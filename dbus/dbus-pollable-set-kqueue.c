/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dbus-pollable-set-epoll.c - a pollable set implemented via kqueue(2) API
 *
 * Copyright © 2025 Gleb Popov <arrowd@FreeBSD.org>
 *
 * SPDX-License-Identifier: AFL-2.1 OR GPL-2.0-or-later
 *
 * Licensed under the Academic Free License version 2.1
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301  USA
 *
 */

#include <config.h>
#include "dbus-pollable-set.h"

#include <dbus/dbus-internals.h>

#include <sys/event.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef DOXYGEN_SHOULD_SKIP_THIS

typedef struct {
    DBusPollableSet parent;
    int kqfd;
} DBusPollableSetKqueue;

static inline DBusPollableSetKqueue *
socket_set_kqueue_cast (DBusPollableSet *set)
{
  _dbus_assert (set->cls == &_dbus_pollable_set_kqueue_class);
  return (DBusPollableSetKqueue *) set;
}

/* this is safe to call on a partially-allocated socket set */
static void
socket_set_kqueue_free (DBusPollableSet *set)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);

  if (self == NULL)
    return;

  if (self->kqfd != -1)
    close (self->kqfd);

  dbus_free (self);
}

DBusPollableSet *
_dbus_pollable_set_kqueue_new (void)
{
  DBusPollableSetKqueue *self;

  self = dbus_new0 (DBusPollableSetKqueue, 1);

  if (self == NULL)
    return NULL;

  self->parent.cls = &_dbus_pollable_set_kqueue_class;

  /* kqueue fds are normally not live through a fork. This is different from
   * epoll fds, which are inherited by process children.
   * dbus-daemon code first creates an empty pollable set and then forks,
   * which makes kqueue-based implementation impossible.
   * Luckily, FreeBSD features the KQUEUE_CPONFORK flag for kqueuex, which
   * preserves the kqueue fd across forks. Its semantics is different from epoll,
   * though - the kqueue's kernel data is copied, so the parent and the child end
   * up with two completely separate queues and event streams. Luckily again,
   * dbus-daemon doesn't really need to share the event stream between the
   * parent and the child, so KQUEUE_CPONFORK works for us perfectly.
   */
  self->kqfd = kqueuex (KQUEUE_CLOEXEC | KQUEUE_CPONFORK);

  if (self->kqfd == -1)
    {
      socket_set_kqueue_free ((DBusPollableSet *) self);
      return NULL;
    }

  return (DBusPollableSet *) self;
}

static unsigned int
kevent_filter_to_watch_flag (short filter)
{
  if (filter == EVFILT_READ)
    return DBUS_WATCH_READABLE;
  if (filter == EVFILT_WRITE)
    return DBUS_WATCH_WRITABLE;

  return 0;
}

/* DBUS_WATCH_READABLE and DBUS_WATCH_WRITABLE */
#define NUM_SUPPORTED_DBUS_WATCH_STATUSES 2

static dbus_bool_t
socket_set_kqueue_add (DBusPollableSet  *set,
                       DBusPollable      fd,
                       unsigned int      flags,
                       dbus_bool_t       enabled)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);
  struct kevent events[NUM_SUPPORTED_DBUS_WATCH_STATUSES];
  struct kevent revents[NUM_SUPPORTED_DBUS_WATCH_STATUSES];
  int ret, err = 0;

  /* A kqueue event is identified by a pair (fd, filter), unlike epoll which
   * uses only fd as a key. This means that we have to create two events if
   * the caller wants both DBUS_WATCH_READABLE and DBUS_WATCH_WRITABLE.
   * But we always create two events to fullfill the requirement that
   * pollable_set_kqueue_enable should not allocate any memory.
   * Created events are disabled initially and then get enabled depending on
   * flags and enabled args.
   */
  EV_SET(&events[0], fd, EVFILT_READ, EV_ADD | EV_DISABLE, 0, 0, NULL);
  EV_SET(&events[1], fd, EVFILT_WRITE, EV_ADD | EV_DISABLE, 0, 0, NULL);

  if (enabled)
    {
      if (flags & DBUS_WATCH_READABLE)
        events[0].flags = EV_ADD;
      if (flags & DBUS_WATCH_WRITABLE)
        events[1].flags = EV_ADD;
    }

  /* We use EV_RECEIPT to receive an error code for each event we're trying
   * to add rather than an aggregated one in the ret variable.
   */
  events[0].flags |= EV_RECEIPT;
  events[1].flags |= EV_RECEIPT;

  ret = kevent (self->kqfd,
                events,
                NUM_SUPPORTED_DBUS_WATCH_STATUSES,
                revents,
                NUM_SUPPORTED_DBUS_WATCH_STATUSES,
                NULL);
  if (ret == NUM_SUPPORTED_DBUS_WATCH_STATUSES)
    {
      for (int i = 0; i < ret; i++)
        {
          _dbus_assert (revents[i].flags & EV_ERROR);
          err += revents[i].data != 0;
        }

      if (err == 0)
        return TRUE;

      /* The caller might try inserting an kqueue fd into the pollable set.
       * This is supported, but only for the EVFILT_READ filter.
       * The problem here is that we're always trying to create the EVFILT_WRITE
       * event too, although disabled if the caller did not request DBUS_WATCH_WRITABLE
       * So if the caller did not ask for DBUS_WATCH_WRITABLE and if it was
       * the only event that failed, then we assume that the fd is the kqueue
       * one and swallow the error.
       */
      if (err == 1 && !(flags & DBUS_WATCH_WRITABLE))
        {
          for (int i = 0; i < ret; i++)
            {
              if (revents[i].filter == EVFILT_WRITE && revents[i].data != 0)
                return TRUE;
            }
        }
    }

  err = errno;
  switch (err)
    {
      case ENOMEM:
        _dbus_warn ("Insufficient memory to add watch for fd %d", fd);
        break;

      case EBADF:
        _dbus_warn ("Bad fd %d", fd);
        break;

      default:
        _dbus_warn ("Misc error when trying to watch fd %d: %s", fd,
                    strerror (err));
        break;
    }

  return FALSE;
}

static void
socket_set_kqueue_enable (DBusPollableSet  *set,
                          DBusPollable      fd,
                          unsigned int      flags)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);
  struct kevent events[NUM_SUPPORTED_DBUS_WATCH_STATUSES];
  int ret, err;

  EV_SET(&events[0], fd, EVFILT_READ, EV_DISABLE, 0, 0, NULL);
  EV_SET(&events[1], fd, EVFILT_WRITE, EV_DISABLE, 0, 0, NULL);

  if (flags & DBUS_WATCH_READABLE)
    events[0].flags = EV_ENABLE;
  if (flags & DBUS_WATCH_WRITABLE)
    events[1].flags = EV_ENABLE;

  ret = kevent (self->kqfd,
                events,
                NUM_SUPPORTED_DBUS_WATCH_STATUSES,
                NULL,
                0,
                NULL);
  if (ret != -1)
    return;

  err = errno;
  switch (err)
    {
      case ENOMEM:
        _dbus_warn ("Insufficient memory to add watch for fd %d", fd);
        break;

      case EBADF:
        _dbus_warn ("Bad fd %d", fd);
        break;

      default:
        _dbus_warn ("Misc error when trying to watch fd %d: %s", fd,
                    strerror (err));
        break;
    }
}

static void
socket_set_kqueue_disable (DBusPollableSet  *set,
                           DBusPollable      fd)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);
  struct kevent events[NUM_SUPPORTED_DBUS_WATCH_STATUSES];

  EV_SET(&events[0], fd, EVFILT_READ, EV_DISABLE, 0, 0, NULL);
  EV_SET(&events[1], fd, EVFILT_WRITE, EV_DISABLE, 0, 0, NULL);

  kevent (self->kqfd,
          events,
          NUM_SUPPORTED_DBUS_WATCH_STATUSES,
          NULL,
          0,
          NULL);
}

static void
socket_set_kqueue_remove (DBusPollableSet  *set,
                          DBusPollable      fd)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);
  struct kevent events[NUM_SUPPORTED_DBUS_WATCH_STATUSES];

  EV_SET(&events[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
  EV_SET(&events[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);

  kevent (self->kqfd,
          events,
          NUM_SUPPORTED_DBUS_WATCH_STATUSES,
          NULL,
          0,
          NULL);
}

/* This is about the same amount of memory that
 * pollable-set-epoll uses for its poll method */
#define N_STACK_DESCRIPTORS 12

static int
socket_set_kqueue_poll (DBusPollableSet   *set,
                        DBusPollableEvent *revents,
                        int                max_events,
                        int                timeout_ms)
{
  DBusPollableSetKqueue *self = socket_set_kqueue_cast (set);
  struct kevent events[N_STACK_DESCRIPTORS];
  struct timespec timeout;
  int n_ready;
  int i;

  _dbus_assert (max_events > 0);

  timeout.tv_sec = timeout_ms / 1000;
  timeout.tv_nsec = (timeout_ms % 1000) * 1000 * 1000;

  n_ready = kevent (self->kqfd,
                    NULL,
                    0,
                    events,
                    MIN (_DBUS_N_ELEMENTS (events), max_events),
                    timeout_ms < 0 ? NULL : &timeout);

  if (n_ready <= 0)
    return n_ready;

  for (i = 0; i < n_ready; i++)
    {
      revents[i].fd = events[i].ident;
      revents[i].flags = kevent_filter_to_watch_flag (events[i].filter);
    }

  return n_ready;
}

DBusPollableSetClass _dbus_pollable_set_kqueue_class = {
    socket_set_kqueue_free,
    socket_set_kqueue_add,
    socket_set_kqueue_remove,
    socket_set_kqueue_enable,
    socket_set_kqueue_disable,
    socket_set_kqueue_poll
};

#endif /* !DOXYGEN_SHOULD_SKIP_THIS */
