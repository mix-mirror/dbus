/* -*- mode: C; c-file-style: "gnu"; indent-tabs-mode: nil; -*- */
/* dir-watch-evports.c  OS specific directory change notification for message bus
 *
 * Copyright (C) 2025 Oracle and/or its affiliates.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <config.h>

#include <errno.h>
#include <port.h>
#include <sys/stat.h>
#include <unistd.h>
#include <poll.h>
#include <dirent.h>

#include <dbus/dbus-internals.h>
#include <dbus/dbus-list.h>
#include <dbus/dbus-watch.h>
#include "dir-watch.h"

/* This limit is not just for the directories given by dbus but also for
 * all the files and directories within.
 */
#define MAX_OBJECTS_TO_WATCH 128

/* Because the data passed to port_associate are no longer significant after
 * the call, we can save memory by overlapping file_obj structures (such that
 * alignment is not an issue).
 */
static dbus_int64_t fobjs[MAX_OBJECTS_TO_WATCH + sizeof(struct file_obj) - 1];

static int port = -1;
static DBusWatch *watch = NULL;
static DBusLoop *loop = NULL;
/* Used to define the point since given directories are being watched */
struct timespec last_sighup;

/* For the comparison of timespec structures */
# define tslower(a, b)            \
  (((a).tv_sec == (b).tv_sec) ?   \
   ((a).tv_nsec < (b).tv_nsec) :  \
   ((a).tv_sec < (b).tv_sec))


static dbus_bool_t
_handle_evport_watch (DBusWatch *_watch, unsigned int flags, void *data)
{
  struct timespec nullts = { 0, 0 };
  int res;
  port_event_t pe;

  res = port_get (port, &pe, &nullts);

  /* Sleep for half a second to avoid a race when files are being installed. */
  usleep (500000);

  if (res == 0)
    {
      /* Remember this point in order to not miss any further changes. */
      clock_gettime (CLOCK_REALTIME, &last_sighup);
      _dbus_verbose ("Sending SIGHUP signal on reception of an event\n");
      (void) kill (_dbus_getpid (), SIGHUP);
    }
  else if (res < 0 && errno == EBADF)
    {
      port = -1;
      _dbus_assert (watch == _watch);
      if (watch != NULL)
        {
          _dbus_loop_remove_watch (loop, watch);
          _dbus_watch_invalidate (watch);
          _dbus_watch_unref (watch);
          watch = NULL;
        }
      _dbus_verbose ("Sending SIGHUP signal since event port has been closed\n");
      (void) kill (_dbus_getpid (), SIGHUP);
    }

  return TRUE;
}

static void
_shutdown_watch (void *data)
{
  if (loop == NULL)
    return;

  _dbus_loop_unref (loop);
  loop = NULL;
}

static int
_init_watch (BusContext *context)
{
  if (loop == NULL)
    {
      if (!_dbus_register_shutdown_func (_shutdown_watch, NULL))
        {
          _dbus_warn ("Unable to register shutdown function");
          return FALSE;
        }

      loop = bus_context_get_loop (context);
      _dbus_loop_ref (loop);

      /* This is the point since when changes to files is being watched */
      if (clock_gettime (CLOCK_REALTIME, &last_sighup))
        {
          _dbus_warn ("Cannot create evport; error '%s'", _dbus_strerror (errno));
          return FALSE;
        }
    }

  return TRUE;
}

static dbus_bool_t
_init_evport (void)
{
  /* First, close the old port if necessary. We can do so now and not miss any
   * notification as any changes since the last SIGHUP will be caught by the
   * new port (as last_sighup was set back then).
   */
  if (loop && watch)
    {
      _dbus_loop_remove_watch (loop, watch);
    }

  if (watch)
    {
      _dbus_watch_invalidate (watch);
      _dbus_watch_unref (watch);
      watch = NULL;
    }

  if (port != -1)
    {
      /* This will also dissociate all the objects previously associated
       * with given port - no need to do so one by one.
       */
      close (port);
      port = -1;
    }

  /* Rebuild everything at this point */
  port = port_create ();
  if (port == -1)
    {
      _dbus_warn ("Cannot create evport; error '%s'", _dbus_strerror (errno));
      goto out;
    }

  watch = _dbus_watch_new (port, DBUS_WATCH_READABLE, TRUE,
                           _handle_evport_watch, NULL, NULL);

  if (watch == NULL)
    {
      _dbus_warn ("Unable to create evport watch\n");
      goto out1;
    }

  if (!_dbus_loop_add_watch (loop, watch))
    {
      _dbus_warn ("Unable to add reload watch to main loop");
      goto out2;
    }

  return TRUE;

out2:
  if (watch)
    {
      _dbus_watch_invalidate (watch);
      _dbus_watch_unref (watch);
      watch = NULL;
    }

out1:
  if (port != -1)
    {
      close (port);
      port = -1;
    }

out:
  return FALSE;
}

static dbus_bool_t
_associate (char *filepath, int index, dbus_bool_t file_only)
{
	int res;
  struct stat sb;
  struct file_obj *fobj;

  res = stat (filepath, &sb);
  if (res < 0)
    {
      if (errno != ENOENT)
        {
          _dbus_warn ("Cannot stat '%s'; error '%s'", filepath, _dbus_strerror (errno));
        }
      return FALSE;
    }

  if (file_only && !S_ISREG(sb.st_mode))
    return FALSE;

  /* file_obj structures can safely overlap as the data is no longer
   * necessary after the call
   */
  fobj = (struct file_obj *)(&fobjs[index]);
  fobj->fo_name = filepath;
  fobj->fo_atime = sb.st_atim;
  fobj->fo_mtime = sb.st_mtim;
  fobj->fo_ctime = sb.st_ctim;

  /* Event ports sadly don't let us set last_sighup to fobj directly as it only
   * checks for differences; it doesn't make timespec comparison.
   */
  if (tslower (last_sighup, sb.st_mtim) || tslower (last_sighup, sb.st_ctim)) {
    /* Changing one value to something different from stat forces immediate event. */
    fobj->fo_mtime = last_sighup;
  }

  res = port_associate (port, PORT_SOURCE_FILE, (uintptr_t)fobj, FILE_MODIFIED|FILE_ATTRIB, NULL);
  if (res < 0)
    {
      _dbus_warn ("Cannot setup evport for '%s'; error '%s'", filepath, _dbus_strerror (errno));
      return FALSE;
    }
  return TRUE;
}

void
bus_set_watched_dirs (BusContext *context, DBusList **directories)
{
  DBusList *link;
  char buffer[256];
  int num_objects;
  DIR *folder;
  struct dirent *entry = NULL;

  if (!_init_watch (context))
    return;

  if (!_init_evport ())
    return;

  num_objects = 0;
  link = _dbus_list_get_first_link (directories);
  while (link != NULL && num_objects < MAX_OBJECTS_TO_WATCH)
    {
      if (!_associate ((char *)link->data, num_objects, FALSE))
        {
          /* Currently, this implementation goes through every directory given,
           * even if some of them fail stat/association, which is different
           * from other implementations. I am not sure whether that is an
           * issue; we'll see.
           */
          link = _dbus_list_get_next_link (directories, link);
          continue;
        }

      num_objects++;

      /* Go through the entire directory */
      folder = opendir ((char *)link->data);
      if (folder == NULL)
        {
          _dbus_warn ("Cannot read directory '%s'; error '%s'", (char *)link->data, _dbus_strerror (errno));
          link = _dbus_list_get_next_link (directories, link);
          continue;
        }

      while ((entry = readdir (folder)))
        {
          if (!strcmp (entry->d_name, ".") || !strcmp (entry->d_name, ".."))
            continue;

          if (num_objects >= MAX_OBJECTS_TO_WATCH)
            break;

          /* Construct full path to files within */
          buffer[0] = 0;
          strlcat (buffer, (char*)link->data, sizeof (buffer));
          if (buffer[strlen ((char*)link->data)-1] != '/') {
            strlcat (buffer, "/", sizeof (buffer));
          }
          strlcat (buffer, entry->d_name, sizeof (buffer));

          if (!_associate (buffer, num_objects, TRUE))
            continue;

          num_objects++;
        }
      closedir (folder);
      link = _dbus_list_get_next_link (directories, link);
    }

  if (link != NULL || entry != NULL)
    {
      _dbus_warn ("Too many files and directories to watch them all, only watching first %d.", MAX_OBJECTS_TO_WATCH);
    }
}
