/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2025 Ralf Habacker <ralf.habacker@freenet.de>
 */

#include <config.h>
#include <dbus/dbus-test-tap.h>
#include <test/test-utils.h>

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#ifdef DBUS_WIN
#include <io.h>
#include <winsock.h>
#include <winsock2.h>
#include <afunix.h>
#define close(a) closesocket(a)
#undef errno
#define errno WSAGetLastError()
#define strerror(a) ""
#define unlink _unlink
#define F_OK 0
#define access _access
#ifndef ERROR_NO_SUCH_DEVICE
#define ERROR_NO_SUCH_DEVICE 433
#endif
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define INVALID_SOCKET -1
#define SOCKET int
#endif

#define SOCK_PATH "tpf_unix_sock.server"
#define DATA "Hello from server"

static char*
sock_path(void)
{
  static DBusString path = _DBUS_STRING_INIT_INVALID;
  static dbus_bool_t first = TRUE;

  if (first)
    {
      if (!_dbus_string_init (&path))
        goto out;
      if (!_dbus_string_append (&path, _dbus_get_tmpdir ()))
        goto out;
      if (!_dbus_string_append (&path, "/" SOCK_PATH "-"))
        goto out;
      if (!_dbus_generate_random_ascii (&path, 6, NULL))
        goto out;
      first = FALSE;
   }

  return _dbus_string_get_data (&path);
out:
  _dbus_test_fatal ("Could not setup socket path");
  return NULL;
}

static dbus_bool_t
test_afunix_socket_raw (const char *test_data_dir _DBUS_GNUC_UNUSED)
{
  SOCKET accept_sock = INVALID_SOCKET, server_sock = INVALID_SOCKET, client_sock = INVALID_SOCKET;
  int rc;
  int bytes_rec = 0;
  int ret = FALSE;
  socklen_t len;
  struct sockaddr_un server_sockaddr;
  struct sockaddr_un client_sockaddr;
  char buf[256];
  int backlog = 10;

  _DBUS_ZERO (server_sockaddr);
  _DBUS_ZERO (client_sockaddr);
  _DBUS_ZERO (buf);

#ifdef DBUS_WIN
  {
    WSADATA data;
    WORD version = MAKEWORD (2, 2);
    rc = WSAStartup (version, &data);
    if (rc == -1)
      {
        _dbus_test_fatal ("STARTUP ERROR: %d '%s'", WSAGetLastError(), "");
        goto err;
      }
  }
#endif

  server_sock = socket (AF_UNIX, SOCK_STREAM, 0);

  if (server_sock == INVALID_SOCKET)
    {
#ifdef DBUS_WIN
      if (errno == WSAEAFNOSUPPORT)
        {
          _dbus_test_skip ("No AF_UNIX support available");
          ret = TRUE;
          goto err;
        }
#endif
      _dbus_test_fatal ("server SOCKET ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    {
      _dbus_test_diag ("AF_UNIX stream socket created for server");
    }

  client_sock = socket (AF_UNIX, SOCK_STREAM, 0);

  if (client_sock == INVALID_SOCKET)
    {
#ifdef DBUS_WIN
      if (errno == WSAEAFNOSUPPORT)
        {
          _dbus_test_skip ("No AF_UNIX support available");
          ret = TRUE;
          goto err;
        }
#endif
      _dbus_test_fatal ("client SOCKET ERROR = %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    _dbus_test_diag ("AF_UNIX stream socket created for client");

  server_sockaddr.sun_family = AF_UNIX;
  server_sockaddr.sun_path[0] = '\0';
  strncat (server_sockaddr.sun_path, sock_path(), sizeof (server_sockaddr.sun_path) - 1);
  len = sizeof (server_sockaddr);
  rc = unlink (sock_path());

  if (rc == -1)
    {
#ifdef DBUS_WIN
      if (errno == ERROR_NO_SUCH_DEVICE)
        {
          _dbus_test_diag ("got error ERROR_NO_SUCH_DEVICE on unlinking file, ignoring");
        }
      else
#endif
      if (errno == ENOENT)
        {
          _dbus_test_diag ("AF_UNIX socket file did not exist");
        }
      else
        {
          _dbus_test_fatal ("Unlinking AF_UNIX socket file fails = %d '%s'", errno, strerror(errno));
          goto err;
        }
    }

  if (access (sock_path(), F_OK) == 0)
    {
      _dbus_test_fatal ("AF_UNIX socket file '%s' still present", sock_path());
    }

  rc = bind (server_sock, (struct sockaddr *) &server_sockaddr, len);

  if (rc == -1)
    {
#ifdef DBUS_WIN
      if (errno == WSAEAFNOSUPPORT)
        {
          _dbus_test_skip ("Binding to AF_UNIX socket failed, no support available");
          return FALSE;
        }
      else if (errno == WSAEADDRINUSE)
        {
          _dbus_test_diag ("Binding to AF_UNIX socket failed, address in use");
          return FALSE;
        }
#endif
      _dbus_test_fatal ("BIND ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }

  rc = listen (server_sock, backlog);
  if (rc == -1)
    {
      _dbus_test_fatal ("LISTEN ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    _dbus_test_diag ("Listening on AF_UNIX server socket");

  rc = connect (client_sock, (struct sockaddr *) &server_sockaddr, len);
  if(rc == -1)
    {
      _dbus_test_fatal ("CONNECT ERROR = %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    {
      _dbus_test_diag ("Connected to AF_UNIX server socket");
    }

  accept_sock = accept (server_sock, (struct sockaddr *) &client_sockaddr, &len);
  if (accept_sock == INVALID_SOCKET)
    {
      _dbus_test_fatal ("ACCEPT ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    {
      _dbus_test_diag ("AF_UNIX server accepted connection");
    }

  len = sizeof (client_sockaddr);
  rc = getsockname (server_sock, (struct sockaddr *) &client_sockaddr, &len);
  if (rc == -1)
    {
      _dbus_test_fatal ("GETPEERNAME ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    _dbus_test_diag ("AF_UNIX server socket filepath: '%s'", client_sockaddr.sun_path);

  len = sizeof (client_sockaddr);
  rc = getsockname (accept_sock, (struct sockaddr *) &client_sockaddr, &len);
  if (rc == -1)
    {
      _dbus_test_fatal ("GETSOCKNAME ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    _dbus_test_diag ("Accepted AF_UNIX socket filepath: '%s'", client_sockaddr.sun_path);

  len = sizeof (client_sockaddr);
  rc = getpeername (accept_sock, (struct sockaddr *) &client_sockaddr, &len);
  if (rc == -1)
    {
      _dbus_test_fatal ("GETPEERNAME ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    _dbus_test_diag ("Client AF_UNIX socket filepath: '%s'", client_sockaddr.sun_path);

  memset (buf, 0, sizeof (buf));
  strcpy (buf, DATA);
  _dbus_test_diag ("Sending data over AF_UNIX socket ...");
  rc = send (client_sock, buf, strlen(buf) + 1, 0);
  if (rc == -1)
    {
      _dbus_test_fatal ("SEND ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    {
      _dbus_test_diag ("Data sent!");
    }

  _dbus_test_diag ("Waiting to read data from AF_UNIX socket ...");
  bytes_rec = recv (accept_sock, buf, sizeof(buf), 0);
  if (bytes_rec == -1 || bytes_rec != strlen(DATA) + 1)
    {
      _dbus_test_diag ("RECV ERROR: %d '%s'", errno, strerror(errno));
      goto err;
    }
  else
    {
      _dbus_test_diag ("Data from AF_UNIX socket received = '%s'", buf);
    }
  ret = TRUE;
err:
  if (server_sock != INVALID_SOCKET)
    close (server_sock);
  if (accept_sock != INVALID_SOCKET)
    close (accept_sock);
  if (client_sock != INVALID_SOCKET)
    close (client_sock);
  rc = unlink (sock_path());
  if (rc == -1)
    _dbus_test_diag ("unlink AF_UNIX socket file failure: %d '%s'", errno, strerror(errno));

  return ret;
}

static DBusTestCase tests[] =
{
  { "test dbus unix socket raw", test_afunix_socket_raw },
  { NULL }
};

int
main (int argc, char **argv)
{
  return _dbus_test_main (argc, argv, _DBUS_N_ELEMENTS (tests), tests,
                          DBUS_TEST_FLAGS_NONE,
                          NULL, NULL);
}
