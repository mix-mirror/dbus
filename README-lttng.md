# LTTNG support for dbus

The lttng support for DBus allows verbose messages issued on the console
on unix-like operating systems, when verbose mode is enabled at build time
and the environment variable DBUS_VERBOSE=1 is set, to be redirected to the
tracing system provided by lttng.

This requires installing the development package for lttng-ust and building
dbus with it by adding -DENABLE_VERBOSE_LTTNG=1 to the cmake configure line.

For more details on lttng, see https://lttng.org/.

## lttng example session
```sh
# create session
$ lttng create dbus
Session dbus created.
Traces will be output to /home/user/lttng-traces/dbus-20230116-094713

# activate session (only required when using multiple sessions)
$ lttng set-session dbus

# enable events
$ lttng enable-event --userspace 'dbus:*'
UST event dbus:* created in channel channel0

# show session status (opptional)
$ lttng status
Tracing session dbus: [active]
    Trace output: /home/user/lttng-traces/dbus-20230116-094713

=== Domain: User space ===

Buffering scheme: per-user

Tracked process attributes
  Virtual process IDs:  all
  Virtual user IDs:     all
  Virtual group IDs:    all

Channels:
-------------
- channel0: [enabled]

    Attributes:
      Event-loss mode:  discard
      Sub-buffer size:  524288 bytes
      Sub-buffer count: 4
      Switch timer:     inactive
      Read timer:       inactive
      Monitor timer:    1000000 us
      Blocking timeout: 0 us
      Trace file count: 1 per stream
      Trace file size:  unlimited
      Output mode:      mmap

    Statistics:
      Discarded events: 0

    Event rules:
      dbus:* (type: tracepoint) [enabled]

# start tracing
$ lttng start

# run dbus app
$ ../dbus-cmake-build/bin/test-lttng

# stop tracing
$ lttng stop
Waiting for data availability.
Tracing stopped for session dbus

# show tracing results
$ lttng view
Trace directory: /home/user/lttng-traces/dbus-20230116-094713

[10:34:22.255406515] (+?.?????????) host dbus:lttng_test: { cpu_id = 8 }, { my_integer_field = 1, my_string_field = "../dbus-cmake-build/bin/test-lttng" }

# destroy session
$ lttng destroy dbus
```
