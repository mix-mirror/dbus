

#include <lttng/tracef.h>

#include "test-lttng-tp.h"

int main(int argc, char **argv)
{
      tracef("argc %d, argv[0] %s", argc, argv[0]);
      tracepoint(dbus, lttng_test, argc, argv[0]);
      return 0;
}
