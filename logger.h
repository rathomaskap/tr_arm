#include <syslog.h>

#define iprint(level, ...) syslog(level, __VA_ARGS__)