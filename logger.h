#include <syslog.h>

#define iprint(level, ...) syslog(level & 0xFFFF, __VA_ARGS__)