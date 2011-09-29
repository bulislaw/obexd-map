extern "C" {
#include "log.h"
}

/* Original DBG uses C99-style struct initializer which is not compatible
 * with g++ */

#ifdef DBG
#undef DBG
#endif
#define DBG(fmt, arg...) obex_debug("%s:%s() " fmt,  __FILE__, __FUNCTION__ , ## arg)
