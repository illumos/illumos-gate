/*
 * internal include file for com_err package
 */
#include "mit-sipb-copyright.h"

#include <errno.h>

#ifndef SYS_ERRLIST_DECLARED
extern char const * const sys_errlist[];
extern const int sys_nerr;
#endif

#if defined(__STDC__) && !defined(HDR_HAS_PERROR) && !defined(WIN32)
void perror (const char *);
#endif
