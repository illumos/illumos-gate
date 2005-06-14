/* $Id: bsd-snprintf.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_BSD_SNPRINTF_H
#define	_BSD_SNPRINTF_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#include <sys/types.h> /* For size_t */

#ifndef HAVE_SNPRINTF
int snprintf(char *str, size_t count, const char *fmt, ...);
#endif /* !HAVE_SNPRINTF */

#ifndef HAVE_VSNPRINTF
int vsnprintf(char *str, size_t count, const char *fmt, va_list args);
#endif /* !HAVE_SNPRINTF */

#ifdef __cplusplus
}
#endif

#endif /* _BSD_SNPRINTF_H */
