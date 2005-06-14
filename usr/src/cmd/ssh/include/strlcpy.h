/* $Id: strlcpy.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_STRLCPY_H
#define	_STRLCPY_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#ifndef HAVE_STRLCPY
#include <sys/types.h>
size_t strlcpy(char *dst, const char *src, size_t siz);
#endif /* !HAVE_STRLCPY */

#ifdef __cplusplus
}
#endif

#endif /* _STRLCPY_H */
