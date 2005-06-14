/* $Id: strlcat.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_STRLCAT_H
#define	_STRLCAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#ifndef HAVE_STRLCAT
#include <sys/types.h>
size_t strlcat(char *dst, const char *src, size_t siz);
#endif /* !HAVE_STRLCAT */

#ifdef __cplusplus
}
#endif

#endif /* _STRLCAT_H */
