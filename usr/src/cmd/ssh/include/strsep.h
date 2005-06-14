/* $Id: strsep.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_STRSEP_H
#define	_STRSEP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_STRSEP
char *strsep(char **stringp, const char *delim);
#endif /* HAVE_STRSEP */

#ifdef __cplusplus
}
#endif

#endif /* _STRSEP_H */
