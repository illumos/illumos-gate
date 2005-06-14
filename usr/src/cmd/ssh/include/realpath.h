/* $Id: realpath.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_REALPATH_H
#define	_REALPATH_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#if !defined(HAVE_REALPATH) || defined(BROKEN_REALPATH)

char *realpath(const char *path, char *resolved);

#endif /* !defined(HAVE_REALPATH) || defined(BROKEN_REALPATH) */

#ifdef __cplusplus
}
#endif

#endif /* _REALPATH_H */
