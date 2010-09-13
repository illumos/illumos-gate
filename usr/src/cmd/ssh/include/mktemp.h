/* $Id: mktemp.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_MKTEMP_H
#define	_MKTEMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"
#ifndef HAVE_MKDTEMP
int mkstemps(char *path, int slen);
int mkstemp(char *path);
char *mkdtemp(char *path);
#endif /* !HAVE_MKDTEMP */

#ifdef __cplusplus
}
#endif

#endif /* _MKTEMP_H */
