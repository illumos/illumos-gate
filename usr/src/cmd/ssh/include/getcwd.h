/* $Id: getcwd.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_GETCWD_H
#define	_GETCWD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#if !defined(HAVE_GETCWD)

char *getcwd(char *pt, size_t size);

#endif /* !defined(HAVE_GETCWD) */

#ifdef __cplusplus
}
#endif

#endif /* _GETCWD_H */
