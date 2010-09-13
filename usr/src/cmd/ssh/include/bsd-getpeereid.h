/* $Id: bsd-getpeereid.h,v 1.1 2002/09/12 00:33:02 djm Exp $ */

#ifndef	_BSD_GETPEEREID_H
#define	_BSD_GETPEEREID_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#include <sys/types.h> /* For uid_t, gid_t */

#ifndef HAVE_GETPEEREID
int	 getpeereid(int , uid_t *, gid_t *);
#endif /* HAVE_GETPEEREID */

#ifdef __cplusplus
}
#endif

#endif /* _BSD_GETPEEREID_H */
