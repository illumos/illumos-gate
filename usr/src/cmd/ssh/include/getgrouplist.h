/* $Id: getgrouplist.h,v 1.2 2001/02/09 01:55:36 djm Exp $ */

#ifndef	_GETGROUPLIST_H
#define	_GETGROUPLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include "config.h"

#ifndef HAVE_GETGROUPLIST

#include <grp.h>

int getgrouplist(const char *, gid_t, gid_t *, int *);

#endif

#ifdef __cplusplus
}
#endif

#endif /* _GETGROUPLIST_H */
