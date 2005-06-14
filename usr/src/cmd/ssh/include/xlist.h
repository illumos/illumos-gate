/*
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_XLIST_H
#define	_XLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif


char ** xsplit(char *list, char sep);
char * xjoin(char **alist, char sep);
void xfree_split_list(char **list);

#ifdef __cplusplus
}
#endif

#endif /* _XLIST_H */
