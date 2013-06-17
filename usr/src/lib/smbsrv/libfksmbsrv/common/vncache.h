/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _VNCACHE_H
#define	_VNCACHE_H

#ifdef __cplusplus
extern "C" {
#endif

struct stat;
vnode_t *vncache_lookup(struct stat *);
vnode_t *vncache_enter(struct stat *, vnode_t *, char *, int);
void	vncache_renamed(vnode_t *, vnode_t *, char *);
void 	vncache_inactive(vnode_t *);
int 	vncache_cmp(const void *, const void *);

int vncache_init(void);
void vncache_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* _VNCACHE_H */
