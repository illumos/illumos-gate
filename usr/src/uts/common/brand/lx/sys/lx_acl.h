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
 * Copyright (c) 2017 Joyent, Inc.
 */

#ifndef _LX_ACL_H
#define	_LX_ACL_H

#include <sys/vnode.h>
#include <sys/uio.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Both fall under the 'system.' namespace */
#define	LX_XATTR_POSIX_ACL_ACCESS	"posix_acl_access"
#define	LX_XATTR_POSIX_ACL_DEFAULT	"posix_acl_default"

enum lx_acl_type {
	LX_ACL_ACCESS,
	LX_ACL_DEFAULT
};

extern int lx_acl_setxattr(vnode_t *, enum lx_acl_type, void *, size_t);
extern int lx_acl_getxattr(vnode_t *, enum lx_acl_type, void *, size_t,
    ssize_t *);
extern int lx_acl_removexattr(vnode_t *, enum lx_acl_type);
extern int lx_acl_listxattr(vnode_t *, uio_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LX_ACL_H */
