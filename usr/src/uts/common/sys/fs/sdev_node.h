/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SDEV_NODE_H
#define	_SYS_SDEV_NODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#include <sys/fs/sdev_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

#define	DEVNOPS_REV	1

/*
 * directory vnode ops implemented in a loadable module
 */
struct devname_ops {
	int	devnops_rev;	/* module build version */
	int	(*devnops_lookup)(char *, devname_handle_t *, struct cred *);
	int	(*devnops_remove)(devname_handle_t *);
	int	(*devnops_rename)(devname_handle_t *, char *);
	int 	(*devnops_getattr)(devname_handle_t *, struct vattr *,
		    struct cred *);
	int	(*devnops_readdir)(devname_handle_t *, struct cred *);
	void	(*devnops_inactive)(devname_handle_t *, struct cred *);
};

/*
 * supported protocols
 */
#define	DEVNAME_NS_PATH	1
#define	DEVNAME_NS_DEV	2

/*
 * default devname_ops for a /dev directory
 * that has a device name binding rule map
 */
extern void devname_set_nodetype(devname_handle_t *, void *, int);
extern void devname_get_vnode(devname_handle_t *, vnode_t **);
extern int devname_get_path(devname_handle_t *, char **);
extern int devname_get_name(devname_handle_t *, char **);
extern int devname_get_dir_handle(devname_handle_t *, devname_handle_t **);
extern void devname_get_dir_vnode(devname_handle_t *, vnode_t **);
extern int devname_get_dir_path(devname_handle_t *, char **);
extern int devname_get_dir_name(devname_handle_t *, char **);

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_SDEV_NODE_H */
