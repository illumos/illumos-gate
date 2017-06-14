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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_NAMENODE_H
#define	_SYS_FS_NAMENODE_H

#if defined(_KERNEL)
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This structure is used to pass a file descriptor from user
 * level to the kernel. It is first used by fattach() and then
 * be NAMEFS.
 */
struct namefd {
	int fd;
};

#if defined(_KERNEL)
/*
 * Each NAMEFS object is identified by a struct namenode/vnode pair.
 */
struct namenode {
	struct vnode    *nm_vnode;	/* represents mounted file desc. */
	int		nm_flag;	/* flags defined below */
	struct vattr    nm_vattr;	/* attributes of mounted file desc. */
	struct vnode	*nm_filevp;	/* file desc. prior to mounting */
	struct file	*nm_filep;	/* file pointer of nm_filevp */
	struct vnode	*nm_mountpt;	/* mount point prior to mounting */
	struct namenode *nm_nextp;	/* next link in the linked list */
	kmutex_t	nm_lock;	/* protects nm_vattr */
};

/*
 * Valid flags for namenodes.
 */
#define	NMNMNT		0x01	/* namenode not mounted */

/*
 * Macros to convert a vnode to a namenode, and vice versa.
 */
#define	VTONM(vp) ((struct namenode *)((vp)->v_data))
#define	NMTOV(nm) ((nm)->nm_vnode)

#define	NM_FILEVP_HASH_SIZE	64
#define	NM_FILEVP_HASH_MASK	(NM_FILEVP_HASH_SIZE - 1)
#define	NM_FILEVP_HASH_SHIFT	7
#define	NM_FILEVP_HASH(vp)	(&nm_filevp_hash[(((uintptr_t)vp) >> \
	NM_FILEVP_HASH_SHIFT) & NM_FILEVP_HASH_MASK])

extern struct namenode *nm_filevp_hash[NM_FILEVP_HASH_SIZE];
extern struct vfs namevfs;

extern int nameinit(int, char *);
extern int nm_unmountall(struct vnode *, struct cred *);
extern void nameinsert(struct namenode *);
extern void nameremove(struct namenode *);
extern struct namenode *namefind(struct vnode *, struct vnode *);
extern uint64_t namenodeno_alloc(void);
extern void namenodeno_free(uint64_t);
extern struct vnodeops *nm_vnodeops;
extern const struct fs_operation_def nm_vnodeops_template[];
extern kmutex_t ntable_lock;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_NAMENODE_H */
