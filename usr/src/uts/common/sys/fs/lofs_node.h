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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Loop-back file information structure.
 */

#ifndef _SYS_FS_LOFS_NODE_H
#define	_SYS_FS_LOFS_NODE_H

#include <sys/fs/lofs_info.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The lnode is the "inode" for loop-back files.  It contains
 * all the information necessary to handle loop-back file on the
 * client side.
 */
typedef struct lnode {
	struct lnode	*lo_next;	/* link for hash chain */
	struct vnode	*lo_vp;		/* pointer to real vnode */
	uint_t		lo_looping; 	/* looping flags (see below) */
	struct vnode	*lo_vnode;	/* place holder vnode for file */
} lnode_t;

/*
 * Flags used when looping has been detected.
 */
#define	LO_LOOPING	0x01	/* Looping detected */
#define	LO_AUTOLOOP	0x02	/* Autonode looping detected */

/*
 * Flag passed to makelonode().
 */
#define	LOF_FORCE	0x1	/* Force creation of new lnode */

/*
 * Convert between vnode and lnode
 */
#define	ltov(lp)	(((lp)->lo_vnode))
#define	vtol(vp)	((struct lnode *)((vp)->v_data))
#define	realvp(vp)	(vtol(vp)->lo_vp)

#ifdef _KERNEL
extern vnode_t *makelonode(vnode_t *, struct loinfo *, int);
extern void freelonode(lnode_t *);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_LOFS_NODE_H */
