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

#ifndef	_LX_AUTOFS_IMPL_H
#define	_LX_AUTOFS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/file.h>
#include <sys/id_space.h>
#include <sys/modhash.h>
#include <sys/vnode.h>

#include <sys/lx_autofs.h>

/*
 * Space key.
 * Used to persist data across lx_autofs filesystem module unloads.
 */
#define	LX_AUTOFS_SPACE_KEY_UDEV	LX_AUTOFS_NAME "_udev"

/*
 * Name of the backing store directory.
 */
#define	LX_AUTOFS_BS_DIR		"." LX_AUTOFS_NAME

#define	LX_AUTOFS_VFS_ID_HASH_SIZE	15
#define	LX_AUTOFS_VFS_PATH_HASH_SIZE	15
#define	LX_AUTOFS_VFS_VN_HASH_SIZE	15

/*
 * VFS data object.
 */
typedef struct lx_autofs_vfs {
	/* Info about the underlying filesystem and backing store. */
	vnode_t		*lav_mvp;
	char		*lav_bs_name;
	vnode_t		*lav_bs_vp;

	/* Info about the automounter process managing this filesystem. */
	int		lav_fd;
	pid_t		lav_pgrp;
	file_t		*lav_fifo_wr;
	file_t		*lav_fifo_rd;

	/* Each automount requests needs a unique id. */
	id_space_t	*lav_ids;

	/* All remaining structure members are protected by lav_lock. */
	kmutex_t	lav_lock;

	/* Hashes to keep track of outstanding automounter requests. */
	mod_hash_t	*lav_path_hash;
	mod_hash_t	*lav_id_hash;

	/* We need to keep track of all our vnodes. */
	vnode_t		*lav_root;
	mod_hash_t	*lav_vn_hash;
} lx_autofs_vfs_t;

/*
 * Structure to keep track of requests sent to the automounter.
 */
typedef struct lx_autofs_lookup_req {
	/* Packet that gets sent to the automounter. */
	lx_autofs_pkt_t	lalr_pkt;

	/* Reference count.  Always updated atomically. */
	uint_t		lalr_ref;

	/*
	 * Fields to keep track and sync threads waiting on a lookup.
	 * Fields are protected by lalr_lock.
	 */
	kmutex_t	lalr_lock;
	kcondvar_t	lalr_cv;
	int		lalr_complete;
} lx_autofs_lookup_req_t;

/*
 * Generic stack structure.
 */
typedef struct stack_elem {
	list_node_t	se_list;
	caddr_t		se_ptr1;
	caddr_t		se_ptr2;
	caddr_t		se_ptr3;
} stack_elem_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _LX_AUTOFS_IMPL_H */
