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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef	_LX_AUTOFS_IMPL_H
#define	_LX_AUTOFS_IMPL_H

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

typedef struct lx_autofs_mntent {
	list_node_t	lxafme_lst;
	uint64_t	lxafme_ts;	/* time stamp */
	uint_t		lxafme_len;
	char		*lxafme_path;
} lx_autofs_mntent_t;

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

	/* The mount's dev and ino values for v5 protocol msg */
	uint64_t	lav_dev;
	u_longlong_t	lav_ino;

	/* options from the mount */
	boolean_t	lav_indirect;
	int		lav_min_proto;

	/*
	 * ioctl-set timeout value. The automounter will perform an expire
	 * ioctl every timeout/4 seconds. We use this to expire a mount once
	 * it is inactive for the full timeout.
	 */
	ulong_t		lav_timeout;

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

	/* list of current mounts */
	list_t		lav_mnt_list;
} lx_autofs_vfs_t;

enum lx_autofs_callres	{ LXACR_NONE, LXACR_READY, LXACR_FAIL };

/*
 * Structure to keep track of automounter requests sent to user-land.
 */
typedef struct lx_autofs_automnt_req {
	/* Packet that gets sent to the automounter. */
	union lx_autofs_pkt laar_pkt;
	int		laar_pkt_size;

	/* Reference count.  Always updated atomically. */
	uint_t		laar_ref;

	/*
	 * Fields to keep track and sync threads waiting on a lookup.
	 * Fields are protected by lalr_lock.
	 */
	kmutex_t	laar_lock;
	kcondvar_t	laar_cv;
	int		laar_complete;

	enum lx_autofs_callres laar_result;
} lx_autofs_automnt_req_t;

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
