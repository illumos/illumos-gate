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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_CTFS_IMPL_H
#define	_SYS_CTFS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/contract.h>
#include <sys/gfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Inode numbers
 */

/*
 * Root inode:
 * ---------------------------------------------------
 * |                       0                         |
 * ---------------------------------------------------
 * 63						     0
 */

#define	CTFS_INO_ROOT 0

/*
 * Contract-specific file:
 * ---------------------------------------------------
 * |1|    file (62:32)     |   contract id (31:0)    |
 * ---------------------------------------------------
 * 63						     0
 *	file = 0 : directory
 *	file = 1 : "all" directory symlink
 *	file > 1 : special files ("ctl", "status", etc.)
 */

#define	CTFS_INO_CT_SHIFT	32
#define	CTFS_INO_CT(ctid, file)	\
	((1ULL << 63) | \
	((unsigned long long)(file) << CTFS_INO_CT_SHIFT) | \
	(ctid))
#define	CTFS_INO_CT_DIR(ctid)		CTFS_INO_CT((ctid), 0)
#define	CTFS_INO_CT_LINK(ctid)		CTFS_INO_CT((ctid), 1)
#define	CTFS_INO_CT_FILE(ctid, file)	CTFS_INO_CT((ctid), (file) + 2)

/*
 * Type-specific file:
 * ---------------------------------------------------
 * |          0         | type (31:16) | file (15:0) |
 * ---------------------------------------------------
 * 63						     0
 *	type = 0 : invalid
 *	type > 0 : contract type index + 1 ("all" is #types + 1)
 *	file = 0 : directory
 *	file > 0 : special files ("template", "latest", etc.)
 */

#define	CTFS_INO_TYPE_SHIFT	16
#define	CTFS_INO_TYPE(type, file)	\
	(((type) + 1) << CTFS_INO_TYPE_SHIFT | (file))
#define	CTFS_INO_TYPE_DIR(type)		CTFS_INO_TYPE((type), 0)
#define	CTFS_INO_TYPE_FILE(type, file)	CTFS_INO_TYPE((type), (file) + 1)

/*
 * Other constants
 */
#define	CTFS_NAME_MAX		32

/*
 * Possible values for ctfs_endpt_flags, below.
 */
#define	CTFS_ENDPT_SETUP	0x1
#define	CTFS_ENDPT_NBLOCK	0x2

/*
 * Common endpoint object.
 */
typedef struct ctfs_endpoint {
	kmutex_t	ctfs_endpt_lock;
	ct_listener_t	ctfs_endpt_listener;
	uint_t		ctfs_endpt_flags;
} ctfs_endpoint_t;

/*
 * root directory data
 */
typedef gfs_dir_t	ctfs_rootnode_t;

/*
 * /all directory data
 */
typedef gfs_dir_t	ctfs_adirnode_t;

/*
 * /all symlink data
 */
typedef struct ctfs_symnode {
	gfs_file_t	ctfs_sn_file;		/* gfs file */
	contract_t	*ctfs_sn_contract;	/* target contract */
	char		*ctfs_sn_string;	/* target path */
	size_t		ctfs_sn_size;		/* length of target path */
} ctfs_symnode_t;

/*
 * contract type directory data
 */
typedef	gfs_dir_t	ctfs_tdirnode_t;

/*
 * contract directory data
 */
typedef struct ctfs_cdirnode {
	gfs_dir_t	ctfs_cn_dir;		/* directory contents */
	contract_t	*ctfs_cn_contract;	/* contract pointer */
	contract_vnode_t ctfs_cn_linkage;	/* contract vnode list node */
} ctfs_cdirnode_t;

/*
 * template file data
 */
typedef struct ctfs_tmplnode {
	gfs_file_t	ctfs_tmn_file;		/* gfs file */
	ct_template_t	*ctfs_tmn_tmpl;		/* template pointer */
} ctfs_tmplnode_t;

/*
 * ctl and status file data
 */
typedef struct ctfs_ctlnode {
	gfs_file_t	ctfs_ctl_file;		/* gfs file */
	contract_t	*ctfs_ctl_contract;	/* contract pointer */
} ctfs_ctlnode_t;

/*
 * latest file data
 */
typedef gfs_dir_t	ctfs_latenode_t;

/*
 * events file data
 */
typedef struct ctfs_evnode {
	gfs_file_t	ctfs_ev_file;		/* gfs file */
	contract_t	*ctfs_ev_contract;	/* contract we're watching */
	ctfs_endpoint_t	ctfs_ev_listener;	/* common endpoint data */
} ctfs_evnode_t;

/*
 * bundle and pbundle file data
 */
typedef struct ctfs_bunode {
	gfs_file_t	ctfs_bu_file;		/* gfs file */
	ct_equeue_t	*ctfs_bu_queue;		/* queue we're watching */
	ctfs_endpoint_t	ctfs_bu_listener;	/* common endpoint data */
} ctfs_bunode_t;

/*
 * VFS data object
 */
typedef struct ctfs_vfs {
	vnode_t	*ctvfs_root;		/* root vnode pointer */
} ctfs_vfs_t;

/*
 * vnode creation routines
 */
extern vnode_t *ctfs_create_tdirnode(vnode_t *);
extern vnode_t *ctfs_create_tmplnode(vnode_t *);
extern vnode_t *ctfs_create_latenode(vnode_t *);
extern vnode_t *ctfs_create_pbundle(vnode_t *);
extern vnode_t *ctfs_create_bundle(vnode_t *);
extern vnode_t *ctfs_create_ctlnode(vnode_t *);
extern vnode_t *ctfs_create_statnode(vnode_t *);
extern vnode_t *ctfs_create_evnode(vnode_t *);
extern vnode_t *ctfs_create_adirnode(vnode_t *);
extern vnode_t *ctfs_create_cdirnode(vnode_t *, contract_t *);
extern vnode_t *ctfs_create_symnode(vnode_t *, contract_t *);

/*
 * common ctfs routines
 */
extern void ctfs_common_getattr(vnode_t *, vattr_t *);
extern int ctfs_close(vnode_t *, int, int, offset_t, cred_t *,
		caller_context_t *);
extern int ctfs_access_dir(vnode_t *, int, int, cred_t *,
		caller_context_t *);
extern int ctfs_access_readonly(vnode_t *, int, int, cred_t *,
		caller_context_t *);
extern int ctfs_access_readwrite(vnode_t *, int, int, cred_t *,
		caller_context_t *);
extern int ctfs_open(vnode_t **, int, cred_t *,
		caller_context_t *);

/*
 * vnode ops vector templates
 */
extern vnodeops_t *ctfs_ops_root;
extern vnodeops_t *ctfs_ops_adir;
extern vnodeops_t *ctfs_ops_sym;
extern vnodeops_t *ctfs_ops_tdir;
extern vnodeops_t *ctfs_ops_tmpl;
extern vnodeops_t *ctfs_ops_cdir;
extern vnodeops_t *ctfs_ops_ctl;
extern vnodeops_t *ctfs_ops_stat;
extern vnodeops_t *ctfs_ops_event;
extern vnodeops_t *ctfs_ops_bundle;
extern vnodeops_t *ctfs_ops_latest;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CTFS_IMPL_H */
