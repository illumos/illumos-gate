/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RSM_IN_H
#define	_RSM_IN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/rsm/rsm.h>
#include <sys/rsm/rsmpi.h>

#define	DRIVER_NAME	"rsm"


#define	RSM_DRIVER_MINOR	0

#define	RSM_CNUM	8

#define	RSMIPC_SZ	10	/* number of outstanding requests, max: 256 */

#define	RSMIPC_MAX_MESSAGES	64 /* max msgs that receiver can buffer */
#define	RSMIPC_LOTSFREE_MSGBUFS	16 /* chunks of credits sent to sender  */

/*
 * The base for Sun RSMAPI Kernel Agent service idenitifiers is RSM_INTR_T_KA
 * as defined below. This is as per the RSMPI specification. Thus,
 * in the kernel agent, we need to use this value as the service identifier
 * while registering the service handlers.
 */
#define	RSM_INTR_T_KA	0x88
#define	RSM_SERVICE	RSM_INTR_T_KA

#define	RSM_PRI		2
#define	RSM_QUEUE_SZ	256

#define	RSM_LOCK	0
#define	RSM_NOLOCK	1

#define	RSM_MAX_NUM_SEG	4095	/* default value for max imp and exp segs */

#define	RSM_MAX_NODE	64	/* maximum number of nodes in the cluster */

#define	RSM_MAX_CTRL	32	/* maximum number of controllers per node */

/*
 * The following defines UINT_MAX rounded down to a page aligned value.
 */
#define	RSM_MAXSZ_PAGE_ALIGNED (UINT_MAX & PAGEMASK)
/*
 * Define TRASHSIZE as the maximum possible size which is page aligned
 * This value cannot be 0xffffffffffffe000 since this is taken as a
 * negative value in the devmap_umem_remap call, thus causing the call
 * to fail.
 */
#define	TRASHSIZE 0x7fffffffffffe000

#define	RSM_ACCESS_READ				0444
#define	RSM_ACCESS_WRITE			0222
#define	RSM_ACCESS_TRUSTED			0666

/* flag values for rsmseg_unload */
#define	DISCONNECT	1
#define	NO_DISCONNECT	0

struct rsm_driver_data {
	kmutex_t	drv_lock;
	kcondvar_t	drv_cv;
	int		drv_state;	/* RSM_DRV_YYYY states */
	int		drv_memdel_cnt; /* number of memdel callbacks */
};

/* rsm driver state */
#define	RSM_DRV_NEW			0
#define	RSM_DRV_OK			1
#define	RSM_DRV_PREDEL_STARTED		2
#define	RSM_DRV_PREDEL_COMPLETED	3
#define	RSM_DRV_POSTDEL_IN_PROGRESS	4
#define	RSM_DRV_DR_IN_PROGRESS		5
#define	RSM_DRV_REG_PROCESSING		6
#define	RSM_DRV_UNREG_PROCESSING	7

/* internal flags */
#define	RSM_DR_QUIESCE		0
#define	RSM_DR_UNQUIESCE	1

typedef enum {
	RSM_STATE_NEW = 0,
	RSM_STATE_NEW_QUIESCED,
	RSM_STATE_BIND,
	RSM_STATE_BIND_QUIESCED,
	RSM_STATE_EXPORT,
	RSM_STATE_EXPORT_QUIESCING,
	RSM_STATE_EXPORT_QUIESCED,
	RSM_STATE_ZOMBIE,
	RSM_STATE_CONNECTING,
	RSM_STATE_ABORT_CONNECT,
	RSM_STATE_CONNECT,
	RSM_STATE_CONN_QUIESCE,
	RSM_STATE_MAPPING,
	RSM_STATE_ACTIVE,
	RSM_STATE_MAP_QUIESCE,
	RSM_STATE_DISCONNECT,
	RSM_STATE_END
} rsm_resource_state_t;

typedef enum {
	RSM_RESOURCE_EXPORT_SEGMENT,
	RSM_RESOURCE_IMPORT_SEGMENT,
	RSM_RESOURCE_BAR
}rsm_resource_type_t;

/*
 * All resources have the only common info. whether it is a segment or
 * a notification queue.
 */
typedef struct rsm_resource {
	kmutex_t		rsmrc_lock;	/* sync on resource */
	minor_t			rsmrc_num;	/* (minor) number */
	rsm_memseg_id_t		rsmrc_key;	/* user key */
	mode_t			rsmrc_mode;	/* access permission */
	struct adapter		*rsmrc_adapter;	/* controller number */
	rsm_node_id_t		rsmrc_node;	/*  nodeid */
	rsm_resource_type_t	rsmrc_type;	/* type of this resource */
	rsm_resource_state_t	rsmrc_state;	/* segment state */
	struct rsm_resource	*rsmrc_next;
} rsmresource_t;

#define	RSMRC_BLKSZ	16
#define	RSMRC_RESERVED	((rsmresource_t *)0x1)

#define	RSM_HASHSZ	128

#define	RSM_USER_MEMORY		0x1
#define	RSM_KERNEL_MEMORY	0x2
#define	RSM_EXPORT_WAIT		0x4
#define	RSM_SEGMENT_POLL	0x8
#define	RSM_FORCE_DISCONNECT	0x10
#define	RSM_IMPORT_DUMMY	0x20
/*
 * The following macro is used within the kernel agent to indicate that
 * rebind/unbind is allowed for an exported segment. It is a part of the
 * segment's s_flags field.
 */
#define	RSMKA_ALLOW_UNBIND_REBIND	0x40
#define	RSM_REPUBLISH_WAIT	0x80
#define	RSM_DR_INPROGRESS	0x100
#define	RSM_FORCE_DESTROY_WAIT	0x200
#define	RSMKA_SET_RESOURCE_DONTWAIT	0x400

#define	RSMRC_LOCK(p)	mutex_enter(&(p)->rsmrc_lock)
#define	RSMRC_UNLOCK(p)	mutex_exit(&(p)->rsmrc_lock)
#define	RSMRC_HELD(p)	MUTEX_HELD(&(p)->rsmrc_lock)
#define	RSMRC_TRY(p)	mutex_tryenter(&(p)->rsmrc_lock)

typedef struct rsm_region {
	caddr_t		r_vaddr;	/* exported virtual address */
	size_t		r_len;		/* length of export region */
	offset_t	r_off;		/* offset of this region in segment */
	struct as	*r_asp;
	struct rsm_region *r_next;	/* next region of segment */
}rsm_region;

typedef struct rsm_cookie {
	devmap_cookie_t		c_dhp;		/* devmap cookie handle */
	offset_t		c_off;		/* offset of mapping	*/
	size_t			c_len;		/* len of mapping	*/
	struct rsm_cookie	*c_next;	/* next handle		*/
}rsmcookie_t;

typedef struct rsm_mapinfo {
	dev_info_t	*dip;
	uint_t		dev_register;
	off_t		dev_offset;
	off_t		start_offset;
	size_t		individual_len;
	struct rsm_mapinfo *next;
} rsm_mapinfo_t;



/*
 * Shared Importer data structure
 *
 */
typedef struct rsm_import_share {
	kmutex_t	rsmsi_lock;	/* lock for shared importers	*/
	kcondvar_t	rsmsi_cv;	/* condvar to wait at		*/
	rsm_node_id_t	rsmsi_node;
	rsm_memseg_id_t	rsmsi_segid;
	size_t		rsmsi_seglen;
	rsm_memseg_import_handle_t	rsmsi_handle; /* RSMPI handle */
	uint_t		rsmsi_state;
#define	RSMSI_STATE_NEW			0x0001
#define	RSMSI_STATE_CONNECTING		0x0002
#define	RSMSI_STATE_ABORT_CONNECT	0x0004
#define	RSMSI_STATE_CONNECTED		0x0008
#define	RSMSI_STATE_CONN_QUIESCE	0x0010
#define	RSMSI_STATE_MAPPED		0x0020
#define	RSMSI_STATE_MAP_QUIESCE		0x0040
#define	RSMSI_STATE_DISCONNECTED	0x0080

	uint_t		rsmsi_refcnt;	/* ref count of importers	*/
	uint_t		rsmsi_mapcnt;	/* count of mapped importers	*/
	mode_t		rsmsi_mode;	/* mode of last (re)publish	*/
	uid_t		rsmsi_uid;
	gid_t		rsmsi_gid;
	rsm_mapinfo_t	*rsmsi_mapinfo;	/* register, offset, len values */
	uint_t		rsmsi_flags;	/* flags			*/
#define	RSMSI_FLAGS_ABORTDONE	0x0001	/* NOT_IMPORTING msg for abort conn */
					/* has been sent		    */
	void		*rsmsi_cookie;	/* cookie of the first seg connect */
} rsm_import_share_t;

#define	RSMSI_LOCK(sharep)	mutex_enter(&(sharep)->rsmsi_lock)
#define	RSMSI_UNLOCK(sharep)	mutex_exit(&(sharep)->rsmsi_lock)
#define	RSMSI_HELD(sharep)	MUTEX_HELD(&(sharep)->rsmsi_lock)
#define	RSMSI_TRY(sharep)	mutex_tryenter(&(sharep)->rsmsi_lock)

typedef struct rsm_seginfo {
	rsmresource_t		s_hdr;		/* resource hdr */
#define	s_state	s_hdr.rsmrc_state	/* segment state */
#define	s_adapter s_hdr.rsmrc_adapter
#define	s_node	s_hdr.rsmrc_node
#define	s_lock	s_hdr.rsmrc_lock
#define	s_minor	s_hdr.rsmrc_num		/* minor # of segment */
#define	s_key	s_hdr.rsmrc_key		/* user segment key */
#define	s_mode	s_hdr.rsmrc_mode	/* user segment mode */
#define	s_type	s_hdr.rsmrc_type	/* segment type */
	uid_t			s_uid;		/* owner id */
	gid_t			s_gid;		/* owner id */

	size_t			s_len;		/* total segment size */
	rsm_region		s_region;	/* regions of segment */

	int			s_flags;
	int			s_pollflag;	/* indicates poll status */

	kcondvar_t		s_cv;		/* condition to wait on */

	rsm_memseg_id_t		s_segid;	/* NIC segment id */

	int		s_acl_len;		/* length of access list */
	rsmapi_access_entry_t *s_acl;		/* access list */
	rsm_access_entry_t *s_acl_in;		/* access list with hwaddr */

	struct pollhead	s_poll;
	uint32_t	s_pollevent;
	pid_t 		s_pid;

	rsmcookie_t	*s_ckl;		/* list of devmap cookie */

	size_t		s_total_maplen;
	rsm_mapinfo_t	*s_mapinfo;	/* register, offset, len  */

	union {
		rsm_memseg_import_handle_t	in;
		rsm_memseg_export_handle_t	out;
	} s_handle;			/* NIC handle for segment */

	/*
	 * This field is used to indicate the cookie returned by the
	 * ddi_umem_lock when binding pages for an export segment.
	 * Also, for importers on the same node as the export segment,
	 * this field indicates the cookie used during import mapping.
	 */
	ddi_umem_cookie_t	s_cookie;
	rsm_import_share_t	*s_share;	/* shared importer data	    */
	/*
	 * This field in an import segments indicates the number of
	 * putv/getv operations in progress and in an export segment
	 * it is the number of putv/getv ops currently using it as
	 * a handle in the iovec.
	 */
	uint_t			s_rdmacnt;
	struct proc		*s_proc;
} rsmseg_t;

#define	rsmseglock_acquire(p)	RSMRC_LOCK((rsmresource_t *)(p))
#define	rsmseglock_release(p)	RSMRC_UNLOCK((rsmresource_t *)(p))
#define	rsmseglock_held(p)	RSMRC_HELD((rsmresource_t *)(p))
#define	rsmseglock_try(p)	RSMRC_TRY((rsmresource_t *)(p))

#define	rsmsharelock_acquire(p)	RSMSI_LOCK(p->s_share)
#define	rsmsharelock_release(p)	RSMSI_UNLOCK(p->s_share)
#define	rsmsharelock_held(p)	RSMSI_HELD(p->s_share)
#define	rsmsharelock_try(p)	RSMSI_TRY(p->s_share)

/*
 * Resource elements structure
 */
typedef struct {
	int		rsmrcblk_avail;
	rsmresource_t	*rsmrcblk_blks[RSMRC_BLKSZ];
}rsmresource_blk_t;

struct rsmresource_table {
	krwlock_t	rsmrc_lock;
	int		rsmrc_len;
	int		rsmrc_sz;
	rsmresource_blk_t **rsmrc_root;
};

/*
 * Struct for advertised resource list
 */
/*
 * Hashtable structs
 * bucket points to an array of pointers, each entry in the bucket array
 * points to a linked list of resource items.
 * bucket index = bucket_address%RSM_HASHSZ
 */
typedef struct rsmhash_table {
	krwlock_t		rsmhash_rw;
	rsmresource_t		**bucket;
} rsmhash_table_t;

/*
 * Remote messaging related structure
 */

/*
 * Flags for ipc slot
 */
#define	RSMIPC_FREE	0x1			/* slot is free */
#define	RSMIPC_PENDING	0x2			/* slot has pending request */

#define	RSMIPC_SET(x, v)	((x)->rsmipc_flags |= (v))
#define	RSMIPC_GET(x, v)	((x)->rsmipc_flags & (v))
#define	RSMIPC_CLEAR(x, v)	((x)->rsmipc_flags &= ~(v))

typedef struct rsmipc_slot {
	kmutex_t 	rsmipc_lock;		/* lock for remote msgs */
	kcondvar_t	rsmipc_cv;		/* condition var to wait on */
	int		rsmipc_flags;
	rsmipc_cookie_t	rsmipc_cookie;		/* cookie of request in wire */
	void 		*rsmipc_data;		/* ptr to data to copy */
}rsmipc_slot_t;

/*
 * Messaging struc
 */
typedef struct {
	kmutex_t	lock;
	kcondvar_t	cv;
	int		count;
	int		wanted;
	int		sequence;
	rsmipc_slot_t	slots[RSMIPC_SZ];
}rsm_ipc_t;

/*
 * These tokens are used for building the list of remote node importers
 * of a segment exported from the local node
 */
typedef struct importing_token {
	struct importing_token	*next;
	rsm_memseg_id_t		key;
	rsm_node_id_t		importing_node;
	void			*import_segment_cookie;
	rsm_addr_t		importing_adapter_hwaddr;
} importing_token_t;

typedef struct {
	kmutex_t		lock;
	importing_token_t	**bucket;
} importers_table_t;

/*
 * Used by the rsm_send_republish() fn
 */
typedef struct republish_token {
	struct republish_token	*next;
	rsm_memseg_id_t		key;
	rsm_node_id_t		importing_node;
	rsm_permission_t	permission;
} republish_token_t;

/*
 * data strucuture for list manipulation
 */
typedef struct list_element {
	struct list_element	*next;
	rsm_node_id_t		nodeid;
	uint32_t		flags;
#define	RSM_SUSPEND_ACKPENDING	0x01
#define	RSM_SUSPEND_NODEDEAD	0x02
} list_element_t;

typedef struct list_head {
	struct list_element	*list_head;
	kmutex_t		list_lock;
} list_head_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _RSM_IN_H */
