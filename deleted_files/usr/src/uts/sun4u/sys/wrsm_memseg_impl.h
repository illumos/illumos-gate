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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _WRSM_MEMSEG_IMPL_H
#define	_WRSM_MEMSEG_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * this file is included by the RSM memory segment module
 */

#ifndef _ASM

#include <sys/wrsm_common.h>
#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_transport.h>
#include <sys/wrsm_intr.h>

#endif /* _ASM */


#ifdef	__cplusplus
extern "C" {
#endif


#define	WRSM_SMPUT_PACKETRING_SIZE	50

#define	WRSM_LONG_SIZE		(sizeof (long))
#define	WRSM_LONG_SHIFT		3
#define	WRSM_LONG_MASK		(sizeof (long) - 1)


#ifndef _ASM

/*
 * Hash for segid to iseginfo pointer mapping.
 * Hash for segid to exportseg pointer mapping.
 * Hash for segid to importset pointer mapping.
 *
 * Most likely the segid will be a low integer, so use lower bits
 * of dev_t for hash index.
 */
#define	WRSM_SEGID_HASH_SIZE		0x100	/* # of entries in hash table */
#define	WRSM_SEGID_HASH_SHIFT		0
#define	WRSM_SEGID_HASH_MASK \
	((WRSM_SEGID_HASH_SIZE - 1) << WRSM_SEGID_HASH_SHIFT)
#define	WRSM_SEGID_HASH_FUNC(r) \
	((((uint_t)r) & WRSM_SEGID_HASH_MASK) >> WRSM_SEGID_HASH_SHIFT)




/*
 * choose some middle bits of the pointer for the hash index
 */
#define	WRSM_PTR_HASH_SIZE		0x100	/* # of entries in hash table */
#define	WRSM_PTR_HASH_SHIFT		7
#define	WRSM_PTR_HASH_MASK \
	((WRSM_PTR_HASH_SIZE - 1) << WRSM_PTR_HASH_SHIFT)
#define	WRSM_PTR_HASH_FUNC(r) \
	((((uint_t)(uintptr_t)r) & WRSM_PTR_HASH_MASK) >> WRSM_PTR_HASH_SHIFT)



typedef struct __rsm_memseg_export_handle exportseg_t;
typedef struct __rsm_memseg_import_handle importseg_t;
typedef struct iseginfo iseginfo_t;


/*
 * list of cmmu entries, all one page size
 */
typedef struct cmmugrp {
	off_t offset;			/* offset into segment */
	off_t len;			/* length (bytes)  of region mapped */
	size_t pgbytes;			/* size of page cmmu entry maps */
	unsigned num_tuples;		/* number of cmmu tuples */
	wrsm_cmmu_tuple_t *tuples;	/* array of cmmu tuples */
	struct cmmugrp *next;
} cmmugrp_t;


typedef struct mseg_intr_page {
	wrsm_cmmu_tuple_t *tuple;
	wrsm_intr_recvq_t *recvq;
} mseg_intr_page_t;


typedef struct barrier_page {
	wrsm_cmmu_tuple_t *tuple;
	caddr_t vaddr;
} barrier_page_t;


typedef struct mseg_node_export {
	boolean_t allow_import;		/* this node can access this seg? */
	rsm_permission_t perms;		/* last set permissions for node */
	rsm_permission_t actual_perms;	/* actual permissions for node */
	boolean_t inuse;		/* is node connected to this seg? */

	/*
	 * if hardware access protection is used, need to set up
	 * private cmmu entries for this node
	 */
	cmmugrp_t *hw_cmmugrps;	/* node private cmmu entries */
	mseg_intr_page_t hw_small_put_intr; /* node private intr page */
	barrier_page_t hw_barrier_page;	/* node private barrier page */
} mseg_node_export_t;


/* flags for cmmu_update_fields() function */
typedef enum {
	memseg_set_valid,
	memseg_unset_valid,
	memseg_set_writeable,
	memseg_unset_writeable
} memseg_cmmufield_t;

#define	CMMU_UPDATE_STR(a)						\
	(((a) == memseg_set_valid) ? "memseg_set_valid" :		\
	((a) == memseg_unset_valid) ? "memseg_unset_valid" :		\
	((a) == memseg_set_writeable) ? "memseg_set_writeable" :	\
	((a) == memseg_unset_writeable) ? "memseg_unset_writeable" :	\
	"unknown")


typedef enum {
	memseg_unpublished,			/* unpublished */
	memseg_wait_for_disconnects,		/* unpublishing */
	memseg_published			/* published */
} exportseg_state_t;

/*
 * an exportseg structure is create for each segment created with
 * rsm_create_seg().
 */
struct __rsm_memseg_export_handle {
	kmutex_t lock;
	boolean_t valid;		/* is exportseg being removed? */
	wrsm_network_t *network;
	exportseg_state_t state;	/* is segment published? */
	rsm_memseg_id_t segid;		/* user assigned segment id */
	size_t size;			/* length of segment */
	int num_pages;			/* number of 8k pages in segment */
	pfn_t *pfn_list;		/* 8k pfns backing the segment */
	boolean_t allow_rebind;		/* unbind/rebind allowed? */
	int total_tuples;		/* total number of cmmu tuples */
	int num_cmmugrps;		/* # of cmmugrps */
	cmmugrp_t *cmmugrps;		/* linked list of cmmugrps */
	mseg_intr_page_t small_put_intr; /* CMMU/handler for small put intr */
	barrier_page_t barrier_page;	/* page/CMMU for barriers */
	mseg_node_export_t nodes[WRSM_MAX_CNODES]; /* per node info */
	cnode_bitmask_t import_bitmask;	/* nodes with import permission */
	uint_t wait_for_disconnects;	/* post-unpublish node cleanup count */
	boolean_t writeable;		/* how to set generic CMMU entries */
	exportseg_t *segid_next;	/* linked list for segid hash table */
	exportseg_t *all_next;		/* all_exportsegs_hash pointer */
};



typedef struct import_ncslice {
	off_t seg_offset;
	ncslice_t ncslice;
	off_t ncslice_offset;
	size_t  len;
} import_ncslice_t;



/*
 * each connection to a segment is represented with an importseg structure
 */
struct __rsm_memseg_import_handle {
	krwlock_t rw_lock;		/* lock for put/get and disconnect */
	boolean_t valid;		/* is importseg being removed? */
	boolean_t unpublished;		/* is segment still published? */
	iseginfo_t *iseginfo;		/* iseginfo for this segment */
	wrsm_network_t *network;	/* local controller info */
	boolean_t kernel_user;		/* is a kernel thread using put/get? */
	rsm_barrier_mode_t barrier_mode; /* barrier mode for this connection */
	boolean_t mappings;		/* user has mappings of segment */
	void *barrier_page;		/* user as mapping of barrier page */
	void *intr_page;		/* user as mapping of interrupt page */
	void *cesr_page;		/* user as mapping of CESR regs */
	void *reroute_page;		/* user as mapping of reroutecounters */
	boolean_t have_mappings;	/* segment mapped into user vaddr */
	rsm_resource_callback_t mapping_callback; /* callwhen segment invalid */
	rsm_resource_callback_arg_t mapping_callback_arg; /* arg for callback */

	importseg_t *iseg_next;		/* linked list off iseginfo */
	importseg_t *all_next;		/* all_importsegs_hash pointer */
};



/*
 * if a connection is requested by a kernel RSMPI client, the following
 * mappings are automatically set up
 */
#define	MEMSEG_DEVLOAD_ATTRS	(HAT_NEVERSWAP | HAT_STRICTORDER)

typedef struct mseg_kmap {
	caddr_t seg;			/* hidden segment mapping */
	caddr_t barrier_page;		/* kernel mapping of barrier page */
	caddr_t small_put_intr;		/* kernel mapping of interrupt page */
	caddr_t small_put_offset;	/* address for striped small puts */
} mseg_kmap_t;


typedef struct errorpage_t {
	wrsm_cmmu_tuple_t *tuple;
	pfn_t pfn;
} wrsm_errorpage_t;


/*
 * An iseginfo structure is created the first time a segment is imported
 * from a remote node through rsm_import_connect_memseg().  It is destroyed
 * after the last disconnect, when a session is torn down, or when the
 * remote node removes this node's access to the segment.
 */
struct iseginfo {
	kmutex_t lock;
	wrsm_network_t *network;	/* this iseginfo's network */
	cnodeid_t cnodeid;		/* cnodeid of exporting node */
	rsm_memseg_id_t segid;		/* segment id */
	size_t size;			/* length of segment */
	boolean_t unpublished;		/* node unpublished the segment */
	boolean_t send_disconnect;	/* notify when disconnecting */
	rsm_permission_t perms;		/* last set permissions for node */
	uint_t num_seg_tuples;		/* # of tuples in seg_tuples */
	import_ncslice_t *seg_tuples;	/* array of ncslice tuples for seg */
	pfn_t *pfns;			/* array of pfns for kernel mapping */
	import_ncslice_t barrier_tuple;	/* ncslice/offset for barrier page */
	import_ncslice_t small_put_tuple; /* ncslice/offset for smallput intr */
	mseg_kmap_t kernel_mapping;	/* kernel mapping info */
	int kernel_users;		/* # kernel connections (imports) */
	int errorpages;			/* reserved error pages */
	wrsm_errorpage_t *errorpage_info; /* error pages for kernel mapping */
	uint_t transfer_errors;		/* count of non-EIO errors on seg */
	int last_transfer_error;	/* reason transfer_errors incremented */
	importseg_t *importsegs;	/* connections to imported segment */
	uint_t wait_for_unmaps;		/* number of outstanding client maps */
	struct iseginfo *segid_next;	/* linked list for hash table */
};




/*
 * local node's RSMPI memory segment information (in network structure)
 */
struct wrsm_memseg {
	uint_t transfer_errors;		/* count of non-EIO errors */
	int last_transfer_error;	/* reason transfer_errors incremented */
	uint_t import_count;		/* # of importsegs for this network */
	uint_t export_count;		/* # of exportsegs for this network */
	uint_t export_published;	/* # of exportsegs published */
	uint_t export_connected;	/* # of connections (one per node) */
	uint_t bytes_bound;		/* total bound memory */
	exportseg_t *exportseg_hash[WRSM_SEGID_HASH_SIZE];
					/* published exportsegs */
};


kmutex_t	all_exportsegs_lock;
kmutex_t	all_importsegs_lock;


/*
 * remote node info
 */

typedef struct connect_info {
	exportseg_t *exportseg;
	struct connect_info *next;
} connect_info_t;


struct wrsm_node_memseg {
	kmutex_t lock;
	boolean_t removing_session;	/* removing session to node */
	connect_info_t *connected;	/* local segments node has imported */
	iseginfo_t *iseginfo_hash[WRSM_SEGID_HASH_SIZE];
					/* segments imported from node */
	uint_t wait_for_unmaps;		/* importsegs with client maps */
	uint_t transfer_errors;		/* count of non-EIO errors */
	int last_transfer_error;	/* reason transfer_errors incremented */
};



/*
 * messages
 */

typedef struct connect_msg {
	rsm_memseg_id_t segid;
} connect_msg_t;


typedef struct connect_resp {
	uint_t err;
	rsm_permission_t perms;
	size_t size;
	uint_t num_seg_tuples;
} connect_resp_t;


typedef struct smallputmap_msg {
	rsm_memseg_id_t segid;
} smallputmap_msg_t;

typedef struct smallputmap_resp {
	uint_t err;
	import_ncslice_t small_put_tuple;
} smallputmap_resp_t;


typedef struct barriermap_msg {
	rsm_memseg_id_t segid;
} barriermap_msg_t;

typedef struct barriermap_resp {
	uint_t err;
	import_ncslice_t barrier_tuple;
} barriermap_resp_t;


typedef struct segmap_msg {
	rsm_memseg_id_t segid;
	uint_t tuple_index;
} segmap_msg_t;

#define	MAP_MSG_TUPLES	((WRSM_MESSAGE_BODY_SIZE - (2 * sizeof (uint_t))) \
	/ sizeof (import_ncslice_t))

typedef struct segmap_resp {
	uint_t err;
	uint_t num_tuples;
	import_ncslice_t tuples[MAP_MSG_TUPLES];
} segmap_resp_t;


typedef struct disconnect_msg {
	rsm_memseg_id_t segid;
} disconnect_msg_t;

typedef struct unpublish_msg {
	rsm_memseg_id_t segid;
} unpublish_msg_t;

typedef struct unpublish_resp {
	int status;
} unpublish_resp_t;

/* status values for unpublish_resp */
#define	WC_DISCONNECTED	0x01
#define	WC_CONNECTED	0x02


typedef struct access_msg {
	rsm_memseg_id_t segid;
	rsm_permission_t perms;
} access_msg_t;

int wrsm_lock_importseg(importseg_t *importseg, krw_t rw);
boolean_t iseginfo_sess_teardown(wrsm_node_t *node);
int create_segment_mapping(iseginfo_t *iseginfo);

boolean_t exportseg_sess_teardown(wrsm_node_t *node);

/* Support for plugin library for RSMAPI */
int
wrsm_memseg_remote_node_to_iseginfo(uint32_t ctrl_num,
    cnodeid_t remote_cnode, rsm_memseg_id_t segid, iseginfo_t **iseginfo);
int wrsm_memseg_segmap(dev_t dev, off_t off, struct as *asp, caddr_t *addrp,
    off_t len, unsigned int prot, unsigned int maxprot,
    unsigned int flags, cred_t *cred);
int wrsm_memseg_devmap(dev_t dev, devmap_cookie_t handle, offset_t off,
    size_t len, size_t *maplen, uint_t model);
int wrsm_smallput_plugin_ioctl(int minor, int cmd, intptr_t arg, int flag,
    cred_t *cred_p, int *rval_p);

typedef struct smallput_header {
	uint32_t reserved;	/* reserved for DMV interrupt info */
	uint8_t	len;		/* value ranges from 1 - 64 */
	uint8_t	start;		/* start byte in putdata (to allow alignment) */
	uint8_t sending_cnode;
	uint8_t byte_filler;
	off_t	offset;
} smallput_header_t;

#define	WRSM_SMALLPUT_BODY_SIZE (WRSM_TL_MSG_SIZE - \
				sizeof (smallput_header_t))

typedef struct wrsm_smallput_msg {
	smallput_header_t header;
	uint8_t putdata[WRSM_SMALLPUT_BODY_SIZE];
} wrsm_smallput_msg_t;



#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_MEMSEG_IMPL_H */
