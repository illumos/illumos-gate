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
 * Copyright 2001-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RSM_RSMNDI_H
#define	_SYS_RSM_RSMNDI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <thread.h>
#include <synch.h>
#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmapi_common.h>

/*
 * This structure defines the functions implemented in rsmlib
 * that the NDI library can call.
 */
typedef struct {
	int	version;
#define	RSM_LIB_FUNCS_VERSION	1
	int	(* rsm_get_hwaddr)(
	    rsmapi_controller_handle_t handle,
	    rsm_node_id_t nodeid,
	    rsm_addr_t *hwaddrp);
	int	(* rsm_get_nodeid)(
	    rsmapi_controller_handle_t handle,
	    rsm_addr_t hwaddr,
	    rsm_node_id_t *nodeidp);
} rsm_lib_funcs_t;

/* Library attributes - set by specific NDI libraries */
typedef struct {
	boolean_t	rsm_putget_map_reqd;	/* put/get require mapping */
	boolean_t	rsm_scatgath_map_reqd;	/* putv/getv require mapping */
} rsm_ndlib_attr_t;

/* The opaque barrier handle used by the RSMNDI plugin for the barrier calls */
typedef struct rsm_barrier *rsm_barrier_handle_t;

typedef struct {

	/*
	 * structure revision number:
	 */
	int rsm_version;

	/*
	 * import side memory segment operations
	 */
	int (* rsm_memseg_import_connect)
	    (rsmapi_controller_handle_t controller,
	    rsm_node_id_t node_id,
	    rsm_memseg_id_t segment_id,
	    rsm_permission_t perm,
	    rsm_memseg_import_handle_t *im_memseg);
	int (* rsm_memseg_import_disconnect)
	    (rsm_memseg_import_handle_t im_memseg);

	/*
	 * import side memory segment operations (read access functions):
	 */
	int (* rsm_memseg_import_get8)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint8_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_get16)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint16_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_get32)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint32_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_get64)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint64_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_get)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    void *dst_addr,
	    size_t length);

	/*
	 * import side memory segment operations (read access functions):
	 */
	int (* rsm_memseg_import_put8)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint8_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_put16)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint16_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_put32)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint32_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_put64)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint64_t *datap,
	    ulong_t rep_cnt,
	    boolean_t swap);
	int (* rsm_memseg_import_put)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    void *src_addr,
	    size_t length);

	/*
	 * import side memory segment operations (barriers):
	 */
	int (* rsm_memseg_import_init_barrier)
	    (rsm_memseg_import_handle_t im_memseg,
	    rsm_barrier_type_t type,
	    rsm_barrier_handle_t barrier);

	int (* rsm_memseg_import_open_barrier)(rsm_barrier_handle_t barrier);

	int (* rsm_memseg_import_order_barrier)(rsm_barrier_handle_t barrier);

	int (* rsm_memseg_import_close_barrier)(rsm_barrier_handle_t barrier);

	int (* rsm_memseg_import_destroy_barrier)(rsm_barrier_handle_t barrier);

	int (* rsm_memseg_import_get_mode)
	    (rsm_memseg_import_handle_t im_memseg,
	    rsm_barrier_mode_t *mode);

	int (* rsm_memseg_import_set_mode)
	    (rsm_memseg_import_handle_t im_memseg,
	    rsm_barrier_mode_t mode);


	/*
	 * import side memory segment data transfer operations.
	 */
	int (* rsm_memseg_import_putv)(rsm_scat_gath_t *sg_io);
	int (* rsm_memseg_import_getv)(rsm_scat_gath_t *sg_io);

	int (* rsm_create_localmemory_handle)
	    (rsmapi_controller_handle_t controller,
	    rsm_localmemory_handle_t *local_handle_p,
	    caddr_t local_vaddr, size_t len);

	int (* rsm_free_localmemory_handle)
	    (rsm_localmemory_handle_t local_handle);

	int (* rsm_register_lib_funcs)
	    (rsm_lib_funcs_t *libfuncs);
	int (* rsm_get_lib_attr)
	    (rsm_ndlib_attr_t **libattr);
	int (* rsm_closedevice)
	    (rsmapi_controller_handle_t controller);
} rsm_segops_t;

#define	RSM_LIB_VERSION	1

/* library internal controller attribute structure */
typedef struct {
	/* following fields should be identical to rsmapi_controller_attr_t */
	uint_t		attr_direct_access_sizes;
	uint_t		attr_atomic_sizes;
	size_t		attr_page_size;
	size_t		attr_max_export_segment_size;
	size_t		attr_tot_export_segment_size;
	ulong_t		attr_max_export_segments;
	size_t		attr_max_import_map_size;
	size_t		attr_tot_import_map_size;
	ulong_t		attr_max_import_segments;
	/* following fields are for internal use */
	rsm_addr_t	attr_controller_addr;
} rsm_int_controller_attr_t;

typedef struct rsm_controller {
	void			*cntr_privdata;
	struct rsm_controller	*cntr_next;
	int			cntr_fd;
	int			cntr_refcnt;
	int			cntr_unit;
	char			*cntr_name;	/* generic type eg. sci   */
	rsm_segops_t		*cntr_segops;
	struct rsmqueue		*cntr_rqlist;	/* list of receive queues */
	rsm_int_controller_attr_t	cntr_attr;
	rsm_ndlib_attr_t	*cntr_lib_attr;
	mutex_t			cntr_lock;
	cond_t			cntr_cv;
} rsm_controller_t;


typedef enum {
	EXPORT_CREATE = 0x1,
	EXPORT_BIND,
	EXPORT_PUBLISH,
	IMPORT_CONNECT,
	IMPORT_DISCONNECT,
	IMPORT_MAP,
	IMPORT_UNMAP
} rsm_seg_state_t;

typedef struct {
	void		*rsmseg_privdata;
	rsm_segops_t	*rsmseg_ops;
	rsm_seg_state_t	rsmseg_state;
	caddr_t		rsmseg_vaddr;	/* base address of segment */
	size_t		rsmseg_size;	/* size of segment */
	size_t		rsmseg_maplen;	/* length of mapped region */
	rsm_node_id_t	rsmseg_nodeid;
	rsm_memseg_id_t	rsmseg_keyid;
	int		rsmseg_fd;
	int		rsmseg_pollfd_refcnt;
	rsm_permission_t rsmseg_perm;
	rsm_controller_t *rsmseg_controller;
	rsm_barrier_mode_t rsmseg_barmode;
	void		*rsmseg_data;
	uint16_t	*rsmseg_bar;
	uint16_t	rsmseg_gnum;	/* generation number */
	int		rsmseg_type;
	mutex_t		rsmseg_lock;
	rsmapi_barrier_t	*rsmseg_barrier; /* used in put/get routines */
	offset_t	rsmseg_mapoffset; /* seg offset where mmapped */
	uint32_t	rsmseg_flags;
	minor_t		rsmseg_rnum; /* resource number of the segment */
} rsmseg_handle_t;

/*
 * defines for rsmseg_flags
 */
#define	RSM_IMPLICIT_MAP	0x00000001	/* segment mapped implicitly */

/* This is a template for all barrier implementations */
typedef struct {
	rsmseg_handle_t	*rsmbar_seg;
	uint16_t	rsmbar_gen; /* generation number */
	void		*rsmbar_privdata;
} rsmbar_handle_t;

/*
 * These macros set and get the private data pointer in the opaque barrier
 * structure for Network plugins.
 */
#define	RSMNDI_BARRIER_SETPRIV(HANDLE, ADDR) \
		((rsmbar_handle_t *)HANDLE)->rsmbar_privdata = (void *)ADDR;

#define	RSMNDI_BARRIER_GETPRIV(HANDLE) \
		((rsmbar_handle_t *)HANDLE)->rsmbar_privdata

#define	RSMNDI_BARRIER_GETSEG(HANDLE)	\
		((rsmbar_handle_t *)HANDLE)->rsmbar_seg

#define	RSMNDI_BARRIER_GETUNIT(HANDLE)	\
	((rsmbar_handle_t *)HANDLE)->rsmbar_seg->rsmseg_controller->cntr_unit

/*
 * These macros set and get the private data pointer in the opaque segment
 * structure for Network plugins.
 */
#define	RSMNDI_SEG_SETPRIV(HANDLE, ADDR) \
		((rsmseg_handle_t *)HANDLE)->rsmseg_privdata = (void *)ADDR;

#define	RSMNDI_SEG_GETPRIV(HANDLE) \
		((rsmseg_handle_t *)HANDLE)->rsmseg_privdata

/*
 * Get the controller unit number from a opaque segment structure.
 */

#define	RSMNDI_SEG_GETUNIT(HANDLE) \
		((rsmseg_handle_t *)HANDLE)->rsmseg_controller->cntr_unit

/*
 * These macros set and get the private data pointer in the opaque controller
 * structure for Network plugins.
 */
#define	RSMNDI_CNTRLR_SETPRIV(HANDLE, ADDR) \
		((rsm_controller_t *)HANDLE)->cntr_privdata = (void *)ADDR;

#define	RSMNDI_CNTRLR_GETPRIV(HANDLE) \
		((rsm_controller_t *)HANDLE)->cntr_privdata

/*
 * Get the controller unit number from a opaque controller structure.
 */
#define	RSMNDI_CNTRLR_GETUNIT(HANDLE) \
		((rsm_controller_t *)HANDLE)->cntr_unit

/*
 * This macro returns an address inside a segment given the segment handle
 * and a byte offset.
 */
#define	RSMNDI_GET_MAPADDR(HANDLE, OFFSET) \
		(((rsmseg_handle_t *)HANDLE)->rsmseg_vaddr + OFFSET)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_RSM_RSMNDI_H */
