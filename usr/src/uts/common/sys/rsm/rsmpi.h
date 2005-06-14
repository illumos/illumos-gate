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
 * Copyright (c) 1998-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_RSM_RSMPI_H
#define	_SYS_RSM_RSMPI_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _KERNEL
typedef void * ddi_as_handle_t;
#endif

#include <sys/sunddi.h>
#include <sys/rsm/rsm_common.h>

struct __rsm_resource_callback_arg;
typedef struct __rsm_resource_callback_arg *rsm_resource_callback_arg_t;

typedef void (*rsm_resource_callback_t)(rsm_resource_callback_arg_t);

struct __rsm_callback_arg;
typedef struct __rsm_callback_arg *rsm_callback_arg_t;

typedef void (*rsm_callback_t)(rsm_callback_arg_t);

/* Values for resource callback function pointer */
#define	RSM_RESOURCE_SLEEP	(rsm_resource_callback_t)0
#define	RSM_RESOURCE_DONTWAIT	(rsm_resource_callback_t)-1

/* rsm_seg_create() flags values */
#define	RSM_ALLOW_UNBIND_REBIND		0x01

typedef uint_t rsm_intr_t;
typedef rsm_intr_t rsm_intr_service_t;
/* The following definitions used to describe the ranges fro rsm_intr_t */
#define	RSM_INTR_T_DRV_BASE		0
#define	RSM_INTR_T_DRV_END		0x3F
#define	RSM_INTR_T_FRM_BASE		0x40
#define	RSM_INTR_T_FRM_END		0x4F
#define	RSM_INTR_T_RESERVED_BASE	0x50
#define	RSM_INTR_T_RESERVED_END		0x5F
#define	RSM_INTR_T_SUN_BASE		0x60
#define	RSM_INTR_T_SUN_END		0xDF
#define	RSM_INTR_T_USR_BASE		0xE0
#define	RSM_INTR_T_USR_END		0xFF
#define	RSM_INTR_T_NSVC			0x100

/* kstat's ks_name for RSMPI controller drivers */
#define	RSM_KS_NAME			"rsmpi_stat"

/* named kstat component names */
#define	RSM_KS_CTLR_STATE		"ctlr_state"	/* CHAR */
#define	RSM_KS_ADDR			"addr"		/* UINT64 */
#define	RSM_KS_EX_MEMSEGS		"ex_memsegs"	/* UINT32 */
#define	RSM_KS_EX_MEMSEGS_PUB		"ex_memsegs_pub"	/* UINT32 */
#define	RSM_KS_EX_MEMSEGS_CON		"ex_memsegs_con"	/* UINT32 */
#define	RSM_KS_BYTES_BOUND		"bytes_bound"		/* UINT64 */
#define	RSM_KS_IM_MEMSEGS_CON		"im_memsegs_con"	/* UINT32 */
#define	RSM_KS_SENDQS			"sendqs"		/* UINT64 */
#define	RSM_KS_HANDLERS			"handlers"		/* UINT64 */

/* The following are the possible values of RSM_KS_CTLR_STATE */
#define	RSM_AE_CTLR_DOWN	"rsm_down"
#define	RSM_AE_CTLR_UP		"rsm_up"


struct __rsm_send_q_handle;
typedef struct __rsm_send_q_handle *rsm_send_q_handle_t;

/* rsm_intr_send_q_create flags values */
#define	RSM_INTR_SEND_Q_NO_FENCE	0x1
#define	RSM_INTR_SEND_Q_FULL_FAIL	0x2
#define	RSM_INTR_SEND_Q_UNRELIABLE	0x4

typedef struct {
	void	*is_data;
	size_t	is_size;
	int	is_flags;
	clock_t	is_wait;
} rsm_send_t;

/* rsm_send_t flags values */
#define	RSM_INTR_SEND_QUEUE		0x1
#define	RSM_INTR_SEND_DELIVER		0x2
#define	RSM_INTR_SEND_POLL		0x4
#define	RSM_INTR_SEND_SLEEP		0x8
#define	RSM_INTR_SEND_LOWER_FENCE	0x10

typedef enum {
	RSM_INTR_HAND_UNCLAIMED = 0,
	RSM_INTR_HAND_CLAIMED = 1,
	RSM_INTR_HAND_CLAIMED_EXCLUSIVE = 2
} rsm_intr_hand_ret_t;

typedef enum {
	RSM_INTR_Q_OP_CREATE,
	RSM_INTR_Q_OP_CONFIGURE,
	RSM_INTR_Q_OP_DESTROY,
	RSM_INTR_Q_OP_RECEIVE,
	RSM_INTR_Q_OP_DROP
} rsm_intr_q_op_t;

struct __rsm_intr_hand_arg;
typedef struct __rsm_intr_hand_arg *rsm_intr_hand_arg_t;

struct __rsm_registry_item;
typedef struct __rsm_registry_item *rsm_registry_item_t;

typedef int   rsm_intr_pri_t;

typedef struct {
	rsm_addr_t	 ae_addr;	/* node hwaddr allowed access */
	rsm_permission_t ae_permission;	/* permissions for node */
} rsm_access_entry_t;
/*
 * ae_addr can be set to the following value to mean that the permissions
 * should apply to all nodes accessible through this RSM controller
 */
#define	RSM_ACCESS_PUBLIC	0xFFFF

struct __rsm_controller_handle;
typedef struct __rsm_controller_handle *rsm_controller_handle_t;

/*
 * The following typedef is used to represent a controller object.
 */
typedef struct rsm_controller_object {
	struct rsm_ops *ops;
	rsm_controller_handle_t handle;
} rsm_controller_object_t;

typedef rsm_intr_hand_ret_t (*rsm_intr_hand_t)(
    rsm_controller_object_t *controller,
    rsm_intr_q_op_t operation,
    rsm_addr_t sender,
    void *data,
    size_t size,
    rsm_intr_hand_arg_t arg);

typedef struct {
	enum { RSM_MEM_VADDR,
		RSM_MEM_BUF,
		RSM_MEM_HANDLE,
		RSM_MEM_INVALID } ms_type;
	union {
		struct {
			void *vaddr;
			size_t length;
			ddi_as_handle_t as;
		} vr;
		struct buf *bp;
		rsm_memseg_export_handle_t	handle;
	} ms_memory;
#define	ms_bp		ms_memory.bp
#define	ms_vaddr	ms_memory.vr.vaddr
#define	ms_length	ms_memory.vr.length
#define	ms_as		ms_memory.vr.as
} rsm_memory_local_t;

typedef struct {
	rsm_memory_local_t		local_mem;
	size_t				local_offset;
	rsm_memseg_import_handle_t	remote_handle;
	size_t				remote_offset;
	size_t				transfer_length;
} rsmpi_iovec_t;

typedef struct {
	ulong_t		io_request_count;	/* size of iovec array */
	ulong_t		io_residual_count;	/* zero for success    */
	uio_seg_t	io_segflg;		/* user/kernel addr    */
	rsmpi_iovec_t	*iovec;			/* ptr to array		*/
} rsmpi_scat_gath_t;

typedef struct {
	char			*attr_name;
	rsm_addr_t		attr_controller_addr;
	uint_t			attr_direct_access_sizes;
	uint_t			attr_atomic_sizes;
	uint_t			attr_error_sizes;
	uint_t			attr_error_behavior;
	boolean_t		attr_mmu_protections;
	size_t			attr_page_size;
	size_t			attr_max_export_segment_size;
	size_t			attr_tot_export_segment_size;
	ulong_t			attr_max_export_segments;
	size_t			attr_max_import_map_size;
	size_t			attr_tot_import_map_size;
	ulong_t			attr_max_import_segments;
	boolean_t		attr_io_space_exportable;
	boolean_t		attr_imported_space_ioable;
	boolean_t		attr_intr_sender_ident;
	size_t			attr_intr_data_size_max;
	uint_t			attr_intr_data_align;
	boolean_t		attr_intr_piggyback;
	boolean_t	attr_resource_callbacks;
} rsm_controller_attr_t;

/*
 * The following three defines are possible values for attr_error_behavior
 * field of the rsm_controller_attr_t struct.
 */
#define	RSM_ERR_NOCHANGE	0
#define	RSM_ERR_ZEROES		0x1
#define	RSM_ERR_RANDOM		0x2

typedef struct rsm_ops {

	/*
	 * structure revision number:
	 */
	uint_t rsm_version;

	/*
	 * export side memory segment operations:
	 */
	int (*rsm_seg_create)
	    (rsm_controller_handle_t controller,
	    rsm_memseg_export_handle_t *memseg,
	    size_t	size,
	    uint_t	flags,
	    rsm_memory_local_t *memory,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);
	int (*rsm_seg_destroy)
	    (rsm_memseg_export_handle_t handle);
	int (*rsm_bind)
	    (rsm_memseg_export_handle_t memseg,
	    off_t offset,
	    rsm_memory_local_t *memory,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);
	int (*rsm_unbind)
	    (rsm_memseg_export_handle_t memseg,
	    off_t offset,
	    size_t length);
	int (*rsm_rebind)
	    (rsm_memseg_export_handle_t memseg,
	    off_t offset,
	    rsm_memory_local_t *memory,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);
	int (*rsm_publish)
	    (rsm_memseg_export_handle_t memseg,
	    rsm_access_entry_t access_list[],
	    uint_t access_list_length,
	    rsm_memseg_id_t segment_id,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);
	int (*rsm_unpublish)
	    (rsm_memseg_export_handle_t memseg);
	int (*rsm_republish)
	    (rsm_memseg_export_handle_t memseg,
	    rsm_access_entry_t access_list[],
	    uint_t access_list_length,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);

	/*
	 * import side memory segment operations
	 */
	int (*rsm_connect)
	    (rsm_controller_handle_t controller,
	    rsm_addr_t addr,
	    rsm_memseg_id_t segment_id,
	    rsm_memseg_import_handle_t *im_memseg);

	int (*rsm_disconnect)
	    (rsm_memseg_import_handle_t im_memseg);

	/*
	 * import side memory segment operations (read access functions):
	 */
	int (* rsm_get8)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint8_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_get16)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint16_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_get32)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint32_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_get64)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint64_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_get)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    void *datap,
	    size_t length);

	/*
	 * import side memory segment operations (write access functions)
	 */
	int (* rsm_put8)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint8_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_put16)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint16_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_put32)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint32_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_put64)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    uint64_t *datap,
	    ulong_t rep_cnt,
	    boolean_t byte_swap);
	int (* rsm_put)
	    (rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    void *datap,
	    size_t length);

	/*
	 * import side memory segment operations (mapping)
	 */
	int (*rsm_map)(rsm_memseg_import_handle_t im_memseg,
	    off_t offset,
	    size_t len,
	    size_t *maplen,
	    dev_info_t **dipp,
	    uint_t *register_number,
	    off_t *register_offset,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t callback_arg);

	int (*rsm_unmap)
	    (rsm_memseg_import_handle_t im_memseg);

	/*
	 * import side memory segment operations (barriers):
	 */
	int (* rsm_open_barrier_region)
	    (rsm_memseg_import_handle_t region,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_regions)
	    (rsm_memseg_import_handle_t regions[],
	    uint_t num_regions,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_node)
	    (rsm_controller_handle_t controller,
	    rsm_addr_t addr,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_ctrl)
	    (rsm_controller_handle_t controller,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_region_thr)
	    (rsm_memseg_import_handle_t region,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_regions_thr)
	    (rsm_memseg_import_handle_t regions[],
	    uint_t num_regions,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_node_thr)
	    (rsm_controller_handle_t controller,
	    rsm_addr_t addr,
	    rsm_barrier_t *barrier);
	int (* rsm_open_barrier_ctrl_thr)
	    (rsm_controller_handle_t controller,
	    rsm_barrier_t *barrier);
	int (* rsm_close_barrier)
	    (rsm_barrier_t *barrier);
	int (* rsm_reopen_barrier)
	    (rsm_barrier_t *barrier);
	int (* rsm_order_barrier)
	    (rsm_barrier_t *barrier);
	int (* rsm_thread_init)
	    (rsm_controller_handle_t controller);
	int (* rsm_thread_fini)
	    (rsm_controller_handle_t controller);
	int (* rsm_get_barrier_mode)
	    (rsm_memseg_import_handle_t im_memseg,
	    rsm_barrier_mode_t *mode);
	int (* rsm_set_barrier_mode)
	    (rsm_memseg_import_handle_t im_memseg,
	    rsm_barrier_mode_t mode);

	/*
	 * sending side interrupt operations:
	 */
	int (* rsm_sendq_create)
	    (rsm_controller_handle_t controller,
	    rsm_addr_t addr,
	    rsm_intr_service_t service,
	    rsm_intr_pri_t pri,
	    ulong_t qdepth,
	    uint_t flags,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t arg,
	    rsm_send_q_handle_t *iqp);
	int (* rsm_sendq_config)
	    (rsm_send_q_handle_t iq,
	    rsm_intr_pri_t pri,
	    ulong_t qdepth,
	    uint_t flags,
	    rsm_resource_callback_t callback,
	    rsm_resource_callback_arg_t arg);
	int (* rsm_sendq_destroy)
	    (rsm_send_q_handle_t iq);
	int (* rsm_send)
	    (rsm_send_q_handle_t iq,
	    rsm_send_t *is,
	    rsm_barrier_t *barrier);


	/*
	 * receiving side interrupt operations:
	 */
	int (* rsm_register_handler)
	    (rsm_controller_handle_t controller,
	    rsm_controller_object_t *controller_obj,
	    rsm_intr_t type,
	    rsm_intr_hand_t handler,
	    rsm_intr_hand_arg_t handler_arg,
	    rsm_addr_t senders_list[],
	    uint_t senders_list_length);

	int (* rsm_unregister_handler)
	    (rsm_controller_handle_t controller,
	    rsm_intr_t type,
	    rsm_intr_hand_t handler,
	    rsm_intr_hand_arg_t handler_arg);


	/* scatter-gather I/O */
	int (* rsm_memseg_import_getv)
	    (rsm_controller_handle_t cp,
	    rsmpi_scat_gath_t *sg_io);
	int (* rsm_memseg_import_putv)
	    (rsm_controller_handle_t cp,
	    rsmpi_scat_gath_t *sg_io);

	/* Management operation */
	int (*rsm_get_peers)
	    (rsm_controller_handle_t controller,
	    rsm_addr_t *addr_list,
	    uint_t count,
	    uint_t *num_addrs);

	/* Extension operation */
	int (*rsm_extension)
	    (rsm_controller_handle_t controller,
	    char *extname,
	    void *extobj);

} rsm_ops_t;

/*
 * service module function templates:
 */

int rsm_get_controller(const char *name, uint_t number,
    rsm_controller_object_t *controller,
    uint_t version);

int rsm_release_controller(const char *name, uint_t number,
    rsm_controller_object_t *controller);

int rsm_get_controller_attr(rsm_controller_handle_t,
    rsm_controller_attr_t **attrp);
/*
 * MACROS for Clients requesting services via RSMPI module
 */

/*
 * Export Side segment operations
 */

#define	RSM_SEG_CREATE(controller, memseg, size, flags, memory, callback, \
	callback_arg) \
	(*((controller).ops->rsm_seg_create)) \
	((controller).handle, (memseg), (size), (flags), (memory), \
	(callback), (callback_arg))
#define	RSM_SEG_DESTROY(controller, memseg) \
	(*((controller).ops->rsm_seg_destroy)) \
	((memseg))
#define	RSM_BIND(controller, memseg, offset, memory, callback, \
	callback_arg) \
	(*((controller).ops->rsm_bind)) \
	((memseg), offset, (memory), (callback), (callback_arg))
#define	RSM_UNBIND(controller, memseg, offset, length) \
	(*((controller).ops->rsm_unbind)) \
	((memseg), (offset), (length))
#define	RSM_REBIND(controller, memseg, offset, memory, callback, \
	callback_arg) \
	(*((controller).ops->rsm_rebind)) \
	((memseg), offset, (memory), (callback), (callback_arg))
#define	RSM_PUBLISH(controller, memseg, access_list, access_list_length, \
	segment_id, callback, callback_arg) \
	(*((controller).ops->rsm_publish)) \
	((memseg), access_list,	access_list_length, segment_id, \
	(callback), (callback_arg))
#define	RSM_UNPUBLISH(controller, memseg) \
	(*((controller).ops->rsm_unpublish)) \
	((memseg))
#define	RSM_REPUBLISH(controller, memseg,  access_list, access_list_length, \
	callback, callback_arg) \
	(*((controller).ops->rsm_republish)) \
	((memseg), (access_list), (access_list_length), (callback), \
	(callback_arg))
#define	RSM_CONNECT(controller, addr, segment_id, im_memseg) \
	(*((controller).ops->rsm_connect)) \
	((controller).handle, (addr), (segment_id), (im_memseg))
#define	RSM_DISCONNECT(controller, im_memseg) \
	(*((controller).ops->rsm_disconnect))  \
	((im_memseg))

	/*
	 * import side memory segment operations (read access functions)
	 */

#define	RSM_GET8(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_get8)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_GET16(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_get16)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_GET32(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_get32)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_GET64(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_get64)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_GET(controller, im_memseg, offset, dst_addr, length) \
	(*((controller).ops->rsm_get)) \
	((im_memseg), (offset), (dst_addr), (length))

	/*
	 * import side memory segment operations (write access functions)
	 */

#define	RSM_PUT8(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_put8)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_PUT16(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_put16)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_PUT32(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_put32)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_PUT64(controller, im_memseg, offset, datap, rep_cnt, byte_swap) \
	(*((controller).ops->rsm_put64)) \
	((im_memseg), (offset), (datap), (rep_cnt), (byte_swap))
#define	RSM_PUT(controller, im_memseg, offset, datap, length) \
	(*((controller).ops->rsm_put)) \
	((im_memseg), (offset), (datap), (length))

	/*
	 * import side memory segment operations (mapping):
	 */

#define	RSM_MAP(controller, im_memseg, offset, length, maplen, dipp, \
	dev_register, dev_offset, callback, arg) \
	(*((controller).ops->rsm_map)) \
	((im_memseg), (offset), (length), (maplen), (dipp), (dev_register), \
	(dev_offset), (callback), (arg))
#define	RSM_UNMAP(controller, im_memseg) \
	(*((controller).ops->rsm_unmap)) \
	((im_memseg))

	/*
	 * import side memory segment operations (barriers):
	 */

#define	RSM_OPEN_BARRIER_REGION(controller, region, barrier) \
	(*((controller).ops->rsm_open_barrier_region)) \
	((region), (barrier))
#define	RSM_OPEN_BARRIER_REGIONS(controller, regions, num_regions, barrier) \
	(*((controller).ops->rsm_open_barrier_regions)) \
	((regions), (num_regions), (barrier))
#define	RSM_OPEN_BARRIER_NODE(controller, addr, barrier) \
	(*((controller).ops-> rsm_open_barrier_node)) \
	((controller).handle, (addr), (barrier))
#define	RSM_OPEN_BARRIER_CTRL(controller, barrier) \
	(*((controller).ops->rsm_open_barrier_ctrl)) \
	((controller).handle, (barrier))
#define	RSM_OPEN_BARRIER_REGION_THR(controller, region, barrier) \
	(*((controller).ops->rsm_open_barrier_region_thr)) \
	((region), (barrier))
#define	RSM_OPEN_BARRIER_REGIONS_THR(controller, regions, num_regions, barrier)\
	(*((controller).ops->rsm_open_barrier_regions_thr)) \
	((regions), (num_regions), (barrier))
#define	RSM_OPEN_BARRIER_NODE_THR(controller, addr, barrier) \
	(*((controller).ops->rsm_open_barrier_node_thr)) \
	((controller).handle, (addr), (barrier))
#define	RSM_OPEN_BARRIER_CTRL_THR(controller, barrier) \
	(*((controller).ops->rsm_open_barrier_ctrl_thr)) \
	((controller).handle, (barrier));
#define	RSM_CLOSE_BARRIER(controller, barrier) \
	(*((controller).ops->rsm_close_barrier)) \
	((barrier))
#define	RSM_REOPEN_BARRIER(controller, barrier) \
	(*((controller).ops->rsm_reopen_barrier)) \
	((barrier));
#define	RSM_ORDER_BARRIER(controller, barrier) \
	(*((controller).ops->rsm_order_barrier)) \
	((barrier))
#define	RSM_THREAD_INIT(controller) \
	(*((controller).ops->rsm_thread_init)) \
	((controller).handle)
#define	RSM_THREAD_FINI(controller) \
	(*((controller).ops->rsm_thread_fini)) \
	((controller).handle)
#define	RSM_GET_BARRIER_MODE(controller, im_memseg, mode) \
	(*((controller).ops->rsm_get_barrier_mode)) \
	((im_memseg), (mode))
#define	RSM_SET_BARRIER_MODE(controller, im_memseg, mode) \
	(*((controller).ops->rsm_set_barrier_mode)) \
	((im_memseg), (mode))
	/*
	 * sending side interrupt operations:
	 */

#define	RSM_SENDQ_CREATE(controller, addr, service, pri, qdepth, flags, \
	callback, arg, iqp) \
	(*((controller).ops->rsm_sendq_create)) \
	((controller).handle, (addr), (service), (pri), (qdepth), (flags), \
	(callback), (arg),  (iqp))
#define	RSM_SENDQ_CONFIG(controller, iq, pri, qdepth, flags, callback, arg) \
	(*((controller).ops->rsm_sendq_config)) \
	((iq),  (pri),  (qdepth), (flags), \
	(callback), (arg))
#define	RSM_SENDQ_DESTROY(controller, iq) \
	(*((controller).ops->rsm_sendq_destroy)) \
	((iq))
#define	RSM_SEND(controller, iq, is, barrier) \
	(*((controller).ops->rsm_send)) \
	((iq), (is), (barrier))

	/*
	 * receiving side interrupt operations:
	 */
#define	RSM_REGISTER_HANDLER(controller, type, handler, handler_arg, \
	senders_list, senders_list_length) \
	(*((controller).ops->rsm_register_handler)) \
	((controller).handle, &(controller), (type), (handler), (handler_arg), \
	(senders_list), (senders_list_length))
#define	RSM_UNREGISTER_HANDLER(controller, type, handler, handler_arg) \
	(*((controller).ops->rsm_unregister_handler))  \
	((controller).handle, (type), (handler), (handler_arg))
#define	RSM_GETV(controller, sg_io) \
	(*((controller).ops->rsm_memseg_import_getv)) \
	((controller).handle, (sg_io))
#define	RSM_PUTV(controller, sg_io) \
	(*((controller).ops->rsm_memseg_import_putv)) \
	((controller).handle, (sg_io))
#define	RSM_GET_PEERS(controller, addr_list, count, num_addrs) \
	(*((controller).ops->rsm_get_peers)) \
	((controller).handle, (addr_list), (count), (num_addrs))
#define	RSM_EXTENSION(controller, extname, extobj) \
	(*((controller).ops->rsm_extension)) \
	((controller).handle, (extname), (extobj))

#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_RSM_RSMPI_H */
