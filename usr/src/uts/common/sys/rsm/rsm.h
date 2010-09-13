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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_RSM_RSM_H
#define	_SYS_RSM_RSM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/rsm/rsm_common.h>
#include <sys/rsm/rsmapi_common.h>

#define	RSM_IOCTL_CONTROLLER	0x00
#define	RSM_IOCTL_EXPORT_SEG	0x10
#define	RSM_IOCTL_IMPORT_SEG	0x20
#define	RSM_IOCTL_QUEUE		0x30
#define	RSM_IOCTL_TOPOLOGY	0x40
#define	RSM_IOCTL_BAR		0x50
#define	RSM_IOCTL_ERRCNT	0x60
#define	RSM_IOCTL_BELL		0x70
#define	RSM_IOCTL_IOVEC		0x80
#define	RSM_IOCTL_MAP_ADDR	0x90

#define	RSM_IOCTL_ATTR	RSM_IOCTL_CONTROLLER + 0x0 /* get device attribute */
#define	RSM_IOCTL_BAR_INFO RSM_IOCTL_CONTROLLER + 0x1 /* get barrier info */

#define	RSM_IOCTL_CREATE	RSM_IOCTL_EXPORT_SEG + 0x1
#define	RSM_IOCTL_BIND		RSM_IOCTL_EXPORT_SEG + 0x3
#define	RSM_IOCTL_REBIND	RSM_IOCTL_EXPORT_SEG + 0x4
#define	RSM_IOCTL_UNBIND	RSM_IOCTL_EXPORT_SEG + 0x5
#define	RSM_IOCTL_PUBLISH	RSM_IOCTL_EXPORT_SEG + 0x6
#define	RSM_IOCTL_REPUBLISH	RSM_IOCTL_EXPORT_SEG + 0x7
#define	RSM_IOCTL_UNPUBLISH	RSM_IOCTL_EXPORT_SEG + 0x8

#define	RSM_IOCTL_CONNECT	RSM_IOCTL_IMPORT_SEG + 0x0
#define	RSM_IOCTL_DISCONNECT	RSM_IOCTL_IMPORT_SEG + 0x1

#define	RSM_IOCTL_TOPOLOGY_SIZE	RSM_IOCTL_TOPOLOGY + 0x1
#define	RSM_IOCTL_TOPOLOGY_DATA	RSM_IOCTL_TOPOLOGY + 0x2

#define	RSM_IOCTL_GETV		RSM_IOCTL_IOVEC	+ 0x1
#define	RSM_IOCTL_PUTV		RSM_IOCTL_IOVEC	+ 0x2

#define	RSM_IOCTL_BAR_OPEN	RSM_IOCTL_BAR + 0x1
#define	RSM_IOCTL_BAR_ORDER	RSM_IOCTL_BAR + 0x2
#define	RSM_IOCTL_BAR_CLOSE	RSM_IOCTL_BAR + 0x3
#define	RSM_IOCTL_BAR_CHECK	RSM_IOCTL_BAR + 0x4

#define	RSM_IOCTL_RING_BELL	RSM_IOCTL_BELL + 0x1
#define	RSM_IOCTL_CONSUMEEVENT	RSM_IOCTL_BELL + 0x2

#define	RSM_IOCTL_MAP_TO_ADDR		RSM_IOCTL_MAP_ADDR + 0x1
#define	RSM_IOCTL_MAP_TO_NODEID	RSM_IOCTL_MAP_ADDR + 0x2

#define	RSM_IOCTL_CMDGRP(cmd)	((cmd) & 0xfffffff0)

#define	BETWEEN(x, lo, hi)	(((x) >= (lo)) && ((x) <= (hi)))

#define	RSM_MAX_IOVLEN	4
/*
 * DEBUG message categories
 * 0xABCD:  A=module, B=functionality C=operation D=misc
 *
 */
#define	RSM_KERNEL_AGENT	0x1000  /* kernel agent messages	*/
#define	RSM_LIBRARY		0x2000  /* rsmapi library messages	*/
#define	RSM_OPS			0x4000	/* rsmops module messages	*/
#define	RSM_PATH_MANAGER	0x8000	/* path manager messages	*/
#define	RSM_MODULE_ALL		0xF000

#define	RSM_IMPORT		0x0100  /* import operations		*/
#define	RSM_EXPORT		0x0200	/* export operations		*/
#define	RSM_LOOPBACK		0x0400	/* loopback mode		*/
#define	RSM_FUNC_ALL		0x0F00

#define	RSM_DDI			0x0010	/* dev driver infrastructure    */
#define	RSM_IO_ROUTINES		0x0020	/* put/get processing		*/
#define	RSM_IOCTL		0x0040	/* ioctl processing		*/
#define	RSM_INTR_CALLBACK	0x0080	/* interrupt processing		*/
#define	RSM_OPER_ALL		0x00F0

#define	RSM_FLOWCONTROL		0x0001	/* flow control related		*/

#define	RSM_KERNEL_ALL		(RSM_KERNEL_AGENT | RSM_PATH_MANAGER | 0x0FFF)
#define	RSM_ALL			0xFFFF  /* All of the above		*/

/*
 * DEBUG message levels
 */
#define	RSM_DEBUG_VERBOSE	6
#define	RSM_DEBUG_LVL2		5
#define	RSM_DEBUG_LVL1		4
#define	RSM_DEBUG		3
#define	RSM_NOTICE		2
#define	RSM_WARNING		1
#define	RSM_ERR			0

#ifdef	DEBUG
extern void dbg_printf(int category, int level, char *fmt, ...);
#define	DBG_DEFINE(var, value) int var = (value)
#define	DBG_DEFINE_STR(var, value) char *var = (value)
#define	DBG_ADDCATEGORY(var, category) (var |= (category))
#define	DBG_PRINTF(message) dbg_printf message
#else
#define	DBG_DEFINE(var, value)
#define	DBG_DEFINE_STR(var, value)
#define	DBG_ADDCATEGORY(var, category)
#define	DBG_PRINTF(message)
#endif /* DEBUG */

typedef	uint16_t	rsm_gnum_t;

/*
 * data struct used between rsm base library and kernel agent for IOCTLS
 */
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
} rsmka_int_controller_attr_t;

#ifdef _SYSCALL32
typedef struct {
	/* following fields should be identical to rsmapi_controller_attr_t */
	uint32_t	attr_direct_access_sizes;
	uint32_t	attr_atomic_sizes;
	uint32_t	attr_page_size;
	uint32_t	attr_max_export_segment_size;
	uint32_t	attr_tot_export_segment_size;
	uint32_t	attr_max_export_segments;
	uint32_t	attr_max_import_map_size;
	uint32_t	attr_tot_import_map_size;
	uint32_t	attr_max_import_segments;
	/* the following fields are for internal use */
	rsm_addr_t	attr_controller_addr;
} rsmka_int_controller_attr32_t;
#endif

/* kernel agent equivalents of rsm_iovec_t and rsm_scat_gath_t */
typedef struct {
	int					io_type;
	union {
		rsm_localmemory_handle_t	handle;
		rsm_memseg_id_t			segid;
		caddr_t				vaddr;
	} local;
	size_t					local_offset;
	size_t					remote_offset;
	size_t					transfer_len;
} rsmka_iovec_t;

#ifdef _SYSCALL32
typedef struct {
	int32_t					io_type;
	uint32_t				local;
	uint32_t				local_offset;
	uint32_t				remote_offset;
	uint32_t				transfer_len;
} rsmka_iovec32_t;
#endif

/*
 * The following 2 structures represent the scatter-gather structures used
 * within the kernel agent. Note that the io_residual_count and the flags fields
 * fields must be contiguous within these structures due to this assumption
 * made by the kernel agent when updating them in ddi_copyout.
 */
typedef struct {
	rsm_node_id_t			local_nodeid;
	ulong_t				io_request_count;
	ulong_t				io_residual_count;
	uint_t				flags;
	rsm_memseg_import_handle_t	remote_handle;
	rsmka_iovec_t			*iovec;
} rsmka_scat_gath_t;

#ifdef _SYSCALL32
typedef struct {
	rsm_node_id_t		local_nodeid;
	uint32_t		io_request_count;
	uint32_t		io_residual_count;
	uint32_t		flags;
	caddr32_t		remote_handle;
	caddr32_t		iovec;
} rsmka_scat_gath32_t;
#endif

/*
 * Define the number of pollfds upto which we don't allocate memory on heap
 *
 */
#define	RSM_MAX_POLLFDS	4

typedef struct {
	minor_t		rnum;	/* segment's resource number */
	int		fdsidx; /* index of the fd in the pollfd array */
	int		revent; /* returned event */
} rsm_poll_event_t;

#ifdef _SYSCALL32
typedef struct {
	minor_t		rnum;
	int32_t		fdsidx;
	int32_t		revent;
} rsm_poll_event32_t;
#endif

typedef struct {
	caddr_t		seglist; /* array of rsm_poll_event_t */
	uint32_t	numents;
} rsm_consume_event_msg_t;

#ifdef _SYSCALL32
typedef struct {
	caddr32_t	seglist; /* array of rsm_poll_event32_t */
	uint32_t	numents;
} rsm_consume_event_msg32_t;
#endif

typedef struct {
	int			cnum;
	caddr_t			cname;
	int			cname_len;
	caddr_t			arg;
	int			len;	/* size as well */
	caddr_t			vaddr;
	int			off;
	rsm_memseg_id_t		key;
	int			acl_len;
	rsmapi_access_entry_t	*acl;
	rsm_node_id_t		nodeid;
	rsm_addr_t		hwaddr;
	rsm_permission_t	perm;
	rsm_barrier_t		bar;
	rsm_gnum_t		gnum; /* segment generation number */
	minor_t			rnum; /* segment resource number */
} rsm_ioctlmsg_t;

#ifdef _SYSCALL32
typedef struct {
	int32_t			cnum;
	caddr32_t		cname;
	int32_t			cname_len;
	caddr32_t		arg;
	int32_t			len;	/* size as well */
	caddr32_t		vaddr;
	int32_t			off;
	rsm_memseg_id_t		key;
	int32_t			acl_len;
	caddr32_t		acl;
	rsm_node_id_t		nodeid;
	rsm_addr_t		hwaddr;
	rsm_permission_t	perm;
	rsm_barrier_t		bar;
	rsm_gnum_t		gnum; /* segment generation number */
	minor_t			rnum; /* segment resource number */
} rsm_ioctlmsg32_t;
#endif

/*
 * Remote messaging structures
 */

/* cookie to exchange between sender and receiver */
typedef union {
	struct {
		uint_t		index : 8;		/* slot number */
		uint_t		sequence : 24;		/* seq. number */
	} ic;
	uint_t			value;
}rsmipc_cookie_t;

/*  IPC msg types */
#define	RSMIPC_MSG_SEGCONNECT	0	/* connect seg	    */
#define	RSMIPC_MSG_DISCONNECT	1	/* disconnect seg   */
#define	RSMIPC_MSG_IMPORTING	2
#define	RSMIPC_MSG_NOTIMPORTING	3
#define	RSMIPC_MSG_REPLY	4	/* reply msg	    */
#define	RSMIPC_MSG_BELL		5	/* post an event    */
#define	RSMIPC_MSG_REPUBLISH	6	/* seg republished  */
#define	RSMIPC_MSG_SUSPEND	7	/* tell importers to SUSPEND	*/
#define	RSMIPC_MSG_SUSPEND_DONE	8	/* tell exporters - SUSPEND done */
#define	RSMIPC_MSG_RESUME	9	/* tell importers to RESUME	*/
#define	RSMIPC_MSG_SQREADY	10	/* sendq ready = I am up	*/
#define	RSMIPC_MSG_SQREADY_ACK	11	/* sendq ready ack = I am up too */
#define	RSMIPC_MSG_CREDIT	12	/* credits to sender	*/

/*
 * Dummy message header
 */
typedef struct rsmipc_msg {
	int		rsmipc_version;
	rsm_node_id_t	rsmipc_src;
	int		rsmipc_type;
	rsmipc_cookie_t	rsmipc_cookie;
	int64_t		rsmipc_incn;
}rsmipc_msghdr_t;


#define	RSM_NO_REPLY	0	/* for rsmipc_send when no reply is expected */

/*
 * Request message of connect operation
 */
typedef struct rsmipc_request {
	rsmipc_msghdr_t		rsmipc_hdr;
	rsm_memseg_id_t		rsmipc_key;	/* user key or segid */
	rsm_permission_t	rsmipc_perm;
	rsm_addr_t		rsmipc_adapter_hwaddr;
	void			*rsmipc_segment_cookie;
}rsmipc_request_t;

/*
 * Message format of the flow control messages
 */
typedef struct rsmipc_controlmsg {
	rsmipc_msghdr_t		rsmipc_hdr;
	int64_t			rsmipc_local_incn;
	rsm_addr_t		rsmipc_adapter_hwaddr;
	int32_t			rsmipc_credits;	/* credits */
}rsmipc_controlmsg_t;

/*
 * Reply message for connect operation
 */
typedef struct rsmipc_reply {
	rsmipc_msghdr_t	rsmipc_hdr;
	short		rsmipc_status;	/* error code of remote call */
	uint16_t	rsmipc_cnum;	/* exported controller addr */
	rsm_memseg_id_t	rsmipc_segid;	/* segid from remote node */
	size_t		rsmipc_seglen;	/* exporter segment size */
	mode_t		rsmipc_mode;
	uid_t		rsmipc_uid;
	gid_t		rsmipc_gid;
}rsmipc_reply_t;

#ifdef	__cplusplus
}
#endif


#endif	/* _SYS_RSM_RSM_H */
