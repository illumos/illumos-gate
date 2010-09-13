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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_H
#define	_SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *
 * NAME: sol_uverbs.h
 *
 * DESC: Solaris OFED User Verbs Kernel Agent header file.
 *
 */
#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/rdma/ib_user_verbs.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_hca.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs2ucma.h>

/*
 * Definitions
 */
#define	SOL_UVERBS_DRIVER_MAX_HCA_MINOR	(16)
#define	SOL_UVERBS_DRIVER_EVENT_MINOR	(17)
#define	SOL_UVERBS_DRIVER_MAX_MINOR	(18)


/*
 * Structures
 */

/*
 * Kernel User Verbs Events.
 *
 * User verbs kernel events (asynchronous and completion) representation.
 * IBT events are mapped back to OFA events.
 */
typedef struct uverbs_event {

	union {
		struct ib_uverbs_async_event_desc	async;
		struct ib_uverbs_comp_event_desc	comp;
	} ev_desc;

	llist_head_t	ev_list;
	llist_head_t	ev_obj_list;
	uint32_t	*ev_counter;
} uverbs_event_t;


/*
 * Module Context.
 *
 * There is a single module context which maintains the list
 * of HCA's retrieved from IBT. A user process indicates the
 * target HCA open via the uverbs unique minor device number
 * associated with the HCA.
 */
typedef struct {
	kmutex_t		lock;
	dev_info_t		*dip;

	/*
	 * Underlying IBT HCA Info
	 */

	ibt_clnt_modinfo_t	clnt_modinfo;
	ibt_clnt_hdl_t		clnt_hdl;
	uint32_t		hca_count;
	ib_guid_t		*hca_guid_list;
	sol_uverbs_hca_t	*hcas;

	/*
	 * Support user asyncrhonous and completion event delivery via
	 * user event filesystem.
	 */
	dev_t			dev;
} uverbs_module_context_t;

/*
 * User Event File.
 *
 * Used for delivery of asynchronous and synchronous events to the user.
 * An asynchronous event file is created during the allocation of
 * a user verbs consumer context, a completion event file is created
 * when the user verbs consumer creates a completion channel.
 */
typedef struct uverbs_ufile_uobj {
	sol_ofs_uobj_t			uobj;
	kmutex_t			lock;
	int				ref;
	kcondvar_t			poll_wait;
	struct pollhead			poll_head;
	struct uverbs_uctxt_uobj	*uctxt;
	int				is_async;
	llist_head_t			event_list;
	sol_uverbs_cq_ctrl_t		ufile_notify_enabled;
	uint32_t			ufile_cq_cnt;
} uverbs_ufile_uobj_t;

/*
 * Type of user context -
 */
#define		SOL_UVERBS_UCTXT_VERBS		0x001
#define		SOL_UVERBS_UCTXT_EVENT		0x100
#define		SOL_UVERBS_UCTXT_ASYNC		0x101
#define		SOL_UVERBS_UCTXT_COMPL		0x110

/*
 * User Context.
 *
 * A user context is created when a user process opens a specific minor
 * device.  The context maintains a list of resources created by this
 * user that allows the resources to be cleaned up on user close.
 */
typedef struct uverbs_uctxt_uobj {
	sol_ofs_uobj_t		uobj;
	kmutex_t		lock;
	uverbs_module_context_t	*mod_ctxt;
	sol_uverbs_hca_t	*hca;		/* short cut to specific hca */

	/*
	 * List of user resource objects created by this context.  The
	 * objects themselves live in the associated object table, and
	 * the code should use the table to access and use resources.
	 * Any objects that remain in these list will be destroyed at
	 * user close to free the associated resources.
	 *
	 * The user context "lock" should be held when invoking
	 * routines to manipulate the lists.
	 */
	genlist_t		pd_list;
	genlist_t		mr_list;
	genlist_t		cq_list;
	genlist_t		qp_list;
	genlist_t		srq_list;
	genlist_t		ah_list;

	/*
	 * Event filesystem interfaces for IB asyncrhonous events
	 * and completion events.
	 */
	uverbs_ufile_uobj_t    *comp_evfile;
	uverbs_ufile_uobj_t    *async_evfile;

	/*
	 * User context can be created for :
	 *	1. All Verbs API
	 *	2. For getting a file for async events.
	 *	3. For getting a file for completion events.
	 * For (1) - pointers to (2) & (3) will be updated. For (2) and (3)
	 * pointer to (1) will be maintained.
	 */
	uint16_t		uctxt_type;
	uint32_t		uctxt_verbs_id;
	uint32_t		uctxt_async_id;
	uint32_t		uctxt_comp_id;
	uint8_t			uctxt_free_pending;
} uverbs_uctxt_uobj_t;

/*
 * User PD objects created at PD allocation
 */
typedef struct uverbs_upd_uobj {
	sol_ofs_uobj_t		uobj;
	ibt_pd_hdl_t		pd;
	genlist_entry_t		*list_entry;	/* per user ctx list entry */
	uint32_t		active_qp_cnt;
	uint8_t			free_pending;
} uverbs_upd_uobj_t;

/*
 * User MR objects created at MR registration
 */
typedef struct uverbs_umr_uobj {
	sol_ofs_uobj_t	uobj;
	ibt_mr_hdl_t	mr;
	genlist_entry_t	*list_entry;	/* per user ctx list entry */
} uverbs_umr_uobj_t;

/*
 * User CQ objects created at CQ allocation
 */
typedef struct uverbs_ucq_uobj {
	sol_ofs_uobj_t		uobj;
	ibt_cq_hdl_t		cq;
	genlist_entry_t		*list_entry;	/* per user ctx list entry */
	uverbs_uctxt_uobj_t	*uctxt;
	uverbs_ufile_uobj_t	*comp_chan;
	uint32_t		comp_events_reported;
	uint32_t		async_events_reported;
	llist_head_t		async_list;
	llist_head_t		comp_list;
	uint32_t		active_qp_cnt;
	uint8_t			free_pending;
} uverbs_ucq_uobj_t;

/*
 * User Shared Receive CQ objects created at SRQ allocation
 */
typedef struct uverbs_usrq_uobj {
	sol_ofs_uobj_t		uobj;
	ibt_srq_hdl_t		srq;
	genlist_entry_t		*list_entry;	/* per user ctx list entry */
	uverbs_uctxt_uobj_t	*uctxt;
	uint32_t		async_events_reported;
	llist_head_t		async_list;
	uint32_t		active_qp_cnt;
	uint8_t			free_pending;
} uverbs_usrq_uobj_t;

/*
 * User address handle objects created at AH allocation
 */
typedef struct uverbs_uah_uobj {
	sol_ofs_uobj_t	uobj;
	ibt_ah_hdl_t	ah;
	genlist_entry_t	*list_entry;	/* per user ctx list entry */
} uverbs_uah_uobj_t;

/*
 * User QP objects created at QP allocation
 */
#define	SOL_UVERBS_UQP_RCQ_VALID	0x01
#define	SOL_UVERBS_UQP_SRQ_VALID	0x02

typedef struct uverbs_uqp_uobj {
	sol_ofs_uobj_t			uobj;
	ibt_qp_hdl_t			qp;
	genlist_entry_t			*list_entry;	/* per uctx list */
	uint32_t			max_inline_data;
	uverbs_uctxt_uobj_t		*uctxt;
	uint32_t			qp_num;		/* 24 bits valid */
	uint32_t			disable_qp_mod;
	enum ib_qp_type			ofa_qp_type;
	llist_head_t			mcast_list;
	llist_head_t			async_list;
	uint32_t			async_events_reported;
	uverbs_ucq_uobj_t		*uqp_rcq;
	uverbs_ucq_uobj_t		*uqp_scq;

	uint32_t			uqp_pd_hdl;
	uint32_t			uqp_scq_hdl;
	uint32_t			uqp_rcq_hdl;
	uint32_t			uqp_srq_hdl;
	uint8_t				uqp_rcq_srq_valid;

	sol_uverbs_qp_free_state_t	uqp_free_state;
} uverbs_uqp_uobj_t;

extern sol_ofs_uobj_table_t uverbs_uctxt_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_upd_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_uah_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_umr_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_ucq_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_usrq_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_uqp_uo_tbl;
extern sol_ofs_uobj_table_t uverbs_ufile_uo_tbl;

/*
 * The following structure is used currently to pass data back to
 * libmthca on user allocation context.  This should be passed opaquely
 * to maintain a true hal, we'll look for a generic way to get this information
 * and deliver it opaquely post EA-1.
 */
struct mthca_alloc_ucontext_resp {
	uint32_t	qp_tab_size;
	uint32_t	uarc_size;
};

struct ib_udata {
	void	*inbuf;
	void	*outbuf;
	size_t	inlen;
	size_t	outlen;
};

int sol_uverbs_dummy_command(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len);
int sol_uverbs_get_context(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_alloc_pd(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_dealloc_pd(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_create_ah(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_destroy_ah(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_query_device(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_query_port(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_query_gid(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_query_pkey(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_reg_mr(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_dereg_mr(uverbs_uctxt_uobj_t *uctxt, char *buf, int in_len,
    int out_len);
int sol_uverbs_create_comp_channel(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len);

uint32_t
sol_uverbs_ibt_to_of_device_cap_flags(ibt_hca_flags_t flags,
    ibt_hca_flags2_t flags2);

uint64_t
sol_uverbs_ibt_to_of_page_sz(ibt_page_sizes_t page_szs);

int sol_uverbs_ibt_to_kernel_status(ibt_status_t  status);
uint32_t sol_uverbs_qpnum2uqpid(uint32_t qp_num);

int uverbs_upd_free(uverbs_upd_uobj_t *, uverbs_uctxt_uobj_t *);
int uverbs_uqp_free(uverbs_uqp_uobj_t *, uverbs_uctxt_uobj_t *);
int uverbs_usrq_free(uverbs_usrq_uobj_t *, uverbs_uctxt_uobj_t *);
int uverbs_ucq_free(uverbs_ucq_uobj_t *, uverbs_uctxt_uobj_t *);

/*
 * The following helpers simply provide easy access for acquiring and locking
 * User Objects.
 */
static inline uverbs_uctxt_uobj_t *
uverbs_uobj_get_uctxt_read(uint32_t id)
{
	return (uverbs_uctxt_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_uctxt_uo_tbl, id);
}
static inline uverbs_uctxt_uobj_t *
uverbs_uobj_get_uctxt_write(uint32_t id)
{
	return (uverbs_uctxt_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_uctxt_uo_tbl, id);
}
static inline uverbs_upd_uobj_t *
uverbs_uobj_get_upd_read(uint32_t id)
{
	return (uverbs_upd_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_upd_uo_tbl, id);
}
static inline uverbs_upd_uobj_t *
uverbs_uobj_get_upd_write(uint32_t id)
{
	return (uverbs_upd_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_upd_uo_tbl, id);
}
static inline uverbs_umr_uobj_t *
uverbs_uobj_get_umr_read(uint32_t id)
{
	return (uverbs_umr_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_umr_uo_tbl, id);
}
static inline uverbs_umr_uobj_t *
uverbs_uobj_get_umr_write(uint32_t id)
{
	return (uverbs_umr_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_umr_uo_tbl, id);
}
static inline uverbs_ucq_uobj_t *
uverbs_uobj_get_ucq_read(uint32_t id)
{
	return (uverbs_ucq_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_ucq_uo_tbl, id);
}
static inline uverbs_ucq_uobj_t *
uverbs_uobj_get_ucq_write(uint32_t id)
{
	return (uverbs_ucq_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_ucq_uo_tbl, (int)id);
}
static inline uverbs_usrq_uobj_t *
uverbs_uobj_get_usrq_read(uint32_t id)
{
	return (uverbs_usrq_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_usrq_uo_tbl, id);
}
static inline uverbs_usrq_uobj_t *
uverbs_uobj_get_usrq_write(uint32_t id)
{
	return (uverbs_usrq_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_usrq_uo_tbl, id);
}
static inline uverbs_uah_uobj_t *
uverbs_uobj_get_uah_read(uint32_t id)
{
	return (uverbs_uah_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_uah_uo_tbl, id);
}
static inline uverbs_uah_uobj_t *
uverbs_uobj_get_uah_write(uint32_t id)
{
	return (uverbs_uah_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_uah_uo_tbl, id);
}
static inline uverbs_uqp_uobj_t *
uverbs_uobj_get_uqp_read(uint32_t id)
{
	return (uverbs_uqp_uobj_t *)
	    sol_ofs_uobj_get_read(&uverbs_uqp_uo_tbl, id);
}
static inline uverbs_uqp_uobj_t *
uverbs_uobj_get_uqp_write(uint32_t id)
{
	return (uverbs_uqp_uobj_t *)
	    sol_ofs_uobj_get_write(&uverbs_uqp_uo_tbl, id);
}

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_SOL_UVERBS_SOL_UVERBS_H */
