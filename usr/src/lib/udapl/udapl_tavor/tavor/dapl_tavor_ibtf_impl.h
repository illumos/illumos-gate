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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DAPL_TAVOR_IMPL_H
#define	_DAPL_TAVOR_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>

#include "dapl_hash.h"
#include "dapl_tavor_ibtf.h"
#include "dapl_tavor_wr.h"

/*
 * Struct defining the hca handle
 */
struct dapls_ib_hca_handle {
	int		ia_fd;	 /* fd corresponding to the IA */
	minor_t		ia_rnum; /* Kernel resource number of the IA */
	int		hca_fd;  /* fd for the HCA ie. tavor */
	int		*ia_bf_toggle; /* toggle between the 2 bf buffers */
	dapls_hw_uar_t	ia_uar;  /* pointer to the HCA UAR page */
	void		*ia_bf;	 /* pointer to the Hermon Blueflame page */
};

/*
 * Struct defining the CQ handle
 */
struct dapls_ib_cq_handle {
	uint64_t		evd_hkey;
	uint32_t		cq_num;
	uint32_t		cq_size;
	uint32_t		cq_cqesz;
	off64_t			cq_map_offset;
	uint64_t		cq_map_len;
	dapls_hw_uar_t		cq_iauar;  /* copy of the UAR doorbell page */
	dapls_hw_cqe_t		cq_addr;
	uint32_t		cq_consindx;
	uint32_t		cq_log_cqsz;
	/* For Work Request ID processing */
	DAPL_OS_LOCK		cq_wrid_wqhdr_lock;
	DAPL_HASH_TABLE		*cq_wrid_wqhdr_list;
	dapls_tavor_wrid_list_hdr_t	*cq_wrid_reap_head;
	dapls_tavor_wrid_list_hdr_t	*cq_wrid_reap_tail;
	/* For Arbel or Hermon */
	uint32_t		*cq_poll_dbp;
	uint32_t		*cq_arm_dbp;
	/* For Hermon cq_resize */
	dapls_hw_cqe_t		cq_resize_addr;
	off64_t			cq_resize_map_offset;
	uint64_t		cq_resize_map_len;
	uint32_t		cq_resize_size;
	uint32_t		cq_resize_cqesz;
};

struct dapls_ib_qp_handle {
	uint64_t		ep_hkey;
	caddr_t			qp_addr;
	uint64_t		qp_map_len;
	uint32_t		qp_num;
	dapls_hw_uar_t		qp_iauar; /* copy of the UAR doorbell page */
	void			*qp_ia_bf; /* copy of the Hermon Blueflame pg */
	int			*qp_ia_bf_toggle; /* ptr to adapter toggle */
	uint32_t		qp_num_mpt_shift; /* Max # of MPT entries  */
						/* in bit shift	   */
	uint32_t		qp_num_premature_events;
	ib_work_completion_t	*qp_premature_events;

	/* Send Work Queue */
	ib_cq_handle_t		qp_sq_cqhdl;
	uint64_t		*qp_sq_lastwqeaddr;
	dapls_tavor_workq_hdr_t *qp_sq_wqhdr;
	caddr_t			qp_sq_buf;
	uint32_t		qp_sq_desc_addr;
	uint32_t		qp_sq_numwqe;
	uint32_t		qp_sq_wqesz;
	uint32_t		qp_sq_sgl;
	uint16_t		qp_sq_counter;
	uint32_t		qp_sq_headroom;	/* For Hermon */
	int			qp_sq_inline;
	uint32_t		*qp_sq_dbp;	/* For Arbel */

	/* Receive Work Queue */
	ib_cq_handle_t		qp_rq_cqhdl;
	uint64_t		*qp_rq_lastwqeaddr;
	dapls_tavor_workq_hdr_t *qp_rq_wqhdr;
	caddr_t			qp_rq_buf;
	uint32_t		qp_rq_desc_addr;
	uint32_t		qp_rq_numwqe;
	uint32_t		qp_rq_wqesz;
	uint32_t		qp_rq_sgl;
	uint32_t		*qp_rq_dbp;	/* For Arbel or Hermon */
	uint16_t		qp_rq_counter;	/* For Arbel or Hermon */

	/* SRQ related */
	uint32_t		qp_srq_enabled; /* QP will use an SRQ */
	ib_srq_handle_t		qp_srq;
};

/*
 * Structure defining the protection domain handle
 */
struct dapls_ib_pd_handle {
	uint64_t	pd_hkey;
};

/*
 * Structure defining the memory region handle
 */
struct dapls_ib_mr_handle {
	uint64_t	mr_hkey;
};

/*
 * Structure defining the memory window handle
 */
struct dapls_ib_mw_handle {
	uint64_t	mw_hkey;
};

/*
 * Structure defining the service provider handle
 */
struct dapls_ib_cm_srvc_handle {
	uint64_t	sv_sp_hkey;
};

/*
 * Structure defining the service provider handle
 */
struct dapls_ib_srq_handle {
	uint64_t		srq_hkey;
	caddr_t			srq_addr;
	uint64_t		srq_map_offset;
	uint64_t		srq_map_len;
	uint32_t		srq_num;
	dapls_hw_uar_t		srq_iauar; /* copy of the UAR doorbell page */
	uint32_t		*srq_dbp;	/* For Arbel or Hermon */

	/* Work Queue */
	int32_t			srq_wq_lastwqeindex;
	uint32_t		srq_wq_desc_addr;
	uint32_t		srq_wq_numwqe;
	uint32_t		srq_wq_wqesz;
	uint32_t		srq_wq_sgl;
	uint16_t		srq_counter;
	/* premature events */
	ib_work_completion_t	*srq_premature_events;
	uint32_t		*srq_freepr_events; /* free premature events */
	uint32_t		srq_freepr_head;
	uint32_t		srq_freepr_tail;
	uint32_t		srq_freepr_num_events;
	/* For Work Request ID processing */
	dapls_tavor_wrid_list_hdr_t	*srq_wridlist;
	/* EP Hash Table, key is QP number */
	DAPL_HASH_TABLE		*srq_ep_table;
};

/*
 * Struct that defines key per HCA instance information for OS
 * bypass implementation.
 */
struct dapls_ib_hca_state {
	int	hca_fd;
	void	*uarpg_baseaddr; /* base addr of the UAR page */
	size_t	uarpg_size;	 /* size of the UAR page */
	void	*bf_pg_baseaddr; /* base addr of the Hermon Blueflame page */
	int	bf_toggle;
	char	hca_path[MAXPATHLEN];
};

DAPL_OS_LOCK	dapls_ib_dbp_lock;

/* Function that returns a pointer to the specified doorbell entry */
uint32_t *dapls_ib_get_dbp(uint64_t maplen, int fd, uint64_t mapoffset,
    uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif /* _DAPL_TAVOR_IMPL_H */
