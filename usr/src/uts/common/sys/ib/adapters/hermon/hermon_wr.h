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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_WR_H
#define	_SYS_IB_ADAPTERS_HERMON_WR_H

/*
 * hermon_wr.h
 *    Contains all of the prototypes, #defines, and structures necessary
 *    for the Hermon Work Request Processing Routines
 *    Specifically it contains #defines, macros, and prototypes for each of
 *    building each of the various types of WQE and for managing the WRID
 *    tracking mechanisms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * WQEADDRSZ is a bit of a misnomer, it's really a token for the
 * WRID processing.  We simply use the wqe_counter.
 */
#define	HERMON_QP_WQEADDRSZ(wcnt, qpn)	(wcnt) & 0xFFFF

/* And put the get from the CQ here as well	*/
#define	HERMON_CQE_WQEADDRSZ_GET(cq, cqe)				\
	((uint32_t)((((uint8_t *)(cqe))[0x18]) << 8) | ((uint8_t *)(cqe))[0x19])


/*
 * The following macro sets the owner bit in the Control Segment of the
 * WQE, based on the wqe_counter value passed in
 */
#define	HERMON_SET_SEND_WQE_OWNER(qp, desc, opcode)			\
	*(uint32_t *)desc = htonl((((*(uint8_t *)desc & 0x80) ^ 0x80) << 24) | \
	    opcode);

/*
 * The following macros are used to calculate pointers to the Send or Receive
 * (or SRQ) WQEs on a given QP, respectively
 */
#define	HERMON_QP_SQ_ENTRY(qp, tail)					\
	((uint64_t *)((uintptr_t)((qp)->qp_sq_buf) +			\
	((tail) << (qp)->qp_sq_log_wqesz)))
#define	HERMON_QP_RQ_ENTRY(qp, tail)					\
	((uint64_t *)((uintptr_t)((qp)->qp_rq_buf) +			\
	((tail) << (qp)->qp_rq_log_wqesz)))
#define	HERMON_SRQ_WQ_ENTRY(srq, tail)					\
	((uint64_t *)((uintptr_t)((srq)->srq_wq_buf) +			\
	((tail) << (srq)->srq_wq_log_wqesz)))

/*
 * The following macro is used to calculate the 'wqe_index' field during SRQ
 * operation.  This returns the index based on the WQE size, that can be used
 * to reference WQEs in an SRQ.
 */
#define	HERMON_SRQ_WQE_INDEX(srq_base_addr, wqe_addr, log_wqesz)	\
	(((uint32_t)(uintptr_t)wqe_addr -				\
	(uint32_t)(uintptr_t)srq_base_addr) >> log_wqesz)
/*
 * The following macro is used to calculate the 'wqe_addr' during SRQ
 * operation.  This returns the addr based on the WQE size and index,
 * that can be used to reference WQEs in an SRQ.
 */

#define	HERMON_SRQ_WQE_ADDR(srq, wqe_index)				\
	((uint64_t *)((uintptr_t)srq->srq_wq_buf +			\
	(wqe_index << srq->srq_wq_log_wqesz)))

/*
 * The following macros are used to access specific fields in Directed Route
 * MAD packets.  We can extract the MgmtClass, "hop pointer", and "hop count".
 * We can also update the "hop pointer" as appropriate.  Note:  Again, because
 * of the limited amount of direct handling the Hermon hardware does on special
 * QP request (specifically on Directed Route MADs), the driver needs to
 * update (as necessary) the "hop pointer" value depending on whether a MAD
 * is outbound or inbound (i.e. depending on the relationship between "hop
 * pointer" and "hop count" in the given MAD)
 */
#define	HERMON_SPECIAL_QP_DRMAD_GET_MGMTCLASS(mgmtclass, offset, va, len) \
	if (((mgmtclass) == NULL) && ((offset) + (len) > 1)) {		 \
	    (mgmtclass) = &((uint8_t *)(uintptr_t)(va))[1 - (offset)];	 \
	}
#define	HERMON_SPECIAL_QP_DRMAD_GET_HOPPOINTER(hp, offset, va, len)	\
	if (((hp) == NULL) &&					  	\
	    ((offset) + (len) > 6)) {					\
	    (hp) = &((uint8_t *)(uintptr_t)(va))[6 - (offset)];		\
	}
#define	HERMON_SPECIAL_QP_DRMAD_GET_HOPCOUNT(hc, offset, va, len)	\
	if (((hc) == NULL) &&						\
	    ((offset) + (len) > 7)) {					\
	    (hc) = &((uint8_t *)(uintptr_t)(va))[7 - (offset)];		\
	}
#define	HERMON_SPECIAL_QP_DRMAD_DO_HOPPOINTER_MODIFY(mgmtclass, hp, hc)	\
	if ((mgmtclass) == 0x81) {					\
		if ((hp) < (hc)) {					\
			(hp) = (hp) + 1;				\
		} else if ((hp) > (hc)) {				\
			(hp) = (hp) - 1;				\
		}							\
	}

/*
 * The hermon_workq_hdr_s structure is used internally by the Hermon driver
 * to track the information necessary to manage the work queues (send, recv,
 * or shared recv).  The hermon_workq_avl_s is used for each association of
 * a work queue with a given completion queue, where SRQs can be associated
 * with multiple queue pairs and their associated completion queues.
 */
struct hermon_workq_hdr_s {
	uint32_t		wq_size;
	uint32_t		wq_mask;
	ibt_wrid_t		*wq_wrid;
	uint32_t		wq_head;
	uint32_t		wq_tail;
	uint32_t		wq_full;
};

_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    hermon_workq_hdr_s::wq_wrid
    hermon_workq_hdr_s::wq_head
    hermon_workq_hdr_s::wq_tail
    hermon_workq_hdr_s::wq_full))

struct hermon_workq_avl_s {
	avl_node_t		wqa_link;
	uint32_t		wqa_qpn;
	uint32_t		wqa_type;	/* send or recv */
	struct hermon_workq_hdr_s *wqa_wq;

	/* For SRQ, this is needed to add the wqe to the free list */
	uint_t			wqa_srq_en;
	hermon_srqhdl_t		wqa_srq;
};

#define	HERMON_WR_RECV			0x0
#define	HERMON_WR_SEND			0x1
#define	HERMON_WR_SRQ			0x2

extern int hermon_wrid_workq_compare(const void *p1, const void *p2);
typedef struct hermon_workq_compare_s {
	uint32_t cmp_type;
	uint32_t cmp_qpn;
} hermon_workq_compare_t;

/* For Work Request posting */
int hermon_post_send(hermon_state_t *state, hermon_qphdl_t qphdl,
    ibt_send_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
int hermon_post_recv(hermon_state_t *state, hermon_qphdl_t qphdl,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);
int hermon_post_srq(hermon_state_t *state, hermon_srqhdl_t srqhdl,
    ibt_recv_wr_t *wr_p, uint_t num_wr, uint_t *num_posted);

/* For WRID handling */
int hermon_wrid_from_reset_handling(hermon_state_t *state, hermon_qphdl_t qp);
int hermon_wrid_to_reset_handling(hermon_state_t *state, hermon_qphdl_t qp);
ibt_wrid_t hermon_wrid_get_entry(hermon_cqhdl_t cqhdl, hermon_hw_cqe_t *cqe);
hermon_workq_hdr_t *hermon_wrid_wqhdr_create(int bufsz);
void hermon_wrid_wqhdr_destroy(hermon_workq_hdr_t *wqhdr);

/* debug routine */
void hermon_check_qp_debug(hermon_state_t *state, hermon_qphdl_t qp);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_WR_H */
