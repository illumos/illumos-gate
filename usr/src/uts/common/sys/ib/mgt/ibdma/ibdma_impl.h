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
#ifndef _IBDMA_IMPL_H
#define	_IBDMA_IMPL_H

/*
 * ibdma_impl.h
 *
 * Device Management Agent private prototypes and structures.
 */

#ifdef __cpluplus
extern "C" {
#endif

#include <sys/ib/ibtl/ibvti.h>		/* IB verrbs interfaces */
#include <sys/ib/mgt/ib_dm_attr.h>	/* IB DM defines/structures */
#include <sys/ib/mgt/ib_mad.h>		/* IB MAD defines/structures */

enum  {
	IBDMA_MAD_SIZE		= 256,
	IBDMA_DM_MAD_HDR_SIZE	= 40,
	IBDMA_DM_RESP_TIME	= 20,
	IBDMA_MAX_IOC		= 16
};

/*
 * Implementation of handle returned to consumer.
 */
typedef struct ibdma_hdl_impl_s {
	list_node_t		ih_node;
	ib_guid_t		ih_iou_guid;
	uint8_t			ih_ioc_ndx;
} ibdma_hdl_impl_t;

/*
 * Each I/O Controller slot for the I/O Unit.
 */
typedef struct ibdma_ioc_s {
	uint8_t				ii_inuse;
	/*
	 * Just to map handle back to slot number and hca
	 */
	int				ii_slot;
	struct ibdma_hca_s		*ii_hcap;

	/*
	 * Profile provided by the I/O Controller, must be stored
	 * in network order.  Note that the profile indicates the
	 * number of service entries pointed to by ii_srvcs.
	 */
	ib_dm_ioc_ctrl_profile_t	ii_profile;
	ib_dm_srv_t			*ii_srvcs;
} ibdma_ioc_t;

/*
 * The ibdma_hca_t structure is only used internally by the
 * IB DM Agent.  It is created when the associated HCA is
 * opened as part of initialization or as a result of a
 * notification via IBTF.  It is destroyed when the HCA
 * is closed as part of fini processing or as a result of
 * a notification via IBTF.  The structure is not directly
 * accessed by IBMF call-backs or the consumer API.
 */
typedef struct ibdma_port_s {
	ibmf_handle_t		ip_ibmf_hdl;
	ibmf_register_info_t	ip_ibmf_reg;
	ibmf_impl_caps_t	ip_ibmf_caps;
	struct ibdma_hca_s	*ip_hcap;
} ibdma_port_t;

typedef struct ibdma_hca_s {
	list_node_t		ih_node;
	ibt_hca_hdl_t		ih_ibt_hdl;

	/*
	 * Consumer handles associated with I/O Controllers
	 * that have registered with this I/O Unit.
	 */
	list_t			ih_hdl_list;

	/*
	 * The I/O Unit that is presented to the IB Fabric.
	 * It is stored in network order.
	 */
	krwlock_t		ih_iou_rwlock;
	ib_guid_t		ih_iou_guid;
	ib_dm_io_unitinfo_t	ih_iou;
	ibdma_ioc_t		ih_ioc[IBDMA_MAX_IOC];
	uint8_t			ih_nports;
	ibdma_port_t		ih_port[1];
} ibdma_hca_t;


/*
 * The IBDMA module state information created and initialized
 * at _init() and freed at _fini().
 */
typedef struct ibdma_mod_state_s {
	ibt_clnt_hdl_t		ms_ibt_hdl;

	/*
	 * The HCA list lock is used protect the HCA list and
	 * is held during consumer routines (in place of a
	 * reference count) to ensure the HCA exists for the
	 * duration of it's use in the routine.
	 */
	kmutex_t		ms_hca_list_lock;
	list_t			ms_hca_list;
	uint_t			ms_num_hcas;

} ibdma_mod_state_t;


/*
 * Client API internal helpers
 */
typedef enum ibdma_ioc_state_e {
	IBDMA_IOC_NOT_INSTALLED = 0,
	IBDMA_IOC_PRESENT = 1,
	IBDMA_IOC_DOES_NOT_EXIST = 255,
	IBDMA_HDL_MAGIC = 0x00931000
} ibdma_ioc_state_t;

static void
ibdma_set_ioc_state(ibdma_hca_t *hca, int slot, ibdma_ioc_state_t state);
static ibdma_ioc_state_t ibdma_get_ioc_state(ibdma_hca_t *hca, int slot);

#endif /* _IBDMA_IMPL_H */
