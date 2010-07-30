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

#ifndef	_SYS_IB_ADAPTERS_HERMON_FCOIB_H
#define	_SYS_IB_ADAPTERS_HERMON_FCOIB_H

/*
 * hermon_fcoib.h
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hermon_fcoib_qp_s {
	hermon_rsrc_t	hfc_qp_rsrc;
	vmem_t		*hfc_qp_vmp;
} hermon_fcoib_qp_t;

typedef struct hermon_fcoib_s {
	uint8_t		hfc_log2_max_port_ids_queried;
	uint8_t		hfc_log2_max_fexch_queried;
	uint8_t		hfc_log2_max_rfci_queried;
	kmutex_t	hfc_lock;
	hermon_rsrc_t	*hfc_mpt_rsrc;	/* FEXCH MPTs for all ports */
	hermon_rsrc_t	*hfc_mtt_rsrc;	/* FEXCH MTTs for all MPTs */
	hermon_rsrc_t	*hfc_fexch_rsrc; /* FEXCH QPs for all ports */
	hermon_rsrc_t	*hfc_rfci_rsrc;	/* RFCI QPs for all ports */
	uint8_t		hfc_nports;	/* #HCA ports */
	uint8_t		hfc_port_enabled[HERMON_MAX_PORTS];
	uint_t		hfc_mpts_per_port;
	uint_t		hfc_mtts_per_mpt;
	uint_t		hfc_fexch_qps_per_port;
	uint_t		hfc_rfci_qps_per_port;
	vmem_t		*hfc_rfci_vmemp[HERMON_MAX_PORTS];
	vmem_t		*hfc_fexch_vmemp[HERMON_MAX_PORTS];
	uintptr_t	hfc_vmemstart;
	uint32_t	*hfc_n_port_ids[HERMON_MAX_PORTS];

	/* Convenient, but redundant values */
	uint32_t	hfc_mpt_base[HERMON_MAX_PORTS];
	uint32_t	hfc_mtt_base[HERMON_MAX_PORTS];
	uint32_t	hfc_fexch_base[HERMON_MAX_PORTS];
	uint32_t	hfc_rfci_base[HERMON_MAX_PORTS];
} hermon_fcoib_t;

_NOTE(DATA_READABLE_WITHOUT_LOCK(hermon_fcoib_s::hfc_fexch_rsrc
    hermon_fcoib_s::hfc_nports
    hermon_fcoib_s::hfc_mpts_per_port
    hermon_fcoib_s::hfc_mtts_per_mpt
    hermon_fcoib_s::hfc_fexch_qps_per_port
    hermon_fcoib_s::hfc_rfci_qps_per_port
    hermon_fcoib_s::hfc_mpt_base
    hermon_fcoib_s::hfc_mtt_base
    hermon_fcoib_s::hfc_fexch_base
    hermon_fcoib_s::hfc_rfci_base))

int hermon_fcoib_set_id(hermon_state_t *state, int port, uint32_t rfci_qpn,
    uint32_t src_id);
int hermon_fcoib_get_id_idx(hermon_state_t *state, int port,
    ibt_fc_attr_t *fcp);
int hermon_fcoib_check_exch_base_off(hermon_state_t *state, int port,
    ibt_fc_attr_t *fcp);
uint_t hermon_fcoib_qpnum_from_fexch(hermon_state_t *state, int port,
    uint16_t fexch);
int hermon_fcoib_is_fexch_qpn(hermon_state_t *state, uint_t qpnum);
uint32_t hermon_fcoib_qpn_to_mkey(hermon_state_t *state, uint_t qpnum);
int hermon_fcoib_fexch_mkey_init(hermon_state_t *state, hermon_pdhdl_t pd,
    uint8_t port, uint32_t qp_indx, uint_t sleep);
int hermon_fcoib_fexch_mkey_fini(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t qpnum, uint_t sleep);
uint32_t hermon_fcoib_fexch_relative_qpn(hermon_state_t *state, uint8_t port,
    uint32_t qpnum);
int hermon_fcoib_init(hermon_state_t *state);
void hermon_fcoib_fini(hermon_state_t *state);


#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_FCOIB_H */
