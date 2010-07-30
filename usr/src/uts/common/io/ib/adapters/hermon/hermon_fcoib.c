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

/*
 * hermon_fcoib.c
 *    Hermon Fibre Channel over IB routines
 *
 *    Implements all the routines necessary for setting up, using, and
 *    (later) tearing down all the FCoIB state.
 */

#include <sys/ib/adapters/hermon/hermon.h>

/*
 * hermon_fcoib_enable()
 *    Context: user or kernel context
 */
static int
hermon_fcoib_enable(hermon_state_t *state, int port)
{
	hermon_fcoib_t	*fcoib;
	hermon_hw_config_fc_basic_t config_fc_basic;
	int		status;

	port--;		/* passed in as 1 or 2, used as 0 or 1 */
	ASSERT(port >= 0 && port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;

	/* Configure FCoIB on the port */
	bzero(&config_fc_basic, sizeof (config_fc_basic));
	config_fc_basic.fexch_base_hi = fcoib->hfc_fexch_base[port] >> 16;
	config_fc_basic.fx_base_mpt_hi = fcoib->hfc_mpt_base[port] >> 17;
	config_fc_basic.fx_base_mpt_lo = 0;
	config_fc_basic.log2_num_rfci =
	    state->hs_ibtfinfo.hca_attr->hca_rfci_max_log2_qp;
	config_fc_basic.rfci_base = fcoib->hfc_rfci_qps_per_port * port +
	    fcoib->hfc_rfci_rsrc->hr_indx;
#if 1
	status = hermon_config_fc_cmd_post(state, &config_fc_basic, 1,
	    HERMON_HW_FC_CONF_BASIC, 0, port + 1, HERMON_CMD_NOSLEEP_SPIN);
#else
	status = hermon_config_fc_cmd_post(state, &config_fc_basic, 1,
	    HERMON_HW_FC_CONF_BASIC, 0, 0, HERMON_CMD_NOSLEEP_SPIN);
#endif
	if (status != HERMON_CMD_SUCCESS) {
		cmn_err(CE_CONT, "fcoib_enable failed: status 0x%x\n", status);
		HERMON_WARNING(state, "fcoib_enable failed");
		return (DDI_FAILURE);
	}
	fcoib->hfc_port_enabled[port] = 1;
	state->hs_fcoib_may_be_running = B_TRUE;
	return (DDI_SUCCESS);
}

/*
 * hermon_fcoib_set_id()
 *    Context: user or kernel context
 */
int
hermon_fcoib_set_id(hermon_state_t *state, int port, uint32_t rfci_qpn,
    uint32_t src_id)
{
	hermon_fcoib_t	*fcoib;
	int		status;
	int		offset;
	uint32_t	*n_port_ids;

	port--;		/* passed in as 1 or 2, used as 0 or 1 */
	ASSERT(port >= 0 && port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;
	mutex_enter(&fcoib->hfc_lock);

	if (fcoib->hfc_port_enabled[port] == 0) {
		if (hermon_fcoib_enable(state, port + 1) != DDI_SUCCESS) {
			mutex_exit(&fcoib->hfc_lock);
			return (DDI_FAILURE);
		}
	}

	n_port_ids = fcoib->hfc_n_port_ids[port];
	offset = rfci_qpn - fcoib->hfc_rfci_base[port];
	ASSERT(offset >= 0 && offset < fcoib->hfc_rfci_qps_per_port);
	n_port_ids[offset] = src_id;

	status = hermon_config_fc_cmd_post(state, n_port_ids, 1,
	    HERMON_HW_FC_CONF_NPORT, fcoib->hfc_rfci_qps_per_port,
	    port + 1, HERMON_CMD_NOSLEEP_SPIN);
	if (status != HERMON_CMD_SUCCESS) {
		HERMON_WARNING(state, "fcoib_set_id failed");
		mutex_exit(&fcoib->hfc_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&fcoib->hfc_lock);
	return (DDI_SUCCESS);
}

/*
 * hermon_fcoib_get_id_idx()
 *    Context: user or kernel context
 */
int
hermon_fcoib_get_id_idx(hermon_state_t *state, int port, ibt_fc_attr_t *fcp)
{
	hermon_fcoib_t	*fcoib;
	int		idx;

	port--;		/* passed in as 1 or 2, used as 0 or 1 */
	ASSERT(port >= 0 && port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;

	idx = fcp->fc_rfci_qpn - fcoib->hfc_rfci_base[port];
	if (idx < 0 || idx >= fcoib->hfc_rfci_qps_per_port)
		idx = -1;

	return (idx);
}

/*
 * hermon_fcoib_get_exch_base()
 *    Context: user or kernel context
 */
int
hermon_fcoib_check_exch_base_off(hermon_state_t *state, int port,
    ibt_fc_attr_t *fcp)
{
	hermon_fcoib_t	*fcoib;
	int		exch_base_off;

	port--;		/* passed in as 1 or 2, used as 0 or 1 */
	ASSERT(port >= 0 && port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;

	exch_base_off = fcp->fc_exch_base_off;
	if (exch_base_off >= fcoib->hfc_fexch_qps_per_port)
		exch_base_off = -1;

	return (exch_base_off);
}

/*
 * hermon_fcoib_qpnum_from_fexch()
 *    Context: user, kernel, or interrupt context
 */
int
hermon_fcoib_is_fexch_qpn(hermon_state_t *state, uint_t qpnum)
{
	hermon_fcoib_t	*fcoib;

	fcoib = &state->hs_fcoib;
	qpnum -= fcoib->hfc_fexch_rsrc->hr_indx;
	return (qpnum < fcoib->hfc_nports * fcoib->hfc_fexch_qps_per_port);
}

/*
 * hermon_fcoib_qpnum_from_fexch()
 *    Context: user, kernel, or interrupt context
 */
uint_t
hermon_fcoib_qpnum_from_fexch(hermon_state_t *state, int port,
    uint16_t fexch)
{
	hermon_fcoib_t	*fcoib;
	uint_t		qpnum;

	port--;		/* passed in as 1 or 2, used as 0 or 1 */
	ASSERT(port >= 0 && port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;
	qpnum = fexch + fcoib->hfc_fexch_base[port];
	return (qpnum);
}

/*
 * hermon_fcoib_qpn_to_mkey
 *    Context: user or kernel context
 */
uint32_t
hermon_fcoib_qpn_to_mkey(hermon_state_t *state, uint_t qpnum)
{
	int		i;
	hermon_fcoib_t	*fcoib;
	uint32_t	qp_indx;

	fcoib = &state->hs_fcoib;
	for (i = 0; i < fcoib->hfc_nports; i++) {
		qp_indx = qpnum - fcoib->hfc_fexch_base[i];
		if (qp_indx < fcoib->hfc_fexch_qps_per_port)
			return ((qp_indx + fcoib->hfc_mpt_base[i]) << 8);
	}
	return ((uint32_t)-1);	/* cannot get here with valid qpnum argument */
}

/*
 * hermon_fcoib_fexch_relative_qpn()
 *    Context: user or kernel context
 */
uint32_t
hermon_fcoib_fexch_relative_qpn(hermon_state_t *state, uint8_t port,
    uint32_t qp_indx)
{
	port--;
	ASSERT(port < HERMON_MAX_PORTS);
	qp_indx -= state->hs_fcoib.hfc_fexch_base[port];
	return (qp_indx);
}

/*
 * hermon_fcoib_fexch_mkey_init()
 *    Context: user or kernel context
 */
int
hermon_fcoib_fexch_mkey_init(hermon_state_t *state, hermon_pdhdl_t pd,
    uint8_t port, uint32_t qp_indx, uint_t sleep)
{
	int		status;
	uint32_t	mpt_indx;
	uint_t		nummtt;
	uint64_t	mtt_addr;
	hermon_fcoib_t	*fcoib;

	port--;
	ASSERT(port < HERMON_MAX_PORTS);
	fcoib = &state->hs_fcoib;
	qp_indx -= fcoib->hfc_fexch_base[port];	/* relative to FEXCH base */
	if (qp_indx > fcoib->hfc_fexch_qps_per_port)
		return (IBT_INVALID_PARAM);
	mpt_indx = qp_indx + fcoib->hfc_mpt_base[port];
	nummtt = fcoib->hfc_mtts_per_mpt;
	mtt_addr = ((uint64_t)qp_indx * nummtt + fcoib->hfc_mtt_base[port]) <<
	    HERMON_MTT_SIZE_SHIFT;

	status = hermon_mr_fexch_mpt_init(state, pd, mpt_indx,
	    nummtt, mtt_addr, sleep);
	return (status);
}

/*
 * hermon_fcoib_fexch_mkey_fini()
 *    Context: user or kernel context
 */
int
hermon_fcoib_fexch_mkey_fini(hermon_state_t *state, hermon_pdhdl_t pd,
    uint32_t qpnum, uint_t sleep)
{
	int		status;
	uint8_t		port;
	uint32_t	qp_indx;
	uint32_t	mpt_indx;
	hermon_fcoib_t	*fcoib;

	fcoib = &state->hs_fcoib;
	for (port = 0; port < fcoib->hfc_nports; port++) {
		qp_indx = qpnum - fcoib->hfc_fexch_base[port];
		if (qp_indx < fcoib->hfc_fexch_qps_per_port)
			goto found;
	}
	return (IBT_INVALID_PARAM);
found:
	/* qp_indx relative to FEXCH base */
	mpt_indx = qp_indx + fcoib->hfc_mpt_base[port];

	status = hermon_mr_fexch_mpt_fini(state, pd, mpt_indx, sleep);
	return (status);
}

/*
 * hermon_fcoib_query_fc()
 *    Context: user or kernel context
 */
void
hermon_fcoib_query_fc(hermon_state_t *state, hermon_fcoib_t *fcoib)
{
	int status;
	struct hermon_hw_query_fc_s query_fc;

	status = hermon_cmn_query_cmd_post(state, QUERY_FC, 0, 0, &query_fc,
	    sizeof (query_fc), HERMON_CMD_NOSLEEP_SPIN);
	if (status == HERMON_CMD_SUCCESS) {
		fcoib->hfc_log2_max_port_ids_queried = query_fc.log2_max_nports;
		fcoib->hfc_log2_max_fexch_queried = query_fc.log2_max_fexch;
		fcoib->hfc_log2_max_rfci_queried = query_fc.log2_max_rfci;
	} else
		cmn_err(CE_CONT, "!query_fc status 0x%x\n", status);
}

/*
 * hermon_fcoib_init()
 *    Context: Only called from attach() path context
 */
int
hermon_fcoib_init(hermon_state_t *state)
{
	hermon_fcoib_t	*fcoib;
	uint_t		numports;
	char		string[128];
	int		i;
	uintptr_t	vmemstart = (uintptr_t)0x10000000;

	/* used for fast checking for FCoIB during cqe_consume */
	state->hs_fcoib_may_be_running = B_FALSE;

	if ((state->hs_ibtfinfo.hca_attr->hca_flags2 & IBT_HCA2_FC) == 0)
		return (DDI_SUCCESS);

	fcoib = &state->hs_fcoib;
	bzero(fcoib, sizeof (*fcoib));

	hermon_fcoib_query_fc(state, fcoib);

	mutex_init(&fcoib->hfc_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&fcoib->hfc_lock);

	/* use a ROUND value that works on both 32 and 64-bit kernels */
	fcoib->hfc_vmemstart = vmemstart;

	fcoib->hfc_nports = numports = state->hs_cfg_profile->cp_num_ports;
	fcoib->hfc_fexch_qps_per_port =
	    1 << state->hs_ibtfinfo.hca_attr->hca_fexch_max_log2_qp;
	fcoib->hfc_mpts_per_port = fcoib->hfc_fexch_qps_per_port * 2;
	fcoib->hfc_mtts_per_mpt =
	    (1 << state->hs_ibtfinfo.hca_attr->hca_fexch_max_log2_mem) >>
	    PAGESHIFT;
	fcoib->hfc_rfci_qps_per_port =
	    1 << state->hs_ibtfinfo.hca_attr->hca_rfci_max_log2_qp;

	if (hermon_rsrc_reserve(state, HERMON_DMPT, numports *
	    fcoib->hfc_mpts_per_port, HERMON_SLEEP,
	    &fcoib->hfc_mpt_rsrc) != DDI_SUCCESS) {
		mutex_exit(&fcoib->hfc_lock);
		hermon_fcoib_fini(state);
		return (DDI_FAILURE);
	}

	/*
	 * Only reserve MTTs for the Primary MPTs (first half of the
	 * range for each port).
	 */
	if (hermon_rsrc_reserve(state, HERMON_MTT, numports *
	    fcoib->hfc_mpts_per_port * fcoib->hfc_mtts_per_mpt / 2,
	    HERMON_SLEEP, &fcoib->hfc_mtt_rsrc) != DDI_SUCCESS) {
		mutex_exit(&fcoib->hfc_lock);
		hermon_fcoib_fini(state);
		return (DDI_FAILURE);
	}
	if (hermon_rsrc_reserve(state, HERMON_QPC, numports *
	    fcoib->hfc_fexch_qps_per_port, HERMON_SLEEP,
	    &fcoib->hfc_fexch_rsrc) != DDI_SUCCESS) {
		mutex_exit(&fcoib->hfc_lock);
		hermon_fcoib_fini(state);
		return (DDI_FAILURE);
	}
	if (hermon_rsrc_reserve(state, HERMON_QPC, numports *
	    fcoib->hfc_rfci_qps_per_port, HERMON_SLEEP,
	    &fcoib->hfc_rfci_rsrc) != DDI_SUCCESS) {
		mutex_exit(&fcoib->hfc_lock);
		hermon_fcoib_fini(state);
		return (DDI_FAILURE);
	}

	for (i = 0; i < numports; i++) {
		fcoib->hfc_port_enabled[i] = 0;
		fcoib->hfc_n_port_ids[i] = kmem_zalloc(sizeof (uint32_t) *
		    fcoib->hfc_rfci_qps_per_port, KM_SLEEP);

		fcoib->hfc_mpt_base[i] = i * fcoib->hfc_mpts_per_port +
		    fcoib->hfc_mpt_rsrc->hr_indx;
		/* "/ 2" is for Secondary MKEYs never used on Client side */
		fcoib->hfc_mtt_base[i] = (i * fcoib->hfc_mpts_per_port *
		    fcoib->hfc_mtts_per_mpt / 2) + fcoib->hfc_mtt_rsrc->hr_indx;
		fcoib->hfc_fexch_base[i] = i * fcoib->hfc_fexch_qps_per_port +
		    fcoib->hfc_fexch_rsrc->hr_indx;
		fcoib->hfc_rfci_base[i] = i * fcoib->hfc_rfci_qps_per_port +
		    fcoib->hfc_rfci_rsrc->hr_indx;

		/* init FEXCH QP rsrc pool */
		(void) sprintf(string, "hermon%d_port%d_fexch_vmem",
		    state->hs_instance, i + 1);
		fcoib->hfc_fexch_vmemp[i] = vmem_create(string,
		    (void *)vmemstart, fcoib->hfc_fexch_qps_per_port,
		    1, NULL, NULL, NULL, 0, VM_SLEEP);

		/* init RFCI QP rsrc pool */
		(void) sprintf(string, "hermon%d_port%d_rfci_vmem",
		    state->hs_instance, i + 1);
		fcoib->hfc_rfci_vmemp[i] = vmem_create(string,
		    (void *)vmemstart, fcoib->hfc_rfci_qps_per_port,
		    1, NULL, NULL, NULL, 0, VM_SLEEP);
	}

	mutex_exit(&fcoib->hfc_lock);

	return (DDI_SUCCESS);
}


/*
 * hermon_fcoib_fini()
 *    Context: Only called from attach() and/or detach() path contexts
 */
void
hermon_fcoib_fini(hermon_state_t *state)
{
	hermon_fcoib_t	*fcoib;
	uint_t		numports;
	int		i;

	if ((state->hs_ibtfinfo.hca_attr->hca_flags2 & IBT_HCA2_FC) == 0)
		return;

	fcoib = &state->hs_fcoib;

	mutex_enter(&fcoib->hfc_lock);

	numports = fcoib->hfc_nports;

	for (i = 0; i < numports; i++) {
		if (fcoib->hfc_rfci_vmemp[i])
			vmem_destroy(fcoib->hfc_rfci_vmemp[i]);
		if (fcoib->hfc_fexch_vmemp[i])
			vmem_destroy(fcoib->hfc_fexch_vmemp[i]);
		if (fcoib->hfc_n_port_ids[i])
			kmem_free(fcoib->hfc_n_port_ids[i], sizeof (uint32_t) *
			    fcoib->hfc_rfci_qps_per_port);

		/* XXX --- should we issue HERMON_HW_FC_CONF_BASIC disable? */
		fcoib->hfc_port_enabled[i] = 0;
	}
	if (fcoib->hfc_rfci_rsrc)
		hermon_rsrc_free(state, &fcoib->hfc_rfci_rsrc);
	if (fcoib->hfc_fexch_rsrc)
		hermon_rsrc_free(state, &fcoib->hfc_fexch_rsrc);
	if (fcoib->hfc_mpt_rsrc)
		hermon_rsrc_free(state, &fcoib->hfc_mpt_rsrc);
	if (fcoib->hfc_mtt_rsrc)
		hermon_rsrc_free(state, &fcoib->hfc_mtt_rsrc);

	mutex_exit(&fcoib->hfc_lock);
	mutex_destroy(&fcoib->hfc_lock);

	bzero(fcoib, sizeof (*fcoib));
}
