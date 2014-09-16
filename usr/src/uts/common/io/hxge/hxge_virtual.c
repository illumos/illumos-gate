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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <hxge_impl.h>
#include <hxge_vmac.h>
#include <hxge_pfc.h>
#include <hpi_pfc.h>

static hxge_status_t hxge_get_mac_addr_properties(p_hxge_t);
static void hxge_use_cfg_hydra_properties(p_hxge_t);
static void hxge_use_cfg_dma_config(p_hxge_t);
static void hxge_use_cfg_class_config(p_hxge_t);
static void hxge_set_hw_dma_config(p_hxge_t);
static void hxge_set_hw_class_config(p_hxge_t);
static void hxge_ldgv_setup(p_hxge_ldg_t *ldgp, p_hxge_ldv_t *ldvp, uint8_t ldv,
	uint8_t endldg, int *ngrps);

extern uint16_t hxge_rcr_timeout;
extern uint16_t hxge_rcr_threshold;

extern uint32_t hxge_rbr_size;
extern uint32_t hxge_rcr_size;

extern uint_t hxge_rx_intr(caddr_t, caddr_t);
extern uint_t hxge_tx_intr(caddr_t, caddr_t);
extern uint_t hxge_vmac_intr(caddr_t, caddr_t);
extern uint_t hxge_syserr_intr(caddr_t, caddr_t);
extern uint_t hxge_pfc_intr(caddr_t, caddr_t);

/*
 * Entry point to populate configuration parameters into the master hxge
 * data structure and to update the NDD parameter list.
 */
hxge_status_t
hxge_get_config_properties(p_hxge_t hxgep)
{
	hxge_status_t		status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, VPD_CTL, " ==> hxge_get_config_properties"));

	if (hxgep->hxge_hw_p == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_get_config_properties: common hardware not set"));
		return (HXGE_ERROR);
	}

	hxgep->classifier.tcam_size = TCAM_HXGE_TCAM_MAX_ENTRY;

	status = hxge_get_mac_addr_properties(hxgep);
	if (status != HXGE_OK) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    " hxge_get_config_properties: mac addr properties failed"));
		return (status);
	}

	HXGE_DEBUG_MSG((hxgep, VPD_CTL,
	    " ==> hxge_get_config_properties: Hydra"));

	hxge_use_cfg_hydra_properties(hxgep);

	HXGE_DEBUG_MSG((hxgep, VPD_CTL, " <== hxge_get_config_properties"));
	return (HXGE_OK);
}


static void
hxge_set_hw_vlan_class_config(p_hxge_t hxgep)
{
	int			i;
	p_hxge_param_t		param_arr;
	uint_t			vlan_cnt;
	int			*vlan_cfg_val;
	hxge_param_map_t	*vmap;
	char			*prop;
	p_hxge_class_pt_cfg_t 	p_class_cfgp;
	uint32_t		good_cfg[32];
	int			good_count = 0;
	hxge_mv_cfg_t		*vlan_tbl;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " ==> hxge_set_hw_vlan_config"));
	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;

	param_arr = hxgep->param_arr;
	prop = param_arr[param_vlan_ids].fcode_name;

	/*
	 * uint32_t array, each array entry specifying a VLAN id
	 */
	for (i = 0; i <= VLAN_ID_MAX; i++) {
		p_class_cfgp->vlan_tbl[i].flag = 0;
	}

	vlan_tbl = (hxge_mv_cfg_t *)&p_class_cfgp->vlan_tbl[0];
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0, prop,
	    &vlan_cfg_val, &vlan_cnt) != DDI_PROP_SUCCESS) {
		return;
	}

	for (i = 0; i < vlan_cnt; i++) {
		vmap = (hxge_param_map_t *)&vlan_cfg_val[i];
		if ((vmap->param_id) && (vmap->param_id <= VLAN_ID_MAX)) {
			HXGE_DEBUG_MSG((hxgep, CFG2_CTL,
			    " hxge_vlan_config vlan id %d", vmap->param_id));

			good_cfg[good_count] = vlan_cfg_val[i];
			if (vlan_tbl[vmap->param_id].flag == 0)
				good_count++;

			vlan_tbl[vmap->param_id].flag = 1;
		}
	}

	ddi_prop_free(vlan_cfg_val);
	if (good_count != vlan_cnt) {
		(void) ddi_prop_update_int_array(DDI_DEV_T_NONE,
		    hxgep->dip, prop, (int *)good_cfg, good_count);
	}

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " <== hxge_set_hw_vlan_config"));
}


/*
 * Read param_vlan_ids and param_implicit_vlan_id properties from either
 * hxge.conf or OBP. Update the soft properties. Populate these
 * properties into the hxge data structure.
 */
static void
hxge_use_cfg_vlan_class_config(p_hxge_t hxgep)
{
	uint_t		vlan_cnt;
	int		*vlan_cfg_val;
	int		status;
	p_hxge_param_t	param_arr;
	char		*prop;
	uint32_t	implicit_vlan_id = 0;
	int		*int_prop_val;
	uint_t		prop_len;
	p_hxge_param_t	pa;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " ==> hxge_use_cfg_vlan_config"));
	param_arr = hxgep->param_arr;
	prop = param_arr[param_vlan_ids].fcode_name;

	status = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0, prop,
	    &vlan_cfg_val, &vlan_cnt);
	if (status == DDI_PROP_SUCCESS) {
		status = ddi_prop_update_int_array(DDI_DEV_T_NONE,
		    hxgep->dip, prop, vlan_cfg_val, vlan_cnt);
		ddi_prop_free(vlan_cfg_val);
	}

	pa = &param_arr[param_implicit_vlan_id];
	prop = pa->fcode_name;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0, prop,
	    &int_prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		implicit_vlan_id = (uint32_t)*int_prop_val;
		if ((implicit_vlan_id >= pa->minimum) ||
		    (implicit_vlan_id <= pa->maximum)) {
			status = ddi_prop_update_int(DDI_DEV_T_NONE, hxgep->dip,
			    prop, (int)implicit_vlan_id);
		}
		ddi_prop_free(int_prop_val);
	}

	hxge_set_hw_vlan_class_config(hxgep);

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " <== hxge_use_cfg_vlan_config"));
}

/*
 * Read in the configuration parameters from either hxge.conf or OBP and
 * populate the master data structure hxge.
 * Use these parameters to update the soft properties and the ndd array.
 */
static void
hxge_use_cfg_hydra_properties(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " ==> hxge_use_cfg_hydra_properties"));

	(void) hxge_use_cfg_dma_config(hxgep);
	(void) hxge_use_cfg_vlan_class_config(hxgep);
	(void) hxge_use_cfg_class_config(hxgep);

	/*
	 * Read in the hardware (fcode) properties and use these properties
	 * to update the ndd array.
	 */
	(void) hxge_get_param_soft_properties(hxgep);
	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " <== hxge_use_cfg_hydra_properties"));
}


/*
 * Read param_accept_jumbo, param_rxdma_intr_time, and param_rxdma_intr_pkts
 * from either hxge.conf or OBP.
 * Update the soft properties.
 * Populate these properties into the hxge data structure for latter use.
 */
static void
hxge_use_cfg_dma_config(p_hxge_t hxgep)
{
	int			tx_ndmas, rx_ndmas;
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	dev_info_t		*dip;
	p_hxge_param_t		param_arr;
	char			*prop;
	int 			*prop_val;
	uint_t 			prop_len;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " ==> hxge_use_cfg_dma_config"));
	param_arr = hxgep->param_arr;

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	dip = hxgep->dip;

	tx_ndmas = 4;
	p_cfgp->start_tdc = 0;
	p_cfgp->max_tdcs =  hxgep->max_tdcs = tx_ndmas;
	hxgep->tdc_mask = (tx_ndmas - 1);
	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "==> hxge_use_cfg_dma_config: "
	    "p_cfgp 0x%llx max_tdcs %d hxgep->max_tdcs %d",
	    p_cfgp, p_cfgp->max_tdcs, hxgep->max_tdcs));

	rx_ndmas = 4;
	p_cfgp->start_rdc = 0;
	p_cfgp->max_rdcs =  hxgep->max_rdcs = rx_ndmas;

	p_cfgp->start_ldg = 0;
	p_cfgp->max_ldgs = HXGE_INT_MAX_LDG;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "==> hxge_use_default_dma_config: "
	    "p_cfgp 0x%llx max_rdcs %d hxgep->max_rdcs %d",
	    p_cfgp, p_cfgp->max_rdcs, hxgep->max_rdcs));

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "==> hxge_use_cfg_dma_config: "
	    "p_cfgp 0x%016llx start_ldg %d hxgep->max_ldgs %d ",
	    p_cfgp, p_cfgp->start_ldg,  p_cfgp->max_ldgs));

	/*
	 * add code for individual rdc properties
	 */
	prop = param_arr[param_accept_jumbo].fcode_name;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, prop,
	    &prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		if ((prop_len > 0) && (prop_len <= p_cfgp->max_rdcs)) {
			(void) ddi_prop_update_int_array(DDI_DEV_T_NONE,
			    hxgep->dip, prop, prop_val, prop_len);
		}
		ddi_prop_free(prop_val);
	}

	prop = param_arr[param_rxdma_intr_time].fcode_name;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, prop,
	    &prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		if ((prop_len > 0) && (prop_len <= p_cfgp->max_rdcs)) {
			(void) ddi_prop_update_int_array(DDI_DEV_T_NONE,
			    hxgep->dip, prop, prop_val, prop_len);
		}
		ddi_prop_free(prop_val);
	}

	prop = param_arr[param_rxdma_intr_pkts].fcode_name;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, prop,
	    &prop_val, &prop_len) == DDI_PROP_SUCCESS) {
		if ((prop_len > 0) && (prop_len <= p_cfgp->max_rdcs)) {
			(void) ddi_prop_update_int_array(DDI_DEV_T_NONE,
			    hxgep->dip, prop, prop_val, prop_len);
		}
		ddi_prop_free(prop_val);
	}

	hxge_set_hw_dma_config(hxgep);
	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "<== hxge_use_cfg_dma_config"));
}

static void
hxge_use_cfg_class_config(p_hxge_t hxgep)
{
	hxge_set_hw_class_config(hxgep);
}

static void
hxge_set_hw_dma_config(p_hxge_t hxgep)
{
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, "==> hxge_set_hw_dma_config"));

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	/* Transmit DMA Channels */
	hxgep->ntdc = p_cfgp->max_tdcs;

	/* Receive DMA Channels */
	hxgep->nrdc = p_cfgp->max_rdcs;

	p_dma_cfgp->rbr_size = hxge_rbr_size;
	if (hxge_rcr_size > HXGE_RCR_MAX)
		hxge_rcr_size = HXGE_RCR_MAX;
	p_dma_cfgp->rcr_size = hxge_rcr_size;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " <== hxge_set_hw_dma_config"));
}


boolean_t
hxge_check_rxdma_port_member(p_hxge_t hxgep, uint8_t rdc)
{
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	int			status = B_TRUE;

	HXGE_DEBUG_MSG((hxgep, CFG2_CTL, "==> hxge_check_rxdma_port_member"));

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	/* Receive DMA Channels */
	if (rdc < p_cfgp->max_rdcs)
		status = B_TRUE;
	HXGE_DEBUG_MSG((hxgep, CFG2_CTL, " <== hxge_check_rxdma_port_member"));

	return (status);
}

boolean_t
hxge_check_txdma_port_member(p_hxge_t hxgep, uint8_t tdc)
{
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	int			status = B_FALSE;

	HXGE_DEBUG_MSG((hxgep, CFG2_CTL, "==> hxge_check_txdma_port_member"));

	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	/* Receive DMA Channels */
	if (tdc < p_cfgp->max_tdcs)
		status = B_TRUE;
	HXGE_DEBUG_MSG((hxgep, CFG2_CTL, " <== hxge_check_txdma_port_member"));

	return (status);
}


/*
 * Read the L2 classes, L3 classes, and initial hash from either hxge.conf
 * or OBP. Populate these properties into the hxge data structure for latter
 * use. Note that we are not updating these soft properties.
 */
static void
hxge_set_hw_class_config(p_hxge_t hxgep)
{
	int			i, j;
	p_hxge_param_t		param_arr;
	int			*int_prop_val;
	uint32_t		cfg_value;
	char			*prop;
	p_hxge_class_pt_cfg_t	p_class_cfgp;
	int			start_prop, end_prop;
	uint_t			prop_cnt;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " ==> hxge_set_hw_class_config"));

	p_class_cfgp = (p_hxge_class_pt_cfg_t)&hxgep->class_config;

	param_arr = hxgep->param_arr;

	/*
	 * L2 class configuration. User configurable ether types
	 */
	start_prop =  param_class_cfg_ether_usr1;
	end_prop = param_class_cfg_ether_usr2;

	for (i = start_prop; i <= end_prop; i++) {
		prop = param_arr[i].fcode_name;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip,
		    0, prop, &int_prop_val, &prop_cnt) == DDI_PROP_SUCCESS) {
			cfg_value =  (uint32_t)*int_prop_val;
			ddi_prop_free(int_prop_val);
		} else {
			cfg_value = (uint32_t)param_arr[i].value;
		}

		j = (i - start_prop) + TCAM_CLASS_ETYPE_1;
		p_class_cfgp->class_cfg[j] = cfg_value;
	}

	/*
	 * Use properties from either .conf or the NDD param array. Only bits
	 * 2 and 3 are significant
	 */
	start_prop =  param_class_opt_ipv4_tcp;
	end_prop = param_class_opt_ipv6_sctp;

	for (i = start_prop; i <= end_prop; i++) {
		prop = param_arr[i].fcode_name;
		if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip,
		    0, prop, &int_prop_val, &prop_cnt) == DDI_PROP_SUCCESS) {
			cfg_value =  (uint32_t)*int_prop_val;
			ddi_prop_free(int_prop_val);
		} else {
			cfg_value = (uint32_t)param_arr[i].value;
		}

		j = (i - start_prop) + TCAM_CLASS_TCP_IPV4;
		p_class_cfgp->class_cfg[j] = cfg_value;
	}

	prop = param_arr[param_hash_init_value].fcode_name;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, hxgep->dip, 0, prop,
	    &int_prop_val, &prop_cnt) == DDI_PROP_SUCCESS) {
		cfg_value =  (uint32_t)*int_prop_val;
		ddi_prop_free(int_prop_val);
	} else {
		cfg_value = (uint32_t)param_arr[param_hash_init_value].value;
	}

	p_class_cfgp->init_hash = (uint32_t)cfg_value;

	HXGE_DEBUG_MSG((hxgep, CFG_CTL, " <== hxge_set_hw_class_config"));
}


/*
 * Interrupts related interface functions.
 */
hxge_status_t
hxge_ldgv_init(p_hxge_t hxgep, int *navail_p, int *nrequired_p)
{
	uint8_t			ldv, i, maxldvs, maxldgs, start, end, nldvs;
	int			ldg, endldg, ngrps;
	uint8_t			channel;
	p_hxge_dma_pt_cfg_t	p_dma_cfgp;
	p_hxge_hw_pt_cfg_t	p_cfgp;
	p_hxge_ldgv_t		ldgvp;
	p_hxge_ldg_t		ldgp, ptr;
	p_hxge_ldv_t		ldvp;
	hxge_status_t		status = HXGE_OK;
	peu_intr_mask_t		parity_err_mask;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_ldgv_init"));
	if (!*navail_p) {
		*nrequired_p = 0;
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_ldgv_init:no avail"));
		return (HXGE_ERROR);
	}
	p_dma_cfgp = (p_hxge_dma_pt_cfg_t)&hxgep->pt_config;
	p_cfgp = (p_hxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	/* each DMA channels */
	nldvs = p_cfgp->max_tdcs + p_cfgp->max_rdcs;

	/* vmac */
	nldvs++;

	/* pfc */
	nldvs++;

	/* system error interrupts. */
	nldvs++;

	maxldvs = nldvs;
	maxldgs = p_cfgp->max_ldgs;

	if (!maxldvs || !maxldgs) {
		/* No devices configured. */
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL, "<== hxge_ldgv_init: "
		    "no logical devices or groups configured."));
		return (HXGE_ERROR);
	}
	ldgvp = hxgep->ldgvp;
	if (ldgvp == NULL) {
		ldgvp = KMEM_ZALLOC(sizeof (hxge_ldgv_t), KM_SLEEP);
		hxgep->ldgvp = ldgvp;
		ldgvp->maxldgs = maxldgs;
		ldgvp->maxldvs = maxldvs;
		ldgp = ldgvp->ldgp =
		    KMEM_ZALLOC(sizeof (hxge_ldg_t) * maxldgs, KM_SLEEP);
		ldvp = ldgvp->ldvp =
		    KMEM_ZALLOC(sizeof (hxge_ldv_t) * maxldvs, KM_SLEEP);
	}

	ldgvp->ndma_ldvs = p_cfgp->max_tdcs + p_cfgp->max_rdcs;
	ldgvp->tmres = HXGE_TIMER_RESO;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_ldgv_init: maxldvs %d maxldgs %d nldvs %d",
	    maxldvs, maxldgs, nldvs));

	ldg = p_cfgp->start_ldg;
	ptr = ldgp;
	for (i = 0; i < maxldgs; i++) {
		ptr->arm = B_TRUE;
		ptr->vldg_index = i;
		ptr->ldg_timer = HXGE_TIMER_LDG;
		ptr->ldg = ldg++;
		ptr->sys_intr_handler = hxge_intr;
		ptr->nldvs = 0;
		ptr->hxgep = hxgep;
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_ldgv_init: maxldvs %d maxldgs %d ldg %d",
		    maxldvs, maxldgs, ptr->ldg));
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_ldv_init: timer %d", ptr->ldg_timer));
		ptr++;
	}

	ldg = p_cfgp->start_ldg;
	if (maxldgs > *navail_p) {
		ngrps = *navail_p;
	} else {
		ngrps = maxldgs;
	}
	endldg = ldg + ngrps;

	/*
	 * Receive DMA channels.
	 */
	channel = p_cfgp->start_rdc;
	start = p_cfgp->start_rdc + HXGE_RDMA_LD_START;
	end = start + p_cfgp->max_rdcs;
	nldvs = 0;
	ldgvp->nldvs = 0;
	ldgp->ldvp = NULL;
	*nrequired_p = 0;
	ptr = ldgp;

	/*
	 * Start with RDC to configure logical devices for each group.
	 */
	for (i = 0, ldv = start; ldv < end; i++, ldv++) {
		ldvp->is_rxdma = B_TRUE;
		ldvp->ldv = ldv;

		/*
		 * If non-seq needs to change the following code
		 */
		ldvp->channel = channel++;
		ldvp->vdma_index = i;
		ldvp->ldv_intr_handler = hxge_rx_intr;
		ldvp->ldv_ldf_masks = 0;
		ldvp->use_timer = B_FALSE;
		ldvp->hxgep = hxgep;
		hxge_ldgv_setup(&ptr, &ldvp, ldv, endldg, nrequired_p);
		nldvs++;
	}

	/*
	 * Transmit DMA channels.
	 */
	channel = p_cfgp->start_tdc;
	start = p_cfgp->start_tdc + HXGE_TDMA_LD_START;
	end = start + p_cfgp->max_tdcs;
	for (i = 0, ldv = start; ldv < end; i++, ldv++) {
		ldvp->is_txdma = B_TRUE;
		ldvp->ldv = ldv;
		ldvp->channel = channel++;
		ldvp->vdma_index = i;
		ldvp->ldv_intr_handler = hxge_tx_intr;
		ldvp->ldv_ldf_masks = 0;
		ldvp->use_timer = B_FALSE;
		ldvp->hxgep = hxgep;
		hxge_ldgv_setup(&ptr, &ldvp, ldv, endldg, nrequired_p);
		nldvs++;
	}

	/*
	 * VMAC
	 */
	ldvp->is_vmac = B_TRUE;
	ldvp->ldv_intr_handler = hxge_vmac_intr;
	ldvp->ldv_ldf_masks = 0;
	ldv = HXGE_VMAC_LD;
	ldvp->ldv = ldv;
	ldvp->use_timer = B_FALSE;
	ldvp->hxgep = hxgep;
	hxge_ldgv_setup(&ptr, &ldvp, ldv, endldg, nrequired_p);
	nldvs++;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_ldgv_init: nldvs %d navail %d nrequired %d",
	    nldvs, *navail_p, *nrequired_p));

	/*
	 * PFC
	 */
	ldvp->is_pfc = B_TRUE;
	ldvp->ldv_intr_handler = hxge_pfc_intr;
	ldvp->ldv_ldf_masks = 0;
	ldv = HXGE_PFC_LD;
	ldvp->ldv = ldv;
	ldvp->use_timer = B_FALSE;
	ldvp->hxgep = hxgep;
	hxge_ldgv_setup(&ptr, &ldvp, ldv, endldg, nrequired_p);
	nldvs++;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_ldgv_init: nldvs %d navail %d nrequired %d",
	    nldvs, *navail_p, *nrequired_p));

	/*
	 * System error interrupts.
	 */
	ldv = HXGE_SYS_ERROR_LD;
	ldvp->ldv = ldv;
	ldvp->is_syserr = B_TRUE;
	ldvp->ldv_intr_handler = hxge_syserr_intr;
	ldvp->ldv_ldf_masks = 0;
	ldvp->hxgep = hxgep;
	ldvp->use_timer = B_FALSE;
	ldgvp->ldvp_syserr = ldvp;

	/* Reset PEU error mask to allow PEU error interrupts */
	/*
	 * Keep the msix parity error mask here and remove it
	 * after ddi_intr_enable call to avoid a msix par err
	 */
	parity_err_mask.value = 0;
	parity_err_mask.bits.eic_msix_parerr_mask = 1;
	HXGE_REG_WR32(hxgep->hpi_handle, PEU_INTR_MASK, parity_err_mask.value);

	/*
	 * Unmask the system interrupt states.
	 */
	(void) hxge_fzc_sys_err_mask_set(hxgep, B_FALSE);
	(void) hxge_ldgv_setup(&ptr, &ldvp, ldv, endldg, nrequired_p);
	nldvs++;

	ldgvp->ldg_intrs = *nrequired_p;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_ldgv_init: nldvs %d navail %d nrequired %d",
	    nldvs, *navail_p, *nrequired_p));
	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_ldgv_init"));
	return (status);
}

hxge_status_t
hxge_ldgv_uninit(p_hxge_t hxgep)
{
	p_hxge_ldgv_t		ldgvp;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_ldgv_uninit"));
	ldgvp = hxgep->ldgvp;
	if (ldgvp == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_ldgv_uninit: no logical group configured."));
		return (HXGE_OK);
	}

	if (ldgvp->ldgp) {
		KMEM_FREE(ldgvp->ldgp, sizeof (hxge_ldg_t) * ldgvp->maxldgs);
	}
	if (ldgvp->ldvp) {
		KMEM_FREE(ldgvp->ldvp, sizeof (hxge_ldv_t) * ldgvp->maxldvs);
	}

	KMEM_FREE(ldgvp, sizeof (hxge_ldgv_t));
	hxgep->ldgvp = NULL;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_ldgv_uninit"));
	return (HXGE_OK);
}

hxge_status_t
hxge_intr_ldgv_init(p_hxge_t hxgep)
{
	hxge_status_t	status = HXGE_OK;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr_ldgv_init"));
	/*
	 * Configure the logical device group numbers, state vectors
	 * and interrupt masks for each logical device.
	 */
	status = hxge_fzc_intr_init(hxgep);

	/*
	 * Configure logical device masks and timers.
	 */
	status = hxge_intr_mask_mgmt(hxgep);

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intr_ldgv_init"));
	return (status);
}

hxge_status_t
hxge_intr_mask_mgmt(p_hxge_t hxgep)
{
	p_hxge_ldgv_t	ldgvp;
	p_hxge_ldg_t	ldgp;
	p_hxge_ldv_t	ldvp;
	hpi_handle_t	handle;
	int		i, j;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "==> hxge_intr_mask_mgmt"));

	if ((ldgvp = hxgep->ldgvp) == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_intr_mask_mgmt: Null ldgvp"));
		return (HXGE_ERROR);
	}
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	ldgp = ldgvp->ldgp;
	ldvp = ldgvp->ldvp;
	if (ldgp == NULL || ldvp == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_intr_mask_mgmt: Null ldgp or ldvp"));
		return (HXGE_ERROR);
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_intr_mask_mgmt: # of intrs %d ", ldgvp->ldg_intrs));
	/* Initialize masks. */
	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_intr_mask_mgmt(Hydra): # intrs %d ", ldgvp->ldg_intrs));
	for (i = 0; i < ldgvp->ldg_intrs; i++, ldgp++) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_intr_mask_mgmt(Hydra): # ldv %d in group %d",
		    ldgp->nldvs, ldgp->ldg));
		for (j = 0; j < ldgp->nldvs; j++, ldvp++) {
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_intr_mask_mgmt: set ldv # %d "
			    "for ldg %d", ldvp->ldv, ldgp->ldg));
			rs = hpi_intr_mask_set(handle, ldvp->ldv,
			    ldvp->ldv_ldf_masks);
			if (rs != HPI_SUCCESS) {
				HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
				    "<== hxge_intr_mask_mgmt: set mask failed "
				    " rs 0x%x ldv %d mask 0x%x",
				    rs, ldvp->ldv, ldvp->ldv_ldf_masks));
				return (HXGE_ERROR | rs);
			}
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_intr_mask_mgmt: set mask OK "
			    " rs 0x%x ldv %d mask 0x%x",
			    rs, ldvp->ldv, ldvp->ldv_ldf_masks));
		}
	}

	ldgp = ldgvp->ldgp;
	/* Configure timer and arm bit */
	for (i = 0; i < hxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		rs = hpi_intr_ldg_mgmt_set(handle, ldgp->ldg,
		    ldgp->arm, ldgp->ldg_timer);
		if (rs != HPI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "<== hxge_intr_mask_mgmt: set timer failed "
			    " rs 0x%x dg %d timer 0x%x",
			    rs, ldgp->ldg, ldgp->ldg_timer));
			return (HXGE_ERROR | rs);
		}
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_intr_mask_mgmt: set timer OK "
		    " rs 0x%x ldg %d timer 0x%x",
		    rs, ldgp->ldg, ldgp->ldg_timer));
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_fzc_intr_mask_mgmt"));
	return (HXGE_OK);
}

hxge_status_t
hxge_intr_mask_mgmt_set(p_hxge_t hxgep, boolean_t on)
{
	p_hxge_ldgv_t	ldgvp;
	p_hxge_ldg_t	ldgp;
	p_hxge_ldv_t	ldvp;
	hpi_handle_t	handle;
	int		i, j;
	hpi_status_t	rs = HPI_SUCCESS;

	HXGE_DEBUG_MSG((hxgep, INT_CTL,
	    "==> hxge_intr_mask_mgmt_set (%d)", on));

	if ((ldgvp = hxgep->ldgvp) == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "==> hxge_intr_mask_mgmt_set: Null ldgvp"));
		return (HXGE_ERROR);
	}
	handle = HXGE_DEV_HPI_HANDLE(hxgep);
	ldgp = ldgvp->ldgp;
	ldvp = ldgvp->ldvp;
	if (ldgp == NULL || ldvp == NULL) {
		HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
		    "<== hxge_intr_mask_mgmt_set: Null ldgp or ldvp"));
		return (HXGE_ERROR);
	}

	/* set masks. */
	for (i = 0; i < ldgvp->ldg_intrs; i++, ldgp++) {
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_intr_mask_mgmt_set: flag %d ldg %d"
		    "set mask nldvs %d", on, ldgp->ldg, ldgp->nldvs));
		for (j = 0; j < ldgp->nldvs; j++, ldvp++) {
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_intr_mask_mgmt_set: "
			    "for %d %d flag %d", i, j, on));
			if (on) {
				ldvp->ldv_ldf_masks = 0;
				HXGE_DEBUG_MSG((hxgep, INT_CTL,
				    "==> hxge_intr_mask_mgmt_set: "
				    "ON mask off"));
			} else {
				ldvp->ldv_ldf_masks = (uint8_t)LD_IM_MASK;
				HXGE_DEBUG_MSG((hxgep, INT_CTL,
				    "==> hxge_intr_mask_mgmt_set:mask on"));
			}

			rs = hpi_intr_mask_set(handle, ldvp->ldv,
			    ldvp->ldv_ldf_masks);
			if (rs != HPI_SUCCESS) {
				HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
				    "==> hxge_intr_mask_mgmt_set: "
				    "set mask failed rs 0x%x ldv %d mask 0x%x",
				    rs, ldvp->ldv, ldvp->ldv_ldf_masks));
				return (HXGE_ERROR | rs);
			}
			HXGE_DEBUG_MSG((hxgep, INT_CTL,
			    "==> hxge_intr_mask_mgmt_set: flag %d"
			    "set mask OK ldv %d mask 0x%x",
			    on, ldvp->ldv, ldvp->ldv_ldf_masks));
		}
	}

	ldgp = ldgvp->ldgp;
	/* set the arm bit */
	for (i = 0; i < hxgep->ldgvp->ldg_intrs; i++, ldgp++) {
		if (on && !ldgp->arm) {
			ldgp->arm = B_TRUE;
		} else if (!on && ldgp->arm) {
			ldgp->arm = B_FALSE;
		}
		rs = hpi_intr_ldg_mgmt_set(handle, ldgp->ldg,
		    ldgp->arm, ldgp->ldg_timer);
		if (rs != HPI_SUCCESS) {
			HXGE_ERROR_MSG((hxgep, HXGE_ERR_CTL,
			    "<== hxge_intr_mask_mgmt_set: "
			    "set timer failed rs 0x%x ldg %d timer 0x%x",
			    rs, ldgp->ldg, ldgp->ldg_timer));
			return (HXGE_ERROR | rs);
		}
		HXGE_DEBUG_MSG((hxgep, INT_CTL,
		    "==> hxge_intr_mask_mgmt_set: OK (flag %d) "
		    "set timer ldg %d timer 0x%x",
		    on, ldgp->ldg, ldgp->ldg_timer));
	}

	HXGE_DEBUG_MSG((hxgep, INT_CTL, "<== hxge_intr_mask_mgmt_set"));
	return (HXGE_OK);
}

/*
 * For Big Endian systems, the mac address will be from OBP. For Little
 * Endian (x64) systems, it will be retrieved from the card since it cannot
 * be programmed into PXE.
 * This function also populates the MMAC parameters.
 */
static hxge_status_t
hxge_get_mac_addr_properties(p_hxge_t hxgep)
{
	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "==> hxge_get_mac_addr_properties "));

	(void) hxge_pfc_mac_addrs_get(hxgep);
	hxgep->ouraddr = hxgep->factaddr;

	HXGE_DEBUG_MSG((hxgep, DDI_CTL, "<== hxge_get_mac_addr_properties "));
	return (HXGE_OK);
}

static void
hxge_ldgv_setup(p_hxge_ldg_t *ldgp, p_hxge_ldv_t *ldvp, uint8_t ldv,
	uint8_t endldg, int *ngrps)
{
	HXGE_DEBUG_MSG((NULL, INT_CTL, "==> hxge_ldgv_setup"));
	/* Assign the group number for each device. */
	(*ldvp)->ldg_assigned = (*ldgp)->ldg;
	(*ldvp)->ldgp = *ldgp;
	(*ldvp)->ldv = ldv;

	HXGE_DEBUG_MSG((NULL, INT_CTL,
	    "==> hxge_ldgv_setup: ldv %d endldg %d ldg %d, ldvp $%p",
	    ldv, endldg, (*ldgp)->ldg, (*ldgp)->ldvp));

	(*ldgp)->nldvs++;
	if ((*ldgp)->ldg == (endldg - 1)) {
		if ((*ldgp)->ldvp == NULL) {
			(*ldgp)->ldvp = *ldvp;
			*ngrps += 1;
			HXGE_DEBUG_MSG((NULL, INT_CTL,
			    "==> hxge_ldgv_setup: ngrps %d", *ngrps));
		}
		HXGE_DEBUG_MSG((NULL, INT_CTL,
		    "==> hxge_ldgv_setup: ldvp $%p ngrps %d",
		    *ldvp, *ngrps));
		++*ldvp;
	} else {
		(*ldgp)->ldvp = *ldvp;
		*ngrps += 1;
		HXGE_DEBUG_MSG((NULL, INT_CTL, "==> hxge_ldgv_setup(done): "
		    "ldv %d endldg %d ldg %d, ldvp $%p",
		    ldv, endldg, (*ldgp)->ldg, (*ldgp)->ldvp));
		++*ldvp;
		++*ldgp;
		HXGE_DEBUG_MSG((NULL, INT_CTL,
		    "==> hxge_ldgv_setup: new ngrps %d", *ngrps));
	}

	HXGE_DEBUG_MSG((NULL, INT_CTL, "==> hxge_ldgv_setup: "
	    "ldg %d nldvs %d ldv %d ldvp $%p endldg %d ngrps %d",
	    (*ldgp)->ldg, (*ldgp)->nldvs, ldv, ldvp, endldg, *ngrps));

	HXGE_DEBUG_MSG((NULL, INT_CTL, "<== hxge_ldgv_setup"));
}
