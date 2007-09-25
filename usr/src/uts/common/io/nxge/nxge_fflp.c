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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <npi_fflp.h>
#include <npi_mac.h>
#include <nxge_defs.h>
#include <nxge_flow.h>
#include <nxge_fflp.h>
#include <nxge_impl.h>
#include <nxge_fflp_hash.h>
#include <nxge_common.h>


/*
 * Function prototypes
 */
static nxge_status_t nxge_fflp_vlan_tbl_clear_all(p_nxge_t);
static nxge_status_t nxge_fflp_tcam_invalidate_all(p_nxge_t);
static nxge_status_t nxge_fflp_tcam_init(p_nxge_t);
static nxge_status_t nxge_fflp_fcram_invalidate_all(p_nxge_t);
static nxge_status_t nxge_fflp_fcram_init(p_nxge_t);
static int nxge_flow_need_hash_lookup(p_nxge_t, flow_resource_t *);
static void nxge_fill_tcam_entry_tcp(p_nxge_t, flow_spec_t *, tcam_entry_t *);
static void nxge_fill_tcam_entry_udp(p_nxge_t, flow_spec_t *, tcam_entry_t *);
static void nxge_fill_tcam_entry_sctp(p_nxge_t, flow_spec_t *, tcam_entry_t *);
static void nxge_fill_tcam_entry_tcp_ipv6(p_nxge_t, flow_spec_t *,
	tcam_entry_t *);
static void nxge_fill_tcam_entry_udp_ipv6(p_nxge_t, flow_spec_t *,
	tcam_entry_t *);
static void nxge_fill_tcam_entry_sctp_ipv6(p_nxge_t, flow_spec_t *,
	tcam_entry_t *);
static uint8_t nxge_get_rdc_offset(p_nxge_t, uint8_t, intptr_t);
static uint8_t nxge_get_rdc_group(p_nxge_t, uint8_t, intptr_t);
static tcam_location_t nxge_get_tcam_location(p_nxge_t, uint8_t);

/*
 * functions used outside this file
 */
nxge_status_t nxge_fflp_config_vlan_table(p_nxge_t, uint16_t);
nxge_status_t nxge_fflp_ip_class_config_all(p_nxge_t);
nxge_status_t nxge_add_flow(p_nxge_t, flow_resource_t *);
static nxge_status_t nxge_tcam_handle_ip_fragment(p_nxge_t);
nxge_status_t nxge_add_tcam_entry(p_nxge_t, flow_resource_t *);
nxge_status_t nxge_add_fcram_entry(p_nxge_t, flow_resource_t *);
nxge_status_t nxge_flow_get_hash(p_nxge_t, flow_resource_t *,
	uint32_t *, uint16_t *);

nxge_status_t
nxge_tcam_dump_entry(p_nxge_t nxgep, uint32_t location)
{
	tcam_entry_t tcam_rdptr;
	uint64_t asc_ram = 0;
	npi_handle_t handle;
	npi_status_t status;

	handle = nxgep->npi_reg_handle;

	bzero((char *)&tcam_rdptr, sizeof (struct tcam_entry));
	status = npi_fflp_tcam_entry_read(handle, (tcam_location_t)location,
		(struct tcam_entry *)&tcam_rdptr);
	if (status & NPI_FAILURE) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_tcam_dump_entry:"
			"  tcam read failed at location %d ", location));
		return (NXGE_ERROR);
	}
	status = npi_fflp_tcam_asc_ram_entry_read(handle,
		(tcam_location_t)location, &asc_ram);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "location %x\n"
		" key:  %llx %llx %llx %llx \n"
		" mask: %llx %llx %llx %llx \n"
		" ASC RAM %llx \n", location,
		tcam_rdptr.key0, tcam_rdptr.key1,
		tcam_rdptr.key2, tcam_rdptr.key3,
		tcam_rdptr.mask0, tcam_rdptr.mask1,
		tcam_rdptr.mask2, tcam_rdptr.mask3, asc_ram));
	return (NXGE_OK);
}

void
nxge_get_tcam(p_nxge_t nxgep, p_mblk_t mp)
{
	uint32_t tcam_loc;
	int *lptr;
	int location;

	uint32_t start_location = 0;
	uint32_t stop_location = nxgep->classifier.tcam_size;
	lptr = (int *)mp->b_rptr;
	location = *lptr;

	if ((location >= nxgep->classifier.tcam_size) || (location < -1)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_tcam_dump: Invalid location %d \n", location));
		return;
	}
	if (location == -1) {
		start_location = 0;
		stop_location = nxgep->classifier.tcam_size;
	} else {
		start_location = location;
		stop_location = location + 1;
	}
	for (tcam_loc = start_location; tcam_loc < stop_location; tcam_loc++)
		(void) nxge_tcam_dump_entry(nxgep, tcam_loc);
}

/*
 * nxge_fflp_vlan_table_invalidate_all
 * invalidates the vlan RDC table entries.
 * INPUT
 * nxge    soft state data structure
 * Return
 *      NXGE_OK
 *      NXGE_ERROR
 *
 */

static nxge_status_t
nxge_fflp_vlan_tbl_clear_all(p_nxge_t nxgep)
{
	vlan_id_t vlan_id;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	vlan_id_t start = 0, stop = NXGE_MAX_VLANS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_vlan_tbl_clear_all "));
	handle = nxgep->npi_reg_handle;
	for (vlan_id = start; vlan_id < stop; vlan_id++) {
		rs = npi_fflp_cfg_vlan_table_clear(handle, vlan_id);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"VLAN Table invalidate failed for vlan id %d ",
				vlan_id));
			return (NXGE_ERROR | rs);
		}
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_vlan_tbl_clear_all "));
	return (NXGE_OK);
}

/*
 * The following functions are used by other modules to init
 * the fflp module.
 * these functions are the basic API used to init
 * the fflp modules (tcam, fcram etc ......)
 *
 * The TCAM search future would be disabled  by default.
 */

static nxge_status_t
nxge_fflp_tcam_init(p_nxge_t nxgep)
{
	uint8_t access_ratio;
	tcam_class_t class;
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_tcam_init"));
	handle = nxgep->npi_reg_handle;

	rs = npi_fflp_cfg_tcam_disable(handle);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "failed TCAM Disable\n"));
		return (NXGE_ERROR | rs);
	}

	access_ratio = nxgep->param_arr[param_tcam_access_ratio].value;
	rs = npi_fflp_cfg_tcam_access(handle, access_ratio);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"failed TCAM Access cfg\n"));
		return (NXGE_ERROR | rs);
	}

	/* disable configurable classes */
	/* disable the configurable ethernet classes; */
	for (class = TCAM_CLASS_ETYPE_1;
		class <= TCAM_CLASS_ETYPE_2; class++) {
		rs = npi_fflp_cfg_enet_usr_cls_disable(handle, class);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"TCAM USR Ether Class config failed."));
			return (NXGE_ERROR | rs);
		}
	}

	/* disable the configurable ip classes; */
	for (class = TCAM_CLASS_IP_USER_4;
		class <= TCAM_CLASS_IP_USER_7; class++) {
		rs = npi_fflp_cfg_ip_usr_cls_disable(handle, class);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"TCAM USR IP Class cnfg failed."));
			return (NXGE_ERROR | rs);
		}
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_tcam_init"));
	return (NXGE_OK);
}

/*
 * nxge_fflp_tcam_invalidate_all
 * invalidates all the tcam entries.
 * INPUT
 * nxge    soft state data structure
 * Return
 *      NXGE_OK
 *      NXGE_ERROR
 *
 */


static nxge_status_t
nxge_fflp_tcam_invalidate_all(p_nxge_t nxgep)
{
	uint16_t location;
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle;
	uint16_t start = 0, stop = nxgep->classifier.tcam_size;
	p_nxge_hw_list_t hw_p;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		"==> nxge_fflp_tcam_invalidate_all"));
	handle = nxgep->npi_reg_handle;
	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_tcam_invalidate_all:"
			" common hardware not set", nxgep->niu_type));
		return (NXGE_ERROR);
	}
	MUTEX_ENTER(&hw_p->nxge_tcam_lock);
	for (location = start; location < stop; location++) {
		rs = npi_fflp_tcam_entry_invalidate(handle, location);
		if (rs != NPI_SUCCESS) {
			MUTEX_EXIT(&hw_p->nxge_tcam_lock);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"TCAM invalidate failed at loc %d ", location));
			return (NXGE_ERROR | rs);
		}
	}
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			"<== nxge_fflp_tcam_invalidate_all"));
	return (NXGE_OK);
}

/*
 * nxge_fflp_fcram_entry_invalidate_all
 * invalidates all the FCRAM entries.
 * INPUT
 * nxge    soft state data structure
 * Return
 *      NXGE_OK
 *      NXGE_ERROR
 *
 */

static nxge_status_t
nxge_fflp_fcram_invalidate_all(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	part_id_t pid = 0;
	uint8_t base_mask, base_reloc;
	fcram_entry_t fc;
	uint32_t location;
	uint32_t increment, last_location;

	/*
	 * (1) configure and enable partition 0 with no relocation
	 * (2) Assume the FCRAM is used as IPv4 exact match entry cells
	 * (3) Invalidate these cells by clearing the valid bit in
	 * the subareas 0 and 4
	 * (4) disable the partition
	 *
	 */

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_fcram_invalidate_all"));

	base_mask = base_reloc = 0x0;
	handle = nxgep->npi_reg_handle;
	rs = npi_fflp_cfg_fcram_partition(handle, pid, base_mask, base_reloc);

	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "failed partition cfg\n"));
		return (NXGE_ERROR | rs);
	}
	rs = npi_fflp_cfg_fcram_partition_disable(handle, pid);

	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed partition enable\n"));
		return (NXGE_ERROR | rs);
	}
	fc.dreg[0].value = 0;
	fc.hash_hdr_valid = 0;
	fc.hash_hdr_ext = 1;	/* specify as IPV4 exact match entry */
	increment = sizeof (hash_ipv4_t);
	last_location = FCRAM_SIZE * 0x40;

	for (location = 0; location < last_location; location += increment) {
		rs = npi_fflp_fcram_subarea_write(handle, pid,
			location,
			fc.value[0]);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					"failed write"
					"at location %x ",
					location));
			return (NXGE_ERROR | rs);
		}
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_fcram_invalidate_all"));
	return (NXGE_OK);
}

static nxge_status_t
nxge_fflp_fcram_init(p_nxge_t nxgep)
{
	fflp_fcram_output_drive_t strength;
	fflp_fcram_qs_t qs;
	npi_status_t rs = NPI_SUCCESS;
	uint8_t access_ratio;
	int partition;
	npi_handle_t handle;
	uint32_t min_time, max_time, sys_time;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_fcram_init"));

	/*
	 * Recommended values are needed.
	 */
	min_time = FCRAM_REFRESH_DEFAULT_MIN_TIME;
	max_time = FCRAM_REFRESH_DEFAULT_MAX_TIME;
	sys_time = FCRAM_REFRESH_DEFAULT_SYS_TIME;

	handle = nxgep->npi_reg_handle;
	strength = FCRAM_OUTDR_NORMAL;
	qs = FCRAM_QS_MODE_QS;
	rs = npi_fflp_cfg_fcram_reset(handle, strength, qs);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "failed FCRAM Reset. "));
		return (NXGE_ERROR | rs);
	}

	access_ratio = nxgep->param_arr[param_fcram_access_ratio].value;
	rs = npi_fflp_cfg_fcram_access(handle, access_ratio);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "failed FCRAM Access ratio"
			"configuration \n"));
		return (NXGE_ERROR | rs);
	}
	rs = npi_fflp_cfg_fcram_refresh_time(handle, min_time,
		max_time, sys_time);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed FCRAM refresh cfg"));
		return (NXGE_ERROR);
	}

	/* disable all the partitions until explicitly enabled */
	for (partition = 0; partition < FFLP_FCRAM_MAX_PARTITION; partition++) {
		rs = npi_fflp_cfg_fcram_partition_disable(handle, partition);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"failed FCRAM partition"
				" enable for partition %d ", partition));
			return (NXGE_ERROR | rs);
		}
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_fcram_init"));
	return (NXGE_OK);
}

nxge_status_t
nxge_logical_mac_assign_rdc_table(p_nxge_t nxgep, uint8_t alt_mac)
{
	npi_status_t rs = NPI_SUCCESS;
	hostinfo_t mac_rdc;
	npi_handle_t handle;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	if (p_class_cfgp->mac_host_info[alt_mac].flag == 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_logical_mac_assign_rdc_table"
			" unconfigured alt MAC addr %d ", alt_mac));
		return (NXGE_ERROR);
	}
	handle = nxgep->npi_reg_handle;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num =
		p_class_cfgp->mac_host_info[alt_mac].rdctbl;
	mac_rdc.bits.w0.mac_pref = p_class_cfgp->mac_host_info[alt_mac].mpr_npr;

	rs = npi_mac_hostinfo_entry(handle, OP_SET,
		nxgep->function_num, alt_mac, &mac_rdc);

	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed Assign RDC table"));
		return (NXGE_ERROR | rs);
	}
	return (NXGE_OK);
}

nxge_status_t
nxge_main_mac_assign_rdc_table(p_nxge_t nxgep)
{
	npi_status_t rs = NPI_SUCCESS;
	hostinfo_t mac_rdc;
	npi_handle_t handle;

	handle = nxgep->npi_reg_handle;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = nxgep->class_config.mac_rdcgrp;
	mac_rdc.bits.w0.mac_pref = 1;
	switch (nxgep->function_num) {
	case 0:
	case 1:
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
			nxgep->function_num, XMAC_UNIQUE_HOST_INFO_ENTRY,
			&mac_rdc);
		break;
	case 2:
	case 3:
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
			nxgep->function_num, BMAC_UNIQUE_HOST_INFO_ENTRY,
			&mac_rdc);
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed Assign RDC table (invalid function #)"));
		return (NXGE_ERROR);
	}

	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"failed Assign RDC table"));
		return (NXGE_ERROR | rs);
	}
	return (NXGE_OK);
}

/*
 * Initialize hostinfo registers for alternate MAC addresses and
 * multicast MAC address.
 */
nxge_status_t
nxge_alt_mcast_mac_assign_rdc_table(p_nxge_t nxgep)
{
	npi_status_t rs = NPI_SUCCESS;
	hostinfo_t mac_rdc;
	npi_handle_t handle;
	int i;

	handle = nxgep->npi_reg_handle;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = nxgep->class_config.mcast_rdcgrp;
	mac_rdc.bits.w0.mac_pref = 1;
	switch (nxgep->function_num) {
	case 0:
	case 1:
		/*
		 * Tests indicate that it is OK not to re-initialize the
		 * hostinfo registers for the XMAC's alternate MAC
		 * addresses. But that is necessary for BMAC (case 2
		 * and case 3 below)
		 */
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
			nxgep->function_num,
			XMAC_MULTI_HOST_INFO_ENTRY, &mac_rdc);
		break;
	case 2:
	case 3:
		for (i = 1; i <= BMAC_MAX_ALT_ADDR_ENTRY; i++)
			rs |= npi_mac_hostinfo_entry(handle, OP_SET,
			nxgep->function_num, i, &mac_rdc);

		rs |= npi_mac_hostinfo_entry(handle, OP_SET,
			nxgep->function_num,
			BMAC_MULTI_HOST_INFO_ENTRY, &mac_rdc);
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed Assign RDC table (invalid funcion #)"));
		return (NXGE_ERROR);
	}

	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed Assign RDC table"));
		return (NXGE_ERROR | rs);
	}
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_init_hostinfo(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;

	status = nxge_alt_mcast_mac_assign_rdc_table(nxgep);
	status |= nxge_main_mac_assign_rdc_table(nxgep);
	return (status);
}

nxge_status_t
nxge_fflp_hw_reset(p_nxge_t nxgep)
{
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_hw_reset"));

	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		status = nxge_fflp_fcram_init(nxgep);
		if (status != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				" failed FCRAM init. "));
			return (status);
		}
	}

	status = nxge_fflp_tcam_init(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed TCAM init."));
		return (status);
	}

	handle = nxgep->npi_reg_handle;
	rs = npi_fflp_cfg_llcsnap_enable(handle);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed LLCSNAP enable. "));
		return (NXGE_ERROR | rs);
	}

	rs = npi_fflp_cfg_cam_errorcheck_disable(handle);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed CAM Error Check enable. "));
		return (NXGE_ERROR | rs);
	}

	/* init the hash generators */
	rs = npi_fflp_cfg_hash_h1poly(handle, 0);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed H1 Poly Init. "));
		return (NXGE_ERROR | rs);
	}

	rs = npi_fflp_cfg_hash_h2poly(handle, 0);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed H2 Poly Init. "));
		return (NXGE_ERROR | rs);
	}

	/* invalidate TCAM entries */
	status = nxge_fflp_tcam_invalidate_all(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed TCAM Entry Invalidate. "));
		return (status);
	}

	/* invalidate FCRAM entries */
	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		status = nxge_fflp_fcram_invalidate_all(nxgep);
		if (status != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					"failed FCRAM Entry Invalidate."));
			return (status);
		}
	}

	/* invalidate VLAN RDC tables */
	status = nxge_fflp_vlan_tbl_clear_all(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"failed VLAN Table Invalidate. "));
		return (status);
	}
	nxgep->classifier.state |= NXGE_FFLP_HW_RESET;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_hw_reset"));
	return (NXGE_OK);
}

nxge_status_t
nxge_cfg_ip_cls_flow_key(p_nxge_t nxgep, tcam_class_t l3_class,
	uint32_t class_config)
{
	flow_key_cfg_t fcfg;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_cfg_ip_cls_flow_key"));
	handle = nxgep->npi_reg_handle;
	bzero(&fcfg, sizeof (flow_key_cfg_t));

	if (class_config & NXGE_CLASS_FLOW_USE_PROTO)
		fcfg.use_proto = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_DST_PORT)
		fcfg.use_dport = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_SRC_PORT)
		fcfg.use_sport = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_IPDST)
		fcfg.use_daddr = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_IPSRC)
		fcfg.use_saddr = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_VLAN)
		fcfg.use_vlan = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_L2DA)
		fcfg.use_l2da = 1;
	if (class_config & NXGE_CLASS_FLOW_USE_PORTNUM)
		fcfg.use_portnum = 1;
	fcfg.ip_opts_exist = 0;

	rs = npi_fflp_cfg_ip_cls_flow_key(handle, l3_class, &fcfg);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, " nxge_cfg_ip_cls_flow_key"
			" opt %x for class %d failed ",
			class_config, l3_class));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " <== nxge_cfg_ip_cls_flow_key"));
	return (NXGE_OK);
}

nxge_status_t
nxge_cfg_ip_cls_flow_key_get(p_nxge_t nxgep, tcam_class_t l3_class,
	uint32_t *class_config)
{
	flow_key_cfg_t fcfg;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint32_t ccfg = 0;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_cfg_ip_cls_flow_key_get"));
	handle = nxgep->npi_reg_handle;
	bzero(&fcfg, sizeof (flow_key_cfg_t));

	rs = npi_fflp_cfg_ip_cls_flow_key_get(handle, l3_class, &fcfg);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, " nxge_cfg_ip_cls_flow_key"
				" opt %x for class %d failed ",
				class_config, l3_class));
		return (NXGE_ERROR | rs);
	}

	if (fcfg.use_proto)
		ccfg |= NXGE_CLASS_FLOW_USE_PROTO;
	if (fcfg.use_dport)
		ccfg |= NXGE_CLASS_FLOW_USE_DST_PORT;
	if (fcfg.use_sport)
		ccfg |= NXGE_CLASS_FLOW_USE_SRC_PORT;
	if (fcfg.use_daddr)
		ccfg |= NXGE_CLASS_FLOW_USE_IPDST;
	if (fcfg.use_saddr)
		ccfg |= NXGE_CLASS_FLOW_USE_IPSRC;
	if (fcfg.use_vlan)
		ccfg |= NXGE_CLASS_FLOW_USE_VLAN;
	if (fcfg.use_l2da)
		ccfg |= NXGE_CLASS_FLOW_USE_L2DA;
	if (fcfg.use_portnum)
		ccfg |= NXGE_CLASS_FLOW_USE_PORTNUM;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" nxge_cfg_ip_cls_flow_key_get %x", ccfg));
	*class_config = ccfg;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_cfg_ip_cls_flow_key_get"));
	return (NXGE_OK);
}

static nxge_status_t
nxge_cfg_tcam_ip_class_get(p_nxge_t nxgep, tcam_class_t class,
	uint32_t *class_config)
{
	npi_status_t rs = NPI_SUCCESS;
	tcam_key_cfg_t cfg;
	npi_handle_t handle;
	uint32_t ccfg = 0;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_cfg_tcam_ip_class"));

	bzero(&cfg, sizeof (tcam_key_cfg_t));
	handle = nxgep->npi_reg_handle;

	rs = npi_fflp_cfg_ip_cls_tcam_key_get(handle, class, &cfg);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, " nxge_cfg_tcam_ip_class"
			" opt %x for class %d failed ",
			class_config, class));
		return (NXGE_ERROR | rs);
	}
	if (cfg.discard)
		ccfg |= NXGE_CLASS_DISCARD;
	if (cfg.lookup_enable)
		ccfg |= NXGE_CLASS_TCAM_LOOKUP;
	if (cfg.use_ip_daddr)
		ccfg |= NXGE_CLASS_TCAM_USE_SRC_ADDR;
	*class_config = ccfg;
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			" ==> nxge_cfg_tcam_ip_class %x", ccfg));
	return (NXGE_OK);
}

static nxge_status_t
nxge_cfg_tcam_ip_class(p_nxge_t nxgep, tcam_class_t class,
	uint32_t class_config)
{
	npi_status_t rs = NPI_SUCCESS;
	tcam_key_cfg_t cfg;
	npi_handle_t handle;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_cfg_tcam_ip_class"));

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	p_class_cfgp->class_cfg[class] = class_config;

	bzero(&cfg, sizeof (tcam_key_cfg_t));
	handle = nxgep->npi_reg_handle;
	cfg.discard = 0;
	cfg.lookup_enable = 0;
	cfg.use_ip_daddr = 0;
	if (class_config & NXGE_CLASS_DISCARD)
		cfg.discard = 1;
	if (class_config & NXGE_CLASS_TCAM_LOOKUP)
		cfg.lookup_enable = 1;
	if (class_config & NXGE_CLASS_TCAM_USE_SRC_ADDR)
		cfg.use_ip_daddr = 1;

	rs = npi_fflp_cfg_ip_cls_tcam_key(handle, class, &cfg);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, " nxge_cfg_tcam_ip_class"
			" opt %x for class %d failed ",
			class_config, class));
		return (NXGE_ERROR | rs);
	}
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_set_hash1(p_nxge_t nxgep, uint32_t h1)
{
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_init_h1"));
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	p_class_cfgp->init_h1 = h1;
	handle = nxgep->npi_reg_handle;
	rs = npi_fflp_cfg_hash_h1poly(handle, h1);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_init_h1 %x failed ", h1));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " <== nxge_fflp_init_h1"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_set_hash2(p_nxge_t nxgep, uint16_t h2)
{
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_init_h2"));
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	p_class_cfgp->init_h2 = h2;

	handle = nxgep->npi_reg_handle;
	rs = npi_fflp_cfg_hash_h2poly(handle, h2);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_init_h2 %x failed ", h2));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " <== nxge_fflp_init_h2"));
	return (NXGE_OK);
}

nxge_status_t
nxge_classify_init_sw(p_nxge_t nxgep)
{
	int alloc_size;
	nxge_classify_t *classify_ptr;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_classify_init_sw"));
	classify_ptr = &nxgep->classifier;

	if (classify_ptr->state & NXGE_FFLP_SW_INIT) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			"nxge_classify_init_sw already init"));
		return (NXGE_OK);
	}
	/* Init SW structures */
	classify_ptr->tcam_size = TCAM_NIU_TCAM_MAX_ENTRY;

	/* init data structures, based on HW type */
	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		classify_ptr->tcam_size = TCAM_NXGE_TCAM_MAX_ENTRY;
		/*
		 * check if fcram based classification is required and init the
		 * flow storage
		 */
	}
	alloc_size = sizeof (tcam_flow_spec_t) * classify_ptr->tcam_size;
	classify_ptr->tcam_entries = KMEM_ZALLOC(alloc_size, NULL);

	/* Init defaults */
	/*
	 * add hacks required for HW shortcomings for example, code to handle
	 * fragmented packets
	 */
	nxge_init_h1_table();
	nxge_crc_ccitt_init();
	nxgep->classifier.tcam_location = nxgep->function_num;
	nxgep->classifier.fragment_bug = 1;
	classify_ptr->state |= NXGE_FFLP_SW_INIT;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_classify_init_sw"));
	return (NXGE_OK);
}

nxge_status_t
nxge_classify_exit_sw(p_nxge_t nxgep)
{
	int alloc_size;
	nxge_classify_t *classify_ptr;
	int fsize;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_classify_exit_sw"));
	classify_ptr = &nxgep->classifier;

	fsize = sizeof (tcam_flow_spec_t);
	if (classify_ptr->tcam_entries) {
		alloc_size = fsize * classify_ptr->tcam_size;
		KMEM_FREE((void *) classify_ptr->tcam_entries, alloc_size);
	}
	nxgep->classifier.state = NULL;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_classify_exit_sw"));
	return (NXGE_OK);
}

/*
 * Figures out the location where the TCAM entry is
 * to be inserted.
 *
 * The current implementation is just a place holder and it
 * returns the next tcam location.
 * The real location determining algorithm would consider
 * the priority, partition etc ... before deciding which
 * location to insert.
 *
 */

/* ARGSUSED */
static tcam_location_t
nxge_get_tcam_location(p_nxge_t nxgep, uint8_t class)
{
	tcam_location_t location;

	location = nxgep->classifier.tcam_location;
	nxgep->classifier.tcam_location = (location + nxgep->nports) %
		nxgep->classifier.tcam_size;
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		"nxge_get_tcam_location: location %d next %d \n",
		location, nxgep->classifier.tcam_location));
	return (location);
}

/*
 * Figures out the RDC Group for the entry
 *
 * The current implementation is just a place holder and it
 * returns 0.
 * The real location determining algorithm would consider
 * the partition etc ... before deciding w
 *
 */

/* ARGSUSED */
static uint8_t
nxge_get_rdc_group(p_nxge_t nxgep, uint8_t class, intptr_t cookie)
{
	int use_port_rdc_grp = 0;
	uint8_t rdc_grp = 0;
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;
	p_nxge_rdc_grp_t rdc_grp_p;

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	rdc_grp_p = &p_dma_cfgp->rdc_grps[use_port_rdc_grp];
	rdc_grp = p_cfgp->start_rdc_grpid;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"nxge_get_rdc_group: grp 0x%x real_grp %x grpp $%p\n",
		cookie, rdc_grp, rdc_grp_p));
	return (rdc_grp);
}

/* ARGSUSED */
static uint8_t
nxge_get_rdc_offset(p_nxge_t nxgep, uint8_t class, intptr_t cookie)
{
	return ((uint8_t)cookie);
}

/* ARGSUSED */
static void
nxge_fill_tcam_entry_udp(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	udpip4_spec_t *fspec_key;
	udpip4_spec_t *fspec_mask;

	fspec_key = (udpip4_spec_t *)&flow_spec->uh.udpip4spec;
	fspec_mask = (udpip4_spec_t *)&flow_spec->um.udpip4spec;
	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_key, fspec_key->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_mask, fspec_mask->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_key, fspec_key->ip4src);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_mask, fspec_mask->ip4src);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
	TCAM_IP_CLASS(tcam_ptr->ip4_class_key,
		tcam_ptr->ip4_class_mask,
		TCAM_CLASS_UDP_IPV4);
	TCAM_IP_PROTO(tcam_ptr->ip4_proto_key,
		tcam_ptr->ip4_proto_mask,
		IPPROTO_UDP);
}

static void
nxge_fill_tcam_entry_udp_ipv6(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	udpip6_spec_t *fspec_key;
	udpip6_spec_t *fspec_mask;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	fspec_key = (udpip6_spec_t *)&flow_spec->uh.udpip6spec;
	fspec_mask = (udpip6_spec_t *)&flow_spec->um.udpip6spec;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	if (p_class_cfgp->class_cfg[TCAM_CLASS_UDP_IPV6] &
			NXGE_CLASS_TCAM_USE_SRC_ADDR) {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6src);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6src);
	} else {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6dst);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6dst);
	}

	TCAM_IP_CLASS(tcam_ptr->ip6_class_key,
		tcam_ptr->ip6_class_mask, TCAM_CLASS_UDP_IPV6);
	TCAM_IP_PROTO(tcam_ptr->ip6_nxt_hdr_key,
		tcam_ptr->ip6_nxt_hdr_mask, IPPROTO_UDP);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
}

/* ARGSUSED */
static void
nxge_fill_tcam_entry_tcp(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	tcpip4_spec_t *fspec_key;
	tcpip4_spec_t *fspec_mask;

	fspec_key = (tcpip4_spec_t *)&flow_spec->uh.tcpip4spec;
	fspec_mask = (tcpip4_spec_t *)&flow_spec->um.tcpip4spec;

	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_key, fspec_key->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_mask, fspec_mask->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_key, fspec_key->ip4src);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_mask, fspec_mask->ip4src);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
	TCAM_IP_CLASS(tcam_ptr->ip4_class_key,
		tcam_ptr->ip4_class_mask, TCAM_CLASS_TCP_IPV4);
	TCAM_IP_PROTO(tcam_ptr->ip4_proto_key,
		tcam_ptr->ip4_proto_mask, IPPROTO_TCP);
}

/* ARGSUSED */
static void
nxge_fill_tcam_entry_sctp(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	tcpip4_spec_t *fspec_key;
	tcpip4_spec_t *fspec_mask;

	fspec_key = (tcpip4_spec_t *)&flow_spec->uh.tcpip4spec;
	fspec_mask = (tcpip4_spec_t *)&flow_spec->um.tcpip4spec;

	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_key, fspec_key->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_mask, fspec_mask->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_key, fspec_key->ip4src);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_mask, fspec_mask->ip4src);
	TCAM_IP_CLASS(tcam_ptr->ip4_class_key,
		tcam_ptr->ip4_class_mask, TCAM_CLASS_SCTP_IPV4);
	TCAM_IP_PROTO(tcam_ptr->ip4_proto_key,
		tcam_ptr->ip4_proto_mask, IPPROTO_SCTP);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip4_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
}

static void
nxge_fill_tcam_entry_tcp_ipv6(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	tcpip6_spec_t *fspec_key;
	tcpip6_spec_t *fspec_mask;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	fspec_key = (tcpip6_spec_t *)&flow_spec->uh.tcpip6spec;
	fspec_mask = (tcpip6_spec_t *)&flow_spec->um.tcpip6spec;

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	if (p_class_cfgp->class_cfg[TCAM_CLASS_UDP_IPV6] &
			NXGE_CLASS_TCAM_USE_SRC_ADDR) {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6src);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6src);
	} else {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6dst);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6dst);
	}

	TCAM_IP_CLASS(tcam_ptr->ip6_class_key,
		tcam_ptr->ip6_class_mask, TCAM_CLASS_TCP_IPV6);
	TCAM_IP_PROTO(tcam_ptr->ip6_nxt_hdr_key,
		tcam_ptr->ip6_nxt_hdr_mask, IPPROTO_TCP);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
}

static void
nxge_fill_tcam_entry_sctp_ipv6(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	tcpip6_spec_t *fspec_key;
	tcpip6_spec_t *fspec_mask;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	fspec_key = (tcpip6_spec_t *)&flow_spec->uh.tcpip6spec;
	fspec_mask = (tcpip6_spec_t *)&flow_spec->um.tcpip6spec;
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;

	if (p_class_cfgp->class_cfg[TCAM_CLASS_UDP_IPV6] &
			NXGE_CLASS_TCAM_USE_SRC_ADDR) {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6src);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6src);
	} else {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6dst);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6dst);
	}

	TCAM_IP_CLASS(tcam_ptr->ip6_class_key,
		tcam_ptr->ip6_class_mask, TCAM_CLASS_SCTP_IPV6);
	TCAM_IP_PROTO(tcam_ptr->ip6_nxt_hdr_key,
		tcam_ptr->ip6_nxt_hdr_mask, IPPROTO_SCTP);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_key,
		fspec_key->pdst, fspec_key->psrc);
	TCAM_IP_PORTS(tcam_ptr->ip6_port_mask,
		fspec_mask->pdst, fspec_mask->psrc);
}

nxge_status_t
nxge_flow_get_hash(p_nxge_t nxgep, flow_resource_t *flow_res,
	uint32_t *H1, uint16_t *H2)
{
	flow_spec_t *flow_spec;
	uint32_t class_cfg;
	flow_template_t ft;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	int ft_size = sizeof (flow_template_t);

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_flow_get_hash"));

	flow_spec = (flow_spec_t *)&flow_res->flow_spec;
	bzero((char *)&ft, ft_size);
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;

	switch (flow_spec->flow_type) {
	case FSPEC_TCPIP4:
		class_cfg = p_class_cfgp->class_cfg[TCAM_CLASS_TCP_IPV4];
		if (class_cfg & NXGE_CLASS_FLOW_USE_PROTO)
			ft.ip_proto = IPPROTO_TCP;
		if (class_cfg & NXGE_CLASS_FLOW_USE_IPSRC)
			ft.ip4_saddr = flow_res->flow_spec.uh.tcpip4spec.ip4src;
		if (class_cfg & NXGE_CLASS_FLOW_USE_IPDST)
			ft.ip4_daddr = flow_res->flow_spec.uh.tcpip4spec.ip4dst;
		if (class_cfg & NXGE_CLASS_FLOW_USE_SRC_PORT)
			ft.ip_src_port = flow_res->flow_spec.uh.tcpip4spec.psrc;
		if (class_cfg & NXGE_CLASS_FLOW_USE_DST_PORT)
			ft.ip_dst_port = flow_res->flow_spec.uh.tcpip4spec.pdst;
		break;

	case FSPEC_UDPIP4:
		class_cfg = p_class_cfgp->class_cfg[TCAM_CLASS_UDP_IPV4];
		if (class_cfg & NXGE_CLASS_FLOW_USE_PROTO)
			ft.ip_proto = IPPROTO_UDP;
		if (class_cfg & NXGE_CLASS_FLOW_USE_IPSRC)
			ft.ip4_saddr = flow_res->flow_spec.uh.udpip4spec.ip4src;
		if (class_cfg & NXGE_CLASS_FLOW_USE_IPDST)
			ft.ip4_daddr = flow_res->flow_spec.uh.udpip4spec.ip4dst;
		if (class_cfg & NXGE_CLASS_FLOW_USE_SRC_PORT)
			ft.ip_src_port = flow_res->flow_spec.uh.udpip4spec.psrc;
		if (class_cfg & NXGE_CLASS_FLOW_USE_DST_PORT)
			ft.ip_dst_port = flow_res->flow_spec.uh.udpip4spec.pdst;
		break;

	default:
		return (NXGE_ERROR);
	}

	*H1 = nxge_compute_h1(p_class_cfgp->init_h1,
		(uint32_t *)&ft, ft_size) & 0xfffff;
	*H2 = nxge_compute_h2(p_class_cfgp->init_h2,
		(uint8_t *)&ft, ft_size);

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_flow_get_hash"));
	return (NXGE_OK);
}

nxge_status_t
nxge_add_fcram_entry(p_nxge_t nxgep, flow_resource_t *flow_res)
{
	uint32_t H1;
	uint16_t H2;
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_add_fcram_entry"));
	status = nxge_flow_get_hash(nxgep, flow_res, &H1, &H2);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_add_fcram_entry failed "));
		return (status);
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_add_fcram_entry"));
	return (NXGE_OK);
}

/*
 * Already decided this flow goes into the tcam
 */

nxge_status_t
nxge_add_tcam_entry(p_nxge_t nxgep, flow_resource_t *flow_res)
{
	npi_handle_t handle;
	intptr_t channel_cookie;
	intptr_t flow_cookie;
	flow_spec_t *flow_spec;
	npi_status_t rs = NPI_SUCCESS;
	tcam_entry_t tcam_ptr;
	tcam_location_t location = 0;
	uint8_t offset, rdc_grp;
	p_nxge_hw_list_t hw_p;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_add_tcam_entry"));
	handle = nxgep->npi_reg_handle;

	bzero((void *)&tcam_ptr, sizeof (tcam_entry_t));
	flow_spec = (flow_spec_t *)&flow_res->flow_spec;
	flow_cookie = flow_res->flow_cookie;
	channel_cookie = flow_res->channel_cookie;

	switch (flow_spec->flow_type) {
	case FSPEC_TCPIP4:
		nxge_fill_tcam_entry_tcp(nxgep, flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_TCP_IPV4);
		rdc_grp = nxge_get_rdc_group(nxgep, TCAM_CLASS_TCP_IPV4,
			flow_cookie);
		offset = nxge_get_rdc_offset(nxgep, TCAM_CLASS_TCP_IPV4,
			channel_cookie);
		break;

	case FSPEC_UDPIP4:
		nxge_fill_tcam_entry_udp(nxgep, flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_UDP_IPV4);
		rdc_grp = nxge_get_rdc_group(nxgep,
			TCAM_CLASS_UDP_IPV4,
			flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
			TCAM_CLASS_UDP_IPV4,
			channel_cookie);
		break;

	case FSPEC_TCPIP6:
		nxge_fill_tcam_entry_tcp_ipv6(nxgep,
			flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_TCP_IPV6);
		rdc_grp = nxge_get_rdc_group(nxgep, TCAM_CLASS_TCP_IPV6,
			flow_cookie);
		offset = nxge_get_rdc_offset(nxgep, TCAM_CLASS_TCP_IPV6,
			channel_cookie);
		break;

	case FSPEC_UDPIP6:
		nxge_fill_tcam_entry_udp_ipv6(nxgep,
			flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_UDP_IPV6);
		rdc_grp = nxge_get_rdc_group(nxgep,
			TCAM_CLASS_UDP_IPV6,
			channel_cookie);
		offset = nxge_get_rdc_offset(nxgep,
			TCAM_CLASS_UDP_IPV6,
			flow_cookie);
		break;

	case FSPEC_SCTPIP4:
		nxge_fill_tcam_entry_sctp(nxgep, flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_SCTP_IPV4);
		rdc_grp = nxge_get_rdc_group(nxgep,
			TCAM_CLASS_SCTP_IPV4,
			channel_cookie);
		offset = nxge_get_rdc_offset(nxgep,
			TCAM_CLASS_SCTP_IPV4,
			flow_cookie);
		break;

	case FSPEC_SCTPIP6:
		nxge_fill_tcam_entry_sctp_ipv6(nxgep,
			flow_spec, &tcam_ptr);
		location = nxge_get_tcam_location(nxgep,
			TCAM_CLASS_SCTP_IPV4);
		rdc_grp = nxge_get_rdc_group(nxgep,
			TCAM_CLASS_SCTP_IPV6,
			channel_cookie);
		offset = nxge_get_rdc_offset(nxgep,
			TCAM_CLASS_SCTP_IPV6,
			flow_cookie);
		break;

	default:
		return (NXGE_OK);
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" nxge_add_tcam_entry write"
		" for location %d offset %d", location, offset));

	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_add_tcam_entry: common hardware not set",
			nxgep->niu_type));
		return (NXGE_ERROR);
	}

	MUTEX_ENTER(&hw_p->nxge_tcam_lock);
	rs = npi_fflp_tcam_entry_write(handle, location, &tcam_ptr);

	if (rs & NPI_FFLP_ERROR) {
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_add_tcam_entry write"
			" failed for location %d", location));
		return (NXGE_ERROR | rs);
	}

	tcam_ptr.match_action.value = 0;
	tcam_ptr.match_action.bits.ldw.rdctbl = rdc_grp;
	tcam_ptr.match_action.bits.ldw.offset = offset;
	tcam_ptr.match_action.bits.ldw.tres =
		TRES_TERM_OVRD_L2RDC;
	if (channel_cookie == -1)
		tcam_ptr.match_action.bits.ldw.disc = 1;
	rs = npi_fflp_tcam_asc_ram_entry_write(handle,
		location, tcam_ptr.match_action.value);
	if (rs & NPI_FFLP_ERROR) {
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_add_tcam_entry write"
			" failed for ASC RAM location %d", location));
		return (NXGE_ERROR | rs);
	}
	bcopy((void *) &tcam_ptr,
		(void *) &nxgep->classifier.tcam_entries[location].tce,
		sizeof (tcam_entry_t));

	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_add_tcam_entry"));
	return (NXGE_OK);
}

static nxge_status_t
nxge_tcam_handle_ip_fragment(p_nxge_t nxgep)
{
	tcam_entry_t tcam_ptr;
	tcam_location_t location;
	uint8_t class;
	uint32_t class_config;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	p_nxge_hw_list_t hw_p;
	nxge_status_t status = NXGE_OK;

	handle = nxgep->npi_reg_handle;
	class = 0;
	bzero((void *)&tcam_ptr, sizeof (tcam_entry_t));
	tcam_ptr.ip4_noport_key = 1;
	tcam_ptr.ip4_noport_mask = 1;
	location = nxgep->function_num;
	nxgep->classifier.fragment_bug_location = location;

	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_tcam_handle_ip_fragment:"
			" common hardware not set",
			nxgep->niu_type));
		return (NXGE_ERROR);
	}
	MUTEX_ENTER(&hw_p->nxge_tcam_lock);
	rs = npi_fflp_tcam_entry_write(handle,
		location, &tcam_ptr);

	if (rs & NPI_FFLP_ERROR) {
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_tcam_handle_ip_fragment "
			" tcam_entry write"
			" failed for location %d", location));
		return (NXGE_ERROR);
	}
	tcam_ptr.match_action.bits.ldw.rdctbl = nxgep->class_config.mac_rdcgrp;
	tcam_ptr.match_action.bits.ldw.offset = 0;	/* use the default */
	tcam_ptr.match_action.bits.ldw.tres =
		TRES_TERM_USE_OFFSET;
	rs = npi_fflp_tcam_asc_ram_entry_write(handle,
		location, tcam_ptr.match_action.value);

	if (rs & NPI_FFLP_ERROR) {
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
		NXGE_DEBUG_MSG((nxgep,
			FFLP_CTL,
			" nxge_tcam_handle_ip_fragment "
			" tcam_entry write"
			" failed for ASC RAM location %d", location));
		return (NXGE_ERROR);
	}
	bcopy((void *) &tcam_ptr,
		(void *) &nxgep->classifier.tcam_entries[location].tce,
		sizeof (tcam_entry_t));
	for (class = TCAM_CLASS_TCP_IPV4;
		class <= TCAM_CLASS_SCTP_IPV6; class++) {
		class_config = nxgep->class_config.class_cfg[class];
		class_config |= NXGE_CLASS_TCAM_LOOKUP;
		status = nxge_fflp_ip_class_config(nxgep, class, class_config);

		if (status & NPI_FFLP_ERROR) {
			MUTEX_EXIT(&hw_p->nxge_tcam_lock);
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_tcam_handle_ip_fragment "
				"nxge_fflp_ip_class_config failed "
				" class %d config %x ", class, class_config));
			return (NXGE_ERROR);
		}
	}

	rs = npi_fflp_cfg_tcam_enable(handle);
	if (rs & NPI_FFLP_ERROR) {
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_tcam_handle_ip_fragment "
			" nxge_fflp_config_tcam_enable failed"));
		return (NXGE_ERROR);
	}
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	return (NXGE_OK);
}

/* ARGSUSED */
static int
nxge_flow_need_hash_lookup(p_nxge_t nxgep, flow_resource_t *flow_res)
{
	return (0);
}

nxge_status_t
nxge_add_flow(p_nxge_t nxgep, flow_resource_t *flow_res)
{

	int insert_hash = 0;
	nxge_status_t status = NXGE_OK;

	if (NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
		/* determine whether to do TCAM or Hash flow */
		insert_hash = nxge_flow_need_hash_lookup(nxgep, flow_res);
	}
	if (insert_hash) {
		status = nxge_add_fcram_entry(nxgep, flow_res);
	} else {
		status = nxge_add_tcam_entry(nxgep, flow_res);
	}
	return (status);
}

void
nxge_put_tcam(p_nxge_t nxgep, p_mblk_t mp)
{
	flow_resource_t *fs;

	fs = (flow_resource_t *)mp->b_rptr;
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"nxge_put_tcam addr fs $%p  type %x offset %x",
		fs, fs->flow_spec.flow_type, fs->channel_cookie));
	(void) nxge_add_tcam_entry(nxgep, fs);
}

nxge_status_t
nxge_fflp_config_tcam_enable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_config_tcam_enable"));
	rs = npi_fflp_cfg_tcam_enable(handle);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_config_tcam_enable failed"));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " <== nxge_fflp_config_tcam_enable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_tcam_disable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" ==> nxge_fflp_config_tcam_disable"));
	rs = npi_fflp_cfg_tcam_disable(handle);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				" nxge_fflp_config_tcam_disable failed"));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_fflp_config_tcam_disable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_hash_lookup_enable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;
	uint8_t partition;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" ==> nxge_fflp_config_hash_lookup_enable"));
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	for (partition = p_cfgp->start_rdc_grpid;
		partition < p_cfgp->max_rdc_grpids; partition++) {
		rs = npi_fflp_cfg_fcram_partition_enable(handle, partition);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				" nxge_fflp_config_hash_lookup_enable"
				"failed FCRAM partition"
				" enable for partition %d ", partition));
			return (NXGE_ERROR | rs);
		}
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_fflp_config_hash_lookup_enable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_hash_lookup_disable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;
	uint8_t partition;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" ==> nxge_fflp_config_hash_lookup_disable"));
	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	for (partition = p_cfgp->start_rdc_grpid;
		partition < p_cfgp->max_rdc_grpids; partition++) {
		rs = npi_fflp_cfg_fcram_partition_disable(handle,
			partition);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				" nxge_fflp_config_hash_lookup_disable"
				" failed FCRAM partition"
				" disable for partition %d ", partition));
			return (NXGE_ERROR | rs);
		}
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_fflp_config_hash_lookup_disable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_llc_snap_enable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" ==> nxge_fflp_config_llc_snap_enable"));
	rs = npi_fflp_cfg_llcsnap_enable(handle);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_config_llc_snap_enable failed"));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_fflp_config_llc_snap_enable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_llc_snap_disable(p_nxge_t nxgep)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" ==> nxge_fflp_config_llc_snap_disable"));
	rs = npi_fflp_cfg_llcsnap_disable(handle);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_config_llc_snap_disable failed"));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" <== nxge_fflp_config_llc_snap_disable"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_ip_usr_class_config(p_nxge_t nxgep, tcam_class_t class,
	uint32_t config)
{
	npi_status_t rs = NPI_SUCCESS;
	npi_handle_t handle = nxgep->npi_reg_handle;
	uint8_t tos, tos_mask, proto, ver = 0;
	uint8_t class_enable = 0;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_ip_usr_class_config"));

	tos = (config & NXGE_CLASS_CFG_IP_TOS_MASK) >>
		NXGE_CLASS_CFG_IP_TOS_SHIFT;
	tos_mask = (config & NXGE_CLASS_CFG_IP_TOS_MASK_MASK) >>
		NXGE_CLASS_CFG_IP_TOS_MASK_SHIFT;
	proto = (config & NXGE_CLASS_CFG_IP_PROTO_MASK) >>
		NXGE_CLASS_CFG_IP_PROTO_SHIFT;
	if (config & NXGE_CLASS_CFG_IP_IPV6_MASK)
		ver = 1;
	if (config & NXGE_CLASS_CFG_IP_ENABLE_MASK)
		class_enable = 1;
	rs = npi_fflp_cfg_ip_usr_cls_set(handle, class, tos, tos_mask,
		proto, ver);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_ip_usr_class_config"
			" for class %d failed ", class));
		return (NXGE_ERROR | rs);
	}
	if (class_enable)
		rs = npi_fflp_cfg_ip_usr_cls_enable(handle, class);
	else
		rs = npi_fflp_cfg_ip_usr_cls_disable(handle, class);

	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_ip_usr_class_config"
			" TCAM enable/disable for class %d failed ", class));
		return (NXGE_ERROR | rs);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_ip_usr_class_config"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_ip_class_config(p_nxge_t nxgep, tcam_class_t class, uint32_t config)
{
	uint32_t class_config;
	nxge_status_t t_status = NXGE_OK;
	nxge_status_t f_status = NXGE_OK;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_ip_class_config"));

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	class_config = p_class_cfgp->class_cfg[class];

	if (class_config != config) {
		p_class_cfgp->class_cfg[class] = config;
		class_config = config;
	}

	t_status = nxge_cfg_tcam_ip_class(nxgep, class, class_config);
	f_status = nxge_cfg_ip_cls_flow_key(nxgep, class, class_config);

	if (t_status & NPI_FFLP_ERROR) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			" nxge_fflp_ip_class_config %x"
			" for class %d tcam failed", config, class));
		return (t_status);
	}
	if (f_status & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_ip_class_config %x"
			" for class %d flow key failed", config, class));
		return (f_status);
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_ip_class_config"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_ip_class_config_get(p_nxge_t nxgep, tcam_class_t class,
	uint32_t *config)
{
	uint32_t t_class_config, f_class_config;
	int t_status = NXGE_OK;
	int f_status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, " ==> nxge_fflp_ip_class_config"));

	t_class_config = f_class_config = 0;
	t_status = nxge_cfg_tcam_ip_class_get(nxgep, class, &t_class_config);
	f_status = nxge_cfg_ip_cls_flow_key_get(nxgep, class, &f_class_config);

	if (t_status & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_ip_class_config_get  "
			" for class %d tcam failed", class));
		return (t_status);
	}

	if (f_status & NPI_FFLP_ERROR) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			" nxge_fflp_ip_class_config_get  "
			" for class %d flow key failed", class));
		return (f_status);
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		" nxge_fflp_ip_class_config tcam %x flow %x",
		t_class_config, f_class_config));

	*config = t_class_config | f_class_config;
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_ip_class_config_get"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_ip_class_config_all(p_nxge_t nxgep)
{
	uint32_t class_config;
	tcam_class_t class;

#ifdef	NXGE_DEBUG
	int status = NXGE_OK;
#endif

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_ip_class_config"));
	for (class = TCAM_CLASS_TCP_IPV4;
		class <= TCAM_CLASS_SCTP_IPV6; class++) {
		class_config = nxgep->class_config.class_cfg[class];
#ifndef	NXGE_DEBUG
		(void) nxge_fflp_ip_class_config(nxgep, class, class_config);
#else
		status = nxge_fflp_ip_class_config(nxgep, class, class_config);
		if (status & NPI_FFLP_ERROR) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_fflp_ip_class_config failed "
				" class %d config %x ",
				class, class_config));
		}
#endif
	}
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_ip_class_config"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_config_vlan_table(p_nxge_t nxgep, uint16_t vlan_id)
{
	uint8_t port, rdc_grp;
	npi_handle_t handle;
	npi_status_t rs = NPI_SUCCESS;
	uint8_t priority = 1;
	p_nxge_mv_cfg_t vlan_table;
	p_nxge_class_pt_cfg_t p_class_cfgp;
	p_nxge_hw_list_t hw_p;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_config_vlan_table"));
	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	handle = nxgep->npi_reg_handle;
	vlan_table = p_class_cfgp->vlan_tbl;
	port = nxgep->function_num;

	if (vlan_table[vlan_id].flag == 0) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_config_vlan_table"
			" vlan id is not configured %d", vlan_id));
		return (NXGE_ERROR);
	}

	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			" nxge_fflp_config_vlan_table:"
			" common hardware not set", nxgep->niu_type));
		return (NXGE_ERROR);
	}
	MUTEX_ENTER(&hw_p->nxge_vlan_lock);
	rdc_grp = vlan_table[vlan_id].rdctbl;
	rs = npi_fflp_cfg_enet_vlan_table_assoc(handle,
		port, vlan_id,
		rdc_grp, priority);

	MUTEX_EXIT(&hw_p->nxge_vlan_lock);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_fflp_config_vlan_table failed "
			" Port %d vlan_id %d rdc_grp %d",
			port, vlan_id, rdc_grp));
		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_fflp_config_vlan_table"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_update_hw(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;
	p_nxge_param_t pa;
	uint64_t cfgd_vlans;
	uint64_t *val_ptr;
	int i;
	int num_macs;
	uint8_t alt_mac;
	nxge_param_map_t *p_map;
	p_nxge_mv_cfg_t vlan_table;
	p_nxge_class_pt_cfg_t p_class_cfgp;
	p_nxge_dma_pt_cfg_t p_all_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_fflp_update_hw"));

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	p_all_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_all_cfgp->hw_config;

	status = nxge_fflp_set_hash1(nxgep, p_class_cfgp->init_h1);
	if (status != NXGE_OK) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			"nxge_fflp_set_hash1 Failed"));
		return (NXGE_ERROR);
	}

	status = nxge_fflp_set_hash2(nxgep, p_class_cfgp->init_h2);
	if (status != NXGE_OK) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			"nxge_fflp_set_hash2 Failed"));
		return (NXGE_ERROR);
	}
	vlan_table = p_class_cfgp->vlan_tbl;

	/* configure vlan tables */
	pa = (p_nxge_param_t)&nxgep->param_arr[param_vlan_2rdc_grp];
#if defined(__i386)
	val_ptr = (uint64_t *)(uint32_t)pa->value;
#else
	val_ptr = (uint64_t *)pa->value;
#endif
	cfgd_vlans = ((pa->type & NXGE_PARAM_ARRAY_CNT_MASK) >>
		NXGE_PARAM_ARRAY_CNT_SHIFT);

	for (i = 0; i < cfgd_vlans; i++) {
		p_map = (nxge_param_map_t *)&val_ptr[i];
		if (vlan_table[p_map->param_id].flag) {
			status = nxge_fflp_config_vlan_table(nxgep,
				p_map->param_id);
			if (status != NXGE_OK) {
				NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
					"nxge_fflp_config_vlan_table Failed"));
				return (NXGE_ERROR);
			}
		}
	}

	/* config MAC addresses */
	num_macs = p_cfgp->max_macs;
	pa = (p_nxge_param_t)&nxgep->param_arr[param_mac_2rdc_grp];
#if defined(__i386)
	val_ptr = (uint64_t *)(uint32_t)pa->value;
#else
	val_ptr = (uint64_t *)pa->value;
#endif

	for (alt_mac = 0; alt_mac < num_macs; alt_mac++) {
		if (p_class_cfgp->mac_host_info[alt_mac].flag) {
			status = nxge_logical_mac_assign_rdc_table(nxgep,
				alt_mac);
			if (status != NXGE_OK) {
				NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
					"nxge_logical_mac_assign_rdc_table"
					" Failed"));
				return (NXGE_ERROR);
			}
		}
	}

	/* Config Hash values */
	/* config classess */
	status = nxge_fflp_ip_class_config_all(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_fflp_ip_class_config_all Failed"));
		return (NXGE_ERROR);
	}
	return (NXGE_OK);
}

nxge_status_t
nxge_classify_init_hw(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_classify_init_hw"));

	if (nxgep->classifier.state & NXGE_FFLP_HW_INIT) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
			"nxge_classify_init_hw already init"));
		return (NXGE_OK);
	}

	/* Now do a real configuration */
	status = nxge_fflp_update_hw(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_fflp_update_hw failed"));
		return (NXGE_ERROR);
	}

	/* Init RDC tables? ? who should do that? rxdma or fflp ? */
	/* attach rdc table to the MAC port. */
	status = nxge_main_mac_assign_rdc_table(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				"nxge_main_mac_assign_rdc_table failed"));
		return (NXGE_ERROR);
	}

	status = nxge_alt_mcast_mac_assign_rdc_table(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_multicast_mac_assign_rdc_table failed"));
		return (NXGE_ERROR);
	}

	status = nxge_tcam_handle_ip_fragment(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_tcam_handle_ip_fragment failed"));
		return (NXGE_ERROR);
	}

	nxgep->classifier.state |= NXGE_FFLP_HW_INIT;
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_classify_init_hw"));
	return (NXGE_OK);
}

nxge_status_t
nxge_fflp_handle_sys_errors(p_nxge_t nxgep)
{
	npi_handle_t handle;
	p_nxge_fflp_stats_t statsp;
	uint8_t portn, rdc_grp;
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;
	vlan_par_err_t vlan_err;
	tcam_err_t tcam_err;
	hash_lookup_err_log1_t fcram1_err;
	hash_lookup_err_log2_t fcram2_err;
	hash_tbl_data_log_t fcram_err;

	handle = nxgep->npi_handle;
	statsp = (p_nxge_fflp_stats_t)&nxgep->statsp->fflp_stats;
	portn = nxgep->mac.portnum;

	/*
	 * need to read the fflp error registers to figure out what the error
	 * is
	 */
	npi_fflp_vlan_error_get(handle, &vlan_err);
	npi_fflp_tcam_error_get(handle, &tcam_err);

	if (vlan_err.bits.ldw.m_err || vlan_err.bits.ldw.err) {
		NXGE_ERROR_MSG((nxgep, FFLP_CTL,
			" vlan table parity error on port %d"
			" addr: 0x%x data: 0x%x",
			portn, vlan_err.bits.ldw.addr,
			vlan_err.bits.ldw.data));
		statsp->vlan_parity_err++;

		if (vlan_err.bits.ldw.m_err) {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
				" vlan table multiple errors on port %d",
				portn));
		}
		statsp->errlog.vlan = (uint32_t)vlan_err.value;
		NXGE_FM_REPORT_ERROR(nxgep, NULL, NULL,
			NXGE_FM_EREPORT_FFLP_VLAN_PAR_ERR);
		npi_fflp_vlan_error_clear(handle);
	}

	if (tcam_err.bits.ldw.err) {
		if (tcam_err.bits.ldw.p_ecc != 0) {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
				" TCAM ECC error on port %d"
				" TCAM entry: 0x%x syndrome: 0x%x",
				portn, tcam_err.bits.ldw.addr,
				tcam_err.bits.ldw.syndrome));
			statsp->tcam_ecc_err++;
		} else {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
				" TCAM Parity error on port %d"
				" addr: 0x%x parity value: 0x%x",
				portn, tcam_err.bits.ldw.addr,
				tcam_err.bits.ldw.syndrome));
			statsp->tcam_parity_err++;
		}

		if (tcam_err.bits.ldw.mult) {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
				" TCAM Multiple errors on port %d", portn));
		} else {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
					" TCAM PIO error on port %d",
					portn));
		}

		statsp->errlog.tcam = (uint32_t)tcam_err.value;
		NXGE_FM_REPORT_ERROR(nxgep, NULL, NULL,
			NXGE_FM_EREPORT_FFLP_TCAM_ERR);
		npi_fflp_tcam_error_clear(handle);
	}

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	for (rdc_grp = p_cfgp->start_rdc_grpid;
		rdc_grp < p_cfgp->max_rdc_grpids; rdc_grp++) {
		npi_fflp_fcram_error_get(handle, &fcram_err, rdc_grp);
		if (fcram_err.bits.ldw.pio_err) {
			NXGE_ERROR_MSG((nxgep, FFLP_CTL,
				" FCRAM PIO ECC error on port %d"
				" rdc group: %d Hash Table addr: 0x%x"
				" syndrome: 0x%x",
				portn, rdc_grp,
				fcram_err.bits.ldw.fcram_addr,
				fcram_err.bits.ldw.syndrome));
			statsp->hash_pio_err[rdc_grp]++;
			statsp->errlog.hash_pio[rdc_grp] =
				(uint32_t)fcram_err.value;
			NXGE_FM_REPORT_ERROR(nxgep, NULL, NULL,
				NXGE_FM_EREPORT_FFLP_HASHT_DATA_ERR);
			npi_fflp_fcram_error_clear(handle, rdc_grp);
		}
	}

	npi_fflp_fcram_error_log1_get(handle, &fcram1_err);
	if (fcram1_err.bits.ldw.ecc_err) {
		char *multi_str = "";
		char *multi_bit_str = "";

		npi_fflp_fcram_error_log2_get(handle, &fcram2_err);
		if (fcram1_err.bits.ldw.mult_lk) {
			multi_str = "multiple";
		}
		if (fcram1_err.bits.ldw.mult_bit) {
			multi_bit_str = "multiple bits";
		}
		NXGE_ERROR_MSG((nxgep, FFLP_CTL,
			" FCRAM %s lookup %s ECC error on port %d"
			" H1: 0x%x Subarea: 0x%x Syndrome: 0x%x",
			multi_str, multi_bit_str, portn,
			fcram2_err.bits.ldw.h1,
			fcram2_err.bits.ldw.subarea,
			fcram2_err.bits.ldw.syndrome));
		NXGE_FM_REPORT_ERROR(nxgep, NULL, NULL,
			NXGE_FM_EREPORT_FFLP_HASHT_LOOKUP_ERR);
	}
	statsp->errlog.hash_lookup1 = (uint32_t)fcram1_err.value;
	statsp->errlog.hash_lookup2 = (uint32_t)fcram2_err.value;
	return (NXGE_OK);
}
