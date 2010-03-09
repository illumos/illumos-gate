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
static uint8_t nxge_get_rdc_offset(p_nxge_t, uint8_t, uint64_t);
static uint8_t nxge_get_rdc_group(p_nxge_t, uint8_t, uint64_t);
static uint16_t nxge_tcam_get_index(p_nxge_t, uint16_t);
static uint32_t nxge_tcam_cls_to_flow(uint32_t);
static uint8_t nxge_iptun_pkt_type_to_pid(uint8_t);
static npi_status_t nxge_set_iptun_usr_cls_reg(p_nxge_t, uint64_t,
					iptun_cfg_t *);
static boolean_t nxge_is_iptun_cls_present(p_nxge_t, uint8_t, int *);

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
int nxge_get_valid_tcam_cnt(p_nxge_t);
void nxge_get_tcam_entry_all(p_nxge_t, rx_class_cfg_t *);
void nxge_get_tcam_entry(p_nxge_t, flow_resource_t *);
void nxge_del_tcam_entry(p_nxge_t, uint32_t);
void nxge_add_iptun_class(p_nxge_t, iptun_cfg_t *, uint8_t *);
void nxge_cfg_iptun_hash(p_nxge_t, iptun_cfg_t *, uint8_t);
void nxge_del_iptun_class(p_nxge_t, uint8_t);
void nxge_get_iptun_class(p_nxge_t, iptun_cfg_t *, uint8_t);
void nxge_set_ip_cls_sym(p_nxge_t, uint8_t, uint8_t);
void nxge_get_ip_cls_sym(p_nxge_t, uint8_t, uint8_t *);


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
		    location, fc.value[0]);
		if (rs != NPI_SUCCESS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "failed write at location %x ", location));
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
	int i;

	handle = nxgep->npi_reg_handle;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = nxgep->class_config.mac_rdcgrp;
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
		    nxgep->function_num, XMAC_UNIQUE_HOST_INFO_ENTRY, &mac_rdc);
		break;
	case 2:
	case 3:
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
		    nxgep->function_num, BMAC_UNIQUE_HOST_INFO_ENTRY, &mac_rdc);
		for (i = 1; i <= BMAC_MAX_ALT_ADDR_ENTRY; i++)
			rs |= npi_mac_hostinfo_entry(handle, OP_SET,
			    nxgep->function_num, i, &mac_rdc);
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

	handle = nxgep->npi_reg_handle;
	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = nxgep->class_config.mcast_rdcgrp;
	mac_rdc.bits.w0.mac_pref = 1;
	switch (nxgep->function_num) {
	case 0:
	case 1:
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
		    nxgep->function_num, XMAC_MULTI_HOST_INFO_ENTRY, &mac_rdc);
		break;
	case 2:
	case 3:
		rs = npi_mac_hostinfo_entry(handle, OP_SET,
		    nxgep->function_num, BMAC_MULTI_HOST_INFO_ENTRY, &mac_rdc);
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
		    " opt %x for class %d failed ", class_config, l3_class));
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
		    " opt %x for class %d failed ", class_config, l3_class));
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
		    " opt %x for class %d failed ", class_config, class));
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
		    " opt %x for class %d failed ", class_config, class));
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
	nxge_classify_t *classify_ptr;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_classify_init_sw"));
	classify_ptr = &nxgep->classifier;

	if (classify_ptr->state & NXGE_FFLP_SW_INIT) {
		NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
		    "nxge_classify_init_sw already init"));
		return (NXGE_OK);
	}

	classify_ptr->tcam_size = nxgep->nxge_hw_p->tcam_size / nxgep->nports;
	classify_ptr->tcam_entries = (tcam_flow_spec_t *)nxgep->nxge_hw_p->tcam;
	classify_ptr->tcam_top = nxgep->function_num;

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
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_classify_exit_sw"));
	nxgep->classifier.state = NULL;
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_classify_exit_sw"));
	return (NXGE_OK);
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
nxge_get_rdc_group(p_nxge_t nxgep, uint8_t class, uint64_t cookie)
{
	int use_port_rdc_grp = 0;
	uint8_t rdc_grp = 0;
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;
	p_nxge_rdc_grp_t rdc_grp_p;

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	rdc_grp_p = &p_dma_cfgp->rdc_grps[use_port_rdc_grp];
	rdc_grp = p_cfgp->def_mac_rxdma_grpid;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_get_rdc_group: grp 0x%x real_grp %x grpp $%p\n",
	    cookie, rdc_grp, rdc_grp_p));
	return (rdc_grp);
}

/* ARGSUSED */
static uint8_t
nxge_get_rdc_offset(p_nxge_t nxgep, uint8_t class, uint64_t cookie)
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
	tcam_ptr->ip4_tos_key = fspec_key->tos;
	tcam_ptr->ip4_tos_mask = fspec_mask->tos;
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
	tcam_ptr->ip6_tos_key = fspec_key->tos;
	tcam_ptr->ip6_tos_mask = fspec_mask->tos;
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
	tcam_ptr->ip4_tos_key = fspec_key->tos;
	tcam_ptr->ip4_tos_mask = fspec_mask->tos;
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
	tcam_ptr->ip4_tos_key = fspec_key->tos;
	tcam_ptr->ip4_tos_mask = fspec_mask->tos;
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
	tcam_ptr->ip6_tos_key = fspec_key->tos;
	tcam_ptr->ip6_tos_mask = fspec_mask->tos;
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
	tcam_ptr->ip6_tos_key = fspec_key->tos;
	tcam_ptr->ip6_tos_mask = fspec_mask->tos;
}

/* ARGSUSED */
static void
nxge_fill_tcam_entry_ah_esp(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	ahip4_spec_t *fspec_key;
	ahip4_spec_t *fspec_mask;

	fspec_key = (ahip4_spec_t *)&flow_spec->uh.ahip4spec;
	fspec_mask = (ahip4_spec_t *)&flow_spec->um.ahip4spec;

	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_key, fspec_key->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_mask, fspec_mask->ip4dst);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_key, fspec_key->ip4src);
	TCAM_IPV4_ADDR(tcam_ptr->ip4_src_mask, fspec_mask->ip4src);

	tcam_ptr->ip4_port_key = fspec_key->spi;
	tcam_ptr->ip4_port_mask = fspec_mask->spi;

	TCAM_IP_CLASS(tcam_ptr->ip4_class_key,
	    tcam_ptr->ip4_class_mask,
	    TCAM_CLASS_AH_ESP_IPV4);

	if (flow_spec->flow_type == FSPEC_AHIP4) {
		TCAM_IP_PROTO(tcam_ptr->ip4_proto_key,
		    tcam_ptr->ip4_proto_mask, IPPROTO_AH);
	} else {
		TCAM_IP_PROTO(tcam_ptr->ip4_proto_key,
		    tcam_ptr->ip4_proto_mask, IPPROTO_ESP);
	}
	tcam_ptr->ip4_tos_key = fspec_key->tos;
	tcam_ptr->ip4_tos_mask = fspec_mask->tos;
}

static void
nxge_fill_tcam_entry_ah_esp_ipv6(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr)
{
	ahip6_spec_t *fspec_key;
	ahip6_spec_t *fspec_mask;
	p_nxge_class_pt_cfg_t p_class_cfgp;

	fspec_key = (ahip6_spec_t *)&flow_spec->uh.ahip6spec;
	fspec_mask = (ahip6_spec_t *)&flow_spec->um.ahip6spec;

	p_class_cfgp = (p_nxge_class_pt_cfg_t)&nxgep->class_config;
	if (p_class_cfgp->class_cfg[TCAM_CLASS_AH_ESP_IPV6] &
	    NXGE_CLASS_TCAM_USE_SRC_ADDR) {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6src);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6src);
	} else {
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_key, fspec_key->ip6dst);
		TCAM_IPV6_ADDR(tcam_ptr->ip6_ip_addr_mask, fspec_mask->ip6dst);
	}

	TCAM_IP_CLASS(tcam_ptr->ip6_class_key,
	    tcam_ptr->ip6_class_mask, TCAM_CLASS_AH_ESP_IPV6);

	if (flow_spec->flow_type == FSPEC_AHIP6) {
		TCAM_IP_PROTO(tcam_ptr->ip6_nxt_hdr_key,
		    tcam_ptr->ip6_nxt_hdr_mask, IPPROTO_AH);
	} else {
		TCAM_IP_PROTO(tcam_ptr->ip6_nxt_hdr_key,
		    tcam_ptr->ip6_nxt_hdr_mask, IPPROTO_ESP);
	}
	tcam_ptr->ip6_port_key = fspec_key->spi;
	tcam_ptr->ip6_port_mask = fspec_mask->spi;
	tcam_ptr->ip6_tos_key = fspec_key->tos;
	tcam_ptr->ip6_tos_mask = fspec_mask->tos;
}

/* ARGSUSED */
static void
nxge_fill_tcam_entry_ip_usr(p_nxge_t nxgep, flow_spec_t *flow_spec,
	tcam_entry_t *tcam_ptr, tcam_class_t class)
{
	ip_user_spec_t *fspec_key;
	ip_user_spec_t *fspec_mask;

	fspec_key = (ip_user_spec_t *)&flow_spec->uh.ip_usr_spec;
	fspec_mask = (ip_user_spec_t *)&flow_spec->um.ip_usr_spec;

	if (fspec_key->ip_ver == FSPEC_IP4) {
		TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_key, fspec_key->ip4dst);
		TCAM_IPV4_ADDR(tcam_ptr->ip4_dest_mask, fspec_mask->ip4dst);
		TCAM_IPV4_ADDR(tcam_ptr->ip4_src_key, fspec_key->ip4src);
		TCAM_IPV4_ADDR(tcam_ptr->ip4_src_mask, fspec_mask->ip4src);

		tcam_ptr->ip4_port_key = fspec_key->l4_4_bytes;
		tcam_ptr->ip4_port_mask = fspec_mask->l4_4_bytes;

		TCAM_IP_CLASS(tcam_ptr->ip4_class_key,
		    tcam_ptr->ip4_class_mask, class);

		tcam_ptr->ip4_proto_key = fspec_key->proto;
		tcam_ptr->ip4_proto_mask = fspec_mask->proto;

		tcam_ptr->ip4_tos_key = fspec_key->tos;
		tcam_ptr->ip4_tos_mask = fspec_mask->tos;
	}
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
	uint64_t channel_cookie;
	uint64_t flow_cookie;
	flow_spec_t *flow_spec;
	npi_status_t rs = NPI_SUCCESS;
	tcam_entry_t tcam_ptr;
	tcam_location_t location;
	uint8_t offset, rdc_grp;
	p_nxge_hw_list_t hw_p;
	uint64_t class;

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "==> nxge_add_tcam_entry"));
	handle = nxgep->npi_reg_handle;

	bzero((void *)&tcam_ptr, sizeof (tcam_entry_t));
	flow_spec = (flow_spec_t *)&flow_res->flow_spec;
	flow_cookie = flow_res->flow_cookie;
	channel_cookie = flow_res->channel_cookie;
	location = (tcam_location_t)nxge_tcam_get_index(nxgep,
	    (uint16_t)flow_res->location);

	if ((hw_p = nxgep->nxge_hw_p) == NULL) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    " nxge_add_tcam_entry: common hardware not set",
		    nxgep->niu_type));
		return (NXGE_ERROR);
	}

	if (flow_spec->flow_type == FSPEC_IP_USR) {
		int i;
		int add_usr_cls = 0;
		int ipv6 = 0;
		ip_user_spec_t *uspec = &flow_spec->uh.ip_usr_spec;
		ip_user_spec_t *umask = &flow_spec->um.ip_usr_spec;
		nxge_usr_l3_cls_t *l3_ucls_p;

		MUTEX_ENTER(&hw_p->nxge_tcam_lock);

		for (i = 0; i < NXGE_L3_PROG_CLS; i++) {
			l3_ucls_p = &hw_p->tcam_l3_prog_cls[i];
			if (l3_ucls_p->valid && l3_ucls_p->tcam_ref_cnt) {
				if (uspec->proto == l3_ucls_p->pid) {
					class = l3_ucls_p->cls;
					l3_ucls_p->tcam_ref_cnt++;
					add_usr_cls = 1;
					break;
				}
			} else if (l3_ucls_p->valid == 0) {
				/* Program new user IP class */
				switch (i) {
				case 0:
					class = TCAM_CLASS_IP_USER_4;
					break;
				case 1:
					class = TCAM_CLASS_IP_USER_5;
					break;
				case 2:
					class = TCAM_CLASS_IP_USER_6;
					break;
				case 3:
					class = TCAM_CLASS_IP_USER_7;
					break;
				default:
					break;
				}
				if (uspec->ip_ver == FSPEC_IP6)
					ipv6 = 1;
				rs = npi_fflp_cfg_ip_usr_cls_set(handle,
				    (tcam_class_t)class, uspec->tos,
				    umask->tos, uspec->proto, ipv6);
				if (rs != NPI_SUCCESS)
					goto fail;

				rs = npi_fflp_cfg_ip_usr_cls_enable(handle,
				    (tcam_class_t)class);
				if (rs != NPI_SUCCESS)
					goto fail;

				l3_ucls_p->cls = class;
				l3_ucls_p->pid = uspec->proto;
				l3_ucls_p->tcam_ref_cnt++;
				l3_ucls_p->valid = 1;
				add_usr_cls = 1;
				break;
			} else if (l3_ucls_p->tcam_ref_cnt == 0 &&
			    uspec->proto == l3_ucls_p->pid) {
				/*
				 * The class has already been programmed,
				 * probably for flow hash
				 */
				class = l3_ucls_p->cls;
				if (uspec->ip_ver == FSPEC_IP6)
					ipv6 = 1;
				rs = npi_fflp_cfg_ip_usr_cls_set(handle,
				    (tcam_class_t)class, uspec->tos,
				    umask->tos, uspec->proto, ipv6);
				if (rs != NPI_SUCCESS)
					goto fail;

				rs = npi_fflp_cfg_ip_usr_cls_enable(handle,
				    (tcam_class_t)class);
				if (rs != NPI_SUCCESS)
					goto fail;

				l3_ucls_p->pid = uspec->proto;
				l3_ucls_p->tcam_ref_cnt++;
				add_usr_cls = 1;
				break;
			}
		}
		if (!add_usr_cls) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_add_tcam_entry: Could not find/insert class"
			    "for pid %d", uspec->proto));
			goto fail;
		}
		MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	}

	switch (flow_spec->flow_type) {
	case FSPEC_TCPIP4:
		nxge_fill_tcam_entry_tcp(nxgep, flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep, TCAM_CLASS_TCP_IPV4,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep, TCAM_CLASS_TCP_IPV4,
		    channel_cookie);
		break;

	case FSPEC_UDPIP4:
		nxge_fill_tcam_entry_udp(nxgep, flow_spec, &tcam_ptr);
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
		rdc_grp = nxge_get_rdc_group(nxgep, TCAM_CLASS_TCP_IPV6,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep, TCAM_CLASS_TCP_IPV6,
		    channel_cookie);
		break;

	case FSPEC_UDPIP6:
		nxge_fill_tcam_entry_udp_ipv6(nxgep,
		    flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    TCAM_CLASS_UDP_IPV6,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    TCAM_CLASS_UDP_IPV6,
		    channel_cookie);
		break;

	case FSPEC_SCTPIP4:
		nxge_fill_tcam_entry_sctp(nxgep, flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    TCAM_CLASS_SCTP_IPV4,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    TCAM_CLASS_SCTP_IPV4,
		    channel_cookie);
		break;

	case FSPEC_SCTPIP6:
		nxge_fill_tcam_entry_sctp_ipv6(nxgep,
		    flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    TCAM_CLASS_SCTP_IPV6,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    TCAM_CLASS_SCTP_IPV6,
		    channel_cookie);
		break;

	case FSPEC_AHIP4:
	case FSPEC_ESPIP4:
		nxge_fill_tcam_entry_ah_esp(nxgep, flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    TCAM_CLASS_AH_ESP_IPV4,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    TCAM_CLASS_AH_ESP_IPV4,
		    channel_cookie);
		break;

	case FSPEC_AHIP6:
	case FSPEC_ESPIP6:
		nxge_fill_tcam_entry_ah_esp_ipv6(nxgep,
		    flow_spec, &tcam_ptr);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    TCAM_CLASS_AH_ESP_IPV6,
		    flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    TCAM_CLASS_AH_ESP_IPV6,
		    channel_cookie);
		break;

	case FSPEC_IP_USR:
		nxge_fill_tcam_entry_ip_usr(nxgep, flow_spec, &tcam_ptr,
		    (tcam_class_t)class);
		rdc_grp = nxge_get_rdc_group(nxgep,
		    (tcam_class_t)class, flow_cookie);
		offset = nxge_get_rdc_offset(nxgep,
		    (tcam_class_t)class, channel_cookie);
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_add_tcam_entry: Unknown flow spec 0x%x",
		    flow_spec->flow_type));
		return (NXGE_ERROR);
	}

	NXGE_DEBUG_MSG((nxgep, FFLP_CTL,
	    " nxge_add_tcam_entry write"
	    " for location %d offset %d", location, offset));

	MUTEX_ENTER(&hw_p->nxge_tcam_lock);
	rs = npi_fflp_tcam_entry_write(handle, location, &tcam_ptr);

	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    " nxge_add_tcam_entry write"
		    " failed for location %d", location));
		goto fail;
	}

	tcam_ptr.match_action.value = 0;
	tcam_ptr.match_action.bits.ldw.rdctbl = rdc_grp;
	tcam_ptr.match_action.bits.ldw.offset = offset;
	tcam_ptr.match_action.bits.ldw.tres =
	    TRES_TERM_OVRD_L2RDC;
	if (channel_cookie == NXGE_PKT_DISCARD)
		tcam_ptr.match_action.bits.ldw.disc = 1;
	rs = npi_fflp_tcam_asc_ram_entry_write(handle,
	    location, tcam_ptr.match_action.value);
	if (rs & NPI_FFLP_ERROR) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    " nxge_add_tcam_entry write"
		    " failed for ASC RAM location %d", location));
		goto fail;
	}
	bcopy((void *) &tcam_ptr,
	    (void *) &nxgep->classifier.tcam_entries[location].tce,
	    sizeof (tcam_entry_t));
	nxgep->classifier.tcam_entry_cnt++;
	nxgep->classifier.tcam_entries[location].valid = 1;

	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_add_tcam_entry"));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_add_tcam_entry FAILED"));
	return (NXGE_ERROR);
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
		    " nxge_tcam_handle_ip_fragment: common hardware not set",
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
	nxgep->classifier.tcam_entry_cnt++;
	nxgep->classifier.tcam_entries[location].valid = 1;
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

	for (partition = 0; partition < NXGE_MAX_RDC_GROUPS; partition++) {
		if (p_cfgp->grpids[partition]) {
			rs = npi_fflp_cfg_fcram_partition_enable(
			    handle, partition);
			if (rs != NPI_SUCCESS) {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    " nxge_fflp_config_hash_lookup_enable"
				    "failed FCRAM partition"
				    " enable for partition %d ", partition));
				return (NXGE_ERROR | rs);
			}
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

	for (partition = 0; partition < NXGE_MAX_RDC_GROUPS; partition++) {
		if (p_cfgp->grpids[partition]) {
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
	/* config classes */
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

	if (nxgep->classifier.fragment_bug == 1) {
		status = nxge_tcam_handle_ip_fragment(nxgep);
		if (status != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_tcam_handle_ip_fragment failed"));
			return (NXGE_ERROR);
		}
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
			    " TCAM PIO error on port %d", portn));
		}

		statsp->errlog.tcam = (uint32_t)tcam_err.value;
		NXGE_FM_REPORT_ERROR(nxgep, NULL, NULL,
		    NXGE_FM_EREPORT_FFLP_TCAM_ERR);
		npi_fflp_tcam_error_clear(handle);
	}

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;

	for (rdc_grp = 0; rdc_grp < NXGE_MAX_RDC_GROUPS; rdc_grp++) {
		if (p_cfgp->grpids[rdc_grp]) {
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
		statsp->hash_lookup_err++;
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

int
nxge_get_valid_tcam_cnt(p_nxge_t nxgep) {
	return ((nxgep->classifier.fragment_bug == 1) ?
		nxgep->classifier.tcam_entry_cnt - 1 :
		nxgep->classifier.tcam_entry_cnt);
}

int
nxge_rxdma_channel_cnt(p_nxge_t nxgep)
{
	p_nxge_dma_pt_cfg_t p_dma_cfgp;
	p_nxge_hw_pt_cfg_t p_cfgp;

	p_dma_cfgp = (p_nxge_dma_pt_cfg_t)&nxgep->pt_config;
	p_cfgp = (p_nxge_hw_pt_cfg_t)&p_dma_cfgp->hw_config;
	return (p_cfgp->max_rdcs);
}

/* ARGSUSED */
int
nxge_rxclass_ioctl(p_nxge_t nxgep, queue_t *wq, mblk_t *mp)
{
	uint32_t cmd;
	rx_class_cfg_t *cfg_info = (rx_class_cfg_t *)mp->b_rptr;

	if (nxgep == NULL) {
		return (-1);
	}
	cmd = cfg_info->cmd;
	switch (cmd) {
	default:
		return (-1);

	case NXGE_RX_CLASS_GCHAN:
		cfg_info->data = nxge_rxdma_channel_cnt(nxgep);
		break;
	case NXGE_RX_CLASS_GRULE_CNT:
		MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_tcam_lock);
		cfg_info->rule_cnt = nxge_get_valid_tcam_cnt(nxgep);
		MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);
		break;
	case NXGE_RX_CLASS_GRULE:
		nxge_get_tcam_entry(nxgep, &cfg_info->fs);
		break;
	case NXGE_RX_CLASS_GRULE_ALL:
		nxge_get_tcam_entry_all(nxgep, cfg_info);
		break;
	case NXGE_RX_CLASS_RULE_DEL:
		nxge_del_tcam_entry(nxgep, cfg_info->fs.location);
		break;
	case NXGE_RX_CLASS_RULE_INS:
		(void) nxge_add_tcam_entry(nxgep, &cfg_info->fs);
		break;
	}
	return (0);
}
/* ARGSUSED */
int
nxge_rxhash_ioctl(p_nxge_t nxgep, queue_t *wq, mblk_t *mp)
{
	uint32_t cmd;
	cfg_cmd_t	*cfg_info = (cfg_cmd_t *)mp->b_rptr;

	if (nxgep == NULL) {
		return (-1);
	}
	cmd = cfg_info->cmd;

	switch (cmd) {
	default:
		return (-1);
	case NXGE_IPTUN_CFG_ADD_CLS:
		nxge_add_iptun_class(nxgep, &cfg_info->iptun_cfg,
		    &cfg_info->class_id);
		break;
	case NXGE_IPTUN_CFG_SET_HASH:
		nxge_cfg_iptun_hash(nxgep, &cfg_info->iptun_cfg,
		    cfg_info->class_id);
		break;
	case NXGE_IPTUN_CFG_DEL_CLS:
		nxge_del_iptun_class(nxgep, cfg_info->class_id);
		break;
	case NXGE_IPTUN_CFG_GET_CLS:
		nxge_get_iptun_class(nxgep, &cfg_info->iptun_cfg,
		    cfg_info->class_id);
		break;
	case NXGE_CLS_CFG_SET_SYM:
		nxge_set_ip_cls_sym(nxgep, cfg_info->class_id, cfg_info->sym);
		break;
	case NXGE_CLS_CFG_GET_SYM:
		nxge_get_ip_cls_sym(nxgep, cfg_info->class_id, &cfg_info->sym);
		break;
	}
	return (0);
}

void
nxge_get_tcam_entry_all(p_nxge_t nxgep, rx_class_cfg_t *cfgp)
{
	nxge_classify_t *clasp = &nxgep->classifier;
	uint16_t	n_entries;
	int		i, j, k;
	tcam_flow_spec_t	*tcam_entryp;

	cfgp->data = clasp->tcam_size;
	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_tcam_lock);
	n_entries = cfgp->rule_cnt;

	for (i = 0, j = 0; j < cfgp->data; j++) {
		k = nxge_tcam_get_index(nxgep, j);
		tcam_entryp = &clasp->tcam_entries[k];
		if (tcam_entryp->valid != 1)
			continue;
		cfgp->rule_locs[i] = j;
		i++;
	};
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);

	if (n_entries != i) {
		/* print warning, this should not happen */
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_get_tcam_entry_all"
		    "n_entries[%d] != i[%d]!!!", n_entries, i));
	}
}


/* Entries for the ports are interleaved in the TCAM */
static uint16_t
nxge_tcam_get_index(p_nxge_t nxgep, uint16_t index)
{
	/* One entry reserved for IP fragment rule */
	if (index >= (nxgep->classifier.tcam_size - 1))
		index = 0;
	if (nxgep->classifier.fragment_bug == 1)
		index++;
	return (nxgep->classifier.tcam_top + (index * nxgep->nports));
}

static uint32_t
nxge_tcam_cls_to_flow(uint32_t class_code) {
	switch (class_code) {
	case TCAM_CLASS_TCP_IPV4:
		return (FSPEC_TCPIP4);
	case TCAM_CLASS_UDP_IPV4:
		return (FSPEC_UDPIP4);
	case TCAM_CLASS_AH_ESP_IPV4:
		return (FSPEC_AHIP4);
	case TCAM_CLASS_SCTP_IPV4:
		return (FSPEC_SCTPIP4);
	case  TCAM_CLASS_TCP_IPV6:
		return (FSPEC_TCPIP6);
	case TCAM_CLASS_UDP_IPV6:
		return (FSPEC_UDPIP6);
	case TCAM_CLASS_AH_ESP_IPV6:
		return (FSPEC_AHIP6);
	case TCAM_CLASS_SCTP_IPV6:
		return (FSPEC_SCTPIP6);
	case TCAM_CLASS_IP_USER_4:
	case TCAM_CLASS_IP_USER_5:
	case TCAM_CLASS_IP_USER_6:
	case TCAM_CLASS_IP_USER_7:
		return (FSPEC_IP_USR);
	default:
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL, "nxge_tcam_cls_to_flow"
		    ": Unknown class code [0x%x]", class_code));
		break;
	}
	return (0);
}

void
nxge_get_tcam_entry(p_nxge_t nxgep, flow_resource_t *fs)
{
	uint16_t 	index;
	tcam_flow_spec_t *tcam_ep;
	tcam_entry_t	*tp;
	flow_spec_t	*fspec;
	tcpip4_spec_t 	*fspec_key;
	tcpip4_spec_t 	*fspec_mask;

	index = nxge_tcam_get_index(nxgep, (uint16_t)fs->location);
	tcam_ep = &nxgep->classifier.tcam_entries[index];
	if (tcam_ep->valid != 1) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_get_tcam_entry: :"
		    "Entry [%d] invalid for index [%d]", fs->location, index));
		return;
	}

	/* Fill the flow spec entry */
	tp = &tcam_ep->tce;
	fspec = &fs->flow_spec;
	fspec->flow_type = nxge_tcam_cls_to_flow(tp->ip4_class_key);

	/* TODO - look at proto field to differentiate between AH and ESP */
	if (fspec->flow_type == FSPEC_AHIP4) {
		if (tp->ip4_proto_key == IPPROTO_ESP)
			fspec->flow_type = FSPEC_ESPIP4;
	}

	switch (tp->ip4_class_key) {
	case TCAM_CLASS_TCP_IPV4:
	case TCAM_CLASS_UDP_IPV4:
	case TCAM_CLASS_AH_ESP_IPV4:
	case TCAM_CLASS_SCTP_IPV4:
		fspec_key = (tcpip4_spec_t *)&fspec->uh.tcpip4spec;
		fspec_mask = (tcpip4_spec_t *)&fspec->um.tcpip4spec;
		FSPEC_IPV4_ADDR(fspec_key->ip4dst, tp->ip4_dest_key);
		FSPEC_IPV4_ADDR(fspec_mask->ip4dst, tp->ip4_dest_mask);
		FSPEC_IPV4_ADDR(fspec_key->ip4src, tp->ip4_src_key);
		FSPEC_IPV4_ADDR(fspec_mask->ip4src, tp->ip4_src_mask);
		fspec_key->tos = tp->ip4_tos_key;
		fspec_mask->tos = tp->ip4_tos_mask;
		break;
	default:
		break;
	}

	switch (tp->ip4_class_key) {
	case TCAM_CLASS_TCP_IPV4:
	case TCAM_CLASS_UDP_IPV4:
	case TCAM_CLASS_SCTP_IPV4:
		FSPEC_IP_PORTS(fspec_key->pdst, fspec_key->psrc,
		    tp->ip4_port_key);
		FSPEC_IP_PORTS(fspec_mask->pdst, fspec_mask->psrc,
		    tp->ip4_port_mask);
		break;
	case TCAM_CLASS_AH_ESP_IPV4:
		fspec->uh.ahip4spec.spi = tp->ip4_port_key;
		fspec->um.ahip4spec.spi = tp->ip4_port_mask;
		break;
	case TCAM_CLASS_IP_USER_4:
	case TCAM_CLASS_IP_USER_5:
	case TCAM_CLASS_IP_USER_6:
	case TCAM_CLASS_IP_USER_7:
		fspec->uh.ip_usr_spec.l4_4_bytes = tp->ip4_port_key;
		fspec->um.ip_usr_spec.l4_4_bytes = tp->ip4_port_mask;
		fspec->uh.ip_usr_spec.ip_ver = FSPEC_IP4;
		fspec->uh.ip_usr_spec.proto = tp->ip4_proto_key;
		fspec->um.ip_usr_spec.proto = tp->ip4_proto_mask;
		break;
	default:
		break;
	}

	if (tp->match_action.bits.ldw.disc == 1) {
		fs->channel_cookie = NXGE_PKT_DISCARD;
	} else {
		fs->channel_cookie = tp->match_action.bits.ldw.offset;
	}
}

void
nxge_del_tcam_entry(p_nxge_t nxgep, uint32_t location)
{
	npi_status_t rs = NPI_SUCCESS;
	uint16_t 	index;
	tcam_flow_spec_t *tcam_ep;
	tcam_entry_t	*tp;
	tcam_class_t	class;

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_tcam_lock);
	index = nxge_tcam_get_index(nxgep, (uint16_t)location);
	tcam_ep = &nxgep->classifier.tcam_entries[index];
	if (tcam_ep->valid != 1) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_del_tcam_entry: :"
		    "Entry [%d] invalid for index [%d]", location, index));
		goto fail;
	}

	/* Fill the flow spec entry */
	tp = &tcam_ep->tce;
	class = tp->ip4_class_key;
	if (class >= TCAM_CLASS_IP_USER_4 && class <= TCAM_CLASS_IP_USER_7) {
		int i;
		nxge_usr_l3_cls_t *l3_ucls_p;
		p_nxge_hw_list_t hw_p = nxgep->nxge_hw_p;

		for (i = 0; i < NXGE_L3_PROG_CLS; i++) {
			l3_ucls_p = &hw_p->tcam_l3_prog_cls[i];
			if (l3_ucls_p->valid) {
				if (l3_ucls_p->cls == class &&
				    l3_ucls_p->tcam_ref_cnt) {
					l3_ucls_p->tcam_ref_cnt--;
					if (l3_ucls_p->tcam_ref_cnt > 0)
						continue;
					/* disable class */
					rs = npi_fflp_cfg_ip_usr_cls_disable(
					    nxgep->npi_reg_handle,
					    (tcam_class_t)class);
					if (rs != NPI_SUCCESS)
						goto fail;
					l3_ucls_p->cls = 0;
					l3_ucls_p->pid = 0;
					l3_ucls_p->valid = 0;
					break;
				}
			}
		}
		if (i == NXGE_L3_PROG_CLS) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_del_tcam_entry: Usr class "
			    "0x%llx not found", (unsigned long long) class));
			goto fail;
		}
	}

	rs = npi_fflp_tcam_entry_invalidate(nxgep->npi_reg_handle, index);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_del_tcam_entry: TCAM invalidate failed "
		    "at loc %d ", location));
		goto fail;
	}

	nxgep->classifier.tcam_entries[index].valid = 0;
	nxgep->classifier.tcam_entry_cnt--;

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);
	NXGE_DEBUG_MSG((nxgep, FFLP_CTL, "<== nxge_del_tcam_entry"));
	return;
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "<== nxge_del_tcam_entry FAILED"));
}

static uint8_t
nxge_iptun_pkt_type_to_pid(uint8_t pkt_type)
{
	uint8_t pid = 0;

	switch (pkt_type) {
	case IPTUN_PKT_IPV4:
		pid = 4;
		break;
	case IPTUN_PKT_IPV6:
		pid = 41;
		break;
	case IPTUN_PKT_GRE:
		pid = 47;
		break;
	case IPTUN_PKT_GTP:
		pid = 17;
		break;
	default:
		NXGE_ERROR_MSG((NULL, NXGE_ERR_CTL,
		    "nxge_iptun_pkt_type_to_pid: Unknown pkt type 0x%x",
		    pkt_type));
		break;
	}

	return (pid);
}

static npi_status_t
nxge_set_iptun_usr_cls_reg(p_nxge_t nxgep, uint64_t class,
		iptun_cfg_t *iptunp)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	switch (iptunp->in_pkt_type) {
	case IPTUN_PKT_IPV4:
	case IPTUN_PKT_IPV6:
		rs = npi_fflp_cfg_ip_usr_cls_set_iptun(handle,
		    (tcam_class_t)class, 0, 0, 0, 0);
		break;
	case IPTUN_PKT_GRE:
		rs = npi_fflp_cfg_ip_usr_cls_set_iptun(handle,
		    (tcam_class_t)class, iptunp->l4b0_val,
		    iptunp->l4b0_mask, 0, 0);
		break;
	case IPTUN_PKT_GTP:
		rs = npi_fflp_cfg_ip_usr_cls_set_iptun(handle,
		    (tcam_class_t)class, 0, 0, iptunp->l4b23_val,
		    (iptunp->l4b23_sel & 0x01));
		break;
	default:
		rs = NPI_FFLP_TCAM_CLASS_INVALID;
		break;
	}
	return (rs);
}

void
nxge_add_iptun_class(p_nxge_t nxgep, iptun_cfg_t *iptunp,
		uint8_t *cls_idp)
{
	int i, add_cls;
	uint8_t pid;
	uint64_t class;
	p_nxge_hw_list_t hw_p = nxgep->nxge_hw_p;
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;

	pid = nxge_iptun_pkt_type_to_pid(iptunp->in_pkt_type);
	if (pid == 0)
		return;

	add_cls = 0;
	MUTEX_ENTER(&hw_p->nxge_tcam_lock);

	/* Get an user programmable class ID */
	for (i = 0; i < NXGE_L3_PROG_CLS; i++) {
		if (hw_p->tcam_l3_prog_cls[i].valid == 0) {
			/* todo add new usr class reg */
			switch (i) {
			case 0:
				class = TCAM_CLASS_IP_USER_4;
				break;
			case 1:
				class = TCAM_CLASS_IP_USER_5;
				break;
			case 2:
				class = TCAM_CLASS_IP_USER_6;
				break;
			case 3:
				class = TCAM_CLASS_IP_USER_7;
				break;
			default:
				break;
			}
			rs = npi_fflp_cfg_ip_usr_cls_set(handle,
			    (tcam_class_t)class, 0, 0, pid, 0);
			if (rs != NPI_SUCCESS)
				goto fail;

			rs = nxge_set_iptun_usr_cls_reg(nxgep, class, iptunp);

			if (rs != NPI_SUCCESS)
				goto fail;

			rs = npi_fflp_cfg_ip_usr_cls_enable(handle,
			    (tcam_class_t)class);
			if (rs != NPI_SUCCESS)
				goto fail;

			hw_p->tcam_l3_prog_cls[i].cls = class;
			hw_p->tcam_l3_prog_cls[i].pid = pid;
			hw_p->tcam_l3_prog_cls[i].flow_pkt_type =
			    iptunp->in_pkt_type;
			hw_p->tcam_l3_prog_cls[i].valid = 1;
			*cls_idp = (uint8_t)class;
			add_cls = 1;
			break;
		} else if (hw_p->tcam_l3_prog_cls[i].pid == pid) {
			if (hw_p->tcam_l3_prog_cls[i].flow_pkt_type == 0) {
				/* there is no flow key */
				/* todo program the existing usr class reg */

				rs = nxge_set_iptun_usr_cls_reg(nxgep, class,
				    iptunp);
				if (rs != NPI_SUCCESS)
					goto fail;

				rs = npi_fflp_cfg_ip_usr_cls_enable(handle,
				    (tcam_class_t)class);
				if (rs != NPI_SUCCESS)
					goto fail;

				hw_p->tcam_l3_prog_cls[i].flow_pkt_type =
				    iptunp->in_pkt_type;
				*cls_idp = (uint8_t)class;
				add_cls = 1;
			} else {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "nxge_add_iptun_class: L3 usr "
				    "programmable class with pid %d "
				    "already exists", pid));
			}
			break;
		}
	}
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);

	if (add_cls != 1) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_add_iptun_class: Could not add IP tunneling class"));
	}
	return;
fail:
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_add_iptun_class: FAILED"));
}

static boolean_t
nxge_is_iptun_cls_present(p_nxge_t nxgep, uint8_t cls_id, int *idx)
{
	int i;
	p_nxge_hw_list_t hw_p = nxgep->nxge_hw_p;

	MUTEX_ENTER(&hw_p->nxge_tcam_lock);
	for (i = 0; i < NXGE_L3_PROG_CLS; i++) {
		if (hw_p->tcam_l3_prog_cls[i].valid &&
		    hw_p->tcam_l3_prog_cls[i].flow_pkt_type != 0) {
			if (hw_p->tcam_l3_prog_cls[i].cls == cls_id)
				break;
		}
	}
	MUTEX_EXIT(&hw_p->nxge_tcam_lock);

	if (i == NXGE_L3_PROG_CLS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_is_iptun_cls_present: Invalid class %d", cls_id));
		return (B_FALSE);
	} else {
		*idx = i;
		return (B_TRUE);
	}
}

void
nxge_cfg_iptun_hash(p_nxge_t nxgep, iptun_cfg_t *iptunp, uint8_t cls_id)
{
	int idx;
	npi_handle_t handle = nxgep->npi_reg_handle;
	flow_key_cfg_t cfg;

	/* check to see that this is a valid class ID */
	if (!nxge_is_iptun_cls_present(nxgep, cls_id, &idx)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_cfg_iptun_hash: nxge_is_iptun_cls_present "
		    "failed for cls_id %d", cls_id));
		return;
	}

	bzero((void *)&cfg, sizeof (flow_key_cfg_t));

	/*
	 * This ensures that all 4 bytes of the XOR value are loaded to the
	 * hash key.
	 */
	cfg.use_dport = cfg.use_sport = cfg.ip_opts_exist = 1;

	cfg.l4_xor_sel = (iptunp->l4xor_sel & FL_KEY_USR_L4XOR_MSK);
	cfg.use_l4_md = 1;

	if (iptunp->hash_flags & HASH_L3PROTO)
		cfg.use_proto = 1;
	else if (iptunp->hash_flags & HASH_IPDA)
		cfg.use_daddr = 1;
	else if (iptunp->hash_flags & HASH_IPSA)
		cfg.use_saddr = 1;
	else if (iptunp->hash_flags & HASH_VLAN)
		cfg.use_vlan = 1;
	else if (iptunp->hash_flags & HASH_L2DA)
		cfg.use_l2da = 1;
	else if (iptunp->hash_flags & HASH_IFPORT)
		cfg.use_portnum = 1;

	(void) npi_fflp_cfg_ip_cls_flow_key_rfnl(handle, (tcam_class_t)cls_id,
	    &cfg);
}

void
nxge_del_iptun_class(p_nxge_t nxgep, uint8_t cls_id)
{
	int i;
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;


	/* check to see that this is a valid class ID */
	if (!nxge_is_iptun_cls_present(nxgep, cls_id, &i)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_del_iptun_class: Invalid class ID 0x%x", cls_id));
		return;
	}

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_tcam_lock);
	rs = npi_fflp_cfg_ip_usr_cls_disable(handle, (tcam_class_t)cls_id);
	if (rs != NPI_SUCCESS)
		goto fail;
	nxgep->nxge_hw_p->tcam_l3_prog_cls[i].flow_pkt_type = 0;
	if (nxgep->nxge_hw_p->tcam_l3_prog_cls[i].tcam_ref_cnt == 0)
		nxgep->nxge_hw_p->tcam_l3_prog_cls[i].valid = 0;

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);
	return;
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_tcam_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_del_iptun_class: FAILED"));
}

void
nxge_get_iptun_class(p_nxge_t nxgep, iptun_cfg_t *iptunp, uint8_t cls_id)
{
	int i;
	uint8_t pid;
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;
	flow_key_cfg_t cfg;


	/* check to see that this is a valid class ID */
	if (!nxge_is_iptun_cls_present(nxgep, cls_id, &i))
		return;

	bzero((void *)iptunp, sizeof (iptun_cfg_t));

	pid = nxgep->nxge_hw_p->tcam_l3_prog_cls[i].pid;

	rs = npi_fflp_cfg_ip_usr_cls_get_iptun(handle, (tcam_class_t)cls_id,
	    &iptunp->l4b0_val, &iptunp->l4b0_mask, &iptunp->l4b23_val,
	    &iptunp->l4b23_sel);
	if (rs != NPI_SUCCESS)
		goto fail;

	rs = npi_fflp_cfg_ip_cls_flow_key_get_rfnl(handle,
	    (tcam_class_t)cls_id, &cfg);
	if (rs != NPI_SUCCESS)
		goto fail;

	iptunp->l4xor_sel = cfg.l4_xor_sel;
	if (cfg.use_proto)
		iptunp->hash_flags |= HASH_L3PROTO;
	else if (cfg.use_daddr)
		iptunp->hash_flags |= HASH_IPDA;
	else if (cfg.use_saddr)
		iptunp->hash_flags |= HASH_IPSA;
	else if (cfg.use_vlan)
		iptunp->hash_flags |= HASH_VLAN;
	else if (cfg.use_l2da)
		iptunp->hash_flags |= HASH_L2DA;
	else if (cfg.use_portnum)
		iptunp->hash_flags |= HASH_IFPORT;

	switch (pid) {
	case 4:
		iptunp->in_pkt_type = IPTUN_PKT_IPV4;
		break;
	case 41:
		iptunp->in_pkt_type = IPTUN_PKT_IPV6;
		break;
	case 47:
		iptunp->in_pkt_type = IPTUN_PKT_GRE;
		break;
	case 17:
		iptunp->in_pkt_type = IPTUN_PKT_GTP;
		break;
	default:
		iptunp->in_pkt_type = 0;
		break;
	}

	return;
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_get_iptun_class: FAILED"));
}

void
nxge_set_ip_cls_sym(p_nxge_t nxgep, uint8_t cls_id, uint8_t sym)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;
	boolean_t sym_en = (sym == 1) ? B_TRUE : B_FALSE;

	rs = npi_fflp_cfg_sym_ip_cls_flow_key(handle, (tcam_class_t)cls_id,
	    sym_en);
	if (rs != NPI_SUCCESS)
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_set_ip_cls_sym: FAILED"));
}

void
nxge_get_ip_cls_sym(p_nxge_t nxgep, uint8_t cls_id, uint8_t *sym)
{
	npi_handle_t handle = nxgep->npi_reg_handle;
	npi_status_t rs = NPI_SUCCESS;
	flow_key_cfg_t cfg;

	rs = npi_fflp_cfg_ip_cls_flow_key_get_rfnl(handle,
	    (tcam_class_t)cls_id, &cfg);
	if (rs != NPI_SUCCESS)
		goto fail;

	if (cfg.use_sym)
		*sym = 1;
	else
		*sym = 0;
	return;
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_get_ip_cls_sym: FAILED"));
}
