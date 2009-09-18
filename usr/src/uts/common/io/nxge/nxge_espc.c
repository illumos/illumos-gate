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

#include <nxge_impl.h>
#include <nxge_mac.h>
#include <npi_espc.h>
#include <nxge_espc.h>

static void nxge_check_vpd_version(p_nxge_t nxgep);

void
nxge_espc_get_next_mac_addr(uint8_t *st_mac, uint8_t nxt_cnt,
			    struct ether_addr *final_mac)
{
	uint64_t	mac[ETHERADDRL];
	uint64_t	mac_addr = 0;
	int		i, j;

	for (i = ETHERADDRL - 1, j = 0; j < ETHERADDRL; i--, j++) {
		mac[j] = st_mac[i];
		mac_addr |= (mac[j] << (j*8));
	}

	mac_addr += nxt_cnt;

	final_mac->ether_addr_octet[0] = (mac_addr & 0xff0000000000) >> 40;
	final_mac->ether_addr_octet[1] = (mac_addr & 0xff00000000) >> 32;
	final_mac->ether_addr_octet[2] = (mac_addr & 0xff000000) >> 24;
	final_mac->ether_addr_octet[3] = (mac_addr & 0xff0000) >> 16;
	final_mac->ether_addr_octet[4] = (mac_addr & 0xff00) >> 8;
	final_mac->ether_addr_octet[5] = (mac_addr & 0xff);
}

nxge_status_t
nxge_espc_mac_addrs_get(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	npi_status_t	npi_status = NPI_SUCCESS;
	uint8_t		port_num = nxgep->mac.portnum;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	uint8_t		mac_addr[ETHERADDRL];

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_espc_mac_addr_get, port[%d]", port_num));

	npi_status = npi_espc_mac_addr_get(handle, mac_addr);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_espc_mac_addr_get, port[%d] failed", port_num));
		goto exit;
	}

	nxge_espc_get_next_mac_addr(mac_addr, port_num, &nxgep->factaddr);
		NXGE_DEBUG_MSG((nxgep, CFG_CTL,
		    "Got MAC Addr: %2x:%2x:%2x:%2x:%2x%:%2x%c \n",
		    mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3],
		    mac_addr[4], mac_addr[5]));

exit:
	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "<== nxge_espc_mac_addr_get, "
	    "status [0x%x]", status));

	return (status);
}

nxge_status_t
nxge_espc_num_macs_get(p_nxge_t nxgep, uint8_t *nmacs)
{
	nxge_status_t   status = NXGE_OK;
	npi_status_t    npi_status = NPI_SUCCESS;
	npi_handle_t    handle = NXGE_DEV_NPI_HANDLE(nxgep);
	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "==> nxge_espc_num_macs_get"));

	npi_status = npi_espc_num_macs_get(handle, nmacs);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
	}

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "<== nxge_espc_num_macs_get, "
	    "status [0x%x]", status));

	return (status);
}

nxge_status_t
nxge_espc_num_ports_get(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	npi_status_t	npi_status = NPI_SUCCESS;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	uint8_t		nports = 0;
	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "==> nxge_espc_num_ports_get"));

	npi_status = npi_espc_num_ports_get(handle, &nports);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
	}
	nxgep->nports = nports;
	NXGE_DEBUG_MSG((nxgep, CFG_CTL, " nxge_espc_num_ports_get "
	    "ports [0x%x]", nports));

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "<== nxge_espc_num_ports_get, "
	    "status [0x%x]", status));

	return (status);
}

nxge_status_t
nxge_espc_phy_type_get(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	npi_status_t	npi_status = NPI_SUCCESS;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	uint8_t		port_num = nxgep->mac.portnum;
	uint8_t		phy_type;

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "==> nxge_espc_phy_type_get, port[%d]",
	    port_num));

	npi_status = npi_espc_port_phy_type_get(handle, &phy_type, port_num);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
		goto exit;
	}

	switch (phy_type) {
	case ESC_PHY_10G_FIBER:
		nxgep->mac.portmode = PORT_10G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
		break;
	case ESC_PHY_10G_COPPER:
		nxgep->mac.portmode = PORT_10G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
		break;
	case ESC_PHY_1G_FIBER:
		nxgep->mac.portmode = PORT_1G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
		break;
	case ESC_PHY_1G_COPPER:
		nxgep->mac.portmode = PORT_1G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = INT_MII_XCVR;
		break;
	case ESC_PHY_NONE:
		status = NXGE_ERROR;
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_espc_phy_type_get:"
		    "No phy type set"));
		break;
	default:
		status = NXGE_ERROR;
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_espc_phy_type_get: "
		    "Unknown phy type [%d]", phy_type));
		break;
	}

exit:

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "<== nxge_espc_phy_type_get, "
	    "status [0x%x]", status));

	return (status);
}

nxge_status_t
nxge_espc_max_frame_sz_get(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	npi_status_t	npi_status = NPI_SUCCESS;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "==> nxge_espc_max_frame_sz_get"));

	npi_status = npi_espc_max_frame_get(handle, &nxgep->mac.maxframesize);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
	}

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, " nxge_espc_max_frame_sz_get, "
	    "status [0x%x]", status));

	return (status);
}

void
nxge_vpd_info_get(p_nxge_t nxgep)
{
	npi_status_t	status;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	if ((nxgep->platform_type == P_NEPTUNE_NIU) ||
	    (nxgep->platform_type == P_NEPTUNE_MARAMBA_P0) ||
	    (nxgep->platform_type == P_NEPTUNE_MARAMBA_P1) ||
	    (nxgep->platform_type == P_NEPTUNE_ROCK)) {
		nxgep->vpd_info.present = B_FALSE;
		return;
	}

	NXGE_DEBUG_MSG((nxgep, CFG_CTL, "nxge_vpd_info_get: "
	    "nxgep->platform_type[%d]...reading vpd", nxgep->platform_type));

	nxgep->vpd_info.present = B_TRUE;
	nxgep->vpd_info.ver_valid = B_FALSE;

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_cfg_lock);
	(void) npi_espc_pio_enable(handle);
	status = npi_espc_vpd_info_get(handle, &nxgep->vpd_info,
	    NXGE_EROM_LEN);
	(void) npi_espc_pio_disable(handle);
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_cfg_lock);

	if (status != NPI_SUCCESS)
		return;

	nxge_check_vpd_version(nxgep);
	if (!nxgep->vpd_info.ver_valid)
		return;

	/* Determine the platform type */
	if ((strncmp(nxgep->vpd_info.bd_model, NXGE_QGC_LP_BM_STR,
	    strlen(NXGE_QGC_LP_BM_STR)) == 0) ||
	    (strncmp(nxgep->vpd_info.bd_model, NXGE_QGC_PEM_BM_STR,
	    strlen(NXGE_QGC_PEM_BM_STR)) == 0)) {
		nxgep->platform_type = P_NEPTUNE_ATLAS_4PORT;
	} else if ((strncmp(nxgep->vpd_info.bd_model,
	    NXGE_2XGF_LP_BM_STR, strlen(NXGE_2XGF_LP_BM_STR)) == 0) ||
	    (strncmp(nxgep->vpd_info.bd_model, NXGE_2XGF_PEM_BM_STR,
	    strlen(NXGE_2XGF_PEM_BM_STR)) == 0)) {
		nxgep->platform_type = P_NEPTUNE_ATLAS_2PORT;
	} else if (strncmp(nxgep->vpd_info.bd_model,
	    NXGE_ALONSO_BM_STR, strlen(NXGE_ALONSO_BM_STR)) == 0) {
		nxgep->platform_type = P_NEPTUNE_ALONSO;
	} else if (strncmp(nxgep->vpd_info.bd_model,
	    NXGE_RFEM_BM_STR, strlen(NXGE_RFEM_BM_STR)) == 0) {
		nxgep->hot_swappable_phy = B_TRUE;
		nxgep->platform_type = P_NEPTUNE_GENERIC;
		nxgep->niu_type = NEPTUNE_2_10GF;
	}

	/* If Alonso platform, replace "mif" for the last 2 ports phy-type */
	if ((nxgep->platform_type == P_NEPTUNE_ALONSO) &&
	    ((nxgep->function_num == 2) || (nxgep->function_num == 3))) {
		(void) strcpy(nxgep->vpd_info.phy_type, "mif");
	}

	/* If ARTM card, replace "mif" for the last 2 ports phy-type */
	if ((strncmp(nxgep->vpd_info.bd_model,
	    NXGE_ARTM_BM_STR, strlen(NXGE_ARTM_BM_STR)) == 0) &&
	    ((nxgep->function_num == 2) || (nxgep->function_num == 3))) {
		NXGE_DEBUG_MSG((nxgep, NXGE_ERR_CTL,
		    "Replaced phy type as mif"));
		(void) strcpy(nxgep->vpd_info.phy_type, "mif");
	}
}

static void
nxge_check_vpd_version(p_nxge_t nxgep)
{
	int		i, j;
	const char	*fcode_str = NXGE_FCODE_ID_STR;
	int		fcode_str_len = strlen(fcode_str);
	char		ver_num_str[NXGE_FCODE_VER_STR_LEN];
	char		*ver_num_w;
	char		*ver_num_f;
	int		ver_num_w_len = 0;
	int		ver_num_f_len = 0;
	int		ver_w = 0;
	int		ver_f = 0;

	nxgep->vpd_info.ver_valid = B_FALSE;
	ver_num_str[0] = '\0';

	for (i = 0; i < NXGE_VPD_VER_LEN; i++) {
		if (nxgep->vpd_info.ver[i] == fcode_str[0]) {
			if ((i + fcode_str_len + NXGE_FCODE_VER_STR_LEN) >
			    NXGE_VPD_VER_LEN)
				break;
			for (j = 0; j < fcode_str_len; j++, i++) {
				if (nxgep->vpd_info.ver[i] != fcode_str[j])
					break;
			}
			if (j < fcode_str_len)
				continue;

			/* found the Fcode version string */
			for (j = 0; j < NXGE_FCODE_VER_STR_LEN; j++, i++) {
				ver_num_str[j] = nxgep->vpd_info.ver[i];
				if (ver_num_str[j] == ' ')
					break;
			}
			if (j < NXGE_FCODE_VER_STR_LEN)
				ver_num_str[j] = '\0';
			break;
		}
	}

	ver_num_w = ver_num_str;
	for (i = 0; i < strlen(ver_num_str); i++) {
		if (ver_num_str[i] == '.') {
			ver_num_f = &ver_num_str[i + 1];
			ver_num_w_len = i;
			ver_num_f_len = strlen(ver_num_str) - (i + 1);
			break;
		}
	}

	for (i = 0; i < ver_num_w_len; i++) {
		ver_w = (ver_w * 10) + (ver_num_w[i] - '0');
	}

	for (i = 0; i < ver_num_f_len; i++) {
		ver_f = (ver_f * 10) + (ver_num_f[i] - '0');
	}

	if ((ver_w > NXGE_VPD_VALID_VER_W) ||
	    (ver_w == NXGE_VPD_VALID_VER_W && ver_f >= NXGE_VPD_VALID_VER_F))
		nxgep->vpd_info.ver_valid = B_TRUE;

}
