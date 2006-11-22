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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nxge_impl.h>
#include <nxge_mac.h>
#include <npi_espc.h>
#include <nxge_espc.h>

static void
nxge_espc_get_next_mac_addr(uint8_t *, uint8_t, struct ether_addr *);

static void
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
			    "==> nxge_espc_mac_addr_get, port[%d]",
			    port_num));

	npi_status = npi_espc_mac_addr_get(handle, mac_addr);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "nxge_espc_mac_addr_get, port[%d] failed",
				    port_num));
		goto exit;
	}

	nxge_espc_get_next_mac_addr(mac_addr, port_num, &nxgep->factaddr);
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"Got MAC Addr: %2x:%2x:%2x:%2x:%2x%:%2x%c \n",
			mac_addr[0], mac_addr[1],
			mac_addr[2], mac_addr[3],
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

	npi_status = npi_espc_port_phy_type_get(handle, &phy_type,
						port_num);
	if (npi_status != NPI_SUCCESS) {
		status = (NXGE_ERROR | npi_status);
		goto exit;
	}

	switch (phy_type) {
	case ESC_PHY_10G_FIBER:
		nxgep->mac.portmode = PORT_10G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
		cmn_err(CE_NOTE, "!SPROM Read phy type 10G Fiber \n");
		break;
	case ESC_PHY_10G_COPPER:
		nxgep->mac.portmode = PORT_10G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
		cmn_err(CE_NOTE, "!SPROM Read phy type 10G Copper \n");

		break;
	case ESC_PHY_1G_FIBER:
		nxgep->mac.portmode = PORT_1G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
		cmn_err(CE_NOTE, "!SPROM Read phy type 1G Fiber \n");

		break;
	case ESC_PHY_1G_COPPER:
		nxgep->mac.portmode = PORT_1G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = INT_MII_XCVR;
		cmn_err(CE_NOTE, "!SPROM Read phy type 1G Copper \n");

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
