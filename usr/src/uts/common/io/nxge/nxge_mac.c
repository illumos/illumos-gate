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

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_mac.h>

#define	LINK_MONITOR_PERIOD	(1000 * 1000)
#define	LM_WAIT_MULTIPLIER	8

extern uint32_t nxge_no_link_notify;
extern boolean_t nxge_no_msg;
extern uint32_t nxge_lb_dbg;
extern nxge_os_mutex_t	nxge_mdio_lock;
extern nxge_os_mutex_t	nxge_mii_lock;
extern boolean_t nxge_jumbo_enable;

typedef enum {
	CHECK_LINK_RESCHEDULE,
	CHECK_LINK_STOP
} check_link_state_t;

static check_link_state_t nxge_check_link_stop(nxge_t *);

/*
 * Ethernet broadcast address definition.
 */
static ether_addr_st etherbroadcastaddr =
				{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
/*
 * Ethernet zero address definition.
 */
static ether_addr_st etherzeroaddr =
				{{0x0, 0x0, 0x0, 0x0, 0x0, 0x0}};
/*
 * Supported chip types
 */
static uint32_t nxge_supported_cl45_ids[] = {BCM8704_DEV_ID};
static uint32_t nxge_supported_cl22_ids[] = {BCM5464R_PHY_ID};

#define	NUM_CLAUSE_45_IDS	(sizeof (nxge_supported_cl45_ids) /	\
				sizeof (uint32_t))
#define	NUM_CLAUSE_22_IDS	(sizeof (nxge_supported_cl22_ids) /	\
				sizeof (uint32_t))
/*
 * static functions
 */
static uint32_t nxge_get_cl45_pma_pmd_id(p_nxge_t, int);
static uint32_t nxge_get_cl45_pcs_id(p_nxge_t, int);
static uint32_t nxge_get_cl22_phy_id(p_nxge_t, int);
static boolean_t nxge_is_supported_phy(uint32_t, uint8_t);
static nxge_status_t nxge_n2_serdes_init(p_nxge_t);
static nxge_status_t nxge_neptune_10G_serdes_init(p_nxge_t);
static nxge_status_t nxge_1G_serdes_init(p_nxge_t);
static nxge_status_t nxge_10G_link_intr_stop(p_nxge_t);
static nxge_status_t nxge_10G_link_intr_start(p_nxge_t);
static nxge_status_t nxge_1G_copper_link_intr_stop(p_nxge_t);
static nxge_status_t nxge_1G_copper_link_intr_start(p_nxge_t);
static nxge_status_t nxge_1G_fiber_link_intr_stop(p_nxge_t);
static nxge_status_t nxge_1G_fiber_link_intr_start(p_nxge_t);
static nxge_status_t nxge_check_mii_link(p_nxge_t);
static nxge_status_t nxge_check_10g_link(p_nxge_t);
static nxge_status_t nxge_10G_xcvr_init(p_nxge_t);
static nxge_status_t nxge_1G_xcvr_init(p_nxge_t);
static void nxge_bcm5464_link_led_off(p_nxge_t);

/*
 * xcvr tables for supported transceivers
 */

static nxge_xcvr_table_t nxge_n2_10G_table = {
	nxge_n2_serdes_init,
	nxge_10G_xcvr_init,
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_10g_link,
	PCS_XCVR,
	BCM8704_N2_PORT_ADDR_BASE
};

static nxge_xcvr_table_t nxge_n2_1G_table = {
	nxge_n2_serdes_init,
	nxge_1G_xcvr_init,
	nxge_1G_fiber_link_intr_stop,
	nxge_1G_fiber_link_intr_start,
	nxge_check_mii_link,
	PCS_XCVR,
	0
};

static nxge_xcvr_table_t nxge_10G_fiber_table = {
	nxge_neptune_10G_serdes_init,
	nxge_10G_xcvr_init,
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_10g_link,
	PCS_XCVR,
	BCM8704_NEPTUNE_PORT_ADDR_BASE
};

static nxge_xcvr_table_t nxge_1G_copper_table = {
	NULL,
	nxge_1G_xcvr_init,
	nxge_1G_copper_link_intr_stop,
	nxge_1G_copper_link_intr_start,
	nxge_check_mii_link,
	INT_MII_XCVR,
	BCM5464_NEPTUNE_PORT_ADDR_BASE
};

static nxge_xcvr_table_t nxge_1G_fiber_table = {
	nxge_1G_serdes_init,
	nxge_1G_xcvr_init,
	nxge_1G_fiber_link_intr_stop,
	nxge_1G_fiber_link_intr_start,
	nxge_check_mii_link,
	PCS_XCVR,
	0
};

static nxge_xcvr_table_t nxge_10G_copper_table = {
	nxge_neptune_10G_serdes_init,
	NULL,
	NULL,
	NULL,
	NULL,
	PCS_XCVR,
	0
};

nxge_status_t nxge_mac_init(p_nxge_t);

nxge_status_t
nxge_get_xcvr_type(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;
	char *phy_type;
	char *prop_val;

	nxgep->mac.portmode = 0;

	/* Get property from the driver conf. file */
	if ((ddi_prop_lookup_string(DDI_DEV_T_ANY, nxgep->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "phy-type", &prop_val)) == DDI_PROP_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "found  conf file: phy-type %s", prop_val));
		if (strcmp("xgsd", prop_val) == 0) {
			nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
			nxgep->mac.portmode = PORT_10G_SERDES;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "found: 10G Serdes"));
		} else if (strcmp("gsd", prop_val) == 0) {
			nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
			nxgep->mac.portmode = PORT_1G_SERDES;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G Serdes"));
		} else if (strcmp("mif", prop_val) == 0) {
			nxgep->statsp->mac_stats.xcvr_inuse = INT_MII_XCVR;
			nxgep->mac.portmode = PORT_1G_COPPER;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G Copper Xcvr"));
		} else if (strcmp("pcs", prop_val) == 0) {
			nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
			nxgep->mac.portmode = PORT_1G_FIBER;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G FIBER Xcvr"));
		}

		(void) ddi_prop_update_string(DDI_DEV_T_NONE, nxgep->dip,
		    "phy-type", prop_val);
		ddi_prop_free(prop_val);

		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_get_xcvr_type: "
		    "Got phy type [0x%x] from conf file",
		    nxgep->mac.portmode));

		return (NXGE_OK);
	}
/*
 * TODO add MDIO support for Monza RTM card, Glendale (also Goa) -
 * only N2-NIU
 */
	if (nxgep->niu_type == N2_NIU) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, nxgep->dip, 0,
		    "phy-type", &prop_val) == DDI_PROP_SUCCESS) {
			if (strcmp("xgf", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse =
				    XPCS_XCVR;
				nxgep->mac.portmode = PORT_10G_FIBER;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "10G Fiber Xcvr"));
			} else if (strcmp("mif", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse =
				    INT_MII_XCVR;
				nxgep->mac.portmode = PORT_1G_COPPER;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "1G Copper Xcvr"));
			} else if (strcmp("pcs", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
				nxgep->mac.portmode = PORT_1G_FIBER;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "1G Fiber Xcvr"));
			} else if (strcmp("xgc", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse =
				    XPCS_XCVR;
				nxgep->mac.portmode = PORT_10G_COPPER;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "10G Copper Xcvr"));
			} else if (strcmp("xgsd", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
				nxgep->mac.portmode = PORT_10G_SERDES;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "OBP: 10G Serdes"));
			} else if (strcmp("gsd", prop_val) == 0) {
				nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
				nxgep->mac.portmode = PORT_1G_SERDES;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "OBP: 1G Serdes"));
			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unknown phy-type: %s", prop_val));
				ddi_prop_free(prop_val);
				return (NXGE_ERROR);
			}
			status = NXGE_OK;
			(void) ddi_prop_update_string(DDI_DEV_T_NONE,
			    nxgep->dip, "phy-type", prop_val);
			ddi_prop_free(prop_val);

			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_get_xcvr_type: "
			    "Got phy type [0x%x] from OBP",
			    nxgep->mac.portmode));

			return (status);
		} else {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "Exiting...phy-type property not found"));
			return (NXGE_ERROR);
		}
	}


	if (!nxgep->vpd_info.present) {
		return (NXGE_OK);
	}

	if (!nxgep->vpd_info.ver_valid) {
		goto read_seeprom;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "Reading phy type from expansion ROM"));
	/*
	 * Try to read the phy type from the vpd data read off the
	 * expansion ROM.
	 */
	phy_type = nxgep->vpd_info.phy_type;

	if (phy_type[0] == 'm' && phy_type[1] == 'i' && phy_type[2] == 'f') {
		nxgep->mac.portmode = PORT_1G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = INT_MII_XCVR;
	} else if (phy_type[0] == 'x' && phy_type[1] == 'g' &&
	    phy_type[2] == 'f') {
		nxgep->mac.portmode = PORT_10G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
	} else if (phy_type[0] == 'p' && phy_type[1] == 'c' &&
	    phy_type[2] == 's') {
		nxgep->mac.portmode = PORT_1G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
	} else if (phy_type[0] == 'x' && phy_type[1] == 'g' &&
	    phy_type[2] == 'c') {
		nxgep->mac.portmode = PORT_10G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
	} else {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_get_xcvr_type: Unknown phy type [%c%c%c] in EEPROM",
		    phy_type[0], phy_type[1], phy_type[2]));
		goto read_seeprom;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_get_xcvr_type: "
	    "Got phy type [0x%x] from VPD", nxgep->mac.portmode));

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_get_xcvr_type"));
	return (status);

read_seeprom:
	/*
	 * read the phy type from the SEEPROM - NCR registers
	 */
	status = nxge_espc_phy_type_get(nxgep);
	if (status != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "Failed to get phy type"));
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "EEPROM version "
		    "[%s] invalid...please update", nxgep->vpd_info.ver));
	}

	return (status);

}

/* Set up the PHY specific values. */

nxge_status_t
nxge_setup_xcvr_table(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	uint32_t	port_type;
	uint8_t		portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	uint32_t	pcs_id = 0;
	uint32_t	pma_pmd_id = 0;
	uint32_t	phy_id = 0;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_setup_xcvr_table: port<%d>",
	    portn));

	switch (nxgep->niu_type) {
	case N2_NIU:
		switch (nxgep->mac.portmode) {
		case PORT_1G_FIBER:
		case PORT_1G_SERDES:
			nxgep->xcvr = nxge_n2_1G_table;
			nxgep->xcvr.xcvr_addr = portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "NIU 1G %s Xcvr",
			    (nxgep->mac.portmode == PORT_1G_FIBER) ? "Fiber" :
			    "Serdes"));
			break;
		case PORT_10G_FIBER:
		case PORT_10G_SERDES:
			nxgep->xcvr = nxge_n2_10G_table;
			nxgep->xcvr.xcvr_addr += portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "NIU 10G %s Xcvr",
			    (nxgep->mac.portmode == PORT_10G_FIBER) ? "Fiber" :
			    "Serdes"));
			break;
		default:
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "<== nxge_setup_xcvr_table: "
			    "Unable to determine NIU portmode"));
			return (NXGE_ERROR);
		}
		break;
	default:
		if (nxgep->mac.portmode == 0) {
			/*
			 * Would be the case for platforms like Maramba
			 * in which the phy type could not be got from conf
			 * file, OBP, VPD or Serial PROM.
			 */
			if (!NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "<== nxge_setup_xcvr_table:"
				    " Invalid Neptune type [0x%x]",
				    nxgep->niu_type));
				return (NXGE_ERROR);
			}

			port_type = nxgep->niu_type >>
			    (NXGE_PORT_TYPE_SHIFT * portn);
			port_type = port_type & (NXGE_PORT_TYPE_MASK);

			switch (port_type) {

			case NXGE_PORT_1G_COPPER:
				nxgep->mac.portmode = PORT_1G_COPPER;
				break;
			case NXGE_PORT_10G_COPPER:
				nxgep->mac.portmode = PORT_10G_COPPER;
				break;
			case NXGE_PORT_1G_FIBRE:
				nxgep->mac.portmode = PORT_1G_FIBER;
				break;
			case NXGE_PORT_10G_FIBRE:
				nxgep->mac.portmode = PORT_10G_FIBER;
				break;
			case NXGE_PORT_1G_SERDES:
				nxgep->mac.portmode = PORT_1G_SERDES;
				break;
			case NXGE_PORT_10G_SERDES:
				nxgep->mac.portmode = PORT_10G_SERDES;
				break;
			case NXGE_PORT_1G_RGMII_FIBER:
				nxgep->mac.portmode = PORT_1G_RGMII_FIBER;
				break;
			default:
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "<== nxge_setup_xcvr_table: "
				    "Unknown port-type: 0x%x", port_type));
				return (NXGE_ERROR);
			}
		}

		switch (nxgep->mac.portmode) {
		case PORT_1G_COPPER:
		case PORT_1G_RGMII_FIBER:
			nxgep->xcvr = nxge_1G_copper_table;

			/*
			 * For Altas 4-1G copper, Xcvr port numbers are
			 * swapped with ethernet port number. This is
			 * designed for better signal integrity in
			 * routing. This is also the case for the
			 * on-board Neptune copper ports on the Maramba
			 * platform.
			 */
			switch (nxgep->platform_type) {
			case P_NEPTUNE_MARAMBA_P1:
				nxgep->xcvr.xcvr_addr =
				    BCM5464_MARAMBA_P1_PORT_ADDR_BASE;
				break;
			case P_NEPTUNE_MARAMBA_P0:
				nxgep->xcvr.xcvr_addr =
				    BCM5464_MARAMBA_P0_PORT_ADDR_BASE;
				break;
			default:
				break;
			}
			/*
			 * For Altas 4-1G copper, Xcvr port numbers are
			 * swapped with ethernet port number. This is
			 * designed for better signal integrity in
			 * routing. This is also the case for the
			 * on-board Neptune copper ports on the Maramba
			 * platform.
			 */
			switch (nxgep->platform_type) {
			case P_NEPTUNE_ATLAS_4PORT:
			case P_NEPTUNE_MARAMBA_P0:
			case P_NEPTUNE_MARAMBA_P1:
				switch (portn) {
				case 0:
					nxgep->xcvr.xcvr_addr += 3;
					break;
				case 1:
					nxgep->xcvr.xcvr_addr += 2;
					break;
				case 2:
					nxgep->xcvr.xcvr_addr += 1;
					break;
				case 3:
					break;
				default:
					return (NXGE_ERROR);
				}
				break;
			default:
				break;
			}
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G %s Xcvr",
			    (nxgep->mac.portmode == PORT_1G_COPPER) ?
			    "Copper" : "RGMII Fiber"));
			break;
		case PORT_10G_COPPER:
			nxgep->xcvr = nxge_10G_copper_table;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "10G Copper Xcvr"));
			break;
		case PORT_1G_FIBER:
		case PORT_1G_SERDES:
			nxgep->xcvr = nxge_1G_fiber_table;
			nxgep->xcvr.xcvr_addr = portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G %s Xcvr",
			    (nxgep->mac.portmode == PORT_1G_FIBER) ?
			    "Fiber" : "Serdes"));
			break;
		case PORT_10G_FIBER:
		case PORT_10G_SERDES:
			nxgep->xcvr = nxge_10G_fiber_table;
			switch (nxgep->platform_type) {
			case P_NEPTUNE_MARAMBA_P0:
			case P_NEPTUNE_MARAMBA_P1:
				nxgep->xcvr.xcvr_addr =
				    BCM8704_MARAMBA_PORT_ADDR_BASE;
				/*
				 * Switch off LED for corresponding copper
				 * port
				 */
				nxge_bcm5464_link_led_off(nxgep);
				break;
			default:
				break;
			}
			nxgep->xcvr.xcvr_addr += portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "10G %s Xcvr",
			    (nxgep->mac.portmode == PORT_10G_FIBER) ?
			    "Fiber" : "Serdes"));
			break;
		default:
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "Unknown port-type: 0x%x", port_type));
			return (NXGE_ERROR);
		}
	}

	nxgep->statsp->mac_stats.xcvr_inuse = nxgep->xcvr.xcvr_inuse;
	nxgep->statsp->mac_stats.xcvr_portn = nxgep->xcvr.xcvr_addr;

	/*
	 * Get the actual device ID value returned by MDIO read.
	 */
	nxgep->statsp->mac_stats.xcvr_id = 0;

	pma_pmd_id = nxge_get_cl45_pma_pmd_id(nxgep, nxgep->xcvr.xcvr_addr);
	if (nxge_is_supported_phy(pma_pmd_id, CLAUSE_45_TYPE)) {
		nxgep->statsp->mac_stats.xcvr_id = pma_pmd_id;
	} else {
		pcs_id = nxge_get_cl45_pcs_id(nxgep, nxgep->xcvr.xcvr_addr);
		if (nxge_is_supported_phy(pcs_id, CLAUSE_45_TYPE)) {
			nxgep->statsp->mac_stats.xcvr_id = pcs_id;
		} else {
			phy_id = nxge_get_cl22_phy_id(nxgep,
			    nxgep->xcvr.xcvr_addr);
			if (nxge_is_supported_phy(phy_id, CLAUSE_22_TYPE)) {
				nxgep->statsp->mac_stats.xcvr_id = phy_id;
			}
		}
	}

	nxgep->mac.linkchkmode = LINKCHK_TIMER;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_setup_xcvr_table: niu_type"
	    "[0x%x] platform type[0x%x]", nxgep->niu_type,
	    nxgep->platform_type));

	return (status);
}

/* Initialize the entire MAC and physical layer */

nxge_status_t
nxge_mac_init(p_nxge_t nxgep)
{
	uint8_t			portn;
	nxge_status_t		status = NXGE_OK;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mac_init: port<%d>", portn));

	nxgep->mac.portnum = portn;
	nxgep->mac.porttype = PORT_TYPE_XMAC;

	if ((portn == BMAC_PORT_0) || (portn == BMAC_PORT_1))
		nxgep->mac.porttype = PORT_TYPE_BMAC;

	/* Initialize XIF to configure a network mode */
	if ((status = nxge_xif_init(nxgep)) != NXGE_OK) {
		goto fail;
	}

	if ((status = nxge_pcs_init(nxgep)) != NXGE_OK) {
		goto fail;
	}

	/* Initialize TX and RX MACs */
	/*
	 * Always perform XIF init first, before TX and RX MAC init
	 */
	if ((status = nxge_tx_mac_reset(nxgep)) != NXGE_OK)
		goto fail;

	if ((status = nxge_tx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	if ((status = nxge_rx_mac_reset(nxgep)) != NXGE_OK)
		goto fail;

	if ((status = nxge_rx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	if ((status = nxge_tx_mac_enable(nxgep)) != NXGE_OK)
		goto fail;

	if ((status = nxge_rx_mac_enable(nxgep)) != NXGE_OK)
		goto fail;

	nxgep->statsp->mac_stats.mac_mtu = nxgep->mac.maxframesize;


	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_mac_init: port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			"nxge_mac_init: failed to initialize MAC port<%d>",
			portn));
	return (status);
}

/* Initialize the Ethernet Link */

nxge_status_t
nxge_link_init(p_nxge_t nxgep)
{
	nxge_status_t		status = NXGE_OK;
	nxge_port_mode_t	portmode;
#ifdef	NXGE_DEBUG
	uint8_t			portn;

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_link_init: port<%d>", portn));
#endif

	portmode = nxgep->mac.portmode;
	if (nxgep->niu_type == N2_NIU && (portmode != PORT_10G_SERDES) &&
	    (portmode != PORT_1G_SERDES)) {
		/* Workaround to get link up in both NIU ports */
		if ((status = nxge_xcvr_init(nxgep)) != NXGE_OK) {
			goto fail;
		}
	}
	NXGE_DELAY(200000);
	/* Initialize internal serdes */
	if ((status = nxge_serdes_init(nxgep)) != NXGE_OK)
		goto fail;
	NXGE_DELAY(200000);
	if ((status = nxge_xcvr_init(nxgep)) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_init: port<%d>", portn));

	return (NXGE_OK);

fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"nxge_link_init: ",
		"failed to initialize Ethernet link on port<%d>",
		portn));

	return (status);
}


/* Initialize the XIF sub-block within the MAC */

nxge_status_t
nxge_xif_init(p_nxge_t nxgep)
{
	uint32_t		xif_cfg = 0;
	npi_attr_t		ap;
	uint8_t			portn;
	nxge_port_t		portt;
	nxge_port_mode_t	portmode;
	p_nxge_stats_t		statsp;
	npi_status_t		rs = NPI_SUCCESS;
	npi_handle_t		handle;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_xif_init: port<%d>", portn));

	handle = nxgep->npi_handle;
	portmode = nxgep->mac.portmode;
	portt = nxgep->mac.porttype;
	statsp = nxgep->statsp;

	if (portt == PORT_TYPE_XMAC) {

		/* Setup XIF Configuration for XMAC */

		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_COPPER) ||
		    (portmode == PORT_10G_SERDES))
			xif_cfg |= CFG_XMAC_XIF_LFS;

		if (portmode == PORT_1G_COPPER) {
			xif_cfg |= CFG_XMAC_XIF_1G_PCS_BYPASS;
		}

		/* Set MAC Internal Loopback if necessary */
		if (statsp->port_stats.lb_mode == nxge_lb_mac1000)
			xif_cfg |= CFG_XMAC_XIF_LOOPBACK;

		if (statsp->mac_stats.link_speed == 100)
			xif_cfg |= CFG_XMAC_XIF_SEL_CLK_25MHZ;

		xif_cfg |= CFG_XMAC_XIF_TX_OUTPUT;

		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_SERDES)) {
			if (statsp->mac_stats.link_up) {
				xif_cfg |= CFG_XMAC_XIF_LED_POLARITY;
			} else {
				xif_cfg |= CFG_XMAC_XIF_LED_FORCE;
			}
		}

		rs = npi_xmac_xif_config(handle, INIT, portn, xif_cfg);
		if (rs != NPI_SUCCESS)
			goto fail;

		nxgep->mac.xif_config = xif_cfg;

		/* Set Port Mode */
		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_COPPER) ||
		    (portmode == PORT_10G_SERDES)) {
			SET_MAC_ATTR1(handle, ap, portn, MAC_PORT_MODE,
						MAC_XGMII_MODE, rs);
			if (rs != NPI_SUCCESS)
				goto fail;
			if (statsp->mac_stats.link_up) {
				if (nxge_10g_link_led_on(nxgep) != NXGE_OK)
					goto fail;
			} else {
				if (nxge_10g_link_led_off(nxgep) != NXGE_OK)
					goto fail;
			}
		} else if ((portmode == PORT_1G_FIBER) ||
		    (portmode == PORT_1G_COPPER) ||
		    (portmode == PORT_1G_SERDES)) {
			if (statsp->mac_stats.link_speed == 1000) {
				SET_MAC_ATTR1(handle, ap, portn, MAC_PORT_MODE,
							MAC_GMII_MODE, rs);
			} else {
				SET_MAC_ATTR1(handle, ap, portn, MAC_PORT_MODE,
							MAC_MII_MODE, rs);
			}
			if (rs != NPI_SUCCESS)
				goto fail;
		} else {
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					"nxge_xif_init: Unknown port mode (%d)"
					" for port<%d>", portmode, portn));
			goto fail;
		}

	} else if (portt == PORT_TYPE_BMAC) {

		/* Setup XIF Configuration for BMAC */

		if (portmode == PORT_1G_COPPER) {
			if (statsp->mac_stats.link_speed == 100)
				xif_cfg |= CFG_BMAC_XIF_SEL_CLK_25MHZ;
		}

		if (statsp->port_stats.lb_mode == nxge_lb_mac1000)
			xif_cfg |= CFG_BMAC_XIF_LOOPBACK;

		if (statsp->mac_stats.link_speed == 1000)
			xif_cfg |= CFG_BMAC_XIF_GMII_MODE;

		xif_cfg |= CFG_BMAC_XIF_TX_OUTPUT;

		rs = npi_bmac_xif_config(handle, INIT, portn, xif_cfg);
		if (rs != NPI_SUCCESS)
			goto fail;
		nxgep->mac.xif_config = xif_cfg;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_xif_init: port<%d>", portn));
	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			"nxge_xif_init: Failed to initialize XIF port<%d>",
			portn));
	return (NXGE_ERROR | rs);
}

/* Initialize the PCS sub-block in the MAC */

nxge_status_t
nxge_pcs_init(p_nxge_t nxgep)
{
	pcs_cfg_t		pcs_cfg;
	uint32_t		val;
	uint8_t			portn;
	nxge_port_mode_t	portmode;
	npi_handle_t		handle;
	p_nxge_stats_t		statsp;
	npi_status_t		rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;
	portmode = nxgep->mac.portmode;
	portn = nxgep->mac.portnum;
	statsp = nxgep->statsp;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_pcs_init: port<%d>", portn));

	if ((portmode == PORT_1G_FIBER) || (portmode == PORT_1G_SERDES)) {
		if ((rs = npi_mac_pcs_reset(handle, portn)) != NPI_SUCCESS) {
			goto fail;
		}

		/* Initialize port's PCS */
		pcs_cfg.value = 0;
		pcs_cfg.bits.w0.enable = 1;
		pcs_cfg.bits.w0.mask = 1;
		PCS_REG_WR(handle, portn, PCS_CONFIG_REG, pcs_cfg.value);
		PCS_REG_WR(handle, portn, PCS_DATAPATH_MODE_REG, 0);

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_pcs_init: (1G) port<%d> write config 0x%llx",
		    portn, pcs_cfg.value));
	} else if ((portmode == PORT_10G_FIBER) ||
	    (portmode == PORT_10G_COPPER) || (portmode == PORT_10G_SERDES)) {
		/* Use internal XPCS, bypass 1G PCS */
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
		val &= ~XMAC_XIF_XPCS_BYPASS;
		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);

		if ((rs = npi_xmac_xpcs_reset(handle, portn)) != NPI_SUCCESS)
			goto fail;

		/* Set XPCS Internal Loopback if necessary */
		if ((rs = npi_xmac_xpcs_read(handle, portn,
						XPCS_REG_CONTROL1, &val))
						!= NPI_SUCCESS)
			goto fail;
		if ((statsp->port_stats.lb_mode == nxge_lb_mac10g) ||
			(statsp->port_stats.lb_mode == nxge_lb_mac1000))
			val |= XPCS_CTRL1_LOOPBK;
		else
			val &= ~XPCS_CTRL1_LOOPBK;
		if ((rs = npi_xmac_xpcs_write(handle, portn,
						XPCS_REG_CONTROL1, val))
						!= NPI_SUCCESS)
			goto fail;

		/* Clear descw errors */
		if ((rs = npi_xmac_xpcs_write(handle, portn,
						XPCS_REG_DESCWERR_COUNTER, 0))
						!= NPI_SUCCESS)
			goto fail;
		/* Clear symbol errors */
		if ((rs = npi_xmac_xpcs_read(handle, portn,
					XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &val))
					!= NPI_SUCCESS)
			goto fail;
		if ((rs = npi_xmac_xpcs_read(handle, portn,
					XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &val))
					!= NPI_SUCCESS)
			goto fail;

	} else if (portmode == PORT_1G_COPPER) {
		if (portn < 4) {
			PCS_REG_WR(handle, portn, PCS_DATAPATH_MODE_REG,
					PCS_DATAPATH_MODE_MII);
		}
		if ((rs = npi_mac_pcs_reset(handle, portn)) != NPI_SUCCESS)
			goto fail;

	} else {
		goto fail;
	}
pass:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_pcs_init: port<%d>", portn));
	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			"nxge_pcs_init: Failed to initialize PCS port<%d>",
			portn));
	return (NXGE_ERROR | rs);
}

/* Initialize the Internal Serdes */

nxge_status_t
nxge_serdes_init(p_nxge_t nxgep)
{
	p_nxge_stats_t		statsp;
#ifdef	NXGE_DEBUG
	uint8_t			portn;
#endif
	nxge_status_t		status = NXGE_OK;

#ifdef	NXGE_DEBUG
	portn = nxgep->mac.portnum;
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_serdes_init port<%d>", portn));
#endif

	if (nxgep->xcvr.serdes_init) {
		statsp = nxgep->statsp;
		status = nxgep->xcvr.serdes_init(nxgep);
		if (status != NXGE_OK)
			goto fail;
		statsp->mac_stats.serdes_inits++;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_serdes_init port<%d>",
	    portn));

	return (NXGE_OK);

fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_serdes_init: Failed to initialize serdes for port<%d>",
	    portn));

	return (status);
}

/* Initialize the TI Hedwig Internal Serdes (N2-NIU only) */

static nxge_status_t
nxge_n2_serdes_init(p_nxge_t nxgep)
{
	uint8_t portn;
	int chan;
	esr_ti_cfgpll_l_t pll_cfg_l;
	esr_ti_cfgpll_l_t pll_sts_l;
	esr_ti_cfgrx_l_t rx_cfg_l;
	esr_ti_cfgrx_h_t rx_cfg_h;
	esr_ti_cfgtx_l_t tx_cfg_l;
	esr_ti_cfgtx_h_t tx_cfg_h;
#ifdef NXGE_DEBUG
	esr_ti_testcfg_t cfg;
#endif
	esr_ti_testcfg_t test_cfg;
	nxge_status_t status = NXGE_OK;

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_n2_serdes_init port<%d>",
			portn));

	tx_cfg_l.value = 0;
	tx_cfg_h.value = 0;
	rx_cfg_l.value = 0;
	rx_cfg_h.value = 0;
	pll_cfg_l.value = 0;
	pll_sts_l.value = 0;
	test_cfg.value = 0;

	if ((nxgep->mac.portmode == PORT_10G_FIBER) ||
	    (nxgep->mac.portmode == PORT_10G_SERDES)) {
		/* 0x0E01 */
		tx_cfg_l.bits.entx = 1;
		tx_cfg_l.bits.swing = CFGTX_SWING_1375MV;

		/* 0x9101 */
		rx_cfg_l.bits.enrx = 1;
		rx_cfg_l.bits.term = CFGRX_TERM_0P8VDDT;
		rx_cfg_l.bits.align = CFGRX_ALIGN_EN;
		rx_cfg_l.bits.los = CFGRX_LOS_LOTHRES;

		/* 0x0008 */
		rx_cfg_h.bits.eq = CFGRX_EQ_ADAPTIVE_LP_ADAPTIVE_ZF;

		/* Set loopback mode if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes10g) {
			tx_cfg_l.bits.entest = 1;
			rx_cfg_l.bits.entest = 1;
			test_cfg.bits.loopback = TESTCFG_INNER_CML_DIS_LOOPBACK;
			if ((status = nxge_mdio_write(nxgep, portn,
				ESR_N2_DEV_ADDR,
				ESR_N2_TEST_CFG_REG, test_cfg.value))
				!= NXGE_OK)
			goto fail;
		}

		/* Use default PLL value */

	} else if ((nxgep->mac.portmode == PORT_1G_FIBER) ||
	    (nxgep->mac.portmode == PORT_1G_SERDES)) {

		/* 0x0E21 */
		tx_cfg_l.bits.entx = 1;
		tx_cfg_l.bits.rate = CFGTX_RATE_HALF;
		tx_cfg_l.bits.swing = CFGTX_SWING_1375MV;

		/* 0x9121 */
		rx_cfg_l.bits.enrx = 1;
		rx_cfg_l.bits.rate = CFGRX_RATE_HALF;
		rx_cfg_l.bits.term = CFGRX_TERM_0P8VDDT;
		rx_cfg_l.bits.align = CFGRX_ALIGN_EN;
		rx_cfg_l.bits.los = CFGRX_LOS_LOTHRES;

		if (portn == 0) {
			/* 0x8 */
			rx_cfg_h.bits.eq = CFGRX_EQ_ADAPTIVE_LP_ADAPTIVE_ZF;
		}

		/* MPY = 0x100 */
		pll_cfg_l.bits.mpy = CFGPLL_MPY_8X;

		/* Set PLL */
		pll_cfg_l.bits.enpll = 1;
		pll_sts_l.bits.enpll = 1;
		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
				ESR_N2_PLL_CFG_L_REG, pll_cfg_l.value))
				!= NXGE_OK)
			goto fail;

		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_PLL_STS_L_REG, pll_sts_l.value)) != NXGE_OK)
			goto fail;

#ifdef  NXGE_DEBUG
		nxge_mdio_read(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_PLL_CFG_L_REG, &cfg.value);
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: PLL cfg.l 0x%x (0x%x)",
		    portn, pll_cfg_l.value, cfg.value));

		nxge_mdio_read(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_PLL_STS_L_REG, &cfg.value);
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: PLL sts.l 0x%x (0x%x)",
		    portn, pll_sts_l.value, cfg.value));
#endif

		/* Set loopback mode if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes1000) {
			tx_cfg_l.bits.entest = 1;
			rx_cfg_l.bits.entest = 1;
			test_cfg.bits.loopback = TESTCFG_INNER_CML_DIS_LOOPBACK;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "==> nxge_n2_serdes_init port<%d>: loopback 0x%x",
			    portn, test_cfg.value));
			if ((status = nxge_mdio_write(nxgep, portn,
			    ESR_N2_DEV_ADDR,
			    ESR_N2_TEST_CFG_REG, test_cfg.value)) != NXGE_OK) {
				goto fail;
			}
		}
	} else {
		goto fail;
	}

	/*   MIF_REG_WR(handle, MIF_MASK_REG, ~mask); */

	NXGE_DELAY(20);

	/* init TX channels */
	for (chan = 0; chan < 4; chan++) {
		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
				ESR_N2_TX_CFG_L_REG_ADDR(chan), tx_cfg_l.value))
				!= NXGE_OK)
			goto fail;

		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
				ESR_N2_TX_CFG_H_REG_ADDR(chan), tx_cfg_h.value))
				!= NXGE_OK)
			goto fail;

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: chan %d tx_cfg_l 0x%x",
		    portn, chan, tx_cfg_l.value));
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: chan %d tx_cfg_h 0x%x",
		    portn, chan, tx_cfg_h.value));
	}

	/* init RX channels */
	for (chan = 0; chan < 4; chan++) {
		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
				ESR_N2_RX_CFG_L_REG_ADDR(chan), rx_cfg_l.value))
				!= NXGE_OK)
			goto fail;

		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
				ESR_N2_RX_CFG_H_REG_ADDR(chan), rx_cfg_h.value))
				!= NXGE_OK)
			goto fail;

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: chan %d rx_cfg_l 0x%x",
		    portn, chan, rx_cfg_l.value));
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_n2_serdes_init port<%d>: chan %d rx_cfg_h 0x%x",
		    portn, chan, rx_cfg_h.value));
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_n2_serdes_init port<%d>",
			portn));

	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	"nxge_n2_serdes_init: Failed to initialize N2 serdes for port<%d>",
				portn));

	return (status);
}

/* Initialize the Neptune Internal Serdes for 10G (Neptune only) */

static nxge_status_t
nxge_neptune_10G_serdes_init(p_nxge_t nxgep)
{
	npi_handle_t		handle;
	uint8_t			portn;
	int			chan;
	sr_rx_tx_ctrl_l_t	rx_tx_ctrl_l;
	sr_rx_tx_ctrl_h_t	rx_tx_ctrl_h;
	sr_glue_ctrl0_l_t	glue_ctrl0_l;
	sr_glue_ctrl0_h_t	glue_ctrl0_h;
	uint64_t		val;
	uint16_t		val16l;
	uint16_t		val16h;
	nxge_status_t		status = NXGE_OK;

	portn = nxgep->mac.portnum;

	if ((portn != 0) && (portn != 1))
		return (NXGE_OK);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_neptune_10G_serdes_init port<%d>", portn));

	handle = nxgep->npi_handle;
	switch (portn) {
	case 0:
		ESR_REG_WR(handle, ESR_0_CONTROL_REG,
		    ESR_CTL_EN_SYNCDET_0 | ESR_CTL_EN_SYNCDET_1 |
		    ESR_CTL_EN_SYNCDET_2 | ESR_CTL_EN_SYNCDET_3 |
		    (0x5 << ESR_CTL_OUT_EMPH_0_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_1_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_2_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_3_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_3_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_0_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_1_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_2_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_3_SHIFT));

		/* Set Serdes0 Internal Loopback if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes10g) {
			ESR_REG_WR(handle,
			    ESR_0_TEST_CONFIG_REG,
			    ESR_PAD_LOOPBACK_CH3 |
			    ESR_PAD_LOOPBACK_CH2 |
			    ESR_PAD_LOOPBACK_CH1 |
			    ESR_PAD_LOOPBACK_CH0);
		} else {
			ESR_REG_WR(handle, ESR_0_TEST_CONFIG_REG, 0);
		}
		break;
	case 1:
		ESR_REG_WR(handle, ESR_1_CONTROL_REG,
		    ESR_CTL_EN_SYNCDET_0 | ESR_CTL_EN_SYNCDET_1 |
		    ESR_CTL_EN_SYNCDET_2 | ESR_CTL_EN_SYNCDET_3 |
		    (0x5 << ESR_CTL_OUT_EMPH_0_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_1_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_2_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_3_SHIFT) |
		    (0x5 << ESR_CTL_OUT_EMPH_3_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_0_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_1_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_2_SHIFT) |
		    (0x1 << ESR_CTL_LOSADJ_3_SHIFT));

		/* Set Serdes1 Internal Loopback if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes10g) {
			ESR_REG_WR(handle, ESR_1_TEST_CONFIG_REG,
			    ESR_PAD_LOOPBACK_CH3 | ESR_PAD_LOOPBACK_CH2 |
			    ESR_PAD_LOOPBACK_CH1 | ESR_PAD_LOOPBACK_CH0);
		} else {
			ESR_REG_WR(handle, ESR_1_TEST_CONFIG_REG, 0);
		}
		break;
	default:
		/* Nothing to do here */
		goto done;
	}

	/* init TX RX channels */
	for (chan = 0; chan < 4; chan++) {
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_L_ADDR(chan),
		    &rx_tx_ctrl_l.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_H_ADDR(chan),
		    &rx_tx_ctrl_h.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_L_ADDR(chan),
		    &glue_ctrl0_l.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_H_ADDR(chan),
		    &glue_ctrl0_h.value)) != NXGE_OK)
			goto fail;
		rx_tx_ctrl_l.bits.enstretch = 1;
		rx_tx_ctrl_h.bits.vmuxlo = 2;
		rx_tx_ctrl_h.bits.vpulselo = 2;
		glue_ctrl0_l.bits.rxlosenable = 1;
		glue_ctrl0_l.bits.samplerate = 0xF;
		glue_ctrl0_l.bits.thresholdcount = 0xFF;
		glue_ctrl0_h.bits.bitlocktime = BITLOCKTIME_300_CYCLES;
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_L_ADDR(chan),
		    rx_tx_ctrl_l.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_H_ADDR(chan),
		    rx_tx_ctrl_h.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_L_ADDR(chan),
		    glue_ctrl0_l.value)) != NXGE_OK)
			goto fail;
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_H_ADDR(chan),
		    glue_ctrl0_h.value)) != NXGE_OK)
			goto fail;
		}

	/* Apply Tx core reset */
	if ((status = nxge_mdio_write(nxgep, portn,
	    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(),
	    (uint16_t)0)) != NXGE_OK)
		goto fail;

	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), (uint16_t)0xffff)) !=
	    NXGE_OK)
		goto fail;

	NXGE_DELAY(200);

	/* Apply Rx core reset */
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(), (uint16_t)0xffff)) !=
	    NXGE_OK)
		goto fail;

	NXGE_DELAY(200);
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), (uint16_t)0)) != NXGE_OK)
		goto fail;

	NXGE_DELAY(200);
	if ((status = nxge_mdio_read(nxgep, portn,
	    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(),
	    &val16l)) != NXGE_OK)
		goto fail;
	if ((status = nxge_mdio_read(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), &val16h)) != NXGE_OK)
		goto fail;
	if ((val16l != 0) || (val16h != 0)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "Failed to reset port<%d> XAUI Serdes", portn));
	}

	ESR_REG_RD(handle, ESR_INTERNAL_SIGNALS_REG, &val);

	if (portn == 0) {
		if ((val & ESR_SIG_P0_BITS_MASK) !=
				(ESR_SIG_SERDES_RDY0_P0 | ESR_SIG_DETECT0_P0 |
					ESR_SIG_XSERDES_RDY_P0 |
					ESR_SIG_XDETECT_P0_CH3 |
					ESR_SIG_XDETECT_P0_CH2 |
					ESR_SIG_XDETECT_P0_CH1 |
					ESR_SIG_XDETECT_P0_CH0)) {
			goto fail;
		}
	} else if (portn == 1) {
		if ((val & ESR_SIG_P1_BITS_MASK) !=
				(ESR_SIG_SERDES_RDY0_P1 | ESR_SIG_DETECT0_P1 |
					ESR_SIG_XSERDES_RDY_P1 |
					ESR_SIG_XDETECT_P1_CH3 |
					ESR_SIG_XDETECT_P1_CH2 |
					ESR_SIG_XDETECT_P1_CH1 |
					ESR_SIG_XDETECT_P1_CH0)) {
			goto fail;
		}
	}

done:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_neptune_10G_serdes_init port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_neptune_10G_serdes_init: "
	    "Failed to initialize Neptune serdes for port<%d>", portn));

	return (status);
}

/* Initialize Neptune Internal Serdes for 1G (Neptune only) */

static nxge_status_t
nxge_1G_serdes_init(p_nxge_t nxgep)
{
	npi_handle_t		handle;
	uint8_t			portn;
	uint64_t		val;

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_1G_serdes_init port<%d>", portn));

	handle = nxgep->npi_handle;

	ESR_REG_RD(handle, ESR_1_PLL_CONFIG_REG, &val);
	val &= ~ESR_PLL_CFG_FBDIV_2;
	switch (portn) {
	case 0:
		val |= ESR_PLL_CFG_HALF_RATE_0;
		break;
	case 1:
		val |= ESR_PLL_CFG_HALF_RATE_1;
		break;
	case 2:
		val |= ESR_PLL_CFG_HALF_RATE_2;
		break;
	case 3:
		val |= ESR_PLL_CFG_HALF_RATE_3;
		break;
	default:
		goto fail;
	}

	ESR_REG_WR(handle, ESR_1_PLL_CONFIG_REG, val);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_1G_serdes_init port<%d>", portn));
	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, TX_CTL,
	    "nxge_1G_serdes_init: "
	    "Failed to initialize Neptune serdes for port<%d>",
	    portn));

	return (NXGE_ERROR);
}

/* Initialize the 10G (BCM8704) Transceiver */

static nxge_status_t
nxge_10G_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_stats_t		statsp;
	uint16_t		val;
#ifdef	NXGE_DEBUG
	uint8_t			portn;
	uint16_t		val1;
#endif
	uint8_t			phy_port_addr;
	pmd_tx_control_t	tx_ctl;
	control_t		ctl;
	phyxs_control_t		phyxs_ctl;
	pcs_control_t		pcs_ctl;
	uint32_t		delay = 0;
	optics_dcntr_t		op_ctr;
	nxge_status_t		status = NXGE_OK;
#ifdef	NXGE_DEBUG
	portn = nxgep->mac.portnum;
#endif
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_10G_xcvr_init: port<%d>",
	    portn));

	statsp = nxgep->statsp;

	if (nxgep->mac.portmode == PORT_10G_SERDES) {
		goto done;
	}

	phy_port_addr = nxgep->statsp->mac_stats.xcvr_portn;

	/* Disable Link LEDs */
	if (nxge_10g_link_led_off(nxgep) != NXGE_OK)
		goto fail;

	/* Set Clause 45 */
	npi_mac_mif_set_indirect_mode(nxgep->npi_handle, B_TRUE);

	/* Reset the transceiver */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr, BCM8704_PHYXS_ADDR,
	    BCM8704_PHYXS_CONTROL_REG, &phyxs_ctl.value)) != NXGE_OK)
		goto fail;

	phyxs_ctl.bits.reset = 1;
	if ((status = nxge_mdio_write(nxgep, phy_port_addr, BCM8704_PHYXS_ADDR,
	    BCM8704_PHYXS_CONTROL_REG, phyxs_ctl.value)) != NXGE_OK)
		goto fail;

	do {
		drv_usecwait(500);
		if ((status = nxge_mdio_read(nxgep, phy_port_addr,
		    BCM8704_PHYXS_ADDR, BCM8704_PHYXS_CONTROL_REG,
		    &phyxs_ctl.value)) != NXGE_OK)
			goto fail;
		delay++;
	} while ((phyxs_ctl.bits.reset) && (delay < 100));
	if (delay == 100) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_xcvr_init: "
		    "failed to reset Transceiver on port<%d>", portn));
		status = NXGE_ERROR;
		goto fail;
	}

	/* Set to 0x7FBF */
	ctl.value = 0;
	ctl.bits.res1 = 0x3F;
	ctl.bits.optxon_lvl = 1;
	ctl.bits.oprxflt_lvl = 1;
	ctl.bits.optrxlos_lvl = 1;
	ctl.bits.optxflt_lvl = 1;
	ctl.bits.opprflt_lvl = 1;
	ctl.bits.obtmpflt_lvl = 1;
	ctl.bits.opbiasflt_lvl = 1;
	ctl.bits.optxrst_lvl = 1;
	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_CONTROL_REG, ctl.value))
	    != NXGE_OK)
		goto fail;

	/* Set to 0x164 */
	tx_ctl.value = 0;
	tx_ctl.bits.tsck_lpwren = 1;
	tx_ctl.bits.tx_dac_txck = 0x2;
	tx_ctl.bits.tx_dac_txd = 0x1;
	tx_ctl.bits.xfp_clken = 1;
	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_PMD_TX_CONTROL_REG,
	    tx_ctl.value)) != NXGE_OK)
		goto fail;
	/*
	 * According to Broadcom's instruction, SW needs to read
	 * back these registers twice after written.
	 */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_CONTROL_REG, &val))
	    != NXGE_OK)
		goto fail;

	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_CONTROL_REG, &val))
	    != NXGE_OK)
		goto fail;

	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_PMD_TX_CONTROL_REG, &val))
	    != NXGE_OK)
		goto fail;

	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_PMD_TX_CONTROL_REG, &val))
	    != NXGE_OK)
		goto fail;

	/* Enable Tx and Rx LEDs to be driven by traffic */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_OPTICS_DIGITAL_CTRL_REG,
	    &op_ctr.value)) != NXGE_OK)
		goto fail;
	op_ctr.bits.gpio_sel = 0x3;
	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_OPTICS_DIGITAL_CTRL_REG,
	    op_ctr.value)) != NXGE_OK)
		goto fail;

	NXGE_DELAY(1000000);

	/* Set BCM8704 Internal Loopback mode if necessary */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_PCS_DEV_ADDR, BCM8704_PCS_CONTROL_REG, &pcs_ctl.value))
	    != NXGE_OK)
		goto fail;
	if (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy10g)
		pcs_ctl.bits.loopback = 1;
	else
		pcs_ctl.bits.loopback = 0;
	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    BCM8704_PCS_DEV_ADDR, BCM8704_PCS_CONTROL_REG, pcs_ctl.value))
	    != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr, 0x1, 0xA, &val);
	if (status != NXGE_OK)
		goto fail;
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "BCM8704 port<%d> Dev 1 Reg 0xA = 0x%x\n", portn, val));
	status = nxge_mdio_read(nxgep, phy_port_addr, 0x3, 0x20, &val);
	if (status != NXGE_OK)
		goto fail;
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "BCM8704 port<%d> Dev 3 Reg 0x20 = 0x%x\n", portn, val));
	status = nxge_mdio_read(nxgep, phy_port_addr, 0x4, 0x18, &val);
	if (status != NXGE_OK)
		goto fail;
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "BCM8704 port<%d> Dev 4 Reg 0x18 = 0x%x\n", portn, val));

#ifdef	NXGE_DEBUG
	/* Diagnose link issue if link is not up */
	status = nxge_mdio_read(nxgep, phy_port_addr, BCM8704_USER_DEV3_ADDR,
	    BCM8704_USER_ANALOG_STATUS0_REG,
	    &val);
	if (status != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr,
				BCM8704_USER_DEV3_ADDR,
				BCM8704_USER_ANALOG_STATUS0_REG,
				&val);
	if (status != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr,
				BCM8704_USER_DEV3_ADDR,
				BCM8704_USER_TX_ALARM_STATUS_REG,
				&val1);
	if (status != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr,
				BCM8704_USER_DEV3_ADDR,
				BCM8704_USER_TX_ALARM_STATUS_REG,
				&val1);
	if (status != NXGE_OK)
		goto fail;

	if (val != 0x3FC) {
		if ((val == 0x43BC) && (val1 != 0)) {
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Cable not connected to peer or bad"
			    " cable on port<%d>\n", portn));
		} else if (val == 0x639C) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "Optical module (XFP) is bad or absent"
			    " on port<%d>\n", portn));
		}
	}
#endif

done:
	statsp->mac_stats.cap_10gfdx = 1;
	statsp->mac_stats.lp_cap_10gfdx = 1;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_10G_xcvr_init: port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_10G_xcvr_init: failed to initialize transceiver for "
	    "port<%d>", portn));
	return (status);
}

/* Initialize the 1G copper (BCM 5464) Transceiver */

static nxge_status_t
nxge_1G_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_param_t		param_arr = nxgep->param_arr;
	p_nxge_stats_t		statsp = nxgep->statsp;
	nxge_status_t		status = NXGE_OK;

	if (nxgep->mac.portmode == PORT_1G_SERDES) {
		statsp->mac_stats.cap_1000fdx =
		    param_arr[param_anar_1000fdx].value;
		goto done;
	}

	/* Set Clause 22 */
	npi_mac_mif_set_indirect_mode(nxgep->npi_handle, B_FALSE);

	/* Set capability flags */
	statsp->mac_stats.cap_1000fdx = param_arr[param_anar_1000fdx].value;
	if ((nxgep->mac.portmode == PORT_1G_COPPER) ||
	    (nxgep->mac.portmode == PORT_1G_FIBER)) {
		statsp->mac_stats.cap_100fdx =
		    param_arr[param_anar_100fdx].value;
		statsp->mac_stats.cap_10fdx =
		    param_arr[param_anar_10fdx].value;
	}

	status = nxge_mii_xcvr_init(nxgep);
done:
	return (status);
}

/* Initialize transceiver */

nxge_status_t
nxge_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_stats_t		statsp;
#ifdef	NXGE_DEBUG
	uint8_t			portn;
#endif

	nxge_status_t		status = NXGE_OK;
#ifdef	NXGE_DEBUG
	portn = nxgep->mac.portnum;
#endif
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_xcvr_init: port<%d>", portn));
	statsp = nxgep->statsp;

	/*
	 * Initialize the xcvr statistics.
	 */
	statsp->mac_stats.cap_autoneg = 0;
	statsp->mac_stats.cap_100T4 = 0;
	statsp->mac_stats.cap_100fdx = 0;
	statsp->mac_stats.cap_100hdx = 0;
	statsp->mac_stats.cap_10fdx = 0;
	statsp->mac_stats.cap_10hdx = 0;
	statsp->mac_stats.cap_asmpause = 0;
	statsp->mac_stats.cap_pause = 0;
	statsp->mac_stats.cap_1000fdx = 0;
	statsp->mac_stats.cap_1000hdx = 0;
	statsp->mac_stats.cap_10gfdx = 0;
	statsp->mac_stats.cap_10ghdx = 0;

	/*
	 * Initialize the link statistics.
	 */
	statsp->mac_stats.link_T4 = 0;
	statsp->mac_stats.link_asmpause = 0;
	statsp->mac_stats.link_pause = 0;

	if (nxgep->xcvr.xcvr_init) {
		status = nxgep->xcvr.xcvr_init(nxgep);
		if (status != NXGE_OK)
			goto fail;
		statsp->mac_stats.xcvr_inits++;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_xcvr_init: port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_xcvr_init: failed to initialize transceiver for port<%d>",
	    portn));
	return (status);
}

/* Look for transceiver type */

nxge_status_t
nxge_xcvr_find(p_nxge_t nxgep)
{
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_xcvr_find: port<%d>", nxgep->mac.portnum));

	if (nxge_get_xcvr_type(nxgep) != NXGE_OK)
		return (NXGE_ERROR);

	if (nxge_setup_xcvr_table(nxgep) != NXGE_OK)
		return (NXGE_ERROR);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_xcvr_find: xcvr_inuse = %d",
	    nxgep->statsp->mac_stats.xcvr_inuse));

	return (NXGE_OK);
}

/* Initialize the TxMAC sub-block */

nxge_status_t
nxge_tx_mac_init(p_nxge_t nxgep)
{
	npi_attr_t		ap;
	uint8_t			portn;
	nxge_port_mode_t	portmode;
	nxge_port_t		portt;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	portt    = nxgep->mac.porttype;
	handle   = nxgep->npi_handle;
	portmode = nxgep->mac.portmode;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_tx_mac_init: port<%d>",
			portn));

	/* Set Max and Min Frame Size */
	if (nxgep->param_arr[param_accept_jumbo].value || nxge_jumbo_enable) {
		SET_MAC_ATTR2(handle, ap, portn,
		    MAC_PORT_FRAME_SIZE, 64, 0x2400, rs);
	} else {
		SET_MAC_ATTR2(handle, ap, portn,
		    MAC_PORT_FRAME_SIZE, 64, 0x5EE + 4, rs);
	}

	if (rs != NPI_SUCCESS)
		goto fail;
	if (nxgep->param_arr[param_accept_jumbo].value ||
		nxgep->mac.is_jumbo == B_TRUE)
		nxgep->mac.maxframesize = 0x2400;
	else
		nxgep->mac.maxframesize = 0x5EE + 4;
	nxgep->mac.minframesize = 64;

	if (portt == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_tx_iconfig(handle, INIT, portn,
				0)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.tx_iconfig = NXGE_XMAC_TX_INTRS;
		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_COPPER) ||
		    (portmode == PORT_10G_SERDES)) {
			SET_MAC_ATTR1(handle, ap, portn, XMAC_10G_PORT_IPG,
					XGMII_IPG_12_15, rs);
			if (rs != NPI_SUCCESS)
				goto fail;
			nxgep->mac.ipg[0] = XGMII_IPG_12_15;
		} else {
			SET_MAC_ATTR1(handle, ap, portn, XMAC_PORT_IPG,
					MII_GMII_IPG_12, rs);
			if (rs != NPI_SUCCESS)
				goto fail;
			nxgep->mac.ipg[0] = MII_GMII_IPG_12;
		}
		if ((rs = npi_xmac_tx_config(handle, INIT, portn,
				CFG_XMAC_TX_CRC | CFG_XMAC_TX)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.tx_config = CFG_XMAC_TX_CRC | CFG_XMAC_TX;
		nxgep->mac.maxburstsize = 0;	/* not programmable */
		nxgep->mac.ctrltype = 0;	/* not programmable */
		nxgep->mac.pa_size = 0;		/* not programmable */

		if ((rs = npi_xmac_zap_tx_counters(handle, portn))
							!= NPI_SUCCESS)
			goto fail;

	} else {
		if ((rs = npi_bmac_tx_iconfig(handle, INIT, portn,
				0)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.tx_iconfig = NXGE_BMAC_TX_INTRS;

		SET_MAC_ATTR1(handle, ap, portn, BMAC_PORT_CTRL_TYPE, 0x8808,
				rs);
		if (rs != NPI_SUCCESS)
			goto fail;
		nxgep->mac.ctrltype = 0x8808;

		SET_MAC_ATTR1(handle, ap, portn, BMAC_PORT_PA_SIZE, 0x7, rs);
		if (rs != NPI_SUCCESS)
			goto fail;
		nxgep->mac.pa_size = 0x7;

		if ((rs = npi_bmac_tx_config(handle, INIT, portn,
				CFG_BMAC_TX_CRC | CFG_BMAC_TX)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.tx_config = CFG_BMAC_TX_CRC | CFG_BMAC_TX;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_tx_mac_init: port<%d>",
			portn));

	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"nxge_tx_mac_init: failed to initialize port<%d> TXMAC",
					portn));

	return (NXGE_ERROR | rs);
}

/* Initialize the RxMAC sub-block */

nxge_status_t
nxge_rx_mac_init(p_nxge_t nxgep)
{
	npi_attr_t		ap;
	uint32_t		i;
	uint16_t		hashtab_e;
	p_hash_filter_t		hash_filter;
	nxge_port_t		portt;
	uint8_t			portn;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;
	uint16_t 		*addr16p;
	uint16_t 		addr0, addr1, addr2;
	xmac_rx_config_t	xconfig;
	bmac_rx_config_t	bconfig;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_rx_mac_init: port<%d>\n",
			portn));
	handle = nxgep->npi_handle;
	portt = nxgep->mac.porttype;

	addr16p = (uint16_t *)nxgep->ouraddr.ether_addr_octet;
	addr0 = ntohs(addr16p[2]);
	addr1 = ntohs(addr16p[1]);
	addr2 = ntohs(addr16p[0]);
	SET_MAC_ATTR3(handle, ap, portn, MAC_PORT_ADDR, addr0, addr1, addr2,
		rs);

	if (rs != NPI_SUCCESS)
		goto fail;
	SET_MAC_ATTR3(handle, ap, portn, MAC_PORT_ADDR_FILTER, 0, 0, 0, rs);
	if (rs != NPI_SUCCESS)
		goto fail;
	SET_MAC_ATTR2(handle, ap, portn, MAC_PORT_ADDR_FILTER_MASK, 0, 0, rs);
	if (rs != NPI_SUCCESS)
		goto fail;

	/*
	 * Load the multicast hash filter bits.
	 */
	hash_filter = nxgep->hash_filter;
	for (i = 0; i < MAC_MAX_HASH_ENTRY; i++) {
		if (hash_filter != NULL) {
			hashtab_e = (uint16_t)hash_filter->hash_filter_regs[
				(NMCFILTER_REGS - 1) - i];
		} else {
			hashtab_e = 0;
		}

		if ((rs = npi_mac_hashtab_entry(handle, OP_SET, portn, i,
					(uint16_t *)&hashtab_e)) != NPI_SUCCESS)
			goto fail;
	}

	if (portt == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_rx_iconfig(handle, INIT, portn,
				0)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.rx_iconfig = NXGE_XMAC_RX_INTRS;

		(void) nxge_fflp_init_hostinfo(nxgep);

		xconfig = CFG_XMAC_RX_ERRCHK | CFG_XMAC_RX_CRC_CHK |
			CFG_XMAC_RX | CFG_XMAC_RX_CODE_VIO_CHK &
			~CFG_XMAC_RX_STRIP_CRC;

		if (nxgep->filter.all_phys_cnt != 0)
			xconfig |= CFG_XMAC_RX_PROMISCUOUS;

		if (nxgep->filter.all_multicast_cnt != 0)
			xconfig |= CFG_XMAC_RX_PROMISCUOUSGROUP;

		xconfig |= CFG_XMAC_RX_HASH_FILTER;

		if ((rs = npi_xmac_rx_config(handle, INIT, portn,
					xconfig)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.rx_config = xconfig;

		/* Comparison of mac unique address is always enabled on XMAC */

		if ((rs = npi_xmac_zap_rx_counters(handle, portn))
							!= NPI_SUCCESS)
			goto fail;
	} else {
		(void) nxge_fflp_init_hostinfo(nxgep);

		if (npi_bmac_rx_iconfig(nxgep->npi_handle, INIT, portn,
					0) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.rx_iconfig = NXGE_BMAC_RX_INTRS;

		bconfig = CFG_BMAC_RX_DISCARD_ON_ERR | CFG_BMAC_RX &
			~CFG_BMAC_RX_STRIP_CRC;

		if (nxgep->filter.all_phys_cnt != 0)
			bconfig |= CFG_BMAC_RX_PROMISCUOUS;

		if (nxgep->filter.all_multicast_cnt != 0)
			bconfig |= CFG_BMAC_RX_PROMISCUOUSGROUP;

		bconfig |= CFG_BMAC_RX_HASH_FILTER;
		if ((rs = npi_bmac_rx_config(handle, INIT, portn,
					bconfig)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.rx_config = bconfig;

		/* Always enable comparison of mac unique address */
		if ((rs = npi_mac_altaddr_enable(handle, portn, 0))
					!= NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_rx_mac_init: port<%d>\n",
			portn));

	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		"nxge_rx_mac_init: Failed to Initialize port<%d> RxMAC",
				portn));

	return (NXGE_ERROR | rs);
}

/* Enable TXMAC */

nxge_status_t
nxge_tx_mac_enable(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;

	handle = nxgep->npi_handle;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_tx_mac_enable: port<%d>",
			nxgep->mac.portnum));

	if ((status = nxge_tx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	/* based on speed */
	nxgep->msg_min = ETHERMIN;

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_tx_config(handle, ENABLE, nxgep->mac.portnum,
						CFG_XMAC_TX)) != NPI_SUCCESS)
			goto fail;
	} else {
		if ((rs = npi_bmac_tx_config(handle, ENABLE, nxgep->mac.portnum,
						CFG_BMAC_TX)) != NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_tx_mac_enable: port<%d>",
			nxgep->mac.portnum));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxgep_tx_mac_enable: Failed to enable port<%d> TxMAC",
			nxgep->mac.portnum));
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (status);
}

/* Disable TXMAC */

nxge_status_t
nxge_tx_mac_disable(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	npi_status_t	rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_tx_mac_disable: port<%d>",
			nxgep->mac.portnum));

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_tx_config(handle, DISABLE,
			nxgep->mac.portnum, CFG_XMAC_TX)) != NPI_SUCCESS)
			goto fail;
	} else {
		if ((rs = npi_bmac_tx_config(handle, DISABLE,
			nxgep->mac.portnum, CFG_BMAC_TX)) != NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_tx_mac_disable: port<%d>",
			nxgep->mac.portnum));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_tx_mac_disable: Failed to disable port<%d> TxMAC",
			nxgep->mac.portnum));
	return (NXGE_ERROR | rs);
}

/* Enable RXMAC */

nxge_status_t
nxge_rx_mac_enable(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	uint8_t 	portn;
	npi_status_t	rs = NPI_SUCCESS;
	nxge_status_t	status = NXGE_OK;

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_rx_mac_enable: port<%d>",
			portn));

	if ((status = nxge_rx_mac_init(nxgep)) != NXGE_OK)
		goto fail;

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_rx_config(handle, ENABLE, portn,
						CFG_XMAC_RX)) != NPI_SUCCESS)
			goto fail;
	} else {
		if ((rs = npi_bmac_rx_config(handle, ENABLE, portn,
						CFG_BMAC_RX)) != NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_rx_mac_enable: port<%d>",
			portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxgep_rx_mac_enable: Failed to enable port<%d> RxMAC",
			portn));

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (status);
}

/* Disable RXMAC */

nxge_status_t
nxge_rx_mac_disable(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	uint8_t		portn;
	npi_status_t	rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_rx_mac_disable: port<%d>",
			portn));

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_rx_config(handle, DISABLE, portn,
						CFG_XMAC_RX)) != NPI_SUCCESS)
			goto fail;
	} else {
		if ((rs = npi_bmac_rx_config(handle, DISABLE, portn,
						CFG_BMAC_RX)) != NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_rx_mac_disable: port<%d>",
			portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxgep_rx_mac_disable: ",
			"Failed to disable port<%d> RxMAC",
			portn));

	return (NXGE_ERROR | rs);
}

/* Reset TXMAC */

nxge_status_t
nxge_tx_mac_reset(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	uint8_t		portn;
	npi_status_t	rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_tx_mac_reset: port<%d>",
			portn));

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_reset(handle, portn, XTX_MAC_RESET_ALL))
		    != NPI_SUCCESS)
			goto fail;
	} else {
		if ((rs = npi_bmac_reset(handle, portn, TX_MAC_RESET))
					!= NPI_SUCCESS)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_tx_mac_reset: port<%d>",
			portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_tx_mac_reset: Failed to Reset TxMAC port<%d>",
			portn));

	return (NXGE_ERROR | rs);
}

/* Reset RXMAC */

nxge_status_t
nxge_rx_mac_reset(p_nxge_t nxgep)
{
	npi_handle_t	handle;
	uint8_t		portn;
	npi_status_t	rs = NPI_SUCCESS;

	handle = nxgep->npi_handle;
	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_rx_mac_reset: port<%d>",
			portn));

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_reset(handle, portn, XRX_MAC_RESET_ALL))
		    != NPI_SUCCESS)
		goto fail;
	} else {
		if ((rs = npi_bmac_reset(handle, portn, RX_MAC_RESET))
					!= NPI_SUCCESS)
		goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_rx_mac_reset: port<%d>",
			portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_rx_mac_reset: Failed to Reset RxMAC port<%d>",
			portn));
	return (NXGE_ERROR | rs);
}

/* 10G fiber link interrupt start routine */

static nxge_status_t
nxge_10G_link_intr_start(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_xmac_xpcs_link_intr_enable(nxgep->npi_handle, portn);

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* 10G fiber link interrupt stop routine */

static nxge_status_t
nxge_10G_link_intr_stop(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_xmac_xpcs_link_intr_disable(nxgep->npi_handle, portn);

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* 1G fiber link interrupt start routine */

static nxge_status_t
nxge_1G_fiber_link_intr_start(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_mac_pcs_link_intr_enable(nxgep->npi_handle, portn);
	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* 1G fiber link interrupt stop routine */

static nxge_status_t
nxge_1G_fiber_link_intr_stop(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_mac_pcs_link_intr_disable(nxgep->npi_handle, portn);

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* 1G copper link interrupt start routine */

static nxge_status_t
nxge_1G_copper_link_intr_start(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_mac_mif_link_intr_enable(nxgep->npi_handle, portn,
	    MII_BMSR, BMSR_LSTATUS);

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* 1G copper link interrupt stop routine */

static nxge_status_t
nxge_1G_copper_link_intr_stop(p_nxge_t nxgep)
{
	npi_status_t	rs = NPI_SUCCESS;
	uint8_t		portn = nxgep->mac.portnum;

	rs = npi_mac_mif_link_intr_disable(nxgep->npi_handle, portn);

	if (rs != NPI_SUCCESS)
		return (NXGE_ERROR | rs);
	else
		return (NXGE_OK);
}

/* Enable/Disable Link Status change interrupt */

nxge_status_t
nxge_link_intr(p_nxge_t nxgep, link_intr_enable_t enable)
{
	uint8_t		portn;
	nxge_status_t	status = NXGE_OK;

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_link_intr: port<%d>", portn));
	if (!nxgep->xcvr.link_intr_stop || !nxgep->xcvr.link_intr_start)
		return (NXGE_OK);

	if (enable == LINK_INTR_START)
		status = nxgep->xcvr.link_intr_start(nxgep);
	else if (enable == LINK_INTR_STOP)
		status = nxgep->xcvr.link_intr_stop(nxgep);
	if (status != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_intr: port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_link_intr: Failed to set port<%d> mif intr mode",
			portn));

	return (status);
}

/* Initialize 1G Fiber / Copper transceiver using Clause 22 */

nxge_status_t
nxge_mii_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_param_t	param_arr;
	p_nxge_stats_t	statsp;
	uint8_t		xcvr_portn;
	p_mii_regs_t	mii_regs;
	mii_bmcr_t	bmcr;
	mii_bmsr_t	bmsr;
	mii_anar_t	anar;
	mii_gcr_t	gcr;
	mii_esr_t	esr;
	mii_aux_ctl_t	bcm5464r_aux;
	int		status = NXGE_OK;

	uint_t delay;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mii_xcvr_init"));

	param_arr = nxgep->param_arr;
	statsp = nxgep->statsp;
	xcvr_portn = statsp->mac_stats.xcvr_portn;

	mii_regs = NULL;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		"nxge_param_autoneg = 0x%02x", param_arr[param_autoneg].value));

	/*
	 * Reset the transceiver.
	 */
	delay = 0;
	bmcr.value = 0;
	bmcr.bits.reset = 1;
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
		(uint8_t)(uint32_t)&mii_regs->bmcr, bmcr.value)) != NXGE_OK)
#else
		(uint8_t)(uint64_t)&mii_regs->bmcr, bmcr.value)) != NXGE_OK)
#endif
		goto fail;
	do {
		drv_usecwait(500);
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
			(uint8_t)(uint32_t)&mii_regs->bmcr, &bmcr.value))
#else
			(uint8_t)(uint64_t)&mii_regs->bmcr, &bmcr.value))
#endif
				!= NXGE_OK)
			goto fail;
		delay++;
	} while ((bmcr.bits.reset) && (delay < 1000));
	if (delay == 1000) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Xcvr reset failed."));
		goto fail;
	}

	if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
			(uint8_t)(uint32_t)(&mii_regs->bmsr),
#else
			(uint8_t)(uint64_t)(&mii_regs->bmsr),
#endif
			&bmsr.value)) != NXGE_OK)
		goto fail;

	param_arr[param_autoneg].value &= bmsr.bits.auto_neg_able;
	param_arr[param_anar_100T4].value &= bmsr.bits.link_100T4;
	param_arr[param_anar_100fdx].value &= bmsr.bits.link_100fdx;
	param_arr[param_anar_100hdx].value = 0;
	param_arr[param_anar_10fdx].value &= bmsr.bits.link_10fdx;
	param_arr[param_anar_10hdx].value = 0;

	/*
	 * Initialize the xcvr statistics.
	 */
	statsp->mac_stats.cap_autoneg = bmsr.bits.auto_neg_able;
	statsp->mac_stats.cap_100T4 = bmsr.bits.link_100T4;
	statsp->mac_stats.cap_100fdx = bmsr.bits.link_100fdx;
	statsp->mac_stats.cap_100hdx = 0;
	statsp->mac_stats.cap_10fdx = bmsr.bits.link_10fdx;
	statsp->mac_stats.cap_10hdx = 0;
	statsp->mac_stats.cap_asmpause = param_arr[param_anar_asmpause].value;
	statsp->mac_stats.cap_pause = param_arr[param_anar_pause].value;

	/*
	 * Initialise the xcvr advertised capability statistics.
	 */
	statsp->mac_stats.adv_cap_autoneg = param_arr[param_autoneg].value;
	statsp->mac_stats.adv_cap_1000fdx = param_arr[param_anar_1000fdx].value;
	statsp->mac_stats.adv_cap_1000hdx = param_arr[param_anar_1000hdx].value;
	statsp->mac_stats.adv_cap_100T4 = param_arr[param_anar_100T4].value;
	statsp->mac_stats.adv_cap_100fdx = param_arr[param_anar_100fdx].value;
	statsp->mac_stats.adv_cap_100hdx = param_arr[param_anar_100hdx].value;
	statsp->mac_stats.adv_cap_10fdx = param_arr[param_anar_10fdx].value;
	statsp->mac_stats.adv_cap_10hdx = param_arr[param_anar_10hdx].value;
	statsp->mac_stats.adv_cap_asmpause =
					param_arr[param_anar_asmpause].value;
	statsp->mac_stats.adv_cap_pause = param_arr[param_anar_pause].value;


	/*
	 * Check for extended status just in case we're
	 * running a Gigibit phy.
	 */
	if (bmsr.bits.extend_status) {
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
			(uint8_t)(uint32_t)(&mii_regs->esr), &esr.value))
#else
			(uint8_t)(uint64_t)(&mii_regs->esr), &esr.value))
#endif
				!= NXGE_OK)
			goto fail;
		param_arr[param_anar_1000fdx].value &=
					esr.bits.link_1000fdx;
		param_arr[param_anar_1000hdx].value = 0;

		statsp->mac_stats.cap_1000fdx =
			(esr.bits.link_1000Xfdx ||
				esr.bits.link_1000fdx);
		statsp->mac_stats.cap_1000hdx = 0;
	} else {
		param_arr[param_anar_1000fdx].value = 0;
		param_arr[param_anar_1000hdx].value = 0;
	}

	/*
	 * Initialize 1G Statistics once the capability is established.
	 */
	statsp->mac_stats.adv_cap_1000fdx = param_arr[param_anar_1000fdx].value;
	statsp->mac_stats.adv_cap_1000hdx = param_arr[param_anar_1000hdx].value;

	/*
	 * Initialise the link statistics.
	 */
	statsp->mac_stats.link_T4 = 0;
	statsp->mac_stats.link_asmpause = 0;
	statsp->mac_stats.link_pause = 0;
	statsp->mac_stats.link_speed = 0;
	statsp->mac_stats.link_duplex = 0;
	statsp->mac_stats.link_up = 0;

	/*
	 * Switch off Auto-negotiation, 100M and full duplex.
	 */
	bmcr.value = 0;
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
		(uint8_t)(uint32_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
#else
		(uint8_t)(uint64_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
#endif
		goto fail;

	if ((statsp->port_stats.lb_mode == nxge_lb_phy) ||
			(statsp->port_stats.lb_mode == nxge_lb_phy1000)) {
		bmcr.bits.loopback = 1;
		bmcr.bits.enable_autoneg = 0;
		if (statsp->port_stats.lb_mode == nxge_lb_phy1000)
			bmcr.bits.speed_1000_sel = 1;
		bmcr.bits.duplex_mode = 1;
		param_arr[param_autoneg].value = 0;
	} else {
		bmcr.bits.loopback = 0;
	}

	if ((statsp->port_stats.lb_mode == nxge_lb_ext1000) ||
		(statsp->port_stats.lb_mode == nxge_lb_ext100) ||
		(statsp->port_stats.lb_mode == nxge_lb_ext10)) {
		param_arr[param_autoneg].value = 0;
		bcm5464r_aux.value = 0;
		bcm5464r_aux.bits.ext_lb = 1;
		bcm5464r_aux.bits.write_1 = 1;
		if ((status = nxge_mii_write(nxgep, xcvr_portn,
				BCM5464R_AUX_CTL, bcm5464r_aux.value))
				!= NXGE_OK)
			goto fail;
	}

	if (param_arr[param_autoneg].value) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				"Restarting Auto-negotiation."));
		/*
		 * Setup our Auto-negotiation advertisement register.
		 */
		anar.value = 0;
		anar.bits.selector = 1;
		anar.bits.cap_100T4 = param_arr[param_anar_100T4].value;
		anar.bits.cap_100fdx = param_arr[param_anar_100fdx].value;
		anar.bits.cap_100hdx = param_arr[param_anar_100hdx].value;
		anar.bits.cap_10fdx = param_arr[param_anar_10fdx].value;
		anar.bits.cap_10hdx = param_arr[param_anar_10hdx].value;
		anar.bits.cap_asmpause = 0;
		anar.bits.cap_pause = 0;
		if (param_arr[param_anar_1000fdx].value ||
			param_arr[param_anar_100fdx].value ||
			param_arr[param_anar_10fdx].value) {
			anar.bits.cap_asmpause = statsp->mac_stats.cap_asmpause;
			anar.bits.cap_pause = statsp->mac_stats.cap_pause;
		}

		if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
			(uint8_t)(uint32_t)(&mii_regs->anar), anar.value))
#else
			(uint8_t)(uint64_t)(&mii_regs->anar), anar.value))
#endif
				!= NXGE_OK)
			goto fail;
		if (bmsr.bits.extend_status) {
			gcr.value = 0;
			gcr.bits.ms_mode_en =
				param_arr[param_master_cfg_enable].value;
			gcr.bits.master =
				param_arr[param_master_cfg_value].value;
			gcr.bits.link_1000fdx =
				param_arr[param_anar_1000fdx].value;
			gcr.bits.link_1000hdx =
				param_arr[param_anar_1000hdx].value;
			if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->gcr), gcr.value))
#else
				(uint8_t)(uint64_t)(&mii_regs->gcr), gcr.value))
#endif
				!= NXGE_OK)
				goto fail;
		}

		bmcr.bits.enable_autoneg = 1;
		bmcr.bits.restart_autoneg = 1;

	} else {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Going into forced mode."));
		bmcr.bits.speed_1000_sel =
			param_arr[param_anar_1000fdx].value |
				param_arr[param_anar_1000hdx].value;
		bmcr.bits.speed_sel = (~bmcr.bits.speed_1000_sel) &
			(param_arr[param_anar_100fdx].value |
				param_arr[param_anar_100hdx].value);
		if (bmcr.bits.speed_1000_sel) {
			statsp->mac_stats.link_speed = 1000;
			gcr.value = 0;
			gcr.bits.ms_mode_en =
				param_arr[param_master_cfg_enable].value;
			gcr.bits.master =
				param_arr[param_master_cfg_value].value;
			if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->gcr),
#else
				(uint8_t)(uint64_t)(&mii_regs->gcr),
#endif
				gcr.value))
				!= NXGE_OK)
				goto fail;
			if (param_arr[param_anar_1000fdx].value) {
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_duplex = 2;
			} else
				statsp->mac_stats.link_duplex = 1;
		} else if (bmcr.bits.speed_sel) {
			statsp->mac_stats.link_speed = 100;
			if (param_arr[param_anar_100fdx].value) {
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_duplex = 2;
			} else
				statsp->mac_stats.link_duplex = 1;
		} else {
			statsp->mac_stats.link_speed = 10;
			if (param_arr[param_anar_10fdx].value) {
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_duplex = 2;
			} else
				statsp->mac_stats.link_duplex = 1;
		}
		if (statsp->mac_stats.link_duplex != 1) {
			statsp->mac_stats.link_asmpause =
						statsp->mac_stats.cap_asmpause;
			statsp->mac_stats.link_pause =
						statsp->mac_stats.cap_pause;
		}

		if ((statsp->port_stats.lb_mode == nxge_lb_ext1000) ||
			(statsp->port_stats.lb_mode == nxge_lb_ext100) ||
			(statsp->port_stats.lb_mode == nxge_lb_ext10)) {
			if (statsp->port_stats.lb_mode == nxge_lb_ext1000) {
				/* BCM5464R 1000mbps external loopback mode */
				gcr.value = 0;
				gcr.bits.ms_mode_en = 1;
				gcr.bits.master = 1;
				if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
					(uint8_t)(uint32_t)(&mii_regs->gcr),
#else
					(uint8_t)(uint64_t)(&mii_regs->gcr),
#endif
					gcr.value))
					!= NXGE_OK)
					goto fail;
				bmcr.value = 0;
				bmcr.bits.speed_1000_sel = 1;
				statsp->mac_stats.link_speed = 1000;
			} else if (statsp->port_stats.lb_mode
			    == nxge_lb_ext100) {
				/* BCM5464R 100mbps external loopback mode */
				bmcr.value = 0;
				bmcr.bits.speed_sel = 1;
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_speed = 100;
			} else if (statsp->port_stats.lb_mode
			    == nxge_lb_ext10) {
				/* BCM5464R 10mbps external loopback mode */
				bmcr.value = 0;
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_speed = 10;
			}
		}
	}

	if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
			(uint8_t)(uint32_t)(&mii_regs->bmcr),
#else
			(uint8_t)(uint64_t)(&mii_regs->bmcr),
#endif
			bmcr.value)) != NXGE_OK)
		goto fail;

	if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
		(uint8_t)(uint32_t)(&mii_regs->bmcr), &bmcr.value)) != NXGE_OK)
#else
		(uint8_t)(uint64_t)(&mii_regs->bmcr), &bmcr.value)) != NXGE_OK)
#endif
		goto fail;
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "bmcr = 0x%04X", bmcr.value));

	/*
	 * Initialize the xcvr status kept in the context structure.
	 */
	nxgep->soft_bmsr.value = 0;

	if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
		(uint8_t)(uint32_t)(&mii_regs->bmsr),
#else
		(uint8_t)(uint64_t)(&mii_regs->bmsr),
#endif
			&nxgep->bmsr.value)) != NXGE_OK)
		goto fail;

	statsp->mac_stats.xcvr_inits++;
	nxgep->bmsr.value = 0;

fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			"<== nxge_mii_xcvr_init status 0x%x", status));
	return (status);
}

/* Read from a MII compliant register */

nxge_status_t
nxge_mii_read(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t xcvr_reg,
		uint16_t *value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mii_read: xcvr_port<%d>"
			"xcvr_reg<%d>", xcvr_portn, xcvr_reg));

	MUTEX_ENTER(&nxge_mii_lock);

	if (nxgep->mac.portmode == PORT_1G_COPPER) {
		if ((rs = npi_mac_mif_mii_read(nxgep->npi_handle,
				xcvr_portn, xcvr_reg, value)) != NPI_SUCCESS)
			goto fail;
	} else if ((nxgep->mac.portmode == PORT_1G_FIBER) ||
	    (nxgep->mac.portmode == PORT_1G_SERDES)) {
		if ((rs = npi_mac_pcs_mii_read(nxgep->npi_handle,
				xcvr_portn, xcvr_reg, value)) != NPI_SUCCESS)
			goto fail;
	} else
		goto fail;

	MUTEX_EXIT(&nxge_mii_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mii_read: xcvr_port<%d>"
			"xcvr_reg<%d> value=0x%x",
			xcvr_portn, xcvr_reg, *value));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxge_mii_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_mii_read: Failed to read mii on xcvr %d",
			xcvr_portn));

	return (NXGE_ERROR | rs);
}

/* Write to a MII compliant Register */

nxge_status_t
nxge_mii_write(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t xcvr_reg,
		uint16_t value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mii_write: xcvr_port<%d>"
			"xcvr_reg<%d> value=0x%x", xcvr_portn, xcvr_reg,
			value));

	MUTEX_ENTER(&nxge_mii_lock);

	if (nxgep->mac.portmode == PORT_1G_COPPER) {
		if ((rs = npi_mac_mif_mii_write(nxgep->npi_handle,
				xcvr_portn, xcvr_reg, value)) != NPI_SUCCESS)
			goto fail;
	} else if ((nxgep->mac.portmode == PORT_1G_FIBER) ||
	    (nxgep->mac.portmode == PORT_1G_SERDES)) {
		if ((rs = npi_mac_pcs_mii_write(nxgep->npi_handle,
				xcvr_portn, xcvr_reg, value)) != NPI_SUCCESS)
			goto fail;
	} else
		goto fail;

	MUTEX_EXIT(&nxge_mii_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mii_write: xcvr_port<%d>"
			"xcvr_reg<%d>", xcvr_portn, xcvr_reg));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxge_mii_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_mii_write: Failed to write mii on xcvr %d",
			xcvr_portn));

	return (NXGE_ERROR | rs);
}

/* Perform read from Clause45 serdes / transceiver device */

nxge_status_t
nxge_mdio_read(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t device,
		uint16_t xcvr_reg, uint16_t *value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mdio_read: xcvr_port<%d>",
			xcvr_portn));

	MUTEX_ENTER(&nxge_mdio_lock);

	if ((rs = npi_mac_mif_mdio_read(nxgep->npi_handle,
			xcvr_portn, device, xcvr_reg, value)) != NPI_SUCCESS)
		goto fail;

	MUTEX_EXIT(&nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mdio_read: xcvr_port<%d>",
			xcvr_portn));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxge_mdio_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_mdio_read: Failed to read mdio on xcvr %d",
			xcvr_portn));

	return (NXGE_ERROR | rs);
}

/* Perform write to Clause45 serdes / transceiver device */

nxge_status_t
nxge_mdio_write(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t device,
		uint16_t xcvr_reg, uint16_t value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mdio_write: xcvr_port<%d>",
			xcvr_portn));

	MUTEX_ENTER(&nxge_mdio_lock);

	if ((rs = npi_mac_mif_mdio_write(nxgep->npi_handle,
			xcvr_portn, device, xcvr_reg, value)) != NPI_SUCCESS)
		goto fail;

	MUTEX_EXIT(&nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mdio_write: xcvr_port<%d>",
			xcvr_portn));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxge_mdio_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_mdio_write: Failed to write mdio on xcvr %d",
			xcvr_portn));

	return (NXGE_ERROR | rs);
}


/* Check MII to see if there is any link status change */

nxge_status_t
nxge_mii_check(p_nxge_t nxgep, mii_bmsr_t bmsr, mii_bmsr_t bmsr_ints,
		nxge_link_state_t *link_up)
{
	p_nxge_param_t	param_arr;
	p_nxge_stats_t	statsp;
	p_mii_regs_t	mii_regs;
	p_mii_bmsr_t	soft_bmsr;
	mii_anar_t	anar;
	mii_anlpar_t	anlpar;
	mii_anar_t	an_common;
	mii_aner_t	aner;
	mii_gsr_t	gsr;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mii_check"));

	mii_regs = NULL;
	param_arr = nxgep->param_arr;
	statsp = nxgep->statsp;
	soft_bmsr = &nxgep->soft_bmsr;
	*link_up = LINK_NO_CHANGE;

	if (bmsr_ints.bits.link_status) {
		if (bmsr.bits.link_status) {
			soft_bmsr->bits.link_status = 1;
		} else {
			statsp->mac_stats.link_up = 0;
			soft_bmsr->bits.link_status = 0;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					"Link down cable problem"));
			*link_up = LINK_IS_DOWN;
		}
	}

	if (param_arr[param_autoneg].value) {
		if (bmsr_ints.bits.auto_neg_complete) {
			if (bmsr.bits.auto_neg_complete)
				soft_bmsr->bits.auto_neg_complete = 1;
			else
				soft_bmsr->bits.auto_neg_complete = 0;
		}
		if (soft_bmsr->bits.link_status == 0) {
			statsp->mac_stats.link_T4 = 0;
			statsp->mac_stats.link_speed = 0;
			statsp->mac_stats.link_duplex = 0;
			statsp->mac_stats.link_asmpause = 0;
			statsp->mac_stats.link_pause = 0;
			statsp->mac_stats.lp_cap_autoneg = 0;
			statsp->mac_stats.lp_cap_100T4 = 0;
			statsp->mac_stats.lp_cap_1000fdx = 0;
			statsp->mac_stats.lp_cap_1000hdx = 0;
			statsp->mac_stats.lp_cap_100fdx = 0;
			statsp->mac_stats.lp_cap_100hdx = 0;
			statsp->mac_stats.lp_cap_10fdx = 0;
			statsp->mac_stats.lp_cap_10hdx = 0;
			statsp->mac_stats.lp_cap_10gfdx = 0;
			statsp->mac_stats.lp_cap_10ghdx = 0;
			statsp->mac_stats.lp_cap_asmpause = 0;
			statsp->mac_stats.lp_cap_pause = 0;
		}
	} else
		soft_bmsr->bits.auto_neg_complete = 1;

	if ((bmsr_ints.bits.link_status ||
		bmsr_ints.bits.auto_neg_complete) &&
		soft_bmsr->bits.link_status &&
		soft_bmsr->bits.auto_neg_complete) {
		statsp->mac_stats.link_up = 1;
		if (param_arr[param_autoneg].value) {
			if ((status = nxge_mii_read(nxgep,
				statsp->mac_stats.xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->anar),
#else
				(uint8_t)(uint64_t)(&mii_regs->anar),
#endif
					&anar.value)) != NXGE_OK)
				goto fail;
			if ((status = nxge_mii_read(nxgep,
				statsp->mac_stats.xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->anlpar),
#else
				(uint8_t)(uint64_t)(&mii_regs->anlpar),
#endif
					&anlpar.value)) != NXGE_OK)
				goto fail;
			if ((status = nxge_mii_read(nxgep,
				statsp->mac_stats.xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->aner),
#else
				(uint8_t)(uint64_t)(&mii_regs->aner),
#endif
					&aner.value)) != NXGE_OK)
				goto fail;
			statsp->mac_stats.lp_cap_autoneg = aner.bits.lp_an_able;
			statsp->mac_stats.lp_cap_100T4 = anlpar.bits.cap_100T4;
			statsp->mac_stats.lp_cap_100fdx =
							anlpar.bits.cap_100fdx;
			statsp->mac_stats.lp_cap_100hdx =
							anlpar.bits.cap_100hdx;
			statsp->mac_stats.lp_cap_10fdx = anlpar.bits.cap_10fdx;
			statsp->mac_stats.lp_cap_10hdx = anlpar.bits.cap_10hdx;
			statsp->mac_stats.lp_cap_asmpause =
						anlpar.bits.cap_asmpause;
			statsp->mac_stats.lp_cap_pause = anlpar.bits.cap_pause;
			an_common.value = anar.value & anlpar.value;
			if (param_arr[param_anar_1000fdx].value ||
				param_arr[param_anar_1000hdx].value) {
				if ((status = nxge_mii_read(nxgep,
					statsp->mac_stats.xcvr_portn,
#if defined(__i386)
					(uint8_t)(uint32_t)(&mii_regs->gsr),
#else
					(uint8_t)(uint64_t)(&mii_regs->gsr),
#endif
						&gsr.value))
						!= NXGE_OK)
					goto fail;
				statsp->mac_stats.lp_cap_1000fdx =
					gsr.bits.link_1000fdx;
				statsp->mac_stats.lp_cap_1000hdx =
					gsr.bits.link_1000hdx;
				if (param_arr[param_anar_1000fdx].value &&
					gsr.bits.link_1000fdx) {
					statsp->mac_stats.link_speed = 1000;
					statsp->mac_stats.link_duplex = 2;
				} else if (
					param_arr[param_anar_1000hdx].value &&
						gsr.bits.link_1000hdx) {
					statsp->mac_stats.link_speed = 1000;
					statsp->mac_stats.link_duplex = 1;
				}
			}
			if ((an_common.value != 0) &&
					!(statsp->mac_stats.link_speed)) {
				if (an_common.bits.cap_100T4) {
					statsp->mac_stats.link_T4 = 1;
					statsp->mac_stats.link_speed = 100;
					statsp->mac_stats.link_duplex = 1;
				} else if (an_common.bits.cap_100fdx) {
					statsp->mac_stats.link_speed = 100;
					statsp->mac_stats.link_duplex = 2;
				} else if (an_common.bits.cap_100hdx) {
					statsp->mac_stats.link_speed = 100;
					statsp->mac_stats.link_duplex = 1;
				} else if (an_common.bits.cap_10fdx) {
					statsp->mac_stats.link_speed = 10;
					statsp->mac_stats.link_duplex = 2;
				} else if (an_common.bits.cap_10hdx) {
					statsp->mac_stats.link_speed = 10;
					statsp->mac_stats.link_duplex = 1;
				} else {
					goto fail;
				}
			}
			if (statsp->mac_stats.link_duplex != 1) {
				statsp->mac_stats.link_asmpause =
					an_common.bits.cap_asmpause;
				if (statsp->mac_stats.link_asmpause)
				if ((statsp->mac_stats.cap_pause == 0) &&
						(statsp->mac_stats.lp_cap_pause
						== 1))
						statsp->mac_stats.link_pause
						= 0;
					else
						statsp->mac_stats.link_pause
						= 1;
				else
					statsp->mac_stats.link_pause =
						an_common.bits.cap_pause;
			}
		}
		*link_up = LINK_IS_UP;
	}

	if (nxgep->link_notify) {
		*link_up = ((statsp->mac_stats.link_up) ? LINK_IS_UP :
				LINK_IS_DOWN);
		nxgep->link_notify = B_FALSE;
	}
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_mii_check"));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_mii_check: Unable to check MII"));
	return (status);
}

/* Check PCS to see if there is any link status change */
nxge_status_t
nxge_pcs_check(p_nxge_t nxgep, uint8_t portn, nxge_link_state_t *link_up)
{
	p_nxge_stats_t	statsp;
	nxge_status_t	status = NXGE_OK;
	boolean_t	linkup;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_pcs_check"));

	statsp = nxgep->statsp;
	*link_up = LINK_NO_CHANGE;

	(void) npi_mac_get_link_status(nxgep->npi_handle, portn, &linkup);
	if (linkup) {
		if (nxgep->link_notify ||
		    nxgep->statsp->mac_stats.link_up == 0) {
			statsp->mac_stats.link_up = 1;
			statsp->mac_stats.link_speed = 1000;
			statsp->mac_stats.link_duplex = 2;
			*link_up = LINK_IS_UP;
			nxgep->link_notify = B_FALSE;
		}
	} else {
		if (nxgep->link_notify ||
		    nxgep->statsp->mac_stats.link_up == 1) {
			statsp->mac_stats.link_up = 0;
			statsp->mac_stats.link_speed = 0;
			statsp->mac_stats.link_duplex = 0;
			*link_up = LINK_IS_DOWN;
			nxgep->link_notify = B_FALSE;
		}
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_pcs_check"));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_pcs_check: Unable to check PCS"));
	return (status);
}

/* Add a multicast address entry into the HW hash table */

nxge_status_t
nxge_add_mcast_addr(p_nxge_t nxgep, struct ether_addr *addrp)
{
	uint32_t mchash;
	p_hash_filter_t hash_filter;
	uint16_t hash_bit;
	boolean_t rx_init = B_FALSE;
	uint_t j;
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_add_mcast_addr"));

	RW_ENTER_WRITER(&nxgep->filter_lock);
	mchash = crc32_mchash(addrp);
	if (nxgep->hash_filter == NULL) {
		NXGE_DEBUG_MSG((NULL, STR_CTL,
			"Allocating hash filter storage."));
		nxgep->hash_filter = KMEM_ZALLOC(sizeof (hash_filter_t),
					KM_SLEEP);
	}
	hash_filter = nxgep->hash_filter;
	j = mchash / HASH_REG_WIDTH;
	hash_bit = (1 << (mchash % HASH_REG_WIDTH));
	hash_filter->hash_filter_regs[j] |= hash_bit;
	hash_filter->hash_bit_ref_cnt[mchash]++;
	if (hash_filter->hash_bit_ref_cnt[mchash] == 1) {
		hash_filter->hash_ref_cnt++;
		rx_init = B_TRUE;
	}
	if (rx_init) {
		if ((status = nxge_rx_mac_disable(nxgep)) != NXGE_OK)
			goto fail;
		if ((status = nxge_rx_mac_enable(nxgep)) != NXGE_OK)
			goto fail;
	}

	RW_EXIT(&nxgep->filter_lock);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_add_mcast_addr"));

	return (NXGE_OK);
fail:
	RW_EXIT(&nxgep->filter_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_add_mcast_addr: "
					"Unable to add multicast address"));
	return (status);
}

/* Remove a multicast address entry from the HW hash table */

nxge_status_t
nxge_del_mcast_addr(p_nxge_t nxgep, struct ether_addr *addrp)
{
	uint32_t mchash;
	p_hash_filter_t hash_filter;
	uint16_t hash_bit;
	boolean_t rx_init = B_FALSE;
	uint_t j;
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_del_mcast_addr"));
	RW_ENTER_WRITER(&nxgep->filter_lock);
	mchash = crc32_mchash(addrp);
	if (nxgep->hash_filter == NULL) {
		NXGE_DEBUG_MSG((NULL, STR_CTL,
			"Hash filter already de_allocated."));
		RW_EXIT(&nxgep->filter_lock);
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_del_mcast_addr"));
		return (NXGE_OK);
	}
	hash_filter = nxgep->hash_filter;
	hash_filter->hash_bit_ref_cnt[mchash]--;
	if (hash_filter->hash_bit_ref_cnt[mchash] == 0) {
		j = mchash / HASH_REG_WIDTH;
		hash_bit = (1 << (mchash % HASH_REG_WIDTH));
		hash_filter->hash_filter_regs[j] &= ~hash_bit;
		hash_filter->hash_ref_cnt--;
		rx_init = B_TRUE;
	}
	if (hash_filter->hash_ref_cnt == 0) {
		NXGE_DEBUG_MSG((NULL, STR_CTL,
			"De-allocating hash filter storage."));
		KMEM_FREE(hash_filter, sizeof (hash_filter_t));
		nxgep->hash_filter = NULL;
	}

	if (rx_init) {
		if ((status = nxge_rx_mac_disable(nxgep)) != NXGE_OK)
			goto fail;
		if ((status = nxge_rx_mac_enable(nxgep)) != NXGE_OK)
			goto fail;
	}
	RW_EXIT(&nxgep->filter_lock);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_del_mcast_addr"));

	return (NXGE_OK);
fail:
	RW_EXIT(&nxgep->filter_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_del_mcast_addr: "
			"Unable to remove multicast address"));

	return (status);
}

/* Set MAC address into MAC address HW registers */

nxge_status_t
nxge_set_mac_addr(p_nxge_t nxgep, struct ether_addr *addrp)
{
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_set_mac_addr"));

	MUTEX_ENTER(&nxgep->ouraddr_lock);
	/*
	 * Exit if the address is same as ouraddr or multicast or broadcast
	 */
	if (((addrp->ether_addr_octet[0] & 01) == 1) ||
		(ether_cmp(addrp, &etherbroadcastaddr) == 0) ||
		(ether_cmp(addrp, &nxgep->ouraddr) == 0)) {
		goto nxge_set_mac_addr_exit;
	}
	nxgep->ouraddr = *addrp;
	/*
	 * Set new interface local address and re-init device.
	 * This is destructive to any other streams attached
	 * to this device.
	 */
	RW_ENTER_WRITER(&nxgep->filter_lock);
	if ((status = nxge_rx_mac_disable(nxgep)) != NXGE_OK)
		goto fail;
	if ((status = nxge_rx_mac_enable(nxgep)) != NXGE_OK)
		goto fail;

	RW_EXIT(&nxgep->filter_lock);
	MUTEX_EXIT(&nxgep->ouraddr_lock);
	goto nxge_set_mac_addr_end;
nxge_set_mac_addr_exit:
	MUTEX_EXIT(&nxgep->ouraddr_lock);
nxge_set_mac_addr_end:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_set_mac_addr"));

	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxgep->ouraddr_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_set_mac_addr: "
			"Unable to set mac address"));
	return (status);
}

static
check_link_state_t
nxge_check_link_stop(
	nxge_t *nxge)
{
	/* If the poll has been cancelled, return STOP. */
	MUTEX_ENTER(&nxge->poll_lock);
	if (nxge->suspended || nxge->poll_state == LINK_MONITOR_STOPPING) {
		nxge->poll_state = LINK_MONITOR_STOP;
		nxge->nxge_link_poll_timerid = 0;
		cv_broadcast(&nxge->poll_cv);
		MUTEX_EXIT(&nxge->poll_lock);

		NXGE_DEBUG_MSG((nxge, MAC_CTL,
		    "nxge_check_%s_link(port<%d>) stopped.",
		    nxge->mac.portmode == PORT_10G_FIBER ? "10g" : "mii",
		    nxge->mac.portnum));
		return (CHECK_LINK_STOP);
	}
	MUTEX_EXIT(&nxge->poll_lock);

	return (CHECK_LINK_RESCHEDULE);
}

/* Check status of MII (MIF or PCS) link */

static nxge_status_t
nxge_check_mii_link(p_nxge_t nxgep)
{
	mii_bmsr_t bmsr_ints, bmsr_data;
	mii_anlpar_t anlpar;
	mii_gsr_t gsr;
	p_mii_regs_t mii_regs;
	nxge_status_t status = NXGE_OK;
	uint8_t portn;
	nxge_link_state_t link_up;

	if (nxgep->nxge_magic != NXGE_MAGIC)
		return (NXGE_ERROR);

	if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP)
		return (NXGE_OK);

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_check_mii_link port<%d>",
	    portn));

	mii_regs = NULL;

	RW_ENTER_WRITER(&nxgep->filter_lock);

	if (nxgep->statsp->port_stats.lb_mode > nxge_lb_ext10)
		goto nxge_check_mii_link_exit;

	switch (nxgep->mac.portmode) {
	default:
		if ((status = nxge_mii_read(nxgep,
		    nxgep->statsp->mac_stats.xcvr_portn,
#if defined(__i386)
		    (uint8_t)(uint32_t)(&mii_regs->bmsr),
#else
		    (uint8_t)(uint64_t)(&mii_regs->bmsr),
#endif
		    &bmsr_data.value)) != NXGE_OK) {
			goto fail;
		}

		if (nxgep->param_arr[param_autoneg].value) {
			if ((status = nxge_mii_read(nxgep,
				nxgep->statsp->mac_stats.xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->gsr),
#else
				(uint8_t)(uint64_t)(&mii_regs->gsr),
#endif
				&gsr.value)) != NXGE_OK)
				goto fail;
			if ((status = nxge_mii_read(nxgep,
				nxgep->statsp->mac_stats.xcvr_portn,
#if defined(__i386)
				(uint8_t)(uint32_t)(&mii_regs->anlpar),
#else
				(uint8_t)(uint64_t)(&mii_regs->anlpar),
#endif
				&anlpar.value)) != NXGE_OK)
				goto fail;
			if (nxgep->statsp->mac_stats.link_up &&
				((nxgep->statsp->mac_stats.lp_cap_1000fdx ^
					gsr.bits.link_1000fdx) ||
				(nxgep->statsp->mac_stats.lp_cap_1000hdx ^
					gsr.bits.link_1000hdx) ||
				(nxgep->statsp->mac_stats.lp_cap_100T4 ^
					anlpar.bits.cap_100T4) ||
				(nxgep->statsp->mac_stats.lp_cap_100fdx ^
					anlpar.bits.cap_100fdx) ||
				(nxgep->statsp->mac_stats.lp_cap_100hdx ^
					anlpar.bits.cap_100hdx) ||
				(nxgep->statsp->mac_stats.lp_cap_10fdx ^
					anlpar.bits.cap_10fdx) ||
				(nxgep->statsp->mac_stats.lp_cap_10hdx ^
					anlpar.bits.cap_10hdx))) {
				bmsr_data.bits.link_status = 0;
			}
		}

		/* Workaround for link down issue */
		if (bmsr_data.value == 0) {
			cmn_err(CE_NOTE, "!LINK DEBUG: Read zero bmsr\n");
			goto nxge_check_mii_link_exit;
		}

		bmsr_ints.value = nxgep->bmsr.value ^ bmsr_data.value;
		nxgep->bmsr.value = bmsr_data.value;
		if ((status = nxge_mii_check(nxgep, bmsr_data, bmsr_ints,
		    &link_up)) != NXGE_OK) {
			goto fail;
		}
		break;

	case PORT_1G_SERDES:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_mii_link port<%d> (SERDES)", portn));
		if ((status = nxge_pcs_check(nxgep, portn, &link_up))
		    != NXGE_OK) {
			goto fail;
		}
		break;
	}

nxge_check_mii_link_exit:
	RW_EXIT(&nxgep->filter_lock);
	if (link_up == LINK_IS_UP) {
		nxge_link_is_up(nxgep);
	} else if (link_up == LINK_IS_DOWN) {
		nxge_link_is_down(nxgep);
	}

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_check_mii_link port<%d>",
				portn));
	return (NXGE_OK);

fail:
	RW_EXIT(&nxgep->filter_lock);

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			"nxge_check_mii_link: Failed to check link port<%d>",
			portn));
	return (status);
}


/*ARGSUSED*/
static nxge_status_t
nxge_check_10g_link(p_nxge_t nxgep)
{
	uint8_t		portn;
	nxge_status_t	status = NXGE_OK;
	boolean_t	link_up;
	boolean_t	xpcs_up, xmac_up;
	uint32_t	val;
	npi_status_t	rs;

	if (nxgep->nxge_magic != NXGE_MAGIC)
		return (NXGE_ERROR);

	if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP)
		return (NXGE_OK);

	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_check_10g_link port<%d>",
	    portn));

	switch (nxgep->mac.portmode) {
	default:
		status = nxge_check_bcm8704_link(nxgep, &link_up);
		if (status != NXGE_OK)
			goto fail;
		break;
	case PORT_10G_SERDES:
		rs = npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
		    XPCS_REG_STATUS1, &val);
		if (rs != 0)
			goto fail;

		link_up = B_FALSE;
		xmac_up = B_FALSE;
		xpcs_up = B_FALSE;
		if (val & XPCS_STATUS1_RX_LINK_STATUS_UP) {
			xpcs_up = B_TRUE;
		}

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_10g_link port<%d> "
		    "XPCS_REG_STATUS1 0x%x xpcs_up %d",
		    portn, val, xpcs_up));
		/*
		 * Read the xMAC internal signal 2 register.
		 * This register should be the superset of the XPCS when wanting
		 * to get the link status. If this register read is proved to be
		 * reliable, there is no need to read the XPCS register.
		 */
		xmac_up = B_TRUE;
		XMAC_REG_RD(nxgep->npi_handle, portn, XMAC_INTERN2_REG, &val);
		if (val & XMAC_IS2_LOCAL_FLT_OC_SYNC) { /* link is down */
			xmac_up = B_FALSE;
		}

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_10g_link port<%d> "
		    "XMAC_INTERN2_REG 0x%x xmac_up %d",
		    portn, val, xmac_up));

		if (xpcs_up && xmac_up) {
			link_up = B_TRUE;
		}
		break;
	}

	if (link_up) {
		if (nxgep->link_notify ||
			nxgep->statsp->mac_stats.link_up == 0) {
			if (nxge_10g_link_led_on(nxgep) != NXGE_OK)
				goto fail;
			nxgep->statsp->mac_stats.link_up = 1;
			nxgep->statsp->mac_stats.link_speed = 10000;
			nxgep->statsp->mac_stats.link_duplex = 2;

			nxge_link_is_up(nxgep);
			nxgep->link_notify = B_FALSE;
		}
	} else {
		if (nxgep->link_notify ||
			nxgep->statsp->mac_stats.link_up == 1) {
			if (nxge_10g_link_led_off(nxgep) != NXGE_OK)
				goto fail;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					"Link down cable problem"));
			nxgep->statsp->mac_stats.link_up = 0;
			nxgep->statsp->mac_stats.link_speed = 0;
			nxgep->statsp->mac_stats.link_duplex = 0;

			nxge_link_is_down(nxgep);
			nxgep->link_notify = B_FALSE;
		}
	}

	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_check_10g_link port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	(void) nxge_check_link_stop(nxgep);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_check_10g_link: Failed to check link port<%d>",
	    portn));
	return (status);
}


/* Declare link down */

void
nxge_link_is_down(p_nxge_t nxgep)
{
	p_nxge_stats_t statsp;
	char link_stat_msg[64];

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_link_is_down"));

	statsp = nxgep->statsp;
	(void) sprintf(link_stat_msg, "xcvr addr:0x%02x - link is down",
	    statsp->mac_stats.xcvr_portn);

	if (nxge_no_msg == B_FALSE) {
		NXGE_ERROR_MSG((nxgep, NXGE_NOTE, "%s", link_stat_msg));
	}

	mac_link_update(nxgep->mach, LINK_STATE_DOWN);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_is_down"));
}

/* Declare link up */

void
nxge_link_is_up(p_nxge_t nxgep)
{
	p_nxge_stats_t statsp;
	char link_stat_msg[64];
	uint32_t val;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_link_is_up"));

	statsp = nxgep->statsp;
	(void) sprintf(link_stat_msg, "xcvr addr:0x%02x - link is up %d Mbps ",
	    statsp->mac_stats.xcvr_portn,
	    statsp->mac_stats.link_speed);

	if (statsp->mac_stats.link_T4)
		(void) strcat(link_stat_msg, "T4");
	else if (statsp->mac_stats.link_duplex == 2)
		(void) strcat(link_stat_msg, "full duplex");
	else
		(void) strcat(link_stat_msg, "half duplex");

	(void) nxge_xif_init(nxgep);

	/* Clean up symbol errors incurred during link transition */
	if ((nxgep->mac.portmode == PORT_10G_FIBER) ||
	    (nxgep->mac.portmode == PORT_10G_SERDES)) {
		(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
					XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &val);
		(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
					XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &val);
	}

	if (nxge_no_msg == B_FALSE) {
		NXGE_ERROR_MSG((nxgep, NXGE_NOTE, "%s", link_stat_msg));
	}

	mac_link_update(nxgep->mach, LINK_STATE_UP);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_is_up"));
}

/*
 * Calculate the bit in the multicast address filter
 * that selects the given * address.
 * Note: For GEM, the last 8-bits are used.
 */
uint32_t
crc32_mchash(p_ether_addr_t addr)
{
	uint8_t *cp;
	uint32_t crc;
	uint32_t c;
	int byte;
	int bit;

	cp = (uint8_t *)addr;
	crc = (uint32_t)0xffffffff;
	for (byte = 0; byte < 6; byte++) {
		c = (uint32_t)cp[byte];
		for (bit = 0; bit < 8; bit++) {
			if ((c & 0x1) ^ (crc & 0x1))
				crc = (crc >> 1)^0xedb88320;
			else
				crc = (crc >> 1);
			c >>= 1;
		}
	}
	return ((~crc) >> (32 - HASH_BITS));
}

/* Reset serdes */

nxge_status_t
nxge_serdes_reset(p_nxge_t nxgep)
{
	npi_handle_t		handle;

	handle = nxgep->npi_handle;

	ESR_REG_WR(handle, ESR_RESET_REG, ESR_RESET_0 | ESR_RESET_1);
	drv_usecwait(500);
	ESR_REG_WR(handle, ESR_CONFIG_REG, 0);

	return (NXGE_OK);
}

/* Monitor link status using interrupt or polling */

nxge_status_t
nxge_link_monitor(p_nxge_t nxgep, link_mon_enable_t enable)
{
	nxge_status_t status = NXGE_OK;

	/*
	 * Return immediately if this is an imaginary XMAC port.
	 * (At least, we don't have 4-port XMAC cards yet.)
	 */
	if ((nxgep->mac.portmode == PORT_10G_FIBER ||
	    nxgep->mac.portmode == PORT_10G_SERDES) &&
	    (nxgep->mac.portnum > 1))
		return (NXGE_OK);

	if (nxgep->statsp == NULL) {
		/* stats has not been allocated. */
		return (NXGE_OK);
	}
	/* Don't check link if we're not in internal loopback mode */
	if (nxgep->statsp->port_stats.lb_mode != nxge_lb_normal)
		return (NXGE_OK);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_link_monitor port<%d> enable=%d",
	    nxgep->mac.portnum, enable));
	if (enable == LINK_MONITOR_START) {
		if (nxgep->mac.linkchkmode == LINKCHK_INTR) {
			if ((status = nxge_link_intr(nxgep, LINK_INTR_START))
			    != NXGE_OK)
				goto fail;
		} else {
			timeout_id_t timerid;

			if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP)
				return (NXGE_OK);

			if (nxgep->xcvr.check_link) {
				timerid = timeout(
				    (fptrv_t)(nxgep->xcvr.check_link),
				    nxgep,
				    drv_usectohz(LINK_MONITOR_PERIOD));
				MUTEX_ENTER(&nxgep->poll_lock);
				nxgep->nxge_link_poll_timerid = timerid;
				MUTEX_EXIT(&nxgep->poll_lock);
			} else {
				return (NXGE_ERROR);
			}
		}
	} else {
		if (nxgep->mac.linkchkmode == LINKCHK_INTR) {
			if ((status = nxge_link_intr(nxgep, LINK_INTR_STOP))
			    != NXGE_OK)
				goto fail;
		} else {
			clock_t rv;

			MUTEX_ENTER(&nxgep->poll_lock);

			/* If <timerid> == 0, the link monitor has */
			/* never been started, or just now stopped. */
			if (nxgep->nxge_link_poll_timerid == 0) {
				MUTEX_EXIT(&nxgep->poll_lock);
				return (NXGE_OK);
			}

			nxgep->poll_state = LINK_MONITOR_STOPPING;
			rv = cv_timedwait(&nxgep->poll_cv,
			    &nxgep->poll_lock,
			    ddi_get_lbolt() +
			    drv_usectohz(LM_WAIT_MULTIPLIER *
			    LINK_MONITOR_PERIOD));
			if (rv == -1) {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "==> stopping port %d: "
				    "cv_timedwait(%d) timed out",
				    nxgep->mac.portnum, nxgep->poll_state));
				nxgep->poll_state = LINK_MONITOR_STOP;
				nxgep->nxge_link_poll_timerid = 0;
			}

			MUTEX_EXIT(&nxgep->poll_lock);
		}
	}
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_link_monitor port<%d> enable=%d",
	    nxgep->mac.portnum, enable));
	return (NXGE_OK);
fail:
	return (status);
}

/* Set promiscous mode */

nxge_status_t
nxge_set_promisc(p_nxge_t nxgep, boolean_t on)
{
	nxge_status_t status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_set_promisc: on %d", on));

	nxgep->filter.all_phys_cnt = ((on) ? 1 : 0);

	RW_ENTER_WRITER(&nxgep->filter_lock);

	if ((status = nxge_rx_mac_disable(nxgep)) != NXGE_OK) {
		goto fail;
	}
	if ((status = nxge_rx_mac_enable(nxgep)) != NXGE_OK) {
		goto fail;
	}

	RW_EXIT(&nxgep->filter_lock);

	if (on)
		nxgep->statsp->mac_stats.promisc = B_TRUE;
	else
		nxgep->statsp->mac_stats.promisc = B_FALSE;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_set_promisc"));

	return (NXGE_OK);
fail:
	RW_EXIT(&nxgep->filter_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_set_promisc: "
	    "Unable to set promisc (%d)", on));

	return (status);
}

/*ARGSUSED*/
uint_t
nxge_mif_intr(void *arg1, void *arg2)
{
#ifdef	NXGE_DEBUG
	p_nxge_t		nxgep = (p_nxge_t)arg2;
#endif
#if NXGE_MIF
	p_nxge_ldv_t		ldvp = (p_nxge_ldv_t)arg1;
	uint32_t		status;
	npi_handle_t		handle;
	uint8_t			portn;
	p_nxge_stats_t		statsp;
#endif

#ifdef	NXGE_MIF
	if (arg2 == NULL || (void *)ldvp->nxgep != arg2) {
		nxgep = ldvp->nxgep;
	}
	nxgep = ldvp->nxgep;
#endif
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_mif_intr"));

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_mif_intr"));
	return (DDI_INTR_CLAIMED);

mif_intr_fail:
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_mif_intr"));
	return (DDI_INTR_UNCLAIMED);
}

/*ARGSUSED*/
uint_t
nxge_mac_intr(void *arg1, void *arg2)
{
	p_nxge_t		nxgep = (p_nxge_t)arg2;
	p_nxge_ldv_t		ldvp = (p_nxge_ldv_t)arg1;
	p_nxge_ldg_t		ldgp;
	uint32_t		status;
	npi_handle_t		handle;
	uint8_t			portn;
	p_nxge_stats_t		statsp;
	npi_status_t		rs = NPI_SUCCESS;

	if (arg2 == NULL || (void *)ldvp->nxgep != arg2) {
		nxgep = ldvp->nxgep;
	}

	ldgp = ldvp->ldgp;
	NXGE_DEBUG_MSG((nxgep, INT_CTL, "==> nxge_mac_intr: "
	    "group %d", ldgp->ldg));

	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	/*
	 * This interrupt handler is for a specific
	 * mac port.
	 */
	statsp = (p_nxge_stats_t)nxgep->statsp;
	portn = nxgep->mac.portnum;

	NXGE_DEBUG_MSG((nxgep, INT_CTL,
	    "==> nxge_mac_intr: reading mac stats: port<%d>", portn));

	if (nxgep->mac.porttype == PORT_TYPE_XMAC) {
		rs = npi_xmac_tx_get_istatus(handle, portn,
					(xmac_tx_iconfig_t *)&status);
		if (rs != NPI_SUCCESS)
			goto npi_fail;
		if (status & ICFG_XMAC_TX_ALL) {
			if (status & ICFG_XMAC_TX_UNDERRUN) {
				statsp->xmac_stats.tx_underflow_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_UNDERFLOW);
			}
			if (status & ICFG_XMAC_TX_MAX_PACKET_ERR) {
				statsp->xmac_stats.tx_maxpktsize_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_MAX_PKT_ERR);
			}
			if (status & ICFG_XMAC_TX_OVERFLOW) {
				statsp->xmac_stats.tx_overflow_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_OVERFLOW);
			}
			if (status & ICFG_XMAC_TX_FIFO_XFR_ERR) {
				statsp->xmac_stats.tx_fifo_xfr_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_TXFIFO_XFR_ERR);
			}
			if (status & ICFG_XMAC_TX_BYTE_CNT_EXP) {
				statsp->xmac_stats.tx_byte_cnt +=
							XTXMAC_BYTE_CNT_MASK;
			}
			if (status & ICFG_XMAC_TX_FRAME_CNT_EXP) {
				statsp->xmac_stats.tx_frame_cnt +=
							XTXMAC_FRM_CNT_MASK;
			}
		}

		rs = npi_xmac_rx_get_istatus(handle, portn,
					(xmac_rx_iconfig_t *)&status);
		if (rs != NPI_SUCCESS)
			goto npi_fail;
		if (status & ICFG_XMAC_RX_ALL) {
			if (status & ICFG_XMAC_RX_OVERFLOW)
				statsp->xmac_stats.rx_overflow_err++;
			if (status & ICFG_XMAC_RX_UNDERFLOW) {
				statsp->xmac_stats.rx_underflow_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_UNDERFLOW);
			}
			if (status & ICFG_XMAC_RX_CRC_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_crc_err_cnt +=
							XRXMAC_CRC_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_CRC_ERRCNT_EXP);
			}
			if (status & ICFG_XMAC_RX_LEN_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_len_err_cnt +=
							MAC_LEN_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
				NXGE_FM_EREPORT_RXMAC_LENGTH_ERRCNT_EXP);
			}
			if (status & ICFG_XMAC_RX_VIOL_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_viol_err_cnt +=
							XRXMAC_CD_VIO_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_VIOL_ERRCNT_EXP);
			}
			if (status & ICFG_XMAC_RX_OCT_CNT_EXP) {
				statsp->xmac_stats.rx_byte_cnt +=
							XRXMAC_BT_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT1_EXP) {
				statsp->xmac_stats.rx_hist1_cnt +=
							XRXMAC_HIST_CNT1_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT2_EXP) {
				statsp->xmac_stats.rx_hist2_cnt +=
							XRXMAC_HIST_CNT2_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT3_EXP) {
				statsp->xmac_stats.rx_hist3_cnt +=
							XRXMAC_HIST_CNT3_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT4_EXP) {
				statsp->xmac_stats.rx_hist4_cnt +=
							XRXMAC_HIST_CNT4_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT5_EXP) {
				statsp->xmac_stats.rx_hist5_cnt +=
							XRXMAC_HIST_CNT5_MASK;
			}
			if (status & ICFG_XMAC_RX_HST_CNT6_EXP) {
				statsp->xmac_stats.rx_hist6_cnt +=
							XRXMAC_HIST_CNT6_MASK;
			}
			if (status & ICFG_XMAC_RX_BCAST_CNT_EXP) {
				statsp->xmac_stats.rx_broadcast_cnt +=
							XRXMAC_BC_FRM_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_MCAST_CNT_EXP) {
				statsp->xmac_stats.rx_mult_cnt +=
							XRXMAC_MC_FRM_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_FRAG_CNT_EXP) {
				statsp->xmac_stats.rx_frag_cnt +=
							XRXMAC_FRAG_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_RXFRAG_CNT_EXP);
			}
			if (status & ICFG_XMAC_RX_ALIGNERR_CNT_EXP) {
				statsp->xmac_stats.rx_frame_align_err_cnt +=
							XRXMAC_AL_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_ALIGN_ECNT_EXP);
			}
			if (status & ICFG_XMAC_RX_LINK_FLT_CNT_EXP) {
				statsp->xmac_stats.rx_linkfault_err_cnt +=
							XMAC_LINK_FLT_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
				NXGE_FM_EREPORT_RXMAC_LINKFAULT_CNT_EXP);
			}
			if (status & ICFG_XMAC_RX_REMOTE_FLT_DET) {
				statsp->xmac_stats.rx_remotefault_err++;
			}
			if (status & ICFG_XMAC_RX_LOCAL_FLT_DET) {
				statsp->xmac_stats.rx_localfault_err++;
			}
		}

		rs = npi_xmac_ctl_get_istatus(handle, portn,
						(xmac_ctl_iconfig_t *)&status);
		if (rs != NPI_SUCCESS)
			goto npi_fail;
		if (status & ICFG_XMAC_CTRL_ALL) {
			if (status & ICFG_XMAC_CTRL_PAUSE_RCVD)
				statsp->xmac_stats.rx_pause_cnt++;
			if (status & ICFG_XMAC_CTRL_PAUSE_STATE)
				statsp->xmac_stats.tx_pause_state++;
			if (status & ICFG_XMAC_CTRL_NOPAUSE_STATE)
				statsp->xmac_stats.tx_nopause_state++;
		}
	} else if (nxgep->mac.porttype == PORT_TYPE_BMAC) {
		rs = npi_bmac_tx_get_istatus(handle, portn,
						(bmac_tx_iconfig_t *)&status);
		if (rs != NPI_SUCCESS)
			goto npi_fail;
		if (status & ICFG_BMAC_TX_ALL) {
			if (status & ICFG_BMAC_TX_UNDERFLOW) {
				statsp->bmac_stats.tx_underrun_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_UNDERFLOW);
			}
			if (status & ICFG_BMAC_TX_MAXPKTSZ_ERR) {
				statsp->bmac_stats.tx_max_pkt_err++;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_TXMAC_MAX_PKT_ERR);
			}
			if (status & ICFG_BMAC_TX_BYTE_CNT_EXP) {
				statsp->bmac_stats.tx_byte_cnt +=
							BTXMAC_BYTE_CNT_MASK;
			}
			if (status & ICFG_BMAC_TX_FRAME_CNT_EXP) {
				statsp->bmac_stats.tx_frame_cnt +=
							BTXMAC_FRM_CNT_MASK;
			}
		}

		rs = npi_bmac_rx_get_istatus(handle, portn,
						(bmac_rx_iconfig_t *)&status);
		if (rs != NPI_SUCCESS)
			goto npi_fail;
		if (status & ICFG_BMAC_RX_ALL) {
			if (status & ICFG_BMAC_RX_OVERFLOW) {
				statsp->bmac_stats.rx_overflow_err++;
			}
			if (status & ICFG_BMAC_RX_FRAME_CNT_EXP) {
				statsp->bmac_stats.rx_frame_cnt +=
							RXMAC_FRM_CNT_MASK;
			}
			if (status & ICFG_BMAC_RX_CRC_ERR_CNT_EXP) {
				statsp->bmac_stats.rx_crc_err_cnt +=
							BMAC_CRC_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_CRC_ERRCNT_EXP);
			}
			if (status & ICFG_BMAC_RX_LEN_ERR_CNT_EXP) {
				statsp->bmac_stats.rx_len_err_cnt +=
							MAC_LEN_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
				NXGE_FM_EREPORT_RXMAC_LENGTH_ERRCNT_EXP);
			}
			if (status & ICFG_BMAC_RX_VIOL_ERR_CNT_EXP)
				statsp->bmac_stats.rx_viol_err_cnt +=
							BMAC_CD_VIO_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_VIOL_ERRCNT_EXP);
			}
			if (status & ICFG_BMAC_RX_BYTE_CNT_EXP) {
				statsp->bmac_stats.rx_byte_cnt +=
							BRXMAC_BYTE_CNT_MASK;
			}
			if (status & ICFG_BMAC_RX_ALIGNERR_CNT_EXP) {
				statsp->bmac_stats.rx_align_err_cnt +=
							BMAC_AL_ER_CNT_MASK;
				NXGE_FM_REPORT_ERROR(nxgep, portn, NULL,
					NXGE_FM_EREPORT_RXMAC_ALIGN_ECNT_EXP);
			}

			rs = npi_bmac_ctl_get_istatus(handle, portn,
						(bmac_ctl_iconfig_t *)&status);
			if (rs != NPI_SUCCESS)
				goto npi_fail;

			if (status & ICFG_BMAC_CTL_ALL) {
				if (status & ICFG_BMAC_CTL_RCVPAUSE)
					statsp->bmac_stats.rx_pause_cnt++;
				if (status & ICFG_BMAC_CTL_INPAUSE_ST)
					statsp->bmac_stats.tx_pause_state++;
				if (status & ICFG_BMAC_CTL_INNOTPAUSE_ST)
					statsp->bmac_stats.tx_nopause_state++;
			}
		}

	if (ldgp->nldvs == 1) {
		(void) npi_intr_ldg_mgmt_set(handle, ldgp->ldg,
			B_TRUE, ldgp->ldg_timer);
	}

	NXGE_DEBUG_MSG((nxgep, INT_CTL, "<== nxge_mac_intr"));
	return (DDI_INTR_CLAIMED);

npi_fail:
	NXGE_ERROR_MSG((nxgep, INT_CTL, "<== nxge_mac_intr"));
	return (DDI_INTR_UNCLAIMED);
}

nxge_status_t
nxge_check_bcm8704_link(p_nxge_t nxgep, boolean_t *link_up)
{
	uint8_t		phy_port_addr;
	nxge_status_t	status = NXGE_OK;
	boolean_t	rx_sig_ok;
	boolean_t	pcs_blk_lock;
	boolean_t	link_align;
	uint16_t	val1, val2, val3;
#ifdef	NXGE_DEBUG_SYMBOL_ERR
	uint16_t	val_debug;
	uint16_t	val;
#endif

	phy_port_addr = nxgep->statsp->mac_stats.xcvr_portn;

#ifdef	NXGE_DEBUG_SYMBOL_ERR
	/* Check Device 3 Register Device 3 0xC809 */
	(void) nxge_mdio_read(nxgep, phy_port_addr, 0x3, 0xC809, &val_debug);
	if ((val_debug & ~0x200) != 0) {
		cmn_err(CE_NOTE, "!Port%d BCM8704 Dev3 Reg 0xc809 = 0x%x\n",
				nxgep->mac.portnum, val_debug);
		(void) nxge_mdio_read(nxgep, phy_port_addr, 0x4, 0x18,
				&val_debug);
		cmn_err(CE_NOTE, "!Port%d BCM8704 Dev4 Reg 0x18 = 0x%x\n",
				nxgep->mac.portnum, val_debug);
	}

	(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
					XPCS_REG_DESCWERR_COUNTER, &val);
	if (val != 0)
		cmn_err(CE_NOTE, "!XPCS DESCWERR = 0x%x\n", val);

	(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
					XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &val);
	if (val != 0)
		cmn_err(CE_NOTE, "!XPCS SYMBOL_ERR_L0_1 = 0x%x\n", val);

	(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
					XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &val);
	if (val != 0)
		cmn_err(CE_NOTE, "!XPCS SYMBOL_ERR_L2_3 = 0x%x\n", val);
#endif

	/* Check from BCM8704 if 10G link is up or down */

	/* Check Device 1 Register 0xA bit0 */
	status = nxge_mdio_read(nxgep, phy_port_addr,
			BCM8704_PMA_PMD_DEV_ADDR,
			BCM8704_PMD_RECEIVE_SIG_DETECT,
			&val1);
	if (status != NXGE_OK)
		goto fail;
	rx_sig_ok = ((val1 & GLOB_PMD_RX_SIG_OK) ? B_TRUE : B_FALSE);

	/* Check Device 3 Register 0x20 bit0 */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
			BCM8704_PCS_DEV_ADDR,
			BCM8704_10GBASE_R_PCS_STATUS_REG,
			&val2)) != NPI_SUCCESS)
		goto fail;
	pcs_blk_lock = ((val2 & PCS_10GBASE_R_PCS_BLK_LOCK) ? B_TRUE : B_FALSE);

	/* Check Device 4 Register 0x18 bit12 */
	status = nxge_mdio_read(nxgep, phy_port_addr,
			BCM8704_PHYXS_ADDR,
			BCM8704_PHYXS_XGXS_LANE_STATUS_REG,
			&val3);
	if (status != NXGE_OK)
		goto fail;
	link_align = (val3 == (XGXS_LANE_ALIGN_STATUS | XGXS_LANE3_SYNC |
				XGXS_LANE2_SYNC | XGXS_LANE1_SYNC |
				XGXS_LANE0_SYNC | 0x400)) ? B_TRUE : B_FALSE;

#ifdef	NXGE_DEBUG_ALIGN_ERR
	/* Temp workaround for link down issue */
	if (pcs_blk_lock == B_FALSE) {
		if (val2 != 0x4) {
			pcs_blk_lock = B_TRUE;
			cmn_err(CE_NOTE,
				"!LINK DEBUG: port%d PHY Dev3 "
				"Reg 0x20 = 0x%x\n",
				nxgep->mac.portnum, val2);
		}
	}

	if (link_align == B_FALSE) {
		if (val3 != 0x140f) {
			link_align = B_TRUE;
			cmn_err(CE_NOTE,
				"!LINK DEBUG: port%d PHY Dev4 "
				"Reg 0x18 = 0x%x\n",
				nxgep->mac.portnum, val3);
		}
	}

	if (rx_sig_ok == B_FALSE) {
		if ((val2 == 0) || (val3 == 0)) {
			rx_sig_ok = B_TRUE;
			cmn_err(CE_NOTE,
				"!LINK DEBUG: port %d Dev3 or Dev4 read zero\n",
				nxgep->mac.portnum);
		}
	}
#endif

	*link_up = ((rx_sig_ok == B_TRUE) && (pcs_blk_lock == B_TRUE) &&
			(link_align == B_TRUE)) ? B_TRUE : B_FALSE;

	return (NXGE_OK);
fail:
	return (status);
}

nxge_status_t
nxge_10g_link_led_on(p_nxge_t nxgep)
{
	if (npi_xmac_xif_led(nxgep->npi_handle, nxgep->mac.portnum, B_TRUE)
	    != NPI_SUCCESS)
		return (NXGE_ERROR);
	else
		return (NXGE_OK);
}

nxge_status_t
nxge_10g_link_led_off(p_nxge_t nxgep)
{
	if (npi_xmac_xif_led(nxgep->npi_handle, nxgep->mac.portnum, B_FALSE)
	    != NPI_SUCCESS)
		return (NXGE_ERROR);
	else
		return (NXGE_OK);
}

/* Check if the given id read using the given MDIO Clause is supported */

static boolean_t
nxge_is_supported_phy(uint32_t id, uint8_t type)
{
	int		i;
	int		cl45_arr_len = NUM_CLAUSE_45_IDS;
	int		cl22_arr_len = NUM_CLAUSE_22_IDS;
	boolean_t	found = B_FALSE;

	switch (type) {
	case CLAUSE_45_TYPE:
		for (i = 0; i < cl45_arr_len; i++) {
			if ((nxge_supported_cl45_ids[i] & BCM_PHY_ID_MASK) ==
			    (id & BCM_PHY_ID_MASK)) {
				found = B_TRUE;
				break;
			}
		}
		break;
	case CLAUSE_22_TYPE:
		for (i = 0; i < cl22_arr_len; i++) {
			if ((nxge_supported_cl22_ids[i] & BCM_PHY_ID_MASK) ==
			    (id & BCM_PHY_ID_MASK)) {
				found = B_TRUE;
				break;
			}
		}
		break;
	default:
		break;
	}

	return (found);
}

static uint32_t
nxge_get_cl45_pma_pmd_id(p_nxge_t nxgep, int phy_port)
{
	uint16_t	val1 = 0;
	uint16_t	val2 = 0;
	uint32_t	pma_pmd_dev_id = 0;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PMA_PMD_DEV_ADDR,
	    NXGE_DEV_ID_REG_1, &val1);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PMA_PMD_DEV_ADDR,
	    NXGE_DEV_ID_REG_2, &val2);

	pma_pmd_dev_id = val1;
	pma_pmd_dev_id = (pma_pmd_dev_id << 16);
	pma_pmd_dev_id |= val2;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PMA/PMD "
	    "devid[0x%llx]", phy_port, pma_pmd_dev_id));

	return (pma_pmd_dev_id);
}

static uint32_t
nxge_get_cl45_pcs_id(p_nxge_t nxgep, int phy_port)
{
	uint16_t	val1 = 0;
	uint16_t	val2 = 0;
	uint32_t	pcs_dev_id = 0;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);

	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PCS_DEV_ADDR,
	    NXGE_DEV_ID_REG_1, &val1);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PCS_DEV_ADDR,
	    NXGE_DEV_ID_REG_2, &val2);

	pcs_dev_id = val1;
	pcs_dev_id = (pcs_dev_id << 16);
	pcs_dev_id |= val2;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PCS "
	    "devid[0x%llx]", phy_port, pcs_dev_id));

	return (pcs_dev_id);
}

static uint32_t
nxge_get_cl22_phy_id(p_nxge_t nxgep, int phy_port)
{
	uint16_t	val1 = 0;
	uint16_t	val2 = 0;
	uint32_t	phy_id = 0;
	npi_handle_t	handle = NXGE_DEV_NPI_HANDLE(nxgep);
	npi_status_t	npi_status = NPI_SUCCESS;

	npi_status = npi_mac_mif_mii_read(handle, phy_port, NXGE_PHY_ID_REG_1,
	    &val1);
	if (npi_status != NPI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] "
		    "clause 22 read to reg 2 failed!!!"));
		goto exit;
	}
	npi_status = npi_mac_mif_mii_read(handle, phy_port, NXGE_PHY_ID_REG_2,
	    &val2);
	if (npi_status != 0) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] "
		    "clause 22 read to reg 3 failed!!!"));
		goto exit;
	}
	phy_id = val1;
	phy_id = (phy_id << 16);
	phy_id |= val2;

exit:

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PHY ID [0x%llx]",
	    phy_port, phy_id));

	return (phy_id);
}

/*
 * Scan the PHY ports 0 through 31 to get the PHY ID using Clause 22 MDIO
 * read and the PMA/PMD device ID and the PCS device ID using Clause 45 MDIO
 * read. Then use the values obtained to determine the phy type of each port
 * and the Neptune type.
 */

nxge_status_t
nxge_scan_ports_phy(p_nxge_t nxgep, p_nxge_hw_list_t hw_p)
{
	int		i, j, k, l;
	uint32_t	pma_pmd_dev_id = 0;
	uint32_t	pcs_dev_id = 0;
	uint32_t	phy_id = 0;
	uint32_t	port_pma_pmd_dev_id[NXGE_PORTS_NEPTUNE];
	uint32_t	port_pcs_dev_id[NXGE_PORTS_NEPTUNE];
	uint32_t	port_phy_id[NXGE_PORTS_NEPTUNE];
	uint8_t		pma_pmd_dev_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		pcs_dev_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		phy_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		port_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		total_port_fd, total_phy_fd;
	nxge_status_t	status = NXGE_OK;
	int		prt_id = -1;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_scan_ports_phy: "));
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_scan_ports_phy: nxge niu_type[0x%x]",
	    nxgep->niu_type));

	j = k = l = 0;
	total_port_fd = total_phy_fd = 0;
	/*
	 * Clause 45 and Clause 22 port/phy addresses 0 through 7 are reserved
	 * for on chip serdes usages.
	 */
	for (i = NXGE_EXT_PHY_PORT_ST; i < NXGE_MAX_PHY_PORTS; i++) {

		pma_pmd_dev_id = nxge_get_cl45_pma_pmd_id(nxgep, i);

		if (nxge_is_supported_phy(pma_pmd_dev_id, CLAUSE_45_TYPE)) {
			pma_pmd_dev_fd[i] = 1;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] "
			    "PMA/PMD dev found", i));
			if (j < NXGE_PORTS_NEPTUNE) {
				port_pma_pmd_dev_id[j] = pma_pmd_dev_id &
				    BCM_PHY_ID_MASK;
				j++;
			}
		} else {
			pma_pmd_dev_fd[i] = 0;
		}

		pcs_dev_id = nxge_get_cl45_pcs_id(nxgep, i);

		if (nxge_is_supported_phy(pcs_dev_id, CLAUSE_45_TYPE)) {
			pcs_dev_fd[i] = 1;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PCS "
			    "dev found", i));
			if (k < NXGE_PORTS_NEPTUNE) {
				port_pcs_dev_id[k] = pcs_dev_id &
				    BCM_PHY_ID_MASK;
				k++;
			}
		} else {
			pcs_dev_fd[i] = 0;
		}

		if (pcs_dev_fd[i] || pma_pmd_dev_fd[i])
			port_fd[i] = 1;
		else
			port_fd[i] = 0;
		total_port_fd += port_fd[i];

		phy_id = nxge_get_cl22_phy_id(nxgep, i);

		if (nxge_is_supported_phy(phy_id, CLAUSE_22_TYPE)) {
			phy_fd[i] = 1;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PHY ID"
			    "found", i));
			if (l < NXGE_PORTS_NEPTUNE) {
				port_phy_id[l] = phy_id & BCM_PHY_ID_MASK;
				l++;
			}
		} else {
			phy_fd[i] = 0;
		}
		total_phy_fd += phy_fd[i];
	}

	switch (total_port_fd) {
	case 2:
		switch (total_phy_fd) {
		case 2:
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 1"));
			goto error_exit;
		case 1:
			/* TODO - 2 10G, 1 1G */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 2 10G, 1 1G"));
			goto error_exit;
		case 0:
			/* 2 10G */
			if (((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pcs_dev_id[1] == PHY_BCM8704_FAMILY)) ||
			    ((port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pma_pmd_dev_id[1] == PHY_BCM8704_FAMILY))) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */
				for (i = NXGE_EXT_PHY_PORT_ST;
				    i < NXGE_MAX_PHY_PORTS; i++) {
					if (port_fd[i] == 1)
						break;
				}
				if (i == BCM8704_NEPTUNE_PORT_ADDR_BASE) {
					hw_p->niu_type = NEPTUNE_2_10GF;
					hw_p->platform_type =
					    P_NEPTUNE_ATLAS_2PORT;
				} else {
					NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					    "Unsupported neptune type 2 - 1"));
					goto error_exit;
				}
				hw_p->niu_type = NEPTUNE_2_10GF;
			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 2"));
				goto error_exit;
			}
			break;
		case 4:
			/* Maramba with 2 XAUI */
			if ((((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pcs_dev_id[1] == PHY_BCM8704_FAMILY)) ||
			    ((port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pma_pmd_dev_id[1] == PHY_BCM8704_FAMILY))) &&
			    ((port_phy_id[0] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[1] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[2] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[3] == PHY_BCM5464R_FAMILY))) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */
				for (i = NXGE_EXT_PHY_PORT_ST;
				    i < NXGE_MAX_PHY_PORTS; i++) {
					if (phy_fd[i] == 1)
						break;
				}
				if (i == BCM5464_MARAMBA_P0_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P0;
				} else if (i ==
				    BCM5464_MARAMBA_P1_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P1;
				} else {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unknown port %d...Cannot "
					    "determine platform type", i));
					goto error_exit;
				}
				hw_p->niu_type = NEPTUNE_2_10GF_2_1GC;

				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Maramba with 2 XAUI"));
			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 3"));
				goto error_exit;
			}
			break;
		default:
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 5"));
			goto error_exit;
		}
		break;
	case 1:
		switch (total_phy_fd) {
		case 3:
			/*
			 * TODO 3 1G, 1 10G mode.
			 * Differentiate between 1_1G_1_10G_2_1G and
			 * 1_10G_3_1G
			 */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 7"));
			goto error_exit;
		case 2:
			/*
			 * TODO 2 1G, 1 10G mode.
			 * Differentiate between 1_1G_1_10G_1_1G and
			 * 1_10G_2_1G
			 */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 8"));
			goto error_exit;
		case 1:
			/*
			 * TODO 1 1G, 1 10G mode.
			 * Differentiate between 1_1G_1_10G and
			 * 1_10G_1_1G
			 */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 9"));
			goto error_exit;
		case 0:
			/* TODO 1 10G mode */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 10"));
			goto error_exit;
		case 4:
			/* Maramba with 1 XAUI */
			if ((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY) ||
			    (port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY)) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */
				for (i = NXGE_EXT_PHY_PORT_ST;
				    i < NXGE_MAX_PHY_PORTS; i++) {
					if (phy_fd[i] == 1)
						break;
				}

				if (i == BCM5464_MARAMBA_P0_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P0;
				} else if (i ==
				    BCM5464_MARAMBA_P1_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P1;
				} else {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unknown port %d...Cannot "
					    "determine platform type", i));
					goto error_exit;
				}

				/* The 10G port is BCM8704 */
				for (i = NXGE_EXT_PHY_PORT_ST;
				    i < NXGE_MAX_PHY_PORTS; i++) {
					if (port_fd[i] == 1) {
						prt_id = i;
						break;
					}
				}

				prt_id %= BCM8704_MARAMBA_PORT_ADDR_BASE;
				if (prt_id == 0) {
					hw_p->niu_type = NEPTUNE_1_10GF_3_1GC;
				} else if (prt_id == 1) {
					hw_p->niu_type =
					    NEPTUNE_1_1GC_1_10GF_2_1GC;
				} else {
					NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					    "Unsupported neptune type 11"));
					goto error_exit;
				}
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Maramba with 1 XAUI"));
			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 12"));
				goto error_exit;
			}
			break;
		default:
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 13"));
			goto error_exit;
		}
		break;
	case 0:
		switch (total_phy_fd) {
		case 4:
			if ((port_phy_id[0] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[1] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[2] == PHY_BCM5464R_FAMILY) &&
			    (port_phy_id[3] == PHY_BCM5464R_FAMILY)) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */
				for (i = NXGE_EXT_PHY_PORT_ST;
				    i < NXGE_MAX_PHY_PORTS; i++) {
					if (phy_fd[i] == 1)
						break;
				}

				if (i == BCM5464_MARAMBA_P1_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P1;
				} else if (i ==
				    BCM5464_NEPTUNE_PORT_ADDR_BASE) {
					hw_p->platform_type =
					    P_NEPTUNE_ATLAS_4PORT;
				} else {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unknown port %d...Cannot "
					    "determine platform type", i));
					goto error_exit;
				}
				hw_p->niu_type = NEPTUNE_4_1GC;
			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 14"));
				goto error_exit;
			}
			break;
		case 3:
			/* TODO 3 1G mode */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 15"));
			goto error_exit;
		case 2:
			/* TODO 2 1G mode */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 16"));
			goto error_exit;
		case 1:
			/* TODO 1 1G mode */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 17"));
			goto error_exit;
		default:
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 18, total phy fd %d",
			    total_phy_fd));
			goto error_exit;
		}
		break;
	default:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "Unsupported neptune type 19"));
		goto error_exit;
	}

scan_exit:

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_scan_ports_phy, "
	    "niu type [0x%x]\n", hw_p->niu_type));
	return (status);

error_exit:
	return (NXGE_ERROR);
}

boolean_t
nxge_is_valid_local_mac(ether_addr_st mac_addr)
{
	if ((mac_addr.ether_addr_octet[0] & 0x01) ||
	    (ether_cmp(&mac_addr, &etherbroadcastaddr) == 0) ||
	    (ether_cmp(&mac_addr, &etherzeroaddr) == 0))
		return (B_FALSE);
	else
		return (B_TRUE);
}

static void
nxge_bcm5464_link_led_off(p_nxge_t nxgep) {

	npi_status_t rs = NPI_SUCCESS;
	uint8_t xcvr_portn;
	uint8_t	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_bcm5464_link_led_off"));

	if (nxgep->nxge_hw_p->platform_type == P_NEPTUNE_MARAMBA_P1) {
		xcvr_portn = BCM5464_MARAMBA_P1_PORT_ADDR_BASE;
	} else if (nxgep->nxge_hw_p->platform_type == P_NEPTUNE_MARAMBA_P0) {
		xcvr_portn = BCM5464_MARAMBA_P0_PORT_ADDR_BASE;
	}
	/*
	 * For Altas 4-1G copper, Xcvr port numbers are
	 * swapped with ethernet port number. This is
	 * designed for better signal integrity in routing.
	 */
	switch (portn) {
	case 0:
		xcvr_portn += 3;
		break;
	case 1:
		xcvr_portn += 2;
		break;
	case 2:
		xcvr_portn += 1;
		break;
	case 3:
	default:
		break;
	}

	MUTEX_ENTER(&nxge_mii_lock);
	rs = npi_mac_mif_mii_write(nxgep->npi_handle,
	    xcvr_portn, BCM5464R_MISC, 0xb4ee);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_bcm5464_link_led_off: npi_mac_mif_mii_write "
		    "returned error 0x[%x]", rs));
		MUTEX_EXIT(&nxge_mii_lock);
		return;
	}

	rs = npi_mac_mif_mii_write(nxgep->npi_handle,
	    xcvr_portn, BCM5464R_MISC, 0xb8ee);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_bcm5464_link_led_off: npi_mac_mif_mii_write "
		    "returned error 0x[%x]", rs));
		MUTEX_EXIT(&nxge_mii_lock);
		return;
	}

	MUTEX_EXIT(&nxge_mii_lock);
}
