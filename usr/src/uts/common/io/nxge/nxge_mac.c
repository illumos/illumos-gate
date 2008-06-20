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
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/nxge/nxge_impl.h>
#include <sys/nxge/nxge_mac.h>
#include <sys/nxge/nxge_hio.h>

#define	LINK_MONITOR_PERIOD	(1000 * 1000)
#define	LM_WAIT_MULTIPLIER	8

#define	SERDES_RDY_WT_INTERVAL	50
#define	MAX_SERDES_RDY_RETRIES	10

#define	TN1010_SPEED_1G		1
#define	TN1010_SPEED_10G	0
#define	TN1010_AN_IN_PROG	0	/* Auto negotiation in progress */
#define	TN1010_AN_COMPLETE	1
#define	TN1010_AN_RSVD		2
#define	TN1010_AN_FAILED	3

extern uint32_t nxge_no_link_notify;
extern boolean_t nxge_no_msg;
extern uint32_t nxge_lb_dbg;
extern boolean_t nxge_jumbo_enable;
extern uint32_t nxge_jumbo_mtu;

	/* The following functions may be found in nxge_main.c */
extern void nxge_mmac_kstat_update(p_nxge_t nxgep, mac_addr_slot_t slot,
	boolean_t factory);
extern int nxge_m_mmac_add(void *arg, mac_multi_addr_t *maddr);
extern int nxge_m_mmac_remove(void *arg, mac_addr_slot_t slot);

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
static uint32_t nxge_supported_cl45_ids[] = {
	BCM8704_DEV_ID,
	MARVELL_88X_201X_DEV_ID,
	BCM8706_DEV_ID,
	TN1010_DEV_ID
};

static uint32_t nxge_supported_cl22_ids[] = {
    BCM5464R_PHY_ID,
    BCM5482_PHY_ID
};

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
static boolean_t nxge_is_phy_present(p_nxge_t, int, uint32_t, uint32_t);
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
static nxge_status_t nxge_BCM8704_xcvr_init(p_nxge_t);
static nxge_status_t nxge_BCM8706_xcvr_init(p_nxge_t);
static nxge_status_t nxge_1G_xcvr_init(p_nxge_t);
static void nxge_bcm5464_link_led_off(p_nxge_t);
static nxge_status_t nxge_check_mrvl88x2011_link(p_nxge_t, boolean_t *);
static nxge_status_t nxge_mrvl88x2011_xcvr_init(p_nxge_t);
static nxge_status_t nxge_get_num_of_xaui(uint32_t *port_pma_pmd_dev_id,
	uint32_t *port_pcs_dev_id, uint32_t *port_phy_id, uint8_t *num_xaui);
static nxge_status_t nxge_get_tn1010_speed(p_nxge_t nxgep, uint16_t *speed);
static nxge_status_t nxge_set_tn1010_param(p_nxge_t nxgep);
static nxge_status_t nxge_tn1010_check(p_nxge_t nxgep,
	nxge_link_state_t *link_up);
static boolean_t nxge_is_tn1010_phy(p_nxge_t nxgep);
static nxge_status_t nxge_tn1010_xcvr_init(p_nxge_t nxgep);

nxge_status_t nxge_mac_init(p_nxge_t);
static nxge_status_t nxge_mii_get_link_mode(p_nxge_t);

#ifdef NXGE_DEBUG
static void nxge_mii_dump(p_nxge_t);
static nxge_status_t nxge_tn1010_reset(p_nxge_t nxgep);
static void nxge_dump_tn1010_status_regs(p_nxge_t nxgep);
#endif

/*
 * xcvr tables for supported transceivers
 */

/*
 * nxge_n2_10G_table is for 10G fiber or serdes on N2-NIU systems.
 * The Teranetics TN1010 based copper XAUI card can also be used
 * on N2-NIU systems in 10G mode, but it uses its own table
 * nxge_n2_10G_tn1010_table below.
 */
static nxge_xcvr_table_t nxge_n2_10G_table = {
	nxge_n2_serdes_init,
	nxge_10G_xcvr_init,
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_10g_link,
	PCS_XCVR
};

/*
 * For the Teranetics TN1010 based copper XAUI card
 */
static nxge_xcvr_table_t nxge_n2_10G_tn1010_table = {
	nxge_n2_serdes_init,		/* Handle both 1G and 10G */
	nxge_tn1010_xcvr_init,		/* Handle both 1G and 10G */
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_tn1010_link,		/* Will figure out speed */
	XPCS_XCVR
};

static nxge_xcvr_table_t nxge_n2_1G_table = {
	nxge_n2_serdes_init,
	nxge_1G_xcvr_init,
	nxge_1G_fiber_link_intr_stop,
	nxge_1G_fiber_link_intr_start,
	nxge_check_mii_link,
	PCS_XCVR
};

static nxge_xcvr_table_t nxge_n2_1G_tn1010_table = {
	nxge_n2_serdes_init,
	nxge_tn1010_xcvr_init,
	nxge_1G_fiber_link_intr_stop,	/* TN1010 is a Cu PHY, but it uses */
	nxge_1G_fiber_link_intr_start,	/* PCS for 1G, so call fiber func */
	nxge_check_tn1010_link,
	PCS_XCVR
};

static nxge_xcvr_table_t nxge_10G_tn1010_table = {
	nxge_neptune_10G_serdes_init,
	nxge_tn1010_xcvr_init,
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_tn1010_link,
	XPCS_XCVR
};

static nxge_xcvr_table_t nxge_1G_tn1010_table = {
	nxge_1G_serdes_init,
	nxge_tn1010_xcvr_init,
	nxge_1G_fiber_link_intr_stop,
	nxge_1G_fiber_link_intr_start,
	nxge_check_tn1010_link,
	PCS_XCVR
};

static nxge_xcvr_table_t nxge_10G_fiber_table = {
	nxge_neptune_10G_serdes_init,
	nxge_10G_xcvr_init,
	nxge_10G_link_intr_stop,
	nxge_10G_link_intr_start,
	nxge_check_10g_link,
	PCS_XCVR
};

static nxge_xcvr_table_t nxge_1G_copper_table = {
	NULL,
	nxge_1G_xcvr_init,
	nxge_1G_copper_link_intr_stop,
	nxge_1G_copper_link_intr_start,
	nxge_check_mii_link,
	INT_MII_XCVR
};

/* This table is for Neptune portmode == PORT_1G_SERDES cases */
static nxge_xcvr_table_t nxge_1G_fiber_table = {
	nxge_1G_serdes_init,
	nxge_1G_xcvr_init,
	nxge_1G_fiber_link_intr_stop,
	nxge_1G_fiber_link_intr_start,
	nxge_check_mii_link,
	PCS_XCVR
};

static nxge_xcvr_table_t nxge_10G_copper_table = {
	nxge_neptune_10G_serdes_init,
	NULL,
	NULL,
	NULL,
	NULL,
	PCS_XCVR
};

/*
 * NXGE_PORT_TN1010 is defined as,
 *      NXGE_PORT_SPD_NONE | (NXGE_PHY_TN1010 << NXGE_PHY_SHIFT)
 *	= 0 | 5 << 16 = 0x50000
 *
 * So NEPTUNE_2_TN1010 =
 *      (NXGE_PORT_TN1010 |
 *      (NXGE_PORT_TN1010 << 4) |
 *      (NXGE_PORT_NONE << 8) |
 *      (NXGE_PORT_NONE << 12)),
 *      = 0x50000 | (0x50000 << 4)
 *	= 0x550000
 *
 * This function partitions nxgep->nxge_hw_p->niu_type (which may have
 * value NEPTUNE_2_TN1010) and checks if a port has type = NXGE_PORT_TN1010
 * = 0x50000
 */
static boolean_t nxge_is_tn1010_phy(p_nxge_t nxgep)
{
	uint8_t	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	if (((nxgep->nxge_hw_p->niu_type >> (NXGE_PORT_TYPE_SHIFT * portn))
	    & NXGE_PHY_MASK) == NXGE_PORT_TN1010) {
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}


/*
 * Figure out nxgep->mac.portmode from nxge.conf, OBP's device properties,
 * serial EEPROM or VPD if possible.  Note that not all systems could get
 * the portmode information by calling this function.  For example, the
 * Maramba system figures out the portmode information by calling function
 * nxge_setup_xcvr_table.
 */
nxge_status_t
nxge_get_xcvr_type(p_nxge_t nxgep)
{
	nxge_status_t status = NXGE_OK;
	char *phy_type;
	char *prop_val;
	uint8_t portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	nxgep->mac.portmode = 0;
	nxgep->xcvr_addr = 0;

	/*
	 * First check for hot swappable phy property.
	 */
	if (nxgep->hot_swappable_phy == B_TRUE) {
		nxgep->statsp->mac_stats.xcvr_inuse = HSP_XCVR;
		nxgep->mac.portmode = PORT_HSP_MODE;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Other: Hot Swappable"));
	} else if (ddi_prop_exists(DDI_DEV_T_ANY, nxgep->dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    "hot-swappable-phy") == 1) {
		nxgep->statsp->mac_stats.xcvr_inuse = HSP_XCVR;
		nxgep->mac.portmode = PORT_HSP_MODE;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, ".conf: Hot Swappable"));
	} else if (nxgep->niu_type == N2_NIU &&
	    ddi_prop_exists(DDI_DEV_T_ANY, nxgep->dip, 0,
	    "hot-swappable-phy") == 1) {
		nxgep->statsp->mac_stats.xcvr_inuse = HSP_XCVR;
		nxgep->mac.portmode = PORT_HSP_MODE;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "OBP: Hot Swappable"));
	}

	/*
	 * MDIO polling support for Monza RTM card, Goa NEM card
	 */
	if (nxgep->mac.portmode == PORT_HSP_MODE) {
		nxgep->hot_swappable_phy = B_TRUE;
		/*
		 * If this is the 2nd NIU port, then check 2 addresses
		 * to take care of the Goa NEM card. Port 1 can have addr 17
		 * (in the eval board) or 20 (in the P0 board).
		 */
		if (portn == 1) {
			if (nxge_is_phy_present(nxgep,
			    ALT_GOA_CLAUSE45_PORT1_ADDR, BCM8706_DEV_ID,
			    BCM_PHY_ID_MASK)) {
				nxgep->xcvr_addr =
				    ALT_GOA_CLAUSE45_PORT1_ADDR;
				goto found_phy;
			}
		}
		if (nxge_is_phy_present(nxgep,
		    GOA_CLAUSE45_PORT_ADDR_BASE + portn,
		    BCM8706_DEV_ID, BCM_PHY_ID_MASK)) {
			nxgep->xcvr_addr = GOA_CLAUSE45_PORT_ADDR_BASE +
			    portn;
			goto found_phy;
		}

		nxgep->phy_absent = B_TRUE;
		goto check_phy_done;
found_phy:
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
		nxgep->mac.portmode = PORT_10G_FIBER;
		nxgep->phy_absent = B_FALSE;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "10G Fiber Xcvr "
		    "found for hot swappable phy"));
check_phy_done:
		return (status);
	}

	/* Get phy-type property (May have been set by nxge.conf) */
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
		} else if (strcmp("xgf", prop_val) == 0) {
			/*
			 * Before OBP supports new phy-type property
			 * value "xgc", the 10G copper XAUI may carry
			 * "xgf" instead of "xgc". If the OBP is
			 * upgraded to a newer version which supports
			 * "xgc", then the TN1010 related code in this
			 * "xgf" case will not be used anymore.
			 */
			if (nxge_is_tn1010_phy(nxgep)) {
				if ((status = nxge_set_tn1010_param(nxgep))
				    != NXGE_OK) {
					return (status);
				}
				NXGE_DEBUG_MSG((nxgep, MAC_CTL, "TN1010 Xcvr"));
			} else {  /* For Fiber XAUI */
				nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
				nxgep->mac.portmode = PORT_10G_FIBER;
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "10G Fiber Xcvr"));
			}
		} else if (strcmp("xgc", prop_val) == 0) {
			if ((status = nxge_set_tn1010_param(nxgep)) != NXGE_OK)
				return (status);
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "TN1010 Xcvr"));
		}

		(void) ddi_prop_update_string(DDI_DEV_T_NONE, nxgep->dip,
		    "phy-type", prop_val);
		ddi_prop_free(prop_val);

		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_get_xcvr_type: "
		    "Got phy type [0x%x] from conf file",
		    nxgep->mac.portmode));

		return (NXGE_OK);
	}

	/* Get phy-type property from OBP */
	if (nxgep->niu_type == N2_NIU) {
		if (ddi_prop_lookup_string(DDI_DEV_T_ANY, nxgep->dip, 0,
		    "phy-type", &prop_val) == DDI_PROP_SUCCESS) {
			if (strcmp("xgf", prop_val) == 0) {
				/*
				 * Before OBP supports new phy-type property
				 * value "xgc", the 10G copper XAUI may carry
				 * "xgf" instead of "xgc". If the OBP is
				 * upgraded to a newer version which supports
				 * "xgc", then the TN1010 related code in this
				 * "xgf" case will not be used anymore.
				 */
				if (nxge_is_tn1010_phy(nxgep)) {
					if ((status =
					    nxge_set_tn1010_param(nxgep))
					    != NXGE_OK) {
						return (status);
					}
					NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					    "TN1010 Xcvr"));
				} else {  /* For Fiber XAUI */
					nxgep->statsp->mac_stats.xcvr_inuse
					    = XPCS_XCVR;
					nxgep->mac.portmode = PORT_10G_FIBER;
					NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					    "10G Fiber Xcvr"));
				}
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
				status = nxge_set_tn1010_param(nxgep);
				if (status != NXGE_OK)
					return (status);
				NXGE_DEBUG_MSG((nxgep, MAC_CTL, "TN1010 Xcvr"));
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

	if (strncmp(phy_type, "mif", 3) == 0) {
		nxgep->mac.portmode = PORT_1G_COPPER;
		nxgep->statsp->mac_stats.xcvr_inuse = INT_MII_XCVR;
	} else if (strncmp(phy_type, "xgf", 3) == 0) {
		nxgep->mac.portmode = PORT_10G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
	} else if (strncmp(phy_type, "pcs", 3) == 0) {
		nxgep->mac.portmode = PORT_1G_FIBER;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
	} else if (strncmp(phy_type, "xgc", 3) == 0) {
		status = nxge_set_tn1010_param(nxgep);
		if (status != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_get_xcvr_type: Failed to set TN1010 param"));
			goto read_seeprom;
		}
	} else if (strncmp(phy_type, "xgsd", 4) == 0) {
		nxgep->mac.portmode = PORT_10G_SERDES;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
	} else if (strncmp(phy_type, "gsd", 3) == 0) {
		nxgep->mac.portmode = PORT_1G_SERDES;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
	} else {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
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
	uint16_t	chip_id = 0;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_setup_xcvr_table: port<%d>",
	    portn));

	switch (nxgep->niu_type) {
	case N2_NIU:
		switch (nxgep->mac.portmode) {
		case PORT_1G_FIBER:
		case PORT_1G_SERDES:
			nxgep->xcvr = nxge_n2_1G_table;
			nxgep->xcvr_addr = portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "NIU 1G %s Xcvr",
			    (nxgep->mac.portmode == PORT_1G_FIBER) ? "Fiber" :
			    "Serdes"));
			break;
		case PORT_10G_FIBER:
		case PORT_10G_SERDES:
			nxgep->xcvr = nxge_n2_10G_table;
			if (nxgep->nxge_hw_p->xcvr_addr[portn]) {
				nxgep->xcvr_addr =
				    nxgep->nxge_hw_p->xcvr_addr[portn];
			}
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "NIU 10G %s Xcvr",
			    (nxgep->mac.portmode == PORT_10G_FIBER) ? "Fiber" :
			    "Serdes"));
			break;
		case PORT_1G_TN1010:
			nxgep->xcvr = nxge_n2_1G_tn1010_table;
			nxgep->xcvr_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "TN1010 Copper Xcvr in 1G"));
			break;
		case PORT_10G_TN1010:
			nxgep->xcvr = nxge_n2_10G_tn1010_table;
			nxgep->xcvr_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "TN1010 Copper Xcvr in 10G"));
			break;
		case PORT_HSP_MODE:
			nxgep->xcvr = nxge_n2_10G_table;
			nxgep->xcvr.xcvr_inuse = HSP_XCVR;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "NIU 10G Hot "
			    "Swappable Xcvr (not present)"));
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
			/* Ports 2 and 3 of Alonso or ARTM */
			case NXGE_PORT_1G_RGMII_FIBER:
				nxgep->mac.portmode = PORT_1G_RGMII_FIBER;
				break;
			case NXGE_PORT_TN1010:
				/*
				 * If this port uses the TN1010 copper
				 * PHY, then its speed is not known yet
				 * because nxge_scan_ports_phy could only
				 * figure out the vendor of the PHY but
				 * not its speed. nxge_set_tn1010_param
				 * will read the PHY speed and set
				 * portmode accordingly.
				 */
				if ((status = nxge_set_tn1010_param(nxgep))
				    != NXGE_OK) {
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "nxge_set_tn1010_param failed"));
					return (status);
				}
				break;
			default:
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "<== nxge_setup_xcvr_table: "
				    "Unknown port-type: 0x%x", port_type));
				return (NXGE_ERROR);
			}
		}

		/*
		 * Above switch has figured out nxge->mac.portmode, now set
		 * nxgep->xcvr (the table) and nxgep->xcvr_addr according
		 * to portmode.
		 */
		switch (nxgep->mac.portmode) {
		case PORT_1G_COPPER:
		case PORT_1G_RGMII_FIBER:
			nxgep->xcvr = nxge_1G_copper_table;
			nxgep->xcvr_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
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
					nxgep->xcvr_addr += 3;
					break;
				case 1:
					nxgep->xcvr_addr += 1;
					break;
				case 2:
					nxgep->xcvr_addr -= 1;
					break;
				case 3:
					nxgep->xcvr_addr -= 3;
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

		case PORT_1G_TN1010:
			nxgep->xcvr = nxge_1G_tn1010_table;
			nxgep->xcvr_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "1G TN1010 copper Xcvr"));
			break;

		case PORT_10G_TN1010:
			nxgep->xcvr = nxge_10G_tn1010_table;
			nxgep->xcvr_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "10G TN1010 copper Xcvr"));
			break;

		case PORT_1G_FIBER:
		case PORT_1G_SERDES:
			nxgep->xcvr = nxge_1G_fiber_table;
			nxgep->xcvr_addr = portn;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "1G %s Xcvr",
			    (nxgep->mac.portmode == PORT_1G_FIBER) ?
			    "Fiber" : "Serdes"));
			break;
		case PORT_10G_FIBER:
		case PORT_10G_SERDES:
			nxgep->xcvr = nxge_10G_fiber_table;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "10G xcvr "
			    "nxgep->nxge_hw_p->xcvr_addr[portn] = [%d] "
			    "nxgep->xcvr_addr = [%d]",
			    nxgep->nxge_hw_p->xcvr_addr[portn],
			    nxgep->xcvr_addr));
			if (nxgep->nxge_hw_p->xcvr_addr[portn]) {
				nxgep->xcvr_addr =
				    nxgep->nxge_hw_p->xcvr_addr[portn];
			}
			switch (nxgep->platform_type) {
			case P_NEPTUNE_MARAMBA_P0:
			case P_NEPTUNE_MARAMBA_P1:
				/*
				 * Switch off LED for corresponding copper
				 * port
				 */
				nxge_bcm5464_link_led_off(nxgep);
				break;
			default:
				break;
			}
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "10G %s Xcvr",
			    (nxgep->mac.portmode == PORT_10G_FIBER) ?
			    "Fiber" : "Serdes"));
			break;

		case PORT_HSP_MODE:
			nxgep->xcvr = nxge_10G_fiber_table;
			nxgep->xcvr.xcvr_inuse = HSP_XCVR;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Neptune 10G Hot "
			    "Swappable Xcvr (not present)"));
			break;
		default:
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "Unknown port-type: 0x%x", port_type));
			return (NXGE_ERROR);
		}
	}

	if (nxgep->mac.portmode == PORT_10G_FIBER) {
		uint32_t pma_pmd_id;
		pma_pmd_id = nxge_get_cl45_pma_pmd_id(nxgep,
		    nxgep->xcvr_addr);
		if ((pma_pmd_id & BCM_PHY_ID_MASK) == MARVELL_88X201X_PHY_ID) {
			chip_id = MRVL88X201X_CHIP_ID;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "nxge_setup_xcvr_table: "
			    "Chip ID  MARVELL [0x%x] for 10G xcvr", chip_id));
		} else if ((status = nxge_mdio_read(nxgep, nxgep->xcvr_addr,
		    BCM8704_PCS_DEV_ADDR, BCM8704_CHIP_ID_REG,
		    &chip_id)) == NXGE_OK) {

			switch (chip_id) {
			case BCM8704_CHIP_ID:
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "nxge_setup_xcvr_table: "
				    "Chip ID 8704 [0x%x] for 10G xcvr",
				    chip_id));
				break;
			case BCM8706_CHIP_ID:
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "nxge_setup_xcvr_table: "
				    "Chip ID 8706 [0x%x] for 10G xcvr",
				    chip_id));
				break;
			default:
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "nxge_setup_xcvr_table: "
				    "Unknown Chip ID [0x%x] for 10G xcvr",
				    chip_id));
				break;
			}
		}
	}

	nxgep->statsp->mac_stats.xcvr_inuse = nxgep->xcvr.xcvr_inuse;
	nxgep->statsp->mac_stats.xcvr_portn = nxgep->xcvr_addr;
	nxgep->chip_id = chip_id;

	/*
	 * Get the actual device ID value returned by MDIO read.
	 */
	nxgep->statsp->mac_stats.xcvr_id = 0;

	pma_pmd_id = nxge_get_cl45_pma_pmd_id(nxgep, nxgep->xcvr_addr);
	if (nxge_is_supported_phy(pma_pmd_id, CLAUSE_45_TYPE)) {
		nxgep->statsp->mac_stats.xcvr_id = pma_pmd_id;
	} else {
		pcs_id = nxge_get_cl45_pcs_id(nxgep, nxgep->xcvr_addr);
		if (nxge_is_supported_phy(pcs_id, CLAUSE_45_TYPE)) {
			nxgep->statsp->mac_stats.xcvr_id = pcs_id;
		} else {
			phy_id = nxge_get_cl22_phy_id(nxgep,
			    nxgep->xcvr_addr);
			if (nxge_is_supported_phy(phy_id, CLAUSE_22_TYPE)) {
				nxgep->statsp->mac_stats.xcvr_id = phy_id;
			}
		}
	}

	nxgep->mac.linkchkmode = LINKCHK_TIMER;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_setup_xcvr_table: niu_type"
	    "[0x%x] platform type[0x%x] xcvr_arr[%d]", nxgep->niu_type,
	    nxgep->platform_type, nxgep->xcvr_addr));

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

	/* Initialize MAC control configuration */
	if ((status = nxge_mac_ctrl_init(nxgep)) != NXGE_OK) {
		goto fail;
	}

	nxgep->statsp->mac_stats.mac_mtu = nxgep->mac.maxframesize;

	/* The Neptune Serdes needs to be reinitialized again */
	if ((NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) &&
	    ((nxgep->mac.portmode == PORT_1G_SERDES) ||
	    (nxgep->mac.portmode == PORT_1G_TN1010) ||
	    (nxgep->mac.portmode == PORT_1G_FIBER)) &&
	    ((portn == 0) || (portn == 1))) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_mac_init: reinit Neptune 1G Serdes "));
		if ((status = nxge_1G_serdes_init(nxgep)) != NXGE_OK) {
			goto fail;
		}
	}


	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_mac_init: port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_mac_init: failed to initialize MAC port<%d>", portn));
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
	if (nxgep->hot_swappable_phy && nxgep->phy_absent) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_init: "
		    "Phy not present, cannot initialize link"));
		return (status);
	}

	portmode = nxgep->mac.portmode;

	/*
	 * Workaround to get link up in both NIU ports. Some portmodes require
	 * that the xcvr be initialized twice, the first time before calling
	 * nxge_serdes_init.
	 */
	if (nxgep->niu_type == N2_NIU && (portmode != PORT_10G_SERDES) &&
	    (portmode != PORT_10G_TN1010) &&
	    (portmode != PORT_1G_TN1010) &&
	    (portmode != PORT_1G_SERDES)) {
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
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_link_init: ",
	    "failed to initialize Ethernet link on port<%d>", portn));

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

	if ((NXGE_IS_VALID_NEPTUNE_TYPE(nxgep)) &&
	    ((nxgep->mac.portmode == PORT_1G_SERDES) ||
	    (nxgep->mac.portmode == PORT_1G_TN1010) ||
	    (nxgep->mac.portmode == PORT_1G_FIBER)) &&
	    ((portn == 0) || (portn == 1))) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_xcvr_init: set ATCA mode"));
		npi_mac_mif_set_atca_mode(nxgep->npi_handle, B_TRUE);
	}

	if (portt == PORT_TYPE_XMAC) {

		/* Setup XIF Configuration for XMAC */

		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_COPPER) ||
		    (portmode == PORT_10G_TN1010) ||
		    (portmode == PORT_10G_SERDES))
			xif_cfg |= CFG_XMAC_XIF_LFS;

		/* Bypass PCS so that RGMII will be used */
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
		    (portmode == PORT_10G_TN1010) ||
		    (portmode == PORT_1G_TN1010) ||
		    (portmode == PORT_10G_SERDES)) {
			/* Assume LED same for 1G and 10G */
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
		    (portmode == PORT_10G_TN1010) ||
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
		    (portmode == PORT_1G_SERDES) ||
		    (portmode == PORT_1G_TN1010) ||
		    (portmode == PORT_1G_RGMII_FIBER)) {
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "nxge_xif_init: Port[%d] Mode[%d] Speed[%d]",
			    portn, portmode, statsp->mac_stats.link_speed));
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

		/* Enable ATCA mode */

	} else if (portt == PORT_TYPE_BMAC) {

		/* Setup XIF Configuration for BMAC */

		if ((portmode == PORT_1G_COPPER) ||
		    (portmode == PORT_1G_RGMII_FIBER)) {
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
	    "nxge_xif_init: Failed to initialize XIF port<%d>", portn));
	return (NXGE_ERROR | rs);
}


/*
 * Initialize the PCS sub-block in the MAC.  Note that PCS does not
 * support loopback like XPCS.
 */
nxge_status_t
nxge_pcs_init(p_nxge_t nxgep)
{
	pcs_cfg_t		pcs_cfg;
	uint32_t		val;
	uint8_t			portn;
	nxge_port_mode_t	portmode;
	npi_handle_t		handle;
	p_nxge_stats_t		statsp;
	pcs_ctrl_t		pcs_ctrl;
	npi_status_t		rs = NPI_SUCCESS;
	uint8_t i;

	handle = nxgep->npi_handle;
	portmode = nxgep->mac.portmode;
	portn = nxgep->mac.portnum;
	statsp = nxgep->statsp;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_pcs_init: port<%d>", portn));

	if (portmode == PORT_1G_FIBER ||
	    portmode == PORT_1G_TN1010 ||
	    portmode == PORT_1G_SERDES) {
		if (portmode == PORT_1G_TN1010) {
			/* Reset PCS multiple time in PORT_1G_TN1010 mode */
			for (i = 0; i < 6; i ++) {
				if ((rs = npi_mac_pcs_reset(handle, portn))
				    != NPI_SUCCESS) {
					goto fail;
				}
			}
		} else {
			if ((rs = npi_mac_pcs_reset(handle, portn))
			    != NPI_SUCCESS)
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

		if (portmode == PORT_1G_TN1010) {
			/*
			 * Must disable PCS auto-negotiation when the the driver
			 * is driving the TN1010 based XAUI card  Otherwise the
			 * autonegotiation between the PCS and the TN1010 PCS
			 * will never complete and the Neptune/NIU will not work
			 */
			pcs_ctrl.value = 0;
			PCS_REG_WR(handle, portn, PCS_MII_CTRL_REG,
			    pcs_ctrl.value);
		}
	} else if (portmode == PORT_10G_FIBER ||
	    portmode == PORT_10G_COPPER ||
	    portmode == PORT_10G_TN1010 ||
	    portmode == PORT_10G_SERDES) {
		/* Use internal XPCS, bypass 1G PCS */
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);
		val &= ~XMAC_XIF_XPCS_BYPASS;
		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);

		if ((rs = npi_xmac_xpcs_reset(handle, portn)) != NPI_SUCCESS)
			goto fail;

		/* Set XPCS Internal Loopback if necessary */
		if ((rs = npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_CONTROL1, &val)) != NPI_SUCCESS)
			goto fail;

		if ((statsp->port_stats.lb_mode == nxge_lb_mac10g) ||
		    (statsp->port_stats.lb_mode == nxge_lb_mac1000))
			val |= XPCS_CTRL1_LOOPBK;
		else
			val &= ~XPCS_CTRL1_LOOPBK;
		if ((rs = npi_xmac_xpcs_write(handle, portn,
		    XPCS_REG_CONTROL1, val)) != NPI_SUCCESS)
			goto fail;

		/* Clear descw errors */
		if ((rs = npi_xmac_xpcs_write(handle, portn,
		    XPCS_REG_DESCWERR_COUNTER, 0)) != NPI_SUCCESS)
			goto fail;
		/* Clear symbol errors */
		if ((rs = npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &val)) != NPI_SUCCESS)
			goto fail;
		if ((rs = npi_xmac_xpcs_read(handle, portn,
		    XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &val)) != NPI_SUCCESS)
			goto fail;

	} else if ((portmode == PORT_1G_COPPER) ||
	    (portmode == PORT_1G_RGMII_FIBER)) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_pcs_init: (1G) copper port<%d>", portn));
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
	    "nxge_pcs_init: Failed to initialize PCS port<%d>", portn));
	return (NXGE_ERROR | rs);
}

/*
 * Initialize the MAC CTRL sub-block within the MAC
 * Only the receive-pause-cap is supported.
 */
nxge_status_t
nxge_mac_ctrl_init(p_nxge_t nxgep)
{
	uint8_t			portn;
	nxge_port_t		portt;
	p_nxge_stats_t		statsp;
	npi_handle_t		handle;
	uint32_t		val;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mac_ctrl_init: port<%d>",
	    portn));

	handle = nxgep->npi_handle;
	portt = nxgep->mac.porttype;
	statsp = nxgep->statsp;

	if (portt == PORT_TYPE_XMAC) {
		/* Reading the current XMAC Config Register for XMAC */
		XMAC_REG_RD(handle, portn, XMAC_CONFIG_REG, &val);

		/*
		 * Setup XMAC Configuration for XMAC
		 * XMAC only supports receive-pause
		 */
		if (statsp->mac_stats.adv_cap_asmpause) {
			if (!statsp->mac_stats.adv_cap_pause) {
				/*
				 * If adv_cap_asmpause is 1 and adv_cap_pause
				 * is 0, enable receive pause.
				 */
				val |= XMAC_RX_CFG_RX_PAUSE_EN;
			} else {
				/*
				 * If adv_cap_asmpause is 1 and adv_cap_pause
				 * is 1, disable receive pause.  Send pause is
				 * not supported.
				 */
				val &= ~XMAC_RX_CFG_RX_PAUSE_EN;
			}
		} else {
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "==> nxge_mac_ctrl_init: port<%d>: pause",
			    portn));
			if (statsp->mac_stats.adv_cap_pause) {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "==> nxge_mac_ctrl_init: port<%d>: "
				    "enable pause", portn));
				/*
				 * If adv_cap_asmpause is 0 and adv_cap_pause
				 * is 1, enable receive pause.
				 */
				val |= XMAC_RX_CFG_RX_PAUSE_EN;
			} else {
				/*
				 * If adv_cap_asmpause is 0 and adv_cap_pause
				 * is 0, disable receive pause. Send pause is
				 * not supported
				 */
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "==> nxge_mac_ctrl_init: port<%d>: "
				    "disable pause", portn));
				val &= ~XMAC_RX_CFG_RX_PAUSE_EN;
			}
		}
		XMAC_REG_WR(handle, portn, XMAC_CONFIG_REG, val);
	} else if (portt == PORT_TYPE_BMAC) {
		/* Reading the current MAC CTRL Config Register for BMAC */
		BMAC_REG_RD(handle, portn, MAC_CTRL_CONFIG_REG, &val);

		/* Setup MAC CTRL Configuration for BMAC */
		if (statsp->mac_stats.adv_cap_asmpause) {
			if (statsp->mac_stats.adv_cap_pause) {
				/*
				 * If adv_cap_asmpause is 1 and adv_cap_pause
				 * is 1, disable receive pause. Send pause
				 * is not supported
				 */
				val &= ~MAC_CTRL_CFG_RECV_PAUSE_EN;
			} else {
				/*
				 * If adv_cap_asmpause is 1 and adv_cap_pause
				 * is 0, enable receive pause and disable
				 * send pause.
				 */
				val |= MAC_CTRL_CFG_RECV_PAUSE_EN;
				val &= ~MAC_CTRL_CFG_SEND_PAUSE_EN;
			}
		} else {
			if (statsp->mac_stats.adv_cap_pause) {
				/*
				 * If adv_cap_asmpause is 0 and adv_cap_pause
				 * is 1, enable receive pause. Send pause is
				 * not supported.
				 */
				val |= MAC_CTRL_CFG_RECV_PAUSE_EN;
			} else {
				/*
				 * If adv_cap_asmpause is 0 and adv_cap_pause
				 * is 0, pause capability is not available in
				 * either direction.
				 */
				val &= (~MAC_CTRL_CFG_SEND_PAUSE_EN &
				    ~MAC_CTRL_CFG_RECV_PAUSE_EN);
			}
		}
		BMAC_REG_WR(handle, portn, MAC_CTRL_CONFIG_REG, val);
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_mac_ctrl_init: port<%d>",
	    portn));

	return (NXGE_OK);
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

	/*
	 * If the nxge driver has been plumbed without a link, then it will
	 * detect a link up when a cable connecting to an anto-negotiation
	 * partner is plugged into the port. Because the TN1010 PHY supports
	 * both 1G and 10G speeds, the driver must re-configure the
	 * Neptune/NIU according to the negotiated speed.  nxge_n2_serdes_init
	 * is called at the post-link-up reconfiguration time. Here it calls
	 * nxge_set_tn1010_param to set portmode before re-initializing
	 * the serdes.
	 */
	if (nxgep->mac.portmode == PORT_1G_TN1010 ||
	    nxgep->mac.portmode == PORT_10G_TN1010) {
		if (nxge_set_tn1010_param(nxgep) != NXGE_OK) {
			goto fail;
		}
	}

	if (nxgep->mac.portmode == PORT_10G_FIBER ||
	    nxgep->mac.portmode == PORT_10G_TN1010 ||
	    nxgep->mac.portmode == PORT_10G_SERDES) {
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
			    ESR_N2_TEST_CFG_REG, test_cfg.value)) != NXGE_OK)
			goto fail;
		}

		/* Initialize PLL for 10G */
		pll_cfg_l.bits.mpy = CFGPLL_MPY_10X;
		pll_cfg_l.bits.enpll = 1;
		pll_sts_l.bits.enpll = 1;
		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_PLL_CFG_L_REG, pll_cfg_l.value)) != NXGE_OK)
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
	} else if (nxgep->mac.portmode == PORT_1G_FIBER ||
	    nxgep->mac.portmode == PORT_1G_TN1010 ||
	    nxgep->mac.portmode == PORT_1G_SERDES) {
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

		/* Initialize PLL for 1G */
		pll_cfg_l.bits.mpy = CFGPLL_MPY_8X;
		pll_cfg_l.bits.enpll = 1;
		pll_sts_l.bits.enpll = 1;
		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_PLL_CFG_L_REG, pll_cfg_l.value)) != NXGE_OK)
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
		    ESR_N2_TX_CFG_L_REG_ADDR(chan), tx_cfg_l.value)) != NXGE_OK)
			goto fail;

		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_TX_CFG_H_REG_ADDR(chan), tx_cfg_h.value)) != NXGE_OK)
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
		    ESR_N2_RX_CFG_L_REG_ADDR(chan), rx_cfg_l.value)) != NXGE_OK)
			goto fail;

		if ((status = nxge_mdio_write(nxgep, portn, ESR_N2_DEV_ADDR,
		    ESR_N2_RX_CFG_H_REG_ADDR(chan), rx_cfg_h.value)) != NXGE_OK)
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
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
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
	int			chan, i;
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
		/* Reset Serdes */
		ESR_REG_WR(handle, ESR_RESET_REG, ESR_RESET_0);
		NXGE_DELAY(20);
		ESR_REG_WR(handle, ESR_RESET_REG, 0x0);
		NXGE_DELAY(2000);

		/* Configure Serdes to 10G mode */
		ESR_REG_WR(handle, ESR_0_PLL_CONFIG_REG,
		    ESR_PLL_CFG_10G_SERDES);

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
		/* Reset Serdes */
		ESR_REG_WR(handle, ESR_RESET_REG, ESR_RESET_1);
		NXGE_DELAY(20);
		ESR_REG_WR(handle, ESR_RESET_REG, 0x0);
		NXGE_DELAY(2000);

		/* Configure Serdes to 10G mode */
		ESR_REG_WR(handle, ESR_1_PLL_CONFIG_REG,
		    ESR_PLL_CFG_10G_SERDES);

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
		    "Failed to reset port<%d> XAUI Serdes "
		    "(val16l 0x%x val16h 0x%x)",
		    portn, val16l, val16h));
	}

	if (portn == 0) {
		/* Wait for serdes to be ready */
		for (i = 0; i < MAX_SERDES_RDY_RETRIES; i++) {
			ESR_REG_RD(handle, ESR_INTERNAL_SIGNALS_REG, &val);
			if ((val & ESR_SIG_P0_BITS_MASK) !=
			    (ESR_SIG_SERDES_RDY0_P0 | ESR_SIG_DETECT0_P0 |
			    ESR_SIG_XSERDES_RDY_P0 |
			    ESR_SIG_XDETECT_P0_CH3 |
			    ESR_SIG_XDETECT_P0_CH2 |
			    ESR_SIG_XDETECT_P0_CH1 |
			    ESR_SIG_XDETECT_P0_CH0))

				NXGE_DELAY(SERDES_RDY_WT_INTERVAL);
			else
				break;
		}

		if (i == MAX_SERDES_RDY_RETRIES) {
			/*
			 * RDY signal stays low may due to the absent of the
			 * external PHY, it is not an error condition. But still
			 * print the message for the debugging purpose when link
			 * stays down
			 */
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_neptune_10G_serdes_init: "
			    "Serdes/signal for port<%d> not ready", portn));
				goto done;
		}
	} else if (portn == 1) {
		/* Wait for serdes to be ready */
		for (i = 0; i < MAX_SERDES_RDY_RETRIES; i++) {
			ESR_REG_RD(handle, ESR_INTERNAL_SIGNALS_REG, &val);
			if ((val & ESR_SIG_P1_BITS_MASK) !=
			    (ESR_SIG_SERDES_RDY0_P1 | ESR_SIG_DETECT0_P1 |
			    ESR_SIG_XSERDES_RDY_P1 |
			    ESR_SIG_XDETECT_P1_CH3 |
			    ESR_SIG_XDETECT_P1_CH2 |
			    ESR_SIG_XDETECT_P1_CH1 |
			    ESR_SIG_XDETECT_P1_CH0))

				NXGE_DELAY(SERDES_RDY_WT_INTERVAL);
			else
				break;
		}

		if (i == MAX_SERDES_RDY_RETRIES) {
			/*
			 * RDY signal stays low may due to the absent of the
			 * external PHY, it is not an error condition. But still
			 * print the message for the debugging purpose when link
			 * stays down
			 */
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_neptune_10G_serdes_init: "
			    "Serdes/signal for port<%d> not ready", portn));
				goto done;
		}
	}

done:
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_neptune_10G_serdes_init port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
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

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_1G_serdes_init port<%d>", portn));

	handle = nxgep->npi_handle;

	switch (portn) {
	case 0:
		/* Assert the reset register */
		ESR_REG_RD(handle, ESR_RESET_REG, &val);
		val |= ESR_RESET_0;
		ESR_REG_WR(handle, ESR_RESET_REG, val);

		/* Set the PLL register to 0x79 */
		ESR_REG_WR(handle, ESR_0_PLL_CONFIG_REG,
		    ESR_PLL_CFG_1G_SERDES);

		/* Set the control register to 0x249249f */
		ESR_REG_WR(handle, ESR_0_CONTROL_REG, ESR_CTL_1G_SERDES);

		/* Set Serdes0 Internal Loopback if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes1000) {
			/* Set pad loopback modes 0xaa */
			ESR_REG_WR(handle, ESR_0_TEST_CONFIG_REG,
			    ESR_TSTCFG_LBTEST_PAD);
		} else {
			ESR_REG_WR(handle, ESR_0_TEST_CONFIG_REG, 0);
		}

		/* Deassert the reset register */
		ESR_REG_RD(handle, ESR_RESET_REG, &val);
		val &= ~ESR_RESET_0;
		ESR_REG_WR(handle, ESR_RESET_REG, val);
		break;

	case 1:
		/* Assert the reset register */
		ESR_REG_RD(handle, ESR_RESET_REG, &val);
		val |= ESR_RESET_1;
		ESR_REG_WR(handle, ESR_RESET_REG, val);

		/* Set PLL register to 0x79 */
		ESR_REG_WR(handle, ESR_1_PLL_CONFIG_REG,
		    ESR_PLL_CFG_1G_SERDES);

		/* Set the control register to 0x249249f */
		ESR_REG_WR(handle, ESR_1_CONTROL_REG, ESR_CTL_1G_SERDES);

		/* Set Serdes1 Internal Loopback if necessary */
		if (nxgep->statsp->port_stats.lb_mode == nxge_lb_serdes1000) {
			/* Set pad loopback mode 0xaa */
			ESR_REG_WR(handle, ESR_1_TEST_CONFIG_REG,
			    ESR_TSTCFG_LBTEST_PAD);
		} else {
			ESR_REG_WR(handle, ESR_1_TEST_CONFIG_REG, 0);
		}

		/* Deassert the reset register */
		ESR_REG_RD(handle, ESR_RESET_REG, &val);
		val &= ~ESR_RESET_1;
		ESR_REG_WR(handle, ESR_RESET_REG, val);
		break;

	default:
		/* Nothing to do here */
		goto done;
	}

	/* init TX RX channels */
	for (chan = 0; chan < 4; chan++) {
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_L_ADDR(chan),
		    &rx_tx_ctrl_l.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_H_ADDR(chan),
		    &rx_tx_ctrl_h.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_L_ADDR(chan),
		    &glue_ctrl0_l.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_read(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_H_ADDR(chan),
		    &glue_ctrl0_h.value)) != NXGE_OK) {
			goto fail;
		}

		rx_tx_ctrl_l.bits.enstretch = 1;
		rx_tx_ctrl_h.bits.vmuxlo = 2;
		rx_tx_ctrl_h.bits.vpulselo = 2;
		glue_ctrl0_l.bits.rxlosenable = 1;
		glue_ctrl0_l.bits.samplerate = 0xF;
		glue_ctrl0_l.bits.thresholdcount = 0xFF;
		glue_ctrl0_h.bits.bitlocktime = BITLOCKTIME_300_CYCLES;
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_L_ADDR(chan),
		    rx_tx_ctrl_l.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_RX_TX_CONTROL_H_ADDR(chan),
		    rx_tx_ctrl_h.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_L_ADDR(chan),
		    glue_ctrl0_l.value)) != NXGE_OK) {
			goto fail;
		}
		if ((status = nxge_mdio_write(nxgep, portn,
		    ESR_NEPTUNE_DEV_ADDR, ESR_NEP_GLUE_CONTROL0_H_ADDR(chan),
		    glue_ctrl0_h.value)) != NXGE_OK) {
			goto fail;
		}
	}

	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_POWER_CONTROL_L_ADDR(), 0xfff)) != NXGE_OK) {
		goto fail;
	}
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_POWER_CONTROL_H_ADDR(), 0xfff)) != NXGE_OK) {
		goto fail;
	}
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_TX_POWER_CONTROL_L_ADDR(), 0x70)) != NXGE_OK) {
		goto fail;
	}
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_TX_POWER_CONTROL_H_ADDR(), 0xfff)) != NXGE_OK) {
		goto fail;
	}

	/* Apply Tx core reset */
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(), (uint16_t)0)) != NXGE_OK) {
		goto fail;
	}

	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), (uint16_t)0xffff)) !=
	    NXGE_OK) {
		goto fail;
	}

	NXGE_DELAY(200);

	/* Apply Rx core reset */
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(), (uint16_t)0xffff)) !=
	    NXGE_OK) {
		goto fail;
	}

	NXGE_DELAY(200);
	if ((status = nxge_mdio_write(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), (uint16_t)0)) != NXGE_OK) {
		goto fail;
	}

	NXGE_DELAY(200);
	if ((status = nxge_mdio_read(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_L_ADDR(), &val16l)) != NXGE_OK) {
		goto fail;
	}
	if ((status = nxge_mdio_read(nxgep, portn, ESR_NEPTUNE_DEV_ADDR,
	    ESR_NEP_RX_TX_RESET_CONTROL_H_ADDR(), &val16h)) != NXGE_OK) {
		goto fail;
	}
	if ((val16l != 0) || (val16h != 0)) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "Failed to reset port<%d> XAUI Serdes "
		    "(val16l 0x%x val16h 0x%x)", portn, val16l, val16h));
		status = NXGE_ERROR;
		goto fail;
	}

	NXGE_DELAY(200);
	ESR_REG_RD(handle, ESR_INTERNAL_SIGNALS_REG, &val);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_neptune_serdes_init: read internal signal reg port<%d> "
	    "val 0x%x", portn, val));
	if (portn == 0) {
		if ((val & ESR_SIG_P0_BITS_MASK_1G) !=
		    (ESR_SIG_SERDES_RDY0_P0 | ESR_SIG_DETECT0_P0)) {
			/*
			 * RDY signal stays low may due to the absent of the
			 * external PHY, it is not an error condition. But still
			 * print the message for the debugging purpose when link
			 * stays down
			 */
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_neptune_1G_serdes_init: "
			    "Serdes/signal for port<%d> not ready", portn));
				goto done;
		}
	} else if (portn == 1) {
		if ((val & ESR_SIG_P1_BITS_MASK_1G) !=
		    (ESR_SIG_SERDES_RDY0_P1 | ESR_SIG_DETECT0_P1)) {
			/*
			 * RDY signal stays low may due to the absent of the
			 * external PHY, it is not an error condition. But still
			 * print the message for the debugging purpose when link
			 * stays down
			 */
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_neptune_1G_serdes_init: "
			    "Serdes/signal for port<%d> not ready", portn));
				goto done;

		}
	}
done:

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_1G_serdes_init port<%d>", portn));
	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_1G_serdes_init: "
	    "Failed to initialize Neptune serdes for port<%d>",
	    portn));

	return (status);
}

/* Initialize the BCM 8704 xcvr */

static nxge_status_t
nxge_BCM8704_xcvr_init(p_nxge_t nxgep)
{
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
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_BCM8704_xcvr_init: port<%d>",
	    portn));

	phy_port_addr = nxgep->statsp->mac_stats.xcvr_portn;

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
	if (NXGE_IS_XAUI_PLATFORM(nxgep)) {
		op_ctr.bits.gpio_sel = 0x1;
	} else {
		op_ctr.bits.gpio_sel = 0x3;
	}
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
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_ANALOG_STATUS0_REG, &val);
	if (status != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_TX_ALARM_STATUS_REG, &val1);
	if (status != NXGE_OK)
		goto fail;

	status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_TX_ALARM_STATUS_REG, &val1);
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

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_BCM8704_xcvr_init: port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_BCM8704_xcvr_init: failed to initialize transceiver for "
	    "port<%d>", nxgep->mac.portnum));
	return (NXGE_ERROR);
}

/* Initialize the BCM 8706 Transceiver */

static nxge_status_t
nxge_BCM8706_xcvr_init(p_nxge_t nxgep)
{
	uint8_t			phy_port_addr;
	phyxs_control_t		phyxs_ctl;
	pcs_control_t		pcs_ctl;
	uint32_t		delay = 0;
	optics_dcntr_t		op_ctr;
	nxge_status_t		status = NXGE_OK;
#ifdef	NXGE_DEBUG
	uint8_t			portn = nxgep->mac.portnum;
#endif

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_BCM8706_xcvr_init: port<%d>",
	    portn));

	phy_port_addr = nxgep->statsp->mac_stats.xcvr_portn;

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

	NXGE_DELAY(1000000);

	/* Set BCM8706 Internal Loopback mode if necessary */
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

	/* Enable Tx and Rx LEDs to be driven by traffic */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_OPTICS_DIGITAL_CTRL_REG,
	    &op_ctr.value)) != NXGE_OK)
		goto fail;
	op_ctr.bits.gpio_sel = 0x3;
	op_ctr.bits.res2 = 0x1;

	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    BCM8704_USER_DEV3_ADDR, BCM8704_USER_OPTICS_DIGITAL_CTRL_REG,
	    op_ctr.value)) != NXGE_OK)
		goto fail;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_BCM8706_xcvr_init: port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_BCM8706_xcvr_init: failed to initialize transceiver for "
	    "port<%d>", nxgep->mac.portnum));
	return (status);
}

#define	CHK_STAT(x)	status = (x); if (status != NXGE_OK) goto fail

#define	MRVL88X2011_RD(nxgep, port, d, r, p) \
	CHK_STAT(nxge_mdio_read(nxgep, port, d, r, p))

#define	MRVL88X2011_WR(nxgep, port, d, r, p) \
	CHK_STAT(nxge_mdio_write(nxgep, port, d, r, p))


static void
nxge_mrvl88x2011_led_blink_rate(p_nxge_t nxgep, uint16_t rate)
{
	uint16_t	value;
	uint8_t phy = nxgep->statsp->mac_stats.xcvr_portn;

	if (nxge_mdio_read(nxgep, phy, MRVL_88X2011_USER_DEV2_ADDR,
	    MRVL_88X2011_LED_BLINK_CTL, &value) == NXGE_OK) {
		value &= ~MRVL_88X2011_LED_BLK_MASK;
		value |= (rate << MRVL_88X2011_LED_BLK_SHIFT);
		(void) nxge_mdio_write(nxgep, phy,
		    MRVL_88X2011_USER_DEV2_ADDR, MRVL_88X2011_LED_BLINK_CTL,
		    value);
	}
}

static nxge_status_t
nxge_mrvl88x2011_setup_lb(p_nxge_t nxgep)
{
	nxge_status_t	status;
	pcs_control_t	pcs_ctl;
	uint8_t phy = nxgep->statsp->mac_stats.xcvr_portn;

	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_PMA_PMD_CTL_1, &pcs_ctl.value);

	if (nxgep->statsp->port_stats.lb_mode == nxge_lb_phy10g)
		pcs_ctl.bits.loopback = 1;
	else
		pcs_ctl.bits.loopback = 0;

	MRVL88X2011_WR(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_PMA_PMD_CTL_1, pcs_ctl.value);

fail:
	return (status);
}


static void
nxge_mrvl88x2011_led(p_nxge_t nxgep,  uint16_t val)
{
	uint16_t	val2;
	uint8_t phy = nxgep->statsp->mac_stats.xcvr_portn;

	val2 = MRVL_88X2011_LED(MRVL_88X2011_LED_ACT, val);
	val2 &= ~MRVL_88X2011_LED(MRVL_88X2011_LED_ACT,
	    MRVL_88X2011_LED_CTL_MASK);
	val2 |= MRVL_88X2011_LED(MRVL_88X2011_LED_ACT, val);

	if (nxge_mdio_write(nxgep, phy, MRVL_88X2011_USER_DEV2_ADDR,
	    MRVL_88X2011_LED_8_TO_11_CTL, val2) != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_mrvl88x2011_led: nxge_mdio_write failed!!"));
	}
}


static nxge_status_t
nxge_mrvl88x2011_xcvr_init(p_nxge_t nxgep)
{
	uint8_t		phy;
	nxge_status_t	status;
	uint16_t	clk;

	phy = nxgep->statsp->mac_stats.xcvr_portn;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_mrvl88x2011_xcvr_init: port<%d> addr<0x%x>",
	    nxgep->mac.portnum, phy));

	/* Set LED functions	*/
	nxge_mrvl88x2011_led_blink_rate(nxgep, MRVL_88X2011_LED_BLK134MS);
	/* PCS activity */
	nxge_mrvl88x2011_led(nxgep, MRVL_88X2011_LED_ACT);

	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_GEN_CTL, &clk);
	clk |= MRVL_88X2011_ENA_XFPREFCLK;
	MRVL88X2011_WR(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_GEN_CTL, clk);

	/* Set internal loopback mode if necessary */

	CHK_STAT(nxge_mrvl88x2011_setup_lb(nxgep));

	/* Enable PMD */
	MRVL88X2011_WR(nxgep, phy, MRVL_88X2011_USER_DEV1_ADDR,
	    MRVL_88X2011_10G_PMD_TX_DIS, MRVL_88X2011_ENA_PMDTX);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, " nxge_mrvl88x2011_reset: OK"));

fail:
	return (status);
}



/* Initialize the 10G Transceiver */

static nxge_status_t
nxge_10G_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_stats_t		statsp;
	p_nxge_param_t		param_arr = nxgep->param_arr;
	nxge_status_t		status = NXGE_OK;
#ifdef	NXGE_DEBUG
	uint8_t			portn = nxgep->mac.portnum;
#endif
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_10G_xcvr_init: port<%d>",
	    portn));

	statsp = nxgep->statsp;

	if (nxgep->mac.portmode == PORT_10G_SERDES) {
		goto done;
	}

	/* Disable Link LEDs */
	if (nxge_10g_link_led_off(nxgep) != NXGE_OK)
		goto fail;

	/* Set Clause 45 */
	npi_mac_mif_set_indirect_mode(nxgep->npi_handle, B_TRUE);

	switch (nxgep->chip_id) {
	case BCM8704_CHIP_ID:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_10G_xcvr_init: "
		    "Chip ID 8704 [0x%x] for 10G xcvr", nxgep->chip_id));
		status = nxge_BCM8704_xcvr_init(nxgep);
		break;
	case BCM8706_CHIP_ID:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_10G_xcvr_init: "
		    "Chip ID 8706 [0x%x] for 10G xcvr", nxgep->chip_id));
		status = nxge_BCM8706_xcvr_init(nxgep);
		break;
	case MRVL88X201X_CHIP_ID:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "nxge_10G_xcvr_init: "
		    "Chip ID 8706 [0x%x] for 10G xcvr", nxgep->chip_id));
		status = nxge_mrvl88x2011_xcvr_init(nxgep);
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_xcvr_init: "
		    "Unknown chip ID 0x%x for 10G xcvr addr[%d]",
		    nxgep->chip_id, nxgep->statsp->mac_stats.xcvr_portn));
		goto fail;
	}

	if (status != NXGE_OK) {
		goto fail;
	}
done:
	statsp->mac_stats.cap_10gfdx = 1;
	statsp->mac_stats.lp_cap_10gfdx = 1;
	statsp->mac_stats.adv_cap_asmpause =
	    param_arr[param_anar_asmpause].value;
	statsp->mac_stats.adv_cap_pause = param_arr[param_anar_pause].value;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_10G_xcvr_init: port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_10G_xcvr_init: failed to initialize transceiver for "
	    "port<%d>", nxgep->mac.portnum));
	return (NXGE_ERROR);
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

/*
 * Although the Teranetics copper transceiver (TN1010) does not need
 * to be initialized by the driver for passing packets, this funtion
 * initializes the members of nxgep->statsp->mac_stats struct for
 * kstat based on the value of nxgep->statsp->ports_stats.lb_mode.
 * It also configures the TN1010 for PHY loopback to support SunVTS.
 *
 * TN1010 only has the option to disable advertisement for the 10G
 * mode. So we can set it to either Dual Mode or 1G Only mode but
 * can't set it to 10G Only mode.
 *
 * ndd -set command can set the following 6 speed/duplex related parameters.
 *
 * ----------------------------------------------------------------
 * ndd -set /dev/nxgeX param n		kstat nxge:X | grep param
 * ----------------------------------------------------------------
 * adv_autoneg_cap		kstat nxge:1 | grep adv_cap_autoneg
 * adv_10gfdx_cap
 * adv_1000fdx_cap		kstat nxge:1 | grep adv_cap_1000fdx
 * adv_100fdx_cap		kstat nxge:1 | grep adv_cap_100fdx
 * adv_10fdx_cap		kstat nxge:1 | grep adv_cap_10fdx
 * adv_pause_cap		kstat nxge:1 | grep adv_cap_pause
 * ----------------------------------------------------------------
 */
static nxge_status_t
nxge_tn1010_xcvr_init(p_nxge_t nxgep)
{
	p_nxge_param_t		param_arr;
	p_nxge_stats_t		statsp;
	tn1010_pcs_ctrl_t	tn1010_pcs_ctrl;
	uint16_t		speed;
	uint8_t			phy_port_addr;
	uint8_t			portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	int			status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_1G_tn1010_xcvr_init"));

	param_arr	= nxgep->param_arr;
	statsp		= nxgep->statsp;

	/*
	 * Initialize the xcvr statistics which are NOT controlled by ndd
	 */
	statsp->mac_stats.cap_autoneg  = 1; /* TN1010 autoneg is always on */
	statsp->mac_stats.cap_100T4    = 0;

	/*
	 * Read the TN1010 link speed and initialize capabilities kstat. Note
	 * that function nxge_check_tn1010_link repeatedly invoked by the
	 * timer will update link_speed real time.
	 */
	if (nxge_get_tn1010_speed(nxgep,  &speed) != NXGE_OK) {
		goto fail;
	}
	if (speed == TN1010_SPEED_1G) {
		statsp->mac_stats.cap_10gfdx = 0;
	} else {
		statsp->mac_stats.cap_10gfdx = 1;
	}

	/* Whether we are in 1G or 10G mode, we always have the 1G capability */
	statsp->mac_stats.cap_1000fdx  = 1;

	/* TN1010 is not able to operate in the following states */
	statsp->mac_stats.cap_1000hdx  = 0;
	statsp->mac_stats.cap_100fdx   = 0;
	statsp->mac_stats.cap_100hdx   = 0;
	statsp->mac_stats.cap_10fdx    = 0;
	statsp->mac_stats.cap_10hdx    = 0;

	/* param_anar_pause can be modified by ndd -set */
	statsp->mac_stats.cap_pause    = param_arr[param_anar_pause].value;

	/*
	 * The following 4 lines actually overwrites what ever the ndd command
	 * has set. For example, by command
	 * 	ndd -set /dev/nxge1 adv_autoneg_cap n (n = 0 or 1)
	 * we could set param_arr[param_autoneg].value to n.  However, because
	 * here we assign constants to these parameters, whatever we set with
	 * the "ndd -set" command will be replaced. So command
	 *	kstat nxge:X | grep param
	 * will always show those constant values.  In other words, the
	 * "ndd -set" command can NOT change the values of these 4 parameters
	 * even though the command appears to be successful.
	 *
	 * Note: TN1010 auto negotiation is always enabled.
	 */
	statsp->mac_stats.adv_cap_autoneg
	    = param_arr[param_autoneg].value = 1;
	statsp->mac_stats.adv_cap_1000fdx
	    = param_arr[param_anar_1000fdx].value = 1;
	statsp->mac_stats.adv_cap_100fdx
	    = param_arr[param_anar_100fdx].value = 0;
	statsp->mac_stats.adv_cap_10fdx
	    = param_arr[param_anar_10fdx].value = 0;

	/*
	 * The following 4 ndd params have type NXGE_PARAM_MAC_DONT_SHOW as
	 * defined in nxge_param_arr[], therefore they are not seen by the
	 * "ndd -get" command and can not be changed by ndd.  We just set
	 * them (both ndd param and kstat values) to constant 0 because TN1010
	 * does not support those speeds.
	 */
	statsp->mac_stats.adv_cap_100T4
	    = param_arr[param_anar_100T4].value = 0;
	statsp->mac_stats.adv_cap_1000hdx
	    = param_arr[param_anar_1000hdx].value = 0;
	statsp->mac_stats.adv_cap_100hdx
	    = param_arr[param_anar_100hdx].value = 0;
	statsp->mac_stats.adv_cap_10hdx
	    = param_arr[param_anar_10hdx].value = 0;

	/*
	 * adv_cap_pause has type NXGE_PARAM_MAC_RW, so it can be modified
	 * by ndd
	 */
	statsp->mac_stats.adv_cap_pause    = param_arr[param_anar_pause].value;

	/*
	 * nxge_param_arr[] defines the adv_cap_asmpause with type
	 * NXGE_PARAM_DONT_SHOW, therefore they are NOT seen by the
	 * "ndd -get" command and can not be changed by ndd. Here we do not
	 * assign a constant to it so the default value defined in
	 * nxge_param_arr[] will be used to set the parameter and
	 * will be shown by the kstat.
	 */
	statsp->mac_stats.adv_cap_asmpause
	    = param_arr[param_anar_asmpause].value;

	/*
	 * Initialize the link statistics.
	 */
	statsp->mac_stats.link_T4 = 0;
	statsp->mac_stats.link_asmpause = 0;
	statsp->mac_stats.link_pause = 0;
	if (speed == TN1010_SPEED_1G) {
		statsp->mac_stats.link_speed = 1000;
		statsp->mac_stats.link_duplex = 2;	/* Full duplex */
		statsp->mac_stats.link_up = 1;
	} else {
		statsp->mac_stats.link_speed = 10000;
		statsp->mac_stats.link_duplex = 2;
		statsp->mac_stats.link_up = 1;
	}

	/*
	 * Because TN1010 does not have a link partner register, to
	 * figure out the link partner's capabilities is tricky. Here we
	 * just set the kstat based on our knowledge about the partner
	 * (The partner must support auto-neg because auto-negotiation
	 * has completed, it must support 1G or 10G because that is the
	 * negotiated speed we are using.)
	 *
	 * Note: Current kstat does not show lp_cap_10gfdx and
	 *	lp_cap_10ghdx.
	 */
	if (speed == TN1010_SPEED_1G) {
		statsp->mac_stats.lp_cap_1000fdx  = 1;
		statsp->mac_stats.lp_cap_10gfdx   = 0;
	} else {
		statsp->mac_stats.lp_cap_1000fdx  = 0;
		statsp->mac_stats.lp_cap_10gfdx   = 1;
	}
	statsp->mac_stats.lp_cap_10ghdx   = 0;
	statsp->mac_stats.lp_cap_1000hdx  = 0;
	statsp->mac_stats.lp_cap_100fdx   = 0;
	statsp->mac_stats.lp_cap_100hdx   = 0;
	statsp->mac_stats.lp_cap_10fdx    = 0;
	statsp->mac_stats.lp_cap_10hdx    = 0;
	statsp->mac_stats.lp_cap_10gfdx   = 0;
	statsp->mac_stats.lp_cap_10ghdx   = 0;
	statsp->mac_stats.lp_cap_100T4    = 0;
	statsp->mac_stats.lp_cap_autoneg  = 1;
	statsp->mac_stats.lp_cap_asmpause = 0;
	statsp->mac_stats.lp_cap_pause    = 0;

	/* Handle PHY loopback for SunVTS loopback test */
	npi_mac_mif_set_indirect_mode(nxgep->npi_handle, B_TRUE);
	phy_port_addr = nxgep->nxge_hw_p->xcvr_addr[portn];

	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    TN1010_PCS_DEV_ADDR, TN1010_PCS_CONTROL_REG,
	    &tn1010_pcs_ctrl.value)) != NXGE_OK) {
		goto fail;
	}
	if ((statsp->port_stats.lb_mode == nxge_lb_phy1000) ||
	    (statsp->port_stats.lb_mode == nxge_lb_phy10g)) {
		tn1010_pcs_ctrl.bits.loopback = 1;
	} else {
		tn1010_pcs_ctrl.bits.loopback = 0;
	}
	if ((status = nxge_mdio_write(nxgep, phy_port_addr,
	    TN1010_PCS_DEV_ADDR, TN1010_PCS_CONTROL_REG,
	    tn1010_pcs_ctrl.value)) != NXGE_OK) {
		goto fail;
	}

	statsp->mac_stats.xcvr_inits++;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_1G_tn1010_xcvr_init status 0x%x", status));
	return (status);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "<== nxge_1G_tn1010_xcvr_init status 0x%x", status));
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
	 * Initialize the xcvr statistics. nxgep->xcvr.xcvr_init will
	 * modify mac_stats.
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
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_xcvr_find: port<%d>",
	    nxgep->mac.portnum));

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
	/*
	 * Use maxframesize to configure the hardware maxframe size
	 * and minframesize to configure the hardware minframe size.
	 */
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_tx_mac_init: port<%d> "
	    "min framesize %d max framesize %d ",
	    nxgep->mac.minframesize,
	    nxgep->mac.maxframesize,
	    portn));

	SET_MAC_ATTR2(handle, ap, portn,
	    MAC_PORT_FRAME_SIZE,
	    nxgep->mac.minframesize,
	    nxgep->mac.maxframesize,
	    rs);
	if (rs != NPI_SUCCESS)
		goto fail;

	if (portt == PORT_TYPE_XMAC) {
		if ((rs = npi_xmac_tx_iconfig(handle, INIT, portn,
		    0)) != NPI_SUCCESS)
			goto fail;
		nxgep->mac.tx_iconfig = NXGE_XMAC_TX_INTRS;
		if ((portmode == PORT_10G_FIBER) ||
		    (portmode == PORT_10G_COPPER) ||
		    (portmode == PORT_10G_TN1010) ||
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
	    "nxge_tx_mac_init: failed to initialize port<%d> TXMAC", portn));

	return (NXGE_ERROR | rs);
}

int
nxge_hio_hostinfo_get_rdc_table(p_nxge_t nxgep)
{
	int rdc_tbl;

	/*
	 * Get an RDC table (version 0).
	 */
	if ((rdc_tbl = nxge_fzc_rdc_tbl_bind(nxgep, -1, B_FALSE)) < 0) {
		NXGE_ERROR_MSG((nxgep, OBP_CTL,
		    "nxge_hio_hostinfo_get_rdc_table: "
		    "there are no free RDC tables!"));
		return (EBUSY);
	}

	return (rdc_tbl);
}

/*
 * nxge_hio_hostinfo_init
 *
 *	Initialize an alternate MAC address, and bind a macrdctbln to it.
 *
 * Arguments:
 * 	nxge
 * 	vr	The Virtualization Region
 * 	macaddr	The alternate MAC address
 *
 * Notes:
 *	1. Find & bind an RDC table to <nxge>.
 *	2. Program an alternate MAC address (<macaddr>).
 *	3. Bind the RDC table to <macaddr>.
 *
 * Context:
 *	Service domain
 *
 * Side Effects:
 *	nxge->class_config.mac_host_info[slot].rdctbl
 *	vr->slot & vr->altmac
 *
 */
int
nxge_hio_hostinfo_init(
	nxge_t *nxge,
	nxge_hio_vr_t *vr,	/* Virtualization Region */
	ether_addr_t *macaddr)	/* The alternate MAC address */
{
	int rdc_tbl, slot;

	nxge_class_pt_cfg_t *class;
	hostinfo_t mac_rdc;
	npi_mac_addr_t altmac;
	nxge_mmac_t *mmac_info;
	nxge_rdc_grp_t	*group;
	uint8_t *addr = (uint8_t *)macaddr;

	mutex_enter(nxge->genlock);

	rdc_tbl = vr->rdc_tbl;

	/* Initialize the NXGE RDC table data structure. */
	group = &nxge->pt_config.rdc_grps[rdc_tbl];
	group->port = NXGE_GET_PORT_NUM(nxge->function_num);
	group->config_method = RDC_TABLE_ENTRY_METHOD_REP;
	group->flag = 1;	/* This group has been configured. */

	mmac_info = &nxge->nxge_mmac_info;

	/*
	 * Are there free slots.
	 */
	if (mmac_info->naddrfree == 0) {
		mutex_exit(nxge->genlock);
		return (ENOSPC);
	}

	/*
	 * The vswitch has already added this MAC address.
	 * Find its assigned slot.
	 */
	if (mmac_info->num_factory_mmac < mmac_info->num_mmac) {
		for (slot = mmac_info->num_factory_mmac + 1;
		    slot <= mmac_info->num_mmac; slot++) {
			if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
				break;
		}
		if (slot > mmac_info->num_mmac) {
			for (slot = 1; slot <= mmac_info->num_factory_mmac;
			    slot++) {
				if (!(mmac_info->mac_pool[slot].flags
				    & MMAC_SLOT_USED))
					break;
			}
		}
	} else {
		for (slot = 1; slot <= mmac_info->num_mmac; slot++) {
			if (!(mmac_info->mac_pool[slot].flags & MMAC_SLOT_USED))
				break;
		}
	}

	ASSERT(slot <= mmac_info->num_mmac);
	vr->slot = slot;
	slot = vr->slot - 1;

	/*
	 * Program the mac address.
	 */
	altmac.w2 = (((uint16_t)addr[0]) << 8) |
	    (((uint16_t)addr[1]) & 0x0ff);
	altmac.w1 = (((uint16_t)addr[2]) << 8) |
	    (((uint16_t)addr[3]) & 0x0ff);
	altmac.w0 = (((uint16_t)addr[4]) << 8) |
	    (((uint16_t)addr[5]) & 0x0ff);

	if (npi_mac_altaddr_entry(nxge->npi_handle, OP_SET,
	    nxge->function_num, slot, &altmac) != NPI_SUCCESS) {
		mutex_exit(nxge->genlock);
		return (EIO);
	}

	/*
	 * Associate <rdc_tbl> with this MAC address slot.
	 */
	class = (p_nxge_class_pt_cfg_t)&nxge->class_config;

	/* Update this variable. */
	class = (p_nxge_class_pt_cfg_t)&nxge->class_config;
	class->mac_host_info[slot].rdctbl = (uint8_t)rdc_tbl;

	mac_rdc.value = 0;
	mac_rdc.bits.w0.rdc_tbl_num = rdc_tbl;
	mac_rdc.bits.w0.mac_pref = class->mac_host_info[slot].mpr_npr;
	/* <mpr_npr> had better be 1! */

	/* Program the RDC table. */
	if ((npi_mac_hostinfo_entry(nxge->npi_handle, OP_SET,
	    nxge->function_num, slot, &mac_rdc)) != NPI_SUCCESS) {
		mutex_exit(nxge->genlock);
		(void) nxge_m_mmac_remove(nxge, vr->slot);
		return (EIO);
	}

	if (nxge->mac.portnum != XMAC_PORT_0 &&
	    nxge->mac.portnum != XMAC_PORT_1)
		slot++;

	/* (Re-)enable the MAC address. */
	(void) npi_mac_altaddr_enable(
	    nxge->npi_handle, nxge->mac.portnum, slot);

	bcopy(macaddr, vr->altmac, sizeof (vr->altmac));

	/*
	 * Update mmac
	 */
	bcopy(addr, mmac_info->mac_pool[vr->slot].addr, ETHERADDRL);
	mmac_info->mac_pool[vr->slot].flags |= MMAC_SLOT_USED;
	mmac_info->mac_pool[vr->slot].flags &= ~MMAC_VENDOR_ADDR;
	mmac_info->naddrfree--;
	nxge_mmac_kstat_update(nxge, vr->slot, B_FALSE);

	mutex_exit(nxge->genlock);
	return (0);
}

/*
 * nxge_hio_hostinfo_uninit
 *
 *	Uninitialize an alternate MAC address.
 *
 * Arguments:
 * 	nxge
 * 	vr	The Virtualization Region
 *
 * Notes:
 *	1. Remove the VR's alternate MAC address.
 *	1. Free (unbind) the RDC table allocated to this VR.
 *
 * Context:
 *	Service domain
 *
 * Side Effects:
 *	nxge->class_config.mac_host_info[slot].rdctbl
 *
 */
void
nxge_hio_hostinfo_uninit(
	nxge_t *nxge,
	nxge_hio_vr_t *vr)
{
	nxge_class_pt_cfg_t *class;

	(void) npi_mac_altaddr_disable(
	    nxge->npi_handle, nxge->mac.portnum, vr->slot);

	/* Set this variable to its default. */
	class = (p_nxge_class_pt_cfg_t)&nxge->class_config;
	class->mac_host_info[vr->slot].rdctbl =
	    nxge->pt_config.hw_config.def_mac_rxdma_grpid;

	(void) nxge_m_mmac_remove(nxge, vr->slot);
	vr->slot = -1;

	(void) nxge_fzc_rdc_tbl_unbind(nxge, vr->rdc_tbl);
	vr->rdc_tbl = -1;
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
	    "nxge_rx_mac_init: Failed to Initialize port<%d> RxMAC", portn));

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

	if (isLDOMguest(nxgep))
		return (NXGE_OK);

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

	/* This is a service-domain-only activity. */
	if (isLDOMguest(nxgep))
		return (status);

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

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_rx_mac_enable: port<%d>", portn));

	return (NXGE_OK);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxgep_rx_mac_enable: Failed to enable port<%d> RxMAC", portn));

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

	/* If we are a guest domain driver, don't bother. */
	if (isLDOMguest(nxgep))
		return (NXGE_OK);

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
	    "nxgep_rx_mac_disable: Failed to disable port<%d> RxMAC", portn));

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
	    "nxge_tx_mac_reset: Failed to Reset TxMAC port<%d>", portn));

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
	    "nxge_rx_mac_reset: Failed to Reset RxMAC port<%d>", portn));
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
	    MII_STATUS, MII_STATUS_LINKUP);

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
	    "nxge_link_intr: Failed to set port<%d> mif intr mode", portn));

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
	 * The mif phy mode may be connected to either a copper link
	 * or fiber link. Read the mode control register to get the fiber
	 * configuration if it is hard-wired to fiber link.
	 */
	(void) nxge_mii_get_link_mode(nxgep);
	if (nxgep->mac.portmode == PORT_1G_RGMII_FIBER) {
		return (nxge_mii_xcvr_fiber_init(nxgep));
	}

	/*
	 * Reset the transceiver.
	 */
	delay = 0;
	bmcr.value = 0;
	bmcr.bits.reset = 1;
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
	    (uint8_t)(uint32_t)&mii_regs->bmcr,
#else
	    (uint8_t)(uint64_t)&mii_regs->bmcr,
#endif
	    bmcr.value)) != NXGE_OK)
		goto fail;
	do {
		drv_usecwait(500);
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
#if defined(__i386)
		    (uint8_t)(uint32_t)&mii_regs->bmcr,
#else
		    (uint8_t)(uint64_t)&mii_regs->bmcr,
#endif
		    &bmcr.value)) != NXGE_OK)
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
	 * Initialize the xcvr advertised capability statistics.
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
		    (uint8_t)(uint32_t)(&mii_regs->esr),
#else
		    (uint8_t)(uint64_t)(&mii_regs->esr),
#endif
		    &esr.value)) != NXGE_OK)
			goto fail;
		param_arr[param_anar_1000fdx].value &= esr.bits.link_1000fdx;
		param_arr[param_anar_1000hdx].value = 0;

		statsp->mac_stats.cap_1000fdx =
		    (esr.bits.link_1000Xfdx || esr.bits.link_1000fdx);
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
	 * Initialize the link statistics.
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
	    (uint8_t)(uint32_t)(&mii_regs->bmcr),
#else
	    (uint8_t)(uint64_t)(&mii_regs->bmcr),
#endif
	    bmcr.value)) != NXGE_OK)
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
		    BCM5464R_AUX_CTL, bcm5464r_aux.value)) != NXGE_OK)
			goto fail;
	}

	/* If auto-negotiation is desired */
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

		/* Write to the auto-negotiation advertisement register */
		if ((status = nxge_mii_write(nxgep, xcvr_portn,
#if defined(__i386)
		    (uint8_t)(uint32_t)(&mii_regs->anar),
#else
		    (uint8_t)(uint64_t)(&mii_regs->anar),
#endif
		    anar.value)) != NXGE_OK)
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
			    (uint8_t)(uint32_t)(&mii_regs->gcr),
#else
			    (uint8_t)(uint64_t)(&mii_regs->gcr),
#endif
			    gcr.value)) != NXGE_OK)
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

		/* Force to 1G */
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
			    gcr.value)) != NXGE_OK)
				goto fail;
			if (param_arr[param_anar_1000fdx].value) {
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_duplex = 2;
			} else
				statsp->mac_stats.link_duplex = 1;

		/* Force to 100M */
		} else if (bmcr.bits.speed_sel) {
			statsp->mac_stats.link_speed = 100;
			if (param_arr[param_anar_100fdx].value) {
				bmcr.bits.duplex_mode = 1;
				statsp->mac_stats.link_duplex = 2;
			} else
				statsp->mac_stats.link_duplex = 1;

		/* Force to 10M */
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
				    gcr.value)) != NXGE_OK)
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
	    (uint8_t)(uint32_t)(&mii_regs->bmcr),
#else
	    (uint8_t)(uint64_t)(&mii_regs->bmcr),
#endif
	    &bmcr.value)) != NXGE_OK)
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

nxge_status_t
nxge_mii_xcvr_fiber_init(p_nxge_t nxgep)
{
	p_nxge_param_t	param_arr;
	p_nxge_stats_t	statsp;
	uint8_t		xcvr_portn;
	p_mii_regs_t	mii_regs;
	mii_bmcr_t	bmcr;
	mii_bmsr_t	bmsr;
	mii_gcr_t	gcr;
	mii_esr_t	esr;
	mii_aux_ctl_t	bcm5464r_aux;
	int		status = NXGE_OK;

	uint_t delay;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mii_xcvr_fiber_init"));

	param_arr = nxgep->param_arr;
	statsp = nxgep->statsp;
	xcvr_portn = statsp->mac_stats.xcvr_portn;

	mii_regs = NULL;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_mii_xcvr_fiber_init: "
	    "nxge_param_autoneg = 0x%02x", param_arr[param_autoneg].value));

	/*
	 * Reset the transceiver.
	 */
	delay = 0;
	bmcr.value = 0;
	bmcr.bits.reset = 1;

#if defined(__i386)

	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
		goto fail;
#endif
	do {
		drv_usecwait(500);
#if defined(__i386)
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
		    (uint8_t)(uint32_t)(&mii_regs->bmcr), &bmcr.value))
		    != NXGE_OK)
			goto fail;
#else
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
		    (uint8_t)(uint64_t)(&mii_regs->bmcr), &bmcr.value))
		    != NXGE_OK)
			goto fail;
#endif
		delay++;
	} while ((bmcr.bits.reset) && (delay < 1000));
	if (delay == 1000) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Xcvr reset failed."));
		goto fail;
	}

#if defined(__i386)
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmsr), &bmsr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmsr), &bmsr.value)) != NXGE_OK)
		goto fail;
#endif

	param_arr[param_autoneg].value &= bmsr.bits.auto_neg_able;
	param_arr[param_anar_100T4].value = 0;
	param_arr[param_anar_100fdx].value = 0;
	param_arr[param_anar_100hdx].value = 0;
	param_arr[param_anar_10fdx].value = 0;
	param_arr[param_anar_10hdx].value = 0;

	/*
	 * Initialize the xcvr statistics.
	 */
	statsp->mac_stats.cap_autoneg = bmsr.bits.auto_neg_able;
	statsp->mac_stats.cap_100T4 = 0;
	statsp->mac_stats.cap_100fdx = 0;
	statsp->mac_stats.cap_100hdx = 0;
	statsp->mac_stats.cap_10fdx = 0;
	statsp->mac_stats.cap_10hdx = 0;
	statsp->mac_stats.cap_asmpause = param_arr[param_anar_asmpause].value;
	statsp->mac_stats.cap_pause = param_arr[param_anar_pause].value;

	/*
	 * Initialize the xcvr advertised capability statistics.
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
#if defined(__i386)
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
		    (uint8_t)(uint32_t)(&mii_regs->esr), &esr.value)) !=
		    NXGE_OK)
			goto fail;
#else
		if ((status = nxge_mii_read(nxgep, xcvr_portn,
		    (uint8_t)(uint64_t)(&mii_regs->esr), &esr.value)) !=
		    NXGE_OK)
			goto fail;
#endif
		param_arr[param_anar_1000fdx].value &=
		    esr.bits.link_1000fdx;
		param_arr[param_anar_1000hdx].value = 0;

		statsp->mac_stats.cap_1000fdx =
		    (esr.bits.link_1000Xfdx || esr.bits.link_1000fdx);
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
	 * Initialize the link statistics.
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
#if defined(__i386)
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmcr), bmcr.value)) != NXGE_OK)
		goto fail;
#endif

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

	if (statsp->port_stats.lb_mode == nxge_lb_ext1000) {
		param_arr[param_autoneg].value = 0;
		bcm5464r_aux.value = 0;
		bcm5464r_aux.bits.ext_lb = 1;
		bcm5464r_aux.bits.write_1 = 1;
		if ((status = nxge_mii_write(nxgep, xcvr_portn,
		    BCM5464R_AUX_CTL, bcm5464r_aux.value)) != NXGE_OK)
			goto fail;
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "Going into forced mode."));
	bmcr.bits.speed_1000_sel = 1;
	bmcr.bits.speed_sel = 0;
	bmcr.bits.duplex_mode = 1;
	statsp->mac_stats.link_speed = 1000;
	statsp->mac_stats.link_duplex = 2;

	if ((statsp->port_stats.lb_mode == nxge_lb_ext1000)) {
		/* BCM5464R 1000mbps external loopback mode */
		gcr.value = 0;
		gcr.bits.ms_mode_en = 1;
		gcr.bits.master = 1;
#if defined(__i386)
		if ((status = nxge_mii_write(nxgep, xcvr_portn,
		    (uint8_t)(uint32_t)(&mii_regs->gcr),
		    gcr.value)) != NXGE_OK)
			goto fail;
#else
		if ((status = nxge_mii_write(nxgep, xcvr_portn,
		    (uint8_t)(uint64_t)(&mii_regs->gcr),
		    gcr.value)) != NXGE_OK)
			goto fail;
#endif
		bmcr.value = 0;
		bmcr.bits.speed_1000_sel = 1;
		statsp->mac_stats.link_speed = 1000;
	}

#if defined(__i386)
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmcr),
	    bmcr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmcr),
	    bmcr.value)) != NXGE_OK)
		goto fail;
#endif

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_mii_xcvr_fiber_init: value wrote bmcr = 0x%x",
	    bmcr.value));

#if defined(__i386)
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmcr), &bmcr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmcr), &bmcr.value)) != NXGE_OK)
		goto fail;
#endif

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_mii_xcvr_fiber_init: read bmcr = 0x%04X", bmcr.value));

	/*
	 * Initialize the xcvr status kept in the context structure.
	 */
	nxgep->soft_bmsr.value = 0;
#if defined(__i386)
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmsr),
	    &nxgep->bmsr.value)) != NXGE_OK)
		goto fail;
#else
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmsr),
	    &nxgep->bmsr.value)) != NXGE_OK)
		goto fail;
#endif

	statsp->mac_stats.xcvr_inits++;
	nxgep->bmsr.value = 0;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_mii_xcvr_fiber_init status 0x%x", status));
	return (status);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "<== nxge_mii_xcvr_fiber_init status 0x%x", status));
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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);

	if ((nxgep->mac.portmode == PORT_1G_COPPER) ||
	    (nxgep->mac.portmode == PORT_1G_RGMII_FIBER)) {
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

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mii_read: xcvr_port<%d>"
	    "xcvr_reg<%d> value=0x%x", xcvr_portn, xcvr_reg, *value));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_read: Failed to read mii on xcvr %d", xcvr_portn));

	return (NXGE_ERROR | rs);
}

/* Write to a MII compliant Register */

nxge_status_t
nxge_mii_write(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t xcvr_reg,
		uint16_t value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mii_write: xcvr_port<%d>"
	    "xcvr_reg<%d> value=0x%x", xcvr_portn, xcvr_reg, value));

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);

	if ((nxgep->mac.portmode == PORT_1G_COPPER) ||
	    (nxgep->mac.portmode == PORT_1G_RGMII_FIBER)) {
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

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mii_write: xcvr_port<%d>"
	    "xcvr_reg<%d>", xcvr_portn, xcvr_reg));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_write: Failed to write mii on xcvr %d", xcvr_portn));

	return (NXGE_ERROR | rs);
}

/*
 * Perform write to Clause45 serdes / transceiver device
 * Arguments:
 *	xcvr_portn: 	The IEEE 802.3 Clause45 PHYAD, it is the same as port
 *			number if nxge_mdio_write is used for accessing the
 *			internal LSIL serdes. Otherwise PHYAD is different
 * 			for different platforms.
 *	device:		With each PHYAD, the driver can use MDIO to control
 *			multiple devices inside the PHY, here "device" is an
 *			MMD (MDIO managable device).
 *	xcvr_reg:	Each device has multiple registers. xcvr_reg specifies
 *			the register which the driver will write value to.
 *	value:		The register value will be filled in.
 */
nxge_status_t
nxge_mdio_read(p_nxge_t nxgep, uint8_t xcvr_portn, uint8_t device,
		uint16_t xcvr_reg, uint16_t *value)
{
	npi_status_t rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "==> nxge_mdio_read: xcvr_port<%d>",
	    xcvr_portn));

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);

	if ((rs = npi_mac_mif_mdio_read(nxgep->npi_handle,
	    xcvr_portn, device, xcvr_reg, value)) != NPI_SUCCESS)
		goto fail;

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mdio_read: xcvr_port<%d>",
	    xcvr_portn));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mdio_read: Failed to read mdio on xcvr %d", xcvr_portn));

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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);

	if ((rs = npi_mac_mif_mdio_write(nxgep->npi_handle,
	    xcvr_portn, device, xcvr_reg, value)) != NPI_SUCCESS)
		goto fail;

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_DEBUG_MSG((nxgep, MIF_CTL, "<== nxge_mdio_write: xcvr_port<%d>",
	    xcvr_portn));
	return (NXGE_OK);
fail:
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mdio_write: Failed to write mdio on xcvr %d", xcvr_portn));

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

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_mii_check bmsr 0x%x bmsr_int 0x%x",
	    bmsr.value, bmsr_ints.value));

	if (bmsr_ints.bits.link_status) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_mii_check (link up) bmsr 0x%x bmsr_int 0x%x",
		    bmsr.value, bmsr_ints.value));
		if (bmsr.bits.link_status) {
			soft_bmsr->bits.link_status = 1;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_mii_check (link up) soft bmsr 0x%x bmsr_int "
		    "0x%x", bmsr.value, bmsr_ints.value));
		} else {
			statsp->mac_stats.link_up = 0;
			soft_bmsr->bits.link_status = 0;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Link down cable problem"));
			*link_up = LINK_IS_DOWN;
		}
	}

	if (nxgep->mac.portmode == PORT_1G_COPPER &&
	    param_arr[param_autoneg].value) {
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

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_mii_check "
		    "(auto negotiation complete or link up) "
		    "soft bmsr 0x%x bmsr_int 0x%x",
		    bmsr.value, bmsr_ints.value));

		if (nxgep->mac.portmode == PORT_1G_COPPER &&
		    param_arr[param_autoneg].value) {
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
				    &gsr.value)) != NXGE_OK)
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
				int	link_pause;
				int	cp, lcp;

				statsp->mac_stats.link_asmpause =
				    an_common.bits.cap_asmpause;
				cp = statsp->mac_stats.cap_pause;
				lcp = statsp->mac_stats.lp_cap_pause;
				if (statsp->mac_stats.link_asmpause) {
					if ((cp == 0) && (lcp == 1)) {
						link_pause = 0;
					} else {
						link_pause = 1;
					}
				} else {
					link_pause = an_common.bits.cap_pause;
				}
				statsp->mac_stats.link_pause = link_pause;
			}
		} else if (nxgep->mac.portmode == PORT_1G_RGMII_FIBER) {
			statsp->mac_stats.link_speed = 1000;
			statsp->mac_stats.link_duplex = 2;
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

/*
 * Check PCS to see if there is any link status change.
 * This function is called by PORT_1G_SERDES only.
 */
void
nxge_pcs_check(p_nxge_t nxgep, uint8_t portn, nxge_link_state_t *link_up)
{
	p_nxge_stats_t	statsp;
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
nxge_check_link_stop(nxge_t *nxge)
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

/*
 * Check status of MII (MIF or PCS) link.
 * This function is called once per second, that is because this function
 * calls nxge_link_monitor with LINK_MONITOR_START, which starts a timer to
 * call this function recursively.
 */
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
		bmsr_data.value = 0;
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

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_mii_link port<0x%x> "
		    "RIGHT AFTER READ bmsr_data 0x%x (nxgep->bmsr 0x%x ",
		    portn, bmsr_data.value, nxgep->bmsr.value));

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
			if (nxgep->mac.portmode != PORT_1G_RGMII_FIBER) {

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
		}

		/* Workaround for link down issue */
		if (bmsr_data.value == 0) {
			cmn_err(CE_NOTE, "!LINK DEBUG: Read zero bmsr\n");
			goto nxge_check_mii_link_exit;
		}

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_mii_link port<0x%x> :"
		    "BEFORE BMSR ^ nxgep->bmsr 0x%x bmsr_data 0x%x",
		    portn, nxgep->bmsr.value, bmsr_data.value));

		bmsr_ints.value = nxgep->bmsr.value ^ bmsr_data.value;
		nxgep->bmsr.value = bmsr_data.value;

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_mii_link port<0x%x> CALLING "
		    "bmsr_data 0x%x bmsr_ints.value 0x%x",
		    portn, bmsr_data.value, bmsr_ints.value));

		if ((status = nxge_mii_check(nxgep, bmsr_data, bmsr_ints,
		    &link_up)) != NXGE_OK) {
			goto fail;
		}
		break;

	case PORT_1G_SERDES:
		/*
		 * Above default is for all cases except PORT_1G_SERDES.
		 * The default case gets information from the PHY, but a
		 * nxge whose portmode equals PORT_1G_SERDES does not
		 * have a PHY.
		 */
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_mii_link port<%d> (SERDES)", portn));
		nxge_pcs_check(nxgep, portn, &link_up);
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
	    "nxge_check_mii_link: Failed to check link port<%d>", portn));
	return (status);
}

/*ARGSUSED*/
static nxge_status_t
nxge_check_10g_link(p_nxge_t nxgep)
{
	uint8_t		portn;
	nxge_status_t	status = NXGE_OK;
	boolean_t	link_up;
	uint32_t	val;
	npi_status_t	rs;

	if (nxgep->nxge_magic != NXGE_MAGIC)
		return (NXGE_ERROR);

	if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP)
		return (NXGE_OK);

	portn = nxgep->mac.portnum;
	val = 0;
	rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_check_10g_link port<%d>",
	    portn));

	switch (nxgep->mac.portmode) {
	default:
		/*
		 * Check if the phy is present in case of hot swappable phy
		 */
		if (nxgep->hot_swappable_phy) {
			boolean_t phy_present_now = B_FALSE;

			/*
			 * If this is the 2nd Goa port, then check 2 addresses
			 * to take care of the Goa NEM card requirements.
			 */
			if (portn == 1) {
				if (nxge_is_phy_present(nxgep,
				    ALT_GOA_CLAUSE45_PORT1_ADDR,
				    BCM8706_DEV_ID, BCM_PHY_ID_MASK)) {
					phy_present_now = B_TRUE;
					nxgep->xcvr_addr =
					    ALT_GOA_CLAUSE45_PORT1_ADDR;
					goto phy_check_done;
				}
			}
			if (nxge_is_phy_present(nxgep,
			    (GOA_CLAUSE45_PORT_ADDR_BASE) + portn,
			    BCM8706_DEV_ID, BCM_PHY_ID_MASK)) {
				nxgep->xcvr_addr =
				    (GOA_CLAUSE45_PORT_ADDR_BASE) + portn;
				phy_present_now = B_TRUE;
			}

phy_check_done:
			if (nxgep->phy_absent) {
				if (phy_present_now) {
				/*
				 * Detect, Initialize phy and do link up
				 * set xcvr vals, link_init, nxge_init
				 */
					NXGE_DEBUG_MSG((nxgep, MAC_CTL,
					    "Hot swappable phy DETECTED!!"));
					nxgep->phy_absent = B_FALSE;
					(void) nxge_xcvr_find(nxgep);
					(void) nxge_link_init(nxgep);
					if (!(nxgep->drv_state &
					    STATE_HW_INITIALIZED)) {
						status = nxge_init(nxgep);
						if (status != NXGE_OK) {
							NXGE_ERROR_MSG((nxgep,
							    NXGE_ERR_CTL,
							    "Hot swappable "
							    "phy present, but"
							    " driver init"
							    "  failed..."));
							goto fail;
						}
					}
				}

				goto start_link_check;

			} else if (!phy_present_now) {
				/*
				 * Phy gone, bring link down reset xcvr vals
				 */
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Hot swappable phy REMOVED!!"));
				nxgep->phy_absent = B_TRUE;
				nxgep->statsp->mac_stats.link_up = 0;
				nxgep->statsp->mac_stats.link_speed = 0;
				nxgep->statsp->mac_stats.link_duplex = 0;
				nxge_link_is_down(nxgep);
				nxgep->link_notify = B_FALSE;

				(void) nxge_xcvr_find(nxgep);

				goto start_link_check;

			}
		}
		if (nxgep->chip_id == MRVL88X201X_CHIP_ID) {
			status = nxge_check_mrvl88x2011_link(nxgep, &link_up);
		} else {
			status = nxge_check_bcm8704_link(nxgep, &link_up);
		}
		if (status != NXGE_OK)
			goto fail;
		break;
	case PORT_10G_SERDES:
		rs = npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
		    XPCS_REG_STATUS, &val);
		if (rs != 0)
			goto fail;

		link_up = B_FALSE;
		if (val & XPCS_STATUS_LANE_ALIGN) {
			link_up = B_TRUE;
		}

		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "==> nxge_check_10g_link port<%d> "
		    "XPCS_REG_STATUS2 0x%x link_up %d",
		    portn, val, link_up));

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

start_link_check:
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


	/* Clean up symbol errors incurred during link transition */
	if ((nxgep->mac.portmode == PORT_10G_FIBER) ||
	    (nxgep->mac.portmode == PORT_10G_SERDES)) {
		(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
		    XPCS_REG_SYMBOL_ERR_L0_1_COUNTER, &val);
		(void) npi_xmac_xpcs_read(nxgep->npi_handle, nxgep->mac.portnum,
		    XPCS_REG_SYMBOL_ERR_L2_3_COUNTER, &val);
	}

	/*
	 * If the driver was plumbed without a link (therefore auto-negotiation
	 * could not complete), the driver will detect a link up when a cable
	 * conneting to a link partner is plugged into the port. By the time
	 * link-up is detected, auto-negotiation should have completed (The
	 * TN1010 tries to contact a link partner every 8~24ms). Here we re-
	 * configure the Neptune/NIU according to the newly negotiated speed.
	 * This is necessary only for the TN1010 basad device because only the
	 * TN1010 supports dual speeds.
	 */
	if (nxgep->mac.portmode == PORT_1G_TN1010 ||
	    nxgep->mac.portmode == PORT_10G_TN1010) {

		(void) nxge_set_tn1010_param(nxgep);

		/*
		 * nxge_xcvr_find calls nxge_get_xcvr_type (which sets
		 * nxgep->portmode) and nxge_setup_xcvr_table (which sets
		 * the nxgep->xcvr to the proper nxge_xcvr_table_t struct).
		 */
		if (nxge_xcvr_find(nxgep) != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_link_is_up: nxge_xcvr_find failed"));
		}

		/* nxge_link_init calls nxge_xcvr_init and nxge_serdes_init */
		if (nxge_link_init(nxgep) != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_link_is_up: nxge_link_init failed"));
		}

		/*
		 * nxge_mac_init calls many subroutines including
		 * nxge_xif_init which sets XGMII or GMII mode
		 */
		if (nxge_mac_init(nxgep) != NXGE_OK) {
			NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
			    "nxge_link_is_up: nxge_mac_init failed"));
		}
	} else {
		(void) nxge_xif_init(nxgep);
	}

	if (nxge_no_msg == B_FALSE) {
		NXGE_ERROR_MSG((nxgep, NXGE_NOTE, "%s", link_stat_msg));
	}

	mac_link_update(nxgep->mach, LINK_STATE_UP);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_link_is_up"));
}

#ifdef NXGE_DEBUG
/* Dump all TN1010 Status registers */
static void
nxge_dump_tn1010_status_regs(p_nxge_t nxgep)
{
	uint16_t val;

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PMA_PMD_DEV_ADDR, 1, &val);
	cmn_err(CE_NOTE, "PMA status1 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PMA_PMD_DEV_ADDR, 8, &val);
	cmn_err(CE_NOTE, "PMA status2 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PMA_PMD_DEV_ADDR, 129, &val);
	cmn_err(CE_NOTE, "10BASET-T status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PCS_DEV_ADDR, 1, &val);
	cmn_err(CE_NOTE, "PCS status1 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PCS_DEV_ADDR, 8, &val);
	cmn_err(CE_NOTE, "PCS status2 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PCS_DEV_ADDR, 32, &val);
	cmn_err(CE_NOTE, "10GBASE-R status1 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PCS_DEV_ADDR, 33, &val);
	cmn_err(CE_NOTE, "10GBASE-R Status2 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PHYXS_DEV_ADDR, 1, &val);
	cmn_err(CE_NOTE, "PHYXS status1 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PHYXS_DEV_ADDR, 8, &val);
	cmn_err(CE_NOTE, "PHYXS status2 = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_PHYXS_DEV_ADDR, 24, &val);
	cmn_err(CE_NOTE, "XGXS Lane status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_AUTONEG_DEV_ADDR, 1, &val);
	cmn_err(CE_NOTE, "Autoneg status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_AUTONEG_DEV_ADDR, 33, &val);
	cmn_err(CE_NOTE, "10Gbase-T An status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, 1, &val);
	cmn_err(CE_NOTE, "TN1010 status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, 8, &val);
	cmn_err(CE_NOTE, "Device status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, 16, &val);
	cmn_err(CE_NOTE, "DDR status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, 17, &val);
	cmn_err(CE_NOTE, "DDR fault status = 0x%x", val);

	nxge_mdio_read(nxgep, nxgep->xcvr_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, 11, &val);
	cmn_err(CE_NOTE, "Firmware Revision = 0x%x  Major = 0x%x Minor = 0x%x",
	    val,  (val & 0xFF00) >> 8, val & 0x00FF);
}
#endif

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

/*
 * This function monitors link status using interrupt or polling.
 * It calls nxgep->xcvr.check_link, a member function of
 * nxge_xcvr_table_t. But nxgep->xcvr.check_link calls this
 * function back, that is why the check_link routine is
 * executed periodically.
 */
nxge_status_t
nxge_link_monitor(p_nxge_t nxgep, link_mon_enable_t enable)
{
	nxge_status_t status = NXGE_OK;

	/* If we are a guest domain driver, don't bother. */
	if (isLDOMguest(nxgep))
		return (status);

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
	/* Don't check link if we're in internal loopback mode */
	if (nxgep->statsp->port_stats.lb_mode >= nxge_lb_serdes10g)
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
			/*
			 * check_link_stop means "Stop the link check", so
			 * we return without starting the timer.
			 */
			if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP)
				return (NXGE_OK);

			/*
			 * Otherwise fire the timer for the nxge to check
			 * the link using the check_link function
			 * of the nxge_xcvr_table and pass "nxgep" as the
			 * argument to the check_link function.
			 */
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

nxge_status_t
nxge_check_tn1010_link(p_nxge_t nxgep)
{
	nxge_status_t	status = NXGE_OK;
	nxge_link_state_t link_up;

	if (nxgep->nxge_magic != NXGE_MAGIC) {
		/* magic is 0 if driver is not attached */
		return (NXGE_ERROR);
	}

	/* Link has been stopped, no need to continue */
	if (nxge_check_link_stop(nxgep) == CHECK_LINK_STOP) {
		return (NXGE_OK);
	}

	if (nxgep->statsp->port_stats.lb_mode > nxge_lb_ext10)
		goto nxge_check_tn1010_link_exit;

	if ((status = nxge_tn1010_check(nxgep, &link_up)) != NXGE_OK)
		goto fail;

nxge_check_tn1010_link_exit:
	if (link_up == LINK_IS_UP)
		nxge_link_is_up(nxgep);
	else if (link_up == LINK_IS_DOWN)
		nxge_link_is_down(nxgep);

	/*
	 * nxge_link_monitor will call (nxgep->xcvr.check_link)
	 * which could be THIS function.
	 */
	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "<== nxge_check_tn1010_link port<%d>",
	    portn));
	return (NXGE_OK);

fail:
	(void) nxge_link_monitor(nxgep, LINK_MONITOR_START);

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_check_tn1010_link: Failed to check link"));
	return (status);
}


/*
 * Fill variable "link_up" with either LINK_IS_UP or LINK_IS_DOWN.
 */
static nxge_status_t
nxge_tn1010_check(p_nxge_t nxgep, nxge_link_state_t *link_up)
{
	nxge_status_t	status = NXGE_OK;
	p_nxge_stats_t	statsp;
	uint8_t		phy_port_addr, portn;
	uint16_t	val;

	*link_up = LINK_NO_CHANGE;

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	phy_port_addr = nxgep->nxge_hw_p->xcvr_addr[portn];
	statsp = nxgep->statsp;

	/* Check if link is up */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    TN1010_AUTONEG_DEV_ADDR, TN1010_AUTONEG_STATUS_REG, &val))
	    != NXGE_OK) {
		goto fail;
	}
	/*
	 * nxge_link_is_up has called nxge_set_tn1010_param and set
	 * portmode and link_speed
	 */
	if (val & TN1010_AN_LINK_STAT_BIT) {
		if (nxgep->link_notify ||
		    nxgep->statsp->mac_stats.link_up == 0) {
			statsp->mac_stats.link_up = 1;
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
	return (NXGE_OK);

fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_tn1010_check: Unable to check TN1010"));
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
				/*
				 * Do not send FMA ereport because this
				 * error does not indicate HW failure.
				 */
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
			/*
			 * Do not send FMA ereport for the following 3 errors
			 * because they do not indicate HW failures.
			 */
			if (status & ICFG_XMAC_RX_CRC_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_crc_err_cnt +=
				    XRXMAC_CRC_ER_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_LEN_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_len_err_cnt +=
				    MAC_LEN_ER_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_VIOL_ERR_CNT_EXP) {
				statsp->xmac_stats.rx_viol_err_cnt +=
				    XRXMAC_CD_VIO_CNT_MASK;
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
			/*
			 * Do not send FMA ereport for the following 3 errors
			 * because they do not indicate HW failures.
			 */
			if (status & ICFG_XMAC_RX_FRAG_CNT_EXP) {
				statsp->xmac_stats.rx_frag_cnt +=
				    XRXMAC_FRAG_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_ALIGNERR_CNT_EXP) {
				statsp->xmac_stats.rx_frame_align_err_cnt +=
				    XRXMAC_AL_ER_CNT_MASK;
			}
			if (status & ICFG_XMAC_RX_LINK_FLT_CNT_EXP) {
				statsp->xmac_stats.rx_linkfault_err_cnt +=
				    XMAC_LINK_FLT_CNT_MASK;
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
	status = nxge_mdio_read(nxgep, phy_port_addr, BCM8704_PMA_PMD_DEV_ADDR,
	    BCM8704_PMD_RECEIVE_SIG_DETECT, &val1);
	if (status != NXGE_OK)
		goto fail;
	rx_sig_ok = ((val1 & GLOB_PMD_RX_SIG_OK) ? B_TRUE : B_FALSE);

	/* Check Device 3 Register 0x20 bit0 */
	if ((status = nxge_mdio_read(nxgep, phy_port_addr, BCM8704_PCS_DEV_ADDR,
	    BCM8704_10GBASE_R_PCS_STATUS_REG, &val2)) != NPI_SUCCESS)
		goto fail;
	pcs_blk_lock = ((val2 & PCS_10GBASE_R_PCS_BLK_LOCK) ? B_TRUE : B_FALSE);

	/* Check Device 4 Register 0x18 bit12 */
	status = nxge_mdio_read(nxgep, phy_port_addr, BCM8704_PHYXS_ADDR,
	    BCM8704_PHYXS_XGXS_LANE_STATUS_REG, &val3);
	if (status != NXGE_OK)
		goto fail;

	switch (nxgep->chip_id) {
	case BCM8704_CHIP_ID:
		link_align = (val3 == (XGXS_LANE_ALIGN_STATUS |
		    XGXS_LANE3_SYNC | XGXS_LANE2_SYNC | XGXS_LANE1_SYNC |
		    XGXS_LANE0_SYNC | 0x400)) ? B_TRUE : B_FALSE;
		break;
	case BCM8706_CHIP_ID:
		link_align = ((val3 & XGXS_LANE_ALIGN_STATUS) &&
		    (val3 & XGXS_LANE3_SYNC) && (val3 & XGXS_LANE2_SYNC) &&
		    (val3 & XGXS_LANE1_SYNC) && (val3 & XGXS_LANE0_SYNC)) ?
		    B_TRUE : B_FALSE;
		break;
	default:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "nxge_check_bcm8704_link:"
		    "Unknown chip ID [0x%x]", nxgep->chip_id));
		goto fail;
	}


#ifdef	NXGE_DEBUG_ALIGN_ERR
	/* Temp workaround for link down issue */
	if (pcs_blk_lock == B_FALSE) {
		if (val2 != 0x4) {
			pcs_blk_lock = B_TRUE;
			cmn_err(CE_NOTE, "!LINK DEBUG: port%d PHY Dev3 "
			    "Reg 0x20 = 0x%x\n", nxgep->mac.portnum, val2);
		}
	}

	if (link_align == B_FALSE) {
		if (val3 != 0x140f) {
			link_align = B_TRUE;
			cmn_err(CE_NOTE, "!LINK DEBUG: port%d PHY Dev4 "
			    "Reg 0x18 = 0x%x\n", nxgep->mac.portnum, val3);
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

static nxge_status_t
nxge_check_mrvl88x2011_link(p_nxge_t nxgep, boolean_t *link_up)
{
	uint8_t		phy;
	nxge_status_t   status = NXGE_OK;
	boolean_t	pma_status;
	boolean_t	pcs_status;
	boolean_t	xgxs_status;
	uint16_t	val;

	phy = nxgep->statsp->mac_stats.xcvr_portn;

	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV1_ADDR,
	    MRVL_88X2011_10G_PMD_STAT_2, &val);

	*link_up = B_FALSE;

	/* Check from Marvell 88X2011 if 10G link is up or down */

	/* Check PMA/PMD Register: 1.0001.2 == 1 */
	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV1_ADDR,
	    MRVL_88X2011_PMA_PMD_STAT_1, &val);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_check_mrvl88x2011_link: pmd=0x%x", val));

	pma_status = ((val & MRVL_88X2011_LNK_STATUS_OK) ? B_TRUE : B_FALSE);

	/* Check PMC Register : 3.0001.2 == 1: read twice */
	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_PMA_PMD_STAT_1, &val);
	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV3_ADDR,
	    MRVL_88X2011_PMA_PMD_STAT_1, &val);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_check_mrvl88x2011_link: pcs=0x%x", val));

	pcs_status = ((val & MRVL_88X2011_LNK_STATUS_OK) ? B_TRUE : B_FALSE);

	/* Check XGXS Register : 4.0018.[0-3,12] */
	MRVL88X2011_RD(nxgep, phy, MRVL_88X2011_USER_DEV4_ADDR,
	    MRVL_88X2011_10G_XGXS_LANE_STAT, &val);

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_check_mrvl88x2011_link: xgxs=0x%x", val));

	xgxs_status = (val == (XGXS_LANE_ALIGN_STATUS | XGXS_LANE3_SYNC |
	    XGXS_LANE2_SYNC | XGXS_LANE1_SYNC |
	    XGXS_LANE0_SYNC | XGXS_PATTERN_TEST_ABILITY |
	    XGXS_LANE_STAT_MAGIC)) ? B_TRUE : B_FALSE;

	*link_up = (pma_status && pcs_status && xgxs_status) ?
	    B_TRUE : B_FALSE;

fail:

	if (*link_up == B_FALSE) {
		/* PCS OFF */
		nxge_mrvl88x2011_led(nxgep, MRVL_88X2011_LED_CTL_OFF);
	} else {
		/* PCS Activity */
		nxge_mrvl88x2011_led(nxgep, MRVL_88X2011_LED_CTL_PCS_ACT);
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    " <== nxge_check_mrvl88x2011_link: up=%d", *link_up));

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

static boolean_t
nxge_is_phy_present(p_nxge_t nxgep, int addr, uint32_t id, uint32_t mask)
{
	uint32_t pma_pmd_id = 0;
	uint32_t pcs_id = 0;
	uint32_t phy_id = 0;

	pma_pmd_id = nxge_get_cl45_pma_pmd_id(nxgep, addr);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_is_phy_present: pma_pmd_id[0x%x]", pma_pmd_id));
	if ((pma_pmd_id & mask) == (id & mask))
		goto found_phy;
	pcs_id = nxge_get_cl45_pcs_id(nxgep, addr);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_is_phy_present: pcs_id[0x%x]", pcs_id));
	if ((pcs_id & mask) == (id & mask))
		goto found_phy;
	phy_id = nxge_get_cl22_phy_id(nxgep, addr);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_is_phy_present: phy_id[0x%x]", phy_id));
	if ((phy_id & mask) == (id & mask))
		goto found_phy;

	return (B_FALSE);

found_phy:
	return (B_TRUE);
}

/* Check if the given id read using the given MDIO Clause is supported */

static boolean_t
nxge_is_supported_phy(uint32_t id, uint8_t type)
{
	int		i;
	boolean_t	found = B_FALSE;

	switch (type) {
	case CLAUSE_45_TYPE:
		for (i = 0; i < NUM_CLAUSE_45_IDS; i++) {
			if (((nxge_supported_cl45_ids[i] & BCM_PHY_ID_MASK) ==
			    (id & BCM_PHY_ID_MASK)) ||
			    (TN1010_DEV_ID == (id & TN1010_DEV_ID_MASK))) {
				found = B_TRUE;
				break;
			}
		}
		break;
	case CLAUSE_22_TYPE:
		for (i = 0; i < NUM_CLAUSE_22_IDS; i++) {
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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PMA_PMD_DEV_ADDR,
	    NXGE_DEV_ID_REG_1, &val1);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PMA_PMD_DEV_ADDR,
	    NXGE_DEV_ID_REG_2, &val2);
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

	/* Concatenate the Device ID stored in two registers. */
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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PCS_DEV_ADDR,
	    NXGE_DEV_ID_REG_1, &val1);
	(void) npi_mac_mif_mdio_read(handle, phy_port, NXGE_PCS_DEV_ADDR,
	    NXGE_DEV_ID_REG_2, &val2);
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);

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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);
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
	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);
	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PHY ID [0x%llx]",
	    phy_port, phy_id));

	return (phy_id);
}

/*
 * Scan the PHY ports 0 through 31 to get the PHY ID using Clause 22 MDIO
 * read and the PMA/PMD device ID and the PCS device ID using Clause 45 MDIO
 * read. Then use the values obtained to determine the phy type of each port
 * and the Neptune type.
 *
 * This function sets hw_p->xcvr_addr[i] for future MDIO access and set
 * hw_p->niu_type for each nxge instance to figure out nxgep->mac.portmode
 * in case the portmode information is not available via OBP, nxge.conf,
 * VPD or SEEPROM.
 */
nxge_status_t
nxge_scan_ports_phy(p_nxge_t nxgep, p_nxge_hw_list_t hw_p)
{
	int		i, j, l;
	uint32_t	pma_pmd_dev_id = 0;
	uint32_t	pcs_dev_id = 0;
	uint32_t	phy_id = 0;
	uint32_t	port_pma_pmd_dev_id[NXGE_PORTS_NEPTUNE];
	uint32_t	port_pcs_dev_id[NXGE_PORTS_NEPTUNE];
	uint32_t	port_phy_id[NXGE_PORTS_NEPTUNE];
	uint8_t		pma_pmd_dev_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		pcs_dev_fd[NXGE_MAX_PHY_PORTS];
	uint8_t		phy_fd_arr[NXGE_MAX_PHY_PORTS];
	uint8_t		port_fd_arr[NXGE_MAX_PHY_PORTS];
	uint8_t		total_port_fd, total_phy_fd;
	uint8_t		num_xaui;
	nxge_status_t	status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_scan_ports_phy: "));
	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_scan_ports_phy: nxge niu_type[0x%x]",
	    nxgep->niu_type));

	if (isLDOMguest(nxgep)) {
		hw_p->niu_type = NIU_TYPE_NONE;
		hw_p->platform_type = P_NEPTUNE_NONE;
		return (NXGE_OK);
	}

	j = l = 0;
	total_port_fd = total_phy_fd = 0;
	/*
	 * Clause 45 and Clause 22 port/phy addresses 0 through 7 are reserved
	 * for on chip serdes usages. "i" in the following for loop starts at 8.
	 */
	for (i = NXGE_EXT_PHY_PORT_ST; i < NXGE_MAX_PHY_PORTS; i++) {

		pma_pmd_dev_id = nxge_get_cl45_pma_pmd_id(nxgep, i);

		if (nxge_is_supported_phy(pma_pmd_dev_id, CLAUSE_45_TYPE)) {
			pma_pmd_dev_fd[i] = 1;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] "
			    "PMA/PMD dev %x found", i, pma_pmd_dev_id));
			if (j < NXGE_PORTS_NEPTUNE) {
				if ((pma_pmd_dev_id & TN1010_DEV_ID_MASK)
				    == TN1010_DEV_ID) {
					port_pma_pmd_dev_id[j] = TN1010_DEV_ID;
				} else {
					port_pma_pmd_dev_id[j] =
					    pma_pmd_dev_id & BCM_PHY_ID_MASK;
				}
				port_fd_arr[j] = (uint8_t)i;
				j++;
			}
		} else {
			pma_pmd_dev_fd[i] = 0;
		}

		pcs_dev_id = nxge_get_cl45_pcs_id(nxgep, i);

		if (nxge_is_supported_phy(pcs_dev_id, CLAUSE_45_TYPE)) {
			pcs_dev_fd[i] = 1;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PCS "
			    "dev %x found", i, pcs_dev_id));
			if (pma_pmd_dev_fd[i] == 1) {
				if ((pcs_dev_id & TN1010_DEV_ID_MASK)
				    == TN1010_DEV_ID) {
					port_pcs_dev_id[j - 1] =
					    TN1010_DEV_ID;
				} else {
					port_pcs_dev_id[j - 1] =
					    pcs_dev_id &
					    BCM_PHY_ID_MASK;
				}
			} else {
				if (j < NXGE_PORTS_NEPTUNE) {
					if ((pcs_dev_id & TN1010_DEV_ID_MASK)
					    == TN1010_DEV_ID) {
						port_pcs_dev_id[j] =
						    TN1010_DEV_ID;
					} else {
						port_pcs_dev_id[j] =
						    pcs_dev_id &
						    BCM_PHY_ID_MASK;
					}
					port_fd_arr[j] = (uint8_t)i;
					j++;
				}
			}
		} else {
			pcs_dev_fd[i] = 0;
		}

		if (pcs_dev_fd[i] || pma_pmd_dev_fd[i]) {
			total_port_fd ++;
		}

		phy_id = nxge_get_cl22_phy_id(nxgep, i);
		if (nxge_is_supported_phy(phy_id, CLAUSE_22_TYPE)) {
			total_phy_fd ++;
			NXGE_DEBUG_MSG((nxgep, MAC_CTL, "port[%d] PHY ID"
			    "%x found", i, phy_id));
			if (l < NXGE_PORTS_NEPTUNE) {
				if ((phy_id & TN1010_DEV_ID_MASK)
				    == TN1010_DEV_ID) {
					port_phy_id[l] = TN1010_DEV_ID;
				} else {
					port_phy_id[l]
					    = phy_id & BCM_PHY_ID_MASK;
				}
				phy_fd_arr[l] = (uint8_t)i;
				l++;
			}
		}
	}

	switch (total_port_fd) {
	case 2:
		switch (total_phy_fd) {
		case 2:
			/* 2 10G, 2 1G RGMII Fiber */
			if ((((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pcs_dev_id[1] == PHY_BCM8704_FAMILY)) ||
			    ((port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pma_pmd_dev_id[1] == PHY_BCM8704_FAMILY))) &&
			    ((port_phy_id[0] == PHY_BCM5482_FAMILY) &&
			    (port_phy_id[1] == PHY_BCM5482_FAMILY))) {

				hw_p->platform_type = P_NEPTUNE_GENERIC;

				hw_p->niu_type = NEPTUNE_2_10GF_2_1GRF;

				hw_p->xcvr_addr[0] = port_fd_arr[0];
				hw_p->xcvr_addr[1] = port_fd_arr[1];
				hw_p->xcvr_addr[2] = phy_fd_arr[0];
				hw_p->xcvr_addr[3] = phy_fd_arr[1];

				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "ARTM card with 2 10G, 2 1G"));
			} else {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "Unsupported neptune type 1"));
				goto error_exit;
			}
			break;

		case 1:
			/* TODO - 2 10G, 1 1G */
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 2 10G, 1 1G"));
			goto error_exit;
		case 0:
			/*
			 * 2 10G: 2XGF NIC, Marvell, Goa, Huron with 2 XAUI
			 * cards, etc.
			 */
			if (((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pcs_dev_id[1] == PHY_BCM8704_FAMILY)) ||
			    ((port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY) &&
			    (port_pma_pmd_dev_id[1] == PHY_BCM8704_FAMILY)) ||
			    ((port_pcs_dev_id[0] == MARVELL_88X201X_PHY_ID) &&
			    (port_pcs_dev_id[1] == MARVELL_88X201X_PHY_ID)) ||
			    ((port_pma_pmd_dev_id[0] ==
			    MARVELL_88X201X_PHY_ID) &&
			    (port_pma_pmd_dev_id[1] ==
			    MARVELL_88X201X_PHY_ID))) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */

				switch (port_fd_arr[0]) {
				case NEPTUNE_CLAUSE45_PORT_ADDR_BASE:
					/*
					 * The Marvell case also falls into
					 * this case as
					 * MRVL88X2011_NEPTUNE_PORT_ADDR_BASE
					 * == NEPTUNE_CLAUSE45_PORT_ADDR_BASE.
					 * This is OK for the 2 10G case.
					 */
					hw_p->niu_type = NEPTUNE_2_10GF;
					hw_p->platform_type =
					    P_NEPTUNE_ATLAS_2PORT;
					break;
				case GOA_CLAUSE45_PORT_ADDR_BASE:
					if (hw_p->platform_type !=
					    P_NEPTUNE_NIU) {
						hw_p->platform_type =
						    P_NEPTUNE_GENERIC;
						hw_p->niu_type =
						    NEPTUNE_2_10GF;
					}
					break;
				default:
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unsupported neptune type 2 - 1"));
					goto error_exit;
				}

				for (i = 0; i < 2; i++) {
					hw_p->xcvr_addr[i] = port_fd_arr[i];
				}

			/* Both XAUI slots have copper XAUI cards */
			} else if ((((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) &&
			    ((port_pcs_dev_id[1] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID)) ||
			    (((port_pma_pmd_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) &&
			    ((port_pma_pmd_dev_id[1] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID))) {
				hw_p->niu_type = NEPTUNE_2_TN1010;
				hw_p->xcvr_addr[0] = port_fd_arr[0];
				hw_p->xcvr_addr[1] = port_fd_arr[1];

			/* Slot0 has fiber XAUI, slot1 has copper XAUI */
			} else if ((port_pcs_dev_id[0] == PHY_BCM8704_FAMILY &&
			    (port_pcs_dev_id[1] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) ||
			    (port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY &&
			    (port_pma_pmd_dev_id[1] & TN1010_DEV_ID_MASK) ==
			    TN1010_DEV_ID)) {
				hw_p->niu_type = NEPTUNE_1_10GF_1_TN1010;
				hw_p->xcvr_addr[0] = port_fd_arr[0];
				hw_p->xcvr_addr[1] = port_fd_arr[1];

			/* Slot0 has copper XAUI, slot1 has fiber XAUI */
			} else if ((port_pcs_dev_id[1] == PHY_BCM8704_FAMILY &&
			    (port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) ||
			    (port_pma_pmd_dev_id[1] == PHY_BCM8704_FAMILY &&
			    (port_pma_pmd_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID)) {
				hw_p->niu_type = NEPTUNE_1_TN1010_1_10GF;
				hw_p->xcvr_addr[0] = port_fd_arr[0];
				hw_p->xcvr_addr[1] = port_fd_arr[1];

			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 2"));
				goto error_exit;
			}
			break;

		case 4:
			if (nxge_get_num_of_xaui(
			    port_pma_pmd_dev_id, port_pcs_dev_id,
			    port_phy_id, &num_xaui) == NXGE_ERROR) {
				goto error_exit;
			}
			if (num_xaui != 2)
				goto error_exit;

			/*
			 *  Maramba with 2 XAUIs (either fiber or copper)
			 *
			 * Check the first phy port address against
			 * the known phy start addresses to determine
			 * the platform type.
			 */
			switch (phy_fd_arr[0]) {
			case MARAMBA_P0_CLAUSE22_PORT_ADDR_BASE:
				hw_p->platform_type =
				    P_NEPTUNE_MARAMBA_P0;
				break;
			case MARAMBA_P1_CLAUSE22_PORT_ADDR_BASE:
				hw_p->platform_type =
				    P_NEPTUNE_MARAMBA_P1;
				break;
			default:
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "Unknown port %d...Cannot "
				    "determine platform type", i));
				goto error_exit;
			}

			hw_p->xcvr_addr[0] = port_fd_arr[0];
			hw_p->xcvr_addr[1] = port_fd_arr[1];
			hw_p->xcvr_addr[2] = phy_fd_arr[2];
			hw_p->xcvr_addr[3] = phy_fd_arr[3];

			/* slot0 has fiber XAUI, slot1 has Cu XAUI */
			if (port_pcs_dev_id[0] == PHY_BCM8704_FAMILY &&
			    (port_pcs_dev_id[1] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) {
				hw_p->niu_type = NEPTUNE_1_10GF_1_TN1010_2_1GC;

			/* slot0 has Cu XAUI, slot1 has fiber XAUI */
			} else if (((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) &&
			    port_pcs_dev_id[1] == PHY_BCM8704_FAMILY) {
				hw_p->niu_type = NEPTUNE_1_TN1010_1_10GF_2_1GC;

			/* Both slots have fiber XAUI */
			} else if (port_pcs_dev_id[0] == PHY_BCM8704_FAMILY &&
			    port_pcs_dev_id[1] == PHY_BCM8704_FAMILY) {
				hw_p->niu_type = NEPTUNE_2_10GF_2_1GC;

			/* Both slots have copper XAUI */
			} else if (((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) &&
			    (port_pcs_dev_id[1] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) {
				hw_p->niu_type = NEPTUNE_2_TN1010_2_1GC;

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
	case 1: 	/* Only one clause45 port */
		switch (total_phy_fd) {	/* Number of clause22 ports */
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
		case 0:	/* N2 with 1 XAUI (fiber or copper) */
			/* Fiber XAUI */
			if (port_pcs_dev_id[0] == PHY_BCM8704_FAMILY ||
			    port_pma_pmd_dev_id[0] == PHY_BCM8704_FAMILY) {

				/*
				 * Check the first phy port address against
				 * the known phy start addresses to determine
				 * the platform type.
				 */

				switch (port_fd_arr[0]) {
				case N2_CLAUSE45_PORT_ADDR_BASE:
				case (N2_CLAUSE45_PORT_ADDR_BASE + 1):
				case ALT_GOA_CLAUSE45_PORT1_ADDR:
					/*
					 * If hw_p->platform_type ==
					 * P_NEPTUNE_NIU, then portmode
					 * is already known, so there is
					 * no need to figure out hw_p->
					 * platform_type because
					 * platform_type is only for
					 * figuring out portmode.
					 */
					if (hw_p->platform_type !=
					    P_NEPTUNE_NIU) {
						hw_p->platform_type =
						    P_NEPTUNE_GENERIC;
						hw_p->niu_type =
						    NEPTUNE_2_10GF;
					}
					break;
				default:
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unsupported neptune type 10"));
					goto error_exit;
				}
				/*
				 * For GOA, which is a hot swappable PHY, the
				 * phy address to function number mapping
				 * should be preserved, i.e., addr 16 is
				 * assigned to function 0 and 20 to function 1
				 * But for Huron XAUI, the assignment should
				 * be by function number, i.e., whichever
				 * function number attaches should be
				 * assigned the available PHY (this is required
				 * primarily to support pre-production Huron
				 * boards where function 0 is mapped to addr 17
				 */
				if (port_fd_arr[0] ==
				    ALT_GOA_CLAUSE45_PORT1_ADDR) {
					hw_p->xcvr_addr[1] = port_fd_arr[0];
				} else {
					hw_p->xcvr_addr[nxgep->function_num] =
					    port_fd_arr[0];
				}

			/* A 10G copper XAUI in either slot0 or slot1 */
			} else if ((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID ||
			    (port_pma_pmd_dev_id[0] & TN1010_DEV_ID_MASK)
			    == TN1010_DEV_ID) {
				switch (port_fd_arr[0]) {
				/* The XAUI is in slot0 */
				case N2_CLAUSE45_PORT_ADDR_BASE:
					hw_p->niu_type = NEPTUNE_1_TN1010;
					break;

				/* The XAUI is in slot1 */
				case (N2_CLAUSE45_PORT_ADDR_BASE + 1):
					hw_p->niu_type
					    = NEPTUNE_1_NONE_1_TN1010;
					break;
				default:
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unsupported XAUI port address"));
					goto error_exit;
				}
				hw_p->xcvr_addr[nxgep->function_num]
				    = port_fd_arr[0];

			} else {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported PHY type"));
				goto error_exit;
			}
			break;
		case 4: /* Maramba always have 4 clause 45 ports */

			/* Maramba with 1 XAUI */
			if ((port_pcs_dev_id[0] != PHY_BCM8704_FAMILY) &&
			    (port_pma_pmd_dev_id[0] != PHY_BCM8704_FAMILY) &&
			    ((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
			    != TN1010_DEV_ID) &&
			    ((port_pma_pmd_dev_id[0] & TN1010_DEV_ID_MASK)
			    != TN1010_DEV_ID)) {
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 12"));
				goto error_exit;
			}

			/*
			 * Check the first phy port address against
			 * the known phy start addresses to determine
			 * the platform type.
			 */
			switch (phy_fd_arr[0]) {
			case MARAMBA_P0_CLAUSE22_PORT_ADDR_BASE:
				hw_p->platform_type =
				    P_NEPTUNE_MARAMBA_P0;
				break;
			case MARAMBA_P1_CLAUSE22_PORT_ADDR_BASE:
				hw_p->platform_type =
				    P_NEPTUNE_MARAMBA_P1;
				break;
			default:
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "Unknown port %d...Cannot "
				    "determine platform type 10 - 2",
				    i));
				goto error_exit;
			}

			/*
			 * Check the clause45 address to determine
			 * if XAUI is in port 0 or port 1.
			 */
			switch (port_fd_arr[0]) {
			case MARAMBA_CLAUSE45_PORT_ADDR_BASE:
				if (port_pcs_dev_id[0]
				    == PHY_BCM8704_FAMILY ||
				    port_pma_pmd_dev_id[0]
				    == PHY_BCM8704_FAMILY) {
					hw_p->niu_type
					    = NEPTUNE_1_10GF_3_1GC;
				} else {
					hw_p->niu_type
					    = NEPTUNE_1_TN1010_3_1GC;
				}
				hw_p->xcvr_addr[0] = port_fd_arr[0];
				for (i = 1; i < NXGE_MAX_PORTS; i++) {
					hw_p->xcvr_addr[i] =
					    phy_fd_arr[i];
				}
				break;
			case (MARAMBA_CLAUSE45_PORT_ADDR_BASE + 1):
				if (port_pcs_dev_id[0]
				    == PHY_BCM8704_FAMILY ||
				    port_pma_pmd_dev_id[0]
				    == PHY_BCM8704_FAMILY) {
					hw_p->niu_type =
					    NEPTUNE_1_1GC_1_10GF_2_1GC;
				} else {
					hw_p->niu_type =
					    NEPTUNE_1_1GC_1_TN1010_2_1GC;
				}
				hw_p->xcvr_addr[0] = phy_fd_arr[0];
				hw_p->xcvr_addr[1] = port_fd_arr[0];
				hw_p->xcvr_addr[2] = phy_fd_arr[2];
				hw_p->xcvr_addr[3] = phy_fd_arr[3];
				break;
			default:
				NXGE_DEBUG_MSG((nxgep, MAC_CTL,
				    "Unsupported neptune type 11"));
				goto error_exit;
			}
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Maramba with 1 XAUI (fiber or copper)"));
			break;
		default:
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "Unsupported neptune type 13"));
			goto error_exit;
		}
		break;
	case 0: /* 4 ports Neptune based NIC */
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
				switch (phy_fd_arr[0]) {
				case MARAMBA_P1_CLAUSE22_PORT_ADDR_BASE:
					hw_p->platform_type =
					    P_NEPTUNE_MARAMBA_P1;
					break;
				case NEPTUNE_CLAUSE22_PORT_ADDR_BASE:
					hw_p->platform_type =
					    P_NEPTUNE_ATLAS_4PORT;
					break;
				default:
					NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
					    "Unknown port %d...Cannot "
					    "determine platform type", i));
					goto error_exit;
				}
				hw_p->niu_type = NEPTUNE_4_1GC;
				for (i = 0; i < NXGE_MAX_PORTS; i++) {
					hw_p->xcvr_addr[i] = phy_fd_arr[i];
				}
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
			if ((port_phy_id[0] == PHY_BCM5482_FAMILY) &&
			    (port_phy_id[1] == PHY_BCM5482_FAMILY)) {
				hw_p->platform_type = P_NEPTUNE_GENERIC;
				hw_p->niu_type = NEPTUNE_2_1GRF;
				hw_p->xcvr_addr[2] = phy_fd_arr[0];
				hw_p->xcvr_addr[3] = phy_fd_arr[1];
			} else {
				NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
				    "Unsupported neptune type 16"));
				goto error_exit;
			}
			NXGE_DEBUG_MSG((nxgep, MAC_CTL,
			    "2 RGMII Fiber ports - RTM"));
			break;

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
		xcvr_portn = MARAMBA_P1_CLAUSE22_PORT_ADDR_BASE;
	} else if (nxgep->nxge_hw_p->platform_type == P_NEPTUNE_MARAMBA_P0) {
		xcvr_portn = MARAMBA_P0_CLAUSE22_PORT_ADDR_BASE;
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

	MUTEX_ENTER(&nxgep->nxge_hw_p->nxge_mdio_lock);
	rs = npi_mac_mif_mii_write(nxgep->npi_handle,
	    xcvr_portn, BCM5464R_MISC, 0xb4ee);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_bcm5464_link_led_off: npi_mac_mif_mii_write "
		    "returned error 0x[%x]", rs));
		MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);
		return;
	}

	rs = npi_mac_mif_mii_write(nxgep->npi_handle,
	    xcvr_portn, BCM5464R_MISC, 0xb8ee);
	if (rs != NPI_SUCCESS) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "<== nxge_bcm5464_link_led_off: npi_mac_mif_mii_write "
		    "returned error 0x[%x]", rs));
	}

	MUTEX_EXIT(&nxgep->nxge_hw_p->nxge_mdio_lock);
}

static nxge_status_t
nxge_mii_get_link_mode(p_nxge_t nxgep)
{
	p_nxge_stats_t	statsp;
	uint8_t		xcvr_portn;
	p_mii_regs_t	mii_regs;
	mii_mode_control_stat_t	mode;
	int		status = NXGE_OK;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mii_get_link_mode"));

	statsp = nxgep->statsp;
	xcvr_portn = statsp->mac_stats.xcvr_portn;
	mii_regs = NULL;
	mode.value = 0;
	mode.bits.shadow = NXGE_MII_MODE_CONTROL_REG;
#if defined(__i386)
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->shadow),
	    mode.value)) != NXGE_OK) {
		goto fail;
#else
	if ((status = nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->shadow),
	    mode.value)) != NXGE_OK) {
		goto fail;
#endif
	}
#if defined(__i386)
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->shadow),
	    &mode.value)) != NXGE_OK) {
		goto fail;
	}
#else
	if ((status = nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->shadow),
	    &mode.value)) != NXGE_OK) {
		goto fail;
	}
#endif

	if (mode.bits.mode == NXGE_MODE_SELECT_FIBER) {
		nxgep->mac.portmode = PORT_1G_RGMII_FIBER;
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_mii_get_link_mode: fiber mode"));
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "nxge_mii_get_link_mode: "
	    "(address 0x%x) port 0x%x mode value 0x%x link mode 0x%x",
	    NXGE_MII_MODE_CONTROL_REG, xcvr_portn,
	    mode.value, nxgep->mac.portmode));

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_mii_get_link_mode"));
	return (status);
fail:
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "<== nxge_mii_get_link_mode (failed)"));
	return (NXGE_ERROR);
}

nxge_status_t
nxge_mac_set_framesize(p_nxge_t nxgep)
{
	npi_attr_t		ap;
	uint8_t			portn;
	npi_handle_t		handle;
	npi_status_t		rs = NPI_SUCCESS;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL, "==> nxge_mac_set_framesize"));

	portn = NXGE_GET_PORT_NUM(nxgep->function_num);
	handle = nxgep->npi_handle;

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "==> nxge_mac_sec_framesize: port<%d> "
	    "min framesize %d max framesize %d ",
	    portn,
	    nxgep->mac.minframesize,
	    nxgep->mac.maxframesize));

	SET_MAC_ATTR2(handle, ap, portn,
	    MAC_PORT_FRAME_SIZE,
	    nxgep->mac.minframesize,
	    nxgep->mac.maxframesize,
	    rs);
	if (rs != NPI_SUCCESS) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "<== nxge_mac_set_framesize: failed to configure "
		    "max/min frame size port %d", portn));

		return (NXGE_ERROR | rs);
	}

	NXGE_DEBUG_MSG((nxgep, MAC_CTL,
	    "<== nxge_mac_set_framesize: port<%d>", portn));

	return (NXGE_OK);
}

static nxge_status_t
nxge_get_num_of_xaui(uint32_t *port_pma_pmd_dev_id,
    uint32_t *port_pcs_dev_id, uint32_t *port_phy_id, uint8_t *num_xaui)
{
	uint8_t i;

	for (i = 0; i < 4; i++) {
		if (port_phy_id[i] != PHY_BCM5464R_FAMILY)
			return (NXGE_ERROR);
	}

	*num_xaui = 0;
	if ((port_pma_pmd_dev_id[0]  == PHY_BCM8704_FAMILY &&
	    port_pcs_dev_id[0] 	== PHY_BCM8704_FAMILY) ||
	    (((port_pma_pmd_dev_id[0] & TN1010_DEV_ID_MASK)
	    == TN1010_DEV_ID) &&
	    ((port_pcs_dev_id[0] & TN1010_DEV_ID_MASK)
	    == TN1010_DEV_ID))) {
		(*num_xaui) ++;
	}
	if ((port_pma_pmd_dev_id[1]  == PHY_BCM8704_FAMILY &&
	    port_pcs_dev_id[1] == PHY_BCM8704_FAMILY) ||
	    (((port_pma_pmd_dev_id[1] & TN1010_DEV_ID_MASK)
	    == TN1010_DEV_ID) &&
	    ((port_pcs_dev_id[1] & TN1010_DEV_ID_MASK)
	    == TN1010_DEV_ID))) {
		(*num_xaui) ++;
	}
	return (NXGE_OK);
}

/*
 * Instruction from Teranetics:  Once you detect link is up, go
 * read Reg 30.1.4 for link speed: '1' for 1G and '0' for 10G. You
 * may want to qualify it by first checking Register 30.1.7:6 and
 * making sure it reads "01" (Auto-Neg Complete).
 *
 * If this function is called when the link is down or before auto-
 * negotiation has completed, then the speed of the PHY is not certain.
 * In such cases, this function returns 1G as the default speed with
 * NXGE_OK status instead of NXGE_ERROR.  It is OK to initialize the
 * driver based on a default speed because this function will be called
 * again when the link comes up.  Returning NXGE_ERROR, which may
 * cause brutal chain reaction in caller functions, is not necessary.
 */
static nxge_status_t
nxge_get_tn1010_speed(p_nxge_t nxgep, uint16_t *speed)
{
	uint8_t		phy_port_addr, autoneg_stat, link_up;
	nxge_status_t	status = NXGE_OK;
	uint16_t	val;
	uint8_t		portn = NXGE_GET_PORT_NUM(nxgep->function_num);

	/* Set default speed to 10G */
	*speed = TN1010_SPEED_10G;

	/* Set Clause 45 */
	npi_mac_mif_set_indirect_mode(nxgep->npi_handle, B_TRUE);

	phy_port_addr = nxgep->nxge_hw_p->xcvr_addr[portn];

	/* Check Device 1 Register 0xA bit0 for link up status */
	status = nxge_mdio_read(nxgep, phy_port_addr,
	    TN1010_AUTONEG_DEV_ADDR, TN1010_AUTONEG_STATUS_REG, &val);
	if (status != NXGE_OK)
		goto fail;

	link_up = ((val & TN1010_AN_LINK_STAT_BIT)
	    ? B_TRUE : B_FALSE);
	if (link_up == B_FALSE) {
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_get_tn1010_speed: link is down"));
		goto nxge_get_tn1010_speed_exit;
	}

	if ((status = nxge_mdio_read(nxgep, phy_port_addr,
	    TN1010_VENDOR_MMD1_DEV_ADDR, TN1010_VENDOR_MMD1_STATUS_REG,
	    &val)) != NXGE_OK) {
		goto fail;
	}
	autoneg_stat = (val & TN1010_VENDOR_MMD1_AN_STAT_BITS) >>
	    TN1010_VENDOR_MMD1_AN_STAT_SHIFT;

	/*
	 * Return NXGE_OK even when we can not get a settled speed. In
	 * such case, the speed reported should not be trusted but that
	 * is OK, we will call this function periodically and will get
	 * the correct speed after the link is up.
	 */
	switch (autoneg_stat) {
	case TN1010_AN_IN_PROG:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_get_tn1010_speed: Auto-negotiation in progress"));
		break;
	case TN1010_AN_COMPLETE:
		if ((status = nxge_mdio_read(nxgep, phy_port_addr,
		    TN1010_VENDOR_MMD1_DEV_ADDR,
		    TN1010_VENDOR_MMD1_STATUS_REG,
		    &val)) != NXGE_OK) {
			goto fail;
		}
		*speed = (val & TN1010_VENDOR_MMD1_AN_SPEED_BIT) >>
		    TN1010_VENDOR_MMD1_AN_SPEED_SHIFT;
		break;
	case TN1010_AN_RSVD:
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_get_tn1010_speed: Autoneg status undefined"));
		break;
	case TN1010_AN_FAILED:
		NXGE_DEBUG_MSG((nxgep, MAC_CTL,
		    "nxge_get_tn1010_speed: Auto-negotiation failed"));
		break;
	default:
		break;
	}
nxge_get_tn1010_speed_exit:
	return (NXGE_OK);
fail:
	return (status);
}


/*
 * Teranetics TN1010 PHY chip supports both 1G and 10G modes, this function
 * figures out the speed of the PHY determined by the autonegotiation
 * process and sets the following 3 parameters,
 * 	nxgep->mac.portmode
 *     	nxgep->statsp->mac_stats.link_speed
 *	nxgep->statsp->mac_stats.xcvr_inuse
 */
static nxge_status_t
nxge_set_tn1010_param(p_nxge_t nxgep)
{
	uint16_t speed;

	if (nxge_get_tn1010_speed(nxgep,  &speed) != NXGE_OK) {
		NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
		    "nxge_set_tn1010_param: "
		    "Failed to get TN1010 speed"));
		return (NXGE_ERROR);
	}
	if (speed == TN1010_SPEED_1G) {
		nxgep->mac.portmode = PORT_1G_TN1010;
		nxgep->statsp->mac_stats.link_speed = 1000;
		nxgep->statsp->mac_stats.xcvr_inuse = PCS_XCVR;
	} else {
		nxgep->mac.portmode = PORT_10G_TN1010;
		nxgep->statsp->mac_stats.link_speed = 10000;
		nxgep->statsp->mac_stats.xcvr_inuse = XPCS_XCVR;
	}
	return (NXGE_OK);
}

#ifdef NXGE_DEBUG
static void
nxge_mii_dump(p_nxge_t nxgep)
{
	p_nxge_stats_t	statsp;
	uint8_t		xcvr_portn;
	p_mii_regs_t	mii_regs;
	mii_bmcr_t	bmcr;
	mii_bmsr_t	bmsr;
	mii_idr1_t	idr1;
	mii_idr2_t	idr2;
	mii_mode_control_stat_t	mode;
	p_nxge_param_t	param_arr;

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL, "==> nxge_mii_dump"));

	statsp = nxgep->statsp;
	xcvr_portn = statsp->mac_stats.xcvr_portn;

	mii_regs = NULL;

#if defined(__i386)
	(void) nxge_mii_read(nxgep, nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmcr), &bmcr.value);
#else
	(void) nxge_mii_read(nxgep, nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmcr), &bmcr.value);
#endif
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_dump: bmcr (0) xcvr 0x%x value 0x%x",
	    xcvr_portn, bmcr.value));

#if defined(__i386)
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->bmsr), &bmsr.value);
#else
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->bmsr), &bmsr.value);
#endif
	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_dump: bmsr (1) xcvr 0x%x value 0x%x",
	    xcvr_portn, bmsr.value));

#if defined(__i386)
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->idr1), &idr1.value);
#else
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->idr1), &idr1.value);
#endif


#if defined(__i386)
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->idr2), &idr2.value);
#else
	(void) nxge_mii_read(nxgep,
	    nxgep->statsp->mac_stats.xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->idr2), &idr2.value);
#endif

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_dump: idr1 (2) xcvr 0x%x value 0x%x",
	    xcvr_portn, idr1.value));

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_dump: idr2 (3) xcvr 0x%x value 0x%x",
	    xcvr_portn, idr2.value));

	mode.value = 0;
	mode.bits.shadow = NXGE_MII_MODE_CONTROL_REG;

#if defined(__i386)
	(void) nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->shadow), mode.value);

	(void) nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint32_t)(&mii_regs->shadow), &mode.value);
#else
	(void) nxge_mii_write(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->shadow), mode.value);

	(void) nxge_mii_read(nxgep, xcvr_portn,
	    (uint8_t)(uint64_t)(&mii_regs->shadow), &mode.value);
#endif

	NXGE_ERROR_MSG((nxgep, NXGE_ERR_CTL,
	    "nxge_mii_dump: mode control xcvr 0x%x value 0x%x",
	    xcvr_portn, mode.value));
}
#endif
