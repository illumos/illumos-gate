/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2007 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "e1000g_sw.h"
#include "e1000g_debug.h"

static int e1000g_nd_param_load(struct e1000g *Adapter);
static int e1000g_nd_set(queue_t *q, mblk_t *mp,
    char *value, caddr_t cp, cred_t *credp);
static int e1000g_nd_get(queue_t *q, mblk_t *mp,
    caddr_t cp, cred_t *credp);
static void e1000g_nd_get_param_val(nd_param_t *ndp);
static void e1000g_nd_set_param_val(nd_param_t *ndp, uint32_t value);

/*
 * Notes:
 *	The first character of the <name> field encodes the read/write
 *	status of the parameter:
 *		'-' => read-only
 *		'+' => read/write,
 *		'?' => read/write on copper, read-only on serdes
 *		'!' => invisible!
 *
 *	For writable parameters, we check for a driver property with the
 *	same name; if found, and its value is in range, we initialise
 *	the parameter from the property, overriding the default in the
 *	table below.
 *
 *	A NULL in the <name> field terminates the array.
 *
 *	The <info> field is used here to provide the index of the
 *	parameter to be initialised; thus it doesn't matter whether
 *	this table is kept ordered or not.
 *
 *	The <info> field in the per-instance copy, on the other hand,
 *	is used to count assignments so that we can tell when a magic
 *	parameter has been set via ndd (see e1000g_nd_set()).
 */
static const nd_param_t nd_template[] = {
/* info			  min max init	adapter	r/w+name */

/* Our hardware capabilities */
{ PARAM_AUTONEG_CAP,	    0, 1, 1,	NULL,	"-autoneg_cap"		},
{ PARAM_PAUSE_CAP,	    0, 1, 1,	NULL,	"-pause_cap"		},
{ PARAM_ASYM_PAUSE_CAP,	    0, 1, 1,	NULL,	"-asym_pause_cap"	},
{ PARAM_1000FDX_CAP,	    0, 1, 1,	NULL,	"-1000fdx_cap"		},
{ PARAM_1000HDX_CAP,	    0, 1, 1,	NULL,	"-1000hdx_cap"		},
{ PARAM_100T4_CAP,	    0, 1, 0,	NULL,	"-100T4_cap"		},
{ PARAM_100FDX_CAP,	    0, 1, 1,	NULL,	"-100fdx_cap"		},
{ PARAM_100HDX_CAP,	    0, 1, 1,	NULL,	"-100hdx_cap"		},
{ PARAM_10FDX_CAP,	    0, 1, 1,	NULL,	"-10fdx_cap"		},
{ PARAM_10HDX_CAP,	    0, 1, 1,	NULL,	"-10hdx_cap"		},

/* Our advertised capabilities */
{ PARAM_ADV_AUTONEG_CAP,    0, 1, 1,	NULL,	"?adv_autoneg_cap"	},
{ PARAM_ADV_PAUSE_CAP,	    0, 1, 1,	NULL,	"-adv_pause_cap"	},
{ PARAM_ADV_ASYM_PAUSE_CAP, 0, 1, 1,	NULL,	"-adv_asym_pause_cap"	},
{ PARAM_ADV_1000FDX_CAP,    0, 1, 1,	NULL,	"?adv_1000fdx_cap"	},
{ PARAM_ADV_1000HDX_CAP,    0, 1, 1,	NULL,	"-adv_1000hdx_cap"	},
{ PARAM_ADV_100T4_CAP,	    0, 1, 0,	NULL,	"-adv_100T4_cap"	},
{ PARAM_ADV_100FDX_CAP,	    0, 1, 1,	NULL,	"?adv_100fdx_cap"	},
{ PARAM_ADV_100HDX_CAP,	    0, 1, 1,	NULL,	"?adv_100hdx_cap"	},
{ PARAM_ADV_10FDX_CAP,	    0, 1, 1,	NULL,	"?adv_10fdx_cap"	},
{ PARAM_ADV_10HDX_CAP,	    0, 1, 1,	NULL,	"?adv_10hdx_cap"	},

/* Partner's advertised capabilities */
{ PARAM_LP_AUTONEG_CAP,	    0, 1, 0,	NULL,	"-lp_autoneg_cap"	},
{ PARAM_LP_PAUSE_CAP,	    0, 1, 0,	NULL,	"-lp_pause_cap"		},
{ PARAM_LP_ASYM_PAUSE_CAP,  0, 1, 0,	NULL,	"-lp_asym_pause_cap"	},
{ PARAM_LP_1000FDX_CAP,	    0, 1, 0,	NULL,	"-lp_1000fdx_cap"	},
{ PARAM_LP_1000HDX_CAP,	    0, 1, 0,	NULL,	"-lp_1000hdx_cap"	},
{ PARAM_LP_100T4_CAP,	    0, 1, 0,	NULL,	"-lp_100T4_cap"		},
{ PARAM_LP_100FDX_CAP,	    0, 1, 0,	NULL,	"-lp_100fdx_cap"	},
{ PARAM_LP_100HDX_CAP,	    0, 1, 0,	NULL,	"-lp_100hdx_cap"	},
{ PARAM_LP_10FDX_CAP,	    0, 1, 0,	NULL,	"-lp_10fdx_cap"		},
{ PARAM_LP_10HDX_CAP,	    0, 1, 0,	NULL,	"-lp_10hdx_cap"		},

/* Force Speed and Duplex */
{ PARAM_FORCE_SPEED_DUPLEX, GDIAG_10_HALF, GDIAG_100_FULL, GDIAG_100_FULL,
					NULL,	"?force_speed_duplex"	},

/* Current operating modes */
{ PARAM_LINK_STATUS,	    0, 1, 0,	NULL,	"-link_status"		},
{ PARAM_LINK_SPEED,	    0, 1000, 0,	NULL,	"-link_speed"		},
{ PARAM_LINK_DUPLEX,	    0, 2, 0,	NULL,	"-link_duplex"		},
{ PARAM_LINK_AUTONEG,	    0, 1, 0,	NULL,	"-link_autoneg"		},

/* Max Frame Size */
{ PARAM_MAX_FRAME_SIZE,	    ETHERMAX, FRAME_SIZE_UPTO_16K, ETHERMAX,
					NULL,	"-max_frame_size"	},
/* Loopback mode */
{ PARAM_LOOP_MODE,	    0, 4, 0,	NULL,	"-loopback_mode"	},
/* Interrupt Type */
{ PARAM_INTR_TYPE,	    0, 4, 0,	NULL,	"-interrupt_type"	},

/* Tx Bcopy Threshold */
{ PARAM_TX_BCOPY_THRESHOLD, MINTXBCOPYTHRESHOLD,
			    MAXTXBCOPYTHRESHOLD,
			    DEFAULTTXBCOPYTHRESHOLD,
					NULL,	"+tx_bcopy_threshold"	},
/* Tx Bcopy Fragments Limit */
{ PARAM_TX_FRAGS_LIMIT,	    MINTXFRAGSLIMIT,
			    MAXTXFRAGSLIMIT,
			    DEFAULTTXFRAGSLIMIT,
					NULL,	"-tx_bcopy_frags_limit"	},
/* Tx Recycle Low-Water */
{ PARAM_TX_RECYCLE_LOW_WATER, MINTXRECYCLELOWWATER,
			    MAXTXRECYCLELOWWATER,
			    DEFAULTTXRECYCLELOWWATER,
					NULL,	"+tx_recycle_low_water"	},
/* Tx Recycle Number */
{ PARAM_TX_RECYCLE_NUM,	    MINTXRECYCLENUM,
			    MAXTXRECYCLENUM,
			    DEFAULTTXRECYCLENUM,
					NULL,	"+tx_recycle_num"	},
/* Tx Interrupt Enable */
{ PARAM_TX_INTR_ENABLE,	    0, 1, 1,	NULL,	"+tx_interrupt_enable"	},
/* Tx Interrupt Delay */
{ PARAM_TX_INTR_DELAY,	    MINTXINTERRUPTDELAYVAL,
			    MAXTXINTERRUPTDELAYVAL,
			    DEFAULTTXINTERRUPTDELAYVAL,
					NULL,	"+tx_interrupt_delay"	},
/* Rx Bcopy Threshold */
{ PARAM_RX_BCOPY_THRESHOLD, MINRXBCOPYTHRESHOLD,
			    MAXRXBCOPYTHRESHOLD,
			    DEFAULTRXBCOPYTHRESHOLD,
					NULL,	"+rx_bcopy_threshold"	},
/* Rx Max Receive Packets Per Interrupt */
{ PARAM_RX_PKT_ON_INTR,	    MINNUMRCVPKTONINTR,
			    MAXNUMRCVPKTONINTR,
			    DEFAULTMAXNUMRCVPKTONINTR,
					NULL,	"+max_num_rcv_packets"	},
/* Receive Delay Timer Register */
{ PARAM_RX_RDTR,	    0, 65535, 0, NULL,	"+rx_intr_delay"	},
/* Receive Interrupt Absolute Delay Register */
{ PARAM_RX_RADV,	    0, 65535, 0, NULL,	"+rx_intr_abs_delay"	},

/* Terminator */
{ PARAM_COUNT,		    0, 0, 0,	NULL,	NULL			}
};


static int
e1000g_nd_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;

	ndp = (nd_param_t *)cp;
	e1000g_nd_get_param_val(ndp);
	(void) mi_mpprintf(mp, "%d", ndp->ndp_val);

	return (0);
}

static int
e1000g_nd_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;
	long new_value;
	char *end;

	ndp = (nd_param_t *)cp;
	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);
	if (new_value < ndp->ndp_min || new_value > ndp->ndp_max)
		return (EINVAL);

	e1000g_nd_set_param_val(ndp, new_value);

	return (0);
}

static int
e1000g_nd_param_load(struct e1000g *Adapter)
{
	const nd_param_t *tmplp;
	dev_info_t *dip;
	nd_param_t *ndp;
	caddr_t *nddpp;
	pfi_t setfn;
	char *nm;
	int pval;

	dip = Adapter->dip;
	nddpp = &Adapter->nd_data;
	ASSERT(*nddpp == NULL);

	for (tmplp = nd_template; tmplp->ndp_name != NULL; ++tmplp) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters,
		 * then register the parameter with nd_load()
		 */
		ndp = &Adapter->nd_params[tmplp->ndp_info];
		*ndp = *tmplp;
		ndp->ndp_instance = Adapter;
		e1000g_nd_get_param_val(ndp);

		nm = &ndp->ndp_name[0];
		setfn = e1000g_nd_set;

		if (Adapter->Shared.media_type != e1000_media_type_copper) {
			switch (*nm) {
			default:
				break;

			case '?':
				setfn = NULL;
				break;
			}
		}

		switch (*nm) {
		default:
		case '!':
			continue;

		case '+':
		case '?':
			break;

		case '-':
			setfn = NULL;
			break;
		}

		if (!nd_load(nddpp, ++nm, e1000g_nd_get, setfn, (caddr_t)ndp))
			goto nd_fail;

		/*
		 * If the parameter is writable, and there's a property
		 * with the same name, and its value is in range, we use
		 * it to initialise the parameter.  If it exists but is
		 * out of range, it's ignored.
		 */
		if (setfn && E1000G_PROP_EXISTS(dip, nm)) {
			pval = E1000G_PROP_GET_INT(dip, nm);
			if (pval >= ndp->ndp_min && pval <= ndp->ndp_max)
				ndp->ndp_val = pval;
		}
	}

	return (DDI_SUCCESS);

nd_fail:
	e1000g_DEBUGLOG_2(Adapter, e1000g_INFO_LEVEL,
		"e1000g_nd_param_load: FAILED at index %d [info %d]",
		tmplp-nd_template, tmplp->ndp_info);
	nd_free(nddpp);
	return (DDI_FAILURE);
}

static void
e1000g_nd_get_param_val(nd_param_t *ndp)
{
	struct e1000g *Adapter;
	uint16_t phy_reg;

	Adapter = ndp->ndp_instance;
	ASSERT(Adapter);

	switch (ndp->ndp_info) {
	/* Hardware Capabilities */
	case PARAM_AUTONEG_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & MII_SR_AUTONEG_CAPS) ? 1 : 0;
		break;
	case PARAM_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_PAUSE) ? 1 : 0;
		break;
	case PARAM_ASYM_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_ASM_DIR) ? 1 : 0;
		break;
	case PARAM_1000FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_EXT_STATUS,
		    &phy_reg);
		ndp->ndp_val = ((phy_reg & IEEE_ESR_1000T_FD_CAPS) ||
		    (phy_reg & IEEE_ESR_1000X_FD_CAPS)) ? 1 : 0;
		break;
	case PARAM_1000HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_EXT_STATUS,
		    &phy_reg);
		ndp->ndp_val = ((phy_reg & IEEE_ESR_1000T_HD_CAPS) ||
		    (phy_reg & IEEE_ESR_1000X_HD_CAPS)) ? 1 : 0;
		break;
	case PARAM_100T4_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & MII_SR_100T4_CAPS) ? 1 : 0;
		break;
	case PARAM_100FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = ((phy_reg & MII_SR_100X_FD_CAPS) ||
		    (phy_reg & MII_SR_100T2_FD_CAPS)) ? 1 : 0;
		break;
	case PARAM_100HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = ((phy_reg & MII_SR_100X_HD_CAPS) ||
		    (phy_reg & MII_SR_100T2_HD_CAPS)) ? 1 : 0;
		break;
	case PARAM_10FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & MII_SR_10T_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_10HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & MII_SR_10T_HD_CAPS) ? 1 : 0;
		break;

	/* Auto-Negotiation Advertisement Capabilities */
	case PARAM_ADV_AUTONEG_CAP:
		ndp->ndp_val = Adapter->Shared.autoneg;
		break;
	case PARAM_ADV_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_PAUSE) ? 1 : 0;
		break;
	case PARAM_ADV_ASYM_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_ASM_DIR) ? 1 : 0;
		break;
	case PARAM_ADV_1000FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_CTRL,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & CR_1000T_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_1000HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_CTRL,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & CR_1000T_HD_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_100T4_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_100T4_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_100FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_100TX_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_100HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_100TX_HD_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_10FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_10T_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_ADV_10HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_ADV,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_AR_10T_HD_CAPS) ? 1 : 0;
		break;

	/* Link-Partner's Advertisement Capabilities */
	case PARAM_LP_AUTONEG_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_AUTONEG_EXP,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_ER_LP_NWAY_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_PAUSE) ? 1 : 0;
		break;
	case PARAM_LP_ASYM_PAUSE_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_ASM_DIR) ? 1 : 0;
		break;
	case PARAM_LP_1000FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & SR_1000T_LP_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_1000HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_1000T_STATUS,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & SR_1000T_LP_HD_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_100T4_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_100T4_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_100FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_100TX_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_100HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_100TX_HD_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_10FDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_10T_FD_CAPS) ? 1 : 0;
		break;
	case PARAM_LP_10HDX_CAP:
		e1000_read_phy_reg(&Adapter->Shared, PHY_LP_ABILITY,
		    &phy_reg);
		ndp->ndp_val = (phy_reg & NWAY_LPAR_10T_HD_CAPS) ? 1 : 0;
		break;

	/* Force Speed and Duplex Parameter */
	case PARAM_FORCE_SPEED_DUPLEX:
		switch (Adapter->Shared.forced_speed_duplex) {
		case e1000_10_half:
			ndp->ndp_val = GDIAG_10_HALF;
			break;
		case e1000_10_full:
			ndp->ndp_val = GDIAG_10_FULL;
			break;
		case e1000_100_half:
			ndp->ndp_val = GDIAG_100_HALF;
			break;
		case e1000_100_full:
			ndp->ndp_val = GDIAG_100_FULL;
			break;
		}
		break;
	/* Link States */
	case PARAM_LINK_STATUS:
		ndp->ndp_val = (Adapter->link_state == LINK_STATE_UP) ? 1 : 0;
		break;
	case PARAM_LINK_SPEED:
		ndp->ndp_val = Adapter->link_speed;
		break;
	case PARAM_LINK_DUPLEX:
		ndp->ndp_val = Adapter->link_duplex;
		break;
	case PARAM_LINK_AUTONEG:
		ndp->ndp_val = Adapter->Shared.autoneg;
		break;

	/* Driver Properties */
	case PARAM_MAX_FRAME_SIZE:
		ndp->ndp_val = Adapter->Shared.max_frame_size;
		break;
	case PARAM_LOOP_MODE:
		ndp->ndp_val = Adapter->loopback_mode;
		break;
	case PARAM_INTR_TYPE:
		ndp->ndp_val = Adapter->intr_type;
		break;

	/* Tunable Driver Properties */
	case PARAM_TX_BCOPY_THRESHOLD:
		ndp->ndp_val = Adapter->tx_bcopy_thresh;
		break;
	case PARAM_TX_FRAGS_LIMIT:
		ndp->ndp_val = Adapter->tx_frags_limit;
		break;
	case PARAM_TX_RECYCLE_LOW_WATER:
		ndp->ndp_val = Adapter->tx_recycle_low_water;
		break;
	case PARAM_TX_RECYCLE_NUM:
		ndp->ndp_val = Adapter->tx_recycle_num;
		break;
	case PARAM_TX_INTR_ENABLE:
		ndp->ndp_val = Adapter->tx_intr_enable;
		break;
	case PARAM_TX_INTR_DELAY:
		ndp->ndp_val = Adapter->TxInterruptDelay;
		break;
	case PARAM_RX_BCOPY_THRESHOLD:
		ndp->ndp_val = Adapter->rx_bcopy_thresh;
		break;
	case PARAM_RX_PKT_ON_INTR:
		ndp->ndp_val = Adapter->MaxNumReceivePackets;
		break;
	case PARAM_RX_RDTR:
		ndp->ndp_val = E1000_READ_REG(&Adapter->Shared, RDTR);
		break;
	case PARAM_RX_RADV:
		ndp->ndp_val = E1000_READ_REG(&Adapter->Shared, RADV);
		break;
	default:
		break;
	}
}

static void
e1000g_nd_set_param_val(nd_param_t *ndp, uint32_t value)
{
	struct e1000g *Adapter;
	uint16_t autoneg_advertised;
	uint8_t forced_speed_duplex;
	boolean_t autoneg_enable;
	boolean_t link_change;

	Adapter = ndp->ndp_instance;
	ASSERT(Adapter);

	autoneg_advertised = 0;
	forced_speed_duplex = 0;
	autoneg_enable = B_FALSE;
	link_change = B_FALSE;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	switch (ndp->ndp_info) {
	case PARAM_TX_BCOPY_THRESHOLD:
		ndp->ndp_val = value;
		Adapter->tx_bcopy_thresh = value;
		Adapter->tx_frags_limit = (Adapter->Shared.max_frame_size /
		    Adapter->tx_bcopy_thresh) + 2;
		if (Adapter->tx_frags_limit > (MAX_TX_DESC_PER_PACKET >> 1))
			Adapter->tx_frags_limit = (MAX_TX_DESC_PER_PACKET >> 1);
		goto finished;
	case PARAM_TX_RECYCLE_LOW_WATER:
		ndp->ndp_val = value;
		Adapter->tx_recycle_low_water = value;
		goto finished;
	case PARAM_TX_RECYCLE_NUM:
		ndp->ndp_val = value;
		Adapter->tx_recycle_num = value;
		goto finished;
	case PARAM_TX_INTR_ENABLE:
		ndp->ndp_val = value;
		Adapter->tx_intr_enable = (value == 1) ? B_TRUE : B_FALSE;
		if (Adapter->tx_intr_enable)
			e1000g_EnableTxInterrupt(Adapter);
		else
			e1000g_DisableTxInterrupt(Adapter);
		goto finished;
	case PARAM_TX_INTR_DELAY:
		ndp->ndp_val = value;
		Adapter->TxInterruptDelay = value;
		/*
		 * Setup Transmit Interrupt Delay Value
		 */
		if (Adapter->TxInterruptDelay) {
			E1000_WRITE_REG(&Adapter->Shared, TIDV,
			    Adapter->TxInterruptDelay);
		}
		goto finished;
	case PARAM_RX_BCOPY_THRESHOLD:
		ndp->ndp_val = value;
		Adapter->rx_bcopy_thresh = value;
		goto finished;
	case PARAM_RX_PKT_ON_INTR:
		ndp->ndp_val = value;
		Adapter->MaxNumReceivePackets = value;
		goto finished;
	case PARAM_RX_RDTR:
		ndp->ndp_val = value;
		E1000_WRITE_REG(&Adapter->Shared, RDTR, value);
		goto finished;
	case PARAM_RX_RADV:
		ndp->ndp_val = value;
		E1000_WRITE_REG(&Adapter->Shared, RADV, value);
		goto finished;
	default:
		break;
	}

	/*
	 * ndd params that will impact link status
	 */
	if (Adapter->param_adv_1000fdx) {
		autoneg_advertised |= ADVERTISE_1000_FULL;
	}
	if (Adapter->param_adv_100fdx) {
		autoneg_advertised |= ADVERTISE_100_FULL;
	}
	if (Adapter->param_adv_100hdx) {
		autoneg_advertised |= ADVERTISE_100_HALF;
	}
	if (Adapter->param_adv_10fdx) {
		autoneg_advertised |= ADVERTISE_10_FULL;
	}
	if (Adapter->param_adv_10hdx) {
		autoneg_advertised |= ADVERTISE_10_HALF;
	}

	switch (Adapter->param_force_speed_duplex) {
	case GDIAG_10_HALF:
		forced_speed_duplex = e1000_10_half;
		break;
	case GDIAG_10_FULL:
		forced_speed_duplex = e1000_10_full;
		break;
	case GDIAG_100_HALF:
		forced_speed_duplex = e1000_100_half;
		break;
	case GDIAG_100_FULL:
		forced_speed_duplex = e1000_100_full;
		break;
	default:
		ASSERT(B_FALSE);
		break;
	}

	switch (ndp->ndp_info) {
	/* Auto-Negotiation Advertisement Capabilities */
	case PARAM_ADV_AUTONEG_CAP:
		if (value != ndp->ndp_val) {
			autoneg_enable = (value == 1) ? B_TRUE : B_FALSE;
			link_change = B_TRUE;
		}
		break;
	case PARAM_ADV_1000FDX_CAP:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: adv_1000fdx requires "
				    "adv_autoneg_cap enabled");
				goto finished;
			}
			autoneg_enable = B_TRUE;
			link_change = B_TRUE;
			if (value == 1) {
				autoneg_advertised |= ADVERTISE_1000_FULL;
			} else {
				autoneg_advertised &= ~ADVERTISE_1000_FULL;
			}
		}
		break;
	case PARAM_ADV_100FDX_CAP:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: adv_100fdx requires "
				    "adv_autoneg_cap enabled");
				goto finished;
			}
			autoneg_enable = B_TRUE;
			link_change = B_TRUE;
			if (value == 1) {
				autoneg_advertised |= ADVERTISE_100_FULL;
			} else {
				autoneg_advertised &= ~ADVERTISE_100_FULL;
			}
		}
		break;
	case PARAM_ADV_100HDX_CAP:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: adv_100hdx requires "
				    "adv_autoneg_cap enabled");
				goto finished;
			}
			autoneg_enable = B_TRUE;
			link_change = B_TRUE;
			if (value == 1) {
				autoneg_advertised |= ADVERTISE_100_HALF;
			} else {
				autoneg_advertised &= ~ADVERTISE_100_HALF;
			}
		}
		break;
	case PARAM_ADV_10FDX_CAP:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: adv_10fdx requires "
				    "adv_autoneg_cap enabled");
				goto finished;
			}
			autoneg_enable = B_TRUE;
			link_change = B_TRUE;
			if (value == 1) {
				autoneg_advertised |= ADVERTISE_10_FULL;
			} else {
				autoneg_advertised &= ~ADVERTISE_10_FULL;
			}
		}
		break;
	case PARAM_ADV_10HDX_CAP:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: adv_10hdx requires "
				    "adv_autoneg_cap enabled");
				goto finished;
			}
			autoneg_enable = B_TRUE;
			link_change = B_TRUE;
			if (value == 1) {
				autoneg_advertised |= ADVERTISE_10_HALF;
			} else {
				autoneg_advertised &= ~ADVERTISE_10_HALF;
			}
		}
		break;
	case PARAM_FORCE_SPEED_DUPLEX:
		if (value != ndp->ndp_val) {
			if (Adapter->param_adv_autoneg == 1) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: force_speed_duplex requires "
				    "adv_autoneg_cap disabled");
				goto finished;
			}
			autoneg_enable = B_FALSE;
			link_change = B_TRUE;
			switch (value) {
			case GDIAG_10_HALF:
				forced_speed_duplex = e1000_10_half;
				break;
			case GDIAG_10_FULL:
				forced_speed_duplex = e1000_10_full;
				break;
			case GDIAG_100_HALF:
				forced_speed_duplex = e1000_100_half;
				break;
			case GDIAG_100_FULL:
				forced_speed_duplex = e1000_100_full;
				break;
			default:
				ASSERT(B_FALSE);
				break;
			}
		}
		break;
	default:
		goto finished;
	}

	if (link_change) {
		if (autoneg_enable) {
			if (autoneg_advertised == 0) {
				e1000g_log(Adapter, CE_WARN,
				    "ndd set: there must be at least one "
				    "advertised capability enabled");
				goto finished;
			}

			Adapter->Shared.autoneg = B_TRUE;
			Adapter->Shared.autoneg_advertised =
				autoneg_advertised;
		} else {
			Adapter->Shared.autoneg = B_FALSE;
			Adapter->Shared.forced_speed_duplex =
				forced_speed_duplex;
		}

		ndp->ndp_val = value;

		rw_exit(&Adapter->chip_lock);
		(void) e1000g_reset(Adapter);
		return;
	}

finished:
	rw_exit(&Adapter->chip_lock);
}

int
e1000g_nd_init(struct e1000g *Adapter)
{
	dev_info_t *dip;
	int duplex;
	int speed;

	dip = Adapter->dip;

	/*
	 * Register all the per-instance properties, initialising
	 * them from the table above or from driver properties set
	 * in the .conf file
	 */
	if (e1000g_nd_param_load(Adapter) != DDI_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/* Free the Named Dispatch Table by calling nd_free */
void
e1000g_nd_cleanup(struct e1000g *Adapter)
{
	nd_free(&Adapter->nd_data);
}

enum ioc_reply
e1000g_nd_ioctl(struct e1000g *Adapter, queue_t *wq,
    mblk_t *mp, struct iocblk *iocp)
{
	nd_param_t *ndp;
	boolean_t ok;
	int info;
	int cmd;

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		ASSERT(FALSE);
		return (IOC_INVAL);

	case ND_GET:
		/*
		 * If nd_getset() returns B_FALSE, the command was
		 * not valid (e.g. unknown name), so we just tell the
		 * top-level ioctl code to send a NAK (with code EINVAL).
		 *
		 * Otherwise, nd_getset() will have built the reply to
		 * be sent (but not actually sent it), so we tell the
		 * caller to send the prepared reply.
		 */
		ok = nd_getset(wq, Adapter->nd_data, mp);
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		/*
		 * All adv_* parameters are locked (read-only) while
		 * the device is in any sort of loopback mode ...
		 */
		if (Adapter->loopback_mode != E1000G_LB_NONE) {
			iocp->ioc_error = EBUSY;
			return (IOC_INVAL);
		}

		ok = nd_getset(wq, Adapter->nd_data, mp);

		if (!ok)
			return (IOC_INVAL);

		return (IOC_REPLY);
	}
}
