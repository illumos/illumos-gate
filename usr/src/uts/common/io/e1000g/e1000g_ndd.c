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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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
static void e1000g_nd_param_sync(struct e1000g *Adapter);
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

/* Current operating modes */
{ PARAM_LINK_STATUS,	    0, 1, 0,	NULL,	"-link_status"		},
{ PARAM_LINK_SPEED,	    0, 1000, 0,	NULL,	"-link_speed"		},
{ PARAM_LINK_DUPLEX,	    0, 2, 0,	NULL,	"-link_duplex"		},
{ PARAM_LINK_AUTONEG,	    0, 1, 0,	NULL,	"-link_autoneg"		},

/* Tx Bcopy Threshold */
{ PARAM_TX_BCOPY_THRESHOLD, MIN_TX_BCOPY_THRESHOLD,
			    MAX_TX_BCOPY_THRESHOLD,
			    DEFAULT_TX_BCOPY_THRESHOLD,
					NULL,	"+tx_bcopy_threshold"	},
/* Tx Interrupt Enable */
{ PARAM_TX_INTR_ENABLE,	    0, 1, DEFAULT_TX_INTR_ENABLE,
					NULL,	"+tx_interrupt_enable"	},
/* Tx Interrupt Delay */
{ PARAM_TX_TIDV,	    MIN_TX_INTR_DELAY,
			    MAX_TX_INTR_DELAY,
			    DEFAULT_TX_INTR_DELAY,
					NULL,	"+tx_intr_delay"	},
/* Tx Interrupt Delay */
{ PARAM_TX_TADV,	    MIN_TX_INTR_ABS_DELAY,
			    MAX_TX_INTR_ABS_DELAY,
			    DEFAULT_TX_INTR_ABS_DELAY,
					NULL,	"+tx_intr_abs_delay"	},
/* Rx Bcopy Threshold */
{ PARAM_RX_BCOPY_THRESHOLD, MIN_RX_BCOPY_THRESHOLD,
			    MAX_RX_BCOPY_THRESHOLD,
			    DEFAULT_RX_BCOPY_THRESHOLD,
					NULL,	"+rx_bcopy_threshold"	},
/* Rx Max Receive Packets Per Interrupt */
{ PARAM_RX_PKT_ON_INTR,	    MIN_RX_LIMIT_ON_INTR,
			    MAX_RX_LIMIT_ON_INTR,
			    DEFAULT_RX_LIMIT_ON_INTR,
					NULL,	"+max_num_rcv_packets"	},
/* Receive Delay Timer Register */
{ PARAM_RX_RDTR,	    MIN_RX_INTR_DELAY,
			    MAX_RX_INTR_DELAY,
			    DEFAULT_RX_INTR_DELAY,
					NULL,	"+rx_intr_delay"	},
/* Receive Interrupt Absolute Delay Register */
{ PARAM_RX_RADV,	    MIN_RX_INTR_ABS_DELAY,
			    MAX_RX_INTR_ABS_DELAY,
			    DEFAULT_RX_INTR_ABS_DELAY,
					NULL,	"+rx_intr_abs_delay"	},

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

/*
 * synchronize the adv* and en* parameters.
 *
 * See comments in <sys/dld.h> for details of the *_en_*
 * parameters. The usage of ndd for setting adv parameters will
 * synchronize all the en parameters with the e1000g parameters,
 * implicity disalbing any settings made via dladm.
 */
static void
e1000g_nd_param_sync(struct e1000g *Adapter)
{
	Adapter->param_en_1000fdx = Adapter->param_adv_1000fdx;
	Adapter->param_en_1000hdx = Adapter->param_adv_1000hdx;
	Adapter->param_en_100fdx = Adapter->param_adv_100fdx;
	Adapter->param_en_100hdx = Adapter->param_adv_100hdx;
	Adapter->param_en_10fdx = Adapter->param_adv_10fdx;
	Adapter->param_en_10hdx = Adapter->param_adv_10hdx;
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

		if (Adapter->shared.media_type != e1000_media_type_copper) {
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
	E1000G_DEBUGLOG_2(Adapter, E1000G_INFO_LEVEL,
	    "e1000g_nd_param_load: FAILED at index %d [info %d]",
	    tmplp-nd_template, tmplp->ndp_info);
	nd_free(nddpp);
	return (DDI_FAILURE);
}

static void
e1000g_nd_get_param_val(nd_param_t *ndp)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;

	Adapter = ndp->ndp_instance;
	ASSERT(Adapter);
	hw = &Adapter->shared;

	rw_enter(&Adapter->chip_lock, RW_READER);

	switch (ndp->ndp_info) {
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
		ndp->ndp_val = hw->mac.autoneg;
		break;

	/* Driver Properties */
	case PARAM_MAX_FRAME_SIZE:
		ndp->ndp_val = hw->mac.max_frame_size;
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
	case PARAM_TX_INTR_ENABLE:
		ndp->ndp_val = Adapter->tx_intr_enable;
		break;
	case PARAM_TX_TIDV:
		ndp->ndp_val = Adapter->tx_intr_delay;
		break;
	case PARAM_TX_TADV:
		ndp->ndp_val = Adapter->tx_intr_abs_delay;
		break;
	case PARAM_RX_BCOPY_THRESHOLD:
		ndp->ndp_val = Adapter->rx_bcopy_thresh;
		break;
	case PARAM_RX_PKT_ON_INTR:
		ndp->ndp_val = Adapter->rx_limit_onintr;
		break;
	case PARAM_RX_RDTR:
		ndp->ndp_val = Adapter->rx_intr_delay;
		break;
	case PARAM_RX_RADV:
		ndp->ndp_val = Adapter->rx_intr_abs_delay;
		break;
	default:
		break;
	}

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_UNAFFECTED);

	rw_exit(&Adapter->chip_lock);
}

static void
e1000g_nd_set_param_val(nd_param_t *ndp, uint32_t value)
{
	struct e1000g *Adapter;
	struct e1000_hw *hw;
	e1000g_tx_ring_t *tx_ring;

	Adapter = ndp->ndp_instance;
	ASSERT(Adapter);
	hw = &Adapter->shared;
	tx_ring = Adapter->tx_ring;

	rw_enter(&Adapter->chip_lock, RW_WRITER);

	switch (ndp->ndp_info) {
	case PARAM_TX_BCOPY_THRESHOLD:
		ndp->ndp_val = value;
		Adapter->tx_bcopy_thresh = value;
		tx_ring->frags_limit = (hw->mac.max_frame_size /
		    Adapter->tx_bcopy_thresh) + 2;
		if (tx_ring->frags_limit > (MAX_TX_DESC_PER_PACKET >> 1))
			tx_ring->frags_limit = (MAX_TX_DESC_PER_PACKET >> 1);
		break;
	case PARAM_TX_INTR_ENABLE:
		ndp->ndp_val = value;
		Adapter->tx_intr_enable = (value == 1) ? B_TRUE : B_FALSE;
		if (Adapter->tx_intr_enable)
			e1000g_mask_tx_interrupt(Adapter);
		else
			e1000g_clear_tx_interrupt(Adapter);
		break;
	case PARAM_TX_TIDV:
		ndp->ndp_val = value;
		Adapter->tx_intr_delay = value;
		/* A value of zero is not allowed for TIDV */
		if (Adapter->tx_intr_delay) {
			E1000_WRITE_REG(hw, E1000_TIDV, Adapter->tx_intr_delay);
		}
		break;
	case PARAM_TX_TADV:
		ndp->ndp_val = value;
		Adapter->tx_intr_abs_delay = value;
		E1000_WRITE_REG(hw, E1000_TADV, Adapter->tx_intr_abs_delay);
		break;
	case PARAM_RX_BCOPY_THRESHOLD:
		ndp->ndp_val = value;
		Adapter->rx_bcopy_thresh = value;
		break;
	case PARAM_RX_PKT_ON_INTR:
		ndp->ndp_val = value;
		Adapter->rx_limit_onintr = value;
		break;
	case PARAM_RX_RDTR:
		ndp->ndp_val = value;
		Adapter->rx_intr_delay = value;
		E1000_WRITE_REG(hw, E1000_RDTR, value);
		break;
	case PARAM_RX_RADV:
		ndp->ndp_val = value;
		Adapter->rx_intr_abs_delay = value;
		E1000_WRITE_REG(hw, E1000_RADV, value);
		break;
	case PARAM_ADV_AUTONEG_CAP:
	case PARAM_ADV_1000FDX_CAP:
	case PARAM_ADV_100FDX_CAP:
	case PARAM_ADV_100HDX_CAP:
	case PARAM_ADV_10FDX_CAP:
	case PARAM_ADV_10HDX_CAP:
		ndp->ndp_val = value;
		(void) e1000g_reset_link(Adapter);
		break;
	default:
		break;
	}
	rw_exit(&Adapter->chip_lock);

	if (e1000g_check_acc_handle(Adapter->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(Adapter->dip, DDI_SERVICE_DEGRADED);
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

	e1000g_nd_param_sync(Adapter);

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

		e1000g_nd_param_sync(Adapter);

		if (!ok)
			return (IOC_INVAL);

		return (IOC_REPLY);
	}
}
