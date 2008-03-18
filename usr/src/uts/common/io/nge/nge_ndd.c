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

#include "nge.h"

#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_NDD

static char transfer_speed_propname[] = "transfer-speed";
static char speed_propname[] = "speed";
static char duplex_propname[] = "full-duplex";

/*
 * Notes:
 *	The first character of the <name> field encodes the read/write
 *	status of the parameter:
 *		'=' => read-only,
 *		'-' => read-only and forced to 0 on serdes
 *		'+' => read/write,
 *		'?' => read/write on copper, read-only and 0 on serdes
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
 *	parameter has been set via ndd (see nge_param_set()).
 */
static const nd_param_t nd_template[] = {
/*	info		min	max	init	r/w+name		*/

/* Our hardware capabilities */
{ PARAM_AUTONEG_CAP,	    0,	  1,	1,	"=autoneg_cap"		},
{ PARAM_PAUSE_CAP,	    0,	  1,	1,	"=pause_cap"		},
{ PARAM_ASYM_PAUSE_CAP,	    0,	  1,	1,	"=asym_pause_cap"	},
{ PARAM_1000FDX_CAP,	    0,	  1,	1,	"=1000fdx_cap"		},
{ PARAM_1000HDX_CAP,	    0,	  1,	0,	"=1000hdx_cap"		},
{ PARAM_100T4_CAP,	    0,	  1,	0,	"=100T4_cap"		},
{ PARAM_100FDX_CAP,	    0,	  1,	1,	"-100fdx_cap"		},
{ PARAM_100HDX_CAP,	    0,	  1,	1,	"-100hdx_cap"		},
{ PARAM_10FDX_CAP,	    0,	  1,	1,	"-10fdx_cap"		},
{ PARAM_10HDX_CAP,	    0,	  1,	1,	"-10hdx_cap"		},

/* Our advertised capabilities */
{ PARAM_ADV_AUTONEG_CAP,    0,	  1,	1,	"+adv_autoneg_cap"	},
{ PARAM_ADV_PAUSE_CAP,	    0,	  1,	1,	"+adv_pause_cap"	},
{ PARAM_ADV_ASYM_PAUSE_CAP, 0,	  1,	1,	"+adv_asym_pause_cap"	},
{ PARAM_ADV_1000FDX_CAP,    0,	  1,	1,	"+adv_1000fdx_cap"	},
{ PARAM_ADV_1000HDX_CAP,    0,	  1,	0,	"=adv_1000hdx_cap"	},
{ PARAM_ADV_100T4_CAP,	    0,	  1,	0,	"=adv_100T4_cap"	},
{ PARAM_ADV_100FDX_CAP,	    0,	  1,	1,	"?adv_100fdx_cap"	},
{ PARAM_ADV_100HDX_CAP,	    0,	  1,	1,	"?adv_100hdx_cap"	},
{ PARAM_ADV_10FDX_CAP,	    0,	  1,	1,	"?adv_10fdx_cap"	},
{ PARAM_ADV_10HDX_CAP,	    0,	  1,	1,	"?adv_10hdx_cap"	},

/* Partner's advertised capabilities */
{ PARAM_LP_AUTONEG_CAP,	    0,	  1,	0,	"-lp_autoneg_cap"	},
{ PARAM_LP_PAUSE_CAP,	    0,	  1,	0,	"-lp_pause_cap"		},
{ PARAM_LP_ASYM_PAUSE_CAP,  0,	  1,	0,	"-lp_asym_pause_cap"	},
{ PARAM_LP_1000FDX_CAP,	    0,	  1,	0,	"-lp_1000fdx_cap"	},
{ PARAM_LP_1000HDX_CAP,	    0,	  1,	0,	"-lp_1000hdx_cap"	},
{ PARAM_LP_100T4_CAP,	    0,	  1,	0,	"-lp_100T4_cap"		},
{ PARAM_LP_100FDX_CAP,	    0,	  1,	0,	"-lp_100fdx_cap"	},
{ PARAM_LP_100HDX_CAP,	    0,	  1,	0,	"-lp_100hdx_cap"	},
{ PARAM_LP_10FDX_CAP,	    0,	  1,	0,	"-lp_10fdx_cap"		},
{ PARAM_LP_10HDX_CAP,	    0,	  1,	0,	"-lp_10hdx_cap"		},

/* Current operating modes */
{ PARAM_LINK_STATUS,	    0,	  1,	0,	"-link_status"		},
{ PARAM_LINK_SPEED,	    0,    1000,	0,	"-link_speed"		},
{ PARAM_LINK_DUPLEX,	   -1,	  1,	-1,	"-link_duplex"		},

{ PARAM_LINK_AUTONEG,	    0,	  1,	0,	"-link_autoneg"		},
{ PARAM_LINK_RX_PAUSE,	    0,	  1,	0,	"-link_rx_pause"	},
{ PARAM_LINK_TX_PAUSE,	    0,	  1,	0,	"-link_tx_pause"	},

/* Loopback status */
{ PARAM_LOOP_MODE,	    0,	  5,	0,	"-loop_mode"		},

/* TX Bcopy threshold */
{ PARAM_TXBCOPY_THRESHOLD,	0,	NGE_MAX_SDU,	NGE_TX_COPY_SIZE,
"+tx_bcopy_threshold" },

/* RX Bcopy threshold */
{ PARAM_RXBCOPY_THRESHOLD,	0,	NGE_MAX_SDU,	NGE_RX_COPY_SIZE,
"+rx_bcopy_threshold" },

/* Max packet received per interrupt */
{ PARAM_RECV_MAX_PACKET,	0,	NGE_RECV_SLOTS_DESC_1024,	128,
"+recv_max_packet" },
/* Quiet time switch from polling interrupt to per packet interrupt */
{ PARAM_POLL_QUIET_TIME,	0,	10000,	NGE_POLL_QUIET_TIME,
"+poll_quiet_time" },

/* Busy time switch from per packet interrupt to polling interrupt */
{ PARAM_POLL_BUSY_TIME,		0,	10000,	NGE_POLL_BUSY_TIME,
"+poll_busy_time" },

/* Packets received to trigger the poll_quiet_time counter */
{ PARAM_RX_INTR_HWATER,		0,	PARAM_RECV_MAX_PACKET,	1,
"+rx_intr_hwater" },

/* Packets received to trigger the poll_busy_time counter */
{ PARAM_RX_INTR_LWATER,		0,	PARAM_RECV_MAX_PACKET,	8,
"+rx_intr_lwater" },

/* Per N tx packets to do tx recycle in poll mode */
{ PARAM_TX_N_INTR,		1,	10000,	NGE_TX_N_INTR,
"+tx_n_intr" },

/* Terminator */
{ PARAM_COUNT,		    0,	  0,	0,	NULL			}
};


/*  ============== NDD Support Functions ===============  */

/*
 * Extracts the value from the nge parameter array and prints
 * the parameter value. cp points to the required parameter.
 */
static int
nge_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;

	_NOTE(ARGUNUSED(q, credp))
	ndp = (nd_param_t *)cp;
	(void) mi_mpprintf(mp, "%d", ndp->ndp_val);

	return (0);
}

/*
 * synchronize the  adv* and en* parameters.
 *
 * See comments in <sys/dld.h> for details of the *_en_*
 * parameters.  The usage of ndd for setting adv parameters will
 * synchronize all the en parameters with the nge parameters,
 * implicitly disabling any settings made via dladm.
 */
static void
nge_param_sync(nge_t *ngep)
{
	ngep->param_en_pause = ngep->param_adv_pause;
	ngep->param_en_asym_pause = ngep->param_adv_asym_pause;
	ngep->param_en_1000fdx = ngep->param_adv_1000fdx;
	ngep->param_en_1000hdx = ngep->param_adv_1000hdx;
	ngep->param_en_100fdx = ngep->param_adv_100fdx;
	ngep->param_en_100hdx = ngep->param_adv_100hdx;
	ngep->param_en_10fdx = ngep->param_adv_10fdx;
	ngep->param_en_10hdx = ngep->param_adv_10hdx;
}

/*
 * Validates the request to set a NGE parameter to a specific value.
 * If the request is OK, the parameter is set.  Also the <info> field
 * is incremented to show that the parameter was touched, even though
 * it may have been set to the same value it already had.
 */
static int
nge_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;
	long new_value;
	char *end;

	_NOTE(ARGUNUSED(q, mp, credp))
	ndp = (nd_param_t *)cp;
	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);
	if (new_value < ndp->ndp_min || new_value > ndp->ndp_max)
		return (EINVAL);

	ndp->ndp_val = new_value;
	ndp->ndp_info += 1;
	return (0);
}

/*
 * Initialise the per-instance parameter array from the global prototype,
 * and register each element with the named dispatch handler using nd_load()
 */
static int
nge_param_register(nge_t *ngep)
{
	const nd_param_t *tmplp;
	dev_info_t *dip;
	nd_param_t *ndp;
	caddr_t *nddpp;
	pfi_t setfn;
	char *nm;
	int pval;

	dip = ngep->devinfo;
	nddpp = &ngep->nd_data_p;
	ASSERT(*nddpp == NULL);

	NGE_TRACE(("nge_param_register($%p)", (void *)ngep));

	for (tmplp = nd_template; tmplp->ndp_name != NULL; ++tmplp) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters,
		 * then register the parameter with nd_load()
		 */
		ndp = &ngep->nd_params[tmplp->ndp_info];
		*ndp = *tmplp;
		nm = &ndp->ndp_name[0];
		setfn = nge_param_set;
		switch (*nm) {
		default:
		case '!':
			continue;

		case '+':
		case '?':
			break;

		case '=':
		case '-':
			setfn = NULL;
			break;
		}

		if (!nd_load(nddpp, ++nm, nge_param_get, setfn, (caddr_t)ndp))
			goto nd_fail;

		/*
		 * If the parameter is writable, and there's a property
		 * with the same name, and its value is in range, we use
		 * it to initialise the parameter.  If it exists but is
		 * out of range, it's ignored.
		 */
		if (setfn && NGE_PROP_EXISTS(dip, nm)) {
			pval = NGE_PROP_GET_INT(dip, nm);
			if (pval >= ndp->ndp_min && pval <= ndp->ndp_max)
				ndp->ndp_val = pval;
		}
	}
	return (DDI_SUCCESS);

nd_fail:
	nd_free(nddpp);
	return (DDI_FAILURE);
}

int
nge_nd_init(nge_t *ngep)
{
	int duplex;
	int speed;
	dev_info_t *dip;

	NGE_TRACE(("nge_nd_init($%p)", (void *)ngep));
	/*
	 * Register all the per-instance properties, initialising
	 * them from the table above or from driver properties set
	 * in the .conf file
	 */
	if (nge_param_register(ngep) != DDI_SUCCESS)
		return (-1);

	/*
	 * The link speed may be forced to 10, 100 or 1000 Mbps using
	 * the property "transfer-speed". This may be done in OBP by
	 * using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 10, 100 or 1000 - any other value will be
	 * ignored.  Note that this does *enables* autonegotiation, but
	 * restricts it to the speed specified by the property.
	 */
	dip = ngep->devinfo;
	if (NGE_PROP_EXISTS(dip, transfer_speed_propname)) {

		speed = NGE_PROP_GET_INT(dip, transfer_speed_propname);
		nge_log(ngep, "%s property is %d",
		    transfer_speed_propname, speed);

		switch (speed) {
		case 1000:
			ngep->param_adv_autoneg = 1;
			ngep->param_adv_1000fdx = 1;
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_100fdx = 0;
			ngep->param_adv_100hdx = 0;
			ngep->param_adv_10fdx = 0;
			ngep->param_adv_10hdx = 0;
			break;

		case 100:
			ngep->param_adv_autoneg = 1;
			ngep->param_adv_1000fdx = 0;
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_100fdx = 1;
			ngep->param_adv_100hdx = 1;
			ngep->param_adv_10fdx = 0;
			ngep->param_adv_10hdx = 0;
			break;

		case 10:
			ngep->param_adv_autoneg = 1;
			ngep->param_adv_1000fdx = 0;
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_100fdx = 0;
			ngep->param_adv_100hdx = 0;
			ngep->param_adv_10fdx = 1;
			ngep->param_adv_10hdx = 1;
			break;

		default:
			break;
		}
	}

	/*
	 * Also check the "speed" and "full-duplex" properties.  Setting
	 * these properties will override all other settings and *disable*
	 * autonegotiation, so both should be specified if either one is.
	 * Otherwise, the unspecified parameter will be set to a default
	 * value (1000Mb/s, full-duplex).
	 */
	if (NGE_PROP_EXISTS(dip, speed_propname) ||
	    NGE_PROP_EXISTS(dip, duplex_propname)) {

		ngep->param_adv_autoneg = 0;
		ngep->param_adv_1000fdx = 1;
		ngep->param_adv_1000hdx = 0;
		ngep->param_adv_100fdx = 1;
		ngep->param_adv_100hdx = 1;
		ngep->param_adv_10fdx = 1;
		ngep->param_adv_10hdx = 1;

		speed = NGE_PROP_GET_INT(dip, speed_propname);
		duplex = NGE_PROP_GET_INT(dip, duplex_propname);
		nge_log(ngep, "%s property is %d",
		    speed_propname, speed);
		nge_log(ngep, "%s property is %d",
		    duplex_propname, duplex);

		switch (speed) {
		case 1000:
		default:
			ngep->param_adv_100fdx = 0;
			ngep->param_adv_100hdx = 0;
			ngep->param_adv_10fdx = 0;
			ngep->param_adv_10hdx = 0;
			break;

		case 100:
			ngep->param_adv_1000fdx = 0;
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_10fdx = 0;
			ngep->param_adv_10hdx = 0;
			break;

		case 10:
			ngep->param_adv_1000fdx = 0;
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_100fdx = 0;
			ngep->param_adv_100hdx = 0;
			break;
		}

		switch (duplex) {
		default:
		case 1:
			ngep->param_adv_1000hdx = 0;
			ngep->param_adv_100hdx = 0;
			ngep->param_adv_10hdx = 0;
			break;

		case 0:
			ngep->param_adv_1000fdx = 0;
			ngep->param_adv_100fdx = 0;
			ngep->param_adv_10fdx = 0;
			break;
		}
	}

	nge_param_sync(ngep);

	return (0);
}

enum ioc_reply
nge_nd_ioctl(nge_t *ngep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	boolean_t ok;
	int cmd;
	NGE_TRACE(("nge_nd_ioctl($%p, $%p, $%p, $%p)",
	    (void *)ngep, (void *)wq, (void *)mp, (void *)iocp));

	ASSERT(mutex_owned(ngep->genlock));

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		nge_error(ngep, "nge_nd_ioctl: invalid cmd 0x%x", cmd);
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
		ok = nd_getset(wq, ngep->nd_data_p, mp);
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		/*
		 * All adv_* parameters are locked (read-only) while
		 * the device is in any sort of loopback mode ...
		 */
		if (ngep->param_loop_mode != NGE_LOOP_NONE) {
			iocp->ioc_error = EBUSY;
			return (IOC_INVAL);
		}

		ok = nd_getset(wq, ngep->nd_data_p, mp);

		nge_param_sync(ngep);

		/*
		 * If nd_getset() returns B_FALSE, the command was
		 * not valid (e.g. unknown name), so we just tell
		 * the top-level ioctl code to send a NAK (with code
		 * EINVAL by default).
		 *
		 * Otherwise, nd_getset() will have built the reply to
		 * be sent - but that doesn't imply success!  In some
		 * cases, the reply it's built will have a non-zero
		 * error code in it (e.g. EPERM if not superuser).
		 * So, we also drop out in that case ...
		 */
		if (!ok)
			return (IOC_INVAL);
		if (iocp->ioc_error)
			return (IOC_REPLY);

		/*
		 * OK, a successful 'set'.  Return IOC_RESTART_REPLY,
		 * telling the top-level ioctl code to update the PHY
		 * and restart the chip before sending our prepared reply
		 */
		return (IOC_RESTART_REPLY);
	}
}

/* Free the Named Dispatch Table by calling nd_free */
void
nge_nd_cleanup(nge_t *ngep)
{
	NGE_TRACE(("nge_nd_cleanup($%p)", (void *)ngep));
	nd_free(&ngep->nd_data_p);
}
