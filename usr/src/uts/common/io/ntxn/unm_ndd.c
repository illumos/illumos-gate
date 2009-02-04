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
 * Copyright 2008 NetXen, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "unm_nic.h"

static char transfer_speed_propname[] = "transfer-speed";
static char speed_propname[] = "speed";
static char duplex_propname[] = "full-duplex";

/*
 * Notes:
 *	The first character of the <name> field encodes the read/write
 *	status of the parameter:
 *		'-' => read-only,
 *		'+' => read/write,
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
 *	parameter has been set via ndd (see unm_param_set()).
 */
static const nd_param_t nd_template_10000[] = {
/*	info		min	max	init	r/w+name		*/

/* Our hardware capabilities */
{ PARAM_AUTONEG_CAP,	    0,	  1,	1,	"-autoneg_cap"		},
{ PARAM_PAUSE_CAP,	    0,	  1,	1,	"-pause_cap"		},
{ PARAM_ASYM_PAUSE_CAP,	    0,	  1,	1,	"-asym_pause_cap"	},
{ PARAM_10000FDX_CAP,	    0,	  1,	1,	"-10000fdx_cap"		},
{ PARAM_1000FDX_CAP,	    0,	  1,	0,	"-1000fdx_cap"		},
{ PARAM_1000HDX_CAP,	    0,	  1,	0,	"-1000hdx_cap"		},
{ PARAM_100T4_CAP,	    0,	  1,	0,	"-100T4_cap"		},
{ PARAM_100FDX_CAP,	    0,	  1,	0,	"-100fdx_cap"		},
{ PARAM_100HDX_CAP,	    0,	  1,	0,	"-100hdx_cap"		},
{ PARAM_10FDX_CAP,	    0,	  1,	0,	"-10fdx_cap"		},
{ PARAM_10HDX_CAP,	    0,	  1,	0,	"-10hdx_cap"		},

/* Our advertised capabilities */
{ PARAM_ADV_AUTONEG_CAP,    0,	  1,	1,	"-adv_autoneg_cap"	},
{ PARAM_ADV_PAUSE_CAP,	    0,	  1,	1,	"+adv_pause_cap"	},
{ PARAM_ADV_ASYM_PAUSE_CAP, 0,	  1,	1,	"+adv_asym_pause_cap"	},
{ PARAM_ADV_10000FDX_CAP,   0,	  1,	1,	"+adv_10000fdx_cap"	},
{ PARAM_ADV_1000FDX_CAP,    0,	  1,	0,	"+adv_1000fdx_cap"	},
{ PARAM_ADV_1000HDX_CAP,    0,	  1,	0,	"-adv_1000hdx_cap"	},
{ PARAM_ADV_100T4_CAP,	    0,	  1,	0,	"-adv_100T4_cap"	},
{ PARAM_ADV_100FDX_CAP,	    0,	  1,	0,	"+adv_100fdx_cap"	},
{ PARAM_ADV_100HDX_CAP,	    0,	  1,	0,	"+adv_100hdx_cap"	},
{ PARAM_ADV_10FDX_CAP,	    0,	  1,	0,	"+adv_10fdx_cap"	},
{ PARAM_ADV_10HDX_CAP,	    0,	  1,	0,	"+adv_10hdx_cap"	},

/* Current operating modes */
{ PARAM_LINK_STATUS,	    0,	  1,	0,	"-link_status"		},
{ PARAM_LINK_SPEED,	    0,    10000, 0,	"-link_speed"		},
{ PARAM_LINK_DUPLEX,	    0,	  2,	0,	"-link_duplex"		},

/* Loopback status */
{ PARAM_LOOP_MODE,	    0,	  2,	0,	"-loop_mode"		},

/* Terminator */
{ PARAM_COUNT,		    0,	  0,	0,	NULL			}
};

static const nd_param_t nd_template_1000[] = {
/*	info		min	max	init	r/w+name		*/

/* Our hardware capabilities */
{ PARAM_AUTONEG_CAP,	    0,	  1,	1,	"-autoneg_cap"		},
{ PARAM_PAUSE_CAP,	    0,	  1,	1,	"-pause_cap"		},
{ PARAM_ASYM_PAUSE_CAP,	    0,	  1,	1,	"-asym_pause_cap"	},
{ PARAM_1000FDX_CAP,	    0,	  1,	1,	"-1000fdx_cap"		},
{ PARAM_1000HDX_CAP,	    0,	  1,	0,	"-1000hdx_cap"		},
{ PARAM_100T4_CAP,	    0,	  1,	0,	"-100T4_cap"		},
{ PARAM_100FDX_CAP,	    0,	  1,	1,	"-100fdx_cap"		},
{ PARAM_100HDX_CAP,	    0,	  1,	1,	"-100hdx_cap"		},
{ PARAM_10FDX_CAP,	    0,	  1,	1,	"-10fdx_cap"		},
{ PARAM_10HDX_CAP,	    0,	  1,	1,	"-10hdx_cap"		},

/* Our advertised capabilities */
{ PARAM_ADV_AUTONEG_CAP,    0,	  1,	1,	"-adv_autoneg_cap"	},
{ PARAM_ADV_PAUSE_CAP,	    0,	  1,	1,	"+adv_pause_cap"	},
{ PARAM_ADV_ASYM_PAUSE_CAP, 0,	  1,	1,	"+adv_asym_pause_cap"	},
{ PARAM_ADV_1000FDX_CAP,    0,	  1,	1,	"+adv_1000fdx_cap"	},
{ PARAM_ADV_1000HDX_CAP,    0,	  1,	0,	"-adv_1000hdx_cap"	},
{ PARAM_ADV_100T4_CAP,	    0,	  1,	0,	"-adv_100T4_cap"	},
{ PARAM_ADV_100FDX_CAP,	    0,	  1,	1,	"+adv_100fdx_cap"	},
{ PARAM_ADV_100HDX_CAP,	    0,	  1,	1,	"+adv_100hdx_cap"	},
{ PARAM_ADV_10FDX_CAP,	    0,	  1,	1,	"+adv_10fdx_cap"	},
{ PARAM_ADV_10HDX_CAP,	    0,	  1,	1,	"+adv_10hdx_cap"	},

/* Current operating modes */
{ PARAM_LINK_STATUS,	    0,	  1,	0,	"-link_status"		},
{ PARAM_LINK_SPEED,	    0,    1000,	0,	"-link_speed"		},
{ PARAM_LINK_DUPLEX,	    0,	  2,	0,	"-link_duplex"		},

/* Loopback status */
{ PARAM_LOOP_MODE,	    0,	  2,	0,	"-loop_mode"		},

/* Terminator */
{ PARAM_COUNT,		    0,	  0,	0,	NULL			}
};

/*  ============== NDD Support Functions ===============  */

/*
 * Extracts the value from the unm parameter array and prints
 * the parameter value. cp points to the required parameter.
 */
/* ARGSUSED */
static int
unm_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;

	ndp = (nd_param_t *)(uintptr_t)cp;
	(void) mi_mpprintf(mp, "%d", ndp->ndp_val);

	return (0);
}

/*
 * Validates the request to set a UNM parameter to a specific value.
 * If the request is OK, the parameter is set.  Also the <info> field
 * is incremented to show that the parameter was touched, even though
 * it may have been set to the same value it already had.
 */
/* ARGSUSED */
static int
unm_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;
	int new_value;
	char *end;

	ndp = (nd_param_t *)(uintptr_t)cp;
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
unm_param_register(unm_adapter *adapter)
{
	const nd_param_t *tmplp;
	dev_info_t *dip;
	nd_param_t *ndp;
	caddr_t *nddpp;
	pfi_t setfn;
	char *nm;
	int pval;

	dip = adapter->dip;
	nddpp = &adapter->nd_data_p;
	ASSERT(*nddpp == NULL);

	if (adapter->ahw.board_type == UNM_NIC_XGBE)
		tmplp = nd_template_10000;
	else
		tmplp = nd_template_1000;

	for (; tmplp->ndp_name != NULL; ++tmplp) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters,
		 * then register the parameter with nd_load()
		 */
		ndp = &adapter->nd_params[tmplp->ndp_info];
		*ndp = *tmplp;
		nm = &ndp->ndp_name[0];
		setfn = unm_param_set;

		switch (*nm) {
		default:
		case '!':
			continue;

		case '+':
			break;

		case '-':
			setfn = NULL;
			break;
		}

		if (!nd_load(nddpp, ++nm, unm_param_get, setfn, (caddr_t)ndp))
			goto nd_fail;

		/*
		 * If the parameter is writable, and there's a property
		 * with the same name, and its value is in range, we use
		 * it to initialise the parameter.  If it exists but is
		 * out of range, it's ignored.
		 */
		if (setfn && UNM_PROP_EXISTS(dip, nm)) {
			pval = UNM_PROP_GET_INT(dip, nm);
			if (pval >= ndp->ndp_min && pval <= ndp->ndp_max)
				ndp->ndp_val = pval;
		}
	}

	DPRINTF(1, (CE_WARN, "unm_param_register: OK"));
	return (DDI_SUCCESS);

nd_fail:
	if (adapter->ahw.board_type == UNM_NIC_XGBE) {
		cmn_err(CE_WARN,
		    "unm_param_register: FAILED at index %d [info %d]",
		    (int)(tmplp-nd_template_10000), tmplp->ndp_info);
	} else {
		cmn_err(CE_WARN,
		    "unm_param_register: FAILED at index %d [info %d]",
		    (int)(tmplp-nd_template_1000), tmplp->ndp_info);
	}
	nd_free(nddpp);
	return (DDI_FAILURE);
}

int
unm_nd_init(unm_adapter *adapter)
{
	dev_info_t *dip;
	int duplex;
	int speed;

	/*
	 * Register all the per-instance properties, initialising
	 * them from the table above or from driver properties set
	 * in the .conf file
	 */
	if (unm_param_register(adapter) != DDI_SUCCESS)
		return (-1);

	/*
	 * The link speed may be forced to 1000 or 10000 Mbps using
	 * the property "transfer-speed". This may be done in OBP by
	 * using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 1000 or 10000 - any other value will be
	 * ignored.  Note that this does *enables* autonegotiation, but
	 * restricts it to the speed specified by the property.
	 */
	dip = adapter->dip;
	if (UNM_PROP_EXISTS(dip, transfer_speed_propname)) {

		speed = UNM_PROP_GET_INT(dip, transfer_speed_propname);

		switch (speed) {
		case 10000:
			adapter->param_adv_autoneg = 1;
			adapter->param_adv_10000fdx = 1;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 1000:
			adapter->param_adv_autoneg = 1;
			adapter->param_adv_1000fdx = 1;
			adapter->param_adv_1000hdx = 1;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 100:
			adapter->param_adv_autoneg = 1;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100fdx = 1;
			adapter->param_adv_100hdx = 1;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 10:
			adapter->param_adv_autoneg = 1;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10fdx = 1;
			adapter->param_adv_10hdx = 1;
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
	 * value (10000Mb/s, full-duplex).
	 */
	if (UNM_PROP_EXISTS(dip, speed_propname) ||
	    UNM_PROP_EXISTS(dip, duplex_propname)) {

		adapter->param_adv_autoneg = 0;
		adapter->param_adv_10000fdx = 1;
		adapter->param_adv_1000fdx = 1;
		adapter->param_adv_1000hdx = 1;
		adapter->param_adv_100fdx = 1;
		adapter->param_adv_100hdx = 1;
		adapter->param_adv_10fdx = 1;
		adapter->param_adv_10hdx = 1;

		speed = UNM_PROP_GET_INT(dip, speed_propname);
		duplex = UNM_PROP_GET_INT(dip, duplex_propname);

		switch (speed) {
		case 10000:
		default:
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 1000:
			adapter->param_adv_10000fdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 100:
			adapter->param_adv_10000fdx = 0;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_10fdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 10:
			adapter->param_adv_10000fdx = 0;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_100hdx = 0;
			break;
		}

		switch (duplex) {
		default:
		case 1:
			adapter->param_adv_1000hdx = 0;
			adapter->param_adv_100hdx = 0;
			adapter->param_adv_10hdx = 0;
			break;

		case 0:
			adapter->param_adv_10000fdx = 0;
			adapter->param_adv_1000fdx = 0;
			adapter->param_adv_100fdx = 0;
			adapter->param_adv_10fdx = 0;
			break;
		}
	}

	DPRINTF(1, (CE_WARN, "unm_nd_init: autoneg %d"
	    "pause %d asym_pause %d "
	    "10000fdx %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    adapter->param_adv_autoneg,
	    adapter->param_adv_pause, adapter->param_adv_asym_pause,
	    adapter->param_adv_10000fdx,
	    adapter->param_adv_1000fdx, adapter->param_adv_1000hdx,
	    adapter->param_adv_100fdx, adapter->param_adv_100hdx,
	    adapter->param_adv_10fdx, adapter->param_adv_10hdx));

	return (0);
}

enum ioc_reply
unm_nd_ioctl(unm_adapter *adapter, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	boolean_t ok;
	int cmd;

	DPRINTF(1, (CE_WARN, "unm_nd_ioctl($%p, $%p, $%p, $%p)",
	    (void *)adapter, (void *)wq, (void *)mp, (void *)iocp));

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		DPRINTF(-1, (CE_WARN, "unm_nd_ioctl: invalid cmd 0x%x", cmd));
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
		ok = nd_getset(wq, adapter->nd_data_p, mp);
		DPRINTF(1, (CE_WARN, "unm_nd_ioctl: get %s", ok ? "OK" :
		    "FAIL"));
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		/*
		 * All adv_* parameters are locked (read-only) while
		 * the device is in any sort of loopback mode ...
		 */
		if (adapter->param_loop_mode != UNM_LOOP_NONE) {
			iocp->ioc_error = EBUSY;
			return (IOC_INVAL);
		}

		ok = nd_getset(wq, adapter->nd_data_p, mp);

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
		DPRINTF(1, (CE_WARN,
		    "unm_nd_ioctl: set %s err %d autoneg %d info %d",
		    ok ? "OK" : "FAIL", iocp->ioc_error,
		    adapter->nd_params[PARAM_ADV_AUTONEG_CAP].ndp_val,
		    adapter->nd_params[PARAM_ADV_AUTONEG_CAP].ndp_info));
		if (!ok)
			return (IOC_INVAL);
		if (iocp->ioc_error)
			return (IOC_REPLY);

		return (IOC_RESTART_REPLY);
	}
}

/* Free the Named Dispatch Table by calling nd_free */
void
unm_nd_cleanup(unm_adapter *adapter)
{
	nd_free(&adapter->nd_data_p);
}
