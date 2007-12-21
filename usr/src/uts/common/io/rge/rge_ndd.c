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

#include "rge.h"

#define	RGE_DBG		RGE_DBG_NDD	/* debug flag for this code	*/

/*
 * Property names
 */
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
 *	parameter has been set via ndd (see rge_param_set()).
 */
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

/* nd_template for RTL8101E */
static const nd_param_t nd_template_100[] = {
/*	info		min	max	init	r/w+name		*/

/* Our hardware capabilities */
{ PARAM_AUTONEG_CAP,	    0,	  1,	1,	"-autoneg_cap"		},
{ PARAM_PAUSE_CAP,	    0,	  1,	1,	"-pause_cap"		},
{ PARAM_ASYM_PAUSE_CAP,	    0,	  1,	1,	"-asym_pause_cap"	},
{ PARAM_1000FDX_CAP,	    0,	  1,	0,	"-1000fdx_cap"		},
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
{ PARAM_ADV_1000FDX_CAP,    0,	  1,	0,	"-adv_1000fdx_cap"	},
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
 * Extracts the value from the rge parameter array and prints
 * the parameter value. cp points to the required parameter.
 */
static int
rge_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;

	_NOTE(ARGUNUSED(q, credp))

	ndp = (nd_param_t *)cp;
	(void) mi_mpprintf(mp, "%d", ndp->ndp_val);

	return (0);
}

/*
 * Validates the request to set a RGE parameter to a specific value.
 * If the request is OK, the parameter is set.  Also the <info> field
 * is incremented to show that the parameter was touched, even though
 * it may have been set to the same value it already had.
 */
static int
rge_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
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
rge_param_register(rge_t *rgep)
{
	const nd_param_t *tmplp;
	dev_info_t *dip;
	nd_param_t *ndp;
	caddr_t *nddpp;
	pfi_t setfn;
	char *nm;
	int pval;

	dip = rgep->devinfo;
	nddpp = &rgep->nd_data_p;
	ASSERT(*nddpp == NULL);

	if (rgep->chipid.mac_ver == MAC_VER_8101E)
		tmplp = nd_template_100;
	else
		tmplp = nd_template_1000;

	for (; tmplp->ndp_name != NULL; ++tmplp) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters,
		 * then register the parameter with nd_load()
		 */
		ndp = &rgep->nd_params[tmplp->ndp_info];
		*ndp = *tmplp;
		nm = &ndp->ndp_name[0];
		setfn = rge_param_set;

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

		if (!nd_load(nddpp, ++nm, rge_param_get, setfn, (caddr_t)ndp))
			goto nd_fail;

		/*
		 * If the parameter is writable, and there's a property
		 * with the same name, and its value is in range, we use
		 * it to initialise the parameter.  If it exists but is
		 * out of range, it's ignored.
		 */
		if (setfn && RGE_PROP_EXISTS(dip, nm)) {
			pval = RGE_PROP_GET_INT(dip, nm);
			if (pval >= ndp->ndp_min && pval <= ndp->ndp_max)
				ndp->ndp_val = pval;
		}
	}

	RGE_DEBUG(("rge_param_register: OK"));
	return (DDI_SUCCESS);

nd_fail:
	if (rgep->chipid.mac_ver == MAC_VER_8101E) {
		RGE_DEBUG(("rge_param_register: FAILED at index %d [info %d]",
		    tmplp-nd_template_100, tmplp->ndp_info));
	} else {
		RGE_DEBUG(("rge_param_register: FAILED at index %d [info %d]",
		    tmplp-nd_template_1000, tmplp->ndp_info));
	}
	nd_free(nddpp);
	return (DDI_FAILURE);
}

int
rge_nd_init(rge_t *rgep)
{
	dev_info_t *dip;
	int duplex;
	int speed;

	/*
	 * Register all the per-instance properties, initialising
	 * them from the table above or from driver properties set
	 * in the .conf file
	 */
	if (rge_param_register(rgep) != DDI_SUCCESS)
		return (-1);

	/*
	 * The link speed may be forced to 10, 100 or 1000 Mbps using
	 * the property "transfer-speed". This may be done in OBP by
	 * using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 10, 100 or 1000 - any other value will be
	 * ignored.  Note that this does *enables* autonegotiation, but
	 * restricts it to the speed specified by the property.
	 */
	dip = rgep->devinfo;
	if (RGE_PROP_EXISTS(dip, transfer_speed_propname)) {

		speed = RGE_PROP_GET_INT(dip, transfer_speed_propname);
		rge_log(rgep, "%s property is %d",
		    transfer_speed_propname, speed);

		switch (speed) {
		case 1000:
			rgep->param_adv_autoneg = 1;
			rgep->param_adv_1000fdx = 1;
			rgep->param_adv_1000hdx = 1;
			rgep->param_adv_100fdx = 0;
			rgep->param_adv_100hdx = 0;
			rgep->param_adv_10fdx = 0;
			rgep->param_adv_10hdx = 0;
			break;

		case 100:
			rgep->param_adv_autoneg = 1;
			rgep->param_adv_1000fdx = 0;
			rgep->param_adv_1000hdx = 0;
			rgep->param_adv_100fdx = 1;
			rgep->param_adv_100hdx = 1;
			rgep->param_adv_10fdx = 0;
			rgep->param_adv_10hdx = 0;
			break;

		case 10:
			rgep->param_adv_autoneg = 1;
			rgep->param_adv_1000fdx = 0;
			rgep->param_adv_1000hdx = 0;
			rgep->param_adv_100fdx = 0;
			rgep->param_adv_100hdx = 0;
			rgep->param_adv_10fdx = 1;
			rgep->param_adv_10hdx = 1;
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
	if (RGE_PROP_EXISTS(dip, speed_propname) ||
	    RGE_PROP_EXISTS(dip, duplex_propname)) {

		rgep->param_adv_autoneg = 0;
		rgep->param_adv_1000fdx = 1;
		rgep->param_adv_1000hdx = 1;
		rgep->param_adv_100fdx = 1;
		rgep->param_adv_100hdx = 1;
		rgep->param_adv_10fdx = 1;
		rgep->param_adv_10hdx = 1;

		speed = RGE_PROP_GET_INT(dip, speed_propname);
		duplex = RGE_PROP_GET_INT(dip, duplex_propname);
		rge_log(rgep, "%s property is %d",
		    speed_propname, speed);
		rge_log(rgep, "%s property is %d",
		    duplex_propname, duplex);

		switch (speed) {
		case 1000:
		default:
			rgep->param_adv_100fdx = 0;
			rgep->param_adv_100hdx = 0;
			rgep->param_adv_10fdx = 0;
			rgep->param_adv_10hdx = 0;
			break;

		case 100:
			rgep->param_adv_1000fdx = 0;
			rgep->param_adv_1000hdx = 0;
			rgep->param_adv_10fdx = 0;
			rgep->param_adv_10hdx = 0;
			break;

		case 10:
			rgep->param_adv_1000fdx = 0;
			rgep->param_adv_1000hdx = 0;
			rgep->param_adv_100fdx = 0;
			rgep->param_adv_100hdx = 0;
			break;
		}

		switch (duplex) {
		default:
		case 1:
			rgep->param_adv_1000hdx = 0;
			rgep->param_adv_100hdx = 0;
			rgep->param_adv_10hdx = 0;
			break;

		case 0:
			rgep->param_adv_1000fdx = 0;
			rgep->param_adv_100fdx = 0;
			rgep->param_adv_10fdx = 0;
			break;
		}
	}

	RGE_DEBUG(("rge_nd_init: autoneg %d"
	    "pause %d asym_pause %d "
	    "1000fdx %d 1000hdx %d "
	    "100fdx %d 100hdx %d "
	    "10fdx %d 10hdx %d ",
	    rgep->param_adv_autoneg,
	    rgep->param_adv_pause, rgep->param_adv_asym_pause,
	    rgep->param_adv_1000fdx, rgep->param_adv_1000hdx,
	    rgep->param_adv_100fdx, rgep->param_adv_100hdx,
	    rgep->param_adv_10fdx, rgep->param_adv_10hdx));

	return (0);
}

enum ioc_reply
rge_nd_ioctl(rge_t *rgep, queue_t *wq, mblk_t *mp, struct iocblk *iocp)
{
	nd_param_t *ndp;
	boolean_t ok;
	int info;
	int cmd;

	RGE_TRACE(("rge_nd_ioctl($%p, $%p, $%p, $%p)",
	    (void *)rgep, (void *)wq, (void *)mp, (void *)iocp));

	ASSERT(mutex_owned(rgep->genlock));

	cmd = iocp->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		rge_error(rgep, "rge_nd_ioctl: invalid cmd 0x%x", cmd);
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
		ok = nd_getset(wq, rgep->nd_data_p, mp);
		RGE_DEBUG(("rge_nd_ioctl: get %s", ok ? "OK" : "FAIL"));
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		/*
		 * All adv_* parameters are locked (read-only) while
		 * the device is in any sort of loopback mode ...
		 */
		if (rgep->param_loop_mode != RGE_LOOP_NONE) {
			iocp->ioc_error = EBUSY;
			return (IOC_INVAL);
		}

		/*
		 * Before calling nd_getset(), we save the <info> field
		 * of the 'autonegotiation' parameter so that we can tell
		 * whether it was assigned (even if its value doesn't
		 * actually change).
		 */
		ndp = &rgep->nd_params[PARAM_ADV_AUTONEG_CAP];
		info = ndp->ndp_info;
		ok = nd_getset(wq, rgep->nd_data_p, mp);

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
		RGE_DEBUG(("rge_nd_ioctl: set %s err %d autoneg %d info %d/%d",
		    ok ? "OK" : "FAIL", iocp->ioc_error,
		    ndp->ndp_val, info, ndp->ndp_info));
		if (!ok)
			return (IOC_INVAL);
		if (iocp->ioc_error)
			return (IOC_REPLY);

		return (IOC_RESTART_REPLY);
	}
}

/* Free the Named Dispatch Table by calling nd_free */
void
rge_nd_cleanup(rge_t *rgep)
{
	nd_free(&rgep->nd_data_p);
}
