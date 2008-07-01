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

#include "dmfe_impl.h"


#define	DMFE_DBG	DMFE_DBG_NDD	/* debug flag for this code	*/

/*
 * The following variables are used for configuring link-operation
 * for all the "dmfe" interfaces in the system.  Later these parameters
 * may be changed per interface using "ndd" command.  These parameters
 * may also be specified as properties using the .conf file mechanism
 * for each interface.
 */

static int adv_autoneg_cap = 1;
static int adv_10hdx_cap = 1;
static int adv_10fdx_cap = 1;
static int adv_100hdx_cap = 1;
static int adv_100fdx_cap = 1;
static int adv_100T4_cap = 0;

/*
 * Property names
 */
static char transfer_speed_propname[] = "transfer-speed";
static char speed_propname[] = "speed";
static char duplex_propname[] = "full-duplex";

/*
 * Notes:
 *	The first character of the <name> field encodes the read/write
 *	status of the parameter: '-' => read-only, '+' => read/write,
 *	'*' => read/write, with magical side-effects ;-)  A NULL in the
 *	<name> field terminates the array.
 *
 *	The <info> field is used here to provide the index of the
 *	parameter to be initialised; thus it doesn't matter whether
 *	this table is kept ordered or not.
 *
 *	The <info> field in the per-instance copy, on the other hand,
 *	is used to count assignments so that we can tell when a magic
 *	parameter has been set via ndd (see dmfe_param_set()).
 */
static const nd_param_t nd_template[] = {
/*	info		min	max	init	r/w+name		*/
{ PARAM_LINK_STATUS,	 0,	  1,	0,	"-link_status"		},
{ PARAM_LINK_SPEED,	 0,	100,	0,	"-link_speed"		},
{ PARAM_LINK_MODE,	 0,	  1,	0,	"-link_mode"		},

{ PARAM_ADV_AUTONEG_CAP, 0,	  1,	1,	"*adv_autoneg_cap"	},
{ PARAM_ADV_100T4_CAP,   0,	  1,    0,	"+adv_100T4_cap"	},
{ PARAM_ADV_100FDX_CAP,	 0,	  1,	1,	"+adv_100fdx_cap"	},
{ PARAM_ADV_100HDX_CAP,	 0,	  1,	1,	"+adv_100hdx_cap"	},
{ PARAM_ADV_10FDX_CAP,	 0,	  1,	1,	"+adv_10fdx_cap"	},
{ PARAM_ADV_10HDX_CAP,	 0,	  1,	1,	"+adv_10hdx_cap"	},

{ PARAM_BMSR_AUTONEG_CAP, 0,  1,	0,	"-autoneg_cap"		},
{ PARAM_BMSR_100T4_CAP,  0,	  1, 	0,	"-100T4_cap"		},
{ PARAM_BMSR_100FDX_CAP, 0,	  1,	0,	"-100fdx_cap"		},
{ PARAM_BMSR_100HDX_CAP, 0,	  1,	0,	"-100hdx_cap"		},
{ PARAM_BMSR_10FDX_CAP,  0,	  1,	0,	"-10fdx_cap"		},
{ PARAM_BMSR_10HDX_CAP,  0,	  1,	0,	"-10hdx_cap"		},

{ PARAM_LP_AUTONEG_CAP,	 0,	  1,	0,	"-lp_autoneg_cap"	},
{ PARAM_LP_100T4_CAP,    0,	  1, 	0,	"-lp_100T4_cap"		},
{ PARAM_LP_100FDX_CAP,   0,	  1,	0,	"-lp_100fdx_cap"	},
{ PARAM_LP_100HDX_CAP,   0,	  1,	0,	"-lp_100hdx_cap"	},
{ PARAM_LP_10FDX_CAP,    0,	  1,	0,	"-lp_10fdx_cap"		},
{ PARAM_LP_10HDX_CAP,    0,	  1,	0,	"-lp_10hdx_cap"		},

{ PARAM_COUNT,		 0,	  0,	0,	NULL			}
};


/*  ============== NDD Support Functions ===============  */

/*
 * Extracts the value from the dmfe parameter array and prints
 * the parameter value. cp points to the required parameter.
 */
static int
dmfe_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;

	_NOTE(ARGUNUSED(q, credp))

	ndp = (void *)cp;
	(void) mi_mpprintf(mp, "%d", ndp->ndp_val);

	return (0);
}

/*
 * Validates the request to set a DMFE parameter to a specific value.
 * If the request is OK, the parameter is set.  Also, update the link reset
 * to show that a link reset is required if the parameter changed, or for
 * magic parameters, that it was touched even if the value did not change.
 */
static int
dmfe_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	nd_param_t *ndp;
	long new_value;
	char *end;

	_NOTE(ARGUNUSED(q, mp, credp))

	ndp = (void *)cp;
	if (ndp->ndp_name[0] == '-')
		return (EACCES);	/* shouldn't happen!	*/

	if (ddi_strtol(value, &end, 10, &new_value) != 0)
		return (EINVAL);
	if (new_value < ndp->ndp_min || new_value > ndp->ndp_max)
		return (EINVAL);

	if ((ndp->ndp_name[0] == '*') ||
	    (ndp->ndp_val != new_value)) {
		ndp->ndp_dmfe->link_reset = B_TRUE;
	}
	ndp->ndp_val = (uint32_t)new_value;
	return (0);
}

/*
 * Initialise the per-instance parameter array from the global prototype,
 * and register each element with the named dispatch handler using nd_load()
 */
static boolean_t
dmfe_param_register(dmfe_t *dmfep)
{
	const nd_param_t *tmplp;
	nd_param_t *ndp;
	caddr_t *nddpp;
	ndsetf_t setfn;
	char *nm;

	DMFE_TRACE(("dmfe_param_register($%p)", (void *)dmfep));

	nddpp = &dmfep->nd_data_p;
	ASSERT(*nddpp == NULL);

	for (tmplp = nd_template; tmplp->ndp_name != NULL; ++tmplp) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters, and
		 * then register it with nd_load()
		 */
		ndp = &dmfep->nd_params[tmplp->ndp_info];
		*ndp = *tmplp;
		ndp->ndp_dmfe = dmfep;
		nm = &ndp->ndp_name[0];
		setfn = *nm++ == '-' ? NULL : dmfe_param_set;
		if (!nd_load(nddpp, nm, dmfe_param_get, setfn, (caddr_t)ndp))
			goto nd_fail;
	}

	DMFE_DEBUG(("dmfe_param_register: OK"));
	return (B_TRUE);

nd_fail:
	DMFE_DEBUG(("dmfe_param_register: FAILED at index %d [info %d]",
	    tmplp-nd_template, tmplp->ndp_info));
	nd_free(nddpp);
	return (B_FALSE);
}

int
dmfe_nd_init(dmfe_t *dmfep)
{
	dev_info_t *dip;
	int duplex;
	int speed;
	int pval;

	DMFE_TRACE(("dmfe_init_xfer_params($%p)", dmfep));

	if (dmfe_param_register(dmfep) != B_TRUE)
		return (-1);

	/*
	 * Set up the start-up values for user-configurable parameters.
	 * Get the values from the global variables first.
	 */
	dmfep->param_anar_10hdx = adv_10hdx_cap;
	dmfep->param_anar_10fdx = adv_10fdx_cap;
	dmfep->param_anar_100hdx = adv_100hdx_cap;
	dmfep->param_anar_100fdx = adv_100fdx_cap;
	dmfep->param_anar_100T4 = adv_100T4_cap;
	dmfep->param_autoneg = adv_autoneg_cap;

	/*
	 * The link speed may be forced to either 10 Mbps or 100 Mbps
	 * using the property "transfer-speed". This may be done in OBP
	 * by using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 10 or 100 - other values will be ignored.
	 * Note that this does *enables* autonegotiation, but restricts
	 * it to the speed specified by the property.
	 */
	dip = dmfep->devinfo;
	speed = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    0, transfer_speed_propname, -1);
	if (speed != -1) {
		dmfe_log(dmfep, "%s property is %d",
		    transfer_speed_propname, speed);
		switch (speed) {
		case 100:
			dmfep->param_anar_10hdx = 0;
			dmfep->param_anar_10fdx = 0;
			dmfep->param_anar_100hdx = 1;
			dmfep->param_anar_100fdx = 1;
			dmfep->param_autoneg = 1;
			break;

		case 10:
			dmfep->param_anar_10hdx = 1;
			dmfep->param_anar_10fdx = 1;
			dmfep->param_anar_100hdx = 0;
			dmfep->param_anar_100fdx = 0;
			dmfep->param_autoneg = 1;
			break;

		default:
			break;
		}
	}

	/*
	 * Get the parameter values configured in .conf file.
	 * These override both the global defaults AND any
	 * value derived from the "transfer-speed" property.
	 */
	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_10hdx_cap", -1);
	if (pval != -1)
		dmfep->param_anar_10hdx = pval ? 1 : 0;

	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_10fdx_cap", -1);
	if (pval != -1)
		dmfep->param_anar_10fdx = pval ? 1 : 0;

	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_100hdx_cap", -1);
	if (pval != -1)
		dmfep->param_anar_100hdx = pval ? 1 : 0;

	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_100fdx_cap", -1);
	if (pval != -1)
		dmfep->param_anar_100fdx = pval ? 1 : 0;

	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_100T4_cap", -1);
	if (pval != -1)
		dmfep->param_anar_100T4 = pval ? 1 : 0;

	pval = ddi_prop_get_int(DDI_DEV_T_ANY, dip, 0, "adv_autoneg_cap", -1);
	if (pval != -1)
		dmfep->param_autoneg = pval ? 1 : 0;

	/*
	 * Finally, check the "speed" and "full-duplex" properties that
	 * may be specified in the .conf file.  Setting either one of
	 * these properties will override all other settings and *disable*
	 * autonegotiation, with the consequence that both should be
	 * specified if either one is.  Otherwise, the unspecified
	 * parameter will be set to a default value (100Mb/s, half-duplex).
	 */
	speed = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, speed_propname, -1);
	duplex = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, duplex_propname, -1);

	if (speed != -1 || duplex != -1) {
		/* force speed */
		dmfep->param_anar_10hdx = 1;
		dmfep->param_anar_10fdx = 1;
		dmfep->param_anar_100hdx = 1;
		dmfep->param_anar_100fdx = 1;
		dmfep->param_anar_100T4 = 0;
		dmfep->param_autoneg = 0;

		dmfe_log(dmfep, "%s property is %d", speed_propname, speed);
		switch (speed) {
		case 10:
			dmfep->param_anar_100hdx = 0;
			dmfep->param_anar_100fdx = 0;
			break;

		case 100:
		default:
			dmfep->param_anar_10hdx = 0;
			dmfep->param_anar_10fdx = 0;
			break;
		}

		dmfe_log(dmfep, "%s property is %d", duplex_propname, duplex);
		switch (duplex) {
		case 1:
			dmfep->param_anar_10hdx = 0;
			dmfep->param_anar_100hdx = 0;
			break;

		default:
		case 0:
			dmfep->param_anar_10fdx = 0;
			dmfep->param_anar_100fdx = 0;
			break;
		}
	}

	return (0);
}

enum ioc_reply
dmfe_nd_ioctl(dmfe_t *dmfep, queue_t *wq, mblk_t *mp, int cmd)
{
	int ok;

	switch (cmd) {
	default:
		/*
		 * This should never happen ...
		 */
		dmfe_error(dmfep, "dmfe_nd_ioctl: invalid cmd 0x%x", cmd);
		return (IOC_INVAL);

	case DMFE_ND_GET:
		/*
		 * If nd_getset() returns B_FALSE, the command was
		 * not valid (e.g. unknown name), so we just tell the
		 * top-level ioctl code to send a NAK (with code EINVAL).
		 *
		 * Otherwise, nd_getset() will have built the reply to
		 * be sent (but not actually sent it), so we tell our
		 * caller to send the prepared reply.
		 */
		ok = nd_getset(wq, dmfep->nd_data_p, mp);
		DMFE_DEBUG(("dmfe_nd_ioctl: get %s", ok ? "OK" : "FAIL"));
		return (ok ? IOC_REPLY : IOC_INVAL);

	case DMFE_ND_SET:
		/*
		 * Before calling nd_getset(), we save the <info> field
		 * of the 'autonegotiation' parameter so that we can tell
		 * whether it was assigned (even if its value doesn't
		 * actually change).
		 *
		 * If nd_getset() returns B_FALSE, the command was
		 * not valid (e.g. unknown name), so we just tell the
		 * top-level ioctl code to send a NAK (with code EINVAL).
		 *
		 * Otherwise, nd_getset() will have built the reply to
		 * be sent (but not actually sent it).  If the command
		 * didn't touch the magic 'autonegotiation' parameter,
		 * we can just tell our caller to send the prepared reply.
		 *
		 * If the 'autonegotiation' parameter *was* touched (or any
		 * of the other link parameters modified), we flag
		 * it so the top-level ioctl code knows to update
		 * the PHY and restart the chip before replying ...
		 */
		ok = nd_getset(wq, dmfep->nd_data_p, mp);
		DMFE_DEBUG(("dmfe_nd_ioctl: set %s link_reset %d",
		    ok ? "OK" : "FAIL", dmfep->link_reset));

		if (!ok)
			return (IOC_INVAL);
		if (!dmfep->link_reset)
			return (IOC_REPLY);
		dmfep->link_reset = B_FALSE;
		return (IOC_RESTART);
	}
}

/* Free the Named Dispatch Table by calling nd_free */
void
dmfe_nd_cleanup(dmfe_t *dmfep)
{
	nd_free(&dmfep->nd_data_p);
}

#undef	DMFE_DBG
