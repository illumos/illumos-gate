/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#include "ixgbe_sw.h"

/* Function prototypes */
static int ixgbe_nd_get(queue_t *, mblk_t *, caddr_t, cred_t *);
static int ixgbe_nd_set(queue_t *, mblk_t *, char *, caddr_t, cred_t *);
static int ixgbe_nd_param_load(ixgbe_t *);
static void ixgbe_nd_get_param_val(nd_param_t *);
static void ixgbe_nd_set_param_val(nd_param_t *, uint32_t);

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
 *	parameter has been set via ndd (see ixgbe_nd_set()).
 */
static const nd_param_t nd_template[] = {
/* ixgbe info  min max init r/w+name */

/* Our hardware capabilities */
{ NULL,	PARAM_AUTONEG_CAP,	0, 1, 1,	"-autoneg_cap"		},
{ NULL,	PARAM_PAUSE_CAP,	0, 1, 1,	"-pause_cap"		},
{ NULL,	PARAM_ASYM_PAUSE_CAP,	0, 1, 1,	"-asym_pause_cap"	},
{ NULL,	PARAM_10000FDX_CAP,	0, 1, 1,	"-10000fdx_cap"		},
{ NULL,	PARAM_1000FDX_CAP,	0, 1, 1,	"-1000fdx_cap"		},
{ NULL,	PARAM_100FDX_CAP,	0, 1, 1,	"-100fdx_cap"		},
{ NULL,	PARAM_REM_FAULT,	0, 1, 0,	"-rem_fault"		},

/* Our advertised capabilities */
{ NULL,	PARAM_ADV_AUTONEG_CAP,	0, 1, 1,	"?adv_autoneg_cap"	},
{ NULL,	PARAM_ADV_PAUSE_CAP,	0, 1, 1,	"-adv_pause_cap"	},
{ NULL,	PARAM_ADV_ASYM_PAUSE_CAP, 0, 1, 1,	"-adv_asym_pause_cap"	},
{ NULL,	PARAM_ADV_10000FDX_CAP,	0, 1, 1,	"?adv_10000fdx_cap"	},
{ NULL,	PARAM_ADV_1000FDX_CAP,	0, 1, 1,	"?adv_1000fdx_cap"	},
{ NULL,	PARAM_ADV_100FDX_CAP,	0, 1, 1,	"?adv_100fdx_cap"	},
{ NULL,	PARAM_ADV_REM_FAULT,	0, 1, 0,	"-adv_rem_fault"	},

/* Partner's advertised capabilities */
{ NULL,	PARAM_LP_AUTONEG_CAP,	0, 1, 0,	"-lp_autoneg_cap"	},
{ NULL,	PARAM_LP_PAUSE_CAP,	0, 1, 0,	"-lp_pause_cap"		},
{ NULL,	PARAM_LP_ASYM_PAUSE_CAP, 0, 1, 0,	"-lp_asym_pause_cap"	},
{ NULL,	PARAM_LP_1000FDX_CAP,	0, 1, 0,	"-lp_1000fdx_cap"	},
{ NULL,	PARAM_LP_100FDX_CAP,	0, 1, 0,	"-lp_100fdx_cap"	},
{ NULL,	PARAM_LP_REM_FAULT,	0, 1, 0,	"-lp_rem_fault"		},

/* Current operating modes */
{ NULL,	PARAM_LINK_STATUS,	0, 1, 0,	"-link_status"		},
{ NULL,	PARAM_LINK_SPEED,	0, 1000, 0,	"-link_speed"		},
{ NULL,	PARAM_LINK_DUPLEX,	0, 2, 0,	"-link_duplex"		},

/* Terminator */
{ NULL, PARAM_COUNT, 0, 0, 0, NULL					}
};

/*
 * ixgbe_nd_get - Ndd get parameter values.
 */
static int
ixgbe_nd_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *credp)
{
	nd_param_t *nd = (nd_param_t *)(uintptr_t)cp;
	_NOTE(ARGUNUSED(q));
	_NOTE(ARGUNUSED(credp));

	ixgbe_nd_get_param_val(nd);
	(void) mi_mpprintf(mp, "%d", nd->val);

	return (0);
}

/*
 * ixgbe_nd_set - Ndd set parameter values.
 */
static int
ixgbe_nd_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *credp)
{
	nd_param_t *nd = (nd_param_t *)(uintptr_t)cp;
	long new_value;
	char *end;
	_NOTE(ARGUNUSED(q));
	_NOTE(ARGUNUSED(mp));
	_NOTE(ARGUNUSED(credp));

	new_value = mi_strtol(value, &end, 10);
	if (end == value)
		return (EINVAL);
	if (new_value < nd->min || new_value > nd->max)
		return (EINVAL);

	ixgbe_nd_set_param_val(nd, new_value);

	return (0);
}

/*
 * ixgbe_nd_param_load - Ndd load parameter values.
 */
static int
ixgbe_nd_param_load(ixgbe_t *ixgbe)
{
	const nd_param_t *tmpnd;
	nd_param_t *nd;
	caddr_t *ndd;
	pfi_t setfn;
	char *nm;
	int value;

	ndd = &ixgbe->nd_data;
	ASSERT(*ndd == NULL);

	for (tmpnd = nd_template; tmpnd->name != NULL; ++tmpnd) {
		/*
		 * Copy the template from nd_template[] into the
		 * proper slot in the per-instance parameters,
		 * then register the parameter with nd_load()
		 */
		nd = &ixgbe->nd_params[tmpnd->info];
		*nd = *tmpnd;
		nd->private = ixgbe;
		ixgbe_nd_get_param_val(nd);

		nm = &nd->name[0];
		setfn = ixgbe_nd_set;

		if (ixgbe->hw.phy.media_type != ixgbe_media_type_copper) {
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

		if (!nd_load(ndd, ++nm, ixgbe_nd_get, setfn, (caddr_t)nd))
			goto nd_fail;

		/*
		 * If the parameter is writable, and there's a property
		 * with the same name, and its value is in range, we use
		 * it to initialise the parameter.  If it exists but is
		 * out of range, it's ignored.
		 */
		if (setfn && IXGBE_PROP_EXISTS(ixgbe->dip, nm)) {
			value = IXGBE_PROP_GET_INT(ixgbe->dip, nm);
			if (value >= nd->min && value <= nd->max)
				nd->val = value;
		}
	}

	return (IXGBE_SUCCESS);

nd_fail:
	ixgbe_log(ixgbe,
	    "ixgbe_nd_param_load: failed at index %d [info %d]",
	    (tmpnd - nd_template), tmpnd->info);
	nd_free(ndd);
	return (IXGBE_FAILURE);
}

/*
 * ixgbe_nd_get_param_val - Get parameter values.
 */
static void
ixgbe_nd_get_param_val(nd_param_t *nd)
{
	ixgbe_t *ixgbe = (ixgbe_t *)nd->private;

	mutex_enter(&ixgbe->gen_lock);

	switch (nd->info) {
	case PARAM_LINK_STATUS:
		nd->val = (ixgbe->link_state == LINK_STATE_UP) ? 1 : 0;
		break;
	case PARAM_LINK_SPEED:
		nd->val = ixgbe->link_speed;
		break;
	case PARAM_LINK_DUPLEX:
		nd->val = ixgbe->link_duplex;
		break;
	default:
		break;
	}

	mutex_exit(&ixgbe->gen_lock);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_UNAFFECTED);
}

/*
 * ixgbe_nd_set_param_val - Set parameter values.
 */
static void
ixgbe_nd_set_param_val(nd_param_t *nd, uint32_t value)
{
	ixgbe_t *ixgbe = (ixgbe_t *)nd->private;

	mutex_enter(&ixgbe->gen_lock);

	if (nd->val == value) {
		mutex_exit(&ixgbe->gen_lock);
		return;
	}

	switch (nd->info) {
	case PARAM_ADV_AUTONEG_CAP:
	case PARAM_ADV_10000FDX_CAP:
	case PARAM_ADV_1000FDX_CAP:
	case PARAM_ADV_100FDX_CAP:
		nd->val = value;
		(void) ixgbe_driver_setup_link(ixgbe, B_TRUE);
		break;

	default:
		break;
	}

	mutex_exit(&ixgbe->gen_lock);

	if (ixgbe_check_acc_handle(ixgbe->osdep.reg_handle) != DDI_FM_OK)
		ddi_fm_service_impact(ixgbe->dip, DDI_SERVICE_DEGRADED);
}

/*
 * ixgbe_nd_init - Init for ndd support.
 */
int
ixgbe_nd_init(ixgbe_t *ixgbe)
{
	/*
	 * Register all the per-instance properties, initialising
	 * them from the table above or from driver properties set
	 * in the .conf file
	 */
	if (ixgbe_nd_param_load(ixgbe) != IXGBE_SUCCESS)
		return (IXGBE_FAILURE);

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_nd_cleanup - Free the Named Dispatch Table by calling nd_free
 */
void
ixgbe_nd_cleanup(ixgbe_t *ixgbe)
{
	nd_free(&ixgbe->nd_data);
}

/*
 * ixgbe_nd_ioctl - Ndd ioctl.
 */
enum ioc_reply
ixgbe_nd_ioctl(ixgbe_t *ixgbe, queue_t *q,
    mblk_t *mp, struct iocblk *ioc)
{
	boolean_t ok;
	int cmd;

	cmd = ioc->ioc_cmd;
	switch (cmd) {
	default:
		/* NOTREACHED */
		ASSERT(B_FALSE);
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
		ok = nd_getset(q, ixgbe->nd_data, mp);
		return (ok ? IOC_REPLY : IOC_INVAL);

	case ND_SET:
		/*
		 * All adv_* parameters are locked (read-only) while
		 * the device is in any sort of loopback mode ...
		 */
		if (ixgbe->loopback_mode != IXGBE_LB_NONE) {
			ioc->ioc_error = EBUSY;
			return (IOC_INVAL);
		}

		ok = nd_getset(q, ixgbe->nd_data, mp);
		return (ok ? IOC_REPLY : IOC_INVAL);
	}
}
