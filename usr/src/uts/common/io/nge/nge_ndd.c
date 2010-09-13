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


boolean_t
nge_nd_get_prop_val(dev_info_t *dip, char *nm, long min, long max, int *pval)
{
	/*
	 * If the parameter is writable, and there's a property
	 * with the same name, and its value is in range, we use
	 * it to initialise the parameter.  If it exists but is
	 * out of range, it's ignored.
	 */
	if (NGE_PROP_EXISTS(dip, nm)) {
		*pval = NGE_PROP_GET_INT(dip, nm);
		if (*pval >= min && *pval <= max)
			return (B_TRUE);
	}
	return (B_FALSE);
}

#define	NGE_INIT_PROP(propname, fieldname, initval) {		\
	if (nge_nd_get_prop_val(dip, propname, 0, 1, &propval)) \
		ngep->fieldname = propval;			\
	else							\
		ngep->fieldname = initval;			\
}

static void
nge_nd_param_init(nge_t *ngep)
{
	dev_info_t *dip;
	int propval;

	dip = ngep->devinfo;

	/*
	 * initialize values to those from driver.conf (if available)
	 * or the default value otherwise.
	 */
	NGE_INIT_PROP("adv_autoneg_cap", param_adv_autoneg, 1);
	NGE_INIT_PROP("adv_1000fdx_cap", param_adv_1000fdx, 1);
	NGE_INIT_PROP("adv_1000hdx_cap", param_adv_1000hdx, 0);
	NGE_INIT_PROP("adv_pause_cap", param_adv_pause, 1);
	NGE_INIT_PROP("adv_asym_pause_cap", param_adv_asym_pause, 1);
	NGE_INIT_PROP("adv_100fdx_cap", param_adv_100fdx, 1);
	NGE_INIT_PROP("adv_100hdx_cap", param_adv_100hdx, 1);
	NGE_INIT_PROP("adv_10fdx_cap", param_adv_10fdx, 1);
	NGE_INIT_PROP("adv_10hdx_cap", param_adv_10hdx, 1);
}

int
nge_nd_init(nge_t *ngep)
{
	dev_info_t *dip;
	int duplex;
	int speed;

	NGE_TRACE(("nge_nd_init($%p)", (void *)ngep));

	/*
	 * initialize from .conf file, if appropriate.
	 */
	nge_nd_param_init(ngep);

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
