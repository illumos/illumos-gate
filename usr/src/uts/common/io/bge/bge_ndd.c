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

#include "bge_impl.h"


#define	BGE_DBG		BGE_DBG_NDD	/* debug flag for this code	*/
/*
 * Property names
 */
static char transfer_speed_propname[] = "transfer-speed";
static char speed_propname[] = "speed";
static char duplex_propname[] = "full-duplex";
static char supported_net[] = "supported-network-types";

/*
 * synchronize the  adv* and en* parameters.
 *
 * See comments in <sys/dld.h> for details of the *_en_*
 * parameters.  The usage of ndd for setting adv parameters will
 * synchronize all the en parameters with the bge parameters,
 * implicitly disabling any settings made via dladm.
 */
static void
bge_param_sync(bge_t *bgep)
{
	bgep->param_en_pause = bgep->param_adv_pause;
	bgep->param_en_asym_pause = bgep->param_adv_asym_pause;
	bgep->param_en_1000fdx = bgep->param_adv_1000fdx;
	bgep->param_en_1000hdx = bgep->param_adv_1000hdx;
	bgep->param_en_100fdx = bgep->param_adv_100fdx;
	bgep->param_en_100hdx = bgep->param_adv_100hdx;
	bgep->param_en_10fdx = bgep->param_adv_10fdx;
	bgep->param_en_10hdx = bgep->param_adv_10hdx;
}

boolean_t
bge_nd_get_prop_val(dev_info_t *dip, char *nm, long min, long max, int *pval)
{
	/*
	 * If there is a driver.conf setting for the prop, we use
	 * it to initialise the parameter.  If it exists but is
	 * out of range, it's ignored.
	 */
	if (BGE_PROP_EXISTS(dip, nm)) {
		*pval = BGE_PROP_GET_INT(dip, nm);
		if (*pval >= min && *pval <= max)
			return (B_TRUE);
	}
	return (B_FALSE);
}

#define	BGE_INIT_PROP(propname, fieldname, initval) {		\
	if (bge_nd_get_prop_val(dip, propname, 0, 1, &propval)) \
		bgep->fieldname = propval;			\
	else							\
		bgep->fieldname = initval;			\
}

static void
bge_nd_param_init(bge_t *bgep)
{
	dev_info_t *dip;
	int flags = bgep->chipid.flags;
	int propval;

	dip = bgep->devinfo;

	/*
	 * initialize values to those from driver.conf (if available)
	 * or the default value otherwise.
	 */
	BGE_INIT_PROP("adv_autoneg_cap", param_adv_autoneg, 1);
	if (DEVICE_5906_SERIES_CHIPSETS(bgep)) {
		BGE_INIT_PROP("adv_1000fdx_cap", param_adv_1000fdx, 0);
		BGE_INIT_PROP("adv_1000hdx_cap", param_adv_1000hdx, 0);
	} else {
		BGE_INIT_PROP("adv_1000fdx_cap", param_adv_1000fdx, 1);
		BGE_INIT_PROP("adv_1000hdx_cap", param_adv_1000hdx, 1);
	}
	BGE_INIT_PROP("adv_pause_cap", param_adv_pause, 1);
	BGE_INIT_PROP("adv_asym_pause_cap", param_adv_asym_pause, 1);

	if (flags & CHIP_FLAG_SERDES) {
		bgep->param_adv_100fdx = 0;
		bgep->param_adv_100hdx = 0;
		bgep->param_adv_10fdx = 0;
		bgep->param_adv_10hdx = 0;
	} else {
		BGE_INIT_PROP("adv_100fdx_cap", param_adv_100fdx, 1);
		BGE_INIT_PROP("adv_100hdx_cap", param_adv_100hdx, 1);
		BGE_INIT_PROP("adv_10fdx_cap", param_adv_10fdx, 1);
		BGE_INIT_PROP("adv_10hdx_cap", param_adv_10hdx, 1);
	}

}

int
bge_nd_init(bge_t *bgep)
{
	dev_info_t *dip;
	int duplex;
	int speed;
	char **options, *prop;
	uint_t  noptions;

	BGE_TRACE(("bge_nd_init($%p)", (void *)bgep));
	bge_nd_param_init(bgep);

	/*
	 * initialize from .conf file, if appropriate.
	 */

	/*
	 * check the OBP property "supported-network-types"
	 */
	if (BGE_PROP_EXISTS(bgep->devinfo, supported_net)) {
		if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, bgep->devinfo,
		    DDI_PROP_DONTPASS, supported_net,
		    &options, &noptions) == DDI_PROP_SUCCESS) {

			bgep->param_adv_autoneg = 0;
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_100hdx = 0;
			bgep->param_adv_10fdx = 0;
			bgep->param_adv_10hdx = 0;

			for (; noptions > 0; noptions--) {
				prop = options[noptions-1];
				if (strstr(prop, "ethernet") == NULL)
					continue;
				if (strstr(prop, "1000")) {
					if (strstr(prop, "auto")) {
						bgep->param_adv_1000fdx = 1;
						bgep->param_adv_1000hdx = 1;
						bgep->param_adv_autoneg = 1;
					} else if (strstr(prop, "full"))
						bgep->param_adv_1000fdx = 1;
					else if (strstr(prop, "half"))
						bgep->param_adv_1000hdx = 1;
				} else if (strstr(prop, "100")) {
					if (strstr(prop, "auto")) {
						bgep->param_adv_100fdx = 1;
						bgep->param_adv_100hdx = 1;
						bgep->param_adv_autoneg = 1;
					} else if (strstr(prop, "full"))
						bgep->param_adv_100fdx = 1;
					else if (strstr(prop, "half"))
						bgep->param_adv_100hdx = 1;
				} else if (strstr(prop, "10")) {
					if (strstr(prop, "auto")) {
						bgep->param_adv_10fdx = 1;
						bgep->param_adv_10hdx = 1;
						bgep->param_adv_autoneg = 1;
					} else if (strstr(prop, "full"))
						bgep->param_adv_10fdx = 1;
					else if (strstr(prop, "half"))
						bgep->param_adv_10hdx = 1;
				}
			}

			ddi_prop_free(options);
		}
	}

	/*
	 * The link speed may be forced to 10, 100 or 1000 Mbps using
	 * the property "transfer-speed". This may be done in OBP by
	 * using the command "apply transfer-speed=<speed> <device>".
	 * The speed may be 10, 100 or 1000 - any other value will be
	 * ignored.  Note that this does *enables* autonegotiation, but
	 * restricts it to the speed specified by the property.
	 */
	dip = bgep->devinfo;
	if (BGE_PROP_EXISTS(dip, transfer_speed_propname)) {

		speed = BGE_PROP_GET_INT(dip, transfer_speed_propname);
		bge_log(bgep, "%s property is %d",
		    transfer_speed_propname, speed);

		switch (speed) {
		case 1000:
			bgep->param_adv_autoneg = 1;
			bgep->param_adv_1000fdx = 1;
			bgep->param_adv_1000hdx = 1;
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_100hdx = 0;
			bgep->param_adv_10fdx = 0;
			bgep->param_adv_10hdx = 0;
			break;

		case 100:
			bgep->param_adv_autoneg = 1;
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_100fdx = 1;
			bgep->param_adv_100hdx = 1;
			bgep->param_adv_10fdx = 0;
			bgep->param_adv_10hdx = 0;
			break;

		case 10:
			bgep->param_adv_autoneg = 1;
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_100hdx = 0;
			bgep->param_adv_10fdx = 1;
			bgep->param_adv_10hdx = 1;
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
	if (BGE_PROP_EXISTS(dip, speed_propname) ||
	    BGE_PROP_EXISTS(dip, duplex_propname)) {

		bgep->param_adv_autoneg = 0;
		bgep->param_adv_1000fdx = 1;
		bgep->param_adv_1000hdx = 1;
		bgep->param_adv_100fdx = 1;
		bgep->param_adv_100hdx = 1;
		bgep->param_adv_10fdx = 1;
		bgep->param_adv_10hdx = 1;

		speed = BGE_PROP_GET_INT(dip, speed_propname);
		duplex = BGE_PROP_GET_INT(dip, duplex_propname);
		bge_log(bgep, "%s property is %d",
		    speed_propname, speed);
		bge_log(bgep, "%s property is %d",
		    duplex_propname, duplex);

		switch (speed) {
		case 1000:
		default:
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_100hdx = 0;
			bgep->param_adv_10fdx = 0;
			bgep->param_adv_10hdx = 0;
			break;

		case 100:
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_10fdx = 0;
			bgep->param_adv_10hdx = 0;
			break;

		case 10:
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_100hdx = 0;
			break;
		}

		switch (duplex) {
		default:
		case 1:
			bgep->param_adv_1000hdx = 0;
			bgep->param_adv_100hdx = 0;
			bgep->param_adv_10hdx = 0;
			break;

		case 0:
			bgep->param_adv_1000fdx = 0;
			bgep->param_adv_100fdx = 0;
			bgep->param_adv_10fdx = 0;
			break;
		}
	}

	bge_param_sync(bgep);

	return (0);
}
