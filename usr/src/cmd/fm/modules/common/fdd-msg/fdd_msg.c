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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * fdd messenger
 *
 * This module sends fdd running on service processor a message which
 * indicates the Solaris host FMA capability when fmd is started. The
 * message is sent via the BMC driver (KCS interface) to the IPMI stack
 * of ILOM using the IPMI Sun OEM core tunnel command. The sub-command
 * is CORE_TUNNEL_SUBCMD_HOSTCAP. The IPMI stack posts an host FMA
 * capability event to the event manager upon receiving this message.
 * fdd subscribes to the event manager for this event. Upon receving
 * this event, fdd will adjust its configuration.
 *
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <libipmi.h>
#include <fm/fmd_api.h>

#define	CMD_SUNOEM_CORE_TUNNEL 0x44
#define	CORE_TUNNEL_SUBCMD_HOSTFMACAP 2
#define	OEM_DATA_LENGTH 3
#define	VERSION 0x10
#define	HOST_CAPABILITY 2

static boolean_t
ipmi_is_sun_ilom(ipmi_deviceid_t *dp)
{
	return (ipmi_devid_manufacturer(dp) == IPMI_OEM_SUN &&
	    dp->id_product == IPMI_PROD_SUN_ILOM);
}

static int
check_sunoem(ipmi_handle_t *ipmi_hdl)
{
	ipmi_deviceid_t *devid;

	if ((devid = ipmi_get_deviceid(ipmi_hdl)) == NULL)
		return (-1);

	if (!ipmi_is_sun_ilom(devid))
		return (-2);

	return (0);
}

/*ARGSUSED*/
static void
send_fma_cap(fmd_hdl_t *hdl, id_t id, void *data)
{
	ipmi_handle_t *ipmi_hdl;
	ipmi_cmd_t cmd;
	uint8_t oem_data[OEM_DATA_LENGTH];

	ipmi_hdl = fmd_hdl_getspecific(hdl);

	oem_data[0] = CORE_TUNNEL_SUBCMD_HOSTFMACAP;
	oem_data[1] = VERSION;
	oem_data[2] = HOST_CAPABILITY;

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_lun = 0;
	cmd.ic_cmd = CMD_SUNOEM_CORE_TUNNEL;
	cmd.ic_dlen = OEM_DATA_LENGTH;
	cmd.ic_data = oem_data;

	if (ipmi_send(ipmi_hdl, &cmd) == NULL) {
		fmd_hdl_debug(hdl, "Failed to send Solaris FMA "
		    "capability to fdd: %s", ipmi_errmsg(ipmi_hdl));
	}

	ipmi_close(ipmi_hdl);
	fmd_hdl_setspecific(hdl, NULL);
	fmd_hdl_unregister(hdl);
}

static const fmd_hdl_ops_t fmd_ops = {
	NULL,		/* fmdo_recv */
	send_fma_cap,	/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "1s" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"fdd Messenger", "1.0", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	ipmi_handle_t	*ipmi_hdl;
	int error;
	char *msg;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	if ((ipmi_hdl = ipmi_open(&error, &msg)) == NULL) {
		/*
		 * If /dev/bmc doesn't exist on the system, then unload the
		 * module without doing anything.
		 */
		if (error != EIPMI_BMC_OPEN_FAILED)
			fmd_hdl_abort(hdl, "Failed to initialize IPMI "
			    "connection: %s\n", msg);
		fmd_hdl_debug(hdl, "Failed to load: no IPMI connection "
		    "present");
		fmd_hdl_unregister(hdl);
		return;
	}

	/*
	 * Check if it's Sun ILOM
	 */
	if (check_sunoem(ipmi_hdl) != 0) {
		fmd_hdl_debug(hdl, "Service Processor does not run "
		    "Sun ILOM");
		ipmi_close(ipmi_hdl);
		fmd_hdl_unregister(hdl);
		return;
	}

	fmd_hdl_setspecific(hdl, ipmi_hdl);

	/*
	 * Setup the timer.
	 */
	(void) fmd_timer_install(hdl, NULL, NULL, 0);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	ipmi_handle_t *ipmi_hdl = fmd_hdl_getspecific(hdl);

	if (ipmi_hdl) {
		ipmi_close(ipmi_hdl);
	}
}
