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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * FMA capability messenger
 *
 * fdd-msg module is called once when fmd starts up. It does the following
 * based on different scenarios
 *
 * 1. If it's on a x86 platform, fdd-msg module sends fdd running on service
 * processor a message (ILOM) which indicates the Solaris host FMA capability.
 * The message is sent via the BMC driver (KCS interface) to the IPMI stack
 * of ILOM using the IPMI Sun OEM core tunnel command. The sub-command is
 * CORE_TUNNEL_SUBCMD_HOSTCAP. The IPMI stack posts an host FMA capability
 * event to the event manager upon receiving this message. fdd subscribes to
 * the event manager for this event. Upon receving this event, fdd will adjust
 * its configuration.
 *
 * 2. If it's on a Sparc platform, fdd-msg module just exit for now.
 */

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <sys/systeminfo.h>
#include <libipmi.h>
#include <sys/devfm.h>
#include <fm/fmd_api.h>
#if defined(__x86)
#include <sys/x86_archext.h>
#include <fm/fmd_agent.h>
#include <libnvpair.h>
#endif

#define	CMD_SUNOEM_CORE_TUNNEL 0x44
#define	CORE_TUNNEL_SUBCMD_HOSTFMACAP 2
#define	OEM_DATA_LENGTH 3
#define	VERSION 0x10

#if defined(__x86)
typedef struct cpu_tbl {
	char vendor[X86_VENDOR_STRLEN];
	int32_t family;
	int32_t model;
	char *propname;
} cpu_tbl_t;

static cpu_tbl_t fma_cap_list[] = {
	{"GenuineIntel", 6, 26, "NHMEP_fma_cap"},
	{"GenuineIntel", 6, 46, "NHMEX_fma_cap"},
	{"GenuineIntel", 6, 44, "WSMEP_fma_cap"},
	{"GenuineIntel", 6, 47, "INTLN_fma_cap"},
	{0, 0, 0, 0}
};
#endif

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

#if defined(__x86)
static int32_t
fma_cap_cpu_info(cpu_tbl_t *ci)
{
	nvlist_t **cpus, *nvl;
	uint_t ncpu, i;
	fmd_agent_hdl_t *hdl;
	char *ven;
	int32_t family, model;

	if ((hdl = fmd_agent_open(FMD_AGENT_VERSION)) == NULL)
		return (-1);
	if (fmd_agent_physcpu_info(hdl, &cpus, &ncpu) != 0) {
		fmd_agent_close(hdl);
		return (-1);
	}
	fmd_agent_close(hdl);

	if (cpus == NULL)
		return (-1);

	/*
	 * There is no mixed CPU type on x86 systems, it's ok to
	 * just pick the first one
	 */
	nvl = cpus[0];
	if (nvlist_lookup_string(nvl, FM_PHYSCPU_INFO_VENDOR_ID, &ven) != 0 ||
	    nvlist_lookup_int32(nvl, FM_PHYSCPU_INFO_FAMILY, &family) != 0 ||
	    nvlist_lookup_int32(nvl, FM_PHYSCPU_INFO_MODEL, &model) != 0) {
		for (i = 0; i < ncpu; i++)
			nvlist_free(cpus[i]);
		umem_free(cpus, sizeof (nvlist_t *) * ncpu);
		return (-1);
	}

	(void) snprintf(ci->vendor, X86_VENDOR_STRLEN, "%s", ven);
	ci->family = family;
	ci->model = model;

	for (i = 0; i < ncpu; i++)
		nvlist_free(cpus[i]);
	umem_free(cpus, sizeof (nvlist_t *) * ncpu);
	return (0);
}
#endif

static uint32_t
get_cap_conf(fmd_hdl_t *hdl)
{
	uint32_t fma_cap;
#if defined(__x86)
	int found = 0;
	cpu_tbl_t *cl, ci;

	if (fma_cap_cpu_info(&ci) == 0) {
		fmd_hdl_debug(hdl, "Got CPU info: vendor=%s, family=%d, "
		    "model=%d\n", ci.vendor, ci.family, ci.model);
		for (cl = fma_cap_list; cl->propname != NULL; cl++) {
			if (strncmp(ci.vendor, cl->vendor,
			    X86_VENDOR_STRLEN) == 0 &&
			    ci.family == cl->family &&
			    ci.model == cl->model) {
				found++;
				break;
			}
		}
	} else {
		fmd_hdl_debug(hdl, "Failed to get CPU info");
	}

	if (found) {
		fma_cap = fmd_prop_get_int32(hdl, cl->propname);
		fmd_hdl_debug(hdl, "Found property, FMA capability=0x%x",
		    fma_cap);
	} else {
#endif
		fma_cap = fmd_prop_get_int32(hdl, "default_fma_cap");
		fmd_hdl_debug(hdl, "Didn't find FMA capability property, "
		    "use default=0x%x", fma_cap);
#if defined(__x86)
	}
#endif

	return (fma_cap);
}

static void
send_fma_cap_to_ilom(fmd_hdl_t *hdl, uint32_t fma_cap)
{
	int error;
	char *msg;
	ipmi_handle_t *ipmi_hdl;
	ipmi_cmd_t cmd;
	uint8_t oem_data[OEM_DATA_LENGTH];

	if ((ipmi_hdl = ipmi_open(&error, &msg, IPMI_TRANSPORT_BMC, NULL))
	    == NULL) {
		/*
		 * If /dev/ipmi0 doesn't exist on the system, then return
		 * without doing anything.
		 */
		if (error != EIPMI_BMC_OPEN_FAILED)
			fmd_hdl_abort(hdl, "Failed to initialize IPMI "
			    "connection: %s\n", msg);
		fmd_hdl_debug(hdl, "Failed: no IPMI connection present");
		return;
	}

	/*
	 * Check if it's Sun ILOM
	 */
	if (check_sunoem(ipmi_hdl) != 0) {
		fmd_hdl_debug(hdl, "Service Processor does not run "
		    "Sun ILOM");
		ipmi_close(ipmi_hdl);
		return;
	}

	oem_data[0] = CORE_TUNNEL_SUBCMD_HOSTFMACAP;
	oem_data[1] = VERSION;
	oem_data[2] = fma_cap;

	cmd.ic_netfn = IPMI_NETFN_OEM;
	cmd.ic_lun = 0;
	cmd.ic_cmd = CMD_SUNOEM_CORE_TUNNEL;
	cmd.ic_dlen = OEM_DATA_LENGTH;
	cmd.ic_data = oem_data;

	if (ipmi_send(ipmi_hdl, &cmd) == NULL) {
		fmd_hdl_debug(hdl, "Failed to send Solaris FMA "
		    "capability to ilom: %s", ipmi_errmsg(ipmi_hdl));
	}

	ipmi_close(ipmi_hdl);
}

/*ARGSUSED*/
static void
fma_cap_init(fmd_hdl_t *hdl, id_t id, void *data)
{
	uint32_t	fma_cap;

	fma_cap = get_cap_conf(hdl);
	send_fma_cap_to_ilom(hdl, fma_cap);

	fmd_hdl_unregister(hdl);
}

static const fmd_hdl_ops_t fmd_ops = {
	NULL,		/* fmdo_recv */
	fma_cap_init,	/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
	NULL,		/* fmdo_send */
	NULL,		/* fmdo_topo */
};

static const fmd_prop_t fmd_props[] = {
	{ "interval", FMD_TYPE_TIME, "1s" },
	{ "default_fma_cap", FMD_TYPE_UINT32, "0x3" },
	{ "NHMEP_fma_cap", FMD_TYPE_UINT32, "0x3" },
	{ "NHMEX_fma_cap", FMD_TYPE_UINT32, "0x2" },
	{ "WSMEP_fma_cap", FMD_TYPE_UINT32, "0x3" },
	{ "INTLN_fma_cap", FMD_TYPE_UINT32, "0x2" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"FMA Capability Messenger", "1.1", &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	char isa[8];

	/*
	 * For now the module only sends message to ILOM on i386 platforms
	 * till CR 6933053 is fixed. Module unregister may cause etm module
	 * core dump due to 6933053.
	 */
	if ((sysinfo(SI_ARCHITECTURE, isa, sizeof (isa)) == -1) ||
	    (strncmp(isa, "i386", 4) != 0))
		return;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return;

	/*
	 * Setup the timer.
	 */
	(void) fmd_timer_install(hdl, NULL, NULL, 2000000000ULL);
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
}
