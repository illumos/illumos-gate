/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2017 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * nvmeadm -- NVMe administration utility
 *
 * nvmeadm [-v] [-d] [-h] <command> [<ctl>[/<ns>][,...]] [args]
 * commands:	list
 *		identify
 *		list-logpages [logpage name],...
 *		get-logpage <logpage name>
 *		get-features <feature>[,...]
 *		format ...
 *		secure-erase ...
 *		detach ...
 *		attach ...
 *		list-firmware ...
 *		load-firmware ...
 *		commit-firmware ...
 *		activate-firmware ...
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <ctype.h>
#include <err.h>
#include <sys/sunddi.h>
#include <libdevinfo.h>
#include <sys/sysmacros.h>

#include <sys/nvme.h>

#include "nvmeadm.h"

/*
 * Assertions to make sure that we've properly captured various aspects of the
 * packed structures and haven't broken them during updates.
 */
CTASSERT(sizeof (nvme_identify_ctrl_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_oacs) == 256);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_sqes) == 512);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_oncs) == 520);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_subnqn) == 768);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_nvmof) == 1792);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_psd) == 2048);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_vs) == 3072);

CTASSERT(sizeof (nvme_identify_nsid_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_nsid_t, id_fpi) == 32);
CTASSERT(offsetof(nvme_identify_nsid_t, id_anagrpid) == 92);
CTASSERT(offsetof(nvme_identify_nsid_t, id_nguid) == 104);
CTASSERT(offsetof(nvme_identify_nsid_t, id_lbaf) == 128);
CTASSERT(offsetof(nvme_identify_nsid_t, id_vs) == 384);

CTASSERT(sizeof (nvme_identify_nsid_list_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(sizeof (nvme_identify_ctrl_list_t) == NVME_IDENTIFY_BUFSIZE);

CTASSERT(sizeof (nvme_identify_primary_caps_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_primary_caps_t, nipc_vqfrt) == 32);
CTASSERT(offsetof(nvme_identify_primary_caps_t, nipc_vifrt) == 64);

CTASSERT(sizeof (nvme_nschange_list_t) == 4096);

#define	NVMEADM_F_CTRL	1
#define	NVMEADM_F_NS	2
#define	NVMEADM_F_BOTH	(NVMEADM_F_CTRL | NVMEADM_F_NS)

static void usage(const nvmeadm_cmd_t *);
static bool nvmeadm_ctrl_disc_cb(nvme_t *, const nvme_ctrl_disc_t *, void *);

static int do_list(const nvme_process_arg_t *);
static int do_identify(const nvme_process_arg_t *);
static int do_identify_ctrl(const nvme_process_arg_t *);
static int do_identify_ns(const nvme_process_arg_t *);
static int do_list_logs(const nvme_process_arg_t *);
static int do_get_logpage_fwslot(const nvme_process_arg_t *);
static int do_get_logpage(const nvme_process_arg_t *);
static int do_list_features(const nvme_process_arg_t *);
static boolean_t do_get_feat_intr_vect(const nvme_process_arg_t *,
    const nvme_feat_disc_t *, const nvmeadm_feature_t *);
static boolean_t do_get_feat_temp_thresh(const nvme_process_arg_t *,
    const nvme_feat_disc_t *, const nvmeadm_feature_t *);
static int do_get_features(const nvme_process_arg_t *);
static int do_format(const nvme_process_arg_t *);
static int do_secure_erase(const nvme_process_arg_t *);
static int do_attach(const nvme_process_arg_t *);
static int do_detach(const nvme_process_arg_t *);
static int do_firmware_load(const nvme_process_arg_t *);
static int do_firmware_commit(const nvme_process_arg_t *);
static int do_firmware_activate(const nvme_process_arg_t *);

static void optparse_list(nvme_process_arg_t *);
static void optparse_identify(nvme_process_arg_t *);
static void optparse_identify_ctrl(nvme_process_arg_t *);
static void optparse_identify_ns(nvme_process_arg_t *);
static void optparse_list_logs(nvme_process_arg_t *);
static void optparse_get_logpage(nvme_process_arg_t *);
static void optparse_list_features(nvme_process_arg_t *);
static void optparse_secure_erase(nvme_process_arg_t *);

static void usage_list(const char *);
static void usage_identify(const char *);
static void usage_identify_ctrl(const char *);
static void usage_identify_ns(const char *);
static void usage_list_logs(const char *);
static void usage_get_logpage(const char *);
static void usage_list_features(const char *);
static void usage_get_features(const char *);
static void usage_format(const char *);
static void usage_secure_erase(const char *);
static void usage_attach_detach(const char *);
static void usage_firmware_list(const char *);
static void usage_firmware_load(const char *);
static void usage_firmware_commit(const char *);
static void usage_firmware_activate(const char *);

int verbose;
int debug;

/*
 * nvmeadm Secure-erase specific options
 */
#define	NVMEADM_O_SE_CRYPTO	0x00000004

/*
 * nvmeadm identify specific options
 */
#define	NVMEADM_O_ID_NSID_LIST	0x00000008
#define	NVMEADM_O_ID_COMMON_NS	0x00000010
#define	NVMEADM_O_ID_CTRL_LIST	0x00000020
#define	NVMEADM_O_ID_DESC_LIST	0x00000040
#define	NVMEADM_O_ID_ALLOC_NS	0x00000080

/*
 * nvmeadm List specific options
 */
#define	NVMEADM_O_LS_CTRL	0x00000100

static int exitcode;

/*
 * Nvmeadm subcommand definitons.
 *
 * When adding a new subcommand, please check that the commands still
 * line up in the usage() message, and adjust the format string in
 * usage() below if necessary.
 */
static const nvmeadm_cmd_t nvmeadm_cmds[] = {
	{
		"list",
		"list controllers and namespaces",
		"  -c\t\tlist only controllers\n"
		"  -p\t\tprint parsable output\n"
		"  -o field\tselect a field for parsable output\n",
		"  model\t\tthe model name of the device\n"
		"  serial\tthe serial number of the device\n"
		"  fwrev\t\tthe device's current firmware revision\n"
		"  version\tthe device's NVMe specification version\n"
		"  capacity\tthe capacity of the device in bytes\n"
		"  instance\tthe device driver instance (e.g. nvme3)\n"
		"  unallocated\tthe amount of unallocated NVM in bytes",
		do_list, usage_list, optparse_list,
		NVMEADM_C_MULTI
	},
	{
		"identify",
		"identify controllers and/or namespaces",
		"  -C\t\tget Common Namespace Identification\n"
		"  -a\t\tget only allocated namespace information\n"
		"  -c\t\tget controller identifier list\n"
		"  -d\t\tget namespace identification descriptors list\n"
		"  -n\t\tget namespaces identifier list",
		NULL,
		do_identify, usage_identify, optparse_identify,
		NVMEADM_C_MULTI
	},
	{
		"identify-controller",
		"identify controllers",
		"  -C\t\tget Common Namespace Identification\n"
		"  -a\t\tget only allocated namespace information\n"
		"  -c\t\tget controller identifier list\n"
		"  -n\t\tget namespaces identifier list",
		NULL,
		do_identify_ctrl, usage_identify_ctrl, optparse_identify_ctrl,
		NVMEADM_C_MULTI
	},
	{
		"identify-namespace",
		"identify namespaces",
		"  -c\t\tget attached controller identifier list\n"
		"  -d\t\tget namespace identification descriptors list",
		NULL,
		do_identify_ns, usage_identify_ns, optparse_identify_ns,
		NVMEADM_C_MULTI
	},
	{
		"list-logpages",
		"list a device's supported log pages",
		"  -a\t\tprint all log pages, including unimplemented ones\n"
		"  -H\t\tomit column headers\n"
		"  -o field\tselect a field for parsable output\n"
		"  -p\t\tprint parsable output\n"
		"  -s scope\tprint logs that match the specified scopes "
		"(default is based on\n\t\tdevice)\n",
		"  device\tthe name of the controller or namespace\n"
		"  name\t\tthe name of the log page\n"
		"  desc\t\ta description of the loage page\n"
		"  scope\t\tthe valid device scopes for the log page\n"
		"  fields\tthe list of fields in the get log request that may "
		"be set or required\n\t\t(e.g. lsi, lsp, rae, etc.)\n"
		"  csi\t\tthe command set interface the log page belongs to\n"
		"  lid\t\tthe log page's numeric ID\n"
		"  impl\t\tindicates whether the device implements the log "
		"page\n"
		"  size\t\tthe size of the log page for fixed size logs\n"
		"  minsize\tthe minimum size required to determine the full "
		"log page size\n\t\tfor variable-length pages\n"
		"  sources\twhere information for this log page came from\n"
		"  kind\t\tindicates the kind of log page e.g. standard, "
		"vendor-specific,\n\t\tetc.",
		do_list_logs, usage_list_logs, optparse_list_logs,
		NVMEADM_C_MULTI
	},
	{
		"get-logpage",
		"get a log page from controllers and/or namespaces",
		"  -O file\toutput log raw binary data to a file\n",
		NULL,
		do_get_logpage, usage_get_logpage, optparse_get_logpage,
		NVMEADM_C_MULTI
	},
	{
		"list-features",
		"list a device's supported features",
		"  -a\t\tprint all features, including unsupported\n"
		"  -H\t\tomit column headers\n"
		"  -o field\tselect a field for parsable output\n"
		"  -p\t\tprint parsable output",
		"  device\tthe name of the controller or namespace\n"
		"  short\t\tthe short name of the feature\n"
		"  spec\t\tthe longer feature description from the NVMe spec\n"
		"  fid\t\tthe numeric feature ID\n"
		"  scope\t\tthe valid device scopes for the feature\n"
		"  kind\t\tindicates the kind of feature e.g. standard, "
		"vendor-specific,\n\t\tetc.\n"
		"  csi\t\tindicates the features command set interface\n"
		"  flags\t\tindicates additional properties of the feature\n"
		"  get-in\tindicates the fields that are required to get the "
		"feature\n"
		"  set-in\tindicates the fields that are required to set the "
		"feature\n"
		"  get-out\tindicates the fields the feature outputs\n"
		"  set-out\tindicates the fields the feature outputs when "
		"setting the feature\n"
		"  datalen\tindicates the length of the feature's data "
		"payload\n"
		"  impl\t\tindicates whether the device implements the "
		"feature",
		do_list_features, usage_list_features, optparse_list_features,
		NVMEADM_C_MULTI
	},
	{
		"get-features",
		"get features from controllers and/or namespaces",
		NULL,
		NULL,
		do_get_features, usage_get_features, NULL,
		NVMEADM_C_MULTI
	},
	{
		"format",
		"format namespace(s) of a controller",
		NULL,
		NULL,
		do_format, usage_format, NULL,
		NVMEADM_C_EXCL
	},
	{
		"secure-erase",
		"secure erase namespace(s) of a controller",
		"  -c  Do a cryptographic erase.",
		NULL,
		do_secure_erase, usage_secure_erase, optparse_secure_erase,
		NVMEADM_C_EXCL
	},
	{
		"detach",
		"detach blkdev(4D) from namespace(s) of a controller",
		NULL,
		NULL,
		do_detach, usage_attach_detach, NULL,
		NVMEADM_C_EXCL
	},
	{
		"attach",
		"attach blkdev(4D) to namespace(s) of a controller",
		NULL,
		NULL,
		do_attach, usage_attach_detach, NULL,
		NVMEADM_C_EXCL
	},
	{
		"list-firmware",
		"list firmware on a controller",
		NULL,
		NULL,
		do_get_logpage_fwslot, usage_firmware_list, NULL,
		0
	},
	{
		"load-firmware",
		"load firmware to a controller",
		NULL,
		NULL,
		do_firmware_load, usage_firmware_load, NULL,
		NVMEADM_C_EXCL
	},
	{
		"commit-firmware",
		"commit downloaded firmware to a slot of a controller",
		NULL,
		NULL,
		do_firmware_commit, usage_firmware_commit, NULL,
		NVMEADM_C_EXCL
	},
	{
		"activate-firmware",
		"activate a firmware slot of a controller",
		NULL,
		NULL,
		do_firmware_activate, usage_firmware_activate, NULL,
		NVMEADM_C_EXCL
	},
	{
		"wdc/e6dump",
		"dump WDC e6 diagnostic log",
		"  -o output\tspecify output file destination\n",
		NULL,
		do_wdc_e6dump, usage_wdc_e6dump, optparse_wdc_e6dump,
		0
	},
	{
		"wdc/resize",
		"change a WDC device's capacity",
		"  -g\t\tquery the device's current resized capacity\n"
		"  -s size\tset the size of a device to the specified in gb",
		NULL,
		do_wdc_resize, usage_wdc_resize, optparse_wdc_resize,
		/*
		 * We do not set NVMEADM_C_EXCL here as that is handled by the
		 * vendor unique command logic and operates based on the
		 * information we get from vuc discovery.
		 */
		0
	},
	{
		"wdc/clear-assert",
		"clear internal device assertion",
		NULL,
		NULL,
		do_wdc_clear_assert, usage_wdc_clear_assert, NULL
	},
	{
		"wdc/inject-assert",
		"inject internal device assertion",
		NULL,
		NULL,
		do_wdc_inject_assert, usage_wdc_inject_assert, NULL
	},
	{
		NULL, NULL, NULL,
		NULL, NULL, NULL, 0
	}
};

static const nvmeadm_feature_t features[] = {
	{
		.f_feature = NVME_FEAT_ARBITRATION,
		.f_print = nvme_print_feat_arbitration
	}, {
		.f_feature = NVME_FEAT_POWER_MGMT,
		.f_print = nvme_print_feat_power_mgmt
	}, {
		.f_feature = NVME_FEAT_LBA_RANGE,
		.f_print = nvme_print_feat_lba_range
	}, {
		.f_feature = NVME_FEAT_TEMPERATURE,
		.f_get = do_get_feat_temp_thresh,
		.f_print = nvme_print_feat_temperature
	}, {
		.f_feature = NVME_FEAT_ERROR,
		.f_print = nvme_print_feat_error
	}, {
		.f_feature = NVME_FEAT_WRITE_CACHE,
		.f_print = nvme_print_feat_write_cache
	}, {
		.f_feature = NVME_FEAT_NQUEUES,
		.f_print = nvme_print_feat_nqueues
	}, {
		.f_feature = NVME_FEAT_INTR_COAL,
		.f_print = nvme_print_feat_intr_coal
	}, {
		.f_feature = NVME_FEAT_INTR_VECT,
		.f_get = do_get_feat_intr_vect,
		.f_print = nvme_print_feat_intr_vect
	}, {
		.f_feature = NVME_FEAT_WRITE_ATOM,
		.f_print = nvme_print_feat_write_atom
	}, {
		.f_feature = NVME_FEAT_ASYNC_EVENT,
		.f_print = nvme_print_feat_async_event
	}, {
		.f_feature = NVME_FEAT_AUTO_PST,
		.f_print = nvme_print_feat_auto_pst
	}, {
		.f_feature = NVME_FEAT_PROGRESS,
		.f_print = nvme_print_feat_progress
	}
};

static void
nvmeadm_ctrl_vwarn(const nvme_process_arg_t *npa, const char *fmt, va_list ap)
{
	nvme_ctrl_t *ctrl = npa->npa_ctrl;

	(void) fprintf(stderr, "nvmeadm: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme: 0x%x, sys: %d)\n",
	    nvme_ctrl_errmsg(ctrl), nvme_ctrl_errtostr(npa->npa_ctrl,
	    nvme_ctrl_err(ctrl)), nvme_ctrl_err(ctrl), nvme_ctrl_syserr(ctrl));
}

static void
nvmeadm_hdl_vwarn(const nvme_process_arg_t *npa, const char *fmt, va_list ap)
{
	nvme_t *nvme = npa->npa_nvme;

	(void) fprintf(stderr, "nvmeadm: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme: 0x%x, sys: %d)\n",
	    nvme_errmsg(nvme), nvme_errtostr(nvme, nvme_err(nvme)),
	    nvme_err(nvme), nvme_syserr(nvme));
}

static void
nvmeadm_ctrl_info_vwarn(const nvme_process_arg_t *npa, const char *fmt,
    va_list ap)
{
	nvme_ctrl_info_t *info = npa->npa_ctrl_info;

	(void) fprintf(stderr, "nvmeadm: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libnvme info: 0x%x, sys: %d)\n",
	    nvme_ctrl_info_errmsg(info), nvme_ctrl_info_errtostr(info,
	    nvme_ctrl_info_err(info)), nvme_ctrl_info_err(info),
	    nvme_ctrl_info_syserr(info));
}

void
nvmeadm_warn(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_ctrl_vwarn(npa, fmt, ap);
	va_end(ap);
}

void __NORETURN
nvmeadm_fatal(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_ctrl_vwarn(npa, fmt, ap);
	va_end(ap);

	exit(-1);
}

void
nvmeadm_hdl_warn(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_hdl_vwarn(npa, fmt, ap);
	va_end(ap);
}

void __NORETURN
nvmeadm_hdl_fatal(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_hdl_vwarn(npa, fmt, ap);
	va_end(ap);

	exit(-1);
}

static void
nvmeadm_ctrl_info_warn(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_ctrl_info_vwarn(npa, fmt, ap);
	va_end(ap);
}

static void
nvmeadm_ctrl_info_fatal(const nvme_process_arg_t *npa, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	nvmeadm_ctrl_info_vwarn(npa, fmt, ap);
	va_end(ap);

	exit(-1);
}

boolean_t
nvme_version_check(const nvme_process_arg_t *npa, const nvme_version_t *vers)
{
	return (nvme_vers_atleast(npa->npa_version, vers) ? B_TRUE : B_FALSE);
}

/*
 * Because nvmeadm operates on a series of NVMe devices for several commands,
 * here we need to clean up everything that we allocated for this device so we
 * can prepare for the next.
 */
static void
nvmeadm_cleanup_npa(nvme_process_arg_t *npa)
{
	npa->npa_idctl = NULL;
	npa->npa_version = NULL;

	if (npa->npa_excl) {
		if (npa->npa_ns != NULL) {
			nvme_ns_unlock(npa->npa_ns);
		} else if (npa->npa_ctrl != NULL) {
			nvme_ctrl_unlock(npa->npa_ctrl);
		}
	}

	if (npa->npa_ns_info != NULL) {
		nvme_ns_info_free(npa->npa_ns_info);
		npa->npa_ns_info = NULL;
	}

	if (npa->npa_ctrl_info != NULL) {
		nvme_ctrl_info_free(npa->npa_ctrl_info);
		npa->npa_ctrl_info = NULL;
	}

	if (npa->npa_ns != NULL) {
		nvme_ns_fini(npa->npa_ns);
		npa->npa_ns = NULL;
	}

	if (npa->npa_ctrl != NULL) {
		nvme_ctrl_fini(npa->npa_ctrl);
		npa->npa_ctrl = NULL;
	}
}

/*
 * Determine if a command requires a controller or namespace write lock. If so
 * we first attempt to grab it non-blocking and then if that fails, we'll warn
 * that we may be blocking for the lock so that way the user has a chance to do
 * something and can cancel it.
 */
static void
nvmeadm_excl(const nvme_process_arg_t *npa, nvme_lock_level_t level)
{
	bool ret;
	nvme_lock_flags_t flags = NVME_LOCK_F_DONT_BLOCK;

	if (npa->npa_ns != NULL) {
		ret = nvme_ns_lock(npa->npa_ns, level, flags);
	} else {
		ret = nvme_ctrl_lock(npa->npa_ctrl, level, flags);
	}

	if (ret) {
		return;
	}

	if (nvme_ctrl_err(npa->npa_ctrl) != NVME_ERR_LOCK_WOULD_BLOCK) {
		nvmeadm_fatal(npa, "failed to acquire lock on %s",
		    npa->npa_name);
	}

	(void) fprintf(stderr, "Waiting on contended %s lock on %s...",
	    npa->npa_ns != NULL ? "namespace": "controller", npa->npa_name);
	(void) fflush(stderr);

	flags &= ~NVME_LOCK_F_DONT_BLOCK;
	if (npa->npa_ns != NULL) {
		ret = nvme_ns_lock(npa->npa_ns, level, flags);
	} else {
		ret = nvme_ctrl_lock(npa->npa_ctrl, level, flags);
	}

	if (!ret) {
		nvmeadm_fatal(npa, "failed to acquire lock on %s",
		    npa->npa_name);
	}

	(void) fprintf(stderr, " acquired\n");
}

/*
 * Most of nvmeadm was written before the existence of libnvme and always had
 * things like the identify controller or namespace information sitting around.
 * As such we try to grab all this in one place for it. Note, regardless if this
 * succeeds or fails, our callers will still call nvmeadm_cleanup_npa() so we
 * don't need to clean up the various libnvme objects.
 */
static boolean_t
nvmeadm_open_dev(nvme_process_arg_t *npa)
{
	if (!nvme_ctrl_ns_init(npa->npa_nvme, npa->npa_name, &npa->npa_ctrl,
	    &npa->npa_ns)) {
		nvmeadm_hdl_warn(npa, "failed to open '%s'", npa->npa_name);
		exitcode = -1;
		return (B_FALSE);
	}

	/*
	 * Several commands expect to be able to access the controller's
	 * information snapshot. Grab that now for it and the namespace if it
	 * exists.
	 */
	if (!nvme_ctrl_info_snap(npa->npa_ctrl, &npa->npa_ctrl_info)) {
		nvmeadm_warn(npa, "failed to get controller info for %s",
		    npa->npa_ctrl_name);
		exitcode = -1;
		return (B_FALSE);
	}

	if (npa->npa_ns != NULL && !nvme_ns_info_snap(npa->npa_ns,
	    &npa->npa_ns_info)) {
		nvmeadm_warn(npa, "failed to get namespace info for %s",
		    npa->npa_name);
		exitcode = -1;
		return (B_FALSE);
	}

	/*
	 * Snapshot data the rest of the command has fairly ingrained.
	 */
	npa->npa_version = nvme_ctrl_info_version(npa->npa_ctrl_info);
	npa->npa_idctl = nvme_ctrl_info_identify(npa->npa_ctrl_info);

	/*
	 * If this command has requested exclusive access, proceed to grab that
	 * before we continue.
	 */
	if (npa->npa_excl) {
		nvmeadm_excl(npa, NVME_LOCK_L_WRITE);
	}

	return (B_TRUE);
}

static bool
nvmeadm_ctrl_disc_cb(nvme_t *nvme, const nvme_ctrl_disc_t *disc, void *arg)
{
	nvme_process_arg_t *npa = arg;
	di_node_t di = nvme_ctrl_disc_devi(disc);
	char name[128];

	(void) snprintf(name, sizeof (name), "%s%d", di_driver_name(di),
	    di_instance(di));
	npa->npa_name = name;
	npa->npa_ctrl_name = name;

	if (nvmeadm_open_dev(npa)) {
		if (npa->npa_cmd->c_func(npa) != 0) {
			exitcode = -1;
		}
	}

	nvmeadm_cleanup_npa(npa);
	return (true);
}

int
main(int argc, char **argv)
{
	int c;
	const nvmeadm_cmd_t *cmd;
	nvme_process_arg_t npa = { 0 };
	int help = 0;
	char *ctrl = NULL;

	while ((c = getopt(argc, argv, "dhv")) != -1) {
		switch (c) {
		case 'd':
			debug++;
			break;

		case 'v':
			verbose++;
			break;

		case 'h':
			help++;
			break;

		case '?':
			usage(NULL);
			exit(-1);
		}
	}

	if (optind == argc) {
		usage(NULL);
		if (help)
			exit(0);
		else
			exit(-1);
	}

	/* Look up the specified command in the command table. */
	for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++)
		if (strcmp(cmd->c_name, argv[optind]) == 0)
			break;

	if (cmd->c_name == NULL) {
		usage(NULL);
		exit(-1);
	}

	if (help) {
		usage(cmd);
		exit(0);
	}

	npa.npa_nvme = nvme_init();
	if (npa.npa_nvme == NULL) {
		err(-1, "failed to initialize libnvme");
	}
	npa.npa_cmd = cmd;
	npa.npa_excl = ((cmd->c_flags & NVMEADM_C_EXCL) != 0);

	optind++;

	/*
	 * Store the remaining arguments for use by the command. Give the
	 * command a chance to process the options across the board before going
	 * into each controller.
	 */
	npa.npa_argc = argc - optind;
	npa.npa_argv = &argv[optind];

	if (cmd->c_optparse != NULL) {
		optind = 0;
		cmd->c_optparse(&npa);
		npa.npa_argc -= optind;
		npa.npa_argv += optind;
	}

	/*
	 * All commands but "list" require a ctl/ns argument. However, this
	 * should not be passed through to the command in its subsequent
	 * arguments.
	 */
	if (npa.npa_argc == 0 && cmd->c_func != do_list) {
		warnx("missing controller/namespace name");
		usage(cmd);
		exit(-1);
	}

	if (npa.npa_argc > 0) {
		ctrl = npa.npa_argv[0];
		npa.npa_argv++;
		npa.npa_argc--;
	} else {
		if (!nvme_ctrl_discover(npa.npa_nvme, nvmeadm_ctrl_disc_cb,
		    &npa)) {
			nvmeadm_hdl_fatal(&npa, "failed to walk controllers");
		}
		exit(exitcode);
	}

	/*
	 * Make sure we're not running commands on multiple controllers that
	 * aren't allowed to do that.
	 */
	if (ctrl != NULL && strchr(ctrl, ',') != NULL &&
	    (cmd->c_flags & NVMEADM_C_MULTI) == 0) {
		warnx("%s not allowed on multiple controllers",
		    cmd->c_name);
		usage(cmd);
		exit(-1);
	}

	/*
	 * Get controller/namespace arguments and run command.
	 */
	while ((npa.npa_name = strsep(&ctrl, ",")) != NULL) {
		char *ctrl_name, *slash;

		/*
		 * We may be given just a controller as an argument or a
		 * controller and a namespace as an argument. Parts of the
		 * commands want to know what controller they're referring to
		 * even if the overall argument was for a namespace. So we
		 * always dup the argument and try to make the controller out of
		 * it.
		 */
		ctrl_name = strdup(npa.npa_name);
		if (ctrl_name == NULL) {
			err(-1, "failed to duplicate NVMe controller/namespace "
			    "name");
		}
		if ((slash = strchr(ctrl_name, '/')) != NULL)
			*slash = '\0';
		npa.npa_ctrl_name = ctrl_name;

		if (nvmeadm_open_dev(&npa)) {
			if (npa.npa_cmd->c_func(&npa) != 0) {
				exitcode = -1;
			}
		}

		nvmeadm_cleanup_npa(&npa);
		free(ctrl_name);
	}

	exit(exitcode);
}

static void
nvme_oferr(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(-1, fmt, ap);
}

static void
usage(const nvmeadm_cmd_t *cmd)
{
	const char *progname = getprogname();

	(void) fprintf(stderr, "usage:\n");
	(void) fprintf(stderr, "  %s -h %s\n", progname,
	    cmd != NULL ? cmd->c_name : "[<command>]");
	(void) fprintf(stderr, "  %s [-dv] ", progname);

	if (cmd != NULL) {
		cmd->c_usage(cmd->c_name);
	} else {
		(void) fprintf(stderr,
		    "<command> <ctl>[/<ns>][,...] [<args>]\n");
		(void) fprintf(stderr,
		    "\n  Manage NVMe controllers and namespaces.\n");
		(void) fprintf(stderr, "\ncommands:\n");

		for (cmd = &nvmeadm_cmds[0]; cmd->c_name != NULL; cmd++) {
			/*
			 * The longest nvmeadm subcommand is 19 characters long.
			 * The format string needs to be updated every time a
			 * longer subcommand is added.
			 */
			(void) fprintf(stderr, "  %-19s - %s\n",
			    cmd->c_name, cmd->c_desc);
		}
	}
	(void) fprintf(stderr, "\n%s flags:\n"
	    "  -h\t\tprint usage information\n"
	    "  -d\t\tprint information useful for debugging %s\n"
	    "  -v\t\tprint verbose information\n",
	    progname, progname);

	if (cmd != NULL && cmd->c_flagdesc != NULL) {
		(void) fprintf(stderr, "\n%s %s flags:\n",
		    progname, cmd->c_name);
		(void) fprintf(stderr, "%s\n", cmd->c_flagdesc);
	}

	if (cmd != NULL && cmd->c_fielddesc != NULL) {
		(void) fprintf(stderr, "\n%s %s valid fields:\n",
		    progname, cmd->c_name);
		(void) fprintf(stderr, "%s\n", cmd->c_fielddesc);
	}
}

char *
nvme_dskname(di_node_t ctrl, const char *bd_addr)
{
	di_dim_t dim;
	char *diskname = NULL;

	dim = di_dim_init();
	if (dim == NULL) {
		err(-1, "failed to initialize devinfo minor translation");
	}

	for (di_node_t child = di_child_node(ctrl); child != DI_NODE_NIL;
	    child = di_sibling_node(child)) {
		char *disk_ctd, *path = NULL;
		const char *addr = di_bus_addr(child);
		if (addr == NULL)
			continue;

		if (strcmp(addr, bd_addr) != 0)
			continue;

		path = di_dim_path_dev(dim, di_driver_name(child),
		    di_instance(child), "c");

		/*
		 * Error out if we didn't get a path, or if it's too short for
		 * the following operations to be safe.
		 */
		if (path == NULL || strlen(path) < 2) {
			errx(-1, "failed to get a valid minor path");
		}

		/* Chop off 's0' and get everything past the last '/' */
		path[strlen(path) - 2] = '\0';
		disk_ctd = strrchr(path, '/');
		if (disk_ctd == NULL) {
			errx(-1, "encountered malformed minor path: %s", path);
		}

		diskname = strdup(++disk_ctd);
		if (diskname == NULL) {
			err(-1, "failed to duplicate disk path");
		}

		free(path);
		break;
	}

	di_dim_fini(dim);
	return (diskname);
}

static void
usage_list(const char *c_name)
{
	(void) fprintf(stderr, "%s "
	    "[-c] [-p -o field[,...]] [<ctl>[/<ns>][,...]\n\n"
	    "  List NVMe controllers and their namespaces. If no "
	    "controllers and/or name-\n  spaces are specified, all "
	    "controllers and namespaces in the system will be\n  "
	    "listed.\n", c_name);
}

static void
optparse_list(nvme_process_arg_t *npa)
{
	int c;
	uint_t oflags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	const ofmt_field_t *ofmt = nvmeadm_list_nsid_ofmt;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":co:p")) != -1) {
		switch (c) {
		case 'c':
			npa->npa_cmdflags |= NVMEADM_O_LS_CTRL;
			ofmt = nvmeadm_list_ctrl_ofmt;
			break;
		case 'o':
			fields = optarg;
			break;

		case 'p':
			parse = B_TRUE;
			oflags |= OFMT_PARSABLE;
			break;

		case '?':
			errx(-1, "unknown option: -%c", optopt);

		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (fields != NULL && !parse) {
		errx(-1, "-o can only be used when in parsable mode (-p)");
	}

	if (parse && fields == NULL) {
		errx(-1, "parsable mode (-p) requires one to specify output "
		    "fields with -o");
	}

	if (parse) {
		ofmt_status_t oferr;

		oferr = ofmt_open(fields, ofmt, oflags, 0,
		    &npa->npa_ofmt);
		ofmt_check(oferr, B_TRUE, npa->npa_ofmt, nvme_oferr, warnx);
	}
}

static void
do_list_nsid(const nvme_process_arg_t *npa, nvme_ctrl_info_t *ctrl,
    nvme_ns_info_t *ns)
{
	const char *bd_addr, *disk = NULL;
	char *disk_path = NULL;
	di_node_t ctrl_devi;

	switch (nvme_ns_info_level(ns)) {
	case NVME_NS_DISC_F_ALL:
		disk = "unallocated";
		break;
	case NVME_NS_DISC_F_ALLOCATED:
		disk = "inactive";
		break;
	case NVME_NS_DISC_F_ACTIVE:
		disk = "ignored";
		break;
	case NVME_NS_DISC_F_NOT_IGNORED:
		disk = "unattached";
		break;
	case NVME_NS_DISC_F_BLKDEV:
		disk = "unknown";
		if (nvme_ns_info_bd_addr(ns, &bd_addr) &&
		    nvme_ctrl_devi(npa->npa_ctrl, &ctrl_devi)) {
			disk_path = nvme_dskname(ctrl_devi, bd_addr);
			disk = disk_path;
		}
		break;
	}

	if (npa->npa_ofmt != NULL) {
		nvmeadm_list_ofmt_arg_t oarg = { 0 };

		oarg.nloa_name = npa->npa_ctrl_name;
		oarg.nloa_ctrl = ctrl;
		oarg.nloa_ns = ns;
		oarg.nloa_disk = disk_path;

		ofmt_print(npa->npa_ofmt, &oarg);
	} else {
		(void) printf("  %s/%u (%s)", npa->npa_ctrl_name,
		    nvme_ns_info_nsid(ns), disk);
		if (nvme_ns_info_level(ns) >= NVME_NS_DISC_F_ACTIVE) {
			(void) printf(": ");
			nvme_print_nsid_summary(ns);
		} else {
			(void) printf("\n");
		}
	}

	free(disk_path);
}

static int
do_list(const nvme_process_arg_t *npa)
{
	nvme_ctrl_info_t *info = NULL;
	nvme_ns_iter_t *iter = NULL;
	nvme_iter_t ret;
	const nvme_ns_disc_t *disc;
	nvme_ns_disc_level_t level;
	int rv = -1;

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if (!nvme_ctrl_info_snap(npa->npa_ctrl, &info)) {
		nvmeadm_warn(npa, "failed to get controller information for %s",
		    npa->npa_ctrl_name);
		return (-1);
	}

	if (npa->npa_ofmt == NULL) {
		(void) printf("%s: ", npa->npa_ctrl_name);
		nvme_print_ctrl_summary(info);
	} else if ((npa->npa_cmdflags & NVMEADM_O_LS_CTRL) != 0) {
		nvmeadm_list_ofmt_arg_t oarg = { 0 };
		oarg.nloa_name = npa->npa_ctrl_name;
		oarg.nloa_ctrl = info;

		ofmt_print(npa->npa_ofmt, &oarg);
	}

	if ((npa->npa_cmdflags & NVMEADM_O_LS_CTRL) != 0) {
		rv = 0;
		goto out;
	}

	/*
	 * Check if we were given an explicit namespace as an argument. If so,
	 * we always list it and don't need to do discovery.
	 */
	if (npa->npa_ns != NULL) {
		nvme_ns_info_t *ns_info;

		if (!nvme_ns_info_snap(npa->npa_ns, &ns_info)) {
			nvmeadm_warn(npa, "failed to get namespace "
			    "information for %s", npa->npa_name);
			goto out;
		}

		do_list_nsid(npa, info, ns_info);
		nvme_ns_info_free(ns_info);
		rv = 0;
		goto out;
	}

	if (verbose) {
		level = NVME_NS_DISC_F_ALL;
	} else {
		level = NVME_NS_DISC_F_NOT_IGNORED;
	}

	if (!nvme_ns_discover_init(npa->npa_ctrl, level, &iter)) {
		nvmeadm_warn(npa, "failed to iterate namespaces on %s",
		    npa->npa_ctrl_name);
		goto out;
	}

	while ((ret = nvme_ns_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		nvme_ns_info_t *ns_info;
		uint32_t nsid = nvme_ns_disc_nsid(disc);

		if (!nvme_ctrl_ns_info_snap(npa->npa_ctrl, nsid, &ns_info)) {
			nvmeadm_warn(npa, "failed to get namespace "
			    "information for %s/%u", npa->npa_ctrl_name, nsid);
			exitcode = -1;
			continue;
		}

		do_list_nsid(npa, info, ns_info);
		nvme_ns_info_free(ns_info);
	}

	nvme_ns_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		nvmeadm_warn(npa, "failed to iterate all namespaces on %s",
		    npa->npa_ctrl_name);
	} else {
		rv = 0;
	}

out:
	nvme_ctrl_info_free(info);
	return (rv);
}

static void
optparse_identify_ctrl(nvme_process_arg_t *npa)
{
	int c;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":Cacn")) != -1) {
		switch (c) {
		case 'C':
			npa->npa_cmdflags |= NVMEADM_O_ID_COMMON_NS;
			break;

		case 'a':
			npa->npa_cmdflags |= NVMEADM_O_ID_ALLOC_NS;
			break;

		case 'c':
			npa->npa_cmdflags |= NVMEADM_O_ID_CTRL_LIST;
			break;

		case 'n':
			npa->npa_cmdflags |= NVMEADM_O_ID_NSID_LIST;
			break;

		case '?':
			errx(-1, "unknown option: -%c", optopt);

		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}
}

static void
usage_identify_ctrl(const char *c_name)
{
	(void) fprintf(stderr, "%s [-C | -c | [-a] -n] <ctl>[,...]\n\n"
	    "  Print detailed information about the specified NVMe "
	    "controllers.\n", c_name);
}

static int
do_identify_ctrl(const nvme_process_arg_t *npa)
{
	boolean_t alloc = B_FALSE;

	if (npa->npa_ns != NULL)
		errx(-1, "identify-controller cannot be used on namespaces");

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_COMMON_NS) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_COMMON_NS) {
		errx(-1, "-C cannot be combined with other flags");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_CTRL_LIST) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_CTRL_LIST) {
		errx(-1, "-c cannot be combined with other flags");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_ALLOC_NS) != 0 &&
	    npa->npa_cmdflags !=
	    (NVMEADM_O_ID_ALLOC_NS | NVMEADM_O_ID_NSID_LIST)) {
		errx(-1, "-a can only be used together with -n");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_ALLOC_NS) != 0) {
		alloc = B_TRUE;
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_COMMON_NS) != 0) {
		const nvme_identify_nsid_t *idns;

		if (!nvme_ctrl_info_common_ns(npa->npa_ctrl_info, &idns)) {
			nvmeadm_ctrl_info_warn(npa, "failed to get common "
			    "namespace information for %s", npa->npa_name);
			return (-1);
		}

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_nsid(idns, npa->npa_version);
	} else if ((npa->npa_cmdflags & NVMEADM_O_ID_NSID_LIST) != 0) {
		const char *caption;
		uint32_t cns;
		nvme_identify_nsid_list_t *idnslist;
		nvme_id_req_t *req;

		if (alloc) {
			caption = "Identify Allocated Namespace List";
			cns = NVME_IDENTIFY_NSID_ALLOC_LIST;
		} else {
			caption = "Identify Active Namespace List";
			cns = NVME_IDENTIFY_NSID_LIST;
		}

		if ((idnslist = malloc(NVME_IDENTIFY_BUFSIZE)) == NULL) {
			err(-1, "failed to allocate identify buffer size");
		}

		if (!nvme_id_req_init_by_cns(npa->npa_ctrl, NVME_CSI_NVM, cns,
		    &req)) {
			nvmeadm_fatal(npa, "failed to initialize %s request",
			    caption);
		}

		/*
		 * Always set the NSID for these requests to NSID 0 so that way
		 * we can start the list at the beginning. When we encounter
		 * devices with more than 1024 NSIDs then we'll need to issue
		 * additional requests.
		 */
		if (!nvme_id_req_set_nsid(req, 0) ||
		    !nvme_id_req_set_output(req, idnslist,
		    NVME_IDENTIFY_BUFSIZE)) {
			nvmeadm_fatal(npa, "failed to set required fields for "
			    "identify request");
		}

		if (!nvme_id_req_exec(req)) {
			nvmeadm_fatal(npa, "failed to execute identify "
			    "request");
		}
		nvme_id_req_fini(req);

		(void) printf("%s: ", npa->npa_name);

		nvme_print_identify_nsid_list(caption, idnslist);
		free(idnslist);
	} else if ((npa->npa_cmdflags & NVMEADM_O_ID_CTRL_LIST) != 0) {
		nvme_identify_ctrl_list_t *ctlist;
		nvme_id_req_t *req;

		if ((ctlist = malloc(NVME_IDENTIFY_BUFSIZE)) == NULL) {
			err(-1, "failed to allocate identify buffer size");
		}

		if (!nvme_id_req_init_by_cns(npa->npa_ctrl, NVME_CSI_NVM,
		    NVME_IDENTIFY_CTRL_LIST, &req)) {
			nvmeadm_fatal(npa, "failed to initialize identify "
			    "request");
		}

		if (!nvme_id_req_set_ctrlid(req, 0) ||
		    !nvme_id_req_set_output(req, ctlist,
		    NVME_IDENTIFY_BUFSIZE)) {
			nvmeadm_fatal(npa, "failed to set required fields for "
			    "identify request");
		}
		if (!nvme_id_req_exec(req)) {
			nvmeadm_fatal(npa, "failed to execute identify "
			    "request");
		}
		nvme_id_req_fini(req);

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_ctrl_list("Identify Controller List",
		    ctlist);
		free(ctlist);
	} else {
		uint32_t mpsmin;

		if (!nvme_ctrl_info_pci_mps_min(npa->npa_ctrl_info,
		    &mpsmin)) {
			nvmeadm_ctrl_info_fatal(npa, "failed to get minimum "
			    "memory page size");
		}

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_ctrl(npa->npa_idctl, mpsmin,
		    npa->npa_version);
	}

	return (0);
}

static void
optparse_identify_ns(nvme_process_arg_t *npa)
{
	int c;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":cd")) != -1) {
		switch (c) {
		case 'c':
			npa->npa_cmdflags |= NVMEADM_O_ID_CTRL_LIST;
			break;

		case 'd':
			npa->npa_cmdflags |= NVMEADM_O_ID_DESC_LIST;
			break;

		case '?':
			errx(-1, "unknown option: -%c", optopt);

		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}
}

static void
usage_identify_ns(const char *c_name)
{
	(void) fprintf(stderr, "%s [-c | -d ] <ctl>/<ns>[,...]\n\n"
	    "  Print detailed information about the specified NVMe "
	    "namespaces.\n", c_name);
}

static int
do_identify_ns(const nvme_process_arg_t *npa)
{
	uint32_t nsid;

	if (npa->npa_ns == NULL)
		errx(-1, "identify-namespace cannot be used on controllers");

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_CTRL_LIST) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_CTRL_LIST) {
		errx(-1, "-c cannot be combined with other flags");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_DESC_LIST) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_DESC_LIST) {
		errx(-1, "-d cannot be combined with other flags");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_ALLOC_NS) != 0) {
		errx(-1, "-a cannot be used on namespaces");
	}

	nsid = nvme_ns_info_nsid(npa->npa_ns_info);

	if ((npa->npa_cmdflags & NVMEADM_O_ID_CTRL_LIST) != 0) {
		nvme_identify_ctrl_list_t *ctlist;
		nvme_id_req_t *req;

		if ((ctlist = malloc(NVME_IDENTIFY_BUFSIZE)) == NULL) {
			err(-1, "failed to allocate identify buffer size");
		}

		if (!nvme_id_req_init_by_cns(npa->npa_ctrl, NVME_CSI_NVM,
		    NVME_IDENTIFY_NSID_CTRL_LIST, &req)) {
			nvmeadm_fatal(npa, "failed to initialize identify "
			    "request");
		}

		if (!nvme_id_req_set_nsid(req, nsid) ||
		    !nvme_id_req_set_ctrlid(req, 0) ||
		    !nvme_id_req_set_output(req, ctlist,
		    NVME_IDENTIFY_BUFSIZE)) {
			nvmeadm_fatal(npa, "failed to set required fields for "
			    "identify request");
		}

		if (!nvme_id_req_exec(req)) {
			nvmeadm_fatal(npa, "failed to execute identify "
			    "request");
		}
		nvme_id_req_fini(req);

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_ctrl_list(
		    "Identify Attached Controller List", ctlist);
		free(ctlist);
	} else if ((npa->npa_cmdflags & NVMEADM_O_ID_DESC_LIST) != 0) {
		nvme_identify_nsid_desc_t *nsdesc;
		nvme_id_req_t *req;

		if ((nsdesc = malloc(NVME_IDENTIFY_BUFSIZE)) == NULL) {
			err(-1, "failed to allocate identify buffer size");
		}

		if (!nvme_id_req_init_by_cns(npa->npa_ctrl, NVME_CSI_NVM,
		    NVME_IDENTIFY_NSID_DESC, &req)) {
			nvmeadm_fatal(npa, "failed to initialize identify "
			    "request");
		}

		if (!nvme_id_req_set_nsid(req, nsid) ||
		    !nvme_id_req_set_output(req, nsdesc,
		    NVME_IDENTIFY_BUFSIZE)) {
			nvmeadm_fatal(npa, "failed to set required fields for "
			    "identify request");
		}

		if (!nvme_id_req_exec(req)) {
			nvmeadm_fatal(npa, "failed to execute identify "
			    "request");
		}
		nvme_id_req_fini(req);

		(void) printf("%s: ", npa->npa_name);
		nvme_print_identify_nsid_desc(nsdesc);
		free(nsdesc);
	} else {
		const nvme_identify_nsid_t *idns;

		(void) printf("%s: ", npa->npa_name);
		idns = nvme_ns_info_identify(npa->npa_ns_info);
		nvme_print_identify_nsid(idns, npa->npa_version);
	}

	return (0);
}

static void
optparse_identify(nvme_process_arg_t *npa)
{
	int c;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":Cacdn")) != -1) {
		switch (c) {
		case 'C':
			npa->npa_cmdflags |= NVMEADM_O_ID_COMMON_NS;
			break;

		case 'a':
			npa->npa_cmdflags |= NVMEADM_O_ID_ALLOC_NS;
			break;

		case 'c':
			npa->npa_cmdflags |= NVMEADM_O_ID_CTRL_LIST;
			break;

		case 'd':
			npa->npa_cmdflags |= NVMEADM_O_ID_DESC_LIST;
			break;

		case 'n':
			npa->npa_cmdflags |= NVMEADM_O_ID_NSID_LIST;
			break;

		case '?':
			errx(-1, "unknown option: -%c", optopt);

		case ':':
			errx(-1, "option -%c requires an argument", optopt);

		}
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_ALLOC_NS) != 0 &&
	    (npa->npa_cmdflags &
	    ~(NVMEADM_O_ID_ALLOC_NS | NVMEADM_O_ID_NSID_LIST)) != 0) {
		errx(-1, "-a can only be used alone or together with -n");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_COMMON_NS) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_COMMON_NS) {
		errx(-1, "-C cannot be combined with other flags");

	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_CTRL_LIST) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_CTRL_LIST) {
		errx(-1, "-c cannot be combined with other flags");
	}

	if ((npa->npa_cmdflags & NVMEADM_O_ID_DESC_LIST) != 0 &&
	    npa->npa_cmdflags != NVMEADM_O_ID_DESC_LIST) {
		errx(-1, "-d cannot be combined with other flags");
	}
}

static void
usage_identify(const char *c_name)
{
	(void) fprintf(stderr,
	    "%s [ -C | -c | -d | [-a] -n ] <ctl>[/<ns>][,...]\n\n"
	    "  Print detailed information about the specified NVMe "
	    "controllers and/or name-\n  spaces.\n", c_name);
}

static int
do_identify(const nvme_process_arg_t *npa)
{
	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if (npa->npa_ns != NULL) {
		if ((npa->npa_cmdflags & NVMEADM_O_ID_COMMON_NS) != 0)
			errx(-1, "-C cannot be used on namespaces");

		if ((npa->npa_cmdflags & NVMEADM_O_ID_ALLOC_NS) != 0)
			errx(-1, "-a cannot be used on namespaces");

		if ((npa->npa_cmdflags & NVMEADM_O_ID_NSID_LIST) != 0)
			errx(-1, "-n cannot be used on namespaces");

		return (do_identify_ns(npa));
	} else {
		if ((npa->npa_cmdflags & NVMEADM_O_ID_DESC_LIST) != 0)
			errx(-1, "-d cannot be used on controllers");

		return (do_identify_ctrl(npa));
	}
}

static void
optparse_list_logs(nvme_process_arg_t *npa)
{
	int c;
	uint_t oflags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	char *scope = NULL;
	ofmt_status_t oferr;
	nvmeadm_list_logs_t *nll;

	if ((nll = calloc(1, sizeof (nvmeadm_list_logs_t))) == NULL) {
		err(-1, "failed to allocate memory to track log information");
	}

	npa->npa_cmd_arg = nll;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":aHo:ps:")) != -1) {
		switch (c) {
		case 'a':
			nll->nll_unimpl = B_TRUE;
			break;
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			parse = B_TRUE;
			oflags |= OFMT_PARSABLE;
			break;
		case 's':
			scope = optarg;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (!parse) {
		oflags |= OFMT_WRAP;
	}

	if (parse && fields == NULL) {
		errx(-1, "parsable mode (-p) requires fields specified with "
		    "-o");
	}

	if (fields == NULL) {
		if (nll->nll_unimpl) {
			fields = nvmeadm_list_logs_fields_impl;
		} else {
			fields = nvmeadm_list_logs_fields;
		}
	}

	if (scope != NULL) {
		const char *str;

		while ((str = strsep(&scope, ",")) != NULL) {
			if (strcasecmp(str, "nvm") == 0) {
				nll->nll_scope |= NVME_LOG_SCOPE_NVM;
			} else if (strcasecmp(str, "ns") == 0 ||
			    strcasecmp(str, "namespace") == 0) {
				nll->nll_scope |= NVME_LOG_SCOPE_NS;
			} else if (strcasecmp(str, "ctrl") == 0 ||
			    strcasecmp(str, "controller") == 0) {
				nll->nll_scope |= NVME_LOG_SCOPE_CTRL;
			} else {
				errx(-1, "unknown scope string: '%s'; valid "
				    "values are 'nvm', 'namespace', and "
				    "'controller'", str);
			}
		}
	}

	oferr = ofmt_open(fields, nvmeadm_list_logs_ofmt, oflags, 0,
	    &npa->npa_ofmt);
	ofmt_check(oferr, B_TRUE, npa->npa_ofmt, nvme_oferr, warnx);

	if (npa->npa_argc - optind > 1) {
		nll->nll_nfilts = npa->npa_argc - optind - 1;
		nll->nll_filts = npa->npa_argv + optind + 1;
		nll->nll_used = calloc(nll->nll_nfilts, sizeof (boolean_t));
		if (nll->nll_used == NULL) {
			err(-1, "failed to allocate memory for tracking log "
			    "page filters");
		}
	}
}

static void
usage_list_logs(const char *c_name)
{
	(void) fprintf(stderr, "%s [-H] [-o field,[...] [-p]] [-s scope,[...]] "
	    "[-a]\n\t  [<ctl>[/<ns>][,...] [logpage...]\n\n"
	    "  List log pages supported by controllers or namespaces.\n",
	    c_name);
}

static boolean_t
do_list_logs_match(const nvme_log_disc_t *disc, nvmeadm_list_logs_t *nll)
{
	if (!nll->nll_unimpl && !nvme_log_disc_impl(disc)) {
		return (B_FALSE);
	}

	if (nll->nll_nfilts <= 0) {
		return (B_TRUE);
	}

	for (int i = 0; i < nll->nll_nfilts; i++) {
		if (strcmp(nvme_log_disc_name(disc), nll->nll_filts[i]) == 0) {
			nll->nll_used[i] = B_TRUE;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static int
do_list_logs(const nvme_process_arg_t *npa)
{
	nvme_log_disc_scope_t scope;
	nvme_log_iter_t *iter;
	nvme_iter_t ret;
	const nvme_log_disc_t *disc;
	nvmeadm_list_logs_t *nll = npa->npa_cmd_arg;

	if (nll->nll_scope != 0) {
		scope = nll->nll_scope;
	} else if (npa->npa_ns != NULL) {
		scope = NVME_LOG_SCOPE_NS;
	} else {
		scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NVM;
	}

	if (!nvme_log_discover_init(npa->npa_ctrl, scope, 0, &iter)) {
		nvmeadm_warn(npa, "failed to iterate logs on %s",
		    npa->npa_ctrl_name);
		return (-1);
	}

	while ((ret = nvme_log_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		if (do_list_logs_match(disc, nll)) {
			nvmeadm_list_logs_ofmt_arg_t print;

			print.nlloa_name = npa->npa_name;
			print.nlloa_disc = disc;
			ofmt_print(npa->npa_ofmt, &print);
			nll->nll_nprint++;
		}
	}

	nvme_log_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		nvmeadm_warn(npa, "failed to iterate logs on %s",
		    npa->npa_ctrl_name);
		return (-1);
	}

	for (int i = 0; i < nll->nll_nfilts; i++) {
		if (!nll->nll_used[i]) {
			warnx("log page filter '%s' did match any log pages",
			    nll->nll_filts[i]);
			exitcode = -1;
		}
	}

	if (nll->nll_nprint == 0) {
		if (nll->nll_nfilts == 0) {
			warnx("no log pages found for %s", npa->npa_name);
		}
		exitcode = -1;
	}

	return (exitcode);
}

static void
usage_get_logpage(const char *c_name)
{
	(void) fprintf(stderr, "%s [-O file] <ctl>[/<ns>][,...] <logpage>\n\n"
	    "  Print the specified log page of the specified NVMe "
	    "controllers and/or name-\n  spaces. Run nvmeadm list-logpages "
	    "for supported log pages. All devices\n support error, health, "
	    "and firmware.\n", c_name);
}

static void
usage_firmware_list(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>\n\n"
	    "  Print the log page that contains the list of firmware "
	    "images installed on the specified NVMe controller.\n", c_name);
}

static uint64_t
do_get_logpage_size(const nvme_process_arg_t *npa, nvme_log_disc_t *disc,
    nvme_log_req_t *req)
{
	uint64_t len, ret;
	void *buf;
	nvme_log_size_kind_t kind;

	kind = nvme_log_disc_size(disc, &len);
	if (kind != NVME_LOG_SIZE_K_VAR) {
		return (len);
	}

	/*
	 * We have a log with a variable length size. To determine the actual
	 * size we must actually determine the full length of this.
	 */
	if ((buf = malloc(len)) == NULL) {
		errx(-1, "failed to allocate %zu byte buffer to get log "
		    "page size", len);
	}

	if (!nvme_log_req_set_output(req, buf, len)) {
		nvmeadm_fatal(npa, "failed to set output parameters to "
		    "determine log length");
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute log request %s to "
		    "determine log length", npa->npa_argv[0]);
	}

	if (!nvme_log_disc_calc_size(disc, &ret, buf, len)) {
		errx(-1, "failed to determine full %s log length",
		    npa->npa_argv[0]);
	}

	free(buf);
	return (ret);
}

static void
do_get_logpage_dump(const void *buf, size_t len, const char *file)
{
	size_t off = 0;
	int fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 0644);

	if (fd < 0) {
		err(-1, "failed to create output file %s", file);
	}

	while (len > 0) {
		ssize_t ret = write(fd, buf + off, len - off);
		if (ret < 0) {
			err(EXIT_FAILURE, "failed to write log data to file %s "
			    "at offset %zu", file, off);
		}

		off += (size_t)ret;
		len -= (size_t)ret;
	}

	(void) close(fd);
}

static int
do_get_logpage_common(const nvme_process_arg_t *npa, const char *page)
{
	int ret = 0;
	nvme_log_disc_t *disc;
	nvme_log_req_t *req;
	nvme_log_disc_scope_t scope;
	void *buf;
	size_t toalloc;
	nvmeadm_get_logpage_t *log = npa->npa_cmd_arg;

	/*
	 * If we have enough information to identify a log-page via libnvme (or
	 * in the future take enough options to allow us to actually do this
	 * manually), then we will fetch it. If we don't know how to print it,
	 * then we'll just hex dump it for now.
	 */
	if (!nvme_log_req_init_by_name(npa->npa_ctrl, page, 0, &disc, &req)) {
		nvmeadm_fatal(npa, "could not initialize log request for %s",
		    page);
	}

	if (npa->npa_ns != NULL) {
		scope = NVME_LOG_SCOPE_NS;
	} else {
		scope = NVME_LOG_SCOPE_CTRL | NVME_LOG_SCOPE_NVM;
	}

	if ((scope & nvme_log_disc_scopes(disc)) == 0) {
		errx(-1, "log page %s does not support operating on %s", page,
		    npa->npa_ns != NULL ? "namespaces" : "controllers");
	}

	/*
	 * In the future we should add options to allow one to specify and set
	 * the fields for the lsp, lsi, etc. and set them here.
	 */

	if (npa->npa_ns != NULL) {
		uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);

		if (!nvme_log_req_set_nsid(req, nsid)) {
			nvmeadm_fatal(npa, "failed to set log request "
			    "namespace ID to 0x%x", nsid);
		}
	}

	/*
	 * The output size should be the last thing that we determine as we may
	 * need to issue a log request to figure out how much data we should
	 * actually be reading.
	 */
	toalloc = do_get_logpage_size(npa, disc, req);
	buf = malloc(toalloc);
	if (buf == NULL) {
		err(-1, "failed to allocate %zu bytes for log "
		    "request %s", toalloc, page);
	}

	if (!nvme_log_req_set_output(req, buf, toalloc)) {
		nvmeadm_fatal(npa, "failed to set output parameters");
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to execute log request %s",
		    npa->npa_argv[0]);
	}

	if (log != NULL && log->ngl_output != NULL) {
		do_get_logpage_dump(buf, toalloc, log->ngl_output);
		goto done;
	}

	(void) printf("%s: ", npa->npa_name);
	if (strcmp(page, "error") == 0) {
		size_t nlog = toalloc / sizeof (nvme_error_log_entry_t);
		nvme_print_error_log(nlog, buf, npa->npa_version);
	} else if (strcmp(page, "health") == 0) {
		nvme_print_health_log(buf, npa->npa_idctl, npa->npa_version);
	} else if (strcmp(page, "firmware") == 0) {
		nvme_print_fwslot_log(buf, npa->npa_idctl);
	} else {
		(void) printf("%s (%s)\n", nvme_log_disc_desc(disc), page);
		nvmeadm_dump_hex(buf, toalloc);
	}

done:
	free(buf);
	nvme_log_disc_free(disc);
	nvme_log_req_fini(req);

	return (ret);
}

static int
do_get_logpage_fwslot(const nvme_process_arg_t *npa)
{
	if (npa->npa_argc >= 1) {
		warnx("no additional arguments may be specified to %s",
		    npa->npa_cmd->c_name);
		usage(npa->npa_cmd);
		exit(-1);
	}

	return (do_get_logpage_common(npa, "firmware"));
}

static void
optparse_get_logpage(nvme_process_arg_t *npa)
{
	int c;
	const char *output = NULL;
	nvmeadm_get_logpage_t *log;

	if ((log = calloc(1, sizeof (nvmeadm_get_logpage_t))) == NULL) {
		err(-1, "failed to allocate memory to track log page "
		    "information");
	}

	npa->npa_cmd_arg = log;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":O:")) != -1) {
		switch (c) {
		case 'O':
			output = optarg;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	log->ngl_output = output;
}

static int
do_get_logpage(const nvme_process_arg_t *npa)
{

	if (npa->npa_argc < 1) {
		warnx("missing log page name");
		usage(npa->npa_cmd);
		exit(-1);
	}

	if (npa->npa_argc > 1) {
		warnx("only a single log page may be specified at a time");
		usage(npa->npa_cmd);
		exit(-1);
	}

	return (do_get_logpage_common(npa, npa->npa_argv[0]));
}

static void
optparse_list_features(nvme_process_arg_t *npa)
{
	int c;
	uint_t oflags = 0;
	boolean_t parse = B_FALSE;
	const char *fields = NULL;
	nvmeadm_features_t *feat;
	ofmt_status_t oferr;

	if ((feat = calloc(1, sizeof (nvmeadm_features_t))) == NULL) {
		err(-1, "failed to allocate memory to track feature "
		    "information");
	}

	npa->npa_cmd_arg = feat;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":aHo:p")) != -1) {
		switch (c) {
		case 'a':
			feat->nf_unimpl = B_TRUE;
			break;
		case 'H':
			oflags |= OFMT_NOHEADER;
			break;
		case 'o':
			fields = optarg;
			break;
		case 'p':
			parse = B_TRUE;
			oflags |= OFMT_PARSABLE;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (!parse) {
		oflags |= OFMT_WRAP;
	}

	if (parse && fields == NULL) {
		errx(-1, "parsable mode (-p) requires fields specified with "
		    "-o");
	}

	if (fields == NULL) {
		fields = nvmeadm_list_features_fields;
	}

	oferr = ofmt_open(fields, nvmeadm_list_features_ofmt, oflags, 0,
	    &npa->npa_ofmt);
	ofmt_check(oferr, B_TRUE, npa->npa_ofmt, nvme_oferr, warnx);

	if (npa->npa_argc - optind > 1) {
		feat->nf_nfilts = (uint32_t)(npa->npa_argc - optind - 1);
		feat->nf_filts = npa->npa_argv + optind + 1;
		feat->nf_used = calloc(feat->nf_nfilts, sizeof (boolean_t));
		if (feat->nf_used == NULL) {
			err(-1, "failed to allocate memory for tracking "
			    "feature filters");
		}
	}
}

static void
usage_list_features(const char *c_name)
{
	(void) fprintf(stderr, "%s [-a] [-H] [-o field,[...] [-p]] "
	    "<ctl>[/<ns>][,...]\n\t  [feature...]\n\n"
	    "  List features supported by controllers or namespaces.\n",
	    c_name);
}

static boolean_t
do_features_match(const nvme_feat_disc_t *disc, nvmeadm_features_t *nf)
{
	if (nf->nf_nfilts == 0) {
		return (B_TRUE);
	}

	for (uint32_t i = 0; i < nf->nf_nfilts; i++) {
		const char *match = nf->nf_filts[i];
		long long fid;
		const char *err;

		if (strcmp(nvme_feat_disc_short(disc), match) == 0 ||
		    strcasecmp(nvme_feat_disc_spec(disc), match) == 0) {
			nf->nf_used[i] = B_TRUE;
			return (B_TRUE);
		}

		fid = strtonumx(match, 0, UINT32_MAX, &err, 0);
		if (err == NULL && fid == nvme_feat_disc_fid(disc)) {
			nf->nf_used[i] = B_TRUE;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}


/*
 * This is a common entry point for both list-features and get-features, which
 * iterate over all features and take action for each one.
 */
typedef void (*do_features_cb_f)(const nvme_process_arg_t *,
    const nvme_feat_disc_t *);
static int
do_features(const nvme_process_arg_t *npa, nvmeadm_features_t *nf,
    do_features_cb_f func)
{
	nvme_feat_scope_t scope;
	nvme_feat_iter_t *iter;
	nvme_iter_t ret;
	const nvme_feat_disc_t *disc;

	if (npa->npa_ns != NULL) {
		scope = NVME_FEAT_SCOPE_NS;
	} else {
		scope = NVME_FEAT_SCOPE_CTRL;
	}

	if (!nvme_feat_discover_init(npa->npa_ctrl, scope, 0, &iter)) {
		nvmeadm_warn(npa, "failed to iterate features on %s",
		    npa->npa_ctrl_name);
		return (-1);
	}

	while ((ret = nvme_feat_discover_step(iter, &disc)) ==
	    NVME_ITER_VALID) {
		if (do_features_match(disc, nf)) {
			if (!nf->nf_unimpl && nvme_feat_disc_impl(disc) ==
			    NVME_FEAT_IMPL_UNSUPPORTED) {
				continue;
			}

			func(npa, disc);
			nf->nf_nprint++;
		}
	}

	nvme_feat_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		nvmeadm_warn(npa, "failed to iterate features on %s",
		    npa->npa_ctrl_name);
		return (-1);
	}

	for (uint32_t i = 0; i < nf->nf_nfilts; i++) {
		if (!nf->nf_used[i]) {
			warnx("feature filter '%s' did match any features",
			    nf->nf_filts[i]);
			exitcode = -1;
		}
	}

	if (nf->nf_nprint == 0) {
		if (nf->nf_nfilts == 0) {
			warnx("no features found for %s", npa->npa_name);
		}
		exitcode = -1;
	}

	return (exitcode);
}

static void
do_list_features_cb(const nvme_process_arg_t *npa, const nvme_feat_disc_t *disc)
{
	nvmeadm_list_features_ofmt_arg_t print;

	print.nlfoa_name = npa->npa_name;
	print.nlfoa_feat = disc;
	ofmt_print(npa->npa_ofmt, &print);
}

static int
do_list_features(const nvme_process_arg_t *npa)
{
	nvmeadm_features_t *nf = npa->npa_cmd_arg;

	return (do_features(npa, nf, do_list_features_cb));
}

static void
usage_get_features(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>][,...] [<feature>[,...]]\n\n"
	    "  Print the specified features of the specified NVMe controllers "
	    "and/or\n  namespaces. Feature support varies on the controller.\n"
	    "Run 'nvmeadm list-features <ctl>' to see supported features.\n",
	    c_name);
}

/*
 * The nvmeadm(8) get-features output has traditionally swallowed certain errors
 * for features that it considers unimplemented in tandem with the kernel. With
 * the introduction of libnvme and ioctl interface changes, the kernel no longer
 * caches information about features that are unimplemented.
 *
 * There are two cases that we currently swallow errors on and the following
 * must all be true:
 *
 * 1) We have a controller error.
 * 2) The system doesn't know whether the feature is implemented or not.
 * 3) The controller error indicates that we have an invalid field.
 *
 * There is one additional wrinkle that we are currently papering over due to
 * the history of nvmeadm swallowing errors. The error recovery feature was made
 * explicitly namespace-specific in NVMe 1.4. However, various NVMe 1.3 devices
 * will error if we ask for it without specifying a namespace. Conversely, older
 * devices will be upset if you do ask for a namespace. This case can be removed
 * once we better survey devices and come up with a heuristic for how to handle
 * this across older generations.
 *
 * If we add a single feature endpoint that gives flexibility over how the
 * feature are listed, then we should not swallow errors.
 */
static boolean_t
swallow_get_feat_err(const nvme_process_arg_t *npa,
    const nvme_feat_disc_t *disc)
{
	uint32_t sct, sc;

	if (nvme_ctrl_err(npa->npa_ctrl) != NVME_ERR_CONTROLLER) {
		return (B_FALSE);
	}

	nvme_ctrl_deverr(npa->npa_ctrl, &sct, &sc);
	if (nvme_feat_disc_impl(disc) == NVME_FEAT_IMPL_UNKNOWN &&
	    sct == NVME_CQE_SCT_GENERIC && sc == NVME_CQE_SC_GEN_INV_FLD) {
		return (B_TRUE);
	}

	if (nvme_feat_disc_fid(disc) == NVME_FEAT_ERROR &&
	    sct == NVME_CQE_SCT_GENERIC && (sc == NVME_CQE_SC_GEN_INV_FLD ||
	    sc == NVME_CQE_SC_GEN_INV_NS)) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

static boolean_t
do_get_feat_common(const nvme_process_arg_t *npa, const nvme_feat_disc_t *disc,
    uint32_t cdw11, uint32_t *cdw0, void **datap, size_t *lenp)
{
	nvme_get_feat_req_t *req = NULL;
	void *data = NULL;
	uint64_t datalen = 0;
	nvme_get_feat_fields_t fields = nvme_feat_disc_fields_get(disc);

	if (!nvme_get_feat_req_init_by_disc(npa->npa_ctrl, disc, &req)) {
		nvmeadm_warn(npa, "failed to initialize get feature request "
		    "for feature %s", nvme_feat_disc_short(disc));
		exitcode = -1;
		goto err;
	}

	if ((fields & NVME_GET_FEAT_F_CDW11) != 0 &&
	    !nvme_get_feat_req_set_cdw11(req, cdw11)) {
		nvmeadm_warn(npa, "failed to set cdw11 to 0x%x for feature %s",
		    cdw11, nvme_feat_disc_short(disc));
		exitcode = -1;
		goto err;
	}

	if ((fields & NVME_GET_FEAT_F_DATA) != 0) {
		datalen = nvme_feat_disc_data_size(disc);
		VERIFY3U(datalen, !=, 0);
		data = malloc(datalen);
		if (data == NULL) {
			err(-1, "failed to allocate %zu bytes for feature %s "
			    "data buffer", datalen, nvme_feat_disc_short(disc));
		}

		if (!nvme_get_feat_req_set_output(req, data, datalen)) {
			nvmeadm_warn(npa, "failed to set output data for "
			    "feature %s", nvme_feat_disc_short(disc));
			exitcode = -1;
			goto err;
		}
	}

	if ((fields & NVME_GET_FEAT_F_NSID) != 0) {
		uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);

		if (!nvme_get_feat_req_set_nsid(req, nsid)) {
			nvmeadm_warn(npa, "failed to set nsid to 0x%x for "
			    "feature %s", nsid, nvme_feat_disc_spec(disc));
			exitcode = -1;
			goto err;
		}
	}

	if (!nvme_get_feat_req_exec(req)) {
		if (!swallow_get_feat_err(npa, disc)) {
			nvmeadm_warn(npa, "failed to get feature %s",
			    nvme_feat_disc_spec(disc));
			exitcode = -1;
		}

		goto err;
	}

	if (!nvme_get_feat_req_get_cdw0(req, cdw0)) {
		nvmeadm_warn(npa, "failed to get cdw0 result data for %s",
		    nvme_feat_disc_spec(disc));
		goto err;
	}

	*datap = data;
	*lenp = datalen;
	nvme_get_feat_req_fini(req);
	return (B_TRUE);

err:
	free(data);
	nvme_get_feat_req_fini(req);
	return (B_FALSE);
}

static void
do_get_feat_temp_thresh_one(const nvme_process_arg_t *npa,
    const nvme_feat_disc_t *disc, const nvmeadm_feature_t *feat,
    const char *label, uint16_t tmpsel, uint16_t thsel)
{
	uint32_t cdw0;
	void *buf = NULL;
	size_t buflen;
	nvme_temp_threshold_t tt;

	tt.r = 0;
	tt.b.tt_tmpsel = tmpsel;
	tt.b.tt_thsel = thsel;

	/*
	 * The printing function treats the buffer argument as the label to
	 * print for this threshold.
	 */
	if (!do_get_feat_common(npa, disc, tt.r, &cdw0, &buf, &buflen)) {
		return;
	}

	feat->f_print(cdw0, (void *)label, 0, npa->npa_idctl,
	    npa->npa_version);
	free(buf);
}

/*
 * In NVMe 1.2, the specification allowed for up to 8 sensors to be on the
 * device and changed the main device to have a composite temperature sensor. As
 * a result, there is a set of thresholds for each sensor. In addition, they
 * added both an over-temperature and under-temperature threshold. Since most
 * devices don't actually implement all the sensors, we get the health page and
 * see which sensors have a non-zero value to determine how to proceed.
 */
static boolean_t
do_get_feat_temp_thresh(const nvme_process_arg_t *npa,
    const nvme_feat_disc_t *disc, const nvmeadm_feature_t *feat)
{
	nvme_log_req_t *req = NULL;
	nvme_log_disc_t *log_disc = NULL;
	size_t toalloc;
	void *buf = NULL;
	boolean_t ret = B_FALSE;
	const nvme_health_log_t *hlog;

	nvme_print(2, nvme_feat_disc_spec(disc), -1, NULL);
	do_get_feat_temp_thresh_one(npa, disc, feat,
	    "Composite Over Temp. Threshold", 0, NVME_TEMP_THRESH_OVER);

	if (!nvme_version_check(npa, &nvme_vers_1v2)) {
		return (B_TRUE);
	}

	if (!nvme_log_req_init_by_name(npa->npa_ctrl, "health", 0, &log_disc,
	    &req)) {
		nvmeadm_warn(npa, "failed to initialize health log page "
		    "request");
		return (B_FALSE);
	}

	toalloc = do_get_logpage_size(npa, log_disc, req);
	buf = malloc(toalloc);
	if (buf == NULL) {
		err(-1, "failed to allocate %zu bytes for health log page",
		    toalloc);
	}

	if (!nvme_log_req_set_output(req, buf, toalloc)) {
		nvmeadm_warn(npa, "failed to set output parameters for health "
		    "log page");
		goto out;
	}

	if (!nvme_log_req_exec(req)) {
		nvmeadm_warn(npa, "failed to retrieve the health log page");
		goto out;
	}

	/* cast required to prove our intentionality to smatch */
	hlog = (const nvme_health_log_t *)buf;

	do_get_feat_temp_thresh_one(npa, disc, feat,
	    "Composite Under Temp. Threshold", 0, NVME_TEMP_THRESH_UNDER);
	if (hlog->hl_temp_sensor_1 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 1 Over Temp. Threshold", 1,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 1 Under Temp. Threshold", 1,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_2 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 2 Over Temp. Threshold", 2,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 2 Under Temp. Threshold", 2,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_3 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 3 Over Temp. Threshold", 3,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 3 Under Temp. Threshold", 3,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_4 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 4 Over Temp. Threshold", 4,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 4 Under Temp. Threshold", 4,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_5 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 5 Over Temp. Threshold", 5,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 5 Under Temp. Threshold", 5,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_6 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 6 Over Temp. Threshold", 6,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 6 Under Temp. Threshold", 6,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_7 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 7 Over Temp. Threshold", 7,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 7 Under Temp. Threshold", 7,
		    NVME_TEMP_THRESH_UNDER);
	}

	if (hlog->hl_temp_sensor_8 != 0) {
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 8 Over Temp. Threshold", 8,
		    NVME_TEMP_THRESH_OVER);
		do_get_feat_temp_thresh_one(npa, disc, feat,
		    "Temp. Sensor 8 Under Temp. Threshold", 8,
		    NVME_TEMP_THRESH_UNDER);
	}

	ret = B_TRUE;
out:
	nvme_log_req_fini(req);
	free(buf);
	return (ret);
}

static boolean_t
do_get_feat_intr_vect(const nvme_process_arg_t *npa,
    const nvme_feat_disc_t *disc, const nvmeadm_feature_t *feat)
{
	uint32_t nintrs;
	boolean_t ret = B_TRUE;

	if (!nvme_ctrl_info_pci_nintrs(npa->npa_ctrl_info, &nintrs)) {
		nvmeadm_ctrl_info_warn(npa, "failed to get interrupt count "
		    "from controller %s information snapshot", npa->npa_name);
		return (B_FALSE);
	}

	nvme_print(2, nvme_feat_disc_spec(disc), -1, NULL);
	for (uint32_t i = 0; i < nintrs; i++) {
		uint32_t cdw0;
		void *buf;
		size_t buflen;
		nvme_intr_vect_t vect;

		vect.r = 0;
		vect.b.iv_iv = i;

		if (!do_get_feat_common(npa, disc, vect.r, &cdw0, &buf,
		    &buflen)) {
			ret = B_FALSE;
			continue;
		}

		feat->f_print(cdw0, buf, buflen, npa->npa_idctl,
		    npa->npa_version);
		free(buf);
	}

	return (ret);
}

/*
 * We've been asked to print the following feature that the controller probably
 * supports. Find our internal feature information for this to see if we know
 * how to deal with it.
 */
static void
do_get_features_cb(const nvme_process_arg_t *npa, const nvme_feat_disc_t *disc)
{
	const nvmeadm_feature_t *feat = NULL;
	uint32_t fid = nvme_feat_disc_fid(disc);
	nvme_get_feat_fields_t fields;
	void *data = NULL;
	size_t datalen = 0;
	uint32_t cdw0;

	for (size_t i = 0; i < ARRAY_SIZE(features); i++) {
		if (features[i].f_feature == fid) {
			feat = &features[i];
			break;
		}
	}

	/*
	 * Determine if we have enough logic in here to get and print the
	 * feature. The vast majority of NVMe features only output a single
	 * uint32_t in cdw0 and potentially a data buffer. As long as no input
	 * arguments are required, then we can go ahead and get this and print
	 * the data. If there is, then we will refuse unless we have a
	 * particular function. If we have a specific get function, we expect it
	 * to do all the printing.
	 */
	if (feat != NULL && feat->f_get != NULL) {
		if (!feat->f_get(npa, disc, feat)) {
			exitcode = -1;
		}
		return;
	}

	fields = nvme_feat_disc_fields_get(disc);
	if ((fields & NVME_GET_FEAT_F_CDW11) != 0) {
		warnx("unable to get feature %s due to missing nvmeadm(8) "
		    "implementation logic", nvme_feat_disc_spec(disc));
		exitcode = -1;
		return;
	}

	/*
	 * We do not set exitcode on failure here so that way we can swallow
	 * errors from unimplemented features.
	 */
	if (!do_get_feat_common(npa, disc, 0, &cdw0, &data, &datalen)) {
		return;
	}

	nvme_print(2, nvme_feat_disc_spec(disc), -1, NULL);
	if (feat != NULL && feat->f_print != NULL) {
		feat->f_print(cdw0, data, datalen, npa->npa_idctl,
		    npa->npa_version);
	} else {
		nvme_feat_output_t output = nvme_feat_disc_output_get(disc);
		nvme_print_feat_unknown(output, cdw0, data, datalen);
	}

	free(data);
}

/*
 * This is an entry point which prints every feature that we know about. We
 * often go to lengths to discover all the variable inputs that can be used for
 * a given feature that requires an argument in cdw11. Due to the semantics of
 * filtering being used for features and the need to print each feature, this is
 * not the place to add general field filtering or a means to request a specific
 * cdw11 argument or similar. Instead, a new get-feature which requires someone
 * to specify the short name for a feature and then allows particular fields to
 * be grabbed and arguments should be created instead.
 *
 * This uses the same general feature logic that underpins do_list_features()
 * and therefore we transform filter arguments into the same style used there.
 */
static int
do_get_features(const nvme_process_arg_t *npa)
{
	char *fstr = NULL;
	char **filts = NULL;
	boolean_t *used = NULL;
	nvmeadm_features_t nf;
	int ret;

	if (npa->npa_argc > 1)
		errx(-1, "unexpected arguments");

	if (npa->npa_ns != NULL && nvme_ns_info_level(npa->npa_ns_info) <
	    NVME_NS_DISC_F_ACTIVE) {
		errx(-1, "cannot get feature: namespace is inactive");
	}

	/*
	 * We always leave nf_unimpl set to false as we don't want to bother
	 * trying to print a feature that we know the device doesn't support.
	 */
	(void) memset(&nf, 0, sizeof (nvmeadm_features_t));

	/*
	 * If we've been given a series of features to print, treat those as
	 * filters on the features as we're walking them to determine which to
	 * print or not.
	 */
	if (npa->npa_argc == 1) {
		char *f;
		uint32_t i;

		nf.nf_nfilts = 1;
		fstr = strdup(npa->npa_argv[0]);

		if (fstr == NULL) {
			err(-1, "failed to allocate memory to duplicate "
			    "feature string");
		}

		for (const char *c = strchr(fstr, ','); c != NULL;
		    c = strchr(c + 1, ',')) {
			nf.nf_nfilts++;
		}

		filts = calloc(nf.nf_nfilts, sizeof (char *));
		if (filts == NULL) {
			err(-1, "failed to allocate memory for filter list");
		}

		i = 0;
		while ((f = strsep(&fstr, ",")) != NULL) {
			filts[i] = f;
			i++;
		}
		VERIFY3U(i, ==, nf.nf_nfilts);
		nf.nf_filts = filts;

		used = calloc(nf.nf_nfilts, sizeof (boolean_t));
		if (used == NULL) {
			err(-1, "failed to allocate memory for filter use "
			    "tracking");
		}
		nf.nf_used = used;
	}

	(void) printf("%s: Get Features\n", npa->npa_name);
	ret = do_features(npa, &nf, do_get_features_cb);

	free(fstr);
	free(filts);
	free(used);
	return (ret);
}

static int
do_format_common(const nvme_process_arg_t *npa, uint32_t lbaf,
    uint32_t ses)
{
	int ret = 0;
	nvme_format_req_t *req;

	if (npa->npa_ns != NULL && nvme_ns_info_level(npa->npa_ns_info) <
	    NVME_NS_DISC_F_ACTIVE) {
		errx(-1, "cannot %s: namespace is inactive",
		    npa->npa_cmd->c_name);
	}

	if (!nvme_format_req_init(npa->npa_ctrl, &req)) {
		nvmeadm_fatal(npa, "failed to initialize format request for "
		    "%s", npa->npa_name);
	}

	if (npa->npa_ns != NULL) {
		uint32_t nsid = nvme_ns_info_nsid(npa->npa_ns_info);

		if (!nvme_format_req_set_nsid(req, nsid)) {
			nvmeadm_fatal(npa, "failed to set format request "
			    "namespace ID to 0x%x", nsid);
		}
	}

	if (!nvme_format_req_set_lbaf(req, lbaf) ||
	    !nvme_format_req_set_ses(req, ses)) {
		nvmeadm_fatal(npa, "failed to set format request fields for %s",
		    npa->npa_name);
	}

	if (do_detach(npa) != 0) {
		errx(-1, "cannot %s %s due to namespace detach failure",
		    npa->npa_cmd->c_name, npa->npa_name);
	}

	if (!nvme_format_req_exec(req)) {
		nvmeadm_warn(npa, "failed to %s %s", npa->npa_cmd->c_name,
		    npa->npa_name);
		ret = -1;
	}

	if (do_attach(npa) != 0)
		ret = -1;

	return (ret);
}

static void
usage_format(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>] [<lba-format>]\n\n"
	    "  Format one or all namespaces of the specified NVMe "
	    "controller. Supported LBA\n  formats can be queried with "
	    "the \"%s identify\" command on the namespace\n  to be "
	    "formatted.\n", c_name, getprogname());
}

static uint32_t
do_format_determine_lbaf(const nvme_process_arg_t *npa)
{
	const nvme_nvm_lba_fmt_t *fmt;
	nvme_ns_info_t *ns_info = NULL;
	uint32_t lbaf;

	if (npa->npa_argc > 0) {
		unsigned long lba;
		uint32_t nlbaf = nvme_ctrl_info_nformats(npa->npa_ctrl_info);

		errno = 0;
		lba = strtoul(npa->npa_argv[0], NULL, 10);
		if (errno != 0 || lba >= nlbaf)
			errx(-1, "invalid LBA format %s", npa->npa_argv[0]);

		if (!nvme_ctrl_info_format(npa->npa_ctrl_info, (uint32_t)lba,
		    &fmt)) {
			nvmeadm_fatal(npa, "failed to get LBA format %lu "
			    "information", lba);
		}
	} else {
		/*
		 * If we have a namespace then we use the current namespace's
		 * LBA format. If we don't have a namespace, then we promised
		 * we'd look at namespace 1 in the manual page.
		 */
		if (npa->npa_ns_info == NULL) {
			if (!nvme_ctrl_ns_info_snap(npa->npa_ctrl, 1,
			    &ns_info)) {
				nvmeadm_fatal(npa, "failed to get namespace 1 "
				    "information, please explicitly specify an "
				    "LBA format");
			}

			if (!nvme_ns_info_curformat(ns_info, &fmt)) {
				nvmeadm_fatal(npa, "failed to retrieve current "
				    "namespace format from namespace 1");
			}
		} else {
			if (!nvme_ns_info_curformat(npa->npa_ns_info, &fmt)) {
				nvmeadm_fatal(npa, "failed to get the current "
				    "format information from %s",
				    npa->npa_name);
			}
		}
	}

	if (nvme_nvm_lba_fmt_meta_size(fmt) != 0) {
		errx(-1, "LBA formats with metadata are not supported");
	}

	lbaf = nvme_nvm_lba_fmt_id(fmt);
	nvme_ns_info_free(ns_info);
	return (lbaf);
}

static int
do_format(const nvme_process_arg_t *npa)
{
	uint32_t lbaf;

	if (npa->npa_argc > 1) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[1]);
	}

	lbaf = do_format_determine_lbaf(npa);
	return (do_format_common(npa, lbaf, 0));
}

static void
usage_secure_erase(const char *c_name)
{
	(void) fprintf(stderr, "%s [-c] <ctl>[/<ns>]\n\n"
	    "  Secure-Erase one or all namespaces of the specified "
	    "NVMe controller.\n", c_name);
}

static void
optparse_secure_erase(nvme_process_arg_t *npa)
{
	int c;

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":c")) != -1) {
		switch (c) {
		case 'c':
			npa->npa_cmdflags |= NVMEADM_O_SE_CRYPTO;
			break;

		case '?':
			errx(-1, "unknown option: -%c", optopt);

		case ':':
			errx(-1, "option -%c requires an argument", optopt);

		}
	}
}

static int
do_secure_erase(const nvme_process_arg_t *npa)
{
	unsigned long lbaf;
	uint8_t ses = NVME_FRMT_SES_USER;

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	if ((npa->npa_cmdflags & NVMEADM_O_SE_CRYPTO) != 0)
		ses = NVME_FRMT_SES_CRYPTO;

	lbaf = do_format_determine_lbaf(npa);
	return (do_format_common(npa, lbaf, ses));
}

static void
usage_attach_detach(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>[/<ns>]\n\n"
	    "  %c%s blkdev(4D) %s one or all namespaces of the "
	    "specified NVMe controller.\n",
	    c_name, toupper(c_name[0]), &c_name[1],
	    c_name[0] == 'd' ? "from" : "to");
}

static int
do_attach(const nvme_process_arg_t *npa)
{
	int rv;
	nvme_ns_iter_t *iter = NULL;
	nvme_iter_t ret;
	const nvme_ns_disc_t *disc;

	if (npa->npa_ns != NULL) {
		if (!nvme_ns_bd_attach(npa->npa_ns)) {
			nvmeadm_warn(npa, "faild to attach %s", npa->npa_name);
			return (-1);
		}
		return (0);
	}

	if (!nvme_ns_discover_init(npa->npa_ctrl, NVME_NS_DISC_F_NOT_IGNORED,
	    &iter))  {
		nvmeadm_fatal(npa, "failed to initialize namespace discovery "
		    "on %s", npa->npa_name);
	}

	rv = 0;
	while ((ret = nvme_ns_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		nvme_ns_t *ns;
		uint32_t nsid;

		if (nvme_ns_disc_level(disc) == NVME_NS_DISC_F_BLKDEV)
			continue;

		nsid = nvme_ns_disc_nsid(disc);
		if (!nvme_ns_init(npa->npa_ctrl, nsid, &ns)) {
			nvmeadm_warn(npa, "failed to open namespace %s/%u "
			    "handle", npa->npa_name, nsid);
			rv = -1;
			continue;
		}

		if (!nvme_ns_bd_attach(ns)) {
			nvmeadm_warn(npa, "failed to attach namespace "
			    "%s/%u", npa->npa_name, nsid);
			rv = -1;
		}
		nvme_ns_fini(ns);
	}

	nvme_ns_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		nvmeadm_warn(npa, "failed to iterate namespaces on %s",
		    npa->npa_name);
		rv = -1;
	}

	return (rv);
}

static int
do_detach(const nvme_process_arg_t *npa)
{
	int rv;
	nvme_ns_iter_t *iter = NULL;
	nvme_iter_t ret;
	const nvme_ns_disc_t *disc;

	if (npa->npa_ns != NULL) {
		if (!nvme_ns_bd_detach(npa->npa_ns)) {
			nvmeadm_warn(npa, "failed to detach %s", npa->npa_name);
			return (-1);
		}
		return (0);
	}

	if (!nvme_ns_discover_init(npa->npa_ctrl, NVME_NS_DISC_F_BLKDEV,
	    &iter))  {
		nvmeadm_fatal(npa, "failed to initialize namespace discovery "
		    "on %s", npa->npa_name);
	}

	rv = 0;
	while ((ret = nvme_ns_discover_step(iter, &disc)) == NVME_ITER_VALID) {
		nvme_ns_t *ns;
		uint32_t nsid = nvme_ns_disc_nsid(disc);

		if (!nvme_ns_init(npa->npa_ctrl, nsid, &ns)) {
			nvmeadm_warn(npa, "failed to open namespace %s/%u "
			    "handle", npa->npa_name, nsid);
			rv = -1;
			continue;
		}

		if (!nvme_ns_bd_detach(ns)) {
			nvmeadm_warn(npa, "failed to detach namespace "
			    "%s/%u", npa->npa_name, nsid);
			rv = -1;
		}
		nvme_ns_fini(ns);
	}

	nvme_ns_discover_fini(iter);
	if (ret == NVME_ITER_ERROR) {
		nvmeadm_warn(npa, "failed to iterate namespaces on %s",
		    npa->npa_name);
		rv = -1;
	}

	return (rv);
}

static void
usage_firmware_load(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl> <image file> [<offset>]\n\n"
	    "  Load firmware <image file> to offset <offset>.\n"
	    "  The firmware needs to be committed to a slot using "
	    "\"nvmeadm commit-firmware\"\n  command.\n", c_name);
}

/*
 * Read exactly len bytes, or until eof.
 */
static size_t
read_block(const nvme_process_arg_t *npa, int fd, char *buf, size_t len)
{
	size_t remain;

	remain = len;
	while (remain > 0) {
		ssize_t bytes = read(fd, buf, remain);
		if (bytes == 0)
			break;

		if (bytes < 0) {
			if (errno == EINTR)
				continue;

			err(-1, "Error reading \"%s\"", npa->npa_argv[0]);
		}

		buf += (size_t)bytes;
		remain -= (size_t)bytes;
	}

	return (len - remain);
}

/*
 * Convert a string to a valid firmware upload offset (in bytes).
 */
static uint64_t
get_fw_offsetb(char *str)
{
	longlong_t offsetb;
	char *valend;

	errno = 0;
	offsetb = strtoll(str, &valend, 0);
	if (errno != 0 || *valend != '\0' || offsetb < 0 ||
	    offsetb > NVME_FW_OFFSETB_MAX)
		errx(-1, "Offset must be numeric and in the range of 0 to %llu",
		    NVME_FW_OFFSETB_MAX);

	if ((offsetb & NVME_DWORD_MASK) != 0)
		errx(-1, "Offset must be multiple of %d", NVME_DWORD_SIZE);

	return ((uint64_t)offsetb);
}

#define	FIRMWARE_READ_BLKSIZE	(64 * 1024)		/* 64K */

static int
do_firmware_load(const nvme_process_arg_t *npa)
{
	int fw_fd;
	uint64_t offset = 0;
	size_t size, len;
	char buf[FIRMWARE_READ_BLKSIZE];

	if (npa->npa_argc > 2)
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[2]);

	if (npa->npa_argc == 0)
		errx(-1, "Requires firmware file name, and an "
		    "optional offset");

	if (npa->npa_ns != NULL)
		errx(-1, "Firmware loading not available on a per-namespace "
		    "basis");

	if (npa->npa_argc == 2)
		offset = get_fw_offsetb(npa->npa_argv[1]);

	fw_fd = open(npa->npa_argv[0], O_RDONLY);
	if (fw_fd < 0)
		errx(-1, "Failed to open \"%s\": %s", npa->npa_argv[0],
		    strerror(errno));

	size = 0;
	do {
		len = read_block(npa, fw_fd, buf, sizeof (buf));

		if (len == 0)
			break;

		if (!nvme_fw_load(npa->npa_ctrl, buf, len, offset)) {
			nvmeadm_fatal(npa, "failed to load firmware image "
			    "\"%s\" at offset %" PRIu64, npa->npa_argv[0],
			    offset);
		}

		offset += len;
		size += len;
	} while (len == sizeof (buf));

	(void) close(fw_fd);

	if (verbose)
		(void) printf("%zu bytes downloaded.\n", size);

	return (0);
}

/*
 * Common firmware commit for nvmeadm commit-firmware and activate-firmware.
 */
static void
nvmeadm_firmware_commit(const nvme_process_arg_t *npa, uint32_t slot,
    uint32_t act)
{
	nvme_fw_commit_req_t *req;

	if (!nvme_fw_commit_req_init(npa->npa_ctrl, &req)) {
		nvmeadm_fatal(npa, "failed to initialize firmware commit "
		    "request for %s", npa->npa_name);
	}

	if (!nvme_fw_commit_req_set_slot(req, slot) ||
	    !nvme_fw_commit_req_set_action(req, act)) {
		nvmeadm_fatal(npa, "failed to set firmware commit fields for "
		    "%s", npa->npa_name);
	}

	if (!nvme_fw_commit_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to %s firmware on %s",
		    npa->npa_cmd->c_name, npa->npa_name);
	}

	nvme_fw_commit_req_fini(req);
}

/*
 * Convert str to a valid firmware slot number.
 */
static uint32_t
get_slot_number(char *str)
{
	longlong_t slot;
	char *valend;

	errno = 0;
	slot = strtoll(str, &valend, 0);
	if (errno != 0 || *valend != '\0' ||
	    slot < NVME_FW_SLOT_MIN || slot > NVME_FW_SLOT_MAX)
		errx(-1, "Slot must be numeric and in the range of %u to %u",
		    NVME_FW_SLOT_MIN, NVME_FW_SLOT_MAX);

	return ((uint32_t)slot);
}

static void
usage_firmware_commit(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl> <slot>\n\n"
	    "  Commit previously downloaded firmware to slot <slot>.\n"
	    "  The firmware is only activated after a "
	    "\"nvmeadm activate-firmware\" command.\n", c_name);
}

static int
do_firmware_commit(const nvme_process_arg_t *npa)
{
	uint32_t slot;

	if (npa->npa_argc > 1)
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[1]);

	if (npa->npa_argc == 0)
		errx(-1, "Firmware slot number is required");

	if (npa->npa_ns != NULL)
		errx(-1, "Firmware committing not available on a per-namespace "
		    "basis");

	slot = get_slot_number(npa->npa_argv[0]);

	if (slot == 1 && npa->npa_idctl->id_frmw.fw_readonly)
		errx(-1, "Cannot commit firmware to slot 1: slot is read-only");

	nvmeadm_firmware_commit(npa, slot, NVME_FWC_SAVE);

	if (verbose)
		(void) printf("Firmware committed to slot %u.\n", slot);

	return (0);
}

static void
usage_firmware_activate(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl> <slot>\n\n"
	    "  Activate firmware in slot <slot>.\n"
	    "  The firmware will be in use after the next system reset.\n",
	    c_name);
}

static int
do_firmware_activate(const nvme_process_arg_t *npa)
{
	uint32_t slot;

	if (npa->npa_argc > 1)
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[1]);

	if (npa->npa_argc == 0)
		errx(-1, "Firmware slot number is required");

	if (npa->npa_ns != NULL)
		errx(-1, "Firmware activation not available on a per-namespace "
		    "basis");

	slot = get_slot_number(npa->npa_argv[0]);

	nvmeadm_firmware_commit(npa, slot, NVME_FWC_ACTIVATE);

	if (verbose)
		(void) printf("Slot %u successfully activated.\n", slot);

	return (0);
}

nvme_vuc_disc_t *
nvmeadm_vuc_init(const nvme_process_arg_t *npa, const char *name)
{
	nvme_vuc_disc_t *vuc;
	nvme_vuc_disc_lock_t lock;

	if (!nvme_vuc_discover_by_name(npa->npa_ctrl, name, 0, &vuc)) {
		nvmeadm_fatal(npa, "%s does not support operation %s: device "
		    "does not support vendor unique command %s", npa->npa_name,
		    npa->npa_cmd->c_name, name);
	}

	lock = nvme_vuc_disc_lock(vuc);
	switch (lock) {
	case NVME_VUC_DISC_LOCK_NONE:
		break;
	case NVME_VUC_DISC_LOCK_READ:
		nvmeadm_excl(npa, NVME_LOCK_L_READ);
		break;
	case NVME_VUC_DISC_LOCK_WRITE:
		nvmeadm_excl(npa, NVME_LOCK_L_WRITE);
		break;
	}

	return (vuc);
}

void
nvmeadm_vuc_fini(const nvme_process_arg_t *npa, nvme_vuc_disc_t *vuc)
{
	if (nvme_vuc_disc_lock(vuc) != NVME_VUC_DISC_LOCK_NONE) {
		if (npa->npa_ns != NULL) {
			nvme_ns_unlock(npa->npa_ns);
		} else if (npa->npa_ctrl != NULL) {
			nvme_ctrl_unlock(npa->npa_ctrl);
		}
	}

	nvme_vuc_disc_free(vuc);
}
