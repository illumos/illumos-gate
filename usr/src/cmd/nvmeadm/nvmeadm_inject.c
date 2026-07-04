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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Commands and logic to support error injection.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/sysmacros.h>
#include <sys/nvme/ocp.h>

#include "nvmeadm.h"

typedef struct {
	uint32_t ni_lat;
	uint32_t ni_nread;
} nvmeadm_inject_t;

typedef struct {
	const char *map_name;
	ocp_errinj_type_t map_type;
} ocp_err_map_t;

static const ocp_err_map_t ocp_err_map[] = {
	{ "cpu-hang", OCP_ERRINJ_T_CPU_HANG },
	{ "nand-hang", OCP_ERRINJ_T_NAND_HANG },
	{ "plp-defect", OCP_ERRINJ_T_PLP_DEFECT },
	{ "fw-error", OCP_ERRINJ_T_FW_ERROR },
	{ "dram-corrupt-crit", OCP_ERRINJ_T_DRAM_CORRUPT_CRIT },
	{ "dram-corrupt-noncrit", OCP_ERRINJ_T_DRAM_CORRUPT_NONCRIT },
	{ "nand-corrupt", OCP_ERRINJ_T_NAND_CORRUPT },
	{ "sram-corrupt", OCP_ERRINJ_T_SRAM_CORRUPT },
	{ "hw-malfunction", OCP_ERRINJ_T_HW_MALFUNC },
	{ "no-spare-nand", OCP_ERRINJ_T_NO_SPARE_NAND },
	{ "incomplete-shutdown", OCP_ERRINJ_T_INCOMPLETE_SHUTDOWN },
	{ "metadata-corrupt", OCP_ERRINJ_T_METADATA_CORRUPT },
	{ "critical-gc", OCP_ERRINJ_T_CRIT_GC },
	{ "latency-spike", OCP_ERRINJ_T_LATENCY_SPIKE },
	{ "io-failure", OCP_ERRINJ_T_IO_FAIL },
	{ "io-timeout", OCP_ERRINJ_T_IO_TIMEOUT },
	{ "admin-failure", OCP_ERRINJ_T_ADMIN_FAIL },
	{ "admin-timeout", OCP_ERRINJ_T_ADMIN_TIMEOUT },
	{ "thermal-throttle-start", OCP_ERRINJ_T_THERM_THROT_EN },
	{ "thermal-throttle-end", OCP_ERRINJ_T_THERM_THROT_DIS },
	{ "crit-temp", OCP_ERRINJ_T_THERM_CRIT_TEMP },
	{ "nand-offline", OCP_ERRINJ_T_DIE_OFFLINE },
	{ "sanitize-cmd-failure", OCP_ERRINJ_T_SANITIZE_CMD_FAIL },
	{ "require-user-data-erase", OCP_ERRINJ_T_USER_DATA_ERASE },
	{ "pcie-correctable", OCP_ERRINJ_T_PCIE_CE },
	{ "pcie-uncorrectable", OCP_ERRINJ_T_PCIE_UE },
	{ "clear-pel", OCP_ERRINJ_T_PEL_CLEAR },
	{ "sanitize-op-failure", OCP_ERRINJ_T_SANITIZE_OP_FAIL },
	{ "random-io-spikes", OCP_ERRINJ_T_RANDOM_LATENCY },
	{ "factory-reset", OCP_ERRINJ_T_FACTORY_RESET },
	{ "voltage-drop", OCP_ERRINJ_T_VOLTAGE_DROP },
	{ "available-spare", OCP_ERRINJ_T_AVAIL_SPARE },
	{ "volatile-memory-backup", OCP_ERRINJ_T_VOL_MEM_BACKUP },
};

const char *
nvmeadm_ocp_errinj_type_to_str(uint32_t val)
{
	for (size_t i = 0; i < ARRAY_SIZE(ocp_err_map); i++) {
		if (ocp_err_map[i].map_type == val) {
			return (ocp_err_map[i].map_name);
		}
	}

	return ("unknown");
}

void
usage_ocp_errinj(const char *c_name)
{

	(void) fprintf(stderr, "%s [-l lat_us] [-n nreads] <ctl> <error>\n\n",
	    c_name);
	(void) fprintf(stderr, "  inject a specific error or event on a "
	    "controller. This may disrupt or degrade\ndevice operation.\n");
}

void
optparse_ocp_errinj(nvme_process_arg_t *npa)
{
	int c;
	nvmeadm_inject_t *inject;

	if ((inject = calloc(1, sizeof (nvmeadm_inject_t))) == NULL) {
		err(-1, "failed to allocate memory for option tracking");
	}

	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":l:n:")) != -1) {
		switch (c) {
		case 'l':
			inject->ni_lat = (uint32_t)optparse_ui_range(optarg,
			    "lat_us", 0, UINT32_MAX);
			break;
		case 'n':
			inject->ni_nread = (uint32_t)optparse_ui_range(optarg,
			    "nread", 0, UINT32_MAX);
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	npa->npa_cmd_arg = inject;
}

int
do_ocp_errinj(const nvme_process_arg_t *npa)
{
	const char *event;
	const nvmeadm_inject_t *inject = npa->npa_cmd_arg;
	nvme_ocp_errinj_req_t *req;

	if (npa->npa_argc < 1) {
		errx(-1, "missing required error to inject");
	} else if (npa->npa_argc > 1) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[1]);
	}
	event = npa->npa_argv[0];

	if (npa->npa_ns != NULL) {
		errx(-1, "error injection may only be performed on a "
		    "controller, not a namespace");
	}

	/*
	 * First try to parse by name. Otherwise try to parse this as an
	 * integer.
	 */
	uint32_t type = UINT32_MAX;
	if (strcasecmp(event, "clear-errors") == 0) {
		if (inject->ni_lat != 0) {
			errx(-1, "-l may not be specified when clearing "
			    "errors");
		}

		if (inject->ni_nread != 0) {
			errx(-1, "-n may not be specified when clearing "
			    "errors");
		}

		if (!nvme_ocp_errinj_clear(npa->npa_ctrl)) {
			nvmeadm_fatal(npa, "failed to clear pending errors");
		}
		return (EXIT_SUCCESS);
	}

	for (size_t i = 0; i < ARRAY_SIZE(ocp_err_map); i++) {
		if (strcasecmp(ocp_err_map[i].map_name, event) == 0) {
			type = ocp_err_map[i].map_type;
			break;
		}
	}

	if (type == UINT32_MAX) {
		const char *errstr;

		type = (uint32_t)strtonumx(event, 0, UINT16_MAX, &errstr, 0);
		if (errstr != NULL) {
			errx(-1, "failed to parse %s as an error injection "
			    "type", event);
		}
	}

	/*
	 * While we could check whether -l is allowed to be set based on the
	 * event type, we instead opt to leave that to the library code for now.
	 */

	if (!nvme_ocp_errinj_req_init(npa->npa_ctrl, &req) ||
	    !nvme_ocp_errinj_req_set_type(req, type) ||
	    (inject->ni_nread != 0 && !nvme_ocp_errinj_req_set_nrtde(req,
	    inject->ni_nread)) ||
	    (inject->ni_lat != 0 && !nvme_ocp_errinj_req_set_ld(req,
	    inject->ni_lat))) {
		nvmeadm_fatal(npa, "failed to initialize error %s injection "
		    "request", event);
	}

	if (!nvme_ocp_errinj_req_exec(req)) {
		nvmeadm_fatal(npa, "failed to inject error %s", event);
	}

	nvme_ocp_errinj_req_fini(req);
	return (EXIT_SUCCESS);
}
