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
 * Sandisk vendor-specific commands. These generally start with the x6x
 * generation of controllers. For prior generations (e.g. x4x and x5x), see
 * nvmeadm_wdc.c.
 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/nvme/wdc.h>

#include "nvmeadm.h"

typedef struct {
	uint8_t se_lane;
	const char *se_output;
} sandisk_eye_t;

void
usage_sandisk_hwrev(const char *c_name)
{
	(void) fprintf(stderr, "%s <ctl>\n\n"
	    "  Print device hardware revision\n", c_name);
}

int
do_sandisk_hwrev(const nvme_process_arg_t *npa)
{
	uint8_t major, minor;
	nvme_vuc_disc_t *vuc;

	if (npa->npa_argc > 0) {
		errx(-1, "%s passed extraneous arguments starting with %s",
		    npa->npa_cmd->c_name, npa->npa_argv[0]);
	}

	vuc = nvmeadm_vuc_init(npa, npa->npa_cmd->c_name);
	if (!nvme_sndk_hw_rev(npa->npa_ctrl, &major, &minor)) {
		nvmeadm_fatal(npa, "failed to retrieve hardware revision");
	}

	(void) printf("%u.%u\n", major, minor);
	nvmeadm_vuc_fini(npa, vuc);
	return (0);
}

void
usage_sandisk_pcieye(const char *c_name)
{
	(void) fprintf(stderr, "%s -l lane -o output <ctl>\n\n"
	    "  Write PCIe eye data from the specified lane to output file.\n",
	    c_name);
}

void
optparse_sandisk_pcieye(nvme_process_arg_t *npa)
{
	int c;
	sandisk_eye_t *eye;

	if ((eye = calloc(1, sizeof (sandisk_eye_t))) == NULL) {
		err(-1, "failed to allocate memory for pci-eye options "
		    "structure");
	}

	eye->se_lane = UINT8_MAX;
	while ((c = getopt(npa->npa_argc, npa->npa_argv, ":l:o:")) != -1) {
		const char *errstr;

		switch (c) {
		case 'l':
			eye->se_lane = (uint8_t)strtonumx(optarg, 0, 3, &errstr,
			    0);
			if (errstr != NULL) {
				errx(-1, "invalid lane specified, valid values "
				    "are 0-3: %s is %s", optarg, errstr);
			}
			break;
		case 'o':
			eye->se_output = optarg;
			break;
		case '?':
			errx(-1, "unknown option: -%c", optopt);
		case ':':
			errx(-1, "option -%c requires an argument", optopt);
		}
	}

	if (eye->se_lane == UINT8_MAX) {
		errx(-1, "missing required PCIe lane (0-3), specify with -l");
	}

	if (eye->se_output == NULL) {
		errx(-1, "missing required output file, specify with -o");
	}

	npa->npa_cmd_arg = eye;
}

int
do_sandisk_pcieye(const nvme_process_arg_t *npa)
{
	const sandisk_eye_t *eye = npa->npa_cmd_arg;
	nvme_vuc_disc_t *vuc;
	uint8_t *buf;
	int ofd;

	if ((buf = calloc(WDC_SN861_VUC_EYE_LEN, sizeof (uint8_t))) == NULL) {
		err(-1, "failed to allocate eye diagram buffer");
	}

	vuc = nvmeadm_vuc_init(npa, npa->npa_cmd->c_name);

	ofd = open(eye->se_output, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (ofd < 0) {
		err(-1, "failed to open output file %s", eye->se_output);
	}

	if (!nvme_sndk_pci_eye(npa->npa_ctrl, eye->se_lane, buf,
	    WDC_SN861_VUC_EYE_LEN)) {
		nvmeadm_fatal(npa, "failed to retrieve PCIe eye information");
	}

	size_t off = 0, len = WDC_SN861_VUC_EYE_LEN;
	while (len > 0) {
		size_t towrite = MIN(len, 32 * 1024);
		ssize_t ret = write(ofd, buf + off, towrite);
		if (ret < 0) {
			err(-1, "failed to write eye data to output file");
		}

		off += (size_t)ret;
		len -= (size_t)ret;
	}

	nvmeadm_vuc_fini(npa, vuc);
	VERIFY0(close(ofd));
	free(buf);
	return (0);
}
