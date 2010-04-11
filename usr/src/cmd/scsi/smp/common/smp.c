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
#include <sys/types.h>
#include <sys/scsi/generic/smp_frames.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>
#include <sys/ccompile.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>

#include <scsi/libsmp.h>
#include <scsi/libsmp_plugin.h>

static void fatal(int, const char *, ...) __NORETURN;

static void
fatal(int err, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	(void) fprintf(stderr, "\n");
	(void) fflush(stderr);

	_exit(err);
}

int
main(int argc, char *argv[])
{
	smp_target_t *tp;
	smp_action_t *ap;
	smp_errno_t err;
	smp_function_t func;
	smp_result_t result;
	smp_target_def_t tdef;
	smp_discover_resp_t *rp;
	smp_report_manufacturer_info_resp_t *ip;
	uint8_t *resp;
	size_t len;
	uint_t cap;
	void *x;
	uint_t i, j;

	if (argc < 3)
		fatal(-1, "Usage: %s <device> <function> ...\n", argv[0]);

	errno = 0;
	func = strtoul(argv[2], NULL, 0);
	if (errno != 0)
		fatal(-1, "Usage: %s <device> <function> ...\n", argv[0]);

	if (smp_init(LIBSMP_VERSION) != 0)
		fatal(-1, "libsmp initialization failed: %s", smp_errmsg());

	bzero(&tdef, sizeof (smp_target_def_t));
	tdef.std_def = argv[1];

	if ((tp = smp_open(&tdef)) == NULL) {
		smp_fini();
		fatal(-2, "failed to open %s: %s", argv[1], smp_errmsg());
	}

	cap = smp_target_getcap(tp);
	ap = smp_action_alloc(func, tp, 0);
	if (ap == NULL) {
		smp_close(tp);
		smp_fini();
		fatal(-3, "failed to allocate action: %s", smp_errmsg());
	}

	if (func == SMP_FUNC_DISCOVER) {
		smp_discover_req_t *dp;
		if (argc < 4)
			fatal(-1,
			    "Usage: %s <device> 0x10 <phy identifier>\n",
			    argv[0]);

		smp_action_get_request(ap, (void **)&dp, NULL);
		dp->sdr_phy_identifier = strtoul(argv[3], NULL, 0);
	} else if (func == SMP_FUNC_REPORT_ROUTE_INFO) {
		smp_report_route_info_req_t *rp;
		if (argc < 5)
			fatal(-1, "Usage: %s <device> 0x13 <expander route "
			    "index> <phy identifier>\n",
			    argv[0]);

		smp_action_get_request(ap, (void **)&rp, NULL);
		rp->srrir_exp_route_index = strtoul(argv[3], NULL, 0);
		rp->srrir_phy_identifier = strtoul(argv[4], NULL, 0);
	} else if (func == SMP_FUNC_ENABLE_DISABLE_ZONING) {
		smp_enable_disable_zoning_req_t *rp;
		if (argc < 4)
			fatal(-1,
			    "Usage: %s <device> 0x81 "
			    "[0(no change) | 1(enable)| 2(disable)]\n",
			    argv[0]);

		smp_action_get_request(ap, (void **)&rp, NULL);
		rp->sedzr_enable_disable_zoning = strtoul(argv[3], NULL, 0);
	} else if (func == SMP_FUNC_PHY_CONTROL) {
		smp_phy_control_req_t *rp;
		if (argc < 5)
			fatal(-1,
			    "Usage: %s <device> 0x91 <phy identifier> "
			    " <phy operation>\n",
			    argv[0]);

		smp_action_get_request(ap, (void **)&rp, NULL);

		smp_action_get_request(ap, (void **)&rp, NULL);
		rp->spcr_phy_identifier = strtoul(argv[3], NULL, 0);
		rp->spcr_phy_operation = strtoul(argv[4], NULL, 0);
	} else if (func == SMP_FUNC_REPORT_EXP_ROUTE_TABLE_LIST) {
		smp_report_exp_route_table_list_req_t *rp;
		if (argc < 4)
			fatal(-1,
			    "Usage: %s <device> 0x22 <SAS Address Index> \n",
			    argv[0]);

		smp_action_get_request(ap, (void **)&rp, NULL);
		SCSI_WRITE16(&rp->srertlr_max_descrs, 64);
		SCSI_WRITE16(&rp->srertlr_starting_routed_sas_addr_index,
		    strtoull(argv[3], NULL, 0));
		rp->srertlr_starting_phy_identifier = 0;
	}

	(void) printf("%s\n", argv[0]);
	(void) printf("\tSAS Address: %016llx\n", smp_target_addr(tp));
	(void) printf("\tVendor: %s\n", smp_target_vendor(tp));
	(void) printf("\tProduct: %s\n", smp_target_product(tp));
	(void) printf("\tRevision: %s\n", smp_target_revision(tp));
	(void) printf("\tExp Vendor: %s\n", smp_target_component_vendor(tp));
	(void) printf("\tExp ID: %04x\n", smp_target_component_id(tp));
	(void) printf("\tExp Rev: %02x\n", smp_target_component_revision(tp));

	if (smp_exec(ap, tp) != 0) {
		smp_close(tp);
		smp_action_free(ap);
		smp_fini();
		fatal(-4, "exec failed: %s", smp_errmsg());
	}

	smp_close(tp);
	smp_action_get_response(ap, &result, (void **)&resp, &len);

	if (result != SMP_RES_FUNCTION_ACCEPTED) {
		smp_action_free(ap);
		smp_fini();
		fatal(-5, "command failed with status code %d", result);
	}

	(void) printf("Response: (len %d)\n", len);
	for (i = 0; i < len; i += 8) {
		(void) printf("%02x: ", i);
		for (j = i; j < i + 8; j++)
			if (j < len)
				(void) printf("%02x ", resp[j]);
			else
				(void) printf("   ");
		for (j = i; j < i + 8; j++)
			(void) printf("%c",
			    j < len && isprint(resp[j]) ? resp[j] :
			    j < len ? '.' : '\0');
		(void) printf("\n");
	}

	if (func == SMP_FUNC_DISCOVER) {
		rp = (smp_discover_resp_t *)resp;
		(void) printf("Addr: %016llx Phy: %02x\n",
		    SCSI_READ64(&rp->sdr_sas_addr), rp->sdr_phy_identifier);
		(void) printf("Peer: %016llx Phy: %02x\n",
		    SCSI_READ64(&rp->sdr_attached_sas_addr),
		    rp->sdr_attached_phy_identifier);
		(void) printf("Device type: %01x\n",
		    rp->sdr_attached_device_type);
	}

	smp_action_free(ap);
	smp_fini();

	return (0);
}
