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
 * Copyright 2025 Oxide Computer Compnay
 */

/*
 * Executor for mac_sw_lso() ktests.
 *
 * This program builds up the packed nvlist payloads expected by the ktest for
 * mac_sw_lso().  The caller provides a snoop(1) with one packet, which may not
 * have valid checksums. This operates the runner similarly to mac_cksum:
 * required checksum types are specified via option flags, and the output mblk
 * chain is compared byte-for-byte with equality against a separate output
 * snoop file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <err.h>
#include <errno.h>
#include <libgen.h>

#include <libktest.h>

#include "mac_ktest_common.h"

static ktest_hdl_t *kthdl = NULL;
const char *mac_lso_cmd = "";

static void __NORETURN
mac_lso_usage(void)
{
	(void) fprintf(stderr, "Usage: %s [flags] [opts] <cap_file_in> "
	    "<cap_file_out>\n\n"
	    "Flags:\n"
	    "\t-4\temulate HCK_IPV4_HDRCKSUM\n"
	    "\t-f\temulate HCK_FULLCKSUM\t(cannot be used with -p)\n"
	    "\t-p\temulate HCK_PARTIALCKSUM\t(cannot be used with -f)\n"
	    "\t\t\tOne of -f/-p *must* be provided.\n"
	    "\t-e\tsplit mblk after Ethernet header\n"
	    "Options:\n"
	    "\t-b <len>\tpad mblk with <len> bytes (must be even)\n"
	    "\t-s <len>\tsplit mblk after len bytes (must be even)\n"
	    "\t\t\tif -e is specified, will be applied after that split\n"
	    "\t-m <len>\tmaximum segment size for LSO (default 1448)\n"
	    "Arguments:\n"
	    "\t<cap_file_in> is a snoop capture containing one test packet.\n"
	    "\t<cap_file_out> is a snoop capture of expected output packets.\n"
	    "\tInput packets may or may not have filled L3/L4 checksums, as\n"
	    "\tclients will have different expectations about which\n",
	    "\tchecksum offloads are available.\n",
	    mac_lso_cmd);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	/* Peel off command name for usage */
	mac_lso_cmd = basename(argv[0]);
	argc--;
	argv++;
	optind = 0;
	const char *errstr = NULL;

	struct payload_opts popts = {
		.po_mss = 1448
	};
	int c;
	while ((c = getopt(argc, argv, "4fpeb:s:m:")) != -1) {
		switch (c) {
		case 'p':
			popts.po_cksum_partial = B_TRUE;
			break;
		case 'f':
			popts.po_cksum_full = B_TRUE;
			break;
		case '4':
			popts.po_cksum_ipv4 = B_TRUE;
			break;
		case 'b':
			popts.po_padding =
			    strtonumx(optarg, 0, UINT16_MAX, &errstr, 0);
			if (errstr != NULL) {
				errx(EXIT_FAILURE,
				    "invalid padding value %s: %s",
				    optarg, errstr);
			}
			break;
		case 'e':
			popts.po_split_ether = B_TRUE;
			break;
		case 's':
			popts.po_split_manual =
			    strtonumx(optarg, 0, UINT16_MAX, &errstr, 0);
			if (errstr != NULL) {
				errx(EXIT_FAILURE,
				    "invalid split value %s: %s",
				    optarg, errstr);
			}
			break;
		case 'm':
			popts.po_mss =
			    strtonumx(optarg, 0, UINT32_MAX, &errstr, 0);
			if (errstr != NULL) {
				errx(EXIT_FAILURE,
				    "invalid MSS value %s: %s",
				    optarg, errstr);
			}
			break;

		case '?':
			warnx("unknown option: -%c", optopt);
			mac_lso_usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2) {
		(void) fprintf(stderr,
		    "cap_file_in and cap_file_out are required arguments\n");
		mac_lso_usage();
	}

	if (popts.po_cksum_full == popts.po_cksum_partial) {
		errx(EXIT_FAILURE, "specify exactly one of -f/-p");
	}

	int in_fd = open(argv[0], O_RDONLY);
	if (in_fd < 0) {
		err(EXIT_FAILURE, "could not open input cap file %s", argv[0]);
	}

	int out_fd = open(argv[1], O_RDONLY);
	if (out_fd < 0) {
		err(EXIT_FAILURE, "could not open output cap file %s", argv[0]);
	}

	pkt_cap_iter_t *in_iter = pkt_cap_open(in_fd);
	if (in_iter == NULL) {
		err(EXIT_FAILURE, "unrecognized cap file %s", argv[0]);
	}

	pkt_cap_iter_t *out_iter = pkt_cap_open(out_fd);
	if (out_iter == NULL) {
		err(EXIT_FAILURE, "unrecognized cap file %s", argv[1]);
	}

	const void *pkt_buf = NULL;
	uint_t pkt_sz;
	if (!pkt_cap_next(in_iter, &pkt_buf, &pkt_sz)) {
		err(EXIT_FAILURE, "no packets in input capture");
	}

	uint_t out_pkt_sz;
	char *out_pkt_buf = serialize_pkt_chain(out_iter, &out_pkt_sz);
	if (out_pkt_buf == NULL) {
		err(EXIT_FAILURE, "failed to read output packet stream");
	}

	if ((kthdl = ktest_init()) == NULL) {
		err(EXIT_FAILURE, "could not initialize libktest");
	}
	if (!ktest_mod_load("mac")) {
		err(EXIT_FAILURE, "could not load mac ktest module");
	}

	ktest_run_req_t req = {
		.krq_module = "mac",
		.krq_suite = "lso",
		.krq_test = "mac_sw_lso_test",
	};
	size_t payload_sz;
	char *payload =
	    build_payload(pkt_buf, pkt_sz, out_pkt_buf, out_pkt_sz, &popts,
	    &payload_sz);
	req.krq_input = (uchar_t *)payload;
	req.krq_input_len = (uint_t)payload_sz;

	ktest_run_result_t result = { 0 };
	if (!ktest_run(kthdl, &req, &result)) {
		err(EXIT_FAILURE, "failure while attempting ktest run");
	}
	free(payload);
	free(out_pkt_buf);

	const char *code_name = ktest_code_name(result.krr_code);
	(void) printf("%s\t(len: %u)\n", code_name, pkt_sz);
	if (result.krr_msg != NULL) {
		if (result.krr_code != KTEST_CODE_PASS) {
			(void) printf("MSG: %s\n", result.krr_msg);
		}
		free(result.krr_msg);
	}

	pkt_cap_close(in_iter);
	pkt_cap_close(out_iter);
	ktest_fini(kthdl);

	return (result.krr_code == KTEST_CODE_PASS ? EXIT_SUCCESS :
	    EXIT_FAILURE);
}
