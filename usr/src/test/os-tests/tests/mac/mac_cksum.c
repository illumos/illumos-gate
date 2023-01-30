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
 * Executor for mac_sw_cksum() ktests.
 *
 * This program builds up the packed nvlist payloads expected by the ktest for
 * mac_sw_cksum().  The caller provides a snoop(1) with one or more packets
 * bearing valid checksums.  Along with the checksum types selected (via option
 * flags), it is passed into the ktest, where it is stripped of its checksums
 * and then run through mac_sw_cksum().  The resulting mblk is compared
 * byte-for-byte with the original input to determine if the emulation generated
 * the correct checksums.
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
const char *mac_cksum_cmd = "";

static void __NORETURN
mac_cksum_usage(void)
{
	(void) fprintf(stderr, "Usage: %s [flags] [opts] <cap_file>\n\n"
	    "Flags:\n"
	    "\t-4\temulate HCK_IPV4_HDRCKSUM\n"
	    "\t-f\temulate HCK_FULLCKSUM\t(cannot be used with -p)\n"
	    "\t-p\temulate HCK_PARTIALCKSUM\t(cannot be used with -f)\n"
	    "\t-e\tsplit mblk after Ethernet header\n"
	    "Options:\n"
	    "\t-b <len>\tpad mblk with <len> bytes (must be even)\n"
	    "\t-s <len>\tsplit mblk after len bytes (must be even)\n"
	    "\t\t\tif -e is specified, will be applied after that split\n"
	    "Arguments:\n"
	    "\t<cap_file> is a snoop capture of packets to test.\n"
	    "\tAny TCP or UDP packets (or plain IPv4) are expected to have\n"
	    "\tcorrect checksums.  The emulated results will be compared\n"
	    "\tagainst those sums in the packet (assuming them proper)\n",
	    mac_cksum_cmd);
	exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
	/* Peel off command name for usage */
	mac_cksum_cmd = basename(argv[0]);
	argc--;
	argv++;
	optind = 0;
	const char *errstr = NULL;

	struct payload_opts popts = { 0 };
	int c;
	while ((c = getopt(argc, argv, "4fpeb:s:")) != -1) {
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

		case '?':
			warnx("unknown option: -%c", optopt);
			mac_cksum_usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1) {
		(void) fprintf(stderr, "cap_file is a required argument\n");
		mac_cksum_usage();
	}

	int fd = open(argv[0], O_RDONLY);
	if (fd < 0) {
		err(EXIT_FAILURE, "could not open cap file %s", argv[0]);
	}

	pkt_cap_iter_t *iter = pkt_cap_open(fd);
	if (iter == NULL) {
		err(EXIT_FAILURE, "unrecognized cap file %s", argv[0]);
	}

	if ((kthdl = ktest_init()) == NULL) {
		err(EXIT_FAILURE, "could not initialize libktest");
	}
	if (!ktest_mod_load("mac")) {
		err(EXIT_FAILURE, "could not load mac ktest module");
	}

	const void *pkt_buf;
	uint_t pkt_sz;
	uint_t count_pass = 0, count_fail = 0, count_skip = 0, idx = 0;
	while (pkt_cap_next(iter, &pkt_buf, &pkt_sz)) {
		ktest_run_req_t req = {
			.krq_module = "mac",
			.krq_suite = "checksum",
			.krq_test = "mac_sw_cksum_test",
		};
		size_t payload_sz;
		char *payload = build_payload(pkt_buf, pkt_sz, NULL, 0,
		    &popts, &payload_sz);
		req.krq_input = (uchar_t *)payload;
		req.krq_input_len = (uint_t)payload_sz;

		ktest_run_result_t result = { 0 };
		if (!ktest_run(kthdl, &req, &result)) {
			err(EXIT_FAILURE, "failure while attempting ktest run");
		}
		free(payload);

		const char *code_name = ktest_code_name(result.krr_code);
		switch (result.krr_code) {
		case KTEST_CODE_PASS:
			count_pass++;
			break;
		case KTEST_CODE_SKIP:
			count_skip++;
			break;
		default:
			count_fail++;
			break;
		}
		(void) printf("%4u\t%s\t(len: %u)\n", idx, code_name, pkt_sz);
		if (result.krr_msg != NULL) {
			if (result.krr_code != KTEST_CODE_PASS) {
				(void) printf("MSG: %s\n", result.krr_msg);
			}
			free(result.krr_msg);
		}
		idx++;
	}
	if (idx == 0) {
		errx(EXIT_FAILURE, "No valid packets found");
	} else if (idx != 1) {
		/* Summarize for > 1 packet */
		(void) printf("SUMMARY: %u PASS, %u SKIP, %u FAIL\n",
		    count_pass, count_skip, count_fail);
	}

	pkt_cap_close(iter);
	ktest_fini(kthdl);

	return (idx == count_pass ? EXIT_SUCCESS : EXIT_FAILURE);
}
