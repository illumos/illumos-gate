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
 * Copyright 2019 Joyent, Inc.
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <err.h>

#include "imc_test.h"

/*
 * Test runner for the IMC driver and its decoder. This operates by creating
 * fake topologies and then building a copy of the decoder into this.
 */

static void
imc_print(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stdout, fmt, ap);
	va_end(ap);
}

static const char *
imc_test_strerror(imc_decode_failure_t fail)
{
	switch (fail) {
	case IMC_DECODE_F_NONE:
		return ("Actually succeeded");
	case IMC_DECODE_F_LEGACY_RANGE:
		return ("Asked to decode legacy address");
	case IMC_DECODE_F_BAD_SOCKET:
		return ("BAD socket data");
	case IMC_DECODE_F_BAD_SAD:
		return ("BAD SAD data");
	case IMC_DECODE_F_OUTSIDE_DRAM:
		return ("Address not DRAM");
	case IMC_DECODE_F_NO_SAD_RULE:
		return ("No valid SAD rule");
	case IMC_DECODE_F_BAD_SAD_INTERLEAVE:
		return ("SAD bad interleave target");
	case IMC_DECODE_F_BAD_REMOTE_MC_ROUTE:
		return ("SAD MC_ROUTE refers to non-existent socket");
	case IMC_DECODE_F_SAD_SEARCH_LOOP:
		return ("SAD search looped");
	case IMC_DECODE_F_SAD_BAD_MOD:
		return ("SAD has a bad mod rule");
	case IMC_DECODE_F_SAD_BAD_SOCKET:
		return ("SAD has a bad Socket target");
	case IMC_DECODE_F_SAD_BAD_TAD:
		return ("SAD has a bad TAD target");
	case IMC_DECODE_F_NO_TAD_RULE:
		return ("No valid TAD rule");
	case IMC_DECODE_F_TAD_3_ILEAVE:
		return ("Unsupported 3-way channel interleave");
	case IMC_DECODE_F_TAD_BAD_TARGET_INDEX:
		return ("Bad TAD target index");
	case IMC_DECODE_F_BAD_CHANNEL_ID:
		return ("Bad channel ID");
	case IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET:
		return ("Bad channel tad offset");
	case IMC_DECODE_F_NO_RIR_RULE:
		return ("No valid rank interleave rule");
	case IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET:
		return ("Bad rank interleave target");
	case IMC_DECODE_F_BAD_DIMM_INDEX:
		return ("Bad DIMM target index");
	case IMC_DECODE_F_DIMM_NOT_PRESENT:
		return ("DIMM not present");
	case IMC_DECODE_F_BAD_DIMM_RANK:
		return ("Bad DIMM rank");
	case IMC_DECODE_F_CHANOFF_UNDERFLOW:
		return ("Channel address offset calculation underflow");
	case IMC_DECODE_F_RANKOFF_UNDERFLOW:
		return ("Rank address offset calculation underflow");
	default:
		return ("<unknown>");
	}
}

static const char *
imc_test_strenum(imc_decode_failure_t fail)
{
	switch (fail) {
	case IMC_DECODE_F_NONE:
		return ("IMC_DECODE_F_NONE");
	case IMC_DECODE_F_LEGACY_RANGE:
		return ("IMC_DECODE_F_LEGACY_RANGE");
	case IMC_DECODE_F_BAD_SOCKET:
		return ("IMC_DECODE_F_BAD_SOCKET");
	case IMC_DECODE_F_BAD_SAD:
		return ("IMC_DECODE_F_BAD_SAD");
	case IMC_DECODE_F_OUTSIDE_DRAM:
		return ("IMC_DECODE_F_OUTSIDE_DRAM");
	case IMC_DECODE_F_NO_SAD_RULE:
		return ("IMC_DECODE_F_NO_SAD_RULE");
	case IMC_DECODE_F_BAD_SAD_INTERLEAVE:
		return ("IMC_DECODE_F_BAD_SAD_INTERLEAVE");
	case IMC_DECODE_F_BAD_REMOTE_MC_ROUTE:
		return ("IMC_DECODE_F_BAD_REMOTE_MC_ROUTE");
	case IMC_DECODE_F_SAD_SEARCH_LOOP:
		return ("IMC_DECODE_F_SAD_SEARCH_LOOP");
	case IMC_DECODE_F_SAD_BAD_MOD:
		return ("IMC_DECODE_F_SAD_BAD_MOD");
	case IMC_DECODE_F_SAD_BAD_SOCKET:
		return ("IMC_DECODE_F_SAD_BAD_SOCKET");
	case IMC_DECODE_F_SAD_BAD_TAD:
		return ("IMC_DECODE_F_SAD_BAD_TAD");
	case IMC_DECODE_F_NO_TAD_RULE:
		return ("IMC_DECODE_F_NO_TAD_RULE");
	case IMC_DECODE_F_TAD_3_ILEAVE:
		return ("IMC_DECODE_F_TAD_3_ILEAVE");
	case IMC_DECODE_F_TAD_BAD_TARGET_INDEX:
		return ("IMC_DECODE_F_TAD_BAD_TARGET_INDEX");
	case IMC_DECODE_F_BAD_CHANNEL_ID:
		return ("IMC_DECODE_F_BAD_CHANNEL_ID");
	case IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET:
		return ("IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET");
	case IMC_DECODE_F_NO_RIR_RULE:
		return ("IMC_DECODE_F_NO_RIR_RULE");
	case IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET:
		return ("IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET");
	case IMC_DECODE_F_BAD_DIMM_INDEX:
		return ("IMC_DECODE_F_BAD_DIMM_INDEX");
	case IMC_DECODE_F_DIMM_NOT_PRESENT:
		return ("IMC_DECODE_F_DIMM_NOT_PRESENT");
	case IMC_DECODE_F_BAD_DIMM_RANK:
		return ("IMC_DECODE_F_BAD_DIMM_RANK");
	case IMC_DECODE_F_CHANOFF_UNDERFLOW:
		return ("IMC_DECODE_F_CHANOFF_UNDERFLOW");
	case IMC_DECODE_F_RANKOFF_UNDERFLOW:
		return ("IMC_DECODE_F_RANKOFF_UNDERFLOW");
	default:
		return ("<unknown>");
	}
}

static uint_t
imc_test_run_one(const imc_test_case_t *test)
{
	imc_decode_state_t dec;
	boolean_t pass;

	imc_print("Running test: %s\n", test->itc_desc);
	imc_print("\tDecoding address: 0x%" PRIx64 "\n", test->itc_pa);

	(void) memset(&dec, '\0', sizeof (dec));
	pass = imc_decode_pa(test->itc_imc, test->itc_pa, &dec);
	if (pass && !test->itc_pass) {
		imc_print("\tdecode unexpectedly succeeded\n");
		imc_print("\texpected error '%s' (%s/0x%x)\n",
		    imc_test_strerror(test->itc_fail),
		    imc_test_strenum(test->itc_fail),
		    test->itc_fail);
		imc_print("\t\tdecoded socket: %u\n", dec.ids_nodeid);
		imc_print("\t\tdecoded tad: %u\n", dec.ids_tadid);
		imc_print("\t\tdecoded channel: %u\n",
		    dec.ids_channelid);
		imc_print("\t\tdecoded channel address: 0x%" PRIx64 "\n",
		    dec.ids_chanaddr);
		imc_print("\t\tdecoded rank: %u\n", dec.ids_rankid);
		imc_print("\t\tdecoded rank address: 0x%" PRIx64 "\n",
		    dec.ids_rankaddr);
		imc_print("\ttest failed\n");

		return (1);
	} else if (pass) {
		uint_t err = 0;

		if (test->itc_nodeid != UINT32_MAX &&
		    test->itc_nodeid != dec.ids_nodeid) {
			imc_print("\tsocket mismatch\n"
			    "\t\texpected %u\n\t\tfound %u\n",
			    test->itc_nodeid, dec.ids_nodeid);
			err |= 1;
		}

		if (test->itc_tadid != UINT32_MAX &&
		    test->itc_tadid != dec.ids_tadid) {
			imc_print("\tTAD mismatch\n"
			    "\t\texpected %u\n\t\tfound %u\n",
			    test->itc_tadid, dec.ids_tadid);
			err |= 1;
		}

		if (test->itc_channelid != UINT32_MAX &&
		    test->itc_channelid != dec.ids_channelid) {
			imc_print("\tchannel mismatch\n"
			    "\t\texpected %u\n\t\tfound %u\n",
			    test->itc_channelid, dec.ids_channelid);
			err |= 1;
		}

		if (test->itc_chanaddr != UINT64_MAX &&
		    test->itc_chanaddr != dec.ids_chanaddr) {
			imc_print("\tchannel address mismatch\n"
			    "\t\texpected 0x%" PRIx64 "\n\t\t"
			    "found 0x%" PRIx64 "\n",
			    test->itc_chanaddr, dec.ids_chanaddr);
			err |= 1;
		}

		if (test->itc_dimmid != UINT32_MAX &&
		    test->itc_dimmid != dec.ids_dimmid) {
			imc_print("\tDIMM mismatch\n"
			    "\t\texpected %u\n\t\tfound %u\n",
			    test->itc_dimmid, dec.ids_dimmid);
			err |= 1;
		}

		if (test->itc_rankid != UINT32_MAX &&
		    test->itc_rankid != dec.ids_rankid) {
			imc_print("\trank mismatch\n"
			    "\t\texpected %u\n\t\tfound %u\n",
			    test->itc_rankid, dec.ids_rankid);
			err |= 1;
		}

		if (test->itc_rankaddr != UINT64_MAX &&
		    test->itc_rankaddr != dec.ids_rankaddr) {
			imc_print("\trank address mismatch\n"
			    "\t\texpected 0x%" PRIx64 "\n\t\t"
			    "found 0x%" PRIx64 "\n",
			    test->itc_rankaddr, dec.ids_rankaddr);
			err |= 1;
		}

		if (err) {
			imc_print("\tDecoding failed\n");
		} else {
			imc_print("\tDecoded successfully\n");
		}

		return (err);
	} else if (!pass && !test->itc_pass) {
		if (dec.ids_fail != test->itc_fail) {
			imc_print("\terror mismatch\n"
			    "\t\texpected '%s' (%s/0x%x)\n\t\tfound '%s' "
			    "(%s/0x%x)\n", imc_test_strerror(test->itc_fail),
			    imc_test_strenum(test->itc_fail), test->itc_fail,
			    imc_test_strerror(dec.ids_fail),
			    imc_test_strenum(dec.ids_fail), dec.ids_fail);
			return (1);
		}

		imc_print("\tCorrect decoding error generated\n");
		return (0);
	} else {
		imc_print("\tdecode failed with '%s' (%s/0x%x)\n",
		    imc_test_strerror(dec.ids_fail),
		    imc_test_strenum(dec.ids_fail),
		    dec.ids_fail);
		if (test->itc_nodeid != UINT32_MAX) {
			imc_print("\t\texpected socket: %u\n",
			    test->itc_nodeid);
		}

		if (test->itc_tadid != UINT32_MAX) {
			imc_print("\t\texpected tad: %u\n", test->itc_tadid);
		}

		if (test->itc_channelid != UINT32_MAX) {
			imc_print("\t\texpected channel: %u\n",
			    test->itc_channelid);
		}

		if (test->itc_chanaddr != UINT64_MAX) {
			imc_print("\t\texpected channel address: 0x%" PRIx64
			    "\n", test->itc_chanaddr);
		}

		if (test->itc_rankid != UINT32_MAX) {
			imc_print("\t\texpected rank: %u\n",
			    test->itc_rankid);
		}

		if (test->itc_rankaddr != UINT64_MAX) {
			imc_print("\t\texpected rank address: 0x%" PRIx64 "\n",
			    test->itc_rankaddr);
		}

		imc_print("\tdecode failed, expected pass\n");

		return (1);
	}
}

static void
imc_test_run(const imc_test_case_t *tests, uint_t *ntests, uint_t *nfail)
{
	while (tests[0].itc_desc != NULL) {
		*nfail += imc_test_run_one(tests);
		*ntests += 1;
		tests++;
	}
}

int
main(int argc, char *argv[])
{
	uint_t ntests = 0, nfail = 0;
	int i;

	if (argc > 1) {
		for (i = 1; i < argc; i++) {
			if (strcmp(argv[i], "basic") == 0) {
				imc_test_run(imc_test_basics, &ntests, &nfail);
			} else if (strcmp(argv[i], "badaddr") == 0) {
				imc_test_run(imc_test_badaddr, &ntests, &nfail);
			} else if (strcmp(argv[i], "sad") == 0) {
				imc_test_run(imc_test_sad, &ntests, &nfail);
			} else if (strcmp(argv[i], "skx_loop") == 0) {
				imc_test_run(imc_test_skx_loop, &ntests,
				    &nfail);
			} else if (strcmp(argv[i], "tad") == 0) {
				imc_test_run(imc_test_tad, &ntests, &nfail);
			} else if (strcmp(argv[i], "rir") == 0) {
				imc_test_run(imc_test_rir, &ntests, &nfail);
			} else if (strcmp(argv[i], "fail") == 0) {
				imc_test_run(imc_test_fail, &ntests, &nfail);
			} else {
				errx(EXIT_FAILURE, "Unknown test argument %s",
				    argv[i]);
			}
		}
	} else {
		imc_test_run(imc_test_basics, &ntests, &nfail);
		imc_test_run(imc_test_badaddr, &ntests, &nfail);
		imc_test_run(imc_test_skx_loop, &ntests, &nfail);
		imc_test_run(imc_test_rir, &ntests, &nfail);
		imc_test_run(imc_test_tad, &ntests, &nfail);
		imc_test_run(imc_test_sad, &ntests, &nfail);
		imc_test_run(imc_test_fail, &ntests, &nfail);
	}

	imc_print("%u/%u tests passed\n", ntests - nfail, ntests);
	return (nfail > 0);
}
