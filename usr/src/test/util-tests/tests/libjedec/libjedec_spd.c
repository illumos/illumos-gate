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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * This constructs various failure cases for our SPD parsing logic and ensures
 * that we can catch them.
 */

#include <err.h>
#include <stdlib.h>
#include <sys/sysmacros.h>
#include <libjedec.h>

typedef struct {
	uint8_t lst_data[1024];
	size_t lst_len;
	spd_error_t lst_err;
	const char *lst_desc;
	boolean_t (*lst_check)(nvlist_t *);
} libjedec_spd_test_t;

/*
 * The test in question only specifies 0x10 bytes. This means we should have a
 * valid errors nvl with an incomplete entry.
 */
static boolean_t
spd_check_short_ddr4(nvlist_t *nvl)
{
	int ret;
	uint32_t inc;

	if ((ret = nvlist_lookup_uint32(nvl, SPD_KEY_INCOMPLETE,
	    &inc)) != 0) {
		warnc(ret, "failed to lookup incomplete key");
		return (B_FALSE);
	}

	if (inc != 0x11) {
		warnx("incomplete key has unexpected offset: expected %u, "
		    "found %u", 0x11, inc);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
spd_check_single_err(nvlist_t *nvl, const char *key, spd_error_kind_t kind)
{
	int ret;
	nvlist_t *check;
	uint32_t code;
	char *msg;
	boolean_t pass = B_TRUE;

	if ((ret = nvlist_lookup_nvlist(nvl, key, &check)) != 0) {
		warnc(ret, "failed to lookup key %s in error nvlist", key);
		dump_nvlist(nvl, 4);
		return (B_FALSE);
	}

	if ((ret = nvlist_lookup_string(check, SPD_KEY_ERRS_MSG, &msg)) != 0) {
		warnc(ret, "missing error message for error key %s", key);
		dump_nvlist(check, 6);
		pass = B_FALSE;
	}

	if ((ret = nvlist_lookup_uint32(check, SPD_KEY_ERRS_CODE,
	    &code)) != 0) {
		warnc(ret, "missing error number for error key %s", key);
		dump_nvlist(check, 6);
		pass = B_FALSE;
	} else if (code != kind) {
		warnx("found wrong error kind for error key %s: expected 0x%x, "
		    "found 0x%x", key, kind, code);
		pass = B_FALSE;
	}

	nvlist_free(check);
	return (pass);
}

/*
 * This goes through and checks for a number of error codes being set as
 * expected. Note, we check that the message exists, but we don't validate its
 * contents in any way. Because we're using all zero data, we can expect to find
 * a number of different cases.
 */
static boolean_t
spd_check_misc_errors(nvlist_t *nvl)
{
	int ret;
	nvlist_t *errs;
	boolean_t pass = B_TRUE;

	if ((ret = nvlist_lookup_nvlist(nvl, SPD_KEY_ERRS, &errs)) != 0) {
		warnc(ret, "failed to lookup errors nvlist");
		return (B_FALSE);
	}

	if (!spd_check_single_err(errs, SPD_KEY_MFG_DRAM_MFG_NAME,
	    SPD_ERROR_NO_XLATE) ||
	    !spd_check_single_err(errs, SPD_KEY_CRC_DDR4_BASE,
	    SPD_ERROR_BAD_DATA) ||
	    !spd_check_single_err(errs, SPD_KEY_MFG_MOD_PN,
	    SPD_ERROR_UNPRINT) ||
	    !spd_check_single_err(errs, SPD_KEY_TRCD_MIN, SPD_ERROR_NO_XLATE)) {
		pass = B_FALSE;
	}


	nvlist_free(errs);
	return (pass);
}

static const libjedec_spd_test_t spd_tests[] = {
	{ .lst_data = {}, .lst_len = 0, .lst_err = LIBJEDEC_SPD_TOOSHORT,
	    .lst_desc = "Invalid SPD Data (zero length)" },
	{ .lst_data = { 0x00, 0x10, SPD_DT_DDR_SGRAM, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_TYPE, .lst_desc = "Unsupported "
	    "SPD type (DDR SGRAM)" },
	{ .lst_data = { 0x00, 0x10, 0x42, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_TYPE, .lst_desc = "Unknown "
	    "SPD type (0x42)" },
	{ .lst_data = { 0x00, 0x00, SPD_DT_DDR4_SDRAM, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_REV, .lst_desc = "Bad DDR4 "
	    "Revision (0x00)" },
	{ .lst_data = { 0x00, 0x54, SPD_DT_DDR4_SDRAM, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_REV, .lst_desc = "Bad DDR4 "
	    "Revision (0x54)" },
	{ .lst_data = { 0x00, 0x00, SPD_DT_DDR5_SDRAM, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_REV, .lst_desc = "Bad DDR4 "
	    "Revision (0x00)" },
	{ .lst_data = { 0x00, 0xb2, SPD_DT_DDR5_SDRAM, 0x00 }, .lst_len = 4,
	    .lst_err = LIBJEDEC_SPD_UNSUP_REV, .lst_desc = "Bad DDR5 "
	    "Revision (0xb2)" },
	{ .lst_data = { 0x00, 0x10, SPD_DT_DDR5_SDRAM, 0x00 }, .lst_len = 0xc3,
	    .lst_err = LIBJEDEC_SPD_UNSUP_REV, .lst_desc = "Bad DDR5 Common "
	    "Revision (0x00)" },
	{ .lst_data = { 0x00, 0x10, SPD_DT_DDR4_SDRAM, 0x00 }, .lst_len = 0x10,
	    .lst_err = LIBJEDEC_SPD_OK, .lst_desc = "Catch incomplete errors",
	    .lst_check = spd_check_short_ddr4 },
	{ .lst_data = { 0x00, 0x10, SPD_DT_DDR4_SDRAM, 0x00 }, .lst_len = 0x200,
	    .lst_err = LIBJEDEC_SPD_OK, .lst_desc = "Non-fatal parsing errors",
	    .lst_check = spd_check_misc_errors },

};

static boolean_t
libjedec_spd_test(const libjedec_spd_test_t *test)
{
	nvlist_t *nvl;
	spd_error_t err;
	boolean_t pass = B_TRUE;

	nvl = libjedec_spd(test->lst_data, test->lst_len, &err);
	if (err != test->lst_err) {
		warnx("found mismatched error: expected 0x%x, found 0x%x",
		    test->lst_err, err);
		pass = B_FALSE;
	}

	if (nvl != NULL) {
		if (test->lst_err != LIBJEDEC_SPD_OK) {
			warnx("expected fatal error (0x%x), but somehow got "
			    "an nvlist! Contents:", test->lst_err);
			dump_nvlist(nvl, 4);
			pass = B_FALSE;
		}
	} else {
		if (test->lst_err == LIBJEDEC_SPD_OK) {
			warnx("expected an nvlist_t, but didn't get one: "
			    "actual spd_error_t: 0x%x", err);
			pass = B_FALSE;
		}
	}

	if (pass && test->lst_check) {
		pass = test->lst_check(nvl);
	}

	return (pass);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;

	for (size_t i = 0; i < ARRAY_SIZE(spd_tests); i++) {
		const libjedec_spd_test_t *test = &spd_tests[i];

		if (!libjedec_spd_test(test)) {
			(void) fprintf(stderr, "TEST FAILED: %s\n",
			    test->lst_desc);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s\n", test->lst_desc);
		}
	}

	return (ret);
}
