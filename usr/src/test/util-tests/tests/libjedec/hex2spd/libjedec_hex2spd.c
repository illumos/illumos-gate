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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This test goes through and converts data files that are in a semi-custom hex
 * format that represent DIMMs into binary data and then tries to parse the SPD
 * data. It then looks at specific fields and flags from within them. Each
 * module is expected to be parsed error free.
 *
 * Tests are organized in files around the DDR module type generation, e.g.
 * DDR3, DDR4, and DDR5 are all found in different directories. SPD information
 * that we use has been taken from a combination of dumping data from actual
 * modules and transforming them, transforming tables that are distributed by
 * vendors in datasheets and supplemental, and manually creating SPD
 * information based on information in datasheets. In particular, LPDDR in its
 * solder package does not actually include SPD information directly and
 * therefore we have translated it. This is what Intel and AMD have recommended
 * and do for their LPDDR bootstrapping.
 */

#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <strings.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <libnvpair.h>
#include <libjedec.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/debug.h>

#include "libjedec_hex2spd.h"

/*
 * Default directory for data.
 */
#define	SPD_DATA_DIR	"/opt/util-tests/tests/hex2spd"

/*
 * Maximum size we'll tolerate for a file. This corresponds to the largest DDR5
 * SPD.
 */
#define	SPD_MAX	2048

static const hex2spd_test_t *hex2spd_tests[] = {
	&micron_ddr4_rdimm,
	&samsung_ddr4_lrdimm,
	&advantech_ddr4_sodimm,
	&advantech_ddr4_udimm,
	&micron_ddr5_rdimm,
	&advantech_ddr5_rdimm,
	&micron_lp4,
	&nanya_lp3,
	&micron_lp5,
	&fake_lp5_camm2,
	&samsung_ddr3_rdimm,
	&micron_ddr3_lrdimm
};

/*
 * Logic to convert an ASCII file with Hex to SPD data. Each byte of data is
 * expected to be 2 hex digits conventionally arranged 16 bytes across. At any
 * point we encounter a '#' character, we treat that as a comment and ignore the
 * rest of the line. A line will start with an address followed by a ':'.
 */
static void *
hex2spd(const char *path, uint32_t *lenp)
{
	char *buf = NULL;
	size_t buflen = 0;
	uint8_t *out = malloc(SPD_MAX);
	uint32_t outlen = 0, curline = 0;
	FILE *f;

	f = fopen(path, "r");
	if (f == NULL) {
		warnx("INTERNAL TEST ERROR: failed to find test file %s",
		    path);
		free(out);
		return (NULL);
	}

	if (out == NULL) {
		err(EXIT_FAILURE, "failed to allocate %u bytes for buffer",
		    SPD_MAX);
	}

	while (getline(&buf, &buflen, f) != -1) {
		char *comment, *colon;
		unsigned long dataoff;

		curline++;

		if ((comment = strchr(buf, '#')) != NULL) {
			*comment = '\0';
		}

		if (*buf == '\0')
			continue;

		/*
		 * First grab out a line offset marker. This should be in order,
		 * but future us may be end up wanting to skip lots of zeros of
		 * course.
		 */
		errno = 0;
		dataoff = strtoul(buf, &colon, 16);
		if (errno != 0 || *colon != ':' || *(colon + 1) != ' ') {
			errx(EXIT_FAILURE, "failed to parse address part of "
			    "line %u", curline);
		}

		if (dataoff >= SPD_MAX || dataoff % 0x10 != 0) {
			errx(EXIT_FAILURE, "line %u parsed data offset %lu is "
			    "invalid", curline, dataoff);
		}

		/*
		 * We've got the starting data offset. Now go ahead and parse
		 * all the actual data that's in here. We use the max power way.
		 */
		if (sscanf(colon + 2, "%02x %02x %02x %02x %02x %02x %02x %02x "
		    "%02x %02x %02x %02x %02x %02x %02x %02x",
		    &out[dataoff + 0], &out[dataoff + 1], &out[dataoff + 2],
		    &out[dataoff + 3], &out[dataoff + 4], &out[dataoff + 5],
		    &out[dataoff + 6], &out[dataoff + 7], &out[dataoff + 8],
		    &out[dataoff + 9], &out[dataoff + 10], &out[dataoff + 11],
		    &out[dataoff + 12], &out[dataoff + 13], &out[dataoff + 14],
		    &out[dataoff + 15]) != 16) {
			errx(EXIT_FAILURE, "failed to parse data from line %u",
			    curline);
		}

		outlen = MAX(outlen, dataoff + 16);
	}

	*lenp = outlen;
	VERIFY0(fclose(f));
	return (out);
}

static bool
hex2spd_test_one(const char *dir, const hex2spd_test_t *test)
{
	char path[PATH_MAX];
	void *data;
	uint32_t dlen;
	nvlist_t *nvl;
	spd_error_t spd_err;
	bool ret = true;

	if (snprintf(path, sizeof (path), "%s/%s.spd", dir, test->ht_file) >=
	    sizeof (path)) {
		errx(EXIT_FAILURE, "INTERNAL TEST ERROR: constructing test "
		    "path for %s would have overflowed internal buffer",
		    test->ht_file);
	}

	data = hex2spd(path, &dlen);
	if (data == NULL) {
		return (false);
	}

	nvl = libjedec_spd(data, dlen, &spd_err);
	free(data);
	if (spd_err != LIBJEDEC_SPD_OK) {
		warnx("TEST FAILURE: failed to parse %s: 0x%x", path, spd_err);
		return (false);
	}
	(void) printf("TEST PASSED: initially parsed %s\n", test->ht_file);

	/*
	 * Verify there are no errors in this data. This means that we shouldn't
	 * find the errors key or the incomplete key.
	 */
	if (nvlist_exists(nvl, SPD_KEY_ERRS)) {
		warnx("TEST FAILED: %s contains errors:", test->ht_file);
		dump_nvlist(nvl, 0);
		ret = false;
	}

	if (nvlist_exists(nvl, SPD_KEY_INCOMPLETE)) {
		ret = false;
		warnx("TEST FAILED: %s flagged as incomplete:", test->ht_file);
		dump_nvlist(nvl, 0);
	}

	for (const hex2spd_spd_t *spd = &test->ht_checks[0];
	    spd->hs_key != NULL; spd++) {
		int nvret;
		uint_t nents;
		uint8_t *u8a;
		uint32_t u32, *u32a;
		uint64_t u64, *u64a;
		boolean_t *ba;
		char *str;
		bool pass;

		switch (spd->hs_type) {
		case DATA_TYPE_UINT32:
			nvret = nvlist_lookup_uint32(nvl, spd->hs_key, &u32);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
			} else if (u32 != spd->hs_val.hs_u32) {
				warnx("TEST FAILED: %s: key %s: found value "
				    "0x%x, but expected 0x%x", test->ht_file,
				    spd->hs_key, u32, spd->hs_val.hs_u32);
				ret = false;
			} else {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		case DATA_TYPE_UINT64:
			nvret = nvlist_lookup_uint64(nvl, spd->hs_key, &u64);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
			} else if (u64 != spd->hs_val.hs_u64) {
				warnx("TEST FAILED: %s: key %s: found value "
				    "0x%" PRIx64 ", but expected 0x%" PRIx64,
				    test->ht_file, spd->hs_key, u64,
				    spd->hs_val.hs_u64);
				ret = false;
			} else {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		case DATA_TYPE_STRING:
			nvret = nvlist_lookup_string(nvl, spd->hs_key, &str);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
			} else if (strcmp(str, spd->hs_val.hs_str) != 0) {
				warnx("TEST FAILED: %s: key %s: found value "
				    "%s, but expected %s", test->ht_file,
				    spd->hs_key, str, spd->hs_val.hs_str);
				ret = false;
			} else {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		case DATA_TYPE_UINT8_ARRAY:
			nvret = nvlist_lookup_uint8_array(nvl, spd->hs_key,
			    &u8a, &nents);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
				break;
			}

			if (nents != spd->hs_val.hs_u8a.ha_nval) {
				warnx("TEST FAILED: %s: key %s array has 0x%x "
				    "values, but expected 0x%x values",
				    test->ht_file, spd->hs_key, nents,
				    spd->hs_val.hs_u8a.ha_nval);
				ret = false;
				break;
			}

			pass = true;
			for (uint_t i = 0; i < nents; i++) {
				uint8_t targ = spd->hs_val.hs_u8a.ha_vals[i];
				if (u8a[i] != targ) {
					warnx("TEST FAILED: %s: key %s: entry "
					    "[%u] has value 0x%x, but expected "
					    "0x%x", test->ht_file, spd->hs_key,
					    i, u8a[i], targ);
					ret = false;
					pass = false;
				}
			}

			if (pass) {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		case DATA_TYPE_UINT32_ARRAY:
			nvret = nvlist_lookup_uint32_array(nvl, spd->hs_key,
			    &u32a, &nents);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
				break;
			}

			if (nents != spd->hs_val.hs_u32a.ha_nval) {
				warnx("TEST FAILED: %s: key %s array has 0x%x "
				    "values, but expected 0x%x values",
				    test->ht_file, spd->hs_key, nents,
				    spd->hs_val.hs_u32a.ha_nval);
				ret = false;
				break;
			}

			pass = true;
			for (uint_t i = 0; i < nents; i++) {
				uint32_t targ = spd->hs_val.hs_u32a.ha_vals[i];
				if (u32a[i] != targ) {
					warnx("TEST FAILED: %s: key %s: entry "
					    "[%u] has value 0x%x, but expected "
					    "0x%x", test->ht_file, spd->hs_key,
					    i, u32a[i], targ);
					ret = false;
					pass = false;
				}
			}

			if (pass) {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		case DATA_TYPE_UINT64_ARRAY:
			nvret = nvlist_lookup_uint64_array(nvl, spd->hs_key,
			    &u64a, &nents);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
				break;
			}

			if (nents != spd->hs_val.hs_u64a.ha_nval) {
				warnx("TEST FAILED: %s: key %s array has 0x%x "
				    "values, but expected 0x%x values",
				    test->ht_file, spd->hs_key, nents,
				    spd->hs_val.hs_u64a.ha_nval);
				ret = false;
				break;
			}

			pass = true;
			for (uint_t i = 0; i < nents; i++) {
				uint64_t targ = spd->hs_val.hs_u64a.ha_vals[i];
				if (u64a[i] != targ) {
					warnx("TEST FAILED: %s: key %s: entry "
					    "[%u] has value 0x%" PRIx64 ", but "
					    "expected 0x%" PRIx64,
					    test->ht_file, spd->hs_key, i,
					    u64a[i], targ);
					ret = false;
					pass = false;
				}
			}

			if (pass) {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;

		case DATA_TYPE_BOOLEAN:
			nvret = nvlist_lookup_boolean(nvl, spd->hs_key);
			if (spd->hs_val.hs_bool) {
				if (nvret != 0) {
					warnc(nvret, "TEST FAILED: %s: failed "
					    "to lookup key %s", test->ht_file,
					    spd->hs_key);
					ret = false;
				} else {
					(void) printf("TEST PASSED: %s: key %s "
					    "data matches\n", test->ht_file,
					    spd->hs_key);
				}
			} else {
				if (nvret == 0) {
					warnc(nvret, "TEST FAILED: %s: "
					    "successfully lookup up key %s, "
					    "but expected it not to be present",
					    test->ht_file, spd->hs_key);
					ret = false;
				} else if (nvret != ENOENT) {
					warnx("TEST FAILED: %s: failed to "
					    "lookup key %s, but got %s not "
					    "ENOENT", test->ht_file,
					    spd->hs_key,
					    strerrorname_np(nvret));
					ret = false;
				} else {
					(void) printf("TEST PASSED: %s: key %s "
					    "data matches\n", test->ht_file,
					    spd->hs_key);
				}
			}
			break;
		case DATA_TYPE_BOOLEAN_ARRAY:
			nvret = nvlist_lookup_boolean_array(nvl, spd->hs_key,
			    &ba, &nents);
			if (nvret != 0) {
				warnc(nvret, "TEST FAILED: %s: failed to "
				    "lookup key %s", test->ht_file,
				    spd->hs_key);
				ret = false;
				break;
			}

			if (nents != spd->hs_val.hs_ba.ha_nval) {
				warnx("TEST FAILED: %s: key %s array has 0x%x "
				    "values, but expected 0x%x values",
				    test->ht_file, spd->hs_key, nents,
				    spd->hs_val.hs_u32a.ha_nval);
				ret = false;
				break;
			}

			pass = true;
			for (uint_t i = 0; i < nents; i++) {
				boolean_t targ = spd->hs_val.hs_ba.ha_vals[i];
				if (ba[i] != targ) {
					warnx("TEST FAILED: %s: key %s: entry "
					    "[%u] is %s, but expected %s",
					    test->ht_file, spd->hs_key, i,
					    ba[i] ? "true" : "false",
					    targ ? "true" : "false");
					ret = false;
					pass = false;
				}
			}

			if (pass) {
				(void) printf("TEST PASSED: %s: key %s data "
				    "matches\n", test->ht_file, spd->hs_key);
			}
			break;
		default:
			warnx("TEST FAILURE: %s: key %s has unsupported "
			    "data type 0x%x", test->ht_file, spd->hs_key,
			    spd->hs_type);
			ret = false;
			break;
		}
	}

	nvlist_free(nvl);
	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	const char *dir;

	dir = getenv("HEX2SPD_DIR");
	if (dir == NULL) {
		dir = SPD_DATA_DIR;
	}

	for (size_t i = 0; i < ARRAY_SIZE(hex2spd_tests); i++) {
		if (!hex2spd_test_one(dir, hex2spd_tests[i]))
			ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully!\n");
	}
	return (ret);
}
