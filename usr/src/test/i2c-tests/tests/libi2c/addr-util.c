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
 * Test our favorite things: parsing addresses and turning them back into
 * strings.
 */

#include <err.h>
#include <string.h>
#include <sys/sysmacros.h>

#include "libi2c_test_util.h"

typedef struct addr_map {
	const char *am_str;
	const char *am_comp;
	uint16_t am_type;
	uint16_t am_addr;
} addr_map_t;

/*
 * The system always outputs addresses in hex, so we have an optional second
 * form that indicates what we expect back.
 */
static const addr_map_t roundtrip_addrs[] = {
	{ "0x23", NULL, I2C_ADDR_7BIT, 0x23 },
	{ "0x10", NULL, I2C_ADDR_7BIT, 0x10 },
	{ "0x7f", NULL, I2C_ADDR_7BIT, 0x7f },
	{ "30", "0x1e", I2C_ADDR_7BIT, 0x1e },
	{ "0x9", "0x09", I2C_ADDR_7BIT, 0x09 },
	{ "10b,0", "10b,0x000", I2C_ADDR_10BIT, 0x0 },
	{ "10b,0x3ff", NULL, I2C_ADDR_10BIT, 0x3ff },
	{ "10b,0x169", NULL, I2C_ADDR_10BIT, 0x169 },
	{ "10b,777", "10b,0x309", I2C_ADDR_10BIT, 0x309 }
};

typedef struct bad_str {
	const char *bs_str;
	i2c_err_t bs_err;
} bad_str_t;

static const bad_str_t bad_strs[] = {
	{ "hello", I2C_ERR_BAD_ADDR },
	{ "0x", I2C_ERR_BAD_ADDR },
	{ "0x3456789", I2C_ERR_BAD_ADDR },
	{ "0x23nope", I2C_ERR_BAD_ADDR },
	{ "2b", I2C_ERR_BAD_ADDR },
	{ "0x2bornot2b", I2C_ERR_BAD_ADDR },
	{ "0x80", I2C_ERR_BAD_ADDR },
	{ "256", I2C_ERR_BAD_ADDR },
	{ "-4", I2C_ERR_BAD_ADDR },
	{ "0x23;0x34", I2C_ERR_BAD_ADDR },
	{ "10b,its", I2C_ERR_BAD_ADDR },
	{ "10b,0xa ", I2C_ERR_BAD_ADDR },
	{ "10b,123\ttrap", I2C_ERR_BAD_ADDR },
	{ "10b,-23", I2C_ERR_BAD_ADDR },
	{ "foo,0x12", I2C_ERR_BAD_ADDR_TYPE },
	{ ",0x12", I2C_ERR_BAD_ADDR_TYPE },
	{ "10b2,0x12", I2C_ERR_BAD_ADDR_TYPE },
};

typedef struct bad_addr {
	uint16_t ba_type;
	uint16_t ba_addr;
	i2c_err_t ba_err;
} bad_addr_t;

/*
 * Unlike other cases, reserved addresses aren't part of this as we will parse
 * any address, regardless if it's reserved for some reason.
 */
static const bad_addr_t bad_addrs[] = {
	{ I2C_ADDR_7BIT, 0x80, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_7BIT, 0x7777, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_7BIT, INT16_MAX, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_10BIT, 0x400, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_10BIT, 0x7777, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_10BIT, 0x2bb2, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_10BIT, UINT16_MAX, I2C_ERR_BAD_ADDR },
	{ I2C_ADDR_10BIT + 1, 0x0, I2C_ERR_BAD_ADDR_TYPE },
	{ I2C_ADDR_10BIT + 1, 0x23, I2C_ERR_BAD_ADDR_TYPE },
	{ 0x42, 0x23, I2C_ERR_BAD_ADDR_TYPE },
	{ 0x7777, 0x7777, I2C_ERR_BAD_ADDR_TYPE },
	{ INT16_MAX, UINT16_MAX, I2C_ERR_BAD_ADDR_TYPE },
};

static bool
valid_addr_roundtrip(i2c_hdl_t *hdl)
{
	bool ret = true;

	for (size_t i = 0; i < ARRAY_SIZE(roundtrip_addrs); i++) {
		const addr_map_t *map = &roundtrip_addrs[i];
		char buf[128];
		i2c_addr_t addr;

		if (!i2c_addr_parse(hdl, map->am_str, &addr)) {
			libi2c_test_warn(hdl, "TEST FAILED: failed to parse "
			    "string %s", map->am_str);
			ret = false;
		} else {
			bool valid = true;
			if (map->am_type != addr.ia_type) {
				warnx("TEST FAILED: parsed string %s address "
				    "type as 0x%x, expected 0x%x", map->am_str,
				    addr.ia_type, map->am_type);
				valid = false;
			}

			if (map->am_addr != addr.ia_addr) {
				warnx("TEST FAILED: parsed string %s address "
				    "as 0x%x, expected 0x%x", map->am_str,
				    addr.ia_addr, map->am_addr);
				valid = false;
			}

			if (valid) {
				(void) printf("TEST PASSED: successful "
				    "str->addr of %s\n", map->am_str);
			}
		}

		addr.ia_type = map->am_type;
		addr.ia_addr = map->am_addr;
		const char *comp = map->am_comp != NULL ? map->am_comp :
		    map->am_str;
		if (!i2c_addr_to_string(hdl, &addr, buf, sizeof (buf))) {
			libi2c_test_warn(hdl, "TEST FAILED: failed to "
			    "transform address 0x%x,0x%x to a string",
			    map->am_type, map->am_addr);
			ret = false;
		} else if (strcmp(buf, comp) != 0) {
			libi2c_test_warn(hdl, "TEST FAILED: parsed 0x%x,0x%x "
			    "to %s, but expected %s", map->am_type,
			    map->am_addr, buf, comp);
			ret = false;
		} else {
			(void) printf("TEST PASSED: successful addr->str of "
			    "%s\n", map->am_str);
		}
	}

	return (ret);
}

static bool
invalid_strings(i2c_hdl_t *hdl)
{
	bool ret = true;

	for (size_t i = 0; i < ARRAY_SIZE(bad_strs); i++) {
		i2c_addr_t addr;

		if (i2c_addr_parse(hdl, bad_strs[i].bs_str, &addr)) {
			warnx("TEST FAILED: incorrectly parsed string %s "
			    "as a valid address", bad_strs[i].bs_str);
			ret = false;
			continue;
		}

		i2c_err_t err = i2c_err(hdl);
		if (err != bad_strs[i].bs_err) {
			warnx("TEST FAILED: parsing address string %s returned "
			    "%s (0x%x) but expected %s (0x%x)",
			    bad_strs[i].bs_str, i2c_errtostr(hdl, err), err,
			    i2c_errtostr(hdl, bad_strs[i].bs_err),
			    bad_strs[i].bs_err);
			ret = false;
		} else {
			(void) printf("TEST PASSED: failed to parse address %s "
			    "with error %s (0x%x)\n", bad_strs[i].bs_str,
			    i2c_errtostr(hdl, err), err);
		}
	}

	return (ret);
}

static bool
invalid_addrs(i2c_hdl_t *hdl)
{
	bool ret = true;

	for (size_t i = 0; i < ARRAY_SIZE(bad_addrs); i++) {
		char buf[128];
		i2c_addr_t addr;

		addr.ia_type = bad_addrs[i].ba_type;
		addr.ia_addr = bad_addrs[i].ba_addr;
		if (i2c_addr_to_string(hdl, &addr, buf, sizeof (buf))) {
			warnx("TEST FAILED: unexpectedly parsed 0x%x,0x%x "
			    "as a valid string", addr.ia_type, addr.ia_addr);
			ret = false;
			continue;
		}

		i2c_err_t err = i2c_err(hdl);
		if (err != bad_addrs[i].ba_err) {
			warnx("TEST FAILED: parsing address 0x%x,0x%x failed "
			    "with %s (0x%x) but expected %s (0x%x)",
			    addr.ia_type, addr.ia_addr, i2c_errtostr(hdl, err),
			    err, i2c_errtostr(hdl, bad_addrs[i].ba_err),
			    bad_addrs[i].ba_err);
			ret = false;
		} else {
			(void) printf("TEST PASSED: failed to parse address "
			    "0x%x,0x%x with error %s (0x%x)\n", addr.ia_type,
			    addr.ia_addr, i2c_errtostr(hdl, err), err);
		}
	}

	return (ret);
}

static bool
short_buffers(i2c_hdl_t *hdl)
{
	bool ret = true;
	char buf[32];
	i2c_addr_t addr = { I2C_ADDR_7BIT, 0x23 };

	if (i2c_addr_to_string(hdl, &addr, buf, 0)) {
		warnx("TEST FAILED: i2c_addr_to_string() with zero sized "
		    "buffer unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BUF_TOO_SMALL) {
		warnx("TEST FAILED: i2c_addr_to_string() with zero sized "
		    "buffer failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BUF_TOO_SMALL (0x%x)", i2c_errtostr(hdl,
		    i2c_err(hdl)), i2c_err(hdl), I2C_ERR_BUF_TOO_SMALL);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_to_string() fails "
		    "correctly with zero sized buffer\n");
	}

	if (i2c_addr_to_string(hdl, &addr, buf, 2)) {
		warnx("TEST FAILED: i2c_addr_to_string() with short buffer "
		    "unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BUF_TOO_SMALL) {
		warnx("TEST FAILED: i2c_addr_to_string() with short buffer "
		    "failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BUF_TOO_SMALL (0x%x)", i2c_errtostr(hdl,
		    i2c_err(hdl)), i2c_err(hdl), I2C_ERR_BUF_TOO_SMALL);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_to_string() fails "
		    "correctly with short buffer\n");
	}

	return (ret);
}

static bool
bad_args(i2c_hdl_t *hdl)
{
	bool ret = true;
	char buf[32] = { 0 };
	i2c_addr_t addr;

	if (i2c_addr_to_string(hdl, NULL, buf, sizeof (buf))) {
		warnx("TEST FAILED: i2c_addr_to_string() with NULL address "
		    "unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BAD_PTR) {
		warnx("TEST FAILED: i2c_addr_to_string() with NULL address "
		    "failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BAD_PTR (0x%x)", i2c_errtostr(hdl, i2c_err(hdl)),
		    i2c_err(hdl), I2C_ERR_BAD_PTR);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_to_string() handles "
		    "NULL address correctly\n");
	}

	if (i2c_addr_to_string(hdl, &addr, NULL, 0)) {
		warnx("TEST FAILED: i2c_addr_to_string() with NULL buffer "
		    "unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BAD_PTR) {
		warnx("TEST FAILED: i2c_addr_to_string() with NULL buffer "
		    "failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BAD_PTR (0x%x)", i2c_errtostr(hdl, i2c_err(hdl)),
		    i2c_err(hdl), I2C_ERR_BAD_PTR);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_to_string() handles "
		    "NULL buffer correctly\n");
	}

	if (i2c_addr_parse(hdl, buf, NULL)) {
		warnx("TEST FAILED: i2c_addr_parse() with NULL address "
		    "unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BAD_PTR) {
		warnx("TEST FAILED: i2c_addr_parse() with NULL address "
		    "failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BAD_PTR (0x%x)", i2c_errtostr(hdl, i2c_err(hdl)),
		    i2c_err(hdl), I2C_ERR_BAD_PTR);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_parse() handles "
		    "NULL address correctly\n");
	}

	if (i2c_addr_parse(hdl, NULL, &addr)) {
		warnx("TEST FAILED: i2c_addr_parse() with NULL string "
		    "unexpectedly worked");
		ret = false;
	} else if (i2c_err(hdl) != I2C_ERR_BAD_PTR) {
		warnx("TEST FAILED: i2c_addr_parse() with NULL string "
		    "failed with wrong code %s (0x%x), expected "
		    "I2C_ERR_BAD_PTR (0x%x)", i2c_errtostr(hdl, i2c_err(hdl)),
		    i2c_err(hdl), I2C_ERR_BAD_PTR);
		ret = false;
	} else {
		(void) printf("TEST PASSED: i2c_addr_parse() handles "
		    "NULL string correctly\n");
	}

	return (ret);
}

static bool
reserved_addrs(i2c_hdl_t *hdl)
{
	bool ret = true;

	for (i2c_rsvd_addr_t ra = I2C_RSVD_ADDR_GEN_CALL;
	    ra <= I2C_RSVD_ADDR_HS_3; ra++) {
		i2c_addr_t addr = { I2C_ADDR_7BIT, ra };
		if (!i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 7-bit 0x%02x mistakenly thought "
			    "as not reserved", ra);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 7-bit 0x%02x is correctly "
			    "considered a reserved address\n", ra);
		}

		addr.ia_type = I2C_ADDR_10BIT;
		if (!i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 10-bit 0x%02x mistakenly thought "
			    "as not reserved", ra);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 10-bit 0x%02x is correctly "
			    "considered a reserved address\n", ra);
		}
	}

	for (i2c_rsvd_addr_t ra = I2C_RSVD_ADDR_10B_0;
	    ra <= I2C_RSVD_ADDR_DID_3; ra++) {
		i2c_addr_t addr = { I2C_ADDR_7BIT, ra };
		if (!i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 7-bit 0x%02x mistakenly thought "
			    "as not reserved", ra);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 7-bit 0x%02x is correctly "
			    "considered a reserved address\n", ra);
		}

		addr.ia_type = I2C_ADDR_10BIT;
		if (!i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 10-bit 0x%02x mistakenly thought "
			    "as not reserved", ra);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 10-bit 0x%02x is correctly "
			    "considered a reserved address\n", ra);
		}
	}

	uint16_t unrsvd_addrs[] = { 0x9, 0x17, 0x23, 0x42, 0x70 };
	for (size_t i = 0; i < ARRAY_SIZE(unrsvd_addrs); i++) {
		i2c_addr_t addr = { I2C_ADDR_7BIT, unrsvd_addrs[i] };
		if (i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 7-bit 0x%02x mistakenly thought "
			    "as reserved", unrsvd_addrs[i]);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 7-bit 0x%02x is correctly "
			    "not a reserved address\n", unrsvd_addrs[i]);
		}

		addr.ia_type = I2C_ADDR_10BIT;
		if (i2c_addr_reserved(&addr)) {
			warnx("TEST FAILED: 10-bit 0x%03x mistakenly thought "
			    "as reserved", unrsvd_addrs[i]);
			ret = false;
		} else {
			(void) printf("TEST PASSED: 10-bit 0x%03x is correctly "
			    "not a reserved address\n", unrsvd_addrs[i]);
		}
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	i2c_hdl_t *hdl = i2c_init();
	if (hdl == NULL) {
		err(EXIT_FAILURE, "INTERNAL TEST FAILURE: failed to create "
		    "libi2c handle");
	}

	if (!valid_addr_roundtrip(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!invalid_strings(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!invalid_addrs(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!short_buffers(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!bad_args(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (!reserved_addrs(hdl)) {
		ret = EXIT_FAILURE;
	}

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}
	i2c_fini(hdl);
	return (ret);
}
