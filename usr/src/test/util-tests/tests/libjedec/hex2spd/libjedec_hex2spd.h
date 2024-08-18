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

#ifndef _LIBJEDEC_HEX2SPD_H
#define	_LIBJEDEC_HEX2SPD_H

/*
 * Common definitions for the hex2spd test.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <libnvpair.h>
#include <stdint.h>
#include <stdbool.h>

/*
 * This is an arbitrary value to give us an upper bound on the number of array
 * entries that we'll support. Currently the largest array we have is 15 entries
 * which is the DDR3 LRDIMM personality bytes.
 */
#define	HEX2SPD_ARR_MAX	16

/*
 * Represents an individual check against a particular nvlist_t payload. The
 * data type is the nvlist_t type of the key. The corresponding value will be
 * used.
 */
typedef struct {
	const char *hs_key;
	data_type_t hs_type;
	union {
		uint32_t hs_u32;
		uint64_t hs_u64;
		const char *hs_str;
		bool hs_bool;
		struct {
			uint32_t ha_nval;
			uint8_t ha_vals[HEX2SPD_ARR_MAX];
		} hs_u8a;
		struct {
			uint32_t ha_nval;
			uint32_t ha_vals[HEX2SPD_ARR_MAX];
		} hs_u32a;
		struct {
			uint32_t ha_nval;
			uint64_t ha_vals[HEX2SPD_ARR_MAX];
		} hs_u64a;
		struct {
			uint32_t ha_nval;
			boolean_t ha_vals[HEX2SPD_ARR_MAX];
		} hs_ba;
	} hs_val;
} hex2spd_spd_t;

/*
 * Represents a set of tests to run against a specific SPD file. The last of the
 * checks should have a key of NULL to indicate the end of the run.
 */
typedef struct {
	const char *ht_file;
	hex2spd_spd_t ht_checks[];
} hex2spd_test_t;

extern const hex2spd_test_t samsung_ddr3_rdimm;
extern const hex2spd_test_t micron_ddr3_lrdimm;

extern const hex2spd_test_t micron_ddr4_rdimm;
extern const hex2spd_test_t samsung_ddr4_lrdimm;
extern const hex2spd_test_t advantech_ddr4_sodimm;
extern const hex2spd_test_t advantech_ddr4_udimm;

extern const hex2spd_test_t micron_ddr5_rdimm;
extern const hex2spd_test_t advantech_ddr5_rdimm;

extern const hex2spd_test_t nanya_lp3;
extern const hex2spd_test_t micron_lp4;
extern const hex2spd_test_t micron_lp5;
extern const hex2spd_test_t fake_lp5_camm2;

#ifdef __cplusplus
}
#endif

#endif /* _LIBJEDEC_HEX2SPD_H */
