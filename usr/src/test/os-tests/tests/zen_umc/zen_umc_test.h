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

#ifndef _ZEN_UMC_TEST_H
#define	_ZEN_UMC_TEST_H

/*
 * Common definitions for testing the pieces of zen_umc(4D).
 */

#include "zen_umc.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Fabric ID Composition / Decomposition tests
 */
typedef struct umc_fabric_test {
	const char			*uft_desc;
	const df_fabric_decomp_t	*uft_decomp;
	/*
	 * If uft_compose is true, we will take the socket/die/comp and try to
	 * create a fabric id from it (and then round trip through it again). If
	 * it is false, we will start with the fabric id, decompose, and then
	 * round trip back.
	 */
	boolean_t			uft_compose;
	/*
	 * If uft_valid is not set, we expect that either the fabric id or the
	 * sock/die/comp is invalid based on uft_compose. This will only perform
	 * the initial validity checks instead.
	 */
	boolean_t			uft_valid;
	uint32_t			uft_fabric_id;
	uint32_t			uft_sock_id;
	uint32_t			uft_die_id;
	uint32_t			uft_comp_id;
} umc_fabric_test_t;

/*
 * Test cases for actual decoding!
 */
typedef struct umc_decode_test {
	const char			*udt_desc;
	const zen_umc_t			*udt_umc;
	uint64_t			udt_pa;
	boolean_t			udt_pass;
	/*
	 * When udt_pass is set to B_FALSE, then the following member will be
	 * checked to ensure that we got the right thing. Otherwise it'll be
	 * skipped.
	 */
	zen_umc_decode_failure_t	udt_fail;
	/*
	 * When udt_pass is set to true, the following will all be checked. If
	 * you wish to skip one, set it to its corresponding UINTXX_MAX.
	 */
	uint64_t			udt_norm_addr;
	uint8_t				udt_sock;
	uint8_t				udt_die;
	uint8_t				udt_comp;
	uint32_t			udt_dimm_no;
	uint32_t			udt_dimm_col;
	uint32_t			udt_dimm_row;
	uint8_t				udt_dimm_bank;
	uint8_t				udt_dimm_bank_group;
	uint8_t				udt_dimm_subchan;
	uint8_t				udt_dimm_rm;
	uint8_t				udt_dimm_cs;
} umc_decode_test_t;

extern const umc_fabric_test_t zen_umc_test_fabric_ids[];

extern const umc_decode_test_t zen_umc_test_basics[];
extern const umc_decode_test_t zen_umc_test_chans[];
extern const umc_decode_test_t zen_umc_test_cod[];
extern const umc_decode_test_t zen_umc_test_errors[];
extern const umc_decode_test_t zen_umc_test_hole[];
extern const umc_decode_test_t zen_umc_test_ilv[];
extern const umc_decode_test_t zen_umc_test_multi[];
extern const umc_decode_test_t zen_umc_test_nps[];
extern const umc_decode_test_t zen_umc_test_remap[];
extern const umc_decode_test_t zen_umc_test_nps_k[];
extern const umc_decode_test_t zen_umc_test_np2_k[];

#ifdef __cplusplus
}
#endif

#endif /* _ZEN_UMC_TEST_H */
