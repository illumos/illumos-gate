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

#ifndef _IMC_TEST_H
#define	_IMC_TEST_H

#include <stdint.h>
#include <inttypes.h>

#include "imc.h"

/*
 * Standard interfaces for the IMC test files.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct imc_test_case {
	const char		*itc_desc;
	uint64_t		itc_pa;
	const imc_t		*itc_imc;
	boolean_t		itc_pass;
	imc_decode_failure_t	itc_fail;
	/*
	 * These will all be checked on the success case unless set to the
	 * respective UINTXX_MAX value.
	 */
	uint32_t		itc_nodeid;
	uint32_t		itc_tadid;
	uint32_t		itc_channelid;
	uint64_t		itc_chanaddr;
	uint32_t		itc_dimmid;
	uint32_t		itc_rankid;
	uint64_t		itc_rankaddr;
} imc_test_case_t;

/*
 * Arrays of tests cases that exist. They are terminated with a NULL itc_desc
 * member.
 */
extern const imc_test_case_t imc_test_basics[];
extern const imc_test_case_t imc_test_badaddr[];
extern const imc_test_case_t imc_test_fail[];
extern const imc_test_case_t imc_test_rir[];
extern const imc_test_case_t imc_test_sad[];
extern const imc_test_case_t imc_test_skx_loop[];
extern const imc_test_case_t imc_test_tad[];


#ifdef __cplusplus
}
#endif

#endif /* _IMC_TEST_H */
