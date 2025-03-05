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
 * Copyright 2025 Oxide Computer Company
 */

#ifndef _LIBKTEST_IMPL_H
#define	_LIBKTEST_IMPL_H

#include <sys/ktest.h>
#include <libktest.h>
#include <sys/debug.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KTEST_DEV_PATH		"/dev/ktest"

struct ktest_hdl {
	int	kt_fd;
};

struct ktest_list_iter {
	ktest_hdl_t	*kli_hdl;

	nvlist_t	*kli_modules;
	nvpair_t	*kli_module;
	nvlist_t	*kli_suites;
	nvpair_t	*kli_suite;
	nvlist_t	*kli_tests;
	nvpair_t	*kli_test;
	boolean_t	kli_req_input;
};

CTASSERT((int)KTEST_CODE_NONE == (int)KTEST_RESULT_NONE);
CTASSERT((int)KTEST_CODE_PASS == (int)KTEST_RESULT_PASS);
CTASSERT((int)KTEST_CODE_FAIL == (int)KTEST_RESULT_FAIL);
CTASSERT((int)KTEST_CODE_SKIP == (int)KTEST_RESULT_SKIP);
CTASSERT((int)KTEST_CODE_ERROR == (int)KTEST_RESULT_ERROR);


#ifdef __cplusplus
}
#endif

#endif /* _LIBKTEST_IMPL_H */
