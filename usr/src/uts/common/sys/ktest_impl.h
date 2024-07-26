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
 * This file contains the private implementation details of the ktest
 * facility -- which is limited strictly to the kernel. Neither
 * userspace nor ktest modules should include this file or rely on any
 * definitions herein. Rather, userspace programs and ktest modules
 * should include sys/ktest.h for access to the appropriate APIs.
 */
#ifndef	_SYS_KTEST_IMPL_H
#define	_SYS_KTEST_IMPL_H

#include <sys/ktest.h>
#include <sys/list.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _KERNEL

typedef struct ktest_module {
	list_node_t	km_node;
	char		km_name[KTEST_MAX_NAME_LEN];
	uint64_t	km_num_suites;
	uint64_t	km_num_tests;
	list_t		km_suites;
} ktest_module_t;

typedef struct ktest_suite {
	list_node_t	ks_node;
	ktest_module_t	*ks_module;
	char		ks_name[KTEST_MAX_NAME_LEN];
	uint64_t	ks_num_tests;
	list_t		ks_tests;
} ktest_suite_t;

typedef struct ktest_test {
	list_node_t	kt_node;
	ktest_suite_t	*kt_suite;
	char		kt_name[KTEST_MAX_NAME_LEN];
	ktest_fn_t	kt_fn;
	boolean_t	kt_requires_input;
} ktest_test_t;

typedef struct ktest_ctx {
	const ktest_test_t	*ktc_test;
	ktest_result_t		*ktc_res;
	uchar_t			*ktc_input;
	uint64_t		ktc_input_len;
} ktest_ctx_t;

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KTEST_IMPL_H */
