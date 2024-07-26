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
 * Copyright 2024 Ryan Zezeski
 */

/*
 * This file defines both the userspace ioctl API/ABI as well as the
 * ktest module API/ABI. The latter is everything hidden behind the
 * _KERNEL guard.
 */
#ifndef	_SYS_KTEST_H
#define	_SYS_KTEST_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/param.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	KTEST_SEPARATOR		":"
#define	KTEST_DEF_TRIPLE	"*:*:*"
#define	KTEST_DEF_TRIPLE_SZ	6
#define	KTEST_MAX_NAME_LEN	64
#define	KTEST_MAX_TRIPLE_LEN	((KTEST_MAX_NAME_LEN * 3) + 3)
#define	KTEST_MAX_LOG_LEN	4096
#define	KTEST_NAME_KEY		"name"
#define	KTEST_MODULE_KEY	"module"
#define	KTEST_MODULE_SUITES_KEY	"suites"
#define	KTEST_SUITE_KEY		"suite"
#define	KTEST_SUITE_TESTS_KEY	"tests"
#define	KTEST_TEST_KEY		"test"
#define	KTEST_TEST_INPUT_KEY	"input_required"
#define	KTEST_GMATCH_CHARS	"*?[]"

#define	KTEST_SER_FMT_KEY	"ser_fmt_version"
#define	KTEST_SER_FMT_VSN	1ULL

/*
 * The maximum amount of memory a user ioctl could require ktest to
 * allocate in order to respond to the request. This doesn't include
 * the actions of the test themselves. It's more to prevent a
 * negligent ioctl directly causing ktest to kmem_alloc(9F) an
 * arbitrarily large buffer.
 *
 * This also currently includes any input streams for a test, thus the
 * cap is larger than you might expect it would be. In the future we
 * should have the ktest driver directly read the file from kernel
 * space, but for now we pass them as part of the packed nvlist via
 * the ioctl interface.
 */
#define	KTEST_IOCTL_MAX_LEN	(64 * 1024 * 1024)

#define	KTEST_IOCTL	(('k' << 16) | ('t' << 8))

typedef enum ktest_ioctl {
	KTEST_IOCTL_RUN_TEST	= (KTEST_IOCTL | 1),
	KTEST_IOCTL_LIST_TESTS	= (KTEST_IOCTL | 2),
} ktest_ioctl_t;

/*
 * Flags used to alter the behavior of ktest or convey additional
 * information about the test. Passed as the final argument to
 * ktest_add_test(9F).
 *
 * KTEST_FLAG_INPUT
 *
 *    This test requires an input stream.
 *
 */
typedef enum ktest_test_flags {
	KTEST_FLAG_NONE	= 0,
	KTEST_FLAG_INPUT	= (1 << 0),
} ktest_test_flags_t;

/*
 * See the ktest architecture comment in ktest.c for the semantics of
 * these values. The KTEST_RESULT_NONE value indicates that the test
 * failed to set a result and should be considered a bug in the test.
 */
typedef enum ktest_result_type {
	KTEST_RESULT_NONE,
	KTEST_RESULT_PASS,
	KTEST_RESULT_FAIL,
	KTEST_RESULT_SKIP,
	KTEST_RESULT_ERROR
} ktest_result_type_t;

/* The result of a single test. */
typedef struct ktest_result {
	char			kr_msg_prepend[KTEST_MAX_LOG_LEN];
	char			kr_msg[KTEST_MAX_LOG_LEN];
	ktest_result_type_t	kr_type;
	int			kr_line;
} ktest_result_t;

typedef struct ktest_run_op {
	char		kro_module[KTEST_MAX_NAME_LEN];
	char		kro_suite[KTEST_MAX_NAME_LEN];
	char		kro_test[KTEST_MAX_NAME_LEN];
	char		kro_input_path[MAXPATHLEN];
	uchar_t		*kro_input_bytes;
	uint64_t	kro_input_len;
	ktest_result_t	kro_result;
} ktest_run_op_t;

typedef struct ktest_list_op {
	char		*klo_resp;
	size_t		klo_resp_len;
} ktest_list_op_t;

/*
 * The following API/ABI is for the ktest modules.
 */
#ifdef _KERNEL

typedef struct __ktest_module_hdl ktest_module_hdl_t;
typedef struct __ktest_suite_hdl ktest_suite_hdl_t;
typedef struct __ktest_test_hdl ktest_test_hdl_t;
typedef struct __ktest_ctx_hdl ktest_ctx_hdl_t;

typedef void (*ktest_fn_t)(ktest_ctx_hdl_t *);

/*
 * Module, suite, and test creation/registration.
 */
int ktest_create_module(const char *, ktest_module_hdl_t **);
int ktest_add_suite(ktest_module_hdl_t *, const char *, ktest_suite_hdl_t **);
int ktest_add_test(ktest_suite_hdl_t *, const char *, ktest_fn_t,
    ktest_test_flags_t);
int ktest_register_module(ktest_module_hdl_t *);
void ktest_unregister_module(const char *);
void ktest_free_module(ktest_module_hdl_t *);

/*
 * Utility for getting a handle to static functions.
 */
int ktest_hold_mod(const char *, ddi_modhandle_t *);
void ktest_release_mod(ddi_modhandle_t);
int ktest_get_fn(ddi_modhandle_t, const char *, void **);

/*
 * Retrieve the input stream for a test.
 */
void ktest_get_input(const ktest_ctx_hdl_t *, uchar_t **, size_t *);

/*
 * Set the test result.
 */
void ktest_result_skip(ktest_ctx_hdl_t *, int, const char *, ...);
void ktest_result_fail(ktest_ctx_hdl_t *, int, const char *, ...);
void ktest_result_error(ktest_ctx_hdl_t *, int, const char *, ...);
void ktest_result_pass(ktest_ctx_hdl_t *, int);
void ktest_msg_clear(ktest_ctx_hdl_t *);
void ktest_msg_prepend(ktest_ctx_hdl_t *, const char *fmt, ...);

/*
 * Note: All the macros wrap the stringizing parameters in parentheses,
 * otherwise make check complains "preprocessor statement not in column 1".
 */

#define	KT_PASS(ctx)	ktest_result_pass((ctx), __LINE__)

#define	KT_FAIL(ctx, msg, ...)						\
	ktest_result_fail((ctx), __LINE__, (msg), ##__VA_ARGS__)

#define	KT_ERROR(ctx, msg, ...)						\
	ktest_result_error((ctx), __LINE__, (msg), ##__VA_ARGS__)

#define	KT_SKIP(ctx, msg, ...)						\
	ktest_result_skip((ctx), __LINE__, (msg), ##__VA_ARGS__)

/*
 * KTest ASSERT
 *
 * If the expression fails, then stash the failure message in ctx and
 * return from the calling function.
 */
#define	KT_ASSERT_IMPL(LEFT, OP, RIGHT, TYPE, ctx) do {			\
	const TYPE __left = (TYPE)(LEFT);				\
	const TYPE __right = (TYPE)(RIGHT);				\
	const boolean_t __res = __left OP __right;			\
	if (!__res) {							\
		ktest_result_fail((ctx), __LINE__,			\
		    "%s %s %s"						\
		    " (0x%" PRIxMAX " %s 0x%" PRIxMAX ")",		\
		    (#LEFT), (#OP), (#RIGHT),				\
		    (uintmax_t)__left, (#OP), (uintmax_t)__right);	\
		return;							\
	}								\
	_NOTE(CONSTCOND)  } while (0)

#define	KT_ASSERT3S(l, op, r, ctx)			\
	KT_ASSERT_IMPL(l, op, r, int64_t, ctx)

#define	KT_ASSERT3U(l, op, r, ctx)			\
	KT_ASSERT_IMPL(l, op, r, uint64_t, ctx)

#define	KT_ASSERT3P(l, op, r, ctx)			\
	KT_ASSERT_IMPL(l, op, r, uintptr_t, ctx)

#define	KT_ASSERT(exp, ctx)				\
	KT_ASSERT_IMPL(exp, ==, B_TRUE, boolean_t, ctx)

#define	KT_ASSERT0(exp, ctx)				\
	KT_ASSERT_IMPL(exp, ==, 0, uintmax_t, ctx)

/*
 * KTest ASSERT Goto
 *
 * If the expression fails, then stash the failure message in ctx and
 * goto label.
 */
#define	KT_ASSERTG_IMPL(LEFT, OP, RIGHT, TYPE, ctx, label) do {		\
	const TYPE __left = (TYPE)(LEFT);				\
	const TYPE __right = (TYPE)(RIGHT);				\
	const boolean_t __res = __left OP __right;			\
	if (!__res) {							\
		ktest_result_fail((ctx), __LINE__,			\
		    "%s %s %s"						\
		    " (0x%" PRIxMAX " %s 0x%" PRIxMAX ")",		\
		    (#LEFT), (#OP), (#RIGHT),				\
		    (uintmax_t)__left, (#OP), (uintmax_t)__right);	\
		goto label;						\
	}								\
	_NOTE(CONSTCOND)  } while (0)

#define	KT_ASSERT3SG(l, op, r, ctx, label)			\
	KT_ASSERTG_IMPL(l, op, r, int64_t, ctx, label)

#define	KT_ASSERT3UG(l, op, r, ctx, label)			\
	KT_ASSERTG_IMPL(l, op, r, uint64_t, ctx, label)

#define	KT_ASSERT3PG(l, op, r, ctx, label)			\
	KT_ASSERTG_IMPL(l, op, r, uintptr_t, ctx, label)

#define	KT_ASSERTG(exp, ctx, label)				\
	KT_ASSERTG_IMPL(exp, ==, B_TRUE, boolean_t, ctx, label)

#define	KT_ASSERT0G(x, ctx, label)				\
	KT_ASSERTG_IMPL(x, ==, 0, uintmax_t, ctx, label)

/*
 * KTest ERROR Macros
 *
 * These are modeled after the KTest ASSERT macros, but are instead
 * used to check for error conditions.
 */
#define	KT_EASSERT_IMPL(LEFT, OP, RIGHT, TYPE, ctx) do {		\
	const TYPE __left = (TYPE)(LEFT);				\
	const TYPE __right = (TYPE)(RIGHT);				\
	const boolean_t __res = __left OP __right;			\
	if (!__res) {							\
		ktest_result_error((ctx), __LINE__,			\
		    "%s %s %s"						\
		    " (0x%" PRIxMAX " %s 0x%" PRIxMAX ")",		\
		    (#LEFT), (#OP), (#RIGHT),				\
		    (uintmax_t)__left, #OP, (uintmax_t)__right);	\
		return;							\
	}								\
	_NOTE(CONSTCOND)  } while (0)

#define	KT_EASSERT3S(l, op, r, ctx)			\
	KT_EASSERT_IMPL(l, op, r, int64_t, ctx)

#define	KT_EASSERT3U(l, op, r, ctx)			\
	KT_EASSERT_IMPL(l, op, r, uint64_t, ctx)

#define	KT_EASSERT3P(l, op, r, ctx)			\
	KT_EASSERT_IMPL(l, op, r, uintptr_t, ctx)

#define	KT_EASSERT(exp, ctx)				\
	KT_EASSERT_IMPL(exp, ==, B_TRUE, boolean_t, ctx)

#define	KT_EASSERT0(exp, ctx)				\
	KT_EASSERT_IMPL(exp, ==, 0, uintmax_t, ctx)

/*
 * KTest ERROR Goto
 *
 * These are modeled after the KTest ASSERT Goto macros, but are
 * instead used to check for error conditions.
 */
#define	KT_EASSERTG_IMPL(LEFT, OP, RIGHT, TYPE, ctx, label) do {	\
	const TYPE __left = (TYPE)(LEFT);				\
	const TYPE __right = (TYPE)(RIGHT);				\
	const boolean_t __res = __left OP __right;			\
	if (!__res) {							\
		ktest_result_error((ctx), __LINE__,			\
		    "%s %s %s"						\
		    " (0x%" PRIxMAX " %s 0x%" PRIxMAX ")",		\
		    (#LEFT), (#OP), (#RIGHT),				\
		    (uintmax_t)__left, #OP, (uintmax_t)__right);	\
		goto label;						\
	}								\
	_NOTE(CONSTCOND)  } while (0)

#define	KT_EASSERT3SG(l, op, r, ctx, label)			\
	KT_EASSERTG_IMPL(l, op, r, int64_t, ctx, label)

#define	KT_EASSERT3UG(l, op, r, ctx, label)			\
	KT_EASSERTG_IMPL(l, op, r, uint64_t, ctx, label)

#define	KT_EASSERT3PG(l, op, r, ctx, label)			\
	KT_EASSERTG_IMPL(l, op, r, uintptr_t, ctx, label)

#define	KT_EASSERTG(exp, ctx, label)				\
	KT_EASSERTG_IMPL(exp, ==, B_TRUE, boolean_t, ctx, label)

#define	KT_EASSERT0G(x, ctx, label)				\
	KT_EASSERTG_IMPL(x, ==, 0, uintmax_t, ctx, label)

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_KTEST_H */
