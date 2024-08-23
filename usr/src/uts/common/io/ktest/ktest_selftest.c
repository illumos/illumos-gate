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
 * The ktest self test. Make sure the basics work.
 */
#include <sys/ktest.h>

void
ktest_st_pass_test(ktest_ctx_hdl_t *ctx)
{
	KT_PASS(ctx);
}

static boolean_t
ktest_st_is_even(int x)
{
	return ((x % 2) == 0);
}

void
ktest_st_fail_test(ktest_ctx_hdl_t *ctx)
{
	KT_ASSERT(ktest_st_is_even(5), ctx);
	KT_PASS(ctx);
}

static int
ktest_st_pretend_func(int input)
{
	if (input == 42) {
		return (0);
	}

	return (-1);
}

/*
 * This test should report a NONE result as it never touches the
 * context.
 */
void
ktest_st_none_test(ktest_ctx_hdl_t *ctx)
{
	(void) ktest_st_pretend_func(7);
}

/*
 * This test should report an ERROR result.
 */
void
ktest_st_err_test(ktest_ctx_hdl_t *ctx)
{
	KT_EASSERT0(ktest_st_pretend_func(7), ctx);
}

/*
 * This test should report a SKIP result.
 */
void
ktest_st_skip_test(ktest_ctx_hdl_t *ctx)
{
	KT_SKIP(ctx, "This test should be skipped.");
}

/*
 * This test should only run when given an input stream.
 */
void
ktest_st_input_test(ktest_ctx_hdl_t *ctx)
{
	uchar_t *bytes;
	size_t num_bytes = 0;

	ktest_get_input(ctx, &bytes, &num_bytes);

	if (num_bytes < 4) {
		KT_ERROR(ctx, "expected 4 or more bytes, got %u", num_bytes);
		return;
	}

	cmn_err(CE_WARN, "bytes (%lu): 0x%x 0x%x 0x%x 0x%x",
	    num_bytes, bytes[0], bytes[1], bytes[2],
	    bytes[3]);

	KT_PASS(ctx);
}

/*
 * Verify that ktest catches multiple results and returns an error to
 * alert the user.
 */
void
ktest_st_mult_result_test(ktest_ctx_hdl_t *ctx)
{
	KT_FAIL(ctx, "this is a fail result");
	KT_PASS(ctx);
}

/*
 * Verify the suite and test name uniqueness is enforced. Module name
 * uniqueness is tested in _init().
 */
void
ktest_st_unique_test(ktest_ctx_hdl_t *ctx)
{
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	KT_ASSERT0(ktest_create_module("ktest", &km), ctx);
	KT_ASSERT0G(ktest_add_suite(km, "selftest", &ks), ctx, cleanup);
	KT_ASSERT3SG(ktest_add_suite(km, "selftest", &ks), ==, EEXIST, ctx,
	    cleanup);
	KT_ASSERT0G(ktest_add_test(ks, "ktest_st_pass_test", ktest_st_pass_test,
	    KTEST_FLAG_NONE), ctx, cleanup);
	KT_ASSERTG(ktest_add_test(ks, "ktest_st_pass_test", ktest_st_pass_test,
	    KTEST_FLAG_NONE) == EEXIST, ctx, cleanup);

	KT_PASS(ctx);

cleanup:
	ktest_free_module(km);
}

void
ktest_st_name_test(ktest_ctx_hdl_t *ctx)
{
	ktest_module_hdl_t *km = NULL;

	KT_ASSERT3SG(ktest_create_module("bad:name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad/name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad?name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad>name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad<name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad&name", &km), ==, EINVAL, ctx,
	    cleanup);
	KT_ASSERT3SG(ktest_create_module("bad*name", &km), ==, EINVAL, ctx,
	    cleanup);

	KT_ASSERT0G(ktest_create_module("good_name", &km), ctx, cleanup);
	ktest_free_module(km);
	KT_ASSERT0G(ktest_create_module("good_name02", &km), ctx, cleanup);
	ktest_free_module(km);
	KT_ASSERT0G(ktest_create_module("good.name02", &km), ctx, cleanup);
	ktest_free_module(km);
	KT_ASSERT0G(ktest_create_module("_l33t.n4m3", &km), ctx, cleanup);

	KT_PASS(ctx);

cleanup:
	ktest_free_module(km);
}

static struct modlmisc ktest_selftest_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "ktest selftest module"
};

static struct modlinkage ktest_selftest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &ktest_selftest_modlmisc, NULL }
};

int
_init()
{
	int ret;
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	VERIFY0(ktest_create_module("ktest", &km));
	VERIFY0(ktest_add_suite(km, "selftest", &ks));
	VERIFY0(ktest_add_test(ks, "ktest_st_none_test", ktest_st_none_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_pass_test", ktest_st_pass_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_fail_test", ktest_st_fail_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_err_test", ktest_st_err_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_skip_test", ktest_st_skip_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_input_test", ktest_st_input_test,
	    KTEST_FLAG_INPUT));
	VERIFY0(ktest_add_test(ks, "ktest_st_mult_result_test",
	    ktest_st_mult_result_test, KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_unique_test",
	    ktest_st_unique_test, KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "ktest_st_name_test",
	    ktest_st_name_test, KTEST_FLAG_NONE));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	/*
	 * It would be nice to test this in ktest_st_test_unique(),
	 * but we can't because this call grabs the ktest_lock, and
	 * the lock is already held while a test is running. If you
	 * see a panic here, check ktest_register_module() to make
	 * sure it's enforcing module name uniqueness.
	 */
	VERIFY(ktest_register_module(km) == EEXIST);

	if ((ret = mod_install(&ktest_selftest_modlinkage)) != 0) {
		ktest_unregister_module("ktest");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	ktest_unregister_module("ktest");
	return (mod_remove(&ktest_selftest_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ktest_selftest_modlinkage, modinfop));
}
