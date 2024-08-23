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
#include <sys/modctl.h>
#include <sys/strsun.h>
#include <sys/ktest.h>

/*
 * Test the MBLKL macro.
 */
void
mblkl_test(ktest_ctx_hdl_t *ctx)
{
	mblk_t *mp1 = allocb(64, 0);

	KT_EASSERT3P(mp1, !=, NULL, ctx);
	KT_ASSERT3UG(MBLKL(mp1), ==, 0, ctx, cleanup);
	mp1->b_wptr += 14;
	KT_ASSERT3UG(MBLKL(mp1), ==, 14, ctx, cleanup);
	KT_PASS(ctx);

cleanup:
	freeb(mp1);
}

void
msgsize_test(ktest_ctx_hdl_t *ctx)
{
	mblk_t *mp1 = allocb(14, 0);
	mblk_t *mp2 = allocb(20, 0);

	KT_EASSERT3P(mp1, !=, NULL, ctx);
	KT_EASSERT3PG(mp2, !=, NULL, ctx, cleanup);
	KT_ASSERT3UG(msgsize(mp1), ==, 0, ctx, cleanup);
	KT_ASSERT3UG(msgsize(mp2), ==, 0, ctx, cleanup);
	mp1->b_wptr += 14;
	mp2->b_wptr += 20;
	KT_ASSERT3UG(msgsize(mp1), ==, 14, ctx, cleanup);
	KT_ASSERT3UG(msgsize(mp2), ==, 20, ctx, cleanup);
	mp1->b_cont = mp2;
	KT_ASSERT3UG(msgsize(mp1), ==, 34, ctx, cleanup);
	KT_ASSERT3UG(msgsize(mp2), ==, 20, ctx, cleanup);
	KT_PASS(ctx);

cleanup:
	freeb(mp1);

	if (mp2 != NULL) {
		freeb(mp2);
	}
}

static struct modlmisc stream_test_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "stream ktest module"
};

static struct modlinkage stream_test_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &stream_test_modlmisc, NULL }
};

int
_init()
{
	int ret;
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	VERIFY0(ktest_create_module("stream", &km));
	VERIFY0(ktest_add_suite(km, "mblk", &ks));
	VERIFY0(ktest_add_test(ks, "mblkl_test", mblkl_test, KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "msgsize_test", msgsize_test,
	    KTEST_FLAG_NONE));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	if ((ret = mod_install(&stream_test_modlinkage)) != 0) {
		ktest_unregister_module("stream");
		return (ret);
	}

	return (0);
}

int
_fini()
{
	ktest_unregister_module("stream");
	return (mod_remove(&stream_test_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&stream_test_modlinkage, modinfop));
}
