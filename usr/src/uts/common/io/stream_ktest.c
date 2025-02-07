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
 * Copyright 2024 Ryan Zezeski
 */
#include <sys/modctl.h>
#include <sys/strsun.h>
#include <sys/ktest.h>

static mblk_t *
allocb_zeroed(size_t len, uint_t pri)
{
	mblk_t *mp = allocb(len, pri);

	if (mp != NULL) {
		bzero(mp->b_wptr, len);
		mp->b_wptr += len;
	}
	return (mp);
}

static size_t
msgsegs(const mblk_t *mp)
{
	size_t out = 0;

	while (mp != NULL) {
		out++;
		mp = mp->b_cont;
	}

	return (out);
}

/*
 * Initialises a chain of n_mps zeroed mblks, each containing
 * mplen[i] bytes.
 */
static mblk_t *
init_chain(const size_t *mp_len, const size_t n_mps)
{
	mblk_t *out = NULL;
	mblk_t **cont = &out;

	for (int i = 0; i < n_mps; ++i) {
		mblk_t *new = allocb_zeroed(mp_len[i], BPRI_LO);
		if (new == NULL)
			goto bail;
		*cont = new;
		cont = &new->b_cont;
	}

	return (out);

bail:
	if (out != NULL)
		freemsg(out);
	return (NULL);
}

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

void
msgpullup_test(ktest_ctx_hdl_t *ctx)
{
	const size_t test_1[] = {8, 8};
	const size_t test_2[] = {4, 8};
	const size_t test_3[] = {4, 4, 8};
	mblk_t *mp = NULL;
	mblk_t *pullmp = NULL;

	/*
	 * Test 1 -> 8 + 8, pullup 4.
	 * Should copy first 4 bytes, then link into the existing mp.
	 */
	mp = init_chain(test_1, 2);
	KT_EASSERT3P(mp, !=, NULL, ctx);
	KT_ASSERT3UG(msgsegs(mp), ==, 2, ctx, cleanup);
	pullmp = msgpullup(mp, 4);
	KT_EASSERT3PG(pullmp, !=, NULL, ctx, cleanup);

	KT_ASSERT3UG(MBLKL(pullmp), ==, 4, ctx, cleanup);
	KT_ASSERT3UG(msgsize(pullmp), ==, 16, ctx, cleanup);
	KT_ASSERT3UG(msgsegs(pullmp), ==, 3, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont, !=, NULL, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont->b_datap, ==, mp->b_datap, ctx, cleanup);

	freemsg(mp);
	freemsg(pullmp);

	/*
	 * Test 2 -> 4 + 8, pullup 5.
	 * Should be 5(copy) + 7(referencing the original tail).
	 */
	mp = init_chain(test_2, 2);
	KT_EASSERT3P(mp, !=, NULL, ctx);
	KT_ASSERT3UG(msgsegs(mp), ==, 2, ctx, cleanup);
	pullmp = msgpullup(mp, 5);
	KT_EASSERT3PG(pullmp, !=, NULL, ctx, cleanup);

	KT_ASSERT3UG(MBLKL(pullmp), ==, 5, ctx, cleanup);
	KT_ASSERT3UG(msgsize(pullmp), ==, 12, ctx, cleanup);
	KT_ASSERT3UG(msgsegs(pullmp), ==, 2, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont, !=, NULL, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont->b_datap, ==, mp->b_cont->b_datap, ctx,
	    cleanup);

	freemsg(mp);
	freemsg(pullmp);

	/*
	 * Test 3 -> 4 + 4 + 8, pullup 12.
	 * Should be 12(copy) + 4(original tail).
	 */
	mp = init_chain(test_3, 3);
	KT_EASSERT3P(mp, !=, NULL, ctx);
	KT_ASSERT3UG(msgsegs(mp), ==, 3, ctx, cleanup);
	pullmp = msgpullup(mp, 12);
	KT_EASSERT3PG(pullmp, !=, NULL, ctx, cleanup);

	KT_ASSERT3UG(MBLKL(pullmp), ==, 12, ctx, cleanup);
	KT_ASSERT3UG(msgsize(pullmp), ==, 16, ctx, cleanup);
	KT_ASSERT3UG(msgsegs(pullmp), ==, 2, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont, !=, NULL, ctx, cleanup);
	KT_ASSERT3PG(pullmp->b_cont->b_datap, ==, mp->b_cont->b_cont->b_datap,
	    ctx, cleanup);

	KT_PASS(ctx);

cleanup:
	if (mp != NULL)
		freemsg(mp);
	if (pullmp != NULL)
		freemsg(pullmp);
}

static struct modlmisc stream_ktest_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "stream ktest module"
};

static struct modlinkage stream_ktest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &stream_ktest_modlmisc, NULL }
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
	VERIFY0(ktest_add_test(ks, "msgpullup_test", msgpullup_test,
	    KTEST_FLAG_NONE));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	if ((ret = mod_install(&stream_ktest_modlinkage)) != 0) {
		ktest_unregister_module("stream");
		return (ret);
	}

	return (0);
}

int
_fini()
{
	ktest_unregister_module("stream");
	return (mod_remove(&stream_ktest_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&stream_ktest_modlinkage, modinfop));
}
