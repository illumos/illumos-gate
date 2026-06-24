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
 * Copyright 2026 Gernot Strasser
 */

/*
 * ktest(8) coverage for the kernel SHA-256 block transform, in particular the
 * amd64 runtime dispatch between the generic transform and the Intel SHA
 * Extensions ("SHA-NI") path in sha2.c.
 *
 * Tests:
 *   kat            - known-answer test against precomputed digests for inputs
 *                    of many lengths, including ones that cross the dispatch's
 *                    32 KiB (512-block) kernel-FPU window and odd tail blocks.
 *   incremental    - the same inputs fed via varied SHA2Update() increments,
 *                    exercising the partial-block buffering and the single
 *                    block tail path in SHA2Final().
 *   fallback_equiv - hashes each input twice, once with SHA-NI forced off
 *                    (sha256_ni_disable=1, generic path) and once on, and
 *                    asserts both match each other and the known answer.  This
 *                    is the differential that catches dispatch / chunking /
 *                    kernel-FPU bugs without needing an external reference.
 *                    It is skipped on non-amd64 platforms and on CPUs without
 *                    the SHA extensions, where both paths would be identical.
 *
 * The test input of length L is the deterministic byte pattern b[i] = i & 0xff,
 * so the expected digests below are reproducible with any sha256 tool.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/stdbool.h>
#include <sys/debug.h>
#include <sys/sha2.h>
#include <sys/ktest.h>
#ifdef	__amd64
#include <sys/x86_archext.h>
#endif

/*
 * The largest test vector, 128 KiB + 1 byte.  The amd64 dispatch in sha2.c
 * hands the SHA-NI transform at most 512 64-byte blocks (32 KiB) per
 * kernel-FPU window, so this length spans four full windows plus a trailing
 * partial block; the 32704..32833 vectors below straddle the first window
 * boundary (32 KiB - 64, exactly 32 KiB, +1, +64, and +65 bytes).
 */
#define	SHA256_KT_MAXLEN	131073

/* Expected SHA-256 of b[i] = (i & 0xff) for i in [0, len). */
static const struct {
	size_t		len;
	uint8_t		dig[SHA256_DIGEST_LENGTH];
} sha256_kat_vec[] = {
	{ 0, {
	    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
	    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
	    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
	    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55 } },
	{ 1, {
	    0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98,
	    0x9c, 0xa5, 0x44, 0xe6, 0xbb, 0x78, 0x0a, 0x2c,
	    0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76,
	    0x85, 0x11, 0xa3, 0x06, 0x17, 0xaf, 0xa0, 0x1d } },
	{ 3, {
	    0xae, 0x4b, 0x32, 0x80, 0xe5, 0x6e, 0x2f, 0xaf,
	    0x83, 0xf4, 0x14, 0xa6, 0xe3, 0xda, 0xbe, 0x9d,
	    0x5f, 0xbe, 0x18, 0x97, 0x65, 0x44, 0xc0, 0x5f,
	    0xed, 0x12, 0x1a, 0xcc, 0xb8, 0x5b, 0x53, 0xfc } },
	{ 55, {
	    0x46, 0x3e, 0xb2, 0x8e, 0x72, 0xf8, 0x2e, 0x0a,
	    0x96, 0xc0, 0xa4, 0xcc, 0x53, 0x69, 0x0c, 0x57,
	    0x12, 0x81, 0x13, 0x1f, 0x67, 0x2a, 0xa2, 0x29,
	    0xe0, 0xd4, 0x5a, 0xe5, 0x9b, 0x59, 0x8b, 0x59 } },
	{ 56, {
	    0xda, 0x2a, 0xe4, 0xd6, 0xb3, 0x67, 0x48, 0xf2,
	    0xa3, 0x18, 0xf2, 0x3e, 0x7a, 0xb1, 0xdf, 0xdf,
	    0x45, 0xac, 0xdc, 0x9d, 0x04, 0x9b, 0xd8, 0x0e,
	    0x59, 0xde, 0x82, 0xa6, 0x08, 0x95, 0xf5, 0x62 } },
	{ 57, {
	    0x2f, 0xe7, 0x41, 0xaf, 0x80, 0x1c, 0xc2, 0x38,
	    0x60, 0x2a, 0xc0, 0xec, 0x6a, 0x7b, 0x0c, 0x3a,
	    0x8a, 0x87, 0xc7, 0xfc, 0x7d, 0x7f, 0x02, 0xa3,
	    0xfe, 0x03, 0xd1, 0xc1, 0x2e, 0xac, 0x4d, 0x8f } },
	{ 63, {
	    0x29, 0xaf, 0x26, 0x86, 0xfd, 0x53, 0x37, 0x4a,
	    0x36, 0xb0, 0x84, 0x66, 0x94, 0xcc, 0x34, 0x21,
	    0x77, 0xe4, 0x28, 0xd1, 0x64, 0x75, 0x15, 0xf0,
	    0x78, 0x78, 0x4d, 0x69, 0xcd, 0xb9, 0xe4, 0x88 } },
	{ 64, {
	    0xfd, 0xea, 0xb9, 0xac, 0xf3, 0x71, 0x03, 0x62,
	    0xbd, 0x26, 0x58, 0xcd, 0xc9, 0xa2, 0x9e, 0x8f,
	    0x9c, 0x75, 0x7f, 0xcf, 0x98, 0x11, 0x60, 0x3a,
	    0x8c, 0x44, 0x7c, 0xd1, 0xd9, 0x15, 0x11, 0x08 } },
	{ 65, {
	    0x4b, 0xfd, 0x2c, 0x8b, 0x6f, 0x1e, 0xec, 0x7a,
	    0x2a, 0xfe, 0xb4, 0x8b, 0x93, 0x4e, 0xe4, 0xb2,
	    0x69, 0x41, 0x82, 0x02, 0x7e, 0x6d, 0x0f, 0xc0,
	    0x75, 0x07, 0x4f, 0x2f, 0xab, 0xb3, 0x17, 0x81 } },
	{ 127, {
	    0x92, 0xca, 0x0f, 0xa6, 0x65, 0x1e, 0xe2, 0xf9,
	    0x7b, 0x88, 0x4b, 0x72, 0x46, 0xa5, 0x62, 0xfa,
	    0x71, 0x25, 0x0f, 0xed, 0xef, 0xe5, 0xeb, 0xf2,
	    0x70, 0xd3, 0x1c, 0x54, 0x6b, 0xfe, 0xa9, 0x76 } },
	{ 128, {
	    0x47, 0x1f, 0xb9, 0x43, 0xaa, 0x23, 0xc5, 0x11,
	    0xf6, 0xf7, 0x2f, 0x8d, 0x16, 0x52, 0xd9, 0xc8,
	    0x80, 0xcf, 0xa3, 0x92, 0xad, 0x80, 0x50, 0x31,
	    0x20, 0x54, 0x77, 0x03, 0xe5, 0x6a, 0x2b, 0xe5 } },
	{ 129, {
	    0x50, 0x99, 0xc6, 0xa5, 0x62, 0x03, 0xf9, 0x68,
	    0x7f, 0x7d, 0x33, 0xf4, 0xbf, 0xdf, 0x57, 0x6d,
	    0x31, 0xdc, 0x91, 0xf6, 0xb6, 0x95, 0xec, 0xea,
	    0x38, 0xb2, 0x77, 0x0c, 0x87, 0x63, 0x11, 0x35 } },
	{ 8192, {
	    0xdc, 0x40, 0x4a, 0x61, 0x3f, 0xed, 0xae, 0xb5,
	    0x40, 0x34, 0x51, 0x4b, 0xc6, 0x50, 0x5f, 0x56,
	    0xb9, 0x33, 0xca, 0xa5, 0x25, 0x02, 0x99, 0xba,
	    0x7d, 0x09, 0x43, 0x77, 0xa5, 0x1c, 0xaa, 0x46 } },
	{ 32704, {
	    0x6a, 0x1c, 0xd5, 0xbb, 0x6e, 0x41, 0xf2, 0x83,
	    0x45, 0x2a, 0x9b, 0xa5, 0x15, 0x24, 0xdd, 0x9e,
	    0xbb, 0x8b, 0x43, 0x3c, 0x1d, 0x23, 0x05, 0x14,
	    0x1c, 0xa9, 0x02, 0x09, 0xbd, 0x63, 0x53, 0xb5 } },
	{ 32768, {
	    0xe1, 0x13, 0x60, 0x25, 0x1d, 0x11, 0x73, 0x65,
	    0x0c, 0xdc, 0xd2, 0x0f, 0x11, 0x1d, 0x8f, 0x1c,
	    0xa2, 0xe4, 0x12, 0xf5, 0x72, 0xe8, 0xb3, 0x6a,
	    0x4d, 0xc0, 0x67, 0x12, 0x1c, 0x17, 0x99, 0xb8 } },
	{ 32769, {
	    0xb9, 0x3c, 0x16, 0xc9, 0x98, 0x95, 0xf1, 0x59,
	    0x33, 0x47, 0xab, 0x57, 0xaf, 0x0c, 0x0a, 0x82,
	    0xf9, 0x67, 0x2e, 0xcb, 0x3d, 0xeb, 0xb5, 0x9d,
	    0x12, 0x4e, 0x1b, 0x38, 0xf3, 0x87, 0x1f, 0x01 } },
	{ 32832, {
	    0x20, 0x6a, 0xa6, 0xcc, 0x56, 0xb0, 0x0c, 0x13,
	    0xa5, 0xce, 0x97, 0xf3, 0xf8, 0x02, 0x99, 0xda,
	    0x72, 0x3c, 0xa1, 0xeb, 0xea, 0xc3, 0x5f, 0xba,
	    0x5f, 0xba, 0x1b, 0xf9, 0xd3, 0x96, 0x45, 0xcc } },
	{ 32833, {
	    0xa7, 0x9b, 0xe6, 0x6d, 0x16, 0xb1, 0x3e, 0x05,
	    0xd7, 0x4b, 0xa2, 0xd8, 0x89, 0x64, 0x8f, 0x02,
	    0x5e, 0x5e, 0xb0, 0x52, 0xf1, 0x83, 0x0b, 0x29,
	    0xe8, 0xa9, 0x27, 0x64, 0x85, 0x78, 0x40, 0x2d } },
	{ 65536, {
	    0x7d, 0xac, 0xa2, 0x09, 0x5d, 0x04, 0x38, 0x26,
	    0x0f, 0xa8, 0x49, 0x18, 0x3d, 0xfc, 0x67, 0xfa,
	    0xa4, 0x59, 0xfd, 0xf4, 0x93, 0x6e, 0x1b, 0xc9,
	    0x1e, 0xec, 0x6b, 0x28, 0x1b, 0x27, 0xe4, 0xc2 } },
	{ 131073, {
	    0x59, 0x14, 0x3c, 0x73, 0xfb, 0xc6, 0x69, 0xc1,
	    0x8b, 0xde, 0xb3, 0x6c, 0x7c, 0xfa, 0x13, 0x88,
	    0x8c, 0x03, 0xa2, 0xd9, 0x35, 0xb1, 0x8d, 0x93,
	    0x9c, 0x62, 0x86, 0x92, 0x36, 0x0c, 0x16, 0xff } },
};

/* SHA-256("abc"), the canonical FIPS 180-2 anchor. */
static const uint8_t sha256_abc_dig[SHA256_DIGEST_LENGTH] = {
	0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
	0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
	0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
	0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

/*
 * Allocate a SHA256_KT_MAXLEN buffer and fill it with the deterministic
 * b[i] = i & 0xff pattern.  Each test allocates its own buffer rather than
 * sharing one, so the tests carry no mutable global state and make no
 * assumption about whether ktest runs them serially.  Freed with
 * sha256_kt_free().
 */
static uint8_t *
sha256_kt_alloc(void)
{
	uint8_t *buf = kmem_alloc(SHA256_KT_MAXLEN, KM_SLEEP);

	for (size_t i = 0; i < SHA256_KT_MAXLEN; i++)
		buf[i] = (uint8_t)(i & 0xff);

	return (buf);
}

static void
sha256_kt_free(uint8_t *buf)
{
	kmem_free(buf, SHA256_KT_MAXLEN);
}

static void
sha256_kt_oneshot(const uint8_t *in, size_t len, uint8_t *out)
{
	SHA256_CTX ctx;

	SHA2Init(SHA256, &ctx);
	SHA2Update(&ctx, in, len);
	SHA2Final(out, &ctx);
}

/*
 * kat: one-shot hash of each vector, compared against the precomputed digest.
 */
void
sha256_kat_test(ktest_ctx_hdl_t *ctx)
{
	uint8_t out[SHA256_DIGEST_LENGTH];
	uint8_t *buf = sha256_kt_alloc();
	bool fail = false;
	size_t faillen = 0;
	uint_t nfail = 0;

	/* canonical "abc" anchor */
	sha256_kt_oneshot((const uint8_t *)"abc", 3, out);
	if (bcmp(out, sha256_abc_dig, SHA256_DIGEST_LENGTH) != 0) {
		KT_FAIL(ctx, "SHA-256(\"abc\") mismatch");
		sha256_kt_free(buf);
		return;
	}

	for (size_t v = 0; v < ARRAY_SIZE(sha256_kat_vec); v++) {
		const size_t len = sha256_kat_vec[v].len;

		sha256_kt_oneshot(buf, len, out);
		if (bcmp(out, sha256_kat_vec[v].dig,
		    SHA256_DIGEST_LENGTH) != 0) {
			if (!fail)
				faillen = len;
			fail = true;
			nfail++;
		}
	}

	sha256_kt_free(buf);

	if (fail) {
		KT_FAIL(ctx, "%u vector(s) mismatched, first at len %zu",
		    nfail, faillen);
	} else {
		KT_PASS(ctx);
	}
}

/*
 * incremental: feed each vector through SHA2Update() in a range of step
 * sizes to exercise the partial-block buffering and the Final() tail path.
 */
void
sha256_incremental_test(ktest_ctx_hdl_t *ctx)
{
	static const size_t steps[] = { 1, 7, 31, 64, 1000 };
	uint8_t out[SHA256_DIGEST_LENGTH];
	uint8_t *buf = sha256_kt_alloc();
	bool fail = false;
	size_t faillen = 0, failstep = 0;
	uint_t nfail = 0;

	for (size_t v = 0; v < ARRAY_SIZE(sha256_kat_vec); v++) {
		const size_t len = sha256_kat_vec[v].len;

		for (size_t s = 0; s < ARRAY_SIZE(steps); s++) {
			const size_t step = steps[s];
			SHA256_CTX c;

			SHA2Init(SHA256, &c);
			for (size_t off = 0; off < len; off += step) {
				SHA2Update(&c, buf + off,
				    MIN(step, len - off));
			}
			SHA2Final(out, &c);

			if (bcmp(out, sha256_kat_vec[v].dig,
			    SHA256_DIGEST_LENGTH) != 0) {
				if (!fail) {
					faillen = len;
					failstep = step;
				}
				fail = true;
				nfail++;
			}
		}
	}

	sha256_kt_free(buf);

	if (fail) {
		KT_FAIL(ctx, "%u case(s) mismatched, first at len %zu "
		    "step %zu", nfail, faillen, failstep);
	} else {
		KT_PASS(ctx);
	}
}

/*
 * fallback_equiv: hash each vector with SHA-NI forced off and on, and assert
 * both equal the known answer.  This exercises the amd64 dispatch and its
 * sha256_ni_disable tunable in sha2.c, so it is skipped elsewhere, and it is
 * skipped unless the CPU has every feature the dispatch requires before it
 * will use the SHA-NI path -- otherwise both the "on" and "off" runs take
 * the generic path (which the kat test already covers) and the differential
 * proves nothing.  The set checked here mirrors sha256_ni_usable() in sha2.c
 * exactly: the SHA extensions plus the SSE2, SSSE3 and SSE4.1 instructions
 * that amd64/sha256-ni.S uses around them.
 */
#ifdef	__amd64
extern int sha256_ni_disable;

void
sha256_fallback_equiv_test(ktest_ctx_hdl_t *ctx)
{
	uint8_t gen_dig[SHA256_DIGEST_LENGTH];
	uint8_t ni_dig[SHA256_DIGEST_LENGTH];
	uint8_t *buf;
	int saved;
	bool fail = false;
	size_t faillen = 0;
	uint_t nfail = 0;

	if (!is_x86_feature(x86_featureset, X86FSET_SSE2) ||
	    !is_x86_feature(x86_featureset, X86FSET_SSSE3) ||
	    !is_x86_feature(x86_featureset, X86FSET_SSE4_1) ||
	    !is_x86_feature(x86_featureset, X86FSET_SHA)) {
		KT_SKIP(ctx, "CPU lacks a feature the SHA-NI path requires");
		return;
	}

	buf = sha256_kt_alloc();
	saved = sha256_ni_disable;

	for (size_t v = 0; v < ARRAY_SIZE(sha256_kat_vec); v++) {
		const size_t len = sha256_kat_vec[v].len;

		sha256_ni_disable = 1;			/* generic */
		sha256_kt_oneshot(buf, len, gen_dig);
		sha256_ni_disable = 0;			/* SHA-NI */
		sha256_kt_oneshot(buf, len, ni_dig);

		if (bcmp(gen_dig, ni_dig, SHA256_DIGEST_LENGTH) != 0 ||
		    bcmp(ni_dig, sha256_kat_vec[v].dig,
		    SHA256_DIGEST_LENGTH) != 0) {
			if (!fail)
				faillen = len;
			fail = true;
			nfail++;
		}
	}

	sha256_ni_disable = saved;
	sha256_kt_free(buf);

	if (fail) {
		KT_FAIL(ctx, "%u vector(s) mismatched, first at len %zu",
		    nfail, faillen);
	} else {
		KT_PASS(ctx);
	}
}
#else	/* !__amd64 */
void
sha256_fallback_equiv_test(ktest_ctx_hdl_t *ctx)
{
	KT_SKIP(ctx, "SHA-NI dispatch is amd64-only");
}
#endif	/* __amd64 */

static struct modlmisc sha256_ktest_modlmisc = {
	.misc_modops = &mod_miscops,
	.misc_linkinfo = "SHA-256 ktest module"
};

static struct modlinkage sha256_ktest_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &sha256_ktest_modlmisc, NULL }
};

int
_init(void)
{
	int ret;
	ktest_module_hdl_t *km = NULL;
	ktest_suite_hdl_t *ks = NULL;

	VERIFY0(ktest_create_module("sha2", &km));
	VERIFY0(ktest_add_suite(km, "sha256", &ks));
	VERIFY0(ktest_add_test(ks, "kat", sha256_kat_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "incremental", sha256_incremental_test,
	    KTEST_FLAG_NONE));
	VERIFY0(ktest_add_test(ks, "fallback_equiv",
	    sha256_fallback_equiv_test, KTEST_FLAG_NONE));

	if ((ret = ktest_register_module(km)) != 0) {
		ktest_free_module(km);
		return (ret);
	}

	if ((ret = mod_install(&sha256_ktest_modlinkage)) != 0) {
		ktest_unregister_module("sha2");
		return (ret);
	}

	return (0);
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&sha256_ktest_modlinkage)) != 0)
		return (ret);

	ktest_unregister_module("sha2");
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&sha256_ktest_modlinkage, modinfop));
}
