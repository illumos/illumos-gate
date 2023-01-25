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
 * This attempts to do a series of writes to the /proc control file that have
 * invalid data for the xregs state. The way that this works is that we create a
 * thread that will be detached and just sleeps whenever it wakes up. We direct
 * this thread to stop with a directed PCSTOP via libproc.
 */

#include <err.h>
#include <stdlib.h>
#include <libproc.h>
#include <thread.h>
#include <errno.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/x86_archext.h>

#include "xsave_util.h"

static prxregset_t *bad_xregs_pxr;
static size_t bad_xregs_size;

typedef struct bad_xregs_test {
	const char *bxt_desc;
	int bxt_errno;
	uint32_t bxt_min;
	void (*bxt_setup)(void **, size_t *);
} bad_xregs_test_t;

static void
bad_xregs_no_data(void **bufp, size_t *sizep)
{
	*bufp = NULL;
	*sizep = 0;
}

static void
bad_xregs_null_buf(void **bufp, size_t *sizep)
{
	*bufp = NULL;
	*sizep = sizeof (prxregset_hdr_t);
}

static void
bad_xregs_short_hdr(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = calloc(1, sizeof (prxregset_hdr_t));
	if (hdr == NULL) {
		err(EXIT_FAILURE, "failed to allocate header");
	}

	hdr->pr_type = PR_TYPE_XSAVE;
	hdr->pr_size = sizeof (prxregset_hdr_t);

	*bufp = hdr;
	*sizep = sizeof (prxregset_hdr_t) - 4;
}

static void
bad_xregs_hdr_too_large(void **bufp, size_t *sizep)
{
	uint32_t large = 32 * 1024 * 1024; /* 4 MiB */
	prxregset_hdr_t *hdr = malloc(32 * 1024 * 1024);
	if (hdr == NULL) {
		err(EXIT_FAILURE, "failed to allocate regset");
	}

	(void) memcpy(hdr, bad_xregs_pxr, bad_xregs_size);
	hdr->pr_size = large;

	*bufp = hdr;
	*sizep = large;
}

static prxregset_hdr_t *
bad_xregs_std_init(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = malloc(bad_xregs_size);
	if (hdr == NULL) {
		err(EXIT_FAILURE, "failed to allocate regset");
	}

	(void) memcpy(hdr, bad_xregs_pxr, bad_xregs_size);

	*bufp = hdr;
	*sizep = bad_xregs_size;
	return (hdr);
}

static void
bad_xregs_missing_data(void **bufp, size_t *sizep)
{
	(void) bad_xregs_std_init(bufp, sizep);
	*sizep /= 2;
}

static void
bad_xregs_hdr_bad_type(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_type = PR_TYPE_XSAVE + 167;
}

static void
bad_xregs_hdr_bad_flags(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_flags = 0x123;
}

static void
bad_xregs_hdr_bad_pad0(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_pad[0] = 0x456;
}

static void
bad_xregs_hdr_bad_pad1(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_pad[1] = 0x789;
}

static void
bad_xregs_hdr_bad_pad2(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_pad[2] = 0xabc;
}

static void
bad_xregs_hdr_bad_pad3(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_pad[3] = 0xdef;
}

static void
bad_xregs_hdr_no_info(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_ninfo = 0;
}

static void
bad_xregs_hdr_no_info_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	uint32_t len = sizeof (prxregset_hdr_t) + sizeof (prxregset_info_t) *
	    hdr->pr_ninfo;
	hdr->pr_size = len - 4;
}

static void
bad_xregs_info_type(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_info[0].pri_type = 0xbaddcafe;
}

static void
bad_xregs_info_flags(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	VERIFY3U(hdr->pr_ninfo, >=, 2);
	hdr->pr_info[1].pri_flags = 0x120b0;
}

static prxregset_info_t *
bad_xregs_find_info(prxregset_hdr_t *hdr, uint32_t type)
{
	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		if (hdr->pr_info[i].pri_type == type) {
			return (&hdr->pr_info[i]);
		}
	}

	return (NULL);
}

static void
bad_xregs_info_xcr_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_xcr_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	info->pri_offset++;
}

static void
bad_xregs_info_xsave_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_xsave_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	info->pri_offset--;
}

static void
bad_xregs_info_ymm_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_YMM);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_ymm_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_YMM);
	VERIFY3P(info, !=, NULL);
	info->pri_offset--;
}

static void
bad_xregs_info_opmask_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_OPMASK);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_opmask_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_OPMASK);
	VERIFY3P(info, !=, NULL);
	info->pri_offset--;
}

static void
bad_xregs_info_zmm_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_ZMM);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_zmm_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_ZMM);
	VERIFY3P(info, !=, NULL);
	info->pri_offset--;
}

static void
bad_xregs_info_hi_zmm_len(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_HI_ZMM);
	VERIFY3P(info, !=, NULL);
	info->pri_size--;
}

static void
bad_xregs_info_hi_zmm_off(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_HI_ZMM);
	VERIFY3P(info, !=, NULL);
	info->pri_offset--;
}

static void
bad_xregs_info_exceeds_len0(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_info[0].pri_offset = hdr->pr_size + 4;
}

static void
bad_xregs_info_exceeds_len1(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_info[0].pri_offset = hdr->pr_size - hdr->pr_info[0].pri_size +
	    8;
}

static void
bad_xregs_info_overlaps(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	hdr->pr_info[0].pri_offset = sizeof (prxregset_hdr_t) + 8;
}

static void
bad_xregs_trim_entry(prxregset_hdr_t *hdr, uint32_t type)
{
	boolean_t found = B_FALSE;
	/*
	 * Walk the info structures and clip out everything after the xsave
	 * entry. This almost suggets it'd be nice to have a nop type that was
	 * ignored.
	 */
	for (uint32_t i = 0; i < hdr->pr_ninfo; i++) {
		if (hdr->pr_info[i].pri_type == type) {
			found = B_TRUE;
		}

		if (found && i + 1 != hdr->pr_ninfo) {
			hdr->pr_info[i] = hdr->pr_info[i + 1];
		}
	}

	VERIFY3U(found, ==, B_TRUE);
	hdr->pr_ninfo--;
}

static void
bad_xregs_no_xsave(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	bad_xregs_trim_entry(hdr, PRX_INFO_XSAVE);
}

static void
bad_xregs_missing_xstate(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	bad_xregs_trim_entry(hdr, PRX_INFO_YMM);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);

	xsave->prx_xsh_xstate_bv |= XFEATURE_AVX;
}

static void
bad_xregs_xcr_bad_xcr0(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	prxregset_xcr_t *xcr = (void *)((uintptr_t)*bufp + info->pri_offset);
	xcr->prx_xcr_xcr0 = ~xcr->prx_xcr_xcr0;
}

static void
bad_xregs_xcr_bad_xfd(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	prxregset_xcr_t *xcr = (void *)((uintptr_t)*bufp + info->pri_offset);
	xcr->prx_xcr_xfd = ~xcr->prx_xcr_xfd;
}

static void
bad_xregs_xcr_bad_pad0(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	prxregset_xcr_t *xcr = (void *)((uintptr_t)*bufp + info->pri_offset);
	xcr->prx_xcr_pad[0] = 0xdeadbeef;
}

static void
bad_xregs_xcr_bad_pad1(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XCR);
	VERIFY3P(info, !=, NULL);
	prxregset_xcr_t *xcr = (void *)((uintptr_t)*bufp + info->pri_offset);
	xcr->prx_xcr_pad[1] = 0xf00b412;
}

static void
bad_xregs_xsave_bad_xbv(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	/*
	 * bit 8 is a supervisor state that we don't currently have defined in
	 * <sys/x86_archext.h> and should always end up being something we don't
	 * see in userland.
	 */
	xsave->prx_xsh_xstate_bv |= (1 << 8);
}

static void
bad_xregs_xsave_bad_xcomp(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	/*
	 * bit 63 is used to say that this is valid. Given that we don't support
	 * it, we just set that bit as the most realistic example of what could
	 * happen.
	 */
	xsave->prx_xsh_xcomp_bv |= (1ULL << 63);
}

static void
bad_xregs_xsave_bad_rsvd0(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[0] = 0xff10;
}

static void
bad_xregs_xsave_bad_rsvd1(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[1] = 0x87654321;
}

static void
bad_xregs_xsave_bad_rsvd2(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[2] = 0x167169;
}

static void
bad_xregs_xsave_bad_rsvd3(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[3] = 0xff7;
}

static void
bad_xregs_xsave_bad_rsvd4(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[4] = 0x00f00;
}

static void
bad_xregs_xsave_bad_rsvd5(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_XSAVE);
	VERIFY3P(info, !=, NULL);
	prxregset_xsave_t *xsave = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	xsave->prx_xsh_reserved[5] = 0x2374013;
}

/*
 * The following tests are all 32-bit specific.
 */
#ifdef __i386
static void
bad_xregs_ymm_ilp32(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_YMM);
	VERIFY3P(info, !=, NULL);
	prxregset_ymm_t *ymm = (void *)((uintptr_t)*bufp + info->pri_offset);
	ymm->prx_rsvd[4]._l[3] = 0x12345;
}

static void
bad_xregs_zmm_ilp32(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_ZMM);
	VERIFY3P(info, !=, NULL);
	prxregset_zmm_t *zmm = (void *)((uintptr_t)*bufp + info->pri_offset);
	zmm->prx_rsvd[2]._l[5] = 0x23456;
}

static void
bad_xregs_hi_zmm_ilp32(void **bufp, size_t *sizep)
{
	prxregset_hdr_t *hdr = bad_xregs_std_init(bufp, sizep);
	prxregset_info_t *info = bad_xregs_find_info(hdr, PRX_INFO_HI_ZMM);
	VERIFY3P(info, !=, NULL);
	prxregset_hi_zmm_t *hi_zmm = (void *)((uintptr_t)*bufp +
	    info->pri_offset);
	hi_zmm->prx_rsvd[1]._l[9] = 0x34567;
}
#endif	/* __i386 */

static const bad_xregs_test_t bad_tests[] = {
	{ "no data (NULL buffer)", EINVAL, XSU_YMM, bad_xregs_no_data },
	{ "NULL buffer, non-zero count", EFAULT, XSU_YMM, bad_xregs_null_buf },
	{ "incomplete prxregset_hdr_t", EINVAL, XSU_YMM, bad_xregs_short_hdr },
	{ "prxregset_hdr_t has wrong type", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_type },
	{ "prxregset_hdr_t size is too large", EINVAL, XSU_YMM,
	    bad_xregs_hdr_too_large },
	{ "prxregset_hdr_t size bigger than /proc write", EINVAL, XSU_YMM,
	    bad_xregs_missing_data },
	{ "prxregset_hdr_t invalid flags", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_flags },
	{ "prxregset_hdr_t invalid pad[0]", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_pad0 },
	{ "prxregset_hdr_t invalid pad[1]", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_pad1 },
	{ "prxregset_hdr_t invalid pad[2]", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_pad2 },
	{ "prxregset_hdr_t invalid pad[3]", EINVAL, XSU_YMM,
	    bad_xregs_hdr_bad_pad3 },
	{ "prxregset_hdr_t no info structures", EINVAL, XSU_YMM,
	    bad_xregs_hdr_no_info },
	{ "prxregset_hdr_t len doesn't cover info structures", EINVAL, XSU_YMM,
	    bad_xregs_hdr_no_info_len },
	{ "prxregset_info_t has bad flags", EINVAL, XSU_YMM,
	    bad_xregs_info_flags },
	{ "prxregset_info_t has bad type", EINVAL, XSU_YMM,
	    bad_xregs_info_type },
	{ "prxregset_info_t has bad len (XCR)", EINVAL, XSU_YMM,
	    bad_xregs_info_xcr_len },
	{ "prxregset_info_t has bad align (XCR)", EINVAL, XSU_YMM,
	    bad_xregs_info_xcr_off },
	{ "prxregset_info_t has bad len (XSAVE)", EINVAL, XSU_YMM,
	    bad_xregs_info_xsave_len },
	{ "prxregset_info_t has bad align (XSAVE)", EINVAL, XSU_YMM,
	    bad_xregs_info_xsave_off },
	{ "prxregset_info_t has bad len (YMM)", EINVAL, XSU_YMM,
	    bad_xregs_info_ymm_len },
	{ "prxregset_info_t has bad align (YMM)", EINVAL, XSU_YMM,
	    bad_xregs_info_ymm_off },
	{ "prxregset_info_t has bad len (OPMASK)", EINVAL, XSU_ZMM,
	    bad_xregs_info_opmask_len },
	{ "prxregset_info_t has bad align (OPMASK)", EINVAL, XSU_ZMM,
	    bad_xregs_info_opmask_off },
	{ "prxregset_info_t has bad len (ZMM)", EINVAL, XSU_ZMM,
	    bad_xregs_info_zmm_len },
	{ "prxregset_info_t has bad align (ZMM)", EINVAL, XSU_ZMM,
	    bad_xregs_info_zmm_off },
	{ "prxregset_info_t has bad len (HI ZMM)", EINVAL, XSU_ZMM,
	    bad_xregs_info_hi_zmm_len },
	{ "prxregset_info_t has bad align (HI ZMM)", EINVAL, XSU_ZMM,
	    bad_xregs_info_hi_zmm_off },
	{ "prxregset_info_t offset exceeds total len (offset beyond len)",
	    EINVAL, XSU_YMM, bad_xregs_info_exceeds_len0 },
	{ "prxregset_info_t offset exceeds total len (size+offset beyond len)",
	    EINVAL, XSU_YMM, bad_xregs_info_exceeds_len1 },
	{ "prxregset_info_t offset overlaps info", EINVAL, XSU_YMM,
	    bad_xregs_info_overlaps },
	{ "prxregset_t missing xsave struct", EINVAL, XSU_YMM,
	    bad_xregs_no_xsave },
	{ "prxregset_t missing xstate bit-vector entry", EINVAL, XSU_YMM,
	    bad_xregs_missing_xstate },
	{ "prxregset_xcr_t modified xcr0", EINVAL, XSU_YMM,
	    bad_xregs_xcr_bad_xcr0 },
	{ "prxregset_xcr_t modified xfd", EINVAL, XSU_YMM,
	    bad_xregs_xcr_bad_xfd },
	{ "prxregset_xcr_t modified pad[0]", EINVAL, XSU_YMM,
	    bad_xregs_xcr_bad_pad0 },
	{ "prxregset_xcr_t modified pad[1]", EINVAL, XSU_YMM,
	    bad_xregs_xcr_bad_pad1 },
	{ "prxregset_xsave_t illegal xbv comp", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_xbv },
	{ "prxregset_xsave_t illegal compressed comp", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_xcomp },
	{ "prxregset_xsave_t illegal rsvd[0]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd0 },
	{ "prxregset_xsave_t illegal rsvd[1]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd1 },
	{ "prxregset_xsave_t illegal rsvd[2]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd2 },
	{ "prxregset_xsave_t illegal rsvd[3]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd3 },
	{ "prxregset_xsave_t illegal rsvd[4]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd4 },
	{ "prxregset_xsave_t illegal rsvd[5]", EINVAL, XSU_YMM,
	    bad_xregs_xsave_bad_rsvd5 },
/*
 * These next sets of tests are specific to 32-bit binaries as they're not
 * allowed to access a bunch of the additional registers that exist.
 */
#ifdef __i386
	{ "prxregset_ymm_t has non-zero reserved i386 reg", EINVAL, XSU_YMM,
	    bad_xregs_ymm_ilp32 },
	{ "prxregset_zmm_t has non-zero reserved i386 reg", EINVAL, XSU_ZMM,
	    bad_xregs_zmm_ilp32 },
	{ "prxregset_hi_zmm_t has non-zero reserved i386 reg", EINVAL, XSU_ZMM,
	    bad_xregs_hi_zmm_ilp32 },
#endif
};

int
main(void)
{
	int ret;
	int estatus = EXIT_SUCCESS;
	struct ps_prochandle *P;
	struct ps_lwphandle *L;
	thread_t targ;
	uint32_t hwsup;
	uint32_t nskip = 0;

	hwsup = xsu_hwsupport();
	P = Pgrab(getpid(), PGRAB_RDONLY, &ret);
	if (P == NULL) {
		errx(EXIT_FAILURE, "failed to grab ourself: %s",
		    Pgrab_error(ret));
	}

	ret = thr_create(NULL, 0, xsu_sleeper_thread, NULL, THR_DETACHED,
	    &targ);
	if (ret != 0) {
		errc(EXIT_FAILURE, ret, "failed to create sleeper thread");
	}

	L = Lgrab(P, targ, &ret);
	if (L == NULL) {
		errx(EXIT_FAILURE, "failed to grab our sleeper thread: %s",
		    Lgrab_error(ret));
	}

	ret = Lstop(L, 0);
	if (ret != 0) {
		err(EXIT_FAILURE, "failed to stop the sleeper thread");
	}

	if (Lgetxregs(L, &bad_xregs_pxr, &bad_xregs_size) != 0) {
		err(EXIT_FAILURE, "failed to get basic xregs");
	}

	if (bad_xregs_size < sizeof (prxregset_hdr_t)) {
		errx(EXIT_FAILURE, "found bad regset size: %zu",
		    bad_xregs_size);
	}

	for (size_t i = 0; i < ARRAY_SIZE(bad_tests); i++) {
		void *buf = NULL;
		size_t len = 0;

		if (bad_tests[i].bxt_min > hwsup) {
			warnx("TEST SKIPPED: %s: requires greater hwsup than "
			    "supported (0x%x)", bad_tests[i].bxt_desc,
			    bad_tests[i].bxt_min);
			nskip++;
			continue;
		}

		bad_tests[i].bxt_setup(&buf, &len);
		if (Lsetxregs(L, buf, len) != -1) {
			warnx("TEST FAILED: %s: Lsetxregs returned 0, not -1!",
			    bad_tests[i].bxt_desc);
			estatus = EXIT_FAILURE;
		} else if (errno != bad_tests[i].bxt_errno) {
			warnx("TEST FAILED: %s: Lsetxregs errno was %d, "
			    "expected %d", bad_tests[i].bxt_desc, errno,
			    bad_tests[i].bxt_errno);
			estatus = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s\n",
			    bad_tests[i].bxt_desc);
		}
		free(buf);
	}

	if (estatus == EXIT_SUCCESS && nskip > 0) {
		warnx("While tests were successful, %u tests were skipped "
		    "due to missing hardware support", nskip);
	}

	exit(estatus);
}
