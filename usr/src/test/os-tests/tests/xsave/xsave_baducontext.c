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
 * The purpose of this test is to go through and construct ucontext_t xsave
 * states that we expect to be invalid and therefore cause setcontext(2) to
 * fail. We only assume that %ymm state is present here with respect to writing
 * invalid tests. As if this test runs at all, that will be present.
 *
 * This is structured a little differently as we expect this program to fail to
 * execute and that libc will cause us to abort() if we don't correctly return
 * from setcontext.
 */

#include <ucontext.h>
#include <err.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <sys/debug.h>
#include <sys/x86_archext.h>
#include <sys/mman.h>
#include <unistd.h>

#include "xsave_util.h"

static void *xsave_buf;
static const char *curtest;

static void
bad_success(void)
{
	errx(EXIT_FAILURE, "TEST FAILED: %s setcontext, took us to success",
	    curtest);
}

static void
test_bad_version(ucontext_t *ctx)
{
	uc_xsave_t *xc = (uc_xsave_t *)ctx->uc_xsave;
	xc->ucx_vers = 23;
}

static void
test_bad_length_small(ucontext_t *ctx)
{
	uc_xsave_t *xc = (uc_xsave_t *)ctx->uc_xsave;
	xc->ucx_len = 0;
}

static void
test_bad_length_large(ucontext_t *ctx)
{
	uc_xsave_t *xc = (uc_xsave_t *)ctx->uc_xsave;
	xc->ucx_len = INT32_MAX;
}

/*
 * As this can run on multiple different systems, we explicitly use bit 8 which
 * is reserved for a supervisor feature and so should never be valid in this
 * context.
 */
static void
test_bad_vector(ucontext_t *ctx)
{
	uc_xsave_t *xc = (uc_xsave_t *)ctx->uc_xsave;
	xc->ucx_bv |= (1 << 8);
}

static void
test_context_too_short(ucontext_t *ctx)
{
	uc_xsave_t *xc = (uc_xsave_t *)ctx->uc_xsave;

	bcopy(xc, xsave_buf, xc->ucx_len);
	ctx->uc_xsave = (long)(uintptr_t)xsave_buf;
	xc = (uc_xsave_t *)ctx->uc_xsave;
	xc->ucx_bv |= XFEATURE_AVX;
	xc->ucx_len = sizeof (uc_xsave_t) + 0x10;
}

static void
test_context_badptr0(ucontext_t *ctx)
{
	ctx->uc_xsave = 0;
}

static void
test_context_badptr1(ucontext_t *ctx)
{
	void *addr = mmap(NULL, sysconf(_SC_PAGESIZE), PROT_NONE,
	    MAP_PRIVATE | MAP_ANON, -1, 0);
	if (addr == NULL) {
		err(EXIT_FAILURE, "failed to get unmapped page");
	}

	ctx->uc_xsave = (long)(uintptr_t)addr;
}

static void
test_context_badptr2(ucontext_t *ctx)
{
	long pgsz = sysconf(_SC_PAGESIZE);
	void *addr = mmap(NULL, pgsz * 2, PROT_NONE, MAP_PRIVATE | MAP_ANON,
	    -1, 0);
	if (addr == NULL) {
		errx(EXIT_FAILURE, "failed to get unmapped page");
	}

	if (mprotect((void *)((uintptr_t)addr + pgsz), pgsz, PROT_NONE) != 0) {
		err(EXIT_FAILURE, "failed to mprotect second page");
	}

	ctx->uc_xsave = (uintptr_t)addr;
	ctx->uc_xsave += pgsz - sizeof (uint64_t);
}

static ucontext_t *
setup_context(void)
{
	ucontext_t *ctx = ucontext_alloc(0);
	if (ctx == NULL) {
		errx(EXIT_FAILURE, "failed to get allocate ucontext_t");
	}

	if (getcontext_extd(ctx, 0) != 0) {
		err(EXIT_FAILURE, "failed to get extended context");
	}
	xsu_ustack_alloc(ctx);
	makecontext(ctx, bad_success, 0);

	return (ctx);
}

typedef struct {
	void (*bct_func)(ucontext_t *);
	const char *bct_test;
	int bct_errno;
} bad_ucontext_test_t;

/*
 * Do not use single quote characters in tests below, that'll break the shell
 * wrapper.
 */
static const bad_ucontext_test_t tests[] = {
	{ test_bad_version, "invalid version", EINVAL },
	{ test_bad_length_small, "invalid length (small)", EINVAL },
	{ test_bad_length_large, "invalid length (large)", EINVAL },
	{ test_bad_vector, "invalid xbv", EINVAL },
	{ test_context_too_short, "length does not cover AVX", EOVERFLOW },
	{ test_context_badptr0, "invalid uc_xsave pointer (NULL)", EINVAL },
	{ test_context_badptr1, "invalid uc_xsave pointer (unmapped page)",
	    EFAULT },
	{ test_context_badptr2, "partially invalid uc_xsave (hit "
	    "unmapped page)", EFAULT },
};

int
main(int argc, char *argv[])
{
	int c;
	char *eptr;
	unsigned long l;
	const char *testno = NULL;
	boolean_t do_info = B_FALSE, do_run = B_FALSE;

	if (argc < 2) {
		(void) fprintf(stderr, "Usage:  %s [-c] [-i testno] "
		    "[-r testno]\n", argv[0]);
	}

	while ((c = getopt(argc, argv, ":ci:r:")) != -1) {
		switch (c) {
		case 'c':
			(void) printf("%zu\n", ARRAY_SIZE(tests));
			return (0);
		case 'i':
			testno = optarg;
			do_info = B_TRUE;
			break;
		case 'r':
			testno = optarg;
			do_run = B_TRUE;
			break;
		case ':':
			errx(EXIT_FAILURE, "Option -%c requires an operand\n",
			    optopt);
			break;
		case '?':
			errx(EXIT_FAILURE, "Unknown option: -%c\n", optopt);
			break;
		}
	}

	if (testno == NULL) {
		errx(EXIT_FAILURE, "one of -r and -i must be specified");
	}

	if (do_run && do_info) {
		errx(EXIT_FAILURE, "only one of -r and -i may be specified");
	}

	errno = 0;
	l = strtoul(testno, &eptr, 0);
	if (*eptr != 0 || errno != 0) {
		errx(EXIT_FAILURE, "failed to parse test number: %s", argv[1]);
	}

	if (l >= ARRAY_SIZE(tests)) {
		errx(EXIT_FAILURE, "test number %lu is too large\n", l);
	}

	if (do_info) {
		/*
		 * Output info for our wrapper shell script in a way that's not
		 * too bad to eval.
		 */
		(void) printf("errno=%u\ndesc='%s'\n", tests[l].bct_errno,
		    tests[l].bct_test);
		return (0);
	}

	/*
	 * This is a little gross, but we know right now that the extended
	 * context is going to be the approximate size that we need for
	 * operations on the system.
	 */
	xsave_buf = ucontext_alloc(0);
	if (xsave_buf == NULL) {
		err(EXIT_FAILURE, "failed to alternative xsave buf");
	}

	ucontext_t *ctx = setup_context();
	VERIFY3U(ctx->uc_xsave, !=, 0);
	tests[l].bct_func(ctx);
	(void) setcontext(ctx);
	errx(EXIT_FAILURE, "TEST FAILED: setcontext returned despite us "
	    "expecting a core");
}
