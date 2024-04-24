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
 * Copyright 2024 Bill Sommerfeld <sommerfeld@hamachi.org>
 */

/*
 * Test that SHA1Update and SHA2Update correctly adjust the bit count
 * when fed large inputs.
 *
 * This is a very focussed white-box unit test that examines
 * handling of the running message bit count updated by SHA*Update.
 *
 * Since we are only testing the bit count updates in this test,
 * we point SHA*Update at a buffer with an unmapped page, catch
 * the SIGSEGV, and siglongjmp back out to the test assertions.
 */

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>

#include <sha1.h>
#include <sha2.h>
#include <sys/debug.h>
#include <sys/mman.h>

static sigjmp_buf from_trap;
static struct sigaction trap_sa;
static void *buf;

static long pagesize;

static void
trap_handler(int signo, siginfo_t *info, void *ucp)
{

	if ((info->si_addr >= buf + pagesize) &&
	    (info->si_addr < (buf + 2 * pagesize))) {
		siglongjmp(from_trap, signo);
	}

	printf("faulting address outside sentinel page\n");
	printf("signal: %d code: %d faulting address: %p\n",
	    info->si_signo, info->si_code, info->si_addr);

}

static void
test_update_sha1(void *buf, size_t len, uint32_t c0, uint32_t c1)
{
	SHA1_CTX ctx;
	VERIFY3U(len, >, pagesize);

	SHA1Init(&ctx);
	VERIFY3U(0, ==, ctx.count[0]);
	VERIFY3U(0, ==, ctx.count[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA1Update(&ctx, buf, len);
		errx(EXIT_FAILURE, "Should have faulted in SHA1Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count[0]);
		VERIFY3U(c1, ==, ctx.count[1]);
	}

	if (len <= pagesize * 2)
		return;

	/*
	 * Try again with the same length split across two calls
	 * to SHA1Update to exercise the other way that the high
	 * order word of the bit count gets incremented.
	 */
	SHA1Init(&ctx);
	SHA1Update(&ctx, buf, pagesize);
	VERIFY3U(0, ==, ctx.count[0]);
	VERIFY3U(pagesize * 8, ==, ctx.count[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA1Update(&ctx, buf, len - pagesize);
		errx(EXIT_FAILURE, "Should have faulted in SHA1Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count[0]);
		VERIFY3U(c1, ==, ctx.count[1]);
	}
}

static void
test_update_32(uint64_t mech, void *buf, size_t len, uint32_t c0, uint32_t c1)
{
	SHA2_CTX ctx;
	VERIFY3U(len, >, pagesize);

	SHA2Init(mech, &ctx);
	VERIFY3U(0, ==, ctx.count.c32[0]);
	VERIFY3U(0, ==, ctx.count.c32[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA2Update(&ctx, buf, len);
		errx(EXIT_FAILURE, "Should have faulted in SHA2Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count.c32[0]);
		VERIFY3U(c1, ==, ctx.count.c32[1]);
	}

	if (len <= pagesize * 2)
		return;

	/*
	 * Try again with the same length split across two calls
	 * to SHA2Update to exercise the other way that the high
	 * order word of the bit count gets incremented.
	 */
	SHA2Init(mech, &ctx);
	SHA2Update(&ctx, buf, pagesize);
	VERIFY3U(0, ==, ctx.count.c32[0]);
	VERIFY3U(pagesize * 8, ==, ctx.count.c32[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA2Update(&ctx, buf, len - pagesize);
		errx(EXIT_FAILURE, "Should have faulted in SHA2Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count.c32[0]);
		VERIFY3U(c1, ==, ctx.count.c32[1]);
	}
}

static void
test_update_64(uint64_t mech, void *buf, size_t len, uint64_t c0, uint64_t c1)
{
	SHA2_CTX ctx;
	VERIFY3U(len, >, pagesize);

	SHA2Init(mech, &ctx);
	VERIFY3U(0, ==, ctx.count.c64[0]);
	VERIFY3U(0, ==, ctx.count.c64[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA2Update(&ctx, buf, len);
		errx(EXIT_FAILURE, "Should have faulted in SHA2Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count.c64[0]);
		VERIFY3U(c1, ==, ctx.count.c64[1]);
	}

	if (len <= pagesize * 2)
		return;

	/*
	 * Try again with the same length split across two calls
	 * to SHA2Update to exercise the other way that the high
	 * order word of the bit count gets incremented.
	 */
	SHA2Init(mech, &ctx);
	SHA2Update(&ctx, buf, pagesize);
	VERIFY3U(0, ==, ctx.count.c64[0]);
	VERIFY3U(pagesize * 8, ==, ctx.count.c64[1]);

	if (sigsetjmp(from_trap, 1) == 0) {
		(void) sigaction(SIGSEGV, &trap_sa, NULL);
		SHA2Update(&ctx, buf, len - pagesize);
		errx(EXIT_FAILURE, "Should have faulted in SHA2Update "
		    "(after %ld of %zu bytes)", pagesize, len);
	} else {
		(void) signal(SIGSEGV, SIG_DFL);
		VERIFY3U(c0, ==, ctx.count.c64[0]);
		VERIFY3U(c1, ==, ctx.count.c64[1]);
	}
}

int
main(int argc, char **argv)
{
	uint64_t len, max_len;
	int flags = MAP_PRIVATE|MAP_ANON;

#ifdef _LP64
	flags |= MAP_32BIT;
#endif
	pagesize = sysconf(_SC_PAGESIZE);
	buf = mmap(0, 2 * pagesize, PROT_READ|PROT_WRITE, flags, -1, 0);
	if (buf == MAP_FAILED) {
		err(EXIT_FAILURE, "mmap MAP_PRIVATE|MAP_ANON|... "
		    "of %ld bytes failed", 2 * pagesize);
	}
	if (mprotect(buf + pagesize, pagesize, PROT_NONE) < 0) {
		err(EXIT_FAILURE, "mprotect of %ld bytes at %p failed",
		    pagesize, buf + pagesize);
	}

	/*
	 * When we set this sigaction, we intend to catch exactly one trap:
	 * a memory reference to the page we've just protected.
	 */
	memset(&trap_sa, 0, sizeof (trap_sa));
	trap_sa.sa_flags = SA_SIGINFO|SA_RESETHAND;
	trap_sa.sa_sigaction = trap_handler;

	max_len = SIZE_MAX;
	for (len = pagesize * 2; len != 0 && len < max_len; len <<= 1) {
		printf("test SHA1 length 0x%016lx\n", len);
		test_update_sha1(buf, len, len >> 29, len << 3);
	}

	for (len = pagesize * 2; len != 0 && len < max_len; len <<= 1) {
		printf("test SHA256 length 0x%016lx\n", len);
		test_update_32(SHA256, buf, len, len >> 29, len << 3);
	}

	for (len = pagesize * 2; len != 0 && len < max_len; len <<= 1) {
		printf("test SHA512 length 0x%016lx\n", len);
		test_update_64(SHA512, buf, len, len >> 61, len << 3);
	}
	return (EXIT_SUCCESS);
}
