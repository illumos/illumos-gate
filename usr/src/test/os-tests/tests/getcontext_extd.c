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
 * Basic test for getcontext_extd() variant. We have two cases that we need to
 * consider. A ucontext_t that is allocated and initialized from the stack and
 * then one that comes from a ucontext_alloc(). We test both that setcontext()
 * and makecontext() work with these.
 */

#include <ucontext.h>
#include <unistd.h>
#include <stdlib.h>
#include <err.h>
#include <string.h>
#include <errno.h>
#include <upanic.h>

#define	STACK_MAGIC	42
#define	EXIT_MAGIC	23
static volatile uint32_t count = 0;
static volatile uint32_t stack_count = 0;

static void
successful_exit(uint32_t test)
{
	if (test != EXIT_MAGIC) {
		errx(EXIT_FAILURE, "TEST FAILED: makecontext had wrong "
		    "argument, found 0x%x, expected 0x%x", test, EXIT_MAGIC);
	}

	printf("TEST PASSED: makecontext called with right argument\n");
	exit(0);
}

static void
getcontext_stack(uint32_t test)
{
	ucontext_t ctx;

	if (test != STACK_MAGIC) {
		errx(EXIT_FAILURE, "TEST FAILED: makecontext had wrong "
		    "argument, found 0x%x, expected 0x%x", test, STACK_MAGIC);
	}

	(void) memset(&ctx, 0, sizeof (ctx));

	if (getcontext_extd(&ctx, 0) != 0) {
		err(EXIT_FAILURE, "failed to get extended context from stack");
	}

	count++;
	if (count < 5) {
		const char *msg = "stack setcontext returned, sorry";
		(void) setcontext(&ctx);
		upanic(msg, strlen(msg) + 1);
	}

	(void) printf("TEST PASSED: stack ucontext_t / getcontext_extd() / "
	    "setcontext() combo worked\n");
	ctx.uc_stack.ss_sp = calloc(SIGSTKSZ, sizeof (uint8_t));
	if (ctx.uc_stack.ss_sp == NULL) {
		err(EXIT_FAILURE, "failed to allocate second makecontext "
		    "stack");
	}
	ctx.uc_stack.ss_size = SIGSTKSZ;
	ctx.uc_stack.ss_flags = 0;
	makecontext(&ctx, successful_exit, 1, EXIT_MAGIC);
	(void) setcontext(&ctx);

	err(EXIT_FAILURE, "TEST FAILED: stack ucontext_t / makecontext() "
	    "returned from setcontext()");
}

int
main(void)
{
	ucontext_t *ctx = ucontext_alloc(0);
	if (ctx == NULL) {
		err(EXIT_FAILURE, "failed to get allocate ucontext_t");
	}

	if (getcontext_extd(ctx, 23) == 0) {
		errx(EXIT_FAILURE, "TEST FAILED: getcontext_extd worked with "
		    "bad flags");
	}

	if (errno != EINVAL) {
		errx(EXIT_FAILURE, "TEST FAILED: getcontext_extd returned "
		    "wrong errno for bad flags: 0x%x", errno);
	}

	if (getcontext_extd(ctx, 0) != 0) {
		err(EXIT_FAILURE, "failed to get extended context");
	}

	count++;
	if (count < 5) {
		const char *msg = "setcontext returned, sorry";
		(void) setcontext(ctx);
		upanic(msg, strlen(msg) + 1);
	}

	(void) printf("TEST PASSED: ucontext_alloc() / getcontext_extd() / "
	    "setcontext() combo worked\n");
	ctx->uc_stack.ss_sp = calloc(SIGSTKSZ, sizeof (uint8_t));
	if (ctx->uc_stack.ss_sp == NULL) {
		err(EXIT_FAILURE, "failed to allocate first makecontext "
		    "stack");
	}
	ctx->uc_stack.ss_size = SIGSTKSZ;
	ctx->uc_stack.ss_flags = 0;
	makecontext(ctx, getcontext_stack, 1, STACK_MAGIC);
	(void) setcontext(ctx);

	warn("TEST FAILED: failed to setcontext() to makecontext() from "
	    "ucontext_alloc() / getcontext_extd()");
	return (EXIT_FAILURE);
}
