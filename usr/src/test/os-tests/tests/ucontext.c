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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <atomic.h>
#include <err.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/types.h>

static __thread uint64_t tlsvar;
static ucontext_t ctx;
static uint32_t failures;
static pthread_t tid;

#define	THREAD1_VALUE	0x1010
#define	THREAD2_VALUE	0x0202

void
report(char *tag)
{
	pthread_t ltid = pthread_self();

	printf("  %-14s: thread=%x, TLS variable=%x\n",
	    tag, (uint_t)ltid, tlsvar);
}

void
run(void)
{
	pthread_t ltid = pthread_self();

	printf("Coroutine started from second thread\n");
	report("coroutine");

	if (ltid != tid) {
		fprintf(stderr,
		    "FAIL: coroutine thread ID is %x, expected %x\n",
		    ltid, tid);
		atomic_inc_32(&failures);
	}

	if (tlsvar != THREAD2_VALUE) {
		fprintf(stderr,
		    "FAIL: coroutine TLS variable is %x, expected %x\n",
		    tlsvar, THREAD2_VALUE);
		atomic_inc_32(&failures);
	}
}

void *
thread(void *arg __unused)
{
	tlsvar = THREAD2_VALUE;

	report("second thread");
	/*
	 * setcontext() does not return if successful, checking the return
	 * value upsets smatch.
	 */
	(void) setcontext(&ctx);
	errx(EXIT_FAILURE, "setcontext() returned and should not have.");

	return (NULL);
}

int
main(void)
{
	char stk[SIGSTKSZ];
	void *status;

	tlsvar = THREAD1_VALUE;

	report("main thread");

	VERIFY0(getcontext(&ctx));
	ctx.uc_link = NULL;
	ctx.uc_stack.ss_sp = stk;
	ctx.uc_stack.ss_size = sizeof (stk);
	makecontext(&ctx, run, 0);

	VERIFY0(pthread_create(&tid, NULL, thread, NULL));
	VERIFY0(pthread_join(tid, &status));

	return (failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
