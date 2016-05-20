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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Test and verify that pthrad_attr_get_np works as we expect.
 *
 * Verify the following:
 *   o ESRCH
 *   o stack size is set to a valid value after a thread is created.
 *   o main thread can grab an alternate thread's info.
 *   o custom guard size is honored
 *   o detach state
 *   	- detached	1
 *   	- joinable		2
 *   	- changing		2
 *   o daemon state
 *   	- enabled	1
 *   	- disabled		2
 *   o scope
 *   	- system	1
 *   	- process		2
 *   o inheritable
 *   	- inherit	1
 *   	- explicit		2
 *   o priority
 *   	- honors change		2
 *   o policy
 *   	- honours change	2
 *
 *
 * For each of the cases above we explicitly go through and create the set of
 * attributes as marked above and then inside of a thread, verify that the
 * attributes match what we expect. Because each case ends up in creating a
 * detached thread, we opt to have both it and the main thread enter a barrier
 * to indicate that we have completed the test successfully.
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <ucontext.h>
#include <sched.h>
#include <strings.h>
#include <stdlib.h>

#include <sys/procfs.h>
#include <sys/debug.h>

/*
 * Currently these are only defined in thr_uberdata.h. Rather than trying and
 * fight with libc headers, just explicitly define them here.
 */
#define	PTHREAD_CREATE_DAEMON_NP	0x100	/* = THR_DAEMON */
#define	PTHREAD_CREATE_NONDAEMON_NP	0
extern	int	pthread_attr_setdaemonstate_np(pthread_attr_t *, int);
extern	int	pthread_attr_getdaemonstate_np(const pthread_attr_t *, int *);

#define	PGN_TEST_PRI	23

static pthread_attr_t pgn_attr;
static pthread_attr_t pgn_thr_attr;
static pthread_barrier_t pgn_barrier;

#ifdef	__sparc
#define	gregs	__gregs
#endif

/*
 * Verify that the stack pointer of a context is consistent with where the
 * attributes indicate.
 */
static void
pgn_verif_thr_stack(pthread_attr_t *attr)
{
	size_t stksz;
	void *stk;
	ucontext_t ctx;
	uint32_t sp;

	VERIFY0(getcontext(&ctx));
	VERIFY0(pthread_attr_getstack(attr, &stk, &stksz));
	VERIFY3P(stk, !=, NULL);
	VERIFY3S(stksz, !=, 0);
	sp = ctx.uc_mcontext.gregs[R_SP];
	VERIFY3U(sp, >, (uintptr_t)stk);
	VERIFY3U(sp, <, (uintptr_t)stk + stksz);
}

#ifdef	__sparc
#undef	gregs
#endif

static void
pgn_test_fini(void)
{
	int ret;

	ret = pthread_barrier_wait(&pgn_barrier);
	VERIFY(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
	VERIFY0(pthread_attr_destroy(&pgn_attr));
	VERIFY0(pthread_attr_destroy(&pgn_thr_attr));
	VERIFY0(pthread_barrier_destroy(&pgn_barrier));
}

static void
pgn_test_init(void)
{
	VERIFY0(pthread_attr_init(&pgn_attr));
	VERIFY0(pthread_attr_init(&pgn_thr_attr));
	VERIFY0(pthread_barrier_init(&pgn_barrier, NULL, 2));
}

/* ARGSUSED */
static void *
pgn_set_one_thr(void *arg)
{
	int odetach, ndetach;
	int odaemon, ndaemon;
	int oscope, nscope;
	int oinherit, ninherit;

	VERIFY0(pthread_attr_get_np(pthread_self(), &pgn_attr));
	pgn_verif_thr_stack(&pgn_attr);

	VERIFY0(pthread_attr_getdetachstate(&pgn_thr_attr, &odetach));
	VERIFY0(pthread_attr_getdetachstate(&pgn_attr, &ndetach));

	VERIFY3S(odetach, ==, ndetach);
	VERIFY3S(ndetach, ==, PTHREAD_CREATE_DETACHED);

	VERIFY0(pthread_attr_getdaemonstate_np(&pgn_thr_attr, &odaemon));
	VERIFY0(pthread_attr_getdaemonstate_np(&pgn_attr, &ndaemon));

	VERIFY3S(odaemon, ==, ndaemon);
	VERIFY3S(ndaemon, ==, PTHREAD_CREATE_DAEMON_NP);

	VERIFY0(pthread_attr_getscope(&pgn_thr_attr, &oscope));
	VERIFY0(pthread_attr_getscope(&pgn_attr, &nscope));

	VERIFY3S(oscope, ==, nscope);
	VERIFY3S(nscope, ==, PTHREAD_SCOPE_SYSTEM);

	VERIFY0(pthread_attr_getinheritsched(&pgn_thr_attr, &oinherit));
	VERIFY0(pthread_attr_getinheritsched(&pgn_attr, &ninherit));

	VERIFY3S(oinherit, ==, ninherit);
	VERIFY3S(ninherit, ==, PTHREAD_INHERIT_SCHED);

	VERIFY3S(pthread_barrier_wait(&pgn_barrier), !=, 1);
	return (NULL);
}

static void
pgn_set_one(void)
{
	int ret;
	pthread_t thr;

	pgn_test_init();

	VERIFY0(pthread_attr_setdetachstate(&pgn_thr_attr,
	    PTHREAD_CREATE_DETACHED));
	VERIFY0(pthread_attr_setdaemonstate_np(&pgn_thr_attr,
	    PTHREAD_CREATE_DAEMON_NP));
	VERIFY0(pthread_attr_setscope(&pgn_thr_attr, PTHREAD_SCOPE_SYSTEM));
	VERIFY0(pthread_attr_setinheritsched(&pgn_thr_attr,
	    PTHREAD_INHERIT_SCHED));

	VERIFY0(pthread_create(&thr, &pgn_thr_attr, pgn_set_one_thr, NULL));

	/*
	 * Verify it's not joinable.
	 */
	ret = pthread_join(thr, NULL);
	VERIFY3S(ret, ==, EINVAL);

	/*
	 * At this point we let the test continue and wait on the barrier. We'll
	 * wake up when the other thread is done.
	 */
	pgn_test_fini();
}

/* ARGSUSED */
static void *
pgn_set_two_thr(void *arg)
{
	int odetach, ndetach;
	int odaemon, ndaemon;
	int oscope, nscope;
	int oinherit, ninherit;
	int opolicy, npolicy;
	struct sched_param oparam, nparam;

	VERIFY0(pthread_attr_get_np(pthread_self(), &pgn_attr));
	pgn_verif_thr_stack(&pgn_attr);

	VERIFY0(pthread_attr_getdetachstate(&pgn_thr_attr, &odetach));
	VERIFY0(pthread_attr_getdetachstate(&pgn_attr, &ndetach));

	VERIFY3S(odetach, ==, ndetach);
	VERIFY3S(ndetach, ==, PTHREAD_CREATE_JOINABLE);

	VERIFY0(pthread_attr_getdaemonstate_np(&pgn_thr_attr, &odaemon));
	VERIFY0(pthread_attr_getdaemonstate_np(&pgn_attr, &ndaemon));

	VERIFY3S(odaemon, ==, ndaemon);
	VERIFY3S(ndaemon, ==, PTHREAD_CREATE_NONDAEMON_NP);

	VERIFY0(pthread_attr_getscope(&pgn_thr_attr, &oscope));
	VERIFY0(pthread_attr_getscope(&pgn_attr, &nscope));

	VERIFY3S(oscope, ==, nscope);
	VERIFY3S(nscope, ==, PTHREAD_SCOPE_PROCESS);

	VERIFY0(pthread_attr_getinheritsched(&pgn_thr_attr, &oinherit));
	VERIFY0(pthread_attr_getinheritsched(&pgn_attr, &ninherit));

	VERIFY3S(oinherit, ==, ninherit);
	VERIFY3S(ninherit, ==, PTHREAD_EXPLICIT_SCHED);

	VERIFY0(pthread_attr_getschedpolicy(&pgn_thr_attr, &opolicy));
	VERIFY0(pthread_attr_getschedpolicy(&pgn_attr, &npolicy));

	VERIFY3S(opolicy, ==, npolicy);
	VERIFY3S(npolicy, ==, SCHED_FSS);

	/*
	 * Now that we've validated the basics, go ahead and test the changes,
	 * which include making sure that we see updates via
	 * pthread_setschedparam() and pthread_detach().
	 */
	VERIFY0(pthread_detach(pthread_self()));

	opolicy = SCHED_FX;
	oparam.sched_priority = PGN_TEST_PRI;
	VERIFY0(pthread_setschedparam(pthread_self(), opolicy, &oparam));

	VERIFY0(pthread_attr_get_np(pthread_self(), &pgn_attr));
	VERIFY0(pthread_attr_getdetachstate(&pgn_attr, &ndetach));

	VERIFY3S(odetach, !=, ndetach);
	VERIFY3S(ndetach, ==, PTHREAD_CREATE_DETACHED);

	VERIFY0(pthread_attr_getschedpolicy(&pgn_attr, &npolicy));
	VERIFY0(pthread_attr_getschedparam(&pgn_attr, &nparam));

	VERIFY3S(opolicy, ==, npolicy);
	VERIFY3S(npolicy, ==, SCHED_FX);

	VERIFY3S(oparam.sched_priority, ==, nparam.sched_priority);
	VERIFY3S(nparam.sched_priority, ==, PGN_TEST_PRI);

	VERIFY3S(pthread_barrier_wait(&pgn_barrier), !=, 1);

	return (NULL);
}

static void
pgn_set_two(void)
{
	pthread_t thr;

	pgn_test_init();

	VERIFY0(pthread_attr_setdetachstate(&pgn_thr_attr,
	    PTHREAD_CREATE_JOINABLE));
	VERIFY0(pthread_attr_setdaemonstate_np(&pgn_thr_attr,
	    PTHREAD_CREATE_NONDAEMON_NP));
	VERIFY0(pthread_attr_setscope(&pgn_thr_attr, PTHREAD_SCOPE_PROCESS));
	VERIFY0(pthread_attr_setinheritsched(&pgn_thr_attr,
	    PTHREAD_EXPLICIT_SCHED));
	VERIFY0(pthread_attr_setschedpolicy(&pgn_thr_attr, SCHED_FSS));

	VERIFY0(pthread_create(&thr, &pgn_thr_attr, pgn_set_two_thr, NULL));

	/*
	 * At this point we let the test continue and wait on the barrier. We'll
	 * wake up when the other thread is done.
	 */
	pgn_test_fini();
}

/* ARGSUSED */
static void *
pgn_set_three_thr(void *arg)
{
	VERIFY3S(pthread_barrier_wait(&pgn_barrier), !=, 1);

	return (NULL);
}

void
pgn_set_three(void)
{
	pthread_t thr;
	pthread_attr_t altattr, selfattr;
	void *altstk, *selfstk;
	size_t altsz, selfsz;

	VERIFY0(pthread_attr_init(&altattr));
	VERIFY0(pthread_attr_init(&selfattr));
	pgn_test_init();

	VERIFY0(pthread_create(&thr, NULL, pgn_set_three_thr, NULL));

	VERIFY0(pthread_attr_get_np(thr, &altattr));
	VERIFY0(pthread_attr_get_np(pthread_self(), &selfattr));

	VERIFY0(pthread_attr_getstack(&selfattr, &selfstk, &selfsz));
	VERIFY0(pthread_attr_getstack(&altattr, &altstk, &altsz));
	VERIFY3P(altstk, !=, selfstk);

	pgn_test_fini();
	VERIFY0(pthread_attr_destroy(&selfattr));
	VERIFY0(pthread_attr_destroy(&altattr));
}

int
main(void)
{
	int ret;

	VERIFY0(pthread_attr_init(&pgn_attr));

	ret = pthread_attr_get_np(UINT32_MAX, &pgn_attr);
	VERIFY3S(ret, ==, ESRCH);

	pgn_set_one();
	pgn_set_two();
	pgn_set_three();

	exit(0);
}
