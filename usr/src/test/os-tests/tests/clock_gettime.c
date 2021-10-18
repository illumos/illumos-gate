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
 * Copyright 2021 Oxide Comptuer Company
 */

/*
 * Test a bunch of basics around clocks.
 */

#include <time.h>
#include <err.h>
#include <stdlib.h>
#include <libproc.h>
#include <thread.h>
#include <sys/sysmacros.h>

typedef hrtime_t (*clock_alttime_f)(void);

typedef struct clock_gettime_test {
	clockid_t	cgt_clock;
	clock_alttime_f	cgt_alt;
	const char	*cgt_name;
} clock_gettime_test_t;

typedef struct clock_gettime_thr_arg {
	hrtime_t	cgta_usr;
	hrtime_t	cgta_usrsys;
} clock_gettime_thr_arg_t;

static hrtime_t
clock_ts2hrt(const timespec_t *tsp)
{
	return ((tsp->tv_sec * NANOSEC) + tsp->tv_nsec);
}

static hrtime_t
clock_gettime_proc(void)
{
	psinfo_t ps;

	if (proc_get_psinfo(getpid(), &ps) != 0) {
		warn("failed to get psinfo for process");
		return (0);
	}

	return (clock_ts2hrt(&ps.pr_time));
}

static hrtime_t
clock_gettime_thread(void)
{
	lwpsinfo_t lwpsinfo;

	if (proc_get_lwpsinfo(getpid(), thr_self(), &lwpsinfo) != 0) {
		warn("failed to get lwpsinfo for thread %u", thr_self());
		return (0);
	}

	return (clock_ts2hrt(&lwpsinfo.pr_time));
}

clock_gettime_test_t clock_tests[] = {
	{ CLOCK_HIGHRES, gethrtime, "highres" },
	{ CLOCK_VIRTUAL, gethrvtime, "virtual" },
	{ CLOCK_THREAD_CPUTIME_ID, clock_gettime_thread, "thread_cputime" },
	{ CLOCK_PROCESS_CPUTIME_ID, clock_gettime_proc, "proc_cputime" }
};

/*
 * Do a series of reads of the clock from clock_gettime and its secondary
 * source. Make sure that we always see increasing values.
 */
static boolean_t
clock_test(clock_gettime_test_t *test)
{
	hrtime_t hrt0, hrt1, hrt2, convts0, convts1;
	struct timespec ts0, ts1;
	boolean_t ret = B_TRUE;

	if (clock_gettime(test->cgt_clock, &ts0) != 0) {
		warn("failed to get clock %u", test->cgt_clock);
		return (B_FALSE);
	}

	hrt0 = test->cgt_alt();
	hrt1 = test->cgt_alt();

	if (clock_gettime(test->cgt_clock, &ts1) != 0) {
		warn("failed to get clock %u", test->cgt_clock);
		return (B_FALSE);
	}

	hrt2 = test->cgt_alt();

	convts0 = clock_ts2hrt(&ts0);
	convts1 = clock_ts2hrt(&ts1);

	if (convts0 > hrt0) {
		warnx("clock %s traveled backwards, clock_gettime ahead of "
		    "later alternate: clock_gettime %lld, alternate: %lld",
		    test->cgt_name, convts0, hrt0);
		ret = B_FALSE;
	}

	if (hrt0 > hrt1) {
		warnx("clock %s traveled backwards, alternate ahead of "
		    "later alternate: first alternate %lld, later "
		    "alternate: %lld", test->cgt_name, hrt0, hrt1);
		ret = B_FALSE;
	}

	if (convts1 > hrt2) {
		warnx("clock %s traveled backwards, clock_gettime ahead of "
		    "later alternate: clock_gettime %lld, alternate: %lld",
		    test->cgt_name, convts1, hrt2);
		ret = B_FALSE;
	}

	if (hrt1 > hrt2) {
		warnx("clock %s traveled backwards, alternate ahead of "
		    "later alternate: first alternate %lld, later "
		    "alternate: %lld", test->cgt_name, hrt1, hrt2);
		ret = B_FALSE;
	}

	if (convts0 > convts1) {
		warnx("clock %s traveled backwards, clock_gettime ahead of "
		    "later clock_gettime: first clock_gettime %lld, later "
		    "clock_gettime: %lld", test->cgt_name, convts0, convts1);
		ret = B_FALSE;
	}

	return (ret);
}

static void *
clock_test_thr(void *arg)
{
	boolean_t ret = B_TRUE;

	for (uint_t i = 0; i < ARRAY_SIZE(clock_tests); i++) {
		boolean_t rval = clock_test(&clock_tests[i]);
		if (!rval) {
			ret = B_FALSE;
		}

		(void) printf("TEST %s: basic %s usage and interleaving%s\n",
		    rval ? "PASSED" : "FAILED", clock_tests[i].cgt_name,
		    thr_self() == 1 ? "" : " (in thread)");
	}

	return ((void *)(uintptr_t)ret);
}

static void *
clock_test_cputime_thr(void *arg)
{
	struct timespec ts;
	clock_gettime_thr_arg_t *cp = arg;

	if (clock_gettime(CLOCK_VIRTUAL, &ts) != 0) {
		warn("failed to get clock CLOCK_VIRTUAL");
		cp->cgta_usr = 0;
	} else {
		cp->cgta_usr = clock_ts2hrt(&ts);
	}

	if (clock_gettime(CLOCK_VIRTUAL, &ts) != 0) {
		warn("failed to get clock CLOCK_VIRTUAL");
		cp->cgta_usrsys = 0;
	} else {
		cp->cgta_usrsys = clock_ts2hrt(&ts);
	}

	return (NULL);
}

/*
 * Compare the value of CLOCK_THREAD_CPUTIME_ID between a new thread and the
 * main thread.
 */
static boolean_t
clock_test_thread_clock(void)
{
	thread_t thr;
	clock_gettime_thr_arg_t arg;
	hrtime_t hrt;
	struct timespec ts;
	boolean_t ret = B_TRUE;

	if (thr_create(NULL, 0, clock_test_cputime_thr, &arg, 0, &thr) != 0) {
		errx(EXIT_FAILURE, "failed to create thread to run basic "
		    "tests!");
	}

	if (thr_join(thr, NULL, NULL) != 0) {
		errx(EXIT_FAILURE, "failed to join to thread that ran basic "
		    "tests");
	}

	if (clock_gettime(CLOCK_VIRTUAL, &ts) != 0) {
		warn("failed to get clock CLOCK_VIRTUAL");
		return (B_FALSE);
	}

	hrt = clock_ts2hrt(&ts);
	if (arg.cgta_usr > hrt) {
		warnx("new thread %u somehow had higher CLOCK_VIRTUAL time "
		    "than main thread: new thread: %lld, main thread: %lld",
		    thr, hrt, arg.cgta_usr);
		ret = B_FALSE;
	}

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
		warn("failed to get clock CLOCK_THREAD_CPUTIME_ID");
		return (B_FALSE);
	}

	hrt = clock_ts2hrt(&ts);
	if (arg.cgta_usr > hrt) {
		warnx("new thread %u somehow had higher "
		    "CLOCK_THREAD_CPUTIME_ID time than main thread: new "
		    "thread: %lld, main thread: %lld", thr, hrt, arg.cgta_usr);
		ret = B_FALSE;
	}

	return (ret);
}

/*
 * This test is a little circumspect. It's basically going to argue that all the
 * time we spent doing kernel actions should be larger than the additional bit
 * of user time to make a subsequent system call. That seems probably
 * reasonable given everything we've done; however, there's no way to feel like
 * it's not possibly going to lead to false positives. If so, then just delete
 * this.
 */
static boolean_t
clock_test_thread_sys(void)
{
	struct timespec usr, sys;
	hrtime_t hrtusr, hrtsys;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &sys) != 0) {
		warn("failed to get clock CLOCK_THREAD_CPUTIME_ID");
		return (B_FALSE);
	}

	if (clock_gettime(CLOCK_VIRTUAL, &usr) != 0) {
		warn("failed to get clock CLOCK_VIRTUAL");
		return (B_FALSE);
	}

	hrtusr = clock_ts2hrt(&usr);
	hrtsys = clock_ts2hrt(&sys);

	if (hrtusr > hrtsys) {
		warnx("CLOCK_VIRTUAL was greater than CLOCK_THREAD_CPUTIME_ID: "
		    "usr time: %lld, usr/sys time: %lld (this may be a race)",
		    hrtusr, hrtsys);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This is similar to clock_test_thread_sys(), but using the process clock and
 * the thread clock. This is circumspect for similar reasons.
 */
static boolean_t
clock_test_thread_proc(void)
{
	struct timespec thr, proc;
	hrtime_t hrtthr, hrtproc;

	if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &proc) != 0) {
		warn("failed to get clock CLOCK_VIRTUAL");
		return (B_FALSE);
	}

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &thr) != 0) {
		warn("failed to get clock CLOCK_THREAD_CPUTIME_ID");
		return (B_FALSE);
	}

	hrtthr = clock_ts2hrt(&thr);
	hrtproc = clock_ts2hrt(&proc);

	if (hrtthr > hrtproc) {
		warnx("CLOCK_THRAD_CPUTIME_ID was greater than "
		    "CLOCK_PROCESS_CPUTIME_ID: thr time: %lld, proc time: %lld "
		    "(this may be a race)", hrtthr, hrtproc);
		return (B_FALSE);
	}

	return (B_TRUE);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	void *thr_ret;
	thread_t thr;
	boolean_t bval;

	thr_ret = clock_test_thr(NULL);
	if (!(boolean_t)(uintptr_t)thr_ret) {
		ret = EXIT_FAILURE;
	}

	if (thr_create(NULL, 0, clock_test_thr, NULL, 0, &thr) != 0) {
		errx(EXIT_FAILURE, "failed to create thread to run basic "
		    "tests!");
	}

	if (thr_join(thr, NULL, &thr_ret) != 0) {
		errx(EXIT_FAILURE, "failed to join to thread that ran basic "
		    "tests");
	}

	if (!(boolean_t)(uintptr_t)thr_ret) {
		ret = EXIT_FAILURE;
	}

	bval = clock_test_thread_clock();
	(void) printf("TEST %s: comparing CLOCK_THREAD_CPUTIME_ID and "
	    "CLOCK_VIRTUAL between threads\n", bval ? "PASSED" : "FAILED");

	bval = clock_test_thread_sys();
	(void) printf("TEST %s: comparing CLOCK_THREAD_CPUTIME_ID and "
	    "CLOCK_VIRTUAL\n", bval ? "PASSED" : "FAILED");


	bval = clock_test_thread_proc();
	(void) printf("TEST %s: comparing CLOCK_THREAD_CPUTIME_ID and "
	    "CLOCK_PROCESS_CPUTIME_ID\n", bval ? "PASSED" : "FAILED");
	/*
	 * XXX CLOCK_THREAD_CPUTIME_ID > CLOCK_VIRTUAL for same thread?
	 * XXX CLOCK_PROCESS_CPUTIME_ID > CLOCK_THREAD_CPUTIME_ID
	 */

	return (ret);
}
