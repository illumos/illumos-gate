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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Regression test for illumos#18362. A libc AIO worker handled only one
 * SIGAIOCANCEL over its lifetime. A later cancellation left the worker
 * blocked in read(2). The request did not complete and no notification
 * was sent. A process could only cancel one request per worker thread.
 *
 * The test sets the number of AIO worker threads and drives them through
 * their states. Counting threads blocked in read(2) confirms the state.
 *
 * Set the aio worker pool size via environment variable.
 * The test loops more times than there are worker threads.
 *   On each iteration:
 *   1) Get the count of threads blocked in read(2)
 *   2) Post the read to a pipe. No data is written, so the read blocks.
 *   3) Loop with timeout until one more thread is blocked in read(2)
 *   4) Call aio_cancel(3C)
 *
 * aio_error() does not report the failure. _aio_cancel_req() sets ECANCELED
 * before it sends the signal, so polling reports the request cancelled while
 * the worker is still in read(2). The test checks aio_error() for conformance
 * only.
 */

#include <sys/types.h>
#include <sys/lwp.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <aio.h>
#include <err.h>
#include <errno.h>
#include <libproc.h>
#include <limits.h>
#include <procfs.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * The default worker pool size in aio.c is 4. Rather than duplicate that
 * private knowledge, this test sets the pool size to 2, a size sufficient
 * to demonstrate all of the interesting states before and after the fix.
 */
#define	AIO_WORKERS	2

#define	AIO_STR_(x)	#x
#define	AIO_STR(x)	AIO_STR_(x)

/*
 * Maximum wait for a worker to accept a request, which takes well under a
 * millisecond. With the defect present, a request queues behind a worker
 * blocked in read(2) instead of entering read(2) itself.
 */
#define	AIO_SETTLE_MS	1000

/*
 * Maximum wait for a notification, which arrives in about a millisecond. A
 * failing run waits this long for each cancellation that goes unreported.
 */
#define	AIO_DEADLINE_MS	5000
static const struct timespec aio_deadline = {
	AIO_DEADLINE_MS / MILLISEC, 0
};

/*
 * The test polls for a worker blocked in read(2) every AIO_POLL_MS before
 * cancelling the request. AIO_SETTLE_TRIES polls sum to AIO_SETTLE_MS of
 * sleeping, so the wait is at least that long.
 */
#define	AIO_POLL_MS	100
#define	AIO_SETTLE_TRIES	(AIO_SETTLE_MS / AIO_POLL_MS)
static const struct timespec aio_poll = {
	0, MSEC2NSEC(AIO_POLL_MS)
};

/* A pool this size makes a failing run take minutes. */
#define	AIO_WORKERS_WARN	10

#define	AIO_BUFSZ	64

static pthread_mutex_t	aio_lock = PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP;
static pthread_cond_t	aio_cv = PTHREAD_COND_INITIALIZER;
static boolean_t	*aio_notified;

static void
aio_notify(union sigval sv)
{
	pthread_mutex_enter_np(&aio_lock);
	aio_notified[sv.sival_int] = B_TRUE;
	(void) pthread_cond_broadcast(&aio_cv);
	pthread_mutex_exit_np(&aio_lock);
}

/*
 * Wait for the notification of request i, up to AIO_DEADLINE_MS.
 *
 * One wait is enough. The cancellation we just issued is the only thing that
 * can complete this request, so either its notification arrives or nothing
 * ever will.
 */
static boolean_t
aio_await(uint_t i)
{
	boolean_t notified;

	pthread_mutex_enter_np(&aio_lock);
	if (!aio_notified[i]) {
		(void) pthread_cond_relclockwait_np(&aio_cv, &aio_lock,
		    CLOCK_MONOTONIC, &aio_deadline);
	}
	notified = aio_notified[i];
	pthread_mutex_exit_np(&aio_lock);

	return (notified);
}

typedef struct {
	int	air_fd;		/* the descriptor our requests read */
	uint_t	air_readers;	/* threads blocked reading it */
} aio_readers_t;

/*
 * Count the LWPs blocked in read(2) on our pipe.
 *
 * Each such thread is an AIO worker whose request has neither completed nor
 * been cancelled.
 * The AIO workers use pread(2) first and then fall back to read(2) on
 * descriptors that are not seekable, which includes this test's pipe.
 *
 * Matching the descriptor keeps the count to threads doing this test's work.
 * libc does not mark its workers, so an unrelated thread blocked on some
 * other descriptor would otherwise be indistinguishable from one of them.
 */
static int
aio_count_reader(void *cd, const lwpstatus_t *lsp)
{
	aio_readers_t *air = cd;

	if (lsp->pr_lwpid == (id_t)_lwp_self() || lsp->pr_syscall != SYS_read)
		return (0);

	if (lsp->pr_nsysarg < 1) {
		errx(EXIT_FAILURE, "TEST FAILED: read(2) on lwp %ld reports "
		    "%d arguments", (long)lsp->pr_lwpid, lsp->pr_nsysarg);
	}

	if (lsp->pr_sysarg[0] == air->air_fd)
		air->air_readers++;

	return (0);
}

static uint_t
aio_readers(struct ps_prochandle *P, int fd)
{
	aio_readers_t air = { .air_fd = fd, .air_readers = 0 };

	if (Plwp_iter(P, aio_count_reader, &air) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: could not iterate our own "
		    "threads");
	}

	return (air.air_readers);
}

/*
 * Iterations to run against the worker pool in force.
 *
 * A caller may set _AIO_MIN_WORKERS to test other pool sizes. The count
 * follows the environment rather than AIO_WORKERS. More requests than
 * workers is what forces a worker to take a second cancellation.
 *
 * Inspection of aio.c and testing show that the known failure modes are
 * fully exercised at two iterations per worker thread plus one.
 *
 * A value libc would reject leaves the pool size unknown to us, since libc
 * substitutes its own default rather than failing. The test stops instead of
 * copying that default.
 */
static uint_t
aio_iterations(void)
{
	const char	*workers = getenv("_AIO_MIN_WORKERS");
	const char	*errstr;
	long long	val;

	if (workers == NULL)
		errx(EXIT_FAILURE, "TEST FAILED: _AIO_MIN_WORKERS is unset");

	val = strtonum(workers, 1, INT_MAX, &errstr);
	if (errstr != NULL) {
		errx(EXIT_FAILURE, "TEST FAILED: _AIO_MIN_WORKERS is %s, "
		    "which is %s; the worker pool size is not known", workers,
		    errstr);
	}

	if (val > AIO_WORKERS_WARN)
		warnx("_AIO_MIN_WORKERS is %lld, so this run may take minutes",
		    val);

	return ((2 * (uint_t)val) + 1);
}

int
main(int argc, char **argv)
{
	struct ps_prochandle	*P;
	int	fds[2];
	int	perr;
	uint_t	stuck = 0;
	uint_t	iterations;
	char	buf[AIO_BUFSZ];

	/*
	 * Ensure that the number of AIO workers is known, so that our model of
	 * the AIO behavior is correct.
	 *
	 * libc reads _AIO_MIN_WORKERS in its init section, so the pool size
	 * must be set before this process starts. If the caller did not
	 * choose one, set our own and exec ourselves again.
	 */
	if (getenv("_AIO_MIN_WORKERS") == NULL) {
		if (setenv("_AIO_MIN_WORKERS", AIO_STR(AIO_WORKERS), 1) != 0)
			err(EXIT_FAILURE, "TEST FAILED: setenv");
		(void) execvp(argv[0], argv);
		err(EXIT_FAILURE, "TEST FAILED: could not re-exec %s",
		    argv[0]);
	}

	iterations = aio_iterations();

	aio_notified = calloc(iterations, sizeof (*aio_notified));
	if (aio_notified == NULL)
		err(EXIT_FAILURE, "TEST FAILED: calloc");

	/*
	 * A read-only grab is the only kind permitted on the calling process,
	 * and it is all Plwp_iter() needs.
	 */
	P = Pgrab(getpid(), PGRAB_RDONLY, &perr);
	if (P == NULL) {
		errx(EXIT_FAILURE, "TEST FAILED: could not grab ourselves: %s",
		    Pgrab_error(perr));
	}

	if (pipe(fds) != 0)
		err(EXIT_FAILURE, "TEST FAILED: could not create a pipe");

	if (aio_readers(P, fds[0]) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: a thread is reading the pipe "
		    "before the first request");
	}

	for (uint_t i = 0; i < iterations; i++) {
		struct aiocb	cb;
		uint_t		before;
		uint_t		try;
		int		error;

		(void) memset(&cb, 0, sizeof (cb));
		cb.aio_fildes = fds[0];
		cb.aio_buf = buf;
		cb.aio_nbytes = sizeof (buf);
		cb.aio_sigevent.sigev_notify = SIGEV_THREAD;
		cb.aio_sigevent.sigev_notify_function = aio_notify;
		cb.aio_sigevent.sigev_value.sival_int = i;

		/* Get a baseline count for this iteration. */
		before = aio_readers(P, fds[0]);

		/*
		 * This read will block indefinitely.
		 *
		 * aio.c adds a worker only when it finds neither an idle
		 * worker nor an acquirable queue lock, which never happens
		 * with one request in flight, so the pool stays at the size
		 * requested above.
		 */
		if (aio_read(&cb) != 0)
			err(EXIT_FAILURE, "TEST FAILED: aio_read %u", i);

		/* Baseline + 1 means the request reached its own worker. */
		for (try = 0; try < AIO_SETTLE_TRIES; try++) {
			if (aio_readers(P, fds[0]) > before)
				break;
			(void) nanosleep(&aio_poll, NULL);
		}
		if (try == AIO_SETTLE_TRIES) {
			errx(EXIT_FAILURE, "TEST FAILED: request %u reached no "
			    "worker within %d ms, with %u already blocked in "
			    "read(2)", i, AIO_SETTLE_MS, before);
		}

		if (aio_cancel(fds[0], &cb) != AIO_CANCELED) {
			warnx("TEST FAILED: request %u was not cancelled", i);
			stuck++;
			continue;
		}

		if (!aio_await(i)) {
			warnx("TEST FAILED: request %u was cancelled but "
			    "never reported after %d ms", i, AIO_DEADLINE_MS);
			stuck++;
			continue;
		}

		/*
		 * aio_error() returns -1 when the aiocb names no outstanding
		 * request, which is a different failure from the request
		 * reporting the wrong status.
		 */
		error = aio_error(&cb);
		if (error == -1) {
			warnx("TEST FAILED: aio_error on request %u: %s", i,
			    strerror(errno));
			stuck++;
		} else if (error != ECANCELED) {
			warnx("TEST FAILED: request %u reported %s, expected "
			    "ECANCELED", i, strerror(error));
			stuck++;
		}
	}

	/*
	 * Any unreported cancellation is a failure. A worker whose
	 * cancellation was not delivered is still blocked in read(2), so
	 * report that count as well.
	 */
	if (stuck != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: %u of %u cancellations were "
		    "not reported, %u workers left blocked in read(2)", stuck,
		    iterations, aio_readers(P, fds[0]));
	}

	Prelease(P, 0);
	free(aio_notified);

	(void) printf("TEST PASSED: %u cancellations were all reported\n",
	    iterations);
	return (EXIT_SUCCESS);
}
