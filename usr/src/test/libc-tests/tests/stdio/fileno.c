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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Tests to verify fileno(3C) behavior. This test explicitly leaks fds and FILE
 * structures to make it easier to verify the subsequent fd behavior works and
 * is apparent through the FILE *.
 */

#include <stdio.h>
#include <unistd.h>
#include <err.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <wchar.h>

#define	FNO_DUPFD	150

static uint_t fno_nfails;
static uint_t fno_ntests;
static int fno_nextfd;

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}


static void
check_file(FILE *fp, int fd, const char *msg)
{
	int act = fileno(fp);
	if (act != fd) {
		(void) printf("TEST FAILED: %s: expected fd %d, found %d\n",
		    msg, fd, act);
		fno_nfails++;
	} else {
		(void) printf("TEST PASSED: %s\n", msg);
	}
	fno_ntests++;
}

static void
check_open_n(int n)
{
	int fdbase;
	uint_t i;

	for (i = 0, fdbase = fno_nextfd; i < n; i++, fdbase++) {
		FILE *f = fopen("/dev/null", "w+");
		if (f == NULL) {
			err(EXIT_FAILURE, "failed to open /dev/null");
		}
		check_file(f, fdbase, "Consecutive FDs");
	}
}

static void
check_memstream(void)
{
	FILE *fmem, *omem, *wmem;
	char *buf;
	wchar_t *wbuf;
	size_t size;

	fmem = fmemopen(NULL, 10, "w+");
	if (fmem == NULL) {
		err(EXIT_FAILURE, "failed to fmemopen()");
	}

	omem = open_memstream(&buf, &size);
	if (omem == NULL) {
		err(EXIT_FAILURE, "failed to open_memstream()");
	}

	wmem = open_wmemstream(&wbuf, &size);
	if (wmem == NULL) {
		err(EXIT_FAILURE, "failed to open_wmemstream()");
	}

	check_file(fmem, -1, "basic fmemopen()");
	check_file(omem, -1, "basic open_memstream()");
	check_file(wmem, -1, "basic open_wmemstream()");
}

static void
check_fdopen(void)
{
	int fd, dupfd;
	FILE *f;

	fd = open("/dev/null", O_RDWR);
	if (fd < 0) {
		err(EXIT_FAILURE, "failed to open /dev/null");
	}
	fno_nextfd = fd + 1;

	f = fdopen(fd, "r+");
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to fdopen /dev/null");
	}
	check_file(f, fd, "fdopen");

	if ((dupfd = dup2(fd, FNO_DUPFD)) != FNO_DUPFD) {
		err(EXIT_FAILURE, "failed to dup2 /dev/null");
	}
	f = fdopen(dupfd, "r+");
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to fdopen dup2'd /dev/null");
	}
	check_file(f, dupfd, "fdopen of dup2'd file");

	f = freopen("/dev/zero", "r+", f);
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to freopen dup2'd FILE *");
	}
	check_file(f, fno_nextfd, "freopen dup2'd FILE *");
	fno_nextfd++;
}

static void
check_alternate(void)
{
	wchar_t *c;
	size_t s, i;

	for (i = 0; i < 10; i++) {
		FILE *f, *save;
		f = fmemopen(NULL, 10, "a+");
		if (f == NULL) {
			err(EXIT_FAILURE, "failed to create fmemopen stream");
		}
		check_file(f, -1, "alternating memstream, fopen (fmemopen)");

		save = f;
		f = fopen("/dev/zero", "r+");
		if (f == NULL) {
			err(EXIT_FAILURE, "failed to open /dev/zero");
		}
		check_file(f, fno_nextfd, "alternating memstream, fopen "
		    "(file)");
		fno_nextfd++;

		f = open_wmemstream(&c, &s);
		if (f == NULL) {
			err(EXIT_FAILURE, "failed to create open_wmemstream() "
			    "stream");
		}
		check_file(f, -1, "alternating memstream, fopen (wmemstream)");

		f = freopen("/dev/null", "r+", save);
		if (f == NULL) {
			err(EXIT_FAILURE, "failed to freopen /dev/null from "
			    "fmemopen()");
		}
		check_file(f, fno_nextfd, "alternating memstream, fopen "
		    "(reopen)");

		f = freopen("/dev/zero", "a+", f);
		check_file(f, fno_nextfd, "alternating memstream, fopen "
		    "(reopen file)");
		fno_nextfd++;
	}
}

int
main(void)
{
	check_file(stdin, STDIN_FILENO, "default stdin fd is correct");
	check_file(stdout, STDOUT_FILENO, "default stdout fd is correct");
	check_file(stderr, STDERR_FILENO, "default stderr fd is correct");

	/*
	 * Establish our base fd. The test runner can open files on our behalf.
	 */
	fno_nextfd = open("/dev/null", O_RDONLY);
	if (fno_nextfd < 0) {
		err(EXIT_FAILURE, "failed to open /dev/null");
	}
	fno_nextfd++;
	check_open_n(10);
	fno_nextfd += 10;
	check_memstream();
	check_fdopen();
	check_alternate();

	printf("%d/%d tests passed\n", fno_ntests - fno_nfails, fno_ntests);
	return (fno_nfails > 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}
