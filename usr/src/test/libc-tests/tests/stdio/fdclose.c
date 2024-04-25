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
 * Copyright 2025 Hans Rosenfeld
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <err.h>
#include <limits.h>

static int
fdclose_test(char *ident, FILE *fp, int exp_ret, int exp_fd, int exp_errno)
{
	int fd = INT_MIN;
	int ret = 0;

	errno = 0;
	ret = fdclose(fp, &fd);
	if (ret != exp_ret)
		err(EXIT_FAILURE, "%s unexpected result %d (expected %d)",
		    ident, ret, exp_ret);

	if (fd != exp_fd)
		err(EXIT_FAILURE, "%s unexpected fd %d (expected %d)",
		    ident, fd, exp_fd);

	if (errno != exp_errno)
		errx(EXIT_FAILURE, "%s unexpected errno %s (expected %s)",
		    ident, strerrorname_np(errno), strerrorname_np(exp_errno));

	return (fd);
}

int
main(int argc, char **argv)
{
	int ret = 0;
	char buf[33];
	int fd;
	FILE *devnull;
	FILE *mem;
	struct stat stat;
	ino_t ino;

	/*
	 * Use /dev/null for our first tests. Open it as a file, then fstat it
	 * and get the underlying inode.
	 */
	fd = open("/dev/null", O_WRONLY);
	if (fd == -1)
		err(EXIT_FAILURE, "open(/dev/null)");

	if (fstat(fd, &stat) == -1)
		err(EXIT_FAILURE, "fstat(/dev/null) after open()");

	ino = stat.st_ino;

	/*
	 * Now, fdopen() this to get a FILE to work with. Make sure the FILE
	 * is backed by the right fd.
	 */
	devnull = fdopen(fd, "w");
	if (devnull == NULL)
		err(EXIT_FAILURE, "fdopen(/dev/null)");

	if (fileno(devnull) != fd)
		err(EXIT_FAILURE, "fileno(/dev/null): unexpected fd %d "
		    "(expected %d)", fileno(devnull), fd);

	/*
	 * Verify fdclose() works on a FILE which is already open.
	 */
	fd = fdclose_test("fdclose(/dev/null)", devnull, 0, fd, 0);

	/*
	 * Verify that the underlying file descriptor hasn't changed.
	 */
	if (fileno(devnull) != fd)
		err(EXIT_FAILURE, "fileno(/dev/null): unexpected fd %d "
		    "(expected %d)", fileno(devnull), fd);

	/*
	 * Verify that we can still fstat() the file descriptor, and that the
	 * inode hasn't changed.
	 */
	if (fstat(fd, &stat) == -1)
		err(EXIT_FAILURE, "fstat(/dev/null) after fdclose()");

	if (ino != stat.st_ino)
		errx(EXIT_FAILURE, "/dev/null inode changed after fdclose(): "
		    "%ld (expected %ld)", stat.st_ino, ino);

	/*
	 * Calling fdclose() again on a closed FILE should return EOF without
	 * setting errno. It should also return the file descriptor. This is
	 * decidedly not part of the interface specification, it's only an
	 * implementation detail of fdclose() and fclose_helper().
	 */
	fd = fdclose_test("2nd fdclose(/dev/null)", devnull, EOF, fd, 0);

	/*
	 * Verify the FILE is indeed closed by writing to it, which should
	 * return EOF. This is an illumos-specific implementation detail,
	 * what fputs() or any other stdio function would do on a closed FILE
	 * is undefined behaviour.
	 */
	ret = fputs("Hello World\n", devnull);
	if (ret != EOF)
		errx(1, "unexpected result from fputs(\"Hello World\\n\") "
		    "on closed FILE, ret = %d", ret);

	/*
	 * Verify that the underlying file descriptor is still open for writing,
	 * so this should not fail.
	 */
	ret = write(fd, "Goodbye Cruel World\n", 20);
	if (ret < 0)
		err(1, "write(/dev/null) failed");

	/*
	 * Close /dev/null, we're done with it. Try to fstat() it again, which
	 * now should fail.
	 */
	(void) close(fd);

	ret = fstat(fd, &stat);
	if (ret != -1)
		errx(EXIT_FAILURE, "unexpected result from fstat(/dev/null) "
		    "after close(), ret = %d", ret);

	/*
	 * Verify fdclose() works as expected on a memory stream: The stream is
	 * closed, the fd returned is -1, and errno is ENOTSUP.
	 */
	bzero(buf, sizeof (buf));
	mem = fmemopen(buf, sizeof (buf), "w");
	if (mem == NULL)
		err(1, "fmemopen() failed");

	ret = fputs("Hello World\n", mem);
	if (ret == EOF)
		err(1, "fputs(mem) failed");

	fd = fdclose_test("fdclose(mem)", mem, EOF, -1, ENOTSUP);

	ret = fputs("Goodbye Cruel World\n", mem);
	if (ret != EOF)
		errx(1, "fputs(..., mem) on closed FILE, ret = %d "
		    "(expected EOF)", ret);

	/*
	 * Verify that only the string successfully written into the FILE ended
	 * up in the buffer.
	 */
	if (strcmp(buf, "Hello World\n") != 0)
		errx(1, "mem contents unexpected: %s\n"
		    "expected: %s", buf, "Hello World\n");

	printf("tests passed\n");
	return (0);
}
