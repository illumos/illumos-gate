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
 * Copyright 2018 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "testlib.h"
#include "mevent.h"

static char *cookie = "Chocolate chip with fudge stripes";

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static void
callback(int fd, enum ev_type ev, void *arg)
{
	static off_t size = 0;
	struct stat st;

	ASSERT_INT_EQ(("bad event"), ev, EVF_VNODE);
	ASSERT_PTR_EQ(("bad cookie"), arg, cookie);

	if (fstat(fd, &st) != 0)
		FAIL_ERRNO("fstat failed");

	ASSERT_INT64_NEQ(("File size has not changed"), size, st.st_size);
	size = st.st_size;

	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));
	pthread_mutex_unlock(&mtx);
}

static void
test_fd(int fd, char *tag)
{
	struct mevent *evp;
	int err;

	evp = mevent_add_flags(fd, EVF_VNODE, EVFF_ATTRIB, callback, cookie);
	ASSERT_PTR_NEQ(("%s: mevent_add", tag), evp, NULL);

	for (uint_t i = 0; cookie[i] != '\0'; i++) {
		ssize_t written;

		pthread_mutex_lock(&mtx);

		if (i > 0) {
			/*
			 * Check that no events are emitted for writes which do
			 * not alter the size.
			 */
			if (lseek(fd, -1, SEEK_CUR) == -1)
				FAIL_ERRNO("lseek");
			if (write(fd, "X", 1) == -1)
				FAIL_ERRNO("write");
		}

		written = write(fd, cookie + i, 1);
		if (written < 0)
			FAIL_ERRNO("bad write");
		ASSERT_INT64_EQ(("write byte %d of cookie", i), written, 1);

		/* Wait for the size change to be processed */
		pthread_cond_wait(&cv, &mtx);
		pthread_mutex_unlock(&mtx);
		/*
		 * This is a bit unsatisfactory but we need to allow time
		 * for mevent to re-associate the port or the next write could
		 * be missed.
		 */
		usleep(500);
	}

	err = mevent_disable(evp);
	ASSERT_INT_EQ(("%s: mevent_disable: %s", tag, strerror(err)), err, 0);

	(void) printf("PASS %s - %s\n", testlib_prog, tag);
}

int
main(int argc, const char **argv)
{
	start_test(argv[0], 5);
	start_event_thread();
	int fd;

	/* Test with a temporary file in /tmp */
	char *template = strdup("/tmp/mevent.vnode.XXXXXX");
	ASSERT_PTR_NEQ(("strdup"), template, NULL);
	fd = mkstemp(template);
	if (fd == -1)
		FAIL_ERRNO("Couldn't create temporary file with mkstemp");

	VERBOSE(("Opened temporary file at '%s'", template));

	test_fd(fd, "temporary file");

	/* Test with a file which is unlinked from the filesystem */
	FILE *fp = tmpfile();
	ASSERT_PTR_NEQ(("tmpfile"), fp, NULL);

	fd = fileno(fp);
	if (fd == -1)
		FAIL_ERRNO("Couldn't get file descriptor for temporary file");

	test_fd(fd, "anon file");

	/*
	 * Defer to here to avoid generating a new event before the disable has
	 * been processed and the port deassociated.
	 */
	unlink(template);
	free(template);

	PASS();
}
