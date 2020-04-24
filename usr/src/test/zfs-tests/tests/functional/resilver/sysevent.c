/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at http://smartos.org/CDDL
 *
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2020 Joyent, Inc.
 *
 */

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>

FILE *out;

static void
process_event(sysevent_t *ev)
{
	char *class = NULL;
	char *subclass = NULL;

	/* get sysevent metadata and add to the nvlist */
	class = sysevent_get_class_name(ev);
	subclass = sysevent_get_subclass_name(ev);

	if (class == NULL || subclass == NULL)
		errx(EXIT_FAILURE, "failed to retrieve sysevent metadata");

	VERIFY0(strcmp(class, EC_ZFS));
	VERIFY0(strcmp(subclass, ESC_ZFS_RESILVER_START));

	flockfile(out);
	(void) fprintf(out, "Received %s.%s event\n", class, subclass);
	(void) fflush(out);
	funlockfile(out);
}

static void
child_fatal(int fd, const char *msg, ...)
{
	va_list ap;
	int fail = EXIT_FAILURE;

	va_start(ap, msg);
	(void) vfprintf(stderr, msg, ap);
	va_end(ap);
	(void) fputc('\n', stderr);

	(void) write(fd, &fail, sizeof (fail));
	(void) close(fd);
	exit(EXIT_FAILURE);
}

static void
do_child(int fd)
{
	const char *subclasses[] = {
		ESC_ZFS_RESILVER_START,
	};
	sysevent_handle_t *handle;
	int ret = 0;

	if ((handle = sysevent_bind_handle(process_event)) == NULL) {
		child_fatal(fd, "sysevent_bind_handle() failed: %s",
		    strerror(errno));
	}

	if (sysevent_subscribe_event(handle, EC_ZFS, subclasses,
	    ARRAY_SIZE(subclasses)) != 0) {
		child_fatal(fd, "failed to subscribe to sysevents: %s",
		    strerror(errno));
	}

	(void) write(fd, &ret, sizeof (ret));
	(void) close(fd);

	/* leave stderr open so any errors get captured by test harness */
	(void) fclose(stdin);
	(void) fclose(stdout);

	for (;;)
		(void) pause();
}

int
main(int argc, char **argv)
{
	pid_t child;
	int fds[2];
	int ret = 0;

	if (argc < 2) {
		(void) fprintf(stderr, "Usage: %s outfile\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	if ((out = fopen(argv[1], "w")) == NULL)
		err(EXIT_FAILURE, "unable to open %s", argv[1]);

	VERIFY0(pipe(fds));

	switch (child = fork()) {
	case -1:
		err(EXIT_FAILURE, "unable to fork");
	case 0:
		do_child(fds[1]);
		break;
	default:
		break;
	}

	(void) close(fds[1]);

	if (read(fds[0], &ret, sizeof (ret)) < 0)
		err(EXIT_FAILURE, "failure waiting on child");

	if (ret != 0)
		return (ret);

	(void) close(fds[0]);
	(void) printf("%d\n", child);
	return (0);
}
