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
 * Copyright 2020 Joyent, Inc.
 */

/*
 * This program watches a directory with portfs or inotify, exiting when the
 * directory is removed.  It is useful in tests that ensure that watching a
 * directory does not prevent it from being used as a mount point.
 */
#include <limits.h>
#include <port.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <unistd.h>

void
fail_usage(void)
{
	(void) fprintf(stderr, "Usage: watch <portfs|inotify> directory\n");
	exit(1);
}

#define	MAX_PES 8

void
watch_port(const char *path)
{
	int port;
	struct file_obj fobj = {0};

	if ((port = port_create()) < 0) {
		perror("port_create");
		exit(1);
	}

	fobj.fo_name = (char *)path;
	for (;;) {
		timespec_t ts = {300, 0};
		port_event_t pe;

		if (port_associate(port, PORT_SOURCE_FILE, (uintptr_t)&fobj,
		    0, (char *)path) != 0) {
			perror("port_associate");
			exit(1);
		}

		if (port_get(port, &pe, &ts) != 0) {
			perror("port_get");
			exit(1);
		}

		if (pe.portev_events & FILE_DELETE) {
			(void) printf("DELETE\t%s\n", path);
			exit(0);
		}
		if (pe.portev_events & MOUNTEDOVER) {
			(void) printf("MOUNTEDOVER\t%s\n", path);
		}
	}
}

void
watch_inotify(const char *path)
{
	int in, wd;
	struct inotify_event ev;

	if ((in = inotify_init()) < 0) {
		perror("inotify_init");
		exit(1);
	}
	if ((wd = inotify_add_watch(in, path, IN_DELETE_SELF)) == -1) {
		perror("inotify_add_watch");
		exit(1);
	}

	for (;;) {
		ssize_t cnt;
		char evpath[PATH_MAX];

		cnt = read(in, &ev, sizeof (ev));
		if (cnt != sizeof (ev)) {
			(void) fprintf(stderr,
			    "read: expected %ld bytes got %ld\n",
			    sizeof (ev), cnt);
			exit(1);
		}
		if (ev.len != 0) {
			if (ev.len > sizeof (evpath)) {
				(void) fprintf(stderr, "read: oversize "
				    "path (%u bytes)\n", ev.len);
				exit(1);
			}
			cnt = read(in, evpath, ev.len);
			if (cnt != ev.len) {
				(void) fprintf(stderr, "read: expected %ld "
				    "bytes for path, got %ld\n", ev.len, cnt);
				exit(1);
			}
			evpath[ev.len - 1] = '\0';
		} else {
			evpath[0] = '\0';
		}
		if (ev.mask & IN_DELETE_SELF) {
			/*
			 * IN_DELETE_SELF events don't appear to include
			 * the path in the event.
			 */
			(void) printf("DELETE_SELF\n");
			exit(0);
		} else {
			(void) printf("EVENT_%08x\t%s\n", ev.mask, evpath);
		}

	}
}

int
main(int argc, char **argv)
{
	const char *watcher, *path;

	if (argc != 3) {
		fail_usage();
	}
	watcher = argv[1];
	path = argv[2];

	if (strcmp(watcher, "portfs") == 0) {
		watch_port(path);
	} else if (strcmp(watcher, "inotify") == 0) {
		watch_inotify(path);
	} else {
		fail_usage();
	}

	return (0);
}
