/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2012, Joyent, Inc.  All rights reserved.
 */

/*
 * This is a simple test program to exercise the hyprlofs ioctls.  This is
 * not designed as a full featured CLI and only does minimal error checking
 * and reporting.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <strings.h>
#include <sys/errno.h>
#include <sys/fs/hyprlofs.h>

extern int errno;

char *usage =	"usage: <fs path> add [<file name> <alias>]+\n"
		"       <fs path> addl [<file name>]+\n"
		"       <fs path> rm [<alias>]+\n"
		"       <fs path> clear"
		"       <fs path> get";

typedef enum {
	CMD_ADD,
	CMD_RM,
	CMD_CLR,
	CMD_ADDL,
	CMD_GET
} cmd_t;

static int
get_entries(int fd)
{
	int err;
	int i;
	hyprlofs_curr_entries_t e;
	hyprlofs_curr_entry_t *ep;

	e.hce_cnt = 0;
	e.hce_entries = NULL;

	err = ioctl(fd, HYPRLOFS_GET_ENTRIES, &e);
	if (err != 0 && errno != E2BIG) {
		perror("ioctl");
		return (1);
	}

	if (err == 0) {
		(void) printf("success, but no entries\n");
		return (0);
	}

	/*
	 * E2BIG is what we expect when there are existing mappings
	 * since the current cnt is still returned in that case.
	 */
	(void) printf("cnt: %d\n", e.hce_cnt);

	/* alloc array and call again, then print array */
	if ((ep = (hyprlofs_curr_entry_t *)
	    malloc(sizeof (hyprlofs_curr_entry_t) * e.hce_cnt)) == NULL) {
		(void) fprintf(stderr, "out of memory\n");
		exit(1);
	}

	e.hce_entries = ep;
	errno = 0;
	if (ioctl(fd, HYPRLOFS_GET_ENTRIES, &e) != 0) {
		/*
		 * Not handling an increase here. We would need to free and
		 * start over to do that, but ok for a test program.
		 */
		perror("ioctl");
		free(ep);
		return (1);
	}
	for (i = 0; i < e.hce_cnt; i++)
		(void) printf("%s %s\n", ep[i].hce_path, ep[i].hce_name);

	free(ep);
	return (0);
}

int
main(int argc, char **argv)
{
	int i, ap;
	cmd_t cmd;
	int cnt = 0;
	int fd;
	int rv = 0;
	hyprlofs_entry_t *e = NULL;
	hyprlofs_entries_t ents;

	if (argc < 3) {
		(void) fprintf(stderr, "%s\n", usage);
		exit(1);
	}

	if ((fd = open(argv[1], O_RDONLY)) < 0) {
		perror("can't open hyprlofs mount");
		exit(1);
	}

	if (strcmp(argv[2], "add") == 0) {
		cmd = CMD_ADD;
	} else if (strcmp(argv[2], "rm") == 0) {
		cmd = CMD_RM;
	} else if (strcmp(argv[2], "clear") == 0) {
		cmd = CMD_CLR;
	} else if (strcmp(argv[2], "addl") == 0) {
		cmd = CMD_ADDL;
	} else if (strcmp(argv[2], "get") == 0) {
		cmd = CMD_GET;
	} else {
		(void) fprintf(stderr, "%s\n", usage);
		exit(1);
	}

	/* Count up the number of parameters. The arg format varies w/ cmd */
	switch (cmd) {
	case CMD_ADD:
		for (i = 3; i < argc; i++) {
			/* argv[i] is the file path */

			/* The next arg is the alias */
			if (++i >= argc) {
				(void) fprintf(stderr, "missing alias for %s\n",
				    argv[i - 1]);
				exit(1);
			}

			cnt++;
		}
		break;
	case CMD_ADDL:
		cnt = argc - 3;
		break;
	case CMD_RM:
		cnt = argc - 3;
		break;
	case CMD_CLR:	/*FALLTHRU*/
	case CMD_GET:
		if (argc > 3) {
			(void) fprintf(stderr, "%s\n", usage);
			exit(1);
		}
		break;
	}

	if (cnt > 0) {
		if ((e = (hyprlofs_entry_t *)malloc(sizeof (hyprlofs_entry_t) *
		    cnt)) == NULL) {
			(void) fprintf(stderr, "out of memory\n");
			exit(1);
		}
	}

	/*
	 * Format up the args.
	 * We only setup the path member for the add cmd.
	 * We won't run this loop for the clear cmd.
	 * The addl command is special since we use basename to get the alias.
	 */
	for (i = 0, ap = 3; i < cnt; i++, ap++) {
		if (cmd == CMD_ADDL) {
			e[i].hle_path = argv[ap];
			e[i].hle_plen = strlen(e[i].hle_path);

			e[i].hle_name = basename(argv[ap]);
			e[i].hle_nlen = strlen(e[i].hle_name);

			continue;
		}

		if (cmd == CMD_ADD) {
			e[i].hle_path = argv[ap++];
			e[i].hle_plen = strlen(e[i].hle_path);
		}

		e[i].hle_name = argv[ap];
		e[i].hle_nlen = strlen(e[i].hle_name);
	}

	ents.hle_entries = e;
	ents.hle_len = cnt;

	switch (cmd) {
	case CMD_ADD:	/*FALLTHRU*/
	case CMD_ADDL:
		if (ioctl(fd, HYPRLOFS_ADD_ENTRIES, &ents) < 0)  {
			perror("ioctl");
			rv = 1;
		}
		break;
	case CMD_RM:
		if (ioctl(fd, HYPRLOFS_RM_ENTRIES, &ents) < 0)  {
			perror("ioctl");
			rv = 1;
		}
		break;
	case CMD_CLR:
		if (ioctl(fd, HYPRLOFS_RM_ALL) < 0)  {
			perror("ioctl");
			rv = 1;
		}
		break;
	case CMD_GET:
		rv = get_entries(fd);
		break;
	}

	(void) close(fd);
	if (cnt > 0)
		free(e);
	return (rv);
}
