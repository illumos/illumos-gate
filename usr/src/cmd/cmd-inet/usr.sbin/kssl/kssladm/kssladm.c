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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <libscf.h>
#include <sys/errno.h>
#include <errno.h>
#include <sys/stropts.h>
#include "kssladm.h"


/*
 * kssladm(8)
 *
 * Command to manage the entries in kernel SSL proxy table. This is
 * a private command called indirectly from ksslcfg(8).
 */

boolean_t verbose = B_FALSE;

static void
usage_all(void)
{
	(void) fprintf(stderr, "Usage:\n");
	usage_create(B_FALSE);
	usage_delete(B_FALSE);
}

int
main(int argc, char **argv)
{
	int rv = SUCCESS;

	if (argc < 2) {
		usage_all();
		return (SMF_EXIT_ERR_CONFIG);
	}

	if (strcmp(argv[1], "create") == 0) {
		rv = do_create(argc, argv);
	} else if (strcmp(argv[1], "delete") == 0) {
		rv = do_delete(argc, argv);
	} else {
		(void) fprintf(stderr, "Unknown sub-command: %s\n", argv[1]);
		usage_all();
		rv = SMF_EXIT_ERR_CONFIG;
	}

	return (rv);
}


/*
 * Read a passphrase from the file into the supplied buffer.
 * A space character and the characters that follow
 * the space character will be ignored.
 * Return 0 when no valid passphrase was found in the file.
 */
static int
read_pass_from_file(const char *filename, char *buffer, size_t bufsize)
{
	char *line;
	char *p;
	FILE *fp;

	fp = fopen(filename, "r");
	if (fp == NULL) {
		(void) fprintf(stderr,
		    "Unable to open password file for reading");
		return (1);
	}

	line = fgets(buffer, bufsize, fp);
	(void) fclose(fp);
	if (line == NULL) {
		return (0);
	}

	for (p = buffer; *p != '\0'; p++) {
		if (isspace(*p)) {
			*p = '\0';
			break;
		}
	}

	return (p - buffer);
}


int
get_passphrase(const char *password_file, char *buf, int buf_size)
{
	if (password_file == NULL) {
		char *passphrase = getpassphrase("Enter passphrase: ");
		if (passphrase) {
			return (strlcpy(buf, passphrase, buf_size));
		}

		return (0);
	}

	return (read_pass_from_file(password_file, buf, buf_size));
}


int
kssl_send_command(char *buf, int cmd)
{
	int ksslfd;
	int rv;

	ksslfd = open("/dev/kssl", O_RDWR);
	if (ksslfd < 0) {
		perror("Cannot open /dev/kssl");
		return (-1);
	}

	if ((rv = ioctl(ksslfd, cmd, buf)) < 0) {
		switch (errno) {
		case EEXIST:
			(void) fprintf(stderr,
			    "Error: Can not create a INADDR_ANY instance"
			    " while another instance exists.\n");
			break;
		case EADDRINUSE:
			(void) fprintf(stderr,
			    "Error: Another instance with the same"
			    " proxy port exists.\n");
			break;
		default:
			perror("ioctl failure");
			break;
		}
	}

	(void) close(ksslfd);

	return (rv);
}
