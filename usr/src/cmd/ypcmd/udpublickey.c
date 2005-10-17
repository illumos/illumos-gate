/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * YP updater for public key map
 */
#include <stdio.h>
#include <rpc/rpc.h>
#include <rpcsvc/ypclnt.h>
#include <sys/file.h>

extern char *malloc();

int
main(argc, argv)
	int argc;
	char *argv[];
{
	unsigned op;
	char name[MAXNETNAMELEN + 1];
	char key[256];
	char data[256];
	char line[256];
	unsigned keylen;
	unsigned datalen;
	FILE *rf;
	FILE *wf;
	char *fname;
	char *tmpname;
	int err;


	if (argc !=  3) {
		exit(YPERR_YPERR);
	}
	fname = argv[1];
	tmpname = malloc(strlen(fname) + 4);
	if (tmpname == NULL) {
		exit(YPERR_YPERR);
	}
	sprintf(tmpname, "%s.tmp", fname);

	/*
	 * Get input
	 */
	if (! scanf("%s\n", name)) {
		exit(YPERR_YPERR);
	}
	if (! scanf("%u\n", &op)) {
		exit(YPERR_YPERR);
	}
	if (! scanf("%u\n", &keylen)) {
		exit(YPERR_YPERR);
	}
	if (! fread(key, keylen, 1, stdin)) {
		exit(YPERR_YPERR);
	}
	key[keylen] = 0;
	if (! scanf("%u\n", &datalen)) {
		exit(YPERR_YPERR);
	}
	if (! fread(data, datalen, 1, stdin)) {
		exit(YPERR_YPERR);
	}
	data[datalen] = 0;

	/*
	 * Check permission
	 */
	if (strcmp(name, key) != 0) {
		exit(YPERR_ACCESS);
	}
	if (strcmp(name, "nobody") == 0) {
		/*
		 * Can't change "nobody"s key.
		 */
		exit(YPERR_ACCESS);
	}

	/*
	 * Open files
	 */
	rf = fopen(fname, "r");
	if (rf == NULL) {
		exit(YPERR_YPERR);
	}
	wf = fopen(tmpname, "w");
	if (wf == NULL) {
		exit(YPERR_YPERR);
	}
	err = -1;
	while (fgets(line, sizeof (line), rf)) {
		if (err < 0 && match(line, name)) {
			switch (op) {
			case YPOP_INSERT:
				err = YPERR_KEY;
				break;
			case YPOP_STORE:
			case YPOP_CHANGE:
				fprintf(wf, "%s %s\n", key, data);
				err = 0;
				break;
			case YPOP_DELETE:
				/* do nothing */
				err = 0;
				break;
			}
		} else {
			fputs(line, wf);
		}
	}
	if (err < 0) {
		switch (op) {
		case YPOP_CHANGE:
		case YPOP_DELETE:
			err = YPERR_KEY;
			break;
		case YPOP_INSERT:
		case YPOP_STORE:
			err = 0;
			fprintf(wf, "%s %s\n", key, data);
			break;
		}
	}
	fclose(wf);
	fclose(rf);
	if (err == 0) {
		if (rename(tmpname, fname) < 0) {
			exit(YPERR_YPERR);
		}
	} else {
		if (unlink(tmpname) < 0) {
			exit(YPERR_YPERR);
		}
	}
	if (fork() == 0) {
		close(0); close(1); close(2);
		open("/dev/null", O_RDWR, 0);
		dup(0); dup(0);
		execl("/bin/sh", "sh", "-c", argv[2], NULL);
	}
	return (err);
	/* NOTREACHED */
}


int
match(line, name)
	char *line;
	char *name;
{
	int len;

	len = strlen(name);
	return (strncmp(line, name, len) == 0 &&
		(line[len] == ' ' || line[len] == '\t'));
}
