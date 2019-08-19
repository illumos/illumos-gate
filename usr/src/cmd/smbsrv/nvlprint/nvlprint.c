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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Print a packed nvlist from a file.
 */

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "libnvpair.h"

char buf[65536];

void
dumpit(FILE *fp)
{
	struct stat st;
	size_t flen;
	int rlen;
	nvlist_t *nvl = NULL;
	int err;

	if (fstat(fileno(fp), &st) < 0) {
		perror("fstat");
		return;
	}
	flen = (size_t)st.st_size;
	if (flen > sizeof (buf)) {
		(void) printf("File too large\n");
		return;
	}
	rlen = fread(buf, 1, flen, fp);
	if (rlen <= 0) {
		perror("fread");
		return;
	}
	if (rlen != flen) {
		(void) printf("Short read %d %d \n", rlen, flen);
		return;
	}

	err = nvlist_unpack(buf, flen, &nvl, 0);
	if (err != 0) {
		(void) printf("nvlist_unpack, err=%d\n", err);
		return;
	}

	nvlist_print(stdout, nvl);
	nvlist_free(nvl);
}

int
main(int argc, char **argv)
{
	FILE *fp;
	int i;

	if (argc < 2) {
		(void) fprintf(stderr, "usage: %s {filename} [filename2...]\n",
		    argv[0]);
		return (1);
	}
	for (i = 1; i < argc; i++) {
		fp = fopen(argv[i], "r");
		if (fp == NULL) {
			perror(argv[i]);
			return (1);
		}
		(void) printf("%s:\n", argv[i]);
		dumpit(fp);
		(void) fclose(fp);
	}
	return (0);
}
