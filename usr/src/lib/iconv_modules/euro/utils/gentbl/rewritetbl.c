/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

int main(int argc, char ** argv) {
	char *inbuf;
	size_t inbytesleft;
	int fd, i;
	struct stat s;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s input\n", argv[0]);
		exit(-1);
	}
	if ((fd = open(argv[1], O_RDONLY)) == -1) {
		perror("open");
		exit(-2);
	}
	if (fstat(fd, &s) == -1) {
		perror("stat");
		exit(-3);
	}
	inbytesleft = s.st_size;
	inbuf = (char *)malloc(inbytesleft);
	if (read(fd, inbuf, inbytesleft) != inbytesleft) {
		perror("read");
		exit(-4);
	}
	/* Output tbl[] contents. */
	for (i = 0; i < s.st_size; i++)
		i == s.st_size-1 ?
			printf("/* 0x%02X */  {  0x%02X, %d  }\n",  i, \
			    (unsigned char) *(inbuf+i), sizeof (*(inbuf+i))) :
			printf("/* 0x%02X */  {  0x%02X, %d  },\n", i, \
			    (unsigned char) *(inbuf+i), sizeof (*(inbuf+i)));
	free(inbuf);
	close(fd);
}
