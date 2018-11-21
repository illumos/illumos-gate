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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef DEBUG_C
#define DEBUG_C

#ifdef DEBUG
#include <sys/fcntl.h>
#include <sys/stat.h>
int main(int argc, char ** argv) {
	char *inbuf, *outbuf, *in_tmp, *out_tmp;
	size_t inbytesleft, outbytesleft;
	int fd;
	int i;
	struct stat s;
	struct _icv_state *st;
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
	inbytesleft = outbytesleft = s.st_size;
	in_tmp = inbuf = (char *)malloc(inbytesleft);
	out_tmp = outbuf = (char *)malloc(outbytesleft);
	if (!inbuf || !outbuf) {
		perror("malloc");
		exit(-1);
	}
	if (read(fd, inbuf, inbytesleft) != inbytesleft) {
		perror("read");
		exit(-4);
	}
	st = (struct _icv_state *)_icv_open();
	if (st == (struct _icv_state *) -1) {
		perror("_icv_open");
		exit(-1);
	}
	if (_icv_iconv(st, &inbuf, &inbytesleft, \
			&outbuf, &outbytesleft) == -1) {
		perror("icv_iconv");
		fprintf(stderr, "\ninbytesleft = %d\n", inbytesleft);
		exit(-2);
	}
	/* Output tbl[] contents. */
	for (i=0; i < s.st_size; i++)
		i == s.st_size-1 ?
			printf("/* 0x%02X */  {  0x%02X, %d  }\n", i, (unsigned char) *(out_tmp+i), sizeof(*(out_tmp+i))) :
			printf("/* 0x%02X */  {  0x%02X, %d  },\n", i, (unsigned char) *(out_tmp+i), sizeof(*(out_tmp+i)));
	free(in_tmp);
	free(out_tmp);
	close(fd);
	_icv_close(st);
}
#endif	/* DEBUG */
#endif	/* DEBUG_C */
