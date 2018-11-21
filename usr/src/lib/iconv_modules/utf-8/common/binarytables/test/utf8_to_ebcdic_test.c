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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */


/*
 * For example,
 *               UCS -> UTF-8 -> IBM -> UTF-8
 *                (1)     (2)     (3)	 (4)
 *               tmp    source   result  tmp
 *                           output     (1) (2) (3)line by line
 *                           comparing  (2) (4)
 */

#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <iconv.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

char *	ME;
int	status;
int	flag_display = 1;
int	flag_bubun = 1;


void
usage(int status)
{
	fprintf(stderr, "Usage: %s [-b] [-d] to-code\n", ME);
	exit(status);
}


void
chkprint(char *format, ...)
{
	va_list		ap;
	va_start(ap, format);

	if (0 != flag_display)  {
		(void) vfprintf(stdout, format, ap);
	}
	va_end(ap);
}


void
validate(uint_t i, iconv_t cd, iconv_t cd2, iconv_t cd3)
{
	char		source_buf[1024];
	char		result_buf[1024];
	char		tmp_buf[1024];
	char *		source;
	char *		result;
	char *		tmp;
	size_t		source_len;
	size_t		result_len;
	size_t		result_len2;
	size_t		tmp_len;
	size_t		s;
	int		j;
	ushort_t	*shortp;
	uint_t	*intp;


#define PREPARE_ILLEGALUTF8 \
	if (i == 0xfffe) { \
		source_buf[0] = 0xef; \
		source_buf[1] = 0xbf; \
		source_buf[2] = 0xbe; \
		source_buf[3] = 0x00; \
		source = source_buf;  \
		source_len = 3; \
		chkprint("U+%04x\t** %x **", i, 0xefbfbe); \
	} else if (i == 0xffff) { \
		source_buf[0] = 0xef; \
		source_buf[1] = 0xbf; \
		source_buf[2] = 0xbf; \
		source_buf[3] = 0x00; \
		source = source_buf;  \
		source_len = 3; \
		chkprint("U+%04x\t** %x **", i, 0xefbfbf); \
	} else if (i > 0x7fffffff) { \
		source_buf[0] = 0x0; \
		source_buf[1] = 0x0; \
		source_buf[2] = 0x0; \
		source_buf[3] = 0x0; \
		source_buf[4] = 0x0; \
		source_buf[5] = 0xfe; \
		source_buf[6] = 0x0; \
		source = source_buf;  \
		source_len = 7; \
		chkprint("U+%04x\t** %x **", i, 0xfe); \
	}

#define DATASIZE 4
	/*
	shortp = (ushort_t*)&tmp_buf[0];
	*shortp = 0xfeff;
	shortp = (ushort_t*)&tmp_buf[2];
	*shortp = i;
	*/
	/* chkprint("U+");  */ \
	/*	for( j = 0; j < tmp_len ; j++)  */ \
	/* 	chkprint("%02x", (uchar_t)tmp[j]); */ \
	/*
	shortp = (ushort_t*)&tmp_buf[0]; \
	*shortp = i; \
	*/

#define PREPAREUTF8 \
	tmp = tmp_buf; \
	tmp_len = DATASIZE; \
	intp = (uint_t*)&tmp_buf[0]; \
	*intp = i; \
	source = source_buf; \
	source_len = sizeof (source_buf); \
	\
	chkprint("U+%04x", i); \
	s = iconv(cd2, (const char**)&tmp, &tmp_len, &source, &source_len); \
	if (s != 0) { \
		chkprint(" \n stopped \n"); \
		fprintf(stderr, "fail to convert Unicode to UTF-8\n"); \
		exit (status); \
	} \
	chkprint("\t0x"); \
	for( j = 0; j < sizeof (source_buf) - source_len; j++) \
		chkprint("%02x", (uchar_t)source_buf[j]); \
	source_len = sizeof (source_buf) - source_len; \
	source = &source_buf[0];

#define	COMPARE_ERROR \
	chkprint("\t-> 0x");\
	for (j = 0; j <  sizeof (tmp_buf) - tmp_len; j++) { \
		chkprint("%02x", (uchar_t)tmp_buf[j]);\
	} \
	chkprint("\n warning \n"); \
	fprintf(stderr, " Converting answer is not the same for  (U+%04x)\n", \
		i);

#define COMPARE \
	tmp = tmp_buf; \
	tmp_len = sizeof (tmp_buf); \
	result = result_buf; \
	result_len2 = sizeof (result_buf) - result_len; \
	s = iconv(cd3, (const char**)&result, &result_len2, &tmp, &tmp_len); \
	if (s != 0) { \
		chkprint(" \n WARNING \n"); \
		fprintf(stderr, "fail to convert Orignal Codeset to UTF-8\n",\
		i); \
		fprintf(stderr, "errno=%d %d %d\n", \
			errno, \
			sizeof (result_buf) - result_len - result_len2, \
			result - result_buf); \
		exit (status); \
	} \
	chkprint("\t"); \
	if (sizeof (tmp_buf) - tmp_len != source_len) { \
		COMPARE_ERROR \
	} else { \
		for (j = 0; j < source_len; j++) { \
			if ((uchar_t)tmp_buf[j] != (uchar_t)source_buf[j]) { \
				COMPARE_ERROR \
			} \
		}\
	}


	/*
	 *	LOGIC START
	 */

	if (i == 0xfffe || i == 0xffff || i > 0x7fffffff) {
		PREPARE_ILLEGALUTF8
	} else {
		PREPAREUTF8
	}

	result = result_buf;
	result_len = sizeof (result_buf);
	tmp_len = source_len; /* save to compare source data */
	s = iconv(cd,  (const char**)&source, &source_len, &result,
		&result_len);

	status = 1;
	if (i == 0xfffe || i == 0xffff || i > 0x7fffffff) {
		if ((((size_t)0) == s) ||
			(errno != EILSEQ)) {
			fprintf(stderr, "EILSEQ expected for 0x%x: %d %d %d\n",
			i,
			errno,
		        source_len,
			source - source_buf);
		}
	}
	if (((size_t)(0)) == s) {
		if ((source_len != 0) ||
			((source - source_buf) != tmp_len) ||
			((result - result_buf + result_len) !=
			sizeof (result_buf))) {
			fprintf(stderr, ": %d %d %d\n",
				errno,
				source_len,
				source - source_buf);
			exit(status);
		}
		chkprint("\t0x");
		for( j = 0; j < sizeof (result_buf) - result_len ; j++)
			chkprint("%02x", (uchar_t)result_buf[j]);
		source_len = tmp_len;
		COMPARE
		chkprint("\n");
		return;
	}

	status += 1;
	if (((size_t)(-1)) == s) {
		if (errno == EILSEQ) {
			if (((source - source_buf) !=
				(tmp_len - source_len)) ||
				((result - result_buf + result_len) !=
				sizeof (result_buf))) {
				fprintf(stderr, ": %d %d %d\n",
					errno,
					source_len,
					source - source_buf);
				exit(status);
			}
			chkprint("\tEILSEQ\n", i);
			return;
		}
		fprintf(stderr, "Error for source U+%04x: %d %d %d %d %d\n",
			i,
			errno,
			(DATASIZE) - source_len, /* not converted size */
			source - source_buf,
			(sizeof (result_buf)) - result_len,
			result - result_buf);
		exit(status);
	}

	status += 1;
	exit(status);
}

main(int argc, char ** argv)
{
	int		r;
	char *		p;
	iconv_t		cd;
	iconv_t		cd2;
	iconv_t		cd3;
	uint_t		i, j, k;

	ME = basename(argv[0]);
	setlocale(LC_ALL, "");
	status = 100;


	for (j = 1;  j < argc; j++) {
		if (argv[j][0] != '-')
			break;
		for (k = 1; ; k++) {
			if (argv[j][k] == '\0')
				break;
			if (argv[j][k] == 'b') {
				flag_bubun = 0;
				continue;
			}
			if (argv[j][k] == 'd') {
				flag_display = 0;
				continue;
			}
		}
	}
	if (j >= argc) usage(-1);

	chkprint( "#UCS-4\tUTF-8\t* %s *\n", argv[j]);

	cd = iconv_open( argv[j], "UTF-8"); /* to, from */
	if (((iconv_t)(-1)) == cd) {
		perror("iconv_open");
		exit(status);
	}

	cd2 = iconv_open("UTF-8", "UCS-4");
	if (((iconv_t)(-1)) == cd2) {
		perror("iconv_open for UTF-8");
		exit(status);
	}

	cd3 = iconv_open("UTF-8", argv[j]);
	if (((iconv_t)(-1)) == cd3) {
		perror("iconv_open for reverse");
		exit(status);
	}


	/*
	 *	main logic
	 */
	if (flag_bubun) {
		for (i = 0; i <= 0xff; i++)
			validate(i, cd, cd2, cd3);
		validate(0x100, cd, cd2, cd3);
		validate(0x3ff, cd, cd2, cd3);
		validate(0x400, cd, cd2, cd3);
		validate(0xfff, cd, cd2, cd3);
		validate(0x1000, cd, cd2, cd3);
		validate(0x3fff, cd, cd2, cd3);
		validate(0x4000, cd, cd2, cd3);
		validate(0xfffd, cd, cd2, cd3);
		validate(0xfffe, cd, cd2, cd3);    /* error */
		validate(0xffff, cd, cd2, cd3);    /* error */
		validate(0x10000, cd, cd2, cd3);
		validate(0x3ffff, cd, cd2, cd3);
		validate(0x40000, cd, cd2, cd3);
		validate(0xfffff, cd, cd2, cd3);
		validate(0x100000, cd, cd2, cd3);
		validate(0x1fffff, cd, cd2, cd3);
		validate(0x200000, cd, cd2, cd3);
		validate(0x3fffff, cd, cd2, cd3);
		validate(0x400000, cd, cd2, cd3);
		validate(0xffffff, cd, cd2, cd3);
		validate(0x1000000, cd, cd2, cd3);
		validate(0x3ffffff, cd, cd2, cd3);
		validate(0x4000000, cd, cd2, cd3);
		validate(0xfffffff, cd, cd2, cd3);
		validate(0x10000000, cd, cd2, cd3);
		validate(0x7fffffff, cd, cd2, cd3);
		validate(0x80000000, cd, cd2, cd3); /* error */
	} else {
		int	k;
		for (i = 0, k = 0; i <= 0x80000000; i++, k++) {
			validate(i, cd, cd2, cd3);
			if ((k == 0x1000000) &&
				(0 == flag_display)) {
				printf(" i < 0x%x: checked\n", i);
				k = 0;
			}

		}
	}

	status = 200;
	r = iconv_close(cd);
	if (-1 == r) {
		perror("iconv_close");
		exit(status);
	}

	r = iconv_close(cd2);
	if (-1 == r) {
		perror("iconv_close for UTF-8");
		exit(status);
	}

	r = iconv_close(cd3);
	if (-1 == r) {
		perror("iconv_close for reverse");
		exit(status);
	}

	return (0);
}
