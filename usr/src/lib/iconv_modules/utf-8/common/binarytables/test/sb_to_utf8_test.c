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
 * This program convert Additional Codeset Characters from 0x00 through 0xff
 * to UTF-8 codeset. And also again converting the chacter in UTF-8 to original
 * codeset.
 * For example,
 *               IBM -> UTF-8 -> IBM
 *                (1)     (2)     (3)
 *                            -> Unicode Scaler
 *                                (4)
 *                           output     (1) (2) (4)line by line
 *                           comparing  (1) (3)
 */

#include <stdio.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <iconv.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

static void mk_data(char *,char *);

char *	ME;
int	status;
static int	flag_check = 0; /* check with data file */

static struct  {
	unsigned int	from;
	unsigned int	u4;
} tbl[0x10000];


void
usage(int status)
{
	fprintf(stderr, "Usage: %s from-code\n", ME);
	exit(status);
}

void
validate(int i, iconv_t cd, iconv_t cd2, iconv_t cd3)
{
	uchar_t		source_buf[1024];
	uchar_t		result_buf[1024];
	uchar_t		tmp_buf[1024];
	const uchar_t *	source;
	uchar_t *		result;
	uchar_t *		tmp;
	size_t		source_len;
	size_t		result_len;
	size_t		result_len2;
	size_t		tmp_len;
	size_t		s;
	int		j;
	ulong_t   	l;

#ifdef _LITTLE_ENDIAN
#define CHECKWITHFILE \
	if( flag_check > 0 ) { \
		l = 0U; \
		for( j =  sizeof (tmp_buf) - tmp_len -1; \
		     j >= ((i == 0) ? 2: 0); j--) \
			l = (l << 8) + ((uint_t)tmp_buf[j]); \
		if (l != tbl[i].u4 ) fprintf(stderr, "%x != %x \n", l, tbl[i].u4 ); \
	}
#else
#define CHECKWITHFILE \
	if( flag_check > 0 ) { \
		l = 0U; \
		j = ((i == 0) ? 2: 0); \
		for(; j < sizeof (tmp_buf) - tmp_len ; j++) \
			l = (l << 8) + ((uint_t)tmp_buf[j]); \
		if (l != tbl[i].u4 ) fprintf(stderr, "%x != %x \n", l, tbl[i].u4 ); \
	}
#endif

#define PRINTUNICODE \
	tmp = tmp_buf; \
	tmp_len = sizeof (tmp_buf); \
	result = result_buf; \
	result_len2 = sizeof (result_buf) - result_len; \
	s = iconv(cd2, (const char**)&result, &result_len2, (char**)&tmp, &tmp_len); \
	if (s != 0) { \
		printf(" \n stoped \n"); \
		fprintf(stderr, "fail to con_LITTLE_ENDIANvert UTF-8 to Unicode\n"); \
		exit (status); \
	} \
	printf("\t"); \
	for( j = 0; j < sizeof (tmp_buf) - tmp_len ; j++) \
		printf("%02x", (uchar_t)tmp_buf[j]); \
	CHECKWITHFILE

#define COMPARE \
	tmp = tmp_buf; \
	tmp_len = sizeof (tmp_buf); \
	result = result_buf; \
	result_len2 = sizeof (result_buf) - result_len; \
	s = iconv(cd3, (const char**)&result, &result_len2, (char**)&tmp, &tmp_len); \
	if (s != 0) { \
		printf(" \n WARNING \n"); \
		fprintf(stderr, "fail to convert UTF-8 to Orignal Codeset(%x)\n",\
		i); \
		fprintf(stderr, "errno=%d %d %d\n", \
			errno, \
			sizeof (result_buf) - result_len - result_len2, \
			result - result_buf); \
		exit (status); \
	} \
	printf("\t"); \
	if ((sizeof (tmp_buf) - tmp_len != 1) || \
	    ((uchar_t)tmp_buf[0] != (uchar_t)i )) { \
		printf("\t-> 0x%2x \n warning \n", (uchar_t)tmp_buf[0] ); \
		fprintf(stderr, " Converting answer is not the same (0x%02x) for  (0x%02x)\n", \
		(uchar_t)tmp_buf[0], i); \
	}

#define DATASIZE 1

	source_buf[0] = i;
	source = source_buf;
	source_len = DATASIZE;

	result = result_buf;
	result_len = sizeof (result_buf);

	s = iconv(cd, (const char**)&source, &source_len, (char**)&result, &result_len);

	status = 1;
	if (((size_t)(0)) == s) {
		if ((source_len != 0) ||
		    ((source - source_buf) != DATASIZE)) {
			fprintf(stderr, ": %d %d %d\n",
				errno,
				source_len,
				source - source_buf);
			exit(status);
		}
		printf("0x%02x\t0x", i);
		for( j = 0; j < sizeof (result_buf) - result_len ; j++)
			printf("%02x", (uchar_t)result_buf[j]);
		PRINTUNICODE
		COMPARE
		printf("\n");
		return;
	}

	status += 1;
	if (((size_t)(-1)) == s) {
		if (errno == EILSEQ) {
			printf("0x%02x	EILSEQ\n", i);
			return;
		}
		fprintf(stderr, "Error for source 0x%02x(%d): %d %d %d %d %d\n",
			i, i,
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
	int		i, j, k;
	char		*dir;

	ME = basename(argv[0]);
	setlocale(LC_ALL, "");
	status = 100;

	for (j = 1;  j < argc; j++) {
		if (argv[j][0] != '-')
			break;
		for (k = 1; ; k++) {
			if (argv[j][k] == '\0')
				break;
			if (argv[j][k] == 'c') {
				flag_check = 1;
				j++;
				if (j >= argc) usage(-1);
				dir = argv[j];
				continue;
			}
		}
	}
	if (j >= argc) usage(-1);


	if( flag_check > 0 ) mk_data(dir, argv[j]);

	cd = iconv_open("UTF-8", argv[j]);
	if (((iconv_t)(-1)) == cd) {
		perror("iconv_open");
		exit(status);
	}

	cd2 = iconv_open("UCS-2", "UTF-8");
	if (((iconv_t)(-1)) == cd2) {
		perror("iconv_open for UTF-8");
		exit(status);
	}

	cd3 = iconv_open(argv[j], "UTF-8");
	if (((iconv_t)(-1)) == cd3) {
		perror("iconv_open for reverse");
		exit(status);
	}

	/*
	 *	main logic
	 */
	for (i = 0; i <= 0xff; i++)
		validate(i, cd, cd2, cd3);

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

	return (0);
}

static void
mk_data(char *dir, char* name)
{
	register int	i, j;
	char		buf[BUFSIZ], num[100];
	unsigned int	l, k;
	FILE		*fd;
	char		file[BUFSIZ];

	sprintf( file, "%s/%s.txt", dir, name);
	if ((fd = fopen(file, "r")) == NULL) {
		perror("fopen");
		exit (-1);
	}
	/* for information file, pari data is created */
	while (fgets(buf, BUFSIZ, fd)) {
		i = 0;
		while (buf[i] && isspace(buf[i]))
			i++;
		if (buf[i] == '#' || buf[i] == '\0')
			continue;

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		k = strtol(num, (char **)NULL, 16);

		while (isspace(buf[i]))
			i++;

		if (buf[i] == '#' || buf[i] == '\0')
			/* undefined */
			continue;

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		l = strtol(num, (char **)NULL, 16);

		tbl[k].u4 = l;
		tbl[k].from = k;
	}
}
