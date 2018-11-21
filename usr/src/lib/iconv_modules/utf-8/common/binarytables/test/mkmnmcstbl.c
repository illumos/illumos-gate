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



#include <libgen.h>
#include <stdio.h>
#include <ctype.h>

char *	ME;
static struct u4_nm {
		signed int	u4;
		unsigned char  	nm[256];
} u4_nm[0x10000];


static struct to_utf8_table_component2 {
		unsigned int	from;
		unsigned int	u4;
		unsigned int	u8;
		signed char	size;
} tbl[0x10000];

#define INDEX_FOR_BETWEEN_MAX 1000


void
usage(int status)
{
	fprintf(stderr, "Usage: %s <mnemonic.txt> < <codeset.txt>\n", ME);
	exit(status);
}


static void mk_u4nm (char *file);
main(int ac, char **av)
{
	register int	i, j;
	char		buf[BUFSIZ], num[100];
	unsigned int	l, k, index_for_between;
	int		mapflag[2];
	int		between[INDEX_FOR_BETWEEN_MAX];

	ME = basename(av[0]);
	if (ac <= 1) usage(-1);
	mk_u4nm(av[1]);

	/* if no data, no mapping pair will be created */
	for (i = 0; i < 0x10000; i++) {
		tbl[i].size = 0;
	}


	/* for information file, pari data is created */
	while (fgets(buf, BUFSIZ, stdin)) {
		i = 0;
		while (buf[i] && isspace(buf[i]))
			i++;
		if (buf[i] == '#' || buf[i] == '\0')
			continue;

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		k = strtol(num, (char **)NULL, 0);

		while (isspace(buf[i]))
			i++;

		if (buf[i] == '#' || buf[i] == '\0')
			/* undefined */
			continue;

		for (j = 0; !isspace(buf[i]); i++, j++)
			num[j] = buf[i];
		num[j] = '\0';

		l = strtol(num, (char **)NULL, 0);

		if (tbl[k].size != 0) {
			/* overwrite */
			fprintf(stderr, "duplicated mapping for 0x%x\n", k );
		}
		tbl[k].u4 = l;
		tbl[k].from = k;

		if (l < 0x80)
			tbl[k].size = 1;
		else if (l < 0x800)
			tbl[k].size = 2;
		else if (l < 0x10000)
			tbl[k].size = 3;
		else if (l < 0x200000)
			tbl[k].size = 4;
		else if (l < 0x4000000)
			tbl[k].size = 5;
		else
			tbl[k].size = 6;
	}
	for (i = 0; i < 0x100; i++) {
		if (tbl[i].size > 0 ) {
			if (u4_nm[tbl[i].u4].u4 >= 0){
				printf("0x%0x\t%s\n", i, u4_nm[tbl[i].u4].nm);
			} else {
				printf("0x%0x\t ????????\n", i, u4_nm[tbl[i].u4].nm);
			}
		} else {
			printf("0x%0x\t??\n", i);
		}
	}
	return (0);
}

static void mk_u4nm (char *file)
{
	register int	i, j;
	char		buf[BUFSIZ], num[100];
	unsigned int	l, k, index_for_between;
	int		mapflag[2];
	int		between[INDEX_FOR_BETWEEN_MAX];
	int	       	somedatalost = 0;
	FILE		*fd;


	for(i = 0; i < 0x1000; i++ ) {
		u4_nm[k].u4 = -1;
	}

	if ((fd = fopen(file, "r")) == NULL) {
		perror("fopen");
		exit (-1);
	}
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

		u4_nm[k].u4 = k;
		for (j = 0; !isspace(buf[i]); i++, j++)
			u4_nm[k].nm[j] = buf[i];
		u4_nm[k].nm[j] = '\0';
		/*	printf("%d(%d): %s\n", k, j, &u4_nm[k].nm[0] ); */
	}
}
