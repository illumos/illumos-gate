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
 */
/*
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#include <stdio.h>
#include <locale.h>
#include <libgen.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

FILE *iobuf;
int gotflg;
char ofile[64];
char a1[1024];
char a2[64];
int c;

int	getnm(char);
int	size(char *);

int
main(int argc, char **argv)
{
	char *name, *str, *v;
	char *bp, *cp, *sv;
	char *message;
	int k, cflg = 0;
	int status = 0;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);
	if (argc > 1 && *argv[1] == '-') {
		cflg++;
		++argv;
		argc--;
	} else cflg = 0;
	while (--argc) {
		++argv;
		bp = *argv;
		if ((iobuf = fopen(*argv, "r")) == NULL) {
			message = gettext("can not open ");
			write(2, message, strlen(message));
			write(2, *argv, size(*argv));
			write(2, "\n", 1);
			/* continues to next file, if any, but the */
			/* exit status will indicate an error */
			status = 1;
			continue;
		}
		cp = ofile;
		while (*++bp)
			if (*bp == '/') *bp = '\0';
		while (*--bp == '\0')
			;
		while (*bp != '\0' && bp > *argv) bp--;
		while (*bp == 0)
			bp++;
		while (*cp++ = *bp++)
			;
		cp--; *cp++ = '.';
		if (cflg) *cp++ = 'c';
		else *cp++ = 'i';
		*cp = '\0';
		close(1);
		if (creat(ofile, 0644) < 0) {
			message = gettext("can not create .i file\n");
			write(2, message, strlen(message));
			exit(1);
		}
		gotflg = 0;
		while (1) {
			str = a1;
			name = a2;
			if (!gotflg)
				while (((c = getc(iobuf)) == '\n') ||
				    (c == ' '))
					;
			else
				gotflg = 0;
			if (c == EOF) break;
			*name++ = c;
			while (((*name++ = c = getc(iobuf)) != ' ') &&
			    (c != EOF) && (c != '\n'))
				;
			*--name = '\0';
			while (((c = getc(iobuf)) == ' ') || (c == '\n'))
				;
			if (c != '"') {
				if (c == EOF) {
					message = gettext("unexpected eof\n");
					write(2, message, strlen(message));
					exit(1);
				}
				message = gettext("missing initial quote for ");
				write(2, message, strlen(message));
				write(2, a2, size(a2));
				message =
				    gettext(" : remainder of line ignored\n");
				write(2, message, strlen(message));
				while ((c = getc(iobuf)) != '\n')
					;
				continue;
			}
			keeponl:
			while (gotflg || (c = getc(iobuf)) != EOF) {
				gotflg = 0;
				switch (c) {
				case '"':
					break;
				case '\\':
					switch (c = getc(iobuf)) {
					case 't':
						*str++ = '\011';
						continue;
					case 'n':
						*str++ = '\012';
						continue;
					case 'r':
						*str++ = '\015';
						continue;
					case 'b':
						*str++ = '\010';
						continue;
					case '\\':
						*str++ = '\\';
						continue;
					default:
						if (c <= '7' && c >= '0')
							*str++ = getnm((char)c);
						else *str++ = c;
						continue;
					}
				default:
					*str++ = c;
				}
				if (c == '"') break;
			}
			if (c == EOF) {
				message = gettext("unexpected eof\n");
				write(2, message, strlen(message));
				exit(1);
			}
			while (((c = getc(iobuf)) == '\n') || (c == ' '))
				;
			if (c == '"') goto keeponl;
			else {
				gotflg++;
			}
			*str = '\0';
			if (!(sv = v = regcmp(a1, 0))) {
				message = gettext("fail: ");
				write(2, message, strlen(message));
				write(2, a2, size(a2));
				write(2, "\n", 1);
				continue;
			}
			printf("/* \"%s\" */\n", a1);
			printf("char %s[] = {\n", a2);
			while (__i_size > 0) {
				for (k = 0; k < 12; k++)
					if (__i_size-- > 0)
						printf("0%o, ", *v++);
				printf("\n");
			}
			printf("0};\n");
			free(sv);
		}
		fclose(iobuf);
	}
	return (status);
}

int
size(char *p)
{
	int i;
	char *q;

	i = 0;
	q = p;
	while (*q++) i++;
	return (i);
}

int
getnm(char j)
{
	int i;
	int k;
	i = j - '0';
	k = 1;
	while (++k < 4 && (c = getc(iobuf)) >= '0' && c <= '7')
		i = (i*8+(c-'0'));
	if (k >= 4)
		c = getc(iobuf);
	gotflg++;
	return (i);
}
