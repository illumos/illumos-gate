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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mkstr - create a string error message file by massaging C source
 *
 * Bill Joy UCB August 1977
 *
 * Modified March 1978 to hash old messages to be able to recompile
 * without addding messages to the message file (usually)
 *
 * Based on an earlier program conceived by Bill Joy and Chuck Haley
 *
 * Program to create a string error message file
 * from a group of C programs.  Arguments are the name
 * of the file where the strings are to be placed, the
 * prefix of the new files where the processed source text
 * is to be placed, and the files to be processed.
 *
 * The program looks for 'error("' in the source stream.
 * Whenever it finds this, the following characters from the '"'
 * to a '"' are replaced by 'seekpt' where seekpt is a
 * pointer into the error message file.
 * If the '(' is not immediately followed by a '"' no change occurs.
 *
 * The optional '-' causes strings to be added at the end of the
 * existing error message file for recompilation of single routines.
 */

#include <stdio.h>
#include <locale.h>

#define	ungetchar(c)	ungetc(c, stdin)

long	ftell();
char	*calloc();

FILE	*mesgread, *mesgwrite;
char	*progname;
char	usagestr[] =	"usage: %s [ - ] mesgfile prefix file ...\n";
char	name[100], *np;

int hashit(char *str, char really, unsigned int fakept);
void process(void);
void inithash(void);
int octdigit(char c);
void copystr(void);

int
main(int argc, char *argv[])
{
	char addon = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	argc--, progname = *argv++;
	if (argc > 1 && argv[0][0] == '-')
		addon++, argc--, argv++;
	if (argc < 3)
		fprintf(stderr, gettext(usagestr), progname), exit(1);
	mesgwrite = fopen(argv[0], addon ? "a" : "w");
	if (mesgwrite == NULL)
		perror(argv[0]), exit(1);
	mesgread = fopen(argv[0], "r");
	if (mesgread == NULL)
		perror(argv[0]), exit(1);
	inithash();
	argc--, argv++;
	strcpy(name, argv[0]);
	np = name + strlen(name);
	argc--, argv++;
	do {
		strcpy(np, argv[0]);
		if (freopen(name, "w", stdout) == NULL)
			perror(name), exit(1);
		if (freopen(argv[0], "r", stdin) == NULL)
			perror(argv[0]), exit(1);
		process();
		argc--, argv++;
	} while (argc > 0);
	return (0);
}

void
process(void)
{
	char *cp;
	int c;

	for (;;) {
		c = getchar();
		if (c == EOF)
			return;
		if (c != 'e') {
			putchar(c);
			continue;
		}
		if (match("error(")) {
			printf(gettext("error("));
			c = getchar();
			if (c != '"')
				putchar(c);
			else
				copystr();
		}
	}
}

int
match(char *ocp)
{
	char *cp;
	int c;

	for (cp = ocp + 1; *cp; cp++) {
		c = getchar();
		if (c != *cp) {
			while (ocp < cp)
				putchar(*ocp++);
			ungetchar(c);
			return (0);
		}
	}
	return (1);
}

void
copystr(void)
{
	int c, ch;
	char buf[512];
	char *cp = buf;

	for (;;) {
		c = getchar();
		if (c == EOF)
			break;
		switch (c) {

		case '"':
			*cp++ = 0;
			goto out;
		case '\\':
			c = getchar();
			switch (c) {

			case 'b':
				c = '\b';
				break;
			case 't':
				c = '\t';
				break;
			case 'r':
				c = '\r';
				break;
			case 'n':
				c = '\n';
				break;
			case '\n':
				continue;
			case 'f':
				c = '\f';
				break;
			case '0':
				c = 0;
				break;
			case '\\':
				break;
			default:
				if (!octdigit(c))
					break;
				c -= '0';
				ch = getchar();
				if (!octdigit(ch))
					break;
				c <<= 7, c += ch - '0';
				ch = getchar();
				if (!octdigit(ch))
					break;
				c <<= 3, c+= ch - '0', ch = -1;
				break;
			}
		}
		*cp++ = c;
	}
out:
	*cp = 0;
	printf("%d", hashit(buf, 1, NULL));
}

int
octdigit(char c)
{

	return (c >= '0' && c <= '7');
}

void
inithash(void)
{
	char buf[512];
	int mesgpt = 0;

	rewind(mesgread);
	while (fgetNUL(buf, sizeof buf, mesgread) != NULL) {
		hashit(buf, 0, mesgpt);
		mesgpt += strlen(buf) + 2;
	}
}

#define	NBUCKETS	511

struct	hash {
	long	hval;
	unsigned int hpt;
	struct	hash *hnext;
} *bucket[NBUCKETS];

int
hashit(char *str, char really, unsigned int fakept)
{
	int i;
	struct hash *hp;
	char buf[512];
	long hashval = 0;
	char *cp;

	if (really)
		fflush(mesgwrite);
	for (cp = str; *cp;)
		hashval = (hashval << 1) + *cp++;
	i = hashval % NBUCKETS;
	if (i < 0)
		i += NBUCKETS;
	if (really != 0)
		for (hp = bucket[i]; hp != 0; hp = hp->hnext)
		if (hp->hval == hashval) {
			fseek(mesgread, (long) hp->hpt, 0);
			fgetNUL(buf, sizeof buf, mesgread);
/*
			fprintf(stderr, gettext("Got (from %d) %s\n"), hp->hpt, buf);
*/
			if (strcmp(buf, str) == 0)
				break;
		}
	if (!really || hp == 0) {
		hp = (struct hash *) calloc(1, sizeof *hp);
		hp->hnext = bucket[i];
		hp->hval = hashval;
		hp->hpt = really ? ftell(mesgwrite) : fakept;
		if (really) {
			fwrite(str, sizeof (char), strlen(str) + 1, mesgwrite);
			fwrite("\n", sizeof (char), 1, mesgwrite);
		}
		bucket[i] = hp;
	}
/*
	fprintf(stderr, gettext("%s hashed to %ld at %d\n"), str, hp->hval, hp->hpt);
*/
	return (hp->hpt);
}

#include <sys/types.h>
#include <sys/stat.h>

int
fgetNUL(char *obuf, int rmdr, FILE *file)
{
	int c;
	char *buf = obuf;

	while (--rmdr > 0 && (c = getc(file)) != 0 && c != EOF)
		*buf++ = c;
	*buf++ = 0;
	getc(file);
	return ((feof(file) || ferror(file)) ? NULL : 1);
}
