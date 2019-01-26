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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <sys/param.h>

#define	ungetchar(c)	ungetc(c, stdin)

#define	NBUCKETS	511

static char	usagestr[] =	"usage: %s [ - ] mesgfile prefix file ...\n";

static FILE	*mesgread, *mesgwrite;

static void process(void);
static int match(char *ocp);
static void copystr(void);
static int octdigit(char c);
static void inithash(void);
static int hashit(char *str, char really, unsigned int fakept);
static int fgetNUL(char *obuf, int rmdr, FILE *file);

int
main(int argc, char *argv[])
{
	char addon = 0;
	char *progname, *np, name[MAXPATHLEN];
	size_t size = 0;
	size_t len;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	argc--, progname = *argv++;
	if (argc > 1 && argv[0][0] == '-')
		addon++, argc--, argv++;
	if (argc < 3)
		(void) fprintf(stderr, gettext(usagestr), progname), exit(1);
	mesgwrite = fopen(argv[0], addon ? "a" : "w");
	if (mesgwrite == NULL)
		perror(argv[0]), exit(1);
	mesgread = fopen(argv[0], "r");
	if (mesgread == NULL)
		perror(argv[0]), exit(1);
	inithash();
	argc--, argv++;

	if (strlcpy(name, argv[0], sizeof (name)) >= sizeof (name)) {
		(void) fprintf(stderr, gettext("%s: %s: string too long"),
			progname, argv[0]);
		exit(1);
	}

	np = name + strlen(name);

	len = strlen(name);
	np = name + len;
	size = sizeof (name) - len;
	argc--, argv++;
	do {
		if (strlcpy(np, argv[0], size) >= size) {
			(void) fprintf(stderr,
				gettext("%s: %s: string too long"),
				progname, argv[0]);
			exit(1);
		}
		if (freopen(name, "w", stdout) == NULL)
			perror(name), exit(1);
		if (freopen(argv[0], "r", stdin) == NULL)
			perror(argv[0]), exit(1);
		process();
		argc--, argv++;
	} while (argc > 0);

	return (0);
}

static void
process(void)
{
	int c;

	for (;;) {
		c = getchar();
		if (c == EOF)
			return;
		if (c != 'e') {
			(void) putchar(c);
			continue;
		}
		if (match("error(")) {
			(void) printf(gettext("error("));
			c = getchar();
			if (c != '"')
				(void) putchar(c);
			else
				copystr();
		}
	}
}

static int
match(char *ocp)
{
	char *cp;
	int c;

	for (cp = ocp + 1; *cp; cp++) {
		c = getchar();
		if (c != *cp) {
			while (ocp < cp)
				(void) putchar(*ocp++);
			(void) ungetchar(c);
			return (0);
		}
	}
	return (1);
}

static void
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
				c <<= 3, c += ch - '0', ch = -1;
				break;
			}
		}
		*cp++ = c;
	}
out:
	*cp = 0;
	(void) printf("%d", hashit(buf, 1, 0));
}

static int
octdigit(char c)
{

	return (c >= '0' && c <= '7');
}

static void
inithash(void)
{
	char buf[512];
	int mesgpt = 0;

	rewind(mesgread);
	while (fgetNUL(buf, sizeof (buf), mesgread) != 0) {
		(void) hashit(buf, 0, mesgpt);
		mesgpt += strlen(buf) + 2;
	}
}

static struct	hash {
	long	hval;
	unsigned int hpt;
	struct	hash *hnext;
} *bucket[NBUCKETS];

static int
hashit(char *str, char really, unsigned int fakept)
{
	int i;
	struct hash *hp;
	char buf[512];
	long hashval = 0;
	char *cp;

	if (really)
		(void) fflush(mesgwrite);
	for (cp = str; *cp; )
		hashval = (hashval << 1) + *cp++;
	i = hashval % NBUCKETS;
	if (i < 0)
		i += NBUCKETS;
	if (really != 0)
		for (hp = bucket[i]; hp != 0; hp = hp->hnext)
		if (hp->hval == hashval) {
			(void) fseek(mesgread, (long)hp->hpt, 0);
			(void) fgetNUL(buf, sizeof (buf), mesgread);
			if (strcmp(buf, str) == 0)
				break;
		}
	if (!really || hp == 0) {
		hp = (struct hash *)calloc(1, sizeof (*hp));
		hp->hnext = bucket[i];
		hp->hval = hashval;
		hp->hpt = really ? ftell(mesgwrite) : fakept;
		if (really) {
			(void) fwrite(str, sizeof (char), strlen(str) + 1,
				mesgwrite);
			(void) fwrite("\n", sizeof (char), 1, mesgwrite);
		}
		bucket[i] = hp;
	}
	return (hp->hpt);
}

static int
fgetNUL(char *obuf, int rmdr, FILE *file)
{
	int c;
	char *buf = obuf;

	while (--rmdr > 0 && (c = getc(file)) != 0 && c != EOF)
		*buf++ = c;
	*buf++ = 0;
	(void) getc(file);
	return ((feof(file) || ferror(file)) ? 0 : 1);
}
