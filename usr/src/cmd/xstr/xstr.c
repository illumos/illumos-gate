/*
 * Copyright 1989 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * xstr - extract and hash strings in a C program
 *
 * Bill Joy UCB
 * November, 1978
 */

off_t	tellpt;
off_t	hashit(char *, int);
void	onintr(void);
char	*savestr(char *);
off_t	yankstr(char **);
void	cleanup(void);
void	process(char *);
int	octdigit(char);
void	inithash(void);
void	flushsh(void);
void	found(int, off_t, char *);
void	prstr(char *);
void	xsdotc(void);
int	fgetNUL(char *, int, FILE *);
int	xgetc(FILE *);
int	lastchr(char *);
int	istail(char *, char *);

off_t	mesgpt;
char	*strings =	"strings";

int	cflg;
int	vflg;
char	*xname = "xstr";
int	readstd;
int	tmpfd;

int
main(int argc, char **argv)
{
	argc--, argv++;
	while (argc > 0 && argv[0][0] == '-') {
		char *cp = &(*argv++)[1];

		argc--;
		if (*cp == 0) {
			readstd++;
			continue;
		}
		do switch (*cp++) {

		case 'c':
			cflg++;
			continue;

		case 'l':
			xname = *argv++;
			argc--;
			continue;

		case 'v':
			vflg++;
			continue;

		default:
			(void) fprintf(stderr,
		"usage: xstr [ -v ] [ -c ] [ -l label ] [ - ] [ name ... ]\n");
		} while (*cp);
	}
	if (signal(SIGINT, SIG_IGN) == SIG_DFL)
		(void) signal(SIGINT, (void (*)(int))onintr);
	if (cflg || argc == 0 && !readstd)
		inithash();
	else {
		strings = savestr("/tmp/xstrXXXXXX");
		tmpfd = mkstemp(strings);
		if (tmpfd == -1) {
			perror(strings);
			(void) free(strings);
			exit(9);
		}
		(void) close(tmpfd);
	}
	while (readstd || argc > 0) {
		if (freopen("x.c", "w", stdout) == NULL)
			perror("x.c"), (void) cleanup(), exit(1);
		if (!readstd && freopen(argv[0], "r", stdin) == NULL)
			perror(argv[0]), (void) cleanup(), exit(2);
		process("x.c");
		if (readstd == 0)
			argc--, argv++;
		else
			readstd = 0;
	}
	flushsh();
	if (cflg == 0)
		xsdotc();
	(void) cleanup();
	return (0);
}

char linebuf[BUFSIZ];

void
process(char *name)
{
	char *cp;
	int c;
	int incomm = 0;
	int ret;

	(void) printf("extern char\t%s[];\n", xname);
	for (;;) {
		if (fgets(linebuf, sizeof (linebuf), stdin) == NULL) {
			if (ferror(stdin)) {
				perror(name);
				(void) cleanup();
				exit(3);
			}
			break;
		}
		if (linebuf[0] == '#') {
			if (linebuf[1] == ' ' && isdigit(linebuf[2]))
				(void) printf("#line%s", &linebuf[1]);
			else
				(void) printf("%s", linebuf);
			continue;
		}
		for (cp = linebuf; (c = *cp++) != 0; ) {
			switch (c) {
				case '"':
					if (incomm)
						goto def;
					if ((ret = (int)yankstr(&cp)) == -1)
						goto out;
					(void) printf("(&%s[%d])", xname, ret);
					break;

				case '\'':
					if (incomm)
						goto def;
					(void) putchar(c);
					if (*cp)
						(void) putchar(*cp++);
					break;

				case '/':
					if (incomm || *cp != '*')
						goto def;
					incomm = 1;
					cp++;
					(void) printf("/*");
					continue;

				case '*':
					if (incomm && *cp == '/') {
						incomm = 0;
						cp++;
						(void) printf("*/");
						continue;
					}
					goto def;
def:
				default:
					(void) putchar(c);
					break;
			}
		}
	}
out:
	if (ferror(stdout))
		perror("x.c"), onintr();
}

off_t
yankstr(char **cpp)
{
	char *cp = *cpp;
	int c, ch;
	char dbuf[BUFSIZ];
	char *dp = dbuf;
	char *tp;

	while ((c = *cp++) != 0) {
		switch (c) {

		case '"':
			cp++;
			goto out;

		case '\\':
			c = *cp++;
			if (c == 0)
				break;
			if (c == '\n') {
				if (fgets(linebuf, sizeof (linebuf), stdin)
				    == NULL) {
					if (ferror(stdin)) {
						perror("x.c");
						(void) cleanup();
						exit(3);
					}
					return (-1);

				}
				cp = linebuf;
				continue;
			}
			for (tp = "b\bt\tr\rn\nf\f\\\\\"\""; (ch = *tp++) != 0;
			    tp++)
				if (c == ch) {
					c = *tp;
					goto gotc;
				}
			if (!octdigit(c)) {
				*dp++ = '\\';
				break;
			}
			c -= '0';
			if (!octdigit(*cp))
				break;
			c <<= 3, c += *cp++ - '0';
			if (!octdigit(*cp))
				break;
			c <<= 3, c += *cp++ - '0';
			break;
		}
gotc:
		*dp++ = c;
	}
out:
	*cpp = --cp;
	*dp = 0;
	return (hashit(dbuf, 1));
}

int
octdigit(char c)
{

	return (isdigit(c) && c != '8' && c != '9');
}

void
inithash(void)
{
	char buf[BUFSIZ];
	FILE *mesgread = fopen(strings, "r");

	if (mesgread == NULL)
		return;
	for (;;) {
		mesgpt = tellpt;
		if (fgetNUL(buf, sizeof (buf), mesgread) == 0)
			break;
		(void) hashit(buf, 0);
	}
	(void) fclose(mesgread);
}

int
fgetNUL(char *obuf, int rmdr, FILE *file)
{
	int c;
	char *buf = obuf;

	while (--rmdr > 0 && (c = xgetc(file)) != 0 && c != EOF)
		*buf++ = c;
	*buf++ = 0;
	return ((feof(file) || ferror(file)) ? 0 : 1);
}

int
xgetc(FILE *file)
{

	tellpt++;
	return (getc(file));
}

#define	BUCKETS	128

struct	hash {
	off_t	hpt;
	char	*hstr;
	struct	hash *hnext;
	short	hnew;
} bucket[BUCKETS];

off_t
hashit(char *str, int new)
{
	int i;
	struct hash *hp, *hp0;

	hp = hp0 = &bucket[lastchr(str) & 0177];
	while (hp->hnext) {
		hp = hp->hnext;
		i = istail(str, hp->hstr);
		if (i >= 0)
			return (hp->hpt + i);
	}
	if ((hp = calloc(1, sizeof (*hp))) == NULL) {
		perror("xstr");
		(void) cleanup();
		exit(8);
	}
	hp->hpt = mesgpt;
	hp->hstr = savestr(str);
	mesgpt += strlen(hp->hstr) + 1;
	hp->hnext = hp0->hnext;
	hp->hnew = new;
	hp0->hnext = hp;
	return (hp->hpt);
}

void
flushsh(void)
{
	int i;
	struct hash *hp;
	FILE *mesgwrit;
	int old = 0, new = 0;

	for (i = 0; i < BUCKETS; i++)
		for (hp = bucket[i].hnext; hp != NULL; hp = hp->hnext)
			if (hp->hnew)
				new++;
			else
				old++;
	if (new == 0 && old != 0)
		return;
	mesgwrit = fopen(strings, old ? "r+" : "w");
	if (mesgwrit == NULL)
		perror(strings), (void) cleanup(), exit(4);
	for (i = 0; i < BUCKETS; i++)
		for (hp = bucket[i].hnext; hp != NULL; hp = hp->hnext) {
			found(hp->hnew, hp->hpt, hp->hstr);
			if (hp->hnew) {
				(void) fseek(mesgwrit, hp->hpt, 0);
				(void) fwrite(hp->hstr,
				    strlen(hp->hstr) + 1, 1, mesgwrit);
				if (ferror(mesgwrit)) {
					perror(strings);
					(void) cleanup();
					exit(4);
				}
			}
		}
	if (fclose(mesgwrit) == EOF)
		perror(strings), (void) cleanup(), exit(4);
}

void
found(int new, off_t off, char *str)
{
	if (vflg == 0)
		return;
	if (!new)
		(void) fprintf(stderr, "found at %d:", (int)off);
	else
		(void) fprintf(stderr, "new at %d:", (int)off);
	prstr(str);
	(void) fprintf(stderr, "\n");
}

void
prstr(char *cp)
{
	int c;

	while ((c = (*cp++ & 0377)) != 0)
		if (c < ' ')
			(void) fprintf(stderr, "^%c", c + '`');
		else if (c == 0177)
			(void) fprintf(stderr, "^?");
		else if (c > 0200)
			(void) fprintf(stderr, "\\%03o", c);
		else
			(void) fprintf(stderr, "%c", c);
}

void
xsdotc(void)
{
	FILE *strf = fopen(strings, "r");
	FILE *xdotcf;

	if (strf == NULL)
		perror(strings), exit(5);
	xdotcf = fopen("xs.c", "w");
	if (xdotcf == NULL)
		perror("xs.c"), exit(6);
	(void) fprintf(xdotcf, "char\t%s[] = {\n", xname);
	for (;;) {
		int i, c;

		for (i = 0; i < 8; i++) {
			c = getc(strf);
			if (ferror(strf)) {
				perror(strings);
				onintr();
			}
			if (feof(strf)) {
				(void) fprintf(xdotcf, "\n");
				goto out;
			}
			(void) fprintf(xdotcf, "0x%02x,", c);
		}
		(void) fprintf(xdotcf, "\n");
	}
out:
	(void) fprintf(xdotcf, "};\n");
	(void) fclose(xdotcf);
	(void) fclose(strf);
}

char *
savestr(char *cp)
{
	char *dp;

	if ((dp = calloc(1, strlen(cp) + 1)) == NULL) {
		perror("xstr");
		exit(8);
	}
	return (strcpy(dp, cp));
}

int
lastchr(char *cp)
{

	while (cp[0] && cp[1])
		cp++;
	return ((int)*cp);
}

int
istail(char *str, char *of)
{
	int d = strlen(of) - strlen(str);

	if (d < 0 || strcmp(&of[d], str) != 0)
		return (-1);
	return (d);
}

void
onintr(void)
{

	(void) signal(SIGINT, SIG_IGN);
	(void) cleanup();
	(void) unlink("x.c");
	(void) unlink("xs.c");
	exit(7);
}

void
cleanup(void)
{
	if (strings[0] == '/') {
		(void) unlink(strings);
	}
}
