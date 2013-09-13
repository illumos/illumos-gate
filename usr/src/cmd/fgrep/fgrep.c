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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation	*/
/*	  All Rights Reserved	*/

/*
 * Copyright 2013 Damian Bogel. All rights reserved.
 */

/*
 * fgrep -- print all lines containing any of a set of keywords
 *
 *	status returns:
 *		0 - ok, and some matches
 *		1 - ok, but no matches
 *		2 - some error
 */

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <libintl.h>
#include <euc.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <getwidth.h>

eucwidth_t WW;
#define	WIDTH1	WW._eucw1
#define	WIDTH2	WW._eucw2
#define	WIDTH3	WW._eucw3
#define	MULTI_BYTE	WW._multibyte
#define	GETONE(lc, p) \
	cw = ISASCII(lc = (unsigned char)*p++) ? 1 :     \
		(ISSET2(lc) ? WIDTH2 :                       \
		(ISSET3(lc) ? WIDTH3 : WIDTH1));             \
	if (--cw > --ccount) {                           \
		cw -= ccount;                                \
		while (ccount--)                             \
			lc = (lc << 7) | ((*p++) & 0177);        \
			if (p >= &buf[fw_lBufsiz + BUFSIZ]) {    \
			if (nlp == buf) {                        \
				/* Increase the buffer size */       \
				fw_lBufsiz += BUFSIZ;                \
				if ((buf = realloc(buf,              \
					fw_lBufsiz + BUFSIZ)) == NULL) { \
					exit(2); /* out of memory */     \
				}                                    \
				nlp = buf;                           \
				p = &buf[fw_lBufsiz];                \
			} else {                                 \
				/* shift the buffer contents down */ \
				(void) memmove(buf, nlp,             \
					&buf[fw_lBufsiz + BUFSIZ] - nlp);\
				p -= nlp - buf;                      \
				nlp = buf;                           \
			}                                        \
		}                                            \
		if (p > &buf[fw_lBufsiz]) {                  \
			if ((ccount = fread(p, sizeof (char),    \
			    &buf[fw_lBufsiz + BUFSIZ] - p, fptr))\
				<= 0) break;                         \
		} else if ((ccount = fread(p,                \
			sizeof (char),  BUFSIZ, fptr)) <= 0)     \
			break;                                   \
		blkno += (long long)ccount;                  \
	}                                                \
	ccount -= cw;                                    \
	while (cw--)                                     \
		lc = (lc << 7) | ((*p++) & 0177)

/*
 * The same() macro and letter() function were inserted to allow for
 * the -i option work for the multi-byte environment.
 */
wchar_t letter();
#define	same(a, b) \
	(a == b || iflag && (!MULTI_BYTE || ISASCII(a)) && (a ^ b) == ' ' && \
	letter(a) == letter(b))

#define	STDIN_FILENAME gettext("(standard input)")

#define	QSIZE 400
struct words {
	wchar_t inp;
	char	out;
	struct	words *nst;
	struct	words *link;
	struct	words *fail;
} *w = NULL, *smax, *q;

FILE *fptr;
long long lnum;
int	bflag, cflag, lflag, fflag, nflag, vflag, xflag, eflag, qflag;
int	Hflag, hflag, iflag;
int	retcode = 0;
int	nfile;
long long blkno;
int	nsucc;
long long tln;
FILE	*wordf;
char	*argptr;
off_t input_size = 0;

void	execute(char *);
void	cgotofn(void);
void	overflo(void);
void	cfail(void);

static long fw_lBufsiz = 0;

int
main(int argc, char **argv)
{
	int c;
	int errflg = 0;
	struct stat file_stat;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "Hhybcie:f:lnvxqs")) != EOF)
		switch (c) {

		case 'q':
		case 's': /* Solaris: legacy option */
			qflag++;
			continue;
		case 'H':
			Hflag++;
			hflag = 0;
			continue;
		case 'h':
			hflag++;
			Hflag = 0;
			continue;
		case 'b':
			bflag++;
			continue;

		case 'i':
		case 'y':
			iflag++;
			continue;

		case 'c':
			cflag++;
			continue;

		case 'e':
			eflag++;
			argptr = optarg;
			input_size = strlen(argptr);
			continue;

		case 'f':
			fflag++;
			wordf = fopen(optarg, "r");
			if (wordf == NULL) {
				(void) fprintf(stderr,
				    gettext("fgrep: can't open %s\n"),
				    optarg);
				exit(2);
			}

			if (fstat(fileno(wordf), &file_stat) == 0) {
				input_size = file_stat.st_size;
			} else {
				(void) fprintf(stderr,
				    gettext("fgrep: can't fstat %s\n"),
				    optarg);
				exit(2);
			}

			continue;

		case 'l':
			lflag++;
			continue;

		case 'n':
			nflag++;
			continue;

		case 'v':
			vflag++;
			continue;

		case 'x':
			xflag++;
			continue;

		case '?':
			errflg++;
	}

	argc -= optind;
	if (errflg || ((argc <= 0) && !fflag && !eflag)) {
		(void) printf(gettext("usage: fgrep [ -bcHhilnqsvx ] "
		    "[ -e exp ] [ -f file ] [ strings ] [ file ] ...\n"));
		exit(2);
	}
	if (!eflag && !fflag) {
		argptr = argv[optind];
		input_size = strlen(argptr);
		input_size++;
		optind++;
		argc--;
	}

/*
 * Normally we need one struct words for each letter in the pattern
 * plus one terminating struct words with outp = 1, but when -x option
 * is specified we require one more struct words for `\n` character so we
 * calculate the input_size as below. We add extra 1 because
 * (input_size/2) rounds off odd numbers
 */

	if (xflag) {
		input_size = input_size + (input_size/2) + 1;
	}

	input_size++;

	w = (struct words *)calloc(input_size, sizeof (struct words));
	if (w == NULL) {
		(void) fprintf(stderr,
		    gettext("fgrep: could not allocate "
		    "memory for wordlist\n"));
		exit(2);
	}

	getwidth(&WW);
	if ((WIDTH1 == 0) && (WIDTH2 == 0) &&
	    (WIDTH3 == 0)) {
		/*
		 * If non EUC-based locale,
		 * assume WIDTH1 is 1.
		 */
		WIDTH1 = 1;
	}
	WIDTH2++;
	WIDTH3++;

	cgotofn();
	cfail();
	nfile = argc;
	argv = &argv[optind];
	if (argc <= 0) {
		execute((char *)NULL);
	} else
		while (--argc >= 0) {
			execute(*argv);
			argv++;
		}

	if (w != NULL) {
		free(w);
	}

	return (retcode != 0 ? retcode : nsucc == 0);
}

void
execute(char *file)
{
	char *p;
	struct words *c;
	int ccount;
	static char *buf = NULL;
	int failed;
	char *nlp;
	wchar_t lc;
	int cw;

	if (buf == NULL) {
		fw_lBufsiz = BUFSIZ;
		if ((buf = malloc(fw_lBufsiz + BUFSIZ)) == NULL) {
			exit(2); /* out of memory */
		}
	}

	if (file) {
		if ((fptr = fopen(file, "r")) == NULL) {
			(void) fprintf(stderr,
			    gettext("fgrep: can't open %s\n"), file);
			retcode = 2;
			return;
		}
	} else {
		fptr = stdin;
		file = STDIN_FILENAME;
	}
	ccount = 0;
	failed = 0;
	lnum = 1;
	tln = 0;
	blkno = 0;
	p = buf;
	nlp = p;
	c = w;
	for (;;) {
		if (c == 0)
			break;
		if (ccount <= 0) {
			if (p >= &buf[fw_lBufsiz + BUFSIZ]) {
				if (nlp == buf) {
					/* increase the buffer size */
					fw_lBufsiz += BUFSIZ;
					if ((buf = realloc(buf,
					    fw_lBufsiz + BUFSIZ)) == NULL) {
						exit(2); /* out of memory */
					}
					nlp = buf;
					p = &buf[fw_lBufsiz];
				} else {
					/* shift the buffer down */
					(void) memmove(buf, nlp,
					    &buf[fw_lBufsiz + BUFSIZ]
					    - nlp);
					p -= nlp - buf;
					nlp = buf;
				}

			}
			if (p > &buf[fw_lBufsiz]) {
				if ((ccount = fread(p, sizeof (char),
				    &buf[fw_lBufsiz + BUFSIZ] - p, fptr))
				    <= 0)
					break;
			} else if ((ccount = fread(p, sizeof (char),
			    BUFSIZ, fptr)) <= 0)
				break;
			blkno += (long long)ccount;
		}
		GETONE(lc, p);
nstate:
		if (same(c->inp, lc)) {
			c = c->nst;
		} else if (c->link != 0) {
			c = c->link;
			goto nstate;
		} else {
			c = c->fail;
			failed = 1;
			if (c == 0) {
				c = w;
istate:
				if (same(c->inp, lc)) {
					c = c->nst;
				} else if (c->link != 0) {
					c = c->link;
					goto istate;
				}
			} else
				goto nstate;
		}

		if (c == 0)
			break;

		if (c->out) {
			while (lc != '\n') {
				if (ccount <= 0) {
if (p == &buf[fw_lBufsiz + BUFSIZ]) {
	if (nlp == buf) {
		/* increase buffer size */
		fw_lBufsiz += BUFSIZ;
		if ((buf = realloc(buf, fw_lBufsiz + BUFSIZ)) == NULL) {
			exit(2); /* out of memory */
		}
		nlp = buf;
		p = &buf[fw_lBufsiz];
	} else {
		/* shift buffer down */
		(void) memmove(buf, nlp, &buf[fw_lBufsiz + BUFSIZ] - nlp);
		p -= nlp - buf;
		nlp = buf;
	}
}
if (p > &buf[fw_lBufsiz]) {
	if ((ccount = fread(p, sizeof (char),
		&buf[fw_lBufsiz + BUFSIZ] - p, fptr)) <= 0) break;
	} else if ((ccount = fread(p, sizeof (char), BUFSIZ,
		fptr)) <= 0) break;
		blkno += (long long)ccount;
	}
	GETONE(lc, p);
}
			if ((vflag && (failed == 0 || xflag == 0)) ||
				(vflag == 0 && xflag && failed))
				goto nomatch;
succeed:
			nsucc = 1;
			if (lflag || qflag) {
				if (!qflag)
					(void) printf("%s\n", file);
				(void) fclose(fptr);
				return;
			}
			if (cflag) {
				tln++;
			} else {
				if (Hflag || (nfile > 1 && !hflag))
					(void) printf("%s:", file);
				if (bflag)
					(void) printf("%lld:",
						(blkno - (long long)(ccount-1))
						/ BUFSIZ);
				if (nflag)
					(void) printf("%lld:", lnum);
				if (p <= nlp) {
					while (nlp < &buf[fw_lBufsiz + BUFSIZ])
						(void) putchar(*nlp++);
					nlp = buf;
				}
				while (nlp < p)
					(void) putchar(*nlp++);
			}
nomatch:
			lnum++;
			nlp = p;
			c = w;
			failed = 0;
			continue;
		}
		if (lc == '\n')
			if (vflag)
				goto succeed;
			else {
				lnum++;
				nlp = p;
				c = w;
				failed = 0;
			}
	}
	(void) fclose(fptr);
	if (cflag && !qflag) {
		if (Hflag || (nfile > 1 && !hflag))
			(void) printf("%s:", file);
		(void) printf("%lld\n", tln);
	}
}


wchar_t
getargc(void)
{
	/* appends a newline to shell quoted argument list so */
	/* the list looks like it came from an ed style file  */
	wchar_t c;
	int cw;
	int b;
	static int endflg;


	if (wordf) {
		if ((b = getc(wordf)) == EOF)
			return (EOF);
		cw = ISASCII(c = (wchar_t)b) ? 1 :
		    (ISSET2(c) ? WIDTH2 : (ISSET3(c) ? WIDTH3 : WIDTH1));
		while (--cw) {
			if ((b = getc(wordf)) == EOF)
				return (EOF);
			c = (c << 7) | (b & 0177);
		}
		return (iflag ? letter(c) : c);
	}

	if (endflg)
		return (EOF);

	{
		cw = ISASCII(c = (unsigned char)*argptr++) ? 1 :
		    (ISSET2(c) ? WIDTH2 : (ISSET3(c) ? WIDTH3 : WIDTH1));

		while (--cw)
			c = (c << 7) | ((*argptr++) & 0177);
		if (c == '\0') {
			endflg++;
			return ('\n');
		}
	}
	return (iflag ? letter(c) : c);


}

void
cgotofn(void)
{
	int c;
	struct words *s;

	s = smax = w;
nword:
	for (;;) {
		c = getargc();
		if (c == EOF)
			return;
		if (c == 0)
			goto enter;
		if (c == '\n') {
			if (xflag) {
				for (;;) {
					if (s->inp == c) {
						s = s->nst;
						break;
					}
					if (s->inp == 0)
						goto nenter;
					if (s->link == 0) {
						if (smax >= &w[input_size -1])
							overflo();
						s->link = ++smax;
						s = smax;
						goto nenter;
					}
					s = s->link;
				}
			}
			s->out = 1;
			s = w;
		} else {
loop:
			if (s->inp == c) {
				s = s->nst;
				continue;
			}
			if (s->inp == 0)
				goto enter;
			if (s->link == 0) {
				if (smax >= &w[input_size -1])
					overflo();
				s->link = ++smax;
				s = smax;
				goto enter;
			}
			s = s->link;
			goto loop;
		}
	}

enter:
	do {
		s->inp = c;
		if (smax >= &w[input_size -1])
			overflo();
		s->nst = ++smax;
		s = smax;
	} while ((c = getargc()) != '\n' && c != EOF);
	if (xflag) {
nenter:
		s->inp = '\n';
		if (smax >= &w[input_size -1])
			overflo();
		s->nst = ++smax;
	}
	smax->out = 1;
	s = w;
	if (c != EOF)
		goto nword;
}

/*
 * This function is an unexpected condition, since input_size should have been
 * calculated correctly before hand.
 */

void
overflo(void)
{
	(void) fprintf(stderr, gettext("fgrep: wordlist too large\n"));
	exit(2);
}

void
cfail(void)
{
	int qsize = QSIZE;
	struct words **queue = NULL;

	/*
	 * front and rear are pointers used to traverse the global words
	 * structure "w" which contains the data of input pattern file
	 */
	struct words **front, **rear;
	struct words *state;
	unsigned long frontoffset = 0, rearoffset = 0;
	char c;
	struct words *s;
	s = w;
	if ((queue = (struct words **)calloc(qsize, sizeof (struct words *)))
	    == NULL) {
		perror("fgrep");
		exit(2);
	}
	front = rear = queue;
init:
	if ((s->inp) != 0) {
		*rear++ = s->nst;
	/*
	 * Reallocates the queue if the number of distinct starting
	 * character of patterns exceeds the qsize value
	 */
		if (rear >= &queue[qsize - 1]) {
			frontoffset = front - queue;
			rearoffset = rear - queue;
			qsize += QSIZE;
			if ((queue = (struct words **)realloc(queue,
				qsize * sizeof (struct words *))) == NULL) {
				perror("fgrep");
				exit(2);
			}
			front = queue + frontoffset;
			rear = queue + rearoffset;
		}
	}
	if ((s = s->link) != 0) {
		goto init;
	}

	while (rear != front) {
		s = *front++;
cloop:
		if ((c = s->inp) != 0) {
			*rear++ = (q = s->nst);
		/*
		 * Reallocate the queue if the rear pointer reaches the end
		 * queue
		 */
			if (rear >= &queue[qsize - 1]) {
				frontoffset = front - queue;
				rearoffset = rear - queue;
				qsize += QSIZE;
				if ((queue = (struct words **)realloc(queue,
				    qsize * sizeof (struct words *))) == NULL) {
					perror("fgrep");
					exit(2);
				}
				front = queue + frontoffset;
				rear = queue + rearoffset;
			}
			state = s->fail;
floop:
			if (state == 0)
				state = w;
			if (state->inp == c) {
qloop:
				q->fail = state->nst;
				if ((state->nst)->out == 1)
					q->out = 1;
				if ((q = q->link) != 0)
					goto qloop;
			} else if ((state = state->link) != 0)
				goto floop;
		}
		if ((s = s->link) != 0)
			goto cloop;
	}
}

wchar_t
letter(wchar_t c)
{
	if (c >= 'a' && c <= 'z')
		return (c);
	if (c >= 'A' && c <= 'Z')
		return (c + 'a' - 'A');
	return (c);
}
