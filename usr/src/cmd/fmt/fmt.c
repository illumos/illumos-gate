/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/


#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <wctype.h>
#include <widec.h>
#include <dlfcn.h>
#include <locale.h>
#include <sys/param.h>
#include <string.h>

/*
 * fmt -- format the concatenation of input files or standard input
 * onto standard output.  Designed for use with Mail ~|
 *
 * Syntax: fmt [ -width | -w width ] [ -cs ] [ name ... ]
 * Author: Kurt Shoens (UCB) 12/7/78
 */

#define	NOSTR	((wchar_t *)0)	/* Null string pointer for lint */
#define	MAXLINES	100	/* maximum mail header lines to verify */

wchar_t	outbuf[BUFSIZ];			/* Sandbagged output line image */
wchar_t	*outp;				/* Pointer in above */
int	filler;				/* Filler amount in outbuf */
char sobuf[BUFSIZ];	/* Global buffer */

int	pfx;			/* Current leading blank count */
int	width = 72;		/* Width that we will not exceed */
int	nojoin = 0;		/* split lines only, don't join short ones */
int	errs = 0;		/* Current number of errors */

enum crown_type	{c_none, c_reset, c_head, c_lead, c_fixup, c_body};
enum crown_type	crown_state;	/* Crown margin state */
int	crown_head;		/* The header offset */
int	crown_body;		/* The body offset */
	/* currently-known initial strings found in mail headers */
wchar_t	*headnames[] = {
	L"Apparently-To", L"Bcc", L"bcc", L"Cc", L"cc", L"Confirmed-By",
	L"Content", L"content-length", L"From", L"Date", L"id",
	L"Message-I", L"MIME-Version", L"Precedence", L"Return-Path",
	L"Received", L"Reply-To", L"Status", L"Subject", L"To", L"X-IMAP",
	L"X-Lines", L"X-Sender", L"X-Sun", L"X-Status", L"X-UID",
	0};

enum hdr_type {
	off,		/* mail header processing is off */
	not_in_hdr,	/* not currently processing a mail header */
	in_hdr, 	/* currently filling hdrbuf with potential hdr lines */
	flush_hdr,	/* flush hdrbuf; not a header, no special processing */
	do_hdr		/* process hdrbuf as a mail header */
};
				/* current state of hdrbuf */
enum hdr_type	hdr_state = not_in_hdr;

wchar_t *hdrbuf[MAXLINES];	/* buffer to hold potential mail header lines */
int 	h_lines;		/* index into lines of hdrbuf */

void (*(split))(wchar_t []);
extern int scrwidth(wchar_t);
extern boolean_t is_headline(const char *);


static void fill_hdrbuf(wchar_t []);
static void header_chk(void);
static void process_hdrbuf(void);
static void leadin(void);
static void tabulate(wchar_t []);
static void oflush(void);
static void pack(wchar_t []);
static void msplit(wchar_t []);
static void csplit(wchar_t []);
static void _wckind_init(void);
static void prefix(wchar_t []);
static void fmt(FILE *);
static int setopt(char *);
int _wckind(wchar_t);

/*
 * Drive the whole formatter by managing input files.  Also,
 * cause initialization of the output stuff and flush it out
 * at the end.
 */

int
main(int argc, char **argv)
{
	FILE *fi;
	char *cp;
	int nofile;
	char *locale;

	outp = NOSTR;
	setbuf(stdout, sobuf);
	setlocale(LC_ALL, "");
	locale = setlocale(LC_CTYPE, "");
	if (strcmp(locale, "C") == 0) {
		split = csplit;
	} else {
		split = msplit;
		_wckind_init();
	}
	if (argc < 2) {
single:
		fmt(stdin);
		oflush();
		exit(0);
	}
	nofile = 1;
	while (--argc) {
		cp = *++argv;
		if (setopt(cp))
			continue;
		nofile = 0;
		if ((fi = fopen(cp, "r")) == NULL) {
			perror(cp);
			errs++;
			continue;
		}
		fmt(fi);
		fclose(fi);
	}
	if (nofile)
		goto single;
	oflush();
	fclose(stdout);
	return (errs);
}

/*
 * Read up characters from the passed input file, forming lines,
 * doing ^H processing, expanding tabs, stripping trailing blanks,
 * and sending each line down for analysis.
 */

static void
fmt(FILE *fi)
{
	wchar_t linebuf[BUFSIZ], canonb[BUFSIZ];
	wchar_t *cp, *cp2;
	int col;
	wchar_t	c;
	char	cbuf[BUFSIZ];	/* stores wchar_t string as char string */

	c = getwc(fi);
	while (c != EOF) {
		/*
		 * Collect a line, doing ^H processing.
		 * Leave tabs for now.
		 */

		cp = linebuf;
		while (c != L'\n' && c != EOF && cp-linebuf < BUFSIZ-1) {
			if (c == L'\b') {
				if (cp > linebuf)
					cp--;
				c = getwc(fi);
				continue;
			}
			if (!(iswprint(c)) && c != L'\t') {
				c = getwc(fi);
				continue;
			}
			*cp++ = c;
			c = getwc(fi);
		}
		*cp = L'\0';

		/*
		 * Toss anything remaining on the input line.
		 */

		while (c != L'\n' && c != EOF)
			c = getwc(fi);
		/*
		 * Expand tabs on the way to canonb.
		 */

		col = 0;
		cp = linebuf;
		cp2 = canonb;
		while (c = *cp++) {
			if (c != L'\t') {
				col += scrwidth(c);
				if (cp2-canonb < BUFSIZ-1)
					*cp2++ = c;
				continue;
			}
			do {
				if (cp2-canonb < BUFSIZ-1)
					*cp2++ = L' ';
				col++;
			} while ((col & 07) != 0);
		}

		/*
		 * Swipe trailing blanks from the line.
		 */

		for (cp2--; cp2 >= canonb && *cp2 == L' '; cp2--) {
		}
		*++cp2 = '\0';

			/* special processing to look for mail header lines */
		switch (hdr_state) {
		case off:
			prefix(canonb);
		case not_in_hdr:
			/* look for an initial mail header line */
			/* skip initial blanks */
			for (cp = canonb; *cp == L' '; cp++) {
			}
			/*
			 * Need to convert string from wchar_t to char,
			 * since this is what is_headline() expects.  Since we
			 * only want to make sure cp points to a "From" line
			 * of the email, we don't have to alloc
			 * BUFSIZ * MB_LEN_MAX to cbuf.
			 */
			wcstombs(cbuf, cp, (BUFSIZ - 1));
			if (is_headline(cbuf) == B_TRUE) {
				hdr_state = in_hdr;
				fill_hdrbuf(canonb);
			} else {
				/* no mail header line; process normally */
				prefix(canonb);
			}
			break;
		case in_hdr:
			/* already saw 1st mail header line; look for more */
			if (canonb[0] == L'\0') {
				/*
				 * blank line means end of mail header;
				 * verify current mail header buffer
				 * then process it accordingly
				 */
				header_chk();
				process_hdrbuf();
				/* now process the current blank line */
				prefix(canonb);
			} else
				/*
				 * not a blank line--save this line as
				 * a potential mail header line
				 */
				fill_hdrbuf(canonb);
			break;
		}
		if (c != EOF)
			c = getwc(fi);
	}
	/*
	 * end of this file--make sure we process the stuff in
	 * hdrbuf before we're finished
	 */
	if (hdr_state == in_hdr) {
		header_chk();
		process_hdrbuf();
	}
}

/*
 * Take a line devoid of tabs and other garbage and determine its
 * blank prefix.  If the indent changes, call for a linebreak.
 * If the input line is blank, echo the blank line on the output.
 * Finally, if the line minus the prefix is a mail header, try to keep
 * it on a line by itself.
 */

static void
prefix(wchar_t line[])
{
	wchar_t *cp;
	int np;
	int nosplit = 0;	/* flag set if line should not be split */

	if (line[0] == L'\0') {
		oflush();
		putchar('\n');
		if (crown_state != c_none)
			crown_state = c_reset;
		return;
	}
	for (cp = line; *cp == L' '; cp++) {
	}
	np = cp - line;

	/*
	 * The following horrible expression attempts to avoid linebreaks
	 * when the indent changes due to a paragraph.
	 */

	if (crown_state == c_none && np != pfx && (np > pfx || abs(pfx-np) > 8))
		oflush();
	/*
	 * if this is a mail header line, don't split it; flush previous
	 * line, if any, so we don't join this line to it
	 */
	if (hdr_state == do_hdr) {
		nosplit = 1;
		oflush();
	}
	/* flush previous line so we don't join this one to it */
	if (nojoin)
		oflush();
	/* nroff-type lines starting with '.' are not split nor joined */
	if (!nosplit && (nosplit = (*cp == L'.')))
		oflush();
	pfx = np;
	switch (crown_state) {
	case c_reset:
		crown_head = pfx;
		crown_state = c_head;
		break;
	case c_lead:
		crown_body = pfx;
		crown_state = c_body;
		break;
	case c_fixup:
		crown_body = pfx;
		crown_state = c_body;
		if (outp) {
			wchar_t s[BUFSIZ];

			*outp = L'\0';
			wscpy(s, &outbuf[crown_head]);
			outp = NOSTR;
			split(s);
		}
		break;
	}
	if (nosplit) {
		/* put whole input line onto outbuf and print it out */
		pack(cp);
		oflush();
	} else
		/*
		 * split puts current line onto outbuf, but splits it
		 * at word boundaries, if it exceeds desired length
		 */
		split(cp);
	if (nojoin)
		/*
		 * flush current line so next lines, if any,
		 * won't join to this one
		 */
		oflush();
}

/*
 * Split up the passed line into output "words" which are
 * maximal strings of non-blanks with the blank separation
 * attached at the end.  Pass these words along to the output
 * line packer.
 */

static void
csplit(wchar_t line[])
{
	wchar_t *cp, *cp2;
	wchar_t word[BUFSIZ];
	static const wchar_t *srchlist = (const wchar_t *) L".:!?";

	cp = line;
	while (*cp) {
		cp2 = word;

		/*
		 * Collect a 'word,' allowing it to contain escaped
		 * white space.
		 */

		while (*cp && !(iswspace(*cp))) {
			if (*cp == '\\' && iswspace(cp[1]))
				*cp2++ = *cp++;
			*cp2++ = *cp++;
		}

		/*
		 * Guarantee a space at end of line.
		 * Two spaces after end of sentence punctuation.
		 */

		if (*cp == L'\0') {
			*cp2++ = L' ';
			if (wschr(srchlist, cp[-1]) != NULL)
				*cp2++ = L' ';
		}
		while (iswspace(*cp))
			*cp2++ = *cp++;
		*cp2 = L'\0';
		pack(word);
	}
}

static void
msplit(wchar_t line[])
{
	wchar_t *cp, *cp2, prev;
	wchar_t word[BUFSIZ];
	static const wchar_t *srchlist = (const wchar_t *) L".:!?";

	cp = line;
	while (*cp) {
		cp2 = word;
		prev = *cp;

		/*
		 * Collect a 'word,' allowing it to contain escaped
		 * white space.
		 */

		while (*cp) {
			if (iswspace(*cp))
				break;
			if (_wckind(*cp) != _wckind(prev))
				if (wcsetno(*cp) != 0 || wcsetno(prev) != 0)
					break;
			if (*cp == '\\' && iswspace(cp[1]))
				*cp2++ = *cp++;
			prev = *cp;
			*cp2++ = *cp++;
		}

		/*
		 * Guarantee a space at end of line.
		 * Two spaces after end of sentence punctuation.
		 */

		if (*cp == L'\0') {
			*cp2++ = L' ';
			if (wschr(srchlist, cp[-1]) != NULL)
				*cp2++ = L' ';
		}
		while (iswspace(*cp))
			*cp2++ = *cp++;
		*cp2 = L'\0';
		pack(word);
	}
}

/*
 * Output section.
 * Build up line images from the words passed in.  Prefix
 * each line with correct number of blanks.  The buffer "outbuf"
 * contains the current partial line image, including prefixed blanks.
 * "outp" points to the next available space therein.  When outp is NOSTR,
 * there ain't nothing in there yet.  At the bottom of this whole mess,
 * leading tabs are reinserted.
 */

/*
 * Pack a word onto the output line.  If this is the beginning of
 * the line, push on the appropriately-sized string of blanks first.
 * If the word won't fit on the current line, flush and begin a new
 * line.  If the word is too long to fit all by itself on a line,
 * just give it its own and hope for the best.
 */

static void
pack(wchar_t word[])
{
	wchar_t *cp;
	int s, t;

	if (outp == NOSTR)
		leadin();
	t = wscol(word);
	*outp = L'\0';
	s = wscol(outbuf);
	if (t+s <= width) {
		for (cp = word; *cp; *outp++ = *cp++) {
		}
		return;
	}
	if (s > filler) {
		oflush();
		leadin();
	}
	for (cp = word; *cp; *outp++ = *cp++) {
	}
}

/*
 * If there is anything on the current output line, send it on
 * its way.  Set outp to NOSTR to indicate the absence of the current
 * line prefix.
 */

static void
oflush(void)
{
	if (outp == NOSTR)
		return;
	*outp = L'\0';
	tabulate(outbuf);
	outp = NOSTR;
}

/*
 * Take the passed line buffer, insert leading tabs where possible, and
 * output on standard output (finally).
 */

static void
tabulate(wchar_t line[])
{
	wchar_t *cp;
	int b, t;


	/* Toss trailing blanks in the output line */
	cp = line + wslen(line) - 1;
	while (cp >= line && *cp == L' ')
		cp--;
	*++cp = L'\0';
	/* Count the leading blank space and tabulate */
	for (cp = line; *cp == L' '; cp++) {
	}
	b = cp - line;
	t = b >> 3;
	b &= 07;
	if (t > 0)
		do {
			putc('\t', stdout);
		} while (--t);
	if (b > 0)
		do {
			putc(' ', stdout);
		} while (--b);
	while (*cp)
		putwc(*cp++, stdout);
	putc('\n', stdout);
}

/*
 * Initialize the output line with the appropriate number of
 * leading blanks.
 */

static void
leadin(void)
{
	int b;
	wchar_t *cp;
	int l;

	switch (crown_state) {
	case c_head:
		l = crown_head;
		crown_state = c_lead;
		break;

	case c_lead:
	case c_fixup:
		l = crown_head;
		crown_state = c_fixup;
		break;

	case c_body:
		l = crown_body;
		break;

	default:
		l = pfx;
		break;
	}
	filler = l;
	for (b = 0, cp = outbuf; b < l; b++)
		*cp++ = L' ';
	outp = cp;
}

/*
 * Is s1 a prefix of s2??
 */

static int
ispref(wchar_t *s1, wchar_t *s2)
{

	while (*s1 != L'\0' && *s2 != L'\0')
		if (*s1++ != *s2++)
			return (0);
	return (1);
}

/*
 * Set an input option
 */

static int
setopt(char *cp)
{
	static int ws = 0;

	if (*cp == '-') {
		if (cp[1] == 'c' && cp[2] == '\0') {
			crown_state = c_reset;
			return (1);
		}
		if (cp[1] == 's' && cp[2] == '\0') {
			nojoin = 1;
			return (1);
		}
		if (cp[1] == 'w' && cp[2] == '\0') {
			ws++;
			return (1);
		}
		width = atoi(cp+1);
	} else if (ws) {
		width = atoi(cp);
		ws = 0;
	} else
		return (0);
	if (width <= 0 || width >= BUFSIZ-2) {
		fprintf(stderr, "fmt:  bad width: %d\n", width);
		exit(1);
	}
	return (1);
}


#define	LIB_WDRESOLVE	"/usr/lib/locale/%s/LC_CTYPE/wdresolve.so"
#define	WCHKIND		"_wdchkind_"

static int	_wckind_c_locale(wchar_t);

static int	(*__wckind)(wchar_t) = _wckind_c_locale;
static void	*dlhandle = NULL;


static void
_wckind_init(void)
{
	char	*locale;
	char	path[MAXPATHLEN + 1];


	if (dlhandle != NULL) {
		(void) dlclose(dlhandle);
		dlhandle = NULL;
	}

	locale = setlocale(LC_CTYPE, NULL);
	if (strcmp(locale, "C") == 0)
		goto c_locale;

	(void) sprintf(path, LIB_WDRESOLVE, locale);

	if ((dlhandle = dlopen(path, RTLD_LAZY)) != NULL) {
		__wckind = (int (*)(wchar_t))dlsym(dlhandle, WCHKIND);
		if (__wckind != NULL)
			return;
		(void) dlclose(dlhandle);
		dlhandle = NULL;
	}

c_locale:
	__wckind = _wckind_c_locale;
}


int
_wckind(wchar_t wc)
{
	return (*__wckind) (wc);
}


static int
_wckind_c_locale(wchar_t wc)
{
	int	ret;

	/*
	 * DEPEND_ON_ANSIC: L notion for the character is new in
	 * ANSI-C, k&r compiler won't work.
	 */
	if (iswascii(wc))
		ret = (iswalnum(wc) || wc == L'_') ? 0 : 1;
	else
		ret = wcsetno(wc) + 1;

	return (ret);
}

/*
 * header_chk -
 * Called when done looking for a set mail header lines.
 * Either a blank line was seen, or EOF was reached.
 *
 * Verifies if current hdrbuf of potential mail header lines
 * is really a mail header.  A mail header must be at least 2
 * lines and more than half of them must start with one of the
 * known mail header strings in headnames.
 *
 * header_chk sets hdr_state to do_hdr if hdrbuf contained a valid
 * mail header.  Otherwise, it sets hdr_state to flush_hdr.
 *
 * h_lines = hdrbuf index for next line to be saved;
 *	     also indicates current # of lines in potential header
 */
static void
header_chk(void)
{
	wchar_t  *cp; 		/* ptr to current char of line */
	wchar_t **hp; 		/* ptr to current char of a valid */
				/* mail header string */
	int	  l;		/* index */
				/*
				 * number of lines in hdrbuf that look
				 * like mail header lines (start with
				 * a known mail header prefix)
				 */
	int	 hdrcount = 0;
		/* header must have at least 2 lines (h_lines > 1) */
		if (h_lines < 2) {
			hdr_state = flush_hdr;
			return;
		}
		/*
		 * go through each line in hdrbuf and see how many
		 * look like mail header lines
		 */
		for (l = 0; l < h_lines; l++) {
			/* skip initial blanks */
			for (cp = hdrbuf[l]; *cp == L' '; cp++) {
			}
			for (hp = &headnames[0]; *hp != (wchar_t *)0; hp++)
				if (ispref(*hp, cp)) {
					hdrcount++;
					break;
				}
		}
		/*
		 * if over half match, we'll assume this is a header;
		 * set hdr_state to indicate whether to treat
		 * these lines as mail header (do_hdr) or not (flush_hdr)
		 */
		if (hdrcount > h_lines / 2)
			hdr_state = do_hdr;
		else
			hdr_state = flush_hdr;
}

/*
 * fill_hdrbuf -
 * Save given input line into next element of hdrbuf,
 * as a potential mail header line, to be processed later
 * once we decide whether or not the contents of hdrbuf is
 * really a mail header, via header_chk().
 *
 * Does not allow hdrbuf to exceed MAXLINES lines.
 * Dynamically allocates space for each line.  If we are unable
 * to allocate space for the current string, stop special mail
 * header preservation at this point and continue formatting
 * without it.
 */
static void
fill_hdrbuf(wchar_t line[])
{
	wchar_t *cp;	/* pointer to characters in input line */
	int	 i;	/* index into characters a hdrbuf line */

	if (h_lines >= MAXLINES) {
		/*
		 * if we run over MAXLINES potential mail header
		 * lines, stop checking--this is most likely NOT a
		 * mail header; flush out the hdrbuf, then process
		 * the current 'line' normally.
		 */
		hdr_state = flush_hdr;
		process_hdrbuf();
		prefix(line);
		return;
	}
	hdrbuf[h_lines] = (wchar_t *)malloc(sizeof (wchar_t) *
	    (wslen(line) + 1));
	if (hdrbuf[h_lines] == NULL) {
		perror("malloc");
		fprintf(stderr, "fmt: unable to do mail header preservation\n");
		errs++;
		/*
		 * Can't process mail header; flush current contents
		 * of mail header and continue with no more mail
		 * header processing
		 */
		if (h_lines == 0)
			/* hdrbuf is empty; process this line normally */
			prefix(line);
		else {
			hdr_state = flush_hdr;
			for (i = 0; i < h_lines; i++) {
				prefix(hdrbuf[i]);
				free(hdrbuf[i]);
			}
			h_lines = 0;
		}
		hdr_state = off;
		return;
	}
	/* save this line as a potential mail header line */
	for (i = 0, cp = line; (hdrbuf[h_lines][i] = *cp) != L'\0'; i++, cp++) {
	}
	h_lines++;
}

/*
 * process_hdrbuf -
 * Outputs the lines currently stored in hdrbuf, according
 * to the current hdr_state value, assumed to be either do_hdr
 * or flush_hdr.
 * This should be called after doing a header_chk() to verify
 * the hdrbuf and set the hdr_state flag.
 */
static void
process_hdrbuf(void)
{
int i;

	for (i = 0; i < h_lines; i++) {
		prefix(hdrbuf[i]);
		free(hdrbuf[i]);
	}
	hdr_state = not_in_hdr;
	h_lines = 0;
}
