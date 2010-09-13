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
 * Copyright (c) 1990, 1991, 1994, Sun Microsystems, Inc.
 * All rights reserved.
 */

#ident	"%Z%%M%	%I%	%E% SMI"

#include <nl_types.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>
#include <libintl.h>

#ifndef NL_MSGMAX
#define	NL_MSGMAX 32767
#endif

#ifndef NL_SETMAX
#define	NL_SETMAX 255
#endif

#ifndef NL_TEXTMAX
#define	NL_TEXTMAX 2048
#endif

#define	BS		'\b'
#define	CR		'\r'
#define	DOLLAR	'$'
#define	FF		'\f'
#define	NEWLINE	'\n'
#define	NUL		'\000'
#define	REVERSE_SOLIDUS '\\'
#define	SPACE	' '
#define	TAB		'\t'
#define	VTAB	'\v'

#define	FPRINTF			(void) fprintf
#define	FREE(x)			free((char *)(x))
#define	MALLOC(n)		malloc((unsigned)(n))
#define	MEMCPY(dst, src, n) \
		(void) memcpy((char *)(dst), (char *)(src), (int)(n))
#define	MEMSET(s, c, n)	(void) memset((char *)(s), (int)(c), (int)(n));
#define	MSG(n)			gettext(MSG ## n)
#define	READ(fd, p, n)	read((int)(fd), (char *)(p), (unsigned)(n))
#define	REALLOC(x, n)	realloc((char *)(x), (unsigned)(n))

/* double linked list */
struct cat_set {
	struct cat_set	*prev;
	struct cat_set	*next;
	int				set_no;
	struct cat_msg	*first_msg;
};

/* double linked list */
struct cat_msg {
	struct cat_msg	*prev;
	struct cat_msg	*next;
	int				msg_no;
	int				msg_len;
	char			s[1];
};

int		catfd;		/* File descriptor of catalog file */
char	*catfname;	/* Catalog file name */
char	*msgfname;	/* message source file name */
int		ateof;		/* boolean indicating END-OF-FILE */
int		lineno;		/* the line number of message source file */
int		quoting;	/* boolean indicating quotes is used */
int		quote;		/* the current quote */
int		text_len;	/* message text length */
int		text_size;	/* the size of allocated text memory */
char	*text;		/* messsge text */

struct _cat_hdr	hdr;
int				current_set_no;	/* the current set number */
struct cat_set	*first_set;	/* the pointer to the first set */
struct cat_set	*current_set;	/* the pointer to the current set */
struct cat_msg	*current_msg;	/* the pointer to the first message */


/* Error message */
/* 0 */
#define	MSG0	""
/* 1 */
#define	MSG1	"usage: gencat catfile msgfile ...\n"
/* 2 */
#define	MSG2	"gencat: cannot open \"%s\"\n"
/* 3 */
#define	MSG3	"gencat: read error on \"%s\"\n"
/* 4 */
#define	MSG4	"gencat: bad magic number (%#lx)\n"
/* 5 */
#define	MSG5	"gencat: corrupt catalogue file \"%s\"\n"
/* 6 */
#define	MSG6	"gencat: memory limit exceeded\n"
/* 7 */
#define	MSG7	"gencat: seek error on \"%s\"\n"
/* 8 */
#define	MSG8	"gencat: write error on \"%s\"\n"
/* 9 */
#define	MSG9	"gencat: \"%s\", line %d: number too large (%s)\n"
/* 10 */
#define	MSG10	"gencat: \"%s\", line %d: 0 is not a permissible " \
				"message number\n"
/* 11 */
#define	MSG11	"gencat: \"%s\", line %d: warning, message number %d " \
				"exceeds limit (%d)\n"
/* 12 */
#define	MSG12	"gencat: \"%s\", line %d: missing quote (%wc)\n"
/* 13 */
#define	MSG13	"gencat: \"%s\", line %d: character value too large ('\\%o')\n"
/* 14 */
#define	MSG14	"gencat: \"%s\", line %d: extra characters following " \
				"message text\n"
/* 15 */
#define	MSG15	"gencat: \"%s\", line %d: extra characters following " \
				"$quote directive\n"
/* 16 */
#define	MSG16	"gencat: \"%s\", line %d: no set number specified in " \
				"$set directive\n"
/* 17 */
#define	MSG17	"getcat: \"%s\", line %d: 0 is not a permissible set number\n"
/* 18 */
#define	MSG18	"gencat: \"%s\", line %d: warning, set number %d " \
				"exceeds limit (%d)\n"
/* 19 */
#define	MSG19	"gencat: \"%s\", line %d: unknown directive %s\n"
/* 20 */
#define	MSG20	"gencat: \"%s\", line %d: no set number specified in " \
				"$delset directive\n"
/* 21 */
#define	MSG21	"stdin"
/* 22 */
#define	MSG22	"gencat: \"%s\", line %d: number or $ expected\n"

struct cat_set *
new_set(n)
	int		n;
{
	struct cat_set *p;

	p = (struct cat_set *) MALLOC(sizeof (struct cat_set));
	if (p == NULL) {
		FPRINTF(stderr, MSG(6));
		exit(1);
	}
	p->next = NULL;
	p->prev = NULL;
	p->set_no = n;
	p->first_msg = NULL;
	return (p);
}

void
find_set(no)
	int		no;
{
	struct cat_set	*prev, *next;

	if (current_set && current_set->set_no == no) {
		return;
	}

	current_set_no = no;
	current_msg = NULL;
	/* if no set exists, create a new set */
	if (current_set == NULL) {
		if (first_set == NULL) {
			current_set = first_set = new_set(no);
			return;
		}
		current_set = first_set;
		if (current_set->set_no == no)
			return;
	}

	if (current_set->set_no > no) {
		if (first_set->set_no > no) {
			/* prepend a new set */
			current_set = new_set(no);
			current_set->next = first_set;
			first_set->prev = current_set;
			first_set = current_set;
			return;
		}
		current_set = first_set;
		if (current_set->set_no == no)
			return;
	}

	/* search for the set number 'no' */
	while (current_set->next && current_set->next->set_no < no)
		current_set = current_set->next;

	if (current_set->next && current_set->next->set_no == no) {
		/* set number 'no' found */
		current_set = current_set->next;
		return;
	}

	/* If set number is not found, insert a new set in the middle */
	prev = current_set;
	next = current_set->next;
	current_set = new_set(no);
	current_set->prev = prev;
	current_set->next = next;
	if (prev)
		prev->next = current_set;
	else
		first_set = current_set;
	if (next)
		next->prev = current_set;
}

void
delete_set(no)
	int		no;
{
	struct cat_set	*prev, *next, *setp;
	struct cat_msg	*p, *q;

	for (setp = first_set; setp && setp->set_no < no; setp = setp->next)
		continue;

	if (setp == NULL || setp->set_no != no)	/* set not found */
		return;

	if (setp == current_set) {
		current_set = NULL;
		current_msg = NULL;
	}

	/* free all messages in the set */
	for (p = setp->first_msg; p; p) {
		q = p->next;
		FREE(p);
		p = q;
	}

	/* do the link operation to delete the set */
	prev = setp->prev;
	next = setp->next;
	FREE(setp);
	if (prev)
		prev->next = next;
	else
		first_set = next;
	if (next)
		next->prev = prev;
}

struct cat_msg *
new_msg(no, len, text)
	int		no;
	int		len;
	char	*text;
{
	struct cat_msg	*p;

	p = (struct cat_msg *) MALLOC(sizeof (struct cat_msg) + len);
	if (p == NULL) {
		FPRINTF(stderr, MSG(6));
		exit(1);
	}
	p->next = NULL;
	p->prev = NULL;
	p->msg_no = no;
	p->msg_len = len;
	MEMCPY(p->s, text, len);
	return (p);
}


void
insert_msg(no, len, text)
	int		no;
	int		len;
	char	*text;
{
	struct cat_msg	*prev, *next;

	if (current_msg == NULL) {
		if (current_set == NULL)
			find_set(current_set_no);
		current_msg = current_set->first_msg;
		if (current_msg == NULL) {
			current_msg = new_msg(no, len, text);
			current_set->first_msg = current_msg;
			return;
		}
	}
	if (current_msg->msg_no >= no) {
		current_msg = current_set->first_msg;
		if (current_msg->msg_no > no) {
			current_msg = new_msg(no, len, text);
			current_msg->next = current_set->first_msg;
			current_set->first_msg->prev = current_msg;
			current_set->first_msg = current_msg;
			return;
		}
		if (current_msg->msg_no == no) {
			current_msg = new_msg(no, len, text);
			current_msg->next = current_set->first_msg->next;
			if (current_set->first_msg->next)
				current_set->first_msg->next->prev =
					current_msg;
			FREE(current_set->first_msg);
			current_set->first_msg = current_msg;
			return;
		}
	}
	while (current_msg->next && current_msg->next->msg_no < no)
		current_msg = current_msg->next;

	/*
	 * if the same msg number is found, then delte the message and
	 * insert the new message. This is same as replacing message.
	 */
	if (current_msg->next && current_msg->next->msg_no == no) {
		current_msg = current_msg->next;
		prev = current_msg->prev;
		next = current_msg->next;
		FREE(current_msg);
	} else {
		prev = current_msg;
		next = current_msg->next;
	}

	current_msg = new_msg(no, len, text);
	current_msg->prev = prev;
	current_msg->next = next;
	if (prev)
		prev->next = current_msg;
	else
		current_set->first_msg = current_msg;
	if (next)
		next->prev = current_msg;
}

void
delete_msg(no)
	int		no;
{
	struct cat_set	*p = current_set;
	struct cat_msg	*prev, *next;

	if (current_msg == NULL) {
		if (current_set == NULL)
			for (p = first_set; p && p->set_no < current_set_no;
							p = p->next)
				continue;
		if (p == NULL || p->set_no != current_set_no)
			return;
		current_set = p;
		current_msg = current_set->first_msg;
		if (current_msg == NULL)
			return;
	}
	if (current_msg->msg_no > no)
		current_msg = current_set->first_msg;

	while (current_msg && current_msg->msg_no != no)
		current_msg = current_msg->next;

	if (current_msg && current_msg->msg_no == no) {
		prev = current_msg->prev;
		next = current_msg->next;
		FREE(current_msg);
		if (prev) {
			current_msg = prev;
			prev->next = next;
		} else {
			current_set->first_msg = next;
			current_msg = next;
		}
		if (next)
			next->prev = prev;
	}
}

int
read_block(fd, p, n, pathname)
	int		fd;
	char	*p;
	int		n;
	char	*pathname;
{
	int		nbytes, bytes_read;

	if (n == 0)
		return (0);

	nbytes = 0;
	while (nbytes < n) {
		bytes_read = READ(fd, p + nbytes, n - nbytes);
		if (bytes_read < 0) {
			if (errno != EINTR) {
				FPRINTF(stderr, MSG(3), pathname);
				perror("");
				exit(1);
			}
		} else if (bytes_read == 0)
			break;
		else
			nbytes += bytes_read;
	}

	return (nbytes);
}

/*
 * Check if catalog file read is valid
 *
 */
int
cat_ok(cat)
	char	*cat;
{
	int		i, j;
	int		nmsgs;
	int		msg_no;
	struct	_cat_msg_hdr	*msg;
	int		set_no;
	int		first_msg_hdr;
	struct	_cat_set_hdr	*set;

	set = (struct _cat_set_hdr *) cat;
	set_no = 0;
	for (i = 0; i < hdr.__nsets; ++set, ++i) {
		if (set->__set_no < set_no)
			return (0);
		set_no = set->__set_no;
		nmsgs = set->__nmsgs;
		if (nmsgs < 0)
			return (0);
		if (nmsgs == 0)
			continue;
		first_msg_hdr = set->__first_msg_hdr;
		if (first_msg_hdr < 0)
			return (0);
		if (hdr.__msg_hdr_offset + (first_msg_hdr + nmsgs) *
					_CAT_MSG_HDR_SIZE > hdr.__mem)
			return (0);

		msg = (struct _cat_msg_hdr *) (cat + hdr.__msg_hdr_offset) +
						first_msg_hdr;
		msg_no = 0;
		for (j = 0; j < nmsgs; ++msg, ++j) {
			if (msg->__msg_no < msg_no)
				return (0);
			msg_no = msg->__msg_no;
			if (msg->__msg_offset < 0)
				return (0);
			if (hdr.__msg_text_offset + msg->__msg_offset +
						msg->__msg_len > hdr.__mem)
				return (0);
		}
	}

	return (1);
}

/*
 * convert a chunk of catalog file into double linked list format
 */
void
initcat(cat)
	char	*cat;
{
	int		i, j;
	int		nmsgs;
	struct	_cat_set_hdr	*set;
	struct	_cat_msg_hdr	*msg;

	set = (struct _cat_set_hdr *) cat;
	for (i = 0; i < hdr.__nsets; ++set, ++i) {
		nmsgs = set->__nmsgs;
		if (nmsgs == 0)
			continue;
		find_set(set->__set_no);
		msg = (struct _cat_msg_hdr *) (cat + hdr.__msg_hdr_offset)
			+ set->__first_msg_hdr;
		current_msg = current_set->first_msg;
		for (j = 0; j < nmsgs; ++msg, ++j) {
			insert_msg(msg->__msg_no, msg->__msg_len,
			    cat + hdr.__msg_text_offset + msg->__msg_offset);
		}
	}
}

/*
 * read a catalog file in a chunk and convert it to double linked list.
 */
void
readcat(fd, pathname)
	int		fd;
	char	*pathname;
{
	int		i;
	char	*cat;

	i = read_block(fd, (char *) &hdr, _CAT_HDR_SIZE, pathname);
	if (i == 0)
		return;

	if (i >= 4 && hdr.__hdr_magic != _CAT_MAGIC) {
		FPRINTF(stderr, MSG(4), hdr.__hdr_magic);
		exit(1);
	}
	if (i < _CAT_HDR_SIZE || hdr.__nsets < 0) {
		FPRINTF(stderr, MSG(5), pathname);
		exit(1);
	}
	if (hdr.__nsets == 0)
		return;

	if (hdr.__mem < 0 ||
	    hdr.__msg_hdr_offset < 0 ||
	    hdr.__msg_text_offset < 0 ||
	    hdr.__mem < hdr.__nsets * _CAT_SET_HDR_SIZE ||
	    hdr.__mem < hdr.__msg_hdr_offset ||
	    hdr.__mem < hdr.__msg_text_offset) {
		FPRINTF(stderr, MSG(5), pathname);
		exit(1);
	}
	cat = MALLOC(hdr.__mem);
	if (cat == NULL) {
		FPRINTF(stderr, MSG(6));
		exit(1);
	}
	i = read_block(fd, cat, hdr.__mem, pathname);
	if (i < hdr.__mem || !cat_ok(cat)) {
		FPRINTF(stderr, MSG(5), pathname);
		exit(1);
	}
	initcat(cat);

	FREE(cat);
}

/*
 * Extend the memory in 1000 byte chunks whenever runs out of text space.
 */
void
extend_text()
{
	text_size += 1000;
	if (text)
		text = REALLOC(text, text_size);
	else
		text = MALLOC(text_size);
	if (text == NULL) {
		FPRINTF(stderr, MSG(6));
		exit(1);
	}
}

int
get_number(fp, c)
	FILE	*fp;
	int		c;
{
	int		i, n;
	char	*s, *t;

	i = 0;
	do {
		while (i >= text_size)
			extend_text();
		text[i] = c;
		++i;
		c = getc(fp);
	}
	while (isdigit(c));
	(void) ungetc(c, fp);

	while (i >= text_size)
		extend_text();
	text[i] = NUL;

	for (s = text; *s == '0'; ++s)
		continue;

	n = 0;
	for (t = s; isdigit(*t); ++t) {
		if (n > INT_MAX / 10 ||
			(n == INT_MAX / 10 && *t > '0' + INT_MAX % 10)) {
			FPRINTF(stderr, MSG(9), msgfname, lineno, s);
			exit(1);
		}
		n = 10 * n + (*t - '0');
	}

	return (n);
}

void
get_text(fp)
	FILE	*fp;
{
	int		c;
	int		n;

	text_len = 0;
	c = fgetwc(fp);
	if (quoting && c == quote) {	/* quote is used */
		c = fgetwc(fp);
		while (c != quote) {
			if (c == NEWLINE || c == EOF) {
				FPRINTF(stderr, MSG(12), msgfname, lineno,
								quote);
				exit(1);
			}
			if (c == REVERSE_SOLIDUS) {
				c = fgetwc(fp);
				switch (c) {
				case EOF:
					FPRINTF(stderr, MSG(12), msgfname,
						lineno, quote);
					exit(1);
					break;
				case NEWLINE:
					++lineno;
					c = fgetwc(fp);
					continue;
					/* NOTREACHED */
					break;
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
					n = (c - '0');
					c = fgetwc(fp);
					if (c >= '0' && c <= '7') {
						n = 8 * n + (c - '0');
						c = fgetwc(fp);
						if (c >= '0' && c <= '7')
							n = 8 * n + (c - '0');
						else
							(void) ungetwc(c, fp);
					} else
						(void) ungetwc(c, fp);
					if (n > UCHAR_MAX) {
						FPRINTF(stderr, MSG(13),
							msgfname, lineno, n);
						exit(1);
					}
					c = n;
					break;

				case 'n':
					c = NEWLINE;
					break;

				case 't':
					c = TAB;
					break;

				case 'v':
					c = VTAB;
					break;

				case 'b':
					c = BS;
					break;

				case 'r':
					c = CR;
					break;

				case 'f':
					c = FF;
					break;
				}
			}
			while ((text_len + (int)MB_CUR_MAX + 1) >= text_size)
				extend_text();
			if ((n = wctomb(&text[text_len], c)) > 0)
				text_len += n;
			c = fgetwc(fp);
		}

		while ((text_len + 1) >= text_size)
			extend_text();
		text[text_len] = '\0';
		++text_len;

		do {
			c = getc(fp);
		} while (c == SPACE || c == TAB);
		if (c == NEWLINE) {
			++lineno;
			return;
		}
		if (c == EOF) {
			ateof = 1;
			return;
		}
		FPRINTF(stderr, MSG(14), msgfname, lineno);
		exit(1);
	}

	while (c != NEWLINE && c != EOF) {	/* quote is not used */
		if (c == REVERSE_SOLIDUS) {
			c = fgetwc(fp);
			switch (c) {
			case EOF:
				return;

			case NEWLINE:
				++lineno;
				c = fgetwc(fp);
				continue;

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
				n = (c - '0');
				c = fgetwc(fp);
				if (c >= '0' && c <= '7') {
					n = 8 * n + (c - '0');
					c = fgetwc(fp);
					if (c >= '0' && c <= '7')
						n = 8 * n + (c - '0');
					else
						(void) ungetwc(c, fp);
				} else
					(void) ungetwc(c, fp);
				if (n > UCHAR_MAX) {
					FPRINTF(stderr, MSG(13), msgfname,
							lineno, n);
					exit(1);
				}
				c = n;
				break;

			case 'n':
				c = NEWLINE;
				break;

			case 't':
				c = TAB;
				break;

			case 'v':
				c = VTAB;
				break;

			case 'b':
				c = BS;
				break;

			case 'r':
				c = CR;
				break;

			case 'f':
				c = FF;
				break;
			}
		}
		while ((text_len + (int)MB_CUR_MAX + 1) >= text_size)
			extend_text();
		if ((n = wctomb(&text[text_len], c)) > 0)
			text_len += n;
		c = fgetwc(fp);
	}

	while ((text_len + 1) >= text_size)
		extend_text();
	text[text_len] = '\0';
	++text_len;

	if (c == NEWLINE)
		++lineno;
	else
		ateof = 1;
}

/*
 * This routine handles $ <comment>, $set, $delset, $quote
 */
void
directive(fp)
	FILE	*fp;
{
	int		c;
	int		n;

	c = fgetwc(fp);
	if (c == SPACE || c == TAB) {	/* $ <comment */
		do {
			c = fgetwc(fp);
		} while (c != NEWLINE && c != EOF);
	}
	if (c == NEWLINE) {
		++lineno;
		return;
	}
	if (c == EOF) {
		ateof = 1;
		return;
	}
	text_len = 1;
	while (text_len >= text_size)
		extend_text();
	text[0] = DOLLAR;
	while (isascii(c) && isalpha(c)) {
		while ((text_len + 1) >= text_size)
			extend_text();
		text[text_len] = c;
		++text_len;
		c = fgetwc(fp);
	}

	while ((text_len + 1) >= text_size)
		extend_text();
	text[text_len] = NUL;

	if (strcmp(text, "$set") == 0) {
		while (c == SPACE || c == TAB)
			c = fgetwc(fp);
		if (!isascii(c) || !isdigit(c)) {
			FPRINTF(stderr, MSG(16), msgfname, lineno);
			exit(1);
		}
		n = get_number(fp, c);
		if (n == 0) {
			FPRINTF(stderr, MSG(17), msgfname, lineno);
			exit(1);
		}
		if (n > NL_SETMAX) {
			FPRINTF(stderr, MSG(18), msgfname, lineno,
						n, NL_SETMAX);
		}
		find_set(n);
		do {	/* skip comment */
			c = getc(fp);
		} while (c != NEWLINE && c != EOF);
		if (c == NEWLINE)
			++lineno;
		else
			ateof = 1;
		return;
	} else if (strcmp(text, "$delset") == 0) {
		while (c == SPACE || c == TAB)
			c = fgetwc(fp);
		if (!isascii(c) || !isdigit(c)) {
			FPRINTF(stderr, MSG(20), msgfname, lineno);
			exit(1);
		}
		n = get_number(fp, c);
		if (n == 0) {
			FPRINTF(stderr, MSG(17), msgfname, lineno);
			exit(1);
		}
		if (n > NL_SETMAX) {
			FPRINTF(stderr, MSG(18), msgfname, lineno,
						n, NL_SETMAX);
		}
		delete_set(n);
		do {	/* skip comment */
			c = getc(fp);
		} while (c != NEWLINE && c != EOF);
		if (c == NEWLINE)
			++lineno;
		else
			ateof = 1;
		return;
	} else if (strcmp(text, "$quote") == 0) {
		if (c == NEWLINE) {
			quoting = 0;
			++lineno;
			return;
		}
		if (c == EOF) {
			quoting = 0;
			ateof = 1;
			return;
		}
		if (c == SPACE || c == TAB)
			c = fgetwc(fp);
		if (c == NEWLINE) {
			quoting = 0;
			++lineno;
			return;
		}
		if (c == EOF) {
			quoting = 0;
			ateof = 1;
			return;
		}
		quoting = 1;
		quote = c;
		do {	/* skip comment */
			c = getc(fp);
		} while (c == SPACE || c == TAB);
		if (c == NEWLINE) {
			++lineno;
			return;
		}
		if (c == EOF) {
			ateof = 1;
			return;
		}
		FPRINTF(stderr, MSG(15), msgfname, lineno);
		exit(1);
	} else {
		FPRINTF(stderr, MSG(19), msgfname, lineno, text);
		exit(1);
	}
}

/*
 * Read message source file and update double linked list message catalog.
 */
void
read_msgfile(fp, pathname)
	FILE	*fp;
	char	*pathname;
{
	int		c;
	int		no;

	ateof = 0;
	msgfname = pathname;
	lineno = 1;
	quoting = 0;
	current_set_no = NL_SETD;
	current_set = NULL;
	current_msg = NULL;

	for (;;) {
		if (ateof)
			return;
		do {
			c = fgetwc(fp);
		} while (c == SPACE || c == TAB);
		if (c == DOLLAR) {
			directive(fp);
			continue;
		}

		if (isascii(c) && isdigit(c)) {
			no = get_number(fp, c);
			if (no == 0) {
				FPRINTF(stderr, MSG(10), msgfname, lineno);
				exit(1);
			}
			if (no > NL_MSGMAX) {
				FPRINTF(stderr, MSG(11), msgfname,
					lineno, no, NL_MSGMAX);
			}
			c = fgetwc(fp);
			if (c == NEWLINE || c == EOF) {
				delete_msg(no);
				if (c == NEWLINE)
					++lineno;
				else
					return;
				continue;
			} else {
				if (c != SPACE && c != TAB)
					(void) ungetwc(c, fp);
				get_text(fp);
				insert_msg(no, text_len, text);
				continue;
			}
		}

		if (c == NEWLINE) {
			++lineno;
			continue;
		}
		if (c == EOF)
			return;

		FPRINTF(stderr, MSG(22), msgfname, lineno);
		exit(1);
	}
}

/*
 * Write double linked list to the file.
 * It first converts a linked list to one chunk of memory and
 * write it to file.
 */
void
writecat(fd, pathname)
	int		fd;
	char	*pathname;
{
	int		i, n;
	int		nsets;
	int		mem;
	int		nmsgs;
	int		text_size;
	int		first_msg_hdr;
	int		msg_offset;
	unsigned	nbytes;
	char	*cat;
	struct	_cat_hdr	*hdrp;
	struct	cat_set		*setp;
	struct	cat_msg		*msgp;
	struct	_cat_set_hdr	*set;
	struct	_cat_msg_hdr	*msg;
	char	*text;

	/* compute number of sets, number of messages, the total text size */
	nsets = 0;
	nmsgs = 0;
	text_size = 0;
	for (setp = first_set; setp; setp = setp->next) {
		++nsets;
		for (msgp = setp->first_msg; msgp; msgp = msgp->next) {
			++nmsgs;
			text_size += msgp->msg_len;
		}
	}

	mem = nsets * _CAT_SET_HDR_SIZE + nmsgs * _CAT_MSG_HDR_SIZE + text_size;
	n = _CAT_HDR_SIZE + mem;
	cat = MALLOC(n);
	if (cat == 0) {
		FPRINTF(stderr, MSG(6));
		exit(1);
	}
	MEMSET(cat, 0, n);

	hdrp = (struct _cat_hdr *) cat;
	hdrp->__hdr_magic = _CAT_MAGIC;
	hdrp->__nsets = nsets;
	hdrp->__mem = mem;
	hdrp->__msg_hdr_offset = nsets * _CAT_SET_HDR_SIZE;
	hdrp->__msg_text_offset = nsets * _CAT_SET_HDR_SIZE +
				nmsgs * _CAT_MSG_HDR_SIZE;

	set = (struct _cat_set_hdr *) (cat + _CAT_HDR_SIZE);
	msg = (struct _cat_msg_hdr *) (set + nsets);
	text = (char *) (msg + nmsgs);

	/* convert linked list to one chunk of memory */
	first_msg_hdr = 0;
	msg_offset = 0;
	for (setp = first_set; setp; ++set, setp = setp->next) {
		set->__set_no = setp->set_no;
		set->__first_msg_hdr = first_msg_hdr;
		nmsgs = 0;
		for (msgp = setp->first_msg; msgp; ++msg, msgp = msgp->next) {
			++nmsgs;
			msg->__msg_no = msgp->msg_no;
			msg->__msg_len = msgp->msg_len;
			msg->__msg_offset = msg_offset;
			if (msgp->msg_len > 0) {
				MEMCPY(text, msgp->s, msgp->msg_len);
				text += msgp->msg_len;
				msg_offset += msgp->msg_len;
			}
		}
		set->__nmsgs = nmsgs;
		first_msg_hdr += nmsgs;
	}

	/* write one chunk of memory to file */
	nbytes = 0;
	while (nbytes < n) {
		i = write(fd, cat + nbytes, n - nbytes);
		if (i < 0) {
			if (errno != EINTR) {
				FPRINTF(stderr, MSG(8), pathname);
				perror("");
				exit(1);
			}
		} else {
			nbytes += n;
		}
	}

	free(cat);
}

int
main(argc, argv)
	int		argc;
	char	*argv[];
{
	int		i;
	int		cat_exists;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)		/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	if (argc < 3) {
		FPRINTF(stderr, MSG(1));
		exit(1);
	}
	catfname = argv[1];
	cat_exists = 0;
	if ((*catfname == '-') && (*(catfname + 1) == '\0')) {
		catfd = 1;				/* Use stdout */
	} else {
		catfd = open(catfname, O_WRONLY | O_CREAT | O_EXCL, 0666);
		if (catfd < 0) {	/* file exists */
			if (errno != EEXIST ||
			    (catfd = open(catfname, O_RDWR)) < 0) {
				/* cannot open file */
				FPRINTF(stderr, MSG(2), catfname);
				perror("");
				exit(1);
			}
			cat_exists = 1;
			/* read catalog file into memory */
			readcat(catfd, catfname);
			if (lseek(catfd, 0L, 0) < 0) {
				FPRINTF(stderr, MSG(7), catfname);
				perror("");
				exit(1);
			}
		}
	}

	/* process all message source files */
	if ((**(argv + 2) == '-') && (*(*(argv + 2) + 1) == '\0')) {
		if (argc != 3) {
			FPRINTF(stderr, MSG(1));
			exit(1);
		} else {
			read_msgfile(stdin, MSG(21));
		}
	} else {
		for (i = 2; i < argc; ++i) {
			FILE	*fp;
			fp = fopen(*(argv + i), "r");
			if (fp == NULL) {
				FPRINTF(stderr, MSG(2), *(argv + i));
				perror("");
				exit(1);
			}
			read_msgfile(fp, *(argv + i));
			(void) fclose(fp);
		}
	}

	if (cat_exists)
		(void) ftruncate(catfd, 0L);

	/* write catalog to file */
	writecat(catfd, catfname);
	return (0);
}
