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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>
#include <fs/sockfs/socktpi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>


volatile uint64_t	nl7c_http_response_chunked = 0;
volatile uint64_t	nl7c_http_response_chunkparse = 0;

volatile uint64_t	nl7c_http_response_pass1 = 0;
volatile uint64_t	nl7c_http_response_pass2 = 0;
volatile uint64_t	nl7c_http_response_304 = 0;
volatile uint64_t	nl7c_http_response_307 = 0;
volatile uint64_t	nl7c_http_response_400 = 0;

volatile uint64_t	nl7c_http_cond_304 = 0;
volatile uint64_t	nl7c_http_cond_412 = 0;

/*
 * Some externs:
 */

extern uint64_t		nl7c_uri_bytes;
extern kmem_cache_t	*nl7c_uri_kmc;
extern kmem_cache_t	*nl7c_uri_rd_kmc;
extern void		nl7c_uri_inactive(uri_desc_t *);
extern uint32_t		nca_major_version;
extern uint32_t		nca_minor_version;

/*
 * HTTP connection persistent headers, mblk_t's, and state values stored in
 * (struct sonode *).so_nl7c_flags & NL7C_SCHEMEPRIV.
 */

char	Shttp_conn_cl[] = "Connection: close\r\n";
char	Shttp_conn_ka[] = "Connection: Keep-Alive\r\n";

mblk_t	*http_conn_cl;
mblk_t	*http_conn_ka;

#define	HTTP_CONN_CL	0x00010000
#define	HTTP_CONN_KA	0x00020000

/*
 * Hex ascii Digit to Integer accumulate, if (char)c is a valid ascii
 * hex digit then the contents of (int32_t)n will be left shifted and
 * the new digit added in, else n will be set to -1.
 */

#define	hd2i(c, n) {							\
	(n) *= 16;							\
	if (isdigit(c))							\
		(n) += (c) - '0';					\
	else if ((c) >= 'a' && (c) <= 'f')				\
		(n) += (c) - 'W';					\
	else if ((c) >= 'A' && (c) <= 'F')				\
		(n) += (c) - '7';					\
	else								\
		(n) = -1;						\
}

/*
 * HTTP parser action values:
 */

typedef enum act_e {
	REQUEST		= 0x0001,
	NUMERIC		= 0x0002,
	QUALIFIER	= 0x0004,
	PASS		= 0x0008,
	FILTER		= 0x0010,
	NOCACHE		= 0x0020,
	HASH		= 0x0040,
	DATE		= 0x0080,
	ETAG		= 0x0100,
	RESPONSE	= 0x0200,
	URIABS		= 0x0400,
	URIREL		= 0x0800,
	HEX		= 0x1000
} act_t;

#define	UNDEF		PASS

/*
 * HTTP parser token:
 */

typedef struct token_s {
	int	tokid;			/* Token ident */
	char	*text;			/* Token text */
	act_t	act;			/* Action to take */
} token_t;

/*
 * The ttree_t (or token tree) is an ascending ordered binary tree
 * built by ttree_build() from an array of tokens and subsequently
 * used by ttree_line_parse() to parse multiline text data.
 */
typedef struct ttree_s {
	token_t *tok;			/* Token */
	struct ttree_s *lt, *gt;	/* < and > next node */
} ttree_t;

/*
 * Note: req_tree[] and res_tree[] must be in ascending case insensitive
 * order of the char[] strings used to initialize each element.
 *
 * See "nl7ctokreq.txt" and "nl7ctokres.txt" which are processed by
 * "nl7ctokgen" to produce "nl7ctokgen.h" and included here.
 */

#define	INIT(s, t) {s, S##s, t}

#include "nl7ctokgen.h"
static ttree_t *req_tree;
static ttree_t *res_tree;

/*
 * HTTP scheme private state:
 */

typedef struct http_s {
	boolean_t	parsed;		/* Response parsed */
	uint32_t	major, minor;	/* HTTP/major.minor */
	uint32_t	headlen;	/* HTTP header length */
	clock_t		date;		/* Response Date: */
	clock_t		expire;		/* Response Expire: */
	clock_t		moddate;	/* Request *Modified-Since date */
	enum tokid_e	modtokid;	/* Request *Modified-Since tokid */
	time_t		lastmod;	/* Response Last-Modified: */
	str_t		accept;		/* Request Accept: */
	str_t		acceptchar;	/* Request Accept-Charset: */
	str_t		acceptenco;	/* Request Accept-Encoding: */
	str_t		acceptlang;	/* Request Accept-Language: */
	str_t		etag;		/* Request/Response ETag: */
	str_t		uagent;		/* Request User-Agent: */
} http_t;

static kmem_cache_t *http_kmc;

/*
 * HTTP date routines, dow[] for day of the week, Dow[] for day of the
 * week for the Unix epoch (i.e. day 0 is a Thu), months[] for the months
 * of the year, and dom[] for day number of the year for the first day
 * of each month (non leap year).
 */

static char *dow[] = {"sunday", "monday", "tuesday", "wednesday", "thursday",
	"friday", "saturday", 0};

static char *Dow[] = {"Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed", 0};

static char *months[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul",
	"Aug", "Sep", "Oct", "Nov", "Dec", 0};

static int dom[] = {0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334};

/*
 * http_date2time_t(const char *) - returns the time(2) value (i.e.
 * the value 0 is Thu, 01 Jan 1970 00:00:00 GMT) for the following
 * time formats used by HTTP request and response headers:
 *
 *	1) Sun, 07 Dec 1998 14:49:37 GMT	; RFC 822, updated by RFC 1123
 *	2) Sunday, 07-Dec-98 14:49:37 GMT	; RFC 850, obsoleted by RFC 1036
 *	3) Sun Nov  7 14:49:37 1998		; ANSI C's asctime() format
 *	4) 60					; Time delta of N seconds
 *
 * On error a time_t value of -1 is returned.
 *
 * All dates are GMT (must be part of the date string for types
 * 1 and 2 and not for type 1).
 *
 * Note, the given mstr_t pointed to by *sp will be modified.
 */

static time_t
http_date2time_t(char *cp, char *ep)
{
	char	*scp = cp;
	time_t	secs;
	char	**tpp;
	char	*tp;
	char	c, sc;
	ssize_t	n;

	ssize_t	zeroleap = 1970 / 4 - 1970 / 100 + 1970 / 400;
	ssize_t	leap;
	ssize_t	year;
	ssize_t	month;
	ssize_t	day;
	ssize_t	hour;
	ssize_t	min;
	ssize_t	sec;

	/* Parse and skip day-of-week (we don't use it) */
	tpp = dow;
	tp = *tpp;
	n = 0;
	while (cp < ep) {
		c = *cp++;
		if (c == ',' || c == ' ')
			break;
		c = tolower(c);
		if (*tp == 0 || *tp != c) {
			cp = scp;
			if ((tp = *++tpp) == NULL)
				break;
			continue;
		}
		tp++;
	}
	if (cp == NULL) {
		/* Not case 1-3, try 4 */
		while (cp < ep) {
			c = *cp;
			if (isdigit(c)) {
				cp++;
				n *= 10;
				n += c - '0';
				continue;
			}
			/* An invalid date sytax */
			return (-1);
		}
		/* Case 4, delta from current time */
		return (gethrestime_sec() + n);
	}
	if (c == ',') {
		/* Case 1 or 2, skip <SP> */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ' ')
			return (-1);
		/* Get day of the month */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		day = n;
		/* Get day/month/year seperator */
		if (cp == ep)
			return (-1);
		sc = *cp++;
		if (sc != ' ' && sc != '-')
			return (-1);
		/* Parse month */
		tpp = months;
		tp = *tpp++;
		scp = cp;
		n = 0;
		while (cp < ep) {
			c = *cp;
			if (c == sc) {
				cp++;
				break;
			}
			c = tolower(c);
			if (*tp == 0 || tolower(*tp) != c) {
				if ((tp = *tpp++) == NULL)
					break;
				cp = scp;
				n++;
				continue;
			}
			cp++;
			tp++;
		}
		if (cp == NULL)
			return (-1);
		month = n;
		/* Get year */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (sc == ' ') {
			/* Case 1, get 2 more year digits */
			if (! isdigit(c))
				return (-1);
			n *= 10;
			n += c - '0';
			if (cp == ep)
				return (-1);
			c = *cp++;
			if (! isdigit(c))
				return (-1);
			n *= 10;
			n += c - '0';
			/* Get seperator char */
			if (cp == ep)
				return (-1);
			c = *cp;
			if (c != ' ')
				return (-1);
			cp++;
		} else {
			/*
			 * Case 2, 2 digit year and as this is a so-called
			 * Unix date format and the begining of time was
			 * 1970 so we can extend this obsoleted date syntax
			 * past the year 1999 into the year 2038 for 32 bit
			 * machines and through 2069 for 64 bit machines.
			 */
			if (n > 69)
				n += 1900;
			else
				n += 2000;
		}
		year = n;
		/* Get GMT time */
		if (c != ' ')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		hour = n;
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ':')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		min = n;
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ':')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		sec = n;
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ' ')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != 'G')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != 'M')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != 'T')
			return (-1);
	} else {
		/* case 3, parse month */
		sc = c;
		tpp = months;
		tp = *tpp++;
		scp = cp;
		n = 0;
		while (cp < ep) {
			c = *cp;
			if (c == sc) {
				cp++;
				break;
			}
			c = tolower(c);
			if (*tp == 0 || tolower(*tp) != c) {
				if ((tp = *tpp++) == NULL)
					break;
				cp = scp;
				n++;
				continue;
			}
			cp++;
			tp++;
		}
		if (cp == NULL)
			return (-1);
		month = n;
		/* Get day of the month */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		day = n;
		/* Skip <SP> */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ' ')
			return (-1);
		/* Get time */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		hour = n;
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ':')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		min = n;
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ':')
			return (-1);
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		sec = n;
		/* Skip <SP> */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (c != ' ')
			return (-1);
		/* Get year */
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n = c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		if (cp == ep)
			return (-1);
		c = *cp++;
		if (! isdigit(c))
			return (-1);
		n *= 10;
		n += c - '0';
		year = n;
	}

	/* Last, caclulate seconds since Unix day zero */
	leap = year;
	if (month < 2)
		leap--;
	leap = leap / 4 - leap / 100 + leap / 400 - zeroleap;
	secs = ((((year - 1970) * 365 + dom[month] + day  - 1 + leap) * 24
	    + hour) * 60 + min) * 60 + sec;

	return (secs);
}

/*
 * http_today(char *) - returns in the given char* pointer the current
 * date in ascii with a format of (char [29]):
 *
 *	Sun, 07 Dec 1998 14:49:37 GMT	; RFC 822, updated by RFC 1123
 */

static void
http_today(char *cp)
{
	ssize_t	i;
	char	*fp;

	ssize_t	leap;
	ssize_t	year;
	ssize_t	month;
	ssize_t	dow;
	ssize_t	day;
	ssize_t	hour;
	ssize_t	min;
	ssize_t	sec;

	/* Secs since Thu, 01 Jan 1970 00:00:00 GMT */
	time_t	now = gethrestime_sec();

	sec = now % 60;
	now /= 60;
	min = now % 60;
	now /= 60;
	hour = now % 24;
	now /= 24;
	dow = now % 7;

	year = 1970;
	for (;;) {
		if (year % 4 == 0 && year % 100 != 0 || year % 400 == 0)
			day = 366;
		else
			day = 365;
		if (now < day)
			break;
		now -= day;
		year++;
	}

	now++;
	if (year % 4 == 0 && year % 100 != 0 || year % 400 == 0)
		leap = 1;
	else
		leap = 0;
	month = 11;
	for (i = 11; i; i--) {
		if (i < 2)
			leap = 0;
		if (now > dom[i] + leap)
			break;
		month--;
	}
	day = now - dom[i] - leap;

	fp = Dow[dow];
	*cp++ = *fp++;
	*cp++ = *fp++;
	*cp++ = *fp++;
	*cp++ = ',';
	*cp++ = ' ';

	i = day / 10;
	*cp++ = '0' + i;
	*cp++ = '0' + (day - i * 10);
	*cp++ = ' ';

	fp = months[month];
	*cp++ = *fp++;
	*cp++ = *fp++;
	*cp++ = *fp++;
	*cp++ = ' ';

	i = year / 1000;
	*cp++ = '0' + i;
	year -= i * 1000;
	i = year / 100;
	*cp++ = '0' + i;
	year -= i * 100;
	i = year / 10;
	*cp++ = '0' + i;
	year -= i * 10;
	*cp++ = '0' + year;
	*cp++ = ' ';

	i = hour / 10;
	*cp++ = '0' + i;
	*cp++ = '0' + (hour - i * 10);
	*cp++ = ':';

	i = min / 10;
	*cp++ = '0' + i;
	*cp++ = '0' + (min - i * 10);
	*cp++ = ':';

	i = sec / 10;
	*cp++ = '0' + i;
	*cp++ = '0' + (sec - i * 10);
	*cp++ = ' ';

	*cp++ = 'G';
	*cp++ = 'M';
	*cp = 'T';
}

/*
 * Given the ttree_t pointer "*t", parse the char buffer pointed to
 * by "**cpp" of multiline text data up to the pointer "**epp", the
 * pointer "*hash" points to the current text hash.
 *
 * If a match is found a pointer to the ttree_t token will be returned,
 * "**cpp" will point to the next line, "**epp" will point to the first
 * EOL char, "**hpp" will point to remainder of the parse data (if none,
 * **hpp == **epp), and "*hash" will be updated.
 *
 * If no match, as above except "**hpp" points to the begining of the
 * line and "*hash" wont be updated.
 *
 * If no EOL is found NULL is returned, "**epp" is set to NULL, no further
 * calls can be made until additional data is ready and all arguments are
 * reset.
 *
 * If EOH (i.e. an empty line) NULL is returned, "**hpp" is set to NULL,
 * *cpp points to past EOH, no further calls can be made.
 */

static token_t *
ttree_line_parse(ttree_t *t, char **cpp, char **epp, char **hpp, uint32_t *hash)
{
	char	ca, cb;			/* current line <=> parse node */

	char	*cp = *cpp;
	char	*ep = *epp;

	char	*tp = t->tok->text;	/* current parse text */
	char	*sp = cp;		/* saved *cp */

	int	parse;			/* parse state */

	uint32_t hv;			/* hash value */

	if (hash != NULL)
		hv = *hash;

	/* Special case, check for EOH (i.e. empty line) */
	if (cp < ep) {
		ca = *cp;
		if (ca == '\n') {
			/* End of header */
			*cpp = ++cp;
			*hpp = NULL;
			return (NULL);
		} else if (ca == '\r') {
			cp++;
			if (cp < ep) {
				ca = *cp;
				if (ca == '\n') {
					/* End of header */
					*cpp = ++cp;
					*hpp = NULL;
					return (NULL);
				}
			}
			cp = *cpp;
		}
	}
	while (cp < ep) {
		/* Get next parse text char */
		cb = *tp;
		if (cb != 0) {
			/* Get next current line char */
			ca = *cp++;
			/* Case insensitive */
			cb = tolower(cb);
			ca = tolower(ca);
			if (ca == cb) {
				/*
				 * Char match, next char.
				 *
				 * Note, parse text can contain EOL chars.
				 */
				tp++;
				continue;
			}
			if (ca == '\r' || ca == '\n') {
				/* EOL, always go less than */
				t = t->lt;
			} else if (ca < cb) {
				/* Go less than */
				t = t->lt;
			} else {
				/* Go greater than */
				t = t->gt;
			}
			while (t != NULL && t->tok == NULL) {
				/* Null node, so descend to < node */
				t = t->lt;
			}
			if (t != NULL) {
				/* Initialize for next node compare */
				tp = t->tok->text;
				cp = sp;
				continue;
			}
			/*
			 * End of tree walk, no match, return pointer
			 * to the start of line then below find EOL.
			 */
			*hpp = *cpp;
		} else {
			/*
			 * End of token text, match, return pointer to
			 * the rest of header text then below find EOL.
			 */
			*hpp = cp;
		}
		/*
		 * Find end of line. Note, the HTTP line syntax supports
		 * implicit multi-line if the next line starts with a <SP>
		 * or <HT>.
		 */
		parse = 0;
		while (cp < ep) {
			ca = *cp;
			if (parse == 0 && ca == '\r') {
				*epp = cp;
				parse = 1;
			} else if (parse == 0 && ca == '\n') {
				*epp = cp;
				parse = 2;
			} else if (parse == 1 && ca == '\n') {
				parse = 2;
			} else if (parse >= 2 && (ca == ' ' || ca == '\t')) {
				parse++;
			} else if (parse > 2) {
				parse = 0;
			} else if (parse == 2) {
				break;
			} else if (t != NULL && (t->tok->act & HASH) &&
			    hash != NULL) {
				CHASH(hv, ca);
			}
			cp++;
		}
		if (parse < 2) {
			/* No EOL, not enough data */
			*epp = NULL;
			return (t != NULL ? t->tok : NULL);
		}
		/*
		 * Return updated hash value (if any), update parse current
		 * pointer for next call (i.e. begin of next line), and last
		 * return pointer to the matching token_t.
		 */
		if (t != NULL && (t->tok->act & HASH) && hash != NULL)
			*hash = hv;
		*cpp = cp;
		return (t != NULL ? t->tok : NULL);
	}
	/*
	 * End of parse text, ...
	 */
	*epp = NULL;
	return (NULL);
}

/*
 * Given a NULL terminated array of token_t(s) ordered in ascending
 * case insensitive order a binary tree is allocated and populated with
 * pointers into the array and a pointer to the root node is returned.
 *
 * Todo, for maximum ttree parse efficiency needs to be path compressed,
 * the function ttree_line_parse() handles the empty nodes correctly.
 */
static ttree_t *
ttree_build(token_t *list, int sz)
{
	ttree_t *treev;
	int	max, lvl, inc, ix;

	/* calc the size of the tree */
	for (max = 1; max < sz; max <<= 1)
		;
	/* allocate the tree */
	treev = kmem_alloc(sizeof (*treev) * (max - 1), KM_SLEEP);

	/* walk the tree and populate from list vector */
	lvl = max;
	while (lvl >>= 1) {
		inc = lvl >> 1;
		for (ix = lvl; ix < max; ix += lvl << 1) {
			if (ix <= sz) {
				treev[ix - 1].tok = &list[ix - 1];
			} else {
				treev[ix - 1].tok = 0;
			}
			if (inc) {
				treev[ix - 1].lt = &treev[ix - inc - 1];
				treev[ix - 1].gt = &treev[ix + inc - 1];
			} else {
				treev[ix - 1].lt = 0;
				treev[ix - 1].gt = 0;
			}
		}
	}

	return (&treev[(max >> 1) - 1]);
}

void
nl7c_http_init(void)
{
	int	n;

	http_kmc = kmem_cache_create("NL7C_http_kmc",
	    sizeof (http_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	req_tree = ttree_build(tokreq, tokreq_cnt - 1);
	res_tree = ttree_build(tokres, tokres_cnt - 1);

	n = sizeof (Shttp_conn_cl) - 1;
	http_conn_cl = allocb_wait(n, BPRI_HI, STR_NOSIG, NULL);
	bcopy(Shttp_conn_cl, http_conn_cl->b_rptr, n);
	http_conn_cl->b_wptr += n;

	n = sizeof (Shttp_conn_ka) - 1;
	http_conn_ka = allocb_wait(n, BPRI_HI, STR_NOSIG, NULL);
	bcopy(Shttp_conn_ka, http_conn_ka->b_rptr, n);
	http_conn_ka->b_wptr += n;
}

void
nl7c_http_free(void *arg)
{
	http_t	*http = arg;

	kmem_cache_free(http_kmc, http);
}

#define	STR_T_NOTCMP_OPT(a, b, m) (					\
    a->m.cp && b->m.cp &&						\
	((a->m.ep - a->m.cp) != (b->m.ep - b->m.cp) ||			\
	strncmp(a->m.cp, b->m.cp, (b->m.ep - b->m.cp))))

#define	STR_T_NOTCMP(a, b, m) (						\
    a->m.cp && ! b->m.cp ||						\
    b->m.cp && ! a->m.cp ||						\
    STR_T_NOTCMP_OPT(a, b, m))

boolean_t
nl7c_http_cmp(void *arg1, void *arg2)
{
	http_t	*httpa = arg1;		/* Response */
	http_t	*httpb = arg2;		/* Request */

	if (httpa->major != httpb->major ||
	    httpa->minor != httpb->minor ||
	    STR_T_NOTCMP(httpa, httpb, accept) ||
	    STR_T_NOTCMP(httpa, httpb, acceptchar) ||
	    STR_T_NOTCMP(httpa, httpb, acceptenco) ||
	    STR_T_NOTCMP(httpa, httpb, acceptlang) ||
	    STR_T_NOTCMP_OPT(httpa, httpb, etag))
		return (B_FALSE);
	return (B_TRUE);
}

/*
 * In-line HTTP responses:
 */

static char http_resp_304[] =
	"HTTP/#.# 304 Not Modified\r\n"
	"Date: #############################\r\n"
	"Server: NCA/#.# (Solaris)\r\n";

static char http_resp_412[] =
	"HTTP/#.# 412 Precondition Failed\r\n"
	"Date: #############################\r\n"
	"Server: NCA/#.# (Solaris)\r\n";

static uri_desc_t *
http_mkresponse(uri_desc_t *req, uri_desc_t *res, char *proto, int sz)
{
	http_t		*qhttp = req->scheme;
	http_t		*shttp = res->scheme;
	uri_desc_t	*uri = kmem_cache_alloc(nl7c_uri_kmc, KM_SLEEP);
	char		*alloc;
	char		*cp;
	char		*ep = &proto[sz];
	uri_rd_t	*rdp;
	int		cnt;

	char		hdr_etag[] = "ETag: ";

	/* Any optional header(s) */
	if (shttp->etag.cp != NULL) {
		/* Response has an ETag:, count it */
		sz += sizeof (hdr_etag) - 1 +
		    (shttp->etag.ep - shttp->etag.cp) + 2;
	}
	sz += 2;
	alloc = kmem_alloc(sz, KM_SLEEP);

	/* Minimum temp uri initialization as needed by uri_response() */
	REF_INIT(uri, 1, nl7c_uri_inactive, nl7c_uri_kmc);
	uri->hash = URI_TEMP;
	uri->tail = NULL;
	uri->scheme = NULL;
	uri->reqmp = NULL;
	uri->count = 0;
	cv_init(&uri->waiting, NULL, CV_DEFAULT, NULL);
	mutex_init(&uri->proclock, NULL, MUTEX_DEFAULT, NULL);

	URI_RD_ADD(uri, rdp, sz, -1);
	rdp->data.kmem = alloc;
	atomic_add_64(&nl7c_uri_bytes, sz);

	cp = alloc;
	if (qhttp->major == 1) {
		/*
		 * Full response format.
		 *
		 * Copy to first sub char '#'.
		 */
		while (proto < ep) {
			if (*proto == '#')
				break;
			*cp++ = *proto++;
		}

		/* Process the HTTP version substitutions */
		if (*proto != '#') goto bad;
		*cp++ = '0' + qhttp->major;
		proto++;
		while (proto < ep) {
			if (*proto == '#')
				break;
			*cp++ = *proto++;
		}
		if (*proto != '#') goto bad;
		*cp++ = '0' + qhttp->minor;
		proto++;

		/* Copy to the next sub char '#' */
		while (proto < ep) {
			if (*proto == '#')
				break;
			*cp++ = *proto++;
		}

		/* Process the "Date: " substitution */
		if (*proto != '#') goto bad;
		http_today(cp);

		/* Skip to the next nonsub char '#' */
		while (proto < ep) {
			if (*proto != '#')
				break;
			cp++;
			proto++;
		}

		/* Copy to the next sub char '#' */
		while (proto < ep) {
			if (*proto == '#')
				break;
			*cp++ = *proto++;
		}

		/* Process the NCA version substitutions */
		if (*proto != '#') goto bad;
		*cp++ = '0' + nca_major_version;
		proto++;
		while (proto < ep) {
			if (*proto == '#')
				break;
			*cp++ = *proto++;
		}
		if (*proto != '#') goto bad;
		*cp++ = '0' + nca_minor_version;
		proto++;

		/* Copy remainder of HTTP header */
		while (proto < ep) {
			*cp++ = *proto++;
		}
	} else {
		goto bad;
	}
	/* Any optional header(s) */
	if (shttp->etag.cp != NULL) {
		/* Response has an ETag:, add it */
		cnt = sizeof (hdr_etag) - 1;
		bcopy(hdr_etag, cp, cnt);
		cp += cnt;
		cnt = (shttp->etag.ep - shttp->etag.cp);
		bcopy(shttp->etag.cp, cp, cnt);
		cp += cnt;
		*cp++ = '\r';
		*cp++ = '\n';
	}
	/* Last, add empty line */
	uri->eoh = cp;
	*cp++ = '\r';
	*cp = '\n';

	return (uri);

bad:
	/*
	 * Free any resources allocated here, note that while we could
	 * use the uri_inactive() to free the uri by doing a REF_RELE()
	 * we instead free it here as the URI may be in less then a fully
	 * initialized state.
	 */
	kmem_free(alloc, sz);
	kmem_cache_free(nl7c_uri_kmc, uri);
	return (NULL);
}

uri_desc_t *
nl7c_http_cond(uri_desc_t *req, uri_desc_t *res)
{
	http_t	*qhttp = req->scheme;
	time_t	qdate = qhttp->moddate;
	http_t	*shttp = res->scheme;
	time_t	sdate = shttp->lastmod == -1 ? shttp->date : shttp->lastmod;
	uri_desc_t *uri;

	if (qhttp->modtokid == Qhdr_If_Modified_Since &&
	    sdate != -1 && qdate != -1 && sdate <= qdate) {
		/*
		 * Request is If-Modified-Since: and both response
		 * and request dates are valid and response is the
		 * same age as request so return a 304 response uri
		 * instead of the cached response.
		 */
		nl7c_http_cond_304++;
		uri = http_mkresponse(req, res, http_resp_304,
		    sizeof (http_resp_304) - 1);
		if (uri != NULL) {
			/* New response uri */
			REF_RELE(res);
			return (uri);
		}
		return (res);
	} else if (qhttp->modtokid == Qhdr_If_Unmodified_Since &&
	    sdate != -1 && qdate != -1 && sdate >= qdate) {
		/*
		 * Request is If-Unmodified-Since: and both response
		 * and request dates are valid and response is not the
		 * same age as the request so return a 412 response
		 * uri instead of the cached response.
		 */
		nl7c_http_cond_412++;
		uri = http_mkresponse(req, res, http_resp_412,
		    sizeof (http_resp_412) - 1);
		if (uri != NULL) {
			/* New response uri */
			REF_RELE(res);
			return (uri);
		}
		return (res);
	}
	/*
	 * No conditional response meet or unknown type or no
	 * valid dates so just return the original uri response.
	 */
	return (res);
}

/*
 * Return the appropriate HTTP connection persist header
 * based on the request HTTP persistent header state.
 */

mblk_t *
nl7c_http_persist(struct sonode *so)
{
	uint64_t	flags = SOTOTPI(so)->sti_nl7c_flags & NL7C_SCHEMEPRIV;
	mblk_t		*mp;

	if (flags & HTTP_CONN_CL)
		mp = dupb(http_conn_cl);
	else if (flags & HTTP_CONN_KA)
		mp = dupb(http_conn_ka);
	else
		mp = NULL;
	return (mp);
}

/*
 * Parse the buffer *p of size len and update the uri_desc_t *uri and our
 * http_t *http with the results.
 */

boolean_t
nl7c_http_request(char **cpp, char *ep, uri_desc_t *uri, struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);
	http_t	*http = kmem_cache_alloc(http_kmc, KM_SLEEP);
	char	*cp = *cpp;
	char	*hp;
	char	*scp, *sep;
	char	*HTTP = "HTTP/";
	token_t	*match;
	boolean_t persist = B_FALSE;

	ASSERT(cp <= ep);

	if (cp == ep) {
		goto bad;
	}
	/*
	 * Initialize any uri_desc_t and/or http_t members.
	 */
	uri->scheme = (void *)http;
	uri->auth.cp = NULL;
	uri->auth.ep = NULL;
	uri->resplen = URI_LEN_NOVALUE;
	uri->respclen = URI_LEN_NOVALUE;
	uri->eoh = NULL;
	uri->nocache = B_FALSE;
	uri->conditional = B_FALSE;
	http->parsed = B_FALSE;
	http->accept.cp = NULL;
	http->acceptchar.cp = NULL;
	http->acceptenco.cp = NULL;
	http->acceptlang.cp = NULL;
	http->etag.cp = NULL;
	http->uagent.cp = NULL;
	http->date = -1;
	http->expire = -1;
	http->lastmod = -1;
	if (*cp == '\r') {
		/*
		 * Special case for a Request-Line without an HTTP version,
		 * assume it's an old style, i.e. HTTP version 0.9 request.
		 */
		http->major = 0;
		http->minor = 9;
		goto got_version;
	}
	/*
	 * Skip URI path delimiter, must be a <SP>.
	 */
	if (*cp++ != ' ')
		/* Unkown or bad Request-Line format, just punt */
		goto bad;
	/*
	 * The URI parser has parsed through the URI and the <SP>
	 * delimiter, parse the HTTP/N.N version
	 */
	while (cp < ep && *HTTP == *cp) {
		HTTP++;
		cp++;
	}
	if (*HTTP != 0) {
		if (cp == ep)
			goto more;
		goto bad;
	}
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto bad;
	http->major = *cp++ - '0';
	if (cp == ep)
		goto more;
	if (*cp++ != '.')
		goto bad;
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto bad;
	http->minor = *cp++ - '0';
	if (cp == ep)
		goto more;

got_version:

	if (*cp++ != '\r')
		goto bad;
	if (cp == ep)
		goto more;
	if (*cp++ != '\n')
		goto bad;
	/*
	 * Initialize persistent state based on HTTP version.
	 */
	if (http->major == 1) {
		if (http->minor >= 1) {
			/* 1.1 persistent by default */
			persist = B_TRUE;
		} else {
			/* 1.0 isn't persistent by default */
			persist = B_FALSE;
		}
	} else if (http->major == 0) {
		/* Before 1.0 no persistent connections */
		persist = B_FALSE;
	} else {
		/* >= 2.0 not supported (yet) */
		goto bad;
	}
	/*
	 * Parse HTTP headers through the EOH
	 * (End Of Header, i.e. an empty line).
	 */
	for (sep = ep; cp < ep; ep = sep) {
		/* Get the next line */
		scp = cp;
		match = ttree_line_parse(req_tree, &cp, &ep, &hp, &uri->hvalue);
		if (match != NULL) {
			if (match->act & QUALIFIER) {
				/*
				 * Header field text is used to qualify this
				 * request/response, based on qualifier type
				 * optionally convert and store *http.
				 */
				char	c;
				int	n = 0;
				time_t	secs;

				ASSERT(hp != NULL && ep != NULL);

				if (match->act & NUMERIC) {
					while (hp < ep) {
						c = *hp++;
						if (! isdigit(c))
							goto bad;
						n *= 10;
						n += c - '0';
					}
				} else if (match->act & DATE) {
					secs = http_date2time_t(hp, ep);
				}
				switch (match->tokid) {

				case Qhdr_Accept_Charset:
					http->acceptchar.cp = hp;
					http->acceptchar.ep = ep;
					break;

				case Qhdr_Accept_Encoding:
					http->acceptenco.cp = hp;
					http->acceptenco.ep = ep;
					break;

				case Qhdr_Accept_Language:
					http->acceptlang.cp = hp;
					http->acceptlang.ep = ep;
					break;

				case Qhdr_Accept:
					http->accept.cp = hp;
					http->accept.ep = ep;
					break;

				case Qhdr_Authorization:
					goto pass;

				case Qhdr_Connection_close:
					persist = B_FALSE;
					break;

				case Qhdr_Connection_Keep_Alive:
					persist = B_TRUE;
					break;

				case Qhdr_Date:
					http->date = secs;
					break;

				case Qhdr_ETag:
					http->etag.cp = hp;
					http->etag.ep = ep;
					break;

				case Qhdr_Host:
					uri->auth.cp = hp;
					uri->auth.ep = ep;
					break;

				case Qhdr_If_Modified_Since:
				case Qhdr_If_Unmodified_Since:
					http->moddate = secs;
					http->modtokid = match->tokid;
					uri->conditional = B_TRUE;
					break;

				case Qhdr_Keep_Alive:
					persist = B_TRUE;
					break;

				case Qhdr_User_Agent:
					http->uagent.cp = hp;
					http->uagent.ep = ep;
					break;

				default:
					break;

				};
			}
			if (match->act & FILTER) {
				/*
				 * Filter header, do a copyover the header
				 * text, guarenteed to be at least 1 byte.
				 */
				char	*cop = scp;
				int	n = (ep - cop) - 1;
				char	filter[] = "NL7C-Filtered";

				n = MIN(n, sizeof (filter) - 1);
				if (n > 0)
					bcopy(filter, cop, n);
				cop += n;
				ASSERT(cop < ep);
				*cop++ = ':';
				while (cop < ep)
					*cop++ = ' ';
			}
			if (match->act & NOCACHE) {
				uri->nocache = B_TRUE;
			}
		} else if (hp == NULL) {
			goto done;
		} else if (ep == NULL) {
			goto more;
		}
	}
	/* No EOH found */
	goto more;

done:
	/*
	 * Initialize socket persist state and response persist type
	 * flag based on the persist state of the request headers.
	 *
	 */
	if (persist)
		sti->sti_nl7c_flags |= NL7C_SOPERSIST;
	else
		sti->sti_nl7c_flags &= ~NL7C_SOPERSIST;

	if (http->major == 1) {
		sti->sti_nl7c_flags &= ~NL7C_SCHEMEPRIV;
		if (http->minor >= 1) {
			if (! persist)
				sti->sti_nl7c_flags |= HTTP_CONN_CL;
		} else {
			if (persist)
				sti->sti_nl7c_flags |= HTTP_CONN_KA;
			else
				sti->sti_nl7c_flags |= HTTP_CONN_CL;
		}
	}
	/*
	 * Last, update parse consumed text pointer.
	 */
	*cpp = cp;
	return (B_TRUE);

pass:
	*cpp = NULL;
	return (B_TRUE);

bad:
	*cpp = NULL;
more:
	return (B_FALSE);
}

boolean_t
nl7c_http_response(char **cpp, char *ep, uri_desc_t *uri, struct sonode *so)
{
	sotpi_info_t *sti = SOTOTPI(so);
	http_t	*http = uri->scheme;
	char	*cp = *cpp;
	char	*hp;
	char	*scp, *sep;
	char	*HTTP = "HTTP/";
	int	status = 0;
	token_t	*match;
#ifdef	NOT_YET
	uint32_t major, minor;
#endif
	boolean_t nocache = B_FALSE;
	boolean_t persist = B_FALSE;

	ASSERT(http != NULL);

	if (http->parsed) {
		if (uri->respclen != URI_LEN_NOVALUE) {
			/* Chunked response */
			sep = ep;
			goto chunked;
		}
		/* Already parsed, nothing todo */
		return (B_TRUE);
	}

	/*
	 * Parse the HTTP/N.N version. Note, there's currently no use
	 * for the actual response major nor minor values as only the
	 * request values are used.
	 */
	while (cp < ep && *HTTP == *cp) {
		HTTP++;
		cp++;
	}
	if (*HTTP != 0) {
		if (cp == ep)
			goto more;
		goto bad;
	}
	if (cp == ep)
		goto more;

	if (*cp < '0' || *cp > '9')
		goto bad;
#ifdef	NOT_YET
	major = *cp++ - '0';
#else
	cp++;
#endif

	if (cp == ep)
		goto more;
	if (*cp++ != '.')
		goto bad;
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto bad;
#ifdef	NOT_YET
	minor = *cp++ - '0';
#else
	cp++;
#endif

	if (cp == ep)
		goto more;

got_version:

	/*
	 * Get the response code.
	 */
	if (*cp++ != ' ')
		goto bad;
	if (cp == ep)
		goto more;

	do {
		if (*cp == ' ')
			break;
		if (*cp < '0' || *cp > '9')
			goto bad;
		if (status)
			status *= 10;
		status += *cp++ - '0';
	} while (cp < ep);

	switch (status) {
	case 200:
		/*
		 * The only response status we continue to process.
		 */
		break;
	case 304:
		nl7c_http_response_304++;
		nocache = B_TRUE;
		uri->resplen = 0;
		goto pass;
	case 307:
		nl7c_http_response_307++;
		nocache = B_TRUE;
		uri->resplen = 0;
		goto pass;
	case 400:
		nl7c_http_response_400++;
		/*
		 * Special case some response status codes, just mark
		 * as nocache and no response length and pass on the
		 * request/connection.
		 */
		nocache = B_TRUE;
		uri->resplen = 0;
		goto pass;
	default:
		/*
		 * All other response codes result in a parse failure.
		 */
		goto bad;
	}

	/*
	 * Initialize persistent state based on request HTTP version.
	 */
	if (http->major == 1) {
		if (http->minor >= 1) {
			/* 1.1 persistent by default */
			persist = B_TRUE;
		} else {
			/* 1.0 isn't persistent by default */
			persist = B_FALSE;
		}
	} else if (http->major == 0) {
		/* Before 1.0 no persistent connections */
		persist = B_FALSE;
	} else {
		/* >= 2.0 not supported (yet) */
		goto bad;
	}

	/*
	 * Parse HTTP headers through the EOH
	 * (End Of Header, i.e. an empty line).
	 */
	for (sep = ep; cp < ep; ep = sep) {
		/* Get the next line */
		scp = cp;
		match = ttree_line_parse(res_tree, &cp, &ep, &hp, NULL);
		if (match != NULL) {
			if (match->act & QUALIFIER) {
				/*
				 * Header field text is used to qualify this
				 * request/response, based on qualifier type
				 * optionally convert and store *http.
				 */
				char	c;
				int	n = 0;
				time_t	secs;

				ASSERT(hp != NULL && ep != NULL);

				if (match->act & NUMERIC) {
					while (hp < ep) {
						c = *hp++;
						if (match->act & HEX) {
							hd2i(c, n);
							if (n == -1)
								goto bad;
						} else {
							if (! isdigit(c))
								goto bad;
							n *= 10;
							n += c - '0';
						}
					}
				} else if (match->act & DATE) {
					secs = http_date2time_t(hp, ep);
				}
				switch (match->tokid) {

				case Shdr_Cache_Control_Max_Age:
					break;

				case Shdr_Cache_Control_No_Cache:
					nocache = B_TRUE;
					break;

				case Shdr_Cache_Control_No_Store:
					nocache = B_TRUE;
					break;

				case Shdr_Connection_close:
					persist = B_FALSE;
					break;

				case Shdr_Connection_Keep_Alive:
					persist = B_TRUE;
					break;

				case Shdr_Chunked:
					uri->respclen = 0;
					uri->resplen = 0;
					nl7c_http_response_chunked++;
					break;

				case Shdr_Content_Length:
					if (uri->respclen == URI_LEN_NOVALUE)
						uri->resplen = n;
					break;

				case Shdr_Date:
					http->date = secs;
					break;

				case Shdr_ETag:
					http->etag.cp = hp;
					http->etag.ep = ep;
					break;

				case Shdr_Expires:
					http->expire = secs;
					break;

				case Shdr_Keep_Alive:
					persist = B_TRUE;
					break;

				case Shdr_Last_Modified:
					http->lastmod = secs;
					break;

				case Shdr_Set_Cookie:
					nocache = B_TRUE;
					break;

				case Shdr_Server:
					break;

				default:
					nocache = B_TRUE;
					break;
				};
			}
			if (match->act & FILTER) {
				/*
				 * Filter header, do a copyover the header
				 * text, guarenteed to be at least 1 byte.
				 */
				char	*cop = scp;
				int	n = (ep - cop) - 1;
				char	filter[] = "NL7C-Filtered";

				n = MIN(n, sizeof (filter) - 1);
				if (n > 0)
					bcopy(filter, cop, n);
				cop += n;
				ASSERT(cop < ep);
				*cop++ = ':';
				while (cop < ep)
					*cop++ = ' ';
			}
			if (match->act & NOCACHE) {
				nocache = B_TRUE;
			}
		} else if (hp == NULL) {
			uri->eoh = scp;
			goto done;
		} else if (ep == NULL) {
			goto more;
		}
	}
	/* No EOH found */
	goto more;

done:
	/* Parse completed */
	http->parsed = B_TRUE;
	/* Save the HTTP header length */
	http->headlen = (cp - *cpp);
	if (uri->respclen == URI_LEN_NOVALUE) {
		if (uri->resplen == URI_LEN_NOVALUE) {
			nl7c_http_response_pass1++;
			goto pass;
		}
	}
	/* Add header length to URI response length */
	uri->resplen += http->headlen;

	/* Set socket persist state */
	if (persist)
		sti->sti_nl7c_flags |= NL7C_SOPERSIST;
	else
		sti->sti_nl7c_flags &= ~NL7C_SOPERSIST;

	if (http->major == 1) {
		sti->sti_nl7c_flags &= ~NL7C_SCHEMEPRIV;
		if (http->minor >= 1) {
			if (! persist)
				sti->sti_nl7c_flags |= HTTP_CONN_CL;
		} else {
			if (persist)
				sti->sti_nl7c_flags |= HTTP_CONN_KA;
			else
				sti->sti_nl7c_flags |= HTTP_CONN_CL;
		}
	}

	if (nocache) {
		/*
		 * Response not to be cached, only post response
		 * processing code common to both non and cached
		 * cases above here and code for the cached case
		 * below.
		 *
		 * Note, chunked transfer processing is the last
		 * to be done.
		 */
		uri->nocache = B_TRUE;
		if (uri->respclen != URI_LEN_NOVALUE) {
			/* Chunked response */
			goto chunked;
		}
		/* Nothing more todo */
		goto parsed;
	}

	if (http->expire != -1 && http->date != -1) {
		if (http->expire <= http->date) {
			/* ??? just pass */
			nl7c_http_response_pass2++;
			goto pass;
		}
		/* Have a valid expire and date so calc an lbolt expire */
		uri->expire = ddi_get_lbolt() + SEC_TO_TICK(http->expire -
		    http->date);
	} else if (nl7c_uri_ttl != -1) {
		/* No valid expire speced and we have a TTL */
		uri->expire = ddi_get_lbolt() + SEC_TO_TICK(nl7c_uri_ttl);
	}

chunked:
	/*
	 * Chunk transfer parser and processing, a very simple parser
	 * is implemented here for the common case were one, or more,
	 * complete chunk(s) are passed in (i.e. length header + body).
	 *
	 * All other cases are passed.
	 */
	scp = cp;
	while (uri->respclen != URI_LEN_NOVALUE && cp < sep) {
		if (uri->respclen == URI_LEN_CONSUMED) {
			/* Skip trailing "\r\n" */
			if (cp == sep)
				goto more;
			if (*cp++ != '\r')
				goto bad;
			if (cp == sep)
				goto more;
			if (*cp++ != '\n')
				goto bad;
			uri->respclen = 0;
		}
		if (uri->respclen == 0) {
			/* Parse a chunklen "[0-9A-Fa-f]+" */
			char	c;
			int	n = 0;

			if (cp == sep)
				goto more;
			nl7c_http_response_chunkparse++;
			while (cp < sep && (c = *cp++) != '\r') {
				hd2i(c, n);
				if (n == -1)
					goto bad;
			}
			if (cp == sep)
				goto more;
			if (*cp++ != '\n')
				goto bad;
			uri->respclen = n;
			if (n == 0) {
				/* Last chunk, skip trailing "\r\n" */
				if (cp == sep)
					goto more;
				if (*cp++ != '\r')
					goto bad;
				if (cp == sep)
					goto more;
				if (*cp++ != '\n')
					goto bad;
				uri->respclen = URI_LEN_NOVALUE;
				break;
			}
		}
		if (uri->respclen > 0) {
			/* Consume some bytes for the current chunk */
			uint32_t sz = (sep - cp);

			if (sz > uri->respclen)
				sz = uri->respclen;
			uri->respclen -= sz;
			cp += sz;
			if (uri->respclen == 0) {
				/* End of chunk, skip trailing "\r\n" */
				if (cp == sep) {
					uri->respclen = URI_LEN_CONSUMED;
					goto more;
				}
				if (*cp++ != '\r')
					goto bad;
				if (cp == sep)
					goto more;
				if (*cp++ != '\n')
					goto bad;
				if (cp == sep)
					goto more;
			}
		}
	}
	uri->resplen += (cp - scp);

parsed:
	*cpp = cp;
	return (B_TRUE);

pass:
	*cpp = NULL;
	return (B_TRUE);

bad:
	*cpp = NULL;
	return (B_FALSE);

more:
	uri->resplen += (cp - scp);
	*cpp = cp;
	return (B_FALSE);
}

boolean_t
nl7c_http_log(uri_desc_t *quri, uri_desc_t *suri, nca_request_log_t *req,
    char **wp, char **pep, uint32_t *off)
{
	http_t	*qhttp = quri->scheme;
	http_t	*shttp = suri->scheme;
	int	sz;

	if (qhttp->uagent.cp != NULL) {
		sz = (qhttp->uagent.ep - qhttp->uagent.cp);
		if ((*wp + sz + 1) >= *pep) goto full;
		bcopy(qhttp->uagent.cp, *wp, sz);
		*wp += sz;
		*(*wp)++ = 0;
		sz++;
		req->useragent_len = sz;
		req->useragent = *off;
		*off += sz;
	}

	req->response_len -= (uint_t)shttp->headlen;

	req->method = NCA_GET;

	if (qhttp->major == 1) {
		if (qhttp->minor == 0) {
			req->version = HTTP_1_0;
		} else if (qhttp->minor == 1) {
			req->version = HTTP_1_1;
		} else {
			req->version = HTTP_0_0;
		}
	} else if (qhttp->major == 0) {
		req->version = HTTP_0_9;
	} else {
		req->version = HTTP_0_0;
	}

	return (B_FALSE);

full:
	return (B_TRUE);
}
