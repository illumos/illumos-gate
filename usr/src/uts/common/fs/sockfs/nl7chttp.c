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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/strsubr.h>
#include <sys/promif.h>
#include <fs/sockfs/nl7c.h>
#include <fs/sockfs/nl7curi.h>

#include <inet/nca/ncadoorhdr.h>
#include <inet/nca/ncalogd.h>

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
 * HTTP scheme private state:
 */

typedef struct http_s {
	boolean_t	parsed;		/* Response parsed */
	uint32_t	major, minor;	/* HTTP/major.minor */
	uint32_t	headlen;	/* HTTP header length */
	clock_t		date;		/* Response Date: */
	clock_t		expire;		/* Response Expire: */
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
	URIREL		= 0x0800
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
 * HTTP date routines:
 */

static char *dow[] = {"sunday", "monday", "tuesday", "wednesday", "thursday",
	"friday", "saturday", 0};

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
ttree_line_parse(ttree_t *t, char **cpp, char **epp, char **hpp, unsigned *hash)
{
	char	ca, cb;			/* current line <=> parse node */

	char	*cp = *cpp;
	char	*ep = *epp;
	unsigned hv = *hash;		/* hash value */

	char	*tp = t->tok->text;	/* current parse text */
	char	*sp = cp;		/* saved *cp */

	int	parse;			/* parse state */

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
			if (ca == '\r' || ca == '\n') {
				/* EOL, always go less than */
				t = t->lt;
			} else {
				/* Case insensitive */
				cb = tolower(cb);
				ca = tolower(ca);
				if (ca == cb) {
					/* Char match, next char */
					tp++;
					continue;
				}
				if (ca < cb) {
					/* Go less than */
					t = t->lt;
				} else {
					/* Go greater than */
					t = t->gt;
				}
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
			} else if (t != NULL && t->tok->act & HASH) {
				hv = hv * 33 + ca;
				hv &= 0xFFFFFF;
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
		if (t != NULL && t->tok->act & HASH)
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
 * Return the appropriate HTTP connection persist header
 * based on the request HTTP persistent header state.
 */

mblk_t *
nl7c_http_persist(struct sonode *so)
{
	uint64_t	flags = so->so_nl7c_flags & NL7C_SCHEMEPRIV;
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
	http_t	*http = kmem_cache_alloc(http_kmc, KM_SLEEP);
	char	*cp = *cpp;
	char	*hp;
	char	*sep;
	unsigned hash = 0;
	char	*HTTP = "HTTP/";
	token_t	*match;
	boolean_t persist = B_FALSE;

	ASSERT(cp <= ep);

	if (cp == ep) {
		goto pass;
	}
	/*
	 * Initialize any uri_desc_t and/or http_t members.
	 */
	uri->scheme = (void *)http;
	uri->auth.cp = NULL;
	uri->auth.ep = NULL;
	uri->resplen = -1;
	uri->eoh = NULL;
	uri->nocache = B_FALSE;
	http->parsed = B_FALSE;
	http->accept.cp = NULL;
	http->acceptchar.cp = NULL;
	http->acceptenco.cp = NULL;
	http->acceptlang.cp = NULL;
	http->etag.cp = NULL;
	http->uagent.cp = NULL;
	http->date = -1;
	http->expire = -1;
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
		goto pass;
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
		goto pass;
	}
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto pass;
	http->major = *cp++ - '0';
	if (cp == ep)
		goto more;
	if (*cp++ != '.')
		goto pass;
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto pass;
	http->minor = *cp++ - '0';
	if (cp == ep)
		goto more;

got_version:

	if (*cp++ != '\r')
		goto pass;
	if (cp == ep)
		goto more;
	if (*cp++ != '\n')
		goto pass;
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
		goto pass;
	}
	/*
	 * Parse HTTP headers through the EOH
	 * (End Of Header, i.e. an empty line).
	 */
	for (sep = ep; cp < ep; ep = sep) {
		/* Get the next line */
		match = ttree_line_parse(req_tree, &cp, &ep, &hp, &hash);
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
							goto pass;
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
					break;

				case Qhdr_If_Unmodified_Since:
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
		so->so_nl7c_flags |= NL7C_SOPERSIST;
	else
		so->so_nl7c_flags &= ~NL7C_SOPERSIST;

	if (http->major == 1) {
		if (http->minor >= 1) {
			if (! persist)
				so->so_nl7c_flags |= HTTP_CONN_CL;
		} else {
			if (persist)
				so->so_nl7c_flags |= HTTP_CONN_KA;
			else
				so->so_nl7c_flags |= HTTP_CONN_CL;
		}
	}
	/*
	 * Last, update parse consumed text pointer.
	 */
	*cpp = cp;
	return (B_TRUE);

pass:
	*cpp = NULL;
more:
	return (B_FALSE);
}

boolean_t
nl7c_http_response(char **cpp, char *ep, uri_desc_t *uri, struct sonode *so)
{
	http_t	*http = uri->scheme;
	char	*cp = *cpp;
	char	*hp;
	char	*scp, *sep;
	unsigned hash = 0;
	char	*HTTP = "HTTP/";
	int	status = 0;
	token_t	*match;
#ifdef	NOT_YET
	uint32_t major, minor;
#endif
	boolean_t nocache = B_FALSE;
	boolean_t persist = B_FALSE;

	ASSERT(http != NULL);

	if (http->parsed)
		return (B_TRUE);

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
		goto pass;
	}
	if (cp == ep)
		goto more;

	if (*cp < '0' || *cp > '9')
		goto pass;
#ifdef	NOT_YET
	major = *cp++ - '0';
#else
	cp++;
#endif

	if (cp == ep)
		goto more;
	if (*cp++ != '.')
		goto pass;
	if (cp == ep)
		goto more;
	if (*cp < '0' || *cp > '9')
		goto pass;
#ifdef	NOT_YET
	minor = *cp++ - '0';
#else
	cp++;
#endif

	if (cp == ep)
		goto more;

got_version:

	/*
	 * Get the response code, if not 200 then pass on this response.
	 */
	if (*cp++ != ' ')
		goto pass;
	if (cp == ep)
		goto more;

	do {
		if (*cp == ' ')
			break;
		if (*cp < '0' || *cp > '9')
			goto pass;
		if (status)
			status *= 10;
		status += *cp++ - '0';
	} while (cp < ep);

	if (status != 200)
		goto pass;

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
		goto pass;
	}

	/*
	 * Parse HTTP headers through the EOH
	 * (End Of Header, i.e. an empty line).
	 */
	for (sep = ep; cp < ep; ep = sep) {
		/* Get the next line */
		scp = cp;
		match = ttree_line_parse(res_tree, &cp, &ep, &hp, &hash);
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
							goto pass;
						n *= 10;
						n += c - '0';
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

				case Shdr_Content_Length:
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

				case Shdr_Set_Cookies:
					nocache = B_TRUE;

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
	http->parsed = B_TRUE;

	if (nocache) {
		uri->nocache = B_TRUE;
		goto pass;
	}
	if (uri->resplen == -1)
		goto pass;

	/* Save the HTTP header length and add to URI response length */
	http->headlen = (cp - *cpp);
	uri->resplen += http->headlen;

	/* Set socket persist state */
	if (persist)
		so->so_nl7c_flags |= NL7C_SOPERSIST;
	else
		so->so_nl7c_flags &= ~NL7C_SOPERSIST;

	if (http->expire != -1 && http->date != -1) {
		if (http->expire <= http->date) {
			/* No cache */
			goto pass;
		}
		/* Have a valid expire and date so calc an lbolt expire */
		uri->expire = lbolt + SEC_TO_TICK(http->expire - http->date);
	} else if (nl7c_uri_ttl != -1) {
		/* No valid expire speced and we have a TTL */
		uri->expire = lbolt + SEC_TO_TICK(nl7c_uri_ttl);
	}

	*cpp = cp;
	return (B_TRUE);

pass:
	*cpp = NULL;
more:
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
