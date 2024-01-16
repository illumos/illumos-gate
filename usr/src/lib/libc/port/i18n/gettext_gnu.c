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

#include "lint.h"
#include "mtlib.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <thread.h>
#include <synch.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <inttypes.h>
#include "libc.h"
#include "msgfmt.h"
#include "nlspath_checks.h"
#include "gettext.h"

/* The following symbols are just for GNU binary compatibility */
int	_nl_msg_cat_cntr;
int	*_nl_domain_bindings;

static const char	*nullstr = "";

#define	CHARSET_MOD	"charset="
#define	CHARSET_LEN	(sizeof (CHARSET_MOD) - 1)
#define	NPLURALS_MOD	"nplurals="
#define	NPLURALS_LEN	(sizeof (NPLURALS_MOD) - 1)
#define	PLURAL_MOD	"plural="
#define	PLURAL_LEN	(sizeof (PLURAL_MOD) - 1)

static uint32_t	get_hash_index(uint32_t *, uint32_t, uint32_t);

/*
 * free_conv_msgstr
 *
 * release the memory allocated for storing code-converted messages
 *
 * f
 *	0:	do not free gmnp->conv_msgstr
 *	1:	free gmnp->conv_msgstr
 */
static void
free_conv_msgstr(Msg_g_node *gmnp, int f)
{
	uint32_t	i, num_of_conv;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** free_conv_msgstr(0x%p, %d)\n",
	    (void *)gmnp, f);
	printgnumsg(gmnp, 1);
#endif

	num_of_conv = gmnp->num_of_str + gmnp->num_of_d_str;
	for (i = 0; i < num_of_conv; i++) {
		if (gmnp->conv_msgstr[i]) {
			free(gmnp->conv_msgstr[i]);
		}
		gmnp->conv_msgstr[i] = NULL;
	}
	if (f) {
		free(gmnp->conv_msgstr);
		gmnp->conv_msgstr = NULL;
	}
}

/*
 * dfltmsgstr
 *
 * choose an appropriate message by evaluating the plural expression,
 * and return it.
 */
static char *
dfltmsgstr(Msg_g_node *gmnp, const char *msgstr, uint32_t msgstr_len,
    struct msg_pack *mp)
{
	unsigned int	pindex;
	size_t	len;
	const char	*p;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** dfltmsgstr(0x%p, \"%s\", %u, 0x%p)\n",
	    (void *)gmnp,
	    msgstr ? msgstr : "(null)", msgstr_len, (void *)mp);
	printgnumsg(gmnp, 1);
	printmp(mp, 1);
#endif

	if (mp->plural) {
		if (gmnp->plural) {
			pindex = plural_eval(gmnp->plural, mp->n);
		} else {
			/*
			 * This mo does not have plural information.
			 * Using the English form.
			 */
			if (mp->n == 1)
				pindex = 0;
			else
				pindex = 1;
		}
#ifdef GETTEXT_DEBUG
		gprintf(0, "plural_eval returned: %u\n", pindex);
#endif
		if (pindex >= gmnp->nplurals) {
			/* should never happen */
			pindex = 0;
		}
		p = msgstr;
		for (; pindex != 0; pindex--) {
			len = msgstr_len - (p - msgstr);
			p = memchr(p, '\0', len);
			if (p == NULL) {
				/*
				 * null byte not found
				 * this should never happen
				 */
				char	*result;
				DFLTMSG(result, mp->msgid1, mp->msgid2,
				    mp->n, mp->plural);
				return (result);
			}
			p++;		/* skip */
		}
		return ((char *)p);
	}

	return ((char *)msgstr);
}

/*
 * parse_header
 *
 * parse the header entry of the GNU MO file and
 * extract the src encoding and the plural information of the MO file
 */
static int
parse_header(const char *header, Msg_g_node *gmnp)
{
	char	*charset = NULL;
	char	*charset_str;
	size_t	len;
	char	*nplurals_str, *plural_str;
	plural_expr_t	plural;
	char	*p, *q;
	unsigned int	nplurals;
	int	ret;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** parse_header(\"%s\", 0x%p)\n",
	    header ? header : "(null)", (void *)gmnp);
	printgnumsg(gmnp, 1);
#endif

	if (header == NULL) {
		gmnp->src_encoding = (char *)nullstr;
		gmnp->nplurals = 2;
		gmnp->plural = NULL;
#ifdef GETTEXT_DEBUG
		gprintf(0, "*************** exiting parse_header\n");
		gprintf(0, "no header\n");
#endif

		return (0);
	}

	charset_str = strstr(header, CHARSET_MOD);
	if (charset_str == NULL) {
		gmnp->src_encoding = (char *)nullstr;
	} else {
		p = charset_str + CHARSET_LEN;
		q = p;
		while ((*q != ' ') && (*q != '\t') &&
		    (*q != '\n')) {
			q++;
		}
		len = q - p;
		if (len > 0) {
			charset = malloc(len + 1);
			if (charset == NULL) {
				gmnp->src_encoding = (char *)nullstr;
				gmnp->nplurals = 2;
				gmnp->plural = NULL;
				return (-1);
			}
			(void) memcpy(charset, p, len);
			charset[len] = '\0';
			gmnp->src_encoding = charset;
		} else {
			gmnp->src_encoding = (char *)nullstr;
		}
	}

	nplurals_str = strstr(header, NPLURALS_MOD);
	plural_str = strstr(header, PLURAL_MOD);
	if (nplurals_str == NULL || plural_str == NULL) {
		/* no valid plural specification */
		gmnp->nplurals = 2;
		gmnp->plural = NULL;
#ifdef GETTEXT_DEBUG
		gprintf(0, "*************** exiting parse_header\n");
		gprintf(0, "no plural entry\n");
#endif
		return (0);
	} else {
		p = nplurals_str + NPLURALS_LEN;
		while (*p && isspace((unsigned char)*p)) {
			p++;
		}
		nplurals = (unsigned int)strtol(p, &q, 10);
		if (p != q) {
			gmnp->nplurals = nplurals;
		} else {
			gmnp->nplurals = 2;
		}

		p = plural_str + PLURAL_LEN;
#ifdef GETTEXT_DEBUG
		gprintf(0, "plural_str: \"%s\"\n", p);
#endif

		ret = plural_expr(&plural, (const char *)p);
		if (ret == 0) {
			/* parse succeeded */
			gmnp->plural = plural;
#ifdef GETTEXT_DEBUG
		gprintf(0, "*************** exiting parse_header\n");
		gprintf(0, "charset: \"%s\"\n",
		    charset ? charset : "(null)");
		printexpr(plural, 1);
#endif
			return (0);
		} else if (ret == 1) {
			/* parse error */
			gmnp->nplurals = 2;
			gmnp->plural = NULL;
			return (0);
		} else {
			/* fatal error */
			if (charset)
				free(charset);
			gmnp->src_encoding = (char *)nullstr;
			gmnp->nplurals = 2;
			gmnp->plural = NULL;
			return (-1);
		}
	}
	/* NOTREACHED */
}

/*
 * handle_lang
 *
 * take care of the LANGUAGE specification
 */
char *
handle_lang(struct msg_pack *mp)
{
	const char	*p, *op, *q;
	size_t	locale_len;
	char	*result;
	char	locale[MAXPATHLEN];


#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** handle_lang(0x%p)\n", (void *)mp);
	printmp(mp, 1);
#endif

	p = mp->language;

	while (*p) {
		op = p;
		q = strchr(p, ':');
		if (q == NULL) {
			locale_len = strlen(p);
			p += locale_len;
		} else {
			locale_len = q - p;
			p += locale_len + 1;
		}
		if (locale_len >= MAXPATHLEN || locale_len == 0) {
			/* illegal locale name */
			continue;
		}
		(void) memcpy(locale, op, locale_len);
		locale[locale_len] = '\0';
		mp->locale = locale;

#ifdef GETTEXT_DEBUG
		*mp->msgfile = '\0';
#endif
		if (mk_msgfile(mp) == NULL) {
			/* illegal locale name */
			continue;
		}

		result = handle_mo(mp);
		if (mp->status & ST_GNU_MSG_FOUND)
			return (result);

		if (mp->status & ST_SUN_MO_FOUND)
			break;
	}

	/*
	 * no valid locale found, Sun MO found, or
	 * GNU MO found but no valid msg found there.
	 */

	if (mp->status & ST_GNU_MO_FOUND) {
		/*
		 * GNU MO found but no valid msg found there.
		 * returning DFLTMSG.
		 */
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}
	return (NULL);
}

/*
 * gnu_msgsearch
 *
 * Searchs the translation message for the specified msgid1.
 * Hash algorithm used in this function is Open Addressing
 * with Double Hashing:
 * H(k, i) = (H1(k) + i * H2(k)) mod M
 * H1(k) = hashvalue % M
 * H2(k) = 1 + (hashvalue % (M - 2))
 *
 * Ref: The Art of Computer Programming Volume 3
 * Sorting and Searching, second edition
 * Donald E Knuth
 */
static char *
gnu_msgsearch(Msg_g_node *gmnp, const char *msgid1,
    uint32_t *msgstrlen, uint32_t *midx)
{
	struct gnu_msg_info	*header = gmnp->msg_file_info;
	struct gnu_msg_ent	*msgid_tbl, *msgstr_tbl;
	uint32_t	num_of_str, idx, mlen, msglen;
	uint32_t	hash_size, hash_val, hash_id, hash_inc, hash_idx;
	uint32_t	*hash_table;
	char	*base;
	char	*msg;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** gnu_msgsearch(0x%p, \"%s\", "
	    "0x%p, 0x%p)\n",
	    (void *)gmnp, msgid1, msgstrlen, midx);
	printgnumsg(gmnp, 1);
#endif

	base = (char *)header;

	msgid_tbl = gmnp->msg_tbl[MSGID];
	msgstr_tbl = gmnp->msg_tbl[MSGSTR];
	hash_table = gmnp->hash_table;
	hash_size = gmnp->hash_size;
	num_of_str = gmnp->num_of_str;

	if (!(gmnp->flag & ST_REV1) &&
	    (hash_table == NULL || (hash_size <= 2))) {
		/*
		 * Revision 0 and
		 * No hash table exists or
		 * hash size is enough small.
		 */
		uint32_t	top, bottom;
		char	*msg_id_str;
		int	val;

		top = 0;
		bottom = num_of_str;
		while (top < bottom) {
			idx = (top + bottom) / 2;
			msg_id_str = base +
			    SWAP(gmnp, msgid_tbl[idx].offset);

			val = strcmp(msg_id_str, msgid1);
			if (val < 0) {
				top = idx + 1;
			} else if (val > 0) {
				bottom = idx;
			} else {
				*msgstrlen = (unsigned int)
				    SWAP(gmnp, msgstr_tbl[idx].len) + 1;
				*midx = idx;
				return (base +
				    SWAP(gmnp, msgstr_tbl[idx].offset));
			}
		}
		/* not found */
		return ((char *)msgid1);
	}

	/* use hash table */
	hash_id = get_hashid(msgid1, &msglen);
	hash_idx = hash_id % hash_size;
	hash_inc = 1 + (hash_id % (hash_size - 2));

	for (;;) {
		hash_val = HASH_TBL(gmnp, hash_table[hash_idx]);

		if (hash_val == 0) {
			/* not found */
			return ((char *)msgid1);
		}
		if (hash_val <= num_of_str) {
			/* static message */
			idx = hash_val - 1;
			mlen = SWAP(gmnp, msgid_tbl[idx].len);
			msg = base + SWAP(gmnp, msgid_tbl[idx].offset);
		} else {
			if (!(gmnp->flag & ST_REV1)) {
				/* rev 0 does not have dynamic message */
				return ((char *)msgid1);
			}
			/* dynamic message */
			idx = hash_val - num_of_str - 1;
			mlen = gmnp->d_msg[MSGID][idx].len;
			msg = gmnp->mchunk + gmnp->d_msg[MSGID][idx].offset;
		}
		if (msglen <= mlen && strcmp(msgid1, msg) == 0) {
			/* found */
			break;
		}
		hash_idx = (hash_idx + hash_inc) % hash_size;
	}

	/* msgstrlen should include a null termination */
	if (hash_val <= num_of_str) {
		*msgstrlen = SWAP(gmnp, msgstr_tbl[idx].len) + 1;
		msg = base + SWAP(gmnp, msgstr_tbl[idx].offset);
		*midx = idx;
	} else {
		*msgstrlen = gmnp->d_msg[MSGSTR][idx].len + 1;
		msg = gmnp->mchunk + gmnp->d_msg[MSGSTR][idx].offset;
		*midx = idx + num_of_str;
	}

	return (msg);
}

/*
 * do_conv
 *
 * Converts the specified string from the src encoding
 * to the dst encoding by calling iconv()
 */
static uint32_t *
do_conv(iconv_t fd, const char *src, uint32_t srclen)
{
	uint32_t	tolen;
	uint32_t	*ptr, *optr;
	size_t	oleft, ileft, bufsize, memincr;
	char	*to, *tptr;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** do_conv("
	    "0x%p, \"%s\", %d)\n",
	    (void *)fd, src ? src : "(null)", srclen);
#endif

	memincr = srclen * 2;
	bufsize = memincr;
	ileft = srclen;
	oleft = bufsize;
	ptr = malloc(bufsize + sizeof (uint32_t));
	if (ptr == NULL) {
		return (NULL);
	}
	to = (char *)(ptr + 1);

	for (;;) {
		tptr = to;
		errno = 0;
#ifdef GETTEXT_DEBUG
		gprintf(0, "******* calling iconv()\n");
#endif
		if (iconv(fd, &src, &ileft, &tptr, &oleft) == (size_t)-1) {
			if (errno == E2BIG) {
#ifdef GETTEXT_DEBUG
				gprintf(0, "******* iconv detected E2BIG\n");
				gprintf(0, "old bufsize: %u\n", bufsize);
#endif

				optr = realloc(ptr,
				    bufsize + memincr + sizeof (uint32_t));
				if (optr == NULL) {
					free(ptr);
					return (NULL);
				}
				ptr = optr;
				to = (char *)(optr + 1);
				to += bufsize - oleft;
				oleft += memincr;
				bufsize += memincr;
#ifdef GETTEXT_DEBUG
				gprintf(0, "new bufsize: %u\n", bufsize);
#endif
				continue;
			} else {
				tolen = (uint32_t)(bufsize - oleft);
				break;
			}
		}
		tolen = (uint32_t)(bufsize - oleft);
		break;
	}

	if (tolen < bufsize) {
		/* shrink the buffer */
		optr = realloc(ptr, tolen + sizeof (uint32_t));
		if (optr == NULL) {
			free(ptr);
			return (NULL);
		}
		ptr = optr;
	}
	*ptr = tolen;

#ifdef GETTEXT_DEBUG
	gprintf(0, "******* exiting do_conv()\n");
	gprintf(0, "tolen: %u\n", *ptr);
	gprintf(0, "return: 0x%p\n", ptr);
#endif
	return (ptr);
}

/*
 * conv_msg
 */
static char *
conv_msg(Msg_g_node *gmnp, char *msgstr, uint32_t msgstr_len, uint32_t midx,
    struct msg_pack *mp)
{
	uint32_t	*conv_dst;
	size_t	num_of_conv, conv_msgstr_len;
	char	*conv_msgstr, *result;

	if (gmnp->conv_msgstr == NULL) {
		num_of_conv = gmnp->num_of_str + gmnp->num_of_d_str;
		gmnp->conv_msgstr =
		    calloc((size_t)num_of_conv, sizeof (uint32_t *));
		if (gmnp->conv_msgstr == NULL) {
			/* malloc failed */
			result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
			return (result);
		}
	}

	conv_dst = do_conv(gmnp->fd, (const char *)msgstr, msgstr_len);

	if (conv_dst == NULL) {
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	conv_msgstr_len = *conv_dst;
	gmnp->conv_msgstr[midx] = conv_dst;
	conv_msgstr = (char *)(conv_dst + 1);
	result = dfltmsgstr(gmnp, conv_msgstr, conv_msgstr_len, mp);
	return (result);
}

/*
 * gnu_key_2_text
 *
 * Extracts msgstr from the GNU MO file
 */
char *
gnu_key_2_text(Msg_g_node *gmnp, const char *codeset,
    struct msg_pack *mp)
{
	uint32_t	msgstr_len, midx;
	iconv_t	fd;
	char	*result, *msgstr;
	int	ret, conversion, new_encoding;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** gnu_key_2_text("
	    "0x%p, \"%s\", 0x%p)\n",
	    (void *)gmnp, codeset ? codeset : "(null)", (void *)mp);
	printgnumsg(gmnp, 1);
	printmp(mp, 1);
#endif

	/* first checks if header entry has been processed */
	if (!(gmnp->flag & ST_CHK)) {
		char	*msg_header;

		msg_header = gnu_msgsearch(gmnp, "", &msgstr_len, &midx);
		ret = parse_header((const char *)msg_header, gmnp);
		if (ret == -1) {
			/* fatal error */
			DFLTMSG(result, mp->msgid1, mp->msgid2,
			    mp->n, mp->plural);
			return (result);
		}
		gmnp->flag |= ST_CHK;
	}
	msgstr = gnu_msgsearch(gmnp, mp->msgid1, &msgstr_len, &midx);
	if (msgstr == mp->msgid1) {
		/* not found */
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		return (result);
	}

#ifdef GETTEXT_DEBUG
	printgnumsg(gmnp, 1);
#endif
	if (gmnp->dst_encoding == NULL) {
		/*
		 * destination encoding has not been set.
		 */
		char	*dupcodeset = strdup(codeset);
		if (dupcodeset == NULL) {
			/* strdup failed */
			result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
			return (result);
		}
		gmnp->dst_encoding = dupcodeset;

		if (strcmp(gmnp->dst_encoding, gmnp->src_encoding) == 0) {
			/*
			 * target encoding and src encoding
			 * are the same.
			 * No conversion required.
			 */
			conversion = 0;
		} else {
			/*
			 * target encoding is different from
			 * src encoding.
			 * New conversion required.
			 */
			/* sanity check */
			if (gmnp->fd && (gmnp->fd != (iconv_t)-1)) {
				(void) iconv_close(gmnp->fd);
				gmnp->fd = (iconv_t)-1;
			}
			if (gmnp->conv_msgstr)
				free_conv_msgstr(gmnp, 0);
			conversion = 1;
			new_encoding = 1;
		}
	} else {
		/*
		 * dst encoding has been already set.
		 */
		if (strcmp(gmnp->dst_encoding, codeset) == 0) {
			/*
			 * dst encoding and target encoding are the same.
			 */
			if (strcmp(gmnp->dst_encoding, gmnp->src_encoding)
			    == 0) {
				/*
				 * dst encoding and src encoding are the same.
				 * No conversion required.
				 */
				conversion = 0;
			} else {
				/*
				 * dst encoding is different from src encoding.
				 * current conversion is valid.
				 */
				conversion = 1;
				new_encoding = 0;
				/* checks if iconv_open has succeeded before */
				if (gmnp->fd == (iconv_t)-1) {
					/*
					 * iconv_open should have failed before
					 * Assume this conversion is invalid
					 */
					conversion = 0;
				} else {
					if (gmnp->conv_msgstr == NULL) {
						/*
						 * memory allocation for
						 * conv_msgstr should
						 * have failed before.
						 */
						new_encoding = 1;
						if (gmnp->fd)
							(void) iconv_close(
							    gmnp->fd);
						gmnp->fd = (iconv_t)-1;
					}
				}
			}
		} else {
			/*
			 * dst encoding is different from target encoding.
			 * It has changed since before.
			 */
			char	*dupcodeset = strdup(codeset);
			if (dupcodeset == NULL) {
				result = dfltmsgstr(gmnp, msgstr,
				    msgstr_len, mp);
				return (result);
			}
			free(gmnp->dst_encoding);
			gmnp->dst_encoding = dupcodeset;
			if (strcmp(gmnp->dst_encoding, gmnp->src_encoding)
			    == 0) {
				/*
				 * dst encoding and src encoding are the same.
				 * now, no conversion required.
				 */
				conversion = 0;
				if (gmnp->conv_msgstr)
					free_conv_msgstr(gmnp, 1);
			} else {
				/*
				 * dst encoding is different from src encoding.
				 * new conversion required.
				 */
				conversion = 1;
				new_encoding = 1;
				if (gmnp->conv_msgstr)
					free_conv_msgstr(gmnp, 0);
			}

			if (gmnp->fd && (gmnp->fd != (iconv_t)-1)) {
				(void) iconv_close(gmnp->fd);
			}
			if (gmnp->fd != (iconv_t)-1) {
				gmnp->fd = (iconv_t)-1;
			}
		}
	}

	if (conversion == 0) {
		/* no conversion */
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	/* conversion required */

	if (new_encoding == 0) {
		/* dst codeset hasn't been changed since before */
		uint32_t	*cmsg;
		uint32_t	conv_msgstr_len;
		char	*conv_msgstr;

		if (gmnp->conv_msgstr[midx] == NULL) {
			/* this msgstr hasn't been converted yet */
			result = conv_msg(gmnp, msgstr, msgstr_len, midx, mp);
			return (result);
		}
		/* this msgstr is in the conversion cache */
		cmsg = (uint32_t *)(uintptr_t)gmnp->conv_msgstr[midx];
		conv_msgstr_len = *cmsg;
		conv_msgstr = (char *)(cmsg + 1);
		result = dfltmsgstr(gmnp, conv_msgstr, conv_msgstr_len, mp);
		return (result);
	}
	/* new conversion */
#ifdef GETTEXT_DEBUG
	gprintf(0, "******* calling iconv_open()\n");
	gprintf(0, "      dst: \"%s\", src: \"%s\"\n",
	    gmnp->dst_encoding, gmnp->src_encoding);
#endif
	fd = iconv_open(gmnp->dst_encoding, gmnp->src_encoding);
	gmnp->fd = fd;
	if (fd == (iconv_t)-1) {
		/*
		 * iconv_open() failed.
		 * no conversion
		 */
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	result = conv_msg(gmnp, msgstr, msgstr_len, midx, mp);
	return (result);
}


#define	PRI_STR(x, n)	PRI##x##n
#define	PRI_LEN(x, n)	(char)(sizeof (PRI_STR(x, n)) - 1)
#define	PRIS(P, x)	{\
/* x/N/ */	P(x, 8), P(x, 16), P(x, 32), P(x, 64), \
/* xLEAST/N/ */	P(x, LEAST8), P(x, LEAST16), P(x, LEAST32), P(x, LEAST64), \
/* xFAST/N/ */	P(x, FAST8), P(x, FAST16), P(x, FAST32), P(x, FAST64), \
/* xMAX,PTR */	P(x, MAX), P(x, PTR) \
}

#define	PRI_BIAS_LEAST	4
#define	PRI_BIAS_FAST	8
#define	PRI_BIAS_MAX	12
#define	PRI_BIAS_PTR	13

static const char	*pri_d[] = PRIS(PRI_STR, d);
static const char	*pri_i[] = PRIS(PRI_STR, i);
static const char	*pri_o[] = PRIS(PRI_STR, o);
static const char	*pri_u[] = PRIS(PRI_STR, u);
static const char	*pri_x[] = PRIS(PRI_STR, x);
static const char	*pri_X[] = PRIS(PRI_STR, X);

static const char	pri_d_len[] = PRIS(PRI_LEN, d);
static const char	pri_i_len[] = PRIS(PRI_LEN, i);
static const char	pri_o_len[] = PRIS(PRI_LEN, o);
static const char	pri_u_len[] = PRIS(PRI_LEN, u);
static const char	pri_x_len[] = PRIS(PRI_LEN, x);
static const char	pri_X_len[] = PRIS(PRI_LEN, X);

static struct {
	const char	type;
	const char	**str_table;
	const char	*len_table;
} pri_table[] = {
	{'d', pri_d, pri_d_len}, {'i', pri_i, pri_i_len},
	{'o', pri_o, pri_o_len}, {'u', pri_u, pri_u_len},
	{'x', pri_x, pri_x_len}, {'X', pri_X, pri_X_len},
};

static struct {
	const char	*name;
	const char	nlen;
	const char	want_digits;
	const char	bias;
} special_table[] = {
	{"LEAST",	5, 1, PRI_BIAS_LEAST},
	{"FAST",	4, 1, PRI_BIAS_FAST},
	{"MAX",		3, 0, PRI_BIAS_MAX},
	{"PTR",		3, 0, PRI_BIAS_PTR},
};

/*
 * conv_macro() returns the conversion specifier corresponding
 * to the macro name specified in 'name'.  'len' contains the
 * length of the macro name including the null termination.
 * '*elen' will be set to the length of the returning conversion
 * specifier without the null termination.
 */
static const char *
conv_macro(const char *str, uint32_t len, uint32_t *lenp)
{
	const char	**tbl;
	const char	*ltbl;
	char	*next;
	int	n, i, num, bias, idx, want_digits;

	if (len == 2) {
		if (*str == 'I') {
			/* Solaris does not support %I */
			*lenp = 0;
			return ("");
		}
		return (NULL);
	}

	if (len <= 4 || strncmp(str, "PRI", 3) != 0)
		return (NULL);

	str += 3;

	n = sizeof (pri_table) / sizeof (pri_table[0]);
	for (i = 0; i < n; i++) {
		if (pri_table[i].type == *str)
			break;
	}
	if (i == n)
		return (NULL);
	tbl = pri_table[i].str_table;
	ltbl = pri_table[i].len_table;

	str++;
	idx = want_digits = 0;

	if (isdigit((unsigned char)*str)) {
		/* PRIx/N/ */
		bias = 0;
		want_digits = 1;
	} else {
		n = sizeof (special_table) / sizeof (special_table[0]);
		for (i = 0; i < n; i++) {
			if (strncmp(special_table[i].name,
			    str, special_table[i].nlen) == 0) {
				break;
			}
		}
		if (i == n)
			return (NULL);
		bias = special_table[i].bias;
		want_digits = special_table[i].want_digits;
		str += special_table[i].nlen;
	}

	if (want_digits) {
		if (!isdigit((unsigned char)*str))
			return (NULL);
		num = strtol(str, &next, 10);
		/* see if it is 8/16/32/64 */
		for (n = 8, idx = 0; idx < 4; idx++, n *= 2) {
			if (n == num)
				break;
		}
		if (idx == 4)
			return (NULL);
		str = next;
	}
	if (*str != '\0') {
		/* unknow format */
		return (NULL);
	}

	*lenp = (uint32_t)ltbl[bias + idx];
	return (tbl[bias + idx]);
}

static gnu_d_macro_t *
expand_macros(Msg_g_node *p)
{
	char	*base = (char *)p->msg_file_info;
	struct gnu_msg_rev1_info	*rev1_header = p->rev1_header;
	struct gnu_msg_ent	*d_macro_tbl;
	gnu_d_macro_t	*d_macro;
	uint32_t	num_of_d_macro, e_maclen, maclen, i;
	const char	*e_macname;
	char	*macname;

	/* number of the dynamic macros */
	num_of_d_macro = SWAP(p, rev1_header->num_of_dynamic_macro);

	d_macro = malloc((size_t)num_of_d_macro * sizeof (gnu_d_macro_t));
	if (d_macro == NULL)
		return (NULL);

	/* pointer to the dynamic strings table */
	d_macro_tbl = (struct gnu_msg_ent *)(uintptr_t)
	    (base + SWAP(p, rev1_header->off_dynamic_macro));

	for (i = 0; i < num_of_d_macro; i++) {
		macname = base + SWAP(p, d_macro_tbl[i].offset);
		maclen = SWAP(p, d_macro_tbl[i].len);

		/*
		 * sanity check
		 * maclen includes a null termination.
		 */
		if (maclen != strlen(macname) + 1) {
			free(d_macro);
			return (NULL);
		}
		e_macname = conv_macro(macname, maclen, &e_maclen);
		if (e_macname == NULL) {
			free(d_macro);
			return (NULL);
		}
		d_macro[i].len = e_maclen;
		d_macro[i].ptr = e_macname;
	}

	return (d_macro);
}

static char *
expand_dynamic_message(Msg_g_node *p, struct gnu_msg_ent **e_msgs)
{

	char	*base = (char *)p->msg_file_info;
	struct gnu_msg_rev1_info	*rev1_header = p->rev1_header;
	struct gnu_dynamic_tbl	*d_info;
	struct gnu_dynamic_ent	*entry;
	gnu_d_macro_t	*d_macro;
	uint32_t	num_of_d_str, mlen, dlen, didx, i, j;
	uint32_t	off_d_tbl;
	uint32_t	*d_msg_off_tbl;
	size_t	mchunk_size, used, need;
	char	*mchunk, *msg;

#define	MEM_INCR	(1024)

	d_macro = expand_macros(p);
	if (d_macro == NULL)
		return (NULL);

	/* number of dynamic messages */
	num_of_d_str = p->num_of_d_str;

	mchunk = NULL;
	mchunk_size = 0;	/* size of the allocated memory in mchunk */
	used = 0;		/* size of the used memory in mchunk */
	for (i = MSGID; i <= MSGSTR; i++) {
		/* pointer to the offset table of dynamic msgids/msgstrs */
		off_d_tbl = SWAP(p,
		    i == MSGID ? rev1_header->off_dynamic_msgid_tbl :
		    rev1_header->off_dynamic_msgstr_tbl);
		/* pointer to the dynamic msgids/msgstrs */
		d_msg_off_tbl = (uint32_t *)(uintptr_t)(base + off_d_tbl);
		for (j = 0; j < num_of_d_str; j++) {
			e_msgs[i][j].offset = used;
			d_info = (struct gnu_dynamic_tbl *)(uintptr_t)
			    (base + SWAP(p, d_msg_off_tbl[j]));
			entry = d_info->entry;
			msg = base + SWAP(p, d_info->offset);

			for (;;) {
				mlen = SWAP(p, entry->len);
				didx = SWAP(p, entry->idx);
				dlen = (didx == NOMORE_DYNAMIC_MACRO) ? 0 :
				    d_macro[didx].len;
				need = used + mlen + dlen;
				if (need >= mchunk_size) {
					char	*t;
					size_t	n = mchunk_size;
					do {
						n += MEM_INCR;
					} while (n <= need);
					t = realloc(mchunk, n);
					if (t == NULL) {
						free(d_macro);
						free(mchunk);
						return (NULL);
					}
					mchunk = t;
					mchunk_size = n;
				}
				(void) memcpy(mchunk + used, msg, (size_t)mlen);
				msg += mlen;
				used += mlen;

				if (didx == NOMORE_DYNAMIC_MACRO) {
					/*
					 * Last segment of a static
					 * msg string contains a null
					 * termination, so an explicit
					 * null termination is not required
					 * here.
					 */
					break;
				}
				(void) memcpy(mchunk + used,
				    d_macro[didx].ptr, (size_t)dlen);
				used += dlen;
				entry++; /* to next entry */
			}
			/*
			 * e_msgs[][].len does not include a null termination
			 */
			e_msgs[i][j].len = used - e_msgs[i][j].offset - 1;
		}
	}

	free(d_macro);

	/* shrink mchunk to 'used' */
	{
		char	*t;
		t = realloc(mchunk, used);
		if (t == NULL) {
			free(mchunk);
			return (NULL);
		}
		mchunk = t;
	}

	return (mchunk);
}

static int
build_rev1_info(Msg_g_node *p)
{
	uint32_t	*d_hash;
	uint32_t	num_of_d_str, num_of_str;
	uint32_t	idx, hash_value, hash_size;
	size_t	hash_mem_size;
	size_t	d_msgid_size, d_msgstr_size;
	char	*chunk, *mchunk;
	int	i;

#ifdef GETTEXT_DEBUG
	gprintf(0, "******* entering build_rev1_info(0x%p)\n", p);
	printgnumsg(p, 1);
#endif

	if (p->hash_table == NULL) {
		/* Revision 1 always requires the hash table */
		return (-1);
	}

	num_of_str = p->num_of_str;
	hash_size = p->hash_size;
	num_of_d_str = p->num_of_d_str;

	hash_mem_size = hash_size * sizeof (uint32_t);
	ROUND(hash_mem_size, sizeof (struct gnu_msg_ent));

	d_msgid_size = num_of_d_str * sizeof (struct gnu_msg_ent);
	d_msgstr_size = num_of_d_str * sizeof (struct gnu_msg_ent);

	chunk = malloc(hash_mem_size + d_msgid_size + d_msgstr_size);
	if (chunk == NULL) {
		return (-1);
	}

	d_hash = (uint32_t *)(uintptr_t)chunk;
	p->d_msg[MSGID] = (struct gnu_msg_ent *)(uintptr_t)
	    (chunk + hash_mem_size);
	p->d_msg[MSGSTR] = (struct gnu_msg_ent *)(uintptr_t)
	    (chunk + hash_mem_size + d_msgid_size);

	if ((mchunk = expand_dynamic_message(p, p->d_msg)) == NULL) {
		free(chunk);
		return (-1);
	}

	/* copy the original hash table into the dynamic hash table */
	for (i = 0; i < hash_size; i++) {
		d_hash[i] = SWAP(p, p->hash_table[i]);
	}

	/* fill in the dynamic hash table with dynamic messages */
	for (i = 0; i < num_of_d_str; i++) {
		hash_value = get_hashid(mchunk + p->d_msg[MSGID][i].offset,
		    NULL);
		idx = get_hash_index(d_hash, hash_value, hash_size);
		d_hash[idx] = num_of_str + i + 1;
	}

	p->mchunk = mchunk;
	p->hash_table = d_hash;

#ifdef	GETTEXT_DEBUG
	print_rev1_info(p);
	gprintf(0, "******* exiting build_rev1_info()\n");
	printgnumsg(p, 1);
#endif

	return (0);
}

/*
 * gnu_setmsg
 *
 * INPUT
 *   mnp  - message node
 *   addr - address to the mmapped file
 *   size - size of the file
 *
 * RETURN
 *   0   - either T_GNU_MO or T_ILL_MO has been set
 *  -1   - failed
 */
int
gnu_setmsg(Msg_node *mnp, char *addr, size_t size)
{
	struct gnu_msg_info	*gnu_header;
	Msg_g_node	*p;

#ifdef GETTEXT_DEBUG
	gprintf(0, "******** entering gnu_setmsg(0x%p, 0x%p, %lu)\n",
	    (void *)mnp, addr, size);
	printmnp(mnp, 1);
#endif

	/* checks the GNU MAGIC number */
	if (size < sizeof (struct gnu_msg_info)) {
		/* invalid mo file */
		mnp->type = T_ILL_MO;
#ifdef	GETTEXT_DEBUG
		gprintf(0, "********* exiting gnu_setmsg\n");
		printmnp(mnp, 1);
#endif
		return (0);
	}

	gnu_header = (struct gnu_msg_info *)(uintptr_t)addr;

	p = calloc(1, sizeof (Msg_g_node));
	if (p == NULL) {
		return (-1);
	}
	p->msg_file_info = gnu_header;

	if (gnu_header->magic == GNU_MAGIC) {
		switch (gnu_header->revision) {
		case GNU_REVISION_0_1:
		case GNU_REVISION_1_1:
			p->flag |= ST_REV1;
			break;
		}
	} else if (gnu_header->magic == GNU_MAGIC_SWAPPED) {
		p->flag |= ST_SWP;
		switch (gnu_header->revision) {
		case GNU_REVISION_0_1_SWAPPED:
		case GNU_REVISION_1_1_SWAPPED:
			p->flag |= ST_REV1;
			break;
		}
	} else {
		/* invalid mo file */
		free(p);
		mnp->type = T_ILL_MO;
#ifdef	GETTEXT_DEBUG
		gprintf(0, "********* exiting gnu_setmsg\n");
		printmnp(mnp, 1);
#endif
		return (0);
	}

	p->fsize = size;
	p->num_of_str = SWAP(p, gnu_header->num_of_str);
	p->hash_size = SWAP(p, gnu_header->sz_hashtbl);
	p->hash_table = p->hash_size <= 2 ? NULL :
	    (uint32_t *)(uintptr_t)
	    (addr + SWAP(p, gnu_header->off_hashtbl));

	p->msg_tbl[MSGID] = (struct gnu_msg_ent *)(uintptr_t)
	    (addr + SWAP(p, gnu_header->off_msgid_tbl));
	p->msg_tbl[MSGSTR] = (struct gnu_msg_ent *)(uintptr_t)
	    (addr + SWAP(p, gnu_header->off_msgstr_tbl));

	if (p->flag & ST_REV1) {
		/* Revision 1 */
		struct gnu_msg_rev1_info	*rev1_header;

		rev1_header = (struct gnu_msg_rev1_info *)
		    (uintptr_t)(addr + sizeof (struct gnu_msg_info));
		p->rev1_header = rev1_header;
		p->num_of_d_str = SWAP(p, rev1_header->num_of_dynamic_str);
		if (build_rev1_info(p) == -1) {
			free(p);
#ifdef GETTEXT_DEBUG
			gprintf(0, "******** exiting gnu_setmsg: "
			    "build_rev1_info() failed\n");
#endif
			return (-1);
		}
	}

	mnp->msg.gnumsg = p;
	mnp->type = T_GNU_MO;

#ifdef GETTEXT_DEBUG
	gprintf(0, "********* exiting gnu_setmsg\n");
	printmnp(mnp, 1);
#endif
	return (0);
}

/*
 * get_hash_index
 *
 * Returns the index to an empty slot in the hash table
 * for the specified hash_value.
 */
static uint32_t
get_hash_index(uint32_t *hash_tbl, uint32_t hash_value, uint32_t hash_size)
{
	uint32_t	idx, inc;

	idx = hash_value % hash_size;
	inc = 1 + (hash_value % (hash_size - 2));

	for (;;) {
		if (hash_tbl[idx] == 0) {
			/* found an empty slot */
			return (idx);
		}
		idx = (idx + inc) % hash_size;
	}
	/* NOTREACHED */
}
