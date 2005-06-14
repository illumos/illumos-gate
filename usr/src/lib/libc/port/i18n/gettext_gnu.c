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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
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
#include "libc.h"
#include "msgfmt.h"
#include "nlspath_checks.h"
#include "gettext.h"

#ifdef DEBUG
#include <assert.h>
#endif

static const char	*nullstr = "";

#define	CHARSET_MOD	"charset="
#define	CHARSET_LEN	(sizeof (CHARSET_MOD) - 1)
#define	NPLURALS_MOD	"nplurals="
#define	NPLURALS_LEN	(sizeof (NPLURALS_MOD) - 1)
#define	PLURAL_MOD	"plural="
#define	PLURAL_LEN	(sizeof (PLURAL_MOD) - 1)

/*
 * free_conv_msgstr
 *
 * release the memory allocated for storing code-converted messages
 */
static void
free_conv_msgstr(Msg_g_node *gmnp)
{
	int	i;
	unsigned int	num_of_str;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** free_conv_msgstr(0x%p)\n",
		(void *)gmnp);
	printgnumsg(gmnp, 0);
#endif

	num_of_str = SWAP(gmnp, gmnp->msg_file_info->num_of_str);
	for (i = 0; i < num_of_str; i++) {
		if (gmnp->conv_msgstr[i]) {
			free(gmnp->conv_msgstr[i]);
		}
	}
	free(gmnp->conv_msgstr);
	gmnp->conv_msgstr = NULL;

}

/*
 * dfltmsgstr
 *
 * choose an appropriate message by evaluating the plural expression,
 * and return it.
 */
static char *
dfltmsgstr(Msg_g_node *gmnp, const char *msgstr, size_t msgstr_len,
	struct msg_pack *mp)
{
	unsigned int	pindex;
	size_t	len;
	const char	*p;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** dfltmsgstr(0x%p, \"%s\", %d, 0x%p)\n",
		(void *)gmnp,
		msgstr ? msgstr : "(null)", msgstr_len, (void *)mp);
	printgnumsg(gmnp, 0);
	printmp(mp, 0);
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
		(void) printf("plural_eval returned: %d\n", pindex);
#endif
		if (pindex >= gmnp->nplurals) {
			/* should never happen */
			pindex = 0;
		}
		p = msgstr;
		for (; pindex != 0; pindex--) {
			len = msgstr_len - (p - msgstr);
			p = memchr(p, '\0', len);
			if (!p) {
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
	(void) printf("*************** parse_header(\"%s\", 0x%p)\n",
		header ? header : "(null)", (void *)gmnp);
	printgnumsg(gmnp, 0);
#endif

	if (!header) {
		gmnp->src_encoding = (char *)nullstr;
		gmnp->nplurals = 2;
		gmnp->plural = NULL;
#ifdef GETTEXT_DEBUG
		(void) printf("*************** exiting parse_header\n");
		(void) printf("no header\n");
#endif

		return (0);
	}

	charset_str = strstr(header, CHARSET_MOD);
	if (!charset_str) {
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
			charset = (char *)malloc(len + 1);
			if (!charset) {
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
	if (!nplurals_str || !plural_str) {
		/* no valid plural specification */
		gmnp->nplurals = 2;
		gmnp->plural = NULL;
#ifdef GETTEXT_DEBUG
		(void) printf("*************** exiting parse_header\n");
		(void) printf("no plural entry\n");
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
		(void) printf("plural_str: \"%s\"\n", p);
#endif

		ret = plural_expr(&plural, (const char *)p);
		if (ret == 0) {
			/* parse succeeded */
			gmnp->plural = plural;
#ifdef GETTEXT_DEBUG
		(void) printf("*************** exiting parse_header\n");
		(void) printf("charset: \"%s\"\n",
			charset ? charset : "(null)");
		printexpr(plural, 0);
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

static char *
handle_gnu_mo(struct cache_pack *cp, struct msg_pack *mp,
	Gettext_t *gt)
{
	char	*result;
	char	*codeset = get_codeset(mp->domain);

	result = gnu_key_2_text(cp->mnp->msg.gnumsg, codeset, mp);
	if (mp->plural) {
		if (((result == mp->msgid1) && (mp->n == 1)) ||
			((result == mp->msgid2) && (mp->n != 1))) {
			return (NULL);
		}
	} else {
		if (result == mp->msgid1) {
			return (NULL);
		}
	}
	gt->c_m_node = cp->mnp;
	if (!cp->mnp->trusted) {
		result = check_format(mp->msgid1, result, 0);
		if (result == mp->msgid1) {
			DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n,
				mp->plural);
		}
	}
	return (result);
}

/*
 * handle_lang
 *
 * take care of the LANGUAGE specification
 */
char *
handle_lang(struct cache_pack *cp, struct msg_pack *mp)
{
	Gettext_t *gt = global_gt;
	struct stat64	statbuf;
	const char	*p, *op, *q;
	char	*locale = NULL, *olocale, *result;
	unsigned int	hash_locale;
	size_t	locale_len, olocale_len = 0;
	int	gnu_mo_found = 0;
	int	fd;
	int	ret;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** handle_lang(0x%p, 0x%p)\n",
		(void *)cp, (void *)mp);
	printcp(cp, 0);
	printmp(mp, 0);
#endif

	p = mp->language;

	while (*p) {
		op = p;
		q = strchr(p, ':');
		if (!q) {
			locale_len = strlen(p);
			p += locale_len;
		} else {
			locale_len = q - p;
			p += locale_len + 1;
		}
		if ((locale_len >= MAXPATHLEN) ||
			(locale_len == 0)) {
			/* illegal locale name */
			continue;
		}
		if (olocale_len < locale_len) {
			olocale = locale;
			locale = (char *)realloc(locale, locale_len + 1);
			if (!locale) {
				if (olocale)
					free(olocale);
				DFLTMSG(result, mp->msgid1, mp->msgid2,
					mp->n, mp->plural);
				return (result);
			}
			olocale_len = locale_len;
		}
		(void) memcpy(locale, op, locale_len);
		locale[locale_len] = '\0';
		hash_locale = get_hashid(locale, NULL);
		mp->locale = locale;
		mp->hash_locale = hash_locale;
		mp->locale_len = locale_len;
#ifdef GETTEXT_DEBUG
		*mp->msgfile = '\0';
#endif
		if (mk_msgfile(mp) == NULL) {
			/* illegal locale name */
			continue;
		}

		cp->node_hash = NULL;

		ret = check_cache(cp, mp);
		if (ret) {
			/*
			 * found in cache
			 */
			switch (cp->mnp->type) {
			case T_ILL_MO:
				/* invalid MO */
				continue;
			case T_SUN_MO:
				/* Solaris MO */
				goto out_loop;
			case T_GNU_MO:
				/* GNU MO */
				gnu_mo_found = 1;
				result = handle_gnu_mo(cp, mp, gt);
				if (result) {
					free(locale);
					return (result);
				}
				continue;
			}
			/* NOTREACHED */
		}
		/*
		 * not found in cache
		 */
		fd = nls_safe_open(mp->msgfile, &statbuf, &mp->trusted, 1);
		if ((fd == -1) || (statbuf.st_size > LONG_MAX)) {
			if (connect_invalid_entry(cp, mp) == -1) {
				DFLTMSG(result, mp->msgid1, mp->msgid2,
					mp->n, mp->plural);
				free(locale);
				return (result);
			}
			continue;
		}
		mp->fsz = (size_t)statbuf.st_size;
		mp->addr = mmap(0, mp->fsz, PROT_READ, MAP_SHARED, fd, 0);
		(void) close(fd);

		if (mp->addr == (caddr_t)-1) {
			if (connect_invalid_entry(cp, mp) == -1) {
				DFLTMSG(result, mp->msgid1, mp->msgid2,
					mp->n, mp->plural);
				free(locale);
				return (result);
			}
			continue;
		}

		cp->mnp = create_mnp(mp);
		if (!cp->mnp) {
			free(locale);
			free_mnp_mp(cp->mnp, mp);
			DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n,
				mp->plural);
			return (result);
		}

		if (setmsg(cp->mnp, (char *)mp->addr, mp->fsz) == -1) {
			free(locale);
			free_mnp_mp(cp->mnp, mp);
			DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n,
				mp->plural);
			return (result);
		}
		if (!cp->cacheline) {
			cp->cnp = create_cnp(cp->mnp, mp);
			if (!cp->cnp) {
				free(locale);
				free_mnp_mp(cp->mnp, mp);
				DFLTMSG(result, mp->msgid1, mp->msgid2,
					mp->n, mp->plural);
				return (result);
			}
		}
		cp->mnp->trusted = mp->trusted;
		connect_entry(cp);

		switch (cp->mnp->type) {
		case T_ILL_MO:
			/* invalid MO */
			continue;
		case T_SUN_MO:
			/* Solaris MO */
			goto out_loop;
		case T_GNU_MO:
			/* GNU MO */
			gnu_mo_found = 1;

			result = handle_gnu_mo(cp, mp, gt);
			if (result) {
				free(locale);
				return (result);
			}
			continue;
		}
		/* NOTREACHED */
	}

out_loop:
	if (gnu_mo_found) {
		DFLTMSG(result, mp->msgid1, mp->msgid2, mp->n, mp->plural);
		free(locale);
		return (result);
	}
	if (locale)
		free(locale);
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
	size_t *msgstrlen, unsigned int *midx)
{
	unsigned int	*hash_table;
	struct gnu_msg_ent	*msgid_tbl, *msgstr_tbl;
	char	*base;
	struct gnu_msg_info	*header = gmnp->msg_file_info;
	unsigned int	hash_size, hash_val, hash_inc, hash_idx;
	unsigned int	offset, msglen, idx;
	unsigned int	num_of_str;
	unsigned int	off_msgid_tbl, off_msgstr_tbl;
	size_t	msgid1_len;

	base = (char *)header;
	off_msgid_tbl = SWAP(gmnp, header->off_msgid_tbl);
	off_msgstr_tbl = SWAP(gmnp, header->off_msgstr_tbl);

	/* LINTED */
	msgid_tbl = (struct gnu_msg_ent *)(base + off_msgid_tbl);
	/* LINTED */
	msgstr_tbl = (struct gnu_msg_ent *)(base + off_msgstr_tbl);
	hash_table = gmnp->hash_table;
	hash_size = SWAP(gmnp, header->sz_hashtbl);
	num_of_str = SWAP(gmnp, header->num_of_str);

#ifdef GETTEXT_DEBUG
	(void) printf("*************** gnu_msgsearch("
		"0x%p, \"%s\", 0x%p, 0x%p)\n",
		(void *)gmnp,
		msgid1 ? msgid1 : "(null)",
		(void *)msgstrlen, (void *)midx);
	printgnumsg(gmnp, 0);
#endif

	if (!hash_table || (hash_size <= 2)) {
		/*
		 * No hash table exists or
		 * hash size is enough small
		 */
		unsigned int	top, bottom;
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
				goto found;
			}
		}
		/* not found */
		return ((char *)msgid1);
	}

	/* use hash table */
	hash_val = get_hashid(msgid1, &msgid1_len);
	msglen = (unsigned int)msgid1_len;
	hash_idx = hash_val % hash_size;
	hash_inc = 1 + (hash_val % (hash_size - 2));

	for (;;) {
		offset = SWAP(gmnp, hash_table[hash_idx]);

		if (offset == 0) {
			return ((char *)msgid1);
		}

		idx = offset - 1;
		if ((msglen <= SWAP(gmnp, msgid_tbl[idx].len)) &&
			strcmp(msgid1, base +
			SWAP(gmnp, msgid_tbl[idx].offset)) == 0) {
			/* found */
			goto found;
		}

		hash_idx = (hash_idx + hash_inc) % hash_size;
	}
	/* NOTREACHED */

found:
	if (msgstrlen)
		*msgstrlen = SWAP(gmnp, msgstr_tbl[idx].len) + 1;
	if (midx)
		*midx = idx;
	return (base + SWAP(gmnp, msgstr_tbl[idx].offset));
}

/*
 * do_conv
 *
 * Converts the specified string from the src encoding
 * to the dst encoding by calling iconv()
 */
static size_t
do_conv(iconv_t fd, char **dst, const char *src, size_t srclen)
{
	size_t	oleft, ileft, bufsize, tolen;
	char	*to, *tptr;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** do_conv("
		"0x%p, 0x%p, \"%s\", %d)\n",
		(void *)fd, (void *)dst, src ? src : "(null)", srclen);
#endif

	bufsize = srclen * 2;
	ileft = srclen;
	oleft = bufsize;
	to = (char *)malloc(bufsize);
	if (!to) {
		return ((size_t)-1);
	}

	for (; ; ) {
		tptr = to;
		errno = 0;
#ifdef GETTEXT_DEBUG
		(void) printf("******* calling iconv()\n");
#endif
		if (iconv(fd, &src, &ileft, &tptr, &oleft) ==
			(size_t)-1) {
			if (errno == E2BIG) {
				char	*oto;
				oleft += bufsize;
				bufsize *= 2;
				oto = to;
				to = (char *)realloc(oto, bufsize);
				if (!to) {
					free(oto);
					return ((size_t)-1);
				}
				continue;
			} else {
				tolen = bufsize - oleft;
				break;
			}
		}
		tolen = bufsize - oleft;
		break;
	}
	*dst = to;
	return (tolen);
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
	char	*result, *msgstr;
	size_t	msgstr_len;
	unsigned int	midx;
	int	ret;
	char	*conv_msgstr, *conv_dst;
	size_t	*p;
	size_t	conv_msgstr_len, buflen;
	iconv_t	fd;
	int	conversion, new_encoding;
	unsigned int	num_of_str;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** gnu_key_2_text("
		"0x%p, \"%s\", 0x%p)\n",
		(void *)gmnp, codeset ? codeset : "(null)", (void *)mp);
	printgnumsg(gmnp, 0);
	printmp(mp, 0);
#endif

	/* first checks if header entry has been processed */
	if (!(gmnp->flag & ST_CHK)) {
		char	*msg_header;

		msg_header = gnu_msgsearch(gmnp, "", NULL, NULL);
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
	printgnumsg(gmnp, 0);
#endif
	if (!gmnp->dst_encoding) {
		/*
		 * destination encoding has not been set.
		 */
		char	*dupcodeset = strdup(codeset);
		if (!dupcodeset) {
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
				free_conv_msgstr(gmnp);
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
					if (!gmnp->conv_msgstr) {
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
			if (!dupcodeset) {
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
			} else {
				/*
				 * dst encoding is different from src encoding.
				 * new conversion required.
				 */
				conversion = 1;
				new_encoding = 1;
			}

			if (gmnp->fd && (gmnp->fd != (iconv_t)-1)) {
				(void) iconv_close(gmnp->fd);
			}
			if (gmnp->fd != (iconv_t)-1) {
				gmnp->fd = (iconv_t)-1;
			}
			if (gmnp->conv_msgstr)
				free_conv_msgstr(gmnp);
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
		if (!gmnp->conv_msgstr[midx]) {
			/* this msgstr hasn't been converted yet */
			conv_msgstr_len = do_conv(gmnp->fd,
				&conv_dst, (const char *)msgstr, msgstr_len);
			if (conv_msgstr_len == (size_t)-1) {
				result = dfltmsgstr(gmnp, msgstr,
					msgstr_len, mp);
				return (result);
			}
			buflen = (conv_msgstr_len + sizeof (size_t));
			/* allign to sizeof (size_t) */
			if (buflen % sizeof (size_t))
				buflen += (sizeof (size_t) -
					(buflen % sizeof (size_t)));
			p = (size_t *)malloc(buflen);
			if (!p) {
				free(conv_dst);
				result = dfltmsgstr(gmnp, msgstr,
					msgstr_len, mp);
				return (result);
			}
			*p = conv_msgstr_len;
			(void) memcpy(p + 1, conv_dst, conv_msgstr_len);
			free(conv_dst);
			gmnp->conv_msgstr[midx] = (char *)p;
			conv_msgstr = (char *)(p + 1);
		} else {
			/* this msgstr is in the conversion cache */
			/* LINTED */
			size_t	*cmsg = (size_t *)gmnp->conv_msgstr[midx];
			conv_msgstr_len = *cmsg;
			conv_msgstr = (char *)(cmsg + 1);
		}
		result = dfltmsgstr(gmnp, conv_msgstr, conv_msgstr_len, mp);
		return (result);
	}
	/* new conversion */
#ifdef GETTEXT_DEBUG
	(void) printf("******* calling iconv_open()\n");
	(void) printf("      dst: \"%s\", src: \"%s\"\n",
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
	num_of_str = SWAP(gmnp, gmnp->msg_file_info->num_of_str);
	gmnp->conv_msgstr = (char **)calloc((size_t)num_of_str,
		sizeof (char *));
	if (!gmnp->conv_msgstr) {
		/* malloc failed */
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	conv_msgstr_len = do_conv(gmnp->fd, &conv_dst,
		(const char *)msgstr, msgstr_len);
	if (conv_msgstr_len == (size_t)-1) {
		free_conv_msgstr(gmnp);
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	buflen = (conv_msgstr_len + sizeof (size_t));
	/* allign to sizeof (size_t) */
	if (buflen % sizeof (size_t))
		buflen += (sizeof (size_t) - (buflen % sizeof (size_t)));
	p = (size_t *)malloc(buflen);
	if (!p) {
		free(conv_dst);
		free_conv_msgstr(gmnp);
		result = dfltmsgstr(gmnp, msgstr, msgstr_len, mp);
		return (result);
	}
	*p = conv_msgstr_len;
	(void) memcpy(p + 1, conv_dst, conv_msgstr_len);
	free(conv_dst);
	gmnp->conv_msgstr[midx] = (char *)p;
	conv_msgstr = (char *)(p + 1);
	result = dfltmsgstr(gmnp, conv_msgstr, conv_msgstr_len, mp);
	return (result);
}
