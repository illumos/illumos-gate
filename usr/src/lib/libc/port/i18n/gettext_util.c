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

#include "synonyms.h"
#include "mtlib.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <thread.h>
#include <synch.h>
#include <limits.h>
#include <unistd.h>
#include <sys/mman.h>
#include <langinfo.h>
#include "libc.h"
#include "_loc_path.h"
#include "msgfmt.h"
#include "gettext.h"

#ifdef GETTEXT_DEBUG
#include "plural_parser.h"
#include <stdarg.h>
#endif

static const char	*category_name[] = {
	"LC_CTYPE",
	"LC_NUMERIC",
	"LC_TIME",
	"LC_COLLATE",
	"LC_MONETARY",
	"LC_MESSAGES"
};

static const int	category_name_len[] = {
	8,
	10,
	7,
	10,
	11,
	11
};

static int
setmo(Msg_node *mnp, char *addr, int type)
{
#ifdef GETTEXT_DEBUG
	(void) printf("*************** setmo(0x%p, %d)\n",
		(void *)mnp, ret);
	printmnp(mnp, 0);
#endif

	switch (type) {
	case T_ILL_MO:
		/* invalid MO */
		mnp->type = T_ILL_MO;
#ifdef GETTEXT_DEBUG
		(void) printf("*************** exiting setmo\n");
		printmnp(mnp, 0);
#endif
		return (0);
	case T_SUN_MO:
		{
			struct msg_info	*sun_header;
			int	struct_size, info_size, count;
			Msg_s_node	*p;
			p = (Msg_s_node *)calloc(1, sizeof (Msg_s_node));
			if (!p) {
				return (-1);
			}
			/* LINTED */
			sun_header = (struct msg_info *)addr;
			count = sun_header->msg_count;
			struct_size = (int)(MSG_STRUCT_SIZE * count);
			info_size = (int)(sizeof (struct msg_info));
			p->msg_file_info = sun_header;
			/* LINTED */
			p->msg_list = (struct msg_struct *)(((char *)addr) +
				info_size);
			p->msg_ids = (char *)(((char *)addr) + info_size +
				struct_size);
			p->msg_strs = (char *)(((char *)addr) + info_size +
				struct_size + sun_header->str_count_msgid);

			mnp->msg.sunmsg = p;
			mnp->type = T_SUN_MO;
#ifdef GETTEXT_DEBUG
			(void) printf("*************** exiting setmo\n");
			printmnp(mnp, 0);
#endif
			return (0);
		}
		/* NOTREACHED */
	case T_GNU_MO:
	case T_GNU_SWAPPED_MO:
		{
			struct gnu_msg_info	*gnu_header;
			Msg_g_node	*p;
			p = (Msg_g_node *)calloc(1, sizeof (Msg_g_node));
			if (!p) {
				return (-1);
			}
			/* LINTED */
			gnu_header = (struct gnu_msg_info *)addr;
			p->msg_file_info = gnu_header;
			if (type == T_GNU_SWAPPED_MO) {
				/*
				 * This MO file has been created on
				 * the reversed endian system
				 */
				p->flag |= ST_SWP;
			}
			/* LINTED */
			p->hash_table = (unsigned int *)(((char *)addr) +
				SWAP(p, gnu_header->off_hashtbl));

			mnp->msg.gnumsg = p;
			mnp->type = T_GNU_MO;
#ifdef GETTEXT_DEBUG
			(void) printf("*************** exiting setmo\n");
			printmnp(mnp, 0);
#endif
			return (0);
		}
		/* NOTREACHED */
	}
	/* NOTREACHED */
	return (0);	/* keep gcc happy */
}

/*
 * setmsg
 *
 * INPUT
 *   mnp  - message node
 *   addr -	address to the mmapped file
 *   size - size of the file
 *
 * RETURN
 *   0   - succeeded
 *  -1   - failed
 */
int
setmsg(Msg_node *mnp, char *addr, size_t size)
{
	struct msg_info	*sun_header;
	struct gnu_msg_info	*gnu_header;
	unsigned int	first_4bytes;
	int	mid, count;
	int	struct_size, struct_size_old;
	int	msg_struct_size;

	if (size < sizeof (struct msg_info)) {
		/* invalid mo file */
		return (setmo(mnp, addr, T_ILL_MO));
	}

	/* LINTED */
	first_4bytes = *((unsigned int *)addr);
	if (first_4bytes <= INT_MAX) {
		/* candidate for sun mo */
		/* LINTED */
		sun_header = (struct msg_info *)addr;
		mid = sun_header->msg_mid;
		count = sun_header->msg_count;
		msg_struct_size = sun_header->msg_struct_size;
		struct_size_old = (int)(OLD_MSG_STRUCT_SIZE * count);
		struct_size = (int)(MSG_STRUCT_SIZE * count);

		if ((((count - 1) / 2) == mid) &&
			((msg_struct_size == struct_size_old) ||
			(msg_struct_size == struct_size))) {
			/* valid sun mo file */
			return (setmo(mnp, addr, T_SUN_MO));
		}
		/* invalid mo file */
		return (setmo(mnp, addr, T_ILL_MO));
	}

	/* checks the GNU MAGIC number */
	if (size < sizeof (struct gnu_msg_info)) {
		/* invalid mo file */
		return (setmo(mnp, addr, T_ILL_MO));
	}

	/* LINTED */
	gnu_header = (struct gnu_msg_info *)addr;
	if ((gnu_header->magic == GNU_MAGIC) &&
		(gnu_header->revision == GNU_REVISION)) {
		/* GNU mo file */
		return (setmo(mnp, addr, T_GNU_MO));
	} else if ((gnu_header->magic == GNU_MAGIC_SWAPPED) &&
		(gnu_header->revision == GNU_REVISION_SWAPPED)) {
		/* endian-swapped GNU mo file */
		return (setmo(mnp, addr, T_GNU_SWAPPED_MO));
	}

	/* invalid mo file */
	return (setmo(mnp, addr, T_ILL_MO));
}

/*
 * mk_msgfile
 *
 * INPUT
 * mp -	uses the following members:
 * 	msgfile  - buffer to store the pathname to the message file
 *	binding  - directory pathname bound to specified domain
 *	cblen    - length of binding
 *	locale   - locale name
 *	domain   - domain name
 *	category - category
 *	locale_len - length of locale name
 *	domain_len - length of domain name
 *
 * OUTPUT
 * mp->msgfile - pathname to the message file is stored
 * mp->msgfile_len - length of mp->msgfile without null termination
 *
 * RETURN
 * mp->msgfile is returned
 */
char *
mk_msgfile(struct msg_pack *mp)
{
	char	*p, *q;
	const char	*catstr;
	size_t	cblen, catlen, totallen;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** mk_msgfile(0x%p)\n",
		(void *)mp);
	printmp(mp, 0);
#endif

	p = mp->msgfile;
	q = mp->binding;
	while (*p = *q++)
		p++;
	cblen = (size_t)(p - mp->msgfile);
	if (*(p - 1) != '/') {
		/*
		 * if the last character of binding
		 * isn't a '/', adding '/'.
		 */
		if (cblen + 1 >= MAXPATHLEN) {
			/* MAXPATHLEN includes a null termination */
			return (NULL);
		}
		*p++ = '/';
		cblen++;
	}

	catstr = category_name[mp->category];
	catlen = (size_t)category_name_len[mp->category];
	/*
	 * totallen is the length of the msgfile
	 * pathname excluding a null termination.
	 */

	totallen = cblen + mp->locale_len + 1 + catlen + 1 +
		mp->domain_len + MSGFILESUFFIXLEN;
	if (totallen >= MAXPATHLEN)
		return (NULL);

	q = mp->locale;
	while (*p++ = *q++)
		;
	*(p - 1) = '/';
	while (*p++ = *catstr++)
		;
	*(p - 1) = '/';
	q = mp->domain;
	while (*p++ = *q++)
		;
	*(p - 1) = '.';
	*p = 'm';
	*(p + 1) = 'o';
	*(p + 2) = '\0';

	mp->msgfile_len = totallen;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** Exiting mk_msgfile\n");
	(void) printf("mp->msgfile: \"%s\"\n", mp->msgfile);
#endif

	return (mp->msgfile);
}


/*
 * check_cache
 *
 * INPUT
 * cp - may use the following members:
 *	node_hash - pointer to the Cache_node object having this locale
 *
 * mp - may use the following members:
 *	msgfile - pathname to the message catalog file
 *	hash_locale - hash id of this locale
 *
 * OUTPUT
 * cp - may update the following members:
 *	mnp - pointer to a Msg_node object
 *	cnp - pointer to a Cache_node object
 *	node_hash - pointer to the Cache_node object having this locale
 *	cacheline - flag to show if the Cache_node for this locale exists
 *
 * RETURN
 * 1 - Entry for this message catalog exists in the cache
 * 0 - Entry for this message catalog doesn't exist in the cache
 */
int
check_cache(struct cache_pack *cp, struct msg_pack *mp)
{
	Msg_node	*cur_msg;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	{
		int level = 0;

		(void) printf("*************** check_cache(0x%p, 0x%p)\n",
			(void *)cp, (void *)mp);
		printcp(cp, 0);
		printmp(mp, 0);
	}
#endif

	cur_msg = gt->c_m_node;
	if (cur_msg &&
		(strcmp(cur_msg->path, mp->msgfile) == 0)) {
		/*
		 * msgfile is the same as the previous message file
		 */
		cp->mnp = cur_msg;
		cp->cnp = gt->c_node;
		cp->cacheline = 1;
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache found\n");
		printmnp(cp->mnp, 0);
#endif
		return (1);
	}
	if (cp->node_hash) {
		/*
		 * already cache_node having the same
		 * hash id found
		 */
		cp->cnp = cp->node_hash;
		cp->mnp = cp->cnp->m_node;
		cp->cacheline = 1;
		while (cp->mnp) {
			if (strcmp(cp->mnp->path, mp->msgfile) == 0) {
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache found\n");
		printmnp(cp->mnp, 0);
#endif
				return (1);
			}
			cp->mnp = cp->mnp->next;
		}
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache not found\n");
#endif
		return (0);
	}
	/* search the cache list */
	cp->cnp = gt->c_node;
	cp->mnp = NULL;
	while (cp->cnp) {
		if (cp->cnp->hashid == mp->hash_locale) {
			cp->node_hash = cp->cnp;
			cp->mnp = cp->cnp->m_node;
			cp->cacheline = 1;
			while (cp->mnp) {
				if (strcmp(cp->mnp->path, mp->msgfile) == 0) {
					/*
					 * msgfile found in the cache
					 */
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache found\n");
		printmnp(cp->mnp, 0);
#endif
					return (1);
				}
				cp->mnp = cp->mnp->next;
			}
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache not found\n");
#endif
			return (0);
		} else {
			cp->cnp = cp->cnp->next;
		}
	}
	cp->cacheline = 0;
#ifdef GETTEXT_DEBUG
		(void) printf("************* exiting check_cache\n");
		(void) printf("cache not found\n");
#endif
	return (0);
}

char *
get_codeset(const char *domain)
{
	char	*codeset;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** get_codeset(\"%s\")\n",
		domain ? domain : "(null)");
#endif

	codeset = _real_bindtextdomain_u(domain, NULL, TP_CODESET);
	if (!codeset) {
		/* no codeset is bound to this domain */
		codeset = nl_langinfo(CODESET);
	}
#ifdef GETTEXT_DEBUG
	(void) printf("*************** existing get_codeset(\"%s\")\n",
		domain ? domain : "(null)");
	(void) printf("                = \"%s\"\n", codeset);
#endif

	return (codeset);
}

void
connect_entry(struct cache_pack *cp)
{
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** connect_entry(0x%p)\n",
		(void *)cp);
	printcp(cp, 0);
#endif

	if (cp->cacheline) {
		if (cp->cnp->m_last)
			cp->cnp->m_last->next = cp->mnp;
		else
			cp->cnp->m_node = cp->mnp;
		cp->cnp->m_last = cp->mnp;
	} else {
		if (gt->c_last)
			gt->c_last->next = cp->cnp;
		else
			gt->c_node = cp->cnp;
		gt->c_last = cp->cnp;
	}
	gt->c_m_node = cp->mnp;
}

int
connect_invalid_entry(struct cache_pack *cp, struct msg_pack *mp)
{
#ifdef GETTEXT_DEBUG
	(void) printf("*************** connect_invalid_entry(0x%p, 0x%p)\n",
		(void *)cp, (void *)mp);
	printcp(cp, 0);
	printmp(mp, 0);
#endif

	cp->mnp = create_mnp(mp);
	if (!cp->mnp) {
		return (-1);
	}

	if (!cp->cacheline) {
		cp->cnp = create_cnp(cp->mnp, mp);
		if (!cp->cnp) {
			free_mnp_mp(cp->mnp, mp);
			return (-1);
		}
	}
	cp->mnp->type = T_ILL_MO;
	connect_entry(cp);

	return (0);
}

Msg_node *
create_mnp(struct msg_pack *mp)
{
	Msg_node	*mnp;
	char	*s;
	size_t	msglen;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** create_mnp(0x%p)\n", (void *)mp);
	printmp(mp, 0);
#endif

	mnp = (Msg_node *)calloc(1, sizeof (Msg_node));
	if (!mnp) {
		return (NULL);
	}
	msglen = mp->msgfile_len;
	s = (char *)malloc(msglen + 1);
	if (!s) {
		free(mnp);
		return (NULL);
	}
	(void) memcpy(s, mp->msgfile, msglen + 1);
	mnp->path = s;
	return (mnp);
}

Cache_node *
create_cnp(Msg_node *mnp, struct msg_pack *mp)
{
	Cache_node	*cnp;

#ifdef GETTEXT_DEBUG
	(void) printf("*************** create_cnp(0x%p, 0x%p)\n",
		(void *)mnp, (void *)mp);
	printmnp(mnp, 0);
	printmp(mp, 0);
#endif

	cnp = (Cache_node *)calloc(1, sizeof (Cache_node));
	if (!cnp) {
		return (NULL);
	}
	cnp->hashid = mp->hash_locale;
	cnp->m_node = mnp;
	cnp->m_last = mnp;

	return (cnp);
}

void
free_mnp_mp(Msg_node *mnp, struct msg_pack *mp)
{
#ifdef GETTEXT_DEBUG
	(void) printf("*************** free_mnp_mp(0x%p, 0x%p)\n",
		(void *)mnp, (void *)mp);
	printmnp(mnp, 0);
	printmp(mp, 0);
#endif

	if (mnp) {
		if (mnp->path)
			free(mnp->path);
		switch (mnp->type) {
		case T_SUN_MO:
			free(mnp->msg.sunmsg);
			break;
		case T_GNU_MO:
			free(mnp->msg.gnumsg);
			break;
		}
		free(mnp);
	}
	if (mp->addr != (caddr_t)-1) {
		(void) munmap(mp->addr, mp->fsz);
	}
}

/*
 * get_hashid
 *
 * Calculates the hash value from the specified string.
 * Actual hashid will be mod(hash value, PRIME_NUMBER).
 *
 * hashpjw
 * Ref: Compilers - Principles, Techniques, and Tools
 * Aho, Sethi, and Ullman
 */
unsigned int
get_hashid(const char *str, size_t *len)
{
	const char	*p;
	unsigned int	h = 0, g;

	for (p = str; *p; p++) {
		h = (h << 4) + *p;
		g = h & 0xf0000000;
		if (g) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}
	if (len)
		*len = (size_t)(p - str);
	return (h);
}

unsigned int
doswap32(unsigned int n)
{
	unsigned int	r;

	r = (n << 24) | ((n & 0xff00) << 8) |
		((n >> 8) & 0xff00) | (n >> 24);
	return (r);
}

#ifdef GETTEXT_DEBUG
void
gprintf(int level, const char *format, ...)
{
	va_list	ap;

	va_start(ap, format);

	while (level-- >= 0) {
		(void) fputs("   ", stdout);
	}
	(void) vprintf(format, ap);
	va_end(ap);
}

void
printlist(void)
{
	struct domain_binding	*ppp;
	Gettext_t	*gt = global_gt;

	(void) printf("=== Printing default list and regural list\n");
	(void) printf("   Default domain=<%s>, binding=<%s>\n",
	    DEFAULT_DOMAIN, defaultbind);

	ppp = FIRSTBIND(gt);
	while (ppp) {
		(void) printf(
			"   domain=<%s>, binding=<%s>, codeset=<%s>\n",
		    ppp->domain ? ppp->domain : "(null)",
			ppp->binding ? ppp->binding : "(null)",
			ppp->codeset ? ppp->codeset : "(null)");
		ppp = ppp->next;
	}
}

void
printmp(struct msg_pack *mp, int level)
{
	gprintf(level, "=== mp ===\n");
	gprintf(level, "   msgid1: \"%s\"\n",
		mp->msgid1 ? mp->msgid1 : "(null)");
	gprintf(level, "   msgid2: \"%s\"\n",
		mp->msgid2 ? mp->msgid2 : "(null)");
	gprintf(level, "   n: %d\n", mp->n);
	gprintf(level, "   plural: %d\n", mp->plural);
	gprintf(level, "   category: \"%s\"\n",
		category_name[mp->category]);
	gprintf(level, "   domain: \"%s\"\n",
		mp->domain ? mp->domain : "(null)");
	gprintf(level, "   binding: \"%s\"\n",
		mp->binding ? mp->binding : "(null)");
	gprintf(level, "   msgfile: \"%s\"\n",
		mp->msgfile ? mp->msgfile : "(null)");
	gprintf(level, "   locale: \"%s\"\n",
		mp->locale ? mp->locale : "(null)");
	gprintf(level, "   language: \"%s\"\n",
		mp->language ? mp->language : "(null)");
	gprintf(level, "   hash_locale: %d\n", mp->hash_locale);
	gprintf(level, "   addr: 0x%p\n", mp->addr);
	gprintf(level, "   fsz: %d\n", mp->fsz);
	gprintf(level, "   trusted: %d\n", mp->trusted);
}

void
printsunmsg(Msg_s_node *smnp, int level)
{
	gprintf(level, "=== sunmsg ===\n");
	gprintf(level, "   msg_file_info: 0x%p\n",
		(void *)smnp->msg_file_info);
	gprintf(level, "      msg_mid: %d\n",
		smnp->msg_file_info->msg_mid);
	gprintf(level, "      msg_count: %d\n",
		smnp->msg_file_info->msg_count);
	gprintf(level, "      str_count_msgid: %d\n",
		smnp->msg_file_info->str_count_msgid);
	gprintf(level, "      str_count_msgstr: %d\n",
		smnp->msg_file_info->str_count_msgstr);
	gprintf(level, "      msg_struct_size: %d\n",
		smnp->msg_file_info->msg_struct_size);
	gprintf(level, "   msg_list: 0x%p\n",
		(void *)smnp->msg_list);
	gprintf(level, "   msg_ids: 0x%p\n",
		(void *)smnp->msg_ids);
	gprintf(level, "   msg_strs: 0x%p\n",
		(void *)smnp->msg_strs);
}

void
printgnumsg(Msg_g_node *gmnp, int level)
{
	gprintf(level, "=== gnumsg ===\n");
	gprintf(level, "   msg_file_info: 0x%p\n",
		(void *)gmnp->msg_file_info);
	gprintf(level, "      magic: 0x%x\n",
		gmnp->msg_file_info->magic);
	gprintf(level, "      revision: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->revision));
	gprintf(level, "      num_of_str: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->num_of_str));
	gprintf(level, "      off_msgid_tbl: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->off_msgid_tbl));
	gprintf(level, "      off_msgstr_tbl: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->off_msgstr_tbl));
	gprintf(level, "      sz_hashtbl: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->sz_hashtbl));
	gprintf(level, "      off_hashtbl: %d\n",
		SWAP(gmnp, gmnp->msg_file_info->off_hashtbl));
	gprintf(level, "   hash_table: 0x%p\n",
		(void *)gmnp->hash_table);
	gprintf(level, "   header_flag: %08x\n",
		gmnp->header_flag);
	gprintf(level, "   src_encoding: \"%s\"\n",
		gmnp->src_encoding ? gmnp->src_encoding : "(null)");
	gprintf(level, "   dst_encoding: \"%s\"\n",
		gmnp->dst_encoding ? gmnp->dst_encoding : "(null)");
	gprintf(level, "   nplurals: %d\n",
		gmnp->nplurals);
	gprintf(level, "   plural: 0x%p\n",
		(void *)gmnp->plural);
	if (gmnp->plural)
		printexpr(gmnp->plural, level+1);
	gprintf(level, "   fd: 0x%p\n", (void *)gmnp->fd);
	gprintf(level, "   conv_msgstr: 0x%p\n",
		(void *)gmnp->conv_msgstr);
}

void
printexpr(struct expr *e, int level)
{
	static const char	*op_name[] = {
		"NULL", "INIT", "EXP",
		"NUM", "VAR", "?", ":", "||",
		"&&", "==", "!=", ">", "<",
		">=", "<=", "+", "-", "*", "/",
		"%", "!", "(", ")", "ERR"
	};
	switch (GETOPNUM(e->op)) {
	case 0:
		switch (GETTYPE(e->op)) {
		case T_NUM:
			gprintf(level, "NUM(%d)\n", e->num);
			break;
		case T_VAR:
			gprintf(level, "VAR(n)\n");
			break;
		}
		break;
	case 1:
		gprintf(level, "OP: !\n");
		printexpr(e->nodes[0], level+1);
		break;
	case 2:
		gprintf(level, "OP: %s\n", op_name[GETTYPE(e->op)]);
		printexpr(e->nodes[0], level+1);
		printexpr(e->nodes[1], level+1);
		break;
	case 3:
		gprintf(level, "OP: ?\n");

		printexpr(e->nodes[0], level+1);
		printexpr(e->nodes[1], level+1);
		printexpr(e->nodes[2], level+1);
		break;
	}
}


void
printmnp(Msg_node *mnp, int level)
{
	gprintf(level, "=== mnp ===\n");

	gprintf(level, "   type: \"%s\"\n",
		mnp->type == T_ILL_MO ? "T_ILL_MO" :
		mnp->type == T_SUN_MO ? "T_SUN_MO" :
		mnp->type == T_GNU_MO ? "T_GNU_MO" :
		"UNKNOWN TYPE");
	gprintf(level, "   path: \"%s\"\n",
		mnp->path ? mnp->path : "(null)");
	gprintf(level, "   msg_file_trusted: %d\n",
		mnp->trusted);
	if (mnp->type == T_SUN_MO)
		printsunmsg(mnp->msg.sunmsg, level+1);
	else if (mnp->type == T_GNU_MO)
		printgnumsg(mnp->msg.gnumsg, level+1);
	gprintf(level, "   next: 0x%p\n", (void *)mnp->next);
}

void
printcnp(Cache_node *cnp, int level)
{
	gprintf(level, "=== cnp ===\n");

	gprintf(level, "   hashid: %d\n", cnp->hashid);
	gprintf(level, "   m_node: 0x%p\n", (void *)cnp->m_node);
	if (cnp->m_node)
		printmnp(cnp->m_node, level+1);
	gprintf(level, "   m_last: 0x%p\n", (void *)cnp->m_last);
	if (cnp->m_last)
		printmnp(cnp->m_last, level+1);
	gprintf(level, "   n_node: 0x%p\n", (void *)cnp->n_node);
	gprintf(level, "   next: 0x%p\n", (void *)cnp->next);
}

void
printcp(struct cache_pack *cp, int level)
{
	gprintf(level, "=== cp ===\n");
	gprintf(level, "   cacheline: %d\n", cp->cacheline);
	gprintf(level, "   mnp: 0x%p\n", (void *)cp->mnp);
	if (cp->mnp)
		printmnp(cp->mnp, level+1);
	gprintf(level, "   cnp: 0x%p\n", (void *)cp->cnp);
	if (cp->cnp)
		printcnp(cp->cnp, level+1);
	gprintf(level, "   node_hash: 0x%p\n", (void *)cp->node_hash);
	if (cp->node_hash)
		printcnp(cp->node_hash, level+1);
}
#endif
