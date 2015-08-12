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
 *	domain_len - length of domain name
 *
 * OUTPUT
 * mp->msgfile - pathname to the message file is stored
 *
 * RETURN
 * mp->msgfile is returned
 */
char *
mk_msgfile(struct msg_pack *mp)
{
	const char *q;
	char	*p;
	const char	*catstr;
	uint32_t	cblen, loclen, catlen, totallen;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** mk_msgfile(0x%p)\n", (void *)mp);
	printmp(mp, 1);
#endif

	p = mp->msgfile;
	q = mp->binding;
	while (*p = *q++)
		p++;
	cblen = (uint32_t)(p - mp->msgfile);
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

	loclen = strlen(mp->locale);
	catstr = category_name[mp->category];
	catlen = (uint32_t)category_name_len[mp->category];
	/*
	 * totallen is the length of the msgfile
	 * pathname excluding a null termination.
	 */

	totallen = cblen + loclen + 1 + catlen + 1 +
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
	while (*p = *q++)
		p++;
	q = MSGFILESUFFIX;
	while (*p++ = *q++)
		;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** Exiting mk_msgfile\n");
	gprintf(0, "mp->msgfile: \"%s\"\n", mp->msgfile);
#endif

	return (mp->msgfile);
}

/*
 * check_cache
 *
 * INPUT
 * mp - may use the following members:
 *	msgfile - pathname to the message catalog file
 *	hash_domain - hash id of this domain
 *
 * RETURN
 * non-NULL
 *	pointer to the Msg_node object of the current message catalog
 *	found in the cache
 *
 * NULL
 *	this message catalog does not exist in the cache
 */
Msg_node *
check_cache(struct msg_pack *mp)
{
	Msg_node	*cur_msg, *mnp;
	Gettext_t	*gt = global_gt;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** check_cache(0x%p)\n", mp);
	printmp(mp, 1);
#endif

	cur_msg = gt->c_m_node;		/* current Msg_node */
	if (cur_msg &&
	    cur_msg->hashid == mp->hash_domain &&
	    strcmp(cur_msg->path, mp->msgfile) == 0) {
		/*
		 * msgfile is the same as the previous message file
		 */
#ifdef GETTEXT_DEBUG
		gprintf(0, "*** cache found\n");
		gprintf(0, "************* exiting check_cache\n");
		printmnp(cur_msg, 1);
#endif
		return (cur_msg);
	}
	mnp = gt->m_node;
	while (mnp) {
#ifdef GETTEXT_DEBUG
		gprintf(0, "========== descending the list\n");
		gprintf(0, "  hashid: %d, hash_domain: %d\n",
		    mnp->hashid, mp->hash_domain);
		printmnp(mnp, 1);
#endif
		if (mnp->hashid == mp->hash_domain &&
		    strcmp(mnp->path, mp->msgfile) == 0) {
#ifdef GETTEXT_DEBUG
			gprintf(0, "*** cache found\n");
			gprintf(0, "******* exiting check_cache\n");
			printmnp(mnp, 1);
#endif
			gt->c_m_node = mnp;
			return (mnp);
		}
		mnp = mnp->next;
	}

#ifdef GETTEXT_DEBUG
	gprintf(0, "*** cache not found\n");
	gprintf(0, "******* exiting check_cache\n");
#endif
	return (NULL);
}

char *
get_codeset(const char *domain)
{
	char	*codeset;

#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** get_codeset(\"%s\")\n",
	    domain ? domain : "(null)");
#endif

	codeset = _real_bindtextdomain_u(domain, NULL, TP_CODESET);
	if (codeset == NULL) {
		/* no codeset is bound to this domain */
		codeset = nl_langinfo(CODESET);
	}
#ifdef GETTEXT_DEBUG
	gprintf(0, "*************** existing get_codeset(\"%s\")\n",
	    domain ? domain : "(null)");
	gprintf(0, "                = \"%s\"\n", codeset);
#endif

	return (codeset);
}

/*
 * get_hashid (hashpjw)
 *
 * Calculates the hash value from the specified string.
 * Actual hashid will be mod(hash value, PRIME_NUMBER).
 *
 * Ref: Compilers - Principles, Techniques, and Tools
 * Aho, Sethi, and Ullman
 */
uint32_t
get_hashid(const char *str, uint32_t *len)
{
	const unsigned char	*p = (unsigned char *)str;
	uint32_t	h = 0;
	uint32_t	g;

	for (; *p; p++) {
		h = (h << 4) + *p;
		g = h & 0xf0000000;
		if (g) {
			h = h ^ (g >> 24);
			h = h ^ g;
		}
	}

	if (len)
		*len = (uint32_t)(p - (unsigned char *)str);
	return (h);
}

uint32_t
doswap32(uint32_t n)
{
	uint32_t	r;

	r = (n << 24) | ((n & 0xff00) << 8) |
	    ((n >> 8) & 0xff00) | (n >> 24);
	return (r);
}

#ifdef GETTEXT_DEBUG
static uint32_t
search_msg(Msg_g_node *p, const char *id, uint32_t hash_val,
    struct gnu_msg_ent *m)
{
	char	*base = (char *)p->msg_file_info;
	uint32_t	hash_size, num_of_str, i, idx, inc;
	char	*ms;

	num_of_str = p->num_of_str;
	hash_size = p->hash_size;
	idx = hash_val % hash_size;
	inc = 1 + (hash_val % (hash_size - 2));

	while ((i = p->hash_table[idx]) != 0) {
		ms = (i <= num_of_str) ?
		    base + SWAP(p, m[i-1].offset) :
		    p->mchunk + p->d_msg[MSGID][i-num_of_str-1].offset;
		if (strcmp(id, ms) == 0) {
			/* found */
			return (i);
		}
		idx = (idx + inc) % hash_size;
	}
	/* not found */
	return (0);
}

void
print_rev1_info(Msg_g_node *p)
{
	char	*base = (char *)p->msg_file_info;
	struct gnu_msg_info	*header = p->msg_file_info;
	struct gnu_msg_ent	*m;
	uint32_t	hv, hidx;
	char	*ms;
	enum gnu_msgidstr	v;
	int	x;

#ifdef	GETTEXT_DEBUG_DYMMSG
	gprintf(0, "******** dynamic msgid/msgstr\n");
	for (v = MSGID; v <= MSGSTR; v++) {
		for (x = 0; x < p->num_of_d_str; x++) {
			gprintf(0, "len: %u\n", p->d_msg[v][x].len);
			gprintf(0, "str: \"%s\"\n",
			    p->mchunk + p->d_msg[v][x].offset);
		}
	}
#endif
#ifdef	GETTEXT_DEBUG_HASHTBL
	gprintf(0, "******** dynamic hash table\n");
	for (x = 0; x < p->hash_size; x++) {
		gprintf(0, "%d: %u\n", x, p->hash_table[x]);
	}
#endif
#ifdef	GETTEXT_DEBUG_CHECK_STMSGID
	gprintf(0, "******** sanity check of static msgid\n");
	m = (struct gnu_msg_ent *)(uintptr_t)
	    (base + SWAP(p, header->off_msgid_tbl));
	for (x = 0; x < p->num_of_str; x++) {
		ms = base + SWAP(p, m[x].offset);
		gprintf(0, "\"%s\"\n", ms);
		hv = get_hashid(ms, NULL);
		hidx = search_msg(p, ms, hv, m);
		if (hidx == 0) {
			gprintf(0,
			    "failed to find this msg in the hash table\n");
		} else {
			if (hidx != x + 1) {
				gprintf(0, "hash table mismatch\n");
			}
		}
	}
#endif
#ifdef	GETTEXT_DEBUG_CHECK_DYMMSGID
	gprintf(0, "******* sanity check of dynamic msgid\n");
	m = (struct gnu_msg_ent *)(uintptr_t)
	    (base + SWAP(p, header->off_msgid_tbl));
	for (x = 0; x < p->num_of_d_str; x++) {
		ms = p->mchunk + p->d_msg[MSGID][x].offset;
		gprintf(0, "\"%s\"\n", ms);
		hv = get_hashid(ms, NULL);
		hidx = search_msg(p, ms, hv, m);
		if (hidx == 0) {
			gprintf(0,
			    "failed to find this msg in the hash table\n");
		} else {
			if (hidx != x + p->num_of_str + 1) {
				gprintf(0, "hash table mismatch\n");
			}
		}
	}
#endif
}

void
gprintf(int level, const char *format, ...)
{
	va_list	ap;

	va_start(ap, format);

	while (level-- > 0) {
		(void) fputs("   ", stdout);
	}
	(void) vprintf(format, ap);
	va_end(ap);

	(void) fflush(stdout);
}

void
printlist(void)
{
	struct domain_binding	*ppp;
	Gettext_t	*gt = global_gt;

	gprintf(0, "=== Printing default list and regural list\n");
	gprintf(0, "   Default domain=<%s>, binding=<%s>\n",
	    DEFAULT_DOMAIN, defaultbind);

	ppp = FIRSTBIND(gt);
	while (ppp) {
		gprintf(0, "   domain=<%s>, binding=<%s>, codeset=<%s>\n",
		    ppp->domain ? ppp->domain : "(null)",
		    ppp->binding ? ppp->binding : "(null)",
		    ppp->codeset ? ppp->codeset : "(null)");
		ppp = ppp->next;
	}
	(void) fflush(stdout);
}

void
printmp(struct msg_pack *mp, int level)
{
	gprintf(level, "=== mp ===\n");
	gprintf(level, "   msgid1: \"%s\"\n",
	    mp->msgid1 ? mp->msgid1 : "(null)");
	gprintf(level, "   msgid2: \"%s\"\n",
	    mp->msgid2 ? mp->msgid2 : "(null)");
	gprintf(level, "   msgfile: \"%s\"\n",
	    mp->msgfile ? mp->msgfile : "(null)");
	gprintf(level, "   domain: \"%s\"\n",
	    mp->domain ? mp->domain : "(null)");
	gprintf(level, "   binding: \"%s\"\n",
	    mp->binding ? mp->binding : "(null)");
	gprintf(level, "   locale: \"%s\"\n",
	    mp->locale ? mp->locale : "(null)");
	gprintf(level, "   language: \"%s\"\n",
	    mp->language ? mp->language : "(null)");
	gprintf(level, "   addr: 0x%p\n", mp->addr);
	gprintf(level, "   fsz: %d\n", mp->fsz);
	gprintf(level, "   hash_domain: %d\n", mp->hash_domain);
	gprintf(level, "   domain_len: %d\n", mp->domain_len);
	gprintf(level, "   n: %d\n", mp->n);
	gprintf(level, "   category: \"%s\"\n",
	    category_name[mp->category]);
	gprintf(level, "   plural: %d\n", mp->plural);
	gprintf(level, "   nlsp: %d\n", mp->nlsp);
	gprintf(level, "   trusted: %d\n", mp->trusted);
	gprintf(level, "   status: %d\n", mp->status);
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
	gprintf(level, "   msg_file_info: 0x%p\n", gmnp->msg_file_info);
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
	if (gmnp->flag & ST_REV1) {
		struct gnu_msg_rev1_info	*a =
		    (struct gnu_msg_rev1_info *)(uintptr_t)
		    ((char *)gmnp->msg_file_info +
		    sizeof (struct gnu_msg_info));
		gprintf(level, "      num_of_dynamic_macro: %d\n",
		    SWAP(gmnp, a->num_of_dynamic_macro));
		gprintf(level, "      off_dynamic_macro: %d\n",
		    SWAP(gmnp, a->off_dynamic_macro));
		gprintf(level, "      num_of_dynamic_str: %d\n",
		    SWAP(gmnp, a->num_of_dynamic_str));
		gprintf(level, "      off_dynamic_msgid_tbl: %d\n",
		    SWAP(gmnp, a->off_dynamic_msgid_tbl));
		gprintf(level, "      off_dynamic_msgstr_tbl: %d\n",
		    SWAP(gmnp, a->off_dynamic_msgstr_tbl));
	}
	gprintf(level, "   fsize: %lu\n", gmnp->fsize);
	gprintf(level, "   flag: %08x\n", gmnp->flag);
	gprintf(level, "   num_of_str: %u\n", gmnp->num_of_str);
	gprintf(level, "   num_of_d_str: %u\n", gmnp->num_of_d_str);
	gprintf(level, "   hash_size: %u\n", gmnp->hash_size);
	gprintf(level, "   hash_table: 0x%p\n", (void *)gmnp->hash_table);
	gprintf(level, "   d_msgid: 0x%p\n", (void *)gmnp->d_msg[MSGID]);
	gprintf(level, "   d_msgstr: 0x%p\n", (void *)gmnp->d_msg[MSGSTR]);
	gprintf(level, "   mchunk: 0x%p\n", (void *)gmnp->mchunk);

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

	gprintf(level, "   hashid: %d\n", mnp->hashid);
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
printnls(Nls_node *n, int level)
{
	gprintf(level, "=== nls ===\n");
	gprintf(level, "   domain: \"%s\"\n", n->domain ? n->domain : "NULL");
	gprintf(level, "   locale: \"%s\"\n", n->locale ? n->locale : "NULL");
	gprintf(level, "   nlspath: \"%s\"\n", n->nlspath ? n->nlspath :
	    "NULL");
	gprintf(level, "   next: 0x%p\n", n->next);
}

void
printdbind(Dbinding *d, int level)
{
	gprintf(level, "=== dbind ===\n");
	gprintf(level, "   domain: \"%s\"\n", d->domain ? d->domain : "NULL");
	gprintf(level, "   binding: \"%s\"\n", d->binding ? d->binding :
	    "NULL");
	gprintf(level, "   codeset: \"%s\"\n", d->codeset ? d->codeset :
	    "NULL");
	gprintf(level, "   next: 0x%p\n", d->next);
}

void
printgt(Gettext_t *gt, int level)
{
	gprintf(level, "=== gt ===\n");
	gprintf(level, "   cur_domain: \"%s\"\n", gt->cur_domain);
	if (gt->dbind) {
		printdbind(gt->dbind, level+1);
	} else {
		gprintf(level, "   dbind: NULL\n");
	}
	if (gt->m_node) {
		printmnp(gt->m_node, level + 1);
	} else {
		gprintf(level, "   m_node: NULL\n");
	}
	if (gt->n_node) {
		printnls(gt->n_node, level + 1);
	} else {
		gprintf(level, "   n_node: NULL\n");
	}
	if (gt->c_m_node) {
		printmnp(gt->c_m_node, level + 1);
	} else {
		gprintf(level, "   c_m_node: NULL\n");
	}
	if (gt->c_n_node) {
		printnls(gt->c_n_node, level + 1);
	} else {
		gprintf(level, "   c_n_node: NULL\n");
	}
}

#endif
