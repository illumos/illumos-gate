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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "synonyms.h"
#include <mtlib.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nss_dbdefs.h>
#include <limits.h>
#include <dlfcn.h>
#include <link.h>
#include <thread.h>
#include <atomic.h>
/* headers for key2str/str2key routines */
#include <sys/ethernet.h>
#include <exec_attr.h>
#include <grp.h>

/*
 * functions in nss_dbdefs.c deal more with the mechanics of
 * the data structures like nss_XbyY_args_t and the interaction
 * with the packed buffers etc.  versus the mechanics of the
 * actual policy component operations such as nss_search sequencing.
 */

/*
 * ALIGN? is there an official definition of this?
 * We use sizeof(long) to cover what we want
 * for both the 32-bit world and 64-bit world.
 */

#define	ALIGN(x) ((((long)(x)) + sizeof (long) - 1) & ~(sizeof (long) - 1))

nss_XbyY_buf_t *
_nss_XbyY_buf_alloc(int struct_size, int buffer_size)
{
	nss_XbyY_buf_t	*b;

	/* Use one malloc for dbargs, result struct and buffer */
	b = (nss_XbyY_buf_t *)
	    malloc(ALIGN(sizeof (*b)) + struct_size + buffer_size);
	if (b == 0) {
		return (0);
	}
	b->result = (void *)ALIGN(&b[1]);
	b->buffer = (char *)(b->result) + struct_size;
	b->buflen = buffer_size;
	return (b);
}

void
_nss_XbyY_buf_free(nss_XbyY_buf_t *b)
{
	if (b != 0) {
		free(b);
	}
}

/* === Comment:  used by fget{gr,pw,sp}ent */
/* ==== Should do ye olde syslog()ing of suspiciously long lines */

void
_nss_XbyY_fgets(FILE *f, nss_XbyY_args_t *b)
{
	char		buf[LINE_MAX];
	int		len, parsestat;

	if (fgets(buf, LINE_MAX, f) == 0) {
		/* End of file */
		b->returnval = 0;
		b->erange    = 0;
		return;
	}
	len = (int)strlen(buf);
	/* len >= 0 (otherwise we would have got EOF) */
	if (buf[len - 1] != '\n') {
		if ((len + 1) == LINE_MAX) {
			/* Line too long for buffer; too bad */
			while (fgets(buf, LINE_MAX, f) != 0 &&
			    buf[strlen(buf) - 1] != '\n') {
				;
			}
			b->returnval = 0;
			b->erange    = 1;
			return;
		}
		/* case where the file is not terminated with a Newline */
		len++;
	}
	parsestat = (*b->str2ent)(buf, (len - 1), b->buf.result, b->buf.buffer,
	    b->buf.buflen);
	if (parsestat == NSS_STR_PARSE_ERANGE) {
		b->returnval = 0;
		b->erange    = 1;
	} else if (parsestat == NSS_STR_PARSE_SUCCESS) {
		b->returnval = b->buf.result;
	}
}

/*
 * parse the aliases string into the buffer and if successful return
 * a char ** pointer to the beginning of the aliases.
 *
 * CAUTION: (instr, instr+lenstr) and (buffer, buffer+buflen) are
 * non-intersecting memory areas. Since this is an internal interface,
 * we should be able to live with that.
 */
char **
_nss_netdb_aliases(const char *instr, int lenstr, char *buffer, int buflen)
	/* "instr" is the beginning of the aliases string */
	/* "buffer" has the return val for success */
	/* "buflen" is the length of the buffer available for aliases */
{
	/*
	 * Build the alias-list in the start of the buffer, and copy
	 * the strings to the end of the buffer.
	 */
	const char
		*instr_limit	= instr + lenstr;
	char	*copyptr	= buffer + buflen;
	char	**aliasp	= (char **)ROUND_UP(buffer, sizeof (*aliasp));
	char	**alias_start	= aliasp;
	int	nstrings	= 0;

	for (;;) {
		const char	*str_start;
		size_t		str_len;

		while (instr < instr_limit && isspace(*instr)) {
			instr++;
		}
		if (instr >= instr_limit || *instr == '#') {
			break;
		}
		str_start = instr;
		while (instr < instr_limit && !isspace(*instr)) {
			instr++;
		}

		++nstrings;

		str_len = instr - str_start;
		copyptr -= str_len + 1;
		if (copyptr <= (char *)(&aliasp[nstrings + 1])) {
			/* Has to be room for the pointer to */
			/* the alias we're about to add,   */
			/* as well as the final NULL ptr.  */
			return (0);
		}
		*aliasp++ = copyptr;
		(void) memcpy(copyptr, str_start, str_len);
		copyptr[str_len] = '\0';
	}
	*aliasp++ = 0;
	return (alias_start);
}


extern nss_status_t process_cstr(const char *, int, struct nss_groupsbymem *);

/*
 * pack well known getXbyY keys to packed buffer prior to the door_call
 * to nscd.  Some consideration is given to ordering the tests based on
 * usage.  Note: buf is nssuint_t aligned.
 */

typedef struct {
	const char	*name;		/* NSS_DBNAM_* */
	const char	*defconf;	/* NSS_DEFCONF_* */
	const char	*initfn;	/* init function name */
	const char	*strfn;		/* str2X function name */
	const char	*cstrfn;	/* cstr2X function name */
	void		*initfnp;	/* init function pointer */
	void		*strfnp;	/* str2X function pointer */
	uint32_t	dbop;		/* NSS_DBOP_* */
	const char	*tostr;		/* key2str cvt str */
} getXbyY_to_dbop_t;

#define	NSS_MK_GETXYDBOP(x, y, f, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##x, "_nss_initf_" f, "str2" f, \
		NULL, NULL, NULL, NSS_DBOP_##x##_##y, (e) }

#define	NSS_MK_GETXYDBOPA(x, a, f, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##x, "_nss_initf_" f, "str2" f, \
		NULL, NULL, NULL, NSS_DBOP_##a, (e) }

#define	NSS_MK_GETXYDBOPB(x, b, a, f, s, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##b, "_nss_initf_" f, s,  \
		NULL, NULL, NULL, NSS_DBOP_##a, (e) }

#define	NSS_MK_GETXYDBOPC(x, a, f, s, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##x, "_nss_initf_" f, s, \
		NULL, NULL, NULL, NSS_DBOP_##x##_##a, (e) }

#define	NSS_MK_GETXYDBOPD(x, y, i, f, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##x, "_nss_initf_" i, "str2" f, \
		NULL, NULL, NULL, NSS_DBOP_##x##_##y, (e) }

#define	NSS_MK_GETXYDBOPCSTR(x, a, f, s, e)	\
	{ NSS_DBNAM_##x, NSS_DEFCONF_##x, "_nss_initf_" f, s, \
		"process_cstr", NULL, NULL, NSS_DBOP_##x##_##a, (e) }

/*
 * The getXbyY_to_dbop structure is hashed on first call in order to
 * reduce the search time for the well known getXbyY operations.
 * A binary search was not fast enough.  There were on average
 * 3-4 tests (strcmps) per getXbyY call.
 *
 * DBOP_PRIME_HASH must be a prime number (reasonably small) but that
 * is sufficient to uniquely map the entries in the following table
 * without collision.
 *
 * The DBOP_PRIME_HASH was selected as the smallest hash value
 * for this table without collisions. Changing this table WILL
 * necessitate re-testing for possible collisions.
 */

#define	DBOP_PRIME_HASH		223
#define	DBOP_HASH_TAG		0xf0000000
static int getXbyYdbopHASH[DBOP_PRIME_HASH] = { 0 };
static mutex_t getXbydbop_hash_lock = DEFAULTMUTEX;
static int getXbyYdbop_hashed = 0;

static getXbyY_to_dbop_t getXbyY_to_dbop[] = {
	/* NSS_MK_GETXYDBOP(ALIASES, ?, ?), */
	NSS_MK_GETXYDBOPD(AUDITUSER, BYNAME, "auuser", "audituser", "n"),
	NSS_MK_GETXYDBOP(AUTHATTR, BYNAME, "authattr", "n"),
	/* NSS_MK_GETXYDBOP(AUTOMOUNT, ?, ?), */
	NSS_MK_GETXYDBOP(BOOTPARAMS, BYNAME, "bootparams", "n"),
	NSS_MK_GETXYDBOPC(ETHERS, HOSTTON, "ethers", "str2ether", "n"),
	NSS_MK_GETXYDBOPC(ETHERS, NTOHOST, "ethers", "str2ether", "e"),
	NSS_MK_GETXYDBOP(EXECATTR, BYNAME, "execattr", "A"),
	NSS_MK_GETXYDBOP(EXECATTR, BYID, "execattr", "A"),
	NSS_MK_GETXYDBOP(EXECATTR, BYNAMEID, "execattr", "A"),
	NSS_MK_GETXYDBOP(GROUP, BYNAME, "group", "n"),
	NSS_MK_GETXYDBOP(GROUP, BYGID, "group", "g"),
	NSS_MK_GETXYDBOPCSTR(GROUP, BYMEMBER, "group", "str2group", "I"),
	NSS_MK_GETXYDBOPC(HOSTS, BYNAME, "hosts", "str2hostent", "n"),
	NSS_MK_GETXYDBOPC(HOSTS, BYADDR, "hosts", "str2hostent", "h"),
	NSS_MK_GETXYDBOPC(IPNODES, BYNAME, "ipnodes", "str2hostent", "i"),
	NSS_MK_GETXYDBOPC(IPNODES, BYADDR, "ipnodes", "str2hostent", "h"),
	NSS_MK_GETXYDBOP(NETGROUP, IN, "netgroup", "t"),
	NSS_MK_GETXYDBOP(NETGROUP, SET, "netgroup", "T"),
	NSS_MK_GETXYDBOPC(NETMASKS, BYNET, "netmasks", "str2addr", "n"),
	NSS_MK_GETXYDBOPC(NETWORKS, BYNAME, "net", "str2netent", "n"),
	NSS_MK_GETXYDBOPC(NETWORKS, BYADDR, "net", "str2netent", "a"),
	NSS_MK_GETXYDBOP(PASSWD, BYNAME, "passwd", "n"),
	NSS_MK_GETXYDBOP(PASSWD, BYUID, "passwd", "u"),
	NSS_MK_GETXYDBOP(PRINTERS, BYNAME, "printers", "n"),
	NSS_MK_GETXYDBOP(PROFATTR, BYNAME, "profattr", "n"),
	NSS_MK_GETXYDBOP(PROJECT, BYNAME, "project", "n"),
	NSS_MK_GETXYDBOP(PROJECT, BYID, "project", "p"),
	NSS_MK_GETXYDBOPC(PROTOCOLS, BYNAME, "proto", "str2protoent", "n"),
	NSS_MK_GETXYDBOPC(PROTOCOLS, BYNUMBER, "proto", "str2protoent", "N"),
	NSS_MK_GETXYDBOPA(PUBLICKEY, KEYS_BYNAME, "publickey", "k"),
	NSS_MK_GETXYDBOPC(RPC, BYNAME, "rpc", "str2rpcent", "n"),
	NSS_MK_GETXYDBOPC(RPC, BYNUMBER, "rpc", "str2rpcent", "N"),
	NSS_MK_GETXYDBOPC(SERVICES, BYNAME, "services", "str2servent", "s"),
	NSS_MK_GETXYDBOPC(SERVICES, BYPORT, "services", "str2servent", "S"),
	NSS_MK_GETXYDBOPB(SHADOW, PASSWD, PASSWD_BYNAME, "shadow",
				"str2spwd", "n"),
	NSS_MK_GETXYDBOPC(TSOL_RH, BYADDR, "tsol_rh", "str_to_rhstr", "h"),
	NSS_MK_GETXYDBOPC(TSOL_TP, BYNAME, "tsol_tp", "str_to_tpstr", "n"),
	NSS_MK_GETXYDBOPC(TSOL_ZC, BYNAME, "tsol_zc", "str_to_zcstr", "n"),
	NSS_MK_GETXYDBOP(USERATTR, BYNAME, "userattr", "n"),
};

static int
nss_dbop_search(const char *name, uint32_t dbop)
{
	getXbyY_to_dbop_t *hptr;
	int count = (sizeof (getXbyY_to_dbop) / sizeof (getXbyY_to_dbop_t));
	uint32_t hval, g;
	const char *cp;
	int i, idx;

	/* Uses a table size is known to have no collisions */
	if (getXbyYdbop_hashed == 0) {
		lmutex_lock(&getXbydbop_hash_lock);
		if (getXbyYdbop_hashed == 0) {
			for (i = 0; i < count; i++) {
				cp = getXbyY_to_dbop[i].name;
				hval = 0;
				while (*cp) {
					hval = (hval << 4) + *cp++;
					if ((g = (hval & 0xf00000000)) != 0)
						hval ^= g >> 24;
					hval &= ~g;
				}
				hval += getXbyY_to_dbop[i].dbop;
				hval %= DBOP_PRIME_HASH;
				if (getXbyYdbopHASH[hval] != 0) {
					/* hash table collision-see above */
					lmutex_unlock(&getXbydbop_hash_lock);
					return (-1);
				}
				getXbyYdbopHASH[hval] = i | DBOP_HASH_TAG;
			}
			membar_producer();
			getXbyYdbop_hashed = 1;
		}
		lmutex_unlock(&getXbydbop_hash_lock);
	}
	membar_consumer();
	cp = name;
	hval = 0;
	while (*cp) {
		hval = (hval << 4) + *cp++;
		if ((g = (hval & 0xf00000000)) != 0)
			hval ^= g >> 24;
		hval &= ~g;
	}
	hval += dbop;
	hval %= DBOP_PRIME_HASH;
	idx = getXbyYdbopHASH[hval];
	if ((idx & DBOP_HASH_TAG) != DBOP_HASH_TAG)
		return (-1);
	idx &= ~DBOP_HASH_TAG;
	if (idx >= count)
		return (-1);
	hptr = &getXbyY_to_dbop[idx];
	if (hptr->dbop != dbop || strcmp(name, hptr->name) != 0)
		return (-1);
	return (idx);
}

/*
 * nss_pack_key2str
 * Private key to string packing function for getXbyY routines
 * This routine performs a printf like parse over the argument
 * key, given a string of items to pack and assembles the key in
 * the packed structure.  This routine is called (currently) by
 * nss_default_key2str, but will be used by other external
 * APIs in the future.
 *
 * buffer - Start of the key buffer location [in packed buffer]
 * length - Length of key buffer component
 * Key offsets are relative to start of key buffer location.
 *
 * Pack fields			Key
 *   key.name			n
 *   key.number			N
 *   key.uid			u
 *   key.gid			g
 *   key.hostaddr		h
 *   key.ipnode			i
 *   key.projid			p
 *   key.serv(name)		s
 *   key.serv(port)		S
 *   key.ether			e
 *   key.pkey			k
 *   key.netaddr		a
 *   key.attrp			A
 *   groupsbymember		I
 *   innetgr_args		t
 *   setnetgr_args		T
 */

/*ARGSUSED*/
static nss_status_t
nss_pack_key2str(void *buffer, size_t length, nss_XbyY_args_t *arg,
	const char *dbname, int dbop, size_t *rlen, const char *typestr)
{
	int				i, j;
	size_t				len, len2, len3, len4, len5, slop;
	nssuint_t 			*uptr, offv, offc;
	struct nss_setnetgrent_args	*sng;
	struct nss_innetgr_args		*ing;
	struct nss_groupsbymem		*gbm;
	char				**cv, *dptr;
	nss_pnetgr_t			*pptr;
	_priv_execattr			*pe;

	if (buffer == NULL || length == 0 || arg == NULL ||
	    dbname == NULL || rlen == NULL || typestr == NULL)
		return (NSS_ERROR);

	while (typestr && *typestr) {
		switch (*typestr++) {
		case 'n':
			if (arg->key.name == NULL)
				return (NSS_NOTFOUND);
			len = strlen(arg->key.name) + 1;
			if (len >= length)
				return (NSS_ERROR);
			(void) strlcpy(buffer, arg->key.name, len);
			*rlen = len;
			break;
		case 'N':
			len = sizeof (nssuint_t);
			if (len >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer = (nssuint_t)arg->key.number;
			*rlen = len;
			break;
		case 'u':
			len = sizeof (nssuint_t);
			if (len >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer = (nssuint_t)arg->key.uid;
			*rlen = len;
			break;
		case 'g':
			len = sizeof (nssuint_t);
			if (len >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer = (nssuint_t)arg->key.gid;
			*rlen = len;
			break;
		case 'h':
			if (arg->key.hostaddr.addr == NULL)
				return (-1);
			len = arg->key.hostaddr.len;
			len = ROUND_UP(len, sizeof (nssuint_t));
			len2 = (sizeof (nssuint_t) * 2) + len;
			if (len2 >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer =
			    (nssuint_t)arg->key.hostaddr.len;
			buffer = (void *)((char *)buffer + sizeof (nssuint_t));
			*(nssuint_t *)buffer =
			    (nssuint_t)arg->key.hostaddr.type;
			buffer = (void *)((char *)buffer + sizeof (nssuint_t));
			(void) memcpy(buffer, arg->key.hostaddr.addr,
			    arg->key.hostaddr.len);
			*rlen = len2;
			break;
		case 'i':
			if (arg->key.ipnode.name == NULL)
				return (NSS_NOTFOUND);
			len = strlen(arg->key.ipnode.name) + 1;
			len = ROUND_UP(len, sizeof (nssuint_t));
			len2 = (sizeof (nssuint_t) * 2) + len;
			if (len2 >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer =
			    (nssuint_t)arg->key.ipnode.af_family;
			buffer = (void *)((char *)buffer + sizeof (nssuint_t));
			*(nssuint_t *)buffer =
			    (nssuint_t)arg->key.ipnode.flags;
			buffer = (void *)((char *)buffer + sizeof (nssuint_t));
			(void) strlcpy(buffer, arg->key.ipnode.name, len);
			*rlen = len2;
			break;
		case 'p':
			len = sizeof (nssuint_t);
			if (len >= length)
				return (NSS_ERROR);
			*(nssuint_t *)buffer = (nssuint_t)arg->key.projid;
			*rlen = len;
			break;
		case 's':
			if (arg->key.serv.serv.name == NULL)
				return (NSS_NOTFOUND);
			len = strlen(arg->key.serv.serv.name) + 1;
			len2 = 1;
			if (arg->key.serv.proto != NULL)
				len2 += strlen(arg->key.serv.proto);
			len3 = len + len2;
			len3 = ROUND_UP(len3, sizeof (nssuint_t));
			if (len3 >= length)
				return (NSS_ERROR);
			(void) strlcpy(buffer, arg->key.serv.serv.name, len);
			buffer = (void *)((char *)buffer + len);
			if (len2 > 1)
				(void) strlcpy(buffer, arg->key.serv.proto,
				    len2);
			else
				*(char *)buffer = '\0';
			*rlen = len3;
			break;
		case 'S':
			len2 = 0;
			if (arg->key.serv.proto != NULL)
				len2 = strlen(arg->key.serv.proto) + 1;
			len = sizeof (nssuint_t) + len2;
			if (len >= length)
				return (NSS_ERROR);
			uptr = (nssuint_t *)buffer;
			*uptr++ = (nssuint_t)arg->key.serv.serv.port;
			if (len2) {
				(void) strlcpy((char *)uptr,
				    arg->key.serv.proto, len2);
			}
			*rlen = len;
			break;
		case 'e':
			if (arg->key.ether == NULL)
				return (NSS_NOTFOUND);
			len = sizeof (struct ether_addr);
			len = ROUND_UP(len, sizeof (nssuint_t));
			if (len >= length)
				return (NSS_ERROR);
			*(struct ether_addr *)buffer =
			    *(struct ether_addr *)arg->key.ether;
			*rlen = len;
			break;
		case 'k':
			if (arg->key.pkey.name == NULL ||
			    arg->key.pkey.keytype == NULL)
				return (NSS_NOTFOUND);
			len = strlen(arg->key.pkey.name) + 1;
			len2 = strlen(arg->key.pkey.keytype) + 1;
			len3 = len + len2;
			len3 = ROUND_UP(len3, sizeof (nssuint_t));
			if (len3 >= length)
				return (NSS_ERROR);
			(void) strlcpy(buffer, arg->key.pkey.name, len);
			buffer = (void *)((char *)buffer + len);
			(void) strlcpy(buffer, arg->key.pkey.keytype, len2);
			*rlen = len3;
			break;
		case 'a':
			uptr = (nssuint_t *)buffer;
			len = sizeof (nssuint_t) * 2;
			if (len >= length)
				return (NSS_ERROR);
			*uptr++ = (nssuint_t)arg->key.netaddr.net;
			*uptr++ = (nssuint_t)arg->key.netaddr.type;
			*rlen = len;
			break;
		case 'A':
			pe = (_priv_execattr *)(arg->key.attrp);
			if (pe == NULL)
				return (NSS_NOTFOUND);
			/* for search flag */
			len = sizeof (nssuint_t);
			/* for sizeof (_priv_execattr) static buffer */
			/* Plus lots of slop just in case... */
			slop = sizeof (nssuint_t) * 16;
			len += slop;

			len2 = len3 = len4 = len5 = 1;
			if (pe->name != NULL)
				len2 = strlen(pe->name) + 1;
			if (pe->type != NULL)
				len3 = strlen(pe->type) + 1;
			if (pe->id != NULL)
				len4 = strlen(pe->id) + 1;
			if (pe->policy != NULL)
				len5 = strlen(pe->policy) + 1;
			/* head_exec, prev_exec - are client side only... */
			len += len2 + len3 + len4 + len5;
			len = ROUND_UP(len, sizeof (nssuint_t));
			if (len >= length)
				return (NSS_ERROR);
			(void) memset((void *)buffer, 0, slop);
			uptr = (nssuint_t *)((void *)((char *)buffer + slop));
			*uptr++ = (nssuint_t)pe->search_flag;
			dptr = (char *)uptr;
			if (len2 == 1)
				*dptr++ = '\0';
			else {
				(void) strlcpy(dptr, pe->name, len2);
				dptr += len2;
			}
			if (len3 == 1)
				*dptr++ = '\0';
			else {
				(void) strlcpy(dptr, pe->type, len3);
				dptr += len3;
			}
			if (len4 == 1)
				*dptr++ = '\0';
			else {
				(void) strlcpy(dptr, pe->id, len4);
				dptr += len4;
			}
			if (len5 == 1)
				*dptr++ = '\0';
			else
				(void) strlcpy(dptr, pe->policy, len5);
			*rlen = len;
			break;
		case 'I':
			gbm = (struct nss_groupsbymem *)arg;
			if (gbm->username == NULL)
				return (NSS_NOTFOUND);
			len = strlen(gbm->username) + 1;
			len2 = sizeof (nssuint_t) * 4;
			len2 += ROUND_UP(len, sizeof (nssuint_t));
			if (len2 >= length)
				return (NSS_ERROR);
			uptr = (nssuint_t *)buffer;
			*uptr++ = (nssuint_t)gbm->force_slow_way;
			*uptr++ = (nssuint_t)gbm->maxgids;
			*uptr++ = (nssuint_t)gbm->numgids;
			if (gbm->numgids == 1) {
				*uptr++ = (nssuint_t)gbm->gid_array[0];
			} else {
				*uptr++ = (nssuint_t)0;
			}
			(void) strlcpy((void *)uptr, gbm->username, len);
			*rlen = len2;
			break;
		case 't':
			pptr = (nss_pnetgr_t *)buffer;
			ing = (struct nss_innetgr_args *)arg;
			len = sizeof (nss_pnetgr_t);
			len2 = ing->arg[NSS_NETGR_MACHINE].argc +
			    ing->arg[NSS_NETGR_USER].argc +
			    ing->arg[NSS_NETGR_DOMAIN].argc +
			    ing->groups.argc;
			len2 *= sizeof (nssuint_t);
			len3 = 0;
			for (j = 0; j < NSS_NETGR_N; j++) {
				cv = ing->arg[j].argv;
				for (i = ing->arg[j].argc; --i >= 0; ) {
					if (*cv)
						len3 += strlen(*cv++) + 1;
				}
			}
			cv = ing->groups.argv;
			for (i = ing->groups.argc; --i >= 0; ) {
				if (*cv)
					len3 += strlen(*cv++) + 1;
			}
			len3 = ROUND_UP(len3, sizeof (nssuint_t));
			/*
			 * Double argv space. Reason:
			 *    First 1/2 offsets
			 *    Second 1/2 for client side pointer arrays
			 *    resolves malloc/free issues with unpacked argvs
			 */
			if ((len + (len2 << 1) + len3) >= length)
				return (NSS_ERROR);
			*rlen = len + (len2 << 1) + len3;

			pptr->machine_argc = ing->arg[NSS_NETGR_MACHINE].argc;
			pptr->user_argc = ing->arg[NSS_NETGR_USER].argc;
			pptr->domain_argc = ing->arg[NSS_NETGR_DOMAIN].argc;
			pptr->groups_argc = ing->groups.argc;
			offv = len;
			uptr = (nssuint_t *)((void *)((char *)buffer + offv));
			offc = len + (len2 << 1);
			dptr = (char *)buffer + offc;
			if (pptr->machine_argc == 0) {
				pptr->machine_offv = (nssuint_t)0;
			} else {
				pptr->machine_offv = offv;
				cv = ing->arg[NSS_NETGR_MACHINE].argv;
				i = pptr->machine_argc;
				offv += sizeof (nssuint_t) * i;
				for (; --i >= 0; ) {
					*uptr++ = offc;
					len3 = strlen(*cv) + 1;
					(void) strlcpy(dptr, *cv++, len3);
					offc += len3;
					dptr += len3;
				}
			}
			if (pptr->user_argc == 0) {
				pptr->user_offv = (nssuint_t)0;
			} else {
				pptr->user_offv = offv;
				cv = ing->arg[NSS_NETGR_USER].argv;
				i = pptr->user_argc;
				offv += sizeof (nssuint_t) * i;
				for (; --i >= 0; ) {
					*uptr++ = offc;
					len3 = strlen(*cv) + 1;
					(void) strlcpy(dptr, *cv++, len3);
					offc += len3;
					dptr += len3;
				}
			}
			if (pptr->domain_argc == 0) {
				pptr->domain_offv = (nssuint_t)0;
			} else {
				pptr->domain_offv = offv;
				cv = ing->arg[NSS_NETGR_DOMAIN].argv;
				i = pptr->domain_argc;
				offv += sizeof (nssuint_t) * i;
				for (; --i >= 0; ) {
					*uptr++ = offc;
					len3 = strlen(*cv) + 1;
					(void) strlcpy(dptr, *cv++, len3);
					offc += len3;
					dptr += len3;
				}
			}
			if (pptr->groups_argc == 0) {
				pptr->groups_offv = (nssuint_t)0;
			} else {
				pptr->groups_offv = offv;
				cv = ing->groups.argv;
				i = pptr->groups_argc;
				offv += sizeof (nssuint_t) * i;
				for (; --i >= 0; ) {
					*uptr++ = offc;
					len3 = strlen(*cv) + 1;
					(void) strlcpy(dptr, *cv++, len3);
					offc += len3;
					dptr += len3;
				}
			}
			break;
		case 'T':
			sng = (struct nss_setnetgrent_args *)arg;
			if (sng->netgroup == NULL)
				return (NSS_NOTFOUND);
			len = strlen(sng->netgroup) + 1;
			if (len >= length)
				return (NSS_ERROR);
			(void) strlcpy(buffer, sng->netgroup, len);
			*rlen = len;
			break;
		default:
			return (NSS_ERROR);
		}
	}
	return (NSS_SUCCESS);
}

nss_status_t
nss_default_key2str(void *buffer, size_t length, nss_XbyY_args_t *arg,
	const char *dbname, int dbop, size_t *rlen)
{
	int		index;

	if (buffer == NULL || length == 0 || arg == NULL ||
	    dbname == NULL || rlen == NULL)
		return (NSS_ERROR);

	/*
	 * If this is not one of the well known getXbyYs
	 * (IE _printers special processing etc.) use a
	 * local (non-nscd) getXbyY lookup.
	 */
	if ((index = nss_dbop_search(dbname, (uint32_t)dbop)) < 0)
		return (NSS_TRYLOCAL);

	return (nss_pack_key2str(buffer, length, arg, dbname,
	    dbop, rlen, getXbyY_to_dbop[index].tostr));
}

/*ARGSUSED*/
void
nss_packed_set_status(void *buffer, size_t length, nss_status_t status,
		nss_XbyY_args_t *arg)
{
	nss_pheader_t 	*pbuf = (nss_pheader_t *)buffer;
	nss_dbd_t	*pdbd;
	char		*dbn;

	/* sidestep odd cases */
	pdbd = (nss_dbd_t *)((void *)((char *)buffer + pbuf->dbd_off));
	dbn = (char *)pdbd + pdbd->o_name;
	if (pbuf->nss_dbop == NSS_DBOP_GROUP_BYMEMBER) {
		if (strcmp(dbn, NSS_DBNAM_GROUP) == 0) {
			struct nss_groupsbymem *in =
			    (struct nss_groupsbymem *)arg;

			if (in->numgids >= 0) {
				pbuf->p_status = NSS_SUCCESS;
				pbuf->data_len = in->numgids *
				    sizeof (gid_t);
				pbuf->p_herrno = 0;
			} else {
				pbuf->p_status = status;
				pbuf->p_errno = errno;
				pbuf->data_len = 0;
				pbuf->p_herrno = (uint32_t)arg->h_errno;
			}
			return;
		}
	}
	if (pbuf->nss_dbop == NSS_DBOP_NETGROUP_IN) {
		if (strcmp(dbn, NSS_DBNAM_NETGROUP) == 0) {
			struct nss_innetgr_args *in =
			    (struct nss_innetgr_args *)arg;

			/* tell nss_unpack() operation is successful */
			pbuf->data_len = 1;

			if (status != NSS_SUCCESS && status != NSS_NOTFOUND) {
				pbuf->p_status = status;
				pbuf->p_errno = errno;
				return;
			}

			if (in->status == NSS_NETGR_FOUND) {
				pbuf->p_status = NSS_SUCCESS;
			} else {
				pbuf->p_status = NSS_NOTFOUND;
				pbuf->p_errno = errno;
			}
			return;
		}
	}

	/* process normal cases */
	if ((pbuf->p_status = status) != NSS_SUCCESS) {
		if (arg->erange == 1)
			pbuf->p_errno = ERANGE;
		else
			pbuf->p_errno = errno;
	} else
		pbuf->p_errno = 0;
	if (arg != NULL) {
		pbuf->p_herrno = (uint32_t)arg->h_errno;
		pbuf->data_len = (nssuint_t)arg->returnlen;
	} else {
		pbuf->p_herrno = 0;
		pbuf->data_len = 0;
	}
}

/*
 * nss_upack_key2arg
 * Private string to key unpacking function for getXbyY routines
 * This routine performs a scanf/printf like parse over the packed
 * string, to uppack and re-assemble the key in the args structure.
 *
 * buffer - Start of the key buffer location [in packed buffer]
 * length - Length of key buffer component
 * Key offsets are relative to start of key buffer location.
 *
 * Unpack fields		Key
 *   key.name			n
 *   key.number			N
 *   key.uid			u
 *   key.gid			g
 *   key.hostaddr		h
 *   key.ipnode			i
 *   key.projid			p
 *   key.serv(name)		s
 *   key.serv(port)		S
 *   key.ether			e
 *   key.pkey			k
 *   key.netaddr		a
 *   key.attrp			A
 *   groupsbymember		I
 *   innetgr_args		t
 *   setnetgr_args		T
 * Assumes arguments are all valid
 */

/*ARGSUSED*/
static nss_status_t
nss_upack_key2arg(void *buffer, size_t length, char **dbname,
		int *dbop, nss_XbyY_args_t *arg, int index)
{
	nss_pheader_t 			*pbuf = (nss_pheader_t *)buffer;
	const char			*strtype = NULL;
	nssuint_t 			off, *uptr, keysize;
	size_t				len, slop;
	int				i, j;
	char				**cv, *bptr;
	struct nss_setnetgrent_args	*sng;
	struct nss_innetgr_args		*ing;
	struct nss_groupsbymem		*gbm;
	nss_pnetgr_t			*pptr;
	_priv_execattr			*pe;

	/* keysize is length of the key area */
	keysize = pbuf->data_off - pbuf->key_off;

	off = pbuf->key_off;
	bptr = (char *)buffer + off;
	uptr = (nssuint_t *)((void *)bptr);
	strtype = getXbyY_to_dbop[index].tostr;
	if (strtype == NULL)
		return (NSS_ERROR);
	while (*strtype) {
		switch (*strtype++) {
		case 'n':
			arg->key.name = (const char *)bptr;
			break;
		case 'N':
			arg->key.number = (int)(*uptr);
			break;
		case 'u':
			arg->key.uid = (uid_t)(*uptr);
			break;
		case 'g':
			arg->key.gid = (gid_t)(*uptr);
			break;
		case 'h':
			arg->key.hostaddr.len = (int)(*uptr++);
			arg->key.hostaddr.type = (int)(*uptr++);
			arg->key.hostaddr.addr = (const char *)uptr;
			break;
		case 'i':
			arg->key.ipnode.af_family = (int)(*uptr++);
			arg->key.ipnode.flags = (int)(*uptr++);
			arg->key.ipnode.name = (const char *)uptr;
			break;
		case 'p':
			arg->key.projid = (projid_t)(*uptr);
			break;
		case 's':
			arg->key.serv.serv.name = (const char *)bptr;
			len = strlen(arg->key.serv.serv.name) + 1;
			bptr += len;
			if (*(const char *)bptr == '\0')
				arg->key.serv.proto = NULL;
			else
				arg->key.serv.proto = (const char *)bptr;
			break;
		case 'S':
			arg->key.serv.serv.port = (int)(*uptr++);
			if (pbuf->key_len == sizeof (nssuint_t)) {
				arg->key.serv.proto = NULL;
			} else {
				bptr += sizeof (nssuint_t);
				arg->key.serv.proto = (const char *)bptr;
			}
			break;
		case 'e':
			arg->key.ether = bptr;
			break;
		case 'k':
			arg->key.pkey.name = (const char *)bptr;
			len = strlen(arg->key.pkey.name) + 1;
			bptr += len;
			arg->key.pkey.keytype = (const char *)bptr;
			break;
		case 'a':
			arg->key.netaddr.net = (uint32_t)(*uptr++);
			arg->key.netaddr.type = (int)(*uptr++);
			break;
		case 'A':
			pe = (_priv_execattr *)((void *)bptr);
			/* use slop space as priv_execattr structure */
			arg->key.attrp = (void *)pe;
			/* skip over slop ... */
			slop = sizeof (nssuint_t) * 16;
			uptr = (nssuint_t *)((void *)((char *)bptr + slop));
			pe->search_flag = (int)*uptr++;
			bptr = (char *)uptr;
			if (*bptr == '\0') {
				pe->name = NULL;
				bptr++;
			} else {
				pe->name = (char *)bptr;
				bptr += strlen(pe->name) + 1;
			}
			if (*bptr == '\0') {
				pe->type = NULL;
				bptr++;
			} else {
				pe->type = (char *)bptr;
				bptr += strlen(pe->type) + 1;
			}
			if (*bptr == '\0') {
				pe->id = NULL;
				bptr++;
			} else {
				pe->id = (char *)bptr;
				bptr += strlen(pe->id) + 1;
			}
			if (*bptr == '\0') {
				pe->policy = NULL;
			} else {
				pe->policy = (char *)bptr;
			}
			pe->head_exec = NULL;
			pe->prev_exec = NULL;
			break;
		case 'I':
			gbm = (struct nss_groupsbymem *)arg;
			gbm->gid_array = (gid_t *)
			    ((void *)((char *)pbuf + pbuf->data_off));
			gbm->force_slow_way = (int)(*uptr++);
			gbm->maxgids = (int)(*uptr++);
			gbm->numgids = (int)(*uptr++);
			if (gbm->numgids == 1) {
				/* insert initial group into data area */
				gbm->gid_array[0] = (gid_t)(*uptr++);
			} else
				uptr++;
			gbm->username = (const char *)uptr;
			break;
		case 't':
			pptr = (nss_pnetgr_t *)((void *)bptr);
			ing = (struct nss_innetgr_args *)arg;
			ing->arg[NSS_NETGR_MACHINE].argc = pptr->machine_argc;
			ing->arg[NSS_NETGR_USER].argc = pptr->user_argc;
			ing->arg[NSS_NETGR_DOMAIN].argc = pptr->domain_argc;
			ing->groups.argc = pptr->groups_argc;

			/*
			 * Start of argv pointer storage
			 */
			off = ing->arg[NSS_NETGR_MACHINE].argc +
			    ing->arg[NSS_NETGR_USER].argc +
			    ing->arg[NSS_NETGR_DOMAIN].argc +
			    ing->groups.argc;
			off *= sizeof (nssuint_t);
			off += sizeof (nss_pnetgr_t);

			cv = (char **)((void *)(bptr + off));
			uptr = (nssuint_t *)
			    ((void *)(bptr + sizeof (nss_pnetgr_t)));
			for (j = 0; j < NSS_NETGR_N; j++) {
				ing->arg[j].argv = cv;
				for (i = 0; i < ing->arg[j].argc; i++) {
					if (*uptr >= keysize)
						return (NSS_ERROR);
					*cv++ = (bptr + *uptr++);
				}
			}
			ing->groups.argv = cv;
			for (i = 0; i < ing->groups.argc; i++) {
				if (*uptr >= keysize)
					return (NSS_ERROR);
				*cv++ = (bptr + *uptr++);
			}
			break;
		case 'T':
			sng = (struct nss_setnetgrent_args *)arg;
			sng->netgroup = (const char *)bptr;
			sng->iterator = 0;
			break;

		default:
			return (NSS_ERROR);
		}
	}
	return (NSS_SUCCESS);
}

static nss_status_t
nss_pinit_funcs(int index, nss_db_initf_t *initf, nss_str2ent_t *s2e)
{
	const char	*name;
	void		*htmp = NULL;
	void		*sym;
	static void	*handle = NULL;
	static mutex_t	handle_lock = DEFAULTMUTEX;
	static mutex_t	initf_lock = DEFAULTMUTEX;
	static mutex_t	s2e_lock = DEFAULTMUTEX;

	if (handle == NULL) {
		lmutex_lock(&handle_lock);
		if (handle == NULL) {
			htmp = dlopen((const char *)0, RTLD_LAZY);
			if (htmp == NULL) {
				lmutex_unlock(&handle_lock);
				return (NSS_ERROR);
			} else {
				membar_producer();
				handle = htmp;
			}
		}
		lmutex_unlock(&handle_lock);
	}
	membar_consumer();

	if (initf) {
		if (getXbyY_to_dbop[index].initfnp != NULL) {
			membar_consumer();
			*initf = (nss_db_initf_t)getXbyY_to_dbop[index].initfnp;
		} else {
			lmutex_lock(&initf_lock);
			if (getXbyY_to_dbop[index].initfnp == NULL) {
				name = getXbyY_to_dbop[index].initfn;
				if ((sym = dlsym(handle, name)) == 0) {
					lmutex_unlock(&initf_lock);
					return (NSS_ERROR);
				}
				getXbyY_to_dbop[index].initfnp = sym;
			}
			membar_producer();
			*initf = (nss_db_initf_t)getXbyY_to_dbop[index].initfnp;
			lmutex_unlock(&initf_lock);
		}
	}
	if (s2e) {
		if (getXbyY_to_dbop[index].strfnp != NULL) {
			membar_consumer();
			*s2e = (nss_str2ent_t)getXbyY_to_dbop[index].strfnp;
		} else {
			lmutex_lock(&s2e_lock);
			if (getXbyY_to_dbop[index].strfnp == NULL) {
				name = getXbyY_to_dbop[index].strfn;
				if ((sym = dlsym(handle, name)) == 0) {
					lmutex_unlock(&s2e_lock);
					return (NSS_ERROR);
				}
				getXbyY_to_dbop[index].strfnp = sym;
			}
			membar_producer();
			*s2e = (nss_str2ent_t)getXbyY_to_dbop[index].strfnp;
			lmutex_unlock(&s2e_lock);
		}
	}

	return (NSS_SUCCESS);
}

nss_status_t
nss_packed_getkey(void *buffer, size_t length, char **dbname,
		int *dbop, nss_XbyY_args_t *arg)
{
	nss_pheader_t 	*pbuf = (nss_pheader_t *)buffer;
	nss_dbd_t	*pdbd;
	nssuint_t 	off, dbdsize;
	int		index;

	if (buffer == NULL || length == 0 || dbop == NULL ||
	    arg == NULL || dbname == NULL)
		return (NSS_ERROR);

	*dbop = pbuf->nss_dbop;
	off = pbuf->dbd_off;
	pdbd = (nss_dbd_t *)((void *)((char *)buffer + off));
	dbdsize = pbuf->key_off - pbuf->dbd_off;
	if (pdbd->o_name >= dbdsize || pdbd->o_config_name >= dbdsize ||
	    pdbd->o_default_config >= dbdsize)
		return (NSS_ERROR);
	*dbname = (char *)buffer + off + pdbd->o_name;
	if ((index = nss_dbop_search(*dbname, (uint32_t)*dbop)) < 0)
		return (NSS_ERROR);
	return (nss_upack_key2arg(buffer, length, dbname, dbop, arg, index));
}


/*
 * str2packent: Standard format interposed str2X function for normal APIs
 *
 * Return values: 0 = success, 1 = parse error, 2 = erange ...
 *
 * The structure pointer is ignored since this is a nscd side packed request.
 * The client side routine does all the real parsing; we just check limits and
 * store the entry in the buffer we were passed by the caller.
 */

/*ARGSUSED*/
static int
str2packent(
    const char *instr,
    int lenstr,
    void *ent,		/* really (char *) */
    char *buffer,
    int buflen
)
{
	if (buflen <= lenstr) {		/* not enough buffer */
		return (NSS_STR_PARSE_ERANGE);
	}
	(void) memmove(buffer, instr, lenstr);
	buffer[lenstr] = '\0';

	return (NSS_STR_PARSE_SUCCESS);
}

/*
 * Initialize db_root, initf, dbop and arg from a packed buffer
 */

/*ARGSUSED*/
nss_status_t
nss_packed_arg_init(void *buffer, size_t length, nss_db_root_t *db_root,
		nss_db_initf_t *initf, int *dbop, nss_XbyY_args_t *arg)
{
	nss_pheader_t 		*pbuf = (nss_pheader_t *)buffer;
	nss_str2ent_t		s2e = str2packent;
	nss_str2ent_t		real_s2e = NULL;
	nss_dbd_t		*pdbd;
	nssuint_t		off, dbdsize;
	char			*dbname, *bptr;
	size_t			len;
	int			index;

	if (buffer == NULL || length == 0 ||
	    dbop == NULL || arg == NULL)
		return (NSS_ERROR);

	/* init dbop */
	*dbop = pbuf->nss_dbop;
	off = pbuf->dbd_off;
	pdbd = (nss_dbd_t *)((void *)((char *)buffer + off));
	dbdsize = pbuf->key_off - pbuf->dbd_off;
	if (pdbd->o_name >= dbdsize || pdbd->o_config_name >= dbdsize ||
	    pdbd->o_default_config >= dbdsize)
		return (NSS_ERROR);
	dbname = (char *)buffer + off + pdbd->o_name;
	if ((index = nss_dbop_search(dbname, (uint32_t)*dbop)) < 0)
		return (NSS_ERROR);

	/* db_root is initialized by nscd's based on door info */
	/* do nothing here */

	/* init key information - (and get dbname dbop etc...) */
	if (nss_upack_key2arg(buffer, length, &dbname,
	    dbop, arg, index) != NSS_SUCCESS)
		return (NSS_ERROR);

	/* possible audituser init */
	if (strcmp(dbname, NSS_DBNAM_AUTHATTR) == 0)
		arg->h_errno = (int)pbuf->p_herrno;

	bptr = (char *)buffer + pbuf->data_off;
	len = (size_t)pbuf->data_len;

	/* sidestep odd arg cases */
	if (*dbop == NSS_DBOP_GROUP_BYMEMBER &&
	    strcmp(dbname, NSS_DBNAM_GROUP) == 0) {
		/* get initf  and str2ent functions */
		if (nss_pinit_funcs(index, initf, &real_s2e) != NSS_SUCCESS)
			return (NSS_ERROR);
		((struct nss_groupsbymem *)arg)->str2ent = real_s2e;
		((struct nss_groupsbymem *)arg)->process_cstr = process_cstr;
		return (NSS_SUCCESS);
	}
	if (pbuf->nss_dbop == NSS_DBOP_NETGROUP_IN &&
	    strcmp(dbname, NSS_DBNAM_NETGROUP) == 0) {
		return (NSS_SUCCESS);
	}

	/* get initf  and str2ent functions */
	if (nss_pinit_funcs(index, initf, NULL) != NSS_SUCCESS)
		return (NSS_ERROR);

	/* init normal arg cases */
	NSS_XbyY_INIT(arg, NULL, bptr, len, s2e);
	arg->h_errno = 0;

	return (NSS_SUCCESS);
}

/*
 * Initialize db_root, initf, dbop, contextp and arg from a packed buffer
 */

/*ARGSUSED*/
nss_status_t
nss_packed_context_init(void *buffer, size_t length, nss_db_root_t *db_root,
		nss_db_initf_t *initf, nss_getent_t **contextp,
		nss_XbyY_args_t *arg)
{
	nss_pheader_t 	*pbuf = (nss_pheader_t *)buffer;
	nss_str2ent_t	s2e = str2packent;
	char		*bptr;
	size_t		len;

	/* init arg */
	if (arg != NULL) {
		bptr = (char *)buffer + pbuf->data_off;
		len = (size_t)pbuf->data_len;
		NSS_XbyY_INIT(arg, NULL, bptr, len, s2e);
	}

	return (NSS_SUCCESS);
}
