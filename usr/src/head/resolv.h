/*
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T
 * All Rights Reserved
 *
 * Portions of this source code were derived from Berkeley
 * 4.3 BSD under license from the regents of the University of
 * California.
 */

/*
 * BIND 4.9.4:
 */

/*
 * Portions Copyright (c) 1993 by Digital Equipment Corporation.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies, and that
 * the name of Digital Equipment Corporation not be used in advertising or
 * publicity pertaining to distribution of the document or software without
 * specific, written prior permission.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND DIGITAL EQUIPMENT CORP. DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.   IN NO EVENT SHALL DIGITAL EQUIPMENT
 * CORPORATION BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * --Copyright--
 *
 * End BIND 4.9.4
 */

/*
 * Copyright (c) 1983, 1987, 1989
 *    The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 * 	This product includes software developed by the University of
 * 	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Portions Copyright (c) 1996-1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND INTERNET SOFTWARE CONSORTIUM DISCLAIMS
 * ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL INTERNET SOFTWARE
 * CONSORTIUM BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
 * ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 */

/*
 *	@(#)resolv.h	8.1 (Berkeley) 6/2/93
 *	$Id: resolv.h,v 8.52 2003/04/29 02:27:03 marka Exp $
 */

#ifndef _RESOLV_H_
#define	_RESOLV_H_

#include <sys/param.h>

#include <stdio.h>
#include <arpa/nameser.h>
#include <sys/socket.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Revision information.  This is the release date in YYYYMMDD format.
 * It can change every day so the right thing to do with it is use it
 * in preprocessor commands such as "#if (__RES > 19931104)".  Do not
 * compare for equality; rather, use it to determine whether your resolver
 * is new enough to contain a certain feature.
 */

#define	__RES	20090302

#define	RES_SET_H_ERRNO(r, x)	__h_errno_set(r, x)
struct __res_state;					/* forward */

void __h_errno_set(struct __res_state *res, int err);

/*
 * Resolver configuration file.
 * Normally not present, but may contain the address of the
 * initial name server(s) to query and the domain search list.
 */

#ifndef _PATH_RESCONF
#define	_PATH_RESCONF		"/etc/resolv.conf"
#endif

#ifndef __P
#define	__P(x)	x
#endif

typedef enum { res_goahead, res_nextns, res_modified, res_done, res_error }
	res_sendhookact;

typedef res_sendhookact (*res_send_qhook)__P((struct sockaddr * const *ns,
						const uchar_t **query,
						int *querylen,
						uchar_t *ans,
						int anssiz,
						int *resplen));

typedef res_sendhookact (*res_send_rhook)__P((const struct sockaddr *ns,
						const uchar_t *query,
						int querylen,
						uchar_t *ans,
						int anssiz,
						int *resplen));

struct res_sym {
	int		number;	   /* Identifying number, like T_MX */
	const char 	*name;	   /* Its symbolic name, like "MX" */
	const char 	*humanname; /* Its fun name, like "mail exchanger" */
};

/*
 * Global defines and variables for resolver stub.
 */
/* ADDRSORT and MAXADDR retained for compatibility; not used */
#define	ADDRSORT	1	/* enable the address-sorting option */
#define	MAXADDR		10	/* max # addresses to sort by */

#define	MAXNS			3	/* max # name servers we'll track */
#define	MAXDFLSRCH		3	/* # default domain levels to try */
#define	MAXDNSRCH		6	/* max # domains in search path */
#define	LOCALDOMAINPARTS	2	/* min levels in name that is "local" */

#define	RES_TIMEOUT		5	/* min. seconds between retries */
#define	MAXRESOLVSORT		10	/* number of net to sort on */
#define	RES_MAXNDOTS		15	/* should reflect bit field size */
#define	RES_MAXRETRANS		30	/* only for resolv.conf/RES_OPTIONS */
#define	RES_MAXRETRY		5	/* only for resolv.conf/RES_OPTIONS */
#define	RES_DFLRETRY		2	/* Default #/tries. */
#define	RES_MAXTIME		65535	/* Infinity, in milliseconds. */

struct __res_state_ext;

struct __res_state {
	int	retrans;		/* retransmission time interval */
	int	retry;			/* number of times to retransmit */
#ifdef __sun
	uint_t	options;		/* option flags - see below. */
#else
	ulong_t	options;		/* option flags - see below. */
#endif
	int	nscount;		/* number of name servers */
	struct sockaddr_in
		nsaddr_list[MAXNS];	/* address of name server */
#define	nsaddr	nsaddr_list[0]		/* for backward compatibility */
	ushort_t id;			/* current packet id */
	char	*dnsrch[MAXDNSRCH+1];	/* components of domain to search */
	char	defdname[256];		/* default domain (deprecated) */
#ifdef __sun
	uint_t	pfcode;			/* RES_PRF_ flags - see below. */
#else
	ulong_t	pfcode;			/* RES_PRF_ flags - see below. */
#endif
	unsigned ndots:4;		/* threshold for initial abs. query */
	unsigned nsort:4;		/* number of elements in sort_list[] */
	char	unused[3];
	struct {
		struct in_addr	addr;
		unsigned int	mask;
	} sort_list[MAXRESOLVSORT];
	res_send_qhook qhook;		/* query hook */
	res_send_rhook rhook;		/* response hook */
	int		res_h_errno;	/* last one set for this context */
	int		_vcsock;	/* PRIVATE: for res_send VC i/o */
	uint_t	_flags;		/* PRIVATE: see below */
	uint_t	_pad;			/* make _u 64 bit aligned */
	union {
		/* On an 32-bit arch this means 512b total. */
		char	pad[72 - 4*sizeof (int) - 2*sizeof (void *)];
		struct {
			uint16_t		nscount;
			uint16_t		nstimes[MAXNS];	/* ms. */
			int			nssocks[MAXNS];
			struct __res_state_ext *ext;	/* extention for IPv6 */
			uchar_t	_rnd[16];	/* PRIVATE: random state */
		} _ext;
	} _u;
};

typedef	struct __res_state	*res_state;

union res_sockaddr_union {
	struct sockaddr_in	sin;
#ifdef IN6ADDR_ANY_INIT
	struct sockaddr_in6	sin6;
#endif
#ifdef ISC_ALIGN64
	int64_t			__align64;	/* 64bit alignment */
#else
	int32_t			__align32;	/* 32bit alignment */
#endif
	char			__space[128];   /* max size */
};

/*
 * Resolver flags (used to be discrete per-module statics ints).
 */
#define	RES_F_VC	0x00000001	/* socket is TCP */
#define	RES_F_CONN	0x00000002	/* socket is connected */
#define	RES_F_EDNS0ERR	0x00000004	/* EDNS0 caused errors */
#define	RES_F__UNUSED	0x00000008	/* (unused) */
#define	RES_F_LASTMASK	0x000000F0	/* ordinal server of last res_nsend */
#define	RES_F_LASTSHIFT	4		/* bit position of LASTMASK "flag" */
#define	RES_GETLAST(res) (((res)._flags & RES_F_LASTMASK) >> RES_F_LASTSHIFT)

/* res_findzonecut2() options */
#define	RES_EXHAUSTIVE	0x00000001	/* always do all queries */
#define	RES_IPV4ONLY	0x00000002	/* IPv4 only */
#define	RES_IPV6ONLY	0x00000004	/* IPv6 only */

/*
 * Resolver options (keep these in synch with res_debug.c, please)
 */
#define	RES_INIT	0x00000001	/* address initialized */
#define	RES_DEBUG	0x00000002	/* print debug messages */
#define	RES_AAONLY	0x00000004	/* authoritative answers only (!IMPL) */
#define	RES_USEVC	0x00000008	/* use virtual circuit */
#define	RES_PRIMARY	0x00000010	/* query primary server only (!IMPL) */
#define	RES_IGNTC	0x00000020	/* ignore trucation errors */
#define	RES_RECURSE	0x00000040	/* recursion desired */
#define	RES_DEFNAMES	0x00000080	/* use default domain name */
#define	RES_STAYOPEN	0x00000100	/* Keep TCP socket open */
#define	RES_DNSRCH	0x00000200	/* search up local domain tree */
#define	RES_INSECURE1	0x00000400	/* type 1 security disabled */
#define	RES_INSECURE2	0x00000800	/* type 2 security disabled */
#define	RES_NOALIASES	0x00001000	/* shuts off HOSTALIASES feature */
#define	RES_USE_INET6	0x00002000	/* use/map IPv6 in gethostbyname() */
#define	RES_ROTATE	0x00004000	/* rotate ns list after each query */
#define	RES_NOCHECKNAME	0x00008000	/* do not check names for sanity. */
#define	RES_KEEPTSIG	0x00010000	/* do not strip TSIG records */
#define	RES_BLAST	0x00020000	/* blast all recursive servers */
#define	RES_NO_NIBBLE	0x00040000	/* disable IPv6 nibble mode reverse */
#define	RES_NO_BITSTRING 0x00080000	/* disable IPv6 bitstring mode revrse */
#define	RES_NOTLDQUERY	0x00100000	/* don't unqualified name as a tld */
#define	RES_USE_DNSSEC	0x00200000	/* use DNSSEC using OK bit in OPT */
/* KAME extensions: use higher bit to avoid conflict with ISC use */
#define	RES_USE_DNAME	0x10000000	/* use DNAME */
#define	RES_USE_EDNS0	0x40000000	/* use EDNS0 if configured */
#define	RES_NO_NIBBLE2	0x80000000	/* disable alternate nibble lookup */

#define	RES_DEFAULT	(RES_RECURSE | RES_DEFNAMES | RES_DNSRCH)

/*
 * Resolver "pfcode" values.  Used by dig.
 */
#define	RES_PRF_STATS	0x00000001
#define	RES_PRF_UPDATE	0x00000002
#define	RES_PRF_CLASS   0x00000004
#define	RES_PRF_CMD		0x00000008
#define	RES_PRF_QUES	0x00000010
#define	RES_PRF_ANS		0x00000020
#define	RES_PRF_AUTH	0x00000040
#define	RES_PRF_ADD		0x00000080
#define	RES_PRF_HEAD1	0x00000100
#define	RES_PRF_HEAD2	0x00000200
#define	RES_PRF_TTLID	0x00000400
#define	RES_PRF_HEADX	0x00000800
#define	RES_PRF_QUERY	0x00001000
#define	RES_PRF_REPLY	0x00002000
#define	RES_PRF_INIT	0x00004000
#define	RES_PRF_TRUNC	0x00008000
/*			0x00010000	*/

/* Things involving an internal (static) resolver context. */
#ifdef _REENTRANT
extern struct __res_state *__res_state(void);
#define	_res (*__res_state())
#else
#ifndef __BIND_NOSTATIC
extern struct __res_state _res;
#endif
#endif

#ifndef __BIND_NOSTATIC
void		fp_nquery __P((const uchar_t *, int, FILE *));
void		fp_query __P((const uchar_t *, FILE *));
const char *hostalias __P((const char *));
void		p_query __P((const uchar_t *));
void		res_close __P((void));
int		res_init __P((void));
int		res_isourserver __P((const struct sockaddr_in *));
int		res_mkquery __P((int, const char *, int, int, const uchar_t *,
				int, const uchar_t *, uchar_t *, int));
int		res_query	__P((const char *, int, int, uchar_t *, int));
int		res_querydomain __P((const char *, const char *, int, int,
				uchar_t *, int));
int		res_search __P((const char *, int, int, uchar_t *, int));
int		res_send __P((const uchar_t *, int, uchar_t *, int));
int		res_sendsigned __P((const uchar_t *, int, ns_tsig_key *,
				    uchar_t *, int));
#endif	/* __BIND_NOSTATIC */

extern const struct res_sym __p_key_syms[];
extern const struct res_sym __p_cert_syms[];
extern const struct res_sym __p_class_syms[];
extern const struct res_sym __p_type_syms[];
extern const struct res_sym __p_rcode_syms[];

int		res_hnok __P((const char *));
int		res_ownok __P((const char *));
int		res_mailok __P((const char *));
int		res_dnok __P((const char *));
int		sym_ston __P((const struct res_sym *, const char *, int *));
const char	*sym_ntos __P((const struct res_sym *, int, int *));
const char	*sym_ntop __P((const struct res_sym *, int, int *));
int		b64_ntop __P((uchar_t const *, size_t, char *, size_t));
int		b64_pton __P((char const *, uchar_t *, size_t));
int		loc_aton __P((const char *ascii, uchar_t *binary));
const char	*loc_ntoa __P((const uchar_t *binary, char *ascii));
int		dn_skipname __P((const uchar_t *, const uchar_t *));
void		putlong __P((unsigned int, uchar_t *));
void		putshort __P((unsigned short, uchar_t *));
const char	*p_class __P((int));
const char	*p_time __P((unsigned int));
const char	*p_type __P((int));
const char	*p_rcode __P((int));
const char	*p_sockun __P((union res_sockaddr_union, char *, size_t));
const uchar_t	*p_cdnname __P((const uchar_t *, const uchar_t *, int,
			FILE *));
const uchar_t	*p_cdname __P((const uchar_t *, const uchar_t *, FILE *));
const uchar_t	*p_fqnname __P((const uchar_t *cp, const uchar_t *msg,
			int, char *, int));
const uchar_t	*p_fqname __P((const uchar_t *, const uchar_t *, FILE *));
const char	*p_option __P((uint_t option));
char		*p_secstodate __P((uint_t));
int		dn_count_labels __P((const char *));
int		dn_comp __P((const char *, uchar_t *, int,
				uchar_t **, uchar_t **));
int		dn_expand __P((const uchar_t *, const uchar_t *,
			const uchar_t *, char *, int));
void		res_rndinit __P((res_state));
uint_t		res_randomid __P((void));
uint_t		res_nrandomid __P((res_state));
int		res_nameinquery __P((const char *, int, int,
				const uchar_t *, const uchar_t *));
int		res_queriesmatch __P((const uchar_t *, const uchar_t *,
				const uchar_t *, const uchar_t *));
const char	*p_section __P((int section, int opcode));


/* Things involving a resolver context. */
int		res_ninit __P((res_state));
int		res_nisourserver __P((const res_state,
				const struct sockaddr_in *));
void	fp_resstat __P((const res_state, FILE *));
void	res_pquery	__P((const res_state, const uchar_t *, int, FILE *));
const char	*res_hostalias __P((const res_state, const char *,
				char *, size_t));
int		res_nquery __P((res_state,
				const char *, int, int, uchar_t *, int));
int		res_nsearch __P((res_state, const char *, int,
				int, uchar_t *, int));
int		res_nquerydomain __P((res_state,
				const char *, const char *, int, int,
				uchar_t *, int));
int		res_nmkquery __P((res_state,
				int, const char *, int, int, const uchar_t *,
				int, const uchar_t *, uchar_t *, int));
int		res_nsend __P((res_state, const uchar_t *, int, uchar_t *,
				int));
int		res_nsendsigned __P((res_state, const uchar_t *, int,
				ns_tsig_key *, uchar_t *, int));
int		res_findzonecut __P((res_state, const char *, ns_class, int,
				char *, size_t, struct in_addr *, int));
int		res_findzonecut2 __P((res_state, const char *, ns_class, int,
				char *, size_t, union res_sockaddr_union *,
				int));
void		res_nclose __P((res_state));
int		res_nopt __P((res_state, int, uchar_t *, int, int));
int		res_nopt_rdata __P((res_state, int, uchar_t *, int, uchar_t *,
				    ushort_t, ushort_t, uchar_t *));
void		res_send_setqhook __P((res_send_qhook hook));
void		res_send_setrhook __P((res_send_rhook hook));
int		__res_vinit __P((res_state, int));
void		res_destroyservicelist __P((void));
const char 	*res_servicename __P((uint16_t port, const char *proto));
const char 	*res_protocolname __P((int num));
void		res_destroyprotolist __P((void));
void		res_buildprotolist __P((void));
const char 	*res_get_nibblesuffix __P((res_state));
const char 	*res_get_nibblesuffix2 __P((res_state));
void		res_ndestroy __P((res_state));
uint16_t	res_nametoclass __P((const char *buf, int *success));
uint16_t	res_nametotype __P((const char *buf, int *success));
void		res_setservers __P((res_state,
				    const union res_sockaddr_union *, int));
int		res_getservers __P((res_state,
				    union res_sockaddr_union *, int));


#ifdef	__cplusplus
}
#endif

#endif /* !_RESOLV_H_ */
