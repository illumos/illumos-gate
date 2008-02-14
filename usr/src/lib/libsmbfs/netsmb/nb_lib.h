/*
 * Copyright (c) 2000, Boris Popov
 * All rights reserved.
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
 *    This product includes software developed by Boris Popov.
 * 4. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: nb_lib.h,v 1.4 2004/12/11 05:23:58 lindak Exp $
 */

#ifndef _NETSMB_NB_LIB_H_
#define	_NETSMB_NB_LIB_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Error codes
 */
#define	NBERR_INVALIDFORMAT	0x0001
#define	NBERR_SRVFAILURE	0x0002
#define	NBERR_NAMENOTFOUND	0x0003
#define	NBERR_IMP		0x0004
#define	NBERR_REFUSED		0x0005
#define	NBERR_ACTIVE		0x0006
#define	NBERR_HOSTNOTFOUND	0x0101
#define	NBERR_TOOMANYREDIRECTS	0x0102
#define	NBERR_INVALIDRESPONSE	0x0103
#define	NBERR_NAMETOOLONG	0x0104
#define	NBERR_NOBCASTIFS	0x0105
#define	NBERR_MAX		0x0106
#define	NBERROR(e)		((e) |  SMB_NB_ERROR)

#define	NBCF_RESOLVED	0x0001
#define	NBCF_NS_ENABLE	0x0002		/* any NetBIOS lookup */
#define	NBCF_BC_ENABLE	0x0004		/* lookup via broadcast */

/*
 * nb environment
 */
struct nb_ctx {
	int		nb_flags;
	int		nb_timo;
	char		*nb_scope;	/* NetBIOS scope */
	in_addr_t	nb_wins1;	/* primary WINS */
	in_addr_t	nb_wins2;	/* secondary WINS (unused now) */
	struct sockaddr_in	nb_lastns; /* see cmd:lookup.c */
};
typedef struct nb_ctx nb_ctx_t;

/*
 * resource record
 */
struct nbns_rr {
	uchar_t		*rr_name;	/* compressed NETBIOS name */
	uint16_t	rr_type;
	uint16_t	rr_class;
	uint32_t	rr_ttl;
	uint16_t	rr_rdlength;
	uchar_t		*rr_data;
};
typedef struct nbns_rr nfns_rr_t;

/*
 * NetBIOS name return
 */
struct nbns_nr {
	char		ns_name[NB_NAMELEN];
	uint16_t	ns_flags;
};
typedef struct nbns_nr nbns_nr_t;

#define	NBRQF_POINT	0x0000
#define	NBRQF_BROADCAST	0x0001

#define	NBNS_GROUPFLG 0x8000

/*
 * nbns request
 */
struct nbns_rq {
	int		nr_opcode;
	int		nr_nmflags;
	int		nr_rcode;
	int		nr_qdcount;
	int		nr_ancount;
	int		nr_nscount;
	int		nr_arcount;
	struct nb_name	*nr_qdname;
	uint16_t	nr_qdtype;
	uint16_t	nr_qdclass;
	struct in_addr	nr_dest;	/* receiver of query */
	struct sockaddr_in nr_sender;	/* sender of response */
	int		nr_rpnmflags;
	int		nr_rprcode;
	uint16_t	nr_rpancount;
	uint16_t	nr_rpnscount;
	uint16_t	nr_rparcount;
	uint16_t	nr_trnid;
	struct nb_ctx	*nr_nbd;
	struct mbdata	nr_rq;
	struct mbdata	nr_rp;
	struct nb_ifdesc *nr_if;
	int		nr_flags;
	int		nr_fd;
	int		nr_maxretry;
};
typedef struct nbns_rq nbns_rq_t;

struct nb_ifdesc {
	int		id_flags;
	struct in_addr	id_addr;
	struct in_addr	id_mask;
	char		id_name[16];	/* actually IFNAMSIZ */
	struct nb_ifdesc *id_next;
};
typedef struct nb_ifdesc nb_ifdesc_t;

struct sockaddr;

#ifdef __cplusplus
extern "C" {
#endif

int nb_name_len(struct nb_name *);
/* new flag UCflag. 1=uppercase,0=don't */
int nb_name_encode(struct nb_name *, uchar_t *);
int nb_encname_len(const uchar_t *);

int  nb_snballoc(int namelen, struct sockaddr_nb **);
void nb_snbfree(struct sockaddr *);
int  nb_sockaddr(struct sockaddr *, struct nb_name *, struct sockaddr_nb **);

int  nb_resolvehost_in(const char *, struct sockaddr **);
int  nbns_resolvename(const char *, struct nb_ctx *, struct sockaddr **);
int  nbns_getnodestatus(struct sockaddr *targethost,
    struct nb_ctx *ctx, char *system, char *workgroup);
int  nb_getlocalname(char *name, size_t maxlen);
int  nb_enum_if(struct nb_ifdesc **);

const char *nb_strerror(int error);

int  nb_ctx_create(struct nb_ctx **);
void nb_ctx_done(struct nb_ctx *);
int  nb_ctx_setns(struct nb_ctx *, const char *);
int  nb_ctx_setscope(struct nb_ctx *, const char *);
int  nb_ctx_resolve(struct nb_ctx *);
int  nb_ctx_readrcsection(struct rcfile *, struct nb_ctx *, const char *, int);

#ifdef __cplusplus
}
#endif

#endif /* !_NETSMB_NB_LIB_H_ */
