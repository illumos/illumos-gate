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

#ifndef	_SOCKSCTP_H_
#define	_SOCKSCTP_H_

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCTP socket structure.
 *
 * The opaque pointer passed in upcalls is either a pointer to sctp_sonode,
 * or sctp_soassoc. The identification is done through the first element
 * in data structure (if it cannot be identified by upcall which gets called).
 */
struct sctp_sonode {
	int			ss_type;	/* sonode or soassoc */
	struct sonode		ss_so;
	struct sockaddr_in6	ss_laddr;	/* can fit both v4 & v6 */
	struct sockaddr_in6	ss_faddr;
	sctp_assoc_t		ss_maxassoc;	/* assoc array size for 1-N */
	sctp_assoc_t		ss_assoccnt;	/* current # of assocs */
	struct sctp_sa_id	*ss_assocs;	/* assoc array for 1-N */
#define	ss_wroff	ss_so.so_proto_props.sopp_wroff
#define	ss_wrsize	ss_so.so_proto_props.sopp_maxblk
};

/*
 * Association for 1-N sockets.
 */
struct sctp_soassoc {
	int			ssa_type;
	sctp_assoc_t		ssa_id;		/* association ID */
	uint_t			ssa_refcnt;
	struct sctp_sonode	*ssa_sonode;
	struct sctp_s		*ssa_conn;	/* opaque ptr passed to SCTP */
	uint_t			ssa_state;	/* same as so_state */
	int			ssa_error;	/* same as so_error */
	boolean_t		ssa_snd_qfull;
	int			ssa_wroff;
	size_t			ssa_wrsize;
	int			ssa_rcv_queued;	/* queued rx bytes/# of conn */
};

/* 1-N socket association cache defined in socksctp.c */

/*
 * Association array element.
 *
 * Association data structures for 1-N socket are stored in
 * an array in similar manner to file descriptor array.
 * Each association is identified by its association ID, which also
 * is used as an index to this array (again, like file descriptor number).
 */
struct sctp_sa_id {
	sctp_assoc_t		ssi_alloc;
	struct sctp_soassoc	*ssi_assoc;
};

extern sonodeops_t sosctp_sonodeops;
extern sonodeops_t sosctp_seq_sonodeops;
extern sock_upcalls_t sosctp_sock_upcalls;
extern sock_upcalls_t sosctp_assoc_upcalls;

extern struct sonode *socksctp_create(struct sockparams *, int, int,
    int, int, int, int *, cred_t *);
extern void sosctp_fini(struct sonode *, struct cred *);
extern int sosctp_aid_grow(struct sctp_sonode *ss, sctp_assoc_t maxid,
    int kmflags);
extern sctp_assoc_t sosctp_aid_get(struct sctp_sonode *ss);
extern void sosctp_aid_reserve(struct sctp_sonode *ss, sctp_assoc_t id,
    int incr);
extern struct cmsghdr *sosctp_find_cmsg(const uchar_t *control, socklen_t clen,
    int type);
extern void sosctp_pack_cmsg(const uchar_t *, struct nmsghdr *, int);

extern int sosctp_assoc(struct sctp_sonode *ss, sctp_assoc_t id,
    struct sctp_soassoc **ssa);
extern struct sctp_soassoc *sosctp_assoc_create(struct sctp_sonode *ss,
    int kmflags);
extern void sosctp_assoc_free(struct sctp_sonode *ss, struct sctp_soassoc *ssa);
extern int sosctp_assoc_createconn(struct sctp_sonode *ss,
    const struct sockaddr *name, socklen_t namelen,
    const uchar_t *control, socklen_t controllen, int fflag, struct cred *,
    struct sctp_soassoc **ssap);
extern void sosctp_assoc_move(struct sctp_sonode *ss, struct sctp_sonode *nss,
    struct sctp_soassoc *ssa);
extern void sosctp_so_inherit(struct sctp_sonode *lss, struct sctp_sonode *nss);

extern void sosctp_assoc_isconnecting(struct sctp_soassoc *ssa);
extern void sosctp_assoc_isconnected(struct sctp_soassoc *ssa);
extern void sosctp_assoc_isdisconnecting(struct sctp_soassoc *ssa);
extern void sosctp_assoc_isdisconnected(struct sctp_soassoc *ssa, int error);

extern int sosctp_waitconnected(struct sonode *so, int fmode);
extern int sosctp_uiomove(mblk_t *hdr_mp, ssize_t count, ssize_t blk_size,
    int wroff, struct uio *uiop, int flags, cred_t *cr);

/*
 * Data structure types.
 */
#define	SOSCTP_SOCKET	0x1
#define	SOSCTP_ASSOC	0x2

#define	SOTOSSO(so) ((struct sctp_sonode *)(((char *)so) -	\
			offsetof(struct sctp_sonode, ss_so)))

#define	SSA_REFHOLD(ssa)					\
{								\
	ASSERT(MUTEX_HELD(&(ssa)->ssa_sonode->ss_so.so_lock));	\
	ASSERT((ssa)->ssa_refcnt > 0);				\
	++(ssa)->ssa_refcnt;					\
	dprint(3, ("ssa_refhold on %p %d (%s,%d)\n", 		\
		(void *)(ssa), (ssa)->ssa_refcnt,		\
		__FILE__, __LINE__));				\
}


#define	SSA_REFRELE(ss, ssa)					\
{								\
	dprint(3, ("ssa_refrele on %p %d (%s, %d)\n",		\
		(void *)(ssa),					\
		(ssa)->ssa_refcnt-1, __FILE__, __LINE__));	\
	ASSERT((ssa)->ssa_refcnt > 0);				\
	if (--(ssa)->ssa_refcnt == 0) {				\
		sosctp_assoc_free(ss, ssa);			\
	}							\
}

#ifdef	__cplusplus
}
#endif

#endif /* _SOCKSCTP_H_ */
