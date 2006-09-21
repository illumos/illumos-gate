/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1988, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 *
 *	@(#)radix.h	8.2 (Berkeley) 10/31/94
 * $FreeBSD: /repoman/r/ncvs/src/sys/net/radix.h,v 1.25.2.1 2005/01/31 23:26:23
 * imp Exp $
 */

#ifndef _RADIX_H_
#define	_RADIX_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL
#include <sys/mutex.h>
#include <netinet/in.h>
#endif
#include <sys/sysmacros.h>

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_RTABLE);
#endif

/*
 * Radix search tree node layout.
 */

struct radix_node {
	struct	radix_mask *rn_mklist;	/* list of masks contained in subtree */
	struct	radix_node *rn_parent;	/* parent */
	short	rn_bit;			/* bit offset; -1-index(netmask) */
	char	rn_bmask;		/* node: mask for bit test */
	uchar_t	rn_flags;		/* enumerated next */
#define	RNF_NORMAL	1		/* leaf contains normal route */
#define	RNF_ROOT	2		/* leaf is root leaf for tree */
#define	RNF_ACTIVE	4		/* This node is alive (for rtfree) */
	union {
		struct {			/* leaf only data: */
			caddr_t	rn_Key;		/* object of search */
			caddr_t	rn_Mask;	/* netmask, if present */
			struct	radix_node *rn_Dupedkey;
		} rn_leaf;
		struct {			/* node only data: */
			int	rn_Off;		/* where to start compare */
			struct	radix_node *rn_L; /* progeny */
			struct	radix_node *rn_R; /* progeny */
		} rn_node;
	}		rn_u;
};


#define	rn_dupedkey	rn_u.rn_leaf.rn_Dupedkey
#define	rn_key		rn_u.rn_leaf.rn_Key
#define	rn_mask		rn_u.rn_leaf.rn_Mask
#define	rn_offset	rn_u.rn_node.rn_Off
#define	rn_left		rn_u.rn_node.rn_L
#define	rn_right	rn_u.rn_node.rn_R

/*
 * Annotations to tree concerning potential routes applying to subtrees.
 */

struct radix_mask {
	short	rm_bit;			/* bit offset; -1-index(netmask) */
	char	rm_unused;		/* cf. rn_bmask */
	uchar_t	rm_flags;		/* cf. rn_flags */
	struct	radix_mask *rm_mklist;	/* more masks to try */
	union	{
		caddr_t	rmu_mask;		/* the mask */
		struct	radix_node *rmu_leaf;	/* for normal routes */
	}	rm_rmu;
	int	rm_refs;		/* # of references to this struct */
};

#define	rm_mask rm_rmu.rmu_mask
#define	rm_leaf rm_rmu.rmu_leaf		/* extra field would make 32 bytes */

typedef int walktree_f_t(struct radix_node *, void *);
typedef boolean_t match_leaf_t(struct radix_node *, void *);
typedef void (*lockf_t)(struct radix_node *);

struct radix_node_head {
	struct	radix_node *rnh_treetop;
	int	rnh_addrsize;		/* permit, but not require fixed keys */
	int	rnh_pktsize;		/* permit, but not require fixed keys */
	struct	radix_node *(*rnh_addaddr)	/* add based on sockaddr */
		(void *v, void *mask,
		struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_addpkt)	/* add based on packet hdr */
		(void *v, void *mask,
		    struct radix_node_head *head, struct radix_node nodes[]);
	struct	radix_node *(*rnh_deladdr)	/* remove based on sockaddr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_delpkt)	/* remove based on packet hdr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchaddr)	/* locate based on sockaddr */
		(void *v, struct radix_node_head *head);
	/* rnh_matchaddr_args: locate based on sockaddr and match_leaf_t() */
	struct	radix_node *(*rnh_matchaddr_args)
		(void *v, struct radix_node_head *head,
		match_leaf_t *f, void *w);
	struct	radix_node *(*rnh_lookup)	/* locate based on sockaddr */
		(void *v, void *mask, struct radix_node_head *head);
	struct	radix_node *(*rnh_matchpkt)	/* locate based on packet hdr */
		(void *v, struct radix_node_head *head);
	int	(*rnh_walktree)			/* traverse tree */
		(struct radix_node_head *head, walktree_f_t *f, void *w);
	int	(*rnh_walktree_mt)			/* traverse tree */
		(struct radix_node_head *head, walktree_f_t *f, void *w,
		lockf_t lockf, lockf_t unlockf);
	/* rn_walktree_mt: MT safe version of rn_walktree */
	int	(*rnh_walktree_from)		/* traverse tree below a */
		(struct radix_node_head *head, void *a, void *m,
		    walktree_f_t *f, void *w);
	void	(*rnh_close)	/* do something when the last ref drops */
		(struct radix_node *rn, struct radix_node_head *head);
	struct	radix_node rnh_nodes[3];	/* empty tree for common case */
#ifdef _KERNEL
	krwlock_t rnh_lock;			/* locks entire radix tree */
#endif
};

#ifdef _KERNEL
/*
 * BSD's sockaddr_in and sockadr have a sin_len and an sa_len
 * field respectively, as the first field in the structure, and
 * everything in radix.c assumes that the first byte of the "varg"
 * passed in tells the length of the key (the sockaddr).
 *
 * Since Solaris' sockaddr_in and sockadr, do not have these fields, we
 * define a BSD4-like sockaddr_in structure with rt_sin_len field to
 * make LEN macro wn radix.c to work correctly for Solaris
 * See comments around LEN() macro in ip/radix.c
 * The callers of functions of radix.c have to use this data structure
 */
struct rt_sockaddr  {
	uint8_t		rt_sin_len;
	uint8_t		rt_sin_family;
	uint16_t	rt_sin_port;
	struct in_addr	rt_sin_addr;
	char		rt_sin_zero[8];
};


#define	R_Malloc(p, c, n)  p = kmem_cache_alloc((c),  KM_NOSLEEP)
#define	R_Zalloc(p, c, n) \
		if (p = kmem_cache_alloc((c), KM_NOSLEEP)) {\
			bzero(p, n); \
		}
#define	R_ZallocSleep(p, t, n)	p = (t) kmem_zalloc(n, KM_SLEEP)
#define	Free(p, c)  kmem_cache_free(c, p)
#define	FreeHead(p, n)  kmem_free(p, n)

typedef struct radix_node rn_t;
typedef struct radix_mask rmsk_t;
typedef struct radix_node_head rnh_t;
typedef struct rt_sockaddr rt_sa_t;

#define	RADIX_NODE_HEAD_LOCK_INIT(rnh)	\
	rw_init(&(rnh)->rnh_lock, NULL, RW_DEFAULT, NULL)
#define	RADIX_NODE_HEAD_RLOCK(rnh)	rw_enter(&(rnh)->rnh_lock, RW_READER)
#define	RADIX_NODE_HEAD_WLOCK(rnh)	rw_enter(&(rnh)->rnh_lock, RW_WRITER)
#define	RADIX_NODE_HEAD_UNLOCK(rnh)	rw_exit(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_DESTROY(rnh)	rw_destroy(&(rnh)->rnh_lock)
#define	RADIX_NODE_HEAD_LOCK_ASSERT(rnh) RW_WRITE_HELD(&(rnh)->rnh_lock)

#else /* _KERNEL */

#define	R_Malloc(p, t, n) (p =  malloc((unsigned int)(n)))
#define	R_Zalloc(p, t, n) (p =  calloc(1, (unsigned int)(n)))
#define	R_ZallocSleep(p, t, n) R_Zalloc(p, t, n)
#define	Free(p, c) free((char *)p); /* c is ignored */
#ifndef	RADIX_NODE_HEAD_RLOCK
#define	RADIX_NODE_HEAD_RLOCK(x)	/* */
#endif
#ifndef	RADIX_NODE_HEAD_WLOCK
#define	RADIX_NODE_HEAD_WLOCK(x)	/* */
#endif
#ifndef	RADIX_NODE_HEAD_UNLOCK
#define	RADIX_NODE_HEAD_UNLOCK(x)	/* */
#endif

#endif /* _KERNEL */

#ifndef min
#define	min MIN
#endif
#ifndef max
#define	max MAX
#endif

void	rn_init(void);
void	rn_fini(void);
int	rn_inithead(void **, int);
int	rn_freenode(struct radix_node *, void *);
void	rn_freehead(struct radix_node_head *);

#ifdef	__cplusplus
}
#endif

#endif /* _RADIX_H_ */
