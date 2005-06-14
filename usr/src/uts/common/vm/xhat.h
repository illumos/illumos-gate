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

#ifndef _VM_XHAT_H
#define	_VM_XHAT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"


#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

#include <sys/types.h>
#include <vm/page.h>
#include <sys/kmem.h>

struct xhat;
struct xhat_hme_blk;

struct xhat_ops {
	struct xhat	*(*xhat_alloc)(void *);
	void		(*xhat_free)(struct xhat *);
	void		(*xhat_free_start)(struct xhat *);
	void		(*xhat_free_end)(struct xhat *);
	int		(*xhat_dup)(struct xhat *, struct xhat *, caddr_t,
	    size_t, uint_t);
	void		(*xhat_swapin)(struct xhat *);
	void		(*xhat_swapout)(struct xhat *);
	void		(*xhat_memload)(struct xhat *, caddr_t, struct page *,
			    uint_t, uint_t);
	void		(*xhat_memload_array)(struct xhat *, caddr_t, size_t,
			    struct page **, uint_t, uint_t);
	void		(*xhat_devload)(struct xhat *, caddr_t, size_t, pfn_t,
	    uint_t, int);
	void		(*xhat_unload)(struct xhat *, caddr_t, size_t, uint_t);
	void		(*xhat_unload_callback)(struct xhat *, caddr_t, size_t,
	    uint_t, hat_callback_t *);
	void		(*xhat_setattr)(struct xhat *, caddr_t, size_t, uint_t);
	void		(*xhat_clrattr)(struct xhat *, caddr_t, size_t, uint_t);
	void		(*xhat_chgattr)(struct xhat *, caddr_t, size_t, uint_t);
	void		(*xhat_unshare)(struct xhat *, caddr_t, size_t);
	void		(*xhat_chgprot)(struct xhat *, caddr_t, size_t, uint_t);
	int		(*xhat_pageunload)(struct xhat *, struct page *, uint_t,
			    void *);
};


#define	XHAT_POPS(_p)	(_p)->xhat_provider_ops
#define	XHAT_PROPS(_h)	XHAT_POPS(((struct xhat *)(_h))->xhat_provider)
#define	XHAT_HOPS(hat, func, args) \
	{ \
		if (XHAT_PROPS(hat)-> /* */ func) \
			XHAT_PROPS(hat)-> /* */ func /* */ args; \
	}

#define	XHAT_FREE_START(a) \
	XHAT_HOPS(a, xhat_free_start, ((struct xhat *)(a)))
#define	XHAT_FREE_END(a) \
	XHAT_HOPS(a, xhat_free_end, ((struct xhat *)(a)))
#define	XHAT_DUP(a, b, c, d, e) \
	((XHAT_PROPS(a)->xhat_dup == NULL) ? (0) : \
	XHAT_PROPS(a)->xhat_dup((struct xhat *)(a), \
				(struct xhat *)(b), c, d, e))
#define	XHAT_SWAPIN(a) \
	XHAT_HOPS(a, xhat_swapin, ((struct xhat *)(a)))
#define	XHAT_SWAPOUT(a) \
	XHAT_HOPS(a, xhat_swapout, ((struct xhat *)(a)))
#define	XHAT_MEMLOAD(a, b, c, d, e) \
	XHAT_HOPS(a, xhat_memload, ((struct xhat *)(a), b, c, d, e))
#define	XHAT_MEMLOAD_ARRAY(a, b, c, d, e, f) \
	XHAT_HOPS(a, xhat_memload_array, ((struct xhat *)(a), b, c, d, e, f))
#define	XHAT_DEVLOAD(a, b, c, d, e, f) \
	XHAT_HOPS(a, xhat_devload, ((struct xhat *)(a), b, c, d, e, f))
#define	XHAT_UNLOAD(a, b, c, d) \
	XHAT_HOPS(a, xhat_unload, ((struct xhat *)(a), b, c, d))
#define	XHAT_UNLOAD_CALLBACK(a, b, c, d, e) \
	XHAT_HOPS(a, xhat_unload_callback, ((struct xhat *)(a), b, c, d, e))
#define	XHAT_SETATTR(a, b, c, d) \
	XHAT_HOPS(a, xhat_setattr, ((struct xhat *)(a), b, c, d))
#define	XHAT_CLRATTR(a, b, c, d) \
	XHAT_HOPS(a, xhat_clrattr, ((struct xhat *)(a), b, c, d))
#define	XHAT_CHGATTR(a, b, c, d) \
	XHAT_HOPS(a, xhat_chgattr, ((struct xhat *)(a), b, c, d))
#define	XHAT_UNSHARE(a, b, c) \
	XHAT_HOPS(a, xhat_unshare, ((struct xhat *)(a), b, c))
#define	XHAT_CHGPROT(a, b, c, d) \
	XHAT_HOPS(a, xhat_chgprot, ((struct xhat *)(a), b, c, d))
#define	XHAT_PAGEUNLOAD(a, b, c, d) \
	((XHAT_PROPS(a)->xhat_pageunload == NULL) ? (0) : \
	XHAT_PROPS(a)->xhat_pageunload((struct xhat *)(a), b, c, d))



#define	XHAT_PROVIDER_VERSION	1

/*
 * Provider name will be appended with "_cache"
 * when initializing kmem cache.
 * The resulting sring must be less than
 * KMEM_CACHE_NAMELEN
 */
#define	XHAT_CACHE_NAMELEN	24

typedef struct xblk_cache {
	kmutex_t	lock;
	kmem_cache_t	*cache;
	void		*free_blks;
	void		(*reclaim)(void *);
} xblk_cache_t;

typedef struct xhat_provider {
	int		xhat_provider_version;
	int		xhat_provider_refcnt;
	struct xhat_provider *next;
	struct xhat_provider *prev;
	char		xhat_provider_name[XHAT_CACHE_NAMELEN];
	xblk_cache_t	*xblkcache;
	struct xhat_ops *xhat_provider_ops;
	int		xhat_provider_blk_size;
} xhat_provider_t;

/*
 * The xhat structure is protected by xhat_lock.
 * A particular xhat implementation is a extension of the
 * xhat structure and may contain its own lock(s) to
 * protect those additional fields.
 * The xhat structure is never allocated directly.
 * Instead its allocation is provided by the hat implementation.
 * The xhat provider ops xhat_alloc/xhat_free are used to
 * alloc/free a implementation dependant xhat structure.
 */
struct xhat {
	xhat_provider_t		*xhat_provider;
	struct as		*xhat_as;
	void			*arg;
	struct xhat		*prev;
	struct xhat		*next;
	kmutex_t		xhat_lock;
	int			xhat_refcnt;
	kthread_t		*holder;
};


/* Error codes */
#define	XH_PRVDR	(1)	/* Provider-specific error */
#define	XH_ASBUSY	(2)	/* Address space is busy */
#define	XH_XHHELD	(3)	/* XHAT is being held */
#define	XH_NOTATTCHD	(4)	/* Provider is not attached to as */


int	xhat_provider_register(xhat_provider_t *);
int	xhat_provider_unregister(xhat_provider_t *);
void	xhat_init(void);
int	xhat_attach_xhat(xhat_provider_t *, struct as *, struct xhat **,
    void *);
int	xhat_detach_xhat(xhat_provider_t *, struct as *);
pfn_t	xhat_insert_xhatblk(page_t *, struct xhat *, void **);
int	xhat_delete_xhatblk(void *, int);
void	xhat_hat_hold(struct xhat *);
void	xhat_hat_rele(struct xhat *);
int	xhat_hat_holders(struct xhat *);

void	xhat_free_start_all(struct as *);
void	xhat_free_end_all(struct as *);
int	xhat_dup_all(struct as *, struct as *, caddr_t, size_t, uint_t);
void	xhat_swapout_all(struct as *);
void	xhat_unload_callback_all(struct as *, caddr_t, size_t, uint_t,
    hat_callback_t *);
void	xhat_setattr_all(struct as *, caddr_t, size_t, uint_t);
void	xhat_clrattr_all(struct as *, caddr_t, size_t, uint_t);
void	xhat_chgattr_all(struct as *, caddr_t, size_t, uint_t);
void	xhat_chgprot_all(struct as *, caddr_t, size_t, uint_t);
void	xhat_unshare_all(struct as *, caddr_t, size_t);


#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_XHAT_H */
