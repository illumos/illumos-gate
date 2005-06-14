/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: ip_pool.h,v 2.19 2003/11/08 23:01:26 darrenr Exp $
 */

#ifndef	__IP_POOL_H__
#define	__IP_POOL_H__

#if defined(_KERNEL) && \
    !(defined(sun) && (defined(__svr4__) || defined(__SVR4)))
# include <net/radix.h>
#else
# include "radix.h"
#endif
#if SOLARIS2 >= 10
#include "ip_lookup.h"
#else
#include "netinet/ip_lookup.h"
#endif

#define	IP_POOL_NOMATCH		0
#define	IP_POOL_POSITIVE	1

typedef	struct ip_pool_node {
	struct	radix_node	ipn_nodes[2];
	addrfamily_t		ipn_addr;
	addrfamily_t		ipn_mask;
	int			ipn_info;
	char			ipn_name[FR_GROUPLEN];
	u_long			ipn_hits;
	struct ip_pool_node	*ipn_next, **ipn_pnext;
} ip_pool_node_t;


typedef	struct ip_pool_s {
	struct ip_pool_s	*ipo_next;
	struct ip_pool_s	**ipo_pnext;
	struct radix_node_head	*ipo_head;
	ip_pool_node_t	*ipo_list;
	u_long		ipo_hits;
	int		ipo_unit;
	int		ipo_flags;
	int		ipo_ref;
	char		ipo_name[FR_GROUPLEN];
} ip_pool_t;

#define	IPOOL_ANON	0x80000000


typedef	struct	ip_pool_stat	{
	u_long		ipls_pools;
	u_long		ipls_tables;
	u_long		ipls_nodes;
	ip_pool_t	*ipls_list[IPL_LOGSIZE];
} ip_pool_stat_t;


extern	ip_pool_stat_t	ipoolstat;
extern	ip_pool_t	*ip_pool_list[IPL_LOGSIZE];

extern	int	ip_pool_search __P((void *, int, void *));
extern	int	ip_pool_init __P((void));
extern	void	ip_pool_fini __P((void));
extern	int	ip_pool_create __P((iplookupop_t *));
extern	int	ip_pool_insert __P((ip_pool_t *, i6addr_t *, i6addr_t *, int));
extern	int	ip_pool_remove __P((ip_pool_t *, ip_pool_node_t *));
extern	int	ip_pool_destroy __P((iplookupop_t *));
extern	void	ip_pool_free __P((ip_pool_t *));
extern	void	ip_pool_deref __P((ip_pool_t *));
extern	void	*ip_pool_find __P((int, char *));
extern	ip_pool_node_t *ip_pool_findeq __P((ip_pool_t *,
					  struct in_addr *, struct in_addr *));

#endif /* __IP_POOL_H__ */
