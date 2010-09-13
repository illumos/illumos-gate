/*
 * Copyright (C) 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef __IP_HTABLE_H__
#define __IP_HTABLE_H__

#include "netinet/ip_lookup.h"

typedef	struct	iphtent_s	{
	struct	iphtent_s	*ipe_next, **ipe_pnext;
	struct	iphtent_s	*ipe_snext, **ipe_psnext;
	void		*ipe_ptr;
	sa_family_t	ipe_family;
	i6addr_t	ipe_addr;
	i6addr_t	ipe_mask;
	U_QUAD_T	ipe_hits;
	U_QUAD_T	ipe_bytes;
	int		ipe_ref;
	union	{
		char	ipeu_char[16];
		u_long	ipeu_long;
		u_int	ipeu_int;
	}ipe_un;
} iphtent_t;

#define	ipe_value	ipe_un.ipeu_int
#define	ipe_group	ipe_un.ipeu_char

#define	IPE_HASH_FN(a, m, s)	(((a) * (m)) % (s))


typedef	struct	iphtable_s	{
	ipfrwlock_t	iph_rwlock;
	struct	iphtable_s	*iph_next, **iph_pnext;
	struct	iphtent_s	**iph_table;
	struct	iphtent_s	*iph_list;
	size_t	iph_size;		/* size of hash table */
	u_long	iph_seed;		/* hashing seed */
	u_32_t	iph_flags;
	u_int	iph_unit;		/* IPL_LOG* */
	u_int	iph_ref;
	u_int	iph_type;		/* lookup or group map  - IPHASH_* */
	u_int	iph_masks[4];		/* IPv4 or IPv6 netmasks in use */
	char	iph_name[FR_GROUPLEN];	/* hash table number */
} iphtable_t;


/* iph_type */
#define	IPHASH_LOOKUP	0
#define	IPHASH_GROUPMAP	1
#define	IPHASH_ANON	0x80000000


typedef	struct	iphtstat_s	{
	iphtable_t	*iphs_tables;
	u_long		iphs_numtables;
	u_long		iphs_numnodes;
	u_long		iphs_nomem;
	u_long		iphs_pad[16];
} iphtstat_t;


extern void fr_htable_unload __P((ipf_stack_t *));
extern int fr_newhtable __P((iplookupop_t *, ipf_stack_t *));
extern iphtable_t *fr_findhtable __P((int, char *, ipf_stack_t *));
extern int fr_removehtable __P((iplookupop_t *, ipf_stack_t *));
extern size_t fr_flushhtable __P((iplookupflush_t *, ipf_stack_t *));
extern int fr_addhtent __P((iphtable_t *, iphtent_t *, ipf_stack_t *));
extern int fr_delhtent __P((iphtable_t *, iphtent_t *, ipf_stack_t *));
extern void fr_derefhtable __P((iphtable_t *, ipf_stack_t *));
extern void fr_derefhtent __P((iphtent_t *));
extern void fr_delhtable __P((iphtable_t *, ipf_stack_t *));
extern void *fr_iphmfindgroup __P((void *, int, void *, ipf_stack_t *));
extern int fr_iphmfindip __P((void *, int, void *, fr_info_t *, ipf_stack_t *));
extern int fr_gethtablestat __P((iplookupop_t *, ipf_stack_t *));
extern int fr_htable_getnext __P((ipftoken_t *, ipflookupiter_t *, ipf_stack_t *));
extern void fr_htable_iterderef __P((u_int, int, void *, ipf_stack_t *));

#endif /* __IP_HTABLE_H__ */
