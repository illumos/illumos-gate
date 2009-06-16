/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * @(#)ip_frag.h	1.5 3/24/96
 * $Id: ip_frag.h,v 2.23.2.2 2005/06/10 18:02:37 darrenr Exp $
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__IP_FRAG_H__
#define	__IP_FRAG_H__

#define	IPFT_SIZE	257

typedef	struct	ipfr	{
	struct	ipfr	*ipfr_hnext, **ipfr_hprev;
	struct	ipfr	*ipfr_next, **ipfr_prev;
	void	*ipfr_data;
	void	*ipfr_ifp;
	i6addr_t	ipfr_src;
	i6addr_t	ipfr_dst;
	u_32_t	ipfr_optmsk;
	u_short	ipfr_secmsk;
	u_short	ipfr_auth;
	u_32_t	ipfr_id;
	u_32_t	ipfr_p;
	u_32_t	ipfr_tos;
	u_32_t	ipfr_pass;
	u_short	ipfr_off;
	u_long	ipfr_ttl;
	u_char	ipfr_seen0;
	frentry_t *ipfr_rule;
	int	ipfr_ref;
} ipfr_t;

typedef	struct	ipfrstat {
	u_long	ifs_exists;	/* add & already exists */
	u_long	ifs_nomem;
	u_long	ifs_new;
	u_long	ifs_hits;
	u_long	ifs_expire;
	u_long	ifs_inuse;
	u_long	ifs_retrans0;
	u_long	ifs_short;
	struct	ipfr	**ifs_table;
	struct	ipfr	**ifs_nattab;
} ipfrstat_t;

#define	IPFR_CMPSZ	(offsetof(ipfr_t, ipfr_tos) - \
			 offsetof(ipfr_t, ipfr_ifp))

extern	int	fr_fraginit __P((ipf_stack_t *));
extern	void	fr_fragunload __P((ipf_stack_t *));
extern	ipfrstat_t	*fr_fragstats __P((ipf_stack_t *));

extern	int	fr_newfrag __P((fr_info_t *, u_32_t));
extern	frentry_t *fr_knownfrag __P((fr_info_t *, u_32_t *));

extern	int	fr_nat_newfrag __P((fr_info_t *, u_32_t, struct nat *));
extern	nat_t	*fr_nat_knownfrag __P((fr_info_t *));

extern	int	fr_ipid_newfrag __P((fr_info_t *, u_32_t));
extern	u_32_t	fr_ipid_knownfrag __P((fr_info_t *));
extern  void    fr_fragderef __P((ipfr_t **, ipfrwlock_t *, ipf_stack_t *));

extern	void	fr_forget __P((void *, ipf_stack_t *));
extern	void	fr_forgetnat __P((void *, ipf_stack_t *));
extern	void	fr_fragclear __P((ipf_stack_t *));
extern	void	fr_fragexpire __P((ipf_stack_t *));
extern	int	fr_nextfrag __P((ipftoken_t *, ipfgeniter_t *, ipfr_t **, \
				 ipfr_t ***, ipfrwlock_t *, ipf_stack_t *));

#if     defined(_KERNEL) && ((BSD >= 199306) || SOLARIS || defined(__sgi) \
	        || defined(__osf__) || (defined(__sgi) && (IRIX >= 60500)))
# if defined(SOLARIS2) && (SOLARIS2 < 7)
extern	void	fr_slowtimer __P((void *));
# else
extern	void	fr_slowtimer __P((void *));
# endif
#else
# if defined(linux) && defined(_KERNEL)
extern	void	fr_slowtimer __P((long));
# else
extern	int	fr_slowtimer __P((void *));
# endif
#endif

#endif	/* __IP_FRAG_H__ */
