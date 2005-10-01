/*
 * Copyright (C) 1993-2001 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * @(#)ip_frag.h	1.5 3/24/96
 * $Id: ip_frag.h,v 2.22 2003/06/24 11:13:53 darrenr Exp $
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__IP_FRAG_H__
#define	__IP_FRAG_H__

#define	IPFT_SIZE	257

typedef	struct	ipfr	{
	struct	ipfr	*ipfr_hnext, **ipfr_hprev;
	struct	ipfr	*ipfr_next, **ipfr_prev;
	void	*ipfr_data;
	void	*ipfr_ifp;
	i6addr_t	ipfr_source;
	i6addr_t	ipfr_dest;
	u_32_t	ipfr_optmsk;
	u_short	ipfr_secmsk;
	u_short	ipfr_auth;
	u_32_t	ipfr_id;
	u_char	ipfr_p;
	u_char	ipfr_tos;
	u_32_t	ipfr_pass;
	u_short	ipfr_off;
	u_char	ipfr_ttl;
	u_char	ipfr_seen0;
	u_short ipfr_firstend;
	frentry_t *ipfr_rule;
} ipfr_t;

#define	ipfr_src	ipfr_source.in4
#define	ipfr_dst	ipfr_dest.in4

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

extern	int	ipfr_size;
extern	int	fr_ipfrttl;
extern	int	fr_frag_lock;
extern	int	fr_fraginit __P((void));
extern	void	fr_fragunload __P((void));
extern	ipfrstat_t	*fr_fragstats __P((void));

extern	int	fr_newfrag __P((fr_info_t *, u_32_t));
extern	frentry_t *fr_knownfrag __P((fr_info_t *, u_32_t *));

extern	int	fr_nat_newfrag __P((fr_info_t *, u_32_t, struct nat *));
extern	nat_t	*fr_nat_knownfrag __P((fr_info_t *));

extern	int	fr_ipid_newfrag __P((fr_info_t *, u_32_t));
extern	u_32_t	fr_ipid_knownfrag __P((fr_info_t *));

extern	void	fr_forget __P((void *));
extern	void	fr_forgetnat __P((void *));
extern	void	fr_fragclear __P((void));
extern	void	fr_fragexpire __P((void));

#if     defined(_KERNEL) && ((BSD >= 199306) || SOLARIS || defined(__sgi) \
	        || defined(__osf__) || (defined(__sgi) && (IRIX >= 605)))
# if defined(SOLARIS2) && (SOLARIS2 < 7)
extern	void	fr_slowtimer __P((void));
# else
#ifndef _KERNEL
extern	void	fr_slowtimer __P((void *));
#endif
# endif
#else
extern	int	fr_slowtimer __P((void));
#endif

#endif	/* __IP_FRAG_H__ */
