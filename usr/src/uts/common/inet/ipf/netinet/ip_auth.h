/*
 * Copyright (C) 1997-2001 by Darren Reed & Guido Van Rooij.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * $Id: ip_auth.h,v 2.16 2003/07/25 12:29:56 darrenr Exp $
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef	__IP_AUTH_H__
#define	__IP_AUTH_H__

#define FR_NUMAUTH      32

typedef struct  frauth {
	int	fra_age;
	int	fra_len;
	int	fra_index;
	u_32_t	fra_pass;
	fr_info_t	fra_info;
	char	*fra_buf;
#ifdef	MENTAT
	queue_t	*fra_q;
#endif
} frauth_t;

typedef	struct	frauthent  {
	struct	frentry	fae_fr;
	struct	frauthent	*fae_next;
	u_long	fae_age;
	int	fae_ref;
} frauthent_t;

typedef struct  fr_authstat {
	U_QUAD_T	fas_hits;
	U_QUAD_T	fas_miss;
	u_long		fas_nospace;
	u_long		fas_added;
	u_long		fas_sendfail;
	u_long		fas_sendok;
	u_long		fas_queok;
	u_long		fas_quefail;
	u_long		fas_expire;
	frauthent_t	*fas_faelist;
} fr_authstat_t;


extern	frentry_t *fr_checkauth __P((fr_info_t *, u_32_t *));
extern	void	fr_authexpire __P((ipf_stack_t *));
extern	int	fr_authinit __P((ipf_stack_t *));
extern	void	fr_authunload __P((ipf_stack_t *));
extern	int	fr_authflush __P((ipf_stack_t *));
extern	int	fr_newauth __P((mb_t *, fr_info_t *));
extern	int	fr_preauthcmd __P((ioctlcmd_t, frentry_t *, frentry_t **, ipf_stack_t *));
extern	int	fr_auth_ioctl __P((caddr_t, int, int, int, void *, ipf_stack_t *));

#endif	/* __IP_AUTH_H__ */
