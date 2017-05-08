/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#if defined(KERNEL) || defined(_KERNEL)
# undef KERNEL
# undef _KERNEL
# define        KERNEL	1
# define        _KERNEL	1
#endif
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#if defined(__NetBSD__)
# if (NetBSD >= 199905) && !defined(IPFILTER_LKM) && defined(_KERNEL)
#  include "opt_ipfilter_log.h"
# endif
#endif
#if defined(_KERNEL) && defined(__FreeBSD_version) && \
    (__FreeBSD_version >= 220000)
# if (__FreeBSD_version >= 400000)
#  if !defined(IPFILTER_LKM)
#   include "opt_inet6.h"
#  endif
#  if (__FreeBSD_version == 400019)
#   define CSUM_DELAY_DATA
#  endif
# endif
# include <sys/filio.h>
#else
# include <sys/ioctl.h>
#endif
#if !defined(_AIX51)
# include <sys/fcntl.h>
#endif
#if defined(_KERNEL)
# include <sys/systm.h>
# include <sys/file.h>
#else
# include <stdio.h>
# include <string.h>
# include <stdlib.h>
# include <stddef.h>
# include <sys/file.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#if !defined(__SVR4) && !defined(__svr4__) && !defined(__hpux) && \
    !defined(linux)
# include <sys/mbuf.h>
#else
# if !defined(linux)
#  include <sys/byteorder.h>
# endif
# if (SOLARIS2 < 5) && defined(sun)
#  include <sys/dditypes.h>
# endif
#endif
#ifdef __hpux
# define _NET_ROUTE_INCLUDED
#endif
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#if !defined(_KERNEL) && defined(__FreeBSD__)
# include "radix_ipf.h"
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#if defined(__sgi) && defined(IFF_DRVRLOCK) /* IRIX 6 */
# include <sys/hashing.h>
# include <netinet/in_var.h>
#endif
#include <netinet/tcp.h>
#if (!defined(__sgi) && !defined(AIX)) || defined(_KERNEL)
# include <netinet/udp.h>
# include <netinet/ip_icmp.h>
#endif
#ifdef __hpux
# undef _NET_ROUTE_INCLUDED
#endif
#include "netinet/ip_compat.h"
#ifdef	USE_INET6
# include <netinet/icmp6.h>
# if !defined(SOLARIS) && defined(_KERNEL) && !defined(__osf__) && \
	!defined(__hpux)
#  include <netinet6/in6_var.h>
# endif
#endif
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#include "netinet/ip_auth.h"
#include "netinet/ipf_stack.h"
#ifdef IPFILTER_SCAN
# include "netinet/ip_scan.h"
#endif
#ifdef IPFILTER_SYNC
# include "netinet/ip_sync.h"
#endif
#include "netinet/ip_pool.h"
#include "netinet/ip_htable.h"
#ifdef IPFILTER_COMPILED
# include "netinet/ip_rules.h"
#endif
#if defined(IPFILTER_BPF) && defined(_KERNEL)
# include <net/bpf.h>
#endif
#if defined(__FreeBSD_version) && (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include "opt_ipfilter.h"
# endif
#endif
#include "netinet/ipl.h"
/* END OF INCLUDES */

#ifdef IPFILTER_COMPAT

# define	IPFILTER_VERSION_4010900	4010900

struct nat_4010900 {
	ipfmutex_t	nat_lock;
	struct	nat	*nat_next;
	struct	nat	**nat_pnext;
	struct	nat	*nat_hnext[2];
	struct	nat	**nat_phnext[2];
	struct	hostmap	*nat_hm;
	void		*nat_data;
	struct	nat	**nat_me;
	struct	ipstate	*nat_state;
	struct	ap_session	*nat_aps;		/* proxy session */
	frentry_t	*nat_fr;	/* filter rule ptr if appropriate */
	struct	ipnat	*nat_ptr;	/* pointer back to the rule */
	void		*nat_ifps[2];
	void		*nat_sync;
	ipftqent_t	nat_tqe;
	u_32_t		nat_flags;
	u_32_t		nat_sumd[2];	/* ip checksum delta for data segment */
	u_32_t		nat_ipsumd;	/* ip checksum delta for ip header */
	u_32_t		nat_mssclamp;	/* if != zero clamp MSS to this */
	i6addr_t	nat_inip6;
	i6addr_t	nat_outip6;
	i6addr_t	nat_oip6;		/* other ip */
	U_QUAD_T	nat_pkts[2];
	U_QUAD_T	nat_bytes[2];
	union	{
		udpinfo_t	nat_unu;
		tcpinfo_t	nat_unt;
		icmpinfo_t	nat_uni;
		greinfo_t	nat_ugre;
	} nat_un;
	u_short		nat_oport;		/* other port */
	u_short		nat_use;
	u_char		nat_p;			/* protocol for NAT */
	int		nat_dir;
	int		nat_ref;		/* reference count */
	int		nat_hv[2];
	char		nat_ifnames[2][LIFNAMSIZ];
	int		nat_rev;		/* 0 = forward, 1 = reverse */
	int		nat_redir;
};

struct  nat_save_4010900    {
	void	*ipn_next;
	struct	nat_4010900	ipn_nat;
	struct	ipnat		ipn_ipnat;
	struct	frentry		ipn_fr;
	int			ipn_dsize;
	char			ipn_data[4];
};

struct natlookup_4010900 {
	struct	in_addr	nlc_inip;
	struct	in_addr	nlc_outip;
	struct	in_addr	nlc_realip;
	int		nlc_flags;
	u_short		nlc_inport;
	u_short		nlc_outport;
	u_short		nlc_realport;
};


/* ------------------------------------------------------------------------ */
/* Function:    fr_incomptrans                                              */
/* Returns:     int     - 0 = success, else failure                         */
/* Parameters:  obj(I) - pointer to ioctl data                              */
/*              ptr(I)  - pointer to store real data in                     */
/*                                                                          */
/* Translate the copied in ipfobj_t to new for backward compatibility at    */
/* the ABI for user land.                                                   */
/* ------------------------------------------------------------------------ */
int fr_incomptrans(obj, ptr)
ipfobj_t *obj;
void *ptr;
{
	int error;
	natlookup_t *nlp;
	nat_save_t *nsp;
	struct nat_save_4010900 nsc;
	struct natlookup_4010900 nlc;

	switch (obj->ipfo_type)
	{
	case IPFOBJ_NATLOOKUP :
		if ((obj->ipfo_rev != IPFILTER_VERSION_4010900) ||
		    (obj->ipfo_size != sizeof (nlc)))
			return EINVAL;
		error = COPYIN((caddr_t)obj->ipfo_ptr, (caddr_t)&nlc,
				obj->ipfo_size);
		if (!error) {
			nlp = (natlookup_t *)ptr;
			bzero((char *)nlp, sizeof (*nlp));
			nlp->nl_inip = nlc.nlc_inip;
			nlp->nl_outip = nlc.nlc_outip;
			nlp->nl_inport = nlc.nlc_inport;
			nlp->nl_outport = nlc.nlc_outport;
			nlp->nl_flags = nlc.nlc_flags;
			nlp->nl_v = 4;
		}
		break;
	case IPFOBJ_NATSAVE :
		if ((obj->ipfo_rev != IPFILTER_VERSION_4010900) ||
		    (obj->ipfo_size != sizeof (nsc)))
			return EINVAL;
		error = COPYIN((caddr_t)obj->ipfo_ptr, (caddr_t)&nsc,
				obj->ipfo_size);
		if (!error) {
			nsp = (nat_save_t *)ptr;
			bzero((char *)nsp, sizeof (*nsp));
			nsp->ipn_next = nsc.ipn_next;
			nsp->ipn_dsize = nsc.ipn_dsize;
			nsp->ipn_nat.nat_inip = nsc.ipn_nat.nat_inip;
			nsp->ipn_nat.nat_outip = nsc.ipn_nat.nat_outip;
			nsp->ipn_nat.nat_oip = nsc.ipn_nat.nat_oip;
			nsp->ipn_nat.nat_inport = nsc.ipn_nat.nat_inport;
			nsp->ipn_nat.nat_outport = nsc.ipn_nat.nat_outport;
			nsp->ipn_nat.nat_oport = nsc.ipn_nat.nat_oport;
			nsp->ipn_nat.nat_flags = nsc.ipn_nat.nat_flags;
			nsp->ipn_nat.nat_v = 4;
		}
		break;
	default :
		return EINVAL;
	}
	return error;
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_outcomptrans                                             */
/* Returns:     int     - 0 = success, else failure                         */
/* Parameters:  obj(I) - pointer to ioctl data                              */
/*              ptr(I)  - pointer to store real data in                     */
/*                                                                          */
/* Translate the copied out ipfobj_t to new definition for backward         */
/* compatibility at the ABI for user land.                                  */
/* ------------------------------------------------------------------------ */
int fr_outcomptrans(obj, ptr)
ipfobj_t *obj;
void *ptr;
{
	int error;
	natlookup_t *nlp;
	struct natlookup_4010900 nlc;

	switch (obj->ipfo_type)
	{
	case IPFOBJ_NATLOOKUP :
		if ((obj->ipfo_rev != IPFILTER_VERSION_4010900) ||
		    (obj->ipfo_size != sizeof (nlc)))
			return EINVAL;
		bzero((char *)&nlc, sizeof (nlc));
		nlp = (natlookup_t *)ptr;
		nlc.nlc_inip = nlp->nl_inip;
		nlc.nlc_outip = nlp->nl_outip;
		nlc.nlc_realip = nlp->nl_realip;
		nlc.nlc_inport = nlp->nl_inport;
		nlc.nlc_outport = nlp->nl_outport;
		nlc.nlc_realport = nlp->nl_realport;
		nlc.nlc_flags = nlp->nl_flags;
		error = COPYOUT((caddr_t)&nlc, (caddr_t)obj->ipfo_ptr,
				obj->ipfo_size);
		break;
	default :
		return EINVAL;
	}
	return error;
}

#endif /* IPFILTER_COMPAT */
