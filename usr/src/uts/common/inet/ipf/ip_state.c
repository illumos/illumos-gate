/*
 * Copyright (C) 1995-2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
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
#include <sys/file.h>
#if defined(__NetBSD__) && (NetBSD >= 199905) && !defined(IPFILTER_LKM) && \
    defined(_KERNEL)
# include "opt_ipfilter_log.h"
#endif
#if defined(_KERNEL) && defined(__FreeBSD_version) && \
    (__FreeBSD_version >= 400000) && !defined(KLD_MODULE)
#include "opt_inet6.h"
#endif
#if !defined(_KERNEL) && !defined(__KERNEL__)
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# define _KERNEL
# ifdef __OpenBSD__
struct file;
# endif
# include <sys/uio.h>
# undef _KERNEL
#endif
#if defined(_KERNEL) && (__FreeBSD_version >= 220000)
# include <sys/filio.h>
# include <sys/fcntl.h>
# if (__FreeBSD_version >= 300000) && !defined(IPFILTER_LKM)
#  include "opt_ipfilter.h"
# endif
#else
# include <sys/ioctl.h>
#endif
#include <sys/time.h>
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__)
#  include <sys/mbuf.h>
# endif
#endif
#if defined(__SVR4) || defined(__svr4__)
# include <sys/filio.h>
# include <sys/byteorder.h>
# ifdef _KERNEL
#  include <sys/dditypes.h>
# endif
# include <sys/stream.h>
# include <sys/kmem.h>
#endif

#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#if !defined(__hpux) && !defined(linux)
# include <netinet/tcp_fsm.h>
#endif
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_proxy.h"
#include "netinet/ipf_stack.h"
#ifdef	IPFILTER_SYNC
#include "netinet/ip_sync.h"
#endif
#ifdef	IPFILTER_SCAN
#include "netinet/ip_scan.h"
#endif
#ifdef	USE_INET6
#include <netinet/icmp6.h>
#endif
#if (__FreeBSD_version >= 300000)
# include <sys/malloc.h>
# if defined(_KERNEL) && !defined(IPFILTER_LKM)
#  include <sys/libkern.h>
#  include <sys/systm.h>
# endif
#endif
/* END OF INCLUDES */


#if !defined(lint)
static const char sccsid[] = "@(#)ip_state.c	1.8 6/5/96 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id: ip_state.c,v 2.186.2.36 2005/08/11 19:58:03 darrenr Exp $";
#endif

#ifdef	USE_INET6
static ipstate_t *fr_checkicmp6matchingstate __P((fr_info_t *));
#endif
static ipstate_t *fr_matchsrcdst __P((fr_info_t *, ipstate_t *, i6addr_t *,
				      i6addr_t *, tcphdr_t *, u_32_t));
static ipstate_t *fr_checkicmpmatchingstate __P((fr_info_t *));
static int fr_state_flush __P((int, int, ipf_stack_t *));
static ips_stat_t *fr_statetstats __P((ipf_stack_t *));
static int fr_state_remove __P((caddr_t, ipf_stack_t *));
static void fr_ipsmove __P((ipstate_t *, u_int, ipf_stack_t *));
static int fr_tcpstate __P((fr_info_t *, tcphdr_t *, ipstate_t *));
static int fr_tcpoptions __P((fr_info_t *, tcphdr_t *, tcpdata_t *));
static ipstate_t *fr_stclone __P((fr_info_t *, tcphdr_t *, ipstate_t *));
static void fr_fixinisn __P((fr_info_t *, ipstate_t *));
static void fr_fixoutisn __P((fr_info_t *, ipstate_t *));
static void fr_checknewisn __P((fr_info_t *, ipstate_t *));
static int fr_stateiter __P((ipftoken_t *, ipfgeniter_t *, ipf_stack_t *));

int fr_stputent __P((caddr_t, ipf_stack_t *));
int fr_stgetent __P((caddr_t, ipf_stack_t *));

#define	ONE_DAY		IPF_TTLVAL(1 * 86400)	/* 1 day */
#define	FIVE_DAYS	(5 * ONE_DAY)
#define	DOUBLE_HASH(x, ifs)	\
    (((x) + ifs->ifs_ips_seed[(x) % ifs->ifs_fr_statesize]) % ifs->ifs_fr_statesize)


/* ------------------------------------------------------------------------ */
/* Function:    fr_stateinit                                                */
/* Returns:     int - 0 == success, -1 == failure                           */
/* Parameters:  ifs - ipf stack instance                                    */
/*                                                                          */
/* Initialise all the global variables used within the state code.          */
/* This action also includes initiailising locks.                           */
/* ------------------------------------------------------------------------ */
int fr_stateinit(ifs)
ipf_stack_t *ifs;
{
#if defined(NEED_LOCAL_RAND) || !defined(_KERNEL)
	struct timeval tv;
#endif
	int i;

	KMALLOCS(ifs->ifs_ips_table, ipstate_t **, 
		 ifs->ifs_fr_statesize * sizeof(ipstate_t *));
	if (ifs->ifs_ips_table == NULL)
		return -1;
	bzero((char *)ifs->ifs_ips_table, 
	      ifs->ifs_fr_statesize * sizeof(ipstate_t *));

	KMALLOCS(ifs->ifs_ips_seed, u_long *,
		 ifs->ifs_fr_statesize * sizeof(*ifs->ifs_ips_seed));
	if (ifs->ifs_ips_seed == NULL)
		return -2;
#if defined(NEED_LOCAL_RAND) || !defined(_KERNEL)
	tv.tv_sec = 0;
	GETKTIME(&tv);
#endif
	for (i = 0; i < ifs->ifs_fr_statesize; i++) {
		/*
		 * XXX - ips_seed[X] should be a random number of sorts.
		 */
#if !defined(NEED_LOCAL_RAND) && defined(_KERNEL)
		ifs->ifs_ips_seed[i] = ipf_random();
#else
		ifs->ifs_ips_seed[i] = ((u_long)ifs->ifs_ips_seed + i) *
		    ifs->ifs_fr_statesize;
		ifs->ifs_ips_seed[i] += tv.tv_sec;
		ifs->ifs_ips_seed[i] *= (u_long)ifs->ifs_ips_seed;
		ifs->ifs_ips_seed[i] ^= 0x5a5aa5a5;
		ifs->ifs_ips_seed[i] *= ifs->ifs_fr_statemax;
#endif
	}

	/* fill icmp reply type table */
	for (i = 0; i <= ICMP_MAXTYPE; i++)
		icmpreplytype4[i] = -1;
	icmpreplytype4[ICMP_ECHO] = ICMP_ECHOREPLY;
	icmpreplytype4[ICMP_TSTAMP] = ICMP_TSTAMPREPLY;
	icmpreplytype4[ICMP_IREQ] = ICMP_IREQREPLY;
	icmpreplytype4[ICMP_MASKREQ] = ICMP_MASKREPLY;
#ifdef	USE_INET6
	/* fill icmp reply type table */
	for (i = 0; i <= ICMP6_MAXTYPE; i++)
		icmpreplytype6[i] = -1;
	icmpreplytype6[ICMP6_ECHO_REQUEST] = ICMP6_ECHO_REPLY;
	icmpreplytype6[ICMP6_MEMBERSHIP_QUERY] = ICMP6_MEMBERSHIP_REPORT;
	icmpreplytype6[ICMP6_NI_QUERY] = ICMP6_NI_REPLY;
	icmpreplytype6[ND_ROUTER_SOLICIT] = ND_ROUTER_ADVERT;
	icmpreplytype6[ND_NEIGHBOR_SOLICIT] = ND_NEIGHBOR_ADVERT;
#endif

	KMALLOCS(ifs->ifs_ips_stats.iss_bucketlen, u_long *,
		 ifs->ifs_fr_statesize * sizeof(u_long));
	if (ifs->ifs_ips_stats.iss_bucketlen == NULL)
		return -1;
	bzero((char *)ifs->ifs_ips_stats.iss_bucketlen, 
	      ifs->ifs_fr_statesize * sizeof(u_long));

	if (ifs->ifs_fr_state_maxbucket == 0) {
		for (i = ifs->ifs_fr_statesize; i > 0; i >>= 1)
			ifs->ifs_fr_state_maxbucket++;
		ifs->ifs_fr_state_maxbucket *= 2;
	}

	fr_sttab_init(ifs->ifs_ips_tqtqb, ifs);
	ifs->ifs_ips_tqtqb[IPF_TCP_NSTATES - 1].ifq_next = &ifs->ifs_ips_udptq;
	ifs->ifs_ips_udptq.ifq_ttl = (u_long)ifs->ifs_fr_udptimeout;
	ifs->ifs_ips_udptq.ifq_ref = 1;
	ifs->ifs_ips_udptq.ifq_head = NULL;
	ifs->ifs_ips_udptq.ifq_tail = &ifs->ifs_ips_udptq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_udptq.ifq_lock, "ipftq udp tab");
	ifs->ifs_ips_udptq.ifq_next = &ifs->ifs_ips_udpacktq;
	ifs->ifs_ips_udpacktq.ifq_ttl = (u_long)ifs->ifs_fr_udpacktimeout;
	ifs->ifs_ips_udpacktq.ifq_ref = 1;
	ifs->ifs_ips_udpacktq.ifq_head = NULL;
	ifs->ifs_ips_udpacktq.ifq_tail = &ifs->ifs_ips_udpacktq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_udpacktq.ifq_lock, "ipftq udpack tab");
	ifs->ifs_ips_udpacktq.ifq_next = &ifs->ifs_ips_icmptq;
	ifs->ifs_ips_icmptq.ifq_ttl = (u_long)ifs->ifs_fr_icmptimeout;
	ifs->ifs_ips_icmptq.ifq_ref = 1;
	ifs->ifs_ips_icmptq.ifq_head = NULL;
	ifs->ifs_ips_icmptq.ifq_tail = &ifs->ifs_ips_icmptq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_icmptq.ifq_lock, "ipftq icmp tab");
	ifs->ifs_ips_icmptq.ifq_next = &ifs->ifs_ips_icmpacktq;
	ifs->ifs_ips_icmpacktq.ifq_ttl = (u_long)ifs->ifs_fr_icmpacktimeout;
	ifs->ifs_ips_icmpacktq.ifq_ref = 1;
	ifs->ifs_ips_icmpacktq.ifq_head = NULL;
	ifs->ifs_ips_icmpacktq.ifq_tail = &ifs->ifs_ips_icmpacktq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_icmpacktq.ifq_lock, "ipftq icmpack tab");
	ifs->ifs_ips_icmpacktq.ifq_next = &ifs->ifs_ips_iptq;
	ifs->ifs_ips_iptq.ifq_ttl = (u_long)ifs->ifs_fr_iptimeout;
	ifs->ifs_ips_iptq.ifq_ref = 1;
	ifs->ifs_ips_iptq.ifq_head = NULL;
	ifs->ifs_ips_iptq.ifq_tail = &ifs->ifs_ips_iptq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_iptq.ifq_lock, "ipftq ip tab");
	ifs->ifs_ips_iptq.ifq_next = &ifs->ifs_ips_deletetq;
	/* entry's ttl in deletetq is just 1 tick */
	ifs->ifs_ips_deletetq.ifq_ttl = (u_long) 1;
	ifs->ifs_ips_deletetq.ifq_ref = 1;
	ifs->ifs_ips_deletetq.ifq_head = NULL;
	ifs->ifs_ips_deletetq.ifq_tail = &ifs->ifs_ips_deletetq.ifq_head;
	MUTEX_INIT(&ifs->ifs_ips_deletetq.ifq_lock, "state delete queue");
	ifs->ifs_ips_deletetq.ifq_next = NULL;

	RWLOCK_INIT(&ifs->ifs_ipf_state, "ipf IP state rwlock");
	MUTEX_INIT(&ifs->ifs_ipf_stinsert, "ipf state insert mutex");
	ifs->ifs_fr_state_init = 1;

	ifs->ifs_ips_last_force_flush = ifs->ifs_fr_ticks;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stateunload                                              */
/* Returns:     Nil                                                         */
/* Parameters:  ifs - ipf stack instance                                    */
/*                                                                          */
/* Release and destroy any resources acquired or initialised so that        */
/* IPFilter can be unloaded or re-initialised.                              */
/* ------------------------------------------------------------------------ */
void fr_stateunload(ifs)
ipf_stack_t *ifs;
{
	ipftq_t *ifq, *ifqnext;
	ipstate_t *is;

	while ((is = ifs->ifs_ips_list) != NULL)
	    (void) fr_delstate(is, 0, ifs);

	/*
	 * Proxy timeout queues are not cleaned here because although they
	 * exist on the state list, appr_unload is called after fr_stateunload
	 * and the proxies actually are responsible for them being created.
	 * Should the proxy timeouts have their own list?  There's no real
	 * justification as this is the only complicationA
	 */
	for (ifq = ifs->ifs_ips_utqe; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;
		if (((ifq->ifq_flags & IFQF_PROXY) == 0) &&
		    (fr_deletetimeoutqueue(ifq) == 0))
			fr_freetimeoutqueue(ifq, ifs);
	}

	ifs->ifs_ips_stats.iss_inuse = 0;
	ifs->ifs_ips_num = 0;

	if (ifs->ifs_fr_state_init == 1) {
		fr_sttab_destroy(ifs->ifs_ips_tqtqb);
		MUTEX_DESTROY(&ifs->ifs_ips_udptq.ifq_lock);
		MUTEX_DESTROY(&ifs->ifs_ips_icmptq.ifq_lock);
		MUTEX_DESTROY(&ifs->ifs_ips_udpacktq.ifq_lock);
		MUTEX_DESTROY(&ifs->ifs_ips_icmpacktq.ifq_lock);
		MUTEX_DESTROY(&ifs->ifs_ips_iptq.ifq_lock);
		MUTEX_DESTROY(&ifs->ifs_ips_deletetq.ifq_lock);
	}

	if (ifs->ifs_ips_table != NULL) {
		KFREES(ifs->ifs_ips_table, 
		       ifs->ifs_fr_statesize * sizeof(*ifs->ifs_ips_table));
		ifs->ifs_ips_table = NULL;
	}

	if (ifs->ifs_ips_seed != NULL) {
		KFREES(ifs->ifs_ips_seed, 
		       ifs->ifs_fr_statesize * sizeof(*ifs->ifs_ips_seed));
		ifs->ifs_ips_seed = NULL;
	}

	if (ifs->ifs_ips_stats.iss_bucketlen != NULL) {
		KFREES(ifs->ifs_ips_stats.iss_bucketlen, 
		       ifs->ifs_fr_statesize * sizeof(u_long));
		ifs->ifs_ips_stats.iss_bucketlen = NULL;
	}

	if (ifs->ifs_fr_state_maxbucket_reset == 1)
		ifs->ifs_fr_state_maxbucket = 0;

	if (ifs->ifs_fr_state_init == 1) {
		ifs->ifs_fr_state_init = 0;
		RW_DESTROY(&ifs->ifs_ipf_state);
		MUTEX_DESTROY(&ifs->ifs_ipf_stinsert);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_statetstats                                              */
/* Returns:     ips_state_t* - pointer to state stats structure             */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* Put all the current numbers and pointers into a single struct and return */
/* a pointer to it.                                                         */
/* ------------------------------------------------------------------------ */
static ips_stat_t *fr_statetstats(ifs)
ipf_stack_t *ifs;
{
	ifs->ifs_ips_stats.iss_active = ifs->ifs_ips_num;
	ifs->ifs_ips_stats.iss_statesize = ifs->ifs_fr_statesize;
	ifs->ifs_ips_stats.iss_statemax = ifs->ifs_fr_statemax;
	ifs->ifs_ips_stats.iss_table = ifs->ifs_ips_table;
	ifs->ifs_ips_stats.iss_list = ifs->ifs_ips_list;
	ifs->ifs_ips_stats.iss_ticks = ifs->ifs_fr_ticks;
	return &ifs->ifs_ips_stats;
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_state_remove                                             */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state structure to delete from table   */
/*              ifs - ipf stack instance                                    */
/*                                                                          */
/* Search for a state structure that matches the one passed, according to   */
/* the IP addresses and other protocol specific information.                */
/* ------------------------------------------------------------------------ */
static int fr_state_remove(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	ipstate_t *sp, st;
	int error;

	sp = &st;
	error = fr_inobj(data, &st, IPFOBJ_IPSTATE);
	if (error)
		return EFAULT;

	WRITE_ENTER(&ifs->ifs_ipf_state);
	for (sp = ifs->ifs_ips_list; sp; sp = sp->is_next)
		if ((sp->is_p == st.is_p) && (sp->is_v == st.is_v) &&
		    !bcmp((caddr_t)&sp->is_src, (caddr_t)&st.is_src,
			  sizeof(st.is_src)) &&
		    !bcmp((caddr_t)&sp->is_dst, (caddr_t)&st.is_dst,
			  sizeof(st.is_dst)) &&
		    !bcmp((caddr_t)&sp->is_ps, (caddr_t)&st.is_ps,
			  sizeof(st.is_ps))) {
			(void) fr_delstate(sp, ISL_REMOVE, ifs);
			RWLOCK_EXIT(&ifs->ifs_ipf_state);
			return 0;
		}
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	return ESRCH;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_state_ioctl                                              */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to ioctl data                             */
/*              cmd(I)  - ioctl command integer                             */
/*              mode(I) - file mode bits used with open                     */
/*              uid(I)  - uid of caller                                     */
/*              ctx(I)  - pointer to give the uid context                   */
/*              ifs     - ipf stack instance                                */
/*                                                                          */
/* Processes an ioctl call made to operate on the IP Filter state device.   */
/* ------------------------------------------------------------------------ */
int fr_state_ioctl(data, cmd, mode, uid, ctx, ifs)
caddr_t data;
ioctlcmd_t cmd;
int mode, uid;
void *ctx;
ipf_stack_t *ifs;
{
	int arg, ret, error = 0;

	switch (cmd)
	{
	/*
	 * Delete an entry from the state table.
	 */
	case SIOCDELST :
		error = fr_state_remove(data, ifs);
		break;
	/*
	 * Flush the state table
	 */
	case SIOCIPFFL :
		error = BCOPYIN(data, (char *)&arg, sizeof(arg));
		if (error != 0) {
			error = EFAULT;
		} else {
			if (VALID_TABLE_FLUSH_OPT(arg)) {
				WRITE_ENTER(&ifs->ifs_ipf_state);
				ret = fr_state_flush(arg, 4, ifs);
				RWLOCK_EXIT(&ifs->ifs_ipf_state);
				error = BCOPYOUT((char *)&ret, data,
						sizeof(ret));
				if (error != 0)
					return EFAULT;
			} else {
				error = EINVAL;
			}
		}
		break;

#ifdef	USE_INET6
	case SIOCIPFL6 :
		error = BCOPYIN(data, (char *)&arg, sizeof(arg));
		if (error != 0) {
			error = EFAULT;
		} else {
			if (VALID_TABLE_FLUSH_OPT(arg)) {
				WRITE_ENTER(&ifs->ifs_ipf_state);
				ret = fr_state_flush(arg, 6, ifs);
				RWLOCK_EXIT(&ifs->ifs_ipf_state);
				error = BCOPYOUT((char *)&ret, data,
						sizeof(ret));
				if (error != 0)
					return EFAULT;
			} else {
				error = EINVAL;
			}
		}
		break;
#endif
#ifdef	IPFILTER_LOG
	/*
	 * Flush the state log.
	 */
	case SIOCIPFFB :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			int tmp;

			tmp = ipflog_clear(IPL_LOGSTATE, ifs);
			error = BCOPYOUT((char *)&tmp, data, sizeof(tmp));
			if (error != 0)
				error = EFAULT;
		}
		break;
	/*
	 * Turn logging of state information on/off.
	 */
	case SIOCSETLG :
		if (!(mode & FWRITE)) {
			error = EPERM;
		} else {
			error = BCOPYIN((char *)data,
					(char *)&ifs->ifs_ipstate_logging,
					sizeof(ifs->ifs_ipstate_logging));
			if (error != 0)
				error = EFAULT;
		}
		break;
	/*
	 * Return the current state of logging.
	 */
	case SIOCGETLG :
		error = BCOPYOUT((char *)&ifs->ifs_ipstate_logging,
				(char *)data,
				sizeof(ifs->ifs_ipstate_logging));
		if (error != 0)
			error = EFAULT;
		break;
	/*
	 * Return the number of bytes currently waiting to be read.
	 */
	case FIONREAD :
		arg = ifs->ifs_iplused[IPL_LOGSTATE]; /* returned in an int */
		error = BCOPYOUT((char *)&arg, data, sizeof(arg));
		if (error != 0)
			error = EFAULT;
		break;
#endif
	/*
	 * Get the current state statistics.
	 */
	case SIOCGETFS :
		error = fr_outobj(data, fr_statetstats(ifs), IPFOBJ_STATESTAT);
		break;
	/*
	 * Lock/Unlock the state table.  (Locking prevents any changes, which
	 * means no packets match).
	 */
	case SIOCSTLCK :
		if (!(mode & FWRITE)) {
			error = EPERM;
		} else {
			error = fr_lock(data, &ifs->ifs_fr_state_lock);
		}
		break;
	/*
	 * Add an entry to the current state table.
	 */
	case SIOCSTPUT :
		if (!ifs->ifs_fr_state_lock || !(mode & FWRITE)) {
			error = EACCES;
			break;
		}
		error = fr_stputent(data, ifs);
		break;
	/*
	 * Get a state table entry.
	 */
	case SIOCSTGET :
		if (!ifs->ifs_fr_state_lock) {
			error = EACCES;
			break;
		}
		error = fr_stgetent(data, ifs);
		break;

	case SIOCGENITER :
	    {
		ipftoken_t *token;
		ipfgeniter_t iter;

		error = fr_inobj(data, &iter, IPFOBJ_GENITER);
		if (error != 0)
			break;

		token = ipf_findtoken(IPFGENITER_STATE, uid, ctx, ifs);
		if (token != NULL)
			error = fr_stateiter(token, &iter, ifs);
		else
			error = ESRCH;
		RWLOCK_EXIT(&ifs->ifs_ipf_tokens);
		break;
	    }

	case SIOCIPFDELTOK :
		error = BCOPYIN(data, (char *)&arg, sizeof(arg));
		if (error != 0) {
			error = EFAULT;
		} else {
			error = ipf_deltoken(arg, uid, ctx, ifs);
		}
		break;

	default :
		error = EINVAL;
		break;
	}
	return error;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stgetent                                                 */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state structure to retrieve from table */
/*                                                                          */
/* Copy out state information from the kernel to a user space process.  If  */
/* there is a filter rule associated with the state entry, copy that out    */
/* as well.  The entry to copy out is taken from the value of "ips_next" in */
/* the struct passed in and if not null and not found in the list of current*/
/* state entries, the retrieval fails.                                      */
/* ------------------------------------------------------------------------ */
int fr_stgetent(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	ipstate_t *is, *isn;
	ipstate_save_t ips;
	int error;

	error = fr_inobj(data, &ips, IPFOBJ_STATESAVE);
	if (error)
		return EFAULT;

	isn = ips.ips_next;
	if (isn == NULL) {
		isn = ifs->ifs_ips_list;
		if (isn == NULL) {
			if (ips.ips_next == NULL)
				return ENOENT;
			return 0;
		}
	} else {
		/*
		 * Make sure the pointer we're copying from exists in the
		 * current list of entries.  Security precaution to prevent
		 * copying of random kernel data.
		 */
		for (is = ifs->ifs_ips_list; is; is = is->is_next)
			if (is == isn)
				break;
		if (!is)
			return ESRCH;
	}
	ips.ips_next = isn->is_next;
	bcopy((char *)isn, (char *)&ips.ips_is, sizeof(ips.ips_is));
	ips.ips_rule = isn->is_rule;
	if (isn->is_rule != NULL)
		bcopy((char *)isn->is_rule, (char *)&ips.ips_fr,
		      sizeof(ips.ips_fr));
	error = fr_outobj(data, &ips, IPFOBJ_STATESAVE);
	if (error)
		return EFAULT;
	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stputent                                                 */
/* Returns:     int - 0 == success, != 0 == failure                         */
/* Parameters:  data(I) - pointer to state information struct               */
/*              ifs     - ipf stack instance                                */
/*                                                                          */
/* This function implements the SIOCSTPUT ioctl: insert a state entry into  */
/* the state table.  If the state info. includes a pointer to a filter rule */
/* then also add in an orphaned rule (will not show up in any "ipfstat -io" */
/* output.                                                                  */
/* ------------------------------------------------------------------------ */
int fr_stputent(data, ifs)
caddr_t data;
ipf_stack_t *ifs;
{
	ipstate_t *is, *isn;
	ipstate_save_t ips;
	int error, i;
	frentry_t *fr;
	char *name;

	error = fr_inobj(data, &ips, IPFOBJ_STATESAVE);
	if (error)
		return EFAULT;

	/*
	 * Trigger automatic call to fr_state_flush() if the
	 * table has reached capacity specified by hi watermark.
	 */
	if (ST_TAB_WATER_LEVEL(ifs) > ifs->ifs_state_flush_level_hi)
		ifs->ifs_fr_state_doflush = 1;

	/*
	 * If automatic flushing did not do its job, and the table
	 * has filled up, don't try to create a new entry.
	 */
	if (ifs->ifs_ips_num >= ifs->ifs_fr_statemax) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_max);
		return ENOMEM;
	}

	KMALLOC(isn, ipstate_t *);
	if (isn == NULL)
		return ENOMEM;

	bcopy((char *)&ips.ips_is, (char *)isn, sizeof(*isn));
	bzero((char *)isn, offsetof(struct ipstate, is_pkts));
	isn->is_sti.tqe_pnext = NULL;
	isn->is_sti.tqe_next = NULL;
	isn->is_sti.tqe_ifq = NULL;
	isn->is_sti.tqe_parent = isn;
	isn->is_ifp[0] = NULL;
	isn->is_ifp[1] = NULL;
	isn->is_ifp[2] = NULL;
	isn->is_ifp[3] = NULL;
	isn->is_sync = NULL;
	fr = ips.ips_rule;

	if (fr == NULL) {
		READ_ENTER(&ifs->ifs_ipf_state);
		fr_stinsert(isn, 0, ifs);
		MUTEX_EXIT(&isn->is_lock);
		RWLOCK_EXIT(&ifs->ifs_ipf_state);
		return 0;
	}

	if (isn->is_flags & SI_NEWFR) {
		KMALLOC(fr, frentry_t *);
		if (fr == NULL) {
			KFREE(isn);
			return ENOMEM;
		}
		bcopy((char *)&ips.ips_fr, (char *)fr, sizeof(*fr));
		isn->is_rule = fr;
		ips.ips_is.is_rule = fr;
		MUTEX_NUKE(&fr->fr_lock);
		MUTEX_INIT(&fr->fr_lock, "state filter rule lock");

		/*
		 * Look up all the interface names in the rule.
		 */
		for (i = 0; i < 4; i++) {
			name = fr->fr_ifnames[i];
			fr->fr_ifas[i] = fr_resolvenic(name, fr->fr_v, ifs);
			name = isn->is_ifname[i];
			isn->is_ifp[i] = fr_resolvenic(name, isn->is_v, ifs);
		}

		fr->fr_ref = 0;
		fr->fr_dsize = 0;
		fr->fr_data = NULL;
		fr->fr_type = FR_T_NONE;

		fr_resolvedest(&fr->fr_tif, fr->fr_v, ifs);
		fr_resolvedest(&fr->fr_dif, fr->fr_v, ifs);
		fr_resolvedest(&fr->fr_rif, fr->fr_v, ifs);

		/*
		 * send a copy back to userland of what we ended up
		 * to allow for verification.
		 */
		error = fr_outobj(data, &ips, IPFOBJ_STATESAVE);
		if (error) {
			KFREE(isn);
			MUTEX_DESTROY(&fr->fr_lock);
			KFREE(fr);
			return EFAULT;
		}
		READ_ENTER(&ifs->ifs_ipf_state);
		fr_stinsert(isn, 0, ifs);
		MUTEX_EXIT(&isn->is_lock);
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

	} else {
		READ_ENTER(&ifs->ifs_ipf_state);
		for (is = ifs->ifs_ips_list; is; is = is->is_next)
			if (is->is_rule == fr) {
				fr_stinsert(isn, 0, ifs);
				MUTEX_EXIT(&isn->is_lock);
				break;
			}

		if (is == NULL) {
			KFREE(isn);
			isn = NULL;
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

		return (isn == NULL) ? ESRCH : 0;
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:   fr_stinsert                                                  */
/* Returns:    Nil                                                          */
/* Parameters: is(I)  - pointer to state structure                          */
/*             rev(I) - flag indicating forward/reverse direction of packet */
/*                                                                          */
/* Inserts a state structure into the hash table (for lookups) and the list */
/* of state entries (for enumeration).  Resolves all of the interface names */
/* to pointers and adjusts running stats for the hash table as appropriate. */
/*                                                                          */
/* Locking: it is assumed that some kind of lock on ipf_state is held.      */
/*          Exits with is_lock initialised and held.                        */
/* ------------------------------------------------------------------------ */
void fr_stinsert(is, rev, ifs)
ipstate_t *is;
int rev;
ipf_stack_t *ifs;
{
	frentry_t *fr;
	u_int hv;
	int i;

	MUTEX_INIT(&is->is_lock, "ipf state entry");

	fr = is->is_rule;
	if (fr != NULL) {
		MUTEX_ENTER(&fr->fr_lock);
		fr->fr_ref++;
		fr->fr_statecnt++;
		MUTEX_EXIT(&fr->fr_lock);
	}

	/*
	 * Look up all the interface names in the state entry.
	 */
	for (i = 0; i < 4; i++) {
		if (is->is_ifp[i] != NULL)
			continue;
		is->is_ifp[i] = fr_resolvenic(is->is_ifname[i], is->is_v, ifs);
	}

	/*
	 * If we could trust is_hv, then the modulous would not be needed, but
	 * when running with IPFILTER_SYNC, this stops bad values.
	 */
	hv = is->is_hv % ifs->ifs_fr_statesize;
	is->is_hv = hv;

	/*
	 * We need to get both of these locks...the first because it is
	 * possible that once the insert is complete another packet might
	 * come along, match the entry and want to update it.
	 */
	MUTEX_ENTER(&is->is_lock);
	MUTEX_ENTER(&ifs->ifs_ipf_stinsert);

	/*
	 * add into list table.
	 */
	if (ifs->ifs_ips_list != NULL)
		ifs->ifs_ips_list->is_pnext = &is->is_next;
	is->is_pnext = &ifs->ifs_ips_list;
	is->is_next = ifs->ifs_ips_list;
	ifs->ifs_ips_list = is;

	if (ifs->ifs_ips_table[hv] != NULL)
		ifs->ifs_ips_table[hv]->is_phnext = &is->is_hnext;
	else
		ifs->ifs_ips_stats.iss_inuse++;
	is->is_phnext = ifs->ifs_ips_table + hv;
	is->is_hnext = ifs->ifs_ips_table[hv];
	ifs->ifs_ips_table[hv] = is;
	ifs->ifs_ips_stats.iss_bucketlen[hv]++;
	ifs->ifs_ips_num++;
	MUTEX_EXIT(&ifs->ifs_ipf_stinsert);

	fr_setstatequeue(is, rev, ifs);
}

/* ------------------------------------------------------------------------ */
/* Function:	fr_match_ipv4addrs					    */
/* Returns:	int -	2 strong match (same addresses, same direction)	    */
/*			1 weak match (same address, opposite direction)	    */
/*			0 no match					    */
/*									    */
/* Function matches IPv4 addresses.					    */
/* ------------------------------------------------------------------------ */
static int fr_match_ipv4addrs(is1, is2)
ipstate_t *is1;
ipstate_t *is2;
{
	int	rv;

	if (is1->is_saddr == is2->is_saddr && is1->is_daddr == is2->is_daddr)
		rv = 2;
	else if (is1->is_saddr == is2->is_daddr &&
	    is1->is_daddr == is2->is_saddr)
		rv = 1;
	else
		rv = 0;

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:	fr_match_ipv6addrs					    */
/* Returns:	int - 	2 strong match (same addresses, same direction)	    */
/*			1 weak match (same addresses, opposite direction)   */
/*			0 no match					    */
/*									    */
/* Function matches IPv6 addresses.					    */
/* ------------------------------------------------------------------------ */
static int fr_match_ipv6addrs(is1, is2)
ipstate_t *is1;
ipstate_t *is2;
{
	int	rv;

	if (IP6_EQ(&is1->is_src, &is2->is_src) &&
	    IP6_EQ(&is1->is_dst, &is2->is_dst))
		rv = 2;
	else if (IP6_EQ(&is1->is_src, &is2->is_dst) &&
	    IP6_EQ(&is1->is_dst, &is2->is_src)) {
		rv = 1;
	}
	else
		rv = 0;

	return (rv);
}
/* ------------------------------------------------------------------------ */
/* Function:	fr_match_addresses					    */
/* Returns:	int - 	2 strong match (same addresses, same direction)	    */
/*			1 weak match (same address, opposite directions)    */
/* 			0 no match					    */
/* Parameters:	is1, is2 pointers to states we are checking		    */
/*									    */
/* Matches addresses, function uses fr_match_ipvXaddrs() to deal with IPv4  */
/* and IPv6 address format.						    */
/* ------------------------------------------------------------------------ */
static int fr_match_addresses(is1, is2)
ipstate_t *is1;
ipstate_t *is2;
{
	int	rv;

	if (is1->is_v == 4) {
		rv = fr_match_ipv4addrs(is1, is2);
	} else {
		rv = fr_match_ipv6addrs(is1, is2);
	}

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:	fr_match_ppairs						    */
/* Returns:	int - 	2 strong match (same ports, same direction)	    */
/*			1 weak match (same ports, different direction)	    */
/*			0 no match					    */
/* Parameters	ppairs1, ppairs - src, dst ports we want to match.	    */
/*									    */
/* Matches two port_pair_t types (port pairs). Each port pair contains	    */
/* src, dst port, which belong to session (state entry).		    */
/* ------------------------------------------------------------------------ */
static int fr_match_ppairs(ppairs1, ppairs2)
port_pair_t *ppairs1;
port_pair_t *ppairs2;
{
	int	rv;

	if (ppairs1->pp_sport == ppairs2->pp_sport &&
	    ppairs1->pp_dport == ppairs2->pp_dport)
		rv = 2;
	else if (ppairs1->pp_sport == ppairs2->pp_dport &&
		    ppairs1->pp_dport == ppairs2->pp_sport)
		rv = 1;
	else
		rv = 0;

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:	fr_match_l4_hdr						    */
/* Returns:	int -	0 no match,					    */
/*			1 weak match (same ports, different directions)	    */
/*			2 strong match (same ports, same direction)	    */
/* Parameters	is1, is2 - states we want to match			    */
/*									    */
/* Function matches L4 header data (source ports for TCP, UDP, CallIds for  */
/* GRE protocol).							    */
/* ------------------------------------------------------------------------ */
static int fr_match_l4_hdr(is1, is2)
ipstate_t *is1;
ipstate_t *is2;
{
	int	rv = 0;
	port_pair_t	pp1;
	port_pair_t	pp2;

	if (is1->is_p != is2->is_p)
		return (0);

	switch (is1->is_p) {
		case	IPPROTO_TCP:
			pp1.pp_sport = is1->is_ps.is_ts.ts_sport;
			pp1.pp_dport = is1->is_ps.is_ts.ts_dport;
			pp2.pp_sport = is2->is_ps.is_ts.ts_sport;
			pp2.pp_dport = is2->is_ps.is_ts.ts_dport;
			rv = fr_match_ppairs(&pp1, &pp2);
			break;
		case	IPPROTO_UDP:
			pp1.pp_sport = is1->is_ps.is_us.us_sport;
			pp1.pp_dport = is1->is_ps.is_us.us_dport;
			pp2.pp_sport = is2->is_ps.is_us.us_sport;
			pp2.pp_dport = is2->is_ps.is_us.us_dport;
			rv = fr_match_ppairs(&pp1, &pp2);
			break;
		case	IPPROTO_GRE:
			/* greinfo_t can be also interprted as port pair */
			pp1.pp_sport = is1->is_ps.is_ug.gs_call[0];
			pp1.pp_dport = is1->is_ps.is_ug.gs_call[1];
			pp2.pp_sport = is2->is_ps.is_ug.gs_call[0];
			pp2.pp_dport = is2->is_ps.is_ug.gs_call[1];
			rv = fr_match_ppairs(&pp1, &pp2);
			break;
		case	IPPROTO_ICMP:
		case	IPPROTO_ICMPV6:
			if (bcmp(&is1->is_ps, &is2->is_ps, sizeof (icmpinfo_t)))
				rv = 1;
			else
				rv = 0;
			break;
		default:
			rv = 0;
	}

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:	fr_matchstates						    */
/* Returns:	int - nonzero match, zero no match			    */
/* Parameters	is1, is2 - states we want to match			    */
/*									    */
/* The state entries are equal (identical match) if they belong to the same */
/* session. Any time new state entry is being added the fr_addstate()	    */
/* function creates temporal state entry from the data it gets from IP and  */
/* L4 header. The fr_matchstats() must be also aware of packet direction,   */
/* which is also stored within the state entry. We should keep in mind the  */
/* information about packet direction is spread accross L3 (addresses) and  */
/* L4 (ports). There are three possible relationships betwee is1, is2:	    */
/* 		- no match (match(is1, is2) == 0))			    */
/*		- weak match same addresses (ports), but different	    */
/*			directions (1)	(fr_match_xxxx(is1, is2) == 1)	    */
/*		- strong match same addresses (ports) and same directions   */
/*			 (2) (fr_match_xxxx(is1, is2) == 2)		    */
/*									    */
/* There are functions, which match match addresses (L3 header) in is1, is2 */
/* and functions, which are used to compare ports (L4 header) data. We say  */
/* the is1 and is2 are same (identical) if there is a match		    */
/* (fr_match_l4_hdr(is1, is2) != 0) and matchlevels are same for entries    */
/* (fr_match_l3_hdr(is1, is2) == fr_match_l4_hdr(is1, is2)) for is1, is2.   */
/* Such requirement deals with case as follows:				    */
/*	suppose there are two connections between hosts A, B. Connection 1: */
/*			a.a.a.a:12345 <=> b.b.b.b:54321			    */
/*		Connection 2:						    */
/*			a.a.a.a:54321 <=> b.b.b.b:12345			    */
/* since we've introduced match levels into our fr_matchstates(), we are    */
/* able to identify, which packets belong to connection A and which belong  */
/* to connection B.	Assume there are two entries is1, is2. is1 has been */
/* from con. 1 packet, which travelled from A to B:			    */
/*			a.a.a.a:12345 -> b.b.b.b:54321			    */
/* while s2, has been created from packet which belongs to con. 2 and is    */
/* also coming from A to B:						    */
/*			a.a.a.a:54321 -> b.b.b.b:12345			    */
/* fr_match_l3_hdr(is1, is2) == 2 -> strong match, while		    */
/* fr_match_l4_hdr(is1, is2) == 1 -> weak match. Since match levels are	    */
/* different the state entries are not identical -> no match as a final	    */
/* result.								    */
/* ------------------------------------------------------------------------ */
static int fr_matchstates(is1, is2)
ipstate_t *is1;
ipstate_t *is2;
{
	int	rv;
	int	amatch;
	int	pmatch;

	if (bcmp(&is1->is_pass, &is2->is_pass,
		offsetof(struct ipstate, is_ps) -
		offsetof(struct ipstate, is_pass)) == 0) {

		pmatch = fr_match_l4_hdr(is1, is2);
		amatch = fr_match_addresses(is1, is2);
		/*
		 * If addresses match (amatch != 0), then 'match levels'
		 * must be same for matching entries. If amatch and pmatch
		 * have different values (different match levels), then
		 * is1 and is2 belong to different sessions.
		 */
		rv = (amatch != 0) && (amatch == pmatch);
	}
	else
		rv = 0;

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_addstate                                                 */
/* Returns:     ipstate_t* - NULL == failure, else pointer to new state     */
/* Parameters:  fin(I)    - pointer to packet information                   */
/*              stsave(O) - pointer to place to save pointer to created     */
/*                          state structure.                                */
/*              flags(I)  - flags to use when creating the structure        */
/*                                                                          */
/* Creates a new IP state structure from the packet information collected.  */
/* Inserts it into the state table and appends to the bottom of the active  */
/* list.  If the capacity of the table has reached the maximum allowed then */
/* the call will fail and a flush is scheduled for the next timeout call.   */
/* ------------------------------------------------------------------------ */
ipstate_t *fr_addstate(fin, stsave, flags)
fr_info_t *fin;
ipstate_t **stsave;
u_int flags;
{
	ipstate_t *is, ips;
	struct icmp *ic;
	u_int pass, hv;
	frentry_t *fr;
	tcphdr_t *tcp;
	grehdr_t *gre;
	void *ifp;
	int out;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_fr_state_lock ||
	    (fin->fin_flx & (FI_SHORT|FI_STATE|FI_FRAGBODY|FI_BAD)))
		return NULL;

	if ((fin->fin_flx & FI_OOW) && !(fin->fin_tcpf & TH_SYN))
		return NULL;

	/*
	 * Trigger automatic call to fr_state_flush() if the
	 * table has reached capacity specified by hi watermark.
	 */
	if (ST_TAB_WATER_LEVEL(ifs) > ifs->ifs_state_flush_level_hi)
		ifs->ifs_fr_state_doflush = 1;

	/*
	 * If the max number of state entries has been reached, and there is no
	 * limit on the state count for the rule, then do not continue.  In the
	 * case where a limit exists, it's ok allow the entries to be created as
	 * long as specified limit itself has not been reached. 
	 *
	 * Note that because the lock isn't held on fr, it is possible to exceed
	 * the specified size of the table.  However, the cost of this is being
	 * ignored here; as the number by which it can go over is a product of
	 * the number of simultaneous threads that could be executing in here.
	 * So, a limit of 100 won't result in 200, but could result in 101 or 102.
	 *
	 * Also note that, since the automatic flush should have been triggered
	 * well before we reach the maximum number of state table entries, the
	 * likelihood of reaching the max (and thus exceedng it) is minimal.
	 */ 
	fr = fin->fin_fr;
	if (fr != NULL) {
		if ((ifs->ifs_ips_num >= ifs->ifs_fr_statemax) &&
		    (fr->fr_statemax == 0)) {
			ATOMIC_INCL(ifs->ifs_ips_stats.iss_max);
			return NULL;
		}
		if ((fr->fr_statemax != 0) &&
		    (fr->fr_statecnt >= fr->fr_statemax)) {
			ATOMIC_INCL(ifs->ifs_ips_stats.iss_maxref);
			ifs->ifs_fr_state_doflush = 1;
			return NULL;
		}
	}

	ic = NULL;
	tcp = NULL;
	out = fin->fin_out;
	is = &ips;
	bzero((char *)is, sizeof(*is));

	if (fr == NULL) {
		pass = ifs->ifs_fr_flags;
		is->is_tag = FR_NOLOGTAG;
	} else {
		pass = fr->fr_flags;
	}

	is->is_die = 1 + ifs->ifs_fr_ticks;
	/*
	 * We want to check everything that is a property of this packet,
	 * but we don't (automatically) care about it's fragment status as
	 * this may change.
	 */
	is->is_pass = pass;
	is->is_v = fin->fin_v;
	is->is_opt[0] = fin->fin_optmsk;
	is->is_optmsk[0] = 0xffffffff;
	/*
	 * The reverse direction option mask will be set in fr_matchsrcdst(),
	 * when we will see the first packet from the peer. We will leave it
	 * as zero for now.
	 */
	is->is_optmsk[1] = 0x0;

	if (is->is_v == 6) {
		is->is_opt[0] &= ~0x8;
		is->is_optmsk[0] &= ~0x8;
	}
	is->is_sec = fin->fin_secmsk;
	is->is_secmsk = 0xffff;
	is->is_auth = fin->fin_auth;
	is->is_authmsk = 0xffff;

	/*
	 * Copy and calculate...
	 */
	hv = (is->is_p = fin->fin_fi.fi_p);
	is->is_src = fin->fin_fi.fi_src;
	hv += is->is_saddr;
	is->is_dst = fin->fin_fi.fi_dst;
	hv += is->is_daddr;
#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		/*
		 * For ICMPv6, we check to see if the destination address is
		 * a multicast address.  If it is, do not include it in the
		 * calculation of the hash because the correct reply will come
		 * back from a real address, not a multicast address.
		 */
		if ((is->is_p == IPPROTO_ICMPV6) &&
		    IN6_IS_ADDR_MULTICAST(&is->is_dst.in6)) {
			/*
			 * So you can do keep state with neighbour discovery.
			 *
			 * Here we could use the address from the neighbour
			 * solicit message to put in the state structure and
			 * we could use that without a wildcard flag too...
			 */
			is->is_flags |= SI_W_DADDR;
			hv -= is->is_daddr;
		} else {
			hv += is->is_dst.i6[1];
			hv += is->is_dst.i6[2];
			hv += is->is_dst.i6[3];
		}
		hv += is->is_src.i6[1];
		hv += is->is_src.i6[2];
		hv += is->is_src.i6[3];
	}
#endif
	if ((fin->fin_v == 4) &&
	    (fin->fin_flx & (FI_MULTICAST|FI_BROADCAST|FI_MBCAST))) {
		if (fin->fin_out == 0) {
			flags |= SI_W_DADDR|SI_CLONE;
			hv -= is->is_daddr;
		} else {
			flags |= SI_W_SADDR|SI_CLONE;
			hv -= is->is_saddr;
		}
	}

	switch (is->is_p)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		ic = fin->fin_dp;

		switch (ic->icmp_type)
		{
		case ICMP6_ECHO_REQUEST :
			is->is_icmp.ici_type = ic->icmp_type;
			hv += (is->is_icmp.ici_id = ic->icmp_id);
			break;
		case ICMP6_MEMBERSHIP_QUERY :
		case ND_ROUTER_SOLICIT :
		case ND_NEIGHBOR_SOLICIT :
		case ICMP6_NI_QUERY :
			is->is_icmp.ici_type = ic->icmp_type;
			break;
		default :
			return NULL;
		}
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_icmp);
		break;
#endif
	case IPPROTO_ICMP :
		ic = fin->fin_dp;

		switch (ic->icmp_type)
		{
		case ICMP_ECHO :
		case ICMP_ECHOREPLY :
		case ICMP_TSTAMP :
		case ICMP_IREQ :
		case ICMP_MASKREQ :
			is->is_icmp.ici_type = ic->icmp_type;
			hv += (is->is_icmp.ici_id = ic->icmp_id);
			break;
		default :
			return NULL;
		}
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_icmp);
		break;

	case IPPROTO_GRE :
		gre = fin->fin_dp;

		is->is_gre.gs_flags = gre->gr_flags;
		is->is_gre.gs_ptype = gre->gr_ptype;
		if (GRE_REV(is->is_gre.gs_flags) == 1) {
			is->is_call[0] = fin->fin_data[0];
			is->is_call[1] = fin->fin_data[1];
		}
		break;

	case IPPROTO_TCP :
		tcp = fin->fin_dp;

		if (tcp->th_flags & TH_RST)
			return NULL;
		/*
		 * The endian of the ports doesn't matter, but the ack and
		 * sequence numbers do as we do mathematics on them later.
		 */
		is->is_sport = htons(fin->fin_data[0]);
		is->is_dport = htons(fin->fin_data[1]);
		if ((flags & (SI_W_DPORT|SI_W_SPORT)) == 0) {
			hv += is->is_sport;
			hv += is->is_dport;
		}

		/*
		 * If this is a real packet then initialise fields in the
		 * state information structure from the TCP header information.
		 */

		is->is_maxdwin = 1;
		is->is_maxswin = ntohs(tcp->th_win);
		if (is->is_maxswin == 0)
			is->is_maxswin = 1;

		if ((fin->fin_flx & FI_IGNORE) == 0) {
			is->is_send = ntohl(tcp->th_seq) + fin->fin_dlen -
				      (TCP_OFF(tcp) << 2) +
				      ((tcp->th_flags & TH_SYN) ? 1 : 0) +
				      ((tcp->th_flags & TH_FIN) ? 1 : 0);
			is->is_maxsend = is->is_send;

			/*
			 * Window scale option is only present in
			 * SYN/SYN-ACK packet.
			 */
			if ((tcp->th_flags & ~(TH_FIN|TH_ACK|TH_ECNALL)) ==
			    TH_SYN &&
			    (TCP_OFF(tcp) > (sizeof(tcphdr_t) >> 2))) {
				if (fr_tcpoptions(fin, tcp,
					&is->is_tcp.ts_data[0]) == -1) {
					fin->fin_flx |= FI_BAD;
				}
			}

			if ((fin->fin_out != 0) && (pass & FR_NEWISN) != 0) {
				fr_checknewisn(fin, is);
				fr_fixoutisn(fin, is);
			}

			if ((tcp->th_flags & TH_OPENING) == TH_SYN)
				flags |= IS_TCPFSM;
			else {
				is->is_maxdwin = is->is_maxswin * 2;
				is->is_dend = ntohl(tcp->th_ack);
				is->is_maxdend = ntohl(tcp->th_ack);
				is->is_maxdwin *= 2;
			}
		}

		/*
		 * If we're creating state for a starting connection, start the
		 * timer on it as we'll never see an error if it fails to
		 * connect.
		 */
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_tcp);
		break;

	case IPPROTO_UDP :
		tcp = fin->fin_dp;

		is->is_sport = htons(fin->fin_data[0]);
		is->is_dport = htons(fin->fin_data[1]);
		if ((flags & (SI_W_DPORT|SI_W_SPORT)) == 0) {
			hv += tcp->th_dport;
			hv += tcp->th_sport;
		}
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_udp);
		break;

	default :
		break;
	}
	hv = DOUBLE_HASH(hv, ifs);
	is->is_hv = hv;
	is->is_rule = fr;
	is->is_flags = flags & IS_INHERITED;

	/*
	 * Look for identical state.
	 */
	for (is = ifs->ifs_ips_table[is->is_hv % ifs->ifs_fr_statesize];
	     is != NULL;
	     is = is->is_hnext) {
		if (fr_matchstates(&ips, is) == 1)
			break;
	}

	/*
	 * we've found a matching state -> state already exists,
	 * we are not going to add a duplicate record.
	 */
	if (is != NULL)
		return NULL;

	if (ifs->ifs_ips_stats.iss_bucketlen[hv] >= ifs->ifs_fr_state_maxbucket) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_bucketfull);
		return NULL;
	}
	KMALLOC(is, ipstate_t *);
	if (is == NULL) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_nomem);
		return NULL;
	}
	bcopy((char *)&ips, (char *)is, sizeof(*is));
	/*
	 * Do not do the modulous here, it is done in fr_stinsert().
	 */
	if (fr != NULL) {
		(void) strncpy(is->is_group, fr->fr_group, FR_GROUPLEN);
		if (fr->fr_age[0] != 0) {
			is->is_tqehead[0] = 
			    fr_addtimeoutqueue(&ifs->ifs_ips_utqe,
					       fr->fr_age[0], ifs);
			is->is_sti.tqe_flags |= TQE_RULEBASED;
		}
		if (fr->fr_age[1] != 0) {
			is->is_tqehead[1] = 
			    fr_addtimeoutqueue(&ifs->ifs_ips_utqe,
					       fr->fr_age[1], ifs);
			is->is_sti.tqe_flags |= TQE_RULEBASED;
		}
		is->is_tag = fr->fr_logtag;

		is->is_ifp[(out << 1) + 1] = fr->fr_ifas[1];
		is->is_ifp[(1 - out) << 1] = fr->fr_ifas[2];
		is->is_ifp[((1 - out) << 1) + 1] = fr->fr_ifas[3];

		if (((ifp = fr->fr_ifas[1]) != NULL) &&
		    (ifp != (void *)-1)) {
			COPYIFNAME(ifp, is->is_ifname[(out << 1) + 1], fr->fr_v);
		}
		if (((ifp = fr->fr_ifas[2]) != NULL) &&
		    (ifp != (void *)-1)) {
			COPYIFNAME(ifp, is->is_ifname[(1 - out) << 1], fr->fr_v);
		}
		if (((ifp = fr->fr_ifas[3]) != NULL) &&
		    (ifp != (void *)-1)) {
			COPYIFNAME(ifp, is->is_ifname[((1 - out) << 1) + 1], fr->fr_v);
		}
	}

	is->is_ifp[out << 1] = fin->fin_ifp;
	if (fin->fin_ifp != NULL) {
		COPYIFNAME(fin->fin_ifp, is->is_ifname[out << 1], fin->fin_v);
	}

	is->is_ref = 1;
	is->is_pkts[0] = 0, is->is_bytes[0] = 0;
	is->is_pkts[1] = 0, is->is_bytes[1] = 0;
	is->is_pkts[2] = 0, is->is_bytes[2] = 0;
	is->is_pkts[3] = 0, is->is_bytes[3] = 0;
	if ((fin->fin_flx & FI_IGNORE) == 0) {
		is->is_pkts[out] = 1;
		is->is_bytes[out] = fin->fin_plen;
		is->is_flx[out][0] = fin->fin_flx & FI_CMP;
		is->is_flx[out][0] &= ~FI_OOW;
	}

	if (pass & FR_STSTRICT)
		is->is_flags |= IS_STRICT;

	if (pass & FR_STATESYNC)
		is->is_flags |= IS_STATESYNC;

	if (flags & (SI_WILDP|SI_WILDA)) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_wild);
	}
	is->is_rulen = fin->fin_rule;


	if (pass & FR_LOGFIRST)
		is->is_pass &= ~(FR_LOGFIRST|FR_LOG);

	READ_ENTER(&ifs->ifs_ipf_state);
	is->is_me = stsave;

	fr_stinsert(is, fin->fin_rev, ifs);

	if (fin->fin_p == IPPROTO_TCP) {
		/*
		* If we're creating state for a starting connection, start the
		* timer on it as we'll never see an error if it fails to
		* connect.
		*/
		(void) fr_tcp_age(&is->is_sti, fin, ifs->ifs_ips_tqtqb,
				  is->is_flags);
		MUTEX_EXIT(&is->is_lock);
#ifdef	IPFILTER_SCAN
		if ((is->is_flags & SI_CLONE) == 0)
			(void) ipsc_attachis(is);
#endif
	} else {
		MUTEX_EXIT(&is->is_lock);
	}
#ifdef	IPFILTER_SYNC
	if ((is->is_flags & IS_STATESYNC) && ((is->is_flags & SI_CLONE) == 0))
		is->is_sync = ipfsync_new(SMC_STATE, fin, is);
#endif
	if (ifs->ifs_ipstate_logging)
		ipstate_log(is, ISL_NEW, ifs);

	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	fin->fin_rev = IP6_NEQ(&is->is_dst, &fin->fin_daddr);
	fin->fin_flx |= FI_STATE;
	if (fin->fin_flx & FI_FRAG)
		(void) fr_newfrag(fin, pass ^ FR_KEEPSTATE);

	return is;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_tcpoptions                                               */
/* Returns:     int - 1 == packet matches state entry, 0 == it does not     */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP packet header                       */
/*              td(I)  - pointer to TCP data held as part of the state      */
/*                                                                          */
/* Look after the TCP header for any options and deal with those that are   */
/* present.  Record details about those that we recogise.                   */
/* ------------------------------------------------------------------------ */
static int fr_tcpoptions(fin, tcp, td)
fr_info_t *fin;
tcphdr_t *tcp;
tcpdata_t *td;
{
	int off, mlen, ol, i, len, retval;
	char buf[64], *s, opt;
	mb_t *m = NULL;

	len = (TCP_OFF(tcp) << 2);
	if (fin->fin_dlen < len)
		return 0;
	len -= sizeof(*tcp);

	off = fin->fin_plen - fin->fin_dlen + sizeof(*tcp) + fin->fin_ipoff;

	m = fin->fin_m;
	mlen = MSGDSIZE(m) - off;
	if (len > mlen) {
		len = mlen;
		retval = 0;
	} else {
		retval = 1;
	}

	COPYDATA(m, off, len, buf);

	for (s = buf; len > 0; ) {
		opt = *s;
		if (opt == TCPOPT_EOL)
			break;
		else if (opt == TCPOPT_NOP)
			ol = 1;
		else {
			if (len < 2)
				break;
			ol = (int)*(s + 1);
			if (ol < 2 || ol > len)
				break;

			/*
			 * Extract the TCP options we are interested in out of
			 * the header and store them in the the tcpdata struct.
			 */
			switch (opt)
			{
			case TCPOPT_WINDOW :
				if (ol == TCPOLEN_WINDOW) {
					i = (int)*(s + 2);
					if (i > TCP_WSCALE_MAX)
						i = TCP_WSCALE_MAX;
					else if (i < 0)
						i = 0;
					td->td_winscale = i;
					td->td_winflags |= TCP_WSCALE_SEEN |
							    TCP_WSCALE_FIRST;
				} else
					retval = -1;
				break;
			case TCPOPT_MAXSEG :
				/*
				 * So, if we wanted to set the TCP MAXSEG,
				 * it should be done here...
				 */
				if (ol == TCPOLEN_MAXSEG) {
					i = (int)*(s + 2);
					i <<= 8;
					i += (int)*(s + 3);
					td->td_maxseg = i;
				} else
					retval = -1;
				break;
			case TCPOPT_SACK_PERMITTED :
				if (ol == TCPOLEN_SACK_PERMITTED)
					td->td_winflags |= TCP_SACK_PERMIT;
				else
					retval = -1;
				break;
			}
		}
		len -= ol;
		s += ol;
	}
	return retval;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_tcpstate                                                 */
/* Returns:     int - 1 == packet matches state entry, 0 == it does not     */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              tcp(I)   - pointer to TCP packet header                     */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Check to see if a packet with TCP headers fits within the TCP window.    */
/* Change timeout depending on whether new packet is a SYN-ACK returning    */
/* for a SYN or a RST or FIN which indicate time to close up shop.          */
/* ------------------------------------------------------------------------ */
static int fr_tcpstate(fin, tcp, is)
fr_info_t *fin;
tcphdr_t *tcp;
ipstate_t *is;
{
	int source, ret = 0, flags;
	tcpdata_t  *fdata, *tdata;
	ipf_stack_t *ifs = fin->fin_ifs;

	source = !fin->fin_rev;
	if (((is->is_flags & IS_TCPFSM) != 0) && (source == 1) && 
	    (ntohs(is->is_sport) != fin->fin_data[0]))
		source = 0;
	fdata = &is->is_tcp.ts_data[!source];
	tdata = &is->is_tcp.ts_data[source];

	MUTEX_ENTER(&is->is_lock);

	/*
	 * If a SYN packet is received for a connection that is in a half
	 * closed state, then move its state entry to deletetq. In such case
	 * the SYN packet will be consequently dropped. This allows new state
	 * entry to be created with a retransmited SYN packet.
	 */
	if ((tcp->th_flags & TH_OPENING) == TH_SYN) {
		if ((is->is_state[source] > IPF_TCPS_ESTABLISHED) &&
		    (is->is_state[!source] > IPF_TCPS_ESTABLISHED)) {
			is->is_state[source] = IPF_TCPS_CLOSED;
			is->is_state[!source] = IPF_TCPS_CLOSED;
			/*
			 * Do not update is->is_sti.tqe_die in case state entry
			 * is already present in deletetq. It prevents state
			 * entry ttl update by retransmitted SYN packets, which
			 * may arrive before timer tick kicks off. The SYN
			 * packet will be dropped again.
			 */
			if (is->is_sti.tqe_ifq != &ifs->ifs_ips_deletetq)
				fr_movequeue(&is->is_sti, is->is_sti.tqe_ifq,
					&fin->fin_ifs->ifs_ips_deletetq,
					fin->fin_ifs);

			MUTEX_EXIT(&is->is_lock);
			return 0;
		}
	}

	if (fr_tcpinwindow(fin, fdata, tdata, tcp, is->is_flags)) {
#ifdef	IPFILTER_SCAN
		if (is->is_flags & (IS_SC_CLIENT|IS_SC_SERVER)) {
			ipsc_packet(fin, is);
			if (FR_ISBLOCK(is->is_pass)) {
				MUTEX_EXIT(&is->is_lock);
				return 1;
			}
		}
#endif

		/*
		 * Nearing end of connection, start timeout.
		 */
		ret = fr_tcp_age(&is->is_sti, fin, ifs->ifs_ips_tqtqb,
				 is->is_flags);
		if (ret == 0) {
			MUTEX_EXIT(&is->is_lock);
			return 0;
		}

		/*
		 * set s0's as appropriate.  Use syn-ack packet as it
		 * contains both pieces of required information.
		 */
		/*
		 * Window scale option is only present in SYN/SYN-ACK packet.
		 * Compare with ~TH_FIN to mask out T/TCP setups.
		 */
		flags = tcp->th_flags & ~(TH_FIN|TH_ECNALL);
		if (flags == (TH_SYN|TH_ACK)) {
			is->is_s0[source] = ntohl(tcp->th_ack);
			is->is_s0[!source] = ntohl(tcp->th_seq) + 1;
			if (TCP_OFF(tcp) > (sizeof (tcphdr_t) >> 2)) {
				(void) fr_tcpoptions(fin, tcp, fdata);
			}
			if ((fin->fin_out != 0) && (is->is_pass & FR_NEWISN))
				fr_checknewisn(fin, is);
		} else if (flags == TH_SYN) {
			is->is_s0[source] = ntohl(tcp->th_seq) + 1;
			if ((TCP_OFF(tcp) > (sizeof(tcphdr_t) >> 2)))
				(void) fr_tcpoptions(fin, tcp, tdata);

			if ((fin->fin_out != 0) && (is->is_pass & FR_NEWISN))
				fr_checknewisn(fin, is);

		}
		ret = 1;
	} else
		fin->fin_flx |= FI_OOW;
	MUTEX_EXIT(&is->is_lock);
	return ret;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_checknewisn                                              */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Check to see if this TCP connection is expecting and needs a new         */
/* sequence number for a particular direction of the connection.            */
/*                                                                          */
/* NOTE: This does not actually change the sequence numbers, only gets new  */
/* one ready.                                                               */
/* ------------------------------------------------------------------------ */
static void fr_checknewisn(fin, is)
fr_info_t *fin;
ipstate_t *is;
{
	u_32_t sumd, old, new;
	tcphdr_t *tcp;
	int i;

	i = fin->fin_rev;
	tcp = fin->fin_dp;

	if (((i == 0) && !(is->is_flags & IS_ISNSYN)) ||
	    ((i == 1) && !(is->is_flags & IS_ISNACK))) {
		old = ntohl(tcp->th_seq);
		new = fr_newisn(fin);
		is->is_isninc[i] = new - old;
		CALC_SUMD(old, new, sumd);
		is->is_sumd[i] = (sumd & 0xffff) + (sumd >> 16);

		is->is_flags |= ((i == 0) ? IS_ISNSYN : IS_ISNACK);
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_tcpinwindow                                              */
/* Returns:     int - 1 == packet inside TCP "window", 0 == not inside.     */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              fdata(I) - pointer to tcp state informatio (forward)        */
/*              tdata(I) - pointer to tcp state informatio (reverse)        */
/*              tcp(I)   - pointer to TCP packet header                     */
/*                                                                          */
/* Given a packet has matched addresses and ports, check to see if it is    */
/* within the TCP data window.  In a show of generosity, allow packets that */
/* are within the window space behind the current sequence # as well.       */
/* ------------------------------------------------------------------------ */
int fr_tcpinwindow(fin, fdata, tdata, tcp, flags)
fr_info_t *fin;
tcpdata_t  *fdata, *tdata;
tcphdr_t *tcp;
int flags;
{
	tcp_seq seq, ack, end;
	int ackskew, tcpflags;
	u_32_t win, maxwin;
	int dsize, inseq;

	/*
	 * Find difference between last checked packet and this packet.
	 */
	tcpflags = tcp->th_flags;
	seq = ntohl(tcp->th_seq);
	ack = ntohl(tcp->th_ack);

	if (tcpflags & TH_SYN)
		win = ntohs(tcp->th_win);
	else
		win = ntohs(tcp->th_win) << fdata->td_winscale;

	/*
	 * win 0 means the receiving endpoint has closed the window, because it
	 * has not enough memory to receive data from sender. In such case we
	 * are pretending window size to be 1 to let TCP probe data through.
	 * TCP probe data can be either 0 or 1 octet of data, the RFC does not
	 * state this accurately, so we have to allow 1 octet (win = 1) even if
	 * the window is closed (win == 0).
	 */
	if (win == 0)
		win = 1;

	dsize = fin->fin_dlen - (TCP_OFF(tcp) << 2) +
		((tcpflags & TH_SYN) ? 1 : 0) + ((tcpflags & TH_FIN) ? 1 : 0);

	/*
	 * if window scaling is present, the scaling is only allowed
	 * for windows not in the first SYN packet. In that packet the
	 * window is 65535 to specify the largest window possible
	 * for receivers not implementing the window scale option.
	 * Currently, we do not assume TTCP here. That means that
	 * if we see a second packet from a host (after the initial
	 * SYN), we can assume that the receiver of the SYN did
	 * already send back the SYN/ACK (and thus that we know if
	 * the receiver also does window scaling)
	 */
	if (!(tcpflags & TH_SYN) && (fdata->td_winflags & TCP_WSCALE_FIRST)) {
		fdata->td_maxwin = win;
	}

	end = seq + dsize;

	if ((fdata->td_end == 0) &&
	    (!(flags & IS_TCPFSM) ||
	     ((tcpflags & TH_OPENING) == TH_OPENING))) {
		/*
		 * Must be a (outgoing) SYN-ACK in reply to a SYN.
		 */
		fdata->td_end = end - 1;
		fdata->td_maxwin = 1;
		fdata->td_maxend = end + win;
	}

	if (!(tcpflags & TH_ACK)) {  /* Pretend an ack was sent */
		ack = tdata->td_end;
	} else if (((tcpflags & (TH_ACK|TH_RST)) == (TH_ACK|TH_RST)) &&
		   (ack == 0)) {
		/* gross hack to get around certain broken tcp stacks */
		ack = tdata->td_end;
	}

	maxwin = tdata->td_maxwin;
	ackskew = tdata->td_end - ack;

	/*
	 * Strict sequencing only allows in-order delivery.
	 */
	if ((flags & IS_STRICT) != 0) {
		if (seq != fdata->td_end) {
			DTRACE_PROBE(strict_check);
			return 0;
		}
	}

#define	SEQ_GE(a,b)	((int)((a) - (b)) >= 0)
#define	SEQ_GT(a,b)	((int)((a) - (b)) > 0)
	inseq = 0;
	DTRACE_PROBE4(
		dyn_params,
		int, dsize,
		int, ackskew,
		int, maxwin,
		int, win
	);
	if (
#if defined(_KERNEL)
		/* 
		 * end <-> s + n
		 * maxend <-> ack + win
		 * this is upperbound check
		 */
	    (SEQ_GE(fdata->td_maxend, end)) &&
		/*
		 * this is lowerbound check
		 */
	    (SEQ_GE(seq, fdata->td_end - maxwin)) &&
#endif
/* XXX what about big packets */
#define MAXACKWINDOW 66000
	    (-ackskew <= (MAXACKWINDOW << fdata->td_winscale)) &&
	    ( ackskew <= (MAXACKWINDOW << fdata->td_winscale))) {
		inseq = 1;
	/*
	 * Microsoft Windows will send the next packet to the right of the
	 * window if SACK is in use.
	 */
	} else if ((seq == fdata->td_maxend) && (ackskew == 0) &&
	    (fdata->td_winflags & TCP_SACK_PERMIT) &&
	    (tdata->td_winflags & TCP_SACK_PERMIT)) {
		inseq = 1;
	/*
	 * RST ACK with SEQ equal to 0 is sent by some OSes (i.e. Solaris) as a
	 * response to initial SYN packet, when  there is no application
	 * listeing to on a port, where the SYN packet has came to.
	 */
	} else if ((seq == 0) && (tcpflags == (TH_RST|TH_ACK)) &&
			(ackskew >= -1) && (ackskew <= 1)) {
		inseq = 1;
	} else if (!(flags & IS_TCPFSM)) {

		if (!(fdata->td_winflags &
			    (TCP_WSCALE_SEEN|TCP_WSCALE_FIRST))) {
			/*
			 * No TCPFSM and no window scaling, so make some
			 * extra guesses.
			 */
			if ((seq == fdata->td_maxend) && (ackskew == 0))
				inseq = 1;
			else if (SEQ_GE(seq + maxwin, fdata->td_end - maxwin))
				inseq = 1;
		}
	}

	if (inseq) {
		/* if ackskew < 0 then this should be due to fragmented
		 * packets. There is no way to know the length of the
		 * total packet in advance.
		 * We do know the total length from the fragment cache though.
		 * Note however that there might be more sessions with
		 * exactly the same source and destination parameters in the
		 * state cache (and source and destination is the only stuff
		 * that is saved in the fragment cache). Note further that
		 * some TCP connections in the state cache are hashed with
		 * sport and dport as well which makes it not worthwhile to
		 * look for them.
		 * Thus, when ackskew is negative but still seems to belong
		 * to this session, we bump up the destinations end value.
		 */
		if (ackskew < 0) {
			DTRACE_PROBE2(end_update_td,
				int, tdata->td_end,
				int, ack
			);
			tdata->td_end = ack;
		}

		/* update max window seen */
		if (fdata->td_maxwin < win) {
			DTRACE_PROBE2(win_update_fd,
				int, fdata->td_maxwin,
				int, win
			);
			fdata->td_maxwin = win;
		}

		if (SEQ_GT(end, fdata->td_end)) {
			DTRACE_PROBE2(end_update_fd,
				int, fdata->td_end,
				int, end
			);
			fdata->td_end = end;
		}

		if (SEQ_GE(ack + win, tdata->td_maxend)) {
			DTRACE_PROBE2(max_end_update_td,
				int, tdata->td_maxend,
				int, ack + win
			);
			tdata->td_maxend = ack + win;
		}

		return 1;
	}
	fin->fin_flx |= FI_OOW;

#if defined(_KERNEL)
	if (!(SEQ_GE(seq, fdata->td_end - maxwin)))
		fin->fin_flx |= FI_NEG_OOW;
#endif

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stclone                                                  */
/* Returns:     ipstate_t* - NULL == cloning failed,                        */
/*                           else pointer to new state structure            */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP/UDP header                          */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Create a "duplcate" state table entry from the master.                   */
/* ------------------------------------------------------------------------ */
static ipstate_t *fr_stclone(fin, tcp, is)
fr_info_t *fin;
tcphdr_t *tcp;
ipstate_t *is;
{
	ipstate_t *clone;
	u_32_t send;
	ipf_stack_t *ifs = fin->fin_ifs;

	/*
	 * Trigger automatic call to fr_state_flush() if the
	 * table has reached capacity specified by hi watermark.
	 */
	if (ST_TAB_WATER_LEVEL(ifs) > ifs->ifs_state_flush_level_hi)
		ifs->ifs_fr_state_doflush = 1;

	/*
	 * If automatic flushing did not do its job, and the table
	 * has filled up, don't try to create a new entry.  A NULL
	 * return will indicate that the cloning has failed.
	 */
	if (ifs->ifs_ips_num >= ifs->ifs_fr_statemax) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_max);
		return NULL;
	}

	KMALLOC(clone, ipstate_t *);
	if (clone == NULL)
		return NULL;
	bcopy((char *)is, (char *)clone, sizeof(*clone));

	MUTEX_NUKE(&clone->is_lock);

	clone->is_die = ONE_DAY + ifs->ifs_fr_ticks;
	clone->is_state[0] = 0;
	clone->is_state[1] = 0;
	send = ntohl(tcp->th_seq) + fin->fin_dlen - (TCP_OFF(tcp) << 2) +
		((tcp->th_flags & TH_SYN) ? 1 : 0) +
		((tcp->th_flags & TH_FIN) ? 1 : 0);

	if (fin->fin_rev == 1) {
		clone->is_dend = send;
		clone->is_maxdend = send;
		clone->is_send = 0;
		clone->is_maxswin = 1;
		clone->is_maxdwin = ntohs(tcp->th_win);
		if (clone->is_maxdwin == 0)
			clone->is_maxdwin = 1;
	} else {
		clone->is_send = send;
		clone->is_maxsend = send;
		clone->is_dend = 0;
		clone->is_maxdwin = 1;
		clone->is_maxswin = ntohs(tcp->th_win);
		if (clone->is_maxswin == 0)
			clone->is_maxswin = 1;
	}

	clone->is_flags &= ~SI_CLONE;
	clone->is_flags |= SI_CLONED;
	fr_stinsert(clone, fin->fin_rev, ifs);
	clone->is_ref = 1;
	if (clone->is_p == IPPROTO_TCP) {
		(void) fr_tcp_age(&clone->is_sti, fin, ifs->ifs_ips_tqtqb,
				  clone->is_flags);
	}
	MUTEX_EXIT(&clone->is_lock);
#ifdef	IPFILTER_SCAN
	(void) ipsc_attachis(is);
#endif
#ifdef	IPFILTER_SYNC
	if (is->is_flags & IS_STATESYNC)
		clone->is_sync = ipfsync_new(SMC_STATE, fin, clone);
#endif
	return clone;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_matchsrcdst                                              */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              is(I)  - pointer to state structure                         */
/*              src(I) - pointer to source address                          */
/*              dst(I) - pointer to destination address                     */
/*              tcp(I) - pointer to TCP/UDP header                          */
/*                                                                          */
/* Match a state table entry against an IP packet.  The logic below is that */
/* ret gets set to one if the match succeeds, else remains 0.  If it is     */
/* still 0 after the test. no match.                                        */
/* ------------------------------------------------------------------------ */
static ipstate_t *fr_matchsrcdst(fin, is, src, dst, tcp, cmask)
fr_info_t *fin;
ipstate_t *is;
i6addr_t *src, *dst;
tcphdr_t *tcp;
u_32_t cmask;
{
	int ret = 0, rev, out, flags, flx = 0, idx;
	u_short sp, dp;
	u_32_t cflx;
	void *ifp;
	ipf_stack_t *ifs = fin->fin_ifs;

	rev = IP6_NEQ(&is->is_dst, dst);
	ifp = fin->fin_ifp;
	out = fin->fin_out;
	flags = is->is_flags;
	sp = 0;
	dp = 0;

	if (tcp != NULL) {
		sp = htons(fin->fin_sport);
		dp = ntohs(fin->fin_dport);
	}
	if (!rev) {
		if (tcp != NULL) {
			if (!(flags & SI_W_SPORT) && (sp != is->is_sport))
				rev = 1;
			else if (!(flags & SI_W_DPORT) && (dp != is->is_dport))
				rev = 1;
		}
	}

	idx = (out << 1) + rev;

	/*
	 * If the interface for this 'direction' is set, make sure it matches.
	 * An interface name that is not set matches any, as does a name of *.
	 */
	if ((is->is_ifp[idx] == NULL &&
	    (*is->is_ifname[idx] == '\0' || *is->is_ifname[idx] == '*')) ||
	    is->is_ifp[idx] == ifp)
		ret = 1;

	if (ret == 0) {
		DTRACE_PROBE(no_match_on_iface);
		return NULL;
	}
	ret = 0;

	/*
	 * Match addresses and ports.
	 */
	if (rev == 0) {
		if ((IP6_EQ(&is->is_dst, dst) || (flags & SI_W_DADDR)) &&
		    (IP6_EQ(&is->is_src, src) || (flags & SI_W_SADDR))) {
			if (tcp) {
				if ((sp == is->is_sport || flags & SI_W_SPORT)&&
				    (dp == is->is_dport || flags & SI_W_DPORT))
					ret = 1;
			} else {
				ret = 1;
			}
		}
	} else {
		if ((IP6_EQ(&is->is_dst, src) || (flags & SI_W_DADDR)) &&
		    (IP6_EQ(&is->is_src, dst) || (flags & SI_W_SADDR))) {
			if (tcp) {
				if ((dp == is->is_sport || flags & SI_W_SPORT)&&
				    (sp == is->is_dport || flags & SI_W_DPORT))
					ret = 1;
			} else {
				ret = 1;
			}
		}
	}

	if (ret == 0) {
		DTRACE_PROBE(no_match_on_addrs);
		return NULL;
	}
	/*
	 * Whether or not this should be here, is questionable, but the aim
	 * is to get this out of the main line.
	 */
	if (tcp == NULL)
		flags = is->is_flags & ~(SI_WILDP|SI_NEWFR|SI_CLONE|SI_CLONED);

	/*
	 * Only one of the source or destination address can be flaged as a
	 * wildcard.  Fill in the missing address, if set.
	 * For IPv6, if the address being copied in is multicast, then
	 * don't reset the wild flag - multicast causes it to be set in the
	 * first place!
	 */
	if ((flags & (SI_W_SADDR|SI_W_DADDR))) {
		fr_ip_t *fi = &fin->fin_fi;

		if ((flags & SI_W_SADDR) != 0) {
			if (rev == 0) {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_src.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_src = fi->fi_src;
					is->is_flags &= ~SI_W_SADDR;
				}
			} else {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_dst.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_src = fi->fi_dst;
					is->is_flags &= ~SI_W_SADDR;
				}
			}
		} else if ((flags & SI_W_DADDR) != 0) {
			if (rev == 0) {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_dst.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_dst = fi->fi_dst;
					is->is_flags &= ~SI_W_DADDR;
				}
			} else {
#ifdef USE_INET6
				if (is->is_v == 6 &&
				    IN6_IS_ADDR_MULTICAST(&fi->fi_src.in6))
					/*EMPTY*/;
				else
#endif
				{
					is->is_dst = fi->fi_src;
					is->is_flags &= ~SI_W_DADDR;
				}
			}
		}
		if ((is->is_flags & (SI_WILDA|SI_WILDP)) == 0) {
			ATOMIC_DECL(ifs->ifs_ips_stats.iss_wild);
		}
	}

	flx = fin->fin_flx & cmask;
	cflx = is->is_flx[out][rev];

	/*
	 * Match up any flags set from IP options.
	 */
	if ((cflx && (flx != (cflx & cmask))) ||
	    ((fin->fin_optmsk & is->is_optmsk[rev]) != is->is_opt[rev]) ||
	    ((fin->fin_secmsk & is->is_secmsk) != is->is_sec) ||
	    ((fin->fin_auth & is->is_authmsk) != is->is_auth)) {
		DTRACE_PROBE4(no_match_on_flags,
		    int, (cflx && (flx != (cflx & cmask))),
		    int,
		    ((fin->fin_optmsk & is->is_optmsk[rev]) != is->is_opt[rev]),
		    int, ((fin->fin_secmsk & is->is_secmsk) != is->is_sec),
		    int, ((fin->fin_auth & is->is_authmsk) != is->is_auth)
		);
		return NULL;
	}
	/*
	 * Only one of the source or destination port can be flagged as a
	 * wildcard.  When filling it in, fill in a copy of the matched entry
	 * if it has the cloning flag set.
	 */
	if ((fin->fin_flx & FI_IGNORE) != 0) {
		fin->fin_rev = rev;
		return is;
	}

	if ((flags & (SI_W_SPORT|SI_W_DPORT))) {
		if ((flags & SI_CLONE) != 0) {
			ipstate_t *clone;

			clone = fr_stclone(fin, tcp, is);
			if (clone == NULL)
				return NULL;
			is = clone;
		} else {
			ATOMIC_DECL(ifs->ifs_ips_stats.iss_wild);
		}

		if ((flags & SI_W_SPORT) != 0) {
			if (rev == 0) {
				is->is_sport = sp;
				is->is_send = ntohl(tcp->th_seq);
			} else {
				is->is_sport = dp;
				is->is_send = ntohl(tcp->th_ack);
			}
			is->is_maxsend = is->is_send + 1;
		} else if ((flags & SI_W_DPORT) != 0) {
			if (rev == 0) {
				is->is_dport = dp;
				is->is_dend = ntohl(tcp->th_ack);
			} else {
				is->is_dport = sp;
				is->is_dend = ntohl(tcp->th_seq);
			}
			is->is_maxdend = is->is_dend + 1;
		}
		is->is_flags &= ~(SI_W_SPORT|SI_W_DPORT);
		if ((flags & SI_CLONED) && ifs->ifs_ipstate_logging)
			ipstate_log(is, ISL_CLONE, ifs);
	}

	ret = -1;

	if (is->is_flx[out][rev] == 0) {
		is->is_flx[out][rev] = flx;
		/*
		 * If we are dealing with the first packet coming in reverse
		 * direction (sent by peer), then we have to set options into
		 * state.
		 */
		if (rev == 1 && is->is_optmsk[1] == 0x0) {
			is->is_optmsk[1] = 0xffffffff;
			is->is_opt[1] = fin->fin_optmsk;
			DTRACE_PROBE(set_rev_opts);
		}
		if (is->is_v == 6) {
			is->is_opt[rev] &= ~0x8;
			is->is_optmsk[rev] &= ~0x8;
		}
	}

	/*
	 * Check if the interface name for this "direction" is set and if not,
	 * fill it in.
	 */
	if (is->is_ifp[idx] == NULL &&
	    (*is->is_ifname[idx] == '\0' || *is->is_ifname[idx] == '*')) {
		is->is_ifp[idx] = ifp;
		COPYIFNAME(ifp, is->is_ifname[idx], fin->fin_v);
	}
	fin->fin_rev = rev;
	return is;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_checkicmpmatchingstate                                   */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* If we've got an ICMP error message, using the information stored in the  */
/* ICMP packet, look for a matching state table entry.                      */
/*                                                                          */
/* If we return NULL then no lock on ipf_state is held.                     */
/* If we return non-null then a read-lock on ipf_state is held.             */
/* ------------------------------------------------------------------------ */
static ipstate_t *fr_checkicmpmatchingstate(fin)
fr_info_t *fin;
{
	ipstate_t *is, **isp;
	u_short sport, dport;
	u_char	pr;
	int backward, i, oi;
	i6addr_t dst, src;
	struct icmp *ic;
	u_short savelen;
	icmphdr_t *icmp;
	fr_info_t ofin;
	tcphdr_t *tcp;
	int len;
	ip_t *oip;
	u_int hv;
	ipf_stack_t *ifs = fin->fin_ifs;

	/*
	 * Does it at least have the return (basic) IP header ?
	 * Is it an actual recognised ICMP error type?
	 * Only a basic IP header (no options) should be with
	 * an ICMP error header.
	 */
	if ((fin->fin_v != 4) || (fin->fin_hlen != sizeof(ip_t)) ||
	    (fin->fin_plen < ICMPERR_MINPKTLEN) ||
	    !(fin->fin_flx & FI_ICMPERR))
		return NULL;
	ic = fin->fin_dp;

	oip = (ip_t *)((char *)ic + ICMPERR_ICMPHLEN);
	/*
	 * Check if the at least the old IP header (with options) and
	 * 8 bytes of payload is present.
	 */
	if (fin->fin_plen < ICMPERR_MAXPKTLEN + ((IP_HL(oip) - 5) << 2))
		return NULL;

	/*
	 * Sanity Checks.
	 */
	len = fin->fin_dlen - ICMPERR_ICMPHLEN;
	if ((len <= 0) || ((IP_HL(oip) << 2) > len))
		return NULL;

	/*
	 * Is the buffer big enough for all of it ?  It's the size of the IP
	 * header claimed in the encapsulated part which is of concern.  It
	 * may be too big to be in this buffer but not so big that it's
	 * outside the ICMP packet, leading to TCP deref's causing problems.
	 * This is possible because we don't know how big oip_hl is when we
	 * do the pullup early in fr_check() and thus can't guarantee it is
	 * all here now.
	 */
#ifdef  _KERNEL
	{
	mb_t *m;

	m = fin->fin_m;
# if defined(MENTAT)
	if ((char *)oip + len > (char *)m->b_wptr)
		return NULL;
# else
	if ((char *)oip + len > (char *)fin->fin_ip + m->m_len)
		return NULL;
# endif
	}
#endif
	bcopy((char *)fin, (char *)&ofin, sizeof(*fin));

	/*
	 * in the IPv4 case we must zero the i6addr union otherwise
	 * the IP6_EQ and IP6_NEQ macros produce the wrong results because
	 * of the 'junk' in the unused part of the union
	 */
	bzero((char *)&src, sizeof(src));
	bzero((char *)&dst, sizeof(dst));

	/*
	 * we make an fin entry to be able to feed it to
	 * matchsrcdst note that not all fields are encessary
	 * but this is the cleanest way. Note further we fill
	 * in fin_mp such that if someone uses it we'll get
	 * a kernel panic. fr_matchsrcdst does not use this.
	 *
	 * watch out here, as ip is in host order and oip in network
	 * order. Any change we make must be undone afterwards, like
	 * oip->ip_off - it is still in network byte order so fix it.
	 */
	savelen = oip->ip_len;
	oip->ip_len = len;
	oip->ip_off = ntohs(oip->ip_off);

	ofin.fin_flx = FI_NOCKSUM;
	ofin.fin_v = 4;
	ofin.fin_ip = oip;
	ofin.fin_m = NULL;	/* if dereferenced, panic XXX */
	ofin.fin_mp = NULL;	/* if dereferenced, panic XXX */
	ofin.fin_plen = fin->fin_dlen - ICMPERR_ICMPHLEN;
	(void) fr_makefrip(IP_HL(oip) << 2, oip, &ofin);
	ofin.fin_ifp = fin->fin_ifp;
	ofin.fin_out = !fin->fin_out;
	/*
	 * Reset the short and bad flag here because in fr_matchsrcdst()
	 * the flags for the current packet (fin_flx) are compared against
	 * those for the existing session.
	 */
	ofin.fin_flx &= ~(FI_BAD|FI_SHORT);

	/*
	 * Put old values of ip_len and ip_off back as we don't know
	 * if we have to forward the packet (or process it again.
	 */
	oip->ip_len = savelen;
	oip->ip_off = htons(oip->ip_off);

	switch (oip->ip_p)
	{
	case IPPROTO_ICMP :
		/*
		 * an ICMP error can only be generated as a result of an
		 * ICMP query, not as the response on an ICMP error
		 *
		 * XXX theoretically ICMP_ECHOREP and the other reply's are
		 * ICMP query's as well, but adding them here seems strange XXX
		 */
		if ((ofin.fin_flx & FI_ICMPERR) != 0)
		    	return NULL;

		/*
		 * perform a lookup of the ICMP packet in the state table
		 */
		icmp = (icmphdr_t *)((char *)oip + (IP_HL(oip) << 2));
		hv = (pr = oip->ip_p);
		src.in4 = oip->ip_src;
		hv += src.in4.s_addr;
		dst.in4 = oip->ip_dst;
		hv += dst.in4.s_addr;
		hv += icmp->icmp_id;
		hv = DOUBLE_HASH(hv, ifs);

		READ_ENTER(&ifs->ifs_ipf_state);
		for (isp = &ifs->ifs_ips_table[hv]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != 4))
				continue;
			if (is->is_pass & FR_NOICMPERR)
				continue;
			is = fr_matchsrcdst(&ofin, is, &src, &dst,
					    NULL, FI_ICMPCMP);
			if (is != NULL) {
				if ((is->is_pass & FR_NOICMPERR) != 0) {
					RWLOCK_EXIT(&ifs->ifs_ipf_state);
					return NULL;
				}
				/*
				 * i  : the index of this packet (the icmp
				 *      unreachable)
				 * oi : the index of the original packet found
				 *      in the icmp header (i.e. the packet
				 *      causing this icmp)
				 * backward : original packet was backward
				 *      compared to the state
				 */
				backward = IP6_NEQ(&is->is_src, &src);
				fin->fin_rev = !backward;
				i = (!backward << 1) + fin->fin_out;
				oi = (backward << 1) + ofin.fin_out;
				if (is->is_icmppkts[i] > is->is_pkts[oi])
					continue;
				ifs->ifs_ips_stats.iss_hits++;
				is->is_icmppkts[i]++;
				return is;
			}
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);
		return NULL;
	case IPPROTO_TCP :
	case IPPROTO_UDP :
		break;
	default :
		return NULL;
	}

	tcp = (tcphdr_t *)((char *)oip + (IP_HL(oip) << 2));
	dport = tcp->th_dport;
	sport = tcp->th_sport;

	hv = (pr = oip->ip_p);
	src.in4 = oip->ip_src;
	hv += src.in4.s_addr;
	dst.in4 = oip->ip_dst;
	hv += dst.in4.s_addr;
	hv += dport;
	hv += sport;
	hv = DOUBLE_HASH(hv, ifs);

	READ_ENTER(&ifs->ifs_ipf_state);
	for (isp = &ifs->ifs_ips_table[hv]; ((is = *isp) != NULL); ) {
		isp = &is->is_hnext;
		/*
		 * Only allow this icmp though if the
		 * encapsulated packet was allowed through the
		 * other way around. Note that the minimal amount
		 * of info present does not allow for checking against
		 * tcp internals such as seq and ack numbers.   Only the
		 * ports are known to be present and can be even if the
		 * short flag is set.
		 */
		if ((is->is_p == pr) && (is->is_v == 4) &&
		    (is = fr_matchsrcdst(&ofin, is, &src, &dst,
					 tcp, FI_ICMPCMP))) {
			/*
			 * i  : the index of this packet (the icmp unreachable)
			 * oi : the index of the original packet found in the
			 *      icmp header (i.e. the packet causing this icmp)
			 * backward : original packet was backward compared to
			 *            the state
			 */
			backward = IP6_NEQ(&is->is_src, &src);
			fin->fin_rev = !backward;
			i = (!backward << 1) + fin->fin_out;
			oi = (backward << 1) + ofin.fin_out;

			if (((is->is_pass & FR_NOICMPERR) != 0) ||
			    (is->is_icmppkts[i] > is->is_pkts[oi]))
				break;
			ifs->ifs_ips_stats.iss_hits++;
			is->is_icmppkts[i]++;
			/*
			 * we deliberately do not touch the timeouts
			 * for the accompanying state table entry.
			 * It remains to be seen if that is correct. XXX
			 */
			return is;
		}
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	return NULL;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_ipsmove                                                  */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state table entry                        */
/*              hv(I) - new hash value for state table entry                */
/* Write Locks: ipf_state                                                   */
/*                                                                          */
/* Move a state entry from one position in the hash table to another.       */
/* ------------------------------------------------------------------------ */
static void fr_ipsmove(is, hv, ifs)
ipstate_t *is;
u_int hv;
ipf_stack_t *ifs;
{
	ipstate_t **isp;
	u_int hvm;

	ASSERT(rw_read_locked(&ifs->ifs_ipf_state.ipf_lk) == 0);

	hvm = is->is_hv;
	/*
	 * Remove the hash from the old location...
	 */
	isp = is->is_phnext;
	if (is->is_hnext)
		is->is_hnext->is_phnext = isp;
	*isp = is->is_hnext;
	if (ifs->ifs_ips_table[hvm] == NULL)
		ifs->ifs_ips_stats.iss_inuse--;
	ifs->ifs_ips_stats.iss_bucketlen[hvm]--;

	/*
	 * ...and put the hash in the new one.
	 */
	hvm = DOUBLE_HASH(hv, ifs);
	is->is_hv = hvm;
	isp = &ifs->ifs_ips_table[hvm];
	if (*isp)
		(*isp)->is_phnext = &is->is_hnext;
	else
		ifs->ifs_ips_stats.iss_inuse++;
	ifs->ifs_ips_stats.iss_bucketlen[hvm]++;
	is->is_phnext = isp;
	is->is_hnext = *isp;
	*isp = is;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stlookup                                                 */
/* Returns:     ipstate_t* - NULL == no matching state found,               */
/*                           else pointer to state information is returned  */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              tcp(I) - pointer to TCP/UDP header.                         */
/*                                                                          */
/* Search the state table for a matching entry to the packet described by   */
/* the contents of *fin.                                                    */
/*                                                                          */
/* If we return NULL then no lock on ipf_state is held.                     */
/* If we return non-null then a read-lock on ipf_state is held.             */
/* ------------------------------------------------------------------------ */
ipstate_t *fr_stlookup(fin, tcp, ifqp)
fr_info_t *fin;
tcphdr_t *tcp;
ipftq_t **ifqp;
{
	u_int hv, hvm, pr, v, tryagain;
	ipstate_t *is, **isp;
	u_short dport, sport;
	i6addr_t src, dst;
	struct icmp *ic;
	ipftq_t *ifq;
	int oow;
	ipf_stack_t *ifs = fin->fin_ifs;

	is = NULL;
	ifq = NULL;
	tcp = fin->fin_dp;
	ic = (struct icmp *)tcp;
	hv = (pr = fin->fin_fi.fi_p);
	src = fin->fin_fi.fi_src;
	dst = fin->fin_fi.fi_dst;
	hv += src.in4.s_addr;
	hv += dst.in4.s_addr;

	v = fin->fin_fi.fi_v;
#ifdef	USE_INET6
	if (v == 6) {
		hv  += fin->fin_fi.fi_src.i6[1];
		hv  += fin->fin_fi.fi_src.i6[2];
		hv  += fin->fin_fi.fi_src.i6[3];

		if ((fin->fin_p == IPPROTO_ICMPV6) &&
		    IN6_IS_ADDR_MULTICAST(&fin->fin_fi.fi_dst.in6)) {
			hv -= dst.in4.s_addr;
		} else {
			hv += fin->fin_fi.fi_dst.i6[1];
			hv += fin->fin_fi.fi_dst.i6[2];
			hv += fin->fin_fi.fi_dst.i6[3];
		}
	}
#endif
	if ((v == 4) &&
	    (fin->fin_flx & (FI_MULTICAST|FI_BROADCAST|FI_MBCAST))) {
		if (fin->fin_out == 0) {
			hv -= src.in4.s_addr;
		} else {
			hv -= dst.in4.s_addr;
		}
	}

	/*
	 * Search the hash table for matching packet header info.
	 */
	switch (pr)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		tryagain = 0;
		if (v == 6) {
			if ((ic->icmp_type == ICMP6_ECHO_REQUEST) ||
			    (ic->icmp_type == ICMP6_ECHO_REPLY)) {
				hv += ic->icmp_id;
			}
		}
		READ_ENTER(&ifs->ifs_ipf_state);
icmp6again:
		hvm = DOUBLE_HASH(hv, ifs);
		for (isp = &ifs->ifs_ips_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = fr_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if (is != NULL &&
			    fr_matchicmpqueryreply(v, &is->is_icmp,
						   ic, fin->fin_rev)) {
				if (fin->fin_rev)
					ifq = &ifs->ifs_ips_icmpacktq;
				else
					ifq = &ifs->ifs_ips_icmptq;
				break;
			}
		}

		if (is != NULL) {
			if ((tryagain != 0) && !(is->is_flags & SI_W_DADDR)) {
				hv += fin->fin_fi.fi_src.i6[0];
				hv += fin->fin_fi.fi_src.i6[1];
				hv += fin->fin_fi.fi_src.i6[2];
				hv += fin->fin_fi.fi_src.i6[3];
				fr_ipsmove(is, hv, ifs);
				MUTEX_DOWNGRADE(&ifs->ifs_ipf_state);
			}
			break;
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

		/*
		 * No matching icmp state entry. Perhaps this is a
		 * response to another state entry.
		 *
		 * XXX With some ICMP6 packets, the "other" address is already
		 * in the packet, after the ICMP6 header, and this could be
		 * used in place of the multicast address.  However, taking
		 * advantage of this requires some significant code changes
		 * to handle the specific types where that is the case.
		 */
		if ((ifs->ifs_ips_stats.iss_wild != 0) && (v == 6) && (tryagain == 0) &&
		    !IN6_IS_ADDR_MULTICAST(&fin->fin_fi.fi_src.in6)) {
			hv -= fin->fin_fi.fi_src.i6[0];
			hv -= fin->fin_fi.fi_src.i6[1];
			hv -= fin->fin_fi.fi_src.i6[2];
			hv -= fin->fin_fi.fi_src.i6[3];
			tryagain = 1;
			WRITE_ENTER(&ifs->ifs_ipf_state);
			goto icmp6again;
		}

		is = fr_checkicmp6matchingstate(fin);
		if (is != NULL)
			return is;
		break;
#endif

	case IPPROTO_ICMP :
		if (v == 4) {
			hv += ic->icmp_id;
		}
		hv = DOUBLE_HASH(hv, ifs);
		READ_ENTER(&ifs->ifs_ipf_state);
		for (isp = &ifs->ifs_ips_table[hv]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = fr_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if (is != NULL &&
			    fr_matchicmpqueryreply(v, &is->is_icmp,
						   ic, fin->fin_rev)) {
				if (fin->fin_rev)
					ifq = &ifs->ifs_ips_icmpacktq;
				else
					ifq = &ifs->ifs_ips_icmptq;
				break;
			}
		}
		if (is == NULL) {
			RWLOCK_EXIT(&ifs->ifs_ipf_state);
		}
		break;

	case IPPROTO_TCP :
	case IPPROTO_UDP :
		ifqp = NULL;
		sport = htons(fin->fin_data[0]);
		hv += sport;
		dport = htons(fin->fin_data[1]);
		hv += dport;
		oow = 0;
		tryagain = 0;
		READ_ENTER(&ifs->ifs_ipf_state);
retry_tcpudp:
		hvm = DOUBLE_HASH(hv, ifs);
		for (isp = &ifs->ifs_ips_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			fin->fin_flx &= ~FI_OOW;
			is = fr_matchsrcdst(fin, is, &src, &dst, tcp, FI_CMP);
			if (is != NULL) {
				if (pr == IPPROTO_TCP) {
					if (!fr_tcpstate(fin, tcp, is)) {
						oow |= fin->fin_flx & FI_OOW;
						continue;
					}
				}
				break;
			}
		}
		if (is != NULL) {
			if (tryagain &&
			    !(is->is_flags & (SI_CLONE|SI_WILDP|SI_WILDA))) {
				hv += dport;
				hv += sport;
				fr_ipsmove(is, hv, ifs);
				MUTEX_DOWNGRADE(&ifs->ifs_ipf_state);
			}
			break;
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

		if (ifs->ifs_ips_stats.iss_wild) {
			if (tryagain == 0) {
				hv -= dport;
				hv -= sport;
			} else if (tryagain == 1) {
				hv = fin->fin_fi.fi_p;
				/*
				 * If we try to pretend this is a reply to a
				 * multicast/broadcast packet then we need to
				 * exclude part of the address from the hash
				 * calculation.
				 */
				if (fin->fin_out == 0) {
					hv += src.in4.s_addr;
				} else {
					hv += dst.in4.s_addr;
				}
				hv += dport;
				hv += sport;
			}
			tryagain++;
			if (tryagain <= 2) {
				WRITE_ENTER(&ifs->ifs_ipf_state);
				goto retry_tcpudp;
			}
		}
		fin->fin_flx |= oow;
		break;

#if 0
	case IPPROTO_GRE :
		gre = fin->fin_dp;
		if (GRE_REV(gre->gr_flags) == 1) {
			hv += gre->gr_call;
		}
		/* FALLTHROUGH */
#endif
	default :
		ifqp = NULL;
		hvm = DOUBLE_HASH(hv, ifs);
		READ_ENTER(&ifs->ifs_ipf_state);
		for (isp = &ifs->ifs_ips_table[hvm]; ((is = *isp) != NULL); ) {
			isp = &is->is_hnext;
			if ((is->is_p != pr) || (is->is_v != v))
				continue;
			is = fr_matchsrcdst(fin, is, &src, &dst, NULL, FI_CMP);
			if (is != NULL) {
				ifq = &ifs->ifs_ips_iptq;
				break;
			}
		}
		if (is == NULL) {
			RWLOCK_EXIT(&ifs->ifs_ipf_state);
		}
		break;
	}

	if ((is != NULL) && ((is->is_sti.tqe_flags & TQE_RULEBASED) != 0) &&
	    (is->is_tqehead[fin->fin_rev] != NULL))
		ifq = is->is_tqehead[fin->fin_rev];
	if (ifq != NULL && ifqp != NULL)
		*ifqp = ifq;
	return is;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_updatestate                                              */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I) - pointer to packet information                      */
/*              is(I)  - pointer to state table entry                       */
/* Read Locks:  ipf_state                                                   */
/*                                                                          */
/* Updates packet and byte counters for a newly received packet.  Seeds the */
/* fragment cache with a new entry as required.                             */
/* ------------------------------------------------------------------------ */
void fr_updatestate(fin, is, ifq)
fr_info_t *fin;
ipstate_t *is;
ipftq_t *ifq;
{
	ipftqent_t *tqe;
	int i, pass;
	ipf_stack_t *ifs = fin->fin_ifs;

	i = (fin->fin_rev << 1) + fin->fin_out;

	/*
	 * For TCP packets, ifq == NULL.  For all others, check if this new
	 * queue is different to the last one it was on and move it if so.
	 */
	tqe = &is->is_sti;
	MUTEX_ENTER(&is->is_lock);
	if ((tqe->tqe_flags & TQE_RULEBASED) != 0)
		ifq = is->is_tqehead[fin->fin_rev];

	if (ifq != NULL)
		fr_movequeue(tqe, tqe->tqe_ifq, ifq, ifs);

	is->is_pkts[i]++;
	fin->fin_pktnum = is->is_pkts[i] + is->is_icmppkts[i];
	is->is_bytes[i] += fin->fin_plen;
	MUTEX_EXIT(&is->is_lock);

#ifdef	IPFILTER_SYNC
	if (is->is_flags & IS_STATESYNC)
		ipfsync_update(SMC_STATE, fin, is->is_sync);
#endif

	ATOMIC_INCL(ifs->ifs_ips_stats.iss_hits);

	fin->fin_fr = is->is_rule;

	/*
	 * If this packet is a fragment and the rule says to track fragments,
	 * then create a new fragment cache entry.
	 */
	pass = is->is_pass;
	if ((fin->fin_flx & FI_FRAG) && FR_ISPASS(pass))
		(void) fr_newfrag(fin, pass ^ FR_KEEPSTATE);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_checkstate                                               */
/* Returns:     frentry_t* - NULL == search failed,                         */
/*                           else pointer to rule for matching state        */
/* Parameters:  ifp(I)   - pointer to interface                             */
/*              passp(I) - pointer to filtering result flags                */
/*                                                                          */
/* Check if a packet is associated with an entry in the state table.        */
/* ------------------------------------------------------------------------ */
frentry_t *fr_checkstate(fin, passp)
fr_info_t *fin;
u_32_t *passp;
{
	ipstate_t *is;
	frentry_t *fr;
	tcphdr_t *tcp;
	ipftq_t *ifq;
	u_int pass;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_fr_state_lock || (ifs->ifs_ips_list == NULL) ||
	    (fin->fin_flx & (FI_SHORT|FI_STATE|FI_FRAGBODY|FI_BAD)))
		return NULL;

	is = NULL;
	if ((fin->fin_flx & FI_TCPUDP) ||
	    (fin->fin_fi.fi_p == IPPROTO_ICMP)
#ifdef	USE_INET6
	    || (fin->fin_fi.fi_p == IPPROTO_ICMPV6)
#endif
	    )
		tcp = fin->fin_dp;
	else
		tcp = NULL;

	/*
	 * Search the hash table for matching packet header info.
	 */
	ifq = NULL;
	is = fr_stlookup(fin, tcp, &ifq);
	switch (fin->fin_p)
	{
#ifdef	USE_INET6
	case IPPROTO_ICMPV6 :
		if (is != NULL)
			break;
		if (fin->fin_v == 6) {
			is = fr_checkicmp6matchingstate(fin);
			if (is != NULL)
				goto matched;
		}
		break;
#endif
	case IPPROTO_ICMP :
		if (is != NULL)
			break;
		/*
		 * No matching icmp state entry. Perhaps this is a
		 * response to another state entry.
		 */
		is = fr_checkicmpmatchingstate(fin);
		if (is != NULL)
			goto matched;
		break;
	case IPPROTO_TCP :
		if (is == NULL)
			break;

		if (is->is_pass & FR_NEWISN) {
			if (fin->fin_out == 0)
				fr_fixinisn(fin, is);
			else if (fin->fin_out == 1)
				fr_fixoutisn(fin, is);
		}
		break;
	default :
		if (fin->fin_rev)
			ifq = &ifs->ifs_ips_udpacktq;
		else
			ifq = &ifs->ifs_ips_udptq;
		break;
	}
	if (is == NULL) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_miss);
		return NULL;
	}

matched:
	fr = is->is_rule;
	if (fr != NULL) {
		if ((fin->fin_out == 0) && (fr->fr_nattag.ipt_num[0] != 0)) {
			if (fin->fin_nattag == NULL) {
				RWLOCK_EXIT(&ifs->ifs_ipf_state);
				return NULL;
			}
			if (fr_matchtag(&fr->fr_nattag, fin->fin_nattag) != 0) {
				RWLOCK_EXIT(&ifs->ifs_ipf_state);
				return NULL;
			}
		}
		(void) strncpy(fin->fin_group, fr->fr_group, FR_GROUPLEN);
		fin->fin_icode = fr->fr_icode;
	}

	fin->fin_rule = is->is_rulen;
	pass = is->is_pass;
	fr_updatestate(fin, is, ifq);

	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	fin->fin_flx |= FI_STATE;
	if ((pass & FR_LOGFIRST) != 0)
		pass &= ~(FR_LOGFIRST|FR_LOG);
	*passp = pass;
	return fr;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_fixoutisn                                                */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Called only for outbound packets, adjusts the sequence number and the    */
/* TCP checksum to match that change.                                       */
/* ------------------------------------------------------------------------ */
static void fr_fixoutisn(fin, is)
fr_info_t *fin;
ipstate_t *is;
{
	tcphdr_t *tcp;
	int rev;
	u_32_t seq;

	tcp = fin->fin_dp;
	rev = fin->fin_rev;
	if ((is->is_flags & IS_ISNSYN) != 0) {
		if (rev == 0) {
			seq = ntohl(tcp->th_seq);
			seq += is->is_isninc[0];
			tcp->th_seq = htonl(seq);
			fix_outcksum(&tcp->th_sum, is->is_sumd[0]);
		}
	}
	if ((is->is_flags & IS_ISNACK) != 0) {
		if (rev == 1) {
			seq = ntohl(tcp->th_seq);
			seq += is->is_isninc[1];
			tcp->th_seq = htonl(seq);
			fix_outcksum(&tcp->th_sum, is->is_sumd[1]);
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_fixinisn                                                 */
/* Returns:     Nil                                                         */
/* Parameters:  fin(I)   - pointer to packet information                    */
/*              is(I)  - pointer to master state structure                  */
/*                                                                          */
/* Called only for inbound packets, adjusts the acknowledge number and the  */
/* TCP checksum to match that change.                                       */
/* ------------------------------------------------------------------------ */
static void fr_fixinisn(fin, is)
fr_info_t *fin;
ipstate_t *is;
{
	tcphdr_t *tcp;
	int rev;
	u_32_t ack;

	tcp = fin->fin_dp;
	rev = fin->fin_rev;
	if ((is->is_flags & IS_ISNSYN) != 0) {
		if (rev == 1) {
			ack = ntohl(tcp->th_ack);
			ack -= is->is_isninc[0];
			tcp->th_ack = htonl(ack);
			fix_incksum(&tcp->th_sum, is->is_sumd[0]);
		}
	}
	if ((is->is_flags & IS_ISNACK) != 0) {
		if (rev == 0) {
			ack = ntohl(tcp->th_ack);
			ack -= is->is_isninc[1];
			tcp->th_ack = htonl(ack);
			fix_incksum(&tcp->th_sum, is->is_sumd[1]);
		}
	}
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_statesync                                                */
/* Returns:     Nil                                                         */
/* Parameters:  action(I) - type of synchronisation to do                   */
/*              v(I)      - IP version being sync'd (v4 or v6)              */
/*              ifp(I)    - interface identifier associated with action     */
/*              name(I)   - name associated with ifp parameter              */
/*                                                                          */
/* Walk through all state entries and if an interface pointer match is      */
/* found then look it up again, based on its name in case the pointer has   */
/* changed since last time.                                                 */
/*                                                                          */
/* If ifp is passed in as being non-null then we are only doing updates for */
/* existing, matching, uses of it.                                          */
/* ------------------------------------------------------------------------ */
void fr_statesync(action, v, ifp, name, ifs)
int action, v;
void *ifp;
char *name;
ipf_stack_t *ifs;
{
	ipstate_t *is;
	int i;

	if (ifs->ifs_fr_running <= 0)
		return;

	WRITE_ENTER(&ifs->ifs_ipf_state);

	if (ifs->ifs_fr_running <= 0) {
		RWLOCK_EXIT(&ifs->ifs_ipf_state);
		return;
	}

	switch (action)
	{
	case IPFSYNC_RESYNC :
		for (is = ifs->ifs_ips_list; is; is = is->is_next) {
			if (v != 0 && is->is_v != v)
				continue;
			/*
			 * Look up all the interface names in the state entry.
			 */
			for (i = 0; i < 4; i++) {
				is->is_ifp[i] = fr_resolvenic(is->is_ifname[i],
							      is->is_v, ifs);
			}
		}
		break;
	case IPFSYNC_NEWIFP :
		for (is = ifs->ifs_ips_list; is; is = is->is_next) {
			if (v != 0 && is->is_v != v)
				continue;
			/*
			 * Look up all the interface names in the state entry.
			 */
			for (i = 0; i < 4; i++) {
				if (!strncmp(is->is_ifname[i], name,
					     sizeof(is->is_ifname[i])))
					is->is_ifp[i] = ifp;
			}
		}
		break;
	case IPFSYNC_OLDIFP :
		for (is = ifs->ifs_ips_list; is; is = is->is_next) {
			if (v != 0 && is->is_v != v)
				continue;
			/*
			 * Look up all the interface names in the state entry.
			 */
			for (i = 0; i < 4; i++) {
				if (is->is_ifp[i] == ifp)
					is->is_ifp[i] = (void *)-1;
			}
		}
		break;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
}


#if SOLARIS2 >= 10
/* ------------------------------------------------------------------------ */
/* Function:    fr_stateifindexsync					    */
/* Returns:     void							    */
/* Parameters:	ifp	- current network interface descriptor (ifindex)    */
/*              newifp	- new interface descriptor (new ifindex)	    */
/*		ifs	- pointer to IPF stack				    */
/*									    */
/* Write Locks: assumes ipf_mutex is locked				    */
/*                                                                          */
/* Updates all interface indeces matching to ifp with new interface index   */
/* value.								    */
/* ------------------------------------------------------------------------ */
void fr_stateifindexsync(ifp, newifp, ifs)
void *ifp;
void *newifp;
ipf_stack_t *ifs;
{
	ipstate_t *is;
	int i;

	WRITE_ENTER(&ifs->ifs_ipf_state);

	for (is = ifs->ifs_ips_list; is != NULL; is = is->is_next) {

		for (i = 0; i < 4; i++) {
			if (is->is_ifp[i] == ifp)
				is->is_ifp[i] = newifp;
		}
	}

	RWLOCK_EXIT(&ifs->ifs_ipf_state);
}
#endif

/* ------------------------------------------------------------------------ */
/* Function:    fr_delstate                                                 */
/* Returns:     int - 0 = entry deleted, else ref count on entry            */
/* Parameters:  is(I)  - pointer to state structure to delete               */
/*              why(I) - if not 0, log reason why it was deleted            */
/*              ifs    - ipf stack instance                                 */
/* Write Locks: ipf_state/ipf_global                                        */
/*                                                                          */
/* Deletes a state entry from the enumerated list as well as the hash table */
/* and timeout queue lists.  Make adjustments to hash table statistics and  */
/* global counters as required.                                             */
/* ------------------------------------------------------------------------ */
int fr_delstate(is, why, ifs)
ipstate_t *is;
int why;
ipf_stack_t *ifs;
{
	int removed = 0;

	ASSERT(rw_write_held(&ifs->ifs_ipf_global.ipf_lk) == 0 ||
		rw_write_held(&ifs->ifs_ipf_state.ipf_lk) == 0);

	/*
	 * Start by removing the entry from the hash table of state entries
	 * so it will not be "used" again.
	 *
	 * It will remain in the "list" of state entries until all references
	 * have been accounted for.
	 */
	if (is->is_phnext != NULL) {
		removed = 1;
		*is->is_phnext = is->is_hnext;
		if (is->is_hnext != NULL)
			is->is_hnext->is_phnext = is->is_phnext;
		if (ifs->ifs_ips_table[is->is_hv] == NULL)
			ifs->ifs_ips_stats.iss_inuse--;
		ifs->ifs_ips_stats.iss_bucketlen[is->is_hv]--;

		is->is_phnext = NULL;
		is->is_hnext = NULL;
	}

	/*
	 * Because ifs->ifs_ips_stats.iss_wild is a count of entries in the state
	 * table that have wildcard flags set, only decerement it once
	 * and do it here.
	 */
	if (is->is_flags & (SI_WILDP|SI_WILDA)) {
		if (!(is->is_flags & SI_CLONED)) {
			ATOMIC_DECL(ifs->ifs_ips_stats.iss_wild);
		}
		is->is_flags &= ~(SI_WILDP|SI_WILDA);
	}

	/*
	 * Next, remove it from the timeout queue it is in.
	 */
	fr_deletequeueentry(&is->is_sti);

	is->is_me = NULL;

	/*
	 * If it is still in use by something else, do not go any further,
	 * but note that at this point it is now an orphan.
	 */
	MUTEX_ENTER(&is->is_lock);
	if (is->is_ref > 1) {
		is->is_ref--;
		MUTEX_EXIT(&is->is_lock);
		if (removed)
			ifs->ifs_ips_stats.iss_orphans++;
		return (is->is_ref);
	}
	MUTEX_EXIT(&is->is_lock);

	is->is_ref = 0;

	/*
	 * If entry has already been removed from table,
	 * it means we're simply cleaning up an orphan.
	 */
	if (!removed)
		ifs->ifs_ips_stats.iss_orphans--;

	if (is->is_tqehead[0] != NULL)
		(void) fr_deletetimeoutqueue(is->is_tqehead[0]);

	if (is->is_tqehead[1] != NULL)
		(void) fr_deletetimeoutqueue(is->is_tqehead[1]);

#ifdef	IPFILTER_SYNC
	if (is->is_sync)
		ipfsync_del(is->is_sync);
#endif
#ifdef	IPFILTER_SCAN
	(void) ipsc_detachis(is);
#endif

	/*
	 * Now remove it from master list of state table entries.
	 */
	if (is->is_pnext != NULL) {
		*is->is_pnext = is->is_next;
		if (is->is_next != NULL) {
			is->is_next->is_pnext = is->is_pnext;
			is->is_next = NULL;
		}
		is->is_pnext = NULL;
	}
 
	if (ifs->ifs_ipstate_logging != 0 && why != 0)
		ipstate_log(is, why, ifs);

	if (is->is_rule != NULL) {
		is->is_rule->fr_statecnt--;
		(void)fr_derefrule(&is->is_rule, ifs);
	}

	MUTEX_DESTROY(&is->is_lock);
	KFREE(is);
	ifs->ifs_ips_num--;

	return (0);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_timeoutstate                                             */
/* Returns:     Nil                                                         */
/* Parameters:  ifs - ipf stack instance                                    */
/*                                                                          */
/* Slowly expire held state for thingslike UDP and ICMP.  The algorithm     */
/* used here is to keep the queue sorted with the oldest things at the top  */
/* and the youngest at the bottom.  So if the top one doesn't need to be    */
/* expired then neither will any under it.                                  */
/* ------------------------------------------------------------------------ */
void fr_timeoutstate(ifs)
ipf_stack_t *ifs;
{
	ipftq_t *ifq, *ifqnext;
	ipftqent_t *tqe, *tqn;
	ipstate_t *is;
	SPL_INT(s);

	SPL_NET(s);
	WRITE_ENTER(&ifs->ifs_ipf_state);
	for (ifq = ifs->ifs_ips_tqtqb; ifq != NULL; ifq = ifq->ifq_next)
		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
			if (tqe->tqe_die > ifs->ifs_fr_ticks)
				break;
			tqn = tqe->tqe_next;
			is = tqe->tqe_parent;
			(void) fr_delstate(is, ISL_EXPIRE, ifs);
		}

	for (ifq = ifs->ifs_ips_utqe; ifq != NULL; ifq = ifq->ifq_next) {
		for (tqn = ifq->ifq_head; ((tqe = tqn) != NULL); ) {
			if (tqe->tqe_die > ifs->ifs_fr_ticks)
				break;
			tqn = tqe->tqe_next;
			is = tqe->tqe_parent;
			(void) fr_delstate(is, ISL_EXPIRE, ifs);
		}
	}

	for (ifq = ifs->ifs_ips_utqe; ifq != NULL; ifq = ifqnext) {
		ifqnext = ifq->ifq_next;

		if (((ifq->ifq_flags & IFQF_DELETE) != 0) &&
		    (ifq->ifq_ref == 0)) {
			fr_freetimeoutqueue(ifq, ifs);
		}
	}

	if (ifs->ifs_fr_state_doflush) {
		(void) fr_state_flush(FLUSH_TABLE_EXTRA, 0, ifs);
		ifs->ifs_fr_state_doflush = 0;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	SPL_X(s);
}


/* ---------------------------------------------------------------------- */
/* Function:    fr_state_flush                                            */
/* Returns:     int - 0 == success, -1 == failure                         */
/* Parameters:  flush_option - how to flush the active State table	  */
/*              proto    - IP version to flush (4, 6, or both)            */
/*              ifs      - ipf stack instance                             */
/* Write Locks: ipf_state                                                 */
/*                                                                        */
/* Flush state tables.  Three possible flush options currently defined:	  */
/*                                                                        */
/* FLUSH_TABLE_ALL	: Flush all state table entries			  */
/*                                                                        */
/* FLUSH_TABLE_CLOSING	: Flush entries with TCP connections which	  */
/*			  have started to close on both ends using	  */
/*			  ipf_flushclosing().				  */
/*                                                                        */
/* FLUSH_TABLE_EXTRA	: First, flush entries which are "almost" closed. */
/*			  Then, if needed, flush entries with TCP	  */
/*			  connections which have been idle for a long	  */
/*			  time with ipf_extraflush().			  */
/* ---------------------------------------------------------------------- */
static int fr_state_flush(flush_option, proto, ifs)
int flush_option, proto;
ipf_stack_t *ifs;
{
	ipstate_t *is, *isn;
	int removed;
	SPL_INT(s);

	removed = 0;

	SPL_NET(s);
	switch (flush_option)
	{
	case FLUSH_TABLE_ALL:
		isn = ifs->ifs_ips_list;
		while ((is = isn) != NULL) {
			isn = is->is_next;
			if ((proto != 0) && (is->is_v != proto))
				continue;
			if (fr_delstate(is, ISL_FLUSH, ifs) == 0)
				removed++;
		}
		break;

	case FLUSH_TABLE_CLOSING:
		removed = ipf_flushclosing(STATE_FLUSH,
					   IPF_TCPS_CLOSE_WAIT,
					   ifs->ifs_ips_tqtqb,
					   ifs->ifs_ips_utqe,
					   ifs);
		break;

	case FLUSH_TABLE_EXTRA:
		removed = ipf_flushclosing(STATE_FLUSH,
					   IPF_TCPS_FIN_WAIT_2,
					   ifs->ifs_ips_tqtqb,
					   ifs->ifs_ips_utqe,
					   ifs);

		/*
		 * Be sure we haven't done this in the last 10 seconds.
		 */
		if (ifs->ifs_fr_ticks - ifs->ifs_ips_last_force_flush <
		    IPF_TTLVAL(10))
			break;
		ifs->ifs_ips_last_force_flush = ifs->ifs_fr_ticks;
                removed += ipf_extraflush(STATE_FLUSH,
					  &ifs->ifs_ips_tqtqb[IPF_TCPS_ESTABLISHED],
					  ifs->ifs_ips_utqe,
					  ifs);
		break;

	default: /* Flush Nothing */
		break;
	}

	SPL_X(s);
	return (removed);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_tcp_age                                                  */
/* Returns:     int - 1 == state transition made, 0 == no change (rejected) */
/* Parameters:  tq(I)    - pointer to timeout queue information             */
/*              fin(I)   - pointer to packet information                    */
/*              tqtab(I) - TCP timeout queue table this is in               */
/*              flags(I) - flags from state/NAT entry                       */
/*                                                                          */
/* Rewritten by Arjan de Vet <Arjan.deVet@adv.iae.nl>, 2000-07-29:          */
/*                                                                          */
/* - (try to) base state transitions on real evidence only,                 */
/*   i.e. packets that are sent and have been received by ipfilter;         */
/*   diagram 18.12 of TCP/IP volume 1 by W. Richard Stevens was used.       */
/*                                                                          */
/* - deal with half-closed connections correctly;                           */
/*                                                                          */
/* - store the state of the source in state[0] such that ipfstat            */
/*   displays the state as source/dest instead of dest/source; the calls    */
/*   to fr_tcp_age have been changed accordingly.                           */
/*                                                                          */
/* Internal Parameters:                                                     */
/*                                                                          */
/*    state[0] = state of source (host that initiated connection)           */
/*    state[1] = state of dest   (host that accepted the connection)        */
/*                                                                          */
/*    dir == 0 : a packet from source to dest                               */
/*    dir == 1 : a packet from dest to source                               */
/*                                                                          */
/* Locking: it is assumed that the parent of the tqe structure is locked.   */
/* ------------------------------------------------------------------------ */
int fr_tcp_age(tqe, fin, tqtab, flags)
ipftqent_t *tqe;
fr_info_t *fin;
ipftq_t *tqtab;
int flags;
{
	int dlen, ostate, nstate, rval, dir;
	u_char tcpflags;
	tcphdr_t *tcp;
	ipf_stack_t *ifs = fin->fin_ifs;

	tcp = fin->fin_dp;

	rval = 0;
	dir = fin->fin_rev;
	tcpflags = tcp->th_flags;
	dlen = fin->fin_dlen - (TCP_OFF(tcp) << 2);

	ostate = tqe->tqe_state[1 - dir];
	nstate = tqe->tqe_state[dir];

	DTRACE_PROBE4(
		indata,
		fr_info_t *, fin,
		int, ostate,
		int, nstate,
		u_char, tcpflags
	);

	if (tcpflags & TH_RST) {
		if (!(tcpflags & TH_PUSH) && !dlen)
			nstate = IPF_TCPS_CLOSED;
		else
			nstate = IPF_TCPS_CLOSE_WAIT;

		/*
		 * Once RST is received, we must advance peer's state to
		 * CLOSE_WAIT.
		 */
		if (ostate <= IPF_TCPS_ESTABLISHED) {
			tqe->tqe_state[1 - dir] = IPF_TCPS_CLOSE_WAIT;
		}
		rval = 1;
	} else {

		switch (nstate)
		{
		case IPF_TCPS_LISTEN: /* 0 */
			if ((tcpflags & TH_OPENING) == TH_OPENING) {
				/*
				 * 'dir' received an S and sends SA in
				 * response, CLOSED -> SYN_RECEIVED
				 */
				nstate = IPF_TCPS_SYN_RECEIVED;
				rval = 1;
			} else if ((tcpflags & TH_OPENING) == TH_SYN) {
				/* 'dir' sent S, CLOSED -> SYN_SENT */
				nstate = IPF_TCPS_SYN_SENT;
				rval = 1;
			}
			/*
			 * the next piece of code makes it possible to get
			 * already established connections into the state table
			 * after a restart or reload of the filter rules; this
			 * does not work when a strict 'flags S keep state' is
			 * used for tcp connections of course
			 */
			if (((flags & IS_TCPFSM) == 0) &&
			    ((tcpflags & TH_ACKMASK) == TH_ACK)) {
				/*
				 * we saw an A, guess 'dir' is in ESTABLISHED
				 * mode
				 */
				switch (ostate)
				{
				case IPF_TCPS_LISTEN :
				case IPF_TCPS_SYN_RECEIVED :
					nstate = IPF_TCPS_HALF_ESTAB;
					rval = 1;
					break;
				case IPF_TCPS_HALF_ESTAB :
				case IPF_TCPS_ESTABLISHED :
					nstate = IPF_TCPS_ESTABLISHED;
					rval = 1;
					break;
				default :
					break;
				}
			}
			/*
			 * TODO: besides regular ACK packets we can have other
			 * packets as well; it is yet to be determined how we
			 * should initialize the states in those cases
			 */
			break;

		case IPF_TCPS_SYN_SENT: /* 1 */
			if ((tcpflags & ~(TH_ECN|TH_CWR)) == TH_SYN) {
				/*
				 * A retransmitted SYN packet.  We do not reset
				 * the timeout here to fr_tcptimeout because a
				 * connection connect timeout does not renew
				 * after every packet that is sent.  We need to
				 * set rval so as to indicate the packet has
				 * passed the check for its flags being valid
				 * in the TCP FSM.  Setting rval to 2 has the
				 * result of not resetting the timeout.
				 */
				rval = 2;
			} else if ((tcpflags & (TH_SYN|TH_FIN|TH_ACK)) ==
				   TH_ACK) {
				/*
				 * we see an A from 'dir' which is in SYN_SENT
				 * state: 'dir' sent an A in response to an SA
				 * which it received, SYN_SENT -> ESTABLISHED
				 */
				nstate = IPF_TCPS_ESTABLISHED;
				rval = 1;
			} else if (tcpflags & TH_FIN) {
				/*
				 * we see an F from 'dir' which is in SYN_SENT
				 * state and wants to close its side of the
				 * connection; SYN_SENT -> FIN_WAIT_1
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			} else if ((tcpflags & TH_OPENING) == TH_OPENING) {
				/*
				 * we see an SA from 'dir' which is already in
				 * SYN_SENT state, this means we have a
				 * simultaneous open; SYN_SENT -> SYN_RECEIVED
				 */
				nstate = IPF_TCPS_SYN_RECEIVED;
				rval = 1;
			}
			break;

		case IPF_TCPS_SYN_RECEIVED: /* 2 */
			if ((tcpflags & (TH_SYN|TH_FIN|TH_ACK)) == TH_ACK) {
				/*
				 * we see an A from 'dir' which was in
				 * SYN_RECEIVED state so it must now be in
				 * established state, SYN_RECEIVED ->
				 * ESTABLISHED
				 */
				nstate = IPF_TCPS_ESTABLISHED;
				rval = 1;
			} else if ((tcpflags & ~(TH_ECN|TH_CWR)) ==
				   TH_OPENING) {
				/*
				 * We see an SA from 'dir' which is already in
				 * SYN_RECEIVED state.
				 */
				rval = 2;
			} else if (tcpflags & TH_FIN) {
				/*
				 * we see an F from 'dir' which is in
				 * SYN_RECEIVED state and wants to close its
				 * side of the connection; SYN_RECEIVED ->
				 * FIN_WAIT_1
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			}
			break;

		case IPF_TCPS_HALF_ESTAB: /* 3 */
			if (tcpflags & TH_FIN) {
				nstate = IPF_TCPS_FIN_WAIT_1;
				rval = 1;
			} else if ((tcpflags & TH_ACKMASK) == TH_ACK) {
				/*
				 * If we've picked up a connection in mid
				 * flight, we could be looking at a follow on
				 * packet from the same direction as the one
				 * that created this state.  Recognise it but
				 * do not advance the entire connection's
				 * state.
				 */
				switch (ostate)
				{
				case IPF_TCPS_LISTEN :
				case IPF_TCPS_SYN_SENT :
				case IPF_TCPS_SYN_RECEIVED :
					rval = 1;
					break;
				case IPF_TCPS_HALF_ESTAB :
				case IPF_TCPS_ESTABLISHED :
					nstate = IPF_TCPS_ESTABLISHED;
					rval = 1;
					break;
				default :
					break;
				}
			}
			break;

		case IPF_TCPS_ESTABLISHED: /* 4 */
			rval = 1;
			if (tcpflags & TH_FIN) {
				/*
				 * 'dir' closed its side of the connection;
				 * this gives us a half-closed connection;
				 * ESTABLISHED -> FIN_WAIT_1
				 */
				if (ostate == IPF_TCPS_FIN_WAIT_1) {
					nstate = IPF_TCPS_CLOSING;
				} else {
					nstate = IPF_TCPS_FIN_WAIT_1;
				}
			} else if (tcpflags & TH_ACK) {
				/*
				 * an ACK, should we exclude other flags here?
				 */
				if (ostate == IPF_TCPS_FIN_WAIT_1) {
					/*
					 * We know the other side did an active
					 * close, so we are ACKing the recvd
					 * FIN packet (does the window matching
					 * code guarantee this?) and go into
					 * CLOSE_WAIT state; this gives us a
					 * half-closed connection
					 */
					nstate = IPF_TCPS_CLOSE_WAIT;
				} else if (ostate < IPF_TCPS_CLOSE_WAIT) {
					/*
					 * still a fully established
					 * connection reset timeout
					 */
					nstate = IPF_TCPS_ESTABLISHED;
				}
			}
			break;

		case IPF_TCPS_CLOSE_WAIT: /* 5 */
			rval = 1;
			if (tcpflags & TH_FIN) {
				/*
				 * application closed and 'dir' sent a FIN,
				 * we're now going into LAST_ACK state
				 */
				nstate = IPF_TCPS_LAST_ACK;
			} else {
				/*
				 * we remain in CLOSE_WAIT because the other
				 * side has closed already and we did not
				 * close our side yet; reset timeout
				 */
				nstate = IPF_TCPS_CLOSE_WAIT;
			}
			break;

		case IPF_TCPS_FIN_WAIT_1: /* 6 */
			rval = 1;
			if ((tcpflags & TH_ACK) &&
			    ostate > IPF_TCPS_CLOSE_WAIT) {
				/*
				 * if the other side is not active anymore
				 * it has sent us a FIN packet that we are
				 * ack'ing now with an ACK; this means both
				 * sides have now closed the connection and
				 * we go into LAST_ACK
				 */
				/*
				 * XXX: how do we know we really are ACKing
				 * the FIN packet here? does the window code
				 * guarantee that?
				 */
				nstate = IPF_TCPS_LAST_ACK;
			} else {
				/*
				 * we closed our side of the connection
				 * already but the other side is still active
				 * (ESTABLISHED/CLOSE_WAIT); continue with
				 * this half-closed connection
				 */
				nstate = IPF_TCPS_FIN_WAIT_1;
			}
			break;

		case IPF_TCPS_CLOSING: /* 7 */
			if ((tcpflags & (TH_FIN|TH_ACK)) == TH_ACK) {
				nstate = IPF_TCPS_TIME_WAIT;
			}
			rval = 1;
			break;

		case IPF_TCPS_LAST_ACK: /* 8 */
			/*
			 * We want to reset timer here to keep state in table.
			 * If we would allow the state to time out here, while
			 * there would still be packets being retransmitted, we
			 * would cut off line between the two peers preventing
			 * them to close connection properly. 
			 */
			rval = 1;
			break;

		case IPF_TCPS_FIN_WAIT_2: /* 9 */
			/* NOT USED */
			break;

		case IPF_TCPS_TIME_WAIT: /* 10 */
			/* we're in 2MSL timeout now */
			if (ostate == IPF_TCPS_LAST_ACK) {
				nstate = IPF_TCPS_CLOSED;
				rval = 1;
			} else {
				rval = 2;
			}
			break;

		case IPF_TCPS_CLOSED: /* 11 */
			rval = 2;
			break;

		default :
#if defined(_KERNEL)
			ASSERT(nstate >= IPF_TCPS_LISTEN &&
			    nstate <= IPF_TCPS_CLOSED);
#else
			abort();
#endif
			break;
		}
	}

	/*
	 * If rval == 2 then do not update the queue position, but treat the
	 * packet as being ok.
	 */
	if (rval == 2) {
		DTRACE_PROBE1(state_keeping_timer, int, nstate);
		rval = 1;
	}
	else if (rval == 1) {
		tqe->tqe_state[dir] = nstate;
		/*
		 * The nstate can either advance to a new state, or remain
		 * unchanged, resetting the timer by moving to the bottom of
		 * the queue.
		 */
		DTRACE_PROBE1(state_done, int, nstate);

		if ((tqe->tqe_flags & TQE_RULEBASED) == 0)
			fr_movequeue(tqe, tqe->tqe_ifq, tqtab + nstate, ifs);
	}

	return rval;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipstate_log                                                 */
/* Returns:     Nil                                                         */
/* Parameters:  is(I)   - pointer to state structure                        */
/*              type(I) - type of log entry to create                       */
/*                                                                          */
/* Creates a state table log entry using the state structure and type info. */
/* passed in.  Log packet/byte counts, source/destination address and other */
/* protocol specific information.                                           */
/* ------------------------------------------------------------------------ */
void ipstate_log(is, type, ifs)
struct ipstate *is;
u_int type;
ipf_stack_t *ifs;
{
#ifdef	IPFILTER_LOG
	struct	ipslog	ipsl;
	size_t sizes[1];
	void *items[1];
	int types[1];

	/*
	 * Copy information out of the ipstate_t structure and into the
	 * structure used for logging.
	 */
	ipsl.isl_type = type;
	ipsl.isl_pkts[0] = is->is_pkts[0] + is->is_icmppkts[0];
	ipsl.isl_bytes[0] = is->is_bytes[0];
	ipsl.isl_pkts[1] = is->is_pkts[1] + is->is_icmppkts[1];
	ipsl.isl_bytes[1] = is->is_bytes[1];
	ipsl.isl_pkts[2] = is->is_pkts[2] + is->is_icmppkts[2];
	ipsl.isl_bytes[2] = is->is_bytes[2];
	ipsl.isl_pkts[3] = is->is_pkts[3] + is->is_icmppkts[3];
	ipsl.isl_bytes[3] = is->is_bytes[3];
	ipsl.isl_src = is->is_src;
	ipsl.isl_dst = is->is_dst;
	ipsl.isl_p = is->is_p;
	ipsl.isl_v = is->is_v;
	ipsl.isl_flags = is->is_flags;
	ipsl.isl_tag = is->is_tag;
	ipsl.isl_rulen = is->is_rulen;
	(void) strncpy(ipsl.isl_group, is->is_group, FR_GROUPLEN);

	if (ipsl.isl_p == IPPROTO_TCP || ipsl.isl_p == IPPROTO_UDP) {
		ipsl.isl_sport = is->is_sport;
		ipsl.isl_dport = is->is_dport;
		if (ipsl.isl_p == IPPROTO_TCP) {
			ipsl.isl_state[0] = is->is_state[0];
			ipsl.isl_state[1] = is->is_state[1];
		}
	} else if (ipsl.isl_p == IPPROTO_ICMP) {
		ipsl.isl_itype = is->is_icmp.ici_type;
	} else if (ipsl.isl_p == IPPROTO_ICMPV6) {
		ipsl.isl_itype = is->is_icmp.ici_type;
	} else {
		ipsl.isl_ps.isl_filler[0] = 0;
		ipsl.isl_ps.isl_filler[1] = 0;
	}

	items[0] = &ipsl;
	sizes[0] = sizeof(ipsl);
	types[0] = 0;

	if (ipllog(IPL_LOGSTATE, NULL, items, sizes, types, 1, ifs)) {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_logged);
	} else {
		ATOMIC_INCL(ifs->ifs_ips_stats.iss_logfail);
	}
#endif
}


#ifdef	USE_INET6
/* ------------------------------------------------------------------------ */
/* Function:    fr_checkicmp6matchingstate                                  */
/* Returns:     ipstate_t* - NULL == no match found,                        */
/*                           else  pointer to matching state entry          */
/* Parameters:  fin(I) - pointer to packet information                      */
/* Locks:       NULL == no locks, else Read Lock on ipf_state               */
/*                                                                          */
/* If we've got an ICMPv6 error message, using the information stored in    */
/* the ICMPv6 packet, look for a matching state table entry.                */
/* ------------------------------------------------------------------------ */
static ipstate_t *fr_checkicmp6matchingstate(fin)
fr_info_t *fin;
{
	struct icmp6_hdr *ic6, *oic;
	int backward, i;
	ipstate_t *is, **isp;
	u_short sport, dport;
	i6addr_t dst, src;
	u_short savelen;
	icmpinfo_t *ic;
	fr_info_t ofin;
	tcphdr_t *tcp;
	ip6_t *oip6;
	u_char	pr;
	u_int hv;
	ipf_stack_t *ifs = fin->fin_ifs;

	/*
	 * Does it at least have the return (basic) IP header ?
	 * Is it an actual recognised ICMP error type?
	 * Only a basic IP header (no options) should be with
	 * an ICMP error header.
	 */
	if ((fin->fin_v != 6) || (fin->fin_plen < ICMP6ERR_MINPKTLEN) ||
	    !(fin->fin_flx & FI_ICMPERR))
		return NULL;

	ic6 = fin->fin_dp;

	oip6 = (ip6_t *)((char *)ic6 + ICMPERR_ICMPHLEN);
	if (fin->fin_plen < sizeof(*oip6))
		return NULL;

	bcopy((char *)fin, (char *)&ofin, sizeof(*fin));
	ofin.fin_v = 6;
	ofin.fin_ifp = fin->fin_ifp;
	ofin.fin_out = !fin->fin_out;
	ofin.fin_m = NULL;	/* if dereferenced, panic XXX */
	ofin.fin_mp = NULL;	/* if dereferenced, panic XXX */

	/*
	 * We make a fin entry to be able to feed it to
	 * matchsrcdst. Note that not all fields are necessary
	 * but this is the cleanest way. Note further we fill
	 * in fin_mp such that if someone uses it we'll get
	 * a kernel panic. fr_matchsrcdst does not use this.
	 *
	 * watch out here, as ip is in host order and oip6 in network
	 * order. Any change we make must be undone afterwards.
	 */
	savelen = oip6->ip6_plen;
	oip6->ip6_plen = fin->fin_dlen - ICMPERR_ICMPHLEN;
	ofin.fin_flx = FI_NOCKSUM;
	ofin.fin_ip = (ip_t *)oip6;
	ofin.fin_plen = oip6->ip6_plen;
	(void) fr_makefrip(sizeof(*oip6), (ip_t *)oip6, &ofin);
	ofin.fin_flx &= ~(FI_BAD|FI_SHORT);
	oip6->ip6_plen = savelen;

	if (oip6->ip6_nxt == IPPROTO_ICMPV6) {
		oic = (struct icmp6_hdr *)(oip6 + 1);
		/*
		 * an ICMP error can only be generated as a result of an
		 * ICMP query, not as the response on an ICMP error
		 *
		 * XXX theoretically ICMP_ECHOREP and the other reply's are
		 * ICMP query's as well, but adding them here seems strange XXX
		 */
		 if (!(oic->icmp6_type & ICMP6_INFOMSG_MASK))
		    	return NULL;

		/*
		 * perform a lookup of the ICMP packet in the state table
		 */
		hv = (pr = oip6->ip6_nxt);
		src.in6 = oip6->ip6_src;
		hv += src.in4.s_addr;
		dst.in6 = oip6->ip6_dst;
		hv += dst.in4.s_addr;
		hv += oic->icmp6_id;
		hv += oic->icmp6_seq;
		hv = DOUBLE_HASH(hv, ifs);

		READ_ENTER(&ifs->ifs_ipf_state);
		for (isp = &ifs->ifs_ips_table[hv]; ((is = *isp) != NULL); ) {
			ic = &is->is_icmp;
			isp = &is->is_hnext;
			if ((is->is_p == pr) &&
			    !(is->is_pass & FR_NOICMPERR) &&
			    (oic->icmp6_id == ic->ici_id) &&
			    (oic->icmp6_seq == ic->ici_seq) &&
			    (is = fr_matchsrcdst(&ofin, is, &src,
						 &dst, NULL, FI_ICMPCMP))) {
			    	/*
			    	 * in the state table ICMP query's are stored
			    	 * with the type of the corresponding ICMP
			    	 * response. Correct here
			    	 */
				if (((ic->ici_type == ICMP6_ECHO_REPLY) &&
				     (oic->icmp6_type == ICMP6_ECHO_REQUEST)) ||
				     (ic->ici_type - 1 == oic->icmp6_type )) {
				    	ifs->ifs_ips_stats.iss_hits++;
					backward = IP6_NEQ(&is->is_dst, &src);
					fin->fin_rev = !backward;
					i = (backward << 1) + fin->fin_out;
    					is->is_icmppkts[i]++;
					return is;
				}
			}
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_state);
		return NULL;
	}

	hv = (pr = oip6->ip6_nxt);
	src.in6 = oip6->ip6_src;
	hv += src.i6[0];
	hv += src.i6[1];
	hv += src.i6[2];
	hv += src.i6[3];
	dst.in6 = oip6->ip6_dst;
	hv += dst.i6[0];
	hv += dst.i6[1];
	hv += dst.i6[2];
	hv += dst.i6[3];

	if ((oip6->ip6_nxt == IPPROTO_TCP) || (oip6->ip6_nxt == IPPROTO_UDP)) {
		tcp = (tcphdr_t *)(oip6 + 1);
		dport = tcp->th_dport;
		sport = tcp->th_sport;
		hv += dport;
		hv += sport;
	} else
		tcp = NULL;
	hv = DOUBLE_HASH(hv, ifs);

	READ_ENTER(&ifs->ifs_ipf_state);
	for (isp = &ifs->ifs_ips_table[hv]; ((is = *isp) != NULL); ) {
		isp = &is->is_hnext;
		/*
		 * Only allow this icmp though if the
		 * encapsulated packet was allowed through the
		 * other way around. Note that the minimal amount
		 * of info present does not allow for checking against
		 * tcp internals such as seq and ack numbers.
		 */
		if ((is->is_p != pr) || (is->is_v != 6) ||
		    (is->is_pass & FR_NOICMPERR))
			continue;
		is = fr_matchsrcdst(&ofin, is, &src, &dst, tcp, FI_ICMPCMP);
		if (is != NULL) {
			ifs->ifs_ips_stats.iss_hits++;
			backward = IP6_NEQ(&is->is_dst, &src);
			fin->fin_rev = !backward;
			i = (backward << 1) + fin->fin_out;
			is->is_icmppkts[i]++;
			/*
			 * we deliberately do not touch the timeouts
			 * for the accompanying state table entry.
			 * It remains to be seen if that is correct. XXX
			 */
			return is;
		}
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
	return NULL;
}
#endif


/* ------------------------------------------------------------------------ */
/* Function:    fr_sttab_init                                               */
/* Returns:     Nil                                                         */
/* Parameters:  tqp(I) - pointer to an array of timeout queues for TCP      */
/*                                                                          */
/* Initialise the array of timeout queues for TCP.                          */
/* ------------------------------------------------------------------------ */
void fr_sttab_init(tqp, ifs)
ipftq_t *tqp;
ipf_stack_t *ifs;
{
	int i;

	for (i = IPF_TCP_NSTATES - 1; i >= 0; i--) {
		tqp[i].ifq_ttl = 0;
		tqp[i].ifq_ref = 1;
		tqp[i].ifq_head = NULL;
		tqp[i].ifq_tail = &tqp[i].ifq_head;
		tqp[i].ifq_next = tqp + i + 1;
		MUTEX_INIT(&tqp[i].ifq_lock, "ipftq tcp tab");
	}
	tqp[IPF_TCP_NSTATES - 1].ifq_next = NULL;
	tqp[IPF_TCPS_CLOSED].ifq_ttl = ifs->ifs_fr_tcpclosed;
	tqp[IPF_TCPS_LISTEN].ifq_ttl = ifs->ifs_fr_tcptimeout;
	tqp[IPF_TCPS_SYN_SENT].ifq_ttl = ifs->ifs_fr_tcptimeout;
	tqp[IPF_TCPS_SYN_RECEIVED].ifq_ttl = ifs->ifs_fr_tcptimeout;
	tqp[IPF_TCPS_ESTABLISHED].ifq_ttl = ifs->ifs_fr_tcpidletimeout;
	tqp[IPF_TCPS_CLOSE_WAIT].ifq_ttl = ifs->ifs_fr_tcphalfclosed;
	tqp[IPF_TCPS_FIN_WAIT_1].ifq_ttl = ifs->ifs_fr_tcphalfclosed;
	tqp[IPF_TCPS_CLOSING].ifq_ttl = ifs->ifs_fr_tcptimeout;
	tqp[IPF_TCPS_LAST_ACK].ifq_ttl = ifs->ifs_fr_tcplastack;
	tqp[IPF_TCPS_FIN_WAIT_2].ifq_ttl = ifs->ifs_fr_tcpclosewait;
	tqp[IPF_TCPS_TIME_WAIT].ifq_ttl = ifs->ifs_fr_tcptimeout;
	tqp[IPF_TCPS_HALF_ESTAB].ifq_ttl = ifs->ifs_fr_tcptimeout;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_sttab_destroy                                            */
/* Returns:     Nil                                                         */
/* Parameters:  tqp(I) - pointer to an array of timeout queues for TCP      */
/*                                                                          */
/* Do whatever is necessary to "destroy" each of the entries in the array   */
/* of timeout queues for TCP.                                               */
/* ------------------------------------------------------------------------ */
void fr_sttab_destroy(tqp)
ipftq_t *tqp;
{
	int i;

	for (i = IPF_TCP_NSTATES - 1; i >= 0; i--)
		MUTEX_DESTROY(&tqp[i].ifq_lock);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_statederef                                               */
/* Returns:     Nil                                                         */
/* Parameters:  isp(I) - pointer to pointer to state table entry            */
/*              ifs - ipf stack instance                                    */
/*                                                                          */
/* Decrement the reference counter for this state table entry and free it   */
/* if there are no more things using it.                                    */
/*                                                                          */
/* Internal parameters:                                                     */
/*    state[0] = state of source (host that initiated connection)           */
/*    state[1] = state of dest   (host that accepted the connection)        */
/* ------------------------------------------------------------------------ */
void fr_statederef(isp, ifs)
ipstate_t **isp;
ipf_stack_t *ifs;
{
	ipstate_t *is;

	is = *isp;
	*isp = NULL;

	MUTEX_ENTER(&is->is_lock);
	if (is->is_ref > 1) {
		is->is_ref--;
		MUTEX_EXIT(&is->is_lock);
#ifndef	_KERNEL
		if ((is->is_sti.tqe_state[0] > IPF_TCPS_ESTABLISHED) ||
		   (is->is_sti.tqe_state[1] > IPF_TCPS_ESTABLISHED)) {
			(void) fr_delstate(is, ISL_ORPHAN, ifs);
		}
#endif
		return;
	}
	MUTEX_EXIT(&is->is_lock);

	WRITE_ENTER(&ifs->ifs_ipf_state);
	(void) fr_delstate(is, ISL_EXPIRE, ifs);
	RWLOCK_EXIT(&ifs->ifs_ipf_state);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_setstatequeue                                            */
/* Returns:     Nil                                                         */
/* Parameters:  is(I) - pointer to state structure                          */
/*              rev(I) - forward(0) or reverse(1) direction                 */
/* Locks:       ipf_state (read or write)                                   */
/*                                                                          */
/* Put the state entry on its default queue entry, using rev as a helped in */
/* determining which queue it should be placed on.                          */
/* ------------------------------------------------------------------------ */
void fr_setstatequeue(is, rev, ifs)
ipstate_t *is;
int rev;
ipf_stack_t *ifs;
{
	ipftq_t *oifq, *nifq;


	if ((is->is_sti.tqe_flags & TQE_RULEBASED) != 0)
		nifq = is->is_tqehead[rev];
	else
		nifq = NULL;

	if (nifq == NULL) {
		switch (is->is_p)
		{
#ifdef USE_INET6
		case IPPROTO_ICMPV6 :
			if (rev == 1)
				nifq = &ifs->ifs_ips_icmpacktq;
			else
				nifq = &ifs->ifs_ips_icmptq;
			break;
#endif
		case IPPROTO_ICMP :
			if (rev == 1)
				nifq = &ifs->ifs_ips_icmpacktq;
			else
				nifq = &ifs->ifs_ips_icmptq;
			break;
		case IPPROTO_TCP :
			nifq = ifs->ifs_ips_tqtqb + is->is_state[rev];
			break;

		case IPPROTO_UDP :
			if (rev == 1)
				nifq = &ifs->ifs_ips_udpacktq;
			else
				nifq = &ifs->ifs_ips_udptq;
			break;

		default :
			nifq = &ifs->ifs_ips_iptq;
			break;
		}
	}

	oifq = is->is_sti.tqe_ifq;
	/*
	 * If it's currently on a timeout queue, move it from one queue to
	 * another, else put it on the end of the newly determined queue.
	 */
	if (oifq != NULL)
		fr_movequeue(&is->is_sti, oifq, nifq, ifs);
	else
		fr_queueappend(&is->is_sti, nifq, is, ifs);
	return;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_stateiter                                                */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  token(I) - pointer to ipftoken structure                    */
/*              itp(I)   - pointer to ipfgeniter structure                  */
/*                                                                          */
/* This function handles the SIOCGENITER ioctl for the state tables and     */
/* walks through the list of entries in the state table list (ips_list.)    */
/* ------------------------------------------------------------------------ */
static int fr_stateiter(token, itp, ifs)
ipftoken_t *token;
ipfgeniter_t *itp;
ipf_stack_t *ifs;
{
	ipstate_t *is, *next, zero;
	int error, count;
	char *dst;

	if (itp->igi_data == NULL)
		return EFAULT;

	if (itp->igi_nitems == 0)
		return EINVAL;

	if (itp->igi_type != IPFGENITER_STATE)
		return EINVAL;

	error = 0;

	READ_ENTER(&ifs->ifs_ipf_state);

	/*
	 * Get "previous" entry from the token and find the next entry.
	 */
	is = token->ipt_data;
	if (is == NULL) {
		next = ifs->ifs_ips_list;
	} else {
		next = is->is_next;
	}

	dst = itp->igi_data;
	for (count = itp->igi_nitems; count > 0; count--) {
		/*
		 * If we found an entry, add a reference to it and update the token.
		 * Otherwise, zero out data to be returned and NULL out token.
		 */
		if (next != NULL) {
			MUTEX_ENTER(&next->is_lock);
			next->is_ref++;
			MUTEX_EXIT(&next->is_lock);
			token->ipt_data = next;
		} else {
			bzero(&zero, sizeof(zero));
			next = &zero;
			token->ipt_data = NULL;
		}

		/*
		 * Safe to release lock now the we have a reference.
		 */
		RWLOCK_EXIT(&ifs->ifs_ipf_state);

		/*
		 * Copy out data and clean up references and tokens.
		 */
		error = COPYOUT(next, dst, sizeof(*next));
		if (error != 0)
			error = EFAULT;
		if (token->ipt_data == NULL) {
			ipf_freetoken(token, ifs);
			break;
		} else {
			if (is != NULL)
				fr_statederef(&is, ifs);
			if (next->is_next == NULL) {
				ipf_freetoken(token, ifs);
				break;
			}
		}

		if ((count == 1) || (error != 0))
			break;

		READ_ENTER(&ifs->ifs_ipf_state);
		dst += sizeof(*next);
		is = next;
		next = is->is_next;
	}

	return error;
}
