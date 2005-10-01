/*
 * Copyright (C) 1999-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint)
static const char rcsid[] = "@(#)$Id: ip_fil_solaris.c,v 2.36 2003/07/01 18:30:20 darrenr Exp $";
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/ioctl.h>
#include <sys/filio.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/dditypes.h>
#include <sys/cmn_err.h>
#include <net/if.h>
#include <net/af.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/tcpip.h>
#include <netinet/ip_icmp.h>
#include "ip_compat.h"
#ifdef	USE_INET6
# include <netinet/icmp6.h>
#endif
#include "ip_fil.h"
#include "ip_nat.h"
#include "ip_frag.h"
#include "ip_state.h"
#include "ip_auth.h"
#include "ip_proxy.h"
#ifdef	IPFILTER_LOOKUP
#include "ip_lookup.h"
#endif
#ifdef	IPFILTER_COMPILED
#include "ip_rules.h"
#endif
#include <inet/ip_ire.h>

#include <sys/md5.h>

extern	int fr_flags, fr_active;
#if SOLARIS2 >= 7
extern	timeout_id_t	fr_timer_id;
#else
extern	int	fr_timer_id;
#endif


static	int	frzerostats __P((caddr_t));
static	int	fr_send_ip __P((fr_info_t *fin, mblk_t *m));

ipfmutex_t	ipl_mutex, ipf_authmx, ipf_rw, ipf_stinsert;
ipfmutex_t	ipf_nat_new, ipf_natio, ipf_timeoutlock;
ipfrwlock_t	ipf_mutex, ipf_global, ipf_ipidfrag;
ipfrwlock_t	ipf_frag, ipf_state, ipf_nat, ipf_natfrag, ipf_auth;
kcondvar_t	iplwait, ipfauthwait;
#if SOLARIS2 < 10
#if SOLARIS2 >= 7
u_int		*ip_ttl_ptr;
u_int		*ip_mtudisc;
# if SOLARIS2 >= 8
int		*ip_forwarding;
u_int		*ip6_forwarding;
# else
u_int		*ip_forwarding;
# endif
#else
u_long		*ip_ttl_ptr;
u_long		*ip_mtudisc;
u_long		*ip_forwarding;
#endif
#endif
int		ipf_locks_done = 0;


/* ------------------------------------------------------------------------ */
/* Function:    ipldetach                                                   */
/* Returns:     int - 0 == success, else error.                             */
/* Parameters:  Nil                                                         */
/*                                                                          */
/* This function is responsible for undoing anything that might have been   */
/* done in a call to iplattach().  It must be able to clean up from a call  */
/* to iplattach() that did not succeed.  Why might that happen?  Someone    */
/* configures a table to be so large that we cannot allocate enough memory  */
/* for it.                                                                  */
/* ------------------------------------------------------------------------ */
int ipldetach()
{

	ASSERT(rw_read_locked(&ipf_global.ipf_lk) == 0);

	if (fr_refcnt)
		return EBUSY;
#if SOLARIS2 < 10

	if (fr_control_forwarding & 2) {
		*ip_forwarding = 0;
#if SOLARIS2 >= 8
		*ip6_forwarding = 0;
#endif
	}
#endif

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "ipldetach()\n");
#endif

	fr_fragunload();
	fr_authunload();
	fr_stateunload();
	fr_natunload();
	appr_unload();

#ifdef	IPFILTER_COMPILED
	ipfrule_remove();
#endif

	(void) frflush(IPL_LOGIPF, 0, FR_INQUE|FR_OUTQUE|FR_INACTIVE);
	(void) frflush(IPL_LOGIPF, 0, FR_INQUE|FR_OUTQUE);

#ifdef	IPFILTER_LOOKUP
	ip_lookup_unload();
#endif

#ifdef	IPFILTER_LOG
	fr_logunload();
#endif

	if (ipf_locks_done == 1) {
		MUTEX_DESTROY(&ipf_timeoutlock);
		MUTEX_DESTROY(&ipf_rw);
		RW_DESTROY(&ipf_ipidfrag);
		ipf_locks_done = 0;
	}
	return 0;
}


int iplattach __P((void))
{
#if SOLARIS2 < 10
	int i;
#endif

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplattach()\n");
#endif

	ASSERT(rw_read_locked(&ipf_global.ipf_lk) == 0);

	bzero((char *)frcache, sizeof(frcache));
	MUTEX_INIT(&ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ipf_timeoutlock, "ipf timeout lock mutex");
	RWLOCK_INIT(&ipf_ipidfrag, "ipf IP NAT-Frag rwlock");
	ipf_locks_done = 1;

#ifdef	IPFILTER_LOG
	if (fr_loginit() == -1)
		return -1;
#endif
	if (fr_natinit() == -1)
		return -1;
	if (fr_stateinit() == -1)
		return -1;
	if (fr_authinit() == -1)
		return -1;
	if (fr_fraginit() == -1)
		return -1;
	if (appr_init() == -1)
		return -1;
#ifdef	IPFILTER_SYNC
	ipfsync_init();
#endif
#ifdef	IPFILTER_SCAN
	isc_init();
#endif
#ifdef IPFILTER_LOOKUP
	if (ip_lookup_init() == -1)
		return -1;
#endif

/* Do not use private interface ip_params_arr[] in Solaris 10 */
#if SOLARIS2 < 10

#if SOLARIS2 >= 8
	ip_forwarding = &ip_g_forward;
#endif
	/*
	 * XXX - There is no terminator for this array, so it is not possible
	 * to tell if what we are looking for is missing and go off the end
	 * of the array.
	 */

	for (i = 0; ; i++) {
		if (!strcmp(ip_param_arr[i].ip_param_name, "ip_def_ttl")) {
			ip_ttl_ptr = &ip_param_arr[i].ip_param_value;
		} else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip_path_mtu_discovery")) {
			ip_mtudisc = &ip_param_arr[i].ip_param_value;
		}
#if SOLARIS2 < 8
		else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip_forwarding")) {
			ip_forwarding = &ip_param_arr[i].ip_param_value;
		}
#else
		else if (!strcmp(ip_param_arr[i].ip_param_name,
			    "ip6_forwarding")) {
			ip6_forwarding = &ip_param_arr[i].ip_param_value;
		}
#endif

		if (ip_mtudisc != NULL && ip_ttl_ptr != NULL &&
#if SOLARIS2 >= 8
		    ip6_forwarding != NULL &&
#endif
		    ip_forwarding != NULL)
			break;
	}

	if (fr_control_forwarding & 1) {
		*ip_forwarding = 1;
#if SOLARIS2 >= 8
		*ip6_forwarding = 1;
#endif
	}

#endif

	return 0;
}


static	int	frzerostats(data)
caddr_t	data;
{
	friostat_t fio;
	int error;

	fr_getstat(&fio);
	error = copyoutptr((caddr_t)&fio, data, sizeof(fio));
	if (error)
		return error;

	bzero((char *)frstats, sizeof(*frstats) * 2);

	return 0;
}


/*
 * Filter ioctl interface.
 */
/*ARGSUSED*/
int iplioctl(dev, cmd, data, mode, cp, rp)
dev_t dev;
int cmd;
#if SOLARIS2 >= 7
intptr_t data;
#else
int *data;
#endif
int mode;
cred_t *cp;
int *rp;
{
	int error = 0, tmp;
	friostat_t fio;
	minor_t unit;
	u_int enable;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplioctl(%x,%x,%x,%d,%x,%d)\n",
		dev, cmd, data, mode, cp, rp);
#endif
	unit = getminor(dev);
	if (IPL_LOGMAX < unit)
		return ENXIO;

	if (fr_running <= 0) {
		if (unit != IPL_LOGIPF)
			return EIO;
		if (cmd != SIOCIPFGETNEXT && cmd != SIOCIPFGET &&
		    cmd != SIOCIPFSET && cmd != SIOCFRENB && cmd != SIOCGETFS)
			return EIO;
	}

	READ_ENTER(&ipf_global);

	error = fr_ioctlswitch(unit, (caddr_t)data, cmd, mode);
	if (error != -1) {
		RWLOCK_EXIT(&ipf_global);
		return error;
	}
	error = 0;

	switch (cmd)
	{
	case SIOCFRENB :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&enable,
				       sizeof(enable));
			if (error != 0) {
				error = EFAULT;
				break;
			}

			RWLOCK_EXIT(&ipf_global);
			WRITE_ENTER(&ipf_global);
			if (enable) {
				if (fr_running > 0)
					error = 0;
				else
					error = iplattach();
				if (error == 0)
					fr_running = 1;
				else
					(void) ipldetach();
			} else {
				error = ipldetach();
				if (error == 0)
					fr_running = -1;
			}
		}
		break;
	case SIOCIPFSET :
		if (!(mode & FWRITE)) {
			error = EPERM;
			break;
		}
		/* FALLTHRU */
	case SIOCIPFGETNEXT :
	case SIOCIPFGET :
		error = fr_ipftune(cmd, (char *)data);
		break;
	case SIOCSETFF :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&fr_flags,
			       sizeof(fr_flags));
			if (error != 0)
				error = EFAULT;
		}
		break;
	case SIOCGETFF :
		error = COPYOUT((caddr_t)&fr_flags, (caddr_t)data,
			       sizeof(fr_flags));
		if (error != 0)
			error = EFAULT;
		break;
	case SIOCFUNCL :
		error = fr_resolvefunc((void *)data);
		break;
	case SIOCINAFR :
	case SIOCRMAFR :
	case SIOCADAFR :
	case SIOCZRLST :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frrequest(unit, cmd, (caddr_t)data,
					  fr_active, 1);
		break;
	case SIOCINIFR :
	case SIOCRMIFR :
	case SIOCADIFR :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frrequest(unit, cmd, (caddr_t)data,
					  1 - fr_active, 1);
		break;
	case SIOCSWAPA :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			WRITE_ENTER(&ipf_mutex);
			bzero((char *)frcache, sizeof(frcache[0]) * 2);
			error = COPYOUT((caddr_t)&fr_active, (caddr_t)data,
				       sizeof(fr_active));
			if (error != 0)
				error = EFAULT;
			else
				fr_active = 1 - fr_active;
			RWLOCK_EXIT(&ipf_mutex);
		}
		break;
	case SIOCGETFS :
		fr_getstat(&fio);
		error = fr_outobj((void *)data, &fio, IPFOBJ_IPFSTAT);
		break;
	case SIOCFRZST :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frzerostats((caddr_t)data);
		break;
	case	SIOCIPFFL :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&tmp,
				       sizeof(tmp));
			if (!error) {
				tmp = frflush(unit, 4, tmp);
				error = COPYOUT((caddr_t)&tmp, (caddr_t)data,
					       sizeof(tmp));
				if (error != 0)
					error = EFAULT;
			} else
				error = EFAULT;
		}
		break;
#ifdef USE_INET6
	case	SIOCIPFL6 :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&tmp,
				       sizeof(tmp));
			if (!error) {
				tmp = frflush(unit, 6, tmp);
				error = COPYOUT((caddr_t)&tmp, (caddr_t)data,
					       sizeof(tmp));
				if (error != 0)
					error = EFAULT;
			} else
				error = EFAULT;
		}
		break;
#endif
	case SIOCSTLCK :
		error = COPYIN((caddr_t)data, (caddr_t)&tmp, sizeof(tmp));
		if (error == 0) {
			fr_state_lock = tmp;
			fr_nat_lock = tmp;
			fr_frag_lock = tmp;
			fr_auth_lock = tmp;
		} else
			error = EFAULT;
	break;
#ifdef	IPFILTER_LOG
	case	SIOCIPFFB :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			tmp = ipflog_clear(unit);
			error = COPYOUT((caddr_t)&tmp, (caddr_t)data,
				       sizeof(tmp));
			if (error)
				error = EFAULT;
		}
		break;
#endif /* IPFILTER_LOG */
	case SIOCFRSYN :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			RWLOCK_EXIT(&ipf_global);
			WRITE_ENTER(&ipf_global);
			error = ipfsync();
		}
		break;
	case SIOCGFRST :
		error = fr_outobj((void *)data, fr_fragstats(),
				  IPFOBJ_FRAGSTAT);
		break;
	case FIONREAD :
#ifdef	IPFILTER_LOG
		tmp = (int)iplused[IPL_LOGIPF];

		error = COPYOUT((caddr_t)&tmp, (caddr_t)data, sizeof(tmp));
		if (error != 0)
			error = EFAULT;
#endif
		break;
	default :
		cmn_err(CE_NOTE, "Unknown: cmd 0x%x data %p",
			cmd, (void *)data);
		error = EINVAL;
		break;
	}
	RWLOCK_EXIT(&ipf_global);
	return error;
}

#ifndef IRE_ILL_CN
ill_t	*get_unit(name, v)
char	*name;
int	v;
{
	size_t len = strlen(name) + 1;	/* includes \0 */
	ill_t *il;
#if SOLARIS2 >= 10
	ill_walk_context_t ctx;
#endif
	int sap;

	if (v == 4)
		sap = 0x0800;
	else if (v == 6)
		sap = 0x86dd;
	else
		return NULL;
#if SOLARIS2 >= 10
	for (il = ILL_START_WALK_ALL(&ctx); il; il = ill_next(&ctx, il))
#else
	for (il = ill_g_head; il; il = il->ill_next)
#endif
		if ((len == il->ill_name_length) && (il->ill_sap == sap) &&
		    !strncmp(il->ill_name, name, len))
			return il;
	return NULL;
}
#else
s_ill_t	*get_unit(name, v)
char	*name;
int	v;
{
	s_ill_t *il;

	int sap;

	if (v == 4)
		sap = 0x0800;
	else if (v == 6)
		sap = 0x86dd;
	else
		return NULL;

	mutex_enter(&s_ill_g_head_lock);
	for (il = s_ill_g_head; il; il = il->ill_next)
		if ((il->ill_sap == sap) &&
		    !strncmp(il->ill_name, name, LIFNAMSIZ))
			break;
	mutex_exit(&s_ill_g_head_lock);
	return il;
}
#endif /* IRE_ILL_CN */


/*
 * routines below for saving IP headers to buffer
 */
/*ARGSUSED*/
int iplopen(devp, flags, otype, cred)
dev_t *devp;
int flags, otype;
cred_t *cred;
{
	minor_t min = getminor(*devp);

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplopen(%x,%x,%x,%x)\n", devp, flags, otype, cred);
#endif
	if (!(otype & OTYP_CHR))
		return ENXIO;

	min = (IPL_LOGMAX < min) ? ENXIO : 0;
	return min;
}


/*ARGSUSED*/
int iplclose(dev, flags, otype, cred)
dev_t dev;
int flags, otype;
cred_t *cred;
{
	minor_t	min = getminor(dev);

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplclose(%x,%x,%x,%x)\n", dev, flags, otype, cred);
#endif

	min = (IPL_LOGMAX < min) ? ENXIO : 0;
	return min;
}

#ifdef	IPFILTER_LOG
/*
 * iplread/ipllog
 * both of these must operate with at least splnet() lest they be
 * called during packet processing and cause an inconsistancy to appear in
 * the filter lists.
 */
/*ARGSUSED*/
int iplread(dev, uio, cp)
dev_t dev;
register struct uio *uio;
cred_t *cp;
{
# ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplread(%x,%x,%x)\n", dev, uio, cp);
# endif
# ifdef	IPFILTER_SYNC
	if (getminor(dev) == IPL_LOGSYNC)
		return ipfsync_read(uio);
# endif

	return ipflog_read(getminor(dev), uio);
}
#endif /* IPFILTER_LOG */


#ifdef	IPFILTER_SYNC
/*
 * iplread/ipllog
 * both of these must operate with at least splnet() lest they be
 * called during packet processing and cause an inconsistancy to appear in
 * the filter lists.
 */
int iplwrite(dev, uio, cp)
dev_t dev;
register struct uio *uio;
cred_t *cp;
{
#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplwrite(%x,%x,%x)\n", dev, uio, cp);
#endif
	if (getminor(dev) != IPL_LOGSYNC)
		return ENXIO;
	return ipfsync_write(uio);
}
#endif /* IPFILTER_SYNC */


/*
 * fr_send_reset - this could conceivably be a call to tcp_respond(), but that
 * requires a large amount of setting up and isn't any more efficient.
 */
int fr_send_reset(fin)
fr_info_t *fin;
{
	tcphdr_t *tcp, *tcp2;
	int tlen, hlen;
	mblk_t *m;
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;

	tcp = fin->fin_dp;
	if (tcp->th_flags & TH_RST)
		return -1;

#ifndef	IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		return -1;
#endif

	tlen = (tcp->th_flags & (TH_SYN|TH_FIN)) ? 1 : 0;
#ifdef	USE_INET6
	if (fin->fin_v == 6)
		hlen = sizeof(ip6_t);
	else
#endif
		hlen = sizeof(ip_t);
	hlen += sizeof(*tcp2);
	if ((m = (mblk_t *)allocb(hlen + 64, BPRI_HI)) == NULL)
		return -1;

	m->b_rptr += 64;
	MTYPE(m) = M_DATA;
	m->b_wptr = m->b_rptr + hlen;
	bzero((char *)m->b_rptr, hlen);
	tcp2 = (struct tcphdr *)(m->b_rptr + hlen - sizeof(*tcp2));
	tcp2->th_dport = tcp->th_sport;
	tcp2->th_sport = tcp->th_dport;
	if (tcp->th_flags & TH_ACK) {
		tcp2->th_seq = tcp->th_ack;
		tcp2->th_flags = TH_RST;
	} else {
		tcp2->th_ack = ntohl(tcp->th_seq);
		tcp2->th_ack += tlen;
		tcp2->th_ack = htonl(tcp2->th_ack);
		tcp2->th_flags = TH_RST|TH_ACK;
	}
	tcp2->th_off = sizeof(struct tcphdr) >> 2;

	/*
	 * This is to get around a bug in the Solaris 2.4/2.5 TCP checksum
	 * computation that is done by their put routine.
	 */
#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_flow = ((ip6_t *)fin->fin_ip)->ip6_flow;
		ip6->ip6_src = fin->fin_dst6;
		ip6->ip6_dst = fin->fin_src6;
		ip6->ip6_plen = htons(sizeof(*tcp));
		ip6->ip6_nxt = IPPROTO_TCP;
		tcp2->th_sum = fr_cksum(m, (ip_t *)ip6, IPPROTO_TCP, tcp2);
	} else
#endif
	{
		ip = (ip_t *)m->b_rptr;
		ip->ip_src.s_addr = fin->fin_daddr;
		ip->ip_dst.s_addr = fin->fin_saddr;
		ip->ip_id = fr_nextipid(fin);
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_len = sizeof(*ip) + sizeof(*tcp);
		ip->ip_tos = fin->fin_ip->ip_tos;
		tcp2->th_sum = fr_cksum(m, ip, IPPROTO_TCP, tcp2);
	}
	return fr_send_ip(fin, m);
}


/*
 * Function:	fr_send_ip
 * Returns:	 0: success
 *		-1: failed
 * Parameters:
 *	fin: packet information
 *	m: the message block where ip head starts
 *
 * Send a new packet through the IP stack. 
 *
 * For IPv4 packets, ip_len must be in host byte order, and ip_v,
 * ip_ttl, ip_off, and ip_sum are ignored (filled in by this
 * function).
 *
 * For IPv6 packets, ip6_flow, ip6_vfc, and ip6_hlim are filled
 * in by this function.
 *
 * All other portions of the packet must be in on-the-wire format.
 */
static int fr_send_ip(fin, m)
fr_info_t *fin;
mblk_t *m;
{
	int i;

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6_t *ip6;

		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_vfc = 0x60;
		ip6->ip6_hlim = 127;
	} else
#endif
	{
		ip_t *ip;

		ip = (ip_t *)m->b_rptr;
		ip->ip_v = IPVERSION;

#if SOLARIS2 >= 10
		ip->ip_ttl = 255;

		ip->ip_off = IP_DF;
#else
		ip->ip_ttl = (u_char)(*ip_ttl_ptr);
		ip->ip_off = *ip_mtudisc ? IP_DF : 0;
#endif

		ip->ip_sum = ipf_cksum((u_short *)ip, sizeof(*ip));

	}
	i = fr_fastroute(m, &m, fin, NULL);
	return i;
}


int fr_send_icmp_err(type, fin, dst)
int type;
fr_info_t *fin;
int dst;
{
	struct in_addr dst4;
	struct icmp *icmp;
	int hlen, code;
	qif_t *qif;
	u_short sz;
#ifdef	USE_INET6
	mblk_t *mb;
#endif
	mblk_t *m;
#ifdef	icmp_nextmtu
#ifndef IRE_ILL_CN
	ill_t *il;
#else
	s_ill_t *il;
#endif	/* IRE_ILL_CN */
#endif
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;

#ifdef	icmp_nextmtu
	/* lint fodder */
	il = NULL;
	il = il;
#endif

	if ((type < 0) || (type > ICMP_MAXTYPE))
		return -1;

	code = fin->fin_icode;
#ifdef USE_INET6
	if ((code < 0) || (code > sizeof(icmptoicmp6unreach)/sizeof(int)))
		return -1;
#endif

#ifndef	IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		return -1;
#endif

	qif = fin->fin_qif;

#ifdef	USE_INET6
	mb = fin->fin_qfm;

	if (fin->fin_v == 6) {
		sz = sizeof(ip6_t);
		sz += MIN(mb->b_wptr - mb->b_rptr, 512);
		hlen = sizeof(ip6_t);
		type = icmptoicmp6types[type];
		if (type == ICMP6_DST_UNREACH)
			code = icmptoicmp6unreach[code];
	} else
#endif
	{
		if ((fin->fin_p == IPPROTO_ICMP) &&
		    !(fin->fin_flx & FI_SHORT))
			switch (ntohs(fin->fin_data[0]) >> 8)
			{
			case ICMP_ECHO :
			case ICMP_TSTAMP :
			case ICMP_IREQ :
			case ICMP_MASKREQ :
				break;
			default :
				return 0;
			}

		sz = sizeof(ip_t) * 2;
		sz += 8;		/* 64 bits of data */
		hlen = sizeof(ip_t);
	}

	sz += offsetof(struct icmp, icmp_ip);
	if ((m = (mblk_t *)allocb((size_t)sz + 64, BPRI_HI)) == NULL)
		return -1;
	MTYPE(m) = M_DATA;
	m->b_rptr += 64;
	m->b_wptr = m->b_rptr + sz;
	bzero((char *)m->b_rptr, (size_t)sz);
	icmp = (struct icmp *)(m->b_rptr + hlen);
	icmp->icmp_type = type & 0xff;
	icmp->icmp_code = code & 0xff;
#ifndef IRE_ILL_CN
#ifdef	icmp_nextmtu
	if (type == ICMP_UNREACH && ((il = qif->qf_ill) != NULL) &&
	    fin->fin_icode == ICMP_UNREACH_NEEDFRAG)
		icmp->icmp_nextmtu = htons(il->ill_max_frag);
#endif
#endif	/* IRE_ILL_CN */

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		struct in6_addr dst6;
		int csz;

		if (dst == 0) {
			if (fr_ifpaddr(6, FRI_NORMAL, qif->qf_ill,
				       (struct in_addr *)&dst6, NULL) == -1) {
				FREE_MB_T(m);
				return -1;
			}
		} else
			dst6 = fin->fin_dst6;

		csz = sz;
		sz -= sizeof(ip6_t);
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_flow = ((ip6_t *)fin->fin_ip)->ip6_flow;
		ip6->ip6_plen = htons((u_short)sz);
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_src = dst6;
		ip6->ip6_dst = fin->fin_src6;
		sz -= offsetof(struct icmp, icmp_ip);
		bcopy((char *)mb->b_rptr, (char *)&icmp->icmp_ip, sz);
		icmp->icmp_cksum = csz - sizeof(ip6_t);
	} else
#endif
	{
		ip = (ip_t *)m->b_rptr;
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_id = fin->fin_ip->ip_id;
		ip->ip_tos = fin->fin_ip->ip_tos;
		ip->ip_len = (u_short)sz;
		if (dst == 0) {
			if (fr_ifpaddr(4, FRI_NORMAL, qif->qf_ill,
				       &dst4, NULL) == -1) {
				FREE_MB_T(m);
				return -1;
			}
		} else
			dst4 = fin->fin_dst;
		ip->ip_src = dst4;
		ip->ip_dst = fin->fin_src;
		bcopy((char *)fin->fin_ip, (char *)&icmp->icmp_ip,
		      sizeof(*fin->fin_ip));
		bcopy((char *)fin->fin_ip + fin->fin_hlen,
		      (char *)&icmp->icmp_ip + sizeof(*fin->fin_ip), 8);
		icmp->icmp_ip.ip_len = htons(icmp->icmp_ip.ip_len);
		icmp->icmp_cksum = ipf_cksum((u_short *)icmp,
					     sz - sizeof(ip_t));
	}

	/*
	 * Need to exit out of these so we don't recursively call rw_enter
	 * from fr_qout.
	 */
	return fr_send_ip(fin, m);
}

#ifdef IRE_ILL_CN
#include <sys/time.h>
#include <sys/varargs.h>

#ifndef _KERNEL
#include <stdio.h>
#endif

#define	NULLADDR_RATE_LIMIT 10	/* 10 seconds */


/*
 * Print out warning message at rate-limited speed.
 */
static void rate_limit_message(int rate, const char *message, ...)
{
	static time_t last_time = 0;
	time_t now;
	va_list args;
	char msg_buf[256];
	int  need_printed = 0;

	now = ddi_get_time();

	/* make sure, no multiple entries */
	ASSERT(MUTEX_NOT_HELD(&(ipf_rw.ipf_lk)));
	MUTEX_ENTER(&ipf_rw);
	if (now - last_time >= rate) {
		need_printed = 1;
		last_time = now;
	}
	MUTEX_EXIT(&ipf_rw);

	if (need_printed) {
		va_start(args, message);
		(void)vsnprintf(msg_buf, 255, message, args);
		va_end(args);
#ifdef _KERNEL
		cmn_err(CE_WARN, msg_buf);
#else
		fprintf(std_err, msg_buf);
#endif
	}
}
#endif

/*
 * return the first IP Address associated with an interface
 */
/*ARGSUSED*/
int fr_ifpaddr(v, atype, ifptr, inp, inpmask)
int v, atype;
void *ifptr;
struct in_addr *inp, *inpmask;
{
#ifdef	USE_INET6
	struct sockaddr_in6 sin6, mask6;
#endif
	struct sockaddr_in sin, mask;

#ifndef IRE_ILL_CN
	ill_t *ill = ifptr;
	ipif_t *ipif;
#else
	s_ill_t *ill = ifptr;
#endif /* IRE_ILL_CN */

	if ((ifptr == NULL) || (ifptr == (void *)-1))
		return -1;

#ifdef	USE_INET6
	if (v == 6) {
#ifndef IRE_ILL_CN
		in6_addr_t *inp6;

		/*
		 * First is always link local.
		 */
		for (ipif = ill->ill_ipif; ipif; ipif = ipif->ipif_next) {
			inp6 = &ipif->ipif_v6lcl_addr;
			if (!IN6_IS_ADDR_LINKLOCAL(inp6) &&
			    !IN6_IS_ADDR_LOOPBACK(inp6))
				break;
		}
		if (ipif == NULL)
			return -1;

		mask6.sin6_addr = ipif->ipif_v6net_mask;
		if (atype == FRI_BROADCAST)
			sin6.sin6_addr = ipif->ipif_v6brd_addr;
		else if (atype == FRI_PEERADDR)
			sin6.sin6_addr = ipif->ipif_v6pp_dst_addr;
		else
			sin6.sin6_addr = *inp6;
#else /* IRE_ILL_CN */
		if (IN6_IS_ADDR_UNSPECIFIED(&ill->netmask.in6.sin6_addr) ||
		    IN6_IS_ADDR_UNSPECIFIED(&ill->localaddr.in6.sin6_addr)) {
			rate_limit_message(NULLADDR_RATE_LIMIT,
			   "Check pfild is running: IP#/netmask is 0 on %s.\n",
			   ill->ill_name);
			return -1;
		}
		mask6 = ill->netmask.in6;
		if (atype == FRI_BROADCAST)
			sin6 = ill->broadaddr.in6;
		else if (atype == FRI_PEERADDR)
			sin6 = ill->dstaddr.in6;
		else
			sin6 = ill->localaddr.in6;
#endif /* IRE_ILL_CN */
		return fr_ifpfillv6addr(atype, &sin6, &mask6, inp, inpmask);
	}
#endif
#ifndef IRE_ILL_CN
	ipif = ill->ill_ipif;

	mask.sin_addr.s_addr = ipif->ipif_net_mask;
	if (atype == FRI_BROADCAST)
#if SOLARIS2 < 7
		sin.sin_addr.s_addr = ipif->ipif_broadcast_addr;
#else
		sin.sin_addr.s_addr = ipif->ipif_brd_addr;
#endif
	else if (atype == FRI_PEERADDR)
		sin.sin_addr.s_addr = ipif->ipif_pp_dst_addr;
	else
#if SOLARIS2 < 7
		sin.sin_addr.s_addr = ipif->ipif_local_addr;
#else
		sin.sin_addr.s_addr = ipif->ipif_lcl_addr;
#endif

#else
	if (ill->netmask.in.sin_addr.s_addr == 0 ||
		ill->localaddr.in.sin_addr.s_addr == 0) {
		rate_limit_message(NULLADDR_RATE_LIMIT,
			"Check pfild is running: IP#/netmask is 0 on %s.\n",
			ill->ill_name);
		return -1;
	}
	mask = ill->netmask.in;
	if (atype == FRI_BROADCAST)
		sin = ill->broadaddr.in;
	else if (atype == FRI_PEERADDR)
		sin = ill->dstaddr.in;
	else
		sin = ill->localaddr.in;
#endif /* IRE_ILL_CN */
	return fr_ifpfillv4addr(atype, &sin, &mask, inp, inpmask);
}



#ifdef IRE_ILL_CN
/* ARGSUSED */
#endif
void fr_resolvdest(fdp, v)
frdest_t *fdp;
int v;
{
#ifndef IRE_ILL_CN
	ipif_t *ipif;
	ill_t *ill;
	ire_t *ire;

	ire = NULL;

	if (*fdp->fd_ifname) {
		ill = get_unit(fdp->fd_ifname, v);
		if (ill == NULL)
			ire = (ire_t *)-1;
		else if (((ipif = ill->ill_ipif) != NULL) && (v == 4)) {
#if SOLARIS2 > 5
			ire = ire_ctable_lookup(ipif->ipif_local_addr, 0,
						IRE_LOCAL, NULL, NULL,
						MATCH_IRE_TYPE);
#else
			ire = ire_lookup_myaddr(ipif->ipif_local_addr);
#endif
			if (ire == NULL)
				ire = (ire_t *)-1;
		}
#ifdef	USE_INET6
		else if (((ipif = ill->ill_ipif) != NULL) && (v == 6)) {
			ire = ire_ctable_lookup_v6(&ipif->ipif_v6lcl_addr, 0,
						   IRE_LOCAL, NULL, NULL,
						   MATCH_IRE_TYPE);
			if (ire == NULL)
				ire = (ire_t *)-1;
		}
#endif
	}
	fdp->fd_ifp = (struct ifnet *)ire;
#else
#endif /*IRE_ILL_CN */
}


u_32_t fr_newisn(fin)
fr_info_t *fin;
{
	static int iss_seq_off = 0;
	u_char hash[16];
	u_32_t newiss;
	MD5_CTX ctx;

	/*
	 * Compute the base value of the ISS.  It is a hash
	 * of (saddr, sport, daddr, dport, secret).
	 */
	MD5Init(&ctx);

	MD5Update(&ctx, (u_char *) &fin->fin_fi.fi_src,
		  sizeof(fin->fin_fi.fi_src));
	MD5Update(&ctx, (u_char *) &fin->fin_fi.fi_dst,
		  sizeof(fin->fin_fi.fi_dst));
	MD5Update(&ctx, (u_char *) &fin->fin_dat, sizeof(fin->fin_dat));

	MD5Update(&ctx, ipf_iss_secret, sizeof(ipf_iss_secret));

	MD5Final(hash, &ctx);

	bcopy(hash, &newiss, sizeof(newiss));

	/*
	 * Now increment our "timer", and add it in to
	 * the computed value.
	 *
	 * XXX Use `addin'?
	 * XXX TCP_ISSINCR too large to use?
	 */
	iss_seq_off += 0x00010000;
	newiss += iss_seq_off;
	return newiss;
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_nextipid                                                 */
/* Returns:     int - 0 == success, -1 == error (packet should be droppped) */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* Returns the next IPv4 ID to use for this packet.                         */
/* ------------------------------------------------------------------------ */
INLINE u_short fr_nextipid(fin)
fr_info_t *fin;
{
	static u_short ipid = 0;
	ipstate_t *is;
	nat_t *nat;
	u_short id;

	MUTEX_ENTER(&ipf_rw);
	if (fin->fin_state != NULL) {
		is = fin->fin_state;
		id = (u_short)(is->is_pkts[(fin->fin_rev << 1) + 1] & 0xffff);
	} else if (fin->fin_nat != NULL) {
		nat = fin->fin_nat;
		id = (u_short)(nat->nat_pkts[fin->fin_out] & 0xffff);
	} else
		id = ipid++;
	MUTEX_EXIT(&ipf_rw);

	return id;
}


#ifndef IPFILTER_CKSUM
/* ARGSUSED */
#endif
INLINE void fr_checkv4sum(fin)
fr_info_t *fin;
{
#ifdef IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
#endif
}


#ifdef USE_INET6
/* ARGSUSED */
INLINE void fr_checkv6sum(fin)
fr_info_t *fin;
{
# ifdef IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
# endif
}
#endif /* USE_INET6 */
