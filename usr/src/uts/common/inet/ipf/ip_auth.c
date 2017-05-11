/*
 * Copyright (C) 1998-2003 by Darren Reed & Guido van Rooij.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
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
#include <sys/file.h>
#if !defined(_KERNEL)
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
#else
# include <sys/ioctl.h>
#endif
#if !defined(linux)
# include <sys/protosw.h>
#endif
#include <sys/socket.h>
#if defined(_KERNEL)
# include <sys/systm.h>
# if !defined(__SVR4) && !defined(__svr4__) && !defined(linux)
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
# include <sys/neti.h>
#endif
#if (_BSDI_VERSION >= 199802) || (__FreeBSD_version >= 400000)
# include <sys/queue.h>
#endif
#if defined(__NetBSD__) || defined(__OpenBSD__) || defined(bsdi)
# include <machine/cpu.h>
#endif
#if defined(_KERNEL) && defined(__NetBSD__) && (__NetBSD_Version__ >= 104000000)
# include <sys/proc.h>
#endif
#include <net/if.h>
#ifdef sun
# include <net/af.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if !defined(_KERNEL) && !defined(__osf__) && !defined(__sgi)
# define	KERNEL
# define	_KERNEL
# define	NOT_KERNEL
#endif
#if !defined(linux)
# include <netinet/ip_var.h>
#endif
#ifdef	NOT_KERNEL
# undef	_KERNEL
# undef	KERNEL
#endif
#include <netinet/tcp.h>
#if defined(IRIX) && (IRIX < 60516) /* IRIX < 6 */
extern struct ifqueue   ipintrq;		/* ip packet input queue */
#else
# if !defined(__hpux) && !defined(linux)
#  if __FreeBSD_version >= 300000
#   include <net/if_var.h>
#   if __FreeBSD_version >= 500042
#    define IF_QFULL _IF_QFULL
#    define IF_DROP _IF_DROP
#   endif /* __FreeBSD_version >= 500042 */
#  endif
#  include <netinet/in_var.h>
#  include <netinet/tcp_fsm.h>
# endif
#endif
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "netinet/ip_compat.h"
#include <netinet/tcpip.h>
#include "netinet/ipf_stack.h"
#include "netinet/ip_fil.h"
#include "netinet/ip_auth.h"
#if !defined(MENTAT) && !defined(linux)
# include <net/netisr.h>
# ifdef __FreeBSD__
#  include <machine/cpufunc.h>
# endif
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
static const char rcsid[] = "@(#)$Id: ip_auth.c,v 2.73.2.5 2005/06/12 07:18:14 darrenr Exp $";
#endif

void fr_authderef __P((frauthent_t **));
int fr_authgeniter __P((ipftoken_t *, ipfgeniter_t *, ipf_stack_t *));


int fr_authinit(ifs)
ipf_stack_t *ifs;
{
	KMALLOCS(ifs->ifs_fr_auth, frauth_t *,
		 ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_auth));
	if (ifs->ifs_fr_auth != NULL)
		bzero((char *)ifs->ifs_fr_auth,
		      ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_auth));
	else
		return -1;

	KMALLOCS(ifs->ifs_fr_authpkts, mb_t **,
		 ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_authpkts));
	if (ifs->ifs_fr_authpkts != NULL)
		bzero((char *)ifs->ifs_fr_authpkts,
		      ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_authpkts));
	else
		return -2;

	MUTEX_INIT(&ifs->ifs_ipf_authmx, "ipf auth log mutex");
	RWLOCK_INIT(&ifs->ifs_ipf_auth, "ipf IP User-Auth rwlock");
#if defined(SOLARIS) && defined(_KERNEL)
	cv_init(&ifs->ifs_ipfauthwait, "ipf auth condvar", CV_DRIVER, NULL);
#endif
#if defined(linux) && defined(_KERNEL)
	init_waitqueue_head(&fr_authnext_linux);
#endif

	ifs->ifs_fr_auth_init = 1;

	return 0;
}


/*
 * Check if a packet has authorization.  If the packet is found to match an
 * authorization result and that would result in a feedback loop (i.e. it
 * will end up returning FR_AUTH) then return FR_BLOCK instead.
 */
frentry_t *fr_checkauth(fin, passp)
fr_info_t *fin;
u_32_t *passp;
{
	frentry_t *fr;
	frauth_t *fra;
	u_32_t pass;
	u_short id;
	ip_t *ip;
	int i;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_fr_auth_lock || !ifs->ifs_fr_authused)
		return NULL;

	ip = fin->fin_ip;
	id = ip->ip_id;

	READ_ENTER(&ifs->ifs_ipf_auth);
	for (i = ifs->ifs_fr_authstart; i != ifs->ifs_fr_authend; ) {
		/*
		 * index becomes -2 only after an SIOCAUTHW.  Check this in
		 * case the same packet gets sent again and it hasn't yet been
		 * auth'd.
		 */
		fra = ifs->ifs_fr_auth + i;
		if ((fra->fra_index == -2) && (id == fra->fra_info.fin_id) &&
		    !bcmp((char *)fin, (char *)&fra->fra_info, FI_CSIZE)) {
			/*
			 * Avoid feedback loop.
			 */
			if (!(pass = fra->fra_pass) || (FR_ISAUTH(pass)))
				pass = FR_BLOCK;
			/*
			 * Create a dummy rule for the stateful checking to
			 * use and return.  Zero out any values we don't
			 * trust from userland!
			 */
			if ((pass & FR_KEEPSTATE) || ((pass & FR_KEEPFRAG) &&
			     (fin->fin_flx & FI_FRAG))) {
				KMALLOC(fr, frentry_t *);
				if (fr) {
					bcopy((char *)fra->fra_info.fin_fr,
					      (char *)fr, sizeof(*fr));
					fr->fr_grp = NULL;
					fr->fr_ifa = fin->fin_ifp;
					fr->fr_func = NULL;
					fr->fr_ref = 1;
					fr->fr_flags = pass;
					fr->fr_ifas[1] = NULL;
					fr->fr_ifas[2] = NULL;
					fr->fr_ifas[3] = NULL;
				}
			} else
				fr = fra->fra_info.fin_fr;
			fin->fin_fr = fr;
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			WRITE_ENTER(&ifs->ifs_ipf_auth);
			if ((fr != NULL) && (fr != fra->fra_info.fin_fr)) {
				fr->fr_next = ifs->ifs_fr_authlist;
				ifs->ifs_fr_authlist = fr;
			}
			ifs->ifs_fr_authstats.fas_hits++;
			fra->fra_index = -1;
			ifs->ifs_fr_authused--;
			if (i == ifs->ifs_fr_authstart) {
				while (fra->fra_index == -1) {
					i++;
					fra++;
					if (i == ifs->ifs_fr_authsize) {
						i = 0;
						fra = ifs->ifs_fr_auth;
					}
					ifs->ifs_fr_authstart = i;
					if (i == ifs->ifs_fr_authend)
						break;
				}
				if (ifs->ifs_fr_authstart == ifs->ifs_fr_authend) {
					ifs->ifs_fr_authnext = 0;
					ifs->ifs_fr_authstart = 0;
					ifs->ifs_fr_authend = 0;
				}
			}
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			if (passp != NULL)
				*passp = pass;
			ATOMIC_INC64(ifs->ifs_fr_authstats.fas_hits);
			return fr;
		}
		i++;
		if (i == ifs->ifs_fr_authsize)
			i = 0;
	}
	ifs->ifs_fr_authstats.fas_miss++;
	RWLOCK_EXIT(&ifs->ifs_ipf_auth);
	ATOMIC_INC64(ifs->ifs_fr_authstats.fas_miss);
	return NULL;
}


/*
 * Check if we have room in the auth array to hold details for another packet.
 * If we do, store it and wake up any user programs which are waiting to
 * hear about these events.
 */
int fr_newauth(m, fin)
mb_t *m;
fr_info_t *fin;
{
#if defined(_KERNEL) && defined(MENTAT)
	qpktinfo_t *qpi = fin->fin_qpi;
#endif
	frauth_t *fra;
#if !defined(sparc) && !defined(m68k)
	ip_t *ip;
#endif
	int i;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (ifs->ifs_fr_auth_lock)
		return 0;

	WRITE_ENTER(&ifs->ifs_ipf_auth);
	if (ifs->ifs_fr_authstart > ifs->ifs_fr_authend) {
		ifs->ifs_fr_authstats.fas_nospace++;
		RWLOCK_EXIT(&ifs->ifs_ipf_auth);
		return 0;
	} else {
		if (ifs->ifs_fr_authused == ifs->ifs_fr_authsize) {
			ifs->ifs_fr_authstats.fas_nospace++;
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			return 0;
		}
	}

	ifs->ifs_fr_authstats.fas_added++;
	ifs->ifs_fr_authused++;
	i = ifs->ifs_fr_authend++;
	if (ifs->ifs_fr_authend == ifs->ifs_fr_authsize)
		ifs->ifs_fr_authend = 0;
	RWLOCK_EXIT(&ifs->ifs_ipf_auth);

	fra = ifs->ifs_fr_auth + i;
	fra->fra_index = i;
	fra->fra_pass = 0;
	fra->fra_age = ifs->ifs_fr_defaultauthage;
	bcopy((char *)fin, (char *)&fra->fra_info, sizeof(*fin));
#if !defined(sparc) && !defined(m68k)
	/*
	 * No need to copyback here as we want to undo the changes, not keep
	 * them.
	 */
	ip = fin->fin_ip;
# if defined(MENTAT) && defined(_KERNEL)
	if ((ip == (ip_t *)m->b_rptr) && (fin->fin_v == 4))
# endif
	{
		register u_short bo;

		bo = ip->ip_len;
		ip->ip_len = htons(bo);
		bo = ip->ip_off;
		ip->ip_off = htons(bo);
	}
#endif
#if defined(SOLARIS) && defined(_KERNEL)
	m->b_rptr -= qpi->qpi_off;
	ifs->ifs_fr_authpkts[i] = *(mblk_t **)fin->fin_mp;
	cv_signal(&ifs->ifs_ipfauthwait);
#else
# if defined(BSD) && !defined(sparc) && (BSD >= 199306)
	if (!fin->fin_out) {
		ip->ip_len = htons(ip->ip_len);
		ip->ip_off = htons(ip->ip_off);
	}
# endif
	ifs->ifs_fr_authpkts[i] = m;
	WAKEUP(&ifs->ifs_fr_authnext, 0);
#endif
	return 1;
}


int fr_auth_ioctl(data, cmd, mode, uid, ctx, ifs)
caddr_t data;
ioctlcmd_t cmd;
int mode,uid;
void *ctx;
ipf_stack_t *ifs;
{
	mb_t *m;
#if defined(_KERNEL) && !defined(MENTAT) && !defined(linux) && \
    (!defined(__FreeBSD_version) || (__FreeBSD_version < 501000))
	struct ifqueue *ifq;
	SPL_INT(s);
#endif
	frauth_t auth, *au = &auth, *fra;
	int i, error = 0, len;
	char *t;
	net_handle_t net_data_p;
	net_inject_t inj_data;
	int ret;

	switch (cmd)
	{
	case SIOCGENITER :
	    {
		ipftoken_t *token;
		ipfgeniter_t iter;

		error = fr_inobj(data, &iter, IPFOBJ_GENITER);
		if (error != 0)
			break;

		token = ipf_findtoken(IPFGENITER_AUTH, uid, ctx, ifs);
		if (token != NULL)
			error = fr_authgeniter(token, &iter, ifs);
		else
			error = ESRCH;
		RWLOCK_EXIT(&ifs->ifs_ipf_tokens);

		break;
	    }

	case SIOCSTLCK :
		if (!(mode & FWRITE)) {
			error = EPERM;
			break;
		}
		error = fr_lock(data, &ifs->ifs_fr_auth_lock);
		break;

	case SIOCATHST:
		ifs->ifs_fr_authstats.fas_faelist = ifs->ifs_fae_list;
		error = fr_outobj(data, &ifs->ifs_fr_authstats,
		    IPFOBJ_AUTHSTAT);
		break;

	case SIOCIPFFL:
		SPL_NET(s);
		WRITE_ENTER(&ifs->ifs_ipf_auth);
		i = fr_authflush(ifs);
		RWLOCK_EXIT(&ifs->ifs_ipf_auth);
		SPL_X(s);
		error = copyoutptr((char *)&i, data, sizeof(i));
		break;

	case SIOCAUTHW:
fr_authioctlloop:
		error = fr_inobj(data, au, IPFOBJ_FRAUTH);
		READ_ENTER(&ifs->ifs_ipf_auth);
		if ((ifs->ifs_fr_authnext != ifs->ifs_fr_authend) &&
		    ifs->ifs_fr_authpkts[ifs->ifs_fr_authnext]) {
			error = fr_outobj(data,
					  &ifs->ifs_fr_auth[ifs->ifs_fr_authnext],
					  IPFOBJ_FRAUTH);
			if (auth.fra_len != 0 && auth.fra_buf != NULL) {
				/*
				 * Copy packet contents out to user space if
				 * requested.  Bail on an error.
				 */
				m = ifs->ifs_fr_authpkts[ifs->ifs_fr_authnext];
				len = MSGDSIZE(m);
				if (len > auth.fra_len)
					len = auth.fra_len;
				auth.fra_len = len;
				for (t = auth.fra_buf; m && (len > 0); ) {
					i = MIN(M_LEN(m), len);
					error = copyoutptr(MTOD(m, char *),
							  t, i);
					len -= i;
					t += i;
					if (error != 0)
						break;
				}
			}
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			if (error != 0)
				break;
			SPL_NET(s);
			WRITE_ENTER(&ifs->ifs_ipf_auth);
			ifs->ifs_fr_authnext++;
			if (ifs->ifs_fr_authnext == ifs->ifs_fr_authsize)
				ifs->ifs_fr_authnext = 0;
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			SPL_X(s);
			return 0;
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_auth);
		/*
		 * We exit ipf_global here because a program that enters in
		 * here will have a lock on it and goto sleep having this lock.
		 * If someone were to do an 'ipf -D' the system would then
		 * deadlock.  The catch with releasing it here is that the
		 * caller of this function expects it to be held when we
		 * return so we have to reacquire it in here.
		 */
		RWLOCK_EXIT(&ifs->ifs_ipf_global);

		MUTEX_ENTER(&ifs->ifs_ipf_authmx);
#ifdef	_KERNEL
# if	SOLARIS
		error = 0;
		if (!cv_wait_sig(&ifs->ifs_ipfauthwait, &ifs->ifs_ipf_authmx.ipf_lk))
			error = EINTR;
# else /* SOLARIS */
#  ifdef __hpux
		{
		lock_t *l;

		l = get_sleep_lock(&ifs->ifs_fr_authnext);
		error = sleep(&ifs->ifs_fr_authnext, PZERO+1);
		spinunlock(l);
		}
#  else
#   ifdef __osf__
		error = mpsleep(&ifs->ifs_fr_authnext, PSUSP|PCATCH,
				"fr_authnext", 0,
				&ifs->ifs_ipf_authmx, MS_LOCK_SIMPLE);
#   else
		error = SLEEP(&ifs->ifs_fr_authnext, "fr_authnext");
#   endif /* __osf__ */
#  endif /* __hpux */
# endif /* SOLARIS */
#endif
		MUTEX_EXIT(&ifs->ifs_ipf_authmx);
		READ_ENTER(&ifs->ifs_ipf_global);
		if (error == 0) {
			READ_ENTER(&ifs->ifs_ipf_auth);
			goto fr_authioctlloop;
		}
		break;

	case SIOCAUTHR:
		error = fr_inobj(data, &auth, IPFOBJ_FRAUTH);
		if (error != 0)
			return error;
		SPL_NET(s);
		WRITE_ENTER(&ifs->ifs_ipf_auth);
		i = au->fra_index;
		fra = ifs->ifs_fr_auth + i;
		if ((i < 0) || (i >= ifs->ifs_fr_authsize) ||
		    (fra->fra_info.fin_id != au->fra_info.fin_id)) {
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			SPL_X(s);
			return ESRCH;
		}
		m = ifs->ifs_fr_authpkts[i];
		fra->fra_index = -2;
		fra->fra_pass = au->fra_pass;
		ifs->ifs_fr_authpkts[i] = NULL;
		RWLOCK_EXIT(&ifs->ifs_ipf_auth);
#ifdef	_KERNEL
		if (fra->fra_info.fin_v == 4) { 
			net_data_p = ifs->ifs_ipf_ipv4;
		} else if (fra->fra_info.fin_v == 6) { 
			net_data_p = ifs->ifs_ipf_ipv6;
		} else { 
			return (-1); 
		}

		/*
		 * We're putting the packet back on the same interface
		 * queue that it was originally seen on so that it can
		 * progress through the system properly, with the result
		 * of the auth check done.
		 */
		inj_data.ni_physical = (phy_if_t)fra->fra_info.fin_ifp;

		if ((m != NULL) && (au->fra_info.fin_out != 0)) {
# ifdef MENTAT
			inj_data.ni_packet = m;
			ret = net_inject(net_data_p, NI_QUEUE_OUT, &inj_data);

			if (ret < 0)
				ifs->ifs_fr_authstats.fas_sendfail++;
			else
				ifs->ifs_fr_authstats.fas_sendok++;
# else /* MENTAT */
#  if defined(linux) || defined(AIX)
#  else
#   if (_BSDI_VERSION >= 199802) || defined(__OpenBSD__) || \
       (defined(__sgi) && (IRIX >= 60500) || defined(AIX) || \
       (defined(__FreeBSD__) && (__FreeBSD_version >= 470102)))
			error = ip_output(m, NULL, NULL, IP_FORWARDING, NULL,
					  NULL);
#   else
			error = ip_output(m, NULL, NULL, IP_FORWARDING, NULL);
#   endif
			if (error != 0)
				ifs->ifs_fr_authstats.fas_sendfail++;
			else
				ifs->ifs_fr_authstats.fas_sendok++;
#  endif /* Linux */
# endif /* MENTAT */
		} else if (m) {
# ifdef MENTAT
			inj_data.ni_packet = m;
			ret = net_inject(net_data_p, NI_QUEUE_IN, &inj_data);
# else /* MENTAT */
#  if defined(linux) || defined(AIX)
#  else
#   if (__FreeBSD_version >= 501000)
			netisr_dispatch(NETISR_IP, m);
#   else
#    if (IRIX >= 60516)
			ifq = &((struct ifnet *)fra->fra_info.fin_ifp)->if_snd;
#    else
			ifq = &ipintrq;
#    endif
			if (IF_QFULL(ifq)) {
				IF_DROP(ifq);
				FREE_MB_T(m);
				error = ENOBUFS;
			} else {
				IF_ENQUEUE(ifq, m);
#    if IRIX < 60500
				schednetisr(NETISR_IP);
#    endif
			}
#   endif
#  endif /* Linux */
# endif /* MENTAT */
			if (error != 0)
				ifs->ifs_fr_authstats.fas_quefail++;
			else
				ifs->ifs_fr_authstats.fas_queok++;
		} else
			error = EINVAL;
# ifdef MENTAT
		if (error != 0)
			error = EINVAL;
# else /* MENTAT */
		/*
		 * If we experience an error which will result in the packet
		 * not being processed, make sure we advance to the next one.
		 */
		if (error == ENOBUFS) {
			ifs->ifs_fr_authused--;
			fra->fra_index = -1;
			fra->fra_pass = 0;
			if (i == ifs->ifs_fr_authstart) {
				while (fra->fra_index == -1) {
					i++;
					if (i == ifs->ifs_fr_authsize)
						i = 0;
					ifs->ifs_fr_authstart = i;
					if (i == ifs->ifs_fr_authend)
						break;
				}
				if (ifs->ifs_fr_authstart == ifs->ifs_fr_authend) {
					ifs->ifs_fr_authnext = 0;
					ifs->ifs_fr_authstart = 0;
					ifs->ifs_fr_authend = 0;
				}
			}
		}
# endif /* MENTAT */
#endif /* _KERNEL */
		SPL_X(s);
		break;

	default :
		error = EINVAL;
		break;
	}
	return error;
}


/*
 * Free all network buffer memory used to keep saved packets.
 */
void fr_authunload(ifs)
ipf_stack_t *ifs;
{
	register int i;
	register frauthent_t *fae, **faep;
	frentry_t *fr, **frp;
	mb_t *m;

	if (ifs->ifs_fr_auth != NULL) {
		KFREES(ifs->ifs_fr_auth,
		       ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_auth));
		ifs->ifs_fr_auth = NULL;
	}

	if (ifs->ifs_fr_authpkts != NULL) {
		for (i = 0; i < ifs->ifs_fr_authsize; i++) {
			m = ifs->ifs_fr_authpkts[i];
			if (m != NULL) {
				FREE_MB_T(m);
				ifs->ifs_fr_authpkts[i] = NULL;
			}
		}
		KFREES(ifs->ifs_fr_authpkts,
		       ifs->ifs_fr_authsize * sizeof(*ifs->ifs_fr_authpkts));
		ifs->ifs_fr_authpkts = NULL;
	}

	faep = &ifs->ifs_fae_list;
	while ((fae = *faep) != NULL) {
		*faep = fae->fae_next;
		KFREE(fae);
	}
	ifs->ifs_ipauth = NULL;

	if (ifs->ifs_fr_authlist != NULL) {
		for (frp = &ifs->ifs_fr_authlist; ((fr = *frp) != NULL); ) {
			if (fr->fr_ref == 1) {
				*frp = fr->fr_next;
				KFREE(fr);
			} else
				frp = &fr->fr_next;
		}
	}

	if (ifs->ifs_fr_auth_init == 1) {
# if defined(SOLARIS) && defined(_KERNEL)
		cv_destroy(&ifs->ifs_ipfauthwait);
# endif
		MUTEX_DESTROY(&ifs->ifs_ipf_authmx);
		RW_DESTROY(&ifs->ifs_ipf_auth);

		ifs->ifs_fr_auth_init = 0;
	}
}


/*
 * Slowly expire held auth records.  Timeouts are set
 * in expectation of this being called twice per second.
 */
void fr_authexpire(ifs)
ipf_stack_t *ifs;
{
	register int i;
	register frauth_t *fra;
	register frauthent_t *fae, **faep;
	register frentry_t *fr, **frp;
	mb_t *m;
	SPL_INT(s);

	if (ifs->ifs_fr_auth_lock)
		return;

	SPL_NET(s);
	WRITE_ENTER(&ifs->ifs_ipf_auth);
	for (i = 0, fra = ifs->ifs_fr_auth; i < ifs->ifs_fr_authsize; i++, fra++) {
		fra->fra_age--;
		if ((fra->fra_age == 0) && (m = ifs->ifs_fr_authpkts[i])) {
			FREE_MB_T(m);
			ifs->ifs_fr_authpkts[i] = NULL;
			ifs->ifs_fr_auth[i].fra_index = -1;
			ifs->ifs_fr_authstats.fas_expire++;
			ifs->ifs_fr_authused--;
		}
	}

	for (faep = &ifs->ifs_fae_list; ((fae = *faep) != NULL); ) {
		fae->fae_age--;
		if (fae->fae_age == 0) {
			*faep = fae->fae_next;
			KFREE(fae);
			ifs->ifs_fr_authstats.fas_expire++;
		} else
			faep = &fae->fae_next;
	}
	if (ifs->ifs_fae_list != NULL)
		ifs->ifs_ipauth = &ifs->ifs_fae_list->fae_fr;
	else
		ifs->ifs_ipauth = NULL;

	for (frp = &ifs->ifs_fr_authlist; ((fr = *frp) != NULL); ) {
		if (fr->fr_ref == 1) {
			*frp = fr->fr_next;
			KFREE(fr);
		} else
			frp = &fr->fr_next;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_auth);
	SPL_X(s);
}

int fr_preauthcmd(cmd, fr, frptr, ifs)
ioctlcmd_t cmd;
frentry_t *fr, **frptr;
ipf_stack_t *ifs;
{
	frauthent_t *fae, **faep;
	int error = 0;
	SPL_INT(s);

	if ((cmd != SIOCADAFR) && (cmd != SIOCRMAFR))
		return EIO;
	
	for (faep = &ifs->ifs_fae_list; ((fae = *faep) != NULL); ) {
		if (&fae->fae_fr == fr)
			break;
		else
			faep = &fae->fae_next;
	}

	if (cmd == (ioctlcmd_t)SIOCRMAFR) {
		if (fr == NULL || frptr == NULL)
			error = EINVAL;
		else if (fae == NULL)
			error = ESRCH;
		else {
			SPL_NET(s);
			WRITE_ENTER(&ifs->ifs_ipf_auth);
			*faep = fae->fae_next;
			if (ifs->ifs_ipauth == &fae->fae_fr)
				ifs->ifs_ipauth = ifs->ifs_fae_list ?
				    &ifs->ifs_fae_list->fae_fr : NULL;
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			SPL_X(s);

			KFREE(fae);
		}
	} else if (fr != NULL && frptr != NULL) {
		KMALLOC(fae, frauthent_t *);
		if (fae != NULL) {
			bcopy((char *)fr, (char *)&fae->fae_fr,
			      sizeof(*fr));
			SPL_NET(s);
			WRITE_ENTER(&ifs->ifs_ipf_auth);
			fae->fae_age = ifs->ifs_fr_defaultauthage;
			fae->fae_fr.fr_hits = 0;
			fae->fae_fr.fr_next = *frptr;
			fae->fae_ref = 1;
			*frptr = &fae->fae_fr;
			fae->fae_next = *faep;
			*faep = fae;
			ifs->ifs_ipauth = &ifs->ifs_fae_list->fae_fr;
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
			SPL_X(s);
		} else
			error = ENOMEM;
	} else
		error = EINVAL;
	return error;
}


/*
 * Flush held packets.
 * Must already be properly SPL'ed and Locked on &ipf_auth.
 *
 */
int fr_authflush(ifs)
ipf_stack_t *ifs;
{
	register int i, num_flushed;
	mb_t *m;

	if (ifs->ifs_fr_auth_lock)
		return -1;

	num_flushed = 0;

	for (i = 0 ; i < ifs->ifs_fr_authsize; i++) {
		m = ifs->ifs_fr_authpkts[i];
		if (m != NULL) {
			FREE_MB_T(m);
			ifs->ifs_fr_authpkts[i] = NULL;
			ifs->ifs_fr_auth[i].fra_index = -1;
			/* perhaps add & use a flush counter inst.*/
			ifs->ifs_fr_authstats.fas_expire++;
			ifs->ifs_fr_authused--;
			num_flushed++;
		}
	}

	ifs->ifs_fr_authstart = 0;
	ifs->ifs_fr_authend = 0;
	ifs->ifs_fr_authnext = 0;

	return num_flushed;
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_authgeniter                                              */
/* Returns:     int - 0 == success, else error                              */
/* Parameters:  token(I) - pointer to ipftoken structure                    */
/*              itp(I)   - pointer to ipfgeniter structure                  */
/*                                                                          */
/* ------------------------------------------------------------------------ */
int fr_authgeniter(token, itp, ifs)
ipftoken_t *token;
ipfgeniter_t *itp;
ipf_stack_t *ifs;
{
	frauthent_t *fae, *next, zero;
	int error;

	if (itp->igi_data == NULL)
		return EFAULT;

	if (itp->igi_type != IPFGENITER_AUTH)
		return EINVAL;

	READ_ENTER(&ifs->ifs_ipf_auth);

	/*
	 * Retrieve "previous" entry from token and find the next entry.
	 */
	fae = token->ipt_data;
	if (fae == NULL) {
		next = ifs->ifs_fae_list;
	} else {
		next = fae->fae_next;
	}

	/*
	 * If we found an entry, add reference to it and update token.
	 * Otherwise, zero out data to be returned and NULL out token.
	 */
	if (next != NULL) {
		ATOMIC_INC(next->fae_ref);
		token->ipt_data = next;
	} else {
		bzero(&zero, sizeof(zero));
		next = &zero;
		token->ipt_data = NULL;
	}

	/*
	 * Safe to release the lock now that we have a reference.
	 */
	RWLOCK_EXIT(&ifs->ifs_ipf_auth);

	/*
	 * Copy out the data and clean up references and token as needed.
	 */
	error = COPYOUT(next, itp->igi_data, sizeof(*next));
	if (error != 0)
		error = EFAULT;
	if (token->ipt_data == NULL) {
		ipf_freetoken(token, ifs);
	} else {
		if (fae != NULL) {
			WRITE_ENTER(&ifs->ifs_ipf_auth);
			fr_authderef(&fae);
			RWLOCK_EXIT(&ifs->ifs_ipf_auth);
		}
		if (next->fae_next == NULL)
			ipf_freetoken(token, ifs);
	}
	return error;
}


void fr_authderef(faep)
frauthent_t **faep;
{
	frauthent_t *fae;

	fae = *faep;
	*faep = NULL;

	fae->fae_ref--;
	if (fae->fae_ref == 0) {
		KFREE(fae);
	}
}
