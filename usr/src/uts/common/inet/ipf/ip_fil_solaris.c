/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(lint)
static const char sccsid[] = "@(#)ip_fil_solaris.c	1.7 07/22/06 (C) 1993-2000 Darren Reed";
static const char rcsid[] = "@(#)$Id: ip_fil_solaris.c,v 2.62.2.19 2005/07/13 21:40:46 darrenr Exp $";
#endif

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/cpuvar.h>
#include <sys/open.h>
#include <sys/ioctl.h>
#include <sys/filio.h>
#include <sys/systm.h>
#include <sys/strsubr.h>
#include <sys/cred.h>
#include <sys/cred_impl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/mkdev.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/dditypes.h>
#include <sys/cmn_err.h>
#include <sys/zone.h>
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
#include "netinet/ip_compat.h"
#ifdef	USE_INET6
# include <netinet/icmp6.h>
#endif
#include "netinet/ip_fil.h"
#include "netinet/ip_nat.h"
#include "netinet/ip_frag.h"
#include "netinet/ip_state.h"
#include "netinet/ip_auth.h"
#include "netinet/ip_proxy.h"
#include "netinet/ipf_stack.h"
#ifdef	IPFILTER_LOOKUP
# include "netinet/ip_lookup.h"
#endif
#include <inet/ip_ire.h>

#include <sys/md5.h>
#include <sys/neti.h>

static	int	frzerostats __P((caddr_t, ipf_stack_t *));
static	int	fr_setipfloopback __P((int, ipf_stack_t *));
static	int	fr_enableipf __P((ipf_stack_t *, netstack_t *, int));
static	int	fr_send_ip __P((fr_info_t *fin, mblk_t *m, mblk_t **mp));
static	int	ipf_nic_event_v4 __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_nic_event_v6 __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook4_out __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook4_in __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook4_loop_out __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook4_loop_in __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook4 __P((hook_data_t, int, int, netstack_t *));
static	int	ipf_hook6_out __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook6_in __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook6_loop_out __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int	ipf_hook6_loop_in __P((hook_event_token_t, hook_data_t,
    netstack_t *));
static	int     ipf_hook6 __P((hook_data_t, int, int, netstack_t *));
extern	int	ipf_geniter __P((ipftoken_t *, ipfgeniter_t *, ipf_stack_t *));
extern	int	ipf_frruleiter __P((void *, int, void *, ipf_stack_t *));

#if SOLARIS2 < 10
#if SOLARIS2 >= 7
u_int		*ip_ttl_ptr = NULL;
u_int		*ip_mtudisc = NULL;
# if SOLARIS2 >= 8
int		*ip_forwarding = NULL;
u_int		*ip6_forwarding = NULL;
# else
u_int		*ip_forwarding = NULL;
# endif
#else
u_long		*ip_ttl_ptr = NULL;
u_long		*ip_mtudisc = NULL;
u_long		*ip_forwarding = NULL;
#endif
#endif


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
int ipldetach(ifs)
ipf_stack_t *ifs;
{

	ASSERT(rw_read_locked(&ifs->ifs_ipf_global.ipf_lk) == 0);

#if SOLARIS2 < 10

	if (ifs->ifs_fr_control_forwarding & 2) {
		if (ip_forwarding != NULL)
			*ip_forwarding = 0;
#if SOLARIS2 >= 8
		if (ip6_forwarding != NULL)
			*ip6_forwarding = 0;
#endif
	}
#endif

	/*
	 * This lock needs to be dropped around the net_unregister_hook calls
	 * because we can deadlock here with:
	 * W(ipf_global)->R(hook_family)->W(hei_lock) (this code path) vs
	 * R(hook_family)->R(hei_lock)->R(ipf_global) (active hook running)
	 */
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	/*
	 * Remove IPv6 Hooks
	 */
	if (ifs->ifs_ipf_ipv6 != NULL) {
		if (ifs->ifs_hook6_physical_in) {
			ifs->ifs_hook6_physical_in = (net_unregister_hook(ifs->ifs_ipf_ipv6,
			    NH_PHYSICAL_IN, &ifs->ifs_ipfhook6_in) != 0);
		}
		if (ifs->ifs_hook6_physical_out) {
			ifs->ifs_hook6_physical_out =
			    (net_unregister_hook(ifs->ifs_ipf_ipv6,
			    NH_PHYSICAL_OUT, &ifs->ifs_ipfhook6_out) != 0);
		}
		if (ifs->ifs_hook6_nic_events) {
			ifs->ifs_hook6_nic_events =
			    (net_unregister_hook(ifs->ifs_ipf_ipv6,
			    NH_NIC_EVENTS, &ifs->ifs_ipfhook_nicevents) != 0);
		}
		if (ifs->ifs_hook6_loopback_in) {
			ifs->ifs_hook6_loopback_in =
			    (net_unregister_hook(ifs->ifs_ipf_ipv6,
			    NH_LOOPBACK_IN, &ifs->ifs_ipfhook6_loop_in) != 0);
		}
		if (ifs->ifs_hook6_loopback_out) {
			ifs->ifs_hook6_loopback_out =
			    (net_unregister_hook(ifs->ifs_ipf_ipv6,
			    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook6_loop_out) != 0);
		}

		if (net_release(ifs->ifs_ipf_ipv6) != 0)
			goto detach_failed;
		ifs->ifs_ipf_ipv6 = NULL;
        }

	/*
	 * Remove IPv4 Hooks
	 */
	if (ifs->ifs_ipf_ipv4 != NULL) {
		if (ifs->ifs_hook4_physical_in) {
			ifs->ifs_hook4_physical_in =
			    (net_unregister_hook(ifs->ifs_ipf_ipv4,
			    NH_PHYSICAL_IN, &ifs->ifs_ipfhook4_in) != 0);
		}
		if (ifs->ifs_hook4_physical_out) {
			ifs->ifs_hook4_physical_out =
			    (net_unregister_hook(ifs->ifs_ipf_ipv4,
			    NH_PHYSICAL_OUT, &ifs->ifs_ipfhook4_out) != 0);
		}
		if (ifs->ifs_hook4_nic_events) {
			ifs->ifs_hook4_nic_events =
			    (net_unregister_hook(ifs->ifs_ipf_ipv4,
			    NH_NIC_EVENTS, &ifs->ifs_ipfhook_nicevents) != 0);
		}
		if (ifs->ifs_hook4_loopback_in) {
			ifs->ifs_hook4_loopback_in =
			    (net_unregister_hook(ifs->ifs_ipf_ipv4,
			    NH_LOOPBACK_IN, &ifs->ifs_ipfhook4_loop_in) != 0);
		}
		if (ifs->ifs_hook4_loopback_out) {
			ifs->ifs_hook4_loopback_out =
			    (net_unregister_hook(ifs->ifs_ipf_ipv4,
			    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook4_loop_out) != 0);
		}

		if (net_release(ifs->ifs_ipf_ipv4) != 0)
			goto detach_failed;
		ifs->ifs_ipf_ipv4 = NULL;
	}

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "ipldetach()\n");
#endif

	WRITE_ENTER(&ifs->ifs_ipf_global);
	fr_deinitialise(ifs);

	(void) frflush(IPL_LOGIPF, 0, FR_INQUE|FR_OUTQUE|FR_INACTIVE, ifs);
	(void) frflush(IPL_LOGIPF, 0, FR_INQUE|FR_OUTQUE, ifs);

	if (ifs->ifs_ipf_locks_done == 1) {
		MUTEX_DESTROY(&ifs->ifs_ipf_timeoutlock);
		MUTEX_DESTROY(&ifs->ifs_ipf_rw);
		RW_DESTROY(&ifs->ifs_ipf_tokens);
		RW_DESTROY(&ifs->ifs_ipf_ipidfrag);
		ifs->ifs_ipf_locks_done = 0;
	}

	if (ifs->ifs_hook4_physical_in || ifs->ifs_hook4_physical_out || ifs->ifs_hook4_nic_events ||
	    ifs->ifs_hook4_loopback_in || ifs->ifs_hook4_loopback_out || ifs->ifs_hook6_nic_events ||
	    ifs->ifs_hook6_physical_in || ifs->ifs_hook6_physical_out || ifs->ifs_hook6_loopback_in ||
	    ifs->ifs_hook6_loopback_out)
		return -1;

	return 0;

detach_failed:
	WRITE_ENTER(&ifs->ifs_ipf_global);
	return -1;
}

int iplattach(ifs, ns)
ipf_stack_t *ifs;
netstack_t *ns;
{
#if SOLARIS2 < 10
	int i;
#endif

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplattach()\n");
#endif

	ASSERT(rw_read_locked(&ifs->ifs_ipf_global.ipf_lk) == 0);
	ifs->ifs_fr_flags = IPF_LOGGING;
#ifdef _KERNEL
	ifs->ifs_fr_update_ipid = 0;
#else
	ifs->ifs_fr_update_ipid = 1;
#endif
	ifs->ifs_fr_minttl = 4;
	ifs->ifs_fr_icmpminfragmtu = 68;
#if defined(IPFILTER_DEFAULT_BLOCK)
	ifs->ifs_fr_pass = FR_BLOCK|FR_NOMATCH;
#else
	ifs->ifs_fr_pass = (IPF_DEFAULT_PASS)|FR_NOMATCH;
#endif

	MUTEX_INIT(&ifs->ifs_ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ifs->ifs_ipf_timeoutlock, "ipf timeout lock mutex");
	RWLOCK_INIT(&ifs->ifs_ipf_ipidfrag, "ipf IP NAT-Frag rwlock");
	RWLOCK_INIT(&ifs->ifs_ipf_tokens, "ipf token rwlock");
	ifs->ifs_ipf_locks_done = 1;

	if (fr_initialise(ifs) < 0)
		return -1;

	HOOK_INIT(&ifs->ifs_ipfhook_nicevents, ipf_nic_event_v4,
		  "ipfilter_hook_nicevents");
	HOOK_INIT(&ifs->ifs_ipfhook4_in, ipf_hook4_in, "ipfilter_hook_in");
	HOOK_INIT(&ifs->ifs_ipfhook4_out, ipf_hook4_out, "ipfilter_hook_out");
	HOOK_INIT(&ifs->ifs_ipfhook4_loop_in, ipf_hook4_in,
	    "ipfilter_hook_loop_in");
	HOOK_INIT(&ifs->ifs_ipfhook4_loop_out, ipf_hook4_out,
	    "ipfilter_hook_loop_out");

	/*
	 * If we hold this lock over all of the net_register_hook calls, we
	 * can cause a deadlock to occur with the following lock ordering:
	 * W(ipf_global)->R(hook_family)->W(hei_lock) (this code path) vs
	 * R(hook_family)->R(hei_lock)->R(ipf_global) (packet path)
	 */
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	/*
	 * Add IPv4 hooks
	 */
	ifs->ifs_ipf_ipv4 = net_lookup_impl(NHF_INET, ns);
	if (ifs->ifs_ipf_ipv4 == NULL)
		goto hookup_failed;

	ifs->ifs_hook4_nic_events = (net_register_hook(ifs->ifs_ipf_ipv4,
	    NH_NIC_EVENTS, &ifs->ifs_ipfhook_nicevents) == 0);
	if (!ifs->ifs_hook4_nic_events)
		goto hookup_failed;

	ifs->ifs_hook4_physical_in = (net_register_hook(ifs->ifs_ipf_ipv4,
	    NH_PHYSICAL_IN, &ifs->ifs_ipfhook4_in) == 0);
	if (!ifs->ifs_hook4_physical_in)
		goto hookup_failed;

	ifs->ifs_hook4_physical_out = (net_register_hook(ifs->ifs_ipf_ipv4,
	    NH_PHYSICAL_OUT, &ifs->ifs_ipfhook4_out) == 0);
	if (!ifs->ifs_hook4_physical_out)
		goto hookup_failed;

	if (ifs->ifs_ipf_loopback) {
		ifs->ifs_hook4_loopback_in =
		    (net_register_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook4_loop_in) == 0);
		if (!ifs->ifs_hook4_loopback_in)
			goto hookup_failed;

		ifs->ifs_hook4_loopback_out =
		    (net_register_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook4_loop_out) == 0);
		if (!ifs->ifs_hook4_loopback_out)
			goto hookup_failed;
	}
	/*
	 * Add IPv6 hooks
	 */
	ifs->ifs_ipf_ipv6 = net_lookup_impl(NHF_INET6, ns);
	if (ifs->ifs_ipf_ipv6 == NULL)
		goto hookup_failed;

	HOOK_INIT(&ifs->ifs_ipfhook6_in, ipf_hook6_in, "ipfilter_hook_in");
	HOOK_INIT(&ifs->ifs_ipfhook6_out, ipf_hook6_out, "ipfilter_hook_out");
	HOOK_INIT(&ifs->ifs_ipfhook6_loop_in, ipf_hook6_in,
	    "ipfilter_hook_loop_in");
	HOOK_INIT(&ifs->ifs_ipfhook6_loop_out, ipf_hook6_out,
	    "ipfilter_hook_loop_out");

	HOOK_INIT(&ifs->ifs_ipfhook_nicevents, ipf_nic_event_v6,
		  "ipfilter_hook_nicevents");
	ifs->ifs_hook6_nic_events = (net_register_hook(ifs->ifs_ipf_ipv6,
	    NH_NIC_EVENTS, &ifs->ifs_ipfhook_nicevents) == 0);
	if (!ifs->ifs_hook6_nic_events)
		goto hookup_failed;

	ifs->ifs_hook6_physical_in = (net_register_hook(ifs->ifs_ipf_ipv6,
	    NH_PHYSICAL_IN, &ifs->ifs_ipfhook6_in) == 0);
	if (!ifs->ifs_hook6_physical_in)
		goto hookup_failed;

	ifs->ifs_hook6_physical_out = (net_register_hook(ifs->ifs_ipf_ipv6,
	    NH_PHYSICAL_OUT, &ifs->ifs_ipfhook6_out) == 0);
	if (!ifs->ifs_hook6_physical_out)
		goto hookup_failed;

	if (ifs->ifs_ipf_loopback) {
		ifs->ifs_hook6_loopback_in =
		    (net_register_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook6_loop_in) == 0);
		if (!ifs->ifs_hook6_loopback_in)
			goto hookup_failed;

		ifs->ifs_hook6_loopback_out =
		    (net_register_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook6_loop_out) == 0);
		if (!ifs->ifs_hook6_loopback_out)
			goto hookup_failed;
	}

	/*
	 * Reacquire ipf_global, now it is safe.
	 */
	WRITE_ENTER(&ifs->ifs_ipf_global);

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

#if SOLARIS2 <= 8
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
#endif

	if (ifs->ifs_fr_control_forwarding & 1) {
		if (ip_forwarding != NULL)
			*ip_forwarding = 1;
#if SOLARIS2 >= 8
		if (ip6_forwarding != NULL)
			*ip6_forwarding = 1;
#endif
	}

#endif

	return 0;
hookup_failed:
	WRITE_ENTER(&ifs->ifs_ipf_global);
	return -1;
}

static	int	fr_setipfloopback(set, ifs)
int set;
ipf_stack_t *ifs;
{
	if (ifs->ifs_ipf_ipv4 == NULL || ifs->ifs_ipf_ipv6 == NULL)
		return EFAULT;

	if (set && !ifs->ifs_ipf_loopback) {
		ifs->ifs_ipf_loopback = 1;

		ifs->ifs_hook4_loopback_in =
		    (net_register_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook4_loop_in) == 0);
		if (!ifs->ifs_hook4_loopback_in)
			return EINVAL;

		ifs->ifs_hook4_loopback_out =
		    (net_register_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook4_loop_out) == 0);
		if (!ifs->ifs_hook4_loopback_out)
			return EINVAL;

		ifs->ifs_hook6_loopback_in =
		    (net_register_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook6_loop_in) == 0);
		if (!ifs->ifs_hook6_loopback_in)
			return EINVAL;

		ifs->ifs_hook6_loopback_out =
		    (net_register_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook6_loop_out) == 0);
		if (!ifs->ifs_hook6_loopback_out)
			return EINVAL;

	} else if (!set && ifs->ifs_ipf_loopback) {
		ifs->ifs_ipf_loopback = 0;

		ifs->ifs_hook4_loopback_in =
		    (net_unregister_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook4_loop_in) != 0);
		if (ifs->ifs_hook4_loopback_in)
			return EBUSY;

		ifs->ifs_hook4_loopback_out =
		    (net_unregister_hook(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook4_loop_out) != 0);
		if (ifs->ifs_hook4_loopback_out)
			return EBUSY;

		ifs->ifs_hook6_loopback_in =
		    (net_unregister_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_IN, &ifs->ifs_ipfhook6_loop_in) != 0);
		if (ifs->ifs_hook6_loopback_in)
			return EBUSY;

		ifs->ifs_hook6_loopback_out =
		    (net_unregister_hook(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_OUT, &ifs->ifs_ipfhook6_loop_out) != 0);
		if (ifs->ifs_hook6_loopback_out)
			return EBUSY;
	}
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
	netstack_t *ns;
	ipf_stack_t *ifs;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplioctl(%x,%x,%x,%d,%x,%d)\n",
		dev, cmd, data, mode, cp, rp);
#endif
	unit = getminor(dev);
	if (IPL_LOGMAX < unit)
		return ENXIO;

	ns = netstack_find_by_cred(cp);
	ASSERT(ns != NULL);
	ifs = ns->netstack_ipf;
	ASSERT(ifs != NULL);

	if (ifs->ifs_fr_running <= 0) {
		if (unit != IPL_LOGIPF) {
			netstack_rele(ifs->ifs_netstack);
			return EIO;
		}
		if (cmd != SIOCIPFGETNEXT && cmd != SIOCIPFGET &&
		    cmd != SIOCIPFSET && cmd != SIOCFRENB &&
		    cmd != SIOCGETFS && cmd != SIOCGETFF) {
			netstack_rele(ifs->ifs_netstack);
			return EIO;
		}
	}

	READ_ENTER(&ifs->ifs_ipf_global);

	error = fr_ioctlswitch(unit, (caddr_t)data, cmd, mode, cp->cr_uid, curproc, ifs);
	if (error != -1) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		netstack_rele(ifs->ifs_netstack);
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

			RWLOCK_EXIT(&ifs->ifs_ipf_global);
			WRITE_ENTER(&ifs->ifs_ipf_global);
			error = fr_enableipf(ifs, ns, enable);
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
		error = fr_ipftune(cmd, (void *)data, ifs);
		break;
	case SIOCSETFF :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&ifs->ifs_fr_flags,
			       sizeof(ifs->ifs_fr_flags));
			if (error != 0)
				error = EFAULT;
		}
		break;
	case SIOCIPFLP :
		error = COPYIN((caddr_t)data, (caddr_t)&tmp,
			       sizeof(tmp));
		if (error != 0)
			error = EFAULT;
		else
			error = fr_setipfloopback(tmp, ifs);
		break;
	case SIOCGETFF :
		error = COPYOUT((caddr_t)&ifs->ifs_fr_flags, (caddr_t)data,
			       sizeof(ifs->ifs_fr_flags));
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
					  ifs->ifs_fr_active, 1, ifs);
		break;
	case SIOCINIFR :
	case SIOCRMIFR :
	case SIOCADIFR :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = frrequest(unit, cmd, (caddr_t)data,
					  1 - ifs->ifs_fr_active, 1, ifs);
		break;
	case SIOCSWAPA :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			WRITE_ENTER(&ifs->ifs_ipf_mutex);
			error = COPYOUT((caddr_t)&ifs->ifs_fr_active,
					(caddr_t)data,
					sizeof(ifs->ifs_fr_active));
			if (error != 0)
				error = EFAULT;
			else
				ifs->ifs_fr_active = 1 - ifs->ifs_fr_active;
			RWLOCK_EXIT(&ifs->ifs_ipf_mutex);
		}
		break;
	case SIOCGETFS :
		fr_getstat(&fio, ifs);
		error = fr_outobj((void *)data, &fio, IPFOBJ_IPFSTAT);
		break;
	case SIOCFRZST :
		if (!(mode & FWRITE))
			error = EPERM;
		else
			error = fr_zerostats((caddr_t)data, ifs);
		break;
	case	SIOCIPFFL :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data, (caddr_t)&tmp,
				       sizeof(tmp));
			if (!error) {
				tmp = frflush(unit, 4, tmp, ifs);
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
				tmp = frflush(unit, 6, tmp, ifs);
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
			ifs->ifs_fr_state_lock = tmp;
			ifs->ifs_fr_nat_lock = tmp;
			ifs->ifs_fr_frag_lock = tmp;
			ifs->ifs_fr_auth_lock = tmp;
		} else
			error = EFAULT;
	break;
#ifdef	IPFILTER_LOG
	case	SIOCIPFFB :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			tmp = ipflog_clear(unit, ifs);
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
			RWLOCK_EXIT(&ifs->ifs_ipf_global);
			WRITE_ENTER(&ifs->ifs_ipf_global);

			frsync(IPFSYNC_RESYNC, 0, NULL, NULL, ifs);
			fr_natifpsync(IPFSYNC_RESYNC, NULL, NULL, ifs);
			fr_nataddrsync(NULL, NULL, ifs);
			fr_statesync(IPFSYNC_RESYNC, 0, NULL, NULL, ifs);
			error = 0;
		}
		break;
	case SIOCGFRST :
		error = fr_outobj((void *)data, fr_fragstats(ifs),
				  IPFOBJ_FRAGSTAT);
		break;
	case FIONREAD :
#ifdef	IPFILTER_LOG
		tmp = (int)ifs->ifs_iplused[IPL_LOGIPF];

		error = COPYOUT((caddr_t)&tmp, (caddr_t)data, sizeof(tmp));
		if (error != 0)
			error = EFAULT;
#endif
		break;
	case SIOCIPFITER :
		error = ipf_frruleiter((caddr_t)data, cp->cr_uid, curproc, ifs);
		break;

	case SIOCGENITER :
		error = ipf_genericiter((caddr_t)data, cp->cr_uid, curproc, ifs);
		break;

	case SIOCIPFDELTOK :
		(void)BCOPYIN((caddr_t)data, (caddr_t)&tmp, sizeof(tmp));
		error = ipf_deltoken(tmp, cp->cr_uid, curproc, ifs);
		break;

	default :
		cmn_err(CE_NOTE, "Unknown: cmd 0x%x data %p", cmd, (void *)data);
		error = EINVAL;
		break;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_global);
	netstack_rele(ifs->ifs_netstack);
	return error;
}


static int fr_enableipf(ifs, ns, enable)
ipf_stack_t *ifs;
netstack_t *ns;
int enable;
{
	int error;

	if (!enable) {
		error = ipldetach(ifs);
		if (error == 0)
			ifs->ifs_fr_running = -1;
		return (error);
	}

	if (ifs->ifs_fr_running > 0)
		return (0);

	error = iplattach(ifs, ns);
	if (error == 0) {
		if (ifs->ifs_fr_timer_id == NULL) {
			int hz = drv_usectohz(500000);

			ifs->ifs_fr_timer_id = timeout(fr_slowtimer,
						    (void *)ifs, hz);
		}
		ifs->ifs_fr_running = 1;
	} else {
		(void) ipldetach(ifs);
	}
	return (error);
}


phy_if_t get_unit(name, v, ifs)
char *name;
int v;
ipf_stack_t *ifs;
{
	net_data_t nif;
 
  	if (v == 4)
 		nif = ifs->ifs_ipf_ipv4;
  	else if (v == 6)
 		nif = ifs->ifs_ipf_ipv6;
  	else
 		return 0;

	nif->netd_netstack = ifs->ifs_netstack;

 	return (net_phylookup(nif, name));
}

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
	netstack_t *ns;
	ipf_stack_t *ifs;
	int ret;

	ns = netstack_find_by_cred(cp);
	ASSERT(ns != NULL);
	ifs = ns->netstack_ipf;
	ASSERT(ifs != NULL);

# ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplread(%x,%x,%x)\n", dev, uio, cp);
# endif

	if (ifs->ifs_fr_running < 1) {
		netstack_rele(ifs->ifs_netstack);
		return EIO;
	}

# ifdef	IPFILTER_SYNC
	if (getminor(dev) == IPL_LOGSYNC) {
		netstack_rele(ifs->ifs_netstack);
		return ipfsync_read(uio);
	}
# endif

	ret = ipflog_read(getminor(dev), uio, ifs);
	netstack_rele(ifs->ifs_netstack);
	return ret;
}
#endif /* IPFILTER_LOG */


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
	netstack_t *ns;
	ipf_stack_t *ifs;

	ns = netstack_find_by_cred(cp);
	ASSERT(ns != NULL);
	ifs = ns->netstack_ipf;
	ASSERT(ifs != NULL);

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplwrite(%x,%x,%x)\n", dev, uio, cp);
#endif

	if (ifs->ifs_fr_running < 1) {
		netstack_rele(ifs->ifs_netstack);
		return EIO;
	}

#ifdef	IPFILTER_SYNC
	if (getminor(dev) == IPL_LOGSYNC)
		return ipfsync_write(uio);
#endif /* IPFILTER_SYNC */
	dev = dev;	/* LINT */
	uio = uio;	/* LINT */
	cp = cp;	/* LINT */
	netstack_rele(ifs->ifs_netstack);
	return ENXIO;
}


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
	ip = (ip_t *)m->b_rptr;
	bzero((char *)ip, hlen);
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

	ip->ip_v = fin->fin_v;
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
		ip->ip_src.s_addr = fin->fin_daddr;
		ip->ip_dst.s_addr = fin->fin_saddr;
		ip->ip_id = fr_nextipid(fin);
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_TCP;
		ip->ip_len = sizeof(*ip) + sizeof(*tcp);
		ip->ip_tos = fin->fin_ip->ip_tos;
		tcp2->th_sum = fr_cksum(m, ip, IPPROTO_TCP, tcp2);
	}
	return fr_send_ip(fin, m, &m);
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
/*ARGSUSED*/
static int fr_send_ip(fin, m, mpp)
fr_info_t *fin;
mblk_t *m, **mpp;
{
	qpktinfo_t qpi, *qpip;
	fr_info_t fnew;
	ip_t *ip;
	int i, hlen;
	ipf_stack_t *ifs = fin->fin_ifs;

	ip = (ip_t *)m->b_rptr;
	bzero((char *)&fnew, sizeof(fnew));

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		ip6_t *ip6;

		ip6 = (ip6_t *)ip;
		ip6->ip6_vfc = 0x60;
		ip6->ip6_hlim = 127;
		fnew.fin_v = 6;
		hlen = sizeof(*ip6);
		fnew.fin_plen = ntohs(ip6->ip6_plen) + hlen;
	} else
#endif
	{
		fnew.fin_v = 4;
#if SOLARIS2 >= 10
		ip->ip_ttl = 255;
		if (net_getpmtuenabled(ifs->ifs_ipf_ipv4) == 1)
			ip->ip_off = htons(IP_DF);
#else
		if (ip_ttl_ptr != NULL)
			ip->ip_ttl = (u_char)(*ip_ttl_ptr);
		else
			ip->ip_ttl = 63;
		if (ip_mtudisc != NULL)
			ip->ip_off = htons(*ip_mtudisc ? IP_DF : 0);
		else
			ip->ip_off = htons(IP_DF);
#endif
		/*
		 * The dance with byte order and ip_len/ip_off is because in
		 * fr_fastroute, it expects them to be in host byte order but
		 * ipf_cksum expects them to be in network byte order.
		 */
		ip->ip_len = htons(ip->ip_len);
		ip->ip_sum = ipf_cksum((u_short *)ip, sizeof(*ip));
		ip->ip_len = ntohs(ip->ip_len);
		ip->ip_off = ntohs(ip->ip_off);
		hlen = sizeof(*ip);
		fnew.fin_plen = ip->ip_len;
	}

	qpip = fin->fin_qpi;
	qpi.qpi_off = 0;
	qpi.qpi_ill = qpip->qpi_ill;
	qpi.qpi_m = m;
	qpi.qpi_data = ip;
	fnew.fin_qpi = &qpi;
	fnew.fin_ifp = fin->fin_ifp;
	fnew.fin_flx = FI_NOCKSUM;
	fnew.fin_m = m;
	fnew.fin_ip = ip;
	fnew.fin_mp = mpp;
	fnew.fin_hlen = hlen;
	fnew.fin_dp = (char *)ip + hlen;
	fnew.fin_ifs = fin->fin_ifs;
	(void) fr_makefrip(hlen, ip, &fnew);

	i = fr_fastroute(m, mpp, &fnew, NULL);
	return i;
}


int fr_send_icmp_err(type, fin, dst)
int type;
fr_info_t *fin;
int dst;
{
	struct in_addr dst4;
	struct icmp *icmp;
	qpktinfo_t *qpi;
	int hlen, code;
	phy_if_t phy;
	u_short sz;
#ifdef	USE_INET6
	mblk_t *mb;
#endif
	mblk_t *m;
#ifdef	USE_INET6
	ip6_t *ip6;
#endif
	ip_t *ip;
	ipf_stack_t *ifs = fin->fin_ifs;

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

	qpi = fin->fin_qpi;

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
	ip = (ip_t *)m->b_rptr;
	ip->ip_v = fin->fin_v;
	icmp = (struct icmp *)(m->b_rptr + hlen);
	icmp->icmp_type = type & 0xff;
	icmp->icmp_code = code & 0xff;
	phy = (phy_if_t)qpi->qpi_ill; 
	if (type == ICMP_UNREACH && (phy != 0) && 
	    fin->fin_icode == ICMP_UNREACH_NEEDFRAG)
		icmp->icmp_nextmtu = net_getmtu(ifs->ifs_ipf_ipv4, phy,0 );

#ifdef	USE_INET6
	if (fin->fin_v == 6) {
		struct in6_addr dst6;
		int csz;

		if (dst == 0) {
			ipf_stack_t *ifs = fin->fin_ifs;

			if (fr_ifpaddr(6, FRI_NORMAL, (void *)phy,
				       (void *)&dst6, NULL, ifs) == -1) {
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
		ip->ip_hl = sizeof(*ip) >> 2;
		ip->ip_p = IPPROTO_ICMP;
		ip->ip_id = fin->fin_ip->ip_id;
		ip->ip_tos = fin->fin_ip->ip_tos;
		ip->ip_len = (u_short)sz;
		if (dst == 0) {
			ipf_stack_t *ifs = fin->fin_ifs;

			if (fr_ifpaddr(4, FRI_NORMAL, (void *)phy,
				       (void *)&dst4, NULL, ifs) == -1) {
				FREE_MB_T(m);
				return -1;
			}
		} else {
			dst4 = fin->fin_dst;
		}
		ip->ip_src = dst4;
		ip->ip_dst = fin->fin_src;
		bcopy((char *)fin->fin_ip, (char *)&icmp->icmp_ip,
		      sizeof(*fin->fin_ip));
		bcopy((char *)fin->fin_ip + fin->fin_hlen,
		      (char *)&icmp->icmp_ip + sizeof(*fin->fin_ip), 8);
		icmp->icmp_ip.ip_len = htons(icmp->icmp_ip.ip_len);
		icmp->icmp_ip.ip_off = htons(icmp->icmp_ip.ip_off);
		icmp->icmp_cksum = ipf_cksum((u_short *)icmp,
					     sz - sizeof(ip_t));
	}

	/*
	 * Need to exit out of these so we don't recursively call rw_enter
	 * from fr_qout.
	 */
	return fr_send_ip(fin, m, &m);
}

#include <sys/time.h>
#include <sys/varargs.h>

#ifndef _KERNEL
#include <stdio.h>
#endif

#define	NULLADDR_RATE_LIMIT 10	/* 10 seconds */


/*
 * Print out warning message at rate-limited speed.
 */
static void rate_limit_message(ipf_stack_t *ifs,
			       int rate, const char *message, ...)
{
	static time_t last_time = 0;
	time_t now;
	va_list args;
	char msg_buf[256];
	int  need_printed = 0;

	now = ddi_get_time();

	/* make sure, no multiple entries */
	ASSERT(MUTEX_NOT_HELD(&(ifs->ifs_ipf_rw.ipf_lk)));
	MUTEX_ENTER(&ifs->ifs_ipf_rw);
	if (now - last_time >= rate) {
		need_printed = 1;
		last_time = now;
	}
	MUTEX_EXIT(&ifs->ifs_ipf_rw);

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

/*
 * return the first IP Address associated with an interface
 */
/*ARGSUSED*/
int fr_ifpaddr(v, atype, ifptr, inp, inpmask, ifs)
int v, atype;
void *ifptr;
struct in_addr  *inp, *inpmask;
ipf_stack_t *ifs;
{
	struct sockaddr_in6 v6addr[2];
	struct sockaddr_in v4addr[2];
	net_ifaddr_t type[2];
	net_data_t net_data;
	phy_if_t phyif;
	void *array;

	switch (v)
	{
	case 4:
		net_data = ifs->ifs_ipf_ipv4;
		array = v4addr;
		break;
	case 6:
		net_data = ifs->ifs_ipf_ipv6;
		array = v6addr;
		break;
	default:
		net_data = NULL;
		break;
	}

	if (net_data == NULL)
		return -1;

	phyif = (phy_if_t)ifptr;

	switch (atype)
	{
	case FRI_PEERADDR :
		type[0] = NA_PEER;
		break;

	case FRI_BROADCAST :
		type[0] = NA_BROADCAST;
		break;

	default :
		type[0] = NA_ADDRESS;
		break;
	}

	type[1] = NA_NETMASK;

	if (net_getlifaddr(net_data, phyif, 0, 2, type, array) < 0)
		return -1;

	if (v == 6) {
		return fr_ifpfillv6addr(atype, &v6addr[0], &v6addr[1],
					inp, inpmask);
	}
	return fr_ifpfillv4addr(atype, &v4addr[0], &v4addr[1], inp, inpmask);
}


u_32_t fr_newisn(fin)
fr_info_t *fin;
{
	static int iss_seq_off = 0;
	u_char hash[16];
	u_32_t newiss;
	MD5_CTX ctx;
	ipf_stack_t *ifs = fin->fin_ifs;

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

	MD5Update(&ctx, ifs->ifs_ipf_iss_secret, sizeof(ifs->ifs_ipf_iss_secret));

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
u_short fr_nextipid(fin)
fr_info_t *fin;
{
	static u_short ipid = 0;
	ipstate_t *is;
	nat_t *nat;
	u_short id;
	ipf_stack_t *ifs = fin->fin_ifs;

	MUTEX_ENTER(&ifs->ifs_ipf_rw);
	if (fin->fin_state != NULL) {
		is = fin->fin_state;
		id = (u_short)(is->is_pkts[(fin->fin_rev << 1) + 1] & 0xffff);
	} else if (fin->fin_nat != NULL) {
		nat = fin->fin_nat;
		id = (u_short)(nat->nat_pkts[fin->fin_out] & 0xffff);
	} else
		id = ipid++;
	MUTEX_EXIT(&ifs->ifs_ipf_rw);

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
# ifndef IPFILTER_CKSUM
/* ARGSUSED */
# endif
INLINE void fr_checkv6sum(fin)
fr_info_t *fin;
{
# ifdef IPFILTER_CKSUM
	if (fr_checkl4sum(fin) == -1)
		fin->fin_flx |= FI_BAD;
# endif
}
#endif /* USE_INET6 */


#if (SOLARIS2 < 7)
void fr_slowtimer()
#else
/*ARGSUSED*/
void fr_slowtimer __P((void *arg))
#endif
{
	ipf_stack_t *ifs = arg;

	READ_ENTER(&ifs->ifs_ipf_global);
	if (ifs->ifs_fr_running != 1) {
		ifs->ifs_fr_timer_id = NULL;
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return;
	}
	ipf_expiretokens(ifs);
	fr_fragexpire(ifs);
	fr_timeoutstate(ifs);
	fr_natexpire(ifs);
	fr_authexpire(ifs);
	ifs->ifs_fr_ticks++;
	if (ifs->ifs_fr_running == 1)
		ifs->ifs_fr_timer_id = timeout(fr_slowtimer, arg,
		    drv_usectohz(500000));
	else
		ifs->ifs_fr_timer_id = NULL;
	RWLOCK_EXIT(&ifs->ifs_ipf_global);
}


/* ------------------------------------------------------------------------ */
/* Function:    fr_pullup                                                   */
/* Returns:     NULL == pullup failed, else pointer to protocol header      */
/* Parameters:  m(I)   - pointer to buffer where data packet starts         */
/*              fin(I) - pointer to packet information                      */
/*              len(I) - number of bytes to pullup                          */
/*                                                                          */
/* Attempt to move at least len bytes (from the start of the buffer) into a */
/* single buffer for ease of access.  Operating system native functions are */
/* used to manage buffers - if necessary.  If the entire packet ends up in  */
/* a single buffer, set the FI_COALESCE flag even though fr_coalesce() has  */
/* not been called.  Both fin_ip and fin_dp are updated before exiting _IF_ */
/* and ONLY if the pullup succeeds.                                         */
/*                                                                          */
/* We assume that 'min' is a pointer to a buffer that is part of the chain  */
/* of buffers that starts at *fin->fin_mp.                                  */
/* ------------------------------------------------------------------------ */
void *fr_pullup(min, fin, len)
mb_t *min;
fr_info_t *fin;
int len;
{
	qpktinfo_t *qpi = fin->fin_qpi;
	int out = fin->fin_out, dpoff, ipoff;
	mb_t *m = min, *m1, *m2;
	char *ip;
	uint32_t start, stuff, end, value, flags;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (m == NULL)
		return NULL;

	ip = (char *)fin->fin_ip;
	if ((fin->fin_flx & FI_COALESCE) != 0)
		return ip;

	ipoff = fin->fin_ipoff;
	if (fin->fin_dp != NULL)
		dpoff = (char *)fin->fin_dp - (char *)ip;
	else
		dpoff = 0;

	if (M_LEN(m) < len) {

		/*
		 * pfil_precheck ensures the IP header is on a 32bit
		 * aligned address so simply fail if that isn't currently
		 * the case (should never happen).
		 */
		int inc = 0;

		if (ipoff > 0) {
			if ((ipoff & 3) != 0) {
				inc = 4 - (ipoff & 3);
				if (m->b_rptr - inc >= m->b_datap->db_base)
					m->b_rptr -= inc;
				else
					inc = 0;
			}
		}

		/*
		 * XXX This is here as a work around for a bug with DEBUG
		 * XXX Solaris kernels.  The problem is b_prev is used by IP
		 * XXX code as a way to stash the phyint_index for a packet,
		 * XXX this doesn't get reset by IP but freeb does an ASSERT()
		 * XXX for both of these to be NULL.  See 6442390.
		 */
		m1 = m;
		m2 = m->b_prev;

		do {
			m1->b_next = NULL;
			m1->b_prev = NULL;
			m1 = m1->b_cont;
		} while (m1);

		/*
		 * Need to preserve checksum information by copying them
		 * to newmp which heads the pulluped message.
		 */
		hcksum_retrieve(m, NULL, NULL, &start, &stuff, &end,
		    &value, &flags);

		if (pullupmsg(m, len + ipoff + inc) == 0) {
			ATOMIC_INCL(ifs->ifs_frstats[out].fr_pull[1]);
			FREE_MB_T(*fin->fin_mp);
			*fin->fin_mp = NULL;
			fin->fin_m = NULL;
			fin->fin_ip = NULL;
			fin->fin_dp = NULL;
			qpi->qpi_data = NULL;
			return NULL;
		}

		(void) hcksum_assoc(m, NULL, NULL, start, stuff, end,
		    value, flags, 0);

		m->b_prev = m2;
		m->b_rptr += inc;
		fin->fin_m = m;
		ip = MTOD(m, char *) + ipoff;
		qpi->qpi_data = ip;
	}

	ATOMIC_INCL(ifs->ifs_frstats[out].fr_pull[0]);
	fin->fin_ip = (ip_t *)ip;
	if (fin->fin_dp != NULL)
		fin->fin_dp = (char *)fin->fin_ip + dpoff;

	if (len == fin->fin_plen)
		fin->fin_flx |= FI_COALESCE;
	return ip;
}


/*
 * Function:	fr_verifysrc
 * Returns:	int (really boolean)
 * Parameters:	fin - packet information
 *
 * Check whether the packet has a valid source address for the interface on
 * which the packet arrived, implementing the "fr_chksrc" feature.
 * Returns true iff the packet's source address is valid.
 */
int fr_verifysrc(fin)
fr_info_t *fin;
{
	net_data_t net_data_p;
	phy_if_t phy_ifdata_routeto;
	struct sockaddr	sin;
	ipf_stack_t *ifs = fin->fin_ifs;

	if (fin->fin_v == 4) { 
		net_data_p = ifs->ifs_ipf_ipv4;
	} else if (fin->fin_v == 6) { 
		net_data_p = ifs->ifs_ipf_ipv6;
	} else { 
		return (0); 
	}

	/* Get the index corresponding to the if name */
	sin.sa_family = (fin->fin_v == 4) ? AF_INET : AF_INET6;
	bcopy(&fin->fin_saddr, &sin.sa_data, sizeof (struct in_addr));
	phy_ifdata_routeto = net_routeto(net_data_p, &sin);

	return (((phy_if_t)fin->fin_ifp == phy_ifdata_routeto) ? 1 : 0); 
}


/*
 * Function:	fr_fastroute
 * Returns:	 0: success;
 *		-1: failed
 * Parameters:
 *	mb: the message block where ip head starts
 *	mpp: the pointer to the pointer of the orignal
 *		packet message
 *	fin: packet information
 *	fdp: destination interface information
 *	if it is NULL, no interface information provided.
 *
 * This function is for fastroute/to/dup-to rules. It calls
 * pfil_make_lay2_packet to search route, make lay-2 header
 * ,and identify output queue for the IP packet.
 * The destination address depends on the following conditions:
 * 1: for fastroute rule, fdp is passed in as NULL, so the
 *	destination address is the IP Packet's destination address
 * 2: for to/dup-to rule, if an ip address is specified after
 *	the interface name, this address is the as destination
 *	address. Otherwise IP Packet's destination address is used
 */
int fr_fastroute(mb, mpp, fin, fdp)
mblk_t *mb, **mpp;
fr_info_t *fin;
frdest_t *fdp;
{
        net_data_t net_data_p;
	net_inject_t inj_data;
	mblk_t *mp = NULL;
	frentry_t *fr = fin->fin_fr;
	qpktinfo_t *qpi;
	ip_t *ip;

	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct sockaddr *sinp;
	ipf_stack_t *ifs = fin->fin_ifs;
#ifndef	sparc
	u_short __iplen, __ipoff;
#endif

	if (fin->fin_v == 4) {
		net_data_p = ifs->ifs_ipf_ipv4;
	} else if (fin->fin_v == 6) {
		net_data_p = ifs->ifs_ipf_ipv6;
	} else {
		return (-1);
	}

	ip = fin->fin_ip;
	qpi = fin->fin_qpi;

	/*
	 * If this is a duplicate mblk then we want ip to point at that
	 * data, not the original, if and only if it is already pointing at
	 * the current mblk data.
	 *
	 * Otherwise, if it's not a duplicate, and we're not already pointing
	 * at the current mblk data, then we want to ensure that the data
	 * points at ip.
	 */

	if ((ip == (ip_t *)qpi->qpi_m->b_rptr) && (qpi->qpi_m != mb)) {
		ip = (ip_t *)mb->b_rptr;
	} else if ((qpi->qpi_m == mb) && (ip != (ip_t *)qpi->qpi_m->b_rptr)) {
		qpi->qpi_m->b_rptr = (uchar_t *)ip;
		qpi->qpi_off = 0;
	}

	/*
	 * If there is another M_PROTO, we don't want it
	 */
	if (*mpp != mb) {
		mp = unlinkb(*mpp);
		freeb(*mpp);
		*mpp = mp;
	}

	sinp = (struct sockaddr *)&inj_data.ni_addr;
	sin = (struct sockaddr_in *)sinp;
	sin6 = (struct sockaddr_in6 *)sinp;
	bzero((char *)&inj_data.ni_addr, sizeof (inj_data.ni_addr));
	inj_data.ni_addr.ss_family = (fin->fin_v == 4) ? AF_INET : AF_INET6;
	inj_data.ni_packet = mb;

	/*
	 * In case we're here due to "to <if>" being used with
	 * "keep state", check that we're going in the correct
	 * direction.
	 */
	if (fdp != NULL) {
		if ((fr != NULL) && (fdp->fd_ifp != NULL) &&
			(fin->fin_rev != 0) && (fdp == &fr->fr_tif))
			goto bad_fastroute;
		inj_data.ni_physical = (phy_if_t)fdp->fd_ifp;
		if (fin->fin_v == 4) {
			sin->sin_addr = fdp->fd_ip;
		} else {
			sin6->sin6_addr = fdp->fd_ip6.in6;
		}
	} else {
		if (fin->fin_v == 4) {
			sin->sin_addr = ip->ip_dst;
		} else {
			sin6->sin6_addr = ((ip6_t *)ip)->ip6_dst;
		}
		inj_data.ni_physical = net_routeto(net_data_p, sinp);
	}

	/*
	 * Clear the hardware checksum flags from packets that we are doing
	 * input processing on as leaving them set will cause the outgoing
	 * NIC (if it supports hardware checksum) to calculate them anew,
	 * using the old (correct) checksums as the pseudo value to start
	 * from.
	 */
	if (fin->fin_out == 0) {
		DB_CKSUMFLAGS(mb) = 0;
	}

	*mpp = mb;

	if (fin->fin_out == 0) {
		void *saveifp;
		u_32_t pass;

		saveifp = fin->fin_ifp;
		fin->fin_ifp = (void *)inj_data.ni_physical;
		fin->fin_flx &= ~FI_STATE;
		fin->fin_out = 1;
		(void) fr_acctpkt(fin, &pass);
		fin->fin_fr = NULL;
		if (!fr || !(fr->fr_flags & FR_RETMASK))
			(void) fr_checkstate(fin, &pass);
		if (fr_checknatout(fin, NULL) == -1)
			goto bad_fastroute;
		fin->fin_out = 0;
		fin->fin_ifp = saveifp;

		if (fin->fin_nat != NULL)
			fr_natderef((nat_t **)&fin->fin_nat, ifs);
	}
#ifndef	sparc
	if (fin->fin_v == 4) {
		__iplen = (u_short)ip->ip_len,
		__ipoff = (u_short)ip->ip_off;

		ip->ip_len = htons(__iplen);
		ip->ip_off = htons(__ipoff);
	}
#endif

	if (net_data_p) {
		if (net_inject(net_data_p, NI_DIRECT_OUT, &inj_data) < 0) {
			return (-1);
		}
	}

	ifs->ifs_fr_frouteok[0]++;
	return 0;
bad_fastroute:
	freemsg(mb);
	ifs->ifs_fr_frouteok[1]++;
	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook_out                                                */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_out(hook_event_token_t token, hook_data_t info, netstack_t *ns)
{
	return ipf_hook4(info, 1, 0, ns);
}
/*ARGSUSED*/
int ipf_hook6_out(hook_event_token_t token, hook_data_t info, netstack_t *ns)
{
	return ipf_hook6(info, 1, 0, ns);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook_in                                                 */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_in(hook_event_token_t token, hook_data_t info, netstack_t *ns)
{
	return ipf_hook4(info, 0, 0, ns);
}
/*ARGSUSED*/
int ipf_hook6_in(hook_event_token_t token, hook_data_t info, netstack_t *ns)
{
	return ipf_hook6(info, 0, 0, ns);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook_loop_out                                           */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_loop_out(hook_event_token_t token, hook_data_t info,
    netstack_t *ns)
{
	return ipf_hook4(info, 1, FI_NOCKSUM, ns);
}
/*ARGSUSED*/
int ipf_hook6_loop_out(hook_event_token_t token, hook_data_t info,
    netstack_t *ns)
{
	return ipf_hook6(info, 1, FI_NOCKSUM, ns);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook_loop_in                                            */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_loop_in(hook_event_token_t token, hook_data_t info,
    netstack_t *ns)
{
	return ipf_hook4(info, 0, FI_NOCKSUM, ns);
}
/*ARGSUSED*/
int ipf_hook6_loop_in(hook_event_token_t token, hook_data_t info,
    netstack_t *ns)
{
	return ipf_hook6(info, 0, FI_NOCKSUM, ns);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook                                                    */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  info(I)      - pointer to hook information for firewalling  */
/*              out(I)       - whether packet is going in or out            */
/*              loopback(I)  - whether packet is a loopback packet or not   */
/*                                                                          */
/* Stepping stone function between the IP mainline and IPFilter.  Extracts  */
/* parameters out of the info structure and forms them up to be useful for  */
/* calling ipfilter.                                                        */
/* ------------------------------------------------------------------------ */
int ipf_hook4(hook_data_t info, int out, int loopback, netstack_t *ns)
{
	hook_pkt_event_t *fw;
	int rval, hlen;
	qpktinfo_t qpi;
	u_short swap;
	phy_if_t phy; 
	ip_t *ip;

	fw = (hook_pkt_event_t *)info;

	ASSERT(fw != NULL);
	phy = (out == 0) ? fw->hpe_ifp : fw->hpe_ofp;

	ip = fw->hpe_hdr;
	swap = ntohs(ip->ip_len);
	ip->ip_len = swap;
	swap = ntohs(ip->ip_off);
	ip->ip_off = swap;
	hlen = IPH_HDR_LENGTH(ip);

	qpi.qpi_m = fw->hpe_mb;
	qpi.qpi_data = fw->hpe_hdr;
	qpi.qpi_off = (char *)qpi.qpi_data - (char *)fw->hpe_mb->b_rptr;
	qpi.qpi_ill = (void *)phy;
	qpi.qpi_flags = fw->hpe_flags & (HPE_MULTICAST|HPE_BROADCAST);
	if (qpi.qpi_flags)
		qpi.qpi_flags |= FI_MBCAST;
	qpi.qpi_flags |= loopback;

	rval = fr_check(fw->hpe_hdr, hlen, qpi.qpi_ill, out,
	    &qpi, fw->hpe_mp, ns->netstack_ipf);

	/* For fastroute cases, fr_check returns 0 with mp set to NULL */
	if (rval == 0 && *(fw->hpe_mp) == NULL)
		rval = 1;

	/* Notify IP the packet mblk_t and IP header pointers. */
	fw->hpe_mb = qpi.qpi_m;
	fw->hpe_hdr = qpi.qpi_data;
	if (rval == 0) {
		ip = qpi.qpi_data;
		swap = ntohs(ip->ip_len);
		ip->ip_len = swap;
		swap = ntohs(ip->ip_off);
		ip->ip_off = swap;
	}
	return rval;

}
int ipf_hook6(hook_data_t info, int out, int loopback, netstack_t *ns)
{
	hook_pkt_event_t *fw;
	int rval, hlen;
	qpktinfo_t qpi;
	phy_if_t phy; 

	fw = (hook_pkt_event_t *)info;

	ASSERT(fw != NULL);
	phy = (out == 0) ? fw->hpe_ifp : fw->hpe_ofp;

	hlen = sizeof (ip6_t);

	qpi.qpi_m = fw->hpe_mb;
	qpi.qpi_data = fw->hpe_hdr;
	qpi.qpi_off = (char *)qpi.qpi_data - (char *)fw->hpe_mb->b_rptr;
	qpi.qpi_ill = (void *)phy;
	qpi.qpi_flags = fw->hpe_flags & (HPE_MULTICAST|HPE_BROADCAST);
	if (qpi.qpi_flags)
		qpi.qpi_flags |= FI_MBCAST;
	qpi.qpi_flags |= loopback;

	rval = fr_check(fw->hpe_hdr, hlen, qpi.qpi_ill, out,
	    &qpi, fw->hpe_mp, ns->netstack_ipf);

	/* For fastroute cases, fr_check returns 0 with mp set to NULL */
	if (rval == 0 && *(fw->hpe_mp) == NULL)
		rval = 1;

	/* Notify IP the packet mblk_t and IP header pointers. */
	fw->hpe_mb = qpi.qpi_m;
	fw->hpe_hdr = qpi.qpi_data;
	return rval;

}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nic_event_v4                                            */
/* Returns:     int - 0 == no problems encountered                          */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to information about a NIC event     */
/*                                                                          */
/* Function to receive asynchronous NIC events from IP                      */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_nic_event_v4(hook_event_token_t event, hook_data_t info,
    netstack_t *ns)
{
	struct sockaddr_in *sin;
	hook_nic_event_t *hn;
	ipf_stack_t *ifs = ns->netstack_ipf;

	hn = (hook_nic_event_t *)info;

	switch (hn->hne_event)
	{
	case NE_PLUMB :
		frsync(IPFSYNC_NEWIFP, 4, (void *)hn->hne_nic, hn->hne_data,
		    ifs);
		fr_natifpsync(IPFSYNC_NEWIFP, (void *)hn->hne_nic,
			      hn->hne_data, ifs);
		fr_statesync(IPFSYNC_NEWIFP, 4, (void *)hn->hne_nic,
			     hn->hne_data, ifs);
		break;

	case NE_UNPLUMB :
		frsync(IPFSYNC_OLDIFP, 4, (void *)hn->hne_nic, NULL, ifs);
		fr_natifpsync(IPFSYNC_OLDIFP, (void *)hn->hne_nic, NULL, ifs);
		fr_statesync(IPFSYNC_OLDIFP, 4, (void *)hn->hne_nic, NULL, ifs);
		break;

	case NE_ADDRESS_CHANGE :
		/*
		 * We only respond to events for logical interface 0 because
		 * IPFilter only uses the first address given to a network
		 * interface.  We check for hne_lif==1 because the netinfo
		 * code maps adds 1 to the lif number so that it can return
		 * 0 to indicate "no more lifs" when walking them.
		 */
		if (hn->hne_lif == 1) {
			frsync(IPFSYNC_RESYNC, 4, (void *)hn->hne_nic, NULL,
			    ifs);
			sin = hn->hne_data;
			fr_nataddrsync((void *)hn->hne_nic, &sin->sin_addr,
			    ifs);
		}
		break;

	default :
		break;
	}

	return 0;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_nic_event_v6                                            */
/* Returns:     int - 0 == no problems encountered                          */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to information about a NIC event     */
/*                                                                          */
/* Function to receive asynchronous NIC events from IP                      */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_nic_event_v6(hook_event_token_t event, hook_data_t info,
    netstack_t *ns)
{
	hook_nic_event_t *hn;
	ipf_stack_t *ifs = ns->netstack_ipf;

	hn = (hook_nic_event_t *)info;

	switch (hn->hne_event)
	{
	case NE_PLUMB :
		frsync(IPFSYNC_NEWIFP, 6, (void *)hn->hne_nic, hn->hne_data, ifs);
		fr_statesync(IPFSYNC_NEWIFP, 6, (void *)hn->hne_nic,
			     hn->hne_data, ifs);
		break;

	case NE_UNPLUMB :
		frsync(IPFSYNC_OLDIFP, 6, (void *)hn->hne_nic, NULL, ifs);
		fr_statesync(IPFSYNC_OLDIFP, 6, (void *)hn->hne_nic, NULL, ifs);
		break;

	case NE_ADDRESS_CHANGE :
		break;
	default :
		break;
	}

	return 0;
}
