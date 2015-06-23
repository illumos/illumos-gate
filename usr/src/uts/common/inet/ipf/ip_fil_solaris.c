/*
 * Copyright (C) 1993-2001, 2003 by Darren Reed.
 *
 * See the IPFILTER.LICENCE file for details on licencing.
 *
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

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
static	int	fr_enableipf __P((ipf_stack_t *, int));
static	int	fr_send_ip __P((fr_info_t *fin, mblk_t *m, mblk_t **mp));
static	int	ipf_nic_event_v4 __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_nic_event_v6 __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook __P((hook_data_t, int, int, void *));
static	int	ipf_hook4_in __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook4_out __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook4_loop_out __P((hook_event_token_t, hook_data_t,
    void *));
static	int	ipf_hook4_loop_in __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook4 __P((hook_data_t, int, int, void *));
static	int	ipf_hook6_out __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook6_in __P((hook_event_token_t, hook_data_t, void *));
static	int	ipf_hook6_loop_out __P((hook_event_token_t, hook_data_t,
    void *));
static	int	ipf_hook6_loop_in __P((hook_event_token_t, hook_data_t,
    void *));
static	int     ipf_hook6 __P((hook_data_t, int, int, void *));
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

vmem_t	*ipf_minor;	/* minor number arena */
void 	*ipf_state;	/* DDI state */

/*
 * GZ-controlled and per-zone stacks:
 *
 * For each non-global zone, we create two ipf stacks: the per-zone stack and
 * the GZ-controlled stack.  The per-zone stack can be controlled and observed
 * from inside the zone or from the global zone.  The GZ-controlled stack can
 * only be controlled and observed from the global zone (though the rules
 * still only affect that non-global zone).
 *
 * The two hooks are always arranged so that the GZ-controlled stack is always
 * "outermost" with respect to the zone.  The traffic flow then looks like
 * this:
 *
 * Inbound:
 *
 *     nic ---> [ GZ-controlled rules ] ---> [ per-zone rules ] ---> zone
 *
 * Outbound:
 *
 *     nic <--- [ GZ-controlled rules ] <--- [ per-zone rules ] <--- zone
 */

/* IPv4 hook names */
char *hook4_nicevents = 	"ipfilter_hook4_nicevents";
char *hook4_nicevents_gz = 	"ipfilter_hook4_nicevents_gz";
char *hook4_in = 		"ipfilter_hook4_in";
char *hook4_in_gz = 		"ipfilter_hook4_in_gz";
char *hook4_out = 		"ipfilter_hook4_out";
char *hook4_out_gz = 		"ipfilter_hook4_out_gz";
char *hook4_loop_in = 		"ipfilter_hook4_loop_in";
char *hook4_loop_in_gz = 	"ipfilter_hook4_loop_in_gz";
char *hook4_loop_out = 		"ipfilter_hook4_loop_out";
char *hook4_loop_out_gz = 	"ipfilter_hook4_loop_out_gz";

/* IPv6 hook names */
char *hook6_nicevents = 	"ipfilter_hook6_nicevents";
char *hook6_nicevents_gz = 	"ipfilter_hook6_nicevents_gz";
char *hook6_in = 		"ipfilter_hook6_in";
char *hook6_in_gz = 		"ipfilter_hook6_in_gz";
char *hook6_out = 		"ipfilter_hook6_out";
char *hook6_out_gz = 		"ipfilter_hook6_out_gz";
char *hook6_loop_in = 		"ipfilter_hook6_loop_in";
char *hook6_loop_in_gz = 	"ipfilter_hook6_loop_in_gz";
char *hook6_loop_out = 		"ipfilter_hook6_loop_out";
char *hook6_loop_out_gz = 	"ipfilter_hook6_loop_out_gz";

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

	ASSERT(RW_WRITE_HELD(&ifs->ifs_ipf_global.ipf_lk));

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
	 * This lock needs to be dropped around the net_hook_unregister calls
	 * because we can deadlock here with:
	 * W(ipf_global)->R(hook_family)->W(hei_lock) (this code path) vs
	 * R(hook_family)->R(hei_lock)->R(ipf_global) (active hook running)
	 */
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

#define	UNDO_HOOK(_f, _b, _e, _h)					\
	do {								\
		if (ifs->_f != NULL) {					\
			if (ifs->_b) {					\
				int tmp = net_hook_unregister(ifs->_f,	\
					   _e, ifs->_h);		\
				ifs->_b = (tmp != 0 && tmp != ENXIO);	\
				if (!ifs->_b && ifs->_h != NULL) {	\
					hook_free(ifs->_h);		\
					ifs->_h = NULL;			\
				}					\
			} else if (ifs->_h != NULL) {			\
				hook_free(ifs->_h);			\
				ifs->_h = NULL;				\
			}						\
		}							\
		_NOTE(CONSTCOND)					\
	} while (0)

	/*
	 * Remove IPv6 Hooks
	 */
	if (ifs->ifs_ipf_ipv6 != NULL) {
		UNDO_HOOK(ifs_ipf_ipv6, ifs_hook6_physical_in,
			  NH_PHYSICAL_IN, ifs_ipfhook6_in);
		UNDO_HOOK(ifs_ipf_ipv6, ifs_hook6_physical_out,
			  NH_PHYSICAL_OUT, ifs_ipfhook6_out);
		UNDO_HOOK(ifs_ipf_ipv6, ifs_hook6_nic_events,
			  NH_NIC_EVENTS, ifs_ipfhook6_nicevents);
		UNDO_HOOK(ifs_ipf_ipv6, ifs_hook6_loopback_in,
			  NH_LOOPBACK_IN, ifs_ipfhook6_loop_in);
		UNDO_HOOK(ifs_ipf_ipv6, ifs_hook6_loopback_out,
			  NH_LOOPBACK_OUT, ifs_ipfhook6_loop_out);

		if (net_protocol_release(ifs->ifs_ipf_ipv6) != 0)
			goto detach_failed;
		ifs->ifs_ipf_ipv6 = NULL;
        }

	/*
	 * Remove IPv4 Hooks
	 */
	if (ifs->ifs_ipf_ipv4 != NULL) {
		UNDO_HOOK(ifs_ipf_ipv4, ifs_hook4_physical_in,
			  NH_PHYSICAL_IN, ifs_ipfhook4_in);
		UNDO_HOOK(ifs_ipf_ipv4, ifs_hook4_physical_out,
			  NH_PHYSICAL_OUT, ifs_ipfhook4_out);
		UNDO_HOOK(ifs_ipf_ipv4, ifs_hook4_nic_events,
			  NH_NIC_EVENTS, ifs_ipfhook4_nicevents);
		UNDO_HOOK(ifs_ipf_ipv4, ifs_hook4_loopback_in,
			  NH_LOOPBACK_IN, ifs_ipfhook4_loop_in);
		UNDO_HOOK(ifs_ipf_ipv4, ifs_hook4_loopback_out,
			  NH_LOOPBACK_OUT, ifs_ipfhook4_loop_out);

		if (net_protocol_release(ifs->ifs_ipf_ipv4) != 0)
			goto detach_failed;
		ifs->ifs_ipf_ipv4 = NULL;
	}

#undef UNDO_HOOK

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

	if (ifs->ifs_hook4_physical_in || ifs->ifs_hook4_physical_out ||
	    ifs->ifs_hook4_nic_events || ifs->ifs_hook4_loopback_in ||
	    ifs->ifs_hook4_loopback_out || ifs->ifs_hook6_nic_events ||
	    ifs->ifs_hook6_physical_in || ifs->ifs_hook6_physical_out ||
	    ifs->ifs_hook6_loopback_in || ifs->ifs_hook6_loopback_out)
		return -1;

	return 0;

detach_failed:
	WRITE_ENTER(&ifs->ifs_ipf_global);
	return -1;
}

int iplattach(ifs)
ipf_stack_t *ifs;
{
#if SOLARIS2 < 10
	int i;
#endif
	netid_t id = ifs->ifs_netid;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplattach()\n");
#endif

	ASSERT(RW_WRITE_HELD(&ifs->ifs_ipf_global.ipf_lk));
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

	bzero((char *)ifs->ifs_frcache, sizeof(ifs->ifs_frcache));
	MUTEX_INIT(&ifs->ifs_ipf_rw, "ipf rw mutex");
	MUTEX_INIT(&ifs->ifs_ipf_timeoutlock, "ipf timeout lock mutex");
	RWLOCK_INIT(&ifs->ifs_ipf_ipidfrag, "ipf IP NAT-Frag rwlock");
	RWLOCK_INIT(&ifs->ifs_ipf_tokens, "ipf token rwlock");
	ifs->ifs_ipf_locks_done = 1;

	if (fr_initialise(ifs) < 0)
		return -1;

	/*
	 * For incoming packets, we want the GZ-controlled hooks to run before
	 * the per-zone hooks, regardless of what order they're are installed.
	 * See the "GZ-controlled and per-zone stacks" comment block at the top
	 * of this file.
	 */
#define HOOK_INIT_GZ_BEFORE(x, fn, n, gzn, a)				\
	HOOK_INIT(x, fn, ifs->ifs_gz_controlled ? gzn : n, ifs);	\
	(x)->h_hint = ifs->ifs_gz_controlled ? HH_BEFORE : HH_AFTER;	\
	(x)->h_hintvalue = (uintptr_t) (ifs->ifs_gz_controlled ? n : gzn);

	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook4_nicevents, ipf_nic_event_v4,
		  hook4_nicevents, hook4_nicevents_gz, ifs);
	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook4_in, ipf_hook4_in,
		  hook4_in, hook4_in_gz, ifs);
	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook4_loop_in, ipf_hook4_loop_in,
		  hook4_loop_in, hook4_loop_in_gz, ifs);

	/*
	 * For outgoing packets, we want the GZ-controlled hooks to run after
	 * the per-zone hooks, regardless of what order they're are installed.
	 * See the "GZ-controlled and per-zone stacks" comment block at the top
	 * of this file.
	 */
#define HOOK_INIT_GZ_AFTER(x, fn, n, gzn, a)				\
	HOOK_INIT(x, fn, ifs->ifs_gz_controlled ? gzn : n, ifs);	\
	(x)->h_hint = ifs->ifs_gz_controlled ? HH_AFTER : HH_BEFORE;	\
	(x)->h_hintvalue = (uintptr_t) (ifs->ifs_gz_controlled ? n : gzn);

	HOOK_INIT_GZ_AFTER(ifs->ifs_ipfhook4_out, ipf_hook4_out,
		  hook4_out, hook4_out_gz, ifs);
	HOOK_INIT_GZ_AFTER(ifs->ifs_ipfhook4_loop_out, ipf_hook4_loop_out,
		  hook4_loop_out, hook4_loop_out_gz, ifs);

	/*
	 * If we hold this lock over all of the net_hook_register calls, we
	 * can cause a deadlock to occur with the following lock ordering:
	 * W(ipf_global)->R(hook_family)->W(hei_lock) (this code path) vs
	 * R(hook_family)->R(hei_lock)->R(ipf_global) (packet path)
	 */
	RWLOCK_EXIT(&ifs->ifs_ipf_global);

	/*
	 * Add IPv4 hooks
	 */
	ifs->ifs_ipf_ipv4 = net_protocol_lookup(id, NHF_INET);
	if (ifs->ifs_ipf_ipv4 == NULL)
		goto hookup_failed;

	ifs->ifs_hook4_nic_events = (net_hook_register(ifs->ifs_ipf_ipv4,
	    NH_NIC_EVENTS, ifs->ifs_ipfhook4_nicevents) == 0);
	if (!ifs->ifs_hook4_nic_events)
		goto hookup_failed;

	ifs->ifs_hook4_physical_in = (net_hook_register(ifs->ifs_ipf_ipv4,
	    NH_PHYSICAL_IN, ifs->ifs_ipfhook4_in) == 0);
	if (!ifs->ifs_hook4_physical_in)
		goto hookup_failed;

	ifs->ifs_hook4_physical_out = (net_hook_register(ifs->ifs_ipf_ipv4,
	    NH_PHYSICAL_OUT, ifs->ifs_ipfhook4_out) == 0);
	if (!ifs->ifs_hook4_physical_out)
		goto hookup_failed;

	if (ifs->ifs_ipf_loopback) {
		ifs->ifs_hook4_loopback_in = (net_hook_register(
		    ifs->ifs_ipf_ipv4, NH_LOOPBACK_IN,
		    ifs->ifs_ipfhook4_loop_in) == 0);
		if (!ifs->ifs_hook4_loopback_in)
			goto hookup_failed;

		ifs->ifs_hook4_loopback_out = (net_hook_register(
		    ifs->ifs_ipf_ipv4, NH_LOOPBACK_OUT,
		    ifs->ifs_ipfhook4_loop_out) == 0);
		if (!ifs->ifs_hook4_loopback_out)
			goto hookup_failed;
	}

	/*
	 * Add IPv6 hooks
	 */
	ifs->ifs_ipf_ipv6 = net_protocol_lookup(id, NHF_INET6);
	if (ifs->ifs_ipf_ipv6 == NULL)
		goto hookup_failed;

	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook6_nicevents, ipf_nic_event_v6,
		  hook6_nicevents, hook6_nicevents_gz, ifs);
	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook6_in, ipf_hook6_in,
		  hook6_in, hook6_in_gz, ifs);
	HOOK_INIT_GZ_BEFORE(ifs->ifs_ipfhook6_loop_in, ipf_hook6_loop_in,
		  hook6_loop_in, hook6_loop_in_gz, ifs);
	HOOK_INIT_GZ_AFTER(ifs->ifs_ipfhook6_out, ipf_hook6_out,
		  hook6_out, hook6_out_gz, ifs);
	HOOK_INIT_GZ_AFTER(ifs->ifs_ipfhook6_loop_out, ipf_hook6_loop_out,
		  hook6_loop_out, hook6_loop_out_gz, ifs);

	ifs->ifs_hook6_nic_events = (net_hook_register(ifs->ifs_ipf_ipv6,
	    NH_NIC_EVENTS, ifs->ifs_ipfhook6_nicevents) == 0);
	if (!ifs->ifs_hook6_nic_events)
		goto hookup_failed;

	ifs->ifs_hook6_physical_in = (net_hook_register(ifs->ifs_ipf_ipv6,
	    NH_PHYSICAL_IN, ifs->ifs_ipfhook6_in) == 0);
	if (!ifs->ifs_hook6_physical_in)
		goto hookup_failed;

	ifs->ifs_hook6_physical_out = (net_hook_register(ifs->ifs_ipf_ipv6,
	    NH_PHYSICAL_OUT, ifs->ifs_ipfhook6_out) == 0);
	if (!ifs->ifs_hook6_physical_out)
		goto hookup_failed;

	if (ifs->ifs_ipf_loopback) {
		ifs->ifs_hook6_loopback_in = (net_hook_register(
		    ifs->ifs_ipf_ipv6, NH_LOOPBACK_IN,
		    ifs->ifs_ipfhook6_loop_in) == 0);
		if (!ifs->ifs_hook6_loopback_in)
			goto hookup_failed;

		ifs->ifs_hook6_loopback_out = (net_hook_register(
		    ifs->ifs_ipf_ipv6, NH_LOOPBACK_OUT,
		    ifs->ifs_ipfhook6_loop_out) == 0);
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

		ifs->ifs_hook4_loopback_in = (net_hook_register(
		    ifs->ifs_ipf_ipv4, NH_LOOPBACK_IN,
		    ifs->ifs_ipfhook4_loop_in) == 0);
		if (!ifs->ifs_hook4_loopback_in)
			return EINVAL;

		ifs->ifs_hook4_loopback_out = (net_hook_register(
		    ifs->ifs_ipf_ipv4, NH_LOOPBACK_OUT,
		    ifs->ifs_ipfhook4_loop_out) == 0);
		if (!ifs->ifs_hook4_loopback_out)
			return EINVAL;

		ifs->ifs_hook6_loopback_in = (net_hook_register(
		    ifs->ifs_ipf_ipv6, NH_LOOPBACK_IN,
		    ifs->ifs_ipfhook6_loop_in) == 0);
		if (!ifs->ifs_hook6_loopback_in)
			return EINVAL;

		ifs->ifs_hook6_loopback_out = (net_hook_register(
		    ifs->ifs_ipf_ipv6, NH_LOOPBACK_OUT,
		    ifs->ifs_ipfhook6_loop_out) == 0);
		if (!ifs->ifs_hook6_loopback_out)
			return EINVAL;

	} else if (!set && ifs->ifs_ipf_loopback) {
		ifs->ifs_ipf_loopback = 0;

		ifs->ifs_hook4_loopback_in =
		    (net_hook_unregister(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_IN, ifs->ifs_ipfhook4_loop_in) != 0);
		if (ifs->ifs_hook4_loopback_in)
			return EBUSY;

		ifs->ifs_hook4_loopback_out =
		    (net_hook_unregister(ifs->ifs_ipf_ipv4,
		    NH_LOOPBACK_OUT, ifs->ifs_ipfhook4_loop_out) != 0);
		if (ifs->ifs_hook4_loopback_out)
			return EBUSY;

		ifs->ifs_hook6_loopback_in =
		    (net_hook_unregister(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_IN, ifs->ifs_ipfhook4_loop_in) != 0);
		if (ifs->ifs_hook6_loopback_in)
			return EBUSY;

		ifs->ifs_hook6_loopback_out =
		    (net_hook_unregister(ifs->ifs_ipf_ipv6,
		    NH_LOOPBACK_OUT, ifs->ifs_ipfhook6_loop_out) != 0);
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
	ipf_stack_t *ifs;
	zoneid_t zid;
	ipf_devstate_t *isp;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplioctl(%x,%x,%x,%d,%x,%d)\n",
		dev, cmd, data, mode, cp, rp);
#endif
	unit = getminor(dev);

	isp = ddi_get_soft_state(ipf_state, unit);
	if (isp == NULL)
		return ENXIO;
	unit = isp->ipfs_minor;

	zid = crgetzoneid(cp);
	if (cmd == SIOCIPFZONESET) {
		if (zid == GLOBAL_ZONEID)
			return fr_setzoneid(isp, (caddr_t) data);
		return EACCES;
	}

        /*
	 * ipf_find_stack returns with a read lock on ifs_ipf_global
	 */
	ifs = ipf_find_stack(zid, isp);
	if (ifs == NULL)
		return ENXIO;

	if (ifs->ifs_fr_running <= 0) {
		if (unit != IPL_LOGIPF) {
			RWLOCK_EXIT(&ifs->ifs_ipf_global);
			return EIO;
		}
		if (cmd != SIOCIPFGETNEXT && cmd != SIOCIPFGET &&
		    cmd != SIOCIPFSET && cmd != SIOCFRENB &&
		    cmd != SIOCGETFS && cmd != SIOCGETFF) {
			RWLOCK_EXIT(&ifs->ifs_ipf_global);
			return EIO;
		}
	}

	if (ifs->ifs_fr_enable_active != 0) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return EBUSY;
	}

	error = fr_ioctlswitch(unit, (caddr_t)data, cmd, mode, crgetuid(cp),
			       curproc, ifs);
	if (error != -1) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
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

			/*
			 * We must recheck fr_enable_active here, since we've
			 * dropped ifs_ipf_global from R in order to get it
			 * exclusively.
			 */
			if (ifs->ifs_fr_enable_active == 0) {
				ifs->ifs_fr_enable_active = 1;
				error = fr_enableipf(ifs, enable);
				ifs->ifs_fr_enable_active = 0;
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
		error = fr_ipftune(cmd, (void *)data, ifs);
		break;
	case SIOCSETFF :
		if (!(mode & FWRITE))
			error = EPERM;
		else {
			error = COPYIN((caddr_t)data,
				       (caddr_t)&ifs->ifs_fr_flags,
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
			bzero((char *)ifs->ifs_frcache,
			    sizeof (ifs->ifs_frcache));
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
			fr_natifpsync(IPFSYNC_RESYNC, 0, NULL, NULL, ifs);
			fr_nataddrsync(0, NULL, NULL, ifs);
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
		error = ipf_frruleiter((caddr_t)data, crgetuid(cp),
				       curproc, ifs);
		break;

	case SIOCGENITER :
		error = ipf_genericiter((caddr_t)data, crgetuid(cp),
					curproc, ifs);
		break;

	case SIOCIPFDELTOK :
		error = BCOPYIN((caddr_t)data, (caddr_t)&tmp, sizeof(tmp));
		if (error != 0) {
			error = EFAULT;
		} else {
			error = ipf_deltoken(tmp, crgetuid(cp), curproc, ifs);
		}
		break;

	default :
#ifdef	IPFDEBUG
		cmn_err(CE_NOTE, "Unknown: cmd 0x%x data %p",
			cmd, (void *)data);
#endif
		error = EINVAL;
		break;
	}
	RWLOCK_EXIT(&ifs->ifs_ipf_global);
	return error;
}


static int fr_enableipf(ifs, enable)
ipf_stack_t *ifs;
int enable;
{
	int error;

	if (!enable) {
		error = ipldetach(ifs);
		if (error == 0)
			ifs->ifs_fr_running = -1;
		return error;
	}

	if (ifs->ifs_fr_running > 0)
		return 0;

	error = iplattach(ifs);
	if (error == 0) {
		if (ifs->ifs_fr_timer_id == NULL) {
			int hz = drv_usectohz(500000);

			ifs->ifs_fr_timer_id = timeout(fr_slowtimer,
						       (void *)ifs,
						       hz);
		}
		ifs->ifs_fr_running = 1;
	} else {
		(void) ipldetach(ifs);
	}
	return error;
}


phy_if_t get_unit(name, v, ifs)
char *name;
int v;
ipf_stack_t *ifs;
{
	net_handle_t nif;
 
  	if (v == 4)
 		nif = ifs->ifs_ipf_ipv4;
  	else if (v == 6)
 		nif = ifs->ifs_ipf_ipv6;
  	else
 		return 0;

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
	ipf_devstate_t *isp;
	minor_t min = getminor(*devp);
	minor_t minor;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplopen(%x,%x,%x,%x)\n", devp, flags, otype, cred);
#endif
	if (!(otype & OTYP_CHR))
		return ENXIO;

	if (IPL_LOGMAX < min)
		return ENXIO;

	minor = (minor_t)(uintptr_t)vmem_alloc(ipf_minor, 1,
	    VM_BESTFIT | VM_SLEEP);

	if (ddi_soft_state_zalloc(ipf_state, minor) != 0) {
		vmem_free(ipf_minor, (void *)(uintptr_t)minor, 1);
		return ENXIO;
	}

	*devp = makedevice(getmajor(*devp), minor);
	isp = ddi_get_soft_state(ipf_state, minor);
	VERIFY(isp != NULL);

	isp->ipfs_minor = min;
	isp->ipfs_zoneid = IPFS_ZONE_UNSET;

	return 0;
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

	if (IPL_LOGMAX < min)
		return ENXIO;

	ddi_soft_state_free(ipf_state, min);
	vmem_free(ipf_minor, (void *)(uintptr_t)min, 1);

	return 0;
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
	ipf_stack_t *ifs;
	int ret;
	minor_t unit;
	ipf_devstate_t *isp;

	unit = getminor(dev);
	isp = ddi_get_soft_state(ipf_state, unit);
	if (isp == NULL)
		return ENXIO;
	unit = isp->ipfs_minor;


        /*
	 * ipf_find_stack returns with a read lock on ifs_ipf_global
	 */
	ifs = ipf_find_stack(crgetzoneid(cp), isp);
	if (ifs == NULL)
		return ENXIO;

# ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplread(%x,%x,%x)\n", dev, uio, cp);
# endif

	if (ifs->ifs_fr_running < 1) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return EIO;
	}

# ifdef	IPFILTER_SYNC
	if (unit == IPL_LOGSYNC) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return ipfsync_read(uio);
	}
# endif

	ret = ipflog_read(unit, uio, ifs);
	RWLOCK_EXIT(&ifs->ifs_ipf_global);
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
	ipf_stack_t *ifs;
	minor_t unit;
	ipf_devstate_t *isp;

	unit = getminor(dev);
	isp = ddi_get_soft_state(ipf_state, unit);
	if (isp == NULL)
		return ENXIO;
	unit = isp->ipfs_minor;

        /*
	 * ipf_find_stack returns with a read lock on ifs_ipf_global
	 */
	ifs = ipf_find_stack(crgetzoneid(cp), isp);
	if (ifs == NULL)
		return ENXIO;

#ifdef	IPFDEBUG
	cmn_err(CE_CONT, "iplwrite(%x,%x,%x)\n", dev, uio, cp);
#endif

	if (ifs->ifs_fr_running < 1) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return EIO;
	}

#ifdef	IPFILTER_SYNC
	if (getminor(dev) == IPL_LOGSYNC) {
		RWLOCK_EXIT(&ifs->ifs_ipf_global);
		return ipfsync_write(uio);
	}
#endif /* IPFILTER_SYNC */
	dev = dev;	/* LINT */
	uio = uio;	/* LINT */
	cp = cp;	/* LINT */
	RWLOCK_EXIT(&ifs->ifs_ipf_global);
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
		ip6->ip6_src = fin->fin_dst6.in6;
		ip6->ip6_dst = fin->fin_src6.in6;
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
	fnew.fin_qfm = m;
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
	if ((code < 0) || (code >= ICMP_MAX_UNREACH))
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
			dst6 = fin->fin_dst6.in6;

		csz = sz;
		sz -= sizeof(ip6_t);
		ip6 = (ip6_t *)m->b_rptr;
		ip6->ip6_flow = ((ip6_t *)fin->fin_ip)->ip6_flow;
		ip6->ip6_plen = htons((u_short)sz);
		ip6->ip6_nxt = IPPROTO_ICMPV6;
		ip6->ip6_src = dst6;
		ip6->ip6_dst = fin->fin_src6.in6;
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

/*
 * Return the first IP Address associated with an interface
 * For IPv6, we walk through the list of logical interfaces and return
 * the address of the first one that isn't a link-local interface.
 * We can't assume that it is :1 because another link-local address
 * may have been assigned there.
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
	net_handle_t net_data;
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

	if (v == 6) {
		lif_if_t idx = 0;

		do {
			idx = net_lifgetnext(net_data, phyif, idx);
			if (net_getlifaddr(net_data, phyif, idx, 2, type,
					   array) < 0)
				return -1;
			if (!IN6_IS_ADDR_LINKLOCAL(&v6addr[0].sin6_addr) &&
			    !IN6_IS_ADDR_MULTICAST(&v6addr[0].sin6_addr))
				break;
		} while (idx != 0);

		if (idx == 0)
			return -1;

		return fr_ifpfillv6addr(atype, &v6addr[0], &v6addr[1],
					inp, inpmask);
	}

	if (net_getlifaddr(net_data, phyif, 0, 2, type, array) < 0)
		return -1;

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
	u_short id;
	ipf_stack_t *ifs = fin->fin_ifs;

	MUTEX_ENTER(&ifs->ifs_ipf_rw);
	if (fin->fin_pktnum != 0) {
		id = fin->fin_pktnum & 0xffff;
	} else {
		id = ipid++;
	}
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

	if (M_LEN(m) < len + ipoff) {

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
	net_handle_t net_data_p;
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
	phy_ifdata_routeto = net_routeto(net_data_p, &sin, NULL);

	return (((phy_if_t)fin->fin_ifp == phy_ifdata_routeto) ? 1 : 0); 
}

/*
 * Return true only if forwarding is enabled on the interface.
 */
static int
fr_forwarding_enabled(phy_if_t phyif, net_handle_t ndp)
{
	lif_if_t lif;

	for (lif = net_lifgetnext(ndp, phyif, 0); lif > 0;
	    lif = net_lifgetnext(ndp, phyif, lif)) {
		int res;
		uint64_t flags;

		res = net_getlifflags(ndp, phyif, lif, &flags);
		if (res != 0)
			return (0);
		if (flags & IFF_ROUTER)
			return (1);
	}

	return (0);
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
        net_handle_t net_data_p;
	net_inject_t *inj;
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

	/* Check the src here, fin_ifp is the src interface. */
	if (!fr_forwarding_enabled((phy_if_t)fin->fin_ifp, net_data_p))
		return (-1);

	inj = net_inject_alloc(NETINFO_VERSION);
	if (inj == NULL)
		return -1;

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

	sinp = (struct sockaddr *)&inj->ni_addr;
	sin = (struct sockaddr_in *)sinp;
	sin6 = (struct sockaddr_in6 *)sinp;
	bzero((char *)&inj->ni_addr, sizeof (inj->ni_addr));
	inj->ni_addr.ss_family = (fin->fin_v == 4) ? AF_INET : AF_INET6;
	inj->ni_packet = mb;

	/*
	 * In case we're here due to "to <if>" being used with
	 * "keep state", check that we're going in the correct
	 * direction.
	 */
	if (fdp != NULL) {
		if ((fr != NULL) && (fdp->fd_ifp != NULL) &&
			(fin->fin_rev != 0) && (fdp == &fr->fr_tif))
			goto bad_fastroute;
		inj->ni_physical = (phy_if_t)fdp->fd_ifp;
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
		inj->ni_physical = net_routeto(net_data_p, sinp, NULL);
	}

	/* we're checking the destinatation here */
	if (!fr_forwarding_enabled(inj->ni_physical, net_data_p))
		goto bad_fastroute;

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
		fin->fin_ifp = (void *)inj->ni_physical;
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
		if (net_inject(net_data_p, NI_DIRECT_OUT, inj) < 0) {
			net_inject_free(inj);
			return (-1);
		}
	}

	ifs->ifs_fr_frouteok[0]++;
	net_inject_free(inj);
	return 0;
bad_fastroute:
	net_inject_free(inj);
	freemsg(mb);
	ifs->ifs_fr_frouteok[1]++;
	return -1;
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook4_out                                               */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_out(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook(info, 1, 0, arg);
}
/*ARGSUSED*/
int ipf_hook6_out(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook6(info, 1, 0, arg);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook4_in                                                */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_in(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook(info, 0, 0, arg);
}
/*ARGSUSED*/
int ipf_hook6_in(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook6(info, 0, 0, arg);
}


/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook4_loop_out                                          */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_loop_out(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook(info, 1, FI_NOCKSUM, arg);
}
/*ARGSUSED*/
int ipf_hook6_loop_out(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook6(info, 1, FI_NOCKSUM, arg);
}

/* ------------------------------------------------------------------------ */
/* Function:    ipf_hook4_loop_in                                           */
/* Returns:     int - 0 == packet ok, else problem, free packet if not done */
/* Parameters:  event(I)     - pointer to event                             */
/*              info(I)      - pointer to hook information for firewalling  */
/*                                                                          */
/* Calling ipf_hook.                                                        */
/* ------------------------------------------------------------------------ */
/*ARGSUSED*/
int ipf_hook4_loop_in(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook(info, 0, FI_NOCKSUM, arg);
}
/*ARGSUSED*/
int ipf_hook6_loop_in(hook_event_token_t token, hook_data_t info, void *arg)
{
	return ipf_hook6(info, 0, FI_NOCKSUM, arg);
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
int ipf_hook(hook_data_t info, int out, int loopback, void *arg)
{
	hook_pkt_event_t *fw;
	ipf_stack_t *ifs;
	qpktinfo_t qpi;
	int rval, hlen;
	u_short swap;
	phy_if_t phy; 
	ip_t *ip;

	ifs = arg;
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
	    &qpi, fw->hpe_mp, ifs);

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
int ipf_hook6(hook_data_t info, int out, int loopback, void *arg)
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
	    &qpi, fw->hpe_mp, arg);

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
int ipf_nic_event_v4(hook_event_token_t event, hook_data_t info, void *arg)
{
	struct sockaddr_in *sin;
	hook_nic_event_t *hn;
	ipf_stack_t *ifs = arg;
	void *new_ifp = NULL;

	if (ifs->ifs_fr_running <= 0)
		return (0);

	hn = (hook_nic_event_t *)info;

	switch (hn->hne_event)
	{
	case NE_PLUMB :
		frsync(IPFSYNC_NEWIFP, 4, (void *)hn->hne_nic, hn->hne_data,
		       ifs);
		fr_natifpsync(IPFSYNC_NEWIFP, 4, (void *)hn->hne_nic,
			      hn->hne_data, ifs);
		fr_statesync(IPFSYNC_NEWIFP, 4, (void *)hn->hne_nic,
			     hn->hne_data, ifs);
		break;

	case NE_UNPLUMB :
		frsync(IPFSYNC_OLDIFP, 4, (void *)hn->hne_nic, NULL, ifs);
		fr_natifpsync(IPFSYNC_OLDIFP, 4, (void *)hn->hne_nic, NULL,
			      ifs);
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
			fr_nataddrsync(4, (void *)hn->hne_nic, &sin->sin_addr,
			    ifs);
		}
		break;

#if SOLARIS2 >= 10
	case NE_IFINDEX_CHANGE :
		WRITE_ENTER(&ifs->ifs_ipf_mutex);

		if (hn->hne_data != NULL) {
			/*
			 * The netinfo passes interface index as int (hne_data should be
			 * handled as a pointer to int), which is always 32bit. We need to
			 * convert it to void pointer here, since interfaces are
			 * represented as pointers to void in IPF. The pointers are 64 bits
			 * long on 64bit platforms. Doing something like
			 *	(void *)((int) x)
			 * will throw warning:
			 *   "cast to pointer from integer of different size"
			 * during 64bit compilation.
			 *
			 * The line below uses (size_t) to typecast int to
			 * size_t, which might be 64bit/32bit (depending
			 * on architecture). Once we have proper 64bit/32bit
			 * type (size_t), we can safely convert it to void pointer.
			 */
			new_ifp = (void *)(size_t)*((int *)hn->hne_data);
			fr_ifindexsync((void *)hn->hne_nic, new_ifp, ifs);
			fr_natifindexsync((void *)hn->hne_nic, new_ifp, ifs);
			fr_stateifindexsync((void *)hn->hne_nic, new_ifp, ifs);
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_mutex);
		break;
#endif

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
int ipf_nic_event_v6(hook_event_token_t event, hook_data_t info, void *arg)
{
	struct sockaddr_in6 *sin6;
	hook_nic_event_t *hn;
	ipf_stack_t *ifs = arg;
	void *new_ifp = NULL;

	if (ifs->ifs_fr_running <= 0)
		return (0);

	hn = (hook_nic_event_t *)info;

	switch (hn->hne_event)
	{
	case NE_PLUMB :
		frsync(IPFSYNC_NEWIFP, 6, (void *)hn->hne_nic,
		       hn->hne_data, ifs);
		fr_natifpsync(IPFSYNC_NEWIFP, 6, (void *)hn->hne_nic,
			      hn->hne_data, ifs);
		fr_statesync(IPFSYNC_NEWIFP, 6, (void *)hn->hne_nic,
			     hn->hne_data, ifs);
		break;

	case NE_UNPLUMB :
		frsync(IPFSYNC_OLDIFP, 6, (void *)hn->hne_nic, NULL, ifs);
		fr_natifpsync(IPFSYNC_OLDIFP, 6, (void *)hn->hne_nic, NULL,
			      ifs);
		fr_statesync(IPFSYNC_OLDIFP, 6, (void *)hn->hne_nic, NULL, ifs);
		break;

	case NE_ADDRESS_CHANGE :
		if (hn->hne_lif == 1) {
			sin6 = hn->hne_data;
			fr_nataddrsync(6, (void *)hn->hne_nic, &sin6->sin6_addr,
				       ifs);
		}
		break;

#if SOLARIS2 >= 10
	case NE_IFINDEX_CHANGE :
		WRITE_ENTER(&ifs->ifs_ipf_mutex);
		if (hn->hne_data != NULL) {
			/*
			 * The netinfo passes interface index as int (hne_data should be
			 * handled as a pointer to int), which is always 32bit. We need to
			 * convert it to void pointer here, since interfaces are
			 * represented as pointers to void in IPF. The pointers are 64 bits
			 * long on 64bit platforms. Doing something like
			 *	(void *)((int) x)
			 * will throw warning:
			 *   "cast to pointer from integer of different size"
			 * during 64bit compilation.
			 *
			 * The line below uses (size_t) to typecast int to
			 * size_t, which might be 64bit/32bit (depending
			 * on architecture). Once we have proper 64bit/32bit
			 * type (size_t), we can safely convert it to void pointer.
			 */
			new_ifp = (void *)(size_t)*((int *)hn->hne_data);
			fr_ifindexsync((void *)hn->hne_nic, new_ifp, ifs);
			fr_natifindexsync((void *)hn->hne_nic, new_ifp, ifs);
			fr_stateifindexsync((void *)hn->hne_nic, new_ifp, ifs);
		}
		RWLOCK_EXIT(&ifs->ifs_ipf_mutex);
		break;
#endif

	default :
		break;
	}

	return 0;
}

/*
 * Functions fr_make_rst(), fr_make_icmp_v4(), fr_make_icmp_v6()
 * are needed in Solaris kernel only. We don't need them in
 * ipftest to pretend the ICMP/RST packet was sent as a response.
 */
#if defined(_KERNEL) && (SOLARIS2 >= 10)
/* ------------------------------------------------------------------------ */
/* Function:    fr_make_rst                                                 */
/* Returns:     int - 0 on success, -1 on failure			    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* We must alter the original mblks passed to IPF from IP stack via	    */
/* FW_HOOKS. FW_HOOKS interface is powerfull, but it has some limitations.  */
/* IPF can basicaly do only these things with mblk representing the packet: */
/*	leave it as it is (pass the packet)				    */
/*                                                                          */
/*	discard it (block the packet)					    */
/*                                                                          */
/*	alter it (i.e. NAT)						    */
/*                                                                          */
/* As you can see IPF can not simply discard the mblk and supply a new one  */
/* instead to IP stack via FW_HOOKS.					    */
/*                                                                          */
/* The return-rst action for packets coming via NIC is handled as follows:  */
/*	mblk with packet is discarded					    */
/*                                                                          */
/*	new mblk with RST response is constructed and injected to network   */
/*                                                                          */
/* IPF can't inject packets to loopback interface, this is just another	    */
/* limitation we have to deal with here. The only option to send RST	    */
/* response to offending TCP packet coming via loopback is to alter it.	    */
/*									    */
/* The fr_make_rst() function alters TCP SYN/FIN packet intercepted on	    */
/* loopback interface into TCP RST packet. fin->fin_mp is pointer to	    */
/* mblk L3 (IP) and L4 (TCP/UDP) packet headers.			    */
/* ------------------------------------------------------------------------ */
int fr_make_rst(fin)
fr_info_t *fin;
{
	uint16_t tmp_port;
	int rv = -1;
	uint32_t old_ack;
	tcphdr_t *tcp = NULL;
	struct in_addr tmp_src;
#ifdef USE_INET6
	struct in6_addr	tmp_src6;
#endif
	
	ASSERT(fin->fin_p == IPPROTO_TCP);

	/*
	 * We do not need to adjust chksum, since it is not being checked by
	 * Solaris IP stack for loopback clients.
	 */
	if ((fin->fin_v == 4) && (fin->fin_p == IPPROTO_TCP) &&
	    ((tcp = (tcphdr_t *) fin->fin_dp) != NULL)) {

		if (tcp->th_flags & (TH_SYN | TH_FIN)) {
			/* Swap IPv4 addresses. */
			tmp_src = fin->fin_ip->ip_src;
			fin->fin_ip->ip_src = fin->fin_ip->ip_dst;
			fin->fin_ip->ip_dst = tmp_src;

			rv = 0;
		}
		else
			tcp = NULL;
	}
#ifdef USE_INET6
	else if ((fin->fin_v == 6) && (fin->fin_p == IPPROTO_TCP) &&
	    ((tcp = (tcphdr_t *) fin->fin_dp) != NULL)) {
		/*
		 * We are relying on fact the next header is TCP, which is true
		 * for regular TCP packets coming in over loopback.
		 */
		if (tcp->th_flags & (TH_SYN | TH_FIN)) {
			/* Swap IPv6 addresses. */
			tmp_src6 = fin->fin_ip6->ip6_src;
			fin->fin_ip6->ip6_src = fin->fin_ip6->ip6_dst;
			fin->fin_ip6->ip6_dst = tmp_src6;

			rv = 0;
		}
		else
			tcp = NULL;
	}
#endif

	if (tcp != NULL) {
		/* 
		 * Adjust TCP header:
		 *	swap ports,
		 *	set flags,
		 *	set correct ACK number
		 */
		tmp_port = tcp->th_sport;
		tcp->th_sport = tcp->th_dport;
		tcp->th_dport = tmp_port;
		old_ack = tcp->th_ack;
		tcp->th_ack = htonl(ntohl(tcp->th_seq) + 1);
		tcp->th_seq = old_ack;
		tcp->th_flags = TH_RST | TH_ACK;
	}

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_make_icmp_v4                                             */
/* Returns:     int - 0 on success, -1 on failure			    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* Please read comment at fr_make_icmp() wrapper function to get an idea    */
/* what is going to happen here and why. Once you read the comment there,   */
/* continue here with next paragraph.					    */
/*									    */
/* To turn IPv4 packet into ICMPv4 response packet, these things must	    */
/* happen here:								    */
/*	(1) Original mblk is copied (duplicated).			    */
/*                                                                          */
/*	(2) ICMP header is created.					    */
/*                                                                          */
/*	(3) Link ICMP header with copy of original mblk, we have ICMPv4	    */
/*	    data ready then.						    */
/*                                                                          */
/*      (4) Swap IP addresses in original mblk and adjust IP header data.   */
/*                                                                          */
/*	(5) The mblk containing original packet is trimmed to contain IP    */
/*	    header only and ICMP chksum is computed.			    */
/*                                                                          */
/*	(6) The ICMP header we have from (3) is linked to original mblk,    */
/*	    which now contains new IP header. If original packet was spread */
/*	    over several mblks, only the first mblk is kept.		    */
/* ------------------------------------------------------------------------ */
static int fr_make_icmp_v4(fin)
fr_info_t *fin;
{
	struct in_addr tmp_src;
	tcphdr_t *tcp;
	struct icmp *icmp;
	mblk_t *mblk_icmp;
	mblk_t *mblk_ip;
	size_t icmp_pld_len;	/* octets to append to ICMP header */
	size_t orig_iphdr_len;	/* length of IP header only */
	uint32_t sum;
	uint16_t *buf;
	int len;


	if (fin->fin_v != 4)
		return (-1);

	/*
	 * If we are dealing with TCP, then packet must be SYN/FIN to be routed
	 * by IP stack. If it is not SYN/FIN, then we must drop it silently.
	 */
	tcp = (tcphdr_t *) fin->fin_dp;

	if ((fin->fin_p == IPPROTO_TCP) && 
	    ((tcp == NULL) || ((tcp->th_flags & (TH_SYN | TH_FIN)) == 0)))
		return (-1);

	/*
	 * Step (1)
	 *
	 * Make copy of original mblk.
	 *
	 * We want to copy as much data as necessary, not less, not more.  The
	 * ICMPv4 payload length for unreachable messages is:
	 *	original IP header + 8 bytes of L4 (if there are any).
	 *
	 * We determine if there are at least 8 bytes of L4 data following IP
	 * header first.
	 */
	icmp_pld_len = (fin->fin_dlen > ICMPERR_ICMPHLEN) ?
		ICMPERR_ICMPHLEN : fin->fin_dlen;
	/*
	 * Since we don't want to copy more data than necessary, we must trim
	 * the original mblk here.  The right way (STREAMish) would be to use
	 * adjmsg() to trim it.  However we would have to calculate the length
	 * argument for adjmsg() from pointers we already have here.
	 *
	 * Since we have pointers and offsets, it's faster and easier for
	 * us to just adjust pointers by hand instead of using adjmsg().
	 */
	fin->fin_m->b_wptr = (unsigned char *) fin->fin_dp;
	fin->fin_m->b_wptr += icmp_pld_len;
	icmp_pld_len = fin->fin_m->b_wptr - (unsigned char *) fin->fin_ip;

	/*
	 * Also we don't want to copy any L2 stuff, which might precede IP
	 * header, so we have have to set b_rptr to point to the start of IP
	 * header.
	 */
	fin->fin_m->b_rptr += fin->fin_ipoff;
	if ((mblk_ip = copyb(fin->fin_m)) == NULL)
		return (-1);
	fin->fin_m->b_rptr -= fin->fin_ipoff;

	/*
	 * Step (2)
	 *
	 * Create an ICMP header, which will be appened to original mblk later.
	 * ICMP header is just another mblk.
	 */
	mblk_icmp = (mblk_t *) allocb(ICMPERR_ICMPHLEN, BPRI_HI);
	if (mblk_icmp == NULL) {
		FREE_MB_T(mblk_ip);
		return (-1);
	}

	MTYPE(mblk_icmp) = M_DATA;
	icmp = (struct icmp *) mblk_icmp->b_wptr;
	icmp->icmp_type = ICMP_UNREACH;
	icmp->icmp_code = fin->fin_icode & 0xFF;
	icmp->icmp_void = 0;
	icmp->icmp_cksum = 0;
	mblk_icmp->b_wptr += ICMPERR_ICMPHLEN;

	/*
	 * Step (3)
	 *
	 * Complete ICMP packet - link ICMP header with L4 data from original
	 * IP packet.
	 */
	linkb(mblk_icmp, mblk_ip);

	/*
	 * Step (4)
	 *
	 * Swap IP addresses and change IP header fields accordingly in
	 * original IP packet.
	 *
	 * There is a rule option return-icmp as a dest for physical
	 * interfaces. This option becomes useless for loopback, since IPF box
	 * uses same address as a loopback destination. We ignore the option
	 * here, the ICMP packet will always look like as it would have been
	 * sent from the original destination host.
	 */
	tmp_src = fin->fin_ip->ip_src;
	fin->fin_ip->ip_src = fin->fin_ip->ip_dst;
	fin->fin_ip->ip_dst = tmp_src;
	fin->fin_ip->ip_p = IPPROTO_ICMP;
	fin->fin_ip->ip_sum = 0;

	/*
	 * Step (5)
	 *
	 * We trim the orignal mblk to hold IP header only.
	 */
	fin->fin_m->b_wptr = fin->fin_dp;
	orig_iphdr_len = fin->fin_m->b_wptr -
			    (fin->fin_m->b_rptr + fin->fin_ipoff);
	fin->fin_ip->ip_len = htons(icmp_pld_len + ICMPERR_ICMPHLEN +
			    orig_iphdr_len);

	/*
	 * ICMP chksum calculation. The data we are calculating chksum for are
	 * spread over two mblks, therefore we have to use two for loops.
	 *
	 * First for loop computes chksum part for ICMP header.
	 */
	buf = (uint16_t *) icmp;
	len = ICMPERR_ICMPHLEN;
	for (sum = 0; len > 1; len -= 2)
		sum += *buf++;

	/*
	 * Here we add chksum part for ICMP payload.
	 */
	len = icmp_pld_len;
	buf = (uint16_t *) mblk_ip->b_rptr;
	for (; len > 1; len -= 2)
		sum += *buf++;

	/*
	 * Chksum is done.
	 */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	icmp->icmp_cksum = ~sum; 

	/*
	 * Step (6)
	 *
	 * Release all packet mblks, except the first one.
	 */
	if (fin->fin_m->b_cont != NULL) {
		FREE_MB_T(fin->fin_m->b_cont);
	}

	/*
	 * Append ICMP payload to first mblk, which already contains new IP
	 * header.
	 */
	linkb(fin->fin_m, mblk_icmp);

	return (0);
}

#ifdef USE_INET6
/* ------------------------------------------------------------------------ */
/* Function:    fr_make_icmp_v6                                             */
/* Returns:     int - 0 on success, -1 on failure			    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*									    */
/* Please read comment at fr_make_icmp() wrapper function to get an idea    */
/* what and why is going to happen here. Once you read the comment there,   */
/* continue here with next paragraph.					    */
/*									    */
/* This function turns IPv6 packet (UDP, TCP, ...) into ICMPv6 response.    */
/* The algorithm is fairly simple:					    */
/*	1) We need to get copy of complete mblk.			    */
/*									    */
/*	2) New ICMPv6 header is created.				    */
/*									    */
/*	3) The copy of original mblk with packet is linked to ICMPv6	    */
/*	   header.							    */
/*									    */
/*	4) The checksum must be adjusted.				    */
/*									    */
/*	5) IP addresses in original mblk are swapped and IP header data	    */
/*	   are adjusted (protocol number).				    */
/*									    */
/*	6) Original mblk is trimmed to hold IPv6 header only, then it is    */
/*	   linked with the ICMPv6 data we got from (3).			    */
/* ------------------------------------------------------------------------ */
static int fr_make_icmp_v6(fin)
fr_info_t *fin;
{
	struct icmp6_hdr *icmp6;
	tcphdr_t *tcp;
	struct in6_addr	tmp_src6;
	size_t icmp_pld_len;
	mblk_t *mblk_ip, *mblk_icmp;

	if (fin->fin_v != 6)
		return (-1);

	/*
	 * If we are dealing with TCP, then packet must SYN/FIN to be routed by
	 * IP stack. If it is not SYN/FIN, then we must drop it silently.
	 */
	tcp = (tcphdr_t *) fin->fin_dp;

	if ((fin->fin_p == IPPROTO_TCP) && 
	    ((tcp == NULL) || ((tcp->th_flags & (TH_SYN | TH_FIN)) == 0)))
		return (-1);

	/*
	 * Step (1)
	 *
	 * We need to copy complete packet in case of IPv6, no trimming is
	 * needed (except the L2 headers).
	 */
	icmp_pld_len = M_LEN(fin->fin_m);
	fin->fin_m->b_rptr += fin->fin_ipoff;
	if ((mblk_ip = copyb(fin->fin_m)) == NULL)
		return (-1);
	fin->fin_m->b_rptr -= fin->fin_ipoff;

	/*
	 * Step (2)
	 *
	 * Allocate and create ICMP header.
	 */
	mblk_icmp = (mblk_t *) allocb(sizeof (struct icmp6_hdr),
			BPRI_HI);

	if (mblk_icmp == NULL)
		return (-1);
	
	MTYPE(mblk_icmp) = M_DATA;
	icmp6 =  (struct icmp6_hdr *) mblk_icmp->b_wptr;
	icmp6->icmp6_type = ICMP6_DST_UNREACH;
	icmp6->icmp6_code = fin->fin_icode & 0xFF;
	icmp6->icmp6_data32[0] = 0;
	mblk_icmp->b_wptr += sizeof (struct icmp6_hdr);
	
	/*
	 * Step (3)
	 *
	 * Link the copy of IP packet to ICMP header.
	 */
	linkb(mblk_icmp, mblk_ip);

	/* 
	 * Step (4)
	 *
	 * Calculate chksum - this is much more easier task than in case of
	 * IPv4  - ICMPv6 chksum only covers IP addresses, and payload length.
	 * We are making compensation just for change of packet length.
	 */
	icmp6->icmp6_cksum = icmp_pld_len + sizeof (struct icmp6_hdr);

	/*
	 * Step (5)
	 *
	 * Swap IP addresses.
	 */
	tmp_src6 = fin->fin_ip6->ip6_src;
	fin->fin_ip6->ip6_src = fin->fin_ip6->ip6_dst;
	fin->fin_ip6->ip6_dst = tmp_src6;

	/*
	 * and adjust IP header data.
	 */
	fin->fin_ip6->ip6_nxt = IPPROTO_ICMPV6;
	fin->fin_ip6->ip6_plen = htons(icmp_pld_len + sizeof (struct icmp6_hdr));

	/*
	 * Step (6)
	 *
	 * We must release all linked mblks from original packet and keep only
	 * the first mblk with IP header to link ICMP data.
	 */
	fin->fin_m->b_wptr = (unsigned char *) fin->fin_ip6 + sizeof (ip6_t);

	if (fin->fin_m->b_cont != NULL) {
		FREE_MB_T(fin->fin_m->b_cont);
	}

	/*
	 * Append ICMP payload to IP header.
	 */
	linkb(fin->fin_m, mblk_icmp);

	return (0);
}
#endif	/* USE_INET6 */

/* ------------------------------------------------------------------------ */
/* Function:    fr_make_icmp                                                */
/* Returns:     int - 0 on success, -1 on failure			    */
/* Parameters:  fin(I) - pointer to packet information                      */
/*                                                                          */
/* We must alter the original mblks passed to IPF from IP stack via	    */
/* FW_HOOKS. The reasons why we must alter packet are discussed within	    */
/* comment at fr_make_rst() function.					    */
/*									    */
/* The fr_make_icmp() function acts as a wrapper, which passes the code	    */
/* execution to	fr_make_icmp_v4() or fr_make_icmp_v6() depending on	    */
/* protocol version. However there are some details, which are common to    */
/* both IP versions. The details are going to be explained here.	    */
/*                                                                          */
/* The packet looks as follows:						    */
/*    xxx | IP hdr | IP payload    ...	| 				    */
/*    ^   ^        ^            	^				    */
/*    |   |        |            	|				    */
/*    |   |        |		fin_m->b_wptr = fin->fin_dp + fin->fin_dlen */
/*    |   |        |							    */
/*    |   |        `- fin_m->fin_dp (in case of IPv4 points to L4 header)   */
/*    |   |								    */
/*    |   `- fin_m->b_rptr + fin_ipoff (fin_ipoff is most likely 0 in case  */
/*    |      of loopback)						    */
/*    |   								    */
/*    `- fin_m->b_rptr -  points to L2 header in case of physical NIC	    */
/*                                                                          */
/* All relevant IP headers are pulled up into the first mblk. It happened   */
/* well in advance before the matching rule was found (the rule, which took */
/* us here, to fr_make_icmp() function).				    */
/*                                                                          */
/* Both functions will turn packet passed in fin->fin_m mblk into a new	    */
/* packet. New packet will be represented as chain of mblks.		    */
/* orig mblk |- b_cont ---.						    */
/*    ^                    `-> ICMP hdr |- b_cont--.			    */
/*    |	                          ^	            `-> duped orig mblk	    */
/*    |                           |				^	    */
/*    `- The original mblk        |				|	    */
/*       will be trimmed to       |				|	    */
/*       to contain IP header     |				|	    */
/*       only                     |				|	    */
/*                                |				|	    */
/*                                `- This is newly		|           */
/*                                   allocated mblk to		|	    */
/*                                   hold ICMPv6 data.		|	    */
/*								|	    */
/*								|	    */
/*								|	    */
/*	    This is the copy of original mblk, it will contain -'	    */
/*	    orignal IP  packet in case of ICMPv6. In case of		    */
/*	    ICMPv4 it will contain up to 8 bytes of IP payload		    */
/*	    (TCP/UDP/L4) data from original packet.			    */
/* ------------------------------------------------------------------------ */
int fr_make_icmp(fin)
fr_info_t *fin;
{
	int rv;
	
	if (fin->fin_v == 4)
		rv = fr_make_icmp_v4(fin);
#ifdef USE_INET6
	else if (fin->fin_v == 6)
		rv = fr_make_icmp_v6(fin);
#endif
	else
		rv = -1;

	return (rv);
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_buf_sum						    */
/* Returns:     unsigned int - sum of buffer buf			    */
/* Parameters:  buf - pointer to buf we want to sum up			    */
/*              len - length of buffer buf				    */
/*                                                                          */
/* Sums buffer buf. The result is used for chksum calculation. The buf	    */
/* argument must be aligned.						    */
/* ------------------------------------------------------------------------ */
static uint32_t fr_buf_sum(buf, len)
const void *buf;
unsigned int len;
{
	uint32_t	sum = 0;
	uint16_t	*b = (uint16_t *)buf;

	while (len > 1) {
		sum += *b++;
		len -= 2;
	}

	if (len == 1)
		sum += htons((*(unsigned char *)b) << 8);

	return (sum);
}

/* ------------------------------------------------------------------------ */
/* Function:    fr_calc_chksum						    */
/* Returns:     void							    */
/* Parameters:  fin - pointer to fr_info_t instance with packet data	    */
/*              pkt - pointer to duplicated packet			    */
/*                                                                          */
/* Calculates all chksums (L3, L4) for packet pkt. Works for both IP	    */
/* versions.								    */
/* ------------------------------------------------------------------------ */
void fr_calc_chksum(fin, pkt)
fr_info_t *fin;
mb_t *pkt;
{
	struct pseudo_hdr {
		union {
			struct in_addr	in4;
#ifdef USE_INET6
			struct in6_addr	in6;
#endif
		} src_addr;
		union {
			struct in_addr	in4;
#ifdef USE_INET6
			struct in6_addr	in6;
#endif
		} dst_addr;
		char		zero;
		char		proto;
		uint16_t	len;
	}	phdr;
	uint32_t	sum, ip_sum;
	void	*buf;
	uint16_t	*l4_csum_p;
	tcphdr_t	*tcp;
	udphdr_t	*udp;
	icmphdr_t	*icmp;
#ifdef USE_INET6
	struct icmp6_hdr	*icmp6;
#endif
	ip_t		*ip;
	unsigned int	len;
	int		pld_len;

	/*
	 * We need to pullup the packet to the single continuous buffer to avoid
	 * potential misaligment of b_rptr member in mblk chain.
	 */
	if (pullupmsg(pkt, -1) == 0) {
		cmn_err(CE_WARN, "Failed to pullup loopback pkt -> chksum"
		    " will not be computed by IPF");
		return;
	}

	/*
	 * It is guaranteed IP header starts right at b_rptr, because we are
	 * working with a copy of the original packet.
	 *
	 * Compute pseudo header chksum for TCP and UDP.
	 */
	if ((fin->fin_p == IPPROTO_UDP) ||
	    (fin->fin_p == IPPROTO_TCP)) {
		bzero(&phdr, sizeof (phdr));
#ifdef USE_INET6
		if (fin->fin_v == 6) {
			phdr.src_addr.in6 = fin->fin_srcip6;
			phdr.dst_addr.in6 = fin->fin_dstip6;
		} else {
			phdr.src_addr.in4 = fin->fin_src;
			phdr.dst_addr.in4 = fin->fin_dst;
		}
#else
		phdr.src_addr.in4 = fin->fin_src;
		phdr.dst_addr.in4 = fin->fin_dst;
#endif
		phdr.zero = (char) 0;
		phdr.proto = fin->fin_p;
		phdr.len = htons((uint16_t)fin->fin_dlen);
		sum = fr_buf_sum(&phdr, (unsigned int)sizeof (phdr));
	} else {
		sum = 0;
	}

	/*
	 * Set pointer to the L4 chksum field in the packet, set buf pointer to
	 * the L4 header start.
	 */
	switch (fin->fin_p) {
		case IPPROTO_UDP:
			udp = (udphdr_t *)(pkt->b_rptr + fin->fin_hlen);
			l4_csum_p = &udp->uh_sum;
			buf = udp;
			break;
		case IPPROTO_TCP:
			tcp = (tcphdr_t *)(pkt->b_rptr + fin->fin_hlen);
			l4_csum_p = &tcp->th_sum;
			buf = tcp;
			break;
		case IPPROTO_ICMP:
			icmp = (icmphdr_t *)(pkt->b_rptr + fin->fin_hlen);
			l4_csum_p = &icmp->icmp_cksum;
			buf = icmp;
			break;
#ifdef USE_INET6
		case IPPROTO_ICMPV6:
			icmp6 = (struct icmp6_hdr *)(pkt->b_rptr + fin->fin_hlen);
			l4_csum_p = &icmp6->icmp6_cksum;
			buf = icmp6;
			break;
#endif
		default:
			l4_csum_p = NULL;
	}

	/*
	 * Compute L4 chksum if needed.
	 */
	if (l4_csum_p != NULL) {
		*l4_csum_p = (uint16_t)0;
		pld_len = fin->fin_dlen;
		len = pkt->b_wptr - (unsigned char *)buf;
		ASSERT(len == pld_len);
		/*
		 * Add payload sum to pseudoheader sum.
		 */
		sum += fr_buf_sum(buf, len);
		while (sum >> 16)
			sum = (sum & 0xFFFF) + (sum >> 16);

		*l4_csum_p = ~((uint16_t)sum);
		DTRACE_PROBE1(l4_sum, uint16_t, *l4_csum_p);
	}

	/*
	 * The IP header chksum is needed just for IPv4.
	 */
	if (fin->fin_v == 4) {
		/*
		 * Compute IPv4 header chksum.
		 */
		ip = (ip_t *)pkt->b_rptr;
		ip->ip_sum = (uint16_t)0;
		ip_sum = fr_buf_sum(ip, (unsigned int)fin->fin_hlen);
		while (ip_sum >> 16)
			ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);

		ip->ip_sum = ~((uint16_t)ip_sum);
		DTRACE_PROBE1(l3_sum, uint16_t, ip->ip_sum);
	}

	return;
}

#endif	/* _KERNEL && SOLARIS2 >= 10 */
