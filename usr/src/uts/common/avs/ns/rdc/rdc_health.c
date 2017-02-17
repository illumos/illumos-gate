/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * RDC interface health monitoring code.
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>

#include <sys/errno.h>

#ifdef _SunOS_2_6
/*
 * on 2.6 both dki_lock.h and rpc/types.h define bool_t so we
 * define enum_t here as it is all we need from rpc/types.h
 * anyway and make it look like we included it. Yuck.
 */
#define	_RPC_TYPES_H
typedef int enum_t;
#else
#ifndef DS_DDICT
#include <rpc/types.h>
#endif
#endif /* _SunOS_2_6 */

#include <sys/ddi.h>
#include <sys/nsc_thread.h>
#ifdef DS_DDICT
#include <sys/nsctl/contract.h>
#endif
#include <sys/nsctl/nsctl.h>

#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

#include "rdc_io.h"
#include "rdc_clnt.h"


/*
 * Forward declarations.
 */

static void rdc_update_health(rdc_if_t *);

/*
 * Global data.
 */

/*
 * These structures are added when a new host name is introduced to the
 * kernel. They never disappear (but that won't waste much space at all).
 */
typedef struct rdc_link_down {
	char host[MAX_RDC_HOST_SIZE];	/* The host name of this link */
	int waiting;			/* A user is waiting to be woken up */
	int link_down;			/* The current state of the link */
	struct rdc_link_down *next;	/* Chain */
	kcondvar_t syncd_cv;		/* Syncd wakeup */
	kmutex_t syncd_mutex;		/* Lock for syncd_cv */
} rdc_link_down_t;
static rdc_link_down_t *rdc_link_down = NULL;

int rdc_health_thres = RDC_HEALTH_THRESHOLD;
rdc_if_t *rdc_if_top;


/*
 * IPv6 addresses are represented as 16bit hexadecimal integers
 * separated by colons. Contiguous runs of zeros can be abbreviated by
 * double colons:
 *	FF02:0:0:0:0:1:200E:8C6C
 *		|
 *		v
 *	  FF02::1:200E:8C6C
 */
void
rdc_if_ipv6(const uint16_t *addr, char *buf)
{
	const int end = 8;	/* 8 shorts, 128 bits in an IPv6 address */
	int i;

	for (i = 0; i < end; i++) {
		if (i > 0)
			(void) sprintf(buf, "%s:", buf);

		if (addr[i] != 0 || i == 0 || i == (end - 1)) {
			/* first, last, or non-zero value */
			(void) sprintf(buf, "%s%x", buf, (int)addr[i]);
		} else {
			if ((i + 1) < end && addr[i + 1] != 0) {
				/* single zero */
				(void) sprintf(buf, "%s%x", buf, (int)addr[i]);
			} else {
				/* skip contiguous zeros */
				while ((i + 1) < end && addr[i + 1] == 0)
					i++;
			}
		}
	}
}

static void
rdc_if_xxx(rdc_if_t *ip, char *updown)
{
	if (strcmp("inet6", ip->srv->ri_knconf->knc_protofmly) == 0) {
		uint16_t *this = (uint16_t *)ip->ifaddr.buf;
		uint16_t *other = (uint16_t *)ip->r_ifaddr.buf;
		char this_str[256], other_str[256];

		bzero(this_str, sizeof (this_str));
		bzero(other_str, sizeof (other_str));
		rdc_if_ipv6(&this[4], this_str);
		rdc_if_ipv6(&other[4], other_str);

		cmn_err(CE_NOTE, "!SNDR: Interface %s <==> %s : %s",
		    this_str, other_str, updown);
	} else {
		uchar_t *this = (uchar_t *)ip->ifaddr.buf;
		uchar_t *other = (uchar_t *)ip->r_ifaddr.buf;

		cmn_err(CE_NOTE,
		    "!SNDR: Interface %d.%d.%d.%d <==> %d.%d.%d.%d : %s",
		    (int)this[4], (int)this[5], (int)this[6], (int)this[7],
		    (int)other[4], (int)other[5], (int)other[6], (int)other[7],
		    updown);
	}
}


static void
rdc_if_down(rdc_if_t *ip)
{
	rdc_if_xxx(ip, "Down");
}


static void
rdc_if_up(rdc_if_t *ip)
{
	rdc_if_xxx(ip, "Up");
}


/*
 * Health monitor for a single interface.
 *
 * The secondary sends ping RPCs to the primary.
 * The primary just stores the results and updates its structures.
 */
static void
rdc_health_thread(void *arg)
{
	rdc_if_t *ip = (rdc_if_t *)arg;
	struct rdc_ping ping;
	struct rdc_ping6 ping6;
	struct timeval t;
	int down = 1;
	int ret, err;
	int sec = 0;
	char ifaddr[RDC_MAXADDR];
	char r_ifaddr[RDC_MAXADDR];
	uint16_t *sp;

	bcopy(ip->ifaddr.buf, ifaddr, ip->ifaddr.len);
	sp = (uint16_t *)ifaddr;
	*sp = htons(*sp);
	bcopy(ip->r_ifaddr.buf, r_ifaddr, ip->r_ifaddr.len);
	sp = (uint16_t *)r_ifaddr;
	*sp = htons(*sp);

	while ((ip->exiting != 1) && (net_exit != ATM_EXIT)) {
		delay(HZ);

		/* setup RPC timeout */

		t.tv_sec = rdc_rpc_tmout;
		t.tv_usec = 0;

		if (ip->issecondary && !ip->no_ping) {
			if (ip->rpc_version < RDC_VERSION7) {
				bcopy(ip->r_ifaddr.buf, ping6.p_ifaddr,
				    RDC_MAXADDR);
			/* primary ifaddr */
				bcopy(ip->ifaddr.buf, ping6.s_ifaddr,
				    RDC_MAXADDR);
			/* secondary ifaddr */
				err = rdc_clnt_call_any(ip->srv, ip,
				    RDCPROC_PING4, xdr_rdc_ping6,
				    (char *)&ping6, xdr_int, (char *)&ret, &t);
			} else {
				ping.p_ifaddr.buf = r_ifaddr;
				ping.p_ifaddr.len = ip->r_ifaddr.len;
				ping.p_ifaddr.maxlen = ip->r_ifaddr.len;
				ping.s_ifaddr.buf = ifaddr;
				ping.s_ifaddr.len = ip->ifaddr.len;
				ping.s_ifaddr.maxlen = ip->ifaddr.len;
				err = rdc_clnt_call_any(ip->srv, ip,
				    RDCPROC_PING4, xdr_rdc_ping, (char *)&ping,
				    xdr_int, (char *)&ret, &t);
			}


			if (err || ret) {
				/* RPC failed - link is down */
				if (!down && !ip->isprimary) {
					/*
					 * don't print messages if also
					 * a primary - the primary will
					 * take care of it.
					 */
					rdc_if_down(ip);
					down = 1;
				}
				rdc_dump_alloc_bufs(ip);
				ip->no_ping = 1;

				/*
				 * Start back at the max possible version
				 * since the remote server could come back
				 * on a different protocol version.
				 */
				mutex_enter(&rdc_ping_lock);
				ip->rpc_version = RDC_VERS_MAX;
				mutex_exit(&rdc_ping_lock);
			} else {
				if (down && !ip->isprimary) {
					/*
					 * was failed, but now ok
					 *
					 * don't print messages if also
					 * a primary - the primary will
					 * take care of it.
					 */
					rdc_if_up(ip);
					down = 0;
				}
			}
		}
		if (!ip->isprimary && down && ++sec == 5) {
				sec = 0;
				rdc_dump_alloc_bufs(ip);
		}

		if (ip->isprimary)
			rdc_update_health(ip);
	}

	/* signal that this thread is done */
	ip->exiting = 2;
}


int
rdc_isactive_if(struct netbuf *addr, struct netbuf *r_addr)
{
	rdc_if_t *ip;
	int rc = 0;

	/* search for existing interface structure */

	mutex_enter(&rdc_ping_lock);
	for (ip = rdc_if_top; ip; ip = ip->next) {
		if (ip->exiting != 0)
			continue;
		if (((bcmp(ip->ifaddr.buf, addr->buf, addr->len) == 0) &&
		    (bcmp(ip->r_ifaddr.buf, r_addr->buf, r_addr->len) == 0)) ||
		    ((bcmp(ip->r_ifaddr.buf, addr->buf, addr->len) == 0) &&
		    (bcmp(ip->ifaddr.buf, r_addr->buf, r_addr->len) == 0))) {
			/* found matching interface structure */
			if (ip->isprimary && !ip->if_down) {
				rc = 1;
			} else if (ip->issecondary && !ip->no_ping) {
				rc = 1;
			}
			break;
		}
	}
	mutex_exit(&rdc_ping_lock);
	return (rc);
}

/*
 * Set the rdc rpc version of the rdc_if_t.
 *
 * Called from incoming rpc calls which start before
 * the health service becomes established.
 */
void
rdc_set_if_vers(rdc_u_info_t *urdc, rpcvers_t vers)
{
	rdc_if_t *ip;
	struct netbuf *addr, *r_addr;

	if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
		addr = &(urdc->primary.addr);
		r_addr = &(urdc->secondary.addr);
	} else {
		addr = &(urdc->secondary.addr);
		r_addr = &(urdc->primary.addr);
	}

	/* search for existing interface structure */

	mutex_enter(&rdc_ping_lock);
	for (ip = rdc_if_top; ip; ip = ip->next) {
		if (ip->exiting != 0)
			continue;
		if (((bcmp(ip->ifaddr.buf, addr->buf, addr->len) == 0) &&
		    (bcmp(ip->r_ifaddr.buf, r_addr->buf, r_addr->len) == 0)) ||
		    ((bcmp(ip->r_ifaddr.buf, addr->buf, addr->len) == 0) &&
		    (bcmp(ip->ifaddr.buf, r_addr->buf, r_addr->len) == 0))) {
			/* found matching interface structure */
			ip->rpc_version = vers;
#ifdef DEBUG
			cmn_err(CE_NOTE, "!rdc intf %p rpc version set to %u",
			    (void *)ip, vers);
#endif
			break;
		}
	}
	mutex_exit(&rdc_ping_lock);
}

/*
 * Free all the rdc_link_down structures (only at module unload time)
 */
void
rdc_link_down_free()
{
	rdc_link_down_t *p;
	rdc_link_down_t *q;

	if (rdc_link_down == NULL)
		return;

	for (p = rdc_link_down->next; p != rdc_link_down; ) {
		q = p;
		p = p->next;
		kmem_free(q, sizeof (*q));
	}
	kmem_free(rdc_link_down, sizeof (*q));
	rdc_link_down = NULL;
}


/*
 * Look up the supplied hostname in the rdc_link_down chain. Add a new
 * entry if it isn't found. Return a pointer to the new or found entry.
 */
static rdc_link_down_t *
rdc_lookup_host(char *host)
{
	rdc_link_down_t *p;

	mutex_enter(&rdc_ping_lock);

	if (rdc_link_down == NULL) {
		rdc_link_down = kmem_zalloc(sizeof (*rdc_link_down), KM_SLEEP);
		rdc_link_down->next = rdc_link_down;
	}

	for (p = rdc_link_down->next; p != rdc_link_down; p = p->next) {
		if (strcmp(host, p->host) == 0) {
			/* Match */
			mutex_exit(&rdc_ping_lock);
			return (p);
		}
	}

	/* No match, must create a new entry */

	p = kmem_zalloc(sizeof (*p), KM_SLEEP);
	p->link_down = 1;
	p->next = rdc_link_down->next;
	rdc_link_down->next = p;
	(void) strncpy(p->host, host, MAX_RDC_HOST_SIZE);
	mutex_init(&p->syncd_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&p->syncd_cv, NULL, CV_DRIVER, NULL);

	mutex_exit(&rdc_ping_lock);
	return (p);
}


/*
 * Handle the RDC_LINK_DOWN ioctl.
 * The user specifies which host they're interested in.
 * This function is woken up when the link to that host goes down.
 */

/* ARGSUSED3 */
int
_rdc_link_down(void *arg, int mode, spcs_s_info_t kstatus, int *rvp)
{
	char host[MAX_RDC_HOST_SIZE];
	rdc_link_down_t *syncdp;
	clock_t timeout = RDC_SYNC_EVENT_TIMEOUT * 2; /* 2 min */
	int rc = 0;

	if (ddi_copyin(arg, host, MAX_RDC_HOST_SIZE, mode))
		return (EFAULT);


	syncdp = rdc_lookup_host(host);

	mutex_enter(&syncdp->syncd_mutex);
	if (!syncdp->link_down) {
		syncdp->waiting = 1;
		if (cv_timedwait_sig(&syncdp->syncd_cv, &syncdp->syncd_mutex,
		    nsc_lbolt() + timeout) == 0) {
			/* Woken by a signal, not a link down event */
			syncdp->waiting = 0;
			rc = EAGAIN;
			spcs_s_add(kstatus, rc);
		}

	}
	mutex_exit(&syncdp->syncd_mutex);

	return (rc);
}


/*
 * Add an RDC set to an interface
 *
 * If the interface is new, add it to the list of interfaces.
 */
rdc_if_t *
rdc_add_to_if(rdc_srv_t *svp, struct netbuf *addr, struct netbuf *r_addr,
    int primary)
{
	rdc_if_t *new, *ip;

	if ((addr->buf == NULL) || (r_addr->buf == NULL))
		return (NULL);

	/* setup a new interface structure */
	new = (rdc_if_t *)kmem_zalloc(sizeof (*new), KM_SLEEP);
	if (!new)
		return (NULL);

	dup_rdc_netbuf(addr, &new->ifaddr);
	dup_rdc_netbuf(r_addr, &new->r_ifaddr);
	new->rpc_version = RDC_VERS_MAX;
	new->srv = rdc_create_svinfo(svp->ri_hostname, &svp->ri_addr,
	    svp->ri_knconf);
	new->old_pulse = -1;
	new->new_pulse = 0;

	if (!new->srv) {
		free_rdc_netbuf(&new->r_ifaddr);
		free_rdc_netbuf(&new->ifaddr);
		kmem_free(new, sizeof (*new));
		return (NULL);
	}

	/* search for existing interface structure */

	mutex_enter(&rdc_ping_lock);

	for (ip = rdc_if_top; ip; ip = ip->next) {
		if ((bcmp(ip->ifaddr.buf, addr->buf, addr->len) == 0) &&
		    (bcmp(ip->r_ifaddr.buf, r_addr->buf, r_addr->len) == 0) &&
		    ip->exiting == 0) {
			/* found matching interface structure */
			break;
		}
	}

	if (!ip) {
		/* add new into the chain */

		new->next = rdc_if_top;
		rdc_if_top = new;
		ip = new;

		/* start daemon */

		ip->last = nsc_time();
		ip->deadness = 1;
		ip->if_down = 1;

		if (nsc_create_process(rdc_health_thread, ip, TRUE)) {
			mutex_exit(&rdc_ping_lock);
			return (NULL);
		}
	}

	/* mark usage type */

	if (primary) {
		ip->isprimary = 1;
	} else {
		ip->issecondary = 1;
		ip->no_ping = 0;
	}

	mutex_exit(&rdc_ping_lock);

	/* throw away new if it was not used */

	if (ip != new) {
		free_rdc_netbuf(&new->r_ifaddr);
		free_rdc_netbuf(&new->ifaddr);
		rdc_destroy_svinfo(new->srv);
		kmem_free(new, sizeof (*new));
	}

	return (ip);
}


/*
 * Update an interface following the removal of an RDC set.
 *
 * If there are no more RDC sets using the interface, delete it from
 * the list of interfaces.
 *
 * Either clear krdc->intf, or ensure !IS_CONFIGURED(krdc) before calling this.
 */
void
rdc_remove_from_if(rdc_if_t *ip)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	rdc_if_t **ipp;
	int pfound = 0;
	int sfound = 0;
	int delete = 1;
	int index;

	mutex_enter(&rdc_ping_lock);

	/*
	 * search for RDC sets using this interface and update
	 * the isprimary and issecondary flags.
	 */

	for (index = 0; index < rdc_max_sets; index++) {
		krdc = &rdc_k_info[index];
		urdc = &rdc_u_info[index];
		if (IS_CONFIGURED(krdc) && krdc->intf == ip) {
			delete = 0;

			if (rdc_get_vflags(urdc) & RDC_PRIMARY) {
				pfound = 1;
			} else {
				sfound = 1;
			}

			if (pfound && sfound)
				break;
		}
	}

	ip->isprimary = pfound;
	ip->issecondary = sfound;

	if (!delete || ip->exiting > 0) {
		mutex_exit(&rdc_ping_lock);
		return;
	}

	/* mark and wait for daemon to exit */

	ip->exiting = 1;

	mutex_exit(&rdc_ping_lock);

	while (ip->exiting == 1)
		delay(drv_usectohz(10));

	mutex_enter(&rdc_ping_lock);

	ASSERT(ip->exiting == 2);

	/* remove from chain */

	for (ipp = &rdc_if_top; *ipp; ipp = &((*ipp)->next)) {
		if (*ipp == ip) {
			*ipp = ip->next;
			break;
		}
	}

	mutex_exit(&rdc_ping_lock);

	/* free unused interface structure */

	free_rdc_netbuf(&ip->r_ifaddr);
	free_rdc_netbuf(&ip->ifaddr);
	rdc_destroy_svinfo(ip->srv);
	kmem_free(ip, sizeof (*ip));
}


/*
 * Check the status of the link to the secondary, and optionally update
 * the primary-side ping variables.
 *
 * For use on a primary only.
 *
 * Returns:
 *	TRUE	- interface up.
 *	FALSE	- interface down.
 */
int
rdc_check_secondary(rdc_if_t *ip, int update)
{
	int rc = TRUE;

	if (!ip || !ip->isprimary) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "!rdc_check_secondary: ip %p, isprimary %d, issecondary %d",
		    (void *) ip, ip ? ip->isprimary : 0,
		    ip ? ip->issecondary : 0);
#endif
		return (FALSE);
	}

	if (!ip->deadness) {
#ifdef DEBUG
		cmn_err(CE_WARN, "!rdc_check_secondary: ip %p, ip->deadness %d",
		    (void *) ip, ip->deadness);
#endif
		return (FALSE);
	}

	if (!update) {
		/* quick look */
		return ((ip->deadness > rdc_health_thres) ? FALSE : TRUE);
	}

	/* update (slow) with lock */

	mutex_enter(&rdc_ping_lock);

	if (ip->old_pulse == ip->new_pulse) {
		/*
		 * ping has not been received since last update
		 * or we have not yet been pinged,
		 * the health thread has started only as a
		 * local client so far, not so on the other side
		 */

		if (ip->last != nsc_time()) {
			/* time has passed, so move closer to death */

			ip->last = nsc_time();
			ip->deadness++;

			if (ip->deadness <= 0) {
				/* avoid the wrap */
				ip->deadness = rdc_health_thres + 1;
			}
		}

		if (ip->deadness > rdc_health_thres) {
			rc = FALSE;
			/*
			 * Start back at the max possible version
			 * since the remote server could come back
			 * on a different protocol version.
			 */
			ip->rpc_version = RDC_VERS_MAX;
		}
	} else {
		ip->old_pulse = ip->new_pulse;
	}

	mutex_exit(&rdc_ping_lock);
	return (rc);
}


/*
 * Update the interface structure with the latest ping info, and
 * perform interface up/down transitions if required.
 *
 * For use on a primary only.
 */
static void
rdc_update_health(rdc_if_t *ip)
{
	rdc_k_info_t *krdc;
	rdc_u_info_t *urdc;
	int index;
	rdc_link_down_t *syncdp;

	if (!ip->isprimary) {
#ifdef DEBUG
		cmn_err(CE_WARN,
		    "!rdc_update_health: ip %p, isprimary %d, issecondary %d",
		    (void *) ip, ip ? ip->isprimary : 0,
		    ip ? ip->issecondary : 0);
#endif
		return;
	}

	if (!rdc_check_secondary(ip, TRUE)) {
		/* interface down */
		if (!ip->if_down) {
			rdc_if_down(ip);
			ip->if_down = 1;

			/* scan rdc sets and update status */

			for (index = 0; index < rdc_max_sets; index++) {
				krdc = &rdc_k_info[index];
				urdc = &rdc_u_info[index];

				if (IS_ENABLED(urdc) && (krdc->intf == ip) &&
				    (rdc_get_vflags(urdc) & RDC_PRIMARY) &&
				    !(rdc_get_vflags(urdc) & RDC_LOGGING)) {
					/* mark down */

					rdc_group_enter(krdc);
					/*
					 * check for possible race with
					 * with delete logic
					 */
					if (!IS_ENABLED(urdc)) {
						rdc_group_exit(krdc);
						continue;
					}
					rdc_group_log(krdc, RDC_NOFLUSH |
					    RDC_NOREMOTE | RDC_QUEUING,
					    "hm detected secondary "
					    "interface down");

					rdc_group_exit(krdc);

					/* dump async queues */
					rdc_dump_queue(index);
				}
			}

			/* dump allocated bufs */
			rdc_dump_alloc_bufs(ip);
		}

		syncdp = rdc_lookup_host(ip->srv->ri_hostname);
		mutex_enter(&syncdp->syncd_mutex);
		if (syncdp->link_down == 0) {
			/* Link has gone down, notify rdcsyncd daemon */
			syncdp->link_down = 1;
			if (syncdp->waiting) {
				syncdp->waiting = 0;
				cv_signal(&syncdp->syncd_cv);
			}
		}
		mutex_exit(&syncdp->syncd_mutex);
	} else {
		/* interface up */
		if (ip->if_down && ip->isprimary) {
			rdc_if_up(ip);
			ip->if_down = 0;
		}

		syncdp = rdc_lookup_host(ip->srv->ri_hostname);
		mutex_enter(&syncdp->syncd_mutex);
		if (syncdp->link_down) {
			/* Link has come back up */
			syncdp->link_down = 0;
		}
		mutex_exit(&syncdp->syncd_mutex);
	}
}
