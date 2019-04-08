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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */
#include <sys/types.h>
#include <sys/stream.h>
#include <sys/dlpi.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/strlog.h>
#include <sys/ddi.h>
#include <sys/cmn_err.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <sys/ethernet.h>
#include <inet/arp.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ip_ftable.h>

#include <sys/sunddi.h>
#include <sys/ksynch.h>

#include <sys/rds.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysmacros.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <net/if_types.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/ib.h>
#include <sys/ib/clients/rdsv3/rdsv3_impl.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

#include <sys/dls.h>
#include <sys/mac.h>
#include <sys/mac_client.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>

ddi_taskq_t		*rdsv3_taskq = NULL;
extern kmem_cache_t	*rdsv3_alloc_cache;

extern unsigned int	ip_ocsum(ushort_t *address, int halfword_count,
    unsigned int sum);

/*
 * Check if the IP interface named by `lifrp' is RDS-capable.
 */
boolean_t
rdsv3_capable_interface(struct lifreq *lifrp)
{
	char	ifname[LIFNAMSIZ];
	char	drv[MAXLINKNAMELEN];
	uint_t	ppa;
	char	*cp;

	RDSV3_DPRINTF4("rdsv3_capable_interface", "Enter");

	if (lifrp->lifr_type == IFT_IB)
		return (B_TRUE);

	/*
	 * Strip off the logical interface portion before getting
	 * intimate with the name.
	 */
	(void) strlcpy(ifname, lifrp->lifr_name, LIFNAMSIZ);
	if ((cp = strchr(ifname, ':')) != NULL)
		*cp = '\0';

	if (strcmp("lo0", ifname) == 0) {
		/*
		 * loopback is considered RDS-capable
		 */
		return (B_TRUE);
	}

	return (ddi_parse(ifname, drv, &ppa) == DDI_SUCCESS &&
	    rdsv3_if_lookup_by_name(drv));
}

int
rdsv3_do_ip_ioctl(ksocket_t so4, void **ipaddrs, int *size, int *nifs)
{
	struct lifnum		lifn;
	struct lifconf		lifc;
	struct lifreq		*lp, *rlp, lifr;
	int			rval = 0;
	int			numifs;
	int			bufsize, rbufsize;
	void			*buf, *rbuf;
	int			i, j, n, rc;

	*ipaddrs = NULL;
	*size = 0;
	*nifs = 0;

	RDSV3_DPRINTF4("rdsv3_do_ip_ioctl", "Enter");

retry_count:
	/* snapshot the current number of interfaces */
	lifn.lifn_family = PF_UNSPEC;
	lifn.lifn_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifn.lifn_count = 0;
	rval = ksocket_ioctl(so4, SIOCGLIFNUM, (intptr_t)&lifn, &rval,
	    CRED());
	if (rval != 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl",
		    "ksocket_ioctl returned: %d", rval);
		return (rval);
	}

	numifs = lifn.lifn_count;
	if (numifs <= 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl", "No interfaces found");
		return (0);
	}

	/* allocate extra room in case more interfaces appear */
	numifs += 10;

	/* get the interface names and ip addresses */
	bufsize = numifs * sizeof (struct lifreq);
	buf = kmem_alloc(bufsize, KM_SLEEP);

	lifc.lifc_family = AF_UNSPEC;
	lifc.lifc_flags = LIFC_NOXMIT | LIFC_TEMPORARY | LIFC_ALLZONES;
	lifc.lifc_len = bufsize;
	lifc.lifc_buf = buf;
	rc = ksocket_ioctl(so4, SIOCGLIFCONF, (intptr_t)&lifc, &rval, CRED());
	if (rc != 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl", "SIOCGLIFCONF failed");
		kmem_free(buf, bufsize);
		return (rc);
	}
	/* if our extra room is used up, try again */
	if (bufsize <= lifc.lifc_len) {
		kmem_free(buf, bufsize);
		buf = NULL;
		goto retry_count;
	}
	/* calc actual number of ifconfs */
	n = lifc.lifc_len / sizeof (struct lifreq);

	/*
	 * Count the RDS interfaces
	 */
	for (i = 0, j = 0, lp = lifc.lifc_req; i < n; i++, lp++) {

		/*
		 * Copy as the SIOCGLIFFLAGS ioctl is destructive
		 */
		bcopy(lp, &lifr, sizeof (struct lifreq));
		/*
		 * fetch the flags using the socket of the correct family
		 */
		switch (lifr.lifr_addr.ss_family) {
		case AF_INET:
			rc = ksocket_ioctl(so4, SIOCGLIFFLAGS, (intptr_t)&lifr,
			    &rval, CRED());
			break;
		default:
			continue;
		}

		if (rc != 0) continue;

		/*
		 * If we got the flags, skip uninteresting
		 * interfaces based on flags
		 */
		if ((lifr.lifr_flags & IFF_UP) != IFF_UP)
			continue;
		if (lifr.lifr_flags &
		    (IFF_ANYCAST|IFF_NOLOCAL|IFF_DEPRECATED))
			continue;
		if (!rdsv3_capable_interface(&lifr))
			continue;
		j++;
	}

	if (j <= 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl", "No RDS interfaces");
		kmem_free(buf, bufsize);
		return (rval);
	}

	numifs = j;

	/* This is the buffer we pass back */
	rbufsize = numifs * sizeof (struct lifreq);
	rbuf = kmem_alloc(rbufsize, KM_SLEEP);
	rlp = (struct lifreq *)rbuf;

	/*
	 * Examine the array of interfaces and filter uninteresting ones
	 */
	for (i = 0, lp = lifc.lifc_req; i < n; i++, lp++) {

		/*
		 * Copy the address as the SIOCGLIFFLAGS ioctl is destructive
		 */
		bcopy(lp, &lifr, sizeof (struct lifreq));
		/*
		 * fetch the flags using the socket of the correct family
		 */
		switch (lifr.lifr_addr.ss_family) {
		case AF_INET:
			rc = ksocket_ioctl(so4, SIOCGLIFFLAGS, (intptr_t)&lifr,
			    &rval, CRED());
			break;
		default:
			continue;
		}


		if (rc != 0) {
			RDSV3_DPRINTF2("rdsv3_do_ip_ioctl",
			    "ksocket_ioctl failed" " for %s", lifr.lifr_name);
			continue;
		}

		/*
		 * If we got the flags, skip uninteresting
		 * interfaces based on flags
		 */
		if ((lifr.lifr_flags & IFF_UP) != IFF_UP)
			continue;
		if (lifr.lifr_flags &
		    (IFF_ANYCAST|IFF_NOLOCAL|IFF_DEPRECATED))
			continue;
		if (!rdsv3_capable_interface(&lifr))
			continue;

		/* save the record */
		bcopy(lp, rlp, sizeof (struct lifreq));
		rlp->lifr_addr.ss_family = AF_INET_OFFLOAD;
		rlp++;
	}

	kmem_free(buf, bufsize);

	*ipaddrs = rbuf;
	*size = rbufsize;
	*nifs = numifs;

	RDSV3_DPRINTF4("rdsv3_do_ip_ioctl", "Return");

	return (rval);
}

/*
 * Check if the IP interface named by `ifrp' is RDS-capable.
 */
boolean_t
rdsv3_capable_interface_old(struct ifreq *ifrp)
{
	char	ifname[IFNAMSIZ];
	char	drv[MAXLINKNAMELEN];
	uint_t	ppa;
	char	*cp;

	RDSV3_DPRINTF4("rdsv3_capable_interface_old", "Enter");

	/*
	 * Strip off the logical interface portion before getting
	 * intimate with the name.
	 */
	(void) strlcpy(ifname, ifrp->ifr_name, IFNAMSIZ);
	if ((cp = strchr(ifname, ':')) != NULL)
		*cp = '\0';

	RDSV3_DPRINTF4("rdsv3_capable_interface_old", "ifname: %s", ifname);

	if ((strcmp("lo0", ifname) == 0) ||
	    (strncmp("ibd", ifname, 3) == 0)) {
		/*
		 * loopback and IB are considered RDS-capable
		 */
		return (B_TRUE);
	}

	return (ddi_parse(ifname, drv, &ppa) == DDI_SUCCESS &&
	    rdsv3_if_lookup_by_name(drv));
}

int
rdsv3_do_ip_ioctl_old(ksocket_t so4, void **ipaddrs, int *size, int *nifs)
{
	uint_t			ifn;
	struct ifconf		ifc;
	struct ifreq		*lp, *rlp, ifr;
	int			rval = 0;
	int			numifs;
	int			bufsize, rbufsize;
	void			*buf, *rbuf;
	int			i, j, n, rc;

	*ipaddrs = NULL;
	*size = 0;
	*nifs = 0;

	RDSV3_DPRINTF4("rdsv3_do_ip_ioctl_old", "Enter");

retry_count:
	rval = ksocket_ioctl(so4, SIOCGIFNUM, (intptr_t)&ifn, &rval,
	    CRED());
	if (rval != 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "ksocket_ioctl(SIOCGIFNUM) returned: %d", rval);
		return (rval);
	}

	numifs = ifn;
	if (numifs <= 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old", "No interfaces found");
		return (0);
	}

	/* allocate extra room in case more interfaces appear */
	numifs += 10;

	/* get the interface names and ip addresses */
	bufsize = numifs * sizeof (struct ifreq);
	buf = kmem_alloc(bufsize, KM_SLEEP);

	ifc.ifc_len = bufsize;
	ifc.ifc_buf = buf;
	rc = ksocket_ioctl(so4, SIOCGIFCONF, (intptr_t)&ifc, &rval, CRED());
	if (rc != 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "SIOCGLIFCONF failed: %d", rc);
		kmem_free(buf, bufsize);
		return (rc);
	}
	/* if our extra room is used up, try again */
	if (bufsize <= ifc.ifc_len) {
		kmem_free(buf, bufsize);
		buf = NULL;
		goto retry_count;
	}
	/* calc actual number of ifconfs */
	n = ifc.ifc_len / sizeof (struct ifreq);

	/*
	 * Count the RDS interfaces
	 */
	for (i = 0, j = 0, lp = ifc.ifc_req; i < n; i++, lp++) {

		/*
		 * Copy as the SIOCGIFFLAGS ioctl is destructive
		 */
		bcopy(lp, &ifr, sizeof (struct ifreq));
		/*
		 * fetch the flags using the socket of the correct family
		 */
		switch (ifr.ifr_addr.sa_family) {
		case AF_INET:
			rc = ksocket_ioctl(so4, SIOCGIFFLAGS, (intptr_t)&ifr,
			    &rval, CRED());
			break;
		default:
			continue;
		}

		if (rc != 0) continue;

		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "1. ifr_name: %s, flags: %d", ifr.ifr_name,
		    (ushort_t)ifr.ifr_flags);

		/*
		 * If we got the flags, skip uninteresting
		 * interfaces based on flags
		 */
		if ((((ushort_t)ifr.ifr_flags) & IFF_UP) != IFF_UP)
			continue;
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "2. ifr_name: %s, flags: %d", ifr.ifr_name,
		    (ushort_t)ifr.ifr_flags);
		if (((ushort_t)ifr.ifr_flags) &
		    (IFF_ANYCAST|IFF_NOLOCAL|IFF_DEPRECATED))
			continue;
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "3. ifr_name: %s, flags: %d", ifr.ifr_name,
		    (ushort_t)ifr.ifr_flags);
		if (!rdsv3_capable_interface_old(&ifr))
			continue;
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
		    "4. ifr_name: %s, flags: %d", ifr.ifr_name,
		    (ushort_t)ifr.ifr_flags);
		j++;
	}

	if (j <= 0) {
		RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old", "No RDS interfaces");
		kmem_free(buf, bufsize);
		return (rval);
	}

	numifs = j;

	/* This is the buffer we pass back */
	rbufsize = numifs * sizeof (struct ifreq);
	rbuf = kmem_alloc(rbufsize, KM_SLEEP);
	rlp = (struct ifreq *)rbuf;

	/*
	 * Examine the array of interfaces and filter uninteresting ones
	 */
	for (i = 0, lp = ifc.ifc_req; i < n; i++, lp++) {

		/*
		 * Copy the address as the SIOCGIFFLAGS ioctl is destructive
		 */
		bcopy(lp, &ifr, sizeof (struct ifreq));
		/*
		 * fetch the flags using the socket of the correct family
		 */
		switch (ifr.ifr_addr.sa_family) {
		case AF_INET:
			rc = ksocket_ioctl(so4, SIOCGIFFLAGS, (intptr_t)&ifr,
			    &rval, CRED());
			break;
		default:
			continue;
		}


		if (rc != 0) {
			RDSV3_DPRINTF2("rdsv3_do_ip_ioctl_old",
			    "ksocket_ioctl failed: %d for %s",
			    rc, ifr.ifr_name);
			continue;
		}

		/*
		 * If we got the flags, skip uninteresting
		 * interfaces based on flags
		 */
		if ((((ushort_t)ifr.ifr_flags) & IFF_UP) != IFF_UP)
			continue;
		if (((ushort_t)ifr.ifr_flags) &
		    (IFF_ANYCAST|IFF_NOLOCAL|IFF_DEPRECATED))
			continue;
		if (!rdsv3_capable_interface_old(&ifr))
			continue;

		/* save the record */
		bcopy(lp, rlp, sizeof (struct ifreq));
		rlp->ifr_addr.sa_family = AF_INET_OFFLOAD;
		rlp++;
	}

	kmem_free(buf, bufsize);

	*ipaddrs = rbuf;
	*size = rbufsize;
	*nifs = numifs;

	RDSV3_DPRINTF4("rdsv3_do_ip_ioctl_old", "Return");

	return (rval);
}

boolean_t
rdsv3_isloopback(ipaddr_t addr)
{
	ip_stack_t *ipst;

	ipst = netstack_find_by_zoneid(GLOBAL_ZONEID)->netstack_ip;
	ASSERT(ipst != NULL);
	if (ip_type_v4(addr, ipst) != IRE_LOOPBACK) {
		netstack_rele(ipst->ips_netstack);
		return (B_FALSE);
	}
	netstack_rele(ipst->ips_netstack);
	return (B_TRUE);
}

/*
 * Work Queue Implementation
 */

#define	RDSV3_WQ_THREAD_IDLE		0
#define	RDSV3_WQ_THREAD_RUNNING		1
#define	RDSV3_WQ_THREAD_FLUSHING	2
#define	RDSV3_WQ_THREAD_EXITING		3

/* worker thread */
void
rdsv3_worker_thread(void *arg)
{
	rdsv3_workqueue_struct_t *wq = arg;
	rdsv3_work_t *work;

	RDSV3_DPRINTF4("rdsv3_worker_thread", "Enter(wq: 0x%p)", wq);

	mutex_enter(&wq->wq_lock);
	work = list_remove_head(&wq->wq_queue);
	while (work) {
		mutex_exit(&wq->wq_lock);

		/* process work */
		work->func(work);

		mutex_enter(&wq->wq_lock);
		work = list_remove_head(&wq->wq_queue);
	}

	/* No more work, go home, until called again */
	if (wq->wq_state != RDSV3_WQ_THREAD_EXITING) {
		wq->wq_state = RDSV3_WQ_THREAD_IDLE;
	}
	mutex_exit(&wq->wq_lock);

	RDSV3_DPRINTF4("rdsv3_worker_thread", "Return(wq: 0x%p)", wq);
}

/* XXX */
void
rdsv3_flush_workqueue(rdsv3_workqueue_struct_t *wq)
{
	RDSV3_DPRINTF4("rdsv3_flush_workqueue", "Enter(wq: %p)", wq);

	mutex_enter(&wq->wq_lock);
	switch (wq->wq_state) {
	case RDSV3_WQ_THREAD_IDLE:
		/* nothing to do */
		ASSERT(list_is_empty(&wq->wq_queue));
		break;

	case RDSV3_WQ_THREAD_RUNNING:
		wq->wq_state = RDSV3_WQ_THREAD_FLUSHING;
		/* FALLTHRU */
	case RDSV3_WQ_THREAD_FLUSHING:
		/* already flushing, wait until the flushing is complete */
		do {
			mutex_exit(&wq->wq_lock);
			delay(drv_usectohz(1000000));
			mutex_enter(&wq->wq_lock);
		} while (wq->wq_state == RDSV3_WQ_THREAD_FLUSHING);
		break;
	case RDSV3_WQ_THREAD_EXITING:
		mutex_exit(&wq->wq_lock);
		rdsv3_worker_thread(wq);
		return;
	}
	mutex_exit(&wq->wq_lock);

	RDSV3_DPRINTF4("rdsv3_flush_workqueue", "Return(wq: %p)", wq);
}

void
rdsv3_queue_work(rdsv3_workqueue_struct_t *wq, rdsv3_work_t *wp)
{
	RDSV3_DPRINTF4("rdsv3_queue_work", "Enter(wq: %p, wp: %p)", wq, wp);

	mutex_enter(&wq->wq_lock);

	if (list_link_active(&wp->work_item)) {
		/* This is already in the queue, ignore this call */
		mutex_exit(&wq->wq_lock);
		RDSV3_DPRINTF3("rdsv3_queue_work", "already queued: %p", wp);
		return;
	}

	switch (wq->wq_state) {
	case RDSV3_WQ_THREAD_RUNNING:
		list_insert_tail(&wq->wq_queue, wp);
		mutex_exit(&wq->wq_lock);
		break;

	case RDSV3_WQ_THREAD_FLUSHING:
		do {
			mutex_exit(&wq->wq_lock);
			delay(drv_usectohz(1000000));
			mutex_enter(&wq->wq_lock);
		} while (wq->wq_state == RDSV3_WQ_THREAD_FLUSHING);

		if (wq->wq_state == RDSV3_WQ_THREAD_RUNNING) {
			list_insert_tail(&wq->wq_queue, wp);
			mutex_exit(&wq->wq_lock);
			break;
		}
		/* FALLTHRU */

	case RDSV3_WQ_THREAD_IDLE:
		list_insert_tail(&wq->wq_queue, wp);
		wq->wq_state = RDSV3_WQ_THREAD_RUNNING;
		mutex_exit(&wq->wq_lock);

		(void) ddi_taskq_dispatch(rdsv3_taskq, rdsv3_worker_thread, wq,
		    DDI_SLEEP);
		break;

	case RDSV3_WQ_THREAD_EXITING:
		mutex_exit(&wq->wq_lock);
		break;
	}

	RDSV3_DPRINTF4("rdsv3_queue_work", "Return(wq: %p, wp: %p)", wq, wp);
}

/* timeout handler for delayed work queuing */
void
rdsv3_work_timeout_handler(void *arg)
{
	rdsv3_delayed_work_t *dwp = (rdsv3_delayed_work_t *)arg;

	RDSV3_DPRINTF4("rdsv3_work_timeout_handler",
	    "Enter(wq: %p, wp: %p)", dwp->wq, &dwp->work);

	mutex_enter(&dwp->lock);
	dwp->timeid = 0;
	mutex_exit(&dwp->lock);

	mutex_enter(&dwp->wq->wq_lock);
	dwp->wq->wq_pending--;
	if (dwp->wq->wq_state == RDSV3_WQ_THREAD_EXITING) {
		mutex_exit(&dwp->wq->wq_lock);
		return;
	}
	mutex_exit(&dwp->wq->wq_lock);

	rdsv3_queue_work(dwp->wq, &dwp->work);

	RDSV3_DPRINTF4("rdsv3_work_timeout_handler",
	    "Return(wq: %p, wp: %p)", dwp->wq, &dwp->work);
}

void
rdsv3_queue_delayed_work(rdsv3_workqueue_struct_t *wq,
    rdsv3_delayed_work_t *dwp, uint_t delay)
{
	RDSV3_DPRINTF4("rdsv3_queue_delayed_work",
	    "Enter(wq: %p, wp: %p)", wq, dwp);

	if (delay == 0) {
		rdsv3_queue_work(wq, &dwp->work);
		return;
	}

	mutex_enter(&wq->wq_lock);
	if (wq->wq_state == RDSV3_WQ_THREAD_EXITING) {
		mutex_exit(&wq->wq_lock);
		RDSV3_DPRINTF4("rdsv3_queue_delayed_work",
		    "WQ exiting - don't queue (wq: %p, wp: %p)", wq, dwp);
		return;
	}
	wq->wq_pending++;
	mutex_exit(&wq->wq_lock);

	mutex_enter(&dwp->lock);
	if (dwp->timeid == 0) {
		dwp->wq = wq;
		dwp->timeid = timeout(rdsv3_work_timeout_handler, dwp,
		    jiffies + (delay * rdsv3_one_sec_in_hz));
		mutex_exit(&dwp->lock);
	} else {
		mutex_exit(&dwp->lock);
		RDSV3_DPRINTF4("rdsv3_queue_delayed_work", "Already queued: %p",
		    dwp);
		mutex_enter(&wq->wq_lock);
		wq->wq_pending--;
		mutex_exit(&wq->wq_lock);
	}

	RDSV3_DPRINTF4("rdsv3_queue_delayed_work",
	    "Return(wq: %p, wp: %p)", wq, dwp);
}

void
rdsv3_cancel_delayed_work(rdsv3_delayed_work_t *dwp)
{
	RDSV3_DPRINTF4("rdsv3_cancel_delayed_work",
	    "Enter(wq: %p, dwp: %p)", dwp->wq, dwp);

	mutex_enter(&dwp->lock);
	if (dwp->timeid != 0) {
		(void) untimeout(dwp->timeid);
		dwp->timeid = 0;
	} else {
		RDSV3_DPRINTF4("rdsv3_cancel_delayed_work",
		    "Nothing to cancel (wq: %p, dwp: %p)", dwp->wq, dwp);
		mutex_exit(&dwp->lock);
		return;
	}
	mutex_exit(&dwp->lock);

	mutex_enter(&dwp->wq->wq_lock);
	dwp->wq->wq_pending--;
	mutex_exit(&dwp->wq->wq_lock);

	RDSV3_DPRINTF4("rdsv3_cancel_delayed_work",
	    "Return(wq: %p, dwp: %p)", dwp->wq, dwp);
}

void
rdsv3_destroy_task_workqueue(rdsv3_workqueue_struct_t *wq)
{
	RDSV3_DPRINTF2("rdsv3_destroy_workqueue", "Enter");

	ASSERT(wq);

	mutex_enter(&wq->wq_lock);
	wq->wq_state = RDSV3_WQ_THREAD_EXITING;

	while (wq->wq_pending > 0) {
		mutex_exit(&wq->wq_lock);
		delay(drv_usectohz(1000000));
		mutex_enter(&wq->wq_lock);
	};
	mutex_exit(&wq->wq_lock);

	rdsv3_flush_workqueue(wq);

	list_destroy(&wq->wq_queue);
	mutex_destroy(&wq->wq_lock);
	kmem_free(wq, sizeof (rdsv3_workqueue_struct_t));

	ASSERT(rdsv3_taskq);
	ddi_taskq_destroy(rdsv3_taskq);

	wq = NULL;
	rdsv3_taskq = NULL;

	RDSV3_DPRINTF2("rdsv3_destroy_workqueue", "Return");
}

/* ARGSUSED */
void
rdsv3_rdma_init_worker(struct rdsv3_work_s *work)
{
	rdsv3_rdma_init();
}

#define	RDSV3_NUM_TASKQ_THREADS	1
rdsv3_workqueue_struct_t *
rdsv3_create_task_workqueue(char *name)
{
	rdsv3_workqueue_struct_t	*wq;

	RDSV3_DPRINTF2("create_singlethread_workqueue", "Enter (dip: %p)",
	    rdsv3_dev_info);

	rdsv3_taskq = ddi_taskq_create(rdsv3_dev_info, name,
	    RDSV3_NUM_TASKQ_THREADS, TASKQ_DEFAULTPRI, 0);
	if (rdsv3_taskq == NULL) {
		RDSV3_DPRINTF2(__FILE__,
		    "ddi_taskq_create failed for rdsv3_taskq");
		return (NULL);
	}

	wq = kmem_zalloc(sizeof (rdsv3_workqueue_struct_t), KM_NOSLEEP);
	if (wq == NULL) {
		RDSV3_DPRINTF2(__FILE__, "kmem_zalloc failed for wq");
		ddi_taskq_destroy(rdsv3_taskq);
		return (NULL);
	}

	list_create(&wq->wq_queue, sizeof (struct rdsv3_work_s),
	    offsetof(struct rdsv3_work_s, work_item));
	mutex_init(&wq->wq_lock, NULL, MUTEX_DRIVER, NULL);
	wq->wq_state = RDSV3_WQ_THREAD_IDLE;
	wq->wq_pending = 0;
	rdsv3_one_sec_in_hz = drv_usectohz(1000000);

	RDSV3_DPRINTF2("create_singlethread_workqueue", "Return");

	return (wq);
}

/*
 * Implementation for struct sock
 */

void
rdsv3_sock_exit_data(struct rsock *sk)
{
	struct rdsv3_sock *rs = sk->sk_protinfo;

	RDSV3_DPRINTF4("rdsv3_sock_exit_data", "rs: %p sk: %p", rs, sk);

	ASSERT(rs != NULL);
	ASSERT(rdsv3_sk_sock_flag(sk, SOCK_DEAD));

	rs->rs_sk = NULL;

	list_destroy(&rs->rs_send_queue);
	list_destroy(&rs->rs_notify_queue);
	list_destroy(&rs->rs_recv_queue);

	rw_destroy(&rs->rs_recv_lock);
	mutex_destroy(&rs->rs_lock);

	mutex_destroy(&rs->rs_rdma_lock);
	avl_destroy(&rs->rs_rdma_keys);

	mutex_destroy(&rs->rs_conn_lock);
	mutex_destroy(&rs->rs_congested_lock);
	cv_destroy(&rs->rs_congested_cv);

	rdsv3_exit_waitqueue(sk->sk_sleep);
	kmem_free(sk->sk_sleep, sizeof (rdsv3_wait_queue_t));
	mutex_destroy(&sk->sk_lock);

	kmem_cache_free(rdsv3_alloc_cache, sk);
	RDSV3_DPRINTF4("rdsv3_sock_exit_data", "rs: %p sk: %p", rs, sk);
}

/* XXX - figure out right values */
#define	RDSV3_RECV_HIWATER	(256 * 1024)
#define	RDSV3_RECV_LOWATER	128
#define	RDSV3_XMIT_HIWATER	(256 * 1024)
#define	RDSV3_XMIT_LOWATER	1024

struct rsock *
rdsv3_sk_alloc()
{
	struct rsock *sk;

	sk = kmem_cache_alloc(rdsv3_alloc_cache, KM_SLEEP);
	if (sk == NULL) {
		RDSV3_DPRINTF2("rdsv3_create", "kmem_cache_alloc failed");
		return (NULL);
	}

	bzero(sk, sizeof (struct rsock) + sizeof (struct rdsv3_sock));
	return (sk);
}

void
rdsv3_sock_init_data(struct rsock *sk)
{
	sk->sk_sleep = kmem_zalloc(sizeof (rdsv3_wait_queue_t), KM_SLEEP);
	rdsv3_init_waitqueue(sk->sk_sleep);

	mutex_init(&sk->sk_lock, NULL, MUTEX_DRIVER, NULL);
	sk->sk_refcount = 1;
	sk->sk_protinfo = (struct rdsv3_sock *)(sk + 1);
	sk->sk_sndbuf = RDSV3_XMIT_HIWATER;
	sk->sk_rcvbuf = RDSV3_RECV_HIWATER;
}

/*
 * Connection cache
 */
/* ARGSUSED */
int
rdsv3_conn_constructor(void *buf, void *arg, int kmflags)
{
	struct rdsv3_connection *conn = buf;

	bzero(conn, sizeof (struct rdsv3_connection));

	conn->c_next_tx_seq = 1;
	mutex_init(&conn->c_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&conn->c_send_lock, NULL, MUTEX_DRIVER, NULL);
	conn->c_send_generation = 1;
	conn->c_senders = 0;

	list_create(&conn->c_send_queue, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_conn_item));
	list_create(&conn->c_retrans, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_conn_item));
	return (0);
}

/* ARGSUSED */
void
rdsv3_conn_destructor(void *buf, void *arg)
{
	struct rdsv3_connection *conn = buf;

	ASSERT(list_is_empty(&conn->c_send_queue));
	ASSERT(list_is_empty(&conn->c_retrans));
	list_destroy(&conn->c_send_queue);
	list_destroy(&conn->c_retrans);
	mutex_destroy(&conn->c_send_lock);
	mutex_destroy(&conn->c_lock);
}

int
rdsv3_conn_compare(const void *conn1, const void *conn2)
{
	uint32_be_t	laddr1, faddr1, laddr2, faddr2;

	laddr1 = ((rdsv3_conn_info_t *)conn1)->c_laddr;
	laddr2 = ((struct rdsv3_connection *)conn2)->c_laddr;

	if (laddr1 == laddr2) {
		faddr1 = ((rdsv3_conn_info_t *)conn1)->c_faddr;
		faddr2 = ((struct rdsv3_connection *)conn2)->c_faddr;
		if (faddr1 == faddr2)
			return (0);
		if (faddr1 < faddr2)
			return (-1);
		return (1);
	}

	if (laddr1 < laddr2)
		return (-1);

	return (1);
}

/* rdsv3_ib_incoming cache */
/* ARGSUSED */
int
rdsv3_ib_inc_constructor(void *buf, void *arg, int kmflags)
{
	list_create(&((struct rdsv3_ib_incoming *)buf)->ii_frags,
	    sizeof (struct rdsv3_page_frag),
	    offsetof(struct rdsv3_page_frag, f_item));

	return (0);
}

/* ARGSUSED */
void
rdsv3_ib_inc_destructor(void *buf, void *arg)
{
	list_destroy(&((struct rdsv3_ib_incoming *)buf)->ii_frags);
}

/* ib_frag_slab cache */
/* ARGSUSED */
int
rdsv3_ib_frag_constructor(void *buf, void *arg, int kmflags)
{
	struct rdsv3_page_frag *frag = (struct rdsv3_page_frag *)buf;
	struct rdsv3_ib_device *rds_ibdev = (struct rdsv3_ib_device *)arg;
	ibt_iov_attr_t iov_attr;
	ibt_iov_t iov_arr[1];
	ibt_all_wr_t wr;

	bzero(frag, sizeof (struct rdsv3_page_frag));
	list_link_init(&frag->f_item);

	frag->f_page = kmem_alloc(PAGE_SIZE, kmflags);
	if (frag->f_page == NULL) {
		RDSV3_DPRINTF2("rdsv3_ib_frag_constructor",
		    "kmem_alloc for %d failed", PAGE_SIZE);
		return (-1);
	}
	frag->f_offset = 0;

	iov_attr.iov_as = NULL;
	iov_attr.iov = &iov_arr[0];
	iov_attr.iov_buf = NULL;
	iov_attr.iov_list_len = 1;
	iov_attr.iov_wr_nds = 1;
	iov_attr.iov_lso_hdr_sz = 0;
	iov_attr.iov_flags = IBT_IOV_SLEEP | IBT_IOV_RECV;

	iov_arr[0].iov_addr = frag->f_page;
	iov_arr[0].iov_len = PAGE_SIZE;

	wr.recv.wr_nds = 1;
	wr.recv.wr_sgl = &frag->f_sge;

	if (ibt_map_mem_iov(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    &iov_attr, &wr, &frag->f_mapped) != IBT_SUCCESS) {
		RDSV3_DPRINTF2("rdsv3_ib_frag_constructor",
		    "ibt_map_mem_iov failed");
		kmem_free(frag->f_page, PAGE_SIZE);
		return (-1);
	}

	return (0);
}

/* ARGSUSED */
void
rdsv3_ib_frag_destructor(void *buf, void *arg)
{
	struct rdsv3_page_frag *frag = (struct rdsv3_page_frag *)buf;
	struct rdsv3_ib_device *rds_ibdev = (struct rdsv3_ib_device *)arg;

	/* unmap the page */
	if (ibt_unmap_mem_iov(ib_get_ibt_hca_hdl(rds_ibdev->dev),
	    frag->f_mapped) != IBT_SUCCESS)
		RDSV3_DPRINTF2("rdsv3_ib_frag_destructor",
		    "ibt_unmap_mem_iov failed");

	/* free the page */
	kmem_free(frag->f_page, PAGE_SIZE);
}

/* loop.c */
extern kmutex_t loop_conns_lock;
extern list_t loop_conns;

struct rdsv3_loop_connection
{
	struct list_node loop_node;
	struct rdsv3_connection *conn;
};

void
rdsv3_loop_init(void)
{
	list_create(&loop_conns, sizeof (struct rdsv3_loop_connection),
	    offsetof(struct rdsv3_loop_connection, loop_node));
	mutex_init(&loop_conns_lock, NULL, MUTEX_DRIVER, NULL);
}

/* rdma.c */
/* IB Rkey is used here for comparison */
int
rdsv3_mr_compare(const void *mr1, const void *mr2)
{
	uint32_t key1 = *(uint32_t *)mr1;
	uint32_t key2 = ((struct rdsv3_mr *)mr2)->r_key;

	if (key1 < key2)
		return (-1);
	if (key1 > key2)
		return (1);
	return (0);
}

/* transport.c */
extern struct rdsv3_transport *transports[];
extern krwlock_t		trans_sem;

void
rdsv3_trans_exit(void)
{
	struct rdsv3_transport *trans;
	int i;

	RDSV3_DPRINTF2("rdsv3_trans_exit", "Enter");

	/* currently, only IB transport */
	rw_enter(&trans_sem, RW_READER);
	trans = NULL;
	for (i = 0; i < RDS_TRANS_COUNT; i++) {
		if (transports[i]) {
			trans = transports[i];
			break;
		}
	}
	rw_exit(&trans_sem);

	/* trans->exit() will remove the trans from the list */
	if (trans)
		trans->exit();

	rw_destroy(&trans_sem);

	RDSV3_DPRINTF2("rdsv3_trans_exit", "Return");
}

void
rdsv3_trans_init()
{
	RDSV3_DPRINTF2("rdsv3_trans_init", "Enter");

	rw_init(&trans_sem, NULL, RW_DRIVER, NULL);

	RDSV3_DPRINTF2("rdsv3_trans_init", "Return");
}

int
rdsv3_put_cmsg(struct nmsghdr *msg, int level, int type, size_t size,
    void *payload)
{
	struct cmsghdr *cp;
	char *bp;
	size_t cmlen;
	size_t cmspace;
	size_t bufsz;

	RDSV3_DPRINTF4("rdsv3_put_cmsg",
	    "Enter(msg: %p level: %d type: %d sz: %d)",
	    msg, level, type, size);

	if (msg == NULL || msg->msg_controllen == 0) {
		return (0);
	}
	/* check for first cmsg or this is another cmsg to be appended */
	if (msg->msg_control == NULL)
		msg->msg_controllen = 0;

	cmlen = CMSG_LEN(size);
	cmspace = CMSG_SPACE(size);
	bufsz = msg->msg_controllen + cmspace;

	/* extend the existing cmsg to append the next cmsg */
	bp = kmem_alloc(bufsz, KM_SLEEP);
	if (msg->msg_control) {
		bcopy(msg->msg_control, bp, msg->msg_controllen);
		kmem_free(msg->msg_control, (size_t)msg->msg_controllen);
	}

	/* assign payload the proper cmsg location */
	cp = (struct cmsghdr *)(bp + msg->msg_controllen);
	cp->cmsg_len = cmlen;
	cp->cmsg_level = level;
	cp->cmsg_type = type;

	bcopy(payload, CMSG_DATA(cp), cmlen -
	    (unsigned int)_CMSG_DATA_ALIGN(sizeof (struct cmsghdr)));

	msg->msg_control = bp;
	msg->msg_controllen = bufsz;

	RDSV3_DPRINTF4("rdsv3_put_cmsg", "Return(cmsg_len: %d)", cp->cmsg_len);

	return (0);
}

/* ARGSUSED */
int
rdsv3_verify_bind_address(ipaddr_t addr)
{
	return (1);
}

/* checksum */
uint16_t
rdsv3_ip_fast_csum(void *hdr, size_t length)
{
	return (0xffff &
	    (uint16_t)(~ip_ocsum((ushort_t *)hdr, (int)length <<1, 0)));
}

/* scatterlist implementation */
/* ARGSUSED */
caddr_t
rdsv3_ib_sg_dma_address(ib_device_t *dev, struct rdsv3_scatterlist *scat,
    uint_t offset)
{
	return (0);
}

uint_t
rdsv3_ib_dma_map_sg(struct ib_device *dev, struct rdsv3_scatterlist *scat,
    uint_t num)
{
	struct rdsv3_scatterlist *s, *first;
	ibt_iov_t *iov;
	ibt_wr_ds_t *sgl;
	ibt_iov_attr_t iov_attr;
	ibt_send_wr_t swr;
	uint_t i;

	RDSV3_DPRINTF4("rdsv3_ib_dma_map_sg", "scat %p, num: %d", scat, num);

	s = first = &scat[0];
	ASSERT(first->mihdl == NULL);

	iov = kmem_alloc(num * sizeof (ibt_iov_t), KM_SLEEP);
	sgl = kmem_zalloc((num * 2) *  sizeof (ibt_wr_ds_t), KM_SLEEP);

	for (i = 0; i < num; i++, s++) {
		iov[i].iov_addr = s->vaddr;
		iov[i].iov_len = s->length;
	}

	iov_attr.iov_as = NULL;
	iov_attr.iov = iov;
	iov_attr.iov_buf = NULL;
	iov_attr.iov_list_len = num;
	iov_attr.iov_wr_nds = num * 2;
	iov_attr.iov_lso_hdr_sz = 0;
	iov_attr.iov_flags = IBT_IOV_SLEEP;

	swr.wr_sgl = sgl;

	i = ibt_map_mem_iov(ib_get_ibt_hca_hdl(dev),
	    &iov_attr, (ibt_all_wr_t *)&swr, &first->mihdl);
	kmem_free(iov, num * sizeof (ibt_iov_t));
	if (i != IBT_SUCCESS) {
		RDSV3_DPRINTF2("rdsv3_ib_dma_map_sg",
		    "ibt_map_mem_iov returned: %d", i);
		return (0);
	}

	s = first;
	for (i = 0; i < num; i++, s++, sgl++) {
		s->sgl = sgl;
	}

	return (num);
}

void
rdsv3_ib_dma_unmap_sg(ib_device_t *dev, struct rdsv3_scatterlist *scat,
    uint_t num)
{
	/* Zero length messages have no scatter gather entries */
	if (num != 0) {
		ASSERT(scat->mihdl != NULL);
		ASSERT(scat->sgl != NULL);

		(void) ibt_unmap_mem_iov(ib_get_ibt_hca_hdl(dev), scat->mihdl);

		kmem_free(scat->sgl, (num * 2)  * sizeof (ibt_wr_ds_t));
		scat->sgl = NULL;
		scat->mihdl = NULL;
	}
}

int
rdsv3_ib_alloc_hdrs(ib_device_t *dev, struct rdsv3_ib_connection *ic)
{
	caddr_t addr;
	size_t size;
	ibt_mr_attr_t mr_attr;
	ibt_mr_desc_t mr_desc;
	ibt_mr_hdl_t mr_hdl;
	int ret;

	RDSV3_DPRINTF4("rdsv3_ib_alloc_hdrs", "Enter(dev: %p)", dev);

	ASSERT(ic->i_mr == NULL);

	size = (ic->i_send_ring.w_nr + ic->i_recv_ring.w_nr + 1) *
	    sizeof (struct rdsv3_header);

	addr = kmem_zalloc(size, KM_NOSLEEP);
	if (addr == NULL)
		return (-1);

	mr_attr.mr_vaddr = (ib_vaddr_t)(uintptr_t)addr;
	mr_attr.mr_len = size;
	mr_attr.mr_as = NULL;
	mr_attr.mr_flags = IBT_MR_ENABLE_LOCAL_WRITE;
	ret = ibt_register_mr(ib_get_ibt_hca_hdl(dev), RDSV3_PD2PDHDL(ic->i_pd),
	    &mr_attr, &mr_hdl, &mr_desc);
	if (ret != IBT_SUCCESS) {
		RDSV3_DPRINTF2("rdsv3_ib_alloc_hdrs",
		    "ibt_register_mr returned: " "%d", ret);
		return (-1);
	}

	ic->i_mr =
	    (struct rdsv3_hdrs_mr *)kmem_alloc(sizeof (struct rdsv3_hdrs_mr),
	    KM_SLEEP);
	ic->i_mr->addr = addr;
	ic->i_mr->size = size;
	ic->i_mr->hdl =	mr_hdl;
	ic->i_mr->lkey = mr_desc.md_lkey;

	ic->i_send_hdrs = (struct rdsv3_header *)addr;
	ic->i_send_hdrs_dma = (uint64_t)(uintptr_t)addr;

	ic->i_recv_hdrs = (struct rdsv3_header *)(addr +
	    (ic->i_send_ring.w_nr * sizeof (struct rdsv3_header)));
	ic->i_recv_hdrs_dma = (uint64_t)(uintptr_t)(addr +
	    (ic->i_send_ring.w_nr * sizeof (struct rdsv3_header)));

	ic->i_ack = (struct rdsv3_header *)(addr +
	    ((ic->i_send_ring.w_nr + ic->i_recv_ring.w_nr) *
	    sizeof (struct rdsv3_header)));
	ic->i_ack_dma = (uint64_t)(uintptr_t)(addr +
	    ((ic->i_send_ring.w_nr + ic->i_recv_ring.w_nr) *
	    sizeof (struct rdsv3_header)));

	RDSV3_DPRINTF4("rdsv3_ib_alloc_hdrs", "Return(dev: %p)", dev);

	return (0);
}

void
rdsv3_ib_free_hdrs(ib_device_t *dev, struct rdsv3_ib_connection *ic)
{
	RDSV3_DPRINTF4("rdsv3_ib_free_hdrs", "Enter(dev: %p)", dev);
	ASSERT(ic->i_mr != NULL);

	ic->i_send_hdrs = NULL;
	ic->i_send_hdrs_dma = 0;

	ic->i_recv_hdrs = NULL;
	ic->i_recv_hdrs_dma = 0;

	ic->i_ack = NULL;
	ic->i_ack_dma = 0;

	(void) ibt_deregister_mr(ib_get_ibt_hca_hdl(dev), ic->i_mr->hdl);

	kmem_free(ic->i_mr->addr, ic->i_mr->size);
	kmem_free(ic->i_mr, sizeof (struct rdsv3_hdrs_mr));

	ic->i_mr = NULL;
	RDSV3_DPRINTF4("rdsv3_ib_free_hdrs", "Return(dev: %p)", dev);
}

/*
 * atomic_add_unless - add unless the number is a given value
 * @v: pointer of type atomic_t
 * @a: the amount to add to v...
 * @u: ...unless v is equal to u.
 *
 * Atomically adds @a to @v, so long as it was not @u.
 * Returns non-zero if @v was not @u, and zero otherwise.
 */
int
atomic_add_unless(atomic_t *v, uint_t a, ulong_t u)
{
	uint_t c, old;

	c = *v;
	while (c != u && (old = atomic_cas_uint(v, c, c + a)) != c) {
		c = old;
	}
	return ((ulong_t)c != u);
}
