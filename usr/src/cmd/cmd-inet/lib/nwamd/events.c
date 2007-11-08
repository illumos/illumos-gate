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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains routines to retrieve events from the system and package
 * them for high level processing.
 *
 * struct np_event is the basic event structure.  The np_event structure and
 * its npe_name member are allocated using malloc(3c).  free_event() frees both
 * the npe_name member and the associated np_event structure.
 *
 * np_queue_add_event() and np_queue_get_event() provide functionality for
 * adding events to a queue and blocking on that queue for an event.
 *
 * Functions of the form addevent_*() provide the mechanism to cook down a
 * higher level event into an np_event and put it on the queue.
 *
 * routing_events() reads routing messages off of an IPv4 routing socket and
 * by calling addevent_*() functions places appropriate events on the queue.
 *
 * start_event_collection() creates a thread to run routing_events() and one
 * to run periodic_wireless_scan() in.  Finally it does an initial collection
 * of information from each interface currently known.
 */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <libsysevent.h>
#include <net/if.h>
#include <net/route.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/sysevent/eventdefs.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

struct np_event *equeue = NULL;
static struct np_event *equeue_end = NULL;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_t routing, scan;

static void printaddrs(int mask, void *address);
static char *printaddr(void **address);
static void *getaddr(int addrid, int mask, void *address);

union rtm_buf
{
	/* Routing information. */
	struct
	{
		struct rt_msghdr rtm;
		struct sockaddr_storage addr[RTAX_MAX];
	} r;

	/* Interface information. */
	struct
	{
		struct if_msghdr ifm;
		struct sockaddr_storage addr[RTAX_MAX];
	} im;

	/* Interface address information. */
	struct
	{
		struct ifa_msghdr ifa;
		struct sockaddr_storage addr[RTAX_MAX];
	} ia;
};

void
free_event(struct np_event *e)
{
	free(e->npe_name);
	free(e);
}

void
np_queue_add_event(struct np_event *e)
{
	(void) pthread_mutex_lock(&queue_mutex);
	if (equeue_end != NULL) {
		equeue_end->npe_next = e;
		equeue_end = e;
	} else {
		equeue = equeue_end = e;
	}
	equeue_end->npe_next = NULL;
	(void) pthread_cond_signal(&queue_cond);
	(void) pthread_mutex_unlock(&queue_mutex);
}

/*
 * Blocking getevent.  This routine will block until there is an event for
 * it to return.
 */
struct np_event *
np_queue_get_event(void)
{
	struct np_event *rv = NULL;

	(void) pthread_mutex_lock(&queue_mutex);

	while (equeue == NULL)
		(void) pthread_cond_wait(&queue_cond, &queue_mutex);

	rv = equeue;
	equeue = equeue->npe_next;
	if (equeue == NULL)
		equeue_end = NULL;

	(void) pthread_mutex_unlock(&queue_mutex);

	rv->npe_next = NULL;
	return (rv);
}

const char *
npe_type_str(enum np_event_type type)
{
	switch (type) {
		case EV_ROUTING:
			return ("ROUTING");
		case EV_SYS:
			return ("SYS");
		case EV_TIMER:
			return ("TIMER");
		case EV_SHUTDOWN:
			return ("SHUTDOWN");
		case EV_NEWADDR:
			return ("NEWADDR");
		default:
			return ("unknown");
	}
}

static void
addevent_routing_ifa(struct ifa_msghdr *ifa, const char *name)
{
	struct np_event *e;

	dprintf("addevent_routing_ifa");
	if (ifa->ifam_index == 0) {
		/* what is this? */
		dprintf("tossing index 0 routing event");
		return;
	}

	e = calloc(1, sizeof (*e));
	if (e == NULL) {
		syslog(LOG_ERR, "calloc failed");
		return;
	}

	switch (ifa->ifam_type) {
	case RTM_NEWADDR:
		assert(name != NULL);
		e->npe_type = EV_NEWADDR;
		if ((e->npe_name = strdup(name)) == NULL) {
			syslog(LOG_ERR, "strdup failed");
			free(e);
			return;
		}
		dprintf("adding event type %s name %s to queue",
		    npe_type_str(e->npe_type), STRING(e->npe_name));
		np_queue_add_event(e);
		break;

	default:
		free(e);
		dprintf("unhandled type in addevent_routing_ifa %d",
		    ifa->ifam_type);
		break;
	}
}

static void
addevent_routing_msghdr(struct if_msghdr *ifm, const char *name)
{
	struct np_event *e;

	dprintf("addevent_routing_msghdr");
	if (ifm->ifm_index == 0) {
		/* what is this? */
		dprintf("tossing index 0 routing event");
		return;
	}

	switch (ifm->ifm_type) {
	case RTM_IFINFO:
		assert(name != NULL);
		e = calloc(1, sizeof (*e));
		if (e == NULL) {
			syslog(LOG_ERR, "calloc failed");
			return;
		}

		e->npe_type = EV_ROUTING;
		if ((e->npe_name = strdup(name)) == NULL) {
			syslog(LOG_ERR, "strdup failed");
			free(e);
			return;
		}
		dprintf("flags = %x, IFF_RUNNING = %x", ifm->ifm_flags,
		    IFF_RUNNING);
		dprintf("adding event type %s name %s to queue",
		    npe_type_str(e->npe_type), STRING(e->npe_name));
		np_queue_add_event(e);
		break;

	default:
		dprintf("unhandled type in addevent_routing_msghdr %d",
		    ifm->ifm_type);
		break;
	}
}

static const char *
rtmtype_str(int type)
{
	static char typestr[12]; /* strlen("type ") + enough for an int */

	switch (type) {
		case RTM_ADD:
			return ("ADD");
		case RTM_DELETE:
			return ("DELETE");
		case RTM_NEWADDR:
			return ("NEWADDR");
		case RTM_DELADDR:
			return ("DELADDR");
		case RTM_IFINFO:
			return ("IFINFO");
		default:
			(void) snprintf(typestr, sizeof (typestr), "type %d",
			    type);
			return (typestr);
	}
}

/* ARGSUSED */
static void *
routing_events(void *arg)
{
	int rtsock;
	int n;
	union rtm_buf buffer;
	struct rt_msghdr *rtm;
	struct ifa_msghdr *ifa;
	struct if_msghdr *ifm;

	/*
	 * We use v4 interfaces as proxies for links so those are the only
	 * routing messages we need to listen to.  Look at the comments in
	 * structures.h for more information about the split between the
	 * llp and interfaces.
	 */
	rtsock = socket(AF_ROUTE, SOCK_RAW, AF_INET);
	if (rtsock == -1) {
		syslog(LOG_ERR, "failed to open routing socket: %m");
		exit(EXIT_FAILURE);
	}

	dprintf("routing socket %d", rtsock);

	for (;;) {
		struct interface *ifp;
		char *addrs, *if_name;
		struct sockaddr_dl *addr_dl;
		struct sockaddr *addr;

		rtm = &buffer.r.rtm;
		n = read(rtsock, &buffer, sizeof (buffer));
		if (n == -1 && errno == EAGAIN) {
			continue;
		} else if (n == -1) {
			syslog(LOG_ERR, "error reading routing socket "
			    "%d: %m", rtsock);
			/* Low likelihood.  What's recovery path?  */
			continue;
		}

		if (rtm->rtm_msglen < n) {
			syslog(LOG_ERR, "only read %d bytes from "
			    "routing socket but message claims to be "
			    "of length %d", rtm->rtm_msglen);
			continue;
		}

		if (rtm->rtm_version != RTM_VERSION) {
			syslog(LOG_ERR, "tossing routing message of "
			    "version %d type %d", rtm->rtm_version,
			    rtm->rtm_type);
			continue;
		}

		if (rtm->rtm_msglen != n) {
			dprintf("routing message of %d size came from "
			    "read of %d on socket %d", rtm->rtm_msglen,
			    n, rtsock);
		}

		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
			ifa = (void *)rtm;
			addrs = (char *)ifa + sizeof (*ifa);

			dprintf("routing message NEWADDR: index %d flags %x",
			    ifa->ifam_index, ifa->ifam_flags);
			printaddrs(ifa->ifam_addrs, addrs);

			if ((addr = (struct sockaddr *)getaddr(RTA_IFA,
			    ifa->ifam_addrs, addrs)) == NULL)
				break;

			if ((addr_dl = (struct sockaddr_dl *)getaddr
			    (RTA_IFP, ifa->ifam_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data;
			ifp = get_interface(if_name);
			if (ifp == NULL) {
				dprintf("no interface struct for %s; ignoring "
				    "message", STRING(if_name));
				break;
			}

			/* if no cached address, cache it */
			if (ifp->if_ipaddr == NULL) {
				ifp->if_ipaddr = dupsockaddr(addr);
				dprintf("cached address %s for link %s",
				    printaddr((void **)&addr), if_name);
				addevent_routing_ifa(ifa, if_name);
			} else if (!cmpsockaddr(addr, ifp->if_ipaddr)) {
				free(ifp->if_ipaddr);
				ifp->if_ipaddr = dupsockaddr(addr);
				addevent_routing_ifa(ifa, if_name);
			}
			break;
		case RTM_IFINFO:
		{
			boolean_t plugged_in;

			ifm = (void *)rtm;
			addrs = (char *)ifm + sizeof (*ifm);
			dprintf("routing message IFINFO: index %d flags %x",
			    ifm->ifm_index, ifm->ifm_flags);
			printaddrs(ifm->ifm_addrs, addrs);

			if ((addr_dl = (struct sockaddr_dl *)getaddr(RTA_IFP,
			    ifm->ifm_addrs, addrs)) == NULL)
				break;
			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;
			if_name = addr_dl->sdl_data;
			ifp = get_interface(if_name);
			if (ifp == NULL) {
				dprintf("no interface struct for %s; ignoring "
				    "message", STRING(if_name));
				break;
			}

			/*
			 * Check for toggling of the IFF_RUNNING flag.
			 *
			 * On any change in the flag value, we turn off the
			 * DHCP flags; the change in the RUNNING state
			 * indicates a "fresh start" for the interface, so we
			 * should try dhcp again.
			 *
			 * Ignore specific IFF_RUNNING changes for
			 * wireless interfaces; their semantics are
			 * a bit different (either the flag is always
			 * on, or, with newer drivers, it indicates
			 * whether or not they are connected to an AP).
			 *
			 * For wired interfaces, if the interface was
			 * not plugged in and now it is, start info
			 * collection.
			 *
			 * If it was plugged in and now it is
			 * unplugged, generate an event.
			 *
			 * XXX We probably need a lock to protect
			 * if_flags setting and getting.
			 */
			if ((ifp->if_flags & IFF_RUNNING) !=
			    (ifm->ifm_flags & IFF_RUNNING)) {
				ifp->if_lflags &= ~IF_DHCPFLAGS;
			}
			if (ifp->if_type == IF_WIRELESS)
				break;
			plugged_in = ((ifp->if_flags & IFF_RUNNING) != 0);
			ifp->if_flags = ifm->ifm_flags;
			if (!plugged_in &&
			    (ifm->ifm_flags & IFF_RUNNING)) {
				start_if_info_collect(ifp, NULL);
			} else if (plugged_in &&
			    !(ifm->ifm_flags & IFF_RUNNING)) {
				check_drop_dhcp(ifp);
				addevent_routing_msghdr(ifm, if_name);
			}
			break;
		}
		default:
			dprintf("routing message %s socket %d discarded",
			    rtmtype_str(rtm->rtm_type), rtsock);
			break;
		}
	}
	/* NOTREACHED */
	return (NULL);
}

static char *
printaddr(void **address)
{
	static char buffer[80];
	sa_family_t family = *(sa_family_t *)*address;
	struct sockaddr_in *s4 = *address;
	struct sockaddr_in6 *s6 = *address;
	struct sockaddr_dl *dl = *address;

	switch (family) {
	case AF_UNSPEC:
		(void) inet_ntop(AF_UNSPEC, &s4->sin_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s4);
		break;
	case AF_INET:
		(void) inet_ntop(AF_INET, &s4->sin_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s4);
		break;
	case AF_INET6:
		(void) inet_ntop(AF_INET6, &s6->sin6_addr, buffer,
		    sizeof (buffer));
		*address = (char *)*address + sizeof (*s6);
		break;
	case AF_LINK:
		(void) snprintf(buffer, sizeof (buffer), "link %.*s",
		    dl->sdl_nlen, dl->sdl_data);
		*address = (char *)*address + sizeof (*dl);
		break;
	default:
		/*
		 * We can't reliably update the size of this thing
		 * because we don't know what its type is.  So bump
		 * it by a sockaddr_in and see what happens.  The
		 * caller should really make sure this never happens.
		 */
		*address = (char *)*address + sizeof (*s4);
		(void) snprintf(buffer, sizeof (buffer),
		    "unknown address family %d", family);
		break;
	}
	return (buffer);
}

static void
printaddrs(int mask, void *address)
{
	if (mask == 0)
		return;
	if (mask & RTA_DST)
		dprintf("destination address: %s", printaddr(&address));
	if (mask & RTA_GATEWAY)
		dprintf("gateway address: %s", printaddr(&address));
	if (mask & RTA_NETMASK)
		dprintf("netmask: %s", printaddr(&address));
	if (mask & RTA_GENMASK)
		dprintf("cloning mask: %s", printaddr(&address));
	if (mask & RTA_IFP)
		dprintf("interface name: %s", printaddr(&address));
	if (mask & RTA_IFA)
		dprintf("interface address: %s", printaddr(&address));
	if (mask & RTA_AUTHOR)
		dprintf("author: %s", printaddr(&address));
	if (mask & RTA_BRD)
		dprintf("broadcast address: %s", printaddr(&address));
}

static void
nextaddr(void **address)
{
	sa_family_t family = *(sa_family_t *)*address;

	switch (family) {
	case AF_UNSPEC:
	case AF_INET:
		*address = (char *)*address + sizeof (struct sockaddr_in);
		break;
	case AF_INET6:
		*address = (char *)*address + sizeof (struct sockaddr_in6);
		break;
	case AF_LINK:
		*address = (char *)*address + sizeof (struct sockaddr_dl);
		break;
	default:
		syslog(LOG_ERR, "unknown af (%d) while parsing rtm", family);
		break;
	}
}

static void *
getaddr(int addrid, int mask, void *address)
{
	int i;
	void *p = address;

	if ((mask & addrid) == 0)
		return (NULL);

	for (i = 1; i < addrid; i <<= 1) {
		if (i & mask)
			nextaddr(&p);
	}
	return (p);
}

boolean_t
start_event_collection(void)
{
	int err;
	boolean_t check_cache = B_TRUE;

	/*
	 * if these are ever created/destroyed repetitively then we will
	 * have to change this.
	 */

	if (err = pthread_create(&routing, NULL, routing_events, NULL)) {
		syslog(LOG_ERR, "pthread_create routing: %s", strerror(err));
		exit(EXIT_FAILURE);
	} else {
		dprintf("routing thread: %d", routing);
	}

	if (err = pthread_create(&scan, NULL, periodic_wireless_scan, NULL)) {
		syslog(LOG_ERR, "pthread_create wireless scan: %s",
		    strerror(err));
		exit(EXIT_FAILURE);
	} else {
		dprintf("scan thread: %d", scan);
	}

	walk_interface(start_if_info_collect, &check_cache);

	return (B_TRUE);
}
