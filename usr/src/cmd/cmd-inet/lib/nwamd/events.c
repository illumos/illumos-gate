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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
 * hotplug_handler() is called for EC_DEV_ADD and EC_DEV_REMOVE hotplug events
 * of class ESC_NETWORK - i.e. hotplug insertion/removal of network card -
 * and plumbs/unplumbs the interface, adding/removing it from running
 * configuration (the interface and llp lists).
 *
 * routing_events() reads routing messages off of an IPv4 routing socket and
 * by calling addevent_*() functions places appropriate events on the queue.
 *
 * start_event_collection() creates a thread to run routing_events() and one
 * to run periodic_wireless_scan() in.  Finally it does an initial collection
 * of information from each interface currently known.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <libsysevent.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dev.h>
#include <libnvpair.h>
#include <net/if.h>
#include <net/route.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fcntl.h>
#include <syslog.h>
#include <unistd.h>

#include "defines.h"
#include "structures.h"
#include "functions.h"
#include "variables.h"

struct np_event *equeue;
static struct np_event *equeue_end;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;
pthread_t routing, scan;

static sysevent_handle_t *sysevent_handle;

static void hotplug_handler(sysevent_t *ev);
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
free_event(struct np_event *npe)
{
	free(npe);
}

boolean_t
np_queue_add_event(enum np_event_type evt, const char *ifname)
{
	struct np_event *npe;
	size_t slen;

	slen = ifname == NULL ? 0 : (strlen(ifname) + 1);
	if ((npe = calloc(1, sizeof (*npe) + slen)) == NULL) {
		syslog(LOG_ERR, "event %s alloc for %s failed",
		    npe_type_str(evt), STRING(ifname));
		return (B_FALSE);
	}
	if (ifname != NULL)
		npe->npe_name = strcpy((char *)(npe + 1), ifname);
	npe->npe_type = evt;

	(void) pthread_mutex_lock(&queue_mutex);
	dprintf("adding event type %s name %s to queue",
	    npe_type_str(evt), STRING(ifname));
	if (equeue_end != NULL) {
		equeue_end->npe_next = npe;
		equeue_end = npe;
	} else {
		equeue = equeue_end = npe;
	}
	equeue_end->npe_next = NULL;
	(void) pthread_cond_signal(&queue_cond);
	(void) pthread_mutex_unlock(&queue_mutex);
	return (B_TRUE);
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
	case EV_LINKDROP:
		return ("LINKDROP");
	case EV_LINKUP:
		return ("LINKUP");
	case EV_LINKFADE:
		return ("LINKFADE");
	case EV_LINKDISC:
		return ("LINKDISC");
	case EV_NEWAP:
		return ("NEWAP");
	case EV_USER:
		return ("USER");
	case EV_TIMER:
		return ("TIMER");
	case EV_SHUTDOWN:
		return ("SHUTDOWN");
	case EV_NEWADDR:
		return ("NEWADDR");
	case EV_RESELECT:
		return ("RESELECT");
	case EV_DOOR_TIME:
		return ("DOOR_TIME");
	case EV_ADDIF:
		return ("ADDIF");
	case EV_REMIF:
		return ("REMIF");
	case EV_TAKEDOWN:
		return ("TAKEDOWN");
	default:
		return ("unknown");
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

/*
 * At present, we only handle EC_DEV_ADD/EC_DEV_REMOVE sysevents of
 * subclass ESC_NETWORK.  These signify hotplug addition/removal.
 *
 * The sysevents are converted into NWAM events so that we can process them in
 * the main loop.  If we didn't do this, we'd either have bad pointer
 * references or need to have reference counts on everything.  Serializing
 * through the event mechanism is much simpler.
 */
static void
hotplug_handler(sysevent_t *ev)
{
	int32_t instance;
	char *driver;
	char ifname[LIFNAMSIZ];
	nvlist_t *attr_list;
	char *event_class = sysevent_get_class_name(ev);
	char *event_subclass = sysevent_get_subclass_name(ev);
	int retv;

	dprintf("hotplug_handler: event %s/%s", event_class,
	    event_subclass);

	/* Make sure sysevent is of expected class/subclass */
	if ((strcmp(event_class, EC_DEV_ADD) != 0 &&
	    strcmp(event_class, EC_DEV_REMOVE) != 0) ||
	    strcmp(event_subclass, ESC_NETWORK) != 0) {
		syslog(LOG_ERR, "hotplug_handler: unexpected sysevent "
		    "class/subclass %s/%s", event_class, event_subclass);
		return;
	}

	/*
	 * Retrieve driver name and instance attributes, and combine to
	 * get interface name.
	 */
	if (sysevent_get_attr_list(ev, &attr_list) != 0) {
		syslog(LOG_ERR, "hotplug_handler: sysevent_get_attr_list: %m");
		return;
	}
	retv = nvlist_lookup_string(attr_list, DEV_DRIVER_NAME, &driver);
	if (retv == 0)
		retv = nvlist_lookup_int32(attr_list, DEV_INSTANCE, &instance);
	if (retv != 0) {
		syslog(LOG_ERR, "handle_hotplug_interface: nvlist_lookup "
		    "of attributes failed: %s", strerror(retv));
	} else {
		(void) snprintf(ifname, LIFNAMSIZ, "%s%d", driver, instance);
		(void) np_queue_add_event(strcmp(event_class, EC_DEV_ADD) == 0 ?
		    EV_ADDIF : EV_REMIF, ifname);
	}
	nvlist_free(attr_list);
}

static void
hotplug_events_unregister(void)
{
	/* Unsubscribe to sysevents */
	sysevent_unbind_handle(sysevent_handle);
	sysevent_handle = NULL;
}

static void
hotplug_events_register(void)
{
	const char *subclass = ESC_NETWORK;

	sysevent_handle = sysevent_bind_handle(hotplug_handler);
	if (sysevent_handle == NULL) {
		syslog(LOG_ERR, "sysevent_bind_handle: %s", strerror(errno));
		return;
	}
	/*
	 * Subscribe to ESC_NETWORK subclass of EC_DEV_ADD and EC_DEV_REMOVE
	 * events.  As a result,  we get sysevent notification of hotplug
	 * add/remove events,  which we handle above in hotplug_event_handler().
	 */
	if (sysevent_subscribe_event(sysevent_handle, EC_DEV_ADD, &subclass, 1)
	    != 0 || sysevent_subscribe_event(sysevent_handle, EC_DEV_REMOVE,
	    &subclass, 1) != 0) {
		syslog(LOG_ERR, "sysevent_subscribe_event: %s",
		    strerror(errno));
		hotplug_events_unregister();
	}
}

/*
 * This thread reads routing socket events and sends them to the main state
 * machine.  We must be careful with access to interface data structures here,
 * as we're not the main thread, which may delete things.  Holding a pointer is
 * not allowed.
 */
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
		char *addrs;
		struct sockaddr_dl *addr_dl;
		struct sockaddr_in *addr_in;

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
		case RTM_DELADDR: {
			uint64_t ifflags;

			/*
			 * Check for failure due to CR 6745448: if we get a
			 * report that an address has been deleted, then check
			 * for interface up, datalink down, and actual address
			 * non-zero.  If that combination is seen, then this is
			 * a DHCP cached lease, and we need to remove it from
			 * the system, or it'll louse up the kernel routes
			 * (which aren't smart enough to avoid dead
			 * interfaces).
			 */
			ifa = (void *)rtm;
			addrs = (char *)ifa + sizeof (*ifa);

			dprintf("routing message DELADDR: index %d flags %x",
			    ifa->ifam_index, ifa->ifam_flags);
			printaddrs(ifa->ifam_addrs, addrs);

			if (ifa->ifam_index == 0) {
				/* what is this? */
				dprintf("tossing index 0 routing event");
				break;
			}

			addr_in = getaddr(RTA_IFA, ifa->ifam_addrs, addrs);
			if (addr_in == NULL) {
				dprintf("no RTA_IFA in RTM_DELADDR message");
				break;
			}

			addr_dl = getaddr(RTA_IFP, ifa->ifam_addrs, addrs);
			if (addr_dl == NULL) {
				dprintf("no RTA_IFP in RTM_DELADDR message");
				break;
			}

			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;

			if (addr_in->sin_addr.s_addr == INADDR_ANY) {
				ifflags = get_ifflags(addr_dl->sdl_data,
				    AF_INET);
				if ((ifflags & IFF_UP) &&
				    !(ifflags & IFF_RUNNING))
					zero_out_v4addr(addr_dl->sdl_data);
			}
			break;
		}

		case RTM_NEWADDR:
			ifa = (void *)rtm;
			addrs = (char *)ifa + sizeof (*ifa);

			dprintf("routing message NEWADDR: index %d flags %x",
			    ifa->ifam_index, ifa->ifam_flags);
			printaddrs(ifa->ifam_addrs, addrs);

			if (ifa->ifam_index == 0) {
				/* what is this? */
				dprintf("tossing index 0 routing event");
				break;
			}

			addr_in = getaddr(RTA_IFA, ifa->ifam_addrs, addrs);
			if (addr_in == NULL) {
				dprintf("no RTA_IFA in RTM_NEWADDR message");
				break;
			}

			addr_dl = getaddr(RTA_IFP, ifa->ifam_addrs, addrs);
			if (addr_dl == NULL) {
				dprintf("no RTA_IFP in RTM_NEWADDR message");
				break;
			}

			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;

			update_interface_v4_address(addr_dl->sdl_data,
			    addr_in->sin_addr.s_addr);
			break;

		case RTM_IFINFO:
			ifm = (void *)rtm;
			addrs = (char *)ifm + sizeof (*ifm);
			dprintf("routing message IFINFO: index %d flags %x",
			    ifm->ifm_index, ifm->ifm_flags);
			printaddrs(ifm->ifm_addrs, addrs);

			if (ifm->ifm_index == 0) {
				dprintf("tossing index 0 routing event");
				break;
			}

			addr_dl = getaddr(RTA_IFP, ifm->ifm_addrs, addrs);
			if (addr_dl == NULL) {
				dprintf("no RTA_IFP in RTM_IFINFO message");
				break;
			}

			/*
			 * We don't use the lladdr in this structure so we can
			 * run over it.
			 */
			addr_dl->sdl_data[addr_dl->sdl_nlen] = 0;

			update_interface_flags(addr_dl->sdl_data,
			    ifm->ifm_flags);
			break;

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

	/*
	 * This function registers a callback which will get a dedicated thread
	 * for handling of hotplug sysevents when they occur.
	 */
	hotplug_events_register();

	dprintf("initial interface scan");
	walk_interface(start_if_info_collect, "check");

	return (B_TRUE);
}
