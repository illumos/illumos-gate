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
 * Copyright (c) 1998, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LIBINETUTIL_H
#define	_LIBINETUTIL_H

/*
 * Contains SMI-private API for general Internet functionality
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/inetutil.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>

#if !defined(_KERNEL) && !defined(_BOOT)

typedef struct {
	uint_t		ifsp_ppa;	/* Physical Point of Attachment */
	uint_t		ifsp_lun;	/* Logical Unit number */
	boolean_t	ifsp_lunvalid;	/* TRUE if lun is valid */
	char		ifsp_devnm[LIFNAMSIZ];	/* only the device name */
} ifspec_t;

extern boolean_t	ifparse_ifspec(const char *, ifspec_t *);
extern void		get_netmask4(const struct in_addr *, struct in_addr *);
extern boolean_t	sockaddrcmp(const struct sockaddr_storage *,
			    const struct sockaddr_storage *);
extern int		plen2mask(uint_t, sa_family_t, struct sockaddr *);
extern int		mask2plen(const struct sockaddr *);
extern boolean_t	sockaddrunspec(const struct sockaddr *);

/*
 * Extended version of the classic BSD ifaddrlist() interface:
 *
 *    int ifaddrlist(struct ifaddrlist **addrlistp, int af, uint_t flags,
 *	             char *errbuf);
 *
 * 	* addrlistp: Upon success, ifaddrlist() sets *addrlistp to a
 *	  dynamically-allocated array of addresses.
 *
 *	* af: Either AF_INET to obtain IPv4 addresses, or AF_INET6 to
 *	  obtain IPv6 addresses.
 *
 *	* flags: LIFC_* flags that control the classes of interfaces that
 *	  will be visible.
 *
 *	* errbuf: A caller-supplied buffer of ERRBUFSIZE.  Upon failure,
 *	  provides the reason for the failure.
 *
 * Upon success, ifaddrlist() returns the number of addresses in the array
 * pointed to by `addrlistp'.  If the count is 0, then `addrlistp' is NULL.
 */
union any_in_addr {
	struct in6_addr	addr6;
	struct in_addr	addr;
};

struct ifaddrlist {
	int		index;			/* interface index */
	union any_in_addr addr;			/* interface address */
	char		device[LIFNAMSIZ + 1];	/* interface name */
	uint64_t	flags;			/* interface flags */
};

#define	ERRBUFSIZE 128			/* expected size of fourth argument */

extern int ifaddrlist(struct ifaddrlist **, int, uint_t, char *);

/*
 * Similar to ifaddrlist(), but returns a linked-list of addresses for a
 * *specific* interface name, and allows specific address flags to be matched
 * against.  A linked list is used rather than an array so that information
 * can grow over time without affecting binary compatibility.  Also, leaves
 * error-handling up to the caller.  Returns the number of ifaddrlistx's
 * chained through ifaddrp.
 *
 *    int ifaddrlistx(const char *ifname, uint64_t set, uint64_t clear,
 *        ifaddrlistx_t **ifaddrp);
 *
 *	* ifname: Interface name to match against.
 *
 *	* set: One or more flags that must be set on the address for
 *	  it to be returned.
 *
 *	* clear: Flags that must be clear on the address for it to be
 *	  returned.
 *
 * 	* ifaddrp: Upon success, ifaddrlistx() sets *ifaddrp to the head
 *	  of a dynamically-allocated array of ifaddrlistx structures.
 *
 * Once done, the caller must free `ifaddrp' by calling ifaddrlistx_free().
 */
typedef struct ifaddrlistx {
	struct ifaddrlistx	*ia_next;
	char			ia_name[LIFNAMSIZ];
	uint64_t		ia_flags;
	struct sockaddr_storage	ia_addr;
} ifaddrlistx_t;

extern int ifaddrlistx(const char *, uint64_t, uint64_t, ifaddrlistx_t **);
extern void ifaddrlistx_free(ifaddrlistx_t *);

/*
 * Timer queues
 *
 * timer queues are a facility for managing timeouts in unix.  in the
 * event driven model, unix provides us with poll(2)/select(3C), which
 * allow us to coordinate waiting on multiple descriptors with an
 * optional timeout.  however, often (as is the case with the DHCP
 * agent), we want to manage multiple independent timeouts (say, one
 * for waiting for an OFFER to come back from a server in response to
 * a DISCOVER sent out on one interface, and another for waiting for
 * the T1 time on another interface).  timer queues allow us to do
 * this in the event-driven model.
 *
 * note that timer queues do not in and of themselves provide the
 * event driven model (for instance, there is no handle_events()
 * routine).  they merely provide the hooks to support multiple
 * independent timeouts.  this is done for both simplicity and
 * applicability (for instance, while one approach would be to use
 * this timer queue with poll(2), another one would be to use SIGALRM
 * to wake up periodically, and then process all the expired timers.)
 */

typedef struct iu_timer_queue iu_tq_t;

/*
 * a iu_timer_id_t refers to a given timer.  its value should not be
 * interpreted by the interface consumer.  it is a signed arithmetic
 * type, and no valid iu_timer_id_t has the value `-1'.
 */

typedef int iu_timer_id_t;

#define	IU_TIMER_ID_MAX	4096	/* max number of concurrent timers */

/*
 * a iu_tq_callback_t is a function that is called back in response to a
 * timer expiring.  it may then carry out any necessary work,
 * including rescheduling itself for callback or scheduling /
 * cancelling other timers.  the `void *' argument is the same value
 * that was passed into iu_schedule_timer(), and if it is dynamically
 * allocated, it is the callback's responsibility to know that, and to
 * free it.
 */

typedef void	iu_tq_callback_t(iu_tq_t *, void *);

iu_tq_t		*iu_tq_create(void);
void		iu_tq_destroy(iu_tq_t *);
iu_timer_id_t	iu_schedule_timer(iu_tq_t *, uint32_t, iu_tq_callback_t *,
		    void *);
iu_timer_id_t	iu_schedule_timer_ms(iu_tq_t *, uint64_t, iu_tq_callback_t *,
		    void *);
int		iu_adjust_timer(iu_tq_t *, iu_timer_id_t, uint32_t);
int		iu_cancel_timer(iu_tq_t *, iu_timer_id_t, void **);
int		iu_expire_timers(iu_tq_t *);
int		iu_earliest_timer(iu_tq_t *);

/*
 * Event Handler
 *
 * an event handler is an object-oriented "wrapper" for select(3C) /
 * poll(2), aimed to make the event demultiplexing system calls easier
 * to use and provide a generic reusable component.  instead of
 * applications directly using select(3C) / poll(2), they register
 * events that should be received with the event handler, providing a
 * callback function to call when the event occurs.  they then call
 * iu_handle_events() to wait and callback the registered functions
 * when events occur.  also called a `reactor'.
 */

typedef struct iu_event_handler iu_eh_t;

/*
 * an iu_event_id_t refers to a given event.  its value should not be
 * interpreted by the interface consumer.  it is a signed arithmetic
 * type, and no valid iu_event_id_t has the value `-1'.
 */

typedef int iu_event_id_t;

/*
 * an iu_eh_callback_t is a function that is called back in response to
 * an event occurring.  it may then carry out any work necessary in
 * response to the event.  it receives the file descriptor upon which
 * the event occurred, a bit array of events that occurred (the same
 * array used as the revents by poll(2)), and its context through the
 * `void *' that was originally passed into iu_register_event().
 *
 * NOTE: the same descriptor may not be registered multiple times for
 * different callbacks.  if this behavior is desired, either use dup(2)
 * to get a unique descriptor, or demultiplex in the callback function
 * based on the events.
 */

typedef void	iu_eh_callback_t(iu_eh_t *, int, short, iu_event_id_t, void *);
typedef void	iu_eh_sighandler_t(iu_eh_t *, int, void *);
typedef boolean_t iu_eh_shutdown_t(iu_eh_t *, void *);

iu_eh_t		*iu_eh_create(void);
void		iu_eh_destroy(iu_eh_t *);
iu_event_id_t	iu_register_event(iu_eh_t *, int, short, iu_eh_callback_t *,
		    void *);
int		iu_unregister_event(iu_eh_t *, iu_event_id_t, void **);
int		iu_handle_events(iu_eh_t *, iu_tq_t *);
void		iu_stop_handling_events(iu_eh_t *, unsigned int,
		    iu_eh_shutdown_t *, void *);
int		iu_eh_register_signal(iu_eh_t *, int, iu_eh_sighandler_t *,
		    void *);
int		iu_eh_unregister_signal(iu_eh_t *, int, void **);

#endif	/* !defined(_KERNEL) && !defined(_BOOT) */

#ifdef	__cplusplus
}
#endif

#endif	/* !_LIBINETUTIL_H */
