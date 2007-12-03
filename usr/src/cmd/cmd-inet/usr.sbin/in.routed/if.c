/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright (c) 1983, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgment:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sbin/routed/if.c,v 1.8 2000/08/11 08:24:38 sheldonh Exp $
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "defs.h"
#include "pathnames.h"
#include <sys/sockio.h>
#include <inet/ip.h>
#include <kstat.h>
#include <stropts.h>
#include <fcntl.h>
#include <stddef.h>
#include <assert.h>

/* linked list of all interfaces */
struct interface *ifnet;

/*
 * Acceptable sizes (in number of interfaces) for the interface hash
 * tables.  These must all be prime.  The interface hash tables all
 * start with a size of hash_table_sizes[0], and increase as needed.
 */
size_t hash_table_sizes[] = { 67, 131, 257, 521, 1031, 2053, 4099, 0 };

struct htbl {
	void		**htbl_ptrs;
	uint_t		(*htbl_hash)(const void *, size_t);
	size_t		htbl_link_off;	/* offset of the linkage structure */
	size_t		htbl_key_off;	/* offset of the key value (rehash) */
	size_t		htbl_size;	/* size of the hash */
	uint_t		htbl_size_index;
	uint_t		htbl_ifcount;	/* count of entries */
	boolean_t	htbl_grow;	/* growth allowed */
};

/* Get first element -- for iteration */
#define	HFIRST(htbl, arg) \
	((htbl)->htbl_ptrs[(htbl)->htbl_hash((arg), 0) % (htbl)->htbl_size])

/* Add an element to a hash */
#define	HADD(htbl, strp) \
	hash_link((htbl), (htbl)->htbl_hash((strp), (htbl)->htbl_key_off), \
	    (strp))

uint_t	tot_interfaces;			/* # of remote and local interfaces */
uint_t	rip_interfaces;			/* # of interfaces doing RIP */
uint_t	ripout_interfaces;		/* # of interfaces advertising RIP */
uint_t	fwd_interfaces;			/* # of interfaces ip_forwarding=1 */
static boolean_t foundloopback;		/* valid flag for loopaddr */
in_addr_t	loopaddr;		/* our address on loopback */
static struct	rt_spare loop_rts;

struct timeval ifscan_timer;
static struct timeval last_ifscan;
#define	IF_RESCAN_DELAY() \
	(last_ifscan.tv_sec == now.tv_sec && \
	    last_ifscan.tv_usec == now.tv_usec && \
	    timercmp(&ifscan_timer, &now, > /* */))

boolean_t		have_ripv1_out;	/* have a RIPv1 interface */
static boolean_t	have_ripv1_in;

static void		if_bad(struct interface *, boolean_t);
static boolean_t	addrouteforif(struct interface *);
static int	get_if_kstats(struct interface *, struct phyi_data *);
static uint_t	ahash(const void *, uint_t);
static uint_t	ihash(const void *, uint_t);
static uint_t	nhash(const void *, uint_t);
static void	htbl_grow(struct htbl *);

/*
 * Table of all interfaces, hashed by interface address.  For remote
 * interfaces, the gateway address is used.
 */
static struct htbl ahash_tbl = {
    NULL, ahash, offsetof(struct interface, int_ahash),
    offsetof(struct interface, int_addr),
    0, 0, 0, _B_TRUE };
/*
 * Table of broadcast capable interfaces, hashed by interface broadcast
 * address.
 */
static struct htbl bhash_tbl = {
    NULL, ahash, offsetof(struct interface, int_bhash),
    offsetof(struct interface, int_brdaddr),
    0, 0, 0, _B_TRUE };
/*
 * Table of physical_interface structures (lists of interfaces by ifIndex),
 * hashed by interface index.
 */
static struct htbl ihash_tbl = {
    NULL, ihash, offsetof(struct physical_interface, phyi_link),
    offsetof(struct physical_interface, phyi_index),
    0, 0, 0, _B_TRUE };
/*
 * Table of all interfaces, hashed by interface name.
 */
static struct htbl nhash_tbl = {
    NULL, nhash, offsetof(struct interface, int_nhash),
    offsetof(struct interface, int_name),
    0, 0, 0, _B_TRUE };

static struct physical_interface dummy_phyi;
struct interface dummy_ifp;

/* Hash based on an IP address. */
static uint_t
ahash(const void *arg, size_t voffs)
{
	/* LINTED */
	return ((uint_t)*(const in_addr_t *)((const char *)arg + voffs));
}

static uint_t
ihash(const void *arg, size_t voffs)
{
	/* LINTED */
	return ((uint_t)*(const uint32_t *)((const char *)arg + voffs));
}

static uint_t
nhash(const void *arg, size_t voffs)
{
	const char *cp = (const char *)arg + voffs;
	uint_t i;

	for (i = 0; *cp != '\0'; cp++) {
		i = ((i<<1) & 0x7fffffff) | ((i>>30) & 0x00000003);
		i ^= *cp;
	}
	return (i);
}

/*
 * Add an element to the head of the list.
 */
static void
link_in(void **head, void *strp, size_t loffs)
{
	struct hlinkage *hlp;

	/* LINTED: alignment known to be good. */
	hlp = (struct hlinkage *)((char *)strp + loffs);
	hlp->hl_prev = head;
	if ((hlp->hl_next = *head) != NULL) {
		/* LINTED */
		((struct hlinkage *)((char *)*head + loffs))->hl_prev =
		    &hlp->hl_next;
	}
	*head = strp;
}

/* Remove from a list */
static void
link_out(void *strp, size_t loffs)
{
	struct hlinkage *hlp;

	/* LINTED: alignment known to be good. */
	hlp = (struct hlinkage *)((char *)strp + loffs);
	if ((*hlp->hl_prev = hlp->hl_next) != NULL) {
		/* LINTED */
		((struct hlinkage *)((char *)hlp->hl_next + loffs))->hl_prev =
		    hlp->hl_prev;
	}
}

/* Add to a hash */
static void
hash_link(struct htbl *htbl, uint_t hval, void *strp)
{
	void **hep;

	if (htbl->htbl_grow && htbl->htbl_ifcount >= htbl->htbl_size * 5)
		htbl_grow(htbl);

	hep = &htbl->htbl_ptrs[hval % htbl->htbl_size];
	link_in(hep, strp, htbl->htbl_link_off);
	htbl->htbl_ifcount++;
}

/* Remove from a hash */
static void
hash_unlink(struct htbl *htbl, void *strp)
{
	link_out(strp, htbl->htbl_link_off);
	htbl->htbl_ifcount--;
}

static void
dummy_ifp_init(void)
{
	dummy_phyi.phyi_interface = &dummy_ifp;
	dummy_ifp.int_phys = &dummy_phyi;
	(void) strcpy(dummy_phyi.phyi_name, "wildcard");
	(void) strcpy(dummy_ifp.int_name, "wildcard");
	dummy_ifp.int_dstaddr = dummy_ifp.int_addr = INADDR_NONE;
	dummy_ifp.int_mask = IP_HOST_MASK;
	dummy_ifp.int_metric = HOPCNT_INFINITY;
	dummy_ifp.int_state = (IS_BROKE|IS_PASSIVE|IS_NO_RIP|IS_NO_RDISC);
	dummy_ifp.int_std_mask = std_mask(dummy_ifp.int_addr);
	dummy_ifp.int_std_net = dummy_ifp.int_net & dummy_ifp.int_std_mask;
	dummy_ifp.int_std_addr = htonl(dummy_ifp.int_std_net);
}

/* allocate the interface hash tables */
void
iftbl_alloc(void)
{
	size_t initial_size = hash_table_sizes[0];

	errno = 0;
	ahash_tbl.htbl_ptrs = calloc(initial_size, sizeof (void *));
	bhash_tbl.htbl_ptrs = calloc(initial_size, sizeof (void *));
	ihash_tbl.htbl_ptrs = calloc(initial_size, sizeof (void *));
	nhash_tbl.htbl_ptrs = calloc(initial_size, sizeof (void *));

	if (errno != 0)
		BADERR(_B_FALSE, "Unable to allocate interface tables");

	ahash_tbl.htbl_size = initial_size;
	bhash_tbl.htbl_size = initial_size;
	ihash_tbl.htbl_size = initial_size;
	nhash_tbl.htbl_size = initial_size;

	dummy_ifp_init();
}


static void
htbl_grow(struct htbl *htbl)
{
	void *strp;
	void **new_ptrs, **saved_old_ptrs, **old_ptrs;
	size_t new_size, old_size;
	static uint_t failed_count;

	if ((new_size = hash_table_sizes[htbl->htbl_size_index + 1]) == 0)
		return;

	if ((new_ptrs = calloc(new_size, sizeof (void *))) == NULL) {
		/*
		 * This is not fatal since we already have a
		 * functional, yet crowded, interface table.
		 */
		if (++failed_count % 100 == 1)
			msglog("%sunable to grow interface hash table: %s",
			    failed_count > 1 ? "Still " : "",
			    rip_strerror(errno));
		return;
	}

	failed_count = 0;

	saved_old_ptrs = old_ptrs = htbl->htbl_ptrs;
	old_size = htbl->htbl_size;
	htbl->htbl_ptrs = new_ptrs;
	htbl->htbl_size = new_size;
	htbl->htbl_size_index++;
	htbl->htbl_ifcount = 0;

	/*
	 * Go through the list of structures, and re-link each into
	 * this new table.
	 */
	htbl->htbl_grow = _B_FALSE;
	while (old_size-- > 0) {
		strp = *old_ptrs++;
		HADD(htbl, strp);
	}

	htbl->htbl_grow = _B_TRUE;
	free(saved_old_ptrs);
}

/* Link a new interface into the lists and hash tables. */
void
if_link(struct interface *ifp, uint32_t ifindex)
{
	struct physical_interface *phyi;

	link_in((void **)&ifnet, ifp, offsetof(struct interface, int_link));

	HADD(&ahash_tbl, ifp);
	HADD(&nhash_tbl, ifp);

	if (ifp->int_if_flags & IFF_BROADCAST)
		HADD(&bhash_tbl, ifp);

	if (ifindex != 0) {
		for (phyi = HFIRST(&ihash_tbl, &ifindex);
		    phyi != NULL; phyi = phyi->phyi_link.hl_next) {
			if (phyi->phyi_index == ifindex)
				break;
		}
		if (phyi == NULL) {
			size_t size;

			phyi = rtmalloc(sizeof (*phyi), "physical_interface");
			(void) memset(phyi, 0, sizeof (*phyi));
			phyi->phyi_index = ifindex;
			/* LINTED */
			assert(IF_NAME_LEN >= IF_NAMESIZE);

			size = strcspn(ifp->int_name, ":");
			(void) strncpy(phyi->phyi_name, ifp->int_name,
			    size);
			phyi->phyi_name[size] = '\0';
			HADD(&ihash_tbl, phyi);
		}
		link_in((void **)&phyi->phyi_interface, ifp,
		    offsetof(struct interface, int_ilist));
		ifp->int_phys = phyi;
	}
}

/* Find the interface with an address */
struct interface *
ifwithaddr(in_addr_t addr,
    boolean_t bcast,	/* notice IFF_BROADCAST address */
    boolean_t remote)	/* include IS_REMOTE interfaces */
{
	struct interface *ifp, *possible = NULL;
	uint32_t remote_state;

	remote_state = (!remote ? IS_REMOTE : 0);

	for (ifp = HFIRST(&ahash_tbl, &addr); ifp != NULL;
	    ifp = ifp->int_ahash.hl_next) {
		if (ifp->int_addr != addr)
			continue;
		if (ifp->int_state & remote_state)
			continue;
		if (!(ifp->int_state & (IS_BROKE | IS_PASSIVE)))
			return (ifp);
		possible = ifp;
	}

	if (possible != NULL || !bcast)
		return (possible);

	for (ifp = HFIRST(&bhash_tbl, &addr); ifp != NULL;
	    ifp = ifp->int_bhash.hl_next) {
		if (ifp->int_brdaddr != addr)
			continue;
		if (ifp->int_state & remote_state)
			continue;
		if (!(ifp->int_state & (IS_BROKE | IS_PASSIVE)))
			return (ifp);
		possible = ifp;
	}

	return (possible);
}


/* find the interface with the specified name ("hme0" for example) */
struct interface *
ifwithname(const char *name)
{
	struct interface *ifp;

	for (;;) {
		for (ifp = HFIRST(&nhash_tbl, name); ifp != NULL;
		    ifp = ifp->int_nhash.hl_next) {
			if (strcmp(ifp->int_name, name) == 0)
				return (ifp);
		}

		/*
		 * If there is no known interface, maybe there is a
		 * new interface.  So just once look for new interfaces.
		 */
		if (IF_RESCAN_DELAY())
			return (NULL);
		ifscan();
	}
}

struct interface *
findremoteif(in_addr_t addr)
{
	struct interface *ifp;

	for (ifp = HFIRST(&ahash_tbl, &addr); ifp != NULL;
	    ifp = ifp->int_ahash.hl_next) {
		if ((ifp->int_state & IS_REMOTE) && ifp->int_addr == addr)
			return (ifp);
	}

	return (NULL);
}

struct interface *
findifaddr(in_addr_t addr)
{
	struct interface *ifp;

	for (ifp = HFIRST(&ahash_tbl, &addr); ifp != NULL;
	    ifp = ifp->int_ahash.hl_next) {
		if (ifp->int_addr == addr)
			return (ifp);
	}

	return (NULL);
}

/*
 * Return the first interface with the given index.
 */
struct interface *
ifwithindex(ulong_t index,
    boolean_t rescan_ok)
{
	struct physical_interface *phyi;

	for (;;) {
		for (phyi = HFIRST(&ihash_tbl, &index); phyi != NULL;
		    phyi = phyi->phyi_link.hl_next) {
			if (phyi->phyi_index == index)
				return (phyi->phyi_interface);
		}

		/*
		 * If there is no known interface, maybe there is a
		 * new interface.  So just once look for new interfaces.
		 */
		if (!rescan_ok || IF_RESCAN_DELAY())
			return (NULL);
		rescan_ok = _B_FALSE;
		ifscan();
	}
}


/*
 * Find an interface which should be receiving packets sent from the
 * given address.  Used as a last ditch effort for figuring out which
 * interface a packet came in on.  Also used for finding out which
 * interface points towards the gateway of static routes learned from
 * the kernel.
 */
struct interface *
iflookup(in_addr_t addr)
{
	struct interface *ifp, *maybe;

	maybe = NULL;
	for (;;) {
		for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
			/*
			 * Don't return a duplicate interface since
			 * it is unusable for output.
			 */
			if (ifp->int_state & IS_DUP)
				continue;

			if (ifp->int_if_flags & IFF_POINTOPOINT) {
				/* finished with a match */
				if (ifp->int_dstaddr == addr)
					return (ifp);
			} else {
				/* finished with an exact match */
				if (ifp->int_addr == addr) {
					if (IS_PASSIVE_IFP(ifp))
						trace_misc("iflookup "
						    "returning passive intf %s",
						    ifp->int_name);
					return (ifp);
				}

				/* Look for the longest approximate match. */
				if (on_net(addr, ifp->int_net, ifp->int_mask) &&
				    (maybe == NULL ||
				    ifp->int_mask > maybe->int_mask)) {
					maybe = ifp;
				}
			}
		}

		/*
		 * If there is no known interface, maybe there is a
		 * new interface.  So just once look for new interfaces.
		 */
		if (maybe == NULL && !IF_RESCAN_DELAY())
			ifscan();
		else
			break;
	}

	if (maybe != NULL && IS_PASSIVE_IFP(maybe)) {
		trace_misc("iflookup returning passive intf %s",
		    maybe->int_name);
	}
	return (maybe);
}

/*
 * Find the netmask that would be inferred by RIPv1 listeners
 *	on the given interface for a given network.
 *	If no interface is specified, look for the best fitting	interface.
 */
in_addr_t
ripv1_mask_net(in_addr_t addr,	/* in network byte order */
    const struct interface *ifp)	/* as seen on this interface */
{
	const struct r1net *r1p;
	in_addr_t mask = 0;

	if (addr == 0)			/* default always has 0 mask */
		return (mask);

	if (ifp != NULL && ifp->int_ripv1_mask != HOST_MASK) {
		/*
		 * If the target network is that of the associated interface
		 * on which it arrived, then use the netmask of the interface.
		 */
		if (on_net(addr, ifp->int_net, ifp->int_std_mask))
			mask = ifp->int_ripv1_mask;

	} else {
		/*
		 * Examine all interfaces, and if it the target seems
		 * to have the same network number of an interface, use the
		 * netmask of that interface.  If there is more than one
		 * such interface, prefer the interface with the longest
		 * match.
		 */
		for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
			if (on_net(addr, ifp->int_std_net, ifp->int_std_mask) &&
			    ifp->int_ripv1_mask > mask &&
			    ifp->int_ripv1_mask != HOST_MASK)
				mask = ifp->int_ripv1_mask;
		}

	}

	if (mask == 0) {
		/*
		 * Check to see if the user has supplied an applicable
		 * netmask as a ripv1_mask option in /etc/gateways.
		 */
		for (r1p = r1nets; r1p != NULL; r1p = r1p->r1net_next) {
			/*
			 * If the address is is on a matching network
			 * and we haven't already found a longer match,
			 * use the matching netmask.
			 */
			if (on_net(addr, r1p->r1net_net, r1p->r1net_match) &&
			    r1p->r1net_mask > mask)
				mask = r1p->r1net_mask;
		}

		/* Otherwise, make the classic A/B/C guess. */
		if (mask == 0)
			mask = std_mask(addr);
	}

	return (mask);
}


in_addr_t
ripv1_mask_host(in_addr_t addr,		/* in network byte order */
    const struct interface *ifp)	/* as seen on this interface */
{
	in_addr_t mask = ripv1_mask_net(addr, ifp);


	/*
	 * If the computed netmask does not mask all of the set bits
	 * in the address, then assume it is a host address
	 */
	if ((ntohl(addr) & ~mask) != 0)
		mask = HOST_MASK;
	return (mask);
}


/* See if a IP address looks reasonable as a destination */
boolean_t			/* _B_FALSE=bad _B_TRUE=good */
check_dst(in_addr_t addr)
{
	addr = ntohl(addr);

	if (IN_CLASSA(addr)) {
		if (addr == 0)
			return (_B_TRUE);	/* default */

		addr >>= IN_CLASSA_NSHIFT;
		return (addr != 0 && addr != IN_LOOPBACKNET);
	}

	/* Must not allow destination to be link local address. */
	if (IN_LINKLOCAL(addr))
		return (_B_FALSE);

	if (IN_CLASSB(addr) || IN_CLASSC(addr))
		return (_B_TRUE);

	if (IN_CLASSD(addr))
		return (_B_FALSE);

	return (_B_TRUE);

}

/*
 * Find an existing interface which has the given parameters, but don't
 * return the interface with name "name" if "name" is specified.
 */
struct interface *
check_dup(const char *name,	/* Don't return this interface */
    in_addr_t addr,	/* IP address, so network byte order */
    in_addr_t dstaddr,	/* ditto */
    in_addr_t mask,	/* mask, so host byte order */
    uint64_t if_flags,	/* set IFF_POINTOPOINT to ignore local int_addr */
    boolean_t allowdups)	/* set true to include duplicates */
{
	struct interface *best_ifp = NULL;
	struct interface *ifp;
	in_addr_t dstaddr_h = ntohl(dstaddr);
	int best_pref = 0;
	int pref;

	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		/* This interface, not a duplicate. */
		if (name != NULL && strcmp(name, ifp->int_name) == 0)
			continue;

		/*
		 * Find an interface which isn't already a duplicate to
		 * avoid cyclical duplication.  (i.e. qfe0:1 is a duplicate
		 * of qfe0, and qfe0 is a duplicate of qfe0:1.  That would
		 * be bad)
		 */
		if (!allowdups && (ifp->int_state & IS_DUP))
			continue;

		if (ifp->int_mask != mask)
			continue;

		if (!IS_IFF_UP(ifp->int_if_flags))
			continue;

		/*
		 * The local address can only be shared with a point-to-point
		 * link.
		 */
		if ((ifp->int_addr == addr &&
		    ((if_flags|ifp->int_if_flags) & IFF_POINTOPOINT) == 0) ||
		    on_net(ifp->int_dstaddr, dstaddr_h, mask)) {
			pref = 0;
			if (!(ifp->int_state & IS_ALIAS))
				pref++;
			if (!IS_RIP_OUT_OFF(ifp->int_state))
				pref += 2;
			if (IS_IFF_ROUTING(ifp->int_if_flags))
				pref += 4;
			if (pref > best_pref) {
				best_pref = pref;
				best_ifp = ifp;
			}
		}
	}
	return (best_ifp);
}


/*
 * See that a remote gateway is reachable.
 *	Note that the answer can change as real interfaces come and go.
 */
boolean_t			/* _B_FALSE=bad _B_TRUE=good */
check_remote(struct interface *ifp)
{
	struct rt_entry *rt;

	/* do not worry about other kinds */
	if (!(ifp->int_state & IS_REMOTE))
		return (_B_TRUE);

	rt = rtfind(ifp->int_addr);
	if (rt != NULL &&
	    rt->rt_ifp != NULL &&
	    on_net(ifp->int_addr, rt->rt_ifp->int_net, rt->rt_ifp->int_mask)) {
		return (_B_TRUE);
	}

	/*
	 * the gateway cannot be reached directly from one of our
	 * interfaces
	 */
	if (!(ifp->int_state & IS_BROKE)) {
		msglog("unreachable gateway %s in "PATH_GATEWAYS,
		    naddr_ntoa(ifp->int_addr));
		if_bad(ifp, _B_FALSE);
	}
	return (_B_FALSE);
}

/* Delete an interface. */
static void
ifdel(struct interface *ifp)
{
	struct rewire_data wire;
	boolean_t resurrected;
	struct physical_interface *phyi;

	trace_if("Del", ifp);

	ifp->int_state |= IS_BROKE;

	/* unlink the interface */
	link_out(ifp, offsetof(struct interface, int_link));
	hash_unlink(&ahash_tbl, ifp);
	hash_unlink(&nhash_tbl, ifp);
	if (ifp->int_if_flags & IFF_BROADCAST)
		hash_unlink(&bhash_tbl, ifp);

	/* Remove from list of interfaces with this ifIndex */
	if ((phyi = ifp->int_phys) != NULL) {
		link_out(ifp, offsetof(struct interface, int_ilist));
		if (phyi->phyi_interface == NULL) {
			hash_unlink(&ihash_tbl, phyi);
			free(phyi);
		}
	}

	/*
	 * If this is a lead interface, then check first for
	 * duplicates of this interface with an eye towards promoting
	 * one of them.
	 */
	resurrected = _B_FALSE;
	if (!(ifp->int_state & IS_DUP) &&
	    (wire.if_new = check_dup(ifp->int_name, ifp->int_addr,
	    ifp->int_dstaddr, ifp->int_mask, ifp->int_if_flags,
	    _B_TRUE)) != NULL &&
	    !IS_IFF_QUIET(wire.if_new->int_if_flags)) {

		trace_act("promoting duplicate %s in place of %s",
		    wire.if_new->int_name, ifp->int_name);

		/* Rewire routes with the replacement interface */
		wire.if_old = ifp;
		wire.metric_delta = wire.if_new->int_metric - ifp->int_metric;
		(void) rn_walktree(rhead, walk_rewire, &wire);
		kern_rewire_ifp(wire.if_old, wire.if_new);
		if_rewire_rdisc(wire.if_old, wire.if_new);

		/* Mark the replacement as being no longer a duplicate */
		wire.if_new->int_state &= ~IS_DUP;
		tot_interfaces++;
		if (!IS_RIP_OFF(wire.if_new->int_state))
			rip_interfaces++;
		if (!IS_RIP_OUT_OFF(wire.if_new->int_state))
			ripout_interfaces++;
		if (IS_IFF_ROUTING(wire.if_new->int_if_flags))
			fwd_interfaces++;

		set_rdisc_mg(wire.if_new, 1);
		rip_mcast_on(wire.if_new);

		/* We came out ok; no need to clobber routes over this. */
		resurrected = _B_TRUE;
	}

	rip_mcast_off(ifp);
	if (rip_sock_interface == ifp)
		rip_sock_interface = NULL;

	set_rdisc_mg(ifp, 0);

	/*
	 * Note that duplicates are not counted in the total number of
	 * interfaces.
	 */
	if (!(ifp->int_state & IS_DUP) && !IS_IFF_QUIET(ifp->int_if_flags)) {
		tot_interfaces--;
		if (!IS_RIP_OFF(ifp->int_state))
			rip_interfaces--;
		if (!IS_RIP_OUT_OFF(ifp->int_state))
			ripout_interfaces--;
		if (IS_IFF_ROUTING(ifp->int_if_flags))
			fwd_interfaces--;
	}

	if (!resurrected) {
		/*
		 * Zap all routes associated with this interface.
		 * Assume routes just using gateways beyond this interface
		 * will timeout naturally, and have probably already died.
		 */
		(void) rn_walktree(rhead, walk_bad, ifp);
		kern_flush_ifp(ifp);

		if_bad_rdisc(ifp);
	}

	free(ifp);
}


/* Mark an interface ill. */
void
if_sick(struct interface *ifp, boolean_t recurse)
{
	struct interface *ifp1;

	if (0 == (ifp->int_state & (IS_SICK | IS_BROKE))) {
		ifp->int_state |= IS_SICK;
		ifp->int_act_time = NEVER;
		trace_if("Chg", ifp);

		LIM_SEC(ifscan_timer, now.tv_sec+CHECK_BAD_INTERVAL);
		if (recurse && ifp->int_phys != NULL) {
			/* If an interface is sick, so are its aliases. */
			for (ifp1 = ifp->int_phys->phyi_interface;
			    ifp1 != NULL; ifp1 = ifp1->int_ilist.hl_next) {
				if (ifp1 != ifp)
					if_sick(ifp1, _B_FALSE);
			}
		}
	}
}


/* Mark an interface dead. */
static void
if_bad(struct interface *ifp, boolean_t recurse)
{
	struct interface *ifp1;
	struct rewire_data wire;

	if (ifp->int_state & IS_BROKE)
		return;

	LIM_SEC(ifscan_timer, now.tv_sec+CHECK_BAD_INTERVAL);

	ifp->int_state |= (IS_BROKE | IS_SICK);
	ifp->int_act_time = NEVER;
	ifp->int_query_time = NEVER;
	/* Note: don't reset the stats timestamp here */

	trace_if("Chg", ifp);

	if (recurse && ifp->int_phys != NULL) {
		/* If an interface is bad, so are its aliases. */
		for (ifp1 = ifp->int_phys->phyi_interface;
		    ifp1 != NULL; ifp1 = ifp1->int_ilist.hl_next) {
			if (ifp1 != ifp)
				if_bad(ifp1, _B_FALSE);
		}
	}

	/* If we can find a replacement, then pick it up. */
	if (!(ifp->int_state & IS_DUP) &&
	    (wire.if_new = check_dup(ifp->int_name, ifp->int_addr,
	    ifp->int_dstaddr, ifp->int_mask, ifp->int_if_flags,
	    _B_TRUE)) != NULL &&
	    !IS_IFF_QUIET(wire.if_new->int_if_flags)) {
		trace_act("promoting duplicate %s in place of %s",
		    wire.if_new->int_name, ifp->int_name);
		wire.if_old = ifp;
		wire.metric_delta = wire.if_new->int_metric - ifp->int_metric;
		(void) rn_walktree(rhead, walk_rewire, &wire);
		if_rewire_rdisc(wire.if_old, wire.if_new);

		/* The broken guy becomes the duplicate */
		wire.if_new->int_state &= ~IS_DUP;
		set_rdisc_mg(ifp, 0);
		rip_mcast_off(ifp);
		ifp->int_state |= IS_DUP;

		/* join the mcast groups for the replacement */
		set_rdisc_mg(wire.if_new, 1);
		rip_mcast_on(wire.if_new);

		if (rip_sock_interface == ifp)
			rip_sock_interface = NULL;
	} else {
		(void) rn_walktree(rhead, walk_bad, ifp);
		if_bad_rdisc(ifp);
	}
}


/* Mark an interface alive */
void
if_ok(struct interface *ifp, const char *type, boolean_t recurse)
{
	struct interface *ifp1;
	boolean_t wasbroken = _B_FALSE;

	if (ifp->int_state & IS_BROKE) {
		writelog(LOG_WARNING, "%sinterface %s to %s restored",
		    type, ifp->int_name, naddr_ntoa(ifp->int_dstaddr));
		ifp->int_state &= ~(IS_BROKE | IS_SICK);
		wasbroken = _B_TRUE;
	} else if (ifp->int_state & IS_SICK) {
		trace_act("%sinterface %s to %s working better",
		    type, ifp->int_name, naddr_ntoa(ifp->int_dstaddr));
		ifp->int_state &= ~IS_SICK;
	}

	if (recurse && ifp->int_phys != NULL && IS_IFF_UP(ifp->int_if_flags)) {
		ifp->int_phys->phyi_data.ts = 0;

		/* Also mark all aliases of this interface as ok */
		for (ifp1 = ifp->int_phys->phyi_interface;
		    ifp1 != NULL; ifp1 = ifp1->int_ilist.hl_next) {
			if (ifp1 != ifp)
				if_ok(ifp1, type, _B_FALSE);
		}
	}

	if (wasbroken) {
		if (!(ifp->int_state & IS_DUP))
			if_ok_rdisc(ifp);

		if (ifp->int_state & IS_REMOTE)
			(void) addrouteforif(ifp);
	}
}

boolean_t
remote_address_ok(struct interface *ifp, in_addr_t addr)
{
	if (ifp->int_if_flags & IFF_POINTOPOINT) {
		if (addr == ifp->int_dstaddr)
			return (_B_TRUE);
	} else if (on_net(addr, ifp->int_net, ifp->int_mask)) {
		return (_B_TRUE);
	}
	return (_B_FALSE);
}

/*
 * Find the network interfaces which have configured themselves.
 *	This must be done regularly, if only for extra addresses
 *	that come and go on interfaces.
 */
void
ifscan(void)
{
	uint_t complaints = 0;
	static uint_t prev_complaints = 0;
#define	COMP_BADADDR	0x001
#define	COMP_NODST	0x002
#define	COMP_NOBADDR	0x004
#define	COMP_NOMASK	0x008
#define	COMP_BAD_METRIC	0x010
#define	COMP_NETMASK	0x020
#define	COMP_NO_INDEX	0x040
#define	COMP_BAD_FLAGS	0x080
#define	COMP_NO_KSTATS	0x100
#define	COMP_IPFORWARD	0x200

	struct interface ifs, *ifp, *ifp1;
	struct rt_entry *rt;
	size_t needed;
	static size_t lastneeded = 0;
	char *buf;
	static char *lastbuf = NULL;
	int32_t in, ierr, out, oerr;
	struct intnet *intnetp;
	int sock;
	struct lifnum lifn;
	struct lifconf lifc;
	struct lifreq *lifrp, *lifrp_lim;
	struct sockaddr_in *sinp;
	in_addr_t haddr;
	static in_addr_t myaddr = 0;
	uint32_t ifindex;
	struct phyi_data newstats;
	struct physical_interface *phyi;

	last_ifscan = now;
	ifscan_timer.tv_sec = now.tv_sec +
	    (supplier || tot_interfaces != 1 ?
	    CHECK_ACT_INTERVAL : CHECK_QUIET_INTERVAL);

	/* mark all interfaces so we can get rid of those that disappear */
	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next)
		ifp->int_state &= ~IS_CHECKED;

	/* Fetch the size of the current interface list */
	if ((sock = socket(PF_INET, SOCK_DGRAM, 0)) == -1)
		BADERR(_B_TRUE, "ifscan: socket(SOCK_DGRAM)");
	lifn.lifn_family = AF_INET;	/* Only count IPv4 interfaces */
	/*
	 * Include IFF_NOXMIT interfaces.  Such interfaces are exluded
	 * from protocol operations, but their inclusion in the
	 * internal table enables us to know when packets arrive on
	 * such interfaces.
	 */
	lifn.lifn_flags = LIFC_NOXMIT;
calculate_lifc_len:
	if (ioctl(sock, SIOCGLIFNUM, &lifn) == -1) {
		BADERR(_B_TRUE, "ifscan: ioctl(SIOCGLIFNUM)");
	}

	/*
	 * When calculating the buffer size needed, add a small number
	 * of interfaces to those we counted.  We do this to capture
	 * the interface status of potential interfaces which may have
	 * been plumbed between the SIOCGLIFNUM and the SIOCGLIFCONF.
	 * Try to reuse the buffer we already have to avoid heap
	 * thrash.
	 */
	needed = (lifn.lifn_count + 4) * sizeof (struct lifreq);
	if (needed > lastneeded || needed < lastneeded/2) {
		if (lastbuf != NULL)
			free(lastbuf);
		if ((buf = malloc(needed)) == NULL) {
			lastbuf = NULL;
			msglog("ifscan: malloc: %s", rip_strerror(errno));
			return;
		}
	} else {
		buf = lastbuf;
	}
	lastbuf = buf;
	lastneeded = needed;

	/* Get the list */
	lifc.lifc_family = AF_INET;	/* We only need IPv4 interfaces */
	lifc.lifc_flags = LIFC_NOXMIT;
	lifc.lifc_len = needed;
	lifc.lifc_buf = buf;
	if (ioctl(sock, SIOCGLIFCONF, &lifc) == -1) {
		/*
		 * IP returns EINVAL if the lifc_len we passed in is
		 * too small.  If that's the case, we need to go back
		 * and recalculate it.
		 */
		if (errno == EINVAL)
			goto calculate_lifc_len;
		BADERR(_B_TRUE, "ifscan: ioctl(SIOCGLIFCONF)");
	}

	/*
	 * If the returned lifc_len is within one lifreq of the
	 * requested ammount, we may have used a buffer which
	 * was too small to hold all of the interfaces.  In that
	 * case go back and recalculate needed.
	 */
	if (lifc.lifc_len >= needed - sizeof (struct lifreq))
		goto calculate_lifc_len;

	lifrp = lifc.lifc_req;
	lifrp_lim = lifrp + lifc.lifc_len / sizeof (*lifrp);
	for (; lifrp < lifrp_lim; lifrp++) {

		(void) memset(&ifs, 0, sizeof (ifs));

		(void) strlcpy(ifs.int_name, lifrp->lifr_name,
		    sizeof (ifs.int_name));

		/* SIOCGLIFCONF fills in the lifr_addr of each lifreq */
		ifs.int_addr = ((struct sockaddr_in *)&lifrp->lifr_addr)->
		    sin_addr.s_addr;

		if (ioctl(sock, SIOCGLIFFLAGS, lifrp) == -1) {
			if (!(prev_complaints & COMP_BAD_FLAGS))
				writelog(LOG_NOTICE,
				    "unable to get interface flags for %s: %s",
				    ifs.int_name, rip_strerror(errno));
			complaints |= COMP_BAD_FLAGS;
			ifs.int_if_flags = 0;
		} else {
			ifs.int_if_flags = lifrp->lifr_flags;
		}

		if (IN_CLASSD(ntohl(ifs.int_addr)) ||
		    (ntohl(ifs.int_addr) & IN_CLASSA_NET) == 0) {
			if (IS_IFF_UP(ifs.int_if_flags)) {
				if (!(prev_complaints & COMP_BADADDR))
					writelog(LOG_NOTICE,
					    "%s has a bad address %s",
					    ifs.int_name,
					    naddr_ntoa(ifs.int_addr));
				complaints |= COMP_BADADDR;
			}
			continue;
		}

		/* Ignore interface with IPv4 link local address. */
		if (IN_LINKLOCAL(ntohl(ifs.int_addr)))
			continue;

		/* Get the interface index. */
		if (ioctl(sock, SIOCGLIFINDEX, lifrp) == -1) {
			ifindex = 0;
			ifs.int_if_flags &= ~IFF_UP;
			if (!(prev_complaints & COMP_NO_INDEX))
				writelog(LOG_NOTICE, "%s has no ifIndex: %s",
				    ifs.int_name, rip_strerror(errno));
			complaints |= COMP_NO_INDEX;
		} else {
			ifindex = lifrp->lifr_index;
		}

		/*
		 * Get the destination address for point-to-point
		 * interfaces.
		 */
		if (ifs.int_if_flags & IFF_POINTOPOINT) {
			sinp = (struct sockaddr_in *)&lifrp->lifr_dstaddr;
			if (ioctl(sock, SIOCGLIFDSTADDR, lifrp) == -1) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints & COMP_NODST))
						writelog(LOG_NOTICE,
						    "%s has no destination "
						    "address : %s",
						    ifs.int_name,
						    rip_strerror(errno));
					complaints |= COMP_NODST;
				}
				continue;
			}
			ifs.int_net = ntohl(sinp->sin_addr.s_addr);
			if (IN_CLASSD(ntohl(ifs.int_net)) ||
			    (ifs.int_net != 0 &&
			    (ifs.int_net & IN_CLASSA_NET) == 0)) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints & COMP_NODST))
						writelog(LOG_NOTICE,
						    "%s has a bad "
						    "destination address %s",
						    ifs.int_name,
						    naddr_ntoa(ifs.int_net));
					complaints |= COMP_NODST;
				}
				continue;
			}
			ifs.int_dstaddr = sinp->sin_addr.s_addr;
		}

		/* Get the subnet mask */
		sinp = (struct sockaddr_in *)&lifrp->lifr_addr;
		if (ioctl(sock, SIOCGLIFNETMASK, lifrp) == -1) {
			if (IS_IFF_UP(ifs.int_if_flags)) {
				if (!(prev_complaints & COMP_NOMASK))
					writelog(LOG_NOTICE,
					    "%s has no netmask: %s",
					    ifs.int_name, rip_strerror(errno));
				complaints |= COMP_NOMASK;
			}
			continue;
		}
		if (sinp->sin_addr.s_addr == INADDR_ANY) {
			if (!(ifs.int_if_flags &
			    (IFF_POINTOPOINT|IFF_LOOPBACK))) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints & COMP_NOMASK))
						writelog(LOG_NOTICE,
						    "%s has all-zero netmask",
						    ifs.int_name);
					complaints |= COMP_NOMASK;
				}
				continue;
			}
			ifs.int_mask = IP_HOST_MASK;
		} else {
			ifs.int_mask = ntohl(sinp->sin_addr.s_addr);
		}

		/*
		 * Get the broadcast address on broadcast capable
		 * interfaces.
		 */
		if (ifs.int_if_flags & IFF_BROADCAST) {
			if (ioctl(sock, SIOCGLIFBRDADDR, lifrp) == -1) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints & COMP_NOBADDR))
						writelog(LOG_NOTICE,
						    "%s has no broadcast "
						    "address: %s",
						    ifs.int_name,
						    rip_strerror(errno));
					complaints |= COMP_NOBADDR;
				}
				continue;
			}
			haddr = ntohl(sinp->sin_addr.s_addr);
			if (IN_CLASSD(haddr) ||
			    (haddr & IN_CLASSA_NET) == 0) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints & COMP_NOBADDR))
						writelog(LOG_NOTICE,
						    "%s has a bad broadcast "
						    "address %s",
						    ifs.int_name,
						    naddr_ntoa(haddr));
					complaints |= COMP_NOBADDR;
				}
				continue;
			}
		}
		ifs.int_brdaddr = sinp->sin_addr.s_addr;

		/* Get interface metric, if possible. */
		if (ioctl(sock, SIOCGLIFMETRIC, lifrp) == -1) {
			if (IS_IFF_UP(ifs.int_if_flags)) {
				if (!(prev_complaints & COMP_BAD_METRIC))
					writelog(LOG_NOTICE,
					    "%s has no metric: %s",
					    ifs.int_name, rip_strerror(errno));
				complaints |= COMP_BAD_METRIC;
			}
		} else {
			ifs.int_metric = lifrp->lifr_metric;
			if (ifs.int_metric > HOPCNT_INFINITY) {
				if (IS_IFF_UP(ifs.int_if_flags)) {
					if (!(prev_complaints &
					    COMP_BAD_METRIC))
						writelog(LOG_NOTICE,
						    "%s has a metric of %d, "
						    "defaulting to %d",
						    ifs.int_name,
						    ifs.int_metric,
						    HOPCNT_INFINITY);
					complaints |= COMP_BAD_METRIC;
				}
				ifs.int_metric = HOPCNT_INFINITY;
			}
		}

		ifs.int_state |= IS_CHECKED;
		ifs.int_query_time = NEVER;

		/*
		 * If this is an alias, then mark it appropriately.
		 * Do not output RIP or Router-Discovery packets via
		 * aliases.
		 */
		if (strchr(ifs.int_name, ':') != NULL)
			ifs.int_state |= IS_ALIAS;

		if (ifs.int_if_flags & IFF_LOOPBACK) {
			ifs.int_state |= IS_PASSIVE | IS_NO_RIP | IS_NO_RDISC;
			ifs.int_dstaddr = ifs.int_addr;
			ifs.int_mask = HOST_MASK;
			ifs.int_ripv1_mask = HOST_MASK;
			ifs.int_std_mask = std_mask(ifs.int_dstaddr);
			ifs.int_net = ntohl(ifs.int_dstaddr);
			if (!foundloopback) {
				foundloopback = _B_TRUE;
				loopaddr = ifs.int_addr;
				loop_rts.rts_gate = loopaddr;
				loop_rts.rts_router = loopaddr;
			}

		} else if (ifs.int_if_flags & IFF_POINTOPOINT) {
			ifs.int_ripv1_mask = ifs.int_mask;
			ifs.int_mask = HOST_MASK;
			ifs.int_std_mask = std_mask(ifs.int_dstaddr);

		} else {
			ifs.int_dstaddr = ifs.int_addr;
			ifs.int_ripv1_mask = ifs.int_mask;
			ifs.int_std_mask = std_mask(ifs.int_addr);
			ifs.int_net = ntohl(ifs.int_addr) & ifs.int_mask;
			if (ifs.int_mask != ifs.int_std_mask)
				ifs.int_state |= IS_SUBNET;
		}
		ifs.int_std_net = ifs.int_net & ifs.int_std_mask;
		ifs.int_std_addr = htonl(ifs.int_std_net);

		/*
		 * If this interface duplicates another, mark it
		 * appropriately so that we don't generate duplicate
		 * packets.
		 */
		ifp = check_dup(ifs.int_name, ifs.int_addr, ifs.int_dstaddr,
		    ifs.int_mask, ifs.int_if_flags, _B_FALSE);
		if (ifp != NULL) {
			trace_misc("%s (%s%s%s) is a duplicate of %s (%s%s%s)",
			    ifs.int_name,
			    addrname(ifs.int_addr, ifs.int_mask, 1),
			    ((ifs.int_if_flags & IFF_POINTOPOINT) ?
			    "-->" : ""),
			    ((ifs.int_if_flags & IFF_POINTOPOINT) ?
			    naddr_ntoa(ifs.int_dstaddr) : ""),
			    ifp->int_name,
			    addrname(ifp->int_addr, ifp->int_mask, 1),
			    ((ifp->int_if_flags & IFF_POINTOPOINT) ?
			    "-->" : ""),
			    ((ifp->int_if_flags & IFF_POINTOPOINT) ?
			    naddr_ntoa(ifp->int_dstaddr) : ""));
			ifs.int_state |= IS_DUP;
		} else {
			ifs.int_state &= ~IS_DUP;
		}

		/*
		 * See if this is a familiar interface.
		 * If so, stop worrying about it if it is the same.
		 * Start it over if it now is to somewhere else, as happens
		 * frequently with PPP and SLIP, or if its forwarding
		 * status has changed.
		 */
		ifp = ifwithname(ifs.int_name);
		if (ifp != NULL) {
			ifp->int_state |= IS_CHECKED;
			ifp->int_state = (ifp->int_state & ~IS_DUP) |
			    (ifs.int_state & IS_DUP);

			if ((ifp->int_phys == NULL && ifindex != 0) ||
			    (ifp->int_phys != NULL &&
			    ifp->int_phys->phyi_index != ifindex) ||
			    0 != ((ifp->int_if_flags ^ ifs.int_if_flags)
			    & (IFF_BROADCAST | IFF_LOOPBACK |
			    IFF_POINTOPOINT | IFF_MULTICAST |
			    IFF_ROUTER | IFF_NORTEXCH | IFF_NOXMIT)) ||
			    ifp->int_addr != ifs.int_addr ||
			    ifp->int_brdaddr != ifs.int_brdaddr ||
			    ifp->int_dstaddr != ifs.int_dstaddr ||
			    ifp->int_mask != ifs.int_mask ||
			    ifp->int_metric != ifs.int_metric) {
				/*
				 * Forget old information about
				 * a changed interface.
				 */
				trace_act("interface %s has changed",
				    ifp->int_name);
				ifdel(ifp);
				ifp = NULL;
			}
		}

		if (ifp != NULL) {
			/* note interfaces that have been turned off */
			if (!IS_IFF_UP(ifs.int_if_flags)) {
				if (IS_IFF_UP(ifp->int_if_flags)) {
					writelog(LOG_WARNING,
					    "interface %s to %s turned off",
					    ifp->int_name,
					    naddr_ntoa(ifp->int_dstaddr));
					if_bad(ifp, _B_FALSE);
					ifp->int_if_flags &= ~IFF_UP;
				} else if (ifp->int_phys != NULL &&
				    now.tv_sec > (ifp->int_phys->phyi_data.ts +
				    CHECK_BAD_INTERVAL)) {
					trace_act("interface %s has been off"
					    " %ld seconds; forget it",
					    ifp->int_name,
					    now.tv_sec -
					    ifp->int_phys->phyi_data.ts);
					ifdel(ifp);
				}
				continue;
			}
			/* or that were off and are now ok */
			if (!IS_IFF_UP(ifp->int_if_flags)) {
				ifp->int_if_flags |= IFF_UP;
				if_ok(ifp, "", _B_FALSE);
			}

			/*
			 * If it has been long enough,
			 * see if the interface is broken.
			 */
			if ((phyi = ifp->int_phys) == NULL ||
			    now.tv_sec < phyi->phyi_data.ts +
			    CHECK_BAD_INTERVAL)
				continue;

			(void) memset(&newstats, 0, sizeof (newstats));
			if (get_if_kstats(ifp, &newstats) == -1) {
				if (!(prev_complaints & COMP_NO_KSTATS))
					writelog(LOG_WARNING,
					    "unable to obtain kstats for %s",
					    phyi->phyi_name);
				complaints |= COMP_NO_KSTATS;
			}

			/*
			 * If the interface just awoke, restart the counters.
			 */
			if (phyi->phyi_data.ts == 0) {
				phyi->phyi_data = newstats;
				continue;
			}

			in = newstats.ipackets - phyi->phyi_data.ipackets;
			ierr = newstats.ierrors - phyi->phyi_data.ierrors;
			out = newstats.opackets - phyi->phyi_data.opackets;
			oerr = newstats.oerrors - phyi->phyi_data.oerrors;
			phyi->phyi_data = newstats;

			/*
			 * Withhold judgment when the short error counters
			 * wrap, the interface is reset, or if there are
			 * no kstats.
			 */
			if (ierr < 0 || in < 0 || oerr < 0 || out < 0 ||
			    newstats.ts == 0) {
				LIM_SEC(ifscan_timer,
				    now.tv_sec + CHECK_BAD_INTERVAL);
				continue;
			}

			/* Withhold judgement when there is no traffic */
			if (in == 0 && out == 0 && ierr == 0 && oerr == 0)
				continue;

			/*
			 * It is bad if at least 25% of input or output on
			 * an interface results in errors.  Require
			 * presistent problems before marking it dead.
			 */
			if ((ierr > 0 && ierr >= in/4) ||
			    (oerr > 0 && oerr >= out/4)) {
				if (!(ifp->int_state & IS_SICK)) {
					trace_act("interface %s to %s"
					    " sick: in=%d ierr=%d"
					    " out=%d oerr=%d",
					    ifp->int_name,
					    naddr_ntoa(ifp->int_dstaddr),
					    in, ierr, out, oerr);
					if_sick(ifp, _B_TRUE);
					continue;
				}
				if (!(ifp->int_state & IS_BROKE)) {
					writelog(LOG_WARNING,
					    "interface %s to %s broken:"
					    " in=%d ierr=%d out=%d oerr=%d",
					    ifp->int_name,
					    naddr_ntoa(ifp->int_dstaddr),
					    in, ierr, out, oerr);
					if_bad(ifp, _B_TRUE);
				}
				continue;
			}

			/* otherwise, it is active and healthy */
			ifp->int_act_time = now.tv_sec;
			if_ok(ifp, "", _B_TRUE);
			continue;
		}

		/*
		 * This is a new interface.
		 * If it is dead, forget it.
		 */
		if (!IS_IFF_UP(ifs.int_if_flags))
			continue;

		if (0 == (ifs.int_if_flags & (IFF_POINTOPOINT |
		    IFF_BROADCAST | IFF_LOOPBACK)) &&
		    !(ifs.int_state & IS_PASSIVE)) {
			if (!(prev_complaints & COMP_BAD_FLAGS))
				trace_act("%s is neither broadcast, "
				    "point-to-point, nor loopback",
				    ifs.int_name);
			complaints |= COMP_BAD_FLAGS;
			if (!(ifs.int_if_flags & IFF_MULTICAST))
				ifs.int_state |= IS_NO_RDISC;
		}


		/*
		 * It is new and ok.   Add it to the list of interfaces
		 */
		ifp = rtmalloc(sizeof (*ifp), "ifscan ifp");
		(void) memcpy(ifp, &ifs, sizeof (*ifp));
		get_parms(ifp);
		if_link(ifp, ifindex);
		trace_if("Add", ifp);

		if (ifp->int_phys != NULL &&
		    get_if_kstats(ifp, &ifp->int_phys->phyi_data) == -1) {
			if (!(prev_complaints & COMP_NO_KSTATS))
				writelog(LOG_NOTICE,
				    "unable to obtain kstats for %s",
				    ifp->int_phys->phyi_name);
			complaints |= COMP_NO_KSTATS;
		}

		/* Detect interfaces that have conflicting netmasks. */
		if (!(ifp->int_if_flags & (IFF_POINTOPOINT|IFF_LOOPBACK))) {
			for (ifp1 = ifnet; ifp1 != NULL;
			    ifp1 = ifp1->int_next) {
				if (ifp1->int_mask == ifp->int_mask)
					continue;

				/*
				 * we don't care about point-to-point
				 * or loopback aliases
				 */
				if (ifp1->int_if_flags &
				    (IFF_POINTOPOINT|IFF_LOOPBACK)) {
					continue;
				}

				/* ignore aliases on the same network */
				if (ifp->int_phys == ifp1->int_phys)
					continue;

				if (on_net(ifp->int_addr,
				    ifp1->int_net, ifp1->int_mask) ||
				    on_net(ifp1->int_addr,
				    ifp->int_net, ifp->int_mask)) {
					writelog(LOG_INFO,
					    "possible netmask problem"
					    " between %s:%s and %s:%s",
					    ifp->int_name,
					    addrname(htonl(ifp->int_net),
					    ifp->int_mask, 1),
					    ifp1->int_name,
					    addrname(htonl(ifp1->int_net),
					    ifp1->int_mask, 1));
					complaints |= COMP_NETMASK;
				}
			}
		}

		if (!(ifp->int_state & IS_DUP) &&
		    !IS_IFF_QUIET(ifp->int_if_flags)) {
			/* Count the # of directly connected networks. */
			tot_interfaces++;
			if (!IS_RIP_OFF(ifp->int_state))
				rip_interfaces++;
			if (!IS_RIP_OUT_OFF(ifp->int_state))
				ripout_interfaces++;
			if (IS_IFF_ROUTING(ifp->int_if_flags))
				fwd_interfaces++;

			if_ok_rdisc(ifp);
			rip_on(ifp);
		}
	}

	(void) close(sock);

	/*
	 * If we are multi-homed and have at least two interfaces that
	 * are able to forward, then output RIP by default.
	 */
	if (!supplier_set)
		set_supplier();

	/*
	 * If we are multi-homed, optionally advertise a route to
	 * our main address.
	 */
	if (advertise_mhome || (tot_interfaces > 1 && mhome)) {
		/* lookup myaddr if we haven't done so already */
		if (myaddr == 0) {
			char myname[MAXHOSTNAMELEN+1];

			/*
			 * If we are unable to resolve our hostname, don't
			 * bother trying again.
			 */
			if (gethostname(myname, MAXHOSTNAMELEN) == -1) {
				msglog("gethostname: %s", rip_strerror(errno));
				advertise_mhome = _B_FALSE;
				mhome = _B_FALSE;
			} else if (gethost(myname, &myaddr) == 0) {
				writelog(LOG_WARNING,
				    "unable to resolve local hostname %s",
				    myname);
				advertise_mhome = _B_FALSE;
				mhome = _B_FALSE;
			}
		}
		if (myaddr != 0 &&
		    (ifp = ifwithaddr(myaddr, _B_FALSE, _B_FALSE)) != NULL &&
		    foundloopback) {
			advertise_mhome = _B_TRUE;
			rt = rtget(myaddr, HOST_MASK);
			if (rt != NULL) {
				if (rt->rt_ifp != ifp ||
				    rt->rt_router != loopaddr) {
					rtdelete(rt);
					rt = NULL;
				} else {
					loop_rts.rts_ifp = ifp;
					loop_rts.rts_metric = 0;
					loop_rts.rts_time = rt->rt_time;
					loop_rts.rts_origin = RO_LOOPBCK;
					rtchange(rt, rt->rt_state | RS_MHOME,
					    &loop_rts, NULL);
				}
			}
			if (rt == NULL) {
				loop_rts.rts_ifp = ifp;
				loop_rts.rts_metric = 0;
				loop_rts.rts_origin = RO_LOOPBCK;
				rtadd(myaddr, HOST_MASK, RS_MHOME, &loop_rts);
			}
		}
	}

	for (ifp = ifnet; ifp != NULL; ifp = ifp1) {
		ifp1 = ifp->int_next;	/* because we may delete it */

		/* Forget any interfaces that have disappeared. */
		if (!(ifp->int_state & (IS_CHECKED | IS_REMOTE))) {
			trace_act("interface %s has disappeared",
			    ifp->int_name);
			ifdel(ifp);
			continue;
		}

		if ((ifp->int_state & IS_BROKE) &&
		    !(ifp->int_state & IS_PASSIVE))
			LIM_SEC(ifscan_timer, now.tv_sec+CHECK_BAD_INTERVAL);

		/*
		 * If we ever have a RIPv1 interface, assume we always will.
		 * It might come back if it ever goes away.
		 */
		if (!(ifp->int_state & (IS_NO_RIPV1_OUT | IS_DUP)) &&
		    should_supply(ifp))
			have_ripv1_out = _B_TRUE;
		if (!(ifp->int_state & IS_NO_RIPV1_IN))
			have_ripv1_in = _B_TRUE;
	}

	for (ifp = ifnet; ifp != NULL; ifp = ifp->int_next) {
		/*
		 * Ensure there is always a network route for interfaces,
		 * after any dead interfaces have been deleted, which
		 * might affect routes for point-to-point links.
		 */
		if (addrouteforif(ifp) == 0)
			continue;

		/*
		 * Add routes to the local end of point-to-point interfaces
		 * using loopback.
		 */
		if ((ifp->int_if_flags & IFF_POINTOPOINT) &&
		    !(ifp->int_state & IS_REMOTE) && foundloopback) {
			/*
			 * Delete any routes to the network address through
			 * foreign routers. Remove even static routes.
			 */
			del_static(ifp->int_addr, HOST_MASK, 0, ifp, 0);
			rt = rtget(ifp->int_addr, HOST_MASK);
			if (rt != NULL && rt->rt_router != loopaddr) {
				rtdelete(rt);
				rt = NULL;
			}
			if (rt != NULL) {
				if (!(rt->rt_state & RS_LOCAL) ||
				    rt->rt_metric > ifp->int_metric) {
					ifp1 = ifp;
				} else {
					ifp1 = rt->rt_ifp;
				}
				loop_rts.rts_ifp = ifp1;
				loop_rts.rts_metric = 0;
				loop_rts.rts_time = rt->rt_time;
				loop_rts.rts_origin = RO_LOOPBCK;
				rtchange(rt, ((rt->rt_state & ~RS_NET_SYN) |
				    (RS_IF|RS_LOCAL)), &loop_rts, 0);
			} else {
				loop_rts.rts_ifp = ifp;
				loop_rts.rts_metric = 0;
				loop_rts.rts_origin = RO_LOOPBCK;
				rtadd(ifp->int_addr, HOST_MASK,
				    (RS_IF | RS_LOCAL), &loop_rts);
			}
		}
	}

	/* add the authority routes */
	for (intnetp = intnets; intnetp != NULL;
	    intnetp = intnetp->intnet_next) {
		rt = rtget(intnetp->intnet_addr, intnetp->intnet_mask);
		if (rt != NULL &&
		    !(rt->rt_state & RS_NO_NET_SYN) &&
		    !(rt->rt_state & RS_NET_INT)) {
			rtdelete(rt);
			rt = NULL;
		}
		if (rt == NULL) {
			loop_rts.rts_ifp = NULL;
			loop_rts.rts_metric = intnetp->intnet_metric-1;
			loop_rts.rts_origin = RO_LOOPBCK;
			rtadd(intnetp->intnet_addr, intnetp->intnet_mask,
			    RS_NET_SYN | RS_NET_INT, &loop_rts);
		}
	}

	prev_complaints = complaints;
}


static void
check_net_syn(struct interface *ifp)
{
	struct rt_entry *rt;
	struct rt_spare new;

	/*
	 * Turn on the need to automatically synthesize a network route
	 * for this interface only if we are running RIPv1 on some other
	 * interface that is on a different class-A,B,or C network.
	 */
	if (have_ripv1_out || have_ripv1_in) {
		ifp->int_state |= IS_NEED_NET_SYN;
		rt = rtget(ifp->int_std_addr, ifp->int_std_mask);
		if (rt != NULL &&
		    0 == (rt->rt_state & RS_NO_NET_SYN) &&
		    (!(rt->rt_state & RS_NET_SYN) ||
		    rt->rt_metric > ifp->int_metric)) {
			rtdelete(rt);
			rt = NULL;
		}
		if (rt == NULL) {
			(void) memset(&new, 0, sizeof (new));
			new.rts_ifp = ifp;
			new.rts_gate = ifp->int_addr;
			new.rts_router = ifp->int_addr;
			new.rts_metric = ifp->int_metric;
			new.rts_origin = RO_NET_SYN;
			rtadd(ifp->int_std_addr, ifp->int_std_mask,
			    RS_NET_SYN, &new);
		}

	} else {
		ifp->int_state &= ~IS_NEED_NET_SYN;

		rt = rtget(ifp->int_std_addr, ifp->int_std_mask);
		if (rt != NULL &&
		    (rt->rt_state & RS_NET_SYN) &&
		    rt->rt_ifp == ifp)
			rtbad_sub(rt, NULL);
	}
}


/*
 * Add route for interface if not currently installed.
 * Create route to other end if a point-to-point link,
 * otherwise a route to this (sub)network.
 */
static boolean_t			/* _B_FALSE=bad interface */
addrouteforif(struct interface *ifp)
{
	struct rt_entry *rt;
	struct rt_spare new;
	in_addr_t dst;
	uint16_t rt_newstate = RS_IF;


	/* skip sick interfaces */
	if (ifp->int_state & IS_BROKE)
		return (_B_FALSE);

	/*
	 * don't install routes for duplicate interfaces, or
	 * unnumbered point-to-point interfaces.
	 */
	if ((ifp->int_state & IS_DUP) ||
	    ((ifp->int_if_flags & IFF_POINTOPOINT) && ifp->int_dstaddr == 0))
		return (_B_TRUE);

	/*
	 * If the interface on a subnet, then install a RIPv1 route to
	 * the network as well (unless it is sick).
	 */
	if (ifp->int_state & IS_SUBNET)
		check_net_syn(ifp);

	dst = (0 != (ifp->int_if_flags & (IFF_POINTOPOINT | IFF_LOOPBACK)) ?
	    ifp->int_dstaddr : htonl(ifp->int_net));

	(void) memset(&new, 0, sizeof (new));
	new.rts_ifp = ifp;
	new.rts_router = ifp->int_addr;
	new.rts_gate = ifp->int_addr;
	new.rts_metric = ifp->int_metric;
	new.rts_time = now.tv_sec;
	if (ifp->int_if_flags & IFF_POINTOPOINT)
		new.rts_origin = RO_PTOPT;
	else if (ifp->int_if_flags & IFF_LOOPBACK)
		new.rts_origin = RO_LOOPBCK;
	else
		new.rts_origin = RO_IF;

	/*
	 * If we are going to send packets to the gateway,
	 * it must be reachable using our physical interfaces
	 */
	if ((ifp->int_state & IS_REMOTE) &&
	    !(ifp->int_state & IS_EXTERNAL) &&
	    !check_remote(ifp))
		return (_B_FALSE);

	/*
	 * We are finished if the correct main interface route exists.
	 * The right route must be for the right interface, not synthesized
	 * from a subnet, be a "gateway" or not as appropriate, and so forth.
	 */
	del_static(dst, ifp->int_mask, 0, ifp, 0);
	rt = rtget(dst, ifp->int_mask);
	if (!IS_IFF_ROUTING(ifp->int_if_flags))
		rt_newstate |= RS_NOPROPAGATE;
	if (rt != NULL) {
		if ((rt->rt_ifp != ifp || rt->rt_router != ifp->int_addr) &&
		    (rt->rt_ifp == NULL ||
		    (rt->rt_ifp->int_state & IS_BROKE))) {
			rtdelete(rt);
			rt = NULL;
		} else {
			rtchange(rt, ((rt->rt_state | rt_newstate) &
			    ~(RS_NET_SYN | RS_LOCAL)), &new, 0);
		}
	}
	if (rt == NULL) {
		if (ifp->int_transitions++ > 0)
			trace_act("re-installing interface %s;"
			    " went up %d times",
			    ifp->int_name, ifp->int_transitions);

		rtadd(dst, ifp->int_mask, rt_newstate, &new);
	}

	return (_B_TRUE);
}

/*
 * Obtains the named kstat, and places its value in *value.  It
 * returns 0 for success, -1 for failure.
 */
static int
kstat_named_value(kstat_t *ksp, char *name, uint32_t *value)
{
	kstat_named_t *knp;

	if (ksp == NULL)
		return (-1);

	if ((knp = kstat_data_lookup(ksp, name)) == NULL) {
		return (-1);
	} else if (knp->data_type != KSTAT_DATA_UINT32) {
		return (-1);
	} else {
		*value = knp->value.ui32;
		return (0);
	}
}

static int
get_if_kstats(struct interface *ifp, struct phyi_data *newdata)
{
	struct physical_interface *phyi = ifp->int_phys;
	kstat_ctl_t *kc;
	kstat_t *ksp;

	/* We did this recently; don't do it again. */
	if (phyi->phyi_data.ts == now.tv_sec) {
		if (newdata != &phyi->phyi_data)
			*newdata = phyi->phyi_data;
		return (0);
	}

	if ((kc = kstat_open()) == NULL)
		return (-1);

	if ((ksp = kstat_lookup(kc, NULL, -1, phyi->phyi_name)) == NULL) {
		(void) kstat_close(kc);
		return (-1);
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		(void) kstat_close(kc);
		return (-1);
	}

	if ((kstat_named_value(ksp, "ipackets", &newdata->ipackets) == -1) ||
	    (kstat_named_value(ksp, "opackets",	&newdata->opackets) == -1)) {
		newdata->ts = 0;
		(void) kstat_close(kc);
		return (-1);
	}

	/* The loopback interface does not keep track of errors */
	if (!(ifp->int_if_flags & IFF_LOOPBACK)) {
		if ((kstat_named_value(ksp, "ierrors",
		    &newdata->ierrors) == -1) ||
		    (kstat_named_value(ksp, "oerrors",
		    &newdata->oerrors) == -1)) {
			newdata->ts = 0;
			(void) kstat_close(kc);
			return (-1);
		}
	}

	newdata->ts = now.tv_sec;
	(void) kstat_close(kc);
	return (0);
}

/*
 * Returns true if we should supply routes to other systems.  If the
 * user has forced us to be a supplier (by the command line) or if we
 * have more than one forwarding interface and this is one of the
 * forwarding interfaces, then behave as a RIP supplier (supply rdisc
 * advertisements and RIP responses).
 */
boolean_t
should_supply(struct interface *ifp)
{
	if (ifp != NULL && !IS_IFF_ROUTING(ifp->int_if_flags))
		return (_B_FALSE);
	return ((supplier_set && supplier) ||
	    (!supplier_set && fwd_interfaces > 1));
}
