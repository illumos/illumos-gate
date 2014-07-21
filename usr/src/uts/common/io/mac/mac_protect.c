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
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/strsun.h>
#include <sys/sdt.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/ethernet.h>
#include <sys/vlan.h>
#include <sys/dlpi.h>
#include <sys/avl.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/arp.h>
#include <netinet/arp.h>
#include <netinet/udp.h>
#include <netinet/dhcp.h>
#include <netinet/dhcp6.h>

/*
 * Implementation overview for DHCP address detection
 *
 * The purpose of DHCP address detection is to relieve the user of having to
 * manually configure static IP addresses when ip-nospoof protection is turned
 * on. To achieve this, the mac layer needs to intercept DHCP packets to
 * determine the assigned IP addresses.
 *
 * A DHCP handshake between client and server typically requires at least
 * 4 messages:
 *
 * 1. DISCOVER - client attempts to locate DHCP servers via a
 *               broadcast message to its subnet.
 * 2. OFFER    - server responds to client with an IP address and
 *               other parameters.
 * 3. REQUEST  - client requests the offered address.
 * 4. ACK      - server verifies that the requested address matches
 *               the one it offered.
 *
 * DHCPv6 behaves pretty much the same way aside from different message names.
 *
 * Address information is embedded in either the OFFER or REQUEST message.
 * We chose to intercept REQUEST because this is at the last part of the
 * handshake and it indicates that the client intends to keep the address.
 * Intercepting OFFERs is unreliable because the client may receive multiple
 * offers from different servers, and we can't tell which address the client
 * will keep.
 *
 * Each DHCP message has a transaction ID. We use this transaction ID to match
 * REQUESTs with ACKs received from servers.
 *
 * For IPv4, the process to acquire a DHCP-assigned address is as follows:
 *
 * 1. Client sends REQUEST. a new dhcpv4_txn_t object is created and inserted
 *    in the the mci_v4_pending_txn table (keyed by xid). This object represents
 *    a new transaction. It contains the xid, the client ID and requested IP
 *    address.
 *
 * 2. Server responds with an ACK. The xid from this ACK is used to lookup the
 *    pending transaction from the mci_v4_pending_txn table. Once the object is
 *    found, it is removed from the pending table and inserted into the
 *    completed table (mci_v4_completed_txn, keyed by client ID) and the dynamic
 *    IP table (mci_v4_dyn_ip, keyed by IP address).
 *
 * 3. An outgoing packet that goes through the ip-nospoof path will be checked
 *    against the dynamic IP table. Packets that have the assigned DHCP address
 *    as the source IP address will pass the check and be admitted onto the
 *    network.
 *
 * IPv4 notes:
 *
 * If the server never responds with an ACK, there is a timer that is set after
 * the insertion of the transaction into the pending table. When the timer
 * fires, it will check whether the transaction is old (by comparing current
 * time and the txn's timestamp), if so the transaction will be freed. along
 * with this, any transaction in the completed/dyn-ip tables matching the client
 * ID of this stale transaction will also be freed. If the client fails to
 * extend a lease, we want to stop the client from using any IP addresses that
 * were granted previously.
 *
 * A RELEASE message from the client will not cause a transaction to be created.
 * The client ID in the RELEASE message will be used for finding and removing
 * transactions in the completed and dyn-ip tables.
 *
 *
 * For IPv6, the process to acquire a DHCPv6-assigned address is as follows:
 *
 * 1. Client sends REQUEST. The DUID is extracted and stored into a dhcpv6_cid_t
 *    structure. A new transaction structure (dhcpv6_txn_t) is also created and
 *    it will point to the dhcpv6_cid_t. If an existing transaction with a
 *    matching xid is not found, this dhcpv6_txn_t will be inserted into the
 *    mci_v6_pending_txn table (keyed by xid).
 *
 * 2. Server responds with a REPLY. If a pending transaction is found, the
 *    addresses in the reply will be placed into the dhcpv6_cid_t pointed to by
 *    the transaction. The dhcpv6_cid_t will then be moved to the mci_v6_cid
 *    table (keyed by cid). The associated addresses will be added to the
 *    mci_v6_dyn_ip table (while still being pointed to by the dhcpv6_cid_t).
 *
 * 3. IPv6 ip-nospoof will now check mci_v6_dyn_ip for matching packets.
 *    Packets with a source address matching one of the DHCPv6-assigned
 *    addresses will be allowed through.
 *
 * IPv6 notes:
 *
 * The v6 code shares the same timer as v4 for scrubbing stale transactions.
 * Just like v4, as part of removing an expired transaction, a RELEASE will be
 * be triggered on the cid associated with the expired transaction.
 *
 * The data structures used for v6 are slightly different because a v6 client
 * may have multiple addresses associated with it.
 */

/*
 * These are just arbitrary limits meant for preventing abuse (e.g. a user
 * flooding the network with bogus transactions). They are not meant to be
 * user-modifiable so they are not exposed as linkprops.
 */
static ulong_t	dhcp_max_pending_txn = 512;
static ulong_t	dhcp_max_completed_txn = 512;
static hrtime_t	txn_cleanup_interval = 60 * NANOSEC;

/*
 * DHCPv4 transaction. It may be added to three different tables
 * (keyed by different fields).
 */
typedef struct dhcpv4_txn {
	uint32_t		dt_xid;
	hrtime_t		dt_timestamp;
	uint8_t			dt_cid[DHCP_MAX_OPT_SIZE];
	uint8_t			dt_cid_len;
	ipaddr_t		dt_ipaddr;
	avl_node_t		dt_node;
	avl_node_t		dt_ipnode;
	struct dhcpv4_txn	*dt_next;
} dhcpv4_txn_t;

/*
 * DHCPv6 address. May be added to mci_v6_dyn_ip.
 * It is always pointed to by its parent dhcpv6_cid_t structure.
 */
typedef struct dhcpv6_addr {
	in6_addr_t		da_addr;
	avl_node_t		da_node;
	struct dhcpv6_addr	*da_next;
} dhcpv6_addr_t;

/*
 * DHCPv6 client ID. May be added to mci_v6_cid.
 * No dhcpv6_txn_t should be pointing to it after it is added to mci_v6_cid.
 */
typedef struct dhcpv6_cid {
	uchar_t			*dc_cid;
	uint_t			dc_cid_len;
	dhcpv6_addr_t		*dc_addr;
	uint_t			dc_addrcnt;
	avl_node_t		dc_node;
} dhcpv6_cid_t;

/*
 * DHCPv6 transaction. Unlike its v4 counterpart, this object gets freed up
 * as soon as the transaction completes or expires.
 */
typedef struct dhcpv6_txn {
	uint32_t		dt_xid;
	hrtime_t		dt_timestamp;
	dhcpv6_cid_t		*dt_cid;
	avl_node_t		dt_node;
	struct dhcpv6_txn	*dt_next;
} dhcpv6_txn_t;

static void	start_txn_cleanup_timer(mac_client_impl_t *);
static boolean_t allowed_ips_set(mac_resource_props_t *, uint32_t);

#define	BUMP_STAT(m, s)	(m)->mci_misc_stat.mms_##s++

/*
 * Comparison functions for the 3 AVL trees used:
 * mci_v4_pending_txn, mci_v4_completed_txn, mci_v4_dyn_ip
 */
static int
compare_dhcpv4_xid(const void *arg1, const void *arg2)
{
	const dhcpv4_txn_t	*txn1 = arg1, *txn2 = arg2;

	if (txn1->dt_xid < txn2->dt_xid)
		return (-1);
	else if (txn1->dt_xid > txn2->dt_xid)
		return (1);
	else
		return (0);
}

static int
compare_dhcpv4_cid(const void *arg1, const void *arg2)
{
	const dhcpv4_txn_t	*txn1 = arg1, *txn2 = arg2;
	int			ret;

	if (txn1->dt_cid_len < txn2->dt_cid_len)
		return (-1);
	else if (txn1->dt_cid_len > txn2->dt_cid_len)
		return (1);

	if (txn1->dt_cid_len == 0)
		return (0);

	ret = memcmp(txn1->dt_cid, txn2->dt_cid, txn1->dt_cid_len);
	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

static int
compare_dhcpv4_ip(const void *arg1, const void *arg2)
{
	const dhcpv4_txn_t	*txn1 = arg1, *txn2 = arg2;

	if (txn1->dt_ipaddr < txn2->dt_ipaddr)
		return (-1);
	else if (txn1->dt_ipaddr > txn2->dt_ipaddr)
		return (1);
	else
		return (0);
}

/*
 * Find the specified DHCPv4 option.
 */
static int
get_dhcpv4_option(struct dhcp *dh4, uchar_t *end, uint8_t type,
    uchar_t **opt, uint8_t *opt_len)
{
	uchar_t		*start = (uchar_t *)dh4->options;
	uint8_t		otype, olen;

	while (start < end) {
		if (*start == CD_PAD) {
			start++;
			continue;
		}
		if (*start == CD_END)
			break;

		otype = *start++;
		olen = *start++;
		if (otype == type && olen > 0) {
			*opt = start;
			*opt_len = olen;
			return (0);
		}
		start += olen;
	}
	return (ENOENT);
}

/*
 * Locate the start of a DHCPv4 header.
 * The possible return values and associated meanings are:
 * 0      - packet is DHCP and has a DHCP header.
 * EINVAL - packet is not DHCP. the recommended action is to let it pass.
 * ENOSPC - packet is a initial fragment that is DHCP or is unidentifiable.
 *          the recommended action is to drop it.
 */
static int
get_dhcpv4_info(ipha_t *ipha, uchar_t *end, struct dhcp **dh4)
{
	uint16_t	offset_and_flags, client, server;
	boolean_t	first_frag = B_FALSE;
	struct udphdr	*udph;
	uchar_t		*dh;

	if (ipha->ipha_protocol != IPPROTO_UDP)
		return (EINVAL);

	offset_and_flags = ntohs(ipha->ipha_fragment_offset_and_flags);
	if ((offset_and_flags & (IPH_MF | IPH_OFFSET)) != 0) {
		/*
		 * All non-initial fragments may pass because we cannot
		 * identify their type. It's safe to let them through
		 * because reassembly will fail if we decide to drop the
		 * initial fragment.
		 */
		if (((offset_and_flags << 3) & 0xffff) != 0)
			return (EINVAL);
		first_frag = B_TRUE;
	}
	/* drop packets without a udp header */
	udph = (struct udphdr *)((uchar_t *)ipha + IPH_HDR_LENGTH(ipha));
	if ((uchar_t *)&udph[1] > end)
		return (ENOSPC);

	client = htons(IPPORT_BOOTPC);
	server = htons(IPPORT_BOOTPS);
	if (udph->uh_sport != client && udph->uh_sport != server &&
	    udph->uh_dport != client && udph->uh_dport != server)
		return (EINVAL);

	/* drop dhcp fragments */
	if (first_frag)
		return (ENOSPC);

	dh = (uchar_t *)&udph[1];
	if (dh + BASE_PKT_SIZE > end)
		return (EINVAL);

	*dh4 = (struct dhcp *)dh;
	return (0);
}

/*
 * Wrappers for accesses to avl trees to improve readability.
 * Their purposes are fairly self-explanatory.
 */
static dhcpv4_txn_t *
find_dhcpv4_pending_txn(mac_client_impl_t *mcip, uint32_t xid)
{
	dhcpv4_txn_t	tmp_txn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	tmp_txn.dt_xid = xid;
	return (avl_find(&mcip->mci_v4_pending_txn, &tmp_txn, NULL));
}

static int
insert_dhcpv4_pending_txn(mac_client_impl_t *mcip, dhcpv4_txn_t *txn)
{
	avl_index_t	where;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (avl_find(&mcip->mci_v4_pending_txn, txn, &where) != NULL)
		return (EEXIST);

	if (avl_numnodes(&mcip->mci_v4_pending_txn) >= dhcp_max_pending_txn) {
		BUMP_STAT(mcip, dhcpdropped);
		return (EAGAIN);
	}
	avl_insert(&mcip->mci_v4_pending_txn, txn, where);
	return (0);
}

static void
remove_dhcpv4_pending_txn(mac_client_impl_t *mcip, dhcpv4_txn_t *txn)
{
	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	avl_remove(&mcip->mci_v4_pending_txn, txn);
}

static dhcpv4_txn_t *
find_dhcpv4_completed_txn(mac_client_impl_t *mcip, uint8_t *cid,
    uint8_t cid_len)
{
	dhcpv4_txn_t	tmp_txn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (cid_len > 0)
		bcopy(cid, tmp_txn.dt_cid, cid_len);
	tmp_txn.dt_cid_len = cid_len;
	return (avl_find(&mcip->mci_v4_completed_txn, &tmp_txn, NULL));
}

/*
 * After a pending txn is removed from the pending table, it is inserted
 * into both the completed and dyn-ip tables. These two insertions are
 * done together because a client ID must have 1:1 correspondence with
 * an IP address and IP addresses must be unique in the dyn-ip table.
 */
static int
insert_dhcpv4_completed_txn(mac_client_impl_t *mcip, dhcpv4_txn_t *txn)
{
	avl_index_t	where;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (avl_find(&mcip->mci_v4_completed_txn, txn, &where) != NULL)
		return (EEXIST);

	if (avl_numnodes(&mcip->mci_v4_completed_txn) >=
	    dhcp_max_completed_txn) {
		BUMP_STAT(mcip, dhcpdropped);
		return (EAGAIN);
	}

	avl_insert(&mcip->mci_v4_completed_txn, txn, where);
	if (avl_find(&mcip->mci_v4_dyn_ip, txn, &where) != NULL) {
		avl_remove(&mcip->mci_v4_completed_txn, txn);
		return (EEXIST);
	}
	avl_insert(&mcip->mci_v4_dyn_ip, txn, where);
	return (0);
}

static void
remove_dhcpv4_completed_txn(mac_client_impl_t *mcip, dhcpv4_txn_t *txn)
{
	dhcpv4_txn_t	*ctxn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if ((ctxn = avl_find(&mcip->mci_v4_dyn_ip, txn, NULL)) != NULL &&
	    ctxn == txn)
		avl_remove(&mcip->mci_v4_dyn_ip, txn);

	avl_remove(&mcip->mci_v4_completed_txn, txn);
}

/*
 * Check whether an IP address is in the dyn-ip table.
 */
static boolean_t
check_dhcpv4_dyn_ip(mac_client_impl_t *mcip, ipaddr_t ipaddr)
{
	dhcpv4_txn_t	tmp_txn, *txn;

	mutex_enter(&mcip->mci_protect_lock);
	tmp_txn.dt_ipaddr = ipaddr;
	txn = avl_find(&mcip->mci_v4_dyn_ip, &tmp_txn, NULL);
	mutex_exit(&mcip->mci_protect_lock);
	return (txn != NULL);
}

/*
 * Create/destroy a DHCPv4 transaction.
 */
static dhcpv4_txn_t *
create_dhcpv4_txn(uint32_t xid, uint8_t *cid, uint8_t cid_len, ipaddr_t ipaddr)
{
	dhcpv4_txn_t	*txn;

	if ((txn = kmem_zalloc(sizeof (*txn), KM_NOSLEEP)) == NULL)
		return (NULL);

	txn->dt_xid = xid;
	txn->dt_timestamp = gethrtime();
	if (cid_len > 0)
		bcopy(cid, &txn->dt_cid, cid_len);
	txn->dt_cid_len = cid_len;
	txn->dt_ipaddr = ipaddr;
	return (txn);
}

static void
free_dhcpv4_txn(dhcpv4_txn_t *txn)
{
	kmem_free(txn, sizeof (*txn));
}

/*
 * Clean up all v4 tables.
 */
static void
flush_dhcpv4(mac_client_impl_t *mcip)
{
	void		*cookie = NULL;
	dhcpv4_txn_t	*txn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	while ((txn = avl_destroy_nodes(&mcip->mci_v4_dyn_ip,
	    &cookie)) != NULL) {
		/*
		 * No freeing needed here because the same txn exists
		 * in the mci_v4_completed_txn table as well.
		 */
	}
	cookie = NULL;
	while ((txn = avl_destroy_nodes(&mcip->mci_v4_completed_txn,
	    &cookie)) != NULL) {
		free_dhcpv4_txn(txn);
	}
	cookie = NULL;
	while ((txn = avl_destroy_nodes(&mcip->mci_v4_pending_txn,
	    &cookie)) != NULL) {
		free_dhcpv4_txn(txn);
	}
}

/*
 * Cleanup stale DHCPv4 transactions.
 */
static void
txn_cleanup_v4(mac_client_impl_t *mcip)
{
	dhcpv4_txn_t		*txn, *ctxn, *next, *txn_list = NULL;

	/*
	 * Find stale pending transactions and place them on a list
	 * to be removed.
	 */
	for (txn = avl_first(&mcip->mci_v4_pending_txn); txn != NULL;
	    txn = avl_walk(&mcip->mci_v4_pending_txn, txn, AVL_AFTER)) {
		if (gethrtime() - txn->dt_timestamp > txn_cleanup_interval) {
			DTRACE_PROBE2(found__expired__txn,
			    mac_client_impl_t *, mcip,
			    dhcpv4_txn_t *, txn);

			txn->dt_next = txn_list;
			txn_list = txn;
		}
	}

	/*
	 * Remove and free stale pending transactions and completed
	 * transactions with the same client IDs as the stale transactions.
	 */
	for (txn = txn_list; txn != NULL; txn = next) {
		avl_remove(&mcip->mci_v4_pending_txn, txn);

		ctxn = find_dhcpv4_completed_txn(mcip, txn->dt_cid,
		    txn->dt_cid_len);
		if (ctxn != NULL) {
			DTRACE_PROBE2(removing__completed__txn,
			    mac_client_impl_t *, mcip,
			    dhcpv4_txn_t *, ctxn);

			remove_dhcpv4_completed_txn(mcip, ctxn);
			free_dhcpv4_txn(ctxn);
		}
		next = txn->dt_next;
		txn->dt_next = NULL;

		DTRACE_PROBE2(freeing__txn, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, txn);
		free_dhcpv4_txn(txn);
	}
}

/*
 * Core logic for intercepting outbound DHCPv4 packets.
 */
static boolean_t
intercept_dhcpv4_outbound(mac_client_impl_t *mcip, ipha_t *ipha, uchar_t *end)
{
	struct dhcp		*dh4;
	uchar_t			*opt;
	dhcpv4_txn_t		*txn, *ctxn;
	ipaddr_t		ipaddr;
	uint8_t			opt_len, mtype, cid[DHCP_MAX_OPT_SIZE], cid_len;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);

	if (get_dhcpv4_info(ipha, end, &dh4) != 0)
		return (B_TRUE);

	/* ip_nospoof/allowed-ips and DHCP are mutually exclusive by default */
	if (allowed_ips_set(mrp, IPV4_VERSION))
		return (B_FALSE);

	if (get_dhcpv4_option(dh4, end, CD_DHCP_TYPE, &opt, &opt_len) != 0 ||
	    opt_len != 1) {
		DTRACE_PROBE2(mtype__not__found, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4);
		return (B_TRUE);
	}
	mtype = *opt;
	if (mtype != REQUEST && mtype != RELEASE) {
		DTRACE_PROBE3(ignored__mtype, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4, uint8_t, mtype);
		return (B_TRUE);
	}

	/* client ID is optional for IPv4 */
	if (get_dhcpv4_option(dh4, end, CD_CLIENT_ID, &opt, &opt_len) == 0 &&
	    opt_len >= 2) {
		bcopy(opt, cid, opt_len);
		cid_len = opt_len;
	} else {
		bzero(cid, DHCP_MAX_OPT_SIZE);
		cid_len = 0;
	}

	mutex_enter(&mcip->mci_protect_lock);
	if (mtype == RELEASE) {
		DTRACE_PROBE2(release, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4);

		/* flush any completed txn with this cid */
		ctxn = find_dhcpv4_completed_txn(mcip, cid, cid_len);
		if (ctxn != NULL) {
			DTRACE_PROBE2(release__successful, mac_client_impl_t *,
			    mcip, struct dhcp *, dh4);

			remove_dhcpv4_completed_txn(mcip, ctxn);
			free_dhcpv4_txn(ctxn);
		}
		goto done;
	}

	/*
	 * If a pending txn already exists, we'll update its timestamp so
	 * it won't get flushed by the timer. We don't need to create new
	 * txns for retransmissions.
	 */
	if ((txn = find_dhcpv4_pending_txn(mcip, dh4->xid)) != NULL) {
		DTRACE_PROBE2(update, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, txn);
		txn->dt_timestamp = gethrtime();
		goto done;
	}

	if (get_dhcpv4_option(dh4, end, CD_REQUESTED_IP_ADDR,
	    &opt, &opt_len) != 0 || opt_len != sizeof (ipaddr)) {
		DTRACE_PROBE2(ipaddr__not__found, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4);
		goto done;
	}
	bcopy(opt, &ipaddr, sizeof (ipaddr));
	if ((txn = create_dhcpv4_txn(dh4->xid, cid, cid_len, ipaddr)) == NULL)
		goto done;

	if (insert_dhcpv4_pending_txn(mcip, txn) != 0) {
		DTRACE_PROBE2(insert__failed, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, txn);
		free_dhcpv4_txn(txn);
		goto done;
	}
	start_txn_cleanup_timer(mcip);

	DTRACE_PROBE2(txn__pending, mac_client_impl_t *, mcip,
	    dhcpv4_txn_t *, txn);

done:
	mutex_exit(&mcip->mci_protect_lock);
	return (B_TRUE);
}

/*
 * Core logic for intercepting inbound DHCPv4 packets.
 */
static void
intercept_dhcpv4_inbound(mac_client_impl_t *mcip, ipha_t *ipha, uchar_t *end)
{
	uchar_t		*opt;
	struct dhcp	*dh4;
	dhcpv4_txn_t	*txn, *ctxn;
	uint8_t		opt_len, mtype;

	if (get_dhcpv4_info(ipha, end, &dh4) != 0)
		return;

	if (get_dhcpv4_option(dh4, end, CD_DHCP_TYPE, &opt, &opt_len) != 0 ||
	    opt_len != 1) {
		DTRACE_PROBE2(mtype__not__found, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4);
		return;
	}
	mtype = *opt;
	if (mtype != ACK && mtype != NAK) {
		DTRACE_PROBE3(ignored__mtype, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4, uint8_t, mtype);
		return;
	}

	mutex_enter(&mcip->mci_protect_lock);
	if ((txn = find_dhcpv4_pending_txn(mcip, dh4->xid)) == NULL) {
		DTRACE_PROBE2(txn__not__found, mac_client_impl_t *, mcip,
		    struct dhcp *, dh4);
		goto done;
	}
	remove_dhcpv4_pending_txn(mcip, txn);

	/*
	 * We're about to move a txn from the pending table to the completed/
	 * dyn-ip tables. If there is an existing completed txn with the
	 * same cid as our txn, we need to remove and free it.
	 */
	ctxn = find_dhcpv4_completed_txn(mcip, txn->dt_cid, txn->dt_cid_len);
	if (ctxn != NULL) {
		DTRACE_PROBE2(replacing__old__txn, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, ctxn);
		remove_dhcpv4_completed_txn(mcip, ctxn);
		free_dhcpv4_txn(ctxn);
	}
	if (mtype == NAK) {
		DTRACE_PROBE2(nak__received, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, txn);
		free_dhcpv4_txn(txn);
		goto done;
	}
	if (insert_dhcpv4_completed_txn(mcip, txn) != 0) {
		DTRACE_PROBE2(insert__failed, mac_client_impl_t *, mcip,
		    dhcpv4_txn_t *, txn);
		free_dhcpv4_txn(txn);
		goto done;
	}
	DTRACE_PROBE2(txn__completed, mac_client_impl_t *, mcip,
	    dhcpv4_txn_t *, txn);

done:
	mutex_exit(&mcip->mci_protect_lock);
}


/*
 * Comparison functions for the DHCPv6 AVL trees.
 */
static int
compare_dhcpv6_xid(const void *arg1, const void *arg2)
{
	const dhcpv6_txn_t	*txn1 = arg1, *txn2 = arg2;

	if (txn1->dt_xid < txn2->dt_xid)
		return (-1);
	else if (txn1->dt_xid > txn2->dt_xid)
		return (1);
	else
		return (0);
}

static int
compare_dhcpv6_ip(const void *arg1, const void *arg2)
{
	const dhcpv6_addr_t	*ip1 = arg1, *ip2 = arg2;
	int			ret;

	ret = memcmp(&ip1->da_addr, &ip2->da_addr, sizeof (in6_addr_t));
	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

static int
compare_dhcpv6_cid(const void *arg1, const void *arg2)
{
	const dhcpv6_cid_t	*cid1 = arg1, *cid2 = arg2;
	int			ret;

	if (cid1->dc_cid_len < cid2->dc_cid_len)
		return (-1);
	else if (cid1->dc_cid_len > cid2->dc_cid_len)
		return (1);

	if (cid1->dc_cid_len == 0)
		return (0);

	ret = memcmp(cid1->dc_cid, cid2->dc_cid, cid1->dc_cid_len);
	if (ret < 0)
		return (-1);
	else if (ret > 0)
		return (1);
	else
		return (0);
}

/*
 * Locate the start of a DHCPv6 header.
 * The possible return values and associated meanings are:
 * 0      - packet is DHCP and has a DHCP header.
 * EINVAL - packet is not DHCP. the recommended action is to let it pass.
 * ENOSPC - packet is a initial fragment that is DHCP or is unidentifiable.
 *          the recommended action is to drop it.
 */
static int
get_dhcpv6_info(ip6_t *ip6h, uchar_t *end, dhcpv6_message_t **dh6)
{
	uint16_t	hdrlen, client, server;
	boolean_t	first_frag = B_FALSE;
	ip6_frag_t	*frag = NULL;
	uint8_t		proto;
	struct udphdr	*udph;
	uchar_t		*dh;

	if (!mac_ip_hdr_length_v6(ip6h, end, &hdrlen, &proto, &frag))
		return (ENOSPC);

	if (proto != IPPROTO_UDP)
		return (EINVAL);

	if (frag != NULL) {
		/*
		 * All non-initial fragments may pass because we cannot
		 * identify their type. It's safe to let them through
		 * because reassembly will fail if we decide to drop the
		 * initial fragment.
		 */
		if ((ntohs(frag->ip6f_offlg) & ~7) != 0)
			return (EINVAL);
		first_frag = B_TRUE;
	}
	/* drop packets without a udp header */
	udph = (struct udphdr *)((uchar_t *)ip6h + hdrlen);
	if ((uchar_t *)&udph[1] > end)
		return (ENOSPC);

	client = htons(IPPORT_DHCPV6C);
	server = htons(IPPORT_DHCPV6S);
	if (udph->uh_sport != client && udph->uh_sport != server &&
	    udph->uh_dport != client && udph->uh_dport != server)
		return (EINVAL);

	/* drop dhcp fragments */
	if (first_frag)
		return (ENOSPC);

	dh = (uchar_t *)&udph[1];
	if (dh + sizeof (dhcpv6_message_t) > end)
		return (EINVAL);

	*dh6 = (dhcpv6_message_t *)dh;
	return (0);
}

/*
 * Find the specified DHCPv6 option.
 */
static dhcpv6_option_t *
get_dhcpv6_option(void *buf, size_t buflen, dhcpv6_option_t *oldopt,
    uint16_t codenum, uint_t *retlenp)
{
	uchar_t		*bp;
	dhcpv6_option_t	d6o;
	uint_t		olen;

	codenum = htons(codenum);
	bp = buf;
	while (buflen >= sizeof (dhcpv6_option_t)) {
		bcopy(bp, &d6o, sizeof (d6o));
		olen = ntohs(d6o.d6o_len) + sizeof (d6o);
		if (olen > buflen)
			break;
		if (d6o.d6o_code != codenum || d6o.d6o_len == 0 ||
		    (oldopt != NULL && bp <= (uchar_t *)oldopt)) {
			bp += olen;
			buflen -= olen;
			continue;
		}
		if (retlenp != NULL)
			*retlenp = olen;
		/* LINTED : alignment */
		return ((dhcpv6_option_t *)bp);
	}
	return (NULL);
}

/*
 * Get the status code from a reply message.
 */
static int
get_dhcpv6_status(dhcpv6_message_t *dh6, uchar_t *end, uint16_t *status)
{
	dhcpv6_option_t	*d6o;
	uint_t		olen;
	uint16_t	s;

	d6o = get_dhcpv6_option(&dh6[1], end - (uchar_t *)&dh6[1], NULL,
	    DHCPV6_OPT_STATUS_CODE, &olen);

	/* Success is implied if status code is missing */
	if (d6o == NULL) {
		*status = DHCPV6_STAT_SUCCESS;
		return (0);
	}
	if ((uchar_t *)d6o + olen > end)
		return (EINVAL);

	olen -= sizeof (*d6o);
	if (olen < sizeof (s))
		return (EINVAL);

	bcopy(&d6o[1], &s, sizeof (s));
	*status = ntohs(s);
	return (0);
}

/*
 * Get the addresses from a reply message.
 */
static int
get_dhcpv6_addrs(dhcpv6_message_t *dh6, uchar_t *end, dhcpv6_cid_t *cid)
{
	dhcpv6_option_t		*d6o;
	dhcpv6_addr_t		*next;
	uint_t			olen;

	d6o = NULL;
	while ((d6o = get_dhcpv6_option(&dh6[1], end - (uchar_t *)&dh6[1],
	    d6o, DHCPV6_OPT_IA_NA, &olen)) != NULL) {
		dhcpv6_option_t		*d6so;
		dhcpv6_iaaddr_t		d6ia;
		dhcpv6_addr_t		**addrp;
		uchar_t			*obase;
		uint_t			solen;

		if (olen < sizeof (dhcpv6_ia_na_t) ||
		    (uchar_t *)d6o + olen > end)
			goto fail;

		obase = (uchar_t *)d6o + sizeof (dhcpv6_ia_na_t);
		olen -= sizeof (dhcpv6_ia_na_t);
		d6so = NULL;
		while ((d6so = get_dhcpv6_option(obase, olen, d6so,
		    DHCPV6_OPT_IAADDR, &solen)) != NULL) {
			if (solen < sizeof (dhcpv6_iaaddr_t) ||
			    (uchar_t *)d6so + solen > end)
				goto fail;

			bcopy(d6so, &d6ia, sizeof (d6ia));
			for (addrp = &cid->dc_addr; *addrp != NULL;
			    addrp = &(*addrp)->da_next) {
				if (bcmp(&(*addrp)->da_addr, &d6ia.d6ia_addr,
				    sizeof (in6_addr_t)) == 0)
					goto fail;
			}
			if ((*addrp = kmem_zalloc(sizeof (dhcpv6_addr_t),
			    KM_NOSLEEP)) == NULL)
				goto fail;

			bcopy(&d6ia.d6ia_addr, &(*addrp)->da_addr,
			    sizeof (in6_addr_t));
			cid->dc_addrcnt++;
		}
	}
	if (cid->dc_addrcnt == 0)
		return (ENOENT);

	return (0);

fail:
	for (; cid->dc_addr != NULL; cid->dc_addr = next) {
		next = cid->dc_addr->da_next;
		kmem_free(cid->dc_addr, sizeof (dhcpv6_addr_t));
		cid->dc_addrcnt--;
	}
	ASSERT(cid->dc_addrcnt == 0);
	return (EINVAL);
}

/*
 * Free a cid.
 * Before this gets called the caller must ensure that all the
 * addresses are removed from the mci_v6_dyn_ip table.
 */
static void
free_dhcpv6_cid(dhcpv6_cid_t *cid)
{
	dhcpv6_addr_t	*addr, *next;
	uint_t		cnt = 0;

	kmem_free(cid->dc_cid, cid->dc_cid_len);
	for (addr = cid->dc_addr; addr != NULL; addr = next) {
		next = addr->da_next;
		kmem_free(addr, sizeof (*addr));
		cnt++;
	}
	ASSERT(cnt == cid->dc_addrcnt);
	kmem_free(cid, sizeof (*cid));
}

/*
 * Extract the DUID from a message. The associated addresses will be
 * extracted later from the reply message.
 */
static dhcpv6_cid_t *
create_dhcpv6_cid(dhcpv6_message_t *dh6, uchar_t *end)
{
	dhcpv6_option_t		*d6o;
	dhcpv6_cid_t		*cid;
	uchar_t			*rawcid;
	uint_t			olen, rawcidlen;

	d6o = get_dhcpv6_option(&dh6[1], end - (uchar_t *)&dh6[1], NULL,
	    DHCPV6_OPT_CLIENTID, &olen);
	if (d6o == NULL || (uchar_t *)d6o + olen > end)
		return (NULL);

	rawcidlen = olen - sizeof (*d6o);
	if ((rawcid = kmem_zalloc(rawcidlen, KM_NOSLEEP)) == NULL)
		return (NULL);
	bcopy(d6o + 1, rawcid, rawcidlen);

	if ((cid = kmem_zalloc(sizeof (*cid), KM_NOSLEEP)) == NULL) {
		kmem_free(rawcid, rawcidlen);
		return (NULL);
	}
	cid->dc_cid = rawcid;
	cid->dc_cid_len = rawcidlen;
	return (cid);
}

/*
 * Remove a cid from mci_v6_cid. The addresses owned by the cid
 * are also removed from mci_v6_dyn_ip.
 */
static void
remove_dhcpv6_cid(mac_client_impl_t *mcip, dhcpv6_cid_t *cid)
{
	dhcpv6_addr_t	*addr, *tmp_addr;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	avl_remove(&mcip->mci_v6_cid, cid);
	for (addr = cid->dc_addr; addr != NULL; addr = addr->da_next) {
		tmp_addr = avl_find(&mcip->mci_v6_dyn_ip, addr, NULL);
		if (tmp_addr == addr)
			avl_remove(&mcip->mci_v6_dyn_ip, addr);
	}
}

/*
 * Find and remove a matching cid and associated addresses from
 * their respective tables.
 */
static void
release_dhcpv6_cid(mac_client_impl_t *mcip, dhcpv6_cid_t *cid)
{
	dhcpv6_cid_t	*oldcid;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if ((oldcid = avl_find(&mcip->mci_v6_cid, cid, NULL)) == NULL)
		return;

	/*
	 * Since cid belongs to a pending txn, it can't possibly be in
	 * mci_v6_cid. Anything that's found must be an existing cid.
	 */
	ASSERT(oldcid != cid);
	remove_dhcpv6_cid(mcip, oldcid);
	free_dhcpv6_cid(oldcid);
}

/*
 * Insert cid into mci_v6_cid.
 */
static int
insert_dhcpv6_cid(mac_client_impl_t *mcip, dhcpv6_cid_t *cid)
{
	avl_index_t	where;
	dhcpv6_addr_t	*addr;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (avl_find(&mcip->mci_v6_cid, cid, &where) != NULL)
		return (EEXIST);

	if (avl_numnodes(&mcip->mci_v6_cid) >= dhcp_max_completed_txn) {
		BUMP_STAT(mcip, dhcpdropped);
		return (EAGAIN);
	}
	avl_insert(&mcip->mci_v6_cid, cid, where);
	for (addr = cid->dc_addr; addr != NULL; addr = addr->da_next) {
		if (avl_find(&mcip->mci_v6_dyn_ip, addr, &where) != NULL)
			goto fail;

		avl_insert(&mcip->mci_v6_dyn_ip, addr, where);
	}
	return (0);

fail:
	remove_dhcpv6_cid(mcip, cid);
	return (EEXIST);
}

/*
 * Check whether an IP address is in the dyn-ip table.
 */
static boolean_t
check_dhcpv6_dyn_ip(mac_client_impl_t *mcip, in6_addr_t *addr)
{
	dhcpv6_addr_t	tmp_addr, *a;

	mutex_enter(&mcip->mci_protect_lock);
	bcopy(addr, &tmp_addr.da_addr, sizeof (in6_addr_t));
	a = avl_find(&mcip->mci_v6_dyn_ip, &tmp_addr, NULL);
	mutex_exit(&mcip->mci_protect_lock);
	return (a != NULL);
}

static dhcpv6_txn_t *
find_dhcpv6_pending_txn(mac_client_impl_t *mcip, uint32_t xid)
{
	dhcpv6_txn_t	tmp_txn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	tmp_txn.dt_xid = xid;
	return (avl_find(&mcip->mci_v6_pending_txn, &tmp_txn, NULL));
}

static void
remove_dhcpv6_pending_txn(mac_client_impl_t *mcip, dhcpv6_txn_t *txn)
{
	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	avl_remove(&mcip->mci_v6_pending_txn, txn);
}

static dhcpv6_txn_t *
create_dhcpv6_txn(uint32_t xid, dhcpv6_cid_t *cid)
{
	dhcpv6_txn_t	*txn;

	if ((txn = kmem_zalloc(sizeof (dhcpv6_txn_t), KM_NOSLEEP)) == NULL)
		return (NULL);

	txn->dt_xid = xid;
	txn->dt_cid = cid;
	txn->dt_timestamp = gethrtime();
	return (txn);
}

static void
free_dhcpv6_txn(dhcpv6_txn_t *txn)
{
	if (txn->dt_cid != NULL)
		free_dhcpv6_cid(txn->dt_cid);
	kmem_free(txn, sizeof (dhcpv6_txn_t));
}

static int
insert_dhcpv6_pending_txn(mac_client_impl_t *mcip, dhcpv6_txn_t *txn)
{
	avl_index_t	where;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (avl_find(&mcip->mci_v6_pending_txn, txn, &where) != NULL)
		return (EEXIST);

	if (avl_numnodes(&mcip->mci_v6_pending_txn) >= dhcp_max_pending_txn) {
		BUMP_STAT(mcip, dhcpdropped);
		return (EAGAIN);
	}
	avl_insert(&mcip->mci_v6_pending_txn, txn, where);
	return (0);
}

/*
 * Clean up all v6 tables.
 */
static void
flush_dhcpv6(mac_client_impl_t *mcip)
{
	void		*cookie = NULL;
	dhcpv6_cid_t	*cid;
	dhcpv6_txn_t	*txn;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	while (avl_destroy_nodes(&mcip->mci_v6_dyn_ip, &cookie) != NULL) {
	}
	cookie = NULL;
	while ((cid = avl_destroy_nodes(&mcip->mci_v6_cid, &cookie)) != NULL) {
		free_dhcpv6_cid(cid);
	}
	cookie = NULL;
	while ((txn = avl_destroy_nodes(&mcip->mci_v6_pending_txn,
	    &cookie)) != NULL) {
		free_dhcpv6_txn(txn);
	}
}

/*
 * Cleanup stale DHCPv6 transactions.
 */
static void
txn_cleanup_v6(mac_client_impl_t *mcip)
{
	dhcpv6_txn_t		*txn, *next, *txn_list = NULL;

	/*
	 * Find stale pending transactions and place them on a list
	 * to be removed.
	 */
	for (txn = avl_first(&mcip->mci_v6_pending_txn); txn != NULL;
	    txn = avl_walk(&mcip->mci_v6_pending_txn, txn, AVL_AFTER)) {
		if (gethrtime() - txn->dt_timestamp > txn_cleanup_interval) {
			DTRACE_PROBE2(found__expired__txn,
			    mac_client_impl_t *, mcip,
			    dhcpv6_txn_t *, txn);

			txn->dt_next = txn_list;
			txn_list = txn;
		}
	}

	/*
	 * Remove and free stale pending transactions.
	 * Release any existing cids matching the stale transactions.
	 */
	for (txn = txn_list; txn != NULL; txn = next) {
		avl_remove(&mcip->mci_v6_pending_txn, txn);
		release_dhcpv6_cid(mcip, txn->dt_cid);
		next = txn->dt_next;
		txn->dt_next = NULL;

		DTRACE_PROBE2(freeing__txn, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		free_dhcpv6_txn(txn);
	}

}

/*
 * Core logic for intercepting outbound DHCPv6 packets.
 */
static boolean_t
intercept_dhcpv6_outbound(mac_client_impl_t *mcip, ip6_t *ip6h, uchar_t *end)
{
	dhcpv6_message_t	*dh6;
	dhcpv6_txn_t		*txn;
	dhcpv6_cid_t		*cid = NULL;
	uint32_t		xid;
	uint8_t			mtype;
	mac_resource_props_t *mrp = MCIP_RESOURCE_PROPS(mcip);

	if (get_dhcpv6_info(ip6h, end, &dh6) != 0)
		return (B_TRUE);

	/* ip_nospoof/allowed-ips and DHCP are mutually exclusive by default */
	if (allowed_ips_set(mrp, IPV6_VERSION))
		return (B_FALSE);

	mtype = dh6->d6m_msg_type;
	if (mtype != DHCPV6_MSG_REQUEST && mtype != DHCPV6_MSG_RENEW &&
	    mtype != DHCPV6_MSG_REBIND && mtype != DHCPV6_MSG_RELEASE)
		return (B_TRUE);

	if ((cid = create_dhcpv6_cid(dh6, end)) == NULL)
		return (B_TRUE);

	mutex_enter(&mcip->mci_protect_lock);
	if (mtype == DHCPV6_MSG_RELEASE) {
		release_dhcpv6_cid(mcip, cid);
		goto done;
	}
	xid = DHCPV6_GET_TRANSID(dh6);
	if ((txn = find_dhcpv6_pending_txn(mcip, xid)) != NULL) {
		DTRACE_PROBE2(update, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		txn->dt_timestamp = gethrtime();
		goto done;
	}
	if ((txn = create_dhcpv6_txn(xid, cid)) == NULL)
		goto done;

	cid = NULL;
	if (insert_dhcpv6_pending_txn(mcip, txn) != 0) {
		DTRACE_PROBE2(insert__failed, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		free_dhcpv6_txn(txn);
		goto done;
	}
	start_txn_cleanup_timer(mcip);

	DTRACE_PROBE2(txn__pending, mac_client_impl_t *, mcip,
	    dhcpv6_txn_t *, txn);

done:
	if (cid != NULL)
		free_dhcpv6_cid(cid);

	mutex_exit(&mcip->mci_protect_lock);
	return (B_TRUE);
}

/*
 * Core logic for intercepting inbound DHCPv6 packets.
 */
static void
intercept_dhcpv6_inbound(mac_client_impl_t *mcip, ip6_t *ip6h, uchar_t *end)
{
	dhcpv6_message_t	*dh6;
	dhcpv6_txn_t		*txn;
	uint32_t		xid;
	uint8_t			mtype;
	uint16_t		status;

	if (get_dhcpv6_info(ip6h, end, &dh6) != 0)
		return;

	mtype = dh6->d6m_msg_type;
	if (mtype != DHCPV6_MSG_REPLY)
		return;

	mutex_enter(&mcip->mci_protect_lock);
	xid = DHCPV6_GET_TRANSID(dh6);
	if ((txn = find_dhcpv6_pending_txn(mcip, xid)) == NULL) {
		DTRACE_PROBE2(txn__not__found, mac_client_impl_t *, mcip,
		    dhcpv6_message_t *, dh6);
		goto done;
	}
	remove_dhcpv6_pending_txn(mcip, txn);
	release_dhcpv6_cid(mcip, txn->dt_cid);

	if (get_dhcpv6_status(dh6, end, &status) != 0 ||
	    status != DHCPV6_STAT_SUCCESS) {
		DTRACE_PROBE2(error__status, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		goto done;
	}
	if (get_dhcpv6_addrs(dh6, end, txn->dt_cid) != 0) {
		DTRACE_PROBE2(no__addrs, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		goto done;
	}
	if (insert_dhcpv6_cid(mcip, txn->dt_cid) != 0) {
		DTRACE_PROBE2(insert__failed, mac_client_impl_t *, mcip,
		    dhcpv6_txn_t *, txn);
		goto done;
	}
	DTRACE_PROBE2(txn__completed, mac_client_impl_t *, mcip,
	    dhcpv6_txn_t *, txn);

	txn->dt_cid = NULL;

done:
	if (txn != NULL)
		free_dhcpv6_txn(txn);
	mutex_exit(&mcip->mci_protect_lock);
}

/*
 * Timer for cleaning up stale transactions.
 */
static void
txn_cleanup_timer(void *arg)
{
	mac_client_impl_t	*mcip = arg;

	mutex_enter(&mcip->mci_protect_lock);
	if (mcip->mci_txn_cleanup_tid == 0) {
		/* do nothing if timer got cancelled */
		mutex_exit(&mcip->mci_protect_lock);
		return;
	}
	mcip->mci_txn_cleanup_tid = 0;

	txn_cleanup_v4(mcip);
	txn_cleanup_v6(mcip);

	/*
	 * Restart timer if pending transactions still exist.
	 */
	if (!avl_is_empty(&mcip->mci_v4_pending_txn) ||
	    !avl_is_empty(&mcip->mci_v6_pending_txn)) {
		DTRACE_PROBE1(restarting__timer, mac_client_impl_t *, mcip);

		mcip->mci_txn_cleanup_tid = timeout(txn_cleanup_timer, mcip,
		    drv_usectohz(txn_cleanup_interval / (NANOSEC / MICROSEC)));
	}
	mutex_exit(&mcip->mci_protect_lock);
}

static void
start_txn_cleanup_timer(mac_client_impl_t *mcip)
{
	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));
	if (mcip->mci_txn_cleanup_tid == 0) {
		mcip->mci_txn_cleanup_tid = timeout(txn_cleanup_timer, mcip,
		    drv_usectohz(txn_cleanup_interval / (NANOSEC / MICROSEC)));
	}
}

static void
cancel_txn_cleanup_timer(mac_client_impl_t *mcip)
{
	timeout_id_t	tid;

	ASSERT(MUTEX_HELD(&mcip->mci_protect_lock));

	/*
	 * This needs to be a while loop because the timer could get
	 * rearmed during untimeout().
	 */
	while ((tid = mcip->mci_txn_cleanup_tid) != 0) {
		mcip->mci_txn_cleanup_tid = 0;
		mutex_exit(&mcip->mci_protect_lock);
		(void) untimeout(tid);
		mutex_enter(&mcip->mci_protect_lock);
	}
}

/*
 * Get the start/end pointers of an L3 packet and also do pullup if needed.
 * pulled-up packet needs to be freed by the caller.
 */
static int
get_l3_info(mblk_t *mp, size_t hdrsize, uchar_t **start, uchar_t **end,
    mblk_t **nmp)
{
	uchar_t	*s, *e;
	mblk_t	*newmp = NULL;

	/*
	 * Pullup if necessary but reject packets that do not have
	 * a proper mac header.
	 */
	s = mp->b_rptr + hdrsize;
	e = mp->b_wptr;

	if (s > mp->b_wptr)
		return (EINVAL);

	if (!OK_32PTR(s) || mp->b_cont != NULL) {
		/*
		 * Temporarily adjust mp->b_rptr to ensure proper
		 * alignment of IP header in newmp.
		 */
		DTRACE_PROBE1(pullup__needed, mblk_t *, mp);

		mp->b_rptr += hdrsize;
		newmp = msgpullup(mp, -1);
		mp->b_rptr -= hdrsize;

		if (newmp == NULL)
			return (ENOMEM);

		s = newmp->b_rptr;
		e = newmp->b_wptr;
	}

	*start = s;
	*end = e;
	*nmp = newmp;
	return (0);
}

void
mac_protect_intercept_dhcp_one(mac_client_impl_t *mcip, mblk_t *mp)
{
	mac_impl_t		*mip = mcip->mci_mip;
	uchar_t			*start, *end;
	mblk_t			*nmp = NULL;
	mac_header_info_t	mhi;
	int			err;

	err = mac_vlan_header_info((mac_handle_t)mip, mp, &mhi);
	if (err != 0) {
		DTRACE_PROBE2(invalid__header, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return;
	}

	err = get_l3_info(mp, mhi.mhi_hdrsize, &start, &end, &nmp);
	if (err != 0) {
		DTRACE_PROBE2(invalid__l3, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return;
	}

	switch (mhi.mhi_bindsap) {
	case ETHERTYPE_IP: {
		ipha_t	*ipha = (ipha_t *)start;

		if (start + sizeof (ipha_t) > end)
			return;

		intercept_dhcpv4_inbound(mcip, ipha, end);
		break;
	}
	case ETHERTYPE_IPV6: {
		ip6_t		*ip6h = (ip6_t *)start;

		if (start + sizeof (ip6_t) > end)
			return;

		intercept_dhcpv6_inbound(mcip, ip6h, end);
		break;
	}
	}
	freemsg(nmp);
}

void
mac_protect_intercept_dhcp(mac_client_impl_t *mcip, mblk_t *mp)
{
	/*
	 * Skip checks if we are part of an aggr.
	 */
	if ((mcip->mci_state_flags & MCIS_IS_AGGR_PORT) != 0)
		return;

	for (; mp != NULL; mp = mp->b_next)
		mac_protect_intercept_dhcp_one(mcip, mp);
}

void
mac_protect_flush_dhcp(mac_client_impl_t *mcip)
{
	mutex_enter(&mcip->mci_protect_lock);
	flush_dhcpv4(mcip);
	flush_dhcpv6(mcip);
	mutex_exit(&mcip->mci_protect_lock);
}

void
mac_protect_cancel_timer(mac_client_impl_t *mcip)
{
	mutex_enter(&mcip->mci_protect_lock);
	cancel_txn_cleanup_timer(mcip);
	mutex_exit(&mcip->mci_protect_lock);
}

/*
 * Check if addr is in the 'allowed-ips' list.
 */

/* ARGSUSED */
static boolean_t
ipnospoof_check_v4(mac_client_impl_t *mcip, mac_protect_t *protect,
    ipaddr_t *addr)
{
	uint_t	i;

	/*
	 * The unspecified address is allowed.
	 */
	if (*addr == INADDR_ANY)
		return (B_TRUE);

	for (i = 0; i < protect->mp_ipaddrcnt; i++) {
		mac_ipaddr_t	*v4addr = &protect->mp_ipaddrs[i];

		if (v4addr->ip_version == IPV4_VERSION) {
			uint32_t mask;

			/* LINTED E_SUSPICIOUS_COMPARISON */
			ASSERT(v4addr->ip_netmask >= 0 &&
			    v4addr->ip_netmask <= 32);
			mask = 0xFFFFFFFFu << (32 - v4addr->ip_netmask);
			/*
			 * Since we have a netmask we know this entry
			 * signifies the entire subnet. Check if the
			 * given address is on the subnet.
			 */
			if (htonl(V4_PART_OF_V6(v4addr->ip_addr)) ==
			    (htonl(*addr) & mask))
				return (B_TRUE);
		}
	}
	return (protect->mp_ipaddrcnt == 0 ?
	    check_dhcpv4_dyn_ip(mcip, *addr) : B_FALSE);
}

static boolean_t
ipnospoof_check_v6(mac_client_impl_t *mcip, mac_protect_t *protect,
    in6_addr_t *addr)
{
	uint_t	i;

	/*
	 * The unspecified address and the v6 link local address are allowed.
	 */
	if (IN6_IS_ADDR_UNSPECIFIED(addr) ||
	    ((mcip->mci_protect_flags & MPT_FLAG_V6_LOCAL_ADDR_SET) != 0 &&
	    IN6_ARE_ADDR_EQUAL(&mcip->mci_v6_local_addr, addr)))
		return (B_TRUE);


	for (i = 0; i < protect->mp_ipaddrcnt; i++) {
		mac_ipaddr_t	*v6addr = &protect->mp_ipaddrs[i];

		if (v6addr->ip_version == IPV6_VERSION &&
		    /* LINTED E_SUSPICIOUS_COMPARISON */
		    IN6_ARE_PREFIXEDADDR_EQUAL(&v6addr->ip_addr, addr,
		    v6addr->ip_netmask))
			return (B_TRUE);
	}
	return (protect->mp_ipaddrcnt == 0 ?
	    check_dhcpv6_dyn_ip(mcip, addr) : B_FALSE);
}

/*
 * Checks various fields within an IPv6 NDP packet.
 */
static boolean_t
ipnospoof_check_ndp(mac_client_impl_t *mcip, mac_protect_t *protect,
    ip6_t *ip6h, uchar_t *end)
{
	icmp6_t			*icmp_nd = (icmp6_t *)&ip6h[1];
	int			hdrlen, optlen, opttype, len;
	uint_t			addrlen, maclen;
	uint8_t			type;
	nd_opt_hdr_t		*opt;
	struct nd_opt_lla	*lla = NULL;

	/*
	 * NDP packets do not have extension headers so the ICMPv6 header
	 * must immediately follow the IPv6 header.
	 */
	if (ip6h->ip6_nxt != IPPROTO_ICMPV6)
		return (B_TRUE);

	/* ICMPv6 header missing */
	if ((uchar_t *)&icmp_nd[1] > end)
		return (B_FALSE);

	len = end - (uchar_t *)icmp_nd;
	type = icmp_nd->icmp6_type;

	switch (type) {
	case ND_ROUTER_SOLICIT:
		hdrlen = sizeof (nd_router_solicit_t);
		break;
	case ND_ROUTER_ADVERT:
		hdrlen = sizeof (nd_router_advert_t);
		break;
	case ND_NEIGHBOR_SOLICIT:
		hdrlen = sizeof (nd_neighbor_solicit_t);
		break;
	case ND_NEIGHBOR_ADVERT:
		hdrlen = sizeof (nd_neighbor_advert_t);
		break;
	case ND_REDIRECT:
		hdrlen = sizeof (nd_redirect_t);
		break;
	default:
		return (B_TRUE);
	}

	if (len < hdrlen)
		return (B_FALSE);

	/* SLLA option checking is needed for RS/RA/NS */
	opttype = ND_OPT_SOURCE_LINKADDR;

	switch (type) {
	case ND_NEIGHBOR_ADVERT: {
		nd_neighbor_advert_t	*na = (nd_neighbor_advert_t *)icmp_nd;

		if (!ipnospoof_check_v6(mcip, protect, &na->nd_na_target)) {
			DTRACE_PROBE2(ndp__na__fail,
			    mac_client_impl_t *, mcip, ip6_t *, ip6h);
			return (B_FALSE);
		}

		/* TLLA option for NA */
		opttype = ND_OPT_TARGET_LINKADDR;
		break;
	}
	case ND_REDIRECT: {
		/* option checking not needed for RD */
		return (B_TRUE);
	}
	default:
		break;
	}

	if (len == hdrlen) {
		/* no options, we're done */
		return (B_TRUE);
	}
	opt = (nd_opt_hdr_t *)((uchar_t *)icmp_nd + hdrlen);
	optlen = len - hdrlen;

	/* find the option header we need */
	while (optlen > sizeof (nd_opt_hdr_t)) {
		if (opt->nd_opt_type == opttype) {
			lla = (struct nd_opt_lla *)opt;
			break;
		}
		optlen -= 8 * opt->nd_opt_len;
		opt = (nd_opt_hdr_t *)
		    ((uchar_t *)opt + 8 * opt->nd_opt_len);
	}
	if (lla == NULL)
		return (B_TRUE);

	addrlen = lla->nd_opt_lla_len * 8 - sizeof (nd_opt_hdr_t);
	maclen = mcip->mci_mip->mi_info.mi_addr_length;

	if (addrlen != maclen ||
	    bcmp(mcip->mci_unicast->ma_addr,
	    lla->nd_opt_lla_hdw_addr, maclen) != 0) {
		DTRACE_PROBE2(ndp__lla__fail,
		    mac_client_impl_t *, mcip, ip6_t *, ip6h);
		return (B_FALSE);
	}

	DTRACE_PROBE2(ndp__lla__ok, mac_client_impl_t *, mcip, ip6_t *, ip6h);
	return (B_TRUE);
}

/*
 * Enforce ip-nospoof protection.
 */
static int
ipnospoof_check(mac_client_impl_t *mcip, mac_protect_t *protect,
    mblk_t *mp, mac_header_info_t *mhip)
{
	size_t		hdrsize = mhip->mhi_hdrsize;
	uint32_t	sap = mhip->mhi_bindsap;
	uchar_t		*start, *end;
	mblk_t		*nmp = NULL;
	int		err;

	err = get_l3_info(mp, hdrsize, &start, &end, &nmp);
	if (err != 0) {
		DTRACE_PROBE2(invalid__l3, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return (err);
	}
	err = EINVAL;

	switch (sap) {
	case ETHERTYPE_IP: {
		ipha_t	*ipha = (ipha_t *)start;

		if (start + sizeof (ipha_t) > end)
			goto fail;

		if (!ipnospoof_check_v4(mcip, protect, &ipha->ipha_src))
			goto fail;

		if (!intercept_dhcpv4_outbound(mcip, ipha, end))
			goto fail;
		break;
	}
	case ETHERTYPE_ARP: {
		arh_t		*arh = (arh_t *)start;
		uint32_t	maclen, hlen, plen, arplen;
		ipaddr_t	spaddr;
		uchar_t		*shaddr;

		if (start + sizeof (arh_t) > end)
			goto fail;

		maclen = mcip->mci_mip->mi_info.mi_addr_length;
		hlen = arh->arh_hlen;
		plen = arh->arh_plen;
		if ((hlen != 0 && hlen != maclen) ||
		    plen != sizeof (ipaddr_t))
			goto fail;

		arplen = sizeof (arh_t) + 2 * hlen + 2 * plen;
		if (start + arplen > end)
			goto fail;

		shaddr = start + sizeof (arh_t);
		if (hlen != 0 &&
		    bcmp(mcip->mci_unicast->ma_addr, shaddr, maclen) != 0)
			goto fail;

		bcopy(shaddr + hlen, &spaddr, sizeof (spaddr));
		if (!ipnospoof_check_v4(mcip, protect, &spaddr))
			goto fail;
		break;
	}
	case ETHERTYPE_IPV6: {
		ip6_t		*ip6h = (ip6_t *)start;

		if (start + sizeof (ip6_t) > end)
			goto fail;

		if (!ipnospoof_check_v6(mcip, protect, &ip6h->ip6_src))
			goto fail;

		if (!ipnospoof_check_ndp(mcip, protect, ip6h, end))
			goto fail;

		if (!intercept_dhcpv6_outbound(mcip, ip6h, end))
			goto fail;
		break;
	}
	}
	freemsg(nmp);
	return (0);

fail:
	freemsg(nmp);
	return (err);
}

static boolean_t
dhcpnospoof_check_cid(mac_protect_t *p, uchar_t *cid, uint_t cidlen)
{
	int	i;

	for (i = 0; i < p->mp_cidcnt; i++) {
		mac_dhcpcid_t	*dcid = &p->mp_cids[i];

		if (dcid->dc_len == cidlen &&
		    bcmp(dcid->dc_id, cid, cidlen) == 0)
			return (B_TRUE);
	}
	return (B_FALSE);
}

static boolean_t
dhcpnospoof_check_v4(mac_client_impl_t *mcip, mac_protect_t *p,
    ipha_t *ipha, uchar_t *end)
{
	struct dhcp	*dh4;
	uchar_t		*cid;
	uint_t		maclen, cidlen = 0;
	uint8_t		optlen;
	int		err;

	if ((err = get_dhcpv4_info(ipha, end, &dh4)) != 0)
		return (err == EINVAL);

	maclen = mcip->mci_mip->mi_info.mi_addr_length;
	if (dh4->hlen == maclen &&
	    bcmp(mcip->mci_unicast->ma_addr, dh4->chaddr, maclen) != 0) {
		return (B_FALSE);
	}
	if (get_dhcpv4_option(dh4, end, CD_CLIENT_ID, &cid, &optlen) == 0)
		cidlen = optlen;

	if (cidlen == 0)
		return (B_TRUE);

	if (*cid == ARPHRD_ETHER && cidlen - 1 == maclen &&
	    bcmp(mcip->mci_unicast->ma_addr, cid + 1, maclen) == 0)
		return (B_TRUE);

	return (dhcpnospoof_check_cid(p, cid, cidlen));
}

static boolean_t
dhcpnospoof_check_v6(mac_client_impl_t *mcip, mac_protect_t *p,
    ip6_t *ip6h, uchar_t *end)
{
	dhcpv6_message_t	*dh6;
	dhcpv6_option_t		*d6o;
	uint8_t			mtype;
	uchar_t			*cid, *lladdr = NULL;
	uint_t			cidlen, maclen, addrlen = 0;
	uint16_t		cidtype;
	int			err;

	if ((err = get_dhcpv6_info(ip6h, end, &dh6)) != 0)
		return (err == EINVAL);

	/*
	 * We only check client-generated messages.
	 */
	mtype = dh6->d6m_msg_type;
	if (mtype == DHCPV6_MSG_ADVERTISE || mtype == DHCPV6_MSG_REPLY ||
	    mtype == DHCPV6_MSG_RECONFIGURE)
		return (B_TRUE);

	d6o = get_dhcpv6_option(&dh6[1], end - (uchar_t *)&dh6[1], NULL,
	    DHCPV6_OPT_CLIENTID, &cidlen);
	if (d6o == NULL || (uchar_t *)d6o + cidlen > end)
		return (B_TRUE);

	cid = (uchar_t *)&d6o[1];
	cidlen -= sizeof (*d6o);
	if (cidlen < sizeof (cidtype))
		return (B_TRUE);

	bcopy(cid, &cidtype, sizeof (cidtype));
	cidtype = ntohs(cidtype);
	if (cidtype == DHCPV6_DUID_LLT && cidlen >= sizeof (duid_llt_t)) {
		lladdr = cid + sizeof (duid_llt_t);
		addrlen = cidlen - sizeof (duid_llt_t);
	}
	if (cidtype == DHCPV6_DUID_LL && cidlen >= sizeof (duid_ll_t)) {
		lladdr = cid + sizeof (duid_ll_t);
		addrlen = cidlen - sizeof (duid_ll_t);
	}
	maclen = mcip->mci_mip->mi_info.mi_addr_length;
	if (lladdr != NULL && addrlen == maclen &&
	    bcmp(mcip->mci_unicast->ma_addr, lladdr, maclen) == 0) {
		return (B_TRUE);
	}
	return (dhcpnospoof_check_cid(p, cid, cidlen));
}

/*
 * Enforce dhcp-nospoof protection.
 */
static int
dhcpnospoof_check(mac_client_impl_t *mcip, mac_protect_t *protect,
    mblk_t *mp, mac_header_info_t *mhip)
{
	size_t		hdrsize = mhip->mhi_hdrsize;
	uint32_t	sap = mhip->mhi_bindsap;
	uchar_t		*start, *end;
	mblk_t		*nmp = NULL;
	int		err;

	err = get_l3_info(mp, hdrsize, &start, &end, &nmp);
	if (err != 0) {
		DTRACE_PROBE2(invalid__l3, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return (err);
	}
	err = EINVAL;

	switch (sap) {
	case ETHERTYPE_IP: {
		ipha_t	*ipha = (ipha_t *)start;

		if (start + sizeof (ipha_t) > end)
			goto fail;

		if (!dhcpnospoof_check_v4(mcip, protect, ipha, end))
			goto fail;

		break;
	}
	case ETHERTYPE_IPV6: {
		ip6_t		*ip6h = (ip6_t *)start;

		if (start + sizeof (ip6_t) > end)
			goto fail;

		if (!dhcpnospoof_check_v6(mcip, protect, ip6h, end))
			goto fail;

		break;
	}
	}
	freemsg(nmp);
	return (0);

fail:
	/* increment dhcpnospoof stat here */
	freemsg(nmp);
	return (err);
}

/*
 * This needs to be called whenever the mac client's mac address changes.
 */
void
mac_protect_update_v6_local_addr(mac_client_impl_t *mcip)
{
	uint8_t		*p, *macaddr = mcip->mci_unicast->ma_addr;
	uint_t		i, media = mcip->mci_mip->mi_info.mi_media;
	in6_addr_t	token, *v6addr = &mcip->mci_v6_local_addr;
	in6_addr_t	ll_template = {(uint32_t)V6_LINKLOCAL, 0x0, 0x0, 0x0};


	bzero(&token, sizeof (token));
	p = (uint8_t *)&token.s6_addr32[2];

	switch (media) {
	case DL_ETHER:
		bcopy(macaddr, p, 3);
		p[0] ^= 0x2;
		p[3] = 0xff;
		p[4] = 0xfe;
		bcopy(macaddr + 3, p + 5, 3);
		break;
	case DL_IB:
		ASSERT(mcip->mci_mip->mi_info.mi_addr_length == 20);
		bcopy(macaddr + 12, p, 8);
		p[0] |= 2;
		break;
	default:
		/*
		 * We do not need to generate the local address for link types
		 * that do not support link protection. Wifi pretends to be
		 * ethernet so it is covered by the DL_ETHER case (note the
		 * use of mi_media instead of mi_nativemedia).
		 */
		return;
	}

	for (i = 0; i < 4; i++) {
		v6addr->s6_addr32[i] = token.s6_addr32[i] |
		    ll_template.s6_addr32[i];
	}
	mcip->mci_protect_flags |= MPT_FLAG_V6_LOCAL_ADDR_SET;
}

/*
 * Enforce link protection on one packet.
 */
static int
mac_protect_check_one(mac_client_impl_t *mcip, mblk_t *mp)
{
	mac_impl_t		*mip = mcip->mci_mip;
	mac_resource_props_t	*mrp = MCIP_RESOURCE_PROPS(mcip);
	mac_protect_t		*protect;
	mac_header_info_t	mhi;
	uint32_t		types;
	int			err;

	ASSERT(mp->b_next == NULL);
	ASSERT(mrp != NULL);

	err = mac_vlan_header_info((mac_handle_t)mip, mp, &mhi);
	if (err != 0) {
		DTRACE_PROBE2(invalid__header, mac_client_impl_t *, mcip,
		    mblk_t *, mp);
		return (err);
	}
	protect = &mrp->mrp_protect;
	types = protect->mp_types;

	if ((types & MPT_MACNOSPOOF) != 0) {
		if (mhi.mhi_saddr != NULL &&
		    bcmp(mcip->mci_unicast->ma_addr, mhi.mhi_saddr,
		    mip->mi_info.mi_addr_length) != 0) {
			BUMP_STAT(mcip, macspoofed);
			DTRACE_PROBE2(mac__nospoof__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}
	}
	if ((types & MPT_RESTRICTED) != 0) {
		uint32_t	vid = VLAN_ID(mhi.mhi_tci);
		uint32_t	sap = mhi.mhi_bindsap;

		/*
		 * ETHERTYPE_VLAN packets are allowed through, provided that
		 * the vid is not spoofed.
		 */
		if (vid != 0 && !mac_client_check_flow_vid(mcip, vid)) {
			BUMP_STAT(mcip, restricted);
			DTRACE_PROBE2(restricted__vid__invalid,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}

		if (sap != ETHERTYPE_IP && sap != ETHERTYPE_IPV6 &&
		    sap != ETHERTYPE_ARP) {
			BUMP_STAT(mcip, restricted);
			DTRACE_PROBE2(restricted__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (EINVAL);
		}
	}
	if ((types & MPT_IPNOSPOOF) != 0) {
		if ((err = ipnospoof_check(mcip, protect, mp, &mhi)) != 0) {
			BUMP_STAT(mcip, ipspoofed);
			DTRACE_PROBE2(ip__nospoof__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (err);
		}
	}
	if ((types & MPT_DHCPNOSPOOF) != 0) {
		if ((err = dhcpnospoof_check(mcip, protect, mp, &mhi)) != 0) {
			BUMP_STAT(mcip, dhcpspoofed);
			DTRACE_PROBE2(dhcp__nospoof__fail,
			    mac_client_impl_t *, mcip, mblk_t *, mp);
			return (err);
		}
	}
	return (0);
}

/*
 * Enforce link protection on a packet chain.
 * Packets that pass the checks are returned back to the caller.
 */
mblk_t *
mac_protect_check(mac_client_handle_t mch, mblk_t *mp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mblk_t			*ret_mp = NULL, **tailp = &ret_mp, *next;

	/*
	 * Skip checks if we are part of an aggr.
	 */
	if ((mcip->mci_state_flags & MCIS_IS_AGGR_PORT) != 0)
		return (mp);

	for (; mp != NULL; mp = next) {
		next = mp->b_next;
		mp->b_next = NULL;

		if (mac_protect_check_one(mcip, mp) == 0) {
			*tailp = mp;
			tailp = &mp->b_next;
		} else {
			freemsg(mp);
		}
	}
	return (ret_mp);
}

/*
 * Check if a particular protection type is enabled.
 */
boolean_t
mac_protect_enabled(mac_client_handle_t mch, uint32_t type)
{
	return (MAC_PROTECT_ENABLED((mac_client_impl_t *)mch, type));
}

static int
validate_ips(mac_protect_t *p)
{
	uint_t		i, j;

	if (p->mp_ipaddrcnt == MPT_RESET)
		return (0);

	if (p->mp_ipaddrcnt > MPT_MAXIPADDR)
		return (EINVAL);

	for (i = 0; i < p->mp_ipaddrcnt; i++) {
		mac_ipaddr_t	*addr = &p->mp_ipaddrs[i];

		/*
		 * The unspecified address is implicitly allowed so there's no
		 * need to add it to the list. Also, validate that the netmask,
		 * if any, is sane for the specific version of IP. A mask of
		 * some kind is always required.
		 */
		if (addr->ip_netmask == 0)
			return (EINVAL);

		if (addr->ip_version == IPV4_VERSION) {
			if (V4_PART_OF_V6(addr->ip_addr) == INADDR_ANY)
				return (EINVAL);
			if (addr->ip_netmask > 32)
				return (EINVAL);
		} else if (addr->ip_version == IPV6_VERSION) {
			if (IN6_IS_ADDR_UNSPECIFIED(&addr->ip_addr))
				return (EINVAL);

			if (IN6_IS_ADDR_V4MAPPED_ANY(&addr->ip_addr))
				return (EINVAL);

			if (addr->ip_netmask > 128)
				return (EINVAL);
		} else {
			/* invalid ip version */
			return (EINVAL);
		}

		for (j = 0; j < p->mp_ipaddrcnt; j++) {
			mac_ipaddr_t	*addr1 = &p->mp_ipaddrs[j];

			if (i == j || addr->ip_version != addr1->ip_version)
				continue;

			/* found a duplicate */
			if ((addr->ip_version == IPV4_VERSION &&
			    V4_PART_OF_V6(addr->ip_addr) ==
			    V4_PART_OF_V6(addr1->ip_addr)) ||
			    IN6_ARE_ADDR_EQUAL(&addr->ip_addr,
			    &addr1->ip_addr))
				return (EINVAL);
		}
	}
	return (0);
}

/* ARGSUSED */
static int
validate_cids(mac_protect_t *p)
{
	uint_t		i, j;

	if (p->mp_cidcnt == MPT_RESET)
		return (0);

	if (p->mp_cidcnt > MPT_MAXCID)
		return (EINVAL);

	for (i = 0; i < p->mp_cidcnt; i++) {
		mac_dhcpcid_t	*cid = &p->mp_cids[i];

		if (cid->dc_len > MPT_MAXCIDLEN ||
		    (cid->dc_form != CIDFORM_TYPED &&
		    cid->dc_form != CIDFORM_HEX &&
		    cid->dc_form != CIDFORM_STR))
			return (EINVAL);

		for (j = 0; j < p->mp_cidcnt; j++) {
			mac_dhcpcid_t	*cid1 = &p->mp_cids[j];

			if (i == j || cid->dc_len != cid1->dc_len)
				continue;

			/* found a duplicate */
			if (bcmp(cid->dc_id, cid1->dc_id, cid->dc_len) == 0)
				return (EINVAL);
		}
	}
	return (0);
}

/*
 * Sanity-checks parameters given by userland.
 */
int
mac_protect_validate(mac_resource_props_t *mrp)
{
	mac_protect_t	*p = &mrp->mrp_protect;
	int		err;

	/* check for invalid types */
	if (p->mp_types != MPT_RESET && (p->mp_types & ~MPT_ALL) != 0)
		return (EINVAL);

	if ((err = validate_ips(p)) != 0)
		return (err);

	if ((err = validate_cids(p)) != 0)
		return (err);

	return (0);
}

/*
 * Enable/disable link protection.
 */
int
mac_protect_set(mac_client_handle_t mch, mac_resource_props_t *mrp)
{
	mac_client_impl_t	*mcip = (mac_client_impl_t *)mch;
	mac_impl_t		*mip = mcip->mci_mip;
	uint_t			media = mip->mi_info.mi_nativemedia;
	int			err;

	ASSERT(MAC_PERIM_HELD((mac_handle_t)mip));

	/* tunnels are not supported */
	if (media == DL_IPV4 || media == DL_IPV6 || media == DL_6TO4)
		return (ENOTSUP);

	if ((err = mac_protect_validate(mrp)) != 0)
		return (err);

	if (err != 0)
		return (err);

	mac_update_resources(mrp, MCIP_RESOURCE_PROPS(mcip), B_FALSE);
	i_mac_notify(((mcip->mci_state_flags & MCIS_IS_VNIC) != 0 ?
	    mcip->mci_upper_mip : mip), MAC_NOTE_ALLOWED_IPS);
	return (0);
}

void
mac_protect_update(mac_resource_props_t *new, mac_resource_props_t *curr)
{
	mac_protect_t	*np = &new->mrp_protect;
	mac_protect_t	*cp = &curr->mrp_protect;
	uint32_t	types = np->mp_types;

	if (types == MPT_RESET) {
		cp->mp_types = 0;
		curr->mrp_mask &= ~MRP_PROTECT;
	} else {
		if (types != 0) {
			cp->mp_types = types;
			curr->mrp_mask |= MRP_PROTECT;
		}
	}
	if (np->mp_ipaddrcnt != 0) {
		if (np->mp_ipaddrcnt <= MPT_MAXIPADDR) {
			bcopy(np->mp_ipaddrs, cp->mp_ipaddrs,
			    sizeof (cp->mp_ipaddrs));
			cp->mp_ipaddrcnt = np->mp_ipaddrcnt;
		} else if (np->mp_ipaddrcnt == MPT_RESET) {
			bzero(cp->mp_ipaddrs, sizeof (cp->mp_ipaddrs));
			cp->mp_ipaddrcnt = 0;
		}
	}
	if (np->mp_cidcnt != 0) {
		if (np->mp_cidcnt <= MPT_MAXCID) {
			bcopy(np->mp_cids, cp->mp_cids, sizeof (cp->mp_cids));
			cp->mp_cidcnt = np->mp_cidcnt;
		} else if (np->mp_cidcnt == MPT_RESET) {
			bzero(cp->mp_cids, sizeof (cp->mp_cids));
			cp->mp_cidcnt = 0;
		}
	}
}

void
mac_protect_init(mac_client_impl_t *mcip)
{
	mutex_init(&mcip->mci_protect_lock, NULL, MUTEX_DRIVER, NULL);
	mcip->mci_protect_flags = 0;
	mcip->mci_txn_cleanup_tid = 0;
	avl_create(&mcip->mci_v4_pending_txn, compare_dhcpv4_xid,
	    sizeof (dhcpv4_txn_t), offsetof(dhcpv4_txn_t, dt_node));
	avl_create(&mcip->mci_v4_completed_txn, compare_dhcpv4_cid,
	    sizeof (dhcpv4_txn_t), offsetof(dhcpv4_txn_t, dt_node));
	avl_create(&mcip->mci_v4_dyn_ip, compare_dhcpv4_ip,
	    sizeof (dhcpv4_txn_t), offsetof(dhcpv4_txn_t, dt_ipnode));
	avl_create(&mcip->mci_v6_pending_txn, compare_dhcpv6_xid,
	    sizeof (dhcpv6_txn_t), offsetof(dhcpv6_txn_t, dt_node));
	avl_create(&mcip->mci_v6_cid, compare_dhcpv6_cid,
	    sizeof (dhcpv6_cid_t), offsetof(dhcpv6_cid_t, dc_node));
	avl_create(&mcip->mci_v6_dyn_ip, compare_dhcpv6_ip,
	    sizeof (dhcpv6_addr_t), offsetof(dhcpv6_addr_t, da_node));

	if (mcip->mci_state_flags & MCIS_IS_VNIC)
		mcip->mci_protect_flags |= MPT_FLAG_PROMISC_FILTERED;
}

void
mac_protect_fini(mac_client_impl_t *mcip)
{
	avl_destroy(&mcip->mci_v6_dyn_ip);
	avl_destroy(&mcip->mci_v6_cid);
	avl_destroy(&mcip->mci_v6_pending_txn);
	avl_destroy(&mcip->mci_v4_dyn_ip);
	avl_destroy(&mcip->mci_v4_completed_txn);
	avl_destroy(&mcip->mci_v4_pending_txn);
	mcip->mci_txn_cleanup_tid = 0;
	mcip->mci_protect_flags = 0;
	mutex_destroy(&mcip->mci_protect_lock);
}

static boolean_t
allowed_ips_set(mac_resource_props_t *mrp, uint32_t af)
{
	int i;

	for (i = 0; i < mrp->mrp_protect.mp_ipaddrcnt; i++) {
		if (mrp->mrp_protect.mp_ipaddrs[i].ip_version == af)
			return (B_TRUE);
	}
	return (B_FALSE);
}

mac_protect_t *
mac_protect_get(mac_handle_t mh)
{
	mac_impl_t *mip = (mac_impl_t *)mh;

	return (&mip->mi_resource_props.mrp_protect);
}
