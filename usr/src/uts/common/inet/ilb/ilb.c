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
 */

#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/disp.h>
#include <sys/taskq.h>
#include <sys/cmn_err.h>
#include <sys/strsun.h>
#include <sys/sdt.h>
#include <sys/atomic.h>
#include <netinet/in.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/tcp.h>
#include <inet/udp_impl.h>
#include <inet/kstatcom.h>

#include <inet/ilb_ip.h>
#include "ilb_alg.h"
#include "ilb_nat.h"
#include "ilb_conn.h"

/* ILB kmem cache flag */
int ilb_kmem_flags = 0;

/*
 * The default size for the different hash tables.  Global for all stacks.
 * But each stack has its own table, just that their sizes are the same.
 */
static size_t ilb_rule_hash_size = 2048;

static size_t ilb_conn_hash_size = 262144;

static size_t ilb_sticky_hash_size = 262144;

/* This should be a prime number. */
static size_t ilb_nat_src_hash_size = 97;

/* Default NAT cache entry expiry time. */
static uint32_t ilb_conn_tcp_expiry = 120;
static uint32_t ilb_conn_udp_expiry = 60;

/* Default sticky entry expiry time. */
static uint32_t ilb_sticky_expiry = 60;

/* addr is assumed to be a uint8_t * to an ipaddr_t. */
#define	ILB_RULE_HASH(addr, hash_size) \
	((*((addr) + 3) * 29791 + *((addr) + 2) * 961 + *((addr) + 1) * 31 + \
	*(addr)) & ((hash_size) - 1))

/*
 * Note on ILB delayed processing
 *
 * To avoid in line removal on some of the data structures, such as rules,
 * servers and ilb_conn_hash entries, ILB delays such processing to a taskq.
 * There are three types of ILB taskq:
 *
 * 1. rule handling: created at stack initialialization time, ilb_stack_init()
 * 2. conn hash handling: created at conn hash initialization time,
 *                        ilb_conn_hash_init()
 * 3. sticky hash handling: created at sticky hash initialization time,
 *                          ilb_sticky_hash_init()
 *
 * The rule taskq is for processing rule and server removal.  When a user
 * land rule/server removal request comes in, a taskq is dispatched after
 * removing the rule/server from all related hashes.  This taskq will wait
 * until all references to the rule/server are gone before removing it.
 * So the user land thread requesting the removal does not need to wait
 * for the removal completion.
 *
 * The conn hash/sticky hash taskq is for processing ilb_conn_hash and
 * ilb_sticky_hash table entry removal.  There are ilb_conn_timer_size timers
 * and ilb_sticky_timer_size timers running for ilb_conn_hash and
 * ilb_sticky_hash cleanup respectively.   Each timer is responsible for one
 * portion (same size) of the hash table.  When a timer fires, it dispatches
 * a conn hash taskq to clean up its portion of the table.  This avoids in
 * line processing of the removal.
 *
 * There is another delayed processing, the clean up of NAT source address
 * table.  We just use the timer to directly handle it instead of using
 * a taskq.  The reason is that the table is small so it is OK to use the
 * timer.
 */

/* ILB rule taskq constants. */
#define	ILB_RULE_TASKQ_NUM_THR	20

/* Argument passed to ILB rule taskq routines. */
typedef	struct {
	ilb_stack_t	*ilbs;
	ilb_rule_t	*rule;
} ilb_rule_tq_t;

/* kstat handling routines. */
static kstat_t *ilb_kstat_g_init(netstackid_t, ilb_stack_t *);
static void ilb_kstat_g_fini(netstackid_t, ilb_stack_t *);
static kstat_t *ilb_rule_kstat_init(netstackid_t, ilb_rule_t *);
static kstat_t *ilb_server_kstat_init(netstackid_t, ilb_rule_t *,
    ilb_server_t *);

/* Rule hash handling routines. */
static void ilb_rule_hash_init(ilb_stack_t *);
static void ilb_rule_hash_fini(ilb_stack_t *);
static void ilb_rule_hash_add(ilb_stack_t *, ilb_rule_t *, const in6_addr_t *);
static void ilb_rule_hash_del(ilb_rule_t *);
static ilb_rule_t *ilb_rule_hash(ilb_stack_t *, int, int, in6_addr_t *,
    in_port_t, zoneid_t, uint32_t, boolean_t *);

static void ilb_rule_g_add(ilb_stack_t *, ilb_rule_t *);
static void ilb_rule_g_del(ilb_stack_t *, ilb_rule_t *);
static void ilb_del_rule_common(ilb_stack_t *, ilb_rule_t *);
static ilb_rule_t *ilb_find_rule_locked(ilb_stack_t *, zoneid_t, const char *,
    int *);
static boolean_t ilb_match_rule(ilb_stack_t *, zoneid_t, const char *, int,
    int, in_port_t, in_port_t, const in6_addr_t *);

/* Back end server handling routines. */
static void ilb_server_free(ilb_server_t *);

/* Network stack handling routines. */
static void *ilb_stack_init(netstackid_t, netstack_t *);
static void ilb_stack_shutdown(netstackid_t, void *);
static void ilb_stack_fini(netstackid_t, void *);

/* Sticky connection handling routines. */
static void ilb_rule_sticky_init(ilb_rule_t *);
static void ilb_rule_sticky_fini(ilb_rule_t *);

/* Handy macro to check for unspecified address. */
#define	IS_ADDR_UNSPEC(addr)						\
	(IN6_IS_ADDR_V4MAPPED(addr) ? IN6_IS_ADDR_V4MAPPED_ANY(addr) :	\
	    IN6_IS_ADDR_UNSPECIFIED(addr))

/*
 * Global kstat instance counter.  When a rule is created, its kstat instance
 * number is assigned by ilb_kstat_instance and ilb_kstat_instance is
 * incremented.
 */
static uint_t ilb_kstat_instance = 0;

/*
 * The ILB global kstat has name ILB_G_KS_NAME and class name ILB_G_KS_CNAME.
 * A rule's kstat has ILB_RULE_KS_CNAME class name.
 */
#define	ILB_G_KS_NAME		"global"
#define	ILB_G_KS_CNAME		"kstat"
#define	ILB_RULE_KS_CNAME	"rulestat"

static kstat_t *
ilb_kstat_g_init(netstackid_t stackid, ilb_stack_t *ilbs)
{
	kstat_t *ksp;
	ilb_g_kstat_t template = {
		{ "num_rules",		KSTAT_DATA_UINT64, 0 },
		{ "ip_frag_in",		KSTAT_DATA_UINT64, 0 },
		{ "ip_frag_dropped",	KSTAT_DATA_UINT64, 0 }
	};

	ksp = kstat_create_netstack(ILB_KSTAT_MOD_NAME, 0, ILB_G_KS_NAME,
	    ILB_G_KS_CNAME, KSTAT_TYPE_NAMED, NUM_OF_FIELDS(ilb_g_kstat_t),
	    KSTAT_FLAG_VIRTUAL, stackid);
	if (ksp == NULL)
		return (NULL);
	bcopy(&template, ilbs->ilbs_kstat, sizeof (template));
	ksp->ks_data = ilbs->ilbs_kstat;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
ilb_kstat_g_fini(netstackid_t stackid, ilb_stack_t *ilbs)
{
	if (ilbs->ilbs_ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)
		    ilbs->ilbs_ksp->ks_private);
		kstat_delete_netstack(ilbs->ilbs_ksp, stackid);
		ilbs->ilbs_ksp = NULL;
	}
}

static kstat_t *
ilb_rule_kstat_init(netstackid_t stackid, ilb_rule_t *rule)
{
	kstat_t *ksp;
	ilb_rule_kstat_t template = {
		{ "num_servers",		KSTAT_DATA_UINT64, 0 },
		{ "bytes_not_processed",	KSTAT_DATA_UINT64, 0 },
		{ "pkt_not_processed",		KSTAT_DATA_UINT64, 0 },
		{ "bytes_dropped",		KSTAT_DATA_UINT64, 0 },
		{ "pkt_dropped",		KSTAT_DATA_UINT64, 0 },
		{ "nomem_bytes_dropped",	KSTAT_DATA_UINT64, 0 },
		{ "nomem_pkt_dropped",		KSTAT_DATA_UINT64, 0 },
		{ "noport_bytes_dropped",	KSTAT_DATA_UINT64, 0 },
		{ "noport_pkt_dropped",		KSTAT_DATA_UINT64, 0 },
		{ "icmp_echo_processed",	KSTAT_DATA_UINT64, 0 },
		{ "icmp_dropped",		KSTAT_DATA_UINT64, 0 },
		{ "icmp_too_big_processed",	KSTAT_DATA_UINT64, 0 },
		{ "icmp_too_big_dropped",	KSTAT_DATA_UINT64, 0 }
	};

	ksp = kstat_create_netstack(ILB_KSTAT_MOD_NAME, rule->ir_ks_instance,
	    rule->ir_name, ILB_RULE_KS_CNAME, KSTAT_TYPE_NAMED,
	    NUM_OF_FIELDS(ilb_rule_kstat_t), KSTAT_FLAG_VIRTUAL, stackid);
	if (ksp == NULL)
		return (NULL);

	bcopy(&template, &rule->ir_kstat, sizeof (template));
	ksp->ks_data = &rule->ir_kstat;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static kstat_t *
ilb_server_kstat_init(netstackid_t stackid, ilb_rule_t *rule,
    ilb_server_t *server)
{
	kstat_t *ksp;
	ilb_server_kstat_t template = {
		{ "bytes_processed",	KSTAT_DATA_UINT64, 0 },
		{ "pkt_processed",	KSTAT_DATA_UINT64, 0 },
		{ "ip_address",		KSTAT_DATA_STRING, 0 }
	};
	char cname_buf[KSTAT_STRLEN];

	/* 7 is "-sstat" */
	ASSERT(strlen(rule->ir_name) + 7 < KSTAT_STRLEN);
	(void) sprintf(cname_buf, "%s-sstat", rule->ir_name);
	ksp = kstat_create_netstack(ILB_KSTAT_MOD_NAME, rule->ir_ks_instance,
	    server->iser_name, cname_buf, KSTAT_TYPE_NAMED,
	    NUM_OF_FIELDS(ilb_server_kstat_t), KSTAT_FLAG_VIRTUAL, stackid);
	if (ksp == NULL)
		return (NULL);

	bcopy(&template, &server->iser_kstat, sizeof (template));
	ksp->ks_data = &server->iser_kstat;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_named_setstr(&server->iser_kstat.ip_address,
	    server->iser_ip_addr);
	/* We never change the IP address */
	ksp->ks_data_size += strlen(server->iser_ip_addr) + 1;

	kstat_install(ksp);
	return (ksp);
}

/* Initialize the rule hash table. */
static void
ilb_rule_hash_init(ilb_stack_t *ilbs)
{
	int i;

	/*
	 * If ilbs->ilbs_rule_hash_size is not a power of 2, bump it up to
	 * the next power of 2.
	 */
	if (ilbs->ilbs_rule_hash_size & (ilbs->ilbs_rule_hash_size - 1)) {
		for (i = 0; i < 31; i++) {
			if (ilbs->ilbs_rule_hash_size < (1 << i))
				break;
		}
		ilbs->ilbs_rule_hash_size = 1 << i;
	}
	ilbs->ilbs_g_hash = kmem_zalloc(sizeof (ilb_hash_t) *
	    ilbs->ilbs_rule_hash_size, KM_SLEEP);
	for (i = 0; i < ilbs->ilbs_rule_hash_size; i++) {
		mutex_init(&ilbs->ilbs_g_hash[i].ilb_hash_lock, NULL,
		    MUTEX_DEFAULT, NULL);
	}
}

/* Clean up the rule hash table. */
static void
ilb_rule_hash_fini(ilb_stack_t *ilbs)
{
	if (ilbs->ilbs_g_hash == NULL)
		return;
	kmem_free(ilbs->ilbs_g_hash, sizeof (ilb_hash_t) *
	    ilbs->ilbs_rule_hash_size);
}

/* Add a rule to the rule hash table. */
static void
ilb_rule_hash_add(ilb_stack_t *ilbs, ilb_rule_t *rule, const in6_addr_t *addr)
{
	int i;

	i = ILB_RULE_HASH((uint8_t *)&addr->s6_addr32[3],
	    ilbs->ilbs_rule_hash_size);
	DTRACE_PROBE2(ilb__rule__hash__add, ilb_rule_t *, rule, int, i);
	mutex_enter(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	rule->ir_hash_next = ilbs->ilbs_g_hash[i].ilb_hash_rule;
	if (ilbs->ilbs_g_hash[i].ilb_hash_rule != NULL)
		ilbs->ilbs_g_hash[i].ilb_hash_rule->ir_hash_prev = rule;
	rule->ir_hash_prev = NULL;
	ilbs->ilbs_g_hash[i].ilb_hash_rule = rule;

	rule->ir_hash = &ilbs->ilbs_g_hash[i];
	mutex_exit(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
}

/*
 * Remove a rule from the rule hash table.  Note that the rule is not freed
 * in this routine.
 */
static void
ilb_rule_hash_del(ilb_rule_t *rule)
{
	mutex_enter(&rule->ir_hash->ilb_hash_lock);
	if (rule->ir_hash->ilb_hash_rule == rule) {
		rule->ir_hash->ilb_hash_rule = rule->ir_hash_next;
		if (rule->ir_hash_next != NULL)
			rule->ir_hash_next->ir_hash_prev = NULL;
	} else {
		if (rule->ir_hash_prev != NULL)
			rule->ir_hash_prev->ir_hash_next =
			    rule->ir_hash_next;
		if (rule->ir_hash_next != NULL) {
			rule->ir_hash_next->ir_hash_prev =
			    rule->ir_hash_prev;
		}
	}
	mutex_exit(&rule->ir_hash->ilb_hash_lock);

	rule->ir_hash_next = NULL;
	rule->ir_hash_prev = NULL;
	rule->ir_hash = NULL;
}

/*
 * Given the info of a packet, look for a match in the rule hash table.
 */
static ilb_rule_t *
ilb_rule_hash(ilb_stack_t *ilbs, int l3, int l4, in6_addr_t *addr,
    in_port_t port, zoneid_t zoneid, uint32_t len, boolean_t *busy)
{
	int i;
	ilb_rule_t *rule;
	ipaddr_t v4_addr;

	*busy = B_FALSE;
	IN6_V4MAPPED_TO_IPADDR(addr, v4_addr);
	i = ILB_RULE_HASH((uint8_t *)&v4_addr, ilbs->ilbs_rule_hash_size);
	port = ntohs(port);

	mutex_enter(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	for (rule = ilbs->ilbs_g_hash[i].ilb_hash_rule; rule != NULL;
	    rule = rule->ir_hash_next) {
		if (!rule->ir_port_range) {
			if (rule->ir_min_port != port)
				continue;
		} else {
			if (port < rule->ir_min_port ||
			    port > rule->ir_max_port) {
				continue;
			}
		}
		if (rule->ir_ipver != l3 || rule->ir_proto != l4 ||
		    rule->ir_zoneid != zoneid) {
			continue;
		}

		if (l3 == IPPROTO_IP) {
			if (rule->ir_target_v4 != INADDR_ANY &&
			    rule->ir_target_v4 != v4_addr) {
				continue;
			}
		} else {
			if (!IN6_IS_ADDR_UNSPECIFIED(&rule->ir_target_v6) &&
			    !IN6_ARE_ADDR_EQUAL(addr, &rule->ir_target_v6)) {
				continue;
			}
		}

		/*
		 * Just update the stats if the rule is disabled.
		 */
		mutex_enter(&rule->ir_lock);
		if (!(rule->ir_flags & ILB_RULE_ENABLED)) {
			ILB_R_KSTAT(rule, pkt_not_processed);
			ILB_R_KSTAT_UPDATE(rule, bytes_not_processed, len);
			mutex_exit(&rule->ir_lock);
			rule = NULL;
			break;
		} else if (rule->ir_flags & ILB_RULE_BUSY) {
			/*
			 * If we are busy...
			 *
			 * XXX we should have a queue to postpone the
			 * packet processing.  But this requires a
			 * mechanism in IP to re-start the packet
			 * processing.  So for now, just drop the packet.
			 */
			ILB_R_KSTAT(rule, pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, bytes_dropped, len);
			mutex_exit(&rule->ir_lock);
			*busy = B_TRUE;
			rule = NULL;
			break;
		} else {
			rule->ir_refcnt++;
			ASSERT(rule->ir_refcnt != 1);
			mutex_exit(&rule->ir_lock);
			break;
		}
	}
	mutex_exit(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	return (rule);
}

/*
 * Add a rule to the global rule list.  This list is for finding all rules
 * in an IP stack.  The caller is assumed to hold the ilbs_g_lock.
 */
static void
ilb_rule_g_add(ilb_stack_t *ilbs, ilb_rule_t *rule)
{
	ASSERT(mutex_owned(&ilbs->ilbs_g_lock));
	rule->ir_next = ilbs->ilbs_rule_head;
	ilbs->ilbs_rule_head = rule;
	ILB_KSTAT_UPDATE(ilbs, num_rules, 1);
}

/* The call is assumed to hold the ilbs_g_lock. */
static void
ilb_rule_g_del(ilb_stack_t *ilbs, ilb_rule_t *rule)
{
	ilb_rule_t *tmp_rule;
	ilb_rule_t *prev_rule;

	ASSERT(mutex_owned(&ilbs->ilbs_g_lock));
	prev_rule = NULL;
	for (tmp_rule = ilbs->ilbs_rule_head; tmp_rule != NULL;
	    prev_rule = tmp_rule, tmp_rule = tmp_rule->ir_next) {
		if (tmp_rule == rule)
			break;
	}
	if (tmp_rule == NULL) {
		mutex_exit(&ilbs->ilbs_g_lock);
		return;
	}
	if (prev_rule == NULL)
		ilbs->ilbs_rule_head = tmp_rule->ir_next;
	else
		prev_rule->ir_next = tmp_rule->ir_next;
	ILB_KSTAT_UPDATE(ilbs, num_rules, -1);
}

/*
 * Helper routine to calculate how many source addresses are in a given
 * range.
 */
static int64_t
num_nat_src_v6(const in6_addr_t *a1, const in6_addr_t *a2)
{
	int64_t ret;
	uint32_t addr1, addr2;

	/*
	 * Here we assume that the max number of NAT source cannot be
	 * large such that the most significant 2 s6_addr32 must be
	 * equal.
	 */
	addr1 = ntohl(a1->s6_addr32[3]);
	addr2 = ntohl(a2->s6_addr32[3]);
	if (a1->s6_addr32[0] != a2->s6_addr32[0] ||
	    a1->s6_addr32[1] != a2->s6_addr32[1] ||
	    a1->s6_addr32[2] > a2->s6_addr32[2] ||
	    (a1->s6_addr32[2] == a2->s6_addr32[2] && addr1 > addr2)) {
		return (-1);
	}
	if (a1->s6_addr32[2] == a2->s6_addr32[2]) {
		return (addr2 - addr1 + 1);
	} else {
		ret = (ntohl(a2->s6_addr32[2]) - ntohl(a1->s6_addr32[2]));
		ret <<= 32;
		ret = ret + addr1 - addr2;
		return (ret + 1);
	}
}

/*
 * Add an ILB rule.
 */
int
ilb_rule_add(ilb_stack_t *ilbs, zoneid_t zoneid, const ilb_rule_cmd_t *cmd)
{
	ilb_rule_t *rule;
	netstackid_t stackid;
	int ret;
	in_port_t min_port, max_port;
	int64_t num_src;

	/* Sanity checks. */
	if (cmd->ip_ver != IPPROTO_IP && cmd->ip_ver != IPPROTO_IPV6)
		return (EINVAL);

	/* Need to support SCTP... */
	if (cmd->proto != IPPROTO_TCP && cmd->proto != IPPROTO_UDP)
		return (EINVAL);

	/* For full NAT, the NAT source must be supplied. */
	if (cmd->topo == ILB_TOPO_IMPL_NAT) {
		if (IS_ADDR_UNSPEC(&cmd->nat_src_start) ||
		    IS_ADDR_UNSPEC(&cmd->nat_src_end)) {
			return (EINVAL);
		}
	}

	/* Check invalid mask */
	if ((cmd->flags & ILB_RULE_STICKY) &&
	    IS_ADDR_UNSPEC(&cmd->sticky_mask)) {
		return (EINVAL);
	}

	/* Port is passed in network byte order. */
	min_port = ntohs(cmd->min_port);
	max_port = ntohs(cmd->max_port);
	if (min_port > max_port)
		return (EINVAL);

	/* min_port == 0 means "all ports". Make it so */
	if (min_port == 0) {
		min_port = 1;
		max_port = 65535;
	}

	/* Funny address checking. */
	if (cmd->ip_ver == IPPROTO_IP) {
		in_addr_t v4_addr1, v4_addr2;

		v4_addr1 = cmd->vip.s6_addr32[3];
		if ((*(uchar_t *)&v4_addr1) == IN_LOOPBACKNET ||
		    CLASSD(v4_addr1) || v4_addr1 == INADDR_BROADCAST ||
		    v4_addr1 == INADDR_ANY ||
		    !IN6_IS_ADDR_V4MAPPED(&cmd->vip)) {
			return (EINVAL);
		}

		if (cmd->topo == ILB_TOPO_IMPL_NAT) {
			v4_addr1 = ntohl(cmd->nat_src_start.s6_addr32[3]);
			v4_addr2 = ntohl(cmd->nat_src_end.s6_addr32[3]);
			if ((*(uchar_t *)&v4_addr1) == IN_LOOPBACKNET ||
			    (*(uchar_t *)&v4_addr2) == IN_LOOPBACKNET ||
			    v4_addr1 == INADDR_BROADCAST ||
			    v4_addr2 == INADDR_BROADCAST ||
			    v4_addr1 == INADDR_ANY || v4_addr2 == INADDR_ANY ||
			    CLASSD(v4_addr1) || CLASSD(v4_addr2) ||
			    !IN6_IS_ADDR_V4MAPPED(&cmd->nat_src_start) ||
			    !IN6_IS_ADDR_V4MAPPED(&cmd->nat_src_end)) {
				return (EINVAL);
			}

			num_src = v4_addr2 - v4_addr1 + 1;
			if (v4_addr1 > v4_addr2 || num_src > ILB_MAX_NAT_SRC)
				return (EINVAL);
		}
	} else {
		if (IN6_IS_ADDR_LOOPBACK(&cmd->vip) ||
		    IN6_IS_ADDR_MULTICAST(&cmd->vip) ||
		    IN6_IS_ADDR_UNSPECIFIED(&cmd->vip) ||
		    IN6_IS_ADDR_V4MAPPED(&cmd->vip)) {
			return (EINVAL);
		}

		if (cmd->topo == ILB_TOPO_IMPL_NAT) {
			if (IN6_IS_ADDR_LOOPBACK(&cmd->nat_src_start) ||
			    IN6_IS_ADDR_LOOPBACK(&cmd->nat_src_end) ||
			    IN6_IS_ADDR_MULTICAST(&cmd->nat_src_start) ||
			    IN6_IS_ADDR_MULTICAST(&cmd->nat_src_end) ||
			    IN6_IS_ADDR_UNSPECIFIED(&cmd->nat_src_start) ||
			    IN6_IS_ADDR_UNSPECIFIED(&cmd->nat_src_end) ||
			    IN6_IS_ADDR_V4MAPPED(&cmd->nat_src_start) ||
			    IN6_IS_ADDR_V4MAPPED(&cmd->nat_src_end)) {
				return (EINVAL);
			}

			if ((num_src = num_nat_src_v6(&cmd->nat_src_start,
			    &cmd->nat_src_end)) < 0 ||
			    num_src > ILB_MAX_NAT_SRC) {
				return (EINVAL);
			}
		}
	}

	mutex_enter(&ilbs->ilbs_g_lock);
	if (ilbs->ilbs_g_hash == NULL)
		ilb_rule_hash_init(ilbs);
	if (ilbs->ilbs_c2s_conn_hash == NULL) {
		ASSERT(ilbs->ilbs_s2c_conn_hash == NULL);
		ilb_conn_hash_init(ilbs);
		ilb_nat_src_init(ilbs);
	}

	/* Make sure that the new rule does not duplicate an existing one. */
	if (ilb_match_rule(ilbs, zoneid, cmd->name, cmd->ip_ver, cmd->proto,
	    min_port, max_port, &cmd->vip)) {
		mutex_exit(&ilbs->ilbs_g_lock);
		return (EEXIST);
	}

	rule = kmem_zalloc(sizeof (ilb_rule_t), KM_NOSLEEP);
	if (rule == NULL) {
		mutex_exit(&ilbs->ilbs_g_lock);
		return (ENOMEM);
	}

	/* ir_name is all 0 to begin with */
	(void) memcpy(rule->ir_name, cmd->name, ILB_RULE_NAMESZ - 1);

	rule->ir_ks_instance = atomic_inc_uint_nv(&ilb_kstat_instance);
	stackid = (netstackid_t)(uintptr_t)ilbs->ilbs_ksp->ks_private;
	if ((rule->ir_ksp = ilb_rule_kstat_init(stackid, rule)) == NULL) {
		ret = ENOMEM;
		goto error;
	}

	if (cmd->topo == ILB_TOPO_IMPL_NAT) {
		rule->ir_nat_src_start = cmd->nat_src_start;
		rule->ir_nat_src_end = cmd->nat_src_end;
	}

	rule->ir_ipver = cmd->ip_ver;
	rule->ir_proto = cmd->proto;
	rule->ir_topo = cmd->topo;

	rule->ir_min_port = min_port;
	rule->ir_max_port = max_port;
	if (rule->ir_min_port != rule->ir_max_port)
		rule->ir_port_range = B_TRUE;
	else
		rule->ir_port_range = B_FALSE;

	rule->ir_zoneid = zoneid;

	rule->ir_target_v6 = cmd->vip;
	rule->ir_servers = NULL;

	/*
	 * The default connection drain timeout is indefinite (value 0),
	 * meaning we will wait for all connections to finish.  So we
	 * can assign cmd->conn_drain_timeout to it directly.
	 */
	rule->ir_conn_drain_timeout = cmd->conn_drain_timeout;
	if (cmd->nat_expiry != 0) {
		rule->ir_nat_expiry = cmd->nat_expiry;
	} else {
		switch (rule->ir_proto) {
		case IPPROTO_TCP:
			rule->ir_nat_expiry = ilb_conn_tcp_expiry;
			break;
		case IPPROTO_UDP:
			rule->ir_nat_expiry = ilb_conn_udp_expiry;
			break;
		default:
			cmn_err(CE_PANIC, "data corruption: wrong ir_proto: %p",
			    (void *)rule);
			break;
		}
	}
	if (cmd->sticky_expiry != 0)
		rule->ir_sticky_expiry = cmd->sticky_expiry;
	else
		rule->ir_sticky_expiry = ilb_sticky_expiry;

	if (cmd->flags & ILB_RULE_STICKY) {
		rule->ir_flags |= ILB_RULE_STICKY;
		rule->ir_sticky_mask = cmd->sticky_mask;
		if (ilbs->ilbs_sticky_hash == NULL)
			ilb_sticky_hash_init(ilbs);
	}
	if (cmd->flags & ILB_RULE_ENABLED)
		rule->ir_flags |= ILB_RULE_ENABLED;

	mutex_init(&rule->ir_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rule->ir_cv, NULL, CV_DEFAULT, NULL);

	rule->ir_refcnt = 1;

	switch (cmd->algo) {
	case ILB_ALG_IMPL_ROUNDROBIN:
		if ((rule->ir_alg = ilb_alg_rr_init(rule, NULL)) == NULL) {
			ret = ENOMEM;
			goto error;
		}
		rule->ir_alg_type = ILB_ALG_IMPL_ROUNDROBIN;
		break;
	case ILB_ALG_IMPL_HASH_IP:
	case ILB_ALG_IMPL_HASH_IP_SPORT:
	case ILB_ALG_IMPL_HASH_IP_VIP:
		if ((rule->ir_alg = ilb_alg_hash_init(rule,
		    &cmd->algo)) == NULL) {
			ret = ENOMEM;
			goto error;
		}
		rule->ir_alg_type = cmd->algo;
		break;
	default:
		ret = EINVAL;
		goto error;
	}

	/* Add it to the global list and hash array at the end. */
	ilb_rule_g_add(ilbs, rule);
	ilb_rule_hash_add(ilbs, rule, &cmd->vip);

	mutex_exit(&ilbs->ilbs_g_lock);

	return (0);

error:
	mutex_exit(&ilbs->ilbs_g_lock);
	if (rule->ir_ksp != NULL) {
		/* stackid must be initialized if ir_ksp != NULL */
		kstat_delete_netstack(rule->ir_ksp, stackid);
	}
	kmem_free(rule, sizeof (ilb_rule_t));
	return (ret);
}

/*
 * The final part in deleting a rule.  Either called directly or by the
 * taskq dispatched.
 */
static void
ilb_rule_del_common(ilb_stack_t *ilbs, ilb_rule_t *tmp_rule)
{
	netstackid_t stackid;
	ilb_server_t *server;

	stackid = (netstackid_t)(uintptr_t)ilbs->ilbs_ksp->ks_private;

	/*
	 * Let the algorithm know that the rule is going away.  The
	 * algorithm fini routine will free all its resources with this
	 * rule.
	 */
	tmp_rule->ir_alg->ilb_alg_fini(&tmp_rule->ir_alg);

	while ((server = tmp_rule->ir_servers) != NULL) {
		mutex_enter(&server->iser_lock);
		ilb_destroy_nat_src(&server->iser_nat_src);
		if (tmp_rule->ir_conn_drain_timeout != 0) {
			/*
			 * The garbage collection thread checks this value
			 * without grabing a lock.  So we need to use
			 * atomic_swap_64() to make sure that the value seen
			 * by gc thread is intact.
			 */
			(void) atomic_swap_64(
			    (uint64_t *)&server->iser_die_time,
			    ddi_get_lbolt64() +
			    SEC_TO_TICK(tmp_rule->ir_conn_drain_timeout));
		}
		while (server->iser_refcnt > 1)
			cv_wait(&server->iser_cv, &server->iser_lock);
		tmp_rule->ir_servers = server->iser_next;
		kstat_delete_netstack(server->iser_ksp, stackid);
		kmem_free(server, sizeof (ilb_server_t));
	}

	ASSERT(tmp_rule->ir_ksp != NULL);
	kstat_delete_netstack(tmp_rule->ir_ksp, stackid);

	kmem_free(tmp_rule, sizeof (ilb_rule_t));
}

/* The routine executed by the delayed rule taskq. */
static void
ilb_rule_del_tq(void *arg)
{
	ilb_stack_t *ilbs = ((ilb_rule_tq_t *)arg)->ilbs;
	ilb_rule_t *rule = ((ilb_rule_tq_t *)arg)->rule;

	mutex_enter(&rule->ir_lock);
	while (rule->ir_refcnt > 1)
		cv_wait(&rule->ir_cv, &rule->ir_lock);
	ilb_rule_del_common(ilbs, rule);
	kmem_free(arg, sizeof (ilb_rule_tq_t));
}

/* Routine to delete a rule. */
int
ilb_rule_del(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name)
{
	ilb_rule_t *tmp_rule;
	ilb_rule_tq_t *arg;
	int err;

	mutex_enter(&ilbs->ilbs_g_lock);
	if ((tmp_rule = ilb_find_rule_locked(ilbs, zoneid, name,
	    &err)) == NULL) {
		mutex_exit(&ilbs->ilbs_g_lock);
		return (err);
	}

	/*
	 * First remove the rule from the hash array and the global list so
	 * that no one can find this rule any more.
	 */
	ilb_rule_hash_del(tmp_rule);
	ilb_rule_g_del(ilbs, tmp_rule);
	mutex_exit(&ilbs->ilbs_g_lock);
	ILB_RULE_REFRELE(tmp_rule);

	/*
	 * Now no one can find this rule, we can remove it once all
	 * references to it are dropped and all references to the list
	 * of servers are dropped.  So dispatch a task to finish the deletion.
	 * We do this instead of letting the last one referencing the
	 * rule do it.  The reason is that the last one may be the
	 * interrupt thread.  We want to minimize the work it needs to
	 * do.  Rule deletion is not a critical task so it can be delayed.
	 */
	arg = kmem_alloc(sizeof (ilb_rule_tq_t), KM_SLEEP);
	arg->ilbs = ilbs;
	arg->rule = tmp_rule;
	(void) taskq_dispatch(ilbs->ilbs_rule_taskq, ilb_rule_del_tq, arg,
	    TQ_SLEEP);

	return (0);
}

/*
 * Given an IP address, check to see if there is a rule using this
 * as the VIP.  It can be used to check if we need to drop a fragment.
 */
boolean_t
ilb_rule_match_vip_v6(ilb_stack_t *ilbs, in6_addr_t *vip, ilb_rule_t **ret_rule)
{
	int i;
	ilb_rule_t *rule;
	boolean_t ret = B_FALSE;

	i = ILB_RULE_HASH((uint8_t *)&vip->s6_addr32[3],
	    ilbs->ilbs_rule_hash_size);
	mutex_enter(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	for (rule = ilbs->ilbs_g_hash[i].ilb_hash_rule; rule != NULL;
	    rule = rule->ir_hash_next) {
		if (IN6_ARE_ADDR_EQUAL(vip, &rule->ir_target_v6)) {
			mutex_enter(&rule->ir_lock);
			if (rule->ir_flags & ILB_RULE_BUSY) {
				mutex_exit(&rule->ir_lock);
				break;
			}
			if (ret_rule != NULL) {
				rule->ir_refcnt++;
				mutex_exit(&rule->ir_lock);
				*ret_rule = rule;
			} else {
				mutex_exit(&rule->ir_lock);
			}
			ret = B_TRUE;
			break;
		}
	}
	mutex_exit(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	return (ret);
}

boolean_t
ilb_rule_match_vip_v4(ilb_stack_t *ilbs, ipaddr_t addr, ilb_rule_t **ret_rule)
{
	int i;
	ilb_rule_t *rule;
	boolean_t ret = B_FALSE;

	i = ILB_RULE_HASH((uint8_t *)&addr, ilbs->ilbs_rule_hash_size);
	mutex_enter(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	for (rule = ilbs->ilbs_g_hash[i].ilb_hash_rule; rule != NULL;
	    rule = rule->ir_hash_next) {
		if (rule->ir_target_v6.s6_addr32[3] == addr) {
			mutex_enter(&rule->ir_lock);
			if (rule->ir_flags & ILB_RULE_BUSY) {
				mutex_exit(&rule->ir_lock);
				break;
			}
			if (ret_rule != NULL) {
				rule->ir_refcnt++;
				mutex_exit(&rule->ir_lock);
				*ret_rule = rule;
			} else {
				mutex_exit(&rule->ir_lock);
			}
			ret = B_TRUE;
			break;
		}
	}
	mutex_exit(&ilbs->ilbs_g_hash[i].ilb_hash_lock);
	return (ret);
}

static ilb_rule_t *
ilb_find_rule_locked(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    int *err)
{
	ilb_rule_t *tmp_rule;

	ASSERT(mutex_owned(&ilbs->ilbs_g_lock));

	for (tmp_rule = ilbs->ilbs_rule_head; tmp_rule != NULL;
	    tmp_rule = tmp_rule->ir_next) {
		if (tmp_rule->ir_zoneid != zoneid)
			continue;
		if (strcasecmp(tmp_rule->ir_name, name) == 0) {
			mutex_enter(&tmp_rule->ir_lock);
			if (tmp_rule->ir_flags & ILB_RULE_BUSY) {
				mutex_exit(&tmp_rule->ir_lock);
				*err = EINPROGRESS;
				return (NULL);
			}
			tmp_rule->ir_refcnt++;
			mutex_exit(&tmp_rule->ir_lock);
			*err = 0;
			return (tmp_rule);
		}
	}
	*err = ENOENT;
	return (NULL);
}

/* To find a rule with a given name and zone in the global rule list. */
ilb_rule_t *
ilb_find_rule(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    int *err)
{
	ilb_rule_t *tmp_rule;

	mutex_enter(&ilbs->ilbs_g_lock);
	tmp_rule = ilb_find_rule_locked(ilbs, zoneid, name, err);
	mutex_exit(&ilbs->ilbs_g_lock);
	return (tmp_rule);
}

/* Try to match the given packet info and zone ID with a rule. */
static boolean_t
ilb_match_rule(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name, int l3,
    int l4, in_port_t min_port, in_port_t max_port, const in6_addr_t *addr)
{
	ilb_rule_t *tmp_rule;

	ASSERT(mutex_owned(&ilbs->ilbs_g_lock));

	for (tmp_rule = ilbs->ilbs_rule_head; tmp_rule != NULL;
	    tmp_rule = tmp_rule->ir_next) {
		if (tmp_rule->ir_zoneid != zoneid)
			continue;

		/*
		 * We don't allow the same name in different rules even if all
		 * the other rule components are different.
		 */
		if (strcasecmp(tmp_rule->ir_name, name) == 0)
			return (B_TRUE);

		if (tmp_rule->ir_ipver != l3 || tmp_rule->ir_proto != l4)
			continue;

		/*
		 * ir_min_port and ir_max_port are the same if ir_port_range
		 * is false.  In this case, if the ir_min|max_port (same) is
		 * outside of the given port range, it is OK.  In other cases,
		 * check if min and max port are outside a rule's range.
		 */
		if (tmp_rule->ir_max_port < min_port ||
		    tmp_rule->ir_min_port > max_port) {
			continue;
		}

		/*
		 * If l3 is IPv4, the addr passed in is assumed to be
		 * mapped address.
		 */
		if (V6_OR_V4_INADDR_ANY(*addr) ||
		    V6_OR_V4_INADDR_ANY(tmp_rule->ir_target_v6) ||
		    IN6_ARE_ADDR_EQUAL(addr, &tmp_rule->ir_target_v6)) {
			return (B_TRUE);
		}
	}
	return (B_FALSE);
}

int
ilb_rule_enable(ilb_stack_t *ilbs, zoneid_t zoneid,
    const char *rule_name, ilb_rule_t *in_rule)
{
	ilb_rule_t *rule;
	int err;

	ASSERT((in_rule == NULL && rule_name != NULL) ||
	    (in_rule != NULL && rule_name == NULL));
	if ((rule = in_rule) == NULL) {
		if ((rule = ilb_find_rule(ilbs, zoneid, rule_name,
		    &err)) == NULL) {
			return (err);
		}
	}
	mutex_enter(&rule->ir_lock);
	rule->ir_flags |= ILB_RULE_ENABLED;
	mutex_exit(&rule->ir_lock);

	/* Only refrele if the rule is passed in. */
	if (in_rule == NULL)
		ILB_RULE_REFRELE(rule);
	return (0);
}

int
ilb_rule_disable(ilb_stack_t *ilbs, zoneid_t zoneid,
    const char *rule_name, ilb_rule_t *in_rule)
{
	ilb_rule_t *rule;
	int err;

	ASSERT((in_rule == NULL && rule_name != NULL) ||
	    (in_rule != NULL && rule_name == NULL));
	if ((rule = in_rule) == NULL) {
		if ((rule = ilb_find_rule(ilbs, zoneid, rule_name,
		    &err)) == NULL) {
			return (err);
		}
	}
	mutex_enter(&rule->ir_lock);
	rule->ir_flags &= ~ILB_RULE_ENABLED;
	mutex_exit(&rule->ir_lock);

	/* Only refrele if the rule is passed in. */
	if (in_rule == NULL)
		ILB_RULE_REFRELE(rule);
	return (0);
}

/*
 * XXX We should probably have a walker function to walk all rules.  For
 * now, just add a simple loop for enable/disable/del.
 */
void
ilb_rule_enable_all(ilb_stack_t *ilbs, zoneid_t zoneid)
{
	ilb_rule_t *rule;

	mutex_enter(&ilbs->ilbs_g_lock);
	for (rule = ilbs->ilbs_rule_head; rule != NULL; rule = rule->ir_next) {
		if (rule->ir_zoneid != zoneid)
			continue;
		/*
		 * No need to hold the rule as we are holding the global
		 * lock so it won't go away.  Ignore the return value here
		 * as the rule is provided so the call cannot fail.
		 */
		(void) ilb_rule_enable(ilbs, zoneid, NULL, rule);
	}
	mutex_exit(&ilbs->ilbs_g_lock);
}

void
ilb_rule_disable_all(ilb_stack_t *ilbs, zoneid_t zoneid)
{
	ilb_rule_t *rule;

	mutex_enter(&ilbs->ilbs_g_lock);
	for (rule = ilbs->ilbs_rule_head; rule != NULL;
	    rule = rule->ir_next) {
		if (rule->ir_zoneid != zoneid)
			continue;
		(void) ilb_rule_disable(ilbs, zoneid, NULL, rule);
	}
	mutex_exit(&ilbs->ilbs_g_lock);
}

void
ilb_rule_del_all(ilb_stack_t *ilbs, zoneid_t zoneid)
{
	ilb_rule_t *rule;
	ilb_rule_tq_t *arg;

	mutex_enter(&ilbs->ilbs_g_lock);
	while ((rule = ilbs->ilbs_rule_head) != NULL) {
		if (rule->ir_zoneid != zoneid)
			continue;
		ilb_rule_hash_del(rule);
		ilb_rule_g_del(ilbs, rule);
		mutex_exit(&ilbs->ilbs_g_lock);

		arg = kmem_alloc(sizeof (ilb_rule_tq_t), KM_SLEEP);
		arg->ilbs = ilbs;
		arg->rule = rule;
		(void) taskq_dispatch(ilbs->ilbs_rule_taskq, ilb_rule_del_tq,
		    arg, TQ_SLEEP);

		mutex_enter(&ilbs->ilbs_g_lock);
	}
	mutex_exit(&ilbs->ilbs_g_lock);
}

/*
 * This is just an optimization, so don't grab the global lock.  The
 * worst case is that we missed a couple packets.
 */
boolean_t
ilb_has_rules(ilb_stack_t *ilbs)
{
	return (ilbs->ilbs_rule_head != NULL);
}


static int
ilb_server_toggle(ilb_stack_t *ilbs, zoneid_t zoneid, const char *rule_name,
    ilb_rule_t *rule, in6_addr_t *addr, boolean_t enable)
{
	ilb_server_t *tmp_server;
	int ret;

	ASSERT((rule == NULL && rule_name != NULL) ||
	    (rule != NULL && rule_name == NULL));

	if (rule == NULL) {
		if ((rule = ilb_find_rule(ilbs, zoneid, rule_name,
		    &ret)) == NULL) {
			return (ret);
		}
	}

	/* Once we get a hold on the rule, no server can be added/deleted. */
	for (tmp_server = rule->ir_servers; tmp_server != NULL;
	    tmp_server = tmp_server->iser_next) {
		if (IN6_ARE_ADDR_EQUAL(&tmp_server->iser_addr_v6, addr))
			break;
	}
	if (tmp_server == NULL) {
		ret = ENOENT;
		goto done;
	}

	if (enable) {
		ret = rule->ir_alg->ilb_alg_server_enable(tmp_server,
		    rule->ir_alg->ilb_alg_data);
		if (ret == 0) {
			tmp_server->iser_enabled = B_TRUE;
			tmp_server->iser_die_time = 0;
		}
	} else {
		ret = rule->ir_alg->ilb_alg_server_disable(tmp_server,
		    rule->ir_alg->ilb_alg_data);
		if (ret == 0) {
			tmp_server->iser_enabled = B_FALSE;
			if (rule->ir_conn_drain_timeout != 0) {
				(void) atomic_swap_64(
				    (uint64_t *)&tmp_server->iser_die_time,
				    ddi_get_lbolt64() + SEC_TO_TICK(
				    rule->ir_conn_drain_timeout));
			}
		}
	}

done:
	if (rule_name != NULL)
		ILB_RULE_REFRELE(rule);
	return (ret);
}
int
ilb_server_enable(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    ilb_rule_t *rule, in6_addr_t *addr)
{
	return (ilb_server_toggle(ilbs, zoneid, name, rule, addr, B_TRUE));
}

int
ilb_server_disable(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    ilb_rule_t *rule, in6_addr_t *addr)
{
	return (ilb_server_toggle(ilbs, zoneid, name, rule, addr, B_FALSE));
}

/*
 * Add a back end server to a rule.  If the address is IPv4, it is assumed
 * to be passed in as a mapped address.
 */
int
ilb_server_add(ilb_stack_t *ilbs, ilb_rule_t *rule, ilb_server_info_t *info)
{
	ilb_server_t	*server;
	netstackid_t	stackid;
	int		ret = 0;
	in_port_t	min_port, max_port;
	in_port_t	range;

	/* Port is passed in network byte order. */
	min_port = ntohs(info->min_port);
	max_port = ntohs(info->max_port);
	if (min_port > max_port)
		return (EINVAL);

	/* min_port == 0 means "all ports". Make it so */
	if (min_port == 0) {
		min_port = 1;
		max_port = 65535;
	}
	range = max_port - min_port;

	mutex_enter(&rule->ir_lock);
	/* If someone is already doing server add/del, sleeps and wait. */
	while (rule->ir_flags & ILB_RULE_BUSY) {
		if (cv_wait_sig(&rule->ir_cv, &rule->ir_lock) == 0) {
			mutex_exit(&rule->ir_lock);
			return (EINTR);
		}
	}

	/*
	 * Set the rule to be busy to make sure that no new packet can
	 * use this rule.
	 */
	rule->ir_flags |= ILB_RULE_BUSY;

	/* Now wait for all other guys to finish their work. */
	while (rule->ir_refcnt > 2) {
		if (cv_wait_sig(&rule->ir_cv, &rule->ir_lock) == 0) {
			mutex_exit(&rule->ir_lock);
			ret = EINTR;
			goto end;
		}
	}
	mutex_exit(&rule->ir_lock);

	/* Sanity checks... */
	if ((IN6_IS_ADDR_V4MAPPED(&info->addr) &&
	    rule->ir_ipver != IPPROTO_IP) ||
	    (!IN6_IS_ADDR_V4MAPPED(&info->addr) &&
	    rule->ir_ipver != IPPROTO_IPV6)) {
		ret = EINVAL;
		goto end;
	}

	/*
	 * Check for valid port range.
	 *
	 * For DSR, there can be no port shifting.  Hence the server
	 * specification must be the same as the rule's.
	 *
	 * For half-NAT/NAT, the range must either be 0 (port collapsing) or
	 * it must be equal to the same value as the rule port range.
	 *
	 */
	if (rule->ir_topo == ILB_TOPO_IMPL_DSR) {
		if (rule->ir_max_port != max_port ||
		    rule->ir_min_port != min_port) {
			ret = EINVAL;
			goto end;
		}
	} else {
		if ((range != rule->ir_max_port - rule->ir_min_port) &&
		    range != 0) {
			ret = EINVAL;
			goto end;
		}
	}

	/* Check for duplicate. */
	for (server = rule->ir_servers; server != NULL;
	    server = server->iser_next) {
		if (IN6_ARE_ADDR_EQUAL(&server->iser_addr_v6, &info->addr) ||
		    strcasecmp(server->iser_name, info->name) == 0) {
			break;
		}
	}
	if (server != NULL) {
		ret = EEXIST;
		goto end;
	}

	if ((server = kmem_zalloc(sizeof (ilb_server_t), KM_NOSLEEP)) == NULL) {
		ret = ENOMEM;
		goto end;
	}

	(void) memcpy(server->iser_name, info->name, ILB_SERVER_NAMESZ - 1);
	(void) inet_ntop(AF_INET6, &info->addr, server->iser_ip_addr,
	    sizeof (server->iser_ip_addr));
	stackid = (netstackid_t)(uintptr_t)ilbs->ilbs_ksp->ks_private;
	server->iser_ksp = ilb_server_kstat_init(stackid, rule, server);
	if (server->iser_ksp == NULL) {
		kmem_free(server, sizeof (ilb_server_t));
		ret = EINVAL;
		goto end;
	}

	server->iser_stackid = stackid;
	server->iser_addr_v6 = info->addr;
	server->iser_min_port = min_port;
	server->iser_max_port = max_port;
	if (min_port != max_port)
		server->iser_port_range = B_TRUE;
	else
		server->iser_port_range = B_FALSE;

	/*
	 * If the rule uses NAT, find/create the NAT source entry to use
	 * for this server.
	 */
	if (rule->ir_topo == ILB_TOPO_IMPL_NAT) {
		in_port_t port;

		/*
		 * If the server uses a port range, our port allocation
		 * scheme needs to treat it as a wildcard.  Refer to the
		 * comments in ilb_nat.c about the scheme.
		 */
		if (server->iser_port_range)
			port = 0;
		else
			port = server->iser_min_port;

		if ((ret = ilb_create_nat_src(ilbs, &server->iser_nat_src,
		    &server->iser_addr_v6, port, &rule->ir_nat_src_start,
		    num_nat_src_v6(&rule->ir_nat_src_start,
		    &rule->ir_nat_src_end))) != 0) {
			kstat_delete_netstack(server->iser_ksp, stackid);
			kmem_free(server, sizeof (ilb_server_t));
			goto end;
		}
	}

	/*
	 * The iser_lock is only used to protect iser_refcnt.  All the other
	 * fields in ilb_server_t should not change, except for iser_enabled.
	 * The worst thing that can happen if iser_enabled is messed up is
	 * that one or two packets may not be load balanced to a server
	 * correctly.
	 */
	server->iser_refcnt = 1;
	server->iser_enabled = info->flags & ILB_SERVER_ENABLED ? B_TRUE :
	    B_FALSE;
	mutex_init(&server->iser_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&server->iser_cv, NULL, CV_DEFAULT, NULL);

	/* Let the load balancing algorithm know about the addition. */
	ASSERT(rule->ir_alg != NULL);
	if ((ret = rule->ir_alg->ilb_alg_server_add(server,
	    rule->ir_alg->ilb_alg_data)) != 0) {
		kstat_delete_netstack(server->iser_ksp, stackid);
		kmem_free(server, sizeof (ilb_server_t));
		goto end;
	}

	/*
	 * No need to hold ir_lock since no other thread should manipulate
	 * the following fields until ILB_RULE_BUSY is cleared.
	 */
	if (rule->ir_servers == NULL) {
		server->iser_next = NULL;
	} else {
		server->iser_next = rule->ir_servers;
	}
	rule->ir_servers = server;
	ILB_R_KSTAT(rule, num_servers);

end:
	mutex_enter(&rule->ir_lock);
	rule->ir_flags &= ~ILB_RULE_BUSY;
	cv_signal(&rule->ir_cv);
	mutex_exit(&rule->ir_lock);
	return (ret);
}

/* The routine executed by the delayed rule processing taskq. */
static void
ilb_server_del_tq(void *arg)
{
	ilb_server_t *server = (ilb_server_t *)arg;

	mutex_enter(&server->iser_lock);
	while (server->iser_refcnt > 1)
		cv_wait(&server->iser_cv, &server->iser_lock);
	kstat_delete_netstack(server->iser_ksp, server->iser_stackid);
	kmem_free(server, sizeof (ilb_server_t));
}

/*
 * Delete a back end server from a rule.  If the address is IPv4, it is assumed
 * to be passed in as a mapped address.
 */
int
ilb_server_del(ilb_stack_t *ilbs, zoneid_t zoneid, const char *rule_name,
    ilb_rule_t *rule, in6_addr_t *addr)
{
	ilb_server_t	*server;
	ilb_server_t	*prev_server;
	int		ret = 0;

	ASSERT((rule == NULL && rule_name != NULL) ||
	    (rule != NULL && rule_name == NULL));
	if (rule == NULL) {
		if ((rule = ilb_find_rule(ilbs, zoneid, rule_name,
		    &ret)) == NULL) {
			return (ret);
		}
	}

	mutex_enter(&rule->ir_lock);
	/* If someone is already doing server add/del, sleeps and wait. */
	while (rule->ir_flags & ILB_RULE_BUSY) {
		if (cv_wait_sig(&rule->ir_cv, &rule->ir_lock) == 0) {
			if (rule_name != NULL) {
				if (--rule->ir_refcnt <= 2)
					cv_signal(&rule->ir_cv);
			}
			mutex_exit(&rule->ir_lock);
			return (EINTR);
		}
	}
	/*
	 * Set the rule to be busy to make sure that no new packet can
	 * use this rule.
	 */
	rule->ir_flags |= ILB_RULE_BUSY;

	/* Now wait for all other guys to finish their work. */
	while (rule->ir_refcnt > 2) {
		if (cv_wait_sig(&rule->ir_cv, &rule->ir_lock) == 0) {
			mutex_exit(&rule->ir_lock);
			ret = EINTR;
			goto end;
		}
	}
	mutex_exit(&rule->ir_lock);

	prev_server = NULL;
	for (server = rule->ir_servers; server != NULL;
	    prev_server = server, server = server->iser_next) {
		if (IN6_ARE_ADDR_EQUAL(&server->iser_addr_v6, addr))
			break;
	}
	if (server == NULL) {
		ret = ENOENT;
		goto end;
	}

	/*
	 * Let the load balancing algorithm know about the removal.
	 * The algorithm may disallow the removal...
	 */
	if ((ret = rule->ir_alg->ilb_alg_server_del(server,
	    rule->ir_alg->ilb_alg_data)) != 0) {
		goto end;
	}

	if (prev_server == NULL)
		rule->ir_servers = server->iser_next;
	else
		prev_server->iser_next = server->iser_next;

	ILB_R_KSTAT_UPDATE(rule, num_servers, -1);

	/*
	 * Mark the server as disabled so that if there is any sticky cache
	 * using this server around, it won't be used.
	 */
	server->iser_enabled = B_FALSE;

	mutex_enter(&server->iser_lock);

	/*
	 * De-allocate the NAT source array.  The indiviual ilb_nat_src_entry_t
	 * may not go away if there is still a conn using it.  The NAT source
	 * timer will do the garbage collection.
	 */
	ilb_destroy_nat_src(&server->iser_nat_src);

	/* If there is a hard limit on when a server should die, set it. */
	if (rule->ir_conn_drain_timeout != 0) {
		(void) atomic_swap_64((uint64_t *)&server->iser_die_time,
		    ddi_get_lbolt64() +
		    SEC_TO_TICK(rule->ir_conn_drain_timeout));
	}

	if (server->iser_refcnt > 1) {
		(void) taskq_dispatch(ilbs->ilbs_rule_taskq, ilb_server_del_tq,
		    server, TQ_SLEEP);
		mutex_exit(&server->iser_lock);
	} else {
		kstat_delete_netstack(server->iser_ksp, server->iser_stackid);
		kmem_free(server, sizeof (ilb_server_t));
	}

end:
	mutex_enter(&rule->ir_lock);
	rule->ir_flags &= ~ILB_RULE_BUSY;
	if (rule_name != NULL)
		rule->ir_refcnt--;
	cv_signal(&rule->ir_cv);
	mutex_exit(&rule->ir_lock);
	return (ret);
}

/*
 * First check if the destination of the ICMP message matches a VIP of
 * a rule.  If it does not, just return ILB_PASSED.
 *
 * If the destination matches a VIP:
 *
 * For ICMP_ECHO_REQUEST, generate a response on behalf of the back end
 * server.
 *
 * For ICMP_DEST_UNREACHABLE fragmentation needed, check inside the payload
 * and see which back end server we should send this message to.  And we
 * need to do NAT on both the payload message and the outside IP packet.
 *
 * For other ICMP messages, drop them.
 */
/* ARGSUSED */
static int
ilb_icmp_v4(ilb_stack_t *ilbs, ill_t *ill, mblk_t *mp, ipha_t *ipha,
    icmph_t *icmph, ipaddr_t *lb_dst)
{
	ipaddr_t vip;
	ilb_rule_t *rule;
	in6_addr_t addr6;

	if (!ilb_rule_match_vip_v4(ilbs, ipha->ipha_dst, &rule))
		return (ILB_PASSED);


	if ((uint8_t *)icmph + sizeof (icmph_t) > mp->b_wptr) {
		ILB_R_KSTAT(rule, icmp_dropped);
		ILB_RULE_REFRELE(rule);
		return (ILB_DROPPED);
	}

	switch (icmph->icmph_type) {
	case ICMP_ECHO_REQUEST:
		ILB_R_KSTAT(rule, icmp_echo_processed);
		ILB_RULE_REFRELE(rule);

		icmph->icmph_type = ICMP_ECHO_REPLY;
		icmph->icmph_checksum = 0;
		icmph->icmph_checksum = IP_CSUM(mp, IPH_HDR_LENGTH(ipha), 0);
		ipha->ipha_ttl =
		    ilbs->ilbs_netstack->netstack_ip->ips_ip_def_ttl;
		*lb_dst = ipha->ipha_src;
		vip = ipha->ipha_dst;
		ipha->ipha_dst = ipha->ipha_src;
		ipha->ipha_src = vip;
		return (ILB_BALANCED);
	case ICMP_DEST_UNREACHABLE: {
		int ret;

		if (icmph->icmph_code != ICMP_FRAGMENTATION_NEEDED) {
			ILB_R_KSTAT(rule, icmp_dropped);
			ILB_RULE_REFRELE(rule);
			return (ILB_DROPPED);
		}
		if (ilb_check_icmp_conn(ilbs, mp, IPPROTO_IP, ipha, icmph,
		    &addr6)) {
			ILB_R_KSTAT(rule, icmp_2big_processed);
			ret = ILB_BALANCED;
		} else {
			ILB_R_KSTAT(rule, icmp_2big_dropped);
			ret = ILB_DROPPED;
		}
		ILB_RULE_REFRELE(rule);
		IN6_V4MAPPED_TO_IPADDR(&addr6, *lb_dst);
		return (ret);
	}
	default:
		ILB_R_KSTAT(rule, icmp_dropped);
		ILB_RULE_REFRELE(rule);
		return (ILB_DROPPED);
	}
}

/* ARGSUSED */
static int
ilb_icmp_v6(ilb_stack_t *ilbs, ill_t *ill, mblk_t *mp, ip6_t *ip6h,
    icmp6_t *icmp6, in6_addr_t *lb_dst)
{
	ilb_rule_t *rule;

	if (!ilb_rule_match_vip_v6(ilbs, &ip6h->ip6_dst, &rule))
		return (ILB_PASSED);

	if ((uint8_t *)icmp6 + sizeof (icmp6_t) > mp->b_wptr) {
		ILB_R_KSTAT(rule, icmp_dropped);
		ILB_RULE_REFRELE(rule);
		return (ILB_DROPPED);
	}

	switch (icmp6->icmp6_type) {
	case ICMP6_ECHO_REQUEST: {
		int hdr_len;

		ILB_R_KSTAT(rule, icmp_echo_processed);
		ILB_RULE_REFRELE(rule);

		icmp6->icmp6_type = ICMP6_ECHO_REPLY;
		icmp6->icmp6_cksum = ip6h->ip6_plen;
		hdr_len = (char *)icmp6 - (char *)ip6h;
		icmp6->icmp6_cksum = IP_CSUM(mp, hdr_len,
		    ilb_pseudo_sum_v6(ip6h, IPPROTO_ICMPV6));
		ip6h->ip6_vcf &= ~IPV6_FLOWINFO_FLOWLABEL;
		ip6h->ip6_hops =
		    ilbs->ilbs_netstack->netstack_ip->ips_ipv6_def_hops;
		*lb_dst = ip6h->ip6_src;
		ip6h->ip6_src = ip6h->ip6_dst;
		ip6h->ip6_dst = *lb_dst;
		return (ILB_BALANCED);
	}
	case ICMP6_PACKET_TOO_BIG: {
		int ret;

		if (ilb_check_icmp_conn(ilbs, mp, IPPROTO_IPV6, ip6h, icmp6,
		    lb_dst)) {
			ILB_R_KSTAT(rule, icmp_2big_processed);
			ret = ILB_BALANCED;
		} else {
			ILB_R_KSTAT(rule, icmp_2big_dropped);
			ret = ILB_DROPPED;
		}
		ILB_RULE_REFRELE(rule);
		return (ret);
	}
	default:
		ILB_R_KSTAT(rule, icmp_dropped);
		ILB_RULE_REFRELE(rule);
		return (ILB_DROPPED);
	}
}

/*
 * Common routine to check an incoming packet and decide what to do with it.
 * called by ilb_check_v4|v6().
 */
static int
ilb_check(ilb_stack_t *ilbs, ill_t *ill, mblk_t *mp, in6_addr_t *src,
    in6_addr_t *dst, int l3, int l4, void *iph, uint8_t *tph, uint32_t pkt_len,
    in6_addr_t *lb_dst)
{
	in_port_t		sport, dport;
	tcpha_t			*tcph;
	udpha_t			*udph;
	ilb_rule_t		*rule;
	ilb_server_t		*server;
	boolean_t		balanced;
	struct ilb_sticky_s	*s = NULL;
	int			ret;
	uint32_t		ip_sum, tp_sum;
	ilb_nat_info_t		info;
	uint16_t		nat_src_idx;
	boolean_t		busy;

	/*
	 * We don't really need to switch here since both protocols's
	 * ports are at the same offset.  Just prepare for future protocol
	 * specific processing.
	 */
	switch (l4) {
	case IPPROTO_TCP:
		if (tph + TCP_MIN_HEADER_LENGTH > mp->b_wptr)
			return (ILB_DROPPED);
		tcph = (tcpha_t *)tph;
		sport = tcph->tha_lport;
		dport = tcph->tha_fport;
		break;
	case IPPROTO_UDP:
		if (tph + sizeof (udpha_t) > mp->b_wptr)
			return (ILB_DROPPED);
		udph = (udpha_t *)tph;
		sport = udph->uha_src_port;
		dport = udph->uha_dst_port;
		break;
	default:
		return (ILB_PASSED);
	}

	/* Fast path, there is an existing conn. */
	if (ilb_check_conn(ilbs, l3, iph, l4, tph, src, dst, sport, dport,
	    pkt_len, lb_dst)) {
		return (ILB_BALANCED);
	}

	/*
	 * If there is no existing connection for the incoming packet, check
	 * to see if the packet matches a rule.  If not, just let IP decide
	 * what to do with it.
	 *
	 * Note: a reply from back end server should not match a rule.  A
	 * reply should match one existing conn.
	 */
	rule = ilb_rule_hash(ilbs, l3, l4, dst, dport, ill->ill_zoneid,
	    pkt_len, &busy);
	if (rule == NULL) {
		/* If the rule is busy, just drop the packet. */
		if (busy)
			return (ILB_DROPPED);
		else
			return (ILB_PASSED);
	}

	/*
	 * The packet matches a rule, use the rule load balance algorithm
	 * to find a server.
	 */
	balanced = rule->ir_alg->ilb_alg_lb(src, sport, dst, dport,
	    rule->ir_alg->ilb_alg_data, &server);
	/*
	 * This can only happen if there is no server in a rule or all
	 * the servers are currently disabled.
	 */
	if (!balanced)
		goto no_server;

	/*
	 * If the rule is sticky enabled, we need to check the sticky table.
	 * If there is a sticky entry for the client, use the previous server
	 * instead of the one found above (note that both can be the same).
	 * If there is no entry for that client, add an entry to the sticky
	 * table.  Both the find and add are done in ilb_sticky_find_add()
	 * to avoid checking for duplicate when adding an entry.
	 */
	if (rule->ir_flags & ILB_RULE_STICKY) {
		in6_addr_t addr;

		V6_MASK_COPY(*src, rule->ir_sticky_mask, addr);
		if ((server = ilb_sticky_find_add(ilbs, rule, &addr, server,
		    &s, &nat_src_idx)) == NULL) {
			ILB_R_KSTAT(rule, nomem_pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, nomem_bytes_dropped, pkt_len);
			goto no_server;
		}
	}

	/*
	 * We are holding a reference on the rule, so the server
	 * cannot go away.
	 */
	*lb_dst = server->iser_addr_v6;
	ILB_S_KSTAT(server, pkt_processed);
	ILB_S_KSTAT_UPDATE(server, bytes_processed, pkt_len);

	switch (rule->ir_topo) {
	case ILB_TOPO_IMPL_NAT: {
		ilb_nat_src_entry_t	*src_ent;
		uint16_t		*src_idx;

		/*
		 * We create a cache even if it is not a SYN segment.
		 * The server should return a RST.  When we see the
		 * RST, we will destroy this cache.  But by having
		 * a cache, we know how to NAT the returned RST.
		 */
		info.vip = *dst;
		info.dport = dport;
		info.src = *src;
		info.sport = sport;

		/* If stickiness is enabled, use the same source address */
		if (s != NULL)
			src_idx = &nat_src_idx;
		else
			src_idx = NULL;

		if ((src_ent = ilb_alloc_nat_addr(server->iser_nat_src,
		    &info.nat_src, &info.nat_sport, src_idx)) == NULL) {
			if (s != NULL)
				ilb_sticky_refrele(s);
			ILB_R_KSTAT(rule, pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, bytes_dropped, pkt_len);
			ILB_R_KSTAT(rule, noport_pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, noport_bytes_dropped, pkt_len);
			ret = ILB_DROPPED;
			break;
		}
		info.src_ent = src_ent;
		info.nat_dst = server->iser_addr_v6;
		if (rule->ir_port_range && server->iser_port_range) {
			info.nat_dport = htons(ntohs(dport) -
			    rule->ir_min_port + server->iser_min_port);
		} else {
			info.nat_dport = htons(server->iser_min_port);
		}

		/*
		 * If ilb_conn_add() fails, it will release the reference on
		 * sticky info and de-allocate the NAT source port allocated
		 * above.
		 */
		if (ilb_conn_add(ilbs, rule, server, src, sport, dst,
		    dport, &info, &ip_sum, &tp_sum, s) != 0) {
			ILB_R_KSTAT(rule, pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, bytes_dropped, pkt_len);
			ILB_R_KSTAT(rule, nomem_pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, nomem_bytes_dropped, pkt_len);
			ret = ILB_DROPPED;
			break;
		}
		ilb_full_nat(l3, iph, l4, tph, &info, ip_sum, tp_sum, B_TRUE);
		ret = ILB_BALANCED;
		break;
	}
	case ILB_TOPO_IMPL_HALF_NAT:
		info.vip = *dst;
		info.nat_dst = server->iser_addr_v6;
		info.dport = dport;
		if (rule->ir_port_range && server->iser_port_range) {
			info.nat_dport = htons(ntohs(dport) -
			    rule->ir_min_port + server->iser_min_port);
		} else {
			info.nat_dport = htons(server->iser_min_port);
		}

		if (ilb_conn_add(ilbs, rule, server, src, sport, dst,
		    dport, &info, &ip_sum, &tp_sum, s) != 0) {
			ILB_R_KSTAT(rule, pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, bytes_dropped, pkt_len);
			ILB_R_KSTAT(rule, nomem_pkt_dropped);
			ILB_R_KSTAT_UPDATE(rule, nomem_bytes_dropped, pkt_len);
			ret = ILB_DROPPED;
			break;
		}
		ilb_half_nat(l3, iph, l4, tph, &info, ip_sum, tp_sum, B_TRUE);

		ret = ILB_BALANCED;
		break;
	case ILB_TOPO_IMPL_DSR:
		/*
		 * By decrementing the sticky refcnt, the period of
		 * stickiness (life time of ilb_sticky_t) will be
		 * from now to (now + default expiry time).
		 */
		if (s != NULL)
			ilb_sticky_refrele(s);
		ret = ILB_BALANCED;
		break;
	default:
		cmn_err(CE_PANIC, "data corruption unknown topology: %p",
		    (void *) rule);
		break;
	}
	ILB_RULE_REFRELE(rule);
	return (ret);

no_server:
	/* This can only happen if there is no server available. */
	ILB_R_KSTAT(rule, pkt_dropped);
	ILB_R_KSTAT_UPDATE(rule, bytes_dropped, pkt_len);
	ILB_RULE_REFRELE(rule);
	return (ILB_DROPPED);
}

int
ilb_check_v4(ilb_stack_t *ilbs, ill_t *ill, mblk_t *mp, ipha_t *ipha, int l4,
    uint8_t *tph, ipaddr_t *lb_dst)
{
	in6_addr_t v6_src, v6_dst, v6_lb_dst;
	int ret;

	ASSERT(DB_REF(mp) == 1);

	if (l4 == IPPROTO_ICMP) {
		return (ilb_icmp_v4(ilbs, ill, mp, ipha, (icmph_t *)tph,
		    lb_dst));
	}

	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &v6_src);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &v6_dst);
	ret = ilb_check(ilbs, ill, mp, &v6_src, &v6_dst, IPPROTO_IP, l4, ipha,
	    tph, ntohs(ipha->ipha_length), &v6_lb_dst);
	if (ret == ILB_BALANCED)
		IN6_V4MAPPED_TO_IPADDR(&v6_lb_dst, *lb_dst);
	return (ret);
}

int
ilb_check_v6(ilb_stack_t *ilbs, ill_t *ill, mblk_t *mp, ip6_t *ip6h, int l4,
    uint8_t *tph, in6_addr_t *lb_dst)
{
	uint32_t pkt_len;

	ASSERT(DB_REF(mp) == 1);

	if (l4 == IPPROTO_ICMPV6) {
		return (ilb_icmp_v6(ilbs, ill, mp, ip6h, (icmp6_t *)tph,
		    lb_dst));
	}

	pkt_len = ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN;
	return (ilb_check(ilbs, ill, mp, &ip6h->ip6_src, &ip6h->ip6_dst,
	    IPPROTO_IPV6, l4, ip6h, tph, pkt_len, lb_dst));
}

void
ilb_get_num_rules(ilb_stack_t *ilbs, zoneid_t zoneid, uint32_t *num_rules)
{
	ilb_rule_t *tmp_rule;

	mutex_enter(&ilbs->ilbs_g_lock);
	*num_rules = 0;
	for (tmp_rule = ilbs->ilbs_rule_head; tmp_rule != NULL;
	    tmp_rule = tmp_rule->ir_next) {
		if (tmp_rule->ir_zoneid == zoneid)
			*num_rules += 1;
	}
	mutex_exit(&ilbs->ilbs_g_lock);
}

int
ilb_get_num_servers(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    uint32_t *num_servers)
{
	ilb_rule_t *rule;
	int err;

	if ((rule = ilb_find_rule(ilbs, zoneid, name, &err)) == NULL)
		return (err);
	*num_servers = rule->ir_kstat.num_servers.value.ui64;
	ILB_RULE_REFRELE(rule);
	return (0);
}

int
ilb_get_servers(ilb_stack_t *ilbs, zoneid_t zoneid, const char *name,
    ilb_server_info_t *servers, uint32_t *num_servers)
{
	ilb_rule_t *rule;
	ilb_server_t *server;
	size_t cnt;
	int err;

	if ((rule = ilb_find_rule(ilbs, zoneid, name, &err)) == NULL)
		return (err);
	for (server = rule->ir_servers, cnt = *num_servers;
	    server != NULL && cnt > 0;
	    server = server->iser_next, cnt--, servers++) {
		(void) memcpy(servers->name, server->iser_name,
		    ILB_SERVER_NAMESZ);
		servers->addr = server->iser_addr_v6;
		servers->min_port = htons(server->iser_min_port);
		servers->max_port = htons(server->iser_max_port);
		servers->flags = server->iser_enabled ? ILB_SERVER_ENABLED : 0;
		servers->err = 0;
	}
	ILB_RULE_REFRELE(rule);
	*num_servers -= cnt;

	return (0);
}

void
ilb_get_rulenames(ilb_stack_t *ilbs, zoneid_t zoneid, uint32_t *num_names,
    char *buf)
{
	ilb_rule_t *tmp_rule;
	int cnt;

	if (*num_names == 0)
		return;

	mutex_enter(&ilbs->ilbs_g_lock);
	for (cnt = 0, tmp_rule = ilbs->ilbs_rule_head; tmp_rule != NULL;
	    tmp_rule = tmp_rule->ir_next) {
		if (tmp_rule->ir_zoneid != zoneid)
			continue;

		(void) memcpy(buf, tmp_rule->ir_name, ILB_RULE_NAMESZ);
		buf += ILB_RULE_NAMESZ;
		if (++cnt == *num_names)
			break;
	}
	mutex_exit(&ilbs->ilbs_g_lock);
	*num_names = cnt;
}

int
ilb_rule_list(ilb_stack_t *ilbs, zoneid_t zoneid, ilb_rule_cmd_t *cmd)
{
	ilb_rule_t *rule;
	int err;

	if ((rule = ilb_find_rule(ilbs, zoneid, cmd->name, &err)) == NULL) {
		return (err);
	}

	/*
	 * Except the enabled flags, none of the following will change
	 * in the life time of a rule.  So we don't hold the mutex when
	 * reading them.  The worst is to report a wrong enabled flags.
	 */
	cmd->ip_ver = rule->ir_ipver;
	cmd->proto = rule->ir_proto;
	cmd->min_port = htons(rule->ir_min_port);
	cmd->max_port = htons(rule->ir_max_port);

	cmd->vip = rule->ir_target_v6;
	cmd->algo = rule->ir_alg_type;
	cmd->topo = rule->ir_topo;

	cmd->nat_src_start = rule->ir_nat_src_start;
	cmd->nat_src_end = rule->ir_nat_src_end;

	cmd->conn_drain_timeout = rule->ir_conn_drain_timeout;
	cmd->nat_expiry = rule->ir_nat_expiry;
	cmd->sticky_expiry = rule->ir_sticky_expiry;

	cmd->flags = 0;
	if (rule->ir_flags & ILB_RULE_ENABLED)
		cmd->flags |= ILB_RULE_ENABLED;
	if (rule->ir_flags & ILB_RULE_STICKY) {
		cmd->flags |= ILB_RULE_STICKY;
		cmd->sticky_mask = rule->ir_sticky_mask;
	}

	ILB_RULE_REFRELE(rule);
	return (0);
}

static void *
ilb_stack_init(netstackid_t stackid, netstack_t *ns)
{
	ilb_stack_t *ilbs;
	char tq_name[TASKQ_NAMELEN];

	ilbs = kmem_alloc(sizeof (ilb_stack_t), KM_SLEEP);
	ilbs->ilbs_netstack = ns;

	ilbs->ilbs_rule_head = NULL;
	ilbs->ilbs_g_hash = NULL;
	mutex_init(&ilbs->ilbs_g_lock, NULL, MUTEX_DEFAULT, NULL);

	ilbs->ilbs_kstat = kmem_alloc(sizeof (ilb_g_kstat_t), KM_SLEEP);
	if ((ilbs->ilbs_ksp = ilb_kstat_g_init(stackid, ilbs)) == NULL) {
		kmem_free(ilbs, sizeof (ilb_stack_t));
		return (NULL);
	}

	/*
	 * ilbs_conn/sticky_hash related info is initialized in
	 * ilb_conn/sticky_hash_init().
	 */
	ilbs->ilbs_conn_taskq = NULL;
	ilbs->ilbs_rule_hash_size = ilb_rule_hash_size;
	ilbs->ilbs_conn_hash_size = ilb_conn_hash_size;
	ilbs->ilbs_c2s_conn_hash = NULL;
	ilbs->ilbs_s2c_conn_hash = NULL;
	ilbs->ilbs_conn_timer_list = NULL;

	ilbs->ilbs_sticky_hash = NULL;
	ilbs->ilbs_sticky_hash_size = ilb_sticky_hash_size;
	ilbs->ilbs_sticky_timer_list = NULL;
	ilbs->ilbs_sticky_taskq = NULL;

	/* The allocation is done later when there is a rule using NAT mode. */
	ilbs->ilbs_nat_src = NULL;
	ilbs->ilbs_nat_src_hash_size = ilb_nat_src_hash_size;
	mutex_init(&ilbs->ilbs_nat_src_lock, NULL, MUTEX_DEFAULT, NULL);
	ilbs->ilbs_nat_src_tid = 0;

	/* For listing the conn hash table */
	mutex_init(&ilbs->ilbs_conn_list_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ilbs->ilbs_conn_list_cv, NULL, CV_DEFAULT, NULL);
	ilbs->ilbs_conn_list_busy = B_FALSE;
	ilbs->ilbs_conn_list_cur = 0;
	ilbs->ilbs_conn_list_connp = NULL;

	/* For listing the sticky hash table */
	mutex_init(&ilbs->ilbs_sticky_list_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ilbs->ilbs_sticky_list_cv, NULL, CV_DEFAULT, NULL);
	ilbs->ilbs_sticky_list_busy = B_FALSE;
	ilbs->ilbs_sticky_list_cur = 0;
	ilbs->ilbs_sticky_list_curp = NULL;

	(void) snprintf(tq_name, sizeof (tq_name), "ilb_rule_taskq_%p",
	    (void *)ns);
	ilbs->ilbs_rule_taskq = taskq_create(tq_name, ILB_RULE_TASKQ_NUM_THR,
	    minclsyspri, 1, INT_MAX, TASKQ_PREPOPULATE|TASKQ_DYNAMIC);

	return (ilbs);
}

/* ARGSUSED */
static void
ilb_stack_shutdown(netstackid_t stackid, void *arg)
{
	ilb_stack_t *ilbs = (ilb_stack_t *)arg;
	ilb_rule_t *tmp_rule;

	ilb_sticky_hash_fini(ilbs);
	ilb_conn_hash_fini(ilbs);
	mutex_enter(&ilbs->ilbs_g_lock);
	while ((tmp_rule = ilbs->ilbs_rule_head) != NULL) {
		ilb_rule_hash_del(tmp_rule);
		ilb_rule_g_del(ilbs, tmp_rule);
		mutex_exit(&ilbs->ilbs_g_lock);
		ilb_rule_del_common(ilbs, tmp_rule);
		mutex_enter(&ilbs->ilbs_g_lock);
	}
	mutex_exit(&ilbs->ilbs_g_lock);
	if (ilbs->ilbs_nat_src != NULL)
		ilb_nat_src_fini(ilbs);
}

static void
ilb_stack_fini(netstackid_t stackid, void * arg)
{
	ilb_stack_t *ilbs = (ilb_stack_t *)arg;

	ilb_rule_hash_fini(ilbs);
	taskq_destroy(ilbs->ilbs_rule_taskq);
	ilb_kstat_g_fini(stackid, ilbs);
	kmem_free(ilbs->ilbs_kstat, sizeof (ilb_g_kstat_t));
	kmem_free(ilbs, sizeof (ilb_stack_t));
}

void
ilb_ddi_g_init(void)
{
	netstack_register(NS_ILB, ilb_stack_init, ilb_stack_shutdown,
	    ilb_stack_fini);
}

void
ilb_ddi_g_destroy(void)
{
	netstack_unregister(NS_ILB);
	ilb_conn_cache_fini();
	ilb_sticky_cache_fini();
}
