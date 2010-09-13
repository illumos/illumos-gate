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
#ifndef _INET_ILB_IP_H
#define	_INET_ILB_IP_H

#include <inet/ilb.h>
#include <inet/ilb/ilb_stack.h>
#include <inet/ilb/ilb_impl.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void ilb_ddi_g_init(void);
extern void ilb_ddi_g_destroy(void);

/* Return values of ilb_check_*() */
#define	ILB_DROPPED	1	/* Caller should drop the packet. */
#define	ILB_PASSED	2	/* No load balanced rule is matched. */
#define	ILB_BALANCED	3	/* A rule is matached. */

extern boolean_t ilb_has_rules(ilb_stack_t *);

extern int ilb_check_v4(ilb_stack_t *, ill_t *, mblk_t *, ipha_t *, int,
    uint8_t *, ipaddr_t *);
extern int ilb_check_v6(ilb_stack_t *, ill_t *, mblk_t *, ip6_t *, int,
    uint8_t *, in6_addr_t *);
extern boolean_t ilb_rule_match_vip_v4(ilb_stack_t *, ipaddr_t, ilb_rule_t **);
extern boolean_t ilb_rule_match_vip_v6(ilb_stack_t *, in6_addr_t *,
    ilb_rule_t **);

extern int ip_sioctl_ilb_cmd(ipif_t *, sin_t *, queue_t *, mblk_t *,
    ip_ioctl_cmd_t *, void *);

extern int ilb_rule_add(ilb_stack_t *, zoneid_t, const ilb_rule_cmd_t *);
extern int ilb_rule_del(ilb_stack_t *, zoneid_t, const char *);
extern void ilb_rule_del_all(ilb_stack_t *, zoneid_t);
extern int ilb_rule_enable(ilb_stack_t *, zoneid_t, const char *,
    ilb_rule_t *);
extern void ilb_rule_enable_all(ilb_stack_t *, zoneid_t);
extern int ilb_rule_disable(ilb_stack_t *, zoneid_t, const char *,
    ilb_rule_t *);
extern void ilb_rule_disable_all(ilb_stack_t *, zoneid_t);
extern int ilb_rule_list(ilb_stack_t *, zoneid_t, ilb_rule_cmd_t *);

extern void ilb_get_num_rules(ilb_stack_t *, zoneid_t, uint32_t *);
extern int ilb_get_num_servers(ilb_stack_t *, zoneid_t, const char *,
    uint32_t *);
extern ilb_rule_t *ilb_find_rule(ilb_stack_t *, zoneid_t, const char *, int *);
extern void ilb_get_rulenames(ilb_stack_t *, zoneid_t, uint32_t *,
    char *);
extern int ilb_get_servers(ilb_stack_t *, zoneid_t, const char *,
    ilb_server_info_t *, uint32_t *);

extern int ilb_server_add(ilb_stack_t *, ilb_rule_t *, ilb_server_info_t *);
extern int ilb_server_del(ilb_stack_t *, zoneid_t, const char *,
    ilb_rule_t *, in6_addr_t *);
extern int ilb_server_enable(ilb_stack_t *, zoneid_t, const char *,
    ilb_rule_t *, in6_addr_t *);
extern int ilb_server_disable(ilb_stack_t *, zoneid_t, const char *,
    ilb_rule_t *, in6_addr_t *);

extern int ilb_list_nat(ilb_stack_t *, zoneid_t, ilb_nat_entry_t *,
    uint32_t *, uint32_t *);
extern int ilb_list_sticky(ilb_stack_t *, zoneid_t, ilb_sticky_entry_t *,
    uint32_t *, uint32_t *);

/* Currently supported transport protocol. */
#define	ILB_SUPP_L4(proto)						\
	((proto) == IPPROTO_TCP || (proto) == IPPROTO_UDP ||		\
	    (proto) == IPPROTO_ICMP || (proto) == IPPROTO_ICMPV6)


#ifdef __cplusplus
}
#endif

#endif /* _INET_ILB_IP_H */
