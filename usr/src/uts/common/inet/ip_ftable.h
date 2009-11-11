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

#ifndef _INET_IP_FTABLE_H
#define	_INET_IP_FTABLE_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef 	_KERNEL

#include <net/radix.h>
#include <inet/common.h>
#include <inet/ip.h>

struct rt_entry {
	struct	radix_node rt_nodes[2];	/* tree glue, and other values */
	/*
	 * struct rt_entry must begin with a struct radix_node (or two!)
	 * to a 'struct rt_entry *'
	 */
	struct rt_sockaddr rt_dst;
	/*
	 * multiple routes to same dest/mask via varying gate/ifp are stored
	 * in the rt_irb bucket.
	 */
	irb_t rt_irb;
};

/*
 * vehicle for passing args through rn_walktree
 *
 * The comment below (and for other netstack_t references) refers
 * to the fact that we only do netstack_hold in particular cases,
 * such as the references from open endpoints (ill_t and conn_t's
 * pointers). Internally within IP we rely on IP's ability to cleanup e.g.
 * ire_t's when an ill goes away.
 */
struct rtfuncarg {
	pfv_t rt_func;
	char *rt_arg;
	uint_t rt_match_flags;
	uint_t rt_ire_type;
	ill_t  *rt_ill;
	zoneid_t rt_zoneid;
	ip_stack_t *rt_ipst;   	/* Does not have a netstack_hold */
};
int rtfunc(struct radix_node *, void *);

typedef struct rt_entry rt_t;
typedef struct rtfuncarg rtf_t;

struct ts_label_s;
extern	void ire_delete_host_redirects(ipaddr_t, ip_stack_t *);
extern irb_t	*ire_get_bucket(ire_t *);
extern uint_t ifindex_lookup(const struct sockaddr *, zoneid_t);
extern int ipfil_sendpkt(const struct sockaddr *, mblk_t *, uint_t, zoneid_t);

extern void  irb_refhold_rn(struct radix_node *);
extern void  irb_refrele_rn(struct radix_node *);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_FTABLE_H */
