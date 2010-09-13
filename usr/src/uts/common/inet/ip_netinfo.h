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

#ifndef	_INET_IP_NETINFO_H
#define	_INET_IP_NETINFO_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

extern ddi_taskq_t *eventq_queue_nic;

extern void ip_net_g_init();
extern void ip_net_g_destroy();
extern void ip_net_init(ip_stack_t *, netstack_t *);
extern void ip_net_destroy(ip_stack_t *);
extern void ipv4_hook_init(ip_stack_t *);
extern void ipv6_hook_init(ip_stack_t *);
extern void arp_hook_init(ip_stack_t *);
extern void ipv4_hook_destroy(ip_stack_t *);
extern void ipv6_hook_destroy(ip_stack_t *);
extern void arp_hook_destroy(ip_stack_t *);
extern void ipv4_hook_shutdown(ip_stack_t *);
extern void ipv6_hook_shutdown(ip_stack_t *);
extern void arp_hook_shutdown(ip_stack_t *);
extern void ip_ne_queue_func(void *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP_NETINFO_H */
