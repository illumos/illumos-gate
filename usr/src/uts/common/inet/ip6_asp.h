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

#ifndef	_INET_IP6_ASP_H
#define	_INET_IP6_ASP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <netinet/in.h>
#include <sys/types.h>
#include <inet/ip6.h>

/*
 * The maximum size of the label, including NULL bytes following the
 * label string.  The implementation assumes that this value is 16.
 */
#define	IP6_ASP_MAXLABELSIZE	16

typedef struct ip6_asp {
	in6_addr_t	ip6_asp_prefix;
	in6_addr_t	ip6_asp_mask;
	/*
	 * ip6_asp_label must be on an 8 byte boundary because we cast
	 * them as (int64_t *) in order to compare them as two 64 bit
	 * integers rather than sixteen characters.
	 */
	union {
		char	iau_label_c[IP6_ASP_MAXLABELSIZE];
		int64_t	iau_label_i[IP6_ASP_MAXLABELSIZE / sizeof (int64_t)];
	} ip6_asp_u;
	uint32_t	ip6_asp_precedence;
} ip6_asp_t;
#define	ip6_asp_label	ip6_asp_u.iau_label_c

#if defined(_SYSCALL32) && _LONG_LONG_ALIGNMENT_32 == 4

/*
 * The ip6_asp structure as seen by a 64-bit kernel looking
 * at a 32-bit process, where the 32-bit process uses 32-bit
 * alignment for 64-bit quantities.  Like i386 does :-)
 */
typedef struct ip6_asp32 {
	in6_addr_t	ip6_asp_prefix;
	in6_addr_t	ip6_asp_mask;
	union {
		char	iau_label_c[IP6_ASP_MAXLABELSIZE];
		int32_t	iau_label_i[IP6_ASP_MAXLABELSIZE / sizeof (int32_t)];
	} ip6_asp_u;
	uint32_t	ip6_asp_precedence;
} ip6_asp32_t;

#endif	/* _SYSCALL32 && _LONG_LONG_ALIGNMENT_32 == 4 */

#define	IP6_ASP_TABLE_REFHOLD(ipst) {			\
	ipst->ips_ip6_asp_refcnt++;			\
	ASSERT(ipst->ips_ip6_asp_refcnt != 0);		\
}

#define	IP6_ASP_TABLE_REFRELE(ipst)	{		\
	mutex_enter(&ipst->ips_ip6_asp_lock);		\
	ASSERT(ipst->ips_ip6_asp_refcnt != 0);		\
	if (--ipst->ips_ip6_asp_refcnt == 0) {		\
		mutex_exit(&ipst->ips_ip6_asp_lock);	\
		ip6_asp_check_for_updates(ipst);		\
	} else {					\
		mutex_exit(&ipst->ips_ip6_asp_lock);	\
	}						\
}

/*
 * Structure used in the SIOCGDSTINFO request.
 * Used to retrieve information about the given destination
 * address, to be used by the caller to sort a list of
 * potential destination addresses.
 */
struct dstinforeq {
	in6_addr_t	dir_daddr;		/* destination address */
	in6_addr_t	dir_saddr;		/* source address for daddr */
	in6addr_scope_t	dir_dscope;		/* destination scope */
	in6addr_scope_t	dir_sscope;		/* source scope */
	t_uscalar_t	dir_dmactype;		/* dl_mac_type of output inf */
	uint32_t	dir_precedence;		/* destination precedence */
	uint8_t		dir_dreachable : 1,	/* is destination reachable? */
			dir_sdeprecated : 1,	/* is source deprecated? */
			dir_labelmatch: 1,	/* src and dst labels match? */
			dir_padbits : 5;
};

#ifdef _KERNEL

typedef void (*aspfunc_t)(ipsq_t *, queue_t *, mblk_t *, void *);

extern void	ip6_asp_free(ip_stack_t *);
extern void	ip6_asp_init(ip_stack_t *);
extern boolean_t	ip6_asp_can_lookup(ip_stack_t *);
extern void	ip6_asp_table_refrele(ip_stack_t *);
extern char	*ip6_asp_lookup(const in6_addr_t *, uint32_t *, ip_stack_t *);
extern void	ip6_asp_replace(mblk_t *mp, ip6_asp_t *, size_t, boolean_t,
    ip_stack_t *, model_t);
extern int	ip6_asp_get(ip6_asp_t *, size_t, ip_stack_t *);
extern boolean_t	ip6_asp_labelcmp(const char *, const char *);
extern void	ip6_asp_pending_op(queue_t *, mblk_t *, aspfunc_t);

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _INET_IP6_ASP_H */
