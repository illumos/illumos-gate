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

#ifndef	_SCTP_ADDR_H
#define	_SCTP_ADDR_H

#include <sys/list.h>
#include <sys/zone.h>
#include <inet/ip.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCTP IPIF structure - only relevant fields from ipif_t retained
 *
 * There is a global array, sctp_g_ipifs, to store all addresses of
 * the system.  Each element of the global array is a list of
 * sctp_ipif_t.
 *
 * This structure is also shared by all SCTP PCBs.  Each SCTP PCB has
 * an array of source addresses.  Each element of that array is a list
 * of sctp_saddr_ipif_t.  And each sctp_saddr_ipif_t has a pointer
 * to a sctp_ipif_t.  The reason for sctp_saddr_ipif_t is that each
 * SCTP PCB may do different things to a source address.  This info
 * is stored locally in sctp_saddr_ipif_t.
 *
 */
typedef struct sctp_ipif_s {
	list_node_t		sctp_ipifs;	/* Used by the global list */
	struct sctp_ill_s	*sctp_ipif_ill;
	uint_t			sctp_ipif_id;
	in6_addr_t		sctp_ipif_saddr;
	int			sctp_ipif_state;
	uint32_t		sctp_ipif_refcnt;
	zoneid_t		sctp_ipif_zoneid;
	krwlock_t		sctp_ipif_lock;
	boolean_t		sctp_ipif_isv6;
	uint64_t		sctp_ipif_flags;
} sctp_ipif_t;

/* ipif_state */
#define	SCTP_IPIFS_CONDEMNED	-1
#define	SCTP_IPIFS_INVALID	-2
#define	SCTP_IPIFS_DOWN		1
#define	SCTP_IPIFS_UP		2

/*
 * Individual SCTP source address structure.
 * saddr_ipifp is the actual pointer to the ipif/address.
 * saddr_ipif_dontsrc is used to mark an address as currently unusable. This
 * would be the case when we have added/deleted an address using sctp_bindx()
 * and are waiting for the ASCONF ACK from the peer to confirm the addition/
 * deletion. Additionally, saddr_ipif_delete_pending is used to specifically
 * indicate that an address delete operation is in progress.
 */
typedef struct sctp_saddrs_ipif_s {
	list_node_t	saddr_ipif;
	sctp_ipif_t 	*saddr_ipifp;
	uint32_t	saddr_ipif_dontsrc : 1,
			saddr_ipif_delete_pending : 1,
			saddr_ipif_unconfirmed : 1,
			pad : 29;
} sctp_saddr_ipif_t;

#define	SCTP_DONT_SRC(sctp_saddr)	\
	((sctp_saddr)->saddr_ipif_dontsrc ||	\
	(sctp_saddr)->saddr_ipif_unconfirmed)


/*
 * SCTP ILL structure - only relevant fields from ill_t retained.
 * This pretty much reflects the ILL<->IPIF relation that IP maintains.
 * At present the only state an ILL can be in is CONDEMNED or not.
 * sctp_ill_ipifcnt gives the number of IPIFs for this ILL,
 * sctp_ill_index is phyint_ifindex in the actual ILL structure (in IP)
 * and sctp_ill_flags is ill_flags from the ILL structure.
 *
 * The comment below (and for other netstack_t references) refers
 * to the fact that we only do netstack_hold in particular cases,
 * such as the references from open streams (ill_t and conn_t's
 * pointers). Internally within IP we rely on IP's ability to cleanup e.g.
 * ire_t's when an ill goes away.
 */
typedef struct sctp_ill_s {
	list_node_t	sctp_ills;
	int		sctp_ill_name_length;
	char		*sctp_ill_name;
	int		sctp_ill_state;
	uint32_t	sctp_ill_ipifcnt;
	uint_t		sctp_ill_index;
	uint64_t	sctp_ill_flags;
	boolean_t	sctp_ill_isv6;
	netstack_t	*sctp_ill_netstack; /* Does not have a netstack_hold */
} sctp_ill_t;

/* ill_state */
#define	SCTP_ILLS_CONDEMNED	-1

#define	SCTP_ILL_HASH	16

typedef struct sctp_ill_hash_s {
	list_t	sctp_ill_list;
	int	ill_count;
} sctp_ill_hash_t;


#define	SCTP_IPIF_REFHOLD(sctp_ipif) {				\
	rw_enter(&(sctp_ipif)->sctp_ipif_lock, RW_WRITER);	\
	(sctp_ipif)->sctp_ipif_refcnt++;			\
	rw_exit(&(sctp_ipif)->sctp_ipif_lock);			\
}

#define	SCTP_IPIF_REFRELE(sctp_ipif) {					\
	rw_enter(&(sctp_ipif)->sctp_ipif_lock, RW_WRITER);		\
	ASSERT((sctp_ipif)->sctp_ipif_refcnt != 0);			\
	if (--(sctp_ipif)->sctp_ipif_refcnt == 0 && 			\
	    (sctp_ipif)->sctp_ipif_state == SCTP_IPIFS_CONDEMNED) {	\
		rw_exit(&(sctp_ipif)->sctp_ipif_lock);			\
		sctp_ipif_inactive(sctp_ipif);				\
	} else {							\
		rw_exit(&(sctp_ipif)->sctp_ipif_lock);			\
	}								\
}

/* Address set comparison results. */
#define	SCTP_ADDR_EQUAL		1
#define	SCTP_ADDR_SUBSET	2
#define	SCTP_ADDR_OVERLAP	3
#define	SCTP_ADDR_DISJOINT	4

extern int		sctp_valid_addr_list(sctp_t *, const void *, uint32_t,
			    uchar_t *, size_t);
extern int		sctp_dup_saddrs(sctp_t *, sctp_t *, int);
extern int		sctp_compare_saddrs(sctp_t *, sctp_t *);
extern sctp_saddr_ipif_t	*sctp_saddr_lookup(sctp_t *, in6_addr_t *,
				    uint_t);
extern in6_addr_t	sctp_get_valid_addr(sctp_t *, boolean_t, boolean_t *);
extern size_t		sctp_saddr_info(sctp_t *, int, uchar_t *, boolean_t);
extern void		sctp_del_saddr_list(sctp_t *, const void *, int,
			    boolean_t);
extern void		sctp_del_saddr(sctp_t *, sctp_saddr_ipif_t *);
extern void		sctp_free_saddrs(sctp_t *);
extern void		sctp_saddr_init(sctp_stack_t *);
extern void		sctp_saddr_fini(sctp_stack_t *);
extern int		sctp_getmyaddrs(void *, void *, int *);
extern int		sctp_saddr_add_addr(sctp_t *, in6_addr_t *, uint_t);
extern void		sctp_check_saddr(sctp_t *, int, boolean_t,
			    in6_addr_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SCTP_ADDR_H */
