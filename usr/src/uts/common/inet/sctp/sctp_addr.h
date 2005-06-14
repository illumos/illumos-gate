/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SCTP_ADDR_H
#define	_SCTP_ADDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
	uint_t			sctp_ipif_mtu;
	uint_t			sctp_ipif_id;
	in6_addr_t		sctp_ipif_saddr;
	int			sctp_ipif_state;
	uint32_t		sctp_ipif_refcnt;
	zoneid_t		sctp_ipif_zoneid;
	krwlock_t		sctp_ipif_lock;
	boolean_t		sctp_ipif_isv6;
} sctp_ipif_t;

/* ipif_state */
#define	SCTP_IPIFS_CONDEMNED	-1
#define	SCTP_IPIFS_INVALID	-2
#define	SCTP_IPIFS_DOWN		1
#define	SCTP_IPIFS_UP		2

/* SCTP source address structure for individual SCTP PCB */
typedef struct sctp_saddrs_ipif_s {
	list_node_t	saddr_ipif;
	sctp_ipif_t 	*saddr_ipifp;
	uint32_t	saddr_ipif_dontsrc : 1,
			saddr_ipif_delete_pending : 1,
			pad : 30;
} sctp_saddr_ipif_t;

/* SCTP ILL structure - only relevant fields from ill_t retained */
typedef struct sctp_ill_s {
	list_node_t		sctp_ills;
	int			sctp_ill_name_length;
	char			*sctp_ill_name;
	int			sctp_ill_state;
	uint32_t		sctp_ill_ipifcnt;
	uint_t			sctp_ill_index;
	uint64_t		sctp_ill_flags;
} sctp_ill_t;

/* ill_state */
#define	SCTP_ILLS_CONDEMNED	-1

#define	SCTP_ILL_HASH	16

typedef struct sctp_ill_hash_s {
	list_t	sctp_ill_list;
	int	ill_count;
} sctp_ill_hash_t;

/* Global list of SCTP ILLs */
extern sctp_ill_hash_t	sctp_g_ills[SCTP_ILL_HASH];
krwlock_t		sctp_g_ills_lock;
extern uint32_t		sctp_ills_count;
extern uint32_t		sctp_ills_min_mtu;

/* Global list of SCTP ipifs */
extern	sctp_ipif_hash_t	sctp_g_ipifs[SCTP_IPIF_HASH];
extern	uint32_t		sctp_g_ipifs_count;
krwlock_t			sctp_g_ipifs_lock;


#define	SCTP_IPIF_REFHOLD(sctp_ipif) {				\
	atomic_add_32(&(sctp_ipif)->sctp_ipif_refcnt, 1);	\
	ASSERT((sctp_ipif)->sctp_ipif_refcnt != 0);		\
}

#define	SCTP_IPIF_REFRELE(sctp_ipif) {					\
	ASSERT((sctp_ipif)->sctp_ipif_refcnt != 0);			\
	if (atomic_add_32_nv(&(sctp_ipif)->sctp_ipif_refcnt, -1) == 0)	\
		sctp_ipif_inactive(sctp_ipif);				\
}

/* Address set comparison results. */
#define	SCTP_ADDR_EQUAL		1
#define	SCTP_ADDR_SUBSET	2
#define	SCTP_ADDR_OVERLAP	3
#define	SCTP_ADDR_DISJOINT	4

extern void		sctp_update_ill(ill_t *, int);
extern void		sctp_update_ipif(ipif_t *, int);

extern int		sctp_valid_addr_list(sctp_t *, const void *, uint32_t);
extern int		sctp_dup_saddrs(sctp_t *, sctp_t *, int);
extern int		sctp_compare_saddrs(sctp_t *, sctp_t *);
extern sctp_saddr_ipif_t	*sctp_saddr_lookup(sctp_t *, in6_addr_t *);
extern in6_addr_t	sctp_get_valid_addr(sctp_t *, boolean_t isv6);
extern size_t		sctp_addr_len(sctp_t *, int);
extern size_t		sctp_addr_val(sctp_t *, int, uchar_t *);
extern void		sctp_del_saddr_list(sctp_t *, const void *, int,
			    boolean_t);
extern void		sctp_del_saddr(sctp_t *, sctp_saddr_ipif_t *);
extern void		sctp_free_saddrs(sctp_t *);
extern void		sctp_saddr_init();
extern void		sctp_saddr_fini();
extern sctp_saddr_ipif_t	*sctp_ipif_lookup(sctp_t *, uint_t);
extern int		sctp_getmyaddrs(void *, void *, int *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SCTP_ADDR_H */
