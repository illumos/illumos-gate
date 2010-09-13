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
 * Copyright 2002-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_IPGPC_FILTERS_H
#define	_IPP_IPGPC_FILTERS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <ipp/ipgpc/classifier-objects.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for filter management and configuration of IPGPC module */

#define	NUM_TRIES			6
#define	NUM_BA_TABLES			1
#define	NUM_TABLES			6
#define	TABLE_SIZE			11
#define	IPGPC_DEFAULT_MAX_FILTERS	10007
#define	IPGPC_DEFAULT_MAX_CLASSES	10007

/* Globals */
extern kmutex_t ipgpc_table_list_lock; /* table list lock */
extern kmutex_t ipgpc_fid_list_lock; /* filter id list lock */
extern kmutex_t ipgpc_cid_list_lock; /* class id list lock */
extern trie_id_t ipgpc_trie_list[NUM_TRIES]; /* list of trie structure ids */
extern table_id_t ipgpc_table_list[NUM_TABLES]; /* list of all table ids */
extern ba_table_id_t ipgpc_ds_table_id; /* DiffServ field table id */
extern fid_t *ipgpc_fid_list;	/* filter id list */
extern cid_t *ipgpc_cid_list;	/* class id list */
extern boolean_t ipgpc_gather_stats; /* should stats be performed for ipgpc */
extern uint64_t ipgpc_npackets;	/* number of packets stat */
extern uint64_t ipgpc_nbytes;	/* number of bytes stat */
extern uint64_t ipgpc_epackets;	/* number of pkts in error */
extern int ipgpc_def_class_id;	/* class id of default class */
extern size_t ipgpc_max_filters; /* user tunable, max number of filters */
extern size_t ipgpc_max_classes; /* user tunable, max number of classes */
extern size_t ipgpc_max_num_filters; /* max number of allowable filters */
extern size_t ipgpc_max_num_classes; /* max number of allowable classes */
extern size_t ipgpc_num_fltrs; /* number of loaded filter */
extern size_t ipgpc_num_cls;	/* number of loaded classes */


/*
 * initialization function
 */
extern int ipgpc_initialize(ipp_action_id_t);

/*
 * modify functions
 */
extern int ipgpc_addfilter(ipgpc_filter_t *, char *, ipp_flags_t);
extern int ipgpc_addclass(ipgpc_class_t *, ipp_flags_t);
extern void ipgpc_filter_destructor(ipgpc_filter_t *);
extern int ipgpc_modifyfilter(nvlist_t **, ipp_flags_t);
extern int ipgpc_modifyclass(nvlist_t **, ipp_flags_t);
extern int ipgpc_parse_filter(ipgpc_filter_t *, nvlist_t *);
extern int ipgpc_parse_class(ipgpc_class_t *, nvlist_t *);
extern int ipgpc_removefilter(char *, int32_t, ipp_flags_t);
extern int ipgpc_removeclass(char *, ipp_flags_t);
extern int ipgpc_list_insert(linked_list *, key_t);
extern boolean_t ipgpc_list_remove(linked_list *, key_t);
extern unsigned name_hash(char *, size_t);

/*
 * destroy function
 */
extern void ipgpc_destroy(ipp_flags_t);

/*
 * info functions
 */
extern int ipgpc_params_info(int (*)(nvlist_t *, void *), void *);
extern int ipgpc_classes_info(int (*)(nvlist_t *, void *), void *);
extern int ipgpc_filters_info(int (*)(nvlist_t *, void *), void *);

/*
 * invoke function
 */
extern int ipgpc_findfilters(int, int, ht_match_t *);
extern int ipgpc_findfilters6(int, in6_addr_t, ht_match_t *);
extern int ipgpc_mark_found(uint16_t, linked_list, ht_match_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_FILTERS_H */
