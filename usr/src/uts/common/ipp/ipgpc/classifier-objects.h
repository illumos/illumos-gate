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

#ifndef _IPP_IPGPC_CLASSIFIER_OBJECTS_H
#define	_IPP_IPGPC_CLASSIFIER_OBJECTS_H

#include <sys/time.h>
#include <ipp/ipp.h>
#include <ipp/ipgpc/ipgpc.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* common objects and defines used by the ipgpc code base */

/* default wildcard and unspecified value for selectors */
#define	IPGPC_WILDCARD		-1
#define	IPGPC_UNSPECIFIED	0

/* trie id's */
#define	IPGPC_TRIE_SPORTID	0
#define	IPGPC_TRIE_DPORTID	1
#define	IPGPC_TRIE_SADDRID	2
#define	IPGPC_TRIE_DADDRID	3

/*
 * IPv6 trie id's
 * note: tries for SPORT, DPORT are shared between IPv4 and IPv6 filters
 */
#define	IPGPC_TRIE_SADDRID6	4
#define	IPGPC_TRIE_DADDRID6	5

/* ba table id's */
#define	IPGPC_BA_DSID		6

/* table id's */
#define	IPGPC_TABLE_PROTOID	7
#define	IPGPC_TABLE_UID		8
#define	IPGPC_TABLE_PROJID	9
#define	IPGPC_TABLE_IF		10
#define	IPGPC_TABLE_DIR		11
#define	TABLE_ID_OFFSET		IPGPC_TABLE_PROTOID
#define	PROTOID_IDX		(IPGPC_TABLE_PROTOID - TABLE_ID_OFFSET)
#define	UID_IDX			(IPGPC_TABLE_UID - TABLE_ID_OFFSET)
#define	PROJID_IDX		(IPGPC_TABLE_PROJID - TABLE_ID_OFFSET)
#define	IF_IDX			(IPGPC_TABLE_IF - TABLE_ID_OFFSET)
#define	DIR_IDX			(IPGPC_TABLE_DIR - TABLE_ID_OFFSET)

/* Match types for selector searching */
#define	NORMAL_MATCH		0
#define	NO_MATCHES		1
#define	DONTCARE_ONLY_MATCH	2

/* match masks */
#define	PROTO_MASK	0x01
#define	DS_MASK		0x02
#define	SPORT_MASK	0x04
#define	DPORT_MASK	0x08
#define	SADDR_MASK	0x10
#define	DADDR_MASK	0x20
#define	SADDR6_MASK	SADDR_MASK
#define	DADDR6_MASK	DADDR_MASK
#define	UID_MASK	0x40
#define	PROJID_MASK	0x80
#define	IF_MASK		0x100
#define	DIR_MASK	0x200
#define	ALL_MATCH_MASK	(DS_MASK | PROTO_MASK | SADDR_MASK | DADDR_MASK | \
			SPORT_MASK | DPORT_MASK | UID_MASK | PROJID_MASK | \
			IF_MASK | DIR_MASK)

#define	HASH_SIZE    	11	/* default hash table size */

/* used when inserting values into selector structures */
#define	NORMAL_VALUE	0	/* a valid value was insert */
#define	DONTCARE_VALUE	1	/* a dontcare/wildcard value was inserted */

/* filter definition structure */
typedef struct ipgpc_filter_s {
	char filter_name[MAXNAMELEN]; /* null terminated name of filter */

	/* exact match selectors */
	uid_t uid;		/* uid key, value = exact or IPGPC_WILDCARD */
	projid_t projid;	/* project id, " " */
	uint_t if_index;	/* interface index, " " or 0 for wildcard */
	/*
	 * packet direction
	 * value = IPP_LOCAL_IN | IPP_LOCAL_OUT |
	 * IPP_FWD_IN | IPP_FWD_OUT | 0 for wildcard
	 */
	uint32_t direction;
	uint8_t proto;		/* protocol key, exact or 0 for wildcard */

	/* non-exact match selectors */
	uint8_t dsfield;	/* diffserv field key */
	uint8_t dsfield_mask;	/* mask for diffserv field key */
	/* IP Addresses are represented as IPV6 address structures */
	in6_addr_t saddr;	/* source address key */
	in6_addr_t saddr_mask;	/* mask for saddr key */
	char *saddr_hostname;	/* hostname of source address, optional */
	in6_addr_t daddr;	/* destination address key */
	in6_addr_t daddr_mask;	/* mask for daddr key */
	char *daddr_hostname;	/* hostname of destination address, optional */
	uint16_t sport;		/* source port key */
	uint16_t sport_mask;	/* mask for sport key */
	uint16_t dport;		/* destination port key */
	uint16_t dport_mask;	/* mask for dport key */

	/* filter ranking variables */
	uint32_t precedence;		/* precedence value for filter */
	uint32_t priority;		/* filter priority */

	/*
	 * filter_type accepted values =
	 * IPGPC_GENERIC_FLTR | IPGPC_V4_FLTR |
	 * IPGPC_V6_FLTR
	 */
	uint8_t filter_type;
	int32_t filter_instance; /* filter instance number, -1 if unused */
	uint32_t originator;	/* originator of this config item */
	char *filter_comment;	/* optional and unused by ipgpc */
} ipgpc_filter_t;

typedef struct ipgpc_class_stats_s {
	ipp_action_id_t next_action; /* next action id */
	hrtime_t last_match;	/* hrtime value of last match to class */
	uint64_t nbytes;	/* number of matching bytes */
	uint64_t npackets;	/* number of matching packets */
} ipgpc_class_stats_t;

/* linked list Element node structure */
typedef struct element_node_s *linked_list;
typedef struct element_node_s *plink;
typedef struct element_node_s {
	plink next;
	void (*element_ref)(struct element_node_s *);
	void (*element_unref)(struct element_node_s *);
	int id;
	uint32_t element_refcnt;
} element_node_t;

/* trie node structure  */
typedef struct node_s *node_p;
typedef struct node_s {
	linked_list elements;	/* pointer to element list */
	node_p zero;		/* left link */
	node_p one;		/* right link */
	uint32_t val;		/* value of bits covered */
	uint32_t mask;		/* mask of bits covered */
	uint8_t bits;		/* number of bits covered by this node */
	uint8_t pos;		/* starting position of bits covered */
	uint16_t isroot;	/* 1 if is root node, 0 otherwise */
} node_t;
typedef node_p trie;

/* hashtable node structure */
typedef struct ht_node_s *hash_table;
typedef struct ht_node_s *ht_node_p;
typedef struct ht_node_s {
	ht_node_p next;		/* link to next node in chain */
	linked_list elements;	/* elements stored at this node */
	int key;		/* key stored at this node */
	int info;
} ht_node_t;

/* behavior aggregate table element structure */
typedef struct ba_table_element_s {
	linked_list filter_list; /* list of filters */
	uint32_t info;
} ba_table_element_t;

/* behavior aggregate table structure */
typedef struct ba_table_s {
	linked_list masks;	/* list of loaded masks */
	ba_table_element_t masked_values[256]; /* table of masked values */
} ba_table_t;

/* selector information structure */
typedef struct sel_info_s {
	uint16_t  mask;		/* mask for marking  */
	boolean_t dontcareonly;	/* true if only don't cares are loaded */
} sel_info_t;

/* selector statistics structure */
typedef struct sel_stats_s {
	uint32_t num_inserted; /* number of nodes that are not dontcares */
	uint32_t num_dontcare;	/* number of nodes that are dontcares */
} sel_stats_t;

/* identification structure for a trie */
typedef struct trie_id_s {
	trie   trie;		/* pointer to the trie structure */
	krwlock_t rw_lock;	/* lock protecting this trie */
	size_t key_len;		/* length (bits) of the key for a lookup */
	sel_stats_t stats;	/* selector statistics strucutre */
	sel_info_t info;	/* selector info structure */
} trie_id_t;

/* identification structure for a table */
typedef struct table_id_s {
	hash_table table;	/* pointer to the hash table structure */
	int wildcard;		/* wildcard value for this selector */
	sel_stats_t stats;	/* selector statistics strucutre */
	sel_info_t info;	/* selector info structure */
} table_id_t;

/* identification structure for a ba_table */
typedef struct ba_table_id_s {
	ba_table_t table;
	kmutex_t lock;		/* ba table lock */
	sel_info_t info;	/* selector info structure */
	sel_stats_t stats;	/* selector statistics structure */
} ba_table_id_t;

/* class definition structure  */
typedef struct ipgpc_class_s {
	ipp_action_id_t next_action; /* id of action at head of list */
	boolean_t gather_stats;	/* are stats desired? B_TRUE or B_FALSE */
	uint32_t originator;	/* originator of this config item */
	char class_name[MAXNAMELEN]; /* name of classification */
} ipgpc_class_t;

/* filter id association data structure */
typedef struct fid_s {
	int info;		/* 0 if unused, -1 if dirty, 1 if used */
	int class_id;		/* id of class associated with filter */
	uint16_t insert_map;	/* selectors w/ values inserted for this fid */
	ipgpc_filter_t filter;	/* filter structure that this fid describes */
} fid_t;

/* class_id structure */
typedef struct cid_s {
	linked_list filter_list; /* list of filters associated with class */
	int info;		/* 0 if unused, -1 if dirty, 1 if used */
	ipgpc_class_t aclass;	/* the class structure this cid describes */
	ipp_stat_t *cl_stats;	/* kstats structure */
	ipgpc_class_stats_t stats; /* statistics structure for class */
} cid_t;

/* ipp_stat global stats structure */
typedef struct globalstats_s {
	ipp_named_t nfilters;
	ipp_named_t nclasses;
	ipp_named_t nbytes;
	ipp_named_t npackets;
	ipp_named_t epackets;
} globalstats_t;

/* ipp_stat class stats structure */
typedef struct classstats_s {
	ipp_named_t nbytes;
	ipp_named_t npackets;
	ipp_named_t last_match;
} classstats_t;

/* matching hash table element */
typedef struct ht_match_s *ht_chain;
typedef struct ht_match_s {
	ht_chain next;		/* link to next node in chain */
	int key;		/* key stored at this node in the table */
	uint16_t match_map;	/* match map for this id */
} ht_match_t;

extern kmem_cache_t *ht_node_cache;
extern kmem_cache_t *element_node_cache;
extern kmem_cache_t *ht_match_cache;
extern kmem_cache_t *trie_node_cache;

#ifdef	__cplusplus
}
#endif

#endif	/* _IPP_IPGPC_CLASSIFIER_OBJECTS_H */
