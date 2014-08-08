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

#include <sys/atomic.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <ipp/ipp_config.h>
#include <ipp/ipgpc/filters.h>
#include <ipp/ipgpc/trie.h>
#include <ipp/ipgpc/table.h>
#include <ipp/ipgpc/ba_table.h>
#include <ipp/ipgpc/classifier.h>

/* Implementation for filter management and configuration support of ipgpc */

#define	BITLENGTH(x) (sizeof (x) * NBBY)

/* Globals */
kmutex_t ipgpc_table_list_lock; /* table list lock */
kmutex_t ipgpc_fid_list_lock;	/* filter id list lock */
kmutex_t ipgpc_cid_list_lock;	/* class id list lock */
trie_id_t ipgpc_trie_list[NUM_TRIES]; /* list of all trie structures ids */
table_id_t ipgpc_table_list[NUM_TABLES]; /* list of all table ids */
ba_table_id_t ipgpc_ds_table_id;	/* DiffServ field table id */
fid_t *ipgpc_fid_list = NULL;		/* filter id list */
cid_t *ipgpc_cid_list = NULL;		/* class id list */
kmem_cache_t *ht_node_cache = NULL;	/* hashtable cache */
kmem_cache_t *ht_match_cache = NULL;	/* ht_match cache */
kmem_cache_t *trie_node_cache = NULL;	/* trie node cache */
kmem_cache_t *element_node_cache = NULL; /* element node cache */
boolean_t ipgpc_gather_stats;	/* should stats be performed for ipgpc */
uint64_t ipgpc_npackets;	/* number of packets stat */
uint64_t ipgpc_nbytes;		/* number of bytes stat */
uint64_t ipgpc_epackets;	/* number of packets in error */
int ipgpc_def_class_id = -1;	/* class id of default class */
size_t ipgpc_num_fltrs;		/* number of loaded filter */
size_t ipgpc_num_cls;		/* number of loaded classes */
/* max number of allowable filters */
size_t ipgpc_max_num_filters = IPGPC_DEFAULT_MAX_FILTERS;
/* max number of allowable classes */
size_t ipgpc_max_num_classes = IPGPC_DEFAULT_MAX_CLASSES;
size_t ipgpc_max_filters = 0;	/* set in /etc/system */
size_t ipgpc_max_classes = 0;	/* set in /etc/system */
ipp_stat_t *ipgpc_global_stats = NULL; /* global stats structure */

/* Statics */
static trie saddr_trie;		/* IPv4 source address trie */
static trie daddr_trie;		/* IPv4 destination address trie */
static trie sport_trie;		/* source port trie */
static trie dport_trie;		/* destination port trie */
static trie saddr6_trie;	/* IPv6 source address trie */
static trie daddr6_trie;	/* IPv6 destination address trie */
static ht_node_t proto_table[TABLE_SIZE]; /* protocol table */
static ht_node_t uid_table[TABLE_SIZE]; /* IPGPC_UID table */
static ht_node_t projid_table[TABLE_SIZE]; /* IPGPC_PROJID table */
static ht_node_t if_table[TABLE_SIZE]; /* Interface ID table */
static ht_node_t dir_table[TABLE_SIZE]; /* packet direction table */
static ipp_action_id_t ipgpc_aid; /* the action id for ipgpc */

static int global_statinit(void);
static void insert_ipgpc_trie_list_info(int, size_t, trie, uint16_t);
static int initialize_tries(void);
static void insert_ipgpc_table_list_info(int, hash_table, int, uint16_t);
static void initialize_tables(void);
static void initialize_ba_tables(void);
static void element_node_ref(element_node_t *);
static void element_node_unref(element_node_t *);
static int element_node_cache_constructor(void *, void *, int);
static int filter_name2id(unsigned *, char[], int32_t, int);
static int class_name2id(unsigned *, char[], int);
static boolean_t iscontinuousmask(uint32_t, uint8_t);
static void insertfid(int, ipgpc_filter_t *, uint_t);
static void common_addfilter(fid_t *, int);
static void v4_addfilter(fid_t *, int);
static void v6_addfilter(fid_t *, int);
static void reset_dontcare_stats(void);
static int class_statinit(ipgpc_class_t *, int);
static int insertcid(ipgpc_class_t *, int *);
static void common_removefilter(int, fid_t *);
static void v4_removefilter(int, fid_t *);
static void v6_removefilter(int, fid_t *);
static void removecid(int);
static void remove_from_cid_filter_list(int, int);
static void removeclasses(ipp_flags_t);
static void freetriev6nodes(node_t **);
static int ht_match_insert(ht_match_t *, int, uint16_t);
static int update_class_stats(ipp_stat_t *, void *, int);
static int update_global_stats(ipp_stat_t *, void *, int);
static int build_class_nvlist(nvlist_t **, ipgpc_class_t *, boolean_t);
static int build_filter_nvlist(nvlist_t **, ipgpc_filter_t *, char *);


/*
 * Module initialization code
 */

/*
 * global_statinit()
 *
 * initializes global stats for ipgpc action module.
 * global include:
 * - number of filters loaded
 * - number of classes loaded
 * - number of packets that have passed through ipgpc since action create
 * - number of bytes that have passed through ipgpc since action create
 * if ipp_stat_create fails, an error code is returned
 * if ipp_stat_named_init fails, an error code is returned
 * 0 is returned on success
 */
static int
global_statinit(void)
{
	int rc;
	globalstats_t *gblsnames = NULL;

	/* create stat structure */
	if ((rc = ipp_stat_create(ipgpc_aid, "ipgpc_global_stats", 5,
	    update_global_stats, NULL, &ipgpc_global_stats)) != 0) {
		ipgpc0dbg(("global_statinit: error creating ipp_stat entry"));
		return (rc);
	}

	ASSERT(ipgpc_global_stats != NULL);
	gblsnames = (globalstats_t *)ipgpc_global_stats->ipps_data;
	ASSERT(gblsnames != NULL);

	/* add stat name entries */
	if ((rc = ipp_stat_named_init(ipgpc_global_stats, "nfilters",
	    IPP_STAT_UINT32, &gblsnames->nfilters)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipgpc_global_stats, "nclasses",
	    IPP_STAT_UINT32, &gblsnames->nclasses)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipgpc_global_stats, "nbytes",
	    IPP_STAT_UINT64, &gblsnames->nbytes)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipgpc_global_stats, "npackets",
	    IPP_STAT_UINT64, &gblsnames->npackets)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipgpc_global_stats, "epackets",
	    IPP_STAT_UINT64, &gblsnames->epackets)) != 0) {
		return (rc);
	}
	ipp_stat_install(ipgpc_global_stats);
	return (0);
}

static void
insert_ipgpc_trie_list_info(int trie_id, size_t key_len, trie in_trie,
    uint16_t mask)
{
	ipgpc_trie_list[trie_id].trie = in_trie;
	rw_init(&ipgpc_trie_list[trie_id].rw_lock, NULL, RW_DEFAULT, NULL);
	ipgpc_trie_list[trie_id].key_len = key_len;
	ipgpc_trie_list[trie_id].info.mask = mask;
	ipgpc_trie_list[trie_id].info.dontcareonly = B_TRUE;
}

static int
initialize_tries(void)
{
	/* IPv4 Source Address field structure */
	if ((saddr_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	saddr_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_SADDRID, IP_ABITS, saddr_trie,
	    SADDR_MASK);
	/* IPv4 Destination Address field structure */
	if ((daddr_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	daddr_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_DADDRID, IP_ABITS, daddr_trie,
	    DADDR_MASK);
	/* TCP Source Port field structure */
	if ((sport_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	sport_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_SPORTID, BITLENGTH(uint16_t),
	    sport_trie, SPORT_MASK);
	/* TCP Destination Port field structure */
	if ((dport_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	dport_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_DPORTID, BITLENGTH(uint16_t),
	    dport_trie, DPORT_MASK);
	/* IPv6 Source Address field structure */
	if ((saddr6_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	saddr6_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_SADDRID6, IPV6_ABITS,
	    saddr6_trie, SADDR6_MASK);
	/* IPv6 Destination Address field structure */
	if ((daddr6_trie = create_node(KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	daddr6_trie->isroot = 1;
	insert_ipgpc_trie_list_info(IPGPC_TRIE_DADDRID6, IPV6_ABITS,
	    daddr6_trie, DADDR6_MASK);
	return (0);
}

static void
insert_ipgpc_table_list_info(int table_id, hash_table table, int wildcard,
    uint16_t mask)
{
	ipgpc_table_list[table_id].table = table;
	ipgpc_table_list[table_id].wildcard = wildcard;
	ipgpc_table_list[table_id].info.mask = mask;
	ipgpc_table_list[table_id].info.dontcareonly = B_TRUE;
}
static void
initialize_tables(void)
{
	/* Protocol selector structure */
	insert_ipgpc_table_list_info(PROTOID_IDX, proto_table,
	    IPGPC_UNSPECIFIED, PROTO_MASK);
	/* UID selector structure */
	insert_ipgpc_table_list_info(UID_IDX, uid_table, IPGPC_WILDCARD,
	    UID_MASK);
	/* PROJID selector structure */
	insert_ipgpc_table_list_info(PROJID_IDX, projid_table, IPGPC_WILDCARD,
	    PROJID_MASK);
	/* IF_INDEX selector structure */
	insert_ipgpc_table_list_info(IF_IDX, if_table, IPGPC_UNSPECIFIED,
	    IF_MASK);
	/* DIR selector structure */
	insert_ipgpc_table_list_info(DIR_IDX, dir_table, IPGPC_UNSPECIFIED,
	    DIR_MASK);
}

static void
initialize_ba_tables(void)
{
	/* DS (ToS/Traffic Class) field structure */
	ipgpc_ds_table_id.info.mask = DS_MASK;
	ipgpc_ds_table_id.info.dontcareonly = B_TRUE;
}

static void
element_node_ref(element_node_t *element)
{
	atomic_inc_32(&element->element_refcnt);
	ASSERT(element->element_refcnt > 1);
}

static void
element_node_unref(element_node_t *element)
{
	ASSERT(element->element_refcnt > 0);
	if (atomic_dec_32_nv(&element->element_refcnt) == 0) {
		kmem_cache_free(element_node_cache, element);
	}
}

/* ARGSUSED1 */
static int
element_node_cache_constructor(void *buf, void *cdrarg, int kmflags)
{
	element_node_t *node = buf;

	node->element_ref = element_node_ref;
	node->element_unref = element_node_unref;
	return (0);
}

/* prime values to be used for hashing of filter and class tables */
#define	IPGPC_PRIMES()	{0, 0, 0, 5, 11, 23, 47, 89, 191, 383, 503, 761, \
			1009, 1531, 2003, 2503, 3067, 3511, 4001, 5003, 6143, \
			10007, 12281, 15013, 20011, 24571, 49139, 98299, \
			100003, 196597, 393209, 786431, 1000003, 1251409, \
			1572853, 3145721, 0}

/*
 * ipgpc_initialize(in_aid)
 *
 * initializes locks, data structures, configuration variables used and
 * sets globals.  Will fail on memory or initialization error.
 */
int
ipgpc_initialize(ipp_action_id_t in_aid)
{
	ipgpc_class_t def_class;
	int i;
	int rc;
	int sizes[] = IPGPC_PRIMES();

	/* initialize globals */
	ipgpc_aid = in_aid;	/* store away action id for ipgpc */
	ipgpc_num_fltrs = 0;
	ipgpc_num_cls = 0;
	ipgpc_npackets = 0;
	ipgpc_nbytes = 0;
	ipgpc_epackets = 0;

	/* check for user tunable maximums (set in /etc/system) */
	if (ipgpc_max_filters > 0) {
		/* start with a reasonably small value to find closest prime */
		for (i = 3; i < sizeof (sizes) / sizeof (*sizes) - 1; ++i) {
			if (sizes[i] >= ipgpc_max_filters) {
				break;
			}
		}
		if (sizes[i] == 0) {
			ipgpc0dbg(("ipgpc_initialize: ipgpc_max_filters " \
			    "out of range"));
			/* use the largest allowable value */
			ipgpc_max_num_filters = sizes[(i - 1)];
		} else {
			ipgpc_max_num_filters = sizes[i];
		}
	}
	if (ipgpc_max_classes > 0) {
		/* start with a reasonably small value to find closest prime */
		for (i = 3; i < sizeof (sizes) / sizeof (*sizes) - 1; ++i) {
			if (sizes[i] >= ipgpc_max_classes) {
				break;
			}
		}
		if (sizes[i] == 0) {
			ipgpc0dbg(("ipgpc_initialize: ipgpc_max_classes " \
			    "out of range"));
			/* use the largest allowable value */
			ipgpc_max_num_classes = sizes[(i - 1)];
		} else {
			ipgpc_max_num_classes = sizes[i];
		}
	}

	/* create filter id list */
	ipgpc_fid_list =
	    kmem_zalloc(sizeof (fid_t) * ipgpc_max_num_filters, KM_NOSLEEP);
	if (ipgpc_fid_list == NULL) {
		ipgpc0dbg(("ipgpc_initialize: failed to create fid list"));
		return (ENOMEM);
	}

	/* create class id list */
	ipgpc_cid_list = kmem_zalloc(sizeof (cid_t) * ipgpc_max_num_classes,
	    KM_NOSLEEP);
	if (ipgpc_cid_list == NULL) {
		ipgpc0dbg(("ipgpc_initialize: failed to create cid list"));
		return (ENOMEM);
	}

	/* create object caches */
	element_node_cache = kmem_cache_create("element_node_cache",
	    sizeof (element_node_t), 0, element_node_cache_constructor,
	    NULL, NULL, NULL, NULL, 0);
	trie_node_cache = kmem_cache_create("trie_node_cache",
	    sizeof (node_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	ht_node_cache = kmem_cache_create("ht_node_cache",
	    sizeof (ht_node_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	ht_match_cache = kmem_cache_create("ht_match_cache",
	    sizeof (ht_match_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	/* initialize tries, catch memory errors */
	if ((rc = initialize_tries()) != 0) {
		return (rc);
	}

	initialize_tables();	/* no memory is allocated here */
	initialize_ba_tables();	/* no memory is allocated here */

	if ((rc = global_statinit()) != 0) { /* init global stats */
		ipgpc0dbg(("ipgpc_initialize: global_statinit error " \
		    "%d", rc));
		return (rc);
	}

	/* create default class */
	bzero(&def_class, sizeof (ipgpc_class_t));
	def_class.next_action = IPP_ACTION_CONT;
	def_class.gather_stats = B_FALSE; /* don't gather stats by default */
	(void) strcpy(def_class.class_name, "default");
	def_class.originator = IPP_CONFIG_PERMANENT; /* label as permanent */

	/* add default class and record default class id */
	if ((rc = insertcid(&def_class, &ipgpc_def_class_id)) != ENOENT) {
		ipgpc0dbg(("ipgpc_initialize: insert of default class failed" \
		    " with error %d", rc));
		return (rc);
	}
	return (0);
}

/*
 * Module modify code
 */

/*
 * name_hash(name, M)
 *
 * hash function for a string (name) of lenght M
 */
unsigned
name_hash(char *name, size_t M)
{
	unsigned h;

	for (h = 0; *name != '\0'; name++) {
		h = ((64 * h) + *name);
	}
	return ((h % M));
}


/*
 * ipgpc_filter_destructor(filter)
 *
 * frees any allocated memory pointed to in the filter structure
 * this function should be run before freeing an ipgpc_filter_t
 */
void
ipgpc_filter_destructor(ipgpc_filter_t *filter)
{
	if (filter->filter_comment != NULL) {
		kmem_free(filter->filter_comment,
		    (strlen(filter->filter_comment) + 1));
	}
	if (filter->saddr_hostname != NULL) {
		kmem_free(filter->saddr_hostname,
		    (strlen(filter->saddr_hostname) + 1));
	}
	if (filter->daddr_hostname != NULL) {
		kmem_free(filter->daddr_hostname,
		    (strlen(filter->daddr_hostname) + 1));
	}
}

/*
 * filter_name2id(*out_id, name, filter_instance, in_num_filters)
 *
 * looks up name and instance in filter id table
 * checks in_num_filters against max filter boundary
 * if found, returns EEXIST and places the id in out_id
 * if not found, returns ENOENT and places the new id in out_id
 * if no additional filter ids are available, ENOMEM is returned
 */
static int
filter_name2id(unsigned *out_id, char name[], int32_t filter_instance,
    int in_num_filters)
{
	unsigned h;
	int dirty = -1;		/* set dirty to not found */

	if (in_num_filters >= ipgpc_max_num_filters) {
		return (ENOSPC); /* will exceed maximum number of filters */
	}

	/*
	 * search until fid w/ matching name is found or clean space is found
	 * if clean space is found, return first dirty space found or if
	 * none werer found, return clean space
	 */
	h = name_hash(name, ipgpc_max_num_filters);
	while ((ipgpc_fid_list[h].info != 0) &&
	    ((ipgpc_fid_list[h].filter.filter_instance != filter_instance) ||
	    (strcmp(name, ipgpc_fid_list[h].filter.filter_name) != 0))) {
		if (dirty == -1) { /* this is the first dirty space */
			if (ipgpc_fid_list[h].info == -1) { /* dirty */
				dirty = h;
			}
		}
		h = (h + 1) % ipgpc_max_num_filters;
	}
	/*
	 * check to see if searching stopped because a clean spot was found
	 * and a dirty space was seen before
	 */
	if ((dirty != -1) && (ipgpc_fid_list[h].info == 0)) {
		*out_id = dirty;
		return (ENOENT); /* name does not exist in table */
	} else if (ipgpc_fid_list[h].info == 0) {
		*out_id = h;
		return (ENOENT); /* name does not exist in table */
	} else {
		*out_id = h;
		if (ipgpc_fid_list[h].info == -1) {
			return (ENOENT);
		} else {
			return (EEXIST); /* name exists in table */
		}
	}
}

/*
 * class_name2id(*out_id, name, in_num_classes)
 *
 * looks up name in class id table
 * checks in_num_classes against max class boundry
 * if found, returns EEXIST and places the id in out_id
 * if not found, returns ENOENT and places the new id in out_id
 * if no additional class ids are available, ENOSPC is returned
 */
static int
class_name2id(unsigned *out_id, char name[], int in_num_classes)
{
	unsigned h;
	int dirty = -1;		/* set dirty to not found */

	if (in_num_classes >= ipgpc_max_num_classes) {
		return (ENOSPC); /* will exceed maximum number of classes */
	}

	/*
	 * search until cid w/ matching name is found or clean space is found
	 * if clean space is found, return first dirty space found or if
	 * none were found, return clean space
	 */
	h = name_hash(name, ipgpc_max_num_classes);
	while ((ipgpc_cid_list[h].info != 0) &&
	    (strcmp(name, ipgpc_cid_list[h].aclass.class_name) != 0)) {
		if (dirty == -1) { /* this is the first dirty space */
			if (ipgpc_cid_list[h].info == -1) { /* dirty */
				dirty = h;
			}
		}
		h = (h + 1) % ipgpc_max_num_classes;
	}
	/*
	 * check to see if searching stopped because a clean spot was found
	 * and a dirty space was seen before
	 */
	if ((dirty != -1) && (ipgpc_cid_list[h].info == 0)) {
		*out_id = dirty;
		return (ENOENT); /* name does not exist in table */
	} else if (ipgpc_cid_list[h].info == 0) {
		*out_id = h;
		return (ENOENT); /* name does not exist in table */
	} else {
		*out_id = h;
		if (ipgpc_cid_list[h].info == -1) { /* name did exist */
			return (ENOENT); /* name does not exist in table */
		} else {
			return (EEXIST); /* name exists in table */
		}
	}
}

/*
 * ipgpc_parse_filter(filter, nvlp)
 *
 * given a name value pair list, a filter structure is parsed.  A valid
 * filter must have a filter_name and originator id.  Any value that is not
 * present, will be given the default wildcard value for that selector
 */
int
ipgpc_parse_filter(ipgpc_filter_t *filter, nvlist_t *nvlp)
{
	uint_t nelem = 4;	/* an IPv6 address is an uint32_t array[4] */
	uint32_t *mask;
	uint32_t *addr;
	char *s;
	int i;
	in6_addr_t zeroaddr = IN6ADDR_ANY_INIT;

	/* parse filter name */
	if (nvlist_lookup_string(nvlp, CLASSIFIER_FILTER_NAME, &s) != 0) {
		return (EINVAL); /* filter name is missing, error */
	}

	/* parse originator */
	if (nvlist_lookup_uint32(nvlp, IPP_CONFIG_ORIGINATOR,
	    &filter->originator) != 0) {
		ipgpc0dbg(("ipgpc_parse_filter: originator missing"));
		return (EINVAL);
	}

	/* check for max name length */
	if ((strlen(s) + 1) > MAXNAMELEN) {
		ipgpc0dbg(("ipgpc_parse_filter: filter name length > " \
		    "MAXNAMELEN"));
		return (EINVAL);
	}

	bcopy(s, filter->filter_name, (strlen(s) + 1));

	/* parse uid */
	if (nvlist_lookup_uint32(nvlp, IPGPC_UID, &filter->uid) != 0) {
		filter->uid = (uid_t)IPGPC_WILDCARD;
	}

	/* parse projid */
	if (nvlist_lookup_int32(nvlp, IPGPC_PROJID, &filter->projid) != 0) {
		filter->projid = IPGPC_WILDCARD;
	}

	/* parse if_index */
	if (nvlist_lookup_uint32(nvlp, IPGPC_IF_INDEX, &filter->if_index)
	    != 0) {
		filter->if_index = 0;
	}

	/* parse direction */
	if (nvlist_lookup_uint32(nvlp, IPGPC_DIR, &filter->direction) != 0) {
		filter->direction = 0;
	}

	/* parse proto */
	if (nvlist_lookup_byte(nvlp, IPGPC_PROTO, &filter->proto) != 0) {
		filter->proto = 0;
	}

	/*
	 * parse dsfield mask, if mask is present and dsfield value is not,
	 * then this is an invalid filter configuration
	 */
	if (nvlist_lookup_byte(nvlp, IPGPC_DSFIELD_MASK, &filter->dsfield_mask)
	    == 0) {
		/* parse dsfield */
		if (nvlist_lookup_byte(nvlp, IPGPC_DSFIELD, &filter->dsfield)
		    != 0) {
			ipgpc0dbg(("ipgpc_parse_filter: dsfield missing" \
			    " when dsfield_mask 0x%x is present",
			    filter->dsfield_mask));
			return (EINVAL);
		}
	} else {
		filter->dsfield_mask = 0;
		/* check to see if user added dsfield, but not dsfield_mask */
		if (nvlist_lookup_byte(nvlp, IPGPC_DSFIELD, &filter->dsfield)
		    == 0) {
			ipgpc0dbg(("ipgpc_parse_filter: dsfield_mask missing" \
			    " when dsfield 0x%x is present",
			    filter->dsfield));
			return (EINVAL);
		}
		filter->dsfield = 0;
	}

	/* parse source port */
	if (nvlist_lookup_uint16(nvlp, IPGPC_SPORT, &filter->sport) != 0) {
		filter->sport = 0;
	}

	/*
	 * parse source port mask, mask and value must be present, or neither
	 */
	if (nvlist_lookup_uint16(nvlp, IPGPC_SPORT_MASK, &filter->sport_mask)
	    != 0) {
		if (filter->sport != 0) {
			ipgpc0dbg(("ipgpc_parse_filter: sport_mask missing " \
			    "to mask sport %u", filter->sport));
			return (EINVAL);
		}
		filter->sport_mask = 0;
	} else {		/* sport mask is present */
		if (filter->sport == 0) {
			ipgpc0dbg(("ipgpc_parse_filter: sport missing " \
			    "when sport_mask %u is present",
			    filter->sport_mask));
			return (EINVAL);
		}
	}

	/* check for non-continuous mask */
	if (!iscontinuousmask(filter->sport_mask, BITLENGTH(uint16_t))) {
		ipgpc0dbg(("ipgpc_parse_filter: sport_mask is " \
		    "non-continuous"));
		return (EINVAL);
	}

	/* parse destination port */
	if (nvlist_lookup_uint16(nvlp, IPGPC_DPORT, &filter->dport) != 0) {
		filter->dport = 0;
	}

	/*
	 * parse destination port mask, mask and value must be present,
	 * or neither
	 */
	if (nvlist_lookup_uint16(nvlp, IPGPC_DPORT_MASK, &filter->dport_mask)
	    != 0) {
		if (filter->dport != 0) {
			ipgpc0dbg(("ipgpc_parse_filter: dport_mask missing " \
			    "to mask dport %u", filter->dport));
			return (EINVAL);
		}
		filter->dport_mask = 0;
	} else {		/* dport mask is present */
		if (filter->dport == 0) {
			ipgpc0dbg(("ipgpc_parse_filter: dport missing " \
			    "when dport_mask %u is present",
			    filter->dport_mask));
			return (EINVAL);
		}
	}

	/* check for non-continuous mask */
	if (!iscontinuousmask(filter->dport_mask, BITLENGTH(uint16_t))) {
		ipgpc0dbg(("ipgpc_parse_filter: dport_mask is " \
		    "non-continuous"));
		return (EINVAL);
	}

	/* parse precedence */
	if (nvlist_lookup_uint32(nvlp, IPGPC_PRECEDENCE, &filter->precedence)
	    != 0) {
		filter->precedence = UINT_MAX; /* worst precedence */
	}

	/* parse priority */
	if (nvlist_lookup_uint32(nvlp, IPGPC_PRIORITY, &filter->priority)
	    != 0) {
		filter->priority = 0; /* worst priority */
	}

	/* parse filter type */
	if (nvlist_lookup_byte(nvlp, IPGPC_FILTER_TYPE, &filter->filter_type)
	    != 0) {
		filter->filter_type = IPGPC_GENERIC_FLTR;
	}

	/* parse filter instance */
	if (nvlist_lookup_int32(nvlp, IPGPC_FILTER_INSTANCE,
	    &filter->filter_instance) != 0) {
		filter->filter_instance = -1;
	}

	/* parse filter private field */
	if (nvlist_lookup_string(nvlp, IPGPC_FILTER_PRIVATE, &s) != 0) {
		filter->filter_comment = NULL;
	} else {
		filter->filter_comment = kmem_alloc((strlen(s) + 1), KM_SLEEP);
		(void) strcpy(filter->filter_comment, s);
	}

	/*
	 * parse source address mask, if address is present, mask must be
	 * present
	 */
	if (nvlist_lookup_uint32_array(nvlp, IPGPC_SADDR_MASK, &mask, &nelem)
	    != 0) {
		/* check if source address is present */
		if (nvlist_lookup_uint32_array(nvlp, IPGPC_SADDR, &addr,
		    &nelem) == 0) {
			ipgpc0dbg(("ipgpc_parse_filter: source address mask " \
			    "missing"));
			return (EINVAL);
		} else {	/* both saddr and saddr_mask absent */
			bcopy(zeroaddr.s6_addr32, filter->saddr.s6_addr32,
			    sizeof (filter->saddr.s6_addr32));
		}
		bcopy(zeroaddr.s6_addr32, filter->saddr_mask.s6_addr32,
		    sizeof (filter->saddr_mask.s6_addr32));
	} else {		/* saddr_mask present */
		/* parse source address */
		if (nvlist_lookup_uint32_array(nvlp, IPGPC_SADDR, &addr,
		    &nelem) != 0) {
			ipgpc0dbg(("ipgpc_parse_filter: source address " \
			    "missing"));
			return (EINVAL);
		} else {	/* saddr present */
			bcopy(addr, filter->saddr.s6_addr32,
			    sizeof (filter->saddr.s6_addr32));
		}
		bcopy(mask, filter->saddr_mask.s6_addr32,
		    sizeof (filter->saddr_mask.s6_addr32));
	}

	/* check for non-continuous mask */
	if ((filter->filter_type == IPGPC_V6_FLTR) ||
	    (filter->filter_type == IPGPC_GENERIC_FLTR)) {
		boolean_t zero_found = B_FALSE;
		for (i = 0; i < 4; ++i) {
			if (filter->saddr_mask.s6_addr32[i] == 0) {
				zero_found = B_TRUE;
			} else {
				if (zero_found) {
					ipgpc0dbg(("ipgpc_parse_filter: "
					    "saddr_mask is non-continuous"));
					return (EINVAL);
				}
			}
			if (!iscontinuousmask(filter->saddr_mask.s6_addr32[i],
			    IP_ABITS)) {
				ipgpc0dbg(("ipgpc_parse_filter: saddr_mask " \
				    "is non-continuous"));
				return (EINVAL);
			}
		}
	} else {		/* IPGPC_V4_FLTR */
		if (!iscontinuousmask((V4_PART_OF_V6(filter->saddr_mask)),
		    IP_ABITS)) {
			ipgpc0dbg(("ipgpc_parse_filter: saddr_mask is " \
			    "non-continuous"));
			return (EINVAL);
		}
	}

	/* parse source address hostname */
	if (nvlist_lookup_string(nvlp, IPGPC_SADDR_HOSTNAME, &s) != 0) {
		filter->saddr_hostname = NULL;
	} else {
		filter->saddr_hostname = kmem_alloc((strlen(s) + 1), KM_SLEEP);
		(void) strcpy(filter->saddr_hostname, s);
	}

	/*
	 * parse destination address mask, if address is present, mask must be
	 * present
	 */
	if (nvlist_lookup_uint32_array(nvlp, IPGPC_DADDR_MASK, &mask, &nelem)
	    != 0) {
		/* check if destination address is present */
		if (nvlist_lookup_uint32_array(nvlp, IPGPC_DADDR, &addr,
		    &nelem) == 0) {
			ipgpc0dbg(("ipgpc_parse_filter: destination address " \
			    "mask missing"));
			return (EINVAL);
		} else {	/* both daddr and daddr_mask absent */
			bcopy(zeroaddr.s6_addr32, filter->daddr.s6_addr32,
			    sizeof (filter->daddr.s6_addr32));
		}
		bcopy(zeroaddr.s6_addr32, filter->daddr_mask.s6_addr32,
		    sizeof (filter->daddr_mask.s6_addr32));
	} else {		/* daddr_mask present */
		/* parse destination address */
		if (nvlist_lookup_uint32_array(nvlp, IPGPC_DADDR, &addr,
		    &nelem) != 0) {
			ipgpc0dbg(("ipgpc_parse_filter: destination address " \
			    "missing"));
			return (EINVAL);
		} else {	/* daddr present */
			bcopy(addr, filter->daddr.s6_addr32,
			    sizeof (filter->daddr.s6_addr32));
		}
		bcopy(mask, filter->daddr_mask.s6_addr32,
		    sizeof (filter->daddr_mask.s6_addr32));
	}

	/* check for non-continuous mask */
	if ((filter->filter_type == IPGPC_V6_FLTR) ||
	    (filter->filter_type == IPGPC_GENERIC_FLTR)) {
		boolean_t zero_found = B_FALSE;
		for (i = 0; i < 4; ++i) {
			if (filter->daddr_mask.s6_addr32[i] == 0) {
				zero_found = B_TRUE;
			} else {
				if (zero_found) {
					ipgpc0dbg(("ipgpc_parse_filter: "
					    "daddr_mask is non-continuous"));
					return (EINVAL);
				}
			}
			if (!iscontinuousmask(filter->daddr_mask.s6_addr32[i],
			    IP_ABITS)) {
				ipgpc0dbg(("ipgpc_parse_filter: daddr_mask " \
				    "is non-continuous"));
				return (EINVAL);
			}
		}
	} else {		/* IPGPC_V4_FLTR */
		if (!iscontinuousmask((V4_PART_OF_V6(filter->daddr_mask)),
		    IP_ABITS)) {
			ipgpc0dbg(("ipgpc_parse_filter: daddr_mask is " \
			    "non-continuous"));
			return (EINVAL);
		}
	}

	/* parse destination address hostname */
	if (nvlist_lookup_string(nvlp, IPGPC_DADDR_HOSTNAME, &s) != 0) {
		filter->daddr_hostname = NULL;
	} else {
		filter->daddr_hostname = kmem_alloc((strlen(s) + 1), KM_SLEEP);
		(void) strcpy(filter->daddr_hostname, s);
	}

	return (0);
}

/*
 * iscontinuousmask(mask, len)
 *
 * Searches a given mask of length len from MSB to LSB looking for a zero
 * bit followed by one bit.  A continuous mask must be a string of zero or
 * more ones followed by a string of zero or more zeros, which would return
 * B_TRUE.  Otherwise, it is not continuous and this function returns B_FALSE.
 */
static boolean_t
iscontinuousmask(uint32_t mask, uint8_t len)
{
	uint8_t pos;
	boolean_t zero_found = B_FALSE;

	for (pos = len; pos > 0; --pos) {
		if (EXTRACTBIT(mask, (pos - 1), len) == 0) {
			zero_found = B_TRUE;
		} else {
			if (zero_found) {
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}


/*
 * insertfid(filter_id, filter, class_id)
 *
 * creates a filter id (fid) structure for filter with filter_id.
 * filter is associated with the input class id
 * it is assumed that a fid will not be inserted for a filter that already
 * exists by the same name.
 */
static void
insertfid(int filter_id, ipgpc_filter_t *filter, uint_t class_id)
{
	ipgpc_fid_list[filter_id].info = 1;
	ipgpc3dbg(("insert_fid: adding filter %s to class %s",
	    filter->filter_name,
	    ipgpc_cid_list[class_id].aclass.class_name));
	ipgpc_fid_list[filter_id].class_id = class_id;
	ipgpc_fid_list[filter_id].filter = *filter;
	ipgpc_fid_list[filter_id].insert_map = 0;
}


static void
common_addfilter(fid_t *fid, int filter_id)
{
	/* start trie inserts */
	/* add source port selector */
	if (t_insert(&ipgpc_trie_list[IPGPC_TRIE_SPORTID], filter_id,
	    fid->filter.sport, fid->filter.sport_mask) == NORMAL_VALUE) {
		fid->insert_map |= SPORT_MASK;
	}
	/* add destination port selector */
	if (t_insert(&ipgpc_trie_list[IPGPC_TRIE_DPORTID], filter_id,
	    fid->filter.dport, fid->filter.dport_mask) == NORMAL_VALUE) {
		fid->insert_map |= DPORT_MASK;
	}
	/* end trie inserts */

	/* add diffserv field selector */
	mutex_enter(&ipgpc_ds_table_id.lock);
	if (ba_insert(&ipgpc_ds_table_id, filter_id, fid->filter.dsfield,
	    fid->filter.dsfield_mask) == NORMAL_VALUE) {
		fid->insert_map |= DS_MASK;
	}
	mutex_exit(&ipgpc_ds_table_id.lock);

	/* start table inserts */
	mutex_enter(&ipgpc_table_list_lock);
	/* add protocol selector */
	if (ht_insert(&ipgpc_table_list[PROTOID_IDX], filter_id,
	    fid->filter.proto) == NORMAL_VALUE) {
		fid->insert_map |= PROTO_MASK;
	}

	/* add UID selector */
	if (ht_insert(&ipgpc_table_list[UID_IDX], filter_id, fid->filter.uid)
	    == NORMAL_VALUE) {
		fid->insert_map |= UID_MASK;
	}

	/* add PROJID selector */
	if (ht_insert(&ipgpc_table_list[PROJID_IDX], filter_id,
	    fid->filter.projid) == NORMAL_VALUE) {
		fid->insert_map |= PROJID_MASK;
	}

	/* add interface index selector */
	if (ht_insert(&ipgpc_table_list[IF_IDX], filter_id,
	    fid->filter.if_index) == NORMAL_VALUE) {
		fid->insert_map |= IF_MASK;
	}

	/* add direction selector */
	if (ht_insert(&ipgpc_table_list[DIR_IDX], filter_id,
	    fid->filter.direction) == NORMAL_VALUE) {
		fid->insert_map |= DIR_MASK;
	}
	mutex_exit(&ipgpc_table_list_lock);
	/* end table inserts */
}

static void
v4_addfilter(fid_t *fid, int filter_id)
{
	/* add IPv4 source address selector */
	if (t_insert(&ipgpc_trie_list[IPGPC_TRIE_SADDRID], filter_id,
	    V4_PART_OF_V6(fid->filter.saddr),
	    V4_PART_OF_V6(fid->filter.saddr_mask)) == NORMAL_VALUE) {
		fid->insert_map |= SADDR_MASK;
	}

	/* add IPv4 destination address selector */
	if (t_insert(&ipgpc_trie_list[IPGPC_TRIE_DADDRID], filter_id,
	    V4_PART_OF_V6(fid->filter.daddr),
	    V4_PART_OF_V6(fid->filter.daddr_mask)) == NORMAL_VALUE) {
		fid->insert_map |= DADDR_MASK;
	}
}

static void
v6_addfilter(fid_t *fid, int filter_id)
{
	/* add IPv6 source address selector */
	if (t_insert6(&ipgpc_trie_list[IPGPC_TRIE_SADDRID6], filter_id,
	    fid->filter.saddr, fid->filter.saddr_mask) == NORMAL_VALUE) {
		fid->insert_map |= SADDR6_MASK;
	}

	/* add IPv6 destination address selector */
	if (t_insert6(&ipgpc_trie_list[IPGPC_TRIE_DADDRID6], filter_id,
	    fid->filter.daddr, fid->filter.daddr_mask) == NORMAL_VALUE) {
		fid->insert_map |= DADDR6_MASK;
	}
}

/*
 * ipgpc_addfilter(filter, class_name, flags)
 *
 * add the specified filter and associate it with the specified class
 * name
 * - add filter id to filter list
 * - add filter keys to selector structures
 * - ENOENT is returned if class does not exist
 * - EEXIST is returned if add failed because filter name exists
 * - ENOMEM is returned if no memory is available to add a new filter
 * - EINVAL if filter.filter_type is invalid
 * - 0 is returned on success
 * flags is unused currently
 */
/* ARGSUSED1 */
int
ipgpc_addfilter(ipgpc_filter_t *filter, char *class_name, ipp_flags_t flags)
{
	unsigned filter_id;
	int err = 0;
	fid_t *fid;
	unsigned class_id;

	err = class_name2id(&class_id, class_name, ipgpc_num_cls);
	if (err != EEXIST) {
		ipgpc0dbg(("ipgpc_addfilter: class lookup error %d", err));
		return (err);
	}
	mutex_enter(&ipgpc_fid_list_lock);
	/* make sure filter does not already exist */
	if ((err = filter_name2id(&filter_id, filter->filter_name,
	    filter->filter_instance, ipgpc_num_fltrs + 1)) == EEXIST) {
		ipgpc0dbg(("ipgpc_addfilter: filter name %s already exists",
		    filter->filter_name));
		mutex_exit(&ipgpc_fid_list_lock);
		return (err);
	} else if (err == ENOSPC) {
		ipgpc0dbg(("ipgpc_addfilter: can not add filter %s, " \
		    "ipgpc_max_num_filteres has been reached",
		    filter->filter_name));
		mutex_exit(&ipgpc_fid_list_lock);
		return (err);
	}
	insertfid(filter_id, filter, class_id);

	fid = &ipgpc_fid_list[filter_id];
	/* add filter id to selector structures */
	switch (fid->filter.filter_type) {
	case IPGPC_GENERIC_FLTR:
		/* add filter id to all selectors */
		common_addfilter(fid, filter_id);
		v4_addfilter(fid, filter_id);
		v6_addfilter(fid, filter_id);
		break;
	case IPGPC_V4_FLTR:
		/* add filter to common and V4 selectors */
		common_addfilter(fid, filter_id);
		v4_addfilter(fid, filter_id);
		break;
	case IPGPC_V6_FLTR:
		/* add filter to common and V6 selectors */
		common_addfilter(fid, filter_id);
		v6_addfilter(fid, filter_id);
		break;
	default:
		ipgpc0dbg(("ipgpc_addfilter(): invalid filter type %d",
		    fid->filter.filter_type));
		mutex_exit(&ipgpc_fid_list_lock);
		return (EINVAL);
	}
	/* check to see if this is a catch all filter, which we reject */
	if (fid->insert_map == 0) {
		ipgpc0dbg(("ipgpc_addfilter(): filter %s rejected because " \
		    "catch all filters are not supported\n",
		    filter->filter_name));
		/* cleanup what we allocated */
		/* remove filter from filter list */
		ipgpc_fid_list[filter_id].info = -1;
		ipgpc_fid_list[filter_id].filter.filter_name[0] = '\0';
		reset_dontcare_stats();	/* need to fixup stats */
		mutex_exit(&ipgpc_fid_list_lock);
		return (EINVAL);
	} else {		/* associate filter with class */
		mutex_enter(&ipgpc_cid_list_lock);
		(void) ipgpc_list_insert(&ipgpc_cid_list[class_id].filter_list,
		    filter_id);
		mutex_exit(&ipgpc_cid_list_lock);
	}
	mutex_exit(&ipgpc_fid_list_lock);
	atomic_inc_ulong(&ipgpc_num_fltrs);
	ipgpc3dbg(("ipgpc_addfilter: adding filter %s", filter->filter_name));
	return (0);
}

/*
 * reset_dontcare_stats()
 *
 * when an insertion fails because zero selectors are specified in a filter
 * the number of dontcare's recorded for each selector structure needs to be
 * decremented
 */
static void
reset_dontcare_stats(void)
{
	int i;

	for (i = 0; i < NUM_TRIES; ++i) {
		atomic_dec_32(&ipgpc_trie_list[i].stats.num_dontcare);
	}
	for (i = 0; i < NUM_TABLES; ++i) {
		atomic_dec_32(&ipgpc_table_list[i].stats.num_dontcare);
	}
	atomic_dec_32(&ipgpc_ds_table_id.stats.num_dontcare);
}

/*
 * ipgpc_parse_class(out_class, nvlp)
 *
 * Given a name value pair list, a class structure will be parsed.
 * To be a valid class, the class name, originator id and next action name
 * must be present. gather_stats is optional, if absent default value is used
 */
int
ipgpc_parse_class(ipgpc_class_t *out_class, nvlist_t *nvlp)
{
	char *name;
	size_t name_len;
	uint32_t gather_stats;

	/* parse class name */
	if (nvlist_lookup_string(nvlp, CLASSIFIER_CLASS_NAME, &name) != 0) {
		return (EINVAL); /* class name missing, error */
	}

	name_len = strlen(name);
	/* check for max name length */
	if ((name_len + 1) > MAXNAMELEN) {
		ipgpc0dbg(("ipgpc_parse_class: class name length > " \
		    "MAXNAMELEN"));
		return (EINVAL);
	}

	bcopy(name, out_class->class_name, (name_len + 1));

	/* parse originator */
	if (nvlist_lookup_uint32(nvlp, IPP_CONFIG_ORIGINATOR,
	    &out_class->originator) != 0) {
		ipgpc0dbg(("ipgpc_parse_class: originator missing"));
		return (EINVAL);
	}

	/* parse action name */
	if (nvlist_lookup_string(nvlp, CLASSIFIER_NEXT_ACTION, &name) != 0) {
		return (EINVAL); /* action name missing, error */
	}
	if ((out_class->next_action = ipp_action_lookup(name))
	    == IPP_ACTION_INVAL) {
		ipgpc0dbg(("ipgpc_parse_class: invalid action name %s", name));
		return (EINVAL);
	}

	/* parse gather stats boolean */
	if (nvlist_lookup_uint32(nvlp, CLASSIFIER_CLASS_STATS_ENABLE,
	    &gather_stats) != 0) {
		/* stats turned off by default */
		out_class->gather_stats = B_FALSE;
	} else {
		out_class->gather_stats = (boolean_t)gather_stats;
	}
	return (0);
}


/*
 * ipgpc_addclass(in_class, flags)
 *
 * adds the given class to the class id list.
 * - EEXIST is returned if class of same name already exists
 * - ENOSPC if there is no more available memory to add class
 * - 0 for success
 * flags is currently unused
 */
/* ARGSUSED */
int
ipgpc_addclass(ipgpc_class_t *in_class, ipp_flags_t flags) {
	int class_id;
	int err;

	if ((err = insertcid(in_class, &class_id)) == EEXIST) {
		ipgpc0dbg(("ipgpc_addclass: class name %s already exists",
		    in_class->class_name));
		return (err);
	} else if (err == ENOSPC) {
		ipgpc0dbg(("ipgpc_addclass: can not add class %s, " \
		    "ipgpc_max_num_classes has been reached",
		    in_class->class_name));
		return (err);
	}
	/* add reference to next action */
	if ((err = ipp_action_ref(ipgpc_aid, in_class->next_action, 0)) != 0) {
		/*
		 * the action id we want to reference must have been
		 * destroyed before we could reference it. remove class
		 * and fail.
		 */
		removecid(class_id);
		return (err);
	}
	return (0);
}



/*
 * class_statinit(in_class, in_class_id)
 *
 * for the given class, create stats entries to record
 * - next action id
 * - number of bytes that matched this class
 * - number of packets that matched this class
 * - time in hrtime of last match for this class
 * any failures are returned, zero on success
 */
static int
class_statinit(ipgpc_class_t *in_class, int in_class_id)
{
	int rc;
	ipp_stat_t *ipp_cl_stats;
	classstats_t *clsnames = NULL;

	/* create stat structure */
	if ((rc = ipp_stat_create(ipgpc_aid, in_class->class_name, 3,
	    update_class_stats, &ipgpc_cid_list[in_class_id].stats,
	    &ipp_cl_stats)) != 0) {
		ipgpc0dbg(("class_statinit: error creating ipp_stat entry"));
		return (rc);
	}

	ASSERT(ipp_cl_stats != NULL);
	clsnames = (classstats_t *)ipp_cl_stats->ipps_data;
	ASSERT(clsnames != NULL);

	/* create stats entry */
	bzero(&ipgpc_cid_list[in_class_id].stats,
	    sizeof (ipgpc_class_stats_t));

	/* set next action id */
	ipgpc_cid_list[in_class_id].stats.next_action =
	    ipgpc_cid_list[in_class_id].aclass.next_action;

	if ((rc = ipp_stat_named_init(ipp_cl_stats, "nbytes",
	    IPP_STAT_UINT64, &clsnames->nbytes)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipp_cl_stats, "npackets",
	    IPP_STAT_UINT64, &clsnames->npackets)) != 0) {
		return (rc);
	}
	if ((rc = ipp_stat_named_init(ipp_cl_stats, "last_match",
	    IPP_STAT_INT64, &clsnames->last_match)) != 0) {
		return (rc);
	}

	/* make reference to kstat structure, for removal */
	ipgpc_cid_list[in_class_id].cl_stats = ipp_cl_stats;
	ipp_stat_install(ipp_cl_stats);
	return (0);
}

/*
 * insertcid(in_class, out_class_id)
 *
 * creates a class id (cid) structure for in_class, if in_class name
 * does not exist already.  id is associated with in_class. the internal
 * id of the cid associated with in_class is returned in out_class_id
 * - ENOENT is returned if in_class->class_name does not already exist
 * - EEXIST is returned if in_class->class_name does already exist
 * - ENOSPC is returned if by adding this class, the ipgpc_max_num_classes
 *   will be exceeded.
 */
static int
insertcid(ipgpc_class_t *in_class, int *out_class_id)
{
	int err, rc;
	unsigned class_id;

	mutex_enter(&ipgpc_cid_list_lock);
	/* see if entry already exists for class */
	if ((err = class_name2id(&class_id, in_class->class_name,
	    ipgpc_num_cls + 1)) == ENOENT) {
		/* create new filter list for new class */
		ipgpc_cid_list[class_id].info = 1;
		ipgpc_cid_list[class_id].aclass = *in_class;
		if (in_class->gather_stats == B_TRUE) {
			/* init kstat entry */
			if ((rc = class_statinit(in_class, class_id)) != 0) {
				ipgpc_cid_list[class_id].info = -1;
				ipgpc0dbg(("insertcid: "
				    "class_statinit failed with error %d", rc));
				mutex_exit(&ipgpc_cid_list_lock);
				return (rc);
			}
		} else {
			ipgpc_cid_list[class_id].cl_stats = NULL;
		}
		ipgpc3dbg(("insertcid: adding class %s",
		    in_class->class_name));
		bcopy(in_class->class_name,
		    ipgpc_cid_list[class_id].aclass.class_name, MAXNAMELEN);
		ipgpc_cid_list[class_id].filter_list = NULL;
		atomic_inc_ulong(&ipgpc_num_cls);
	} else {
		ipgpc0dbg(("insertcid: class name lookup error %d", err));
		mutex_exit(&ipgpc_cid_list_lock);
		return (err);
	}
	mutex_exit(&ipgpc_cid_list_lock);
	*out_class_id = class_id;
	return (err);
}

/*
 * common_removefilter(in_filter_id, fid)
 *
 * removes in_filter_id from each of the common selector structures
 */
static void
common_removefilter(int in_filter_id, fid_t *fid)
{
	/* start trie removes */
	t_remove(&ipgpc_trie_list[IPGPC_TRIE_SPORTID], in_filter_id,
	    fid->filter.sport, fid->filter.sport_mask);
	/* remove id from destination port trie */
	t_remove(&ipgpc_trie_list[IPGPC_TRIE_DPORTID], in_filter_id,
	    fid->filter.dport, fid->filter.dport_mask);
	/* end trie revmoves */

	/* remove id from DiffServ field ba table */
	mutex_enter(&ipgpc_ds_table_id.lock);
	ba_remove(&ipgpc_ds_table_id, in_filter_id, fid->filter.dsfield,
	    fid->filter.dsfield_mask);
	mutex_exit(&ipgpc_ds_table_id.lock);

	/* start table removes */
	mutex_enter(&ipgpc_table_list_lock);
	/* remove id from protocol table */
	ht_remove(&ipgpc_table_list[PROTOID_IDX], in_filter_id,
	    fid->filter.proto);
	/* remove id from UID table */
	ht_remove(&ipgpc_table_list[UID_IDX], in_filter_id, fid->filter.uid);
	/* remove id from PROJID table */
	ht_remove(&ipgpc_table_list[PROJID_IDX], in_filter_id,
	    fid->filter.projid);
	/* remove id from interface id table */
	ht_remove(&ipgpc_table_list[IF_IDX], in_filter_id,
	    fid->filter.if_index);
	/* remove id from direction table */
	ht_remove(&ipgpc_table_list[DIR_IDX], in_filter_id,
	    fid->filter.direction);
	mutex_exit(&ipgpc_table_list_lock);
	/* end table removes */
}

/*
 * v4_removefilter(in_filter_id, fid)
 *
 * removes id from IPV4 specific structures
 */
static void
v4_removefilter(int in_filter_id, fid_t *fid)
{
	/* remove id from source address trie */
	t_remove(&ipgpc_trie_list[IPGPC_TRIE_SADDRID], in_filter_id,
	    V4_PART_OF_V6(fid->filter.saddr),
	    V4_PART_OF_V6(fid->filter.saddr_mask));
	/* remove id from destination address trie */
	t_remove(&ipgpc_trie_list[IPGPC_TRIE_DADDRID], in_filter_id,
	    V4_PART_OF_V6(fid->filter.daddr),
	    V4_PART_OF_V6(fid->filter.daddr_mask));
}

/*
 * v6_removefilter(in_filter_id, fid)
 *
 * removes id from IPV6 specific structures
 */
static void
v6_removefilter(int in_filter_id, fid_t *fid)
{
	/* remove id from source address trie */
	t_remove6(&ipgpc_trie_list[IPGPC_TRIE_SADDRID6], in_filter_id,
	    fid->filter.saddr, fid->filter.saddr_mask);
	/* remove id from destination address trie */
	t_remove6(&ipgpc_trie_list[IPGPC_TRIE_DADDRID6], in_filter_id,
	    fid->filter.daddr, fid->filter.daddr_mask);
}

/*
 * ipgpc_removefilter(filter_name, filter_instance, flags)
 *
 * remove the filter associated with the specified name and instance
 * - remove filter keys from all search tries
 * - remove from filter id list
 * - ENOENT is returned if filter name does not exist
 * - returns 0 on success
 */
/* ARGSUSED */
int
ipgpc_removefilter(char *filter_name, int32_t filter_instance,
    ipp_flags_t flags)
{
	unsigned filter_id;
	fid_t *fid;
	int rc;

	/* check to see if any filters are loaded */
	if (ipgpc_num_fltrs == 0) {
		return (ENOENT);
	}

	mutex_enter(&ipgpc_fid_list_lock);
	/* lookup filter name, only existing filters can be removed */
	if ((rc = filter_name2id(&filter_id, filter_name, filter_instance,
	    ipgpc_num_fltrs)) != EEXIST) {
		mutex_exit(&ipgpc_fid_list_lock);
		return (rc);
	}
	fid = &ipgpc_fid_list[filter_id];
	switch (fid->filter.filter_type) {
	case IPGPC_GENERIC_FLTR:
		common_removefilter(filter_id, fid);
		v4_removefilter(filter_id, fid);
		v6_removefilter(filter_id, fid);
		break;
	case IPGPC_V4_FLTR:
		common_removefilter(filter_id, fid);
		v4_removefilter(filter_id, fid);
		break;
	case IPGPC_V6_FLTR:
		common_removefilter(filter_id, fid);
		v6_removefilter(filter_id, fid);
		break;
	default:
		ipgpc0dbg(("ipgpc_removefilter(): invalid filter type %d",
		    fid->filter.filter_type));
		mutex_exit(&ipgpc_fid_list_lock);
		return (EINVAL);
	}
	/* remove filter from filter list */
	ipgpc_fid_list[filter_id].info = -1;
	ipgpc_fid_list[filter_id].insert_map = 0;
	ipgpc_fid_list[filter_id].filter.filter_name[0] = '\0';
	ipgpc_filter_destructor(&ipgpc_fid_list[filter_id].filter);
	mutex_exit(&ipgpc_fid_list_lock);
	/* remove filter id from class' list of filters */
	remove_from_cid_filter_list(ipgpc_fid_list[filter_id].class_id,
	    filter_id);
	atomic_dec_ulong(&ipgpc_num_fltrs);
	return (0);
}

/*
 * removecid(in_class_id)
 *
 * removes the cid entry from the cid list and frees allocated structures
 */
static void
removecid(int in_class_id)
{
	ipgpc_cid_list[in_class_id].info = -1;
	ipgpc_cid_list[in_class_id].aclass.class_name[0] = '\0';
	ipgpc_cid_list[in_class_id].aclass.next_action = -1;
	/* delete kstat entry */
	if (ipgpc_cid_list[in_class_id].cl_stats != NULL) {
		ipp_stat_destroy(ipgpc_cid_list[in_class_id].cl_stats);
		ipgpc_cid_list[in_class_id].cl_stats = NULL;
	}
	/* decrement total number of classes loaded */
	atomic_dec_ulong(&ipgpc_num_cls);
}

/*
 * remove_from_cid_filter_list(in_class_id, in_filter_id)
 *
 * removes the input filter_id from the filter_list of the class associated
 * with the input class_id
 */
static void
remove_from_cid_filter_list(int in_class_id, int in_filter_id)
{
	cid_t *cid = &ipgpc_cid_list[in_class_id];

	if (cid->filter_list != NULL) {
		(void) ipgpc_list_remove(&cid->filter_list, in_filter_id);
	}
}

/*
 * ipgpc_removeclass(class_name)
 *
 * removes a class and all the filters that point to it (ouch!)
 * - returns 0 on success
 * - ENOENT if class name does not exist
 * - ENOTSUP if class name equals 'default'
 */
int
ipgpc_removeclass(char *class_name, ipp_flags_t flags)
{
	unsigned class_id;
	element_node_t *anode = NULL;
	element_node_t *tnode = NULL;
	fid_t *fid = NULL;
	ipp_action_id_t old_next_action;
	int rc;

	/* check to see if any classes are loaded */
	if (ipgpc_num_cls == 0) {
		return (ENOENT);
	}

	mutex_enter(&ipgpc_cid_list_lock); /* set lock */
	/* lookup class name, only classes that exist can be removed */
	if ((rc = class_name2id(&class_id, class_name, (ipgpc_num_cls - 1)))
	    != EEXIST) {
		mutex_exit(&ipgpc_cid_list_lock); /* release lock */
		return (rc);
	}
	if (class_id == ipgpc_def_class_id) {
		ipgpc0dbg(("ipgpc_removeclass(): default class may not be " \
		    "removed"));
		mutex_exit(&ipgpc_cid_list_lock); /* release lock */
		return (ENOTSUP);
	}

	old_next_action = ipgpc_cid_list[class_id].aclass.next_action;
	anode = ipgpc_cid_list[class_id].filter_list;
	while (anode != NULL) {
		fid = &ipgpc_fid_list[anode->id];
		if (ipgpc_fid_list[anode->id].info > 0) {
			anode = anode->next;
			(void) ipgpc_removefilter(fid->filter.filter_name,
			    fid->filter.filter_instance, flags);
		} else {
			tnode = anode;
			anode = anode->next;
			/* free this node */
			kmem_cache_free(element_node_cache, tnode);
		}
	}
	/* remove cid from ipgpc_cid_list and decrement ipgpc_num_cls */
	ipgpc3dbg(("ipgpc_removeclass: class %s has been removed",
	    class_name));
	removecid(class_id);
	mutex_exit(&ipgpc_cid_list_lock); /* release lock */
	rc = ipp_action_unref(ipgpc_aid, old_next_action, flags);
	ASSERT(rc == 0);
	return (0);
}

/*
 * ipgpc_modifyfilter(nvlist, flags)
 *
 * modifies the input filter
 * - if in_class != NULL, filter is associated with that class
 * - EINVAL is returned if filter name does not exist in nvlist
 * - if filter->filter_name does not exist ENOENT is returned
 * - if a class name to associate with is not present in nvlist, then the
 *   previous class association is used
 */
int
ipgpc_modifyfilter(nvlist_t **nvlpp, ipp_flags_t flags)
{
	unsigned filter_id;
	int ret = 0;
	int rc;
	ipgpc_filter_t *filter;
	ipgpc_filter_t old_filter;
	char *name;
	char *s;
	uint_t class_id;

	filter = kmem_zalloc(sizeof (ipgpc_filter_t), KM_SLEEP);
	if ((ret = ipgpc_parse_filter(filter, *nvlpp)) != 0) {
		ipgpc0dbg(("ipgpc_modifyfilter: error %d parsing filter",
		    ret));
		ipgpc_filter_destructor(filter);
		kmem_free(filter, sizeof (ipgpc_filter_t));
		return (ret);
	}

	/* parse class name */
	if (nvlist_lookup_string(*nvlpp, CLASSIFIER_CLASS_NAME, &name)
	    != 0) {
		name = NULL;	/* no class specified */
	}

	/* modify filter entry */
	if ((rc = filter_name2id(&filter_id, filter->filter_name,
	    filter->filter_instance, ipgpc_num_fltrs)) == EEXIST) {
		if (name == NULL) {
			/* set class_name to previous class_name association */
			class_id = ipgpc_fid_list[filter_id].class_id;
			name = ipgpc_cid_list[class_id].aclass.class_name;
		} else {
			if ((ret = class_name2id(&class_id, name,
			    ipgpc_num_cls)) != EEXIST) {
				ipgpc0dbg(("ipgpc_modifyfilter: class does " \
				    "not exist"));
				ipgpc_filter_destructor(filter);
				kmem_free(filter, sizeof (ipgpc_filter_t));
				return (ret);
			}
		}
		/* copy out old filter just in case we need to revert */
		old_filter = ipgpc_fid_list[filter_id].filter;

		/* make copy of filter_comment */
		if (ipgpc_fid_list[filter_id].filter.filter_comment != NULL) {
			s = ipgpc_fid_list[filter_id].filter.filter_comment;
			old_filter.filter_comment =
			    kmem_alloc((strlen(s) + 1), KM_SLEEP);
			(void) strcpy(old_filter.filter_comment, s);
		} else {
			old_filter.filter_comment = NULL;
		}

		/* make copy of saddr_hostname */
		if (ipgpc_fid_list[filter_id].filter.saddr_hostname != NULL) {
			s = ipgpc_fid_list[filter_id].filter.saddr_hostname;
			old_filter.saddr_hostname =
			    kmem_alloc((strlen(s) + 1), KM_SLEEP);
			(void) strcpy(old_filter.saddr_hostname, s);
		} else {
			old_filter.saddr_hostname = NULL;
		}

		/* make copy of daddr_hostname */
		if (ipgpc_fid_list[filter_id].filter.daddr_hostname != NULL) {
			s = ipgpc_fid_list[filter_id].filter.daddr_hostname;
			old_filter.daddr_hostname =
			    kmem_alloc((strlen(s) + 1), KM_SLEEP);
			(void) strcpy(old_filter.daddr_hostname, s);
		} else {
			old_filter.daddr_hostname = NULL;
		}

		/* remove old filter entry */
		ret = ipgpc_removefilter(filter->filter_name,
		    filter->filter_instance, flags);
		if (ret == 0) {	/* no error, add filter */
			ret = ipgpc_addfilter(filter, name, flags);
			if (ret != 0) {
				/* error occurred, free filter fields */
				ipgpc0dbg(("ipgpc_modifyfilter: invalid " \
				    "filter given, unable to modify " \
				    "existing filter %s",
				    filter->filter_name));
				ipgpc_filter_destructor(filter);
				kmem_free(filter, sizeof (ipgpc_filter_t));
				/* revert back to old filter */
				(void) ipgpc_addfilter(&old_filter, name,
				    flags);
				return (ret);
			}
			ipgpc_filter_destructor(&old_filter);
		} else {
			ipgpc0dbg(("ipgpc_modifyfilter: error %d occurred " \
			    "when modifying filter", ret));
			ipgpc_filter_destructor(&old_filter);
			ipgpc_filter_destructor(filter);
			kmem_free(filter, sizeof (ipgpc_filter_t));
			return (ret);
		}
	} else {
		ipgpc0dbg(("ipgpc_modifyfilter: filter lookup error %d", rc));
		return (rc); /* filter name does not exist */
	}
	kmem_free(filter, sizeof (ipgpc_filter_t));
	return (0);
}

/*
 * ipgpc_modifyclass(in_class)
 *
 * if the input class exists, then the action list is modified
 * if the input class does not exist, ENOENT is returned
 */
/* ARGSUSED */
int
ipgpc_modifyclass(nvlist_t **nvlpp, ipp_flags_t flags)
{
	unsigned class_id;
	ipgpc_class_t in_class;
	char *name;
	int rc;
	uint32_t gather_stats;
	boolean_t ref_action = B_FALSE;
	ipp_action_id_t old_next_action;
	size_t name_len;

	/* parse class name */
	if (nvlist_lookup_string(*nvlpp, CLASSIFIER_CLASS_NAME, &name) != 0) {
		return (EINVAL); /* class name missing, error */
	}
	name_len = strlen(name);
	/* check for max name length */
	if ((name_len + 1) > MAXNAMELEN) {
		ipgpc0dbg(("ipgpc_modifyclass: class name length > " \
		    "MAXNAMELEN"));
		return (EINVAL);
	}
	bcopy(name, in_class.class_name, (name_len + 1));

	mutex_enter(&ipgpc_cid_list_lock);
	/* look up class name, only existing classes can be modified */
	if ((rc = class_name2id(&class_id, in_class.class_name,
	    ipgpc_num_cls)) == EEXIST) {
		/* preserve previous config if values are absent */
		/* parse action name */
		old_next_action = ipgpc_cid_list[class_id].aclass.next_action;
		if (nvlist_lookup_string(*nvlpp, CLASSIFIER_NEXT_ACTION, &name)
		    != 0) {
			/* use previous config */
			in_class.next_action = old_next_action;
		} else {	/* next action name present */
			if ((in_class.next_action = ipp_action_lookup(name))
			    == IPP_ACTION_INVAL) {
				ipgpc0dbg(("ipgpc_modifyclass: invalid " \
				    "action name %s", name));
				mutex_exit(&ipgpc_cid_list_lock);
				return (EINVAL); /* this is an error */
			}
			ref_action = B_TRUE;
		}
		/* parse gather stats byte */
		if (nvlist_lookup_uint32(*nvlpp, CLASSIFIER_CLASS_STATS_ENABLE,
		    &gather_stats) != 0) {
			/* use previous config */
			in_class.gather_stats =
			    ipgpc_cid_list[class_id].aclass.gather_stats;
		} else {
			in_class.gather_stats = (boolean_t)gather_stats;
		}
		/* check to see if gather_stats booleans differ */
		if ((ipgpc_cid_list[class_id].aclass.gather_stats !=
		    in_class.gather_stats)) {
			if (ipgpc_cid_list[class_id].aclass.gather_stats) {
				/* delete kstat entry */
				if (ipgpc_cid_list[class_id].cl_stats != NULL) {
					ipp_stat_destroy(
					    ipgpc_cid_list[class_id].cl_stats);
					ipgpc_cid_list[class_id].cl_stats =
					    NULL;
				}
			} else { /* gather_stats == B_FALSE */
				if ((rc = class_statinit(&in_class, class_id))
				    != 0) {
					ipgpc0dbg(("ipgpc_modifyclass: " \
					    "class_statinit failed with " \
					    "error %d", rc));
					mutex_exit(&ipgpc_cid_list_lock);
					return (rc);
				}
			}
		}
		mutex_exit(&ipgpc_cid_list_lock);
		/* check if next_action was modified */
		if (ref_action == B_TRUE) {
			if ((rc = ipp_action_ref(ipgpc_aid,
			    in_class.next_action, 0)) != 0) {
				ipgpc0dbg(("ipgpc_modifyclass: error " \
				    "occurred while adding a reference to " \
				    "the new next_action %d",
				    in_class.next_action));
				mutex_exit(&ipgpc_cid_list_lock);
				return (rc);
			}
			/* fix up references */
			rc = ipp_action_unref(ipgpc_aid, old_next_action,
			    flags);
			ASSERT(rc == 0);
		}
		/* preserve originator id */
		in_class.originator =
		    ipgpc_cid_list[class_id].aclass.originator;
		ipgpc_cid_list[class_id].aclass = in_class;
		ipgpc_cid_list[class_id].stats.next_action =
		    in_class.next_action;
	} else {
		ipgpc0dbg(("ipgpc_modifyclass: class name lookup error %d",
		    rc));
		mutex_exit(&ipgpc_cid_list_lock);
		return (rc);
	}
	return (0);
}


/*
 * ipgpc_list_insert(listpp, id)
 *
 * inserts an item, id, into the list, if item exists EEXIST is returned
 */
int
ipgpc_list_insert(linked_list *listpp, key_t id)
{
	element_node_t *p;

	if (*listpp == NULL) {
		*listpp = kmem_cache_alloc(element_node_cache, KM_SLEEP);
		(*listpp)->element_refcnt = 1;
		(*listpp)->next = NULL;
		(*listpp)->id = id;
	} else {
		for (p = *listpp; p->next != NULL; p = p->next) {
			if (p->id == id) {
				(*p->element_ref)(p);
				return (EEXIST);
			}
		}
		if (p->id == id) {
			(*p->element_ref)(p);
			return (EEXIST);
		} else {
			p->next =
			    kmem_cache_alloc(element_node_cache, KM_SLEEP);
			p->next->element_refcnt = 1;
			p->next->next = NULL;
			p = p->next;
			p->id = id;
		}
	}
	return (0);
}

/*
 * ipgpc_list_remove(listpp, id)
 *
 * removes an item, id, from the list if it exists and returns TRUE or FALSE
 * if not removed
 */
boolean_t
ipgpc_list_remove(element_node_t **listpp, key_t id)
{
	element_node_t *p = NULL;
	element_node_t *t = NULL;

	if (*listpp == NULL) {
		return (B_FALSE);
	}
	if ((*listpp)->id == id) {
		p = *listpp;
		if ((*listpp)->element_refcnt == 1) {
			*listpp = (*listpp)->next;
		}
		(*p->element_unref)(p);
		return (B_TRUE);
	} else if ((*listpp)->next != NULL) {
		/* linear search for matching id */
		for (p = *listpp; p->next != NULL; p = p->next) {
			if (p->next->id == id) {
				t = p->next;
				if (p->next->element_refcnt == 1) {
					p->next = p->next->next;
				}
				(*t->element_unref)(t);
				return (B_TRUE);
			}
		}
	}
	return (B_FALSE);
}

/*
 * Module destroy code
 */

static void
removeclasses(ipp_flags_t flags)
{
	int i;

	for (i = 0; i < ipgpc_max_num_classes; ++i) {
		if (ipgpc_cid_list[i].info > 0) {
			(void) ipgpc_removeclass(
			    ipgpc_cid_list[i].aclass.class_name, flags);
		}
	}
}

static void
freetriev6nodes(node_t **inNode)
{
	node_t *anode = *inNode;
	node_t *tnode;
	node_t *s[130];		/* stack of previous nodes */
	int prev_link[130];	/* stack of what the previous link was */
	int sp = 0;
	node_t *root = *inNode;	/* pointer to root node */

	s[sp] = NULL;
	prev_link[sp] = -1;
	/* loop until only the root node remains */
	while (!((root->zero == NULL) && (root->one == NULL))) {
		if (anode->zero != NULL) { /* check zero node */
			tnode = anode;
			anode = anode->zero;
			s[++sp] = tnode; /* put node on stack */
			prev_link[sp] = 0;
		} else if (anode->one != NULL) { /* check one node */
			tnode = anode;
			anode = anode->one;
			s[++sp] = tnode; /* put node on stack */
			prev_link[sp] = 1;
		} else {	/* leaf node reached */
			/* free leaf node and pop the stack */
			kmem_cache_free(trie_node_cache, anode);
			anode = s[sp];
			if (prev_link[sp--] == 0) {
				anode->zero = NULL;
			} else {
				anode->one = NULL;
			}
			if (anode == NULL) {
				return;
			}
		}
	}
}


void
ipgpc_destroy(ipp_flags_t flags)
{
	int i;
	int rc;
	element_node_t *anode = NULL;
	element_node_t *tnode = NULL;
	fid_t *fid = NULL;

	/* check to see if default class id was set */
	if (ipgpc_def_class_id != -1) {
		ipp_action_id_t next_action =
		    ipgpc_cid_list[ipgpc_def_class_id].aclass.next_action;

		/* unreference default_class->next_action */
		rc = ipp_action_unref(ipgpc_aid, next_action, flags);
		ASSERT(rc == 0);
		/* removing filter associated with the default class */
		anode = ipgpc_cid_list[ipgpc_def_class_id].filter_list;
		while (anode != NULL) {
			fid = &ipgpc_fid_list[anode->id];
			if (ipgpc_fid_list[anode->id].info > 0) {
				anode = anode->next;
				(void) ipgpc_removefilter(
				    fid->filter.filter_name,
				    fid->filter.filter_instance, flags);
			} else {
				tnode = anode;
				anode = anode->next;
				/* free this node */
				kmem_cache_free(element_node_cache, tnode);
			}
		}
		ASSERT(ipgpc_cid_list[ipgpc_def_class_id].filter_list == NULL);
		removecid(ipgpc_def_class_id);
		ASSERT(ipgpc_cid_list[ipgpc_def_class_id].info == -1);
		ipgpc_def_class_id = -1;
	}
	/* remove stats entries */
	if (ipgpc_global_stats != NULL) {
		/* destroy global stats */
		ipp_stat_destroy(ipgpc_global_stats);
		ipgpc_global_stats = NULL;
	}

	/*
	 * remove all classes, which will remove all filters, stats and
	 * selectors
	 */
	if (ipgpc_cid_list != NULL) {
		removeclasses(flags);
		kmem_free(ipgpc_cid_list,
		    sizeof (cid_t) * ipgpc_max_num_classes);
		ipgpc_cid_list = NULL;
	}
	/* all filters and classes should have been removed at this point */
	ASSERT((ipgpc_num_cls == 0) && (ipgpc_num_fltrs == 0));

	/* free filter id list structure */
	if (ipgpc_fid_list != NULL) {
		kmem_free(ipgpc_fid_list,
		    sizeof (fid_t) * ipgpc_max_num_filters);
		ipgpc_fid_list = NULL;
	}

	/*
	 * IPv6 address tries don't implement path compression or node
	 * deletions, like v4/port tries.  All allocated nodes must be freed
	 * before trie root node is destroyed
	 */
	if (ipgpc_trie_list[IPGPC_TRIE_SADDRID6].trie != NULL) {
		freetriev6nodes(&ipgpc_trie_list[IPGPC_TRIE_SADDRID6].trie);
		/* free trie root */
		kmem_cache_free(trie_node_cache,
		    ipgpc_trie_list[IPGPC_TRIE_SADDRID6].trie);
		/* destroy lock */
		rw_destroy(&ipgpc_trie_list[IPGPC_TRIE_SADDRID6].rw_lock);
		ipgpc_trie_list[IPGPC_TRIE_SADDRID6].trie = NULL;
	}
	if (ipgpc_trie_list[IPGPC_TRIE_DADDRID6].trie != NULL) {
		freetriev6nodes(&ipgpc_trie_list[IPGPC_TRIE_DADDRID6].trie);
		/* free trie root */
		kmem_cache_free(trie_node_cache,
		    ipgpc_trie_list[IPGPC_TRIE_DADDRID6].trie);
		/* destroy lock */
		rw_destroy(&ipgpc_trie_list[IPGPC_TRIE_DADDRID6].rw_lock);
		ipgpc_trie_list[IPGPC_TRIE_DADDRID6].trie = NULL;
	}

	/* free remaining tries structures */
	for (i = 0; i < (NUM_TRIES - 2); ++i) {
		if (ipgpc_trie_list[i].trie != NULL) {
			/* free trie root */
			kmem_cache_free(trie_node_cache,
			    ipgpc_trie_list[i].trie);
			/* destroy lock */
			rw_destroy(&ipgpc_trie_list[i].rw_lock);
			ipgpc_trie_list[i].trie = NULL;
		}
	}

	/* destroy caches */
	if (ht_node_cache != NULL) {
		kmem_cache_destroy(ht_node_cache);
		ht_node_cache = NULL;
	}
	if (trie_node_cache != NULL) {
		kmem_cache_destroy(trie_node_cache);
		trie_node_cache = NULL;
	}
	if (element_node_cache != NULL) {
		kmem_cache_destroy(element_node_cache);
		element_node_cache = NULL;
	}
	if (ht_match_cache != NULL) {
		kmem_cache_destroy(ht_match_cache);
		ht_match_cache = NULL;
	}
}

/*
 * Module info code
 */

/*
 * ipgpc_params_info(fn, arg)
 *
 * allocates, builds and passes an nvlist to fn with arg
 */
int
ipgpc_params_info(int (*fn)(nvlist_t *, void *), void *arg)
{
	nvlist_t *nvlp;
	int rc;

	/* allocate nvlist to be passed back */
	if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		return (rc);
	}

	/* add config type */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE, IPP_SET)) != 0) {
		nvlist_free(nvlp);
		return (rc);
	}

	/* add gather stats boolean */
	if ((rc = nvlist_add_uint32(nvlp, IPP_ACTION_STATS_ENABLE,
	    (uint32_t)ipgpc_gather_stats)) != 0) {
		nvlist_free(nvlp);
		return (rc);
	}

	/* call back with nvlist */
	rc = fn(nvlp, arg);

	nvlist_free(nvlp);

	return (rc);
}

/*
 * build_class_nvlist(nvlpp, in_class)
 *
 * build an nvlist based on in_class
 * if isdefault, add apporiate configuration type to nvlpp
 */
static int
build_class_nvlist(nvlist_t **nvlpp, ipgpc_class_t *in_class,
    boolean_t isdefault)
{
	nvlist_t *nvlp = *nvlpp;
	char *next_action;
	int rc;

	/*
	 * add configuration type
	 * if class is the default class, config type should be
	 * CLASSIFIER_MODIFY_CLASS
	 * otherwise it should be CLASSIFIER_ADD_CLASS
	 */
	/* add config type */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE,
	    ((isdefault) ? CLASSIFIER_MODIFY_CLASS : CLASSIFIER_ADD_CLASS)))
	    != 0) {
		return (rc);
	}

	/* add class name */
	if ((rc = nvlist_add_string(nvlp, CLASSIFIER_CLASS_NAME,
	    in_class->class_name)) != 0) {
		return (rc);
	}

	/* add originator */
	if ((rc = nvlist_add_uint32(nvlp, IPP_CONFIG_ORIGINATOR,
	    in_class->originator)) != 0) {
		return (rc);
	}

	/* look up next action name with next action id */
	if ((rc = ipp_action_name(in_class->next_action, &next_action)) != 0) {
		return (rc);
	}

	/* add next action name */
	if ((rc = nvlist_add_string(nvlp, CLASSIFIER_NEXT_ACTION,
	    next_action)) != 0) {
		kmem_free(next_action, (strlen(next_action) + 1));
		return (rc);
	}

	kmem_free(next_action, (strlen(next_action) + 1));

	/* add gather stats boolean */
	if ((rc = nvlist_add_uint32(nvlp, CLASSIFIER_CLASS_STATS_ENABLE,
	    (uint32_t)in_class->gather_stats)) != 0) {
		return (rc);
	}

	return (0);
}


/*
 * ipgpc_classes_info(fn, arg)
 *
 * foreach class, allocate, build and pass an nvlist to fn with arg
 */
int
ipgpc_classes_info(int (*fn)(nvlist_t *, void *), void *arg)
{
	int i;
	int rc;
	nvlist_t *nvlp;

	for (i = 0; i < ipgpc_max_num_classes; ++i) {
		if (ipgpc_cid_list[i].info <= 0) {
			/* cid not allocated for this entry */
			continue;
		}
		/* allocate an nvlist */
		if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP))
		    != 0) {
			return (rc);
		}
		/* build an nvlist for this particular class */
		if ((rc = (build_class_nvlist(&nvlp,
		    &ipgpc_cid_list[i].aclass,
		    ((i == ipgpc_def_class_id) ? B_TRUE : B_FALSE)))) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}
		/* call back with nvlist */
		if ((rc = fn(nvlp, arg)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		nvlist_free(nvlp); /* free nvlist and continue */
	}

	return (0);
}

/*
 * build_filter_nvlist(nvlpp, in_filter, class_name)
 *
 * build an nvlist based on in_filter and class_name.
 * Only non-wildcard/dontcare selectors are added to the nvlist.
 */
static int
build_filter_nvlist(nvlist_t **nvlpp, ipgpc_filter_t *in_filter,
    char *class_name)
{
	nvlist_t *nvlp = *nvlpp;
	int rc;
	in6_addr_t zero_addr = IN6ADDR_ANY_INIT;

	/* add filter name */
	if ((rc = nvlist_add_string(nvlp, CLASSIFIER_FILTER_NAME,
	    in_filter->filter_name)) != 0) {
		return (rc);
	}

	/* add class name */
	if ((rc = nvlist_add_string(nvlp, CLASSIFIER_CLASS_NAME, class_name))
	    != 0) {
		return (rc);
	}

	/* add originator */
	if ((rc = nvlist_add_uint32(nvlp, IPP_CONFIG_ORIGINATOR,
	    in_filter->originator)) != 0) {
		return (rc);
	}

	/* add configuration type of CLASSIFIER_ADD_FILTER */
	if ((rc = nvlist_add_byte(nvlp, IPP_CONFIG_TYPE,
	    CLASSIFIER_ADD_FILTER)) != 0) {
		return (rc);
	}

	/* add uid */
	if (in_filter->uid != IPGPC_WILDCARD) {
		if ((rc = nvlist_add_uint32(nvlp, IPGPC_UID, in_filter->uid))
		    != 0) {
			return (rc);
		}
	}

	/* add projid */
	if (in_filter->projid != IPGPC_WILDCARD) {
		if ((rc = nvlist_add_int32(nvlp, IPGPC_PROJID,
		    in_filter->projid)) != 0) {
			return (rc);
		}
	}

	/* add interface index */
	if (in_filter->if_index != IPGPC_UNSPECIFIED) {
		if ((rc = nvlist_add_uint32(nvlp, IPGPC_IF_INDEX,
		    in_filter->if_index)) != 0) {
			return (rc);
		}
	}

	/* add direction */
	if (in_filter->direction != IPGPC_UNSPECIFIED) {
		if ((rc = nvlist_add_uint32(nvlp, IPGPC_DIR,
		    in_filter->direction)) != 0) {
			return (rc);
		}
	}

	/* add protocol */
	if (in_filter->proto != IPGPC_UNSPECIFIED) {
		if ((rc = nvlist_add_byte(nvlp, IPGPC_PROTO, in_filter->proto))
		    != 0) {
			return (rc);
		}
	}

	/* add dsfield and mask */
	if (in_filter->dsfield_mask != 0) {
		if ((rc = nvlist_add_byte(nvlp, IPGPC_DSFIELD,
		    in_filter->dsfield)) != 0) {
			return (rc);
		}
		if ((rc = nvlist_add_byte(nvlp, IPGPC_DSFIELD_MASK,
		    in_filter->dsfield_mask)) != 0) {
			return (rc);
		}
	}

	/* add source address, mask and hostname */
	if (!(IN6_ARE_ADDR_EQUAL(&in_filter->saddr_mask, &zero_addr))) {
		if ((rc = nvlist_add_uint32_array(nvlp, IPGPC_SADDR,
		    in_filter->saddr.s6_addr32, 4)) != 0) {
			return (rc);
		}

		if ((rc = nvlist_add_uint32_array(nvlp, IPGPC_SADDR_MASK,
		    in_filter->saddr_mask.s6_addr32, 4)) != 0) {
			return (rc);
		}

		if (in_filter->saddr_hostname != NULL) {
			if ((rc = nvlist_add_string(nvlp, IPGPC_SADDR_HOSTNAME,
			    in_filter->saddr_hostname)) != 0) {
				return (rc);
			}
		}
	}

	/* add destination address, mask and hostname */
	if (!(IN6_ARE_ADDR_EQUAL(&in_filter->daddr_mask, &zero_addr))) {
		if ((rc = nvlist_add_uint32_array(nvlp, IPGPC_DADDR,
		    in_filter->daddr.s6_addr32, 4)) != 0) {
			return (rc);
		}
		if ((rc = nvlist_add_uint32_array(nvlp, IPGPC_DADDR_MASK,
		    in_filter->daddr_mask.s6_addr32, 4)) != 0) {
			return (rc);
		}
		if (in_filter->daddr_hostname != NULL) {
			if ((rc = nvlist_add_string(nvlp, IPGPC_DADDR_HOSTNAME,
			    in_filter->daddr_hostname)) != 0) {
				return (rc);
			}
		}
	}

	/* add source port and mask */
	if (in_filter->sport_mask != 0) {
		if ((rc = nvlist_add_uint16(nvlp, IPGPC_SPORT,
		    in_filter->sport)) != 0) {
			return (rc);
		}
		if ((rc = nvlist_add_uint16(nvlp, IPGPC_SPORT_MASK,
		    in_filter->sport_mask)) != 0) {
			return (rc);
		}
	}

	/* add destination port and mask */
	if (in_filter->dport_mask != 0) {
		if ((rc = nvlist_add_uint16(nvlp, IPGPC_DPORT,
		    in_filter->dport)) != 0) {
			return (rc);
		}
		if ((rc = nvlist_add_uint16(nvlp, IPGPC_DPORT_MASK,
		    in_filter->dport_mask)) != 0) {
			return (rc);
		}
	}

	/* add precedence */
	if (in_filter->precedence != UINT_MAX) {
		if ((rc = nvlist_add_uint32(nvlp, IPGPC_PRECEDENCE,
		    in_filter->precedence)) != 0) {
			return (rc);
		}
	}

	/* add priority */
	if (in_filter->priority != 0) {
		if ((rc = nvlist_add_uint32(nvlp, IPGPC_PRIORITY,
		    in_filter->priority)) != 0) {
			return (rc);
		}
	}

	/* add filter type */
	if (in_filter->filter_type != IPGPC_GENERIC_FLTR) {
		if ((rc = nvlist_add_byte(nvlp, IPGPC_FILTER_TYPE,
		    in_filter->filter_type)) != 0) {
			return (rc);
		}
	}

	/* add filter instance */
	if (in_filter->filter_instance != -1) {
		if ((rc = nvlist_add_int32(nvlp, IPGPC_FILTER_INSTANCE,
		    in_filter->filter_instance)) != 0) {
			return (rc);
		}
	}

	/* add filter private field */
	if (in_filter->filter_comment != NULL) {
		if ((rc = nvlist_add_string(nvlp, IPGPC_FILTER_PRIVATE,
		    in_filter->filter_comment)) != 0) {
			return (rc);
		}
	}

	return (0);
}

/*
 * ipgpc_filters_info(fn, arg)
 *
 * for each filter, allocate, build and pass an nvlist to fn with arg
 */
int
ipgpc_filters_info(int (*fn)(nvlist_t *, void *), void *arg)
{
	int i;
	int rc;
	nvlist_t *nvlp;
	int class_id;

	for (i = 0; i < ipgpc_max_num_filters; ++i) {
		if (ipgpc_fid_list[i].info <= 0) {
			/* fid not allocated for this entry */
			continue;
		}
		/* allocate an nvlist */
		if ((rc = nvlist_alloc(&nvlp, NV_UNIQUE_NAME, KM_NOSLEEP))
		    != 0) {
			return (rc);
		}
		class_id = ipgpc_fid_list[i].class_id;
		/* build an nvlist for this particular filter */
		if ((rc = (build_filter_nvlist(&nvlp,
		    &ipgpc_fid_list[i].filter,
		    ipgpc_cid_list[class_id].aclass.class_name))) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}
		/* call back with nvlist */
		if ((rc = fn(nvlp, arg)) != 0) {
			nvlist_free(nvlp);
			return (rc);
		}

		nvlist_free(nvlp); /* free nvlist and continue */
	}
	return (0);
}

/*
 * Module invoke code
 */

/*
 * ipgpc_findfilters(in_id, key, fid_table)
 *
 * returns a list of matching filters for searching the given structure
 * associated with the input id with the input key
 * - returns DONTCARE_ONLY_MATCH if the selector structure described by
 *   in_id contains only dontcares
 * - returns NO_MATCHES if no filters were found and no dontcares exist
 *   for a given selector
 * - ENOMEM is returned if memory error occurs
 * - NORMAL_MATCH on success
 */
int
ipgpc_findfilters(int in_id, int key, ht_match_t *fid_table)
{
	int num_found = 0;

	if (in_id == IPGPC_BA_DSID) {	/* special search for DSFIELD */
		if (ipgpc_ds_table_id.info.dontcareonly == B_TRUE) {
			/* trie is loaded with only DONTCARE(*) keys */
			return (DONTCARE_ONLY_MATCH);
		}
		num_found = ba_retrieve(&ipgpc_ds_table_id, (uint8_t)key,
		    fid_table);
		/* check to see if no matches were made */
		if ((num_found == 0) &&
		    (ipgpc_ds_table_id.stats.num_dontcare == 0)) {
			return (NO_MATCHES);
		}
	} else if (in_id >= TABLE_ID_OFFSET) {	/* table to search */
		table_id_t *taid = &ipgpc_table_list[in_id - TABLE_ID_OFFSET];

		if (taid->info.dontcareonly == B_TRUE) {
			/* trie is loaded with only DONTCARE(*) keys */
			return (DONTCARE_ONLY_MATCH);
		}
		num_found = ht_retrieve(taid, key, fid_table);
		/* check to see if no matches were made */
		if ((num_found == 0) && (taid->stats.num_dontcare == 0)) {
			return (NO_MATCHES);
		}
	} else {		/* trie to search */
		trie_id_t *tid = &ipgpc_trie_list[in_id];

		if (tid->info.dontcareonly == B_TRUE) {
			/* trie is loaded with only DONTCARE(*) keys */
			return (DONTCARE_ONLY_MATCH);
		}
		/* search the trie for matches */
		num_found = t_retrieve(tid, key, fid_table);
		/* check to see if no matches were made */
		if ((num_found == 0) && (tid->stats.num_dontcare == 0)) {
			return (NO_MATCHES);
		}
	}
	if (num_found == -1) {	/* num_found == -1 if memory error */
		return (ENOMEM);
	} else {
		return (NORMAL_MATCH);
	}
}

/*
 * ipgpc_findfilters6(in_id, key, fid_table)
 *
 * findfilters specific to IPv6 traffic
 */
int
ipgpc_findfilters6(int in_id, in6_addr_t key, ht_match_t *fid_table)
{
	trie_id_t *tid = &ipgpc_trie_list[in_id];
	int num_found = 0;

	if (tid->info.dontcareonly == B_TRUE) {
		/* trie is loaded with only DONTCARE(*) keys */
		return (DONTCARE_ONLY_MATCH);
	}
	/* search the trie for matches */
	num_found = t_retrieve6(tid, key, fid_table);
	/* check to see if no matches were made */
	if ((num_found == 0) && (tid->stats.num_dontcare == 0)) {
		return (NO_MATCHES);
	} else if (num_found == -1) { /* num_found == -1 if memory error */
		return (ENOMEM);
	} else {
		return (NORMAL_MATCH);
	}
}

/*
 * ht_match_insert(a, id, mask)
 *
 * inserts id into table and applies mask to match_map
 * returns ENOMEM if can't allocate ht_match_t node, 0 otherwise
 */
static int
ht_match_insert(ht_match_t *a, int id, uint16_t mask)
{
	int x = (id % HASH_SIZE); /* has for index */
	ht_match_t *p = NULL;

	if ((a[x].key == id) || (a[x].key == 0)) {
		a[x].key = id;
		a[x].match_map |= mask;
	} else if (a[x].next == NULL) {
		a[x].next = kmem_cache_alloc(ht_match_cache, KM_NOSLEEP);
		if (a[x].next == NULL) {
			ipgpc0dbg(("ht_match_insert(): kmem_cache_alloc " \
			    "error"));
			return (ENOMEM);
		}
		a[x].next->next = NULL;
		a[x].next->key = id;
		a[x].next->match_map = mask;
	} else {

		p = a[x].next;
		while (p != NULL) {
			if (p->key == id) {
				p->match_map |= mask;
				return (0);
			}
			p = p->next;
		}
		p = kmem_cache_alloc(ht_match_cache, KM_NOSLEEP);
		if (p == NULL) {
			ipgpc0dbg(("ht_match_insert(): kmem_cache_alloc " \
			    "error"));
			return (ENOMEM);
		}
		p->key = id;
		p->match_map = mask;
		p->next = a[x].next;
		a[x].next = p;
	}
	return (0);
}

/*
 * ipgpc_mark_found(mask, list, fid_table)
 *
 * given a list of filter ids and a mask for the selector that is being marked,
 * the ids are inserted (or updated) in the fid_table to being marked as
 * matched for the given selector
 * return -1 if memory error
 */
int
ipgpc_mark_found(uint16_t mask, linked_list list, ht_match_t *fid_table)
{
	linked_list tnode = NULL;
	int num_found = 0;

	for (tnode = list; tnode != NULL; tnode = tnode->next) {
		/* apply the trie mask to the match map for this element */
		if (ipgpc_fid_list[tnode->id].info > 0) {
			if (ht_match_insert(fid_table, tnode->id, mask)
			    == ENOMEM) {
				return (-1);
			}
			++num_found;
		}
	}
	return (num_found);
}

/* updates global stats for ipgpc */
/* ARGSUSED */
static int
update_global_stats(ipp_stat_t *sp, void *arg, int rw)
{
	globalstats_t *gbl_stats = (globalstats_t *)sp->ipps_data;
	uint32_t num_filters = (uint32_t)ipgpc_num_fltrs;
	uint32_t num_classes = (uint32_t)ipgpc_num_cls;

	ASSERT(gbl_stats != NULL);
	(void) ipp_stat_named_op(&gbl_stats->nfilters, &num_filters, rw);
	(void) ipp_stat_named_op(&gbl_stats->nclasses, &num_classes, rw);
	(void) ipp_stat_named_op(&gbl_stats->nbytes, &ipgpc_nbytes, rw);
	(void) ipp_stat_named_op(&gbl_stats->npackets, &ipgpc_npackets, rw);
	(void) ipp_stat_named_op(&gbl_stats->epackets, &ipgpc_epackets, rw);
	return (0);
}


/* updates class stats for a specific class */
static int
update_class_stats(ipp_stat_t *sp, void *arg, int rw)
{
	ipgpc_class_stats_t *stats = (ipgpc_class_stats_t *)arg;
	classstats_t *cl_stats = (classstats_t *)sp->ipps_data;

	ASSERT(stats != NULL);
	ASSERT(cl_stats != NULL);
	(void) ipp_stat_named_op(&cl_stats->nbytes, &stats->nbytes, rw);
	(void) ipp_stat_named_op(&cl_stats->npackets, &stats->npackets, rw);
	(void) ipp_stat_named_op(&cl_stats->last_match, &stats->last_match, rw);
	return (0);
}
