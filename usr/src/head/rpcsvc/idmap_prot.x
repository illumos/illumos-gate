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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/* opaque type to support non-ASCII strings */
typedef	string	idmap_utf8str<>;

/* Return status */
typedef int idmap_retcode;

/* Identity types */
enum idmap_id_type {
	IDMAP_NONE = 0,
	IDMAP_UID = 1,
	IDMAP_GID,
	IDMAP_SID,
	IDMAP_USID,
	IDMAP_GSID,
	IDMAP_POSIXID
};

/* The type of ID mapping */
enum idmap_map_type {
	IDMAP_MAP_TYPE_UNKNOWN = 0,
	IDMAP_MAP_TYPE_DS_AD,
	IDMAP_MAP_TYPE_DS_NLDAP,
	IDMAP_MAP_TYPE_RULE_BASED,
	IDMAP_MAP_TYPE_EPHEMERAL,
	IDMAP_MAP_TYPE_LOCAL_SID,
	IDMAP_MAP_TYPE_KNOWN_SID
};


/* Source of ID mapping */
enum idmap_map_src {
	IDMAP_MAP_SRC_UNKNOWN = 0,
	IDMAP_MAP_SRC_NEW,
	IDMAP_MAP_SRC_CACHE,
	IDMAP_MAP_SRC_HARD_CODED,
	IDMAP_MAP_SRC_ALGORITHMIC
};


/* SID */
struct idmap_sid {
	string		prefix<>;
	uint32_t	rid;
};

/* Identity (sid-posix) */
union idmap_id switch(idmap_id_type idtype) {
	case IDMAP_UID: uint32_t uid;
	case IDMAP_GID: uint32_t gid;
	case IDMAP_SID: idmap_sid sid;
	case IDMAP_USID: idmap_sid usid;
	case IDMAP_GSID: idmap_sid gsid;
	case IDMAP_NONE: void;
	case IDMAP_POSIXID: void;
};


/* Name-based mapping rules */
struct idmap_namerule {
	bool		is_user;
	bool		is_wuser;
	int		direction;
	idmap_utf8str	windomain;
	idmap_utf8str	winname;
	idmap_utf8str	unixname;
	bool		is_nt4;
};
struct idmap_namerules_res {
	idmap_retcode	retcode;
	uint64_t	lastrowid;
	idmap_namerule	rules<>;
};

/* How ID is mapped */ 
struct idmap_how_ds_based {
	idmap_utf8str	dn;
	idmap_utf8str	attr;
	idmap_utf8str	value;
};
 
union idmap_how switch(idmap_map_type map_type) {
	case IDMAP_MAP_TYPE_UNKNOWN: void;
	case IDMAP_MAP_TYPE_DS_AD: idmap_how_ds_based ad;
	case IDMAP_MAP_TYPE_DS_NLDAP: idmap_how_ds_based nldap;
	case IDMAP_MAP_TYPE_RULE_BASED: idmap_namerule rule;
	case IDMAP_MAP_TYPE_EPHEMERAL: void;
	case IDMAP_MAP_TYPE_LOCAL_SID: void;
	case IDMAP_MAP_TYPE_KNOWN_SID: void;
};

struct idmap_info {
	idmap_map_src	src;
	idmap_how	how;
};


/* Id result */
struct idmap_id_res {
	idmap_retcode	retcode;
	idmap_id	id;
	int		direction;
	idmap_info	info;
};
struct idmap_ids_res {
	idmap_retcode	retcode;
	idmap_id_res	ids<>;
};


/*
 * Flag supported by mapping requests
 */

/* Don't allocate a new value for the mapping */
const IDMAP_REQ_FLG_NO_NEW_ID_ALLOC	= 0x00000001;

/* Validate the given identity before mapping */
const IDMAP_REQ_FLG_VALIDATE		= 0x00000002;

/* Avoid name service lookups to prevent looping */
const IDMAP_REQ_FLG_NO_NAMESERVICE	= 0x00000004;

/* Request how a mapping was formed */
const IDMAP_REQ_FLG_MAPPING_INFO	= 0x00000008;

/*
 * This libidmap only flag is defined in idmap.h
 * It enables use of the libidmap cache
 * const IDMAP_REQ_FLG_USE_CACHE	= 0x00000010;
 */

/* Request mapping for well-known or local SIDs only */
const IDMAP_REQ_FLG_WK_OR_LOCAL_SIDS_ONLY	= 0x00000020;


/*
 * Mapping direction definitions
 */
const IDMAP_DIRECTION_UNDEF =	-1;	/* not defined */
const IDMAP_DIRECTION_BI =	0;	/* bi-directional */
const IDMAP_DIRECTION_W2U =	1;	/* windows to unix only */
const IDMAP_DIRECTION_U2W =	2;	/* unix to windows only */


/* Identity mappings (sid-posix) */
struct idmap_mapping {
	int32_t		flag;
	int		direction;
	idmap_id	id1;
	idmap_utf8str	id1domain;
	idmap_utf8str	id1name;
	idmap_id	id2;
	idmap_utf8str	id2domain;
	idmap_utf8str	id2name;
	idmap_info	info;
};

typedef idmap_mapping	idmap_mapping_batch<>;

struct idmap_mappings_res {
	idmap_retcode		retcode;
	uint64_t		lastrowid;
	idmap_mapping		mappings<>;
};


/* Update result */
struct idmap_update_res {
	idmap_retcode	retcode;
	int64_t	error_index;
	idmap_namerule	error_rule;
	idmap_namerule	conflict_rule;
};

/* Update requests */
enum idmap_opnum {
	OP_NONE = 0,
	OP_ADD_NAMERULE = 1,
	OP_RM_NAMERULE = 2,
	OP_FLUSH_NAMERULES = 3
};
union idmap_update_op switch(idmap_opnum opnum) {
	case OP_ADD_NAMERULE:
	case OP_RM_NAMERULE:
		idmap_namerule rule;
	default:
		void;
};
typedef idmap_update_op idmap_update_batch<>;

const AD_DISC_MAXHOSTNAME = 256;

#ifndef _KERNEL
struct idmap_ad_disc_ds_t {
	int	port;
	int	priority;
	int	weight;
	char	host[AD_DISC_MAXHOSTNAME];
};


/* get-prop, set-prop */
enum idmap_prop_type {
	PROP_UNKNOWN = 0,
	PROP_LIST_SIZE_LIMIT = 1,
	PROP_DEFAULT_DOMAIN = 2,	/* default domain name */
	PROP_DOMAIN_NAME = 3,		/* AD domain name */
	PROP_MACHINE_SID = 4,		/* machine sid */
	PROP_DOMAIN_CONTROLLER = 5,	/* domain controller hosts */
	PROP_FOREST_NAME = 6,		/* forest name */
	PROP_SITE_NAME = 7,		/* site name */
	PROP_GLOBAL_CATALOG = 8,	/* global catalog hosts */
	PROP_AD_UNIXUSER_ATTR = 9,
	PROP_AD_UNIXGROUP_ATTR = 10,
	PROP_NLDAP_WINNAME_ATTR = 11,
	PROP_DS_NAME_MAPPING_ENABLED = 12
};

union idmap_prop_val switch(idmap_prop_type prop) {
	case PROP_LIST_SIZE_LIMIT:
		uint64_t intval;
	case PROP_DEFAULT_DOMAIN:
	case PROP_DOMAIN_NAME:
	case PROP_MACHINE_SID:
	case PROP_FOREST_NAME:
	case PROP_SITE_NAME:
	case PROP_AD_UNIXUSER_ATTR:
	case PROP_AD_UNIXGROUP_ATTR:
	case PROP_NLDAP_WINNAME_ATTR:
		idmap_utf8str utf8val;
	case PROP_DS_NAME_MAPPING_ENABLED:
		bool boolval;
	case PROP_DOMAIN_CONTROLLER:
	case PROP_GLOBAL_CATALOG:
		idmap_ad_disc_ds_t dsval;
	default:
		void;
};

struct idmap_prop_res {
	idmap_retcode	retcode;
	idmap_prop_val	value;
	bool		auto_discovered;
};
#endif

program IDMAP_PROG {
	version IDMAP_V1 {
		void
		IDMAP_NULL(void) = 0;

		/* Batch of requests to get mapped identities */
		idmap_ids_res
		IDMAP_GET_MAPPED_IDS(idmap_mapping_batch batch) = 1;

		/* List all identity mappings */
		idmap_mappings_res
		IDMAP_LIST_MAPPINGS(int64_t lastrowid,
			uint64_t limit, int32_t flag) = 2;

		/* List all name-based mapping rules */
		idmap_namerules_res
		IDMAP_LIST_NAMERULES(idmap_namerule rule,
			uint64_t lastrowid, uint64_t limit) = 3;

		/* Batch of update requests */
		idmap_update_res
		IDMAP_UPDATE(idmap_update_batch batch) = 4;

		/* Get mapped identity by name */
		idmap_mappings_res
		IDMAP_GET_MAPPED_ID_BY_NAME(idmap_mapping request) = 5;

#ifndef _KERNEL 
		/* Get configuration property */
		idmap_prop_res
		IDMAP_GET_PROP(idmap_prop_type) = 6;
#endif

	} = 1;
} = 100172;
