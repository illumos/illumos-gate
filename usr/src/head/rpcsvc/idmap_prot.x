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

%#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
struct idmap_id_res {
	idmap_retcode	retcode;
	idmap_id	id;
	int		direction;
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
};
struct idmap_mappings_res {
	idmap_retcode		retcode;
	uint64_t		lastrowid;
	idmap_mapping		mappings<>;
};
typedef idmap_mapping	idmap_mapping_batch<>;


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
			uint64_t limit) = 2;

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

	} = 1;
} = 100172;
