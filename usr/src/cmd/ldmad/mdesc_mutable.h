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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MDESC_MUTABLE_H_
#define	_MDESC_MUTABLE_H_

#ifdef DEBUG
#include <assert.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifdef DEBUG

#define	ASSERT(_s)	assert(_s)

#else	/* DEBUG */

#define	ASSERT(_s)

#endif	/* DEBUG */

#define	MD_ALIGNMENT_SIZE	0x10
#define	MD_OFFSET_UNDEF		(uint32_t)-1
/*
 * List management macros for mutable MD structure
 */
#define	CHAIN(_type, _chain)						\
	struct {							\
		_type	*startp;					\
		_type	*endp;						\
		int	count;						\
	} _chain

#define	CHAIN_ITER(_chain, _itv)					\
	for ((_itv) = CHAIN_START(_chain); (_itv) != NULL;		\
		(_itv) = (_itv)->nextp)

#define	CHAIN_START(_name)	((_name).startp)
#define	CHAIN_LENGTH(_name)	((_name).count)

/*
 * Add node _nodep to the end of _chain via the required 'nextp' element.
 */
#define	CHAIN_ADD(_chain, _nodep)					\
	do {								\
		if ((_chain).startp == NULL) {				\
			(_chain).startp = (_nodep);			\
		} else {						\
			(_chain).endp->nextp = (_nodep);		\
		}							\
		(_chain).endp = (_nodep);				\
		(_nodep)->nextp = NULL;					\
		(_chain).count++;					\
	NOTE(CONSTCOND) } while (0)

/*
 * Internal definitions.
 */

typedef struct md_string md_string_t;
typedef struct md_data_block md_data_block_t;
typedef struct md_prop md_prop_t;
typedef struct md_node md_node_t;
typedef struct mmd mmd_t;

struct md_string {
	md_string_t	*nextp;
	char		*strp;
	int		size;	/* strlen()+1 */
	uint32_t	hash;
	int		ref_cnt;
	uint32_t	build_offset;
};

struct md_data_block {
	md_data_block_t *nextp;
	uint8_t		*datap;
	uint32_t	size;
	uint32_t	hash;
	int		ref_cnt;
	uint32_t	build_offset;
};

struct md_prop {
	uint8_t		type;
	md_string_t	*sp;
	union {
		uint64_t	value;
		struct {
			boolean_t	is_ptr;
			union {
				uint64_t	index;
				md_node_t	*nodep;
			} val;
		} arc;
		md_data_block_t *dbp;
	} d;
	md_prop_t	*nextp;
};

struct md_node {
	md_string_t	*typep;
	CHAIN(md_prop_t, prop_list);
	md_node_t	*nextp;
	int		build_index;	/* for building a binary md & cloning */
	int		next_index;	/* for building a binary md */
	char		seen;		/* seen flag (md_scan_dag/md_scour) */
	char		deleted;	/* pending deletion flag */
};

struct mmd {
	CHAIN(md_node_t, node_list);
	CHAIN(md_string_t, string_list);
	CHAIN(md_data_block_t, data_block_list);
};

md_node_t *md_new_node(mmd_t *mdp, char *sp);
int md_add_value_property(mmd_t *mdp,
    md_node_t *nodep, char *sp, uint64_t value);
int md_add_string_property(mmd_t *mdp, md_node_t *nodep, char *sp, char *bufp);
int md_add_data_property(mmd_t *mdp, md_node_t *nodep, char *sp, int len,
    uint8_t *bufp);
int md_gen_bin(mmd_t *mdp, uint8_t **bufpp);
md_node_t *md_link_new_node(mmd_t *mdp, char *nodenamep, md_node_t *parentnodep,
    char *linktonewp, char *linkbackp);
mmd_t *md_new_md(void);
void md_free_node(mmd_t *mdp, md_node_t *nodep);
void md_destroy(mmd_t *);

#ifdef __cplusplus
}
#endif

#endif	/* _MDESC_MUTABLE_H_ */
