/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2021 Tintri by DDN, Inc. All rights reserved.
 */

#ifndef _COMMON_H
#define	_COMMON_H

#include <sys/zone.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <rpc/svc.h>
#include <nfs/nfs.h>

extern int zoned_zsd_find_by_key(uintptr_t, zone_key_t, uintptr_t *);
extern int zoned_get_nfs_globals(uintptr_t, uintptr_t *);
extern int zoned_get_zsd(uintptr_t, char *, uintptr_t *);

extern const char *common_mutex(kmutex_t *);
extern const char *common_rwlock(krwlock_t *);
extern const char *common_netbuf_str(struct netbuf *);

/*
 * Generic hash table walker
 *
 * Generic hash table is an array of head structures starting at address
 * array_addr. The number of the head structures in the array is array_len.
 * Size of the head structure is head_size. There is a pointer in the head
 * structure called first_name with offset first_offset that points to the
 * linked list of member structures. The member structure type name is stored
 * in member_type_name.  Size of the member structure is member_size. The
 * member structure have a pointer to the next member structure at offset
 * next_offset.
 *
 * A pointer to the hash_table_walk_arg_t should be passed as walk_arg to the
 * hash_table_walk_init().
 */

typedef struct hash_table_walk_arg {
	uintptr_t array_addr;
	int array_len;
	size_t head_size;
	const char *first_name;
	size_t first_offset;
	const char *member_type_name;
	size_t member_size;
	size_t next_offset;
} hash_table_walk_arg_t;

extern int hash_table_walk_init(mdb_walk_state_t *);
extern int hash_table_walk_step(mdb_walk_state_t *);
extern void hash_table_walk_fini(mdb_walk_state_t *);

#endif	/* _COMMON_H */
