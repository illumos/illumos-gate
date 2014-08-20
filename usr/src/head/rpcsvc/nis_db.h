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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright (c) 1991,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * This header file defines the interface to the NIS database. All
 * implementations of the database must export at least these routines.
 * They must also follow the conventions set herein. See the implementors
 * guide for specific semantics that are required.
 */

#ifndef	_RPCSVC_NIS_DB_H
#define	_RPCSVC_NIS_DB_H

#include <rpc/rpc.h>
#include <rpcsvc/nis.h>

#ifdef	__cplusplus
extern "C" {
#endif

enum db_status {
	DB_SUCCESS = 0,
	DB_NOTFOUND = 1,
	DB_NOTUNIQUE = 2,
	DB_BADTABLE = 3,
	DB_BADQUERY = 4,
	DB_BADOBJECT = 5,
	DB_MEMORY_LIMIT = 6,
	DB_STORAGE_LIMIT = 7,
	DB_INTERNAL_ERROR = 8
};
typedef enum db_status db_status;

enum db_action {
	DB_LOOKUP = 0,
	DB_REMOVE = 1,
	DB_ADD = 2,
	DB_FIRST = 3,
	DB_NEXT = 4,
	DB_ALL = 5,
	DB_RESET_NEXT = 6
};
typedef enum db_action db_action;

typedef entry_obj *entry_object_p;

typedef struct {
	uint_t db_next_desc_len;
	char *db_next_desc_val;
} db_next_desc;

struct db_result {
	db_status status;
	db_next_desc nextinfo;
	struct {
		uint_t objects_len;
		entry_object_p *objects_val;
	} objects;
	long ticks;
};
typedef struct db_result db_result;

/*
 * Prototypes for the database functions.
 */

extern bool_t db_initialize(char *);
extern db_status db_create_table(char *, table_obj *);
extern db_status db_destroy_table(char *);
extern db_result *db_first_entry(char *, int, nis_attr *);
extern db_result *db_next_entry(char *, db_next_desc *);
extern db_result *db_reset_next_entry(char *, db_next_desc *);
extern db_result *db_list_entries(char *, int, nis_attr *);
extern db_result *db_add_entry(char *, int,  nis_attr *, entry_obj *);
extern db_result *db_remove_entry(char *, int, nis_attr *);
extern db_status db_checkpoint(char *);
extern db_status db_standby(char *);
extern db_status db_table_exists(char *);
extern db_status db_unload_table(char *);
extern void db_free_result(db_result *);

#ifdef __cplusplus
}
#endif

#endif	/* _RPCSVC_NIS_DB_H */
