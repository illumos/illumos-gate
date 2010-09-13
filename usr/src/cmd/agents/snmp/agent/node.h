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
 *
 * Copyright 1999 Sun Microsystems, Inc.  All Rights Reserved.
 * Use is subject to license terms.
 */

#ifndef _NODE_H_
#define _NODE_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "asn1.h"
#define COLUMN		1
#define OBJECT		2
#define NODE		3

#define READ_FLAG	0x1
#define WRITE_FLAG	0x2


typedef struct _Enum {
	struct _Enum *next_enum;
	char *label;
	Integer value;
} Enum;

typedef struct _Object {
	Oid name;
	u_char asn1_type;
	Enum *first_enum;
	int access;
        int type;
	int (*get)();
	int (*set)();
	void (*dealloc)();
} Object;

typedef struct _Index {
	struct _Index *next_index;
	char *label;
        int index_type;
        int index_len;         /* for strings only */
	struct _Node *node;
} Index;

typedef struct _Entry {
	struct _Index *first_index;
	int n_indexs;
	int (*get)();
	void (*dealloc)();
} Entry;


typedef struct _Column {
	Oid name;
	u_char asn1_type;
	Enum *first_enum;
	int access;
        int type;
        int (*get)();
	int (*set)();
	Entry *entry;
	int offset;
} Column;


typedef struct _Node {
	struct _Node *parent;
	struct _Node *first_child;
	struct _Node *next_peer;
	struct _Node *next;

	char *label;
	Subid subid;

	int type;
	union {
		Object *object;
		Column *column;
	} data;
} Node;

struct CallbackItem {
        Object *ptr;
        int type,next;
};
struct TrapHndlCxt {
        char name[256];
        int is_sun_enterprise;
        int generic,specific;
};

struct TrapEnterpriseInfo {
        Subid subids[7];
};

/* Handling arbitrary length enterprise OID in traps */
struct TrapAnyEnterpriseInfo {
        Subid subids[MAX_OID_LEN+1];
};


extern Enum enum_table[];
extern int enum_table_size;

extern Object object_table[];
extern int object_table_size;

extern Index index_table[];
extern int index_table_size;

extern Entry entry_table[];
extern int entry_table_size;

extern Column column_table[];
extern int column_table_size;

extern Node node_table[];
extern int node_table_size;

extern struct CallbackItem *callItem;
extern int numCallItem;

extern int *trapTableMap;

extern struct TrapHndlCxt *trapBucket;
extern int numTrapElem;

extern struct TrapEnterpriseInfo *trapEnterpriseInfo;
/* For arbitrary length enterprise OID in traps - bug 4133978 */
extern struct TrapAnyEnterpriseInfo *trapAnyEnterpriseInfo;


extern Node *node_find(int search_type, Oid *name, Oid *suffix);

#endif
