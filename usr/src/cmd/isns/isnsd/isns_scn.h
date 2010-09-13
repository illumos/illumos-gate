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

#ifndef	_ISNS_SCN_H
#define	_ISNS_SCN_H

#ifdef __cplusplus
extern "C" {
#endif

/* raw scn data type */
typedef struct scn_raw {
	uint32_t event;
	int type;
	uint32_t uid;
	uchar_t *iscsi;
	uint32_t ref;
	uint32_t ilen;
	uint32_t nt;
	in6_addr_t *ip;
	uint32_t port;
	uint32_t dd_id;
	uint32_t dds_id;
} scn_raw_t;

/* scn context data type */
typedef struct scn_text {
	int flag;
	uint32_t ref;
	uint32_t uid;
	uchar_t *iscsi;
	uint32_t ilen;
	uint32_t nt;
	uint32_t dd_id;
	uint32_t dds_id;
	struct scn_text *next;
} scn_text_t;

/* portal data type stroed in scn registry */
typedef struct scn_portal {
	uint32_t uid;
	int sz;
	union {
		in_addr_t in;
		in6_addr_t *in6;
	} ip;
	uint32_t port;
	uint32_t ref;
	int so;
	struct scn_portal *next;
} scn_portal_t;

typedef struct scn_list {
	union {
		scn_text_t *text;
		scn_portal_t *portal;
	} data;
	struct scn_list *next;
} scn_list_t;

/* scn trigger uint */
typedef struct scn {
	uint32_t event;
	union {
		scn_raw_t *raw;
		scn_list_t *list;
	} data;
	struct scn *next;
} scn_t;

/* scn registry list */
typedef struct scn_registry {
	uint32_t uid;
	uchar_t *name;
	uint32_t nlen;
	uint32_t bitmap;
	union {
		scn_portal_t *p;
		scn_list_t *l;
	} portal;
	scn_t *scn;
	struct scn_registry *next;
} scn_registry_t;


/* function prototypes */
void *scn_proc(void *);

int scn_list_load(uint32_t, uchar_t *, uint32_t, uint32_t);
int verify_scn_portal(void);
int add_scn_entry(uchar_t *, uint32_t, uint32_t);
int remove_scn_entry(uchar_t *);
int remove_scn_portal(uint32_t);
int make_scn(uint32_t, isns_obj_t *);

int connect_to(int, in_addr_t, in6_addr_t *, uint32_t);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_SCN_H */
