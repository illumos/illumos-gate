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
 *
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SYS_SID_H
#define	_SYS_SID_H

#include <sys/types.h>
#include <sys/avl.h>
#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#include <sys/zone.h>
#endif

/*
 * Kernel SID data structure and functions.
 */
#ifdef __cplusplus
extern "C" {
#endif

/* sidsys subcodes */
#define	SIDSYS_ALLOC_IDS	0
/* Flags for ALLOC_IDS */
#define	SID_EXTEND_RANGE	0
#define	SID_NEW_RANGE		1

#define	SIDSYS_IDMAP_REG	1
#define	SIDSYS_IDMAP_UNREG	2
#define	SIDSYS_IDMAP_FLUSH_KCACHE 3

#define	SIDSYS_SID2ID	0
#define	SIDSYS_ID2SID	1

#if defined(_KERNEL) || defined(_FAKE_KERNEL)
#define	KSIDLIST_MEM(n)	(sizeof (ksidlist_t) + ((n) - 1) * sizeof (ksid_t))

/* Domains are stored in AVL trees so we can share them among SIDs */
typedef struct ksiddomain {
	uint_t		kd_ref;
	uint_t		kd_len;
	char		*kd_name;	/* Domain part of SID */
	avl_node_t	kd_link;
} ksiddomain_t;

typedef struct ksid {
	uid_t		ks_id;		/* Cache of (ephemeral) uid */
	uint32_t	ks_rid;		/* Rid part of the name */
	uint32_t	ks_attr;	/* Attribute */
	ksiddomain_t	*ks_domain;	/* Domain descsriptor */
} ksid_t;

typedef enum ksid_index {
	KSID_USER,
	KSID_GROUP,
	KSID_OWNER,
	KSID_COUNT			/* Must be last */
} ksid_index_t;

/*
 * As no memory may be allocated for credentials while holding p_crlock,
 * all sub data structures need to be ref counted.
 */

typedef struct ksidlist {
	uint_t		ksl_ref;
	uint_t		ksl_nsid;
	uint_t		ksl_neid;	/* Number of ids which are ephemeral */
	ksid_t		ksl_sids[1];	/* Allocate ksl_nsid times */
} ksidlist_t;

typedef struct credsid {
	uint_t		kr_ref;			/* Reference count */
	ksid_t		kr_sidx[KSID_COUNT];	/* User, group, default owner */
	ksidlist_t	*kr_sidlist;		/* List of SIDS */
} credsid_t;

const char *ksid_getdomain(ksid_t *);
uint_t ksid_getrid(ksid_t *);
uid_t ksid_getid(ksid_t *);

int ksid_lookupbyuid(zone_t *, uid_t, ksid_t *);
int ksid_lookupbygid(zone_t *, gid_t, ksid_t *);
void ksid_rele(ksid_t *);

credsid_t *kcrsid_alloc(void);

credsid_t *kcrsid_setsid(credsid_t *, ksid_t *, ksid_index_t);
credsid_t *kcrsid_setsidlist(credsid_t *, ksidlist_t *);

void kcrsid_rele(credsid_t *);
void kcrsid_hold(credsid_t *);
void kcrsidcopy_to(const credsid_t *okcr, credsid_t *nkcr);

void ksiddomain_rele(ksiddomain_t *);
void ksiddomain_hold(ksiddomain_t *);
void ksidlist_rele(ksidlist_t *);
void ksidlist_hold(ksidlist_t *);

ksiddomain_t *ksid_lookupdomain(const char *);

ksidlist_t *kcrsid_gidstosids(zone_t *, int, gid_t *);

#else /* _KERNEL */

int allocids(int, int, uid_t *, int, gid_t *);
int __idmap_reg(int);
int __idmap_unreg(int);
int __idmap_flush_kcache(void);

#endif /* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SID_H */
