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
 *
 * from "tndb.h	7.34	01/08/31 SMI; TSOL 2.x"
 */

#ifndef	_SYS_TSOL_TNDB_H
#define	_SYS_TSOL_TNDB_H

#include <sys/types.h>
#include <sys/zone.h>
#include <sys/tsol/label.h>
#include <sys/tsol/label_macro.h>
#include <net/if.h>

#ifdef _KERNEL
#include <net/route.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/* same on ILP32 and LP64 */
typedef union tnaddr {
	struct sockaddr_in	ip_addr_v4;
	struct sockaddr_in6	ip_addr_v6;
} tnaddr_t;

#define	ta_family	ip_addr_v4.sin_family
#define	ta_addr_v4	ip_addr_v4.sin_addr
#define	ta_addr_v6	ip_addr_v6.sin6_addr
#define	ta_port_v4	ip_addr_v4.sin_port
#define	ta_port_v6	ip_addr_v6.sin6_port

#define	TNADDR_EQ(addr1, addr2) \
	(((addr1)->ta_family == AF_INET && (addr2)->ta_family == AF_INET && \
	(addr1)->ta_addr_v4.s_addr == (addr2)->ta_addr_v4.s_addr) || \
	((addr1)->ta_family == AF_INET6 && (addr2)->ta_family == AF_INET6 && \
	IN6_ARE_ADDR_EQUAL(&(addr1)->ta_addr_v6, &(addr2)->ta_addr_v6)))

/*
 * structure for TN database access routines and TN system calls
 */

typedef enum tsol_dbops {
	TNDB_NOOP = 0,
	TNDB_LOAD = 1,
	TNDB_DELETE = 2,
	TNDB_FLUSH = 3,
	TNDB_GET = 5
} tsol_dbops_t;

#define	TNTNAMSIZ 	ZONENAME_MAX	/* template name size */
#define	IP_STR_SIZE 	200		/* string ip address size */

#define	TNRHDB_NCOL	2		/* # of columns in tnrhdb */

/*
 * For tnrhdb access library routines and tnrh(2TSOL)
 * same for both ILP32 and LP64.
 */
typedef struct tsol_rhent {
	short rh_prefix;		/* length of subnet mask */
	short rh_unused;		/* padding */
	tnaddr_t rh_address;		/* IP address */
	char rh_template[TNTNAMSIZ];	/* template name */
} tsol_rhent_t;

typedef struct tsol_rhstr_s {
	int	family;
	char	*address;
	char	*template;
} tsol_rhstr_t;

/*
 * host types recognized by tsol hosts
 */
typedef enum {
	UNLABELED	= 1,
	SUN_CIPSO	= 3
} tsol_host_type_t;

typedef enum {
	OPT_NONE	= 0,
	OPT_CIPSO	= 1
} tsol_ip_label_t;

typedef struct cipso_tag_type_1 {
	uchar_t	tag_type;		/* Tag Type (1) */
	uchar_t	tag_length;		/* Length of Tag */
	uchar_t	tag_align;		/* Alignment Octet */
	uchar_t	tag_sl;			/* Sensitivity Level */
	uchar_t	tag_cat[1];		/* Categories */
} cipso_tag_type_1_t;

#define	TSOL_CIPSO_MIN_LENGTH 6
#define	TSOL_CIPSO_MAX_LENGTH IP_MAX_OPT_LENGTH
#define	TSOL_TT1_MIN_LENGTH 4
#define	TSOL_TT1_MAX_LENGTH 34

#define	TSOL_CIPSO_DOI_OFFSET 2
#define	TSOL_CIPSO_TAG_OFFSET 6

typedef struct cipso_option {
	uchar_t	cipso_type;		/* Type of option (134) */
	uchar_t	cipso_length;		/* Length of option */
	uchar_t	cipso_doi[4];		/* Domain of Interpretation */
	uchar_t	cipso_tag_type[1];	/* variable length */
} cipso_option_t;

/*
 * RIPSO classifications
 */
#define	TSOL_CL_TOP_SECRET 0x3d
#define	TSOL_CL_SECRET 0x5a
#define	TSOL_CL_CONFIDENTIAL 0x96
#define	TSOL_CL_UNCLASSIFIED 0xab

/*
 * RIPSO protection authorities
 */
#define	TSOL_PA_GENSER 0x80
#define	TSOL_PA_SIOP_ESI 0x40
#define	TSOL_PA_SCI 0x20
#define	TSOL_PA_NSA 0x10
#define	TSOL_PA_DOE 0x08

/*
 * this mask is only used for tndb structures, and is different
 * from t6mask_t bits definitions
 */

typedef unsigned int tnmask_t;

/*
 * unlabeled host structure for the tnrhtp template.
 * same for both ILP32 and LP64.
 */
struct tsol_unl {
	tnmask_t mask; /* tells which attributes are returned by the library */
	bslabel_t def_label;	/* default label */
	brange_t gw_sl_range;	/* for routing only */
	blset_t sl_set;		/* label set */
};

/*
 * CIPSO host structure for the tnrhtp template
 * same for both ILP32 and LP64.
 */
struct tsol_cipso {
	tnmask_t mask; /* tells which attributes are returned by the library */
	bclear_t def_cl;	/* default clearance */
	brange_t sl_range;	/* min/max SL range */
	blset_t sl_set;		/* label set */
};

/*
 * Valid keys and values of the key=value pairs for tnrhtp
 */
#define	TP_UNLABELED	"unlabeled"
#define	TP_CIPSO	"cipso"
#define	TP_ZONE		"zone"
#define	TP_HOSTTYPE	"host_type"
#define	TP_DOI		"doi"
#define	TP_DEFLABEL	"def_label"
#define	TP_MINLABEL	"min_sl"
#define	TP_MAXLABEL	"max_sl"
#define	TP_SET		"sl_set"

#define	TP_COMMA	","

#define	TNRHTP_NCOL	2	/* # of columns in tnrhtp */

/*
 * For tnrhtp access library routines and tnrhtp(2TSOL)
 * same for both ILP32 and LP64.
 */
typedef struct tsol_tpent {
	char name[TNTNAMSIZ]; /* template name */
	tsol_host_type_t host_type; /* specifies host type */
	int tp_doi;		/* Domain of Interpretation */
#define	tp_cipso_doi_unl	tp_doi
#define	tp_cipso_doi_cipso	tp_doi
	union {
		struct tsol_unl unl; /* template for unlabeled */
#define	tp_mask_unl		un.unl.mask
#define	tp_def_label		un.unl.def_label
#define	tp_gw_sl_range		un.unl.gw_sl_range
#define	tp_gw_sl_set		un.unl.sl_set

		struct tsol_cipso cipso; /* template for CIPSO */
#define	tp_mask_cipso		un.cipso.mask
#define	tp_def_cl_cipso		un.cipso.def_cl
#define	tp_sl_range_cipso	un.cipso.sl_range
#define	tp_sl_set_cipso		un.cipso.sl_set
	} un;
} tsol_tpent_t;

typedef struct tsol_tpstr_s {
	char	*template;
	char	*attrs;
} tsol_tpstr_t;

/*
 * For tnmlp(2TSOL); same for both ILP32 and LP64.
 */
typedef struct tsol_mlpent {
	zoneid_t	tsme_zoneid;
	uint_t		tsme_flags;	/* TSOL_MEF_* */
	tsol_mlp_t	tsme_mlp;
} tsol_mlpent_t;

#define	TSOL_MEF_SHARED	0x00000001	/* MLP defined on shared addresses */

/*
 * For tnzonecfg access library routines.
 * List of MLPs ends with null entry, where protocol and port are both zero.
 */
typedef struct tsol_zcent {
	char		zc_name[ZONENAME_MAX];
	int		zc_doi;
	bslabel_t	zc_label;
	int		zc_match;
	tsol_mlp_t	*zc_private_mlp;
	tsol_mlp_t	*zc_shared_mlp;
} tsol_zcent_t;
#define	TSOL_MLP_END(mlp)	((mlp)->mlp_ipp == 0 && (mlp)->mlp_port == 0)

typedef struct tsol_tpc {
	kmutex_t		tpc_lock;	/* lock for structure */
	uint_t			tpc_refcnt;	/* reference count */
	boolean_t		tpc_invalid;	/* entry has been deleted */
	struct tsol_tpent	tpc_tp;		/* template */
} tsol_tpc_t;

typedef struct tsol_tnrhc {
	struct tsol_tnrhc 	*rhc_next;	/* link to next entry */
	kmutex_t		rhc_lock;	/* lock for structure */
	tnaddr_t		rhc_host;	/* IPv4/IPv6 host address */
	tsol_tpc_t		*rhc_tpc;	/* pointer to template */
	uint_t			rhc_refcnt;	/* Number of references */
	char			rhc_invalid;	/* out-of-date rhc */
	char			rhc_isbcast;	/* broadcast address */
	char			rhc_local;	/* loopback or local interace */
} tsol_tnrhc_t;

/* Size of remote host hash tables in kernel */
#define	TNRHC_SIZE 256
#define	TSOL_MASK_TABLE_SIZE	33
#define	TSOL_MASK_TABLE_SIZE_V6	129

#ifdef	_KERNEL
#define	TNRHC_HOLD(a)	{					\
	mutex_enter(&(a)->rhc_lock);				\
	(a)->rhc_refcnt++;					\
	ASSERT((a)->rhc_refcnt > 0);				\
	mutex_exit(&(a)->rhc_lock);				\
}
#define	TNRHC_RELE(a)	{					\
	mutex_enter(&(a)->rhc_lock);				\
	ASSERT((a)->rhc_refcnt > 0);				\
	if (--(a)->rhc_refcnt <= 0)				\
		tnrhc_free(a);					\
	else							\
		mutex_exit(&(a)->rhc_lock);			\
}
extern void tnrhc_free(tsol_tnrhc_t *);
#define	TPC_HOLD(a)	{					\
	mutex_enter(&(a)->tpc_lock);				\
	(a)->tpc_refcnt++;					\
	ASSERT((a)->tpc_refcnt > 0);				\
	mutex_exit(&(a)->tpc_lock);				\
}
#define	TPC_RELE(a)	{					\
	mutex_enter(&(a)->tpc_lock);				\
	ASSERT((a)->tpc_refcnt > 0);				\
	if (--(a)->tpc_refcnt <= 0)				\
		tpc_free(a);					\
	else							\
		mutex_exit(&(a)->tpc_lock);			\
}
extern void tpc_free(tsol_tpc_t *);
#endif	/* _KERNEL */

/*
 * The next three hashing macros are copied from macros in ip_ire.h.
 */
#define	TSOL_ADDR_HASH(addr, table_size)				\
	(((((addr) >> 16) ^ (addr)) ^ ((((addr) >> 16) ^ (addr))>> 8))	\
	% (table_size))

#define	TSOL_ADDR_HASH_V6(addr, table_size)				\
	(((addr).s6_addr8[8] ^ (addr).s6_addr8[9] ^			\
	(addr).s6_addr8[10] ^ (addr).s6_addr8[13] ^			\
	(addr).s6_addr8[14] ^ (addr).s6_addr8[15]) % (table_size))

/* This assumes that table_size is a power of 2. */
#define	TSOL_ADDR_MASK_HASH_V6(addr, mask, table_size)                   \
	((((addr).s6_addr8[8] & (mask).s6_addr8[8]) ^                   \
	((addr).s6_addr8[9] & (mask).s6_addr8[9]) ^                     \
	((addr).s6_addr8[10] & (mask).s6_addr8[10]) ^                   \
	((addr).s6_addr8[13] & (mask).s6_addr8[13]) ^                   \
	((addr).s6_addr8[14] & (mask).s6_addr8[14]) ^                   \
	((addr).s6_addr8[15] & (mask).s6_addr8[15])) & ((table_size) - 1))


/*
 * Constants used for getting the mask value in struct tsol_tpent
 */
enum {
	TNT_DEF_LABEL,
	TNT_DEF_CL,
	TNT_SL_RANGE_TSOL, /* use this for both unl and zone */
	TNT_CIPSO_DOI
};

/*
 * mask definitions
 */
#define	tsol_tntmask(value) ((unsigned int)(1<<(value)))

#define	TSOL_MSK_DEF_LABEL tsol_tntmask(TNT_DEF_LABEL)
#define	TSOL_MSK_DEF_CL tsol_tntmask(TNT_DEF_CL)
#define	TSOL_MSK_SL_RANGE_TSOL tsol_tntmask(TNT_SL_RANGE_TSOL)
#define	TSOL_MSK_CIPSO_DOI tsol_tntmask(TNT_CIPSO_DOI)

/*
 * TN errors
 */
#define	TSOL_PARSE_ERANGE 1 /* result buffer not allocated */
#define	TSOL_NOT_SUPPORTED 2 /* address family not supported */
#define	TSOL_NOT_FOUND 3 /* search by * routines target not found */

/*
 * Structure used to hold a list of IP addresses.
 */
typedef struct tsol_address {
	struct tsol_address	*next;
	in_addr_t		ip_address;
} tsol_address_t;

/* This is shared between tcache and mdb */
typedef struct tnrhc_hash_s {
	tsol_tnrhc_t *tnrh_list;
	kmutex_t tnrh_lock;
} tnrhc_hash_t;

#ifdef _KERNEL
typedef enum {
	mlptSingle,
	mlptPrivate,
	mlptShared,
	mlptBoth
} mlp_type_t;

extern tsol_tpc_t *find_tpc(const void *, uchar_t, boolean_t);
extern void tcache_init(void);
extern in_port_t tsol_next_port(zone_t *, in_port_t, int, boolean_t);
extern mlp_type_t tsol_mlp_port_type(zone_t *, uchar_t, uint16_t, mlp_type_t);
extern zoneid_t tsol_mlp_findzone(uchar_t, uint16_t);
extern int tsol_mlp_anon(zone_t *, mlp_type_t, uchar_t, uint16_t, boolean_t);
extern void tsol_print_label(const blevel_t *, const char *);

struct tsol_gc_s;
struct tsol_gcgrp_s;
struct tsol_gcgrp_addr_s;

extern struct tsol_gc_s *gc_create(struct rtsa_s *, struct tsol_gcgrp_s *,
    boolean_t *);
extern void gc_inactive(struct tsol_gc_s *);
extern int rtsa_validate(const struct rtsa_s *);
extern struct tsol_gcgrp_s *gcgrp_lookup(struct tsol_gcgrp_addr_s *, boolean_t);
extern void gcgrp_inactive(struct tsol_gcgrp_s *);
extern int tnrh_load(const tsol_rhent_t *);
#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TSOL_TNDB_H */
