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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_POOL_IMPL_H
#define	_SYS_POOL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/cpupart.h>
#include <sys/exacct_catalog.h>
#include <sys/nvpair.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Pools driver ioctl interfaces
 */
#define	POOL_STATUS	0
#define	POOL_STATUSQ	1
#define	POOL_CREATE	2
#define	POOL_DESTROY	3
#define	POOL_QUERY	4
#define	POOL_ASSOC	5
#define	POOL_DISSOC	6
#define	POOL_TRANSFER	7
#define	POOL_XTRANSFER	8
#define	POOL_PROPGET	9
#define	POOL_PROPPUT	10
#define	POOL_PROPRM	11
#define	POOL_BIND	12
#define	POOL_BINDQ	13
#define	POOL_COMMIT	14

/*
 * Pools-related exacct catalog IDs
 */
#define	EXD_GROUP_SYSTEM	0x000000
#define	EXD_SYSTEM_PROP		0x000001
#define	EXD_SYSTEM_TSTAMP	0x000002

#define	EXD_GROUP_POOL		0x000100
#define	EXD_POOL_POOLID		0x000101
#define	EXD_POOL_PSETID		0x000102
#define	EXD_POOL_PROP		0x000104
#define	EXD_POOL_TSTAMP		0x000105

#define	EXD_GROUP_PSET		0x000200
#define	EXD_PSET_PSETID		0x000201
#define	EXD_PSET_PROP		0x000202
#define	EXD_PSET_TSTAMP		0x000203

#define	EXD_GROUP_CPU		0x000400
#define	EXD_CPU_CPUID		0x000401
#define	EXD_CPU_PROP		0x000402
#define	EXD_CPU_TSTAMP		0x000403

/*
 * Element Types
 */
typedef enum pool_elem_class {
	PEC_INVALID = 0,	/* invalid class, for error reporting */
	PEC_SYSTEM,		/* a system */
	PEC_POOL,		/* a pool */
	PEC_RES_COMP,		/* a set */
	PEC_RES_AGG,		/* a set */
	PEC_COMP		/* a resource component */
} pool_elem_class_t;

typedef enum pool_resource_elem_class {
	PREC_INVALID = 0,
	PREC_PSET		/* processor set */
} pool_resource_elem_class_t;

typedef enum pool_component_elem_class {
	PCEC_INVALID = 0,
	PCEC_CPU		/* CPU */
} pool_component_elem_class_t;

/*
 * Constants used by devpool.
 */
#define	POOL_IDLIST_SIZE	1024
#define	POOL_PROPNAME_SIZE	8192
#define	POOL_PROPBUF_SIZE	65535

typedef struct pool_status {
	int				ps_io_state;
} pool_status_t;

typedef struct pool_create {
	id_t				pc_i_id;
	int				pc_o_type;
	int				pc_o_sub_type;
} pool_create_t;

typedef struct pool_destroy {
	int				pd_o_type;
	int				pd_o_sub_type;
	id_t				pd_o_id;
} pool_destroy_t;

typedef struct pool_query {
	size_t				pq_io_bufsize;
	void				*pq_io_buf;
} pool_query_t;

#ifdef	_SYSCALL32
typedef struct pool_query32 {
	size32_t			pq_io_bufsize;
	caddr32_t			pq_io_buf;
} pool_query32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_assoc {
	poolid_t			pa_o_pool_id;
	pool_resource_elem_class_t	pa_o_id_type;
	id_t				pa_o_res_id;
} pool_assoc_t;

typedef struct pool_dissoc {
	poolid_t			pd_o_pool_id;
	pool_resource_elem_class_t	pd_o_id_type;
} pool_dissoc_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

typedef struct pool_transfer {
	pool_resource_elem_class_t	pt_o_id_type;
	id_t				pt_o_src_id;
	id_t				pt_o_tgt_id;
	uint64_t			pt_o_qty;
} pool_transfer_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

typedef struct pool_xtransfer {
	pool_resource_elem_class_t	px_o_id_type;
	id_t				px_o_src_id;
	id_t				px_o_tgt_id;
	uint_t				px_o_complist_size;
	id_t				*px_o_comp_list;
} pool_xtransfer_t;

#ifdef	_SYSCALL32
typedef struct pool_xtransfer32 {
	pool_resource_elem_class_t	px_o_id_type;
	id_t				px_o_src_id;
	id_t				px_o_tgt_id;
	uint_t				px_o_complist_size;
	caddr32_t			px_o_comp_list;
} pool_xtransfer32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_propget {
	size_t				pp_i_bufsize;
	char				*pp_i_buf;
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_subtype;
	id_t				pp_o_id;
	uint_t				pp_o_prop_name_size;
	char				*pp_o_prop_name;
} pool_propget_t;

#ifdef	_SYSCALL32
typedef	struct pool_propget32 {
	size32_t			pp_i_bufsize;
	caddr32_t			pp_i_buf;
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_subtype;
	id_t				pp_o_id;
	uint_t				pp_o_prop_name_size;
	caddr32_t			pp_o_prop_name;
} pool_propget32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_propgetall {
	size_t				pp_i_proplist_size;
	char				*pp_i_prop_list;
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
} pool_propgetall_t;

#ifdef	_SYSCALL32
typedef struct pool_propgetall32 {
	size32_t			pp_i_proplist_size;
	caddr32_t			pp_i_prop_list;
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
} pool_propgetall32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_propput {
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
	size_t				pp_o_bufsize;
	char				*pp_o_buf;
} pool_propput_t;

#ifdef	_SYSCALL32
typedef struct pool_propput32 {
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
	size32_t			pp_o_bufsize;
	caddr32_t			pp_o_buf;
} pool_propput32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_proprm {
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
	size_t				pp_o_prop_name_size;
	char				*pp_o_prop_name;
} pool_proprm_t;

#ifdef	_SYSCALL32
typedef struct pool_proprm32 {
	pool_elem_class_t		pp_o_id_type;
	pool_resource_elem_class_t	pp_o_id_sub_type;
	id_t				pp_o_id;
	size32_t			pp_o_prop_name_size;
	caddr32_t			pp_o_prop_name;
} pool_proprm32_t;
#endif	/* _SYSCALL32 */

typedef struct pool_bind {
	idtype_t			pb_o_id_type;
	id_t				pb_o_pool_id;
	id_t				pb_o_id;
} pool_bind_t;

typedef struct pool_bindq {
	idtype_t			pb_o_id_type;
	poolid_t			pb_i_id;
	id_t				pb_o_id;
} pool_bindq_t;

/*
 * Values for pp_type below
 */
#define	PP_READ		0x0001
#define	PP_WRITE	0x0002
#define	PP_RDWR		0x0003
#define	PP_OPTIONAL	0x0004
#define	PP_STORED	0x0008
#define	PP_INIT		0x0010
#define	PP_HIDDEN	0x0020

#ifdef	_KERNEL

/*
 * For special properties
 */
typedef struct pool_property {
	char		*pp_name;	/* name of the property */
	data_type_t	pp_type;	/* type of the property */
	int		pp_perm;	/* permissions */
} pool_property_t;

extern int pool_propput_common(nvlist_t *, nvpair_t *, pool_property_t *);
extern int pool_proprm_common(nvlist_t *, char *, pool_property_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_POOL_IMPL_H */
