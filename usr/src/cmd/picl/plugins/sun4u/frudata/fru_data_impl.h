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
 * Copyright (c) 2000-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */


#ifndef	_FRU_DATA_IMPL_H
#define	_FRU_DATA_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include "libfru.h"
#include "picldefs.h"
#include "fru_access.h"

#define	TABLE_SIZE			64	/* hash table size */

#define	NUM_OF_COL_IN_PKT_TABLE		2

#define	FRUTREE_PATH		"/frutree"  /* picltree path of frutree node */

#define	FRUDATA_CONFFILE_NAME	\
		"/usr/platform/%s/lib/picl/plugins/libpiclfrudata.conf"

#define	SECNAMESIZE		10	/* section name length */

typedef	enum {CONTAINER_NODE, SECTION_NODE, SEGMENT_NODE, PACKET_NODE} node_t;

typedef	uint64_t		fru_access_hdl_t;

struct	hash_obj;

typedef struct {
	fru_access_hdl_t	pkt_handle;	/* fru access handle */
	size_t			paylen;		/* payload length */
	fru_tag_t		tag;
	struct hash_obj		*next;
} packet_node_t;

typedef struct {
	fru_access_hdl_t	segment_hdl;	/* fru_access handle */
	picl_nodehdl_t		sec_nodehdl;	/* section node handle */
	int			num_of_pkt;	/* number of packet */
	struct hash_obj		*packet_list;
	struct hash_obj		*next;
} segment_node_t;

typedef struct {
	fru_access_hdl_t	section_hdl;	/* fru_access handle */
	picl_nodehdl_t		container_hdl;	/* container node hdl. */
	int			num_of_segment; /* number of segment */
	struct hash_obj		*segment_list;
	struct hash_obj		*next;
} section_node_t;

typedef struct {
	fru_access_hdl_t	cont_hdl;	/* fru_access handle */
	int			num_of_section; /* number of section */
	struct hash_obj		*section_list;
} container_node_t;

typedef	struct	hash_obj {
	uint64_t	picl_hdl;		/* picl node/property handle */
	node_t		object_type;
	union	{
		container_node_t	*cont_node;	/* container */
		section_node_t		*sec_node;	/* section   */
		segment_node_t		*seg_node;	/* segment   */
		packet_node_t		*pkt_node;	/* packet    */
	} u;
	struct hash_obj		*next;
	struct hash_obj		*prev;
} hash_obj_t;

typedef	struct  container_tbl {
	uint64_t		picl_hdl;
	pthread_rwlock_t	rwlock;
	pthread_cond_t		cond_var;
	hash_obj_t		*hash_obj;
	struct  container_tbl	*next;
	struct  container_tbl	*prev;
} container_tbl_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _FRU_DATA_IMPL_H */
