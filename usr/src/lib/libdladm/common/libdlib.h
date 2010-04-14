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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _LIBDLIB_H
#define	_LIBDLIB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/ib/ib_types.h>

#define	MAXPKEYSTRSZ	968
#define	MAXPKEYLEN 6
#define	IBGUIDSTRLEN 16
#define	IBPORTSTRLEN 5

#define	DLADM_IBPART_FORCE_CREATE 0x1

typedef struct dladm_ib_attr_s {
	datalink_id_t	dia_physlinkid;	/* IB Phys link datalink ID */
	datalink_id_t	dia_partlinkid;	/* IB Partition datalink ID */
	ib_pkey_t	dia_pkey;	/* IB partitions P_Key */
	uint32_t	dia_flags;
	char		*dia_devname;	/* IB Phys link's device name */
	char		*dia_pname;	/* IB partition's name */
	uint_t		dia_portnum;	/* IB Phys link's HCA port number */
	int		dia_instance;	/* IP over IB driver instance number */
	ib_guid_t	dia_hca_guid;	/* IB HCA GUID */
	ib_guid_t	dia_port_guid;	/* IB HCA Port GUID */
	uint_t		dia_port_pkey_tbl_sz;
	ib_pkey_t	*dia_port_pkeys;	/* Ptr to the P_Key table */
} dladm_ib_attr_t;

typedef struct dladm_ib_attr_s dladm_part_attr_t;

typedef enum {
	DLADM_IBPART_UD_MODE = 0,
	DLADM_IBPART_CM_MODE
} dladm_ibpart_linkmode_t;

extern dladm_status_t dladm_part_create(dladm_handle_t, datalink_id_t,
    ib_pkey_t, uint32_t, char *, datalink_id_t *, dladm_arg_list_t *);
extern dladm_status_t dladm_part_delete(dladm_handle_t, datalink_id_t, int);
extern dladm_status_t dladm_part_up(dladm_handle_t, datalink_id_t, uint32_t);
extern dladm_status_t dladm_part_info(dladm_handle_t, datalink_id_t,
    dladm_part_attr_t *, uint32_t);
extern dladm_status_t dladm_ib_info(dladm_handle_t, datalink_id_t,
    dladm_ib_attr_t *, uint32_t);
extern void dladm_free_ib_info(dladm_ib_attr_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _LIBDLIB_H */
