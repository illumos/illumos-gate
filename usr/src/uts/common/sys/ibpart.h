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

#ifndef	_SYS_IBPART_H
#define	_SYS_IBPART_H

#include <sys/types.h>
#include <sys/ib/ib_types.h>
#include <sys/dld_ioc.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	IBD_CREATE_IBPART	IBPARTIOC(1)
#define	IBD_DELETE_IBPART	IBPARTIOC(2)
#define	IBD_INFO_IBPART	IBPARTIOC(3)

#define	IBD_INFO_CMD_IBPART	1
#define	IBD_INFO_CMD_IBPORT	2
#define	IBD_INFO_CMD_PKEYTBLSZ	3

typedef enum ibd_part_err_e {
	IBD_INVALID_PORT_INST = 1,
	IBD_PORT_IS_DOWN,
	IBD_PKEY_NOT_PRESENT,
	IBD_INVALID_PKEY,
	IBD_PARTITION_EXISTS,
	IBD_NO_HW_RESOURCE,
	IBD_INVALID_PKEY_TBL_SIZE
} ibd_part_err_t;
/*
 * NOTE: If you change this structure make sure that alignments are correct
 * for the proper operation of the ioctl in both the 32 and 64 bit modes.
 */
typedef struct ibd_ioctl_s {
	int		ioc_info_cmd;
	datalink_id_t	ioc_linkid;
	int		ioc_port_inst;
	uint_t		ioc_portnum;
	ib_guid_t	ioc_hcaguid;
	ib_guid_t	ioc_portguid;
	int		ioc_status;
	uint32_t	align1;
} ibd_ioctl_t;

/*
 * NOTE: If you change this structure make sure that alignments are correct
 * for the proper operation of the ioctl in both the 32 and 64 bit modes.
 */
typedef struct ibpart_ioctl_s {
	ibd_ioctl_t	ibdioc;
	datalink_id_t	ioc_partid;
	boolean_t	ioc_force_create;
	ib_pkey_t	ioc_pkey;
	uint16_t	align1;
	uint32_t	align2;
} ibpart_ioctl_t;

typedef struct ibpart_ioctl_s ibd_create_ioctl_t;
typedef struct ibpart_ioctl_s ibd_delete_ioctl_t;

typedef struct ibport_ioctl_s {
	ibd_ioctl_t	ibdioc;
	uint_t		ioc_pkey_tbl_sz;
	ib_pkey_t	*ioc_pkeys;
} ibport_ioctl_t;

#ifdef _SYSCALL32
typedef struct ibport_ioctl32_s {
	ibd_ioctl_t	ibdioc;
	uint_t		ioc_pkey_tbl_sz;
	caddr32_t	ioc_pkeys;
} ibport_ioctl32_t;
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_IBPART_H */
