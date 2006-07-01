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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _T10_OSD_H
#define	_T10_OSD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Defines and structures for Object-Base Storage Device emulation
 */

/*
 * OSD revision 10, section 4.6.2
 * Partition_ID and User_Object_ID value assignments
 */
#define	OSD_PARTITION_ROOT	0x00LL
#define	OSD_PARTITION_BASE	0x10000LL
#define	OSD_USER_OBJ_ROOT	0x00LL
#define	OSD_USER_OBJ_BASE	0x10000LL

/*
 * OSD revision 10, section 6.1
 * Commands for OSD type devices
 */
#define	OSD_APPEND		0x8807
#define	OSD_CREATE		0x8802
#define	OSD_CREATE_AND_WRITE	0x8812
#define	OSD_CREATE_COLLECTION	0x8815
#define	OSD_CREATE_PARTITION	0x880b
#define	OSD_FLUSH		0x8808
#define	OSD_FLUSH_COLLECTION	0x881a
#define	OSD_FLUSH_OSD		0x881c
#define	OSD_FLUSH_PARTITION	0x881b
#define	OSD_FORMAT_OSD		0x8801
#define	OSD_GET_ATTR		0x880e
#define	OSD_LIST		0x8803
#define	OSD_LIST_COLLECTION	0x8817
#define	OSD_PERFORM_SCSI	0x8f7e
#define	OSD_TASK_MGMT		0x8f7f

typedef uint64_t	osd_obj_id_t;

typedef struct osd_params {
	uint64_t	o_size;
} osd_params_t;

/*
 * OSD revision 10, section 5.1
 * OSD CDB Format -- basic OSD CDB
 */
typedef struct osd_cmd_basic {
	uint8_t	b_code,
		b_control,
		b_rsvd[5],
		b_add_cdblen,
		b_service_action[2];
} osd_cmd_basic_t;

/*
 * OSD revision 10, section 5.2.1
 * OSD service action specific fields
 * The specification doesn't repeat the fields found in the basic OSD CDB,
 * but it's included here so that one structure contains everything.
 */
typedef struct osd_generic_cdb {
	osd_cmd_basic_t	ocdb_basic;
	uint8_t		ocdb_options;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		ocdb_specific_opts	: 4,
			ocdb_fmt		: 2,
						: 2;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t					: 2,
			ocdb_fmt		: 2,
			ocdb_specific_opts	: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uint8_t		ocdb_ts_control,
			ocdb_rsvd1[3],
			ocdb_partition_id[8],
			ocdb_object_id[8],
			ocdb_rsvd2[4],
			ocdb_length[8],
			ocdb_start_addr[8],
			ocdb_attr_params[28],
			ocdb_capability[80],
			ocdb_security_params[40];
} osd_generic_cdb_t;

/*
 * []------------------------------------------------------------------[]
 * | OSD revision 10, section 6.13 -- LIST command			|
 * []------------------------------------------------------------------[]
 */
typedef struct osd_cmd_list {
	osd_cmd_basic_t	ocdb_basic;
	uint8_t		ocdb_rsvd1;
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		ocdb_sort_order		: 4,
			ocdb_fmt		: 2,
						: 2;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t					: 2,
			ocdb_fmt		: 2,
			ocdb_sort_order		: 4;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uint8_t		ocdb_ts_control,
			ocdb_rsvd2[3],
			ocdb_partition_id[8],
			ocdb_rsvd3[8],
			ocdb_list_id[4],
			ocdb_length[8],
			ocdb_object_id[8],
			ocdb_attr_params[28],
			ocdb_capability[80],
			ocdb_security_params[40];
} osd_cmd_list_t;

/* ---- Table 66, LIST command parameter data ---- */
typedef struct osd_list_param {
	uint8_t		op_length[8],
			op_cont_obj_id[8],
			op_list_id[4],
			op_rsvd1[3];
#if defined(_BIT_FIELDS_LTOH)
	uint8_t		op_root		: 1,
			op_lstchg	: 1,
					: 6;
#elif defined(_BIT_FIELDS_HTOL)
	uint8_t				: 6,
			op_lstchg	: 1,
			op_root		: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	osd_obj_id_t	op_list[1];
} osd_list_param_t;

#ifdef __cplusplus
}
#endif

#endif /* _T10_OSD_H */
