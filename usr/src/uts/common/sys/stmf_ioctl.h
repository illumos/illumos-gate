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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */
#ifndef	_STMF_IOCTL_H
#define	_STMF_IOCTL_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	STMF_VERSION_1			1

#define	STMF_IOCTL			(((uint32_t)'S') << 24)
#define	STMF_IOCTL_LU_LIST			(STMF_IOCTL | 1)
#define	STMF_IOCTL_TARGET_PORT_LIST		(STMF_IOCTL | 2)
#define	STMF_IOCTL_SESSION_LIST			(STMF_IOCTL | 3)
#define	STMF_IOCTL_GET_LU_PROPERTIES		(STMF_IOCTL | 4)
#define	STMF_IOCTL_GET_TARGET_PORT_PROPERTIES	(STMF_IOCTL | 5)
#define	STMF_IOCTL_SET_STMF_STATE		(STMF_IOCTL | 6)
#define	STMF_IOCTL_GET_STMF_STATE		(STMF_IOCTL | 7)
#define	STMF_IOCTL_SET_LU_STATE			(STMF_IOCTL | 8)
#define	STMF_IOCTL_SET_TARGET_PORT_STATE	(STMF_IOCTL | 9)
#define	STMF_IOCTL_CREATE_HOST_GROUP		(STMF_IOCTL | 10)
#define	STMF_IOCTL_REMOVE_HOST_GROUP		(STMF_IOCTL | 11)
#define	STMF_IOCTL_ADD_HG_ENTRY			(STMF_IOCTL | 12)
#define	STMF_IOCTL_REMOVE_HG_ENTRY		(STMF_IOCTL | 13)
#define	STMF_IOCTL_CREATE_TARGET_GROUP		(STMF_IOCTL | 14)
#define	STMF_IOCTL_REMOVE_TARGET_GROUP		(STMF_IOCTL | 15)
#define	STMF_IOCTL_ADD_TG_ENTRY			(STMF_IOCTL | 16)
#define	STMF_IOCTL_REMOVE_TG_ENTRY		(STMF_IOCTL | 17)
#define	STMF_IOCTL_ADD_VIEW_ENTRY		(STMF_IOCTL | 18)
#define	STMF_IOCTL_REMOVE_VIEW_ENTRY		(STMF_IOCTL | 19)
#define	STMF_IOCTL_GET_HG_LIST			(STMF_IOCTL | 20)
#define	STMF_IOCTL_GET_TG_LIST			(STMF_IOCTL | 21)
#define	STMF_IOCTL_GET_HG_ENTRIES		(STMF_IOCTL | 22)
#define	STMF_IOCTL_GET_TG_ENTRIES		(STMF_IOCTL | 23)
#define	STMF_IOCTL_GET_VE_LIST			(STMF_IOCTL | 24)
#define	STMF_IOCTL_LOAD_PP_DATA			(STMF_IOCTL | 25)
#define	STMF_IOCTL_CLEAR_PP_DATA		(STMF_IOCTL | 26)
#define	STMF_IOCTL_GET_PP_DATA			(STMF_IOCTL | 27)
#define	STMF_IOCTL_CLEAR_TRACE			(STMF_IOCTL | 28)
#define	STMF_IOCTL_ADD_TRACE			(STMF_IOCTL | 29)
#define	STMF_IOCTL_GET_TRACE_POSITION		(STMF_IOCTL | 30)
#define	STMF_IOCTL_GET_TRACE			(STMF_IOCTL | 31)
#define	STMF_IOCTL_REG_LU_LIST			(STMF_IOCTL | 32)
#define	STMF_IOCTL_VE_LU_LIST			(STMF_IOCTL | 33)
#define	STMF_IOCTL_LU_VE_LIST			(STMF_IOCTL | 34)
#define	STMF_IOCTL_VALIDATE_VIEW		(STMF_IOCTL | 35)
#define	STMF_IOCTL_SET_ALUA_STATE		(STMF_IOCTL | 36)
#define	STMF_IOCTL_GET_ALUA_STATE		(STMF_IOCTL | 37)
#define	STMF_IOCTL_SET_STMF_PROPS		(STMF_IOCTL | 38)

typedef	struct stmf_iocdata {
	uint32_t	stmf_version;
	uint32_t	stmf_error;
	uint32_t	stmf_ibuf_size;
	uint32_t	stmf_obuf_size;
	uint32_t	stmf_obuf_nentries;	/* # entries xferred */
	uint32_t	stmf_obuf_max_nentries;	/* #,could have been xferred */
	uint64_t	stmf_ibuf;
	uint64_t	stmf_obuf;
} stmf_iocdata_t;

typedef	struct slist_lu {
	uint8_t		lu_guid[16];
} slist_lu_t;

typedef	struct slist_target_port {
	uint8_t		target[260];
} slist_target_port_t;

typedef	struct slist_scsi_session {
	uint8_t		initiator[260];
	/* creation_time is really time_t. But time_t is defined as long. */
	uint32_t	creation_time;
	char		alias[256];
} slist_scsi_session_t;

/*
 * States for LUs and LPORTs
 */
#define	STMF_STATE_OFFLINE		0
#define	STMF_STATE_ONLINING		1
#define	STMF_STATE_ONLINE		2
#define	STMF_STATE_OFFLINING		3

/*
 * States for the STMF config.
 */
#define	STMF_CONFIG_NONE		0
#define	STMF_CONFIG_INIT		1
#define	STMF_CONFIG_INIT_DONE		2

typedef struct sioc_lu_props {
	uint8_t		lu_guid[16];
	uint8_t		lu_state:4,
			lu_present:1,
			lu_rsvd:3;
	char		lu_provider_name[255];
	char		lu_alias[256];
} sioc_lu_props_t;

typedef struct sioc_target_port_props {
	uint8_t		tgt_id[260];
	uint8_t		tgt_state:4,
			tgt_present:1,
			tgt_rsvd:3;
	char		tgt_provider_name[255];
	char		tgt_alias[256];
} sioc_target_port_props_t;

/*
 * This struct is used for getting and setting state of LU/LPORT or STMF.
 */
typedef struct stmf_state_desc {
	uint8_t		ident[260];	/* N/A for STMF itself */
	uint8_t		state;
	uint8_t		config_state;	/* N/A for LU/LPORTs */
} stmf_state_desc_t;

/*
 * This struct is used for setting the alua state
 */
typedef struct stmf_alua_state_desc {
	uint8_t		alua_state;
	uint16_t	alua_node;
} stmf_alua_state_desc_t;

/* Error definitions for group/view entry/provider dataioctls */
#define	STMF_IOCERR_NONE			0
#define	STMF_IOCERR_HG_EXISTS			1
#define	STMF_IOCERR_INVALID_HG			2
#define	STMF_IOCERR_TG_EXISTS			3
#define	STMF_IOCERR_INVALID_TG			4
#define	STMF_IOCERR_HG_ENTRY_EXISTS		5
#define	STMF_IOCERR_INVALID_HG_ENTRY		6
#define	STMF_IOCERR_TG_ENTRY_EXISTS		7
#define	STMF_IOCERR_INVALID_TG_ENTRY		8
#define	STMF_IOCERR_TG_UPDATE_NEED_SVC_OFFLINE	9
#define	STMF_IOCERR_LU_NUMBER_IN_USE		10
#define	STMF_IOCERR_INVALID_LU_ID		11
#define	STMF_IOCERR_VIEW_ENTRY_CONFLICT		12
#define	STMF_IOCERR_HG_IN_USE			13
#define	STMF_IOCERR_TG_IN_USE			14
#define	STMF_IOCERR_INVALID_VIEW_ENTRY		15
#define	STMF_IOCERR_INVALID_VE_ID		16
#define	STMF_IOCERR_UPDATE_NEED_CFG_INIT	17
#define	STMF_IOCERR_PPD_UPDATED			18
#define	STMF_IOCERR_INSUFFICIENT_BUF		19
#define	STMF_IOCERR_TG_NEED_TG_OFFLINE		20


typedef struct stmf_group_name {
	uint16_t	name_size;	/* in bytes */
	uint16_t	rsvd_1;
	uint32_t	rsvd_2;
	uint8_t		name[512];	/* 256 * wchar_t */
} stmf_group_name_t;

/*
 * struct used to operate (add/remove entry) on a group.
 */

typedef struct stmf_ge_ident {
	uint16_t    ident_size;
	uint8_t	    ident[256];
} stmf_ge_ident_t;

typedef struct stmf_group_op_data {
	stmf_group_name_t	group;
	uint8_t			ident[260];
} stmf_group_op_data_t;

typedef struct stmf_view_op_entry {
	uint32_t		ve_ndx_valid:1,
				ve_lu_number_valid:1,
				ve_all_hosts:1,
				ve_all_targets:1,
				rsvd:28;
	uint32_t		ve_ndx;
	uint8_t			ve_lu_nbr[8];
	uint8_t			ve_guid[16];
	stmf_group_name_t	ve_host_group;
	stmf_group_name_t	ve_target_group;
} stmf_view_op_entry_t;

typedef struct stmf_ppioctl_data {
	char		ppi_name[255];	/* Provider name including \0 */
	uint8_t		ppi_port_provider:1,
			ppi_lu_provider:1,
			ppi_token_valid:1,
			ppt_rsvd:5;
	uint64_t	ppi_token;
	uint64_t	ppi_data_size;
	uint8_t		ppi_data[8];
} stmf_ppioctl_data_t;

typedef struct stmf_set_props {
	uint32_t	default_lu_state_value;
	uint32_t	default_target_state_value;
} stmf_set_props_t;

/*
 * SCSI device ID descriptor as per SPC3 7.6.3
 */
typedef struct scsi_devid_desc {
#ifdef	_BIT_FIELDS_HTOL
	uint8_t		protocol_id:4,
			code_set:4;
	uint8_t		piv:1,
			rsvd1:1,
			association:2,
			ident_type:4;
#else
	uint8_t		code_set:4,
			protocol_id:4;
	uint8_t		ident_type:4,
			association:2,
			rsvd1:1,
			piv:1;
#endif
	uint8_t		rsvd2;
	uint8_t		ident_length;
	uint8_t		ident[1];
} scsi_devid_desc_t;

/*
 * Protocol Identifier
 */
#define	PROTOCOL_FIBRE_CHANNEL		0
#define	PROTOCOL_PARALLEL_SCSI		1
#define	PROTOCOL_SSA			2
#define	PROTOCOL_IEEE_1394		3
#define	PROTOCOL_SRP			4
#define	PROTOCOL_iSCSI			5
#define	PROTOCOL_SAS			6
#define	PROTOCOL_ADT			7
#define	PROTOCOL_ATAPI			8
#define	PROTOCOL_ANY			15

/*
 * Code set definitions
 */
#define	CODE_SET_BINARY			1
#define	CODE_SET_ASCII			2
#define	CODE_SET_UTF8			3

/*
 * Association values
 */
#define	ID_IS_LOGICAL_UNIT		0
#define	ID_IS_TARGET_PORT		1
#define	ID_IS_TARGET_CONTAINING_LU	2

/*
 * ident type
 */
#define	ID_TYPE_VENDOR_SPECIFIC		0
#define	ID_TYPE_T10_VID			1
#define	ID_TYPE_EUI64			2
#define	ID_TYPE_NAA			3
#define	ID_TYPE_RELATIVE_TARGET_PORT	4
#define	ID_TYPE_TARGET_PORT_GROUP	5
#define	ID_TYPE_LOGICAL_UNIT_GROUP	6
#define	ID_TYPE_MD5_LOGICAL_UNIT	7
#define	ID_TYPE_SCSI_NAME_STRING	8

int stmf_copyin_iocdata(intptr_t data, int mode, stmf_iocdata_t **iocd,
    void **ibuf, void **obuf);
int stmf_copyout_iocdata(intptr_t data, int mode, stmf_iocdata_t *iocd,
    void *obuf);

#ifdef	__cplusplus
}
#endif

#endif /* _STMF_IOCTL_H */
