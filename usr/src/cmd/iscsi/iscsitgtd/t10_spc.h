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

#ifndef _T10_SPC_H
#define	_T10_SPC_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * []------------------------------------------------------------------[]
 * | SPC-3								|
 * []------------------------------------------------------------------[]
 */

/*
 * FIXED_SENSE_ADDL_INFO_LEN is the length of INFORMATION field
 * in fixed format sense data
 */
#define	FIXED_SENSE_ADDL_INFO_LEN 0xFFFFFFFF
#define	INFORMATION_SENSE_DESCR sizeof (struct scsi_information_sense_descr)

#include <sys/types.h>
#include <netinet/in.h>
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/mode.h>

/*
 * SPC Command Functions
 */
void spc_tur(struct t10_cmd *cmd, uint8_t *cdb, size_t cdb_len);
void spc_request_sense(struct t10_cmd *cmd, uint8_t *cdb, size_t cdb_len);
void spc_unsupported(struct t10_cmd *cmd, uint8_t *cdb, size_t cdb_len);
void spc_inquiry(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_mselect(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_mselect_data(t10_cmd_t *cmd, emul_handle_t id, size_t offset,
    char *data, size_t data_len);
void spc_report_luns(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_report_tpgs(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_msense(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_startstop(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_send_diag(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);

/*
 * SPC Support Functions
 */
void spc_cmd_offline(t10_cmd_t *cmd, uint8_t *cdb, size_t cdb_len);
void spc_sense_create(struct t10_cmd *cmd, int sense_key, int addl_sense_len);
void spc_sense_ascq(struct t10_cmd *cmd, int asc, int ascq);
void spc_sense_info(t10_cmd_t *cmd, uint64_t info);
void spc_sense_flags(t10_cmd_t *cmd, int flags);
void spc_sense_raw(t10_cmd_t *cmd, uchar_t *sense_buf, size_t sense_len);
Boolean_t spc_decode_lu_addr(uint8_t *buf, int len, uint32_t *val);
Boolean_t spc_encode_lu_addr(uint8_t *buf, int select_field, uint32_t lun);

/*
 * SPC flags to use when setting various sense code flags
 */
#define	SPC_SENSE_EOM	0x01
#define	SPC_SENSE_FM	0x02
#define	SPC_SENSE_ILI	0x04

/*
 * []------------------------------------------------------------------[]
 * | SPC-3, revision 21c -- ASC/ASCQ values				|
 * | The full tables can be found in Appendix D (numerical order) or	|
 * | section 4.5.6 (alphabetical order). There are close to fifteen	|
 * | pages of values which will not be included here. Only those used	|
 * | by the code.							|
 * []------------------------------------------------------------------[]
 */
#define	SPC_ASC_FM_DETECTED	0x00 /* file-mark detected */
#define	SPC_ASCQ_FM_DETECTED	0x01

#define	SPC_ASC_EOP		0x00 /* end-of-partition/medium detected */
#define	SPC_ASCQ_EOP		0x02

#define	SPC_ASC_IN_PROG		0x04
#define	SPC_ASCQ_IN_PROG	0x07

#define	SPC_ASC_WRITE_ERROR	0x0c
#define	SPC_ASCQ_WRITE_ERROR	0x00

#define	SPC_ASC_PARAM_LIST_LEN	0x1a /* Parameter List Length Error */
#define	SPC_ASCQ_PARAM_LIST_LEN	0x00

#define	SPC_ASC_MISCOMPARE	0x1d
#define	SPC_ASCQ_MISCOMPARE	0x00

#define	SPC_ASC_INVALID_LU	0x20
#define	SPC_ASCQ_INVALID_LU	0x09

#define	SPC_ASC_BLOCK_RANGE	0x21
#define	SPC_ASCQ_BLOCK_RANGE	0x00

#define	SPC_ASC_INVALID_FIELD_IN_PARAMETER_LIST		0x26
#define	SPC_ASCQ_INVALID_FIELD_IN_PARAMETER_LIST	0x00

#define	SPC_ASC_INVALID_CDB	0x24
#define	SPC_ASCQ_INVALID_CDB	0x00

#define	SPC_ASC_PARAMETERS_CHANGED	0x2a
#define	SPC_ASCQ_RES_PREEMPTED	0x03
#define	SPC_ASCQ_RES_RELEASED	0x04

#define	SPC_ASC_PWR_RESET	0x29
#define	SPC_ASCQ_PWR_RESET	0x00

#define	SPC_ASC_PWR_ON		0x29
#define	SPC_ASCQ_PWR_ON		0x01

#define	SPC_ASC_BUS_RESET	0x29
#define	SPC_ASCQ_BUS_RESET	0x02

#define	SPC_ASC_CAP_CHANGE	0x2a
#define	SPC_ASCQ_CAP_CHANGE	0x09

#define	SPC_ASC_DATA_PATH	0x41
#define	SPC_ASCQ_DATA_PATH	0x00

#define	SPC_ASC_MEMORY_OUT_OF	0x55 /* Auxillary Memory Out Of Space */
#define	SPC_ASCQ_MEMORY_OUT_OF	0x00
#define	SPC_ASCQ_RESERVATION_FAIL 0x02


/*
 * []------------------------------------------------------------------[]
 * | SAM-3, revision 14, section 5.2 - Command descriptor block (CDB)	|
 * |									|
 * | "All CDBs shall contain a CONTROL byte (see table 21). The		|
 * | location of the CONTROL byte within a CDB depends on the CDB	|
 * | format (see SPC-3)."						|
 * |									|
 * | bits	meaning							|
 * | 6-7	vendor specific (we don't use so must be zero)		|
 * | 3-5	reserved must be zero					|
 * | 2		NACA (currently we don't support so must be zero)	|
 * | 1		Obsolete						|
 * | 0		Link (currently we don't support so must be zero)	|
 * |									|
 * | So, this means the control byte must be zero and therefore if	|
 * | this macro returns a non-zero value the emulation code should	|
 * | return a CHECK CONDITION with status set to ILLEGAL REQUEST	|
 * | and the additional sense code set to INVALID FIELD IN CDB.		|
 * |									|
 * | In the future this will likely change with support routines	|
 * | added for dealing with NACA and Linked commands.			|
 * []------------------------------------------------------------------[]
 */
#define	SAM_CONTROL_BYTE_RESERVED(byte)	(byte)

/* ---- Disable Block Descriptors ---- */
#define	SPC_MODE_SENSE_DBD	0x8

#define	SPC_GROUP4_SERVICE_ACTION_MASK	0x1f

#define	SPC_SEND_DIAG_SELFTEST	0x04

/*
 * []------------------------------------------------------------------[]
 * | SPC-3 revision 21c, section 6.4 -- INQUIRY				|
 * | Various defines. The structure for the inquiry command can be	|
 * | found in /usr/include/sys/scsi/generic/inquiry.h			|
 * []------------------------------------------------------------------[]
 */
#define	SPC_INQUIRY_CODE_SET_BINARY	1
#define	SPC_INQUIRY_CODE_SET_ASCII	2
#define	SPC_INQUIRY_CODE_SET_UTF8	3

/* ---- Table 82: Inquiry Version ----  */
#define	SPC_INQ_VERS_NONE	0x00
#define	SPC_INQ_VERS_OBSOLETE	0x02
#define	SPC_INQ_VERS_SPC_1	0x03
#define	SPC_INQ_VERS_SPC_2	0x04
#define	SPC_INQ_VERS_SPC_3	0x05

/* ---- INQUIRY Response Data Format field ---- */
#define	SPC_INQ_RDF		0x02	/* all other values are OBSOLETE */

/*
 * Table 85 -- Version descriptor values
 * There are many, many different values available, so we'll only include
 * those that we actually use.
 */
#define	SPC_INQ_VD_SAM3		0x0076
#define	SPC_INQ_VD_SPC3		0x0307
#define	SPC_INQ_VD_SBC2		0x0322
#define	SPC_INQ_VD_SSC3		0x0400
#define	SPC_INQ_VD_OSD		0x0355

/* --- Version Descriptor length details --- */
#define	SPC_INQ_VD_IDX		0x3A
#define	SPC_INQ_VD_LEN		0x10

#define	SPC_INQ_PAGE0		0x00
#define	SPC_INQ_PAGE80		0x80
#define	SPC_INQ_PAGE83		0x83
#define	SPC_INQ_PAGE86		0x86

/* ---- REPORT LUNS select report has valid values of 0, 1, or 2 ---- */
#define	SPC_RPT_LUNS_SELECT_MASK	0x03

/* ---- Table 293: IDENTIFIER TYPE field ---- */
#define	SPC_INQUIRY_ID_TYPE_T10ID	1	/* ref 7.6.4.3 */
#define	SPC_INQUIRY_ID_TYPE_EUI		2	/* ref 7.6.4.4 */
#define	SPC_INQUIRY_ID_TYPE_NAA		3	/* ref 7.6.4.5 */
#define	SPC_INQUIRY_ID_TYPE_RELATIVE	4	/* ref 7.6.4.6 */
#define	SPC_INQUIRY_ID_TYPE_TARG_PORT	5	/* ref 7.6.4.7 */
#define	SPC_INQUIRY_ID_TYPE_LUN		6	/* ref 7.6.4.8 */
#define	SPC_INQUIRY_ID_TYPE_MD5		7	/* ref 7.6.4.9 */
#define	SPC_INQUIRY_ID_TYPE_SCSI	8	/* ref 7.6.4.10 */

/* ---- Table 292: ASSOCIATION field ----  */
#define	SPC_INQUIRY_ASSOC_LUN		0
#define	SPC_INQUIRY_ASSOC_TARGPORT	1
#define	SPC_INQUIRY_ASSOC_TARG		2

/* ---- Table 80: Peripheral qualifier ---- */
#define	SPC_INQUIRY_PERIPH_CONN		0
#define	SPC_INQUIRY_PERIPH_DISCONN	1
#define	SPC_INQUIRY_PERIPH_INVALID	3

/* ---- Table 256: PROTOCOL IDENTIFIER values ---- */
#define	SPC_INQUIRY_PROTOCOL_FC		0
#define	SPC_INQUIRY_PROTOCOL_PSCSI	1
#define	SPC_INQUIRY_PROTOCOL_SSA	2
#define	SPC_INQUIRY_PROTOCOL_IEEE1394	3
#define	SPC_INQUIRY_PROTOCOL_SCSIRDMA	4
#define	SPC_INQUIRY_PROTOCOL_ISCSI	5
#define	SPC_INQUIRY_PROTOCOL_SAS	6
#define	SPC_INQUIRY_PROTOCOL_ADT	7
#define	SPC_INQUIRY_PROTOCOL_ATA	8

#define	SPC_DEFAULT_TPG	1

/*
 * SPC-3, revision 21c, section 7.6.5
 * Extended INQUIRY Data VPD page
 */
typedef struct extended_inq_data {
	struct vpd_hdr	ei_hdr;
#if defined(_BIT_FIELDS_LTOH)
	uchar_t		ei_ref_chk	: 1,
			ei_app_chk	: 1,
			ei_grd_chk	: 1,
			ei_rto		: 1,
			ei_rsvd1	: 4;
	uchar_t		ei_simpsup	: 1,
			ei_ordsup	: 1,
			ei_headsup	: 1,
			ei_prior_sup	: 1,
			ei_group_sup	: 1,
			ei_rsvd2	: 3;
	uchar_t		ei_v_sup	: 1,
			ei_nv_sup	: 1,
			ei_rsvd3	: 6;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t		ei_ref_rsvd1	: 4,
			ei_rto		: 1,
			ei_grd_chk	: 1,
			ei_app_chk	: 1,
			ei_ref_chk	: 1;
	uchar_t		ei_rsvd2	: 2,
			ei_group_sup	: 1,
			ei_prior_sup	: 1,
			ei_headsup	: 1,
			ei_ordsup	: 1,
			ei_simpsup	: 1;
	uchar_t		ei_rsvd3	: 6,
			ei_nv_sup	: 1,
			ei_v_sup	: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t		ei_rsv4[57];
} extended_inq_data_t;


/*
 * []------------------------------------------------------------------[]
 * | SPC-4 revision 1a, section 6.25 -- REPORT TARGET PORT GROUPS	|
 * | Structures and defines						|
 * []------------------------------------------------------------------[]
 */
/*
 * The service action must be set to 0x0A. This command is really a
 * MAINTENANCE_IN command with a specific service action.
 */
#define	SPC_MI_SVC_MASK		0x1f
#define	SPC_MI_SVC_RTPG		0x0a

/* ---- Table 167: Target port descriptor format ---- */
typedef struct rtpg_targ_desc {
	uchar_t		obsolete[2],
			rel_tpi[2];
} rtpg_targ_desc_t;

/* ---- Table 164: Target port group descript format ---- */
typedef struct rtpg_desc {
#if defined(_BIT_FIELDS_LTOH)
	uchar_t access_state	: 4,
				: 3,
		pref		: 1;
	uchar_t	ao_sup		: 1,
		an_sup		: 1,
		s_sup		: 1,
		u_sup		: 1,
				: 3,
		t_sup		: 1;
#elif defined(_BIT_FIELDS_HTOL)
	uchar_t	pref		: 1,
				: 3,
		access_state	: 4;
	uchar_t	t_sup		: 1,
				: 3,
		u_sup		: 1,
		s_sup		: 1,
		an_sup		: 1,
		ao_sup		: 1;
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	uchar_t			tpg[2],
				reserve_1,
				status_code,
				vendor_spec,
				tpg_cnt;
	rtpg_targ_desc_t	targ_list[1];
} rtpg_desc_t;

/* ---- Table 163: parameter data format. ---- */
typedef struct rtpg_data {
	uchar_t		len[4];
	rtpg_desc_t	desc_list[1];
} rtpg_hdr_t;

/*
 * []------------------------------------------------------------------[]
 * | SPC-3, revision 21c, section 6.6 -- LOG_SENSE			|
 * | Structure and defines						|
 * []------------------------------------------------------------------[]
 */
#define	SSC_LOG_SP		0x01 /* save parameters */
#define	SSC_LOG_PPC		0x02 /* parameter pointer control */
#define	SPC_LOG_PAGE_MASK	0x3f

/* ---- section 7.2.1, Table 192: Log Parameter ---- */
typedef struct spc_log_select_param {
	char	param_code[2];
#if defined(_BIT_FIELDS_LTOH)
	char	lp	: 1,	/* list parameter */
		lbin	: 1,
		tmc	: 2,	/* threshold met criteria */
		etc	: 1,	/* enable threshold comparison */
		tsd	: 1,	/* target save disable */
		ds	: 1,	/* disable save */
		du	: 1;	/* disable update */
#elif defined(_BIT_FIELDS_HTOL)
	char	du	: 1,	/* disable update */
		ds	: 1,	/* disable save */
		tsd	: 1,	/* target save disable */
		etc	: 1,	/* enable threshold comparison */
		tmc	: 2,	/* threshold met criteria */
		lbin	: 1,
		lp	: 1;	/* list parameter */
#else
#error One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif
	char	len;		/* length of bytes to follow */
} spc_log_select_param_t;

/* ---- section 7.2.12, table 218: Supported log pages ---- */
typedef struct spc_log_supported_pages {
	char	page_code,
		resvd,
		length[2],
		list[1];
} spc_log_supported_pages_t;

/*
 * []------------------------------------------------------------------[]
 * | SPC-3, revision 21c, section 6.9 -- MODE_SENSE			|
 * | Structures and defines						|
 * []------------------------------------------------------------------[]
 */
/* ---- Section 7.4.6, Table 241: Queue Algorithm Modifer field ---- */
#define	SPC_QUEUE_RESTRICTED		0x00
#define	SPC_QUEUE_UNRESTRICTED		0x01

/* ---- Section 7.4.11, Table 250: Information Controller Page ---- */
struct mode_info_ctrl {
	struct mode_page	mode_page;
	/*
	 * Currently we don't sent any of this information and it's set
	 * to zero's. We only care about the size.
	 */
	char			info_data[10];
};

#define	MODE_SENSE_PAGE3_CODE		0x03
#define	MODE_SENSE_PAGE4_CODE		0x04
#define	MODE_SENSE_CACHE		0x08
#define	MODE_SENSE_CONTROL		0x0a
#define	MODE_SENSE_COMPRESSION		0x0f
#define	MODE_SENSE_DEV_CONFIG		0x10
#define	MODE_SENSE_INFO_CTRL		0x1c
#define	MODE_SENSE_SEND_ALL		0x3f

/* -- Page Control Mask for Mode Sense -- */
#define	SPC_MODE_SENSE_PAGE_CODE_MASK	0x3f
#define	SPC_MODE_SENSE_PC_MASK		0xc0
#define	SPC_MODE_SENSE_PC_SHIFT		6

#define	SPC_PC_CURRENT_VALUES		0
#define	SPC_PC_MODIFIABLE_VALUES	1
#define	SPC_PC_DEFAULT_VALUES		2
#define	SPC_PC_SAVED_VALUES		3

#define	SCSI_REPORTLUNS_ADDRESS_SIZE			8
#define	SCSI_REPORTLUNS_ADDRESS_MASK			0xC0
#define	SCSI_REPORTLUNS_ADDRESS_PERIPHERAL		0x00
#define	SCSI_REPORTLUNS_ADDRESS_FLAT_SPACE		0x40
#define	SCSI_REPORTLUNS_ADDRESS_LOGICAL_UNIT		0x80
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_UNIT		0xC0
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_2B		0x00
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_4B		0x10
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_6B		0x20
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_8B		0x30
#define	SCSI_REPORTLUNS_ADDRESS_EXTENDED_MASK		0x30
#define	SCSI_REPORTLUNS_SELECT_ALL			0x02

#ifdef __cplusplus
}
#endif

#endif /* _T10_SPC_H */
