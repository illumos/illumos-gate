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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_SCSI_GENERIC_PERSIST_H
#define	_SYS_SCSI_GENERIC_PERSIST_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * SCSI Persistence Data
 *
 * Format of data returned as a result of PERSISTENCE RESERVER { IN | OUT }
 */

/*
 * SPC-3 revision 23, Section 6.11.1, Table 102
 * Persistent Reservations
 * Persistent Reserve In service actions
 */
#define	PR_IN_READ_KEYS		0x0 /* Read all registered reservation keys */
#define	PR_IN_READ_RESERVATION	0x1 /* Reads th persistent reservations */
#define	PR_IN_REPORT_CAPABILITIES 0x2 /* Returns capability information */
#define	PR_IN_READ_FULL_STATUS	0x3 /* Reads complete information about all */
				    /* registrations and the persistent */
				    /* reservations, if any */
/*
 * SPC-3 revision 23, Section 6.11.3.3, Table 106
 * Persistent reservation scope codes
 */
#define	PR_LU_SCOPE		0x0	/* Persistent reservation applies to */
					/* full logical unit */
/*
 * SPC-3 revision 23, Section 6.11.3.4, Table 107
 * Persistent Reservations
 * Persistent reservation type codes
 */
#define	PGR_TYPE_WR_EX		0x1	/* Write Exclusive */
#define	PGR_TYPE_EX_AC		0x3	/* Exclusive Access */
#define	PGR_TYPE_WR_EX_RO	0x5	/* Write Exclusive, Registrants Only */
#define	PGR_TYPE_EX_AC_RO	0x6	/* Exclusive Access, Registrants Only */
#define	PGR_TYPE_WR_EX_AR	0x7	/* Write Exclusive, All Registrants */
#define	PGR_TYPE_EX_AC_AR	0x8	/* Exclusive Access, All Registrants */

/*
 * SPC-3 revision 23, Section 6.12.2, Table 113
 * Persistent Reservations
 * Persistent Reserve Out service action codes
 */
#define	PR_OUT_REGISTER		0x0	/* Register/unregister a reservation */
					/* key with the device server */
#define	PR_OUT_RESERVE		0x1	/* Create a persistent reservation */
					/* having a specified SCOPE & TYPE */
#define	PR_OUT_RELEASE		0x2	/* Release the selected persistent */
					/* reservation */
#define	PR_OUT_CLEAR		0x3	/* Clears all reservation keys and */
					/* all persistent reservations */
#define	PR_OUT_PREEMPT		0x4	/* Preempts persistent reservations */
					/* and/or removes reservations */
#define	PR_OUT_PREEMPT_ABORT	0x5	/* Preempts persistent reservations */
					/* and/or removes reservations, and */
					/* aborts all tasks for all preempted */
					/* I_T nexuses */
#define	PR_OUT_REGISTER_AND_IGNORE_EXISTING_KEY	0x06
					/* Register a reservation key with */
					/* the device server, or unregister a */
					/* reservation key */
#define	PR_OUT_REGISTER_MOVE	0x7	/* Register a reservation key for */
					/* another I_T nexus with the device */
					/* server and move a persistent */
					/* reservation to the I_T nexus */


/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.5 PERSISTENCE RESERVE IN
 *	Table 111 - full status descriptor format
 */
/* Table 289 - iSCSI Initiator Device TransportID format */

#define	iSCSI_PROTOCOL_ID	0x5	/* Table 262 - iSCSI Protocol ID  */
#define	WW_UID_DEVICE_NAME	0x0	/* Table 288 - iSCSI Transport IDs */

/*
 * Definitions related SCSI Transport ID
 * SPC3 rev 23, Tables 284-287
 */
#define	SCSI_TPTID_SIZE			24
#define	SCSI_TPTID_FC_PORT_NAME_SIZE	8
#define	SCSI_TPTID_SPI_ADDRESS_LEN	2
#define	SCSI_TPTID_SPI_REL_TGTPTID_LEN	2
#define	SCSI_TPTID_SBP_PORT_NAME_LEN	8
#define	SCSI_TPTID_SRP_PORT_NAME_LEN	16
#define	SCSI_TPTID_ISCSI_ISID_SEPERATOR	",i,0x"

#if defined(_BIT_FIELDS_LTOH)
/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.1 PERSISTENCE RESERVE IN
 *	Table 101 - PERSISTENCE RESERVE IN command
 */
typedef struct scsi_cdb_prin {
	uint8_t			cmd;
	uint8_t			action : 5,
				resbits : 3;
	uint8_t			resbytes[5];
	uint8_t			alloc_len[2];
	uint8_t			control;
} scsi_cdb_prin_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.2 PERSISTENCE RESERVE IN
 *	Table 103/104/105 - parameter data for READS KEYS
 */
typedef struct scsi_prin_rsrvdesc {
	uint8_t			reservation_key[8];
	uint8_t			obsolete1[4];
	uint8_t			resbytes;
	uint8_t			type : 4,
				scope : 4;
	uint8_t			obsolete2[2];
} scsi_prin_rsrvdesc_t;
typedef struct scsi_prin_readrsrv {
	uint8_t			PRgeneration[4];
	uint8_t			add_len[4];
	union {
		uint64_t		service_key[1];
		scsi_prin_rsrvdesc_t	res_key_list[1];
	} key_list;
} scsi_prin_readrsrv_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.4 PERSISTENCE RESERVE IN
 * 	Table 108 - parameter data for REPORT CAPABILTIES
 */
typedef struct scsi_per_res_type {
	uint8_t			resbits1 : 1,
				wr_ex : 1,
				resbits2 : 1,
				ex_ac : 1,
				resbits3 : 1,
				wr_ex_ro : 1,
				ex_ac_ro : 1,
				wr_ex_ar : 1;
	uint8_t			ex_ac_ar : 1,
				resbits4 : 7;
} scsi_per_res_type_t;

/*
 * Refer SPC-3, Revision 23
 * Section 6.11.4 REPORT CAPABILITIES service action
 */
typedef struct scsi_prin_rpt_cap {
	uint8_t			length[2];
	uint8_t			ptpl_c : 1,
				resbits1 : 1,
				atp_c : 1,
				sip_c : 1,
				crh : 1,
				resbits2 : 3;
	uint8_t			ptpl_a : 1,
				resbits3 : 6,
				tmv : 1;
	scsi_per_res_type_t	pr_type;
	uint8_t			resbytes[2];
} scsi_prin_rpt_cap_t;

/*
 * Refer SPC-3, Revision 23
 * Section 7.5.4 TransportID identifiers
 */
typedef struct scsi_transport_id {
	uint8_t			protocol_id : 4,
				resbits : 2,
				format_code : 2;
	uint8_t			protocol_data[1];
} scsi_transport_id_t;

typedef struct scsi_fc_transport_id {
	uint8_t			protocol_id : 4,
				resbits : 2,
				format_code : 2;
	uint8_t			rsvbytes1[7];
	uint8_t			port_name[8];
	uint8_t			rsvbytes2[8];
} scsi_fc_transport_id_t;

typedef struct iscsi_transport_id {
	uint8_t			protocol_id : 4,
				resbits : 2,
				format_code : 2;
	uint8_t			rsvbyte1;
	uint8_t			add_len[2];
	char			iscsi_name[1];
} iscsi_transport_id_t;

typedef struct scsi_srp_transport_id {
	uint8_t			protocol_id : 4,
				resbits : 2,
				format_code : 2;
	uint8_t			rsvbytes1[7];
	uint8_t			srp_name[16];
} scsi_srp_transport_id_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.5 PERSISTENCE RESERVE IN
 * 	Table 110/111 - parameter data for READ FULL STATUS
 *	Table 281 - TransportId format
 */

typedef struct scsi_prin_status_t {
	uint8_t			reservation_key[8];
	uint8_t			resbytes1[4];
	uint8_t			r_holder : 1,
				all_tg_pt : 1,
				resbits : 6;
	uint8_t			type : 4,
				scope : 4;
	uint8_t			resbytes2[4];
	uint8_t			rel_tgt_port_id[2];
	uint8_t			add_len[4];
	scsi_transport_id_t	trans_id;
} scsi_prin_status_t;

typedef struct scsi_prin_full_status {
	uint8_t			PRgeneration[4];
	uint8_t			add_len[4];
	scsi_prin_status_t	full_desc[1];
} scsi_prin_full_status_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.1 PERSISTENCE RESERVE OUT
 *	Table 112 - PERSISTENCE RESERVE OUT command
 */
typedef struct scsi_cdb_prout {
	uint8_t			cmd;
	uint8_t			action : 5,
				resbits : 3;
	uint8_t			type : 4,
				scope : 4;
	uint8_t			resbytes[2];
	uint8_t			param_len[4];
	uint8_t			control;
} scsi_cdb_prout_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.3 PERSISTENCE RESERVE OUT
 *	Table 114 - PERSISTENCE RESERVE OUT parameter list
 */
typedef struct scsi_prout_plist {
	uint8_t			reservation_key[8];
	uint8_t			service_key[8];
	uint8_t			obsolete1[4];
	uint8_t			aptpl : 1,
				resbits1 : 1,
				all_tg_pt : 1,
				spec_i_pt : 1,
				resbits2 : 4;
	uint8_t			resbytes1;
	uint8_t			obsolete2[2];
	uint8_t			apd[1];
} scsi_prout_plist_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.4 PERSISTENCE RESERVE OUT command with REGISTER AND MOVE
 *	Table 117 - REGISTER and MOVE service action  parameter list
 */
typedef struct scsi_prout_reg_move_plist {
	uint8_t			reservation_key[8];
	uint8_t			service_key[8];
	uint8_t			resbytes1;
	uint8_t			aptpl : 1,
				unreg : 1,
				resbits1 : 6;
	uint8_t			rel_tgt_port_id[2];
	uint8_t			tptid_len[4];
	uint8_t			tptid[1];
} scsi_prout_reg_move_plist_t;

#elif defined(_BIT_FIELDS_HTOL)
/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.1 PERSISTENCE RESERVE IN
 *	Table 101 - PERSISTENCE RESERVE IN command
 */
typedef struct scsi_cdb_prin {
	uint8_t			cmd;
	uint8_t			resbits : 3,
				action : 5;
	uint8_t			resbytes[5];
	uint8_t			alloc_len[2];
	uint8_t			control;
} scsi_cdb_prin_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.2 PERSISTENCE RESERVE IN
 *	Table 103/104/105 - parameter data for READS KEYS
 */
typedef struct scsi_prin_rsrvdesc {
	uint8_t			reservation_key[8];
	uint8_t			obsolete1[4];
	uint8_t			resbytes;
	uint8_t			scope : 4,
				type : 4;
	uint8_t			obsolete2[2];
} scsi_prin_rsrvdesc_t;
typedef struct scsi_prin_readrsrv {
	uint8_t			PRgeneration[4];
	uint8_t			add_len[4];
	union {
		uint64_t		service_key[1];
		scsi_prin_rsrvdesc_t	res_key_list[1];
	} key_list;
} scsi_prin_readrsrv_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.4 PERSISTENCE RESERVE IN
 * 	Table 108 - parameter data for REPORT CAPABILTIES
 */
typedef struct scsi_per_res_type {
	uint8_t			wr_ex_ar : 1,
				ex_ac_ro : 1,
				wr_ex_ro : 1,
				resbits3 : 1,
				ex_ac : 1,
				resbits2 : 1,
				wr_ex : 1,
				resbits1 : 1;
	uint8_t			resbits4 : 7,
				ex_ac_ar : 1;
} scsi_per_res_type_t;
/*
 * Refer SPC-3, Revision 23
 * Section 6.11.4 REPORT CAPABILITIES service action
 */
typedef struct scsi_prin_rpt_cap {
	uint8_t			length[2];
	uint8_t			resbits2 : 3,
				crh : 1,
				sip_c : 1,
				atp_c : 1,
				resbits1 : 1,
				ptpl_c : 1;
	uint8_t			tmv : 1,
				resbits3 : 6,
				ptpl_a : 1;
	scsi_per_res_type_t	pr_type;
	uint8_t			resbytes[2];
} scsi_prin_rpt_cap_t;

/*
 * Refer SPC-3, Revision 23
 * Section 7.5.4 TransportID identifiers
 */
typedef struct scsi_transport_id {
	uint8_t			format_code : 2,
				resbits : 2,
				protocol_id : 4;
	uint8_t			protocol_data[1];
} scsi_transport_id_t;

typedef struct scsi_fc_transport_id {
	uint8_t			format_code : 2,
				resbits : 2,
				protocol_id : 4;
	uint8_t			rsvbytes1[7];
	uint8_t			port_name[8];
	uint8_t			rsvbytes2[8];
} scsi_fc_transport_id_t;

typedef struct iscsi_transport_id {
	uint8_t			format_code : 2,
				resbits : 2,
				protocol_id : 4;
	uint8_t			rsvbyte1;
	uint8_t			add_len[2];
	char			iscsi_name[1];
} iscsi_transport_id_t;


typedef struct scsi_srp_transport_id {
	uint8_t			format_code : 2,
				resbits : 2,
				protocol_id : 4;
	uint8_t			rsvbytes1[7];
	uint8_t			srp_name[16];
} scsi_srp_transport_id_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.11.5 PERSISTENCE RESERVE IN
 * 	Table 110/111 - parameter data for READ FULL STATUS
 *	Table 281 - TransportId format
 */

typedef struct scsi_prin_status_t {
	uint8_t			reservation_key[8];
	uint8_t			resbytes1[4];
	uint8_t			resbits : 6,
				all_tg_pt : 1,
				r_holder : 1;
	uint8_t			scope : 4,
				type : 4;
	uint8_t			resbytes2[4];
	uint8_t			rel_tgt_port_id[2];
	uint8_t			add_len[4];
	scsi_transport_id_t	trans_id;
} scsi_prin_status_t;
typedef struct scsi_prin_full_status {
	uint8_t			PRgeneration[4];
	uint8_t			add_len[4];
	scsi_prin_status_t	full_desc[1];
} scsi_prin_full_status_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.1 PERSISTENCE RESERVE OUT
 *	Table 112 - PERSISTENCE RESERVE OUT command
 */
typedef struct scsi_cdb_prout {
	uint8_t			cmd;
	uint8_t			resbits : 3,
				action : 5;
	uint8_t			scope : 4,
				type : 4;
	uint8_t			resbytes[2];
	uint8_t			param_len[4];
	uint8_t			control;
} scsi_cdb_prout_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.3 PERSISTENCE RESERVE OUT
 *	Table 114 - PERSISTENCE RESERVE OUT parameter list
 */
typedef struct scsi_prout_plist {
	uint8_t			reservation_key[8];
	uint8_t			service_key[8];
	uint8_t			obsolete1[4];
	uint8_t			resbits1 : 4,
				spec_i_pt : 1,
				all_tg_pt : 1,
				resbits2 : 1,
				aptpl : 1;
	uint8_t			resbytes1;
	uint8_t			obsolete2[2];
	uint8_t			apd[1];
} scsi_prout_plist_t;

/*
 * Information obtained from:
 *	SPC-3, Revision 23
 *	Section 6.12.4 PERSISTENCE RESERVE OUT command with REGISTER AND MOVE
 *	Table 117 - REGISTER and MOVE service action  parameter list
 */
typedef struct scsi_prout_reg_move_plist {
	uint8_t			reservation_key[8];
	uint8_t			service_key[8];
	uint8_t			resbytes1;
	uint8_t			resbits1 : 6,
				unreg    : 1,
				aptpl    : 1;
	uint8_t			rel_tgt_port_id[2];
	uint8_t			tptid_len[4];
	uint8_t			tptid[1];
} scsi_prout_reg_move_plist_t;

#else
#error	One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif	/* _BIT_FIELDS_LTOH */
#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_GENERIC_PERSIST_H */
