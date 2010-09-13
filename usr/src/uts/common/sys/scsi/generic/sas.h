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
 *
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * SAS Common Structures and Definitions
 * sas2r14, simplified/reduced
 */
#ifndef	_SAS_H
#define	_SAS_H
#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>
/*
 * SAS Address Frames
 * Trailing 4 byte CRC not included.
 */
typedef struct {
	DECL_BITFIELD3(
	    address_frame_type		:4,
	    device_type			:3,
	    reserved0			:1);
	DECL_BITFIELD2(
	    reason			:4,
	    reserved1			:4);
	DECL_BITFIELD5(
	    restricted0			:1,
	    smp_ini_port		:1,
	    stp_ini_port		:1,
	    ssp_ini_port		:1,
	    reserved2			:4);
	DECL_BITFIELD5(
	    restricted1			:1,
	    smp_tgt_port		:1,
	    stp_tgt_port		:1,
	    ssp_tgt_port		:1,
	    reserved3			:4);
	uint8_t		device_name[8];
	uint8_t		sas_address[8];
	uint8_t		phy_identifier;
	DECL_BITFIELD4(
	    break_reply_capable		:1,
	    requested_inside_zpsds	:1,
	    inside_zpsds_persistent	:1,
	    reserved4			:5);
	uint8_t		reserved5[6];
} sas_identify_af_t;

typedef struct {
	DECL_BITFIELD3(
	    address_frame_type		:4,
	    protocol			:3,
	    ini_port			:1);
	DECL_BITFIELD2(
	    connection_rate		:4,
	    features			:4);
	uint16_t 	itag;			/* initiator connection tag */
	uint8_t 	sas_dst[8];		/* destination sas address */
	uint8_t 	sas_src[8];		/* source sas address */
	uint8_t 	src_zone_group;		/* source zone group  */
	uint8_t 	path_block_count;	/* pathway blocked count */
	uint16_t	arb_wait_time;		/* arbitration wait time */
	uint8_t 	compat[4];		/* 'more' compatible features */
} sas_open_af_t;

#define	SAS_AF_IDENTIFY			0
#define	SAS_AF_OPEN			1

#define	SAS_IF_DTYPE_ENDPOINT		1
#define	SAS_IF_DTYPE_EDGE		2
#define	SAS_IF_DTYPE_FANOUT		3	/* obsolete */

#define	SAS_OF_PROTO_SMP		0
#define	SAS_OF_PROTO_SSP		1
#define	SAS_OF_PROTO_STP		2

#define	SAS_SSP_SUPPORT			0x8
#define	SAS_STP_SUPPORT			0x4
#define	SAS_SMP_SUPPORT			0x2


#define	SAS_CONNRATE_1_5_GBPS		0x8
#define	SAS_CONNRATE_3_0_GBPS		0x9
#define	SAS_CONNRATE_6_0_GBPS		0xA

#define	SAS_SATA_SUPPORT		0x1
#define	SAS_ATTACHED_NAME_OFFSET	52	/* SAS-2 only */

/*
 * SSP Definitions
 */
typedef struct {
	uint8_t		lun[8];
	uint8_t		reserved0;
	DECL_BITFIELD3(
	    task_attribute	:2,
	    command_priority	:4,
	    enable_first_burst	:1);
	uint8_t		reserved1;
	DECL_BITFIELD2(
	    reserved2		:2,
	    addi_cdb_len	:6);
	uint8_t		cdb[16];
	/* additional cdb bytes go here, followed by 4 byte CRC */
} sas_ssp_cmd_iu_t;

#define	SAS_CMD_TASK_ATTR_SIMPLE	0x00
#define	SAS_CMD_TASK_ATTR_HEAD		0x01
#define	SAS_CMD_TASK_ATTR_ORDERED	0x02
#define	SAS_CMD_TASK_ATTR_ACA		0x04

typedef struct {
	uint8_t		reserved0[8];
	uint16_t	status_qualifier;
	DECL_BITFIELD2(
	    datapres		:2,
	    reserved1		:6);
	uint8_t		status;
	uint8_t		reserved2[4];
	uint32_t	sense_data_length;
	uint32_t	response_data_length;
	uint8_t		rspd[];
	/* response data followed by sense data goes here */
} sas_ssp_rsp_iu_t;

/* length of bytes up to response data */
#define	SAS_RSP_HDR_SIZE		24

#define	SAS_RSP_DATAPRES_NO_DATA	0x00
#define	SAS_RSP_DATAPRES_RESPONSE_DATA	0x01
#define	SAS_RSP_DATAPRES_SENSE_DATA	0x02

/*
 * When the RSP IU is type RESPONSE_DATA,
 * the first 4 bytes of response data should
 * be a Big Endian representation of one of
 * these codes.
 */
#define	SAS_RSP_TMF_COMPLETE		0x00
#define	SAS_RSP_INVALID_FRAME		0x02
#define	SAS_RSP_TMF_NOT_SUPPORTED	0x04
#define	SAS_RSP_TMF_FAILED		0x05
#define	SAS_RSP_TMF_SUCCEEDED		0x08
#define	SAS_RSP_TMF_INCORRECT_LUN	0x09
#define	SAS_RSP_OVERLAPPED_OIPTTA	0x0A

/*
 * Task Management Functions- should be in a SAM definition file
 */
#define	SAS_ABORT_TASK			0x01
#define	SAS_ABORT_TASK_SET		0x02
#define	SAS_CLEAR_TASK_SET		0x04
#define	SAS_LOGICAL_UNIT_RESET		0x08
#define	SAS_I_T_NEXUS_RESET		0x10
#define	SAS_CLEAR_ACA			0x40
#define	SAS_QUERY_TASK			0x80
#define	SAS_QUERY_TASK_SET		0x81
#define	SAS_QUERY_UNIT_ATTENTION	0x82

/*
 * PHY size changed from SAS1.1 to SAS2.
 */
#define	SAS_PHYNUM_MAX			127
#define	SAS_PHYNUM_MASK			0x7f

#define	SAS2_PHYNUM_MAX			254
#define	SAS2_PHYNUM_MASK		0xff


/*
 * Maximum SMP payload size, including CRC
 */
#define	SAS_SMP_MAX_PAYLOAD		1032
#ifdef	__cplusplus
}
#endif
#endif	/* _SAS_H */
