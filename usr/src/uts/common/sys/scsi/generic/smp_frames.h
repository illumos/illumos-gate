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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_SCSI_IMPL_SMP_FRAME_H
#define	_SYS_SCSI_IMPL_SMP_FRAME_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/sysmacros.h>

/*
 * The definitions of smp frame types and functions conforming to SAS v1.1.
 * The SAS v2.0 will be supported in the future when it is publicly released.
 */

typedef enum  {
	SMP_FRAME_TYPE_REQUEST		= 0x40,
	SMP_FRAME_TYPE_RESPONSE		= 0x41
} smp_frame_types;

typedef enum {
	SMP_REPORT_GENERAL			= 0x00,
	SMP_REPORT_MANUFACTURER_INFO	= 0x01,
	SMP_DISCOVER				= 0x10,
	SMP_REPORT_PHY_ERROR_LOG		= 0x11,
	SMP_PHY_SATA				= 0x12,
	SMP_REPORT_ROUTE_INFORMATION	= 0x13,
	SMP_CONFIG_ROUTE_INFORMATION	= 0x90,
	SMP_PHY_CONTROL			= 0x91,
	SMP_PHY_TEST_FUNCTION		= 0x92
} smp_func_types;

/*
 * The reqsize and rspsize in usmp_req and usmp_rsp are reserved in
 * SAS v1.1, and the fields should be zero if target device is SAS v1.1
 * compliant.
 */

#pragma	pack(1)
typedef struct usmp_req {
	uint8_t		smpo_frametype;
	uint8_t		smpo_function;
	uint8_t		smpo_reserved;
	uint8_t		smpo_reqsize;
	uint8_t		smpo_msgframe[1];
} usmp_req_t;

typedef struct usmp_rsp {
	uint8_t		smpi_frametype;
	uint8_t		smpi_function;
	uint8_t		smpi_result;
	uint8_t		smpi_rspsize;
	uint8_t		smpi_msgframe[1];
} usmp_rsp_t;

struct smp_crc {
	uint8_t code[4];
};

struct smp_report_general_req {
	uint8_t		frametype;
	uint8_t		function;
	uint8_t 	reserved_byte2;
	uint8_t 	reqsize;
	struct smp_crc	crc;
};

struct smp_report_general_rsp {
	uint8_t		frametype;
	uint8_t		function;
	uint8_t 	result;
	uint8_t 	rspsize;
	uint8_t 	expand_change_count1;
	uint8_t 	expand_change_count0;
	uint8_t 	expand_route_index1;
	uint8_t 	expand_route_index0;
	uint8_t 	reserved_byte8;
	uint8_t		num_of_phy;
	DECL_BITFIELD3(
	    crt			:1,
	    configuring		:1,
	    reserved_byte10	:6);
	uint8_t		reserved_byte11;
	uint64_t	identifier;
	uint8_t		reserved_byte20[8];
	struct smp_crc	crc;
};
#pragma	pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_IMPL_SMP_FRAME_H */
