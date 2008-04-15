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

#ifndef _DR_IO_H
#define	_DR_IO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * VIO DR Control Protocol
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Values of 'msg_type' element of the request message
 */
#define	DR_VIO_CONFIGURE	0x494f43	/* 'IOC' */
#define	DR_VIO_UNCONFIGURE	0x494f55	/* 'IOU' */
#define	DR_VIO_FORCE_UNCONFIG	0x494f46	/* 'IOF' */
#define	DR_VIO_STATUS		0x494f53	/* 'IOS' */

/*
 * VIO DR Request
 */
typedef struct {
	uint64_t	req_num;
	uint64_t	dev_id;
	uint32_t	msg_type;
	char		name[1];
} dr_vio_req_t;

/*
 * Values of 'result' element of the response message
 */
#define	DR_VIO_RES_OK			0x0
#define	DR_VIO_RES_FAILURE		0x1
#define	DR_VIO_RES_BLOCKED		0x2
#define	DR_VIO_RES_NOT_IN_MD		0x3

/*
 * Values of 'status' element of the response message
 */
#define	DR_VIO_STAT_NOT_PRESENT		0x0
#define	DR_VIO_STAT_UNCONFIGURED	0x1
#define	DR_VIO_STAT_CONFIGURED		0x2

/*
 * VIO DR Response
 */
typedef struct {
	uint64_t	req_num;
	uint32_t	result;
	uint32_t	status;
	char		reason[1];
} dr_vio_res_t;

#define	DR_VIO_DS_ID		"dr-vio"
#define	DR_VIO_MAXREASONLEN	1024

#ifdef __cplusplus
}
#endif

#endif /* _DR_IO_H */
