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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _L_DEFINES_H_
#define	_L_DEFINES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <unistd.h>
#include <locale.h>
#include <libintl.h>
#include <stdlib.h>
#include <sys/smedia.h>

struct raw_params {
	uint32_t offset;
	char *buffer;
	size_t size;
	};

struct format_track {
	int32_t track_no;
	int32_t head;
	uint32_t flag;
	};

struct format_flags {
	uint32_t flavor;
	uint32_t mode;
	};

#ifdef DEBUG
#define	DPRINTF(str)			(void) printf(str)
#define	DPRINTF1(str, a)		(void) printf(str, a)
#define	DPRINTF2(str, a, b)		(void) printf(str, a, b)
#define	DPRINTF3(str, a, b, c)		(void) printf(str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)	(void) printf(str, a, b, c, d)
#else
#define	DPRINTF(str)
#define	DPRINTF1(str, a)
#define	DPRINTF2(str, a, b)
#define	DPRINTF3(str, a, b, c)
#define	DPRINTF4(str, a, b, c, d)
#endif


#define	SM_FD_VERSION_1 	1
#define	SM_SCSI_VERSION_1 	1
#define	SM_PCMEM_VERSION_1 	1
#define	SM_PLUGIN_VERSION	1
#define	SM_PCATA_VERSION_1 	1
#define	SM_BLKDEV_VERSION_1	1

#ifdef __cplusplus
}
#endif

#endif /* _L_DEFINES_H_ */
