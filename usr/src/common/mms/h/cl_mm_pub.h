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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _CL_MM_PUB_
#define	_CL_MM_PUB_

#ifndef _LIB_MIXED_MEDIA_
#include "lib_mixed_media.h"
#endif

#ifndef _DEFS_
#include "defs.h"
#endif

#define	MM_UNK_MEDIA_TYPE_NAME	"unknown"

#define	MM_UNK_DRIVE_TYPE_NAME	"unknown"

typedef char MEDIA_TYPE_NAME[MEDIA_TYPE_NAME_LEN + 1];
typedef char DRIVE_TYPE_NAME[DRIVE_TYPE_NAME_LEN + 1];

typedef struct {
    MEDIA_TYPE		media_type;
    LIB_MEDIA_TYPE	lib_media_type;
    MEDIA_TYPE_NAME	media_type_name;
    CLN_CART_CAPABILITY	cleaning_cartridge;
    unsigned short	max_cleaning_usage;
    DRIVE_TYPE		compat_drive_types[MM_MAX_COMPAT_TYPES];
} MEDIA_TYPE_INFO;

typedef struct {
    DRIVE_TYPE		drive_type;
    LIB_DRIVE_TYPE	lib_drive_type;
    DRIVE_TYPE_NAME	drive_type_name;
    unsigned short	compat_count;
    MEDIA_TYPE 		compat_media_types[MM_MAX_COMPAT_TYPES];

    unsigned short	preferred_count;
    MEDIA_TYPE		preferred_media_types[MM_MAX_COMPAT_TYPES];
} DRIVE_TYPE_INFO;

extern STATUS cl_drv_type(DRIVE_TYPE drive_type,
	DRIVE_TYPE_INFO **drive_type_info);
extern STATUS cl_drv_type_lib(LIB_DRIVE_TYPE drive_type,
	DRIVE_TYPE_INFO **drive_type_info);
extern STATUS cl_drv_type_name(DRIVE_TYPE_NAME drive_type,
	DRIVE_TYPE_INFO **drive_type_info);

extern STATUS cl_mt_info(MEDIA_TYPE media_type,
	MEDIA_TYPE_INFO **media_type_info);
extern STATUS cl_mt_lib(LIB_MEDIA_TYPE media_type,
	MEDIA_TYPE_INFO **media_type_info);
extern STATUS cl_mt_name(MEDIA_TYPE_NAME media_type,
	MEDIA_TYPE_INFO **media_type_info);

#endif /* _CL_MM_PUB_ */
