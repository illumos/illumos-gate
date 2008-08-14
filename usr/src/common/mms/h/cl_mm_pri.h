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


#ifndef _CL_MM_PRI_
#define	_CL_MM_PRI_

#ifndef _CL_MM_PUB_
#include "cl_mm_pub.h"
#endif


#define	MM_INTERNAL_FILES		"data/internal/mixed_media"

#define	MEDIA_TYPES_FILE		"media_types.dat"
#define	MEDIA_COMPAT_FILE		"media_compatibility.dat"
#define	MEDIA_CLEAN_FILE		"media_cleaning.dat"
#define	DRIVE_TYPES_FILE		"drive_types.dat"

#define	MM_EXTERNAL_FILES		"data/external/mixed_media"

#define	SCRATCH_PREFERENCES_FILE	"scratch_preferences.dat"

extern int Mm_max_media_types;
extern int Mm_max_drive_types;

extern MEDIA_TYPE_INFO *Mm_media_info_ptr;
extern DRIVE_TYPE_INFO *Mm_drive_info_ptr;

#define	MM_DRIVE_TYPE		"drive type"
#define	MM_LIB_DRIVE_TYPE	"library drive type"
#define	MM_DRIVE_TYPE_NAME	"drive type name"

#define	MM_MEDIA_TYPE		"media type"
#define	MM_LIB_MEDIA_TYPE	"library media type"
#define	MM_MEDIA_TYPE_NAME	"media type name"
#define	MM_CLEAN_CART		"cleaning cartridge type"
#define	MM_MAX_USE		"max usage"

typedef struct  {
	CLN_CART_CAPABILITY	val;
	char *name;
} MM_CLN_CAPAB;

extern MM_CLN_CAPAB mm_cln_capab[];

extern STATUS cl_mm_init(void);
extern STATUS cl_mm_media_types(void);
extern STATUS cl_mm_drive_types(void);
extern STATUS cl_mm_compat(void);
extern STATUS cl_mm_clean(void);
extern STATUS cl_mm_scr_pref(void);

#endif /* _CL_MM_PRI_ */
