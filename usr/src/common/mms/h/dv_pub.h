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


#ifndef _DV_PUB_
#define	_DV_PUB_

#ifndef NOT_CSC
#include "dv_api.h"
#else
#ifndef _DEFS_
#include "defs.h"
#endif

#ifndef _DV_TAG_
#include "dv_tag.h"
#endif

#ifndef _SBLK_DEFS_
#include "sblk_defs.h"
#endif


#define	DV_VALUE_LEN		128

STATUS 	dv_shm_create(enum dshm_build_flag build_flag, char **cpp_memory);
STATUS 	dv_shm_destroy(void);
STATUS 	dv_get_boolean(DV_TAG tag, BOOLEAN *Bpw_bool);
int		dv_get_count(void);
STATUS 	dv_get_mask(DV_TAG tag, unsigned long *lpw_mask);
STATUS 	dv_get_number(DV_TAG tag, long *lpw_value);
STATUS 	dv_get_string(DV_TAG tag, char *cpw_string);
STATUS		dv_check(void);

#endif

#endif /* _DV_PUB_ */
