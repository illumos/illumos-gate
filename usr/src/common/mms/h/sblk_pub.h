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


#ifndef _SBLK_DEFS_
#define	_SBLK_DEFS_


#include <time.h>

#ifndef _DEFS_
#include "defs.h"
#endif


typedef int		COUNT_TYPE;
BOOLEAN cl_sblk_attach(void);
BOOLEAN cl_sblk_available(void);
int cl_sblk_cleanup(void);
BOOLEAN cl_sblk_create(void);
BOOLEAN cl_sblk_destroy(void);
BOOLEAN cl_sblk_read(char *packet, int message_number, int *message_size);
BOOLEAN cl_sblk_remove(int message_number);
int cl_sblk_write(void *message, int message_count, int process_count);


#endif /* _SBLK_DEFS_ */
