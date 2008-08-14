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
#ifndef _MMS_MGMT_MEDIA_H
#define	_MMS_MGMT_MEDIA_H


/*
 * mgmt_media.h
 */

#include <stdio.h>

#include "mms.h"
#include "mgmt_util.h"

/* structure to define a cartridge in MMS */
typedef struct {
	mms_list_node_t	next;
	char		label[MAXNAMELEN];
	time_t		access;
	size_t		capacity;
	int32_t		libacs;
	int32_t		liblsm;
	char		mtype[MAXNAMELEN];
	char		libname[MAXNAMELEN];
	char		groupname[MAXNAMELEN];
	char		appname[MAXNAMELEN];
} mms_acscart_t;

#endif	/* _MMS_MGMT_MEDIA_H */
