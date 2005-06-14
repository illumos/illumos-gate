/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libdiskmgt.h"

dm_desc_type_t alias_assoc_types [] = {
	DM_DRIVE,
	-1
};

dm_desc_type_t bus_assoc_types [] = {
	DM_CONTROLLER,
	DM_BUS,
	-1
};

dm_desc_type_t controller_assoc_types [] = {
	DM_DRIVE,
	DM_PATH,
	DM_BUS,
	-1
};

dm_desc_type_t drive_assoc_types [] = {
	DM_CONTROLLER,
	DM_PATH,
	DM_ALIAS,
	DM_MEDIA,
	-1
};

dm_desc_type_t media_assoc_types [] = {
	DM_DRIVE,
	DM_PARTITION,
	DM_SLICE,
	-1
};

dm_desc_type_t partition_assoc_types [] = {
	DM_MEDIA,
	DM_SLICE,
	-1
};

dm_desc_type_t path_assoc_types [] = {
	DM_DRIVE,
	DM_CONTROLLER,
	-1
};

dm_desc_type_t slice_assoc_types [] = {
	DM_MEDIA,
	DM_PARTITION,
	-1
};
