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
 * Copyright (c) 2002-2006 Neterion, Inc.
 */

#ifndef VERSION_H
#define VERSION_H

#include "build-version.h"

#define XGE_HAL_VERSION_MAJOR	"2"
#define XGE_HAL_VERSION_MINOR	"5"
#define XGE_HAL_VERSION_FIX	"0"
#define XGE_HAL_VERSION_BUILD	GENERATED_BUILD_VERSION
#define XGE_HAL_VERSION XGE_HAL_VERSION_MAJOR"."XGE_HAL_VERSION_MINOR"."\
			XGE_HAL_VERSION_FIX"."XGE_HAL_VERSION_BUILD
#define XGE_HAL_DESC	XGE_DRIVER_NAME" v."XGE_HAL_VERSION

#ifdef XGELL_VERSION_DEFINITION_PROVIDED
/* Link Layer versioning */
#include "xgell-version.h"
#else
#define XGELL_VERSION_MAJOR	"0"
#define XGELL_VERSION_MINOR	"0"
#define XGELL_VERSION_FIX	"0"
#define XGELL_VERSION_BUILD	"0"
#define XGELL_VERSION            XGELL_VERSION_MAJOR"."XGELL_VERSION_MINOR
#endif

#endif /* VERSION_H */
