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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IPP_METERS_METER_H
#define	_IPP_METERS_METER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/* Header file for meters -- tokenmt and tswtclmt */

/* nvpair parameters for meter */
#define	TOKENMT_RED_ACTION_NAME		"tokenmt.red_action_name"
#define	TOKENMT_YELLOW_ACTION_NAME	"tokenmt.yellow_action_name"
#define	TOKENMT_GREEN_ACTION_NAME 	"tokenmt.green_action_name"
#define	TOKENMT_COMMITTED_RATE		"tokenmt.committed_rate"
#define	TOKENMT_COMMITTED_BURST		"tokenmt.committed_burst"
#define	TOKENMT_PEAK_RATE		"tokenmt.peak_rate"
#define	TOKENMT_PEAK_BURST		"tokenmt.peak_burst"
#define	TOKENMT_COLOUR_AWARE		"tokenmt.color_aware"
#define	TOKENMT_COLOUR_MAP		"tokenmt.color_map"

/* nvpair parameters for tswtclmt */
#define	TSWTCL_RED_ACTION_NAME		"tswtclmt.red_action_name"
#define	TSWTCL_YELLOW_ACTION_NAME	"tswtclmt.yellow_action_name"
#define	TSWTCL_GREEN_ACTION_NAME 	"tswtclmt.green_action_name"
#define	TSWTCL_COMMITTED_RATE		"tswtclmt.committed_rate"
#define	TSWTCL_PEAK_RATE		"tswtclmt.peak_rate"
#define	TSWTCL_WINDOW			"tswtclmt.window"

#ifdef	__cplusplus
}
#endif

#endif /* _IPP_METERS_METER_H */
