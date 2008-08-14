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


#ifndef _DV_TAG_
#define	_DV_TAG_

typedef enum dv_tag {
	DV_TAG_FIRST = 0,
	DV_TAG_EVENT_FILE_NUMBER,
	DV_TAG_LOG_PATH,
	DV_TAG_LOG_SIZE,
	DV_TAG_TIME_FORMAT,
	DV_TAG_UNIFORM_CLEAN_USE,
	DV_TAG_AC_CMD_ACCESS,
	DV_TAG_AC_CMD_DEFAULT,
	DV_TAG_AC_VOL_ACCESS,
	DV_TAG_AC_VOL_DEFAULT,
	DV_TAG_AC_LOG_ACCESS,
	DV_TAG_CSI_CONNECT_AGETIME,
	DV_TAG_CSI_RETRY_TIMEOUT,
	DV_TAG_CSI_RETRY_TRIES,
	DV_TAG_CSI_TCP_RPCSERVICE,
	DV_TAG_CSI_UDP_RPCSERVICE,
	DV_TAG_AUTO_CLEAN,
	DV_TAG_AUTO_START,
	DV_TAG_MAX_ACSMT,
	DV_TAG_MAX_ACS_PROCESSES,
	DV_TAG_TRACE_ENTER,
	DV_TAG_TRACE_VOLUME,
	DV_TAG_ACSLS_MIN_VERSION,
	DV_TAG_DI_TRACE_FILE,
	DV_TAG_DI_TRACE_VALUE,
	DV_TAG_LM_RP_TRAIL,
	DV_TAG_ACSLS_ALLOW_ACSPD,
	DV_TAG_LAST
} DV_TAG;

#endif /* _DV_TAG_ */
