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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NSCD_COMMON_H
#define	_NSCD_COMMON_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <synch.h>

/*
 * nscd internal return/error codes
 */
typedef enum {
	NSCD_SUCCESS			= 0,
	NSCD_INITIALIZATION_FAILED,
	NSCD_CTX_NOT_FOUND,
	NSCD_DB_ENTRY_FOUND,
	NSCD_DB_ENTRY_NOT_FOUND,
	NSCD_INVALID_ARGUMENT,
	NSCD_NO_MEMORY,
	NSCD_THREAD_CREATE_ERROR,
	NSCD_SMF_ERROR,
	NSCD_CFG_UNSUPPORTED_SWITCH_DB,
	NSCD_CFG_UNSUPPORTED_SWITCH_SRC,
	NSCD_CFG_DLOPEN_ERROR,
	NSCD_CFG_DLSYM_ERROR,
	NSCD_CFG_SET_PARAM_FAILED,
	NSCD_CFG_PARAM_DESC_ERROR,
	NSCD_CFG_STAT_DESC_ERROR,
	NSCD_CFG_INVALID_HANDLE,
	NSCD_CFG_PARSE_ERROR,
	NSCD_CFG_FILE_OPEN_ERROR,
	NSCD_CFG_FILE_ACCESS_ERROR,
	NSCD_CFG_SYNTAX_ERROR,
	NSCD_CFG_PRELIM_CHECK_FAILED,
	NSCD_CFG_DATA_CONVERSION_FAILED,
	NSCD_CFG_WRITE_ERROR,
	NSCD_CFG_READ_ONLY,
	NSCD_CFG_CHANGE_NOT_ALLOWED,
	NSCD_CREATE_NSW_STATE_FAILED,
	NSCD_CREATE_GETENT_CTX_FAILED,
	NSCD_NSS_BACKEND_NOT_FOUND,
	NSCD_DOOR_UCRED_ERROR,
	NSCD_DOOR_BUFFER_CHECK_FAILED,
	NSCD_SELF_CRED_NOT_CONFIGURED,
	NSCD_SELF_CRED_NO_FORKER,
	NSCD_SELF_CRED_WRONG_NSCD,
	NSCD_SELF_CRED_MAIN_IMPOSTER,
	NSCD_SELF_CRED_FORKER_IMPOSTER,
	NSCD_SELF_CRED_CHILD_IMPOSTER,
	NSCD_SELF_CRED_NO_DOOR,
	NSCD_SELF_CRED_NO_CHILD_SLOT,
	NSCD_SELF_CRED_INVALID_SLOT_NUMBER,
	NSCD_SELF_CRED_INVALID_SLOT_STATE,
	NSCD_ADMIN_FAIL_TO_SET,
	NSCD_CACHE_INVALID_CACHE_NAME,
	NSCD_CACHE_NO_CACHE_CTX,
	NSCD_CACHE_DISABLED,
	NSCD_CACHE_NO_CACHE_FOUND,
	NSCD_CACHE_AVOID_NS

} nscd_rc_t;


/* nscd data type: boolean */
typedef	uint8_t		nscd_bool_t;
#define	nscd_true	1
#define	nscd_false	0

/* common functions */
void _nscd_set_start_time(int reset);
time_t _nscd_get_start_time();
nscd_rc_t _nscd_init(char *cfgfile);
nscd_rc_t _nscd_refresh();

#ifdef	__cplusplus
}
#endif

#endif	/* _NSCD_COMMON_H */
