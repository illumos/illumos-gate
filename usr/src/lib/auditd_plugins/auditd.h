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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2017 Tintri by DDN, Inc. All rights reserved.
 *
 * This is an unstable interface; changes may be made without
 * notice.
 */

#ifndef	_AUDITD_H
#define	_AUDITD_H

#include <secdb.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * "WARN" errors trigger calls to audit_warn
 */
enum auditd_rc {
	AUDITD_SUCCESS,	/*   ok						*/
	AUDITD_RETRY,	/*   retry after a delay	(WARN retry)	*/
	AUDITD_NO_MEMORY, /* can't allocate memory	(WARN no_memory) */
	AUDITD_INVALID,	/*   bad input			(WARN invalid)	*/
	AUDITD_COMM_FAIL, /* communications failure			*/
	AUDITD_FATAL,	/*   other error		(WARN failure)	*/
	AUDITD_FAIL,	/*   other non-fatal error			*/
	AUDITD_DISCARD	/*   Discarded message				*/
};
typedef enum auditd_rc auditd_rc_t;

/*
 * auditd_plugin()
 *	arg 1 - input buffer, binary Solaris audit record
 *	arg 2 - input buffer length
 *	arg 3 - record sequence number
 *	arg 4 - optional explanation of error return (use NULL,
 *		not an empty string if not used.)
 */
auditd_rc_t	auditd_plugin(const char *, size_t, uint64_t, char **);
/*
 * auditd_plugin_open()
 *	arg 1 - attr/val struct, use with kva_match()
 *	arg 2 - attr/value pair string:  attr1=value1;attr2=value2
 *	arg 3 - optional explanation of error return (use NULL,
 *		not an empty string if not used.)
 *
 *	make local copy of args 1 and 2; they are trashed after return.
 */
auditd_rc_t	auditd_plugin_open(const kva_t *, char **, char **);

/*
 * auditd_plugin_close()
 *	arg 1 - optional explanation of error return (use NULL,
 *		not an empty string if not used.)
 */
auditd_rc_t	auditd_plugin_close(char **);

#ifdef	__cplusplus
}
#endif

#endif	/* _AUDITD_H */
