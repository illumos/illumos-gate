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

#ifndef _SPCS_S_U_H
#define	_SPCS_S_U_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	USER level status support utilities
 */

#include <stdio.h>

/*
 *	Create and initialize local status. Call this prior to invoking
 * 	an ioctl
 *	@return The status or NULL if malloc failed
 */

spcs_s_info_t
spcs_s_ucreate();

/*
 *	Initialize ioctl status storage to "remove" any status present
 *	@param ustatus The status
 */

void
spcs_s_uinit(spcs_s_info_t ustatus);

/*
 *	Return a string with the module label and next status message text or
 *	NULL if none left. Supplemental values are edited into the text and
 *	the used status and values are removed so that subsequent calls will
 *	access the next piece of information.
 *	Note that status codes and supplemental values are processed in
 *	the reverse order of their insertion by SPCS kernel code. That is,
 *	spcs_s_string returns the "youngest" status information first (i.e.
 *	LIFO).
 *	Note that spcs_s_string will not have any error information in
 *	the special case where Solaris has aborted an ioctl and returned an
 *	error code via errno or the ioctl service code had an "early" error
 *	from copyin or could not allocate its status area. In this case
 *	spcs_s_string will return NULL the first time it is called and a
 *	positive integer error code will be present in errno and should get
 *	handled by the spcs_s_string caller appropriately by using strerror.
 *	@param ustatus  The status
 *	@param msg      A char array of at least SPCS_S_MAXTEXT length
 *	@return status message string or NULL if no more status present
 */

char *spcs_s_string(spcs_s_info_t ustatus, char *msg);

/*
 *	Write status info to the file specified
 *	Uses spsc_s_string to edit status into strings and output them
 *	to the file specifed in the same order that the status was inserted.
 *	If there is no status present but errno contains a positive value
 *	then it will be treated as a Solaris error code and its message text
 *	will be written. Note that this routine does NOT remove status
 *	information so it can be called more than once.
 *	@param ustatus  The status
 *	@param fd       The file descriptor to use for output
 */

void spcs_s_report(spcs_s_info_t ustatus, FILE *fd);

/*
 *	Release (free) ioctl status storage.
 *	Note that this interface is an extension to SPARC 1998/038 10/22/98
 *	commitment.
 *	@param ustatus_a The address of the status (set to NULL)
 */

void
spcs_s_ufree(spcs_s_info_t *ustatus_a);

/*
 *	Write message to log file.
 *	@param product	Product code for tagging in log file.
 *	@param ustatus  The status - may be NULL.
 *	@param format   printf style format.
 */

void
spcs_log(const char *product, spcs_s_info_t *ustatus, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif /* _SPCS_S_U_H */
