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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SAMPLE_UTILS_H
#define	_SAMPLE_UTILS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

void
__free_msg(int num_msg, struct pam_message *msg);

void
__free_resp(int num_msg, struct pam_response *resp);

int
__display_errmsg(
	int (*conv_funp)(),
	int num_msg,
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE],
	void *conv_apdp
);

int
__get_authtok(
	int (*conv_funp)(),
	int num_msg,
	char messages[PAM_MAX_NUM_MSG][PAM_MAX_MSG_SIZE],
	void *conv_apdp,
	struct pam_response	**ret_respp
);

#ifdef __cplusplus
}
#endif

#endif /* _SAMPLE_UTILS_H */
