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

#ifndef _TALKD_IMPL_H
#define	_TALKD_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the header, function and global variable definitions
 * used throughout the in.talkd source.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "ctl.h"

extern int debug;
extern char hostname[];

extern void print_error(char *string);
extern void print_response(CTL_RESPONSE *response);
extern void print_request(CTL_MSG *request);
extern void process_request(CTL_MSG *request, CTL_RESPONSE *response);
extern CTL_MSG *find_request(CTL_MSG *request);
extern CTL_MSG *find_match(CTL_MSG *request);
extern void insert_table(CTL_MSG *request, CTL_RESPONSE *response);
extern int delete_invite(int id_num);
extern int announce(CTL_MSG *request, char *remote_machine);
extern int new_id(void);

#ifdef __cplusplus
}
#endif

#endif /* _TALKD_IMPL_H */
