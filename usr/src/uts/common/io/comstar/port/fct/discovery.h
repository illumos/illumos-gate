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
#ifndef	_DISCOVERY_H
#define	_DISCOVERY_H

#ifdef	__cplusplus
extern "C" {
#endif

extern char *fct_els_names[];

#define	FCT_ELS_NAME(op)	(((op > 0x7f) || (fct_els_names[(op)] == 0)) ? \
					"" : (fct_els_names[(op)]))

void fct_port_worker(void *arg);
void fct_handle_els(fct_cmd_t *cmd);
void fct_handle_sol_els_completion(fct_i_local_port_t *iport,
						fct_i_cmd_t *icmd);

#ifdef	__cplusplus
}
#endif

#endif /* _DISCOVERY_H */
