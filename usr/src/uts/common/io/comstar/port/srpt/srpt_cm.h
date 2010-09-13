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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SRPT_CM_H
#define	_SRPT_CM_H

/*
 * Prototypes and data structures specific to Infiniband CM
 * interface.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/* Prototypes */

ibt_cm_status_t srpt_cm_hdlr(void *cm_private, ibt_cm_event_t *eventp,
	ibt_cm_return_args_t *ret_args, void *ret_priv_data,
	ibt_priv_data_len_t ret_len_max);

#ifdef	__cplusplus
}
#endif

#endif /* _SRPT_CM_H */
