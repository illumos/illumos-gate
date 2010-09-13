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

#ifndef	_COMMON_H
#define	_COMMON_H

#ifdef	__cplusplus
extern "C" {
#endif

/* Prototypes */
void *kstat_value(kstat_t *, char *);
kstat_t *kstat_retrieve(kstat_ctl_t *, kstat_t *);
void kstat_free(kstat_t *);
uint32_t kstat_delta(kstat_t *, kstat_t *, char *);

#ifdef	__cplusplus
}
#endif

#endif /* _COMMON_H */
