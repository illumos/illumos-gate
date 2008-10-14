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

#ifndef	_RDCRULES_H
#define	_RDCRULES_H

#ifdef	__cplusplus
extern "C" {
#endif

/* insert handy rule enforcing functions here */

extern int bitmap_in_use(int cmd, char *hostp, char *bmp);
extern int mounted(char *);
extern int can_enable(rdcconfig_t *rdc);
extern int can_reconfig_pbmp(rdcconfig_t *rdc, char *bmp);
extern int can_reconfig_sbmp(rdcconfig_t *rdc, char *bmp);
extern rdc_rc_t *cant_rsync(rdcconfig_t *rdc);

#ifdef	__cplusplus
}
#endif

#endif	/* _RDCRULES_H */
