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

#ifndef	_FMADM_H
#define	_FMADM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <fm/fmd_adm.h>
#include <stdio.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	FMADM_EXIT_SUCCESS	0
#define	FMADM_EXIT_ERROR	1
#define	FMADM_EXIT_USAGE	2

extern void note(const char *format, ...);
extern void warn(const char *format, ...);
extern void die(const char *format, ...);

extern int cmd_config(fmd_adm_t *, int, char *[]);
extern int cmd_faulty(fmd_adm_t *, int, char *[]);
extern int cmd_flush(fmd_adm_t *, int, char *[]);
extern int cmd_gc(fmd_adm_t *, int, char *[]);
extern int cmd_load(fmd_adm_t *, int, char *[]);
extern int cmd_repair(fmd_adm_t *, int, char *[]);
extern int cmd_repaired(fmd_adm_t *, int, char *[]);
extern int cmd_replaced(fmd_adm_t *, int, char *[]);
extern int cmd_acquit(fmd_adm_t *, int, char *[]);
extern int cmd_reset(fmd_adm_t *, int, char *[]);
extern int cmd_rotate(fmd_adm_t *, int, char *[]);
extern int cmd_unload(fmd_adm_t *, int, char *[]);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMADM_H */
