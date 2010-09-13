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

/*
 * sppptun_mod.h - References between sppptun.c and sppptun_mod.c
 */

#ifndef	_SPPPTUN_MOD_H
#define	_SPPPTUN_MOD_H

#ifdef	__cplusplus
extern "C" {
#endif

extern struct streamtab sppptun_tab;
extern void sppptun_init(void);
extern void sppptun_tcl_init(void);
extern int sppptun_tcl_fintest(void);
extern void sppptun_tcl_fini(void);

/*
 * Description strings kept in sppptun.c because we're more interested
 * in the revision of that module.
 */
extern const char sppptun_driver_description[];
extern const char sppptun_module_description[];

#ifdef	__cplusplus
}
#endif

#endif /* _SPPPTUN_MOD_H */
