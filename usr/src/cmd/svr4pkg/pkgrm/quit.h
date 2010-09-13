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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Header:	pkgrm: quit.c
 *
 * Function:	external definitions for references to the quit.c module
 *
 */

#ifndef	__PKGRM_QUIT_H__
#define	__PKGRM_QUIT_H__


#ifdef __cplusplus
extern "C" {
#endif

/*
 * required include files
 */

#include "libinst.h"

/*
 * exported (global) functions
 */

typedef void (intfRelocFunc_t)(void);

extern void	quit(int retcode);
extern void	quitSetCkreturnFunc(ckreturnFunc_t *a_ckreturnFunc);
extern void	quitSetZoneName(char *a_zoneName);
extern void	quitSetZoneTmpdir(char *z_zoneTempDir);
extern sighdlrFunc_t *quitGetTrapHandler(void);
extern void	quitSetIntfReloc(intfRelocFunc_t *a_intfReloc);

#ifdef __cplusplus
}
#endif

#endif	/* __PKGRM_QUIT_H__ */
