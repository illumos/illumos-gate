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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INSTALLF_H
#define	_INSTALLF_H


/*
 * Block comment that describes the contents of this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <cfext.h>

extern struct cfextra **extlist;
extern int eptnum;
extern int warnflag;
extern char *classname;

extern int	cfentcmp(const void *, const void *);
extern void	quit(int);
extern void	usage(void);
extern void	removef(int, char *[]);
extern int	installf(int, char *[]);
extern int	dofinal(VFP_T *, VFP_T *, int, char *, char *);

#ifdef __cplusplus
}
#endif

#endif /* _INSTALLF_H */
