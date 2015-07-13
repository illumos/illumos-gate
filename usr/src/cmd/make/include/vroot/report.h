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
 * Copyright 1994 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _REPORT_H_
#define _REPORT_H_

#include <stdio.h>

extern FILE	*get_report_file(void);
extern char	*get_target_being_reported_for(void);
extern void	report_dependency(const char *name);
extern int	file_lock(char *name, char *lockname, int *file_locked, int timeout);

#define SUNPRO_DEPENDENCIES "SUNPRO_DEPENDENCIES"
#define LD 	"LD"
#define COMP 	"COMP"

/*
 * These relate to Sun's ancient source control system that predated TeamWare,
 * named NSE.  They appear to be used regardless of its presence, however, and
 * so linger.
 */
#define NSE_DEPINFO 		".nse_depinfo"
#define NSE_DEPINFO_LOCK 	".nse_depinfo.lock"

#endif
