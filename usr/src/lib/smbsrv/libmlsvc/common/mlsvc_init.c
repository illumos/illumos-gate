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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <unistd.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/mlsvc_util.h>
#include <smbsrv/lsalib.h>

void dssetup_initialize(void);
void srvsvc_initialize(void);
void wkssvc_initialize(void);
void lsarpc_initialize(void);
void logr_initialize(void);
void netr_initialize(void);
void samr_initialize(void);
void svcctl_initialize(void);
void winreg_initialize(void);

/*
 * All mlrpc initialization is invoked from here.
 * Returns 0 upon success.  Otherwise, returns -1.
 */
int
mlsvc_init(void)
{
	srvsvc_initialize();
	wkssvc_initialize();
	lsarpc_initialize();
	netr_initialize();
	dssetup_initialize();
	samr_initialize();
	svcctl_initialize();
	winreg_initialize();
	logr_initialize();

	(void) sam_init();
	return (0);
}
