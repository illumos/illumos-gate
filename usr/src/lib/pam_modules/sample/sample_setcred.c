/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1992-1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#include <libintl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define	PAMTXD	"SUNW_OST_SYSOSPAM"

/*
 * pam_sm_setcred
 */
/*ARGSUSED*/
int
pam_sm_setcred(
	pam_handle_t *pamh,
	int   flags,
	int	argc,
	const char **argv)
{

	/*
	 * Set the credentials
	 */

	return (PAM_SUCCESS);
}
