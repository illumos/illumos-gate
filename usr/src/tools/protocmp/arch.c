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
#include <string.h>

#include "list.h"

int
assign_arch(const char *architecture)
{
	int	arch = 0;

#if defined(__sparc)
	if (strcmp(architecture, "sparc") == 0)
		arch = P_SPARC;
	else if (strcmp(architecture, "ISA") == 0)
		arch = P_SPARC;
	else if (strcmp(architecture, "all") == 0)
		arch = P_SPARC;
	else if (strcmp(architecture, "sparc.sun4") == 0)
		arch = P_SUN4;
	else if (strcmp(architecture, "sparc.sun4c") == 0)
		arch = P_SUN4c;
	else if (strcmp(architecture, "sparc.sun4u") == 0)
		arch = P_SUN4u;
	else if (strcmp(architecture, "sparc.sun4d") == 0)
		arch = P_SUN4d;
	else if (strcmp(architecture, "sparc.sun4e") == 0)
		arch = P_SUN4e;
	else if (strcmp(architecture, "sparc.sun4m") == 0)
		arch = P_SUN4m;
	else if (strcmp(architecture, "sparc.sun4v") == 0)
		arch = P_SUN4v;
#elif defined(__i386)
	if (strcmp(architecture, "i386") == 0)
		arch = P_I386;
	else if (strcmp(architecture, "ISA") == 0)
		arch = P_I386;
	else if (strcmp(architecture, "all") == 0)
		arch = P_I386;
	else if (strcmp(architecture, "i386.i86pc") == 0)
		arch = P_I86PC;
#elif defined(__ppc)
	if (strcmp(architecture, "ppc") == 0)
		arch = P_PPC;
	else if (strcmp(architecture, "ISA") == 0)
		arch = P_PPC;
	else if (strcmp(architecture, "all") == 0)
		arch = P_PPC;
	else if (strcmp(architecture, "ppc.prep") == 0)
		arch = P_PREP;
#else
#error "Unknown instruction set"
#endif

	return (arch);
}
