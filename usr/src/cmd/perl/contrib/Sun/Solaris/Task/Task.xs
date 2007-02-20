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
 *
 * Task.xs contains XS wrappers for the task maniplulation functions.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* Solaris includes. */
#include <sys/task.h>

/* Perl includes. */
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

/*
 * The XS code exported to perl is below here.  Note that the XS preprocessor
 * has its own commenting syntax, so all comments from this point on are in
 * that form.
 */

MODULE = Sun::Solaris::Task PACKAGE = Sun::Solaris::Task
PROTOTYPES: ENABLE

 #
 # Define any constants that need to be exported.  By doing it this way we can
 # avoid the overhead of using the DynaLoader package, and in addition constants
 # defined using this mechanism are eligible for inlining by the perl
 # interpreter at compile time.
 #
BOOT:
	{
	HV *stash;

	stash = gv_stashpv("Sun::Solaris::Task", TRUE);
	newCONSTSUB(stash, "TASK_NORMAL", newSViv(TASK_NORMAL));
	newCONSTSUB(stash, "TASK_FINAL", newSViv(TASK_FINAL));
	newCONSTSUB(stash, "TASK_PROJ_PURGE", newSViv(TASK_PROJ_PURGE));
	}

taskid_t
settaskid(project, flags)
	projid_t	project
	int		flags

taskid_t
gettaskid()

