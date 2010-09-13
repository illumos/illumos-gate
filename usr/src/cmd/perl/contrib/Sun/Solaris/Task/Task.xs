/*
 * Copyright (c) 2002, 2007, Oracle and/or its affiliates. All rights reserved.
 */
/*
 * Task.xs contains XS wrappers for the task maniplulation functions.
 */

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

