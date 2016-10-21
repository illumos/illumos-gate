/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * A little program who's only purpose is to get all the
 * CTF type information we want into an object.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/corectl.h>
#define	_STRUCTURED_PROC	1
#include <sys/procfs.h>
#include <sys/auxv.h>
#include <sys/old_procfs.h>
#include <sys/utsname.h>
#include <sys/secflags.h>

/* prgregset_t is a define on intel */
#ifdef prgregset_t
typedef	prgregset_t
#undef prgregset_t
    prgregset_t;
#endif

/* instantiate the types for CTF */
auxv_t auxv;
prgregset_t prgregset;
lwpstatus_t lwpstatus;
pstatus_t pstatus;
prstatus_t prstatus;
psinfo_t psinfo;
prpsinfo_t prpsinfo;
lwpsinfo_t lwpsinfo;
prcred_t prcred;
prpriv_t prpriv;
priv_impl_info_t priv_impl;
fltset_t fltset;
siginfo_t siginfo;
sigset_t sigset;
struct sigaction sigact;
stack_t stack;
sysset_t sysset;
timestruc_t ts;
struct utsname uts;
prfdinfo_t ptfd;
prsecflags_t psf;
