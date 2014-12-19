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
 * Copyright (c) 2014 Joyent, Inc.  All rights reserved.
 */

provider lx {
	probe debug(char *buf);
	probe sigdeliver(int sig, void *lx_sigaction, void *lx_sigstack,
	    void *lx_ucontext);
	probe sigreturn(void *lx_ucontext, void *ucontext, uintptr_t sp);
};

#pragma D attributes Evolving/Evolving/ISA provider lx provider
#pragma D attributes Private/Private/Unknown provider lx module
#pragma D attributes Private/Private/Unknown provider lx function
#pragma D attributes Private/Private/ISA provider lx name
#pragma D attributes Private/Private/ISA provider lx args
