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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2017-2021 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * See: DTRACE_PROBE... in ./sys/sdt.h
 */

provider fksmb {
	/* generic probes */
	probe probe0(char *probename);
	probe probe1(char *probename, unsigned long arg1);
	probe probe2(char *probename, unsigned long arg1, unsigned long arg2);
	probe probe3(char *probename, unsigned long arg1, unsigned long arg2,
	    unsigned long arg3);
	/* smb provider probes */
	probe smb_start(char *probename, unsigned long arg1);
	probe smb_done(char *probename, unsigned long arg1);
	/* smb2 provider probes */
	probe smb2_start(char *probename, unsigned long arg1);
	probe smb2_done(char *probename, unsigned long arg1);
	probe set__error(int err);
};

#pragma D attributes Evolving/Evolving/ISA provider fksmb provider
#pragma D attributes Private/Private/Unknown provider fksmb module
#pragma D attributes Private/Private/Unknown provider fksmb function
#pragma D attributes Evolving/Evolving/ISA provider fksmb name
#pragma D attributes Evolving/Evolving/ISA provider fksmb args
