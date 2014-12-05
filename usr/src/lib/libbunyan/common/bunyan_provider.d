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
 * Copyright (c) 2014, Joyent, Inc. 
 */

/*
 * Bunyan DTrace provider
 */
provider bunyan {
	probe log__trace(char *);
	probe log__debug(char *);
	probe log__info(char *);
	probe log__warn(char *);
	probe log__error(char *);
	probe log__fatal(char *);
};

#pragma D attributes Stable/Stable/ISA		provider bunyan provider
#pragma D attributes Private/Private/Unknown	provider bunyan module
#pragma D attributes Private/Private/Unknown	provider bunyan function
#pragma D attributes Stable/Stable/ISA		provider bunyan name
#pragma D attributes Stable/Stable/ISA		provider bunyan args
