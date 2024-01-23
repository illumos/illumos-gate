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
 * Copyright 2024 Oxide Computer Company
 */

#ifndef _SYS_EXECX_H
#define	_SYS_EXECX_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * If this flag is set then the first argument to execvex() is interpreted as
 * a file descriptor that is open in the calling process rather than the name
 * of a program to be executed.
 */
#define	EXEC_DESCRIPTOR	0x1

#ifndef _KERNEL
extern int execvex(uintptr_t, char *const *, char *const *, int);
#endif

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_EXECX_H */
