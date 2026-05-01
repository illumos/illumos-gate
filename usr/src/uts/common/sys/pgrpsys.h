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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _SYS_PGRPSYS_H
#define	_SYS_PGRPSYS_H

/*
 * Subcodes for the pgrpsys() system call, which multiplexes the process
 * group and session family of functions. This is a private header that is
 * not packaged.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#define	PGRPSYS_GETPGRP		0
#define	PGRPSYS_SETPGRP		1
#define	PGRPSYS_GETSID		2
#define	PGRPSYS_SETSID		3
#define	PGRPSYS_GETPGID		4
#define	PGRPSYS_SETPGID		5

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PGRPSYS_H */
