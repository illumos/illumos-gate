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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_REBOOT_H
#define	_SYS_REBOOT_H

#ifndef _ASM
#include <sys/types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Boot flags and flags to "reboot" system call.
 *
 * Not all of these necessarily apply to all machines.
 */
#define	RB_AUTOBOOT	0	/* flags for system auto-booting itself */

#define	RB_ASKNAME		0x00000001 /* prompt for boot file name */
#define	RB_SINGLE		0x00000002 /* reboot to single user only */
#define	RB_NOSYNC		0x00000004 /* dont sync before reboot */
#define	RB_HALT			0x00000008 /* don't reboot, just halt */
#define	RB_INITNAME		0x00000010 /* name given for /etc/init */
#define	RB_NOBOOTRC		0x00000020 /* don't run /etc/rc.boot */
#define	RB_DEBUG		0x00000040 /* being run under debugger */
#define	RB_DUMP			0x00000080 /* dump system core */
#define	RB_WRITABLE		0x00000100 /* mount root read/write */
#define	RB_STRING		0x00000200 /* pass boot args to prom monitor */
#define	RB_CONFIG		0x00000800 /* pass to init on a boot -c */
#define	RB_RECONFIG		0x00001000 /* pass to init on a boot -r */
#define	RB_VERBOSE		0x00002000 /* set for chatty boot */
#define	RB_FORTHDEBUG		0x00004000 /* load forthdebug module */
#define	RB_FORTHDEBUGDBP 	0x00008000 /* load forthdebug, enable def bpt */
#define	RB_KMDB			0x00020000 /* load kmdb during boot */
#define	RB_NOBOOTCLUSTER 	0x00040000 /* don't boot as a cluster */
#define	RB_DEBUGENTER		0x00080000 /* enter the debugger at boot */

#ifndef _ASM

extern int reboot(int, char *);

#if defined(_KERNEL)

extern int boothowto;

#if defined(_BOOT)
extern void bootflags(char *, size_t);
#else
struct bootops;
extern void bootflags(struct bootops *);
#endif	/* _BOOT */

#endif	/* _KERNEL */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_REBOOT_H */
