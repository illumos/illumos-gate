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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef _VM_REBOOT_H
#define	_VM_REBOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Arguments to reboot system call and flags to init.
 *
 * On the VAX, these are passed to boot program in r11,
 * and on to init.
 *
 * On the Sun, these are parsed from the boot command line
 * and used to construct the argument list for init.
 */

#define	RB_AUTOBOOT	0	/* flags for system auto-booting itself */

#define	RB_ASKNAME	0x001	/* ask for file name to reboot from */
#define	RB_SINGLE	0x002	/* reboot to single user only */
#define	RB_NOSYNC	0x004	/* dont sync before reboot */
#define	RB_HALT		0x008	/* don't reboot, just halt */
#define	RB_INITNAME	0x010	/* name given for /etc/init */
#define	RB_NOBOOTRC	0x020	/* don't run /etc/rc.boot */
#define	RB_DEBUG	0x040	/* being run under debugger */
#define	RB_DUMP		0x080	/* dump system core */
#define	RB_WRITABLE	0x100	/* mount root read/write */
#define	RB_STRING	0x200	/* pass boot args to prom monitor */

#endif	/* _VM_REBOOT_H */
