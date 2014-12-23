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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_ZFD_H
#define	_SYS_ZFD_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Minor node name of the global zone side (often called the "master" side)
 * of the zfd dev.
 */
#define	ZFD_MASTER_NAME	"master"

/*
 * Minor node name of the non-global zone side (often called the "slave"
 * side) of the zfd dev.
 */
#define	ZFD_SLAVE_NAME	"slave"

#define	ZFD_NAME_LEN	16

/*
 * ZFD_IOC forms the base for all zfd ioctls.
 */
#define	ZFD_IOC		(('Z' << 24) | ('f' << 16) | ('d' << 8))

/*
 * This ioctl tells the slave side it should push the TTY stream modules
 * so that the fd looks like a tty.
 */
#define	ZFD_MAKETTY		(ZFD_IOC | 0)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFD_H */
