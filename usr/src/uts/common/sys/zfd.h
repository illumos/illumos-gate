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
 * Copyright 2015 Joyent, Inc.
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

/*
 * This ioctl puts a hangup into the stream so that the slave side sees EOF.
 */
#define	ZFD_EOF			(ZFD_IOC | 1)

/*
 * This ioctl succeeds if the slave side is open.
 */
#define	ZFD_HAS_SLAVE		(ZFD_IOC | 2)

/*
 * This ioctl links two streams into a multiplexer configuration for in-zone
 * logging.
 */
#define	ZFD_MUX			(ZFD_IOC | 3)

/*
 * This ioctl controls the flow control setting for the log multiplexer stream
 * (1 = true, 0 = false). The default is false which implies teeing into the
 * log stream is "best-effort" but data will be discarded if the stream
 * becomes full. If set and the log stream begins to fill up, the primary
 * stream will stop flowing.
 */
#define	ZFD_MUX_FLOWCON		(ZFD_IOC | 4)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ZFD_H */
