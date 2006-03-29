/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IOSRAMIO_H
#define	_SYS_IOSRAMIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * data_valid flag values
 */
#define	IOSRAM_DATA_INVALID	0
#define	IOSRAM_DATA_VALID	1

/*
 * int_pending flag values
 */
#define	IOSRAM_INT_NONE		0
#define	IOSRAM_INT_TO_SSC	1
#define	IOSRAM_INT_TO_DOM	2

/*
 * IOSRAM control commands, for use in iosram_ctrl().
 */
#define	IOSRAM_CMD_CHUNKLEN			1

/*
 * IOSRAM header control commands, for use in iosram_hdr_ctrl _only_ by the
 * Mailbox Protocol implementation
 */
#define	IOSRAM_HDRCMD_GET_SMS_MBOX_VER		1
#define	IOSRAM_HDRCMD_SET_OS_MBOX_VER		2
#define	IOSRAM_HDRCMD_REG_CALLBACK		3

/*
 * Extern prototypes for kernel drivers/modules
 */
extern int iosram_rd(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr);
extern int iosram_wr(uint32_t key, uint32_t off, uint32_t len, caddr_t dptr);
extern int iosram_force_write(uint32_t key, uint32_t off, uint32_t len,
	caddr_t dptr);
extern int iosram_get_flag(uint32_t key, uint8_t *data_valid,
	uint8_t *int_pending);
extern int iosram_set_flag(uint32_t key, uint8_t data_valid,
	uint8_t int_pending);
extern int iosram_send_intr();
extern int iosram_register(uint32_t key, void (*handler)(), void *arg);
extern int iosram_unregister(uint32_t key);
extern int iosram_ctrl(uint32_t key, uint32_t cmd, void *arg);

/*
 * This function is only intended to be called by DR.
 */
extern int iosram_switchfrom(int instance);

/*
 * The following functions are only to be used by the Mailbox Protocol
 * implementation.
 */
extern int iosram_sema_acquire(uint32_t *);
extern int iosram_sema_release(void);
extern int iosram_hdr_ctrl(uint32_t cmd, void *arg);


#if defined(DEBUG)

/*
 * ioctls for testing purposes only
 */

#define	IOSRAM_IOC			('i' << 8)

#define	IOSRAM_RD		(int)(IOSRAM_IOC|1)
#define	IOSRAM_WR		(int)(IOSRAM_IOC|2)
#define	IOSRAM_GET_FLAG		(int)(IOSRAM_IOC|3)
#define	IOSRAM_SET_FLAG		(int)(IOSRAM_IOC|4)
#define	IOSRAM_TOC		(int)(IOSRAM_IOC|5)
#define	IOSRAM_SEND_INTR	(int)(IOSRAM_IOC|6)
#define	IOSRAM_REG_CBACK	(int)(IOSRAM_IOC|7)
#define	IOSRAM_UNREG_CBACK	(int)(IOSRAM_IOC|8)
#define	IOSRAM_PRINT_CBACK	(int)(IOSRAM_IOC|9)
#define	IOSRAM_PRINT_STATE	(int)(IOSRAM_IOC|10)
#define	IOSRAM_PRINT_LOG	(int)(IOSRAM_IOC|11)
#define	IOSRAM_PRINT_FLAGS	(int)(IOSRAM_IOC|12)
#define	IOSRAM_TUNNEL_SWITCH	(int)(IOSRAM_IOC|13)
#define	IOSRAM_PRINT_STATS	(int)(IOSRAM_IOC|14)
#define	IOSRAM_SEMA_ACQUIRE	(int)(IOSRAM_IOC|15)
#define	IOSRAM_SEMA_RELEASE	(int)(IOSRAM_IOC|16)


/*
 * struct iosram_io:
 *	Used for testing purposes to invoke IOSRAM internal
 *	interface from user level via ioctl() interface.
 */
typedef struct iosram_io {
	uint32_t cmd;		/* read or write */
	uint32_t key;		/* IOSRAM chunk key */
	uint32_t off;		/* offset within IOSRAM chunk */
	uint32_t len;		/* size of read or write */
	uint32_t bufp;		/* buffer pointer */
	uint32_t retval;	/* provided by driver */
	uint32_t data_valid;	/* flag being get/set */
	uint32_t int_pending;	/* flag being get/set */
} iosram_io_t;

#endif /* DEBUG */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_IOSRAMIO_H */
