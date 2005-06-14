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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_1394_CMD1394_H
#define	_SYS_1394_CMD1394_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * cmd1394.h
 *    Contains the enums, command structures, and error codes used with
 *    the 1394 Framework's t1394_read(), t1394_write(), and t1394_lock()
 *    interfaces.
 *    For outgoing (Asynchronous Transmit - AT) commands, target drivers
 *    allocate a command using t1394_alloc_cmd(), fill it in with the
 *    transmit info, and send it using one of t1394_read(), t1394_write(),
 *    of t1394_lock().
 *    The target driver can choose whether to get a callback when the
 *    command completes, block until it completes, or poll on the return
 *    status in the command.
 *    For incoming (Asynchronous Receive - AR) requests, the same command
 *    structure is used and most of the information has the same or a
 *    similar meaning to what it does on the AT side.  The major differences
 *    are that nodeID indicates the node from which the command was sent
 *    and broadcast informs a target driver whether the incoming request
 *    was broadcast to everyone.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/note.h>

#include <sys/1394/s1394_impl.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * cmd1394_cmd.cmd_type
 *    Used to select/indicate the request packet type
 */
typedef enum {
	CMD1394_ASYNCH_RD_QUAD	= 0,
	CMD1394_ASYNCH_WR_QUAD	= 1,
	CMD1394_ASYNCH_RD_BLOCK	= 2,
	CMD1394_ASYNCH_WR_BLOCK	= 3,
	CMD1394_ASYNCH_LOCK_32	= 4,
	CMD1394_ASYNCH_LOCK_64	= 5
} cmd1394_cmd_type_t;

/*
 * cmd1394_cmd.flags
 *    Used to select the request's behavior, including
 *    how the destination address is determined, how
 *    a large request will be broken into smaller requests,
 *    whether the command should be resent after a
 *    bus reset has happened, etc.
 */
typedef enum {
	CMD1394_CANCEL_ON_BUS_RESET	= (1 << 0),
	CMD1394_OVERRIDE_ADDR		= (1 << 1),
	CMD1394_OVERRIDE_MAX_PAYLOAD	= (1 << 2),
	CMD1394_DISABLE_ADDR_INCREMENT	= (1 << 3),
	CMD1394_BLOCKING		= (1 << 4),
	CMD1394_OVERRIDE_SPEED		= (1 << 5)
} cmd1394_flags_t;

/*
 * cmd1394_cmd.arg.l.lock_type
 *    Used to select/indicate the type of lock operation
 *    in the request.  Some are supported by the 1394 spec
 *    others (0x10000+) are supported locally in software.
 */
typedef enum {
	/* Reserved			= 0x0000		*/
	CMD1394_LOCK_MASK_SWAP		= 0x0001,
	CMD1394_LOCK_COMPARE_SWAP	= 0x0002,
	CMD1394_LOCK_FETCH_ADD		= 0x0003,
	CMD1394_LOCK_LITTLE_ADD		= 0x0004,
	CMD1394_LOCK_BOUNDED_ADD	= 0x0005,
	CMD1394_LOCK_WRAP_ADD		= 0x0006,
	/* Vendor-Defined		= 0x0007		*/
	/* Reserved			= 0x0008 - 0xFFFF	*/

	CMD1394_LOCK_BIT_AND		= 0x10000,
	CMD1394_LOCK_BIT_OR		= 0x10001,
	CMD1394_LOCK_BIT_XOR		= 0x10002,
	CMD1394_LOCK_INCREMENT		= 0x10003,
	CMD1394_LOCK_DECREMENT		= 0x10004,
	CMD1394_LOCK_ADD		= 0x10005,
	CMD1394_LOCK_SUBTRACT		= 0x10006,
	CMD1394_LOCK_THRESH_ADD		= 0x10007,
	CMD1394_LOCK_THRESH_SUBTRACT	= 0x10008,
	CMD1394_LOCK_CLIP_ADD		= 0x10009,
	CMD1394_LOCK_CLIP_SUBTRACT	= 0x1000A
} cmd1394_lock_type_t;

/* Asynchronous Command (Data Quadlet) */
typedef struct cmd1394_quadlet {
	uint32_t		quadlet_data;
} cmd1394_quadlet_t;

/* Asynchronous Command (Data Block) */
typedef struct cmd1394_block {
	mblk_t			*data_block;
	size_t			blk_length;
	size_t			bytes_transferred;
	uint_t			max_payload;
} cmd1394_block_t;

/* Asynchronous Command (Lock Cmd - 32 bit) */
typedef struct cmd1394_lock32 {
	uint32_t		old_value;
	uint32_t		data_value;
	uint32_t		arg_value;
	uint_t			num_retries;
	cmd1394_lock_type_t	lock_type;
} cmd1394_lock32_t;

/* Asynchronous Command (Lock Cmd - 64 bit) */
typedef struct cmd1394_lock64 {
	uint64_t		old_value;
	uint64_t		data_value;
	uint64_t		arg_value;
	uint_t			num_retries;
	cmd1394_lock_type_t	lock_type;
} cmd1394_lock64_t;

/* cmd1394_cmd: cmd1394 - common command type */
typedef struct cmd1394_cmd
{
	int			cmd_version;
	volatile int		cmd_result;
	cmd1394_flags_t		cmd_options;
	cmd1394_cmd_type_t	cmd_type;
	void			(*completion_callback)(struct cmd1394_cmd *);
	opaque_t		cmd_callback_arg;
	uint64_t		cmd_addr;
	uint_t			cmd_speed;
	uint_t			bus_generation;
	uint_t			nodeID;
	uint_t			broadcast;
	union {
		cmd1394_quadlet_t	q;
		cmd1394_block_t		b;
		cmd1394_lock32_t	l32;
		cmd1394_lock64_t	l64;
	} cmd_u;
} cmd1394_cmd_t;

/*
 * NOTE: Make sure CMD1394_ERR_LAST is updated if a new error code is
 * added. t1394_errmsg.c uses *FIRST and *LAST as bounds checks.
 */
/* cmd1394_cmd.result - Immediate failures (with DDI_FAILURE) */
#define	CMD1394_ENULL_MBLK		(-10)
#define	CMD1394_EMBLK_TOO_SMALL		(-11)
#define	CMD1394_ESTALE_GENERATION	(-12)
#define	CMD1394_EDEVICE_REMOVED		(-13)
#define	CMD1394_EINVALID_CONTEXT	(-14)
#define	CMD1394_EINVALID_COMMAND	(-15)
#define	CMD1394_EUNKNOWN_ERROR		(-16)
#define	CMD1394_NOSTATUS		(-17)
#define	CMD1394_EFATAL_ERROR		(-18)
#define	CMD1394_ENO_ATREQ		(-19)
#define	CMD1394_EDEVICE_ERROR		(-20)  /* bad tcode or ack or... */

/* cmd1394_cmd.result - Returned with completion_callback */
#define	CMD1394_CMDSUCCESS 		(0)
#define	CMD1394_EDEVICE_BUSY		(-30)
#define	CMD1394_ERETRIES_EXCEEDED	(-31)
#define	CMD1394_ETYPE_ERROR		(-32)
#define	CMD1394_EDATA_ERROR		(-33)
#define	CMD1394_EBUSRESET		(-34)
#define	CMD1394_EADDRESS_ERROR		(-35)
#define	CMD1394_ETIMEOUT		(-36)
#define	CMD1394_ERSRC_CONFLICT		(-37)

#define	CMD1394_ERR_FIRST		CMD1394_CMDSUCCESS
#define	CMD1394_ERR_LAST		CMD1394_ERSRC_CONFLICT

/* Warlock directives for cmd1394 */

_NOTE(SCHEME_PROTECTS_DATA("One per call", cmd1394_cmd_t))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_1394_CMD1394_H */
