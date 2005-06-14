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
 * Copyright (c) 1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _I2O_IMPL_H
#define	_I2O_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/dditypes.h>
#include <sys/i2o/i2omsg.h>
#include <sys/i2o/i2outil.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef DEBUG
#define	I2O_DEBUG
#endif

/*
 * *****************************************************************
 * Definitions used in the  implementation of I2O  nexus driver  and
 * I2O Message module. These are implementation specific definitions.
 * *****************************************************************
 */

/*
 * i2o_msg_trans structure:
 *
 *	version		I2O_MSG_TRANS_VER0 (version of this structure).
 *
 *	iop_base_addr	Base (virtual) address of device memory where
 *			inbound message frames are allocated. The MFA
 *			read from the inbound FIFO is an offset from
 *			this base address.
 *
 *	iop_inbound_fifo_paddr
 *			Inbound Fifo port address (physical).
 *
 *	acc_handle	DDI access handle to access any message frame
 *			from the inbound queue.
 *
 *	nexus_handle	I2O Nexus handle argument to nexus transport
 *			functions.
 *
 *	iblock_cookie	Cookie needed for mutex_init().
 *
 *	i2o_trans_msg_alloc
 *			Allocates a message frame from the inbound
 *			queue. It reads the inbound FIFO register
 *			and returns the MFA.
 *
 *	i2o_trans_msg_send
 *			Write the MFA to the inbound queue of the IOP.
 *
 *	i2o_trans_msg_recv
 *			Reads the outbound queue for the reply
 *			messages and returns the MFA. The MFA is
 *			-1 if there are no reply messages.
 *
 * 	i2o_trans_msg_freebuf
 *			Writes the MFA into the outbound queue.
 *
 *	i2o_trans_disable_intr
 *			Disables the IOP hardware interrupts.
 *
 *	i2o_trans_enable_intr
 *			Enables the IOP hardware interrupts.
 */

#define	I2O_MSG_TRANS_VER0	0
#define	I2O_MSG_TRANS_VER	I2O_MSG_TRANS_VER0

typedef void *i2o_nexus_handle_t;

typedef struct i2o_msg_trans {
    int			version;
    caddr_t		iop_base_addr;
    uint32_t		iop_inbound_fifo_paddr;
    ddi_acc_handle_t 	acc_handle;
    i2o_nexus_handle_t	nexus_handle;
    ddi_iblock_cookie_t	iblock_cookie;
    uint_t		(* i2o_trans_msg_alloc)(i2o_nexus_handle_t
				nexus_handle);
    int			(* i2o_trans_msg_send)(i2o_nexus_handle_t nexus_handle,
				uint_t mfa);
    uint_t		(* i2o_trans_msg_recv)(i2o_nexus_handle_t nexus_handle);
    void		(* i2o_trans_msg_freebuf)(i2o_nexus_handle_t
				nexus_handle, uint_t mfa);
    void		(* i2o_trans_disable_intr)(i2o_nexus_handle_t
				nexus_handle);
    void		(* i2o_trans_enable_intr)(i2o_nexus_handle_t
				nexus_handle);
} i2o_msg_trans_t;


i2o_iop_handle_t i2o_msg_iop_init(dev_info_t *rdip, i2o_msg_trans_t *trans);
void i2o_msg_process_reply_queue(i2o_iop_handle_t iop);
int i2o_msg_iop_uninit(i2o_iop_handle_t *iop);
void i2o_msg_get_lct_info(i2o_iop_handle_t *, i2o_lct_t **, ddi_acc_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _I2O_IMPL_H */
