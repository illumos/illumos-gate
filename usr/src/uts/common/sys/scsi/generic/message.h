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
 * Copyright (c) 1996,2000 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_SCSI_GENERIC_MESSAGE_H
#define	_SYS_SCSI_GENERIC_MESSAGE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Defined Messages For Parallel SCSI.
 */

/*
 * The SCSI specification defines message codes 0x00, 0x02-0x1F,
 * as fixed single byte messages, 0x01 as indicating extended (multi-byte)
 * messages, 0x20-0x2F as fixed two byte messages, and 0x80-0xFF
 * as IDENTIFY messages.
 */

#define	MSG_COMMAND_COMPLETE	0x00
#define	MSG_SAVE_DATA_PTR	0x02
#define	MSG_RESTORE_PTRS	0x03
#define	MSG_DISCONNECT		0x04
#define	MSG_INITIATOR_ERROR	0x05
#define	MSG_ABORT		0x06
#define	MSG_REJECT		0x07
#define	MSG_NOP			0x08
#define	MSG_MSG_PARITY		0x09
#define	MSG_LINK_CMPLT		0x0A
#define	MSG_LINK_CMPLT_FLAG	0x0B
#define	MSG_DEVICE_RESET	0x0C
#define	MSG_ABORT_TAG		0x0D
#define	MSG_CLEAR_QUEUE		0x0E
#define	MSG_INITIATE_RECOVERY	0x0F
#define	MSG_RELEASE_RECOVERY	0x10
#define	MSG_TERMINATE_PROCESS	0x11
#define	MSG_CONTINUE_TASK	0x12
#define	MSG_TARGET_TRAN_DIS	0x13
#define	MSG_CLEAR_ACA		0x16


/*
 * Message code 0x01 indicates an extended
 * (two or more) byte message. The EXTENDED
 * message byte is followed immediately by
 * a message length byte and then an extended
 * message code byte.
 *
 * Note: The EXTENDED IDENTIFY message is pre-SCSI-2.
 */

#define	MSG_EXTENDED		0x01

#define	MSG_MODIFY_DATA_PTR	0x00
#define	MSG_SYNCHRONOUS		0x01
#define	MSG_IDENTIFY_EXTENDED	0x02
#define	MSG_WIDE_DATA_XFER	0x03
#define	MSG_PARALLEL_PROTOCOL	0x04

/*
 * parallel protocol message optional flags
 */
#define	OPT_IU			0x01
#define	OPT_DT			0x02
#define	OPT_QAS_REQ		0x04

/*
 * Message codes 0x20-0x2F are fixed two byte messages.
 */


#define	MSG_SIMPLE_QTAG		0x20
#define	MSG_HEAD_QTAG		0x21
#define	MSG_ORDERED_QTAG	0x22
#define	MSG_IGNORE_WIDE_RESID	0x23
#define	MSG_ACA			0x24
#define	MSG_LUN_RESET		0x25

/*
 * Codes 0x80-0xFF are identify messages, indicated
 * by the setting of the most significant bit in the
 * message (0x80).
 */

#define	MSG_IDENTIFY		0x80

/*
 * Initiators will set bit 6 in an Identify message
 * to indicate whether or not they can accommodate
 * disconnect/reconnect
 */

#define	INI_CAN_DISCON		0x40

/*
 * ..so we can have a compound definition
 * for Initiators that can accommodate
 * disconnect/reconnect
 */

#define	MSG_DR_IDENTIFY		(MSG_IDENTIFY|INI_CAN_DISCON)

/*
 * Note: Following is ONLY applicable to pre-SCSI-3.
 *
 * Bit 5 of the identify message specifies that, if zero,
 * that the IDENTIFY message is directed to a logical unit,
 * and if one, that the IDENTIFY message is directed to a
 * target routine that does not involve a logical unit.
 */

#define	MSG_LUNTAR		0x20

/*
 * Note: Following is ONLY applicable to pre-SCSI-3.
 *
 * Bits 2-0 identify either the logical unit or the target
 * routine number based upon whether MSG_LUNTAR is clear
 * or set.
 */

#define	MSG_LUNRTN		0x07

/*
 * Note: Following is ONLY applicable to pre-SCSI-3.
 *
 * Bits 4-3 are reserved and must be zero.
 */

#define	BAD_IDENTIFY		0x18

/*
 * These macros may be useful to quickly determine the
 * length of a message based upon the message code.
 */

/*
 * Note: IS_IDENTIFY_MSG is ONLY applicable to pre-SCSI-3.
 *	 For SCSI-3, use IS_IDENTIFY_MSG_SCSI3.
 */
#define	IS_IDENTIFY_MSG(msg)	\
	(((msg) & MSG_IDENTIFY) && !((msg) & BAD_IDENTIFY))
#define	IS_IDENTIFY_MSG_SCSI3(msg)	((msg) & MSG_IDENTIFY)
#define	IS_EXTENDED_MSG(msg)	((msg) == MSG_EXTENDED)
#define	IS_2BYTE_MSG(msg)	(((msg) & 0xF0) == 0x20)
#define	IS_1BYTE_MSG(msg)	(!(IS_EXTENDED_MSG((msg))) && \
	((((msg) & 0xF0) == 0) || IS_IDENTIFY_MSG((msg))))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCSI_GENERIC_MESSAGE_H */
