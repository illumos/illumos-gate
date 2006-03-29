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
 * Copyright 2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _RMC_COMM_DP_BOOT_H
#define	_RMC_COMM_DP_BOOT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Boot protocol message types */

#define	BP_OBP_TEST		0xC0
#define	BP_OBP_INIT		0xC1
#define	BP_OBP_ENQUIRE		0xC2
#define	BP_OBP_BOOTINIT		0xC3
#define	BP_OBP_RESET		0xC4
#define	BP_OBP_MACADDR		0xC5
#define	BP_OBP_BOOTMODE		0xC6
#define	BP_OBP_HOST_MACADDR	0xC7
#define	BP_OBP_SOFT_GPIO 	0xC8

#define	BP_RSC_TESTACK		0xD0
#define	BP_RSC_DIAG		0xD1
#define	BP_RSC_OK		0xD2
#define	BP_RSC_STATUS		0xD3
#define	BP_RSC_MACADDRACK	0xD5
#define	BP_RSC_BOOTMODEACK	0xD6
#define	BP_RSC_BOOTREQ		0xD8
#define	BP_RSC_BOOTACK		0xD9
#define	BP_RSC_BOOTFAIL		0xDA
#define	BP_RSC_BOOTOK		0xDB
#define	BP_RSC_SOFTGPIOACK	0xDD

#define	BP_MIN_CMD		0xC0
#define	BP_MAX_CMD		0xDF

/*
 * A boot protocol message consists of one (or more) synchronizing
 * bytes, a command byte, and two data bytes.  The following structure
 * defines how a boot message is passed around.  Hopefully the C
 * compiler will be smart enough to pass this in a register...
 */

#define	BP_SYNC		0x80

typedef struct bp_msg {
	uint8_t pad;	/* make it 4 bytes long */
	uint8_t cmd;
	uint8_t dat1;
	uint8_t dat2;
} bp_msg_t;

/* Test numbers used in the OBP_TEST message: */
#define	BP_DAT1_MIN_TEST	0
#define	BP_DAT1_TTYC_ECHO_ON	0
#define	BP_DAT1_TTYC_ECHO_OFF	1
#define	BP_DAT1_TTYD_ECHO_ON	2
#define	BP_DAT1_TTYD_ECHO_OFF	3
#define	BP_DAT1_TTYCD_ECHO_ON	4
#define	BP_DAT1_TTYCD_ECHO_OFF	5
#define	BP_DAT1_ENET_INT_LB	6
#define	BP_DAT1_ENET_EXT_LB	7
#define	BP_DAT1_TTYU_INT_LB	8
#define	BP_DAT1_TTYU_EXT_LB	9
#define	BP_DAT1_SEEPROM_CKSUM	10
#define	BP_DAT1_DUMMY_TEST	11
#define	BP_DAT1_FRU_CKSUM	12
#define	BP_DAT1_FLASH_CKSUM	13
#define	BP_DAT1_TOD_TEST	14
#define	BP_DAT1_MODEM_TEST	15
#define	BP_DAT1_MAX_TEST	15

/*
 * This bit should be set in the RSC_STATUS message to indicate to the
 * host that there is an interesting bootmode.
 */
#define	BP_DAT1_VALID_BOOTMODE	0x40

/*
 * Bit definitions for the OBP_INIT and RSC_OK messages.
 */

#define	BP_DAT1_MENUS	0x80
#define	BP_DAT1_MAX	0x40
#define	BP_DAT1_MED	0x20
#define	BP_DAT1_MIN	0x10
#define	BP_DAT1_MBO	0x01

#define	BP_DAT2_DIAGSW	0x01

/* Bit definitions for OBP_BOOTINIT message. */

#define	BP_DAT2_FLASH_PDAT	0x04
#define	BP_DAT2_FLASH_MAIN	0x02
#define	BP_DAT2_FLASH_BOOT	0x01

/*
 * For bit definitions for the RSC_STATUS message, see the post word bit
 * definitions in "postword.h".
 */

/* Bit definitions for RSC_BOOTFAIL message. */

#define	BP_DAT1_REJECTED	0x40
#define	BP_DAT1_RANGE_ERR	0x20
#define	BP_DAT1_VERIFY_ERR	0x10
#define	BP_DAT1_ERASE_ERR	0x08
#define	BP_DAT1_INT_WP_ERR	0x04
#define	BP_DAT1_WP_ERR		0x02
#define	BP_DAT1_VPP_ERR		0x01

/* For lower 8 bits, see the lower 8 bits of the post word in "postword.h". */

#define	KANTH_SRECORD_ACK

/*
 * When downloading S-records, a RSC:bootack is sent with the following
 * value in dat1 to indicate whether the S-record checksum was OK or not.
 */

#define	BP_DAT1_BOOTINIT_ACK	0x00
#define	BP_DAT1_SRECORD_ACK	0x01
#define	BP_DAT1_SRECORD_NAK	0x02

/* Definitions for OBP_BOOTMODE message: */
#define	BP_DAT2_BOOTMODE_CLEAR		1

/* Definitions for RSC_BOOTMODE message: */
#define	BP_BAT1_BOOTMODE_DATAMSB	0x10
#define	BP_DAT1_BOOTMODE_OFFSET_MASK	0x07

#define	BP_DAT2_BOOTMODE_DATA_MASK	0x7F

/* Definitions for RSC_BOOTMODEACK message: */
#define	BP_DAT1_BOOTMODE_NORMAL		0
#define	BP_DAT1_BOOTMODE_FORTH		1
#define	BP_DAT1_BOOTMODE_RESET_NVRAM	2
#define	BP_DAT1_BOOTMODE_DIAG		3
#define	BP_DAT1_BOOTMODE_SKIP_DIAG	4

#define	BP_DAT2_BOOTOPT_CONSOLE_RSC	1

/* Definitions for RSC_MACADDRACK message: */
#define	BP_DAT2_MACADDRACK_OK		0
#define	BP_DAT2_MACADDRACK_DONE		1
#define	BP_DAT2_MACADDRACK_BADOFFSET	2
#define	BP_DAT2_MACADDRACK_NOTREADY	3
#define	BP_DAT2_MACADDRACK_NVERR	4

/* Definitions for RSC_SOFTGPIOACK message */
#define	BP_DAT2_HOST_TYPE_OK		0
#define	BP_DAT2_HOST_TYPE_NVERR		1

#ifdef __cplusplus
}
#endif

#endif /* _RMC_COMM_DP_BOOT_H */
