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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_KB8042_H
#define	_KB8042_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Messages from keyboard.
 */
#define	KB_ERROR	0x00	/* Keyboard overrun or detection error */
#define	KB_POST_OK	0xAA	/* Sent at completion of poweron */
#define	KB_ECHO		0xEE	/* Response to Echo command (EE)  */
#define	KB_ACK		0xFA	/* Acknowledgement byte from keyboard */
#define	KB_POST_FAIL	0xFC	/* Power On Self Test failed */
#define	KB_RESEND	0xFE	/* response from keyboard to resend data */
#define	KB_REPLY_MAXLEN	8	/* Maximum # of bytes the keyboard can reply */
/*
 * Commands to keyboard.
 */
#define	KB_SET_LED	0xED	/* Tell kbd that following byte is led status */
#define	KB_READID	0xF2	/* command to read keyboard id */
#define	KB_ENABLE	0xF4	/* command to to enable keyboard */
#define	KB_RESET	0xFF	/* command to reset keyboard */
#define	KB_SET_TYPE	0xF3	/* command--next byte is typematic values */
#define	KB_SET_SCAN	0xF0	/* kbd command to set scan code set */

/*
 * LED bits
 */
#define	LED_SCR		0x01	/* Flag bit for scroll lock */
#define	LED_CAP		0x04	/* Flag bit for cap lock */
#define	LED_NUM		0x02	/* Flag bit for num lock */

/*
 * Keyboard scan code prefixes
 */
#define	KAT_BREAK	0xf0	/* first byte in two byte break sequence */
#define	KXT_EXTEND	0xe0	/* first byte in two byte extended sequence */
#define	KXT_EXTEND2	0xe1	/* Used in "Pause" sequence */

/*
 * Korean keyboard keys.  We handle these specially to avoid having to
 * dramatically extend the table.
 */
#define	KXT_HANGUL_HANJA	0xf1
#define	KXT_HANGUL		0xf2

#ifdef _KERNEL

struct kb8042 {
	kmutex_t	w_hw_mutex;	/* hardware mutex */
	int	w_init;		/* workstation has been initialized */
	queue_t	*w_qp;		/* pointer to queue for this minor device */
	int	w_kblayout;	/* keyboard layout code */
	dev_t	w_dev;		/* major/minor for this device */
	ddi_iblock_cookie_t	w_iblock;
	ddi_acc_handle_t	handle;
	uint8_t			*addr;
	int	kb_old_key_pos;	/* scancode for autorepeat filtering */
	struct {
		int desired;
		int commanded;
	}	leds;
	int	parse_scan_state;
	struct kbtrans	*hw_kbtrans;
	struct cons_polledio	polledio;
	struct {
		unsigned char mod1;
		unsigned char mod2;
		unsigned char trigger;
		boolean_t mod1_down;
		boolean_t mod2_down;
		boolean_t enabled;
	}		debugger;
	boolean_t	polled_synthetic_release_pending;
	int		polled_synthetic_release_key;
	int		simulated_kbd_type;
	uint32_t	init_state;
	int		break_received;
	boolean_t	suspended;
	int		ops;
	kcondvar_t	suspend_cv;
	kcondvar_t	ops_cv;
};

extern boolean_t KeyboardConvertScan(struct kb8042 *, unsigned char scan,
			int *keynum, enum keystate *, boolean_t *);
extern int KeyboardConvertScan_init(struct kb8042 *, int scanset);

#if defined(__i386) || defined(__amd64)
/*
 * We pick up the initial state of the keyboard from the BIOS state.
 */
#define	BIOS_KB_FLAG		0x417	/* address of BIOS keyboard state */
#define	BIOS_SCROLL_STATE	0x10
#define	BIOS_NUM_STATE		0x20
#define	BIOS_CAPS_STATE		0x40
#endif

/*
 * Initialization states
 */
#define	KB8042_UNINITIALIZED		0x00000000
#define	KB8042_MINOR_NODE_CREATED	0x00000001
#define	KB8042_REGS_MAPPED		0x00000002
#define	KB8042_HW_MUTEX_INITTED		0x00000004
#define	KB8042_INTR_ADDED		0x00000008

/*
 * Key values that map into the USB translation table in kb8042.c
 */
#define	K8042_STOP	160

#endif

#ifdef	__cplusplus
}
#endif

#endif /* _KB8042_H */
