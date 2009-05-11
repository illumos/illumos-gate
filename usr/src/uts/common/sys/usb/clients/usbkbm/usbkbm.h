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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_USB_USBKBM_H
#define	_SYS_USB_USBKBM_H


#ifdef __cplusplus
extern "C" {
#endif

#include <sys/time.h>
#include <sys/vuid_event.h>
#include <sys/stream.h>
#include <sys/kbd.h>


/*
 * USB keyboard LED masks (used to set LED's on USB keyboards)
 */
#define	USB_LED_NUM_LOCK	0x1
#define	USB_LED_CAPS_LOCK	0x2
#define	USB_LED_SCROLL_LOCK	0x4
#define	USB_LED_COMPOSE		0x8
#define	USB_LED_KANA		0x10	/* Valid only on Japanese layout */

/* Modifier key masks */
#define	USB_LCTLBIT   0x01
#define	USB_LSHIFTBIT 0x02
#define	USB_LALTBIT   0x04
#define	USB_LMETABIT  0x08
#define	USB_RCTLBIT   0x10
#define	USB_RSHIFTBIT 0x20
#define	USB_RALTBIT   0x40
#define	USB_RMETABIT  0x80

#define	USB_LSHIFTKEY	225
#define	USB_LCTLCKEY	224
#define	USB_LALTKEY	226
#define	USB_LMETAKEY	227
#define	USB_RCTLCKEY	228
#define	USB_RSHIFTKEY	229
#define	USB_RMETAKEY	231
#define	USB_RALTKEY	230

/*
 * The keyboard would report ErrorRollOver in all array fields when
 * the number of non-modifier keys pressed exceeds the Report Count.
 */
#define	USB_ERRORROLLOVER 1


/*
 * This defines the format of translation tables.
 *
 * A translation table is USB_KEYMAP_SIZE "entries", each of which is 2
 * bytes (unsigned shorts).  The top 8 bits of each entry are decoded by
 * a case statement in getkey.c.  If the entry is less than 0x100, it
 * is sent out as an EUC character (possibly with bucky bits
 * OR-ed in).  "Special" entries are 0x100 or greater, and
 * invoke more complicated actions.
 */

/*
 * HID-spec-defined report size (in bytes) for each USB HID boot-protocol
 * mode report.
 */

#define	USB_KBD_BOOT_PROTOCOL_PACKET_SIZE	8

/* definitions for various state machines */
#define	USBKBM_OPEN	0x00000001 /* keyboard is open for business */
#define	USBKBM_QWAIT	0x00000002 /* keyboard is waiting for a response */

/*
 * Polled key state
 */
typedef struct poll_keystate {
	int		poll_key;		/* scancode */
	enum keystate   poll_state;		/* pressed or released */
} poll_keystate_t;

#define	USB_POLLED_BUFFER_SIZE	20	/* # of characters in poll buffer */

#define	USBKBM_MAXPKTSIZE	10	/* Maximum size of a packet */

typedef struct usbkbm_report_format {
	uint8_t	keyid;	/* report id of keyboard input */
	uint_t	kpos;	/* keycode offset in the keyboard data */
	uint_t	klen;	/* length of keycodes */
	uint_t	tlen;	/* length of the input report (inc. report id) */
} usbkbm_report_format_t;

/* state structure for usbkbm */
typedef struct  usbkbm_state {
	struct kbtrans		*usbkbm_kbtrans;
	queue_t			*usbkbm_readq;		/* read queue */
	queue_t			*usbkbm_writeq;		/* write queue */
	int			usbkbm_flags;

	/* Report format of keyboard data */
	usbkbm_report_format_t	usbkbm_report_format;

	/* Pointer to the parser handle */
	hidparser_handle_t	usbkbm_report_descr;
	uint16_t		usbkbm_layout;		/* keyboard layout */
	/*
	 * Setting this indicates that the second IOCTL
	 * after KBD_CMD_SETLED follows
	 */
	int			usbkbm_setled_second_byte;
	/* Keyboard packets sent last */
	uchar_t			usbkbm_lastusbpacket[USBKBM_MAXPKTSIZE];

	/* Currently processed key events of the current keyboard packet */
	uchar_t			usbkbm_pendingusbpacket[USBKBM_MAXPKTSIZE];

	hid_polled_input_callback_t
				usbkbm_hid_callback;	/* poll information */

	mblk_t			*usbkbm_pending_link; /* mp waiting response */

	/* "ioctl" awaiting buffer */
	mblk_t			*usbkbm_streams_iocpending;

	/* id from qbufcall on allocb failure */
	bufcall_id_t		usbkbm_streams_bufcallid;

	/* Polled input information */
	struct cons_polledio	usbkbm_polled_info;

	int			usbkbm_vkbd_type;

	/* keyboard device info from hid */
	hid_vid_pid_t		usbkbm_vid_pid;

	/* These entries are for polled input */
	uint_t		usbkbm_polled_buffer_num_characters;
	poll_keystate_t	usbkbm_polled_scancode_buffer[USB_POLLED_BUFFER_SIZE];
	poll_keystate_t	*usbkbm_polled_buffer_head;
	poll_keystate_t	*usbkbm_polled_buffer_tail;

	/* Boot protocol or report protocol */
	uint8_t	protocol;
} usbkbm_state_t;

#define	USB_PRESSED	0x00	/* key was pressed */
#define	USB_RELEASED	0x01	/* key was released */

/* Sun Japanese type6 and type7 keyboards layout numbers, vid and pid */
#define	SUN_JAPANESE_TYPE6		271
#define	SUN_JAPANESE_TYPE7		15
#define	HID_SUN_JAPANESE_TYPE6_KBD_VID	0x0430
#define	HID_SUN_JAPANESE_TYPE6_KBD_PID	0x0005


/* Number of entries in the keytable */
#define	KEYMAP_SIZE_USB		255

/* Size in bytes of the keytable */
#define	USB_KEYTABLE_SIZE	(KEYMAP_SIZE_USB * sizeof (keymap_entry_t))

/* structure to save global state */
typedef struct usbkbm_save_state {
	/* LED state */
	uchar_t		usbkbm_save_led;
	uchar_t		usbkbm_layout;

	/* Keymap information */
	struct keyboard usbkbm_save_keyindex;

} usbkbm_save_state_t;

/*
 * Masks for debug printing
 */
#define	PRINT_MASK_ATTA		0x00000001
#define	PRINT_MASK_OPEN 	0x00000002
#define	PRINT_MASK_CLOSE	0x00000004
#define	PRINT_MASK_PACKET	0x00000008
#define	PRINT_MASK_ALL		0xFFFFFFFF

#define	INDEXTO_PC	1	/* To PC table */
#define	INDEXTO_USB	0	/* To USB table */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_USBKBM_H */
