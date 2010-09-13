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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Miniature keyboard driver for bootstrap.  This allows keyboard
 * support to continue after we take over interrupts and disable
 * BIOS keyboard support.
 */

#include <sys/types.h>
#include <sys/archsystm.h>
#include <sys/boot_console.h>
#include "boot_keyboard_table.h"

#if defined(_BOOT)
#include "dboot/dboot_asm.h"
#include "dboot/dboot_xboot.h"
#endif /* _BOOT */

/*
 * Definitions for BIOS keyboard state.  We use BIOS's variable to store
 * state, ensuring that we stay in sync with it.
 */
#define	BIOS_KB_FLAG		0x417
#define	BIOS_RIGHT_SHIFT	0x01
#define	BIOS_LEFT_SHIFT		0x02
#define	BIOS_EITHER_SHIFT	(BIOS_LEFT_SHIFT | BIOS_RIGHT_SHIFT)
#define	BIOS_CTL_SHIFT		0x04
#define	BIOS_ALT_SHIFT		0x08
#define	BIOS_SCROLL_STATE	0x10
#define	BIOS_NUM_STATE		0x20
#define	BIOS_CAPS_STATE		0x40
#define	BIOS_INS_STATE		0x80

#define	BIOS_KB_FLAG_1		0x418
#define	BIOS_SYS_SHIFT		0x04
#define	BIOS_HOLD_STATE		0x08
#define	BIOS_SCROLL_SHIFT	0x10
#define	BIOS_NUM_SHIFT		0x20
#define	BIOS_CAPS_SHIFT		0x40
#define	BIOS_INS_SHIFT		0x80

#if defined(__xpv) && defined(_BOOT)

/*
 * Device memory addresses
 *
 * In dboot under the hypervisor we don't have any memory mappings
 * for the first meg of low memory so we can't access devices there.
 * Intead we've mapped the device memory that we need to access into
 * a local variable within dboot so we can access the device memory
 * there.
 */
extern unsigned short *kb_status;
#define	kb_flag		((unsigned char *)&kb_status[BIOS_KB_FLAG])
#define	kb_flag_1	((unsigned char *)&kb_status[BIOS_KB_FLAG_1])

#else /* __xpv && _BOOT */

/* Device memory addresses */
#define	kb_flag		((unsigned char *)BIOS_KB_FLAG)
#define	kb_flag_1	((unsigned char *)BIOS_KB_FLAG_1)

#endif /* __xpv && _BOOT */

/*
 * Keyboard controller registers
 */
#define	I8042_DATA		0x60
#define	I8042_STAT		0x64
#define	I8042_CMD		0x64

/*
 * Keyboard controller status register bits
 */
#define	I8042_STAT_OUTBF	0x01
#define	I8042_STAT_INBF		0x02
#define	I8042_STAT_AUXBF	0x20

/*
 * Keyboard controller commands
 */
#define	I8042_RCB		0x20
#define	I8042_WCB		0x60

/*
 * Keyboard commands
 */
#define	KB_SET_LED		0xED	/* LED byte follows... */
#define	KB_LED_SCROLL_LOCK	0x01	/* Bits for LED byte */
#define	KB_LED_NUM_LOCK		0x02
#define	KB_LED_CAPS_LOCK	0x04

#ifndef ASSERT
#define	ASSERT(x)
#endif

#define	peek8(p)	(*(p))
#define	poke8(p, val)	(*(p) = (val))

static struct {
	boolean_t	initialized;
	enum { KB_LED_IDLE, KB_LED_COMMAND_SENT, KB_LED_VALUE_SENT }
			led_state;
	int		led_commanded;
	/*
	 * Possible values:
	 *
	 * -1		Nothing pending
	 * 0x000-0x0ff	Pending byte
	 * 0x100-0x1ff	Needs leading zero, then low byte next.
	 *
	 * Others undefined.
	 */
	int		pending;
} kb = {
	B_FALSE,	/* initialized? */
	KB_LED_IDLE,	/* LED command state */
	-1,		/* commanded LEDs - force refresh */
	-1,		/* pending */
};

static int kb_translate(unsigned char code);
static void kb_send(unsigned char cmd);
static void kb_update_leds(void);
static uchar_t kb_calculate_leds(void);

int
kb_getchar(void)
{
	int ret;

	while (!kb_ischar())
		/* LOOP */;

	/*
	 * kb_ischar() doesn't succeed without leaving kb.pending
	 * set.
	 */
	ASSERT(kb.pending >= 0);

	if (kb.pending & 0x100) {
		ret = 0;
		kb.pending &= 0xff;
	} else {
		ret = kb.pending;
		kb.pending = -1;
	}

	return (ret);
}

int
kb_ischar(void)
{
	unsigned char buffer_stat;
	unsigned char code;
	unsigned char leds;

	if (!kb.initialized) {
		kb_init();
		kb.initialized = B_TRUE;
	}

	if (kb.pending >= 0)
		return (1);

	for (;;) {
		buffer_stat = inb(I8042_STAT);
		if (buffer_stat == 0xff)
			return (0);
		buffer_stat &= (I8042_STAT_OUTBF | I8042_STAT_AUXBF);

		switch (buffer_stat) {
		case 0:
		case I8042_STAT_AUXBF:
			return (0);
		case (I8042_STAT_OUTBF | I8042_STAT_AUXBF):
			/*
			 * Discard unwanted mouse data.
			 */
			(void) inb(I8042_DATA);
			continue;
		}

		code = inb(I8042_DATA);

		switch (code) {
		/*
		 * case 0xAA:
		 *
		 * You might think that we should ignore 0xAA on the
		 * grounds that it is the BAT Complete response and will
		 * occur on keyboard detach/reattach.  Unfortunately,
		 * it is ambiguous - this is also the code for a break
		 * of the left shift key.  Since it will be harmless for
		 * us to "spuriously" process a break of Left Shift,
		 * we just let the normal code handle it.  Perhaps we
		 * should take a hint and refresh the LEDs, but I
		 * refuse to get very worried about hot-plug issues
		 * in this mini-driver.
		 */
		case 0xFA:

			switch (kb.led_state) {
			case KB_LED_IDLE:
				/*
				 * Spurious.  Oh well, ignore it.
				 */
				break;
			case KB_LED_COMMAND_SENT:
				leds = kb_calculate_leds();
				kb_send(leds);
				kb.led_commanded = leds;
				kb.led_state = KB_LED_VALUE_SENT;
				break;
			case KB_LED_VALUE_SENT:
				kb.led_state = KB_LED_IDLE;
				/*
				 * Check for changes made while we were
				 * working on the last change.
				 */
				kb_update_leds();
				break;
			}
			continue;

		case 0xE0:
		case 0xE1:
			/*
			 * These are used to distinguish the keys added on
			 * the AT-101 keyboard from the original 84 keys.
			 * We don't care, and the codes are carefully arranged
			 * so that we don't have to.
			 */
			continue;

		default:
			if (code & 0x80) {
				/* Release */
				code &= 0x7f;
				switch (keyboard_translate[code].normal) {
				case KBTYPE_SPEC_LSHIFT:
					poke8(kb_flag, peek8(kb_flag) &
					    ~BIOS_LEFT_SHIFT);
					break;
				case KBTYPE_SPEC_RSHIFT:
					poke8(kb_flag, peek8(kb_flag) &
					    ~BIOS_RIGHT_SHIFT);
					break;
				case KBTYPE_SPEC_CTRL:
					poke8(kb_flag, peek8(kb_flag) &
					    ~BIOS_CTL_SHIFT);
					break;
				case KBTYPE_SPEC_ALT:
					poke8(kb_flag, peek8(kb_flag) &
					    ~BIOS_ALT_SHIFT);
					break;
				case KBTYPE_SPEC_CAPS_LOCK:
					poke8(kb_flag_1, peek8(kb_flag_1) &
					    ~BIOS_CAPS_SHIFT);
					break;
				case KBTYPE_SPEC_NUM_LOCK:
					poke8(kb_flag_1, peek8(kb_flag_1) &
					    ~BIOS_NUM_SHIFT);
					break;
				case KBTYPE_SPEC_SCROLL_LOCK:
					poke8(kb_flag_1, peek8(kb_flag_1) &
					    ~BIOS_SCROLL_SHIFT);
					break;
				default:
					/*
					 * Ignore all other releases.
					 */
					break;
				}
			} else {
				/* Press */

				kb.pending = kb_translate(code);
				if (kb.pending >= 0) {
					return (1);
				}
			}
		}
	}
}

int
kb_translate(unsigned char code)
{
	struct keyboard_translate *k;
	unsigned short action;
	boolean_t shifted;

	k = keyboard_translate + code;

	shifted = (peek8(kb_flag) & BIOS_EITHER_SHIFT) != 0;

	switch (k->normal & 0xFF00) {
	case KBTYPE_NUMPAD:
		if (peek8(kb_flag) & BIOS_NUM_STATE)
			shifted = !shifted;
		break;
	case KBTYPE_ALPHA:
		if (peek8(kb_flag) & BIOS_CAPS_STATE)
			shifted = !shifted;
		break;
	}

	if (peek8(kb_flag) & BIOS_ALT_SHIFT)
		action = k->alted;
	else if (peek8(kb_flag) & BIOS_CTL_SHIFT)
		action = k->ctrled;
	else if (shifted)
		action = k->shifted;
	else
		action = k->normal;

	switch (action & 0xFF00) {
	case KBTYPE_NORMAL:
	case KBTYPE_ALPHA:
		return (action & 0xFF);

	case KBTYPE_NUMPAD:
	case KBTYPE_FUNC:
		return ((action & 0xFF) | 0x100);

	case KBTYPE_SPEC:
		break;

	default:
		/*
		 * Bad entry.
		 */
		ASSERT(0);
		return (-1);
	}

	/*
	 * Handle special keys, mostly shifts.
	 */
	switch (action) {
	case KBTYPE_SPEC_NOP:
	case KBTYPE_SPEC_UNDEF:
		break;

	case KBTYPE_SPEC_LSHIFT:
		poke8(kb_flag, peek8(kb_flag) | BIOS_LEFT_SHIFT);
		break;

	case KBTYPE_SPEC_RSHIFT:
		poke8(kb_flag, peek8(kb_flag) | BIOS_RIGHT_SHIFT);
		break;

	case KBTYPE_SPEC_CTRL:
		poke8(kb_flag, peek8(kb_flag) | BIOS_CTL_SHIFT);
		break;

	case KBTYPE_SPEC_ALT:
		poke8(kb_flag, peek8(kb_flag) | BIOS_ALT_SHIFT);
		break;

	case KBTYPE_SPEC_CAPS_LOCK:
		if (!(peek8(kb_flag_1) & BIOS_CAPS_SHIFT)) {
			poke8(kb_flag_1, peek8(kb_flag_1) | BIOS_CAPS_SHIFT);
			poke8(kb_flag, peek8(kb_flag) ^ BIOS_CAPS_STATE);
		}
		break;

	case KBTYPE_SPEC_NUM_LOCK:
		if (!(peek8(kb_flag_1) & BIOS_NUM_SHIFT)) {
			poke8(kb_flag_1, peek8(kb_flag_1) | BIOS_NUM_SHIFT);
			poke8(kb_flag, peek8(kb_flag) ^ BIOS_NUM_STATE);
		}
		break;

	case KBTYPE_SPEC_SCROLL_LOCK:
		if (!(peek8(kb_flag_1) & BIOS_SCROLL_SHIFT)) {
			poke8(kb_flag_1, peek8(kb_flag_1) | BIOS_SCROLL_SHIFT);
			poke8(kb_flag, peek8(kb_flag) ^ BIOS_SCROLL_STATE);
		}
		break;

	case KBTYPE_SPEC_MAYBE_REBOOT:
#if 0	/* Solaris doesn't reboot via ctrl-alt-del */
		if ((peek8(kb_flag) & (BIOS_CTL_SHIFT|BIOS_ALT_SHIFT)) ==
		    (BIOS_CTL_SHIFT|BIOS_ALT_SHIFT)) {
			reset();
			/* NOTREACHED */
		}
#endif
		break;

	default:
		/*
		 * Bad entry
		 */
		ASSERT(0);
		break;
	}

	/*
	 * Consider updating the LEDs.  This does nothing if nothing
	 * needs to be done.
	 */
	kb_update_leds();

	return (-1);
}

void
kb_send(unsigned char cmd)
{
	int retries;

	for (retries = 0;
	    (inb(I8042_STAT) & I8042_STAT_INBF) != 0 && retries < 100000;
	    retries++)
		/* LOOP */;
	outb(I8042_DATA, cmd);
}

void
kb_update_leds(void)
{
	if (kb.led_state != KB_LED_IDLE) {
		/*
		 * The state machine will take care of any additional
		 * changes that are necessary.
		 */
		return;
	}

	if (kb_calculate_leds() == kb.led_commanded) {
		kb.led_state = KB_LED_IDLE;
	} else {
		kb_send(KB_SET_LED);
		kb.led_state = KB_LED_COMMAND_SENT;
	}
}

#define	MIMR_PORT	0x21	/* Mask register for master PIC */
#define	MIMR_KB		2	/* Keyboard mask bit in master PIC */

void
kb_init(void)
{
	/*
	 * Resist the urge to muck with the keyboard/mouse.  Just assume
	 * that the bios, grub, and any optional hypervisor have left
	 * the keyboard in a sane and usable state.  Messing with it now
	 * could result it making it unusuable, which would break early
	 * kmdb debugging support.  Note that we don't actually need to
	 * disable interrupts for the keyboard/mouse since we're already
	 * in protected mode and we're not compeating with the bios for
	 * keyboard access.  Also, we don't need to disable the mouse
	 * port since our polled input routine will just drop any mouse
	 * data that it recieves.
	 */
	kb_update_leds();
}

unsigned char
kb_calculate_leds(void)
{
	int res;

	res = 0;

	if (peek8(kb_flag) & BIOS_CAPS_STATE)
		res |= KB_LED_CAPS_LOCK;

	if (peek8(kb_flag) & BIOS_NUM_STATE)
		res |= KB_LED_NUM_LOCK;

	if (peek8(kb_flag) & BIOS_SCROLL_STATE)
		res |= KB_LED_SCROLL_LOCK;

	return ((char)res);
}
