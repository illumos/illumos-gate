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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Generic Keyboard Support: Polled I/O support for kbtrans-supported keyboards.
 */

#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/kbd.h>
#include <sys/kbio.h>
#include <sys/vuid_event.h>
#include <sys/consdev.h>
#include <sys/kbtrans.h>
#include "kbtrans_lower.h"
#include "kbtrans_streams.h"

/*
 * Internal Function Prototypes
 */
static void kbtrans_polled_pressed(struct kbtrans *, uint_t, kbtrans_key_t,
			uint_t);
static void kbtrans_polled_released(struct kbtrans *, kbtrans_key_t);
static void kbtrans_polled_setled(struct kbtrans *);
static void kbtrans_polled_setup_repeat(struct kbtrans *, uint_t,
			kbtrans_key_t);
static void kbtrans_polled_cancel_repeat(struct kbtrans *);

/*
 * Functions to be called when a key is translated during polled
 * mode
 */
struct keyboard_callback kbtrans_polled_callbacks = {
	NULL,				/* keypressed_raw */
	NULL,				/* keyreleased_raw */
	kbtrans_polled_pressed,		/* keypressed */
	kbtrans_polled_released,	/* keyreleased */
	kbtrans_polled_setup_repeat,	/* setup_repeat */
	kbtrans_polled_cancel_repeat,	/* cancel_repeat */
	kbtrans_polled_setled,		/* setled */
};

/*
 * kbtrans_ischar:
 *	Return B_TRUE if character is pending, else return B_FALSE
 */
boolean_t
kbtrans_ischar(struct kbtrans *upper)
{
	struct kbtrans_callbacks *cb;
	struct kbtrans_hardware *hw;
	kbtrans_key_t key;
	enum keystate state;

	/*
	 * If we've still got input pending, say so.
	 */
	if (*upper->kbtrans_polled_pending_chars != '\0') {
		return (B_TRUE);
	}

	/*
	 * Reset to an empty buffer.
	 */
	upper->kbtrans_polled_buf[0] = '\0';
	upper->kbtrans_polled_pending_chars = upper->kbtrans_polled_buf;

	cb = upper->kbtrans_streams_hw_callbacks;
	hw = upper->kbtrans_streams_hw;

	/*
	 * Process scancodes until either we have input ready
	 * or we run out of scancodes.
	 */
	while (cb->kbtrans_polled_keycheck(hw, &key, &state)) {
		kbtrans_processkey(&upper->kbtrans_lower,
			&kbtrans_polled_callbacks, key, state);
		/*
		 * If that generated any input, we're ready.
		 */
		if (*upper->kbtrans_polled_pending_chars != '\0') {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * kbtrans_getchar:
 * 	Return a character
 */
int
kbtrans_getchar(struct kbtrans *upper)
{
	while (!kbtrans_ischar(upper))
		/* LOOP */;

	return (*upper->kbtrans_polled_pending_chars++);
}

void
kbtrans_polled_putcode(struct kbtrans *upper, char code)
{
	int i;

	/*
	 * NB:  KBTRANS_POLLED_BUF_SIZE is one smaller than
	 * the size of the buffer, to allow for a trailing
	 * null.
	 */
	for (i = 0; i < KBTRANS_POLLED_BUF_SIZE; i++) {
		if (upper->kbtrans_polled_buf[i] == '\0') {
			upper->kbtrans_polled_buf[i] = code;
			upper->kbtrans_polled_buf[i+1] = '\0';
			return;
		}
	}
	DPRINTF(PRINT_L2, PRINT_MASK_PACKET,
		(upper, "kbtrans_polled_pressed:  "
		"buffer overflow, character 0x%x discarded\n", code));
	/*
	 * Didn't fit, throw it on the floor.
	 */
}

/*
 * kbtrans_polled_pressed:
 *	This function is called when we are in polled mode and a key is
 * 	pressed.  The key is put into the kbtrans_polled_buf so that it
 * 	can be picked up later by kbtrans_ischar()
 */
/*ARGSUSED2*/
static void
kbtrans_polled_pressed(
    struct kbtrans *upper,
    uint_t entrytype,
    kbtrans_key_t key,
    uint_t entry)
{
	struct kbtrans_lower	*lower = &upper->kbtrans_lower;
	register char	*cp;

	/*
	 * Based on the type of key, we may need to do some ASCII
	 * specific post processing.
	 */
	switch (entrytype) {

	case BUCKYBITS:
	case SHIFTKEYS:
	case FUNNY:
		/*
		 * There is no ascii equivalent.  We will ignore these
		 * keys
		 */
		break;

	case FUNCKEYS:
		/*
		 * These will no doubt only cause problems.  Ignore them.
		 */

		break;

	case STRING:
		/*
		 * These are the multi byte keys (Home, Up, Down ...)
		 */
		cp = &lower->kbtrans_keystringtab[entry & 0x0F][0];

		/*
		 * Copy the string from the keystringtable, and send it
		 * upstream a character at a time.
		 */
		while (*cp != '\0') {
			kbtrans_polled_putcode(upper, *cp);
			cp++;
		}

		return;

	case PADKEYS:
		/*
		 * These are the keys on the keypad.  Look up the
		 * answer in the kb_numlock_table and send it upstream.
		 */
		kbtrans_polled_putcode(upper,
			lower->kbtrans_numlock_table[entry&0x1F]);

		break;

	case 0:	/* normal character */
	default:
		/*
		 * Send the byte upstream.
		 */
		kbtrans_polled_putcode(upper, (char)entry);
		break;
	}
}

/*
 * kbtrans_polled_released:
 *	This function is called when a key is released.  Nothing is
 * 	done.
 */
/*ARGSUSED*/
static void
kbtrans_polled_released(struct kbtrans *upper, kbtrans_key_t key)
{
	/* Nothing for now */
}

/*
 * kbtrans_polled_setled:
 *	This function is called to set the LEDs.
 */
static void
kbtrans_polled_setled(struct kbtrans *upper)
{
	struct kbtrans_callbacks *cb;
	struct kbtrans_hardware *hw;

	cb = upper->kbtrans_streams_hw_callbacks;
	hw = upper->kbtrans_streams_hw;

	cb->kbtrans_polled_setled(hw, upper->kbtrans_lower.kbtrans_led_state);
}

/*
 * kbtrans_polled_setup_repeat:
 *	Function to be called in order to handle a repeating key.
 *	Nothing is done.
 */
/*ARGSUSED*/
static void
kbtrans_polled_setup_repeat(
    struct kbtrans *upper,
    uint_t entrytype,
    kbtrans_key_t key)
{
	/* Nothing for now */
}

/*
 * kbtrans_polled_cancel_repeat:
 *	Function to be called to cancel a repeating key,
 *	so that we don't end up with an autorepeating key
 * 	on the stream because its release was handled by the
 * 	polled code.
 */
static void
kbtrans_polled_cancel_repeat(struct kbtrans *upper)
{
	/*
	 * Streams code will time out and will discard the
	 * autorepeat.
	 */
	upper->kbtrans_lower.kbtrans_repeatkey = 0;
}
