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

/*
 * Generic keyboard support: translation
 *
 * This module is project private.  Please see PSARC/1998/176 and
 * PSARC/1998/026 for references to the kbtrans module.
 *
 * It is believed that it is safe to call these functions within debugger mode
 * except kbtrans_dprintf.  Debugger mode is a single threaded mode where most
 * kernel services are not available, including memory allocation.  Debugger
 * mode is for kmdb and OBP debugging, where the debugger calls back into the
 * kernel to obtain console input.
 *
 * Please be _very_ careful about what external functions you call.
 */

#define	KEYMAP_SIZE_VARIABLE

#include <sys/types.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/kbd.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>
#include <sys/kbio.h>
#include <sys/vuid_event.h>
#include <sys/consdev.h>
#include <sys/kbtrans.h>
#include <sys/errno.h>
#include <sys/promif.h>
#include <sys/varargs.h>
#include "kbtrans_lower.h"

/*
 * Internal Function Prototypes
 */
static boolean_t kbtrans_do_compose(struct kbtrans_lower *, keymap_entry_t,
    keymap_entry_t, keymap_entry_t *);
static void kbtrans_translate(struct kbtrans_lower *,
    struct keyboard_callback *, kbtrans_key_t, enum keystate);

/*
 * kbtrans_processkey:
 *
 * 	lower	- state information used by the calling driver
 *		  this parameter is passed back to the callback routines.
 * 	key	- scancode
 * 	state	- KEY_PRESSED / KEY_RELEASED
 *
 * This routine checks to see if there is a raw callback, and calls it
 * if it exists.  If there is no raw callback, the key is translated.
 * The raw callback allows the driver that called the translation module
 * to be passed untranslated scancodes.
 */
void
kbtrans_processkey(struct kbtrans_lower *lower,
    struct keyboard_callback *cb, kbtrans_key_t key, enum keystate state)
{
	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (lower, "kbtrans_processkey: "
	    "newstate=%d key=%d", state, key));

	/*
	 * If there is a raw routine, then call it and return.
	 */
	if (cb->kc_keypressed_raw != NULL) {

		if (state == KEY_PRESSED) {

			cb->kc_keypressed_raw(lower->kbtrans_upper, key);
		} else {

			cb->kc_keyreleased_raw(lower->kbtrans_upper, key);
		}

		return;
	}

	/*
	 * translate the scancode into a key.
	 */
	kbtrans_translate(lower, cb, key, state);
}


/*
 * kbtrans_translate:
 *
 * 	lower	- state information used by the calling driver
 *		  this parameter is passed back to the callback routines.
 * 	key		- scan code
 * 	state	- KEY_PRESSED / KEY_RELEASED
 *
 * Called to process key events if we are in TR_ASCII or TR_EVENT
 * (sunview) mode.  This routine will call the appropriate translation_callback
 * for the character when it is done translating it.
 */
static void
kbtrans_translate(struct kbtrans_lower *lower, struct keyboard_callback *cb,
    kbtrans_key_t key, enum keystate newstate)
{
	unsigned		shiftmask;
	register keymap_entry_t	entry;
	register unsigned	entrytype;
	keymap_entry_t		result;
	keymap_entry_t		*ke;
	int			i;
	boolean_t		good_compose;

	DPRINTF(PRINT_L0, PRINT_MASK_ALL, (lower, "KEY TRANSLATE "
	    "newstate=0x%x key=0x%x\n", newstate, key));

	if (lower->kbtrans_keyboard == NULL) {
		/*
		 * Nobody has told us about this keyboard yet.
		 */
		return;
	}

	/*
	 * Get the current state of the shiftmask
	 */
	shiftmask = lower->kbtrans_shiftmask;

	/*
	 * If the key has been released, then or in the UPMASK flag.
	 */
	if (newstate == KEY_RELEASED)
		shiftmask |= UPMASK;

	/*
	 * Based on the shiftmask, lookup the keymap entry that we should
	 * be using for this scancode.
	 */
	ke = kbtrans_find_entry(lower, shiftmask, key);

	if (ke == NULL) {
		/*
		 * This is a gross error.  Cancel the repeat key and exit,
		 * we can not translate this scancode.
		 */
		cb->kc_cancel_repeat(lower->kbtrans_upper);

		return;
	}

	/*
	 * Get the key for this scancode.
	 */
	entry = *ke;

	if (entry == NONL) {
		/*
		 * NONL appears only in the Num Lock table, and indicates that
		 * this key is not affected by Num Lock.  This means we should
		 * ask for the table we would have gotten had Num Lock not been
		 * down, and translate using that table.
		 */
		ke = kbtrans_find_entry(lower, shiftmask & ~NUMLOCKMASK, key);

		if (ke == NULL) {
			/*
			 * This is a gross error.  Cancel the repeat key and
			 * exit, we can not translate this scancode.
			 */
			cb->kc_cancel_repeat(lower->kbtrans_upper);

			return;
		}

		/*
		 * Get the new key for this scancode.
		 */
		entry = *ke;
	}

	/*
	 * The entrytype indicates what category of key we are processing.
	 * Categories include shift keys, function keys, and numeric keypad
	 * keys.
	 */
	entrytype = KEYFLAGS(entry);

	if (entrytype == SHIFTKEYS) {
		/*
		 * Handle the state of toggle shifts specially.
		 * Ups should be ignored, and downs should be mapped to ups if
		 * that shift is currently on.
		 */
		if ((1 << (entry & 0x0F)) &
		    lower->kbtrans_keyboard->k_toggleshifts) {
			if ((1 << (entry & 0x0F)) & lower->kbtrans_togglemask) {
				newstate = KEY_RELEASED; /* toggling off */
			} else {
				newstate = KEY_PRESSED;	/* toggling on */
			}
		}
	} else {
		/*
		 * Handle Compose and floating accent key sequences
		 */
		switch (lower->kbtrans_state) {
		case COMPOSE1:
			if (newstate == KEY_RELEASED)
				return;

			if (entry < ASCII_SET_SIZE) {
				if (lower->kbtrans_compose_map[entry] >= 0) {
					lower->kbtrans_compose_key = entry;
					lower->kbtrans_state = COMPOSE2;

					return;
				}
			}
			lower->kbtrans_state = NORMAL;
			lower->kbtrans_led_state &= ~LED_COMPOSE;

			cb->kc_setled(lower->kbtrans_upper);

			return;

		case COMPOSE2:
			if (newstate == KEY_RELEASED)
				return;

			/* next state is "normal" */
			lower->kbtrans_state = NORMAL;
			lower->kbtrans_led_state &= ~LED_COMPOSE;

			cb->kc_setled(lower->kbtrans_upper);

			good_compose = kbtrans_do_compose(lower,
			    lower->kbtrans_compose_key, entry, &result);
			if (good_compose) {
				cb->kc_keypressed(lower->kbtrans_upper,
				    entrytype, key, result);
			}
			return;

		case FLTACCENT:
			if (newstate == KEY_RELEASED)
				return;

			/* next state is "normal" */
			lower->kbtrans_state = NORMAL;
			for (i = 0;
			    (lower->kbtrans_fltaccent_table[i].fa_entry !=
			    lower->kbtrans_fltaccent_entry) ||
			    (lower->kbtrans_fltaccent_table[i].ascii != entry);
			    i++) {
				if (lower->kbtrans_fltaccent_table[i].fa_entry
				    == 0) {
					/* Invalid second key: ignore key */

					return;
				}
			}

			cb->kc_keypressed(lower->kbtrans_upper, entrytype, key,
			    lower->kbtrans_fltaccent_table[i].utf8);

			return;
		}
	}

	/*
	 * If the key is going down, and it's not one of the keys that doesn't
	 * auto-repeat, set up the auto-repeat timeout.
	 *
	 * The keys that don't auto-repeat are the Compose key,
	 * the shift keys, the "bucky bit" keys, the "floating accent" keys,
	 * and the function keys when in TR_EVENT mode.
	 */
	if (newstate == KEY_PRESSED && entrytype != SHIFTKEYS &&
	    entrytype != BUCKYBITS && entrytype != FUNNY &&
	    entrytype != FA_CLASS) {

		if (lower->kbtrans_repeatkey != key) {
			cb->kc_cancel_repeat(lower->kbtrans_upper);
			cb->kc_setup_repeat(lower->kbtrans_upper, entrytype,
			    key);
		}
		/* key going up */
	} else if (key == lower->kbtrans_repeatkey) {

		cb->kc_cancel_repeat(lower->kbtrans_upper);
	}

	if (newstate == KEY_RELEASED) {
		cb->kc_keyreleased(lower->kbtrans_upper, key);
	}

	/*
	 * We assume here that keys other than shift keys and bucky keys have
	 * entries in the "up" table that cause nothing to be done, and thus we
	 * don't have to check for newstate == KEY_RELEASED.
	 */
	switch (entrytype) {

	case 0x0:		/* regular key */
		cb->kc_keypressed(lower->kbtrans_upper, entrytype, key,
		    SPECIAL(lower->kbtrans_buckybits, entry));
		break;

	case SHIFTKEYS: {
		uint_t shiftbit = 1 << (entry & 0x0F);

		/* Modify toggle state (see toggle processing above) */
		if (shiftbit & lower->kbtrans_keyboard->k_toggleshifts) {
			if (newstate == KEY_RELEASED) {
				if (shiftbit == CAPSMASK) {
					lower->kbtrans_led_state &=
					    ~LED_CAPS_LOCK;

					cb->kc_setled(lower->kbtrans_upper);

				} else if (shiftbit == NUMLOCKMASK) {
					lower->kbtrans_led_state &=
					    ~LED_NUM_LOCK;

					cb->kc_setled(lower->kbtrans_upper);
				}
				lower->kbtrans_togglemask &= ~shiftbit;
			} else {
				if (shiftbit == CAPSMASK) {
					lower->kbtrans_led_state |=
					    LED_CAPS_LOCK;

					cb->kc_setled(lower->kbtrans_upper);
				} else if (shiftbit == NUMLOCKMASK) {
					lower->kbtrans_led_state |=
					    LED_NUM_LOCK;

					cb->kc_setled(lower->kbtrans_upper);
				}
				lower->kbtrans_togglemask |= shiftbit;
			}
		}

		if (newstate == KEY_RELEASED)
			lower->kbtrans_shiftmask &= ~shiftbit;
		else
			lower->kbtrans_shiftmask |= shiftbit;

		if (newstate == KEY_PRESSED) {
			cb->kc_keypressed(lower->kbtrans_upper, entrytype, key,
			    entry);
		}

		break;
		}

	case BUCKYBITS:
		lower->kbtrans_buckybits ^= 1 << (entry & 0x0F);

		if (newstate == KEY_PRESSED) {
			cb->kc_keypressed(lower->kbtrans_upper, entrytype, key,
			    entry);
		}

		break;

	case FUNNY:
		switch (entry) {
		case NOP:
			break;

		case IDLE:
			/* Fall thru into RESET code */
			/* FALLTHRU */
		case RESET:
		case ERROR:
			lower->kbtrans_shiftmask &=
			    lower->kbtrans_keyboard->k_idleshifts;

			lower->kbtrans_shiftmask |=
			    lower->kbtrans_togglemask;

			lower->kbtrans_buckybits &=
			    lower->kbtrans_keyboard->k_idlebuckys;

			cb->kc_cancel_repeat(lower->kbtrans_upper);

			cb->kc_keypressed(lower->kbtrans_upper, entrytype, key,
			    entry);

			break;


		case COMPOSE:
			lower->kbtrans_state = COMPOSE1;
			lower->kbtrans_led_state |= LED_COMPOSE;
			cb->kc_setled(lower->kbtrans_upper);
			break;
		/*
		 * Remember when adding new entries that,
		 * if they should NOT auto-repeat,
		 * they should be put into the IF statement
		 * just above this switch block.
		 */
		default:
			/* Ignore it */
			break;
		}
		break;

	case FA_CLASS:
		if (lower->kbtrans_state == NORMAL) {
			lower->kbtrans_fltaccent_entry = entry;
			lower->kbtrans_state = FLTACCENT;
		}
		break;

	case STRING:
		cb->kc_keypressed(lower->kbtrans_upper, entrytype, key, entry);

		break;

	case FUNCKEYS:
		cb->kc_keypressed(lower->kbtrans_upper, entrytype, key, entry);

		break;

	/*
	 * Remember when adding new entries that,
	 * if they should NOT auto-repeat,
	 * they should be put into the IF statement
	 * just above this switch block.
	 */
	case PADKEYS:
		cb->kc_keypressed(lower->kbtrans_upper, entrytype, key, entry);

		break;
	}
}

/*
 * kbtrans_do_compose:
 *	Given a two key compose sequence, lookup the iso equivalent and put
 *	the result in the result_ptr.
 */
static boolean_t
kbtrans_do_compose(struct kbtrans_lower *lower, keymap_entry_t first_entry,
    keymap_entry_t second_entry, keymap_entry_t *result_ptr)
{
	struct compose_sequence_t *ptr;
	keymap_entry_t tmp;

	/*
	 * Validate the second keystroke.
	 */
	if (second_entry >= ASCII_SET_SIZE)
		return (B_FALSE);

	if (lower->kbtrans_compose_map[second_entry] < 0)
		return (B_FALSE);

	/*
	 * Get them in code order, rather than press order.
	 */
	if (first_entry > second_entry) {
		tmp = first_entry;
		first_entry = second_entry;
		second_entry = tmp;
	}

	ptr = lower->kbtrans_compose_table +
	    lower->kbtrans_compose_map[first_entry];

	while (ptr->first == first_entry) {
		if (ptr->second == second_entry) {
			*result_ptr = ptr->utf8;

			return (B_TRUE);
		}
		ptr++;
	}
	return (B_FALSE);
}


/*
 * kbtrans_find_entry:
 * 	This routine finds the entry corresponding to the current shift
 * 	state and keycode.
 */
keymap_entry_t *
kbtrans_find_entry(struct kbtrans_lower *lower, uint_t mask,
    kbtrans_key_t key_station)
{
	register struct keyboard *kp;
	keymap_entry_t *km;
	struct exception_map *ex;

	kp = lower->kbtrans_keyboard;

	if (kp == NULL)
		return (NULL);

	if (key_station < 0 || key_station >= kp->k_keymap_size)
		return (NULL);

	ex = kp->k_except;
	if (ex != NULL) {
		for (; ex->exc_care != 0; ex++) {
			if ((mask & ex->exc_care) == ex->exc_mask &&
			    key_station == ex->exc_key)
				return (&ex->exc_entry);
		}
	}

	if (mask & UPMASK)
		km = kp->k_up;
	else if (mask & NUMLOCKMASK)
		km = kp->k_numlock;
	else if (mask & CTRLMASK)
		km = kp->k_control;
	else if (mask & ALTGRAPHMASK)
		km = kp->k_altgraph;
	else if (mask & SHIFTMASK)
		km = kp->k_shifted;
	else if (mask & CAPSMASK)
		km = kp->k_caps;
	else km = kp->k_normal;

	return (&km[key_station]);
}

#ifdef DEBUG
/*ARGSUSED*/
void
kbtrans_dprintf(void *un, const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	(void) vsprintf(buf, fmt, ap);
	va_end(ap);

	cmn_err(CE_CONT, "kbtrans: %s", buf);
}
#endif
