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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _KBTRANS_LOWER_H
#define	_KBTRANS_LOWER_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * This structure describes the state of the keyboard.
 * and also specifies the keytables.
 */
struct kbtrans_lower {
	/* Generating pre-4.1 events? */
	int	kbtrans_compat;

	/* key to repeat in TR_ASCII mode */
	kbtrans_key_t kbtrans_repeatkey;

	/* Current state of the LED's */
	uchar_t	kbtrans_led_state;

	/* Pointer to keyboard maps */
	struct  keyboard *kbtrans_keyboard;

	/* Current shift state */
	uint_t   kbtrans_shiftmask;

	uchar_t  kbtrans_state;		/* compose state */
	uint_t   kbtrans_buckybits;	/* current buckybits */
	uint_t   kbtrans_togglemask;   	/* Toggle shifts state */
	kbtrans_key_t kbtrans_compose_key;	/* first compose key */
	kbtrans_key_t kbtrans_fltaccent_entry; /* floating accent entry */

	/*
	 * Various mapping tables.
	 */
	signed char			*kbtrans_compose_map;
	struct compose_sequence_t	*kbtrans_compose_table;
	struct fltaccent_sequence_t	*kbtrans_fltaccent_table;

	/* Strings sent by various keys */
	char				(*kbtrans_keystringtab)[KTAB_STRLEN];

	/* Num lock table */
	unsigned char			*kbtrans_numlock_table;

	/*
	 * The kbtrans structure specifies the state of the
	 * stream.
	 */
	struct kbtrans			*kbtrans_upper;
};


/*
 * Different functions must be called based upon the type of translation
 * mode.  Each translation mode such as TR_ASCII, TR_EVENT, TR_NONE, etc.
 * has an instance of this structure.
 */
struct keyboard_callback {

	/*
	 * Raw (untranslated) keypress
	 */
	void (*kc_keypressed_raw)(struct kbtrans *, kbtrans_key_t);

	/*
	 * Raw (untranslated) keyrelease
	 */
	void (*kc_keyreleased_raw)(struct kbtrans *, kbtrans_key_t);

	/*
	 * Keypress
	 */
	void (*kc_keypressed)(struct kbtrans *, uint_t, kbtrans_key_t, uint_t);

	/*
	 * Keyrelease
	 */
	void (*kc_keyreleased)(struct kbtrans *, kbtrans_key_t);

	/*
	 * Initialize a repeat character
	 */
	void (*kc_setup_repeat)(struct kbtrans *, uint_t, kbtrans_key_t);

	/*
	 * Cancel a repeat character
	 */
	void (*kc_cancel_repeat)(struct kbtrans *);

	/*
	 * Process the led state change
	 */
	void (*kc_setled)(struct kbtrans *);
};

/*
 * Process a scancode.  This routine will call the functions in
 * keyboard_callback to handle the translated key.
 */
void kbtrans_processkey(struct kbtrans_lower *, struct keyboard_callback *,
    kbtrans_key_t, enum keystate);

/*
 * This routine finds the entry for the specified keycode based on the
 * specified shift mask.
 */
keymap_entry_t *kbtrans_find_entry(struct kbtrans_lower *, uint_t,
    kbtrans_key_t);

/*
 * Debug printing
 */
#ifndef DPRINTF
#ifdef DEBUG
#define	DPRINTF(l, m, args) \
	(((l) >= kbtrans_errlevel) && ((m) & kbtrans_errmask) ? \
		kbtrans_dprintf args :                          \
		(void) 0)
#else
#define	DPRINTF(l, m, args)
#endif
#endif

/*
 * Severity levels for printing
 */
#define	PRINT_L0	0	/* print every message */
#define	PRINT_L1	1	/* debug */
#define	PRINT_L2	2	/* minor errors */
#define	PRINT_L3	3	/* major errors */
#define	PRINT_L4	4	/* catastophic errors */

/*
 * Masks
 */

#define	PRINT_MASK_ALL		0xFFFFFFFF
#define	PRINT_MASK_OPEN		0x00000002
#define	PRINT_MASK_PACKET	0x00000008
#define	PRINT_MASK_CLOSE	0x00000004

#ifdef DEBUG
extern int	kbtrans_errmask;
extern int	kbtrans_errlevel;
extern void	kbtrans_dprintf(void *, const char *fmt, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif	/* _KBTRANS_LOWER_H */
