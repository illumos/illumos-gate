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

#ifndef _SYS_KBD_H
#define	_SYS_KBD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 1.18 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Following #defines are related to the older keyboards which
 * are no longer supported by kb module.  The #defines ane left
 * for older programs to still compile.
 */
#define	KB_KLUNK	0x00		/* Micro Switch 103SD32-2 */
#define	KB_VT100	0x01		/* Keytronics VT100 compatible */
#define	KB_SUN2		0x02		/* Sun-2 custom keyboard */
#define	KB_VT220	0x81		/* Emulation VT220 */
#define	KB_VT220I	0x82		/* International VT220 Emulation */

#define	NOTPRESENT	0xFF		/* Keyboard is not plugged in */
#define	KBD_CMD_LED1	0x04		/* Turn on LED 1 for Sun-2 */
#define	KBD_CMD_NOLED1	0x05		/* Turn off LED 1 for Sun-2 */
#define	KBD_CMD_LED2	0x06		/* Turn on LED 2 for Sun-2 */
#define	KBD_CMD_NOLED2	0x07		/* Turn off LED 2 for Sun-2 */

#define	CTLSMASK	0x0100		/* Set if ^S was last keyed of ^S, ^Q */
					/* determines which NOSCROLL sends. */

#define	NOSCROLL	0x303	/* This key alternately sends ^S or ^Q */
#define	CTRLS		0x304	/* This sends ^S and lets NOSCROLL know */
#define	CTRLQ		0x305	/* This sends ^Q and lets NOSCROLL know */


/*
 * Following are the only keyboard types supported by kb module.
 * (Type 5, Hobo, US101A are also supported but they report
 * themselves as Type 4 keyboard with a different layout id.)
 */
#define	KB_SUN3		3		/* Type 3 Sun keyboard */
#define	KB_SUN4		4		/* Type 4 Sun keyboard */
#define	KB_USB		6		/* USB keyboard */
#define	KB_PC		101		/* Type 101 AT keyboard */

#define	KB_ASCII	0x0F		/* Ascii terminal masquerading as kbd */

/*
 * This structure is used to enumerate the supported keyboard types.
 * The array of these is terminated by an entry with a NULL table entry.
 * The first entry is used if none match.
 */
struct keyboards {
	int		id;	/* Keyboard type, per KIOCTYPE */
	struct keyboard	*table;	/* Keyboard table to use. */
};

/*
 * Various special characters that might show up on the port
 */
#define	IDLEKEY		0x7F		/* Keyboard is idle; no keys down */
#define	ERRORKEY	0x7E		/* Keyboard detected an error */
#define	RESETKEY	0xFF		/* Keyboard was just reset */
#define	LAYOUTKEY	0xFE		/* Keyboard layout byte follows */

#define	PRESSED		0x00		/* 0x80 bit off: key was pressed */
#define	RELEASED	0x80		/* 0x80 bit on : key was released */

/*
 * Commands to the Sun-3 keyboard.
 */
#define	KBD_CMD_RESET		0x01	/* Reset keyboard as if power-up */
#define	KBD_CMD_BELL		0x02	/* Turn on the bell */
#define	KBD_CMD_NOBELL		0x03	/* Turn off the bell */
#define	KBD_CMD_CLICK		0x0A	/* Turn on the click annunciator */
#define	KBD_CMD_NOCLICK		0x0B	/* Turn off the click annunciator */

/*
 * Commands to the Type 4 keyboard, in addition to those above.
 */
#define	KBD_CMD_AUTOTEST	0x0C	/* Initiate test sequence */
#define	KBD_CMD_SETLED		0x0E	/* Set keyboard LED's */
#define	KBD_CMD_GETLAYOUT	0x0F	/* Request that keyboard indicate */
					/* layout */
/*
 * Type 4 keyboard LED masks (used to set LED's)
 */
#define	LED_NUM_LOCK	0x1
#define	LED_COMPOSE	0x2
#define	LED_SCROLL_LOCK 0x4
#define	LED_CAPS_LOCK	0x8
#define	LED_KANA	0x10		/* Valid only on Japanese layout */

/*
 * Software related definitions
 */
/*
 * These are the states that the keyboard scanner can be in.
 *
 * It starts out in NORMAL state.
 */
#define	NORMAL		0		/* The usual (ho, hum) */
#define	ABORT1		1		/* Got KEYABORT1 */
#define	COMPOSE1	2		/* Got COMPOSE */
#define	COMPOSE2	3		/* Got COMPOSE plus first key */
#define	FLTACCENT	4		/* Got floating accent key */
#define	NEWABORT1	5		/* Got NEW KEYABORT1 */

/*
 * Size of ASCII set as used in compose handling.
 */
#define	ASCII_SET_SIZE	128

/*
 * These are how you can have your input translated.
 * TR_EVENT means that each keystroke is sent as a firm event.
 * TR_UNTRANS_EVENT also sends a firm event for each up / down transition,
 * but the value is untranslated: the event id is the key station; the
 * value indicates whether the transition was up or down; the value of the
 * shift-mask is undefined.
 */
#define	TR_NONE		  0
#define	TR_ASCII	  1
#define	TR_EVENT	  2
#define	TR_UNTRANS_EVENT  3

/*
 * These bits can appear in the result of TR_NONE & TR_UNTRANS_EVENT getkey()s.
 */
#define	BUILDKEY(key, state)	(key | state)
#define	STATEOF(key)	((key) & RELEASED)	/* 0 = key down, !=0 = key up */
#define	KEYOF(key)	((key) & ~RELEASED)	/* The key number that moved */
#define	NOKEY		(-1)		/* The argument was 0, and no key was */
					/* depressed.  They were all elated. */

/*
 * "Bucky" bits.  These are bits for mode keys.	 The META bit is ORed into the
 * result of TR_ASCII getkey()s, and can be ORed into the result of TR_EVENT
 * getkey()s for backwards compatibility.
 * (NOKEY can also appear if no keypress was queued up.)
 */
#define	METABIT		0		/* Meta key depressed with key */
#define	METAMASK	0x000080
#define	SYSTEMBIT	1		/* Upper left key was down w/key */
#define	SYSTEMMASK	0x000100
/* other "bucky" bits can be defined at will.  See "BUCKYBITS" below. */

/*
 * This defines the bit positions used within "shiftmask" to
 * indicate the "pressed" (1) or "released" (0) state of shift keys.
 * Both the bit numbers, and the aggregate masks, are defined.
 *
 * The "UPMASK" is a minor kludge.  Since whether the key is going
 * up or down determines the translation table (just as the shift
 * keys' positions do), we OR it with "shiftmask" to get "tempmask",
 * which is the mask which is actually used to determine the
 * translation table to use.  Don't reassign 0x0080 for anything
 * else, or we'll have to shift and such to squeeze in UPMASK,
 * since it comes in from the hardware as 0x80.
 */
#define	CAPSLOCK	0		/* Caps Lock key */
#define	CAPSMASK	0x0001
#define	SHIFTLOCK	1		/* Shift Lock key */
#define	LEFTSHIFT	2		/* Left-hand shift key */
#define	RIGHTSHIFT	3		/* Right-hand shift key */
#define	SHIFTMASK	0x000E
#define	LEFTCTRL	4		/* Left-hand (or only) control key */
#define	RIGHTCTRL	5		/* Right-hand control key */
#define	CTRLMASK	0x0030
/*	META		6		Meta keys */
/*	META_SHIFT_MASK 0x0040		reserved */
/*	TOP		7		do not use! */
/*	TOPMASK		0x0080		UPMASK in keyboard driver */
/*	CMD		8		reserved */
/*	CMDMASK		0x0100		reserved */
#define	ALTGRAPH	9		/* Alt Graph key */
#define	ALTGRAPHMASK	0x0200
#define	ALT		10		/* Left (or only) Alt key */
#define	LEFTALT		10		/* Left Alt key */
#define	ALTMASK		0x1400
#define	NUMLOCK		11		/* Num Lock key */
#define	NUMLOCKMASK	0x0800
#define	RIGHTALT	12		/* Right Alt key */
#define	UPMASK		0x0080

/*
 * This defines the format of translation tables.
 *
 * A translation table is KEYMAP_SIZE "entries", each of which is 2 bytes
 * (unsigned shorts).  The top 8 bits of each entry are decoded by
 * a case statement in getkey.c.  If the entry is less than 0x100, it
 * is sent out as an EUC character (possibly with bucky bits
 * OR-ed in).  "Special" entries are 0x100 or greater, and
 * invoke more complicated actions.
 *
 * The KEYMAP_SIZE is dependent upon the keyboard type.  For example, the
 * Sun Type 4/5 keyboards have a KEYMAP_SIZE of 128 where a USB keyboard
 * has a KEYMAP_SIZE of 255.  Instead of defining a KEYMAP_SIZE per
 * keyboard type, a keyboard specific module/driver may supply the value
 * at run time by defining the KEYMAP_SIZE_VARIABLE and filling in the
 * keyboard struct appropriately.
 */

#ifdef KEYMAP_SIZE_VARIABLE

typedef unsigned short keymap_entry_t;

#else
#define	KEYMAP_SIZE	128

struct keymap {
	unsigned short	keymap[KEYMAP_SIZE];	/* maps keycodes to actions */
};

#endif

/*
 * This structure is used for "exception" cases for key sequences that
 * we want to map, that should not be handled by keymap entries (For
 * example: using Control-Shift-F1 on PC's for the compose key).
 */
struct exception_map {
	/*
	 * these are the modifier keys that we "care" about
	 */
	unsigned int exc_care;

	/*
	 * This is the mask of modifier keys that we want to match
	 */
	unsigned int exc_mask;

	/*
	 * This is the key that we want to match.
	 */
	int exc_key;

	/*
	 * This is our translated version of the matching sequence.
	 */
	unsigned short exc_entry;
};

/*
 * A keyboard is defined by its keymaps and what state it resets at idle.
 *
 * The masks k_idleshifts and k_idlebuckys are AND-ed with the current
 * state of  shiftmask	and  buckybits	when a "keyboard idle" code
 * is received.	 This ensures that where we "think" the shift & bucky
 * keys are, more accurately reflects where they really are, since the
 * keyboard knows better than us.  However, some keyboards don't know
 * about shift states that should be remembered across idles.  Such
 * shifts are described by k_toggleshifts.  k_toggleshifts are used to
 * identify such shifts.  A toggle shift state is maintained separately
 * from the general shift state.  The toggle shift state is OR-ed
 * with the state general shift state when an idle is received.
 * k_toggleshifts should not appear in the k_up table.
 */
struct keyboard {
#ifdef KEYMAP_SIZE_VARIABLE
	int		k_keymap_size;	/* Number of entries in keymaps */
	keymap_entry_t	*k_normal;	/* Unshifted */
	keymap_entry_t	*k_shifted;	/* Shifted */
	keymap_entry_t	*k_caps;	/* Caps locked */
	keymap_entry_t	*k_altgraph;	/* Alt Graph down */
	keymap_entry_t	*k_numlock;	/* Num Lock down */
	keymap_entry_t	*k_control;	/* Controlled */
	keymap_entry_t	*k_up;		/* Key went up */
#else
	struct keymap	*k_normal;	/* Unshifted */
	struct keymap	*k_shifted;	/* Shifted */
	struct keymap	*k_caps;	/* Caps locked */
	struct keymap	*k_altgraph;	/* Alt Graph down */
	struct keymap	*k_numlock;	/* Num Lock down */
	struct keymap	*k_control;	/* Controlled */
	struct keymap	*k_up;		/* Key went up */
#endif
	int		k_idleshifts;	/* Shifts that keep across idle */
	int		k_idlebuckys;	/* Bucky bits that keep across idle */
	unsigned char	k_abort1;	/* 1st key of abort sequence */
	unsigned char	k_abort1a;	/* alternate 1st key */
	unsigned char	k_abort2;	/* 2nd key of abort sequence */
	int		k_toggleshifts; /* Shifts that toggle on down from */
					/* kbd and keep across idle */
	struct exception_map *k_except;	/* Oddball cases */
	unsigned char	k_newabort1;	/* 1st key of new abort sequence */
	unsigned char	k_newabort1a;	/* alternate 1st key */
	unsigned char	k_newabort2;	/* 2nd key of new abort sequence */
};

/*
 * Define the compose sequence structure.  First and second
 * ASCII chars of 0 indicate the end of the table.
 */
struct compose_sequence_t {
	unsigned char	first;	/* first ASCII char after COMPOSE key */
	unsigned char	second; /* second ASCII char after COMPOSE key */
	unsigned char	iso;	/* equivalent ISO code */
};

/*
 * Define the floating accent sequence structure.
 */
struct fltaccent_sequence_t {
	unsigned short	fa_entry;	/* floating accent keymap entry */
	unsigned char	ascii;		/* ASCII char after FA-type key */
	unsigned char	iso;		/* equivalent ISO code */
};

/*
 * The "special" entries' top 4 bits are defined below.	 Generally they are
 * used with a 4-bit parameter (such as a bit number) in the low 4 bits.
 * The bytes whose top 4 bits are 0x0 thru 0x7 happen to be ascii
 * characters.	They are not special cased, but just normal cased.
 */

#define	SHIFTKEYS	0x100	/* thru 0x10F.	This key helps to determine */
				/* the translation table used.	The bit */
				/* position of its bit in "shiftmask" */
				/* is added to the entry, eg */
				/* SHIFTKEYS+LEFTCTRL.	When this entry is */
				/* invoked, the bit in "shiftmask" is */
				/* toggled.  Depending which tables you put */
				/* it in, this works well for hold-down */
				/* keys or press-on, press-off keys.  */
#define	BUCKYBITS	0x200	/* thru 0x20F.	This key determines the state */
				/* of one of the "bucky" bits above the */
				/* returned ASCII character.  This is */
				/* basically a way to pass mode-key-up/down */
				/* information back to the caller with each */
				/* "real" key depressed.  The concept, and */
				/* name "bucky" (derivation unknown) comes */
				/* from the MIT/SAIL "TV" system...they had */
				/* TOP, META, CTRL, and a few other bucky */
				/* bits.  The bit position of its bit in */
				/* "buckybits", minus 7, is added to the */
				/* entry; eg bit 0x00000400 is BUCKYBITS+3. */
				/* The "-7" prevents us from messing up the */
				/* ASCII char, and gives us 16 useful bucky */
				/* bits.  When this entry is invoked, */
				/* the designated bit in "buckybits" is */
				/* toggled.  Depending which tables you put */
				/* it in, this works well for hold-down */
				/* keys or press-on, press-off keys.  */
#define	FUNNY		0x300	/* thru 0x30F.	This key does one of 16 funny */
				/* things based on the low 4 bits: */
#define	NOP		0x300	/* This key does nothing. */
#define	OOPS		0x301	/* This key exists but is undefined. */
#define	HOLE		0x302	/* This key does not exist on the keyboard. */
				/* Its position code should never be */
				/* generated.  This indicates a software/ */
				/* hardware mismatch, or bugs. */
#define	RESET		0x306	/* Kbd was just reset */
#define	ERROR		0x307	/* Kbd just detected an internal error */
#define	IDLE		0x308	/* Kbd is idle (no keys down) */
#define	COMPOSE		0x309	/* This key is the Compose key. */
#define	NONL		0x30A	/* This key not affected by Num Lock */
/* Combinations 0x30B to 0x30F are reserved for non-parameterized functions */

#define	FA_CLASS	0x400	/* thru 0x40F.	These are for "floating */
				/* accent" characters.	The low-order 4 bits */
				/* select one of those characters. */
/* Definitions for the individual floating accents: */
#define	FA_UMLAUT	0x400	/* umlaut accent */
#define	FA_CFLEX	0x401	/* circumflex accent */
#define	FA_TILDE	0x402	/* tilde accent */
#define	FA_CEDILLA	0x403	/* cedilla accent */
#define	FA_ACUTE	0x404	/* acute accent */
#define	FA_GRAVE	0x405	/* grave accent */

#define	STRING		0x500	/* thru 0x50F.	The low-order 4 bits index */
				/* a table select a string to be returned, */
				/* char by char.  Each entry the table is */
				/* null terminated. */
#define	KTAB_STRLEN	10	/* Maximum string length (including null) */
/* Definitions for the individual string numbers: */
#define	HOMEARROW	0x00
#define	UPARROW		0x01
#define	DOWNARROW	0x02
#define	LEFTARROW	0x03
#define	RIGHTARROW	0x04
/* string numbers 5 thru F are available to users making custom entries */

/*
 * In the following function key groupings, the low-order 4 bits indicate
 * the function key number within the group, and the next 4 bits indicate
 * the group.
 */
#define	FUNCKEYS	0x600
#define	LEFTFUNC	0x600	/* thru 0x60F.	The "left" group. */
#define	RIGHTFUNC	0x610	/* thru 0x61F.	The "right" group. */
#define	TOPFUNC		0x620	/* thru 0x62F.	The "top" group. */
#define	BOTTOMFUNC	0x630	/* thru 0x63F.	The "bottom" group. */
#define	LF(n)		(LEFTFUNC+(n)-1)
#define	RF(n)		(RIGHTFUNC+(n)-1)
#define	TF(n)		(TOPFUNC+(n)-1)
#define	BF(n)		(BOTTOMFUNC+(n)-1)

/*
 * The actual keyboard positions may not be on the left/right/top/bottom
 * of the physical keyboard (although they usually are).
 * What is important is that we have reserved 64 keys for function keys.
 *
 * Normally, striking a function key will cause the following escape sequence
 * to be sent through the character stream:
 *	ESC[0..9z
 * where ESC is a single escape character and 0..9 indicate some number of
 * digits needed to encode the function key as a decimal number.
 */
#define	PADKEYS		0x700
#define	PADEQUAL	0x700		/* keypad = */
#define	PADSLASH	0x701		/* keypad / */
#define	PADSTAR		0x702		/* keypad * */
#define	PADMINUS	0x703		/* keypad - */
#define	PADSEP		0x704		/* keypad,  */
#define	PAD7		0x705		/* keypad 7 */
#define	PAD8		0x706		/* keypad 8 */
#define	PAD9		0x707		/* keypad 9 */
#define	PADPLUS		0x708		/* keypad + */
#define	PAD4		0x709		/* keypad 4 */
#define	PAD5		0x70A		/* keypad 5 */
#define	PAD6		0x70B		/* keypad 6 */
#define	PAD1		0x70C		/* keypad 1 */
#define	PAD2		0x70D		/* keypad 2 */
#define	PAD3		0x70E		/* keypad 3 */
#define	PAD0		0x70F		/* keypad 0 */
#define	PADDOT		0x710		/* keypad . */
#define	PADENTER	0x711		/* keypad Enter */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KBD_H */
