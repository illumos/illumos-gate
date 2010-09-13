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

#ifndef _BOOT_KEYBOARD_TABLE_H
#define	_BOOT_KEYBOARD_TABLE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Structure of the keyboard table for the bootstrap simple
 * keyboard driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	KBTYPE_NORMAL	0x000	/* Normal keys, process mindlessly. */
#define	KBTYPE_ALPHA	0x100	/* Alpha.  If CapsLock is set, swap */
				/* shifted and unshifted meanings. */
				/* Set this on the unshifted character */
#define	KBTYPE_NUMPAD	0x200	/* Numeric/Arrow Pad.  If NumLock is set, */
				/* swap shifted and unshifted meanings. */
				/* Set this on the unshifted character. */
#define	KBTYPE_FUNC	0x300	/* Extended Function.  Send this code, */
				/* prefixed with zero. */
#define	KBTYPE_SPEC	0x400	/* One-of-a-kind codes.  Self-explanatory. */
#define	KBTYPE_SPEC_NOP			(KBTYPE_SPEC | 0x00)
#define	KBTYPE_SPEC_UNDEF		(KBTYPE_SPEC | 0x01)
#define	KBTYPE_SPEC_LSHIFT		(KBTYPE_SPEC | 0x02)
#define	KBTYPE_SPEC_RSHIFT		(KBTYPE_SPEC | 0x03)
#define	KBTYPE_SPEC_CTRL		(KBTYPE_SPEC | 0x04)
#define	KBTYPE_SPEC_ALT			(KBTYPE_SPEC | 0x05)
#define	KBTYPE_SPEC_CAPS_LOCK		(KBTYPE_SPEC | 0x06)
#define	KBTYPE_SPEC_NUM_LOCK		(KBTYPE_SPEC | 0x07)
#define	KBTYPE_SPEC_SCROLL_LOCK		(KBTYPE_SPEC | 0x08)
#define	KBTYPE_SPEC_MAYBE_REBOOT	(KBTYPE_SPEC | 0x09)

struct keyboard_translate {
	unsigned short normal;
	unsigned short shifted;
	unsigned short ctrled;
	unsigned short alted;
};

extern struct keyboard_translate keyboard_translate[128];

#ifdef __cplusplus
}
#endif

#endif /* _BOOT_KEYBOARD_TABLE_H */
