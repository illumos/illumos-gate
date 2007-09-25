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

#ifndef _SYS_KBIO_H
#define	_SYS_KBIO_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SunOS4.0 1.23 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Keyboard related ioctls
 */

/*
 * See sys/kbd.h for TR_NONE (don't translate) and TR_ASCII
 * (translate to ASCII) TR_EVENT (translate to virtual input
 * device codes)
 */
#define	KIOC		('k'<<8)

#if defined(__i386) || defined(__i386_COMPAT)

/*
 * For x86, these numbers conflict with KD "Xenix" ioctl numbers, so each
 * conflicting command has been offset by 30.
 */
#define	KIOCTRANS	(KIOC|30)	/* set keyboard translation */
#define	KIOCGTRANS	(KIOC|35)	/* get keyboard translation */
#define	KIOCTRANSABLE	(KIOC|36) 	/* set keyboard translatability */
#define	KIOCGTRANSABLE	(KIOC|37)	/* get keyboard translatability */

#else	/* __i386 || __i386_COMPAT */

#define	KIOCTRANS	(KIOC|0)	/* set keyboard translation */
#define	KIOCGTRANS	(KIOC|5)	/* get keyboard translation */
#define	KIOCTRANSABLE	(KIOC|6) 	/* set keyboard translatability */
#define	KIOCGTRANSABLE	(KIOC|7)	/* get keyboard translatability */

#endif	/* __i386 || __i386_COMPAT */


#define	TR_CANNOT	0	/* Cannot translate keyboard using tables */
#define	TR_CAN		1	/* Can translate keyboard using tables */

/*
 * Old-style keymap entry, for backwards compatibility only.
 */
struct	kiockey {
	int	kio_tablemask;	/* Translation table (one of: 0, CAPSMASK, */
				/* SHIFTMASK, CTRLMASK, UPMASK, */
				/* ALTGRAPHMASK, NUMLOCKMASK) */
#define	KIOCABORT1	-1	/* Special "mask": abort1 keystation */
#define	KIOCABORT2	-2	/* Special "mask": abort2 keystation */
#define	KIOCABORT1A	-3	/* Special "mask": alt abort1 keystation */
	uchar_t	kio_station;	/* Physical keyboard key station (0-127) */
	uchar_t	kio_entry;	/* Translation table station's entry */
	char	kio_string[10];	/* Value for STRING entries (null terminated) */
};

/*
 * Set kio_tablemask table's kio_station to kio_entry.
 * Copy kio_string to string table if kio_entry is between STRING and
 * STRING+15.  EINVAL is possible if there are invalid arguments.
 */
#if defined(__i386) || defined(__i386_COMPAT)
#define	KIOCSETKEY	(KIOC|31)	/* avoid conflict with "SETFKEY" */
#else
#define	KIOCSETKEY	(KIOC|1)
#endif

/*
 * Get kio_tablemask table's kio_station to kio_entry.
 * Get kio_string from string table if kio_entry is between STRING and
 * STRING+15.  EINVAL is possible if there are invalid arguments.
 */
#if defined(__i386) || defined(__i386_COMPAT)
#define	KIOCGETKEY	(KIOC|32)	/* avoid conflict with "GIO_SCRNMAP" */
#else
#define	KIOCGETKEY	(KIOC|2)
#endif

/*
 * Send the keyboard device a control command.  sys/kbd.h contains
 * the constants that define the commands.  Normal values are:
 * KBD_CMD_BELL, KBD_CMD_NOBELL, KBD_CMD_CLICK, KBD_CMD_NOCLICK.
 * Inappropriate commands for particular keyboard types are ignored.
 *
 * Since there is no reliable way to get the state of the bell or click
 * or LED (because we can't query the kdb, and also one could do writes
 * to the appropriate serial driver--thus going around this ioctl)
 * we don't provide an equivalent state querying ioctl.
 */
#define	KIOCCMD		(KIOC|8)

/*
 * Get keyboard type.  Return values are one of KB_* from sys/kbd.h,
 * e.g., KB_KLUNK, KB_VT100, KB_SUN2, KB_SUN3, KB_SUN4, KB_ASCII.
 * -1 means that the type is not known.
 */
#define	KIOCTYPE	(KIOC|9)	/* get keyboard type */

/*
 * Set flag indicating whether keystrokes get routed to /dev/console.
 */
#define	KIOCSDIRECT	(KIOC|10)

/*
 * Get flag indicating whether keystrokes get routed to /dev/console.
 */
#if defined(__i386) || defined(__i386_COMPAT)
#define	KIOCGDIRECT	(KIOC|41)	/* avoid conflict with "GIO_STRMAP" */
#else
#define	KIOCGDIRECT	(KIOC|11)
#endif

/*
 * New-style key map entry.
 */
struct kiockeymap {
	int	kio_tablemask;	/* Translation table (one of: 0, CAPSMASK, */
				/*  SHIFTMASK, CTRLMASK, UPMASK, */
				/*  ALTGRAPHMASK) */
	uchar_t	kio_station;	/* Physical keyboard key station (0-127) */
	ushort_t kio_entry;	/* Translation table station's entry */
	char	kio_string[10];	/* Value for STRING entries (null terminated) */
};

/*
 * Set kio_tablemask table's kio_station to kio_entry.
 * Copy kio_string to string table if kio_entry is between STRING and
 * STRING+15.  EINVAL is possible if there are invalid arguments.
 */
#if defined(__i386) || defined(__i386_COMPAT)
#define	KIOCSKEY	(KIOC|42)	/* avoid conflict with "PIO_STRMAP" */
#else
#define	KIOCSKEY	(KIOC|12)
#endif

/*
 * Get kio_tablemask table's kio_station to kio_entry.
 * Get kio_string from string table if kio_entry is between STRING and
 * STRING+15.  EINVAL is possible if there are invalid arguments.
 */
#define	KIOCGKEY	(KIOC|13)

/*
 * Set and get LED state.
 */
#define	KIOCSLED	(KIOC|14)
#define	KIOCGLED	(KIOC|15)

/*
 * Set and get compatibility mode.
 */
#define	KIOCSCOMPAT	(KIOC|16)
#define	KIOCGCOMPAT	(KIOC|17)

/*
 * Set and get keyboard layout.
 */
#define	KIOCSLAYOUT	(KIOC|19)
#define	KIOCLAYOUT	(KIOC|20)

/*
 * KIOCSKABORTEN:
 *
 * Enable/Disable/Alternate Keyboard abort effect (Stop/A, Break or other seq).
 * The argument is a pointer to an integer.  If the integer is zero,
 * keyboard abort is disabled, one will enable keyboard abort (hardware BREAK
 * signal), two will revert to the Alternative Break Sequence.  NB: This ioctl
 * requires root credentials and applies to serial input devices and keyboards.
 * When the Alternative Break Sequence is enabled it applies to serial input
 * devices ONLY.
 */
#define	KIOCSKABORTEN	(KIOC|21)

#define	KIOCABORTDISABLE	0	/* Disable Aborts  */
#define	KIOCABORTENABLE		1	/* Enable BREAK Signal Aborts  */
#define	KIOCABORTALTERNATE	2	/* Enable Alternative Aborts   */

/*
 * Get/Set Keyboard autorepeat delay/rate.
 * Use millisecond as unit used by the user-level application
 */
#define	KIOCGRPTDELAY	(KIOC|22)
#define	KIOCSRPTDELAY	(KIOC|23)
#define	KIOCGRPTRATE	(KIOC|24)
#define	KIOCSRPTRATE	(KIOC|25)

/* Set keyboard and console beeper frequencies */
#define	KIOCSETFREQ	(KIOC|26)

/* Beeper type for struct freq_request */
enum fr_beep_type {CONSOLE_BEEP = 1, KBD_BEEP = 2};

/* Frequency request structure */
struct freq_request {
	enum fr_beep_type type;	/* Beeper type */
	int16_t	freq;		/* Frequency */
};

#define	KIOCMKTONE	(KIOC|27)

/*
 * For historical reasons, the frequency argument to KIOCMKTONE is
 * in i8254 clock cycles.
 */

#define	PIT_HZ		1193182		/* 8254's cycles per second */

#define	KDMKTONE	KIOCMKTONE

/* Used to control the AutoRepeat Min-delay and Min-Rate */
#define	KIOCRPTDELAY_MIN	(100)
#define	KIOCRPTRATE_MIN		(1)

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_KBIO_H */
