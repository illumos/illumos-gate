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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_VUID_EVENT_H
#define	_SYS_VUID_EVENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/types32.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file describes a virtual user input device (vuid) interface.  This
 * is an interface between input devices and their clients.  The interface
 * defines an idealized user input device that may not correspond to any
 * existing physical collection of input devices.
 *
 * It is targeted to input devices that gather command data from humans,
 * e.g., mice, keyboards, tablets, joysticks, light pens, knobs, sliders,
 * buttons, ascii terminals, etc.  The vuid interface is specifically not
 * designed to support input devices that produce voluminous amounts of
 * data, e.g., input scanners, disk drives, voice packets.
 *
 * Here are some of the properties that are expected of a typical client
 * of vuid:
 *
 *	The client has a richer user interface than can be supported by
 *	a simple ascii terminal.
 *
 *	The client serializes multiple input devices being used
 *	by the user into a single stream of events.
 *
 *	The client preserves the entire state of its input so that
 *	it may query this state.
 *
 * Here are some features that vuid provides to its clients:
 *
 *	A client may extend the capabilities of the predefined vuid by
 *	adding input devices.  A client wants to be able to do this in
 *	a way that fits smoothly with its existing input paradigm.
 *
 *	A client can write its code to be input device independent.  A
 *	client can replace the underlaying physical devices and not
 *	have to be concerned.  In fact, the vuid interface doesn't
 *	really care about physical devices.  One physical device can
 *	masquerade a many logical devices and many physical devices can
 *	look like a single logical device.
 *
 * This file defines the protocol that makes up the virtual user input
 * device.  This includes:
 *
 *	The vuid station codes and there meanings.
 *
 *	The form by which changes to vuid stations, i.e., firm events,
 *	are communicated to clients (typically via the read system
 *	call).
 *
 *	The form by which clients send commands to input devices that
 *	support the vuid (typically via an ioctl system call to send
 *	vuid instead of a native byte stream).
 *
 * Explicitly, this file does not define:
 *
 *	How to store the state of the vuid
 *	(see ../sunwindowdev/vuid_state.h).
 *
 *	How to dynamically allocate additional vuid segments in order
 *	to extend the vuid (one could statically allocate additional
 *	vuid segments by treating this file as the central registry
 *	of vuid segments).
 */

/*
 * VUID_SEG_SIZE is the size of a virtual user input "device" address space
 * segment.
 */
#define	VUID_SEG_SIZE	(256)

/*
 * This is the central registry of virtual user input devices.
 * To allocate a new vuid:
 *
 *	o Choose an unused portion of the address space.
 *	  Vuids from 0x00 to 0x7F are reserved for Sun implementers.
 *	  Vuids from 0x80 to 0xFF are reserved for Sun customers.
 *
 *	o Note the new device with a *_DEVID define.  Breifly describe
 *	  the purpose/usage of the device.  Point to the place where
 *	  more information can be found.
 *
 *	o Note the new device with a VUID_* entry in the Vuid_device
 *	  enumeration.
 *
 *	o List the specific event codes in another header file that is
 *	  specific to the new device (ASCII_DEVID, TOP_DEVID &
 *	  WORKSTATION_DEVID events are listing here for historical
 *	  reasons).
 */

#define	ASCII_DEVID		0x00
	/* Ascii codes, which include META codes and 8-bit EUC codes */
	/* (see below) */
#define	TOP_DEVID		0x01
	/* Top codes, which is ASCII with the 9th bit on (see below) */
#define	ISO_DEVID		0x02
	/* ISO characters 0x80 - 0xFF (backwards compatibility) */
/* ... Sun implementers add new device ids here ... */
#define	WHEEL_DEVID		0x78
#define	LIGHTPEN_DEVID		0x79
	/* Lightpen events for	Lightpen */
#define	BUTTON_DEVID		0x7A
	/* Button events from Sun button box */
#define	DIAL_DEVID		0x7B
	/* Dial events from Sun dial box */
#define	SUNVIEW_DEVID		0x7C
	/* Sunview Semantic events */
#define	PANEL_DEVID		0x7D
	/* Panel subwindow package event codes passed around internal */
	/* to the panel package (see <suntool/panel.h>) */
#define	SCROLL_DEVID		0x7E
	/* Scrollbar package event codes passed to scrollbar clients on */
	/* interesting scrollbar activity (see <suntool/scrollbar.h>) */
#define	WORKSTATION_DEVID	0x7F
	/* Virtual keyboard and locator (mouse) related event codes */
	/* that describe a basic "workstation" device collection (see below). */
	/* This device is a bit of a hodge podge for historical reasons; */
	/* the middle of the address space has SunWindows related events */
	/* in it (see <sunwindow/win_input.h >), and the virtual keyboard */
	/* and virtual locator are thrown together. */
/* ... Sun customers add new device ids here ... */
#define	LAST_DEVID		0xFF
	/* No more device ids beyond LAST_DEVID */

typedef enum vuid_device {
	VUID_ASCII = ASCII_DEVID,
	VUID_TOP = TOP_DEVID,
	VUID_ISO = ISO_DEVID,
	VUID_WHEEL = WHEEL_DEVID,
	VUID_LIGHTPEN = LIGHTPEN_DEVID,
	VUID_DIAL = DIAL_DEVID,
	VUID_SUNVIEW = SUNVIEW_DEVID,
	VUID_PANEL = PANEL_DEVID,
	VUID_SCROLL = SCROLL_DEVID,
	VUID_WORKSTATION = WORKSTATION_DEVID,
	VUID_LAST = LAST_DEVID
} Vuid_device;

#define	vuid_first(devid)	((devid) << 8)
#define	vuid_last(devid)	(((devid) << 8)+VUID_SEG_SIZE-1)
#define	vuid_in_range(devid, id) \
	    ((id >= vuid_first(devid)) && (id <= vuid_last(devid)))

/*
 * EUC (Extended UNIX Code) device related definitions:
 */
#define	EUC_FIRST	(0)
#define	EUC_LAST	(255)

/*
 * Old ASCII definitions for backwards compatibility:
 */
#define	ASCII_FIRST	(0)
#define	ASCII_LAST	(127)
#define	META_FIRST	(128)
#define	META_LAST	(255)

/*
 * Top device related definitions:
 */
#define	TOP_FIRST	(256)
#define	TOP_LAST	(511)

/*
 * Old ISO definitions for backwards compatibility:
 */
#define	ISO_FIRST	(512)
#define	ISO_LAST	(767)

/*
 * Workstation device related definitions.  First are virtual keyboard
 * assignments.	 All events for the virtual keyboard have 0 (went up) or
 * 1 (went down) values.
 */

#define	VKEY_FIRST	vuid_first(WORKSTATION_DEVID)
#define	VKEY_UP		0
#define	VKEY_DOWN	1

#define	VKEY_KBD_CODES	(128)	/* The number of event codes in a subset of */
				/* the workstation device's address space */
				/* that belong to the virtual keyboard */

#define	VKEY_FIRSTPSEUDO	(VKEY_FIRST)			/* 32512 */
/*
 * VKEY_FIRSTPSEUDO thru VKEY_LASTPSEUDO are taken (for historical
 * reasons) by SunWindows related codes (see <sunwindow/win_input.h >).
 */
#define	VKEY_LASTPSEUDO		(VKEY_FIRSTPSEUDO+15)		/* 32527 */

#define	VKEY_FIRSTSHIFT		(VKEY_LASTPSEUDO+1)		/* 32528 */
#define	SHIFT_CAPSLOCK		(VKEY_FIRSTSHIFT+0)		/* 32528 */
#define	SHIFT_LOCK		(VKEY_FIRSTSHIFT+1)		/* 32529 */
#define	SHIFT_LEFT		(VKEY_FIRSTSHIFT+2)		/* 32530 */
#define	SHIFT_RIGHT		(VKEY_FIRSTSHIFT+3)		/* 32531 */
#define	SHIFT_LEFTCTRL		(VKEY_FIRSTSHIFT+4)		/* 32532 */
/* SHIFT_CTRL is for compatability with previous releases */	/* 32532 */
#define	SHIFT_CTRL		SHIFT_LEFTCTRL			/* 32532 */
#define	SHIFT_RIGHTCTRL		(VKEY_FIRSTSHIFT+5)		/* 32533 */
#define	SHIFT_META		(VKEY_FIRSTSHIFT+6)		/* 32534 */
#define	SHIFT_TOP		(VKEY_FIRSTSHIFT+7)		/* 32535 */
#define	SHIFT_CMD		(VKEY_FIRSTSHIFT+8)		/* 32536 */
#define	SHIFT_ALTG		(VKEY_FIRSTSHIFT+9)		/* 32537 */
#define	SHIFT_ALT		(VKEY_FIRSTSHIFT+10)		/* 32538 */
#define	SHIFT_NUMLOCK		(VKEY_FIRSTSHIFT+11)		/* 32539 */
#define	VKEY_LASTSHIFT		(VKEY_FIRSTSHIFT+15)		/* 32543 */

#define	VKEY_FIRSTFUNC		(VKEY_LASTSHIFT+1)		/* 32544 */

#define	BUT_FIRST		(VKEY_FIRSTFUNC)		/* 32544 */
#define	BUT(i)			((BUT_FIRST)+(i)-1)		/* 32544+i-1 */
#define	BUT_LAST		(BUT_FIRST+9)			/* 32553 */

#define	KEY_LEFTFIRST		((BUT_LAST)+1)			/* 32554 */
#define	KEY_LEFT(i)		((KEY_LEFTFIRST)+(i)-1)		/* 32554+i-1 */
#define	KEY_LEFTLAST		((KEY_LEFTFIRST)+15)		/* 32569 */

#define	KEY_RIGHTFIRST		((KEY_LEFTLAST)+1)		/* 32570 */
#define	KEY_RIGHT(i)		((KEY_RIGHTFIRST)+(i)-1)	/* 32570+i-1 */
#define	KEY_RIGHTLAST		((KEY_RIGHTFIRST)+15)		/* 32585 */

#define	KEY_TOPFIRST		((KEY_RIGHTLAST)+1)		/* 32586 */
#define	KEY_TOP(i)		((KEY_TOPFIRST)+(i)-1)		/* 32586+i-1 */
#define	KEY_TOPLAST		((KEY_TOPFIRST)+15)		/* 32601 */

#define	KEY_BOTTOMLEFT		((KEY_TOPLAST)+1)		/* 32602 */
#define	KEY_BOTTOMRIGHT		((KEY_BOTTOMLEFT)+1)		/* 32603 */
#define	KEY_BOTTOMFIRST		((KEY_TOPLAST)+1)		/* 32602 */
#define	KEY_BOTTOM(i)		((KEY_BOTTOMFIRST)+(i)-1)	/* 32602+i-1 */
#define	KEY_BOTTOMLAST		((KEY_BOTTOMFIRST)+15)		/* 32617 */

#define	VKEY_LASTFUNC		(VKEY_FIRSTFUNC+73)		/* 32617 */

#define	VKEY_FIRSTPAD		(VKEY_LASTFUNC+1)		/* 32618 */

#define	VKEY_PADEQUAL		(VKEY_FIRSTPAD+0)		/* 32618 */
#define	VKEY_PADSLASH		(VKEY_FIRSTPAD+1)		/* 32619 */
#define	VKEY_PADSTAR		(VKEY_FIRSTPAD+2)		/* 32620 */
#define	VKEY_PADMINUS		(VKEY_FIRSTPAD+3)		/* 32621 */
#define	VKEY_PADSEP		(VKEY_FIRSTPAD+4)		/* 32622 */
#define	VKEY_PAD7		(VKEY_FIRSTPAD+5)		/* 32623 */
#define	VKEY_PAD8		(VKEY_FIRSTPAD+6)		/* 32624 */
#define	VKEY_PAD9		(VKEY_FIRSTPAD+7)		/* 32625 */
#define	VKEY_PADPLUS		(VKEY_FIRSTPAD+8)		/* 32626 */
#define	VKEY_PAD4		(VKEY_FIRSTPAD+9)		/* 32627 */
#define	VKEY_PAD5		(VKEY_FIRSTPAD+10)		/* 32628 */
#define	VKEY_PAD6		(VKEY_FIRSTPAD+11)		/* 32629 */
#define	VKEY_PAD1		(VKEY_FIRSTPAD+12)		/* 32630 */
#define	VKEY_PAD2		(VKEY_FIRSTPAD+13)		/* 32631 */
#define	VKEY_PAD3		(VKEY_FIRSTPAD+14)		/* 32632 */
#define	VKEY_PAD0		(VKEY_FIRSTPAD+15)		/* 32633 */
#define	VKEY_PADDOT		(VKEY_FIRSTPAD+16)		/* 32634 */
#define	VKEY_PADENTER		(VKEY_FIRSTPAD+17)		/* 32635 */

#define	VKEY_LASTPAD		(VKEY_FIRSTPAD+17)		/* 32635 */

#define	VKEY_LAST		(VKEY_FIRST+VKEY_KBD_CODES-1)	/* 32639 */

/*
 * More workstation device definitions.	 These are virtual locator
 * related event code assignments.  Values for these events are int.
 * VLOC_BATCH's value is a uint_t that describes the number of events
 * that follow that should be treated as a batch.
 */
#define	MOUSE_DEVID	WORKSTATION_DEVID	/* Backward compatibility */

#define	VLOC_FIRST		(VKEY_LAST+1)			/* 32640 */
#define	LOC_FIRST_DELTA		(VLOC_FIRST+0)			/* 32640 */
#define	LOC_X_DELTA		(VLOC_FIRST+0)			/* 32640 */
#define	LOC_Y_DELTA		(VLOC_FIRST+1)			/* 32641 */
#define	LOC_LAST_DELTA		(VLOC_FIRST+1)			/* 32641 */

#define	LOC_FIRST_ABSOLUTE	(VLOC_FIRST+2)			/* 32642 */
#define	LOC_X_ABSOLUTE		(VLOC_FIRST+2)			/* 32642 */
#define	LOC_Y_ABSOLUTE		(VLOC_FIRST+3)			/* 32643 */
#define	LOC_LAST_ABSOLUTE	(VLOC_FIRST+3)			/* 32643 */

#define	VLOC_BATCH		(VLOC_FIRST+4)			/* 32644 */
#define	VLOC_LAST		(VLOC_BATCH+1)			/* 32645 */

#define	MOUSE_CAP_CHANGE_FIRST		(VLOC_LAST+1)		/* 32646 */
#define	MOUSE_CAP_CHANGE_NUM_BUT	(MOUSE_CAP_CHANGE_FIRST+0) /* 32646 */
#define	MOUSE_CAP_CHANGE_NUM_WHEEL	(MOUSE_CAP_CHANGE_FIRST+1) /* 32647 */

#define	MOUSE_TYPE_ABSOLUTE	(VLOC_LAST+3)			/* 32648 */

#define	MOUSE_LAST		(VLOC_LAST+3)			/* 32648 */
#define	KEYBOARD_LAYOUT_CHANGE	(MOUSE_LAST+1)			/* 32649 */

/*
 * Common names for certain input codes.  The buttons on the physical
 * mouse are thought to actually belong to the virtual keyboard.
 */
#define	MS_LEFT		BUT(1)					/* 32544 */
#define	MS_MIDDLE	BUT(2)					/* 32545 */
#define	MS_RIGHT	BUT(3)					/* 32546 */

/*
 * A firm_event structure is encoded in the byte stream of a device
 * when the device has been asked to format its byte stream so.
 * The time stamp is not defined to be meaningful except to compare
 * with other Firm_event time stamps.
 *
 * The pair field is critical for a state maintainence package
 * (such as vuid_state.h), one that is designed to not know anything
 * about the semantics of particular events, to maintain correct data
 * for corresponding absolute, delta and paired state variables.
 *
 * pair, when defined (as indicated by pair_type), is the associated
 * state variable that should be updated due to this events generation.
 * This is used to maintain a correspondence between an event that is a
 * delta and a state that is an absolute value (with a known delta event
 * defined) and visa versa, e.g., LOC_X_DELTA & LOC_X_ABSOLUTE.
 * pair is also used to indicate another state variable that
 * should be updated with the occurrence of this event, e.g., if id is
 * '^G' then pair could be 'g' or 'G' depending on the state of the shift
 * key.
 */
typedef struct firm_event {
	ushort_t	id;	/* Event's unique id */
	uchar_t		pair_type;	/* Event pair's type */
#define	FE_PAIR_NONE		0	/* pair is not defined */
#define	FE_PAIR_SET		1	/* pair is accompanying id to set */
					/* to this events value */
#define	FE_PAIR_DELTA		2	/* pair is accompanying id that */
					/* should be set to the delta of */
					/* id's current value and the new */
					/* value indicated by this event */
#define	FE_PAIR_ABSOLUTE	3	/* pair is accompanying id that */
					/* should be set to the sum of its */
					/* current value and the delta */
					/* indicated by this event's value */
	uchar_t		pair;	/* Event id's associated delta|absolute|pair */
				/* offset within id's segment (minus id's */
				/* address) */
	int		value;	/* Event's value */
#if defined(_LP64) || defined(_I32LPx)
	struct timeval32 time;	/* Event's time stamp */
#else
	struct timeval time;
#endif
} Firm_event;
#define	FIRM_EVENT_NULL ((Firm_event *)0)
#define	vuid_id_addr(id)		((id) & 0xFF00)
#define	vuid_id_offset(id)		((id) & 0xFF)
#define	vuid_boolean_value(value)	(((value) == 0) || ((value) == 1))
#define	vuid_int_value(value)		(!(vuid_boolean_value((value))))

/*
 * Ioctls to input devices that support vuid.
 */

/*
 * VUID*FORMAT ioctls are used to control which byte stream format that
 * a input device should use.  An errno of ENOTTY or EINVAL indicates that
 * a device can't speak Firm_events.
 */
#define	VUIOC		('v'<<8)
#if defined(__i386) || defined(__i386_COMPAT)
#define	VUIDSFORMAT   (VUIOC|11) /* avoid conflict with VT_?????? */
#define	VUIDGFORMAT   (VUIOC|12) /* avoid conflict with VT_?????? */
#else
#define	VUIDSFORMAT   (VUIOC|1) /* Set input device byte stream format */
#define	VUIDGFORMAT   (VUIOC|2) /* Get input device byte stream format */
#endif
#define	VUID_NATIVE	0	/* Native byte stream format */
#define	VUID_FIRM_EVENT 1	/* struct firm_event byte stream format */

/*
 * VUID*ADDR ioctls are used to control which address a particular
 * virtual input device segment has.  This is used to have an instancing
 * capability, e.g., a second mouse.  An errno of ENOTTY indicates that
 * a device can't deal with these commands.  An errno of ENODEV indicates
 * that the requested virtual device has no events generated for it by
 * this physical device.
 *
 * VUIDSADDR sets the virtual input device segment address indicated by
 * default to next.
 *
 * VUIDGADDR gets the in force address of the virtual input device segment
 * indicated by default into current.
 */
typedef struct	vuid_addr_probe {
	short	base;		/* default vuid device addr directed too */
	union	{
		short	next;	/* next addr for default when VUIDSADDR */
		short	current; /* current addr of default when VUIDGADDR */
	} data;
} Vuid_addr_probe;

#if defined(__i386) || defined(__i386_COMPAT)
#define	VUIDSADDR   (VUIOC|13)	/* avoid conflict with VT_?????? */
#define	VUIDGADDR   (VUIOC|14)	/* avoid conflict with VT_?????? */
#else
#define	VUIDSADDR   (VUIOC|3)	/* Set vuid address */
#define	VUIDGADDR   (VUIOC|4)	/* Get vuid address */
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_VUID_EVENT_H */
