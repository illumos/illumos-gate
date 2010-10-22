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

#ifndef _SYS_USB_MIXER_H
#define	_SYS_USB_MIXER_H



#ifdef __cplusplus
extern "C" {
#endif

#define	USB_AUDIO_MIXER_REGISTRATION	1

/* Valid for the current alternate */
typedef struct usb_audio_formats {
	uchar_t		fmt_alt;	/* current alternate */
	uchar_t		fmt_chns;	/* 1-255 */
	uchar_t		fmt_precision;	/* 8, 16, 24, or 32 */
	uchar_t		fmt_encoding;	/* AUDIO_ENCODING_LINEAR, etc. */
	uchar_t		fmt_termlink;	/* for feature unit */
	uchar_t		fmt_n_srs;	/* number of sample rates */
	uint_t		*fmt_srs;	/* same as alt_sample_rates */
} usb_audio_formats_t;

_NOTE(SCHEME_PROTECTS_DATA("unshared", usb_audio_formats))


typedef struct usb_audio_play_req {
	int 		up_samples;
	void		*up_handle;
} usb_audio_play_req_t;

#define	USB_AS_N_FORMATS	20

typedef struct usb_as_registration {
	uchar_t			reg_valid;
	uchar_t			reg_mode;	/* play or record */
	uchar_t			reg_n_formats;
	int			reg_ifno;
	usb_audio_formats_t	reg_formats[USB_AS_N_FORMATS];
} usb_as_registration_t;

/* MCTLs between usb_ac and usb_as */
#define	USB_AUDIO_SETUP			0x0100
#define	USB_AUDIO_TEARDOWN		0x0200
#define	USB_AUDIO_START_PLAY		0x0300
#define	USB_AUDIO_STOP_PLAY		0x0400
#define	USB_AUDIO_PAUSE_PLAY		0x0500
#define	USB_AUDIO_START_RECORD		0x0600
#define	USB_AUDIO_STOP_RECORD		0x0700
#define	USB_AUDIO_SET_FORMAT		0x0800
#define	USB_AUDIO_SET_SAMPLE_FREQ	0x0900

/* MCTLs between usb_ac and usb_ah */
#define	USB_AUDIO_VOL_CHANGE		0x1
#define	USB_AUDIO_BALANCE		0x2
#define	USB_AUDIO_MUTE			0x3
#define	USB_AUDIO_BASS			0x4
#define	USB_AUDIO_TREBLE		0x5

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_USB_MIXER_H */
