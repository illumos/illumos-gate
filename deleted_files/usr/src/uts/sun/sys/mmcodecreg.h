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

#ifndef _SYS_MMCODECREG_H
#define	_SYS_MMCODECREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MMCODEC - Multi-Media Codec operates over the CHI bus and interfaces
 * with DBRI.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Data Mode timeslot structure
 */
typedef union {
	struct {
		/* time slot 5 */
		unsigned char
		    om1:1,	/* analog output line 1 control */
		    om0:1,	/* output line 0 control */
		    lo:6;	/* left channel output attenuation */

		/* time slot 6 */
		unsigned char
		    :1,
		    sm:1,	/* speaker mute */
		    ro:6;	/* right channel output attenuation */

		/* time slot 7 */
		unsigned char
		    pio:2,	/* parallel input/output bits */
		    ovr:1,	/* overrange */
		    is:1,	/* line/microphone input selection */
		    lg:4;	/* left channel input gain */

		/* time slot 8 */
		unsigned char
		    ma:4,	/* monitor attenutation */
		    rg:4;	/* right channel input gain */
	} r;

	ushort_t word16[2];	/* short-word access */

	uint_t word32;		/* word access */
} mmcodec_data_t;


/*
 * Time Slot 5 data mode bit defines
 */
#define	MMCODEC_OM0_ENABLE	0x1	/* Output Line 0 On */
#define	MMCODEC_OM1_ENABLE	0x1	/* Output Line 1 On */
#define	MMCODEC_MIN_ATEN	(0)	/* Minimum attenuation */
#define	MMCODEC_MAX_ATEN	(31)	/* Maximum usable attenuation */
#define	MMCODEC_MAX_DEV_ATEN	(63)	/* Maximum device attenuation */

/*
 * Time Slot 6 data mode bit defines
 */
#define	MMCODEC_SM		0x1		/* 1 is enabled, 0 is muted */

/*
 * Time Slot 7 data mode bit defines
 */
#define	MMCODEC_OVR_CLR		0x0		/* Clear ovr condition (wt) */
#define	MMCODEC_OVR		0x1		/* Overrange occurred (rd) */
#define	MMCODEC_IS_LINE		0x0		/* Line level input select */
#define	MMCODEC_IS_MIC		0x1		/* Microphone input select */
#define	MMCODEC_MIN_GAIN	(0)
#define	MMCODEC_MAX_GAIN	(15)

/*
 * Time Slot 8 data mode bit defines
 */
#define	MMCODEC_MA_MIN_ATEN	(0)
#define	MMCODEC_MA_MAX_ATEN	(15)

/*
 * Control Mode timeslot structure
 */
typedef union {
	struct {
		/* time slot 1 */
		unsigned char
		    :3,
		    mb:1,
		    vs1:1,	/* Vendor-Specific bit */
		    dcb:1,	/* Data control handshake bit */
		    sre:1,	/* Shadow register enable */
		    vs0:1;	/* Auto calibration bit */

		/* time slot 2 */
		unsigned char
		    hpf:1,	/* High Pass Filter in revE or higher */
		    :1,
		    dfr:3,	/* Data conversion frequency */
		    st:1,	/* Stereo bit */
		    df:2;	/* Data format selection */

		/* time slot 3 */
		unsigned char
		    :2,
		    mck:2,	/* Clock source select */
		    bsel:2,	/* Bit rate select */
		    xclk:1,	/* Transmit clock select */
		    xen:1;	/* Transmitter enable */

		/* time slot 4 */
		unsigned char
		    :6,
		    enl:1,	/* Enable loopback testing */
		    adl:1;	/* Analog/Digital loopback */

		/* time slot 5 */
		unsigned char
		    pio:2,	/* Parallel input/output lines */
		    :6;

		/* time slot 6 */
		unsigned char
		    :8;		/* reserved */

		/* time slot 7 */
		unsigned char
		    manufacturer:4, /* Manufacturer identification */
		    revision:4;	/* Revision level of Codec */

		/* time slot 8 */
		unsigned char
		    :8;		/* reserved */
	} r;

	ushort_t word16[4];	/* short-word access */

	uint_t word32[2];	/* word access */
} mmcodec_ctrl_t;


/*
 * Time Slot 1 control mode bit defines
 */
#define	MMCODEC_DCB		0x1		/* Data control handshake */
#define	MMCODEC_SRE		0x1		/* Shadow register enable */
#define	MMCODEC_VS0		0x0
#define	MMCODEC_VS1		0x1


/*
 * Time Slot 2 data frequency rate bit defines
 */
#define	MMCODEC_DFR_8000	0x0
#define	MMCODEC_DFR_5513	0x0
#define	MMCODEC_DFR_16000	0x1
#define	MMCODEC_DFR_11025	0x1
#define	MMCODEC_DFR_27429	0x2
#define	MMCODEC_DFR_18900	0x2
#define	MMCODEC_DFR_32000	0x3
#define	MMCODEC_DFR_22050	0x3
#define	MMCODEC_DFR_37800	0x4
#define	MMCODEC_DFR_44100	0x5
#define	MMCODEC_DFR_48000	0x6
#define	MMCODEC_DFR_33075	0x6
#define	MMCODEC_DFR_9600	0x7
#define	MMCODEC_DFR_6615	0x7

#define	MMCODEC_ST_MONO		0x0		/* Mono mode */
#define	MMCODEC_ST_STEREO	0x1		/* Stereo mode */

#define	MMCODEC_DF_16_BIT	0x0		/* Data format 16 bit linear */
#define	MMCODEC_DF_ULAW		0x1		/* Data format 8 bit u-law */
#define	MMCODEC_DF_ALAW		0x2		/* Data format 8 bit A-law */


/*
 * Time Slot 3 master clock bit defines
 */
#define	MMCODEC_MCK_MSTR	0x0		/* SCLK is master clock */
#define	MMCODEC_MCK_XTAL1	0x1		/* Crystal 1 24.576 MHz */
#define	MMCODEC_MCK_XTAL2	0x2		/* Crystal 2 16.9344 MHz */
#define	MMCODEC_MCK_EXT		0x3		/* External clock source */

#define	MMCODEC_BSEL_64		0x0		/* 64 bits per frame */
#define	MMCODEC_BSEL_128	0x1		/* 128 bits per frame */
#define	MMCODEC_BSEL_256	0x2		/* 256 bits per frame */

#define	MMCODEC_XCLK		0x1		/* Xmit clock and frame sync */

#define	MMCODEC_XEN		0x0		/* enable serial data output */


/*
 * Time Slot 4 loopback bit defines
 */
#define	MMCODEC_ENL		0x1		/* Enable loopback testing */
#define	MMCODEC_ADL_DIG		0x0		/* Digital loopback mode */
#define	MMCODEC_ADL_ANLG	0x1		/* Analog loopback mode */

/*
 * General MMCODEC defines
 */
#define	MMCODEC_LEN		256		/* 256 bits/frame */

/* XXX - This potentially belongs in something like dbri_sun_chi.h or ... */
#define	SCHI_SET_DATA_MODE	DBRI_PIO_3
#define	SCHI_SET_CTRL_MODE	(0 << 3)
#define	SCHI_SET_INT_PDN	DBRI_PIO_2
#define	SCHI_CLR_INT_PDN	(0 << 2)
#define	SCHI_SET_RESET		(0 << 1)
#define	SCHI_CLR_RESET		DBRI_PIO_1
#define	SCHI_SET_PDN		DBRI_PIO_0
#define	SCHI_CLR_PDN		(0)

#define	SCHI_ENA_MODE		DBRI_PIO3_EN
#define	SCHI_ENA_INT_PDN	DBRI_PIO2_EN
#define	SCHI_ENA_RESET		DBRI_PIO1_EN
#define	SCHI_ENA_PDN		DBRI_PIO0_EN
#define	SCHI_ENA_ALL		(0xF0)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MMCODECREG_H */
