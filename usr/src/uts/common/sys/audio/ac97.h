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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * CAUTION: This header file has not gone through a formal review process.
 *	Thus its commitment level is very low and may change or be removed
 *	at any time.
 */

#ifndef	_SYS_AC97_H
#define	_SYS_AC97_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * This header file describes the AC-97 V2.1 Codec register set. See the
 * spec for a detailed description of each register.
 */

struct ac97_v21 {
	uint16_t	ac97_reset;			/* 00h */
	uint16_t	ac97_master_volume;		/* 02h */
	uint16_t	ac97_headphone_volume;		/* 04h, optional */
	uint16_t	ac97_master_mono_volume;	/* 06h, optional */
	uint16_t	ac97_master_tone;		/* 08h, optional */
	uint16_t	ac97_pc_beep_volume;		/* 0ah, optional */
	uint16_t	ac97_phone_volume;		/* 0ch, optional */
	uint16_t	ac97_mic_volume;		/* 0eh */
	uint16_t	ac97_line_in_volume;		/* 10h */
	uint16_t	ac97_cd_volume;			/* 12h */
	uint16_t	ac97_video_volume;		/* 14h, optional */
	uint16_t	ac97_aux_volume;		/* 16h, optional */
	uint16_t	ac97_PCM_out_volume;		/* 18h */
	uint16_t	ac97_record_select;		/* 1ah */
	uint16_t	ac97_record_gain;		/* 1ch */
	uint16_t	ac97_record_gain_mic;		/* 1eh, optional */
	uint16_t	ac97_general_purpose;		/* 20h, optional */
	uint16_t	ac97_threeD_control;		/* 22h, optional */
	uint16_t	ac97_reserved_1;		/* 24h */
	uint16_t	ac97_pwrdwn_ctrl_stat;		/* 26h */

	/* extended audio registers */

	uint16_t	ac97_ext_audio_id;		/* 28h, optional */
	uint16_t	ac97_ext_audio_stat_ctrl;	/* 2ah, optional */
	uint16_t	ac97_ext_front_DAC_rate;	/* 2ch, optional */
	uint16_t	ac97_ext_surround_DAC_rate;	/* 2eh, optional */
	uint16_t	ac97_ext_LFE_DAC_rate;		/* 30h, optional */
	uint16_t	ac97_ext_LR_ADC_rate;		/* 32h, optional */
	uint16_t	ac97_ext_mic_ADC_rate;		/* 34h, optional */
	uint16_t	ac97_ext_C_LFE_volume;		/* 36h, optional */
	uint16_t	ac97_ext_LR_surround_volume;	/* 38h, optional */
	uint16_t	ac97_ext_reserved_1;		/* 3ah, optional */

	/* extended modem registers */

	uint16_t	ac97_ext_modem_id;		/* 3ch, optional */
	uint16_t	ac97_ext_modem_stat_ctrl;	/* 3eh, optional */
	uint16_t	ac97_ext_line1_DAC_ADC_rate;	/* 40h, optional */
	uint16_t	ac97_ext_line2_DAC_ADC_rate;	/* 42h, optional */
	uint16_t	ac97_ext_hndst_DAC_ADC_rate;	/* 44h, optional */
	uint16_t	ac97_ext_line1_DAC_ADC_level;	/* 46h, optional */
	uint16_t	ac97_ext_line2_DAC_ADC_level;	/* 48h, optional */
	uint16_t	ac97_ext_hndst_DAC_ADC_level;	/* 4ah, optional */
	uint16_t	ac97_ext_GPIO_pin_config;	/* 4ch, optional */
	uint16_t	ac97_ext_GPIO_pin_polarity;	/* 4eh, optional */
	uint16_t	ac97_ext_GPIO_pin_sticky;	/* 50h, optional */
	uint16_t	ac97_ext_GPIO_pin_wakeup;	/* 52h, optional */
	uint16_t	ac97_ext_GPIO_pin_status;	/* 54h, optional */
	uint16_t	ac97_ext_modem_AFE_stat_ctrl;	/* 56h, optional */
	uint16_t	ac97_ext_reserved_2;		/* 58h, optional */

	/* reserved for vendor usage */
	uint16_t	ac97_vendor_01;			/* 5ah, optional */
	uint16_t	ac97_vendor_02;			/* 5ch, optional */
	uint16_t	ac97_vendor_03;			/* 5eh, optional */
	uint16_t	ac97_vendor_04;			/* 60h, optional */
	uint16_t	ac97_vendor_05;			/* 62h, optional */
	uint16_t	ac97_vendor_06;			/* 64h, optional */
	uint16_t	ac97_vendor_07;			/* 66h, optional */
	uint16_t	ac97_vendor_08;			/* 68h, optional */
	uint16_t	ac97_vendor_09;			/* 6ah, optional */
	uint16_t	ac97_vendor_10;			/* 6ch, optional */
	uint16_t	ac97_vendor_11;			/* 6eh, optional */
	uint16_t	ac97_vendor_12;			/* 70h, optional */
	uint16_t	ac97_vendor_13;			/* 72h, optional */
	uint16_t	ac97_vendor_14;			/* 74h, optional */
	uint16_t	ac97_vendor_15;			/* 76h, optional */
	uint16_t	ac97_vendor_16;			/* 78h, optional */
	uint16_t	ac97_vendor_17;			/* 7ah, optional */

	uint16_t	ac97_vendor_id1;		/* 7ch */
	uint16_t	ac97_vendor_id2;		/* 7eh */
};
typedef struct ac97_v21 ac97_v21_t;

/*
 * Defines for the V2.1 registers.
 */

/* Reset Register					Index 00h */
#define	AC97_RESET_REGISTER				0x00
#define	RR_DEDICATED_MIC				0x0001
#define	RR_RESERVED					0x0002
#define	RR_BASS_TREBLE					0x0004
#define	RR_PSEUDO_STEREO				0x0008
#define	RR_HEADPHONE_SUPPORT				0x0010
#define	RR_LOUDNESS_SUPPORT				0x0020
#define	RR_18_BIT_DAC					0x0040
#define	RR_20_BIT_DAC					0x0080
#define	RR_18_BIT_ADC					0x0100
#define	RR_20_BIT_ADC					0x0200
#define	RR_3D_STEREO_ENHANCE_MASK			0x7c00

/* Master Volume Register				Index 02h */
#define	AC97_MASTER_VOLUME_REGISTER			0x02
#define	MVR_RIGHT_MASK					0x001f
#define	MVR_RIGHT_0dB_ATTEN				0x0000
#define	MVR_RIGHT_OPTIONAL_MASK				0x003f
#define	MVR_LEFT_MASK					0x1f00
#define	MVR_LEFT_0dB_ATTEN				0x0000
#define	MVR_LEFT_OPTIONAL_MASK				0x3f00
#define	MVR_MUTE					0x8000

/* Headphone Volume Register				Index 04h - Optional */
#define	AC97_HEADPHONE_VOLUME_REGISTER			0x04
#define	HPVR_RIGHT_MASK					0x001f
#define	HPVR_RIGHT_0dB_ATTEN				0x0000
#define	HPVR_RIGHT_OPTIONAL_MASK			0x003f
#define	HPVR_LEFT_MASK					0x1f00
#define	HPVR_LEFT_0dB_ATTEN				0x0000
#define	HPVR_LEFT_OPTIONAL_MASK				0x3f00
#define	HPVR_MUTE					0x8000

/* Mono Master Volume Register				Index 06h - Optional */
#define	AC97_MONO_MASTER_VOLUME_REGSITER		0x06
#define	MMVR_MASK					0x001f
#define	MMVR_0dB_ATTEN					0x0000
#define	MMVR_OPTIONAL_MASK				0x003f
#define	MMVR_MUTE					0x8000

/* Master Tone Control Register				Index 08h - Optional */
#define	AC97_MASTER_TONE_CONTROL_REGISTER		0x08
#define	MTCR_TREBLE_MASK				0x000e
#define	MTCR_TREBLE_OPTIONAL_MASK			0x000f
#define	MTCR_TREBLE_BYPASS				0x000f
#define	MTCR_BASS_MASK					0x0e00
#define	MTCR_BASS_OPTIONAL_MASK				0x0f00
#define	MTCR_BASS_BYPASS				0x0f00

/* PC Beep Register					Index 0ah - Optional */
#define	AC97_PC_BEEP_REGISTER				0x0a
#define	PCBR_VOLUME_MASK				0x001e
#define	PCBR_0dB_ATTEN					0x0000
#define	PCBR_MUTE					0x8000

/* Phone Volume	Register				Index 0ch - Optional */
#define	AC97_PHONE_VOLUME_REGISTER			0x0c
#define	PVR_GAIN_MASK					0x001f
#define	PVR_0dB_GAIN					0x0010
#define	PVR_MAX_ATTEN					0x001f
#define	PVR_MUTE					0x8000

/* Mic Volume Register					Index 0eh */
#define	AC97_MIC_VOLUME_REGISTER			0x0e
#define	MICVR_GAIN_MASK					0x001f
#define	MICVR_0dB_GAIN					0x0008
#define	MICVR_MAX_ATTEN					0x001f
#define	MICVR_20dB_BOOST				0x0040
#define	MICVR_20dB_NOBOOST				0x0000
#define	MICVR_MUTE					0x8000

/* Line In Volume Register				Index 10h */
#define	AC97_LINE_IN_VOLUME_REGISTER			0x10
#define	LIVR_RIGHT_GAIN_MASK				0x001f
#define	LIVR_RIGHT_0dB_GAIN				0x0010
#define	LIVR_RIGHT_MAX_ATTEN				0x001f
#define	LIVR_LEFT_GAIN_MASK				0x1f00
#define	LIVR_LEFT_0dB_GAIN				0x1000
#define	LIVR_LEFT_MAX_ATTEN				0x1f00
#define	LIVR_MUTE					0x8000

/* CD Volume Register					Index 12h */
#define	AC97_CD_VOLUME_REGISTER				0x12
#define	CDVR_RIGHT_GAIN_MASK				0x001f
#define	CDVR_RIGHT_0dB_GAIN				0x0010
#define	CDVR_RIGHT_MAX_ATTEN				0x001f
#define	CDVR_LEFT_GAIN_MASK				0x1f00
#define	CDVR_LEFT_0dB_GAIN				0x1000
#define	CDVR_LEFT_MAX_ATTEN				0x1f00
#define	CDVR_MUTE					0x8000

/* Video Volume Register				Index 14h - Optional */
#define	AC97_VIDEO_VOLUME_REGISTER			0x14
#define	VIDVR_RIGHT_GAIN_MASK				0x001f
#define	VIDVR_RIGHT_0dB_GAIN				0x0010
#define	VIDVR_RIGHT_MAX_ATTEN				0x001f
#define	VIDVR_LEFT_GAIN_MASK				0x1f00
#define	VIDVR_LEFT_0dB_GAIN				0x1000
#define	VIDVR_LEFT_MAX_ATTEN				0x1f00
#define	VIDVR_MUTE					0x8000

/* Aux Volume Register					Index 16h - Optional */
#define	AC97_AUX_VOLUME_REGISTER			0x16
#define	AUXVR_RIGHT_GAIN_MASK				0x001f
#define	AUXVR_RIGHT_0dB_GAIN				0x0010
#define	AUXVR_RIGHT_MAX_ATTEN				0x001f
#define	AUXVR_LEFT_GAIN_MASK				0x1f00
#define	AUXVR_LEFT_0dB_GAIN				0x1000
#define	AUXVR_LEFT_MAX_ATTEN				0x1f00
#define	AUXVR_MUTE					0x8000

/* PCM Out Input Volume Register			Index 18h */
#define	AC97_PCM_OUT_VOLUME_REGISTER			0x18
#define	PCMOVR_RIGHT_GAIN_MASK				0x001f
#define	PCMOVR_RIGHT_0dB_GAIN				0x0010
#define	PCMOVR_RIGHT_MAX_ATTEN				0x001f
#define	PCMOVR_LEFT_GAIN_MASK				0x1f00
#define	PCMOVR_LEFT_0dB_GAIN				0x1000
#define	PCMOVR_LEFT_MAX_ATTEN				0x1f00
#define	PCMOVR_MUTE					0x8000
#define	PCMOVR_GAIN_BITS				5

/* Record Select Control Register			Index 1ah */
#define	AC97_RECORD_SELECT_CTRL_REGISTER		0x1a
#define	RSCR_R_MIC					0x0000
#define	RSCR_R_CD					0x0001
#define	RSCR_R_VIDEO					0x0002
#define	RSCR_R_AUX					0x0003
#define	RSCR_R_LINE_IN					0x0004
#define	RSCR_R_STEREO_MIX				0x0005
#define	RSCR_R_MONO_MIX					0x0006
#define	RSCR_R_PHONE					0x0007
#define	RSCR_L_MIC					0x0000
#define	RSCR_L_CD					0x0100
#define	RSCR_L_VIDEO					0x0200
#define	RSCR_L_AUX					0x0300
#define	RSCR_L_LINE_IN					0x0400
#define	RSCR_L_STEREO_MIX				0x0500
#define	RSCR_L_MONO_MIX					0x0600
#define	RSCR_L_PHONE					0x0700

/* Record Gain Register					Index 1ch */
#define	AC97_RECORD_GAIN_REGISTER			0x1c
#define	RGR_RIGHT_MASK					0x000f
#define	RGR_RIGHT_0db_GAIN				0x0000
#define	RGR_RIGHT_MAX_GAIN				0x000f
#define	RGR_LEFT_MASK					0x0f00
#define	RGR_LEFT_0db_GAIN				0x0000
#define	RGR_LEFT_MAX_GAIN				0x0f00
#define	RGR_MUTE					0x8000

/* Record Gain Mic Register				Index 1eh - Optional */
#define	AC97_RECORD_GAIN_MIC_REGISTER			0x1e
#define	RGMR_MASK					0x000f
#define	RGMR_MUTE					0x8000
#define	RGMR_MASK					0x000f
#define	RGMR_0db_GAIN					0x0000
#define	RGMR_MAX_GAIN					0x000f

/* General Purpose Register				Index 20h - Optional */
#define	AC97_GENERAL_PURPOSE_REGISTER			0x20
#define	GPR_LPBK					0x0080
#define	GPR_MS_MIC1					0x0000
#define	GPR_MS_MIC2					0x0100
#define	GPR_MONO_MIX_IN					0x0000
#define	GPR_MONO_MIC_IN					0x0200
#define	GPR_BASS_BOOST					0x1000
#define	GPR_3D_STEREO_ENHANCE				0x2000
#define	GPR_ST						0x4000
#define	GPR_POP_PRE_3D					0x0000
#define	GPR_POP_POST_3D					0x8000

/* 3D Control Regsiter					Index 22h - Optional */
#define	AC97_THREE_D_CONTROL_REGISTER			0x22
#define	TDCR_DEPTH_MASK					0x000f
#define	TDCR_CENTER_MASK				0x0f00
#define	TDCR_NULL					0x0000

/* Powerdown Control Status Register			Index 26h */
#define	AC97_POWERDOWN_CTRL_STAT_REGISTER		0x26
#define	PCSR_ADC					0x0001
#define	PCSR_DAC					0x0002
#define	PCSR_ANL					0x0004
#define	PCSR_REF					0x0008
#define	PCSR_POWERD_UP					(PCSR_ADC|PCSR_DAC|\
							PCSR_ANL|PCSR_REF)
#define	PCSR_PR0					0x0100
#define	PCSR_PR1					0x0200
#define	PCSR_PR2					0x0400
#define	PCSR_PR3					0x0800
#define	PCSR_PR4					0x1000
#define	PCSR_PR5					0x2000
#define	PCSR_PR6					0x4000
#define	PCSR_EAPD					0x8000

/* Extended Audio Register				Index 28h - Optional */
#define	AC97_EXTENDED_AUDIO_REGISTER			0x28
#define	EAR_VRA						0x0001
#define	EAR_DRA						0x0002
#define	EAR_VRM						0x0008
#define	EAR_CDAC					0x0040
#define	EAR_SDAC					0x0080
#define	EAR_LDAC					0x0100
#define	EAR_AMAP					0x0200
#define	EAR_PRIMARY_CODEC				0x0000
#define	EAR_SECONDARY_01_CODEC				0x4000
#define	EAR_SECONDARY_10_CODEC				0x8000
#define	EAR_SECONDARY_11_CODEC				0xc000

/* Extended Audio Status and Control Register		Index 2ah - Optional */
#define	AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER		0x2a
#define	EASCR_VRA					0x0001
#define	EASCR_DRA					0x0002
#define	EASCR_VRM					0x0008
#define	EASCR_CDAC					0x0040
#define	EASCR_SDAC					0x0080
#define	EASCR_LDAC					0x0100
#define	EASCR_MADC					0x0200
#define	EASCR_PRI					0x0800
#define	EASCR_PRJ					0x1000
#define	EASCR_PRK					0x2000
#define	EASCR_PRL					0x4000

/* Extended Front DAC Rate Register			2ch - Optional */
#define	AC97_EXTENDED_FRONT_DAC_RATE_REGISTER		0x2c
#define	AC97_SAMPLE_RATE_48000				0xbb80

/* Extended Surround DAC Rate Register			2eh - Optional */
#define	AC97_EXTENDED_SURROUND_DAC_RATE_REGISTER	0x2e

/* Extended LFE DAC Rate Register			30h - Optional */
#define	AC97_EXTENDED_LFE_DAC_RATE_REGISTER		0x30

/* Extended LR DAC Rate Register			32h - Optional */
#define	AC97_EXTENDED_LR_DAC_RATE_REGISTER		0x32

/* Extended Mic ADC Rate Register			34h - Optional */
#define	AC97_EXTENDED_MIC_ADC_RATE_REGISTER		0x34

/* Extended Center and LFE Volume Register		36h - Optional */
#define	AC97_EXTENDED_C_LFE_VOLUME_REGISTER		0x36
#define	EXLFEVR_CENTER_MASK				0x001f
#define	EXLFEVR_CENTER_OPTIONAL_MASK			0x003f
#define	EXLFEVR_CENTER_MTUE				0x0080
#define	EXLFEVR_LFE_MASK				0x1f00
#define	EXLFEVR_LFE_OPTIONAL_MASK			0x3f00
#define	EXLFEVR_LFE_MUTE				0x8000

/* Extended Left and Right Surround Volume Register	38h - Optional */
#define	AC97_EXTENDED_LRS_VOLUME_REGISTER		0x38
#define	EXLFEVR_RIGHT_MASK				0x001f
#define	EXLFEVR_RIGHT_OPTIONAL_MASK			0x003f
#define	EXLFEVR_RIGHT_MTUE				0x0080
#define	EXLFEVR_LEFT_MASK				0x1f00
#define	EXLFEVR_LEFT_OPTIONAL_MASK			0x3f00
#define	EXLFEVR_LEFT_MUTE				0x8000

/* Extended Modem ID Register				3ch - Optional */
#define	AC97_EXTENDED_MODEM_ID_REGISTER			0x3c
#define	EMIDR_LINE1					0x0001
#define	EMIDR_LINE2					0x0002
#define	EMIDR_HSET					0x0004
#define	EMIDR_CID1					0x0008
#define	EMIDR_CID2					0x0010
#define	EMIDR_PRIMARY_CODEC				0x0000
#define	EMIDR_SECONDARY_01_CODEC			0x4000
#define	EMIDR_SECONDARY_10_CODEC			0x8000
#define	EMIDR_SECONDARY_11_CODEC			0xc000

/* Extended Modem Status and Control Register		3eh - Optional */
#define	AC97_EXTENDED_MODE_STAT_CTRL_REGISTER		0x3e
#define	EMSCR_BPIO					0x0001
#define	EMSCR_MREF					0x0002
#define	EMSCR_ADC1					0x0004
#define	EMSCR_DAC1					0x0008
#define	EMSCR_ADC2					0x0010
#define	EMSCR_DAC2					0x0020
#define	EMSCR_HADC					0x0040
#define	EMSCR_HDAC					0x0080
#define	EMSCR_PRA					0x0100
#define	EMSCR_PRB					0x0200
#define	EMSCR_PRC					0x0400
#define	EMSCR_PRD					0x0800
#define	EMSCR_PRE					0x1000
#define	EMSCR_PRF					0x2000
#define	EMSCR_PRG					0x4000
#define	EMSCR_PRH					0x8000

/* Extended Modem Line 1 DAC/ADC Sample Rate Register	40h - Optional */
#define	AC97_EXTENDED_MODEM_LINE1_RATE_REGISTER		0x40

/* Extended Modem Line 2 DAC/ADC Sample Rate Register	42h - Optional */
#define	AC97_EXTENDED_MODEM_LINE2_RATE_REGISTER		0x42

/* Extended Modem Handset Sample Rate Register		44h - Optional */
#define	AC97_EXTENDED_MODEM_HANDSET_RATE_REGISTER	0x44

/* Extended Modem Line 1 DAC/ADC Level Register		46h - Optional */
#define	AC97_EXTENDED_MODEM_LINE1_LEVEL_REGISTER	0x46
#define	EML1LR_ADC_LEVEL_MASK				0x000f
#define	EML1LR_ADC_LEVEL_MUTE				0x0080
#define	EML1LR_DAC_LEVEL_MASK				0x0f00
#define	EML1LR_DAC_LEVEL_MUTE				0x8000

/* Extended Modem Line 2 DAC/ADC Level Register		48h - Optional */
#define	AC97_EXTENDED_MODEM_LINE2_LEVEL_REGISTER	0x48
#define	EML2LR_ADC_LEVEL_MASK				0x000f
#define	EML2LR_ADC_LEVEL_MUTE				0x0080
#define	EML2LR_DAC_LEVEL_MASK				0x0f00
#define	EML2LR_DAC_LEVEL_MUTE				0x8000

/* Extended Modem Handset DAC/ADC Level Register	4ah - Optional */
#define	AC97_EXTENDED_MODEM_HANDSET_LEVEL_REGISTER	0x4a
#define	EMHLR_ADC_LEVEL_MASK				0x000f
#define	EMHLR_ADC_LEVEL_MUTE				0x0080
#define	EMHLR_DAC_LEVEL_MASK				0x0f00
#define	EMHLR_DAC_LEVEL_MUTE				0x8000

/* Extended Modem GPIO Pin Configuration Register	4ch - Optional */
#define	AC97_EXTENDED_MODEM_GPIO_PIN_REGISTER		0x4c

/* Extended Modem GPIO Pin Polarity Register		4eh - Optional */
#define	AC97_EXTENDED_MODEM_GPIO_POLARITY_REGISTER	0x4e

/* Extended Modem GPIO Pin Sticky Register		50h - Optional */
#define	AC97_EXTENDED_MODEM_GPIO_STICKY_REGISTER	0x50

/* Extended Modem GPIO Pin Wake-up Mask Register	52h - Optional */
#define	AC97_EXTENDED_MODEM_GPIO_WAKEUP_REGISTER	0x52

/* Extended Modem GPIO Pin Status Mask Register		54h - Optional */
#define	AC97_EXTENDED_MODEM_GPIO_STATUS_REGISTER	0x54

/* Extended Modem AFE Status and Control Register	56h - Optional */
#define	AC97_EXTENDED_MODEM_AFE_STAT_CTRL_REGISTER	0x56
#define	EMAFESCR_L1B0					0x0001
#define	EMAFESCR_L1B1					0x0002
#define	EMAFESCR_L1B2					0x0004
#define	EMAFESCR_L2B0					0x0010
#define	EMAFESCR_L2B1					0x0020
#define	EMAFESCR_L2B2					0x0040
#define	EMAFESCR_HSB0					0x0100
#define	EMAFESCR_HSB1					0x0200
#define	EMAFESCR_HSB2					0x0400
#define	EMAFESCR_MLINK_ON				0x0000
#define	EMAFESCR_MLINK_OFF				0x1000
#define	EMAFESCR_CIDR					0x2000
#define	EMAFESCR_CID1					0x4000
#define	EMAFESCR_CID2					0x8000

/* Vender Reserved Registers				5ah - 7ah - Optional */
#define	AC97_VENDOR_REGISTER_01				0x5a
#define	AC97_VENDOR_REGISTER_02				0x5c
#define	AC97_VENDOR_REGISTER_03				0x5e
#define	AC97_VENDOR_REGISTER_04				0x60
#define	AC97_VENDOR_REGISTER_05				0x62
#define	AC97_VENDOR_REGISTER_06				0x64
#define	AC97_VENDOR_REGISTER_07				0x66
#define	AC97_VENDOR_REGISTER_08				0x68
#define	AC97_VENDOR_REGISTER_09				0x6a
#define	AC97_VENDOR_REGISTER_10				0x6c
#define	AC97_VENDOR_REGISTER_11				0x6e
#define	AC97_VENDOR_REGISTER_12				0x70
#define	AC97_VENDOR_REGISTER_13				0x72
#define	AC97_VENDOR_REGISTER_14				0x74
#define	AC97_VENDOR_REGISTER_15				0x76
#define	AC97_VENDOR_REGISTER_16				0x78
#define	AC97_VENDOR_REGISTER_17				0x7a

/* Vendor ID1 Register					7ch */
#define	AC97_VENDOR_ID1_REGISTER			0x7c
#define	VID1R_CHAR2_MASK				0x00ff
#define	VID1R_CHAR1_MASK				0xff00

/* Vendor ID2 Register					7eh */
#define	AC97_VENDOR_ID2_REGISTER			0x7e
#define	VID2R_REVISION_MASK				0x00ff
#define	VID2R_CHAR3_MASK				0xff00

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AC97_H */
