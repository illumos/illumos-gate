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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_AC97_H
#define	_SYS_AC97_H

#include <sys/types.h>
#include <sys/audio/audio_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * This header file describes the AC-97 Codec register set. See the
 * spec for a detailed description of each register.
 */

/*
 * Defines for the registers.
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
#define	AC97_MONO_MASTER_VOLUME_REGISTER		0x06
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

/* PCM Out Volume Register				Index 18h */
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

/* Audio Interrupt and Paging Mechanism			Index 24h - r2.3 */
#define	AC97_INTERRUPT_PAGING_REGISTER			0x24
#define	IPR_IS						0x8000
#define	IPR_CAUSE_MASK					0x6000
#define	IPR_SC						0x1000
#define	IPR_IE						0x0800
#define	IPR_PG_MASK					0x000f

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
#define	EAR_SPDIF					0x0004
#define	EAR_VRM						0x0008
#define	EAR_DSA_MASK					0x0030
#define	EAR_CDAC					0x0040
#define	EAR_SDAC					0x0080
#define	EAR_LDAC					0x0100
#define	EAR_AMAP					0x0200
#define	EAR_REV_MASK					0x0c00
#define	EAR_REV_21					0x0000
#define	EAR_REV_22					0x0400
#define	EAR_REV_23					0x0800
#define	EAR_PRIMARY_CODEC				0x0000
#define	EAR_SECONDARY_01_CODEC				0x4000
#define	EAR_SECONDARY_10_CODEC				0x8000
#define	EAR_SECONDARY_11_CODEC				0xc000

/* Extended Audio Status and Control Register		Index 2ah - Optional */
#define	AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER		0x2a
#define	EASCR_VRA					0x0001
#define	EASCR_DRA					0x0002
#define	EASCR_SPDIF					0x0004
#define	EASCR_VRM					0x0008
#define	EASCR_SPSA_MASK					0x0030
#define	EASCR_SPSA_3_4					0x0000
#define	EASCR_SPSA_7_8					0x0010
#define	EASCR_SPSA_6_9					0x0020
#define	EASCR_SPSA_10_11				0x0030
#define	EASCR_CDAC					0x0040
#define	EASCR_SDAC					0x0080
#define	EASCR_LDAC					0x0100
#define	EASCR_MADC					0x0200
#define	EASCR_SPCV					0x0400
#define	EASCR_PRI					0x0800
#define	EASCR_PRJ					0x1000
#define	EASCR_PRK					0x2000
#define	EASCR_PRL					0x4000
#define	EASCR_VCFG					0x8000

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
#define	EXLFEVR_CENTER_MUTE				0x0080
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

/* S/PDIF Control Register				3ah - Optional */
#define	AC97_SPDIF_CONTROL_REGISTER			0x3a
#define	SPCR_PRO					0x0001
#define	SPCR_AUDIO					0x0002
#define	SPCR_COPY					0x0004
#define	SPCR_PRE					0x0008
#define	SPCR_CC_MASK					0x07f0
#define	SPCR_L						0x0800
#define	SPCR_SPSR_MASK					0x3000
#define	SPCR_SPSR_44100					0x0000
#define	SPCR_SPSR_48000					0x2000
#define	SPCR_SPSR_32000					0x3000
#define	SPCR_DRS					0x4000
#define	SPCR_V						0x8000

/*
 * Modem only registers from 3ch - 58h.
 */

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

/* Vendor Reserved Registers				5ah - 7ah - Optional */
/*
 * Note that 60h - 6eh is also defined as the extended codec page area in
 * AC'97 r2.3.
 */
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

/*
 * Page 01 Extended Codec Registers
 */
#define	AC97_PAGE01_CODEC_CLASS_REV_REGISTER		0x60
#define	AC97_PAGE01_PCI_SVID_REGISTER			0x62
#define	AC97_PAGE01_PCI_SID_REGISTER			0x64
#define	AC97_PAGE01_FUNCTION_SELECT_REGISTER		0x66
#define	AC97_PAGE01_FUNCTION_INFORMATION_REGISTER	0x68
#define	AC97_PAGE01_SENSE_DETAILS_REGISTER		0x6a
#define	AC97_PAGE01_DAC_SLOT_MAPPING_REGISTER		0x6c
#define	AC97_PAGE01_ADC_SLOT_MAPPING_REGISTER		0x6e

/* Vendor ID1 Register					7ch */
#define	AC97_VENDOR_ID1_REGISTER			0x7c
#define	VID1R_CHAR2_MASK				0x00ff
#define	VID1R_CHAR1_MASK				0xff00

/* Vendor ID2 Register					7eh */
#define	AC97_VENDOR_ID2_REGISTER			0x7e
#define	VID2R_REVISION_MASK				0x00ff
#define	VID2R_CHAR3_MASK				0xff00

/*
 * Property names used by AC97.  We should probably have a better way
 * of dealing with some of these.  (LINEIN_FUNC and MIC_FUNC should really
 * be saved/restored with other global settings.)
 */
#define	AC97_PROP_AMPLIFIER	"ac97-amplifier"
#define	AC97_PROP_SPEAKER	"ac97-speaker"
#define	AC97_PROP_MICBOOST	"ac97-micboost"
#define	AC97_PROP_NO_HEADPHONE	"ac97-no-headphone"
#define	AC97_PROP_NO_AUXOUT	"ac97-no-auxout"
#define	AC97_PROP_NO_CDROM	"ac97-no-cdrom"
#define	AC97_PROP_NO_VIDEO	"ac97-no-video"
#define	AC97_PROP_NO_AUXIN	"ac97-no-auxin"
#define	AC97_PROP_NO_MIC	"ac97-no-mic"
#define	AC97_PROP_NO_LINEIN	"ac97-no-linein"
#define	AC97_PROP_LINEIN_FUNC	"ac97-linein-function"	/* 1=linein, 2=surr */
#define	AC97_PROP_MIC_FUNC	"ac97-mic-function"	/* 1=mic, 2=cen/lfe */
#define	AC97_PROP_DOWNMIX	"ac97-downmix"
#define	AC97_PROP_SPREAD	"ac97-spread"

/*
 * Known Codec vendors.
 */
#define	AC97_VENDOR_ADS			0x41445300	/* Analog Devices */
#define	AC97_VENDOR_AKM			0x414b4d00	/* Asahi Kasei */
#define	AC97_VENDOR_ALC			0x414c4300	/* Realtek */
#define	AC97_VENDOR_ALG			0x414c4700	/* Realtek */
#define	AC97_VENDOR_CMI			0x434d4900	/* Cmedia */
#define	AC97_VENDOR_CRY			0x43525900	/* Cirrus Logic */
#define	AC97_VENDOR_CXT			0x43585400	/* Conexant */
#define	AC97_VENDOR_EMC			0x454d4300	/* eMicro */
#define	AC97_VENDOR_EV			0x000f8300	/* Ectiva */
#define	AC97_VENDOR_ESS			0x45838300	/* ESS */
#define	AC97_VENDOR_HRS			0x48525300	/* Intersil */
#define	AC97_VENDOR_ICE			0x49434500	/* ICEnsemble */
#define	AC97_VENDOR_ITE			0x49544500	/* ITE */
#define	AC97_VENDOR_NSC			0x4e534300	/* National */
#define	AC97_VENDOR_PSC			0x50534300	/* Philips */
#define	AC97_VENDOR_SIL			0x53494c00	/* Silicon Labs */
#define	AC97_VENDOR_ST			0x83847600	/* SigmaTel */
#define	AC97_VENDOR_TRA			0x54524100	/* TriTech */
#define	AC97_VENDOR_TXN			0x54584e00	/* TI */
#define	AC97_VENDOR_VIA			0x56494100	/* VIA */
#define	AC97_VENDOR_WML			0x574d4c00	/* Wolfson */
#define	AC97_VENDOR_YMH			0x594d4800	/* Yamaha */

/*
 * Known Codec IDs.
 */
#define	AC97_CODEC_AD1819B		0x41445303
#define	AC97_CODEC_AD1881		0x41445340
#define	AC97_CODEC_AD1881A		0x41445348
#define	AC97_CODEC_AD1885		0x41445360
#define	AC97_CODEC_AD1886		0x41445361
#define	AC97_CODEC_AD1887		0x41445362
#define	AC97_CODEC_AD1888		0x41445368
#define	AC97_CODEC_AD1980		0x41445370
#define	AC97_CODEC_AD1981A		0x41445371
#define	AC97_CODEC_AD1981		0x41445372
#define	AC97_CODEC_AD1981B		0x41445374
#define	AC97_CODEC_AD1985		0x41445375
#define	AC97_CODEC_AK4540		0x414b4d00
#define	AC97_CODEC_ALC100		0x414c4326
#define	AC97_CODEC_ALC200P		0x414c4710
#define	AC97_CODEC_ALC202		0x414c4740
#define	AC97_CODEC_ALC203		0x414c4770
#define	AC97_CODEC_ALC250		0x414c4750
#define	AC97_CODEC_ALC250_2		0x414c4752
#define	AC97_CODEC_ALC650		0x414c4720
#define	AC97_CODEC_ALC655		0x414c4760
#define	AC97_CODEC_ALC658		0x414c4780
#define	AC97_CODEC_ALC850		0x414c4790
#define	AC97_CODEC_CMI9738		0x434d4941
#define	AC97_CODEC_CMI9739		0x434d4961
#define	AC97_CODEC_CMI9780		0x434d4969
#define	AC97_CODEC_CMI9761		0x434d4978
#define	AC97_CODEC_CMI9761_2		0x434d4982
#define	AC97_CODEC_CMI9761_3		0x434d4983
#define	AC97_CODEC_CS4202		0x43525970
#define	AC97_CODEC_CS4205		0x43525950
#define	AC97_CODEC_CS4294		0x43525920
#define	AC97_CODEC_CS4297		0x43525900
#define	AC97_CODEC_CS4297A		0x43525910
#define	AC97_CODEC_CS4299		0x43525930
#define	AC97_CODEC_CX20468		0x43585428
#define	AC97_CODEC_CX20468_2		0x43585429
#define	AC97_CODEC_CX20468_21		0x43585430
#define	AC97_CODEC_EM28028		0x454d4328
#define	AC97_CODEC_ES1921		0x45838308
#define	AC97_CODEC_EV1938		0x000f8384
#define	AC97_CODEC_ICE1232		0x49434511
#define	AC97_CODEC_LM4550		0x4e534350
#define	AC97_CODEC_STAC9700		0x83847600
#define	AC97_CODEC_STAC9701		0x83847601
#define	AC97_CODEC_STAC9701_2		0xc250c250
#define	AC97_CODEC_STAC9704		0x83847604
#define	AC97_CODEC_STAC9705		0x83847605
#define	AC97_CODEC_STAC9708		0x83847608
#define	AC97_CODEC_STAC9721		0x83847609
#define	AC97_CODEC_STAC9744		0x83847644
#define	AC97_CODEC_STAC9750		0x83847650
#define	AC97_CODEC_STAC9752		0x83847652
#define	AC97_CODEC_STAC9756		0x83847656
#define	AC97_CODEC_STAC9758		0x83847658
#define	AC97_CODEC_STAC9766		0x83847666
#define	AC97_CODEC_TR28023		0x54524103
#define	AC97_CODEC_TR28023_2		0x54524123
#define	AC97_CODEC_TR28028		0x54524108
#define	AC97_CODEC_TR28028_2		0x54524128
#define	AC97_CODEC_VT1612A		0x56494161
#define	AC97_CODEC_VT1617A		0x56494170
#define	AC97_CODEC_VT1616		0x49434551
#define	AC97_CODEC_VT1616A		0x49434552
#define	AC97_CODEC_VT1618		0x56494182
#define	AC97_CODEC_WM9701A		0x574d4c00
#define	AC97_CODEC_WM9703		0x574d4c03
#define	AC97_CODEC_WM9704		0x574d4c04
#define	AC97_CODEC_YMF743		0x594d4800
#define	AC97_CODEC_YMF753		0x594d4803

/*
 * Functions for drivers to interact with the common ac97 module.
 */
typedef struct ac97 ac97_t;
typedef void (*ac97_wr_t)(void *, uint8_t, uint16_t);
typedef uint16_t (*ac97_rd_t)(void *, uint8_t);
typedef struct ac97_ctrl ac97_ctrl_t;
typedef boolean_t (*ac97_ctrl_walk_t)(ac97_ctrl_t *, void *);

/*
 * Old style initialization.  The driver simply calls ac97_alloc()
 * followed by ac97_init().  These interfaces should not be used in
 * new drivers.
 */
ac97_t *ac97_alloc(dev_info_t *, ac97_rd_t, ac97_wr_t, void *);
int ac97_init(ac97_t *, audio_dev_t *);

/*
 * New style initialization.  The driver will call ac97_allocate(),
 * then it can call ac97_register_controls() to register controls.
 * Or, if it doesn't want all controls registered, it can find
 * controls with ac97_find_control(), and register them individually
 * with ac97_register_control().  ac97_alloc()
 *
 * Note that adjusting the set of controls should only be performed
 * while the driver is single threaded, during attach or detach
 * processing.  The AC'97 framework does not provide any locks
 * surrounding its internal list of controls.  Note however that
 * changes to the controls made from within the framework (e.g. by
 * someone accessing the control via the audio framework) are safe.
 */
ac97_t *ac97_allocate(audio_dev_t *, dev_info_t *, ac97_rd_t, ac97_wr_t,
    void *);
void ac97_probe_controls(ac97_t *);
void ac97_register_controls(ac97_t *);
void ac97_unregister_controls(ac97_t *);

void ac97_walk_controls(ac97_t *, ac97_ctrl_walk_t, void *);
ac97_ctrl_t *ac97_control_find(ac97_t *, const char *);
void ac97_control_register(ac97_ctrl_t *);
void ac97_control_unregister(ac97_ctrl_t *);
void ac97_control_remove(ac97_ctrl_t *);
const char *ac97_control_name(ac97_ctrl_t *);
const audio_ctrl_desc_t *ac97_control_desc(ac97_ctrl_t *);
int ac97_control_get(ac97_ctrl_t *, uint64_t *);
int ac97_control_set(ac97_ctrl_t *, uint64_t);

/*
 * Bits common to both new style and old style initialization.
 */
void ac97_free(ac97_t *);
void ac97_reset(ac97_t *);
int ac97_num_channels(ac97_t *);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AC97_H */
