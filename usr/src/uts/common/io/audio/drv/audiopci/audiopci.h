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
/*
 * Purpose: Definitions for the Creative/Ensoniq AudioPCI97 driver.
 */
/*
 * This file is part of Open Sound System
 *
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * This software is released under CDDL 1.0 source license.
 * See the COPYING file included in the main directory of this source
 * distribution for the license terms and conditions.
 */

#ifndef	_AUDIOPCI_H
#define	_AUDIOPCI_H

/* CONCERT PCI-SIG defines */
#define	CONC_PCI_VENDID		0x1274U
#define	CONC_PCI_DEVID		0x5000U

/* used for the development board only!! */
#define	CONC_DEV_PCI_VENDID	0x1274U
#define	CONC_DEV_PCI_DEVID	0x5000U


/*
 * CONCERT Registers
 */

#define	DAC_CLOCK_DIVIDE	22579200UL	/* DAC2 (CODEC) clock divide */

/* Concert direct register offset defines */

#define	CONC_bDEVCTL_OFF	0x00	/* Device control/enable */
#define	CONC_bMISCCTL_OFF	0x01	/* Miscellaneous control */
#define	CONC_wDACRATE_OFF	0x02	/* CODEC clock divider for PLL */
#define	CONC_dSTATUS_OFF	0x04	/* long status register */
#define	CONC_bCODECSTAT_OFF	0x05	/* CODEC interface status */
#define	CONC_bUARTDATA_OFF	0x08	/* UART data R/W - read clears RX int */
#define	CONC_bUARTCSTAT_OFF	0x09	/* UART control and status */
#define	CONC_bMEMPAGE_OFF	0x0c	/* Memory page select */
#define	CONC_wCODECCTL_OFF	0x10	/* CODEC control - word-write-only */
#define	CONC_wNMISTAT_OFF	0x18	/* Legacy NMI status */
#define	CONC_bNMIENA_OFF	0x1a	/* Legacy NMI enable */
#define	CONC_bNMICTL_OFF	0x1b	/* Legacy control */
#define	CONC_bSERFMT_OFF	0x20	/* Serial device control */
#define	CONC_bSERCTL_OFF	0x21	/* Serial device format */
#define	CONC_bSKIPC_OFF		0x22	/* Skip counts for DAC (wave) */
#define	CONC_wSYNIC_OFF		0x24	/* Synth int count in sample frames */
#define	CONC_wSYNCIC_OFF	0x26	/* Synth current int count */
#define	CONC_wDACIC_OFF		0x28	/* DAC int count in sample frames */
#define	CONC_wDACCIC_OFF	0x2a	/* DAC current int count */
#define	CONC_wADCIC_OFF		0x2c	/* ADC int count in sample frames */
#define	CONC_wADCCIC_OFF	0x2e	/* ADC current int count */
#define	CONC_MEMBASE_OFF	0x30	/* Memory window base - 16 bytes */

/* Device Control defines */
#define	CONC_DEVCTL_SERR_DIS	0x01	/* internal PCI serr bus enable */
#define	CONC_DEVCTL_CODEC_EN	0x02	/* CoDec Enable */
#define	CONC_DEVCTL_JSTICK_EN	0x04	/* Joystick Enable */
#define	CONC_DEVCTL_UART_EN	0x08	/* UART Enable */
#define	CONC_DEVCTL_ADC_EN	0x10	/* ADC Enable (record) */
#define	CONC_DEVCTL_DAC_EN	0x20	/* DAC Enable (playback) */
#define	CONC_DEVCTL_SYN_EN	0x40	/* Synth Enable */
#define	CONC_DEVCTL_MICBIAS	0x4000L	/* mic bias switch */

/* Misc Control defines */
#define	CONC_MISCCTL_MUTE	0x01	/* XTL0 wired to mute */
#define	CONC_MISCCTL_CCB_INTRM	0x04	/* CCB interrupt mask */
#define	CONC_MISCCTL_SYN_5KHZ	0x00	/* synth: 5512 Hz */
#define	CONC_MISCCTL_SYN_11KHZ	0x10	/* synth: 11025 Hz */
#define	CONC_MISCCTL_SYN_22KHZ	0x20	/* synth: 22050 Hz */
#define	CONC_MISCCTL_SYN_44KHZ	0x30	/* synth: 44100 Hz */

/* Interrupt Status defines */
#define	CONC_INTSTAT_ADCINT	0x01	/* A/D interrupt pending bit */
#define	CONC_INTSTAT_DACINT	0x02	/* DAC interrupt pending bit */
#define	CONC_INTSTAT_SYNINT	0x04	/* synth interrupt pending bit */
#define	CONC_INTSTAT_UARTINT	0x08	/* UART interrupt pending bit */
#define	CONC_INTSTAT_PENDING	0x80000000
			/* this bit set high while'st we have an interrupt */

/* Codec Status defines */
#define	CONC_CSTAT_CSTAT	0x4
#define	CONC_CSTAT_CBUSY	0x2
#define	CONC_CSTAT_CWRIP	0x1

/* SERFMT PCM format defines */
#define	CONC_PCM_SYN_STEREO	0x01
#define	CONC_PCM_SYN_16BIT	0x02
#define	CONC_PCM_DAC_STEREO	0x04
#define	CONC_PCM_DAC_16BIT	0x08
#define	CONC_PCM_ADC_STEREO	0x10
#define	CONC_PCM_ADC_16BIT	0x20

/* Serial Control defines */
#define	CONC_SERCTL_SYNIE	0x01	/* synth int enable */
#define	CONC_SERCTL_DACIE	0x02	/* playback interrupt enable */
#define	CONC_SERCTL_ADCIE	0x04	/* record interrupt enable */
#define	CONC_SERCTL_SYNPAUSE	0x10	/* playback pause */

/* Concert memory page-banked register offset defines */
#define	CONC_dSYNPADDR_OFF	0x30	/* Synth host frame PCI phys addr */
#define	CONC_wSYNFC_OFF		0x34	/* Synth host frame count in DWORDS */
#define	CONC_wSYNCFC_OFF	0x36	/* Synth host current frame count */
#define	CONC_dDACPADDR_OFF	0x38	/* DAC host frame PCI phys addr */
#define	CONC_wDACFC_OFF		0x3c	/* DAC host frame count in DWORDS */
#define	CONC_wDACCFC_OFF	0x3e	/* DAC host current frame count */
#define	CONC_dADCPADDR_OFF	0x30	/* ADC host frame PCI phys addr */
#define	CONC_wADCFC_OFF		0x34	/* ADC host frame count in DWORDS */
#define	CONC_wADCCFC_OFF	0x36	/* ADC host current frame count */

/* Concert memory page number defines */
#define	CONC_SYNRAM_PAGE	0x00	/* Synth host/serial I/F RAM */
#define	CONC_DACRAM_PAGE	0x04	/* DAC host/serial I/F RAM */
#define	CONC_ADCRAM_PAGE	0x08	/* ADC host/serial I/F RAM */
#define	CONC_SYNCTL_PAGE	0x0c	/* Page bank for synth host control */
#define	CONC_DACCTL_PAGE	0x0c	/* Page bank for DAC host control */
#define	CONC_ADCCTL_PAGE	0x0d	/* Page bank for ADC host control */
#define	CONC_FIFO0_PAGE		0x0e	/* page 0 of UART "FIFO" (rx stash) */
#define	CONC_FIFO1_PAGE		0x0f	/* page 1 of UART "FIFO" (rx stash) */

/* UARTCSTAT register masks  */
#define	CONC_UART_RXRDY		0x01
#define	CONC_UART_TXRDY		0x02
#define	CONC_UART_TXINT		0x04
#define	CONC_UART_RXINT		0x80

#define	CONC_UART_CTL		0x03
#define	CONC_UART_TXINTEN	0x20
#define	CONC_UART_RXINTEN	0x80

/*
 * CODEC register map
 */
#define	NUMREGS			32	/* total number of registers */
#define	NUMVOLS			16	/* number of vol regs */

/* Source and output volume control defines */
#define	CODEC_VOL_MASTER_L	0x00U	/* Master out, left */
#define	CODEC_VOL_MASTER_R	0x01U	/* Master out, right */
#define	CODEC_VOL_WAVE_L	0x02U	/* Wave DAC, left */
#define	CODEC_VOL_WAVE_R	0x03U	/* Wave DAC, right */
#define	CODEC_VOL_SYNTH_L	0x04U	/* Synth DAC, left */
#define	CODEC_VOL_SYNTH_R	0x05U	/* Synth DAC, right */
#define	CODEC_VOL_CD_L		0x06U	/* CD audio, left */
#define	CODEC_VOL_CD_R		0x07U	/* CD audio, right */
#define	CODEC_VOL_AUX_L		0x08U	/* Aux line source, left */
#define	CODEC_VOL_AUX_R		0x09U	/* Aux line source, right */
#define	CODEC_VOL_TV_L		0x0aU	/* TV Tuner, left */
#define	CODEC_VOL_TV_R		0x0bU	/* TV Tuner, right */
#define	CODEC_VOL_TAD		0x0cU	/* TAD monitor, mono */
#define	CODEC_VOL_MONO2		0x0dU	/* Unused MONO2 */
#define	CODEC_VOL_MIC		0x0eU	/* Mic, mono */
#define	CODEC_VOL_MONO		0x0fU	/* Mono out volume */

/* Input bus enable defines -SW1 */
#define	CODEC_IN_ENABLE_MIC	0x01U	/* Mic enable, mono */
#define	CODEC_IN_ENABLE_CD_R	0x02U	/* CD audio enable, right */
#define	CODEC_IN_ENABLE_CD_L	0x04U	/* CD audio enable, left */
#define	CODEC_IN_ENABLE_AUX_R	0x08U	/* Aux line source enable, right */
#define	CODEC_IN_ENABLE_AUX_L	0x10U	/* Aux line source enable, left */
#define	CODEC_IN_ENABLE_SYNTH_R 0x20U	/* Synth DAC enable, right */
#define	CODEC_IN_ENABLE_SYNTH_L 0x40U	/* Synth DAC enable, left */

/* Input bus enable defines - SW2 */
#define	CODEC_IN_ENABLE_TAD	0x01U	/* TAD monitor enable, mono */
#define	CODEC_IN_ENABLE_MONO2	0x02U	/* Unused MONO2 enable, mono */
#define	CODEC_IN_ENABLE_WAVE	0x04U	/* Wave DAC enable */
#define	CODEC_IN_ENABLE_TV_R	0x08U	/* TV Tuner enable, right */
#define	CODEC_IN_ENABLE_TV_L	0x10U	/* TV Tuner enable, left */
#define	CODEC_IN_ENABLE_TMONO2	0x20U	/* unboosted MONO2 */
#define	CODEC_IN_ENABLE_TMONO1	0x40U	/* unboosted MONO1 */
#define	CODEC_IN_ENABLE_TMIC	0x80U	/* unboosted MONO3 (mic) */

/* Output bus enable defines - SW1 */
#define	CODEC_OUT_ENABLE_MIC	0x01U	/* Mic enable, mono */
#define	CODEC_OUT_ENABLE_CD	0x06U	/* CD audio enable, stereo */
#define	CODEC_OUT_ENABLE_AUX	0x18U	/* Aux line source enable, stereo */
#define	CODEC_OUT_ENABLE_SYNTH	0x60U	/* Synth DAC enable, stereo */

/* Output bus enable defines - SW2 */
#define	CODEC_OUT_ENABLE_TAD	0x01U	/* TAD monitor enable, mono */
#define	CODEC_OUT_ENABLE_MONO2	0x02U	/* Unused MONO2 enable, mono */
#define	CODEC_OUT_ENABLE_WAVE	0x0cU	/* Wave DAC enable, stereo */
#define	CODEC_OUT_ENABLE_TV	0x30U	/* TV Tuner enable, stereo */

/* Volume setting constants */
#define	CODEC_ATT_MUTE		0x80U
#define	CODEC_ATT_MAX		0x1fU
#define	CODEC_ATT_MONO		0x07U

/* Control function defines */
#define	CODEC_CTL_4SPKR		0x00U	/* 4-spkr output mode enable */
#define	CODEC_CTL_MICBOOST	0x01U	/* Mic boost (+30 dB) enable */

/* Miscellaneous CODEC defines for internal use */
#define	CODEC_OUT_SW1		0x10U
#define	CODEC_OUT_SW2		0x11U
#define	CODEC_LIN_SW1		0x12U
#define	CODEC_RIN_SW1		0x13U
#define	CODEC_LIN_SW2		0x14U
#define	CODEC_RIN_SW2		0x15U
#define	CODEC_RESET_PWRD	0x16U
#define	CODEC_CLKSELECT		0x17U
#define	CODEC_ADSELECT		0x18U
#define	CODEC_MICBOOST		0x19U

#endif	/* _AUDIOPCI_H */
