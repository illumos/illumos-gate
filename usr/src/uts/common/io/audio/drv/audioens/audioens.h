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

#ifndef	_AUDIOENS_H
#define	_AUDIOENS_H

/* CONCERT PCI-SIG defines */
#define	CONC_PCI_VENDID		0x1274U
#define	CONC_PCI_DEVID		0x1371U

/* Concert97 direct register offset defines */
#define	CONC_bDEVCTL_OFF	0x00	/* Device control/enable */
#define	CONC_bMISCCTL_OFF	0x01	/* Miscellaneous control */
#define	CONC_bGPIO_OFF		0x02	/* General purpose I/O control */
#define	CONC_bJOYCTL_OFF	0x03	/* Joystick control (decode) */
#define	CONC_dSTATUS_OFF	0x04	/* long status register */
#define	CONC_bINTSUMM_OFF	0x07	/* Interrupt summary status */
#define	CONC_bUARTDATA_OFF	0x08	/* UART data R/W - read clears RX int */
#define	CONC_bUARTCSTAT_OFF	0x09	/* UART control and status */
#define	CONC_bUARTTEST_OFF	0x0a	/* UART test control reg */
#define	CONC_bMEMPAGE_OFF	0x0c	/* Memory page select */
#define	CONC_dSRCIO_OFF		0x10	/* I/O ctl/stat/data for SRC RAM */
#define	CONC_dCODECCTL_OFF	0x14	/* CODEC control - dword read/write */
#define	CONC_wNMISTAT_OFF	0x18	/* Legacy NMI status */
#define	CONC_bNMIENA_OFF	0x1a	/* Legacy NMI enable */
#define	CONC_bNMICTL_OFF	0x1b	/* Legacy control */
#define	CONC_dSPDIF_OFF		0x1c	/* SPDIF status control */
#define	CONC_bSERFMT_OFF	0x20	/* Serial device control */
#define	CONC_bSERCTL_OFF	0x21	/* Serial device format */
#define	CONC_bSKIPC_OFF		0x22	/* DAC skip count reg */
#define	CONC_wDAC1IC_OFF	0x24	/* Synth int count in sample frames */
#define	CONC_wDAC1CIC_OFF	0x26	/* Synth current int count */
#define	CONC_wDAC2IC_OFF	0x28	/* DAC int count in sample frames */
#define	CONC_wDAC2CIC_OFF	0x2a	/* DAC current int count */
#define	CONC_wADCIC_OFF		0x2c	/* ADC int count in sample frames */
#define	CONC_wADCCIC_OFF	0x2e	/* ADC current int count */
#define	CONC_MEMBASE_OFF	0x30 /* Memory window base - 16 byte window */

/* Concert memory page-banked register offset defines */
#define	CONC_dDAC1PADDR_OFF	0x30	/* Synth host frame PCI phys addr */
#define	CONC_wDAC1FC_OFF	0x34	/* Synth host frame count in DWORDS */
#define	CONC_wDAC1CFC_OFF	0x36	/* Synth host current frame count */
#define	CONC_dDAC2PADDR_OFF	0x38	/* DAC host frame PCI phys addr */
#define	CONC_wDAC2FC_OFF	0x3c	/* DAC host frame count in DWORDS */
#define	CONC_wDAC2CFC_OFF	0x3e	/* DAC host current frame count */
#define	CONC_dADCPADDR_OFF	0x30	/* ADC host frame PCI phys addr */
#define	CONC_wADCFC_OFF		0x34	/* ADC host frame count in DWORDS */
#define	CONC_wADCCFC_OFF	0x36	/* ADC host current frame count */

/* Concert memory page number defines */
#define	CONC_DAC1RAM_PAGE	0x00	/* Synth host/serial I/F RAM */
#define	CONC_DAC2RAM_PAGE	0x04	/* DAC host/serial I/F RAM */
#define	CONC_ADCRAM_PAGE	0x08	/* ADC host/serial I/F RAM */
#define	CONC_DAC1CTL_PAGE	0x0c	/* Page bank for synth host control */
#define	CONC_DAC2CTL_PAGE	0x0c	/* Page bank for DAC host control */
#define	CONC_ADCCTL_PAGE	0x0d	/* Page bank for ADC host control */
#define	CONC_FIFO0_PAGE		0x0e	/* page 0 of UART "FIFO" (rx stash) */
#define	CONC_FIFO1_PAGE		0x0f	/* page 1 of UART "FIFO" (rx stash) */

/* SPDIF defines - only newer chips */
#define	CONC_SPDIF_CLKACCURACY	0x00000000U	/* normal mode */
#define	CONC_SPDIF_SR48KHZ	0x02000000U	/* 48KHZ clock, must be set */
#define	CONC_SPDIF_CHNO_MASK	0x00f00000U	/* channel number */
#define	CONC_SPDIF_SRCNO_MASK	0x000f0000U	/* source number */
#define	CONC_SPDIF_L		0x00008000U	/* 0 = commercial original */
#define	CONC_SPDIF_CATCODE	0x00007f00U	/* category code */
#define	CONC_SPDIF_EMPHASIS	0x00000008U	/* 2 ch, 50/15 usec preemph */
#define	CONC_SPDIF_COPY		0x00000004U	/* copy permitted */
#define	CONC_SPDIF_AC3		0x00000002U	/* data is not pcm (AC3) */

/* PCM format defines */
#define	CONC_PCM_DAC1_STEREO	0x01
#define	CONC_PCM_DAC1_16BIT	0x02
#define	CONC_PCM_DAC2_STEREO	0x04
#define	CONC_PCM_DAC2_16BIT	0x08
#define	CONC_PCM_ADC_STEREO	0x10
#define	CONC_PCM_ADC_16BIT	0x20

/* Device Control defines */
#define	CONC_DEVCTL_PCICLK_DS	0x01	/* PCI Clock Disable */
#define	CONC_DEVCTL_XTALCLK_DS	0x02	/* Crystal Clock Disable */
#define	CONC_DEVCTL_JSTICK_EN	0x04	/* Joystick Enable */
#define	CONC_DEVCTL_UART_EN	0x08	/* UART Enable  */
#define	CONC_DEVCTL_ADC_EN	0x10	/* ADC Enable (record) */
#define	CONC_DEVCTL_DAC2_EN	0x20	/* DAC2 Enable (playback) */
#define	CONC_DEVCTL_DAC1_EN	0x40	/* DAC1 Enabale (synth) */

/* Misc Control defines */
#define	CONC_MISCCTL_PDLEV_D0	0x00	/* These bits reflect the */
#define	CONC_MISCCTL_PDLEV_D1	0x01	/* power down state of  */
#define	CONC_MISCCTL_PDLEV_D2	0x02	/* the part */
#define	CONC_MISCCTL_PDLEV_D3	0x03	/* */
#define	CONC_MISCCTL_CCBINTRM_EN	0x04	/* CCB module interrupt mask */

#define	CONC_MISCCTL_SYNC_RES	0x40	/* for AC97 warm reset */

/* Serial Control defines */
#define	CONC_SERCTL_DAC1IE	0x01 /* playback interrupt enable P1_INT_EN */
#define	CONC_SERCTL_DAC2IE	0x02 /* playback interrupt enable P2_INT_EN */
#define	CONC_SERCTL_ADCIE	0x04	/* record interrupt enable R1_INT_EN */
#define	CONC_SERCTL_DAC1PAUSE	0x08	/* playback pause */
#define	CONC_SERCTL_DAC2PAUSE	0x10	/* playback pause */
#define	CONC_SERCTL_ADCLOOP	0x80
#define	CONC_SERCTL_DAC2LOOP	0x40
#define	CONC_SERCTL_DAC1LOOP	0x20

/* Interrupt Status defines */
#define	CONC_STATUS_ADCINT	0x00000001	/* A/D interrupt pending */
#define	CONC_STATUS_DAC2INT	0x00000002	/* DAC2 interrupt pending */
#define	CONC_STATUS_DAC1INT	0x00000004	/* DAC1 interrupt pending */
#define	CONC_STATUS_UARTINT	0x00000008	/* UART interrupt pending */
#define	CONC_STATUS_PENDING	0x80000000	/* any interrupt pending */
#define	CONC_STATUS_SPDIF_MASK	0x18000000
#define	CONC_STATUS_SPDIF_P1P2	0x00000000
#define	CONC_STATUS_SPDIF_P1	0x08000000
#define	CONC_STATUS_SPDIF_P2	0x10000000
#define	CONC_STATUS_SPDIF_REC	0x18000000
#define	CONC_STATUS_ECHO	0x04000000
#define	CONC_STATUS_SPKR_MASK	0x03000000
#define	CONC_STATUS_SPKR_2CH	0x00000000
#define	CONC_STATUS_SPKR_4CH	0x01000000
#define	CONC_STATUS_SPKR_P1	0x02000000
#define	CONC_STATUS_SPKR_P2	0x03000000
#define	CONC_STATUS_EN_SPDIF	0x00040000

/* JOYCTL register defines */
#define	CONC_JOYCTL_200		0x00
#define	CONC_JOYCTL_208		0x01
#define	CONC_JOYCTL_210		0x02
#define	CONC_JOYCTL_218		0x03
#define	CONC_JOYCTL_SPDIFEN_B	0x04
#define	CONC_JOYCTL_RECEN_B	0x08

/* UARTCSTAT register masks */
#define	CONC_UART_RXRDY		0x01
#define	CONC_UART_TXRDY		0x02
#define	CONC_UART_TXINT		0x04
#define	CONC_UART_RXINT		0x80

#define	CONC_UART_CTL		0x03
#define	CONC_UART_TXINTEN	0x20
#define	CONC_UART_RXINTEN	0x80

/* defines for the CONCERT97 Sample Rate Converters */

/* register/base equates for the SRC RAM */
#define	SRC_DAC1_FIFO		0x00
#define	SRC_DAC2_FIFO		0x20
#define	SRC_ADC_FIFO		0x40
#define	SRC_ADC_VOL_L		0x6c
#define	SRC_ADC_VOL_R		0x6d
#define	SRC_DAC1_BASE		0x70
#define	SRC_DAC2_BASE		0x74
#define	SRC_ADC_BASE		0x78
#define	SRC_DAC1_VOL_L		0x7c
#define	SRC_DAC1_VOL_R		0x7d
#define	SRC_DAC2_VOL_L		0x7e
#define	SRC_DAC2_VOL_R		0x7f

#define	SRC_TRUNC_N_OFF		0x00
#define	SRC_INT_REGS_OFF	0x01
#define	SRC_ACCUM_FRAC_OFF	0x02
#define	SRC_VFREQ_FRAC_OFF	0x03


/* miscellaneous control defines */
#define	SRC_IOPOLL_COUNT	0x20000UL
#define	SRC_WENABLE		(1UL << 24)
#define	SRC_BUSY		(1UL << 23)
#define	SRC_DISABLE		(1UL << 22)
#define	SRC_DAC1FREEZE		(1UL << 21)
#define	SRC_DAC2FREEZE		(1UL << 20)
#define	SRC_ADCFREEZE		(1UL << 19)
#define	SRC_CTLMASK		0x00780000UL

#endif /* _AUDIOENS_H */
