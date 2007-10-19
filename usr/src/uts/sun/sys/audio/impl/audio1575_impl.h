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

#ifndef	_SYS_AUDIO1575_IMPL_H_
#define	_SYS_AUDIO1575_IMPL_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation specific header file for the audio1575 device driver.
 */

#ifdef _KERNEL

/* Misc. defines */
#define	M1575_IDNUM				(0x5455)
#define	M1575_CONFIG_DEVICE_ID			M1575_IDNUM
#define	M1575_CONFIG_VENDOR_ID			(0x10b9)
#define	M1575_CONFIG_SUBSYSTEM_ID		M1575_IDNUM
#define	M1575_CONFIG_SUBSYSTEM_VENDOR_ID	M1575_CONFIG_VENDOR_ID
#define	M1575_AUDIO_PCICFG_SPACE	(0)
#define	M1575_AUDIO_IO_SPACE		(1)
#define	M1575_AUDIO_MEM_SPACE		(2)

#define	M1575_MINPACKET			(0)
#define	M1575_MAXPACKET			(1*1024)
#define	M1575_HIWATER			(64*1024)
#define	M1575_LOWATER			(32*1024)
#define	M1575_LOOP_CTR			(100)

/* Gain and attenuation shift values */
#define	M1575_GAIN_SHIFT3		(3)
#define	M1575_GAIN_SHIFT4		(4)
#define	M1575_BYTE_SHIFT		(8)

/* audio direction */
#define	M1575_DMA_PCM_IN		(1)
#define	M1575_DMA_PCM_OUT		(2)

/* last AC97 saved register */
#define	M1575_LAST_AC_REG		(0x3a)

/* Restore audio flags */
#define	M1575_INIT_RESTORE		(0)
#define	M1575_INIT_NO_RESTORE		~M1575_INIT_RESTORE

/* AC97 codec shadow reg to index macro */
#define	M1575_CODEC_REG(r)		((r) >> 1)

/* play and record sample buffer counts */
#define	M1575_PLAY_BUFS			(2)
#define	M1575_PLAY_BUF_MSK		(M1575_PLAY_BUFS - 1)
#define	M1575_REC_BUFS			(4)
#define	M1575_REC_BUF_MSK		(M1575_REC_BUFS - 1)

/* Buffer Descriptor  List defines */
#define	M1575_BD_NUMS			(32)
#define	M1575_BD_MSK			(M1575_BD_NUMS - 1)
#define	M1575_BD_SIZE	\
	(M1575_BD_NUMS * sizeof (m1575_bd_entry_t))

/* default buffer size */
#define	M1575_BSIZE			(8*1024)
#define	M1575_MOD_SIZE			(16)
#define	M1575_PLAY_BUF_SZ		(1024)
#define	M1575_RECORD_BUF_SZ		(1024)
#define	M1575_BUF_MIN			(512)
#define	M1575_BUF_MAX			(8192)

/* Audio channel defines */
#define	M1575_MAX_CHANNELS		(32)
#define	M1575_MAX_HW_CHANNELS		(6)
#define	M1575_MAX_IN_CHANNELS		(1)
#define	M1575_MAX_OUT_CHANNELS	\
	(M1575_MAX_HW_CHANNELS - M1575_MAX_IN_CHANNELS)
#define	M1575_INPUT_STREAM		1
#define	M1575_PORT_UNMUTE		0xffffffff

/* kstat interrupt counter define */
#define	M1575_KIOP(X)	((kstat_intr_t *)(X->m1575_ksp->ks_data))

/* AD1981B Specific Definitions */
#define	AC97_MISC_CONTROL_BIT_REGISTER	0x76
#define	MIC_20dB_GAIN	0x0000
#define	MIC_10dB_GAIN	0x0001
#define	MIC_30dB_GAIN	0x0010
#define	C2MIC		0x0040
#define	C1MIC		0x0000
#define	AC97_MIXER_ADC_GAIN_REGISTER	0x64
#define	MIXER_GAIN_MUTE	0x8000
#define	MIXER_0db_GAIN_	0x0000
/* Check for poweron status every 10 ms */
#define	AD1981_POWERON_DELAY_USEC	10000

/* PCI CFG SPACE REGISTERS for Audio (Device 29, Function 0) */
#define	M1575_PCIID_REG		0x00	/* Vendor ID 32 */
#define	M1575_PCICS_REG		0x04	/* Cmd & Status 32 */
#define	M1575_PCIREV_REG	0x08	/* Class Code & RevId 32 */
#define	M1575_PCILT_REG		0x0C	/* PCI latency 32 */
#define	M1575_PCIIO_REG		0x10	/* PCI IOBASE 32 */
#define	M1575_PCIMEM_REG	0x14	/* PCI MEMBASE 32 */
#define	M1575_PCIINT_REG	0x3C	/* PCI INT Pin & Line 32 */
#define	M1575_PCIPMR_REG	0x42	/* Power Capabilities 16 */
#define	M1575_PCIPMCSR_REG	0x44	/* Power Cmd & Status 16 */
#define	M1575_PCISCCR_REG	0x48	/* System Cfg Cntrl 16 */
#define	M1575_PCIAPMUCR1_REG	0x54	/* Add. PMU Cntrl Reg  8 */
#define	M1575_PCISCRR_REG	0x57	/* Scratch Reg  8 */
#define	M1575_PCIMISC_REG	0x58	/* Misc Reg  8 */
#define	M1575_PCIGCC_REG	0x59	/* Global Clk Control 16 */
#define	M1575_PCIACD_REG	0x5C	/* AC97 Codec Detect  8 */
#define	M1575_PCIMISC_REG	0x58	/* Misc Reg  8 */
#define	M1575_PCIGCLK_REG	0x59	/* Misc Reg  8 */
#define	M1575_PCIMSICTRL_REG	0x62	/* MSI Control Reg 16 */
#define	M1575_PCIMSIADDR_REG	0x64	/* MSI Address Reg 32 */
#define	M1575_PCIMSIDATA_REG	0x68	/* MSI Data Reg 16 */
#define	M1575_PCIMSIMASK_REG	0x6C	/* MSI Data Reg 32 */
#define	M1575_PCIMSIPEND_REG	0x70	/* MSI Pend Reg 32 */

/* Bit definitions for PCI AC97 Clk detect Reg */
#define	M1575_PCIACD_CLKDET	0x01
#define	M1575_PCIMISC_INTENB	0x40
#define	M1575_PCIINT_LINE	0x05

/* Base Line Audio I/O Memory Registers */
#define	M1575_SCR_REG		0x00	/* System Control Reg 32 */
#define	M1575_SSR_REG		0x04	/* System System Reg 32 */
#define	M1575_DMACR_REG		0x08	/* DMA Control Reg 32 */
#define	M1575_FIFOCR1_REG	0x0C	/* FIFO 1 Control Reg 32 */
#define	M1575_INTFCR_REG	0x10	/* Interface Ctrl Reg 32 */
#define	M1575_INTRCR_REG	0x14	/* Interrupt Ctrl Reg 32 */
#define	M1575_INTRSR_REG	0x18	/* Interrupt Status Reg 32 */
#define	M1575_FIFOCR2_REG	0x1C	/* FIFO 2 Control Reg 32 */
#define	M1575_CPR_REG		0x20	/* Cmd Port Reg 32 */
#define	M1575_SPR_REG		0x24	/* Status Port Reg 32 */
#define	M1575_FIFOCR3_REG	0x2C	/* FIFO 3 Control Reg 32 */
#define	M1575_TTSR_REG		0x30	/* Tx Tag Slot Reg 32 */
#define	M1575_RTSR_REG		0x34	/* Rx Tag Slot Reg 32 */
#define	M1575_CSPSR_REG		0x38	/* CSP Status Reg 32 */
#define	M1575_CASR_REG		0x3C	/* Codec Access Sem Reg 32 */

/* PCM IN Registers */
#define	M1575_PCMIBDBAR_REG	0x40 	/* 32 */
#define	M1575_PCMICIV_REG	0x44 	/* 8 */
#define	M1575_PCMILVIV_REG	0x45 	/* 8 */
#define	M1575_PCMISR_REG	0x46 	/* 16 */
#define	M1575_PCMIPICB_REG	0x48 	/* 16 */
#define	M1575_PCMICR_REG	0x4B 	/* 8 */

/* PCM OUT Registers */
#define	M1575_PCMOBDBAR_REG	0x50 	/* 32 */
#define	M1575_PCMOCIV_REG	0x54 	/* 8 */
#define	M1575_PCMOLVIV_REG	0x55 	/* 8 */
#define	M1575_PCMOSR_REG	0x56 	/* 16 */
#define	M1575_PCMOPICB_REG	0x58 	/* 16 */
#define	M1575_PCMOCR_REG	0x5B 	/* 8 */

/* MIC In Registers */
#define	M1575_MICIBDBAR_REG	0x60 	/* 32 */
#define	M1575_MICICIV_REG	0x64 	/* 8 */
#define	M1575_MICILVIV_REG	0x65 	/* 8 */
#define	M1575_MICISR_REG	0x66 	/* 16 */
#define	M1575_MICIPICB_REG	0x68 	/* 16 */
#define	M1575_MICICR_REG	0x6B 	/* 8 */

/* SPIDOF Registers */
#define	M1575_CSPOBDBAR_REG	0x70 	/* 32 */
#define	M1575_CSPOCIV_REG	0x74 	/* 8 */
#define	M1575_CSPOLVIV_REG	0x75 	/* 8 */
#define	M1575_CSPOSR_REG	0x76 	/* 16 */
#define	M1575_CSPOPICB_REG	0x78 	/* 16 */
#define	M1575_CSPOCR_REG	0x7B 	/* 8 */

/* PCM IN2 Registers */
#define	M1575_PCMI2BDBAR_REG	0xd0 	/* 32 */
#define	M1575_PCMI2CIV_REG	0xd4 	/* 8 */
#define	M1575_PCMI2LVIV_REG	0xd5 	/* 8 */
#define	M1575_PCMI2SR_REG	0xd6 	/* 16 */
#define	M1575_PCMI2PICB_REG	0xd8 	/* 16 */
#define	M1575_PCMI2CR_REG	0xdB 	/* 8 */

/* MIC2 IN2 Registers */
#define	M1575_MICI2BDBAR_REG	0xe0 	/* 32 */
#define	M1575_MICI2CIV_REG	0xe4 	/* 8 */
#define	M1575_MICI2LVIV_REG	0xe5 	/* 8 */
#define	M1575_MICI2SR_REG	0xe6 	/* 16 */
#define	M1575_MICI2PICB_REG	0xe8 	/* 16 */
#define	M1575_MICI2CR_REG	0xeB 	/* 8 */

/* Bits of FIFO Control Register1 */
#define	M1575_FIFOCR1_CSPORST	0x80000000 /* SPDIF Out Reset */
#define	M1575_FIFOCR1_MICIRST	0x00800000 /* MIC In Reset */
#define	M1575_FIFOCR1_PCMORST	0x00008000 /* PCM Out Reset */
#define	M1575_FIFOCR1_PCMIRST	0x00000080 /* PCM In Reset */

/* Bits of FIFO Control Register2 */
#define	M1575_FIFOCR2_SPORST	0x80000000 /* SPDIF Out FIFO Reset */
#define	M1575_FIFOCR2_SPIRST	0x00800000 /* SPDIF In  FIFO Reset */
#define	M1575_FIFOCR2_LFEORST	0x00008000 /* LFE Out FIFO Reset */
#define	M1575_FIFOCR2_CENORST	0x00000080 /* CENTER Out Reset */

/* Bits of FIFO Control Register3 */
#define	M1575_FIFOCR3_PCMI2RST	0x00800000 /* PCM In2 FIFO  Reset */
#define	M1575_FIFOCR3_MICI2RST	0x00008000 /* MIC In2 FIFO Reset */
#define	M1575_FIFOCR3_I2SIRST	0x00000080 /* I2S In FIFO Reset */

/* Bits of DMA Control Register */
#define	M1575_DMACR_PCMISTART	0x00000001
#define	M1575_DMACR_PCMOSTART	0x00000002
#define	M1575_DMACR_MICISTART	0x00000004
#define	M1575_DMACR_CSPOSTART	0x00000008
#define	M1575_DMACR_CENOSTART	0x00000010
#define	M1575_DMACR_LFEOSTART	0x00000020
#define	M1575_DMACR_SPISTART	0x00000040
#define	M1575_DMACR_SPOSTART	0x00000080
#define	M1575_DMACR_I2SISTART	0x00000100
#define	M1575_DMACR_PCMI2START	0x00000200
#define	M1575_DMACR_MICI2START	0x00000400
#define	M1575_DMACR_PCMIPAUSE	0x00010000
#define	M1575_DMACR_PCMOPAUSE	0x00020000
#define	M1575_DMACR_MICIPAUSE	0x00040000
#define	M1575_DMACR_CSPOPAUSE	0x00080000
#define	M1575_DMACR_CENOPAUSE	0x00100000
#define	M1575_DMACR_LFEOPAUSE	0x00200000
#define	M1575_DMACR_SPIPAUSE	0x00400000
#define	M1575_DMACR_SPOPAUSE	0x00800000
#define	M1575_DMACR_I2SIPAUSE	0x01000000
#define	M1575_DMACR_PCMI2PAUSE	0x02000000
#define	M1575_DMACR_MICI2PAUSE	0x04000000

#define	M1575_DMACR_PAUSE_ALL	0x07ff0000

/* Bits of INTRSR Interrupt Status Register */
#define	M1575_INTRSR_GPIOINTR	0x0000002
#define	M1575_INTRSR_SPRINTR	0x0000020
#define	M1575_INTRSR_CPRINTR	0x0000080
#define	M1575_INTRSR_PCMIINTR   0x0010000
#define	M1575_INTRSR_PCMOINTR 	0x0020000
#define	M1575_INTRSR_MICIINTR  	0x0040000
#define	M1575_INTRSR_CSPOINTR  	0x0080000
#define	M1575_INTRSR_CENOINTR  	0x0100000
#define	M1575_INTRSR_LFEOINTR  	0x0200000
#define	M1575_INTRSR_SPIINTR	0x0400000
#define	M1575_INTRSR_SPOINTR	0x0800000
#define	M1575_INTRSR_I2SIINTR	0x1000000
#define	M1575_INTRSR_PCMI2INTR	0x2000000
#define	M1575_INTRSR_MICI2INTR	0x4000000

#define	M1575_INTR_MASK (M1575_INTRSR_GPIOINTR |\
	M1575_INTRSR_SPRINTR  |\
	M1575_INTRSR_CPRINTR  |\
	M1575_INTRSR_PCMIINTR |\
	M1575_INTRSR_PCMOINTR |\
	M1575_INTRSR_MICIINTR |\
	M1575_INTRSR_CSPOINTR |\
	M1575_INTRSR_CENOINTR |\
	M1575_INTRSR_LFEOINTR |\
	M1575_INTRSR_SPIINTR  |\
	M1575_INTRSR_SPOINTR  |\
	M1575_INTRSR_I2SIINTR |\
	M1575_INTRSR_PCMI2INTR|\
	M1575_INTRSR_MICI2INTR)

#define	M1575_UNUSED_INTR_MASK (M1575_INTRSR_GPIOINTR |\
	M1575_INTRSR_SPRINTR  |\
	M1575_INTRSR_CPRINTR  |\
	M1575_INTRSR_MICIINTR |\
	M1575_INTRSR_CSPOINTR |\
	M1575_INTRSR_CENOINTR |\
	M1575_INTRSR_LFEOINTR |\
	M1575_INTRSR_SPIINTR  |\
	M1575_INTRSR_SPOINTR  |\
	M1575_INTRSR_I2SIINTR |\
	M1575_INTRSR_PCMI2INTR|\
	M1575_INTRSR_MICI2INTR)

/* Defines a generic clear for all MIC and PCM Status Registers */
#define	M1575_STATUS_CLR	0x001e

/* Defines a generic RESET for all MIC and PCM Control Registers */
#define	M1575_CR_RR		0x02
#define	M1575_SR_DMACS		0x01

/* Bits of PCM In Status Register */
#define	M1575_PCMISR_DMACS	0x01 	/* DMACS=0 if DMA Engine is IDLE */
#define	M1575_PCMISR_CELV	0x02
#define	M1575_PCMISR_LVBCI	0x04
#define	M1575_PCMISR_BCIS	0x08
#define	M1575_PCMISR_FIFOE	0x10

/* Bits in PCM In Control Register */
#define	M1575_PCMICR_RR		0x02	/* Reset */
#define	M1575_PCMICR_LVBIE	0x04	/* Last valid Buffer Intr Enable */
#define	M1575_PCMICR_IOCE	0x10	/* Intr On Completion Enable */

/* Bits of PCM Out Status Register */
#define	M1575_PCMOSR_DMACS	0x01	/* DMACS=0 if DMA Engine is IDLE */
#define	M1575_PCMOSR_CELV	0x02
#define	M1575_PCMOSR_LVBCI	0x04
#define	M1575_PCMOSR_BCIS	0x08
#define	M1575_PCMOSR_FIFOE	0x10

/* Bits in PCM Out Control Register */
#define	M1575_PCMOCR_RR		0x02	/* Reset */
#define	M1575_PCMOCR_LVBIE	0x04	/* Last valid Buffer Intr Enable */
#define	M1575_PCMOCR_IOCE	0x10	/* Intr On Completion Enable */

/* Bits of MIC In Status Register */
#define	M1575_MICISR_DMACS	0x01	/* DMACS=0 if DMA Engine is IDLE */
#define	M1575_MICISR_CELV	0x02
#define	M1575_MICISR_LVBCI	0x04
#define	M1575_MICISR_BCIS	0x08
#define	M1575_MICISR_FIFOE	0x10

/* Bits in PCM In Control Register */
#define	M1575_MICICR_RR		0x02	/* Reset */
#define	M1575_MICICR_LVBIE	0x04	/* Last valid Buffer Intr Enable */
#define	M1575_MICICR_IOCE	0x10	/* Intr On Completion Enable */

/* Bits in System Control  Register */
#define	M1575_SCR_WARMRST	0x00000001
#define	M1575_SCR_COLDRST	0x00000002
#define	M1575_SCR_DRENT		0x40000000
#define	M1575_SCR_MSTRST	0x80000000

/* Bits in System Status Register */
#define	M1575_SSR_RSTBLK	0x00000002
#define	M1575_SSR_FACCS_MSK	0x00000018
#define	M1575_SSR_SCID		0x00000040

/* Bits in Command Port Register */
#define	M1575_CPR_ACSCS		0x0100 /* Audio Codec for cmd 1=codec 2 */
#define	M1575_CPR_READ		0x0080

/* Bits in Cmd Status Port Register */
#define	M1575_CSPSR_SUCC	0x08	/* cmd successful */
#define	M1575_CSPSR_RDRDY	0x02	/* ready for read cmd */
#define	M1575_CSPSR_WRRDY	0x01	/* ready for write cmd */
#define	M1575_PCMI2CR_RR	0x02	/* Reset */
#define	M1575_MICI2CR_RR	0x02	/* Reset */
#define	M1575_CSPOCR_RR		0x02	/* Reset */

/* Bits in  Interface  Control  Register */
#define	M1575_INTFCR_RSTREL		0x02000000
#define	M1575_INTFCR_RSTBLK		0x00200000
#define	M1575_INTFCR_MICENB		0x00100000
#define	M1575_INTFCR_PCMIENB		0x00080000
#define	M1575_INTFCR_MICI2ENB		0x00040000
#define	M1575_INTFCR_PCMI2ENB		0x00020000
#define	M1575_INTFCR_MICI2SEL		0x00008000
#define	M1575_INTFCR_MICISEL		0x00004000
#define	M1575_INTFCR_PCMOENB		0x00000002

#define	M1575_INTRCR_CPRINTR		0x00000080
#define	M1575_INTRCR_SPRINTR		0x00000020
#define	M1575_INTRCR_GPIOINTR		0x00000002

/* Bits of Recv Tag Slot Register */
#define	M1575_RTSR_SACRDY	0x20u	/* 2nd Audio Codec Rdy */
#define	M1575_RTSR_FACRDY	0x80u	/* 1st Audio Codec Rdy */

/* Semaphore busy */
#define	M1575_CASR_SEMBSY	0x80000000

/* AD1981 codec vendor ID */
#define	AD1981_VID1		0x4144
#define	AD1981_VID2		0x5374

/* AD1981B Codec Registers */
#define	AD1981_RESET_REG	0x00
#define	AD1981_MSTVOL_REG	0x02
#define	AD1981_HPHVOL_REG	0x04
#define	AD1981_MONOVOL_REG	0x06
#define	AD1981_MICVOL_REG	0x0E
#define	AD1981_CDVOL_REG	0x12
#define	AD1981_PCMOVOL_REG	0x18
#define	AD1981_RECSEL_REG	0x1A
#define	AD1981_RECGAIN_REG	0x1C
#define	AD1981_GENPUR_REG	0x20
#define	AD1981_PWRCSR_REG	0x26
#define	AD1981_EXTID_REG	0x28
#define	AD1981_EXTCSR_REG	0x2A
#define	AD1981_PCMDAC_REG	0x2C
#define	AD1981_PCMADC_REG	0x32
#define	AD1981_EQCTRL_REG	0x60
#define	AD1981_EQDATA_REG	0x62
#define	AD1981_MIXVOL_REG	0x64
#define	AD1981_MISCTRL_REG	0x76
#define	AD1981_VNDID1_REG	0x7C
#define	AD1981_VNDID2_REG	0x7E

/* AD1981B Biquad filter definitions */
#define	AD1981_MAX_FILTERS	35
#define	AD1981_EQCTRL_EQM	0x8000
#define	AD1981_EQCTRL_SYM	0x0080

/*
 * Equalizer Biquad Filter Coefficient Address offsets
 */
struct m1575_biquad {
	uint16_t addr;
	uint16_t coeff;
};
typedef struct m1575_biquad m1575_biquad_t;

/*
 * chunk buffer
 */
struct m1575_bdlist_chunk {
	caddr_t	 data_buf;		/* virtual address of buffer */
	uint32_t addr_phy;		/* physical address of buffer */
	ddi_dma_handle_t dma_handle;	/* dma handle */
	ddi_acc_handle_t acc_handle;	/* access handle */
	size_t real_len;		/* real len */
};
typedef struct m1575_bdlist_chunk m1575_bdlist_chunk_t;

/*
 * sample buffer
 */
struct m1575_sample_buf {
	boolean_t io_started;	/* start/stop state for play/record */
	int avail;		/* the number of available chunk(s) */
	uint8_t tail;		/* For CPU, 1st available BD entry */
	uint8_t head;		/* For CPU, 1st BD entry to reclaim */
	m1575_bdlist_chunk_t chunk[M1575_BD_NUMS];
};
typedef struct m1575_sample_buf m1575_sample_buf_t;

/*
 * buffer descripter list entry, see M1575 datasheet
 */
#define	IOC 0x8000
#define	BUP 0x4000

struct m1575_bd_entry {
	uint32_t buf_base;	/* the address of the buffer */
	uint16_t buf_len;	/* the number of samples */
	uint16_t buf_cmd;
};
typedef struct m1575_bd_entry m1575_bd_entry_t;

/*
 * PCI config space register layout
 */
struct audio1575_pci_regs {
    uint32_t	vendor_dev_id;			/* 00h - 03h */
    uint32_t	cmd_status_reg;			/* 04h - 07h */
    uint32_t	class_code_rev_id;		/* 08h - 0bh */
    uint32_t	bist_cache;			/* 0ch - 0fh */
    uint32_t	io_base;			/* 10h - 13h */
    uint32_t	mem_base;			/* 14h - 17h */
    uint32_t	rsvd1[4];			/* 18h - 28h */
    uint32_t	sub_ids;			/* 2ch - 2fh */
    uint32_t	rsvd2;				/* 30h - 33h */
    uint32_t	cap_ptr;			/* 34h - 37h */
    uint32_t	rsvd3;				/* 38h - 3bh */
    uint32_t	intr_line;			/* 3ch - 3fh */
    uint16_t	cap_id_next;			/* 40h - 41h */
    uint16_t	pm_cap;				/* 42h - 43h */
    uint16_t	pm_csr;				/* 44h - 45h */
    uint8_t	pm_csrbse;			/* 46h - 46h */
    uint8_t	data_reg;			/* 47h - 47h */
    uint16_t  	sccr_reg;			/* 48h - 49h */
    uint16_t  	subvendor_id;			/* 50h - 51h */
    uint16_t  	subdevice_id;			/* 52h - 53h */
    uint8_t	apmucr1_reg;			/* 54h	*/
    uint8_t	apmucr2_reg;			/* 55h 	*/
    uint8_t	itec;				/* 56h	*/
    uint8_t	scrr_reg;			/* 57h	*/
    uint8_t	misc_reg;			/* 58h	*/
    uint8_t	gcc_reg;			/* 59h	*/
    uint16_t	rsvd5;				/* 5ah - 5bh */
    uint8_t	ac97acd_reg;			/* 5ch	*/
    uint8_t	rsvd6[3];			/* 5dh - 5fh */
    uint8_t	msi_capid;			/* 60h	*/
    uint8_t	msi_next;			/* 61h	*/
    uint16_t	msi_ctrl;			/* 62h - 63h */
    uint32_t	msi_addr;			/* 64h - 67h */
    uint16_t	msi_data;			/* 68h - 69h */
    uint16_t	rsvd7;				/* 6ah - 6bh */
    uint32_t	msi_mask;			/* 6ch - 6fh */
    uint32_t	msi_pend;			/* 70h - 73h */
    uint16_t	rsrvd8[39];			/* 74h - c1h */
    uint16_t	smodem_devid;			/* c2h - c3h */
};
typedef struct audio1575_pci_regs audio1575_pci_regs_t;

/*
 * M1575 audio register layout
 */
struct audio1575_audio_regs {
	uint32_t	scr_reg;		/* 00h - 03h */
	uint32_t	ssr_reg;		/* 04h - 07h */
	uint32_t	dmacr_reg;		/* 08h - 0bh */
	uint32_t	fifocr1_reg;		/* 0ch - 0fh */
	uint32_t	intfcr_reg;		/* 10h - 13h */
	uint32_t	intrcr_reg;		/* 14h - 17h */
	uint32_t	intrsr_reg;		/* 18h - 1bh */
	uint32_t	fifocr2_reg;		/* 1ch - 1fh */
	uint32_t	cpr_reg;		/* 20h - 23h */
	uint32_t	spr_reg;		/* 24h - 27h */
	uint32_t	rsvd1;			/* 28h - 2bh */
	uint32_t	fifocr3_reg;		/* 2ch - 2fh */
	uint32_t	ttsr_reg;		/* 30h - 33h */
	uint32_t	rtsr_reg;		/* 34h - 37h */
	uint32_t	cspsr_reg;		/* 38h - 3bh */
	uint32_t	casr_reg;		/* 3ch - 3fh */
	uint32_t	pcmibdbar_reg;		/* 40h - 43h */
	uint8_t		pcmciv_reg;		/* 44h - 44h */
	uint8_t		pcmilviv_reg;		/* 45h - 45h */
	uint16_t	pcmisr_reg;		/* 46h - 47h */
	uint16_t	pcmipicb_reg;		/* 48h - 49h */
	uint8_t		rsvd2;			/* 4ah - 4ah */
	uint8_t		pcmicr_reg;		/* 4bh - 4bh */
	uint32_t	rsvd3;			/* 4ch - 4fh */
	uint32_t	pcmobdbar_reg;		/* 50h - 53h */
	uint8_t		pcmociv_reg;		/* 54h - 54h */
	uint8_t		pcmolviv_reg;		/* 55h - 55h */
	uint16_t	pcmosr_reg;		/* 56h - 57h */
	uint16_t	pcmopicb_reg;		/* 58h - 59h */
	uint8_t		rsvd4;			/* 5ah - 5ah */
	uint8_t		pcmocr_reg;		/* 5bh - 5bh */
	uint32_t	rsvd5;			/* 5ch - 5fh */
	uint32_t	micibdbar_reg;		/* 60h - 63h */
	uint8_t		miciciv_reg;		/* 64h - 64h */
	uint8_t		micilviv_reg;		/* 65h - 65h */
	uint16_t	micisr_reg;		/* 66h - 67h */
	uint16_t	micipicb_reg;		/* 68h - 69h */
	uint8_t		rsvd6;			/* 6ah - 6ah */
	uint8_t		micicr_reg;		/* 6bh - 6bh */
	uint32_t	rsvd7;			/* 6ch - 6fh */
	uint32_t	cspobdbar_reg;		/* 70h - 53h */
	uint8_t		cspociv_reg;		/* 74h - 74h */
	uint8_t		cspolviv_reg;		/* 75h - 75h */
	uint16_t	csposr_reg;		/* 76h - 77h */
	uint16_t	cspopicb_reg;		/* 78h - 79h */
	uint8_t		rsvd8;			/* 7ah - 7ah */
	uint8_t		cspocr_reg;		/* 7bh - 7bh */
	uint32_t	rsvd9[21];		/* 7ch - cfh */
	uint32_t	pcmi2bdbar_reg;		/* d0h - d3h */
	uint8_t		pcmi2civ_reg;		/* d4h - d4h */
	uint8_t		pcmi2lviv_reg;		/* d5h - d5h */
	uint16_t	pcmi2sr_reg;		/* d6h - d7h */
	uint16_t	pcmi2picb_reg;		/* d8h - d9h */
	uint8_t		rsvd10;			/* dah - dah */
	uint8_t		pcmi2cr_reg;		/* dbh - dbh */
	uint32_t	rsvd11;			/* dch - dfh */
	uint32_t	mici2bdbar_reg;		/* e0h - e3h */
	uint8_t		mici2civ_reg;		/* e4h - e4h */
	uint8_t		mici2lviv_reg;		/* e5h - e5h */
	uint16_t	mici2sr_reg;		/* e6h - e7h */
	uint16_t	mici2picb_reg;		/* e8h - e9h */
	uint8_t		rsvd12;			/* eah - eah */
	uint8_t		mici2cr_reg;		/* ebh - ebh */
	uint32_t	rsvd13;			/* ech - efh */
	uint32_t	hvcsr_reg;		/* f0h - f3h */
	uint32_t	rsvd14[3];		/* f4h - ffh */
};
typedef struct audio1575_audio_regs audio1575_audio_regs_t;

/*
 * audio1575_state_t per instance state and operation data
 */
struct audio1575_state	{
	kmutex_t		m1575_intr_mutex;	/* intr mutex */
	dev_info_t		*m1575_dip;		/* dev instance ptr */
	int			m1575_inst;		/* dev instance */
	int			m1575_intr_type;	/* intr type */
	uint_t			m1575_intr_pri;		/* intr priority */
	ddi_intr_handle_t	*m1575_h_table;		/* intr table ptr */
	audiohdl_t		m1575_ahandle;		/* audio handle */
	am_ad_info_t		m1575_ad_info;		/* audio device info */
	uint16_t		m1575_codec_shadow[64]; /* shadow AC97 regs */
	ddi_acc_handle_t	m1575_pci_regs_handle;	/* pci config space */
	ddi_acc_handle_t	m1575_am_regs_handle;	/* audio i/o regs */
	ddi_acc_handle_t	m1575_bm_regs_handle;	/* audio mem regs */
	audio1575_pci_regs_t	*m1575_pci_regs;	/* base of pci regs */
	audio1575_audio_regs_t	*m1575_am_regs;		/* base of i/o regs */
	audio1575_audio_regs_t	*m1575_bm_regs;		/* base of mem regs */
	ddi_dma_handle_t	m1575_bdl_dma_handle;	/* for BDL */
	ddi_acc_handle_t	m1575_bdl_acc_handle;	/* acc handle of BDL */
	void			*m1575_bdl_virtual;	/* virt addr of BDL */
	size_t			m1575_bdl_size;		/* real len of BDL */
	m1575_bd_entry_t	*m1575_bdl_virt_pin;  	/* vaddr PCMIN BDL */
	m1575_bd_entry_t	*m1575_bdl_virt_pout;	/* vaddr PCMOUT BDL */
	uint32_t		m1575_bdl_phys_pin;	/* physadr PCMIN BDL */
	uint32_t		m1575_bdl_phys_pout;	/* physadr PCMOUT BDL */
	audio_info_t		m1575_defaults;		/* default states */
	audio_device_t		m1575_dev_info;		/* audio device info */
	uint16_t		m1575_vol_bits_mask;	/* volume ctrl bits */
	kstat_t			*m1575_ksp;		/* kernel statistics */
	uint32_t		m1575_flags;		/* state flags */
	uint_t			m1575_cdrom;		/* 1= present, 0 not */
	uint_t			m1575_mode; 		/* MIXER/COMPAT_MODE */
	uint_t			m1575_psample_rate;	/* play sample rate */
	uint_t			m1575_pchannels; 	/* play channels */
	uint_t			m1575_pprecision; 	/* play precision */
	uint_t			m1575_csample_rate;	/* record sample rate */
	uint_t			m1575_cchannels;	/* record channels */
	uint_t			m1575_cprecision;	/* record precision */
	uint_t			m1575_output_port;	/* current out port */
	uint_t			m1575_input_port;	/* current input port */
	uint_t			m1575_monitor_gain;	/* monitor gain */
	int			m1575_csamples;		/* pcmin samples/int */
	int			m1575_psamples;		/* pcmout samples/int */
	uint32_t		m1575_res_flags;	/* resource flags */
	m1575_sample_buf_t	m1575_play_buf;		/* buf for playback */
	int			m1575_play_buf_size; 	/* size of in buf */
	m1575_sample_buf_t	m1575_record_buf;	/* buffer for record */
	int			m1575_record_buf_size; 	/* size of in buffer */
};
typedef struct audio1575_state audio1575_state_t;

/* audio1575_state_t.flags defines */
#define	M1575_DMA_PLAY_STARTED		0x0001u	/* play DMA eng. initialized */
#define	M1575_DMA_PLAY_PAUSED		0x0002u	/* play DMA engine paused */
#define	M1575_DMA_PLAY_EMPTY		0x0004u	/* play DMA engine empty */
#define	M1575_DMA_RECD_STARTED		0x0010u	/* record DMA engine started */
#define	M1575_DMA_SUSPENDED		0x0020u	/* DMA suspended flag */

/* bits of audio1575_state_t.m1575_res_flags */
#define	M1575_RS_PCI_REGS		0x0001
#define	M1575_RS_AM_REGS		0x0002
#define	M1575_RS_BM_REGS		0x0004
#define	M1575_RS_DMA_BDL_HANDLE		0x0008
#define	M1575_RS_DMA_BDL_MEM		0x0010
#define	M1575_RS_DMA_BDL_BIND		0x0020

/* PCI Config register macros */
#define	M1575_PCI_GET8(reg)						\
	ddi_get8(statep->m1575_pci_regs_handle,				\
	    (void *)((char *)statep->m1575_pci_regs + (reg)))

#define	M1575_PCI_GET16(reg)						\
	ddi_get16(statep->m1575_pci_regs_handle,			\
	    (void *)((char *)statep->m1575_pci_regs + (reg)))

#define	M1575_PCI_GET32(reg)						\
	ddi_get32(statep->m1575_pci_regs_handle,			\
	    (void *)((char *)statep->m1575_pci_regs + (reg)))

#define	M1575_PCI_PUT8(reg, val)					\
	ddi_put8(statep->m1575_pci_regs_handle,				\
	    (void *)((char *)statep->m1575_pci_regs + (reg)), (val))

#define	M1575_PCI_PUT16(reg, val)					\
	ddi_put16(statep->m1575_pci_regs_handle,			\
	    (void *)((char *)statep->m1575_pci_regs + (reg)), (val))

#define	M1575_PCI_PUT32(reg, val)					\
	ddi_put32(statep->m1575_pci_regs_handle,			\
	    (void *)((char *)statep->m1575_pci_regs + (reg)), (val))

/* audio i/o register macros */
#define	M1575_AM_GET8(reg)						\
	ddi_get8(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)))

#define	M1575_AM_GET16(reg)						\
	ddi_get16(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)))

#define	M1575_AM_GET32(reg)						\
	ddi_get32(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)))

#define	M1575_AM_PUT8(reg, val)						\
	ddi_put8(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)), (val))

#define	M1575_AM_PUT16(reg, val)					\
	ddi_put16(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)), (val))

#define	M1575_AM_PUT32(reg, val)					\
	ddi_put32(statep->m1575_am_regs_handle,				\
	    (void *)((char *)statep->m1575_am_regs + (reg)), (val))

/* audio memory bus master registers */
#define	M1575_BM_GET8(reg)						\
	ddi_get8(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)))

#define	M1575_BM_GET16(reg)						\
	ddi_get16(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)))

#define	M1575_BM_GET32(reg)						\
	ddi_get32(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)))

#define	M1575_BM_PUT8(reg, val) {					\
	uint8_t	__T;							\
	ddi_put8(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)), (val));	\
	__T = ddi_get8(statep->m1575_bm_regs_handle,			\
	    (void *)((char *)statep->m1575_bm_regs + (reg)));		\
	if (__T != val) {						\
		cmn_err(CE_NOTE, "audio1575: couldn't set "		\
		    "value (%d 0x%02x 0x%02x)", __LINE__, __T, val);	\
		    cmn_err(CE_CONT, "audio may not work "		\
		    "correctly until it is stopped and restarted");	\
	}								\
}

#define	M1575_BM_PUT16(reg, val) {					\
	uint16_t	__T;						\
	ddi_put16(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)), (val));	\
	__T = ddi_get16(statep->m1575_bm_regs_handle,			\
	    (void *)((char *)statep->m1575_bm_regs + (reg)));		\
	if (__T != val) {						\
		cmn_err(CE_NOTE, "audio1575: couldn't set "		\
		    "value (%d 0x%02x 0x%02x)", __LINE__, __T, val);	\
		    cmn_err(CE_CONT, "audio may not work "		\
		    "correctly until it is stopped and restarted");	\
	}								\
}

#define	M1575_BM_PUT32(reg, val) {					\
	uint32_t	__T;						\
	ddi_put32(statep->m1575_bm_regs_handle,				\
	    (void *)((char *)statep->m1575_bm_regs + (reg)), (val));	\
	__T = ddi_get32(statep->m1575_bm_regs_handle,			\
	    (void *)((char *)statep->m1575_bm_regs + (reg)));		\
	if (__T != val) {						\
		cmn_err(CE_NOTE, "audio1575: couldn't set "		\
		    "value (%d 0x%02x 0x%02x)", __LINE__, __T, val);	\
		    cmn_err(CE_CONT, "audio may not work "		\
		    "correctly until it is stopped and restarted");	\
	}								\
}

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO1575_IMPL_H_ */
