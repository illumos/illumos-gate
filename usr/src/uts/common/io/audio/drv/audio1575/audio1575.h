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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	AUDIO1575_H
#define	AUDIO1575_H

/*
 * Header file for the audio1575 device driver
 */

/*
 * Driver supported configuration information
 */
#define	M1575_NAME			"audio1575"
#define	M1575_MOD_NAME			"M1575 audio driver"

/*
 * Implementation specific header file for the audio1575 device driver.
 */

/* Misc. defines */
#define	M1575_AUDIO_IO_SPACE		(1)

#define	M1575_LOOP_CTR			(100)

/* audio direction */
#define	M1575_PLAY			(0)
#define	M1575_REC			(1)

/* Buffer Descriptor  List defines */
#define	M1575_BD_NUMS			(32)
#define	M1575_NUM_PORTS			(2)
#define	M1575_MOD_SIZE			(16)

/* kstat interrupt counter define */
#define	M1575_ROUNDUP(x, algn)		(((x) + ((algn) - 1)) & ~((algn) - 1))

/* PCI CFG SPACE REGISTERS for Audio (Device 29, Function 0) */
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
#define	M1575_SR_CLR		0x001e
#define	M1575_SR_DMACS		0x0001

/* Defines a generic RESET for all MIC and PCM Control Registers */
#define	M1575_CR_IOCE		0x10
#define	M1575_CR_RR		0x02

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
#define	M1575_SCR_SPDIF_SLOT	0x00300000	/* 1=7/8, 2=6/9, 3=10/11 */
#define	M1575_SCR_RECMOD	0x000c0000	/* 0 = 16bit, 1=20 bit */
#define	M1575_SCR_PCMMOD	0x00030000	/* 0 = 16bit, 1=20 bit */
#define	M1575_SCR_6CHL_MASK	0x0000c000	/* FL, FR, C, BL, BR, LFE */
#define	M1575_SCR_6CHL_0	0x00000000	/* channel ordering */
#define	M1575_SCR_6CHL_1	0x00004000	/* FL, C, FR, BL, BR, LFE */
#define	M1575_SCR_6CHL_2	0x00008000	/* FL, FR, C, LFE, BL, BR */
#define	M1575_SCR_6CHL_3	0x0000c000	/* FL, C, FR, LFE, BL, BR */
#define	M1575_SCR_CHAMOD_MASK	0x00000300	/* 2, 4, or 6 channel */
#define	M1575_SCR_CHAMOD_2	0x00000000	/* 2 channel */
#define	M1575_SCR_CHAMOD_4	0x00000100	/* 4 channel surround */
#define	M1575_SCR_CHAMOD_6	0x00000200	/* 6 channel (5.1) surround */
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

struct audio1575_port {
	struct audio1575_state	*statep;
	ddi_dma_handle_t	samp_dmah;
	ddi_acc_handle_t	samp_acch;
	size_t			samp_size;
	caddr_t			samp_kaddr;
	uint32_t		samp_paddr;

	ddi_dma_handle_t	bdl_dmah;
	ddi_acc_handle_t	bdl_acch;
	size_t			bdl_size;
	caddr_t			bdl_kaddr;
	uint32_t		bdl_paddr;

	int			num;
	unsigned		nframes;
	uint32_t		offset;
	uint64_t		count;
	uint8_t			nchan;

	unsigned		sync_dir;

	audio_engine_t		*engine;
};
typedef struct audio1575_port audio1575_port_t;


/*
 * audio1575_state_t per instance state and operation data
 */
struct audio1575_state	{
	kmutex_t		lock;			/* intr mutex */
	dev_info_t		*dip;			/* dev instance ptr */
	audio_dev_t		*adev;			/* audio handle */
	ac97_t			*ac97;			/* ac'97 handle */
	audio1575_port_t	*ports[2];		/* DMA engines */

	ddi_acc_handle_t	pcih;			/* pci config space */

	ddi_acc_handle_t	regsh;			/* audio i/o regs */
	caddr_t			regsp;			/* base of i/o regs */

	uint8_t			maxch;			/* maximum channels */
};
typedef struct audio1575_state audio1575_state_t;

/* audio i/o register macros */
#define	GET8(reg)						\
	ddi_get8(statep->regsh, (void *)(statep->regsp + (reg)))

#define	GET16(reg)						\
	ddi_get16(statep->regsh, (void *)(statep->regsp + (reg)))

#define	GET32(reg)						\
	ddi_get32(statep->regsh, (void *)(statep->regsp + (reg)))

#define	PUT8(reg, val)						\
	ddi_put8(statep->regsh,	(void *)(statep->regsp + (reg)), (val))

#define	PUT16(reg, val)						\
	ddi_put16(statep->regsh, (void *)(statep->regsp + (reg)), (val))

#define	PUT32(reg, val)						\
	ddi_put32(statep->regsh, (void *)(statep->regsp + (reg)), (val))

#define	SET8(reg, bit)		PUT8(reg, GET8(reg) | (bit))
#define	SET16(reg, bit)		PUT16(reg, GET16(reg) | (bit))
#define	SET32(reg, bit)		PUT32(reg, GET32(reg) | (bit))
#define	CLR8(reg, bit)		PUT8(reg, GET8(reg) & ~(bit))
#define	CLR16(reg, bit)		PUT16(reg, GET16(reg) & ~(bit))
#define	CLR32(reg, bit)		PUT32(reg, GET32(reg) & ~(bit))


#endif	/* AUDIO1575_H */
