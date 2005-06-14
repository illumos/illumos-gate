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
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_ECPPREG_H
#define	_SYS_ECPPREG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Register definitions for the National Semiconductor PC87332VLJ
 * SuperI/O chip.
 */

/*
 * configuration registers
 */
struct config_reg {
	uint8_t index;
	uint8_t data;
};

/* index values for the configuration registers */
#define	FER	0x0	/* Function Enable Register */
#define	FAR	0x1	/* Function Address Register */
#define	PTR	0x2	/* Power and Test Register */
#define	FCR	0x3	/* Function Control Register */
#define	PCR	0x4	/* Printer Control Register */
#define	KRR	0x5	/* Keyboard and RTC control Register */
#define	PMC	0x6	/* Power Management Control register */
#define	TUP	0x7	/* Tape, UART, and Parallel port register */
#define	SID	0x8	/* Super I/O Identification register */

#define	SIO_LITE	0x40
#define	SIO_LITE_B	0x90
#define	SIO_REVA	0x1a
#define	SIO_REVB	0x1b

/* bit definitions for the FCR register */
#define	PC87332_FCR_MSD_SEL		0x01
#define	PC87332_FCR_RESERVED		0x02
#define	PC87332_FCR_PPM_EN		0x04
#define	PC87332_FCR_PPM_FLOAT_CTL	0x08
#define	PC87332_FCR_LDX			0x10
#define	PC87332_FCR_ZWS_EN		0x20
#define	PC87332_FCR_ZWS_SEL		0x40
#define	PC87332_FCR_IOCHRDY_SEL		0x80

/* bit definitions for the PCR register */
#define	PC87332_PCR_EPP_EN		0x01
#define	PC87332_PCR_EPP_VER		0x02
#define	PC87332_PCR_ECP_EN		0x04
#define	PC87332_PCR_ECP_CLK_FZ		0x08
#define	PC87332_PCR_INTR_LEVL		0x10
#define	PC87332_PCR_INTR_POL		0x20
#define	PC87332_PCR_INTR_DRAIN		0x40
#define	PC87332_PCR_RESERVED		0x80

/* bit definitions for the PMC register */
#define	PC87332_PMC_IDE_TRISTATE	0x01
#define	PC87332_PMC_FDC_TRISTATE	0x02
#define	PC87332_PMC_UART_TRISTATE	0x04
#define	PC87332_PMC_ECP_DMA_CONFIG	0x08
#define	PC87332_PMC_FDC_PD		0x10
#define	PC87332_PMC_SLB			0x20
#define	PC87332_PMC_PP_TRISTATE		0x40
#define	PC87332_PMC_RESERVED		0x80

/*
 * National 97317 superio registers
 */
#define	PC97317_CONFIG_DEV_NO		0x07
#define	PC97317_CONFIG_ACTIVATE		0x30
#define	PC97317_CONFIG_IO_RANGE		0x31
#define	PC97317_CONFIG_BASE_ADDR_MSB	0x60
#define	PC97317_CONFIG_BASE_ADDR_LSB	0x61
#define	PC97317_CONFIG_INTR_SEL		0x70
#define	PC97317_CONFIG_INTR_TYPE	0x71
#define	PC97317_CONFIG_DMA0_CHAN	0x74
#define	PC97317_CONFIG_DMA1_CHAN	0x75
#define	PC97317_CONFIG_PP_CONFIG	0xF0

/*
 * Plug N Play configuration superio registers
 * used in PC97317 & M1553
 */
#define	PnP_CONFIG_DEV_NO		0x07
#define	PnP_CONFIG_ACTIVATE		0x30
#define	PnP_CONFIG_IO_RANGE		0x31
#define	PnP_CONFIG_BASE_ADDR_MSB	0x60
#define	PnP_CONFIG_BASE_ADDR_LSB	0x61
#define	PnP_CONFIG_INTR_SEL		0x70
#define	PnP_CONFIG_INTR_TYPE		0x71
#define	PnP_CONFIG_DMA0_CHAN		0x74
#define	PnP_CONFIG_DMA1_CHAN		0x75
#define	PnP_CONFIG_PP_CONFIG0		0xF0
#define	PnP_CONFIG_PP_CONFIG1		0xF1


/*
 * parallel port interface registers - same for all 1284 modes.
 */
struct info_reg {
	union {
		uint8_t	datar;
		uint8_t	afifo;
	} ir;
	uint8_t dsr;
	uint8_t dcr;
	uint8_t epp_addr;
	uint8_t epp_data;
	uint8_t epp_data32[3];
};

/*
 * additional ECP mode registers.
 */
struct fifo_reg {
	union {
		uint8_t cfifo;
		uint8_t dfifo;
		uint8_t tfifo;
		uint8_t config_a;
	} fr;
	uint8_t config_b;
	uint8_t ecr;
};

/*
 * Values for the ECR field
 *
 * The ECR has 3 read-only bits - bits 0,1,2.  Bits 3,4,5,6,7 are read/write.
 * While writing to this register (ECPPIOC_SETREGS), bits 0,1,2 must be 0.
 * If not, ECPPIOC_SETREGS will return EINVAL.
 */

#define	ECPP_FIFO_EMPTY		0x01	/* 1 when FIFO empty */
#define	ECPP_FIFO_FULL		0x02	/* 1 when FIFO full  */
#define	ECPP_INTR_SRV		0x04

/*
 * When bit is 0, bit will be set to 1
 * and interrupt will be generated if
 * any of the three events occur:
 * (a) TC is reached while DMA enabled
 * (b) If DMA disabled & DCR5 = 0, 8 or more bytes free in FIFO,
 * (c) IF DMA disable & DCR5 = 1, 8 or more bytes to be read in FIFO.
 *
 * When this bit is 1, DMA & (a), (b), (c)
 * interrupts are disabled.
 */

#define	ECPP_DMA_ENABLE		0x08  /* DMA enable =1 */
#define	ECPP_INTR_MASK		0x10  /* intr-enable nErr mask=1 */
#define	ECR_mode_000		0x00  /* PIO CENTRONICS */
#define	ECR_mode_001		0x20  /* PIO NIBBLE */
#define	ECR_mode_010		0x40  /* DMA CENTRONICS */
#define	ECR_mode_011		0x60  /* DMA ECP */
#define	ECR_mode_100		0x80  /* PIO EPP */
#define	ECR_mode_110		0xc0  /* TDMA (TFIFO) */
#define	ECR_mode_111		0xe0  /* Config Mode */

/*
 * 97317 second level configuration registers
 */
struct config2_reg {
	uint8_t		eir;	/* Extended Index Register */
	uint8_t		edr;	/* Extended Data Register */
};

/*
 * Second level offset
 */
#define	PC97317_CONFIG2_CONTROL0	0x00
#define	PC97317_CONFIG2_CONTROL2	0x02
#define	PC97317_CONFIG2_CONTROL4	0x04
#define	PC97317_CONFIG2_PPCONFG0	0x05

/* Cheerio Ebus DMAC */

struct cheerio_dma_reg {
	uint32_t csr;	/* Data Control Status Register */
	uint32_t acr;	/* DMA Address Count Registers */
	uint32_t bcr;	/* DMA Byte Count Register */
};

/*
 * DMA Control and Status Register(DCSR) definitions.  See Cheerio spec
 * for more details
 */
#define	DCSR_INT_PEND 	0x00000001	/* 1= pport or dma interrupts */
#define	DCSR_ERR_PEND 	0x00000002	/* 1= host bus error detected */
#define	DCSR_INT_EN 	0x00000010	/* 1= enable sidewinder/ebus intr */
#define	DCSR_RESET  	0x00000080	/* 1= resets the DCSR */
#define	DCSR_WRITE  	0x00000100  	/* DMA direction; 1 = memory */
#define	DCSR_EN_DMA  	0x00000200  	/* 1= enable DMA */
#define	DCSR_CYC_PEND	0x00000400	/* 1 = DMA pending */
#define	DCSR_EN_CNT 	0x00002000	/* 1= enables byte counter */
#define	DCSR_TC		0x00004000  	/* 1= Terminal Count occurred */
#define	DCSR_CSR_DRAIN 	0x00000000 	/* 1= disable draining */
#define	DCSR_BURST_0    0x00040000 	/* Burst Size bit 0 */
#define	DCSR_BURST_1    0x00080000 	/* Burst Size bit 1 */
#define	DCSR_DIAG	0x00000000 	/* 1= diag enable */
#define	DCSR_TCI_DIS 	0x00800000	/* 1= TC won't cause interrupt */


/* Southbridge support */
struct isaspace {
	uchar_t	isa_reg[0x500];	/* 0x500 regs from isa config space */
};


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_ECPPREG_H */
