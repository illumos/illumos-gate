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

#ifndef _AUDIO_4231_H
#define	_AUDIO_4231_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Header file for the audiocs device driver.
 */

/*
 * Values returned by the AUDIO_GETDEV ioctl()
 */
#define	CS_DEV_NAME		"SUNW,CS4231"
#define	CS_DEV_CONFIG_ONBRD1	"onboard1"
#define	CS_DEV_VERSION		"a"	/* SS5 				*/
#define	CS_DEV_VERSION_A	CS_DEV_VERSION
#define	CS_DEV_VERSION_B	"b"	/* Electron - internal loopback	*/
#define	CS_DEV_VERSION_C	"c"	/* Positron			*/
#define	CS_DEV_VERSION_D	"d"	/* PowerPC - Retired		*/
#define	CS_DEV_VERSION_E	"e"	/* x86 - Retired		*/
#define	CS_DEV_VERSION_F	"f"	/* Tazmo			*/
#define	CS_DEV_VERSION_G	"g"	/* Quark Audio Module		*/
#define	CS_DEV_VERSION_H	"h"	/* Darwin			*/

/*
 * Driver supported configuration information
 */
#define	CS4231_NAME		"audiocs"
#define	CS4231_MOD_NAME		"CS4231 audio driver"

/*
 * Implementation specific header file for the audiocs device driver.
 */

#ifdef _KERNEL

enum {
	CTL_VOLUME = 0,
	CTL_IGAIN,
	CTL_MGAIN,
	CTL_INPUTS,
	CTL_OUTPUTS,
	CTL_MICBOOST,
	CTL_NUM
};

typedef struct CS_engine CS_engine_t;
typedef struct CS_ctrl CS_ctrl_t;
typedef struct CS_state CS_state_t;

/*
 * These are the registers for the APC DMA channel interface to the
 * 4231. One handle provides access the CODEC and the DMA engine's
 * registers.
 */

struct cs4231_apc {
	uint32_t 	dmacsr;		/* APC CSR */
	uint32_t	lpad[3];	/* PAD */
	uint32_t 	dmacva;		/* Capture Virtual Address */
	uint32_t 	dmacc;		/* Capture Count */
	uint32_t 	dmacnva;	/* Capture Next VAddress */
	uint32_t 	dmacnc;		/* Capture next count */
	uint32_t 	dmapva;		/* Playback Virtual Address */
	uint32_t 	dmapc;		/* Playback Count */
	uint32_t 	dmapnva;	/* Playback Next VAddress */
	uint32_t 	dmapnc;		/* Playback Next Count */
};
typedef struct cs4231_apc cs4231_apc_t;

#define	APC_DMACSR	state->cs_regs->apc.dmacsr
#define	APC_DMACVA	state->cs_regs->apc.dmacva
#define	APC_DMACC	state->cs_regs->apc.dmacc
#define	APC_DMACNVA	state->cs_regs->apc.dmacnva
#define	APC_DMACNC	state->cs_regs->apc.dmacnc
#define	APC_DMAPVA	state->cs_regs->apc.dmapva
#define	APC_DMAPC	state->cs_regs->apc.dmapc
#define	APC_DMAPNVA	state->cs_regs->apc.dmapnva
#define	APC_DMAPNC	state->cs_regs->apc.dmapnc

/*
 * APC CSR Register bit definitions
 */

#define	APC_RESET	0x00000001u	/* Reset the DMA engine, R/W */
#define	APC_CDMA_GO	0x00000004u	/* Capture DMA go, R/W */
#define	APC_PDMA_GO	0x00000008u	/* Playback DMA go, R/W */
#define	APC_LOOP_BACK	0x00000010u	/* Loopback, Capture to Play */
#define	APC_COD_PDWN	0x00000020u	/* CODEC power down, R/W */
#define	APC_C_ABORT	0x00000040u	/* Capture abort, R/W */
#define	APC_P_ABORT	0x00000080u	/* Play abort, R/W */
#define	APC_CXI_EN	0x00000100u	/* Capture expired int. enable, R/W */
#define	APC_CXI		0x00000200u	/* Capture expired interrupt, R/W */
#define	APC_CD		0x00000400u	/* Capture next VA dirty, R/O */
#define	APC_CX		0x00000800u	/* Capture expired (pipe empty), R/O */
#define	APC_PMI_EN	0x00001000u	/* Play pipe empty int. enable, R/W */
#define	APC_PD		0x00002000u	/* Playback next VA dirty, R/O */
#define	APC_PM		0x00004000u	/* Play pipe empty, R/O */
#define	APC_PMI		0x00008000u	/* Play pipe empty interrupt, R/W */
#define	APC_EIE		0x00010000u	/* Error interrupt enable, R/W */
#define	APC_CIE		0x00020000u	/* Capture interrupt enable, R/W */
#define	APC_PIE		0x00040000u	/* Playback interrupt enable, R/W */
#define	APC_IE		0x00080000u	/* Interrupt enable, R/W */
#define	APC_EI		0x00100000u	/* Error interrupt, R/W */
#define	APC_CI		0x00200000u	/* Capture interrupt, R/W */
#define	APC_PI		0x00400000u	/* Playback interrupt, R/W */
#define	APC_IP		0x00800000u	/* Interrupt Pending, R/O */
#define	APC_ID		0xff000000u	/* ID bits, set to 7E, R/O */

#define	APC_ID_VALUE	0x7E000000u	/* ID read from CSR */
#define	APC_CLEAR_RESET_VALUE	0x00

#define	APC_PINTR_MASK		(APC_PI|APC_PMI)
#define	APC_CINTR_MASK		(APC_CI|APC_CXI)
#define	APC_COMMON_MASK		(APC_IP|APC_EI)
#define	APC_PINTR_ENABLE	(APC_PIE|APC_PMI_EN)
#define	APC_CINTR_ENABLE	(APC_CIE|APC_CXI_EN)
#define	APC_COMMON_ENABLE	(APC_IE|APC_EIE)

#define	APC_PLAY_ENABLE		(APC_PDMA_GO)
#define	APC_PLAY_DISABLE	(APC_PDMA_GO)
#define	APC_CAP_ENABLE		(APC_CDMA_GO)
#define	APC_CAP_DISABLE		(APC_CDMA_GO)

/*
 * These are the registers for the EBUS2 DMA channel interface to the
 * 4231. One struct per channel for playback and record, therefore there
 * individual handles for the CODEC and the two DMA engines.
 */

struct cs4231_eb2regs {
	uint32_t 	eb2csr;		/* Ebus 2 csr */
	uint32_t 	eb2acr;		/* ebus 2 Addrs */
	uint32_t 	eb2bcr;		/* ebus 2 counts */
};
typedef struct cs4231_eb2regs cs4231_eb2regs_t;

#define	EB2_PLAY_CSR	state->cs_eb2_regs.play->eb2csr
#define	EB2_PLAY_ACR	state->cs_eb2_regs.play->eb2acr
#define	EB2_PLAY_BCR	state->cs_eb2_regs.play->eb2bcr
#define	EB2_REC_CSR	state->cs_eb2_regs.record->eb2csr
#define	EB2_REC_ACR	state->cs_eb2_regs.record->eb2acr
#define	EB2_REC_BCR	state->cs_eb2_regs.record->eb2bcr
#define	EB2_AUXIO_REG	state->cs_eb2_regs.auxio

/*
 * Audio auxio register definitions
 */
#define	EB2_AUXIO_COD_PDWN	0x00000001u	/* power down Codec */

/*
 * EBUS 2 CSR definitions
 */

#define	EB2_INT_PEND		0x00000001u	/* Interrupt pending, R/O */
#define	EB2_ERR_PEND		0x00000002u	/* Error interrupt, R/O */
#define	EB2_DRAIN		0x00000004u	/* FIFO being drained, R/O */
#define	EB2_INT_EN		0x00000010u	/* Enable interrupts, R/W */
#define	EB2_RESET		0x00000080u	/* Reset DMA engine, R/W */
#define	EB2_WRITE		0x00000100u	/* DMA direction (to mem) R/W */
#define	EB2_READ		0x00000000u	/* DMA direction (to dev) R/W */
#define	EB2_EN_DMA		0x00000200u	/* Enable DMA, R/W */
#define	EB2_CYC_PENDING		0x00000400u	/* DMA cycle pending, R/O */
#define	EB2_DIAG_RD_DONE	0x00000800u	/* Diag RD done, R/O */
#define	EB2_DIAG_WR_DONE	0x00001000u	/* Diag WR done, R/O */
#define	EB2_EN_CNT		0x00002000u	/* Enable byte count, R/W */
#define	EB2_TC			0x00004000u	/* Terminal count, R/W */
#define	EB2_DIS_CSR_DRN		0x00010000u	/* Dis. drain with W-CSR, R/W */
#define	EB2_16			0x00000000u 	/* 19,18 == 0,0, R/W */
#define	EB2_32			0x00040000u	/* 19,18 == 0,1, R/W */
#define	EB2_4			0x00080000u	/* 19,18 == 1,0, R/W */
#define	EB2_64			0x000C0000u	/* 19,18 == 1,1, R/W */
#define	EB2_DIAG_EN		0x00100000u	/* DMA diag. enable, R/W */
#define	EB2_DIS_ERR_PEND	0x00400000u	/* Disable Error int., R/W */
#define	EB2_TCI_DIS		0x00800000u	/* Disable TC int., R/W */
#define	EB2_EN_NEXT		0x01000000u	/* Next addr. enabled, R/W */
#define	EB2_DMA_ON		0x02000000u	/* DMA engine enabled, R/O */
#define	EB2_A_LOADED		0x04000000u	/* Address loaded, R/O */
#define	EB2_NA_LOADED		0x08000000u	/* Next add. loaded, R/O */
#define	EB2_DEV_ID		0xf0000000u	/* Device ID -0x0C, R/O */

#define	EB2_ID_VALUE		0xC0000000u	/* ID read from CSR */
#define	EB2_PCLEAR_RESET_VALUE	(EB2_READ|EB2_EN_NEXT|EB2_EN_CNT)
#define	EB2_RCLEAR_RESET_VALUE	(EB2_WRITE|EB2_EN_NEXT|EB2_EN_CNT)

#define	EB2_PLAY_ENABLE		(EB2_EN_DMA|EB2_EN_CNT|EB2_64|\
					EB2_PCLEAR_RESET_VALUE)

#define	EB2_REC_ENABLE		(EB2_EN_DMA|EB2_EN_CNT|EB2_64|\
					EB2_RCLEAR_RESET_VALUE)

#define	EB2_FIFO_DRAIN		(EB2_DRAIN|EB2_CYC_PENDING)

/*
 * Misc. defines
 */
#define	CS4231_REGS			(32)
#define	CS4231_NCOMPONENTS		(1)
#define	CS4231_COMPONENT		(0)
#define	CS4231_PWR_OFF			(0)
#define	CS4231_PWR_ON			(1)
#define	CS4231_TIMEOUT			(100000)
#define	CS4231_300MS			(300*1000)
#define	CS4231_PLAY			0
#define	CS4231_REC			1
#define	CS4231_NFRAMES			4096
#define	CS4231_NFRAGS			2
#define	CS4231_FRAGSZ			((CS4231_NFRAMES / CS4231_NFRAGS) * 4)
#define	CS4231_BUFSZ			(CS4231_NFRAMES * 4)

/*
 * Supported dma engines and the ops vector
 */
enum cs_dmae_types {APC_DMA, EB2_DMA};
typedef enum cs_dmae_types cs_dmae_types_e;

/*
 * Hardware registers
 */
struct cs4231_pioregs {
	uint8_t iar;		/* index address register */
	uint8_t pad1[3];		/* pad */
	uint8_t idr;		/* indexed data register */
	uint8_t pad2[3];		/* pad */
	uint8_t statr;		/* status register */
	uint8_t pad3[3];		/* pad */
	uint8_t piodr;		/* PIO data regsiter */
	uint8_t pad4[3];
};
typedef struct cs4231_pioregs cs4231_pioregs_t;


struct cs4231_eb2 {
	cs4231_eb2regs_t	*play;		/* play EB2 registers */
	cs4231_eb2regs_t	*record;	/* record EB2 registers */
	uint_t			*auxio;		/* aux io - power down */
};
typedef struct cs4231_eb2 cs4231_eb2_t;

struct cs4231_regs {
	cs4231_pioregs_t	codec;		/* CS4231 CODEC registers */
	cs4231_apc_t		apc;		/* gets mapped with CODEC */
};
typedef struct cs4231_regs cs4231_regs_t;

#define	CS4231_IAR	state->cs_regs->codec.iar	/* Index Add. Reg. */
#define	CS4231_IDR	state->cs_regs->codec.idr	/* Index Data Reg. */
#define	CS4231_STATUS	state->cs_regs->codec.statr	/* Status Reg. */
#define	CS4231_PIODR	state->cs_regs->codec.piodr	/* PIO Data Reg. */

/*
 * Misc. state enumerations and structures
 */
struct cs4231_handle {
	ddi_acc_handle_t	cs_codec_hndl;	/* CODEC handle, APC & EB2 */
	ddi_acc_handle_t	cs_eb2_play_hndl; /* EB2 only, play handle */
	ddi_acc_handle_t	cs_eb2_rec_hndl; /* EB2 only, record handle */
	ddi_acc_handle_t	cs_eb2_auxio_hndl; /* EB2 only, auxio handle */
};
typedef struct cs4231_handle cs4231_handle_t;
#define	CODEC_HANDLE	state->cs_handles.cs_codec_hndl
#define	APC_HANDLE	state->cs_handles.cs_codec_hndl
#define	EB2_PLAY_HNDL	state->cs_handles.cs_eb2_play_hndl
#define	EB2_REC_HNDL	state->cs_handles.cs_eb2_rec_hndl
#define	EB2_AUXIO_HNDL	state->cs_handles.cs_eb2_auxio_hndl

/*
 * CS_port_t - per port (playback or record) state
 */
struct CS_engine {
	CS_state_t		*ce_state;
	audio_engine_t		*ce_engine;
	int			ce_num;
	unsigned		ce_syncdir;
	boolean_t		ce_started;
	uint64_t		ce_count;

	caddr_t			ce_kaddr;
	ddi_dma_handle_t	ce_dmah;
	ddi_acc_handle_t	ce_acch;
	uint32_t		ce_paddr;
	uint32_t		ce_curoff;
	int			ce_curidx;

	/* registers (EB2 only) */
	ddi_acc_handle_t	ce_regsh;
	cs4231_eb2regs_t	*ce_eb2regs;	/* EB2 registers */

	/* codec enable */
	uint8_t			ce_codec_en;
};

struct CS_ctrl {
	CS_state_t		*cc_state;
	audio_ctrl_t		*cc_ctrl;
	uint32_t		cc_num;
	uint64_t		cc_val;
};

/*
 * CS_state_t - per instance state and operation data
 */
struct CS_state {
	kmutex_t		cs_lock;	/* state protection lock */
	kcondvar_t		cs_cv;		/* suspend/resume cond. var. */
	dev_info_t		*cs_dip;	/* used by cs4231_getinfo() */
	audio_dev_t		*cs_adev;	/* audio device state */

	cs_dmae_types_e		cs_dma_engine;	/* dma engine for this h/w */
	struct cs4231_dma_ops	*cs_dma_ops;	/* dma engine ops vector */
	cs4231_regs_t		*cs_regs;	/* hardware registers */
	cs4231_eb2_t		cs_eb2_regs;	/* eb2 DMA registers */
	cs4231_handle_t		cs_handles;	/* hardware handles */

	boolean_t		cs_suspended;	/* power management state */
	boolean_t		cs_powered;	/* device powered up? */

	CS_engine_t		*cs_engines[2];

	boolean_t		cs_revA;	/* B_TRUE if Rev A CODEC */
	uint8_t			cs_save[CS4231_REGS];	/* PM reg. storage */

	/*
	 * Control related fields.
	 */
	uint64_t		cs_imask;
	uint64_t		cs_omask;
	uint64_t		cs_omod;	/* modifiable ports */

	CS_ctrl_t		*cs_ogain;
	CS_ctrl_t		*cs_igain;
	CS_ctrl_t		*cs_micboost;
	CS_ctrl_t		*cs_mgain;
	CS_ctrl_t		*cs_outputs;
	CS_ctrl_t		*cs_inputs;
};

/*
 * DMA ops vector definition
 */
struct cs4231_dma_ops {
	char	*dma_device;
	ddi_dma_attr_t	*cs_dma_attr;
	int	(*cs_dma_map_regs)(CS_state_t *);
	void	(*cs_dma_unmap_regs)(CS_state_t *);
	void	(*cs_dma_reset)(CS_state_t *);
	int 	(*cs_dma_start)(CS_engine_t *);
	void	(*cs_dma_stop)(CS_engine_t *);
	void	(*cs_dma_power)(CS_state_t *, int);
	void	(*cs_dma_reload)(CS_engine_t *);
	uint32_t	(*cs_dma_addr)(CS_engine_t *);
};
typedef struct cs4231_dma_ops cs4231_dma_ops_t;

extern cs4231_dma_ops_t cs4231_apcdma_ops;
extern cs4231_dma_ops_t cs4231_eb2dma_ops;

#define	CS4231_DMA_MAP_REGS(S)		((S)->cs_dma_ops->cs_dma_map_regs)(S)
#define	CS4231_DMA_UNMAP_REGS(S)	((S)->cs_dma_ops->cs_dma_unmap_regs)(S)
#define	CS4231_DMA_RESET(S)		((S)->cs_dma_ops->cs_dma_reset)(S)
#define	CS4231_DMA_START(S, E)		((S)->cs_dma_ops->cs_dma_start)(E)
#define	CS4231_DMA_STOP(S, E)		((S)->cs_dma_ops->cs_dma_stop)(E)
#define	CS4231_DMA_POWER(S, L)		((S)->cs_dma_ops->cs_dma_power)(S, L)
#define	CS4231_DMA_ATTR(S)		((S)->cs_dma_ops->cs_dma_attr)
#define	CS4231_DMA_RELOAD(S, E)		((S)->cs_dma_ops->cs_dma_reload)(E)
#define	CS4231_DMA_ADDR(S, E)		((S)->cs_dma_ops->cs_dma_addr)(E)

/*
 * Useful bit twiddlers
 */
#define	CS4231_RETRIES		10

#define	OR_SET_WORD(handle, addr, val)					\
	ddi_put32((handle), (uint_t *)(addr),				\
		(ddi_get32((handle), (uint_t *)(addr)) | (uint_t)(val)))

#define	AND_SET_WORD(handle, addr, val)					\
	ddi_put32((handle), (uint_t *)(addr),				\
		(ddi_get32((handle), (uint_t *)(addr)) & (uint_t)(val)))

/*
 * CS4231 Register Set Definitions
 */
/* Index Address Register */
#define	IAR_ADDRESS_MASK	0x1f	/* mask for index addresses, R/W */
#define	IAR_TRD			0x20	/* Transfer Request Disable, R/W */
#define	IAR_MCE			0x40	/* Mode Change Enable, R/W */
#define	IAR_INIT		0x80	/* 4231 init cycle, R/O */

/* Status Register */
#define	STATUS_INT		0x01	/* Interrupt status, R/O */
#define	STATUS_PRDY		0x02	/* Playback Data Ready */
#define	STATUS_PLR		0x04	/* Playback Left/Right sample */
#define	STATUS_PUL		0x08	/* Playback Upper/Lower byte */
#define	STATUS_SER		0x10	/* Sample Error, see Index 24 */
#define	STATUS_CRDY		0x20	/* Capture Data Ready */
#define	STATUS_CLR		0x40	/* Capture Left/Right sample */
#define	STATUS_CUL		0x80	/* Capture Upper/Lower byte */
#define	STATUS_RESET		0x00	/* Reset the status register */

/* Index 00 - Left ADC Input Control, Modes 1&2 */
#define	LADCI_REG		0x00	/* Left ADC Register */
#define	LADCI_GAIN_MASK		0x0f	/* Left gain mask, 1.5 dB/step */
#define	LADCI_LMGE		0x20	/* Left Mic Gain Enable, 20 dB stage */
#define	LADCI_LLINE		0x00	/* Left Line in enable */
#define	LADCI_LAUX1		0x40	/* Left AUX1 in enable */
#define	LADCI_LMIC		0x80	/* Left MIC in enable */
#define	LADCI_LLOOP		0xc0	/* Left Loopback enable */
#define	LADCI_IN_MASK		0xc0	/* Left input mask */
#define	LADCI_VALID_MASK	0xef	/* Left valid bits mask */

/* Index 01 - Right ADC Input Control, Modes 1&2 */
#define	RADCI_REG		0x01	/* Right ADC Register */
#define	RADCI_GAIN_MASK		0x0f	/* Right gain mask, 1.5 dB/step */
#define	RADCI_RMGE		0x20	/* Right Mic Gain Enable, 20 dB stage */
#define	RADCI_RLINE		0x00	/* Right Line in enable */
#define	RADCI_RAUX1		0x40	/* Right AUX1 in enable */
#define	RADCI_RMIC		0x80	/* Right MIC in enable */
#define	RADCI_RLOOP		0xc0	/* Right Loopback enable */
#define	RADCI_IN_MASK		0xc0	/* Right input mask */
#define	RADCI_VALID_MASK	0xef	/* Right valid bits mask */

/* Index 02 - Left Aux #1 Input Control, Modes 1&2 */
#define	LAUX1_REG		0x02	/* Left Aux#1 Register */
#define	LAUX1_GAIN_MASK		0x1f	/* Left Aux#1 gain mask, 1.5 dB/step */
#define	LAUX1_LX1M		0x80	/* Left Aux#1 mute */
#define	LAUX1_UNITY_GAIN	0x08	/* Left Aux#1 unity gain */
#define	LAUX1_VALID_MASK	0x9f	/* Left valid bits mask */

/* Index 03 - Right Aux #1 Input Control, Modes 1&2 */
#define	RAUX1_REG		0x03	/* Right Aux#1 Register */
#define	RAUX1_GAIN_MASK		0x1f	/* Right Aux#1 gain mask, 1.5 dB/step */
#define	RAUX1_RX1M		0x80	/* Right Aux#1 mute */
#define	RAUX1_UNITY_GAIN	0x08	/* Right Aux#1 unity gain */
#define	RAUX1_VALID_MASK	0x9f	/* Right valid bits mask */

/* Index 04 - Left Aux #2 Input Control, Modes 1&2 */
#define	LAUX2_REG		0x04	/* Left Aux#2 Register */
#define	LAUX2_GAIN_MASK		0x1f	/* Left Aux#2 gain mask, 1.5 dB/step */
#define	LAUX2_LX2M		0x80	/* Left Aux#2 mute */
#define	LAUX2_UNITY_GAIN	0x08	/* Left Aux#2 unity gain */
#define	LAUX2_VALID_MASK	0x9f	/* Left valid bits mask */

/* Index 05 - Right Aux #2 Input Control, Modes 1&2 */
#define	RAUX2_REG		0x05	/* Right Aux#2 Register */
#define	RAUX2_GAIN_MASK		0x1f	/* Right Aux#2 gain mask, 1.5 dB/step */
#define	RAUX2_RX2M		0x80	/* Right Aux#2 mute */
#define	RAUX2_UNITY_GAIN	0x08	/* Right Aux#2 unity gain */
#define	RAUX2_VALID_MASK	0x9f	/* Right valid bits mask */

/* Index 06 - Left DAC Output Control, Modes 1&2 */
#define	LDACO_REG		0x06	/* Left DAC Register */
#define	LDACO_ATTEN_MASK	0x3f	/* Left attenuation mask, 1.5 dB/setp */
#define	LDACO_LDM		0x80	/* Left mute */
#define	LDACO_MID_GAIN		0x11	/* Left DAC mid gain */
#define	LDAC0_VALID_MASK	0xbf	/* Left valid bits mask */

/* Index 07 - Right DAC Output Control, Modes 1&2 */
#define	RDACO_REG		0x07	/* Right DAC Register */
#define	RDACO_ATTEN_MASK	0x3f	/* Right atten. mask, 1.5 dB/setp */
#define	RDACO_RDM		0x80	/* Right mute */
#define	RDACO_MID_GAIN		0x11	/* Right DAC mid gain */
#define	RDAC0_VALID_MASK	0xbf	/* Right valid bits mask */

/* Index 08 - Sample Rate and Data Format, Mode 2 only */
#define	FSDF_REG		0x08	/* Sample Rate & Data Format Register */
#define	FS_5510			0x01	/* XTAL2, Freq. Divide #0 */
#define	FS_6620			0x0f	/* XTAL2, Freq. Divide #7 */
#define	FS_8000			0x00	/* XTAL1, Freq. Divide #0 */
#define	FS_9600			0x0e	/* XTAL2, Freq. Divide #7 */
#define	FS_11025		0x03	/* XTAL2, Freq. Divide #1 */
#define	FS_16000		0x02	/* XTAL1, Freq. Divide #1 */
#define	FS_18900		0x05	/* XTAL2, Freq. Divide #2 */
#define	FS_22050		0x07	/* XTAL2, Freq. Divide #3 */
#define	FS_27420		0x04	/* XTAL1, Freq. Divide #2 */
#define	FS_32000		0x06	/* XTAL1, Freq. Divide #3 */
#define	FS_33075		0x0d	/* XTAL2, Freq. Divide #6 */
#define	FS_37800		0x09	/* XTAL2, Freq. Divide #4 */
#define	FS_44100		0x0b	/* XTAL2, Freq. Divide #5 */
#define	FS_48000		0x0c	/* XTAL1, Freq. Divide #6 */
#define	PDF_STEREO		0x10	/* Stereo Playback */
#define	PDF_MONO		0x00	/* Mono Playback */
#define	PDF_LINEAR8		0x00	/* Linear, 8-bit unsigned */
#define	PDF_ULAW8		0x20	/* u-Law, 8-bit companded */
#define	PDF_LINEAR16LE		0x40	/* Linear, 16-bit signed, little end. */
#define	PDF_ALAW8		0x60	/* A-Law, 8-bit companded */
#define	PDF_ADPCM4		0xa0	/* ADPCM, 4-bit, IMA compatible */
#define	PDF_LINEAR16BE		0xc0	/* Linear, 16-bit signed, big endian */
#define	FSDF_VALID_MASK		0xff	/* Valid bits mask */
#ifdef	_BIG_ENDIAN
#define	PDF_LINEAR16NE		PDF_LINEAR16BE
#else
#define	PDF_LINEAR16NE		PDF_LINEAR16LE
#endif

/* Index 09 - Interface Configuration, Mode 1&2 */
#define	INTC_REG		0x09	/* Interrupt Configuration Register */
#define	INTC_PEN		0x01	/* Playback enable */
#define	INTC_CEN		0x02	/* Capture enable */
#define	INTC_SDC		0x04	/* Single DMA channel */
#define	INTC_DDC		0x00	/* Dual DMA channels */
#define	INTC_ACAL		0x08	/* Auto-Calibrate Enable */
#define	INTC_PPIO		0x40	/* Playback vi PIO */
#define	INTC_PDMA		0x00	/* Playback vi DMA */
#define	INTC_CPIO		0x80	/* Capture vi PIO */
#define	INTC_CDMA		0x00	/* Capture vi DMA */
#define	INTC_VALID_MASK		0xcf	/* Valid bits mask */

/* Index 10 - Pin Control, Mode 1&2 */
#define	PC_REG			0x0a	/* Pin Control Register */
#define	PC_IEN			0x02	/* Interrupt Enable */
#define	PC_DEN			0x04	/* Dither Enable */
#define	PC_XCTL0		0x40	/* External control 0 */
#define	PC_LINE_OUT_MUTE	0x40	/* Line Out Mute */
#define	PC_XCTL1		0x80	/* External control 1 */
#define	PC_HEADPHONE_MUTE	0x80	/* Headphone Mute */
#define	PC_VALID_MASK		0xca	/* Valid bits mask */

/* Index 11 - Error Status and Initialization, Mode 1&2 */
#define	ESI_REG			0x0b	/* Error Status & Init. Register */
#define	ESI_ORL_MASK		0x03	/* Left ADC Overrange */
#define	ESI_ORR_MASK		0x0c	/* Right ADC Overrange */
#define	ESI_DRS			0x10	/* DRQ status */
#define	ESI_ACI			0x20	/* Auto-Calibrate In Progress */
#define	ESI_PUR			0x40	/* Playback Underrun */
#define	ESI_COR			0x80	/* Capture Overrun */
#define	ESI_VALID_MASK		0xff	/* Valid bits mask */

/* Index 12 - Mode and ID, Modes 1&2 */
#define	MID_REG			0x0c	/* Mode and ID Register */
#define	MID_ID_MASK		0x0f	/* CODEC ID */
#define	MID_MODE2		0x40	/* Mode 2 enable */
#define	MID_VALID_MASK		0xcf	/* Valid bits mask */

/* Index 13 - Loopback Control, Modes 1&2 */
#define	LC_REG			0x0d	/* Loopback Control Register */
#define	LC_LBE			0x01	/* Loopback Enable */
#define	LC_ATTEN_MASK		0xfc	/* Loopback attenuation mask */
#define	LC_OFF			0x00	/* Loopback off */
#define	LC_VALID_MASK		0xfd	/* Valid bits mask */

/* Index 14 - Playback Upper Base, Mode 2 only */
#define	PUB_REG			0x0e	/* Playback Upper Base Register */
#define	PUB_VALID_MASK		0xff	/* Valid bits mask */

/* Index 15 - Playback Lower Base, Mode 2 only */
#define	PLB_REG			0x0f	/* Playback Lower Base Register */
#define	PLB_VALID_MASK		0xff	/* Valid bits mask */

/* Index 16 - Alternate Feature Enable 1, Mode 2 only */
#define	AFE1_REG		0x10	/* Alternate Feature Enable 1 Reg */
#define	AFE1_DACZ		0x01	/* DAC Zero */
#define	AFE1_TE			0x40	/* Timer Enable */
#define	AFE1_OLB		0x80	/* Output Level Bit, 1=2.8Vpp, 0=2Vpp */
#define	AFE1_VALID_MASK		0xc1	/* Valid bits mask */

/* Index 17 - Alternate Feature Enable 2, Mode 2 only */
#define	AFE2_REG		0x11	/* Alternate Feature Enable 2 Reg */
#define	AFE2_HPF		0x01	/* High Pass Filter - DC blocking */
#define	AFE2_VALID_MASK		0x01	/* Valid bits mask */

/* Index 18 - Left Line Input Control, Mode 2 only */
#define	LLIC_REG		0x12	/* Left Line Input Control Register */
#define	LLIC_MIX_GAIN_MASK	0x1f	/* Left Mix Gain Mask, 1.5 dB/step */
#define	LLIC_LLM		0x80	/* Left Line Mute */
#define	LLIC_UNITY_GAIN		0x08	/* Left unit gain */
#define	LLIC_VALID_MASK		0x9f	/* Left valid bits mask */

/* Index 19 - Right Line Input Control, Mode 2 only */
#define	RLIC_REG		0x13	/* Right Line Input Control Register */
#define	RLIC_MIX_GAIN_MASK	0x1f	/* Right Mix Gain Mask, 1.5 dB/step */
#define	RLIC_RLM		0x80	/* Right Line Mute */
#define	RLIC_UNITY_GAIN		0x08	/* Right unit gain */
#define	RLIC_VALID_MASK		0x9f	/* Right valid bits mask */

/* Index 20 - Timer Lower Byte, Mode 2 only */
#define	TLB_REG			0x14	/* Timer Lower Byte Register */
#define	TLB_VALID_MASK		0xff	/* Valid bits mask */

/* Index 21 - Timer Upper Byte, Mode 2 only */
#define	TUB_REG			0x15	/* Timer Upper Byte Register */
#define	TUB_VALID_MASK		0xff	/* Valid bits mask */

/* Index 22 and 23 are reserved */

/* Index 24 - Alternate Feature Status, Mode 2 only */
#define	AFS_REG			0x18	/* Alternate Feature Status Register */
#define	AFS_PU			0x01	/* Playback Underrun */
#define	AFS_PO			0x02	/* Playback Overrun */
#define	AFS_CO			0x04	/* Capture Overrun */
#define	AFS_CU			0x08	/* Capture Underrun */
#define	AFS_PI			0x10	/* Playback Interrupt */
#define	AFS_CI			0x20	/* Capture Interrupt */
#define	AFS_TI			0x40	/* Timer Interrupt */
#define	AFS_RESET_STATUS	0x00	/* Reset the status register */
#define	AFS_VALID_MASK		0x7f	/* Valid bits mask */

/* Index 25 - Version and ID, Mode 2 only */
#define	VID_REG			0x19	/* Version and ID Register */
#define	VID_CID_MASK		0x07	/* Chip ID Mask */
#define	VID_VERSION_MASK	0xe0	/* Version number Mask */
#define	VID_A			0x20	/* Version A */
#define	VID_CDE			0x80	/* Versions C, D or E */
#define	VID_VALID_MASK		0xe7	/* Valid bits mask */

/* Index 26 - Mono I/O Control, Mode 2 only */
#define	MIOC_REG		0x1a	/* Mono I/O Control Register */
#define	MIOC_MI_ATTEN_MASK	0x0f	/* Mono In Attenuation Mask */
#define	MIOC_MOM		0x40	/* Mono Out Mute */
#define	MIOC_MONO_SPKR_MUTE	0x40	/* Mono (internal) speaker mute */
#define	MIOC_MIM		0x80	/* Mono In Mute */
#define	MIOC_VALID_MASK		0xcf	/* Valid bits mask */

/* Index 27 is reserved */

/* Index 28 - Capture Data Format, Mode 2 only */
#define	CDF_REG			0x1c	/* Capture Date Foramt Register */
#define	CDF_STEREO		0x10	/* Stereo Capture */
#define	CDF_MONO		0x00	/* Mono Capture */
#define	CDF_LINEAR8		0x00	/* Linear, 8-bit unsigned */
#define	CDF_ULAW8		0x20	/* u-Law, 8-bit companded */
#define	CDF_LINEAR16LE		0x40	/* Linear, 16-bit signed, little end. */
#define	CDF_ALAW8		0x60	/* A-Law, 8-bit companded */
#define	CDF_ADPCM4		0xa0	/* ADPCM, 4-bit, IMA compatible */
#define	CDF_LINEAR16BE		0xc0	/* Linear, 16-bit signed, big endian */
#define	CDF_VALID_MASK		0xf0	/* Valid bits mask */
#ifdef	_BIG_ENDIAN
#define	CDF_LINEAR16NE		CDF_LINEAR16BE
#else
#define	CDF_LINEAR16NE		CDF_LINEAR16LE
#endif

/* Index 29 is reserved */

/* Index 30 - Capture Upper Base, Mode 2 only */
#define	CUB_REG			0x1e	/* Capture Upper Base Register */
#define	CUB_VALID_MASK		0xff	/* Valid bits mask */

/* Index 31 - Capture Lower Base, Mode 2 only */
#define	CLB_REG			0x1f	/* Capture Lower Base Register */
#define	CLB_VALID_MASK		0xff	/* Valid bits mask */

#endif	/* _KERNEL */

#ifdef __cplusplus
}
#endif

#endif	/* _AUDIO_4231_H */
