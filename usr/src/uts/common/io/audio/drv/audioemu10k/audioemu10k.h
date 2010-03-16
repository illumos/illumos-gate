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

/*
 * Purpose: Definitions for the SB Live/Audigy driver
 */
/*
 * Copyright (C) 4Front Technologies 1996-2009.
 */
#ifndef	EMU10K_H
#define	EMU10K_H

#define	PCI_VENDOR_ID_CREATIVE		0x1102
#define	PCI_DEVICE_ID_SBLIVE		0x0002
#define	PCI_DEVICE_ID_AUDIGY		0x0004
#define	PCI_DEVICE_ID_AUDIGYVALUE	0x0008

#define	SAMPLE_RATE		48000

#define	EMU10K_NAME		"audioemu10k"

#define	EMU10K_NUM_PORTC	2
#define	EMU10K_PLAY		0
#define	EMU10K_REC		1

#define	EMU10K_NUM_FRAGS	(2*4)	/* Must be multiple of 2 */

#define	EMU10K_MAX_INTRS	512
#define	EMU10K_MIN_INTRS	10
#define	EMU10K_INTRS		100

#define	FRAGMENT_FRAMES		512

#define	EMU10K1_MAGIC		0xe10001
#define	EMU10K2_MAGIC		0xe10002

/* Audio */

#define	DMABUF_SIZE		(256 * 1024)

#define	AUDIO_MAXVOICE		(2*EMU10K_NUM_PORTC)
/* Audio buffer + silent page */
#define	AUDIO_MEMSIZE		(EMU10K_NUM_PORTC*DMABUF_SIZE+4096)

/* Wall clock register */
#define	WC			0x10

/* Hardware config register */
#define	HCFG			0x14
#define	HCFG_CODECFORMAT_MASK	0x00070000	/* CODEC format */
#define	HCFG_CODECFORMAT_AC97	0x00000000	/* AC97 CODEC format */
#define	HCFG_CODECFORMAT_I2S	0x00010000	/* I2S CODEC format */
#define	HCFG_GPINPUT0		0x00004000	/* External pin112 */
#define	HCFG_GPINPUT1		0x00002000	/* External pin110 */
#define	HCFG_GPOUTPUT_MASK	0x00001c00	/* Controllable pins */
#define	HCFG_GPOUT0		0x00001000	/* enable dig out on 5.1 */
#define	HCFG_GPOUT1		0x00000800	/* IR */
#define	HCFG_GPOUT2		0x00000400	/* IR */
#define	HCFG_JOYENABLE		0x00000200	/* Internal joystick enable */
#define	HCFG_PHASETRACKENABLE	0x00000100	/* Phase tracking enable */
#define	HCFG_AC3ENABLE_MASK	0x0x0000e0	/* AC3 async input control */
#define	HCFG_AC3ENABLE_ZVIDEO	0x00000080	/* Chan 0/1 replace ZVIDEO  */
#define	HCFG_AC3ENABLE_CDSPDIF	0x00000040	/* Chan 0/1 replace CDSPDIF */
#define	HCFG_AC3ENABLE_GPSPDIF	0x00000020	/* Chan 0/1 replace GPSPDIF */
#define	HCFG_AUTOMUTE		0x00000010
#define	HCFG_LOCKSOUNDCACHE	0x00000008
#define	HCFG_LOCKTANKCACHE_MASK	0x00000004
#define	HCFG_LOCKTANKCACHE	0x01020014
#define	HCFG_MUTEBUTTONENABLE	0x00000002	/* Mute can clear audioenable */
#define	HCFG_AUDIOENABLE	0x00000001	/* Codecs can send data */
#define	A_HCFG_VMUTE		0x00004000
#define	A_HCFG_AUTOMUTE		0x00008000
#define	A_HCFG_XM		0x00040000	/* Xtended address mode */

/*
 * GPIO bit definitions (global register 0x18) for Audigy.
 */

#define	A_IOCFG_GPOUT0		0x0044	/* analog/digital? */
#define	A_IOCFG_GPOUT1		0x0002	/* IR */
#define	A_IOCFG_GPOUT2		0x0001	/* IR */

/* Status bits (read only) */
#define	GPIO_VERSAPLUGGED	0x2000	/* Center/LFE/digital */
#define	GPIO_FRONTPLUGGED	0x4000
#define	GPIO_REARPLUGGED	0x8000
#define	GPIO_HEADPHPLUGGED	0x0100
#define	GPIO_ANALOG_MUTE	0x0040
#define	GPIO_DIGITAL_ENABLE	0x0004	/* Cen/lfe (0) or digital (1) switch */

#define	FILL_PAGE_MAP_ENTRY(e, v)					\
	ddi_put32(devc->pt_acch, devc->page_map + e, ((v) << 1) | (e));

/*
 * Audio block registers
 */

#define	CPF		0x000	/* DW:cnl   Current pitch and fraction */
#define	CPF_CURRENTPITCH_MASK		0xffff0000
#define	CPF_CURRENTPITCH		0x10100000
#define	CPF_STEREO_MASK			0x00008000
#define	CPF_STOP_MASK			0x00004000
#define	CPF_FRACADDRESS_MASK		0x00003fff


#define	PTAB		0x001	/* DW:cnl   Pitch target and sends A and B */
#define	PTRX_PITCHTARGET_MASK		0xffff0000
#define	PTRX_PITCHTARGET		0x10100001
#define	PTRX_FXSENDAMOUNT_A_MASK	0x0000ff00
#define	PTRX_FXSENDAMOUNT_A		0x08080001
#define	PTRX_FXSENDAMOUNT_B_MASK	0x000000ff
#define	PTRX_FXSENDAMOUNT_B		0x08000001


#define	CVCF		0x002	/* DW:cnl   Curr vol and curr filter cutoff */
#define	VTFT		0x003	/* DW:cnl   Volume tgt and filter cutoff tgt */
#define	Z2		0x004	/* DW:cnl   Filter delay memory 2 */
#define	Z1		0x005	/* DW:cnl   Filter delay memory 1 */
#define	SCSA		0x006	/* DW:cnl   Send C and Start addr */
#define	SDL		0x007	/* DW:cnl   Send D and Loop addr */
#define	QKBCA		0x008	/* DW:cnl   Filter Q, ROM, etc */
#define	CCR		0x009
#define	CCR_CACHEINVALIDSIZE		0x07190009
#define	CCR_CACHEINVALIDSIZE_MASK	0xfe000000
#define	CCR_CACHELOOPFLAG		0x01000000
#define	CCR_INTERLEAVEDSAMPLES		0x00800000
#define	CCR_WORDSIZEDSAMPLES		0x00400000
#define	CCR_READADDRESS			0x06100009
#define	CCR_READADDRESS_MASK		0x003f0000
#define	CCR_LOOPINVALSIZE		0x0000fe00
#define	CCR_LOOPFLAG			0x00000100
#define	CCR_CACHELOOPADDRHI		0x000000ff

#define	CLP		0x00a
#define	SRHE		0x07c
#define	STHE		0x07d
#define	SRDA		0x07e
#define	STDA		0x07f
#define	L_FXRT		0x00b
#define	FXRT		0x00b	/* W:cnl */
#define	MAPA		0x00c
#define	MAPB		0x00d
#define	VEV		0x010	/* W:cnl */
#define	VEHA		0x011	/* W:cnl */
#define	VEDS		0x012	/* W:cnl */
#define	MLV		0x013	/* W:cnl */
#define	MEV		0x014	/* W:cnl */
#define	MEHA		0x015	/* W:cnl */
#define	MEDS		0x016	/* W:cnl */
#define	VLV		0x017	/* W:cnl */
#define	IP		0x018	/* W:cnl */
#define	IFA		0x019	/* W:cnl */
#define	PEFE		0x01a	/* W:cnl */
#define	PEFE_PITCHAMOUNT_MASK	0x0000ff00	/* Pitch envlope amount */
#define	PEFE_PITCHAMOUNT	0x0808001a
#define	PEFE_FILTERAMOUNT_MASK	0x000000ff	/* Filter envlope amount */
#define	PEFE_FILTERAMOUNT	0x0800001a

#define	VFM		0x01b	/* W:cnl */
#define	TMFQ		0x01c	/* W:cnl */
#define	VVFQ		0x01d	/* W:cnl */
#define	TMPE		0x01e	/* W:cnl */
#define	CD0		0x020	/* DW:cnl (16 registers) */
#define	PTBA		0x040	/* DW:nocnl */
#define	TCBA		0x041	/* DW:nocnl */
#define	ADCSR		0x042	/* B:nocnl */
#define	FXWC		0x043	/* DW:nocnl */
#define	TCBS		0x044	/* B:nocnl */
#define	MBA		0x045	/* DW:nocnl */
#define	ADCBA		0x046	/* DW:nocnl */
#define	FXBA		0x047	/* DW:nocnl */

#define	MBS		0x049	/* B:nocnl */
#define	ADCBS		0x04a	/* B:nocnl */
#define	FXBS		0x04b	/* B:nocnl */
#define	CSBA	0x4c
#define	CSDC	0x4d
#define	CSFE	0x4e
#define	CSHG	0x4f
#define	CDCS		0x050	/* DW:nocnl */
#define	GPSCS		0x051	/* DW:nocnl */
#define	DBG		0x052	/* DW:nocnl */
#define	AUDIGY_DBG	0x053	/* DW:nocnl */
#define	SCS0		0x054	/* DW:nocnl */
#define	SCS1		0x055	/* DW:nocnl */
#define	SCS2		0x056	/* DW:nocnl */
#define	CLIEL		0x058	/* DW:nocnl */
#define	CLIEH		0x059	/* DW:nocnl */
#define	CLIPL		0x05a	/* DW:nocnl */
#define	CLIPH		0x05b	/* DW:nocnl */
#define	SOLL		0x05c	/* DW:nocnl */
#define	SOLH		0x05d	/* DW:nocnl */
#define	SOC		0x05e	/* DW:nocnl */
#define	AC97SLOT	0x05f
#define	AC97SLOT_REAR_RIGHT	0x01
#define	AC97SLOT_REAR_LEFT	0x02
#define	AC97SLOT_CENTER		0x10
#define	AC97SLOT_LFE		0x20
#define	CDSRCS		0x060	/* DW:nocnl */
#define	GPSRCS		0x061	/* DW:nocnl */
#define	ZVSRCS		0x062	/* DW:nocnl */
#define	ADCIDX		0x063	/* W:nocnl */
#define	MIDX		0x064	/* W:nocnl */
#define	FXIDX		0x065	/* W:nocnl */

/* Half loop interrupt registers (audigy only) */
#define	HLIEL		0x066	/* DW:nocnl */
#define	HLIEH		0x067	/* DW:nocnl */
#define	HLIPL		0x068	/* DW:nocnl */
#define	HLIPH		0x069	/* DW:nocnl */
#define	GPR0	((devc->feature_mask&SB_LIVE)? 0x100:0x400)	/* DW:nocnl */
#define	TMA0		0x300	/* Tank memory */
#define	UC0	((devc->feature_mask&SB_LIVE) ? 0x400:0x600)	/* DSM ucode */

/* Interrupt pending register */
#define	INTPEND	0x08
#define		INT_VI		0x00100000
#define		INT_VD		0x00080000
#define		INT_MU		0x00040000
#define		INT_MF		0x00020000
#define		INT_MH		0x00010000
#define		INT_AF		0x00008000
#define		INT_AH		0x00004000
#define		INT_IT		0x00000200
#define		INT_TX		0x00000100
#define		INT_RX		0x00000080
#define		INT_CL		0x00000040
/* Interrupt enable register */
#define	IE	0x0c
#define		IE_VI		0x00000400
#define		IE_VD		0x00000200
#define		IE_MU		0x00000100
#define		IE_MB		0x00000080
#define		IE_AB		0x00000040
#define		IE_IT		0x00000004
#define		IE_TX		0x00000002
#define		IE_RX		0x00000001

/* Interval timer register */
#define	TIMR		0x1a

/* EMU10K2 MIDI UART */
#define	MUADAT		0x070
#define	MUACMD		0x071
#define	MUASTAT		MUACMD

/* EMU10K2 S/PDIF recording buffer */
#define	SPRI		0x6a
#define	SPRA		0x6b
#define	SPRC		0x6c

#define	EHC		0x76	/* Audigy 2 */

#define	SRHE	0x07c
#define	STHE	0x07d
#define	SRDA	0x07e

#define	ROM0		0x00000000	/* interpolation ROM 0 */
#define	ROM1		0x02000000	/* interpolation ROM 1 */
#define	ROM2		0x04000000	/* interpolation ROM 2 */
#define	ROM3		0x06000000	/* interpolation ROM 3 */
#define	ROM4		0x08000000	/* interpolation ROM 4 */
#define	ROM5		0x0A000000	/* interpolation ROM 5 */
#define	ROM6		0x0C000000	/* interpolation ROM 6 */
#define	ROM7		0x0E000000	/* interpolation ROM 7 */
#define	BYTESIZE	0x01000000	/* byte sound memory */

#define	MAX_GPR	256

/* See feature_mask below */
#define	SB_LIVE		1
#define	SB_AUDIGY	2
#define	SB_AUDIGY2	4
#define	SB_AUDIGY2VAL	8
#define	SB_51		0x10
#define	SB_71		0x20
#define	SB_INVSP	0x40	/* invert shared spdif switch */
#define	SB_NOEXP	0x80	/* no support for Live! Drive or expansion */

#define	LEFT_CH		0
#define	RIGHT_CH	1

#ifdef	_KERNEL

typedef struct _emu10k_devc_t emu10k_devc_t;
typedef struct _emu10k_portc_t emu10k_portc_t;


typedef enum {
	CTL_VOLUME = 0,
	CTL_FRONT,
	CTL_SURROUND,
	CTL_CENTER,
	CTL_LFE,
	CTL_SIDE,
	CTL_HEADPH,

	CTL_RECGAIN,
	CTL_RECSRC,
	CTL_AC97SRC,

	/* monitor source values */
	CTL_AC97,
	CTL_DIGCD,
	CTL_SPD1,
	CTL_SPD2,
	CTL_LINE2,
	CTL_AUX2,

	CTL_JACK3,

	/* this one must be last */
	CTL_MAX,
} emu10k_ctrl_id_t;

typedef struct _emu10k_ctrl {
	emu10k_devc_t	*devc;
	audio_ctrl_t	*ctrl;
	int		gpr_num;
	uint64_t	val;
} emu10k_ctrl_t;

typedef struct _emu10k_gpr {
	boolean_t	valid;
	uint32_t	value;
} emu10k_gpr_t;

struct _emu10k_portc_t {
	emu10k_devc_t		*devc;
	audio_engine_t		*engine;

	/* Helper functions */
	void			(*update_port)(emu10k_portc_t *);
	void			(*reset_port)(emu10k_portc_t *);
	void			(*stop_port)(emu10k_portc_t *);
	void			(*start_port)(emu10k_portc_t *);

	int			channels;

	boolean_t		started;
	boolean_t		active;
	unsigned		nframes;
	unsigned		nfrags;
	unsigned		fragsz;

	ddi_dma_handle_t	buf_dmah;	/* dma for buffers */
	ddi_acc_handle_t	buf_acch;
	uint32_t		buf_paddr;
	caddr_t			buf_kaddr;
	size_t			buf_size;
	/* Start of loop within the internal memory space */
	uint32_t		memptr;
	int			syncdir;
	/* Position & timing */
	uint64_t		count;
	uint32_t		pos;
	int		dopos;
};

struct _emu10k_devc_t {
	dev_info_t		*dip;
	audio_dev_t		*adev;
	ddi_acc_handle_t	pcih;
	ddi_acc_handle_t	regsh;
	caddr_t			regs;
	kmutex_t		mutex;

	/*
	 * Page table
	 */
	ddi_dma_handle_t	pt_dmah;	/* dma for page_tablefers */
	ddi_acc_handle_t	pt_acch;
	uint32_t		pt_paddr;
	caddr_t			pt_kaddr;
	uint32_t		*page_map;	/* up to 8k ptrs to 4k pages */


	/*
	 * Silent page used by voices that don't play anything.
	 */
	ddi_dma_handle_t	silence_dmah;	/* dma for silencefers */
	ddi_acc_handle_t	silence_acch;
	uint32_t		silence_paddr;
	caddr_t			silence_kaddr;

	/*
	 * Device feature mask tells which kind of features are
	 * supported by the hardware. Audigy2/2val have multiple bits
	 * set while Live! has just the SB_LIVE bits. So Features of
	 * Audigy will be reported by Audigy2/val too.
	 */
	int			feature_mask;
	int			max_mem, max_pages, nr_pages;
	/*
	 * Mixer
	 */
	ac97_t			*ac97;
	ac97_ctrl_t		*ac97_recsrc;
	uint32_t		ac97_stereomix;
	emu10k_gpr_t		gpr_shadow[MAX_GPR];
	emu10k_ctrl_t		ctrls[CTL_MAX];

	/*
	 * Audio
	 */

	int			audio_memptr;
	int			*silent_page;

	emu10k_portc_t		*portc[EMU10K_NUM_PORTC];
};

#define	INB(devc, reg)		ddi_get8(devc->regsh, (void *)(reg))
#define	OUTB(devc, val, reg)	ddi_put8(devc->regsh, (void *)(reg), (val))

#define	INW(devc, reg)		ddi_get16(devc->regsh, (void *)(reg))
#define	OUTW(devc, val, reg)	ddi_put16(devc->regsh, (void *)(reg), (val))

#define	INL(devc, reg)		ddi_get32(devc->regsh, (void *)(reg))
#define	OUTL(devc, val, reg)	ddi_put32(devc->regsh, (void *)(reg), (val))

#endif	/* _KERNEL */

#endif /* EMU10K_H */
