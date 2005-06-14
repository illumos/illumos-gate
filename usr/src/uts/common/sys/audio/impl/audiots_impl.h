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
 * Copyright 2000-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_AUDIOTS_IMPL_H
#define	_SYS_AUDIOTS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Implementation specific header file for the audiots device driver.
 */

#ifdef _KERNEL

/*
 * Misc. defines
 */
#define	TS_CONFIG_REGS		(0)
#define	TS_IO_MAPPED_REGS	(1)
#define	TS_MEM_MAPPED_REGS	(2)
#define	TS_ALL_DMA_ENGINES	(0xffffffff)
#define	TS_ALL_DMA_OFF		(0x00000000)

#define	TS_IDNUM		(0x6175)
#define	TS_MINPACKET		(0)
#define	TS_MAXPACKET		(1*1024)
#define	TS_HIWATER		(64*1024)
#define	TS_LOWATER		(32*1024)

#define	TS_BSIZE		(8*1024)
#define	TS_20MS			(20000)		/* 20,000 microseconds */
#define	TS_20US			(20)		/* 20 microseconds */
#define	TS_GAIN_SHIFT3		(3)		/* 5 significan bits */
#define	TS_GAIN_SHIFT4		(4)		/* 4 significan bits */
#define	TS_BYTE_SHIFT		(8)
#define	TS_LAST_AC_REG		(0x23)
#define	TS_REG_SIZE		(2)
#define	TS_MOD_SIZE		(16)
#define	TS_BUF_HALVES		(2)
#define	TS_1ST_HALF		(0)
#define	TS_2ND_HALF		(1)
#define	TS_SRC_SHIFT		(12)
#define	TS_NOT_SUSPENDED	(0)
#define	TS_SUSPENDED		(~TS_NOT_SUSPENDED)
#define	TS_VENDOR_ID1_MASK	(0x0000ffff);
#define	TS_PORT_MASK		(0x0ff)

#define	TS_MAX_CHANNELS		(200)		/* force max # chs */
#define	TS_MAX_HW_CHANNELS	(32)
#define	TS_MAX_IN_CHANNELS	1
#define	TS_MAX_OUT_CHANNELS	(TS_MAX_HW_CHANNELS - TS_MAX_IN_CHANNELS)
#define	TS_INPUT_STREAM		(31)
#define	TS_INPUT_CHANNEL_MASK	(0x80000000u)
#define	TS_INPUT_CHANNEL	(TS_INPUT_CHANNEL_MASK)
#define	TS_OUTPUT_STREAM	(0)
#define	TS_OUTPUT_CHANNEL	(0x00000001u)
#define	TS_CH_ARRAY_SZIE	(TS_MAX_HW_CHANNELS * sizeof (int))
#define	TS_COMPONENT		(0)
#define	TS_PWR_OFF		(0)
#define	TS_PWR_ON		(1)
#define	TS_NO_PWR_MANAGE	(0)
#define	TS_PWR_MANAGE		(1)
#define	TS_NORMAL_POWER		(1)
#define	TS_KIOP(X)		((kstat_intr_t *)(X->ts_ksp->ks_data))
#define	TS_WAIT_CNT		(512)
#define	TS_LOOP_CNT		(10)
#define	TS_DELAY_CNT		(25)
#define	TS_INIT_RESTORE		(0)
#define	TS_INIT_NO_RESTORE	~TS_INIT_RESTORE
#define	TS_CODEC_REG(r)		((r) >> 1)
#define	TS_PORT_UNMUTE		(0xffffffff)
#define	TS_AC97_ATTEN_HP	(0x1818)
#define	TS_AC97_ATTEN_LINE	(0x0404)
#define	TS_AC97_ATTEN_SPKR	(0x0001)
#define	TS_FIFO_SIZE		(8)

/* ALI Hacks */
#define	TS_READ_TRIES		(TS_WAIT_CNT/10)
#define	TS_RESET_TRIES		(16)
#define	TS_SB_RESET		(0x7fff)


/*
 * audiots_config_t	- Config space registers
 */
struct audiots_config {
	uint16_t	tsc_vendor_id;			/* 00h - 01h */
	uint16_t	tsc_device_id;			/* 02h - 03h */
	uint16_t	tsc_command;			/* 04h - 05h */
	uint16_t	tsc_status;			/* 06h - 07h */
	uint32_t	tsc_class_code_rev_id;		/* 08h - 0bh */
	uint32_t	tsc_bist_cache;			/* 0ch - 0fh */
	uint32_t	tsc_audio_io_base;		/* 10h - 13h */
	uint32_t	tsc_audio_mem_base;		/* 14h - 17h */
	uint32_t	tsc_rsvd1[5];			/* 18h - 2bh */
	uint32_t	tsc_sub_ids;			/* 2ch - 2fh */
	uint32_t	tsc_rsvd2;			/* 30h - 33h */
	uint16_t	tsc_cap_ptr;			/* 34h - 35h */
	uint16_t	tsc_rsvd3;			/* 36h - 37h */
	uint32_t	tsc_rsvd4;			/* 38h - 3bh */
	uint32_t	tsc_compat1;			/* 3ch - 3fh */
	uint32_t	tsc_ddma_slave;			/* 40h - 43h */
	uint32_t	tsc_compat2;			/* 44h - 47h */
	uint32_t	tsc_compat3;			/* 48h - 4bh */
	uint32_t	tsc_rsvd5[36];			/* 4ch - dbh */
	uint16_t	tsc_pm_id_next_ptr;		/* dch - ddh */
	uint16_t	tsc_pmc;			/* deh - dfh */
	uint16_t	tsc_pmcsr;			/* e0h - e1h */
	uint16_t	tsc_pmcsr_bse_base;		/* e2h - e3h */
	uint32_t	tsc_rsvd6[7];			/* e4h - ffh */
};
typedef struct audiots_config audiots_config_t;

#define	TS_AD_CODEC_ID				0x4144
#define	TS_AD_REV_ID				0x5340
#define	TS_CONFIG_VENDOR_ID			0x10b9
#define	TS_CONFIG_DEVICE_ID			0x5451
#define	TS_CONFIG_SUBSYSTEM_VENDOR_ID		0x10b9
#define	TS_CONFIG_SUBSYSTEM_ID			0x5451
#define	TRI_CONFIG_VENDOR_ID			0x1023
#define	TRI_CONFIG_DEVICE_ID			0x2000
#define	TRI_CONFIG_SUBSYSTEM_VENDOR_ID		0x1023
#define	TRI_CONFIG_SUBSYSTEM_ID			0x2000
#define	AC_REV_ID1				0x0001
#define	AC_REV_ID2				0x0002

#define	TS_CAP_PTR				0xdc
#define	TS_PWR_D0				0x0000
#define	TS_PWR_D1				0x0001
#define	TS_PWR_D2				0x0002
#define	TS_PWR_D3				0x0003
#define	TS_PWR_PME				0x8000

/*
 * audiots_aram_t	- ARAM registers
 */
struct audiots_aram {
	uint16_t	aram_alpha_fms;			/* e0h - e1h */
	uint16_t	aram_cso;			/* e2h - e3h */
	uint32_t	aram_cptr_lba;			/* e4h - e7h */
	uint16_t	aram_delta;			/* e8h - e9h */
	uint16_t	aram_eso;			/* eah - ebh */
	uint32_t	aram_reserved;			/* ech - efh */
};
typedef struct audiots_aram audiots_aram_t;

/* aram_cso_alpha_fms register defines */
#define	ARAM_FMS_MASK				0x000f
#define	ARAM_ALPHA_MASK				0xfff0

/* aram_cptr_lba register defines */
#define	ARAM_LBA_MASK				0x7fffffff
#define	ARAM_CPTR_MASK				0x80000000

/*
 * audiots_eram_t	- ERAM registers
 */
struct audiots_eram {
	uint16_t	eram_ctrl_ec;			/* f0h - f1h */
	uint16_t	eram_gvsel_pan_vol;		/* f2h - f3h */
	uint32_t	eram_ebuf1;			/* f4h - f7h */
	uint32_t	eram_ebuf2;			/* f8h - fbh */
	uint32_t	eram_reserved;			/* fch - ffh */
};
typedef struct audiots_eram audiots_eram_t;

/* eram_ctrl_ec register defines */
#define	ERAM_EC_MASK				0x0fff
#define	ERAM_CTRL_MASK				0xf000
#define	ERAM_LOOP_MODE				0x1000
#define	ERAM_NOLOOP_MODE			0x0000
#define	ERAM_SIGNED_PCM				0x2000
#define	ERAM_UNSIGNED_PCM			0x0000
#define	ERAM_STEREO				0x4000
#define	ERAM_MONO				0x0000
#define	ERAM_16_BITS				0x8000
#define	ERAM_8_BITS				0x0000

/* eram_gvsel_pan_vol register defines */
#define	ERAM_VOL_MASK				0x00ff
#define	ERAM_VOL_0dB				0x0000
#define	ERAM_VOL_DEFAULT			0x000f
#define	ERAM_VOL_MAX_ATTEN			0x00ff
#define	ERAM_PAN_MASK				0x3f00
#define	ERAM_PAN_0dB				0x0000
#define	ERAM_PAN_MAX_ATTEN			0x3f00
#define	ERAM_PAN_LEFT				0x0000
#define	ERAM_PAN_RIGHT				0x4000
#define	ERAM_MUSIC_VOL				0x0000
#define	ERAM_WAVE_VOL				0x8000

/* eram_ebuf register defines */
#define	ERAM_EBUF_STILL				0x30000000

/*
 * audiots_processor_t	- Audio Processor registers via I/O space
 *
 * NOTE: Soutbridge rev 1535D+ uses a read/write register at AudioBase +40
 * Previous SB chip revs had a seperate write register at AudioBase +40, and
 * a read register at AudioBase +44.
 *
 */
struct audiots_processor {
	uint32_t	ap_dmar0_1_2_3;			/* 00h - 03h */
	uint32_t	ap_dmar4_5_6_7;			/* 04h - 07h */
	uint32_t	ap_dmar8_9_10_11;		/* 08h - 0bh */
	uint32_t	ap_dmar12_13_14_15;		/* 0ch - 0fh */
	uint32_t	ap_sbr0_1_2_3;			/* 10h - 13h */
	uint32_t	ap_sbr4_5_6;			/* 14h - 17h */
	uint32_t	ap_svbr7;			/* 18h - 1bh */
	uint32_t	ap_sbr8_9_10;			/* 1ch - 1fh */
	uint32_t	ap_mpur0_1_2_3;			/* 20h - 23h */
	uint32_t	ap_rsvd1[3];			/* 24h - 2fh */
	uint32_t	ap_gamer0_1;			/* 30h - 33h */
	uint32_t	ap_gamer2;			/* 34h - 37h */
	uint32_t	ap_gamer3;			/* 38h - 3bh */
	uint32_t	ap_rsvd2;			/* 3ch - 3fh */
	uint16_t	ap_acrdwr_reg;			/* 40h - 41h */
	uint16_t	ap_acrdwr_data;			/* 42h - 43h */
	uint16_t	ap_acrd_35D_reg;		/* 44h - 45h */
	uint16_t	ap_acrd_35D_data;		/* 46h - 47h */
	uint32_t	ap_sctrl;			/* 48h - 4bh */
	uint32_t	ap_acgpio;			/* 4ch - 4fh */
	uint32_t	ap_asr0;			/* 50h - 53h */
	uint32_t	ap_asr1_2;			/* 54h - 57h */
	uint32_t	ap_asr3;			/* 58h - 5bh */
	uint32_t	ap_asr4_5_6;			/* 5ch - 5fh */
	uint32_t	ap_aoplsr0;			/* 60h - 63h */
	uint32_t	ap_rsvd3[6];			/* 64h - 7bh */
	uint32_t	ap_gp;				/* 7ch - 7fh */
	uint32_t	ap_start;			/* 80h - 83h */
	uint32_t	ap_stop;			/* 84h - 87h */
	uint32_t	ap_delay;			/* 88h - 8bh */
	uint32_t	ap_sign_cso;			/* 8ch - 8fh */
	uint32_t	ap_cspf;			/* 90h - 93h */
	uint32_t	ap_cebc;			/* 94h - 97h */
	uint32_t	ap_aint;			/* 98h - 9bh */
	uint32_t	ap_eint;			/* 9ch - 9fh */
	uint32_t	ap_cir_gc;			/* a0h - a3h */
	uint32_t	ap_ainten;			/* a4h - a7h */
	uint32_t	ap_volume;			/* a8h - abh */
	uint32_t	ap_sbdelta;			/* ach - afh */
	uint32_t	ap_miscint;			/* b0h - b3h */
	uint32_t	ap_rsvd4[3];			/* b4h - bfh */
	uint32_t	ap_sbdm;			/* c0h - c3h */
	uint32_t	ap_sb;				/* c4h - c7h */
	uint32_t	ap_stimer;			/* c8h - cbh */
	uint32_t	ap_lfo_i2s_delta;		/* cch - cfh */
	uint32_t	ap_st_target;			/* d0h - d3h */
	uint32_t	ap_global_control;		/* d4h - d7h */
	uint32_t	ap_rsvd5[2];			/* d8h - dfh */
	audiots_aram_t	ap_aram;			/* e0h - efh */
	audiots_eram_t	ap_eram;			/* f0h - ffh */
};
typedef struct audiots_processor audiots_processor_t;

/* ap_acwr_reg register defines (40h - 41h) */
#define	AP_ACWR_INDEX_MASK			0x007f
#define	AP_ACWR_W_PRIMARY_CODEC			0x0000
#define	AP_ACWR_W_SECONDARY_CODEC		0x0080
#define	AP_ACWR_W_WRITE_MIXER_REG		0x8000
#define	AP_ACWR_W_SELECT_WRITE			0x0100
#define	AP_ACWR_R_PRIMARY_CODEC			0x0000
#define	AP_ACWR_R_SECONDARY_CODEC		0x0080
#define	AP_ACWR_R_WRITE_BUSY			0x8000

/* ap_acrd_reg register defines (44h - 45h) */
#define	AP_ACRD_INDEX_MASK			0x007f
#define	AP_ACRD_W_PRIMARY_CODEC			0x0000
#define	AP_ACRD_W_SECONDARY_CODEC		0x0080
#define	AP_ACRD_W_MODEM_READ_REQ		0x2000
#define	AP_ACRD_W_AUDIO_READ_REQ		0x4000
#define	AP_ACRD_W_READ_MIXER_REG		0x8000
#define	AP_ACRD_R_PRIMARY_CODEC			0x0000
#define	AP_ACRD_R_SECONDARY_CODEC		0x0080
#define	AP_ACRD_R_MODEM_READ_REQ		0x2000
#define	AP_ACRD_R_AUDIO_READ_REQ		0x4000
#define	AP_ACRD_R_READ_BUSY			0x8000

/* ap_sctrl register defines (48h - 4bh) */
#define	AP_SCTRL_WRST_CODEC			0x00000001
#define	AP_SCTRL_CRST_CODEC			0x00000002
#define	AP_SCTRL_12288K_CLOCK			0x00000000
#define	AP_SCTRL_6144K_CLOCK			0x00000004
#define	AP_SCTRL_PCM_TO_PRIMARY			0x00000000
#define	AP_SCTRL_PCM_TO_SECONDARY		0x00000008
#define	AP_SCTRL_DOUPLE_RATE_DISABLE		0x00000000
#define	AP_SCTRL_DOUPLE_RATE_ENABLE		0x00000010
#define	AP_SCTRL_I2S_DISABLE			0x00000000
#define	AP_SCTRL_I2S_ENABLE			0x00000080
#define	AP_SCTRL_PCMIN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_PCMIN_SEL_SECONDARY_CODEC	0x00000100
#define	AP_SCTRL_LINE1IN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_LINE1IN_SEL_SECONDARY_CODEC	0x00000200
#define	AP_SCTRL_MICIN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_MICIN_SEL_SECONDARY_CODEC	0x00000400
#define	AP_SCTRL_LINE2IN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_LINE2IN_SEL_SECONDARY_CODEC	0x00000800
#define	AP_SCTRL_HSETIN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_HSETIN_SEL_SECONDARY_CODEC	0x00001000
#define	AP_SCTRL_GPIOIN_SEL_PRIMARY_CODEC	0x00000000
#define	AP_SCTRL_GPIOIN_SEL_SECONDARY_CODEC	0x00002000
#define	AP_SCTRL_SECONDARY_CODEC_MASK		0x0000c000
#define	AP_SCTRL_SECONDARY_CODEC_DEFAULT	0x00004000
#define	AP_SCTRL_PCMOUT_EN			0x00010000
#define	AP_SCTRL_SURROUT_EN			0x00020000
#define	AP_SCTRL_CENTEROUT_EN			0x00040000
#define	AP_SCTRL_LFEOUT_EN			0x00080000
#define	AP_SCTRL_LINE1OUT_EN			0x00100000
#define	AP_SCTRL_LINE2OUT_EN			0x00200000
#define	AP_SCTRL_HSETOUT_EN			0x00400000
#define	AP_SCTRL_GPIOOUT_EN			0x00800000
#define	AP_SCTRL_CODECA_RDY			0x01000000	/* primary */
#define	AP_SCTRL_CODECB_RDY			0x02000000	/* secondary */
#define	AP_SCTRL_CODEC_PD			0x04000000

/* ap_acgpio resister defines (4ch - 4fh) */
#define	AP_ACGPIO_IRQ1				0x00000002	/* primary */
#define	AP_ACGPIO_IRQ2				0x00000004	/* secondary */
#define	AP_ACGPIO_INT1_ENABLE			0x00000008
#define	AP_ACGPIO_INT1_DISABLE			0x00000000
#define	AP_ACGPIO_INT2_ENABLE			0x00000010
#define	AP_ACGPIO_INT2_DISABLE			0x00000000
#define	AP_ACGPIO_WRITE_SLOT_12			0x00008000
#define	AP_ACGPIO_R_SLOT_12_BUSY		0x00008000
#define	AP_ACGPIO_DATA_MASK			0xffff0000

/* ap_asr0 resgister defines (50h - 53h) */
#define	AP_ASR0_CODEC_READY			0x00008000

/* ap_asr4_5_6 register defines (5ch - 5fh) */
#define	AP_ASR4_REV_A				0x00000080
#define	AP_ASR4_REV_BC				0x00000049
#define	AP_ASR5_ESP_VERSION			0x00040000
#define	AP_ASR6_ESP_VERSION			0x02000000

/* ap_ain register defines (98h - 9bh) */
#define	AP_AIN_RESET_ALL			0xffffffff

/* ap_eain register defines (9ch - 9fh) */
#define	AP_EAIN_RESET_ALL			0xffffffff

/* ap_cir_gc register defines (a0h - a3h) */
#define	AP_CIR_GC_CHANNEL_INDEX_MASK		0x0000001f
#define	AP_CIR_GC_RST_STIMER			0x00000100
#define	AP_CIR_GC_PAUSE				0x00000200
#define	AP_CIR_GC_OVERUN_IE			0x00000400
#define	AP_CIR_GC_UNDERUN_IE			0x00000800
#define	AP_CIR_GC_ENDLP_IE			0x00001000
#define	AP_CIR_GC_MIDLP_IE			0x00002000
#define	AP_CIR_GC_ETOG_IE			0x00004000
#define	AP_CIR_GC_EDROP_IE			0x00008000
#define	AP_CIR_GC_PCM_FIFO			0x00000000
#define	AP_CIR_GC_MMC_BUFFER			0x00100000
#define	AP_CIR_GC_NORMAL_MODE			0x00000000
#define	AP_CIR_GC_EXPROM_DUMP_MODE_ENABLE	0x00800000
#define	AP_CIR_GC_EXPROM_DEBUG_MODE		0x04000000
#define	AP_CIR_GC_TEST_LOOPBACK_ON		0x08000000

/* ap_ainten register defines (a4h - a7h) */
#define	AP_AINTEN_DISABLE_ALL			0x00000000

/* ap_volume regsiter defines (a8h - abh) */
#define	AP_VOLUME_WAVE_LEFT_MASK		0x000000ff
#define	AP_VOLUME_WAVE_LEFT_MUTE		0x000000ff
#define	AP_VOLUME_WAVE_LEFT_FULL		0x00000000
#define	AP_VOLUME_WAVE_LEFT_SHIFT		0
#define	AP_VOLUME_WAVE_RIGHT_MASK		0x0000ff00
#define	AP_VOLUME_WAVE_RIGHT_MUTE		0x0000ff00
#define	AP_VOLUME_WAVE_RIGHT_FULL		0x00000000
#define	AP_VOLUME_WAVE_RIGHT_SHIFT		8
#define	AP_VOLUME_MUSIC_LEFT_MASK		0x00ff0000
#define	AP_VOLUME_MUSIC_LEFT_MUTE		0x00ff0000
#define	AP_VOLUME_MUSIC_LEFT_FULL		0x00000000
#define	AP_VOLUME_MUSIC_LEFT_SHIFT		16
#define	AP_VOLUME_MUSIC_RIGHT_MASK		0xff000000
#define	AP_VOLUME_MUSIC_RIGHT_MUTE		0xff000000
#define	AP_VOLUME_MUSIC_RIGHT_FULL		0x00000000
#define	AP_VOLUME_MUSIC_RIGHT_SHIFT		24

/* ap_miscint register defines (b0h - b3h) */
#define	AP_MISCINT_PB_UNDERUN_IRQ		0x00000001
#define	AP_MISCINT_REC_OVERRUN_IRQ		0x00000002
#define	AP_MISCINT_SB_IRQ			0x00000004
#define	AP_MISCINT_MPU401_IRQ			0x00000008
#define	AP_MISCINT_OPL3_IRQ			0x00000010
#define	AP_MISCINT_ADDRESS_IRQ			0x00000020
#define	AP_MISCINT_ENVELOPE_IRQ			0x00000040
#define	AP_MISCINT_ST_IRQ			0x00000080
#define	AP_MISCINT_PB_UNDERUN			0x00000100
#define	AP_MISCINT_REC_OVERUN			0x00000200
#define	AP_MISCINT_MIXER_UNDERFLOW_FLAG		0x00000400
#define	AP_MISCINT_MIXER_OVERFLOW_FLAG		0x00000800
#define	AP_MISCINT_ST_TARGET_REACHED		0x00008000
#define	AP_MISCINT_PB_24K_MODE			0x00010000
#define	AP_MISCINT_OPLTIMER_IE			0x00020000
#define	AP_MISCINT_GPIO_IE			0x00040000
#define	AP_MISCINT_ST_IRQ_EN			0x00800000
#define	AP_MISCINT_ACGPIO_IRQ			0x01000000
#define	AP_MISCINT_GPIO_IRQ			0x02000000

/* ap_lfo_i2s_delta register defines (cch - cfh) */
#define	AP_I2S_DELTA_MASK			0x00001fff
#define	AP_LFO_INIT_MASK			0x00ff0000
#define	AP_LFO_48KHZ				0x00000000
#define	AP_LFO_48KHZ_BY_4			0x01000000
#define	AP_LFO_48KHZ_BY_16			0x02000000
#define	AP_LFO_48KHZ_BY_64			0x03000000
#define	AP_LFO_ENABLE				0x04000000

/* ap_global_control register defines (d4h - d7h) */
#define	AP_GLOBAL_CTRL_ENABLE_HW_VOLUME		0x00000001
#define	AP_CLOGAL_CTRL_PCM_OUT_AC97		0x00000000
#define	AP_CLOGAL_CTRL_PCM_OUT_I2S		0x00000080
#define	AP_CLOGAL_CTRL_I2SIN_TO_SYS_MEMORY	0x00000000
#define	AP_CLOGAL_CTRL_I2SIN_TO_AC97		0x00001000
#define	AP_CLOGAL_CTRL_I2SIN_TO_SYS_MEMORY_AC97	0x00002000
#define	AP_CLOGAL_CTRL_MMC_FROM_MIXER		0x00000000
#define	AP_CLOGAL_CTRL_MMC_FROM_PCM_OUT		0x00004000
#define	AP_CLOGAL_CTRL_PCM_OUT_TO_AC97		0x00000000
#define	AP_CLOGAL_CTRL_PCM_OUT_TO_I2S		0x00008000
#define	AP_CLOGAL_CTRL_E_HSETOUT_CH16		0x00010000
#define	AP_CLOGAL_CTRL_E_HSETIN_CH17		0x00020000
#define	AP_CLOGAL_CTRL_E_LINE2OUT_CH18		0x00040000
#define	AP_CLOGAL_CTRL_E_LINE2IN_CH19		0x00080000
#define	AP_CLOGAL_CTRL_E_LINE1OUT_CH20		0x00100000
#define	AP_CLOGAL_CTRL_E_LINE1IN_CH21		0x00200000
#define	AP_CLOGAL_CTRL_E_MIC_CH22		0x00400000
#define	AP_CLOGAL_CTRL_E_LFE_CH23		0x00800000
#define	AP_CLOGAL_CTRL_E_CENTER_CH24		0x01000000
#define	AP_CLOGAL_CTRL_E_SURR_R_CH25		0x02000000
#define	AP_CLOGAL_CTRL_E_SURR_L_CH26		0x04000000
#define	AP_CLOGAL_CTRL_E_PCMOUT_R_CH27		0x08000000
#define	AP_CLOGAL_CTRL_E_PCMOUT_L_CH28		0x10000000
#define	AP_CLOGAL_CTRL_E_I2SIN_CH29		0x20000000
#define	AP_CLOGAL_CTRL_E_MMC_CH30		0x40000000
#define	AP_CLOGAL_CTRL_E_PCMIN_CH31		0x80000000

/*
 * audiots_regs_t	- Audio processor registers via memory space.
 */
struct audiots_regs {
	audiots_processor_t	aud_regs;
	uint32_t		aud_rsvd1[64];
	uint32_t		aud_oplram[128];
	uint32_t		aud_rsvd2[256];
	struct {
		audiots_aram_t	aram;
		audiots_eram_t	eram;
	} aud_ram[TS_MAX_HW_CHANNELS];	/* 32 channels */
	struct {
		audiots_aram_t	aram;
		audiots_eram_t	eram;
	} aud_rsvd3[TS_MAX_HW_CHANNELS]; /* another 32 chs not implemented */
};
typedef struct audiots_regs audiots_regs_t;

/*
 * audiots_save_regs_t	- Saved audio controller registers.
 */
struct audiots_save_regs {
	uint16_t	aram_delta;
	uint16_t	eram_ctrl_ec;
};
typedef struct audiots_save_regs audiots_save_regs_t;

/*
 * audiots_state_t	- per instance state and operation data
 */
struct audiots_state {
	kmutex_t		ts_lock;	/* state protection lock */
	kcondvar_t		ts_cv;		/* suspend/resume cond. var. */
	ddi_iblock_cookie_t	ts_iblock;	/* iblock cookie */
	uint_t			ts_flags;	/* flags */
	kstat_t			*ts_ksp;	/* kernel statistics */
	dev_info_t		*ts_dip;	/* used by ts_getinfo() */
	audiohdl_t		ts_ahandle;	/* audio handle */
	audio_info_t		ts_defaults;	/* default state for the dev */
	am_ad_info_t		ts_ad_info;	/* audio device info state */
	audiots_config_t	*ts_config;	/* configuration registers */
	audiots_regs_t		*ts_regs;	/* memory mapped registers */
	audiots_save_regs_t	ts_save_regs[TS_MAX_HW_CHANNELS];
						/* saved controller regs */
	ddi_acc_handle_t	ts_chandle;	/* handle to config regs */
	ddi_acc_handle_t	ts_handle;	/* handle to mapped regs */
	audio_device_t		ts_dev_info;	/* device info strings */
	int			ts_instance;	/* device instance */
	uint16_t		ts_shadow[64];	/* ac97 shadow registers */
	boolean_t		ts_pm_core;	/* power manage audio core? */
	int			ts_suspended;	/* power management state */
	int			ts_powered;	/* device powered up? */
	int			ts_busy_cnt;	/* device busy count */
	ddi_dma_attr_t		*ts_dma_attr;	/* DMA attributes */
	ddi_dma_handle_t	ts_ph;		/* play DMA handles */
	ddi_dma_handle_t	ts_ch;		/* capture DMA handles */
	ddi_dma_cookie_t	ts_pc;		/* play DMA cookies */
	ddi_dma_cookie_t	ts_cc;		/* capture DMA cookies */
	ddi_acc_handle_t	ts_pmh;		/* play DMA memory handles */
	ddi_acc_handle_t	ts_cmh;		/* capture DMA memory handles */
	size_t			ts_pbuf_size;	/* size of play buffer */
	size_t			ts_pml;		/* play DMA memory length */
	size_t			ts_cbuf_size;	/* size of capture buffer */
	size_t			ts_cml;		/* capture DMA memory length */
	caddr_t			ts_pb;		/* play DMA buffers */
	caddr_t			ts_cb;		/* capture DMA buffers */
	uint16_t		*ts_tcbuf;	/* temp capture buffer */
	int			ts_pcnt[2];	/* play count, in bytes */
	int			ts_ccnt;	/* capture count, in bytes */
	int			ts_psamples[2];	/* play samples */
	uint_t			ts_output_muted; /* output muted */
	uint_t			ts_psample_rate; /* play sample rate */
	uint_t			ts_pchannels;	/* play channels */
	uint_t			ts_pprecision;	/* play precision */
	uint_t			ts_csample_rate; /* capture sample rate */
	uint_t			ts_cchannels;	/* capture channels */
	uint_t			ts_cprecision;	/* capture precision */
	uint_t			ts_output_port;	/* current output port */
	uint_t			ts_input_port;	/* current input port */
	uint16_t		ts_monitor_gain; /* monitor gain */
	int			ts_rev_id;	/* SB Chip Revision ID */
};
typedef struct audiots_state audiots_state_t;

_NOTE(MUTEX_PROTECTS_DATA(audiots_state::ts_lock, audiots_state))
_NOTE(READ_ONLY_DATA(audiots_state::ts_instance))
_NOTE(READ_ONLY_DATA(audiots_state::ts_dip))
_NOTE(READ_ONLY_DATA(audiots_state::ts_ahandle))

/* audiots_state.ts_flags defines */
#define	TS_DMA_ENGINE_INITIALIZED	0x0001u /* play DMA eng. initialized */
#define	TS_DMA_ENGINE_PAUSED		0x0002u /* play DMA engine paused */
#define	TS_DMA_ENGINE_EMPTY		0x0004u /* play DMA engine empty */
#define	TS_DMA_RECORD_START		0x0008u /* record DMA engine started */
#define	TS_INTR_PENDING			0x0010u /* interrupt pending at DMA */
						/* stop */
#define	TS_AUDIO_READ_FAILED		0x0020u /* reading the AC97 register */
						/* has stopped working */
#define	TS_READ_FAILURE_PRINTED		0x0040u /* Flag to avoid flooding the */
						/* console with AC97 failure */
						/* messages */
#define	TS_ATTACH_PWR			0x0080u	/* Power raised at */
						/* attach time */
#define	TS_PM_SUPPORTED			0x0100u	/* PM supported? */
#define	TS_PLAY_ACTIVE			0x0200u	/* play active, for PM */

/*
 * Read and write the AC-97 Codec's registers
 */
#define	AC97_RETRIES		1000
#define	AC97_WAIT		1

/*
 * Useful bit twiddlers
 */
#define	OR_SET_BYTE(handle, addr, val)					\
	ddi_put8((handle), (uint8_t *)(addr),				\
		(ddi_get8((handle), (uint8_t *)(addr)) | (uint8_t)(val)));

#define	OR_SET_SHORT(handle, addr, val)					\
	ddi_put16((handle), (uint16_t *)(addr),				\
		(ddi_get16((handle), (uint16_t *)(addr)) | (uint16_t)(val)));

#define	OR_SET_WORD(handle, addr, val)					\
	ddi_put32((handle), (uint32_t *)(addr),				\
		(ddi_get32((handle), (uint32_t *)(addr)) | (uint32_t)(val)));

#define	AND_SET_BYTE(handle, addr, val)					\
	ddi_put8((handle), (uint8_t *)(addr),				\
		(ddi_get8((handle), (uint8_t *)(addr)) & (uint8_t)(val)));

#define	AND_SET_SHORT(handle, addr, val)				\
	ddi_put16((handle), (uint16_t *)(addr),				\
		(ddi_get16((handle), (uint16_t *)(addr)) & (uint16_t)(val)));

#define	AND_SET_WORD(handle, addr, val)					\
	ddi_put32((handle), (uint32_t *)(addr),				\
		(ddi_get32((handle), (uint32_t *)(addr)) & (uint32_t)(val)));

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIOTS_IMPL_H */
