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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#ifndef _SYS_AUDIOHD_IMPL_H_
#define	_SYS_AUDIOHD_IMPL_H_

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/synch.h>
#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>
#include <sys/audio/audiohd.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * vendor IDs and device IDs of supported devices
 */
#define	AUDIOHD_VID_ALC260	0x10ec0260
#define	AUDIOHD_VID_ALC262	0x10ec0262
#define	AUDIOHD_VID_ALC880	0x10ec0880
#define	AUDIOHD_VID_ALC882	0x10ec0882
#define	AUDIOHD_VID_ALC883	0x10ec0883
#define	AUDIOHD_VID_ALC885	0x10ec0885
#define	AUDIOHD_VID_ALC888	0x10ec0888
#define	AUDIOHD_VID_STAC9200	0x83847690
#define	AUDIOHD_VID_STAC9200D	0x83847691
#define	AUDIOHD_VID_CXD9872RD	0x83847661
#define	AUDIOHD_VID_STAC9872AK	0x83847662
#define	AUDIOHD_VID_CXD9872AKD	0x83847664
#define	AUDIOHD_VID_AD1986A	0x11d41986
#define	AUDIOHD_VID_AD1988A	0x11d41988
#define	AUDIOHD_VID_AD1988B	0x11d4198b

#define	AUDIOHD_VID_INTEL	0x8086
#define	AUDIOHD_VID_ATI		0x1002


/*
 * Only for Intel hardware:
 * PCI Express traffic class select register in PCI configure space
 */
#define	AUDIOHD_INTEL_PCI_TCSEL 0x44

/*
 * Only for ATI SB450:
 * MISC control register 2
 */
#define	AUDIOHD_ATI_PCI_MISC2	0x42
#define	AUDIOHD_ATI_MISC2_SNOOP	0x02

#define	AUDIOHDC_NID(x)		x
#define	AUDIOHDC_NULL_NODE	-1
/*
 * currently, only the format of 48K sample rate, 16-bit
 * 2-channel is supported.
 */
#define	AUDIOHD_FMT_PCMOUT	0x0011
#define	AUDIOHD_FMT_PCMIN	0x0011


#define	AUDIOHD_CODEC_MAX	15
#define	AUDIOHD_MEMIO_LEN	0x4000

#define	AUDIOHD_BDLE_BUF_ALIGN	128
#define	AUDIOHD_CMDIO_ENT_MASK	0x00ff	/* 256 entries for CORB/RIRB */
#define	AUDIOHD_CDBIO_CORB_LEN	1024	/* 256 entries for CORB, 1024B */
#define	AUDIOHD_CDBIO_RIRB_LEN	2048	/* 256 entries for RIRB, 2048B */
#define	AUDIOHD_BDLE_NUMS	4	/* 4 entires for record/play BD list */

#define	AUDIOHD_MOD_NAME	"HD Audio Driver"
#define	AUDIOHD_IDNUM		0x6176
#define	AUDIOHD_NAME		"SUNW,audiohd"
#define	AUDIOHD_MINPACKET	(0)
#define	AUDIOHD_MAXPACKET	(1024)
#define	AUDIOHD_HIWATER		(64*1024)
#define	AUDIOHD_LOWATER		(32*1024)

#define	AUDIOHD_PORT_UNMUTE	(0xffffffff)

/*
 * Audio registers of high definition
 */
#define	AUDIOHD_REG_GCAP		0x00
#define	AUDIOHDR_GCAP_OUTSTREAMS	0xf000
#define	AUDIOHDR_GCAP_INSTREAMS		0x0f00
#define	AUDIOHDR_GCAP_BSTREAMS		0x00f8
#define	AUDIOHDR_GCAP_NSDO		0x0006
#define	AUDIOHDR_GCAP_64OK		0x0001

#define	AUDIOHD_REG_VMIN		0x02
#define	AUDIOHD_REG_VMAJ		0x03
#define	AUDIOHD_REG_OUTPAY		0x04
#define	AUDIOHD_REG_INPAY		0x06
#define	AUDIOHD_REG_GCTL		0x08
#define	AUDIOHD_REG_WAKEEN		0x0C
#define	AUDIOHD_REG_STATESTS		0x0E
#define	AUDIOHD_STATESTS_BIT_SDINS	0x7F

#define	AUDIOHD_REG_GSTS		0x10
#define	AUDIOHD_REG_INTCTL		0x20
#define	AUDIOHD_INTCTL_BIT_GIE		0x80000000
#define	AUDIOHD_INTCTL_BIT_CIE		0x40000000
#define	AUDIOHD_INTCTL_BIT_SIE		0x3FFFFFFF


#define	AUDIOHD_REG_INTSTS		0x24
#define	AUDIOHD_INTSTS_BIT_GIS		0x80000000
#define	AUDIOHD_INTSTS_BIT_CIS		0x40000000
#define	AUDIOHD_INTSTS_BIT_SINTS	(0x3fffffff)

#define	AUDIOHD_REG_WALCLK		0x30
#define	AUDIOHD_REG_SYNC		0x38

#define	AUDIOHD_REG_CORBLBASE		0x40
#define	AUDIOHD_REG_CORBUBASE		0x44
#define	AUDIOHD_REG_CORBWP		0x48
#define	AUDIOHD_REG_CORBRP		0x4A
#define	AUDIOHD_REG_CORBCTL		0x4C
#define	AUDIOHD_REG_CORBST		0x4D
#define	AUDIOHD_REG_CORBSIZE		0x4E

#define	AUDIOHD_REG_RIRBLBASE		0x50
#define	AUDIOHD_REG_RIRBUBASE		0x54
#define	AUDIOHD_REG_RIRBWP		0x58
#define	AUDIOHD_REG_RINTCNT		0x5A
#define	AUDIOHD_REG_RIRBCTL		0x5C
#define	AUDIOHD_REG_RIRBSTS		0x5D
#define	AUDIOHD_REG_RIRBSIZE		0x5E

#define	AUDIOHD_REG_IC			0x60
#define	AUDIOHD_REG_IR			0x64
#define	AUDIOHD_REG_IRS			0x68
#define	AUDIOHD_REG_DPLBASE		0x70
#define	AUDIOHD_REG_DPUBASE		0x74

#define	AUDIOHD_REG_SD_BASE		0x80
#define	AUDIOHD_REG_SD_LEN		0x20

/*
 * Offset of Stream Descriptor Registers
 */
#define	AUDIOHD_SDREG_OFFSET_CTL		0x00
#define	AUDIOHD_SDREG_OFFSET_STS		0x03
#define	AUDIOHD_SDREG_OFFSET_LPIB		0x04
#define	AUDIOHD_SDREG_OFFSET_CBL		0x08
#define	AUDIOHD_SDREG_OFFSET_LVI		0x0c
#define	AUDIOHD_SDREG_OFFSET_FIFOW		0x0e
#define	AUDIOHD_SDREG_OFFSET_FIFOSIZE		0x10
#define	AUDIOHD_SDREG_OFFSET_FORMAT		0x12
#define	AUDIOHD_SDREG_OFFSET_BDLPL		0x18
#define	AUDIOHD_SDREG_OFFSET_BDLPU		0x1c

/* bits for stream descriptor control reg */
#define	AUDIOHDR_SD_CTL_DEIE		0x000010
#define	AUDIOHDR_SD_CTL_FEIE		0x000008
#define	AUDIOHDR_SD_CTL_IOCE		0x000004
#define	AUDIOHDR_SD_CTL_SRUN		0x000002
#define	AUDIOHDR_SD_CTL_SRST		0x000001
#define	AUDIOHDR_SD_CTL_INTS	\
	(AUDIOHDR_SD_CTL_DEIE |	\
	AUDIOHDR_SD_CTL_FEIE |	\
	AUDIOHDR_SD_CTL_IOCE)


/* bits for stream descriptor status register */
#define	AUDIOHDR_SD_STS_BCIS		0x0004
#define	AUDIOHDR_SD_STS_FIFOE		0x0008
#define	AUDIOHDR_SD_STS_DESE		0x0010
#define	AUDIOHDR_SD_STS_FIFORY		0x0020
#define	AUDIOHDR_SD_STS_INTRS	\
	(AUDIOHDR_SD_STS_BCIS | \
	AUDIOHDR_SD_STS_FIFOE |	\
	AUDIOHDR_SD_STS_DESE)


/* bits for GCTL register */
#define	AUDIOHDR_GCTL_CRST		0x00000001
#define	AUDIOHDR_GCTL_URESPE		0x00000100

/* bits for CORBRP register */
#define	AUDIOHDR_CORBRP_RESET		0x8000
#define	AUDIOHDR_CORBRP_WPTR		0x00ff

/* bits for CORBCTL register */
#define	AUDIOHDR_CORBCTL_CMEIE		0x01
#define	AUDIOHDR_CORBCTL_DMARUN		0x02

/* bits for CORB SIZE register */
#define	AUDIOHDR_CORBSZ_8		0
#define	AUDIOHDR_CORBSZ_16		1
#define	AUDIOHDR_CORBSZ_256		2

/* bits for RIRBCTL register */
#define	AUDIOHDR_RIRBCTL_RINTCTL	0x01
#define	AUDIOHDR_RIRBCTL_DMARUN		0x02
#define	AUDIOHDR_RIRBCTL_RIRBOIC	0x04

/* bits for RIRBWP register */
#define	AUDIOHDR_RIRBWP_RESET		0x8000
#define	AUDIOHDR_RIRBWP_WPTR		0x00ff

/* bits for RIRB SIZE register */
#define	AUDIOHDR_RIRBSZ_8		0
#define	AUDIOHDR_RIRBSZ_16		1
#define	AUDIOHDR_RIRBSZ_256		2

#define	AUDIOHD_BDLE_RIRB_SDI		0x0000000f
#define	AUDIOHD_BDLE_RIRB_UNSOLICIT	0x00000010

/* HD spec: ID of Root node is 0 */
#define	AUDIOHDC_NODE_ROOT		0x00

/* HD spec: ID of audio function group is "1" */
#define	AUDIOHDC_AUDIO_FUNC_GROUP	1

/*
 * HD audio verbs can be either 12-bit or 4-bit in length.
 */
#define	AUDIOHDC_12BIT_VERB_MASK	0xfffff000
#define	AUDIOHDC_4BIT_VERB_MASK		0xfffffff0

/*
 * 12-bit verbs
 */
#define	AUDIOHDC_VERB_GET_PARAM			0xf00

#define	AUDIOHDC_VERB_GET_CONN_SEL		0xf01
#define	AUDIOHDC_VERB_SET_CONN_SEL		0x701

#define	AUDIOHDC_VERB_GET_CONN_LIST_ENT		0xf02
#define	AUDIOHDC_VERB_GET_PROCESS_STATE		0xf03
#define	AUDIOHDC_VERB_GET_SDI_SEL		0xf04

#define	AUDIOHDC_VERB_GET_POWER_STATE		0xf05
#define	AUDIOHDC_VERB_SET_POWER_STATE		0x705

#define	AUDIOHDC_VERB_GET_STREAM_CHANN		0xf06
#define	AUDIOHDC_VERB_SET_STREAM_CHANN		0x706

#define	AUDIOHDC_VERB_GET_PIN_CTRL		0xf07
#define	AUDIOHDC_VERB_SET_PIN_CTRL		0x707

#define	AUDIOHDC_VERB_GET_UNS_ENABLE		0xf08
#define	AUDIOHDC_VERB_GET_PIN_SENSE		0xf09
#define	AUDIOHDC_VERB_EXEC_PIN_SENSE		0x709
#define	AUDIOHDC_VERB_GET_BEEP_GEN		0xf0a
#define	AUDIOHDC_VERB_GET_DEFAULT_CONF		0xf1c

/*
 * 4-bit verbs
 */
#define	AUDIOHDC_VERB_GET_CONVERTER_FMT		0xa
#define	AUDIOHDC_VERB_SET_CONVERTER_FMT		0x2

#define	AUDIOHDC_VERB_GET_AMP_MUTE		0xb
#define	AUDIOHDC_VERB_SET_AMP_MUTE		0x3

/*
 * parameters of nodes
 */
#define	AUDIOHDC_PAR_VENDOR_ID			0x00
#define	AUDIOHDC_PAR_SUBSYS_ID			0x01
#define	AUDIOHDC_PAR_REV_ID			0x02
#define	AUDIOHDC_PAR_NODE_COUNT			0x04
#define	AUDIOHDC_PAR_FUNCTION_TYPE		0x05
#define	AUDIOHDC_PAR_AUDIO_FG_CAP		0x08
#define	AUDIOHDC_PAR_AUDIO_WID_CAP		0x09
#define	AUDIOHDC_PAR_PCM			0x0a
#define	AUDIOHDC_PAR_STREAM			0x0b
#define	AUDIOHDC_PAR_PIN_CAP			0x0c
#define	AUDIOHDC_PAR_AMP_IN_CAP			0x0d
#define	AUDIOHDC_PAR_CONNLIST_LEN		0x0e
#define	AUDIOHDC_PAR_POWER_STATE		0x0f
#define	AUDIOHDC_PAR_PROC_CAP			0x10
#define	AUDIOHDC_PAR_GPIO_CAP			0x11
#define	AUDIOHDC_PAR_AMP_OUT_CAP		0x12

/*
 * bits for get/set amplifier gain/mute
 */
#define	AUDIOHDC_AMP_SET_OUTPUT			0x8000
#define	AUDIOHDC_AMP_SET_INPUT			0x4000
#define	AUDIOHDC_AMP_SET_LEFT			0x2000
#define	AUDIOHDC_AMP_SET_RIGHT			0x1000
#define	AUDIOHDC_AMP_SET_MUTE			0x0080
#define	AUDIOHDC_AMP_SET_LR_INPUT		0x7000
#define	AUDIOHDC_AMP_SET_LR_OUTPUT		0xb000
#define	AUDIOHDC_AMP_SET_INDEX_OFFSET		8
#define	AUDIOHDC_AMP_SET_GAIN_MASK		0x007f
#define	AUDIOHDC_GAIN_MAX			0x7f
#define	AUDIOHDC_GAIN_BITS			7
#define	AUDIOHDC_GAIN_DEFAULT			0x0f

/* value used to set max volume for left output */
#define	AUDIOHDC_AMP_LOUT_MAX	\
	(AUDIOHDC_AMP_SET_OUTPUT | \
	AUDIOHDC_AMP_SET_LEFT | \
	AUDIOHDC_GAIN_MAX)

/* value used to set max volume for right output */
#define	AUDIOHDC_AMP_ROUT_MAX	\
	(AUDIOHDC_AMP_SET_OUTPUT | \
	AUDIOHDC_AMP_SET_RIGHT | \
	AUDIOHDC_GAIN_MAX)


/*
 * Bits for pin widget control verb
 */
#define	AUDIOHDC_PIN_CONTROL_HP_ENABLE		0x80
#define	AUDIOHDC_PIN_CONTROL_OUT_ENABLE		0x40
#define	AUDIOHDC_PIN_CONTROL_IN_ENABLE		0x20

/*
 * Bits for Amplifier capabilities
 */
#define	AUDIOHDC_AMP_CAP_MUTE_CAP		0x80000000
#define	AUDIOHDC_AMP_CAP_STEP_SIZE		0x007f0000
#define	AUDIOHDC_AMP_CAP_STEP_NUMS		0x00007f00
#define	AUDIOHDC_AMP_CAP_0DB_OFFSET		0x0000007f


#define	AUDIOHD_CODEC_FAILURE	(uint32_t)(-1)


/*
 * input index for analog mixer (nid=0x20) of AD1988 CODEC
 */
enum {
	AD1988_NID20H_INPUT_INDEX_MIC1 = 0,
	AD1988_NID20H_INPUT_INDEX_LINE_IN = 1,
	AD1988_NID20H_INPUT_INDEX_MIC2 = 4,
	AD1988_NID20H_INPUT_INDEX_CD = 6,
	AD1988_NID20H_INPUT_INDEX_NULL = -1
};

struct audiohd_codec_ops;
typedef struct  {
	uint8_t		hc_addr;	/* codec address */
	uint32_t	hc_vid;		/* vendor id and device id */
	uint32_t	hc_revid;	/* revision id */

	/*
	 * although the following are the parameters/capabilities
	 * of audio function group, but we just care about AFG,
	 * therefore, it is no different that codec or AFG has
	 * the parameters
	 */
	uint32_t	hc_afg_id;	/* id of AFG */
	uint32_t	hc_sid;		/* sybsystem id for AFG */

	struct audiohd_codec_ops *hc_ops;

}audiohd_hda_codec_t;

/*
 * buffer descriptor list entry of stream descriptor
 */
typedef struct {
	uint64_t	sbde_addr;
	uint32_t	sbde_len;
	uint32_t
		sbde_ioc: 1,
		reserved: 31;
}sd_bdle_t;


#define	AUDIOHD_PLAY_STARTED		0x00000001
#define	AUDIOHD_PLAY_EMPTY		0x00000002
#define	AUDIOHD_PLAY_PAUSED		0x00000004
#define	AUDIOHD_RECORD_STARTED		0x00000008

typedef struct {
	ddi_dma_handle_t	ad_dmahdl;
	ddi_acc_handle_t	ad_acchdl;
	caddr_t		ad_vaddr;	/* virtual addr */
	uint64_t	ad_paddr;	/* physical addr */
	size_t		ad_req_sz;	/* required size of memory */
	size_t		ad_real_sz;	/* real size of memory */
} audiohd_dma_t;

struct audiohd_state {
	audiohdl_t	hda_ahandle;
	dev_info_t	*hda_dip;
	kstat_t		*hda_ksp;
	kmutex_t	hda_mutex;
	uint32_t	hda_flags;

	caddr_t		hda_reg_base;
	ddi_acc_handle_t	hda_pci_handle;
	ddi_acc_handle_t	hda_reg_handle;
	ddi_iblock_cookie_t	hda_intr_cookie;

	audiohd_dma_t	hda_dma_corb;
	audiohd_dma_t	hda_dma_rirb;
	audiohd_dma_t	hda_dma_play_bd;
	audiohd_dma_t	hda_dma_play_buf;
	audiohd_dma_t	hda_dma_record_bd;
	audiohd_dma_t	hda_dma_record_buf;

	int		hda_input_streams;	/* # of input stream */
	int		hda_output_streams;	/* # of output stream */
	int		hda_streams_nums;	/* # of stream */
	int		hda_pbuf_pos;		/* play buffer position */
	int		hda_rbuf_pos;		/* record buffer position */
	uint8_t		hda_rirb_rp;		/* read pointer for rirb */
	uint16_t	hda_codec_mask;

	am_ad_info_t	hda_ad_info;
	audio_info_t	hda_info_defaults;
	audio_device_t	hda_dev_info;

	int		hda_csamples;
	int		hda_psamples;
	int		hda_psample_rate;
	int		hda_pchannels;
	int		hda_pprecision;
	int		hda_csample_rate;
	int		hda_cchannels;
	int		hda_cprecision;
	int		hda_pint_freq;	/* play intr frequence */
	int		hda_rint_freq;	/* record intr frequence */
	int		hda_pbuf_size;	/* play buffer size */
	int		hda_rbuf_size;	/* record buffer size */

	boolean_t	hda_outputs_muted;

	uint_t		hda_monitor_gain;
	uint_t		hda_mgain_max;
	uint_t		hda_play_stag;		/* tag of playback stream */
	uint_t		hda_record_stag;	/* tag of record stream */
	uint_t		hda_play_regbase;	/* regbase for play stream */
	uint_t		hda_record_regbase;	/* regbase for record stream */
	uint_t		hda_play_lgain;		/* left gain for playback */
	uint_t		hda_play_rgain;		/* right gain for playback */
	uint_t		hda_pgain_max;		/* max gain for playback */
	uint_t		hda_record_lgain;	/* left gain for recording */
	uint_t		hda_record_rgain;	/* right gain for recording */
	uint_t		hda_rgain_max;		/* max gain for record */
	uint_t		hda_play_format;
	uint_t		hda_record_format;
	uint_t		hda_out_ports;		/* active outputs */
	uint_t		hda_in_ports;		/* active inputs */

	audiohd_hda_codec_t	*hda_codec;

	boolean_t	suspended;		/* suspend/resume state */
	int		hda_busy_cnt;		/* device busy count */
	kcondvar_t	hda_cv;
};

typedef struct audiohd_state audiohd_state_t;

struct audiohd_codec_ops {
	int (*ac_init_codec)(audiohd_state_t *);
	int (*ac_set_pcm_fmt)(audiohd_state_t *, int, uint_t);
	int (*ac_set_gain)(audiohd_state_t *, int, int, int);
	int (*ac_set_port)(audiohd_state_t *, int, int);
	int (*ac_mute_outputs)(audiohd_state_t *, boolean_t);
	int (*ac_set_monitor_gain)(audiohd_state_t *, int);
	void (*ac_get_max_gain)
		(audiohd_state_t *, uint_t *, uint_t *, uint_t *);
};

#define	AUDIOHD_CODEC_INIT_CODEC(x) \
	x->hda_codec->hc_ops->ac_init_codec(x);

#define	AUDIOHD_CODEC_SET_PCM_FORMAT(x, y, z) \
	x->hda_codec->hc_ops->ac_set_pcm_fmt(x, y, z);

#define	AUDIOHD_CODEC_SET_GAIN(x, y, z, w) \
	x->hda_codec->hc_ops->ac_set_gain(x, y, z, w)

#define	AUDIOHD_CODEC_SET_PORT(x, y, z) \
	x->hda_codec->hc_ops->ac_set_port(x, y, z)

#define	AUDIOHD_CODEC_MUTE_OUTPUTS(x, y) \
	x->hda_codec->hc_ops->ac_mute_outputs(x, y)

#define	AUDIOHD_CODEC_SET_MON_GAIN(x, y) \
	x->hda_codec->hc_ops->ac_set_monitor_gain(x, y)

#define	AUDIOHD_CODEC_MAX_GAIN(x, y, z, w) \
	x->hda_codec->hc_ops->ac_get_max_gain(x, y, z, w)

/*
 * Operation for high definition audio control system bus
 * interface registers
 */
#define	AUDIOHD_REG_GET8(reg)	\
	ddi_get8(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)))

#define	AUDIOHD_REG_GET16(reg)	\
	ddi_get16(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)))

#define	AUDIOHD_REG_GET32(reg)	\
	ddi_get32(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)))

#define	AUDIOHD_REG_GET64(reg)	\
	ddi_get64(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)))

#define	AUDIOHD_REG_SET8(reg, val)	\
	ddi_put8(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)), (val))

#define	AUDIOHD_REG_SET16(reg, val)	\
	ddi_put16(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)), (val))

#define	AUDIOHD_REG_SET32(reg, val)	\
	ddi_put32(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)), (val))

#define	AUDIOHD_REG_SET64(reg, val)	\
	ddi_put64(statep->hda_reg_handle, \
	(void *)((char *)statep->hda_reg_base + (reg)), (val))


/*
 * This is used to initialize ADC node of CODEC
 */
#define	AUDIOHD_NODE_INIT_ADC(statep, caddr, nid) \
{	\
	/* for ADC node, set channel and stream tag */ \
	if (audioha_codec_verb_get(statep, \
	    caddr, nid, AUDIOHDC_VERB_SET_STREAM_CHANN, \
	    statep->hda_record_stag << 4) == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	\
	/* set input amp of ADC node to max */ \
	if (audioha_codec_4bit_verb_get(statep, \
	    caddr, nid, AUDIOHDC_VERB_SET_AMP_MUTE, \
	    AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX) == \
	    AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}

/*
 * This is used to initialize DAC node of CODEC
 */
#define	AUDIOHD_NODE_INIT_DAC(statep, caddr, nid) \
{	\
	if (audioha_codec_verb_get(statep, \
	    caddr, nid, AUDIOHDC_VERB_SET_STREAM_CHANN, \
	    statep->hda_play_stag << 4) == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	\
	/* set output amp of DAC to max */ \
	if (audioha_codec_4bit_verb_get(statep, \
	    caddr, nid, AUDIOHDC_VERB_SET_AMP_MUTE, \
	    AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_GAIN_MAX) == \
	    AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}


/*
 * unmute specified one of a mixer's inputs, and set the
 * left & right output volume of mixer to specified value
 */
#define	AUDIOHD_NODE_INIT_MIXER(statep, caddr, nid_m, in_num) \
{ \
	/* unmute input of mixer */ \
	if (audioha_codec_4bit_verb_get(statep, caddr, nid_m, \
	    AUDIOHDC_VERB_SET_AMP_MUTE, \
	    AUDIOHDC_AMP_SET_LR_INPUT | AUDIOHDC_GAIN_MAX | \
		(in_num << AUDIOHDC_AMP_SET_INDEX_OFFSET)) == \
	    AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	\
	/* output left amp of mixer */ \
	(void) audioha_codec_4bit_verb_get(statep, caddr, nid_m, \
	    AUDIOHDC_VERB_SET_AMP_MUTE, AUDIOHDC_AMP_SET_OUTPUT | \
	    AUDIOHDC_AMP_SET_LEFT | statep->hda_play_lgain); \
	\
	/* output right amp of mixer */ \
	(void) audioha_codec_4bit_verb_get(statep, caddr, nid_m, \
	    AUDIOHDC_VERB_SET_AMP_MUTE, AUDIOHDC_AMP_SET_OUTPUT | \
	    AUDIOHDC_AMP_SET_RIGHT | statep->hda_play_rgain); \
}


/*
 * enable a pin widget to output
 */
#define	AUDIOHD_NODE_ENABLE_PIN_OUT(statep, caddr, nid) \
{ \
	uint32_t	lTmp; \
\
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_GET_PIN_CTRL, 0); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_SET_PIN_CTRL, \
	    (lTmp | AUDIOHDC_PIN_CONTROL_OUT_ENABLE | \
	    AUDIOHDC_PIN_CONTROL_HP_ENABLE)); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}

/*
 * disable output pin
 */
#define	AUDIOHD_NODE_DISABLE_PIN_OUT(statep, caddr, nid) \
{ \
	uint32_t	lTmp; \
\
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_GET_PIN_CTRL, 0); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_SET_PIN_CTRL, \
	    (lTmp & ~AUDIOHDC_PIN_CONTROL_OUT_ENABLE)); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}

/*
 * enable a pin widget to input
 */
#define	AUDIOHD_NODE_ENABLE_PIN_IN(statep, caddr, nid) \
{ \
	(void) audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_SET_PIN_CTRL, AUDIOHDC_PIN_CONTROL_IN_ENABLE | 4); \
}


/*
 * disable input pin
 */
#define	AUDIOHD_NODE_DISABLE_PIN_IN(statep, caddr, nid) \
{ \
	uint32_t	lTmp; \
\
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_GET_PIN_CTRL, 0); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
	lTmp = audioha_codec_verb_get(statep, caddr, nid, \
	    AUDIOHDC_VERB_SET_PIN_CTRL, \
	    (lTmp & ~AUDIOHDC_PIN_CONTROL_IN_ENABLE)); \
	if (lTmp == AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}

/*
 * unmute an output pin
 */
#define	AUDIOHD_NODE_UNMUTE_OUT(statep, caddr, nid) \
{ \
	if (audioha_codec_4bit_verb_get(statep, \
	    caddr, nid, AUDIOHDC_VERB_SET_AMP_MUTE, \
	    AUDIOHDC_AMP_SET_LR_OUTPUT | AUDIOHDC_GAIN_MAX) == \
	    AUDIOHD_CODEC_FAILURE) \
		return (AUDIO_FAILURE); \
}

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_AUDIOHD_IMPL_H_ */
