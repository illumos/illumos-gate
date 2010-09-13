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
 * ADS (Analog Devices) codec extensions.
 */

/*
 * TODO:
 *
 * Most vendors connect the surr-out of ad1980/ad1985 codecs to the
 * line-out jack. So far we haven't found which vendors don't
 * do that. So we assume that all vendors swap the surr-out
 * and the line-out outputs. So we need swap the two outputs.
 *
 * Historically we internally processed the "ad198x-swap-output"
 * property. If someday some vendors do not swap the outputs, we would
 * set "ad198x-swap-output = 0" in the driver.conf file, and unload
 * and reload the driver (or reboot).
 *
 * TODO:
 *
 * Since we don't have access (at present) to any such systems, we have
 * not implemented this swapping property.  Once we can test it, we will
 * add it.  This is noted as CR 6819556.
 *
 * The old code did this:
 *
 *	if (ddi_prop_get_int(DDI_DEV_T_ANY, statep->dip,
 *	    DDI_PROP_DONTPASS, "ad198x-swap-output", 1) == 1) {
 *		statep->swap_out = B_TRUE;
 *		(void) audioixp_read_ac97(statep, CODEC_AD_REG_MISC, &tmp);
 *		(void) audioixp_write_ac97(statep,
 *		    CODEC_AD_REG_MISC,
 *		    tmp | AD1980_MISC_LOSEL | AD1980_MISC_HPSEL);
 *
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include <sys/note.h>
#include "ac97_impl.h"

#define	ADS_EQ_CTRL_REGISTER		0x60
#define	AECR_EQM			0x8000	/* disable EQ */
#define	AECR_SYM			0x0080

#define	ADS_EQ_DATA_REGISTER		0x62

#define	ADS_MIXER_ADC_IGAIN_REGISTER	0x64
#define	AMADIR_LEFT_MASK		0x0f00
#define	AMADIR_RIGHT_MASK		0x000f
#define	AMADIR_MXM			0x8000

#define	ADS_JS_INTS_STATUS_REGISTER	0x72
#define	AJISR_JS0INT			0x0001
#define	AJISR_JS1INT			0x0002
#define	AJISR_JS0ST			0x0004
#define	AJISR_JS1ST			0x0008
#define	AJISR_JS0MD			0x0010
#define	AJISR_JS1MD			0x0020
#define	AJISR_JS0TMR			0x0040
#define	AJISR_JS1TMR			0x0080
#define	AJISR_JS0EQB			0x0100
#define	AJISR_JS1EQB			0x0200
#define	AJISR_JSMT_MASK			0x1c00
#define	AJISR_JSMT_NONE			0x0000
#define	AJISR_JSMT_HP_LNOUT		0x0400	/* hp mutes line out */
#define	AJISR_JSMT_HP_BOTH		0x0800	/* hp mutes both mono & line */
#define	AJISR_JSMT_LNOUT_MONO		0x1000	/* lineout mutes mono */
#define	AJISR_JSMT_ALL			0x1800	/* all JS muting enabled */

#define	ADS_SERIAL_CFG_REGISTER		0x74
#define	ASCR_SPLNK			0x0001
#define	ASCR_SPDZ			0x0002
#define	ASCR_SPAL			0x0004
#define	ASCR_INTS			0x0010
#define	ASCR_CHEN			0x0100
#define	ASCR_REGM0			0x1000
#define	ASCR_REGM1			0x2000
#define	ASCR_REGM2			0x4000
#define	ASCR_SLOT16			0x8000

#define	ADS_MISC_CFG_REGISTER		0x76
#define	AMCR_MBG_MASK			0x0003
#define	AMCR_MBG_20dB			0x0000
#define	AMCR_MBG_10dB			0x0001
#define	AMCR_MBG_30dB			0x0002
#define	AMCR_VREFD			0x0004
#define	AMCR_VREFH			0x0008
#define	AMCR_MADST			0x0010	/* AD1981B */
#define	AMCR_SRU			0x0010	/* AD1980 */
#define	AMCR_LOSEL			0x0020	/* AD1980 */
#define	AMCR_2CMIC			0x0040
#define	AMCR_MADPD			0x0080	/* AD1981B */
#define	AMCR_SPRD			0x0080	/* AD1980 */
#define	AMCR_DMIX_6TO2			0x0100	/* AD1980 */
#define	AMCR_DMIX_FORCE			0x0200	/* AD1980 */
#define	AMCR_FMXE			0x0200	/* AD1981B */
#define	AMCR_HPSEL			0x0400	/* AD1980 */
#define	AMCR_CLDIS			0x0800	/* AD1980 */
#define	AMCR_LODIS			0x1000	/* AD1980 */
#define	AMCR_DAM			0x0800	/* AD1981B */
#define	AMCR_MSPLT			0x2000
#define	AMCR_AC97NC			0x4000	/* AD1980 */
#define	AMCR_DACZ			0x8000

static void
ads_set_micboost(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t	*ac = actrl->actrl_ac97;
	uint16_t	v;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	switch (value) {
	case 0x1:
		/* 0db */
		ac_clr(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		break;
	case 0x2:
		/* 10dB */
		ac_set(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		v = ac_rd(ac, ADS_MISC_CFG_REGISTER);
		v &= ~AMCR_MBG_MASK;
		v |= AMCR_MBG_10dB;
		ac_wr(ac, ADS_MISC_CFG_REGISTER, v);
		break;
	case 0x4:
		/* 20dB */
		ac_set(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		v = ac_rd(ac, ADS_MISC_CFG_REGISTER);
		v &= ~AMCR_MBG_MASK;
		v |= AMCR_MBG_20dB;
		ac_wr(ac, ADS_MISC_CFG_REGISTER, v);
		break;
	case 0x8:
		/* 30dB */
		ac_set(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		v = ac_rd(ac, ADS_MISC_CFG_REGISTER);
		v &= ~AMCR_MBG_MASK;
		v |= AMCR_MBG_30dB;
		ac_wr(ac, ADS_MISC_CFG_REGISTER, v);
		break;
	}
}

static void
ads_set_micsrc(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t	*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	switch (value) {
	case 0x1:	/* mic1 */
		ac_clr(ac, ADS_MISC_CFG_REGISTER, AMCR_2CMIC);
		ac_clr(ac, AC97_GENERAL_PURPOSE_REGISTER, GPR_MS_MIC2);
		break;
	case 0x2:	/* mic2 */
		ac_clr(ac, ADS_MISC_CFG_REGISTER, AMCR_2CMIC);
		ac_set(ac, AC97_GENERAL_PURPOSE_REGISTER, GPR_MS_MIC2);
		break;
	case 0x4:	/* stereo - ms bit clear to allow MIC1 to be mixed */
		ac_set(ac, ADS_MISC_CFG_REGISTER, AMCR_2CMIC);
		ac_clr(ac, AC97_GENERAL_PURPOSE_REGISTER, GPR_MS_MIC2);
		break;
	}
}

static void
ads_setup_micsrc(ac97_t *ac)
{
	static const char	*values[] = {
		AUDIO_PORT_MIC1,
		AUDIO_PORT_MIC2,
		AUDIO_PORT_STEREO,
		NULL
	};
	ac97_ctrl_probe_t cpt = {
		AUDIO_CTRL_ID_MICSRC, 1, 0x7, 0x7, AUDIO_CTRL_TYPE_ENUM,
		AC97_FLAGS | AUDIO_CTRL_FLAG_REC, 0, ads_set_micsrc,
		NULL, 0, values };

	ac_add_control(ac, &cpt);
}

static void
ads_setup_micboost(ac97_t *ac)
{
	ac97_ctrl_t		*ctrl;

	static const char	*values[] = {
		AUDIO_VALUE_OFF,	/* 0dB */
		AUDIO_VALUE_LOW,	/* 10dB */
		AUDIO_VALUE_MEDIUM,	/* 20dB */
		AUDIO_VALUE_HIGH,	/* 30dB */
		NULL
	};
	ac97_ctrl_probe_t cpt = {
		AUDIO_CTRL_ID_MICBOOST, 1, 0xf, 0xf, AUDIO_CTRL_TYPE_ENUM,
		AC97_FLAGS | AUDIO_CTRL_FLAG_REC, 0, ads_set_micboost,
		NULL, 0, values };

	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_MICBOOST);
	if (ctrl) {
		if (ctrl->actrl_initval) {
			/* 20dB by default */
			cpt.cp_initval = 2;
		}
	}

	ac_add_control(ac, &cpt);
}

void
ad1981a_init(ac97_t *ac)
{
	ads_setup_micboost(ac);
}

void
ad1981b_init(ac97_t *ac)
{
	ads_setup_micboost(ac);
	ads_setup_micsrc(ac);	/* this part can use a mic array */
}
