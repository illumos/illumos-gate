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
 * ALC (Realtek/Advance Logic) codec extensions.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include <sys/note.h>
#include "ac97_impl.h"

#define	ALC_DATA_FLOW_CTRL_REGISTER	0x6a
#define	ADFC_SPDIFIN_EN			0x8000
#define	ADFC_SPDIFIN_MON_EN		0x4000
#define	ADFC_SPDIF_OUT_MASK		0x3000
#define	ADFC_SPDIF_OUT_ACLINK		0x0000
#define	ADFC_SPDIF_OUT_ADC		0x1000
#define	ADFC_SPDIF_OUT_BYPASS		0x2000
#define	ADFC_PCM_SPDIFIN		0x0800
#define	ADFC_BACK_SURROUND		0x0400	/* ALC850 only */
#define	ADFC_CENTER_LFE			0x0400	/* ALC650 series */
#define	ADFC_MIC			0x0000
#define	ADFC_SURROUND			0x0200
#define	ADFC_LINEIN			0x0000
#define	ADFC_FRONT_MIC_MONO_OUT		0x0100	/* ALC850 */
#define	ADFC_ANALOG_INPUT_PASS_CLFE	0x0020
#define	ADFC_ANALOG_INPUT_PASS_SURROUND	0x0010
#define	ADFC_SURROUND_MIRROR		0x0001

#define	ALC_SURROUND_DAC_REGISTER	0x64
#define	ASD_SURROUND_MUTE		0x8000
#define	ASD_SURR_LEFT_VOL		0x1f00
#define	ASD_SURR_RIGHT_VOL		0x001f

#define	ALC_CEN_LFE_DAC_REGISTER	0x66
#define	ACLD_CEN_LFE_MUTE		0x8000
#define	ACLD_LFE_VOL			0x1f00
#define	ACLD_CEN_VOL			0x001f

#define	ALC_MISC_CTRL_REGISTER		0x7a
#define	AMC_XTLSEL			0x8000
#define	AMC_VREFOUT_DIS			0x1000
#define	AMC_INDEP_MUTE_CTRL		0x0800
#define	AMC_JD2_SURR_CEN_LFE		0x0008
#define	AMC_JD1_SURR_CEN_LFE		0x0004
#define	AMC_PIN47_SPDIF			0x0002
#define	AMC_PIN47_EAPD			0x0000
#define	AMC_JD0_SURR_CEN_LFE		0x0001

static void
alc650_set_linein_func(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	if (value & 2) {
		ac_set(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_SURROUND);
	} else {
		ac_clr(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_SURROUND);
	}
}

static void
alc650_set_mic_func(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	if (value & 2) {
		ac_set(ac, ALC_MISC_CTRL_REGISTER, AMC_VREFOUT_DIS);
		ac_set(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_CENTER_LFE);
	} else {
		ac_clr(ac, ALC_MISC_CTRL_REGISTER, AMC_VREFOUT_DIS);
		ac_clr(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_CENTER_LFE);
	}
}

#if 0
static void
alc850_set_auxin_func(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	if (value & 2) {
		ac_set(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_BACK_SURROUND);
	} else {
		ac_clr(ac, ALC_DATA_FLOW_CTRL_REGISTER, ADFC_BACK_SURROUND);
	}
}
#endif

static void
alc650_set_pcm(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;
	uint16_t	adj_value;
	uint16_t	mute;
	uint8_t		vol;

	/* limit input values to 16 bits and split to right and left */
	vol = value & 0xff;

	/* If this control is mute-able than set as muted if needed */
	mute = vol ? 0 : ASD_SURROUND_MUTE;
	adj_value = ac_val_scale(vol, vol, 5) | mute;

	/* select page 0 */
	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);
	/* adjust all three PCM volumes */
	ac_wr(ac, AC97_PCM_OUT_VOLUME_REGISTER, adj_value);
	ac_wr(ac, ALC_SURROUND_DAC_REGISTER, adj_value);
	ac_wr(ac, ALC_CEN_LFE_DAC_REGISTER, adj_value);
}

static const char *alc_linein_funcs[] = {
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_SURROUND,
	NULL
};

static const char *alc_mic_funcs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_CENLFE,
	NULL
};

static ac97_ctrl_probe_t alc650_linein_func_cpt = {
	AUDIO_CTRL_ID_JACK1, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM, AC97_FLAGS,
	0, alc650_set_linein_func, NULL, 0, alc_linein_funcs
};
static ac97_ctrl_probe_t alc650_mic_func_cpt = {
	AUDIO_CTRL_ID_JACK2, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM, AC97_FLAGS,
	0, alc650_set_mic_func, NULL, 0, alc_mic_funcs
};

static void
alc_pcm_override(ac97_t *ac)
{
	ac97_ctrl_t	*ctrl;

	/* override master PCM volume function */
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_VOLUME);
	if (ctrl != NULL) {
		ctrl->actrl_write_fn = alc650_set_pcm;
	}
}

void
alc650_init(ac97_t *ac)
{
	ac97_ctrl_probe_t	cp;
	int			ival;

	bcopy(&alc650_linein_func_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_LINEIN_FUNC, 0);
	if ((ival >= 1) && (ival <= 2)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);

	bcopy(&alc650_mic_func_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_MIC_FUNC, 0);
	if ((ival >= 1) && (ival <= 2)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);

	alc_pcm_override(ac);
}

void
alc850_init(ac97_t *ac)
{
	/*
	 * NB: We could probably enable 7.1 here using the AUXIN source,
	 * but there are a few details still missing from the data sheet.
	 * (Such as, how is volume from the back-surround DAC managed?,
	 * and what SDATA slots are the back surround delivered on?)
	 *
	 * Also, the AC'97 controllers themselves don't necessarily support
	 * 7.1, so we'd have to figure out how to coordinate detection
	 * with the controller.  5.1 should be good enough for now.
	 *
	 * Unlike other products, ALC850 has separate pins for 5.1 data,
	 * so jack retasking isn't needed.  However, it can retask
	 * some jacks, but we don't have full details for that right
	 * now.  We've not seen it on any systems (yet) where this was
	 * necessary, though.
	 */

	alc_pcm_override(ac);
}
