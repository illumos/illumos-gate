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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * CMI (C-Media) codec extensions.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include <sys/note.h>
#include "ac97_impl.h"

/*
 * C-Media 9739 part is weird.  Instead of having independent volume
 * controls for each of the channels, it uses a single master volume
 * and just provides mute support for the other bits.  It does this
 * for PCM volume as well, so we can't use it either.  Ugh.  It also
 * has an optional 30 dB mic boost.  Apparently the 9761 behaves in
 * much the same fashion as the 9739.
 *
 * C-Media 9738 is a more or less typical 4CH device according to the
 * datasheet.  It however supports jack retasking allowing the line in
 * jack to function as a surround output.  Google suggests that the
 * volume controls on this part are about as busted as on the other
 * parts.  So, we just use synthetic volume for it.
 *
 * C-Media 9780 is largely a mystery (ENODATASHEET).
 */


#define	CMI_TASK_REGISTER	0x5A	/* 9738 jack retasking */
#define	CTR_F2R			0x2000	/* front routed to rear */
#define	CTR_S2LNI		0x0400	/* surround to line in */

#define	CMI_MULTICH_REGISTER	0x64	/* 9739 and 9761a */
#define	CMR_PCBSW		0x8000	/* PC Beep volume bypass */
#define	CMR_P47			0x4000	/* configure P47 function */
#define	CMR_REFCTL		0x2000	/* enable vref output */
#define	CMR_CLCTL		0x1000	/* center/lfe output enable */
#define	CMR_S2LNI		0x0400	/* surround to line in */
#define	CMR_MIX2S		0x0200	/* analog input pass to surround */
#define	CMR_BSTSEL		0x0001	/* micboost use 30dB */

static void
cmi_set_micboost(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t	*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	switch (value) {
	case 0x1:
		/* 0db */
		ac_clr(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		ac_clr(ac, CMI_MULTICH_REGISTER, CMR_BSTSEL);
		break;
	case 0x2:
		/* 20dB */
		ac_set(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		ac_clr(ac, CMI_MULTICH_REGISTER, CMR_BSTSEL);
		break;
	case 0x4:
		/* 30dB */
		ac_set(ac, AC97_MIC_VOLUME_REGISTER, MICVR_20dB_BOOST);
		ac_set(ac, CMI_MULTICH_REGISTER, CMR_BSTSEL);
		break;
	}
}

static void
cmi_set_linein_func(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	if (value & 2) {
		ac_set(ac, CMI_MULTICH_REGISTER, CMR_S2LNI);
	} else {
		ac_clr(ac, CMI_MULTICH_REGISTER, CMR_S2LNI);
	}
}

static void
cmi_set_mic_func(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	if (value & 2) {
		ac_set(ac, CMI_MULTICH_REGISTER, CMR_CLCTL);
	} else {
		ac_clr(ac, CMI_MULTICH_REGISTER, CMR_CLCTL);
	}
}

static void
cmi_setup_micboost(ac97_t *ac)
{
	ac97_ctrl_t		*ctrl;

	static const char	*values[] = {
		AUDIO_VALUE_OFF,	/* 0dB */
		AUDIO_VALUE_MEDIUM,	/* 20dB */
		AUDIO_VALUE_HIGH,	/* 30dB */
		NULL
	};
	ac97_ctrl_probe_t cpt = {
		AUDIO_CTRL_ID_MICBOOST, 1, 0xf, 0xf, AUDIO_CTRL_TYPE_ENUM,
		AC97_FLAGS | AUDIO_CTRL_FLAG_REC, 0, cmi_set_micboost,
		NULL, 0, values };

	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_MICBOOST);
	if (ctrl) {
		if (ctrl->actrl_initval) {
			/* 20dB by default */
			cpt.cp_initval = 1;
		}
	}

	ac_add_control(ac, &cpt);
}

static const char *cmi_linein_funcs[] = {
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_SURROUND,
	NULL
};

static const char *cmi_mic_funcs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_CENLFE,
	NULL
};

static void
cmi_setup_jack_funcs(ac97_t *ac)
{
	ac97_ctrl_probe_t	cp;
	int			ival;

	ac97_ctrl_probe_t linein_cpt = {
		AUDIO_CTRL_ID_JACK1, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM, AC97_FLAGS,
		0, cmi_set_linein_func, NULL, 0, cmi_linein_funcs
	};
	ac97_ctrl_probe_t mic_cpt = {
		AUDIO_CTRL_ID_JACK2, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM, AC97_FLAGS,
		0, cmi_set_mic_func, NULL, 0, cmi_mic_funcs
	};

	bcopy(&linein_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_LINEIN_FUNC, 0);
	if ((ival >= 1) && (ival <= 2)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);

	bcopy(&mic_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_MIC_FUNC, 0);
	if ((ival >= 1) && (ival <= 2)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);
}

static void
cmi_set_linein_func_9738(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	if (value & 2) {
		ac_set(ac, CMI_TASK_REGISTER, CTR_S2LNI);
	} else {
		ac_clr(ac, CMI_TASK_REGISTER, CTR_S2LNI);
	}
}

static void
cmi_set_spread_9738(ac97_ctrl_t *actrl, uint64_t value)
{
	ac97_t		*ac = actrl->actrl_ac97;

	if (value) {
		ac_set(ac, CMI_TASK_REGISTER, CTR_F2R);
	} else {
		ac_clr(ac, CMI_TASK_REGISTER, CTR_F2R);
	}
}

static void
cmi_setup_jack_func_9738(ac97_t *ac)
{
	ac97_ctrl_probe_t	cp;
	int			ival;

	ac97_ctrl_probe_t linein_cpt = {
		AUDIO_CTRL_ID_JACK1, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM, AC97_FLAGS,
		0, cmi_set_linein_func_9738, NULL, 0, cmi_linein_funcs
	};
	ac97_ctrl_probe_t spread_cpt = {
		AUDIO_CTRL_ID_SPREAD, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
		AC97_FLAGS, 0, cmi_set_spread_9738,
	};

	bcopy(&linein_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_LINEIN_FUNC, 0);
	if ((ival >= 1) && (ival <= 2)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);

	bcopy(&spread_cpt, &cp, sizeof (cp));
	ival = ac_get_prop(ac, AC97_PROP_SPREAD, -1);
	if ((ival >= 0) && (ival <= 1)) {
		cp.cp_initval = ival;
	}
	ac_add_control(ac, &cp);
}


static void
cmi_setup_volume(ac97_t *ac)
{
	ac97_ctrl_t	*ctrl;

	/*
	 * These CMI parts seem to be really weird.  They don't have
	 * *any* functioning volume controls on them (mute only) apart
	 * from the record and monitor sources (excluding PCM).  I
	 * don't understand why not.  We just eliminate all of the
	 * volume controls and replace with a soft volume control.
	 * Its not an ideal situation, but I don't know what else I
	 * can do about it.
	 */
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_VOLUME);
	if (ctrl) {
		ac97_control_remove(ctrl);
	}
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_FRONT);
	if (ctrl) {
		ac97_control_remove(ctrl);
	}
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_SURROUND);
	if (ctrl) {
		ac97_control_remove(ctrl);
	}
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_CENTER);
	if (ctrl) {
		ac97_control_remove(ctrl);
	}
	ctrl = ac97_control_find(ac, AUDIO_CTRL_ID_LFE);
	if (ctrl) {
		ac97_control_remove(ctrl);
	}

	/* make sure we have disabled mute and attenuation on physical ctrls */
	ac_wr(ac, AC97_INTERRUPT_PAGING_REGISTER, 0);	/* select page 0 */
	ac_wr(ac, AC97_PCM_OUT_VOLUME_REGISTER, 0);
	ac_wr(ac, AC97_MASTER_VOLUME_REGISTER, 0);
	ac_wr(ac, AC97_EXTENDED_C_LFE_VOLUME_REGISTER, 0);
	ac_wr(ac, AC97_EXTENDED_LRS_VOLUME_REGISTER, 0);

	/*
	 * NB: This is probably not the best way to do this, because
	 * it will make overriding this hard for drivers that desire
	 * to.  Fortunately, we don't think any drivers that want to
	 * override or fine tune AC'97 controls (i.e. creative cards)
	 * use these C-Media codecs.
	 */
	audio_dev_add_soft_volume(ac_get_dev(ac));
}

void
cmi9739_init(ac97_t *ac)
{
	cmi_setup_volume(ac);
	cmi_setup_micboost(ac);
	cmi_setup_jack_funcs(ac);
}

void
cmi9761_init(ac97_t *ac)
{
	cmi_setup_volume(ac);
	cmi_setup_micboost(ac);
	cmi_setup_jack_funcs(ac);
}

void
cmi9738_init(ac97_t *ac)
{
	cmi_setup_volume(ac);
	cmi_setup_jack_func_9738(ac);
}
