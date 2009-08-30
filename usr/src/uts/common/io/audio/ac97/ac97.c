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
 * Copyright (C) 4Front Technologies 1996-2008.
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_driver.h>
#include <sys/audio/ac97.h>
#include <sys/note.h>
#include "ac97_impl.h"

/*
 * This is the initial value for many controls. This is
 * a 75% level.
 */
#define	INIT_VAL_MAIN	((75 << 8) | 75)
#define	INIT_VAL_ST	((75 << 8) | 75)
#define	INIT_VAL_MN	75
#define	INIT_IGAIN_ST	((50 << 8) | 50)
#define	INIT_IGAIN_MN	50

/*
 * In AC'97 v2.3, the registers are carved up as follows:
 *
 * Audio Base Registers: 	0x00 - 0x26
 * Audio Extended Registers:	0x28 - 0x3A
 * Modem Extended Registers:	0x3C - 0x58
 * Vendor Reserved Registers:	0x5A - 0x5F
 * Page Registers:		0x60 - 0x6F
 * Vendor Reserved Registers:	0x70 - 0x7A
 * Vendor ID Registers:		0x7C - 0x7F
 *
 * We only need to shadow the normal audio registers by default.
 * TBD: Handling of codec-specific registers in vendor reserved space.
 * We cannot necessarily meaningfully shadow them.
 */
#define	LAST_SHADOW_REG	0x3A
#define	NUM_SHADOW	((LAST_SHADOW_REG / sizeof (uint16_t)) + 1)
#define	SHADOW(ac, reg)	((ac)->shadow[((reg) / sizeof (uint16_t))])

/*
 * Record source selection.
 */
#define	INPUT_MIC		0
#define	INPUT_CD		1
#define	INPUT_VIDEO		2
#define	INPUT_AUXIN		3
#define	INPUT_LINEIN		4
#define	INPUT_STEREOMIX		5
#define	INPUT_MONOMIX		6
#define	INPUT_PHONE		7

static const char *ac_insrcs[] = {
	AUDIO_PORT_MIC,
	AUDIO_PORT_CD,
	AUDIO_PORT_VIDEO,
	AUDIO_PORT_AUX1IN,
	AUDIO_PORT_LINEIN,
	AUDIO_PORT_STEREOMIX,
	AUDIO_PORT_MONOMIX,
	AUDIO_PORT_PHONE,
	NULL,
};

/*
 * Per audio device state structure
 */
struct ac97 {
	dev_info_t	*dip;	/* DDI device instance */
	audio_dev_t	*d;
	void		*private;  /* drivers devc */
	ac97_rd_t	rd;	/* drivers port read routine */
	ac97_wr_t	wr;	/* drivers port write routine */
	char		name[128]; /* driver instance name */
	uint8_t		nchan;

	uint16_t	shadow[NUM_SHADOW];

	boolean_t	suspended;		/* true if suspended */
	kt_did_t	resumer;		/* resumer if suspended */
	uint32_t	flags;
#define	AC97_FLAG_AMPLIFIER	(1 << 0)	/* ext. amp on by default */
#define	AC97_FLAG_MICBOOST	(1 << 1)	/* micboost on by default */
#define	AC97_FLAG_SPEAKER	(1 << 2)	/* mono out on by default */

#define	AC97_FLAG_AUX_HP	(1 << 4)	/* possible uses for AUX_OUT */
#define	AC97_FLAG_AUX_4CH	(1 << 5)
#define	AC97_FLAG_AUX_LVL	(1 << 6)
#define	AC97_FLAG_SPEAKER_OK	(1 << 7)	/* expose mono out */
#define	AC97_FLAG_NO_HEADPHONE	(1 << 8)	/* do not expose headphone */
#define	AC97_FLAG_NO_CDROM	(1 << 9)	/* do not expose CDROM */
#define	AC97_FLAG_NO_PHONE	(1 << 10)	/* do not expose phone in */
#define	AC97_FLAG_NO_VIDEO	(1 << 11)	/* do not expose video in */
#define	AC97_FLAG_NO_AUXIN	(1 << 12)	/* do not expose aux in */
#define	AC97_FLAG_NO_AUXOUT	(1 << 13)	/* do not expose aux out */
#define	AC97_FLAG_NO_LINEIN	(1 << 14)	/* do not expose linein */
#define	AC97_FLAG_NO_MIC	(1 << 15)	/* do not expose mic */

	uint32_t	vid;			/* Vendor ID for CODEC */
	uint16_t	caps;

	void		(*codec_init)(ac97_t *);
	void		(*codec_reset)(ac97_t *);

	kmutex_t	ac_lock;
	list_t		ctrls;

	uint64_t	inputs;

};

struct modlmisc ac97_modlmisc = {
	&mod_miscops,
	"Audio Codec '97 Support"
};

struct modlinkage ac97_modlinkage = {
	MODREV_1,
	{ &ac97_modlmisc, NULL }
};

int
_init(void)
{
	return (mod_install(&ac97_modlinkage));
}

int
_fini(void)
{
	return (mod_install(&ac97_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&ac97_modlinkage, modinfop));
}


#if 0
/*
 * The following table, and the code to scale it, works in percentages.
 * This may be convenient for humans, but it would be faster if the table
 * entries were rescaled to 256.  (Division by 100 is painful.  Divison by
 * 256 is trivial.)
 */
static const char ac97_val_cvt[101] = {
	0, 0, 3, 7, 10, 13, 16, 19,
	21, 23, 26, 28, 30, 32, 34, 35,
	37, 39, 40, 42,	43, 45, 46, 47,
	49, 50, 51, 52, 53, 55, 56, 57,
	58, 59, 60, 61, 62, 63, 64, 65,
	65, 66, 67, 68, 69, 70, 70, 71,
	72, 73, 73, 74, 75, 75, 76, 77,
	77, 78, 79, 79, 80, 81, 81, 82,
	82, 83, 84, 84, 85, 85, 86, 86,
	87, 87, 88, 88, 89, 89, 90, 90,
	91, 91, 92, 92, 93, 93, 94, 94,
	95, 95, 96, 96, 96, 97, 97, 98,
	98, 98, 99, 99, 100
};
#endif

/*
 * This code has three main functions. All related to converting
 * a standard controls value to hardware specific values. All
 * Standard passed in values are 0-100 as in percent.
 *
 * First it takes a value passed in as volume or gain and
 * converts to attenuation or gain correspondingly. Since this is
 * what the hardware needs.
 *
 * Second it adjusts the value passed in to compensate for the none
 * linear nature of human hearing, sound loudness, sensitivity. It
 * converts the linear value to a logarithmic value. This gives users
 * the perception that the controls are linear.
 *
 * Third it converts the value to the number of bits that a hardware
 * register needs to be.
 *
 * On input the following are supplied:
 * left           - The gain or volume in percent for left channel.
 * right          - The gain or volume in percent for right channel.
 * bits           - The number of bits the hardware needs. If this value
 *                  is negetive then right and left are gain else they
 *                  are volume.
 *
 * On return the following is returned:
 *
 * bit: 15             8 7             0
 *     ----------------------------------
 *     | left channel   | right channel |
 *     ----------------------------------
 *      ( each channel is "bits" wide )
 */
uint16_t
ac_val_scale(int left, int right, int bits)
{
	ASSERT(left <= 100);
	ASSERT(right <= 100);

	if (bits < 0) {		/* This is gain not ATTN */
		left = 100 - left;
		right = 100 - right;
		bits = -bits;
	}

#if 0
	/*
	 * 4Front's code used a table to smooth the transitions
	 * somewhat.  Without this change, the volume levels adjusted
	 * near the top of the table seem to have less effect.  Its
	 * hard to notice a volume change from 100 to 95, without the
	 * val_cvt table, for example.  However, the scaling has an
	 * ugly side effect, which is at the default volumes (75%), we
	 * wind up having the level set too high for some
	 * codec/amplifier combinations.
	 *
	 * Legacy Sun code didn't have this table, and some
	 * qualitative testing shows that it isn't really necessary.
	 */
	left = 100 - ac97_val_cvt[left];
	right = 100 - ac97_val_cvt[right];
#else
	left = 100 - left;
	right = 100 - right;
#endif
	return (((left * ((1 << bits) - 1) / 100) << 8) |
	    (right * ((1 << bits) - 1) / 100));
}

uint16_t
ac_mono_scale(int val, int bits)
{
	ASSERT(val <= 100);

	if (bits < 0) {		/* This is gain not ATTN */
		bits = -bits;
	} else {
		val = 100 - val;	/* convert to attenuation */
	}
	return (val * ((1 << bits) - 1) / 100);
}

audio_dev_t *
ac_get_dev(ac97_t *ac)
{
	return (ac->d);
}

int
ac_get_prop(ac97_t *ac, char *prop, int defval)
{
	int	rv;

	rv = ddi_prop_get_int(DDI_DEV_T_ANY, ac->dip, DDI_PROP_DONTPASS,
	    prop, defval);
	return (rv);
}

/*
 * This calls the Hardware drivers access write routine
 * to write to a device register.
 */
#define	WR(r, v)	(ac)->wr((ac)->private, (r), (v))
#define	RD(r)		(ac)->rd((ac)->private, (r))

/*
 * Probe routines for optional controls
 *
 * These routines each probe one aspect of hardware
 * for controls presents.
 * If the control is present these routines should
 * return none zero.
 */

/*
 * Is the named register implemented?  This routine saves and
 * restores the original value, and relies on the fact that the
 * registers (if implemented) will have at least one bit that acts
 * as a mute (0x8000, 0x8080), so we can probe "silently".
 *
 * The probe logic is suggested by the AC'97 2.3 spec.  (Unimplemented
 * registers are required to return zero to facilitate this sort of
 * detection.)
 */
static int
ac_probe_reg(ac97_t *ac, uint8_t reg)
{
	uint16_t	val;
	int		rv = 0;

	/* get the original value */
	val = RD(reg);
	WR(reg, 0xffff);
	if (RD(reg) != 0) {
		rv = 1;
	}
	/* restore the original value */
	WR(reg, val);
	return (rv);
}

/*
 * Does this device have bass/treble controls?
 */
static int
ac_probe_tone(ac97_t *ac)
{
	/* Bass/Treble contols  present */
	if (ac->caps & RR_BASS_TREBLE)
		return (1);
	else
		return (0);
}

/*
 * If there is a loudness switch?
 */
static int
ac_probe_loud(ac97_t *ac)
{
	/* loudness contol present */
	if (ac->caps & RR_LOUDNESS_SUPPORT)
		return (1);
	else
		return (0);
}

/*
 * Does this device have a mono-mic input volume control?
 */
static int
ac_probe_mmic(ac97_t *ac)
{
	/* mono mic present */
	if (ac->caps & RR_DEDICATED_MIC)
		return (1);
	else
		return (0);
}

/*
 * Does this device have a simulated stereo switch?
 */
static int
ac_probe_stsim(ac97_t *ac)
{
	/* simulated stereocontol present */
	if (ac->caps & RR_PSEUDO_STEREO)
		return (1);
	else
		return (0);
}

/*
 * Does this device have a PC beeper input volume control?
 */
static int
ac_probe_pcbeep(ac97_t *ac)
{
	return (ac_probe_reg(ac, AC97_PC_BEEP_REGISTER));
}

/*
 * Does this device have AUX output port volume control?
 */
static int
ac_probe_rear(ac97_t *ac)
{
	if (ac->flags & AC97_FLAG_AUX_4CH)
		return (1);
	else
		return (0);

}

/*
 * Does this device have a mic?
 */
static int
ac_probe_mic(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_MIC)) &&
	    (ac_probe_reg(ac, AC97_MIC_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_MIC);
		return (1);
	}
	return (0);
}

/*
 * If this device has an AUX output port is it used for headphones?
 */
static int
ac_probe_headphone(ac97_t *ac)
{
	/* headphone control present */
	if ((ac->flags & AC97_FLAG_AUX_HP) &&
	    !(ac->flags & AC97_FLAG_NO_HEADPHONE)) {
		return (1);
	}
	return (0);
}

/*
 * Does this device have AUX output port volume control?
 */
static int
ac_probe_auxout(ac97_t *ac)
{
	/* ALT PCM control present */
	if ((ac->flags & AC97_FLAG_AUX_LVL) &&
	    !(ac->flags & AC97_FLAG_NO_AUXOUT)) {
		return (1);
	}
	return (0);
}

/*
 * Does this device have an AUX input port volume control?
 */
static int
ac_probe_auxin(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_AUXIN)) &&
	    (ac_probe_reg(ac, AC97_AUX_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_AUXIN);
		return (1);
	}
	return (0);
}

/*
 * Does this device have a phone input port with a volume control?
 */
static int
ac_probe_phone(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_PHONE)) &&
	    (ac_probe_reg(ac, AC97_PHONE_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_PHONE);
		return (1);
	}
	return (0);
}

/*
 * Does this device have a mono output port with volume control?
 */
static int
ac_probe_mono(ac97_t *ac)
{
	if (!(ac->flags & AC97_FLAG_SPEAKER_OK)) {
		return (0);
	}
	if (ac_probe_reg(ac, AC97_MONO_MASTER_VOLUME_REGISTER)) {
		return (1);
	}
	return (0);
}

/*
 * Does this device have a line input port with volume control?
 */
static int
ac_probe_linein(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_LINEIN)) &&
	    (ac_probe_reg(ac, AC97_LINE_IN_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_LINEIN);
		return (1);
	}
	return (0);
}

/*
 * Does this device have a cdrom input port with volume control?
 */
static int
ac_probe_cdrom(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_CDROM)) &&
	    (ac_probe_reg(ac, AC97_CD_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_CD);
		return (1);
	}
	return (0);
}

/*
 * Does this device have a video input port with volume control?
 */
static int
ac_probe_video(ac97_t *ac)
{
	if ((!(ac->flags & AC97_FLAG_NO_VIDEO)) &&
	    (ac_probe_reg(ac, AC97_VIDEO_VOLUME_REGISTER))) {
		ac->inputs |= (1U << INPUT_VIDEO);
		return (1);
	}
	return (0);
}

/*
 * Does this device have a 3D sound enhancement?
 */
static int
ac_probe_3d(ac97_t *ac)
{
	/* 3D control present */
	if (ac->caps & RR_3D_STEREO_ENHANCE_MASK)
		return (1);
	else
		return (0);
}

static int
ac_probe_3d_impl(ac97_t *ac, uint16_t mask)
{
	int	rv = 0;
	uint16_t val;

	if ((ac->caps & RR_3D_STEREO_ENHANCE_MASK) == 0)
		return (0);

	/* get the original value */
	val = RD(AC97_THREE_D_CONTROL_REGISTER);
	WR(AC97_THREE_D_CONTROL_REGISTER, mask);
	if ((RD(AC97_THREE_D_CONTROL_REGISTER) & mask) != 0) {
		rv = 1;
	}
	/* restore the original value */
	WR(AC97_THREE_D_CONTROL_REGISTER, val);
	return (rv);
}

static int
ac_probe_3d_depth(ac97_t *ac)
{
	return (ac_probe_3d_impl(ac, TDCR_DEPTH_MASK));
}

static int
ac_probe_3d_center(ac97_t *ac)
{
	return (ac_probe_3d_impl(ac, TDCR_CENTER_MASK));
}

/*
 * Does this device have a center output port with volume control?
 */
static int
ac_probe_center(ac97_t *ac)
{
	uint16_t val;

	val = RD(AC97_EXTENDED_AUDIO_REGISTER);

	/* center volume present */
	if (val & EAR_CDAC)
		return (1);
	else
		return (0);
}

/*
 * Does this device have a LFE (Sub-woofer) output port with
 * a volume control?
 */
static int
ac_probe_lfe(ac97_t *ac)
{
	uint16_t val;

	val = RD(AC97_EXTENDED_AUDIO_REGISTER);

	/* We have LFE control */
	if (val & EAR_LDAC)
		return (1);
	else
		return (0);

}

/*
 * Are we a multichannel codec?
 */
static int
ac_probe_front(ac97_t *ac)
{
	uint16_t val;

	val = RD(AC97_EXTENDED_AUDIO_REGISTER);

	/* Are any of the Surround, Center, or LFE dacs present? */
	if (val & (EAR_SDAC | EAR_CDAC | EAR_LDAC))
		return (1);
	else
		return (0);
}

static int
ac_probe_lineout(ac97_t *ac)
{
	/* if not multichannel, then use "lineout" instead of "front" label */
	return (!ac_probe_front(ac));
}

static const char *ac_mics[] = {
	AUDIO_PORT_MIC1,
	AUDIO_PORT_MIC2,
	NULL,
};

static const char *ac_monos[] = {
	AUDIO_PORT_MONOMIX,
	AUDIO_PORT_MIC,
	NULL
};

/*
 * This calls the Hardware drivers access write routine
 * to write to a device register.
 */
void
ac_wr(ac97_t *ac, uint8_t reg, uint16_t val)
{
	if ((reg < LAST_SHADOW_REG) && (reg > 0)) {
		SHADOW(ac, reg) = val;
	}

	/*
	 * Don't touch hardware _unless_ if we are suspended, unless we
	 * are in the process of resuming.
	 */
	if ((!ac->suspended) || (ac->resumer == ddi_get_kt_did())) {
		ac->wr(ac->private, reg, val);
	}
}

/*
 * This obtains the shadowed value of a register.  If the register is
 * out of range, zero is returned.
 *
 * To read a hardware register, use the RD() macro above.
 */
uint16_t
ac_rd(ac97_t *ac, uint8_t reg)
{
	if ((reg < LAST_SHADOW_REG) && (reg > 0)) {
		return (SHADOW(ac, reg));
	}
	if ((!ac->suspended) || (ac->resumer == ddi_get_kt_did())) {
		return (ac->rd(ac->private, reg));
	}
	return (0);
}

/*
 * This calls the hardware driver's access read/write routine
 * to set bits in a device register.
 */
void
ac_set(ac97_t *ac, uint8_t reg, uint16_t val)
{
	ac_wr(ac, reg, ac->rd(ac->private, reg) | val);
}

/*
 * This calls the hardware driver's access read/write routine
 * to clear bits in a device register.
 */
void
ac_clr(ac97_t *ac, uint8_t reg, uint16_t val)
{
	ac_wr(ac, reg, ac->rd(ac->private, reg) & ~val);
}

/*
 * Look for a control attached to this device based
 * on its control number.
 *
 * If this control number is found the per controls state
 * structure is returned.
 */
ac97_ctrl_t *
ac97_control_find(ac97_t *ac, const char *name)
{
	ac97_ctrl_t *ctrl;
	list_t *l = &ac->ctrls;

	/* Validate that ctrlnum is real and usable */
	for (ctrl = list_head(l); ctrl; ctrl = list_next(l, ctrl)) {
		if (strcmp(ctrl->actrl_name, name) == 0) {
			return (ctrl);
		}
	}
	return (NULL);
}

/*
 * This will update all the codec registers from the shadow table.
 */
static void
ac_restore(ac97_t *ac)
{
	/*
	 * If we are restoring previous settings, just reload from the
	 * shadowed settings.
	 */
	for (int i = 2; i < LAST_SHADOW_REG; i += sizeof (uint16_t)) {
		ac->wr(ac->private, i, SHADOW(ac, i));
	}

	/*
	 * Then go and do the controls.  This is important because some of
	 * the controls might use registers that aren't shadowed.  Doing it
	 * a second time also may help guarantee that it all works.
	 */
	for (ac97_ctrl_t *ctrl = list_head(&ac->ctrls); ctrl;
	    ctrl = list_next(&ac->ctrls, ctrl)) {
		ctrl->actrl_write_fn(ctrl, ctrl->actrl_value);
	}
}

/*
 * This will update all the hardware controls to the initial values at
 * start of day.
 */
static void
ac_init_values(ac97_t *ac)
{
	ac97_ctrl_t	*ctrl;

	mutex_enter(&ac->ac_lock);
	for (ctrl = list_head(&ac->ctrls); ctrl;
	    ctrl = list_next(&ac->ctrls, ctrl)) {
		ctrl->actrl_value = ctrl->actrl_initval;
		ctrl->actrl_write_fn(ctrl, ctrl->actrl_initval);
	}
	mutex_exit(&ac->ac_lock);
}

/*
 * Select the input source for recording. This is the set routine
 * for the control AUDIO_CONTROL_INPUTS.
 */
static void
ac_insrc_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac97_t		*ac = ctrl->actrl_ac97;
	uint16_t	set_val;

	set_val = ddi_ffs(value & 0xffff);
	if ((set_val > 0) && (set_val <= 8)) {
		set_val--;
		ac_wr(ac, AC97_RECORD_SELECT_CTRL_REGISTER,
		    set_val | (set_val << 8));
	}
}

static void
ac_gpr_toggle(ac97_ctrl_t *ctrl, int bit, uint64_t onoff)
{
	ac97_t			*ac = ctrl->actrl_ac97;
	uint16_t		v;

	v = SHADOW(ac, AC97_GENERAL_PURPOSE_REGISTER);
	if (onoff) {
		v |= bit;
	} else {
		v &= ~bit;
	}
	ac_wr(ac, AC97_GENERAL_PURPOSE_REGISTER, v);
}

static void
ac_3donoff_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_3D_STEREO_ENHANCE, value);
}

static void
ac_loudness_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_BASS_BOOST, value);
}

static void
ac_loopback_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_LPBK, value);
}

/*
 * This will set simulated stereo control to on or off.
 */
static void
ac_stsim_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_ST, value);
}

/*
 * This will set mic select control to mic1=0 or mic2=1.
 */
static void
ac_selmic_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_MS_MIC2, value & 2);
}

/*
 * This will set mono source select control to mix=0 or mic=1.
 */
static void
ac_monosrc_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_gpr_toggle(ctrl, GPR_MONO_MIC_IN, value & 2);
}

static void
ac_stereo_set(ac97_ctrl_t *ctrl, uint64_t value, uint8_t reg)
{
	ac97_t			*ac = ctrl->actrl_ac97;
	uint8_t			left, right;
	uint16_t		mute;

	left = (value >> 8) & 0xff;
	right = value & 0xff;
	mute = value ? 0 : ctrl->actrl_muteable;

	ac_wr(ac, reg, ac_val_scale(left, right, ctrl->actrl_bits) | mute);
}

static void
ac_mono_set(ac97_ctrl_t *ctrl, uint64_t value, uint8_t reg, int shift)
{
	ac97_t			*ac = ctrl->actrl_ac97;
	uint8_t			val;
	uint16_t		mute, v;
	uint16_t		mask;

	val = value & 0xff;
	mute = val ? 0 : ctrl->actrl_muteable;

	mask = ctrl->actrl_muteable |
	    (((1 << ABS(ctrl->actrl_bits)) - 1) << shift);

	v = SHADOW(ac, reg);
	v &= ~mask;	/* clear all of our bits, preserve others */

	/* now set the mute bit, and volume bits */
	v |= mute;
	v |= (ac_mono_scale(val, ctrl->actrl_bits) << shift);

	ac_wr(ac, reg, v);
}

static void
ac97_master_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	value = value | (value << 8);
	ac_stereo_set(ctrl, value, AC97_PCM_OUT_VOLUME_REGISTER);
}

static void
ac97_lineout_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_MASTER_VOLUME_REGISTER);
}

static void
ac97_surround_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_EXTENDED_LRS_VOLUME_REGISTER);
}

static void
ac97_aux1out_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_HEADPHONE_VOLUME_REGISTER);
}

static void
ac97_headphone_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_HEADPHONE_VOLUME_REGISTER);
}

static void
ac_cd_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_CD_VOLUME_REGISTER);
}

static void
ac_video_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_VIDEO_VOLUME_REGISTER);
}

static void
ac_auxin_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_AUX_VOLUME_REGISTER);
}

static void
ac_linein_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_LINE_IN_VOLUME_REGISTER);
}

/*
 * This will set mono mic gain control.
 */
static void
ac_monomic_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_RECORD_GAIN_MIC_REGISTER, 0);
}

static void
ac_phone_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_PHONE_VOLUME_REGISTER, 0);
}

static void
ac_mic_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_MIC_VOLUME_REGISTER, 0);
}

static void
ac_speaker_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_MONO_MASTER_VOLUME_REGISTER, 0);
}

static void
ac_pcbeep_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_PC_BEEP_REGISTER, 1);
}

static void
ac_recgain_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_stereo_set(ctrl, value, AC97_RECORD_GAIN_REGISTER);
}

static void
ac_center_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_EXTENDED_C_LFE_VOLUME_REGISTER, 0);
}

static void
ac_lfe_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_EXTENDED_C_LFE_VOLUME_REGISTER, 8);
}

static void
ac_bass_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_MASTER_TONE_CONTROL_REGISTER, 8);
}

static void
ac_treble_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac_mono_set(ctrl, value, AC97_MASTER_TONE_CONTROL_REGISTER, 0);
}

static void
ac_3ddepth_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	/*
	 * XXX: This is all wrong... 3D depth/center cannot necessarily
	 * be scaled, because the technology in use may vary.  We
	 * need more information about each of the options available
	 * to do the right thing.
	 */
	ac_mono_set(ctrl, value, AC97_THREE_D_CONTROL_REGISTER, 0);
}

static void
ac_3dcent_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	/*
	 * XXX: This is all wrong... 3D depth/center cannot necessarily
	 * be scaled, because the technology in use may vary.  We
	 * need more information about each of the options available
	 * to do the right thing.
	 */
	ac_mono_set(ctrl, value, AC97_THREE_D_CONTROL_REGISTER, 8);
}

static void
ac97_micboost_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac97_t		*ac = ctrl->actrl_ac97;
	uint16_t	v;

	v = SHADOW(ac, AC97_MIC_VOLUME_REGISTER);
	if (value) {
		v |= MICVR_20dB_BOOST;
	} else {
		v &= ~MICVR_20dB_BOOST;
	}
	ac_wr(ac, AC97_MIC_VOLUME_REGISTER, v);
}

/*
 * This will return the stored value for any control that has been set.
 * Note this does not return the actual hardware value from a port. But
 * instead returns the cached value from the last write to the hardware
 * port.
 *
 * arg            - This control structure for this control.
 * value          - This is a pointer to the location to put the
 *                  controls value.
 *
 * On success zero is returned.
 */
int
ac97_control_get(ac97_ctrl_t *ctrl, uint64_t *value)
{
	ac97_t		*ac = ctrl->actrl_ac97;

	mutex_enter(&ac->ac_lock);
	*value = ctrl->actrl_value;
	mutex_exit(&ac->ac_lock);

	return (0);
}

int
ac97_control_set(ac97_ctrl_t *ctrl, uint64_t value)
{
	ac97_t			*ac = ctrl->actrl_ac97;
	uint8_t			v1, v2;

	/* a bit of quick checking */
	switch (ctrl->actrl_type) {
	case AUDIO_CTRL_TYPE_STEREO:
		v1 = (value >> 8) & 0xff;
		v2 = value & 0xff;
		if ((v1 < ctrl->actrl_minval) || (v1 > ctrl->actrl_maxval) ||
		    (v2 < ctrl->actrl_minval) || (v2 > ctrl->actrl_maxval) ||
		    (value > 0xffff)) {
			return (EINVAL);
		}
		break;

	case AUDIO_CTRL_TYPE_ENUM:
		if ((value & ~ctrl->actrl_minval) !=
		    (ctrl->actrl_maxval & ~ctrl->actrl_minval)) {
			return (EINVAL);
		}
		break;

	case AUDIO_CTRL_TYPE_MONO:
	case AUDIO_CTRL_TYPE_BOOLEAN:
		if ((value < ctrl->actrl_minval) ||
		    (value > ctrl->actrl_maxval)) {
			return (EINVAL);
		}
		break;
	}

	mutex_enter(&ac->ac_lock);
	ctrl->actrl_value = value;
	ctrl->actrl_write_fn(ctrl, value);
	mutex_exit(&ac->ac_lock);

	return (0);
}

static int
ac_get_value(void *arg, uint64_t *value)
{
	return (ac97_control_get(arg, value));
}

static int
ac_set_value(void *arg, uint64_t value)
{
	return (ac97_control_set(arg, value));
}

/*
 * This simply sets a flag to block calls to the underlying
 * hardware driver to get or set hardware controls. This is usually
 * called just before a power down of devices. Once this gets called any
 * calls to set controls will not touch the real hardware. But
 * since all control updates are always saved in soft registers it
 * is a simple mater to update the hardware with the latest values
 * on resume which also unblocks calls to the hardware controls.
 */
void
ac97_suspend(ac97_t *ac)
{
	mutex_enter(&ac->ac_lock);

	/* This will prevent any new operations from starting! */
	ac->suspended = B_TRUE;
	ac->resumer = 0;

	/* XXX - should we powerdown codec's here?? */
	mutex_exit(&ac->ac_lock);
}

/*
 * Reset the analog codec hardware
 *
 * Reset all analog AC97 hardware, input ADC's, output DAC's and MIXER.
 * Wait a resonable amount of time for hardware to become ready.
 */
static void
ac_analog_reset(ac97_t *ac)
{
	uint16_t	tmp;
	int		wait = 1000; /* delay for up to 1s */

	/* Clear stale data and resync register accesses */
	tmp = RD(AC97_POWERDOWN_CTRL_STAT_REGISTER);

	/* reset the codec */
	WR(AC97_RESET_REGISTER, 0);
	tmp = RD(AC97_RESET_REGISTER);

	/* power up */
	WR(AC97_POWERDOWN_CTRL_STAT_REGISTER, 0);

	/* Wait for ADC/DAC/MIXER to become ready */
	while (wait--) {
		/* 1 msec delay */
		drv_usecwait(1000);

		/* If all ready - end delay */
		tmp = RD(AC97_POWERDOWN_CTRL_STAT_REGISTER);
		SHADOW(ac, AC97_POWERDOWN_CTRL_STAT_REGISTER) = tmp;
		if ((tmp & PCSR_POWERD_UP) == PCSR_POWERD_UP) {
			return;
		}
	}

	audio_dev_warn(ac->d, "AC'97 analog power up timed out");
}

/*
 * This is the internal hardware reset routine.
 * It has no locking and we must be locked before it is
 * called!
 *
 * This will reset and re-initialize the device.
 * It has two modes of operation that affect how it handles
 * all controls.
 *
 * It re-initializes the device and reloads values with
 * last updated versions.
 */
static void
ac_hw_reset(ac97_t *ac)
{
	/*
	 * Fully Power up the device
	 */
	if (ac->flags & AC97_FLAG_AMPLIFIER) {
		/* power up - external amp powerd up */
		ac_wr(ac, AC97_POWERDOWN_CTRL_STAT_REGISTER, 0);
	} else {
		/* power up - external amp powered down */
		ac_wr(ac, AC97_POWERDOWN_CTRL_STAT_REGISTER, PCSR_EAPD);
	}

	ac_wr(ac, AC97_GENERAL_PURPOSE_REGISTER, 0);

	switch (ac->vid) {
	case AC97_CODEC_STAC9708:
#if 0
		/* non-inverted phase */
		/* ac_rd(ac, AC97_VENDOR_REGISTER_11) & ~0x8); */
#endif
		WR(AC97_VENDOR_REGISTER_11, 8);
		break;

	case AC97_CODEC_EM28028:
		ac_wr(ac, AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER,
		    (ac_rd(ac, AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER) &
		    ~3800) | 0xE0);
		break;

	case AC97_CODEC_AD1886:
		/* jack sense */
		WR(AC97_VENDOR_REGISTER_13,
		    (RD(AC97_VENDOR_REGISTER_13) & ~0xEF) | 0x10);
		break;

	case AC97_CODEC_AD1888:
		WR(AC97_VENDOR_REGISTER_15, 0xC420);
#if 0
		/* GED: This looks fishy to me, so I'm nuking it for now */
		/* headphone/aux volume (?) */
		ac_wr(ac, AC97_HEADPHONE_VOLUME_REGISTER,  0x0808);
#endif
		break;

	case AC97_CODEC_AD1980:
#if 0
		/* set jacksense to mute line if headphone is plugged */
		WR(AC97_VENDOR_REGISTER_13,
		    (RD(AC97_VENDOR_REGISTER_13) & ~0xe00) | 0x400);
#endif
		WR(AC97_VENDOR_REGISTER_15, 0xC420);
		break;

	case AC97_CODEC_AD1985:
		WR(AC97_VENDOR_REGISTER_15, 0xC420);
		break;

	case AC97_CODEC_WM9704:
		/* enable I2S */
		WR(AC97_VENDOR_REGISTER_01, RD(AC97_VENDOR_REGISTER_01) | 0x80);
		break;

	case AC97_CODEC_VT1612A:
	case AC97_CODEC_VT1617A:
	case AC97_CODEC_VT1616:
		/* Turn off Center, Surround, and LFE DACs */
		ac_clr(ac, AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER,
		    EASCR_PRI | EASCR_PRJ | EASCR_PRK);
		WR(AC97_VENDOR_REGISTER_01, 0x0230);
		break;

	case AC97_CODEC_YMF753:
		/* set TX8 + 3AWE */
		WR(AC97_VENDOR_REGISTER_07, RD(AC97_VENDOR_REGISTER_07) | 0x9);
		break;

	default:
		break;
	}

	/* call codec specific reset hook */
	if (ac->codec_reset != NULL) {
		ac->codec_reset(ac);
	}

	/* Turn off variable sampling rate support */
	ac_clr(ac, AC97_EXTENDED_AUDIO_STAT_CTRL_REGISTER, EASCR_VRA);
}

/*
 * This will reset and re-initialize the device.
 * It has two modes of operation that affect how it handles
 * all controls.
 *
 * It re-initializes the device and then can either reset
 * all controls back to their initial values or it can
 * re-load all controls with their last updated values.
 *
 * initval         - If this is none zero then all controls will
 *                   be restored to their initial values.
 */
void
ac97_reset(ac97_t *ac)
{
	/* If we are about to suspend so no point in going on */
	mutex_enter(&ac->ac_lock);
	if (ac->suspended) {
		mutex_exit(&ac->ac_lock);
		return;
	}
	ac_analog_reset(ac);
	ac_hw_reset(ac);
	ac_restore(ac);

	mutex_exit(&ac->ac_lock);
}

/*
 * Given the need to resume the hardware this reloads the base hardware
 * and then takes the stored values for each control and sends them
 * to the hardware again.
 */
void
ac97_resume(ac97_t *ac)
{

	/*
	 * This should only be called when already suspended.
	 * this takes us out of suspend state after it brings the
	 * controls back to life.
	 */
	ASSERT(ac->suspended);
	mutex_enter(&ac->ac_lock);
	ac->resumer = ddi_get_kt_did();

	/* We simply call reset since the operation is the same */
	ac_analog_reset(ac);
	ac_hw_reset(ac);
	ac_restore(ac);

	ac->resumer = 0;
	ac->suspended = B_FALSE;
	mutex_exit(&ac->ac_lock);
}

/*
 * Return the number of channels supported by this codec.
 */
int
ac97_num_channels(ac97_t *ac)
{
	return (ac->nchan);
}

/*
 * Register a control -- if it fails, it will generate a message to
 * syslog, but the driver muddles on.  (Failure to register a control
 * should never occur, but is generally benign if it happens.)
 */
void
ac97_control_register(ac97_ctrl_t *ctrl)
{
	ac97_t	*ac = ctrl->actrl_ac97;
	ASSERT(ac->d != NULL);

	ctrl->actrl_suppress = B_FALSE;

	/* Register control with framework */
	ctrl->actrl_ctrl = audio_dev_add_control(ac->d, &ctrl->actrl_desc,
	    ac_get_value, ac_set_value, ctrl);
	if (ctrl->actrl_ctrl == NULL) {
		audio_dev_warn(ac->d, "AC97 %s alloc failed",
		    ctrl->actrl_name);
	}
}

void
ac97_control_unregister(ac97_ctrl_t *ctrl)
{
	ctrl->actrl_suppress = B_TRUE;

	if (ctrl->actrl_ctrl != NULL) {
		audio_dev_del_control(ctrl->actrl_ctrl);
		ctrl->actrl_ctrl = NULL;
	}
}

const char *
ac97_control_name(ac97_ctrl_t *ctrl)
{
	return (ctrl->actrl_name);
}

const audio_ctrl_desc_t *
ac97_control_desc(ac97_ctrl_t *ctrl)
{
	return (&ctrl->actrl_desc);
}

void
ac97_register_controls(ac97_t *ac)
{
	ac97_ctrl_t	*ctrl;

	for (ctrl = list_head(&ac->ctrls); ctrl;
	    ctrl = list_next(&ac->ctrls, ctrl)) {
		if (ctrl->actrl_suppress)
			continue;
		ac97_control_register(ctrl);
	}
}

void
ac97_walk_controls(ac97_t *ac, ac97_ctrl_walk_t walker, void *arg)
{
	ac97_ctrl_t	*ctrl;

	for (ctrl = list_head(&ac->ctrls); ctrl;
	    ctrl = list_next(&ac->ctrls, ctrl)) {
		if (!(*walker)(ctrl, arg)) {
			break;
		}
	}
}

void
ac_add_control(ac97_t *ac, ac97_ctrl_probe_t *cpt)
{
	ac97_ctrl_t		*ctrl;
	boolean_t		is_new;

	ASSERT(ac);
	ASSERT(ac->d);

	ctrl = ac97_control_find(ac, cpt->cp_name);
	if (ctrl != NULL) {
		is_new = B_FALSE;
	} else {
		ctrl = kmem_zalloc(sizeof (ac97_ctrl_t), KM_SLEEP);
		is_new = B_TRUE;
	}
	ctrl->actrl_ac97 = ac;
	ctrl->actrl_minval = cpt->cp_minval;
	ctrl->actrl_maxval = cpt->cp_maxval;
	ctrl->actrl_type = cpt->cp_type;
	ctrl->actrl_name = cpt->cp_name;
	ctrl->actrl_flags = cpt->cp_flags;
	if (cpt->cp_enum) {
		for (int e = 0; e < 64; e++) {
			if (cpt->cp_enum[e] == NULL)
				break;
			ctrl->actrl_enum[e] = cpt->cp_enum[e];
		}
	}

	/*
	 * Warning for extended controls this field gets changed
	 * by audio_dev_add_control() to be a unique value.
	 */
	ctrl->actrl_initval = cpt->cp_initval;
	ctrl->actrl_muteable = cpt->cp_muteable;
	ctrl->actrl_write_fn = cpt->cp_write_fn;
	ctrl->actrl_bits = cpt->cp_bits;

	/*
	 * Not that it can not be referenced until it is in the
	 * list. So again by adding to the list last we avoid the need
	 * for locks.
	 */
	if (is_new)
		list_insert_tail(&ac->ctrls, ctrl);
}

/*
 * De-Register and free up a control
 */
void
ac97_control_remove(ac97_ctrl_t *ctrl)
{
	ac97_t	*ac = ctrl->actrl_ac97;

	list_remove(&ac->ctrls, ctrl);

	if (ctrl->actrl_ctrl != NULL)
		audio_dev_del_control(ctrl->actrl_ctrl);
	kmem_free(ctrl, sizeof (ac97_ctrl_t));
}

/*
 * This is the master list of all controls known and handled by
 * the AC97 framework. This is the list used to probe, allocate
 * and configure controls. If a control is not in this list it
 * will not be handled. If a control is in this list but does not
 * have a probe routine then it will always be included. If a
 * control in list has a probe routine then it must return true
 * for that control to be included.
 */

#define	MONCTL	(AC97_FLAGS | AUDIO_CTRL_FLAG_MONITOR)
#define	PLAYCTL	(AC97_FLAGS | AUDIO_CTRL_FLAG_PLAY)
#define	RECCTL	(AC97_FLAGS | AUDIO_CTRL_FLAG_REC)
#define	T3DCTL	(AC97_FLAGS | AUDIO_CTRL_FLAG_3D)
#define	TONECTL	(AC97_FLAGS | AUDIO_CTRL_FLAG_TONE)
#define	MAINVOL	(PLAYCTL | AUDIO_CTRL_FLAG_MAINVOL)
#define	PCMVOL	(PLAYCTL | AUDIO_CTRL_FLAG_PCMVOL)
#define	RECVOL	(RECCTL | AUDIO_CTRL_FLAG_RECVOL)
#define	MONVOL	(MONCTL | AUDIO_CTRL_FLAG_MONVOL)

ac97_ctrl_probe_t	ctrl_probe_tbl[] = {

	/* Master PCM Volume */
	{AUDIO_CTRL_ID_VOLUME, INIT_VAL_MAIN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	PCMVOL, PCMOVR_MUTE, ac97_master_set, NULL, 5},

	/* LINE out volume */
	{AUDIO_CTRL_ID_LINEOUT, INIT_VAL_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MAINVOL, 0x8080, ac97_lineout_set, ac_probe_lineout, 6},

	/* Front volume */
	{AUDIO_CTRL_ID_FRONT, INIT_VAL_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MAINVOL, 0x8080, ac97_lineout_set, ac_probe_front, 6},

	/* 4CH out volume (has one of three possible uses, first use) */
	{AUDIO_CTRL_ID_SURROUND, INIT_VAL_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MAINVOL, 0x8080, ac97_surround_set, ac_probe_rear, 6},

	/* ALT out volume (has one of three possible uses, second use) */
	{AUDIO_CTRL_ID_HEADPHONE, INIT_VAL_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MAINVOL, 0x8080, ac97_headphone_set, ac_probe_headphone, 6},

	/* ALT out volume (has one of three possible uses, third use) */
	{AUDIO_CTRL_ID_AUX1OUT, INIT_VAL_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MAINVOL, 0x8080, ac97_aux1out_set, ac_probe_auxout, 6},

	/* center out volume */
	{AUDIO_CTRL_ID_CENTER, INIT_VAL_MN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	MAINVOL, EXLFEVR_CENTER_MUTE, ac_center_set, ac_probe_center, 6},

	/* LFE out volume (sub-woofer) */
	{AUDIO_CTRL_ID_LFE, INIT_VAL_MN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	MAINVOL, EXLFEVR_LFE_MUTE, ac_lfe_set, ac_probe_lfe, 6},

	/* MONO out volume */
	{AUDIO_CTRL_ID_SPEAKER, INIT_VAL_MN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	MAINVOL, MMVR_MUTE, ac_speaker_set, ac_probe_mono, 6},

	/* Record in GAIN */
	{AUDIO_CTRL_ID_RECGAIN, INIT_IGAIN_ST, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	RECVOL, RGR_MUTE, ac_recgain_set, NULL, -4},

	/* MIC in volume */
	{AUDIO_CTRL_ID_MIC, 0, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MONVOL, MICVR_MUTE, ac_mic_set, ac_probe_mic, 5},

	/* LINE in volume */
	{AUDIO_CTRL_ID_LINEIN, 0, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MONVOL, LIVR_MUTE, ac_linein_set, ac_probe_linein, 5},

	/* CD in volume */
	{AUDIO_CTRL_ID_CD, 0, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MONVOL, CDVR_MUTE, ac_cd_set, ac_probe_cdrom, 5},

	/* VIDEO in volume */
	{AUDIO_CTRL_ID_VIDEO, 0, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MONVOL, VIDVR_MUTE, ac_video_set, ac_probe_video, 5},

	/* AUX in volume */
	{AUDIO_CTRL_ID_AUX1IN, 0, 0, 100, AUDIO_CTRL_TYPE_STEREO,
	MONVOL, AUXVR_MUTE, ac_auxin_set, ac_probe_auxin, 5},

	/* PHONE in volume */
	{AUDIO_CTRL_ID_PHONE, 0, 0, 100, AUDIO_CTRL_TYPE_MONO,
	MONVOL, PVR_MUTE, ac_phone_set, ac_probe_phone, 5},

	/* PC BEEPER in volume (motherboard speaker pins) */
	{AUDIO_CTRL_ID_BEEP, INIT_VAL_MN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	AC97_RW, PCBR_MUTE, ac_pcbeep_set, ac_probe_pcbeep, 4},

	/* BASS out level (note, zero is hardware bypass) */
	{AUDIO_CTRL_ID_BASS, 0, 0, 100, AUDIO_CTRL_TYPE_MONO,
	TONECTL, 0, ac_bass_set, ac_probe_tone, 4},

	/* TREBLE out level (note, zero is hardware bypass) */
	{AUDIO_CTRL_ID_TREBLE, 0, 0, 100, AUDIO_CTRL_TYPE_MONO,
	TONECTL, 0, ac_treble_set, ac_probe_tone, 4},

	/* Loudness on/off switch */
	{AUDIO_CTRL_ID_LOUDNESS, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
	TONECTL, 0, ac_loudness_set, ac_probe_loud, 0},

	/* 3D depth out level */
	{AUDIO_CTRL_ID_3DDEPTH, 0, 0, 100, AUDIO_CTRL_TYPE_MONO,
	T3DCTL, 0, ac_3ddepth_set, ac_probe_3d_depth, 4},

	/* 3D center out level */
	{AUDIO_CTRL_ID_3DCENT, 0, 0, 100, AUDIO_CTRL_TYPE_MONO,
	T3DCTL, 0, ac_3dcent_set, ac_probe_3d_center, 4},

	/* 3D enhance on/off switch */
	{AUDIO_CTRL_ID_3DENHANCE, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
	T3DCTL, 0, ac_3donoff_set, ac_probe_3d, 0},

	/* MIC BOOST switch */
	{AUDIO_CTRL_ID_MICBOOST, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
	RECCTL, 0, ac97_micboost_set, ac_probe_mic, 0},

	/* Loopback on/off switch */
	{AUDIO_CTRL_ID_LOOPBACK, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
	AC97_RW, 0, ac_loopback_set, NULL, 0},

	/*
	 * The following selectors *must* come after the others, as they rely
	 * on the probe results of other controls.
	 */
	/* record src select  (only one port at a time) */
	{AUDIO_CTRL_ID_RECSRC, (1U << INPUT_MIC), 0, 0, AUDIO_CTRL_TYPE_ENUM,
	RECCTL, 0, ac_insrc_set, NULL, 0, ac_insrcs},

	/* Start of non-standard private controls */

	/* Simulated stereo on/off switch */
	{AUDIO_CTRL_ID_STEREOSIM, 0, 0, 1, AUDIO_CTRL_TYPE_BOOLEAN,
	AC97_RW, 0, ac_stsim_set, ac_probe_stsim, 0},

	/* mono MIC GAIN */
	{AUDIO_CTRL_ID_MICGAIN, INIT_IGAIN_MN, 0, 100, AUDIO_CTRL_TYPE_MONO,
	RECCTL, RGMR_MUTE, ac_monomic_set, ac_probe_mmic, -4},

	/* MIC select switch 0=mic1 1=mic2 */
	{AUDIO_CTRL_ID_MICSRC, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM,
	RECCTL, 0, ac_selmic_set, ac_probe_mic, 0, ac_mics},

	/* MONO out src select 0=mix 1=mic */
	{AUDIO_CTRL_ID_SPKSRC, 1, 3, 3, AUDIO_CTRL_TYPE_ENUM,
	AC97_RW, 0, ac_monosrc_set, ac_probe_mono, 0, ac_monos},

	{NULL}
};

/*
 * Probe all possible controls and register existing
 * ones and set initial values
 *
 * Returns zero on success
 */
static void
ac_probeinit_ctrls(ac97_t *ac, int vol_bits, int enh_bits)
{
	ac97_ctrl_probe_t	*cpt;
	ac97_ctrl_probe_t	my_cpt;

	ASSERT(ac);

	/*
	 * Set some ports which are always present.
	 */
	ac->inputs = (1U << INPUT_STEREOMIX) | (1U << INPUT_MONOMIX);
	for (cpt = &ctrl_probe_tbl[0]; cpt->cp_name != NULL; cpt++) {
		bcopy(cpt, &my_cpt, sizeof (my_cpt));

		if (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_RECSRC) == 0) {
			my_cpt.cp_minval |= ac->inputs;
			my_cpt.cp_maxval |= ac->inputs;
		}

		if (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_MICBOOST) == 0) {
			if (ac->flags & AC97_FLAG_MICBOOST)
				my_cpt.cp_initval = 1;
		}

		if ((strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_FRONT) == 0) ||
		    (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_HEADPHONE) == 0) ||
		    (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_SURROUND) == 0) ||
		    (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_SPEAKER) == 0)) {
			my_cpt.cp_bits = vol_bits;
		}

		if ((strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_3DDEPTH) == 0) ||
		    (strcmp(my_cpt.cp_name, AUDIO_CTRL_ID_3DCENT) == 0)) {
			my_cpt.cp_bits = enh_bits;
		}

		if (!my_cpt.cp_probe || my_cpt.cp_probe(ac)) {
			ac_add_control(ac, &my_cpt);
		}
	}

	if (ac->codec_init != NULL) {
		ac->codec_init(ac);
	}
}

/*
 * Allocate an AC97 instance for use by a hardware driver.
 *
 * returns an allocated and initialize ac97 structure.
 */
ac97_t *
ac97_alloc(dev_info_t *dip, ac97_rd_t rd, ac97_wr_t wr, void *priv)
{
	ac97_t	*ac;

	ac = kmem_zalloc(sizeof (ac97_t), KM_SLEEP);
	ac->dip = dip;
	ac->rd = rd;
	ac->wr = wr;
	ac->private = priv;

	list_create(&ac->ctrls, sizeof (struct ac97_ctrl),
	    offsetof(struct ac97_ctrl, actrl_linkage));

	mutex_init(&ac->ac_lock, NULL, MUTEX_DRIVER, NULL);

#define	PROP_FLAG(prop, flag, def)				    \
	if (ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, \
	    (prop), (def))) {					    \
		ac->flags |= (flag);				    \
	} else {						    \
		ac->flags &= ~(flag);				    \
	}

	/*
	 * Engage the external amplifier by default, suppress with
	 * a property of the form "ac97-amplifier=0".
	 */
	PROP_FLAG(AC97_PROP_AMPLIFIER, AC97_FLAG_AMPLIFIER, 1);

	/*
	 * We cannot necessarily know if the headphone jack is present
	 * or not.  There's a technique to probe the codec for
	 * headphone support, but many vendors seem to simply hang the
	 * headphone jack on the line out circuit, and have some kind
	 * of jack sense detection to enable or disable it by default.
	 * None of this is visible in the AC'97 registers.
	 *
	 * We cannot do much about it, but what we can do is offer users
	 * a way to suppress the option for a headphone port.  Users and
	 * administrators can then set a flag in the driver.conf to suppress
	 * the option from display.
	 *
	 * It turns out that this problem exists for other signals as
	 * well.
	 */
	PROP_FLAG(AC97_PROP_NO_HEADPHONE, AC97_FLAG_NO_HEADPHONE, 0);
	PROP_FLAG(AC97_PROP_NO_AUXOUT, AC97_FLAG_NO_AUXOUT, 0);
	PROP_FLAG(AC97_PROP_NO_CDROM, AC97_FLAG_NO_CDROM, 0);
	PROP_FLAG(AC97_PROP_NO_AUXIN, AC97_FLAG_NO_AUXIN, 0);
	PROP_FLAG(AC97_PROP_NO_VIDEO, AC97_FLAG_NO_VIDEO, 0);
	PROP_FLAG(AC97_PROP_NO_LINEIN, AC97_FLAG_NO_LINEIN, 0);
	PROP_FLAG(AC97_PROP_NO_MIC, AC97_FLAG_NO_MIC, 0);

	/*
	 * Most SPARC systems use the AC97 monoaural output for the
	 * built-in speaker.  On these systems, we want to expose and
	 * enable the built-in speaker by default.
	 *
	 * On most x86 systems, the mono output is not connected to
	 * anything -- the AC'97 spec makes it pretty clear that the
	 * output was actually intended for use with speaker phones.
	 * So on those systems, we really don't want to activate the
	 * speaker -- we don't even want to expose it's presence
	 * normally.
	 *
	 * However, there could be an exception to the rule here.  To
	 * facilitate this, we allow for the presence of the property
	 * to indicate that the speaker should be exposed.  Whether it
	 * is enabled by default or not depends on the value of the
	 * property.  (Generally on SPARC, we enable by default.  On
	 * other systems we do not.)
	 */
#ifdef	__sparc
	ac->flags |= AC97_FLAG_SPEAKER_OK;
	PROP_FLAG(AC97_PROP_SPEAKER, AC97_FLAG_SPEAKER, 1);
#else
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    AC97_PROP_SPEAKER)) {
		ac->flags |= AC97_FLAG_SPEAKER_OK;
		PROP_FLAG(AC97_PROP_SPEAKER, AC97_FLAG_SPEAKER, 0);
	}
#endif

	/*
	 * Enable microphone boost (20dB normally) by default?
	 */
	PROP_FLAG(AC97_PROP_MICBOOST, AC97_FLAG_MICBOOST, 0);

	return (ac);
}
/*
 * Allocate an AC97 instance for use by a hardware driver.
 *
 * returns an allocated and initialize ac97 structure.
 */
ac97_t *
ac97_allocate(audio_dev_t *adev, dev_info_t *dip, ac97_rd_t rd, ac97_wr_t wr,
    void *priv)
{
	ac97_t *ac;

	ac = ac97_alloc(dip, rd, wr, priv);
	if (ac != NULL) {
		ac->d = adev;
	}
	return (ac);
}

/*
 * Free an AC97 instance.
 */
void
ac97_free(ac97_t *ac)
{
	ac97_ctrl_t *ctrl;

	/* Clear out any controls that are still attached */
	while ((ctrl = list_head(&ac->ctrls)) != NULL) {
		ac97_control_remove(ctrl);
	}

	list_destroy(&ac->ctrls);
	mutex_destroy(&ac->ac_lock);
	kmem_free(ac, sizeof (ac97_t));
}

static struct vendor {
	unsigned	id;
	const char	*name;
} vendors[] = {
	{ AC97_VENDOR_ADS,	"Analog Devices" },
	{ AC97_VENDOR_AKM,	"Asahi Kasei" },
	{ AC97_VENDOR_ALC,	"Realtek" },
	{ AC97_VENDOR_ALG,	"Avance Logic" },
	{ AC97_VENDOR_CMI,	"C-Media" },
	{ AC97_VENDOR_CRY,	"Cirrus Logic" },
	{ AC97_VENDOR_CXT,	"Conexant" },
	{ AC97_VENDOR_ESS,	"ESS Technology" },
	{ AC97_VENDOR_EV,	"Ectiva" },
	{ AC97_VENDOR_ICE,	"ICEnsemble" },
	{ AC97_VENDOR_ST,	"SigmaTel" },
	{ AC97_VENDOR_TRA,	"TriTech", },
	{ AC97_VENDOR_VIA,	"VIA Technologies" },
	{ AC97_VENDOR_WML,	"Wolfson" },
	{ AC97_VENDOR_YMH,	"Yamaha" },
	{ 0, NULL },
};

static struct codec {
	unsigned	id;
	const char	*name;
	int		enh_bits;
	void		(*init)(ac97_t *ac);
	void		(*reset)(ac97_t *ac);
} codecs[] = {
	{ AC97_CODEC_AK4540,	"AK4540" },
	{ AC97_CODEC_STAC9700,	"STAC9700" },
	{ AC97_CODEC_STAC9701,  "STAC9701" },
	{ AC97_CODEC_STAC9701_2,	"STAC9701" },
	{ AC97_CODEC_STAC9704,	"STAC9704" },
	{ AC97_CODEC_STAC9705,	"STAC9705" },
	{ AC97_CODEC_STAC9721,	"STAC9721" },
	{ AC97_CODEC_STAC9708,	"STAC9708", 2 },
	{ AC97_CODEC_STAC9744,	"STAC9744" },
	{ AC97_CODEC_STAC9750,	"STAC9750", 3 },
	{ AC97_CODEC_STAC9752,	"STAC9752", 3 },
	{ AC97_CODEC_STAC9756,	"STAC9756", 3 },
	{ AC97_CODEC_STAC9758,	"STAC9758", 3 },
	{ AC97_CODEC_STAC9766,	"STAC9766", 3 },
	{ AC97_CODEC_TR28028,	"TR28028" },
	{ AC97_CODEC_TR28028_2,	"TR28028" },
	{ AC97_CODEC_TR28023,	"TR28023" },
	{ AC97_CODEC_TR28023_2,	"TR28023" },
	{ AC97_CODEC_EM28028,	"EM28028" },
	{ AC97_CODEC_CX20468,	"CX20468" },
	{ AC97_CODEC_CX20468_2,	"CX20468" },
	{ AC97_CODEC_CX20468_21,	"CX20468-21" },
	{ AC97_CODEC_CS4297,	"CS4297" },
	{ AC97_CODEC_CS4297A,	"CS4297A" },
	{ AC97_CODEC_CS4294,	"CS4294" },
	{ AC97_CODEC_CS4299,	"CS4299" },
	{ AC97_CODEC_CS4202,	"CS4202" },
	{ AC97_CODEC_CS4205,	"CS4205" },
	{ AC97_CODEC_AD1819B,	"AD1819B" },
	{ AC97_CODEC_AD1881,	"AD1881" },
	{ AC97_CODEC_AD1881A,	"AD1881A" },
	{ AC97_CODEC_AD1885,	"AD1885" },
	{ AC97_CODEC_AD1886,	"AD1886" },
	{ AC97_CODEC_AD1887,	"AD1887" },
	{ AC97_CODEC_AD1888,	"AD1888" },
	{ AC97_CODEC_AD1980,	"AD1980" },
	{ AC97_CODEC_AD1981,	"AD1981" },	/* no data sheet */
	{ AC97_CODEC_AD1981A,	"AD1981A", 0, ad1981a_init },
	{ AC97_CODEC_AD1981B,	"AD1981B", 0, ad1981b_init },
	{ AC97_CODEC_AD1985,	"AD1985" },
	{ AC97_CODEC_WM9701A,	"WM9701A" },
	{ AC97_CODEC_WM9703,	"WM9703" },
	{ AC97_CODEC_WM9704,	"WM9704" },
	{ AC97_CODEC_ES1921,	"ES1921" },
	{ AC97_CODEC_ICE1232,	"ICE1232/VT1611A" },
	{ AC97_CODEC_VT1612A,	"VT1612A" },
	{ AC97_CODEC_VT1616,	"VT1616" },
	{ AC97_CODEC_VT1616A,	"VT1616A" },
	{ AC97_CODEC_VT1617A,	"VT1617A" },
	{ AC97_CODEC_VT1618,	"VT1618" },
	{ AC97_CODEC_ALC100,	"ALC100", 2 },
	{ AC97_CODEC_ALC200P,	"ALC200P", 2 },
	{ AC97_CODEC_ALC202,	"ALC202", 2 },
	{ AC97_CODEC_ALC203,	"ALC203", 2 },
	{ AC97_CODEC_ALC250,	"ALC250", 2 },
	{ AC97_CODEC_ALC250_2,	"ALC250", 2 },
	{ AC97_CODEC_ALC650,	"ALC650", 2, alc650_init },
	{ AC97_CODEC_ALC655,	"ALC655", 2, alc650_init },
	{ AC97_CODEC_ALC658,	"ALC658", 2, alc650_init },
	{ AC97_CODEC_ALC850,	"ALC850", 2, alc850_init },
	{ AC97_CODEC_EV1938,	"EV1938" },
	{ AC97_CODEC_CMI9738,	"CMI9738", 0, cmi9738_init },
	{ AC97_CODEC_CMI9739,	"CMI9739", 0, cmi9739_init },
	{ AC97_CODEC_CMI9780,	"CMI9780" },
	{ AC97_CODEC_CMI9761,	"CMI9761A", 0, cmi9761_init },
	{ AC97_CODEC_CMI9761_2,	"CMI9761B", 0, cmi9761_init },
	{ AC97_CODEC_CMI9761_3,	"CMI9761A+", 0, cmi9761_init },
	{ AC97_CODEC_YMF743,	"YMF743" },
	{ AC97_CODEC_YMF753,	"YMF753" },
	{ 0, NULL }
};

void
ac97_probe_controls(ac97_t *ac)
{
	uint32_t		vid1, vid2;
	uint16_t		ear;
	const char		*name = NULL;
	const char		*vendor = NULL;
	int			enh_bits;
	int			vol_bits;
	uint32_t		flags;
	char			nmbuf[128];
	char			buf[128];

	/* This is only valid when used with new style ac97_allocate(). */
	ASSERT(ac->d);

	ac_analog_reset(ac);

	vid1 = RD(AC97_VENDOR_ID1_REGISTER);
	vid2 = RD(AC97_VENDOR_ID2_REGISTER);

	if (vid1 == 0xffff) {
		audio_dev_warn(ac->d, "AC'97 codec unresponsive");
		return;
	}

	ac->vid = (vid1 << 16) | vid2;

	/*
	 * Find out kind of codec we have and set any special case
	 * settings needed.
	 */
	for (int i = 0; codecs[i].id; i++) {
		if (ac->vid == codecs[i].id) {
			name = codecs[i].name;
			enh_bits = codecs[i].enh_bits;
			ac->codec_init = codecs[i].init;
			break;
		}
	}
	for (int i = 0; vendors[i].id; i++) {
		if ((ac->vid & 0xffffff00) == vendors[i].id) {
			vendor = vendors[i].name;
			break;
		}
	}
	if (name == NULL) {
		(void) snprintf(nmbuf, sizeof (nmbuf), "0x%04x%04x",
		    vid1, vid2);
		name = nmbuf;
	}
	if (vendor == NULL) {
		vendor = "Unknown";
	}

	/*
	 * Populate the initial shadow table.
	 */
	for (int i = 0; i < LAST_SHADOW_REG; i += sizeof (uint16_t)) {
		SHADOW(ac, i) = RD(i);
	}

	ac->caps = RD(AC97_RESET_REGISTER);

	enh_bits = 4;
	vol_bits = 6;
	flags = 0;

	/* detect the bit width of the master volume controls */
	WR(AC97_MASTER_VOLUME_REGISTER, 0x20);
	if ((RD(AC97_MASTER_VOLUME_REGISTER) & 0x1f) == 0x1f) {
		vol_bits = 5;
	}

	/*
	 * AC'97 2.3 spec indicates three possible uses for AUX_OUT
	 * (aka LNLVL_OUT aka HP_OUT).  We have to figure out which one
	 * is in use.
	 */
	if (ac->caps & RR_HEADPHONE_SUPPORT) {
		/* it looks like it is probably headphones */
		if (ac_probe_reg(ac, AC97_HEADPHONE_VOLUME_REGISTER)) {
			/* it is implemented */
			ac->flags |= AC97_FLAG_AUX_HP;
		}
	}

	/* Read EAR just once. */
	ear = RD(AC97_EXTENDED_AUDIO_REGISTER);

	/*
	 * If not a headphone, is it 4CH_OUT (surround?)
	 */
	if ((!(ac->flags & AC97_FLAG_AUX_HP)) && (ear & EAR_SDAC)) {
		if (ac_probe_reg(ac, AC97_EXTENDED_LRS_VOLUME_REGISTER)) {
			ac->flags |= AC97_FLAG_AUX_4CH;
		}
	}

	/*
	 * If neither, then maybe its an auxiliary line level output?
	 */
	if (!(ac->flags & (AC97_FLAG_AUX_HP | AC97_FLAG_AUX_4CH))) {
		if (ac_probe_reg(ac, AC97_HEADPHONE_VOLUME_REGISTER)) {
			ac->flags |= AC97_FLAG_AUX_LVL;
		}
	}

	/*
	 * How many channels?
	 */
	ac->nchan = 2;
	if (ear & EAR_SDAC) {
		ac->nchan += 2;
	}
	if (ear & EAR_CDAC) {
		ac->nchan++;
	}
	if (ear & EAR_LDAC) {
		ac->nchan++;
	}

	ac->flags |= flags;
	(void) snprintf(ac->name, sizeof (ac->name), "%s %s", vendor, name);

	(void) snprintf(buf, sizeof (buf), "AC'97 codec: %s", ac->name);
	audio_dev_add_info(ac->d, buf);

	cmn_err(CE_CONT,
	    "?%s#%d: AC'97 codec id %s (%x, %d channels, caps %x)\n",
	    ddi_driver_name(ac->dip), ddi_get_instance(ac->dip),
	    ac->name, ac->vid, ac->nchan, ac->caps);

	/*
	 * Probe and register all known controls with framework
	 */
	ac_probeinit_ctrls(ac, vol_bits, enh_bits);

	ac_hw_reset(ac);
	ac_init_values(ac);
}

/*
 * Init the actual hardware related to a previously allocated instance
 * of an AC97 device.  This is a legacy function and should not be
 * used in new code.
 *
 * Return zero on success.
 */
int
ac97_init(ac97_t *ac, struct audio_dev *d)
{
	/* Make sure we aren't using this with new style ac97_allocate(). */
	ASSERT(ac->d == NULL);

	/* Save audio framework instance structure */
	ac->d = d;

	ac97_probe_controls(ac);
	ac97_register_controls(ac);

	return (0);
}
