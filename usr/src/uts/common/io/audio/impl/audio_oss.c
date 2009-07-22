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

#include <sys/types.h>
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_oss.h>
#include <sys/file.h>
#include <sys/note.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include "audio_client.h"

#define	OSS_FMT		AFMT_S16_LE
#define	OSS_RATE	48000
#define	OSS_CHANNELS	2

typedef struct ossclient ossclient_t;
typedef struct ossdev ossdev_t;

static const struct {
	int	oss;
	int	fmt;
} oss_formats[] = {
	{ AFMT_MU_LAW,		AUDIO_FORMAT_ULAW },
	{ AFMT_A_LAW,		AUDIO_FORMAT_ALAW },
	{ AFMT_U8,		AUDIO_FORMAT_U8 },
	{ AFMT_S8,		AUDIO_FORMAT_S8 },
	{ AFMT_S16_BE,		AUDIO_FORMAT_S16_BE },
	{ AFMT_S16_LE,		AUDIO_FORMAT_S16_LE },
	{ AFMT_U16_BE,		AUDIO_FORMAT_U16_BE },
	{ AFMT_U16_LE,		AUDIO_FORMAT_U16_LE },
	{ AFMT_S24_BE,		AUDIO_FORMAT_S24_BE },
	{ AFMT_S24_LE,		AUDIO_FORMAT_S24_LE },
	{ AFMT_S32_BE,		AUDIO_FORMAT_S32_BE },
	{ AFMT_S32_LE,		AUDIO_FORMAT_S32_LE },
	{ AFMT_S24_PACKED,	AUDIO_FORMAT_S24_PACKED },
	{ AFMT_AC3,		AUDIO_FORMAT_AC3 },
	{ AFMT_QUERY,		AUDIO_FORMAT_NONE }
};

/* common structure shared between both mixer and dsp nodes */
struct ossclient {
	ossdev_t		*o_ossdev;
	audio_client_t		*o_client;
	/* sndstat */
	kmutex_t		o_ss_lock;
	char			*o_ss_buf;
	size_t			o_ss_len;
	size_t			o_ss_sz;
	size_t			o_ss_off;
};

struct ossdev {
	audio_dev_t		*d_dev;

	uint_t			d_modify_cnt;	/* flag apps of ctrl changes */
	uint_t			d_nctrl;	/* num actual controls */
	uint_t			d_nalloc;	/* num allocated controls */
	audio_ctrl_t		**d_ctrls;	/* array of control handles */
	oss_mixext		*d_exts;	/* array of mixer descs */

	int			d_play_grp;
	int			d_rec_grp;
	int			d_mon_grp;
	int			d_misc_grp;

	kmutex_t		d_mx;
	kcondvar_t		d_cv;
};

static int
oss_cnt_controls(audio_ctrl_t *ctrl, void *arg)
{
	int			*pint = (int *)arg;
	int			cnt;
	audio_ctrl_desc_t	desc;

	cnt = *pint;
	cnt++;
	*pint = cnt;

	if (auclnt_control_describe(ctrl, &desc) != 0)
		return (AUDIO_WALK_CONTINUE);

	if (desc.acd_flags & AUDIO_CTRL_FLAG_MULTI) {
		for (uint64_t mask = desc.acd_maxvalue; mask; mask >>= 1) {
			if (mask & 1) {
				cnt++;
			}
		}
		*pint = cnt;
	}

	return (AUDIO_WALK_CONTINUE);
}

/*
 * Add one entry to the OSS user control table to internal control
 * helper table.
 *
 * This is used with auimpl_walk_controls. The table must be pre-
 * allocated before it is walk'd. This includes the root and
 * extended control markers!
 */
static int
oss_add_control(audio_ctrl_t *ctrl, void *arg)
{
	ossdev_t		*odev = arg;
	audio_ctrl_desc_t	desc;
	oss_mixext		*ext;
	int			bit;
	uint64_t		mask;
	const char		*name;
	int			parent;
	int			flags;
	unsigned		scope;

	if (auclnt_control_describe(ctrl, &desc))
		return (AUDIO_WALK_CONTINUE);

	parent = 0;

	/*
	 * Add appropriate group if not already done so.
	 */
	if (desc.acd_flags & AUDIO_CTRL_FLAG_PLAY) {
		if (!odev->d_play_grp) {
			ext = &odev->d_exts[odev->d_nctrl];
			ext->ctrl = odev->d_nctrl;
			ext->control_no = -1;
			ext->type = MIXT_GROUP;
			ext->desc = MIXEXT_SCOPE_OUTPUT;
			ext->timestamp = gethrtime();
			(void) snprintf(ext->id, sizeof (ext->id), "PLAYBACK");
			odev->d_play_grp = odev->d_nctrl;
			odev->d_nctrl++;
		}
		scope = MIXEXT_SCOPE_OUTPUT;
		parent = odev->d_play_grp;
	} else if (desc.acd_flags & AUDIO_CTRL_FLAG_REC) {
		if (!odev->d_rec_grp) {
			ext = &odev->d_exts[odev->d_nctrl];
			ext->ctrl = odev->d_nctrl;
			ext->control_no = -1;
			ext->type = MIXT_GROUP;
			ext->desc = MIXEXT_SCOPE_INPUT;
			ext->timestamp = gethrtime();
			(void) snprintf(ext->id, sizeof (ext->id), "RECORD");
			odev->d_rec_grp = odev->d_nctrl;
			odev->d_nctrl++;
		}
		scope = MIXEXT_SCOPE_INPUT;
		parent = odev->d_rec_grp;
	} else if (desc.acd_flags & AUDIO_CTRL_FLAG_MONITOR) {
		if (!odev->d_mon_grp) {
			ext = &odev->d_exts[odev->d_nctrl];
			ext->ctrl = odev->d_nctrl;
			ext->control_no = -1;
			ext->type = MIXT_GROUP;
			ext->desc = MIXEXT_SCOPE_MONITOR;
			ext->timestamp = gethrtime();
			(void) snprintf(ext->id, sizeof (ext->id), "MONITOR");
			odev->d_mon_grp = odev->d_nctrl;
			odev->d_nctrl++;
		}
		scope = MIXEXT_SCOPE_MONITOR;
		parent = odev->d_mon_grp;
	} else {
		if (!odev->d_misc_grp) {
			ext = &odev->d_exts[odev->d_nctrl];
			ext->ctrl = odev->d_nctrl;
			ext->control_no = -1;
			ext->type = MIXT_GROUP;
			ext->desc = MIXEXT_SCOPE_OTHER;
			ext->timestamp = gethrtime();
			(void) snprintf(ext->id, sizeof (ext->id), "MISC");
			odev->d_misc_grp = odev->d_nctrl;
			odev->d_nctrl++;
		}
		scope = MIXEXT_SCOPE_OTHER;
		parent = odev->d_misc_grp;
	}

	name = desc.acd_name ? desc.acd_name : "";

	if (desc.acd_flags & AUDIO_CTRL_FLAG_MULTI) {
		ext = &odev->d_exts[odev->d_nctrl];
		ext->ctrl = odev->d_nctrl;
		ext->control_no = -1;
		ext->type = MIXT_GROUP;
		ext->timestamp = gethrtime();
		ext->parent = parent;
		ext->desc = scope;
		(void) snprintf(ext->id, sizeof (ext->id), "%s", name);
		(void) snprintf(ext->extname, sizeof (ext->extname),
		    "%s", name);
		parent = odev->d_nctrl++;
	}

	/* Next available open entry */
	ext = &odev->d_exts[odev->d_nctrl];

	/* Record the underlying control handle */
	odev->d_ctrls[odev->d_nctrl] = ctrl;

	/*
	 * Now setup the oss entry
	 */

	ext->ctrl = odev->d_nctrl;
	ext->control_no = -1;
	ext->maxvalue = (int)desc.acd_maxvalue;
	ext->minvalue = (int)desc.acd_minvalue;
	ext->timestamp = gethrtime();
	ext->parent = parent;
	ext->desc = scope;
	/* all controls should be pollable for now */
	flags = MIXF_POLL;

	/*
	 * The following flags are intended to help out applications
	 * which need to figure out where to place certain controls.
	 * A few further words of guidance:
	 *
	 * Apps that just want a single master volume control should
	 * adjust the control(s) that are labelled with MIXF_PCMVOL if
	 * present.  They can fall back to adjusting all MAINVOL
	 * levels instead, if no PCMVOL is present.
	 *
	 * Controls that are one type on a certain device might be a
	 * different type on another device.  For example,
	 * audiopci/ak4531 can adjust input gains for individual
	 * levels, but lacks a master record gain.  AC'97, on the
	 * other hand, has individual monitor gains for inputs, but
	 * only a single master recording gain.
	 */
	if (desc.acd_flags & AUDIO_CTRL_FLAG_READABLE)
		flags |= MIXF_READABLE;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_WRITEABLE)
		flags |= MIXF_WRITEABLE;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_CENTIBEL)
		flags |= MIXF_CENTIBEL;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_DECIBEL)
		flags |= MIXF_DECIBEL;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_MAINVOL)
		flags |= MIXF_MAINVOL;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_PCMVOL)
		flags |= MIXF_PCMVOL;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_RECVOL)
		flags |= MIXF_RECVOL;
	if (desc.acd_flags & AUDIO_CTRL_FLAG_MONVOL)
		flags |= MIXF_MONVOL;
	ext->flags = flags;

	(void) snprintf(ext->id, sizeof (ext->id), "%s", name);

	/*
	 * For now just use the same extname as the real name.
	 */
	(void) snprintf(ext->extname, sizeof (ext->extname), name);

	/*
	 * Now we deal with various control types.
	 */
	switch (desc.acd_type) {
	case AUDIO_CTRL_TYPE_BOOLEAN:
		ext->type = MIXT_ONOFF;
		ext->enumbit = -1;
		break;
	case AUDIO_CTRL_TYPE_STEREO:
		ext->type = MIXT_STEREOSLIDER;
		break;
	case AUDIO_CTRL_TYPE_MONO:
		ext->type = MIXT_MONOSLIDER;
		break;
	case AUDIO_CTRL_TYPE_ENUM:

		if (desc.acd_flags & AUDIO_CTRL_FLAG_MULTI) {
			/*
			 * We turn AUDIO_CTRL_FLAG_MULTI into a group
			 * of checkboxes, since OSS can't represent it
			 * natively.
			 */
			mask = desc.acd_maxvalue;
			bit = 0;
			while (mask) {
				if (mask & 1) {
					ext = &odev->d_exts[odev->d_nctrl];
					(void) snprintf(ext->extname,
					    sizeof (ext->extname), "%s.%s",
					    name, desc.acd_enum[bit]);
					(void) snprintf(ext->id,
					    sizeof (ext->id), "%s",
					    desc.acd_enum[bit]);
					ext->ctrl = odev->d_nctrl;
					ext->control_no = -1;
					ext->parent = parent;
					ext->timestamp = gethrtime();
					ext->type = MIXT_ONOFF;
					ext->minvalue = 0;
					ext->maxvalue = 1;
					ext->enumbit = bit;
					ext->flags = flags;
					odev->d_ctrls[odev->d_nctrl] = ctrl;
					odev->d_nctrl++;
				}
				bit++;
				mask >>= 1;
			}
			return (AUDIO_WALK_CONTINUE);
		} else {
			/*
			 * NB: This is sufficient only for controls
			 * with a single value.  It cannot express the
			 * richer bitmask capabilities.
			 */
			ext->type = MIXT_ENUM;
			ext->minvalue = 0;

			/*
			 * For an enumaration, we need to figure out
			 * which values are present, and set the
			 * appropriate mask and max value.
			 */
			bzero(ext->enum_present, sizeof (ext->enum_present));
			mask = desc.acd_maxvalue;
			bit = 0;
			while (mask) {
				if (mask & 1) {
					ext->enum_present[bit / 8] |=
					    (1 << (bit % 8));
				}
				mask >>= 1;
				bit++;
			}
			ext->maxvalue = bit;
		}
		break;

	case AUDIO_CTRL_TYPE_METER:
	default:
		/* Its an unknown or unsupported (for now) control, skip */
		return (AUDIO_WALK_CONTINUE);
	}

	odev->d_nctrl++;

	return (AUDIO_WALK_CONTINUE);
}

/*
 * Free up an OSS user land control to internal control,
 * helper table.
 */
static void
oss_free_controls(ossdev_t *odev)
{
	kmem_free(odev->d_ctrls, sizeof (audio_ctrl_t *) * odev->d_nalloc);
	kmem_free(odev->d_exts, sizeof (oss_mixext) * odev->d_nalloc);
	odev->d_nctrl = 0;
	odev->d_nalloc = 0;
}

/*
 * Allocate and fill in an OSS user land controls to internal controls
 * helper table. This is done on one audio_dev device.
 */
static void
oss_alloc_controls(ossdev_t *odev)
{
	audio_dev_t		*d = odev->d_dev;
	int			nctrl = 0;
	oss_mixext		*ext;
	oss_mixext_root		*root_data;

	/* Find out who many entries we need */
	auclnt_walk_controls(d, oss_cnt_controls, &nctrl);
	nctrl++;		/* Needs space for the device root node */
	nctrl++;		/* Needs space for the device ext marker */
	nctrl++;		/* Needs space for the play group */
	nctrl++;		/* Needs space for the record group */
	nctrl++;		/* Needs space for the monitor group */
	nctrl++;		/* Needs space for the tone group */
	nctrl++;		/* Needs space for the 3D group */
	nctrl++;		/* Needs space for the misc group */

	/* Allocate the OSS to boomer helper table */
	odev->d_nalloc = nctrl;
	odev->d_ctrls = kmem_zalloc(sizeof (audio_ctrl_t *) * nctrl, KM_SLEEP);
	odev->d_exts = kmem_zalloc(sizeof (oss_mixext) * nctrl, KM_SLEEP);

	/*
	 * Setup special case outputs to output OSS routes helper tables
	 */

	/*
	 * Root node is first, that way all others parent is this one
	 */
	ext = &odev->d_exts[odev->d_nctrl];
	ext->ctrl = 0;
	ext->parent = -1;
	ext->type = MIXT_DEVROOT;
	ext->timestamp = gethrtime();
	(void) snprintf(ext->id, sizeof (ext->id), "DEVROOT");
	/*
	 * Root data... nobody should be using this though.
	 */
	root_data = (oss_mixext_root *)&ext->data;
	(void) snprintf(root_data->name, sizeof (root_data->name), "%s",
	    auclnt_get_dev_name(d));
	(void) snprintf(root_data->id, sizeof (root_data->id), "%s",
	    auclnt_get_dev_name(d));

	odev->d_nctrl++;

	/*
	 * Insert an extra marker -- needed to keep layout apps hapy.
	 * This prevents some apps from assuming we are in "LEGACY" mode.
	 */
	ext = &odev->d_exts[odev->d_nctrl];
	ext->ctrl = odev->d_nctrl;
	ext->control_no = -1;
	ext->type = MIXT_MARKER;
	ext->timestamp = gethrtime();
	ext->parent = 0;
	odev->d_nctrl++;

	/* Fill in the complete table now */
	auclnt_walk_controls(d, oss_add_control, odev);

	/* Update the update_counter reference counter for groups */
	for (nctrl = 0; nctrl < odev->d_nctrl; nctrl++) {
		int i;

		ext = &odev->d_exts[nctrl];
		i = ext->parent;
		while ((i >= 0) && (i < odev->d_nctrl)) {

			ext = &odev->d_exts[i];
			ASSERT(ext->parent < i);
			ASSERT((ext->type == MIXT_GROUP) ||
			    (ext->type == MIXT_DEVROOT));
			ext->update_counter++;
			i = ext->parent;
		}
	}

	ASSERT(odev->d_nctrl <= odev->d_nalloc);
}

static int
oss_open(audio_client_t *c, int oflag)
{
	int		rv;
	ossdev_t	*odev;
	ossclient_t	*sc;
	audio_stream_t	*isp, *osp;

	isp = auclnt_input_stream(c);
	osp = auclnt_output_stream(c);

	/* note that OSS always uses nonblocking open() semantics */
	if ((rv = auclnt_open(c, AUDIO_FORMAT_PCM, oflag | FNDELAY)) != 0) {
		return (rv);
	}

	if ((sc = kmem_zalloc(sizeof (*sc), KM_NOSLEEP)) == NULL) {
		auclnt_close(c);
		return (ENOMEM);
	}
	auclnt_set_private(c, sc);

	odev = auclnt_get_minor_data(c, AUDIO_MINOR_DSP);

	/* set a couple of common fields */
	sc->o_client = c;
	sc->o_ossdev = odev;

	/* set all default parameters */
	if (oflag & FWRITE) {
		if (((rv = auclnt_set_format(osp, OSS_FMT)) != 0) ||
		    ((rv = auclnt_set_rate(osp, OSS_RATE)) != 0) ||
		    ((rv = auclnt_set_channels(osp, OSS_CHANNELS)) != 0)) {
			goto failed;
		}
		/* default to 5 fragments to provide reasonable latency */
		auclnt_set_latency(osp, 5, 0);
	}

	if (oflag & FREAD) {
		if (((rv = auclnt_set_format(isp, OSS_FMT)) != 0) ||
		    ((rv = auclnt_set_rate(isp, OSS_RATE)) != 0) ||
		    ((rv = auclnt_set_channels(isp, OSS_CHANNELS)) != 0)) {
			goto failed;
		}
		/* default to 5 fragments to provide reasonable latency */
		auclnt_set_latency(isp, 5, 0);
	}

	return (0);

failed:
	auclnt_close(c);
	return (rv);
}

static void
oss_close(audio_client_t *c)
{
	ossclient_t	*sc;

	sc = auclnt_get_private(c);

	if (ddi_can_receive_sig() || (ddi_get_pid() == 0)) {
		(void) auclnt_drain(c);
	}

	kmem_free(sc, sizeof (*sc));

	auclnt_close(c);
}

/*
 * This is used to generate an array of names for an enumeration
 */
static ushort_t
oss_set_enum(oss_mixer_enuminfo *ei, ushort_t nxt, const char *name)
{
	uint32_t	n;

	/* Get current entry to fill in */
	n = ei->nvalues;
	(void) snprintf(&ei->strings[nxt], ((sizeof (ei->strings) - nxt) - 1),
	    "%s", name);
	ei->strindex[n] = nxt;

	/* Adjust everything for next entry */
	nxt += strnlen(name, ((sizeof (ei->strings) - nxt) - 1));
	ei->strings[nxt++] = '\0';

	ei->nvalues++;
	return (nxt);
}

/*
 * The following two functions are used to count the number of devices
 * in under the boomer framework.
 *
 * We actually report the highest "index", and then if an audio device
 * is not found, we report a bogus removed device for it in the actual
 * ioctls.  This goofiness is required to make the OSS API happy.
 */
int
oss_dev_walker(audio_dev_t *d, void *arg)
{
	int		*pcnt = arg;
	int		cnt;
	int		index;

	cnt = *pcnt;
	index = auclnt_get_dev_index(d);
	if ((index + 1) > cnt) {
		cnt = index + 1;
		*pcnt = cnt;
	}

	return (AUDIO_WALK_CONTINUE);
}

static int
oss_cnt_devs(void)
{
	int cnt = 0;

	auclnt_walk_devs(oss_dev_walker, &cnt);
	return (cnt);
}

static int
sndctl_dsp_speed(audio_client_t *c, int *ratep)
{
	int		rv;
	int		rate;
	int		oflag;

	rate = *ratep;

	oflag = auclnt_get_oflag(c);
	if (oflag & FREAD) {
		if ((rv = auclnt_set_rate(auclnt_input_stream(c), rate)) != 0)
			return (rv);
	}

	if (oflag & FWRITE) {
		if ((rv = auclnt_set_rate(auclnt_output_stream(c), rate)) != 0)
			return (rv);
	}

	return (0);
}

static int
sndctl_dsp_setfmt(audio_client_t *c, int *fmtp)
{
	int		rv;
	int		fmt;
	int		i;
	int		oflag;

	oflag = auclnt_get_oflag(c);

	if (*fmtp != AFMT_QUERY) {
		/* convert from OSS */
		for (i = 0; oss_formats[i].fmt != AUDIO_FORMAT_NONE; i++) {
			if (oss_formats[i].oss == *fmtp) {
				fmt = oss_formats[i].fmt;
				break;
			}
		}
		if (fmt == AUDIO_FORMAT_NONE) {
			/* if format not known, return ENOTSUP */
			return (ENOTSUP);
		}

		if (oflag & FWRITE) {
			rv = auclnt_set_format(auclnt_output_stream(c), fmt);
			if (rv != 0)
				return (rv);
		}

		if (oflag & FREAD) {
			rv = auclnt_set_format(auclnt_input_stream(c), fmt);
			if (rv != 0)
				return (rv);
		}
	}

	if (oflag & FWRITE) {
		fmt = auclnt_get_format(auclnt_output_stream(c));
	} else if (oflag & FREAD) {
		fmt = auclnt_get_format(auclnt_input_stream(c));
	}

	/* convert back to OSS */
	*(int *)fmtp = AFMT_QUERY;
	for (i = 0; oss_formats[i].fmt != AUDIO_FORMAT_NONE; i++) {
		if (oss_formats[i].fmt == fmt) {
			*(int *)fmtp = oss_formats[i].oss;
		}
	}

	return (0);
}

static int
sndctl_dsp_getfmts(audio_client_t *c, int *fmtsp)
{
	_NOTE(ARGUNUSED(c));

	/*
	 * For now, we support all the standard ones.  Later we might
	 * add in conditional support for AC3.
	 */
	*fmtsp = (AFMT_MU_LAW | AFMT_A_LAW |
	    AFMT_U8 | AFMT_S8 |
	    AFMT_S16_LE |AFMT_S16_BE |
	    AFMT_S24_LE | AFMT_S24_BE |
	    AFMT_S32_LE | AFMT_S32_BE |
	    AFMT_S24_PACKED);

	return (0);
}

static int
sndctl_dsp_channels(audio_client_t *c, int *chanp)
{
	int		rv;
	int		nchan;
	int		oflag;

	oflag = auclnt_get_oflag(c);

	nchan = *chanp;
	if (nchan != 0) {
		if (oflag & FWRITE) {
			rv = auclnt_set_channels(auclnt_output_stream(c),
			    nchan);
			if (rv != 0)
				return (rv);
		}

		if (oflag & FREAD) {
			rv = auclnt_set_channels(auclnt_input_stream(c), nchan);
			if (rv != 0)
				return (rv);
		}
	}

	if (oflag & FWRITE) {
		nchan = auclnt_get_channels(auclnt_output_stream(c));
	} else if (oflag & FREAD) {
		nchan = auclnt_get_channels(auclnt_input_stream(c));
	}
	*chanp = nchan;
	return (0);
}

static int
sndctl_dsp_stereo(audio_client_t *c, int *onoff)
{
	int	nchan;

	switch (*onoff) {
	case 0:
		nchan = 1;
		break;
	case 1:
		nchan = 2;
		break;
	default:
		return (EINVAL);
	}

	return (sndctl_dsp_channels(c, &nchan));
}

static int
sndctl_dsp_post(audio_client_t *c)
{
	if (auclnt_get_oflag(c) & FWRITE) {
		audio_stream_t	*sp = auclnt_output_stream(c);
		auclnt_flush(sp);
		auclnt_clear_paused(sp);
	}
	return (0);
}

static int
sndctl_dsp_getcaps(audio_client_t *c, int *capsp)
{
	int		ncaps;
	int		osscaps = 0;

	ncaps = auclnt_get_dev_capab(auclnt_get_dev(c));

	if (ncaps & AUDIO_CLIENT_CAP_PLAY)
		osscaps |= PCM_CAP_OUTPUT;
	if (ncaps & AUDIO_CLIENT_CAP_RECORD)
		osscaps |= PCM_CAP_INPUT;
	if (ncaps & AUDIO_CLIENT_CAP_DUPLEX)
		osscaps |= PCM_CAP_DUPLEX;

	*capsp = osscaps;
	return (0);
}

static int
sndctl_dsp_gettrigger(audio_client_t *c, int *trigp)
{
	int		triggers = 0;
	int		oflag;

	oflag = auclnt_get_oflag(c);

	if (oflag & FWRITE) {
		if (!auclnt_is_paused(auclnt_output_stream(c))) {
			triggers |= PCM_ENABLE_OUTPUT;
		}
	}

	if (oflag & FREAD) {
		if (!auclnt_is_paused(auclnt_input_stream(c))) {
			triggers |= PCM_ENABLE_INPUT;
		}
	}
	*trigp = triggers;

	return (0);
}

static int
sndctl_dsp_settrigger(audio_client_t *c, int *trigp)
{
	int		triggers;
	int		oflag;
	audio_stream_t	*sp;

	oflag = auclnt_get_oflag(c);
	triggers = *trigp;

	if ((oflag & FWRITE) && (triggers & PCM_ENABLE_OUTPUT)) {
		sp = auclnt_output_stream(c);
		auclnt_clear_paused(sp);
		auclnt_start(sp);
	}

	if ((oflag & FREAD) && (triggers & PCM_ENABLE_INPUT)) {
		sp = auclnt_input_stream(c);
		auclnt_clear_paused(sp);
		auclnt_start(sp);
	}

	return (0);
}

struct oss_legacy_volume {
	pid_t		pid;
	uint8_t		ogain;
	uint8_t		igain;
};

static int
oss_legacy_volume_walker(audio_client_t *c, void *arg)
{
	struct oss_legacy_volume	 *olv = arg;

	if (auclnt_get_pid(c) == olv->pid) {
		if (olv->ogain <= 100) {
			auclnt_set_gain(auclnt_output_stream(c), olv->ogain);
		}
		if (olv->igain <= 100) {
			auclnt_set_gain(auclnt_input_stream(c), olv->igain);
		}
	}
	return (AUDIO_WALK_CONTINUE);
}

static void
oss_set_legacy_volume(audio_client_t *c, uint8_t ogain, uint8_t igain)
{
	struct oss_legacy_volume olv;

	olv.pid = auclnt_get_pid(c);
	olv.ogain = ogain;
	olv.igain = igain;
	auclnt_dev_walk_clients(auclnt_get_dev(c),
	    oss_legacy_volume_walker, &olv);
}

static int
sndctl_dsp_getplayvol(audio_client_t *c, int *volp)
{
	int	vol;

	/* convert monophonic soft value to OSS stereo value */
	vol = auclnt_get_gain(auclnt_output_stream(c));
	*volp = vol | (vol << 8);
	return (0);
}

static int
sndctl_dsp_setplayvol(audio_client_t *c, int *volp)
{
	uint8_t		vol;

	vol = *volp & 0xff;
	if (vol > 100) {
		return (EINVAL);
	}

	auclnt_set_gain(auclnt_output_stream(c), vol);
	*volp = (vol | (vol << 8));

	return (0);
}

static int
sndctl_dsp_getrecvol(audio_client_t *c, int *volp)
{
	int	vol;

	vol = auclnt_get_gain(auclnt_input_stream(c));
	*volp = (vol | (vol << 8));
	return (0);
}

static int
sndctl_dsp_setrecvol(audio_client_t *c, int *volp)
{
	uint8_t		vol;

	vol = *volp & 0xff;
	if (vol > 100) {
		return (EINVAL);
	}

	auclnt_set_gain(auclnt_input_stream(c), vol);
	*volp = (vol | (vol << 8));

	return (0);
}

static int
sound_mixer_write_ogain(audio_client_t *c, int *volp)
{
	uint8_t		vol;

	vol = *volp & 0xff;
	if (vol > 100) {
		return (EINVAL);
	}
	oss_set_legacy_volume(c, vol, 255);
	*volp = (vol | (vol << 8));
	return (0);
}

static int
sound_mixer_write_igain(audio_client_t *c, int *volp)
{
	uint8_t		vol;

	vol = *volp & 0xff;
	if (vol > 100) {
		return (EINVAL);
	}
	oss_set_legacy_volume(c, 255, vol);
	*volp = (vol | (vol << 8));
	return (0);
}

static int
sndctl_dsp_readctl(audio_client_t *c, oss_digital_control *ctl)
{
	/* SPDIF: need to add support with spdif */
	_NOTE(ARGUNUSED(c));
	_NOTE(ARGUNUSED(ctl));
	return (ENOTSUP);
}

static int
sndctl_dsp_writectl(audio_client_t *c, oss_digital_control *ctl)
{
	/* SPDIF: need to add support with spdif */
	_NOTE(ARGUNUSED(c));
	_NOTE(ARGUNUSED(ctl));
	return (ENOTSUP);
}

static int
sndctl_dsp_cookedmode(audio_client_t *c, int *rvp)
{
	_NOTE(ARGUNUSED(c));

	/* We are *always* in cooked mode -- at least until we have AC3. */
	if (*rvp == 0) {
		return (ENOTSUP);
	} else {
		return (0);
	}
}

static int
sndctl_dsp_silence(audio_client_t *c)
{
	if (auclnt_get_oflag(c) & FWRITE) {
		audio_stream_t	*sp = auclnt_output_stream(c);
		auclnt_set_paused(sp);
		auclnt_flush(sp);
	}
	return (0);
}

static int
sndctl_dsp_skip(audio_client_t *c)
{
	if (auclnt_get_oflag(c) & FWRITE) {
		audio_stream_t	*sp = auclnt_output_stream(c);
		auclnt_set_paused(sp);
		auclnt_flush(sp);
		auclnt_clear_paused(sp);
	}
	return (0);
}

static int
sndctl_dsp_halt_input(audio_client_t *c)
{
	if (auclnt_get_oflag(c) & FREAD) {
		audio_stream_t	*sp = auclnt_input_stream(c);
		auclnt_set_paused(sp);
		auclnt_flush(sp);
	}
	return (0);
}

static int
sndctl_dsp_halt_output(audio_client_t *c)
{
	if (auclnt_get_oflag(c) & FWRITE) {
		audio_stream_t	*sp = auclnt_output_stream(c);
		auclnt_set_paused(sp);
		auclnt_flush(sp);
	}
	return (0);
}

static int
sndctl_dsp_halt(audio_client_t *c)
{
	(void) sndctl_dsp_halt_input(c);
	(void) sndctl_dsp_halt_output(c);
	return (0);
}

static int
sndctl_dsp_sync(audio_client_t *c)
{
	return (auclnt_drain(c));
}

static int
sndctl_dsp_setfragment(audio_client_t *c, int *fragp)
{
	int	bufsz;
	int	nfrags;
	int	fragsz;

	nfrags = (*fragp) >> 16;
	if ((nfrags >= 0x7fffU) || (nfrags < 2)) {
		/* use infinite setting... no change */
		return (0);
	}

	fragsz = (*fragp) & 0xffff;
	if (fragsz > 16) {
		/* basically too big, so, no change */
		return (0);
	}
	bufsz = (1U << fragsz) * nfrags;

	/*
	 * Now we have our desired buffer size, but we have to
	 * make sure we have a whole number of fragments >= 2, and
	 * less than the maximum.
	 */
	bufsz = ((*fragp) >> 16) * (1U << (*fragp));
	if (bufsz >= 65536) {
		return (0);
	}

	/*
	 * We set the latency hints in terms of bytes, not fragments.
	 */
	auclnt_set_latency(auclnt_output_stream(c), 0, bufsz);
	auclnt_set_latency(auclnt_input_stream(c), 0, bufsz);

	/*
	 * According to the OSS API documentation, the values provided
	 * are nothing more than a "hint" and not to be relied upon
	 * anyway.  And we aren't obligated to report the actual
	 * values back!
	 */
	return (0);
}

static int
sndctl_dsp_policy(audio_client_t *c, int *policy)
{
	int	hint = *policy;
	if ((hint >= 2) && (hint <= 10)) {
		auclnt_set_latency(auclnt_input_stream(c), hint, 0);
		auclnt_set_latency(auclnt_output_stream(c), hint, 0);
	}
	return (0);
}

/*
 * A word about recsrc, and playtgt ioctls: We don't allow ordinary DSP
 * applications to change port configurations, because these could have a
 * bad effect for other applications.  Instead, these settings have to
 * be changed using the master mixer panel.  In order to make applications
 * happy, we just present a single "default" source/target.
 */
static int
sndctl_dsp_get_recsrc_names(audio_client_t *c, oss_mixer_enuminfo *ei)
{
	_NOTE(ARGUNUSED(c));

	ei->nvalues = 1;
	(void) snprintf(ei->strings, sizeof (ei->strings), "default");
	ei->strindex[0] = 0;

	return (0);
}

static int
sndctl_dsp_get_recsrc(audio_client_t *c, int *srcp)
{
	_NOTE(ARGUNUSED(c));
	*srcp = 0;
	return (0);
}

static int
sndctl_dsp_set_recsrc(audio_client_t *c, int *srcp)
{
	_NOTE(ARGUNUSED(c));
	*srcp = 0;
	return (0);
}

static int
sndctl_dsp_get_playtgt_names(audio_client_t *c, oss_mixer_enuminfo *ei)
{
	_NOTE(ARGUNUSED(c));

	ei->nvalues = 1;
	(void) snprintf(ei->strings, sizeof (ei->strings), "default");
	ei->strindex[0] = 0;

	return (0);
}

static int
sndctl_dsp_get_playtgt(audio_client_t *c, int *tgtp)
{
	_NOTE(ARGUNUSED(c));
	*tgtp = 0;
	return (0);
}

static int
sndctl_dsp_set_playtgt(audio_client_t *c, int *tgtp)
{
	_NOTE(ARGUNUSED(c));
	*tgtp = 0;
	return (0);
}

static int
sndctl_sysinfo(oss_sysinfo *si)
{
	bzero(si, sizeof (*si));
	(void) snprintf(si->product, sizeof (si->product), "SunOS Audio");
	(void) snprintf(si->version, sizeof (si->version), "4.0");
	si->versionnum = OSS_VERSION;
	si->numcards = oss_cnt_devs();
	si->nummixers = si->numcards - 1;
	si->numaudios = si->numcards - 1;
	si->numaudioengines = si->numaudios;
	(void) snprintf(si->license, sizeof (si->license), "CDDL");
	return (0);
}

static int
sndctl_cardinfo(audio_client_t *c, oss_card_info *ci)
{
	audio_dev_t	*d;
	void		*iter;
	const char 	*info;
	int		n;
	boolean_t	release;

	if ((n = ci->card) == -1) {
		release = B_FALSE;
		d = auclnt_get_dev(c);
		n = auclnt_get_dev_index(d);
	} else {
		release = B_TRUE;
		d = auclnt_hold_dev_by_index(n);
	}

	bzero(ci, sizeof (*ci));
	ci->card = n;

	if (d == NULL) {
		/*
		 * If device removed (e.g. for DR), then
		 * report a bogus removed entry.
		 */
		(void) snprintf(ci->shortname, sizeof (ci->shortname),
		    "<removed>");
		(void) snprintf(ci->longname, sizeof (ci->longname),
		    "<removed>");
		return (0);
	}

	(void) snprintf(ci->shortname, sizeof (ci->shortname),
	    "%s", auclnt_get_dev_name(d));
	(void) snprintf(ci->longname, sizeof (ci->longname),
	    "%s (%s)", auclnt_get_dev_description(d),
	    auclnt_get_dev_version(d));

	iter = NULL;
	while ((info = auclnt_get_dev_hw_info(d, &iter)) != NULL) {
		(void) strlcat(ci->hw_info, info, sizeof (ci->hw_info));
		(void) strlcat(ci->hw_info, "\n", sizeof (ci->hw_info));
	}

	/*
	 * We don't report interrupt counts, ack counts (which are
	 * just "read" interrupts, not spurious), or any other flags.
	 * Nothing should be using any of this data anyway ... these
	 * values were intended for 4Front's debugging purposes.  In
	 * Solaris, drivers should use interrupt kstats to report
	 * interrupt related statistics.
	 */
	if (release)
		auclnt_release_dev(d);
	return (0);
}

static int
audioinfo_walker(audio_engine_t *e, void *a)
{
	oss_audioinfo *si = a;
	int fmt, nchan, rate, cap;

	fmt = auclnt_engine_get_format(e);
	nchan = auclnt_engine_get_channels(e);
	rate = auclnt_engine_get_rate(e);
	cap = auclnt_engine_get_capab(e);

	for (int i = 0; oss_formats[i].fmt != AUDIO_FORMAT_NONE; i++) {
		if (fmt == oss_formats[i].fmt) {
			if (cap & AUDIO_CLIENT_CAP_PLAY) {
				si->oformats |= oss_formats[i].oss;
			}
			if (cap & AUDIO_CLIENT_CAP_RECORD) {
				si->iformats |= oss_formats[i].oss;
			}
			break;
		}
	}
	si->max_channels = max(nchan, si->max_channels);
	si->max_rate = max(rate, si->max_rate);

	return (AUDIO_WALK_CONTINUE);
}

static int
sndctl_audioinfo(audio_client_t *c, oss_audioinfo *si)
{
	audio_dev_t		*d;
	const char		*name;
	int			n;
	boolean_t		release;
	unsigned		cap;

	if ((n = si->dev) == -1) {
		release = B_FALSE;
		d = auclnt_get_dev(c);
		n = auclnt_get_dev_index(d);
	} else {
		release = B_TRUE;
		n++;	/* skip pseudo device */
		d = auclnt_hold_dev_by_index(n);
	}

	bzero(si, sizeof (*si));
	si->dev = n - 1;

	if (d == NULL) {
		/* if device not present, forge a false entry */
		si->card_number = n;
		si->mixer_dev = n - 1;
		si->legacy_device = -1;
		si->enabled = 0;
		(void) snprintf(si->name, sizeof (si->name), "<removed>");
		return (0);
	}

	name = auclnt_get_dev_name(d);
	(void) snprintf(si->name, sizeof (si->name), "%s", name);

	si->legacy_device = auclnt_get_dev_number(d);
	si->caps = 0;

	auclnt_dev_walk_engines(d, audioinfo_walker, si);

	cap = auclnt_get_dev_capab(d);

	if (cap	& AUDIO_CLIENT_CAP_DUPLEX) {
		si->caps |= PCM_CAP_DUPLEX;
	}
	if (cap & AUDIO_CLIENT_CAP_PLAY) {
		si->caps |= PCM_CAP_OUTPUT;
	}
	if (cap & AUDIO_CLIENT_CAP_RECORD) {
		si->caps |= PCM_CAP_INPUT;
	}

	if (si->caps != 0) {
		/* AC3: PCM_CAP_MULTI would be wrong for an AC3 only device */
		si->caps |= PCM_CAP_BATCH | PCM_CAP_TRIGGER | PCM_CAP_MULTI;
		/* MMAP: we add PCM_CAP_MMAP when we we support it */
		si->enabled = 1;
		si->rate_source = si->dev;

		/* we can convert PCM formats */
		if ((si->iformats | si->oformats) &
		    AUDIO_FORMAT_PCM) {
			si->min_channels = min(2, si->max_channels);
			si->min_rate = min(5000, si->max_rate);
			si->caps |= PCM_CAP_FREERATE;
		}
		(void) snprintf(si->devnode, sizeof (si->devnode),
		    "/dev/sound/%s:%ddsp",
		    auclnt_get_dev_driver(d), auclnt_get_dev_instance(d));
	} else {
		si->enabled = 0;	/* stops apps from using us directly */
		si->caps = PCM_CAP_VIRTUAL;
		(void) snprintf(si->devnode, sizeof (si->devnode),
		    "/dev/sndstat");
	}

	si->pid = -1;
	(void) snprintf(si->handle, sizeof (si->handle), "%s", name);
	(void) snprintf(si->label, sizeof (si->label), "%s", name);
	si->latency = -1;
	si->card_number = n;
	si->mixer_dev = n - 1;

	if (release)
		auclnt_release_dev(d);

	return (0);
}

static int
sound_mixer_info(audio_client_t *c, mixer_info *mi)
{
	audio_dev_t	*d;
	ossdev_t	*odev;
	ossclient_t	*sc;
	const char	*name;

	sc = auclnt_get_private(c);
	odev = sc->o_ossdev;

	d = auclnt_get_dev(c);

	name = auclnt_get_dev_name(d);
	(void) snprintf(mi->id, sizeof (mi->id), "%s", name);
	(void) snprintf(mi->name, sizeof (mi->name), "%s", name);
	(void) snprintf(mi->handle, sizeof (mi->handle), "%s", name);
	mi->modify_counter = odev->d_modify_cnt;
	mi->card_number = auclnt_get_dev_index(d);
	mi->port_number = 0;
	return (0);
}

static int
sound_mixer_read_devmask(audio_client_t *c, int *devmask)
{
	_NOTE(ARGUNUSED(c));
	*devmask = SOUND_MASK_VOLUME | SOUND_MASK_PCM | SOUND_MASK_IGAIN;
	return (0);
}

static int
sound_mixer_read_recmask(audio_client_t *c, int *recmask)
{
	_NOTE(ARGUNUSED(c));
	*recmask = 0;
	return (0);
}

static int
sound_mixer_read_recsrc(audio_client_t *c, int *recsrc)
{
	_NOTE(ARGUNUSED(c));
	*recsrc = 0;
	return (0);
}

static int
sound_mixer_read_caps(audio_client_t *c, int *caps)
{
	_NOTE(ARGUNUSED(c));
	/* single recording source... sort of */
	*caps = SOUND_CAP_EXCL_INPUT;
	return (0);
}

static int
sndctl_mixerinfo(audio_client_t *c, oss_mixerinfo *mi)
{
	audio_dev_t		*d;
	ossdev_t 		*odev;
	const char		*name;
	int			n;
	boolean_t		release = B_FALSE;

	if ((n = mi->dev) == -1) {
		release = B_FALSE;
		d = auclnt_get_dev(c);
		n = auclnt_get_dev_index(d);
	} else {
		release = B_TRUE;
		n++;
		d = auclnt_hold_dev_by_index(n);
	}

	bzero(mi, sizeof (*mi));
	mi->dev = n - 1;

	if (d == NULL) {
		mi->card_number = n;
		mi->enabled = 0;
		mi->legacy_device = -1;
		(void) snprintf(mi->name, sizeof (mi->name), "<removed>");
		(void) snprintf(mi->id, sizeof (mi->id), "<removed>");
		return (0);
	}

	if ((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) {
		if (release)
			auclnt_release_dev(d);
		return (EINVAL);
	}

	name = auclnt_get_dev_name(d);
	(void) snprintf(mi->name, sizeof (mi->name), "%s", name);
	(void) snprintf(mi->id, sizeof (mi->id), "%s", name);
	(void) snprintf(mi->handle, sizeof (mi->handle), "%s", name);
	mi->modify_counter = odev->d_modify_cnt;
	mi->card_number = auclnt_get_dev_index(d);
	mi->legacy_device = auclnt_get_dev_number(d);
	if (mi->legacy_device >= 0) {
		(void) snprintf(mi->devnode, sizeof (mi->devnode),
		    "/dev/sound/%s:%dmixer",
		    auclnt_get_dev_driver(d), auclnt_get_dev_instance(d));
		mi->enabled = 1;
	} else {
		/* special nodes use generic sndstat node */
		(void) snprintf(mi->devnode, sizeof (mi->devnode),
		    "/dev/sndstat");
		mi->enabled = 0;
	}
	mi->nrext = odev->d_nctrl;

	if (release)
		auclnt_release_dev(d);

	return (0);
}

static int
sndctl_dsp_getblksize(audio_client_t *c, int *fragsz)
{
	int	oflag = auclnt_get_oflag(c);

	if (oflag & FWRITE)
		*fragsz  = auclnt_get_fragsz(auclnt_output_stream(c));
	else if (oflag & FREAD)
		*fragsz  = auclnt_get_fragsz(auclnt_input_stream(c));

	return (0);
}

static int
sndctl_dsp_getospace(audio_client_t *c, audio_buf_info *bi)
{
	audio_stream_t	*sp;
	unsigned	n;

	if ((auclnt_get_oflag(c) & FWRITE) == 0) {
		return (EACCES);
	}

	sp = auclnt_output_stream(c);
	n = auclnt_get_nframes(sp) - auclnt_get_count(sp);

	bi->fragsize  = auclnt_get_fragsz(sp);
	bi->fragstotal = auclnt_get_nfrags(sp);
	bi->bytes = (n * auclnt_get_framesz(sp));
	bi->fragments = bi->bytes / bi->fragsize;

	return (0);
}

static int
sndctl_dsp_getispace(audio_client_t *c, audio_buf_info *bi)
{
	audio_stream_t	*sp;
	unsigned	n;

	if ((auclnt_get_oflag(c) & FREAD) == 0) {
		return (EACCES);
	}

	sp = auclnt_input_stream(c);
	n = auclnt_get_count(sp);

	bi->fragsize  = auclnt_get_fragsz(sp);
	bi->fragstotal = auclnt_get_nfrags(sp);
	bi->bytes = (n * auclnt_get_framesz(sp));
	bi->fragments = bi->bytes / bi->fragsize;

	return (0);
}

static int
sndctl_dsp_getodelay(audio_client_t *c, int *bytes)
{
	unsigned	framesz;
	unsigned	slen, flen;

	if (auclnt_get_oflag(c) & FWRITE) {
		audio_stream_t	*sp = auclnt_output_stream(c);
		framesz = auclnt_get_framesz(sp);
		auclnt_get_output_qlen(c, &slen, &flen);
		*bytes = (slen + flen) * framesz;
	} else {
		*bytes = 0;
	}
	return (0);
}

static int
sndctl_dsp_current_iptr(audio_client_t *c, oss_count_t *count)
{
	if (auclnt_get_oflag(c) & FREAD) {
		count->samples = auclnt_get_samples(auclnt_input_stream(c));
		count->fifo_samples = 0;	/* not quite accurate */
	} else {
		count->samples = 0;
		count->fifo_samples = 0;
	}
	return (0);
}

static int
sndctl_dsp_current_optr(audio_client_t *c, oss_count_t *count)
{
	unsigned samples, fifo;

	if (auclnt_get_oflag(c) & FWRITE) {
		auclnt_get_output_qlen(c, &samples, &fifo);
		count->samples = samples;
		count->fifo_samples = fifo;
	} else {
		count->samples = 0;
		count->fifo_samples = 0;
	}
	return (0);
}

static int
sndctl_dsp_getoptr(audio_client_t *c, count_info *ci)
{
	audio_stream_t	*sp;
	unsigned	framesz;
	unsigned	fragsz;

	bzero(ci, sizeof (*ci));
	if ((auclnt_get_oflag(c) & FWRITE) == 0) {
		return (0);
	}
	sp = auclnt_output_stream(c);
	framesz = auclnt_get_framesz(sp);
	fragsz = auclnt_get_fragsz(sp);
	ci->blocks = auclnt_get_samples(sp) * framesz / fragsz;
	auclnt_set_samples(sp, 0);
	ci->bytes = auclnt_get_tail(sp) * framesz;
	ci->ptr = auclnt_get_tidx(sp) * framesz;
	return (0);
}

static int
sndctl_dsp_getiptr(audio_client_t *c, count_info *ci)
{
	audio_stream_t	*sp;
	unsigned	framesz;
	unsigned	fragsz;

	bzero(ci, sizeof (*ci));
	if ((auclnt_get_oflag(c) & FREAD) == 0) {
		return (0);
	}
	sp = auclnt_input_stream(c);
	framesz = auclnt_get_framesz(sp);
	fragsz = auclnt_get_fragsz(sp);
	ci->blocks = auclnt_get_samples(sp) * framesz / fragsz;
	auclnt_set_samples(sp, 0);
	ci->bytes = auclnt_get_head(sp) * framesz;
	ci->ptr = auclnt_get_hidx(sp) * framesz;
	return (0);
}

static int
sndctl_dsp_geterror(audio_client_t *c, audio_errinfo *bi)
{
	audio_stream_t	*sp;
	unsigned	fragsz;
	/*
	 * Note: The use of this structure is unsafe... different
	 * meanings for error codes are used by different implementations,
	 * according to the spec.  (Even different versions of the same
	 * implementation could have different values.)
	 *
	 * Rather than try to come up with a reliable solution here, we
	 * don't use it.  If you want to report errors, or see the result
	 * of errors, use syslog.
	 */
	bzero(bi, sizeof (*bi));

	sp = auclnt_output_stream(c);
	fragsz = max(auclnt_get_fragsz(sp), 1);
	bi->play_underruns = (int)((auclnt_get_errors(sp) + (fragsz - 1)) /
	    fragsz);
	auclnt_set_errors(sp, 0);

	sp = auclnt_input_stream(c);
	fragsz = max(auclnt_get_fragsz(sp), 1);
	bi->rec_overruns = (int)((auclnt_get_errors(sp) + (fragsz - 1)) /
	    fragsz);
	auclnt_set_errors(sp, 0);

	return (0);
}

static int
sndctl_sun_send_number(audio_client_t *c, int *num, cred_t *cr)
{
	audio_dev_t	*dev;
	int		rv;

	if ((rv = drv_priv(cr)) != 0) {
		return (rv);
	}

	dev = auclnt_get_dev(c);
	auclnt_set_dev_number(dev, *num);
	return (0);
}

static int
oss_getversion(int *versp)
{
	*versp = OSS_VERSION;
	return (0);
}

static int
oss_ioctl(audio_client_t *c, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int	sz;
	void	*data;
	int	rv = 0;

	_NOTE(ARGUNUSED(credp));

	sz = OSSIOC_GETSZ(cmd);

	if ((cmd & (OSSIOC_IN | OSSIOC_OUT)) && sz) {
		if ((data = kmem_zalloc(sz, KM_NOSLEEP)) == NULL) {
			return (ENOMEM);
		}
	} else {
		sz = 0;
	}

	if (cmd & OSSIOC_IN) {
		if ((rv = ddi_copyin((void *)arg, data, sz, mode)) != 0) {
			goto done;
		}
	}

	switch (cmd) {
		/*
		 * DSP specific ioctls
		 */
	case SNDCTL_DSP_HALT:
		rv = sndctl_dsp_halt(c);
		break;

	case SNDCTL_DSP_SYNC:
		rv = sndctl_dsp_sync(c);
		break;

	case SNDCTL_DSP_SPEED:
		rv = sndctl_dsp_speed(c, (int *)data);
		break;
	case SNDCTL_DSP_SETFMT:
		rv = sndctl_dsp_setfmt(c, (int *)data);
		break;
	case SNDCTL_DSP_GETFMTS:
		rv = sndctl_dsp_getfmts(c, (int *)data);
		break;
	case SNDCTL_DSP_STEREO:
		rv = sndctl_dsp_stereo(c, (int *)data);
		break;
	case SNDCTL_DSP_CHANNELS:
		rv = sndctl_dsp_channels(c, (int *)data);
		break;
	case SNDCTL_DSP_POST:
		rv = sndctl_dsp_post(c);
		break;
	case SNDCTL_DSP_GETCAPS:
		rv = sndctl_dsp_getcaps(c, (int *)data);
		break;
	case SNDCTL_DSP_GETTRIGGER:
		rv = sndctl_dsp_gettrigger(c, (int *)data);
		break;
	case SNDCTL_DSP_SETTRIGGER:
		rv = sndctl_dsp_settrigger(c, (int *)data);
		break;
	case SNDCTL_DSP_GETPLAYVOL:
	case SOUND_MIXER_READ_VOLUME:	/* legacy mixer on dsp */
	case SOUND_MIXER_READ_PCM:	/* legacy mixer on dsp */
	case SOUND_MIXER_READ_OGAIN:	/* legacy mixer on dsp */
		rv = sndctl_dsp_getplayvol(c, (int *)data);
		break;
	case SOUND_MIXER_WRITE_VOLUME:	/* legacy mixer on dsp */
	case SOUND_MIXER_WRITE_PCM:	/* legacy mixer on dsp */
	case SOUND_MIXER_WRITE_OGAIN:	/* legacy mixer on dsp */
		rv = sound_mixer_write_ogain(c, (int *)data);
		break;
	case SNDCTL_DSP_SETPLAYVOL:
		rv = sndctl_dsp_setplayvol(c, (int *)data);
		break;
	case SNDCTL_DSP_READCTL:
		rv = sndctl_dsp_readctl(c, (oss_digital_control *)data);
		break;
	case SNDCTL_DSP_WRITECTL:
		rv = sndctl_dsp_writectl(c, (oss_digital_control *)data);
		break;
	case SNDCTL_DSP_COOKEDMODE:
		rv = sndctl_dsp_cookedmode(c, (int *)data);
		break;
	case SNDCTL_DSP_SILENCE:
		rv = sndctl_dsp_silence(c);
		break;
	case SNDCTL_DSP_SKIP:
		rv = sndctl_dsp_skip(c);
		break;
	case SNDCTL_DSP_HALT_INPUT:
		rv = sndctl_dsp_halt_input(c);
		break;
	case SNDCTL_DSP_HALT_OUTPUT:
		rv = sndctl_dsp_halt_output(c);
		break;
	case SNDCTL_DSP_GET_RECSRC_NAMES:
		rv = sndctl_dsp_get_recsrc_names(c, (oss_mixer_enuminfo *)data);
		break;
	case SNDCTL_DSP_SETFRAGMENT:
		rv = sndctl_dsp_setfragment(c, (int *)data);
		break;
	case SNDCTL_DSP_GET_RECSRC:
		rv = sndctl_dsp_get_recsrc(c, (int *)data);
		break;
	case SNDCTL_DSP_SET_RECSRC:
		rv = sndctl_dsp_set_recsrc(c, (int *)data);
		break;
	case SNDCTL_DSP_GET_PLAYTGT_NAMES:
		rv = sndctl_dsp_get_playtgt_names(c,
		    (oss_mixer_enuminfo *)data);
		break;
	case SNDCTL_DSP_GET_PLAYTGT:
		rv = sndctl_dsp_get_playtgt(c, (int *)data);
		break;
	case SNDCTL_DSP_SET_PLAYTGT:
		rv = sndctl_dsp_set_playtgt(c, (int *)data);
		break;
	case SNDCTL_DSP_GETRECVOL:
	case SOUND_MIXER_READ_RECGAIN:	/* legacy mixer on dsp */
	case SOUND_MIXER_READ_RECLEV:	/* legacy mixer on dsp */
	case SOUND_MIXER_READ_IGAIN:	/* legacy mixer on dsp */
		rv = sndctl_dsp_getrecvol(c, (int *)data);
		break;
	case SOUND_MIXER_WRITE_RECGAIN:	/* legacy mixer on dsp */
	case SOUND_MIXER_WRITE_RECLEV:	/* legacy mixer on dsp */
	case SOUND_MIXER_WRITE_IGAIN:	/* legacy mixer on dsp */
		rv = sound_mixer_write_igain(c, (int *)data);
		break;
	case SNDCTL_DSP_SETRECVOL:
		rv = sndctl_dsp_setrecvol(c, (int *)data);
		break;
	case SNDCTL_DSP_SUBDIVIDE:	/* Ignored */
	case SNDCTL_DSP_SETDUPLEX:	/* Ignored */
	case SNDCTL_DSP_LOW_WATER:	/* Ignored */
	case SNDCTL_DSP_PROFILE:	/* Ignored */
		rv = 0;
		break;
	case SNDCTL_DSP_POLICY:
		rv = sndctl_dsp_policy(c, (int *)data);
		break;
	case SNDCTL_DSP_GETBLKSIZE:
		rv = sndctl_dsp_getblksize(c, (int *)data);
		break;
	case SNDCTL_DSP_GETOSPACE:
		rv = sndctl_dsp_getospace(c, (audio_buf_info *)data);
		break;
	case SNDCTL_DSP_GETISPACE:
		rv = sndctl_dsp_getispace(c, (audio_buf_info *)data);
		break;
	case SNDCTL_DSP_GETODELAY:
		rv = sndctl_dsp_getodelay(c, (int *)data);
		break;
	case SNDCTL_DSP_GETOPTR:
		rv = sndctl_dsp_getoptr(c, (count_info *)data);
		break;
	case SNDCTL_DSP_GETIPTR:
		rv = sndctl_dsp_getiptr(c, (count_info *)data);
		break;
	case SNDCTL_DSP_GETERROR:
		rv = sndctl_dsp_geterror(c, (audio_errinfo *)data);
		break;
	case SNDCTL_DSP_CURRENT_IPTR:
		rv = sndctl_dsp_current_iptr(c, (oss_count_t *)data);
		break;
	case SNDCTL_DSP_CURRENT_OPTR:
		rv = sndctl_dsp_current_optr(c, (oss_count_t *)data);
		break;

		/*
		 * Shared ioctls with /dev/mixer.
		 */
	case OSS_GETVERSION:
		rv = oss_getversion((int *)data);
		break;
	case SNDCTL_CARDINFO:
		rv = sndctl_cardinfo(c, (oss_card_info *)data);
		break;
	case SNDCTL_ENGINEINFO:
	case SNDCTL_AUDIOINFO:
	case SNDCTL_AUDIOINFO_EX:
		rv = sndctl_audioinfo(c, (oss_audioinfo *)data);
		break;
	case SNDCTL_SYSINFO:
		rv = sndctl_sysinfo((oss_sysinfo *)data);
		break;
	case SNDCTL_MIXERINFO:
		rv = sndctl_mixerinfo(c, (oss_mixerinfo *)data);
		break;
	case SOUND_MIXER_INFO:
		rv = sound_mixer_info(c, (mixer_info *)data);
		break;

		/*
		 * These are mixer ioctls that are virtualized for the DSP
		 * device.  They are accessible via either /dev/mixer or
		 * /dev/dsp.
		 */
	case SOUND_MIXER_READ_RECSRC:
	case SOUND_MIXER_WRITE_RECSRC:
		rv = sound_mixer_read_recsrc(c, (int *)data);
		break;

	case SOUND_MIXER_READ_DEVMASK:
	case SOUND_MIXER_READ_STEREODEVS:
		rv = sound_mixer_read_devmask(c, (int *)data);
		break;

	case SOUND_MIXER_READ_RECMASK:
		rv = sound_mixer_read_recmask(c, (int *)data);
		break;

	case SOUND_MIXER_READ_CAPS:
		rv = sound_mixer_read_caps(c, (int *)data);
		break;

		/*
		 * Ioctls we have chosen not to support for now.  Some
		 * of these are of legacy interest only.
		 */
	case SNDCTL_SETSONG:
	case SNDCTL_GETSONG:
	case SNDCTL_DSP_SYNCGROUP:
	case SNDCTL_DSP_SYNCSTART:
	case SNDCTL_DSP_GET_CHNORDER:
	case SNDCTL_DSP_SET_CHNORDER:
	case SNDCTL_DSP_GETIPEAKS:
	case SNDCTL_DSP_GETOPEAKS:
	case SNDCTL_DSP_GETCHANNELMASK:
	case SNDCTL_DSP_BIND_CHANNEL:
	case SNDCTL_DSP_SETSYNCRO:
	default:
		rv = EINVAL;
		break;
	}

	if ((rv == 0) && (cmd & OSSIOC_OUT)) {
		rv = ddi_copyout(data, (void *)arg, sz, mode);
	}
	if (rv == 0) {
		*rvalp = 0;
	}

done:
	if (sz) {
		kmem_free(data, sz);
	}
	return (rv);
}

static void
oss_output(audio_client_t *c)
{
	auclnt_pollwakeup(c, POLLOUT);
}

static void
oss_input(audio_client_t *c)
{
	auclnt_pollwakeup(c, POLLIN | POLLRDNORM);
}

static void
oss_notify(audio_client_t *c)
{
	audio_dev_t	*d;
	ossdev_t	*odev;

	d = auclnt_get_dev(c);
	if ((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) {
		return;
	}
	odev->d_modify_cnt++;
}

static int
ossmix_open(audio_client_t *c, int oflag)
{
	int		rv;
	ossclient_t	*sc;
	ossdev_t	*odev;

	_NOTE(ARGUNUSED(oflag));

	if ((rv = auclnt_open(c, AUDIO_FORMAT_NONE, 0)) != 0) {
		return (rv);
	}

	if ((sc = kmem_zalloc(sizeof (*sc), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}
	sc->o_ss_sz = 8192;
	if ((sc->o_ss_buf = kmem_zalloc(sc->o_ss_sz, KM_NOSLEEP)) == NULL) {
		kmem_free(sc, sizeof (*sc));
		return (ENOMEM);
	}
	auclnt_set_private(c, sc);

	odev = auclnt_get_minor_data(c, AUDIO_MINOR_DSP);

	/* set a couple of common fields */
	sc->o_client = c;
	sc->o_ossdev = odev;

	return (rv);
}

static void
ossmix_close(audio_client_t *c)
{
	ossclient_t	*sc;

	sc = auclnt_get_private(c);

	kmem_free(sc->o_ss_buf, sc->o_ss_sz);
	kmem_free(sc, sizeof (*sc));

	auclnt_close(c);
}

static int
sndctl_mix_nrext(audio_client_t *c, int *ncp)
{
	audio_dev_t	*d;
	ossdev_t	*odev;

	d = auclnt_get_dev(c);

	if ((*ncp != -1) && (*ncp != (auclnt_get_dev_index(d) - 1))) {
		return (ENXIO);
	}

	if ((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) {
		return (EINVAL);
	}

	*ncp = odev->d_nctrl;

	return (0);
}

static int
sndctl_mix_extinfo(audio_client_t *c, oss_mixext *pext)
{
	audio_dev_t		*d;
	ossdev_t		*odev;
	int			rv = 0;
	int			dev;

	d = auclnt_get_dev(c);

	if (((dev = pext->dev) != -1) && (dev != (auclnt_get_dev_index(d) - 1)))
		return (ENXIO);

	if (((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) ||
	    (pext->ctrl >= odev->d_nctrl)) {
		return (EINVAL);
	}

	bcopy(&odev->d_exts[pext->ctrl], pext, sizeof (*pext));
	pext->enumbit = 0;
	pext->dev = dev;

	return (rv);
}

static int
sndctl_mix_enuminfo(audio_client_t *c, oss_mixer_enuminfo *ei)
{
	audio_dev_t		*d;
	audio_ctrl_desc_t	desc;
	audio_ctrl_t		*ctrl;
	ossdev_t		*odev;
	uint64_t		mask;
	int			bit;
	ushort_t		nxt;

	d = auclnt_get_dev(c);

	if ((ei->dev != -1) && (ei->dev != (auclnt_get_dev_index(d) - 1)))
		return (ENXIO);

	if (((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) ||
	    (ei->ctrl >= odev->d_nctrl) ||
	    (odev->d_exts[ei->ctrl].type != MIXT_ENUM) ||
	    ((ctrl = odev->d_ctrls[ei->ctrl]) == NULL) ||
	    (auclnt_control_describe(ctrl, &desc) != 0)) {
		return (EINVAL);
	}

	mask = desc.acd_maxvalue;
	bit = 0;
	nxt = 0;
	ei->nvalues = 0;
	bzero(ei->strings, sizeof (ei->strings));
	bzero(ei->strindex, sizeof (ei->strindex));

	while (mask) {
		const char *name = desc.acd_enum[bit];
		nxt = oss_set_enum(ei, nxt, name ? name : "");
		mask >>= 1;
		bit++;
	}

	return (0);
}

static int
sndctl_mix_read(audio_client_t *c, oss_mixer_value *vr)
{
	int			rv;
	uint64_t		v;
	audio_dev_t		*d;
	audio_ctrl_t		*ctrl;
	ossdev_t		*odev;

	d = auclnt_get_dev(c);

	if ((vr->dev != -1) && (vr->dev != (auclnt_get_dev_index(d) - 1)))
		return (ENXIO);

	if (((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) ||
	    (vr->ctrl >= odev->d_nctrl) ||
	    ((ctrl = odev->d_ctrls[vr->ctrl]) == NULL)) {
		return (EINVAL);
	}
	if ((rv = auclnt_control_read(ctrl, &v)) == 0) {
		switch (odev->d_exts[vr->ctrl].type) {
		case MIXT_ENUM:
			/* translate this from an enum style bit mask */
			vr->value = ddi_ffs((unsigned long)v) - 1;
			break;
		case MIXT_STEREOSLIDER:
			vr->value = (int)ddi_swap16(v & 0xffff);
			break;
		case MIXT_MONOSLIDER:
			vr->value = (int)(v | (v << 8));
			break;
		case MIXT_ONOFF:
			/* this could be simple, or could be part of a multi */
			if (odev->d_exts[vr->ctrl].enumbit >= 0) {
				uint64_t mask;
				mask = 1;
				mask <<= (odev->d_exts[vr->ctrl].enumbit);
				vr->value = (v & mask) ? 1 : 0;
			} else {
				vr->value = v ? 1 : 0;
			}
			break;

		default:
			vr->value = (int)v;
			break;
		}
	}

	return (rv);
}

static int
sndctl_mix_write(audio_client_t *c, oss_mixer_value *vr)
{
	int			rv;
	uint64_t		v;
	audio_dev_t		*d;
	audio_ctrl_t		*ctrl;
	ossdev_t		*odev;

	d = auclnt_get_dev(c);

	if ((vr->dev != -1) && (vr->dev != (auclnt_get_dev_index(d) - 1)))
		return (ENXIO);

	if (((odev = auclnt_get_dev_minor_data(d, AUDIO_MINOR_DSP)) == NULL) ||
	    (vr->ctrl >= odev->d_nctrl) ||
	    ((ctrl = odev->d_ctrls[vr->ctrl]) == NULL)) {
		return (EINVAL);
	}

	switch (odev->d_exts[vr->ctrl].type) {
	case MIXT_ONOFF:
		/* this could be standalone, or it could be part of a multi */
		if (odev->d_exts[vr->ctrl].enumbit >= 0) {
			uint64_t mask;
			if ((rv = auclnt_control_read(ctrl, &v)) != 0) {
				return (EINVAL);
			}
			mask = 1;
			mask <<= (odev->d_exts[vr->ctrl].enumbit);
			if (vr->value) {
				v |= mask;
			} else {
				v &= ~mask;
			}
		} else {
			v = vr->value;
		}
		break;
	case MIXT_ENUM:
		/* translate this to an enum style bit mask */
		v = 1U << vr->value;
		break;
	case MIXT_MONOSLIDER:
		/* mask off high order bits */
		v = vr->value & 0xff;
		break;
	case MIXT_STEREOSLIDER:
		/* OSS uses reverse byte ordering */
		v = vr->value;
		v = ddi_swap16(vr->value & 0xffff);
		break;
	default:
		v = vr->value;
	}
	rv = auclnt_control_write(ctrl, v);

	return (rv);
}

static int
sndctl_mix_nrmix(audio_client_t *c, int *nmixp)
{
	_NOTE(ARGUNUSED(c));
	*nmixp = oss_cnt_devs() - 1;
	return (0);
}

static int
ossmix_ioctl(audio_client_t *c, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int	sz;
	void	*data;
	int	rv = 0;

	sz = OSSIOC_GETSZ(cmd);

	if ((cmd & (OSSIOC_IN | OSSIOC_OUT)) && sz) {
		if ((data = kmem_zalloc(sz, KM_NOSLEEP)) == NULL) {
			return (ENOMEM);
		}
	} else {
		sz = 0;
	}

	if (cmd & OSSIOC_IN) {
		if ((rv = ddi_copyin((void *)arg, data, sz, mode)) != 0) {
			goto done;
		}
	}

	switch (cmd) {
		/*
		 * Mixer specific ioctls
		 */
	case SNDCTL_MIX_NREXT:
		rv = sndctl_mix_nrext(c, (int *)data);
		break;
	case SNDCTL_MIX_EXTINFO:
		rv = sndctl_mix_extinfo(c, (oss_mixext *)data);
		break;
	case SNDCTL_MIX_ENUMINFO:
		rv = sndctl_mix_enuminfo(c, (oss_mixer_enuminfo *)data);
		break;
	case SNDCTL_MIX_READ:
		rv = sndctl_mix_read(c, (oss_mixer_value *)data);
		break;
	case SNDCTL_MIX_WRITE:
		rv = sndctl_mix_write(c, (oss_mixer_value *)data);
		break;
	case SNDCTL_MIX_NRMIX:
		rv = sndctl_mix_nrmix(c, (int *)data);
		break;

		/*
		 * Legacy ioctls.  These are treated as soft values only,
		 * and do not affect global hardware state.  For use by
		 * legacy DSP applications.
		 */
	case SOUND_MIXER_READ_VOLUME:
	case SOUND_MIXER_READ_PCM:
	case SOUND_MIXER_READ_OGAIN:
		rv = sndctl_dsp_getplayvol(c, (int *)data);
		break;

	case SOUND_MIXER_WRITE_VOLUME:
	case SOUND_MIXER_WRITE_PCM:
	case SOUND_MIXER_WRITE_OGAIN:
		rv = sound_mixer_write_ogain(c, (int *)data);
		break;

	case SOUND_MIXER_READ_RECGAIN:
	case SOUND_MIXER_READ_RECLEV:
	case SOUND_MIXER_READ_IGAIN:
		rv = sndctl_dsp_getrecvol(c, (int *)data);
		break;

	case SOUND_MIXER_WRITE_RECGAIN:
	case SOUND_MIXER_WRITE_RECLEV:
	case SOUND_MIXER_WRITE_IGAIN:
		rv = sound_mixer_write_igain(c, (int *)data);
		break;

	case SOUND_MIXER_READ_RECSRC:
	case SOUND_MIXER_WRITE_RECSRC:
		rv = sound_mixer_read_recsrc(c, (int *)data);
		break;

	case SOUND_MIXER_READ_DEVMASK:
	case SOUND_MIXER_READ_STEREODEVS:
		rv = sound_mixer_read_devmask(c, (int *)data);
		break;

	case SOUND_MIXER_READ_RECMASK:
		rv = sound_mixer_read_recmask(c, (int *)data);
		break;

		/*
		 * Common ioctls shared with DSP
		 */
	case OSS_GETVERSION:
		rv = oss_getversion((int *)data);
		break;

	case SNDCTL_CARDINFO:
		rv = sndctl_cardinfo(c, (oss_card_info *)data);
		break;

	case SNDCTL_ENGINEINFO:
	case SNDCTL_AUDIOINFO:
	case SNDCTL_AUDIOINFO_EX:
		rv = sndctl_audioinfo(c, (oss_audioinfo *)data);
		break;

	case SNDCTL_SYSINFO:
		rv = sndctl_sysinfo((oss_sysinfo *)data);
		break;

	case SNDCTL_MIXERINFO:
		rv = sndctl_mixerinfo(c, (oss_mixerinfo *)data);
		break;

	case SOUND_MIXER_INFO:
		rv = sound_mixer_info(c, (mixer_info *)data);
		break;

	case SNDCTL_MIX_DESCRIPTION:	/* NOT SUPPORTED: tooltip */
		rv = EIO;	/* OSS returns EIO for this one */
		break;

		/*
		 * Special implementation-private ioctls.
		 */
	case SNDCTL_SUN_SEND_NUMBER:
		rv = sndctl_sun_send_number(c, (int *)data, credp);
		break;

		/*
		 * Legacy ioctls we don't support.
		 */
	case SOUND_MIXER_WRITE_MONGAIN:
	case SOUND_MIXER_READ_MONGAIN:
	case SOUND_MIXER_READ_BASS:
	case SOUND_MIXER_READ_TREBLE:
	case SOUND_MIXER_READ_SPEAKER:
	case SOUND_MIXER_READ_LINE:
	case SOUND_MIXER_READ_MIC:
	case SOUND_MIXER_READ_CD:
	case SOUND_MIXER_READ_IMIX:
	case SOUND_MIXER_READ_ALTPCM:
	case SOUND_MIXER_READ_SYNTH:
	case SOUND_MIXER_READ_LINE1:
	case SOUND_MIXER_READ_LINE2:
	case SOUND_MIXER_READ_LINE3:
	case SOUND_MIXER_WRITE_BASS:
	case SOUND_MIXER_WRITE_TREBLE:
	case SOUND_MIXER_WRITE_SPEAKER:
	case SOUND_MIXER_WRITE_LINE:
	case SOUND_MIXER_WRITE_MIC:
	case SOUND_MIXER_WRITE_CD:
	case SOUND_MIXER_WRITE_IMIX:
	case SOUND_MIXER_WRITE_ALTPCM:
	case SOUND_MIXER_WRITE_SYNTH:
	case SOUND_MIXER_WRITE_LINE1:
	case SOUND_MIXER_WRITE_LINE2:
	case SOUND_MIXER_WRITE_LINE3:
		/*
		 * Additional ioctls we *could* support, but don't.
		 */
	case SNDCTL_SETSONG:
	case SNDCTL_SETLABEL:
	case SNDCTL_GETSONG:
	case SNDCTL_GETLABEL:
	case SNDCTL_MIDIINFO:
	case SNDCTL_SETNAME:
	default:
		rv = EINVAL;
		break;
	}

	if ((rv == 0) && (cmd & OSSIOC_OUT)) {
		rv = ddi_copyout(data, (void *)arg, sz, mode);
	}
	if (rv == 0) {
		*rvalp = 0;
	}

done:
	if (sz) {
		kmem_free(data, sz);
	}
	return (rv);
}

static void *
oss_dev_init(audio_dev_t *dev)
{
	ossdev_t	*odev;

	odev = kmem_zalloc(sizeof (*odev), KM_SLEEP);
	odev->d_dev = dev;

	mutex_init(&odev->d_mx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&odev->d_cv, NULL, CV_DRIVER, NULL);
	oss_alloc_controls(odev);

	return (odev);
}

static void
oss_dev_fini(void *arg)
{
	ossdev_t	*odev = arg;

	if (odev != NULL) {
		oss_free_controls(odev);
		mutex_destroy(&odev->d_mx);
		cv_destroy(&odev->d_cv);
		kmem_free(odev, sizeof (*odev));
	}
}

static void
sndstat_printf(ossclient_t *oc, const char *fmt, ...)
{
	va_list	va;

	va_start(va, fmt);
	(void) vsnprintf(oc->o_ss_buf + oc->o_ss_len,
	    oc->o_ss_sz - oc->o_ss_len, fmt, va);
	va_end(va);
	oc->o_ss_len = strlen(oc->o_ss_buf);
}

static int
sndstat_dev_walker(audio_dev_t *d, void *arg)
{
	ossclient_t	*oc = arg;
	const char	*capstr;
	unsigned	cap;

	cap = auclnt_get_dev_capab(d);

	if (cap	& AUDIO_CLIENT_CAP_DUPLEX) {
		capstr = "DUPLEX";
	} else if ((cap & AUDIO_CLIENT_CAP_PLAY) &&
	    (cap & AUDIO_CLIENT_CAP_RECORD)) {
		capstr = "INPUT,OUTPUT";
	} else if (cap & AUDIO_CLIENT_CAP_PLAY) {
		capstr = "OUTPUT";
	} else if (cap & AUDIO_CLIENT_CAP_RECORD) {
		capstr = "INPUT";
	} else {
		capstr = NULL;
	}

	if (capstr == NULL)
		return (AUDIO_WALK_CONTINUE);

	sndstat_printf(oc, "%d: %s %s, %s (%s)\n",
	    auclnt_get_dev_number(d), auclnt_get_dev_name(d),
	    auclnt_get_dev_description(d), auclnt_get_dev_version(d), capstr);

	return (AUDIO_WALK_CONTINUE);
}

static int
sndstat_mixer_walker(audio_dev_t *d, void *arg)
{
	ossclient_t	*oc = arg;
	unsigned	cap;
	void		*iter;
	const char	*info;

	cap = auclnt_get_dev_capab(d);

	if ((cap & (AUDIO_CLIENT_CAP_PLAY|AUDIO_CLIENT_CAP_RECORD)) == 0)
		return (AUDIO_WALK_CONTINUE);

	sndstat_printf(oc, "%d: %s %s, %s\n",
	    auclnt_get_dev_number(d), auclnt_get_dev_name(d),
	    auclnt_get_dev_description(d), auclnt_get_dev_version(d));
	iter = NULL;
	while ((info = auclnt_get_dev_hw_info(d, &iter)) != NULL) {
		sndstat_printf(oc, "\t%s\n", info);
	}
	return (AUDIO_WALK_CONTINUE);
}

static int
ossmix_write(audio_client_t *c, struct uio *uio, cred_t *cr)
{
	/* write on sndstat is a no-op */
	_NOTE(ARGUNUSED(c));
	_NOTE(ARGUNUSED(uio));
	_NOTE(ARGUNUSED(cr));

	return (0);
}

static int
ossmix_read(audio_client_t *c, struct uio *uio, cred_t *cr)
{
	ossclient_t	*oc;
	unsigned	n;
	int		rv;

	_NOTE(ARGUNUSED(cr));

	if (uio->uio_resid == 0) {
		return (0);
	}

	oc = auclnt_get_private(c);

	mutex_enter(&oc->o_ss_lock);

	if (oc->o_ss_off == 0) {

		sndstat_printf(oc, "SunOS Audio Framework\n");

		sndstat_printf(oc, "\nAudio Devices:\n");
		auclnt_walk_devs_by_number(sndstat_dev_walker, oc);

		sndstat_printf(oc, "\nMixers:\n");
		auclnt_walk_devs_by_number(sndstat_mixer_walker, oc);
	}

	/*
	 * For simplicity's sake, we implement a non-seekable device.  We could
	 * support seekability, but offsets would be rather meaningless between
	 * changes.
	 */
	n = min(uio->uio_resid, (oc->o_ss_len - oc->o_ss_off));

	rv = uiomove(oc->o_ss_buf + oc->o_ss_off, n, UIO_READ, uio);
	if (rv != 0) {
		n = 0;
	}
	oc->o_ss_off += n;

	if (n == 0) {
		/*
		 * end-of-file reached... clear the sndstat buffer so that
		 * subsequent reads will get the latest data.
		 */
		oc->o_ss_off = oc->o_ss_len = 0;
	}
	mutex_exit(&oc->o_ss_lock);
	return (rv);
}

int
oss_read(audio_client_t *c, struct uio *uio, cred_t *cr)
{
	_NOTE(ARGUNUSED(cr));

	auclnt_clear_paused(auclnt_input_stream(c));

	return (auclnt_read(c, uio));
}

int
oss_write(audio_client_t *c, struct uio *uio, cred_t *cr)
{
	_NOTE(ARGUNUSED(cr));

	auclnt_clear_paused(auclnt_output_stream(c));

	return (auclnt_write(c, uio));
}

int
oss_chpoll(audio_client_t *c, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	return (auclnt_chpoll(c, events, anyyet, reventsp, phpp));
}

static struct audio_client_ops oss_ops = {
	"sound,dsp",
	oss_dev_init,
	oss_dev_fini,
	oss_open,
	oss_close,
	oss_read,
	oss_write,
	oss_ioctl,
	oss_chpoll,
	NULL,		/* mmap */
	oss_input,
	oss_output,
	NULL,		/* notify */
	NULL,		/* drain */
};

static struct audio_client_ops ossmix_ops = {
	"sound,mixer",
	NULL,
	NULL,
	ossmix_open,
	ossmix_close,
	ossmix_read,
	ossmix_write,
	ossmix_ioctl,
	NULL,	/* chpoll */
	NULL,   /* mmap */
	NULL,	/* input */
	NULL,   /* output */
	oss_notify,
	NULL,	/* drain */
	NULL,	/* wput */
	NULL,	/* wsrv */
};

/* nearly the same as ossxmix; different minor name helps devfsadm */
static struct audio_client_ops sndstat_ops = {
	"sound,sndstat",
	NULL,	/* dev_init */
	NULL,	/* dev_fini */
	ossmix_open,
	ossmix_close,
	ossmix_read,
	ossmix_write,
	ossmix_ioctl,
	NULL,	/* chpoll */
	NULL,	/* mmap */
	NULL,	/* input */
	NULL,	/* output */
	NULL,	/* notify */
	NULL,	/* drain */
	NULL,	/* wput */
	NULL,	/* wsrv */
};

void
auimpl_oss_init(void)
{
	auclnt_register_ops(AUDIO_MINOR_DSP, &oss_ops);
	auclnt_register_ops(AUDIO_MINOR_MIXER, &ossmix_ops);
	auclnt_register_ops(AUDIO_MINOR_SNDSTAT, &sndstat_ops);
}
