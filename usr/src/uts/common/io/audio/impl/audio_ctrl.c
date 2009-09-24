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
#include <sys/list.h>
#include <sys/sysmacros.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/atomic.h>

#include "audio_impl.h"

/*
 * Audio Control functions.
 */

/*
 * Given a control structure - free all names
 * strings allocated to it.
 *
 * ctrl             - The control who's names that will be free'd.
 */
static void
audio_control_freenames(audio_ctrl_t *ctrl)
{
	int	indx;

	if (ctrl->ctrl_name != NULL)
		strfree((char *)ctrl->ctrl_name);
	ctrl->ctrl_name = NULL;

	for (indx = 0; indx < 64; indx++) {
		if (ctrl->ctrl_enum[indx] != NULL) {
			strfree((char *)ctrl->ctrl_enum[indx]);
			ctrl->ctrl_enum[indx] = NULL;
		}
	}
}

/*
 * This will allocate and register a control for my audio device.
 *
 * d                - The audio device the control will be attached to.
 * desc             - Attributes about this new control
 * read_fn          - Callback function in driver to read control
 * write_fn         - Callback function in driver to write control.
 * arg              - driver private context passed to read_fn/write_fn
 *
 * On success this will return a control structure else NULL.
 *
 * The value passed in for a control number in the audio_ctrl_desc_t
 * has some special meaning. If it is less then AUDIO_CONTROL_EXTBASE
 * then the control is assumed to be a known control. If it is
 * AUDIO_CONTROL_EXTBASE then the framework will allocate a unique
 * control number and replace it in the audio_ctrl_desc_t structure
 * and this control is considered an extended driver private control.
 * The number that is replaced in audio_ctrl_desc_t will be greater
 * then AUDIO_CONTROL_EXTBASE.
 *
 */
audio_ctrl_t *
audio_dev_add_control(audio_dev_t *d, audio_ctrl_desc_t *desc,
    audio_ctrl_rd_t read_fn, audio_ctrl_wr_t write_fn, void *arg)
{
	audio_ctrl_t *ctrl;
	audio_ctrl_desc_t *new_desc;
	char	scratch[16];
	const char	*name;

	/* Verify arguments */
	ASSERT(d);
	ASSERT(desc);

	/* We cannot deal with unnamed controls */
	if ((name = desc->acd_name) == NULL) {
		return (NULL);
	}

	/*
	 * If this was called with a control name that was already
	 * added, then we do some special things. First we reuse the
	 * control audio_ctrl_t and as far as outside users are
	 * concerned the handle is reused. To users this looks like we
	 * are changing the controls attributes. But what we really do
	 * is free every thing allocated to the control and then
	 * reinit everything.  That way the same code can get used for
	 * both.
	 *
	 * We verify anything that could fail before we change the
	 * control or commit to any changes. If there is something bad
	 * return null to indicate an error but the original control
	 * is still usable and untouched.
	 */
	ctrl = auclnt_find_control(d, name);

	if (ctrl == NULL) {
		/* Allocate a new control */
		ctrl = kmem_zalloc(sizeof (*ctrl), KM_SLEEP);
	} else {
		/* Re-configure an existing control */
		switch (desc->acd_type) {
		case AUDIO_CTRL_TYPE_BOOLEAN:
		case AUDIO_CTRL_TYPE_STEREO:
		case AUDIO_CTRL_TYPE_MONO:
		case AUDIO_CTRL_TYPE_METER:
		case AUDIO_CTRL_TYPE_ENUM:
			break;
		default:
			audio_dev_warn(d, "bad control type %d for %s "
			    "not replaced", desc->acd_type, desc->acd_name);
			return (NULL);
		}

		/*
		 * By removing it from the list we prevent the need to lock
		 * and check for locks on the control itself.
		 * Also by doing this we can use the normal add code to do
		 * what it normally does below.
		 */
		rw_enter(&d->d_ctrl_lock, RW_WRITER);
		list_remove(&d->d_controls, ctrl);
		rw_exit(&d->d_ctrl_lock);

		audio_control_freenames(ctrl);
		ctrl->ctrl_read_fn = NULL;
		ctrl->ctrl_write_fn = NULL;
		ctrl->ctrl_arg = NULL;
		ctrl->ctrl_dev = NULL;
		mutex_destroy(&ctrl->ctrl_lock);
	}
	new_desc = &ctrl->ctrl_des;

	/* Fill in new control description */
	new_desc->acd_type = desc->acd_type;
	new_desc->acd_flags = desc->acd_flags;
	new_desc->acd_maxvalue = desc->acd_maxvalue;
	new_desc->acd_minvalue = desc->acd_minvalue;
	new_desc->acd_name = strdup(name);

	/* Process type of control special actions, if any */
	switch (desc->acd_type) {
	case AUDIO_CTRL_TYPE_BOOLEAN:
	case AUDIO_CTRL_TYPE_STEREO:
	case AUDIO_CTRL_TYPE_MONO:
	case AUDIO_CTRL_TYPE_METER:
		break;

	case AUDIO_CTRL_TYPE_ENUM:
		for (int bit = 0; bit < 64; bit++) {
			if (((1U << bit) & desc->acd_maxvalue) == 0)
				continue;
			name = desc->acd_enum[bit];
			if (name == NULL) {
				(void) snprintf(scratch, sizeof (scratch),
				    "bit%d", bit);
				name = scratch;
			}
			new_desc->acd_enum[bit] = strdup(name);
		}
		break;
	default:
		audio_dev_warn(d, "bad control type %d for %s",
		    desc->acd_type, desc->acd_name);
		goto ctrl_fail;
	}

	ctrl->ctrl_dev = d;
	if (new_desc->acd_flags & AUDIO_CTRL_FLAG_READABLE) {
		ASSERT(read_fn);
		ctrl->ctrl_read_fn = read_fn;
		ctrl->ctrl_arg = arg;
	}
	if (new_desc->acd_flags & AUDIO_CTRL_FLAG_WRITEABLE) {
		ASSERT(write_fn);
		ctrl->ctrl_write_fn = write_fn;
		ctrl->ctrl_arg = arg;
	}

	mutex_init(&ctrl->ctrl_lock, NULL, MUTEX_DRIVER, NULL);

	rw_enter(&d->d_ctrl_lock, RW_WRITER);
	list_insert_tail(&d->d_controls, ctrl);
	rw_exit(&d->d_ctrl_lock);

	return (ctrl);


ctrl_fail:
	if (ctrl) {
		audio_control_freenames(ctrl);
		kmem_free(ctrl, sizeof (*ctrl));
	}
	return (NULL);
}

/*
 * This will remove a control from my audio device.
 *
 * ctrl             - The control will be removed.
 */
void
audio_dev_del_control(audio_ctrl_t *ctrl)
{
	audio_dev_t *d;

	/* Verify argument */
	ASSERT(ctrl);
	d = ctrl->ctrl_dev;
	ASSERT(d);

	rw_enter(&d->d_ctrl_lock, RW_WRITER);
	list_remove(&d->d_controls, ctrl);
	rw_exit(&d->d_ctrl_lock);

	mutex_destroy(&ctrl->ctrl_lock);

	audio_control_freenames(ctrl);
	kmem_free(ctrl, sizeof (*ctrl));
}

int
audio_dev_add_soft_volume(audio_dev_t *d)
{
	audio_ctrl_desc_t	desc;

	bzero(&desc, sizeof (desc));
	if (d->d_pcmvol_ctrl == NULL) {
		desc.acd_name = AUDIO_CTRL_ID_VOLUME;
		desc.acd_type = AUDIO_CTRL_TYPE_MONO;
		desc.acd_minvalue = 0;
		desc.acd_maxvalue = 100;
		desc.acd_flags = AUDIO_CTRL_FLAG_RW | AUDIO_CTRL_FLAG_PLAY |
		    AUDIO_CTRL_FLAG_PCMVOL;
		d->d_pcmvol_ctrl = audio_dev_add_control(d, &desc,
		    auimpl_get_pcmvol, auimpl_set_pcmvol, d);
		d->d_pcmvol = 75;
	}
	return (0);
}

/*
 * This will notify clients of need to reread control
 * values since they have changed.
 *
 * There will be a routine that allows a client to register
 * a callback.   For now we just update the serial number.
 *
 * d                - The device that needs updates.
 */
void
audio_dev_update_controls(audio_dev_t *d)
{
	atomic_inc_uint(&d->d_serial);
}


/*
 * This is used to read the current value of a control.
 * Note, this will cause a callback into the driver to get the value.
 *
 * ctrl        - should be the valid control being read.
 * value       - is a pointer to the place that will contain the value read.
 *
 * On return zero is returned on success else errno is returned.
 *
 */
int
audio_control_read(audio_ctrl_t *ctrl, uint64_t *value)
{
	uint64_t my_value;
	int ret;

	/* Verify arguments */
	ASSERT(ctrl);
	ASSERT(value);
	ASSERT(ctrl->ctrl_dev);

	if (!(ctrl->ctrl_flags & AUDIO_CTRL_FLAG_READABLE)) {
		return (ENXIO);
	}

	ASSERT(ctrl->ctrl_read_fn);

	if ((ret = ctrl->ctrl_read_fn(ctrl->ctrl_arg, &my_value)) != 0) {
		return (ret);
	}

	*value = my_value;

	return (ret);
}

/*
 * This is used to write a value to a control.
 * Note, this will cause a callback into the driver to write the value.
 *
 * ctrl        - should be the valid control being written.
 * value       - is value to set the control to.
 *
 * On return zero is returned on success else errno is returned.
 *
 */
int
audio_control_write(audio_ctrl_t *ctrl, uint64_t value)
{
	int		ret;
	audio_dev_t	*d = ctrl->ctrl_dev;

	/* Verify arguments */
	ASSERT(ctrl);
	ASSERT(d);

	if (!(ctrl->ctrl_flags & AUDIO_CTRL_FLAG_WRITEABLE)) {
		return (ENXIO);
	}

	ASSERT(ctrl->ctrl_write_fn);

	ret = ctrl->ctrl_write_fn(ctrl->ctrl_arg, value);

	if (ret == 0)
		audio_dev_update_controls(d);

	return (ret);
}
