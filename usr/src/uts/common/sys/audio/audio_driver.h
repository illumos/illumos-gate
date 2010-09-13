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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_AUDIO_AUDIO_DRIVER_H
#define	_SYS_AUDIO_AUDIO_DRIVER_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio/audio_common.h>


#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

struct audio_engine_ops {
	int	audio_engine_version;
#define	AUDIO_ENGINE_VERSION	2

	/*
	 * Initialize engine, including buffer allocation.  Arguments
	 * that are pointers are hints.  On return, they are updated with
	 * the actual values configured by the driver.
	 */
	int	(*audio_engine_open)(void *, int, uint_t *, caddr_t *);
	void	(*audio_engine_close)(void *);

	/*
	 * Start and stop are used to actually get the hardware running
	 * or stop the hardware.  Until this is kicked off, the engine
	 * will not actually transfer data.  These are not destructive to
	 * ring positions, etc.  (Think of it like pause/play).
	 */
	int	(*audio_engine_start)(void *);
	void	(*audio_engine_stop)(void *);

	/*
	 * Obtain the engine offset.  Offsets start at zero at engine_open,
	 * and keep counting upwards.  Count is returned in frames.
	 */
	uint64_t	(*audio_engine_count)(void *);

	/*
	 * The following entry points return the currently configured
	 * status of the engine.  It is assumed that the engine's
	 * configuration is relatively fixed, and does not change
	 * while open, or in response to open.
	 *
	 * However, in the future we might like to allow for the
	 * device to change the settings while it is not open, which
	 * could allow for mixerctl to change the configured channels,
	 * for example.  In order to synchronize this properly, we'll
	 * need the engine to perform a notification/request.  That
	 * will be added later.
	 *
	 * AC3: We will have to figure out how to support dynamically
	 * selecting different sampling frequencies for AC3, since
	 * it needs to be able to support 32, 44.1, and 48 kHz.
	 * Perhaps special flags used during open() would do the trick.
	 */
	int	(*audio_engine_format)(void *);
	int	(*audio_engine_channels)(void *);
	int	(*audio_engine_rate)(void *);

	/*
	 * DMA cache synchronization.  The framework does this on
	 * behalf of the driver for both input and output.  The driver
	 * is responsible for tracking the direction (based on the
	 * flags passed to ae_open()), and dealing with any partial
	 * synchronization if any is needed.
	 */
	void	(*audio_engine_sync)(void *, uint_t);

	/*
	 * The framework may like to know how deep the device queues data.
	 * This can be used to provide a more accurate latency calculation.
	 */
	uint_t	(*audio_engine_qlen)(void *);

	/*
	 * If the driver doesn't use simple interleaving, then we need to
	 * know more about the offsets of channels within the buffer.
	 * We obtain both the starting offset within the buffer, and the
	 * increment for each new sample.  As usual, these are given in
	 * samples.  If this entry point is NULL, the framework assumes
	 * that simple interlevaing is used instead.
	 */
	void	(*audio_engine_chinfo)(void *, int chan, uint_t *offset,
	    uint_t *incr);

	/*
	 * The following entry point is used to determine the play ahead
	 * desired by the engine.  Engines with less consistent scheduling,
	 * or with a need for deeper queuing, implement this.  If not
	 * implemented, the framework assumes 1.5 * fragfr.
	 */
	uint_t	(*audio_engine_playahead)(void *);
};

/*
 * Drivers call these.
 */
void audio_init_ops(struct dev_ops *, const char *);
void audio_fini_ops(struct dev_ops *);

audio_dev_t *audio_dev_alloc(dev_info_t *, int);
void audio_dev_free(audio_dev_t *);

void audio_dev_set_description(audio_dev_t *, const char *);
void audio_dev_set_version(audio_dev_t *, const char *);
void audio_dev_add_info(audio_dev_t *, const char *);

audio_engine_t *audio_engine_alloc(audio_engine_ops_t *, uint_t);
void audio_engine_set_private(audio_engine_t *, void *);
void *audio_engine_get_private(audio_engine_t *);
void audio_engine_free(audio_engine_t *);

void audio_dev_add_engine(audio_dev_t *, audio_engine_t *);
void audio_dev_remove_engine(audio_dev_t *, audio_engine_t *);
int audio_dev_register(audio_dev_t *);
int audio_dev_unregister(audio_dev_t *);
void audio_dev_suspend(audio_dev_t *);
void audio_dev_resume(audio_dev_t *);
void audio_dev_warn(audio_dev_t *, const char *, ...);

/* DEBUG ONLY */
void audio_dump_bytes(const uint8_t *w, int dcount);
void audio_dump_words(const uint16_t *w, int dcount);
void audio_dump_dwords(const uint32_t *w, int dcount);


/* Engine flags */
#define	ENGINE_OUTPUT_CAP	(1U << 2)
#define	ENGINE_INPUT_CAP	(1U << 3)
#define	ENGINE_CAPS		(ENGINE_OUTPUT_CAP | ENGINE_INPUT_CAP)
#define	ENGINE_DRIVER_FLAGS	(0xffff)	/* flags usable by driver */

#define	ENGINE_OUTPUT		(1U << 16)	/* fields not for driver use */
#define	ENGINE_INPUT		(1U << 17)
#define	ENGINE_EXCLUSIVE	(1U << 20)	/* exclusive use, e.g. AC3 */
#define	ENGINE_NDELAY		(1U << 21)	/* non-blocking open */

/*
 * entry points used by legacy SADA drivers
 */
int audio_legacy_open(queue_t *, dev_t *, int, int, cred_t *);
int audio_legacy_close(queue_t *, int, cred_t *);
int audio_legacy_wput(queue_t *, mblk_t *);
int audio_legacy_wsrv(queue_t *);



/*
 * Audio device controls
 */

/*
 * Control read or write driver function type.
 *
 * Returns zero on success, errno on failure.
 */
typedef int (*audio_ctrl_wr_t)(void *, uint64_t);
typedef int (*audio_ctrl_rd_t)(void *, uint64_t *);


/*
 * This will allocate and register a control for my audio device.
 *
 * On success this will return a control structure else NULL.
 */
audio_ctrl_t *audio_dev_add_control(audio_dev_t *,
    audio_ctrl_desc_t *, audio_ctrl_rd_t, audio_ctrl_wr_t, void *);

/*
 * Add a synthetic PCM volume control.  This should only be used by
 * devices which have no physical PCM volume controls.  The control
 * implements a simple attenuator on the PCM data; unlike AC'97 there
 * is no "gain", so using this instead of a hardware control may
 * result in loss range.  The control is implemented using
 * AUDIO_CTRL_ID_VOLUME.
 */
void audio_dev_add_soft_volume(audio_dev_t *);

/*
 * This will remove a control from an audio device.
 */
void audio_dev_del_control(audio_ctrl_t *);

/*
 * This will tell the framework that controls have changed
 * and it should update its values.
 */
void audio_dev_update_controls(audio_dev_t *);

/*
 * This is used to read the current value of a control.
 * Note, this will cause a callback into the driver to get the value.
 *
 * On return zero is returned on success else errno is returned.
 */
int audio_control_read(audio_ctrl_t *, uint64_t *);

/*
 * This is used to write a value to a control.
 * Note, this will cause a callback into the driver to write the value.
 *
 * On return zero is returned on success else errno is returned.
 */
int audio_control_write(audio_ctrl_t *, uint64_t);

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_AUDIO_AUDIO_DRIVER_H */
