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

#ifndef	_AUDIO_CLIENT_H
#define	_AUDIO_CLIENT_H

/*
 * Structure implementation in audio_impl.h
 */
#include <sys/audio/audio_common.h>

typedef struct audio_client_ops {
	const char	*aco_minor_prefix;
	void		*(*aco_dev_init)(audio_dev_t *);
	void		(*aco_dev_fini)(void *);
	int		(*aco_open)(audio_client_t *, int);
	void		(*aco_close)(audio_client_t *);
	int		(*aco_read)(audio_client_t *, struct uio *, cred_t *);
	int		(*aco_write)(audio_client_t *, struct uio *, cred_t *);
	int		(*aco_ioctl)(audio_client_t *, int, intptr_t, int,
			    cred_t *, int *);
	int		(*aco_chpoll)(audio_client_t *, short, int, short *,
			    struct pollhead **);
	int		(*aco_mmap)(audio_client_t *, ...);
	void		(*aco_input)(audio_client_t *);
	void		(*aco_output)(audio_client_t *);
	void		(*aco_notify)(audio_client_t *);
	void		(*aco_drain)(audio_client_t *);

	void		(*aco_wput)(audio_client_t *, mblk_t *);
	void		(*aco_wsrv)(audio_client_t *);
} audio_client_ops_t;

void *auclnt_get_private(audio_client_t *);
void auclnt_set_private(audio_client_t *, void *);

int auclnt_drain(audio_client_t *);
int auclnt_start_drain(audio_client_t *);

int auclnt_set_rate(audio_stream_t *, int);
int auclnt_get_rate(audio_stream_t *);

int auclnt_set_format(audio_stream_t *, int);
int auclnt_get_format(audio_stream_t *);

int auclnt_set_channels(audio_stream_t *, int);
int auclnt_get_channels(audio_stream_t *);

void auclnt_set_gain(audio_stream_t *, uint8_t);
uint8_t auclnt_get_gain(audio_stream_t *);

void auclnt_set_muted(audio_stream_t *, boolean_t);
boolean_t auclnt_get_muted(audio_stream_t *);

uint64_t auclnt_get_samples(audio_stream_t *);
void auclnt_set_samples(audio_stream_t *, uint64_t);

uint64_t auclnt_get_errors(audio_stream_t *);
void auclnt_set_errors(audio_stream_t *, uint64_t);

uint64_t auclnt_get_eof(audio_stream_t *);
void auclnt_set_eof(audio_stream_t *, uint64_t);

boolean_t auclnt_is_running(audio_stream_t *);
void auclnt_start(audio_stream_t *);
void auclnt_stop(audio_stream_t *);

void auclnt_set_paused(audio_stream_t *);
void auclnt_clear_paused(audio_stream_t *);
boolean_t auclnt_is_paused(audio_stream_t *);

void auclnt_flush(audio_stream_t *);

void auclnt_get_output_qlen(audio_client_t *, unsigned *, unsigned *);

unsigned auclnt_get_fragsz(audio_stream_t *);
unsigned auclnt_get_framesz(audio_stream_t *);
unsigned auclnt_get_nfrags(audio_stream_t *);
unsigned auclnt_get_nframes(audio_stream_t *);
unsigned auclnt_get_count(audio_stream_t *);
uint64_t auclnt_get_head(audio_stream_t *);
uint64_t auclnt_get_tail(audio_stream_t *);
unsigned auclnt_get_hidx(audio_stream_t *);
unsigned auclnt_get_tidx(audio_stream_t *);

void auclnt_set_latency(audio_stream_t *, unsigned, unsigned);

audio_stream_t *auclnt_input_stream(audio_client_t *);
audio_stream_t *auclnt_output_stream(audio_client_t *);

int auclnt_get_oflag(audio_client_t *);

int auclnt_open(audio_client_t *, unsigned, int);
void auclnt_close(audio_client_t *);

void auclnt_register_ops(minor_t, audio_client_ops_t *);

minor_t	auclnt_get_minor(audio_client_t *);
minor_t auclnt_get_original_minor(audio_client_t *);
minor_t auclnt_get_minor_type(audio_client_t *);
queue_t *auclnt_get_rq(audio_client_t *);
queue_t *auclnt_get_wq(audio_client_t *);

unsigned auclnt_produce(audio_stream_t *, unsigned);
unsigned auclnt_produce_data(audio_stream_t *, caddr_t, unsigned);
unsigned auclnt_consume(audio_stream_t *, unsigned);
unsigned auclnt_consume_data(audio_stream_t *, caddr_t, unsigned);
int auclnt_read(audio_client_t *, struct uio *);
int auclnt_write(audio_client_t *, struct uio *);
int auclnt_chpoll(audio_client_t *, short, int, short *, struct pollhead **);
void auclnt_pollwakeup(audio_client_t *, short);

/*
 * Return the process id that performed the original open() of the client.
 */
pid_t auclnt_get_pid(audio_client_t *);

/*
 * Return the credentials of the process that opened the client.
 */
cred_t *auclnt_get_cred(audio_client_t *);

/*
 * Get an opaque handle the underlying device for an audio client.
 */
audio_dev_t *auclnt_get_dev(audio_client_t *);
audio_dev_t *auclnt_hold_dev_by_index(int);
void auclnt_release_dev(audio_dev_t *);
void auclnt_notify_dev(audio_dev_t *);
int auclnt_get_dev_index(audio_dev_t *);
int auclnt_get_dev_number(audio_dev_t *);
void auclnt_set_dev_number(audio_dev_t *, int);
const char *auclnt_get_dev_name(audio_dev_t *);
const char *auclnt_get_dev_driver(audio_dev_t *);
dev_info_t *auclnt_get_dev_devinfo(audio_dev_t *);
int auclnt_get_dev_instance(audio_dev_t *);
const char *auclnt_get_dev_description(audio_dev_t *);
const char *auclnt_get_dev_version(audio_dev_t *);
const char *auclnt_get_dev_hw_info(audio_dev_t *, void **);
unsigned auclnt_get_dev_capab(audio_dev_t *);
#define	AUDIO_CLIENT_CAP_PLAY		(1U << 0)
#define	AUDIO_CLIENT_CAP_RECORD		(1U << 1)
#define	AUDIO_CLIENT_CAP_DUPLEX		(1U << 2)
#define	AUDIO_CLIENT_CAP_SNDSTAT	(1U << 3)
#define	AUDIO_CLIENT_CAP_OPAQUE		(1U << 4)

/*
 * Walk all the open client structures for a named audio device.
 * Clients can use this to find "peer" clients accessing the same
 * audio device.  (This is useful for implementing special linkages,
 * e.g. between /dev/audio and /dev/audioctl.)
 */
void auclnt_dev_walk_clients(audio_dev_t *,
    int (*)(audio_client_t *, void *), void *);

/*
 * Audio control functions for use by clients.
 */

/*
 * This will walk all controls registered to my device and callback
 * to walker for each one with its audio_ctrl_desc_t..
 *
 * Note that walk_func may return values to continue (AUDIO_WALK_CONTINUE)
 * or stop walk (AUDIO_WALK_STOP).
 *
 */
void auclnt_walk_controls(audio_dev_t *,
    int (*)(audio_ctrl_t *, void *), void *);

/*
 * This will search all controls attached to a clients
 * audio device for a control with the desired name.
 *
 * On successful return a ctrl handle will be returned. On
 * failure NULL is returned.
 */
audio_ctrl_t *auclnt_find_control(audio_dev_t *, const char *);

/*
 * Given a known control, get its attributes.
 *
 * The caller must supply a audio_ctrl_desc_t structure.  Also the
 * values in the structure are ignored when making the call and filled
 * in by this function.
 *
 * If an error occurs then a non-zero is returned.
 */
int auclnt_control_describe(audio_ctrl_t *, audio_ctrl_desc_t *);


/*
 * This is used to read the current value of a control.
 * Note, this will cause a callback into the driver to get the value.
 *
 * On return zero is returned on success else errno is returned.
 */
int auclnt_control_read(audio_ctrl_t *, uint64_t *);

/*
 * This is used to write a value to a control.
 * Note, this will cause a callback into the driver to write the value.
 *
 * On return zero is returned on success else errno is returned.
 *
 */
int auclnt_control_write(audio_ctrl_t *, uint64_t);

/*
 * Walk all the audio devices on the system.  Useful for clients
 * like sndstat, which may need to inquire about every audio device
 * on the system.
 */
void auclnt_walk_devs(int (*walker)(audio_dev_t *, void *), void *);
void auclnt_walk_devs_by_number(int (*walker)(audio_dev_t *, void *), void *);

audio_client_t *auclnt_hold_by_devt(dev_t);
void auclnt_release(audio_client_t *);

/*
 * Engine rlated accesses.  Note that normally clients don't need this level
 * of information.
 */
void auclnt_dev_walk_engines(audio_dev_t *,
    int (*)(audio_engine_t *, void *), void *);
int auclnt_engine_get_format(audio_engine_t *);
int auclnt_engine_get_rate(audio_engine_t *);
int auclnt_engine_get_channels(audio_engine_t *);
unsigned auclnt_engine_get_capab(audio_engine_t *);

/*
 * Retrieve minor-specific data for the instance.  This allows for
 * personality modules to store persistent state data on a physical
 * device (e.g. to store persistent settings.)  Synchronization of
 * stored settings between personality modules is up to the
 * personality modules themselves.
 */
void *auclnt_get_minor_data(audio_client_t *, minor_t);
void *auclnt_get_dev_minor_data(audio_dev_t *, minor_t);

/*
 * Simpler warning message, alternative to cmn_err.
 */
void auclnt_warn(audio_client_t *, const char *fmt, ...);

#endif	/* _AUDIO_CLIENT_H */
