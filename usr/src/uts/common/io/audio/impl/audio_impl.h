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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_AUDIO_IMPL_H
#define	_AUDIO_IMPL_H

#include <sys/types.h>
#include <sys/list.h>
#include <sys/poll.h>

#include <sys/audio/audio_driver.h>
#include "audio_client.h"

#define	AUDIO_MAX_OPENS		256
#define	AUDIO_MAX_CHANNELS	16
#define	AUDIO_UNIT_EXPAND	1024
#define	AUDIO_CHBUFS		2048	/* samples for mixing */
#define	AUDIO_VOL_SCALE		256
#define	AUDIO_DB_SIZE		50

#define	AUDIO_INTRHZ		100
#define	AUDIO_INTRHZ_MIN	50	/* 20 msec max */
#define	AUDIO_INTRHZ_MAX	500

struct audio_parms {
	int		p_format;
	int		p_rate;
	int		p_nchan;
};

typedef int (*audio_cnv_func_t)(audio_stream_t *, int);

struct audio_buffer {
	caddr_t			b_data;
	uint64_t		b_head;
	uint64_t		b_tail;
	uint_t			b_hidx;		/* head % nframes */
	uint_t			b_tidx;		/* tail % nframes */
	uint_t			b_nframes;	/* total frames */
	uint_t			b_framesz;	/* bytes per frame  */
};

/*
 * struct audio_stream: This structure represents a virtual stream exposed
 * to a single client.  Each client will have at most two of these (one for
 * record, one for playback.)
 */
struct audio_stream {
	audio_buffer_t		s_buf;
#define	s_data			s_buf.b_data
#define	s_bufsz			s_buf.b_size
#define	s_head			s_buf.b_head
#define	s_tail			s_buf.b_tail
#define	s_framesz		s_buf.b_framesz
#define	s_nframes		s_buf.b_nframes
#define	s_tidx			s_buf.b_tidx
#define	s_hidx			s_buf.b_hidx
	uint_t			s_nfrags;
	uint_t			s_fragfr;
	uint_t			s_nbytes;
	uint_t			s_fragbytes;
	ddi_umem_cookie_t	s_cookie;
	uint32_t		s_allocsz;
	uint32_t		s_hintsz;	/* latency hints */
	uint16_t		s_hintfrags;

	/*
	 * Various counters.
	 */
	uint64_t		s_samples;
	uint64_t		s_errors;	/* underrun or overrun count */

	boolean_t		s_running;
	boolean_t		s_paused;	/* stream paused */
	boolean_t		s_draining;	/* stream draining */

	/*
	 * Sample rate conversion (SRC) and format conversion details.
	 */
	struct grc3state	*s_src_state[AUDIO_MAX_CHANNELS];
	uint_t			s_src_quality;
	int			s_cnv_max;
	audio_cnv_func_t	s_converter;
	uint32_t		*s_cnv_buf0;
	uint32_t		*s_cnv_buf1;
	void			*s_cnv_src;
	void			*s_cnv_dst;
	audio_parms_t		s_cnv_src_parms;
#define	s_cnv_src_nchan		s_cnv_src_parms.p_nchan
#define	s_cnv_src_rate		s_cnv_src_parms.p_rate
#define	s_cnv_src_format	s_cnv_src_parms.p_format

	audio_parms_t		s_cnv_dst_parms;
#define	s_cnv_dst_nchan		s_cnv_dst_parms.p_nchan
#define	s_cnv_dst_rate		s_cnv_dst_parms.p_rate
#define	s_cnv_dst_format	s_cnv_dst_parms.p_format

	size_t			s_cnv_cnt;
	int32_t			*s_cnv_ptr;

	audio_parms_t		*s_user_parms;
	audio_parms_t		*s_phys_parms;

	/*
	 * Volume.
	 */
	uint8_t			s_gain_master;
	uint8_t			s_gain_pct;
	uint16_t		s_gain_scaled;
	uint16_t		s_gain_eff;
	boolean_t		s_muted;

	/*
	 * Callbacks.
	 */
	uint64_t		s_drain_idx;	/* engine index */

	/*
	 * Other per stream details, e.g. channel offset, etc.
	 */
	kmutex_t		s_lock;
	kcondvar_t		s_cv;
	list_node_t		s_eng_linkage;	/*  place on engine list */
	audio_client_t		*s_client;
	audio_engine_t		*s_engine;
	int			s_choffs;

	/*
	 * Other bits.
	 */
	uint_t			s_engcap;	/* ENGINE_xxx_CAP */
};

/*
 * struct audio_client: This structure represents a logical port,
 * associated with an open file, etc.  These are the entities that are
 * mixed.
 */
struct audio_client {
	audio_stream_t		c_istream;
	audio_stream_t		c_ostream;
	void			*c_private;

	/*
	 * We can keep a linked list of clients to "notify" so that
	 * we can do this outside of locked context.
	 */
	audio_client_t		*c_next_input;
	audio_client_t		*c_next_output;
	audio_client_t		*c_next_drain;

	/*
	 * DDI support.
	 */
	major_t			c_major;
	minor_t			c_minor;
	minor_t			c_origminor;
	queue_t			*c_rq;
	queue_t			*c_wq;

	/*
	 * Linkage for per-device list of clients.
	 */
	list_node_t		c_global_linkage;
	list_node_t		c_dev_linkage;
	int			c_refcnt;
	boolean_t		c_serialize;

	kmutex_t		c_lock;
	kcondvar_t		c_cv;
	boolean_t		c_is_active;

	/*
	 * Client wide settings... e.g. ops vector, etc.
	 */
	uint_t			c_omode;	/* open mode */
	pid_t			c_pid;		/* opening process id */
	audio_dev_t		*c_dev;
	cred_t			*c_cred;
	audio_client_ops_t	c_ops;
#define	c_open			c_ops.aco_open
#define	c_close			c_ops.aco_close
#define	c_read			c_ops.aco_read
#define	c_write			c_ops.aco_write
#define	c_ioctl			c_ops.aco_ioctl
#define	c_chpoll		c_ops.aco_chpoll
#define	c_output		c_ops.aco_output
#define	c_input			c_ops.aco_input
#define	c_notify		c_ops.aco_notify
#define	c_drain			c_ops.aco_drain
#define	c_wput			c_ops.aco_wput
#define	c_wsrv			c_ops.aco_wsrv
#define	c_rsrv			c_ops.aco_rsrv

	struct pollhead		c_pollhead;

};

struct audio_infostr {
	char			i_line[100];
	list_node_t		i_linkage;
};

struct audio_stats {
	kstat_named_t		st_head;
	kstat_named_t		st_tail;
	kstat_named_t		st_flags;
	kstat_named_t		st_nfrags;
	kstat_named_t		st_framesz;
	kstat_named_t		st_nbytes;
	kstat_named_t		st_hidx;
	kstat_named_t		st_tidx;
	kstat_named_t		st_format;
	kstat_named_t		st_nchan;
	kstat_named_t		st_rate;
	kstat_named_t		st_intrs;
	kstat_named_t		st_errors;
	kstat_named_t		st_engine_underruns;
	kstat_named_t		st_engine_overruns;
	kstat_named_t		st_stream_underruns;
	kstat_named_t		st_stream_overruns;
	kstat_named_t		st_playahead;
	kstat_named_t		st_suspended;
	kstat_named_t		st_failed;
};

typedef void (*audio_import_fn_t)(audio_engine_t *, uint_t, audio_stream_t *);
typedef void (*audio_export_fn_t)(audio_engine_t *, uint_t, uint_t);

/*
 * An audio engine corresponds to a single DMA transfer channel.  It can
 * represent either record or playback, but not both at the same time.
 * A device that supports simultaneous record and playback will register
 * separate channels.
 */
struct audio_engine {
	audio_engine_ops_t	e_ops;
	void			*e_private;
	uint_t			e_flags;

	/*
	 * Mixing related fields.
	 */
	uint_t			e_limiter_state;
	int32_t			*e_chbufs[AUDIO_MAX_CHANNELS];
	uint_t			e_choffs[AUDIO_MAX_CHANNELS];
	uint_t			e_chincr[AUDIO_MAX_CHANNELS];
	audio_export_fn_t	e_export;
	audio_import_fn_t	e_import;

	/*
	 * Underlying physical buffer shared with device driver.
	 */
	audio_buffer_t		e_buf;
#define	e_head			e_buf.b_head
#define	e_tail			e_buf.b_tail
#define	e_data			e_buf.b_data
#define	e_framesz		e_buf.b_framesz
#define	e_nframes		e_buf.b_nframes
#define	e_hidx			e_buf.b_hidx
#define	e_tidx			e_buf.b_tidx
	uint_t			e_fragfr;
	uint_t			e_playahead;

	int			e_intrs;
	int			e_errors;
	int			e_overruns;
	int			e_underruns;
	int			e_stream_overruns;
	int			e_stream_underruns;

	audio_parms_t		e_parms;
#define	e_format		e_parms.p_format
#define	e_nchan			e_parms.p_nchan
#define	e_rate			e_parms.p_rate

	/*
	 * Statistics.
	 */
	kstat_t			*e_ksp;
	struct audio_stats	e_stats;


	/*
	 * Synchronization.
	 */
	kmutex_t		e_lock;
	kcondvar_t		e_cv;
	ddi_periodic_t		e_periodic;

	/*
	 * Linkage for per-device list.
	 */
	list_node_t		e_dev_linkage;
	audio_dev_t		*e_dev;
	int			e_num;	/* arbitrary engine number */

	/*
	 * List of of streams attached to this engine.
	 */
	list_t			e_streams;
	int			e_nrunning;
	int			e_suspended;
	boolean_t		e_failed;

	boolean_t		e_need_start;
};

struct audio_dev {
	dev_info_t		*d_dip;
	major_t			d_major;
	int			d_instance;

	uint32_t		d_flags;
#define	DEV_OUTPUT_CAP		(1U << 0)
#define	DEV_INPUT_CAP		(1U << 1)
#define	DEV_DUPLEX_CAP		(1U << 2)
#define	DEV_SNDSTAT_CAP		(1U << 3)
#define	DEV_OPAQUE_CAP		(1U << 4)	/* AC3 are not mixable */

	char			d_name[128];	/* generic description */
	char			d_desc[128];	/* detailed config descr */
	char			d_vers[128];	/* detailed version descr */
	int			d_number;	/* global /dev/audioXX # */
	int			d_index;	/* master device index */
	int			d_engno;	/* engine counter */

	list_t			d_hwinfo;	/* strings of hw info */

	/*
	 * Synchronization.
	 */
	kmutex_t		d_lock;
	kcondvar_t		d_cv;
	kmutex_t		d_ctrl_lock;	/* leaf lock */
	kcondvar_t		d_ctrl_cv;
	krwlock_t		d_clnt_lock;
	uint_t			d_refcnt;
	int			d_suspended;
	boolean_t		d_failed;

	/*
	 * Lists of virtual clients, controls and engines.  Protected by
	 * the d_lock field above.
	 */
	list_t			d_clients;
	list_t			d_engines;
	list_t			d_controls;
	audio_ctrl_t		*d_pcmvol_ctrl;
	uint64_t		d_pcmvol;

	volatile uint_t		d_serial;

	/*
	 * Linkage onto global list of devices.
	 */
	list_node_t		d_by_index;
	list_node_t		d_by_number;

	/*
	 * Personality specific data.
	 */
	void			*d_minor_data[1 << AUDIO_MN_TYPE_NBITS];
};

/*
 * Each audio_dev optionally can have controls attached to it.
 * Controls are separate from audio engines. They are methods of
 * adjusting pharameters or reading metrics that usually relate to
 * hardware on devices engine by the driver. They can be things like
 * master volume for example.
 *
 * If the driver does not support controls then it must insure
 * that any hardware controls are initialized to a usable state.
 *
 * For the framework/user-apps to be able to change controls
 * the driver must create, enable and configure controls with
 * control API's.
 *
 * There are a number of common controls (well-known) that most
 * hardware supports. These have known names and known ctrl numbers.
 * In addition a driver can have any number of extention
 * controls (device-private). These can have any name and any ctrl
 * number other then the ones, defined as well-knonw ones.
 *
 * Only controls created through control API's will be available,
 * well-known or device-private.
 */
struct	audio_ctrl {
	audio_ctrl_desc_t	ctrl_des;
#define	ctrl_name		ctrl_des.acd_name
#define	ctrl_type		ctrl_des.acd_type
#define	ctrl_enum		ctrl_des.acd_enum
#define	ctrl_flags		ctrl_des.acd_flags
	audio_dev_t		*ctrl_dev;
	audio_ctrl_rd_t		ctrl_read_fn;
	audio_ctrl_wr_t		ctrl_write_fn;
	list_node_t		ctrl_linkage;
	void			*ctrl_arg;
	uint64_t		ctrl_saved;	/* the saved value */
	boolean_t		ctrl_saved_ok;
};


/*
 * Prototypes.
 */

/* audio_format.c */
int auimpl_format_alloc(audio_stream_t *);
void auimpl_format_free(audio_stream_t *);
int auimpl_format_setup(audio_stream_t *, audio_parms_t *);

/* audio_output.c */
void auimpl_export_16ne(audio_engine_t *, uint_t, uint_t);
void auimpl_export_16oe(audio_engine_t *, uint_t, uint_t);
void auimpl_export_24ne(audio_engine_t *, uint_t, uint_t);
void auimpl_export_24oe(audio_engine_t *, uint_t, uint_t);
void auimpl_export_32ne(audio_engine_t *, uint_t, uint_t);
void auimpl_export_32oe(audio_engine_t *, uint_t, uint_t);
void auimpl_output_callback(void *);
void auimpl_output_preload(audio_engine_t *);

/* audio_input.c */
void auimpl_import_16ne(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_import_16oe(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_import_24ne(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_import_24oe(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_import_32ne(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_import_32oe(audio_engine_t *, uint_t, audio_stream_t *);
void auimpl_input_callback(void *);
int auimpl_input_drain(audio_stream_t *);

/* audio_client.c */
void auimpl_client_init(void);
void auimpl_client_fini(void);
audio_client_t *auimpl_client_create(dev_t);
void auimpl_client_destroy(audio_client_t *);
void auimpl_client_activate(audio_client_t *);
void auimpl_client_deactivate(audio_client_t *);
int auimpl_create_minors(audio_dev_t *);
void auimpl_remove_minors(audio_dev_t *);
int auimpl_set_pcmvol(void *, uint64_t);
int auimpl_get_pcmvol(void *, uint64_t *);

/* audio_ctrl.c */
int auimpl_save_controls(audio_dev_t *);
int auimpl_restore_controls(audio_dev_t *);

/* audio_engine.c */
extern int audio_priority;
void auimpl_dev_init(void);
void auimpl_dev_fini(void);
void auimpl_dev_hold(audio_dev_t *);
audio_dev_t *auimpl_dev_hold_by_devt(dev_t);
audio_dev_t *auimpl_dev_hold_by_index(int);
void auimpl_dev_release(audio_dev_t *);
int auimpl_choose_format(int);

int auimpl_engine_open(audio_dev_t *, int, int, audio_stream_t *);
void auimpl_engine_close(audio_stream_t *);

void auimpl_dev_walk_engines(audio_dev_t *,
    int (*)(audio_engine_t *, void *), void *);

void auimpl_dev_vwarn(audio_dev_t *, const char *, va_list);

/* engine operations */
#define	E_OP(e, entry)		((e)->e_ops.audio_engine_##entry)
#define	E_PRV(e)		((e)->e_private)
#define	ENG_FORMAT(e)		E_OP(e, format)(E_PRV(e))
#define	ENG_RATE(e)		E_OP(e, rate)(E_PRV(e))
#define	ENG_CHANNELS(e)		E_OP(e, channels)(E_PRV(e))
#define	ENG_SYNC(e, num)	E_OP(e, sync)(E_PRV(e), num)
#define	ENG_START(e)		E_OP(e, start)(E_PRV(e))
#define	ENG_STOP(e)		E_OP(e, stop)(E_PRV(e))
#define	ENG_COUNT(e)		E_OP(e, count)(E_PRV(e))
#define	ENG_QLEN(e)		E_OP(e, qlen)(E_PRV(e))
#define	ENG_PLAYAHEAD(e)	E_OP(e, playahead)(E_PRV(e))
#define	ENG_CLOSE(e)		E_OP(e, close)(E_PRV(e))
#define	ENG_OPEN(e, nf, d) 	E_OP(e, open)(E_PRV(e), e->e_flags, nf, d)
#define	ENG_CHINFO(e, c, o, i)	E_OP(e, chinfo(E_PRV(e), c, o, i))

/* audio_sun.c */
void auimpl_sun_init(void);

/* audio_oss.c */
void auimpl_oss_init(void);

#endif	/* _AUDIO_IMPL_H */
