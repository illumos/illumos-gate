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
 * Sun audio(7I) and mixer(7I) personality.
 *
 * There are some "undocumented" details of how legacy Sun audio
 * interfaces work.  The following "rules" were derived from reading the
 * legacy Sun mixer code, and to the best of our knowledge are not
 * documented elsewhere.
 *
 * - We create a "fake" audio device, which behaves like a classic
 *   exclusive audio device, for each PID, as determined during open(2).
 *
 * - Different processes don't interfere with each other.  Even though
 *   they are running concurrently, they each think they have exclusive
 *   control over the audio device.
 *
 * - Read and write directions operate independent of each other.  That
 *   is, a device open for reading won't intefere with a future open for
 *   writing, and vice versa.  This is true even within the same process.
 *
 * - Because the virtualization is by PID, strange behavior may occur
 *   if a process tries to open an audio device at the same time it
 *   has already received a file descriptor from another process (such
 *   through inheritence via fork()).
 *
 * - The "fake" audio device has no control over physical settings.
 *   It sees only the software attenuation-based volumes for play and
 *   record, and has no support for alternate input or output ports or
 *   access to the monitoring features of the hardware.
 *
 * - Explicit notificaton signals (SIGPOLL) are only ever sent up the
 *   audioctl node -- never up a regular audio node.  (The stream head
 *   may still issue SIGPOLL based on readability/writability of
 *   course.)
 *
 * - Corollary: processes that want asynch. notifications will open
 *   /dev/audioctl as well as /dev/audio.
 *
 * - We don't support the MIXER mode at all.
 *
 * - By corollary, a process is only allowed to open /dev/audio once
 *   (in each direction.)
 *
 * - Attempts to open /dev/audio in duplex mode (O_RDWR) fail (EBUSY)
 *   if the device cannot support duplex operation.
 *
 * - Attempts to open a device with FREAD set fail if the device is not
 *   capable of recording.  (Likewise for FWRITE and playback.)
 *
 * - No data transfer is permitted for audioctl nodes.  (No actual
 *   record or play.)
 *
 * - Sun audio does not support any formats other than linear and
 *   ULAW/ALAW.  I.e. it will never support AC3 or other "opaque"
 *   streams which require special handling.
 *
 * - Sun audio only supports stereo or monophonic data streams.
 */

#include <sys/types.h>
#include <sys/open.h>
#include <sys/errno.h>
#include <sys/audio.h>
#include <sys/mixer.h>
#include <sys/file.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/sysmacros.h>
#include <sys/list.h>
#include <sys/note.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include "audio_client.h"

typedef struct daclient daclient_t;
typedef struct dadev dadev_t;
typedef struct daproc daproc_t;

/* common structure shared between both audioctl and audio nodes */
struct daclient {
	daproc_t		*dc_proc;
	dadev_t			*dc_dev;
	audio_client_t		*dc_client;
	queue_t			*dc_wq;
	unsigned		dc_eof;
	list_t			dc_eofcnt;
	kmutex_t		dc_lock;
	mblk_t			*dc_draining;
};

struct eofcnt {
	list_node_t		linkage;
	uint64_t		tail;
};

struct dadev {
	audio_dev_t		*d_dev;

	list_t			d_procs;
	kmutex_t		d_mx;
	kcondvar_t		d_cv;
};

struct daproc {
	pid_t			p_id;
	struct audio_info	p_info;
	int			p_refcnt;
	int			p_oflag;
	list_node_t		p_linkage;
	dadev_t			*p_dev;
	audio_client_t		*p_writer;
	audio_client_t		*p_reader;
};

int devaudio_proc_hold(audio_client_t *, int);
void devaudio_proc_release(audio_client_t *);
static void devaudio_proc_update(daproc_t *);


static int
devaudio_compose_format(audio_prinfo_t *prinfo)
{
	switch (prinfo->precision) {
	case 8:
		switch (prinfo->encoding) {
		case AUDIO_ENCODING_ULAW:
			return (AUDIO_FORMAT_ULAW);
		case AUDIO_ENCODING_ALAW:
			return (AUDIO_FORMAT_ALAW);
		case AUDIO_ENCODING_LINEAR8:
			return (AUDIO_FORMAT_U8);
		case AUDIO_ENCODING_LINEAR:
			return (AUDIO_FORMAT_S8);
		}
		break;
	case 16:
		if (prinfo->encoding == AUDIO_ENCODING_LINEAR)
			return (AUDIO_FORMAT_S16_NE);
		break;
	case 32:
		if (prinfo->encoding == AUDIO_ENCODING_LINEAR)
			return (AUDIO_FORMAT_S32_NE);
		break;
	}
	return (AUDIO_FORMAT_NONE);

}

static void
devaudio_decompose_format(audio_prinfo_t *prinfo, int afmt)
{
	int	e, p;

	/*
	 * N.B.: Even though some of the formats below can't be set by
	 * this personality, reporting them (using the closest match)
	 * allows this personality to roughly approximate settings for
	 * other streams.  It would be incredibly poor form for any
	 * personality to modify the format settings for a different
	 * personality, so we don't worry about that case.
	 */

	switch (afmt) {
	case AUDIO_FORMAT_ULAW:
		e = AUDIO_ENCODING_ULAW;
		p = 8;
		break;

	case AUDIO_FORMAT_ALAW:
		e = AUDIO_ENCODING_ALAW;
		p = 8;
		break;

	case AUDIO_FORMAT_U8:
		e = AUDIO_ENCODING_LINEAR8;
		p = 8;
		break;

	case AUDIO_FORMAT_S8:
		e = AUDIO_ENCODING_LINEAR;
		p = 8;
		break;

	case AUDIO_FORMAT_S16_NE:
	case AUDIO_FORMAT_S16_OE:
	case AUDIO_FORMAT_U16_NE:
	case AUDIO_FORMAT_U16_OE:
		e = AUDIO_ENCODING_LINEAR;
		p = 16;
		break;

	case AUDIO_FORMAT_S24_NE:
	case AUDIO_FORMAT_S24_OE:
	case AUDIO_FORMAT_S24_PACKED:
		e = AUDIO_ENCODING_LINEAR;
		p = 24;
		break;

	case AUDIO_FORMAT_S32_NE:
	case AUDIO_FORMAT_S32_OE:
		e = AUDIO_ENCODING_LINEAR;
		p = 32;
		break;

	default:
		/* all other formats (e.g. AC3) are uninterpreted */
		e = AUDIO_ENCODING_NONE;
		p = 32;
		break;
	}

	prinfo->encoding = e;
	prinfo->precision = p;
}

static daproc_t *
devaudio_proc_alloc(audio_client_t *c)
{
	audio_info_t	*info;
	audio_prinfo_t	*prinfo;
	uint32_t	caps;
	daproc_t	*proc;

	if ((proc = kmem_zalloc(sizeof (*proc), KM_NOSLEEP)) == NULL) {
		return (NULL);
	}
	info = &proc->p_info;

	/*
	 * audio(7I) says: Upon the initial open() of the audio
	 * device, the driver resets the data format of the device to
	 * the default state of 8-bit, 8Khz, mono u-Law data.
	 */
	prinfo = &info->play;
	prinfo->channels =	1;
	prinfo->sample_rate =	8000;
	prinfo->encoding =	AUDIO_ENCODING_ULAW;
	prinfo->precision =	8;
	prinfo->gain =		AUDIO_MAX_GAIN;
	prinfo->balance =	AUDIO_MID_BALANCE;
	prinfo->buffer_size =	8192;
	prinfo->pause =		B_FALSE;
	prinfo->waiting =	B_FALSE;
	prinfo->open =		B_FALSE;
	prinfo->active =	B_FALSE;
	prinfo->samples =	0;
	prinfo->eof =		0;
	prinfo->error =		0;
	prinfo->minordev =	0;
	prinfo->port =		AUDIO_SPEAKER;
	prinfo->avail_ports =	AUDIO_SPEAKER;
	prinfo->mod_ports =	AUDIO_NONE;
	prinfo->_xxx =		0;

	prinfo = &info->record;
	prinfo->channels =	1;
	prinfo->sample_rate =	8000;
	prinfo->encoding =	AUDIO_ENCODING_ULAW;
	prinfo->precision =	8;
	prinfo->gain =		AUDIO_MAX_GAIN;
	prinfo->balance =	AUDIO_MID_BALANCE;
	prinfo->buffer_size =	8192;
	prinfo->waiting =	B_FALSE;
	prinfo->open =  	B_FALSE;
	prinfo->active =	B_FALSE;
	prinfo->samples =	0;
	prinfo->eof =		0;
	prinfo->error =		0;
	prinfo->minordev =	0;
	prinfo->port =		AUDIO_MICROPHONE;
	prinfo->avail_ports =	AUDIO_MICROPHONE;
	prinfo->mod_ports =	AUDIO_MICROPHONE;

	info->output_muted =	B_FALSE;
	/* pretend we don't have a software mixer - we don't support the API */
	info->hw_features =	0;
	info->sw_features =	0;
	info->sw_features_enabled = 0;

	caps = auclnt_get_dev_capab(auclnt_get_dev(c));
	if (caps & AUDIO_CLIENT_CAP_PLAY)
		info->hw_features |= AUDIO_HWFEATURE_PLAY;
	if (caps & AUDIO_CLIENT_CAP_RECORD)
		info->hw_features |= AUDIO_HWFEATURE_RECORD;
	if (caps & AUDIO_CLIENT_CAP_DUPLEX)
		info->hw_features |= AUDIO_HWFEATURE_DUPLEX;

	return (proc);
}

static void
devaudio_proc_free(daproc_t *proc)
{
	kmem_free(proc, sizeof (*proc));
}

int
devaudio_proc_hold(audio_client_t *c, int oflag)
{
	pid_t		pid;
	daproc_t	*proc;
	dadev_t		*dev;
	daclient_t	*dc;
	list_t		*l;
	audio_dev_t	*adev;
	int		rv;

	adev = auclnt_get_dev(c);

	/* first allocate and initialize the daclient private data */
	if ((dc = kmem_zalloc(sizeof (*dc), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	mutex_init(&dc->dc_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&dc->dc_eofcnt, sizeof (struct eofcnt),
	    offsetof(struct eofcnt, linkage));
	auclnt_set_private(c, dc);

	dev = auclnt_get_dev_minor_data(adev, AUDIO_MINOR_DEVAUDIO);
	l = &dev->d_procs;
	pid = auclnt_get_pid(c);

	/* set a couple of common fields */
	dc->dc_client = c;
	dc->dc_dev = dev;

	mutex_enter(&dev->d_mx);
	for (proc = list_head(l); proc != NULL; proc = list_next(l, proc)) {
		if (proc->p_id == pid) {
			proc->p_refcnt++;
			break;
		}
	}
	if (proc == NULL) {
		if ((proc = devaudio_proc_alloc(c)) == NULL) {
			rv = ENOMEM;
			goto failed;
		}
		proc->p_refcnt = 1;
		proc->p_id = pid;
		proc->p_dev = dev;
		list_insert_tail(l, proc);
	}

	while (proc->p_oflag & oflag) {

		if (oflag & (FNDELAY|FNONBLOCK)) {
			rv = EBUSY;
			goto failed;
		}
		if (oflag & FWRITE)
			proc->p_info.play.waiting++;
		if (oflag & FREAD)
			proc->p_info.record.waiting++;
		if (cv_wait_sig(&dev->d_cv, &dev->d_mx) == 0) {
			/* interrupted! */
			if (oflag & FWRITE)
				proc->p_info.play.waiting--;
			if (oflag & FREAD)
				proc->p_info.record.waiting--;
			rv = EINTR;
			goto failed;
		}
		if (oflag & FWRITE)
			proc->p_info.play.waiting--;
		if (oflag & FREAD)
			proc->p_info.record.waiting--;
	}

	if (oflag & FWRITE) {
		audio_prinfo_t	*play = &proc->p_info.play;
		audio_stream_t	*sp = auclnt_output_stream(c);

		if (((rv = auclnt_set_rate(sp, 8000)) != 0) ||
		    ((rv = auclnt_set_format(sp, AUDIO_FORMAT_ULAW)) != 0) ||
		    ((rv = auclnt_set_channels(sp, 1)) != 0)) {
			goto failed;
		}

		auclnt_set_samples(sp, 0);
		auclnt_set_errors(sp, 0);
		play->eof = 0;
		play->buffer_size = 8192;

		auclnt_set_gain(sp, ((play->gain * 100) / AUDIO_MAX_GAIN));
		auclnt_set_muted(sp, proc->p_info.output_muted);
		play->open = B_TRUE;
		proc->p_writer = c;
		proc->p_oflag |= FWRITE;
	}

	if (oflag & FREAD) {
		audio_prinfo_t	*rec = &proc->p_info.record;
		audio_stream_t	*sp = auclnt_input_stream(c);

		if (((rv = auclnt_set_rate(sp, 8000)) != 0) ||
		    ((rv = auclnt_set_format(sp, AUDIO_FORMAT_ULAW)) != 0) ||
		    ((rv = auclnt_set_channels(sp, 1)) != 0)) {
			goto failed;
		}

		auclnt_set_samples(sp, 0);
		auclnt_set_errors(sp, 0);
		rec->eof = 0;
		rec->buffer_size = 8192;

		auclnt_set_gain(sp, ((rec->gain * 100) / AUDIO_MAX_GAIN));
		rec->open = B_TRUE;
		proc->p_reader = c;
		proc->p_oflag |= FREAD;
	}


	dc->dc_wq = auclnt_get_wq(c);

	/* we update the s_proc last to avoid a race */
	dc->dc_proc = proc;

	devaudio_proc_update(proc);

	mutex_exit(&dev->d_mx);

	return (0);

failed:
	mutex_exit(&dev->d_mx);
	devaudio_proc_release(c);
	return (rv);

}

static void
devaudio_clear_eof(audio_client_t *c)
{
	struct eofcnt	*eof;
	daclient_t	*dc;

	dc = auclnt_get_private(c);
	mutex_enter(&dc->dc_lock);
	while ((eof = list_remove_head(&dc->dc_eofcnt)) != NULL) {
		kmem_free(eof, sizeof (*eof));
	}
	mutex_exit(&dc->dc_lock);
}

void
devaudio_proc_release(audio_client_t *c)
{
	daproc_t	*proc;
	dadev_t		*dev;
	mblk_t		*mp;
	daclient_t	*dc;

	dc = auclnt_get_private(c);
	proc = dc->dc_proc;
	dev = dc->dc_dev;
	dc->dc_proc = NULL;

	mutex_enter(&dev->d_mx);

	if (proc != NULL) {
		proc->p_refcnt--;
		ASSERT(proc->p_refcnt >= 0);

		if (c == proc->p_writer) {
			proc->p_oflag &= ~FWRITE;
			proc->p_writer = NULL;
		}
		if (c == proc->p_reader) {
			proc->p_oflag &= ~FREAD;
			proc->p_reader = NULL;
		}
		cv_broadcast(&dev->d_cv);

		if (proc->p_refcnt == 0) {
			list_remove(&dev->d_procs, proc);
			devaudio_proc_free(proc);
		}
		dc->dc_proc = NULL;
	}

	mutex_exit(&dev->d_mx);

	devaudio_clear_eof(c);

	while ((mp = dc->dc_draining) != NULL) {
		dc->dc_draining = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
	}

	mutex_destroy(&dc->dc_lock);
	list_destroy(&dc->dc_eofcnt);
	kmem_free(dc, sizeof (*dc));
}

static void
devaudio_input(audio_client_t *c)
{
	audio_stream_t	*sp = auclnt_input_stream(c);
	daclient_t	*dc = auclnt_get_private(c);
	unsigned	framesz = auclnt_get_framesz(sp);
	queue_t		*rq = auclnt_get_rq(c);
	mblk_t		*mp;
	unsigned	nbytes = dc->dc_proc->p_info.record.buffer_size;
	unsigned	count = nbytes / framesz;

	/*
	 * Potentially send a message upstream with the record data.
	 * We collect this up in chunks of the buffer size requested
	 * by the client.
	 */

	while (auclnt_get_count(sp) >= count) {

		if ((!canput(rq)) ||
		    ((mp = allocb(nbytes, BPRI_MED)) == NULL)) {
			/*
			 * This will apply back pressure to the
			 * buffer.  We haven't yet lost any data, we
			 * just can't send it up.  The point at which
			 * we have an unrecoverable overrun is in the
			 * buffer, not in the streams queue.  So, no
			 * need to do anything right now.
			 *
			 * Note that since recording is enabled, we
			 * expect that the callback routine will be
			 * called repeatedly & regularly, so we don't
			 * have to worry about leaving data orphaned
			 * in the queue.
			 */
			break;
		}

		(void) auclnt_consume_data(sp, (caddr_t)mp->b_wptr, count);
		mp->b_wptr += nbytes;
		(void) putq(rq, mp);
	}
}

static void
devaudio_proc_update(daproc_t *proc)
{
	audio_info_t	*info;
	audio_stream_t	*sp;
	audio_client_t	*c;

	info = &proc->p_info;

	ASSERT(mutex_owned(&proc->p_dev->d_mx));

	if ((c = proc->p_writer) != NULL) {
		sp = auclnt_output_stream(c);

		info->play.sample_rate = auclnt_get_rate(sp);
		info->play.channels = auclnt_get_channels(sp);
		devaudio_decompose_format(&info->play, auclnt_get_format(sp));

		info->play.gain =
		    (auclnt_get_gain(sp) * AUDIO_MAX_GAIN) / 100;
		info->play.pause = auclnt_is_paused(sp);
		info->play.active = auclnt_is_running(sp);
		info->play.samples = auclnt_get_samples(sp);
		info->play.error = auclnt_get_errors(sp) ? B_TRUE : B_FALSE;
		info->output_muted = auclnt_get_muted(sp);
	} else {
		info->play.encoding = AUDIO_ENCODING_NONE;
		info->play.precision = 0;
		info->play.sample_rate = 0;
		info->play.pause = B_FALSE;
		info->play.active = B_FALSE;
		info->play.error = B_FALSE;
		info->play.samples = 0;
	}

	if ((c = proc->p_reader) != NULL) {
		sp = auclnt_input_stream(c);

		info->record.sample_rate = auclnt_get_rate(sp);
		info->record.channels = auclnt_get_channels(sp);
		devaudio_decompose_format(&info->record, auclnt_get_format(sp));

		info->record.gain =
		    (auclnt_get_gain(sp) * AUDIO_MAX_GAIN) / 100;
		info->record.pause = auclnt_is_paused(sp);
		info->record.active = auclnt_is_running(sp);
		info->record.samples = auclnt_get_samples(sp);
		info->record.error = auclnt_get_errors(sp) ? B_TRUE : B_FALSE;
	} else {
		info->record.encoding = AUDIO_ENCODING_NONE;
		info->record.precision = 0;
		info->record.sample_rate = 0;
		info->record.pause = B_FALSE;
		info->record.active = B_FALSE;
		info->record.error = B_FALSE;
		info->record.samples = 0;
	}
}

static void
devaudio_ioc_getinfo(queue_t *wq, audio_client_t *c, mblk_t *mp)
{
	daclient_t	*dc = auclnt_get_private(c);
	daproc_t	*proc = dc->dc_proc;
	mblk_t		*bcont;

	if ((bcont = allocb(sizeof (audio_info_t), BPRI_MED)) == NULL) {
		miocnak(wq, mp, 0, ENOMEM);
		return;
	}

	mutex_enter(&dc->dc_dev->d_mx);
	devaudio_proc_update(proc);
	bcopy(&proc->p_info, bcont->b_wptr, sizeof (audio_info_t));
	mutex_exit(&dc->dc_dev->d_mx);

	bcont->b_wptr += sizeof (audio_info_t);

	mcopyout(mp, NULL, sizeof (audio_info_t), NULL, bcont);
	qreply(wq, mp);
}

#define	CHANGED(new, old, field)			\
	((new->field != ((uint32_t)~0)) && (new->field != old->field))
#define	CHANGED8(new, old, field)			\
	((new->field != ((uint8_t)~0)) && (new->field != old->field))

static void
devaudio_ioc_setinfo(queue_t *wq, audio_client_t *c, mblk_t *mp)
{
	daclient_t	*dc;
	daproc_t	*proc;
	audio_info_t	*oinfo;
	audio_info_t	*ninfo;
	audio_prinfo_t	*npr;
	audio_prinfo_t	*opr;

	int		pfmt = AUDIO_FORMAT_NONE;
	int		rfmt = AUDIO_FORMAT_NONE;

	boolean_t	reader;
	boolean_t	writer;
	boolean_t	isctl;
	audio_stream_t	*sp;
	int		rv;
	caddr_t		uaddr;
	mblk_t		*bcont;

	struct copyresp	*csp;

	if (DB_TYPE(mp) == M_IOCTL) {
		/* the special value "1" indicates that this is a copyin */
		uaddr = *(caddr_t *)(void *)mp->b_cont->b_rptr;

		mcopyin(mp, uaddr, sizeof (audio_info_t), NULL);
		qreply(wq, mp);
		return;
	}

	ASSERT(DB_TYPE(mp) == M_IOCDATA);
	if (((bcont = mp->b_cont) == NULL) ||
	    (MBLKL(mp->b_cont) != sizeof (audio_info_t))) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	mp->b_cont = NULL;
	csp = (void *)mp->b_rptr;
	uaddr = (void *)csp->cp_private;
	dc = auclnt_get_private(c);
	ninfo = (void *)bcont->b_rptr;

	mutex_enter(&dc->dc_dev->d_mx);

	proc = dc->dc_proc;
	oinfo = &proc->p_info;

	if (auclnt_get_minor_type(c) == AUDIO_MINOR_DEVAUDIOCTL) {
		/* control node can do both read and write fields */
		isctl = B_TRUE;
		reader = B_TRUE;
		writer = B_TRUE;
	} else {
		isctl = B_FALSE;
		writer = (c == proc->p_writer);
		reader = (c == proc->p_reader);
	}

	/*
	 * Start by validating settings.
	 */
	npr = &ninfo->play;
	opr = &oinfo->play;

	if (writer && CHANGED(npr, opr, sample_rate)) {
		if ((isctl) ||
		    (npr->sample_rate < 5500) || (npr->sample_rate > 48000)) {
			rv = EINVAL;
			goto err;
		}
	}
	if (writer && CHANGED(npr, opr, channels)) {
		if ((isctl) || (npr->channels < 1) || (npr->channels > 2)) {
			rv = EINVAL;
			goto err;
		}
	}
	if (writer &&
	    (CHANGED(npr, opr, encoding) || CHANGED(npr, opr, precision))) {
		if (npr->encoding == (uint32_t)~0)
			npr->encoding = opr->encoding;
		if (npr->precision == (uint32_t)~0)
			npr->precision = opr->precision;
		pfmt = devaudio_compose_format(npr);
		if ((isctl) || (pfmt == AUDIO_FORMAT_NONE)) {
			rv = EINVAL;
			goto err;
		}
	}

	/* play fields that anyone can modify */
	if (CHANGED(npr, opr, gain)) {
		if (npr->gain > AUDIO_MAX_GAIN) {
			rv = EINVAL;
			goto err;
		}
	}


	npr = &ninfo->record;
	opr = &oinfo->record;

	if (reader && CHANGED(npr, opr, sample_rate)) {
		if ((isctl) ||
		    (npr->sample_rate < 5500) || (npr->sample_rate > 48000)) {
			rv = EINVAL;
			goto err;
		}
	}
	if (reader && CHANGED(npr, opr, channels)) {
		if ((isctl) || (npr->channels < 1) || (npr->channels > 2)) {
			rv = EINVAL;
			goto err;
		}
	}
	if (reader &&
	    (CHANGED(npr, opr, encoding) || CHANGED(npr, opr, precision))) {
		if (npr->encoding == (uint32_t)~0)
			npr->encoding = opr->encoding;
		if (npr->precision == (uint32_t)~0)
			npr->precision = opr->precision;
		rfmt = devaudio_compose_format(npr);
		if ((isctl) || (rfmt == AUDIO_FORMAT_NONE)) {
			rv = EINVAL;
			goto err;
		}
	}
	if (reader && CHANGED(npr, opr, buffer_size)) {
		if (isctl) {
			rv = EINVAL;
			goto err;
		}
		/* make sure we can support 16-bit stereo samples */
		if ((npr->buffer_size % 4) != 0) {
			npr->buffer_size = (npr->buffer_size + 3) & ~3;
		}
		/* limit the maximum buffer size somewhat */
		if (npr->buffer_size > 16384) {
			npr->buffer_size = 16384;
		}
	}

	/* record fields that anyone can modify */
	if (CHANGED(npr, opr, gain)) {
		if (npr->gain > AUDIO_MAX_GAIN) {
			rv = EINVAL;
			goto err;
		}
	}

	/*
	 * Now apply the changes.
	 */
	if (proc->p_writer != NULL) {
		sp = auclnt_output_stream(proc->p_writer);
		npr = &ninfo->play;
		opr = &oinfo->play;

		if (CHANGED(npr, opr, sample_rate)) {
			if ((rv = auclnt_set_rate(sp, npr->sample_rate)) != 0)
				goto err;
		}
		if (CHANGED(npr, opr, channels)) {
			if ((rv = auclnt_set_channels(sp, npr->channels)) != 0)
				goto err;
		}
		if (pfmt != AUDIO_FORMAT_NONE) {
			if ((rv = auclnt_set_format(sp, pfmt)) != 0)
				goto err;
		}
		if (CHANGED(npr, opr, samples)) {
			auclnt_set_samples(sp, npr->samples);
		}
		if (CHANGED(npr, opr, eof)) {
			/*
			 * This ugly special case code is required to
			 * prevent problems with realaudio.
			 */
			if (npr->eof == 0) {
				devaudio_clear_eof(proc->p_writer);
			}
			opr->eof = npr->eof;
		}
		if (CHANGED8(npr, opr, pause)) {
			if (npr->pause) {
				auclnt_set_paused(sp);
			} else {
				auclnt_clear_paused(sp);

				/* qenable to start up the playback */
				qenable(auclnt_get_wq(proc->p_writer));
			}
		}
		if (CHANGED8(npr, opr, waiting) && (npr->waiting)) {
			opr->waiting = npr->waiting;
		}
		if (CHANGED8(npr, opr, error)) {
			auclnt_set_errors(sp, npr->error);
		}
		if (CHANGED(npr, opr, gain)) {
			auclnt_set_gain(sp, (npr->gain * 100) / AUDIO_MAX_GAIN);
		}
		if (CHANGED8(ninfo, oinfo, output_muted)) {
			auclnt_set_muted(sp, ninfo->output_muted);
		}
		if (CHANGED(npr, opr, buffer_size)) {
			/*
			 * No checks on the buffer size are performed
			 * for play side.  The value of the buffer size
			 * is meaningless for play side anyway.
			 */
			opr->buffer_size = npr->buffer_size;
		}
	} else {
		/* these values are preserved even if /dev/audio not open */
		if (CHANGED(npr, opr, gain)) {
			opr->gain = npr->gain;
		}
		if (CHANGED8(ninfo, oinfo, output_muted)) {
			oinfo->output_muted = ninfo->output_muted;
		}
	}

	if (proc->p_reader != NULL) {
		sp = auclnt_input_stream(proc->p_reader);
		npr = &ninfo->record;
		opr = &oinfo->record;

		if (CHANGED(npr, opr, sample_rate)) {
			if ((rv = auclnt_set_rate(sp, npr->sample_rate)) != 0)
				goto err;
		}
		if (CHANGED(npr, opr, channels)) {
			if ((rv = auclnt_set_channels(sp, npr->channels)) != 0)
				goto err;
		}
		if (rfmt != AUDIO_FORMAT_NONE) {
			if ((rv = auclnt_set_format(sp, rfmt)) != 0)
				goto err;
		}
		if (CHANGED(npr, opr, samples)) {
			auclnt_set_samples(sp, npr->samples);
		}
		if (CHANGED(npr, opr, eof)) {
			opr->eof = npr->eof;
		}
		if (CHANGED8(npr, opr, pause)) {
			if (npr->pause) {
				auclnt_set_paused(sp);
			} else {
				auclnt_clear_paused(sp);
				auclnt_start(sp);
			}
		}
		if (CHANGED8(npr, opr, waiting) && (npr->waiting)) {
			opr->waiting = npr->waiting;
		}
		if (CHANGED8(npr, opr, error)) {
			auclnt_set_errors(sp, npr->error);
		}
		if (CHANGED(npr, opr, buffer_size)) {
			opr->buffer_size = npr->buffer_size;
		}
		if (CHANGED(npr, opr, gain)) {
			auclnt_set_gain(sp, (npr->gain * 100) / AUDIO_MAX_GAIN);
		}
	} else {
		/* these values are preserved even if /dev/audio not open */
		if (CHANGED(npr, opr, gain)) {
			opr->gain = npr->gain;
		}
	}

	devaudio_proc_update(dc->dc_proc);
	bcopy(&dc->dc_proc->p_info, ninfo, sizeof (*ninfo));

	mutex_exit(&dc->dc_dev->d_mx);
	mcopyout(mp, NULL, sizeof (audio_info_t), uaddr, bcont);
	qreply(wq, mp);
	return;

err:
	mutex_exit(&dc->dc_dev->d_mx);
	miocnak(wq, mp, 0, rv);
}

static void
devaudio_ioc_getdev(queue_t *wq, audio_client_t *c, mblk_t *mp)
{
	audio_dev_t	*d = auclnt_get_dev(c);
	mblk_t		*bcont;
	audio_device_t	*a;

	if ((bcont = allocb(sizeof (*a), BPRI_MED)) == NULL) {
		miocnak(wq, mp, 0, ENOMEM);
		return;
	}

	a = (void *)bcont->b_wptr;
	(void) snprintf(a->name, sizeof (a->name),
	    "SUNW,%s", auclnt_get_dev_name(d));
	(void) strlcpy(a->config,
	    auclnt_get_dev_description(d), sizeof (a->config));
	(void) strlcpy(a->version,
	    auclnt_get_dev_version(d),  sizeof (a->version));
	bcont->b_wptr += sizeof (*a);

	mcopyout(mp, NULL, sizeof (*a), NULL, bcont);
	qreply(wq, mp);
}

static int
devaudio_sigpoll(audio_client_t *c, void *arg)
{
	pid_t		pid = (pid_t)(uintptr_t)arg;

	if (auclnt_get_minor_type(c) == AUDIO_MINOR_DEVAUDIOCTL) {
		/* we only need to notify peers in our own process */
		if (auclnt_get_pid(c) == pid) {
			(void) putctl1(auclnt_get_rq(c), M_PCSIG, SIGPOLL);
		}
	}
	return (AUDIO_WALK_CONTINUE);
}

static void
devaudio_drain(audio_client_t *c)
{
	daclient_t	*dc = auclnt_get_private(c);
	mblk_t		*mplist, *mp;

	mutex_enter(&dc->dc_lock);
	mplist = dc->dc_draining;
	dc->dc_draining = NULL;
	mutex_exit(&dc->dc_lock);

	while ((mp = mplist) != NULL) {
		mplist = mp->b_next;
		mp->b_next = NULL;
		mioc2ack(mp, NULL, 0, 0);
		(void) putq(auclnt_get_rq(c), mp);
	}
}

static void
devaudio_output(audio_client_t *c)
{
	daclient_t	*dc = auclnt_get_private(c);
	daproc_t	*proc = dc->dc_proc;
	uint64_t	tail;
	struct eofcnt	*eof;
	int		eofs = 0;

	tail = auclnt_get_tail(auclnt_output_stream(c));

	/* get more data! (do this early) */
	qenable(auclnt_get_wq(c));

	mutex_enter(&dc->dc_lock);
	while (((eof = list_head(&dc->dc_eofcnt)) != NULL) &&
	    (eof->tail <= tail)) {
		list_remove(&dc->dc_eofcnt, eof);
		kmem_free(eof, sizeof (*eof));
		eofs++;
	}
	proc->p_info.play.eof += eofs;
	mutex_exit(&dc->dc_lock);

	if (eofs) {
		auclnt_dev_walk_clients(auclnt_get_dev(c),
		    devaudio_sigpoll, (void *)(uintptr_t)auclnt_get_pid(c));
	}
}

static void *
devaudio_init(audio_dev_t *adev)
{
	dadev_t		*dev;
	unsigned	cap;

	cap = auclnt_get_dev_capab(adev);
	/* if not a play or record device, don't bother initializing it */
	if ((cap & (AUDIO_CLIENT_CAP_PLAY | AUDIO_CLIENT_CAP_RECORD)) == 0) {
		return (NULL);
	}

	dev = kmem_zalloc(sizeof (*dev), KM_SLEEP);
	dev->d_dev = adev;
	mutex_init(&dev->d_mx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&dev->d_cv, NULL, CV_DRIVER, NULL);
	list_create(&dev->d_procs, sizeof (struct daproc),
	    offsetof(struct daproc, p_linkage));

	return (dev);
}

static void
devaudio_fini(void *arg)
{
	dadev_t	*dev = arg;

	if (dev != NULL) {

		mutex_destroy(&dev->d_mx);
		cv_destroy(&dev->d_cv);
		list_destroy(&dev->d_procs);
		kmem_free(dev, sizeof (*dev));
	}
}

static int
devaudio_open(audio_client_t *c, int oflag)
{
	int	rv;

	if ((rv = auclnt_open(c, oflag)) != 0) {
		return (rv);
	}

	if ((rv = devaudio_proc_hold(c, oflag)) != 0) {
		auclnt_close(c);
		return (rv);
	}

	/* start up the input */
	if (oflag & FREAD) {
		auclnt_start(auclnt_input_stream(c));
	}

	return (0);
}

static int
devaudioctl_open(audio_client_t *c, int oflag)
{
	int	rv;

	_NOTE(ARGUNUSED(oflag));

	oflag &= ~(FWRITE | FREAD);

	if ((rv = auclnt_open(c, 0)) != 0) {
		return (rv);
	}

	if ((rv = devaudio_proc_hold(c, oflag)) != 0) {
		auclnt_close(c);
		return (rv);
	}

	return (0);
}

static void
devaudio_close(audio_client_t *c)
{
	auclnt_stop(auclnt_output_stream(c));
	auclnt_stop(auclnt_input_stream(c));

	auclnt_close(c);
	devaudio_proc_release(c);
}

static void
devaudioctl_close(audio_client_t *c)
{
	auclnt_close(c);
	devaudio_proc_release(c);
}

static void
devaudio_miocdata(audio_client_t *c, mblk_t *mp)
{
	struct copyresp		*csp;
	queue_t			*wq;

	csp = (void *)mp->b_rptr;
	wq = auclnt_get_wq(c);

	/*
	 * If a transfer error occurred, the framework already
	 * MIOCNAK'd it.
	 */
	if (csp->cp_rval != 0) {
		freemsg(mp);
		return;
	}

	/*
	 * If no state, then this is a response to M_COPYOUT, and we
	 * are done.  (Audio ioctls just copyout a single structure at
	 * completion of work.)
	 */
	if (csp->cp_private == NULL) {
		miocack(wq, mp, 0, 0);
		return;
	}

	/* now, call the handler ioctl */
	switch (csp->cp_cmd) {
	case AUDIO_SETINFO:
		devaudio_ioc_setinfo(wq, c, mp);
		break;
	default:
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
}

static void
devaudio_mioctl(audio_client_t *c, mblk_t *mp)
{
	struct iocblk	*iocp = (void *)mp->b_rptr;
	queue_t		*wq = auclnt_get_wq(c);

	/* BSD legacy here: we only support transparent ioctls */
	if (iocp->ioc_count != TRANSPARENT) {
		miocnak(wq, mp, 0, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {
	case AUDIO_GETINFO:
		devaudio_ioc_getinfo(wq, c, mp);
		break;

	case AUDIO_SETINFO:
		devaudio_ioc_setinfo(wq, c, mp);
		break;

	case AUDIO_GETDEV:
		devaudio_ioc_getdev(wq, c, mp);
		break;

	case AUDIO_DIAG_LOOPBACK:
		/* we don't support this one */
		miocnak(wq, mp, 0, ENOTTY);
		break;

	case AUDIO_MIXERCTL_GET_MODE:
	case AUDIO_MIXERCTL_SET_MODE:
	case AUDIO_MIXERCTL_GET_CHINFO:
	case AUDIO_MIXERCTL_SET_CHINFO:
	case AUDIO_MIXERCTL_GETINFO:
	case AUDIO_MIXERCTL_SETINFO:
	case AUDIO_GET_NUM_CHS:
	case AUDIO_GET_CH_NUMBER:
	case AUDIO_GET_CH_TYPE:
	case AUDIO_MIXER_SINGLE_OPEN:
	case AUDIO_MIXER_MULTIPLE_OPEN:
	case AUDIO_MIXER_GET_SAMPLE_RATES:
	default:
		miocnak(wq, mp, 0, EINVAL);
		break;
	}
}

static void
devaudioctl_wput(audio_client_t *c, mblk_t *mp)
{
	queue_t		*wq = auclnt_get_wq(c);

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		/* Drain ioctl needs to be handled on the service queue */
		devaudio_mioctl(c, mp);
		break;

	case M_IOCDATA:
		devaudio_miocdata(c, mp);
		break;

	case M_FLUSH:
		/*
		 * We don't flush the engine.  The reason is that
		 * other streams might be using the engine.  This is
		 * fundamentally no different from the case where the
		 * engine hardware has data buffered in an
		 * inaccessible FIFO.
		 *
		 * Clients that want to ensure no more data is coming
		 * should stop the stream before flushing.
		 */
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	case M_DATA:
		/*
		 * No audio data on control nodes!
		 */

	default:
		freemsg(mp);
		break;
	}
}

static void
devaudio_wput(audio_client_t *c, mblk_t *mp)
{
	queue_t		*wq = auclnt_get_wq(c);

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		/* Drain ioctl needs to be handled on the service queue */
		if (*(int *)(void *)mp->b_rptr == AUDIO_DRAIN) {
			(void) putq(wq, mp);
		} else {
			devaudio_mioctl(c, mp);
		}
		break;

	case M_IOCDATA:
		devaudio_miocdata(c, mp);
		break;

	case M_FLUSH:
		/*
		 * We don't flush the engine.  The reason is that
		 * other streams might be using the engine.  This is
		 * fundamentally no different from the case where the
		 * engine hardware has data buffered in an
		 * inaccessible FIFO.
		 *
		 * Clients that want to ensure no more data is coming
		 * should stop the stream before flushing.
		 */
		if (*mp->b_rptr & FLUSHW) {
			flushq(wq, FLUSHALL);
			auclnt_flush(auclnt_output_stream(c));
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(wq), FLUSHALL);
			auclnt_flush(auclnt_input_stream(c));
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	case M_DATA:
		/*
		 * Defer processing to the queue.  This keeps the data
		 * ordered, and allows the wsrv routine to gather
		 * multiple mblks at once.
		 */
		if (mp->b_cont != NULL) {

			/*
			 * If we need to pullup, do it here to
			 * simplify the rest of the processing later.
			 * This should rarely (if ever) be necessary.
			 */
			mblk_t	*nmp;

			if ((nmp = msgpullup(mp, -1)) == NULL) {
				freemsg(mp);
			} else {
				freemsg(mp);
				(void) putq(wq, nmp);
			}
		} else {
			(void) putq(wq, mp);
		}
		break;

	default:
		freemsg(mp);
		break;
	}
}

static void
devaudio_rsrv(audio_client_t *c)
{
	queue_t		*rq = auclnt_get_rq(c);
	mblk_t		*mp;

	while ((mp = getq(rq)) != NULL) {

		if ((queclass(mp) != QPCTL) && (!canputnext(rq))) {
			/*
			 * Put it back in the queue so we can apply
			 * backpressure properly.
			 */
			(void) putbq(rq, mp);
			return;
		}
		putnext(rq, mp);
	}
}

static void
devaudio_wsrv(audio_client_t *c)
{
	queue_t		*wq = auclnt_get_wq(c);
	daclient_t	*dc = auclnt_get_private(c);
	audio_stream_t	*sp;
	mblk_t		*mp;
	unsigned	framesz;

	sp = auclnt_output_stream(c);

	framesz = auclnt_get_framesz(sp);

	while ((mp = getq(wq)) != NULL) {

		unsigned	count;

		/* got a message */

		/* if its a drain ioctl, we need to process it here */
		if (DB_TYPE(mp) == M_IOCTL) {
			ASSERT((*(int *)(void *)mp->b_rptr) == AUDIO_DRAIN);
			mutex_enter(&dc->dc_lock);
			mp->b_next = dc->dc_draining;
			dc->dc_draining = mp;
			mutex_exit(&dc->dc_lock);

			if (auclnt_start_drain(c) != 0) {
				devaudio_drain(c);
			}
			continue;
		}

		ASSERT(DB_TYPE(mp) == M_DATA);

		/*
		 * Empty mblk require special handling, since they
		 * indicate EOF.  We treat them separate from the main
		 * processing loop.
		 */
		if (MBLKL(mp) == 0) {
			struct eofcnt	*eof;

			eof = kmem_zalloc(sizeof (*eof), KM_NOSLEEP);
			if (eof != NULL) {
				eof->tail = auclnt_get_head(sp);
				mutex_enter(&dc->dc_lock);
				list_insert_tail(&dc->dc_eofcnt, eof);
				mutex_exit(&dc->dc_lock);
			}
			freemsg(mp);
			continue;
		}

		count = auclnt_produce_data(sp, (caddr_t)mp->b_rptr,
		    MBLKL(mp) / framesz);

		mp->b_rptr += count * framesz;

		if (MBLKL(mp) >= framesz) {
			(void) putbq(wq, mp);
			break;
		} else {
			freemsg(mp);
		}
	}

	/* if the stream isn't running yet, start it up */
	if (!auclnt_is_paused(sp))
		auclnt_start(sp);
}

static struct audio_client_ops devaudio_ops = {
	"sound,audio",
	devaudio_init,
	devaudio_fini,
	devaudio_open,
	devaudio_close,
	NULL,	/* read */
	NULL,	/* write */
	NULL,	/* ioctl */
	NULL,	/* chpoll */
	NULL,	/* mmap */
	devaudio_input,
	devaudio_output,
	devaudio_drain,
	devaudio_wput,
	devaudio_wsrv,
	devaudio_rsrv
};

static struct audio_client_ops devaudioctl_ops = {
	"sound,audioctl",
	NULL,	/* dev_init */
	NULL,	/* dev_fini */
	devaudioctl_open,
	devaudioctl_close,
	NULL,	/* read */
	NULL,	/* write */
	NULL,	/* ioctl */
	NULL,	/* chpoll */
	NULL,	/* mmap */
	NULL,	/* output */
	NULL,	/* input */
	NULL,	/* drain */
	devaudioctl_wput,
	NULL,
	devaudio_rsrv
};

void
auimpl_sun_init(void)
{
	auclnt_register_ops(AUDIO_MINOR_DEVAUDIO, &devaudio_ops);
	auclnt_register_ops(AUDIO_MINOR_DEVAUDIOCTL, &devaudioctl_ops);
}
