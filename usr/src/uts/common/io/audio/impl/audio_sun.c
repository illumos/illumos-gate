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

typedef struct sclient sclient_t;
typedef struct sdev sdev_t;
typedef struct sproc sproc_t;
typedef struct sioc sioc_t;

typedef enum {
	COPYIN,
	COPYOUT,
	IOCTL,
	ACK,
	NAK,
	FINI
} sioc_state_t;

struct sioc {
	sclient_t		*i_sc;
	int			i_cmd;
	size_t			i_size;
	void			*i_data;
	mblk_t			*i_bcont;
	int			i_step;
	uint_t			i_model;
	sioc_state_t		i_state;
	mblk_t			*i_mp;
	caddr_t			i_addr;
	int			i_error;
};

/* common structure shared between both audioctl and audio nodes */
struct sclient {
	sproc_t			*s_proc;
	sdev_t			*s_sdev;
	audio_client_t		*s_client;
	queue_t			*s_rq;
	queue_t			*s_wq;
	ldi_handle_t		s_lh;
	unsigned		s_eof;
	list_t			s_eofcnt;
	kmutex_t		s_lock;
	mblk_t			*s_draining;
};

struct eofcnt {
	list_node_t		linkage;
	uint64_t		tail;
};

struct sdev {
	audio_dev_t		*d_dev;

	list_t			d_procs;
	kmutex_t		d_mx;
	kcondvar_t		d_cv;
};

struct sproc {
	pid_t			p_id;
	struct audio_info	p_info;
	int			p_refcnt;
	int			p_oflag;
	list_node_t		p_linkage;
	sdev_t			*p_sdev;
	sclient_t		*p_writer;
	sclient_t		*p_reader;
};

int sproc_hold(audio_client_t *, ldi_handle_t, queue_t *, int);
void sproc_release(sclient_t *);
static void sproc_update(sproc_t *);


static kmutex_t	sdev_lock;
static dev_info_t *sdev_dip;

/*
 * Alloc extra room for ioctl buffer, in case none was supplied or copyin was
 * shorter than we need for the whole struct.  On failure, returns an
 * appropriate errno, zero on success.  Any original data is preserved.
 */
static int
sioc_alloc(sioc_t *ip, size_t size)
{
	mblk_t			*nmp;

	/* if we already have enough, just use what we've got */
	if (ip->i_size >= size)
		return (0);

	if ((nmp = allocb(size, BPRI_MED)) == NULL) {
		ip->i_state = NAK;
		ip->i_error = ENOMEM;
		return (ENOMEM);
	}
	bzero(nmp->b_rptr, size);

	/* if there was already some data present, preserve it */
	if (ip->i_size != 0) {
		bcopy(ip->i_data, nmp->b_rptr, ip->i_size);
		freemsg(ip->i_bcont);
	}
	ip->i_bcont = nmp;
	ip->i_data = nmp->b_rptr;
	ip->i_size = size;

	return (0);
}

static void
sioc_copyin(sioc_t *ip, size_t size)
{
	ip->i_state = COPYIN;
	ip->i_size = size;
	if (ip->i_bcont != NULL) {
		freemsg(ip->i_bcont);
		ip->i_bcont = NULL;
	}

	mcopyin(ip->i_mp, ip, size, ip->i_addr);
}

static void
sioc_copyout(sioc_t *ip, size_t size)
{
	mblk_t			*bcont;

	ASSERT(ip->i_size >= size);

	bcont = ip->i_bcont;

	ip->i_state = COPYOUT;
	ip->i_bcont = NULL;

	mcopyout(ip->i_mp, ip, size, ip->i_addr, bcont);
}

static void
sioc_error(sioc_t *ip, int error)
{
	ip->i_state = NAK;
	ip->i_error = error;
}

static void
sioc_success(sioc_t *ip)
{
	ip->i_state = ACK;
}

static void
sioc_fini(sioc_t *ip)
{
	if (ip->i_bcont != NULL)
		freemsg(ip->i_bcont);

	kmem_free(ip, sizeof (*ip));
}

static void
sioc_finish(sioc_t *ip)
{
	mblk_t		*mp;
	sclient_t	*sc;

	sc = ip->i_sc;
	mp = ip->i_mp;
	ip->i_mp = NULL;

	switch (ip->i_state) {
	case ACK:
		miocack(sc->s_wq, mp, 0, 0);
		break;

	case IOCTL:	/* caller didn't use sioc_success */
		ip->i_error = ECANCELED;
		miocnak(sc->s_wq, mp, 0, ip->i_error);
		break;

	case NAK:
		miocnak(sc->s_wq, mp, 0, ip->i_error);
		break;

	case COPYOUT:
	case COPYIN:
		/* data copy to be done */
		qreply(sc->s_wq, mp);
		return;

	case FINI:
		if (mp != NULL) {
			freemsg(mp);
		}
		break;
	}

	sioc_fini(ip);
}

static int
sun_compose_format(audio_prinfo_t *prinfo)
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
sun_decompose_format(audio_prinfo_t *prinfo, int afmt)
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

static sproc_t *
sproc_alloc(sclient_t *sc)
{
	audio_client_t	*c;
	audio_info_t	*info;
	audio_prinfo_t	*prinfo;
	uint32_t	caps;
	sproc_t		*proc;

	c = sc->s_client;
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
sproc_free(sproc_t *proc)
{
	kmem_free(proc, sizeof (*proc));
}

int
sproc_hold(audio_client_t *c, ldi_handle_t lh, queue_t *rq, int oflag)
{
	pid_t		pid;
	sproc_t		*proc;
	sdev_t		*sdev;
	sclient_t	*sc;
	list_t		*l;
	audio_dev_t	*adev;
	int		rv;

	adev = auclnt_get_dev(c);

	/* first allocate and initialize the sclient private data */
	if ((sc = kmem_zalloc(sizeof (*sc), KM_NOSLEEP)) == NULL) {
		return (ENOMEM);
	}

	mutex_init(&sc->s_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&sc->s_eofcnt, sizeof (struct eofcnt),
	    offsetof(struct eofcnt, linkage));
	auclnt_set_private(c, sc);

	sdev = auclnt_get_dev_minor_data(adev, AUDIO_MINOR_DEVAUDIO);
	l = &sdev->d_procs;
	pid = auclnt_get_pid(c);

	/* set a couple of common fields */
	sc->s_client = c;
	sc->s_sdev = sdev;

	mutex_enter(&sdev->d_mx);
	for (proc = list_head(l); proc != NULL; proc = list_next(l, proc)) {
		if (proc->p_id == pid) {
			proc->p_refcnt++;
			break;
		}
	}
	if (proc == NULL) {
		if ((proc = sproc_alloc(sc)) == NULL) {
			rv = ENOMEM;
			goto failed;
		}
		proc->p_refcnt = 1;
		proc->p_id = pid;
		proc->p_sdev = sdev;
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
		if (cv_wait_sig(&sdev->d_cv, &sdev->d_mx) == 0) {
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
		proc->p_writer = sc;
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
		proc->p_reader = sc;
		proc->p_oflag |= FREAD;
	}

	sc->s_lh = lh;
	sc->s_rq = rq;
	sc->s_wq = WR(rq);
	WR(rq)->q_ptr = rq->q_ptr = sc;
	/* we update the s_proc last to avoid a race */
	sc->s_proc = proc;

	sproc_update(proc);

	mutex_exit(&sdev->d_mx);

	return (0);

failed:
	mutex_exit(&sdev->d_mx);
	sproc_release(sc);
	return (rv);

}

static void
sun_clear_eof(sclient_t *sc)
{
	struct eofcnt *eof;
	mutex_enter(&sc->s_lock);
	while ((eof = list_remove_head(&sc->s_eofcnt)) != NULL) {
		kmem_free(eof, sizeof (*eof));
	}
	mutex_exit(&sc->s_lock);
}

void
sproc_release(sclient_t *sc)
{
	sproc_t		*proc;
	sdev_t		*sdev;
	mblk_t		*mp;

	proc = sc->s_proc;
	sdev = sc->s_sdev;
	sc->s_proc = NULL;

	mutex_enter(&sdev->d_mx);

	if (proc != NULL) {
		proc->p_refcnt--;
		ASSERT(proc->p_refcnt >= 0);

		if (sc == proc->p_writer) {
			proc->p_oflag &= ~FWRITE;
			proc->p_writer = NULL;
		}
		if (sc == proc->p_reader) {
			proc->p_oflag &= ~FREAD;
			proc->p_reader = NULL;
		}
		cv_broadcast(&sdev->d_cv);

		if (proc->p_refcnt == 0) {
			list_remove(&sdev->d_procs, proc);
			sproc_free(proc);
		}
		sc->s_proc = NULL;
	}

	mutex_exit(&sdev->d_mx);

	sun_clear_eof(sc);

	while ((mp = sc->s_draining) != NULL) {
		sc->s_draining = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
	}

	mutex_destroy(&sc->s_lock);
	list_destroy(&sc->s_eofcnt);
	kmem_free(sc, sizeof (*sc));
}

static void
sun_sendup(audio_client_t *c)
{
	audio_stream_t	*sp = auclnt_input_stream(c);
	sclient_t	*sc = auclnt_get_private(c);
	unsigned	framesz = auclnt_get_framesz(sp);
	queue_t		*rq = sc->s_rq;
	mblk_t		*mp;
	unsigned	nbytes = sc->s_proc->p_info.record.buffer_size;
	unsigned	count = nbytes / framesz;

	/*
	 * Potentially send a message upstream with the record data.
	 * We collect this up in chunks of the buffer size requested
	 * by the client.
	 */

	while (auclnt_get_count(sp) >= count) {

		if ((!canputnext(rq)) ||
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
		putnext(rq, mp);
	}
}

static int
sun_open(audio_client_t *c, int oflag)
{
	_NOTE(ARGUNUSED(c));
	_NOTE(ARGUNUSED(oflag));
	return (0);
}

static void
sun_close(audio_client_t *c)
{
	_NOTE(ARGUNUSED(c));
}

static void
sproc_update(sproc_t *proc)
{
	audio_info_t	*info;
	audio_stream_t	*sp;
	sclient_t	*sc;

	info = &proc->p_info;

	ASSERT(mutex_owned(&proc->p_sdev->d_mx));

	if ((sc = proc->p_writer) != NULL) {
		sp = auclnt_output_stream(sc->s_client);

		info->play.sample_rate = auclnt_get_rate(sp);
		info->play.channels = auclnt_get_channels(sp);
		sun_decompose_format(&info->play, auclnt_get_format(sp));

		info->play.gain =
		    (auclnt_get_gain(sp) * AUDIO_MAX_GAIN) / 100;
		info->play.pause = auclnt_is_paused(sp);
		info->play.active = !info->play.pause;
		info->play.samples = auclnt_get_samples(sp);
		info->play.error = auclnt_get_errors(sp) ? B_TRUE : B_FALSE;
		info->output_muted = auclnt_get_muted(sp);
	}

	if ((sc = proc->p_reader) != NULL) {
		sp = auclnt_input_stream(sc->s_client);

		info->record.sample_rate = auclnt_get_rate(sp);
		info->record.channels = auclnt_get_channels(sp);
		sun_decompose_format(&info->record, auclnt_get_format(sp));

		info->record.gain =
		    (auclnt_get_gain(sp) * AUDIO_MAX_GAIN) / 100;
		info->record.pause = auclnt_is_paused(sp);
		info->record.active = !info->record.pause;
		info->record.samples = auclnt_get_samples(sp);
		info->record.error = auclnt_get_errors(sp) ? B_TRUE : B_FALSE;
	}
}

static void
sioc_getinfo(sioc_t *ip)
{
	sclient_t	*sc = ip->i_sc;
	sproc_t		*proc = sc->s_proc;
	int		rv;

	switch (ip->i_step) {
	case 0:
		if ((rv = sioc_alloc(ip, sizeof (audio_info_t))) != 0) {
			sioc_error(ip, rv);
			break;
		}

		mutex_enter(&sc->s_sdev->d_mx);
		sproc_update(proc);
		mutex_exit(&sc->s_sdev->d_mx);

		bcopy(&proc->p_info, ip->i_data, sizeof (audio_info_t));
		sioc_copyout(ip, sizeof (audio_info_t));
		break;
	case 1:
		sioc_success(ip);
		break;
	}

	ip->i_step++;
	sioc_finish(ip);
}

#define	CHANGED(new, old, field)			\
	((new->field != ((uint32_t)~0)) && (new->field != old->field))
#define	CHANGED8(new, old, field)			\
	((new->field != ((uint8_t)~0)) && (new->field != old->field))

static int
sun_setinfo(sclient_t *sc, audio_info_t *ninfo)
{
	sproc_t		*proc = sc->s_proc;
	audio_info_t	*oinfo = &proc->p_info;
	audio_prinfo_t	*npr;
	audio_prinfo_t	*opr;

	int		pfmt = AUDIO_FORMAT_NONE;
	int		rfmt = AUDIO_FORMAT_NONE;

	boolean_t	reader;
	boolean_t	writer;
	boolean_t	isctl;
	audio_stream_t	*sp;
	int		rv;

	if (auclnt_get_minor_type(sc->s_client) == AUDIO_MINOR_DEVAUDIOCTL) {
		/* control node can do both read and write fields */
		isctl = B_TRUE;
		reader = B_TRUE;
		writer = B_TRUE;
	} else {
		isctl = B_FALSE;
		writer = sc == proc->p_writer;
		reader = sc == proc->p_reader;
	}

	/*
	 * Start by validating settings.
	 */
	npr = &ninfo->play;
	opr = &oinfo->play;

	if (writer && CHANGED(npr, opr, sample_rate)) {
		if ((isctl) ||
		    (npr->sample_rate < 5500) || (npr->sample_rate > 48000)) {
			return (EINVAL);
		}
	}
	if (writer && CHANGED(npr, opr, channels)) {
		if ((isctl) || (npr->channels < 1) || (npr->channels > 2)) {
			return (EINVAL);
		}
	}
	if (writer &&
	    (CHANGED(npr, opr, encoding) || CHANGED(npr, opr, precision))) {
		if (npr->encoding == (uint32_t)~0)
			npr->encoding = opr->encoding;
		if (npr->precision == (uint32_t)~0)
			npr->precision = opr->precision;
		pfmt = sun_compose_format(npr);
		if ((isctl) || (pfmt == AUDIO_FORMAT_NONE)) {
			return (EINVAL);
		}
	}

	/* play fields that anyone can modify */
	if (CHANGED(npr, opr, gain)) {
		if (npr->gain > AUDIO_MAX_GAIN) {
			return (EINVAL);
		}
	}


	npr = &ninfo->record;
	opr = &oinfo->record;

	if (reader && CHANGED(npr, opr, sample_rate)) {
		if ((isctl) ||
		    (npr->sample_rate < 5500) ||
		    (npr->sample_rate > 48000)) {
			return (EINVAL);
		}
	}
	if (reader && CHANGED(npr, opr, channels)) {
		if ((isctl) || (npr->channels < 1) || (npr->channels > 2)) {
			return (EINVAL);
		}
	}
	if (reader &&
	    (CHANGED(npr, opr, encoding) || CHANGED(npr, opr, precision))) {
		if (npr->encoding == (uint32_t)~0)
			npr->encoding = opr->encoding;
		if (npr->precision == (uint32_t)~0)
			npr->precision = opr->precision;
		rfmt = sun_compose_format(npr);
		if ((isctl) || (rfmt == AUDIO_FORMAT_NONE)) {
			return (EINVAL);
		}
	}
	if (reader && CHANGED(npr, opr, buffer_size)) {
		if (isctl) {
			return (EINVAL);
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
			return (EINVAL);
		}
	}

	/*
	 * Now apply the changes.
	 */
	if (proc->p_writer != NULL) {
		sp = auclnt_output_stream(proc->p_writer->s_client);
		npr = &ninfo->play;
		opr = &oinfo->play;

		if (CHANGED(npr, opr, sample_rate)) {
			rv = auclnt_set_rate(sp, npr->sample_rate);
			if (rv != 0)
				return (rv);
		}
		if (CHANGED(npr, opr, channels)) {
			rv = auclnt_set_channels(sp, npr->channels);
			if (rv != 0)
				return (rv);
		}
		if (pfmt != AUDIO_FORMAT_NONE) {
			rv = auclnt_set_format(sp, pfmt);
			if (rv != 0)
				return (rv);
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
				sun_clear_eof(proc->p_writer);
			}
			opr->eof = npr->eof;
		}
		if (CHANGED8(npr, opr, pause)) {
			if (npr->pause) {
				auclnt_set_paused(sp);
			} else {
				auclnt_clear_paused(sp);
				/* qenable to start up the playback */
				qenable(proc->p_writer->s_wq);
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
		/* these vaalues are preserved even if /dev/audio not open */
		if (CHANGED(npr, opr, gain)) {
			opr->gain = npr->gain;
		}
		if (CHANGED8(ninfo, oinfo, output_muted)) {
			oinfo->output_muted = ninfo->output_muted;
		}
	}

	if (proc->p_reader != NULL) {
		sp = auclnt_input_stream(proc->p_reader->s_client);
		npr = &ninfo->record;
		opr = &oinfo->record;

		if (CHANGED(npr, opr, sample_rate)) {
			rv = auclnt_set_rate(sp, npr->sample_rate);
			if (rv != 0)
				return (rv);
		}
		if (CHANGED(npr, opr, channels)) {
			rv = auclnt_set_channels(sp, npr->channels);
			if (rv != 0)
				return (rv);
		}
		if (rfmt != AUDIO_FORMAT_NONE) {
			rv = auclnt_set_format(sp, rfmt);
			if (rv != 0)
				return (rv);
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

	return (0);
}

static void
sioc_setinfo(sioc_t *ip)
{
	int		rv;
	sclient_t	*sc = ip->i_sc;
	audio_info_t	*ninfo;

	switch (ip->i_step) {
	case 0:
		sioc_copyin(ip, sizeof (audio_info_t));
		break;

	case 1:
		ninfo = (audio_info_t *)ip->i_data;

		mutex_enter(&sc->s_sdev->d_mx);
		rv = sun_setinfo(ip->i_sc, ninfo);

		if (rv != 0) {
			sioc_error(ip, rv);
		} else {
			sproc_update(sc->s_proc);

			bcopy(&sc->s_proc->p_info, ninfo, sizeof (*ninfo));
			sioc_copyout(ip, sizeof (audio_info_t));
		}
		mutex_exit(&sc->s_sdev->d_mx);
		break;

	case 2:
		sioc_success(ip);
		break;
	}

	ip->i_step++;
	sioc_finish(ip);
}

static void
sioc_getdev(sioc_t *ip)
{
	int		rv;
	sclient_t	*sc = ip->i_sc;
	audio_client_t	*c = sc->s_client;
	audio_dev_t	*d = auclnt_get_dev(c);

	switch (ip->i_step) {
	case 0:
		rv = sioc_alloc(ip, sizeof (audio_device_t));
		if (rv == 0) {
			audio_device_t *a = ip->i_data;

			(void) snprintf(a->name, sizeof (a->name),
			    "SUNW,%s", auclnt_get_dev_name(d));
			(void) strlcpy(a->config,
			    auclnt_get_dev_description(d), sizeof (a->config));
			(void) strlcpy(a->version,
			    auclnt_get_dev_version(d),  sizeof (a->version));
			sioc_copyout(ip, sizeof (*a));
		} else {
			sioc_error(ip, rv);
		}
		break;

	case 1:
		sioc_success(ip);
		break;
	}

	ip->i_step++;
	sioc_finish(ip);
}

static void
sunstr_ioctl(sioc_t *ip)
{
	switch (ip->i_cmd) {
	case AUDIO_GETINFO:
		sioc_getinfo(ip);
		break;

	case AUDIO_SETINFO:
		sioc_setinfo(ip);
		break;

	case AUDIO_GETDEV:
		sioc_getdev(ip);
		break;

	case AUDIO_DIAG_LOOPBACK:
		/* we don't support this one */
		sioc_error(ip, ENOTTY);
		sioc_finish(ip);
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
		sioc_error(ip, EINVAL);
		sioc_finish(ip);
		break;
	}
}

static int
sun_sigpoll(audio_client_t *c, void *arg)
{
	sproc_t		*proc = arg;
	sclient_t	*sc;

	if (auclnt_get_minor_type(c) == AUDIO_MINOR_DEVAUDIOCTL) {
		sc = auclnt_get_private(c);
		/* we only need to notify peers in our own process */
		if ((sc != NULL) && (sc->s_proc == proc)) {
			(void) putnextctl1(sc->s_rq, M_PCSIG, SIGPOLL);
		}
	}
	return (AUDIO_WALK_CONTINUE);
}

static void
sun_drain(audio_client_t *c)
{
	sclient_t	*sc = auclnt_get_private(c);
	mblk_t		*mplist, *mp;

	mutex_enter(&sc->s_lock);
	mplist = sc->s_draining;
	sc->s_draining = NULL;
	mutex_exit(&sc->s_lock);

	while ((mp = mplist) != NULL) {
		mplist = mp->b_next;
		mp->b_next = NULL;
		miocack(sc->s_wq, mp, 0, 0);
	}
}

static void
sun_output(audio_client_t *c)
{
	sclient_t	*sc = auclnt_get_private(c);
	sproc_t		*proc = sc->s_proc;
	uint64_t	tail;
	struct eofcnt	*eof;
	int		eofs = 0;

	tail = auclnt_get_tail(auclnt_output_stream(c));

	/* get more data! (do this early) */
	qenable(sc->s_wq);

	mutex_enter(&sc->s_lock);
	while (((eof = list_head(&sc->s_eofcnt)) != NULL) &&
	    (eof->tail < tail)) {
		list_remove(&sc->s_eofcnt, eof);
		kmem_free(eof, sizeof (*eof));
		eofs++;
	}
	proc->p_info.play.eof += eofs;
	mutex_exit(&sc->s_lock);

	if (eofs) {
		auclnt_dev_walk_clients(auclnt_get_dev(c),
		    sun_sigpoll, proc);
	}
}

static void
sun_input(audio_client_t *c)
{
	sun_sendup(c);
}

static int
sun_create_minors(audio_dev_t *adev, void *notused)
{
	char		path[MAXPATHLEN];
	minor_t		minor;
	int		inst;
	int		index;
	const char	*driver;
	unsigned	cap;

	_NOTE(ARGUNUSED(notused));

	ASSERT(mutex_owned(&sdev_lock));

	/* don't create device nodes for sndstat device */
	cap = auclnt_get_dev_capab(adev);
	if ((cap & (AUDIO_CLIENT_CAP_PLAY | AUDIO_CLIENT_CAP_RECORD)) == 0) {
		return (AUDIO_WALK_CONTINUE);
	}

	index = auclnt_get_dev_index(adev);
	inst = auclnt_get_dev_instance(adev);
	driver = auclnt_get_dev_driver(adev);

	if (sdev_dip != NULL) {

		minor = AUDIO_MKMN(index, AUDIO_MINOR_DEVAUDIO);
		(void) snprintf(path, sizeof (path), "sound,%s,audio%d",
		    driver, inst);
		(void) ddi_create_minor_node(sdev_dip, path, S_IFCHR, minor,
		    DDI_NT_AUDIO, 0);

		minor = AUDIO_MKMN(index, AUDIO_MINOR_DEVAUDIOCTL);
		(void) snprintf(path, sizeof (path), "sound,%s,audioctl%d",
		    driver, inst);
		(void) ddi_create_minor_node(sdev_dip, path, S_IFCHR, minor,
		    DDI_NT_AUDIO, 0);
	}

	return (AUDIO_WALK_CONTINUE);
}

static int
sun_remove_minors(audio_dev_t *adev, void *notused)
{
	char		path[MAXPATHLEN];
	int		inst;
	const char	*driver;
	unsigned	cap;

	_NOTE(ARGUNUSED(notused));

	ASSERT(mutex_owned(&sdev_lock));

	cap = auclnt_get_dev_capab(adev);
	/* if not a play or record device, don't bother creating minors */
	if ((cap & (AUDIO_CLIENT_CAP_PLAY | AUDIO_CLIENT_CAP_RECORD)) == 0) {
		return (AUDIO_WALK_CONTINUE);
	}

	inst = auclnt_get_dev_instance(adev);
	driver = auclnt_get_dev_driver(adev);

	if (sdev_dip != NULL) {

		(void) snprintf(path, sizeof (path), "sound,%s,audio%d",
		    driver, inst);
		ddi_remove_minor_node(sdev_dip, path);

		(void) snprintf(path, sizeof (path), "sound,%s,audioctl%d",
		    driver, inst);
		ddi_remove_minor_node(sdev_dip, path);
	}

	return (AUDIO_WALK_CONTINUE);
}

static void *
sun_dev_init(audio_dev_t *adev)
{
	sdev_t		*sdev;
	unsigned	cap;

	cap = auclnt_get_dev_capab(adev);
	/* if not a play or record device, don't bother initializing it */
	if ((cap & (AUDIO_CLIENT_CAP_PLAY | AUDIO_CLIENT_CAP_RECORD)) == 0) {
		return (NULL);
	}

	sdev = kmem_zalloc(sizeof (*sdev), KM_SLEEP);
	sdev->d_dev = adev;
	mutex_init(&sdev->d_mx, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sdev->d_cv, NULL, CV_DRIVER, NULL);
	list_create(&sdev->d_procs, sizeof (struct sproc),
	    offsetof(struct sproc, p_linkage));

	mutex_enter(&sdev_lock);
	(void) sun_create_minors(adev, NULL);
	mutex_exit(&sdev_lock);

	return (sdev);
}

static void
sun_dev_fini(void *arg)
{
	sdev_t	*sdev = arg;

	if (sdev != NULL) {

		/* remove minor nodes */
		mutex_enter(&sdev_lock);
		(void) sun_remove_minors(sdev->d_dev, NULL);
		mutex_exit(&sdev_lock);

		mutex_destroy(&sdev->d_mx);
		cv_destroy(&sdev->d_cv);
		list_destroy(&sdev->d_procs);
		kmem_free(sdev, sizeof (*sdev));
	}
}

static struct audio_client_ops sun_ops = {
	"internal,audio",
	sun_dev_init,
	sun_dev_fini,
	sun_open,
	sun_close,
	NULL,	/* read */
	NULL,	/* write */
	NULL,	/* ioctl */
	NULL,	/* chpoll */
	NULL,	/* mmap */
	sun_input,
	sun_output,
	NULL,	/* notify */
	sun_drain,
};

static struct audio_client_ops sunctl_ops = {
	"internal,audioctl",
	NULL,	/* dev_init */
	NULL,	/* dev_fini */
	sun_open,
	sun_close,
	NULL,	/* read */
	NULL,	/* write */
	NULL,	/* ioctl */
	NULL,	/* chpoll */
	NULL,	/* mmap */
	NULL,	/* output */
	NULL,	/* input */
	NULL,	/* notify */
	NULL,	/* drain */
};

void
auimpl_sun_init(void)
{
	mutex_init(&sdev_lock, NULL, MUTEX_DRIVER, NULL);
	sdev_dip = NULL;
	auclnt_register_ops(AUDIO_MINOR_DEVAUDIO, &sun_ops);
	auclnt_register_ops(AUDIO_MINOR_DEVAUDIOCTL, &sunctl_ops);
}

/*
 * This is the operations entry points that are streams specific...
 * We map "instance" numbers.
 */

static int
sunstr_open(queue_t *rq, dev_t *devp, int flag, int sflag, cred_t *cr)
{
	int			rv;
	minor_t			minor;
	minor_t			index;
	minor_t			type;
	dev_t			physdev;
	ldi_ident_t		lid;
	ldi_handle_t		lh = NULL;
	audio_client_t		*c = NULL;
	audio_dev_t		*adev;
	unsigned		fmt;
	int			oflag;
	boolean_t		isopen = B_FALSE;

	if (sflag != 0) {
		/* no direct clone or module opens */
		return (EINVAL);
	}

	/*
	 * NB: We reuse the partitioning that the core framework is
	 * using for instance numbering.  This does mean that we are
	 * limited to at most AUDIO_MN_INST_MASK devices, but this
	 * number is sufficiently large (8192) that not to be a concern.
	 */

	minor = getminor(*devp);
	index = (minor >> AUDIO_MN_INST_SHIFT) & AUDIO_MN_INST_MASK;
	type = (minor >> AUDIO_MN_TYPE_SHIFT) & AUDIO_MN_TYPE_MASK;

	/* can't directly open a cloned node! */
	if (minor & AUDIO_MN_CLONE_MASK) {
		return (ENXIO);
	}

	switch (type) {
	case AUDIO_MINOR_DEVAUDIOCTL:
		fmt = AUDIO_FORMAT_NONE;
		oflag = flag & ~(FWRITE | FREAD);
		break;
	case AUDIO_MINOR_DEVAUDIO:
		fmt = AUDIO_FORMAT_PCM;
		oflag = flag;
		break;
	default:
		/* these minor types are not legal */
		return (ENXIO);
	}

	/* look up and hold the matching audio device */
	adev = auclnt_hold_dev_by_index(index);
	if (adev == NULL) {
		return (ENXIO);
	}
	/* find the matching physical devt */
	physdev = makedevice(ddi_driver_major(auclnt_get_dev_devinfo(adev)),
	    AUDIO_MKMN(auclnt_get_dev_instance(adev), type));

	if ((rv = ldi_ident_from_stream(rq, &lid)) == 0) {
		rv = ldi_open_by_dev(&physdev, OTYP_CHR, flag, cr, &lh, lid);
	}

	/* ldi open is done, lh holds device, and we can release our hold */
	auclnt_release_dev(adev);

	if (rv != 0) {
		goto fail;
	}
	/* phys layer clones a device for us */
	ASSERT((getminor(physdev) & AUDIO_MN_CLONE_MASK) != 0);

	/*
	 * Note: We don't need to retain the hold on the client
	 * structure, because the client is logically "held" by the
	 * open LDI handle.  We're just using this hold_by_devt to
	 * locate the associated client.
	 */
	c = auclnt_hold_by_devt(physdev);
	ASSERT(c != NULL);
	auclnt_release(c);

	if ((rv = auclnt_open(c, fmt, oflag)) != 0) {
		goto fail;
	}
	isopen = B_TRUE;

	if ((rv = sproc_hold(c, lh, rq, oflag)) != 0) {
		goto fail;
	}

	/* start up the input */
	if (oflag & FREAD) {
		auclnt_start(auclnt_input_stream(c));
	}

	/* we just reuse same minor number that phys layer used */
	*devp = makedevice(getmajor(*devp), getminor(physdev));

	qprocson(rq);

	return (0);

fail:
	if (isopen) {
		auclnt_close(c);
	}
	if (lh != NULL) {
		(void) ldi_close(lh, flag, cr);
	}

	return (rv);
}

static int
sunstr_close(queue_t *rq, int flag, cred_t *cr)
{
	sclient_t	*sc;
	audio_client_t	*c;
	int		rv;

	sc = rq->q_ptr;
	c = sc->s_client;

	if ((auclnt_get_minor_type(c) == AUDIO_MINOR_DEVAUDIO) &&
	    (ddi_can_receive_sig() || (ddi_get_pid() == 0))) {
		rv = auclnt_drain(c);
	}

	auclnt_stop(auclnt_output_stream(c));
	auclnt_stop(auclnt_input_stream(c));

	auclnt_close(c);

	qprocsoff(rq);

	(void) ldi_close(sc->s_lh, flag, cr);

	sproc_release(sc);

	return (rv);
}

static void
sunstr_miocdata(sclient_t *sc, mblk_t *mp)
{
	struct copyresp		*csp;
	sioc_t			*ip;
	mblk_t			*bcont;

	csp = (void *)mp->b_rptr;

	/*
	 * If no state, then something "bad" has happened.
	 */
	if (((ip = (void *)csp->cp_private) == NULL) || (ip->i_sc != sc)) {
		miocnak(sc->s_wq, mp, 0, EFAULT);
		return;
	}

	/*
	 * If we failed to transfer data to/from userland, then we are
	 * done.  (Stream head will have notified userland.)
	 */
	if (csp->cp_rval != 0) {
		ip->i_state = FINI;
		ip->i_mp = mp;
		sioc_finish(ip);
		return;
	}

	/*
	 * Buffer area for ioctl is attached to chain.
	 * For an ioctl that didn't have any data to copyin,
	 * we might need to allocate a new buffer area.
	 */
	bcont = mp->b_cont;
	ip->i_bcont = bcont;
	mp->b_cont = NULL;

	if (bcont != NULL) {
		ip->i_data = bcont->b_rptr;
	}

	/*
	 * Meaty part of data processing.
	 */
	ip->i_state = IOCTL;
	ip->i_mp = mp;

	/* now, call the handler ioctl */
	sunstr_ioctl(ip);
}

static void
sunstr_mioctl(sclient_t *sc, mblk_t *mp)
{
	struct iocblk	*iocp = (void *)mp->b_rptr;
	sioc_t		*ip;

	/* BSD legacy here: we only support transparent ioctls */
	if (iocp->ioc_count != TRANSPARENT) {
		miocnak(sc->s_wq, mp, 0, EINVAL);
		return;
	}

	ip = kmem_zalloc(sizeof (*ip), KM_NOSLEEP);
	if (ip == NULL) {
		miocnak(sc->s_wq, mp, 0, ENOMEM);
		return;
	}

	/* make sure everything is setup in case we need to do copyin/out */
	ip->i_sc = sc;
	ip->i_model = iocp->ioc_flag;
	ip->i_cmd = iocp->ioc_cmd;
	ip->i_addr = *(caddr_t *)(void *)mp->b_cont->b_rptr;
	ip->i_state = IOCTL;
	ip->i_mp = mp;
	freemsg(mp->b_cont);
	mp->b_cont = NULL;

	/* now, call the handler ioctl */
	sunstr_ioctl(ip);
}

static int
sunstr_wput(queue_t *wq, mblk_t *mp)
{
	sclient_t	*sc = wq->q_ptr;
	struct iocblk	*iocp;

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		/* Drain ioctl needs to be handled on the service queue */
		iocp = (void *)mp->b_rptr;
		if (iocp->ioc_cmd == AUDIO_DRAIN) {
			if (auclnt_get_minor_type(sc->s_client) ==
			    AUDIO_MINOR_DEVAUDIO) {
				(void) putq(wq, mp);
			} else {
				miocnak(wq, mp, 0, EINVAL);
			}
		} else {
			sunstr_mioctl(sc, mp);
		}
		break;

	case M_IOCDATA:
		sunstr_miocdata(sc, mp);
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
			auclnt_flush(auclnt_output_stream(sc->s_client));
			*mp->b_rptr &= ~FLUSHW;
		}
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(wq), FLUSHALL);
			auclnt_flush(auclnt_input_stream(sc->s_client));
			qreply(wq, mp);
		} else {
			freemsg(mp);
		}
		break;

	case M_DATA:
		/*
		 * If we don't have an engine, then we can't accept
		 * write() data.  audio(7i) says we just ignore it,
		 * so we toss it.
		 */
		if (auclnt_get_minor_type(sc->s_client) !=
		    AUDIO_MINOR_DEVAUDIO) {
			freemsg(mp);
		} else {
			/*
			 * Defer processing to the queue.  This keeps
			 * the data ordered, and allows the wsrv
			 * routine to gather multiple mblks at once.
			 */
			if (mp->b_cont != NULL) {

				/*
				 * If we need to pullup, do it here to
				 * simplify the rest of the processing
				 * later.  This should rarely (if
				 * ever) be necessary.
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
		}
		break;

	default:
		freemsg(mp);
		break;
	}
	return (0);
}

static int
sunstr_wsrv(queue_t *wq)
{
	sclient_t	*sc = wq->q_ptr;
	audio_client_t	*c = sc->s_client;
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
			mutex_enter(&sc->s_lock);
			mp->b_next = sc->s_draining;
			sc->s_draining = mp;
			mutex_exit(&sc->s_lock);

			if (auclnt_start_drain(c) != 0) {
				sun_drain(c);
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
				mutex_enter(&sc->s_lock);
				list_insert_tail(&sc->s_eofcnt, eof);
				mutex_exit(&sc->s_lock);
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

	return (0);
}

static int
sunstr_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	if ((cmd != DDI_ATTACH) || (dip == NULL)) {
		return (DDI_FAILURE);
	}
	if (ddi_get_instance(dip) != 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&sdev_lock);
	sdev_dip = dip;
	auclnt_walk_devs(sun_create_minors, NULL);
	mutex_exit(&sdev_lock);
	ddi_report_dev(dip);

	return (0);
}

static int
sunstr_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if ((cmd != DDI_DETACH) || (dip == NULL)) {
		return (DDI_FAILURE);
	}
	if (ddi_get_instance(dip) != 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&sdev_lock);
	/* remove all minors */
	auclnt_walk_devs(sun_remove_minors, NULL);
	sdev_dip = NULL;
	mutex_exit(&sdev_lock);

	return (0);
}

static int
sunstr_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int		error;

	_NOTE(ARGUNUSED(dip));
	_NOTE(ARGUNUSED(arg));

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = sdev_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = 0;
		error = DDI_SUCCESS;
		break;
	default:
		*result = NULL;
		error = DDI_FAILURE;
	}
	return (error);
}

static struct module_info sunstr_minfo = {
	0,		/* used for strlog(1M) only, which we don't use */
	"austr",
	0,		/* min pkt size */
	2048,		/* max pkt size */
	65536,		/* hi water */
	32768,		/* lo water */
};

static struct qinit sunstr_rqinit = {
	NULL,		/* qi_putp */
	NULL,		/* qi_srvp */
	sunstr_open,	/* qi_qopen */
	sunstr_close,	/* qi_qclose */
	NULL,		/* qi_qadmin */
	&sunstr_minfo,	/* qi_minfo */
	NULL,		/* qi_mstat */
};

static struct qinit sunstr_wqinit = {
	sunstr_wput,	/* qi_putp */
	sunstr_wsrv,	/* qi_srvp */
	NULL,		/* qi_qopen */
	NULL,		/* qi_qclose */
	NULL,		/* qi_qadmin */
	&sunstr_minfo,	/* qi_minfo */
	NULL,		/* qi_mstat */
};

static struct streamtab sunstr_strtab = {
	&sunstr_rqinit,
	&sunstr_wqinit,
	NULL,
	NULL
};

struct cb_ops sunstr_cb_ops = {
	nodev,		/* open */
	nodev,		/* close */
	nodev,		/* strategy */
	nodev,		/* print */
	nodev,		/* dump */
	nodev,		/* read */
	nodev,		/* write */
	nodev,		/* ioctl */
	nodev,		/* devmap */
	nodev,		/* mmap */
	nodev,		/* segmap */
	nochpoll,	/* chpoll */
	ddi_prop_op,	/* prop_op */
	&sunstr_strtab,	/* str */
	D_MP,		/* flag */
	CB_REV, 	/* rev */
	nodev,		/* aread */
	nodev,		/* awrite */
};

static struct dev_ops sunstr_dev_ops = {
	DEVO_REV,		/* rev */
	0,			/* refcnt */
	sunstr_getinfo,		/* getinfo */
	nulldev,		/* identify */
	nulldev,		/* probe */
	sunstr_attach,		/* attach */
	sunstr_detach,		/* detach */
	nodev,			/* reset */
	&sunstr_cb_ops,		/* cb_ops */
	NULL,			/* bus_ops */
	NULL,			/* power */
};

static struct modldrv sunstr_modldrv = {
	&mod_driverops,
	"Audio Streams Support",
	&sunstr_dev_ops,
};

static struct modlinkage sunstr_modlinkage = {
	MODREV_1,			/* MODREV_1 indicated by manual */
	&sunstr_modldrv,
	NULL
};

int
sunstr_init(void)
{
	/*
	 * NB: This *must* be called after the "audio" module's
	 * _init routine has called auimpl_sun_init().
	 */
	return (mod_install(&sunstr_modlinkage));
}

int
sunstr_fini(void)
{
	return (mod_remove(&sunstr_modlinkage));
}

int
sunstr_info(struct modinfo *modinfop)
{
	return (mod_info(&sunstr_modlinkage, modinfop));
}
