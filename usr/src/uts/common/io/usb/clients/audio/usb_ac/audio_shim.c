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

#include <sys/note.h>
#include <sys/varargs.h>
#include <sys/stream.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/taskq.h>

#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>

#include <sys/usb/usba/usbai_version.h>
#include <sys/usb/usba.h>
#include <sys/usb/clients/audio/usb_audio.h>
#include <sys/usb/clients/audio/usb_mixer.h>
#include <sys/usb/clients/audio/usb_ac/usb_ac.h>

#include "audio_shim.h"

extern void *usb_ac_statep;

extern struct cb_ops audio_cb_ops;


/*
 * The code here is a "shim" connecting legacy SADA USB drivers with the
 * Boomer audio framework, translating interfaces between the two.
 * This is an interim measure until new Boomer-native USB drivers are in place.
 */

extern void audio_dump_bytes(const uint8_t *, int);
extern void audio_dump_words(const uint16_t *, int);
extern void audio_dump_dwords(const uint32_t *, int);


#define	ASHIM_ENG_PLAY	0
#define	ASHIM_ENG_REC	1

#define	ASHIM_GET_ENG(statep, which)	(&(statep)->engines[(which)])
#define	ASHIM_ENG_DIR(engp)	\
	(((engp)->af_eflags & ENGINE_OUTPUT_CAP) ? AUDIO_PLAY : AUDIO_RECORD)

static int ashim_eng_start(ashim_eng_t *);
static void ashim_eng_stop(ashim_eng_t *);

static int ashim_af_open(void *arg, int flag,
    unsigned *fragszp, unsigned *nfragsp, caddr_t *bufp);
static void ashim_af_close(void *arg);
static uint64_t ashim_af_count(void *arg);
static int ashim_af_start(void *arg);
static void ashim_af_stop(void *arg);
static int ashim_af_format(void *arg);
static int ashim_af_channels(void *arg);
static int ashim_af_rate(void *arg);
static void ashim_af_sync(void *arg, unsigned nframes);
static size_t ashim_af_qlen(void *arg);

audio_engine_ops_t ashim_engine_ops = {
	AUDIO_ENGINE_VERSION,
	ashim_af_open,
	ashim_af_close,
	ashim_af_start,
	ashim_af_stop,
	ashim_af_count,
	ashim_af_format,
	ashim_af_channels,
	ashim_af_rate,
	ashim_af_sync,
	ashim_af_qlen,
};


#define	ASHIM_BUFSCALE_MIN	1
#define	ASHIM_BUFSCALE_MAX	2000
#define	ASHIM_BUFSCALE_DEF	10

/* engine buffer size in terms of fragments */
int ashim_bufscale = ASHIM_BUFSCALE_DEF;

/* use driver specified buffer size instead */
int ashim_use_drvbuf = 0;

/* format override */
uint_t ashim_fmt_sr = 0;
uint_t ashim_fmt_ch = 0;
uint_t ashim_fmt_prec = 0;
uint_t ashim_fmt_enc = 0; /* use SADA values e.g. AUDIO_ENCODING_LINEAR = 3 */

/* open without starting engine */
int ashim_eng_disable = 0;

/* dump audio data */
uint64_t ashim_dump_audio_start = 0;
uint64_t ashim_dump_audio_len = 0;
int ashim_dump_audio_bufsel = 0;	/* 0 = shim buf; 1 = drv/dma buf */

/* dump i/o related counters */
uint64_t ashim_dump_counters_start = 0;
uint64_t ashim_dump_counters_len = 0;

/* ignore errors when setting control values */
int ashim_ctrl_ignore_errors = 0;

/*
 * *************************************************************************
 * audio controls
 *
 * Note: we cannot determine if a SADA device truly supports play or record
 * gain adjustment until we actually try the command.  Messages showing
 * failed control updates will be printed at the DINFO ashim_debug level.
 */

#define	AUDIO_CTRL_STEREO_LEFT(v)	((uint8_t)((v) & 0xff))
#define	AUDIO_CTRL_STEREO_RIGHT(v)	((uint8_t)(((v) >> 8) & 0xff))
#define	AUDIO_CTRL_STEREO_VAL(l, r)	(((l) & 0xff) | (((r) & 0xff) << 8))

/*
 * framework gain range
 */
#define	AF_MAX_GAIN	100
#define	AF_MIN_GAIN	0

#define	AF_MAX_GAIN_ST	AUDIO_CTRL_STEREO_VAL(AF_MAX_GAIN, AF_MAX_GAIN)
#define	AF_MIN_GAIN_ST	AUDIO_CTRL_STEREO_VAL(AF_MIN_GAIN, AF_MIN_GAIN)

/*
 * convert between framework and driver gain values
 * must multiply (n) before dividing else D2F_GAIN result will be 0
 */
#define	F2D_GAIN(n)	(((n) * AUDIO_MAX_GAIN) / AF_MAX_GAIN)
#define	D2F_GAIN(n)	(((n) * AF_MAX_GAIN) / AUDIO_MAX_GAIN)

typedef struct ashim_ctrl_map ashim_ctrl_map_t;

static uint64_t ashim_ctrl_defval(ashim_state_t *statep,
    ashim_ctrl_map_t *mapp);
static int ashim_ctrl_set_defaults(ashim_state_t *statep);
static int ashim_ctrl_restore(ashim_state_t *statep);

static int ashim_ctrl_rd(void *, uint64_t *);
static int ashim_ctrl_wr_st(void *, uint64_t);
static int ashim_ctrl_wr_mn(void *, uint64_t);
static int ashim_ctrl_wr_bool(void *, uint64_t);
static int ashim_ctrl_wr_ports(void *, uint64_t);

static void ashim_rem_controls(ashim_state_t *statep);
static int ashim_add_controls(ashim_state_t *statep);


/*
 * map framework port definitions to SADA ports
 */

typedef struct {
	int		dport;
	const char	*pname;
} ashim_port_map_t;


static ashim_port_map_t ashim_play_pmap[] = {
	{AUDIO_SPEAKER,		AUDIO_PORT_SPEAKER},
	{AUDIO_HEADPHONE,	AUDIO_PORT_HEADPHONES},
	{AUDIO_LINE_OUT,	AUDIO_PORT_LINEOUT},
	{AUDIO_SPDIF_OUT,	AUDIO_PORT_SPDIFOUT},
	{AUDIO_AUX1_OUT,	AUDIO_PORT_AUX1OUT},
	{AUDIO_AUX2_OUT,	AUDIO_PORT_AUX2OUT}
};
static int ashim_play_pmap_len =
	sizeof (ashim_play_pmap) / sizeof (ashim_port_map_t);


static ashim_port_map_t ashim_rec_pmap[] = {
	{AUDIO_MICROPHONE,	AUDIO_PORT_MIC},
	{AUDIO_LINE_IN,		AUDIO_PORT_LINEIN},
	{AUDIO_CD,		AUDIO_PORT_CD},
	{AUDIO_SPDIF_IN,	AUDIO_PORT_SPDIFIN},
	{AUDIO_AUX1_IN,		AUDIO_PORT_AUX1IN},
	{AUDIO_AUX2_IN,		AUDIO_PORT_AUX2IN},
	{AUDIO_CODEC_LOOPB_IN,	AUDIO_PORT_STEREOMIX}
};
static int ashim_rec_pmap_len =
	sizeof (ashim_rec_pmap) / sizeof (ashim_port_map_t);


/*
 * map frameowork controls to SADA controls
 */
struct ashim_ctrl_map {
	int			dcmd;
	int			dir;
	audio_ctrl_desc_t	acd;
	audio_ctrl_wr_t		af_wr;
	audio_ctrl_rd_t		af_rd;
};

#define	DESC_ST(n, f)	{						\
	.acd_name = (n),						\
	.acd_type = AUDIO_CTRL_TYPE_STEREO,				\
	.acd_flags = (f) |						\
		AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE,	\
	.acd_maxvalue = AF_MAX_GAIN,					\
	.acd_minvalue = AF_MIN_GAIN,					\
}
#define	FUNC_ST		\
	&ashim_ctrl_wr_st, &ashim_ctrl_rd


#define	DESC_MN(n, f)	{						\
	.acd_name = (n),						\
	.acd_type = AUDIO_CTRL_TYPE_MONO,				\
	.acd_flags = (f) |						\
		AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE,	\
	.acd_maxvalue = AF_MAX_GAIN,					\
	.acd_minvalue = AF_MIN_GAIN,					\
}
#define	FUNC_MN		\
	&ashim_ctrl_wr_mn, &ashim_ctrl_rd


#define	DESC_BOOL(n, f)	{						\
	.acd_name = (n),						\
	.acd_type = AUDIO_CTRL_TYPE_BOOLEAN,				\
	.acd_flags = (f) |						\
		AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE,	\
	.acd_maxvalue = 1,						\
	.acd_minvalue = 0,						\
}
#define	FUNC_BOOL	\
	&ashim_ctrl_wr_bool, &ashim_ctrl_rd


#define	DESC_OUTS(n, f)	{						\
	.acd_name = AUDIO_CTRL_ID_OUTPUTS,				\
	.acd_type = AUDIO_CTRL_TYPE_ENUM,				\
	.acd_flags = (f) |						\
		AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE |	\
		AUDIO_CTRL_FLAG_MULTI,					\
	.acd_maxvalue = (n),						\
	.acd_minvalue = (n),						\
}

#define	DESC_INS(n, f)	{						\
	.acd_name = AUDIO_CTRL_ID_INPUTS,				\
	.acd_type = AUDIO_CTRL_TYPE_ENUM,				\
	.acd_flags = (f) |						\
		AUDIO_CTRL_FLAG_READABLE | AUDIO_CTRL_FLAG_WRITEABLE,	\
	.acd_maxvalue = (n),						\
	.acd_minvalue = (n),						\
}
#define	FUNC_PORTS	\
	&ashim_ctrl_wr_ports, &ashim_ctrl_rd


/*
 * sada <-> framework translation table
 * a DESC_NULL() for audio_ctrl_desc_t is used to indicate a
 * non-registered sada control that needs some initialization or be used
 * internally by the shim
 *
 * Note: currently, usb_ac only notifies the framework of play volume changes
 * from HID so the volume control the only one using AUDIO_CTRL_FLAG_POLL
 */
static ashim_ctrl_map_t ashim_ctrl_map[] = {
	{AM_SET_GAIN,		AUDIO_PLAY,
		DESC_ST(AUDIO_CTRL_ID_VOLUME, AUDIO_CTRL_FLAG_MAINVOL |
			AUDIO_CTRL_FLAG_PLAY | AUDIO_CTRL_FLAG_POLL),
		FUNC_ST},

	{AM_SET_GAIN,		AUDIO_PLAY,
		DESC_MN(AUDIO_CTRL_ID_VOLUME, AUDIO_CTRL_FLAG_MAINVOL |
			AUDIO_CTRL_FLAG_PLAY | AUDIO_CTRL_FLAG_POLL),
		FUNC_MN},

	{AM_SET_GAIN,		AUDIO_RECORD,
		DESC_ST(AUDIO_CTRL_ID_RECGAIN, AUDIO_CTRL_FLAG_RECVOL |
			AUDIO_CTRL_FLAG_REC),
		FUNC_ST},

	{AM_SET_GAIN,		AUDIO_RECORD,
		DESC_MN(AUDIO_CTRL_ID_RECGAIN, AUDIO_CTRL_FLAG_RECVOL |
			AUDIO_CTRL_FLAG_REC),
		FUNC_MN},

	{AM_SET_MONITOR_GAIN,	AUDIO_RECORD,
		DESC_MN(AUDIO_CTRL_ID_MONGAIN, AUDIO_CTRL_FLAG_MONVOL |
			AUDIO_CTRL_FLAG_MONITOR),
		FUNC_MN},

	{AM_MIC_BOOST,		AUDIO_RECORD,
		DESC_BOOL(AUDIO_CTRL_ID_MICBOOST, 0),
		FUNC_BOOL},

	{AM_SET_PORT,		AUDIO_PLAY,
		DESC_OUTS(0, 0),
		FUNC_PORTS},

	{AM_SET_PORT,		AUDIO_RECORD,
		DESC_INS(0, 0),
		FUNC_PORTS},
};
static int ashim_ctrl_map_len =
	sizeof (ashim_ctrl_map) / sizeof (ashim_ctrl_map_t);


/*
 * *************************************************************************
 * shim support routines
 */

int ashim_debug = DBG_WARN;

void
vdprint(debug_level_t lvl, const char *fmt, va_list adx)
{
	if (ashim_debug < lvl)
		return;

	vcmn_err(CE_CONT, fmt, adx);
}

void
dprint(debug_level_t lvl, const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vdprint(lvl, fmt, adx);
	va_end(adx);
}

void
dwarn(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vdprint(DBG_WARN, fmt, adx);
	va_end(adx);
}

void
dinfo(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vdprint(DBG_INFO, fmt, adx);
	va_end(adx);
}

void
ddtl(const char *fmt, ...)
{
	va_list adx;

	va_start(adx, fmt);
	vdprint(DBG_DETAIL, fmt, adx);
	va_end(adx);
}


/*
 * get the maximum format specification the device supports
 */
static void
ashim_max_fmt(ashim_state_t *statep, int dir, ashim_fmt_t *fmtp)
{
	am_ad_ch_cap_t *capp = &statep->ad_infop->ad_play;
	am_ad_cap_comb_t *combp = statep->ad_infop->ad_play_comb;

	uint_t *srs, *chs;
	uint_t sr, ch, prec, enc, val;
	int i;

	if (dir == AUDIO_RECORD) {
		capp = &statep->ad_infop->ad_record;
		combp = statep->ad_infop->ad_rec_comb;
	}
	srs = capp->ad_mixer_srs.ad_srs;
	chs = capp->ad_chs;

	for (i = 0, sr = 0; srs[i]; i++) {
		val = srs[i];
		if (val > sr)
			sr = val;
	}

	for (i = 0, ch = 0; chs[i]; i++) {
		val = chs[i];
		if (val > ch)
			ch = val;
	}

	for (i = 0, prec = 0, enc = 0; combp[i].ad_prec; i++) {
		val = combp[i].ad_prec;
		if (val > prec)
			prec = val;

		val = combp[i].ad_enc;
		if (val > enc)
			enc = val;
	}

	fmtp->sr = ashim_fmt_sr ? ashim_fmt_sr : sr;
	fmtp->ch = ashim_fmt_ch ? ashim_fmt_ch : ch;
	fmtp->prec = ashim_fmt_prec ? ashim_fmt_prec : prec;
	fmtp->enc = ashim_fmt_enc ? ashim_fmt_enc : enc;
}


/*
 * calls the driver's setup routine if present
 * For USB audio, this opens a pipe to the endpoint usb_as
 * returns AUDIO_SUCCESS or AUDIO_FAILURE
 */
static int
ashim_ad_setup(ashim_state_t *statep, int dir)
{
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;

	if (ad_entry->ad_setup == NULL)
		return (AUDIO_SUCCESS);

	return (ad_entry->ad_setup(AUDIO_SHIMST2HDL(statep), dir));
}


/*
 * calls the driver's teardown routine if present.
 * Note that the amount of teardowns must match the amount of setups used
 * in each direction.
 * returns AUDIO_SUCCESS or AUDIO_FAILURE
 */
static void
ashim_ad_teardown(ashim_state_t *statep, int dir)
{
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;

	if (ad_entry->ad_teardown != NULL)
		ad_entry->ad_teardown(AUDIO_SHIMST2HDL(statep), dir);
}


/*
 * sets the audio format (sample rate, channels, precision, encoding)
 * returns AUDIO_SUCCESS or AUDIO_FAILURE
 */
static int
ashim_set_fmt(ashim_state_t *statep, int dir, ashim_fmt_t *fmtp)
{
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;

	return (ad_entry->ad_set_format(AUDIO_SHIMST2HDL(statep), dir,
	    fmtp->sr, fmtp->ch, fmtp->prec, fmtp->enc));
}


static int
ashim_af_fmt(ashim_fmt_t *fmtp)
{
	switch (fmtp->enc) {
	case AUDIO_ENCODING_ULAW:
		return (AUDIO_FORMAT_ULAW);
	case AUDIO_ENCODING_ALAW:
		return (AUDIO_FORMAT_ALAW);
	case AUDIO_ENCODING_DVI:
		return (AUDIO_FORMAT_NONE);
	case AUDIO_ENCODING_LINEAR8:
		return (AUDIO_FORMAT_U8);
	case AUDIO_ENCODING_LINEAR:
		break;
	default:
		return (AUDIO_FORMAT_NONE);
	}

	switch (fmtp->prec) {
	case 8:
		return (AUDIO_FORMAT_S8);
	case 16:
		return (AUDIO_FORMAT_S16_NE);
	case 24:
		return (AUDIO_FORMAT_S24_NE);
	case 32:
		return (AUDIO_FORMAT_S32_NE);
	default:
		break;
	}
	return (AUDIO_FORMAT_NONE);
}


static void
ashim_rem_eng(ashim_state_t *statep, ashim_eng_t *engp)
{
	if (statep->af_devp == NULL || engp->af_engp == NULL)
		return;

	audio_dev_remove_engine(statep->af_devp, engp->af_engp);
	audio_engine_free(engp->af_engp);
	engp->af_engp = NULL;

	if (statep->engcnt > 0)
		statep->engcnt--;
}


static int
ashim_add_eng(ashim_state_t *statep, int dir)
{
	audio_dev_t *af_devp = statep->af_devp;
	ashim_eng_t *engp;
	audio_engine_t *af_engp;
	int rv = AUDIO_FAILURE;
	int which;

	if (dir == AUDIO_PLAY) {
		which = ASHIM_ENG_PLAY;
		engp = ASHIM_GET_ENG(statep, which);
		engp->af_eflags = ENGINE_OUTPUT_CAP;
		engp->prinfop = &statep->ad_infop->ad_defaults->play;
		engp->name = "PLAY";
	} else {
		which = ASHIM_ENG_REC;
		engp = ASHIM_GET_ENG(statep, which);
		engp->af_eflags = ENGINE_INPUT_CAP;
		engp->prinfop = &statep->ad_infop->ad_defaults->record;
		engp->name = "RECORD";
	}

	mutex_init(&engp->lock, NULL, MUTEX_DRIVER, NULL);

	engp->statep = statep;

	ashim_max_fmt(statep, dir, &engp->fmt);
	engp->af_fmt = ashim_af_fmt(&engp->fmt);

	af_engp = audio_engine_alloc(&ashim_engine_ops, engp->af_eflags);
	if (af_engp == NULL) {
		audio_dev_warn(af_devp, "audio_engine_alloc failed");
		goto OUT;
	}

	engp->af_engp = af_engp;
	audio_engine_set_private(af_engp, engp);
	audio_dev_add_engine(af_devp, af_engp);

	engp->flags = ENG_ENABLED;

	statep->engcnt++;
	rv = AUDIO_SUCCESS;

OUT:
	if (rv != AUDIO_SUCCESS)
		ashim_rem_eng(statep, engp);

	return (rv);
}


static int
ashim_set_config(ashim_state_t *statep, ashim_ctrl_t *ctrlp, int cmd, int dir,
    int arg1, int arg2)
{
	int (*fn)(audiohdl_t, int, int, int, int) =
	    statep->ad_infop->ad_entry->ad_set_config;

	ddtl("%s - ashim_set_config: cmd 0x%x, dir %d, arg1 0x%x, arg2 0x%x\n",
	    statep->dstr, cmd, dir, arg1, arg2);

	if (fn(AUDIO_SHIMST2HDL(statep), cmd, dir, arg1, arg2) !=
	    AUDIO_SUCCESS) {
		dinfo("%s: failed update control %s "
		    "with cmd 0x%x, dir %d, arg1 0x%x, arg2 0x%x",
		    statep->dstr, ctrlp->acd.acd_name, cmd, dir, arg1, arg2);
		return (EIO);
	}

	return (0);
}


static int
ashim_ctrl_set_defaults(ashim_state_t *statep)
{
	ashim_ctrl_t *ctrlp;
	int rv = AUDIO_SUCCESS;

	for (ctrlp = statep->controls; ctrlp; ctrlp = ctrlp->nextp) {
		if (audio_control_write(ctrlp->af_ctrlp, ctrlp->defval)) {
			dinfo("%s: setting control %s to default value "
			    "0x%llx failed\n",
			    statep->dstr, ctrlp->acd.acd_name,
			    (long long unsigned)ctrlp->defval);
			rv = AUDIO_FAILURE;
		}
	}
	return (rv);
}


static int
ashim_ctrl_restore(ashim_state_t *statep)
{
	ashim_ctrl_t *ctrlp;
	int rv = AUDIO_SUCCESS;

	for (ctrlp = statep->controls; ctrlp; ctrlp = ctrlp->nextp) {
		if (ctrlp->af_wr((void *)ctrlp, ctrlp->cval) != 0) {
			dinfo("%s: restoring "
			    "control %s to value 0x%llx failed",
			    statep->dstr, ctrlp->acd.acd_name,
			    (long long unsigned)ctrlp->cval);
			rv = AUDIO_FAILURE;
		}
	}
	return (rv);
}


static inline void
ashim_dump_audio(ashim_eng_t *engp, void *buf, int sz)
{
	if (engp->io_count >= ashim_dump_audio_start &&
	    engp->io_count - ashim_dump_audio_start < ashim_dump_audio_len) {
		int samples = sz >> engp->smszshift;
		int frames = samples >> engp->frsmshift;

		cmn_err(CE_NOTE, "\n\n======= %s - %s: REQUEST #%llu, "
		    "BUF I/O #%llu, SAMPLES %d (%d frames, %d bytes), "
		    "BUF ADDR 0x%p =======\n",
		    engp->statep->dstr, engp->name,
		    (unsigned long long)engp->io_count,
		    (unsigned long long)engp->bufio_count,
		    samples, frames, sz, buf);

		if (sz <= 0)
			return;

		switch (engp->fmt.prec) {
		case 8:
		case 24:
			audio_dump_bytes((uint8_t *)buf, sz);
			break;
		case 16:
			audio_dump_words((uint16_t *)buf, sz >> 1);
			break;
		case 32:
			audio_dump_dwords((uint32_t *)buf, sz >> 2);
			break;
		}
	}
}


static inline void
ashim_dump_counters(ashim_eng_t *engp, unsigned frames, int bufcnt)
{
	if (engp->io_count >= ashim_dump_counters_start &&
	    engp->io_count - ashim_dump_counters_start <
	    ashim_dump_counters_len) {
		int samples = frames << engp->frsmshift;
		int sz = samples << engp->smszshift;

		if (bufcnt >= 0) {
			cmn_err(CE_CONT, "======= %s - %s: buf i/o %d of "
			    "REQUEST #%llu, SAMPLES %d "
			    "(%d frames, %d bytes)\n",
			    engp->statep->dstr, engp->name, bufcnt,
			    (unsigned long long)engp->io_count, samples,
			    frames, sz);
		} else {
			cmn_err(CE_CONT, "======= %s - %s: REQUEST #%llu, "
			    "SAMPLES %d (%d frames, %d bytes)\n",
			    engp->statep->dstr, engp->name,
			    (unsigned long long)engp->io_count,
			    samples, frames, sz);
		}
	}
}


/*
 * moves data between driver buffer and framework/shim buffer
 */
static void
ashim_eng_bufio(ashim_eng_t *engp, void *buf, size_t sz)
{
	size_t cpsz = sz;
	caddr_t *src, *dst, *dp;

	if (engp->af_eflags & ENGINE_OUTPUT_CAP) {
		src = &engp->bufpos;
		dst = (caddr_t *)&buf;
	} else {
		src = (caddr_t *)&buf;
		dst = &engp->bufpos;
	}
	dp = ashim_dump_audio_bufsel ? (caddr_t *)&buf : &engp->bufpos;

	/*
	 * Wrap.  If sz is exactly the remainder of the buffer
	 * (bufpos + sz == bufendp) then the second cpsz should be 0 and so
	 * the second memcpy() should have no effect, with bufpos updated
	 * to the head of the buffer.
	 */
	if (engp->bufpos + sz >= engp->bufendp) {
		cpsz = (size_t)engp->bufendp - (size_t)engp->bufpos;
		(void) memcpy(*dst, *src, cpsz);

		if (ashim_dump_audio_len)
			ashim_dump_audio(engp, *dp, cpsz);

		buf = (caddr_t)buf + cpsz;
		engp->bufpos = engp->bufp;
		cpsz = sz - cpsz;
	}

	if (cpsz) {
		(void) memcpy(*dst, *src, cpsz);

		if (ashim_dump_audio_len)
			ashim_dump_audio(engp, *dp, cpsz);

		engp->bufpos += cpsz;
	}
	engp->bufio_count++;
}


static void
ashim_prtstats(ashim_eng_t *engp)
{
	ashim_state_t *statep = engp->statep;

	dinfo("%s - %s: driver i/o: %llu, framework i/o: %llu, "
	    "frames: %llu\n", statep->dstr, engp->name,
	    (long long unsigned)engp->io_count,
	    (long long unsigned)engp->bufio_count,
	    (long long unsigned)engp->frames);
}


/*
 * *************************************************************************
 * audio control routines
 */

static uint64_t
ashim_ctrl_defval(ashim_state_t *statep, ashim_ctrl_map_t *mapp)
{
	audio_prinfo_t *play_prp = &statep->ad_infop->ad_defaults->play;
	audio_prinfo_t *rec_prp = &statep->ad_infop->ad_defaults->record;
	const char *cname = mapp->acd.acd_name;
	uint64_t cval = 0;
	uint64_t gain;
	ashim_fmt_t fmt;

	if (strcmp(cname, AUDIO_CTRL_ID_VOLUME) == 0) {
		ashim_max_fmt(statep, AUDIO_PLAY, &fmt);
		if (fmt.ch == 0)
			return (0);

		gain = D2F_GAIN(play_prp->gain);
		if (fmt.ch == 1)
			cval = gain;
		else
			cval = AUDIO_CTRL_STEREO_VAL(gain, gain);

	} else if (strcmp(cname, AUDIO_CTRL_ID_RECGAIN) == 0) {
		ashim_max_fmt(statep, AUDIO_RECORD, &fmt);
		if (fmt.ch == 0)
			return (0);

		gain = D2F_GAIN(rec_prp->gain);
		if (fmt.ch == 1)
			cval = gain;
		else
			cval = AUDIO_CTRL_STEREO_VAL(gain, gain);

	} else if (strcmp(cname, AUDIO_CTRL_ID_MONGAIN) == 0) {
		cval = D2F_GAIN(statep->ad_infop->ad_defaults->monitor_gain);

	} else if (strcmp(cname, AUDIO_CTRL_ID_MICBOOST) == 0) {
		cval = 0;

	} else if (strcmp(cname, AUDIO_CTRL_ID_OUTPUTS) == 0) {
		cval = play_prp->port;

	} else if (strcmp(cname, AUDIO_CTRL_ID_INPUTS) == 0) {
		cval = rec_prp->port;
	}

	return (cval);
}


static ashim_ctrl_t *
ashim_find_ctrl_dcmd(ashim_state_t *statep, int dcmd, int dir)
{
	ashim_ctrl_t *ctrlp;

	for (ctrlp = statep->controls; ctrlp != NULL; ctrlp = ctrlp->nextp) {
		if (ctrlp->dcmd == dcmd && ctrlp->dir == dir)
			break;
	}
	return (ctrlp);
}


/*
 * control callback and related routines
 */

static int
ashim_ctrl_gain_mutable(ashim_ctrl_t *ctrlp, int left, int right)
{
	ashim_state_t *statep = ctrlp->statep;
	int gain;

	if (left == 0 && right == 0)
		gain = 0;
	else if (left != 0)
		gain = left;
	else
		gain = right;

	if (ctrlp->dcmd == AM_SET_GAIN && ctrlp->dir == AUDIO_PLAY) {
		/*
		 * mute when gain = 0, and on the transition when gain != 0
		 * but do not set unmute cmds during non-zero changes
		 */
		if (gain == 0) {
			ctrlp->flags |= CTRL_MUTED;

			if (ashim_set_config(statep, ctrlp, AM_OUTPUT_MUTE,
			    AUDIO_PLAY, 1, 0) != AUDIO_SUCCESS)
				return (EIO);

		} else if (ctrlp->flags & CTRL_MUTED) {
			ctrlp->flags &= ~CTRL_MUTED;

			if (ashim_set_config(statep, ctrlp, AM_OUTPUT_MUTE,
			    AUDIO_PLAY, 0, 0) != AUDIO_SUCCESS)
				return (EIO);
		}
	}

	return (0);
}


/*
 * control read callback
 */
static int
ashim_ctrl_rd(void *arg, uint64_t *cvalp)
{
	ashim_ctrl_t *ctrlp = arg;

	mutex_enter(&ctrlp->lock);
	*cvalp = ctrlp->cval;
	mutex_exit(&ctrlp->lock);

	return (0);
}


/*
 * stereo level control callback
 */
static int
ashim_ctrl_wr_st(void *arg, uint64_t cval)
{
	ashim_ctrl_t *ctrlp = arg;
	ashim_state_t *statep = ctrlp->statep;
	int rv = EIO;
	int left, right;

	ddtl("%s - control %s WRITE: 0x%llx\n", statep->dstr,
	    ctrlp->acd.acd_name, (long long unsigned)cval);

	left = AUDIO_CTRL_STEREO_LEFT(cval);
	right = AUDIO_CTRL_STEREO_RIGHT(cval);

	if (left < AF_MIN_GAIN || left > AF_MAX_GAIN ||
	    right < AF_MIN_GAIN || right > AF_MAX_GAIN) {
		dinfo("%s - control %s invalid value: 0x%llx\n", statep->dstr,
		    ctrlp->acd.acd_name, (long long unsigned)cval);
		return (EINVAL);
	}

	mutex_enter(&ctrlp->lock);
	ctrlp->cval = cval;

	left = F2D_GAIN(left);
	right = F2D_GAIN(right);

	if (ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir, left,
	    0) != AUDIO_SUCCESS)
		goto OUT;

	if (ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir, right,
	    1) != AUDIO_SUCCESS) {
		/* restore previous left gain value */
		(void) ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir,
		    left, 0);
		goto OUT;
	}

	rv = ashim_ctrl_gain_mutable(ctrlp, left, right);

OUT:
	mutex_exit(&ctrlp->lock);
	return (ashim_ctrl_ignore_errors ? 0 : rv);
}


/*
 * mono level control callback
 */
static int
ashim_ctrl_wr_mn(void *arg, uint64_t cval)
{
	ashim_ctrl_t *ctrlp = arg;
	ashim_state_t *statep = ctrlp->statep;
	int rv = EIO;
	int gain;

	ddtl("%s - control %s WRITE: 0x%llx\n", statep->dstr,
	    ctrlp->acd.acd_name, (long long unsigned)cval);

	if (cval < (uint64_t)AF_MIN_GAIN || cval > (uint64_t)AF_MAX_GAIN) {
		dinfo("%s - control %s invalid value: 0x%llx\n", statep->dstr,
		    ctrlp->acd.acd_name, (long long unsigned)cval);
		return (EINVAL);
	}

	mutex_enter(&ctrlp->lock);
	ctrlp->cval = cval;

	gain = (int)F2D_GAIN(cval);

	if (ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir,
	    gain, 0) != AUDIO_SUCCESS)
		goto OUT;

	rv = ashim_ctrl_gain_mutable(ctrlp, gain, 0);

OUT:
	mutex_exit(&ctrlp->lock);
	return (ashim_ctrl_ignore_errors ? 0 : rv);
}


/*
 * boolean control callback
 */
/*ARGSUSED*/
static int
ashim_ctrl_wr_bool(void *arg, uint64_t cval)
{
	ashim_ctrl_t *ctrlp = arg;
	ashim_state_t *statep = ctrlp->statep;
	int rv = EIO;

	ddtl("%s - control %s WRITE: 0x%llx\n", statep->dstr,
	    ctrlp->acd.acd_name, (long long unsigned)cval);

	mutex_enter(&ctrlp->lock);
	ctrlp->cval = cval;

	if (ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir,
	    (int)cval, 0) != AUDIO_SUCCESS)
		goto OUT;

	rv = 0;

OUT:
	mutex_exit(&ctrlp->lock);
	return (ashim_ctrl_ignore_errors ? 0 : rv);
}


/*
 * port selection control callback
 */
static int
ashim_ctrl_wr_ports(void *arg, uint64_t cval)
{
	ashim_ctrl_t *ctrlp = arg;
	ashim_state_t *statep = ctrlp->statep;
	int rv = EIO;
	int dports = cval & 0xff;

	ddtl("%s - control %s WRITE: 0x%llx\n", statep->dstr,
	    ctrlp->acd.acd_name, (long long unsigned)cval);

	if ((cval & ~ctrlp->acd.acd_minvalue) !=
	    (ctrlp->acd.acd_maxvalue & ~ctrlp->acd.acd_minvalue)) {
		dinfo("%s - control %s invalid value: 0x%llx\n", statep->dstr,
		    ctrlp->acd.acd_name, (long long unsigned)cval);
		return (EINVAL);
	}

	mutex_enter(&ctrlp->lock);
	ctrlp->cval = cval;

	if (ashim_set_config(statep, ctrlp, ctrlp->dcmd, ctrlp->dir, dports,
	    0) != AUDIO_SUCCESS)
		goto OUT;

	rv = 0;

OUT:
	mutex_exit(&ctrlp->lock);
	return (ashim_ctrl_ignore_errors ? 0 : rv);
}


/*
 * audio control registration related routines
 */

static ashim_ctrl_t *
ashim_ctrl_alloc(void)
{
	return (kmem_zalloc(sizeof (ashim_ctrl_t), KM_SLEEP));
}


static void
ashim_ctrl_free(ashim_ctrl_t *ctrlp)
{
	kmem_free(ctrlp, sizeof (ashim_ctrl_t));
}


static void
ashim_ctrl_insert(ashim_state_t *statep, ashim_ctrl_t *ctrlp)
{
	ctrlp->nextp = statep->controls;
	statep->controls = ctrlp;
}


/*
 * returns the amount of modifiable ports
 */
static int
ashim_ctrl_init_ports(ashim_state_t *statep, ashim_ctrl_t *ctrlp)
{
	audio_prinfo_t *prp;
	ashim_port_map_t *pmap;
	int pmaplen;
	int i;
	int count = 0;

	if (ctrlp->dir == AUDIO_PLAY) {
		prp = &statep->ad_infop->ad_defaults->play;
		pmap = ashim_play_pmap;
		pmaplen = ashim_play_pmap_len;
	} else {
		prp = &statep->ad_infop->ad_defaults->record;
		pmap = ashim_rec_pmap;
		pmaplen = ashim_rec_pmap_len;
	}

	/*
	 * look at all SADA supported ports then set the corresponding
	 * framework defined bits in the control description if the driver
	 * informs us that it is present (avail_ports) and if it can be
	 * toggled on/off (mod_ports)
	 */
	for (i = 0; i < pmaplen; i++) {
		ctrlp->acd.acd_enum[i] = pmap[i].pname;

		if (pmap[i].dport & prp->avail_ports) {
			ctrlp->acd.acd_maxvalue |= pmap[i].dport;

			dinfo("%s: available port: "
			    "driver 0x%x, framework 0x%s\n",
			    statep->dstr, pmap[i].dport, pmap[i].pname);
		}
		if (pmap[i].dport & prp->mod_ports) {
			ctrlp->acd.acd_minvalue |= pmap[i].dport;

			dinfo("%s: modifiable port: "
			    "(driver 0x%x, framework %s)\n",
			    statep->dstr, pmap[i].dport, pmap[i].pname);

			count++;
		}
	}

	return (count);
}


static void
ashim_ctrl_fini(ashim_ctrl_t *ctrlp)
{
	mutex_destroy(&ctrlp->lock);
}


/*
 * returns 0 if initialization is successful; failure to initialize is
 * not fatal so caller should deallocate and continue on to the next control
 */
static int
ashim_ctrl_init(ashim_state_t *statep, ashim_ctrl_t *ctrlp,
    ashim_ctrl_map_t *mapp)
{
	ctrlp->dcmd = mapp->dcmd;
	ctrlp->dir = mapp->dir;
	ctrlp->acd = mapp->acd;
	ctrlp->af_ctrlp = NULL;
	ctrlp->defval = ashim_ctrl_defval(statep, mapp);
	ctrlp->cval = ctrlp->defval;
	ctrlp->af_wr = mapp->af_wr;
	ctrlp->statep = statep;

	if (mapp->acd.acd_type == AUDIO_CTRL_TYPE_ENUM &&
	    ashim_ctrl_init_ports(statep, ctrlp) <= 1) {
		dinfo("%s: no more than one modifiable port detected for "
		    "control %s, enabling and skipping\n",
		    statep->dstr, ctrlp->acd.acd_name);

		(void) ctrlp->af_wr((void *)ctrlp, ctrlp->defval);
		return (1);
	}

	mutex_init(&ctrlp->lock, NULL, MUTEX_DRIVER, NULL);
	return (0);
}


/*
 * heuristic to determine if a control is actually present by writing the
 * default value and checking if the operation succeeds
 */
/*ARGSUSED*/
static int
ashim_ctrl_test(ashim_state_t *statep, ashim_ctrl_t *ctrlp)
{
	return (ctrlp->af_wr((void *)ctrlp, ctrlp->defval));
}


static void
ashim_rem_controls(ashim_state_t *statep)
{
	ashim_ctrl_t *ctrlp = statep->controls;
	ashim_ctrl_t *nextp;

	while (ctrlp != NULL) {
		if (ctrlp->af_ctrlp != NULL)
			audio_dev_del_control(ctrlp->af_ctrlp);

		nextp = ctrlp->nextp;
		ashim_ctrl_fini(ctrlp);
		ashim_ctrl_free(ctrlp);
		ctrlp = nextp;
	}

	/* required */
	statep->controls = NULL;
}


static int
ashim_add_controls(ashim_state_t *statep)
{
	int rv = AUDIO_FAILURE;
	int i;
	ashim_ctrl_map_t *mapp;
	ashim_ctrl_t *ctrlp;
	audio_ctrl_t *af_ctrlp;
	ashim_fmt_t playfmt = {0};
	ashim_fmt_t recfmt = {0};
	ashim_fmt_t *fmtp;
	int ad_feat = statep->ad_infop->ad_defaults->hw_features;

	if (ad_feat & AUDIO_HWFEATURE_PLAY)
		ashim_max_fmt(statep, AUDIO_PLAY, &playfmt);

	if (ad_feat & AUDIO_HWFEATURE_RECORD)
		ashim_max_fmt(statep, AUDIO_RECORD, &recfmt);

	for (i = 0; i < ashim_ctrl_map_len; i++) {
		mapp = &ashim_ctrl_map[i];
		fmtp = NULL;

		if (mapp->dir == AUDIO_PLAY) {
			if (!(ad_feat & AUDIO_HWFEATURE_PLAY))
				continue;

			fmtp = &playfmt;
		}
		if (mapp->dir == AUDIO_RECORD) {
			if (!(ad_feat & AUDIO_HWFEATURE_RECORD))
				continue;

			fmtp = &recfmt;
		}

		if (mapp->dcmd == AM_SET_GAIN) {
			if (fmtp->ch == 0)
				continue;

			if (mapp->acd.acd_type == AUDIO_CTRL_TYPE_MONO &&
			    fmtp->ch != 1)
				continue;

			if (mapp->acd.acd_type == AUDIO_CTRL_TYPE_STEREO &&
			    fmtp->ch != 2)
				continue;
		}

		ctrlp = ashim_ctrl_alloc();

		if (ashim_ctrl_init(statep, ctrlp, mapp)) {
			ashim_ctrl_free(ctrlp);
			continue;
		}

		if (ashim_ctrl_test(statep, ctrlp)) {
			dinfo("%s: control %s tested invalid, ignoring\n",
			    statep->dstr, ctrlp->acd.acd_name);

			ashim_ctrl_fini(ctrlp);
			ashim_ctrl_free(ctrlp);
			continue;
		}

		af_ctrlp = audio_dev_add_control(statep->af_devp, &ctrlp->acd,
		    mapp->af_rd, mapp->af_wr, (void *)ctrlp);

		if (af_ctrlp == NULL) {
			audio_dev_warn(statep->af_devp, "failed to add "
			    "control %s", ctrlp->acd.acd_name);
			ashim_ctrl_fini(ctrlp);
			ashim_ctrl_free(ctrlp);
			goto OUT;
		}

		dinfo("%s: added control %s, type: %d, "
		    "flags: 0x%x, min: 0x%llx, max: 0x%llx, default: 0x%llx\n",
		    statep->dstr, ctrlp->acd.acd_name, ctrlp->acd.acd_type,
		    ctrlp->acd.acd_flags,
		    ctrlp->acd.acd_minvalue, ctrlp->acd.acd_maxvalue,
		    ctrlp->defval);

		ctrlp->af_ctrlp = af_ctrlp;
		ashim_ctrl_insert(statep, ctrlp);
	}

	rv = AUDIO_SUCCESS;

OUT:
	if (rv != AUDIO_SUCCESS)
		ashim_rem_controls(statep);
	return (rv);
}


/*
 * **************************************************************************
 * replacements for SADA framework interfaces
 */

void *
audio_sup_get_private(audiohdl_t handle)
{
	return (AUDIO_HDL2SHIMST(handle)->private);
}


void
audio_sup_set_private(audiohdl_t handle, void *private)
{
	AUDIO_HDL2SHIMST(handle)->private = private;
}


int
audio_sup_unregister(audiohdl_t handle)
{
	ashim_state_t *statep;

	if (handle == NULL)
		return (AUDIO_SUCCESS);

	statep = AUDIO_HDL2SHIMST(handle);

	kmem_free(statep, sizeof (*statep));
	return (AUDIO_SUCCESS);
}


audiohdl_t
audio_sup_register(dev_info_t *dip)
{
	ashim_state_t *statep = NULL;
	int inst;
	const char *nm;

	statep = kmem_zalloc(sizeof (*statep), KM_SLEEP);
	statep->dip = dip;

	inst = ddi_get_instance(dip);
	nm = ddi_driver_name(dip);

	(void) snprintf(statep->dstr, sizeof (statep->dstr),
	    "%s#%d", nm, inst);

	return (AUDIO_SHIMST2HDL(statep));
}


int
am_unregister(audiohdl_t handle)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);

	if (statep->af_devp == NULL)
		return (AUDIO_SUCCESS);

	if (statep->flags & AF_REGISTERED) {
		if (audio_dev_unregister(statep->af_devp) != DDI_SUCCESS) {
			dwarn("%s: am_unregister: audio_dev_unregister() "
			    "failed\n", statep->dstr);

			return (AUDIO_FAILURE);
		}
		statep->flags &= ~AF_REGISTERED;
	}

	return (AUDIO_SUCCESS);
}


/*ARGSUSED*/
int
am_detach(audiohdl_t handle, ddi_detach_cmd_t cmd)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	int i;

	if (statep == NULL)
		return (AUDIO_SUCCESS);

	if (statep->af_devp == NULL)
		return (AUDIO_SUCCESS);

	if ((statep->flags & AF_REGISTERED) &&
	    audio_dev_unregister(statep->af_devp) != DDI_SUCCESS) {
		dwarn("%s: am_detach: audio_dev_unregister() failed\n",
		    statep->dstr);
		return (AUDIO_FAILURE);
	}
	statep->flags &= ~AF_REGISTERED;

	for (i = 0; i < statep->engcnt; i++)
		ashim_rem_eng(statep, &statep->engines[i]);

	if (statep->controls != NULL)
		ashim_rem_controls(statep);

	audio_dev_free(statep->af_devp);
	statep->af_devp = NULL;

	return (AUDIO_SUCCESS);
}


int
am_attach(audiohdl_t handle, ddi_attach_cmd_t cmd,
    am_ad_info_t *ad_infop)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	audio_dev_t *af_devp;
	int ad_feat = ad_infop->ad_defaults->hw_features;
	int rv = AUDIO_FAILURE;

	if (cmd != DDI_ATTACH)
		return (AUDIO_FAILURE);

	af_devp = audio_dev_alloc(statep->dip, 0);
	audio_dev_set_description(af_devp, ad_infop->ad_dev_info->name);
	audio_dev_set_version(af_devp, ad_infop->ad_dev_info->version);

	statep->af_devp = af_devp;
	statep->ad_infop = ad_infop;

	/*
	 * setup the engines
	 */
	statep->engcnt = 0;

	/*
	 * If the device supports both play and record we require duplex
	 * functionality.  However, there are no known simplex SADA devices.
	 * In this case we limit the device to play only.
	 */
	if ((ad_feat & AUDIO_HWFEATURE_PLAY) &&
	    (ad_feat & AUDIO_HWFEATURE_RECORD) &&
	    !(ad_feat & AUDIO_HWFEATURE_DUPLEX)) {
		audio_dev_warn(af_devp, "missing duplex feature "
		    "required for record");

		ad_feat &= ~AUDIO_HWFEATURE_RECORD;
		ad_infop->ad_defaults->hw_features = ad_feat;
	}

	if (ad_feat & AUDIO_HWFEATURE_PLAY) {
		if (ashim_add_eng(statep, AUDIO_PLAY) != AUDIO_SUCCESS)
			goto OUT;
	}
	if (ad_feat & AUDIO_HWFEATURE_RECORD) {
		if (ashim_add_eng(statep, AUDIO_RECORD) != AUDIO_SUCCESS)
			goto OUT;
	}

	if (ashim_add_controls(statep) != AUDIO_SUCCESS)
		goto OUT;

	if (ashim_ctrl_set_defaults(statep) != AUDIO_SUCCESS)
		goto OUT;

	if (audio_dev_register(af_devp) != DDI_SUCCESS) {
		audio_dev_warn(af_devp, "audio_dev_register() failed");
		goto OUT;
	}
	statep->flags |= AF_REGISTERED;

	rv = AUDIO_SUCCESS;

OUT:
	if (rv != AUDIO_SUCCESS)
		(void) am_detach(handle, DDI_DETACH);
	return (rv);
}


int
am_get_audio(audiohdl_t handle, void *buf, int samples)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	ashim_eng_t *engp = ASHIM_GET_ENG(statep, ASHIM_ENG_PLAY);
	unsigned reqframes = samples >> engp->frsmshift;
	unsigned frames;
	unsigned i;
	size_t sz;
	int bufcnt = 0;
	caddr_t bp = buf;

	mutex_enter(&engp->lock);
	if (ashim_dump_counters_len)
		ashim_dump_counters(engp, reqframes, -1);

	if (!(engp->flags & ENG_STARTED)) {
		ddtl("%s - am_get_audio: stop in progress, ignoring\n",
		    statep->dstr);
		mutex_exit(&engp->lock);
		return (0);
	}
	mutex_exit(&engp->lock);

	/* break requests from the driver into fragment sized chunks */
	for (i = 0; i < reqframes; i += frames) {
		mutex_enter(&engp->lock);

		frames = reqframes - i;
		if (frames > engp->fragfr)
			frames = engp->fragfr;

		sz = (frames << engp->frsmshift) << engp->smszshift;

		if (ashim_dump_counters_len) {
			ashim_dump_counters(engp, frames, bufcnt);
		}
		bufcnt++;

		/* must move data before updating framework */
		ashim_eng_bufio(engp, bp, sz);
		engp->frames += frames;
		bp += sz;

		mutex_exit(&engp->lock);
		audio_engine_consume(engp->af_engp);
	}

	mutex_enter(&engp->lock);
	engp->io_count++;
	mutex_exit(&engp->lock);

	return (samples);
}


void
am_play_shutdown(audiohdl_t handle)
{

	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;

	ad_entry->ad_stop_play(handle);

	/*
	 * XXX
	 * used to notify framework that device's engine has stopped
	 */
}


void
am_send_audio(audiohdl_t handle, void *buf, int samples)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	ashim_eng_t *engp = ASHIM_GET_ENG(statep, ASHIM_ENG_REC);
	unsigned reqframes = samples >> engp->frsmshift;
	unsigned frames;
	unsigned i;
	size_t sz;
	int bufcnt = 0;
	caddr_t bp = buf;

	mutex_enter(&engp->lock);
	if (ashim_dump_counters_len)
		ashim_dump_counters(engp, reqframes, -1);

	if (!(engp->flags & ENG_STARTED)) {
		ddtl("%s - am_send_audio: stop in progress, ignoring\n",
		    statep->dstr);

		mutex_exit(&engp->lock);
		return;
	}
	mutex_exit(&engp->lock);

	/* break requests from the driver into fragment sized chunks */
	for (i = 0; i < reqframes; i += frames) {
		mutex_enter(&engp->lock);

		frames = reqframes - i;
		if (frames > engp->fragfr)
			frames = engp->fragfr;

		sz = (frames << engp->frsmshift) << engp->smszshift;

		if (ashim_dump_counters_len)
			ashim_dump_counters(engp, frames, bufcnt);
		bufcnt++;

		/* must move data before updating framework */
		ashim_eng_bufio(engp, bp, sz);
		engp->frames += frames;
		bp += sz;

		mutex_exit(&engp->lock);
		audio_engine_produce(engp->af_engp);
	}

	mutex_enter(&engp->lock);
	engp->io_count++;
	mutex_exit(&engp->lock);
}

void
audio_sup_restore_state(audiohdl_t handle)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	ashim_eng_t *engp;
	int i;
	int start = 0;

	(void) ashim_ctrl_restore(statep);

	for (i = 0; i < statep->engcnt; i++) {
		engp = &statep->engines[i];

		mutex_enter(&engp->lock);
		start = (engp->flags & ENG_STARTED);
		mutex_exit(&engp->lock);

		if (start)
			(void) ashim_eng_start(engp);
	}
}


/*
 * **************************************************************************
 * audio framework engine callbacks
 */

/*ARGSUSED*/
static int
ashim_af_open(void *arg, int flag,
    unsigned *fragfrp, unsigned *nfragsp, caddr_t *bufp)
{
	ashim_eng_t *engp = (ashim_eng_t *)arg;
	ashim_state_t *statep = engp->statep;
	int rv = EIO;
	int dir = ASHIM_ENG_DIR(engp);


	if (usb_ac_open(statep->dip) != AUDIO_SUCCESS) {
		audio_dev_warn(statep->af_devp, "usb_ac_open failed");
		return (EIO);
	}

	mutex_enter(&engp->lock);

	if (ashim_set_fmt(statep, dir, &engp->fmt) != AUDIO_SUCCESS) {
		audio_dev_warn(statep->af_devp, "set format failed");
		goto OUT;
	}

	engp->intrate = (engp->af_eflags & ENGINE_OUTPUT_CAP) ?
	    statep->ad_infop->ad_play.ad_int_rate :
	    statep->ad_infop->ad_record.ad_int_rate;

	engp->sampsz = engp->fmt.prec / 8;
	engp->framesz = engp->sampsz * engp->fmt.ch;

	if (engp->fmt.ch > 2) {
		audio_dev_warn(statep->af_devp, "unsupported ",
		    "channel count: %u", engp->fmt.ch);
		goto OUT;
	}
	if (engp->fmt.prec > 16) {
		audio_dev_warn(statep->af_devp, "unsupported ",
		    "precision: %u", engp->fmt.prec);
		goto OUT;
	}

	engp->frsmshift = engp->fmt.ch / 2;
	engp->smszshift = engp->sampsz / 2;

	/*
	 * In order to match the requested number of samples per interrupt
	 * from SADA drivers when computing the fragment size,
	 * we need to first truncate the floating point result from
	 *	sample rate * channels / intr rate
	 * then adjust up to an even number, before multiplying it
	 * with the sample size
	 */
	engp->fragsz = engp->fmt.sr * engp->fmt.ch / engp->intrate;
	if (engp->fragsz & 1)
		engp->fragsz++;
	engp->fragsz *= engp->sampsz;
	engp->fragfr = engp->fragsz / engp->framesz;

	if (ashim_use_drvbuf) {
		engp->bufsz = ((engp)->af_eflags & ENGINE_OUTPUT_CAP) ?
		    statep->ad_infop->ad_play.ad_bsize :
		    statep->ad_infop->ad_record.ad_bsize;

		engp->nfrags = engp->bufsz / engp->fragsz;

		/* adjust buf size to frag boundary */
		if (engp->nfrags * engp->fragsz < engp->bufsz)
			engp->nfrags++;

		engp->bufsz = engp->nfrags * engp->fragsz;
	} else {
		if (ashim_bufscale < ASHIM_BUFSCALE_MIN ||
		    ashim_bufscale > ASHIM_BUFSCALE_MAX)
			engp->nfrags = ASHIM_BUFSCALE_DEF;
		else
			engp->nfrags = ashim_bufscale;
		engp->bufsz = engp->fragsz * engp->nfrags;
	}

	engp->bufp = kmem_zalloc(engp->bufsz, KM_SLEEP);
	engp->bufpos = engp->bufp;
	engp->bufendp = engp->bufp + engp->bufsz;
	engp->frames = 0;
	engp->io_count = 0;
	engp->bufio_count = 0;

	*fragfrp = engp->fragfr;
	*nfragsp = engp->nfrags;
	*bufp = engp->bufp;

	if (ashim_ad_setup(statep, dir) != AUDIO_SUCCESS) {
		audio_dev_warn(statep->af_devp, "device setup failed");
		goto OUT;
	}
	statep->flags |= AD_SETUP;

	rv = 0;

	dinfo("%s - %s: "
	    "frames per frag: %u, frags in buffer: %u, frag size: %u, "
	    "intr rate: %u, buffer size: %u, buffer: 0x%p - 0x%p\n",
	    statep->dstr, engp->name,
	    *fragfrp, *nfragsp, engp->fragsz,
	    engp->intrate, engp->bufsz, *bufp, engp->bufendp);

OUT:
	mutex_exit(&engp->lock);
	if (rv != 0)
		ashim_af_close(arg);

	return (rv);
}


static void
ashim_af_close(void *arg)
{
	ashim_eng_t *engp = (ashim_eng_t *)arg;
	ashim_state_t *statep = engp->statep;

	mutex_enter(&engp->lock);

	if (statep->flags & AD_SETUP) {
		ashim_ad_teardown(statep, ASHIM_ENG_DIR(engp));
		statep->flags &= ~AD_SETUP;
	}

	if (engp->bufp != NULL) {
		kmem_free(engp->bufp, engp->bufsz);
		engp->bufp = NULL;
		engp->bufpos = NULL;
		engp->bufendp = NULL;
	}

	ashim_prtstats(engp);
	mutex_exit(&engp->lock);

	usb_ac_close(statep->dip);
}


static int
ashim_eng_start(ashim_eng_t *engp)
{
	ashim_state_t *statep = engp->statep;
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;
	int (*start)(audiohdl_t);
	int rv = 0;

	start = ((engp)->af_eflags & ENGINE_OUTPUT_CAP) ?
	    ad_entry->ad_start_play : ad_entry->ad_start_record;

	dinfo("%s: starting device %s engine\n", statep->dstr, engp->name);

	if ((*start)(AUDIO_SHIMST2HDL(statep)) != AUDIO_SUCCESS) {
		audio_dev_warn(statep->af_devp, "failed to start %s engine",
		    engp->name);
		rv = EIO;
	}

	return (rv);
}


static void
ashim_eng_stop(ashim_eng_t *engp)
{
	ashim_state_t *statep = engp->statep;
	am_ad_entry_t *ad_entry = statep->ad_infop->ad_entry;
	void (*stop)(audiohdl_t);

	stop = ((engp)->af_eflags & ENGINE_OUTPUT_CAP) ?
	    ad_entry->ad_stop_play : ad_entry->ad_stop_record;

	dinfo("%s: stopping device %s engine\n", statep->dstr, engp->name);

	(*stop)(AUDIO_SHIMST2HDL(statep));
}


static int
ashim_af_start(void *arg)
{
	ashim_eng_t *engp = (ashim_eng_t *)arg;
	int rv = EIO;

	if (ashim_eng_disable)
		return (rv);

	mutex_enter(&engp->lock);
	engp->flags |= ENG_STARTED;
	mutex_exit(&engp->lock);

	rv = ashim_eng_start(engp);

	return (rv);
}


static void
ashim_af_stop(void *arg)
{
	ashim_eng_t *engp = (ashim_eng_t *)arg;

	mutex_enter(&engp->lock);
	engp->flags &= ~ENG_STARTED;
	mutex_exit(&engp->lock);

	ashim_eng_stop(engp);
}


static uint64_t
ashim_af_count(void *arg)
{
	ashim_eng_t	*engp = arg;
	uint64_t	val;

	mutex_enter(&engp->lock);
	val = engp->frames;
	mutex_exit(&engp->lock);

	return (val);
}


static int
ashim_af_format(void *arg)
{
	ashim_eng_t *engp = arg;

	return (engp->af_fmt);
}

static int
ashim_af_channels(void *arg)
{
	ashim_eng_t *engp = arg;

	return (engp->fmt.ch);
}


static int
ashim_af_rate(void *arg)
{
	ashim_eng_t *engp = arg;

	return (engp->fmt.sr);
}


/*ARGSUSED*/
static void
ashim_af_sync(void *arg, unsigned nframes)
{
	/*
	 * drivers will call ddi_dma_sync() themselves after requesting data
	 * on playback and before sending data on record through the shim
	 */
}


static size_t
ashim_af_qlen(void *arg)
{
	ashim_eng_t *engp = (ashim_eng_t *)arg;

	return (engp->fragfr);
}


/*
 * **************************************************************************
 * interfaces used by USB audio
 */

/*ARGSUSED*/
int
am_hw_state_change(audiohdl_t handle, int cmd, int dir, int value,
    int sleep)
{
	ashim_state_t *statep = AUDIO_HDL2SHIMST(handle);
	ashim_ctrl_t *ctrlp;
	uint64_t cval = 0;
	int64_t left, right, delta = 0;
	int dcmd = AM_SET_GAIN;

	/* only known HWSC command used */
	if (cmd != AM_HWSC_SET_GAIN_DELTA) {
		audio_dev_warn(statep->af_devp, "invalid HW state change "
		    "command recieved");
		return (AUDIO_FAILURE);
	}

	ctrlp = ashim_find_ctrl_dcmd(statep, dcmd, dir);
	if (ctrlp == NULL) {
		audio_dev_warn(statep->af_devp, "driver control command %d "
		    "not found for HW state change command %d", dcmd, cmd);
		return (AUDIO_FAILURE);
	}

	mutex_enter(&ctrlp->lock);

	delta = D2F_GAIN(value);
	left = AUDIO_CTRL_STEREO_LEFT(ctrlp->cval) + delta;
	right = AUDIO_CTRL_STEREO_RIGHT(ctrlp->cval) + delta;

	if (left > AF_MAX_GAIN)
		left = AF_MAX_GAIN;
	if (right > AF_MAX_GAIN)
		right = AF_MAX_GAIN;

	if (left < AF_MIN_GAIN)
		left = AF_MIN_GAIN;
	if (right < AF_MIN_GAIN)
		right = AF_MIN_GAIN;

	cval = AUDIO_CTRL_STEREO_VAL(left, right);
	mutex_exit(&ctrlp->lock);

	if (audio_control_write(ctrlp->af_ctrlp, cval)) {
		audio_dev_warn(statep->af_devp, "updating "
		    "control %s to value 0x%llx by driver failed",
		    ctrlp->acd.acd_name, (long long unsigned)cval);
		return (AUDIO_FAILURE);
	}
	return (AUDIO_SUCCESS);
}
