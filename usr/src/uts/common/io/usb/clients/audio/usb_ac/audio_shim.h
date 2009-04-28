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


#ifndef	_AUDIO_SHIM_H
#define	_AUDIO_SHIM_H

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/audio.h>
#include <sys/audio/audio_support.h>
#include <sys/mixer.h>
#include <sys/audio/audio_mixer.h>

#include <sys/audio/audio_driver.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {DBG_WARN = 1, DBG_INFO, DBG_DETAIL} debug_level_t;

void vdprint(debug_level_t lvl, const char *fmt, va_list adx);
void dprint(debug_level_t lvl, const char *fmt, ...);
void dwarn(const char *fmt, ...);
void dinfo(const char *fmt, ...);
void ddtl(const char *fmt, ...);


int am_unregister(audiohdl_t handle);

#define	CTRL_MUTED	0x1		/* muted output gain */

#define	TQ_NM_MAX	64
#define	DSTR_MAX	64

typedef struct ashim_config_arg ashim_config_arg_t;
typedef struct ashim_ctrl ashim_ctrl_t;
typedef struct ashim_fmt ashim_fmt_t;
typedef struct ashim_eng ashim_eng_t;
typedef struct ashim_state ashim_state_t;

struct ashim_config_arg {
	int		cmd;
	int		dir;
	int		arg1;
	int		arg2;
};

struct ashim_ctrl {
	int			dcmd;		/* SADA command */
	int			dir;		/* play or record */
	audio_ctrl_desc_t	acd;		/* description */
	audio_ctrl_t		*af_ctrlp;	/* framework handle */
	uint64_t		cval;		/* current control value */
	uint64_t		defval;		/* default control value */
	audio_ctrl_wr_t		af_wr;		/* write callback */

	int			flags;		/* CTRL_XXX flags */
	kmutex_t		lock;

	ashim_state_t		*statep;
	ashim_ctrl_t		*nextp;
};

struct ashim_fmt {
	int		sr;	/* sample rate */
	uint_t		ch;	/* channels */
	uint_t		prec;	/* precision */
	uint_t		enc;	/* encoding */
};

struct ashim_eng {
	ashim_state_t	*statep;
	audio_engine_t	*af_engp;
	int		af_eflags;	/* ENGINE_* flags */
	int		af_fmt;		/* AUDIO_FORMAT_* flags */
	ashim_fmt_t	fmt;

	unsigned	intrate;	/* interrupt rate */
	unsigned	sampsz;		/* sample size */
	unsigned	framesz;	/* frame size */
	unsigned	fragsz;		/* fragment size */
	unsigned	nfrags;		/* number of fragments in buffer */
	unsigned	fragfr;		/* number of frames per fragment */
	unsigned	frsmshift;	/* right shift: frames in sample cnt */
	unsigned	smszshift;	/* left shift: sample cnt * sampsz */

	caddr_t		bufp;		/* I/O buf; framework to/from drv */
	unsigned	bufsz;		/* buffer size */
	caddr_t		bufpos;		/* buffer position */
	caddr_t		bufendp;	/* end of buffer */

	audio_prinfo_t	*prinfop;	/* SADA ad_defaults play/record */

	uint64_t	frames;		/* total frames processed since open */
	uint64_t	io_count;	/* i/o requests from the driver */
	uint64_t	bufio_count;	/* i/o requests to the framework */
	char		*name;

#define	ENG_STARTED	0x1
#define	ENG_ENABLED	0x10
	int		flags;

	kmutex_t	lock;
};

struct ashim_state {
	dev_info_t	*dip;
	void		*private;	/* private audio driver data */
	audio_dev_t	*af_devp;
	am_ad_info_t	*ad_infop;

#define	ASHIM_ENG_MAX	2
	ashim_eng_t	engines[ASHIM_ENG_MAX];
	int		engcnt;

	ashim_ctrl_t	*controls;

	char		*devnm;
	char		dstr[DSTR_MAX];

#define	AF_REGISTERED	0x1
#define	AD_SETUP	0x10
	int		flags;
};

/*
 * Macros used to convert between audio handles and the shim state structure.
 */
#define	AUDIO_HDL2SHIMST(hdl)		((ashim_state_t *)(hdl))
#define	AUDIO_SHIMST2HDL(statep)	((audiohdl_t)(statep))


#ifdef	__cplusplus
}
#endif

#endif /* _AUDIO_SHIM_H */
