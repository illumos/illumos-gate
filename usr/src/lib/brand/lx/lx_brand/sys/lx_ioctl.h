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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_LX_IOCTL_H
#define	_SYS_LX_IOCTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

extern int lx_ioctl_init(void);

/*
 * LX_NCC must be different from LX_NCCS since while the termio and termios
 * structures may look similar they are fundamentally different sizes and
 * have different members.
 */
#define	LX_NCC	8
#define	LX_NCCS	19

struct lx_termio {
	unsigned short c_iflag;		/* input mode flags */
	unsigned short c_oflag;		/* output mode flags */
	unsigned short c_cflag;		/* control mode flags */
	unsigned short c_lflag;		/* local mode flags */
	unsigned char c_line;		/* line discipline */
	unsigned char c_cc[LX_NCC];	/* control characters */
};

struct lx_termios {
	uint32_t c_iflag;		/* input mode flags */
	uint32_t c_oflag;		/* output mode flags */
	uint32_t c_cflag;		/* control mode flags */
	uint32_t c_lflag;		/* local mode flags */
	unsigned char c_line;		/* line discipline */
	unsigned char c_cc[LX_NCCS];	/* control characters */
};

/*
 * c_cc characters which are valid for lx_termio and lx_termios
 */
#define	LX_VINTR	0
#define	LX_VQUIT	1
#define	LX_VERASE	2
#define	LX_VKILL	3
#define	LX_VEOF		4
#define	LX_VTIME	5
#define	LX_VMIN		6
#define	LX_VSWTC	7

/*
 * c_cc characters which are valid for lx_termios
 */
#define	LX_VSTART	8
#define	LX_VSTOP	9
#define	LX_VSUSP	10
#define	LX_VEOL		11
#define	LX_VREPRINT	12
#define	LX_VDISCARD	13
#define	LX_VWERASE	14
#define	LX_VLNEXT	15
#define	LX_VEOL2	16

/*
 * Sound formats
 */
#define	LX_AFMT_QUERY		0x00000000
#define	LX_AFMT_MU_LAW		0x00000001
#define	LX_AFMT_A_LAW		0x00000002
#define	LX_AFMT_IMA_ADPCM	0x00000004
#define	LX_AFMT_U8		0x00000008
#define	LX_AFMT_S16_LE		0x00000010
#define	LX_AFMT_S16_BE		0x00000020
#define	LX_AFMT_S8		0x00000040
#define	LX_AFMT_U16_LE		0x00000080
#define	LX_AFMT_U16_BE		0x00000100
#define	LX_AFMT_MPEG		0x00000200
#define	LX_AFMT_AC3		0x00000400

/*
 * Supported ioctls
 */
#define	LX_TCGETS		0x5401
#define	LX_TCSETS		0x5402
#define	LX_TCSETSW		0x5403
#define	LX_TCSETSF		0x5404
#define	LX_TCGETA		0x5405
#define	LX_TCSETA		0x5406
#define	LX_TCSETAW		0x5407
#define	LX_TCSETAF		0x5408
#define	LX_TCSBRK		0x5409
#define	LX_TCXONC		0x540a
#define	LX_TCFLSH		0x540b
#define	LX_TIOCEXCL		0x540c
#define	LX_TIOCNXCL		0x540d
#define	LX_TIOCSCTTY		0x540e
#define	LX_TIOCGPGRP		0x540f
#define	LX_TIOCSPGRP		0x5410
#define	LX_TIOCOUTQ		0x5411
#define	LX_TIOCSTI		0x5412
#define	LX_TIOCGWINSZ		0x5413
#define	LX_TIOCSWINSZ		0x5414
#define	LX_TIOCMGET		0x5415
#define	LX_TIOCMBIS		0x5416
#define	LX_TIOCMBIC		0x5417
#define	LX_TIOCMSET		0x5418
#define	LX_TIOCGSOFTCAR		0x5419
#define	LX_TIOCSSOFTCAR		0x541a
#define	LX_FIONREAD		0x541b
#define	LX_TIOCPKT		0x5420
#define	LX_FIONBIO		0x5421
#define	LX_TIOCNOTTY		0x5422
#define	LX_TIOCSETD		0x5423
#define	LX_TIOCGETD		0x5424
#define	LX_TCSBRKP		0x5425
#define	LX_TIOCGSID		0x5429
#define	LX_TIOCGPTN		0x80045430
#define	LX_TIOCSPTLCK		0x40045431
#define	LX_FIONCLEX		0x5450
#define	LX_FIOCLEX		0x5451
#define	LX_FIOASYNC		0x5452
#define	LX_FIOSETOWN		0x8901
#define	LX_SIOCSPGRP		0x8902
#define	LX_FIOGETOWN		0x8903
#define	LX_SIOCGPGRP		0x8904
#define	LX_SIOCATMARK		0x8905
#define	LX_SIOCGIFCONF		0x8912
#define	LX_SIOCGIFFLAGS		0x8913
#define	LX_SIOCSIFFLAGS		0x8914
#define	LX_SIOCGIFADDR		0x8915
#define	LX_SIOCSIFADDR		0x8916
#define	LX_SIOCGIFDSTADDR	0x8917
#define	LX_SIOCSIFDSTADDR	0x8918
#define	LX_SIOCGIFBRDADDR	0x8919
#define	LX_SIOCSIFBRDADDR	0x891a
#define	LX_SIOCGIFNETMASK	0x891b
#define	LX_SIOCSIFNETMASK	0x891c
#define	LX_SIOCGIFMETRIC	0x891d
#define	LX_SIOCSIFMETRIC	0x891e
#define	LX_SIOCGIFMEM		0x891f
#define	LX_SIOCSIFMEM		0x8920
#define	LX_SIOCGIFMTU		0x8921
#define	LX_SIOCSIFMTU		0x8922
#define	LX_SIOCSIFHWADDR	0x8924
#define	LX_SIOCGIFHWADDR	0x8927

/*
 * /dev/dsp ioctls - supported
 */
#define	LX_OSS_SNDCTL_DSP_RESET		0x5000
#define	LX_OSS_SNDCTL_DSP_SYNC		0x5001
#define	LX_OSS_SNDCTL_DSP_SPEED		0xc0045002
#define	LX_OSS_SNDCTL_DSP_STEREO	0xc0045003
#define	LX_OSS_SNDCTL_DSP_GETBLKSIZE	0xc0045004
#define	LX_OSS_SNDCTL_DSP_SETFMTS	0xc0045005
#define	LX_OSS_SNDCTL_DSP_CHANNELS	0xc0045006
#define	LX_OSS_SNDCTL_DSP_SETFRAGMENT	0xc004500a
#define	LX_OSS_SNDCTL_DSP_GETFMTS	0x8004500b
#define	LX_OSS_SNDCTL_DSP_GETOSPACE	0x8010500c
#define	LX_OSS_SNDCTL_DSP_GETCAPS	0x8004500f
#define	LX_OSS_SNDCTL_DSP_SETTRIGGER	0x40045010
#define	LX_OSS_SNDCTL_DSP_GETOPTR	0x800c5012
#define	LX_OSS_SNDCTL_DSP_GETISPACE	0x8010500d

/*
 * support for /dev/dsp SNDCTL_DSP_GETFMTS and SNDCTL_DSP_SETFMTS
 */
#define	LX_OSS_AFMT_QUERY		0x0000
#define	LX_OSS_AFMT_MU_LAW		0x0001
#define	LX_OSS_AFMT_A_LAW		0x0002
#define	LX_OSS_AFMT_IMA_ADPCM		0x0004
#define	LX_OSS_AFMT_U8			0x0008
#define	LX_OSS_AFMT_S16_LE		0x0010
#define	LX_OSS_AFMT_S16_BE		0x0020
#define	LX_OSS_AFMT_S8			0x0040
#define	LX_OSS_AFMT_U16_LE		0x0080
#define	LX_OSS_AFMT_U16_BE		0x0100
#define	LX_OSS_AFMT_MPEG		0x0200

#ifdef _LITTLE_ENDIAN
#define	LX_OSS_AFMT_S16_NE		LX_OSS_AFMT_S16_LE
#define	LX_OSS_AFMT_U16_NE		LX_OSS_AFMT_U16_LE
#elif defined(_BIG_ENDIAN)
#define	LX_OSS_AFMT_S16_NE		LX_OSS_AFMT_S16_BE
#define	LX_OSS_AFMT_U16_NE		LX_OSS_AFMT_U16_BE
#else /* _LITTLE_ENDIAN */
#error	NO ENDIAN defined.
#endif /* _LITTLE_ENDIAN */

/*
 * support for /dev/dsp SNDCTL_DSP_GETISPACE and SNDCTL_DSP_GETOSPACE
 */
typedef struct lx_oss_audio_buf_info {
	int fragments;	/* fragments that can be rd/wr without blocking */
	int fragstotal;	/* total number of fragments allocated for buffering */
	int fragsize;	/* size of fragments, same as SNDCTL_DSP_GETBLKSIZE */
	int bytes;	/* what can be rd/wr immediatly without blocking */
} lx_oss_audio_buf_info_t;

/*
 * support for /dev/dsp SNDCTL_DSP_GETOPTR
 */
typedef struct lx_oss_count_info {
	/* # of bytes processed since opening the device */
	int bytes;

	/*
	 * # of fragment transitions since last call to this function.
	 * only valid for mmap acess mode.
	 */
	int blocks;

	/*
	 * byte offset of the current recording/playback position from
	 * the beginning of the audio buffer.  only valid for mmap access
	 * mode.
	 */
	int ptr;
} lx_oss_count_info_t;

/*
 * support for /dev/dsp SNDCTL_DSP_GETCAPS
 */
#define	LX_OSS_DSP_CAP_TRIGGER		0x1000
#define	LX_OSS_DSP_CAP_MMAP		0x2000

/*
 * support for /dev/dsp/ SNDCTL_DSP_SETTRIGGER
 */
#define	LX_OSS_PCM_DISABLE_OUTPUT	0
#define	LX_OSS_PCM_ENABLE_OUTPUT	2

/*
 * /dev/mixer ioctl macros
 */
#define	LX_OSS_SM_NRDEVICES	25
#define	LX_OSS_SM_READ(x)	(0x80044d00 | (x))
#define	LX_OSS_SM_WRITE(x)	(0xc0044d00 | (x))

/*
 * /dev/mixer ioctls - supported
 */
#define	LX_OSS_SOUND_MIXER_READ_VOLUME	LX_OSS_SM_READ(LX_OSS_SM_VOLUME)
#define	LX_OSS_SOUND_MIXER_READ_PCM	LX_OSS_SM_READ(LX_OSS_SM_PCM)
#define	LX_OSS_SOUND_MIXER_READ_MIC	LX_OSS_SM_READ(LX_OSS_SM_MIC)
#define	LX_OSS_SOUND_MIXER_READ_IGAIN	LX_OSS_SM_READ(LX_OSS_SM_IGAIN)
#define	LX_OSS_SOUND_MIXER_WRITE_VOLUME	LX_OSS_SM_WRITE(LX_OSS_SM_VOLUME)
#define	LX_OSS_SOUND_MIXER_WRITE_PCM	LX_OSS_SM_WRITE(LX_OSS_SM_PCM)
#define	LX_OSS_SOUND_MIXER_WRITE_MIC	LX_OSS_SM_WRITE(LX_OSS_SM_MIC)
#define	LX_OSS_SOUND_MIXER_WRITE_IGAIN	LX_OSS_SM_WRITE(LX_OSS_SM_IGAIN)
#define	LX_OSS_SOUND_MIXER_READ_STEREODEVS LX_OSS_SM_READ(LX_OSS_SM_STEREODEVS)
#define	LX_OSS_SOUND_MIXER_READ_RECMASK	LX_OSS_SM_READ(LX_OSS_SM_RECMASK)
#define	LX_OSS_SOUND_MIXER_READ_DEVMASK	LX_OSS_SM_READ(LX_OSS_SM_DEVMASK)
#define	LX_OSS_SOUND_MIXER_READ_RECSRC	LX_OSS_SM_READ(LX_OSS_SM_RECSRC)

/*
 * /dev/mixer channels
 */
#define	LX_OSS_SM_VOLUME	0
#define	LX_OSS_SM_BASS		1
#define	LX_OSS_SM_TREBLE	2
#define	LX_OSS_SM_SYNTH		3
#define	LX_OSS_SM_PCM		4
#define	LX_OSS_SM_SPEAKER	5
#define	LX_OSS_SM_LINE		6
#define	LX_OSS_SM_MIC		7
#define	LX_OSS_SM_CD		8
#define	LX_OSS_SM_MIX		9
#define	LX_OSS_SM_PCM2		10
#define	LX_OSS_SM_REC		11
#define	LX_OSS_SM_IGAIN		12
#define	LX_OSS_SM_OGAIN		13
#define	LX_OSS_SM_LINE1		14
#define	LX_OSS_SM_LINE2		15
#define	LX_OSS_SM_LINE3		16
#define	LX_OSS_SM_DIGITAL1	17
#define	LX_OSS_SM_DIGITAL2	18
#define	LX_OSS_SM_DIGITAL3	19
#define	LX_OSS_SM_PHONEIN	20
#define	LX_OSS_SM_PHONEOUT	21
#define	LX_OSS_SM_VIDEO		22
#define	LX_OSS_SM_RADIO		23
#define	LX_OSS_SM_MONITOR	24

/*
 * /dev/mixer operations
 */
#define	LX_OSS_SM_STEREODEVS	251
#define	LX_OSS_SM_CAPS		252
#define	LX_OSS_SM_RECMASK	253
#define	LX_OSS_SM_DEVMASK	254
#define	LX_OSS_SM_RECSRC	255

/*
 * /dev/mixer value conversion macros
 *
 * solaris expects gain level on a scale of 0 - 255
 * oss expects gain level on a scale of 0 - 100
 *
 * oss also encodes multiple channels volume values in a single int,
 * one channel value per byte.
 */
#define	LX_OSS_S2L_GAIN(v)		(((v) * 100) / 255)
#define	LX_OSS_L2S_GAIN(v)		(((v) * 255) / 100)
#define	LX_OSS_MIXER_DEC1(v)		((v) & 0xff)
#define	LX_OSS_MIXER_DEC2(v)		(((v) >> 8) & 0xff)
#define	LX_OSS_MIXER_ENC2(v1, v2)	(((v2) << 8) | (v1))

/*
 * /dev/mixer value verification macros
 */
#define	LX_OSS_MIXER_VCHECK(x)	(((int)(x) >= 0) && ((int)(x) <= 100))
#define	LX_OSS_MIXER_1CH_OK(x)	((((x) & ~0xff) == 0) &&	\
	LX_OSS_MIXER_VCHECK(LX_OSS_MIXER_DEC1(x)))
#define	LX_OSS_MIXER_2CH_OK(x)	((((x) & ~0xffff) == 0) &&	\
	LX_OSS_MIXER_VCHECK(LX_OSS_MIXER_DEC1(x)) &&		\
	LX_OSS_MIXER_VCHECK(LX_OSS_MIXER_DEC2(x)))

/*
 * Unsupported ioctls (NOT a comprehensive list)
 */
#define	LX_TIOCLINUX		0x541c
#define	LX_TIOCCONS		0x541d
#define	LX_TIOCGSERIAL		0x541e
#define	LX_TIOCSSERIAL		0x541f
#define	LX_TIOCTTYGSTRUCT	0x5426
#define	LX_TIOCSERCONFIG	0x5453
#define	LX_TIOCSERGWILD		0x5454
#define	LX_TIOCSERSWILD		0x5455
#define	LX_TIOCGLCKTRMIOS	0x5456
#define	LX_TIOCSLCKTRMIOS	0x5457
#define	LX_TIOCSERGSTRUCT	0x5458
#define	LX_TIOCSERGETLSR	0x5459
#define	LX_TIOCSERGETMULTI	0x545a
#define	LX_TIOCSERSETMULTI	0x545b
#define	LX_OLD_SIOCGIFHWADDR	0x8923
#define	LX_SIOCSIFENCAP		0x8926
#define	LX_SIOCGIFSLAVE		0x8929
#define	LX_SIOCSIFSLAVE		0x8930
#define	LX_SIOCADDMULTI		0x8931
#define	LX_SIOCDELMULTI		0x8932
#define	LX_SIOCADDRTOLD		0x8940
#define	LX_SIOCDELRTOLD		0x8941
#define	LX_SIOCGIFTXQLEN	0x8942
#define	LX_SIOCDARP		0x8950
#define	LX_SIOCGARP		0x8951
#define	LX_SIOCSARP		0x8952
#define	LX_SIOCDRARP		0x8960
#define	LX_SIOCGRARP		0x8961
#define	LX_SIOCSRARP		0x8962
#define	LX_SIOCGIFMAP		0x8970
#define	LX_SIOCSIFMAP		0x8971

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_IOCTL_H */
