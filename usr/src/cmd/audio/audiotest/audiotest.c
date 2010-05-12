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
/*
 * This program is a general purpose test facility for audio output.
 * It does not test record.
 *
 * The wavedata.c and wavedata.h files contain the actual samples compressed
 * using the MS ADPCM algorithm.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/soundcard.h>
#include <inttypes.h>
#include <locale.h>

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif

#define	_(s)	gettext(s)

/*
 * Channel selectors
 */
#define	CH_LEFT		(1 << 0)
#define	CH_RIGHT	(1 << 1)
#define	CH_LREAR4	(1 << 2)	/* quadraphonic */
#define	CH_RREAR4	(1 << 3)	/* quadraphonic */
#define	CH_CENTER	(1 << 2)
#define	CH_LFE		(1 << 3)
#define	CH_LSURR	(1 << 4)
#define	CH_RSURR	(1 << 5)
#define	CH_LREAR	(1 << 6)
#define	CH_RREAR	(1 << 7)
#define	CH_STEREO	(CH_LEFT|CH_RIGHT)
#define	CH_4		(CH_STEREO | CH_LREAR4 | CH_RREAR4)
#define	CH_5		(CH_STEREO | CH_CENTER | CH_LSURR | CH_RSURR)
#define	CH_7		(CH_5 | CH_LREAR | CH_RREAR)

typedef struct chancfg {
	int		mask;
	const char	*name;
	unsigned	flags;
	int16_t		*data;
	int		len;
} chancfg_t;

typedef struct testcfg {
	int		nchan;
	uint32_t	rate;
	chancfg_t	*tests[16];
} testcfg_t;

#define	CFLAG_LFE	0x1	/* lfe channel - not full range */

/*
 * TRANSLATION_NOTE : The following strings are displayed during progress.
 * Its important for alignment that they have the same displayed length.
 */
#define	NM_LEFT		"\t<left> ................"
#define	NM_RIGHT	"\t<right> ..............."
#define	NM_LREAR	"\t<left rear> ..........."
#define	NM_RREAR	"\t<right rear> .........."
#define	NM_LSIDE	"\t<left side> ..........."
#define	NM_RSIDE	"\t<right side> .........."
#define	NM_CENTER	"\t<center> .............."
#define	NM_LFE		"\t<lfe> ................."
#define	NM_STEREO	"\t<stereo> .............."
#define	NM_40		"\t<4.0 surround> ........"
#define	NM_50		"\t<5.0 surround> ........"
#define	NM_70		"\t<7.0 surround> ........"

chancfg_t ch_left = { CH_LEFT, NM_LEFT, 0 };
chancfg_t ch_right = { CH_RIGHT, NM_RIGHT, 0 };
chancfg_t ch_stereo = { CH_STEREO, NM_STEREO, 0 };

chancfg_t ch_center = { CH_CENTER, NM_CENTER, 0 };
chancfg_t ch_lfe = { CH_LFE, NM_LFE, CFLAG_LFE };

chancfg_t ch_lsurr_4 = { (1 << 2), NM_LREAR, 0 };
chancfg_t ch_rsurr_4 = { (1 << 3), NM_RREAR, 0 };
chancfg_t ch_4 = { CH_4, NM_40, 0 };

chancfg_t ch_lsurr_5 = { CH_LSURR, NM_LREAR, 0 };
chancfg_t ch_rsurr_5 = { CH_RSURR, NM_RREAR, 0 };
chancfg_t ch_5 = { CH_5, NM_50, 0 };

chancfg_t ch_lsurr_7 = { CH_LSURR, NM_LSIDE, 0 };
chancfg_t ch_rsurr_7 = { CH_RSURR, NM_RSIDE, 0 };
chancfg_t ch_lrear_7 = { CH_LREAR, NM_LREAR, 0 };
chancfg_t ch_rrear_7 = { CH_RREAR, NM_RREAR, 0 };
chancfg_t ch_7 = { CH_7, NM_70, 0 };

testcfg_t test_stereo = {
	2, 48000, { &ch_left, &ch_right, &ch_stereo, NULL }
};

testcfg_t test_quad = {
	4, 48000, { &ch_left, &ch_right, &ch_stereo,
	&ch_lsurr_4, &ch_rsurr_4, &ch_4, NULL }
};

testcfg_t test_51 = {
	6, 48000, { &ch_left, &ch_right, &ch_stereo,
	&ch_lsurr_5, &ch_rsurr_5, &ch_center, &ch_lfe, &ch_5, NULL }
};

testcfg_t test_71 = {
	8, 48000, { &ch_left, &ch_right, &ch_stereo,
	&ch_lsurr_7, &ch_rsurr_7, &ch_lrear_7, &ch_rrear_7,
	&ch_center, &ch_lfe, &ch_7, NULL }
};

/*
 * uncompress_wave() is defined in wavedata.c. It expands the audio
 * samples stored in wavedata.h and returns the lenghth of the
 * uncompressed version in bytes.
 *
 * The uncompressed wave data format is 16 bit (native) stereo
 * recorded at 48000 Hz.
 */
extern int uncompress_wave(short *outbuf);

static int data_len;

#define	MAXDEVICE   64
extern void describe_error(int);

#define	SAMPLE_RATE 48000

/*
 * Operating mode flags (set from the command line).
 */
#define	TF_LOOP		0x00000010	/* Loop until interrupted */

static int mixerfd;
static int num_devices_tested = 0;

static short *sample_buf;

void
prepare(testcfg_t *tcfg)
{
	int	nsamples;
	int	i, j;
	chancfg_t	*ccfg;
	if ((sample_buf = malloc(2000000)) == NULL) {
		perror("malloc");
		exit(-1);
	}

	data_len = uncompress_wave(sample_buf);
	nsamples = (data_len / sizeof (int16_t)) / 2;

	for (i = 0; (ccfg = tcfg->tests[i]) != NULL; i++) {
		int16_t		*src, *dst;
		int		ch;
		int		samp;
		int		rate_multiple;

		src = sample_buf;
		rate_multiple = tcfg->rate / 48000;

		if (ccfg->flags != CFLAG_LFE) {
			ccfg->len = nsamples * tcfg->nchan *
			    sizeof (int16_t) * rate_multiple;
			ccfg->data = malloc(ccfg->len);
			if ((dst = ccfg->data) == NULL) {
				perror("malloc");
				exit(-1);
			}
			for (samp = 0; samp < nsamples; samp++) {
				for (ch = 0; ch < tcfg->nchan; ch++) {
					for (j = 0; j < rate_multiple; j++) {
						*dst = ((1U << ch) & ccfg->mask)
						    ? *src : 0;
						dst++;
					}
				}
				src += 2;
			}
		} else {
			/* Skip LFE for now */
			ccfg->len = 0;
		}
	}
}

/*
 * The testdsp() routine checks the capabilities of a given audio device number
 * (parameter n) and decides if the test sound needs to be played.
 */

/*ARGSUSED*/
int
testdsp(int hd, int flags, testcfg_t *tcfg)
{
	float ratio;
	struct timeval t1, t2;
	unsigned long t;
	int sample_rate;
	int delay;
	long long total_bytes = 0;
	unsigned int tmp, caps;
	int i;
	chancfg_t *ccfg;

	caps = 0;
	if (ioctl(hd, SNDCTL_DSP_GETCAPS, &caps) == -1) {
		perror("SNDCTL_DSP_GETCAPS");
		return (-1);
	}

	/*
	 * Setup the sample format. Since OSS will support AFMT_S16_NE
	 * regardless of the device we do not need to support any
	 * other formats.
	 */
	tmp = AFMT_S16_NE;
	if (ioctl(hd, SNDCTL_DSP_SETFMT, &tmp) == -1 || tmp != AFMT_S16_NE) {
		(void) printf(_("Device doesn't support native 16-bit PCM\n"));
		return (-1);
	}

	/*
	 * Setup the device for channels. Once again we can simply
	 * assume that stereo will always work before OSS takes care
	 * of this by emulation if necessary.
	 */
	tmp = tcfg->nchan;
	if (ioctl(hd, SNDCTL_DSP_CHANNELS, &tmp) == -1 || tmp != tcfg->nchan) {
		(void) printf(_("The device doesn't support %d channels\n"),
		    tcfg->nchan);
		return (-2);
	}

	/*
	 * Set up the sample rate.
	 */
	tmp = tcfg->rate;
	if (ioctl(hd, SNDCTL_DSP_SPEED, &tmp) == -1) {
		perror("SNDCTL_DSP_SPEED");
		return (-3);
	}

	sample_rate = tmp;
	if (sample_rate != tcfg->rate) {
		(void) printf(_("The device doesn't support %d Hz\n"),
		    tcfg->rate);
		return (-3);
	}
	(void) printf("\n");

	/*
	 * This program will measure the real sampling rate by
	 * computing the total time required to play the sample.
	 *
	 * This is not terribly presice with short test sounds but it
	 * can be used to detect if the sampling rate badly
	 * wrong. Errors of few percents is more likely to be caused
	 * by poor accuracy of the system clock rather than problems
	 * with the sampling rate.
	 */
	(void) gettimeofday(&t1, NULL);

	for (i = 0; (ccfg = tcfg->tests[i]) != NULL; i++) {
		(void) fputs(_(ccfg->name), stdout);
		(void) fflush(stdout);
		if (ccfg->flags & CFLAG_LFE) {
			(void) printf(_("SKIPPED\n"));
			continue;
		}

		if (write(hd, ccfg->data, ccfg->len) < 0) {
			(void) printf(_("ERROR: %s\n"),
			    strerror(errno));
			return (-3);
		}
		(void) printf(_("OK\n"));
		total_bytes += ccfg->len;
	}

	(void) gettimeofday(&t2, NULL);
	delay = 0;
	(void) ioctl(hd, SNDCTL_DSP_GETODELAY, &delay);	/* Ignore errors */

	/*
	 * Perform the time computations using milliseconds.
	 */

	t = t2.tv_sec - t1.tv_sec;
	t *= 1000;

	t += t2.tv_usec / 1000;
	t -= t1.tv_usec / 1000;

	total_bytes -= delay;
	total_bytes *= 1000;

	total_bytes /= t;
	total_bytes /= (tcfg->nchan * sizeof (int16_t));

	ratio = ((float)total_bytes / (float)sample_rate) * 100.0;
	(void) printf(_("\t<measured sample rate %8.2f Hz (%4.2f%%)>\n"),
	    (float)sample_rate * ratio / 100.0, ratio - 100.0);
	num_devices_tested++;

	return (1);
}

static int
find_num_devices(void)
{
	oss_sysinfo info;
	struct utsname un;
	/*
	 * Find out the number of available audio devices by calling
	 * SNDCTL_SYSINFO.
	 */

	if (ioctl(mixerfd, SNDCTL_SYSINFO, &info) == -1) {
		if (errno == ENXIO) {
			(void) fprintf(stderr,
			    _("No supported sound hardware detected.\n"));
			exit(-1);
		} else {
			perror("SNDCTL_SYSINFO");
			(void) printf(_("Cannot get system information.\n"));
			exit(-1);
		}
	}
	(void) printf(_("Sound subsystem and version: %s %s (0x%08X)\n"),
	    info.product, info.version, info.versionnum);

	if (uname(&un) != -1)
		(void) printf(_("Platform: %s %s %s %s\n"),
		    un.sysname, un.release, un.version, un.machine);

	return (info.numaudios);
}

/*
 * The test_device() routine checks certain information about the device
 * and calls testdsp() to play the test sound.
 */

int
test_device(char *dn, int flags, testcfg_t *tcfg)
{
	oss_audioinfo ainfo;
	int code;
	int fd;

	fd = open(dn, O_WRONLY, 0);
	if (fd == -1) {
		int err = errno;
		perror(dn);
		errno = err;
		describe_error(errno);
		return (-1);
	}

	ainfo.dev = -1;
	if (ioctl(fd, SNDCTL_AUDIOINFO, &ainfo) == -1) {
		perror("SNDCTL_AUDIOINFO");
		(void) close(fd);
		return (-1);
	}

	(void) printf(_("\n*** Scanning sound adapter #%d ***\n"),
	    ainfo.card_number);

	(void) printf(_("%s (audio engine %d): %s\n"), ainfo.devnode, ainfo.dev,
	    ainfo.name);

	if (!ainfo.enabled) {
		(void) printf(_("  - Device not present - Skipping\n"));
		(void) close(fd);
		return (0);
	}

	if (!(ainfo.caps & PCM_CAP_OUTPUT)) {
		(void) printf(_("  - Skipping input only device\n"));
		(void) close(fd);
		return (0);
	}

	(void) printf(_("  - Performing audio playback test... "));
	(void) fflush(stdout);

	code = testdsp(fd, flags, tcfg);
	(void) close(fd);
	if (code < 0) {
		return (code);
	}

	return (code == 1);
}

void
describe_error(int err)
{
	switch (err) {
	case ENODEV:
		(void) fprintf(stderr,
		    _("The device file was found in /dev but\n"
		    "the driver was not loaded.\n"));
		break;

	case ENXIO:
		(void) fprintf(stderr,
		    _("There are no sound devices available.\n"
		    "The most likely reason is that the device you have\n"
		    "is malfunctioning or it's not supported.\n"
		    "It's also possible that you are trying to use the wrong "
		    "device file.\n"));
		break;

	case ENOSPC:
		(void) fprintf(stderr,
		    _("Your system cannot allocate memory for the device\n"
		    "buffers. Reboot your machine and try again.\n"));
		break;

	case ENOENT:
		(void) fprintf(stderr,
		    _("The device file is missing from /dev.\n"));
		break;


	case EBUSY:
		(void) fprintf(stderr,
		    _("The device is busy. There is some other application\n"
		    "using it.\n"));
		break;

	default:
		break;
	}
}

int
main(int argc, char *argv[])
{
	int t, i;
	int maxdev;
	int flags = 0;
	int status = 0;
	int errors = 0;
	int numdev;
	extern int optind;
	testcfg_t	*tcfg;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	tcfg = &test_stereo;

	/*
	 * Simple command line switch handling.
	 */

	while ((i = getopt(argc, argv, "l2457r:")) != EOF) {
		switch (i) {
		case 'l':
			flags |= TF_LOOP;
			break;
		case '2':
			tcfg = &test_stereo;
			break;
		case '4':
			tcfg = &test_quad;
			break;
		case '5':
			tcfg = &test_51;
			break;
		case '7':
			tcfg = &test_71;
			break;
		case 'r':
			tcfg->rate = atoi(optarg);
			break;
		default:
			(void) printf(_("Usage: %s [options...] [device]\n"
			    "	-2	Stereo test\n"
			    "	-4	Quadraphonic 4.0 test\n"
			    "	-5	Surround 5.1 test\n"
			    "	-7	Surround 7.1 test\n"
			    "	-r	Sample Rate (48000|96000|192000)\n"
			    "	-l	Loop test\n"), argv[0]);
			exit(-1);
		}
	}

	/*
	 * Open the mixer device used for calling SNDCTL_SYSINFO and
	 * SNDCTL_AUDIOINFO.
	 */
	if ((mixerfd = open("/dev/mixer", O_RDWR, 0)) == -1) {
		int err = errno;
		perror("/dev/mixer");
		errno = err;
		describe_error(errno);
		exit(-1);
	}

	prepare(tcfg);			/* Prepare the wave data */

	/*
	 * Enumerate all devices and play the test sounds.
	 */
	maxdev = find_num_devices();
	if (maxdev < 1) {
		(void) printf(_("\n*** No audio hardware available ***\n"));
		exit(-1);
	}

	numdev = (argc - optind);
	do {
		char *dn;
		oss_audioinfo	ainfo;
		int rv;

		status = 0;
		if (numdev > 0) {
			for (t = 0; t < numdev; t++) {
				dn = argv[optind + t];
				rv = test_device(dn, flags, tcfg);
				if (rv < 0) {
					errors++;
				} else if (rv) {
					status++;
				}
			}
		} else {
			for (t = 0; t < maxdev; t++) {
				ainfo.dev = t;
				if (ioctl(mixerfd, SNDCTL_AUDIOINFO,
				    &ainfo) == -1) {
					perror("SNDCTL_AUDIOINFO");
					status++;
					continue;
				}
				dn = ainfo.devnode;
				rv = test_device(dn, flags, tcfg);
				if (rv < 0) {
					errors++;
				} else if (rv) {
					status++;
				}
			}
		}

		if (errors == 0)
			(void) printf(_("\n*** All tests completed OK ***\n"));
		else
			(void) printf(_("\n*** Errors were detected ***\n"));

	} while (status && (flags & TF_LOOP));

	(void) close(mixerfd);

	return (status);
}
