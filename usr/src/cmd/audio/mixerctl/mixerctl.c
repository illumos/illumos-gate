/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * mixerctl command:
 *	mixerctl [-a|-d dev] [-iv] [-e|-o]
 *
 *	NOTE: Option D is not documented, it is for debugging.
 */

#include <stdio.h>
#include <stdlib.h>		/* getopt() */
#include <errno.h>		/* errno */
#include <strings.h>		/* strrchr(), strcpy(), strcat(), strerror() */
#include <locale.h>		/* setlocale() */
#include <libintl.h>		/* textdomain(), gettext() */
#include <sys/types.h>		/* open(), fstat() */
#include <sys/stat.h>		/* open(), fstat() */
#include <fcntl.h>		/* open() */
#include <unistd.h>		/* close(), ioctl() */
#include <stropts.h>		/* ioctl() */
#include <ctype.h>		/* isdigit() */
#include <dirent.h>		/* opendir(), readdir(), closedir() */
#include <sys/audioio.h>
#include <sys/mixer.h>

#define	GETOPT		"ad:iveoD"

#define	DEFAULT_DEVICE	"/dev/audioctl"
#define	CONTROL		"ctl"

#define	SOUND_DIR	"/dev/sound"
#define	DOT		"."
#define	DOTDOT		".."
#define	SLASH		"/"

#define	ENV		"AUDIODEV"

#define	AUX1		"AUX1"
#define	AUX2		"AUX2"
#define	CD		"CD"
#define	HDPHONE		"HDPHONE"
#define	LINE		"LINE"
#define	LOOPBACK	"CODEC LOOPBACK"
#define	MIC		"MIC"
#define	NONE		"NONE"
#define	SPDIF		"SPDIF"
#define	SPEAKER		"SPKR"
#define	SUNVTSLB	"SunVTS LOOPBACK"
#define	UNKNOWN		"UNKNOWN"
#define	SEPARATOR	"|"

#define	ALL_PLAY_PORTS	(AUDIO_SPEAKER|AUDIO_HEADPHONE|AUDIO_LINE_OUT|\
				AUDIO_SPDIF_OUT|AUDIO_AUX1_OUT|AUDIO_AUX2_OUT)
#define	ALL_REC_PORTS	(AUDIO_MICROPHONE|AUDIO_LINE_IN|AUDIO_CD|\
				AUDIO_SPDIF_IN|AUDIO_AUX1_IN|AUDIO_AUX2_IN|\
				AUDIO_CODEC_LOOPB_IN|AUDIO_SUNVTS)

#define	BUF_SIZE	128
#define	PPORT_STR_SIZE	30

#define	NOT_SUPPORTED	(-1)

typedef struct info {
	char	*pgm;
	char	*opt;
	char	*device;
	int	all;
	int	debug;
	int	disable;
	int	enable;
	int	info;
	int	verbose;
} info_t;

/* local functions */
static int doit(info_t *, char *);
static void pport2str(uint_t, char *);
static void rport2str(uint_t, char *);

int
main(const int argc, char * const *argv)
{
	DIR		*dirp;
	struct dirent	*dp;
	info_t		info;
	char		dev_buffer[BUF_SIZE];
	int		c;
	int		errflag = 0;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN "SYS_TEST"	/* Use this only if it weren't */
#endif
	(void) textdomain(TEXT_DOMAIN);

	/* make sure info structure is zeroed out */
	(void) memset(&info, 0, sizeof (info));

	if (info.pgm = strrchr(argv[0], '/')) {
		++info.pgm;
	} else {
		info.pgm = argv[0];
	}

	info.opt = GETOPT;

	/* check for options, they're listed at the top */
	while ((c = getopt(argc, argv, info.opt)) != EOF) {
		switch (c) {
		case 'a':	info.all++;		break;
		case 'd':	(void) strcpy(dev_buffer, optarg);
				info.device = dev_buffer;
				break;
		case 'e':	info.enable++;		break;
		case 'o':	info.disable++;		break;
		case 'i':	info.info++;		break;
		case 'v':	info.verbose++;		break;
		case 'D':	info.debug++;		break;
		default:	errflag++;		break;
		}
	}

	/* now we do some checks to make sure we haven't done anything bad */
	if (errflag || (info.all && info.device) ||
	    (info.enable && info.disable) || optind != argc) {
		(void) fprintf(stderr,
		    gettext("usage: %s [-a|-d dev] [-iv] [-e|-o]\n"),
		    info.pgm);
		return (1);
	}

	/* make sure we have something to do */
	if (!info.disable && !info.enable && !info.info && !info.verbose) {
		info.info++;
	}

	/* if "all" then we loop, otherwise we just take care of business */
	if (info.all) {
		/*
		 * Devices in /dev/sound are in the form of:
		 *	dev_number{function}
		 *
		 * Currently there are only entries like /dev/sound/0 (audio
		 * device) and /dev/sound/0ctl (audio control device).
		 */
		if ((dirp = opendir(SOUND_DIR)) == NULL) {
			(void) fprintf(stderr, gettext(
			    "Couldn't open directory %s: %s\n"), SOUND_DIR,
			    strerror(errno));
			return (1);
		}

		while ((dp = readdir(dirp)) != NULL) {
			char	*cp = dp->d_name;

			/* skip . and .. */
			if (strcmp(cp, DOT) == 0 || strcmp(cp, DOTDOT) == 0) {
				if (info.debug) {
					(void) printf(gettext("Skipping %s\n"),
					    cp);
				}
				continue;
			}

			/* go past the device number */
			while (isdigit(*cp)) {
				cp++;
			}

			/* if next char is NULL then not an audio ctl device */
			if (*cp == '\0') {
				if (info.debug) {
					(void) printf(gettext("Skipping %s\n"),
					    dp->d_name);
				}
				continue;
			}

			if (strcmp(cp, CONTROL) == 0) {
				/* we've got a control device, so call it */
				(void) strcpy(dev_buffer, SOUND_DIR);
				(void) strcat(dev_buffer, SLASH);
				(void) strcat(dev_buffer, dp->d_name);

				if (info.debug) {
					(void) printf(gettext(
					    "Found device: %s\n"), dev_buffer);
				}

				/* we don't bother with the return code */
				(void) doit(&info, dev_buffer);
			}
		}

		(void) closedir(dirp);
	} else {
		/* make sure we've got a good device */
		if (info.device == NULL) {
			if ((info.device = getenv(ENV)) == NULL) {
				if (info.debug) {
					(void) printf(gettext(
					    "using default device: %s\n"),
					    DEFAULT_DEVICE);
				}
				info.device = DEFAULT_DEVICE;
			} else {
				/* using ENV value, so get it */
				(void) strcpy(dev_buffer, info.device);
				info.device = dev_buffer;
				if (info.debug) {
					(void) printf(gettext(
					    "using ENV device: %s\n"),
					    info.device);
				}
			}
		}
		/* we have a device, make sure it is a control device */
		if (strspn(CONTROL, info.device) != strlen(CONTROL)) {
			(void) strcpy(dev_buffer, info.device);
			(void) strcat(dev_buffer, CONTROL);
			info.device = dev_buffer;
		}

		if (info.debug) {
			(void) printf(
			    gettext("calling doit(%s)\n"), info.device);
		}
		return (doit(&info, info.device));
	}

	return (0);

}	/* main() */

/*
 * doit()
 *
 * Description:
 *	This routine does all the real work
 *
 * Arguments:
 *	info_t	*info	Program info
 *	char	*dev	Device
 *
 * Returns:
 *	1		Error
 *	0		Okay
 */
static int
doit(info_t *info, char *dev)
{
	audio_device_t	dev_info;
	audio_info_t	audio_info;
	struct stat	buf;
	char		*pencoding;
	char		*rencoding;
	char		pport_buf[BUF_SIZE];
	char		rport_buf[BUF_SIZE];
	int		fd;
	int		mode;
	int		new_mode;
	int		rc = 0;

	/* first, make sure the device is there */
	if ((fd = open(dev, O_RDONLY)) < 0) {
		/* return a meaningful error message if possible */
		switch (errno) {
		case EPERM :
		case EACCES :
			(void) fprintf(stderr,
			    gettext("%s: device %s permission denied\n"),
			    info->pgm, dev);
			break;
		case ENOENT :
		case ENXIO :
		case ENODEV :
			(void) fprintf(stderr,
			    gettext("%s: device %s does not exist\n"),
			    info->pgm, dev);
			break;
		default:
			(void) fprintf(stderr,
			    gettext("%s: device %s not available\n"),
			    info->pgm, dev);
			break;
		}
		return (1);
	}

	/* make sure it is a special device */
	if (fstat(fd, &buf) < 0) {
		(void) fprintf(stderr,
		    gettext("%s: fstat() of %s failed\n"), info->pgm, dev);
		(void) close(fd);
		return (1);
	}
	if (!S_ISCHR(buf.st_mode)) {
		(void) fprintf(stderr,
		    gettext("%s: %s is not a character special device\n"),
		    info->pgm, dev);
		(void) close(fd);
		return (1);
	}

	/* if verbose or info wanted, we get the device info */
	if (info->verbose || info->info) {
		if (ioctl(fd, AUDIO_GETDEV, &dev_info) < 0) {
			(void) fprintf(stderr, gettext(
			    "%s: AUDIO_GETDEV ioctl() for device %s failed\n"),
			    info->pgm, dev);
			(void) close(fd);
			return (1);
		}

		(void) printf(gettext("Device %s:\n"), dev);
		(void) printf(gettext("  Name    = %s\n"), dev_info.name);
		(void) printf(gettext("  Version = %s\n"), dev_info.version);
		(void) printf(gettext("  Config  = %s\n"), dev_info.config);
	}

	/* get the mixer mode, if there is a mixer */
	if (ioctl(fd, AUDIO_MIXERCTL_GET_MODE, &mode) < 0) {
		(void) printf(
		    gettext("\n%s doesn't support the audio mixer function\n"),
		    dev);
		mode = NOT_SUPPORTED;
	} else if (!info->enable && !info->disable) {
		(void) printf(gettext("\nAudio mixer for %s is %s\n"),
		    dev, (mode == AM_MIXER_MODE ?
		    gettext("enabled") : gettext("disabled")));
	} else if (info->enable) {
		new_mode = AM_MIXER_MODE;
		if (mode != AM_MIXER_MODE) {
			if (ioctl(fd, AUDIO_MIXERCTL_SET_MODE, &new_mode) < 0) {
				(void) fprintf(stderr, gettext(
				    "%s: couldn't enable audio mixer for %s\n"),
				    info->pgm, dev);
				rc = 1;
			}
		}
		if (!rc) {
			(void) printf(gettext(
			    "Audio mixer for %s is enabled\n"), dev);
		}
	} else {
		/* sanity check */
		if (!info->disable) {
			(void) fprintf(stderr,
			    gettext("%s: program error #1\n"), info->pgm);
			rc = 1;
		} else if (mode != AM_COMPAT_MODE) {
			new_mode = AM_COMPAT_MODE;
			if (ioctl(fd, AUDIO_MIXERCTL_SET_MODE, &new_mode) < 0) {
				(void) fprintf(stderr, gettext("%s: "
				    "couldn't disable audio mixer for %s\n"),
				    info->pgm, dev);
				rc = 1;
			}
		}
		if (!rc) {
			(void) printf(gettext(
			    "Audio mixer for %s is disabled\n"), dev);
		}
	}

	/* only for verbose do we get the device's info_t structure */
	if (info->verbose) {
		if (ioctl(fd, AUDIO_GETINFO, &audio_info) < 0) {
			(void) fprintf(stderr, gettext(
			    "%s: AUDIO_GETINFO ioctl() for device %s failed\n"),
			    info->pgm, dev);
			(void) close(fd);
			return (1);
		}

		switch (audio_info.play.encoding) {
		case AUDIO_ENCODING_ULAW:
			pencoding = gettext("u-law");
			break;
		case AUDIO_ENCODING_ALAW:
			pencoding = gettext("A-law");
			break;
		case AUDIO_ENCODING_LINEAR:
			pencoding = gettext("linear");
			break;
		default:
			pencoding = gettext("UNKNOWN");
			break;
		}

		switch (audio_info.record.encoding) {
		case AUDIO_ENCODING_ULAW:
			rencoding = gettext("u-law");
			break;
		case AUDIO_ENCODING_ALAW:
			rencoding = gettext("A-law");
			break;
		case AUDIO_ENCODING_LINEAR:
			rencoding = gettext("linear");
			break;
		default:
			rencoding = gettext("UNKNOWN");
			break;
		}

		(void) printf(
		    gettext("Sample Rate\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.sample_rate, audio_info.record.sample_rate);
		(void) printf(gettext("Channels\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.channels, audio_info.record.channels);
		(void) printf(
		    gettext("Precision\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.precision, audio_info.record.precision);
		(void) printf(gettext("Encoding\n  Play\t\t%u (%s)\n"),
		    audio_info.play.encoding, pencoding);
		(void) printf(gettext("  Record\t%u (%s)\n"),
		    audio_info.record.encoding, rencoding);
		(void) printf(gettext("Gain\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.gain, audio_info.record.gain);
		(void) printf(gettext("Balance\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.balance, audio_info.record.balance);
		pport2str(audio_info.play.port, pport_buf),
		rport2str(audio_info.record.port, rport_buf),
		(void) printf(
		    gettext("Port\n  Play\t\t0x%08x %s\n  Record\t0x%08x %s\n"),
		    audio_info.play.port, pport_buf,
		    audio_info.record.port, rport_buf);
		pport2str(audio_info.play.avail_ports, pport_buf),
		rport2str(audio_info.record.avail_ports, rport_buf),
		(void) printf(
		    gettext("Avail Ports\n  Play\t\t0x%08x %s\n"
		    "  Record\t0x%08x %s\n"),
		    audio_info.play.avail_ports, pport_buf,
		    audio_info.record.avail_ports, rport_buf);
		pport2str(audio_info.play.mod_ports, pport_buf),
		rport2str(audio_info.record.mod_ports, rport_buf),
		(void) printf(
		    gettext("Mod Ports\n  Play\t\t0x%08x %s\n"
		    "  Record\t0x%08x %s\n"),
		    audio_info.play.mod_ports, pport_buf,
		    audio_info.record.mod_ports, rport_buf);
		(void) printf(gettext("Samples\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.samples, audio_info.record.samples);
		(void) printf(gettext("Active\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.active, audio_info.record.active);
		(void) printf(gettext("Pause\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.pause, audio_info.record.pause);
		(void) printf(gettext("Error\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.error, audio_info.record.error);
		(void) printf(gettext("EOF Count\n  Play\t\t%u\n"),
		    audio_info.play.eof);
		(void) printf(gettext("Waiting\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.waiting, audio_info.record.waiting);
		(void) printf(gettext("Open\n  Play\t\t%u\n  Record\t%u\n"),
		    audio_info.play.open, audio_info.record.open);
		(void) printf(gettext("HW Features\t\t0x%08x\n"),
		    audio_info.hw_features);
		if (audio_info.hw_features & AUDIO_HWFEATURE_PLAY) {
			(void) printf(gettext("  PLAY\n"));
		}
		if (audio_info.hw_features & AUDIO_HWFEATURE_RECORD) {
			(void) printf(gettext("  RECORD\n"));
		}
		if (audio_info.hw_features & AUDIO_HWFEATURE_DUPLEX) {
			(void) printf(gettext("  DUPLEX\n"));
		}
		if (audio_info.hw_features & AUDIO_HWFEATURE_MSCODEC) {
			(void) printf(gettext("  MULTI-STREAM CODEC\n"));
		}
		if (audio_info.hw_features & AUDIO_HWFEATURE_IN2OUT) {
			(void) printf(gettext("  INPUT TO OUTPUT LOOPBACK\n"));
		}
		(void) printf(gettext("SW Features\t\t0x%08x\n"),
		    audio_info.sw_features);
		if (audio_info.sw_features & AUDIO_SWFEATURE_MIXER) {
			(void) printf(gettext("  MIXER\n"));
		}
		(void) printf(gettext("SW Features Enabled\t0x%08x\n"),
		    audio_info.sw_features_enabled);
		if (audio_info.sw_features_enabled & AUDIO_SWFEATURE_MIXER) {
			(void) printf(gettext("  MIXER\n"));
		}
	}

	(void) close(fd);

	(void) printf("\n");

	return (rc);

}	/* doit() */

/*
 * pport2str()
 *
 * Description:
 *	Convert the play port bit map into strings. This makes the port number
 *	a bit more readable. The returned string is in parenthesis and always
 *	has 30 valid characters for spacing.
 *
 * Arguments:
 *	uint	port		The port to convert
 *	char	*buf		The storage to put the string into
 *
 * Returns:
 *	void
 */
static void
pport2str(uint_t port, char *buf)
{
	int		sep = 0;

	(void) strcpy(buf, gettext("("));

	if (port & AUDIO_SPEAKER) {
		(void) strcat(buf, gettext(SPEAKER));
		sep++;
	}
	if (port & AUDIO_HEADPHONE) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(HDPHONE));
	}
	if (port & AUDIO_LINE_OUT) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(LINE));
	}
	if (port & AUDIO_SPDIF_OUT) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(SPDIF));
	}
	if (port & AUDIO_AUX1_OUT) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(AUX1));
	}
	if (port & AUDIO_AUX2_OUT) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(AUX2));
	}
	if (port & ~ALL_PLAY_PORTS) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(UNKNOWN));
	}

	if (sep == 0) {
		(void) strcat(buf, gettext(NONE));
	}

	(void) strcat(buf, gettext(")"));

}	/* pport2str() */

/*
 * rport2str()
 *
 * Description:
 *	Convert the record port bit map into strings. This makes the port
 *	number a bit more readable. The returned string in parenthesis.
 *
 * Arguments:
 *	uint	port		The port to convert
 *	char	*buf		The storage to put the string into
 *
 * Returns:
 *	void
 */
static void
rport2str(uint_t port, char *buf)
{
	int		sep = 0;

	(void) strcpy(buf, gettext("("));

	if (port & AUDIO_MICROPHONE) {
		(void) strcat(buf, gettext(MIC));
		sep++;
	}
	if (port & AUDIO_LINE_IN) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(LINE));
	}
	if (port & AUDIO_CD) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(CD));
	}
	if (port & AUDIO_SPDIF_IN) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(SPDIF));
	}
	if (port & AUDIO_AUX1_IN) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(AUX1));
	}
	if (port & AUDIO_AUX2_IN) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(AUX2));
	}
	if (port & AUDIO_CODEC_LOOPB_IN) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(LOOPBACK));
	}
	if (port & AUDIO_SUNVTS) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(SUNVTSLB));
	}
	if (port & ~ALL_REC_PORTS) {
		if (sep) {
			(void) strcat(buf, gettext(SEPARATOR));
		} else {
			sep++;
		}
		(void) strcat(buf, gettext(UNKNOWN));
	}

	if (sep == 0) {
		(void) strcat(buf, gettext(NONE));
	}

	(void) strcat(buf, gettext(")"));

}	/* rport2str() */
