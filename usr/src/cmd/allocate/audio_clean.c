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
/* Copyright (c) 1991-2001 by Sun Microsystems, Inc. */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
 * audio_clean - Clear any residual data that may be residing in the in the
 *	audio device driver or chip.
 *
 *	Usage: audio_clean [-Iisf] device_name
 *
 *	Note: The same operation is performed for any of the "ifs" flags.
 *		The "I" flag is a silent form of "i".  Support for the flags
 *		is provided so that the framework is place if added
 *		functionality is required.
 *
 *	Note: The AUDIO_SETINFO ioctl is used instead of the low level
 *		AUDIOSETREG command which is used to perform low level
 *		operations on the device.  If a process had previously used
 *		AUDIOSETREG to monkey with the device, then the driver would
 *		have reset the chip when the process performed a close,
 *		so this can just clear the info structure.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <unistd.h>

#include <sys/audioio.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#define	BUF_SIZE 512
#define	DMINFO	"dminfo -v -n"	/* Cmd to xlate name to device */
#define	AUDIO	"/dev/audio"	/* Device name of audio device */

static char *Audio_dev = AUDIO;

#ifdef	DEBUG
static void print_info(audio_info_t *);
static void print_prinfo(audio_prinfo_t *);
#endif	/* DEBUG */

static void
usage(char *prog, int verbose)
{
	if (verbose)
		(void) fprintf(stderr,
		    gettext("usage: %s [-I|-s|-f|-i] device\n"), prog);
}

/*
 * Return the first substring in string before the ':' in "item"
 */
static void
first_field(char *string, char *item)
{
	item = string;

	while (*item != ':')
		item++;
	*item = 0;
}

main(int argc, char *argv[])
{
	int	err = 0;
	struct stat	st;
	audio_info_t	info;
	int	i;
	char	cmd_str[BUF_SIZE];
	char	map[BUF_SIZE];
	char	*prog;
	FILE	*fp;
	int	Audio_fd;
	int	forced = 0;		/* Command line options */
	int	initial = 0;
	int	standard = 0;
	int	verbose = 1;		/* default is to be verbose */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	prog = argv[0];		/* save program initiation name */

	/*
	 * Parse arguments.  Currently i, s and f all do the
	 * the same thing.
	 */

	while ((i = getopt(argc, argv, "Iifs")) != EOF) {
		switch (i) {
		case 'I':
			verbose = 0;
			initial++;
			if (standard || forced)
				err++;
			break;
		case 'i':
			initial++;
			if (standard || forced)
				err++;
			break;
		case 's':
			standard++;
			if (initial || forced)
				err++;
			break;
		case 'f':
			forced++;
			if (initial || standard)
				err++;
			break;
		case '?':
			err++;
			break;
		}
		if (err) {
			usage(prog, verbose);
			exit(1);
		}
		argc -= optind;
		argv += optind;
	}

	if (argv[0] == NULL) {	/* no device name */
		usage(prog, verbose);
		exit(1);
	}

	if (strlen(argv[0]) > (BUF_SIZE - sizeof (DMINFO) - 2)) {
		(void) fprintf(stderr, gettext("device name %s too long\n"),
		    argv[0]);
		exit(1);
	}

	(void) strcpy(cmd_str, DMINFO);
	(void) strcat(cmd_str, " ");
	(void) strcat(cmd_str, argv[0]);	/* device name */

	if ((fp = popen(cmd_str, "r")) == NULL) {
		if (verbose)
			(void) fprintf(stderr,
			    gettext("%s couldn't execute \"%s\"\n"), prog,
			    cmd_str);
		exit(1);
	}

	if (fread(map, 1, BUF_SIZE, fp) == 0) {
		if (verbose)
			(void) fprintf(stderr,
			    gettext("%s no results from \"%s\"\n"), prog,
			    cmd_str);
		exit(1);
	}

	(void) pclose(fp);

	first_field(map, Audio_dev);  /* Put the 1st field in dev */

	/*
	 * Validate and open the audio device
	 */
	err = stat(Audio_dev, &st);

	if (err < 0) {
		if (verbose) {
			(void) fprintf(stderr, gettext("%s: cannot stat "),
			    prog);
			perror("audio_clean");
		}
		exit(1);
	}
	if (!S_ISCHR(st.st_mode)) {
		if (verbose)
			(void) fprintf(stderr,
			    gettext("%s: %s is not an audio device\n"), prog,
			    Audio_dev);
		exit(1);
	}

	/*
	 * Since the device /dev/audio can suspend if someone else is
	 * using it we check to see if we're going to hang before we
	 * do anything.
	 */
	/* Try it quickly, first */
	Audio_fd = open(Audio_dev, O_WRONLY | O_NDELAY);

	if ((Audio_fd < 0) && (errno == EBUSY)) {
		if (verbose)
			(void) fprintf(stderr, gettext("%s: waiting for %s..."),
			    prog, Audio_dev);

		/* Now hang until it's open */
		Audio_fd = open(Audio_dev, O_WRONLY);
		if (Audio_fd < 0) {
			if (verbose)
				perror(Audio_dev);
			exit(1);
		}
	} else if (Audio_fd < 0) {
		if (verbose) {
			(void) fprintf(stderr, gettext("%s: error opening "),
			    prog);
			perror(Audio_dev);
		}
		exit(1);
	}

#ifdef	DEBUG
	/*
	 * Read the audio_info structure.
	 */

	if (ioctl(Audio_fd, AUDIO_GETINFO, &info) != 0)  {
		perror("Ioctl AUDIO_GETINFO error");
		exit(1);
	}

	print_info(&info);
#endif	/* DEBUG */

/* LINTED */
	AUDIO_INITINFO(&info);	/* clear audit info structure */

	if (ioctl(Audio_fd, AUDIO_SETINFO, &info) != 0) {
		if (verbose)
			perror(gettext("Ioctl AUDIO_SETINFO error"));
		exit(1);
	}

#ifdef	DEBUG
	if (ioctl(Audio_fd, AUDIO_GETINFO, &info) != 0)  {
		perror("Ioctl AUDIO_GETINFO-2 error");
		exit(1);
	}

	print_info(&info);
#endif	/* DEBUG */

	return (0);
}


#ifdef	DEBUG
void
print_info(audio_info_t *info)
{
	print_prinfo(&info->play);
	print_prinfo(&info->record);
	(void) printf("monitor_gain %d\n", info->monitor_gain);
	(void) fflush(stdout);
}


void
print_prinfo(audio_prinfo_t *prinfo)
{
	/* The following values decribe audio data encoding: */
	(void) printf("sample_rate %d\n",	prinfo->sample_rate);
	(void) printf("channels %d\n", 	prinfo->channels);
	(void) printf("precision %d\n", 	prinfo->precision);
	(void) printf("encoding %d\n", 	prinfo->encoding);

	/* The following values control audio device configuration */
	(void) printf("gain %d\n", 	prinfo->gain);
	(void) printf("port %d\n", 	prinfo->port);
	(void) printf("avail_ports %d\n", 	prinfo->avail_ports);
	(void) printf("mod_ports %d\n", 	prinfo->mod_ports);

	/* These are Reserved for future use, but we clear them  */
	(void) printf("_xxx %d\n", 	prinfo->_xxx);

	(void) printf("buffer_size %d\n", 	prinfo->buffer_size);

	/* The following values describe driver state */
	(void) printf("samples %d\n", 	prinfo->samples);
	(void) printf("eof %d\n", 	prinfo->eof);
	(void) printf("pause %d\n", 	prinfo->pause);
	(void) printf("error %d\n", 	prinfo->error);
	(void) printf("waiting %d\n", 	prinfo->waiting);
	(void) printf("balance %d\n", 	prinfo->balance);

	/* The following values are read-only state flags */
	(void) printf("open %d\n", 	prinfo->open);
	(void) printf("active %d\n", 	prinfo->active);
}
#endif	/* DEBUG */
