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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <strings.h>
#include <stropts.h>
#include <unistd.h>
#include <bsm/devices.h>
#include <sys/audioio.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>

#ifndef	TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif

#ifdef	DEBUG
static void print_info(audio_info_t *);
static void print_prinfo(audio_prinfo_t *);
#endif	/* DEBUG */

static void
usage(char *prog)
{
	(void) fprintf(stderr, "%s%s", prog,
	    gettext(" : usage:[-I|-s|-f|-i] device\n"));
}

int
main(int argc, char **argv)
{
	int		err = 0;
	int		Audio_fd;
	int		forced = 0;		/* Command line options */
	int		initial = 0;
	int		standard = 0;
	int		verbose = 1;		/* default is to be verbose */
	int		c;
	char		*prog, *devname, *devpath;
	devmap_t	*dm;
	struct stat	st;
	audio_info_t	info;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	prog = argv[0];		/* save program initiation name */

	/*
	 * Parse arguments.  Currently i, s and f all do the
	 * the same thing.
	 */

	while ((c = getopt(argc, argv, "Iifs")) != -1) {
		switch (c) {
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
		default:
			err++;
			break;
		}
		if (err) {
			if (verbose)
				usage(prog);
			exit(1);
		}
	}

	if ((argc - optind) != 1) {
		if (verbose)
			usage(prog);
		exit(1);
	} else {
		devname = argv[optind];
	}

	setdmapent();
	if ((dm = getdmapnam(devname)) == NULL) {
		enddmapent();
		if (verbose)
			(void) fprintf(stderr, "%s%s",
			    devname,
			    gettext(" : No such allocatable device\n"));
			exit(1);
	}
	enddmapent();
	if (dm->dmap_devarray == NULL || dm->dmap_devarray[0] == NULL) {
		if (verbose)
			(void) fprintf(stderr, "%s%s",
			    devname,
			    gettext(" : No such allocatable device\n"));
			exit(1);
	}
	devpath = strdup(dm->dmap_devarray[0]);
	freedmapent(dm);

	/*
	 * Validate and open the audio device
	 */
	err = stat(devpath, &st);

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
			    devpath);
		exit(1);
	}

	/*
	 * Since the device /dev/audio can suspend if someone else is
	 * using it we check to see if we're going to hang before we
	 * do anything.
	 */
	Audio_fd = open(devpath, O_WRONLY | O_NDELAY);

	if ((Audio_fd < 0) && (errno == EBUSY)) {
		if (verbose)
			(void) fprintf(stderr, gettext("%s: waiting for %s..."),
			    prog, devpath);
		exit(0);
	} else if (Audio_fd < 0) {
		if (verbose) {
			(void) fprintf(stderr, gettext("%s: error opening "),
			    prog);
			perror(devpath);
		}
		exit(1);
	}

#ifdef	DEBUG
	/*
	 * Read the audio_info structure.
	 */

	if (ioctl(Audio_fd, AUDIO_GETINFO, &info) != 0)  {
		perror("Ioctl AUDIO_GETINFO error");
		(void) close(Audio_fd);
		exit(1);
	}

	print_info(&info);
#endif	/* DEBUG */

/* LINTED */
	AUDIO_INITINFO(&info);	/* clear audit info structure */

	if (ioctl(Audio_fd, AUDIO_SETINFO, &info) != 0) {
		if (verbose)
			perror(gettext("Ioctl AUDIO_SETINFO error"));
		(void) close(Audio_fd);
		exit(1);
	}

#ifdef	DEBUG
	if (ioctl(Audio_fd, AUDIO_GETINFO, &info) != 0)  {
		perror("Ioctl AUDIO_GETINFO-2 error");
		(void) close(Audio_fd);
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
