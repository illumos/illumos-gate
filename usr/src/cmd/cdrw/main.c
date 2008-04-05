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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>
#include <dbus/dbus.h>
#include <hal/libhal.h>

#include "msgs.h"
#include "device.h"
#include "util.h"
#include "main.h"
#include "options.h"
#include "mmc.h"
#include "misc_scsi.h"

/*
 * global flags
 */
int	debug = 0;
int	use_media_stated_capacity = 0;
int	keep_disc_open = 0;
int	requested_speed = 0;
int	simulation = 0;
int	verbose = 0;
char	*image_file = NULL;
char	*blanking_type = NULL;
int	audio_type = AUDIO_TYPE_NONE;
int	extract_track_no = 0;
char	*extract_file = NULL;
char	*alt_tmp_dir = NULL;
char	*copy_src = NULL;
int	vol_running = 0;
int	cflag = 0;
int	tflag = 0;
uid_t	ruid, cur_uid;

/*
 * global variables
 */
cd_device *target = NULL;		/* Default target device */
static char *tgtdev = NULL;
int device_type = CD_RW;		/* Default to CD/RW */
int write_mode = TAO_MODE;		/* Default to track at once */

static void
print_usage(void)
{
	err_msg(gettext("USAGE:\n"));
	err_msg(gettext("\tcdrw -i [ -vSCO ] [ -d device ] [ -p speed ]"));
	err_msg(gettext(" [ image-file ]\n"));
	err_msg(gettext("\tcdrw -a [ -vSCO ] [ -d device ] [ -p speed ]"));
	err_msg(gettext(" [ -T audio-type ] audio-file1 audio-file2 ...\n"));
	err_msg(gettext("\tcdrw -x [ -v ] [ -d device ] [ -T audio-type ]"));
	err_msg(gettext(" track-number audio-file\n"));
	err_msg(gettext("\tcdrw -c [ -SC ] [ -d device ] [ -p speed ]"));
	err_msg(gettext(" [ -m tmp-dir ] [ -s src-device ]\n"));
	err_msg(
	    gettext("\tcdrw -b [ -v ] [ -d device ] all | session | fast\n"));
	err_msg(gettext("\tcdrw -M [ -v ] [ -d device ]\n"));
	err_msg(gettext("\tcdrw -L [ -v ] [ -d device ]\n"));
	err_msg(gettext("\tcdrw -l [ -v ]\n"));
	err_msg(gettext("\tcdrw -h\n"));

	exit(2);
}

static void
check_invalid_option(options *specified, char *opstr)
{
	options c_op;
	int ret;

	set_options_mask(&c_op, opstr);
	if ((ret = compare_options_mask(&c_op, specified)) != 0) {
		err_msg(
		    gettext("Option %c is not defined for this operation.\n"),
		    (char)ret);
		print_usage();
	}
}

LibHalContext *
attach_to_hald(void)
{
	LibHalContext *ctx = NULL;
	DBusConnection *con = NULL;
	DBusError error;
	hal_state_t state;

	/* Initialize the dbus error states */
	dbus_error_init(&error);

	if ((con = dbus_bus_get(DBUS_BUS_SYSTEM, &error)) == NULL) {
		return (NULL);
	}
	state = DBUS_CONNECTION;

	/* Allocate a new hal context to work with the dbus */
	if ((ctx = libhal_ctx_new()) == NULL)
		return (NULL);
	state = HAL_CONTEXT;

	/* Pair up the context with the connection */
	if (!libhal_ctx_set_dbus_connection(ctx, con))
		goto fail;
	state = HAL_PAIRED;

	/* If libhal_ctx_init fails hald is not present */
	if (!libhal_ctx_init(ctx, &error)) {
		goto fail;
	}
	state = HAL_INITIALIZED;

	return (ctx);
fail:
	if (dbus_error_is_set(&error))
		dbus_error_free(&error);
	detach_from_hald(ctx, state);
	return (NULL);

}

void
detach_from_hald(LibHalContext *ctx, hal_state_t state)
{
	DBusError error;
	DBusConnection *con = libhal_ctx_get_dbus_connection(ctx);

	dbus_error_init(&error);

	switch (state) {
	case HAL_INITIALIZED:
		if (libhal_ctx_shutdown(ctx, &error) == FALSE)
			if (dbus_error_is_set(&error))
				dbus_error_free(&error);
	/*FALLTHROUGH*/
	case HAL_PAIRED:
		(void) libhal_ctx_free(ctx);
		dbus_connection_unref(con);
		break;
	case HAL_CONTEXT:
		(void) libhal_ctx_free(ctx);
		break;
	case DBUS_CONNECTION:
	default:
		break;
	}
}

/*
 * This function returns one if hald is running and
 * zero if hald is not running
 */
int
hald_running(void)
{
	LibHalContext *ctx;

	if ((ctx = attach_to_hald()) == NULL)
		return (0);

	detach_from_hald(ctx, HAL_INITIALIZED);
	return (1);
}

int
setup_target(int flag)
{
	char *devpath;

	if (tgtdev != NULL) {
		devpath = (char *)my_zalloc(PATH_MAX);
		if (lookup_device(tgtdev, devpath)) {
			target = get_device(tgtdev, devpath);
		}
		free(devpath);
		if (target == NULL) {
			return (0);
		}
		return (1);
	}
	return (scan_for_cd_device(flag, &target));
}

int
main(int argc, char **argv)
{
	int		c;
	int		operations;
	options		specified_ops;
	int		aflag, iflag, Mflag, Lflag, lflag, bflag, xflag;
	int		ret;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif


	(void) textdomain(TEXT_DOMAIN);

	ruid = getuid();
	cur_uid = geteuid();

	if (check_auth(ruid) != 1)  {
		err_msg(gettext(
		    "Authorization failed, Cannot access disks.\n"));
		exit(1);
	}

	if ((cur_uid == 0) && (ruid != 0)) {
		priv_change_needed = 1;
		lower_priv();
	}

	vol_running = hald_running();

	tgtdev = NULL;
	operations = 0;
	set_options_mask(&specified_ops, "");
	iflag = Mflag = Lflag = lflag = bflag = aflag = xflag = cflag = 0;

	while ((c = getopt(argc, argv, "abcCd:hiLlm:MOp:s:ST:vVx")) != EOF) {
		add_option(&specified_ops, c);
		switch (c) {
		case 'a':
			aflag = 1;
			operations++;
			break;
		case 'b':
			bflag = 1;
			operations++;
			break;
		case 'c':
			cflag = 1;
			operations++;
			break;
		case 'C':
			use_media_stated_capacity = 1;
			break;
		case 'd':
			tgtdev = optarg;
			break;
		case 'h':
			print_usage(); /* will not return */
			break;
		case 'i':
			iflag = 1;
			operations++;
			break;
		case 'L':
			Lflag = 1;
			operations++;
			break;
		case 'l':
			lflag = 1;
			operations++;
			break;
		case 'm':
			alt_tmp_dir = optarg;
			break;
		case 'M':
			Mflag = 1;
			operations++;
			break;
		case 'O':
			keep_disc_open = 1;
			break;
		case 'p':
			requested_speed = atoi(optarg);
			break;
		case 's':
			copy_src = optarg;
			break;
		case 'S':
			simulation++;
			break;
		case 'T':
			audio_type = get_audio_type(optarg);
			if (audio_type == -1) {
				err_msg(gettext("Unknown audio type %s\n"),
				    optarg);
				exit(1);
			}
			break;
		case 'v':
			verbose++;
			break;
		case 'V':
			/*
			 * more verbose. this will print out debug comments
			 */

			debug++;
			break;
		case 'x':
			xflag++;
			operations++;
			break;
		default:
			print_usage();
		}
	}
	if (operations == 0) {
		err_msg(gettext("No operation specified.\n"));
		exit(1);
	}
	if (operations != 1) {
		err_msg(gettext("More than one operation specified.\n"));
		exit(1);
	}

	if (lflag) {
		check_invalid_option(&specified_ops, "lhvV");
		list();
	}

	/*
	 * we'll allow the user to specify the source device (-s) when
	 *  extracting audio.
	 */

	if (xflag && copy_src)
		tgtdev = copy_src;

	/*
	 * This will scan for all CD devices when xflag or Mflag
	 * (extract audio, list toc) commands are used, providing
	 * no CD-RW devices are found. Since these commands can
	 * be used without a CD writer.
	 */

	if (xflag || Mflag) {
		ret = setup_target(SCAN_ALL_CDS);
	} else {
		ret = setup_target(SCAN_WRITERS);
	}

	if (ret == 0) {

		if (tgtdev != NULL) {
			err_msg(gettext(
			    "Cannot find device %s.\n"), tgtdev);

		}

		if (vol_running) {
			err_msg(gettext(
			    "No CD writers found or no media in the drive.\n"));
		} else {
			if (cur_uid != 0) {
				err_msg(gettext(
				    "Volume manager is not running.\n"));
				err_msg(gettext(
"Please start volume manager or run cdrw as root to access all devices.\n"));
			} else {
				err_msg(gettext(
				    "No CD writers found.\n"));
			}
		}
		exit(1);

	} else if (ret != 1) {
		err_msg(gettext("More than one CD device found.\n"));
		err_msg(gettext("Specify one using -d option.\n"));
		err_msg(gettext(
		    "Or use -l option to list all the CD devices found\n"));
		exit(1);
	}
	(void) check_device(target, CHECK_TYPE_NOT_CDROM|EXIT_IF_CHECK_FAILED);

	if (check_device(target, CHECK_NO_MEDIA) == 0) {
		int retry;
		for (retry = 0; retry < 5; retry++) {
			if (check_device(target, CHECK_DEVICE_NOT_READY) == 0)
				break;
			(void) sleep(3);
		}
	}

	if (aflag) {
		check_invalid_option(&specified_ops, "ahvSCOdpTV");
		if (optind == argc) {
			err_msg(gettext("No audio files specified.\n"));
			exit(1);
		}
		write_audio(argv, optind, argc);
	}
	if (Mflag) {
		check_invalid_option(&specified_ops, "MhvdV");
		info();
	}
	if (iflag) {
		check_invalid_option(&specified_ops, "ihvSCOdpV");
		if (optind == (argc - 1)) {
			image_file = argv[optind];
			write_image();
		}
		if (optind == argc)
			write_image();
		err_msg(gettext("Command line parsing error.\n"));
		err_msg(gettext("Only one image-file can be specified.\n"));
		exit(1);
	}
	if (bflag) {
		check_invalid_option(&specified_ops, "bhvdV");
		if (optind != (argc - 1)) {
			err_msg(gettext("Command line parsing error.\n"));
			print_usage();
		}
		blanking_type = argv[argc - 1];
		blank();
	}
	if (xflag) {
		check_invalid_option(&specified_ops, "xhpvdsTV");
		if (optind != (argc - 2)) {
			err_msg(gettext("Command line parsing error.\n"));
			print_usage();
		}
		extract_track_no = atoi(argv[argc - 2]);
		extract_file = argv[argc - 1];
		extract_audio();
	}
	if (cflag) {
		check_invalid_option(&specified_ops, "chvSCdpmsV");
		copy_cd();
	}

	/*
	 * Open a closed disk, we do this by erasing the track tail
	 * and then re-finalizing with an open leadout.
	 */
	if (Lflag) {
		check_invalid_option(&specified_ops, "LvdV");
		(void) check_device(target, CHECK_NO_MEDIA |
		    CHECK_DEVICE_NOT_READY | EXIT_IF_CHECK_FAILED);

		/* no need to erase blank media */
		if (!check_device(target, CHECK_MEDIA_IS_NOT_BLANK))
			exit(0);

		blanking_type = "leadout";
		blank();

		write_init(TRACK_MODE_DATA);
		(void) close_track(target->d_fd, 0, 1, 1);
		(void) finalize(target);
		(void) printf(gettext("done.\n"));
		exit(0);
	}
	return (0);
}
