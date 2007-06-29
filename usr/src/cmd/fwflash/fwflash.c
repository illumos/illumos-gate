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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fwflash.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "fwflash.h"
#include "fwflash_ib.h"

/* FWflash functions */
static fwflash_device_info_t *fwflash_device_list(int *count);
static char *fwflash_name_from_class(int class);
static int  fwflash_class_from_name(char *class_name);
static int  fwflash_device_class_from_path(char *dev_name);
static int  fwflash_update(char *device, char *filename);
static int  fwflash_read_file(char *device, char *filename);
static int  fwflash_list_fw(int dev_class);
static void fwflash_intr(int sig);
static void fwflash_handle_signals(void);
static void fwflash_usage();
static void fwflash_help(void);
static void fwflash_version(void);

/* IB Specific functions */
static int  fwflash_list_fw_ib(int device);
static void fwflash_ib_print_guids(uint64_t *guids);
static int  fwflash_update_ib(char *device);
static int  fwflash_read_file_ib(char *device);

#if !defined(lint)
/* embedded software license agreement */
static char *sla [] = { "Copyright 2007 Sun Microsystems, Inc., 4150 Network "
"Circle, Santa Clara, California 95054, U.S.A. All rights reserved. U.S. "
"Government Rights - Commercial software.  Government users are subject to the "
"Sun Microsystems, Inc. standard license agreement and applicable provisions "
"of the FAR and its supplements.  Use is subject to license terms.  Parts of "
"the product may be derived from Berkeley BSD systems, licensed from the "
"University of California. UNIX is a registered trademark in the U.S. and in "
"other countries, exclusively licensed through X/Open Company, Ltd.Sun, Sun "
"Microsystems, the Sun logo and Solaris are trademarks or registered "
"trademarks of Sun Microsystems, Inc. in the U.S. and other countries. This "
"product is covered and controlled by U.S. Export Control laws and may be "
"subject to the export or import laws in other countries.  Nuclear, missile, "
"chemical biological weapons or nuclear maritime end uses or end users, "
"whether direct or indirect, are strictly prohibited.  Export or reexport "
"to countries subject to U.S. embargo or to entities identified on U.S. export "
"exclusion lists, including, but not limited to, the denied persons and "
"specially designated nationals lists is strictly prohibited." };
#endif	/* lint */

/* global arg list */
int	fwflash_arg_list = 0;

/* global state */
fwflash_state_t state;

/* are we writing to flash? */
static int fwflash_in_write = 0;

/*
 * Define the types of devices we support.  The order matters, add appropriate
 * values to the below #defines as well when updating this information.
 */
char *fwflash_classes [] =
{
	"ALL",
	"IB",
	""
};
#define	FWFLASH_DEVCLASS_ALL	0
#define	FWFLASH_DEVCLASS_IB	1

/*
 * FWFlash main code
 */
int
main(int argc, char *argv[])
{
	int		rv;
	char		ch;
	char		*fw_file;
	char		*read_file;
	int		dev_class = FWFLASH_DEVCLASS_ALL;
	extern char	*optarg;

	fw_file = NULL;
	read_file = NULL;

	bzero(&state, sizeof (fwflash_state_t));

	/* gather list of available devices to flash */
	state.devices = fwflash_device_list(&state.count);
	if (state.devices == NULL) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr, gettext("No flash devices found"));
		(void) fprintf(stderr, "\n");
		fwflash_usage();
		return (FWFLASH_FAILURE);
	}

	while ((ch = getopt(argc, argv, "hvylc:f:r:d:-:")) != -1) {
		switch (ch) {
		case 'h':
			fwflash_arg_list |= FWFLASH_HELP_FLAG;
			break;

		case 'v':
			fwflash_arg_list |= FWFLASH_VER_FLAG;
			break;

		case 'y':
			fwflash_arg_list |= FWFLASH_YES_FLAG;
			break;

		case 'l':
			fwflash_arg_list |= FWFLASH_LIST_FLAG;
			break;

		case 'c':
			fwflash_arg_list |= FWFLASH_CLASS_FLAG;

			while (*optarg == ' ') {
				optarg++;
			}
			dev_class = fwflash_class_from_name(optarg);
			if (dev_class == -1) {
				(void) fprintf(stderr, "%s: ",
				    FWFLASH_PGM_NAME);
				(void) fprintf(stderr,
				    gettext("Invalid device class"));
				(void) fprintf(stderr, ": %s", optarg);
				(void) fprintf(stderr, "\n");
				return (FWFLASH_FAILURE);
			}
			break;

		case 'd':
			fwflash_arg_list |= FWFLASH_DEVICE_FLAG;

			while (*optarg == ' ') {
				optarg++;
			}

			if (isdigit(*optarg)) {
				if (atoi(optarg) >= state.count) {
					(void) fprintf(stderr,
					    gettext(
					    "Unknown device specification"));
					(void) fprintf(stderr,
					    ": %s\n", optarg);
					fwflash_usage();
					return (FWFLASH_FAILURE);
				}
				state.device_name =
				    state.devices->device_list[atoi(optarg)];
			} else {
				state.device_name = optarg;
			}
			break;

		case 'f':
			fwflash_arg_list |= FWFLASH_FW_FLAG;
			while (*optarg == ' ') {
				optarg++;
			}
			fw_file = optarg;
			break;

		case 'r':
			fwflash_arg_list |= FWFLASH_READ_FLAG;
			while (*optarg == ' ') {
				optarg++;
			}
			read_file = optarg;
			break;

		/* illegal options */
		default:
			fwflash_usage();
			return (FWFLASH_FAILURE);
		}
	}

	/* Do Help */
	if (fwflash_arg_list & FWFLASH_HELP_FLAG) {
		fwflash_help();
		return (FWFLASH_SUCCESS);
	}

	/* Do Version */
	if (fwflash_arg_list == FWFLASH_VER_FLAG) {
		fwflash_version();
		return (FWFLASH_SUCCESS);
	}

	/* Do list */
	if (fwflash_arg_list == (FWFLASH_LIST_FLAG) ||
	    fwflash_arg_list == (FWFLASH_LIST_FLAG | FWFLASH_CLASS_FLAG)) {
		rv = fwflash_list_fw(dev_class);
		if (rv != FWFLASH_SUCCESS) {
			(void) fprintf(stderr,
			    gettext(
			    "Unable to generate list of available devices"));
			(void) fprintf(stderr, "\n");
		}
		return (FWFLASH_SUCCESS);
	}

	fwflash_handle_signals();

	/* Do flash update */
	if (fwflash_arg_list == (FWFLASH_FW_FLAG | FWFLASH_DEVICE_FLAG) ||
	    fwflash_arg_list == (FWFLASH_FW_FLAG | FWFLASH_DEVICE_FLAG |
	    FWFLASH_YES_FLAG)) {

		if (fw_file != NULL) {
			rv = fwflash_update(state.device_name, fw_file);
			if (rv != FWFLASH_SUCCESS) {
				(void) fprintf(stderr,
				    gettext("Failed to (re)write firmware"));
				(void) fprintf(stderr, "\n");
				return (FWFLASH_FAILURE);
			}
			return (FWFLASH_SUCCESS);
		} else {
			(void) fprintf(stderr,
			    gettext("Write filename invalid"));
			(void) fprintf(stderr, "\n");
			return (FWFLASH_FAILURE);
		}
	}

	/* Do flash read */
	if (fwflash_arg_list == (FWFLASH_READ_FLAG | FWFLASH_DEVICE_FLAG) ||
	    fwflash_arg_list == (FWFLASH_READ_FLAG | FWFLASH_DEVICE_FLAG |
	    FWFLASH_YES_FLAG)) {

		if (read_file != NULL) {
			rv = fwflash_read_file(state.device_name, read_file);
			if (rv == 0) {
				(void) fprintf(stderr,
				    gettext("Failed to read out firmware"));
				(void) fprintf(stderr, "\n");
				return (FWFLASH_FAILURE);
			}
			return (FWFLASH_SUCCESS);
		} else {
			(void) fprintf(stderr,
			    gettext("Read filename invalid"));
			(void) fprintf(stderr, "\n");
			return (FWFLASH_FAILURE);
		}
	}

	if (fwflash_arg_list == 0) {
		(void) fprintf(stdout, "%s: ", FWFLASH_PGM_NAME);
		(void) fprintf(stdout, gettext("please choose an option"));
		(void) fprintf(stdout, "\n");
	} else {
		(void) fprintf(stdout, "%s: ", FWFLASH_PGM_NAME);
		(void) fprintf(stdout, gettext("illegal options"));
		(void) fprintf(stdout, "\n");
	}
	fwflash_usage();

	return (FWFLASH_FAILURE);
}

static fwflash_device_info_t *
fwflash_device_list(int *count)
{
	fwflash_device_info_t	*devices;
	int			i;

	devices = (fwflash_device_info_t *)malloc(
	    sizeof (fwflash_device_info_t));

	/* Probe out all the supported devices */

	/*
	 * First find all IB devices
	 */
	devices->device_list = fwflash_ib_device_list(count);
	if (count == 0) {
		free(devices);
		devices = NULL;
	} else {
		devices->device_class = (int *)malloc(sizeof (int) * (*count));
		for (i = 0; i < *count; i++) {
			devices->device_class[i] = FWFLASH_DEVCLASS_IB;
		}
	}

	return (devices);
}

static char *
fwflash_name_from_class(int dev_class)
{
	return (fwflash_classes[dev_class]);
}

static int
fwflash_class_from_name(char *class_name)
{
	int class;

	while (*class_name == ' ') {
		class_name++;
	}

	for (class = 0; fwflash_classes[class][0] != '\0'; class++) {
		if (!strcasecmp(fwflash_classes[class], class_name))
			break;
	}

	if (fwflash_classes[class][0] == '\0') {
		return (-1);
	} else {
		return (class);
	}
}

static int
fwflash_device_class_from_path(char *dev_name)
{
	int entry;

	for (entry = 0; entry < state.count; entry++) {
		if (!strcasecmp(state.devices->device_list[entry], dev_name))
			break;
	}

	if (entry == state.count) {
		return (-1);
	} else {
		return (state.devices->device_class[entry]);
	}
}

static int
fwflash_list_fw(int dev_class)
{
	int		rv = FWFLASH_FAILURE;
	int		i;

	(void) fprintf(stdout, gettext("List of available devices"));
	(void) fprintf(stdout, ":\n");
	for (i = 0; i < state.count; i++) {
		(void) fprintf(stdout, gettext("Device"));
		(void) fprintf(stdout, "[%d],  %s\n", i,
		    state.devices->device_list[i]);

		if (dev_class == FWFLASH_DEVCLASS_ALL ||
		    dev_class == state.devices->device_class[i]) {
			switch (state.devices->device_class[i]) {
			case FWFLASH_DEVCLASS_IB:
				state.device_class = FWFLASH_DEVCLASS_IB;
				rv = fwflash_list_fw_ib(i);
				if (rv != 0) {
					/*
					 * flash type not yet supported
					 * move on to the next device
					 */
					rv = 0;
				}
				break;
			default:
				(void) fprintf(stderr,
				    gettext("Unknown class for device"));
				(void) fprintf(stderr, " %d.\n", i);
				break;
			}
		}
	}
out:
	return (rv);
}

static int
fwflash_update(char *device, char *filename)
{
	int		class;
	int		rv = 0;

	/* new firmware filename and device desc */
	DPRINTF(DBG_INFO, ("fwflash_update: fw_filename (%s) device (%s)\n",
	    filename, device));
	state.filename = filename;

	class = fwflash_device_class_from_path(device);
	if (class == -1) {
		(void) fprintf(stderr, gettext("Invalid class type for"));
		(void) fprintf(stderr, ": %s\n", device);
		return (FWFLASH_FAILURE);
	}

	switch (class) {
	case FWFLASH_DEVCLASS_IB:
		state.device_class = FWFLASH_DEVCLASS_IB;
		rv = fwflash_update_ib(device);
		if (rv != 0) {
			(void) fprintf(stderr,
			    gettext("Flash update IB failed."));
			(void) fprintf(stderr, "\n");
			return (rv);
		}
		break;
	default:
		break;
	}
	return (rv);
}

static int
fwflash_read_file(char *device, char *filename)
{
	int	class;
	int	rv;

	/* new firmware filename and device desc */
	DPRINTF(DBG_INFO, ("fwflash_read_file: fw_filename (%s) device (%s)\n",
	    filename, device));
	state.filename = filename;

	class = fwflash_device_class_from_path(device);
	if (class == -1) {
		(void) fprintf(stderr, gettext("Unknown device path"));
		(void) fprintf(stderr, ": %s\n", device);
		return (FWFLASH_FAILURE);
	}

	switch (class) {
	case FWFLASH_DEVCLASS_IB:
		state.device_class = FWFLASH_DEVCLASS_IB;
		rv = fwflash_read_file_ib(device);
		if (rv == 0) {
			(void) fprintf(stderr,
			    gettext("Flash read file failed."));
			(void) fprintf(stderr, "\n");
			return (rv);
		}
		break;
	default:
		break;
	}
	return (rv);
}

static void
fwflash_usage()
{
	(void) fprintf(stderr, gettext("Usage"));
	(void) fprintf(stderr, ": \n\t");
	(void) fprintf(stderr, gettext(
	    "fwflash [-l [-c <device_class> | ALL]] | [-v] | [-h]"));
	(void) fprintf(stderr, "\n\t");
	(void) fprintf(stderr, gettext(
	    "fwflash [-f <file>] | -r <file>] [-y] -d <dev_spec]"));
	(void) fprintf(stderr, "\n");
}

static void
fwflash_version(void)
{
	(void) fprintf(stderr, "%s: ", FWFLASH_PGM_NAME);
	(void) fprintf(stderr, gettext("version"));
	(void) fprintf(stderr, " %s\n", FWFLASH_VERSION);
}

static void
fwflash_help(void)
{
	fwflash_usage();
}

/* ARGSUSED */
static void
fwflash_intr(int sig)
{
	(void) signal(SIGINT, SIG_IGN);
	(void) signal(SIGTERM, SIG_IGN);
	if (fwflash_in_write) {
		(void) fprintf(stderr, "\n");
		(void) fprintf(stderr,
		    gettext("WARNING: firmware image may be corrupted"));
		(void) fprintf(stderr, "\n\t");
		(void) fprintf(stderr,
		    gettext("Reflash firmware before rebooting!"));
		(void) fprintf(stderr, "\n");
	}

	(void) fprintf(stderr, "\n");
	(void) fprintf(stderr, gettext("fwflash exiting due to signal"));
	(void) fprintf(stderr, "\n");

	switch (state.device_class) {
	case FWFLASH_DEVCLASS_IB:
		fwflash_ib_close(state.ibhdl);
		break;
	default:
		break;
	}
	exit(FWFLASH_FAILURE);
}

static void
fwflash_handle_signals(void)
{
	if (signal(SIGINT, fwflash_intr) == SIG_ERR) {
		perror("signal");
		exit(FWFLASH_FAILURE);
	}

	if (signal(SIGTERM, fwflash_intr) == SIG_ERR) {
		perror("signal");
		exit(FWFLASH_FAILURE);
	}
}

/*
 * IB (InfiniBand) specific functions.  Add additional functions following
 * these for otherclass types.
 */
static int
fwflash_list_fw_ib(int device)
{
	uint64_t		guids[4];
	int			rv;
	char			*dev_name;

	DPRINTF(DBG_INFO, ("fwflash_list_fw_ib\n"));
	/* open device and read some stuff */
	dev_name = state.devices->device_list[device];
	state.ibhdl = fwflash_ib_open(dev_name);
	if (state.ibhdl == NULL) {
		(void) fprintf(stderr, gettext("Failed to open device"));
		(void) fprintf(stderr, " (%s)\n", dev_name);
		return (FWFLASH_FAILURE);
	}

	/*
	 * Flash read GUIDs
	 * - First try the primary image GUIDs.  If this exists, then
	 * we have booted the primary image.
	 *
	 * - If primary doesn't work, fallback to the secondary GUIDs,
	 * assuming we have booted from the secondary firmware image.
	 *
	 * - If both fail, something is wrong here, and we must print
	 * out an error.
	 */
	rv = fwflash_ib_flash_read_guids(state.ibhdl, &guids[0],
	    FWFLASH_IB_PRIMARY_IMAGE);
	if (rv != 0) {
		DPRINTF(DBG_ERR, ("Failed to read primary guids. "
		    "Trying secondary..\n"));
		rv = fwflash_ib_flash_read_guids(state.ibhdl, &guids[0],
		    FWFLASH_IB_SECONDARY_IMAGE);
		if (rv != 0) {
			fwflash_ib_close(state.ibhdl);
			(void) fprintf(stderr, "\n");
			(void) fprintf(stderr,
			    gettext("WARNING: HCA FIRMWARE MAY BE CORRUPT"));
			(void) fprintf(stderr, "\n");
			(void) fprintf(stderr,
			    gettext("Unable to read GUID values"));
			(void) fprintf(stderr, "\n");
			fwflash_ib_close(state.ibhdl);
			return (FWFLASH_FAILURE);
		}
	}

	(void) fprintf(stdout, "    ");
	(void) fprintf(stdout, gettext("Class"));
	(void) fprintf(stdout, " [%s]\n",
	    fwflash_name_from_class(state.devices->device_class[device]));

	/* print the guids */
	fwflash_ib_print_guids(guids);

	/* print firmware revision */
	if (state.ibhdl->fw_rev.major != 0x0) {
		(void) fprintf(stdout, "        ");
		(void) fprintf(stdout, gettext("Firmware revision"));
		(void) fprintf(stdout, " : ");
		(void) fprintf(stdout, "%d.%d.%04d\n",
		    state.ibhdl->fw_rev.major,
		    state.ibhdl->fw_rev.minor,
		    state.ibhdl->fw_rev.subminor);
	} else {
		(void) fprintf(stdout, "\n");
		(void) fprintf(stdout,
		    gettext("WARNING: HCA FIRMWARE MAY BE CORRUPT"));
		(void) fprintf(stdout, "\n");
		(void) fprintf(stdout,
		    gettext("Unable to read firmware version"));
		(void) fprintf(stdout, "\n");
		fwflash_ib_close(state.ibhdl);
		return (FWFLASH_FAILURE);
	}

	/* print the HW product name, PSID, and part number */
	if (state.ibhdl->pn_len != 0) {
		(void) fprintf(stdout, "        ");
		(void) fprintf(stdout, gettext("Product"));
		(void) fprintf(stdout, "           : ");
		(void) fprintf(stdout, "%s ", state.ibhdl->info.mlx_pn);
		(void) fprintf(stdout, "(%s)\n", state.ibhdl->info.mlx_id);
		(void) fprintf(stdout, "        ");
		(void) fprintf(stdout, gettext("PSID"));
		(void) fprintf(stdout, "              : ");
		(void) fprintf(stdout, "%s\n", state.ibhdl->info.mlx_psid);
	} else {
		(void) fprintf(stdout, "        ");
		(void) fprintf(stdout, gettext("No HW information available"));
		(void) fprintf(stdout, "\n\n");
	}

	/* close the device */
	fwflash_ib_close(state.ibhdl);

	return (FWFLASH_SUCCESS);
}

static void
fwflash_ib_print_guids(uint64_t *guids)
{
	(void) fprintf(stdout, "        ");
	(void) fprintf(stdout, gettext("GUID"));
	(void) fprintf(stdout, ":\t");
	(void) fprintf(stdout, gettext("System Image"));
	(void) fprintf(stdout, " - %016llx\n", guids[3]);
	(void) fprintf(stdout, "        \t");
	(void) fprintf(stdout, gettext("Node Image"));
	(void) fprintf(stdout, "   - %016llx\n", guids[0]);
	(void) fprintf(stdout, "        \t");
	(void) fprintf(stdout, gettext("Port 1"));
	(void) fprintf(stdout, "       - %016llx\n", guids[1]);
	(void) fprintf(stdout, "        \t");
	(void) fprintf(stdout, gettext("Port 2"));
	(void) fprintf(stdout, "       - %016llx\n", guids[2]);
}

static int
fwflash_update_ib(char *device)
{
	uint64_t	guids[4];
	char		ans;
	int		rv;
	int		i;

	DPRINTF(DBG_INFO, ("fwflash_update_ib\n"));
	/* flash devices we're working on */
	state.ibhdl = fwflash_ib_open(device);
	if (state.ibhdl == NULL) {
		(void) fprintf(stderr, gettext("Failed to open device"));
		(void) fprintf(stderr, " (%s)\n", device);
		return (FWFLASH_FAILURE);
	}

	/* read in and verify the new firmware */
	DPRINTF(DBG_INFO, ("Verify new FW image\n"));
	rv = fwflash_ib_read_file(state.ibhdl, state.filename);
	if (rv != 0) {
		fwflash_usage();
		goto out;
	}

	/*
	 * Ask the user if he would like to continue.
	 */
	(void) fprintf(stdout, gettext("About to update firmware on"));
	(void) fprintf(stdout, ":\n\t%s\n", device);

	if (!(fwflash_arg_list & FWFLASH_YES_FLAG)) {
		(void) fprintf(stdout, gettext("Continue"));
		(void) fprintf(stdout, " (Y/N): ");
		ans = getchar();
		if (ans != 'Y' && ans != 'y') {
			DPRINTF(DBG_INFO, ("ans (%c)\n", ans));
			rv = FWFLASH_FAILURE;
			goto out;
		}
	}

	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("Updating"));
	(void) fprintf(stdout, " ");
	/* write both the primary and secondary images */
	fwflash_in_write = 1;

	/*
	 * Try to read existing GUIDs from the device.  We will use these, if
	 * we are able to read them, when updating each image.  We try the
	 * primary first, and then the secondary.  To the end user, there
	 * should be no distinction between primary and secondary images, so
	 * the GUID values are expected to be the same between both sets of
	 * images.
	 */
	DPRINTF(DBG_INFO, ("Using Existing GUIDs.\n"));
	rv = fwflash_ib_flash_read_guids(state.ibhdl, &guids[0], 1);
	if (rv != 0) {
		DPRINTF(DBG_ERR, ("Failed to read Primary GUIDs.  Trying "
		    "from secondary image.\n"));
		rv = fwflash_ib_flash_read_guids(state.ibhdl, &guids[0], 2);
		if (rv != 0) {
			(void) fprintf(stdout, "\n");
			(void) fprintf(stdout,
			    gettext("Failed to read any valid GUIDs."));
			(void) fprintf(stdout, "\n");
			(void) fprintf(stdout,
			    gettext("Using default GUIDs from file."));
			(void) fprintf(stdout, "\n");
		}
	}

	/*
	 * If we were able to read some valid GUIDs from either primary or
	 * secondary images, then we set them here to our local image.  This
	 * allows us to use the existing GUIDs in the firmware.  However, if
	 * both attempts to read GUIDs failed, then we do not set any of the
	 * GUIDs in our local image, and will use the values that are in the
	 * firmware file itself instead.
	 */
	if (rv == 0) {
		state.ibhdl->state |=
		    FWFLASH_IB_STATE_GUIDN |
		    FWFLASH_IB_STATE_GUID1 |
		    FWFLASH_IB_STATE_GUID2 |
		    FWFLASH_IB_STATE_GUIDS;
		rv = fwflash_ib_set_guids(state.ibhdl, guids, 1);
		if (rv != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to set GUIDs\n"));
		}
		rv = fwflash_ib_set_guids(state.ibhdl, guids, 2);
		if (rv != 0) {
			DPRINTF(DBG_ERR, ("\nFailed to set GUIDs\n"));
		}
	}

	/*
	 * Update both Primary and Secondary images
	 */
	for (i = FWFLASH_FLASH_IMAGES; i > 0; i--) {
		char *type = i == 1 ? "Primary" : "Secondary";

		DPRINTF(DBG_INFO, ("UPDATING %s IMAGE\n", type));
		rv = fwflash_ib_write_image(state.ibhdl, i);
		if (rv != 0) {
			(void) fprintf(stderr, gettext("Failed to update"));
			(void) fprintf(stderr, " %s ", type);
			(void) fprintf(stderr, gettext("image on device"));
			(void) fprintf(stderr, " %s\n", device);
			goto out;
		}

		DPRINTF(DBG_INFO, ("Verify %s image..\n", type));
		rv = fwflash_ib_verify_image(state.ibhdl, i);
		if (rv != 0) {
			(void) fprintf(stderr, gettext("Failed to verify"));
			(void) fprintf(stderr, " %s ", type);
			(void) fprintf(stderr, gettext("image for device"));
			(void) fprintf(stderr, " %s\n", state.device_name);
			goto out;
		}
	}
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("Done."));
	(void) fprintf(stdout, "  ");
	(void) fprintf(stdout,
	    gettext("New image will be active after the system is rebooted."));
	(void) fprintf(stdout, "\n");
out:
	fwflash_ib_close(state.ibhdl);
	fwflash_in_write = 0;
	return (rv);
}

static int
fwflash_read_file_ib(char *device)
{
	char			ans;
	int			rv;
	int			i;

	DPRINTF(DBG_INFO, ("fwflash_read_file_ib\n"));
	/* flash devices we're working on */
	state.ibhdl = fwflash_ib_open(device);
	if (state.ibhdl == NULL) {
		(void) fprintf(stderr, gettext("Failed to open device"));
		(void) fprintf(stderr, " (%s)\n", device);
		return (FWFLASH_FAILURE);
	}

	/*
	 * Ask the user if he would like to continue.
	 */
	(void) fprintf(stdout, gettext("About to read firmware on"));
	(void) fprintf(stdout, ":\n\t%s\n", device);
	(void) fprintf(stdout, gettext("to filename"));
	(void) fprintf(stdout, ": %s\n", state.filename);

	if (!(fwflash_arg_list & FWFLASH_YES_FLAG)) {
		(void) fprintf(stdout, gettext("Continue"));
		(void) fprintf(stdout, " (Y/N): ");
		ans = getchar();
		if (ans != 'Y' && ans != 'y') {
			DPRINTF(DBG_INFO, ("ans (%c)\n", ans));
			rv = FWFLASH_FAILURE;
			goto out;
		}
	}

	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("Reading"));

	/* read both the primary and secondary images */
	for (i = FWFLASH_FLASH_IMAGES; i > 0; i--) {
		char *type = i == 1 ? "Primary" : "Secondary";

		DPRINTF(DBG_INFO, ("READING %s IMAGE\n", type));
		(void) printf(" .");
		(void) fflush((void *)NULL);
		rv = fwflash_ib_read_image(state.ibhdl, i);
		if (rv != 0) {
			(void) fprintf(stderr, gettext("Failed to read"));
			(void) fprintf(stderr, " %s ", type);
			(void) fprintf(stderr, gettext("image on device"));
			(void) fprintf(stderr, " (%s)\n", state.device_name);
			goto out;
		}
	}
	(void) printf(" .");
	(void) fflush((void *)NULL);
	rv = fwflash_ib_write_file(state.ibhdl, state.filename);
	(void) fprintf(stdout, "\n");
	(void) fprintf(stdout, gettext("Done."));
	(void) fprintf(stdout, "\n");
out:
	fwflash_ib_close(state.ibhdl);
	fwflash_in_write = 0;
	return (rv);
}
