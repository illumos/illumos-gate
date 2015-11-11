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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 * Copyright 2014 Toomas Soome <tsoome@me.com>
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * This file contains functions that implement the command menu commands.
 */

#include "global.h"
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <strings.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#if defined(sparc)
#include <sys/hdio.h>
#endif /* defined(sparc) */

#include "main.h"
#include "analyze.h"
#include "menu.h"
#include "menu_command.h"
#include "menu_defect.h"
#include "menu_partition.h"
#include "param.h"
#include "misc.h"
#include "label.h"
#include "startup.h"
#include "partition.h"
#include "prompts.h"
#include "checkdev.h"
#include "io.h"
#include "ctlr_scsi.h"
#include "auto_sense.h"
#include "modify_partition.h"


extern	struct menu_item menu_partition[];
extern	struct menu_item menu_analyze[];
extern	struct menu_item menu_defect[];

/*
 * Choices for the p_tag vtoc field
 */
slist_t	ptag_choices[] = {
	{ "unassigned",	"",	V_UNASSIGNED	},
	{ "boot",	"",	V_BOOT		},
	{ "root",	"",	V_ROOT		},
	{ "swap",	"",	V_SWAP		},
	{ "usr",	"",	V_USR		},
	{ "backup",	"",	V_BACKUP	},
	{ "stand",	"",	V_STAND		},
	{ "var",	"",	V_VAR		},
	{ "home",	"",	V_HOME		},
	{ "alternates",	"",	V_ALTSCTR	},
	{ "reserved",	"",	V_RESERVED	},
	{ "system",	"",	V_SYSTEM	},
	{ "BIOS_boot",	"",	V_BIOS_BOOT	},
	{ NULL }
};


/*
 * Choices for the p_flag vtoc field
 */
slist_t	pflag_choices[] = {
	{ "wm",	"read-write, mountable",	0		},
	{ "wu",	"read-write, unmountable",	V_UNMNT		},
	{ "rm",	"read-only, mountable",		V_RONLY		},
	{ "ru",	"read-only, unmountable",	V_RONLY|V_UNMNT	},
	{ NULL }
};


/*
 * This routine implements the 'disk' command.  It allows the user to
 * select a disk to be current.  The list of choices is the list of
 * disks that were found at startup time.
 */
int
c_disk()
{
	struct disk_info	*disk;
	u_ioparam_t		ioparam;
	int			i;
	int			ndisks = 0;
	int			blind_select = 0;
	int			deflt;
	int			index;
	int			*defltptr = NULL;
	int			more = 0;
	int			more_quit = 0;
	int			one_line = 0;
	int			tty_lines;

/*
 * This buffer holds the check() prompt that verifies we've got the right
 * disk when performing a blind selection.  The size should be sufficient
 * to hold the prompt string, plus 256 characters for the disk name -
 * way more than should ever be necessary.  See the #define in misc.h.
 */
	char			chk_buf[BLIND_SELECT_VER_PROMPT];

	if (istokenpresent()) {
		/*
		 * disk number to be selected is already in the
		 * input stream .
		 */
		TOKEN token, cleantoken;

		/*
		 * Get the disk number the user has given.
		 */
		i = 0;
		for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
			i++;
		}

		ioparam.io_bounds.lower = 0;
		ioparam.io_bounds.upper = i - 1;
		(void) gettoken(token);
		clean_token(cleantoken, token);

		/*
		 * Convert the token into an integer.
		 */
		if (geti(cleantoken, &index, (int *)NULL))
			return (0);

		/*
		 * Check to be sure it is within the legal bounds.
		 */
		if ((index < 0) || (index >= i)) {
			err_print("`%d' is out of range.\n", index);
			return (0);
		}
		goto checkdisk;
	}

	fmt_print("\n\nAVAILABLE DISK SELECTIONS:\n");

	i = 0;
	if ((option_f == (char *)NULL) && isatty(0) == 1 && isatty(1) == 1) {
		/*
		 * We have a real terminal for std input and output, enable
		 * more style of output for disk selection list.
		 */
		more = 1;
		tty_lines = get_tty_lines();
		enter_critical();
		echo_off();
		charmode_on();
		exit_critical();
	}

	/*
	 * Loop through the list of found disks.
	 */
	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		/*
		 * If using more output, account 2 lines for each disk.
		 */
		if (more && !more_quit && i && (one_line ||
		    ((2 * i + 1) % (tty_lines - 2) <= 1))) {
			int	c;

			/*
			 * Get the next character.
			 */
			fmt_print("- hit space for more or s to select - ");
			c = getchar();
			fmt_print("\015");
			one_line = 0;
			/*
			 * Handle display one line command
			 * (return key)
			 */
			if (c == '\012') {
				one_line++;
			}
			/* Handle Quit command */
			if (c == 'q') {
				fmt_print(
				"                       \015");
				more_quit++;
			}
			/* Handle ^D command */
			if (c == '\004')
				fullabort();
			/* or get on with the show */
			if (c == 's' || c == 'S') {
				fmt_print("%80s\n", " ");
				break;
			}
		}
		/*
		 * If this is the current disk, mark it as
		 * the default.
		 */
		if (cur_disk == disk) {
			deflt = i;
			defltptr = &deflt;
		}
		if (!more || !more_quit)
			pr_diskline(disk, i);
		i++;
	}
	if (more) {
		enter_critical();
		charmode_off();
		echo_on();
		exit_critical();
	}

	/*
	 * Determine total number of disks, and ask the user which disk he
	 * would like to make current.
	 */

	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		ndisks++;
	}

	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = ndisks - 1;
	index = input(FIO_INT, "Specify disk (enter its number)", ':',
	    &ioparam, defltptr, DATA_INPUT);

	if (index >= i) {
		blind_select = 1;
	}

	/*
	 * Find the disk chosen.  Search through controllers/disks
	 * in the same original order, so we match what the user
	 * chose.
	 */
checkdisk:
	i = 0;
	for (disk = disk_list; disk != NULL; disk = disk->disk_next) {
		if (i == index)
			goto found;
		i++;
	}
	/*
	 * Should never happen.
	 */
	impossible("no disk found");

found:
	if (blind_select) {
		(void) snprintf(chk_buf, sizeof (chk_buf),
"Disk %s selected - is this the desired disk? ", disk->disk_name);
		if (check(chk_buf)) {
			return (-1);
		}
	}

	/*
	 * Update the state.  We lock out interrupts so the state can't
	 * get half-updated.
	 */

	enter_critical();
	init_globals(disk);
	exit_critical();

	/*
	 * If type unknown and interactive, ask user to specify type.
	 * Also, set partition table (best guess) too.
	 */
	if (!option_f && ncyl == 0 && nhead == 0 && nsect == 0 &&
	    (disk->label_type != L_TYPE_EFI)) {
		(void) c_type();
	}

	/*
	 * Get the Solaris Fdisk Partition information
	 */
	if (nhead != 0 && nsect != 0)
		(void) copy_solaris_part(&cur_disk->fdisk_part);

	if ((cur_disk->label_type == L_TYPE_EFI) &&
	    (cur_disk->disk_parts->etoc->efi_flags &
	    EFI_GPT_PRIMARY_CORRUPT)) {
		err_print("Reading the primary EFI GPT label ");
		err_print("failed.  Using backup label.\n");
		err_print("Use the 'backup' command to restore ");
		err_print("the primary label.\n");
	}

#if defined(_SUNOS_VTOC_16)
	/*
	 * If there is no fdisk solaris partition.
	 */
	if (cur_disk->fdisk_part.numsect == 0) {
		err_print("No Solaris fdisk partition found.\n");
		goto exit;
	}
#endif /* defined(_SUNOS_VTOC_16) */

	/*
	 * If the label of the disk is marked dirty,
	 * see if they'd like to label the disk now.
	 */
	if (cur_disk->disk_flags & DSK_LABEL_DIRTY) {
		if (check("Disk not labeled.  Label it now") == 0) {
			if (write_label()) {
				err_print("Write label failed\n");
			} else {
				cur_disk->disk_flags &= ~DSK_LABEL_DIRTY;
			}
		}
	}
exit:
	return (0);
}

/*
 * This routine implements the 'type' command.  It allows the user to
 * specify the type of the current disk.  It should be necessary only
 * if the disk was not labelled or was somehow labelled incorrectly.
 * The list of legal types for the disk comes from information that was
 * in the data file.
 */
int
c_type()
{
	struct disk_type	*type, *tptr, *oldtype;
	u_ioparam_t		ioparam;
	int			i, index, deflt, *defltptr = NULL;
	struct disk_type	disk_type;
	struct disk_type	*d = &disk_type;
	int			first_disk;
	int			auto_conf_choice;
	int			other_choice;
	struct dk_label		label;
	struct efi_info		efi_info;
	uint64_t		maxLBA;
	char			volname[LEN_DKL_VVOL];
	int			volinit = 0;

	/*
	 * There must be a current disk.
	 */
	if (cur_disk == NULL) {
		err_print("Current Disk is not set.\n");
		return (-1);
	}
	oldtype = cur_disk->disk_type;
	type = cur_ctype->ctype_dlist;
	/*
	 * Print out the list of choices.
	 */
	fmt_print("\n\nAVAILABLE DRIVE TYPES:\n");
	first_disk = 0;
	if (cur_ctype->ctype_ctype == DKC_SCSI_CCS) {
		auto_conf_choice = 0;
		fmt_print("        %d. Auto configure\n", first_disk++);
	} else {
		auto_conf_choice = -1;
	}

	i = first_disk;
	for (tptr = type; tptr != NULL; tptr = tptr->dtype_next) {
		/*
		 * If we pass the current type, mark it to be the default.
		 */
		if (cur_dtype == tptr) {
			deflt = i;
			defltptr = &deflt;
		}
		if (cur_disk->label_type == L_TYPE_EFI) {
			continue;
		}
		if (tptr->dtype_asciilabel)
			fmt_print("        %d. %s\n", i++,
			    tptr->dtype_asciilabel);
	}
	other_choice = i;
	fmt_print("        %d. other\n", i);
	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = i;
	/*
	 * Ask the user which type the disk is.
	 */
	index = input(FIO_INT, "Specify disk type (enter its number)", ':',
	    &ioparam, defltptr, DATA_INPUT);
	/*
	 * Find the type s/he chose.
	 */
	if (index == auto_conf_choice) {
		float			scaled;
		diskaddr_t		nblks;
		int			nparts;

		/*
		 * User chose "auto configure".
		 */
		(void) strcpy(x86_devname, cur_disk->disk_name);
		switch (cur_disk->label_type) {
		case L_TYPE_SOLARIS:
			if ((tptr = auto_sense(cur_file, 1, &label)) == NULL) {
				err_print("Auto configure failed\n");
				return (-1);
			}
			fmt_print("%s: configured with capacity of ",
			    cur_disk->disk_name);
			nblks = (diskaddr_t)tptr->dtype_ncyl *
			    tptr->dtype_nhead * tptr->dtype_nsect;
			scaled = bn2mb(nblks);
			if (scaled > 1024.0) {
				fmt_print("%1.2fGB\n", scaled/1024.0);
			} else {
				fmt_print("%1.2fMB\n", scaled);
			}
			fmt_print("<%s cyl %d alt %d hd %d sec %d>\n",
			    tptr->dtype_asciilabel, tptr->dtype_ncyl,
			    tptr->dtype_acyl, tptr->dtype_nhead,
			    tptr->dtype_nsect);
			break;
		case L_TYPE_EFI:
			if ((tptr = auto_efi_sense(cur_file, &efi_info))
			    == NULL) {
				err_print("Auto configure failed\n");
				return (-1);
			}
			fmt_print("%s: configured with capacity of ",
			    cur_disk->disk_name);
			scaled = bn2mb(efi_info.capacity);
			if (scaled > 1024.0) {
				fmt_print("%1.2fGB\n", scaled/1024.0);
			} else {
				fmt_print("%1.2fMB\n", scaled);
			}
			cur_blksz = efi_info.e_parts->efi_lbasize;
			print_efi_string(efi_info.vendor, efi_info.product,
			    efi_info.revision, efi_info.capacity);
			fmt_print("\n");
			for (nparts = 0; nparts < cur_parts->etoc->efi_nparts;
			    nparts++) {
				if (cur_parts->etoc->efi_parts[nparts].p_tag ==
				    V_RESERVED) {
					if (cur_parts->etoc->efi_parts[nparts].
					    p_name) {
						(void) strcpy(volname,
						    cur_parts->etoc->efi_parts
						    [nparts].p_name);
						volinit = 1;
					}
					break;
				}
			}
			enter_critical();
			if (delete_disk_type(cur_disk->disk_type) != 0) {
				fmt_print("Autoconfiguration failed.\n");
				return (-1);
			}
			cur_disk->disk_type = tptr;
			cur_disk->disk_parts = tptr->dtype_plist;
			init_globals(cur_disk);
			exit_critical();
			if (volinit) {
				for (nparts = 0; nparts <
				    cur_parts->etoc->efi_nparts; nparts++) {
				if (cur_parts->etoc->efi_parts[nparts].p_tag ==
				    V_RESERVED) {
				(void) strcpy(
				    cur_parts->etoc->efi_parts[nparts].p_name,
				    volname);
				(void) strlcpy(cur_disk->v_volume, volname,
				    LEN_DKL_VVOL);
				break;
				}
				}
			}
			return (0);
		default:
			/* Should never happen */
			return (-1);
		}
	} else if ((index == other_choice) && (cur_label == L_TYPE_SOLARIS)) {
		/*
		 * User chose "other".
		 * Get the standard information on the new type.
		 * Put all information in a tmp structure, in
		 * case user aborts.
		 */
		bzero((char *)d, sizeof (struct disk_type));

		d->dtype_ncyl = get_ncyl();
		d->dtype_acyl = get_acyl(d->dtype_ncyl);
		d->dtype_pcyl = get_pcyl(d->dtype_ncyl, d->dtype_acyl);
		d->dtype_nhead = get_nhead();
		d->dtype_phead = get_phead(d->dtype_nhead, &d->dtype_options);
		d->dtype_nsect = get_nsect();
		d->dtype_psect = get_psect(&d->dtype_options);
		d->dtype_bpt = get_bpt(d->dtype_nsect, &d->dtype_options);
		d->dtype_rpm = get_rpm();
		d->dtype_fmt_time = get_fmt_time(&d->dtype_options);
		d->dtype_cyl_skew = get_cyl_skew(&d->dtype_options);
		d->dtype_trk_skew = get_trk_skew(&d->dtype_options);
		d->dtype_trks_zone = get_trks_zone(&d->dtype_options);
		d->dtype_atrks = get_atrks(&d->dtype_options);
		d->dtype_asect = get_asect(&d->dtype_options);
		d->dtype_cache = get_cache(&d->dtype_options);
		d->dtype_threshold = get_threshold(&d->dtype_options);
		d->dtype_prefetch_min = get_min_prefetch(&d->dtype_options);
		d->dtype_prefetch_max = get_max_prefetch(d->dtype_prefetch_min,
		    &d->dtype_options);
		d->dtype_bps = get_bps();
#if defined(sparc)
		d->dtype_dr_type = 0;
#endif /* defined(sparc) */

		d->dtype_asciilabel = get_asciilabel();
		/*
		 * Add the new type to the list of possible types for
		 * this controller.  We lock out interrupts so the lists
		 * can't get munged.  We put off actually allocating the
		 * structure till here in case the user wanted to
		 * interrupt while still inputting information.
		 */
		enter_critical();
		tptr = (struct disk_type *)zalloc(sizeof (struct disk_type));
		if (type == NULL)
			cur_ctype->ctype_dlist = tptr;
		else {
			while (type->dtype_next != NULL)
				type = type->dtype_next;
			type->dtype_next = tptr;
		}
		bcopy((char *)d, (char *)tptr, sizeof (disk_type));
		tptr->dtype_next = NULL;
		/*
		 * the new disk type does not have any defined
		 * partition table . Hence copy the current partition
		 * table if possible else create a default
		 * paritition table.
		 */
		new_partitiontable(tptr, oldtype);
	} else if ((index == other_choice) && (cur_label == L_TYPE_EFI)) {
		maxLBA = get_mlba();
		cur_parts->etoc->efi_last_lba = maxLBA;
		cur_parts->etoc->efi_last_u_lba = maxLBA - 34;
		for (i = 0; i < cur_parts->etoc->efi_nparts; i++) {
			cur_parts->etoc->efi_parts[i].p_start = 0;
			cur_parts->etoc->efi_parts[i].p_size = 0;
			cur_parts->etoc->efi_parts[i].p_tag = V_UNASSIGNED;
		}
		cur_parts->etoc->efi_parts[8].p_start =
		    maxLBA - 34 - (1024 * 16);
		cur_parts->etoc->efi_parts[8].p_size = (1024 * 16);
		cur_parts->etoc->efi_parts[8].p_tag = V_RESERVED;
		if (write_label()) {
			err_print("Write label failed\n");
		} else {
			cur_disk->disk_flags &= ~DSK_LABEL_DIRTY;
		}
		return (0);
	} else {
		/*
		 * User picked an existing disk type.
		 */
		i = first_disk;
		tptr = type;
		while (i < index) {
			if (tptr->dtype_asciilabel) {
				i++;
			}
			tptr = tptr->dtype_next;
		}
		if ((tptr->dtype_asciilabel == NULL) &&
		    (tptr->dtype_next != NULL)) {
			while (tptr->dtype_asciilabel == NULL) {
				tptr = tptr->dtype_next;
			}
		}
	}
	/*
	 * Check for mounted file systems in the format zone.
	 * One potential problem with this would be that check()
	 * always returns 'yes' when running out of a file.  However,
	 * it is actually ok because we don't let the program get
	 * started if there are mounted file systems and we are
	 * running from a file.
	 */
	if ((tptr != oldtype) &&
	    checkmount((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print(
		    "Cannot set disk type while it has mounted "
		    "partitions.\n\n");
		return (-1);
	}
	/*
	 * check for partitions being used for swapping in format zone
	 */
	if ((tptr != oldtype) &&
	    checkswap((diskaddr_t)-1, (diskaddr_t)-1)) {
		err_print("Cannot set disk type while its partition are "
		"currently being used for swapping.\n");
		return (-1);
	}

	/*
	 * Check for partitions being used in SVM, VxVM or LU devices
	 */

	if ((tptr != oldtype) &&
	    checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 0)) {
		err_print("Cannot set disk type while its "
		    "partitions are currently in use.\n");
		return (-1);
	}
	/*
	 * If the type selected is different from the previous type,
	 * mark the disk as not labelled and reload the current
	 * partition info.  This is not essential but probably the
	 * right thing to do, since the size of the disk has probably
	 * changed.
	 */
	enter_critical();
	if (tptr != oldtype) {
		cur_disk->disk_type = tptr;
		cur_disk->disk_parts = NULL;
		cur_disk->disk_flags &= ~DSK_LABEL;
	}
	/*
	 * Initialize the state of the current disk.
	 */
	init_globals(cur_disk);
	(void) get_partition();
	exit_critical();

	/*
	 * If the label of the disk is marked dirty,
	 * see if they'd like to label the disk now.
	 */
	if (cur_disk->disk_flags & DSK_LABEL_DIRTY) {
		if (check("Disk not labeled.  Label it now") == 0) {
			if (write_label()) {
				err_print("Write label failed\n");
			} else {
				cur_disk->disk_flags &= ~DSK_LABEL_DIRTY;
			}
		}
	}

	return (0);
}

/*
 * This routine implements the 'partition' command.  It simply runs
 * the partition menu.
 */
int
c_partition()
{

	/*
	 * There must be a current disk type and a current disk
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}

	cur_menu++;
	last_menu = cur_menu;

#ifdef	not
	/*
	 * If there is no current partition table, make one.  This is
	 * so the commands within the menu never have to check for
	 * a non-existent table.
	 */
	if (cur_parts == NULL)
		err_print("making partition.\n");
		make_partition();
#endif	/* not */

	/*
	 * Run the menu.
	 */
	run_menu(menu_partition, "PARTITION", "partition", 0);
	cur_menu--;
	return (0);
}

/*
 * This routine implements the 'current' command.  It describes the
 * current disk.
 */
int
c_current()
{

	/*
	 * If there is no current disk, say so.  Note that this is
	 * not an error since it is a legitimate response to the inquiry.
	 */
	if (cur_disk == NULL) {
		fmt_print("No Current Disk.\n");
		return (0);
	}
	/*
	 * Print out the info we have on the current disk.
	 */
	fmt_print("Current Disk = %s", cur_disk->disk_name);
	if (chk_volname(cur_disk)) {
		fmt_print(": ");
		print_volname(cur_disk);
	}
	fmt_print("\n");
	if (cur_disk->devfs_name != NULL) {
		if (cur_dtype == NULL) {
			fmt_print("<type unknown>\n");
		} else if (cur_label == L_TYPE_SOLARIS) {
			fmt_print("<%s cyl %d alt %d hd %d sec %d>\n",
			    cur_dtype->dtype_asciilabel, ncyl,
			    acyl, nhead, nsect);
		} else if (cur_label == L_TYPE_EFI) {
			print_efi_string(cur_dtype->vendor,
			    cur_dtype->product, cur_dtype->revision,
			    cur_dtype->capacity);
			fmt_print("\n");
		}
		fmt_print("%s\n", cur_disk->devfs_name);
	} else {
		fmt_print("%s%d: <", cur_ctlr->ctlr_dname,
		    cur_disk->disk_dkinfo.dki_unit);
		if (cur_dtype == NULL) {
			fmt_print("type unknown");
		} else if (cur_label == L_TYPE_SOLARIS) {
			fmt_print("%s cyl %d alt %d hd %d sec %d",
			    cur_dtype->dtype_asciilabel, ncyl,
			    acyl, nhead, nsect);
		} else if (cur_label == L_TYPE_EFI) {
			print_efi_string(cur_dtype->vendor,
			    cur_dtype->product, cur_dtype->revision,
			    cur_dtype->capacity);
			fmt_print("\n");
		}
		fmt_print(">\n");
	}
	fmt_print("\n");
	return (0);
}
/*
 * This routine implements the 'format' command.  It allows the user
 * to format and verify any portion of the disk.
 */
int
c_format()
{
	diskaddr_t		start, end;
	time_t			clock;
	int			format_time, format_tracks, format_cyls;
	int			format_interval;
	diskaddr_t		deflt;
	int			status;
	u_ioparam_t		ioparam;
	struct scsi_inquiry	*inq;
	char	rawbuf[MAX_MODE_SENSE_SIZE];
	struct scsi_capacity_16	capacity;
	struct vpd_hdr	*vpdhdr;
	uint8_t	protect;
	uint8_t	pagecode;
	uint8_t	spt;
	uint8_t	p_type;
	uint8_t	prot_flag[NUM_PROT_TYPE] = {1, 0, 0, 0};
	int	i;
	char	*prot_descriptor[NUM_PROT_TYPE] = {
	    "Protection Information is disabled.",
	    "Protection Information is enabled.",
	    "Protection Information is enabled.",
	    "Protection Information is enabled.", };

	/*
	 * There must be a current disk type and a current disk
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}

	/*
	 * There must be a format routine in cur_ops structure to have
	 *  this routine work.
	 */
	if (cur_ops->op_format == NULL) {
		err_print(
"Cannot format this drive. Please use your Manufacturer supplied formatting "
"utility.\n");
		return (-1);
	}

	/*
	 * There must be a current defect list.  Except for
	 * unformatted SCSI disks.  For them the defect list
	 * can only be retrieved after formatting the disk.
	 */
	if ((cur_ctype->ctype_flags & CF_SCSI) && !EMBEDDED_SCSI &&
	    (cur_ctype->ctype_flags & CF_DEFECTS) &&
	    ! (cur_flags & DISK_FORMATTED)) {
		cur_list.flags |= LIST_RELOAD;

	} else if (cur_list.list == NULL && !EMBEDDED_SCSI) {
		err_print("Current Defect List must be initialized.\n");
		return (-1);
	}
	/*
	 * Ask for the bounds of the format.  We always use the whole
	 * disk as the default, since that is the most likely case.
	 * Note, for disks which must be formatted accross the whole disk,
	 * don't bother the user.
	 */
	ioparam.io_bounds.lower = start = 0;
	if (cur_label == L_TYPE_SOLARIS) {
		if (cur_ctype->ctype_flags & CF_SCSI) {
			ioparam.io_bounds.upper = end = datasects() - 1;
		} else {
			ioparam.io_bounds.upper = end = physsects() - 1;
		}
	} else {
		ioparam.io_bounds.upper = end = cur_parts->etoc->efi_last_lba;
	}

	if (! (cur_ctlr->ctlr_flags & DKI_FMTVOL)) {
		deflt = ioparam.io_bounds.lower;
		start = input(FIO_BN,
		    "Enter starting block number", ':',
		    &ioparam, (int *)&deflt, DATA_INPUT);
		ioparam.io_bounds.lower = start;
		deflt = ioparam.io_bounds.upper;
		end = input(FIO_BN,
		    "Enter ending block number", ':',
		    &ioparam, (int *)&deflt, DATA_INPUT);
	}
	/*
	 * Some disks can format tracks.  Make sure the whole track is
	 * specified for them.
	 */
	if (cur_ctlr->ctlr_flags & DKI_FMTTRK) {
		if (bn2s(start) != 0 ||
		    bn2s(end) != sectors(bn2h(end)) - 1) {
			err_print("Controller requires formatting of ");
			err_print("entire tracks.\n");
			return (-1);
		}
	}
	/*
	 * Check for mounted file systems in the format zone, and if we
	 * find any, make sure they are really serious.  One potential
	 * problem with this would be that check() always returns 'yes'
	 * when running out of a file.  However, it is actually ok
	 * because we don't let the program get started if there are
	 * mounted file systems and we are running from a file.
	 */
	if (checkmount(start, end)) {
		err_print(
		"Cannot format disk while it has mounted partitions.\n\n");
		return (-1);
	}
	/*
	 * check for partitions being used for swapping in format zone
	 */
	if (checkswap(start, end)) {
		err_print("Cannot format disk while its partition are \
currently being used for swapping.\n");
		return (-1);
	}
	/*
	 * Check for partitions being used in SVM, VxVM or LU devices
	 * in this format zone
	 */
	if (checkdevinuse(cur_disk->disk_name, start, end, 0, 0)) {
		err_print("Cannot format disk while its partitions "
		    "are currently in use.\n");
		return (-1);
	}

	if (cur_disk->disk_lbasize != DEV_BSIZE) {
		fmt_print("Current disk sector size is %d Byte, format\n"
		    "will change the sector size to 512 Byte. ",
		    cur_disk->disk_lbasize);
		if (check("Continue")) {
			return (-1);
		}
	}

	/*
	 * set the default protection type
	 */
	prot_type = PROT_TYPE_0;

	/*
	 * Check if the protect information of this disk is enabled
	 */
	if (uscsi_inquiry(cur_file, rawbuf, sizeof (rawbuf))) {
		err_print("Inquiry failed\n");
		return (-1);
	}
	inq = (struct scsi_inquiry *)rawbuf;
	protect = inq->inq_protect;
	if (protect == 0) {
		fmt_print("The protection information is not enabled\n");
		fmt_print(
		    "The disk will be formatted with protection type 0\n");
	} else {
		(void) memset(rawbuf, 0, MAX_MODE_SENSE_SIZE);
		if (uscsi_inquiry_page_86h(cur_file, rawbuf, sizeof (rawbuf))) {
			err_print("Inquiry with page 86h failed\n");
			return (-1);
		}
		vpdhdr = (struct vpd_hdr *)rawbuf;
		pagecode = vpdhdr->page_code;
		if (pagecode != 0x86) {
			err_print("Inquiry with page 86h failed\n");
			return (-1);
		}
		spt = (rawbuf[4] << 2) >> 5;
		fmt_print("This disk can support protection types:\n");

		switch (spt) {
		case 0:
			prot_flag[1] = 1;
			break;
		case 1:
			prot_flag[1] = 1;
			prot_flag[2] = 1;
			break;
		case 2:
			prot_flag[2] = 1;
			break;
		case 3:
			prot_flag[1] = 1;
			prot_flag[3] = 1;
			break;
		case 4:
			prot_flag[3] = 1;
			break;
		case 5:
			prot_flag[2] = 1;
			prot_flag[3] = 1;
			break;
		case 7:
			prot_flag[1] = 1;
			prot_flag[2] = 1;
			prot_flag[3] = 1;
			break;
		default:
			err_print(
			    "Invalid supported protection types\n");
			return (-1);
		}
		for (i = 0; i < NUM_PROT_TYPE; i++) {
			if (prot_flag[i] == 1) {
				fmt_print("[%d] TYPE_%d : ", i, i);
				fmt_print("%s\n", prot_descriptor[i]);
			}
		}

		/*
		 * Get the current protection type
		 */
		if (uscsi_read_capacity_16(cur_file, &capacity)) {
			err_print("Read capacity_16 failed\n");
			return (-1);
		}
		p_type = get_cur_protection_type(&capacity);
		fmt_print("\nThe disk is currently formatted with TYPE_%d.\n",
		    p_type);

		/*
		 * Ask user what protection type to use
		 */
		ioparam.io_bounds.lower = PROT_TYPE_0;
		ioparam.io_bounds.upper = PROT_TYPE_3;
		prot_type = input(FIO_INT, "Specify the New Protection Type",
		    ':', &ioparam, NULL, DATA_INPUT);
		/*
		 * if get a unsupported protection type, then use the
		 * current type: p_type.
		 */
		if (prot_flag[prot_type] == 0) {
			fmt_print("Unsupported protection type.\n");
			prot_type = p_type;
		}
		fmt_print("The disk will be formatted to type %d\n", prot_type);
	}

	if (SCSI && (format_time = scsi_format_time()) > 0) {
		fmt_print(
		    "\nReady to format.  Formatting cannot be interrupted\n"
		    "and takes %d minutes (estimated). ", format_time);

	} else if (cur_dtype->dtype_options & SUP_FMTTIME) {
		/*
		 * Formatting time is (2 * time of 1 spin * number of
		 * tracks) + (step rate * number of cylinders) rounded
		 * up to the nearest minute.  Note, a 10% fudge factor
		 * is thrown in for insurance.
		 */
		if (cur_dtype->dtype_fmt_time == 0)
			cur_dtype->dtype_fmt_time = 2;

		format_tracks = ((end-start) / cur_dtype->dtype_nsect) + 1;
		format_cyls = format_tracks / cur_dtype->dtype_nhead;
		format_tracks = format_tracks * cur_dtype->dtype_fmt_time;

		/*
		 * ms.
		 */
		format_time = ((60000 / cur_dtype->dtype_rpm) +1) *
		    format_tracks + format_cyls * 7;
		/*
		 * 20% done tick (sec)
		 */
		format_interval = format_time / 5000;
		/*
		 * min.
		 */
		format_time = (format_time + 59999) / 60000;

		/*
		 * Check format time values and make adjustments
		 * to prevent sleeping too long (forever?) or
		 * too short.
		 */
		if (format_time <= 1) {
			/*
			 * Format time is less than 1 min..
			 */
			format_time = 1;
		}

		if (format_interval < 11) {
			/* Format time is less than 1 minute. */
			if (format_interval < 2)
				format_interval = 2;	/* failsafe */
			format_interval = 10;
		} else {
			/* Format time is greater than 1 minute. */
			format_interval -= 10;
		}

		fmt_print(
		    "Ready to format.  Formatting cannot be interrupted\n"
		    "and takes %d minutes (estimated). ", format_time);
	} else {
		fmt_print(
		    "Ready to format.  Formatting cannot be interrupted.\n");
	}
	if (check("Continue")) {
		return (-1);
	}

	/*
	 * Print the time so that the user will know when format started.
	 * Lock out interrupts.  This could be a problem, since it could
	 * cause the user to sit for quite awhile with no control, but we
	 * don't have any other good way of keeping his gun from going off.
	 */
	clock = time((time_t *)0);
	fmt_print("Beginning format. The current time is %s\n",
	    ctime(&clock));
	enter_critical();
	/*
	 * Mark the defect list dirty so it will be rewritten when we are
	 * done.  It is possible to qualify this so it doesn't always
	 * get rewritten, but it's not worth the trouble.
	 * Note: no defect lists for embedded scsi drives.
	 */
	if (!EMBEDDED_SCSI) {
		cur_list.flags |= LIST_DIRTY;
	}
	/*
	 * If we are formatting over any of the labels, mark the label
	 * dirty so it will be rewritten.
	 */
	if (cur_disk->label_type == L_TYPE_SOLARIS) {
		if (start < totalsects() && end >= datasects()) {
			if (cur_disk->disk_flags & DSK_LABEL)
				cur_flags |= LABEL_DIRTY;
		}
	} else if (cur_disk->label_type == L_TYPE_EFI) {
		if (start < 34) {
			if (cur_disk->disk_flags & DSK_LABEL)
				cur_flags |= LABEL_DIRTY;
		}
	}
	if (start == 0) {
		cur_flags |= LABEL_DIRTY;
	}
	/*
	 * Do the format. bugid 1009138 removed the use of fork to
	 * background the format and print a tick.
	 */

	status = (*cur_ops->op_format)(start, end, &cur_list);
	if (status) {
		exit_critical();
		err_print("failed\n");
		return (-1);
	}
	fmt_print("done\n");
	if (option_msg && diag_msg) {
		clock = time((time_t *)0);
		fmt_print("The current time is %s\n", ctime(&clock));
	}
	cur_flags |= DISK_FORMATTED;
	/*
	 * If the defect list or label is dirty, write them out again.
	 * Note, for SCSI we have to wait til now to load defect list
	 * since we can't access it until after formatting a virgin disk.
	 */
	/* enter_critical(); */
	if (cur_list.flags & LIST_RELOAD) {
		assert(!EMBEDDED_SCSI);
		if (*cur_ops->op_ex_man == NULL ||
		    (*cur_ops->op_ex_man)(&cur_list)) {
			err_print("Warning: unable to reload defect list\n");
			cur_list.flags &= ~LIST_DIRTY;
			return (-1);
		}
		cur_list.flags |= LIST_DIRTY;
	}

	if (cur_list.flags & LIST_DIRTY) {
		assert(!EMBEDDED_SCSI);
		write_deflist(&cur_list);
		cur_list.flags = 0;
	}
	if (cur_flags & LABEL_DIRTY) {
		(void) write_label();
		cur_flags &= ~LABEL_DIRTY;
	}
	/*
	 * Come up for air, since the verify step does not need to
	 * be atomic (it does it's own lockouts when necessary).
	 */
	exit_critical();
	/*
	 * If we are supposed to verify, we do the 'write' test over
	 * the format zone.  The rest of the analysis parameters are
	 * left the way they were.
	 */
	if (scan_auto) {
		scan_entire = 0;
		scan_lower = start;
		scan_upper = end;
		fmt_print("\nVerifying media...");
		status = do_scan(SCAN_PATTERN, F_SILENT);
	}
	/*
	 * If the defect list or label is dirty, write them out again.
	 */
	if (cur_list.flags & LIST_DIRTY) {
		assert(!EMBEDDED_SCSI);
		cur_list.flags = 0;
		write_deflist(&cur_list);
	}
	if (cur_flags & LABEL_DIRTY) {
		cur_flags &= ~LABEL_DIRTY;
		(void) write_label();
	}
	return (status);
}

/*
 * This routine implements the 'repair' command.  It allows the user
 * to reallocate sectors on the disk that have gone bad.
 */
int
c_repair()
{
	diskaddr_t	bn;
	int		status;
	u_ioparam_t	ioparam;
	char		*buf;
	int		buf_is_good;
	int		block_has_error;
	int		i;

	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * The current disk must be formatted for repair to work.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}
	/*
	 * Repair is an optional command for controllers, so it may
	 * not be supported.
	 */
	if (cur_ops->op_repair == NULL) {
		err_print("Controller does not support repairing.\n");
		err_print("or disk supports automatic defect management.\n");
		return (-1);
	}
	/*
	 * There must be a defect list for non-embedded scsi devices,
	 * since we will add to it.
	 */
	if (!EMBEDDED_SCSI && cur_list.list == NULL) {
		err_print("Current Defect List must be initialized.\n");
		return (-1);
	}
	/*
	 * Ask the user which sector has gone bad.
	 */
	ioparam.io_bounds.lower = 0;
	if (cur_disk->label_type == L_TYPE_SOLARIS) {
		ioparam.io_bounds.upper = physsects() - 1;
	} else {
		ioparam.io_bounds.upper = cur_parts->etoc->efi_last_lba;
	}
	bn = input(FIO_BN,
	    "Enter absolute block number of defect", ':',
	    &ioparam, (int *)NULL, DATA_INPUT);
	/*
	 * Check to see if there is a mounted file system over the
	 * specified sector.  If there is, make sure the user is
	 * really serious.
	 */
	if (checkmount(bn, bn)) {
		if (check("Repair is in a mounted partition, continue"))
			return (-1);
	}
	/*
	 * check for partitions being used for swapping in format zone
	 */
	if (checkswap(bn, bn)) {
		if (check("Repair is in a partition which is currently \
being used for swapping.\ncontinue"))
		return (-1);
	}

	if (checkdevinuse(cur_disk->disk_name, bn, bn, 0, 0)) {
		if (check("Repair is in a partition which is currently "
		    "in use.\ncontinue"))
			return (-1);
	}

	buf = zalloc((cur_disk->disk_lbasize == 0) ?
	    SECSIZE : cur_disk->disk_lbasize);

	/*
	 * Try to read the sector before repairing it.  If we can
	 * get good data out of it, we can write that data back
	 * after the repair.  If the sector looks ok, ask the
	 * user to confirm the repair, since it doesn't appear
	 * necessary.  Try reading the block several times to
	 * see if we can read it consistently.
	 *
	 * First, let's see if the block appears to have problems...
	 */
	block_has_error = 1;
	for (i = 0; i < 5; i++) {
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, bn,
		    1, buf, (F_SILENT | F_ALLERRS), NULL);
		if (status)
			break;		/* one of the tries failed */
	}
	if (status == 0) {
		block_has_error = 0;
		if (check("\
This block doesn't appear to be bad.  Repair it anyway")) {
			free(buf);
			return (0);
		}
	}
	/*
	 * Last chance...
	 */
	if (check("Ready to repair defect, continue")) {
		free(buf);
		return (-1);
	}
	/*
	 * We're committed to repairing it.  Try to get any good
	 * data out of the block if possible.  Note that we do
	 * not set the F_ALLERRS flag.
	 */
	buf_is_good = 0;
	for (i = 0; i < 5; i++) {
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, bn,
		    1, buf, F_SILENT, NULL);
		if (status == 0) {
			buf_is_good = 1;
			break;
		}
	}
	/*
	 * Lock out interrupts so the disk can't get out of sync with
	 * the defect list.
	 */
	enter_critical();

	fmt_print("Repairing ");
	if (block_has_error) {
		fmt_print("%s error on ", buf_is_good ? "soft" : "hard");
	}
	fmt_print("block %llu (", bn);
	pr_dblock(fmt_print, bn);
	fmt_print(")...");
	/*
	 * Do the repair.
	 */
	status = (*cur_ops->op_repair)(bn, F_NORMAL);
	if (status) {
		fmt_print("failed.\n\n");
	} else {
		/*
		 * The repair worked.  Write the old data to the new
		 * block if we were able to read it, otherwise
		 * zero out the new block.  If it looks like the
		 * new block is bad, let the user know that, too.
		 * Should we attempt auto-repair in this case?
		 */
		fmt_print("ok.\n");
		if (!buf_is_good) {
			bzero(buf, cur_disk->disk_lbasize);
		}
		status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file, bn,
		    1, buf, (F_SILENT | F_ALLERRS), NULL);
		if (status == 0) {
			status = (*cur_ops->op_rdwr)(DIR_READ, cur_file,
			    bn, 1, buf, (F_SILENT | F_ALLERRS), NULL);
		}
		if (status) {
			fmt_print("The new block %llu (", bn);
			pr_dblock(fmt_print, bn);
			fmt_print(") also appears defective.\n");
		}
		fmt_print("\n");
		/*
		 * Add the bad sector to the defect list, write out
		 * the defect list, and kill off the working list so
		 * it will get synced up with the current defect list
		 * next time we need it.
		 *
		 * For embedded scsi, we don't require a defect list.
		 * However, if we have one, add the defect if the
		 * list includes the grown list.  If not, kill it
		 * to force a resync if we need the list later.
		 */
		if (EMBEDDED_SCSI) {
			if (cur_list.list != NULL) {
				if (cur_list.flags & LIST_PGLIST) {
					add_ldef(bn, &cur_list);
				} else {
					kill_deflist(&cur_list);
				}
			}
		} else if (cur_ctype->ctype_flags & CF_WLIST) {
			kill_deflist(&cur_list);
			if (*cur_ops->op_ex_cur != NULL) {
				(*cur_ops->op_ex_cur)(&cur_list);
				fmt_print("Current list updated\n");
			}
		} else {
			add_ldef(bn, &cur_list);
			write_deflist(&cur_list);
		}
		kill_deflist(&work_list);
	}
	exit_critical();
	free(buf);

	/*
	 * Return status.
	 */
	return (status);
}

/*
 * This routine implements the 'show' command.  It translates a disk
 * block given in any format into decimal, hexadecimal, and
 * cylinder/head/sector format.
 */
int
c_show()
{
	u_ioparam_t	ioparam;
	diskaddr_t	bn;

	/*
	 * There must be a current disk type, so we will know the geometry.
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * Ask the user for a disk block.
	 */
	ioparam.io_bounds.lower = 0;
	if (cur_disk->label_type == L_TYPE_SOLARIS) {
		ioparam.io_bounds.upper = physsects() - 1;
	} else {
		ioparam.io_bounds.upper = cur_parts->etoc->efi_last_lba;
	}
	bn = input(FIO_BN, "Enter a disk block", ':',
	    &ioparam, (int *)NULL, DATA_INPUT);
	/*
	 * Echo it back.
	 */
	fmt_print("Disk block = %lld = 0x%llx = (", bn, bn);
	pr_dblock(fmt_print, bn);
	fmt_print(")\n\n");
	return (0);
}

/*
 * This routine implements the 'label' command.  It writes the
 * primary and backup labels onto the current disk.
 */
int
c_label()
{
	int			status;
	int			deflt, *defltptr = NULL;

	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * The current disk must be formatted to label it.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}
	/*
	 * Check to see if there are any mounted file systems anywhere
	 * on the current disk.  If so, refuse to label the disk, but
	 * only if the partitions would change for the mounted partitions.
	 *
	 */
	if (checkmount((diskaddr_t)-1, (diskaddr_t)-1)) {
		/* Bleagh, too descriptive */
		if (check_label_with_mount()) {
			err_print("Cannot label disk while it has "
			    "mounted partitions.\n\n");
			return (-1);
		}
	}

	/*
	 * check to see if there any partitions being used for swapping
	 * on the current disk.  If so, refuse to label the disk, but
	 * only if the partitions would change for the mounted partitions.
	 */
	if (checkswap((diskaddr_t)-1, (diskaddr_t)-1)) {
		if (check_label_with_swap()) {
			err_print("Cannot label disk while its "
			    "partitions are currently being used for "
			    "swapping.\n");
			return (-1);
		}
	}

	/*
	 * Check to see if any partitions used for svm, vxvm or live upgrade
	 * are on the disk. If so, refuse to label the disk, but only
	 * if we are trying to shrink a partition in use.
	 */
	if (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 1)) {
		err_print("Cannot label disk when "
		    "partitions are in use as described.\n");
		return (-1);
	}

	/*
	 * If there is not a current partition map, warn the user we
	 * are going to use the default.  The default is the first
	 * partition map we encountered in the data file.  If there is
	 * no default we give up.
	 */
	if (cur_parts == NULL) {
		fmt_print("Current Partition Table is not set, "
		    "using default.\n");
		cur_disk->disk_parts = cur_parts = cur_dtype->dtype_plist;
		if (cur_parts == NULL) {
			err_print("No default available, cannot label.\n");
			return (-1);
		}
	}
	/*
	 * If expert (-e) mode, then ask user if they wish
	 * to change the current solaris label into an EFI one
	 */
	if (expert_mode) {
#if defined(_SUNOS_VTOC_8)
		int 		i;
#endif
		int 		choice;
		u_ioparam_t		ioparam;
		struct extvtoc	vtoc;
		struct dk_label	label;
		struct dk_gpt	*vtoc64;
		struct efi_info	efinfo;
		struct disk_type	*dptr;

		/* Ask user what label to use */
		fmt_print("[0] SMI Label\n");
		fmt_print("[1] EFI Label\n");
		ioparam.io_bounds.lower = 0;
		ioparam.io_bounds.upper = 1;
		if ((cur_label == L_TYPE_SOLARIS) &&
		    (cur_disk->fdisk_part.systid != EFI_PMBR))
			deflt = L_TYPE_SOLARIS;
		else
			deflt = L_TYPE_EFI;
		defltptr = &deflt;
		choice = input(FIO_INT, "Specify Label type", ':',
		    &ioparam, defltptr, DATA_INPUT);
		if ((choice == L_TYPE_SOLARIS) &&
		    (cur_label == L_TYPE_SOLARIS) &&
		    (cur_disk->fdisk_part.systid != EFI_PMBR)) {
			goto expert_end;
		} else if ((choice == L_TYPE_EFI) &&
		    (cur_label == L_TYPE_EFI)) {
			goto expert_end;
		}
		switch (choice) {
		case L_TYPE_SOLARIS:
		/*
		 * EFI label to SMI label
		 */
		if (cur_dtype->capacity > INFINITY) {
			fmt_print("Warning: SMI labels only support up to "
			    "2 TB.\n");
		}

		if (cur_disk->fdisk_part.systid == EFI_PMBR) {
			fmt_print("Warning: This disk has an EFI label. "
			    "Changing to SMI label will erase all\n"
			    "current partitions.\n");
			if (check("Continue"))
			return (-1);
#if defined(_FIRMWARE_NEEDS_FDISK)
			fmt_print("You must use fdisk to delete the current "
			    "EFI partition and create a new\n"
			    "Solaris partition before you can convert the "
			    "label.\n");
			return (-1);
#endif
		}

#if defined(_FIRMWARE_NEEDS_FDISK)
		if (!(((cur_disk->fdisk_part.systid != SUNIXOS) ||
		    (cur_disk->fdisk_part.systid != SUNIXOS2)) &&
		    (cur_disk->fdisk_part.numsect > 0))) {
			fmt_print("You must use fdisk to create a Solaris "
			    "partition before you can convert the label.\n");
			return (-1);
		}
#endif

		(void) memset((char *)&label, 0, sizeof (struct dk_label));

		(void) strcpy(x86_devname, cur_disk->disk_name);
		if (cur_ctype->ctype_ctype == DKC_DIRECT)
			dptr = auto_direct_get_geom_label(cur_file,  &label);
		else
			dptr = auto_sense(cur_file, 1, &label);
		if (dptr == NULL) {
			fmt_print("Autoconfiguration failed.\n");
			return (-1);
		}

		pcyl = label.dkl_pcyl;
		ncyl = label.dkl_ncyl;
		acyl = label.dkl_acyl;
		nhead = label.dkl_nhead;
		nsect = label.dkl_nsect;

		if (delete_disk_type(cur_disk->disk_type) == 0) {
			cur_label = L_TYPE_SOLARIS;
			cur_disk->label_type = L_TYPE_SOLARIS;
			cur_disk->disk_type = dptr;
			cur_disk->disk_parts = dptr->dtype_plist;
			cur_dtype = dptr;
			cur_parts = dptr->dtype_plist;

			if (status = write_label())
				err_print("Label failed.\n");
			else
				cur_disk->disk_flags &= ~DSK_LABEL_DIRTY;

			return (status);
		} else {
			err_print("Label failed.\n");
			return (-1);
		}


		case L_TYPE_EFI:
		/*
		 * SMI label to EFI label
		 */

		if ((cur_disk->fdisk_part.systid == SUNIXOS) ||
		    (cur_disk->fdisk_part.systid == SUNIXOS2)) {
			fmt_print("Warning: This disk has an SMI label. "
			    "Changing to EFI label will erase all\ncurrent "
			    "partitions.\n");
			if (check("Continue")) {
				return (-1);
			}
		}

		if (get_disk_info(cur_file, &efinfo, cur_disk) != 0) {
			return (-1);
		}
		(void) memset((char *)&label, 0, sizeof (struct dk_label));
		label.dkl_pcyl = pcyl;
		label.dkl_ncyl = ncyl;
		label.dkl_acyl = acyl;
#if defined(_SUNOS_VTOC_16)
		label.dkl_bcyl = bcyl;
#endif			/* defined(_SUNOC_VTOC_16) */
		label.dkl_nhead = nhead;
		label.dkl_nsect = nsect;
#if defined(_SUNOS_VTOC_8)
		for (i = 0; i < NDKMAP; i++) {
			label.dkl_map[i] = cur_parts->pinfo_map[i];
		}
#endif			/* defined(_SUNOS_VTOC_8) */
		label.dkl_magic = DKL_MAGIC;
		label.dkl_vtoc = cur_parts->vtoc;
		if (label_to_vtoc(&vtoc, &label) == -1) {
			return (-1);
		}
		if (SMI_vtoc_to_EFI(cur_file, &vtoc64) == -1) {
			return (-1);
		}
		if (efi_write(cur_file, vtoc64) != 0) {
			err_check(vtoc64);
			err_print("Warning: error writing EFI.\n");
			return (-1);
		} else {
			cur_disk->disk_flags &= ~DSK_LABEL_DIRTY;
		}
		/*
		 * copy over the EFI vtoc onto the SMI vtoc and return
		 * okay.
		 */
		dptr = auto_efi_sense(cur_file, &efinfo);
		if (dptr == NULL) {
			fmt_print("Autoconfiguration failed.\n");
			return (-1);
		}

		cur_label = L_TYPE_EFI;
		cur_disk->label_type = L_TYPE_EFI;
		cur_disk->disk_type = dptr;
		cur_disk->disk_parts = dptr->dtype_plist;
		cur_dtype = dptr;
		cur_parts = dptr->dtype_plist;
		cur_parts->etoc = vtoc64;

		ncyl = pcyl = nsect = psect = acyl = phead = 0;

		/*
		 * Get the Solais Fdisk Partition information.
		 */
		(void) copy_solaris_part(&cur_disk->fdisk_part);

		return (0);
		}
	}

expert_end:
	/*
	 * Make sure the user is serious.
	 */
	if (check("Ready to label disk, continue")) {
		return (-1);
	}
	/*
	 * Write the labels out (this will also notify unix) and
	 * return status.
	 */
	fmt_print("\n");
	if (status = write_label())
		err_print("Label failed.\n");
	return (status);
}

/*
 * This routine implements the 'analyze' command.  It simply runs
 * the analyze menu.
 */
int
c_analyze()
{

	/*
	 * There must be a current disk type (and therefor a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	cur_menu++;
	last_menu = cur_menu;

	/*
	 * Run the menu.
	 */
	run_menu(menu_analyze, "ANALYZE", "analyze", 0);
	cur_menu--;
	return (0);
}

/*
 * This routine implements the 'defect' command.  It simply runs
 * the defect menu.
 */
int
c_defect()
{
	int	i;

	/*
	 * There must be a current disk type (and therefor a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}

	/*
	 * Check for the defect management and list management ops and
	 * display appropriate message.
	 */
	if ((cur_ops->op_ex_man == NULL) && (cur_ops->op_ex_cur == NULL) &&
	    (cur_ops->op_create == NULL) && (cur_ops->op_wr_cur == NULL)) {
		err_print("Controller does not support defect management\n");
		err_print("or disk supports automatic defect management.\n");
		return (-1);
	}
	cur_menu++;
	last_menu = cur_menu;

	/*
	 * Lock out interrupt while we manipulate the defect lists.
	 */
	enter_critical();
	/*
	 * If the working list is null but there is a current list,
	 * update the working list to be a copy of the current list.
	 */
	if ((work_list.list == NULL) && (cur_list.list != NULL)) {
		work_list.header = cur_list.header;
		work_list.list = (struct defect_entry *)zalloc(
		    deflist_size(cur_blksz, work_list.header.count) *
		    cur_blksz);
		for (i = 0; i < work_list.header.count; i++)
			*(work_list.list + i) = *(cur_list.list + i);
		work_list.flags = cur_list.flags & LIST_PGLIST;
	}
	exit_critical();
	/*
	 * Run the menu.
	 */
	run_menu(menu_defect, "DEFECT", "defect", 0);
	cur_menu--;

	/*
	 * If the user has modified the working list but not committed
	 * it, warn him that he is probably making a mistake.
	 */
	if (work_list.flags & LIST_DIRTY) {
		if (!EMBEDDED_SCSI) {
			err_print(
		"Warning: working defect list modified; but not committed.\n");
			if (!check(
		"Do you wish to commit changes to current defect list"))
			(void) do_commit();
		}
	}
	return (0);
}

/*
 * This routine implements the 'backup' command.  It allows the user
 * to search for backup labels on the current disk.  This is useful
 * if the primary label was lost and the user wishes to recover the
 * partition information for the disk. The disk is relabeled and
 * the current defect list is written out if a backup label is found.
 */
int
c_backup()
{
	struct	dk_label label;
	struct	disk_type *dtype;
	struct	partition_info *parts, *plist;
	diskaddr_t	bn;
	int	sec, head, i;
	char	*buf;

	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * The disk must be formatted to read backup labels.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}
	/*
	 * If we found a primary label on this disk, make sure
	 * the user is serious.
	 */
	if (cur_disk->label_type == L_TYPE_EFI) {
		if (((cur_disk->disk_parts->etoc->efi_flags &
		    EFI_GPT_PRIMARY_CORRUPT) == 0) &&
		    check("Disk has a primary label, still continue"))
			return (-1);
		fmt_print("Restoring primary label.\n");
		if (write_label()) {
			err_print("Failed\n");
			return (-1);
		}
		return (0);
	} else if (((cur_disk->disk_flags & (DSK_LABEL | DSK_LABEL_DIRTY)) ==
	    DSK_LABEL) &&
	    (check("Disk has a primary label, still continue"))) {
		return (-1);
	}

	buf = zalloc(cur_blksz);
	fmt_print("Searching for backup labels...");
	(void) fflush(stdout);

	/*
	 * Some disks have the backup labels in a strange place.
	 */
	if (cur_ctype->ctype_flags & CF_BLABEL)
		head = 2;
	else
		head = nhead - 1;
	/*
	 * Loop through each copy of the backup label.
	 */
	for (sec = 1; ((sec < BAD_LISTCNT * 2 + 1) && (sec < nsect));
	    sec += 2) {
		bn = chs2bn(ncyl + acyl - 1, head, sec) + solaris_offset;
		/*
		 * Attempt to read it.
		 */
		if ((*cur_ops->op_rdwr)(DIR_READ, cur_file, bn,
		    1, buf, F_NORMAL, NULL)) {
			continue;
		}

		(void *) memcpy((char *)&label, buf, sizeof (struct dk_label));

		/*
		 * Verify that it is a reasonable label.
		 */
		if (!checklabel(&label))
			continue;
		if (trim_id(label.dkl_asciilabel))
			continue;
		/*
		 * Lock out interrupts while we manipulate lists.
		 */
		enter_critical();
		fmt_print("found.\n");
		/*
		 * Find out which disk type the backup label claims.
		 */
		for (dtype = cur_ctype->ctype_dlist; dtype != NULL;
		    dtype = dtype->dtype_next)
			if (dtype_match(&label, dtype))
				break;
		/*
		 * If it disagrees with our current type, something
		 * real bad is happening.
		 */
		if (dtype != cur_dtype) {
			if (dtype == NULL) {
				fmt_print("\
Unknown disk type in backup label\n");
				exit_critical();
				free(buf);
				return (-1);
			}
			fmt_print("Backup label claims different type:\n");
			fmt_print("    <%s cyl %d alt %d hd %d sec %d>\n",
			    label.dkl_asciilabel, label.dkl_ncyl,
			    label.dkl_acyl, label.dkl_nhead,
			    label.dkl_nsect);
			if (check("Continue")) {
				exit_critical();
				free(buf);
				return (-1);
			}
			cur_dtype = dtype;
		}
		/*
		 * Try to match the partition map with a known map.
		 */
		for (parts = dtype->dtype_plist; parts != NULL;
		    parts = parts->pinfo_next)
			if (parts_match(&label, parts))
				break;
		/*
		 * If we couldn't match it, allocate space for a new one,
		 * fill in the info, and add it to the list.  The name
		 * for the new map is derived from the disk name.
		 */
		if (parts == NULL) {
			parts = (struct partition_info *)
			    zalloc(sizeof (struct partition_info));
			plist = dtype->dtype_plist;
			if (plist == NULL)
				dtype->dtype_plist = parts;
			else {
				while (plist->pinfo_next != NULL)
					plist = plist->pinfo_next;
				plist->pinfo_next = parts;
			}
			parts->pinfo_name = alloc_string("original");
			for (i = 0; i < NDKMAP; i++)

#if defined(_SUNOS_VTOC_8)
				parts->pinfo_map[i] = label.dkl_map[i];

#elif defined(_SUNOS_VTOC_16)
				parts->pinfo_map[i].dkl_cylno  =
				    label.dkl_vtoc.v_part[i].p_start / spc();
				parts->pinfo_map[i].dkl_nblk =
				    label.dkl_vtoc.v_part[i].p_size;
#else
#error No VTOC layout defined.
#endif /* defined(_SUNOS_VTOC_8) */
			parts->vtoc = label.dkl_vtoc;
		}
		/*
		 * We now have a partition map.  Make it the current map.
		 */
		cur_disk->disk_parts = cur_parts = parts;
		exit_critical();
		/*
		 * Rewrite the labels and defect lists, as appropriate.
		 */
		if (EMBEDDED_SCSI) {
			fmt_print("Restoring primary label.\n");
			if (write_label()) {
				free(buf);
				return (-1);
			}
		} else {
			fmt_print("Restoring primary label and defect list.\n");
			if (write_label()) {
				free(buf);
				return (-1);
			}
			if (cur_list.list != NULL)
				write_deflist(&cur_list);
		}
		fmt_print("\n");
		free(buf);
		return (0);
	}
	/*
	 * If we didn't find any backup labels, say so.
	 */
	fmt_print("not found.\n\n");
	free(buf);
	return (0);
}

/*
 * This routine is called by c_verify() for an EFI labeled disk
 */
static int
c_verify_efi()
{
	struct efi_info efi_info;
	struct	partition_info	tmp_pinfo;
	int status;

	status = read_efi_label(cur_file, &efi_info, cur_disk);
	if (status != 0) {
		err_print("Warning: Could not read label.\n");
		return (-1);
	}
	if (cur_parts->etoc->efi_flags & EFI_GPT_PRIMARY_CORRUPT) {
		err_print("Reading the primary EFI GPT label ");
		err_print("failed.  Using backup label.\n");
		err_print("Use the 'backup' command to restore ");
		err_print("the primary label.\n");
	}
	tmp_pinfo.etoc = efi_info.e_parts;
	fmt_print("\n");
	if (cur_parts->etoc->efi_parts[8].p_name) {
		fmt_print("Volume name = <%8s>\n",
		    cur_parts->etoc->efi_parts[8].p_name);
	} else {
		fmt_print("Volume name = <        >\n");
	}
	fmt_print("ascii name  = ");
	print_efi_string(efi_info.vendor, efi_info.product,
	    efi_info.revision, efi_info.capacity);
	fmt_print("\n");

	fmt_print("bytes/sector	=  %d\n", cur_blksz);
	fmt_print("sectors = %llu\n", cur_parts->etoc->efi_last_lba);
	fmt_print("accessible sectors = %llu\n",
	    cur_parts->etoc->efi_last_u_lba);

	print_map(&tmp_pinfo);

	free(efi_info.vendor);
	free(efi_info.product);
	free(efi_info.revision);
	return (0);
}

/*
 * This routine implements the 'verify' command.  It allows the user
 * to read the labels on the current disk.
 */
int
c_verify()
{
	struct	dk_label p_label, b_label, *label;
	struct	partition_info tmp_pinfo;
	diskaddr_t	bn;
	int	sec, head, i, status;
	int	p_label_bad = 0;
	int	b_label_bad = 0;
	int	p_label_found = 0;
	int	b_label_found = 0;
	char	id_str[128];
	char	*buf;

	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * The disk must be formatted to read labels.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}
	/*
	 * Branch off here if the disk is EFI labelled.
	 */
	if (cur_label == L_TYPE_EFI) {
		return (c_verify_efi());
	}
	/*
	 * Attempt to read the primary label.
	 */
	status = read_label(cur_file, &p_label);
	if (status == -1) {
		err_print("Warning: Could not read primary label.\n");
		p_label_bad = 1;
	} else {
		/*
		 * Verify that it is a reasonable label.
		 */
		/*
		 * Save complete ascii string for printing later.
		 */
		(void) strncpy(id_str, p_label.dkl_asciilabel, 128);

		if ((!checklabel((struct dk_label *)&p_label)) ||
		    (trim_id(p_label.dkl_asciilabel))) {
			err_print("\
Warning: Primary label appears to be corrupt.\n");
			p_label_bad = 1;
		} else {
			p_label_found = 1;
			/*
			 * Make sure it matches current label
			 */
			if ((!dtype_match(&p_label, cur_dtype)) ||
			    (!parts_match(&p_label, cur_parts))) {
				err_print("\
Warning: Primary label on disk appears to be different from\ncurrent label.\n");
				p_label_bad = 1;
			}
		}
	}

	/*
	 * Read backup labels.
	 * Some disks have the backup labels in a strange place.
	 */
	if (cur_ctype->ctype_flags & CF_BLABEL)
		head = 2;
	else
		head = nhead - 1;

	buf = zalloc(cur_blksz);
	/*
	 * Loop through each copy of the backup label.
	 */
	for (sec = 1; ((sec < BAD_LISTCNT * 2 + 1) && (sec < nsect));
	    sec += 2) {
		bn = chs2bn(ncyl + acyl - 1, head, sec) + solaris_offset;
		/*
		 * Attempt to read it.
		 */
		if ((*cur_ops->op_rdwr)(DIR_READ, cur_file, bn,
		    1, buf, F_NORMAL, NULL))
			continue;

		(void *) memcpy((char *)&b_label, buf,
		    sizeof (struct dk_label));

		/*
		 * Verify that it is a reasonable label.
		 */
		if (!checklabel(&b_label))
			continue;

		/*
		 * Save complete label only if no primary label exists
		 */
		if (!p_label_found)
			(void) strncpy(id_str, b_label.dkl_asciilabel, 128);

		if (trim_id(b_label.dkl_asciilabel))
			continue;
		b_label_found = 1;
		/*
		 * Compare against primary label
		 */
		if (p_label_found) {
			if ((strcmp(b_label.dkl_asciilabel,
			    p_label.dkl_asciilabel) != 0) ||
			    (b_label.dkl_ncyl != p_label.dkl_ncyl) ||
			    (b_label.dkl_acyl != p_label.dkl_acyl) ||
			    (b_label.dkl_nhead != p_label.dkl_nhead) ||
			    (b_label.dkl_nsect != p_label.dkl_nsect)) {
				b_label_bad = 1;
			} else {
				for (i = 0; i < NDKMAP; i++) {
#if defined(_SUNOS_VTOC_8)
					if ((b_label.dkl_map[i].dkl_cylno !=
					    p_label.dkl_map[i].dkl_cylno) ||
					    (b_label.dkl_map[i].dkl_nblk !=
					    p_label.dkl_map[i].dkl_nblk)) {
						b_label_bad = 1;
						break;
					}

#elif defined(_SUNOS_VTOC_16)
					if ((b_label.dkl_vtoc.v_part[i].p_tag !=
					    p_label.dkl_vtoc.v_part[i].p_tag) ||
					    (b_label.dkl_vtoc.v_part[i].p_flag
					    != p_label.dkl_vtoc.v_part[i].
					    p_flag) ||
					    (b_label.dkl_vtoc.v_part[i].p_start
					    != p_label.dkl_vtoc.v_part[i].
					    p_start) ||
					    (b_label.dkl_vtoc.v_part[i].p_size
					    != p_label.dkl_vtoc.v_part[i].
					    p_size)) {
						b_label_bad = 1;
						break;
					}
#else
#error No VTOC layout defined.
#endif /* defined(_SUNOS_VTOC_8) */
				}
			}
		}
		if (b_label_bad)
			err_print(
"Warning: Primary and backup labels do not match.\n");
		break;
	}
	/*
	 * If we didn't find any backup labels, say so.
	 */
	if (!b_label_found)
		err_print("Warning: Could not read backup labels.\n");

	if ((!b_label_found) || (p_label_bad) || (b_label_bad))
		err_print("\n\
Warning: Check the current partitioning and 'label' the disk or use the\n\
\t 'backup' command.\n");

	/*
	 * Print label information.
	 */
	if (p_label_found) {
		fmt_print("\nPrimary label contents:\n");
		label = &p_label;
	} else if (b_label_found) {
		fmt_print("\nBackup label contents:\n");
		label = &b_label;
	} else {
		free(buf);
		return (0);
	}

	/*
	 * Must put info into partition_info struct for
	 * for print routine.
	 */
	bzero(&tmp_pinfo, sizeof (struct partition_info));
	for (i = 0; i < NDKMAP; i++) {

#if defined(_SUNOS_VTOC_8)
		tmp_pinfo.pinfo_map[i] = label->dkl_map[i];

#elif defined(_SUNOS_VTOC_16)
		tmp_pinfo.pinfo_map[i].dkl_cylno =
		    label->dkl_vtoc.v_part[i].p_start / spc();
		tmp_pinfo.pinfo_map[i].dkl_nblk =
		    label->dkl_vtoc.v_part[i].p_size;
#else
#error No VTOC layout defined.
#endif /* defined(_SUNOS_VTOC_8) */
	}
	tmp_pinfo.vtoc = label->dkl_vtoc;

	fmt_print("\n");
	fmt_print("Volume name = <%8s>\n", label->dkl_vtoc.v_volume);
	fmt_print("ascii name  = <%s>\n", id_str);
	fmt_print("pcyl        = %4d\n", label->dkl_pcyl);
	fmt_print("ncyl        = %4d\n", label->dkl_ncyl);
	fmt_print("acyl        = %4d\n", label->dkl_acyl);

#if defined(_SUNOS_VTOC_16)
	fmt_print("bcyl        = %4d\n", label->dkl_bcyl);
#endif /* defined(_SUNOS_VTOC_16) */

	fmt_print("nhead       = %4d\n", label->dkl_nhead);
	fmt_print("nsect       = %4d\n", label->dkl_nsect);

	print_map(&tmp_pinfo);
	free(buf);
	return (0);
}


/*
 * This command implements the inquiry command, for embedded SCSI
 * disks only, which issues a SCSI inquiry command, and
 * displays the resulting vendor, product id and revision level.
 */
int
c_inquiry()
{
	char			inqbuf[255];
	struct scsi_inquiry	*inq;

	assert(SCSI);

	inq = (struct scsi_inquiry *)inqbuf;

	if (uscsi_inquiry(cur_file, inqbuf, sizeof (inqbuf))) {
		err_print("Failed\n");
		return (-1);
	} else {
		fmt_print("Vendor:   ");
		print_buf(inq->inq_vid, sizeof (inq->inq_vid));
		fmt_print("\nProduct:  ");
		print_buf(inq->inq_pid, sizeof (inq->inq_pid));
		fmt_print("\nRevision: ");
		print_buf(inq->inq_revision, sizeof (inq->inq_revision));
		fmt_print("\n");
	}

	return (0);
}


/*
 * This routine allows the user to set the 8-character
 * volume name in the vtoc.  It then writes both the
 * primary and backup labels onto the current disk.
 */
int
c_volname()
{
	int	 status;
	char	*prompt;
	union {
		int	xfoo;
		char	defvolname[LEN_DKL_VVOL+1];
	} x;
	char    s1[MAXPATHLEN], nclean[MAXPATHLEN];
	char	*volname;


	/*
	 * There must be a current disk type (and therefore a current disk).
	 */
	if (cur_dtype == NULL) {
		err_print("Current Disk Type is not set.\n");
		return (-1);
	}
	/*
	 * The current disk must be formatted to label it.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	/*
	 * Check for a valid fdisk table entry for Solaris
	 */
	if (!good_fdisk()) {
		return (-1);
	}
	/*
	 * The current disk must be formatted to label it.
	 */
	if (cur_parts == NULL) {
	err_print(
"Please select a partition map for the disk first.\n");
	return (-1);
	}

	/*
	 * Check to see if there are any mounted file systems anywhere
	 * on the current disk.  If so, refuse to label the disk, but
	 * only if the partitions would change for the mounted partitions.
	 *
	 */
	if (checkmount((diskaddr_t)-1, (diskaddr_t)-1)) {
		/* Bleagh, too descriptive */
		if (check_label_with_mount()) {
			err_print(
"Cannot label disk while it has mounted partitions.\n\n");
			return (-1);
		}
	}

	/*
	 * Check to see if there are partitions being used for swapping
	 * on the current disk.  If so, refuse to label the disk, but
	 * only if the partitions would change for the swap partitions.
	 *
	 */
	if (checkswap((diskaddr_t)-1, (diskaddr_t)-1)) {
		/* Bleagh, too descriptive */
		if (check_label_with_swap()) {
			err_print(
"Cannot label disk while its partitions are currently \
being used for swapping.\n\n");
			return (-1);
		}
	}

	/*
	 * Check to see if any partitions used for svm, vxvm, ZFS zpool
	 * or live upgrade are on the disk. If so, refuse to label the
	 * disk, but only if we are trying to shrink a partition in
	 * use.
	 */
	if (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 1)) {
		err_print("Cannot label disk while its partitions "
		    "are in use as described.\n");
		return (-1);
	}

	/*
	 * Prompt for the disk volume name.
	 */
	prompt = "Enter 8-character volume name (remember quotes)";
	bzero(x.defvolname, LEN_DKL_VVOL+1);
	bcopy(cur_disk->v_volume, x.defvolname, LEN_DKL_VVOL);
	/*
	 *  Get the input using "get_inputline" since
	 *  input would never return null string.
	 */
	fmt_print("%s[\"%s\"]:", prompt, x.defvolname);

	/*
	 * Get input from the user.
	 */
	get_inputline(nclean, MAXPATHLEN);
	clean_token(s1, nclean);
	/*
	 * check for return.
	 */
	if (s1[0] == 0) {
		volname = x.defvolname;
	} else {
		/*
		 * remove the " mark from volname.
		 */
		if (s1[0] == '"') {
			int i = 1;
			volname = &s1[1];
			while (s1[i] != '"' && s1[i] != '\0')
				i++;
			s1[i] = '\0';
			clean_token(nclean, volname);
			volname = nclean;
		} else {
			(void) sscanf(&s1[0], "%1024s", nclean);
			volname = nclean;
		};
	}
	/*
	 * Make sure the user is serious.
	 */
	if (check("Ready to label disk, continue")) {
		fmt_print("\n");
		return (-1);
	}
	/*
	 * Use the volume name chosen above
	 */
	bzero(cur_disk->v_volume, LEN_DKL_VVOL);
	bcopy(volname, cur_disk->v_volume, min((int)strlen(volname),
	    LEN_DKL_VVOL));
	if (cur_label == L_TYPE_EFI) {
		bzero(cur_parts->etoc->efi_parts[8].p_name, LEN_DKL_VVOL);
		bcopy(volname, cur_parts->etoc->efi_parts[8].p_name,
		    LEN_DKL_VVOL);
	}
	/*
	 * Write the labels out (this will also notify unix) and
	 * return status.
	 */
	fmt_print("\n");
	if (status = write_label())
		err_print("Label failed.\n");
	return (status);
}
