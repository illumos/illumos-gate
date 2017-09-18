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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * This file contains the main entry point of the program and other
 * routines relating to the general flow.
 */
#include "global.h"
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <memory.h>
#include <string.h>
#include <errno.h>

#ifdef sparc
#include <sys/hdio.h>
#include <sys/dkbad.h>
#endif

#include <sys/time.h>
#include "main.h"
#include "analyze.h"
#include "menu.h"
#include "param.h"
#include "misc.h"
#include "startup.h"
#include "menu_command.h"
#include "menu_partition.h"
#include "prompts.h"
#include "checkdev.h"
#include "label.h"

extern	struct menu_item menu_command[];

#ifdef	__STDC__

/*
 *	Local prototypes for ANSI C compilers
 */
static void	get_disk_characteristics(void);


#else	/* __STDC__ */

/*
 *	Local prototypes for non-ANSI C compilers
 */
static void	get_disk_characteristics();

#endif	/* __STDC__ */

/*
 * This is the main entry point.
 */
int
main(int argc, char *argv[])
{
	int	i;
	int	ret_code = 1;
	char	**arglist;
	struct	disk_info *disk = NULL;
	struct	disk_type *type, *oldtype;
	struct	partition_info *parts;
	struct	sigaction act;

	solaris_offset = 0;
	/*
	 * Initialize cur_ctype to avoid null pointer dereference
	 * in auto_efi_sense().
	 */
	cur_ctype = (struct ctlr_type *)NULL;
	/*
	 * Decode the command line options.
	 */
	i = do_options(argc, argv);
	/*
	 * If we are to run from a command file, open it up.
	 */
	if (option_f) {
		if (freopen(option_f, "r", stdin) == NULL) {
			err_print("Unable to open command file '%s'.\n",
			    option_f);
			fullabort();
		}
	}
	/*
	 * If we are logging, open the log file.
	 */
	if (option_l) {
		if ((log_file = fopen(option_l, "w")) == NULL) {
			err_print("Unable to open log file '%s'.\n",
			    option_l);
			fullabort();
		}
	}
	/*
	 * Read in the data file and initialize the hardware structs.
	 */
	sup_init();
	/*
	 * If there are no disks on the command line, search the
	 * appropriate device directory for character devices that
	 * look like disks.
	 */
	if (i < 0) {
		arglist = (char **)NULL;
	/*
	 * There were disks on the command line.  They comprise the
	 * search list.
	 */
	} else {
		arglist = &argv[i];
	}
	/*
	 * Perform the search for disks.
	 */
	do_search(arglist);
	/*
	 * Catch ctrl-C and ctrl-Z so critical sections can be
	 * implemented.  We use sigaction, as this sets up the
	 * signal handler permanently, and also automatically
	 * restarts any interrupted system call.
	 */
	act.sa_handler = cmdabort;
	(void) memset(&act.sa_mask, 0, sizeof (sigset_t));
	act.sa_flags = SA_RESTART | SA_NODEFER;
	if (sigaction(SIGINT, &act, (struct sigaction *)NULL) == -1) {
		err_print("sigaction(SIGINT) failed - %s\n",
		    strerror(errno));
		fullabort();
	}

	act.sa_handler = onsusp;
	(void) memset(&act.sa_mask, 0, sizeof (sigset_t));
	act.sa_flags = SA_RESTART | SA_NODEFER;
	if (sigaction(SIGTSTP, &act, (struct sigaction *)NULL) == -1) {
		err_print("sigaction(SIGTSTP) failed - %s\n",
		    strerror(errno));
		fullabort();
	}

	act.sa_handler = onalarm;
	(void) memset(&act.sa_mask, 0, sizeof (sigset_t));
	act.sa_flags = SA_RESTART;
	if (sigaction(SIGALRM, &act, (struct sigaction *)NULL) == -1) {
		err_print("sigaction(SIGALRM) failed - %s\n",
		    strerror(errno));
		fullabort();
	}

	/*
	 * If there was only 1 disk on the command line, mark it
	 * to be the current disk.  If it wasn't found, it's an error.
	 */
	if (i == argc - 1) {
		disk = disk_list;
		if (disk == NULL) {
			err_print("Unable to find specified disk '%s'.\n",
			    argv[i]);
			fullabort();
		}
	}
	/*
	 * A disk was forced on the command line.
	 */
	if (option_d) {
		/*
		 * Find it in the list of found disks and mark it to
		 * be the current disk.
		 */
		for (disk = disk_list; disk != NULL; disk = disk->disk_next)
			if (diskname_match(option_d, disk))
				break;
		/*
		 * If it wasn't found, it's an error.
		 */
		if (disk == NULL) {
			err_print("Unable to find specified disk '%s'.\n",
			    option_d);
			fullabort();
		}
	}
	/*
	 * A disk type was forced on the command line.
	 */
	if (option_t != NULL) {
		/*
		 * Only legal if a disk was also forced.
		 */
		if (disk == NULL) {
			err_print("Must specify disk as well as type.\n");
			fullabort();
		}
		oldtype = disk->disk_type;
		/*
		 * Find the specified type in the list of legal types
		 * for the disk.
		 */
		for (type = disk->disk_ctlr->ctlr_ctype->ctype_dlist;
		    type != NULL; type = type->dtype_next)
			if (strcmp(option_t, type->dtype_asciilabel) == 0)
				break;
		/*
		 * If it wasn't found, it's an error.
		 */
		if (type == NULL) {
			err_print(
"Specified type '%s' is not a known type.\n", option_t);
			fullabort();
		}
		/*
		 * If the specified type is not the same as the type
		 * in the disk label, update the type and nullify the
		 * partition map.
		 */
		if (type != oldtype) {
			disk->disk_type = type;
			disk->disk_parts = NULL;
		}
	}
	/*
	 * A partition map was forced on the command line.
	 */
	if (option_p) {
		/*
		 * Only legal if both disk and type were also forced.
		 */
		if (disk == NULL || disk->disk_type == NULL) {
			err_print("Must specify disk and type as well ");
			err_print("as partitiion.\n");
			fullabort();
		}
		/*
		 * Find the specified map in the list of legal maps
		 * for the type.
		 */
		for (parts = disk->disk_type->dtype_plist; parts != NULL;
		    parts = parts->pinfo_next)
			if (strcmp(option_p, parts->pinfo_name) == 0)
				break;
		/*
		 * If it wasn't found, it's an error.
		 */
		if (parts == NULL) {
			err_print(
"Specified table '%s' is not a known table.\n", option_p);
			fullabort();
		}
		/*
		 * Update the map.
		 */
		disk->disk_parts = parts;
	}
	/*
	 * If a disk was marked to become current, initialize the state
	 * to make it current.  If not, ask user to pick one.
	 */
	if (disk != NULL) {
		init_globals(disk);
	} else if (option_f == 0 && option_d == 0) {
		while (ret_code) {
			ret_code = c_disk();
		}
	}

#ifdef	BUG1134748
	/*
	 * if -f command-file is specified, check for disk and disktype
	 * input also. For SCSI disks, the type input may not be needed
	 * since format would have figured that using inquiry information.
	 */
	if (option_f) {
		if (cur_disk == NULL) {
			err_print("Must specify a disk using -d option.\n");
			fullabort();
		}
		if (cur_dtype == NULL) {
			err_print("Must specify disk as well as type.\n");
			fullabort();
		}
	}
#endif	/* BUG1134748 */

	/*
	 * Run the command menu.
	 */
	cur_menu = last_menu = 0;
	run_menu(menu_command, "FORMAT", "format", 1);

	/*
	 * normal ending. Explicitly return(0);
	 */
	return (0);
}

/*
 * This routine initializes the internal state to ready it for a new
 * current disk.  There are a zillion state variables that store
 * information on the current disk, and they must all be updated.
 * We also tell SunOS about the disk, since it may not know if the
 * disk wasn't labeled at boot time.
 */
void
init_globals(disk)
	struct	disk_info *disk;
{
	int		status;
	int		found_mount;
	int		found_inuse;
#ifdef sparc
	int		i;
	caddr_t		bad_ptr = (caddr_t)&badmap;
#endif

	/*
	 * If there was an old current disk, close the file for it.
	 */
	if (cur_disk != NULL)
		(void) close(cur_file);
	/*
	 * Kill off any defect lists still lying around.
	 */
	kill_deflist(&cur_list);
	kill_deflist(&work_list);
	/*
	 * If there were any buffers, free them up.
	 */
	if ((char *)cur_buf != NULL) {
		destroy_data((char *)cur_buf);
		cur_buf = NULL;
	}
	if ((char *)pattern_buf != NULL) {
		destroy_data((char *)pattern_buf);
		pattern_buf = NULL;
	}
	/*
	 * Fill in the hardware struct pointers for the new disk.
	 */
	cur_disk = disk;
	cur_dtype = cur_disk->disk_type;
	cur_label = cur_disk->label_type;
	cur_ctlr = cur_disk->disk_ctlr;
	cur_parts = cur_disk->disk_parts;
	cur_blksz = cur_disk->disk_lbasize;
	cur_ctype = cur_ctlr->ctlr_ctype;
	cur_ops = cur_ctype->ctype_ops;
	cur_flags = 0;
	/*
	 * Open a file for the new disk.
	 */
	if ((cur_file = open_disk(cur_disk->disk_path,
					O_RDWR | O_NDELAY)) < 0) {
		err_print(
"Error: can't open selected disk '%s'.\n", cur_disk->disk_name);
		fullabort();
	}
#ifdef sparc
	/*
	 * If the new disk uses bad-144, initialize the bad block table.
	 */
	if (cur_ctlr->ctlr_flags & DKI_BAD144) {
		badmap.bt_mbz = badmap.bt_csn = badmap.bt_flag = 0;
		for (i = 0; i < NDKBAD; i++) {
			badmap.bt_bad[i].bt_cyl = -1;
			badmap.bt_bad[i].bt_trksec = -1;
		}
	}
#endif
	/*
	 * If the type of the new disk is known...
	 */
	if (cur_dtype != NULL) {
		/*
		 * Initialize the physical characteristics.
		 * If need disk specs, prompt for undefined disk
		 * characteristics.  If running from a file,
		 * use defaults.
		 */
		if (cur_dtype->dtype_flags & DT_NEED_SPEFS) {
			get_disk_characteristics();
			cur_dtype->dtype_flags &= ~DT_NEED_SPEFS;
		}

		ncyl = cur_dtype->dtype_ncyl;
		acyl = cur_dtype->dtype_acyl;
		pcyl = cur_dtype->dtype_pcyl;
		nhead = cur_dtype->dtype_nhead;
		nsect = cur_dtype->dtype_nsect;
		phead = cur_dtype->dtype_phead;
		psect = cur_dtype->dtype_psect;
		/*
		 * Alternates per cylinder are forced to 0 or 1,
		 * independent of what the label says.  This works
		 * because we know which ctlr we are dealing with.
		 */
		if (cur_ctype->ctype_flags & CF_APC)
			apc = 1;
		else
			apc = 0;
		/*
		 * Initialize the surface analysis info.  We always start
		 * out with scan set for the whole disk.  Note,
		 * for SCSI disks, we can only scan the data area.
		 */
		scan_lower = 0;
		scan_size = BUF_SECTS;
		if ((cur_ctype->ctype_flags & CF_SCSI) &&
		    (cur_disk->label_type == L_TYPE_SOLARIS)) {
			scan_upper = datasects() - 1;
		} else if (cur_disk->label_type == L_TYPE_SOLARIS) {
			scan_upper = physsects() - 1;
		} else if (cur_disk->label_type == L_TYPE_EFI) {
			scan_upper = cur_parts->etoc->efi_last_lba;
		}

		/*
		 * Allocate the buffers.
		 */
		cur_buf = (void *) zalloc(BUF_SECTS * cur_blksz);
		pattern_buf = (void *) zalloc(BUF_SECTS * cur_blksz);

		/*
		 * Tell the user which disk they selected.
		 */
		if (chk_volname(cur_disk)) {
			fmt_print("selecting %s: ", cur_disk->disk_name);
			print_volname(cur_disk);
			fmt_print("\n");
		} else {
			fmt_print("selecting %s\n", cur_disk->disk_name);
		}

		/*
		 * If the drive is formatted...
		 */
		if ((*cur_ops->op_ck_format)()) {
			/*
			 * Mark it formatted.
			 */
			cur_flags |= DISK_FORMATTED;
			/*
			 * Read the defect list, if we have one.
			 */
			if (!EMBEDDED_SCSI) {
				read_list(&cur_list);
			}
#ifdef sparc
			/*
			 * If the disk does BAD-144, we do an ioctl to
			 * tell SunOS about the bad block table.
			 */
			if (cur_ctlr->ctlr_flags & DKI_BAD144) {
				if (ioctl(cur_file, HDKIOCSBAD, &bad_ptr)) {
					err_print(
"Warning: error telling SunOS bad block map table.\n");
				}
			}
#endif
			fmt_print("[disk formatted");
			if (!EMBEDDED_SCSI) {
				if (cur_list.list != NULL) {
					fmt_print(", defect list found");
				} else {
					fmt_print(", no defect list found");
				}
			}
			fmt_print("]");
		/*
		 * Drive wasn't formatted.  Tell the user in case they
		 * disagree.
		 */
		} else if (EMBEDDED_SCSI) {
			fmt_print("[disk unformatted]");
		} else {
			/*
			 * Make sure the user is serious.  Note, for
			 * SCSI disks since this is instantaneous, we
			 * will just do it and not ask for confirmation.
			 */
			status = 0;
			if (!(cur_ctype->ctype_flags & CF_CONFIRM)) {
				if (check("\n\
Ready to get manufacturer's defect list from unformatted drive.\n\
This cannot be interrupted and takes a long while.\n\
Continue"))
					status = 1;
				else
					fmt_print(
				"Extracting manufacturer's defect list...");
			}
			/*
			 * Extract manufacturer's defect list.
			 */
			if ((status == 0) && (cur_ops->op_ex_man != NULL)) {
				status = (*cur_ops->op_ex_man)(&cur_list);
			} else {
				status = 1;
			}
			fmt_print("[disk unformatted");
			if (status != 0) {
				fmt_print(", no defect list found]");
			} else {
				fmt_print(", defect list found]");
			}
		}
	} else {
		/*
		 * Disk type is not known.
		 * Initialize physical characteristics to 0 and tell the
		 * user we don't know what type the disk is.
		 */
		ncyl = acyl = nhead = nsect = psect = 0;
	}

	fmt_print("\n");

	/*
	 * Check to see if there are any mounted file systems on the
	 * disk.  If there are, print a warning.
	 */
	if ((found_mount = checkmount((diskaddr_t)-1, (diskaddr_t)-1)) != 0)
		err_print("Warning: Current Disk has mounted partitions.\n");

	/*
	 * If any part of this device is also part of an SVM, VxVM or
	 * Live Upgrade device, print a warning.
	 */
	found_inuse =  checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 1, 0);

	/*
	 * Get the Solaris Fdisk Partition information
	 */
	(void) copy_solaris_part(&cur_disk->fdisk_part);

	if (!found_mount && !found_inuse &&
	    cur_disk->label_type == L_TYPE_EFI) {

		/*
		 * If alter_lba is 1, we are using the backup label.
		 * Since we can locate the backup label by disk capacity,
		 * there must be no space expanded after backup label.
		 */
		if ((cur_parts->etoc->efi_altern_lba != 1) &&
		    (cur_parts->etoc->efi_altern_lba <
		    cur_parts->etoc->efi_last_lba)) {

			/*
			 * Lun expansion detected. Prompt user now and actually
			 * adjust the label in <partition> command.
			 */
			fmt_print(
"Note: capacity in disk label is smaller than the real disk capacity.\n\
Select <partition> <expand> to adjust the label capacity. \n");
		}
	}
}


/*
 * Prompt for some undefined disk characteristics.
 * Used when there is no disk definition, but the
 * disk has a valid label, so basically we're
 * prompting for everything that isn't in the label.
 */
static void
get_disk_characteristics()
{
	/*
	 * The need_spefs flag is used to tell us that this disk
	 * is not a known type and the ctlr specific info must
	 * be prompted for.  We only prompt for the info that applies
	 * to this ctlr.
	 */
	assert(cur_dtype->dtype_flags & DT_NEED_SPEFS);

	/*
	 * If we're running with input from a file, use
	 * reasonable defaults, since prompting for the
	 * information will probably mess things up.
	 */
	if (option_f) {
		cur_dtype->dtype_pcyl = ncyl + acyl;
		cur_dtype->dtype_rpm = AVG_RPM;
		cur_dtype->dtype_bpt = INFINITY;
		cur_dtype->dtype_phead = 0;
		cur_dtype->dtype_psect = 0;
		cur_dtype->dtype_cyl_skew = 0;
		cur_dtype->dtype_trk_skew = 0;
		cur_dtype->dtype_trks_zone = 0;
		cur_dtype->dtype_atrks = 0;
		cur_dtype->dtype_asect = 0;
		cur_dtype->dtype_cache = 0;
		cur_dtype->dtype_threshold = 0;
		cur_dtype->dtype_prefetch_min = 0;
		cur_dtype->dtype_prefetch_max = 0;

		if (cur_ctype->ctype_flags & CF_SMD_DEFS) {
			cur_dtype->dtype_bps = AVG_BPS;
		}
	} else {

		cur_dtype->dtype_pcyl = get_pcyl(ncyl, cur_dtype->dtype_acyl);
		cur_dtype->dtype_bpt = get_bpt(cur_dtype->dtype_nsect,
		    &cur_dtype->dtype_options);
		cur_dtype->dtype_rpm = get_rpm();
		cur_dtype->dtype_fmt_time =
		    get_fmt_time(&cur_dtype->dtype_options);
		cur_dtype->dtype_cyl_skew =
		    get_cyl_skew(&cur_dtype->dtype_options);
		cur_dtype->dtype_trk_skew =
		    get_trk_skew(&cur_dtype->dtype_options);
		cur_dtype->dtype_trks_zone =
		    get_trks_zone(&cur_dtype->dtype_options);
		cur_dtype->dtype_atrks = get_atrks(&cur_dtype->dtype_options);
		cur_dtype->dtype_asect = get_asect(&cur_dtype->dtype_options);
		cur_dtype->dtype_cache = get_cache(&cur_dtype->dtype_options);
		cur_dtype->dtype_threshold =
		    get_threshold(&cur_dtype->dtype_options);
		cur_dtype->dtype_prefetch_min =
		    get_min_prefetch(&cur_dtype->dtype_options);
		cur_dtype->dtype_prefetch_max =
		    get_max_prefetch(cur_dtype->dtype_prefetch_min,
		    &cur_dtype->dtype_options);
		cur_dtype->dtype_phead =
		    get_phead(nhead, &cur_dtype->dtype_options);
		cur_dtype->dtype_psect = get_psect(&cur_dtype->dtype_options);
		cur_dtype->dtype_bps = get_bps();
#ifdef sparc
		cur_dtype->dtype_dr_type = 0;
#endif
	}
}
