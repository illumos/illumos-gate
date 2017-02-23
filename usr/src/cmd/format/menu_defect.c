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
 * This file contains functions to implement the defect menu commands.
 */
#include "global.h"
#include <unistd.h>
#include <string.h>
#include "misc.h"
#include "menu_defect.h"
#include "param.h"
#include "ctlr_scsi.h"

/*
 * This is the working defect list.  All the commands here operate on
 * the working list, except for 'commit'.  This way the user can
 * change their mind at any time without having mangled the current defect
 * list.
 */
struct	defect_list work_list;

#ifdef __STDC__

/* Function prototypes for ANSI C Compilers */
static int	commit_list(void);

#else	/* __STDC__ */

/* Function prototypes for non-ANSI C Compilers */
static int	commit_list();

#endif	/* __STDC__ */

/*
 * This routine implements the 'restore' command.  It sets the working
 * list equal to the current list.
 */
int
d_restore()
{
	int	i;

	assert(!EMBEDDED_SCSI);

	/*
	 * If the working list has not been modified, there's nothing to do.
	 */
	if (!(work_list.flags & LIST_DIRTY)) {
		err_print("working list was not modified.\n");
		return (0);
	}
	/*
	 * Make sure the user is serious.
	 */
	if (check("Ready to update working list, continue"))
		return (-1);
	/*
	 * Lock out interrupts so the lists can't get mangled.
	 */
	enter_critical();
	/*
	 * Kill off the old working list.
	 */
	kill_deflist(&work_list);
	/*
	 * If the current isn't null, set the working list to be a
	 * copy of it.
	 */
	if (cur_list.list != NULL) {
		work_list.header = cur_list.header;
		work_list.list = (struct defect_entry *)zalloc(
		    deflist_size(cur_blksz, work_list.header.count) *
		    cur_blksz);
		for (i = 0; i < work_list.header.count; i++)
			*(work_list.list + i) = *(cur_list.list + i);
	}
	/*
	 * Initialize the flags since they are now in sync.
	 */
	work_list.flags = 0;
	if (work_list.list == NULL)
		fmt_print("working list set to null.\n\n");
	else
		fmt_print("working list updated, total of %d defects.\n\n",
		    work_list.header.count);
	exit_critical();
	return (0);
}

/*
 * This routine implements the 'original' command.  It extracts the
 * manufacturer's defect list from the current disk.
 */
int
d_original()
{
	int	status;


	/*
	 * If the controller does not support the extraction, we're out
	 * of luck.
	 */
	if (cur_ops->op_ex_man == NULL) {
		err_print("Controller does not support extracting ");
		err_print("manufacturer's defect list.\n");
		return (-1);
	}
	/*
	 * Make sure the user is serious.  Note, for SCSI disks
	 * since this is instantaneous, we will just do it and
	 * not ask for confirmation.
	 */
	if (!(cur_ctype->ctype_flags & CF_CONFIRM) &&
	    check(
"Ready to update working list. This cannot be interrupted\n\
and may take a long while. Continue"))
		return (-1);
	/*
	 * Lock out interrupts so we don't get half the list.
	 */
	enter_critical();
	/*
	 * Kill off the working list.
	 */
	kill_deflist(&work_list);
	fmt_print("Extracting manufacturer's defect list...");
	/*
	 * Do the extraction.
	 */
	status = (*cur_ops->op_ex_man)(&work_list);
	if (status)
		fmt_print("Extraction failed.\n\n");
	else {
		fmt_print("Extraction complete.\n");
		fmt_print("Working list updated, total of %d defects.\n\n",
		    work_list.header.count);
	}
	/*
	 * Mark the working list dirty since we modified it.
	 */
	work_list.flags |= LIST_DIRTY;
	exit_critical();
	/*
	 * Return status.
	 */
	return (status);
}

/*
 * This routine implements the 'extract' command.  It extracts the
 * entire defect list from the current disk.
 */
int
d_extract()
{
	int	status;

	/*
	 * If the controller does not support the extraction, we are out
	 * of luck.
	 */
	if (cur_ops->op_ex_cur == NULL) {
		err_print("Controller does not support extracting ");
		err_print("current defect list.\n");
		return (-1);
	}

	/*
	 * If disk is unformatted, you really shouldn't do this.
	 * However, ask user to be sure.
	 */
	if (! (cur_flags & DISK_FORMATTED) &&
	    (check(
"Cannot extract defect list from an unformatted disk. Continue")))
		return (-1);

	/*
	 * If this takes a long time, let's ask the user if they
	 * doesn't mind waiting.  Note, for SCSI disks
	 * this operation is instantaneous so we won't ask for
	 * for confirmation.
	 */
	if (! (cur_ctype->ctype_flags & CF_CONFIRM) &&
	    check(
"Ready to extract working list. This cannot be interrupted\n\
and may take a long while. Continue"))
		return (-1);
	/*
	 * Lock out interrupts so we don't get half the list and
	 * Kill off the working list.
	 */
	enter_critical();
	kill_deflist(&work_list);
	fmt_print("Extracting defect list...");

	/*
	 * Do the extraction.
	 */
	status = (*cur_ops->op_ex_cur)(&work_list);
	if (status) {
		if (!EMBEDDED_SCSI) {
			if (cur_flags & DISK_FORMATTED)
				read_list(&work_list);

			if (work_list.list != NULL) {
				status = 0;
				fmt_print("Extraction complete.\n");
				fmt_print(
"Working list updated, total of %d defects.\n\n",
				    work_list.header.count);
			} else {
				fmt_print("Extraction failed.\n\n");
			}
		} else {
			fmt_print("Extraction failed.\n\n");
		}
	} else {
		fmt_print("Extraction complete.\n");
		fmt_print("Working list updated, total of %d defects.\n\n",
		    work_list.header.count);
	}
	/*
	 * Mark the working list dirty since we modified it.
	 */
	work_list.flags |= LIST_DIRTY;
	exit_critical();
	/*
	 * Return status.
	 */
	return (status);
}

/*
 * This routine implements the 'add' command.  It allows the user to
 * enter the working defect list manually.  It loops infinitely until
 * the user breaks out with a ctrl-C.
 */
int
d_add()
{
	int			type, deflt, index;
	diskaddr_t		bn;
	u_ioparam_t		ioparam;
	struct defect_entry	def;

	assert(!EMBEDDED_SCSI);

	/*
	 * Ask the user which mode of input they'd like to use.
	 */
	fmt_print("        0. bytes-from-index\n");
	fmt_print("        1. logical block\n");
	deflt = 0;
	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = 1;
	type = input(FIO_INT, "Select input format (enter its number)", ':',
	    &ioparam, &deflt, DATA_INPUT);
	fmt_print("\nEnter Control-C to terminate.\n");
loop:
	if (type) {
		/*
		 * Mode selected is logical block.  Input the defective block
		 * and fill in the defect entry with the info.
		 */
		def.bfi = def.nbits = UNKNOWN;
		ioparam.io_bounds.lower = 0;
		if (cur_disk->label_type == L_TYPE_SOLARIS) {
			ioparam.io_bounds.upper = physsects() - 1;
		} else {
			ioparam.io_bounds.upper = cur_parts->etoc->efi_last_lba;
		}
		bn = input(FIO_BN, "Enter defective block number", ':',
		    &ioparam, (int *)NULL, DATA_INPUT);
		def.cyl = bn2c(bn);
		def.head = bn2h(bn);
		def.sect = bn2s(bn);
	} else {
		/*
		 * Mode selected is bytes-from-index.  Input the information
		 * about the defect and fill in the defect entry.
		 */
		def.sect = UNKNOWN;
		ioparam.io_bounds.lower = 0;
		ioparam.io_bounds.upper = pcyl - 1;
		def.cyl = input(FIO_INT,
		    "Enter defect's cylinder number", ':',
		    &ioparam, (int *)NULL, DATA_INPUT);
		ioparam.io_bounds.upper = nhead - 1;
		def.head = input(FIO_INT, "Enter defect's head number",
		    ':', &ioparam, (int *)NULL, DATA_INPUT);
		ioparam.io_bounds.upper = cur_dtype->dtype_bpt - 1;
		def.bfi = input(FIO_INT, "Enter defect's bytes-from-index",
		    ':', &ioparam, (int *)NULL, DATA_INPUT);
		ioparam.io_bounds.lower = -1;
		ioparam.io_bounds.upper = (cur_dtype->dtype_bpt - def.bfi) * 8;
		if (ioparam.io_bounds.upper >= 32 * 1024)
			ioparam.io_bounds.upper = 32 * 1024 - 1;
		/*
		 * Note: a length of -1 means the length is not known.  We
		 * make this the default value.
		 */
		deflt = -1;
		def.nbits = input(FIO_INT, "Enter defect's length (in bits)",
		    ':', &ioparam, &deflt, DATA_INPUT);
	}
	/*
	 * Calculate where in the defect list this defect belongs
	 * and print it out.
	 */
	index = sort_defect(&def, &work_list);
	fmt_print(DEF_PRINTHEADER);
	pr_defect(&def, index);

	/*
	 * Lock out interrupts so lists don't get mangled.
	 * Also, mark the working list dirty since we are modifying it.
	 */
	enter_critical();
	work_list.flags |= LIST_DIRTY;
	/*
	 * If the list is null, create it with zero length.  This is
	 * necessary because the routines to add a defect to the list
	 * assume the list is initialized.
	 */
	if (work_list.list == NULL) {
		work_list.header.magicno = (uint_t)DEFECT_MAGIC;
		work_list.header.count = 0;
		work_list.list = (struct defect_entry *)zalloc(
		    deflist_size(cur_blksz, 0) * cur_blksz);
	}
	/*
	 * Add the defect to the working list.
	 */
	add_def(&def, &work_list, index);
	fmt_print("defect number %d added.\n\n", index + 1);
	exit_critical();
	/*
	 * Loop back for the next defect.
	 */
	goto loop;
	/*NOTREACHED*/
#ifdef	lint
	return (0);
#endif
}

/*
 * This routine implements the 'delete' command.  It allows the user
 * to manually delete a defect from the working list.
 */
int
d_delete()
{
	int		i, count, num;
	u_ioparam_t	ioparam;

	assert(!EMBEDDED_SCSI);

	/*
	 * If the working list is null or zero length, there's nothing
	 * to delete.
	 */
	count = work_list.header.count;
	if (work_list.list == NULL || count == 0) {
		err_print("No defects to delete.\n");
		return (-1);
	}
	/*
	 * Ask the user which defect should be deleted. Bounds are off by
	 * one because user sees a one-relative list.
	 */
	ioparam.io_bounds.lower = 1;
	ioparam.io_bounds.upper = count;
	num = input(FIO_INT, "Specify defect to be deleted (enter its number)",
	    ':', &ioparam, (int *)NULL, DATA_INPUT);
	/*
	 *
	 * The user thinks it's one relative but it's not really.
	 */
	--num;
	/*
	 * Print the defect selected and ask the user for confirmation.
	 */
	fmt_print(DEF_PRINTHEADER);
	pr_defect(work_list.list + num, num);
	/*
	 * Lock out interrupts so the lists don't get mangled.
	 */
	enter_critical();
	/*
	 * Move down all the defects beyond the one deleted so the defect
	 * list is still fully populated.
	 */
	for (i = num; i < count - 1; i++)
		*(work_list.list + i) = *(work_list.list + i + 1);
	/*
	 * If the size of the list in sectors has changed, reallocate
	 * the list to shrink it appropriately.
	 */
	if (deflist_size(cur_blksz, count - 1) <
	    deflist_size(cur_blksz, count))
		work_list.list = (struct defect_entry *)rezalloc(
		    (void *)work_list.list,
		    deflist_size(cur_blksz, count - 1) * cur_blksz);
	/*
	 * Decrement the defect count.
	 */
	work_list.header.count--;
	/*
	 * Recalculate the list's checksum.
	 */
	(void) checkdefsum(&work_list, CK_MAKESUM);
	/*
	 * Mark the working list dirty since we modified it.
	 */
	work_list.flags |= LIST_DIRTY;
	fmt_print("defect number %d deleted.\n\n", ++num);
	exit_critical();
	return (0);
}

/*
 * This routine implements the 'print' command.  It prints the working
 * defect list out in human-readable format.
 */
int
d_print()
{
	int	i, nomore = 0;
	int	c, one_line = 0;
	int	tty_lines = get_tty_lines();

	/*
	 * If the working list is null, there's nothing to print.
	 */
	if (work_list.list == NULL) {
		if (EMBEDDED_SCSI)
			err_print(
"No list defined,extract primary or grown or both defects list first.\n");
		else
			err_print("No working list defined.\n");
		return (-1);
	}
	/*
	 * If we're running from a file, don't use the paging scheme.
	 * If we are running interactive, turn off echoing.
	 */
	if (option_f || (!isatty(0)) || (!isatty(1)))
		nomore++;
	else {
		enter_critical();
		echo_off();
		charmode_on();
		exit_critical();
	}
	/* Print out the banner. */
	if (work_list.header.count != 0)
		fmt_print(DEF_PRINTHEADER);

	/*
	 * Loop through the each defect in the working list.
	 */
	for (i = 0; i < work_list.header.count; i++) {
		/*
		 * If we are paging and hit the end of a page, wait for
		 * the user to hit either space-bar, "q", or return
		 * before going on.
		 */
		if (one_line ||
		    (!nomore && ((i + 1) % (tty_lines - 1) == 0))) {
			/*
			 * Get the next character.
			 */
			fmt_print("- hit space for more - ");
			c = getchar();
			fmt_print("\015");
			one_line = 0;
			/* Handle display one line command (return key) */
			if (c == '\012') {
				one_line++;
			}
			/* Handle Quit command */
			if (c == 'q') {
				fmt_print("                       \015");
				goto PRINT_EXIT;
			}
			/* Handle ^D */
			if (c == '\004')
				fullabort();
		}
		/*
		 * Print the defect.
		 */
		pr_defect(work_list.list + i, i);
	}
	fmt_print("total of %d defects.\n\n", i);
	/*
	 * If we were doing paging, turn echoing back on.
	 */
PRINT_EXIT:
	if (!nomore) {
		enter_critical();
		charmode_off();
		echo_on();
		exit_critical();
	}
	return (0);
}

/*
 * This routine implements the 'dump' command.  It writes the working
 * defect list to a file.
 */
int
d_dump()
{
	int	i, status = 0;
	char	*str;
	FILE	*fptr;
	struct	defect_entry *dptr;

	/*
	 * If the working list is null, there's nothing to do.
	 */
	if (work_list.list == NULL) {
		if (EMBEDDED_SCSI)
			err_print(
"No list defined,extract primary or grown or both defects list first.\n");
		else
			err_print("No working list defined.\n");
		return (-1);
	}
	/*
	 * Ask the user for the name of the defect file.  Note that the
	 * input will be in malloc'd space since we are inputting
	 * type OSTR.
	 */
	str = (char *)(uintptr_t)input(FIO_OSTR, "Enter name of defect file",
	    ':', (u_ioparam_t *)NULL, (int *)NULL, DATA_INPUT);
	/*
	 * Lock out interrupts so the file doesn't get half written.
	 */
	enter_critical();
	/*
	 * Open the file for writing.
	 */
	if ((fptr = fopen(str, "w+")) == NULL) {
		err_print("unable to open defect file.\n");
		status = -1;
		goto out;
	}
	/*
	 * Print a header containing the magic number, count, and checksum.
	 */
	(void) fprintf(fptr, "0x%08x%8d  0x%08x\n",
	    work_list.header.magicno,
	    work_list.header.count, work_list.header.cksum);
	/*
	 * Loop through each defect in the working list.  Write the
	 * defect info to the defect file.
	 */
	for (i = 0; i < work_list.header.count; i++) {
		dptr = work_list.list + i;
		(void) fprintf(fptr, "%4d%8d%7d%8d%8d%8d\n",
		    i+1, dptr->cyl, dptr->head,
		    dptr->bfi, dptr->nbits, dptr->sect);
	}
	fmt_print("defect file updated, total of %d defects.\n", i);
	/*
	 * Close the defect file.
	 */
	(void) fclose(fptr);
out:
	/*
	 * Destroy the string used for the file name.
	 */
	destroy_data(str);
	exit_critical();
	fmt_print("\n");
	return (status);
}

/*
 * This routine implements the 'load' command.  It reads the working
 * list in from a file.
 */
int
d_load()
{
	int	i, items, status = 0, count, cksum;
	uint_t	magicno;
	char	*str;
	TOKEN	filename;
	FILE	*fptr;
	struct	defect_entry *dptr;

	assert(!EMBEDDED_SCSI);

	/*
	 * Ask the user for the name of the defect file.  Note that the
	 * input will be malloc'd space since we inputted type OSTR.
	 */
	str = (char *)(uintptr_t)input(FIO_OSTR, "Enter name of defect file",
	    ':', (u_ioparam_t *)NULL, (int *)NULL, DATA_INPUT);
	/*
	 * Copy the file name into local space then destroy the string
	 * it came in.  This is simply a precaution against later having
	 * to remember to destroy this space.
	 */
	enter_critical();
	(void) strcpy(filename, str);
	destroy_data(str);
	exit_critical();
	/*
	 * See if the defect file is accessable.  If not, we can't load
	 * from it.  We do this here just so we can get out before asking
	 * the user for confirmation.
	 */
	status = access(filename, 4);
	if (status) {
		err_print("defect file not accessable.\n");
		return (-1);
	}
	/*
	 * Make sure the user is serious.
	 */
	if (check("ready to update working list, continue"))
		return (-1);
	/*
	 * Lock out interrupts so the list doesn't get half loaded.
	 */
	enter_critical();
	/*
	 * Open the defect file.
	 */
	if ((fptr = fopen(filename, "r")) == NULL) {
		err_print("unable to open defect file.\n");
		exit_critical();
		return (-1);
	}
	/*
	 * Scan in the header.
	 */
	items = fscanf(fptr, "0x%x%d  0x%x\n", &magicno,
	    &count, (uint_t *)&cksum);
	/*
	 * If the header is wrong, this isn't a good defect file.
	 */
	if (items != 3 || count < 0 ||
	    (magicno != (uint_t)DEFECT_MAGIC &&
	    magicno != (uint_t)NO_CHECKSUM)) {
		err_print("Defect file is corrupted.\n");
		status = -1;
		goto out;
	}
	/*
	 * Kill off any old defects in the working list.
	 */
	kill_deflist(&work_list);
	/*
	 * Load the working list header with the header info.
	 */
	if (magicno == NO_CHECKSUM)
		work_list.header.magicno = (uint_t)DEFECT_MAGIC;
	else
		work_list.header.magicno = magicno;
	work_list.header.count = count;
	work_list.header.cksum = cksum;
	/*
	 * Allocate space for the new list.
	 */
	work_list.list = (struct defect_entry *)zalloc(
	    deflist_size(cur_blksz, count) * cur_blksz);
	/*
	 * Mark the working list dirty since we are modifying it.
	 */
	work_list.flags |= LIST_DIRTY;
	/*
	 * Loop through each defect in the defect file.
	 */
	for (i = 0; i < count; i++) {
		dptr = work_list.list + i;
		/*
		 * Scan the info into the defect entry.
		 */
		items = fscanf(fptr, "%*d%hd%hd%d%hd%hd\n", &dptr->cyl,
		    &dptr->head, &dptr->bfi, &dptr->nbits, &dptr->sect);
		/*
		 * If it didn't scan right, give up.
		 */
		if (items != 5)
			goto bad;
	}
	/*
	 * Check to be sure the checksum from the defect file was correct
	 * unless there wasn't supposed to be a checksum.
	 * If there was supposed to be a valid checksum and there isn't
	 * then give up.
	 */
	if (magicno != NO_CHECKSUM && checkdefsum(&work_list, CK_CHECKSUM))
		goto bad;
	fmt_print("working list updated, total of %d defects.\n", i);
	goto out;

bad:
	/*
	 * Some kind of error occurred.  Kill off the working list and
	 * mark the status bad.
	 */
	err_print("Defect file is corrupted, working list set to NULL.\n");
	kill_deflist(&work_list);
	status = -1;
out:
	/*
	 * Close the defect file.
	 */
	(void) fclose(fptr);
	exit_critical();
	fmt_print("\n");
	return (status);
}

/*
 * This routine implements the 'commit' command.  It causes the current
 * defect list to be set equal to the working defect list.  It is the only
 * way that changes made to the working list can actually take effect in
 * the next format.
 */
int
d_commit()
{
	/*
	 * If the working list wasn't modified, no commit is necessary.
	 */
	if (work_list.list != NULL && !(work_list.flags & LIST_DIRTY)) {
		err_print("working list was not modified.\n");
		return (0);
	}

	/*
	 * Make sure the user is serious.
	 */
	if (check("Ready to update Current Defect List, continue"))
		return (-1);
	return (do_commit());
}

int
do_commit()
{
	int	status;

	if ((status = commit_list()) == 0) {
		/*
		 * Remind the user to format the drive, since changing
		 * the list does nothing unless a format is performed.
		 */
		fmt_print(\
"Disk must be reformatted for changes to take effect.\n\n");
	}
	return (status);
}


static int
commit_list()
{
	int	i;

	/*
	 * Lock out interrupts so the list doesn't get half copied.
	 */
	enter_critical();
	/*
	 * Kill off any current defect list.
	 */
	kill_deflist(&cur_list);
	/*
	 * If the working list is null, initialize it to zero length.
	 * This is so the user can do a commit on a null list and get
	 * a zero length list.  Otherwise there would be no way to get
	 * a zero length list conveniently.
	 */
	if (work_list.list == NULL) {
		work_list.header.magicno = (uint_t)DEFECT_MAGIC;
		work_list.header.count = 0;
		work_list.list = (struct defect_entry *)zalloc(
		    deflist_size(cur_blksz, 0) * cur_blksz);
	}
	/*
	 * Copy the working list into the current list.
	 */
	cur_list.header = work_list.header;
	cur_list.list = (struct defect_entry *)zalloc(
	    deflist_size(cur_blksz, cur_list.header.count) * cur_blksz);
	for (i = 0; i < cur_list.header.count; i++)
		*(cur_list.list + i) = *(work_list.list + i);
	/*
	 * Mark the working list clean, since it is now the same as the
	 * current list.  Note we do not mark the current list dirty,
	 * even though it has been changed.  This is because it does
	 * not reflect the state of disk, so we don't want it written
	 * out until a format has been done.  The format will mark it
	 * dirty and write it out.
	 */
	work_list.flags &= ~(LIST_DIRTY|LIST_RELOAD);
	cur_list.flags = work_list.flags;
	if (EMBEDDED_SCSI)
		fmt_print("Defect List has a total of %d defects.\n",
		    cur_list.header.count);
	else
		fmt_print("Current Defect List updated, total of %d defects.\n",
		    cur_list.header.count);
	exit_critical();
	return (0);
}


/*
 * This routine implements the 'create' command.  It creates the
 * manufacturer's defect on the current disk from the defect list
 */
int
d_create()
{
	int	status;

	assert(!EMBEDDED_SCSI);

	/*
	 * If the controller does not support the extraction, we're out
	 * of luck.
	 */
	if (cur_ops->op_create == NULL) {
		err_print("Controller does not support creating ");
		err_print("manufacturer's defect list.\n");
		return (-1);
	}
	/*
	 * Make sure the user is serious.  Note, for SCSI disks
	 * since this is instantaneous, we will just do it and
	 * not ask for confirmation.
	 */
	if (! (cur_ctype->ctype_flags & CF_SCSI) &&
	    check(
"Ready to create the manufacturers defect information on the disk.\n\
This cannot be interrupted and may take a long while.\n\
IT WILL DESTROY ALL OF THE DATA ON THE DISK! Continue"))
		return (-1);
	/*
	 * Lock out interrupts so we don't get half the list.
	 */
	enter_critical();
	fmt_print("Creating manufacturer's defect list...");
	/*
	 * Do the Creation
	 */
	status = (*cur_ops->op_create)(&work_list);
	if (status) {
		fmt_print("Creation failed.\n\n");
	} else {
		fmt_print("Creation complete.\n");
	}
	exit_critical();
	/*
	 * Return status.
	 */
	return (status);
}


/*
 * Extract primary defect list - SCSI only
 */
int
d_primary()
{
	int	status;

	assert(EMBEDDED_SCSI);

	/*
	 * Lock out interrupts so we don't get half the list and
	 * Kill off the working list.
	 */
	enter_critical();
	kill_deflist(&work_list);
	fmt_print("Extracting primary defect list...");

	/*
	 * Do the extraction.
	 */
	status = scsi_ex_man(&work_list);
	if (status) {
		fmt_print("Extraction failed.\n\n");
	} else {
		fmt_print("Extraction complete.\n");
		/*
		 * Mark the working list dirty since we modified it.
		 * Automatically commit it, for SCSI only.
		 */
		work_list.flags |= LIST_DIRTY;
		status = commit_list();
		fmt_print("\n");
	}
	exit_critical();

	/*
	 * Return status.
	 */
	return (status);
}


/*
 * Extract grown defects list - SCSI only
 */
int
d_grown()
{
	int	status;

	assert(EMBEDDED_SCSI);

	/*
	 * Lock out interrupts so we don't get half the list and
	 * Kill off the working list.
	 */
	enter_critical();
	kill_deflist(&work_list);
	fmt_print("Extracting grown defects list...");

	/*
	 * Do the extraction.
	 */
	status = scsi_ex_grown(&work_list);
	if (status) {
		fmt_print("Extraction failed.\n\n");
	} else {
		fmt_print("Extraction complete.\n");
		/*
		 * Mark the working list dirty since we modified it.
		 * Automatically commit it, for SCSI only.
		 */
		work_list.flags |= LIST_DIRTY;
		status = commit_list();
		fmt_print("\n");
	}
	exit_critical();

	/*
	 * Return status.
	 */
	return (status);
}


/*
 * Extract both primary and grown defects list - SCSI only
 */
int
d_both()
{
	int	status;

	assert(EMBEDDED_SCSI);

	/*
	 * Lock out interrupts so we don't get half the list and
	 * Kill off the working list.
	 */
	enter_critical();
	kill_deflist(&work_list);
	fmt_print("Extracting both primary and grown defects lists...");

	/*
	 * Do the extraction.
	 */
	status = scsi_ex_cur(&work_list);
	if (status) {
		fmt_print("Extraction failed.\n\n");
	} else {
		fmt_print("Extraction complete.\n");
		/*
		 * Mark the working list dirty since we modified it.
		 * Automatically commit it, for SCSI only.
		 */
		work_list.flags |= LIST_DIRTY;
		status = commit_list();
		fmt_print("\n");
	}
	exit_critical();

	/*
	 * Return status.
	 */
	return (status);
}
