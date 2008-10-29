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

/*
 * This file contains functions implementing the analyze menu commands.
 */
#include <string.h>
#include "global.h"
#include "analyze.h"
#include "misc.h"
#include "menu_analyze.h"
#include "param.h"



/*
 * This routine implements the 'read' command.  It performs surface
 * analysis by reading the disk.  It is ok to run this command on
 * mounted file systems.
 */
int
a_read()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}

	if (check(
"Ready to analyze (won't harm SunOS). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);
	return (do_scan(SCAN_VALID, F_NORMAL));
}

/*
 * This routine implements the 'refresh' command.  It performs surface
 * analysis by reading the disk then writing the same data back to the
 * disk.  It is ok to run this command on file systems, but not while
 * they are mounted.
 */
int
a_refresh()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}

	if (check(
"Ready to analyze (won't harm data). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);
	return (do_scan(SCAN_VALID | SCAN_WRITE, F_NORMAL));
}

/*
 * This routine implements the 'test' command.  It performs surface
 * analysis by reading the disk, writing then reading a pattern on the disk,
 * then writing the original data back to the disk.
 * It is ok to run this command on file systems, but not while they are
 * mounted.
 */
int
a_test()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}

	if (check(
"Ready to analyze (won't harm data). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);
	return (do_scan(SCAN_VALID | SCAN_PATTERN | SCAN_WRITE, F_NORMAL));
}

/*
 * This routine implements the 'write' command.  It performs surface
 * analysis by writing a pattern to the disk then reading it back.
 * It is not ok to run this command on any data you want to keep.
 */
int
a_write()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}

	if (check(
"Ready to analyze (will corrupt data). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);
	return (do_scan(SCAN_PATTERN, F_NORMAL));
}

/*
 * This routine implements the 'compare' command.  It performs surface
 * analysis by writing a pattern to the disk, reading it back, then
 * checking the data to be sure it's the same.
 * It is not ok to run this command on any data you want to keep.
 */
int
a_compare()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}

	if (check(
"Ready to analyze (will corrupt data). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);
	return (do_scan(SCAN_PATTERN | SCAN_COMPARE, F_NORMAL));
}

/*
 * This routine implements the 'print' command.  It displays the data
 * buffer in hexadecimal.  It is only useful for checking the disk for
 * a specific set of data (by reading it then printing it).
 */
int
a_print()
{
	int	i, j, lines, nomore = 0;
	int	c, one_line = 0;
	int	tty_lines = get_tty_lines();

	/*
	 * If we are running out of command file, don't page the output.
	 * Otherwise we are running with a user.  Turn off echoing of
	 * input characters so we can page the output.
	 */
	if (option_f || (!isatty(0)) || (!isatty(1)))
		nomore++;
	else {
		enter_critical();
		echo_off();
		charmode_on();
		exit_critical();
	}
	/*
	 * Loop through the data buffer.
	 */
	lines = 0;
	for (i = 0; i < scan_size * SECSIZE / sizeof (int); i += 6) {
		/*
		 * Print the data.
		 */
		for (j = 0; j < 6; j++)
			if (i + j < scan_size * SECSIZE / sizeof (int))
				fmt_print("0x%08x  ",
				    *((int *)((int *)cur_buf + i + j)));
		fmt_print("\n");
		lines++;

		/*
		 * If we are paging and hit the end of a page, wait for
		 * the user to hit either space-bar, "q", return,
		 * or ctrl-C before going on.
		 */
		if (one_line ||
		    (!nomore && (lines % (tty_lines - 1) == 0))) {
			/*
			 * Print until first screenfull
			 */
			if (lines < (tty_lines -1))
				continue;
			/*
			 * Get the next character.
			 */
			(void) printf("- hit space for more - ");
			c = getchar();
			(void) printf("\015");
			one_line = 0;
			/*
			 * Handle display one line command (return key)
			 */
			if (c == '\012') {
				one_line++;
			}
			/* Handle Quit command */
			if (c == 'q') {
				(void) printf(
				"                       \015");
				goto PRINT_EXIT;
			}
			/* handle ^D */
			if (c == '\004')
				fullabort();
		}
	}
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
 * This routine implements the 'setup' command.  It allows the user
 * to program the variables that drive surface analysis.  The approach
 * is to prompt the user for the value of each variable, with the current
 * value as the default.
 */
int
a_setup()
{
	int			deflt;
	uint64_t		size;
	u_ioparam_t		ioparam;

	/*
	 * Because of the polarity of the yes/no structure (yes is 0),
	 * we have to invert the values for all yes/no questions.
	 */
	deflt = !scan_entire;
	ioparam.io_charlist = confirm_list;
	scan_entire = !input(FIO_MSTR, "Analyze entire disk", '?',
	    &ioparam, &deflt, DATA_INPUT);
	/*
	 * If we are not scanning the whole disk, input the bounds of the scan.
	 */
	if (!scan_entire) {
		ioparam.io_bounds.lower = 0;
		if ((cur_ctype->ctype_flags & CF_SCSI) &&
		    (cur_disk->label_type == L_TYPE_SOLARIS)) {
			ioparam.io_bounds.upper = datasects() - 1;
		} else if (cur_disk->label_type == L_TYPE_SOLARIS) {
			ioparam.io_bounds.upper = physsects() - 1;
		} else if (cur_disk->label_type == L_TYPE_EFI) {
			ioparam.io_bounds.upper = cur_parts->etoc->efi_last_lba;
		}

		scan_lower = (diskaddr_t)input(FIO_BN,
		    "Enter starting block number", ':',
		    &ioparam, (int *)&scan_lower, DATA_INPUT);
		ioparam.io_bounds.lower = scan_lower;
		if (scan_upper < scan_lower)
			scan_upper = scan_lower;
		scan_upper = (diskaddr_t)input(FIO_BN,
		    "Enter ending block number", ':',
		    &ioparam, (int *)&scan_upper, DATA_INPUT);
	}
	deflt = !scan_loop;
	ioparam.io_charlist = confirm_list;
	scan_loop = !input(FIO_MSTR, "Loop continuously", '?',
	    &ioparam, &deflt, DATA_INPUT);
	/*
	 * If we are not looping continuously, input the number of passes.
	 */
	if (!scan_loop) {
		ioparam.io_bounds.lower = 1;
		ioparam.io_bounds.upper = 100;
		scan_passes = input(FIO_INT, "Enter number of passes", ':',
		    &ioparam, &scan_passes, DATA_INPUT);
	}
	deflt = !scan_correct;
	ioparam.io_charlist = confirm_list;
	scan_correct = !input(FIO_MSTR, "Repair defective blocks", '?',
	    &ioparam, &deflt, DATA_INPUT);
	deflt = !scan_stop;
	ioparam.io_charlist = confirm_list;
	scan_stop = !input(FIO_MSTR, "Stop after first error", '?',
	    &ioparam, &deflt, DATA_INPUT);
	deflt = !scan_random;
	ioparam.io_charlist = confirm_list;
	scan_random = !input(FIO_MSTR, "Use random bit patterns", '?',
	    &ioparam, &deflt, DATA_INPUT);
	ioparam.io_bounds.lower = 1;
	/*
	 * The number of blocks per transfer is limited by the buffer
	 * size, or the scan boundaries, whichever is smaller.
	 */
	if ((scan_entire) && (cur_disk->label_type == L_TYPE_SOLARIS)) {
		size = physsects() - 1;
	} else if ((scan_entire) && (cur_disk->label_type == L_TYPE_EFI)) {
		size = cur_parts->etoc->efi_last_lba;
	} else {
		size = scan_upper - scan_lower + 1;
	}
	ioparam.io_bounds.upper = min(size, BUF_SECTS);
	if (scan_size > ioparam.io_bounds.upper)
		scan_size = ioparam.io_bounds.upper;
	scan_size = input(FIO_INT, "Enter number of blocks per transfer", ':',
	    &ioparam, (int *)&scan_size, DATA_INPUT);
	deflt = !scan_auto;
	ioparam.io_charlist = confirm_list;
	scan_auto = !input(FIO_MSTR, "Verify media after formatting", '?',
	    &ioparam, &deflt, DATA_INPUT);

	deflt = !option_msg;
	ioparam.io_charlist = confirm_list;
	option_msg = !input(FIO_MSTR, "Enable extended messages", '?',
	    &ioparam, &deflt, DATA_INPUT);
	deflt = !scan_restore_defects;
	ioparam.io_charlist = confirm_list;
	scan_restore_defects = !input(FIO_MSTR, "Restore defect list", '?',
	    &ioparam, &deflt, DATA_INPUT);
	deflt = !scan_restore_label;
	ioparam.io_charlist = confirm_list;
	scan_restore_label = !input(FIO_MSTR, "Restore disk label", '?',
	    &ioparam, &deflt, DATA_INPUT);
	fmt_print("\n");
	return (0);
}

/*
 * This routine implements the 'config' command.  It simply prints out
 * the values of all the variables controlling surface analysis.  It
 * is meant to complement the 'setup' command by allowing the user to
 * check the current setup.
 */
int
a_config()
{

	fmt_print("        Analyze entire disk? ");
	fmt_print(scan_entire ? "yes\n" : "no\n");

	if (!scan_entire) {
		fmt_print("        Starting block number: %llu (", scan_lower);
		pr_dblock(fmt_print, scan_lower);
		fmt_print(")\n        Ending block number: %llu (", scan_upper);
		pr_dblock(fmt_print, scan_upper);
		fmt_print(")\n");
	}
	fmt_print("        Loop continuously? ");
	fmt_print(scan_loop ? "yes\n" : "no\n");

	if (!scan_loop) {
		fmt_print("        Number of passes: %d\n", scan_passes);
	}

	fmt_print("        Repair defective blocks? ");
	fmt_print(scan_correct ? "yes\n" : "no\n");

	fmt_print("        Stop after first error? ");
	fmt_print(scan_stop ? "yes\n" : "no\n");

	fmt_print("        Use random bit patterns? ");
	fmt_print(scan_random ? "yes\n" : "no\n");

	fmt_print("        Number of blocks per transfer: %d (", scan_size);
	pr_dblock(fmt_print, (diskaddr_t)scan_size);
	fmt_print(")\n");

	fmt_print("        Verify media after formatting? ");
	fmt_print(scan_auto ? "yes\n" : "no\n");

	fmt_print("        Enable extended messages? ");
	fmt_print(option_msg ? "yes\n" : "no\n");

	fmt_print("        Restore defect list? ");
	fmt_print(scan_restore_defects ? "yes\n" : "no\n");

	fmt_print("        Restore disk label? ");
	fmt_print(scan_restore_label ? "yes\n" : "no\n");

	fmt_print("\n");
	return (0);
}

/*
 * This routine implements the 'purge' command.  It purges the disk
 * by writing three patterns to the disk then reading the last one back.
 * It is not ok to run this command on any data you want to keep.
 */
int
a_purge()
{
	int status = 0;

	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	if (scan_random) {
		fmt_print("The purge command does not write random data\n");
		scan_random = 0;
	}

	if (!scan_loop && (scan_passes <= NPPATTERNS)) {
		if (scan_passes < NPPATTERNS) {
			fmt_print("The purge command runs for a minimum of ");
			fmt_print("%d passes plus a last pass if the\n",
			    NPPATTERNS);
			fmt_print("first %d passes were successful.\n",
			    NPPATTERNS);
		}
		scan_passes = NPPATTERNS + 1;
	}

	if (check(
"Ready to purge (will corrupt data). This takes a long time, \n"
"but is interruptible with CTRL-C. Continue"))
		return (-1);

	status = do_scan(SCAN_PATTERN | SCAN_PURGE, F_NORMAL);

	return (status);
}

/*
 * This routine implements the 'verify' command.  It writes the disk
 * by writing unique data for each block; after the write pass, it
 * reads the data and verifies for correctness. Note that the entire
 * disk (or the range of disk) is fully written first and then read.
 * This should eliminate any caching effect on the drives.
 * It is not ok to run this command on any data you want to keep.
 */
int
a_verify()
{
	/*
	 * The current disk must be formatted before disk analysis.
	 */
	if (!(cur_flags & DISK_FORMATTED)) {
		err_print("Current Disk is unformatted.\n");
		return (-1);
	}
	if (scan_random) {
		fmt_print("The verify command does not write random data\n");
		scan_random = 0;
	}
	if (scan_passes < 2 && !scan_loop) {
		scan_passes = 2;
		fmt_print("The verify command runs minimum of 2 passes, one"
		    " for writing and \nanother for reading and verfying."
		    " Resetting the number of passes to 2.\n");
	}

	if (check("Ready to verify (will corrupt data). This takes a long time,"
	    "\nbut is interruptible with CTRL-C. Continue")) {
		return (-1);
	}

	return (do_scan(SCAN_WRITE | SCAN_VERIFY, F_NORMAL));
}
