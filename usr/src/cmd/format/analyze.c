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
 */

/*
 * This file contains routines to analyze the surface of a disk.
 */
#include "global.h"
#include "analyze.h"
#include <stdlib.h>
#include <errno.h>
#include "misc.h"
#include "defect.h"
#include "label.h"
#include "param.h"
#include "checkdev.h"


/*
 * These global variables control the surface analysis process.  They
 * are set from a command in the defect menu.
 */
int	scan_entire = 1;		/* scan whole disk flag */
diskaddr_t	scan_lower = 0;			/* lower bound */
diskaddr_t	scan_upper = 0;			/* upper bound */
int	scan_correct = 1;		/* correct errors flag */
int	scan_stop = 0;			/* stop after error flag */
int	scan_loop = 0;			/* loop forever flag */
int	scan_passes = 2;		/* number of passes */
int	scan_random = 0;		/* random patterns flag */
uint_t	scan_size = 0;			/* sectors/scan operation */
int	scan_auto = 1;			/* scan after format flag */
int	scan_restore_defects = 1;	/* restore defect list after writing */
int	scan_restore_label = 1;		/* restore label after writing */

/*
 * These are summary variables to print out info after analysis.
 * Values less than 0 imply they are invalid.
 */
offset_t	scan_cur_block = -1;		/* current block */
int64_t		scan_blocks_fixed = -1;		/* # blocks repaired */

/*
 * This variable is used to tell whether the most recent surface
 * analysis error was caused by a media defect or some other problem.
 */
int	media_error;			/* error was caused by defect */

int	disk_error;			/* disk errors during analysis */

/*
 * These are the data patterns used if random patterns are not chosen.
 * They are designed to show pattern dependent errors.
 */
static unsigned int	scan_patterns[] = {
	0xc6dec6de,
	0x6db6db6d,
	0x00000000,
	0xffffffff,
	0xaaaaaaaa,
};
#define	NPATTERNS	5		/* number of predefined patterns */

/*
 * These are the data patterns from the SunFed requirements document.
 */
static unsigned int purge_patterns[] = {	/* patterns to be written */
	0xaaaaaaaa,		/* 10101010... */
	0x55555555,		/* 01010101...  == UUUU... */
	0xaaaaaaaa,		/* 10101010... */
	0xaaaaaaaa,		/* 10101010... */
};

static unsigned int alpha_pattern =  0x40404040;   /* 10000000...  == @@@@... */

/* Function prototypes */
#ifdef	__STDC__

static int	scan_repair(diskaddr_t bn, int mode);
static int	analyze_blocks(int flags, diskaddr_t blkno, uint_t blkcnt,
		unsigned data, int init, int driver_flags, int *xfercntp);
static int	handle_error_conditions(void);
static int	verify_blocks(int flags, diskaddr_t blkno, uint_t blkcnt,
		unsigned data, int driver_flags, int *xfercntp);
#else	/* __STDC__ */

static int	scan_repair();
static int	analyze_blocks();
static int	handle_error_conditions();
static int	verify_blocks();

#endif	/* __STDC__ */

/*
 * This routine performs a surface analysis based upon the global
 * parameters.  It is called from several commands in the defect menu,
 * and from the format command in the command menu (if post-format
 * analysis is enable).
 */
int
do_scan(flags, mode)
	int	flags, mode;
{
	diskaddr_t	start, end, curnt;
	int	pass, needinit, data;
	uint_t	size;
	int	status, founderr, i, j;
	int	error = 0;
	int	pattern = 0;
	int	xfercnt;

	/*
	 * Check to be sure we aren't correcting without a defect list
	 * if the controller can correct the defect.
	 */
	if (scan_correct && !EMBEDDED_SCSI && (cur_ops->op_repair != NULL) &&
			(cur_list.list == NULL)) {
		err_print("Current Defect List must be initialized ");
		err_print("to do automatic repair.\n");
		return (-1);
	}
	/*
	 * Define the bounds of the scan.
	 */
	if (scan_entire) {
		start = 0;
	    if (cur_label == L_TYPE_SOLARIS) {
		if (cur_ctype->ctype_flags & CF_SCSI)
			end = datasects() - 1;
		else
			end = physsects() - 1;
	    } else if (cur_label == L_TYPE_EFI) {
		end = cur_parts->etoc->efi_last_lba;
	    }
	} else {
		start = scan_lower;
		end = scan_upper;
	}
	/*
	 * Make sure the user knows if we are scanning over a mounted
	 * partition.
	 */
	if ((flags & (SCAN_PATTERN | SCAN_WRITE)) &&
	    (checkmount(start, end))) {
		err_print("Cannot do analysis on a mounted partition.\n");
		return (-1);
	}

	/*
	 * Make sure the user knows if we are scanning over a
	 * partition being used for swapping.
	 */
	if ((flags & (SCAN_PATTERN | SCAN_WRITE)) &&
	    (checkswap(start, end))) {
		err_print("Cannot do analysis on a partition \
		    which is currently being used for swapping.\n");
		return (-1);
	}

	/*
	 * Check to see if any partitions used for svm, vxvm, ZFS zpool
	 * or live upgrade are on the disk.
	 */
	if ((flags & (SCAN_PATTERN | SCAN_WRITE)) &&
	    (checkdevinuse(cur_disk->disk_name, (diskaddr_t)-1,
	    (diskaddr_t)-1, 0, 0))) {
		err_print("Cannot do analysis on a partition "
		    "while it in use as described above.\n");
		return (-1);
	}

	/*
	 * If we are scanning destructively over certain sectors,
	 * we mark the defect list and/or label dirty so it will get rewritten.
	 */
	if (flags & (SCAN_PATTERN | SCAN_WRITE)) {
	    if (cur_label == L_TYPE_SOLARIS) {
		if (start < (diskaddr_t)totalsects() &&
				end >= (diskaddr_t)datasects()) {
			if (!EMBEDDED_SCSI) {
				cur_list.flags |= LIST_DIRTY;
			}
			if (cur_disk->disk_flags & DSK_LABEL)
				cur_flags |= LABEL_DIRTY;
		}
	    }
	    if (start == 0) {
		if (cur_disk->disk_flags & DSK_LABEL)
			cur_flags |= LABEL_DIRTY;
	    }
	}
	/*
	 * Initialize the summary info on sectors repaired.
	 */
	scan_blocks_fixed = 0;
	/*
	 * Loop through the passes of the scan. If required, loop forever.
	 */
	for (pass = 0; pass < scan_passes || scan_loop; pass++) {
		/*
		 * Determine the data pattern to use if pattern testing
		 * is to be done.
		 */
		if (flags & SCAN_PATTERN) {
			if (scan_random)
				data = (int)mrand48();
			else
				data = scan_patterns[pass % NPPATTERNS];

			if (flags & SCAN_PURGE) {
				flags &= ~(SCAN_PURGE_READ_PASS
						| SCAN_PURGE_ALPHA_PASS);
				switch (pattern % (NPPATTERNS + 1)) {
				case NPPATTERNS:
					pattern = 0;
					if (!error) {
					    fmt_print(
"\nThe last %d passes were successful, running alpha pattern pass", NPPATTERNS);
					    flags |= SCAN_PURGE_ALPHA_PASS;
					    data = alpha_pattern;
					} else {
					    data = purge_patterns[pattern];
					    pattern++;
					};
					break;
				case READPATTERN:
					flags |=  SCAN_PURGE_READ_PASS;
					/* FALLTHROUGH */
				default:
					data = purge_patterns[pattern];
					pattern++;
					break;
				}
			}
			fmt_print("\n        pass %d", pass);
			fmt_print(" - pattern = 0x%x", data);
		} else
			fmt_print("\n        pass %d", pass);

		fmt_print("\n");
		/*
		 * Mark the pattern buffer as corrupt, since it
		 * hasn't been initialized.
		 */
		needinit = 1;
		/*
		 * Print the first block number to the log file if
		 * logging is on so there is some record of what
		 * analysis was performed.
		 */
		if (log_file) {
			pr_dblock(log_print, start);
			log_print("\n");
		}
		/*
		 * Loop through this pass, each time analyzing an amount
		 * specified by the global parameters.
		 */
		xfercnt = 0;
		for (curnt = start; curnt <= end; curnt += size) {
			if ((end - curnt) < scan_size)
				size = end - curnt + 1;
			else
				size = scan_size;
			/*
			 * Print out where we are, so we don't look dead.
			 * Also store it in summary info for logging.
			 */
			scan_cur_block = curnt;
			nolog_print("   ");
			pr_dblock(nolog_print, curnt);
			nolog_print("  \015");
			(void) fflush(stdout);
			disk_error = 0;
			/*
			 * Do the actual analysis.
			 */
			status = analyze_blocks(flags, curnt, size,
			    (unsigned)data, needinit, (F_ALLERRS | F_SILENT),
			    &xfercnt);
			/*
			 * If there were no errors, the pattern buffer is
			 * still initialized, and we just loop to next chunk.
			 */
			needinit = 0;
			if (!status)
				continue;
			/*
			 * There was an error. Check if surface analysis
			 * can be continued.
			 */
			if (handle_error_conditions()) {
				scan_blocks_fixed = scan_cur_block = -1;
				return (-1);
			}
			/*
			 * There was an error. Mark the pattern buffer
			 * corrupt so it will get reinitialized.
			 */
			needinit = 1;
			/*
			 * If it was not a media error, ignore it.
			 */
			if (!media_error)
				continue;
			/*
			 * Loop 5 times through each sector of the chunk,
			 * analyzing them individually.
			 */
			nolog_print("   ");
			pr_dblock(nolog_print, curnt);
			nolog_print("  \015");
			(void) fflush(stdout);
			founderr = 0;
			for (j = 0; j < size * 5; j++) {
				i = j % size;
				disk_error = 0;
				status = analyze_blocks(flags, (curnt + i), 1,
				    (unsigned)data, needinit, F_ALLERRS, NULL);
				needinit = 0;
				if (!status)
					continue;
				/*
				 * There was an error. Check if surface analysis
				 * can be continued.
				 */
				if (handle_error_conditions()) {
					scan_blocks_fixed = scan_cur_block = -1;
					return (-1);
				}
				/*
				 * An error occurred.  Mark the buffer
				 * corrupt and see if it was media
				 * related.
				 */
				needinit = 1;
				if (!media_error)
					continue;
				/*
				 * We found a bad sector. Print out a message
				 * and fix it if required.
				 */
				founderr = 1;
				if (scan_correct && (flags != SCAN_VALID)) {
					if (scan_repair(curnt+i, mode)) {
						error = -1;
					}
				} else
					err_print("\n");
				/*
				 * Stop after the error if required.
				 */
				if (scan_stop)
					goto out;
			}
			/*
			 * Mark the pattern buffer corrupt to be safe.
			 */
			needinit = 1;
			/*
			 * We didn't find an individual sector that was bad.
			 * Print out a warning.
			 */
			if (!founderr) {
				err_print("Warning: unable to pinpoint ");
				err_print("defective block.\n");
			}
		}
		/*
		 * Print the end of each pass to the log file.
		 */
		enter_critical();
		if (log_file) {
			pr_dblock(log_print, scan_cur_block);
			log_print("\n");
		}
		scan_cur_block = -1;
		exit_critical();
		fmt_print("\n");

		/*
		 * alternate the read and write for SCAN_VERIFY test
		 */
		if (flags & SCAN_VERIFY) {
			flags ^= SCAN_VERIFY_READ_PASS;
		}
	}
out:
	/*
	 * We got here either by giving up after an error or falling
	 * through after all passes were completed.
	 */
	fmt_print("\n");
	enter_critical();
	/*
	 * If the defect list is dirty, write it to disk,
	 * if scan_restore_defects (the default) is true.
	 */
	if (!EMBEDDED_SCSI && (cur_list.flags & LIST_DIRTY) &&
				(scan_restore_defects)) {
		cur_list.flags = 0;
		write_deflist(&cur_list);
		}
	/*
	 * If the label is dirty, write it to disk.
	 * if scan_restore_label (the default) is true.
	 */
	if ((cur_flags & LABEL_DIRTY) && (scan_restore_label)) {
		cur_flags &= ~LABEL_DIRTY;
		(void) write_label();
	}
	/*
	 * If we dropped down to here after an error, we need to write
	 * the final block number to the log file for record keeping.
	 */
	if (log_file && scan_cur_block >= 0) {
		pr_dblock(log_print, scan_cur_block);
		log_print("\n");
	}
	fmt_print("Total of %lld defective blocks repaired.\n",
		scan_blocks_fixed);
	/*
	 * Reinitialize the logging variables so they don't get used
	 * when they are not really valid.
	 */
	scan_blocks_fixed = scan_cur_block = -1;
	exit_critical();
	return (error);
}


/*
 * This routine is called to repair a bad block discovered
 * during a scan operation.  Return 0 for success, 1 for failure.
 * (This has been extracted out of do_scan(), to simplify it.)
 */
static int
scan_repair(bn, mode)
	diskaddr_t	bn;
	int	mode;
{
	int	status;
	int	result = 1;
	char	*buf;
	int	buf_is_good;
	int	i;

	if (cur_ops->op_repair == NULL) {
		err_print("Warning: Controller does ");
		err_print("not support repairing.\n\n");
		return (result);
	}

	buf = malloc(cur_blksz);
	if (buf == NULL) {
		err_print("Warning: no memory.\n\n");
		return (result);
	}
	enter_critical();

	/*
	 * Determine if the error appears to be hard or soft.  We
	 * already assume there's an error.  If we can get any
	 * good data out of the sector, write that data back
	 * after the repair.
	 */
	buf_is_good = 0;
	for (i = 0; i < 5; i++) {
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, bn, 1,
				buf, F_SILENT, NULL);
		if (status == 0) {
			buf_is_good = 1;
			break;
		}
	}

	fmt_print("Repairing %s error on %llu (",
				buf_is_good ? "soft" : "hard", bn);
	pr_dblock(fmt_print, bn);
	fmt_print(")...");

	status = (*cur_ops->op_repair)(bn, mode);
	if (status) {
		/*
		 * If the repair failed, we note it and will return the
		 * failure. However, the analysis goes on.
		 */
		fmt_print("failed.\n\n");
	} else {
		/*
		 * The repair worked.  Write the good data we could
		 * recover from the failed block, if possible.
		 * If not, zero the block.  In doing so, try to
		 * determine if the new block appears ok.
		 */
		if (!buf_is_good) {
			bzero(buf, cur_blksz);
			fmt_print("Warning: Block %llu zero-filled.\n", bn);
		} else {
			fmt_print("ok.\n");
		}
		status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file, bn,
					1, buf, (F_SILENT | F_ALLERRS), NULL);
		if (status == 0) {
			status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, bn,
					1, buf, (F_SILENT | F_ALLERRS), NULL);
		}
		if (status) {
			fmt_print("The new block also appears defective.\n");
		}
		fmt_print("\n");
		/*
		 * add the defect to the list and write the list out.
		 * Also, kill the working list so it will get resynced
		 * with the current list.
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
		/*
		 * The next "if" statement reflects the fix for
		 * bug id 1026096 where format keeps adding the
		 * same defect to the defect list.
		 */
		} else if (cur_ctype->ctype_flags & CF_WLIST) {
			kill_deflist(&cur_list);
			(*cur_ops->op_ex_cur)(&cur_list);
			fmt_print("Current list updated\n");
		} else {
			add_ldef(bn, &cur_list);
			write_deflist(&cur_list);
		}
		kill_deflist(&work_list);

		/* Log the repair.  */
		scan_blocks_fixed++;

		/* return ok */
		result = 0;
	}

	exit_critical();
	free(buf);
	return (result);
}


/*
 * This routine analyzes a set of sectors on the disk.  It simply returns
 * an error if a defect is found.  It is called by do_scan().
 */
static int
analyze_blocks(flags, blkno, blkcnt, data, init, driver_flags, xfercntp)
	int	flags, driver_flags, init;
	uint_t	blkcnt;
	register unsigned data;
	diskaddr_t	blkno;
	int	*xfercntp;
{
	int		corrupt = 0;
	int		status;
	register diskaddr_t	i, nints;
	register unsigned *ptr = (uint_t *)pattern_buf;

	media_error = 0;
	if (flags & SCAN_VERIFY) {
		return (verify_blocks(flags, blkno, blkcnt, data,
		    driver_flags, xfercntp));
	}

	/*
	 * Initialize the pattern buffer if necessary.
	 */
	nints = (diskaddr_t)blkcnt * cur_blksz / sizeof (int);
	if ((flags & SCAN_PATTERN) && init) {
		for (i = 0; i < nints; i++)
			*((int *)((int *)pattern_buf + i)) = data;
	}
	/*
	 * Lock out interrupts so we can insure valid data will get
	 * restored. This is necessary because there are modes
	 * of scanning that corrupt the disk data then restore it at
	 * the end of the analysis.
	 */
	enter_critical();
	/*
	 * If the disk data is valid, read it into the data buffer.
	 */
	if (flags & SCAN_VALID) {
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, blkno,
		    blkcnt, (caddr_t)cur_buf, driver_flags, xfercntp);
		if (status)
			goto bad;
	}
	/*
	 * If we are doing pattern testing, write and read the pattern
	 * from the pattern buffer.
	 */
	if (flags & SCAN_PATTERN) {
		/*
		 * If the disk data was valid, mark it corrupt so we know
		 * to restore it later.
		 */
		if (flags & SCAN_VALID)
			corrupt++;
		/*
		 * Only write if we're not on the read pass of SCAN_PURGE.
		 */
		if (!(flags & SCAN_PURGE_READ_PASS)) {
			status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file, blkno,
			    blkcnt, (caddr_t)pattern_buf, driver_flags,
			    xfercntp);
			if (status)
			    goto bad;
		}
		/*
		 * Only read if we are on the read pass of SCAN_PURGE, if we
		 * are purging.
		 */
		if ((!(flags & SCAN_PURGE)) || (flags & SCAN_PURGE_READ_PASS)) {
			status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, blkno,
			    blkcnt, (caddr_t)pattern_buf, driver_flags,
			    xfercntp);
			if (status)
			    goto bad;
		}
	}
	/*
	 * If we are doing a data compare, make sure the pattern
	 * came back intact.
	 * Only compare if we are on the read pass of SCAN_PURGE, or
	 * we wrote random data instead of the expected data pattern.
	 */
	if ((flags & SCAN_COMPARE) || (flags & SCAN_PURGE_READ_PASS)) {
		for (i = nints, ptr = (uint_t *)pattern_buf; i; i--)
			if (*ptr++ != data) {
				err_print("Data miscompare error (expecting ");
				err_print("0x%x, got 0x%x) at ", data,
					*((int *)((int *)pattern_buf +
					(nints - i))));
				pr_dblock(err_print, blkno);
				err_print(", offset = 0x%llx.\n",
					(nints - i) * sizeof (int));
				goto bad;
			}
	}
	/*
	 * If we are supposed to write data out, do so.
	 */
	if (flags & SCAN_WRITE) {
		status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file, blkno,
		    blkcnt, (caddr_t)cur_buf, driver_flags, xfercntp);
		if (status)
			goto bad;
	}
	exit_critical();
	/*
	 * No errors occurred, return ok.
	 */
	return (0);
bad:
	/*
	 * There was an error.  If the data was corrupted, we write it
	 * out from the data buffer to restore it.
	 */
	if (corrupt) {
		if ((*cur_ops->op_rdwr)(DIR_WRITE, cur_file, blkno,
				blkcnt, (caddr_t)cur_buf, F_NORMAL, xfercntp))
		err_print("Warning: unable to restore original data.\n");
	}
	exit_critical();
	/*
	 * Return the error.
	 */
	return (-1);
}


/*
 * This routine analyzes a set of sectors on the disk. It simply returns
 * an error if a defect is found.  It is called by analyze_blocks().
 * For simplicity, this is done as a separate function instead of
 * making the analyze_block routine complex.
 *
 * This routine implements the 'verify' command.  It writes the disk
 * by writing unique data for each block; after the write pass, it
 * reads the data and verifies for correctness. Note that the entire
 * disk (or the range of disk) is fully written first and then read.
 * This should eliminate any caching effect on the drives.
 */
static int
verify_blocks(int flags,
		diskaddr_t blkno,
		uint_t blkcnt,
		unsigned data,
		int driver_flags,
		int *xfercntp)
{
	int		status, i, nints;
	unsigned	*ptr = (uint_t *)pattern_buf;

	nints = cur_blksz / sizeof (int);

	/*
	 * Initialize the pattern buffer if we are in write pass.
	 * Use the block number itself as data, each block has unique
	 * buffer data that way.
	 */
	if (!(flags & SCAN_VERIFY_READ_PASS)) {
		for (data = blkno; data < blkno + blkcnt; data++) {
			for (i = 0; i < nints; i++) {
				*ptr++ = data;
			}
		}
		ptr = (uint_t *)pattern_buf;
	}

	/*
	 * Only write if we're not on the read pass of SCAN_VERIFY.
	 */
	if (!(flags & SCAN_VERIFY_READ_PASS)) {
		status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file, blkno,
		    blkcnt, (caddr_t)pattern_buf, driver_flags, xfercntp);
		if (status)
			goto bad;
	} else {
		/*
		 * Only read if we are on the read pass of SCAN_VERIFY
		 */
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file, blkno,
		    blkcnt, (caddr_t)pattern_buf, driver_flags, xfercntp);
		if (status)
			goto bad;
		/*
		 * compare and make sure the pattern came back intact.
		 */
		for (data = blkno; data < blkno + blkcnt; data++) {
			for (i = 0; i < nints; i++) {
				if (*ptr++ != data) {
					ptr--;
					err_print("Data miscompare error "
					    "(expecting 0x%x, got 0x%x) at ",
					    data, *ptr);
					pr_dblock(err_print, blkno);
					err_print(", offset = 0x%x.\n",
					    (ptr - (uint_t *)pattern_buf) *
					    sizeof (int));
					goto bad;
				}
			}
		}
	}
	/*
	 * No errors occurred, return ok.
	 */
	return (0);
bad:
	return (-1);
}


static int
handle_error_conditions()
{

	/*
	 * Check if the errno is ENXIO.
	 */
	if (errno == ENXIO) {
		fmt_print("\n\nWarning:Cannot access drive, ");
		fmt_print("aborting surface analysis.\n");
		return (-1);
	}
	/*
	 * check for disk errors
	 */
	switch (disk_error) {
	case DISK_STAT_RESERVED:
	case DISK_STAT_UNAVAILABLE:
		fmt_print("\n\nWarning:Drive may be reserved ");
		fmt_print("or has been removed, ");
		fmt_print("aborting surface analysis.\n");
		return (-1);
	case DISK_STAT_NOTREADY:
		fmt_print("\n\nWarning: Drive not ready, ");
		fmt_print("aborting surface analysis.\n");
		return (-1);
	case DISK_STAT_DATA_PROTECT:
		fmt_print("\n\nWarning: Drive is write protected, ");
		fmt_print("aborting surface analysis.\n");
		return (-1);
	default:
		break;
	}
	return (0);
}
