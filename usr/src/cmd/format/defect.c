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
 * This file contains routines that manipulate the defect list.
 */
#include "global.h"
#include <sys/types.h>
#include <sys/param.h>

#if defined(sparc)
#include <sys/hdio.h>
#endif		/* defined(sparc) */

#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/fcntl.h>
#include <string.h>
#include <unistd.h>
#include <memory.h>

#if defined(sparc)
#include <sys/dkbad.h>
#endif		/* defined(sparc) */

#include "misc.h"
#include "param.h"


#if defined(sparc)
/*
 * This structure is the bad block table for the current disk if
 * the disk uses bad-144 defect mapping.
 */
struct	dkbad badmap;
#endif		/* defined(sparc) */

/*
 * This routine reads the defect list off the disk.  It also reads in the
 * bad block table if the disk is a BAD144 type.  The defect list is
 * located on the first 2 tracks of the 2nd alternate cylinder of all
 * disks.  The bad block map is located on the first 5 even sectors of
 * the last track of the last cylinder.
 */
void
read_list(struct defect_list *list)
{
	int	size, head;

#if defined(sparc)
	int sec, status;
	struct	bt_bad *bt;
#endif	/* defined(sparc) */

	assert(!EMBEDDED_SCSI);

	/*
	 * This flags has been introduced only for Sparc ATA IDE.
	 * This indicates that no list manipulation is done in this controller
	 * and hence return without any other checking.
	 */
	if (cur_ctype->ctype_flags & CF_NOWLIST) {
		return;
	}

	/*
	 * Panther's working list is maintained by the controller
	 */
	if (cur_ctype->ctype_flags & CF_WLIST) {
		if (*cur_ops->op_ex_cur != NULL &&
		    ((*cur_ops->op_ex_cur)(list)) == 0) {
			if (list->header.magicno != DEFECT_MAGIC) {
				fmt_print("Defect list BAD\n");
			} else {
				fmt_print("Controller working list found\n");
			}
			return;
		}

		if (*cur_ops->op_ex_man != NULL &&
		    ((*cur_ops->op_ex_man)(list)) == 0) {
			if (list->header.magicno != DEFECT_MAGIC) {
				fmt_print("Defect list BAD\n");
			} else {
				fmt_print("MANUFACTURER's list found\n");
			}
			return;
		}
		fmt_print("No defect list found\n");
		return;
	}

	/*
	 * Loop for each copy of the defect list until we get a good one.
	 */
	for (head = 0; head < LISTCOUNT; head++) {
		/*
		 * Try to read the list header.
		 */
		if ((*cur_ops->op_rdwr)(DIR_READ, cur_file,
		    (diskaddr_t)chs2bn(ncyl + 1, head, 0), 1,
		    (char *)&list->header, NULL), F_NORMAL)
			continue;
		/*
		 * If the magic number is wrong, this copy is corrupt.
		 */
		if (list->header.magicno != DEFECT_MAGIC)
			continue;
		/*
		 * Allocate space for the rest of the list.
		 */
		size = LISTSIZE(list->header.count);
		list->list = (struct defect_entry *)zalloc(size * SECSIZE);
		/*
		 * Try to read in the rest of the list. If there is an
		 * error, or the checksum is wrong, this copy is corrupt.
		 */
		if ((*cur_ops->op_rdwr)(DIR_READ, cur_file,
		    (diskaddr_t)chs2bn(ncyl + 1, head, 1), size,
		    (char *)list->list, F_NORMAL, NULL) ||
		    checkdefsum(list, CK_CHECKSUM)) {
			/*
			 * Destroy the list and go on.
			 */
			kill_deflist(list);
			continue;
		}
		/*
		 * Got a good copy, stop searching.
		 */
		break;
	}
#if defined(sparc)
	if (!(cur_ctlr->ctlr_flags & DKI_BAD144))
		return;
	/*
	 * The disk uses BAD144, read in the bad-block table.
	 */
	for (sec = 0; ((sec < BAD_LISTCNT * 2) && (sec < nsect)); sec += 2) {
		status = (*cur_ops->op_rdwr)(DIR_READ, cur_file,
		    (diskaddr_t)chs2bn(ncyl + acyl - 1, nhead - 1, sec), 1,
		    &badmap, F_NORMAL, NULL);
		if (status)
			continue;
		/*
		 * Do a sanity check on the list read in.  If it passes,
		 * stop searching.
		 */
		if (badmap.bt_mbz != 0)
			continue;
		for (bt = badmap.bt_bad; bt - badmap.bt_bad < NDKBAD; bt++) {
			if (bt->bt_cyl < 0)
				break;
			if (bt->bt_trksec < 0)
				continue;
			head = bt->bt_trksec >> 8;
			if ((bt->bt_cyl >= pcyl) || (head >= nhead) ||
			    ((bt->bt_trksec & 0xff) >= sectors(head))) {
				status = -1;
				break;
			}
		}
		if (status)
			continue;
		return;
	}
	/*
	 * If we couldn't find the bad block table, initialize it to
	 * zero entries.
	 */
	for (bt = badmap.bt_bad; bt - badmap.bt_bad < NDKBAD; bt++)
		bt->bt_cyl = bt->bt_trksec = -1;
	badmap.bt_mbz = badmap.bt_csn = badmap.bt_flag = 0;
#endif		/* defined(sparc) */
}

/*
 * This routine either checks or calculates the checksum for a defect
 * list, depending on the mode parameter. In check mode, it returns
 * whether or not the checksum is correct.
 */
int
checkdefsum(struct defect_list *list, int mode)
{
	register int *lp, i, sum = 0;

	/*
	 * Perform the rolling xor to get what the checksum should be.
	 */
	lp = (int *)list->list;
	for (i = 0; i < (list->header.count *
	    sizeof (struct defect_entry) / sizeof (int)); i++)
		sum ^= *(lp + i);
	/*
	 * If in check mode, return whether header checksum was correct.
	 */
	if (mode == CK_CHECKSUM)
		return (sum != list->header.cksum);
	/*
	 * If in create mode, set the header checksum.
	 */
	else {
		list->header.cksum = sum;
		return (0);
	}
}

/*
 * This routine prints a single defect to stdout in a readable format.
 */
void
pr_defect(struct defect_entry *def, int num)
{

	/*
	 * Make defect numbering look 1 relative.
	 */
	++num;
	/*
	 * Print out common values.
	 */
	fmt_print("%4d%8d%7d", num, def->cyl, def->head);
	/*
	 * The rest of the values may be unknown. If they are, just
	 * print blanks instead.  Also, only print length only if bfi is
	 * known, and assume that a known bfi implies an unknown sect.
	 */
	if (def->bfi != UNKNOWN) {
		fmt_print("%8d", def->bfi);
		if (def->nbits != UNKNOWN)
			fmt_print("%8d", def->nbits);
	} else {
		fmt_print("                ");
		fmt_print("%8d", def->sect);
		fmt_print("%8llu", chs2bn(def->cyl, def->head, def->sect));
	}
	fmt_print("\n");
}

/*
 * This routine calculates where in a defect list a given defect should
 * be sorted. It returns the index that the defect should become.  The
 * algorithm used sorts all bfi based defects by cylinder/head/bfi, and
 * adds all logical sector defects to the end of the list.  This is
 * necessary because the ordering of logical sector defects is significant
 * when sector slipping is employed.
 */
int
sort_defect(struct defect_entry *def, struct defect_list *list)
{
	struct	defect_entry *ptr;

	/*
	 * If it's a logical sector defect, return the entry at the end
	 * of the list.
	 */
	if (def->bfi == UNKNOWN)
		return (list->header.count);
	/*
	 * It's a bfi defect.  Loop through the defect list.
	 */
	for (ptr = list->list; ptr - list->list < list->header.count; ptr++) {
		/*
		 * If we get to a logical sector defect, put this defect
		 * right before it.
		 */
		if (ptr->bfi == UNKNOWN)
			goto found;
		/*
		 * If we get to a defect that is past this one in
		 * cylinder/head/bfi, put this defect right before it.
		 */
		if (def->cyl < ptr->cyl)
			goto found;
		if (def->cyl != ptr->cyl)
			continue;
		if (def->head < ptr->head)
			goto found;
		if (def->head != ptr->head)
			continue;
		if (def->bfi < ptr->bfi)
			goto found;
	}
found:
	/*
	 * Return the index to put the defect at.
	 */
	return (ptr - list->list);
}

/*
 * This routine writes the defect list on the back on the disk.  It also
 * writes the bad block table to disk if bad-144 mapping applies to the
 * current disk.
 */
void
write_deflist(struct defect_list *list)
{
	int	size, head, status;

#if defined(sparc)
	int sec;
	caddr_t	bad_ptr = (caddr_t)&badmap;
#endif			/* defined(sparc) */

	assert(!EMBEDDED_SCSI);

	/*
	 * Sparc ATA IDE.
	 * This indicates that no list manipulation is done in this controller
	 * and hence return without any other checking.
	 */
	if (cur_ctype->ctype_flags & CF_NOWLIST) {
		return;
	}

	/*
	 * Panther's working list is maintained by the controller
	 */
	if (cur_ctype->ctype_flags & CF_WLIST) {
		(*cur_ops->op_wr_cur)(list);
		return;
	}

	/*
	 * If the list is null, there is nothing to write.
	 */
	if (list->list != NULL) {
		/*
		 * calculate how many sectors the defect list will occupy.
		 */
		size = LISTSIZE(list->header.count);
		/*
		 * Loop for each copy of the list to be written.  Write
		 * out the header of the list followed by the data.
		 */
		for (head = 0; head < LISTCOUNT; head++) {
			status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file,
			    (diskaddr_t)chs2bn(ncyl + 1, head, 0), 1,
			    (char *)&list->header, F_NORMAL, NULL);
			if (status) {
				err_print(
"Warning: error saving defect list.\n");
				continue;
			}
			status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file,
			    (diskaddr_t)chs2bn(ncyl + 1, head, 1), size,
			    (char *)list->list, F_NORMAL, NULL);
			if (status)
				err_print(
"Warning: error saving defect list.\n");
		}
	}
	if (!(cur_ctlr->ctlr_flags & DKI_BAD144))
		return;
#if defined(sparc)
	/*
	 * Current disk uses bad-144 mapping.  Loop for each copy of the
	 * bad block table to be written and write it out.
	 */
	for (sec = 0; ((sec < BAD_LISTCNT * 2) && (sec < nsect)); sec += 2) {
		status = (*cur_ops->op_rdwr)(DIR_WRITE, cur_file,
		    (diskaddr_t)chs2bn(ncyl + acyl - 1, nhead - 1, sec), 1,
		    &badmap, F_NORMAL, NULL);
		if (status) {
			err_print(
"Warning: error saving bad block map table.\n");
			continue;
		}
	}
	/*
	 * Execute an ioctl to tell unix about the new bad block table.
	 */
	if (ioctl(cur_file, HDKIOCSBAD, &bad_ptr))
		err_print(
"Warning: error telling SunOS bad block map table.\n");
#endif		/* defined(sparc) */
}

/*
 * This routine adds a logical sector to the given defect list.
 */
void
add_ldef(diskaddr_t blkno, struct defect_list *list)
{
	struct	defect_entry def;
	int	index;


	/*
	 * Calculate the fields for the defect struct.
	 */
	def.cyl = bn2c(blkno);
	def.head = bn2h(blkno);
	def.sect = bn2s(blkno);
	/*
	 * Initialize the unknown fields.
	 */
	def.bfi = def.nbits = UNKNOWN;
	/*
	 * Calculate the index into the list that the defect belongs at.
	 */
	index = sort_defect(&def, list);
	/*
	 * Add the defect to the list.
	 */
	add_def(&def, list, index);
}

/*
 * This routine adds the given defect struct to the defect list at
 * a precalculated index.
 */
void
add_def(struct defect_entry *def, struct defect_list *list, int index)
{
	int	count, i;

	/*
	 * If adding this defect makes the list overflow into another
	 * sector, allocate the necessary space.
	 */
	count = list->header.count;
	if (LISTSIZE(count + 1) > LISTSIZE(count))
		list->list = (struct defect_entry *)rezalloc((void *)list->list,
		    LISTSIZE(count + 1) * SECSIZE);
	/*
	 * Slip all the defects after this one down one slot in the list.
	 */
	for (i = count; i > index; i--)
		*(list->list + i) = *(list->list + i - 1);
	/*
	 * Fill in the created hole with this defect.
	 */
	*(list->list + i) = *def;
	/*
	 * Increment the count and calculate a new checksum.
	 */
	list->header.count++;
	(void) checkdefsum(list, CK_MAKESUM);
}

/*
 * This routine sets the given defect list back to null.
 */
void
kill_deflist(struct defect_list *list)
{

	/*
	 * If it's already null, we're done.
	 */
	if (list->list == NULL)
		return;
	/*
	 * Free the malloc'd space it's using.
	 */
	destroy_data((char *)list->list);
	/*
	 * Mark it as null, and clear any flags.
	 */
	list->list = NULL;
	list->flags = 0;
}
