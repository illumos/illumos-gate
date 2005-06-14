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
/*
 * Copyright 1991-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DEFECT_H
#define	_DEFECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file contains definitions related to the defect list.
 */

extern	struct defect_list work_list;
extern	struct dkbad badmap;

/*
 * This is the structure of the header of a defect list.  It is always
 * the first sector on a track containing a defect list.
 */
struct defectHeader {
	uint_t	magicno;
	int	count;
	int	cksum;
	int	save[125];
};

/*
 * This is the structure of a defect.  Defects are stored on the disk
 * as an array of these structures following the defect header.
 */
struct defect_entry {
	short	cyl;
	short	head;
	short	sect;
	short	nbits;
	int	bfi;
};

/*
 * This is the internal representation of a defect list.  We store
 * the header statically, but dynamically allocate space for the
 * actual defects, since their number may vary.  The flags field is
 * used to keep track of whether the list has been modified.
 */
struct defect_list {
	struct	defectHeader header;
	struct	defect_entry *list;
	int	flags;
};

/*
 * This defines the number of copies of the defect list kept on the disk.
 * They are stored 1/track, starting at track 0 of the second alternate cyl.
 */
#define	LISTCOUNT	2

/*
 * This defines the size (in sectors) of the defect array given the number
 * of defects in the array.  It must be rounded to a sector boundary since
 * that is the atomic disk size.  We make a zero length list use up a
 * sector because it is convenient to have malloc'd space in every
 * non-null list.
 */
#define	LISTSIZE(x)	((x) ? ((x) * sizeof (struct defect_entry) + \
			SECSIZE - 1) / SECSIZE : 1)

/*
 * These defines are the flags for the defect list.
 */
#define	LIST_DIRTY	0x01	/* List needs to be synced */
#define	LIST_RELOAD	0x02	/* Reload list after formatting (SCSI) */
#define	LIST_PGLIST	0x04	/* embedded SCSI - both manufacturer's (P) */
				/* and grown (G) list */

/*
 * Miscellaneous defines.
 */
#define	DEFECT_MAGIC	0x89898989	/* magic no for defect lists */
#define	NO_CHECKSUM	0x1		/* magic no for no checksum in */
					/* defect list */
#define	UNKNOWN		(-1)		/* value used in defect fields */
#define	DEF_PRINTHEADER	" num     cyl     hd     bfi     len     sec     blk\n"

/*
 * This defines the number of copies of the bad block table kept on the
 * disk.  They are stored in the first 5 even sectors on the last track
 * of the disk.  Note: this also defines the number of backup labels,
 * which are kept in the first 5 odd sectors of the appropriate
 * track.
 */
#define	BAD_LISTCNT	5


/*
 * Prototypes for ANSI C compilers
 */
void	read_list(struct defect_list *list);
int	makebfi(struct defect_list *list, struct defect_entry *def);
void	calc_bfi(struct defect_list *list, struct defect_entry *def,
		struct defect_entry *end, int skew);
int	makelsect(struct defect_list *list);
int	checkdefsum(struct defect_list *list, int mode);
void	pr_defect(struct defect_entry *def, int num);
int	sort_defect(struct defect_entry *def, struct defect_list *list);
void	write_deflist(struct defect_list *list);
void	add_ldef(diskaddr_t blkno, struct defect_list *list);
void	add_def(struct defect_entry *def, struct defect_list *list,
		int index);
void	kill_deflist(struct defect_list *list);

#ifdef	__cplusplus
}
#endif

#endif	/* _DEFECT_H */
