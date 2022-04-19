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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This file contains the code to add new disk_type and partition
 * definitions to a format data file.
 */
#include "global.h"

#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <memory.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>

#include "add_definition.h"
#include "misc.h"
#include "partition.h"
#include "menu_command.h"
#include "startup.h"

extern	struct	ctlr_type ctlr_types[];
extern	int	nctypes;

extern	int	errno;

/* Function prototypes */
#ifdef	__STDC__

static void	add_disktype(FILE *fd, struct disk_info *disk_info);
static void	add_partition(FILE *fd, struct disk_info *,
		struct partition_info *);
static int	add_entry(int col, FILE *fd, char *format, ...);

#else	/* __STDC__ */

static void	add_disktype();
static void	add_partition();
static int	add_entry();

#endif	/* __STDC__ */

/*
 * Add new definitions for the current disk/partition to a format data file.
 */
int
add_definition(void)
{
	FILE	*fd;
	char	*filename;
	time_t	clock;
	char	*prompt;
	union {
		int	xfoo;
		char	deflt_str[MAXPATHLEN];
	} x;

	/*
	 * There must be a current disk and partition table
	 */
	if (cur_disk == NULL) {
		err_print("No Current Disk.\n");
		return (0);
	}
	if (cur_dtype == NULL) {
		err_print("Current disk type is not set.\n");
		return (-1);
	}
	if (cur_parts == NULL) {
		err_print("Current partition is not set.\n");
		return (-1);
	}
	/*
	 * If neither the disk definition nor the partition
	 * information has been changed, there's nothing to save.
	 */
	if (cur_dtype->dtype_filename != NULL &&
	    cur_parts->pinfo_filename != NULL) {
		err_print("\
Neither the disk type nor the partitioning has been changed.\n");
		return (-1);
	}
	/*
	 * If saving the partition, and it's unnamed, the user should name
	 * it first.
	 */
	if (cur_parts->pinfo_name == NULL) {
		assert(cur_parts->pinfo_filename == NULL);
		err_print("Please name this partition type before saving it\n");
		return (-1);
	}
	/*
	 * Let the user know what we're doing
	 */
	if (cur_dtype->dtype_filename == NULL &&
	    cur_parts->pinfo_filename == NULL) {
		fmt_print("Saving new disk and partition definitions\n");
	} else if (cur_dtype->dtype_filename == NULL) {
		fmt_print("Saving new disk definition\n");
	} else {
		assert(cur_parts->pinfo_filename == NULL);
		fmt_print("Saving new partition definition\n");
	}
	/*
	 * Ask for the file to which to append the new definitions
	 */
	prompt = "Enter file name";
	(void) strcpy(x.deflt_str, "./format.dat");
	filename = (char *)(uintptr_t)input(FIO_OSTR, prompt,
	    ':', NULL, &x.xfoo, DATA_INPUT);
	assert(filename != NULL);
	/*
	 * Open the file in append mode, or create it, if necessary
	 */
	if ((fd = fopen(filename, "a")) == NULL) {
		err_print("Cannot open `%s' - %s\n", filename,
		    strerror(errno));
		destroy_data(filename);
		return (-1);
	}
	/*
	 * Write a header for the new definitions
	 */
	if ((cur_dtype->dtype_filename == NULL) &&
	    (cur_parts->pinfo_filename == NULL)) {
		(void) fprintf(fd, "#\n# New disk/partition type ");
	} else if (cur_dtype->dtype_filename == NULL) {
		(void) fprintf(fd, "#\n# New disk type ");
	} else {
		(void) fprintf(fd, "#\n# New partition type ");
	}
	(void) time(&clock);
	(void) fprintf(fd, " saved on %s#\n", ctime(&clock));
	/*
	 * Save the new definitions
	 */
	if (cur_dtype->dtype_filename == NULL) {
		add_disktype(fd, cur_disk);
	}
	if (cur_parts->pinfo_filename == NULL) {
		add_partition(fd, cur_disk, cur_parts);
	}
	/*
	 * We're finished.  Clean up
	 */
	(void) fclose(fd);
	destroy_data(filename);
	return (0);
}

/*
 * Add a disk_type definition to the file fd
 */
static void
add_disktype(FILE *fd, struct disk_info *disk_info)
{
	int			col;
	struct disk_type	*disk_type;

	disk_type = disk_info->disk_type;

	(void) fprintf(fd, "disk_type = \"%s\" \\\n",
	    disk_type->dtype_asciilabel);
	col = add_entry(0, fd, " : ctlr = %s",
	    ((disk_info->disk_ctlr)->ctlr_ctype)->ctype_name);

	col = add_entry(col, fd, " : ncyl = %d", disk_type->dtype_ncyl);

	col = add_entry(col, fd, " : acyl = %d", disk_type->dtype_acyl);

	col = add_entry(col, fd, " : pcyl = %d", disk_type->dtype_pcyl);

	col = add_entry(col, fd, " : nhead = %d", disk_type->dtype_nhead);

	if (disk_type->dtype_options & SUP_PHEAD) {
		col = add_entry(col, fd, " : phead = %d",
		    disk_type->dtype_phead);
	}

	col = add_entry(col, fd, " : nsect = %d", disk_type->dtype_nsect);

	if (disk_type->dtype_options & SUP_PSECT) {
		col = add_entry(col, fd, " : psect = %d",
		    disk_type->dtype_psect);
	}

	if (disk_type->dtype_options & SUP_BPT) {
		col = add_entry(col, fd, " : bpt = %d", disk_type->dtype_bpt);
	}

	col = add_entry(col, fd, " : rpm = %d", disk_type->dtype_rpm);

	if (disk_type->dtype_options & SUP_FMTTIME) {
		col = add_entry(col, fd, " : fmt_time = %d",
		    disk_type->dtype_fmt_time);
	}

	if (disk_type->dtype_options & SUP_CYLSKEW) {
		col = add_entry(col, fd, " : cyl_skew = %d",
		    disk_type->dtype_cyl_skew);
	}

	if (disk_type->dtype_options & SUP_TRKSKEW) {
		col = add_entry(col, fd, " : trk_skew = %d",
		    disk_type->dtype_trk_skew);
	}

	if (disk_type->dtype_options & SUP_TRKS_ZONE) {
		col = add_entry(col, fd, " : trks_zone = %d",
		    disk_type->dtype_trks_zone);
	}

	if (disk_type->dtype_options & SUP_ATRKS) {
		col = add_entry(col, fd, " : atrks = %d",
		    disk_type->dtype_atrks);
	}

	if (disk_type->dtype_options & SUP_ASECT) {
		col = add_entry(col, fd, " : asect = %d",
		    disk_type->dtype_asect);
	}

	if (disk_type->dtype_options & SUP_CACHE) {
		col = add_entry(col, fd, " : cache = %d",
		    disk_type->dtype_cache);
	}

	if (disk_type->dtype_options & SUP_PREFETCH) {
		col = add_entry(col, fd, " : prefetch = %d",
		    disk_type->dtype_threshold);
	}

	if (disk_type->dtype_options & SUP_CACHE_MIN) {
		col = add_entry(col, fd, " : min_prefetch = %d",
		    disk_type->dtype_prefetch_min);
	}

	if (disk_type->dtype_options & SUP_CACHE_MAX) {
		col = add_entry(col, fd, " : max_prefetch = %d",
		    disk_type->dtype_prefetch_max);
	}

	if (disk_type->dtype_options & SUP_BPS) {
		col = add_entry(col, fd, " : bps = %d",
		    disk_type->dtype_bps);
	}

	if (disk_type->dtype_options & SUP_DRTYPE) {
		col = add_entry(col, fd, " : drive_type = %d",
		    disk_type->dtype_dr_type);
	}

	/*
	 * Terminate the last line, and print one blank line
	 */
	(void) fprintf(fd, col == 0 ? "\n" : "\n\n");
}



/*
 * Once we exceed this length, wrap to a new line
 */
#define	MAX_COLUMNS	50

/*
 * Add a partition definition to the file fd
 */
static void
add_partition(FILE *fd, struct disk_info *disk_info,
    struct partition_info *part)
{
	int			col;
	int			i;
	struct disk_type	*disk_type;
	struct dk_map32		*pp;
	char			*s;

#if defined(_SUNOS_VTOC_8)
	struct dk_map2		*pv;

#elif defined(_SUNOS_VTOC_16)
	struct dkl_partition	*pv;

#else
#error No VTOC format defined.
#endif			/* defined (_SUNOS_VTOC_8) */
	struct dk_map2		*dv;

	disk_type = disk_info->disk_type;

	(void) fprintf(fd, "partition = \"%s\" \\\n", part->pinfo_name);
	(void) fprintf(fd, "\t : disk = \"%s\" : ctlr = %s \\\n",
	    disk_type->dtype_asciilabel,
	    ((disk_info->disk_ctlr)->ctlr_ctype)->ctype_name);

	/*
	 * Print the specifications for each useful partition
	 */
	col = 0;
	pp = part->pinfo_map;
	pv = part->vtoc.v_part;
	dv = default_vtoc_map;
	for (i = 0; i < NDKMAP; i++, pp++, pv++, dv++) {
		if (pp->dkl_nblk != 0) {
			col = add_entry(col, fd, " : %c = ",
			    i + PARTITION_BASE);
			if (pv->p_tag != dv->p_tag ||
			    pv->p_flag != dv->p_flag) {
				s = find_string(ptag_choices, (int)pv->p_tag);
				if (s != NULL) {
					col = add_entry(col, fd, " %s,", s);
				}
				s = find_string(pflag_choices, (int)pv->p_flag);
				if (s != NULL) {
					col = add_entry(col, fd, " %s,", s);
				}
			}
			col = add_entry(col, fd, " %d, %d", pp->dkl_cylno,
			    pp->dkl_nblk);
		}
	}

	/*
	 * Terminate the last line, and print one blank line
	 */
	(void) fprintf(fd, col == 0 ? "\n" : "\n\n");
}

/*
 * Add an entry to the file fd.  col is the current starting column.
 * Return the resulting new column position.
 */
/*PRINTFLIKE3*/
static int
add_entry(int col, FILE *fd, char *format, ...)
{
	va_list	ap;
	va_start(ap, format);

	if (col > MAX_COLUMNS) {
		(void) fprintf(fd, " \\\n");
		col = 0;
	}
	if (col == 0) {
		col += fprintf(fd, "\t");
	}
	col += vfprintf(fd, format, ap);
	va_end(ap);

	return (col);
}
