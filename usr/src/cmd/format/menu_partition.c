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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains functions to implement the partition menu commands.
 */
#include "global.h"
#include <stdlib.h>
#include <string.h>

#include "partition.h"
#include "menu_partition.h"
#include "menu_command.h"
#include "misc.h"
#include "param.h"

/* Function prototypes for ANSI C Compilers */
static void	nspaces(int);
static int	ndigits(uint64_t);

/*
 * This routine implements the 'a' command.  It changes the 'a' partition.
 */
int
p_apart(void)
{

	change_partition(0);
	return (0);
}

/*
 * This routine implements the 'b' command.  It changes the 'b' partition.
 */
int
p_bpart(void)
{

	change_partition(1);
	return (0);
}

/*
 * This routine implements the 'c' command.  It changes the 'c' partition.
 */
int
p_cpart(void)
{

	change_partition(2);
	return (0);
}

/*
 * This routine implements the 'd' command.  It changes the 'd' partition.
 */
int
p_dpart(void)
{

	change_partition(3);
	return (0);
}

/*
 * This routine implements the 'e' command.  It changes the 'e' partition.
 */
int
p_epart(void)
{

	change_partition(4);
	return (0);
}

/*
 * This routine implements the 'f' command.  It changes the 'f' partition.
 */
int
p_fpart(void)
{

	change_partition(5);
	return (0);
}

/*
 * This routine implements the 'g' command.  It changes the 'g' partition.
 */
int
p_gpart(void)
{

	change_partition(6);
	return (0);
}

/*
 * This routine implements the 'h' command.  It changes the 'h' partition.
 */
int
p_hpart(void)
{

	change_partition(7);
	return (0);
}

/*
 * This routine implements the 'i' command. It is valid only for EFI
 * labeled disks. This can be used only in expert mode.
 */
int
p_ipart(void)
{
	change_partition(8);
	return (0);
}

#if defined(i386)
/*
 * This routine implements the 'j' command.  It changes the 'j' partition.
 */
int
p_jpart(void)
{

	change_partition(9);
	return (0);
}
#endif	/* defined(i386) */

int
p_expand(void)
{
	uint64_t delta;
	uint_t nparts;
	struct dk_gpt *efi_label = cur_parts->etoc;

	if (cur_parts->etoc->efi_altern_lba == 1 ||
	    (cur_parts->etoc->efi_altern_lba >=
	    cur_parts->etoc->efi_last_lba)) {
		err_print("Warning: No expanded capacity is found.\n");
		return (0);
	}

	delta = efi_label->efi_last_lba - efi_label->efi_altern_lba;
	nparts = efi_label->efi_nparts;

	enter_critical();
	efi_label->efi_parts[nparts - 1].p_start += delta;
	efi_label->efi_last_u_lba += delta;
	efi_label->efi_altern_lba = cur_parts->etoc->efi_last_lba;
	exit_critical();

	fmt_print("The expanded capacity is added to the unallocated space.\n");
	return (0);
}

/*
 * This routine implements the 'select' command.  It allows the user
 * to make a pre-defined partition map the current map.
 */
int
p_select(void)
{
	struct partition_info	*pptr, *parts;
	u_ioparam_t		ioparam;
	int			i, index, deflt, *defltptr = NULL;
	blkaddr_t		b_cylno;
#if defined(i386)
	blkaddr_t		cyl_offset;
#endif

	parts = cur_dtype->dtype_plist;
	/*
	 * If there are no pre-defined maps for this disk type, it's
	 * an error.
	 */
	if (parts == NULL) {
		err_print("No defined partition tables.\n");
		return (-1);
	}

	/*
	 * Loop through the pre-defined maps and list them by name.  If
	 * the current map is one of them, make it the default.  If any
	 * the maps are unnamed, label them as such.
	 */
	for (i = 0, pptr = parts; pptr != NULL; pptr = pptr->pinfo_next) {
		if (cur_parts == pptr) {
			deflt = i;
			defltptr = &deflt;
		}
		if (pptr->pinfo_name == NULL)
			fmt_print("        %d. unnamed\n", i++);
		else
			fmt_print("        %d. %s\n", i++, pptr->pinfo_name);
	}
	ioparam.io_bounds.lower = 0;
	ioparam.io_bounds.upper = i - 1;
	/*
	 * Ask which map should be made current.
	 */
	index = input(FIO_INT, "Specify table (enter its number)", ':',
	    &ioparam, defltptr, DATA_INPUT);
	for (i = 0, pptr = parts; i < index; i++, pptr = pptr->pinfo_next)
		;
	if (cur_label == L_TYPE_EFI) {
		enter_critical();
		cur_disk->disk_parts = cur_parts = pptr;
		exit_critical();
		fmt_print("\n");
		return (0);
	}
#if defined(i386)
	/*
	 * Adjust for the boot and alternate sectors partition - assuming that
	 * the alternate sectors partition physical location follows
	 * immediately the boot partition and partition sizes are
	 * expressed in multiple of cylinder size.
	 */
	cyl_offset = pptr->pinfo_map[I_PARTITION].dkl_cylno + 1;
	if (pptr->pinfo_map[J_PARTITION].dkl_nblk != 0) {
		cyl_offset = pptr->pinfo_map[J_PARTITION].dkl_cylno +
		    ((pptr->pinfo_map[J_PARTITION].dkl_nblk +
		    (spc() - 1)) / spc());
	}
#else	/* !defined(i386) */

	b_cylno = 0;

#endif	/* defined(i386) */

	/*
	 * Before we blow the current map away, do some limits checking.
	 */
	for (i = 0; i < NDKMAP; i++)  {

#if defined(i386)
		if (i == I_PARTITION || i == J_PARTITION || i == C_PARTITION) {
			b_cylno = 0;
		} else if (pptr->pinfo_map[i].dkl_nblk == 0) {
			/*
			 * Always accept starting cyl 0 if the size is 0 also
			 */
			b_cylno = 0;
		} else {
			b_cylno = cyl_offset;
		}
#endif		/* defined(i386) */
		if (pptr->pinfo_map[i].dkl_cylno < b_cylno ||
		    pptr->pinfo_map[i].dkl_cylno > (ncyl-1)) {
			err_print("partition %c: starting cylinder %d is out "
			    "of range\n", (PARTITION_BASE + i),
			    pptr->pinfo_map[i].dkl_cylno);
			return (0);
		}
		if (pptr->pinfo_map[i].dkl_nblk > ((ncyl -
		    pptr->pinfo_map[i].dkl_cylno) * spc())) {
			err_print(
			    "partition %c: specified # of blocks, %u, "
			    "is out of range\n",
			    (PARTITION_BASE+i),
			    pptr->pinfo_map[i].dkl_nblk);
			return (0);
		}
	}
	/*
	 * Lock out interrupts so the lists don't get mangled.
	 */
	enter_critical();
	/*
	 * If the old current map is unnamed, delete it.
	 */
	if (cur_parts != NULL && cur_parts != pptr &&
	    cur_parts->pinfo_name == NULL)
		delete_partition(cur_parts);
	/*
	 * Make the selected map current.
	 */
	cur_disk->disk_parts = cur_parts = pptr;

#if defined(_SUNOS_VTOC_16)
	for (i = 0; i < NDKMAP; i++)  {
		cur_parts->vtoc.v_part[i].p_start =
		    (blkaddr_t)(cur_parts->pinfo_map[i].dkl_cylno *
		    (nhead * nsect));
		cur_parts->vtoc.v_part[i].p_size =
		    (blkaddr_t)cur_parts->pinfo_map[i].dkl_nblk;
	}
#endif	/* defined(_SUNOS_VTOC_16) */

	exit_critical();
	fmt_print("\n");
	return (0);
}

/*
 * This routine implements the 'name' command.  It allows the user
 * to name the current partition map.  If the map was already named,
 * the name is changed.  Once a map is named, the values of the partitions
 * cannot be changed.  Attempts to change them will cause another map
 * to be created.
 */
int
p_name(void)
{
	char	*name;

	/*
	 * check if there exists a partition table for the disk.
	 */
	if (cur_parts == NULL) {
		err_print("Current Disk has no partition table.\n");
		return (-1);
	}


	/*
	 * Ask for the name.  Note that the input routine will malloc
	 * space for the name since we are using the OSTR input type.
	 */
	name = (char *)(uintptr_t)input(FIO_OSTR,
	    "Enter table name (remember quotes)",
	    ':', (u_ioparam_t *)NULL, (int *)NULL, DATA_INPUT);
	/*
	 * Lock out interrupts.
	 */
	enter_critical();
	/*
	 * If it was already named, destroy the old name.
	 */
	if (cur_parts->pinfo_name != NULL)
		destroy_data(cur_parts->pinfo_name);
	/*
	 * Set the name.
	 */
	cur_parts->pinfo_name = name;
	exit_critical();
	fmt_print("\n");
	return (0);
}


/*
 * This routine implements the 'print' command.  It lists the values
 * for all the partitions in the current partition map.
 */
int
p_print(void)
{
	/*
	 * check if there exists a partition table for the disk.
	 */
	if (cur_parts == NULL) {
		err_print("Current Disk has no partition table.\n");
		return (-1);
	}

	/*
	 * Print the volume name, if it appears to be set
	 */
	if (chk_volname(cur_disk)) {
		fmt_print("Volume:  ");
		print_volname(cur_disk);
		fmt_print("\n");
	}
	/*
	 * Print the name of the current map.
	 */
	if ((cur_parts->pinfo_name != NULL) && (cur_label == L_TYPE_SOLARIS)) {
		fmt_print("Current partition table (%s):\n",
		    cur_parts->pinfo_name);
		fmt_print("Total disk cylinders available: %d + %d "
		    "(reserved cylinders)\n\n", ncyl, acyl);
	} else if (cur_label == L_TYPE_SOLARIS) {
		fmt_print("Current partition table (unnamed):\n");
		fmt_print("Total disk cylinders available: %d + %d "
		    "(reserved cylinders)\n\n", ncyl, acyl);
	} else if (cur_label == L_TYPE_EFI) {
		unsigned reserved;

		reserved = efi_reserved_sectors(cur_parts->etoc);
		fmt_print("Current partition table (%s):\n",
		    cur_parts->pinfo_name != NULL ?
		    cur_parts->pinfo_name : "unnamed");
		fmt_print("Total disk sectors available: %llu + %u "
		    "(reserved sectors)\n\n",
		    cur_parts->etoc->efi_last_u_lba - reserved -
		    cur_parts->etoc->efi_first_u_lba + 1, reserved);
	}


	/*
	 * Print the partition map itself
	 */
	print_map(cur_parts);
	return (0);
}


/*
 * Print a partition map
 */
void
print_map(struct partition_info *map)
{
	int	i;
	int	want_header;
	struct	dk_gpt *vtoc64;

	if (cur_label == L_TYPE_EFI) {
		vtoc64 = map->etoc;
		want_header = 1;
		for (i = 0; i < vtoc64->efi_nparts; i++) {
		/*
		 * we want to print partitions above 7 in expert mode only
		 * or if the partition is reserved
		 */
			if (i >= 7 && !expert_mode &&
			    ((int)vtoc64->efi_parts[i].p_tag !=
			    V_RESERVED)) {
				continue;
			}

			print_efi_partition(vtoc64, i, want_header);
			want_header = 0;
		}
		fmt_print("\n");
		return;
	}
	/*
	 * Loop through each partition, printing the header
	 * the first time.
	 */
	want_header = 1;
	for (i = 0; i < NDKMAP; i++) {
		if (i > 9) {
			break;
		}
		print_partition(map, i, want_header);
		want_header = 0;
	}

	fmt_print("\n");
}

/*
 * Print out one line of partition information,
 * with optional header for EFI type disks.
 */
/*ARGSUSED*/
void
print_efi_partition(struct dk_gpt *map, int partnum, int want_header)
{
	int		ncyl2_digits = 0;
	float		scaled;
	char		*s;
	uint64_t	secsize;

	ncyl2_digits = ndigits(map->efi_last_u_lba);
	if (want_header) {
		fmt_print("Part      ");
		fmt_print("Tag    Flag     ");
		fmt_print("First Sector");
		nspaces(ncyl2_digits);
		fmt_print("Size");
		nspaces(ncyl2_digits);
		fmt_print("Last Sector\n");
	}

	fmt_print("  %d ", partnum);
	s = find_string(ptag_choices, (int)map->efi_parts[partnum].p_tag);
	if (s == (char *)NULL)
		s = "-";
	nspaces(10 - (int)strlen(s));
	fmt_print("%s", s);

	s = find_string(pflag_choices, (int)map->efi_parts[partnum].p_flag);
	if (s == (char *)NULL)
		s = "-";
	nspaces(6 - (int)strlen(s));
	fmt_print("%s", s);

	nspaces(2);

	secsize = map->efi_parts[partnum].p_size;
	if (secsize == 0) {
		fmt_print("%16llu", map->efi_parts[partnum].p_start);
		nspaces(ncyl2_digits);
		fmt_print("  0     ");
	} else {
		fmt_print("%16llu", map->efi_parts[partnum].p_start);
		scaled = bn2mb(secsize);
		nspaces(ncyl2_digits - 5);
		if (scaled >= (float)1024.0 * 1024) {
			fmt_print("%8.2fTB", scaled/((float)1024.0 * 1024));
		} else if (scaled >= (float)1024.0) {
			fmt_print("%8.2fGB", scaled/(float)1024.0);
		} else {
			fmt_print("%8.2fMB", scaled);
		}
	}
	nspaces(ncyl2_digits);
	if ((map->efi_parts[partnum].p_start + secsize - 1) == UINT_MAX64) {
		fmt_print(" 0    \n");
	} else {
		fmt_print(" %llu    \n",
		    map->efi_parts[partnum].p_start + secsize - 1);
	}
}

/*
 * Print out one line of partition information,
 * with optional header.
 */
/*ARGSUSED*/
void
print_partition(struct partition_info *pinfo, int partnum, int want_header)
{
	int		i;
	blkaddr_t	nblks;
	int		cyl1;
	int		cyl2;
	float		scaled;
	int		maxcyl2;
	int		ncyl2_digits;
	char		*s;
	blkaddr_t	maxnblks = 0;
	blkaddr_t	len;

	/*
	 * To align things nicely, we need to know the maximum
	 * width of the number of cylinders field.
	 */
	maxcyl2 = 0;
	for (i = 0; i < NDKMAP; i++) {
		nblks	= (uint_t)pinfo->pinfo_map[i].dkl_nblk;
		cyl1	= pinfo->pinfo_map[i].dkl_cylno;
		cyl2	= cyl1 + (nblks / spc()) - 1;
		if (nblks > 0) {
			maxcyl2 = max(cyl2, maxcyl2);
			maxnblks = max(nblks, maxnblks);
		}
	}
	/*
	 * Get the number of digits required
	 */
	ncyl2_digits = ndigits(maxcyl2);

	/*
	 * Print the header, if necessary
	 */
	if (want_header) {
		fmt_print("Part      ");
		fmt_print("Tag    Flag     ");
		fmt_print("Cylinders");
		nspaces(ncyl2_digits);
		fmt_print("    Size            Blocks\n");
	}

	/*
	 * Print the partition information
	 */
	nblks	= pinfo->pinfo_map[partnum].dkl_nblk;
	cyl1	= pinfo->pinfo_map[partnum].dkl_cylno;
	cyl2	= cyl1 + (nblks / spc()) - 1;

	fmt_print("  %x ", partnum);

	/*
	 * Print the partition tag.  If invalid, print -
	 */
	s = find_string(ptag_choices, (int)pinfo->vtoc.v_part[partnum].p_tag);
	if (s == (char *)NULL)
		s = "-";
	nspaces(10 - (int)strlen(s));
	fmt_print("%s", s);

	/*
	 * Print the partition flag.  If invalid print -
	 */
	s = find_string(pflag_choices, (int)pinfo->vtoc.v_part[partnum].p_flag);
	if (s == NULL)
		s = "-";
	nspaces(6 - (int)strlen(s));
	fmt_print("%s", s);

	nspaces(2);

	if (nblks == 0) {
		fmt_print("%6d      ", cyl1);
		nspaces(ncyl2_digits);
		fmt_print("     0         ");
	} else {
		fmt_print("%6d - ", cyl1);
		nspaces(ncyl2_digits - ndigits(cyl2));
		fmt_print("%d    ", cyl2);
		scaled = bn2mb(nblks);
		if (scaled > (float)1024.0 * 1024.0) {
			fmt_print("%8.2fTB    ",
			    scaled/((float)1024.0 * 1024.0));
		} else if (scaled > (float)1024.0) {
			fmt_print("%8.2fGB    ", scaled/(float)1024.0);
		} else {
			fmt_print("%8.2fMB    ", scaled);
		}
	}
	fmt_print("(");
	pr_dblock(fmt_print, nblks);
	fmt_print(")");

	nspaces(ndigits(maxnblks/spc()) - ndigits(nblks/spc()));
	/*
	 * Allocates size of the printf format string.
	 * ndigits(ndigits(maxblks)) gives the byte size of
	 * the printf width field for maxnblks.
	 */
	len = strlen(" %") + ndigits(ndigits(maxnblks)) + strlen("d\n") + 1;
	s = zalloc(len);
	(void) snprintf(s, len, "%s%u%s", " %", ndigits(maxnblks), "u\n");
	fmt_print(s, nblks);
	(void) free(s);
}


/*
 * Return true if a disk has a volume name
 */
int
chk_volname(struct disk_info *disk)
{
	return (disk->v_volume[0] != 0);
}


/*
 * Print the volume name, if it appears to be set
 */
void
print_volname(struct disk_info *disk)
{
	int	i;
	char	*p;

	p = disk->v_volume;
	for (i = 0; i < LEN_DKL_VVOL; i++, p++) {
		if (*p == 0)
			break;
		fmt_print("%c", *p);
	}
}


/*
 * Print a number of spaces
 */
static void
nspaces(int n)
{
	while (n-- > 0)
		fmt_print(" ");
}

/*
 * Return the number of digits required to print a number
 */
static int
ndigits(uint64_t n)
{
	int	i;

	i = 0;
	while (n > 0) {
		n /= 10;
		i++;
	}

	return (i == 0 ? 1 : i);
}
