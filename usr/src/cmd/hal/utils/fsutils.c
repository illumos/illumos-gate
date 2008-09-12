/*
 *
 * fsutils.c : filesystem utilities
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Licensed under the Academic Free License version 2.1
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <sys/types.h>
#include <sys/scsi/impl/uscsi.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/dkio.h>
#include <libintl.h>
#include <sys/dktp/fdisk.h>
#include <sys/fs/pc_label.h>

#include <libhal.h>
#include "fsutils.h"

/*
 * Separates dos notation device spec into device and drive number
 */
boolean_t
dos_to_dev(char *path, char **devpath, int *num)
{
	char *p;

	if ((p = strrchr(path, ':')) == NULL) {
		return (B_FALSE);
	}
	if ((*num = atoi(p + 1)) == 0) {
		return (B_FALSE);
	}
	p[0] = '\0';
	*devpath = strdup(path);
	p[0] = ':';
	return (*devpath != NULL);
}

char *
get_slice_name(char *devlink)
{
	char	*part, *slice, *disk;
	char	*s = NULL;
	char	*p;

	if ((p = strstr(devlink, "/lofi/")) != 0) {
		return (p + sizeof ("/lofi/") - 1);
	}

	part = strrchr(devlink, 'p');
	slice = strrchr(devlink, 's');
	disk = strrchr(devlink, 'd');

	if ((part != NULL) && (part > slice) && (part > disk)) {
		s = part;
	} else if ((slice != NULL) && (slice > disk)) {
		s = slice;
	} else {
		s = disk;
	}
	if ((s != NULL) && isdigit(s[1])) {
		return (s);
	} else {
		return ("");
	}
}

boolean_t
is_dos_drive(uchar_t type)
{
	return ((type == DOSOS12) || (type == DOSOS16) ||
	    (type == DOSHUGE) || (type == FDISK_WINDOWS) ||
	    (type == FDISK_EXT_WIN) || (type == FDISK_FAT95) ||
	    (type == DIAGPART));
}

boolean_t
is_dos_extended(uchar_t id)
{
	return ((id == EXTDOS) || (id == FDISK_EXTLBA));
}

struct part_find_s {
	int	num;
	int	count;
	int	systid;
	int	r_systid;
	uint_t	r_relsect;
	uint_t	r_numsect;
};

enum { WALK_CONTINUE, WALK_TERMINATE };

/*
 * Walk partition tables and invoke a callback for each.
 */
static void
walk_partitions(int fd, int startsec, uint_t secsz,
    int (*f)(void *, int, uint_t, uint_t), void *arg)
{
	uint32_t buf[1024/4];
	int bufsize = 1024;
	struct mboot *mboot = (struct mboot *)&buf[0];
	struct ipart ipart[FD_NUMPART];
	uint_t sec = startsec;
	uint_t lastsec = sec + 1;
	uint_t relsect;
	int ext = 0;
	int systid;
	boolean_t valid;
	int i;

	while (sec != lastsec) {
		if (pread(fd, buf, bufsize, (off_t)sec * secsz) != bufsize) {
			break;
		}
		lastsec = sec;
		if (ltohs(mboot->signature) != MBB_MAGIC) {
			break;
		}
		bcopy(mboot->parts, ipart, FD_NUMPART * sizeof (struct ipart));

		for (i = 0; i < FD_NUMPART; i++) {
			systid = ipart[i].systid;
			relsect = sec + ltohi(ipart[i].relsect);
			if (systid == 0) {
				continue;
			}
			valid = B_TRUE;
			if (is_dos_extended(systid) && (sec == lastsec)) {
				sec = startsec + ltohi(ipart[i].relsect);
				if (ext++ == 0) {
					relsect = startsec = sec;
				} else {
					valid = B_FALSE;
				}
			}
			if (valid && f(arg, ipart[i].systid, relsect,
			    ltohi(ipart[i].numsect)) == WALK_TERMINATE) {
				return;
			}
		}
	}
}

static int
find_dos_drive_cb(void *arg, int systid, uint_t relsect, uint_t numsect)
{
	struct part_find_s *p = arg;

	if (is_dos_drive(systid)) {
		if (++p->count == p->num) {
			p->r_relsect = relsect;
			p->r_numsect = numsect;
			p->r_systid = systid;
			return (WALK_TERMINATE);
		}
	}

	return (WALK_CONTINUE);
}

/*
 * Given a dos drive number, return its relative sector number,
 * number of sectors in partition and the system id.
 */
boolean_t
find_dos_drive(int fd, int num, uint_t secsz, off_t *offset)
{
	struct part_find_s p = { 0, 0, 0, 0, 0, 0 };

	p.num = num;

	if (num > 0) {
		walk_partitions(fd, 0, secsz, find_dos_drive_cb, &p);
		if (p.count == num) {
			*offset = (off_t)p.r_relsect * secsz;
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static int
get_num_dos_drives_cb(void *arg, int systid, uint_t relsect, uint_t numsect)
{
	if (is_dos_drive(systid)) {
		(*(int *)arg)++;
	}
	return (WALK_CONTINUE);
}

int
get_num_dos_drives(int fd, uint_t secsz)
{
	int count = 0;

	walk_partitions(fd, 0, secsz, get_num_dos_drives_cb, &count);

	return (count);
}

/*
 * Return true if all non-empty slices in vtoc have identical start/size and
 * are tagged backup/entire disk.
 */
boolean_t
vtoc_one_slice_entire_disk(struct extvtoc *vtoc)
{
	int		i;
	struct extpartition *p;
	diskaddr_t	prev_start;
	diskaddr_t	prev_size;

	for (i = 0; i < vtoc->v_nparts; i++) {
		p = &vtoc->v_part[i];
		if (p->p_size == 0) {
			continue;
		}
		if ((p->p_tag != V_BACKUP) && ((p->p_tag != V_UNASSIGNED))) {
			return (B_FALSE);
		}
		if ((i > 0) &&
		    ((p->p_start != prev_start) || (p->p_size != prev_size))) {
			return (B_FALSE);
		}
		prev_start = p->p_start;
		prev_size = p->p_size;
	}

	return (B_TRUE);
}
