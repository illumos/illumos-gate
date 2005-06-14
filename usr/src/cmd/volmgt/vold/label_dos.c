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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include	<stdio.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<sys/types.h>
#include	<fcntl.h>
#include	<ctype.h>
#include	<string.h>
#include	<sys/dktp/fdisk.h>
#include	<sys/vtoc.h>
#include	<sys/dklabel.h>
#include	<sys/fs/pc_label.h>
#include	<sys/fs/pc_fs.h>
#include	<sys/fs/pc_dir.h>

#include	"vold.h"

extern char	*laread_res_to_str(enum laread_res);
extern ulong_t  unique_key(char *, char *);

/*
 * NOTE: most DOS-related constants come from <sys/fs/pc_*.h>
 */

#define	DOS_NAMELEN_REG		PCFNAMESIZE
#define	DOS_NAMELEN_EXT		PCFEXTSIZE
#define	DOS_NAMELEN		(DOS_NAMELEN_REG + DOS_NAMELEN_EXT)
#define	DOS_VERSION		2

/*
 * Number of bytes in the "volume header" located in sector
 * 0 on a DOS disk.
 */
#define	DOS_LABLEN	0x3e
/*
 * Offset in the volume header of the pseudo-random id number.
 * This is only valid for DOS version 4.0 and later.
 */
#define	DOS_ID_OFF	0x27

/*
 * Offset in the volume header of the ascii name of the volume.
 * This is only valid for dos 4.0 and later.
 */
#define	DOS_NAME_OFF	0x2b

/*
 * location and length of the OEM name and version
 */
#define	DOS_OEM_NAME	0x3
#define	DOS_OEM_LENGTH	8
/*
 * OEM name of NEC 2.0 floppies
 */
#define	DOS_OEM_NEC2	"NEC 2.00"

#define	NUMBUFLEN	512
#define	DOS_READ_LENGTH  	(PC_SECSIZE * 4)
#define	DOS_READ_LENGTH_MASK	(DOS_READ_LENGTH - 1)

/*
 * Values for dos_type
 */

#define	DOS_UNKNOWN	0
#define	DOS_CDROM	1
#define	DOS_MO		2
#define	DOS_FLOPPY	3
#define	DOS_DISK	4
#define	DOS_PCMEM	5

struct dos_label {
	ushort_t	dos_version;	/* version of this structure for db */
	ulong_t	dos_lcrc;	/* crc of label */
	ulong_t	dos_magic;	/* pseudo rand # from label */
	uchar_t	dos_nparts;	/* number of partitions */
	ulong_t	dos_parts;	/* partition mask */
	uchar_t	dos_type;	/* type of media */
	uchar_t	dos_volname[DOS_NAMELEN+1];	/* name from label */
};

static char		*dos_key(label *);
static bool_t		dos_compare(label *, label *);
static enum laread_res	dos_read(int, label *, struct devs *dp);
static void		dos_setup(vol_t *);
static void		dos_xdr(label *, enum xdr_op, void **);
#define	DOS_LABEL_SIZE	sizeof (struct dos_label)
static struct label_loc	dos_labelloc = { 0, DOS_LABLEN };

static struct labsw	doslabsw = {
	dos_key, 	/* l_key */
	dos_compare, 	/* l_compare */
	dos_read, 	/* l_read */
	NULL, 		/* l_write */
	dos_setup, 	/* l_setup */
	dos_xdr, 	/* l_xdr */
	DOS_LABEL_SIZE,	/* l_size */
	DOS_LABEL_SIZE,	/* l_xdrsize */
	PCFS_LTYPE,	/* l_ident */
	1,		/* l_nll */
	&dos_labelloc,	/* l_ll */
};

/*
 * Forward declarations of private functions
 */
static void		dirname_to_volname(char *volname,
					struct pcdir *dir_entry);
static bool_t		dos_filename_char(char c);
static int		dos_label_char(int c);
static enum laread_res	find_dos_label(int fd, struct devs *dp, off_t offset,
					uchar_t *label_bufferp);
static char		*find_dos_volname(int fd, char *boot_bufferp);
static bool_t		find_fdisk_partition(int fd, int *partition_numberp,
						off_t *offsetp);
static void		read_dos_label(int fd, uchar_t *label_bufferp,
					label *la);

/*
 * Definitions of the functions that implement the label interface.
 */

bool_t
label_init(void)
{
	label_new(&doslabsw);
	return (TRUE);
}

static char *
dos_key(label *la)
{
	char			buf[NUMBUFLEN];
	struct dos_label	*labelp;

	labelp = (struct dos_label *)la->l_label;
	(void) sprintf(buf, "0x%lx", labelp->dos_magic);
	return (strdup(buf));
}


static bool_t
dos_compare(label *la1, label *la2)
{
	struct dos_label	*label1p;
	struct dos_label	*label2p;
	bool_t			match;

	label1p = (struct dos_label *)la1->l_label;
	label2p = (struct dos_label *)la2->l_label;

	if ((label1p->dos_lcrc != label2p->dos_lcrc) ||
	    (label1p->dos_magic != label2p->dos_magic)) {
		match = FALSE;
	} else {
		match = TRUE;
	}
	return (match);
}


static enum laread_res
dos_read(int fd, label *la, struct devs *dp)
{
	uchar_t			label_bufferp[DOS_READ_LENGTH];
	struct dos_label	*labelp;
	int			partition_number;
	off_t			offset;
	enum laread_res		result;
	char			*type = dp->dp_dsw->d_mtype;

	debug(1, "dos_read: entering, fd = %d\n", fd);

	offset = 0L;
	result = find_dos_label(fd, dp, offset, label_bufferp);
	if (result == L_FOUND) {
		read_dos_label(fd, label_bufferp, la);
	} else if (result == L_UNRECOG) {
		if (find_fdisk_partition(fd, &partition_number, &offset)) {
			result = find_dos_label(fd, dp, offset, label_bufferp);
			if (result == L_FOUND) {
				read_dos_label(fd, label_bufferp, la);
			}
		}
	}
	if (result == L_FOUND) {
		labelp = (struct dos_label *)la->l_label;
		labelp->dos_nparts = (uchar_t)1;
		/*
		 * For the time being, until we can overcome
		 * the volume code's inability to handle multiple
		 * DOS partitions, we set the partition mask for
		 * the volume to indicate that only the default
		 * partition is mountable.
		 */
#ifdef i386
		labelp->dos_parts = (ulong_t)1; /* P0 on Intel */
#else
		labelp->dos_parts = (ulong_t)4; /* S2 on SPARC */
#endif
		if (strcmp(type, FLOPPY_MTYPE) == 0) {
			labelp->dos_type = DOS_FLOPPY;
		} else if (strcmp(type, MO_MTYPE) == 0) {
			labelp->dos_type = DOS_MO;
		} else if (strcmp(type, RMDISK_MTYPE) == 0) {
			labelp->dos_type = DOS_DISK;
		} else if (strcmp(type, CDROM_MTYPE) == 0) {
			labelp->dos_type = DOS_CDROM;
		} else if (strcmp(type, PCMEM_MTYPE) == 0) {
			labelp->dos_type = DOS_PCMEM;
		} else {
			labelp->dos_type = DOS_UNKNOWN;
		}
	}
	debug(1, "dos_read: returning %s\n", laread_res_to_str(result));
	return (result);
}


static void
dos_setup(vol_t *v)
{
	struct dos_label	*labelp;
	char			unnamed_buf[MAXNAMELEN+1];

	labelp = (struct dos_label *)v->v_label.l_label;
	if (v->v_mtype == NULL) {
		switch (labelp->dos_type) {
		case DOS_FLOPPY:
			v->v_mtype = FLOPPY_MTYPE;
			break;
		case DOS_CDROM:
			v->v_mtype = CDROM_MTYPE;
			break;
		case DOS_MO:
			v->v_mtype = MO_MTYPE;
			break;
		case DOS_DISK:
			v->v_mtype = RMDISK_MTYPE;
			break;
		case DOS_PCMEM:
			v->v_mtype = PCMEM_MTYPE;
			break;
		case DOS_UNKNOWN:
		default:
			v->v_mtype = OTHER_MTYPE;
		}
	}
	if (labelp->dos_volname[0] != NULLC) {
		v->v_obj.o_name = makename((char *)(labelp->dos_volname),
		    DOS_NAMELEN);
		if (v->v_obj.o_name[0] == NULLC) {
			free(v->v_obj.o_name);
			(void) sprintf(unnamed_buf, "%s%s", UNNAMED_PREFIX,
					v->v_mtype);
			v->v_obj.o_name = strdup(unnamed_buf);
		}
	} else {
		(void) sprintf(unnamed_buf, "%s%s", UNNAMED_PREFIX,
		    v->v_mtype);
		v->v_obj.o_name = strdup(unnamed_buf);
	}
	v->v_ndev = labelp->dos_nparts;
	v->v_parts = labelp->dos_parts;
	v->v_flags |= V_NETWIDE;
	v->v_fstype = V_PCFS;
}

static void
dos_xdr(label *l, enum xdr_op op, void **data)
{
	XDR			xdrs;
	struct dos_label	label;
	struct dos_label	*labelp;
	char			*volnamep;

	if (doslabsw.l_xdrsize == 0) {
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_short, (void *)&label.dos_version);
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_long, (void *)&label.dos_lcrc);
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_long, (void *)&label.dos_magic);
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_char, (void *)&label.dos_nparts);
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_long, (void *)&label.dos_parts);
		doslabsw.l_xdrsize +=
			xdr_sizeof(xdr_u_char, (void *)&label.dos_type);
		/*
		 * xdr_string encodes a string as an integer equal
		 * to the length of the string, followed by the
		 * string itself
		 */
		doslabsw.l_xdrsize += DOS_NAMELEN + sizeof (int);
	}

	if (op == XDR_ENCODE) {

		labelp = (struct dos_label *)l->l_label;
		*data = malloc(doslabsw.l_xdrsize);
		xdrmem_create(&xdrs, *data, doslabsw.l_xdrsize, op);
		labelp->dos_version = DOS_VERSION;
		(void) xdr_u_short(&xdrs, &labelp->dos_version);
		(void) xdr_u_long(&xdrs, &labelp->dos_lcrc);
		(void) xdr_u_long(&xdrs, &labelp->dos_magic);
		(void) xdr_u_char(&xdrs, &labelp->dos_nparts);
		(void) xdr_u_long(&xdrs, &labelp->dos_parts);
		(void) xdr_u_char(&xdrs, &labelp->dos_type);
		volnamep = (char *)(labelp->dos_volname);
		(void) xdr_string(&xdrs, &volnamep, DOS_NAMELEN);
		xdr_destroy(&xdrs);

	} else if (op == XDR_DECODE) {

		xdrmem_create(&xdrs, *data, doslabsw.l_xdrsize, op);
		if (l->l_label == NULL) {
			l->l_label =
			    (void *)calloc(1, sizeof (struct dos_label));
		}
		labelp = (struct dos_label *)l->l_label;
		(void) xdr_u_short(&xdrs, &labelp->dos_version);
		/*
		 * Version check.  As yet there's no algorithm for
		 * handling different versions of the DOS label
		 * structure.
		 */
		ASSERT(labelp->dos_version == DOS_VERSION);
		(void) xdr_u_long(&xdrs, &labelp->dos_lcrc);
		(void) xdr_u_long(&xdrs, &labelp->dos_magic);
		(void) xdr_u_char(&xdrs, &labelp->dos_nparts);
		(void) xdr_u_long(&xdrs, &labelp->dos_parts);
		(void) xdr_u_char(&xdrs, &labelp->dos_type);
		(void) xdr_string(&xdrs, &volnamep, DOS_NAMELEN);
		/*
		 * xdr_string seems not to allocate any memory for
		 * null strings; therefore volnamep is null on return.
		 */
		if (volnamep != NULL) {
			(void) strncpy((char *)(labelp->dos_volname), volnamep,
			    DOS_NAMELEN);
			xdr_free(xdr_string, (void *)&volnamep);
		}
		xdr_destroy(&xdrs);
	}

}

/*
 * Definitions of private functions
 */

static void
dirname_to_volname(char *volname, struct pcdir *dir_entry)
{
	int  dirname_index;
	int  test_char;
	int  volname_index;

	volname[0] = NULLC;
	dirname_index = 0;
	volname_index = 0;
	test_char = dos_label_char(dir_entry->pcd_filename[dirname_index]);
	while ((test_char != (int)NULLC) && (dirname_index < DOS_NAMELEN_REG)) {
		volname[volname_index] = (char)test_char;
		volname_index++;
		dirname_index++;
		test_char =
			dos_label_char(dir_entry->pcd_filename[dirname_index]);
	}
	dirname_index = 0;
	test_char = dos_label_char(dir_entry->pcd_ext[dirname_index]);
	while ((test_char != (int)NULLC) && (dirname_index < DOS_NAMELEN_EXT)) {
		volname[volname_index] = (char)test_char;
		volname_index++;
		dirname_index++;
		test_char = dos_label_char(dir_entry->pcd_ext[dirname_index]);
	}
	volname[volname_index] = NULLC;
}

/*
 * copied from pc_validchar() in the kernel
 *
 * isdigit(), isupper(), ..., aren't used because they're
 * character-set-dependent, but DOS isn't
 */

static bool_t
dos_filename_char(char c)
{

	static char valid_chars[] = {
		"$#&@!%()-{}<>`_\\^~|'"
	};

	char	*charp;
	bool_t  is_valid;

	/*
	 * Should be "$#&@!%()-{}`_^~' " ??
	 * From experiment in DOSWindows, "*+=|\[];:\",<>.?/" are illegal.
	 * See IBM DOS4.0 Tech Ref. B-57.
	 */

	is_valid = FALSE;
	if ((c >= 'A') && (c <= 'Z')) {
		is_valid = TRUE;
	} else if ((c >= '0') && (c <= '9')) {
		is_valid = TRUE;
	} else {
		charp = valid_chars;
		while ((*charp != NULLC) && (is_valid == FALSE)) {
			if (c == *charp) {
				is_valid = TRUE;
			}
			charp++;
		}
	}
	return (is_valid);
}


static int
dos_label_char(int c)
{
	int return_char;

	if (isalnum(c)) {
		return_char = c;
	} else if (isspace(c)) {
		return_char = '_';
	} else {
		switch (c) {
		case '.':
		case '_':
		case '+':
			return_char = c;
			break;
		default:
			return_char = NULLC;
		}
	}
	return (return_char);
}

static char *
find_dos_volname(int fd, char *boot_bufferp)
{
	struct pcdir	*dir_entry;
	ushort_t	dir_index;
	size_t		dir_size;
	ushort_t	num_entries;
	ushort_t	root_sec;
	ushort_t	sec_size;
	uchar_t		*root_dir;
	static char	volname[DOS_NAMELEN + 2];

	root_sec = ltohs(boot_bufferp[PCB_RESSEC]) +
	    ((ushort_t)boot_bufferp[PCB_NFAT] * ltohs(boot_bufferp[PCB_SPF]));
	sec_size = ltohs(boot_bufferp[PCB_BPSEC]);
	num_entries = ltohs(boot_bufferp[PCB_NROOTENT]);
	dir_size = (size_t)(num_entries * sizeof (struct pcdir));
	root_dir = (uchar_t *)malloc(dir_size);
	if (root_dir == NULL) {
		debug(1, "find_dos_volname: can't alloc memory; %m\n");
		return (NULL);
	}
	if (lseek(fd, (root_sec * sec_size), SEEK_SET) < 0) {
		debug(1, "find_dos_volname: can't seek; %m\n");
		free(root_dir);
		return (NULL);
	}
	if (read(fd, root_dir, dir_size) != dir_size) {
		debug(1, "find_dos_volname: can't read root dir; %m\n");
		free(root_dir);
		return (NULL);
	}
	volname[0] = NULLC;
	dir_index = 0;
	/*
	 * Lint complains about the cast below,
	 * but there's no alignment problem.
	 */
	dir_entry = (struct pcdir *)&root_dir[0];
	while ((volname[0] == NULLC) &&
		(dir_entry->pcd_filename[0] != PCD_UNUSED) &&
		(dir_index < num_entries)) {
		if ((dir_entry->pcd_filename[0] != PCD_ERASED) &&
		    ((dir_entry->pcd_attr & PCDL_LFN_BITS) != PCDL_LFN_BITS) &&
		    (dir_entry->pcd_attr & PCA_LABEL)) {
			dirname_to_volname(volname, dir_entry);
		}
		dir_index++;
		/*
		 * Lint complains about the cast below,
		 * but there's no alignment problem.
		 */
		dir_entry = (struct pcdir *)&root_dir[dir_index *
				sizeof (struct pcdir)];
	}
	free(root_dir);
	return (volname);
}

static enum laread_res
find_dos_label(int fd, struct devs *dp, off_t offset, uchar_t *label_bufferp)
{
	uchar_t		dos_buf[DOS_READ_LENGTH];
	uchar_t		dos_buf2[DOS_READ_LENGTH];
	ulong_t		dos_magic;
	unsigned long	fat_offset;
	unsigned long	fat_sec_off;	/* offset of FAT sector */
	unsigned int	fat_sub_off;	/* offset within sector */
	int		read_length;
	char		*type = dp->dp_dsw->d_mtype;

	debug(1, "find_dos_label: fd = %d, offset = %ld\n", fd, offset);

	if (lseek(fd, offset, SEEK_SET) != offset) {
		debug(1, "find_dos_label: can't seek to %ld; %m\n", offset);
		return (L_ERROR);
	}
	read_length = read(fd, dos_buf, DOS_READ_LENGTH);
	if (read_length != DOS_READ_LENGTH) {
		debug(1, "find_dos_label: can't read label\n");
		return (L_UNFORMATTED);
	}
	if ((*dos_buf != (uchar_t)DOS_ID1) &&
	    (*dos_buf != (uchar_t)DOS_ID2a)) {
		debug(3, "find_dos_label: jump instruction missing/wrong\n");
		return (L_UNRECOG);
	}
	fat_offset = ltohs(dos_buf[PCB_BPSEC]) * ltohs(dos_buf[PCB_RESSEC]);
	if (fat_offset >= sizeof (dos_buf)) {
		fat_sec_off = (fat_offset & ~DOS_READ_LENGTH_MASK) + offset;
		fat_sub_off = fat_offset & DOS_READ_LENGTH_MASK;
		if (llseek(fd, fat_sec_off, SEEK_SET) != fat_sec_off) {
			debug(1, "find_dos_label: can't seek to %ld; %m\n",
			    fat_sec_off);
			return (L_ERROR);
		}
		read_length = read(fd, dos_buf2, DOS_READ_LENGTH);
		if (read_length != DOS_READ_LENGTH) {
			debug(1, "find_dos_label: read of \"%s\"; %m\n",
			    dp->dp_path);
			return (L_UNRECOG);
		}
		if ((dos_buf2[PCB_MEDIA] != dos_buf2[fat_sub_off]) ||
		    ((uchar_t)0xff != dos_buf2[fat_sub_off + 1]) ||
		    ((uchar_t)0xff != dos_buf2[fat_sub_off + 2])) {
			debug(3, "find_dos_label: can't read remote FAT.\n");
			return (L_UNRECOG);
		}
	} else  if ((dos_buf[PCB_MEDIA] != dos_buf[fat_offset]) ||
		    ((uchar_t)0xff != dos_buf[fat_offset + 1]) ||
		    ((uchar_t)0xff != dos_buf[fat_offset + 2])) {
		debug(3, "find_dos_label: can't read FAT\n");
		return (L_UNRECOG);
	}
	if (strncmp((char *)(dos_buf + DOS_OEM_NAME), DOS_OEM_NEC2,
	    DOS_OEM_LENGTH) == 0) {
		debug(3, "find_dos_label: found NEC 2.0 label\n");
		return (L_NOTUNIQUE);
	}
	(void) memcpy(&dos_magic, &dos_buf[DOS_ID_OFF], sizeof (ulong_t));
	if ((dos_magic == 0) && (dp->dp_writeprot || never_writeback)) {
		debug(3, "find_dos_label: can't write back label\n");
		return (L_NOTUNIQUE);
	} else if (dos_magic == 0) {
		dos_magic = unique_key(type, PCFS_LTYPE);
		(void) memcpy(&dos_buf[DOS_ID_OFF], &dos_magic,
				(size_t)sizeof (ulong_t));
		if (lseek(fd, offset, SEEK_SET) != offset) {
			warning(gettext(
			    "find_dos_label(): seek failed; %m\n"));
			return (L_NOTUNIQUE);
		}
		if (write(fd, dos_buf, DOS_READ_LENGTH) < 0) {
			warning(gettext(
			"find_dos_label: couldn't write back label; %m\n"));
			return (L_NOTUNIQUE);
		}
		debug(6, "find_dos_label: wroteback %#x as magic number\n",
		    dos_magic);
	}
	(void) memcpy(label_bufferp, dos_buf, (size_t)sizeof (dos_buf));
	return (L_FOUND);
}

static bool_t
find_fdisk_partition(int fd, int *partition_numberp, off_t *offsetp)
{
	bool_t		found;
	char		master_boot_record[DOS_READ_LENGTH];
	struct mboot	*master_boot_recordp;
	bool_t		no_solaris_partition;
	int		partition_index;
	struct ipart	*partitionp;
	int		read_length;
	ushort_t	signature;

	debug(5, "find_fdisk_partition: fd = %d\n", fd);

	(void) lseek(fd, 0L, SEEK_SET);
	read_length = read(fd, master_boot_record, DOS_READ_LENGTH);
	if ((read_length) != DOS_READ_LENGTH) {
		debug(1, "find_fdisk_partition: bad DOS read (%d); %m\n",
			read_length);
		return (FALSE);
	}
	/*
	 * Lint complains about the cast below,
	 * but there's no alignment problem.
	 */
	master_boot_recordp = (struct mboot *)master_boot_record;
	signature = ltohs(master_boot_recordp->signature);
	if (signature != MBB_MAGIC) {
		debug(3,
		    "find_fdisk_partition: DOS magic %X AFU (%X expected)\n",
		    signature, MBB_MAGIC);
		return (FALSE);
	}
	partition_index = 0;
	found = FALSE;
	no_solaris_partition = TRUE;
	while ((partition_index < FD_NUMPART) &&
		(no_solaris_partition == TRUE)) {
		/*
		 * Lint complains about the cast below,
		 * but there's no alignment problem.
		 */
		partitionp = (struct ipart *)
			&(master_boot_recordp->parts[partition_index *
						    sizeof (struct ipart)]);
		if (partitionp->systid == SUNIXOS ||
		    partitionp->systid == SUNIXOS2) {
			no_solaris_partition = FALSE;
		} else if ((found == FALSE) &&
				((partitionp->systid == DOSOS16) ||
				(partitionp->systid == DOSHUGE))) {
			found = TRUE;
			*partition_numberp = partition_index + 1;
			*offsetp = PC_SECSIZE * ltohi(partitionp->relsect);
		}
		partition_index++;
	}
	if (no_solaris_partition == FALSE) {
		found = FALSE;
	}
	return (found);
}

static void
read_dos_label(int fd, uchar_t *label_bufferp, label *la)
{
	int			index;
	struct dos_label	*labelp;
	int			offset;
	char			test_char;
	char			*volnamep;

	debug(1, "Entering read_dos_label\n");

	la->l_label = (void *)calloc(1, sizeof (struct dos_label));
	labelp = (struct dos_label *)la->l_label;

	labelp->dos_lcrc = calc_crc(label_bufferp, DOS_LABLEN);
	(void) memcpy(&labelp->dos_magic, &label_bufferp[DOS_ID_OFF],
			(size_t)sizeof (ulong_t));

	labelp->dos_volname[0] = NULLC;
	if (dos_filename_char(label_bufferp[DOS_NAME_OFF])) {
		index = 0;
		offset = DOS_NAME_OFF + index;
		test_char = (char)dos_label_char(label_bufferp[DOS_NAME_OFF]);
		while ((index < DOS_NAMELEN) && (test_char != NULLC)) {
			labelp->dos_volname[index] = test_char;
			index++;
			offset++;
			test_char = (char)dos_label_char(label_bufferp[offset]);
		}
		while ((labelp->dos_volname[index] == '-') && (index > 0)) {
			labelp->dos_volname[index] = NULLC;
			index--;
		}
	} else {
		volnamep = find_dos_volname(fd, (char *)label_bufferp);
		if ((volnamep != NULL) && (*volnamep != NULLC)) {
			(void) strcpy((char *)(labelp->dos_volname), volnamep);
		}
	}
	debug(1, "read_dos_label: returning label = \"%s\"\n",
		labelp->dos_volname);
}
