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
 * fdformat program - formats floppy disks, and then adds a label to them
 *
 *	 ****Warning, Warning, Warning, Warning*****
 *	 This program runs suid root.  This change was made to
 *	 allow it to umount a file system if it's mounted.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>
#include <errno.h>
#include <locale.h>
#include <libintl.h>
#include <volmgt.h>
#include <sys/isa_defs.h>
#include <sys/ioccom.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <sys/dklabel.h>
#include <sys/ioctl.h>
#include <sys/dkio.h>
#include <sys/fdio.h>
#include <sys/stat.h>
#include <sys/vtoc.h>
#include <sys/mnttab.h>

/* DEFINES */
#if defined(_BIG_ENDIAN)
#define	getbyte(A, N)	(((unsigned char *)(&(A)))[N])
#define	htols(S)	((getbyte(S, 1) <<8) | getbyte(S, 0))
#elif defined(_LITTLE_ENDIAN)
#define	htols(S)	(*((ushort_t *)(&(S))))
#else
#error One of _BIG_ENDIAN or LITTLE_ENDIAN must be defined
#endif

#define	getlobyte(A)	(A & 0xFF)
#define	gethibyte(A)	(A >> 8 & 0xFF)
#define	uppercase(c)	((c) >= 'a' && (c) <= 'z' ? (c) - 'a' + 'A' : (c))
#define	min(a, b)	((a) < (b) ? (a) : (b))

/* FORMAT PATTERNS */
#define		PATTERN_1	0x55;
#define		PATTERN_2	0xaa;
#define		PATTERN_3	0xff;
#define		PATTERN_4	0x00;

/* UNINITIALIZED DATA */
static 	struct fd_char 		fdchar;
static 	struct dk_geom 		fdgeom;
static 	struct dk_allmap 	allmap;
static 	struct dk_cinfo 	dkinfo;

/* EXTERN */
extern char	*optarg;
extern int	optind;

/* for verify buffers */
static uchar_t	*ibuf1;
static uchar_t	*obuf;

static char	*myname;

static 	int	fd_debug = 1;	/* 1 if debug XXX */
static 	int	b_flag = 0;	/* install a volume label to the diskette */
static 	int	d_flag = 0;	/* format the diskette in dos format */
static 	int	D_flag = 0;	/* double (aka low) density flag */
static 	int	e_flag = 0;	/* "eject" diskette when done (if supported) */
static 	int	E_flag = 0;	/* extended density */
static 	int	f_flag = 0;	/* "force" (no confirmation before start) */
static 	int	H_flag = 0;	/* high density */
static 	int	m_flag = 0;	/* medium density */
static 	int	n_flag = 0;	/* format the diskette in NEC-DOS format */
static 	int	q_flag = 0;	/* quiet format flag */
static 	int	U_flag = 0;	/* automatically unmount if it's mounted */
static 	int	v_flag = 0;	/* verify format/diskette flag */
static 	int	x_flag = 0;	/* skip the format, only install SunOS label */
				/* or DOS file system */
static 	int	z_flag = 0;	/* debugging only, setting partial formatting */
static 	int	interleave = 1;	/* interleave factor */

static	uid_t	euid = 0;	/* stores effective user id */

struct bios_param_blk {
	uchar_t	b_bps[2];		/* bytes per sector */
	uchar_t	b_spcl;			/* sectors per alloction unit */
	uchar_t	b_res_sec[2];		/* reserved sectors, starting at 0 */
	uchar_t	b_nfat;			/* number of FATs */
	uchar_t	b_rdirents[2];		/* number of root directory entries */
	uchar_t	b_totalsec[2];		/* total sectors in logical image */
	char	b_mediadescriptor;	/* media descriptor byte */
	uchar_t	b_fatsec[2];		/* number of sectors per FAT */
	uchar_t	b_spt[2];		/* sectors per track */
	uchar_t	b_nhead[2];		/* number of heads */
	uchar_t	b_hiddensec[2];		/* number of hidden sectors */
};

/*
 * ON-private functions from libvolmgt
 */
char	*_media_oldaliases(char *name);
int	_dev_mounted(char *path);
int	_dev_unmount(char *path);

/*
 * local functions
 */
static void	usage(char *);
static int	verify(int, int, int);
static void	write_SunOS_label(int, char *, struct vtoc *);
static int	valid_DOS_boot(char *, uchar_t **);
static void	write_DOS_label(int, uchar_t *, int, char *, char *,
			struct  bios_param_blk *, int);
static void	write_NEC_DOS_label(int, char *);
static int	check_mount();
static void	format_diskette(int, char *, struct vtoc *,
				struct  bios_param_blk *,  int *);
static void	restore_default_chars(int fd,
				    struct fd_char save_fdchar,
				    struct dk_allmap save_allmap);

int
main(int argc, char **argv)
{
	int	altsize = 0;
	int	fd;
	int	i;
	uchar_t	*altboot = NULL;
	char	*altbootname = NULL;
	char	*dev_name = NULL, *real_name, *alias_name;
	char	*vollabel = "";
	struct  vtoc fd_vtoc;
	struct	bios_param_blk bpb;
	int	rdirsec;
	char    *nullstring = "";

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

	(void) textdomain(TEXT_DOMAIN);

	myname = argv[0];
	while ((i = getopt(argc, argv, "B:b:dDeEfhHlLmMxqt:UvVZ?")) != -1) {
		switch (i) {

		case 'B':
			altbootname = strdup(optarg);
			d_flag++;
			/* check for valid boot file now */
			altsize = valid_DOS_boot(altbootname, &altboot);
			if (!altsize) {
				(void) fprintf(stderr, gettext(
				    "%s: invalid boot loader\n"), myname);
				exit(1);
			}
			break;

		case 'b':
			b_flag++;
			vollabel = strdup(optarg);
			break;

		case 'd':
			/* format a MS-DOS diskette */
			d_flag++;
			break;

		case 'D':
		case 'L':
		case 'l':
			/* format a Double density 720KB (or 360KB) disk */
			D_flag++;
			break;

		case 'e':
			/* eject diskette when done */
			e_flag++;
			break;

		case 'E':
			/* format an 2.88MB Extended density disk */
			E_flag++;
			break;

		case 'f':
			/* don't ask for confirmation */
			f_flag++;
			break;

		case 'H':
		case 'h':
			/* format a High density 1.2MB or 1.44MB disk */
			H_flag++;
			break;

#if 0
		case 'i':
			/* interleave factor */
			interleave = atol(optarg);
			if (interleave <= 0) {
				(void) fprintf(stderr, gettext(
				    "%s: invalid interleave\n"), myname);
				exit(1);
			}
			break;
#endif

		case 'M':
		case 'm':
			/* format a 3.5" HD disk to 1.2MB */
			m_flag++;
			break;

		case 'x':
			/* skip format, just write label */
			x_flag++;
			break;

		case 'q':
			/* quiet format */
			q_flag++;
			break;

		case 't':
			/* Type of DOS formatting: NEC or MS */
			if (strcmp(optarg, "nec") == 0) {
				n_flag++;
			}
			if (strcmp(optarg, "dos") == 0) {
				d_flag++;
			}
			break;

		case 'U':
			/* umount filesystem if mounted */
			U_flag++;
			break;

		case 'v':
		case 'V':
			/* verify the diskette after format */
			v_flag++;
			break;

		case 'Z':
			/* for debug only, format cyl 0 only */
			if (!fd_debug) {
				usage(gettext("unknown argument"));
				/* NOTREACHED */
			}
			(void) printf(gettext("\nFormat cyl Zero only\n"));
			z_flag++;
			break;

		default:
			usage(" ");
			/* NOTREACHED */
		}
	}

	if (optind < argc -1) {
		usage(gettext("more than one device name argument"));
		/* NOTREACHED */
	}
	if (optind == argc -1) {
		dev_name = argv[optind];
	}
	if (D_flag && H_flag) {
		usage(gettext("switches -D, -L and -H incompatible"));
		/* NOTREACHED */
	}
	if (D_flag && E_flag) {
		usage(gettext("switches -D, -L and -E incompatible"));
		/* NOTREACHED */
	}
	if (H_flag && E_flag) {
		usage(gettext("switches -H and -E incompatible"));
		/* NOTREACHED */
	}
	if (n_flag && d_flag) {
		usage(gettext("switches nec and dos incompatible"));
		/* NOTREACHED */
	}
	if (n_flag && !m_flag) {
		usage(gettext("switch -M required for NEC-DOS"));
		/* NOTREACHED */
	}
	if (D_flag && m_flag) {
		usage(gettext("switches -D, -L and -M incompatible"));
		/* NOTREACHED */
	}
	if (d_flag && m_flag) {
		usage(gettext("switches -d and -M incompatible"));
		/* NOTREACHED */
	}

	if (dev_name == NULL)
		dev_name = "floppy";

	if ((real_name = media_findname(dev_name)) == NULL) {
		if ((alias_name = _media_oldaliases(dev_name)) != NULL)
			real_name = media_findname(alias_name);
		if (real_name == NULL) {
			(void) fprintf(stderr,
gettext("No such volume (or no media in specified device): %s\n"),
					dev_name);
			exit(1);
		}
	}

	/*
	 * This check is required because program runs suid root.
	 */
	if (access(real_name, R_OK|W_OK) < 0) {
		perror(real_name);
		exit(1);
	}

	/* store callers euid */

	euid = geteuid();

	/*
	 * See if the given device name is mounted.  If this check isn't done
	 * before the open, the open will fail.  The failed open will not
	 * indicate that the device is mounted, only that it's busy
	 */
	if (_dev_mounted(real_name)) {
		if (U_flag) {
			if (!_dev_unmount(real_name)) {
				(void) fprintf(stderr,
					gettext("%s: umount of %s failed\n"),
				myname, real_name);
				exit(1);
			}
		} else {
			(void) fprintf(stderr,
				gettext("%s: %s is mounted (use -U flag)\n"),
				myname, real_name);
			exit(1);
		}
	}

	/* Set to user access permissions to open file */
	(void) seteuid(getuid());

	if ((fd = open(real_name, O_NDELAY | O_RDWR | O_EXCL)) == -1) {
		if (errno == EROFS) {
			(void) fprintf(stderr,
			    gettext("%s: \"%s\" is write protected\n"),
			    myname, real_name);
			exit(1);
		}
		/* XXX ought to check for "drive not installed", etc. */
		(void) fprintf(stderr, gettext("%s: could not open \"%s\": "),
		    myname, real_name);
		perror(nullstring);
		exit(1);
	}

	/* restore effective id */
	(void) seteuid(euid);

	if (ioctl(fd, DKIOCINFO, &dkinfo) < 0) {
		(void) fprintf(stderr,
			gettext("%s: DKIOCINFO failed, "), myname);
		perror(nullstring);
		exit(3);
	}

	/* See if there are any mounted partitions. */
	if (check_mount() != 0) {
			exit(3);
	}

	/*
	 * The fd_vtoc, bpb, and rdirsec structures will be
	 * partially filled in by format_diskette().
	 * This was done so that write_DOS_label(),
	 * write_SunOS_label(), and write_NEC_DOS_label() could be
	 * device independent.  If a new device needs to be added to
	 * fdformat, a new format function like format_diskette should
	 * be added.  This function should fill in fd_vtoc, bpb, and
	 * rdirsec with device dependent information.
	 */
	(void) memset((void *)&fd_vtoc, (char)0, sizeof (struct vtoc));
	(void) memset((void *)&bpb, (char)0, sizeof (struct  bios_param_blk));

	format_diskette(fd, real_name, &fd_vtoc, &bpb, &rdirsec);

	if (d_flag)
		write_DOS_label(fd, altboot, altsize, altbootname,
				vollabel, &bpb, rdirsec);
	else if (n_flag)
		write_NEC_DOS_label(fd, vollabel);
	else
		write_SunOS_label(fd, vollabel, &fd_vtoc);

	if (e_flag)
		/* eject media if possible */
		if (ioctl(fd, FDEJECT, 0)) {
			(void) fprintf(stderr,
			    gettext("%s: could not eject diskette, "), myname);
			perror(nullstring);
			exit(3);
		}

	return (0);
}

/*
 * Inputs: file descriptor for the device and the device name.
 * Oututs: the fd_vtoc will be partially filled in with the
 *         device specific information such as partition
 *         information and ascillabel. bpb and rdirsec will
 *	   also be partially filled in with device specific information
 */
void
format_diskette(int fd, char *real_name, struct vtoc *fd_vtoc,
				struct  bios_param_blk *bpb, int *rdirsec)
{
	int	transfer_rate = 1000;   /* transfer rate code */
	int	sec_size = 512;		/* sector size */
	uchar_t	gap = 0x54;		/* format gap size */
	uchar_t *fbuf, *p;
	char    *capacity = NULL;
	int	cyl_size;
	int	i;
	int	chgd;			/* for testing disk changed/present */
	int	cyl, hd;
	int	size_of_part, size_of_dev;
	int	spt = 36;		/* sectors per track */
	int	drive_size;
	uchar_t	num_cyl = 80;		/*  max number of cylinders */
	char    *nullstring = "";
	struct fd_char save_fdchar;	/* original diskette characteristics */
	struct dk_allmap save_allmap;	/* original diskette partition info */

	/* FDRAW ioctl command structures for seeking and formatting */
	struct fd_raw fdr_seek = {
		FDRAW_SEEK, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		3,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0,
		0
	};

	struct fd_raw fdr_form = {
		0x4D, 0, 2, 0, 0x54, (char)0xA5, 0, 0, 0, 0,
		6,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0,	/* nbytes */
		0	/* addr */
	};


	/*
	 * restore drive to default geometry and characteristics
	 * (probably not implemented on sparc)
	 */
	(void) ioctl(fd, FDDEFGEOCHAR, NULL);

	/* get the default partititon maps */
	if (ioctl(fd, DKIOCGAPART, &allmap) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: DKIOCGAPART failed, "), myname);
		perror(nullstring);
		exit(3);
	}

	/* Save the original default partition maps */
	save_allmap = allmap;

	/* find out the characteristics of the default diskette */
	if (ioctl(fd, FDIOGCHAR, &fdchar) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: FDIOGCHAR failed, "), myname);
		perror(nullstring);
		exit(3);
	}

	/* Save the original characteristics of the default diskette */
	save_fdchar = fdchar;

	/*
	 * The user may only format the entire diskette.
	 * formatting partion a or b is not allowed
	 */
	size_of_part = allmap.dka_map[dkinfo.dki_partition].dkl_nblk
			* DEV_BSIZE;
	size_of_dev = fdchar.fdc_ncyl * fdchar.fdc_nhead
			* fdchar.fdc_secptrack * fdchar.fdc_sec_size;

	if (size_of_part != size_of_dev) {
		(void) fprintf(stderr,
			/*CSTYLED*/
			gettext("%s: The entire diskette must be formatted. Invalid device name.\n"),
			myname);
		exit(3);
	}


	/* find out the geometry of the drive */
	if (ioctl(fd, DKIOCGGEOM, &fdgeom) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: DKIOCGGEOM failed, "), myname);
		perror(nullstring);
		exit(3);
	}

#ifdef sparc
	fdchar.fdc_medium = 3;
#endif
	if (fdchar.fdc_medium == 5)
		drive_size = 5;
	else
		drive_size = 3;

	/*
	 * set proper density flag in case we're formating to default
	 * characteristics because no density switch was input
	 */
	if ((E_flag | H_flag | D_flag | m_flag) == 0) {
		switch (fdchar.fdc_transfer_rate) {
		case 1000:
			/* assumes only ED uses 1.0 MB/sec */
			E_flag++;
			break;
		case 500:
		default:
			/*
			 * default to HD even though High density and
			 * "medium" density both use 500 KB/sec
			 */
			H_flag++;
			break;
#ifndef sparc
		case 250:
			/* assumes only DD uses 250 KB/sec */
			D_flag++;
			break;
#endif
		}
	}

	if (H_flag) {
		transfer_rate = 500;
		num_cyl = 80;
		sec_size = 512;
		if (drive_size == 5) {
			(void) strcpy(fd_vtoc->v_asciilabel,
				"5.25\" floppy cyl 80 alt 0 hd 2 sec 15");
			spt = 15;
			capacity = "1.2 MB";
		} else {
			(void) strcpy(fd_vtoc->v_asciilabel,
				"3.5\" floppy cyl 80 alt 0 hd 2 sec 18");
			spt = 18;
			capacity = "1.44 MB";
		}
		gap = 0x54;
	} else if (D_flag) {
		transfer_rate = 250;
		if (drive_size == 5) {
			(void) strcpy(fd_vtoc->v_asciilabel,
				"5.25\" floppy cyl 40 alt 0 hd 2 sec 9");
			if (fdchar.fdc_transfer_rate == 500) {
				/*
				 * formatting a 360KB DD diskette in
				 * a 1.2MB drive is not a good idea
				 */
				transfer_rate = 300;
				fdchar.fdc_steps = 2;
			}
			num_cyl = 40;
			gap = 0x50;
			capacity = "360 KB";
		} else {
			(void) strcpy(fd_vtoc->v_asciilabel,
				"3.5\" floppy cyl 80 alt 0 hd 2 sec 9");
			num_cyl = 80;
			gap = 0x54;
			capacity = "720 KB";
		}
		sec_size = 512;
		spt = 9;
	} else if (m_flag) {
#ifdef sparc
		transfer_rate = 500;
#else
		/*
		 * 416.67 KB/sec is the effective transfer rate of a "medium"
		 * density diskette spun at 300 rpm instead of 360 rpm
		 */
		transfer_rate = 417;
#endif
		(void) strcpy(fd_vtoc->v_asciilabel,
				"3.5\" floppy cyl 77 alt 0 hd 2 sec 8");
		num_cyl = 77;
		sec_size = 1024;
		spt = 8;
		gap = 0x74;
		capacity = "1.2 MB";
	} else if (E_flag) {
		(void) strcpy(fd_vtoc->v_asciilabel,
				"3.5\" floppy cyl 80 alt 0 hd 2 sec 36");
		transfer_rate = 1000;
		num_cyl = 80;
		sec_size = 512;
		spt = 36;
		gap = 0x54;
		capacity = "2.88 MB";
	}
	/*
	 * Medium density diskettes have 1024 byte blocks.  The dk_map
	 * structure in dklabel.h assumes the blocks size is DEVBSIZE (512)
	 * bytes.  The dkl_nblk field is in terms of DEVBSIZE byte blocks
	 * while the spt variable is in terms of the true block size on
	 * the diskette.
	 */
	if (allmap.dka_map[2].dkl_nblk !=
			(2 * num_cyl * spt * (m_flag ? 2 : 1))) {
		allmap.dka_map[1].dkl_cylno = num_cyl - 1;
		allmap.dka_map[0].dkl_nblk = 2 * (num_cyl - 1) * spt *
							(m_flag ? 2 : 1);
		allmap.dka_map[1].dkl_nblk = 2 * spt * (m_flag ? 2 : 1);
		allmap.dka_map[2].dkl_nblk = 2 * num_cyl * spt *
							(m_flag ? 2 : 1);
		if (allmap.dka_map[3].dkl_nblk)
			allmap.dka_map[3].dkl_nblk = 2 * (num_cyl - 1) * spt *
							(m_flag ? 2 : 1);
		if (allmap.dka_map[4].dkl_nblk)
			allmap.dka_map[4].dkl_nblk =
					2 * spt * (m_flag ? 2 : 1);
	}


	/* initialize the vtoc structure */
	fd_vtoc->v_nparts = 3;

	fd_vtoc->v_part[0].p_start = 0;
	fd_vtoc->v_part[0].p_size = ((num_cyl - 1) * 2 * spt *
							(m_flag ? 2 : 1));
	fd_vtoc->v_part[1].p_start = ((num_cyl - 1) * 2 * spt *
							(m_flag ? 2 : 1));
	fd_vtoc->v_part[1].p_size = 2 * spt * (m_flag ? 2 : 1);

	fd_vtoc->v_part[2].p_start = 0;
	fd_vtoc->v_part[2].p_size = num_cyl * 2 * spt * (m_flag ? 2 : 1);

	/* initialize the bios parameter blockstructure */
	bpb->b_nfat = 2;
	if (E_flag && drive_size == 3) {
		bpb->b_spcl = 2;
		*rdirsec = (ushort_t)240;
		bpb->b_mediadescriptor = (char)0xF0;
		bpb->b_fatsec[0] = 9;
		bpb->b_fatsec[1] = 0;
	} else if (H_flag) {
		if (drive_size == 5) {
			bpb->b_spcl = 1;
			*rdirsec = 224;
			bpb->b_mediadescriptor = (char)0xF9;
			bpb->b_fatsec[0] = 7;
			bpb->b_fatsec[1] = 0;
		} else {
			bpb->b_spcl = 1;
			*rdirsec = 224;
			bpb->b_mediadescriptor = (char)0xF0;
			bpb->b_fatsec[0] = 9;
			bpb->b_fatsec[1] = 0;
		}
	} else if (drive_size == 5) {
		bpb->b_spcl = 2;
		*rdirsec = 112;
		bpb->b_mediadescriptor = (char)0xFD;
		bpb->b_fatsec[0] = 2;
		bpb->b_fatsec[1] = 0;
	} else if (drive_size == 3) {
		bpb->b_spcl = 2;
		*rdirsec = 112;
		bpb->b_mediadescriptor = (char)0xF9;
		bpb->b_fatsec[0] = 3;
		bpb->b_fatsec[1] = 0;
	}



#ifndef sparc
	if (num_cyl > fdchar.fdc_ncyl || spt > fdchar.fdc_secptrack ||
	    transfer_rate > fdchar.fdc_transfer_rate) {
		(void) fprintf(stderr,
		    gettext("%s: drive not capable of requested density, "),
		    myname);
		perror(nullstring);
		exit(3);
	}
#endif
	if (num_cyl != fdchar.fdc_ncyl || spt != fdchar.fdc_secptrack ||
	    transfer_rate != fdchar.fdc_transfer_rate) {
		/*
		 * -- CAUTION --
		 * The SPARC fd driver is using a non-zero value in
		 * fdc_medium to indicate the 360 rpm, 77 track,
		 * 9 sectors/track, 1024 bytes/sector mode of operation
		 * (similar to an 8", DS/DD, 1.2 MB floppy).
		 *
		 * The x86 fd driver uses fdc_medium as the diameter
		 * indicator, either 3 or 5.  It should not be modified.
		 */
#ifdef sparc
		fdchar.fdc_medium = m_flag ? 1 : 0;
#endif
		fdchar.fdc_transfer_rate = transfer_rate;
		fdchar.fdc_ncyl = num_cyl;
		fdchar.fdc_sec_size = sec_size;
		fdchar.fdc_secptrack = spt;

		if (ioctl(fd, FDIOSCHAR, &fdchar) == -1) {
			(void) fprintf(stderr, gettext(
			    "%s: FDIOSCHAR (density selection) failed, "),
			    myname);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);
			perror(nullstring);
			exit(3);
		}
		if (ioctl(fd, DKIOCSAPART, &allmap) == -1) {
			(void) fprintf(stderr,
			    gettext("%s: DKIOCSAPART failed, "),
			    myname);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);

			perror(nullstring);
			exit(3);
		}
	}

	if (interleave != 1 && interleave != fdgeom.dkg_intrlv) {
		fdgeom.dkg_intrlv = interleave;
		if (ioctl(fd, DKIOCSGEOM, &fdgeom) == -1) {
			(void) fprintf(stderr,
			    gettext("%s: DKIOCSGEOM failed, "), myname);
			perror(nullstring);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);

			exit(3);
		}
	}

	cyl_size = 2 * sec_size * spt;

	if ((ibuf1 = (uchar_t *)malloc((size_t)cyl_size)) == 0 ||
	    (obuf = (uchar_t *)malloc((size_t)cyl_size)) == 0) {
		(void) fprintf(stderr,
		    gettext("%s: can't malloc verify buffer, "),
		    myname);
		perror(nullstring);
		/* restore the default characteristics */
		restore_default_chars(fd, save_fdchar, save_allmap);

		exit(4);
	}
	(void) memset(ibuf1, (uchar_t)0xA5, cyl_size);

	if (x_flag)
		goto skipformat;

	if (!(q_flag && f_flag)) {
		if (interleave != 1) {
			(void) printf(gettext(
"Formatting %s, %d cylinders, %d sectors per trk, interleave=%d in %s\n"),
			    capacity, num_cyl, spt, interleave, real_name);
		} else {
			(void) printf(gettext("Formatting %s in %s\n"),
			    capacity, real_name);
		}
	}
	if (!f_flag) {
		(void) printf(
		    gettext("Press return to start formatting floppy."));
		while (getchar() != '\n')
			;
	}
	/*
	 * for those systems that support this ioctl, they will
	 * return whether or not a diskette is in the drive.
	 */
	if (ioctl(fd, FDGETCHANGE, &chgd) == 0) {
		if (chgd & FDGC_CURRENT) {
			(void) fprintf(stderr,
			    gettext("%s: no diskette in drive %s\n"),
			    myname, real_name);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);

			exit(4);
		}
		if (chgd & FDGC_CURWPROT) {
			(void) fprintf(stderr,
			    gettext("%s: \"%s\" is write protected\n"),
			    myname, real_name);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);

			exit(1);
		}
	}

	if ((fbuf = (uchar_t *)malloc((unsigned)(4 * spt))) == 0) {
		(void) fprintf(stderr,
		    gettext("%s: can't malloc format header buffer, "),
		    myname);
		perror(nullstring);

		/* restore the default characteristics */
		restore_default_chars(fd, save_fdchar, save_allmap);

		exit(3);
	}
	/*
	 * do the format, a track at a time
	 */
	for (cyl = 0; cyl < (z_flag ? 1 : (int)num_cyl); cyl++) {
		/*
		 * This is not the optimal ioctl to format the floppy.
		 * The device driver should do do the work,
		 * instead of this program mucking with a lot
		 * of low-level, device-dependent code.
		 */
		fdr_seek.fdr_cmd[2] = cyl;
		if (ioctl(fd, FDRAW, &fdr_seek) == -1) {
			(void) fprintf(stderr,
			    gettext("%s: seek to cyl %d failed\n"),
			    myname, cyl);

			/* restore the default characteristics */
			restore_default_chars(fd, save_fdchar, save_allmap);

			exit(3);
		}
		/*
		 * Assume that the fd driver has issued a SENSE_INT
		 * command to complete the seek operation.
		 */
		for (hd = 0; hd < fdchar.fdc_nhead; hd++) {
			p = (uchar_t *)fbuf;
			for (i = 1; i <= spt; i++) {
				*p++ = cyl;
				*p++ = hd;
				*p++ = i; /* sector # */
				*p++ = (sec_size == 1024) ? 3 : 2;
			}
			/*
			 * ASSUME the fd driver is going to set drive-select
			 * bits in the second command byte
			 */
			fdr_form.fdr_cmd[1] = hd << 2;
			fdr_form.fdr_cmd[2] = (sec_size == 1024) ? 3 : 2;
			fdr_form.fdr_cmd[3] = spt;
			fdr_form.fdr_cmd[4] = gap;
			fdr_form.fdr_nbytes = 4 * spt;
			fdr_form.fdr_addr = (char *)fbuf;

			if (ioctl(fd, FDRAW, &fdr_form) == -1) {


				(void) fprintf(stderr, gettext(
				    "%s: format of cyl %d head %d failed\n"),
				    myname, cyl, hd);

				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
						    save_allmap);

				exit(3);
			}
			if (fdr_form.fdr_result[0] & 0xC0) {
				if (fdr_form.fdr_result[1] & 0x02) {
					(void) fprintf(stderr, gettext(
					/*CSTYLED*/
					"%s: diskette is write protected\n"),
					    myname);

					/*
					 * restore the default
					 * characteristics
					 */
					restore_default_chars(fd, save_fdchar,
						    save_allmap);

					exit(3);
				}
				(void) fprintf(stderr, gettext(
				    "%s: format of cyl %d head %d failed\n"),
				    myname, cyl, hd);

				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
						    save_allmap);

				exit(3);
			}

		}

		/*
		 *  do a quick verify
		 */
		if (!v_flag) {
			if (lseek(fd, cyl * cyl_size, 0) != cyl * cyl_size) {
				(void) fprintf(stderr,
				    gettext("%s: bad seek to format verify, "),
				    myname);
				perror(nullstring);
				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
						    save_allmap);

				exit(3);
			}
			if (read(fd, obuf, cyl_size) == cyl_size) {
				/* write some progress msg */
				/* when each cylinder is done. */
				if (!q_flag)
					(void) printf(".");
			} else {
				if (!q_flag)
					(void) printf(gettext("e\n"));
				(void) fprintf(stderr, gettext(
				    "%s: can't read format data, "), myname);
				perror(nullstring);
				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
						    save_allmap);

				exit(3);
			}
		} else
			if (!q_flag)
				(void) printf(".");
		if (!q_flag)
			(void) fflush(stdout);
	}
	if (!q_flag)
		(void) printf("\n");
skipformat:
	if (v_flag) {
		/*
		 *  do a write & read verify of the entire diskette
		 */
		if (!q_flag && x_flag)
			(void) printf(gettext("Verifying %s in %s\n"),
			    capacity, real_name);

		for (cyl = 0; cyl < (int)num_cyl; cyl++) {

			int val;
			if ((val = verify(fd, 2 * spt * cyl, cyl_size)) != 0) {
				perror(nullstring);

				/* restore the default characteristics */
				restore_default_chars(fd, save_fdchar,
						save_allmap);

				exit(val);

			}
			/* write some progress msg as */
			/* each cylinder is done. */
			if (!q_flag)
				(void) printf(gettext("v"));
			(void) fflush(stdout);
		}
		if (!q_flag)
			(void) printf("\n");
	}

	if (lseek(fd, (off_t)0, 0) != 0) {
		(void) fprintf(stderr, gettext("%s: seek to blk 0 failed, "),
		    myname);
		perror(nullstring);
		/* restore the default characteristics */
		restore_default_chars(fd, save_fdchar, save_allmap);

		exit(3);
	}

}


/*
 * Restore the default characteristics of the floppy diskette.
 * Fdformat changes the characteristics in the process of formatting.
 * If fdformat fails while in the process of doing the format, fdformat
 * should clean up after itself and reset the driver back to the original
 * state.
 */

static void
restore_default_chars(int fd,
			struct fd_char save_fdchar,
			struct dk_allmap save_allmap)
{


	/*
	 * When this function is called, fdformat is failing anyways,
	 * so the errors are not processed.
	 */

	(void) ioctl(fd, FDIOSCHAR, &save_fdchar);

	(void) ioctl(fd, DKIOCSAPART, &save_allmap);

	/*
	 * Before looking at the diskette's characteristics, format_diskette()
	 * sets the x86 floppy driver to the default characteristics.
	 * restore drive to default geometry and
	 * characteristics.  This ioctl isn't implemented on
	 * sparc.
	 */
	(void) ioctl(fd, FDDEFGEOCHAR, NULL);

}

/*
 * See if any partitions on the device are mounted.  Return 1 if a partition is
 * mounted.  Return 0 otherwise.
 */
static int
check_mount()
{
	FILE	*fp = NULL;
	int	mfd;
	struct dk_cinfo dkinfo_tmp;
	struct mnttab   mnt_record;
	struct mnttab   *mp = &mnt_record;
	struct stat	stbuf;
	char		raw_device[MAXPATHLEN];
	int	found = 0;

	if ((fp = fopen(MNTTAB, "r")) == NULL) {
		perror(MNTTAB);
		exit(3);
	}

	while (getmntent(fp, mp) == 0) {
		if (strstr(mp->mnt_special, "/dev/fd") == NULL &&
		    strstr(mp->mnt_special, "/dev/disket") == NULL &&
		    strstr(mp->mnt_special, "/dev/c") == NULL) {
			continue;
		}

		(void) strcpy(raw_device, "/dev/r");
		(void) strcat(raw_device, mp->mnt_special + strlen("/dev/"));

		/*
		 * Attempt to open the device.  If it fails, skip it.
		 */
		if ((mfd = open(raw_device, O_RDWR | O_NDELAY)) < 0) {
			continue;
		}

		/*
		 * Must be a character device
		 */
		if (fstat(mfd, &stbuf) == -1 || !S_ISCHR(stbuf.st_mode)) {
			(void) close(mfd);
			continue;
		}
		/*
		 * Attempt to read the configuration info on the disk.
		 */
		if (ioctl(mfd, DKIOCINFO, &dkinfo_tmp) < 0) {
			(void) close(mfd);
			continue;
		}
		/*
		 * Finished with the opened device
		 */
		(void) close(mfd);

		/*
		 * If it's not the disk we're interested in, it doesn't apply.
		 */
		if (dkinfo.dki_ctype != dkinfo_tmp.dki_ctype ||
			dkinfo.dki_cnum != dkinfo_tmp.dki_cnum ||
			dkinfo.dki_unit != dkinfo_tmp.dki_unit) {
				continue;
		}
		/*
		 * It's a mount on the disk we're checking.  If we are
		 * checking whole disk, then we found trouble.  We can
		 * quit searching.
		 */

		if (U_flag) {
			if (!_dev_unmount(mp->mnt_special)) {
					(void) fprintf(stderr,
					gettext("%s: umount of %s failed\n"),
					myname, mp->mnt_special);
				found = 1;
			}
		} else {
			(void) fprintf(stderr,
				gettext("%s: %s is mounted (use -U flag)\n"),
				myname, mp->mnt_special);
			found = 1;
		}
	}
	return (found);
}

static void
usage(char *str)
{
char    *real_name, *alias_name;

	if ((real_name = media_findname("floppy")) == NULL) {
		if ((alias_name = _media_oldaliases("floppy")) != NULL)
			real_name = media_findname(alias_name);
	}

	if (str[0] != ' ')
		(void) printf("%s: %s\n", myname, str);
	(void) printf(gettext(
/*CSTYLED*/
"\n   usage: %s [-dDeEfHlLmMqUvx] [-b label] [-B file] [-t dostype] [devname]\n"),
	    myname);

	(void) printf(gettext(
/*CSTYLED*/
	    "      -b label install \"label\" on media\n"));
	(void) printf(gettext(
	    "      -B file  install special boot loader on MS-DOS media\n"));
	(void) printf(gettext(
/*CSTYLED*/
	    "      -d       format MS-DOS media\n"));
	(void) printf(gettext(
/*CSTYLED*/
"      -D       format 720KB (3.5\") or 360KB (5.25\") Double-density diskette\n"));
	(void) printf(gettext(
	    "      -e       eject the media when done\n"));
/*CSTYLED*/
	(void) printf(gettext(
/*CSTYLED*/
	    "      -E       format 2.88MB (3.5\") Extended-density diskette\n"));
	(void) printf(gettext(
	    "      -f       \"force\" - don't wait for confirmation\n"));
	(void) printf(gettext(
/*CSTYLED*/
"      -H       format 1.44MB (3.5\") or 1.2MB (5.25\") High-density diskette\n"));
	(void) printf(gettext(
/*CSTYLED*/
"      -l       format 720KB (3.5\") or 360KB (5.25\") Double-density diskette\n"));
	(void) printf(gettext(
/*CSTYLED*/
"      -L       format 720KB (3.5\") or 360KB (5.25\") Double-density diskette\n"));
	(void) printf(gettext(
	    "      -m       format 1.2MB (3.5\") Medium-density diskette\n"));
	(void) printf(gettext(
	    "      -M       format 1.2MB (3.5\") Medium-density diskette\n"));
	(void) printf(gettext(
	    "      -q       quiet\n"));
	(void) printf(gettext(
/*CSTYLED*/
	    "      -t dos   format MS-DOS media (same as -d)\n"));
	(void) printf(gettext(
	    "      -t nec   format NEC-DOS media (with -M only)\n"));
(void) printf(gettext(
/*CSTYLED*/
	    "      -U       unmount media if it's mounted\n"));
	(void) printf(gettext(
	    "      -v       verify each block of the media\n"));
	(void) printf(gettext(
"      -x       skip the format, only install SunOS or DOS label\n"));

	(void) printf(gettext(
	    "      devname defaults to '%s'\n"),
	    real_name ? real_name : gettext("no available default device"));

	exit(1);

}


static int
verify(int fd, int blk, int len)
{
	off_t	off;
	char    *nullstring = "";

	off = (off_t)(blk * (m_flag ? 1024 : 512));

	if (lseek(fd, off, 0) != off) {
		if (!q_flag)
			(void) printf(gettext("e\n"));
		(void) fprintf(stderr,
		    gettext("%s: can't seek to write verify, "), myname);
		perror(nullstring);
		return (4);
	}
	if (write(fd, ibuf1, len) != len) {
		if (!q_flag)
			(void) printf(gettext("e\n"));
		if (blk == 0)
			(void) fprintf(stderr,
			    gettext("%s: check diskette density, "),
			    myname);
		else
			(void) fprintf(stderr,
			    gettext("%s: can't write verify data, "),
			    myname);
		perror(nullstring);
		return (4);
	}

	if (lseek(fd, off, 0) != off) {
		if (!q_flag)
			(void) printf(gettext("e\n"));
		(void) fprintf(stderr,
		    gettext("%s: bad seek to read verify, "),
		    myname);
		perror(nullstring);
		return (4);
	}
	if (read(fd, obuf, len) != len) {
		if (!q_flag)
			(void) printf(gettext("e\n"));
		(void) fprintf(stderr,
		    gettext("%s: can't read verify data, "), myname);
		perror(nullstring);
		return (4);
	}
	if (memcmp(ibuf1, obuf, len)) {
		if (!q_flag)
			(void) printf(gettext("e\n"));
		(void) fprintf(stderr, gettext("%s: verify data failure\n"),
		    myname);
		return (4);
	}
	return (0);
}

/*
 *  write a SunOS label
 *  NOTE:  this function assumes fd_vtoc has been filled in with the
 *  device specific information such as partition information
 *  and the asciilabel
 */
static void
write_SunOS_label(int fd, char *volname, struct vtoc *fd_vtoc)
{
	char    *nullstring = "";

	fd_vtoc->v_sanity = VTOC_SANE;

	/*
	 * The label structure is set up for DEV_BSIZE (512 byte) blocks,
	 * even though a medium density diskette has 1024 byte blocks
	 * See dklabel.h for more details.
	 */
	fd_vtoc->v_sectorsz = DEV_BSIZE;

	(void) strncpy(fd_vtoc->v_volume, volname, sizeof (fd_vtoc->v_volume));

	/* let the fd driver finish constructing the label and writing it */
	if (ioctl(fd, DKIOCSVTOC, fd_vtoc) == -1) {
		(void) fprintf(stderr,
		    gettext("%s: write of SunOS label failed, "), myname);
		perror(nullstring);
		exit(3);
	}

}


/*
 *	MS-DOS Disk layout:
 *
 *	---------------------
 *	|    Boot sector    |
 *	|-------------------|
 *	|   Reserved area   |
 *	|-------------------|
 *	|	FAT #1      |
 *	|-------------------|
 *	|	FAT #2      |
 *	|-------------------|
 *	|   Root directory  |
 *	|-------------------|
 *	|                   |
 *	|     File area     |
 *	|___________________|
 */

/*
 * The following is a copy of MS-DOS 3.3 boot block.
 * It consists of the BIOS parameter block, and a disk
 * bootstrap program.
 *
 * The BIOS parameter block contains the right values
 * for the 3.5" high-density 1.44MB floppy format.
 *
 */
static uchar_t bootsec[512] = {
	0xeb, 0x34, 0x90,	/* 8086 short jump + displacement + NOP */
	'M', 'S', 'D', 'O', 'S', '3', '.', '3',	/* OEM name & version */
	0, 2, 1, 1, 0,		/* Start of BIOS parameter block */
	2, 224, 0, 0x40, 0xb, 0xf0, 9, 0,
	18, 0, 2, 0, 0, 0,	/* End of BIOS parameter block */
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
	0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x12,
	0x0, 0x0, 0x0, 0x0,
	0x1, 0x0, 0xfa, 0x33,	/* 0x34, start of the bootstrap. */
	0xc0, 0x8e, 0xd0, 0xbc, 0x0, 0x7c, 0x16, 0x7,
	0xbb, 0x78, 0x0, 0x36, 0xc5, 0x37, 0x1e, 0x56,
	0x16, 0x53, 0xbf, 0x2b, 0x7c, 0xb9, 0xb, 0x0,
	0xfc, 0xac, 0x26, 0x80, 0x3d, 0x0, 0x74, 0x3,
	0x26, 0x8a, 0x5, 0xaa, 0x8a, 0xc4, 0xe2, 0xf1,
	0x6, 0x1f, 0x89, 0x47, 0x2, 0xc7, 0x7, 0x2b,
	0x7c, 0xfb, 0xcd, 0x13, 0x72, 0x67, 0xa0, 0x10,
	0x7c, 0x98, 0xf7, 0x26, 0x16, 0x7c, 0x3, 0x6,
	0x1c, 0x7c, 0x3, 0x6, 0xe, 0x7c, 0xa3, 0x3f,
	0x7c, 0xa3, 0x37, 0x7c, 0xb8, 0x20, 0x0, 0xf7,
	0x26, 0x11, 0x7c, 0x8b, 0x1e, 0xb, 0x7c, 0x3,
	0xc3, 0x48, 0xf7, 0xf3, 0x1, 0x6, 0x37, 0x7c,
	0xbb, 0x0, 0x5, 0xa1, 0x3f, 0x7c, 0xe8, 0x9f,
	0x0, 0xb8, 0x1, 0x2, 0xe8, 0xb3, 0x0, 0x72,
	0x19, 0x8b, 0xfb, 0xb9, 0xb, 0x0, 0xbe, 0xd6,
	0x7d, 0xf3, 0xa6, 0x75, 0xd, 0x8d, 0x7f, 0x20,
	0xbe, 0xe1, 0x7d, 0xb9, 0xb, 0x0, 0xf3, 0xa6,
	0x74, 0x18, 0xbe, 0x77, 0x7d, 0xe8, 0x6a, 0x0,
	0x32, 0xe4, 0xcd, 0x16, 0x5e, 0x1f, 0x8f, 0x4,
	0x8f, 0x44, 0x2, 0xcd, 0x19, 0xbe, 0xc0, 0x7d,
	0xeb, 0xeb, 0xa1, 0x1c, 0x5, 0x33, 0xd2, 0xf7,
	0x36, 0xb, 0x7c, 0xfe, 0xc0, 0xa2, 0x3c, 0x7c,
	0xa1, 0x37, 0x7c, 0xa3, 0x3d, 0x7c, 0xbb, 0x0,
	0x7, 0xa1, 0x37, 0x7c, 0xe8, 0x49, 0x0, 0xa1,
	0x18, 0x7c, 0x2a, 0x6, 0x3b, 0x7c, 0x40, 0x38,
	0x6, 0x3c, 0x7c, 0x73, 0x3, 0xa0, 0x3c, 0x7c,
	0x50, 0xe8, 0x4e, 0x0, 0x58, 0x72, 0xc6, 0x28,
	0x6, 0x3c, 0x7c, 0x74, 0xc, 0x1, 0x6, 0x37,
	0x7c, 0xf7, 0x26, 0xb, 0x7c, 0x3, 0xd8, 0xeb,
	0xd0, 0x8a, 0x2e, 0x15, 0x7c, 0x8a, 0x16, 0xfd,
	0x7d, 0x8b, 0x1e, 0x3d, 0x7c, 0xea, 0x0, 0x0,
	0x70, 0x0, 0xac, 0xa, 0xc0, 0x74, 0x22, 0xb4,
	0xe, 0xbb, 0x7, 0x0, 0xcd, 0x10, 0xeb, 0xf2,
	0x33, 0xd2, 0xf7, 0x36, 0x18, 0x7c, 0xfe, 0xc2,
	0x88, 0x16, 0x3b, 0x7c, 0x33, 0xd2, 0xf7, 0x36,
	0x1a, 0x7c, 0x88, 0x16, 0x2a, 0x7c, 0xa3, 0x39,
	0x7c, 0xc3, 0xb4, 0x2, 0x8b, 0x16, 0x39, 0x7c,
	0xb1, 0x6, 0xd2, 0xe6, 0xa, 0x36, 0x3b, 0x7c,
	0x8b, 0xca, 0x86, 0xe9, 0x8a, 0x16, 0xfd, 0x7d,
	0x8a, 0x36, 0x2a, 0x7c, 0xcd, 0x13, 0xc3, '\r',
	'\n', 'N', 'o', 'n', '-', 'S', 'y', 's',
	't', 'e', 'm', ' ', 'd', 'i', 's', 'k',
	' ', 'o', 'r', ' ', 'd', 'i', 's', 'k',
	' ', 'e', 'r', 'r', 'o', 'r', '\r', '\n',
	'R', 'e', 'p', 'l', 'a', 'c', 'e', ' ',
	'a', 'n', 'd', ' ', 's', 't', 'r', 'i',
	'k', 'e', ' ', 'a', 'n', 'y', ' ', 'k',
	'e', 'y', ' ', 'w', 'h', 'e', 'n', ' ',
	'r', 'e', 'a', 'd', 'y', '\r', '\n', '\0',
	'\r', '\n', 'D', 'i', 's', 'k', ' ', 'B',
	'o', 'o', 't', ' ', 'f', 'a', 'i', 'l',
	'u', 'r', 'e', '\r', '\n', '\0', 'I', 'O',
	' ', ' ', ' ', ' ', ' ', ' ', 'S', 'Y',
	'S', 'M', 'S', 'D', 'O', 'S', ' ', ' ',
	' ', 'S', 'Y', 'S', '\0', 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0x55, 0xaa
};

static int
valid_DOS_boot(char *bootfile, uchar_t **bootloadp)
{
	struct	stat status;
	size_t	sizebootldr;
	uchar_t	*bootloader;
	int	bfd;
	int	boot_size = 0;
	int	err;
	char	*nullstring = "";

	if ((err = stat(bootfile, &status)) != 0) {
		(void) fprintf(stderr, gettext("%s: \"%s\" stat error %d\n"),
		    myname, bootfile, err);
		return (0);
	}
	if ((boot_size = status.st_size) < 512) {
		(void) fprintf(stderr,
		    gettext("%s: short boot sector"), myname);
		perror(nullstring);
		return (0);
	}
	sizebootldr = (boot_size + 511) / 512 * 512;
	if ((bootloader = (uchar_t *)malloc((size_t)sizebootldr)) == NULL) {
		(void) fprintf(stderr, gettext("%s: malloc error\n"),
		    myname);
		return (0);
	}

	/* switch to user to access the boot file */
	(void) seteuid(getuid());

	if ((bfd = open(bootfile, O_RDONLY)) == -1) {
		(void) fprintf(stderr, gettext("%s: could not open \"%s\": "),
		    myname, bootfile);
		perror(nullstring);
		return (0);
	}

	/* restore effective id */
	(void) seteuid(euid);

	if (read(bfd, bootloader, boot_size) != boot_size) {
		(void) fprintf(stderr,
		    gettext("%s: read of MS-DOS boot file failed, "), myname);
		perror(nullstring);
		(void) close(bfd);
		return (0);
	}

	if (!((*bootloader == 0xE9 ||
	    (*bootloader == 0xEB && *(bootloader + 2) == 0x90)) &&
		*(bootloader + 510) == 0x55 &&
		*(bootloader + 511) == 0xAA)) {
		(void) fprintf(stderr,
		    gettext("%s: invalid MS-DOS boot loader image\n"), myname);
		boot_size = 0;
	}

	(void) close(bfd);
	*bootloadp = bootloader;
	return (boot_size);
}


static void
write_DOS_label(int fd, uchar_t *bootloadr, int bootlen, char *altbootname,
    char *doslabel, struct  bios_param_blk *bpb, int rdirsec)
{
	int		i, j;
	int		bootclen;
	size_t		fat_bsize;
	ushort_t	totalsec;
	uchar_t		*fat_rdir;
	uchar_t		*fatptr;
	char		*nullstring = "";

	if (bootlen < 512 || !bootloadr) {
		/* use default boot loader routine */
		bootloadr = bootsec;
		bootlen = 512;
	} else
		(void) printf
			(gettext("%s: using \"%s\" for MS-DOS boot loader\n"),
		    myname, altbootname);
	if (bootlen % 512 > 0)
		bootlen = (bootlen + 511) / 512 * 512;

	bpb->b_bps[0] = getlobyte(512);
	bpb->b_bps[1] = gethibyte(512);
	/* MS-DOS 5.0 supports only 1 reserved sector :-( */
	bpb->b_res_sec[0] = 1;
	bpb->b_res_sec[1] = 0;

	totalsec = fdchar.fdc_ncyl * fdchar.fdc_nhead * fdchar.fdc_secptrack;
	bpb->b_totalsec[0] = getlobyte(totalsec);
	bpb->b_totalsec[1] = gethibyte(totalsec);
	bpb->b_spt[0] = fdchar.fdc_secptrack;
	bpb->b_spt[1] = 0;
	bpb->b_nhead[0] = fdchar.fdc_nhead;
	bpb->b_nhead[1] = 0;
	bpb->b_hiddensec[0] = 0;
	bpb->b_hiddensec[1] = 0;

	bpb->b_rdirents[0] = getlobyte(rdirsec);
	bpb->b_rdirents[1] = gethibyte(rdirsec);

	(void) memcpy((char *)(bootloadr + 0x0B), (char *)bpb,
					sizeof (struct  bios_param_blk));

	if (write(fd, bootloadr, 512) != 512) {
		(void) fprintf(stderr,
		    gettext("%s: write of MS-DOS boot sector failed"), myname);
		perror(nullstring);
		exit(3);
	}
	bootloadr += 512;
	bootlen -= 512;

	fat_bsize = 512 * bpb->b_fatsec[0];
	fat_rdir = (uchar_t *)malloc(fat_bsize);
	(void) memset(fat_rdir, (char)0, fat_bsize);

	*fat_rdir = bpb->b_mediadescriptor;
	*(fat_rdir + 1) = 0xFF;
	*(fat_rdir + 2) = 0xFF;
	bootclen = (bootlen + 512 * (int)bpb->b_spcl - 1) /
	    (512 * (int)bpb->b_spcl);
#define	BAD_CLUSTER 0xFF7
	for (i = 0, fatptr = fat_rdir+3; i < bootclen; i++)
		/*
		 * pre-allocate any clusters used by boot loader if
		 * loader will occupy more than 1 sector
		 */
		if (!(i & 01)) {
			*fatptr++ = BAD_CLUSTER & 0xFF;
			*fatptr = (BAD_CLUSTER >> 8) & 0x0F;
		} else {
			*fatptr = (*fatptr & 0x0F) |
			    ((BAD_CLUSTER << 4) & 0xF0);
			fatptr++;
			*fatptr++ = (BAD_CLUSTER >> 4) & 0xFF;
		}
	for (i = 0; i < (int)bpb->b_nfat; ++i)
		if (write(fd, fat_rdir, fat_bsize) != fat_bsize) {
			(void) fprintf(stderr,
gettext("%s: write of MS-DOS File Allocation Table failed, "),
			    myname);
			perror(nullstring);
			exit(3);
		}
	rdirsec = bpb->b_rdirents[0];
	rdirsec = 32 * (int)rdirsec / 512;
	if (b_flag) {
		struct  timeval tv;
		struct	tm	*tp;
		ushort_t	dostime;
		ushort_t	dosday;

		/* the label can be no more than 11 characters */
		j = min(11, (int)strlen(doslabel));
		for (i = 0; i < j; i++) {
			fat_rdir[i] = uppercase(doslabel[i]);
		}
		for (; i < 11; i++) {
			fat_rdir[i] = ' ';
		}
		fat_rdir[0x0B] = 0x28;
		(void) gettimeofday(&tv, (struct timezone *)0);
		tp = localtime(&tv.tv_sec);
		/* get the time & day into DOS format */
		dostime = tp->tm_sec / 2;
		dostime |= tp->tm_min << 5;
		dostime |= tp->tm_hour << 11;
		dosday = tp->tm_mday;
		dosday |= (tp->tm_mon + 1) << 5;
		dosday |= (tp->tm_year - 80) << 9;
		fat_rdir[0x16] = getlobyte(dostime);
		fat_rdir[0x17] = gethibyte(dostime);
		fat_rdir[0x18] = getlobyte(dosday);
		fat_rdir[0x19] = gethibyte(dosday);

		if (write(fd, fat_rdir, 512) != 512) {
			(void) fprintf(stderr,
			    gettext("%s: write of MS-DOS FAT failed, "),
			    myname);
			perror(nullstring);
			exit(3);
		}
		i = 1;
	} else {
		i = 0;
	}
	(void) memset(fat_rdir, (char)0, 512);
	for (; i < (int)rdirsec; ++i) {
		if (write(fd, fat_rdir, 512) != 512) {
			(void) fprintf(stderr,
gettext("%s: write of MS-DOS root directory failed, "),
			    myname);
			perror(nullstring);
			exit(3);
		}
	}
	/*
	 * Write the rest of the boot loader if it's longer than one sector.
	 * The clusters used are marked Bad in the FAT.
	 * No directory entry exists for this file (so that it cannot be
	 * deleted).
	 */
	if (bootlen && write(fd, bootloadr, bootlen) != bootlen) {
		(void) fprintf(stderr,
		    gettext("%s: write of MS-DOS boot sectors failed"), myname);
		perror(nullstring);
		exit(3);
	}
}

static void
write_NEC_DOS_label(int fd, char *doslabel)
{
	struct		bios_param_blk *bpb;
	ushort_t	fatsec;
	ushort_t	rdirsec;
	char		fat_rdir[1024];
	int		i, j, m = 1;
	uchar_t		bootsec_NEC[1024];
	char		*nullstring = "";

	uchar_t bios_param_NEC[30] = { 0xeb, 0x1c, 0x90, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0,  0x0,  0x0, 0x0, 0x4, 0x1, 0x1, 0x0,
				0x2, 0xc0, 0x0, 0xd0, 0x4, 0xfe, 0x2, 0x0,
				0x8, 0x0, 0x2, 0x0, 0x0, 0x0
	};

	uchar_t fatdir[32] = {   0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5,
			0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5,
			0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5,
			0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5, 0xe5

	};


	(void) memset(bootsec_NEC, (char)0, 1024);

	(void) memcpy(&bootsec_NEC, &bios_param_NEC, 30);

	bpb = (struct bios_param_blk *)&(bootsec_NEC[0xb]);
	if (write(fd, &bootsec_NEC[0], 1024) != 1024) {
		(void) fprintf(stderr, gettext(
		    "%s: write of NEC-DOS boot sector failed, "),
		    myname);
		perror(nullstring);
		exit(3);
	}
	(void) memset(fat_rdir, (char)0, 1024);
	fatsec = bpb->b_fatsec[0];
	for (i = 0; i < (int)bpb->b_nfat * (int)fatsec; ++i) {
		if ((i % (int)fatsec) == 0) {
			fat_rdir[0] = bpb->b_mediadescriptor;
			fat_rdir[1] = (char)0xff;
			fat_rdir[2] = (char)0xff;
			fat_rdir[3] = 0;
			fat_rdir[4] = 0;
			fat_rdir[5] = 0;
		} else {
			fat_rdir[0] = 0;
			fat_rdir[1] = 0;
			fat_rdir[2] = 0;
			fat_rdir[3] = 0;
			fat_rdir[4] = 0;
			fat_rdir[5] = 0;
		}
		if (write(fd, &fat_rdir[0], 1024) != 1024) {
			(void) fprintf(stderr,
/*CSTYLED*/
gettext("%s: write of NEC-DOS File Allocation Table failed, "), myname);
			perror(nullstring);
			exit(3);
		}
	}
#ifndef	sparc
	/* LINTED */
	rdirsec = (int)htols(bpb->b_rdirents[0]) * 32 /1024;
#else
	rdirsec = (int)htols(bpb->b_rdirents[0]) * 32 /1024;
#endif
	if (b_flag) {
		struct  timeval tv;
		struct	tm	*tp;
		ushort_t	dostime;
		ushort_t	dosday;

		/* the label can be no more than 11 characters */
		j = min(11, (int)strlen(doslabel));
		for (i = 0; i < j; i++) {
			fat_rdir[i] = uppercase(doslabel[i]);
		}
		for (; i < 11; i++) {
			fat_rdir[i] = ' ';
		}
		fat_rdir[0xb] = 0x28;
		(void) gettimeofday(&tv, (struct timezone *)0);
		tp = localtime(&tv.tv_sec);
		/* get the time & day into DOS format */
		dostime = tp->tm_sec / 2;
		dostime |= tp->tm_min << 5;
		dostime |= tp->tm_hour << 11;
		dosday = tp->tm_mday;
		dosday |= (tp->tm_mon + 1) << 5;
		dosday |= (tp->tm_year - 80) << 9;
		fat_rdir[0x16] = getlobyte(dostime);
		fat_rdir[0x17] = gethibyte(dostime);
		fat_rdir[0x18] = getlobyte(dosday);
		fat_rdir[0x19] = gethibyte(dosday);

		if (write(fd, &fat_rdir[0], 1024) != 1024) {
			(void) fprintf(stderr,
			    /*CSTYLED*/
gettext("%s: write of NEC-DOS root directory failed, "), myname);
			perror(nullstring);
			exit(3);
		}
		(void) memset(fat_rdir, (char)0, 512);
		i = 1;
	} else {
		i = 0;

		while (m < 1024) {
			(void) memcpy(&fat_rdir[m], &fatdir, 31);
			m = m + 32;
		}
	}
	for (; i < (int)rdirsec; ++i) {

		if (write(fd, &fat_rdir[0], 1024) != 1024) {
			(void) fprintf(stderr,
			    /*CSTYLED*/
gettext("%s: write of NEC-DOS root directory failed, "), myname);
			perror(nullstring);
			exit(3);
		}
	}
}
