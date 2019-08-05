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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/param.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/vnode.h>
#include <sys/fs/ufs_fsdir.h>
#include <sys/fs/ufs_inode.h>
#include <sys/fs/ufs_fs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/errno.h>
#include <sys/utsname.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <archives.h>
#include "volcopy.h"

#include <locale.h>

/*
 * main I/O information structure, contains information for the
 * source and destination files.
 */

struct file_info {
	char	*f_dev_p,	/* name of device */
		*f_vol_p;	/* volume name */
	int	f_bsize,	/* size to buffer I/O to */
		f_des,		/* file descriptor */
		f_dev;		/* device type (generic I/O library) */
} In, Out;


int	Sem_id[BUFCNT],	/* semaphore ids for controlling shared memory */
	Shm_id[BUFCNT],	/* shared memory identifier */
	*Cnts[BUFCNT];	/* an array of byte counts for shared memory */

char	Empty[BLKSIZ],	/* empty memory used to clear sections of memory */
	*Buf[BUFCNT];	/* buffer pointers (possibly to shared memory) */

struct sembuf	Sem_buf,	/* semaphore operation buffer */
		Rstsem_buf;	/* semaphore reset operation buffer */

typedef union {
	char		dummy[SBSIZE];
	struct fs	sblk;

} sb_un;

sb_un	isup, osup, tsup;

#define	Isup isup.sblk
#define	Osup osup.sblk

struct fs *Sptr = (struct fs *)&tsup.sblk;	/* super-block pointer */

char    *Ifname, *Ifpack, *Ofname, *Ofpack;
struct volcopy_label	V_labl;

char	From_vol[VVOLLEN + 1],
	To_vol[VVOLLEN + 1],
	*Fsys_p;

static	char	*nolabel = "";  /* used when there is no room for label */

int	Blk_cnt = 1,	/* Do I/O in (Blk_cnt * BLKSIZ) byte blocks */
	Blocks = 0,	/* Number of blocks transferred */
	Bpi = 0,
	Bufcnt,
	Bufflg = 0,
	Bufsz = BLKSIZ,
	Disk_cnt = 1,	/* Disk I/O (Disk_cnt * Blk_cnt * BLKSIZ) byte blocks */
	Drive_typ = 0,	/* Flag for special tape drive types */
	Eomflg = 0,
	Ipc = 0,
	Itape,
	M3b15 = 0,	/* Machine types, set to 1 for the machine */
	M3b2 = 0,	/* the command is executing on */
	Otape,
	Pid = -1,
	R_blks = 0,	/* Number of blocks per tape reel */
	R_cur = 1,	/* Current tape reel being processed */
	R_len = 0,	/* Length in feet of tape reels */
	R_num = 0,	/* Number of tape reels to be processed */
	Shell_esc = 1,	/* Allow shell after delete -nosh (3b15) can disable */
	Yesflg = 0;

void (*singal())();
long	Fs,
	Fstype;

time_t	Tvec;

FILE	*Devtty;

static void	getinfs(),
		getoutfs();

static char	*getfslabel(struct fs *);
static char	*getvolabel(struct fs *);
static void	prompt(int, const char *, ...);
static void	perr(int, const char *, ...);
static void	mklabel(void);
static void	get_mach_type(void);
static void	mem_setup(void);
static void	rprt(void);
static void	chgreel(struct file_info *, int);
static void	parent_copy(void);
static void	copy(void);
static void	flush_bufs(int);
static void	cleanup(void);

#ifdef LOG
static int	fslog(void);
#endif	/* LOG */

/*
 * g_init(), g_read(), g_write() originally came from libgenIO,
 * a totally obsolete device interface library, now deleted.
 * volcopy should be deleted too, since it doesn't work.
 */

#define	G_TM_TAPE	1	/* Tapemaster controller    */
#define	G_XY_DISK	3	/* xy disks		*/
#define	G_SD_DISK	7	/* scsi sd disk		*/
#define	G_XT_TAPE	8	/* xt tapes		*/
#define	G_SF_FLOPPY	9	/* sf floppy		*/
#define	G_XD_DISK	10	/* xd disks		*/
#define	G_ST_TAPE	11	/* scsi tape		*/
#define	G_NS		12	/* noswap pseudo-dev	*/
#define	G_RAM		13	/* ram pseudo-dev	*/
#define	G_FT		14	/* tftp			*/
#define	G_HD		15	/* 386 network disk	*/
#define	G_FD		16	/* 386 AT disk		*/
#define	G_FILE		28	/* file, not a device	*/
#define	G_NO_DEV	29	/* device does not require special treatment */
#define	G_DEV_MAX	30	/* last valid device type */

/*
 * g_init: Determine the device being accessed, set the buffer size,
 * and perform any device specific initialization. Since at this point
 * Sun has no system call to read the configuration, the major numbers
 * are assumed to be static and types are figured out as such. However,
 * as a rough estimate, the buffer size for all types is set to 512
 * as a default.
 */
static int
g_init(int *devtype, int *fdes)
{
	major_t maj;
	int bufsize;
	struct stat64 st_buf;
	struct statvfs64 stfs_buf;

	*devtype = G_NO_DEV;
	if (fstat64(*fdes, &st_buf) == -1)
		return (-1);
	if (!S_ISCHR(st_buf.st_mode) && !S_ISBLK(st_buf.st_mode)) {
		if (S_ISFIFO(st_buf.st_mode))
			bufsize = 512;
		else {
			/* find block size for this file system */
			*devtype = G_FILE;
			if (fstatvfs64(*fdes, &stfs_buf) < 0) {
				bufsize = -1;
				errno = ENODEV;
			} else {
				bufsize = stfs_buf.f_bsize;
			}
		}
		return (bufsize);
	}

	return (512);
}

/*
 * g_read: Read nbytes of data from fdes (of type devtype) and place
 * data in location pointed to by buf.  In case of end of medium,
 * translate (where necessary) device specific EOM indications into
 * the generic EOM indication of rv = -1, errno = ENOSPC.
 */
/* ARGSUSED */
static ssize_t
g_read(int devtype, int fdes, void *buf, size_t nbytes)
{
	ssize_t rv;

	rv = read(fdes, buf, nbytes);

	/* st devices return 0 when no space left */
	if ((rv == 0 && errno == 0) || (rv == -1 && errno == EIO)) {
		errno = ENOSPC;
		rv = -1;
	}

	return (rv);
}

/*
 * g_write: Write nbytes of data to fdes (of type devtype) from
 * the location pointed to by buf.  In case of end of medium,
 * translate (where necessary) device specific EOM indications into
 * the generic EOM indication of rv = -1, errno = ENOSPC.
 */
/* ARGSUSED */
static ssize_t
g_write(int devtype, int fdes, void *buf, size_t nbytes)
{
	ssize_t rv;

	rv = write(fdes, buf, nbytes);

	/* st devices return 0 when no more space left */
	if ((rv == 0 && errno == 0) || (rv == -1 && errno == EIO)) {
		errno = ENOSPC;
		rv = -1;
	}

	return (rv);
}

/*
 * filesystem copy with propagation of volume ID and filesystem name:
 *
 * volcopy [-options]  filesystem /dev/from From_vol /dev/to To_vol
 *
 * options are:
 *	-feet - length of tape
 *	-bpi  - recording density
 *	-reel - reel number (if not starting from beginning)
 *	-buf  - use double buffered i/o (if dens >= 1600 bpi)
 *	-block - Set the transfer block size to NUM physical blocks (512
 *	bytes on 3B2 and 3B15).  Note that an arbitrary block size might
 *	or might not work on a given system.  Also, the block size
 *	read from the header of an input tape silently overrides this.
 *	-nosh - Don't offer the user a shell after hitting break or delete.
 *	-r - Read NUM transfer blocks from the disk at once and write it
 *	to the output device one block at a time.  Intended only to
 *	boost the 3B15 EDFC disk to tape performance.  Disabled on 3B2.
 *	-a    - ask "y or n" instead of "DEL if wrong"
 *	-s    - inverse of -a, from/to devices are printed followed by `?'.
 *		User has 10 seconds to DEL if mistaken!
 *	-y    - assume "yes" response to all questions
 *
 * Examples:
 *
 * volcopy root /dev/rdsk/0s2 pk5 /dev/rdsk/1s2 pk12
 *
 * volcopy u3 /dev/rdsk/1s5 pk1 /dev/rmt/0m tp123
 *
 * volcopy u5 /dev/rmt/0m -  /dev/rdsk/1s5 -
 */

int
main(int argc, char *argv[])
{
	char c;
	int lfdes, altflg = 0, result, verify;
	long dist;
	char *align();
	void sigalrm(), sigint();
	struct stat stbuf;
	int cnt;

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	(void) get_mach_type();
	(void) signal(SIGINT, sigint);
	(void) signal(SIGALRM, sigalrm);
	In.f_bsize = Out.f_bsize = BLKSIZ;
	while (argc > 1 && argv[1][0] == '-') {
		if (EQ(argv[1], "-a", 2)) {
			altflg |= MINUSA;
		} else if (EQ(argv[1], "-e", 2)) {
			Eomflg = 1;
		} else if (EQ(argv[1], "-s", 2)) {
			altflg |= MINUSS;
		} else if (EQ(argv[1], "-y", 2)) {
			Yesflg++;
		} else if (EQ(argv[1], "-buf", 4)) {
			Bufflg++;
		} else if (EQ(argv[1], "-bpi", 4)) {
			if ((c = argv[1][4]) >= '0' && c <= '9')
				Bpi = getbpi(&argv[1][4]);
			else {
				++argv;
				--argc;
				Bpi = getbpi(&argv[1][0]);
			}
		} else if (EQ(argv[1], "-feet", 5)) {
			if ((c = argv[1][5]) >= '0' && c <= '9')
				R_len = atoi(&argv[1][5]);
			else {
				++argv;
				--argc;
				R_len = atoi(&argv[1][0]);
			}
		} else if (EQ(argv[1], "-reel", 5)) {
			if ((c = argv[1][5]) >= '0' && c <= '9')
				R_cur = atoi(&argv[1][5]);
			else {
				++argv;
				--argc;
				R_cur = atoi(&argv[1][0]);
			}
		} else if (EQ(argv[1], "-r", 2)) { /* 3b15 only */
			if ((c = argv[1][2]) >= '0' && c <= '9')
				Disk_cnt = atoi(&argv[1][2]);
			else {
				++argv;
				--argc;
				Disk_cnt = atoi(&argv[1][0]);
			}
			if (Disk_cnt == 0)
		perr(1, "volcopy: Need a non-zero value for the -r option\n");
		} else if (EQ(argv[1], "-block", 6)) { /* 3b15 only */
			if ((c = argv[1][6]) >= '0' && c <= '9')
				Blk_cnt = atoi(&argv[1][6]);
			else {
				++argv;
				--argc;
				Blk_cnt = atoi(&argv[1][0]);
			}
			if (Blk_cnt == 0)
	perr(1, "volcopy: Need a non-zero value for the -block option\n");
		} else if (EQ(argv[1], "-nosh", 5)) { /* 3b15 only */
			Shell_esc = 0;
		} else
			perr(1, "<%s> invalid option\n", argv[1]);
		++argv;
		--argc;
	} /* argv[1][0] == '-' */

	Devtty = fopen("/dev/tty", "r");
	if ((Devtty == NULL) && !isatty(0))
		Devtty = stdin;
	time(&Tvec);

	if (Eomflg && R_len)
		perr(9, "volcopy: -e and -feet are mutually exclusive\n");
	if ((altflg & MINUSA) && (altflg & MINUSS))
		perr(9, "volcopy: -a and -s are mutually exclusive\n");
	if (argc != 6) /* if mandatory fields not present */
		perr(9, "ufs usage: volcopy [-F ufs] [generic options] \
fsname /devfrom volfrom /devto volto\n");
	if (!(altflg & MINUSA)) /* -a was not specified, use default (-s) */
		altflg |= MINUSS;

	In.f_dev_p = argv[DEV_IN];
	Out.f_dev_p = argv[DEV_OUT];
	strncpy(To_vol, argv[VOL_OUT], VVOLLEN);
	To_vol[VVOLLEN] = '\0';
	Out.f_vol_p = &To_vol[0];
	strncpy(From_vol, argv[VOL_IN], VVOLLEN);
	From_vol[VVOLLEN] = '\0';
	In.f_vol_p = &From_vol[0];
	Fsys_p = argv[FIL_SYS];

	if ((In.f_des = open(In.f_dev_p, O_RDONLY)) < 1)
		perr(10, "%s: cannot open\n", In.f_dev_p);
	if ((Out.f_des = open(Out.f_dev_p, O_RDONLY)) < 1)
		perr(10, "%s: cannot open\n", Out.f_dev_p);

	if (fstat(In.f_des, &stbuf) < 0 || (stbuf.st_mode & S_IFMT) != S_IFCHR)
		perr(10, "From device not character-special\n");
	if (fstat(Out.f_des, &stbuf) < 0 || (stbuf.st_mode & S_IFMT) != S_IFCHR)
		perr(10, "To device not character-special\n");

	if ((Itape = tapeck(&In, INPUT)) == 1)
		R_blks = V_labl.v_reelblks;
	Otape = tapeck(&Out, OUTPUT);
	if (Otape && Itape)
		perr(10, "Use dd(1) command to copy tapes\n");
	(void) mem_setup();
	if (Bufflg && !Ipc)
		perr(1, "The -buf option requires ipc\n");
	if (!Itape && !Otape)
		R_cur = 1;
	if (R_cur == 1 || !Itape) {
		/* read in superblock */
		verify = 0;
		(void) getinfs(In.f_dev, In.f_des, Sptr);

		if ((Sptr->fs_magic != FS_MAGIC) &&
		    (Sptr->fs_magic != MTB_UFS_MAGIC))
			perr(10, "File System type unknown--get help\n");

		if (Sptr->fs_magic == FS_MAGIC &&
		    (Sptr->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
		    Sptr->fs_version != UFS_VERSION_MIN))
			perr(10, "Unrecognized version of UFS--get help\n");

		if (Sptr->fs_magic == MTB_UFS_MAGIC &&
		    (Sptr->fs_version > MTB_UFS_VERSION_1 ||
		    Sptr->fs_version < MTB_UFS_VERSION_MIN))
			perr(10, "Unrecognized version of UFS--get help\n");

		(void) memcpy(&Isup, Sptr, Sptr->fs_sbsize);
		Ifname = getfslabel(&Isup);
		Ifpack = getvolabel(&Isup);
		Fs = Sptr->fs_size * Sptr->fs_nspf;
	}  /* R_cur == 1 || !Itape */

	/* read in superblock */
	verify = !Otape || (altflg & MINUSS);
	(void) getoutfs(Out.f_dev, Out.f_des, Sptr, verify);

	if ((Sptr->fs_magic == FS_MAGIC) || (Sptr->fs_magic == MTB_UFS_MAGIC)) {
		(void) memcpy(&Osup, Sptr, Sptr->fs_sbsize);
		Ofname = getfslabel(&Osup);
		Ofpack = getvolabel(&Osup);
	} else  {
		int i;

		/* out vol does not contain a ufs file system */
		/* stuff let over from Isup */
		(void) memcpy(&Osup, &Isup, Isup.fs_sbsize);
		Ofname = getfslabel(&Osup);
		Ofpack = getvolabel(&Osup);
		/* wipe out the fs name and pack name for warning purposes */
		for (i = 0; i < 6; i++) Ofname[i] = ' ';
		for (i = 0; i < 6; i++) Ofpack[i] = ' ';
	}

	if (Itape) {
		if (R_cur != 1) {
			(void) printf(gettext(
				"\nvolcopy: IF REEL 1 HAS NOT BEEN RESTORED,"));
			(void) printf(gettext(
				" STOP NOW AND START OVER ***\07\n"));
			if (!ask(" Continue? ")) {
				cleanup();
				exit(31+9);
			}
			strncpy(Ifname, Fsys_p, 6);
			strncpy(Ifpack, In.f_vol_p, 6);
		}
		if (V_labl.v_reel != R_cur || V_labl.v_reels != R_num)
	prompt(1, "Tape disagrees: Reel %d of %d : looking for %d of %d\n",
				V_labl.v_reel, V_labl.v_reels, R_cur, R_num);
	} else if (Otape) {
		strncpy(V_labl.v_volume, Out.f_vol_p, 6);
		strncpy(Ofpack, Out.f_vol_p, 6);
		strncpy(Ofname, Fsys_p, 6);
		if (!Eomflg) {
			R_num = Fs / R_blks + ((Fs % R_blks) ? 1 : 0);
			(void) printf(gettext(
				"You will need %d reels.\n"), R_num);
			(void) printf(gettext(
		"(\tThe same size and density is expected for all reels)\n"));
		}
	}
	if (NOT_EQ(Fsys_p, Ifname, 6)) {
		verify = !Otape || (altflg & MINUSS);
		prompt(verify,
			"arg. (%.6s) doesn't agree with from fs. (%.6s)\n",
			Fsys_p, Ifname);
	}
	if (NOT_EQ(In.f_vol_p, "-", 6) && NOT_EQ(In.f_vol_p, Ifpack, 6)) {
		verify = !Otape || (altflg & MINUSS);
	prompt(verify, "arg. (%.6s) doesn't agree with from vol.(%.6s)\n",
			In.f_vol_p, Ifpack);
	}

	if (*In.f_vol_p == '-')
		In.f_vol_p = Ifpack;
	if (*Out.f_vol_p == '-')
		Out.f_vol_p = Ofpack;

	if (R_cur == 1 && (Osup.fs_time + _2_DAYS) > Isup.fs_time) {
		time_t t;

		verify = altflg & MINUSS;
		t = (time_t)Osup.fs_time;
		prompt(verify, "%s less than 48 hours older than %s\n"
		    "To filesystem dated:  %s",
		    Out.f_dev_p, In.f_dev_p, ctime(&t));
	}
	if (NOT_EQ(Out.f_vol_p, Ofpack, 6)) {
		prompt(1, "arg.(%.6s) doesn't agree with to vol.(%.6s)\n",
			Out.f_vol_p, Ofpack);
		strncpy(Ofpack, Out.f_vol_p, 6);
	}
	if (Isup.fs_size > Osup.fs_size && !Otape)
		prompt(1, "from fs larger than to fs\n");
	if (!Otape && NOT_EQ(Ifname, Ofname, 6)) {
		verify = altflg & MINUSS;
	prompt(verify, "warning! from fs(%.6s) differs from to fs(%.6s)\n",
			Ifname, Ofname);
	}

	(void) printf(gettext("From: %s, to: %s? "), In.f_dev_p, Out.f_dev_p);
	if (!(altflg & MINUSA)) {
		(void) printf(gettext("(DEL if wrong)\n"));
		sleep(10);
	} else if (!ask("(y or n) "))
		perr(10, "\nvolcopy: STOP\n");
	close(In.f_des);
	close(Out.f_des);
	sync();
	In.f_des = open(In.f_dev_p, O_RDONLY);
	Out.f_des = open(Out.f_dev_p, O_WRONLY);
	errno = 0;
	if (g_init(&In.f_dev, &In.f_des) < 0 ||
	    g_init(&Out.f_dev, &Out.f_des) < 0)
		perr(1, "volcopy: Error %d during initialization\n", errno);
	if (Itape) {
		errno = 0;
		if (g_read(In.f_dev, In.f_des, &V_labl, sizeof (V_labl)) <
		    sizeof (V_labl))
			perr(10, "Error while reading label\n");
	} else if (Otape) {
		V_labl.v_reels = R_num;
		V_labl.v_reel = R_cur;
		V_labl.v_time = Tvec;
		V_labl.v_reelblks = R_blks;
		V_labl.v_blksize = BLKSIZ * Blk_cnt;
		V_labl.v_nblocks = Blk_cnt;
		V_labl.v_offset = 0L;
		V_labl.v_type = T_TYPE;
		errno = 0;
		if (g_write(Out.f_dev, Out.f_des, &V_labl, sizeof (V_labl)) <
		    sizeof (V_labl))
			perr(10, "Error while writing label\n");
	}
	if (R_cur > 1) {
		if (!Eomflg) {
			Fs = (R_cur - 1) * actual_blocks();
			lfdes = Otape ? In.f_des : Out.f_des;
			dist = (long)(Fs * BLKSIZ);
		} else { /* Eomflg */
			if (Otape)
		perr(1, "Cannot use -reel with -e when copying to tape\n");
			lfdes = Out.f_des;
			dist = (long)(V_labl.v_offset * BLKSIZ);
			Fs = V_labl.v_offset;
		}
		if (lseek(lfdes, dist, 0) < 0)
			perr(1, "Cannot lseek()\n");
		Sptr = Otape ? &Isup : &Osup;
		if ((Sptr -> fs_magic != FS_MAGIC) &&
		    (Sptr -> fs_magic != MTB_UFS_MAGIC))
			perr(10, "File System type unknown--get help!\n");

		if (Sptr->fs_magic == FS_MAGIC &&
		    (Sptr->fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
		    Sptr->fs_version != UFS_VERSION_MIN))
			perr(10, "Unrecognized version of UFS--get help\n");

		if (Sptr->fs_magic == MTB_UFS_MAGIC &&
		    (Sptr->fs_version > MTB_UFS_VERSION_1 ||
		    Sptr->fs_version < MTB_UFS_VERSION_MIN))
			perr(10, "Unrecognized version of UFS--get help\n");

		Fs = (Sptr->fs_size * Sptr->fs_nspf) - Fs;
	}
	if (Itape || Otape)
		rprt();

	if (Ipc) {
		parent_copy();
		(void) cleanup();
	} else
		copy();
	(void) printf(gettext("  END: %ld blocks.\n"), Blocks);

#ifdef LOG
	fslog();
#endif
	if (Blocks)
		return (0);
	return (31+1);		/* failed.. 0 blocks */
}

/*
 * sigalrm: catch alarm signals.
 */

void
sigalrm()
{
	void (*signal())();

	(void) signal(SIGALRM, sigalrm);
}

/*
 * sigsys: catch illegal system calls to determine if IPC is available.
 */

void
sigsys()
{

	Ipc = 0;
}

/*
 * sigint: catch interrupts and prompt user for shell or to quit.
 */

void
sigint()
{
	void (*signal())();
	extern char **environ;
	int tmpflg, i = 0, ps1 = -1, ps2 = -1;

	tmpflg = Yesflg; /* override yesflag for duration of interrupt */
	Yesflg = 0;
	if (Shell_esc && ask("Want Shell?   ")) {
		if (!fork()) {
			/* both PS1 and PS2 must be exported */
			while (environ[i]) {
				if (EQ(environ[i], "PS1", 3))
					ps1 = i;
				if (EQ(environ[i], "PS2", 3))
					ps2 = i;
				i++;
			}
			if (ps1 >= 0 && ps2 >= 0)
				environ[ps1] = environ[ps2];
			(void) signal(SIGINT, SIG_DFL);
			execl("/usr/bin/sh", "/usr/bin/sh", 0);
		} else { /* parent */
			(void) signal(SIGINT, SIG_IGN);
			wait((int *)0);
		}
	} else if (ask("Want to quit?    ")) {
		if (Pid > 0)
			kill(Pid, 9);
		(void) cleanup(); /* ipc */
		exit(31+2);
	}
	(void) signal(SIGINT, sigint);
	Yesflg = tmpflg; /* reset Yesflg */
}

/*
 * actual_blocks: Calculate the actual number of blocks written to
 * the tape (will differ from V_labl.v_reelblks if v_reelblks is not
 * an even multiple of the blocking factor Blk_cnt).
 */

int
actual_blocks()
{

	if (R_blks % Blk_cnt)
		return (((R_blks / Blk_cnt) + 1) * Blk_cnt);
	else
		return (R_blks);
}

/*
 * get_mach_type: Determine what machine this is executing on.
 */

static void
get_mach_type(void)
{
	struct utsname utsinfo;

	errno = 0;
	if (uname(&utsinfo) < 0)
		perr(1, "Unable to determine machine type\n");
	if (strcmp(utsinfo.machine, "3B2") == 0)
		M3b2 = 1;
	else if (strcmp(utsinfo.machine, "3B15") == 0)
		M3b15 = 1;
}

/*
 * mem_setup: Determine memory needs and check for IPC.  If IPC is available,
 * used shared memory and semaphores to increase performance.  If no IPC,
 * get normal memory and only use one process.
 */

static void
mem_setup(void)
{
	void (*signal())();
	int cnt, num, size;
	char *align();

	union semun {
		int val;
		struct semid_ds *buf;
		ushort_t *array;
	} sem_arg;

	if (Blk_cnt == 1) {
		switch (Drive_typ) {
		case A_DRIVE:
			Blk_cnt = 32;
			break;
		case C_DRIVE:
			Blk_cnt = 10;
			break;
		case K_DRIVE:
			Blk_cnt = 4;
			break;
		case T_DRIVE:
			if (Bpi == 6250)
				Blk_cnt = 50;
			else
				Blk_cnt = 10;
			break;
		default:
			if (M3b15) {
				if (Itape || Otape)
					Blk_cnt = 16;
			} else {
				if (Otape || Itape) {
					if (Bpi == 6250)
						Blk_cnt = 50;
					else
						Blk_cnt = 10;
				}
			}
			break;
		} /* Drive_typ */
	} /* Blk_cnt == 1 */
	if (Blk_cnt > 1) /* user overrode g_init */
		In.f_bsize = Out.f_bsize = Blk_cnt * BLKSIZ;
	In.f_bsize = (!Itape) ? Disk_cnt * In.f_bsize : In.f_bsize;
	Out.f_bsize = (!Otape) ? Disk_cnt * Out.f_bsize : Out.f_bsize;
	Bufsz = find_lcm(In.f_bsize, Out.f_bsize);
	num = _128K / (Bufsz + sizeof (int));
	Bufsz *= num;
	size = Bufsz + sizeof (int);
	/* test to see if ipc is available, the shmat should fail with EINVAL */
	(void) signal(SIGSYS, sigsys);
	errno = 0;
	if (Ipc) {
		if ((int)shmat(0, (char *)NULL, 0) < 0 && errno != EINVAL)
			Ipc = 0; /* something went wrong */
	}
	if (Ipc) { /* ipc is available */
		Bufcnt = 2;
		sem_arg.val = 0;
		for (cnt = 0; cnt < BUFCNT; cnt++) {
			errno = 0;
			if ((Sem_id[cnt] = semget(IPC_PRIVATE, 1, 0)) < 0)
				perr(1, "Error allocating semaphores: %d",
				    errno);
			if (semctl(Sem_id[cnt], 0, SETVAL, sem_arg) < 0)
				perr(1, "Error setting semaphores: %d", errno);
			if ((Shm_id[cnt] = shmget(IPC_PRIVATE, size, 0)) < 0)
				perr(1, "Error allocating shared memory: %d",
				    errno);
			if ((Buf[cnt] = shmat(Shm_id[cnt], 0, 0)) == (void *)-1)
				perr(1, "Error attaching shared memory: %d",
				    errno);
			if (shmctl(Shm_id[cnt], SHM_LOCK, 0) < 0)
				perr(0, "Error locking in shared memory: %d",
				    errno);
			Cnts[cnt] = (int *)(Buf[cnt] + Bufsz);
		}
	} else { /* ipc is not available */
		Bufcnt = 1;
		if ((Buf[0] = align(size)) == (char *)NULL)
			perr(1, "Out of memory\n");
		Cnts[0] = (int *)(Buf[0] + Bufsz);
		*Cnts[0] = 0;
	}
}

/*
 * prompt: Prompt the user for verification.
 */

static void
prompt(int verify, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (fmt != NULL)
		(void) vfprintf(stdout, gettext(fmt), ap);
	va_end(ap);
	if (verify) {
		(void) fprintf(stdout, gettext("Type 'y' to override:    "));
		if (!ask("")) {
			cleanup();
			exit(31+9);
		}
	}
}

/*
 * ask: Ask the user a question and get the answer.
 */

int
ask(char *s)
{
	char ans[12];

	(void) printf(gettext(s));
	if (Yesflg) {
		(void) printf(gettext("YES\n"));
		return (1);
	}
	ans[0] = '\0';
	fgets(ans, 10, Devtty);
	for (;;) {
		switch (ans[0]) {
			case 'a':
			case 'A':
				if (Pid > 0) /* parent with a child */
					kill(Pid, 9);
				cleanup();
				exit(31+1);
			case 'y':
			case 'Y':
				return (1);
			case 'n':
			case 'N':
				return (0);
			default:
				(void) printf(gettext("\n(y or n)?"));
				fgets(ans, 10, Devtty);
		}
	}
}

/*
 * align: Align a malloc'd memory section on a page boundry.
 */

char *
align(int size)
{
	int pad;

	if ((pad = ((int)malloc(0) & (PAGESIZE-1))) > 0) {
		pad = PAGESIZE - pad;
		if (malloc(pad) == (char *)NULL)
			return ((char *)NULL);
	}
	return (malloc((unsigned)size));
}

/*
 * child_copy:  Using IPC, this child process reads from shared memory
 * and writes to the destination file system.
 */

int
child_copy()
{
	int rv, cur_buf, left, have, tpcnt;
	char *c_p;

	(void) signal(SIGINT, SIG_IGN);
	Sem_buf.sem_op = -1;
	(void) close(In.f_des);
	if (Otape && !Eomflg)
		tpcnt = actual_blocks() * BLKSIZ;
	cur_buf = 0;
	for (;;) {
		if (semop(Sem_id[cur_buf], &Sem_buf, 1) < 0)
			perr(1, "semaphore operation error %d\n", errno);
		left = *Cnts[cur_buf];
		if (!left)
			break;
		c_p = Buf[cur_buf];
		rv = 0;
		while (left) {
			have = (left < Out.f_bsize) ? left : Out.f_bsize;
			if (!Eomflg && Otape) {
				if (!tpcnt) {
					(void) chgreel(&Out, OUTPUT);
					tpcnt = actual_blocks() * BLKSIZ;
				}
				have = (tpcnt < have) ? tpcnt : have;
			}
			errno = 0;
			if ((rv = g_write(Out.f_dev, Out.f_des, c_p, have)) <
			    0) {
				if (Eomflg && errno == ENOSPC) {
					(void) chgreel(&Out, OUTPUT);
					continue;
				} else
					perr(1, "I/O error %d on write\n",
					    errno);
			}
			left -= rv;
			c_p += rv;
			V_labl.v_offset += rv;
			if (!Eomflg && Otape)
				tpcnt -= rv;
		}
		if (semop(Sem_id[cur_buf], &Sem_buf, 1) < 0)
			perr(2, "semaphore operation error %d\n", errno);
		cur_buf = (cur_buf + 1) % BUFCNT;
	}
	exit(0);
}

/*
 * parent_copy:  Using shared memory, the parent process reads fromt the
 * source file system and writes to shared memory.
 */

static void
parent_copy(void)
{
	int rv, left, have, tpcnt, cur_buf;
	char *c_p;
	int eom = 0, xfer_cnt = Fs * BLKSIZ;

	Sem_buf.sem_num = 0;
	Sem_buf.sem_flg = 0;
	if ((Pid = fork()) == 0)
		child_copy(); /* child does not return */
	(void) close(Out.f_des);
	Rstsem_buf.sem_num = 0;
	Rstsem_buf.sem_flg = 0;
	Rstsem_buf.sem_op = 2;
	Sem_buf.sem_op = 0;
	cur_buf = 0;
	if (Itape && !Eomflg)
		tpcnt = actual_blocks() * BLKSIZ;
	while (xfer_cnt) {
		if (semop(Sem_id[cur_buf], &Sem_buf, 1) < 0)
			perr(1, "Semaphore operation error %d\n", errno);
		c_p = Buf[cur_buf];
		left = Bufsz;
		rv = 0;
		while (left >= In.f_bsize && xfer_cnt) {
			have = (xfer_cnt < In.f_bsize) ? xfer_cnt : In.f_bsize;
			if (!Eomflg && Itape) {
				if (!tpcnt) {
					*Cnts[cur_buf] = Bufsz - left;
					(void) flush_bufs(cur_buf);
					(void) chgreel(&In, INPUT);
					tpcnt = actual_blocks() * BLKSIZ;
					cur_buf = (cur_buf == 0) ? 1 : 0;
					eom = 1;
					break;
				}
				have = (tpcnt < have) ? tpcnt : have;
			}
			errno = 0;
			if ((rv = g_read(In.f_dev, In.f_des, c_p, have)) < 0) {
				if (Eomflg && errno == ENOSPC) {
					*Cnts[cur_buf] = Bufsz - left;
					(void) flush_bufs(cur_buf);
					(void) chgreel(&In, INPUT);
					cur_buf = (cur_buf == 0) ? 1 : 0;
					eom = 1;
					break;
				} else
					perr(1, "I/O error %d on read\n",
					    errno);
			}
			left -= rv;
			c_p += rv;
			xfer_cnt -= rv;
			if (!Eomflg && Itape)
				tpcnt -= rv;
		}
		if (eom > 0) {
			eom = 0;
			if (Eomflg)
				xfer_cnt -= rv;
			else if (Itape)
				tpcnt -= rv;
			continue;
		}
		*Cnts[cur_buf] = Bufsz - left;
		Blocks += *Cnts[cur_buf];
		if (semop(Sem_id[cur_buf], &Rstsem_buf, 1) < 0)
			perr(2, "Semaphore operation error %d\n", errno);
		cur_buf = (cur_buf == 0) ? 1 : 0;
	}
	if (semop(Sem_id[cur_buf], &Sem_buf, 1) < 0)
		perr(3, "Semaphore operation error %d\n", errno);
	*Cnts[cur_buf] = 0;
	if (semop(Sem_id[cur_buf], &Rstsem_buf, 1) < 0)
		perr(4, "Semaphore operation error %d\n", errno);
	wait((int *)NULL);
	Blocks /= BLKSIZ;
}

/*
 * copy:  Copy without shared memory.  The process reads from the source
 * filesystem and writes to the destination filesystem.
 */

static void
copy(void)
{
	int rv, left, have, tpcnt = 1, xfer_cnt = Fs * BLKSIZ;
	char *c_p;

	if ((Itape || Otape) && !Eomflg)
		tpcnt = actual_blocks() * BLKSIZ;
	while (xfer_cnt) {
		c_p = (char *)(Buf[0] + *Cnts[0]);
		left = Bufsz - *Cnts[0];
		rv = 0;
		while (left >= In.f_bsize && xfer_cnt) {
			have = (xfer_cnt < In.f_bsize) ? xfer_cnt : In.f_bsize;
			if (!Eomflg && Itape) {
				if (!tpcnt) {
					*Cnts[0] = Bufsz - left;
					(void) chgreel(&In, INPUT);
					tpcnt = actual_blocks() * BLKSIZ;
					break;
				}
				have = (tpcnt < have) ? tpcnt : have;
			}
			errno = 0;
			if ((rv = g_read(In.f_dev, In.f_des, c_p, have)) < 0) {
				if (Eomflg && errno == ENOSPC) {
					(void) chgreel(&In, INPUT);
					break;
				} else
					perr(1, "I/O error %d on read\n",
					    errno);
			}
			left -= rv;
			c_p += rv;
			xfer_cnt -= rv;
			if (!Eomflg && Itape)
				tpcnt -= rv;
		} /* left >= In.f_bsize && xfer_cnt */
		*Cnts[0] = Bufsz - left;
		Blocks += *Cnts[0];
		c_p = Buf[0];
		left = *Cnts[0];
		rv = 0;
		while (left >= Out.f_bsize || (left > 0 && !xfer_cnt)) {
			have = (left < Out.f_bsize) ? left : Out.f_bsize;
			if (!Eomflg && Otape) {
				if (!tpcnt) {
					(void) chgreel(&Out, OUTPUT);
					tpcnt = actual_blocks() * BLKSIZ;
				}
				have = (tpcnt < have) ? tpcnt : have;
			}
			errno = 0;
			if ((rv = g_write(Out.f_dev, Out.f_des, c_p, have)) <
			    0) {
				if (Eomflg && errno == ENOSPC) {
					(void) chgreel(&Out, OUTPUT);
					continue;
				} else
					perr(1, "I/O error %d on write\n",
					    errno);
			}
			left -= rv;
			c_p += rv;
			V_labl.v_offset += rv;
			if (!Eomflg && Otape)
				tpcnt -= rv;
		} /* left >= Out.f_bsize */
		if (left) {
			(void) memcpy(Buf[0], c_p, left);
			Blocks -= left;
		}
		*Cnts[0] = left;
	} /* xfer_cnt */
	Blocks /= BLKSIZ;
}

/*
 * flush_bufs:  Permit child to read the remaining data from the
 * buffer before prompting user for end-of-media.
 */

static void
flush_bufs(int buffer)
{

	Blocks += *Cnts[buffer];
	if (semop(Sem_id[buffer], &Rstsem_buf, 1) < 0)
		perr(5, "Semaphore operation error %d\n", errno);
	if (semop(Sem_id[buffer], &Sem_buf, 1) < 0)
		perr(6, "Semaphore operation error %d\n", errno);
}

/*
 * cleanup:  Clean up shared memory and semaphore resources.
 */

static void
cleanup(void)
{
	int cnt;

	if (Ipc) {
		for (cnt = 0; cnt < BUFCNT; cnt++) {
			(void) semctl(Sem_id[cnt], IPC_RMID, 0);
			(void) shmctl(Shm_id[cnt], IPC_RMID, 0);
		}
	}
}

/*
 * find_lcm: Find the lowest common multiple of two numbers.  This is used
 * to determine the buffer size that should be malloc(3)'d such that the
 * input and output data blocks can both fit evenly into the buffer.
 */

int
find_lcm(int sz1, int sz2)
{
	int inc, lcm, small;

	if (sz1 < sz2) {
		lcm = inc = sz2;
		small = sz1;
	} else { /* sz1 >= sz2 */
		lcm = inc = sz1;
		small = sz2;
	}
	while (lcm % small != 0)
		lcm += inc;
	return (lcm);
}

/*
 * Determine bpi information from drive names.
 */

int
getbpi(char *inp)
{

/*
 * Kludge to recognize Accellerated Tape Controller usage from
 * letter 'a' or 'A' following density given by user.
 *
 * Kludge to recognize 3B15 Compatibility Mode from
 * letter 'c' or 'C' following density given by user.
 */
	if (M3b15) {
		if (inp[4] == 'a' || inp[4] == 'A') {
			Drive_typ = A_DRIVE;
			inp[4] = '\0';
		}
		if (inp[4] == 'c' || inp[4] == 'C') {
			Drive_typ = C_DRIVE;
			inp[4] = '\0';
		}
	}
	return (atoi(inp));
}

/*
 * blks_per_ft:  Determine the number of blocks per foot of tape.
 * Inter-block gap (dgap) is 0.3 in.
 */

int
blks_per_ft(double disc)
{
	double dcnt = Blk_cnt, dBpi = Bpi, dsiz = BLKSIZ, dgap = 0.3;

	return ((int)(dcnt / (((dcnt * dsiz / dBpi) + dgap) / 12.0) * disc));
}

/*
 * tapeck:  Arbitrary block size.  Determine the number of physical blocks per
 * foot of tape, including the inter-block gap, and the possibility of a short
 * tape.  Assume the usable portion of a tape is 85% of its length for small
 * block sizes and 88% for large block sizes.
 */

int
tapeck(struct file_info *f_p, int dir)
{
	int again = 1, verify, old_style, new_style;
	char resp[16];

	errno = 0;
	if ((f_p->f_bsize = g_init(&f_p->f_dev, &f_p->f_des)) < 0)
		perr(1, "volcopy: Error %d during initialization\n", errno);
	if ((f_p->f_dev != G_TM_TAPE) && (f_p->f_dev != G_XT_TAPE) &&
	    (f_p->f_dev != G_ST_TAPE))
		return (0);
	V_labl.v_magic[0] = '\0';	/* scribble on old data */
	alarm(5);
	if (g_read(f_p->f_dev, f_p->f_des, &V_labl, sizeof (V_labl)) <= 0) {
		if (dir == INPUT)
			perror("input tape");
		else
			perror("output tape");
	}
	alarm(0);
	if (V_labl.v_reel == '\0' && dir == INPUT)
		perr(9, "Input tape is empty\n");
	else {
		old_style = strncmp(V_labl.v_magic, "Volcopy", 7) == 0;
		new_style = strncmp(V_labl.v_magic, "VOLCOPY", 7) == 0;
		if (!old_style && !new_style) {
			verify = (dir == INPUT) ? 0 : 1;
			prompt(verify, "Not a labeled tape\n");
			if (dir == INPUT)
				perr(10, "Input tape not made by volcopy\n");
			mklabel();
			strncpy(V_labl.v_volume, f_p->f_vol_p, 6);
			Osup.fs_time = 0;
		} else if (new_style) {
			Eomflg = (dir == INPUT) ? 1 : Eomflg;
			if (!Eomflg)
				strncpy(V_labl.v_magic, "Volcopy", 7);
		}
	}
	if (*f_p->f_vol_p == '-')
		strncpy(f_p->f_vol_p, V_labl.v_volume, 6);
	else if (NOT_EQ(V_labl.v_volume, f_p->f_vol_p, 6)) {
		prompt(1, "Header volume(%.6s) does not match (%s)\n",
			V_labl.v_volume, f_p->f_vol_p);
		strncpy(V_labl.v_volume, f_p->f_vol_p, 6);
	}
	if (dir == INPUT) {
		Bpi = V_labl.v_dens;
		if (!Eomflg) {
			R_len = V_labl.v_length;
			R_num = V_labl.v_reels;
		}
		if (M3b15) {
			if (V_labl.v_type == T_TYPE) {
				if (V_labl.v_nblocks == 0) {
					Blk_cnt = 10;
					Drive_typ = C_DRIVE;
				} else
					Blk_cnt = V_labl.v_nblocks;
				if (V_labl.v_nblocks == 32)
					Drive_typ = A_DRIVE;
				else
					Drive_typ = 0;
			} else {
				Drive_typ = 0;
				Blk_cnt = 10;
				Drive_typ = C_DRIVE;
			}
		}
	}
	while (!Eomflg && (R_len <= 0 || R_len > 3600)) {
		(void) printf(gettext(
			"Enter size of reel in feet for <%s>:   "),
				f_p->f_vol_p);
		fgets(resp, 10, Devtty);
		R_len = atoi(resp);
		if (R_len > 0 && R_len <= 3600)
			break;
		perr(0, "Size of reel must be > 0, <= 3600\n");
	}
	while (!Eomflg && again) {
		again = 0;
		if (!Bpi) {
			(void) printf(gettext(
				"Tape density? (i.e., 800 | 1600 | 6250)?   "));
			fgets(resp, 10, Devtty);
			Bpi = getbpi(resp);
		}
		switch (Bpi) {
		case 800:
			R_blks = Ft800x10 * R_len;
			break;
		case 1600:
			if (M3b15) {
				switch (Blk_cnt) {
				case 1: /* Writing a new tape */
					if (Drive_typ == A_DRIVE)
						R_blks = Ft1600x32 * R_len;
					else if (Drive_typ == C_DRIVE)
						R_blks = Ft1600x10 * R_len;
					else
						R_blks = Ft1600x16 * R_len;
					break;
				case 10:
					R_blks = Ft1600x10 * R_len;
					break;
				case 16:
					R_blks = Ft1600x16 * R_len;
					break;
				case 32:
					R_blks = Ft1600x32 * R_len;
					break;
				default:
					if (Blk_cnt < 32)
						R_blks = blks_per_ft(0.85);
					else
						R_blks = blks_per_ft(0.88);
					R_blks *= R_len;
				} /* Blk_cnt */
			} else
				R_blks = Ft1600x10 * R_len;
			break;
		case 6250:
			if (M3b15) {
				switch (Blk_cnt) {
				case 1: /* Writing a new tape */
					if (Drive_typ == A_DRIVE)
						R_blks = Ft6250x32 * R_len;
					else if (Drive_typ == C_DRIVE)
						R_blks = Ft6250x10 * R_len;
					else
						R_blks = Ft6250x16 * R_len;
					break;
				case 10:
					R_blks = Ft6250x10 * R_len;
					break;
				case 16:
					R_blks = Ft6250x16 * R_len;
					break;
				case 32:
					R_blks = Ft6250x32 * R_len;
					break;
				default:
					if (Blk_cnt < 32)
						R_blks = blks_per_ft(0.85);
					else
						R_blks = blks_per_ft(0.88);
					R_blks *= R_len;
				}
			} else
				R_blks = Ft6250x50 * R_len;
			break;
		default:
			perr(0, "Bpi must be 800, 1600, or 6250\n");
			Bpi = 0;
			again = 1;
		} /* Bpi */
	} /* again */
	(void) printf(gettext("\nReel %.6s"), V_labl.v_volume);
	if (!Eomflg) {
		V_labl.v_length = R_len;
		V_labl.v_dens = Bpi;
		(void) printf(gettext(", %d feet, %d BPI\n"), R_len, Bpi);
	} else
		(void) printf(gettext(", ? feet\n"));
	return (1);
}

/*
 * hdrck:  Look for and validate a volcopy style tape label.
 */

int
hdrck(int dev, int fd, char *tvol)
{
	int verify;
	struct volcopy_label tlabl;

	alarm(15); /* don't scan whole tape for label */
	errno = 0;
	if (g_read(dev, fd, &tlabl, sizeof (tlabl)) != sizeof (tlabl)) {
		alarm(0);
		verify = Otape;
		prompt(verify, "Cannot read header\n");
		if (Itape)
			close(fd);
		else
			strncpy(V_labl.v_volume, tvol, 6);
		return (verify);
	}
	alarm(0);
	V_labl.v_reel = tlabl.v_reel;
	if (NOT_EQ(tlabl.v_volume, tvol, 6)) {
		perr(0, "Volume is <%.6s>, not <%s>.\n", tlabl.v_volume, tvol);
		if (ask("Want to override?   ")) {
			if (Otape)
				strncpy(V_labl.v_volume, tvol, 6);
			else
				strncpy(tvol, tlabl.v_volume, 6);
			return (1);
		}
		return (0);
	}
	return (1);
}

/*
 * mklabel:  Zero out and initialize a volcopy label.
 */

static void
mklabel(void)
{

	(void) memcpy(&V_labl, Empty, sizeof (V_labl));
	if (!Eomflg)
		(void) strcpy(V_labl.v_magic, "Volcopy");
	else
		(void) strcpy(V_labl.v_magic, "VOLCOPY");
}

/*
 * rprt:  Report activity to user.
 */

static void
rprt(void)
{

	if (Itape)
		(void) printf(gettext("\nReading "));
	else /* Otape */
		(void) printf(gettext("\nWriting "));
	if (!Eomflg)
		(void) printf(gettext(
			"REEL %d of %d VOL = %.6s\n"),
				R_cur, R_num, In.f_vol_p);
	else
		(void) printf(gettext(
			"REEL %d of ? VOL = %.6s\n"), R_cur, In.f_vol_p);
}

#ifdef LOG
/*
 * fslog: Log current activity.
 */

static int
fslog(void)
{
	FILE *fp = NULL;

	fp = fopen("/var/adm/filesave.log", "a");
	if (fp == NULL) {
		perr(1, "volcopy: cannot open /var/adm/filesave.log\n");
	}

	fprintf(fp, "%s%c%.6s%c%.6s -> %s%c%.6s%c%.6s on %.24s\n",
		In.f_dev_p, ';', Ifname, ';', Ifpack, Out.f_dev_p,
		';', Ofname, ';', Ofpack, ctime(&Tvec));
	fclose(fp);
	return (0);
}
#endif	/* LOG */

/*
 * getname:  Get device name.
 */

void
getname(char *nam_p)
{
	int lastchar;
	char nam_buf[21];

	nam_buf[0] = '\0';
	(void) printf(gettext("Changing drives? (type RETURN for no,\n"));
	(void) printf(gettext("\t`/dev/rmt/??\' or `/dev/rtp/??\' for yes: "));
	fgets(nam_buf, 20, Devtty);
	nam_buf[20] = '\0';
	lastchar = strlen(nam_buf) - 1;
	if (nam_buf[lastchar] == '\n')
		nam_buf[lastchar] = '\0'; /* remove it */
	if (nam_buf[0] != '\0')
		(void) strcpy(nam_p, nam_buf);
}

/*
 * chgreel:  Change reel on end-of-media.
 */

static void
chgreel(struct file_info *f_p, int dir)
{
	int again = 1, lastchar, temp;
	char vol_tmp[11];

	R_cur++;
	while (again) {
		again = 0;
		errno = 0;
		(void) close(f_p->f_des);
		(void) getname(f_p->f_dev_p);
		(void) printf(gettext(
			"Mount tape %d\nType volume-ID when ready:   "), R_cur);
		vol_tmp[0] = '\0';
		fgets(vol_tmp, 10, Devtty);
		vol_tmp[10] = '\0';
		lastchar = strlen(vol_tmp) - 1;
		if (vol_tmp[lastchar] == '\n')
			vol_tmp[lastchar] = '\0'; /* remove it */
		if (vol_tmp[0] != '\0') { /* if null string, use old vol-id */
			strncpy(f_p->f_vol_p, vol_tmp, 6);
			strncpy(V_labl.v_volume, vol_tmp, 6);
		}
		errno = 0;
		f_p->f_des = open(f_p->f_dev_p, 0);
		if (f_p->f_des <= 0 || f_p->f_des > 10) {
			if (dir == INPUT)
				perror("input ERR");
			else
				perror("output ERR");
		}
		errno = 0;
		if (g_init(&(f_p->f_dev), &(f_p->f_des)) < 0)
			perr(0, "Initialization error %d\n", errno);
		if ((f_p->f_dev != G_TM_TAPE) && (f_p->f_dev != G_XT_TAPE) &&
		    (f_p->f_dev != G_ST_TAPE)) {
			(void) printf(gettext(
				"\n'%s' is not a valid device"), f_p->f_dev_p);
			(void) printf(gettext(
		"\n\tenter device name `/dev/rmt/??\' or `/dev/rtp/??\' :"));
			again = 1;
			continue;
		}
		if (!hdrck(f_p->f_dev, f_p->f_des, f_p->f_vol_p)) {
			again = 1;
			continue;
		}
		switch (dir) {
		case INPUT:
			if (V_labl.v_reel != R_cur) {
				perr(0, "Need reel %d, label says reel %d\n",
				    R_cur, V_labl.v_reel);
				again = 1;
				continue;
			}
			break;
		case OUTPUT:
			V_labl.v_reel = R_cur;
			temp = V_labl.v_offset;
			V_labl.v_offset /= BUFSIZ;
			close(f_p->f_des);
			sleep(2);
			errno = 0;
			f_p->f_des = open(f_p->f_dev_p, 1);
			if (f_p->f_des <= 0 || f_p->f_des > 10)
				perror("output ERR");
			errno = 0;
			if (g_init(&(f_p->f_dev), &(f_p->f_des)) < 0)
				perr(1, "Initialization error %d\n", errno);
			errno = 0;
			if (g_write(f_p->f_dev, f_p->f_des, &V_labl,
			    sizeof (V_labl)) < 0) {
				perr(0, "Cannot re-write header -Try again!\n");
				again = 1;
				V_labl.v_offset = temp;
				continue;
			}
			V_labl.v_offset = temp;
			break;
		default:
			perr(1, "Impossible case\n");
		} /* dir */
	} /* again */
	rprt();
}

/*
 * perr:  Print error messages.
 */

static void
perr(int severity, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fflush(stdout);
	(void) fflush(stderr);
	if (severity == 10) {
		(void) vfprintf(stdout, gettext(fmt), ap);
		(void) fprintf(stdout, gettext(
			"\t%d reel(s) completed\n"), --R_cur);
		(void) fflush(stdout);
		(void) fflush(stderr);
		cleanup();
		exit(31+9);
	}
	(void) vfprintf(stderr, gettext(fmt), ap);
	(void) fflush(stderr);
	va_end(ap);
	if (severity > 0) {
		(void) cleanup();
		exit(31+severity);
	}
}


static void
getinfs(int dev, int fd, char *buf)
{
	int cnt;
	int i;

	if (lseek(fd, SBLOCK * DEV_BSIZE, 0) != SBLOCK * DEV_BSIZE) {
		perr(10, "Unable to lseek on input\n");
	}
	cnt = SBSIZE/DEV_BSIZE;
	for (i = 0; i < cnt; i++) {
		if (g_read(dev, fd, (char *)buf + i*DEV_BSIZE, DEV_BSIZE)
			!= DEV_BSIZE) {
			perr(10, "Unable to read on input\n");
		}
	}
}

static void
getoutfs(int dev, int fd, char *buf, int verify)
{
	int cnt;
	int i;

	errno = 0;
	if (lseek(fd, SBLOCK * DEV_BSIZE, 0) != SBLOCK * DEV_BSIZE) {
		prompt(verify, "Unable to lseek on output\n", errno);
	}
	cnt = SBSIZE/DEV_BSIZE;
	for (i = 0; i < cnt; i++) {
		if (g_read(dev, fd, (char *)buf + i*DEV_BSIZE, DEV_BSIZE)
			!= DEV_BSIZE) {
			prompt(verify, "Unable to read on output\n", errno);
		}
	}
}

static char *
getfslabel(struct fs *sb)
{
	int i;
	int blk;

	/*
	 * is there room for label?
	 */

	if (sb->fs_cpc <= 0)
		return (nolabel);

	/*
	 * calculate the available blocks for each rotational position
	 */
	blk = sb->fs_spc * sb->fs_cpc / sb->fs_nspf;
	for (i = 0; i < blk; i += sb->fs_frag)
		/* void */;
	i -= sb->fs_frag;
	blk = i / sb->fs_frag;

	return ((char *)&(fs_rotbl(sb)[blk]));
}

static char *
getvolabel(struct fs *sb)
{
	char *p;
	int i;

	p = getfslabel(sb);

	if (p == nolabel || p == NULL)
		return (nolabel);

	for (i = 0; *p && i < 6; p++, i++)
		;
	p++;
	return (p);
}
