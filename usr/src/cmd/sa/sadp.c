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
 * Copyright 1994 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*	sadp.c 1.14.1.12 of 8/9/89	*/
/*	sadp.c - For VAX and PDP11 machines,
		disk profiler profiles rp06, rm05 and general disk drives.
		It reads system buffer header pool, physical buffer header
		pool and swap buffer header pool once every second,
		to examine disk drive's I/O queue.
		For 3b20s system, it profiles the regular disk drives,
		it reads the circular output queue for each drive
		once every second.
	usage : sadp [-th][-d device[-drive]] s [n]
*/

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/buf.h>
#include <sys/elog.h>
#include <nlist.h>

#include <string.h>
#include <fcntl.h>
#include <sys/dkio.h>
#ifdef FIXME
#include <sys/dk.h>
#endif

#include <time.h>
#include <sys/utsname.h>
#include <sys/var.h>
#include <ctype.h>
#include <sys/sysinfo.h>
#include <kvm.h>

/*
 * These includes are for dealing with scsi targets.
 */
#include <sys/dditypes.h>
#include <sys/scsi/scsi.h>
#include <sys/scsi/conf/device.h>
#include <sys/scsi/targets/sddef.h>


/* cylinder profiling */
#define	BLANK ' '
#define	BLOB '*'
#define	TRACE '.'
#define	BRK '='
#define	FOOT '-'
#define	CYLNO   1
#define	SEEKD   2

struct dk_geom	dk_geom;
#define	CHUNK		16
#define	CHUNKSHIFT	4
#define	PHYS_CYL	dk_geom.dkg_pcyl
#define	CHPERCYL	(int)(PHYS_CYL/CHUNK)	/*
						 * the number of CHUNK cylinder
						 * chunks on a disk
						 */
#define	SECTPERTRK	(int)(dk_geom.dkg_nsect)	/* sectors per track */
#define	SECTPERCYL	(SECTPERTRK * (int)(dk_geom.dkg_nhead))
#define	ERR_BAD_DEV	"Device %s is not defined, valid devices are: "
#define	ERR_BAD_UNIT \
		"Invalid drive specified for device %s, valid drives are: "
#define	ERR_NO_DEV	"Please specify a device type, valid devices are: "
#define	DRVNUM(devname)	strpbrk(devname, "0123456789")

#define	cylin b_resid
#define	NDRIVE  10
#define	SNDRIVE NDRIVE		/* Not used */
#define	MAX_HDISK_REP	NDRIVE
#define	MAXDRIVE	20	/* maximum number of configured disks */
#define	NAMESIZE	10	/* size of device names */


struct nlist setup[] = {

#define	X1_V		0
	{"v"},
#define	X1_BUF		1
	{"buf"},
#define	X1_PBUF		2
	{"pbuf"},
#define	X1_SDUNITS	3
	{"sdunits"},
#ifdef FIXME
#define	X1_DK_NDRIVE	4
	{"dk_ndrive"},
#define	X1_DK_BUSY	5
	{"dk_busy"},
#define	X1_DK_TIME	6
	{"dk_time"},
#define	X1_DK_SEEK	7
	{"dk_seek"},
#define	X1_DK_XFER	8
	{"dk_xfer"},
#define	X1_DK_WDS	9
	{"dk_wds"},
#define	X1_DK_BPS	10
	{"dk_bps"},
#define	X1_DK_READ	11
	{"dk_read"},
#define	X1_DK_IVEC	12
	{"dk_ivec"},
#define	X1_NUMSYMBOLS	13
#else
#define	X1_NUMSYMBOLS	4
#endif
	{0}
};

void	do_disk_stats ();
void	usage ();
void	prthist ();
void	pline ();
void	cylhdr ();
void	cylftr ();
void	cylhist ();
void	validate_device ();
void	validate_drive ();
void	init_geom ();
void	bad_device ();
void	read_devinfo_names ();
void	fail ();
void	init_disk ();
void	safe_kvm_read ();

#undef n_name			/* to resolve conflict with <syms.h> */
#define	MAXINTSIZE	12	/* sizeof "-2147483648" + 1 */

int debug = 1;

#define	Debug		if (debug)
#define	dfprintf	if (debug) fprintf

/*
 * FETCH_XYZ naming convention:
 * X = I for nlist index, A for actual address
 * Y = V for regular variable, A for array variable
 * Z = L if length explicitly specified
 */

#define	FETCH_AAL(addr, var, len, vname)\
	safe_kvm_read(kd, (unsigned long) addr, \
		(char *) var, len, vname)

#define	FETCH_IV(index, var)\
	safe_kvm_read(kd, (unsigned long) setup[index].n_value, \
		(char *) &var, sizeof (var), setup[index].n_name)

#define	FETCH_IAL(index, var, len)\
	safe_kvm_read(kd, (unsigned long)setup[index].n_value, \
		(char *) var, len, setup[index].n_name)

int	dk_ndrive;
int	ndrives;
int	all = 0;	/*
			 * indicate whether all drives
			 * are implicitly specified
			 */
char    *cmdname = "sadp";
char	device[NAMESIZE];
char	dr_name[NDRIVE][NAMESIZE];
long	dk_bps[NDRIVE];

struct {
	long	dk_busy[NDRIVE];
	long	dk_time[NDRIVE];
	long	dk_wds[NDRIVE];
	long	dk_seek[NDRIVE];
	long	dk_xfer[NDRIVE];
	long	dk_read[NDRIVE];
} dk;

struct var 	tbl;
char 		*sbuf, *phybuf;
struct buf 	bp[2];		/*  for swap buffers  */
int 		nonblk;
int 		index;
int 		index1;
unsigned 	temp1;
#define devnm dr_name

int fflg, dflg, tflg, hflg, errflg;
int s, n, ct;
static int ub = 8;
int sdist;
int m;
int dev;
int temp;
int f;
int i;
int n1, dleng, dashb, k, devlen;
int dashf;
int dn;
int drvlist[NDRIVE];

int Sdrvlist[SNDRIVE];	/* SCSI */

struct HISTDATA {
	long	hdata[1];
};
struct utsname name;

char	*nopt;
char	empty[30];
char	drive[30];
char	*malloc();

int	SCSI;	/* SCSI */
int	ALL;

long	lseek();
long	**dkcyl;
long	**skcyl;
long	*iocnt;
static kvm_t	*kd = NULL;
struct scsi_device	*sdunits[SD_MAXUNIT];
struct scsi_device	sdunit[NDRIVE];
int			cyl_no, prev_cyl_no;
int			cyl_bk, prev_cyl_bk;
int			seek_dist, seek_bk;
int			max_cyl_no = 0;
int			max_seek_dist = 0;

main(argc, argv)
int argc;
char **argv;
{
	unsigned sleep();
	extern int	optind;
	extern char	*optarg;
	int c, j;
	char *ctime(), *stime;
	long curt;
	extern time_t time();
	long *skdist;
	long *disk;

	fail("sadp does not work yet -- no disk statistics in the kernel", 0);

	while ((c = getopt(argc, argv, "thd:")) != EOF)
		switch (c) {
		case 't':
			tflg++;
			break;
		case 'h':
			hflg++;
			break;
		case 'd':
			dleng = strlen(optarg);

			/*
			 * Controller types can be arbitrary length.
			 */
			devlen =  strchr(optarg, '-') ?
					strchr(optarg, '-') - optarg : dleng;
			SCSI = 0;
			strncpy(device, optarg, devlen);

			if (dleng == (devlen+1)) {
				errflg++;
				break;
			}
			if (dleng > devlen) {
			for (i = (devlen+1), n1 = (devlen+1); i < dleng; i++){

				if (optarg[i] == ','){
					if (n1 == i){
					errflg++;
					break;
					}
					if (getdrvn() != 0) {
						errflg++;
						break;
					}
					if (dashf != 0) {
						if (dashb >= dn){
							errflg++;
							break;
						}
						for (j = dashb; j < dn+1; j++){
							if (SCSI) /*  SCSI */
								Sdrvlist[j] = 1;
							else
								drvlist[j] = 1;
						}
						dashb = 0;
						dashf = 0;
					}
					else
					{
						if (SCSI)
							Sdrvlist[dn] = 1;
						else
							drvlist[dn] = 1;
					}
					n1 = i+1;
				} else {
				if (optarg[i] == '-'){
					if (dashf != 0) {
						errflg++;
						break;
					}
					if (getdrvn() != 0) {
						errflg++;
						break;
					}
					if (SCSI)
						Sdrvlist[dn] = 1;
					else
						drvlist[dn] = 1;
					dashb = dn;
					dashf = 1;
					n1 = i+1;
				} else {
					if (i == dleng-1){
					i++;
					if (getdrvn() != 0) {
						errflg++;
						break;
					}
					if (dashf != 0)
						for (j = dashb; j < dn+1; j++){
							if (SCSI)
								Sdrvlist[j] = 1;
							else
								drvlist[j] = 1;
						}
					else
					{
						if (SCSI)
							Sdrvlist[dn] = 1;
						else
							drvlist[dn] = 1;
					}
					}
				}
				}
			}
			} else {
				if (dleng != devlen){
					errflg++;
					break;
				}
				all++;
				if (SCSI)
					ALL++;
				else
					for (i = 0; i < MAX_HDISK_REP; i++)
						drvlist[i] = 1;
			}
			if (errflg)
				break;
			dflg++;
			break;
		case '?':
			errflg++;
			break;
		}
	if (errflg) {
		fprintf (stderr, "%s: errors in arguments\n", cmdname);
		usage();
	}

	/*
	 * If no frequency arguments present, exit.
	 */
	if (optind == argc)
		usage();
	/*
	 * If a non-dash field is presented as an argument,
	 * check if it is a numerical arg.
	 */
	nopt = argv[optind];
	if (tstdigit(nopt) != 0)
		usage();
	/*
	 * For frequency arguments, if only s is presented , set n to 1
	 */
	if ((optind +1) == argc) {
		s = atoi(argv[optind]);
		n = 1;
	}
	/*
	 * If both s and n are specified, check if
	 * arg n is numeric.
	 */
	if ((optind +1) < argc) {
		nopt = argv[optind + 1];
		if (tstdigit(nopt) != 0)
			usage();
		s = atoi(argv[optind]);
		n = atoi(argv[optind+1]);
	}
	if (s <= 0)
		fail("bad value of s", 0);
	if (n <= 0)
		fail("bad value of n", 0);
	ct = s;
	/*
	 * Get entries defined in setup from /stand/unix
	 */
	if ((kd = kvm_open (NULL, NULL, NULL, O_RDONLY, "Bad kvm open"))
		== NULL)
		fail("kvm_open failed", 1);

	dfprintf (stderr, "main: successful kvm_open\n");
	/*
	 * Search name list to get offsets.
	 */
	dfprintf (stderr, "main: about to kvm_nlist\n");
	if (kvm_nlist(kd, setup) == -1) {
		fail("kvm_nlist failed", 1);
	}
	dfprintf (stderr, "main: good nlist\n");
	Debug dump_nlist (setup, "main");

	/*
	 * Initialize buffers and get disk info.
	 */
	init_disk();
	dfprintf (stderr, "init_disk\n");
	skdist = (long *)calloc(dk_ndrive, sizeof (long));
	disk = (long *)calloc(dk_ndrive, sizeof (long));

	/*
	 * Make sure device and drive specified is legitimate.
	 */
	validate_device();
	dfprintf (stderr, "validate_device\n");
	validate_drive();
	dfprintf (stderr, "validate_drive\n");

	/*
	 * Get storage from memory for sysbuf pool and physical buf pool
	 */
	FETCH_IV (X1_V, tbl);
	Debug dump_v_struct (&tbl);
	sbuf = malloc(sizeof (struct buf) * tbl.v_buf);
	if (sbuf == NULL)
		fail("malloc of sbuf failed", 1);
	phybuf = malloc(sizeof (struct buf) * tbl.v_pbuf);
	if (phybuf == NULL)
		fail("malloc of physbuf failed", 1);

	/*
	 * Determine the number of CHUNK cylinder chunks on the disk.
	 * This will be referenced as CHPERCYL.
	 */
	init_geom();
	dfprintf (stderr, "init_geom\n");

	ub = dk_ndrive;
#ifdef FIXME
	FETCH_IAL(X1_DK_XFER, dk.dk_xfer, dk_ndrive*sizeof (long));
	FETCH_IAL(X1_DK_READ, dk.dk_read, dk_ndrive*sizeof (long));
	FETCH_IAL(X1_DK_SEEK, dk.dk_seek, dk_ndrive*sizeof (long));
	FETCH_IAL(X1_DK_WDS, dk.dk_wds, dk_ndrive*sizeof (long));
	FETCH_IAL(X1_DK_TIME, dk.dk_time, dk_ndrive*sizeof (long));
#endif
	dfprintf (stderr, "%s: ub %d\n", cmdname, ub);
	/*
	 * Get the list of scsi device pointers from kernel space.
	 */
	FETCH_IAL(X1_SDUNITS, sdunits, SD_MAXUNIT);
	for (i = 0; i < SD_MAXUNIT; i++) {
		dfprintf (stderr, "sdunits[%d] 0x%x ", i, (int)sdunits[i]);
	}
	dfprintf (stderr, "\n");
	for (k = 0, i = 0; k < ub; k++) {
		if (drvlist[k] == 0)
			continue;
		/*
		 * Make sure that there is a scsi_device struct for
		 * the chosen device.
		 */
		if (!sdunits[k]) {
			fprintf (stderr, "%s: no valid scsi_device struct\n",
				cmdname);
		}
		dfprintf (stderr, "%s: read unit %d\n", cmdname, k);
		/*
		 * Read the scsi_device struct for the device.
		 */
		FETCH_AAL(sdunits[k], &sdunit[k],
			sizeof (struct scsi_device), "sdunits");
		dfprintf (stderr, "%s: sd_private 0x%x\n",
			cmdname, (int)sdunit[k].sd_private);
	}

	/*
	 * Get current I/O count for each drive.
	 */
	for (;;) {
		s = ct;
		for (k = 0, i = 0; k < ub; k++) {
			if (drvlist[k] == 0)
				continue;
			for (j = 0; j < CHPERCYL; j++) {
				dkcyl[i][j] = 0;
				skcyl[i][j] = 0;
			}
			iocnt[i] = 0;
			disk[i] = 0;
			skdist[i] = 0;
			i++;
		}
		/*
		 * If no drives are selected or illegal drive number
		 * is specified, exit.
		 */
		if (i == 0)
			usage();

		/*
		 * Get i/o count for each disk.
		 */

		for (k = 0, i = 0; k < ub; k++) {
			if (drvlist[k] == 0)
				continue;
			iocnt[i] = dk.dk_xfer[k];
			i++;
		}

	cyl_no = 0; prev_cyl_no = 0; cyl_bk = 0; prev_cyl_bk = 0; seek_dist = 0;
	for (;;) {

		/*
		 * Take a snapshot of buffer header pool, swap
		 * buffer pool and physical buffer header.
		 */

		/*
		 * read system buffer header pool.
		 */
		FETCH_IAL(X1_BUF, sbuf, tbl.v_buf*sizeof (struct buf));

		/*
		 * Read physical buffer header pool.
		 */
		FETCH_IAL(X1_PBUF, phybuf, tbl.v_pbuf*sizeof (struct buf));

		for (k = 0, i = 0; k < ub; k++) {
			if (drvlist[k] == 0)
				continue;
			do_disk_stats (i, k);
		i++;
		dfprintf (stderr, "%s: i %d\n", cmdname, i);
		}

	/* TBD - get more samples */

		if (--s)
			sleep(1);
		else {

			/*
			 * At the end of sampling, get the present I/O
			 * count, and system name.
			 */
			uname(&name);

			/*
			 * Print the report, there are two parts:
			 * cylinder profile, seeking distance profile.
			 */
			curt = time((long *) 0);
			stime = ctime (&curt);
			printf("\n\n%s\n", stime);
			printf("%s %s %s %s %s\n",
				name.sysname,
				name.nodename,
				name.release,
				name.version,
				name.machine);
			for (k = 0, i = 0; k < ub; k++) {
				if (drvlist[k] == 0)
					continue;
				for (j = 0; j < CHPERCYL; j++) {
					disk[i] = disk[i] +dkcyl[i][j];
					skdist[i] = skdist[i] + skcyl[i][j];

				}
				i++;
			}
			if ((tflg == 0) && (hflg == 0))
				tflg = 1;
			if (tflg){
				printf("\nCYLINDER ACCESS PROFILE\n");
				for (k = 0, i = 0; k < ub; k++) {
					if (drvlist[k] == 0)
						continue;
					if (disk[i] != 0){
						iocnt[i] = dk.dk_xfer[k] - iocnt[i];
						printf("\n%s-%d:\n",
							device, k);
						printf("Cylinders\tTransfers\n");
						for (j = 0; j < CHPERCYL; j++) {
							if (dkcyl[i][j] > 0)
								printf("%3d - %3d\t%ld\n",
								j*8, j*8+7, dkcyl[i][j]);
						}
						printf("\nSampled I/O = %ld, Actual I/O = %ld\n",
						disk[i], iocnt[i]);
						if (iocnt[i] > 0)
						printf("Percentage of I/O sampled = %2.2f\n",
						((float)disk[i] /(float)iocnt[i]) * 100.0);
					}
					i++;
				}

				printf("\n\n\nSEEK DISTANCE PROFILE\n");
				for (k = 0, i = 0; k < ub; k++) {
					if (drvlist[k] == 0)
						continue;
					if (skdist[i] != 0){
						printf("\n%s-%d:\n",
							device, k);
						printf("Seek Distance\tSeeks\n");
						for (j = 0; j < CHPERCYL; j++)

							if (skcyl[i][j] > 0){
								if (j == 0)
									printf("        0\t%ld\n",
									skcyl[i][j]);
								else
									printf("%3d - %3d\t%ld\n",
								j*8-7, j*8, skcyl[i][j]);
							}
						printf("Total Seeks = %ld\n", skdist[i]);
					}
					i++;
				}
			}
			if (hflg){
				for (k = 0, i = 0; k < ub; k++) {
					if (drvlist[k] == 0)
						continue;
					if (disk[i] != 0) {
						cylhdr(CYLNO, disk[i]);
						cylhist(disk[i], dkcyl[i]);
						cylftr(CYLNO);
					}
					i++;
				}
				for (k = 0, i = 0; k < ub; k++) {
					if (drvlist[k] == 0)
						continue;
					if (skdist[i] != 0){
						cylhdr(SEEKD, skdist[i]);
						cylhist(skdist[i], skcyl[i]);
						cylftr(SEEKD);
					}
					i++;
				}
			}

			break;
		}
	}
	if (--n)
		continue;
	exit(0);
	}
}

void
do_disk_stats (i, k)
{
#ifdef	fixed
	struct scsi_disk	sddisk[NDRIVE];
	struct diskhd		*dp;
	struct buf		buffer, *bp;
	struct buf		*last_bp = 0;

	dfprintf (stderr, "do_disk_stats (i %d, k %d)\n", i, k);
	/*
	 * In each scsi_device struct there is a sd_private
	 * pointer to a specialised scsi_disk struct which
	 * describes the disk.
	 */
	do {
		FETCH_AAL(sdunit[k].sd_private, &sddisk[k],
			sizeof (struct scsi_disk), "sdunit");
		/*
		 * The diskhd struct describing the active and waiting
		 * queues is embedded in the scsi_disk struct.
		 */
		dp = &sddisk[k].un_utab;
		Debug dump_diskhd (dp);
		/*
		 * The current SunOS sd.c driver uses the b_forw
		 * pointer for the currently active buffer, and the
		 * b_actf (av_forw) pointer for the waiting queue
		 * of buffers.
		 */
		dfprintf (stderr, "%s: b_forw 0x%x\n", cmdname, (int)dp->b_forw);
		/*
		 * Trace disk queue for I/O location, seek distance.
		 */
		if (dp->b_forw) {
			if (dp->b_forw == last_bp) {
				continue;
			} else {
				last_bp = dp->b_forw;
			}
			dfprintf (stderr, "%s: b_forw 0x%x\n",
				cmdname, (int)dp->b_forw);
			FETCH_AAL(dp->b_forw, &buffer, sizeof (struct buf),
				"b_forw");
			bp = &buffer;
			dfprintf (stderr, "%s: b_lblkno 0x%x b_blkno 0x%x\n",
				cmdname, bp->b_lblkno, bp->b_blkno);
			cyl_no = bp->b_blkno / SECTPERCYL;
			cyl_bk = cyl_no >> CHUNKSHIFT;
			seek_dist = prev_cyl_no - cyl_no;
			if (seek_dist < 0)
				seek_dist = -seek_dist;
			seek_bk = prev_cyl_bk - cyl_bk;
			if (seek_bk < 0)
				seek_bk = -seek_bk;
			prev_cyl_no = cyl_no;
			prev_cyl_bk = cyl_bk;
			if (cyl_no > max_cyl_no) {
				max_cyl_no = cyl_no;
			}
			if (seek_dist > max_seek_dist) {
				max_seek_dist = seek_dist;
			}
			skcyl[i][seek_bk]++;
			dkcyl[i][cyl_bk]++;
		}
	} while (dp->b_forw);
#endif
}


/*
 * Determine if the I/O is from system buffer pool,
 * or swap buffer pool or physical buffer.
 */

int
testbuf()
{
	if ((temp1 < setup[X1_BUF].n_value) || (index > tbl.v_buf)){
		index = (int)(temp1 -setup[X1_PBUF].n_value)/
			(sizeof (struct buf));
		if (index < tbl.v_pbuf){
			nonblk = 1;
			return (0);

		}
/* TBD - Is it possible to access swap buffers on Sun? */
#ifndef sun
		index = (int)(temp1 -setup[SWP].n_value)/
			(sizeof (struct buf));
		if (index < NSWP) {
			m = index;
			nonblk = 2;
			return (0);
		}
#endif
		return (-1);
	}
	return (0);
}

/*
 * Verify the I/O, get the cylinder number.
 */

ckbits(x)
	register struct buf *x;
{
	register p;
	for (p = 0; p < index; p++, x++)
		continue;
	if ((x->b_flags & B_BUSY) &&
	    ((x->b_flags & B_DONE) == 0)){
		temp = x->cylin;
		temp1 = (unsigned)x->av_forw;
		return (0);
	}
	else
		return (-1);

}
int
testdev()
{
	if ((nonblk == 0) && (ckbits((struct buf *)sbuf) != -1))
		goto endtest;
	else {
		if ((nonblk == 1) && (ckbits((struct buf *)phybuf) != -1))
			goto endtest;

		else {

			if ((nonblk == 2) &&
			    ((bp[m].b_flags & B_BUSY) &&
			    ((bp[m].b_flags & B_DONE) == 0))){
				temp = bp[m].cylin;
				temp1 = (unsigned)bp[m].av_forw;
			} else {
				dfprintf (stderr, "testdev -1\n");
				return (-1);
			}
		}
	}
endtest:
	dkcyl[i][temp >> 3]++;
	return (0);
}



/*
 * Get drive number routine.
 */
getdrvn()
{
	extern char *optarg;
	char *strcpy();
	char *strncat();

	strcpy(drive, empty);
	strncat(drive, &optarg[n1], i-n1);
	if (tstdigit(drive) != 0)
		return (-1);
	dn = atoi(drive);
	if (SCSI) {
		if (dn >= SNDRIVE)
			return (-1);
	} else {
		if (dn >= NDRIVE)
			return (-1);
	}
	return (0);
}

void
usage()
{
	fprintf(stderr, "usage:  sadp [-th][-d device[-drive]] s [n]\n");
	exit(1);
}

int tstdigit(ss)
char *ss;
{
	int kk, cc;
	kk = 0;
	while ((cc = ss[kk]) != '\0'){
		if (isdigit(cc) == 0)
			return (-1);
		kk++;
	}
	return (0);
}

/*
 * The following routines are obtained from iostat.
 *
 * Output Cylinder Histogram.
 */
void
cylhist(at, dp)
long at;
register struct HISTDATA *dp;
{
	register ii;
	int maxrow;
	long *graph = (long *)calloc(CHPERCYL, sizeof (long));
	long    max, max2;
	long    data;
	long    scale;

	for (ii = 0; ii < CHPERCYL; ii++) {
		dfprintf (stderr, "(%d %d) ", ii, (int)dp->hdata[ii]);
	}
	dfprintf (stderr, "\n");
	max = 0;
	for (ii = 0; ii < CHPERCYL; ii++) {
		if (data = dp->hdata[ii]) {
			maxrow = ii;
			if (data > max) {
				max2 = max;
				max = data;
			} else if (data > max2 && data != max)
				max2 = data;
		}
	}
	maxrow++;

	/* determine scaling */
	scale = 1;
	if (max2) {
		scale = at / (max2 * 2);
		if (scale > 48)
			scale = 48;
		}

	for (ii = 0; ii < maxrow; ii++) {
		if (dp->hdata[ii])
			graph[ii] = (scale * 100 * dp->hdata[ii]) / at;
		else
			graph[ii] = -1;
	}

	prthist(graph, maxrow, scale, (long) (max*100*scale/at));
}
/*
 * Print Histogram.
 */
void
prthist(array, mrow, scale, gmax)
	long array[], scale, gmax;
register mrow;
{
	long    line;

	line = 50;
	/* handle overflow in scaling */
	if (gmax > 51) {
		line = 52;
		printf("\n%2ld%% -|", gmax/scale);
		pline(line--, array, mrow, BLOB);
		printf("\n     %c", BRK);
		pline(line--, array, mrow, BRK);
	} else if (gmax = 51)
		line = 51;
	while (line > 0) {
		if ((line & 07) == 0) {
			printf("\n%2ld%% -|", line/scale);
		} else {
			printf("\n     |");
		}
		pline(line--, array, mrow, BLOB);
	}
	printf("\n 0%% -+");
	line = -1;
	pline(line, array, mrow, FOOT);
}

/*
 * Print Histogram Line.
 */
void
pline(line, array, mrow, dot)
	long line, array[];
int mrow;
char dot;
{
	register ii;
	register char *lp;
	char lbuff[132];

	dfprintf (stderr,
		"pline(line 0x%x, array 0x%x, mrow 0x%x, dot 0x%x)\n",
		line, array, mrow, dot);
	lp = lbuff;
	for (ii = 0; ii < mrow; ii++)
		if (array[ii] < line)
			if (line == 1 && array[ii] == 0)
				*lp++ = TRACE;
			else
				*lp++ = BLANK;
		else
			*lp++ = dot;
	*lp++ = 0;
	printf("%s", lbuff);
}
/*
 * Print Cylinder Profiling Headers.
 */
void
cylhdr(flag, total)
	long total;
{

	dfprintf (stderr, "cylhdr(flag 0x%x, total 0x%x)\n", flag, total);
	if (fflg)
		printf("\014\n");
	if (flag == CYLNO)
		printf("\nCYLINDER ACCESS HISTOGRAM\n");
	if (flag == SEEKD)
		printf("\nSEEK DISTANCE HISTOGRAM\n");
	printf("\n%s-%d:\n",
		device, k);
	printf("Total %s = %ld\n",
		flag == CYLNO ? "transfers" : "seeks", total);
}

#define	MAXCOL	80
/* Print Histogram Footers */
void
cylftr(flag)
{
	int		i;
	int		chunk_mult = 1;
	int		col;
	char		footer[4][MAXCOL];
	char		digits[] = "0123456789";
	int		significant = 0;

	dfprintf (stderr, "cylftr(flag 0x%x)\n", flag);
	if (flag == CYLNO)
		printf("\n      \t\t\tCylinder number, granularity=%d", CHUNK);
	else
		printf("\n      =<< ");
	for (i = 0; i < 4; i++) {
		for (col = 0; col < MAXCOL - 1; col++) {
			footer[i][col] = ' ';
		}
		footer[i][MAXCOL - 1] = '\0';
	}
	for (i = 0, col = 0; i < (int)PHYS_CYL;
		i += (chunk_mult * CHUNK), col += chunk_mult, significant = 0) {
		if ((i / 1000) > 0) {
			footer[0][col] = digits[(i / 1000)];
			significant = 1;
		}
		if ((significant) || (((i % 1000) / 100) > 0)) {
			footer[1][col] = digits[((i % 1000) / 100)];
			significant = 1;
		}
		if ((significant) || (((i % 100) / 10) > 0)) {
			footer[2][col] = digits[((i % 100) / 10)];
			significant = 1;
		}
		if ((i == 0) || (significant) || ((i % 10) > 0)) {
			footer[3][col] = digits[(i % 10)];
		}
		if (i > CHUNK) {
			chunk_mult = 2;
		}
		if (i > (3 * CHUNK)) {
			chunk_mult = 4;
			if (flag != CYLNO)
				printf ("<   ");
		}
	}
	for (i = 0; i < 4; i++) {
		printf ("      %s\n", footer[i]);
	}
	printf ("\n");
}

void
validate_device()
{
	int	i;
	char	tempdev[NAMESIZE];

	if (dflg == 0) {

		/*
		 * No device specified, so default to the first
		 * one if it is the only one, otherwise prompt
		 * user to enter one.
		 */
		strcpy(device, devnm[0]);
		*DRVNUM(device) = NULL;
		devlen = strlen(device);
		for (i = 0; i < dk_ndrive; i++)
			drvlist[i] = 1;
		if (dk_ndrive > 1)
			bad_device(device, ERR_NO_DEV);
		dev = 0;
	} else {

		/*
		 * Device was specified.  Make sure it matches
		 * one that is configured in the system.
		 */
		for (i = 0; i < dk_ndrive; i++) {
			strncpy(tempdev, devnm[i], DRVNUM(devnm[i])-devnm[i]);
			tempdev[DRVNUM(devnm[i])-devnm[i]] = NULL;
			if (strcmp(device, tempdev) == 0)
				break;
		}
		if (i == dk_ndrive)
			bad_device(device, ERR_BAD_DEV);
		dev = i;
	}
}

void
validate_drive()
{
	int	i, j, c;

	/*
	 * For each controller number specified, make sure it exists
	 * in the configured device list.
	 */
	for (i = 0; i < dk_ndrive; i++) {
		if (drvlist[i] == 0)
			continue;

		/*
		 * Since this controller number (i) was specified,
		 * find the corresponding entry (j) in the device list.
		 * If found, save the device list index in drvlist[].
		 */
		for (j = 0; j < dk_ndrive; j++) {
			if (strncmp(device, devnm[j], devlen) != 0)
				continue;
			c = atoi(DRVNUM(devnm[j]));
			if (c == i) {
				/*
				 * NOTE: saved value actual index+1
				 * as entries with 0 imply don't care.
				 */
				drvlist[i] = j+1;  /* not a flag anymore! */

				break;
			}
		}

		/*
		 * If not found, output error, except if all drives
		 * were implied by only specifying controller type.
		 * In this case, flag it as don't care.
		 */
		if (j == dk_ndrive) {
			if (all)
				drvlist[i] = 0;
			else
				bad_device(device, ERR_BAD_UNIT);
			}
	}
}

void
init_geom()
{
	char	tempdev[NAMESIZE];
	int	i, fd;
/*
 * When the new device naming convention is in effect, switch to it
 */
#ifdef NEW_DEVICE_NAMES
#define	DEV_PREFIX	"/dev/rdsk/"
#else
#define	DEV_PREFIX	"/dev/r"
#endif

	for (i = 0; drvlist[i] == 0; i++);
	sprintf(tempdev, "%s%s%da", DEV_PREFIX, device, i);
	if ((fd = open(tempdev, O_RDONLY)) == -1)
		fail("open failed", 1);
	if (ioctl(fd, DKIOCGGEOM, &dk_geom) == -1) {
		close(fd);
		fail("ioctl failed", 1);
	}
	close(fd);

	/*
	 * dk_geom structure now has data, and the number
	 * of 8 cylinder chunks on the disk can now be
	 * referenced via the CHPERCYL macro.  So allocate
	 * appropriate buffers based on this value.
	 */
	iocnt = (long *)calloc(dk_ndrive, sizeof (long));
	dkcyl = (long **)calloc(dk_ndrive, sizeof (long *));
	skcyl = (long **)calloc(dk_ndrive, sizeof (long *));
	for (i = 0; i < dk_ndrive; i++) {
		dkcyl[i] = (long *)calloc(CHPERCYL, sizeof (long));
		skcyl[i] = (long *)calloc(CHPERCYL, sizeof (long));
	}
}

/*
 * General routine for printing out an error message
 * when the specified device/drive is insufficient.
 */
void
bad_device(device, errmsg)
	char	*device;
	char	*errmsg;
{
	int	i, j;
	int	unique = 0;
	char	*p, *p1, **buf;
	char	s[NAMESIZE];
	char	*msg;


	/*
	 * Print usage statement if no device is specified.
	 */
	if (device[0] == NULL)
		usage();

	/*
	 * Compose a list of unique device controller types, or
	 * unit numbers for a specified controller type, from
	 * the complete device list.
	 */
	buf = (char **)calloc(dk_ndrive, sizeof (char *));
	for (i = 0; i < dk_ndrive; i++) {

		/*
		 * Get controller type or unit
		 */
		p = devnm[i];
		p1 = DRVNUM(devnm[i]);
		if (!strcmp(errmsg, ERR_BAD_UNIT)) {
			if (strncmp(devnm[i], device, devlen))
				continue;
			p = p1;
			p1++;
		}
		strncpy(s, p, p1-p);
		s[p1-p] = NULL;

		/*
		 * Have we already logged this one as unique?
		 * If not, then do so now.
		 */
		for (j = 0; j < unique; j++)
			if (!strcmp(s, buf[j]))
				break;
		if (j == unique)
			buf[unique++] = strdup(s);
	}

	/*
	 * Invalid device was specified.  Compose message containing
	 * list of valid devices.
	 */
	msg = (char *)malloc(strlen(errmsg) +
			strlen(device) + unique*(NAMESIZE+1) + 1);
	sprintf(msg, errmsg, device);
	for (p = msg + strlen(msg), i = 0; i < unique; i++) {
		sprintf(p, "%s ", buf[i]);
		p += (strlen(buf[i])+ 1);
	}

	/*
	 * Output the message and exit.
	 */
	fail(msg, 0);
}

/*
 * Code below here was taken from the SunOS 5.0 iostat command.
 */

#ifdef FIXME

void
read_devinfo_names()
{
	int i;
	struct dk_ivec dkivec[NDRIVE];

	safe_kvm_read (kd, nl_4c[X1_DK_IVEC].n_value, dkivec, sizeof dkivec,
		"dk_ivec");
	for (i = 0; i < NDRIVE; i++) {
		if (dkivec[i].dk_name) {
			safe_kvm_read (kd, dkivec[i].dk_name, dr_name[i], 2,
				"dk_name");
			sprintf(dr_name[i] + 2, "%d", dkivec[i].dk_unit);
		}
	}
}

#endif

void
init_disk()
{
#ifdef FIXME
	int i;

	for (i = 0; i < NDRIVE; i++) {
		dr_select[i] = 0;
		dk_bps[i] = 0;
	}

	/*
	 * The default device names: dk#
	 */
	for (i = 0; i < dk_ndrive; i++) {
		dr_name[i] = buf;
		(void) sprintf(buf, "dk%d", i);
		buf += NAMESIZE;
	}

	/*
	 * Device names must be discovered in this program, and output
	 * with its io data via the "sa" structure.
	 */

	read_devinfo_names();
#else
	return;
#endif
}

/*
 * issue failure message and exit
 */
void
fail(message, doperror)
char *message;
int doperror;
{
	if (kd != NULL)
		(void) kvm_close(kd);

	if (doperror) {
		fprintf(stderr, "%s: ", cmdname);
		perror(message);
	}
	fprintf(stderr, "%s: %s\n", cmdname, message);
	exit(2);
}

void
safe_kvm_read(kd, addr, buf, size, who)
kvm_t *kd;
unsigned long addr;
char *buf;
unsigned size;
{
	int ret_code;
	char errmsg[100];

	if (addr == 0) {
		sprintf(errmsg, "kvm_read of %s failed -- no address", who);
		fail(errmsg, 0);
	}
		
	ret_code = kvm_read(kd, addr, buf, size);
	if (ret_code != size) {
		sprintf(errmsg, "kvm_read of %s failed with code %d",
			who, ret_code);
		fail(errmsg, 0);
	}
}

/*
 * code for debugging dumps
 */

#include <sys/tuneable.h>
#include <sys/var.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/fs/rf_acct.h>

int	dump_iodev ();

dump_diskhd (dp)
	struct diskhd	*dp;
{

	dfprintf (stderr, "dump_diskhd: dp 0x%x\n", (int)dp);
	dfprintf (stderr, "flags\tb_forw\tb_back\tav_forw\tav_back\tb_bcount\n0x%x\t0x%x\t0x%x\t0x%x\t0x%x\t%d\n",
		(int)dp->b_flags, (int)dp->b_forw, (int)dp->b_back,
		(int)dp->av_forw, (int)dp->av_back, (int)dp->b_bcount);

return (0);
}

dump_nlist (nlist, str)
	struct nlist    nlist[];
	char            *str;
{
	int             i;

	for (i = 0; nlist[i].n_name; i++) {
		dfprintf (stderr, "%s: i %d n_name '%s' n_value 0x%x\n",
			str, i, nlist[i].n_name, (int)nlist[i].n_value);
	}

return (0);
}

dump_v_struct (tbl)
	struct var *tbl;
{
	dfprintf (stderr, "dump_v_struct: tbl 0x%x\n", (int)tbl);
	dfprintf (stderr, "v_buf\tv_call\tv_proc\tv_nglobpris\n%d\t%d\t%d\t%d\n",
		tbl->v_buf, tbl->v_call, tbl->v_proc, tbl->v_nglobpris);
	dfprintf (stderr, "v_maxsyspri\tv_clist\tv_maxup\tv_hbuf\n%d\t\t%d\t%d\t%d\n",
		tbl->v_maxsyspri, tbl->v_clist, tbl->v_maxup, tbl->v_hbuf);
	dfprintf (stderr, "v_hmask\tv_pbuf\tv_sptmap\tv_maxpmem\n0x%x\t%d\t%d\t\t%d\n",
		tbl->v_hmask, tbl->v_pbuf, tbl->v_sptmap, tbl->v_maxpmem);
	dfprintf (stderr, "v_autoup\tv_bufhwm\n%d\t\t%d\n",
		tbl->v_autoup, tbl->v_bufhwm);

return (0);
}

dump_tblmap (tbl, size)
	int	*tbl;
	int	size;
{
	int	i;

	dfprintf (stderr, "tblmap size %d/4 = %d ", size, size/4);
	for (i = 0; i < size/4; i++) {
		dfprintf (stderr, "tblmap[%d] %d ", i, tbl[i]);
	}
	dfprintf (stderr, "\n");

return (0);
}
