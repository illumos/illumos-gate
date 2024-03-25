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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

/*
 * make file system for udfs (UDF - ISO13346)
 *
 * usage:
 *
 *    mkfs [-F FSType] [-V] [-m] [options]
 *	[-o specific_options]  special size
 *
 *  where specific_options are:
 *	N - no create
 *	label - volume label
 *	psize - physical block size
 */

#include	<stdio.h>
#include	<strings.h>
#include	<string.h>
#include	<stdlib.h>
#include	<unistd.h>
#include	<time.h>
#include	<locale.h>
#include	<fcntl.h>
#include	<errno.h>
#include	<limits.h>
#include	<sys/mnttab.h>
#include	<sys/param.h>
#include	<sys/types.h>
#include	<sys/sysmacros.h>
#include	<sys/vnode.h>
#include	<sys/mntent.h>
#include	<sys/filio.h>
#include	<sys/stat.h>
#include	<ustat.h>
#include	<sys/isa_defs.h>	/* for ENDIAN defines */
#include	<sys/dkio.h>
#include	<sys/fdio.h>
#include	<sys/vtoc.h>
#include	<sys/fs/udf_volume.h>

extern char	*getfullrawname(char *);
extern char	*getfullblkname(char *);
extern struct tm *localtime_r(const time_t *, struct tm *);
extern void	maketag(struct tag *, struct tag *);
extern int	verifytag(struct tag *, uint32_t, struct tag *, int);
extern void	setcharspec(struct charspec *, int32_t, uint8_t *);


#define	UMASK		0755
#define	POWEROF2(num)	(((num) & ((num) - 1)) == 0)
#define	MB		(1024*1024)

/*
 * Forward declarations
 */
static void rdfs(daddr_t bno, int size, char *bf);
static void wtfs(daddr_t bno, int size, char *bf);
static void dump_fscmd(char *fsys, int fsi);
static int32_t number(long big, char *param);
static void usage();
static int match(char *s);
static int readvolseq();
static uint32_t get_last_block();

/*
 * variables set up by front end.
 */
static int	Nflag = 0;		/* run mkfs without writing */
					/* file system */
static int	mflag = 0;		/* return the command line used */
					/* to create this FS */
static int	fssize;			/* file system size */
static uint32_t	disk_size;		/* partition size from VTOC */
static uint32_t unused;			/* unused sectors in partition */
static int	sectorsize = 2048;	/* bytes/sector default */
					/* If nothing specified */

static char	*fsys;
static int	fsi;
static int	fso;

#define	BIG	LONG_MAX
static	uint32_t	number_flags = 0;

static char	*string;

static void	setstamp(tstamp_t *);
static void	setextad(extent_ad_t *, uint32_t, uint32_t);
static void	setdstring(dstring_t *, char *, int32_t);
static void	wtvolseq(tag_t *, daddr_t, daddr_t);
static void	volseqinit();
static void	setstamp(tstamp_t *);
static uint32_t	get_bsize();


#define	VOLRECSTART	(32 * 1024)

#define	VOLSEQSTART	128
#define	VOLSEQLEN	16
#define	INTSEQSTART	192
#define	INTSEQLEN	8192
#define	FIRSTAVDP	256
#define	AVDPLEN		1


#define	FILESETLEN	2

#define	SPACEMAP_OFF	24
#define	MAXID		16

static time_t mkfstime;
static struct tm res;
static long tzone;
static char vsibuf[128];

static regid_t sunmicro = { 0, "*SUN SOLARIS UDF", 4, 2 };
static regid_t lvinfo = { 0, "*UDF LV Info", 0x50, 0x1, 4, 2 };
static regid_t partid = { 0, "+NSR02", 0 };
static regid_t udf_compliant = { 0, "*OSTA UDF Compliant", 0x50, 0x1, 0 };
static uint8_t osta_unicode[] = "OSTA Compressed Unicode";

static int bdevismounted;
static int ismounted;
static int directory;
static char buf[MAXBSIZE];
static char buf2[MAXBSIZE];
static char lvid[MAXBSIZE];

uint32_t ecma_version = 2;

static int serialnum = 1;	/* Tag serial number */
static char udfs_label[128] = "*NoLabel*";
static int acctype = PART_ACC_OW;
static uint32_t part_start;
static uint32_t part_len;
static uint32_t part_bmp_bytes;
static uint32_t part_bmp_sectors;
static int32_t part_unalloc = -1;
static uint32_t filesetblock;

/* Set by readvolseq for -m option */
static uint32_t oldfssize;
static char *oldlabel;

int
main(int32_t argc, int8_t *argv[])
{
	long i;
	FILE *mnttab;
	struct mnttab mntp;
	char *special, *raw_special;
	struct stat statarea;
	struct ustat ustatarea;
	int	c;
	uint32_t temp_secsz;
	int isfs;

	(void) setlocale(LC_ALL, "");

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "F:Vmo:")) != EOF) {
		switch (c) {

			case 'F':
				string = optarg;
				if (strcmp(string, "udfs") != 0) {
					usage();
				}
				break;

			case 'V':
				{
					char	*opt_text;
					int	opt_count;

					(void) fprintf(stdout,
					gettext("mkfs -F udfs "));
					for (opt_count = 1; opt_count < argc;
							opt_count++) {
						opt_text = argv[opt_count];
						if (opt_text) {
							(void) fprintf(stdout,
							" %s ", opt_text);
						}
					}
					(void) fprintf(stdout, "\n");
				}
				break;

			case 'm':
				/*
				 * return command line used
				 * to create this FS
				 */
				mflag++;
				break;

			case 'o':
				/*
				 * udfs specific options.
				 */
				string = optarg;
				while (*string != '\0') {
					if (match("N")) {
						Nflag++;
					} else if (match("psize=")) {
						number_flags = 0;
						sectorsize = number(BIG,
							"psize");
					} else if (match("label=")) {
						for (i = 0; i < 31; i++) {
							if (*string == '\0') {
								break;
							}
							udfs_label[i] =
								*string++;
						}
						udfs_label[i] = '\0';
					} else if (*string == '\0') {
						break;
					} else {
						(void) fprintf(stdout,
							gettext("illegal "
							"option: %s\n"),
							string);
						usage();
					}
					if (*string == ',') {
						string++;
					}
					if (*string == ' ') {
						string++;
					}
				}
				break;

			case '?':
				usage();
				break;
		}
	}

	(void) time(&mkfstime);
	if (optind > (argc - 1)) {
		usage();
	}

	argc -= optind;
	argv = &argv[optind];
	fsys = argv[0];
	raw_special = getfullrawname(fsys);
	fsi = open(raw_special, 0);
	if (fsi < 0) {
		(void) fprintf(stdout,
			gettext("%s: cannot open\n"), fsys);
		exit(32);
	}
	fso = fsi;

	if ((temp_secsz = get_bsize()) != 0) {
		sectorsize = temp_secsz;
	}

	/* Get old file system information */
	isfs = readvolseq();

	if (mflag) {
		/*
		 * Figure out the block size and
		 * file system size and print the information
		 */
		if (isfs)
			dump_fscmd(fsys, fsi);
		else
			(void) printf(gettext(
				"[not currently a valid file system]\n"));
		exit(0);
	}

	/*
	 * Get the disk size from the drive or VTOC for the N and N-256
	 * AVDPs and to make sure we don't want to create a file system
	 * bigger than the partition.
	 */
	disk_size = get_last_block();

	if (argc < 2 && disk_size == 0 || argc < 1) {
		usage();
	}

	if (argc < 2) {
		(void) printf(gettext("No size specified, entire partition "
			"of %u sectors used\n"), disk_size);
		fssize = disk_size;
	} else {
		string = argv[1];
		number_flags = 0;
		fssize = number(BIG, "size");
	}

	if (fssize < 0) {
		(void) fprintf(stderr,
			gettext("Negative number of sectors(%d) not allowed\n"),
			fssize);
		exit(32);
	}

	if (fssize < (512 * sectorsize / DEV_BSIZE)) {
		(void) fprintf(stdout,
			gettext("size should be at least %d sectors\n"),
			(512 * sectorsize / DEV_BSIZE));
		exit(32);
	}

	if (disk_size != 0) {
		if (fssize > disk_size) {
			(void) fprintf(stderr, gettext("Invalid size: %d "
				"larger than the partition size\n"), fssize);
			exit(32);
		} else if (fssize < disk_size) {
			unused = disk_size - fssize;
			(void) printf(
			    gettext("File system size %d smaller than "
				"partition, %u sectors unused\n"),
				fssize, unused);
		}
	} else {
		/* Use passed-in size */
		disk_size = fssize;
	}

	if (!Nflag) {
		special = getfullblkname(fsys);

		/*
		 * If we found the block device name,
		 * then check the mount table.
		 * if mounted, write lock the file system
		 *
		 */
		if ((special != NULL) && (*special != '\0')) {
			mnttab = fopen(MNTTAB, "r");
			while ((getmntent(mnttab, &mntp)) == 0) {
				if (strcmp(special, mntp.mnt_special) == 0) {
					(void) fprintf(stdout,
						gettext("%s is mounted,"
						" can't mkfs\n"), special);
					exit(32);
				}
			}
			(void) fclose(mnttab);
		}
		if ((bdevismounted) && (ismounted == 0)) {
			(void) fprintf(stdout,
				gettext("can't check mount point; "));
			(void) fprintf(stdout,
				gettext("%s is mounted but not in mnttab(5)\n"),
				special);
			exit(32);
		}
		if (directory) {
			if (ismounted == 0) {
				(void) fprintf(stdout,
					gettext("%s is not mounted\n"),
					special);
				exit(32);
			}
		}
		fso = creat(fsys, 0666);
		if (fso < 0) {
			(void) fprintf(stdout,
				gettext("%s: cannot create\n"), fsys);
			exit(32);
		}
		if (stat(fsys, &statarea) < 0) {
			(void) fprintf(stderr,
				gettext("%s: %s: cannot stat\n"),
				argv[0], fsys);
			exit(32);
		}
		if (ustat(statarea.st_rdev, &ustatarea) >= 0) {
			(void) fprintf(stderr,
				gettext("%s is mounted, can't mkfs\n"), fsys);
			exit(32);
		}
	} else {
		/*
		 * For the -N case, a file descriptor is needed for the llseek()
		 * in wtfs(). See the comment in wtfs() for more information.
		 *
		 * Get a file descriptor that's read-only so that this code
		 * doesn't accidentally write to the file.
		 */
		fso = open(fsys, O_RDONLY);
		if (fso < 0) {
			(void) fprintf(stderr, gettext("%s: cannot open\n"),
				fsys);
			exit(32);
		}
	}


	/*
	 * Validate the given file system size.
	 * Verify that its last block can actually be accessed.
	 */
	fssize = fssize / (sectorsize / DEV_BSIZE);
	if (fssize <= 0) {
		(void) fprintf(stdout,
			gettext("preposterous size %d. sectors\n"), fssize);
		exit(32);
	}
	fssize --;

	/*
	 * verify device size
	 */
	rdfs(fssize - 1, sectorsize, buf);

	if ((sectorsize < DEV_BSIZE) ||
		(sectorsize > MAXBSIZE)) {
		(void) fprintf(stdout,
			gettext("sector size must be"
			" between 512, 8192 bytes\n"));
	}
	if (!POWEROF2(sectorsize)) {
		(void) fprintf(stdout,
			gettext("sector size must be a power of 2, not %d\n"),
			sectorsize);
		exit(32);
	}
	if (Nflag) {
		exit(0);
	}

	(void) printf(gettext("Creating file system with sector size of "
		"%d bytes\n"), sectorsize);

	/*
	 * Set up time stamp values
	 */
	mkfstime = time(0);
	(void) localtime_r(&mkfstime, &res);
	if (res.tm_isdst > 0) {
		tzone = altzone / 60;
	} else if (res.tm_isdst == 0) {
		tzone = tzone / 60;
	} else {
		tzone = 2047;	/* Unknown */
	}

	/*
	 * Initialize the volume recognition sequence, the volume descriptor
	 * sequences and the anchor pointer.
	 */
	volseqinit();

	(void) fsync(fso);
	(void) close(fsi);
	(void) close(fso);

	return (0);
}

static void
setstamp(tstamp_t *tp)
{
	tp->ts_usec = 0;
	tp->ts_husec = 0;
	tp->ts_csec = 0;

	tp->ts_sec = res.tm_sec;
	tp->ts_min = res.tm_min;
	tp->ts_hour = res.tm_hour;
	tp->ts_day = res.tm_mday;
	tp->ts_month = res.tm_mon + 1;
	tp->ts_year = 1900 + res.tm_year;

	tp->ts_tzone = 0x1000 + (-tzone & 0xFFF);
}

static void
setextad(extent_ad_t *eap, uint32_t len, uint32_t loc)
{
	eap->ext_len = len;
	eap->ext_loc = loc;
}

static void
setdstring(dstring_t *dp, char *cp, int len)
{
	int32_t length;

	bzero(dp, len);
	length = strlen(cp);
	if (length > len - 3) {
		length = len - 3;
	}
	dp[len - 1] = length + 1;
	*dp++ = 8;
	(void) strncpy(dp, cp, len-2);
}

static void
wtvolseq(tag_t *tp, daddr_t blk1, daddr_t blk2)
{
	static uint32_t vdsn = 0;

	tp->tag_loc = blk1;
	switch (tp->tag_id) {
	case UD_PRI_VOL_DESC :
		((struct pri_vol_desc *)tp)->pvd_vdsn = vdsn++;
		break;
	case UD_VOL_DESC_PTR :
		((struct vol_desc_ptr *)tp)->vdp_vdsn = vdsn++;
		break;
	case UD_IMPL_USE_DESC :
		((struct iuvd_desc *)tp)->iuvd_vdsn = vdsn++;
		break;
	case UD_PART_DESC :
		((struct part_desc *)tp)->pd_vdsn = vdsn++;
		break;
	case UD_LOG_VOL_DESC :
		((struct log_vol_desc *)tp)->lvd_vdsn = vdsn++;
		break;
	case UD_UNALL_SPA_DESC :
		((struct unall_spc_desc *)tp)->ua_vdsn = vdsn++;
		break;
	}

	bzero(buf2, sectorsize);
	/* LINTED */
	maketag(tp, (struct tag *)buf2);

	/*
	 * Write at Main Volume Descriptor Sequence
	 */
	wtfs(blk1, sectorsize, buf2);

	tp->tag_loc = blk2;
	switch (tp->tag_id) {
	case UD_PRI_VOL_DESC :
		((struct pri_vol_desc *)tp)->pvd_vdsn = vdsn++;
		break;
	case UD_VOL_DESC_PTR :
		((struct vol_desc_ptr *)tp)->vdp_vdsn = vdsn++;
		break;
	case UD_IMPL_USE_DESC :
		((struct iuvd_desc *)tp)->iuvd_vdsn = vdsn++;
		break;
	case UD_PART_DESC :
		((struct part_desc *)tp)->pd_vdsn = vdsn++;
		break;
	case UD_LOG_VOL_DESC :
		((struct log_vol_desc *)tp)->lvd_vdsn = vdsn++;
		break;
	case UD_UNALL_SPA_DESC :
		((struct unall_spc_desc *)tp)->ua_vdsn = vdsn++;
		break;
	}
	maketag(tp, tp);
	/*
	 * Write at Reserve Volume Descriptor Sequence
	 */
	wtfs(blk2, sectorsize, buf);
}

static void
volseqinit(void)
{
	struct tag *tp;
	struct nsr_desc *nsp;
	struct pri_vol_desc *pvdp;
	struct iuvd_desc *iudp;
	struct part_desc *pp;
	struct phdr_desc *php;
	struct log_vol_desc *lvp;
	long_ad_t *lap;
	struct pmap_typ1 *pmp;
	struct unall_spc_desc *uap;
	struct log_vol_int_desc *lvip;
	struct term_desc *tdp;
	struct anch_vol_desc_ptr *avp;
	struct lvid_iu *lviup;
	struct file_set_desc *fsp;
	struct file_entry *fp;
	struct icb_tag *icb;
	struct short_ad *sap;
	struct file_id *fip;
	struct space_bmap_desc *sbp;
	uint8_t *cp;
	daddr_t nextblock, endblock;
	int32_t volseq_sectors, nextlogblock, rootfelen, i;
	uint32_t mvds_loc, rvds_loc;

	bzero(buf, MAXBSIZE);

	/*
	 * Starting from MAXBSIZE, clear out till 256 sectors.
	 */
	for (i = MAXBSIZE / sectorsize; i < FIRSTAVDP; i++) {
		wtfs(i, sectorsize, buf);
	}

	/* Zero out the avdp at N - 257 */
	wtfs(fssize - 256, sectorsize, buf);

	/*
	 * Leave 1st 32K for O.S.
	 */
	nextblock = VOLRECSTART / sectorsize;

	/*
	 * Write BEA01/NSR02/TEA01 sequence.
	 * Each one must be 2K bytes in length.
	 */
	nsp = (struct nsr_desc *)buf;
	nsp->nsr_str_type = 0;
	nsp->nsr_ver = 1;
	(void) strncpy((int8_t *)nsp->nsr_id, "BEA01", 5);

	nsp = (struct nsr_desc *)&buf[2048];
	nsp->nsr_str_type = 0;
	nsp->nsr_ver = 1;
	(void) strncpy((int8_t *)nsp->nsr_id, "NSR02", 5);

	nsp = (struct nsr_desc *)&buf[4096];
	nsp->nsr_str_type = 0;
	nsp->nsr_ver = 1;
	(void) strncpy((int8_t *)nsp->nsr_id, "TEA01", 5);

	wtfs(nextblock, 8192, buf);
	bzero(buf, MAXBSIZE);

	/*
	 * Minimum length of volume sequences
	 */
	volseq_sectors = 16;

	/*
	 * Round up to next 32K boundary for
	 * volume descriptor sequences
	 */
	nextblock = VOLSEQSTART;
	bzero(buf, sectorsize);
	mvds_loc = VOLSEQSTART;
	rvds_loc = mvds_loc + volseq_sectors;

	/*
	 * Primary Volume Descriptor
	 */
	/* LINTED */
	pvdp = (struct pri_vol_desc *)buf;
	tp = &pvdp->pvd_tag;
	tp->tag_id =  UD_PRI_VOL_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct pri_vol_desc) -
			sizeof (struct tag);
	pvdp->pvd_vdsn = 0;
	pvdp->pvd_pvdn = 0;
	setdstring(pvdp->pvd_vol_id, udfs_label, 32);
	pvdp->pvd_vsn = 1;
	pvdp->pvd_mvsn = 1;
	pvdp->pvd_il = 2;		/* Single-volume */
	pvdp->pvd_mil = 3;		/* Multi-volume */
	pvdp->pvd_csl = 1;		/* CS0 */
	pvdp->pvd_mcsl = 1;		/* CS0 */
	(void) sprintf(vsibuf, "%08X", SWAP_32((uint32_t)mkfstime));
	setdstring(pvdp->pvd_vsi, vsibuf, 128);
	(void) strncpy(pvdp->pvd_vsi + 17, udfs_label, 128 - 17);
	setcharspec(&pvdp->pvd_desc_cs, 0, osta_unicode);
	setcharspec(&pvdp->pvd_exp_cs, 0, osta_unicode);
	setextad(&pvdp->pvd_vol_abs, 0, 0);
	setextad(&pvdp->pvd_vcn, 0, 0);
	bzero(&pvdp->pvd_appl_id, sizeof (regid_t));
	setstamp(&pvdp->pvd_time);
	bcopy(&sunmicro, &pvdp->pvd_ii, sizeof (regid_t));
	pvdp->pvd_flags = 0;
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Implementation Use Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	iudp = (struct iuvd_desc *)buf;
	tp = &iudp->iuvd_tag;
	tp->tag_id =  UD_IMPL_USE_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct iuvd_desc) -
			sizeof (struct tag);
	iudp->iuvd_vdsn = 0;
	bcopy(&lvinfo, &iudp->iuvd_ii, sizeof (regid_t));
	setcharspec(&iudp->iuvd_cset, 0, osta_unicode);
	setdstring(iudp->iuvd_lvi, udfs_label, 128);

	setdstring(iudp->iuvd_ifo1, "", 36);
	setdstring(iudp->iuvd_ifo2, "", 36);
	setdstring(iudp->iuvd_ifo3, "", 36);


	/*
	 * info1,2,3 = user specified
	 */
	bcopy(&sunmicro, &iudp->iuvd_iid, sizeof (regid_t));
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Partition Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	pp = (struct part_desc *)buf;
	tp = &pp->pd_tag;
	tp->tag_id =  UD_PART_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct part_desc) -
			sizeof (struct tag);
	pp->pd_vdsn = 0;
	pp->pd_pflags = 1;			/* Allocated */
	pp->pd_pnum = 0;
	bcopy(&partid, &pp->pd_pcontents, sizeof (regid_t));

	part_start = FIRSTAVDP + AVDPLEN;
	part_len = fssize - part_start;
	part_bmp_bytes = (part_len + NBBY - 1) / NBBY;
	part_bmp_sectors = (part_bmp_bytes + SPACEMAP_OFF + sectorsize - 1) /
		sectorsize;

	pp->pd_part_start = part_start;
	pp->pd_part_length = part_len;

	pp->pd_acc_type = acctype;
	nextlogblock = 0;

	/*
	 * Do the partition header
	 */
	/* LINTED */
	php = (struct phdr_desc *)&pp->pd_pc_use;

	/*
	 * Set up unallocated space bitmap
	 */
	if (acctype == PART_ACC_RW || acctype == PART_ACC_OW) {
		php->phdr_usb.sad_ext_len =
			(part_bmp_bytes + SPACEMAP_OFF + sectorsize - 1) &
				(~(sectorsize - 1));
		php->phdr_usb.sad_ext_loc = nextlogblock;
		part_unalloc = nextlogblock;
		nextlogblock += part_bmp_sectors;
	}

	bcopy(&sunmicro, &pp->pd_ii, sizeof (regid_t));
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Logical Volume Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	lvp = (struct log_vol_desc *)buf;
	tp = &lvp->lvd_tag;
	tp->tag_id =  UD_LOG_VOL_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct log_vol_desc) -
			sizeof (struct tag);
	lvp->lvd_vdsn = 0;
	setcharspec(&lvp->lvd_desc_cs, 0, osta_unicode);
	setdstring(lvp->lvd_lvid, udfs_label, 128);
	lvp->lvd_log_bsize = sectorsize;
	bcopy(&udf_compliant, &lvp->lvd_dom_id, sizeof (regid_t));
	lap = (long_ad_t *)&lvp->lvd_lvcu;
	lap->lad_ext_len = FILESETLEN * sectorsize;
	filesetblock = nextlogblock;
	lap->lad_ext_loc = nextlogblock;
	lap->lad_ext_prn = 0;
	lvp->lvd_mtbl_len = 6;
	lvp->lvd_num_pmaps = 1;
	bcopy(&sunmicro, &lvp->lvd_ii, sizeof (regid_t));
	/* LINTED */
	pmp = (struct pmap_typ1 *)&lvp->lvd_pmaps;
	pmp->map1_type = 1;
	pmp->map1_length = 6;
	pmp->map1_vsn = SWAP_16(1);
	pmp->map1_pn  = 0;
	tp->tag_crc_len = (char *)(pmp + 1) - buf - sizeof (struct tag);
	setextad(&lvp->lvd_int_seq_ext, INTSEQLEN, INTSEQSTART);
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Unallocated Space Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	uap = (struct unall_spc_desc *)buf;
	tp = &uap->ua_tag;
	tp->tag_id =  UD_UNALL_SPA_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	uap->ua_vdsn = 0;
	uap->ua_nad = 0;
	tp->tag_crc_len = (char *)uap->ua_al_dsc - buf - sizeof (struct tag);
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Terminating Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	tdp = (struct term_desc *)buf;
	tp = &tdp->td_tag;
	tp->tag_id =  UD_TERM_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct term_desc) -
			sizeof (struct tag);
	tp->tag_loc = nextblock;
	wtvolseq(tp, nextblock, nextblock + volseq_sectors);
	nextblock++;

	/*
	 * Do the anchor volume descriptor
	 */
	if (nextblock > FIRSTAVDP) {
		(void) fprintf(stdout,
			gettext("Volume integrity sequence"
			" descriptors too long\n"));
		exit(32);
	}

	nextblock = FIRSTAVDP;
	bzero(buf, sectorsize);
	/* LINTED */
	avp = (struct anch_vol_desc_ptr *)buf;
	tp = &avp->avd_tag;
	tp->tag_id =  UD_ANCH_VOL_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct anch_vol_desc_ptr) -
			sizeof (struct tag);
	tp->tag_loc = nextblock;
	setextad(&avp->avd_main_vdse,
			volseq_sectors * sectorsize, mvds_loc);
	setextad(&avp->avd_res_vdse,
			volseq_sectors * sectorsize, rvds_loc);
	bzero(buf2, sectorsize);
	/* LINTED */
	maketag(tp, (struct tag *)buf2);
	wtfs(nextblock, sectorsize, buf2);
	nextblock++;

	tp->tag_loc = fssize;
	/* LINTED */
	maketag(tp, (struct tag *)buf2);
	wtfs(fssize, sectorsize, buf2);

	/*
	 * File Set Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	fsp = (struct file_set_desc *)&buf;
	tp = &fsp->fsd_tag;
	tp->tag_id =  UD_FILE_SET_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct file_set_desc) -
			sizeof (struct tag);
	tp->tag_loc = nextlogblock;
	setstamp(&fsp->fsd_time);
	fsp->fsd_ilevel = 3;
	fsp->fsd_mi_level = 3;
	fsp->fsd_cs_list = 1;
	fsp->fsd_mcs_list = 1;
	fsp->fsd_fs_no = 0;
	fsp->fsd_fsd_no = 0;
	setcharspec(&fsp->fsd_lvidcs, 0, osta_unicode);
	setdstring(fsp->fsd_lvid, udfs_label, 128);
	setcharspec(&fsp->fsd_fscs, 0, osta_unicode);
	setdstring(fsp->fsd_fsi, udfs_label, 32);
	setdstring(fsp->fsd_cfi, "", 32);
	setdstring(fsp->fsd_afi, "", 32);
	lap = (long_ad_t *)&fsp->fsd_root_icb;
	lap->lad_ext_len = sectorsize;
	lap->lad_ext_loc = filesetblock + FILESETLEN;
	lap->lad_ext_prn = 0;
	bcopy(&udf_compliant, &fsp->fsd_did, sizeof (regid_t));
	maketag(tp, tp);
	wtfs(nextlogblock + part_start, sectorsize, (char *)tp);
	nextlogblock++;

	/*
	 * Terminating Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	tdp = (struct term_desc *)buf;
	tp = &tdp->td_tag;
	tp->tag_id =  UD_TERM_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct term_desc) -
			sizeof (struct tag);
	tp->tag_loc = nextlogblock;
	maketag(tp, tp);
	wtfs(nextlogblock + part_start, sectorsize, (char *)tp);
	nextlogblock++;

	if (nextlogblock > filesetblock + FILESETLEN) {
		(void) fprintf(stdout,
			gettext("File set descriptor too long\n"));
		exit(32);
	}
	nextlogblock = filesetblock + FILESETLEN;

	/*
	 * Root File Entry
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	fp = (struct file_entry *)&buf;
	tp = &fp->fe_tag;
	tp->tag_id =  UD_FILE_ENTRY;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_loc = nextlogblock;
	icb = &fp->fe_icb_tag;
	icb->itag_prnde = 0;
	icb->itag_strategy = STRAT_TYPE4;
	icb->itag_param = 0; /* what does this mean? */
	icb->itag_max_ent = 1;
	icb->itag_ftype = FTYPE_DIRECTORY;
	icb->itag_lb_loc = 0;
	icb->itag_lb_prn = 0;
	icb->itag_flags = ICB_FLAG_ARCHIVE;
	fp->fe_uid = getuid();
	fp->fe_gid = getgid();
	fp->fe_perms = (0x1f << 10) | (0x5 << 5) | 0x5;
	fp->fe_lcount = 1;
	fp->fe_rec_for = 0;
	fp->fe_rec_dis = 0;
	fp->fe_rec_len = 0;
	fp->fe_info_len = sizeof (struct file_id);
	fp->fe_lbr = 1;
	setstamp(&fp->fe_acc_time);
	setstamp(&fp->fe_mod_time);
	setstamp(&fp->fe_attr_time);
	fp->fe_ckpoint = 1;
	bcopy(&sunmicro, &fp->fe_impl_id, sizeof (regid_t));
	fp->fe_uniq_id = 0;
	fp->fe_len_ear = 0;
	fp->fe_len_adesc = sizeof (short_ad_t);

	/* LINTED */
	sap = (short_ad_t *)(fp->fe_spec + fp->fe_len_ear);
	sap->sad_ext_len = sizeof (struct file_id);
	sap->sad_ext_loc = nextlogblock + 1;
	rootfelen = (char *)(sap + 1) - buf;
	tp->tag_crc_len = rootfelen - sizeof (struct tag);
	maketag(tp, tp);
	wtfs(nextlogblock + part_start, sectorsize, (char *)tp);
	nextlogblock++;

	/*
	 * Root Directory
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	fip = (struct file_id *)&buf;
	tp = &fip->fid_tag;
	tp->tag_id =  UD_FILE_ID_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct file_id) -
			sizeof (struct tag);
	tp->tag_loc = nextlogblock;
	fip->fid_ver = 1;
	fip->fid_flags = FID_DIR | FID_PARENT;
	fip->fid_idlen = 0;
	fip->fid_iulen = 0;
	fip->fid_icb.lad_ext_len = sectorsize; /* rootfelen; */
	fip->fid_icb.lad_ext_loc = nextlogblock - 1;
	fip->fid_icb.lad_ext_prn = 0;
	maketag(tp, tp);
	wtfs(nextlogblock + part_start, sectorsize, (char *)tp);
	nextlogblock++;

	/*
	 * Now do the space bitmaps
	 */
	if (part_unalloc >= 0) {
		int size = sectorsize * part_bmp_sectors;

		sbp = (struct space_bmap_desc *)malloc(size);
		if (!sbp) {
			(void) fprintf(stdout,
				gettext("Can't allocate bitmap space\n"));
			exit(32);
		}
		bzero((char *)sbp, sectorsize * part_bmp_sectors);
		tp = &sbp->sbd_tag;
		tp->tag_id =  UD_SPA_BMAP_DESC;
		tp->tag_desc_ver = ecma_version;
		tp->tag_sno = serialnum;
		tp->tag_crc_len = 0;	/* Don't do CRCs on bitmaps */
		tp->tag_loc = part_unalloc;
		sbp->sbd_nbits = part_len;
		sbp->sbd_nbytes = part_bmp_bytes;
		maketag(tp, tp);
		if (part_unalloc >= 0) {
			int32_t i;

			cp = (uint8_t *)sbp + SPACEMAP_OFF;
			i = nextlogblock / NBBY;
			cp[i++] = (0xff << (nextlogblock % NBBY)) & 0xff;
			while (i < part_bmp_bytes)
				cp[i++] = 0xff;
			if (part_len % NBBY)
				cp[--i] = (unsigned)0xff >>
					(NBBY - part_len % NBBY);

			wtfs(part_unalloc + part_start, size, (char *)tp);
		}
		free((char *)sbp);
	}

	/*
	 * Volume Integrity Descriptor
	 */
	nextblock = INTSEQSTART;
	endblock = nextblock + INTSEQLEN / sectorsize;
	/* LINTED */
	lvip = (struct log_vol_int_desc *)&lvid;
	tp = &lvip->lvid_tag;
	tp->tag_id =  UD_LOG_VOL_INT;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_loc = nextblock;
	setstamp(&lvip->lvid_tstamp);
	lvip->lvid_int_type = LOG_VOL_CLOSE_INT;
	setextad(&lvip->lvid_nie, 0, 0);
	lvip->lvid_npart = 1;
	lvip->lvid_liu = 0x2e;
	lvip->lvid_uniqid = MAXID + 1;
	lvip->lvid_fst[0] = part_len - nextlogblock;	/* Free space */
	lvip->lvid_fst[1] = part_len;			/* Size */
	lviup = (struct lvid_iu *)&lvip->lvid_fst[2];
	bcopy(&sunmicro, &lviup->lvidiu_regid, sizeof (regid_t));
	lviup->lvidiu_nfiles = 0;
	lviup->lvidiu_ndirs = 1;
	lviup->lvidiu_mread = 0x102;
	lviup->lvidiu_mwrite = 0x102;
	lviup->lvidiu_maxwr = 0x150;
	tp->tag_crc_len = sizeof (struct log_vol_int_desc) + lvip->lvid_liu -
		sizeof (struct tag);
	maketag(tp, tp);
	wtfs(nextblock, sectorsize, (char *)tp);
	nextblock++;

	/*
	 * Terminating Descriptor
	 */
	bzero(buf, sectorsize);
	/* LINTED */
	tdp = (struct term_desc *)buf;
	tp = &tdp->td_tag;
	tp->tag_id =  UD_TERM_DESC;
	tp->tag_desc_ver = ecma_version;
	tp->tag_sno = serialnum;
	tp->tag_crc_len = sizeof (struct term_desc) - sizeof (struct tag);
	tp->tag_loc = nextblock;
	maketag(tp, tp);
	wtfs(nextblock, sectorsize, (char *)tp);
	nextblock++;

	/* Zero out the rest of the LVI extent */
	bzero(buf, sectorsize);
	while (nextblock < endblock)
		wtfs(nextblock++, sectorsize, buf);
}

/*
 * read a block from the file system
 */
static void
rdfs(daddr_t bno, int size, char *bf)
{
	int n, saverr;

	if (llseek(fsi, (offset_t)bno * sectorsize, 0) < 0) {
		saverr = errno;
		(void) fprintf(stderr,
			gettext("seek error on sector %ld: %s\n"),
			bno, strerror(saverr));
		exit(32);
	}
	n = read(fsi, bf, size);
	if (n != size) {
		saverr = errno;
		(void) fprintf(stderr,
			gettext("read error on sector %ld: %s\n"),
			bno, strerror(saverr));
		exit(32);
	}
}

/*
 * write a block to the file system
 */
static void
wtfs(daddr_t bno, int size, char *bf)
{
	int n, saverr;

	if (fso == -1)
		return;

	if (llseek(fso, (offset_t)bno * sectorsize, 0) < 0) {
		saverr = errno;
		(void) fprintf(stderr,
			gettext("seek error on sector %ld: %s\n"),
			bno, strerror(saverr));
		exit(32);
	}
	if (Nflag)
		return;
	n = write(fso, bf, size);
	if (n != size) {
		saverr = errno;
		(void) fprintf(stderr,
			gettext("write error on sector %ld: %s\n"),
			bno, strerror(saverr));
		exit(32);
	}
}

static void
usage(void)
{
	(void) fprintf(stderr,
		gettext("udfs usage: mkfs [-F FSType] [-V]"
		" [-m] [-o options] special size(sectors)\n"));
	(void) fprintf(stderr,
		gettext(" -m : dump fs cmd line used to make"
		" this partition\n"));
	(void) fprintf(stderr,
		gettext(" -V : print this command line and return\n"));
	(void) fprintf(stderr,
		gettext(" -o : udfs options: :psize=%d:label=%s\n"),
		sectorsize, udfs_label);
	(void) fprintf(stderr,
		gettext("NOTE that all -o suboptions: must"
		" be separated only by commas so as to\n"));
	(void) fprintf(stderr,
		gettext("be parsed as a single argument\n"));
	exit(32);
}

/*ARGSUSED*/
static void
dump_fscmd(char *fsys, int fsi)
{
	(void) printf(gettext("mkfs -F udfs -o "));
	(void) printf("psize=%d,label=\"%s\" %s %d\n",
		sectorsize, oldlabel, fsys, oldfssize);
}

/* number ************************************************************* */
/*									*/
/* Convert a numeric arg to binary					*/
/*									*/
/* Arg:	 big - maximum valid input number				*/
/* Global arg:  string - pointer to command arg				*/
/*									*/
/* Valid forms: 123 | 123k | 123*123 | 123x123				*/
/*									*/
/* Return:	converted number					*/
/*									*/
/* ******************************************************************** */

static int32_t
number(long big, char *param)
{
	char		*cs;
	int64_t		n = 0;
	int64_t		cut = BIG;
	int32_t		minus = 0;

#define	FOUND_MULT	0x1
#define	FOUND_K		0x2

	cs = string;
	if (*cs == '-') {
		minus = 1;
		cs++;
	}
	n = 0;
	while ((*cs != ' ') && (*cs != '\0') && (*cs != ',')) {
		if ((*cs >= '0') && (*cs <= '9')) {
			n = n * 10 + *cs - '0';
			cs++;
		} else if ((*cs == '*') || (*cs == 'x')) {
			if (number_flags & FOUND_MULT) {
				(void) fprintf(stderr,
				gettext("mkfs: only one \"*\" "
				"or \"x\" allowed\n"));
				exit(2);
			}
			number_flags |= FOUND_MULT;
			cs++;
			string = cs;
			n = n * number(big, param);
			cs = string;
			continue;
		} else if (*cs == 'k') {
			if (number_flags & FOUND_K) {
				(void) fprintf(stderr,
				gettext("mkfs: only one \"k\" allowed\n"));
				exit(2);
			}
			number_flags |= FOUND_K;
			n = n * 1024;
			cs++;
			continue;
		} else {
			(void) fprintf(stderr,
				gettext("mkfs: bad numeric arg: \"%s\"\n"),
				string);
			exit(2);
		}
	}

	if (n > cut) {
		(void) fprintf(stderr,
			gettext("mkfs: value for %s overflowed\n"), param);
		exit(2);
	}

	if (minus) {
		n = -n;
	}

	if ((n > big) || (n < 0)) {
		(void) fprintf(stderr,
			gettext("mkfs: argument %s out of range\n"), param);
		exit(2);
	}

	string = cs;
	return ((int32_t)n);
}

/* match ************************************************************** */
/*									*/
/* Compare two text strings for equality				*/
/*									*/
/* Arg:	 s - pointer to string to match with a command arg		*/
/* Global arg:  string - pointer to command arg				*/
/*									*/
/* Return:	1 if match, 0 if no match				*/
/*		If match, also reset `string' to point to the text	*/
/*		that follows the matching text.				*/
/*									*/
/* ******************************************************************** */

static int
match(char *s)
{
	char *cs;

	cs = string;
	while (*cs++ == *s) {
		if (*s++ == '\0') {
			goto true;
		}
	}
	if (*s != '\0') {
		return (0);
	}

true:
	cs--;
	string = cs;
	return (1);
}

static uint32_t
get_bsize(void)
{
	struct dk_cinfo info;
	struct fd_char fd_char;
	struct dk_minfo dkminfo;

	if (ioctl(fso, DKIOCINFO, &info) < 0) {
		perror("mkfs DKIOCINFO ");
		(void) fprintf(stdout,
			gettext("DKIOCINFO failed using psize = 2048"
			" for creating file-system\n"));
		return (0);
	}

	switch (info.dki_ctype) {
		case DKC_CDROM :
			return (2048);
		case DKC_SCSI_CCS :
			if (ioctl(fso, DKIOCGMEDIAINFO, &dkminfo) != -1) {
				if (dkminfo.dki_lbsize != 0 &&
				    POWEROF2(dkminfo.dki_lbsize / DEV_BSIZE) &&
				    dkminfo.dki_lbsize != DEV_BSIZE) {
					fprintf(stderr,
					    gettext("The device sector size "
					    "%u is not supported by udfs!\n"),
					    dkminfo.dki_lbsize);
					(void) close(fso);
					exit(1);
				}
			}
			/* FALLTHROUGH */
		case DKC_INTEL82072 :
			/* FALLTHROUGH */
		case DKC_INTEL82077 :
			/* FALLTHROUGH */
		case DKC_DIRECT :
			if (ioctl(fso, FDIOGCHAR, &fd_char) >= 0) {
				return (fd_char.fdc_sec_size);
			}
			/* FALLTHROUGH */
		case DKC_PCMCIA_ATA :
			return (512);
		default :
			return (0);
	}
}

/*
 * Read in the volume sequences descriptors.
 */
static int
readvolseq(void)
{
	struct tag *tp;
	uint8_t *cp, *end;
	int err;
	struct pri_vol_desc *pvolp;
	struct part_desc *partp = NULL;
	struct log_vol_desc *logvp = NULL;
	struct anch_vol_desc_ptr *avp;
	char *main_vdbuf;
	uint32_t nextblock;

	avp = (struct anch_vol_desc_ptr *)malloc(sectorsize);
	rdfs(FIRSTAVDP, sectorsize, (char *)avp);
	tp = (struct tag *)avp;
	err = verifytag(tp, FIRSTAVDP, tp, UD_ANCH_VOL_DESC);
	if (err)
		return (0);
	main_vdbuf = malloc(avp->avd_main_vdse.ext_len);
	if (main_vdbuf == NULL) {
		(void) fprintf(stderr, gettext("Cannot allocate space for "
			"volume sequences\n"));
		exit(32);
	}
	rdfs(avp->avd_main_vdse.ext_loc, avp->avd_main_vdse.ext_len,
		main_vdbuf);
	end = (uint8_t *)main_vdbuf + avp->avd_main_vdse.ext_len;

	nextblock = avp->avd_main_vdse.ext_loc;
	for (cp = (uint8_t *)main_vdbuf; cp < end; cp += sectorsize,
		nextblock++) {
		/* LINTED */
		tp = (struct tag *)cp;
		err = verifytag(tp, nextblock, tp, 0);
		if (err)
			continue;

		switch (tp->tag_id) {
		case UD_PRI_VOL_DESC:
			/* Bump serial number, according to spec. */
			serialnum = tp->tag_sno + 1;
			pvolp = (struct pri_vol_desc *)tp;
			oldlabel = pvolp->pvd_vol_id + 1;
			break;
		case UD_ANCH_VOL_DESC:
			avp = (struct anch_vol_desc_ptr *)tp;
			break;
		case UD_VOL_DESC_PTR:
			break;
		case UD_IMPL_USE_DESC:
			break;
		case UD_PART_DESC:
			partp = (struct part_desc *)tp;
			part_start = partp->pd_part_start;
			part_len = partp->pd_part_length;
			oldfssize = part_start + part_len;
			break;
		case UD_LOG_VOL_DESC:
			logvp = (struct log_vol_desc *)tp;
			break;
		case UD_UNALL_SPA_DESC:
			break;
		case UD_TERM_DESC:
			goto done;
			break;
		case UD_LOG_VOL_INT:
			break;
		default:
			break;
		}
	}
done:
	if (!partp || !logvp) {
		return (0);
	}
	return (1);
}

uint32_t
get_last_block(void)
{
	struct vtoc vtoc;
	struct dk_cinfo dki_info;

	if (ioctl(fsi, DKIOCGVTOC, (intptr_t)&vtoc) != 0) {
		(void) fprintf(stderr, gettext("Unable to read VTOC\n"));
		return (0);
	}

	if (vtoc.v_sanity != VTOC_SANE) {
		(void) fprintf(stderr, gettext("Vtoc.v_sanity != VTOC_SANE\n"));
		return (0);
	}

	if (ioctl(fsi, DKIOCINFO, (intptr_t)&dki_info) != 0) {
		(void) fprintf(stderr,
		    gettext("Could not get the slice information\n"));
		return (0);
	}

	if (dki_info.dki_partition > V_NUMPAR) {
		(void) fprintf(stderr,
		    gettext("dki_info.dki_partition > V_NUMPAR\n"));
		return (0);
	}

	return ((uint32_t)vtoc.v_part[dki_info.dki_partition].p_size);
}
