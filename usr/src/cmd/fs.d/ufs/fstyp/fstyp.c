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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * fstyp
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <locale.h>
#include <fcntl.h>
#include <errno.h>
#include <strings.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/mntent.h>
#include <sys/errno.h>
#include <sys/fs/ufs_fs.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/mnttab.h>

#include <sys/fs/ufs_log.h>
#include <sys/inttypes.h>

#define	MAXLABELS	20
#define	LINEMAX		256
#define	NRPOS		8	/* for pre FFFS compatibility */

static int vflag = 0;		/* verbose output */
static int errflag = 0;
static char *special;

static void usage(void);
static int dumpfs(const char *name);
static void dumpcg(const char *name, const int c);
static void pbits(const void *cp, const int max);

static void dumplog(const char *name);

extern  char    *getfullrawname();

int
main(int argc, char *argv[])
{
	int c;
	struct stat64 st;
	char device[MAXPATHLEN];

	(void) setlocale(LC_ALL, "");
#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN "SYS_TEST"
#endif
	(void) textdomain(TEXT_DOMAIN);

	while ((c = getopt(argc, argv, "v")) != EOF) {
		switch (c) {
		case 'v':		/* dump super block */
			vflag++;
			break;

		case '?':
			errflag++;
		}
	}
	if (errflag || argc <= optind) {
		usage();
		return (31+1);
	}

	/*
	 * insure that the special device is raw since > 32-bit seeks
	 * will not work with block devices (bugs 1248701 and 4045593).
	 */

	special = getfullrawname(argv[optind]);
	if (special == NULL) {
		(void) fprintf(stderr, gettext("fstyp: malloc failed\n"));
		exit(31+1);
	}

	if (*special == '\0') {
		if (strchr(argv[optind], '/') != NULL) {
			if (stat64(argv[optind], &st) < 0) {
				(void) fprintf(stderr, "fstyp: %s: %s\n",
				    argv[optind], strerror(errno));
				usage();
				exit(31+1);
			}
			(void) fprintf(stderr,
			    gettext("%s: not a raw disk device\n"),
			    argv[optind]);
			usage();
			exit(31+1);
		}
		(void) snprintf(device, MAXPATHLEN, "/dev/rdsk/%s",
		    argv[optind]);
		if ((special = getfullrawname(device)) == NULL) {
			(void) fprintf(stderr,
			    gettext("fstyp: malloc failed\n"));
			exit(31+1);
		}

		if (*special == '\0') {
			(void) snprintf(device, MAXPATHLEN, "/dev/%s",
			    argv[optind]);
			if ((special = getfullrawname(device)) == NULL) {
				(void) fprintf(stderr,
				    gettext("fstyp: malloc failed\n"));
				exit(31+1);
			}
			if (*special == '\0') {
				(void) fprintf(stderr,
				    gettext("%s: not a raw disk device\n"),
				    argv[optind]);
				usage();
				exit(31+1);
			}
		}
	}

	return (dumpfs(special));
}


static void
usage(void)
{
	(void) fprintf(stderr, gettext("ufs usage: fstyp [-v] special\n"));
}

static union {
	struct fs fs;
	char pad[MAXBSIZE];
} fsun;
#define	afs	fsun.fs

static union {
	struct cg cg;
	char pad[MAXBSIZE];
} cgun;
#define	acg	cgun.cg

char	eg[MAXBSIZE];

static int
dumpfs(const char *name)
{
	int c, i, j, k, size, nrpos;
	struct fs *fsp;
	offset_t offset;
	caddr_t sip;
	time_t t;

	(void) close(0);
	if (open64(name, 0) != 0) {
		perror(name);
		return (1);
	}
	llseek(0, (offset_t)SBLOCK * DEV_BSIZE, 0);
	if (read(0, &afs, SBSIZE) != SBSIZE) {
		perror(name);
		return (1);
	}
	if ((afs.fs_magic != FS_MAGIC) && (afs.fs_magic != MTB_UFS_MAGIC))
		return (31+1);
	if ((afs.fs_magic == MTB_UFS_MAGIC) &&
	    (afs.fs_version > MTB_UFS_VERSION_1 ||
	    afs.fs_version < MTB_UFS_VERSION_MIN))
		return (31+1);
	printf("%s\n", "ufs");
	if (!vflag)
		return (0);
	fsp = &afs;
	t = (time_t)afs.fs_time;
	printf("magic\t%x\tformat\t%s\ttime\t%s", afs.fs_magic,
	    afs.fs_postblformat == FS_42POSTBLFMT ? "static" : "dynamic",
	    ctime(&t));
	printf("sblkno\t%d\tcblkno\t%d\tiblkno\t%d\tdblkno\t%d\n",
	    afs.fs_sblkno, afs.fs_cblkno, afs.fs_iblkno, afs.fs_dblkno);
	printf("sbsize\t%d\tcgsize\t%d\tcgoffset %d\tcgmask\t0x%08x\n",
	    afs.fs_sbsize, afs.fs_cgsize, afs.fs_cgoffset, afs.fs_cgmask);
	printf("ncg\t%d\tsize\t%d\tblocks\t%d\n",
	    afs.fs_ncg, afs.fs_size, afs.fs_dsize);
	printf("bsize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    afs.fs_bsize, afs.fs_bshift, afs.fs_bmask);
	printf("fsize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    afs.fs_fsize, afs.fs_fshift, afs.fs_fmask);
	printf("frag\t%d\tshift\t%d\tfsbtodb\t%d\n",
	    afs.fs_frag, afs.fs_fragshift, afs.fs_fsbtodb);
	printf("minfree\t%d%%\tmaxbpg\t%d\toptim\t%s\n",
	    afs.fs_minfree, afs.fs_maxbpg,
	    afs.fs_optim == FS_OPTSPACE ? "space" : "time");
	printf("maxcontig %d\trotdelay %dms\trps\t%d\n",
	    afs.fs_maxcontig, afs.fs_rotdelay, afs.fs_rps);
	printf("csaddr\t%d\tcssize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    afs.fs_csaddr, afs.fs_cssize, afs.fs_csshift, afs.fs_csmask);
	printf("ntrak\t%d\tnsect\t%d\tspc\t%d\tncyl\t%d\n",
	    afs.fs_ntrak, afs.fs_nsect, afs.fs_spc, afs.fs_ncyl);
	printf("cpg\t%d\tbpg\t%d\tfpg\t%d\tipg\t%d\n",
	    afs.fs_cpg, afs.fs_fpg / afs.fs_frag, afs.fs_fpg, afs.fs_ipg);
	printf("nindir\t%d\tinopb\t%d\tnspf\t%d\n",
	    afs.fs_nindir, afs.fs_inopb, afs.fs_nspf);
	printf("nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
	    afs.fs_cstotal.cs_nbfree, afs.fs_cstotal.cs_ndir,
	    afs.fs_cstotal.cs_nifree, afs.fs_cstotal.cs_nffree);
	printf("cgrotor\t%d\tfmod\t%d\tronly\t%d\tlogbno\t%d\n",
	    afs.fs_cgrotor, afs.fs_fmod, afs.fs_ronly, afs.fs_logbno);
	printf("version\t%d\n", afs.fs_version);
	if (afs.fs_reclaim & (FS_RECLAIM | FS_RECLAIMING)) {
		printf("fs_reclaim%s%s\n",
		    (afs.fs_reclaim & FS_RECLAIM)    ? " FS_RECLAIM"    : "",
		    (afs.fs_reclaim & FS_RECLAIMING) ? " FS_RECLAIMING" : "");
	} else {
		printf("fs_reclaim is not set\n");
	}
	if (afs.fs_state + (long)afs.fs_time == FSOKAY) {
		printf(gettext("file system state is valid, fsclean is %d\n"),
		    afs.fs_clean);
	} else {
		printf(gettext("file system state is not valid\n"));
	}
	if (afs.fs_cpc != 0) {
		printf(gettext("blocks available in each rotational position"));
	} else {
		printf(gettext(
		    "insufficient space to maintain rotational tables\n"));
	}
	for (c = 0; c < afs.fs_cpc; c++) {
		printf(gettext("\ncylinder number %d:"), c);
		nrpos = (((fsp)->fs_postblformat == FS_DYNAMICPOSTBLFMT) ?
		    (fsp)->fs_nrpos : NRPOS);
		for (i = 0; i < nrpos; i++) {
			if (fs_postbl(fsp, c)[i] == -1)
				continue;
			printf(gettext("\n   position %d:\t"), i);
			/*CSTYLED*/
			for (j = fs_postbl(fsp, c)[i], k = 1; ;
			    j += fs_rotbl(fsp)[j], k++) {
				printf("%5d", j);
				if (k % 12 == 0)
					printf("\n\t\t");
				if ((fs_rotbl(fsp))[j] == 0)
					break;
			}
		}
	}
	printf("\ncs[].cs_(nbfree,ndir,nifree,nffree):\n\t");
	sip = calloc(1, afs.fs_cssize);
	afs.fs_u.fs_csp = (struct csum *)sip;
	for (i = 0, j = 0; i < afs.fs_cssize; i += afs.fs_bsize, j++) {
		size = afs.fs_cssize - i < afs.fs_bsize ?
		    afs.fs_cssize - i : afs.fs_bsize;
		offset = (offset_t)fsbtodb(
		    &afs, (afs.fs_csaddr + j * afs.fs_frag)) * DEV_BSIZE;
		llseek(0, offset, 0);
		if (read(0, sip, size) != size) {
			perror(name);
			return (1);
		}
		sip += size;
	}
	for (i = 0; i < afs.fs_ncg; i++) {
		struct csum *cs = &afs.fs_cs(&afs, i);
		if (i && i % 4 == 0)
			printf("\n\t");
		printf("(%ld,%ld,%ld,%ld) ",
		    cs->cs_nbfree, cs->cs_ndir, cs->cs_nifree, cs->cs_nffree);
	}
	printf("\n");
	if (afs.fs_ncyl % afs.fs_cpg) {
		printf(gettext("cylinders in last group %d\n"),
		    i = afs.fs_ncyl % afs.fs_cpg);
		printf(gettext("blocks in last group %d\n"),
		    i * afs.fs_spc / NSPB(&afs));
	}
	printf("\n");
	for (i = 0; i < afs.fs_ncg; i++)
		dumpcg(name, i);
	if (afs.fs_logbno)
		dumplog(name);
	(void) close(0);
	return (0);
}

static void
setsum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t csum = 0;

	*sp = 0;
	nb /= sizeof (int32_t);
	while (nb--)
		csum += *lp++;
	*sp = csum;
}

static int
checksum(int32_t *sp, int32_t *lp, int nb)
{
	int32_t ssum = *sp;

	setsum(sp, lp, nb);
	if (ssum != *sp) {
		*sp = ssum;
		return (0);
	}
	return (1);
}

static void
dumplog(const char *name)
{
	int i;
	long		tb = 0;
	extent_block_t	*ebp;
	extent_t	*ep;
	ml_odunit_t	*ud;

	printf("\nlog\n");
	if (afs.fs_magic == FS_MAGIC)
		printf("log allocation block %ld\n", afs.fs_logbno);
	else
		printf("log allocation block (in frags) %ld\n", afs.fs_logbno);
	(void) llseek(0, (offset_t)logbtodb(&afs, afs.fs_logbno) * DEV_BSIZE,
	    0);
	if (read(0, (char *)&eg, afs.fs_bsize) != afs.fs_bsize) {
		printf(gettext(
			"dumplog: %s: error reading log allocation\n"),
			name);
		return;
	}
	ebp = (void *)eg;
	if (ebp->type != LUFS_EXTENTS)
		printf(gettext("Invalid log allocation type %x\n"), ebp->type);
	if (!checksum(&ebp->chksum, (int32_t *)ebp, afs.fs_bsize))
		printf(gettext("Invalid log checksum\n"));

	for (i = 0, ep = &ebp->extents[0]; i < ebp->nextents; ++i, ++ep) {
		printf("\tlogical block\t%" PRId32
			"\tphysical block\t%" PRId32
			"\tblocks\t%" PRId32 "\n",
			ep->lbno, ep->pbno, ep->nbno);
		tb += dbtob(ep->nbno);
	}
	printf("log size %" PRIu32 " bytes (%ld calculated)\n",
		ebp->nbytes, tb);
	printf("\n");
	ep = &ebp->extents[0];
	(void) llseek(0, (offset_t)logbtodb(&afs, ep->pbno) * DEV_BSIZE, 0);
	if (read(0, (char *)&eg, dbtob(LS_SECTORS)) != dbtob(LS_SECTORS)) {
		printf(gettext(
			"dumplog: %s: error reading log state\n"), name);
		return;
	}
	ud = (void *)&eg;
	printf("version\t\t%" PRIu32 "\t\t", ud->od_version);
	if (ud->od_badlog)
		printf("logstate\tError\n");
	else
		printf("logstate\tOkay\n");
	printf("bol\t\t%" PRId32 "\t\teol\t\t%" PRId32 "\n",
		ud->od_bol_lof, ud->od_eol_lof);
	printf("requestsize\t%" PRIu32 "\n", ud->od_requestsize);
	printf("statesize\t%" PRIu32 "\n", ud->od_statesize);
	printf("logsize\t\t%" PRIu32 "\n", ud->od_logsize);
	printf("maxtransfer\t%" PRIu32 "\t\tdevbsize\t%" PRIu32 "\n",
		ud->od_maxtransfer, ud->od_devbsize);
	printf("head\t\t%" PRId32 "\t\thead ident\t%#" PRIx32 "\n",
		ud->od_head_lof, ud->od_head_ident);
	printf("tail\t\t%" PRId32 "\t\ttail ident\t%#" PRIx32 "\n",
		ud->od_tail_lof, ud->od_tail_ident);
	printf("\t\t\t\tdebug\t\t%#" PRIx32 "\n", ud->od_debug);
	if (ud->od_head_ident + ud->od_tail_ident != ud->od_chksum)
		printf("Bad chksum\t%#" PRIx32 "\n", ud->od_chksum);
	else
		printf("Good chksum\t%#" PRIx32 "\n", ud->od_chksum);
}

static void
dumpcg(const char *name, const int c)
{
	int i, j;
	offset_t	off;
	struct cg	*cgp;
	struct ocg	*ocgp;
	struct fs	*fsp;
	time_t		t;

	printf("\ncg %d:\n", c);
	off = llseek(0, (offset_t)fsbtodb(&afs, cgtod(&afs, c)) * DEV_BSIZE, 0);
	if (read(0, (char *)&acg, afs.fs_bsize) != afs.fs_bsize) {
		printf(gettext("dumpfs: %s: error reading cg\n"), name);
		return;
	}
	cgp = (struct cg *)&acg;
	ocgp = (struct ocg *)&acg;
	fsp = &afs;
	if (!cg_chkmagic(cgp))
	    printf(gettext("Invalid Cylinder grp magic fffs:%x  4.2 fs:%x\n"),
		cgp->cg_magic, ocgp->cg_magic);
	if (cgp->cg_magic == CG_MAGIC) {
		/* print FFFS 4.3 cyl grp format. */
		t = (time_t)cgp->cg_time;
		printf("magic\t%x\ttell\t%lx\ttime\t%s",
		    cgp->cg_magic, (off_t)off, ctime(&t)); /* *** */
		printf("cgx\t%d\tncyl\t%d\tniblk\t%d\tndblk\t%d\n",
		    cgp->cg_cgx, cgp->cg_ncyl, cgp->cg_niblk, cgp->cg_ndblk);
		printf("nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
		    cgp->cg_cs.cs_nbfree, cgp->cg_cs.cs_ndir,
		    cgp->cg_cs.cs_nifree, cgp->cg_cs.cs_nffree);
		printf("rotor\t%d\tirotor\t%d\tfrotor\t%d\nfrsum",
		    cgp->cg_rotor, cgp->cg_irotor, cgp->cg_frotor);
		for (i = 1, j = 0; i < afs.fs_frag; i++) {
			printf("\t%d", cgp->cg_frsum[i]);
			j += i * cgp->cg_frsum[i];
		}
		printf(gettext("\nsum of frsum: %d\niused:\t"), j);
		pbits(cg_inosused(cgp), afs.fs_ipg);
		printf(gettext("free:\t"));
		pbits(cg_blksfree(cgp), afs.fs_fpg);
		printf("b:\n");
		for (i = 0; i < afs.fs_cpg; i++) {
			printf("   c%d:\t(%d)\t", i, cg_blktot(cgp)[i]);
			for (j = 0; j < fsp->fs_nrpos; j++)	/* ****** */
				printf(" %d", cg_blks(fsp, cgp, i)[j]);
			printf("\n");
		}
	} else if (ocgp->cg_magic == CG_MAGIC) {
		/* print Old cyl grp format. */
		t = (time_t)ocgp->cg_time;
		printf("magic\t%x\ttell\t%lx\ttime\t%s",
		    ocgp->cg_magic, (off_t)off, ctime(&t));
		printf("cgx\t%d\tncyl\t%d\tniblk\t%d\tndblk\t%d\n",
		    ocgp->cg_cgx, ocgp->cg_ncyl, ocgp->cg_niblk,
		    ocgp->cg_ndblk);
		printf("nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
		    ocgp->cg_cs.cs_nbfree, ocgp->cg_cs.cs_ndir,
		    ocgp->cg_cs.cs_nifree, ocgp->cg_cs.cs_nffree);
		printf("rotor\t%d\tirotor\t%d\tfrotor\t%d\nfrsum",
		    ocgp->cg_rotor, ocgp->cg_irotor, ocgp->cg_frotor);
		for (i = 1, j = 0; i < afs.fs_frag; i++) {
			printf("\t%d", ocgp->cg_frsum[i]);
			j += i * ocgp->cg_frsum[i];
		}
		printf(gettext("\nsum of frsum: %d\niused:\t"), j);
		pbits(ocgp->cg_iused, afs.fs_ipg);
		printf(gettext("free:\t"));
		pbits(ocgp->cg_free, afs.fs_fpg);
		printf("b:\n");
		for (i = 0; i < afs.fs_cpg; i++) {
			printf("   c%d:\t(%d)\t", i, ocgp->cg_btot[i]);
			for (j = 0; j < NRPOS; j++)
				printf(" %d", ocgp->cg_b[i][j]);
			printf("\n");
		}
	}
}


static void
pbits(const void *p, const int max)
{
	int i;
	int count = 0, j;
	unsigned char *cp = (unsigned char *)p;

	for (i = 0; i < max; i++) {
		if (isset(cp, i)) {
			if (count)
				printf(",%s", (count % 9 == 8) ? "\n\t" : " ");
			count++;
			printf("%d", i);
			j = i;
			while ((i + 1) < max && isset(cp, i+1))
				i++;
			if (i != j)
				printf("-%d", i);
		}
	}
	printf("\n");
}
