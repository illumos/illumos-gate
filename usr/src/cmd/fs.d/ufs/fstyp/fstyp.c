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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
 * libfstyp module for ufs
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

#include <libfstyp_module.h>

typedef struct fstyp_ufs {
	int		fd;
	nvlist_t	*attr;

	union {
		struct fs fs;
		char pad[MAXBSIZE];
	} fsun;

	union {
		struct cg cg;
		char pad[MAXBSIZE];
	} cgun;

	char		eg[MAXBSIZE];
} fstyp_ufs_t;

#define	afs	fsun.fs
#define	acg	cgun.cg

#define	MAXLABELS	20
#define	LINEMAX		256
#define	NRPOS		8	/* for pre FFFS compatibility */

static int	is_ufs(fstyp_ufs_t *h);
static int	get_attr(fstyp_ufs_t *h);
static int	dumpfs(fstyp_ufs_t *h, FILE *fout, FILE *ferr);
static void	dumplog(fstyp_ufs_t *h, FILE *fout, FILE *ferr);
static void	dumpcg(fstyp_ufs_t *h, FILE *fout, FILE *ferr, const int c);
static void	pbits(FILE *out, const void *cp, const int max);

int	fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle);
void	fstyp_mod_fini(fstyp_mod_handle_t handle);
int	fstyp_mod_ident(fstyp_mod_handle_t handle);
int	fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp);
int	fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr);


int
fstyp_mod_init(int fd, off_t offset, fstyp_mod_handle_t *handle)
{
	struct fstyp_ufs *h;

	if (offset != 0) {
		return (FSTYP_ERR_OFFSET);
	}

	if ((h = calloc(1, sizeof (struct fstyp_ufs))) == NULL) {
		return (FSTYP_ERR_NOMEM);
	}
	h->fd = fd;

	*handle = (fstyp_mod_handle_t)h;
	return (0);
}

void
fstyp_mod_fini(fstyp_mod_handle_t handle)
{
	struct fstyp_ufs *h = (struct fstyp_ufs *)handle;

	if (h->attr == NULL) {
		nvlist_free(h->attr);
		h->attr = NULL;
	}
	free(h);
}

int
fstyp_mod_ident(fstyp_mod_handle_t handle)
{
	struct fstyp_ufs *h = (struct fstyp_ufs *)handle;

	return (is_ufs(h));
}

int
fstyp_mod_get_attr(fstyp_mod_handle_t handle, nvlist_t **attrp)
{
	struct fstyp_ufs *h = (struct fstyp_ufs *)handle;
	int error;

	if (h->attr == NULL) {
		if (nvlist_alloc(&h->attr, NV_UNIQUE_NAME_TYPE, 0)) {
			return (FSTYP_ERR_NOMEM);
		}
		if ((error = get_attr(h)) != 0) {
			nvlist_free(h->attr);
			h->attr = NULL;
			return (error);
		}
	}

	*attrp = h->attr;
	return (0);
}

int
fstyp_mod_dump(fstyp_mod_handle_t handle, FILE *fout, FILE *ferr)
{
	struct fstyp_ufs *h = (struct fstyp_ufs *)handle;

	return (dumpfs(h, fout, ferr));
}

static int
is_ufs(fstyp_ufs_t *h)
{
	(void) llseek(h->fd, (offset_t)SBLOCK * DEV_BSIZE, 0);
	if (read(h->fd, &h->afs, SBSIZE) != SBSIZE) {
		return (FSTYP_ERR_IO);
	}
	if ((h->afs.fs_magic != FS_MAGIC) &&
	    (h->afs.fs_magic != MTB_UFS_MAGIC)) {
		return (FSTYP_ERR_NO_MATCH);
	}
	if ((h->afs.fs_magic == FS_MAGIC) &&
	    (h->afs.fs_version != UFS_EFISTYLE4NONEFI_VERSION_2 &&
	    h->afs.fs_version != UFS_VERSION_MIN)) {
		return (FSTYP_ERR_NO_MATCH);
	}
	if ((h->afs.fs_magic == MTB_UFS_MAGIC) &&
	    (h->afs.fs_version > MTB_UFS_VERSION_1 ||
	    h->afs.fs_version < MTB_UFS_VERSION_MIN)) {
		return (FSTYP_ERR_NO_MATCH);
	}
	return (0);
}

#define	ADD_STRING(h, name, value) \
	if (nvlist_add_string(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_INT32(h, name, value) \
	if (nvlist_add_int32(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

#define	ADD_BOOL(h, name, value) \
	if (nvlist_add_boolean_value(h->attr, name, value) != 0) { \
		return (FSTYP_ERR_NOMEM); \
	}

static int
get_attr(fstyp_ufs_t *h)
{
	struct fs *fsp = &h->afs;
	char	s[128];
	time_t	t;

	ADD_INT32(h, "magic", fsp->fs_magic);
	ADD_STRING(h, "format",
	    fsp->fs_postblformat == FS_42POSTBLFMT ? "static" : "dynamic");
	t = (time_t)fsp->fs_time;
	(void) snprintf(s, sizeof (s), "%s", ctime(&t));
	s[strlen(s) - 1] = '\0';
	ADD_STRING(h, "time", s);
	ADD_INT32(h, "sblkno", fsp->fs_sblkno);
	ADD_INT32(h, "cblkno", fsp->fs_cblkno);
	ADD_INT32(h, "iblkno", fsp->fs_iblkno);
	ADD_INT32(h, "dblkno", fsp->fs_dblkno);
	ADD_INT32(h, "sbsize", fsp->fs_sbsize);
	ADD_INT32(h, "cgsize", fsp->fs_cgsize);
	ADD_INT32(h, "cgoffset", fsp->fs_cgoffset);
	ADD_INT32(h, "cgmask", fsp->fs_cgmask);
	ADD_INT32(h, "ncg", fsp->fs_ncg);
	ADD_INT32(h, "size", fsp->fs_size);
	ADD_INT32(h, "blocks", fsp->fs_dsize);
	ADD_INT32(h, "bsize", fsp->fs_bsize);
	ADD_INT32(h, "bshift", fsp->fs_bshift);
	ADD_INT32(h, "bmask", fsp->fs_bmask);
	ADD_INT32(h, "fsize", fsp->fs_fsize);
	ADD_INT32(h, "fshift", fsp->fs_fshift);
	ADD_INT32(h, "fmask", fsp->fs_fmask);
	ADD_INT32(h, "frag", fsp->fs_frag);
	ADD_INT32(h, "fragshift", fsp->fs_fragshift);
	ADD_INT32(h, "fsbtodb", fsp->fs_fsbtodb);
	ADD_INT32(h, "minfree", fsp->fs_minfree);
	ADD_INT32(h, "maxbpg", fsp->fs_maxbpg);
	ADD_STRING(h, "optim",
	    fsp->fs_optim == FS_OPTSPACE ? "space" : "time");
	ADD_INT32(h, "maxcontig", fsp->fs_maxcontig);
	ADD_INT32(h, "rotdelay", fsp->fs_rotdelay);
	ADD_INT32(h, "rps", fsp->fs_rps);
	ADD_INT32(h, "csaddr", fsp->fs_csaddr);
	ADD_INT32(h, "cssize", fsp->fs_cssize);
	ADD_INT32(h, "csshift", fsp->fs_csshift);
	ADD_INT32(h, "csmask", fsp->fs_csmask);
	ADD_INT32(h, "ntrak", fsp->fs_ntrak);
	ADD_INT32(h, "nsect", fsp->fs_nsect);
	ADD_INT32(h, "spc", fsp->fs_spc);
	ADD_INT32(h, "ncyl", fsp->fs_ncyl);
	ADD_INT32(h, "cpg", fsp->fs_cpg);
	ADD_INT32(h, "bpg", fsp->fs_fpg / fsp->fs_frag);
	ADD_INT32(h, "fpg", fsp->fs_fpg);
	ADD_INT32(h, "ipg", fsp->fs_ipg);
	ADD_INT32(h, "nindir", fsp->fs_nindir);
	ADD_INT32(h, "inopb", fsp->fs_inopb);
	ADD_INT32(h, "nspf", fsp->fs_nspf);
	ADD_INT32(h, "nbfree", fsp->fs_cstotal.cs_nbfree);
	ADD_INT32(h, "ndir", fsp->fs_cstotal.cs_ndir);
	ADD_INT32(h, "nifree", fsp->fs_cstotal.cs_nifree);
	ADD_INT32(h, "nffree", fsp->fs_cstotal.cs_nffree);
	ADD_INT32(h, "cgrotor", fsp->fs_cgrotor);
	ADD_INT32(h, "fmod", fsp->fs_fmod);
	ADD_INT32(h, "ronly", fsp->fs_ronly);
	ADD_INT32(h, "logbno", fsp->fs_logbno);
	ADD_INT32(h, "rolled", fsp->fs_rolled);
	ADD_INT32(h, "si", fsp->fs_si);
	ADD_INT32(h, "flags", fsp->fs_flags);
	ADD_INT32(h, "version", fsp->fs_version);
	if (fsp->fs_reclaim & (FS_RECLAIM | FS_RECLAIMING)) {
		(void) snprintf(s, sizeof (s), "%s%s",
		    (fsp->fs_reclaim & FS_RECLAIM)    ? " FS_RECLAIM"    : "",
		    (fsp->fs_reclaim & FS_RECLAIMING) ? " FS_RECLAIMING" : "");
		ADD_STRING(h, "fs_reclaim", s);
	}
	ADD_INT32(h, "clean", fsp->fs_clean);

	if ((fsp->fs_state + (long)fsp->fs_time == FSOKAY) &&
	    (fsp->fs_clean == FSCLEAN || fsp->fs_clean == FSSTABLE ||
	    (fsp->fs_clean == FSLOG))) {
		ADD_BOOL(h, "gen_clean", B_TRUE);
	} else {
		ADD_BOOL(h, "gen_clean", B_FALSE);
	}

	(void) snprintf(s, sizeof (s), "%d", fsp->fs_version);
	ADD_STRING(h, "gen_version", s);

	return (0);
}


static int
dumpfs(fstyp_ufs_t *h, FILE *fout, FILE *ferr)
{
	int c, i, j, k, size, nrpos;
	struct fs *fsp = &h->afs;
	offset_t offset;
	caddr_t sip;
	time_t t;

	t = (time_t)fsp->fs_time;
	(void) fprintf(fout, "magic\t%x\tformat\t%s\ttime\t%s", fsp->fs_magic,
	    fsp->fs_postblformat == FS_42POSTBLFMT ? "static" : "dynamic",
	    ctime(&t));
	(void) fprintf(fout, "sblkno\t%d\tcblkno\t%d\tiblkno\t%d\tdblkno\t%d\n",
	    fsp->fs_sblkno, fsp->fs_cblkno, fsp->fs_iblkno, fsp->fs_dblkno);
	(void) fprintf(fout,
	    "sbsize\t%d\tcgsize\t%d\tcgoffset %d\tcgmask\t0x%08x\n",
	    fsp->fs_sbsize, fsp->fs_cgsize, fsp->fs_cgoffset, fsp->fs_cgmask);
	(void) fprintf(fout, "ncg\t%d\tsize\t%d\tblocks\t%d\n",
	    fsp->fs_ncg, fsp->fs_size, fsp->fs_dsize);
	(void) fprintf(fout, "bsize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    fsp->fs_bsize, fsp->fs_bshift, fsp->fs_bmask);
	(void) fprintf(fout, "fsize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    fsp->fs_fsize, fsp->fs_fshift, fsp->fs_fmask);
	(void) fprintf(fout, "frag\t%d\tshift\t%d\tfsbtodb\t%d\n",
	    fsp->fs_frag, fsp->fs_fragshift, fsp->fs_fsbtodb);
	(void) fprintf(fout, "minfree\t%d%%\tmaxbpg\t%d\toptim\t%s\n",
	    fsp->fs_minfree, fsp->fs_maxbpg,
	    fsp->fs_optim == FS_OPTSPACE ? "space" : "time");
	(void) fprintf(fout, "maxcontig %d\trotdelay %dms\trps\t%d\n",
	    fsp->fs_maxcontig, fsp->fs_rotdelay, fsp->fs_rps);
	(void) fprintf(fout,
	    "csaddr\t%d\tcssize\t%d\tshift\t%d\tmask\t0x%08x\n",
	    fsp->fs_csaddr, fsp->fs_cssize, fsp->fs_csshift, fsp->fs_csmask);
	(void) fprintf(fout, "ntrak\t%d\tnsect\t%d\tspc\t%d\tncyl\t%d\n",
	    fsp->fs_ntrak, fsp->fs_nsect, fsp->fs_spc, fsp->fs_ncyl);
	(void) fprintf(fout, "cpg\t%d\tbpg\t%d\tfpg\t%d\tipg\t%d\n",
	    fsp->fs_cpg, fsp->fs_fpg / fsp->fs_frag, fsp->fs_fpg, fsp->fs_ipg);
	(void) fprintf(fout, "nindir\t%d\tinopb\t%d\tnspf\t%d\n",
	    fsp->fs_nindir, fsp->fs_inopb, fsp->fs_nspf);
	(void) fprintf(fout, "nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
	    fsp->fs_cstotal.cs_nbfree, fsp->fs_cstotal.cs_ndir,
	    fsp->fs_cstotal.cs_nifree, fsp->fs_cstotal.cs_nffree);
	(void) fprintf(fout, "cgrotor\t%d\tfmod\t%d\tronly\t%d\tlogbno\t%d\n",
	    fsp->fs_cgrotor, fsp->fs_fmod, fsp->fs_ronly, fsp->fs_logbno);
	(void) fprintf(fout, "rolled\t%d\tsi\t%d\tflags\t%x\n",
	    fsp->fs_rolled, fsp->fs_si, fsp->fs_flags);
	(void) fprintf(fout, "version\t%d\n", fsp->fs_version);
	if (fsp->fs_reclaim & (FS_RECLAIM | FS_RECLAIMING)) {
		(void) fprintf(fout, "fs_reclaim%s%s\n",
		    (fsp->fs_reclaim & FS_RECLAIM)    ? " FS_RECLAIM"    : "",
		    (fsp->fs_reclaim & FS_RECLAIMING) ? " FS_RECLAIMING" : "");
	} else {
		(void) fprintf(fout, "fs_reclaim is not set\n");
	}
	if (fsp->fs_state + (long)fsp->fs_time == FSOKAY) {
		(void) fprintf(fout, gettext(
		    "file system state is valid, fsclean is %d\n"),
		    fsp->fs_clean);
	} else {
		(void) fprintf(fout,
		    gettext("file system state is not valid\n"));
	}
	if (fsp->fs_cpc != 0) {
		(void) fprintf(fout, gettext(
		    "blocks available in each rotational position"));
	} else {
		(void) fprintf(fout, gettext(
		    "insufficient space to maintain rotational tables\n"));
	}
	for (c = 0; c < fsp->fs_cpc; c++) {
		(void) fprintf(fout, gettext("\ncylinder number %d:"), c);
		nrpos = (((fsp)->fs_postblformat == FS_DYNAMICPOSTBLFMT) ?
		    (fsp)->fs_nrpos : NRPOS);
		for (i = 0; i < nrpos; i++) {
			if (fs_postbl(fsp, c)[i] == -1)
				continue;
			(void) fprintf(fout, gettext("\n   position %d:\t"), i);
			/*CSTYLED*/
			for (j = fs_postbl(fsp, c)[i], k = 1; ;
			    j += fs_rotbl(fsp)[j], k++) {
				(void) fprintf(fout, "%5d", j);
				if (k % 12 == 0)
					(void) fprintf(fout, "\n\t\t");
				if ((fs_rotbl(fsp))[j] == 0)
					break;
			}
		}
	}
	(void) fprintf(fout, "\ncs[].cs_(nbfree,ndir,nifree,nffree):\n\t");
	sip = calloc(1, fsp->fs_cssize);
	/* void * cast is to convince lint that sip really is aligned */
	fsp->fs_u.fs_csp = (struct csum *)(void *)sip;
	for (i = 0, j = 0; i < fsp->fs_cssize; i += fsp->fs_bsize, j++) {
		size = fsp->fs_cssize - i < fsp->fs_bsize ?
		    fsp->fs_cssize - i : fsp->fs_bsize;
		offset = (offset_t)fsbtodb(
		    fsp, (fsp->fs_csaddr + j * fsp->fs_frag)) * DEV_BSIZE;
		(void) llseek(h->fd, offset, 0);
		if (read(h->fd, sip, size) != size) {
			return (FSTYP_ERR_IO);
		}
		sip += size;
	}
	for (i = 0; i < fsp->fs_ncg; i++) {
		struct csum *cs = &fsp->fs_cs(fsp, i);
		if (i && i % 4 == 0)
			(void) fprintf(fout, "\n\t");
		(void) fprintf(fout, "(%d,%d,%d,%d) ",
		    cs->cs_nbfree, cs->cs_ndir, cs->cs_nifree, cs->cs_nffree);
	}
	(void) fprintf(fout, "\n");
	if (fsp->fs_ncyl % fsp->fs_cpg) {
		(void) fprintf(fout, gettext("cylinders in last group %d\n"),
		    i = fsp->fs_ncyl % fsp->fs_cpg);
		(void) fprintf(fout, gettext("blocks in last group %d\n"),
		    i * fsp->fs_spc / NSPB(fsp));
	}
	(void) fprintf(fout, "\n");
	for (i = 0; i < fsp->fs_ncg; i++)
		dumpcg(h, fout, ferr, i);
	if (fsp->fs_logbno)
		dumplog(h, fout, ferr);
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

/* ARGSUSED */
static void
dumplog(fstyp_ufs_t *h, FILE *fout, FILE *ferr)
{
	int i;
	long		tb = 0;
	extent_block_t	*ebp;
	extent_t	*ep;
	ml_odunit_t	*ud;
	struct fs *fsp = &h->afs;

	(void) fprintf(fout, "\nlog\n");
	if (fsp->fs_magic == FS_MAGIC)
		(void) fprintf(fout,
		    "log allocation block %d\n", fsp->fs_logbno);
	else
		(void) fprintf(fout, "log allocation block (in frags) %d\n",
		    fsp->fs_logbno);
	(void) llseek(h->fd, (offset_t)logbtodb(fsp,
	    fsp->fs_logbno) * DEV_BSIZE, 0);
	if (read(h->fd, (char *)&h->eg, fsp->fs_bsize) != fsp->fs_bsize) {
		(void) fprintf(fout, gettext(
		    "dumplog: error reading log allocation\n"));
		return;
	}
	ebp = (void *)h->eg;
	if (ebp->type != LUFS_EXTENTS)
		(void) fprintf(fout,
		    gettext("Invalid log allocation type %x\n"), ebp->type);
	if (!checksum(&ebp->chksum, (int32_t *)ebp, fsp->fs_bsize))
		(void) fprintf(fout, gettext("Invalid log checksum\n"));

	for (i = 0, ep = &ebp->extents[0]; i < ebp->nextents; ++i, ++ep) {
		(void) fprintf(fout, "\tlogical block\t%" PRId32
		    "\tphysical block\t%" PRId32
		    "\tblocks\t%" PRId32 "\n",
		    ep->lbno, ep->pbno, ep->nbno);
		tb += dbtob(ep->nbno);
	}
	(void) fprintf(fout, "log size %" PRIu32 " bytes (%ld calculated)\n",
		ebp->nbytes, tb);
	(void) fprintf(fout, "\n");
	ep = &ebp->extents[0];
	(void) llseek(h->fd, (offset_t)logbtodb(fsp, ep->pbno) * DEV_BSIZE, 0);
	if (read(h->fd, &h->eg, dbtob(LS_SECTORS)) != dbtob(LS_SECTORS)) {
		(void) fprintf(fout, gettext(
		    "dumplog: error reading log state\n"));
		return;
	}
	ud = (void *)&h->eg;
	(void) fprintf(fout, "version\t\t%" PRIu32 "\t\t", ud->od_version);
	if (ud->od_badlog)
		(void) fprintf(fout, "logstate\tError\n");
	else
		(void) fprintf(fout, "logstate\tOkay\n");
	(void) fprintf(fout, "bol\t\t%" PRId32 "\t\teol\t\t%" PRId32 "\n",
		ud->od_bol_lof, ud->od_eol_lof);
	(void) fprintf(fout, "requestsize\t%" PRIu32 "\n", ud->od_requestsize);
	(void) fprintf(fout, "statesize\t%" PRIu32 "\n", ud->od_statesize);
	(void) fprintf(fout, "logsize\t\t%" PRIu32 "\n", ud->od_logsize);
	(void) fprintf(fout,
	    "maxtransfer\t%" PRIu32 "\t\tdevbsize\t%" PRIu32 "\n",
	    ud->od_maxtransfer, ud->od_devbsize);
	(void) fprintf(fout,
	    "head\t\t%" PRId32 "\t\thead ident\t%#" PRIx32 "\n",
	    ud->od_head_lof, ud->od_head_ident);
	(void) fprintf(fout,
	    "tail\t\t%" PRId32 "\t\ttail ident\t%#" PRIx32 "\n",
	    ud->od_tail_lof, ud->od_tail_ident);
	(void) fprintf(fout, "\t\t\t\tdebug\t\t%#" PRIx32 "\n", ud->od_debug);
	if (ud->od_head_ident + ud->od_tail_ident != ud->od_chksum)
		(void) fprintf(fout,
		    "Bad chksum\t%#" PRIx32 "\n", ud->od_chksum);
	else
		(void) fprintf(fout,
		    "Good chksum\t%#" PRIx32 "\n", ud->od_chksum);
}

/* ARGSUSED */
static void
dumpcg(fstyp_ufs_t *h, FILE *fout, FILE *ferr, const int c)
{
	int		i, j;
	offset_t	off;
	struct cg	*cgp;
	struct ocg	*ocgp;
	struct fs	*fsp = &h->afs;
	time_t		t;

	(void) fprintf(fout, "\ncg %d:\n", c);
	off = llseek(h->fd,
	    (offset_t)fsbtodb(fsp, cgtod(fsp, c)) * DEV_BSIZE, 0);
	if (read(h->fd, (char *)&h->acg, fsp->fs_bsize) != fsp->fs_bsize) {
		(void) fprintf(fout, gettext("dumpfs: error reading cg\n"));
		return;
	}
	cgp = (struct cg *)&h->acg;
	ocgp = (struct ocg *)&h->acg;
	if (!cg_chkmagic(cgp))
	    (void) fprintf(fout, gettext(
		"Invalid Cylinder grp magic fffs:%x  4.2 fs:%x\n"),
		cgp->cg_magic, ocgp->cg_magic);
	if (cgp->cg_magic == CG_MAGIC) {
		/* print FFFS 4.3 cyl grp format. */
		t = (time_t)cgp->cg_time;
		(void) fprintf(fout, "magic\t%x\ttell\t%llx\ttime\t%s",
		    cgp->cg_magic, off, ctime(&t)); /* *** */
		(void) fprintf(fout,
		    "cgx\t%d\tncyl\t%d\tniblk\t%d\tndblk\t%d\n",
		    cgp->cg_cgx, cgp->cg_ncyl, cgp->cg_niblk, cgp->cg_ndblk);
		(void) fprintf(fout,
		    "nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
		    cgp->cg_cs.cs_nbfree, cgp->cg_cs.cs_ndir,
		    cgp->cg_cs.cs_nifree, cgp->cg_cs.cs_nffree);
		(void) fprintf(fout, "rotor\t%d\tirotor\t%d\tfrotor\t%d\nfrsum",
		    cgp->cg_rotor, cgp->cg_irotor, cgp->cg_frotor);
		for (i = 1, j = 0; i < fsp->fs_frag; i++) {
			(void) fprintf(fout, "\t%d", cgp->cg_frsum[i]);
			j += i * cgp->cg_frsum[i];
		}
		(void) fprintf(fout,
		    gettext("\nsum of frsum: %d\niused:\t"), j);
		pbits(fout, cg_inosused(cgp), fsp->fs_ipg);
		(void) fprintf(fout, gettext("free:\t"));
		pbits(fout, cg_blksfree(cgp), fsp->fs_fpg);
		(void) fprintf(fout, "b:\n");
		for (i = 0; i < fsp->fs_cpg; i++) {
			(void) fprintf(fout,
			    "   c%d:\t(%d)\t", i, cg_blktot(cgp)[i]);
			for (j = 0; j < fsp->fs_nrpos; j++)	/* ****** */
				(void) fprintf(fout,
				    " %d", cg_blks(fsp, cgp, i)[j]);
			(void) fprintf(fout, "\n");
		}
	} else if (ocgp->cg_magic == CG_MAGIC) {
		/* print Old cyl grp format. */
		t = (time_t)ocgp->cg_time;
		(void) fprintf(fout, "magic\t%x\ttell\t%llx\ttime\t%s",
		    ocgp->cg_magic, off, ctime(&t));
		(void) fprintf(fout,
		    "cgx\t%d\tncyl\t%d\tniblk\t%d\tndblk\t%d\n",
		    ocgp->cg_cgx, ocgp->cg_ncyl, ocgp->cg_niblk,
		    ocgp->cg_ndblk);
		(void) fprintf(fout,
		    "nbfree\t%d\tndir\t%d\tnifree\t%d\tnffree\t%d\n",
		    ocgp->cg_cs.cs_nbfree, ocgp->cg_cs.cs_ndir,
		    ocgp->cg_cs.cs_nifree, ocgp->cg_cs.cs_nffree);
		(void) fprintf(fout,
		    "rotor\t%d\tirotor\t%d\tfrotor\t%d\nfrsum",
		    ocgp->cg_rotor, ocgp->cg_irotor, ocgp->cg_frotor);
		for (i = 1, j = 0; i < fsp->fs_frag; i++) {
			(void) fprintf(fout, "\t%d", ocgp->cg_frsum[i]);
			j += i * ocgp->cg_frsum[i];
		}
		(void) fprintf(fout,
		    gettext("\nsum of frsum: %d\niused:\t"), j);
		pbits(fout, ocgp->cg_iused, fsp->fs_ipg);
		(void) fprintf(fout, gettext("free:\t"));
		pbits(fout, ocgp->cg_free, fsp->fs_fpg);
		(void) fprintf(fout, "b:\n");
		for (i = 0; i < fsp->fs_cpg; i++) {
			(void) fprintf(fout,
			    "   c%d:\t(%d)\t", i, ocgp->cg_btot[i]);
			for (j = 0; j < NRPOS; j++)
				(void) fprintf(fout, " %d", ocgp->cg_b[i][j]);
			(void) fprintf(fout, "\n");
		}
	}
}


static void
pbits(FILE *fout, const void *p, const int max)
{
	int i;
	int count = 0, j;
	unsigned char *cp = (unsigned char *)p;

	for (i = 0; i < max; i++) {
		if (isset(cp, i)) {
			if (count)
				(void) fprintf(fout, ",%s",
				    (count % 9 == 8) ? "\n\t" : " ");
			count++;
			(void) fprintf(fout, "%d", i);
			j = i;
			while ((i + 1) < max && isset(cp, i+1))
				i++;
			if (i != j)
				(void) fprintf(fout, "-%d", i);
		}
	}
	(void) fprintf(fout, "\n");
}
