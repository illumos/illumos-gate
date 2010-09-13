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

#include <sys/fm/protocol.h>
#include <sys/types.h>
#include <sys/mkdev.h>

#include <alloca.h>
#include <unistd.h>
#include <limits.h>
#include <strings.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <dirent.h>
#include <fmd_log_impl.h>
#include <fmd_log.h>

#define	CAT_FMA_RGROUP	(EXT_GROUP | EXC_DEFAULT | EXD_GROUP_RFMA)
#define	CAT_FMA_GROUP	(EXT_GROUP | EXC_DEFAULT | EXD_GROUP_FMA)

#define	CAT_FMA_LABEL	(EXT_STRING | EXC_DEFAULT | EXD_FMA_LABEL)
#define	CAT_FMA_VERSION	(EXT_STRING | EXC_DEFAULT | EXD_FMA_VERSION)
#define	CAT_FMA_OSREL	(EXT_STRING | EXC_DEFAULT | EXD_FMA_OSREL)
#define	CAT_FMA_OSVER	(EXT_STRING | EXC_DEFAULT | EXD_FMA_OSVER)
#define	CAT_FMA_PLAT	(EXT_STRING | EXC_DEFAULT | EXD_FMA_PLAT)
#define	CAT_FMA_UUID	(EXT_STRING | EXC_DEFAULT | EXD_FMA_UUID)
#define	CAT_FMA_TODSEC	(EXT_UINT64 | EXC_DEFAULT | EXD_FMA_TODSEC)
#define	CAT_FMA_TODNSEC	(EXT_UINT64 | EXC_DEFAULT | EXD_FMA_TODNSEC)
#define	CAT_FMA_NVLIST	(EXT_RAW | EXC_DEFAULT | EXD_FMA_NVLIST)
#define	CAT_FMA_MAJOR	(EXT_UINT32 | EXC_DEFAULT | EXD_FMA_MAJOR)
#define	CAT_FMA_MINOR	(EXT_UINT32 | EXC_DEFAULT | EXD_FMA_MINOR)
#define	CAT_FMA_INODE	(EXT_UINT64 | EXC_DEFAULT | EXD_FMA_INODE)
#define	CAT_FMA_OFFSET	(EXT_UINT64 | EXC_DEFAULT | EXD_FMA_OFFSET)

static int fmd_log_load_record(fmd_log_t *, uint_t, fmd_log_record_t *);
static void fmd_log_free_record(fmd_log_record_t *);
static int fmd_log_load_xrefs(fmd_log_t *, uint_t, fmd_log_record_t *);

static const char FMD_CREATOR[] = "fmd";

/*
 * fmd_log_set_errno is used as a utility function throughout the library.  It
 * sets both lp->log_errno and errno to the specified value.  If the current
 * error is EFDL_EXACCT, we store it internally as that value plus ea_error().
 * If no ea_error() is present, we assume EFDL_BADTAG (catalog tag mismatch).
 */
static int
fmd_log_set_errno(fmd_log_t *lp, int err)
{
	if (err == EFDL_EXACCT && ea_error() != EXR_OK)
		lp->log_errno = EFDL_EXACCT + ea_error();
	else if (err == EFDL_EXACCT)
		lp->log_errno = EFDL_BADTAG;
	else
		lp->log_errno = err;

	errno = lp->log_errno;
	return (-1);
}

/*PRINTFLIKE2*/
static void
fmd_log_dprintf(fmd_log_t *lp, const char *format, ...)
{
	va_list ap;

	if (lp->log_flags & FMD_LF_DEBUG) {
		(void) fputs("fmd_log DEBUG: ", stderr);
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);
	}
}

/*
 * fmd_log_load_record() is used to load the exacct object at the current file
 * location into the specified fmd_log_record structure.  Once the caller has
 * made use of this information, it can clean up using fmd_log_free_record().
 */
static int
fmd_log_load_record(fmd_log_t *lp, uint_t iflags, fmd_log_record_t *rp)
{
	ea_object_t *grp, *obj;
	off64_t off;
	int err;

	if (iflags & FMD_LOG_XITER_OFFS) {
		ea_clear(&lp->log_ea);
		off = lseek64(lp->log_fd, 0, SEEK_CUR);
	}

	if ((grp = ea_get_object_tree(&lp->log_ea, 1)) == NULL)
		return (fmd_log_set_errno(lp, EFDL_EXACCT));

	if (grp->eo_catalog != CAT_FMA_RGROUP &&
	    grp->eo_catalog != CAT_FMA_GROUP) {
		fmd_log_dprintf(lp, "bad catalog tag 0x%x\n", grp->eo_catalog);
		ea_free_object(grp, EUP_ALLOC);
		return (fmd_log_set_errno(lp, EFDL_EXACCT));
	}

	bzero(rp, sizeof (fmd_log_record_t));
	rp->rec_grp = grp;

	if (iflags & FMD_LOG_XITER_OFFS)
		rp->rec_off = off;

	for (obj = grp->eo_group.eg_objs; obj != NULL; obj = obj->eo_next) {
		switch (obj->eo_catalog) {
		case CAT_FMA_NVLIST:
			if ((err = nvlist_unpack(obj->eo_item.ei_raw,
			    obj->eo_item.ei_size, &rp->rec_nvl, 0)) != 0) {
				fmd_log_free_record(rp);
				return (fmd_log_set_errno(lp, err));
			}
			break;

		case CAT_FMA_TODSEC:
			rp->rec_sec = obj->eo_item.ei_uint64;
			break;

		case CAT_FMA_TODNSEC:
			rp->rec_nsec = obj->eo_item.ei_uint64;
			break;

		case CAT_FMA_GROUP:
			rp->rec_nrefs += obj->eo_group.eg_nobjs;
			break;
		}
	}

	if (rp->rec_nvl == NULL || nvlist_lookup_string(rp->rec_nvl,
	    FM_CLASS, (char **)&rp->rec_class) != 0) {
		fmd_log_free_record(rp);
		return (fmd_log_set_errno(lp, EFDL_NOCLASS));
	}

	if (rp->rec_nrefs != 0 && fmd_log_load_xrefs(lp, iflags, rp) != 0) {
		err = errno; /* errno is set for us */
		fmd_log_free_record(rp);
		return (fmd_log_set_errno(lp, err));
	}

	return (0);
}

/*
 * fmd_log_free_record frees memory associated with the specified record.  If
 * cross-references are contained in this record, we proceed recursively.
 */
static void
fmd_log_free_record(fmd_log_record_t *rp)
{
	uint_t i;

	if (rp->rec_xrefs != NULL) {
		for (i = 0; i < rp->rec_nrefs; i++)
			fmd_log_free_record(&rp->rec_xrefs[i]);
		free(rp->rec_xrefs);
	}

	nvlist_free(rp->rec_nvl);
	ea_free_object(rp->rec_grp, EUP_ALLOC);
}

/*
 * fmd_log_load_xref loads the cross-reference represented by the specified
 * exacct group 'grp' into the next empty slot in rp->rec_xrefs.  This function
 * is called repeatedly by fmd_log_load_xrefs() for each embedded reference.
 */
static int
fmd_log_load_xref(fmd_log_t *lp, uint_t iflags,
    fmd_log_record_t *rp, ea_object_t *grp)
{
	ea_object_t *obj;
	fmd_log_t *xlp;
	dev_t dev;

	off64_t off = (off64_t)-1L;
	major_t maj = (major_t)-1L;
	minor_t min = (minor_t)-1L;
	ino64_t ino = (ino64_t)-1L;
	char *uuid = NULL;

	for (obj = grp->eo_group.eg_objs; obj != NULL; obj = obj->eo_next) {
		switch (obj->eo_catalog) {
		case CAT_FMA_MAJOR:
			maj = obj->eo_item.ei_uint32;
			break;
		case CAT_FMA_MINOR:
			min = obj->eo_item.ei_uint32;
			break;
		case CAT_FMA_INODE:
			ino = obj->eo_item.ei_uint64;
			break;
		case CAT_FMA_OFFSET:
			off = obj->eo_item.ei_uint64;
			break;
		case CAT_FMA_UUID:
			uuid = obj->eo_item.ei_string;
			break;
		}
	}

	if (off == (off64_t)-1L || (uuid == NULL && (ino == (ino64_t)-1L ||
	    maj == (major_t)-1L || min == (minor_t)-1L)))
		return (fmd_log_set_errno(lp, EFDL_BADREF));

	if (uuid == NULL && (dev = makedev(maj, min)) == NODEV)
		return (fmd_log_set_errno(lp, EFDL_BADDEV));

	/*
	 * Search our xref list for matching (dev_t, ino64_t) or (uuid).
	 * If we can't find one, return silently without
	 * doing anything.  We expect log xrefs to be broken whenever log
	 * files are trimmed or removed; their only purpose is to help us
	 * debug diagnosis engine algorithms.
	 */
	for (xlp = lp->log_xrefs; xlp != NULL; xlp = xlp->log_xnext) {
		if (uuid == NULL) {
			if (xlp->log_stat.st_ino == ino &&
			    xlp->log_stat.st_dev == dev)
				break;
		} else if (xlp->log_uuid != NULL &&
		    strcmp(xlp->log_uuid, uuid) == 0)
			break;
	}

	if (xlp == NULL) {
		if (uuid == NULL)
			fmd_log_dprintf(lp, "broken xref dev=%lx ino=%llx\n",
			    (ulong_t)dev, (u_longlong_t)ino);
		else
			fmd_log_dprintf(lp, "broken xref uuid=%s\n", uuid);

		return (0);
	}

	xlp->log_flags &= ~FMD_LF_START;
	ea_clear(&xlp->log_ea);
	(void) lseek64(xlp->log_fd, off, SEEK_SET);

	return (fmd_log_load_record(xlp,
	    iflags, &rp->rec_xrefs[rp->rec_nrefs++]));
}

/*
 * fmd_log_load_xrdir is called by fmd_log_load_xrefs when the FMD_LF_XREFS bit
 * is not yet set, indicating we haven't looked for cross-referenced files.  We
 * open the directory associated with the specified log file and attempt to
 * perform an fmd_log_open() on every file found there (i.e. /var/fm/fmd).  If
 * we are successful, the files are chained on to lp->log_xrefs, where the
 * fmd_log_load_xref() function can find them by comparing dev/ino to log_stat.
 */
static void
fmd_log_load_xrdir(fmd_log_t *lp)
{
	fmd_log_t *xlp;
	char dirbuf[PATH_MAX], path[PATH_MAX], *dirpath;
	struct dirent *dp;
	DIR *dirp;
	struct stat statbuf;

	lp->log_flags |= FMD_LF_XREFS;
	(void) strlcpy(dirbuf, lp->log_path, sizeof (dirbuf));
	dirpath = dirname(dirbuf);

	if ((dirp = opendir(dirpath)) == NULL)
		return; /* failed to open directory; just skip it */

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue; /* skip "." and ".." and hidden files */

		(void) snprintf(path, sizeof (path),
		    "%s/%s", dirpath, dp->d_name);

		if (strcmp(path, lp->log_path) != 0 &&
		    stat(path, &statbuf) != -1 &&
		    (statbuf.st_mode & S_IFMT) == S_IFREG &&
		    (xlp = fmd_log_open(lp->log_abi, path, NULL)) != NULL) {
			fmd_log_dprintf(lp, "%s loaded %s for xrefs\n",
			    lp->log_path, xlp->log_path);
			xlp->log_xnext = lp->log_xrefs;
			lp->log_xrefs = xlp;
		}
	}
}

/*
 * fmd_log_load_xrefs iterates again over the record's exacct group and for
 * each cross-reference (embedded CAT_FMA_GROUP), attempts to fill in the
 * corresponding xref.  rp->rec_nrefs is reset to the number of valid items
 * in the finished rp->rec_xrefs array; see fmd_log_load_xref() for more info.
 */
static int
fmd_log_load_xrefs(fmd_log_t *lp, uint_t iflags, fmd_log_record_t *rp)
{
	size_t size = sizeof (fmd_log_record_t) * rp->rec_nrefs;
	ea_object_t *rgrp = rp->rec_grp;
	ea_object_t *grp, *obj;

	if (!(iflags & FMD_LOG_XITER_REFS))
		return (0); /* do not load any xrefs */

	if (!(lp->log_flags & FMD_LF_XREFS))
		fmd_log_load_xrdir(lp);

	if ((rp->rec_xrefs = malloc(size)) == NULL)
		return (fmd_log_set_errno(lp, EFDL_NOMEM));

	bzero(rp->rec_xrefs, size);
	rp->rec_nrefs = 0;

	/*
	 * Make a second pass through the record group to locate and process
	 * each cross-reference sub-group.  The structure of the groups is
	 * as follows (left-hand-side symbols named after the variables used):
	 *
	 * rgrp := CAT_FMA_TODSEC CAT_FMA_TODNSEC CAT_FMA_NVLIST grp*
	 * grp  := obj* (i.e. zero or more groups of xref items)
	 * obj  := CAT_FMA_MAJOR CAT_FMA_MINOR CAT_FMA_INODE CAT_FMA_OFFSET
	 *
	 * For each xref 'obj', we call fmd_log_load_xref() to parse the four
	 * xref members and then load the specified record into rp->rec_xrefs.
	 */
	for (grp = rgrp->eo_group.eg_objs; grp != NULL; grp = grp->eo_next) {
		if (grp->eo_catalog != CAT_FMA_GROUP)
			continue; /* ignore anything that isn't a group */

		for (obj = grp->eo_group.eg_objs;
		    obj != NULL; obj = obj->eo_next) {
			if (fmd_log_load_xref(lp, iflags, rp, obj) != 0)
				return (-1); /* errno is set for us */
		}
	}

	return (0);
}

static fmd_log_t *
fmd_log_open_err(fmd_log_t *lp, int *errp, int err)
{
	if (errp != NULL)
		*errp = err == EFDL_EXACCT ? EFDL_EXACCT + ea_error() : err;

	if (lp != NULL)
		fmd_log_close(lp);

	return (NULL);
}

fmd_log_t *
fmd_log_open(int abi, const char *name, int *errp)
{
	ea_object_t *grp, *obj;
	fmd_log_t *lp;
	int fd;

	if (abi > FMD_LOG_VERSION)
		return (fmd_log_open_err(NULL, errp, EFDL_VERSION));

	if ((lp = malloc(sizeof (fmd_log_t))) == NULL)
		return (fmd_log_open_err(NULL, errp, EFDL_NOMEM));

	bzero(lp, sizeof (fmd_log_t));

	if ((lp->log_path = strdup(name)) == NULL)
		return (fmd_log_open_err(lp, errp, EFDL_NOMEM));

	if ((lp->log_fd = open64(name, O_RDONLY)) == -1 ||
	    fstat64(lp->log_fd, &lp->log_stat) == -1 ||
	    (fd = dup(lp->log_fd)) == -1)
		return (fmd_log_open_err(lp, errp, errno));

	if (ea_fdopen(&lp->log_ea, fd, FMD_CREATOR,
	    EO_VALID_HDR | EO_HEAD, O_RDONLY) == -1) {
		(void) close(fd);
		return (fmd_log_open_err(lp, errp, EFDL_EXACCT));
	}

	lp->log_abi = abi;
	lp->log_flags |= FMD_LF_EAOPEN;
	if (getenv("FMD_LOG_DEBUG") != NULL)
		lp->log_flags |= FMD_LF_DEBUG;

	/*
	 * Read the first group of log meta-data: the write-once read-only
	 * file header.  We read all records in this group, ignoring all but
	 * the VERSION and LABEL, which are required and must be verified.
	 */
	if ((grp = ea_get_object_tree(&lp->log_ea, 1)) == NULL)
		return (fmd_log_open_err(lp, errp, EFDL_EXACCT));

	if (grp->eo_catalog != CAT_FMA_GROUP) {
		ea_free_object(grp, EUP_ALLOC);
		return (fmd_log_open_err(lp, errp, EFDL_EXACCT));
	}

	for (obj = grp->eo_group.eg_objs; obj != NULL; obj = obj->eo_next) {
		switch (obj->eo_catalog) {
		case CAT_FMA_VERSION:
			lp->log_version = strdup(obj->eo_item.ei_string);
			if (lp->log_version == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		case CAT_FMA_LABEL:
			lp->log_label = strdup(obj->eo_item.ei_string);
			if (lp->log_label == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		case CAT_FMA_OSREL:
			lp->log_osrelease = strdup(obj->eo_item.ei_string);
			if (lp->log_osrelease == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		case CAT_FMA_OSVER:
			lp->log_osversion = strdup(obj->eo_item.ei_string);
			if (lp->log_osversion == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		case CAT_FMA_PLAT:
			lp->log_platform = strdup(obj->eo_item.ei_string);
			if (lp->log_platform == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		case CAT_FMA_UUID:
			lp->log_uuid = strdup(obj->eo_item.ei_string);
			if (lp->log_uuid == NULL) {
				ea_free_object(grp, EUP_ALLOC);
				return (fmd_log_open_err(lp, errp, EFDL_NOMEM));
			}
			break;
		}
	}

	ea_free_object(grp, EUP_ALLOC);

	if (lp->log_version == NULL || lp->log_label == NULL)
		return (fmd_log_open_err(lp, errp, EFDL_BADHDR));

	/*
	 * Read the second group of log meta-data: the table of contents.  At
	 * present there are no records libfmd_log needs in here, so we just
	 * skip over this entire group so that fmd_log_xiter() starts after it.
	 */
	if ((grp = ea_get_object_tree(&lp->log_ea, 1)) == NULL)
		return (fmd_log_open_err(lp, errp, EFDL_EXACCT));

	if (grp->eo_catalog != CAT_FMA_GROUP) {
		ea_free_object(grp, EUP_ALLOC);
		return (fmd_log_open_err(lp, errp, EFDL_EXACCT));
	}

	ea_free_object(grp, EUP_ALLOC);
	lp->log_flags |= FMD_LF_START;

	fmd_log_dprintf(lp, "open log %s dev=%lx ino=%llx\n", lp->log_path,
	    (ulong_t)lp->log_stat.st_dev, (u_longlong_t)lp->log_stat.st_ino);

	return (lp);
}

void
fmd_log_close(fmd_log_t *lp)
{
	fmd_log_t *xlp, *nlp;

	if (lp == NULL)
		return; /* permit null lp to simply caller code */

	for (xlp = lp->log_xrefs; xlp != NULL; xlp = nlp) {
		nlp = xlp->log_xnext;
		fmd_log_close(xlp);
	}

	if (lp->log_flags & FMD_LF_EAOPEN)
		(void) ea_close(&lp->log_ea);

	if (lp->log_fd >= 0)
		(void) close(lp->log_fd);

	free(lp->log_path);
	free(lp->log_version);
	free(lp->log_label);
	free(lp->log_osrelease);
	free(lp->log_osversion);
	free(lp->log_platform);
	free(lp->log_uuid);

	free(lp);
}

const char *
fmd_log_label(fmd_log_t *lp)
{
	return (lp->log_label);
}

void
fmd_log_header(fmd_log_t *lp, fmd_log_header_t *hp)
{
	const char *creator = ea_get_creator(&lp->log_ea);
	const char *hostname = ea_get_hostname(&lp->log_ea);

	hp->log_creator = creator ? creator : "";
	hp->log_hostname = hostname ? hostname : "";
	hp->log_label = lp->log_label ? lp->log_label : "";
	hp->log_version = lp->log_version ? lp->log_version : "";
	hp->log_osrelease = lp->log_osrelease ? lp->log_osrelease : "";
	hp->log_osversion = lp->log_osversion ? lp->log_osversion : "";
	hp->log_platform = lp->log_platform ? lp->log_platform : "";
	if (lp->log_abi > 1)
		hp->log_uuid = lp->log_uuid ? lp->log_uuid : "";
}

/*
 * Note: this will be verrrry slow for big files.  If this function becomes
 * important, we'll need to add a function to libexacct to let us rewind.
 * Currently libexacct has no notion of seeking other than record-at-a-time.
 */
int
fmd_log_rewind(fmd_log_t *lp)
{
	ea_object_t obj, *grp;

	if (!(lp->log_flags & FMD_LF_START)) {
		while (ea_previous_object(&lp->log_ea, &obj) != EO_ERROR)
			continue; /* rewind until beginning of file */

		if ((grp = ea_get_object_tree(&lp->log_ea, 1)) == NULL)
			return (fmd_log_set_errno(lp, EFDL_EXACCT));
		else
			ea_free_object(grp, EUP_ALLOC); /* hdr group */

		if ((grp = ea_get_object_tree(&lp->log_ea, 1)) == NULL)
			return (fmd_log_set_errno(lp, EFDL_EXACCT));
		else
			ea_free_object(grp, EUP_ALLOC); /* toc group */

		lp->log_flags |= FMD_LF_START;
	}

	return (0);
}

static int
fmd_log_xiter_filter(fmd_log_t *lp, const fmd_log_record_t *rp,
    uint_t fac, const fmd_log_filtvec_t *fav)
{
	uint_t i, j;

	for (i = 0; i < fac; i++) {
		for (j = 0; j < fav[i].filt_argc; j++) {
			if (fav[i].filt_argv[j].filt_func(lp, rp,
			    fav[i].filt_argv[j].filt_arg) != 0)
				break; /* logical OR of this class is true */
		}

		if (j == fav[i].filt_argc)
			return (0); /* logical AND of filter is false */
	}

	return (1); /* logical AND of filter is true */
}

static int
fmd_log_xiter_filtcmp(const void *lp, const void *rp)
{
	return ((intptr_t)((fmd_log_filter_t *)lp)->filt_func -
	    (intptr_t)((fmd_log_filter_t *)rp)->filt_func);
}

int
fmd_log_filter(fmd_log_t *lp, uint_t fc, fmd_log_filter_t *fv,
    const fmd_log_record_t *rp)
{
	fmd_log_filtvec_t *fav = alloca(fc * sizeof (fmd_log_filtvec_t));
	uint_t i, fac = 0;

	/*
	 * If a filter array was provided, create an array of filtvec structs
	 * to perform logical AND/OR processing.  See fmd_log_xiter(), below.
	 */
	bzero(fav, fc * sizeof (fmd_log_filtvec_t));
	qsort(fv, fc, sizeof (fmd_log_filter_t), fmd_log_xiter_filtcmp);

	for (i = 0; i < fc; i++) {
		if (i == 0 || fv[i].filt_func != fv[i - 1].filt_func)
			fav[fac++].filt_argv = &fv[i];
		fav[fac - 1].filt_argc++;
	}

	return (fmd_log_xiter_filter(lp, rp, fac, fav));
}

int
fmd_log_xiter(fmd_log_t *lp, uint_t flag, uint_t fc, fmd_log_filter_t *fv,
    fmd_log_rec_f *rfunc, fmd_log_err_f *efunc, void *private, ulong_t *rcntp)
{
	fmd_log_record_t rec;
	fmd_log_filtvec_t *fav = NULL;
	uint_t i, fac = 0;
	ulong_t rcnt = 0;
	int rv = 0;

	if (flag & ~FMD_LOG_XITER_MASK)
		return (fmd_log_set_errno(lp, EINVAL));

	/*
	 * If a filter array was provided, create an array of filtvec structs
	 * where each filtvec holds a pointer to an equivalent list of filters,
	 * as determined by their filt_func.  We sort the input array by func,
	 * and then fill in the filtvec struct array.  We can then compute the
	 * logical OR of equivalent filters by iterating over filt_argv, and
	 * we can compute the logical AND of 'fv' by iterating over filt_argc.
	 */
	if (fc != 0) {
		if ((fav = calloc(fc, sizeof (fmd_log_filtvec_t))) == NULL)
			return (fmd_log_set_errno(lp, EFDL_NOMEM));

		qsort(fv, fc, sizeof (fmd_log_filter_t), fmd_log_xiter_filtcmp);

		for (i = 0; i < fc; i++) {
			if (i == 0 || fv[i].filt_func != fv[i - 1].filt_func)
				fav[fac++].filt_argv = &fv[i];
			fav[fac - 1].filt_argc++;
		}
	}

	lp->log_flags &= ~FMD_LF_START;
	ea_clear(&lp->log_ea);

	do {
		if (fmd_log_load_record(lp, flag, &rec) != 0) {
			if (lp->log_errno == EFDL_EXACCT + EXR_EOF)
				break; /* end-of-file reached */
			rv = efunc ? efunc(lp, private) : -1;
			rcnt++;
		} else {
			if (fc == 0 || fmd_log_xiter_filter(lp, &rec, fac, fav))
				rv = rfunc(lp, &rec, private);

			fmd_log_free_record(&rec);
			rcnt++;
		}
	} while (rv == 0);

	if (fac != 0)
		free(fav);

	if (rcntp != NULL)
		*rcntp = rcnt;

	return (rv);
}

int
fmd_log_iter(fmd_log_t *lp, fmd_log_rec_f *rfunc, void *private)
{
	return (fmd_log_xiter(lp, 0, 0, NULL, rfunc, NULL, private, NULL));
}

int
fmd_log_seek(fmd_log_t *lp, off64_t off)
{
	lp->log_flags &= ~FMD_LF_START;
	ea_clear(&lp->log_ea);

	if (lseek64(lp->log_fd, off, SEEK_SET) != off)
		return (fmd_log_set_errno(lp, errno));

	return (0);
}

static const char *const _fmd_errs[] = {
	"client requires newer version of libfmd_log",	/* EFDL_VERSION */
	"required memory allocation failed",		/* EFDL_NOMEM */
	"log header did not contain required field",	/* EFDL_BADHDR */
	"log record did not contain protocol class",	/* EFDL_NOCLASS */
	"log record has invalid catalog tag",		/* EFDL_BADTAG */
	"log record has invalid cross-reference group",	/* EFDL_BADREF */
	"log record has invalid cross-reference dev_t",	/* EFDL_BADDEV */
	"log record was not of expected type",		/* EFDL_EXACCT + OK */
	"log access system call failed",		/* EXR_SYSCALL_FAIL */
	"log file corruption detected",			/* EXR_CORRUPT_FILE */
	"end-of-file reached",				/* EXR_EOF */
	"log file does not have appropriate creator",	/* EXR_NO_CREATOR */
	"invalid unpack buffer specified",		/* EXR_INVALID_BUF */
	"invalid exacct operation for log file",	/* EXR_NOTSUPP */
	"log file requires newer version of libexacct",	/* EXR_UNKN_VERSION */
	"invalid object buffer specified",		/* EXR_INVALID_OBJ */
};

static const int _fmd_nerr = sizeof (_fmd_errs) / sizeof (_fmd_errs[0]);

/*ARGSUSED*/
const char *
fmd_log_errmsg(fmd_log_t *lp, int err)
{
	const char *msg;

	if (err >= EFDL_BASE && err - EFDL_BASE < _fmd_nerr)
		msg = _fmd_errs[err - EFDL_BASE];
	else
		msg = strerror(err);

	return (msg ? msg : "unknown error");
}

int
fmd_log_errno(fmd_log_t *lp)
{
	return (lp->log_errno);
}
