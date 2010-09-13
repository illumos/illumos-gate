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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */



#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include "pkgstrct.h"
#include "pkglib.h"

/*
 * Name:	putcfile
 * Description:	Write contents file entry to specified FILE
 * Arguments:	struct cfent a_ept - data for contents file entry
 *		FILE *a_fp - FP of file to write contents file entry to
 * Notes:	This is identical to putcvfpfile() but this function takes a
 *		stdio FILE* file to write to instead of a VFP_T file. It is
 *		MUCH slower than putcvfpfile().
 */

int
putcfile(struct cfent *a_ept, FILE *a_fp)
{
	struct pinfo *pinfo;

	if (a_ept->ftype == 'i') {
		return (0); /* no ifiles stored in contents DB */
	}

	if (a_ept->path == NULL) {
		return (-1);	/* no path name - no entry to write */
	}

	if (fputs(a_ept->path, a_fp) == EOF) {
		return (-1);
	}

	if (a_ept->ainfo.local) {
		if (putc('=', a_fp) == EOF) {
			return (-1);
		}
		if (fputs(a_ept->ainfo.local, a_fp) == EOF)
			return (-1);
	}

	if (a_ept->volno) {
		if (fprintf(a_fp, " %d", a_ept->volno) < 0) {
			return (-1);
		}
	}

	if (putc(' ', a_fp) == EOF) {
		return (-1);
	}

	if (putc(a_ept->ftype, a_fp) == EOF) {
		return (-1);
	}

	if (putc(' ', a_fp) == EOF) {
		return (-1);
	}

	if (fputs(a_ept->pkg_class, a_fp) == EOF) {
		return (-1);
	}

	if ((a_ept->ftype == 'c') || (a_ept->ftype == 'b')) {
		if (a_ept->ainfo.major == BADMAJOR) {
			if (putc(' ', a_fp) == EOF) {
				return (-1);
			}

			if (putc('?', a_fp) == EOF) {
				return (-1);
			}
		} else {
			if (fprintf(a_fp, " %d", a_ept->ainfo.major) < 0)
				return (-1);
		}

		if (a_ept->ainfo.minor == BADMINOR) {
			if (putc(' ', a_fp) == EOF) {
				return (-1);
			}

			if (putc('?', a_fp) == EOF) {
				return (-1);
			}
		} else {
			if (fprintf(a_fp, " %d", a_ept->ainfo.minor) < 0)
				return (-1);
		}
	}

	if ((a_ept->ftype == 'd') || (a_ept->ftype == 'x') ||
		(a_ept->ftype == 'c') || (a_ept->ftype == 'b') ||
		(a_ept->ftype == 'p') || (a_ept->ftype == 'f') ||
		(a_ept->ftype == 'v') || (a_ept->ftype == 'e')) {
		if (fprintf(a_fp,
			((a_ept->ainfo.mode == BADMODE) ? " ?" : " %04o"),
			a_ept->ainfo.mode) < 0)
			return (-1);

		if (putc(' ', a_fp) == EOF) {
			return (-1);
		}

		if (fputs(a_ept->ainfo.owner, a_fp) == EOF) {
			return (-1);
		}

		if (putc(' ', a_fp) == EOF) {
			return (-1);
		}

		if (fputs(a_ept->ainfo.group, a_fp) == EOF) {
			return (-1);
		}
	}

	if ((a_ept->ftype == 'f') || (a_ept->ftype == 'v') ||
		(a_ept->ftype == 'e')) {
		if (fprintf(a_fp,
			((a_ept->cinfo.size == BADCONT) ? " ?" : " %llu"),
			a_ept->cinfo.size) < 0)
			return (-1);

		if (fprintf(a_fp,
			((a_ept->cinfo.cksum == BADCONT) ? " ?" : " %ld"),
			a_ept->cinfo.cksum) < 0)
			return (-1);

		if (fprintf(a_fp,
		    ((a_ept->cinfo.modtime == BADCONT) ? " ?" : " %ld"),
		    a_ept->cinfo.modtime) < 0)
			return (-1);
	}

	pinfo = a_ept->pinfo;
	while (pinfo) {
		if (putc(' ', a_fp) == EOF) {
			return (-1);
		}

		if (pinfo->status) {
			if (fputc(pinfo->status, a_fp) == EOF) {
				return (-1);
			}
		}

		if (fputs(pinfo->pkg, a_fp) == EOF) {
			return (-1);
		}

		if (pinfo->editflag) {
			if (putc('\\', a_fp) == EOF) {
				return (-1);
			}
		}

		if (pinfo->aclass[0]) {
			if (putc(':', a_fp) == EOF) {
				return (-1);
			}
			if (fputs(pinfo->aclass, a_fp) == EOF) {
				return (-1);
			}
		}
		pinfo = pinfo->next;
	}

	if (putc('\n', a_fp) == EOF) {
		return (-1);
	}
	return (0);
}

/*
 * Name:	putcvfpfile
 * Description:	Write contents file entry to specified VFP
 * Arguments:	struct cfent a_ept - data for contents file entry
 *		VFP_T *a_vfp - VFP of file to write contents file entry to
 * Notes:	This is identical to putcfile() but this function takes a
 *		VFP_T file to write to instead of a stdio FILE file. It is
 *		MUCH faster tha putcfile().
 */

int
putcvfpfile(struct cfent *a_ept, VFP_T *a_vfp)
{
	struct pinfo *pinfo;

	/* contents file does not maintain any 'i' file entries */

	if (a_ept->ftype == 'i') {
		return (0);
	}

	/* cannot create an entry if it has no file name */

	if (a_ept->path == NULL) {
		return (-1);
	}

	/*
	 * Format of contents file line could be one of:
	 * /file=./dir/file s class SUNWxxx
	 * /file=../dir/file l class SUNWxxx
	 * /dir d class mode owner group SUNWxxx SUNWyyy
	 * /devices/name c class major minor mode owner group SUNWxxx
	 * /file f class mode owner group size cksum modtime SUNWxxx
	 * /file x class mode owner group SUNWppro
	 * /file v class mode owner group size cksum modtime SUNWxxx
	 * /file e class mode owner group size cksum modtime SUNWxxx
	 * The package name could be prefixed by one of the following
	 * status indicators: +-*!%@#~
	 */

	/*
	 * Adding an entry to the specified VFP.  During normal processing the
	 * contents file is copied to a temporary contents file and entries are
	 * added as appropriate.  When this processing is completed, a decision
	 * is made on whether or not to overwrite the real contents file with
	 * the contents of the temporary contents file.  If the temporary
	 * contents file is just a copy of the real contents file then there is
	 * no need to overwrite the real contents file with the contents of the
	 * temporary contents file.  This decision is made in part on whether
	 * or not any new or modified entries have been added to the temporary
	 * contents file.  Set the "data is modified" indication associated
	 * with this VFP so that the real contents file is overwritten when
	 * processing is done.
	 */

	(void) vfpSetModified(a_vfp);

	/* write initial path [all entries] */

	vfpPuts(a_vfp, a_ept->path);

	/* if link, write out '=' portion */

	if (a_ept->ainfo.local) {
		vfpPutc(a_vfp, '=');
		vfpPuts(a_vfp, a_ept->ainfo.local);
	}

	/* if volume, write it out */

	if (a_ept->volno) {
		vfpPutc(a_vfp, ' ');
		vfpPutInteger(a_vfp, a_ept->volno);
	}

	/* write out <space><entry type><space>class> */

	vfpPutc(a_vfp, ' ');
	vfpPutc(a_vfp, a_ept->ftype);
	vfpPutc(a_vfp, ' ');
	vfpPuts(a_vfp, a_ept->pkg_class);

	/* if char/block device, write out major/minor numbers */

	if ((a_ept->ftype == 'c') || (a_ept->ftype == 'b')) {
		/* major device number */
		if (a_ept->ainfo.major == BADMAJOR) {
			vfpPutc(a_vfp, ' ');
			vfpPutc(a_vfp, '?');
		} else {
			vfpPutc(a_vfp, ' ');
			vfpPutInteger(a_vfp, a_ept->ainfo.major);
		}

		/* minor device number */
		if (a_ept->ainfo.minor == BADMINOR) {
			vfpPutc(a_vfp, ' ');
			vfpPutc(a_vfp, '?');
		} else {
			vfpPutc(a_vfp, ' ');
			vfpPutInteger(a_vfp, a_ept->ainfo.minor);
		}
	}

	/* if dxcbpfve, write out mode, owner, group */

	if ((a_ept->ftype == 'd') || (a_ept->ftype == 'x') ||
		(a_ept->ftype == 'c') || (a_ept->ftype == 'b') ||
		(a_ept->ftype == 'p') || (a_ept->ftype == 'f') ||
		(a_ept->ftype == 'v') || (a_ept->ftype == 'e')) {

		/* mode */
		vfpPutFormat(a_vfp,
			((a_ept->ainfo.mode == BADMODE) ? " ?" : " %04o"),
			a_ept->ainfo.mode);

		/* owner */
		vfpPutc(a_vfp, ' ');
		vfpPuts(a_vfp, a_ept->ainfo.owner);

		/* group */
		vfpPutc(a_vfp, ' ');
		vfpPuts(a_vfp, a_ept->ainfo.group);
	}
	/* if f/v/e, write out size, cksum, modtime */

	if ((a_ept->ftype == 'f') || (a_ept->ftype == 'v') ||
		(a_ept->ftype == 'e')) {
		/* size */
		vfpPutFormat(a_vfp,
			((a_ept->cinfo.size == BADCONT) ? " ?" : " %llu"),
			a_ept->cinfo.size);

		/* cksum */
		vfpPutFormat(a_vfp,
			((a_ept->cinfo.cksum == BADCONT) ? " ?" : " %ld"),
			a_ept->cinfo.cksum);

		/* modtime */
		vfpPutFormat(a_vfp,
			((a_ept->cinfo.modtime == BADCONT) ? " ?" : " %ld"),
			a_ept->cinfo.modtime);
	}

	/* write out list of all packages referencing this entry */

	pinfo = a_ept->pinfo;
	while (pinfo) {
		vfpPutc(a_vfp, ' ');
		if (pinfo->status) {
			vfpPutc(a_vfp, pinfo->status);
		}

		vfpPuts(a_vfp, pinfo->pkg);

		if (pinfo->editflag) {
			vfpPutc(a_vfp, '\\');
		}

		if (pinfo->aclass[0]) {
			vfpPutc(a_vfp, ':');
			vfpPuts(a_vfp, pinfo->aclass);
		}
		pinfo = pinfo->next;
	}

	vfpPutc(a_vfp, '\n');
	return (0);
}
