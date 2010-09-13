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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include "pkgstrct.h"

int	holdcinfo = 0;

int
ppkgmap(struct cfent *ept, FILE *fp)
{
	if (ept->path == NULL)
		return (-1);

	if (ept->volno) {
		if (fprintf(fp, "%d ", ept->volno) < 0)
			return (-1);
	}

	if (ept->ftype == 'i') {
		if (fprintf(fp, "%c %s", ept->ftype, ept->path) < 0)
			return (-1);
	} else {
		if (fprintf(fp, "%c %s %s", ept->ftype, ept->pkg_class,
		    ept->path) < 0)
			return (-1);
	}

	if (ept->ainfo.local) {
		if (fprintf(fp, "=%s", ept->ainfo.local) < 0)
			return (-1);
	}

	if (strchr("cb", ept->ftype)) {
#ifdef SUNOS41
		if (ept->ainfo.xmajor == BADMAJOR) {
			if (fprintf(fp, " ?") < 0)
				return (-1);
		} else {
			if (fprintf(fp, " %d", ept->ainfo.xmajor) < 0)
				return (-1);
		}
#else
		if (ept->ainfo.major == BADMAJOR) {
			if (fprintf(fp, " ?") < 0)
				return (-1);
		} else {
			if (fprintf(fp, " %d", ept->ainfo.major) < 0)
				return (-1);
		}
#endif
#ifdef SUNOS41
		if (ept->ainfo.xminor == BADMINOR) {
			if (fprintf(fp, " ?") < 0)
				return (-1);
		} else {
			if (fprintf(fp, " %d", ept->ainfo.xminor) < 0)
				return (-1);
		}
#else
		if (ept->ainfo.minor == BADMINOR) {
			if (fprintf(fp, " ?") < 0)
				return (-1);
		} else {
			if (fprintf(fp, " %d", ept->ainfo.minor) < 0)
				return (-1);
		}
#endif
	}

	if (strchr("dxcbpfve", ept->ftype)) {
		if (fprintf(fp, ((ept->ainfo.mode == BADMODE) ? " ?" : " %04o"),
		    ept->ainfo.mode) < 0)
			return (-1);
		if (fprintf(fp, " %s %s", ept->ainfo.owner, ept->ainfo.group) <
		    0)
			return (-1);
	}
	if (holdcinfo) {
		if (fputc('\n', fp) == EOF)
			return (-1);
		return (0);
	}

	if (strchr("ifve", ept->ftype)) {
		if (fprintf(fp, ((ept->cinfo.size == BADCONT) ? " ?" : " %llu"),
		    ept->cinfo.size) < 0)
			return (-1);
		if (fprintf(fp, ((ept->cinfo.cksum == BADCONT) ? " ?" : " %ld"),
		    ept->cinfo.cksum) < 0)
			return (-1);
		if (fprintf(fp,
		    ((ept->cinfo.modtime == BADCONT) ? " ?" : " %ld"),
		    ept->cinfo.modtime) < 0)
			return (-1);
	}

	if (ept->ftype == 'i') {
		if (fputc('\n', fp) == EOF)
			return (-1);
		return (0);
	}
	if (fprintf(fp, "\n") < 0)
		return (-1);
	return (0);
}
