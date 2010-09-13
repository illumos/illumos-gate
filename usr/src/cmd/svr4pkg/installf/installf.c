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

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <pkgstrct.h>
#include <locale.h>
#include <libintl.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include "installf.h"

#define	LSIZE	1024
#define	MALSIZ	164

#define	ERR_MAJOR 	"invalid major number <%s> specified for <%s>"
#define	ERR_MINOR 	"invalid minor number <%s> specified for <%s>"
#define	ERR_MODE	"invalid mode <%s> specified for <%s>"
#define	ERR_RELPATH 	"relative pathname <%s> not permitted"
#define	ERR_NULLPATH 	"NULL or garbled pathname"
#define	ERR_LINK	"invalid link specification <%s>"
#define	ERR_LINKFTYPE	"ftype <%c> does not match link specification <%s>"
#define	ERR_LINKARGS	"extra arguments in link specification <%s>"
#define	ERR_LINKREL	"relative pathname in link specification <%s>"
#define	ERR_FTYPE	"invalid ftype <%c> for <%s>"
#define	ERR_ARGC 	"invalid number of arguments for <%s>"
#define	ERR_SPECALL	"ftype <%c> requires all fields to be specified"

static int validate(struct cfextra *ext, int argc, char *argv[]);
static void checkPaths(char *argv[]);

int
installf(int argc, char *argv[])
{
	struct cfextra *new;
	char	line[LSIZE];
	char	*largv[8];
	int	myerror;

	if (strcmp(argv[0], "-") != 0) {
		if (argc < 1)
			usage(); /* at least pathname is required */
		extlist = calloc(2, sizeof (struct cfextra *));
		extlist[0] = new = calloc(1, sizeof (struct cfextra));
		eptnum = 1;

		/* There is only one filename on the command line. */
		checkPaths(argv);
		if (validate(new, argc, argv))
			quit(1);
		return (0);
	}

	/* Read stdin to obtain entries, which need to be sorted. */
	eptnum = 0;
	myerror = 0;
	extlist = calloc(MALSIZ, sizeof (struct cfextra *));
	while (fgets(line, LSIZE, stdin) != NULL) {
		argc = 0;
		argv = largv;
		argv[argc++] = strtok(line, " \t\n");
		while (argv[argc] = strtok(NULL, " \t\n"))
			argc++;

		if (argc < 1)
			usage(); /* at least pathname is required */

		new = calloc(1, sizeof (struct cfextra));
		if (new == NULL) {
			progerr(strerror(errno));
			quit(99);
		}

		checkPaths(argv);

		if (validate(new, argc, argv))
			myerror++;

		extlist[eptnum] = new;
		if ((++eptnum % MALSIZ) == 0) {
			extlist = realloc(extlist,
			    (sizeof (struct cfextra *) * (eptnum+MALSIZ)));
			if (!extlist) {
				progerr(strerror(errno));
				quit(99);
			}
		}
	}
	extlist[eptnum] = (struct cfextra *)NULL;
	qsort((char *)extlist, (unsigned)eptnum, sizeof (struct cfextra *),
	    cfentcmp);
	return (myerror);
}

static int
validate(struct cfextra *ext, int argc, char *argv[])
{
	char	*ret, *pt;
	int	n, allspec, is_a_link;
	struct	cfent *ept;

	ept = &(ext->cf_ent);

	/* initialize cfent structure */
	ept->pinfo = NULL;
	(void) gpkgmapvfp(ept, (VFP_T *)NULL);	/* This just clears stuff. */

	n = allspec = 0;
	if (classname)
		(void) strncpy(ept->pkg_class, classname, CLSSIZ);

	if (argv[n] == NULL || *(argv[n]) == '\000') {
		progerr(gettext(ERR_NULLPATH));
		return (1);
	}

	/*
	 * It would be a good idea to figure out how to get much of
	 * this done using facilities in procmap.c - JST
	 */
	if (pt = strchr(argv[n], '=')) {
		*pt = '\0';	/* cut off pathname at the = sign */
		is_a_link = 1;
	} else
		is_a_link = 0;

	if (RELATIVE(argv[n])) {
		progerr(gettext(ERR_RELPATH),
		    (argv[n] == NULL) ? "unknown" : argv[n]);
		return (1);
	}

	/* get the pathnames */
	if (eval_path(&(ext->server_path), &(ext->client_path),
	    &(ext->map_path), argv[n++]) == 0)
		return (1);

	ept->path = ext->client_path;

	/* This isn't likely to happen; but, better safe than sorry. */
	if (RELATIVE(ept->path)) {
		progerr(gettext(ERR_RELPATH), ept->path);
		return (1);
	}

	if (is_a_link) {
		/* links specifications should be handled right here */
		ept->ftype = ((n >= argc) ? 'l' : argv[n++][0]);

		/* If nothing follows the '=', it's invalid */
		if (!pt[1]) {
			progerr(gettext(ERR_LINK), ept->path);
			return (1);
		}

		/* Test for an argument after the link. */
		if (argc != n) {
			progerr(gettext(ERR_LINKARGS), ept->path);
			return (1);
		}

		/*
		 * If it's a link but it's neither hard nor symbolic then
		 * it's bad.
		 */
		if (!strchr("sl", ept->ftype)) {
			progerr(gettext(ERR_LINKFTYPE), ept->ftype, ept->path);
			return (1);
		}

		ext->server_local = pathdup(pt+1);
		ext->client_local = ext->server_local;

		ept->ainfo.local = ext->client_local;

		return (0);
	} else if (n >= argc) {
		/* we are expecting to change object's contents */
		return (0);
	}

	ept->ftype = argv[n++][0];
	if (strchr("sl", ept->ftype)) {
		progerr(gettext(ERR_LINK), ept->path);
		return (1);
	} else if (!strchr("?fvedxcbp", ept->ftype)) {
		progerr(gettext(ERR_FTYPE), ept->ftype, ept->path);
		return (1);
	}

	if (ept->ftype == 'b' || ept->ftype == 'c') {
		if (n < argc) {
			ept->ainfo.major = strtol(argv[n++], &ret, 0);
			if (ret && *ret) {
				progerr(gettext(ERR_MAJOR), argv[n-1],
				    ept->path);
				return (1);
			}
		}
		if (n < argc) {
			ept->ainfo.minor = strtol(argv[n++], &ret, 0);
			if (ret && *ret) {
				progerr(gettext(ERR_MINOR), argv[n-1],
				    ept->path);
				return (1);
			}
			allspec++;
		}
	}

	allspec = 0;
	if (n < argc) {
		ept->ainfo.mode = strtol(argv[n++], &ret, 8);
		if (ret && *ret) {
			progerr(gettext(ERR_MODE), argv[n-1], ept->path);
			return (1);
		}
	}
	if (n < argc)
		(void) strncpy(ept->ainfo.owner, argv[n++], ATRSIZ);
	if (n < argc) {
		(void) strncpy(ept->ainfo.group, argv[n++], ATRSIZ);
		allspec++;
	}
	if (strchr("dxbcp", ept->ftype) && !allspec) {
		progerr(gettext(ERR_ARGC), ept->path);
		progerr(gettext(ERR_SPECALL), ept->ftype);
		return (1);
	}
	if (n < argc) {
		progerr(gettext(ERR_ARGC), ept->path);
		return (1);
	}
	return (0);
}

int
cfentcmp(const void *p1, const void *p2)
{
	struct cfextra *ext1 = *((struct cfextra **)p1);
	struct cfextra *ext2 = *((struct cfextra **)p2);

	return (strcmp(ext1->cf_ent.path, ext2->cf_ent.path));
}

/*
 * If the path at argv[0] has the value of
 * PKG_INSTALL_ROOT prepended, remove it
 */
static void
checkPaths(char *argv[])
{
	char *root;
	int rootLen;

	/*
	 * Note- No local copy of argv is needed since this
	 * function is guaranteed to replace argv with a subset of
	 * the original argv.
	 */

	/* We only want to canonize the path if it contains multiple '/'s */

	canonize_slashes(argv[0]);

	if ((root = get_inst_root()) == NULL)
		return;
	if (strcmp(root, "/") != 0) {
		rootLen = strlen(root);
		if (strncmp(argv[0], root, rootLen) == 0) {
			argv[0] += rootLen;
		}
	}
}
