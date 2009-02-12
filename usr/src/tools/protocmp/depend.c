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


#include <stdio.h>
#include <sys/param.h>
#include <fcntl.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/stat.h>

#include "list.h"
#include "protodir.h"
#include "arch.h"

static pkg_list *packages[HASH_SIZE];

#define	HASH(name) (hash(name) % HASH_SIZE)

int
processed_package(const char *pkgname)
{
	int	bucket;
	pkg_list *tmp;

	bucket = HASH(pkgname);
	for (tmp = packages[bucket]; tmp != NULL; tmp = tmp->next) {
		if (strcmp(tmp->pkg_name, pkgname) == 0)
			return (1);
	}
	return (0);
}

void
mark_processed(const char *pkgname)
{
	int	bucket;
	pkg_list *tmp;

	bucket = HASH(pkgname);
	tmp = malloc(sizeof (pkg_list));
	bzero(tmp, sizeof (pkg_list));
	(void) strcpy(tmp->pkg_name, pkgname);
	tmp->next = packages[bucket];
	packages[bucket] = tmp;
}

static pkg_list *
add_dependency(pkg_list *dependlist, const char *pkgname)
{
	pkg_list *tmp;
	pkg_list *pkg;

	pkg = malloc(sizeof (pkg_list));
	bzero(pkg, sizeof (pkg_list));
	(void) strcpy(pkg->pkg_name, pkgname);

	/* easy case */
	if (dependlist == NULL)
		return (pkg);
	/* insert at end, since the order matters */
	for (tmp = dependlist; tmp->next != NULL; tmp = tmp->next) {
		/* NULL */
	}
	tmp->next = pkg;
	return (dependlist);
}

static void
free_dependency_list(pkg_list *dependlist)
{
	pkg_list *tmp;

	while (dependlist) {
		tmp = dependlist;
		dependlist = dependlist->next;
		tmp->next = NULL;
		free(tmp);
	}
}

#ifdef DEBUG
void
print_dependencies(const char *pkgname, pkg_list *dependlist)
{
	pkg_list *tmp;

	fprintf(stderr, "%s:", pkgname);
	for (tmp = dependlist; tmp != NULL; tmp = tmp->next)
		fprintf(stderr, " %s", tmp->pkg_name);
	fprintf(stderr, "\n");
}
#endif

static char *suffix_list[] = {
#if defined(__i386)
	".i",
#elif defined(__sparc)
	".c",
	".d",
	".m",
	".u",
	".v",
#else
#error "Unknown architecture."
#endif
	NULL,
};

static pkg_list *
find_dependencies(const char *pkgname, const char *parentdir)
{
	char	dependfile[MAXPATHLEN + 1];
	char	pkgdir[MAXPATHLEN + 1];
	char	buf[BUFSIZ];
	char	deppkg[MAXNAME];
	char	archpkg[MAXNAME];
	struct stat sbuf;
	FILE	*fp;
	pkg_list *dependlist = NULL;
	char	**suffixes;

	(void) sprintf(dependfile, "%s/%s/depend", parentdir, pkgname);
	fp = fopen(dependfile, "r");
	if (fp == NULL) {
		/*
		 * depend won't exist in ON packages until a build
		 * has been done, but it would be nice if you didn't have
		 * to do that. So try the generic depend file that those
		 * packages would copy in during the build.
		 */
		(void) sprintf(dependfile, "%s/common_files/depend", parentdir);
		fp = fopen(dependfile, "r");
		if (fp == NULL)
			return (NULL);
	}
	while (fgets(buf, BUFSIZ, fp) != NULL) {
		if ((buf[0] == '\0') || (buf[0] == '#') || isspace(buf[0]))
			continue;
		/* we only care about prerequisites */
		if (buf[0] != 'P')
			continue;
		(void) sscanf(buf, "P %s", deppkg);
		/*
		 * We have to be careful with some of the packages that are
		 * listed as dependencies but exist under a different name -
		 * SUNWcar is good, because it's actually SUNWcar.{c,d,i,m,u}.
		 * What do we do there? We can't just go for all the '.'
		 * packages, since on x86 we only want the .i one, and on sparc
		 * we want everything _but_ .i. Maybe
		 *
		 * I think perhaps what we do is, if we don't find a package
		 * dependency, on intel we append '.i' and try for that, and on
		 * sparc we try the other extensions. Any we find get added.
		 *
		 * Note also we're quiet on failures. This is because you might
		 * be dependant on some outside package.
		 */
		(void) sprintf(pkgdir, "%s/%s", parentdir, deppkg);
		if (stat(pkgdir, &sbuf) == -1) {
			if (errno != ENOENT) {
				continue;
			}
			for (suffixes = &suffix_list[0]; *suffixes != NULL;
			    suffixes++) {
				(void) sprintf(archpkg, "%s%s", deppkg,
				    *suffixes);
				(void) sprintf(pkgdir, "%s/%s", parentdir,
				    archpkg);
				if (stat(pkgdir, &sbuf) == -1) {
					continue;
				}
				if (!S_ISDIR(sbuf.st_mode)) {
					continue;
				}
				/* found one */
				dependlist = add_dependency(dependlist,
				    archpkg);
			}
		}
		if (!S_ISDIR(sbuf.st_mode)) {
			continue;
		}
		dependlist = add_dependency(dependlist, deppkg);
	}
	(void) fclose(fp);
	return (dependlist);
}

int
process_dependencies(const char *pkgname, const char *parentdir,
    elem_list *list, int verbose)
{
	int	count = 0;
	char	pkgdir[MAXPATHLEN + 1];
	pkg_list *dependlist;
	pkg_list *tmp;

	dependlist = find_dependencies(pkgname, parentdir);
/*
 *	print_dependencies(pkgname, dependlist);
 */
	if (dependlist == NULL)
		return (0);

	for (tmp = dependlist; tmp != NULL; tmp = tmp->next) {
		(void) sprintf(pkgdir, "%s/%s", parentdir, tmp->pkg_name);
		count += process_package_dir(tmp->pkg_name, pkgdir, list,
		    verbose);
	}

	free_dependency_list(dependlist);
	return (count);
}
