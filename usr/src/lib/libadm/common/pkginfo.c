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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.2 */
/*LINTLIBRARY*/

/*  5-20-92   added newroot functions  */

#include <stdio.h>
#include <limits.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <pkginfo.h>
#include <pkgstrct.h>
#include <pkglocs.h>
#include <errno.h>
#include "libadm.h"

static void	initpkg(struct pkginfo *);
static char	*svr4inst(char *);
static int	rdconfig(struct pkginfo *, char *, char *);
static int	svr4info(struct pkginfo *, char *, char *);
static int	ckinfo(char *, char *, char *);
static int	ckinst(char *, char *, char *, char *, char *);
static int	verscmp(char *, char *);
static int	archcmp(char *, char *);
static int	compver(char *, char *);

/*
 * Globals:
 *	pkgdir - specifies the directory where information about packages
 *	    resides, i.e. the pkginfo file is located in a subdirectory
 *
 * Caveats:
 *	The structure provided via "info" will contain malloc'd information;
 *	    this will be free'd upon the next call to pkginfo with this
 *	    same structure.  Application calls must make sure this structure
 *	    is null on the first call, or else we'll free static memory areas
 *	If the "pkg" argument is a wildcard specification, the next found
 *	    instance available which matches the request will be returned
 *	If the "pkg" argument is a NULL pointer, the structure pointed to
 *	    via "info" will have its elements deallocated and all files
 *	    associated with this routine will be closed
 *
 * Return codes:
 *	A non-zero exit code indicates error with "errno" appropriately set:
 *	    EINVAL - invalid argument
 *	    ESRCH - there are no more instances of this package around
 *	    EACCESS - unable to access files which should have been there
 */

/*VARARGS*/
int
pkginfo(struct pkginfo *info, char *pkginst, ...)
{
	char	*ckarch, *ckvers;
	int	check;
	va_list ap;

	va_start(ap, pkginst);
	if (info == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (pkginst == NULL) {
		info->pkginst = NULL;
		(void) fpkginfo(info, NULL);
		(void) fpkginst(NULL);
		return (0);
	}
	ckarch = va_arg(ap, char *);
	ckvers = va_arg(ap, char *);
	va_end(ap);

	check = 0;
	if (pkgnmchk(pkginst, "all", 1)) {
		/* wild card specification */
		pkginst = fpkginst(pkginst, ckarch, ckvers);
		if (pkginst == NULL)
			return (-1);
	} else {
		/* request to check indicated instance */
		if (ckarch || ckvers)
			check++;
	}

	info->pkginst = NULL;
	if (fpkginfo(info, pkginst))
		return (-1);

	if (check) {
		/*
		 * verify that the provided instance matches
		 * any arch & vers specs that were provided
		 */
		if (ckinst(pkginst, info->arch, info->version, ckarch,
		    ckvers)) {
			errno = ESRCH;
			return (-1);
		}
	}
	return (0);
}
/*ARGSUSED*/

int
fpkginfo(struct pkginfo *info, char *pkginst)
{

	if (info == NULL) {
		errno = EINVAL;
		return (-1);
	}

	initpkg(info);

	if (pkginst == NULL)
		return (0);
	else if (pkgnmchk(pkginst, "all", 1)) {
		errno = EINVAL; /* not an instance identifier */
		return (-1);
	}
	if (pkgdir == NULL)
		pkgdir = get_PKGLOC();

	if (rdconfig(info, pkginst, NULL)) {
		initpkg(info);
		return (-1);
	}
	return (0);
}

static void
initpkg(struct pkginfo *info)
{
	/* free previously allocated space */
	if (info->pkginst) {
		free(info->pkginst);
		if (info->arch)
			free(info->arch);
		if (info->version)
			free(info->version);
		if (info->basedir)
			free(info->basedir);
		if (info->name)
			free(info->name);
		if (info->vendor)
			free(info->vendor);
		if (info->catg)
			free(info->catg);
	}

	info->pkginst = NULL;
	info->arch = info->version = NULL;
	info->basedir = info->name = NULL;
	info->vendor = info->catg = NULL;
	info->status = PI_UNKNOWN;
}

static int
rdconfig(struct pkginfo *info, char *pkginst, char *ckvers)
{
	FILE	*fp;
	char	temp[256];
	char	*value, *pt, *copy, **memloc;
	int	count;

	if ((fp = pkginfopen(pkgdir, pkginst)) == NULL) {
		if ((errno == ENOENT) && strcmp(pkgdir, get_PKGLOC()) == 0)
			return (svr4info(info, pkginst, ckvers));

		errno = EACCES;
		return (-1);
	}

	*temp = '\0';
	count = 0;
	while (value = fpkgparam(fp, temp)) {
		if (strcmp(temp, "ARCH") == 0 ||
		    strcmp(temp, "CATEGORY") == 0) {
			/* remove all whitespace from value */
			pt = copy = value;
			while (*pt) {
				if (!isspace((unsigned char)*pt))
					*copy++ = *pt;
				pt++;
			}
			*copy = '\0';
		}
		count++;
		memloc = NULL;
		if (strcmp(temp, "NAME") == 0)
			memloc = &info->name;
		else if (strcmp(temp, "VERSION") == 0)
			memloc = &info->version;
		else if (strcmp(temp, "ARCH") == 0)
			memloc = &info->arch;
		else if (strcmp(temp, "VENDOR") == 0)
			memloc = &info->vendor;
		else if (strcmp(temp, "BASEDIR") == 0)
			memloc = &info->basedir;
		else if (strcmp(temp, "CATEGORY") == 0)
			memloc = &info->catg;

		temp[0] = '\0';
		if (memloc == NULL)
			continue; /* not a parameter we're looking for */

		*memloc = strdup(value);
		if (!*memloc) {
			(void) fclose(fp);
			errno = ENOMEM;
			return (-1); /* malloc from strdup failed */
		}
	}
	(void) fclose(fp);

	if (!count) {
		errno = ESRCH;
		return (-1);
	}

	info->status = (strcmp(pkgdir, get_PKGLOC()) ? PI_SPOOLED :
	    PI_INSTALLED);

	if (info->status == PI_INSTALLED) {
		(void) sprintf(temp, "%s/%s/!I-Lock!", pkgdir, pkginst);
		if (access(temp, 0) == 0)
			info->status = PI_PARTIAL;
		else {
			(void) sprintf(temp, "%s/%s/!R-Lock!", pkgdir, pkginst);
			if (access(temp, 0) == 0)
				info->status = PI_PARTIAL;
		}
	}
	info->pkginst = strdup(pkginst);
	return (0);
}

static int
svr4info(struct pkginfo *info, char *pkginst, char *ckvers)
{
	static DIR *pdirfp;
	struct stat64 status;
	FILE *fp;
	char *pt, path[128], line[128];
	char	temp[PKGSIZ+1];

	if (strcmp(pkginst, "all")) {
		if (pdirfp) {
			(void) closedir(pdirfp);
			pdirfp = NULL;
		}
		/* determine pkginst - remove '.*' extension, if any */
		(void) strncpy(temp, pkginst, PKGSIZ);
		if (((pt = strchr(temp, '.')) != NULL) && strcmp(pt, ".*") == 0)
			*pt = '\0';
	}

	/* look in /usr/options direcotry for 'name' file */
	(void) sprintf(path, "%s/%s.name", get_PKGOLD(), temp);
	if (lstat64(path, &status)) {
		errno = (errno == ENOENT) ? ESRCH : EACCES;
		return (-1);
	}
	if ((status.st_mode & S_IFMT) != S_IFREG) {
		errno = ESRCH;
		return (-1);
	}
	if ((fp = fopen(path, "r")) == NULL) {
		errno = (errno == ENOENT) ? ESRCH : EACCES;
		return (-1);
	}

	/* /usr/options/xxx.name exists */
	(void) fgets(line, 128, fp);
	(void) fclose(fp);
	if (pt = strchr(line, '\n'))
		*pt = '\0'; /* remove trailing newline */
	if (pt = strchr(line, ':'))
		*pt++ = '\0'; /* assumed version specification */

	if (info) {
		info->name = strdup(line);
		info->pkginst = strdup(temp);
		if (!info->name || !info->pkginst) {
			errno = ENOMEM;
			return (-1);
		}
		info->status = PI_PRESVR4;
		info->version = NULL;
	}

	if (pt) {
		/* eat leading space off of version spec */
		while (isspace((unsigned char)*pt))
			pt++;
	}
	if (ckvers && verscmp(ckvers, pt)) {
		errno = ESRCH;
		return (-1);
	}
	if (info && *pt)
		info->version = strdup(pt);
	return (0);
}

static int
ckinst(char *pkginst, char *pkgarch, char *pkgvers, char *ckarch, char *ckvers)
{
	if (ckarch && archcmp(ckarch, pkgarch))
		return (-1);
	if (ckvers) {
		/* Check for exact version match */
		if (verscmp(ckvers, pkgvers)) {
			/* Check for compatable version */
			if (compver(pkginst, ckvers))
				return (-1);
		}
	}
	return (0);
}

/*VARARGS*/
char *
fpkginst(char *pkg, ...)
{
	static char pkginst[PKGSIZ+1];
	static DIR *pdirfp;
	struct dirent64 *dp;
	char	*pt, *ckarch, *ckvers;
	va_list	ap;

	va_start(ap, pkg);

	if (pkg == NULL) {
		/* request to close or rewind the file */
		if (pdirfp) {
			(void) closedir(pdirfp);
			pdirfp = NULL;
		}
		(void) svr4inst(NULL); /* close any files used here */
		return (NULL);
	}

	ckarch = va_arg(ap, char *);
	ckvers = va_arg(ap, char *);
	va_end(ap);

	if (!pkgdir)
		pkgdir = get_PKGLOC();

	if (!pdirfp && ((pdirfp = opendir(pkgdir)) == NULL)) {
		errno = EACCES;
		return (NULL);
	}

	while ((dp = readdir64(pdirfp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;

		if (pkgnmchk(dp->d_name, pkg, 0))
			continue; /* ignore invalid SVR4 package names */

		if (ckinfo(dp->d_name, ckarch, ckvers))
			continue;

		/*
		 * Leave directory open in case user requests another
		 * instance.
		 */
		(void) strcpy(pkginst, dp->d_name);
		return (pkginst);
	}

	/*
	 * If we are searching the directory which contains info about
	 * installed packages, check the pre-svr4 directory for an instance
	 * and be sure it matches any version specification provided to us
	 */
	if (strcmp(pkgdir, get_PKGLOC()) == 0 && (ckarch == NULL)) {
		/* search for pre-SVR4 instance */
		if (pt = svr4inst(pkg))
			return (pt);
	}
	errno = ESRCH;
	/* close any file we might have open */
	(void) closedir(pdirfp);
	pdirfp = NULL;
	return (NULL);
}
/*ARGSUSED*/

static char *
svr4inst(char *pkg)
{
	static char pkginst[PKGSIZ];
	static DIR *pdirfp;
	struct dirent64 *dp;
	struct stat64	status;	/* file status buffer */
	char	*pt;
	char	path[PATH_MAX];

	if (pkg == NULL) {
		if (pdirfp) {
			(void) closedir(pdirfp);
			pdirfp = NULL;
		}
		return (NULL);
	}

	if (!pdirfp && ((pdirfp = opendir(get_PKGOLD())) == NULL))
		return (NULL);

	while ((dp = readdir64(pdirfp)) != NULL) {
		if (dp->d_name[0] == '.')
			continue;
		pt = strchr(dp->d_name, '.');
		if (pt && strcmp(pt, ".name") == 0) {
			/* the pkgnmchk function works on .name extensions */
			if (pkgnmchk(dp->d_name, pkg, 1))
				continue;
			(void) sprintf(path, "%s/%s", get_PKGOLD(), dp->d_name);
			if (lstat64(path, &status))
				continue;
			if ((status.st_mode & S_IFMT) != S_IFREG)
				continue;
			*pt = '\0';
			(void) strcpy(pkginst, dp->d_name);
			return (pkginst);
		}
	}
	(void) closedir(pdirfp);
	pdirfp = NULL;
	return (NULL);
}

static int
verscmp(char *request, char *actual)
{
	/* eat leading white space */
	while (isspace((unsigned char)*actual))
		actual++;
	while (isspace((unsigned char)*request))
		request++;

	while (*request || *actual) {
		/*
		 * Once the pointers don't match, return an error condition.
		 */

		if (*request++ != *actual++)
			return (-1);

		/* eat white space if any in both the strings */
		if (isspace((unsigned char)*request)) {
			if (*actual && !isspace((unsigned char)*actual))
				return (-1);
			while (isspace((unsigned char)*request))
				request++;
			while (isspace((unsigned char)*actual))
				actual++;
		}
	}

	return (0);

}

static int
compver(char *pkginst, char *version)
{
	FILE *fp;
	char temp[256];

	(void) sprintf(temp, "%s/%s/install/compver", get_PKGLOC(), pkginst);
	if ((fp = fopen(temp, "r")) == NULL)
		return (-1);

	while (fgets(temp, 256, fp)) {
		if (*temp == '#')
			continue;
		if (verscmp(temp, version) == 0) {
			(void) fclose(fp);
			return (0);
		}
	}
	(void) fclose(fp);
	return (-1);
}

static int
archcmp(char *arch, char *archlist)
{
	char *pt;

	if (arch == NULL)
		return (0);

	/* arch and archlist must not contain whitespace! */

	while (*archlist) {
		for (pt = arch; *pt && (*pt == *archlist); )
			pt++, archlist++;
		if (!*pt && (!*archlist || (*archlist == ',')))
			return (0);
		while (*archlist) {
			if (*archlist++ == ',')
				break;
		}
	}
	return (-1);
}

static int
ckinfo(char *inst, char *arch, char *vers)
{
	FILE	*fp;
	char	temp[128];
	char	file[PATH_MAX];
	char	*pt, *copy, *value, *myarch, *myvers;
	int	errflg;

	(void) sprintf(file, "%s/%s/pkginfo", pkgdir, inst);
	if ((fp = fopen(file, "r")) == NULL)
		return (1);

	if ((arch == NULL) && (vers == NULL)) {
		(void) fclose(fp);
		return (0);
	}
	temp[0] = '\0';
	myarch = myvers = NULL;
	while (value = fpkgparam(fp, temp)) {
		if (strcmp(temp, "ARCH") == 0) {
			/* remove all whitespace from value */
			pt = copy = value;
			while (*pt) {
				if (!isspace((unsigned char)*pt))
					*copy++ = *pt;
				pt++;
			}
			*copy = '\0';
			myarch = value;
			if (myvers)
				break;
		} else if (strcmp(temp, "VERSION") == 0) {
			myvers = value;
			if (myarch)
				break;
		} else
			free(value);
		temp[0] = '\0';
	}
	(void) fclose(fp);
	errflg = 0;

	if (ckinst(inst, myarch, myvers, arch, vers))
		errflg++;

	if (myarch)
		free(myarch);
	if (myvers)
		free(myvers);

	return (errflg);
}
