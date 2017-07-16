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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */


#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <pkgdev.h>
#include <pkginfo.h>
#include <pkglocs.h>
#include <locale.h>
#include <libintl.h>
#include <instzones_api.h>
#include <pkglib.h>
#include <install.h>
#include <libinst.h>
#include <libadm.h>
#include <messages.h>

/* commands to execute */

#define	PKGINFO_CMD	"/usr/bin/pkginfo"

#define	GLOBALZONE_ONLY_PACKAGE_FILE_PATH	\
					"/var/sadm/install/gz-only-packages"

#if	!defined(TEXT_DOMAIN)	/* Should be defined by cc -D */
#define	TEXT_DOMAIN	"SYS_TEST"
#endif

/*
 * forward declarations
 */

static void		_pkginfoInit(struct pkginfo *a_info);
static struct pkginfo	*_pkginfoFactory(void);
static char		**thisZonePackages;
static int		numThisZonePackages;

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	pkginfoFree
 * Description:	free pkginfo structure returned from various functions
 * Arguments:	r_info - pointer to pointer to pkginfo structure to free
 * Returns:	void
 */

void
pkginfoFree(struct pkginfo **r_info)
{
	struct pkginfo	*pinfo;

	/* entry assertions */

	assert(r_info != (struct pkginfo **)NULL);

	/* localize reference to info structure to free */

	pinfo = *r_info;

	/* reset callers handle to info structure */

	*r_info = (struct pkginfo *)NULL;

	assert(pinfo != (struct pkginfo *)NULL);

	/* free up contents of the structure */

	_pkginfoInit(pinfo);

	/* free up structure itself */

	(void) free(pinfo);
}

/*
 * Name:	pkginfoIsPkgInstalled
 * Description:	determine if specified package is installed, return pkginfo
 *		structure describing package if package is installed
 * Arguments:	r_pinfo - pointer to pointer to pkginfo structure
 *			If this pointer is NOT null:
 *			-On success, this handle is filled in with a pointer
 *			--to a newly allocated pkginfo structure describing
 *			--the package discovered
 *			-On failure, this handle is filled with NULL
 *			If this pointer is NULL:
 *			-no pkginfo structure is returned on success.
 *		a_pkgInst - package instance (name) to lookup
 * Returns:	boolean_t
 *			B_TRUE - package installed, pkginfo returned
 *			B_FALSE - package not installed, no pkginfo returned
 * NOTE:	This function returns the first instance of package that
 *		is installed - see pkginfo() function for details
 * NOTE:    	Any pkginfo structure returned is placed in new storage for the
 *		calling function. The caller must use 'pkginfoFree' to dispose
 *		of the storage once the pkginfo structure is no longer needed.
 */

boolean_t
pkginfoIsPkgInstalled(struct pkginfo **r_pinfo, char *a_pkgInst)
{
	int		r;
	struct pkginfo	*pinf;

	/* entry assertions */

	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* reset returned pkginfo structure handle */

	if (r_pinfo != (struct pkginfo **)NULL) {
		*r_pinfo = (struct pkginfo *)NULL;
	}

	/* allocate a new pinfo structure for use in the call to pkginfo */

	pinf = _pkginfoFactory();

	/* lookup the specified package */

	/* NOTE: required 'pkgdir' set to spool directory or NULL */
	r = pkginfo(pinf, a_pkgInst, NULL, NULL);
	echoDebug(DBG_PKGOPS_PKGINFO_RETURNED, a_pkgInst, r);

	if (r_pinfo != (struct pkginfo **)NULL) {
		*r_pinfo = pinf;
	} else {
		/* free pkginfo structure */
		pkginfoFree(&pinf);
	}

	return (r == 0 ? B_TRUE : B_FALSE);
}

/*
 * Name:	pkgOpenInGzOnlyFile
 * Description:	Open the global zone only package list file
 * Arguments:	a_rootPath - pointer to string representing the root path
 *			where the global zone only package list file is
 *			located - NULL is the same as "/"
 * Returns:	FILE *
 *			== NULL - failure - file not open
 *			!= NULL - success - file pointer returned
 * NOTE:	This function will create the file if it does not exist.
 */

FILE *
pkgOpenInGzOnlyFile(char *a_rootPath)
{
	FILE	*pkgingzonlyFP;
	char	pkgingzonlyPath[PATH_MAX];
	int	len;

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/* generate path to glocal zone only list file */

	len = snprintf(pkgingzonlyPath, sizeof (pkgingzonlyPath), "%s/%s",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (pkgingzonlyPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return ((FILE *)NULL);
	}

	/* open global zone only list file */

	pkgingzonlyFP = fopen(pkgingzonlyPath, "r+");
	if ((pkgingzonlyFP == (FILE *)NULL) && (errno == ENOENT)) {
		pkgingzonlyFP = fopen(pkgingzonlyPath, "w+");
	}

	if ((pkgingzonlyFP == (FILE *)NULL) && (errno != ENOENT)) {
		progerr(ERR_PKGOPS_OPEN_GZONLY, pkgingzonlyPath,
				strerror(errno));
		return ((FILE *)NULL);
	}

	/* success - return FILE pointer open on global zone only list file */

	return (pkgingzonlyFP);
}

/*
 * Name:	pkgIsPkgInGzOnly
 * Description:	determine if package is recorded as "in global zone only"
 *		by opening the appropriate files and searching for the
 *		specified package
 * Arguments:	a_rootPath - pointer to string representing the root path
 *			where the global zone only package list file is
 *			located - NULL is the same as "/"
 *		a_pkgInst - pointer to string representing the package instance
 *			(name) of the package to lookup
 * Returns:	boolean_t
 *			B_TRUE - package is recorded as "in global zone only"
 *			B_FALSE - package is NOT recorded as "in gz only"
 * NOTE:	This function will create the file if it does not exist.
 */

boolean_t
pkgIsPkgInGzOnly(char *a_rootPath, char *a_pkgInst)
{
	FILE		*fp;
	boolean_t	in_gz_only;

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/* open the global zone only package list file */

	fp = pkgOpenInGzOnlyFile(a_rootPath);
	if (fp == (FILE *)NULL) {
		echoDebug(ERR_PKGOPS_CANNOT_OPEN_GZONLY,
				a_rootPath ? a_rootPath : "/");
		return (B_FALSE);
	}

	/* is the package recorded as "in global zone only" ? */

	in_gz_only = pkgIsPkgInGzOnlyFP(fp, a_pkgInst);

	/* close the global zone only package list file */

	(void) fclose(fp);

	/* return results */

	return (in_gz_only);
}

/*
 * Name:	pkgIsPkgInGzOnly
 * Description:	determine if package is recorded as "in global zone only"
 *		by searching the specified open FILE for the specified package
 * Arguments:	a_fp - pointer to FILE handle open on file to search
 *		a_pkgInst - pointer to string representing the package instance
 *			(name) of the package to lookup
 * Returns:	boolean_t
 *			B_TRUE - package is recorded as "in global zone only"
 *			B_FALSE - package is NOT recorded as "in gz only"
 */

boolean_t
pkgIsPkgInGzOnlyFP(FILE *a_fp, char *a_pkgInst)
{
	char	line[PATH_MAX+1];

	/* entry assertions */

	assert(a_fp != (FILE *)NULL);
	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* rewind the file to the beginning */

	rewind(a_fp);

	/* read the file line by line searching for the specified package */

	while (fgets(line, sizeof (line), a_fp) != (char *)NULL) {
		int	len;

		/* strip off trailing newlines */
		len = strlen(line);
		while ((len > 0) && (line[len-1] == '\n')) {
			line[--len] = '\0';
		}

		/* ignore blank and comment lines */
		if ((line[0] == '#') || (line[0] == '\0')) {
			continue;
		}

		/* return true if this is the package we are looking for */
		if (strcmp(a_pkgInst, line) == 0) {
			echoDebug(DBG_PKGOPS_PKG_IS_GZONLY, a_pkgInst);
			return (B_TRUE);
		}
	}

	/* end of file - package not found */

	echoDebug(DBG_PKGOPS_PKG_NOT_GZONLY, a_pkgInst);

	return (B_FALSE);
}

/*
 * Name:	pkgRemovePackageFromGzonlyList
 * Description:	Remove specified package from the global zone only package list
 *		file located at a specified root path
 * Arguments:	a_rootPath - pointer to string representing the root path
 *			where the global zone only package list file is
 *			located - NULL is the same as "/"
 *		a_pkgInst - pointer to string representing the package instance
 *			(name) of the package to remove
 * Returns:	boolean_t
 *			B_TRUE - package is successfully removed
 *			B_FALSE - failed to remove package from file
 * NOTE:	This function will create the file if it does not exist.
 */

boolean_t
pkgRemovePackageFromGzonlyList(char *a_rootPath, char *a_pkgInst)
{
	FILE		*destFP;
	FILE		*srcFP;
	boolean_t	pkgremoved = B_FALSE;
	char		destPath[PATH_MAX];
	char		line[PATH_MAX+1];
	char		savePath[PATH_MAX];
	char		srcPath[PATH_MAX];
	char		timeb[BUFSIZ];
	int		len;
	struct tm	*timep;
	time_t		clock;

	/* entry assertions */

	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/*
	 * calculate paths to various objects
	 */

	/* path to current "source" ingzonly file */

	len = snprintf(srcPath, sizeof (srcPath), "%s/%s",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* path to new "destination" ingzonly file */

	len = snprintf(destPath, sizeof (destPath), "%s/%s.tmp",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* path to temporary "saved" ingzonly file */

	len = snprintf(savePath, sizeof (savePath), "%s/%s.save",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* open source file, creating if necessary */

	srcFP = fopen(srcPath, "r+");
	if ((srcFP == (FILE *)NULL) && (errno == ENOENT)) {
		srcFP = fopen(srcPath, "w+");
	}

	/* error if could not open/create file */

	if (srcFP == (FILE *)NULL) {
		progerr(ERR_PKGOPS_OPEN_GZONLY, srcPath, strerror(errno));
		return (B_FALSE);
	}

	/* open/create new destination file */

	(void) remove(destPath);
	destFP = fopen(destPath, "w");
	if (destFP == (FILE *)NULL) {
		progerr(ERR_PKGOPS_TMPOPEN, destPath, strerror(errno));
		if (srcFP != (FILE *)NULL) {
			(void) fclose(srcFP);
		}
		return (B_FALSE);
	}

	/* add standard comment to beginning of file */

	(void) time(&clock);
	timep = localtime(&clock);

	(void) strftime(timeb, sizeof (timeb), "%c\n", timep);

	/* put standard header at the beginning of the file */

	(void) fprintf(destFP, MSG_GZONLY_FILE_HEADER,
			get_prog_name(), "remove", a_pkgInst, timeb);

	/* read source/write destination - removing specified package */

	while (fgets(line, sizeof (line), srcFP) != (char *)NULL) {
		int	len;

		/* strip off trailing newlines */
		len = strlen(line);
		while ((len > 0) && (line[len-1] == '\n')) {
			line[--len] = '\0';
		}

		/* ignore blank and comment lines */
		if ((line[0] == '#') || (line[0] == '\0')) {
			continue;
		}

		/* add pkg if yet to add and pkg <= line */
		if ((pkgremoved == B_FALSE) && (strcmp(a_pkgInst, line) == 0)) {
			pkgremoved = B_TRUE;
		} else {
			(void) fprintf(destFP, "%s\n", line);
		}
	}

	/* close both files */

	(void) fclose(srcFP);

	(void) fclose(destFP);

	/*
	 * if package not found there is no need to update the original file
	 */

	if (pkgremoved == B_FALSE) {
		(void) unlink(destPath);
		return (B_TRUE);
	}

	/*
	 * Now we want to make a copy of the old gzonly file as a
	 * fail-safe.
	 */

	if ((access(savePath, F_OK) == 0) && remove(savePath)) {
		progerr(ERR_REMOVE, savePath, strerror(errno));
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (link(srcPath, savePath) != 0) {
		progerr(ERR_LINK, savePath, srcPath, strerror(errno));
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (rename(destPath, srcPath) != 0) {
		progerr(ERR_RENAME, destPath, srcPath, strerror(errno));
		if (rename(savePath, srcPath)) {
			progerr(ERR_RENAME, savePath, srcPath, strerror(errno));
		}
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (remove(savePath) != 0) {
		progerr(ERR_REMOVE, savePath, strerror(errno));
	}

	/* successfully removed package */

	echoDebug(DBG_PKGOPS_REMOVED_GZPKG, a_pkgInst);

	return (B_TRUE);
}

/*
 * Name:	pkgAddPackageFromGzonlyList
 * Description:	Add specified package to the global zone only package list
 *		file located at a specified root path
 * Arguments:	a_rootPath - pointer to string representing the root path
 *			where the global zone only package list file is
 *			located - NULL is the same as "/"
 *		a_pkgInst - pointer to string representing the package instance
 *			(name) of the package to add
 * Returns:	boolean_t
 *			B_TRUE - package is successfully added
 *			B_FALSE - failed to add package to the file
 * NOTE:	This function will create the file if it does not exist.
 */

boolean_t
pkgAddPackageToGzonlyList(char *a_pkgInst, char *a_rootPath)
{
	FILE		*destFP;
	FILE		*srcFP;
	boolean_t	pkgadded = B_FALSE;
	char		destPath[PATH_MAX];
	char		line[PATH_MAX+1];
	char		savePath[PATH_MAX];
	char		srcPath[PATH_MAX];
	char		timeb[BUFSIZ];
	int		len;
	struct tm	*timep;
	time_t		clock;

	/* entry assertions */

	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* normalize root path */

	if (a_rootPath == (char *)NULL) {
		a_rootPath = "";
	}

	/* entry debugging info */

	echoDebug(DBG_PKGOPS_ADDGZPKG, a_pkgInst, a_rootPath);

	/*
	 * calculate paths to various objects
	 */

	/* path to current "source" ingzonly file */

	len = snprintf(srcPath, sizeof (srcPath), "%s/%s",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* path to new "destination" ingzonly file */

	len = snprintf(destPath, sizeof (destPath), "%s/%s.tmp",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* path to temporary "saved" ingzonly file */

	len = snprintf(savePath, sizeof (savePath), "%s/%s.save",
		a_rootPath, GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
	if (len > sizeof (srcPath)) {
		progerr(ERR_CREATE_PATH_2, a_rootPath,
				GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
		return (B_FALSE);
	}

	/* open source file, creating if necessary */

	srcFP = fopen(srcPath, "r+");
	if ((srcFP == (FILE *)NULL) && (errno == ENOENT)) {
		srcFP = fopen(srcPath, "w+");
	}

	/* error if could not open/create file */

	if (srcFP == (FILE *)NULL) {
		progerr(ERR_PKGOPS_OPEN_GZONLY, srcPath, strerror(errno));
		return (B_FALSE);
	}

	/* open/create new destination file */

	(void) remove(destPath);
	destFP = fopen(destPath, "w");
	if (destFP == (FILE *)NULL) {
		progerr(ERR_PKGOPS_TMPOPEN, destPath, strerror(errno));
		if (srcFP != (FILE *)NULL) {
			(void) fclose(srcFP);
		}
		return (B_FALSE);
	}

	/* add standard comment to beginning of file */

	(void) time(&clock);
	timep = localtime(&clock);

	(void) strftime(timeb, sizeof (timeb), "%c\n", timep);

	/* put standard header at the beginning of the file */

	(void) fprintf(destFP, MSG_GZONLY_FILE_HEADER,
			get_prog_name(), "add", a_pkgInst, timeb);

	/* read source/write destination; add package at appropriate location */

	while (fgets(line, sizeof (line), srcFP) != (char *)NULL) {
		int	len;

		/* strip off trailing newlines */
		len = strlen(line);
		while ((len > 0) && (line[len-1] == '\n')) {
			line[--len] = '\0';
		}

		/* ignore blank and comment lines */
		if ((line[0] == '#') || (line[0] == '\0')) {
			continue;
		}

		/* add pkg if yet to add and pkg <= line */
		if ((pkgadded == B_FALSE) && (strcmp(a_pkgInst, line) <= 0)) {
			if (strcmp(a_pkgInst, line) != 0) {
				(void) fprintf(destFP, "%s\n", a_pkgInst);
			}
			pkgadded = B_TRUE;
		}

		(void) fprintf(destFP, "%s\n", line);
	}

	/* if package not added yet, add to end of the file */

	if (pkgadded == B_FALSE) {
		(void) fprintf(destFP, "%s\n", a_pkgInst);
	}

	/* close both files */

	(void) fclose(srcFP);

	(void) fclose(destFP);

	/*
	 * Now we want to make a copy of the old gzonly file as a
	 * fail-safe.
	 */

	if ((access(savePath, F_OK) == 0) && remove(savePath)) {
		progerr(ERR_REMOVE, savePath, strerror(errno));
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (link(srcPath, savePath) != 0) {
		progerr(ERR_LINK, savePath, srcPath, strerror(errno));
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (rename(destPath, srcPath) != 0) {
		progerr(ERR_RENAME, destPath, srcPath, strerror(errno));
		if (rename(savePath, srcPath)) {
			progerr(ERR_RENAME, savePath, srcPath, strerror(errno));
		}
		(void) remove(destPath);
		return (B_FALSE);
	}

	if (remove(savePath) != 0) {
		progerr(ERR_REMOVE, savePath, strerror(errno));
	}

	/* successfully added package */

	echoDebug(DBG_PKGOPS_ADDED_GZPKG, a_pkgInst);

	return (B_TRUE);
}

/*
 * Name:	pkginfoParamTruth
 * Description:	Search pkginfo file for specified parameter/value pair
 * Arguments:	a_fp - Pointer to FILE handle open on pkginfo file to search
 *		a_param - Pointer to string representing the parameter name
 *			to search for
 *		a_value - Pointer to string representing the "success" value
 *			being searched for
 *		a_default - determine results if parameter NOT found
 *			B_TRUE - parameter is TRUE if not found
 *			B_FALSE - parameter is FALSE if not found
 * Returns:	boolean_t
 *		B_TRUE - the parameter was found and matched the specified value
 *			OR the paramter was not found and a_default == B_TRUE
 *		B_FALSE - the parameter was found and did NOT match the value
 *			OR the paramter was not found and a_default == B_FALSE
 */

boolean_t
pkginfoParamTruth(FILE *a_fp, char *a_param, char *a_value, boolean_t a_default)
{
	char		*param;
	boolean_t	result;

	/* entry assertions */

	assert(a_fp != (FILE *)NULL);
	assert(a_param != (char *)NULL);
	assert(*a_param != '\0');
	assert(a_value != (char *)NULL);
	assert(*a_value != '\0');

	/* rewind the file to the beginning */

	rewind(a_fp);

	/* search pkginfo file for the specified parameter */

	param = fpkgparam(a_fp, a_param);

	if (param == (char *)NULL) {
		/* parameter not found - return default */
		result = a_default;
	} else if (*param == '\0') {
		/* parameter found but no value - return default */
		result = a_default;
	} else if (strcasecmp(param, a_value) == 0) {
		/* paramter found - matches value */
		result = B_TRUE;
	} else {
		/* parameter found - does not match value */
		result = B_FALSE;
	}

	/* exit debugging info */

	echoDebug(DBG_PKGOPS_PARAMTRUTH_RESULTS,
		a_param, a_value, a_default == B_TRUE ? "true" : "false",
		param ? param : "?", result == B_TRUE ? "true" : "false");

	/* if parameter value found, free results */

	if (param != (char *)NULL) {
		(void) free(param);
	}

	/* return results of search */

	return (result);
}

/*
 * Name:	pkgGetPackageList
 * Description:	Determine list of packages based on list of packages that are
 *		available, category of packages to select, and list of packages
 *		to select.
 * Arguments:	r_pkgList - pointer to pointer to string array where the list
 *			of selected packages will be returned
 *		a_argv - pointer to string array containing list of packages
 *			to select
 *		a_optind - index into string array of first package to select
 *		a_categories - pointer to string representing the categories of
 *			packages to select
 *		a_categoryList - pointer to string array representing a list
 *			of categories to select
 *		a_pkgdev - package dev containing packages that can be selected
 * Returns:	int
 *	== 0  - packages found r_pkgList contains results package list retrieved
 *	== -1 - no packages found (errno == ENOPKG)
 *	!= 0 - "quit" value entered by user
 * NOTE:	If both a category and a list of packages to select are provided
 *		the category is used over the list of packages provided
 * NOTE:	If neither a category nor a list of packages to select are
 *		provided, an error is returned
 */

int
pkgGetPackageList(char ***r_pkgList, char **a_argv, int a_optind,
	char *a_categories, char **a_categoryList, struct pkgdev *a_pkgdev)
{
	char	*all_pkgs[4] = {"all", NULL};

	/* entry assertions */

	assert(a_pkgdev != (struct pkgdev *)NULL);
	assert(a_pkgdev->dirname != (char *)NULL);
	assert(*a_pkgdev->dirname != '\0');
	assert(r_pkgList != (char ***)NULL);
	assert(a_argv != (char **)NULL);

	/* entry debugging info */

	echoDebug(DBG_PKGOPS_GETPKGLIST_ENTRY);
	echoDebug(DBG_PKGOPS_GETPKGLIST_ARGS, a_pkgdev->dirname,
			a_categories ? a_categories : "?");

	/* reset returned package list handle */

	*r_pkgList = (char **)NULL;

	/*
	 * generate list of packages to be removed: if removing by category,
	 * then generate package list based on all packages by category,
	 * else generate package list based on all packages specified.
	 */

	if (a_categories != NULL) {
		/* generate package list from all packages in given category */

		*r_pkgList = gpkglist(a_pkgdev->dirname, &all_pkgs[0],
					a_categoryList);

		if (*r_pkgList == NULL) {
			echoDebug(DBG_PKGOPS_GPKGLIST_CATFAILED, a_categories);
			progerr(ERR_CAT_FND, a_categories);
			return (1);
		}

		echoDebug(DBG_PKGOPS_GPKGLIST_CATOK, a_categories);

		return (0);
	}

	/* generate package list from specified packages */

	*r_pkgList = gpkglist(a_pkgdev->dirname, &a_argv[a_optind], NULL);

	/* if list generated return results */

	if (*r_pkgList != NULL) {
		echoDebug(DBG_PKGOPS_GPKGLIST_OK);
		return (0);
	}

	/* handle error from gpkglist */

	switch (errno) {
	    case ENOPKG:	/* no packages */
		echoDebug(DBG_PKGOPS_GPKGLIST_ENOPKG);
		return (-1);

	    case ESRCH:
		echoDebug(DBG_PKGOPS_GPKGLIST_ESRCH);
		return (1);

	    case EINTR:
		echoDebug(DBG_PKGOPS_GPKGLIST_EINTR);
		return (3);

	    default:
		echoDebug(DBG_PKGOPS_GPKGLIST_UNKNOWN, errno);
		progerr(ERR_GPKGLIST_ERROR);
		return (99);
	}
}

/*
 * return string representing path to "global zone only file"
 */

char *
pkgGetGzOnlyPath(void)
{
	return (GLOBALZONE_ONLY_PACKAGE_FILE_PATH);
}

/*
 * Name:	pkgAddThisZonePackage
 * Description:	Add specified package to internal list of "this zone only" pkgs
 * Arguments:	a_pkgInst - name of package to add to list
 * Returns:	void
 */

void
pkgAddThisZonePackage(char *a_pkgInst)
{
	/* entry assertions */

	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* do not duplicate entries */

	if (pkgPackageIsThisZone(a_pkgInst) == B_TRUE) {
		return;
	}

	/* add package name to internal list */

	if (thisZonePackages == (char **)NULL) {
		thisZonePackages =
				(char **)calloc(2, sizeof (char **));
	} else {
		thisZonePackages =
				(char **)realloc(thisZonePackages,
				sizeof (char **)*(numThisZonePackages+2));
	}

	/* handle out of memory error */

	if (thisZonePackages == (char **)NULL) {
		progerr(ERR_MEMORY, errno);
		quit(99);
	}

	/* add this entry to the end of the list */

	thisZonePackages[numThisZonePackages] = strdup(a_pkgInst);
	if (thisZonePackages[numThisZonePackages] == (char *)NULL) {
		progerr(ERR_MEMORY, errno);
		quit(99);
	}

	numThisZonePackages++;

	/* make sure end of the list is properly terminated */

	thisZonePackages[numThisZonePackages] = (char *)NULL;

	/* exit debugging info */

	echoDebug(DBG_PKGOPS_ADD_TZP, numThisZonePackages,
			thisZonePackages[numThisZonePackages-1]);
}

/*
 * Name:	pkgPackageIsThisZone
 * Description:	Determine if the specified package is marked to be installed
 *		in this zone only
 * Arguments:	a_pkgInst - pointer to string representing package name to check
 * Returns:	boolean_t
 *			B_TRUE - the package IS "this zone only"
 *			B_FALSE - the paackage is NOT "this zone only"
 */

boolean_t
pkgPackageIsThisZone(char *a_pkgInst)
{
	int		n;

	/* entry assertions */

	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/*
	 * see if this package is in the "this zone only" list
	 */

	for (n = 0; n < numThisZonePackages; n++) {
		if (strcmp(a_pkgInst, thisZonePackages[n]) == 0) {
			echoDebug(DBG_PKGOPS_IS_THISZONE, a_pkgInst);
			return (B_TRUE);
		}
	}

	/* path is not in "this zone only" list */

	echoDebug(DBG_PKGOPS_IS_NOT_THISZONE, a_pkgInst);

	return (B_FALSE);
}

/*
 * Name:	pkgLocateHighestInst
 * Description:	Locate the highest installed instance of a package
 * Arguments:	r_path - [RO, *RW] - (char *)
 *			Pointer to buffer where the full path to the top level
 *			directory containing the latest instance of the
 *			specified package is located is placed.
 *		r_pathLen - [RO, *RO] - (int)
 *			Integer representing the size of r_path in bytes.
 *		r_pkgInst - [RO, *RW] - (char *)
 *			Pointer to buffer where the package instance name of the
 *			latest instance of the specified package is placed.
 *		r_pkgInstLen - [RO, *RO] - (int)
 *			Integer representing the size of r_pkgInst in bytes.
 *		a_rootPath - [RO, *RO] - (char *)
 *			Pointer to string representing the root path to look
 *			for the latest instance of the specified package.
 *		a_pkgInst - [RO, *RO] - (char *)
 *			Pointer to string representing the name of the package
 *			to locate the latest installed instance of.
 */

void
pkgLocateHighestInst(char *r_path, int r_pathLen, char *r_pkgInst,
	int r_pkgInstLen, char *a_rootPath, char *a_pkgInst)
{
	char		pkgInstPath[PATH_MAX] = {'\0'};
	char		pkgWild[PKGSIZ+1] = {'\0'};
	char		pkgName[PKGSIZ+1] = {'\0'};
	int		npkgs;
	struct pkginfo	*pinf = (struct pkginfo *)NULL;

	/* entry assertions */

	assert(r_path != (char *)NULL);
	assert(r_pathLen > 0);
	assert(r_pkgInst != (char *)NULL);
	assert(r_pkgInstLen > 0);
	assert(a_pkgInst != (char *)NULL);
	assert(*a_pkgInst != '\0');

	/* normalize root path */

	if ((a_rootPath == (char *)NULL) || (strcmp(a_rootPath, "/") == 0)) {
		a_rootPath = "";
	}

	/* construct path to package repository directory (eg. /var/sadm/pkg) */

	(void) snprintf(pkgInstPath, sizeof (pkgInstPath), "%s%s", a_rootPath,
		PKGLOC);

	/* entry debugging info */

	echoDebug(DBG_PKGOPS_LOCHIGH_ENTRY);
	echoDebug(DBG_PKGOPS_LOCHIGH_ARGS, pkgInstPath, a_pkgInst);

	/* reset returned path/package instance so both ares empty */

	*r_path = '\0';
	*r_pkgInst = '\0';

	/* remove any architecture extension */

	pkgstrGetToken_r((char *)NULL, a_pkgInst, 0, ".",
		pkgName, sizeof (pkgName));

	/* make sure that the package name is valid and can be wild carded */

	if (pkgnmchk(pkgName, NULL, 0) || strchr(pkgName, '.')) {
		progerr(ERR_PKGOPS_LOCHIGH_BAD_PKGNAME, pkgName);
		quit(99);
	}

	/* create wild card specification for this package instance */

	(void) snprintf(pkgWild, sizeof (pkgWild), "%s.*", pkgName);

	echoDebug(DBG_PKGOPS_LOCHIGH_WILDCARD, pkgName, pkgWild);

	/*
	 * inspect the system to determine if any instances of the
	 * package being installed already exist on the system
	 */

	for (npkgs = 0; ; npkgs++) {
		char	*savePkgdir;
		int	r;

		/* allocate new pinfo structure for use in the pkginfo call */

		pinf = _pkginfoFactory();

		/*
		 * lookup the specified package; the first call will cause the
		 * pkgdir directory to be opened - it will be closed when the
		 * end of directory is read and pkginfo() returns != 0. You must
		 * cycle through all instances until pkginfo() returns != 0.
		 * NOTE: pkginfo() requires the global variable 'pkgdir' be set
		 * to the package installed directory (<root>/var/sadm/pkg).
		 */

		savePkgdir = pkgdir;
		pkgdir = pkgInstPath;

		r = pkginfo(pinf, pkgWild, NULL, NULL);

		pkgdir = savePkgdir;

		echoDebug(DBG_PKGOPS_PKGINFO_RETURNED, pkgName, r);

		/* break out of loop of no package found */

		if (r != 0) {
			pkginfoFree(&pinf);
			break;
		}

		echoDebug(DBG_PKGOPS_LOCHIGH_INSTANCE, npkgs,
			pinf->pkginst ? pinf->pkginst : "",
			pinf->name ? pinf->name : "",
			pinf->arch ? pinf->arch : "",
			pinf->version ? pinf->version : "",
			pinf->vendor ? pinf->vendor : "",
			pinf->basedir ? pinf->basedir : "",
			pinf->catg ? pinf->catg : "",
			pinf->status);

		/* save path/instance name for this instance found */

		(void) strlcpy(r_pkgInst, pinf->pkginst, r_pkgInstLen);
		pkgstrPrintf_r(r_path, r_pathLen, "%s%s/%s", a_rootPath,
			PKGLOC, pinf->pkginst);

		pkginfoFree(&pinf);
	}

	echoDebug(DBG_PKGOPS_LOCHIGH_RETURN, npkgs, r_pkgInst, r_path);
}

/*
 * Name:	pkgTestInstalled
 * Description:	determine if package is installed at specified root path
 * Arguments:	a_packageName - name of package to test
 * 		a_rootPath - root path of alternative root to test
 * Returns:	B_TRUE - package is installed
 *		B_FALSE - package is not installed
 */

boolean_t
pkgTestInstalled(char *a_packageName, char *a_rootPath)
{
	char	cmd[MAXPATHLEN+1];
	int	rc;

	/* entry assertions */

	assert(a_packageName != NULL);
	assert(*a_packageName != '\0');
	assert(a_rootPath != NULL);
	assert(*a_rootPath != '\0');

	/* entry debugging info */

	echoDebug(DBG_PKG_TEST_EXISTENCE, a_packageName, a_rootPath);

	/*
	 * create pkginfo command to execute:
	 * /usr/bin/pkginfo -q <packageName>
	 */
	(void) snprintf(cmd, sizeof (cmd),
		"%s -q %s", PKGINFO_CMD, a_packageName);

	/* execute command */

	rc = system(cmd);

	/* return success if pkginfo returns "0" */

	if (rc == 0) {
		echoDebug(DBG_PKG_INSTALLED, a_packageName, a_rootPath);
		return (B_TRUE);
	}

	/* package not installed */

	echoDebug(DBG_PKG_NOT_INSTALLED, a_packageName, a_rootPath);

	return (B_FALSE);
}

/*
 * *****************************************************************************
 * static internal (private) functions
 * *****************************************************************************
 */

static void
_pkginfoInit(struct pkginfo *a_info)
{
	/* entry assertions */

	assert(a_info != (struct pkginfo *)NULL);

	/* free previously allocated space */

	if (a_info->pkginst) {
		free(a_info->pkginst);
		if (a_info->arch)
			free(a_info->arch);
		if (a_info->version)
			free(a_info->version);
		if (a_info->basedir)
			free(a_info->basedir);
		if (a_info->name)
			free(a_info->name);
		if (a_info->vendor)
			free(a_info->vendor);
		if (a_info->catg)
			free(a_info->catg);
	}

	a_info->pkginst = NULL;
	a_info->arch = a_info->version = NULL;
	a_info->basedir = a_info->name = NULL;
	a_info->vendor = a_info->catg = NULL;
	a_info->status = PI_UNKNOWN;
}

static struct pkginfo *
_pkginfoFactory(void)
{
	struct pkginfo *pinf;

	pinf = (struct pkginfo *)calloc(1, sizeof (struct pkginfo));
	if (pinf == (struct pkginfo *)NULL) {
		progerr(ERR_MEM);
		exit(1);
	}

	_pkginfoInit(pinf);
	return (pinf);
}
