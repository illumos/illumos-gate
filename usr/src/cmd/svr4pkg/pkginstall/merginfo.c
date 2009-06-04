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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */
/* All Rights Reserved */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <locale.h>
#include <libintl.h>
#include <errno.h>
#include "pkglib.h"
#include "install.h"
#include "libadm.h"
#include "libinst.h"
#include "pkginstall.h"
#include "messages.h"

extern char	instdir[], pkgbin[], pkgloc[], savlog[], *pkginst, **environ;
extern char	saveSpoolInstallDir[];
extern char	pkgsav[];	/* pkginstall/main.c */
static char 	*infoloc;

/*
 * flag definitions for each entry in table
 */

typedef unsigned int TBL_FLAG_T;

/* no flag set */
#define	FLAG_NONE	((TBL_FLAG_T)0x0000)

/* exclude this attribute if found */
#define	FLAG_EXCLUDE	((TBL_FLAG_T)0x0001)

/* this attribute must not change if found */
#define	FLAG_IDENTICAL	((TBL_FLAG_T)0x0002)

/*
 * macro to generate an entry in the table:
 *	TBL_ENTRY("PKGINFO_ATTRIBUTE=", FLAG_XXX)
 * where:
 *	"PKGINFO_ATTRIBUTE=" is the attribute to look for
 *	FLAG_XXX is the action to perform when the attribute is found
 */

#define	TBL_ENTRY(_Y_, _F_)	{ (_Y_), ((sizeof ((_Y_)))-1), (_F_) }

/*
 * table containing attributes that require special handling
 */

struct _namelist {
	char		*_nlName;	/* attribute name */
	int		_nlLen;		/* attribute length */
	TBL_FLAG_T	_nlFlag;	/* attribute disposition flag */
};

typedef struct _namelist NAMELIST_T;

/*
 * These are attributes to be acted on in some way when a pkginfo file is
 * merged. This table MUST be in alphabetical order because it is searched
 * using a binary search algorithm.
 */

static NAMELIST_T attrTbl[] = {
	TBL_ENTRY("BASEDIR=",			FLAG_EXCLUDE),
	TBL_ENTRY("CLASSES=",			FLAG_EXCLUDE),
	TBL_ENTRY("CLIENT_BASEDIR=",		FLAG_EXCLUDE),
	TBL_ENTRY("INST_DATADIR=",		FLAG_EXCLUDE),
	TBL_ENTRY("PKG_CAS_PASSRELATIVE=",	FLAG_EXCLUDE),
	TBL_ENTRY("PKG_DST_QKVERIFY=",		FLAG_EXCLUDE),
	TBL_ENTRY("PKG_INIT_INSTALL=",		FLAG_EXCLUDE),
	TBL_ENTRY("PKG_INSTALL_ROOT=",		FLAG_EXCLUDE),
	TBL_ENTRY("PKG_SRC_NOVERIFY=",		FLAG_EXCLUDE),
	TBL_ENTRY("SUNW_PKGCOND_GLOBAL_DATA=",	FLAG_EXCLUDE),
	TBL_ENTRY("SUNW_PKG_ALLZONES=",		FLAG_IDENTICAL),
	TBL_ENTRY("SUNW_PKG_DIR=",		FLAG_EXCLUDE),
	TBL_ENTRY("SUNW_PKG_HOLLOW=",		FLAG_IDENTICAL),
	TBL_ENTRY("SUNW_PKG_INSTALL_ZONENAME=",	FLAG_EXCLUDE),
	TBL_ENTRY("SUNW_PKG_THISZONE=",		FLAG_IDENTICAL),
};

#define	ATTRTBL_SIZE	(sizeof (attrTbl) / sizeof (NAMELIST_T))

/*
 * While pkgsav has to be set up with reference to the server for package
 * scripts, it has to be client-relative in the pkginfo file. This function
 * is used to set the client-relative value for use in the pkginfo file.
 */
void
set_infoloc(char *path)
{
	if (path && *path) {
		if (is_an_inst_root()) {
			/* Strip the server portion of the path. */
			infoloc = orig_path(path);
		} else {
			infoloc = strdup(path);
		}
	}
}

void
merginfo(struct cl_attr **pclass, int install_from_pspool)
{
	DIR		*pdirfp;
	FILE		*fp;
	FILE		*pkginfoFP;
	char		path[PATH_MAX];
	char		cmd[PATH_MAX];
	char		pkginfoPath[PATH_MAX];
	char		temp[PATH_MAX];
	int		i;
	int		nc;
	int		out;

	/* remove savelog from previous attempts */

	(void) unlink(savlog);

	/*
	 * create path to appropriate pkginfo file for the package that is
	 * already installed - is_spool_create() will be set (!= 0) if the
	 * -t option is presented to pkginstall - the -t option is used to
	 * disable save spool area creation; do not spool any partial package
	 * contents, that is, suppress the creation and population of the
	 * package save spool area (var/sadm/pkg/PKG/save/pspool/PKG). This
	 * option is set only when a non-global zone is being created.
	 */

	if (is_spool_create() == 0) {
		/*
		 * normal package install (not a non-global zone install);
		 * use the standard installed pkginfo file for this package:
		 * --> /var/sadm/pkg/PKGINST/pkginfo
		 * as the source pkginfo file to scan.
		 */
		i = snprintf(pkginfoPath, sizeof (pkginfoPath),
			"%s/var/sadm/pkg/%s/%s",
			((get_inst_root()) &&
			(strcmp(get_inst_root(), "/") != 0)) ?
			get_inst_root() : "", pkginst,
			PKGINFO);
		if (i > sizeof (pkginfoPath)) {
			progerr(ERR_CREATE_PATH_2,
				((get_inst_root()) &&
				(strcmp(get_inst_root(), "/") != 0)) ?
				get_inst_root() : "/",
				pkginst);
			quit(1);
		}
	} else {
		/*
		 * non-global zone installation - use the "saved" pspool
		 * pkginfo file in the global zone for this package:
		 * --> /var/sadm/install/PKG/save/pspool/PKG/pkginfo
		 * as the source pkginfo file to scan.
		 */
		i = snprintf(pkginfoPath, sizeof (pkginfoPath), "%s/%s",
			saveSpoolInstallDir, PKGINFO);
		if (i > sizeof (pkginfoPath)) {
			progerr(ERR_CREATE_PATH_2,
				saveSpoolInstallDir, PKGINFO);
			quit(1);
		}
	}

	i = snprintf(path, PATH_MAX, "%s/%s", pkgloc, PKGINFO);
	if (i > PATH_MAX) {
		progerr(ERR_CREATE_PATH_2, pkgloc, PKGINFO);
		quit(1);
	}

	/* entry debugging info */

	echoDebug(DBG_MERGINFO_ENTRY,
		instdir ? instdir : "??",
		((get_inst_root()) &&
		(strcmp(get_inst_root(), "/") != 0)) ?
		get_inst_root() : "??",
		saveSpoolInstallDir ? saveSpoolInstallDir : "??",
		pkgloc ? pkgloc : "??",	is_spool_create(),
		get_info_basedir() ? get_info_basedir() : "??",
		pkginfoPath, path);

	/*
	 * open the pkginfo file:
	 * if the source pkginfo file to check is the same as the merged one
	 * (e.g. /var/sadm/pkg/PKGINST/pkginfo) then do not open the source
	 * pkginfo file to "verify"
	 */

	if (strcmp(pkginfoPath, path) == 0) {
		pkginfoFP = (FILE *)NULL;
		echoDebug(DBG_MERGINFO_SAME, path);
	} else {
		echoDebug(DBG_MERGINFO_DIFFERENT, pkginfoPath, path);
		pkginfoFP = fopen(pkginfoPath, "r");

		if (pkginfoFP == (FILE *)NULL) {
			echoDebug(ERR_NO_PKG_INFOFILE, pkginst, pkginfoPath,
				strerror(errno));
		}
	}

	/*
	 * output packaging environment to create a pkginfo file in pkgloc[]
	 */

	if ((fp = fopen(path, "w")) == NULL) {
		progerr(ERR_CANNOT_OPEN_FOR_WRITING, path, strerror(errno));
		quit(99);
	}

	/*
	 * output CLASSES attribute
	 */

	out = 0;
	(void) fputs("CLASSES=", fp);
	if (pclass) {
		(void) fputs(pclass[0]->name, fp);
		out++;
		for (i = 1; pclass[i]; i++) {
			(void) putc(' ', fp);
			(void) fputs(pclass[i]->name, fp);
			out++;
		}
	}
	nc = cl_getn();
	for (i = 0; i < nc; i++) {
		int found = 0;

		if (pclass) {
			int	j;

			for (j = 0; pclass[j]; ++j) {
				if (cl_nam(i) != NULL &&
					strcmp(cl_nam(i),
					pclass[j]->name) == 0) {
					found++;
					break;
				}
			}
		}
		if (!found) {
			if (out > 0) {
				(void) putc(' ', fp);
			}
			(void) fputs(cl_nam(i), fp);
			out++;
		}
	}
	(void) putc('\n', fp);

	/*
	 * NOTE : BASEDIR below is relative to the machine that
	 * *runs* the package. If there's an install root, this
	 * is actually the CLIENT_BASEDIR wrt the machine
	 * doing the pkgadd'ing here. -- JST
	 */

	if (is_a_basedir()) {
		static char	*txs1 = "BASEDIR=";

		(void) fputs(txs1, fp);
		(void) fputs(get_info_basedir(), fp);
		(void) putc('\n', fp);
	} else {
		(void) fputs("BASEDIR=/", fp);
		(void) putc('\n', fp);
	}

	/*
	 * output all other environment attributes except those which
	 * are relevant only to install.
	 */

	for (i = 0; environ[i] != (char *)NULL; i++) {
		char	*ep = environ[i];
		int	attrPos = -1;
		int	incr = (ATTRTBL_SIZE >> 1)+1;	/* searches possible */
		int	pos = ATTRTBL_SIZE >> 1;	/* start in middle */
		NAMELIST_T	*pp = (NAMELIST_T *)NULL;

		/*
		 * find this attribute in the table - accept the attribute if it
		 * is outside of the bounds of the table; otherwise, do a binary
		 * search looking for this attribute.
		 */

		if (strncmp(ep, attrTbl[0]._nlName, attrTbl[0]._nlLen) < 0) {

			/* entry < first entry in attribute table */

			echoDebug(DBG_MERGINFO_LESS_THAN, ep,
				attrTbl[0]._nlName);

		} else if (strncmp(ep, attrTbl[ATTRTBL_SIZE-1]._nlName,
				attrTbl[ATTRTBL_SIZE-1]._nlLen) > 0) {

			/* entry > last entry in attribute table */

			echoDebug(DBG_MERGINFO_GREATER_THAN, ep,
				attrTbl[ATTRTBL_SIZE-1]._nlName);

		} else {
			/* first entry < entry < last entry in table: search */

			echoDebug(DBG_MERGINFO_SEARCHING, ep,
				attrTbl[0]._nlName,
				attrTbl[ATTRTBL_SIZE-1]._nlName);

			while (incr > 0) {	/* while possible to divide */
				int	r;

				pp = &attrTbl[pos];

				/* compare current attr with this table entry */
				r = strncmp(pp->_nlName, ep, pp->_nlLen);

				/* break out of loop if match */
				if (r == 0) {
					/* save location/break if match found */
					attrPos = pos;
					break;
				}

				/* no match search to next/prev half */
				incr = incr >> 1;
				pos += (r < 0) ? incr : -incr;
				continue;
			}
		}

		/* handle excluded attribute found */

		if ((attrPos >= 0) && (pp->_nlFlag == FLAG_EXCLUDE)) {
			/* attribute is excluded */
			echoDebug(DBG_MERGINFO_EXCLUDING, ep);
			continue;
		}

		/* handle fixed attribute found */

		if ((pkginfoFP != (FILE *)NULL) && (attrPos >= 0) &&
			(pp->_nlFlag == FLAG_IDENTICAL)) {
			/* attribute must not change */

			char	*src = ep+pp->_nlLen;
			char	*trg;
			char	theAttr[PATH_MAX+1];

			/* isolate attribute name only without '=' at end */

			(void) strncpy(theAttr, pp->_nlName, pp->_nlLen-1);
			theAttr[pp->_nlLen-1] = '\0';

			/* lookup attribute in installed package pkginfo file */

			rewind(pkginfoFP);
			trg = fpkgparam(pkginfoFP, theAttr);

			echoDebug(DBG_MERGINFO_ATTRCOMP, theAttr,
				trg ? trg : "");

			/* if target not found attribute is being added */

			if (trg == (char *)NULL) {
				progerr(ERR_PKGINFO_ATTR_ADDED, pkginst, ep);
				quit(1);
			}

			/* error if two values are not the same */

			if (strcmp(src, trg) != 0) {
				progerr(ERR_PKGINFO_ATTR_CHANGED, pkginst,
					theAttr, src, trg);
				quit(1);
			}
		}

		/* attribute not excluded/has not changed - process */

		if ((strncmp(ep, "PKGSAV=", 7) == 0)) {
			(void) fputs("PKGSAV=", fp);
			(void) fputs(infoloc, fp);
			(void) putc('/', fp);
			(void) fputs(pkginst, fp);
			(void) fputs("/save\n", fp);
			continue;
		}

		if ((strncmp(ep, "UPDATE=", 7) == 0) &&
				install_from_pspool != 0 &&
				!isPatchUpdate() &&
				!isUpdate()) {
			continue;
		}

		echoDebug(DBG_MERGINFO_FINAL, ep);

		(void) fputs(ep, fp);
		(void) putc('\n', fp);
	}

	(void) fclose(fp);
	(void) fclose(pkginfoFP);

	/*
	 * copy all packaging scripts to appropriate directory
	 */

	i = snprintf(path, PATH_MAX, "%s/install", instdir);
	if (i > PATH_MAX) {
		progerr(ERR_CREATE_PATH_2, instdir, "/install");
		quit(1);
	}

	if ((pdirfp = opendir(path)) != NULL) {
		struct dirent	*dp;

		while ((dp = readdir(pdirfp)) != NULL) {
			if (dp->d_name[0] == '.')
				continue;

			i = snprintf(path, PATH_MAX, "%s/install/%s",
					instdir, dp->d_name);
			if (i > PATH_MAX) {
				progerr(ERR_CREATE_PATH_3, instdir, "/install/",
					dp->d_name);
				quit(1);
			}

			i = snprintf(temp, PATH_MAX, "%s/%s", pkgbin,
					dp->d_name);
			if (i > PATH_MAX) {
				progerr(ERR_CREATE_PATH_2, pkgbin, dp->d_name);
				quit(1);
			}

			if (cppath(MODE_SRC|DIR_DISPLAY, path, temp, 0644)) {
			    progerr(ERR_CANNOT_COPY, dp->d_name, pkgbin);
				quit(99);
			}
		}
		(void) closedir(pdirfp);
	}

	/*
	 * copy all packaging scripts to the partial spool directory
	 */

	if (!is_spool_create()) {
		/* packages are being spooled to ../save/pspool/.. */
		i = snprintf(path, PATH_MAX, "%s/install", instdir);
		if (i > PATH_MAX) {
			progerr(ERR_CREATE_PATH_2, instdir, "/install");
			quit(1);
		}

		if (((pdirfp = opendir(path)) != NULL) &&
			!isPatchUpdate()) {
			struct dirent	*dp;


			while ((dp = readdir(pdirfp)) != NULL) {
				if (dp->d_name[0] == '.')
					continue;
				/*
				 * Don't copy i.none since if it exists it
				 * contains Class Archive Format procedure
				 * for installing archives. Only Directory
				 * Format packages can exist
				 * in a global spooled area.
				 */
				if (strcmp(dp->d_name, "i.none") == 0)
					continue;

				i = snprintf(path, PATH_MAX, "%s/install/%s",
						instdir, dp->d_name);

				if (i > PATH_MAX) {
					progerr(ERR_CREATE_PATH_3, instdir,
						"/install/", dp->d_name);
					quit(1);
				}

				i = snprintf(temp, PATH_MAX, "%s/install/%s",
						saveSpoolInstallDir,
						dp->d_name);

				if (i > PATH_MAX) {
					progerr(ERR_CREATE_PATH_3,
						saveSpoolInstallDir,
						"/install/", dp->d_name);
					quit(1);
				}

				if (cppath(MODE_SRC, path, temp, 0644)) {
					progerr(ERR_CANNOT_COPY, path, temp);
					(void) closedir(pdirfp);
					quit(99);
				}
			}
			(void) closedir(pdirfp);
		}

		/*
		 * Now copy the original pkginfo and pkgmap files from the
		 * installing package to the spooled directory.
		 */

		i = snprintf(path, sizeof (path), "%s/%s", instdir, PKGINFO);
		if (i > sizeof (path)) {
			progerr(ERR_CREATE_PATH_2, instdir, PKGINFO);
			quit(1);
		}

		i = snprintf(temp, sizeof (temp), "%s/%s",
				saveSpoolInstallDir, PKGINFO);
		if (i > sizeof (temp)) {
			progerr(ERR_CREATE_PATH_2, saveSpoolInstallDir,
				PKGINFO);
			quit(1);
		}

		if (cppath(MODE_SRC, path, temp, 0644)) {
			progerr(ERR_CANNOT_COPY, path, temp);
			quit(99);
		}

		/*
		 * Only want to copy the FCS pkgmap if this is not a
		 * patch installation.
		 */

		if (!isPatchUpdate()) {
			i = snprintf(path, sizeof (path), "%s/pkgmap", instdir);
			if (i > sizeof (path)) {
				progerr(ERR_CREATE_PATH_2, instdir, "pkgmap");
				quit(1);
			}

			i = snprintf(temp, sizeof (temp), "%s/pkgmap",
				saveSpoolInstallDir);
			if (i > sizeof (path)) {
				progerr(ERR_CREATE_PATH_2, saveSpoolInstallDir,
					"pkgmap");
				quit(1);
			}

			if (cppath(MODE_SRC, path, temp, 0644)) {
				progerr(ERR_CANNOT_COPY, path, temp);
				quit(99);
			}
		}
	}

	/*
	 * If we are installing from a spool directory
	 * copy the save directory from it, it may have
	 * been patched. Duplicate it only if this
	 * installation isn't an update and is not to
	 * an alternate root.
	 */
	if (strstr(instdir, "pspool") != NULL) {
		struct stat status;

		i = snprintf(path, sizeof (path), "%s/save", instdir);
		if (i > sizeof (path)) {
			progerr(ERR_CREATE_PATH_2, instdir, "save");
			quit(1);
		}

		if ((stat(path, &status) == 0) &&
				(status.st_mode & S_IFDIR) &&
				!isPatchUpdate()) {
			i = snprintf(cmd, sizeof (cmd), "cp -pr %s/* %s",
					path, pkgsav);
			if (i > sizeof (cmd)) {
				progerr(ERR_SNPRINTF, "cp -pr %s/* %s");
				quit(1);
			}

			if (system(cmd)) {
				progerr(ERR_PKGBINCP, path, pkgsav);
				quit(99);
			}
		}
	}
}
