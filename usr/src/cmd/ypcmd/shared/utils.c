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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T */
/*	  All Rights Reserved   */

/*
 * Portions of this source code were derived from Berkeley
 * under license from the Regents of the University of
 * California.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DESCRIPTION:	This file contains various functions used by more than one NIS
 *		components. A lot of this code started off in ypxfr and then
 *		got used by other components. Some of it has become a little
 *		'quirky' and should probably be re-worked.
 */

#include <unistd.h>
#include <syslog.h>
#include <sys/mman.h>
#include <thread.h>
#include <synch.h>
#include <stdarg.h>
#include <ndbm.h>
#include "../ypsym.h"
#include "../ypdefs.h"
#include "shim.h"

USE_DBM

/*
 * Globals
 */

/*
 * DESCRIPTION : Utility functions used by everything.
 */
bool check_map_existence(char *);
void logprintf2(char *format, ...);
extern bool ypcheck_map_existence_yptol();

/*
 * This checks to see if the source map files exist, then renames them to the
 * target names.  This is a boolean function.  The file names from.pag and
 * from.dir will be changed to to.pag and to.dir in the success case.
 *
 * Note:  If the second of the two renames fails, yprename_map will try to
 * un-rename the first pair, and leave the world in the state it was on entry.
 * This might fail, too, though...
 *
 * GIVEN :	Name of map to copy from
 *		Name of map to copy to
 *		Flag indicating if map is secure.
 */
bool
rename_map(from, to, secure_map)
	char *from;
	char *to;
	bool_t secure_map;
{
	char fromfile[MAXNAMLEN + 1];
	char tofile[MAXNAMLEN + 1];
	char savefile[MAXNAMLEN + 1];

	if (!from || !to) {
		return (FALSE);
	}

	if (!check_map_existence(from)) {
		return (FALSE);
	}

	(void) strcpy(fromfile, from);
	(void) strcat(fromfile, dbm_pag);
	(void) strcpy(tofile, to);
	(void) strcat(tofile, dbm_pag);

	if (rename(fromfile, tofile)) {
		logprintf2("Can't mv %s to %s.\n", fromfile,
		    tofile);
		return (FALSE);
	}

	(void) strcpy(savefile, tofile);
	(void) strcpy(fromfile, from);
	(void) strcat(fromfile, dbm_dir);
	(void) strcpy(tofile, to);
	(void) strcat(tofile, dbm_dir);

	if (rename(fromfile, tofile)) {
		logprintf2("Can't mv %s to %s.\n", fromfile,
		    tofile);
		(void) strcpy(fromfile, from);
		(void) strcat(fromfile, dbm_pag);
		(void) strcpy(tofile, to);
		(void) strcat(tofile, dbm_pag);

		if (rename(tofile, fromfile)) {
			logprintf2(
			    "Can't recover from rename failure.\n");
			return (FALSE);
		}

		return (FALSE);
	}

	if (!secure_map) {
		chmod(savefile, 0644);
		chmod(tofile, 0644);
	}

	return (TRUE);
}

/*
 * Function :	delete_map()
 *
 * Description:	Deletes a map
 *
 * Given :	Map name
 *
 * Return :	TRUE = Map deleted
 *		FALSE = Map not completly deleted
 */
bool
delete_map(name)
	char *name;
{
	char fromfile[MAXNAMLEN + 1];

	if (!name) {
		return (FALSE);
	}

	if (!check_map_existence(name)) {
		/* Already gone */
		return (TRUE);
	}

	(void) strcpy(fromfile, name);
	(void) strcat(fromfile, dbm_pag);

	if (unlink(fromfile)) {
		logprintf2("Can't unlink %s.\n", fromfile);
		return (FALSE);
	}

	(void) strcpy(fromfile, name);
	(void) strcat(fromfile, dbm_dir);

	if (unlink(fromfile)) {
		logprintf2("Can't unlink %s.\n", fromfile);
		return (FALSE);
	}

	return (TRUE);
}

/*
 * This performs an existence check on the dbm data base files <pname>.pag and
 * <pname>.dir.
 */
bool
check_map_existence(pname)
	char *pname;
{
	char dbfile[MAXNAMLEN + 1];
	struct stat64 filestat;
	int len;

	if (!pname || ((len = strlen(pname)) == 0) ||
	    (len + 5) > (MAXNAMLEN + 1)) {
		return (FALSE);
	}

	errno = 0;
	(void) strcpy(dbfile, pname);
	(void) strcat(dbfile, dbm_dir);

	if (stat64(dbfile, &filestat) != -1) {
		(void) strcpy(dbfile, pname);
		(void) strcat(dbfile, dbm_pag);

		if (stat64(dbfile, &filestat) != -1) {
			return (TRUE);
		} else {

			if (errno != ENOENT) {
				logprintf2(
				    "Stat error on map file %s.\n",
				    dbfile);
			}

			return (FALSE);
		}

	} else {

		if (errno != ENOENT) {
			logprintf2(
			    "Stat error on map file %s.\n",
			    dbfile);
		}

		return (FALSE);
	}
}

/*
 * FUNCTION :	logprintf2()
 *
 * DESCRIPTION:	The functions in this file were oringinaly shared between
 *		ypxfr and ypserv. On error they called logprintf().
 *		Unfortunatly this had been implemented differently in the two
 *		sources and not at all in some of the NIS components required
 *		for N2L.
 *
 *		This function is simplified version of logprinf() as/when
 *		possible the other error calls should be migrated to use this
 *		common version. If a common set of functionality can be found
 *		this versions should be modified to support it.
 */
void
logprintf2(char *format, ...)
{
	va_list ap;

	va_start(ap, format);

	syslog(LOG_ERR, format, ap);

	va_end(ap);
}

/*
 * This performs an existence check on the dbm data base files <name>.pag and
 * <name>.dir.  pname is a ptr to the filename.  This should be an absolute
 * path.
 * Returns TRUE if the map exists and is accessable; else FALSE.
 *
 * Note:  The file name should be a "base" form, without a file "extension" of
 * .dir or .pag appended.  See ypmkfilename for a function which will generate
 * the name correctly.  Errors in the stat call will be reported at this level,
 * however, the non-existence of a file is not considered an error, and so will
 * not be reported.
 *
 * Calls ypcheck_map_existence_yptol() defined in
 * usr/src/lib/libnisdb/yptol/shim_ancil.c
 */
bool
ypcheck_map_existence(char *pname)
{
	return (ypcheck_map_existence_yptol(pname));
}
