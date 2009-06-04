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

#ifndef _DBTABLES_H
#define _DBTABLES_H


#ifdef  __cplusplus
extern "C" {
#endif /* __cplusplus */

#define	TBL_HDR "create table"
#define	TBL_TRL "on conflict replace"

/*
 * The patch contents table. This table is used for storing patch package
 * related file object information and is similar to the pkg contents table.
 * This table is for future use in allowing FS object checking instead or
 * in lieu of package level chacking.
 *
 * The pkgs column is not normalized. This is due to trying to represent the
 * data the same way as the legacy patch system does. The column should be
 * normalized when the Patch Architecture is re-designed.
 *
 * Note that path is given the maximum length of /usr/include/limits.h
 * defined PATH_MAX.
 */

const char *pcPatchContents = {
	"CREATE TABLE patch_contents_table (" \
	"patch CHAR(16) NOT NULL," \
	"path VARCHAR(1024) NOT NULL," \
	"ftype CHAR(1) NOT NULL," \
	"class CHAR(32) NOT NULL," \
	"mode CHAR(5) NOT NULL," \
	"owner CHAR(32) NOT NULL," \
	"grp CHAR(32) NOT NULL," \
	"major CHAR(32) NOT NULL," \
	"minor CHAR(32) NOT NULL," \
	"sz CHAR(32) NOT NULL," \
	"sum CHAR(32) NOT NULL," \
	"modtime CHAR(32) NOT NULL," \
	"pkgstatus CHAR(1) NOT NULL," \
	"pkgs VARCHAR(4096) NOT NULL," \
	"PRIMARY KEY(patch)" \
	"ON CONFLICT REPLACE);"};

/*
 * The patch table. This table represents all patch meta data needed
 * to handle dependency checking during the installation and removal of
 * a patch.
 */

const char *pcPatchPkg = {
	"CREATE TABLE patch_pkg_table (" \
	"patch CHAR(16) NOT NULL," \
	"pkg VARCHAR(64) NOT NULL," \
	"PRIMARY KEY(patch, pkg)" \
	"ON CONFLICT REPLACE);"};

/* This table represents the informatin associated with an installed patch */

const char *pcPatch = {
	"CREATE TABLE patch_table (" \
	"patch CHAR(16) NOT NULL," \
	"rev CHAR(8) NOT NULL," \
	"bcode CHAR(12) NOT NULL," \
	"sep CHAR(1) NOT NULL," \
	"obs VARCHAR(1024) NULL," \
	"reqs VARCHAR(1024) NULL," \
	"incs VARCHAR(1024) NULL," \
	"backout VARCHAR(256) NULL," \
	"time TIMESTAMP(64) NOT NULL," \
	"pkgs VARCHAR(1024) NOT NULL," \
	"PRIMARY KEY(patch)" \
	"ON CONFLICT REPLACE);"};

/* This table represents the patchinfo file in its entirety */

const char *pcPatchinfo = {
	"CREATE TABLE patchinfo_table (" \
	"patch CHAR(16) NOT NULL," \
	"key CHAR(256) NOT NULL," \
	"value CHAR(256) NOT NULL," \
	"PRIMARY KEY(patch)" \
	"ON CONFLICT REPLACE);"};

/*
 * Since it is read in as a whole - column by column
 * and processed by legacy code which expects all of
 * the data, all the time, it is not useful to separate
 * the columns into separate tables via normalization.
 * In effect, each column is logically one data unit,
 * even if it comprises several distinct values (ie. pkgs).
 *
 * Note that path is given the maximum length of /usr/include/limits.h
 * defined PATH_MAX.
 */

const char *pcContents =
	"CREATE TABLE pkg_table (" \
	"path VARCHAR(1024) NOT NULL," \
	"ftype CHAR(1) NOT NULL," \
	"class CHAR(32) NOT NULL," \
	"mode CHAR(5) DEFAULT '-1'," \
	"owner CHAR(32) DEFAULT '?'," \
	"grp CHAR(32) DEFAULT '?'," \
	"major CHAR(32) DEFAULT '-1'," \
	"minor CHAR(32) DEFAULT '-1'," \
	"sz CHAR(32) DEFAULT '-1'," \
	"sum CHAR(32) DEFAULT '-1'," \
	"modtime CHAR(32) DEFAULT '-1'," \
	"pkgstatus CHAR(1) DEFAULT '0'," \
	"pkgs VARCHAR(4096) NOT NULL," \
	"PRIMARY KEY(path)" \
	" ON CONFLICT REPLACE);";

/*
 * It is necessary to save off the dependency comments so that
 * they can be regenerated in the depend output.  This is due
 * to there being copyright information in the depend files
 * which cannot be tossed.  This is a logically distinct table
 * to the depend data since it includes none of the other data
 * used in that table.
 */

const char *pcDepComments =
	"CREATE TABLE depcomment_table (" \
	"pkg     VARCHAR(64) NOT NULL, " \
	"comment VARCHAR(800) NOT NULL, " \
	"seqno   INT NOT NULL, " \
	"PRIMARY KEY(pkg) " \
	"ON CONFLICT REPLACE);";

/* This is the table which contains the pkginfo data. */

const char *pcSQL_pkginfo =
	"CREATE TABLE pkginfo_table (" \
	"pkg VARCHAR(80) NOT NULL, " \
	"param VARCHAR(128) NOT NULL, " \
	"value VARCHAR(128) NOT NULL, "\
	"seqno INT NOT NULL, " \
	"PRIMARY KEY(pkg, param) " \
	"ON CONFLICT REPLACE);";

/*
 * This is the table which contains the depenency data.
 * Note that the 'name' data is optional.  Further, note
 * that platform information (version & architecture)
 * have been separated off into a separate table.
 */

const char *pcSQL_depend =
	"CREATE TABLE depend_table (" \
	"pkg     VARCHAR(64) NOT NULL, " \
	"pkgdep  VARCHAR(64) NOT NULL, " \
	"type    CHAR(1) NOT NULL, "\
	"name    VARCHAR(128) NULL, " \
	"seqno INT NOT NULL, " \
	"PRIMARY KEY(pkg, pkgdep) " \
	"ON CONFLICT REPLACE);";

/*
 * This table includes data which is specifically related to
 * an individual dependency.  The version and arch info are
 * related to a specific pkg/pkgdep pair.  It is possible to
 * list more than one version/arch pair for a pkg/pkgdep
 * pair using the definition below.
 */

const char *pcSQL_platform =
	"CREATE TABLE depplatform_table ( " \
	"pkg      VARCHAR(64) NOT NULL " \
	"  REFERENCES depend_table(pkg), " \
	"pkgdep   VARCHAR(64) NOT NULL " \
	"  REFERENCES depend_table(pkgdep), " \
	"version  VARCHAR(32) NOT NULL, " \
	"arch     VARCHAR(32) NOT NULL, " \
	"seqno INT NOT NULL, " \
	"PRIMARY KEY (pkg, pkgdep, version, arch) " \
	"ON CONFLICT REPLACE);";

#ifdef  __cplusplus
}
#endif /* __cplusplus */

#endif /* _DBTABLES_H */
