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

#ifndef _SCHEMA_H
#define	_SCHEMA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Various macros (constant strings) containing:
 *
 *  - CREATE TABLE/INDEX/TRIGGER/VIEW SQL
 *  - old versions of schema items that have changed
 *  - SQL to detect the version currently installed in a db
 *  - SQL to upgrade the schema from any older version to the current
 *     - the SQL to install the current version of the schema on a
 *       freshly created db is the SQL used to "upgrade" from "version 0"
 *
 * There is one set of such macros for the cache DB (CACHE_*) and
 * another set for the persistent DB (DB_*).  The macros ending in _SQL
 * are used in arguments to init_db_instance().
 *
 * Schema version detection SQL has the following form:
 *
 * SELECT CASE (SELECT count(*) FROM sqlite_master) WHEN 0 THEN 0 ELSE
 * (CASE (SELECT count(*) FROM sqlite_master WHERE sql = <original schema> ...)
 * WHEN <correct count> THEN 1 ELSE (CASE (<v2 schema>) WHEN ... THEN 2
 * ELSE -1 END) END AS version;
 *
 * That is, check that there is no schema else that the current schema
 * sql matches the original schema, else the next version, ... and
 * return an integer identifying the schema.  Version numbers returned:
 *
 * -1 -> unknown schema  (shouldn't happen)
 *  0 -> no schema       (brand new DB, install latest schema)
 *  1 -> original schema (if != latest, then upgrade)
 *  . -> ...             (if != latest, then upgrade)
 *  n -> latest schema   (nothing to do)
 *
 * Upgrade SQL for the cache DB is simple: drop everything, create
 * latest schema.  This means losing ephemeral mappings, so idmapd must
 * tell the kernel about that in its registration call.
 *
 * Upgrade SQL for the persistent DB is simple: drop the indexes, create
 * temporary tables with the latest schema, insert into those from the
 * old tables (transforming the data in the process), then drop the old
 * tables, create the latest schema, restore the data from the temp.
 * tables and drop the temp tables.
 *
 * Complex, but it avoids all sorts of packaging install/upgrade
 * complexity, requiring reboots on patch.
 *
 * Conventions:
 * - each TABLE/INDEX gets its own macro, and the SQL therein must not
 *   end in a semi-colon (';)
 * - macros are named * TABLE_* for tables, INDEX_* for indexes,
 *   *_VERSION_SQL for SQL for determining version number,
 *   *_UPGRADE_FROM_v<version>_SQL for SQL for upgrading from some
 *   schema, *_LATEST_SQL for SQL for installing the latest schema.
 * - some macros nest expansions of other macros
 *
 * The latest schema has two columns for Windows user/group name in
 * tables where there used to be one.  One of those columns contains the
 * name as it came from the user or from AD, the other is set via a
 * TRIGGER to be the lower-case version of the first, and we always
 * search (and index) by the latter.  This is for case-insensitivity.
 */
#define	TABLE_IDMAP_CACHE_v1 \
	"CREATE TABLE idmap_cache (" \
	"	sidprefix TEXT," \
	"	rid INTEGER," \
	"	windomain TEXT," \
	"	winname TEXT," \
	"	pid INTEGER," \
	"	unixname TEXT," \
	"	is_user INTEGER," \
	"	w2u INTEGER," \
	"	u2w INTEGER," \
	"	expiration INTEGER" \
	")"

#define	TABLE_IDMAP_CACHE_v2 \
	"CREATE TABLE idmap_cache " \
	"(" \
	"	sidprefix TEXT," \
	"	rid INTEGER," \
	"	windomain TEXT," \
	"	canon_winname TEXT," \
	"	winname TEXT," \
	"	pid INTEGER," \
	"	unixname TEXT," \
	"	is_user INTEGER," \
	"	is_wuser INTEGER," \
	"	w2u INTEGER," \
	"	u2w INTEGER," \
	"	expiration INTEGER" \
	")"

#define	TABLE_IDMAP_CACHE \
	"CREATE TABLE idmap_cache " \
	"(" \
	"	sidprefix TEXT," \
	"	rid INTEGER," \
	"	windomain TEXT," \
	"	canon_winname TEXT," \
	"	winname TEXT," \
	"	pid INTEGER," \
	"	unixname TEXT," \
	"	is_user INTEGER," \
	"	is_wuser INTEGER," \
	"	w2u INTEGER," \
	"	u2w INTEGER," \
	"	map_type INTEGER," \
	"	map_dn TEXT, "\
	"	map_attr TEXT, "\
	"	map_value TEXT, "\
	"	map_windomain TEXT, "\
	"	map_winname TEXT, "\
	"	map_unixname TEXT, "\
	"	map_is_nt4 INTEGER, "\
	"	expiration INTEGER" \
	")"

#define	INDEX_IDMAP_CACHE_SID_W2U_v1 \
	"CREATE UNIQUE INDEX idmap_cache_sid_w2u ON idmap_cache" \
	"		(sidprefix, rid, w2u)"

#define	INDEX_IDMAP_CACHE_SID_W2U \
	"CREATE UNIQUE INDEX idmap_cache_sid_w2u ON idmap_cache" \
	"		(sidprefix, rid, is_user, w2u)"

#define	INDEX_IDMAP_CACHE_PID_U2W \
	"CREATE UNIQUE INDEX idmap_cache_pid_u2w ON idmap_cache" \
	"		(pid, is_user, u2w)"

#define	TRIGGER_IDMAP_CACHE_TOLOWER_INSERT \
	"CREATE TRIGGER idmap_cache_tolower_name_insert " \
	"AFTER INSERT ON idmap_cache " \
	"BEGIN " \
	"	UPDATE idmap_cache SET winname = lower_utf8(canon_winname)" \
	"		WHERE rowid = new.rowid;" \
	"END"

#define	TRIGGER_IDMAP_CACHE_TOLOWER_UPDATE \
	"CREATE TRIGGER idmap_cache_tolower_name_update " \
	"AFTER UPDATE ON idmap_cache " \
	"BEGIN " \
	"	UPDATE idmap_cache SET winname = lower_utf8(canon_winname)" \
	"		WHERE rowid = new.rowid;" \
	"END"

#define	TABLE_NAME_CACHE \
	"CREATE TABLE name_cache (" \
	"	sidprefix TEXT," \
	"	rid INTEGER," \
	"	name TEXT," \
	"	canon_name TEXT," \
	"	domain TEXT," \
	"	type INTEGER," \
	"	expiration INTEGER" \
	")"

#define	TABLE_NAME_CACHE_v1 \
	"CREATE TABLE name_cache (" \
	"	sidprefix TEXT," \
	"	rid INTEGER," \
	"	name TEXT," \
	"	domain TEXT," \
	"	type INTEGER," \
	"	expiration INTEGER" \
	")"

#define	TRIGGER_NAME_CACHE_TOLOWER_INSERT \
	"CREATE TRIGGER name_cache_tolower_name_insert " \
	"AFTER INSERT ON name_cache " \
	"BEGIN " \
	"	UPDATE name_cache SET name = lower_utf8(canon_name)" \
	"		WHERE rowid = new.rowid;" \
	"END"

#define	TRIGGER_NAME_CACHE_TOLOWER_UPDATE \
	"CREATE TRIGGER name_cache_tolower_name_update " \
	"AFTER UPDATE ON name_cache " \
	"BEGIN " \
	"	UPDATE name_cache SET name = lower_utf8(canon_name)" \
	"		WHERE rowid = new.rowid;" \
	"END"

#define	INDEX_NAME_CACHE_SID \
	"CREATE UNIQUE INDEX name_cache_sid ON name_cache" \
	"		(sidprefix, rid)"

#define	INDEX_NAME_CACHE_NAME \
	"CREATE UNIQUE INDEX name_cache_name ON name_cache" \
	"		(name, domain)"

#define	CACHE_INSTALL_SQL \
	TABLE_IDMAP_CACHE ";" \
	INDEX_IDMAP_CACHE_SID_W2U ";" \
	INDEX_IDMAP_CACHE_PID_U2W ";" \
	TRIGGER_IDMAP_CACHE_TOLOWER_INSERT ";" \
	TRIGGER_IDMAP_CACHE_TOLOWER_UPDATE ";" \
	TABLE_NAME_CACHE ";" \
	INDEX_NAME_CACHE_SID ";" \
	INDEX_NAME_CACHE_NAME ";" \
	TRIGGER_NAME_CACHE_TOLOWER_INSERT ";" \
	TRIGGER_NAME_CACHE_TOLOWER_UPDATE ";"

#define	CACHE_VERSION_SQL \
	"SELECT CASE (SELECT count(*) FROM sqlite_master) WHEN 0 THEN 0 ELSE " \
	"(CASE (SELECT count(*) FROM sqlite_master WHERE " \
	"sql = '" TABLE_IDMAP_CACHE_v1 "' OR " \
	"sql = '" INDEX_IDMAP_CACHE_SID_W2U_v1 "' OR " \
	"sql = '" INDEX_IDMAP_CACHE_PID_U2W "' OR " \
	"sql = '" TABLE_NAME_CACHE_v1 "' OR " \
	"sql = '" INDEX_NAME_CACHE_SID "') " \
	"WHEN 5 THEN 1 ELSE " \
	"(CASE (SELECT count(*) FROM sqlite_master WHERE " \
	"sql = '" TABLE_IDMAP_CACHE_v2"' OR " \
	"sql = '" INDEX_IDMAP_CACHE_SID_W2U "' OR " \
	"sql = '" INDEX_IDMAP_CACHE_PID_U2W "' OR " \
	"sql = '" TRIGGER_IDMAP_CACHE_TOLOWER_INSERT "' OR " \
	"sql = '" TRIGGER_IDMAP_CACHE_TOLOWER_UPDATE "' OR " \
	"sql = '" TABLE_NAME_CACHE "' OR " \
	"sql = '" INDEX_NAME_CACHE_SID "' OR " \
	"sql = '" INDEX_NAME_CACHE_NAME "' OR " \
	"sql = '" TRIGGER_NAME_CACHE_TOLOWER_INSERT "' OR " \
	"sql = '" TRIGGER_NAME_CACHE_TOLOWER_UPDATE "') " \
	"WHEN 10 THEN 2 ELSE " \
	"(CASE (SELECT count(*) FROM sqlite_master WHERE " \
	"sql = '" TABLE_IDMAP_CACHE"' OR " \
	"sql = '" INDEX_IDMAP_CACHE_SID_W2U "' OR " \
	"sql = '" INDEX_IDMAP_CACHE_PID_U2W "' OR " \
	"sql = '" TRIGGER_IDMAP_CACHE_TOLOWER_INSERT "' OR " \
	"sql = '" TRIGGER_IDMAP_CACHE_TOLOWER_UPDATE "' OR " \
	"sql = '" TABLE_NAME_CACHE "' OR " \
	"sql = '" INDEX_NAME_CACHE_SID "' OR " \
	"sql = '" INDEX_NAME_CACHE_NAME "' OR " \
	"sql = '" TRIGGER_NAME_CACHE_TOLOWER_INSERT "' OR " \
	"sql = '" TRIGGER_NAME_CACHE_TOLOWER_UPDATE "') " \
	"WHEN 10 THEN 3 ELSE -1 END) END) END) END AS version;"

#define	CACHE_UPGRADE_FROM_v1_SQL \
	"DROP TABLE idmap_cache;" \
	"DROP TABLE name_cache;" \
	CACHE_INSTALL_SQL

#define	CACHE_UPGRADE_FROM_v2_SQL \
	"DROP TABLE idmap_cache;" \
	"DROP TABLE name_cache;" \
	CACHE_INSTALL_SQL

#define	CACHE_VERSION	3


#define	TABLE_NAMERULES_v1 \
	"CREATE TABLE namerules (" \
	"	is_user INTEGER NOT NULL," \
	"	windomain TEXT," \
	"	winname TEXT NOT NULL," \
	"	is_nt4 INTEGER NOT NULL," \
	"	unixname NOT NULL," \
	"	w2u_order INTEGER," \
	"	u2w_order INTEGER" \
	")"

#define	TABLE_NAMERULES_BODY \
	"(" \
	"	is_user INTEGER NOT NULL," \
	"	is_wuser INTEGER NOT NULL," \
	"	windomain TEXT," \
	"	winname_display TEXT NOT NULL," \
	"	winname TEXT," \
	"	is_nt4 INTEGER NOT NULL," \
	"	unixname NOT NULL," \
	"	w2u_order INTEGER," \
	"	u2w_order INTEGER" \
	")"

#define	TABLE_NAMERULES \
	"CREATE TABLE namerules " \
	TABLE_NAMERULES_BODY

#define	INDEX_NAMERULES_W2U_v1 \
	"CREATE UNIQUE INDEX namerules_w2u ON namerules" \
	"		(winname, windomain, is_user, w2u_order)"

#define	INDEX_NAMERULES_W2U \
	"CREATE UNIQUE INDEX namerules_w2u ON namerules" \
	"		(winname, windomain, is_user, is_wuser, w2u_order)"

#define	INDEX_NAMERULES_U2W \
	"CREATE UNIQUE INDEX namerules_u2w ON namerules" \
	"		(unixname, is_user, u2w_order)"

#define	TRIGGER_NAMERULES_TOLOWER_BODY \
	"BEGIN " \
	"	UPDATE namerules SET winname = lower_utf8(winname_display)" \
	"		WHERE rowid = new.rowid;" \
	"END"

#define	TRIGGER_NAMERULES_TOLOWER_INSERT \
	"CREATE TRIGGER namerules_tolower_name_insert " \
	"AFTER INSERT ON namerules " \
	TRIGGER_NAMERULES_TOLOWER_BODY

#define	TRIGGER_NAMERULES_TOLOWER_UPDATE \
	"CREATE TRIGGER namerules_tolower_name_update " \
	"AFTER UPDATE ON namerules " \
	TRIGGER_NAMERULES_TOLOWER_BODY

#define	TRIGGER_NAMERULES_UNIQUE_BODY \
	"	SELECT CASE (SELECT count(*) FROM namerules AS n" \
	"		WHERE n.unixname = NEW.unixname AND" \
	"		n.is_user = NEW.is_user AND" \
	"		(n.winname != lower(NEW.winname_display) OR" \
	"		n.windomain != NEW.windomain ) AND" \
	"		n.u2w_order = NEW.u2w_order AND" \
	"		n.is_wuser != NEW.is_wuser) > 0" \
	"	WHEN 1 THEN" \
	"		raise(ROLLBACK, 'Conflicting w2u namerules')"\
	"	END; " \
	"END"

#define	TRIGGER_NAMERULES_UNIQUE_INSERT \
	"CREATE TRIGGER namerules_unique_insert " \
	"BEFORE INSERT ON namerules " \
	"BEGIN " \
	TRIGGER_NAMERULES_UNIQUE_BODY

#define	TRIGGER_NAMERULES_UNIQUE_UPDATE \
	"CREATE TRIGGER namerules_unique_update " \
	"BEFORE INSERT ON namerules " \
	"BEGIN " \
	TRIGGER_NAMERULES_UNIQUE_BODY

#define	DB_INSTALL_SQL \
	TABLE_NAMERULES ";" \
	INDEX_NAMERULES_W2U ";" \
	INDEX_NAMERULES_U2W ";" \
	TRIGGER_NAMERULES_TOLOWER_INSERT ";" \
	TRIGGER_NAMERULES_TOLOWER_UPDATE ";" \
	TRIGGER_NAMERULES_UNIQUE_INSERT ";" \
	TRIGGER_NAMERULES_UNIQUE_UPDATE ";"

#define	DB_VERSION_SQL \
	"SELECT CASE (SELECT count(*) FROM sqlite_master) WHEN 0 THEN 0 ELSE " \
	"(CASE (SELECT count(*) FROM sqlite_master WHERE " \
	"sql = '" TABLE_NAMERULES_v1 "' OR " \
	"sql = '" INDEX_NAMERULES_W2U_v1 "' OR " \
	"sql = '" INDEX_NAMERULES_U2W "') " \
	"WHEN 3 THEN 1 ELSE "\
	"(CASE (SELECT count(*) FROM sqlite_master WHERE " \
	"sql = '" TABLE_NAMERULES "' OR " \
	"sql = '" INDEX_NAMERULES_W2U "' OR " \
	"sql = '" INDEX_NAMERULES_U2W "' OR " \
	"sql = '" TRIGGER_NAMERULES_TOLOWER_INSERT "' OR " \
	"sql = '" TRIGGER_NAMERULES_TOLOWER_UPDATE "' OR " \
	"sql = \"" TRIGGER_NAMERULES_UNIQUE_INSERT "\" OR " \
	"sql = \"" TRIGGER_NAMERULES_UNIQUE_UPDATE "\") " \
	"WHEN 7 THEN 2 ELSE -1 END) END) END AS version;"

/* SQL for upgrading an existing name rules DB.  Includes DB_INSTALL_SQL */
#define	DB_UPGRADE_FROM_v1_SQL \
	"CREATE TABLE namerules_new " TABLE_NAMERULES_BODY ";" \
	"INSERT INTO namerules_new SELECT is_user, is_user, windomain, " \
	"winname, winname, is_nt4, unixname, w2u_order, u2w_order " \
	"FROM namerules;" \
	"DROP TABLE namerules;" \
	DB_INSTALL_SQL \
	"INSERT INTO namerules SELECT * FROM namerules_new;" \
	"DROP TABLE namerules_new;"

#define	DB_VERSION	2

#ifdef __cplusplus
}
#endif


#endif	/* _SCHEMA_H */
