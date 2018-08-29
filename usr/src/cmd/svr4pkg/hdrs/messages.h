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
 * Copyright (c) 2018 Peter Tribble.
 */

/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_MESSAGES_H
#define	_MESSAGES_H


/*
 * Module:	messages
 * Group:	pkg commands
 * Description: l10n strings for all pkg commands
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	MSG_MAX	1024
#define	MAXARGS 100
#define	MAX_CAT_ARGS 64

/* BEGIN CSTYLED */

/*
 * I18N: these messages are questions asked of the user
 */

#define	ASK_CONFIRM			gettext("Do you want to remove this package?")
#define	ASK_CONT			gettext("Do you want to continue with the installation of <%s>")
#define	ASK_CONTINUE_ADD		gettext("Do you want to continue with package installation?")
#define	ASK_CONTINUE_RM			gettext("Do you want to continue with package removal?")
#define	ASK_PKGREMOVE_CONTINUE		gettext("Do you want to continue with the removal of this package")
#define	ASK_PKGRMCHK_CONT		gettext("Do you want to continue with the removal of <%s>")

/*
 * I18N: these messages are debugging message and are only displayed
 * when special debugging output has been enabled - these messages
 * will never be displayed during normal product usage
 */

#define	DBG_ADDPACKAGES_ARGS		gettext("npkgs <%d> uri <%s> stream device <%s> repeat <%d> altBinDir <%s> device <%s>")
#define	DBG_ADDPACKAGES_ENTRY		gettext("add_packages:")
#define	DBG_ADDPACKAGES_GZ_NO_LZ_ARGS	gettext("npkgs <%d> uri <%s> stream device <%s> repeat <%d> device <%s>")
#define	DBG_ADDPACKAGES_GZ_NO_LZ_ENTRY	gettext("add_pkgs_in_gz_no_zones: adding packages in global zone with NO non-global zones")
#define	DBG_ADDPACKAGES_GZ_W_LZ_ARGS	gettext("npkgs <%d> uri <%s> stream device <%s> repeat <%d> device <%s>")
#define	DBG_ADDPACKAGES_GZ_W_LZ_ENTRY	gettext("add_pkgs_in_gz_with_zones: adding packages in global zone with non-global zones present")
#define	DBG_ADDPACKAGES_LZ_ARGS		gettext("npkgs <%d> uri <%s> stream device <%s> repeat <%d> device <%s>")
#define	DBG_ADDPACKAGES_LZ_ENTRY	gettext("add_pkgs_in_lz: adding packages in non-global zone")
#define	DBG_ARG				gettext("argument <%d> = <%s>")
#define	DBG_BOOTCHECKINSTALLINZONES_ARGS gettext("ids <%s> admin <%s> tempdir <%s>")
#define	DBG_BOOTCHECKINSTALLINZONES_ENTRY gettext("boot_and_check_install_in_zones:")
#define	DBG_BOOTING_ZONE		gettext("booting up non-running zone <%s>")
#define	DBG_BOOTINSTALLINZONES_ARGS	gettext("ids <%s> admin <%s> tempdir <%s>")
#define	DBG_BOOTINSTALLINZONES_ENTRY	gettext("boot_and_install_in_zones:")
#define	DBG_BRANDS_ARE_IMPLEMENTED	gettext("brands are implemented")
#define	DBG_BRANDS_NOT_IMPLEMENTED	gettext("brands are NOT implemented")
#define	DBG_CANNOT_GET_PKGLIST		gettext("unable to get package list")
#define	DBG_CHECKAPP_ARGS		gettext("package <%s> directory <%s> rootpath <%s>")
#define	DBG_CHECKAPP_ENTRY		gettext("check install applicability:")
#define	DBG_CHECKAPP_THISZONE_INSTREQ	gettext("WARNING: the package <%s> to be installed does not contain a request script, but the currently installed instance (package <%s>) does contain a request script, so the package to be installed can only be installed in the current zone, and will not be installed in any future zones created.")
#define	DBG_CHECKAPP_THISZONE_REQUEST	gettext("WARNING: package <%s> contains a request script, and can only be installed in the current zone, and will not be installed in any future zones created.")
#define	DBG_CHECKINSTALL_IN_ZONE	gettext("checking install of package <%s> in zone <%s> from stream <%s>")
#define	DBG_CHECKREMOVE_PKG_IN_ZONE	gettext("verifying package <%s> dependencies in zone <%s>")
#define	DBG_CLOSING_STREAM		gettext("closing datastream <%s> at <%s>")
#define	DBG_CONVERTING_PKG		gettext("converting package <%s/%s> to stream <%s>")
#define	DBG_COPY_FILE			gettext("copy <%s> to <%s>")
#define	DBG_CPPATH_ENTRY		gettext("copy path: control <0x%02x> mode <0%04lo> source <%s> destination <%s>")
#define	DBG_CREATED_ZONE_ADMINFILE	gettext("created temporary zone administration file <%s>")
#define	DBG_CREATED_ZONE_TEMPDIR	gettext("created temporary zone directory <%s>")
#define	DBG_CREATE_ZONE_ADMINFILE	gettext("create temporary zone administration file in directory <%s> template <%s>")
#define	DBG_CREATE_ZONE_TEMPDIR		gettext("create temporary zone directory in temporary directory <%s>")
#define	DBG_DEPCHK_COLLECT_ERROR	gettext("dependency report error: ign <null> ret <%d> package <%s> msg <%s>")
#define	DBG_DEPCHK_COLLECT_IGNORE	gettext("dependency report error: ign <null> no check function package <%s> msg <%s>")
#define	DBG_DEPCHK_ENTRY		gettext("depchkReportErrors:")
#define	DBG_DEPCHK_IGNORE_ERROR		gettext("dependency report error: ign <%s> no check function package <%s> msg <%s>")
#define	DBG_DEPCHK_RECORD_ERROR		gettext("dependency record error: erc <0x%08lx> add first package <%s> zone <%s> value <%s>")
#define	DBG_DEPCHK_RECORD_PERROR	gettext("dependency record error: erc <0x%08lx> add package <%d> <%s> zone <%s> value <%s>")
#define	DBG_DEPCHK_RECORD_ZERROR	gettext("dependency record error: erc <0x%08lx> add zone <%s> value <%s> to existing package <%s> # <%d> zones[0] <%s>")
#define	DBG_DEPCHK_REPORT_ERROR		gettext("dependency report error: ign <%s> ret <%d> package <%s> msg <%s>")
#define	DBG_DOMERG_NOT_THERE		gettext("object does not exist or has incorrect contents: type <%c> class <%s> path <%s>")
#define	DBG_DOMERG_NOT_WRITABLE		gettext("object not writable or cannot be created: type <%c> class <%s> path <%s>")
#define	DBG_DOMERG_NO_SUCH_FILE		gettext("file does not exist or has incorrect contents: type <%c> class <%s> path <%s>")
#define	DBG_DOREMOVE_ARGS		gettext("found package <%s> name <%s> arch <%s> version <%s> basedir <%s> catg <%s> status <%d>\n")
#define	DBG_DOREMOVE_ENTRY		gettext("doremove:")
#define	DBG_DOREMOVE_INTERRUPTED	gettext("interrupted: package <%s> not installed")
#define	DBG_DO_EXEC_REQUEST_USER	gettext("running request script <%s> output <%s> as user <%s> i.d. <%ld> group <%s> i.d. <%ld>")
#define	DBG_ENTRY_IN_GZ			gettext("[<%s> in global zone]")
#define	DBG_ENTRY_IN_LZ			gettext("[<%s> in non-global zone <%ld>:<%s>]")
#define	DBG_EXIT_WITH_CODE		gettext("exiting with code <%d>")
#define	DBG_FINALCK_ERROR		gettext("final check (error): attrchg <%d> contchg <%d> ftype <%c> path <%s>")
#define	DBG_FINALCK_ERROR_AVERIFY	gettext("final check (error): attribute verification = <%d>")
#define	DBG_FINALCK_ERROR_CVERIFY	gettext("final check (error): content verification = <%d>")
#define	DBG_FINALCK_EXIT		gettext("final check (return): error <%d> type <%c> path <%s>")
#define	DBG_FINALCK_WARNING		gettext("final check (warning): attrchg <%d> contchg <%d> ftype <%c> path <%s>")
#define	DBG_FINALCK_WARNING_AVERIFY	gettext("final check (warning): attribute verification = <%d>")
#define	DBG_FINALCK_WARNING_CVERIFY	gettext("final check (warning): content verification = <%d>")
#define	DBG_GETPKGLIST_ARGS		gettext("stream device <%s> directory <%s> repeat <%d>")
#define	DBG_GETPKGLIST_ENTRY		gettext("get_package_list:")
#define	DBG_INSTALLING_TO_SPOOL		gettext("installing packages to spool directory <%s>")
#define	DBG_INSTALLINZONES_ARGS		gettext("ids <%s> admin <%s> tempdir <%s>")
#define	DBG_INSTALLINZONES_ENTRY	gettext("install_in_zones:")
#define	DBG_INSTALL_FLAG_VALUES		gettext("%s: admnflag <%d> doreboot <%d> failflag <%d> interrupted <%d> intrflag <%d> ireboot <%d> needconsult <%d> nullflag <%d> warnflag <%d>")
#define	DBG_INSTALL_IN_ZONE		gettext("installing package <%s> in zone <%s> from stream <%s>")
#define	DBG_INSTALL_SKIP_THISZONE	gettext("skipping installation of package <%s>: marked this zone only")
#define	DBG_INSTINONEZONE_ARGS		gettext("zone <%s> ids <%s> admin <%s> tempdir <%s> altbindir <%s>")
#define	DBG_INSTINONEZONE_ENTRY		gettext("install_in_one_zone:")
#define	DBG_INSTVOL_CAS_INFO		gettext("is partial <%d> updated <%s>\n")
#define	DBG_INSTVOL_NOT_RUNNING_CAS	gettext("not running zone <%s> object <%s> class <%s> action script <%s>")
#define	DBG_INSTVOL_OBJ_LOCAL		gettext("objects local <%s>")
#define	DBG_INSTVOL_OBJ_UPDATED		gettext("objects updated <%s>")
#define	DBG_INSTVOL_RUNNING_CAS		gettext("running zone <%s> object <%s> class <%s> action script <%s>")
#define	DBG_IN_GZ_NO_LZ			gettext("running in global zone with NO non-global zones")
#define	DBG_IN_GZ_WITH_LZ		gettext("running in global zone with non-global zones")
#define	DBG_IN_LZ			gettext("running in non-global zone")
#define	DBG_MERGINFOS_ASK_BASEDIR	gettext("merg_pkginfos: ask for BASEDIR change later")
#define	DBG_MERGINFOS_ENTRY		gettext("merg_pkginfos: installed pkginfo <%s>")
#define	DBG_MERGINFOS_EXIT		gettext("merg_pkginfos: done changing <%s> result <%d>")
#define	DBG_MERGINFOS_SET_BASEDIR	gettext("merg_pkginfos: set BASEDIR to <%s>")
#define	DBG_MERGINFOS_SET_CHANGE	gettext("merg_pkginfos: change existing attribute <%s> from <%s> to <%s>")
#define	DBG_MERGINFOS_SET_CLASSES	gettext("merg_pkginfos: set CLASSES to <%s>")
#define	DBG_MERGINFOS_SET_DUPLICATE	gettext("merg_pkginfos: set existing attribute <%s> to current value <%s>")
#define	DBG_MERGINFOS_RETAIN_OLD	gettext("merg_pkginfos: retain existing attribute <%s> value <%s>")
#define	DBG_MERGINFOS_SET_TO		gettext("merg_pkginfos: validate change attribute <%s> from <%s>")
#define	DBG_MERGINFO_ATTRCOMP		gettext("merginfo: attribute <%s> currently set to <%s>")
#define	DBG_MERGINFO_DIFFERENT		gettext("merginfo: pkginfo file source <%s> different than merged <%s>: open source pkginfo file")
#define	DBG_MERGINFO_ENTRY		gettext("merginfo: instdir <%s> get_inst_root() <%s> saveSpoolInstallDir <%s> pkgloc <%s> is_spool_create <%d> get_info_basedir() <%s> installed pkginfo <%s> merged pkginfo <%s>")
#define	DBG_MERGINFO_EXCLUDING		gettext("merginfo: excluding attribute <%s>")
#define	DBG_MERGINFO_FINAL		gettext("merginfo: accepting attribute <%s>")
#define	DBG_MERGINFO_GREATER_THAN	gettext("merginfo: attribute <%s> greater than last entry <%s>")
#define	DBG_MERGINFO_LESS_THAN		gettext("merginfo: attribute <%s> less than first entry <%s>")
#define	DBG_MERGINFO_SAME		gettext("merginfo: pkginfo file source and merged <%s> identical: no source pkginfo file used")
#define	DBG_MERGINFO_SEARCHING		gettext("merginfo: attribute <%s> within range of <%s> and <%s>: searching")
#define	DBG_NUM_PKGS_TO_ADD		gettext("number of packages to add <%d>")
#define	DBG_NUM_PKGS_TO_REMOVE		gettext("number of packages to remove <%d> longest package name length <%d>")
#define	DBG_ODS_ARGS			gettext("bdevice <%s> cdevice <%s> pathname <%s> argc <%d> spool-device <%s>")
#define	DBG_ODS_DATASTREAM_BDEV		gettext("package source is block device <%s>")
#define	DBG_ODS_DATASTREAM_CDEV		gettext("package source is character device <%s>")
#define	DBG_ODS_DATASTREAM_INIT		gettext("initializing package datastream <%s>")
#define	DBG_ODS_DATASTREAM_ISFILE	gettext("package source is ordinary file <%s>")
#define	DBG_ODS_DATASTREAM_MOUNTING	gettext("mounting package datastream device <%s> on <%s>")
#define	DBG_ODS_DATASTREAM_UNK		gettext("package source not contained in a recognized datastream")
#define	DBG_ODS_ENTRY			gettext("open_package_datastream:")
#define	DBG_PKGADD_ADMINFILE		gettext("using admin file <%s>")
#define	DBG_PKGADD_CKRETURN		gettext("check return code <%d> package <%s> function <add packages>")
#define	DBG_PKGADD_ENABLING_HOLLOW	gettext("enabling hollow package support")
#define	DBG_PKGADD_HOLLOW_ENABLED	gettext("hollow package support is enabled")
#define	DBG_PKGADD_PKGPATHS		gettext("locations set: pkg <%s> adm <%s>")
#define	DBG_PKGADD_RESPFILE		gettext("using response file <%s> directory <%s>")
#define	DBG_PKGADD_TMPDIR		gettext("using temporary directory <%s>")
#define	DBG_PKGDBMRG_INHERITED		gettext("path inherited and assumed correct: <%s>")
#define	DBG_PKGINSTALL_ADMINFILE	gettext("using admin file <%s>")
#define	DBG_PKGINSTALL_ARGS		gettext("package <%s> dirname <%s> bdevice <%s> mount <%s> ir <%s> idsName <%s> pkgdir <%s>")
#define	DBG_PKGINSTALL_COC_DBUPD	gettext("skipping checkinstall package <%s> script <%s> zone <%s> (db update only)")
#define	DBG_PKGINSTALL_COC_NODEL	gettext("skipping checkinstall package <%s> script <%s> zone <%s> (nodelete)")
#define	DBG_PKGINSTALL_COC_NONE		gettext("no checkinstall in package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_DS_ISFILE	gettext("package source <%s> is an ordinary file - treating as a package data stream")
#define	DBG_PKGINSTALL_ENTRY		gettext("pkgInstall:")
#define	DBG_PKGINSTALL_EXECOC_GZ	gettext("executing checkinstall package <%s> script <%s>")
#define	DBG_PKGINSTALL_EXECOC_LZ	gettext("executing checkinstall package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_EXEPIC_GZ	gettext("executing postinstall package <%s> script <%s>")
#define	DBG_PKGINSTALL_EXEPIC_LZ	gettext("executing postinstall package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_EXEPOC_GZ	gettext("executing preinstall package <%s> script <%s>")
#define	DBG_PKGINSTALL_EXEPOC_LZ	gettext("executing preinstall package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_HAS_LOCKFILE	gettext("before removing package <%s> found existing lockfile <%s> zone <%s>")
#define	DBG_PKGINSTALL_INSDONE		gettext("install completed: hollow support <%d> is hollow <%d> fresh install <%d> updated <%s> script <%s> access <%d>")
#define	DBG_PKGINSTALL_POCALT_NONE	gettext("no pkgbin preinstall package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_POC_DBUPD	gettext("skipping preinstall package <%s> script <%s> zone <%s> (db update only)")
#define	DBG_PKGINSTALL_POC_NONE		gettext("has no media preinstall package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_POIS_DBUPD	gettext("skipping postinstall package <%s> script <%s> zone <%s> (db update only)")
#define	DBG_PKGINSTALL_POIS_NONE	gettext("no postinstall in package <%s> script <%s> zone <%s>")
#define	DBG_PKGINSTALL_POIS_NOPATH	gettext("no postinstall in package <%s> zone <%s>")
#define	DBG_PKGINSTALL_POIS_NOUPDATING	gettext("no objects updated when installing in zone <%s>: skipping postinstall package <%s> script <%s>")
#define	DBG_PKGINSTALL_PREINSCHK	gettext("preinstallation check of package <%s> zone <%s>")
#define	DBG_PKGINSTALL_PREINSCHK_OK	gettext("preinstall check successful")
#define	DBG_PKGINSTALL_RSCRIPT_IS_ROOT	gettext("request script run as root = <%d>")
#define	DBG_PKGINSTALL_RSCRIPT_NOT_SET	gettext("admin file parameter <%s> is not set")
#define	DBG_PKGINSTALL_RSCRIPT_SET_TO	gettext("admin file parameter <%s> is set to <%s>")
#define	DBG_PKGINSTALL_TMPDIR		gettext("using temporary directory <%s>")
#define	DBG_PKGLIST_ERROR		gettext("unable to get package list from device <%s> directory <%s>: fatal error <%d>")
#define	DBG_PKGLIST_NONFOUND		gettext("unable to get package list from device <%s> directory <%s>: no packages found")
#define	DBG_PKGLIST_RM_ERROR		gettext("unable to get package list from directory <%s>: fatal error <%d>")
#define	DBG_PKGLIST_RM_NONFOUND		gettext("unable to get package list from directory <%s>: no packages found")
#define	DBG_PKGOPS_ADDED_GZPKG		gettext("added package <%s> to global zone only file")
#define	DBG_PKGOPS_ADDGZPKG		gettext("add package <%s> to global zone only file at <%s>")
#define	DBG_PKGOPS_ADD_TZP		gettext("add package entry <%d> instance <%s> as this zone only")
#define	DBG_PKGOPS_CKSUM_MISMATCH	gettext("checksum <%s>:<0x%08lx> does not match <%s>:<0x%08lx>")
#define	DBG_PKGOPS_EDITABLE_EXISTS	gettext("editable file <%s> exists: ok")
#define	DBG_PKGOPS_GETPKGLIST_ARGS	gettext("directory <%s> category <%s>")
#define	DBG_PKGOPS_GETPKGLIST_ENTRY	gettext("pkgGetPackageList:")
#define	DBG_PKGOPS_GPKGLIST_CATFAILED	gettext("no packages found for category <%s>")
#define	DBG_PKGOPS_GPKGLIST_CATOK	gettext("successfully generated package list for category <%s>")
#define	DBG_PKGOPS_GPKGLIST_EINTR	gettext("search interrupted looking for packages from list of packages specified")
#define	DBG_PKGOPS_GPKGLIST_ENOPKG	gettext("no packages found from list of packages specified")
#define	DBG_PKGOPS_GPKGLIST_ESRCH	gettext("search failed looking for packages from list of packages specified")
#define	DBG_PKGOPS_GPKGLIST_OK		gettext("successfully generated package list from list of packages specified")
#define	DBG_PKGOPS_GPKGLIST_UNKNOWN	gettext("unknown value <%d> returned from gpkglist")
#define	DBG_PKGOPS_IS_INHERITED		gettext("path <%s> is inherited from <%s>")
#define	DBG_PKGOPS_IS_NOT_THISZONE	gettext("package <%s> is NOT this zone only")
#define	DBG_PKGOPS_IS_THISZONE		gettext("package <%s> is this zone only")
#define	DBG_PKGOPS_LOCHIGH_ARGS		gettext("rootpath <%s> pkginst <%s>")
#define	DBG_PKGOPS_LOCHIGH_ENTRY	gettext("pkgLocateHighestInst:")
#define	DBG_PKGOPS_LOCHIGH_INSTANCE	gettext("instance <%d> = pkginst <%s> name <%s> arch <%s> version <%s> vendor <%s> basedir <%s> catg <%s> status <0x%02x>")
#define	DBG_PKGOPS_LOCHIGH_RETURN	gettext("npkgs is <%d> returned pkginst <%s> path <%s>")
#define	DBG_PKGOPS_LOCHIGH_WILDCARD	gettext("package <%s> wild card specification <%s>")
#define DBG_PKGOPS_MATCHINHERIT_ARGS    gettext("<%s> vs <%s> root <%s> mode <0%04o> modtime <0x%08lx> ftype <%c> cksum <0x%08lx>")
#define	DBG_PKGOPS_MATCHINHERIT_ENTRY	gettext("match inherited:")
#define	DBG_PKGOPS_MOD_MISMATCH		gettext("mod time <%s>:<0x%08lx> does not match <%s>:<0x%08lx>")
#define	DBG_PKGOPS_NOT_THISZONE		gettext("package <%s> is NOT this zone only: no this zone only packages")
#define	DBG_PKGOPS_PARAMTRUTH_RESULTS	gettext("lookup param <%s> compare-value <%s> default-value <%s> param-is <%s> result <%s>")
#define	DBG_PKGOPS_PKGINFO_RETURNED	gettext("pkginfo for path <%s> returned <%d>")
#define	DBG_PKGOPS_PKG_IS_GZONLY	gettext("package <%s> IS recorded as installed in the global zone only")
#define	DBG_PKGOPS_PKG_NOT_GZONLY	gettext("package <%s> not recorded as installed in the global zone only")
#define	DBG_PKGOPS_REMOVED_GZPKG	gettext("removed package <%s> from global zone only file")
#define	DBG_PKGOPS_VOLATILE_EXISTS	gettext("volatile file <%s> exists")
#define	DBG_PKGREMOVE_ADMINFILE		gettext("using admin file <%s>")
#define	DBG_PKGREMOVE_ARGS		gettext("package <%s> dirname <%s> nodelete <%d> adminFile <%s>")
#define	DBG_PKGREMOVE_ENTRY		gettext("pkgRemove:")
#define	DBG_PKGREMOVE_EXEPIC_GZ		gettext("executing postremove package <%s> script <%s>.")
#define	DBG_PKGREMOVE_EXEPIC_LZ		gettext("executing postremove package <%s> script <%s> zone <%s>.")
#define	DBG_PKGREMOVE_EXEPOC_GZ		gettext("executing preremove package <%s> script <%s>.")
#define	DBG_PKGREMOVE_EXEPOC_LZ		gettext("executing preremove package <%s> script <%s> zone <%s>.")
#define	DBG_PKGREMOVE_HOLLOW_DISABLED	gettext("hollow package support is disabled")
#define	DBG_PKGREMOVE_HOLLOW_ENABLED	gettext("hollow package support is enabled")
#define	DBG_PKGREMOVE_PIC_DBUPD		gettext("skipping postremove package <%s> script <%s> zone <%s> (db update only)")
#define	DBG_PKGREMOVE_PIC_NODEL		gettext("skipping postremove package <%s> script <%s> zone <%s> (nodelete)")
#define	DBG_PKGREMOVE_PIC_NONE		gettext("package <%s> zone <%s> has no postremove script")
#define	DBG_PKGREMOVE_POC_DBUPD		gettext("skipping preremove package <%s> script <%s> zone <%s> (db update only)")
#define	DBG_PKGREMOVE_POC_NODEL		gettext("skipping preremove package <%s> script <%s> zone <%s> (nodelete)")
#define	DBG_PKGREMOVE_POC_NONE		gettext("package <%s> zone <%s> has no preremove script")
#define	DBG_PKGREMOVE_PRERMCHK		gettext("preremoval check of package <%s> zone <%s>")
#define	DBG_PKGREMOVE_PRERMCHK_OK	gettext("preremoval check successful")
#define	DBG_PKGREMOVE_PROCPKG_GZ	gettext("begin processing package <%s> information lockfile <%s>")
#define	DBG_PKGREMOVE_PROCPKG_LZ	gettext("begin processing package <%s> information lockfile <%s> zone <%s>")
#define	DBG_PKGREMOVE_REM		gettext("performing class removal package <%s> zone <%s>")
#define	DBG_PKGREMOVE_REM_DBUPD		gettext("skipping class removal package <%s> zone <%s> (db update only)")
#define	DBG_PKGREMOVE_REM_NODEL		gettext("skipping class removal package <%s> zone <%s> (nodelete)")
#define	DBG_PKGREMOVE_TMPDIR		gettext("using temporary directory <%s>")
#define	DBG_PKGREMPKGSGZNNGZ_ARGS	gettext("nodelete <%d> longest package <%d> repeat <%d> altbindir <%s>")
#define	DBG_PKGREMPKGSGZNNGZ_ENTRY	gettext("remove_packages_in_global_no_zones:")
#define	DBG_PKGREMPKGSGZWNGZ_ARGS	gettext("nodelete <%d> longest package <%d> repeat <%d> altbindir <%s> pkgdir <%s>")
#define	DBG_PKGREMPKGSGZWNGZ_ENTRY	gettext("remove_packages_in_global_with_zones:")
#define	DBG_PKGREMPKGSNGZ_ARGS		gettext("nodelete <%d> longest package <%d> repeat <%d> altbindir <%s> pkgdir <%s>")
#define	DBG_PKGREMPKGSNGZ_ENTRY		gettext("remove_packages_in_nonglobal_zone:")
#define	DBG_PKGRM_ADMINFILE		gettext("using admin file <%s>")
#define	DBG_PKGRM_CKRETURN		gettext("check return code <%d> package <%s> function <remove packages>")
#define	DBG_PKGRM_ENABLING_HOLLOW	gettext("enabling hollow package support")
#define	DBG_PKGRM_HOLLOW_ENABLED	gettext("hollow package support is enabled")
#define	DBG_PKGRM_TMPDIR		gettext("using temporary directory <%s>")
#define	DBG_PKGZONECHECKINSTALL_ARGS	gettext("zone <%s> package <%s> dirname <%s> bdevice <%s> mount <%s> ir <%s> idsName <%s> adminFile <%s> stdout <%s>")
#define	DBG_PKGZONECHECKINSTALL_ENTRY	gettext("pkgZoneCheckInstall:")
#define	DBG_PKGZONECHECKREMOVE_ARGS	gettext("zone <%s> package <%s> dirname <%s> adminFile <%s> stdoutpath <%s>")
#define	DBG_PKGZONECHECKREMOVE_ENTRY	gettext("pkgZoneCheckRemove:")
#define	DBG_PKGZONEINSTALL_ARGS		gettext("zone <%s> package <%s> dirname <%s> bdevice <%s> mount <%s> ir <%s> idsName <%s> adminFile <%s>")
#define	DBG_PKGZONEINSTALL_ENTRY	gettext("pkgZoneInstall:")
#define	DBG_PKGZONEREMOVE_ARGS		gettext("zone <%s> package <%s> dirname <%s> nodelete <%d> adminFile <%s>")
#define	DBG_PKGZONEREMOVE_ENTRY		gettext("pkgZoneRemove:")
#define	DBG_PKG_INSTALLED		gettext("package <%s> is installed at <%s>")
#define	DBG_PKG_IN_DIR			gettext("package <%s> available in directory <%s>")
#define	DBG_PKG_NOT_INSTALLED		gettext("package <%s> is not installed at <%s>")
#define	DBG_PKG_SELECTED		gettext("-> package [%d] = <%s>")
#define	DBG_PKG_TEST_EXISTENCE		gettext("test existence of package <%s> at <%s>")
#define	DBG_PREIVFY_CKCFCONTENT		gettext("check content conflict: package <%s> message <%s>")
#define	DBG_PREIVFY_CKCONFLICT		gettext("check conflicting installed object: package <%s> message <%s>")
#define	DBG_PREIVFY_CKDEPEND		gettext("check dependency: package <%s> message <%s>")
#define	DBG_PREIVFY_CKDIRS		gettext("check directories: package <%s> message <%s>")
#define	DBG_PREIVFY_CKINSTANCE		gettext("check instance: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPARTIALINSTALL	gettext("check partially installed: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPARTIALREMOVE	gettext("check partially removed: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPKGDIRS		gettext("check package directories: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPKGFILEBAD	gettext("check file bad: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPKGFILES		gettext("check package files: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPRENCI		gettext("check prerequisite incomplete: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPREREQ		gettext("check prerequisite installed: package <%s> message <%s>")
#define	DBG_PREIVFY_CKPRIV		gettext("check privileges: package <%s> message <%s>")
#define	DBG_PREIVFY_CKRUNLEVEL		gettext("check run level: package <%s> message <%s>")
#define	DBG_PREIVFY_CKSETUID		gettext("check setuid: package <%s> message <%s>")
#define	DBG_PREIVFY_CKSPACE		gettext("check space: package <%s> message <%s>")
#define	DBG_PREIVFY_ENTRY		gettext("performing preinstallation dependency verification")
#define	DBG_PREIVFY_GETYORN_ARGS	gettext("package <%s> nocheck <%d> quit <%d> message <%s> admin-msg <%s>")
#define	DBG_PREIVFY_GETYORN_CKYORN	gettext("package <%s> ckyorn return non-zero <%d>")
#define	DBG_PREIVFY_GETYORN_NOCHECK	gettext("package <%s> no check - return <0> (success)")
#define	DBG_PREIVFY_GETYORN_NOT_Y	gettext("package <%s> ckyorn answer <%s> - return <3> (interruption)")
#define	DBG_PREIVFY_GETYORN_QUIT	gettext("package <%s> quit - return <4> (administration)")
#define	DBG_PREIVFY_GETYORN_QUIT_USER	gettext("package <%s> noninteractive mode - return <5> (administration required)")
#define	DBG_PREIVFY_GETYORN_SUCCESS	gettext("package <%s> continue installation")
#define	DBG_PREIVFY_NOFILE		gettext("unable to perform preinstallation check of package <%s> in zone <%s> data file <%s>: %s")
#define	DBG_PREIVFY_SCAN		gettext("scanning for line <%s> found package <%s> zone <%s>")
#define	DBG_PREIVFY_SKIP_THISZONE	gettext("skipping preinstall verification of package <%s>: marked this zone only")
#define	DBG_PRERVFY_ENTRY		gettext("performing preremoval dependency verification")
#define	DBG_PRERVFY_GETYORN_ARGS	gettext("package <%s> nocheck <%d> quit <%d> message <%s> admin-msg <%s>")
#define	DBG_PRERVFY_GETYORN_CKYORN	gettext("package <%s> ckyorn return non-zero <%d>")
#define	DBG_PRERVFY_GETYORN_NOCHECK	gettext("package <%s> no check - return <0> (success)")
#define	DBG_PRERVFY_GETYORN_NOT_Y	gettext("package <%s> ckyorn answer <%s> - return <3> (interruption)")
#define	DBG_PRERVFY_GETYORN_QUIT	gettext("package <%s> quit - return <4> (administration)")
#define	DBG_PRERVFY_GETYORN_QUIT_USER	gettext("package <%s> noninteractive mode - return <5> (administration required)")
#define	DBG_PRERVFY_GETYORN_SUCCESS	gettext("package <%s> continue removal")
#define	DBG_PRERVFY_NOFILE		gettext("unable to perform preremoval check of package <%s> in zone <%s> data file <%s>: %s")
#define	DBG_PRERVFY_RCKDEPEND		gettext("check dependency: package <%s> message <%s>")
#define	DBG_PRERVFY_RCKDEPSONME		gettext("check depends on this package: package <%s> message <%s>")
#define	DBG_PRERVFY_RCKPRENCI		gettext("check prerequisite incomplete: package <%s> message <%s>")
#define	DBG_PRERVFY_RCKPREREQ		gettext("check prerequisite installed: package <%s> message <%s>")
#define	DBG_PRERVFY_RCKPRIV		gettext("check privileges: package <%s> message <%s>")
#define	DBG_PRERVFY_RCKRUNLEVEL		gettext("check run level: package <%s> message <%s>")
#define	DBG_PRERVFY_SCAN		gettext("scanning for line <%s> found package <%s> zone <%s>")
#define	DBG_PUTPARAM_PUTCONDINFO_ENTRY	gettext("generating environment condition information")
#define	DBG_PUTPARAM_PUTCONDINFO_EXIT	gettext("environment condition information is <%s>")
#define	DBG_QUIT_REMOVING_PKGDIR	gettext("install not yet started and not updating existing: removing package directory <%s>")
#define	DBG_QUIT_REMOVING_PKGSAV	gettext("install started and updating existing: removing package temp directory <%s>")
#define	DBG_REMOVEPKGS_ARGS		gettext("npkgs <%d> nodelete <%d> longest pkg <%d> repeat <%d> pkgdir <%s> spooldir <%s>")
#define	DBG_REMOVEPKGS_ENTRY		gettext("remove_packages:")
#define	DBG_REMOVE_FLAG_VALUES		gettext("%s: admnflag <%d> doreboot <%d> failflag <%d> interrupted <%d> intrflag <%d> ireboot <%d> nullflag <%d> warnflag <%d>")
#define	DBG_REMOVE_PKGS_FROM_SPOOL	gettext("removing packages from spool directory <%s>")
#define	DBG_REMOVE_PKG_FROM_ZONE	gettext("removing package <%s> from zone <%s>")
#define	DBG_REMOVING_DSTREAM_PKGDIR	gettext("removing temporary stream <%s> for package <%s>")
#define	DBG_REMOVING_DSTREAM_TMPDIR	gettext("removing package datastream temporary directory <%s>")
#define	DBG_REMOVING_PKG_TMPDIR		gettext("removing temporary directory <%s> for package <%s>")
#define	DBG_REMOVING_ZONE_TMPDIR	gettext("removing zones temporary directory <%s>")
#define	DBG_RESTORE_ZONE_STATE		gettext("restoring state of zone <%s>")
#define	DBG_SETUP_TEMPDIR		gettext("created temporary directory <%s>")
#define	DBG_SKIPPING_ZONE		gettext("skipping processing of zone <%s>: zone not running")
#define	DBG_SKIPPING_ZONE_BOOT		gettext("not booting zone <%s>: zone is running")
#define	DBG_SKIPPING_ZONE_NOT_RUNNABLE	gettext("not booting zone <%s>: zone cannot be booted")
#define	DBG_SML_ADD_TAG			gettext("add element <%s> to tag <%s>")
#define	DBG_SML_CREATED_NEW_TAG_OBJECT	gettext("new tag <0x%08lx> name=<%s> created")
#define	DBG_SML_CREATE_NEW_TAG_OBJECT	gettext("create new tag name=<%s>")
#define	DBG_SML_DELETE_PARAM		gettext("delete parameter tag <%s> name <%s>: ")
#define	DBG_SML_DELETE_PARAM_FOUND	gettext("parameter <%s> value=<%s> - deleted")
#define	DBG_SML_DELETE_PARAM_NOT_FOUND	gettext("parameter <%s> not found - not deleted")
#define	DBG_SML_DELETE_PARAM_NO_PARAMS	gettext("tag contains no parameters - not deleted")
#define	DBG_SML_DEL_TAG			gettext("delete element <%s> from tag <%s>")
#define	DBG_SML_FREE_TAG		gettext("freeing tag <0x%08lx> name=<%s>")
#define	DBG_SML_GET_PARAM		gettext("get parameter <%s> tag <%s>")
#define	DBG_SML_GET_PARAM_BY_TAG	gettext("get param by tag name <%s> index <%d> param <%s>")
#define	DBG_SML_GET_PARAM_NAME		gettext("tag <%s> get parameter number <%d>")
#define	DBG_SML_GET_TAG_BY_NAME		gettext("get tag by name <%s> index <%d>")
#define	DBG_SML_GOT_PARAM		gettext("tag <%s> %s = <%s>")
#define	DBG_SML_GOT_PARAM_NAME		gettext("tag <%s> got parameter number <%d> name=<%s>")
#define	DBG_SML_HAVE_PARM_NAME		gettext("read tag: parameter name <%s> tag <%s>")
#define	DBG_SML_HAVE_PARM_VALUE		gettext("read tag: parameter %s=\"%s\" tag <%s>")
#define	DBG_SML_HAVE_TAG_NAME		gettext("read tag: open tag <%s>parent <%s>")
#define	DBG_SML_INT_FREE_PARAMS		gettext("freeing parameters at <0x%08lx>")
#define	DBG_SML_INT_FREE_PARAM_NAME	gettext("free param name <0x%08lx> name=<0x%08lx> value=<%s>")
#define	DBG_SML_INT_FREE_PARAM_VALUE	gettext("free param value <0x%08lx> name=<0x%08lx> value=<%s>")
#define	DBG_SML_INT_FREE_TAG		gettext("free tag <0x%08lx> name=<%s> param <%d> tags <%d>")
#define	DBG_SML_INT_FREE_TAGS		gettext("freeing tags at <0x%08lx>")
#define	DBG_SML_INT_FREE_TAG_NAME	gettext("freeing tag name <0x%08lx> name=<%s>")
#define	DBG_SML_LOADED_TAGS_FROM_STR	gettext("tag <0x%08lx> <%s> loaded from string")
#define	DBG_SML_ONE_TAG_READ		gettext("one tag read - tag <0x%08lx> name=<%s>")
#define	DBG_SML_PRINTTAG		gettext("dump of tag <%s> size <%d> bytes\n\n****************************************************************************\n%s****************************************************************************\n")
#define	DBG_SML_READTAG_BLANKLINE	gettext("read tag: blank line (no tag returned) at <%s>")
#define	DBG_SML_READTAG_CLOSED_TAG	gettext("read tag: closed tag <%s> inside tag <%s>")
#define	DBG_SML_READTAG_CLOSE_TAG	gettext("read tag: close tag <%s> found")
#define	DBG_SML_READTAG_EXPECTED_EOF	gettext("read tag: provider <%s> EOF outside of tag input")
#define	DBG_SML_READTAG_UNEXPECTED_EOF	gettext("read tag: provider <%s> unexpected EOF in middle of tag input")
#define	DBG_SML_READ_IN_TOP_TAG		gettext(" --> read in top tag <%s>")
#define	DBG_SML_READ_ONE_TAG		gettext("read one tag from <%s>")
#define	DBG_SML_READ_ONE_TAG_NOTAG	gettext("cannot read tag - no tag present")
#define	DBG_SML_READ_TAG		gettext("read tag: loading subtag for <%s>")
#define	DBG_SML_SET_PARAM		gettext("set parameter tag <%s> %s = <%s>: ")
#define	DBG_SML_SET_PARAM_CREATE_NEW	gettext("create new parameter")
#define	DBG_SML_SET_PARAM_LEAVE_ALONE	gettext("existing value=<%s> identical - not changed")
#define	DBG_SML_SET_PARAM_MODIFY	gettext("modify existing value=<%s>")
#define	DBG_SML_START_CLOSE_TAG		gettext("read tag: close tag found current tag=<%s>")
#define	DBG_SML_TAG_HEAD_DONE		gettext("read tag: tag <%s> started inside tag <%s>")
#define	DBG_SML_TAG_ONLY		gettext("read tag: line with tag name only tag <%s>")
#define	DBG_UNMOUNTING_DEV		gettext("unmounting package device <%s>")
#define	DBG_UNPACKCHECK_ARGS		gettext("idsname <%s> packagedir <%s>")
#define	DBG_UNPACKCHECK_ENTRY		gettext("unpack_and_check_packages:")
#define	DBG_UNPACKSTRM_ARGS		gettext("unpack package <%s> from stream <%s> into directory <%s>")
#define	DBG_UNPACKSTRM_ENTRY		gettext("unpack_package_from_stream:")
#define	DBG_UNPACKSTRM_UNPACKING	gettext("unpacking package <%s> from stream <%s> into temporary directory <%s>")
#define	DBG_VERIFY_SKIP_THISZONE	gettext("skipping dependency checking of package <%s>: marked this zone only")
#define	DBG_WRITEFILE_ENTRY		gettext("write file: control <0x%02x> mode <0%04lo> file <%s>")
#define	DBG_ZONES_SKIPPED		gettext("skipped <%d> zones that are not currently booted")
#define	DBG_ZONE_EXEC_ENTER		gettext("zone_exec: enter zone <%s> command <%s> args:")
#define	DBG_ZONE_EXEC_EXIT		gettext("zone_exec: exit zone <%s> command <%s> exit code <%d> stdout <%s>")

/*
 * I18N: these messages are error messages that can be displayed
 * during the normal usage of the products
 */

#define	ERR_ACCRESP			gettext("unable to access response file <%s>")
#define	ERR_ADMBD			gettext("%s is already installed at %s. Admin file will force a duplicate installation at %s.")
#define	ERR_ALLZONES_AND_G_USED		gettext("The -G option (install packages in the global zone only)\nmay not be used with package <%s> because the package must be\ninstalled in all zones.")
#define	ERR_ALLZONES_AND_IN_LZ		gettext("The package <%s> may only be installed by the global zone administrator")
#define	ERR_ALLZONES_AND_IN_LZ_PKGRM	gettext("The package <%s> may only be removed by the global zone administrator")
#define	ERR_ALLZONES_AND_THISZONE	gettext("The package <%s> has <%s> = true and <%s> = true: the package may set either parameter to true, but may not set both parameters to true. NOTE: if the package contains a request script, it is treated as though it has <SUNW_PKG_THISZONE> = true")
#define	ERR_ARG				gettext("URL <%s> is not valid")
#define	ERR_BADULIMIT  			gettext("cannot process invalid ULIMIT value of <%s>.")
#define	ERR_BADUSER			gettext("unable to find user <%s> or <%s>.")
#define	ERR_BAD_DEVICE			gettext("bad device <%s> specified")
#define	ERR_BAD_N_PKGRM			gettext("you must specify a category (-Y) or list of packages to remove")
#define	ERR_BRAND_GETBRAND		gettext("unable to get zone brand: zonecfg_get_brand: %s")
#define	ERR_CANNOT_BOOT_ZONE		gettext("no changes made to zone <%s>: unable to boot zone")
#define	ERR_CANNOT_CKSUM_FILE		gettext("unable to determine checksum of file <%s>: %s")
#define	ERR_CANNOT_CONVERT_PKGSTRM	gettext("unable to convert package <%s> to stream from <%s> to <%s>")
#define	ERR_CANNOT_COPY			gettext("unable to copy <%s>\n\tto <%s>")
#define	ERR_CANNOT_COPY_LOCAL		gettext("cannot obtain local copy of <%s>: (%d) %s")
#define	ERR_CANNOT_CREATE_PKGPATH	gettext("unable to create package path <%s>")
#define	ERR_CANNOT_GET_ZONE_LIST	gettext("unable to determine list of non-global zones installed on this system")
#define	ERR_CANNOT_LOCK_THIS_ZONE	gettext("Unable to lock this zone for administration")
#define	ERR_CANNOT_LOCK_ZONES		gettext("unable to lock zones to perform operations")
#define	ERR_CANNOT_OPEN_DEPEND_FILE	gettext("unable to open depend file <%s>: %s")
#define	ERR_CANNOT_OPEN_FOR_WRITING	gettext("unable to open <%s> for writing: %s")
#define	ERR_CANNOT_OPEN_PKG_STREAM	gettext("unable to open package datastream <%s>")
#define	ERR_CANNOT_UNPACK_PKGSTRM	gettext("unable to unpack package <%s> from stream <%s> into directory <%s>")
#define	ERR_CANNOT_USE_DIR		gettext("cannot use directory <%s>: %s")
#define	ERR_CASFAIL			gettext("class action script did not complete successfully")
#define	ERR_CAT_FND			gettext("Category argument <%s> cannot be found.")
#define	ERR_CAT_INV			gettext("Category argument <%s> is invalid.")
#define	ERR_CAT_LNGTH			gettext("The category argument exceeds the SVR4 ABI defined maximum supported length of 16 characters.")
#define	ERR_CAT_SYS			gettext("Unable to remove packages that are part of the SYSTEM category with the -Y option.")
#define	ERR_CFBAD			gettext("bad entry read of contents file")
#define	ERR_CFMISSING			gettext("missing entry in contents file for <%s>")
#define	ERR_CHDIR			gettext("unable to change current working directory to <%s>")
#define	ERR_CHGDIR			gettext("unable to change directory to <%s>")
#define	ERR_CHKINSTALL 			gettext("checkinstall script did not complete successfully")
#define	ERR_CHKINSTALL_NOSCRIPT		gettext("unable to access checkinstall script <%s>")
#define	ERR_CHMOD			gettext("unable to change the mode of the response file <%s>")
#define	ERR_CHMOD_CHK 			gettext("unable to change the mode of the checkinstall script")
#define	ERR_CLASSES			gettext("CLASSES parameter undefined in <%s>")
#define	ERR_CLIDX			gettext("invalid class index of <%d> detected for file %s.")
#define	ERR_COPY_MEMORY			gettext("unable to allocate memory to copy file <%s>: (%d) %s")
#define	ERR_CORRUPT			gettext("source path <%s> is corrupt")
#define	ERR_COULD_NOT_INSTALL		gettext("%s could not be installed.")
#define	ERR_CREATE_PATH_2		gettext("unable to create path from <%s> and <%s>")
#define	ERR_CREATE_PATH_3		gettext("unable to create path from <%s> and <%s> and <%s>")
#define	ERR_CREATE_PKGOBJ		gettext("unable to create package object <%s>.")
#define	ERR_CREATE_TMPADMIN		gettext("unable to create temporary admin file <%s>: %s")
#define	ERR_CREAT_CONT 			gettext("unable to create contents file <%s>")
#define	ERR_CRERESP			gettext("unable to create response file <%s>")
#define	ERR_DB				gettext("unable to query or modify database")
#define	ERR_DB_QUERY			gettext("unable to find <%s> in the database.")
#define	ERR_DB_TBL			gettext("unable to remove database entries for package <%s> in table <%s>.")
#define	ERR_DEPENDENCY_IGNORED		gettext("\nERROR: %s <%s> on %s <%s>\n")
#define	ERR_DEPENDENCY_REPORT		gettext("\nERROR: <%s> %s <%s> on %s <%s>\n")
#define	ERR_DEPNAM			gettext("The <%s> package \"%s\" depends on the package currently being removed.")
#define	ERR_DEPONME			gettext("The <%s> package depends on the package currently being removed.")
#define	ERR_DIR_CONST			gettext("unable to construct download directory <%s>")
#define	ERR_DSARCH			gettext("unable to find archive for <%s> in datastream")
#define	ERR_DSINIT			gettext("could not process datastream from <%s>")
#define	ERR_DSTREAM			gettext("unable to unpack datastream")
#define	ERR_DSTREAMCNT 			gettext("datastream early termination problem")
#define	ERR_FCHMOD			gettext("unable to change mode of file <%s> to <0x%04lx>: (%d) %s")
#define	ERR_FINALCK_ATTR		gettext("ERROR: attribute verification of <%s> failed")
#define	ERR_FINALCK_CONT		gettext("ERROR: content verification of <%s> failed")
#define	ERR_FSYS_FELLOUT		gettext("fsys(): fell out of loop looking for <%s>")
#define	ERR_F_REQUIRES_M		gettext("the -f option must be used in conjunction with the -m option")
#define	ERR_FSTAT			gettext("unable to fstat fd <%d> pathname <%s>: (%d) %s")
#define	ERR_GPKGLIST_ERROR		gettext("unable to determine list of packages to operate on (internal error in gpkglist)")
#define	ERR_GZ_USED_TOGETHER		gettext("the -G and zonelist options cannot be used together")
#define	ERR_INCOMP_VERS			gettext("A version of <%s> package \"%s\" (which is incompatible with the package that is being installed) is currently installed and must be removed.")
#define	ERR_INPUT			gettext("error while reading file <%s>: (%d) %s")
#define	ERR_INSTALL_ZONES_SKIPPED	gettext("unable to boot <%d> zones that are not currently running - no packages installed on those zones")
#define	ERR_INTONLY			gettext("unable to install <%s> without user interaction")
#define	ERR_INTR			gettext("Interactive request script supplied by package")
#define ERR_INVALID_O_OPTION            gettext("option <%s> passed to -O is not recognized: option ignored")
#define	ERR_IN_GZ_AND_ALLZONES_AND_INSTALLED	gettext("The package <%s> is currently installed on\nthe system in the global zone only.  When this package was last installed\nthe -G option was used (install package in the global zone only).  The new\ninstance of this package to be installed may only be installed in all zones.\nBefore you can install the latest version of this package, you must first\nremove all instances of this package from the global zone (via pkgrm).")
#define	ERR_IN_GZ_AND_NOT_INSTALLED		gettext("WARNING: The package <%s> is marked as being installed in the\nglobal zone only. The package is NOT installed on the system. This condition\nis not possible. The file <%s> must be edited\nand the line for this package removed.")
#define	ERR_IN_GZ_AND_NO_G_USED		gettext("The package <%s> is currently installed on the system in the\nglobal zone. To install the new instance of this package in the global\nzone only, you must specify the -G option. To install the new instance\nof this package in all zones you must first remove the existing instance\nof this package from the global zone first (via pkgrm) and then install\nthe new instance of this package in all zones.")

#define	ERR_LINK			gettext("unable to link <%s> to <%s>: %s")
#define	ERR_LIVE_CONTINUE_NOT_SUPPORTED	gettext("live continue mode is not supported")
#define	ERR_LOCKFILE			gettext("unable to create lockfile <%s>")
#define	ERR_LOG				gettext("unable to open logfile <%s>: (%d) %s")
#define	ERR_LOG_FAIL			gettext("failed to log message using format <%s>")
#define	ERR_MALLOC			gettext("unable to allocate %s memory, errno %d: %s")
#define	ERR_MAPFAILED			gettext("unable to mmap <%s> for reading: (%d) %s")
#define	ERR_MEM				gettext("unable to allocate memory.")
#define	ERR_MEMORY	 		gettext("memory allocation failure, errno=%d")
#define	ERR_MERGINFOS_CHANGE_ZONEATTR	gettext("attempt to change package <%s> version <%s> package zone attribute <%s> from <%s> to <%s>: the package zone attribute values of installed packages cannot be changed")
#define	ERR_MERGINFOS_UNSET_ZONEATTR	gettext("attempt to unset package <%s> version <%s> package zone attribute <%s> from <%s>: the package zone attribute values of installed packages that are set to <true> cannot be unset")
#define	ERR_MERGINFOS_SET_ZONEATTR	gettext("attempt to set package <%s> version <%s> package zone attribute <%s> that is not currently set to <%s>: the package zone attribute values of installed packages cannot be set to any value except <false>")
#define	ERR_MISSING_DIR_AND_PKG		gettext("missing directory containing package to install and package instance (name of package ) to install from end of command line")
#define	ERR_MISSING_PKG_INSTANCE	gettext("missing package instance (name of package) to install from end of command line")
#define	ERR_MKDIR			gettext("unable to make temporary directory <%s>")
#define	ERR_MAKE_DIR			gettext("unable to create directory <%s>: (%d) %s")
#define	ERR_MKTEMP			gettext("unable to create unique temporary file <%s>: (%d) %s")
#define	ERR_MNT_NOMOUNTS		gettext("get_mntinfo() could find no filesystems")
#define	ERR_MNT_NOROOT			gettext("get_mntinfo() identified <%s> as root file system instead of <%s> errno %d: %s")
#define	ERR_MODTIM			gettext("unable to reset access/modification time of <%s>: (%d) %s")
#define	ERR_NEWBD			gettext("%s is already installed at %s. Duplicate installation attempted at %s.")
#define	ERR_NODIR			gettext("unable to create directory <%s>: (%d) %s")
#define	ERR_NORESPCOPY			gettext("unable to copy response file <%s> to <%s>")
#define	ERR_NODEVICE			gettext("unable to determine device to install from")
#define	ERR_NOINT			gettext("-n option cannot be used when removing pre-SVR4 packages")
#define	ERR_NOPKGS			gettext("no packages were found in <%s>")
#define	ERR_NOREQUEST  			gettext("package does not contain an interactive request script")
#define	ERR_NORESP			gettext("response file <%s> must not exist")
#define	ERR_NOTABLE			gettext("unable to open %s table <%s>: %s")
#define	ERR_NOT_ROOT			gettext("You must be \"root\" for %s to execute properly.")
#define	ERR_NOW_ALLZONES_AND_HOLLOW	gettext("The package <%s> has <%s> = false and <%s> = true: a hollow package must also be set to install in all zones")
#define	ERR_NO_LIVE_MODE		gettext("live continue mode is not supported")
#define	ERR_NO_PKGDIR			gettext("unable to use package directory <%s> for package <%s>: %s")
#define	ERR_NO_PKG_INFOFILE		gettext("unable to open package <%s> pkginfo file <%s>: %s")
#define	ERR_NO_PKG_MAPFILE		gettext("unable to open package <%s> pkgmap file <%s>: %s")
#define	ERR_NO_SUCH_INSTANCE		gettext("instance <%s> does not exist")
#define	ERR_OPEN_ADMIN_FILE		gettext("unable to open admin file <%s>: %s")
#define	ERR_OPEN_READ			gettext("unable to open <%s> for reading: (%d) %s")
#define	ERR_OPEN_WRITE			gettext("unable to open <%s> for writing: (%d) %s")
#define	ERR_OPRESVR4			gettext("unable to unlink options file <%s>")
#define	ERR_OUTPUT_WRITING		gettext("error while writing file <%s>: (%d) %s")
#define	ERR_PACKAGEBINREN		gettext("unable to rename <%s>\n\tto <%s>")
#define	ERR_PATH			gettext("the path <%s> is invalid!")
#define	ERR_PKGABRV			gettext("illegal package abbreviation <%s> in dependency file")
#define	ERR_PKGADDCHK_CNFFAILED		gettext("Conflicting file dependency checking failed.")
#define	ERR_PKGADDCHK_DEPFAILED		gettext("Dependency checking failed.")
#define	ERR_PKGADDCHK_MKPKGDIR		gettext("Unable to make required packaging directory")
#define	ERR_PKGADDCHK_PRIVFAILED	gettext("Privilege checking failed.")
#define	ERR_PKGADDCHK_SPCFAILED		gettext("Space checking failed.")
#define	ERR_PKGASK_AND_NOINTERACT	gettext("cannot use the -n option with pkgask")
#define	ERR_PKGASK_AND_SPOOLDIR		gettext("cannot use the -s option with pkgask")
#define	ERR_PKGBINCP			gettext("unable to copy <%s>\n\tto <%s>")
#define	ERR_PKGBINREN  			gettext("unable to rename <%s>\n\tto <%s>")
#define	ERR_PKGINFO			gettext("unable to open pkginfo file <%s>")
#define	ERR_PKGINFO_ATTR_ADDED		gettext("package <%s> is attempting to add the package attribute <%s>: this attribute cannot be added once the package is installed")
#define	ERR_PKGINFO_ATTR_CHANGED	gettext("package <%s> is attempting to change the package attribute <%s> from <%s> to <%s>: this attribute cannot be changed once the package is installed")
#define	ERR_PKGINSTALL_GZONLY_ADD	gettext("unable to add package <%s> to global zone only package list file")
#define	ERR_PKGINSTALL_STATOF		gettext("unable to get space usage of <%s>: %s")
#define	ERR_PKGINSTALL_STATVFS		gettext("unable to determine file system space for <%s>: %s")
#define	ERR_PKGMAP			gettext("unable to open pkgmap file <%s>")
#define	ERR_PKGOPS_CANNOT_OPEN_GZONLY	gettext("unable to open global zone only package list file at <%s>")
#define	ERR_PKGOPS_LOCHIGH_BAD_PKGNAME	gettext("package name is not valid: %s")
#define	ERR_PKGOPS_OPEN_GZONLY		gettext("unable to open global zone only package list file <%s>: %s")
#define	ERR_PKGOPS_TMPOPEN		gettext("unable to create temporary global zone only package list file <%s>: %s")
#define	ERR_PKGREMOVE_GZONLY_REMOVE	gettext("unable to remove package <%s> from global zone only package list file")
#define	ERR_PKGRMCHK_DEPFAILED		gettext("Dependency checking failed.")
#define	ERR_PKGRMCHK_PRIVFAILED		gettext("Privilege checking failed.")
#define	ERR_PKGS_AND_CAT_PKGADD		gettext("cannot specify both a list of packages and a category (-Y) to install")
#define	ERR_PKGS_AND_CAT_PKGRM		gettext("cannot specify both a list of packages and a category (-Y) to remove")
#define	ERR_PKGUNMOUNT			gettext("unable to unmount <%s>")
#define	ERR_PKGVOL			gettext("unable to obtain package volume")
#define	ERR_PKGZONEINSTALL_NO_STREAM	gettext("internal error - package to install in zone not in stream format")
#define	ERR_PKG_NOT_APPLICABLE		gettext("package <%s> cannot be installed on this system/zone")
#define	ERR_PKG_NOT_INSTALLABLE		gettext("unable to install package <%s>")
#define	ERR_PKG_NOT_REMOVABLE		gettext("unable to remove package <%s>")
#define	ERR_POSTINSTALL			gettext("postinstall script did not complete successfully")
#define	ERR_POSTREMOVE			gettext("postremove script did not complete successfully")
#define	ERR_PREINSTALL 			gettext("preinstall script did not complete successfully")
#define	ERR_PREIVFY_NOFILE		gettext("unable to perform preinstallation check of package <%s> in zone <%s>")
#define	ERR_PREIVFY_OPEN_FILE		gettext("unable to examine preinstallation check file <%s> for package <%s> in zone <%s>: %s")
#define	ERR_PREIVFY_UNKNOWN_LINE	gettext("unknown preinstallation dependency check line <%s> for package <%s> zone <%s>: ignored")
#define	ERR_PRENCI			gettext("The <%s> package \"%s\" is a prerequisite package and is not completely installed.")
#define	ERR_PREREMOVE			gettext("preremove script did not complete successfully")
#define	ERR_PREREQ			gettext("The <%s> package \"%s\" is a prerequisite package and should be installed.")
#define	ERR_PRERVFY_NOFILE		gettext("unable to perform preremoval check of package <%s> in zone <%s>")
#define	ERR_PRERVFY_OPEN_FILE		gettext("unable to examine preremoval check file <%s> for package <%s> in zone <%s>: %s")
#define	ERR_PRERVFY_UNKNOWN_LINE	gettext("unknown preremoval dependency check line <%s> for package <%s> zone <%s>: ignored")
#define	ERR_RDONLY			gettext("read-only parameter <%s> cannot be assigned a value")
#define	ERR_READ			gettext("unable to read <%s>: (%d) %s")
#define	ERR_REMOVE			gettext("unable to remove file <%s>: %s")
#define	ERR_RENAME			gettext("unable to rename <%s> to <%s>: %s")
#define	ERR_REQUEST			gettext("request script did not complete successfully")
#define	ERR_RESOLVEPATH			gettext("unable to resolve path <%s>: %s")
#define	ERR_RESPFILE			gettext("response file is invalid for pre-SVR4 package")
#define	ERR_RESPONSE			gettext("unable to open response file <%s>")
#define	ERR_RMDIR			gettext("unable to remove existing directory at <%s>")
#define	ERR_RMPATH			gettext("unable to remove <%s>")
#define	ERR_RMRESP			gettext("unable to remove response file <%s>")
#define	ERR_ROOT_CMD			gettext("Command line install root contends with environment.")
#define	ERR_ROOT_SET   			gettext("Could not set install root from the environment.")
#define	ERR_RSP_FILE_NOTFULLPATH	gettext("response file <%s> must be full pathname")
#define	ERR_RSP_FILE_NOT_GIVEN		gettext("response file (to write) is required")
#define	ERR_RUNSTATE			gettext("unable to determine current run-state")
#define	ERR_SCRULIMIT			gettext("script <%s> created a file exceeding ULIMIT.")
#define	ERR_SML_CANNOT_READ_TAG						gettext("cannot read tag")
#define	ERR_SML_EOF_BEFORE_TAG_NAME					gettext("reading tag: unexpected EOF before reading tag name expecting tag=<%s>")
#define	ERR_SML_PARM_SEP_BAD						gettext("reading tag: parameter value start found <%c> (0x%02x) expected '\"'")
#define	ERR_SML_READTAG_BADPARMNAME_CLOSE				gettext("reading tag: expected '>' after '/' to close parm <%s> tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_BADTAG_CLOSE					gettext("reading tag: expected '>' after '/' to close tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_BAD_START_CHAR					gettext("reading tag: invalid character <%c> (0x%02x) before start of tag")
#define	ERR_SML_READTAG_CLOSE_EMPTY_TAG					gettext("reading tag: no element name provided before close of tag")
#define	ERR_SML_READTAG_CLOSE_NO_PARENT					gettext("reading tag: close tag <%s> not within any tag to close")
#define	ERR_SML_READTAG_CLOSE_TAG_EOF					gettext("reading tag: unexpected EOF reading close tag name expecting tag=<%s>")
#define	ERR_SML_READTAG_CLOSE_TAG_ILLCHAR				gettext("reading tag: invalid character <%c> (0x%02x) in close tag name <%s>")
#define	ERR_SML_READTAG_CLOSE_WRONG_TAG					gettext("reading tag: close tag <%s> does not match current tag <%s>")
#define	ERR_SML_READTAG_EMPTY_PARMNAME					gettext("reading tag: no parameter name provided tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_EMPTY_TAG					gettext("reading tag: no element name provided before close of tag inside tag <%s>")
#define	ERR_SML_READTAG_PARMNAME_ILLCHAR				gettext("reading tag: invalid character <%c> (0x%02x) in parameter name <%s> tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_PARMVAL_EOF					gettext("reading tag: unexpected EOF reading parameter value name <%s> tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_PARMVAL_NL					gettext("reading tag: unexpected newline reading parameter value name <%s> tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_PARM_EOF					gettext("reading tag: unexpected EOF reading parameter name tag <%s> inside tag <%s>")
#define	ERR_SML_READTAG_TAG_EOF						gettext("reading tag: unexpected EOF reading tag name <%s> inside tag <%s>")
#define	ERR_SML_READTAG_TAG_ILLCHAR					gettext("reading tag: invalid character <%c> (0x%02x) in tag name <%s>")
#define	ERR_SNPRINTF			gettext("Not enough memory to format, %s")
#define	ERR_SPOOLDIR_AND_ADMNFILE	gettext("cannot use the -s option with the -a option")
#define	ERR_SPOOLDIR_AND_INST_ROOT	gettext("cannot use the -s option with the -R option")
#define	ERR_SPOOLDIR_AND_NOINTERACT	gettext("cannot use the -s option with the -n option")
#define	ERR_SPOOLDIR_AND_PKGRMREMOTE	gettext("cannot use the -s option with the -A option")
#define	ERR_SPOOLDIR_AND_PKGVERBOSE	gettext("cannot use the -s option with the -v option")
#define	ERR_SPOOLDIR_AND_RESPFILE	gettext("cannot use the -s option with the -r option")
#define	ERR_SPOOLDIR_CANNOT_BE_SYS	gettext("the -s option cannot specify %s")
#define	ERR_SPOOLDIR_USED_WITH_G	gettext("the -G option cannot be used with the -s option")
#define	ERR_SPOOLDIR_USED_WITH_Z	gettext("the zonelist option cannot be used with the -s option")
#define	ERR_STAT			gettext("unable to stat <%s>: %s")
#define	ERR_STREAMDIR			gettext("unable to make temporary directory to unpack datastream: %s")
#define	ERR_STREAM_UNAVAILABLE		gettext("unable to open stream <%s> for package <%s>: %s")
#define	ERR_SYSINFO			gettext("unable to process installed package information, errno=%d")
#define	ERR_TMPFILE			gettext("unable to establish temporary file")
#define	ERR_TMPFILE_CHK			gettext("unable to create temporary checkinstall script")
#define	ERR_TMPRESP			gettext("unable to create temporary response file")
#define	ERR_TOO_MANY_CMD_ARGS		gettext("too many arguments to command")
#define	ERR_TOO_MANY_PKGS		gettext("too many packages referenced specified at the end of the command line: only one package may be specified")
#define	ERR_UNKNOWN_DEPENDENCY		gettext("unknown dependency type specified: %c\n")
#define	ERR_UNKNOWN_DEV			gettext("unknown device <%s>")
#define	ERR_UNPACK_DSREAD		gettext("unable to read part <%d> of stream <%s> to directory <%s> for package <%s>")
#define	ERR_UNPACK_FMKDIR		gettext("unable to create temporary package area <%s>: %s")
#define	ERR_UNSUCC			gettext("(A previous attempt may have been unsuccessful.)")

#define	ERR_USAGE_PKGADD_GLOBALZONE	gettext("usage:\n\t%s [-nv] [-d device] [[-M] -R host_path] [-V fs_file] [-a admin_file] [-r response] [-G] [-Y category[,category ...] | pkg [pkg ...]]\n\t%s -s dir [-d device] [-G] [-Y category[,category ...] | pkg [pkg ...]]\n")
#define	ERR_USAGE_PKGADD_NONGLOBALZONE	gettext("usage:\n\t%s [-nv] [-d device] [[-M] -R host_path] [-V fs_file] [-a admin_file] [-r response] [-Y category[,category ...] | pkg [pkg ...]]\n\t%s -s dir [-d device] [-Y category[,category ...] | pkg [pkg ...]]\n")
#define	ERR_USAGE_PKGASK		gettext("usage: %s -r response [-d device]  [-R host_path] [-Y category[,category ...]] | [pkg [pkg ...]]\n")
#define	ERR_USAGE_PKGINSTALL  		gettext("usage:\n\tpkginstall [-o] [-n] [-d device] [-m mountpt [-f fstype]] [-v] [[-M] -R host_path] [-V fs_file] [-b bindir] [-a admin_file] [-r resp_file] [-N calling_prog] directory pkginst\n")
#define	ERR_USAGE_PKGREMOVE		gettext("usage:\n\tpkgremove [-a admin_file] [-n] [-V ...] [[-M|-A] -R host_path] [-v] [-o] [-N calling_prog] pkginst\n")
#define	ERR_USAGE_PKGRM  		gettext("usage:\n\t%s [-a admin] [-n] [[-M|-A] -R host_path] [-V fs_file] [-v] [-Y category[,category ...] | pkg [pkg ...]]\n\t%s -s spool [-Y category[,category ...] | pkg [pkg ...]]\n")
#define	ERR_VALINST			gettext(" Allowable instances include (in order of preference:)\n")
#define	ERR_V_USED_AND_PKGRMREMOTE	gettext("cannot use the -V option with the -A option")
#define	ERR_V_USED_WITH_GZS		gettext("cannot use the -V option when non-global zones exist")
#define	ERR_WARNING			gettext("WARNING:")
#define	ERR_WRITE			gettext("unable to write <%s>: (%d) %s")
#define	ERR_WTMPFILE			gettext("unable to write temporary file <%s>")
#define	ERR_ZONETEMPDIR			gettext("unable to make temporary directory for non-global zone operations in directory <%s>: %s")
#define	ERR_Z_USED_IN_NONGLOBAL_ZONE	gettext("the zonelist option may not be used in a non-global zone")
#define	ERR_CANNOT_ENABLE_LOCAL_FS	gettext("Failed to enable the filesystem/local service.\n")
#define	ERR_CANNOT_RESTORE_LOCAL_FS	gettext("Failed to bring the filesystem/local service back to its original state.\n")

/*
 * I18N: these messages are help messages that are displayed when the
 * user answers a question with "?" - asking for help to be displayed
 */

#define	HLP_PKGADDCHK_CONFLICT		gettext("If you choose to install conflicting files, the files listed above will be overwritten and/or have their access permissions changed.  If you choose not to install these files, installation will proceed but these specific files will not be installed.  Note that sane operation of the software being installed may require these files be installed; thus choosing to not to do so may cause inappropriate operation.  If you wish to stop installation of this package, enter 'q' to quit.")
#define	HLP_PKGADDCHK_CONT		gettext("If you choose 'y', installation of this package will continue.  If you want to stop installation of this package, choose 'n'.")
#define	HLP_PKGADDCHK_DEPEND		gettext("The package being installed has indicated a dependency on the existence (or non-existence) of another software package.  If this dependency is not met before continuing, the package may not install or operate properly.  If you wish to disregard this dependency, answer 'y' to continue the installation process.")
#define	HLP_PKGADDCHK_PARTIAL		gettext("Installation of partially installed packages is normally allowable, but some packages providers may suggest that a partially installed package be completely removed before re-attempting installation.  Check the documentation provided with this package, and then answer 'y' if you feel it is advisable to continue the installation process.")
#define	HLP_PKGADDCHK_PRIV		gettext("During the installation of this package, certain scripts provided with the package will execute with super-user permission.  These scripts may modify or otherwise change your system without your knowledge.  If you are certain of the origin and trustworthiness of the package being installed, answer 'y' to continue the installation process.")
#define	HLP_PKGADDCHK_SETUID		gettext("The package being installed appears to contain processes which will have their effective user or group ids set upon execution.  History has shown that these types of processes can be a source of security problems on your system.  If you choose not to install these as setuid files, installation will proceed but these specific files will be installed as regular files with setuid and/or setgid permissions reset.  Note that sane operation of the software being installed may require that these files be installed with setuid or setgid permissions as delivered; thus choosing to install them as regular files may cause inappropriate operation.  If you wish to stop installation of this package, enter 'q' to quit.")
#define	HLP_PKGADDCHK_SPACE		gettext("It appears that there is not enough free space on your system in which to install this package.  It is possible that one or more filesystems are not properly mounted.  Neither installation of the package nor its operation can be guaranteed under these conditions.  If you choose to disregard this warning, enter 'y' to continue the installation process.")
#define	HLP_PKGREMOVE_DEPEND	gettext("Other packages currently installed on the system have indicated a dependency on the package being removed.  If removal of this package occurs, it may render other packages inoperative.  If you wish to disregard this dependency, answer 'y' to continue the package removal process.")
#define	HLP_PKGREMOVE_PRIV	gettext("During the removal of this package, certain scripts provided with the package will execute with super-user permission.  These scripts may modify or otherwise change your system without your knowledge.  If you are certain of the origin of the package being removed and trust its worthiness, answer 'y' to continue the package removal process.")
#define	HLP_PKGREMOVE_RUNLEVEL	gettext("If this package is not removed in a run-level which has been suggested, it is possible that the package may not remove properly.  If you wish to follow the run-level suggestions, answer 'n' to stop the package removal process.")
#define	HLP_PKGRMCHK_DEPEND		gettext("The package being removed has indicated a dependency on the existence (or non-existence) of another software package.  If this dependency is not met before continuing, the package may not remove or operate properly.  If you wish to disregard this dependency, answer 'y' to continue the removal process.")
#define	HLP_PKGRMCHK_PRIV		gettext("During the removal of this package, certain scripts provided with the package will execute with super-user permission.  These scripts may modify or otherwise change your system without your knowledge.  If you are certain of the origin and trustworthiness of the package being removed, answer 'y' to continue the removal process.")

#define	INFO_INSTALL			gettext("\nThe following package is currently installed:")
#define	INFO_RMSPOOL			gettext("\nRemoving spooled package instance <%s>")
#define	INFO_SPOOLED			gettext("\nThe following package is currently spooled:")

#define	LOG_GETVOL_RET			gettext("getvol() returned <%d>")

#define	MSG_1MORETODO			gettext("\nThere is 1 more package to be removed.")
#define	MSG_1MORE_INST			gettext("\nThere is 1 more package to be installed.")
#define	MSG_1MORE_PROC			gettext("\nThere is 1 more package to be processed.")
#define	MSG_1_PKG_NOT_PROCESSED		gettext("\n1 package was not processed!\n")
#define	MSG_ATTRIB			gettext("%s <attribute change only>")
#define	MSG_BASE_USED   		gettext("Using <%s> as the package base directory.")
#define	MSG_BOOTING_ZONE		gettext("## Booting non-running zone <%s> into administrative state")
#define	MSG_BYPASSING_ZONE		gettext("## pkgask - bypassing zone <%s>")
#define	MSG_CHECKINSTALL_INTERRUPT_B4_Z	gettext("## interrupted: package <%s> not installed")
#define	MSG_CHECKINSTALL_PKG_IN_ZONE	gettext("## Verifying package <%s> dependencies in zone <%s>")
#define	MSG_CHECKREMOVE_PKG_IN_GZ	gettext("## Verifying package <%s> dependencies in global zone")
#define	MSG_CHECKREMOVE_PKG_IN_ZONE	gettext("## Verifying package <%s> dependencies in zone <%s>")
#define	MSG_DBUPD_N_N			gettext("## Database update of part %d of %d is complete.")
#define	MSG_DBUPD_N_N_LZ		gettext("## Database update of part %d of %d in zone <%s> is complete.")
#define	MSG_DIRBUSY			gettext("%s <mount point not removed>")
#define	MSG_DOREMOVE_INTERRUPTED	gettext("## interrupted: package <%s> not installed")
#define	MSG_DOREMOVE_INTERRUPTED_B4_Z	gettext("## interrupted: package <%s> not removed")
#define	MSG_DRYRUN_DONE			gettext("Dryrun complete.")
#define	MSG_HRDLINK			gettext("%s <linked pathname>")
#define	MSG_IMPDIR			gettext("%s <implied directory>")
#define	MSG_INSERT_VOL			gettext("Insert %v into %p.")
#define	MSG_INSTALLING_PKG_IN_GZ	gettext("## Installing package <%s> in global zone")
#define	MSG_INSTALL_INTERRUPT_B4_ZONES	gettext("## Interrupted: package <%s> not installed in any non-global zones")
#define	MSG_INSTALL_PKG_IN_ZONE		gettext("## Installing package <%s> in zone <%s>")
#define	MSG_INST_MANY  			gettext("   %d package pathnames are already properly installed.")
#define	MSG_INST_N_N			gettext("## Installation of part %d of %d is complete.")
#define	MSG_INST_N_N_LZ			gettext("## Installation of part %d of %d in zone <%s> is complete.")
#define	MSG_INST_ONE			gettext("   %d package pathname is already properly installed.")
#define	MSG_INS_N_N			gettext("## Installing part %d of %d.")
#define	MSG_INS_N_N_LZ			gettext("## Installing part %d of %d in zone <%s>.")
#define	MSG_IS_PRESENT			gettext("%s <already present on Read Only file system>")
#define	MSG_LOG_ERROR			gettext("ERROR")
#define	MSG_LOG_WARNING			gettext("WARNING")
#define	MSG_LOG_DEBUG			gettext("DEBUG")
#define	MSG_MANMOUNT			gettext("Assuming mounts have been provided.")
#define	MSG_MORETODO			gettext("\nThere are %d more packages to be removed.")
#define	MSG_MORE_INST			gettext("\nThere are %d more packages to be installed.")
#define	MSG_MORE_PROC			gettext("\nThere are %d more packages to be processed.")
#define	MSG_NOCHANGE			gettext("No changes were made to the system.")
#define	MSG_NODENAME			gettext("(unknown)")
#define	MSG_NOTEMPTY			gettext("%s <non-empty directory not removed>")
#define	MSG_N_PKGS_NOT_PROCESSED	gettext("\n%d packages were not processed!\n")
#define	MSG_PKGADDCHK_ABADFILE		gettext("\\nPackaging file <%s> is corrupt for %s <%s> on %s <%s>")
#define	MSG_PKGADDCHK_BADFILE		gettext("\\nPackaging files are corrupt for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_CFCONTENT		gettext("\\nThe file <%s> is already installed and in use by %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_CKRUNLVL		gettext("\\nThe current run-level of this machine is <s%>, which is not a run-level suggested for installation of the %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_CNFFAILED		gettext("\\nConflict checking issues for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_DEPEND		gettext("\\nDependency checking issues for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_DIRS 		gettext("\\nThe required packaging directory <%s> cannot be created or accessed for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_NEWONLY		gettext("\\nA version of %s <%s> is already installed on %s <%s>.  Current administration does not allow new instances of an existing package to be created, nor existing instances to be overwritten.")
#define	MSG_PKGADDCHK_OVERWRITE		gettext("\\nCurrent administration does not allow new instances of a %s <%s> on %s <%s> to be created. However, the installation service was unable to determine which package instance to overwrite.")
#define	MSG_PKGADDCHK_PARTINST		gettext("\\nThe installation of %s <%s> on %s <%s> previously terminated and installation was never successfully completed.")
#define	MSG_PKGADDCHK_PARTREM		gettext("\\nThe removal of %s <%s> on %s <%s> was terminated at some point in time, and package removal was only partially completed.")
#define	MSG_PKGADDCHK_PKGDIRS		gettext("\\nA required packaging directory cannot be created or accessed for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_PRENCI 		gettext("\\nThe package <%s> is a prerequisite package and is not completely installed for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_PREREQ 		gettext("\\nThe package <%s> is a prerequisite package and should be installed for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_PRIV		gettext("\\nThe %s <%s> contains scripts which will be executed on %s <%s> with super-user permission during the process of installing this package.")
#define	MSG_PKGADDCHK_RUNLEVEL		gettext("\\n run level <%s> for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_SAME		gettext("\\nThis appears to be an attempt to install the same architecture and version of %s <%s> which is already installed on %s <%s>.  This installation will attempt to overwrite this package.\\n")
#define	MSG_PKGADDCHK_SETUID		gettext("\\nFiles that are setuid and/or setgid will be installed and/or modified for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_SPCFAILED		gettext("\\nSpace checking failed for %s <%s> on %s <%s>.")
#define	MSG_PKGADDCHK_UNIQ1		gettext("\\nCurrent administration requires that a unique instance of %s <%s> on %s <%s> be created.  However, the maximum number of instances of the package which may be supported at one time on the same system has already been met.")
#define	MSG_PKGINSTALL_DRYRUN		gettext("\nDryrunning install of %s as <%s>\n")
#define	MSG_PKGINSTALL_EXECOC_GZ	gettext("## Executing checkinstall script.")
#define	MSG_PKGINSTALL_EXECOC_LZ	gettext("## Executing checkinstall script in zone <%s>.")
#define	MSG_PKGINSTALL_EXEPIC_GZ	gettext("## Executing postinstall script.")
#define	MSG_PKGINSTALL_EXEPIC_LZ	gettext("## Executing postinstall script in zone <%s>.")
#define	MSG_PKGINSTALL_EXEPOC_GZ	gettext("## Executing preinstall script.")
#define	MSG_PKGINSTALL_EXEPOC_LZ	gettext("## Executing preinstall script in zone <%s>.")
#define	MSG_PKGINSTALL_INSIN_GZ		gettext("\nInstalling %s as <%s>\n")
#define	MSG_PKGINSTALL_INSIN_LZ		gettext("\nInstalling %s as <%s> in zone <%s>\n")
#define	MSG_PKGREMOVE_DEPEND		gettext("Dependency checking failed.")
#define	MSG_PKGREMOVE_EXEPIC_GZ		gettext("## Executing postremove script.")
#define	MSG_PKGREMOVE_EXEPIC_LZ		gettext("## Executing postremove script in zone <%s>.")
#define	MSG_PKGREMOVE_EXEPOC_GZ		gettext("## Executing preremove script.")
#define	MSG_PKGREMOVE_EXEPOC_LZ		gettext("## Executing preremove script in zone <%s>.")
#define	MSG_PKGREMOVE_ID_STR		gettext("ID")
#define	MSG_PKGREMOVE_NAME_STR		gettext("Name")
#define	MSG_PKGREMOVE_PRIV		gettext("\\nThis package contains scripts which will be executed with super-user permission during the process of removing this package.")
#define	MSG_PKGREMOVE_PROCPKG_GZ	gettext("## Processing package information.")
#define	MSG_PKGREMOVE_PROCPKG_LZ	gettext("## Processing package information in zone <%s>.")
#define	MSG_PKGREMOVE_REMPATHCLASS_GZ	gettext("## Removing pathnames in class <%s>")
#define	MSG_PKGREMOVE_REMPATHCLASS_LZ	gettext("## Removing pathnames in class <%s> in zone <%s>")
#define	MSG_PKGREMOVE_RUNLEVEL		gettext("\\nThe current run-level of this machine is <%s>, which is not a run-level suggested for removal of this package.  Suggested run-levels (in order of preference) include:")
#define	MSG_PKGREMOVE_UPDINF_GZ		gettext("## Updating system information.")
#define	MSG_PKGREMOVE_UPDINF_LZ		gettext("## Updating system information in zone <%s>.")
#define	MSG_PKGRMCHK_CKRUNLVL		gettext("\\nThe current run-level of this machine is <s%>, which is not a run-level suggested for removal of the %s <%s> on %s <%s>.")
#define	MSG_PKGRMCHK_DEPEND		gettext("\\nDependency checking failed for %s <%s> on %s <%s>.")
#define	MSG_PKGRMCHK_DEPSONME		gettext("\\nThe package <%s> depends on %s <%s> currently being removed from %s <%s>.")
#define	MSG_PKGRMCHK_PRENCI 		gettext("\\nThe package <%s> is a prerequisite package and is not completely installed for %s <%s> on %s <%s>.")
#define	MSG_PKGRMCHK_PREREQ 		gettext("\\nThe package <%s> is a prerequisite package and should be removed for %s <%s> on %s <%s>.")
#define	MSG_PKGRMCHK_PRIV		gettext("\\nThe %s <%s> contains scripts which will be executed on %s <%s> with super-user permission during the process of removing this package.")
#define	MSG_PKGRMCHK_RUNLEVEL		gettext("\\n run level <%s> for %s <%s> on %s <%s>.")
#define	MSG_PKGSCRIPTS_FOUND		gettext("Package scripts were found.")
#define	MSG_PREIVFY_GETYORN_SUSP	gettext("\\nInstallation of <%s> was suspended (interaction required).")
#define	MSG_PREIVFY_GETYORN_TERM	gettext("\\nInstallation of <%s> was terminated.")
#define	MSG_PREIVFY_GETYORN_TERM_USER	gettext("\\nInstallation of <%s> was terminated due to user request.")
#define	MSG_PREREMOVE_REMINST		gettext("\n## Removing installed package instance <%s>")
#define	MSG_PRERVFY_GETYORN_SUSP	gettext("\\nRemoval of <%s> was suspended (interaction required).")
#define	MSG_PRERVFY_GETYORN_TERM	gettext("\\nRemoval of <%s> was terminated.")
#define	MSG_PRERVFY_GETYORN_TERM_USER	gettext("\\nRemoval of <%s> was terminated due to user request.")
#define	MSG_PROCMV			gettext("- executing process moved to <%s>")
#define	MSG_PROC_CONT			gettext("\nProcessing continuation packages from <%s>")
#define	MSG_PROC_INST			gettext("\nProcessing package instance <%s> from <%s>")
#define	MSG_REMOVE_PKG_FROM_ZONE	gettext("## Removing package <%s> from zone <%s>")
#define	MSG_RESTORE_ZONE_STATE		gettext("## Restoring state of global zone <%s>")
#define	MSG_RMSRVR			gettext("%s <removed from server's file system>")
#define	MSG_SERVER			gettext("%s <server package pathname not removed>")
#define	MSG_SHARED			gettext("%s <shared pathname not removed>")
#define	MSG_SHIGN			gettext("%s <conflicting pathname not installed>")
#define	MSG_SKIPPING_ZONE_NOT_RUNNABLE	gettext("## Not processing zone <%s>: the zone is not running and cannot be booted")
#define	MSG_SLINK			gettext("%s <symbolic link>")
#define	MSG_SUSPEND_ADD			gettext("Installation of <%s> has been suspended.")
#define	MSG_SUSPEND_RM			gettext("Removals of <%s> has been suspended.")
#define	MSG_UGID			gettext("%s <installed with setuid/setgid bits reset>")
#define	MSG_UGMOD			gettext("%s <reset setuid/setgid bits>")
#define	MSG_VERIFYING			gettext("Verifying signer <%s>")
#define	MSG_VERIFYING_CLASS		gettext("[ verifying class <%s> ]")

#define	SPECIAL_ACCESS			gettext("unable to maintain package contents text due to an access failure: %s")
#define	SPECIAL_INPUT			gettext("unable to maintain package contents text: alternate root path too long")
#define	SPECIAL_MALLOC			gettext("unable to maintain package contents text due to insufficient memory: %s")
#define	SPECIAL_MAP			gettext("unable to maintain package contents text due to a failure to map the database into memory: %S")

#define	WRN_BAD_FORK			gettext("WARNING: bad fork(), errno=%d: %s")
#define	WRN_BAD_WAIT			gettext("WARNING: wait for process %ld failed, pid <%ld> status <0x%08lx> errno <%d> (%s)")
#define	WRN_CHKINSTALL 			gettext("checkinstall script suspends")
#define	WRN_DEF_MODE			gettext("WARNING: installing <%s> with default mode of 644")
#define WRN_SET_DEF_MODE		gettext("WARNING: setting mode of <%s> to default mode (%o)")
#define	WRN_FINALCK_ATTR		gettext("WARNING: attribute verification of <%s> failed")
#define	WRN_FINALCK_CONT		gettext("WARNING: content verification of <%s> failed")
#define	WRN_FLMAIL			gettext("WARNING: e-mail notification may have failed")
#define	WRN_FSTAB_MOUNT			gettext("WARNING: unable to mount client's file system at %s - errcode=%d")
#define	WRN_FSTAB_UMOUNT		gettext("WARNING: unable to unmount client's file system at %s - errcode=%d.")
#define	WRN_INSTVOL_NONE		gettext("WARNING: %s <not present on Read Only file system>")
#define	WRN_INSTVOL_NOTDIR		gettext("WARNING: %s may not overwrite a populated directory.")
#define	WRN_INSTVOL_NOVERIFY		gettext("WARNING: %s <cannot install to or verify on %s>")
#define	WRN_NOMAIL			gettext("WARNING: unable to send e-mail notification")
#define	WRN_RELATIVE			gettext("attempting to rename a relative file <%s>")
#define	WRN_RSCRIPTALT_BAD		gettext("WARNING: the admin parameter <%s> is set to <%s> which is not recognized; the parameter may only be set to <%s> or <%s>")
#define	WRN_RSCRIPTALT_USING		gettext("WARNING: the admin parameter <%s> is assumed to be set to <%s>")
#define	WRN_UNKNOWN_ADM_PARAM		gettext("WARNING: unknown admin parameter <%s>")
#define	NOTE_INSTVOL_FINALCKFAIL	gettext("NOTE: When the package <%s> was installed in the zone,\nthe file <%s> was also installed. After the file was\ninstalled in the zone, the contents and/or attributes of the file\nchanged. The contents of this file must never be changed.")

#define	MSG_REBOOT			gettext("\\n*** IMPORTANT NOTICE ***\\n" \
			"\\tThis machine must now be rebooted in order to " \
			"ensure\\n" \
			"\\tsane operation.  Execute\\n\\t\\tshutdown -y -i6 " \
			"-g0\\n" \
			"\\tand wait for the \"Console Login:\" prompt.")

/*
 * These messages are output by qreason() - they are the "reason"
 * for the success/fail of the operation
 */

#define	MSG_UNKREQ						gettext \
			("qreason(): unrecognized message request.")
#define	MSG_RE_SUC						gettext \
			("Processing of request script was successful.")
#define	MSG_IN_SUC0						gettext \
			("Installation of <%s> was successful.")
#define	MSG_IN_SUC1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> was successful.")
#define	MSG_RM_SUC0						gettext \
			("Removal of <%s> was successful.")
#define	MSG_RM_SUC1						gettext \
			("\nRemoval of <%s> package instance on %s was " \
			"successful.")
#define	MSG_RE_FAIL						gettext \
			("Processing of request script failed.")
#define	MSG_IN_FAIL0						gettext \
			("Installation of <%s> failed.")
#define	MSG_IN_FAIL1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> failed.")
#define	MSG_RM_FAIL0						gettext \
			("Removal of <%s> failed.")
#define	MSG_RM_FAIL1						gettext \
			("\nRemoval of <%s> package instance on %s failed.")
#define	MSG_RE_PARFAIL						gettext \
			("Processing of request script partially failed.")
#define	MSG_IN_PARFAIL0						gettext \
			("Installation of <%s> partially failed.")
#define	MSG_IN_PARFAIL1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> partially failed.")
#define	MSG_RM_PARFAIL0						gettext \
			("Removal of <%s> partially failed.")
#define	MSG_RM_PARFAIL1						gettext \
			("\nRemoval of <%s> package instance on %s partially " \
			"failed.")
#define	MSG_RE_USER						gettext \
			("Processing of request script was terminated due to " \
			"user request.")
#define	MSG_IN_USER0						gettext \
			("Installation of <%s> was terminated due to user " \
			"request.")
#define	MSG_IN_USER1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> was terminated due to user request.")
#define	MSG_RM_USER0						gettext \
			("Removal of <%s> was terminated due to user request.")
#define	MSG_RM_USER1						gettext \
			("\nRemoval of <%s> package instance on %s was " \
			"terminated due to user request.")
#define	MSG_RE_SUA						gettext \
			("Processing of request script was suspended " \
			"(administration).")
#define	MSG_IN_SUA0						gettext \
			("Installation of <%s> was suspended (administration).")
#define	MSG_IN_SUA1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> was suspended (administration).")
#define	MSG_RM_SUA0						gettext \
			("Removal of <%s> was suspended (administration).")
#define	MSG_RM_SUA1						gettext \
			("\nRemoval of <%s> package instance on %s was " \
			"suspended (administration).")
#define	MSG_RE_SUI						gettext \
			("Processing of request script was suspended " \
			"(interaction required).")
#define	MSG_IN_SUI0						gettext \
			("Installation of <%s> was suspended (interaction " \
			"required).")
#define	MSG_IN_SUI1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> was suspended (interaction required).")
#define	MSG_RM_SUI0						gettext \
			("Removal of <%s> was suspended (interaction " \
			"required).")
#define	MSG_RM_SUI1						gettext \
			("\nRemoval of <%s> package instance on %s was " \
			"suspended (interaction required).")
#define	MSG_RE_IEPI						gettext \
			("Processing of request script failed (internal " \
			"error) - package partially installed.")
#define	MSG_IN_IEPI0						gettext \
			("Installation of <%s> failed (internal error) - " \
			"package partially installed.")
#define	MSG_IN_IEPI1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> failed (internal error) - package partially " \
			"installed.")
#define	MSG_RM_IEPI0						gettext \
			("Removal of <%s> failed (internal error) - package " \
			"partially installed.")
#define	MSG_RM_IEPI1						gettext \
			("\nRemoval of <%s> package instance on %s failed " \
			"(internal error) - package partially installed.")
#define	MSG_RE_IE						gettext \
			("Processing of request script failed (internal " \
			"error).")
#define	MSG_IN_IE0						gettext \
			("Installation of <%s> failed (internal error).")
#define	MSG_IN_IE1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> failed (internal error).")
#define	MSG_RM_IE0						gettext \
			("Removal of <%s> failed (internal error).")
#define	MSG_RM_IE1						gettext \
			("\nRemoval of <%s> package instance on %s failed " \
			"(internal error).")
#define	MSG_RE_UNK						gettext \
			("Processing of request script failed with an " \
			"unrecognized error code.")
#define	MSG_IN_UNK0						gettext \
			("Installation of <%s> failed with an unrecognized " \
			"error code.")
#define	MSG_IN_UNK1						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> failed with an unrecognized error code.")
#define	MSG_RM_UNK0						gettext \
			("Removal of <%s> failed with an unrecognized error " \
			"code.")
#define	MSG_RM_UNK1						gettext \
			("\nRemoval of <%s> package instance on %s failed " \
			"with an unrecognized error code.")
/* WITH ZONE NAME */
#define	MSG_UNKREQ_ZONE						gettext \
			("qreason(): unrecognized message request.")
#define	MSG_RE_SUC_ZONE						gettext \
			("Processing of request script for zone <%s> was " \
			"successful.")
#define	MSG_IN_SUC0_ZONE					gettext \
			("Installation of <%s> on zone <%s> was successful.")
#define	MSG_IN_SUC1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> was successful.")
#define	MSG_RM_SUC0_ZONE					gettext \
			("Removal of <%s> from zone <%s> was successful.")
#define	MSG_RM_SUC1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> was successful.")
#define	MSG_RE_FAIL_ZONE					gettext \
			("Processing of request script for zone <%s> failed.")
#define	MSG_IN_FAIL0_ZONE					gettext \
			("Installation of <%s> on zone <%s> failed.")
#define	MSG_IN_FAIL1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> failed.")
#define	MSG_RM_FAIL0_ZONE					gettext \
			("Removal of <%s> from zone <%s> failed.")
#define	MSG_RM_FAIL1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from zone " \
			"<%s> failed.")
#define	MSG_RE_PARFAIL_ZONE					gettext \
			("Processing of request script partially failed on " \
			"zone <%s>.")
#define	MSG_IN_PARFAIL0_ZONE					gettext \
			("Installation of <%s> on zone <%s> partially failed.")
#define	MSG_IN_PARFAIL1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> partially failed.")
#define	MSG_RM_PARFAIL0_ZONE					gettext \
			("Removal of <%s> from zone <%s> partially failed.")
#define	MSG_RM_PARFAIL1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from zone " \
			"<%s> partially failed.")
#define	MSG_RE_USER_ZONE					gettext \
			("Processing of request script on zone <%s> was " \
			"terminated due to user request.")
#define	MSG_IN_USER0_ZONE					gettext \
			("Installation of <%s> on zone <%s> was terminated " \
			"due to user request.")
#define	MSG_IN_USER1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> was terminated due to user request.")
#define	MSG_RM_USER0_ZONE					gettext \
			("Removal of <%s> from zone <%s> was terminated due " \
			"to user request.")
#define	MSG_RM_USER1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> was terminated due to user request.")
#define	MSG_RE_SUA_ZONE						gettext \
			("Processing of request script on zone <%s> was " \
			"suspended (administration).")
#define	MSG_IN_SUA0_ZONE					gettext \
			("Installation of <%s> on zone <%s> was suspended " \
			"(administration).")
#define	MSG_IN_SUA1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> was suspended (administration).")
#define	MSG_RM_SUA0_ZONE					gettext \
			("Removal of <%s> from zone <%s> was suspended " \
			"(administration).")
#define	MSG_RM_SUA1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> was suspended (administration).")
#define	MSG_RE_SUI_ZONE						gettext \
			("Processing of request script on zone <%s> was " \
			"suspended (interaction required).")
#define	MSG_IN_SUI0_ZONE					gettext \
			("Installation of <%s> on zone <%s> was suspended " \
			"(interaction required).")
#define	MSG_IN_SUI1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> was suspended (interaction " \
			"required).")
#define	MSG_RM_SUI0_ZONE					gettext \
			("Removal of <%s> from zone <%s> was suspended " \
			"(interaction required).")
#define	MSG_RM_SUI1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> was suspended (interaction required).")
#define	MSG_RE_IEPI_ZONE					gettext \
			("Processing of request script on zone <%s> " \
			"failed (internal error) - package partially " \
			"installed.")
#define	MSG_IN_IEPI0_ZONE					gettext \
			("Installation of <%s> on zone failed (internal " \
			"error) on zone <%s> - package partially installed.")
#define	MSG_IN_IEPI1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			" <%s> on zone <%s> failed (internal error) - " \
			"package partially installed.")
#define	MSG_RM_IEPI0_ZONE					gettext \
			("Removal of <%s> from zone <%s> failed (internal " \
			"error) - package partially installed.")
#define	MSG_RM_IEPI1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> failed (internal error) - package " \
			"partially installed.")
#define	MSG_RE_IE_ZONE						gettext \
			("Processing of request script on zone <%s> failed " \
			"(internal error).")
#define	MSG_IN_IE0_ZONE						gettext \
			("Installation of <%s> on zone <%s> failed (internal " \
			"error).")
#define	MSG_IN_IE1_ZONE						gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> failed (internal error).")
#define	MSG_RM_IE0_ZONE						gettext \
			("Removal of <%s> on zone <%s> failed (internal " \
			"error).")
#define	MSG_RM_IE1_ZONE						gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> failed (internal error).")
#define	MSG_RE_UNK_ZONE						gettext \
			("Processing of request script on zone <%s> failed " \
			"with an unrecognized error code.")
#define	MSG_IN_UNK0_ZONE					gettext \
			("Installation of <%s> on zone <%s> failed with an " \
			"unrecognized error code.")
#define	MSG_IN_UNK1_ZONE					gettext \
			("\nInstallation of %s on %s as package instance " \
			"<%s> on zone <%s> failed with an unrecognized " \
			"error code.")
#define	MSG_RM_UNK0_ZONE					gettext \
			("Removal of <%s> from zone <%s> failed with an " \
			"unrecognized error code.")
#define	MSG_RM_UNK1_ZONE					gettext \
			("\nRemoval of <%s> package instance on %s from " \
			"zone <%s> failed with an unrecognized error code.")

#define	MSG_UNIQ1						gettext( \
			"\\nCurrent administration requires that a unique " \
			"instance of the <%s> package be created.  However, " \
			"the maximum number of instances of the package " \
			"which may be supported at one time on the same " \
			"system has already been met.")

#define	MSG_NOINTERACT						gettext( \
			"\\nUnable to determine whether to overwrite an " \
			"existing package instance, or add a new instance.")

#define	MSG_NEWONLY						gettext( \
			"\\nA version of the <%s> package is already " \
			"installed on this machine.  Current administration " \
			"does not allow new instances of an existing package " \
			"to be created, nor existing instances to be " \
			"overwritten.")

#define	MSG_SAME						gettext( \
			"\\nThis appears to be an attempt to install the " \
			"same architecture and version of a package which " \
			"is already installed.  This installation will " \
			"attempt to overwrite this package.\\n")

#define	MSG_OVERWRITE						gettext( \
			"\\nCurrent administration does not allow new " \
			"instances of an existing package to be created.  " \
			"However, the installation service was unable to " \
			"determine which package instance to overwrite.")


#define	MSG_GETINST_PROMPT0				gettext( \
		"Do you want to overwrite this installed instance")

#define	MSG_GETINST_PROMPT1				gettext( \
		"Do you want to create a new instance of this package")

#define	MSG_GETINST_HELP1				gettext( \
		"The package you are attempting to install already exists " \
		"on this machine.  You may choose to create a new instance " \
		"of this package by answering 'y' to this prompt.  If you " \
		"answer 'n' you will be asked to choose one of the instances " \
		"which is already to be overwritten.")

#define	MSG_GETINST_HEADER				gettext( \
		"The following instance(s) of the <%s> package are already " \
		"installed on this machine:")

#define	MSG_GETINST_PROMPT2				gettext( \
		"Enter the identifier for the instance that you want to " \
		"overwrite")

#define	MSG_GETINST_HELP2				gettext( \
		"The package you are attempting to install already exists on " \
		"this machine.  You may choose to overwrite one of the " \
		"versions which is already installed by selecting the " \
		"appropriate entry from the menu.")

/*
 * I18N: MSG_GZONLY_FILE_HEADER must NOT be translated!
 * ----- This message is placed at the beginning of an internal (private)
 * ----- database file. The contents of the message is a warning telling
 * ----- anyone who examines the contents of the database to not modify the
 * ----- database manually (by hand).
 * ----- Do NOT change or translate this text!
 */

#define	MSG_GZONLY_FILE_HEADER		\
"# DO NOT EDIT THIS FILE BY HAND. This file is not a public interface.\n" \
"# The format and contents of this file are subject to change.\n" \
"# Any user modification to this file may result in the incorrect\n" \
"# operation of the package and patch tools.\n" \
"# Last modified by <%s> to <%s> package <%s>\n# %s"

/* END CSTYLED */

#ifdef __cplusplus
}
#endif

#endif	/* _MESSAGES_H */
