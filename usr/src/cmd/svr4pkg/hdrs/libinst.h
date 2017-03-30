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
 * Copyright (c) 2017 Peter Tribble.
 */

/*
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	__HDRS_LIBINST_H__
#define	__HDRS_LIBINST_H__


#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pkgstrct.h>
#include <pkginfo.h>
#include "pkglib.h"
#include <cfext.h>
#include "install.h"

#define	DEF_NONE_SCR	"i.CompCpio"

#define	BL_ALL		-1	/* refers to all allocated lists */

/* signal handler function definition */

typedef void (sighdlrFunc_t)(int);

/* maximum parameter length */

#define	MAX_PKG_PARAM_LENGTH	(64+1)	/* +1 for null termination */

/* flag for check_applicability */

typedef unsigned long CAF_T;

/* flags for check_applicability */

#define	CAF_IN_GLOBAL_ZONE	0x00000001	/* in global zone */
#define	CAF_SCOPE_GLOBAL	0x00000002	/* -G specified */
#define	CAF_SCOPE_NONGLOBAL	0x00000004	/* -Z specified */

/* path to the request file in the package directory */

#define	REQUEST_FILE	"install/request"

/* path to the copyright file in the package directory */

#define	COPYRIGHT_FILE	"install/copyright"

/* path to the depend file in the package directory */

#define	DEPEND_FILE	"install/depend"

/*
 * name of environment variable set to non-global zone name being installed:
 * pkgadd/pkginstall expects this name and passes it on to any scripts that
 * are run if it is set.
 */

#define	PKG_ZONENAME_VARIABLE	"SUNW_PKG_INSTALL_ZONENAME"

/*
 * name of environment variable set to indicate this package should be installed
 * in the current zone only - see PSARC/2004/789 - New Pkginfo(4) attributes
 * for zones
 */

#define	PKG_THISZONE_VARIABLE	"SUNW_PKG_THISZONE"

/*
 * name of environment variable set to indicate this package should be installed
 * in all zones, and only from the global zone - see PSARC/2003/460
 */

#define	PKG_ALLZONES_VARIABLE	"SUNW_PKG_ALLZONES"

/*
 * name of environment variable set to indicate this package should be installed
 * hollow (db update only) when installed in nonglobal zone - see PSARC/2003/460
 */

#define	PKG_HOLLOW_VARIABLE	"SUNW_PKG_HOLLOW"

/*
 * General purpose return codes used for functions which don't return a basic
 * success or failure. For those functions wherein a yes/no result is
 * possible, then 1 means OK and 0 means FAIL.
 */
#define	RESULT_OK	0x0
#define	RESULT_WRN	0x1
#define	RESULT_ERR	0x2

/* These are the file status indicators for the contents file */
#define	INST_RDY	'+'	/* entry is ready to installf -f */
#define	RM_RDY		'-'	/* entry is ready for removef -f */
#define	NOT_FND		'!'	/* entry (or part of entry) was not found */
#define	SERVED_FILE	'%'	/* using the file server's RO partition */
#define	STAT_NEXT	'@'	/* this is awaiting eptstat */
#define	DUP_ENTRY	'#'	/* there's a duplicate of this */
#define	CONFIRM_CONT	'*'	/* need to confirm contents */
#define	CONFIRM_ATTR	'~'	/* need to confirm attributes */
#define	ENTRY_OK	'\0'	/* entry is a confirmed file */

/* control bits for pkgdbmerg() */
#define	NO_COPY		0x0001
#define	CLIENT_PATHS	0x0002	/* working with a client database */

/* control bits for file verification by class */
#define	DEFAULT		0x0	/* standard full verification */
#define	NOVERIFY	0x1	/* do not verify */
#define	QKVERIFY	0x2	/* do a quick verification instead */

/* control bit for path type to pass to CAS */
#define	DEFAULT		0x0	/* standard server-relative absolute path */
#define	REL_2_CAS	0x1	/* pass pkgmap-type relative path */

/* findscripts() argument */
#define	I_ONLY		0x0	/* find install class action scripts */
#define	R_ONLY		0x1	/* find removal class action scripts */

struct cl_attr {
	char	name[CLSSIZ+1];	/* name of class */
	char	*inst_script;	/* install class action script */
	char	*rem_script;	/* remove class action script */
	unsigned	src_verify:3;	/* source verification level */
	unsigned 	dst_verify:4;	/* destination verification level */
	unsigned	relpath_2_CAS:1;	/* CAS gets relative paths */
};

#if defined(__STDC__)
#define	__P(protos) protos
#else	/* __STDC__ */
#define	__P(protos) ()
#endif	/* __STDC__ */

/* Common quit declaration used across many package commands */
extern void	quit(int) __NORETURN;


/* listmgr.c */
extern int	bl_create __P((int count_per_block, int struct_size,
		    char *desc));
extern char	*bl_next_avail __P((int list_handle));
extern char	*bl_get_record __P((int list_handle, int recno));
extern void	bl_free __P((int list_handle));
extern int	ar_create __P((int count_per_block, int struct_size,
		    char *desc));
extern char	**ar_next_avail __P((int list_handle));
extern char	**ar_get_head __P((int list_handle));
extern int	ar_delete __P((int list_handle, int index));
extern void	ar_free __P((int list_handle));

/* doulimit.c */
extern int	set_ulimit __P((char *script, char *err_msg));
extern int	clr_ulimit __P((void));
extern int	assign_ulimit __P((char *fslimit));

/* dryrun.c */
extern void	set_continue_not_ok __P((void));
extern int	continue_is_ok __P((void));
extern int	in_dryrun_mode __P((void));
extern int	in_continue_mode __P((void));
extern void	init_dryrunfile __P((char *dr_dir));
extern void	init_contfile __P((char *cn_dir));
extern void	set_dr_exitmsg __P((char *value));
extern void	set_dr_info __P((int type, int value));
extern void	write_dryrun_file __P((struct cfextra **extlist));

/* instvol.c */
extern void	regfiles_free __P((void));

/* lockinst.c */
extern int	lockinst __P((char *util_name, char *pkg_name, char *place));
extern void	lockupd __P((char *place));
extern void	unlockinst __P((void));

extern char	*pathdup __P((char *s));
extern char	*pathalloc __P((int n));
extern char	*fixpath __P((char *path));
extern char	*get_info_basedir __P((void));
extern char	*get_basedir __P((void));
extern char	*get_client_basedir __P((void));
extern int	set_basedirs __P((int reloc, char *adm_basedir,
		    char *pkginst, int nointeract));
extern int	eval_path __P((char **server_ptr, char **client_ptr,
		    char **map_ptr, char *path));
extern int	get_orig_offset __P((void));
extern char	*get_inst_root __P((void));
extern char	*get_mount_point __P((uint32_t n));
extern char	*get_remote_path __P((uint32_t n));
extern void	set_env_cbdir __P((void));
extern int	set_inst_root __P((char *path));
extern void	put_path_params __P((void));
extern int	mkpath __P((char *p));
extern void	mkbasedir __P((int flag, char *path));
extern int	is_an_inst_root __P((void));
extern int	is_a_basedir __P((void));
extern int	is_a_cl_basedir __P((void));
extern int	is_relocatable __P((void));
extern char	*orig_path __P((char *path));
extern char	*orig_path_ptr __P((char *path));
extern char	*qreason __P((int caller, int retcode, int started,
			int includeZonename));
extern char	*qstrdup __P((char *s));
extern char	*srcpath __P((char *d, char *p, int part, int nparts));
extern char	*trans_srcp_pi __P((char *local_path));
extern int	copyf __P((char *from, char *to, time_t mytime));
extern int	copyFile __P((int, int, char *, char *, struct stat *, long));
extern int	openLocal __P((char *a_path, int a_oflag, char *a_tmpdir));
extern int	dockdeps __P((char *depfile, int removeFlag,
			boolean_t a_preinstallCheck));
extern int	finalck __P((struct cfent *ept, int attrchg, int contchg,
			boolean_t a_warning));

/* dockdeps.c */
extern void setUpdate __P((void));
extern int  isUpdate __P((void));

/* mntinfo.c */
extern int	get_mntinfo __P((int map_client, char *vfstab_file));
extern uint32_t	fsys __P((char *path));
extern struct fstable *get_fs_entry __P((uint32_t n));
extern int	mount_client __P((void));
extern int	unmount_client __P((void));
extern uint32_t	resolved_fsys __P((char *path));
extern char	*get_server_host __P((uint32_t n));
extern char	*server_map __P((char *path, uint32_t fsys_value));
extern int	use_srvr_map __P((char *path, uint32_t *fsys_value));
extern int	use_srvr_map_n __P((uint32_t n));
extern int	is_fs_writeable __P((char *path, uint32_t *fsys_value));
extern int	is_remote_fs __P((char *path, uint32_t *fsys_value));
extern int	is_served __P((char *path, uint32_t *fsys_value));
extern int	is_mounted __P((char *path, uint32_t *fsys_value));
extern int	is_fs_writeable_n __P((uint32_t n));
extern int	is_remote_fs_n __P((uint32_t n));
extern int	is_served_n __P((uint32_t n));
extern int	is_mounted_n __P((uint32_t n));
extern fsblkcnt_t	get_blk_size_n __P((uint32_t n));
extern fsblkcnt_t	get_frag_size_n __P((uint32_t n));
extern fsblkcnt_t	get_blk_used_n __P((uint32_t n));
extern fsblkcnt_t	get_blk_free_n __P((uint32_t n));
extern fsblkcnt_t	get_inode_used_n __P((uint32_t n));
extern fsblkcnt_t	get_inode_free_n __P((uint32_t n));
extern void	set_blk_used_n __P((uint32_t n, fsblkcnt_t value));
extern char	*get_source_name_n __P((uint32_t n));
extern char	*get_fs_name_n __P((uint32_t n));
extern int	load_fsentry __P((struct fstable *fs_entry, char *name,
		    char *fstype, char *remote_name));
extern int	isreloc __P((char *pkginstdir));
extern int	is_local_host __P((char *hostname));
extern void	fs_tab_free __P((void));

/* pkgdbmerg.c */
extern int	pkgdbmerg __P((PKGserver server, VFP_T *tmpvfp,
		    struct cfextra **extlist));
extern int	files_installed __P((void));

/* ocfile.c */
extern int	trunc_tcfile __P((int fd));
extern int	ocfile __P((PKGserver *serverp, VFP_T **tmpvfp,
			fsblkcnt_t map_blks));
extern int	swapcfile __P((PKGserver server, VFP_T **a_tmpvfp,
			char *pkginst, int dbchg));
extern int	set_cfdir __P((char *cfdir));
extern int	socfile __P((PKGserver *server, boolean_t quiet));
extern int	relslock __P((void));
extern int	pkgWlock __P((int verbose));
extern int	iscfile __P((void));
extern int	vcfile __P((void));

extern fsblkcnt_t	nblk __P((fsblkcnt_t size, ulong_t bsize,
			ulong_t frsize));
extern struct	cfent **procmap __P((VFP_T *vfp, int mapflag, char *ir));
extern void	repl_cfent __P((struct cfent *new, struct cfent *old));
extern struct	cfextra **pkgobjmap __P((VFP_T *vfp, int mapflag, char *ir));
extern void	pkgobjinit __P((void));
extern int	seed_pkgobjmap __P((struct cfextra *ext_entry, char *path,
		    char *local));
extern int	init_pkgobjspace __P((void));

/* eptstat.c */
extern void	pinfo_free __P((void));
extern struct	pinfo *eptstat __P((struct cfent *entry, char *pkg, char c));

/* echo.c */
/*PRINTFLIKE1*/
extern void	echo __P((char *a_fmt, ...));
/*PRINTFLIKE1*/
extern void	echoDebug __P((char *a_fmt, ...));
extern boolean_t	echoGetFlag __P((void));
extern boolean_t	echoDebugGetFlag __P((void));
extern boolean_t	echoSetFlag __P((boolean_t a_debugFlag));
extern boolean_t	echoDebugSetFlag __P((boolean_t a_debugFlag));

/* ptext.c */
/*PRINTFLIKE2*/
extern void	ptext __P((FILE *fp, char *fmt, ...));

/* putparam.c */
extern void	putparam __P((char *param, char *value));
extern void	getuserlocale __P((void));
extern void	putuserlocale __P((void));
extern void	putConditionInfo __P((char *, char *));

/* setadmin.c */
extern void		setadminFile __P((char *file));
extern char		*setadminSetting __P((char *a_paramName,
				char *a_paramValue));

/* setlist.c */
extern char	*cl_iscript __P((int idx));
extern char	*cl_rscript __P((int idx));
extern void	find_CAS __P((int CAS_type, char *bin_ptr, char *inst_ptr));
extern int	setlist __P((struct cl_attr ***plist, char *slist));
extern void	addlist __P((struct cl_attr ***plist, char *item));
extern char	*cl_nam __P((int cl_idx));
extern char	*flex_device(char *device_name, int dev_ok);
extern int	cl_getn __P((void));
extern int	cl_idx __P((char *cl_nam));
extern void	cl_sets __P((char *slist));
extern void	cl_setl __P((struct cl_attr **cl_lst));
extern void	cl_putl __P((char *parm_name, struct cl_attr **list));
extern int	cl_deliscript __P((int i));
extern unsigned	cl_svfy __P((int i));
extern unsigned	cl_dvfy __P((int i));
extern unsigned	cl_pthrel __P((int i));

/* fixpath.c */
extern void __P(export_client_env(char *));
extern void __P(set_partial_inst(void));
extern int __P(is_partial_inst(void));
extern void __P(set_depend_pkginfo_DB(boolean_t a_setting));
extern boolean_t __P(is_depend_pkginfo_DB(void));
extern void __P(disable_spool_create(void));
extern int __P(is_spool_create(void));

/* open_package_datastream.c */
extern boolean_t	open_package_datastream(int a_argc, char **a_argv,
				char *a_spoolto, char *a_device,
				int *r_repeat, char **r_idsName,
				char *a_tmpdir, struct pkgdev *a_pkgdev,
				int a_optind);

/* setup_temporary_directory.c */
extern boolean_t	setup_temporary_directory(char **r_dirname,
				char *a_tmpdir, char *a_suffix);

/* unpack_package_from_stream.c */
extern boolean_t	unpack_package_from_stream(char *a_idsName,
				char *a_pkginst, char *a_tempDir);

/* pkgops.c */

extern boolean_t	pkgAddPackageToGzonlyList(char *a_pkgInst,
				char *a_rootPath);
extern void		pkgAddThisZonePackage(char *a_pkgInst);
extern boolean_t	pkgRemovePackageFromGzonlyList(char *a_rootPath,
				char *a_pkgInst);
extern FILE		*pkgOpenInGzOnlyFile(char *a_rootPath);
extern void		pkginfoFree(struct pkginfo **r_info);
extern boolean_t	pkginfoIsPkgInstalled(struct pkginfo **r_pinfo,
				char *a_pkgInst);
extern boolean_t	pkgIsPkgInGzOnly(char *a_rootPath, char *a_pkgInst);
extern boolean_t	pkgIsPkgInGzOnlyFP(FILE *a_fp, char *a_pkgInst);
extern boolean_t	pkginfoParamTruth(FILE *a_fp, char *a_param,
				char *a_value, boolean_t a_default);
extern int		pkgGetPackageList(char ***r_pkgList, char **a_argv,
				int a_optind, char *a_categories,
				char **a_categoryList, struct pkgdev *a_pkgdev);
extern void		pkgLocateHighestInst(char *r_path, int r_pathLen,
				char *r_pkgInst, int r_pkgInstLen,
				char *a_rootPath, char *a_pkgInst);
extern boolean_t	pkgPackageIsThisZone(char *a_pkgInst);
extern char		*pkgGetGzOnlyPath(void);
extern boolean_t	pkgTestInstalled(char *a_packageName, char *a_rootPath);

/* depchk.c */

struct depckErrorRecord {
	int	ier_numZones;
	char	*ier_packageName;
	char	**ier_zones;
	char	**ier_values;
};

typedef struct depckErrorRecord depckErrorRecord_t;

struct depckError {
	int			er_numEntries;
	depckErrorRecord_t	*er_theEntries;
};

typedef struct depckError depckError_t;

typedef int (depcklFunc_t)(char *a_msg, char *a_pkg);

/*
 * ignore_values:
 *	== NULL - record one message for each instance of "name" found
 *	== "" - record multiple instances
 *	!= "" - record multiple instances if value not in ignore_values
 */

struct depckl_struct {
	char		*name;
	char		*ignore_values;
	char		**err_msg;
	depcklFunc_t	*depcklFunc;
	depckError_t	*record;
};

typedef struct depckl_struct depckl_t;

extern int		depchkReportErrors(depckl_t *depckl);
extern void		depchkRecordError(depckError_t *a_erc,
				char *a_pkginst, char *a_zoneName,
				char *a_value);

/* log.c */

/* types of log messages we recognize */
typedef enum {
	LOG_MSG_ERR,
	LOG_MSG_WRN,
	LOG_MSG_INFO,
	LOG_MSG_DEBUG
} LogMsgType;

/*PRINTFLIKE2*/
extern	void		log_msg(LogMsgType, const char *, ...);
extern	void		log_set_verbose(boolean_t);
extern	boolean_t	log_get_verbose(void);

/*
 * typedef for the 'ckreturn' function
 */
typedef void (ckreturnFunc_t)(int a_retcode);

/* sml.c */

/* null reference to SML_TAG object */

#define	SML_TAG__NULL		((SML_TAG*)NULL)

/* null reference to SML_TAG * object */

#define	SML_TAG__R_NULL		((SML_TAG**)NULL)

/* is reference to SML_TAG object valid? */

#define	SML_TAG__ISVALID(tag)	((tag) != (SML_TAG__NULL))

/* is indirect reference to SML_TAG object valid? */

#define	SML_TAG__R_ISVALID(r_tag)	\
	((r_tag) != ((SML_TAG**)(SML_TAG__NULL)))

/* definitions for sml passed from pkginstall to pkgcond */

#define	PKGCOND_GLOBAL_VARIABLE	"SUNW_PKGCOND_GLOBAL_DATA"
#define	TAG_COND_TOPLEVEL	"environmentConditionInformation"
#define	TAG_COND_PARENT_ZONE	"parentZone"
#define	TAG_COND_CURRENT_ZONE	"currentZone"
#define	TAG_COND_ZONE_NAME	"zoneName"
#define	TAG_COND_ZONE_TYPE	"zoneType"
#define	TAG_COND_FS_NAME	"fileSystemName"
#define	TAG_VALUE_GLOBAL_ZONE	"global"
#define	TAG_VALUE_NONGLOBAL_ZONE	"nonglobal"

typedef struct _sml_tag_struct SML_TAG;
typedef struct _sml_parameter_struct SML_PARAM;

struct _sml_tag_struct {
	char		*name;		/* tag name */
	int		params_num;	/* # params in *params */
	SML_PARAM	*params;	/* tag parameters */
	int		tags_num;	/* # subtags in *tags */
	SML_TAG		*tags;		/* tag subtags */
};

struct _sml_parameter_struct {
	char	*name;		/* tag name */
	char	*value;		/* parameters */
};

SML_TAG		*smlAddTag(SML_TAG **r_tag, int a_index,
			SML_TAG *a_subTag);
boolean_t	smlFstatCompareEq(struct stat *statbuf,
				SML_TAG *tag, char *path);
char		*smlConvertTagToString(SML_TAG *tag);
/*PRINTFLIKE2*/
void		smlDbgPrintTag(SML_TAG *a_tag, char *a_format, ...);
void		smlDelTag(SML_TAG *tag, SML_TAG *sub_tag);
void		smlDelParam(SML_TAG *tag, char *name);
SML_TAG		*smlDup(SML_TAG *tag);
boolean_t	smlFindAndDelTag(SML_TAG *tag, char *findTag);
void		smlFreeTag(SML_TAG *tag);
char		*smlGetElementName(SML_TAG *a_tag);
int		smlGetNumParams(SML_TAG *a_tag);
char		*smlGetParam(SML_TAG *tag, char *name);
/*PRINTFLIKE2*/
char		*smlGetParamF(SML_TAG *tag, char *format, ...);
void		smlGetParam_r(SML_TAG *tag, char *name, char *buf,
			int bufLen);
char		*smlGetParamByTag(SML_TAG *tag, int index,
			char *tagName, char *parmName);
char		*smlGetParamByTagParam(SML_TAG *tag, int index,
			char *tagName, char *parmName, char *parmValue,
			char *parmReturn);
char		*smlGetParamName(SML_TAG *tag, int index);
SML_TAG		*smlGetTag(SML_TAG *tag, int index);
SML_TAG		*smlGetTagByName(SML_TAG *tag, int index, char *name);
SML_TAG		*smlGetTagByTagParam(SML_TAG *tag, int index,
			char *tagName, char *paramName, char *paramValue);
boolean_t	smlGetVerbose(void);
int		smlLoadTagFromFile(SML_TAG **r_tag, char *a_fileName);
SML_TAG		*smlNewTag(char *name);
boolean_t	smlParamEq(SML_TAG *tag, char *findTag,
			char *findParam, char *str);
/*PRINTFLIKE4*/
boolean_t	smlParamEqF(SML_TAG *tag, char *findTag, char *findParam,
			char *format, ...);
void		smlPrintTag(SML_TAG *tag);
int		smlReadOneTag(SML_TAG **r_tag, char *a_str);
int		smlConvertStringToTag(SML_TAG **r_tag, char *str);
void		smlSetFileStatInfo(SML_TAG **tag,
				struct stat *statbuf, char *path);
void		smlSetParam(SML_TAG *tag, char *name, char *value);
/*PRINTFLIKE3*/
void		smlSetParamF(SML_TAG *tag, char *name, char *format, ...);
void		smlSetVerbose(boolean_t a_setting);
int		smlWriteTagToFd(SML_TAG *tag, int fd);
int		smlWriteTagToFile(SML_TAG *tag, char *filename);
/*PRINTFLIKE3*/
void		sml_strPrintf_r(char *a_buf, int a_bufLen, char *a_format, ...);
/*PRINTFLIKE1*/
char 		*sml_strPrintf(char *a_format, ...);
char		*sml_XmlEncodeString(char *a_plainTextString);
char		*sml_XmlDecodeString(char *a_xmlEncodedString);

#if defined(lint) && !defined(gettext)
#define	gettext(x)	x
#endif	/* defined(lint) && !defined(gettext) */

#ifdef __cplusplus
}
#endif

#endif	/* __HDRS_LIBINST_H__ */
