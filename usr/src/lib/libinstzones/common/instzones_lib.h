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



#ifndef _INSTZONES_LIB_H
#define	_INSTZONES_LIB_H


/*
 * Module:	instzones_lib.h
 * Group:	libinstzones
 * Description:	This module contains the libinstzones internal data structures,
 *		constants, and function prototypes. This include should not be
 *		needed by any external code (consumers of this library).
 */

/*
 * required includes
 */

/* System includes */

#include <zone.h>
#include <libzonecfg.h>
#include <libcontract.h>
#include <instzones_api.h>



/*
 * C++ prefix
 */

#ifdef __cplusplus
extern "C" {
#endif

/* constants */


/* macros */

/*
 * argument array processing type
 */

/*
 * This is the "argument array" definition that is returned by _z_new_args
 * and is used by _z_add_args, _z_free_args, etc.
 */

struct _argArray_t {
	long	_aaNumArgs;	/* number of arguments set */
	long	_aaMaxArgs;	/* number of arguments allocated */
	char	**_aaArgs;	/* actual arguments */
};

typedef struct _argArray_t argArray_t;

/*
 * lock objects
 */

/*
 * this allows a root path to be prepended to a lock object; e.g.
 *   rootpath.%s/zone.%s/...
 */
#define	LOBJ_ROOTPATH	"rootpath.%s"

/* this locks a single zone (zone.name) */
#define	LOBJ_ONE_ZONE	"zone.%s"

/* this locks all zones */
#define	LOBJ_ZONEADMIN	"zone.*"

/* this locks all packages, in all zones */
#define	LOBJ_PKGADMIN	"zone.*/package.*"

/* this locks all patches, in all zones */
#define	LOBJ_PATCHADMIN	"zone.*/patch.*"

#define	LOCK_OBJECT_MAXLEN	512
#define	LOCK_KEY_MAXLEN		37

/* paths to commands executed by this module */

#define	PKGADM_CMD	"/usr/bin/pkgadm"
#define	ZONEADM_CMD	"/usr/sbin/zoneadm"

/* max message size for program output functions (echo, echo debug, progerr) */

#define	MAX_MESSAGE_SIZE	4096

/* maximum number of retries when waiting for lock */

#define	MAX_RETRIES	300

/* delay (in seconds) between retries when waiting for lock */

#define	RETRY_DELAY_SECS	1

/* Size of buffer increments when reading from pipe */

#define	PIPE_BUFFER_INCREMENT	256

/* Maximum number of arguments to pkg_ExecCmdList */

#define	MAX_EXEC_CMD_ARGS	100

/*
 * These dynamic libraries are required in order to use the zones
 * functionality - if these libraries are not available at runtime,
 * then zones are assumed to NOT be available, and it is assumed that
 * the program is running in the global zone with no non-global zones.
 */

#if	defined(LIBZONECFG_PATH)
#define	ZONECFG1_LIBRARY	LIBZONECFG_PATH
#else	/* defined(LIBZONECFG_PATH) */
#define	ZONECFG1_LIBRARY	"libzonecfg.so.1"
#endif	/* defined(LIBZONECFG_PATH) */

#define	ZONECFG_LIBRARY		"libzonecfg.so"

#define	CONTRACT1_LIBRARY	"libcontract.so.1"
#define	CONTRACT_LIBRARY	"libcontract.so"

/*
 * Environment values used when running commands within a non-global zone
 */

/* SHELL= */

#define	ZONE_FAILSAFESHELL	"/sbin/sh"

/* PATH= */

#define	ZONE_DEF_PATH		"/usr/sbin:/usr/bin"

/* error codes */
#define	ERR_MALLOC_FAIL		-50

/*
 * zone brand list structure
 */

struct _zoneBrandList {
	char			*string_ptr;
	struct _zoneBrandList	*next;
};

/*
 * zone status structure - used to retrieve and hold status of zones
 */

typedef unsigned long _zone_status_t;

struct _zoneListElement_t {
	char		**_zlInheritedDirs;
	char		*_zlName;
	char		*_zlPath;
	char		*_zlScratchName;
	char		*_zlLockObjects;
	/*
	 * the install "state" refers to the zone states listed in
	 * /usr/include/libzonecfg.h that is stored in the zone_state_t
	 * structure and returned from getzoneent_private() - such as:
	 * ZONE_STATE_CONFIGURED, ZONE_STATE_INCOMPLETE,
	 * ZONE_STATE_INSTALLED, ZONE_STATE_READY, ZONE_STATE_MOUNTED,
	 * ZONE_STATE_SHUTTING_DOWN, ZONE_STATE_DOWN.
	 */
	zone_state_t	_zlOrigInstallState;
	zone_state_t	_zlCurrInstallState;
	/*
	 * the kernel "status" refers to the zone status listed in
	 * /usr/include/sys/zone.h, returned by zone_get_state(),
	 * and defined in the zone_status_t enum - such as:
	 * ZONE_IS_UNINITIALIZED, ZONE_IS_READY, ZONE_IS_BOOTING,
	 * ZONE_IS_RUNNING, ZONE_IS_SHUTTING_DOWN, ZONE_IS_EMPTY,
	 * ZONE_IS_DOWN, ZONE_IS_DYING, ZONE_IS_DEAD.
	 */
	zone_status_t	_zlOrigKernelStatus;
	zone_status_t	_zlCurrKernelStatus;
	/*
	 * this is an internal state recorded about the zone (ZSF_xxx).
	 */
	_zone_status_t	_zlStatus;
};

typedef struct _zoneListElement_t zoneListElement_t;

/* bits used in the _zoneListElement _zlStatus variable */

#define	ZST_NOT_BOOTABLE	((_zone_status_t)0x00000001)
#define	ZST_LOCKED		((_zone_status_t)0x00000002)

/*
 * User-specified list of zones.
 */

typedef struct zone_spec_s {
	struct zone_spec_s	*zl_next;
	boolean_t		zl_used;
	char			zl_name[ZONENAME_MAX];
} zone_spec_t;

/*
 * The global data structure used to hold all of the global (extern) data
 * used by this library.
 *
 * --> THESE DEFINITIONS ARE ORDER DEPENDENT BASED <--
 * --> ON THE ORDER OF THE STRUCTURE INITIALIZERS! <--
 */

struct _z_global_data_t {
	char		*_z_ObjectLocks;	/* object locks held */
	char 		*_z_root_dir;		/* root for zone lib fctns */
	int		_z_SigReceived;		/* received signal count */
	pid_t		_z_ChildProcessId;	/* child to propagate sigs to */
	zone_spec_t	*_zone_spec;		/* zones to operate on */
	_z_printf_fcn_t	_z_echo;		/* operational message fcn */
	_z_printf_fcn_t	_z_echo_debug;		/* debug message fcn */
	_z_printf_fcn_t	_z_progerr;		/* program error fcn */
};

typedef struct _z_global_data_t z_global_data_t;

/*
 * When _INSTZONES_LIB_Z_DEFINE_GLOBAL_DATA is defined,
 * instzones_lib.h will define the z_global_data structure.
 * Otherwise an extern to the structure is inserted.
 *
 * --> THESE DEFINITIONS ARE ORDER DEPENDENT BASED ON <--
 * --> THE ORDER OF THE _z_global_data_t STRUCTURE!!! <--
 */

#if	defined(_INSTZONES_LIB_Z_DEFINE_GLOBAL_DATA)

/* define and initialize structure */

z_global_data_t _z_global_data = {
	NULL,	/* *_z_ObjectLocks */
	"",	/* *_z_root_dir */
	0,	/* _z_SigReceived */
	-1,	/* _z_ChildProcessId */
	NULL,	/* *_zone_spec */
	NULL,	/* _z_echo */
	NULL,	/* _z_echo_debug */
	NULL	/* _z_progerr */
};

#else	/* !defined(_INSTZONES_LIB__Z_DEFINE_GLOBAL_DATA) */

/* define structure extern */

extern z_global_data_t _z_global_data;

#endif	/* defined(_INSTZONES_LIB_Z_DEFINE_GLOBAL_DATA) */

/* function prototypes */

/*
 *  The following functions can be used by other libs, but not
 *  by applications.
 */

/* ---> zones_states.c */

boolean_t	_z_make_zone_ready(zoneListElement_t *a_zlem);
boolean_t	_z_make_zone_down(zoneListElement_t *a_zlem);
boolean_t	_z_make_zone_running(zoneListElement_t *a_zlem);
int		UmountAllZones(char *mntpnt);
void		*_z_calloc(size_t size);
void		*_z_malloc(size_t size);
void		*_z_realloc(void *ptr, size_t size);
void		*_z_strdup(char *str);

/* ---> zones_utils.c */

/*PRINTFLIKE1*/
void		_z_program_error(char *fmt, ...);
/*PRINTFLIKE1*/
void		_z_echo(char *fmt, ...);
/*PRINTFLIKE1*/
void		_z_echoDebug(char *a_fmt, ...);
int		_z_is_directory(char *path);
char		**_z_get_inherited_dirs(char *a_zoneName);
boolean_t	_z_running_in_global_zone(void);
boolean_t	_z_zones_are_implemented(void);
void		_z_sig_trap(int a_signo);
int		_z_close_file_descriptors(void *a_fds, int a_fd);
boolean_t	_z_brands_are_implemented(void);


/* ---> zones_locks.c */

boolean_t	_z_adjust_lock_object_for_rootpath(char **r_result,
			char *a_lockObject);
boolean_t	_z_acquire_lock(char **r_lockKey, char *a_zoneName,
			char *a_lock, pid_t a_pid, boolean_t a_wait);
boolean_t	_z_lock_zone(zoneListElement_t *a_zlst,
			ZLOCKS_T a_lflags);
boolean_t	_z_lock_zone_object(char **r_objectLocks,
			char *a_zoneName, char *a_lockObject,
			pid_t a_pid, char *a_waitingMsg,
			char *a_busyMsg);
boolean_t	_z_release_lock(char *a_zoneName, char *a_lock,
			char *a_key, boolean_t a_wait);
boolean_t	_z_unlock_zone(zoneListElement_t *a_zlst,
			ZLOCKS_T a_lflags);
boolean_t	_z_unlock_zone_object(char **r_objectLocks,
			char *a_zoneName, char *a_lockObject,
			char *a_errMsg);

/* ---> zones_args.c */

void		_z_free_args(argArray_t *a_args);
argArray_t	*_z_new_args(int initialCount);
/*PRINTFLIKE2*/
boolean_t	_z_add_arg(argArray_t *a_args, char *a_format, ...);
int		_z_get_argc(argArray_t *a_args);
char		**_z_get_argv(argArray_t *a_args);

/* ---> zones_str.c */

boolean_t	_z_strContainsToken(char *a_string, char *a_token,
			char *a_separators);
char		*_z_strGetToken(char *r_sep, char *a_string,
			int a_index, char *a_separators);
void		_z_strRemoveLeadingWhitespace(char **a_str);
void		_z_strGetToken_r(char *r_sep, char *a_string,
			int a_index, char *a_separators, char *a_buf,
			int a_bufLen);
void		_z_strAddToken(char **a_old, char *a_new,
			char a_separator);
void		_z_strRemoveToken(char **r_string, char *a_token,
			char *a_separators, int a_index);
/*PRINTFLIKE3*/
void		_z_strPrintf_r(char *a_buf, int a_bufLen,
			char *a_format, ...);
/*PRINTFLIKE1*/
char		*_z_strPrintf(char *a_format, ...);

/* ---> zones_exec.c */

int		_z_zone_exec(int *r_status, char **r_results, char *a_inputFile,
			char *a_path, char *a_argv[], const char *a_zoneName,
			int *a_fds);
int		_zexec(const char *a_zoneName,
			const char *path, char *argv[]);
char		*_zexec_add_env(char *name, char *value);
int		_zexec_init_template(void);
char		**_zexec_prep_env();

/*
 * C++ postfix
 */

#ifdef __cplusplus
}
#endif

#endif	/* _INSTZONES_LIB_H */
