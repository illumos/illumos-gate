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
#ifndef	_MMS_MGMT_H_
#define	_MMS_MGMT_H_


#include <sys/types.h>
#include <sys/param.h>
#include <netdb.h>
#include <pwd.h>
#include <libnvpair.h>

#include "mms_list.h"	/* temporary, change over to nvlists */

/* MMS Options and Default Values */

/* All MMS configurable options for all objects */

#define	O_MMHOST	"mmhost"
#define	O_MMPORT	"port"
#define	O_MMPASS	"password"
#define	O_OBJTYPE	"objtype"
#define	O_SECURECOMM	"secure-comm"
#define	O_SSLENABLED	"sslenabled"
#define	O_SSLPASSFILE	"sslpassfile"
#define	O_CERTFILE	"certfile"
#define	O_CRLFILE	"crlfile"
#define	O_PEERFILE	"peerfile"
#define	O_WELCOME	"welcomefile"
#define	O_DHFILE	"dhfile"
#define	O_VERIFY	"verify"
#define	O_LOGLEVEL	"log-level"
#define	O_LOGFILE	"log-file"
#define	O_DBDIR		"db-dir"
#define	O_DBPORT	"db-port"
#define	O_DBLOG		"db-log"
#define	O_DBNAME	"dbname"
#define	O_DBHOST	"dbhost"
#define	O_NUMRESTART	"num-restarts"
#define	O_ATTENDED	"attended"
#define	O_NUMSOCKET	"num-socket"
#define	O_DKTIMEOUT	"disk-timeout"
#define	O_SERIALNO	"serialno"
#define	O_ACSHOST	"acsls"
#define	O_ACSPORT	"acsport"
#define	O_OBJSTATE	"state"
#define	O_MSGLEVEL	"msg-level"
#define	O_TRACELEVEL	"trace-level"
#define	O_TRACESZ	"trace-file-size"
#define	O_MMSLIB	"library"
#define	O_DEVCONN	"connection"
#define	O_LIBCONN	"libconntype"
#define	O_APPS		"apps"
#define	O_UNLOADTM	"unload-time"
#define	O_RESERVE	"reserve"
#define	O_RETENTION	"retain"
#define	O_VALIDATEEXP	"validate-expiration"
#define	O_VALIDATEVOL	"validate-volid"
#define	O_VALIDATEFN	"validate-filename"
#define	O_OVERWRITEEXT	"overwrite-existing"
#define	O_RESPTXT	"responsetxt"
#define	O_FORCE		"force"
#define	O_MPOOL		"mpool"
#define	O_HOST		"host"
#define	O_UNCFG		"uncfg"
#define	O_NAME		"name"
#define	O_ACSNUM	"acs"
#define	O_LSMNUM	"lsm"
#define	O_LMNAME	"lmname"
#define	O_DMNAME	"dmname"
#define	O_DGNAME	"drivegroupname"
#define	O_MMSDRV	"drive"
#define	O_TYPE		"hwtype"
#define	O_ONLINE	"online"
#define	O_DISABLED	"disabled"
#define	O_VOLUMES	"volumes"
#define	O_DEVPATH	"devpath"
#define	O_SIZE		"size"
#define	O_MTYPE		"mediatype"
#define	O_VOLTYPE	"voltype"
#define	O_ACSLSDIR	"acslsdir"
#define	O_DENSITY	"density"
#define	O_NOWAIT	"nowait"
#define	O_NOREWIND	"norewind"
/* helpers for MMS services */
#define	MM	0x00000001
#define	WCR	0x00000002
#define	DB	0x00000004

#if 0
#define	MMSVC	"svc:/application/management/mms:mm"
#define	WCRSVC	"svc:/application/management/mms:wcr"
#define	DBSVC	"svc:/application/management/mms:db"
#endif
#define	MMSVC	MMS_CFG_MM_INST
#define	WCRSVC	MMS_CFG_WCR_INST
#define	DBSVC	MMS_CFG_DB_INST

/* defaults */
#define	MMSSBINDIR	"/usr/bin"
#define	MMSVARDIR	"/var/mms"
#define	MMSETCDIR	"/etc/mms"
#define	MMSSSLDIR	"/var/mms/ssl/pub"
#define	MMSLOGDIR	MMSVARDIR"/logs"
#define	MMS_DEF_DBDIR	MMSVARDIR"/db"
#define	MMS_DEF_MMPORT	"7151"
#define	MMS_DEF_DBPORT	"7656"
#define	MMS_DEF_LOGLVL	"error"

/*
 * mms_mgmt_init_host()
 *
 *  DESCRIPTION:
 *  Sets all required MMS options, and starts required services.
 *
 *  On an MMS client system,
 *	sets MM host, port and administrative password
 *	sets SSL options, if desired
 *	starts the Watcher daemon
 *
 *  On on MMS server system,
 *	creates MMS database admin user
 *	initializes MMS database and starts database server
 *	sets MM options [TBD:  list these with explanation]
 *	starts MM daemon and Watcher daemon
 *
 *  ARGUMENTS:
 *	nvlist_t *opts		key/value pairs for requested options
 *	nvlist_t **errs		optional - used to return detailed errors
 *				about invalid/missing options, and other
 *				operational failures during initialization.
 *				If 'errs' is non-NULL, a new nvlist will be
 *				allocated.  The caller should free this list
 *				with nvlist_free().
 *
 *  RETURN VALUES:
 *
 *	0		Success
 *	MMS_MGMT_NOARG	'opts' argument missing
 *	EINVAL		One or more requested options is invalid
 *	EALREADY	Host has already been initialized for MMS
 *	ENOMEM		Out of memory
 *	[others TBD]
 */

int
mms_mgmt_init_host(nvlist_t *opts, nvlist_t **errs);

/*
 *  Required opts that are not in inopts, and options with invalid values
 *  are added to the argument nvlist "errlist".
 */
int mms_mgmt_set_opts(nvlist_t *optlist, nvlist_t *errlist);

/*
 * mms_mgmt_get_opts(char* type, nvlist_t **opts)
 */
int
mms_mgmt_get_opts(char *type, nvlist_t **opts);


int mms_mgmt_uninitialize(void);

/* MMS Database Functions */
int
mgmt_set_db_opts(nvlist_t *opts, nvlist_t *errlist);

int
mgmt_db_init(void);

int
mgmt_db_create(int initialize, int populate, nvlist_t *optlist);

int
mgmt_db_drop(void);

int
mgmt_db_check(void);

int
mgmt_db_dump(char *dumpdir, char *dumpfile, int len);

int
mgmt_db_restore(char *dumpfile);

/* Library and Drive functions */
/*
 * mms_mgmt_discover_libraries()
 *
 *  Finds ACSLS libraries, and optionally associated drives.
 *  Those already configured for use with MMS are filtered out unless
 *  'showall' is TRUE.
 */
int
mms_mgmt_discover_libraries(
	char *acshost, boolean_t getdrives, mms_list_t *liblist);

void free_drive_list(void *arg);
void free_acslib_list(void *arg);

/* Online/Offline functions */
int
mms_mgmt_set_state(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_add_application(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_remove_application(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_modify_application(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_discover_media(
    void *session, boolean_t showall, nvlist_t *opts, mms_list_t *vol_list,
    nvlist_t *errs);

int
mms_mgmt_add_mpool(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_modify_mpool(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_remove_mpool(void *session, char *mpool, boolean_t force,
    nvlist_t *errs);

int
mms_mgmt_add_cartridges(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_remove_cartridges(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_set_pass(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_list_vols(void *session, nvlist_t *nvl, nvlist_t **vol_list);

int
mms_mgmt_list_drives(void *session, nvlist_t *nvl, nvlist_t *errs,
    nvlist_t **drvs);

int
mms_mgmt_list_supported_types(void *session, nvlist_t **supported);

int
mms_mgmt_show_cartridge_type(void *session, char *voltype, nvlist_t **nvl);

int
mms_mgmt_create_voltype(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_remove_voltype(void *session, char *voltype);

int
mms_mgmt_modify_voltype(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_list_libraries(void *session, nvlist_t *nvl, nvlist_t *errs,
    nvlist_t **libs);

int
mms_mgmt_show_requests(void *session, nvlist_t *nvl, nvlist_t **reqs);

int
mms_mgmt_accept_request(void *session, char *reqID, char *text);

int
mms_mgmt_reject_request(void *session, char *reqID, char *text);

int
mms_mgmt_add_dklib(void *session, char *libname, nvlist_t *errs);

int
mms_mgmt_create_dkvol(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_create_dkdrive(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_show_apps(void *session, nvlist_t *nvl, nvlist_t **apps);

int
mms_mgmt_show_mpool(void *session, nvlist_t *nvl, nvlist_t **pools);

int
mms_mgmt_set_dkvol_mode(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mgmt_delete_dkvol(char *volpath, nvlist_t *errs);

int
mms_mgmt_create_partition(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_remove_partition(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_label_multi(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_label_vol(void *session, nvlist_t *nvl, nvlist_t *errs);


/* mount processing door info */
#define	MMS_MGMT_MOUNT		1
#define	MMS_MGMT_UNMOUNT	2

typedef struct {
	int		op;
	int		st;
	char		cartridge[1024];
	char		library[1024];
	char		volname[1024];
	char		devname[1024];
	char		app[1024];
	char		inst[1024];
	char		pass[1024];
	char		cmd[8192];
} mmsmnt_arg_t;

int
mms_mgmt_mount_vol(void *session, nvlist_t *nvl, nvlist_t *errs);

int
mms_mgmt_unmount_vol(nvlist_t *nvl, nvlist_t *errs);

int
mgmt_set_db_pass(char *dbpass, nvlist_t *errs);

#endif	/* _MMS_MGMT_H_ */
