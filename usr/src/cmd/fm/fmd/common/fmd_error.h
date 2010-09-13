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

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_FMD_ERROR_H
#define	_FMD_ERROR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <errno.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This enum definition is used to define a set of error tags associated with
 * the fmd daemon's various error conditions.  The shell script mkerror.sh is
 * used to parse this file and create a corresponding fmd_error.c source file.
 * If you do something other than add a new error tag here, you may need to
 * update the mkerror shell script as it is based upon simple regexps.
 */
typedef enum fmd_errno {
    EFMD_UNKNOWN = 1000, /* unknown fault management daemon error */
    EFMD_PANIC,		/* unrecoverable fatal error in daemon occurred */
    EFMD_EXIT,		/* failed to initialize fault management daemon */
    EFMD_MODULE,	/* fmd module detected or caused an error */
    EFMD_CONF_OPEN,	/* failed to open configuration file */
    EFMD_CONF_KEYWORD,	/* invalid configuration file keyword */
    EFMD_CONF_NOPROP,	/* invalid configuration file parameter name */
    EFMD_CONF_NODEFER,	/* deferred properties not permitted in this file */
    EFMD_CONF_PROPDUP,	/* duplicate configuration file parameter name */
    EFMD_CONF_INVAL,	/* invalid value for configuration file property */
    EFMD_CONF_OVERFLOW,	/* configuration value too large for data type */
    EFMD_CONF_USAGE,	/* syntax error in configuration file directive */
    EFMD_CONF_DEFAULT,	/* invalid default value for configuration property */
    EFMD_CONF_ERRS,	/* error(s) detected in configuration file */
    EFMD_CONF_IO,	/* i/o error prevented configuration file processing */
    EFMD_CONF_PROPNAME,	/* configuration property name is not an identifier */
    EFMD_CONF_RDONLY,	/* configuration property is read-only */
    EFMD_CONF_DEFER,	/* invalid deferred configuration file property */
    EFMD_CONF_UNDEF,	/* configuration property is not defined */
    EFMD_MOD_INIT,	/* failed to initialize module */
    EFMD_MOD_FINI,	/* failed to uninitialize module */
    EFMD_MOD_THR,	/* failed to create processing thread for module */
    EFMD_MOD_JOIN,	/* failed to join processing thread for module */
    EFMD_MOD_CONF,	/* error(s) detected in module configuration file */
    EFMD_MOD_DICT,	/* failed to open module's event code dictionary */
    EFMD_MOD_LOADED,	/* specified module is already loaded */
    EFMD_MOD_NOMOD,	/* specified module is not loaded */
    EFMD_MOD_FAIL,	/* module failed due to preceding error */
    EFMD_MOD_TOPO,	/* failed to obtain topology handle */
    EFMD_RTLD_OPEN,	/* rtld failed to open shared library plug-in */
    EFMD_RTLD_INIT,	/* shared library plug-in does not define _fmd_init */
    EFMD_BLTIN_NAME,	/* built-in plug-in name not found in definition list */
    EFMD_BLTIN_INIT,	/* built-in plug-in does not define init function */
    EFMD_EVENT_INVAL,	/* event interface programming error */
    EFMD_XPRT_INVAL,	/* transport interface programming error */
    EFMD_XPRT_PAYLOAD,	/* transport event has invalid payload */
    EFMD_XPRT_OWNER,	/* transport can only be manipulated by owner */
    EFMD_XPRT_THR,	/* failed to create thread for transport */
    EFMD_XPRT_LIMIT,	/* limit on number of open transports exceeded */
    EFMD_TIME_GETTOD,	/* failed to get current time-of-day */
    EFMD_LOG_OPEN,	/* failed to open and initialize log file */
    EFMD_LOG_CLOSE,	/* failed to close log file */
    EFMD_LOG_EXACCT,	/* failed to perform log exacct operation */
    EFMD_LOG_APPEND,	/* failed to append event to log */
    EFMD_LOG_MINFREE,	/* insufficient min fs space to append event to log */
    EFMD_LOG_COMMIT,	/* failed to commit event to log */
    EFMD_LOG_INVAL,	/* invalid log header information */
    EFMD_LOG_VERSION,	/* invalid log version information */
    EFMD_LOG_UNPACK,	/* failed to unpack data in log */
    EFMD_LOG_REPLAY,	/* failed to replay log content */
    EFMD_LOG_UPDATE,	/* failed to update log toc */
    EFMD_LOG_ROTATE,	/* failed to rotate log file */
    EFMD_LOG_ROTBUSY,	/* failed to rotate log file due to pending events */
    EFMD_ASRU_NODIR,	/* failed to open asru cache directory */
    EFMD_ASRU_EVENT,	/* failed to process asru event log */
    EFMD_ASRU_FMRI,	/* failed to convert asru fmri to string */
    EFMD_ASRU_NOENT,	/* failed to locate specified asru entry */
    EFMD_ASRU_UNLINK,	/* failed to delete asru cache entry */
    EFMD_ASRU_DUP,	/* asru log is a duplicate of an existing asru */
    EFMD_FMRI_SCHEME,	/* fmri scheme module is missing or failed to load */
    EFMD_FMRI_OP,	/* fmri scheme module operation failed */
    EFMD_FMRI_INVAL,	/* fmri nvlist is missing required element */
    EFMD_FMRI_NOTSUP,	/* fmri scheme module does not support operation */
    EFMD_VER_OLD,	/* plug-in is compiled using an obsolete fmd API */
    EFMD_VER_NEW,	/* plug-in is compiled using a newer fmd API */
    EFMD_HDL_INIT,	/* client handle wasn't initialized by _fmd_init */
    EFMD_HDL_INFO,	/* client info is missing required information */
    EFMD_HDL_PROP,	/* client info includes invalid property definition */
    EFMD_HDL_NOTREG,	/* client handle has never been registered */
    EFMD_HDL_REG,	/* client handle has already been registered */
    EFMD_HDL_TID,	/* client handle must be registered by owner */
    EFMD_HDL_INVAL,	/* client handle is corrupt or not owned by caller */
    EFMD_HDL_ABORT,	/* client requested that module execution abort */
    EFMD_HDL_NOMEM,	/* client memory limit exceeded */
    EFMD_PROP_TYPE,	/* property accessed using incompatible type */
    EFMD_PROP_DEFN,	/* property is not defined */
    EFMD_STAT_FLAGS,	/* invalid flags passed to fmd_stat_* function */
    EFMD_STAT_TYPE,	/* invalid operation for statistic type */
    EFMD_STAT_BADTYPE,	/* invalid type for statistic */
    EFMD_STAT_BADNAME,	/* invalid name for statistic */
    EFMD_STAT_DUPNAME,	/* statistic name is already defined in collection */
    EFMD_STAT_NOMEM,	/* failed to allocate memory for statistics snapshot */
    EFMD_CASE_OWNER,	/* case can only be manipulated or closed by owner */
    EFMD_CASE_STATE,	/* case is not in appropriate state for operation */
    EFMD_CASE_EVENT,	/* case operation failed due to invalid event */
    EFMD_CASE_INVAL,	/* case uuid does not match any known case */
    EFMD_BUF_INVAL,	/* buffer specification uses invalid name or size */
    EFMD_BUF_LIMIT,	/* client exceeded limit on total buffer space */
    EFMD_BUF_NOENT,	/* no such buffer is currently defined by client */
    EFMD_BUF_OFLOW,	/* write would overflow the size of this buffer */
    EFMD_BUF_EXISTS,	/* buffer with the specified name already exists */
    EFMD_SERD_NAME,	/* no serd engine with the specified name exists */
    EFMD_SERD_EXISTS,	/* serd engine with the specified name already exists */
    EFMD_THR_CREATE,	/* failed to create auxiliary module thread */
    EFMD_THR_LIMIT,	/* limit on module auxiliary threads exceeded */
    EFMD_THR_INVAL,	/* invalid thread id specified for thread call */
    EFMD_THR_JOIN,	/* failed to join with auxiliary thread */
    EFMD_TIMER_INVAL,	/* invalid time delta or id specified for timer call */
    EFMD_TIMER_LIMIT,	/* client exceeded limit on number of pending timers */
    EFMD_CKPT_NOMEM,	/* failed to allocate checkpoint buffer */
    EFMD_CKPT_MKDIR,	/* failed to create checkpoint directory */
    EFMD_CKPT_CREATE,	/* failed to create checkpoint file */
    EFMD_CKPT_COMMIT,	/* failed to commit checkpoint file */
    EFMD_CKPT_DELETE,	/* failed to delete checkpoint file */
    EFMD_CKPT_OPEN,	/* failed to open checkpoint file */
    EFMD_CKPT_SHORT,	/* checkpoint file has been truncated or corrupted */
    EFMD_CKPT_INVAL,	/* checkpoint file has invalid header or content */
    EFMD_CKPT_RESTORE,	/* failed to restore checkpoint file */
    EFMD_RPC_REG,	/* failed to register rpc service */
    EFMD_RPC_BOUND,	/* rpc program/version is already bound */
    EFMD_NVL_INVAL,	/* invalid nvlist function argument */
    EFMD_CTL_INVAL,	/* invalid fault manager control event */
    EFMD_END		/* end of custom errno list (to ease auto-merge) */
} fmd_errno_t;

extern const char *fmd_errclass(int);
extern const char *fmd_strerror(int);
extern int fmd_set_errno(int);

#ifdef	__cplusplus
}
#endif

#endif	/* _FMD_ERROR_H */
