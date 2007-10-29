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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <locale.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include <synch.h>
#include <thread.h>
#include <string.h>
#include <unistd.h>
#include "nscd_log.h"
#include "nscd_config.h"
#include "nscd_switch.h"
#include "cache.h"

/*
 * old nscd debug levels
 */
#define	DBG_OFF		0
#define	DBG_CANT_FIND	2
#define	DBG_NETLOOKUPS	4
#define	DBG_ALL		6

/* max. chars in a nscd log entry */
#define	LOGBUFLEN	1024

/* configuration for the nscd log component */
int		_nscd_log_comp = 0x0;
int		_nscd_log_level = 0x0;
static char	_nscd_logfile[PATH_MAX] = { 0 };

#define	NSCD_DEBUG_NONE		'0'
#define	NSCD_DEBUG_OPEN		'1'
#define	NSCD_DEBUG_CLOSE	'2'

static char	_nscd_debug = NSCD_DEBUG_NONE;
static char	_nscd_logfile_d[PATH_MAX] = { 0 };
static char	_nscd_logfile_s[PATH_MAX] = { 0 };

/* statistics data */
static nscd_cfg_stat_global_log_t logstats = {
	NSCD_CFG_STAT_GROUP_INFO_GLOBAL_LOG, 0 };

/* if no log file specified, log entry goes to stderr */
int _logfd = 2;


/* close old log file and open a new one */
static nscd_rc_t
_nscd_set_lf(
	char	*lf)
{
	int	newlogfd;
	char	*me = "_nscd_set_lf";

	/*
	 *  don't try and open the log file /dev/null
	 */
	if (lf == NULL || *lf == 0) {
		/* ignore empty log file specs */
		return (NSCD_SUCCESS);
	} else if (strcmp(lf, "/dev/null") == 0) {
		(void) strlcpy(_nscd_logfile, lf, PATH_MAX);
		if (_logfd >= 0)
			(void) close(_logfd);
		_logfd = -1;
		return (NSCD_SUCCESS);
	} else if (strcmp(lf, "stderr") == 0) {
		(void) strlcpy(_nscd_logfile, lf, PATH_MAX);
		if (_logfd != -1 && _logfd != 2)
			(void) close(_logfd);
		_logfd = 2;
		return (NSCD_SUCCESS);
	} else {

		/*
		 * In order to open this file securely, we'll try a few tricks
		 */

		if ((newlogfd = open(lf, O_EXCL|O_WRONLY|O_CREAT, 0644)) < 0) {
			/*
			 * File already exists... now we need to get cute
			 * since opening a file in a world-writeable directory
			 * safely is hard = it could be a hard link or a
			 * symbolic link to a system file.
			 */
			struct stat before;

			if (lstat(lf, &before) < 0) {
				if (_nscd_debug == NSCD_DEBUG_NONE)
					_nscd_logit(me, "Cannot open new "
					    "logfile \"%s\": %sn",
					    lf, strerror(errno));
				return (NSCD_CFG_FILE_OPEN_ERROR);
			}

			if (S_ISREG(before.st_mode) && /* no symbolic links */
			    (before.st_nlink == 1) && /* no hard links */
			    (before.st_uid == 0)) {   /* owned by root */
				if ((newlogfd =
				    open(lf, O_APPEND|O_WRONLY, 0644)) < 0) {
					if (_nscd_debug == NSCD_DEBUG_NONE)
						_nscd_logit(me,
						    "Cannot open new "\
						    "logfile \"%s\": %s\n", lf,
						    strerror(errno));
					return (NSCD_CFG_FILE_OPEN_ERROR);
				}
			} else {
				if (_nscd_debug == NSCD_DEBUG_NONE)
					_nscd_logit(me, "Cannot use specified "
					    "logfile \"%s\": "\
					    "file is/has links or isn't "
					    "owned by root\n", lf);
				return (NSCD_CFG_FILE_OPEN_ERROR);
			}
		}

		(void) close(_logfd);
		(void) strlcpy(_nscd_logfile, lf, PATH_MAX);
		_logfd = newlogfd;
		if (_nscd_debug == NSCD_DEBUG_NONE)
			_nscd_logit(me, "Start of new logfile %s\n", lf);
	}
	return (NSCD_SUCCESS);
}


/* log an entry to the configured nscd log file */
void
_nscd_logit(
	char		*funcname,
	char		*format,
	...)
{
	static mutex_t	loglock = DEFAULTMUTEX;
	struct timeval	tv;
	char		tid_buf[32];
	char		pid_buf[32];
	char		buffer[LOGBUFLEN];
	int		safechars, offset;
	va_list		ap;

	if (_logfd < 0)
		return;

	if (_nscd_debug == NSCD_DEBUG_OPEN) {
		(void) mutex_lock(&loglock);
		if (_nscd_debug == NSCD_DEBUG_OPEN &&
		    *_nscd_logfile_d != '\0' &&
		    (strcmp(_nscd_logfile, "/dev/null") == 0 ||
		    strcmp(_nscd_logfile, "stderr") == 0)) {
			(void) strlcpy(_nscd_logfile_s,
			    _nscd_logfile, PATH_MAX);
			(void) _nscd_set_lf(_nscd_logfile_d);
		}
		_nscd_debug = NSCD_DEBUG_NONE;
		(void) mutex_unlock(&loglock);
	} else if (_nscd_debug == NSCD_DEBUG_CLOSE) {
		(void) mutex_lock(&loglock);
		if (_nscd_debug == NSCD_DEBUG_CLOSE)
			(void) _nscd_set_lf(_nscd_logfile_s);
		_nscd_debug = NSCD_DEBUG_NONE;
		(void) mutex_unlock(&loglock);
	}

	va_start(ap, format);

	if (gettimeofday(&tv, NULL) != 0 ||
	    ctime_r(&tv.tv_sec, buffer, LOGBUFLEN) == NULL) {
		(void) snprintf(buffer, LOGBUFLEN,
		    "<time conversion failed>\t");
	} else {
		(void) sprintf(tid_buf, "--%d", thr_self());
		(void) sprintf(pid_buf, "--%ld", getpid());
		/*
		 * ctime_r() includes some stuff we don't want;
		 * adjust length to overwrite " YYYY\n" and
		 * include tid string length.
		 */
		offset = strlen(buffer) - 6;
		safechars = LOGBUFLEN - (offset - 1);
		(void) snprintf(buffer + offset,
		    safechars, ".%.4ld%s%s\t%s:\n\t\t",
		    tv.tv_usec/100, tid_buf, pid_buf,
		    funcname);
	}
	offset = strlen(buffer);
	safechars = LOGBUFLEN - (offset - 1);
	/*LINTED: E_SEC_PRINTF_VAR_FMT*/
	if (vsnprintf(buffer + offset, safechars, format, ap) >
	    safechars) {
		(void) strncat(buffer, "...\n", LOGBUFLEN);
	}

	(void) mutex_lock(&loglock);
	(void) write(_logfd, buffer, strlen(buffer));
	logstats.entries_logged++;
	(void) mutex_unlock(&loglock);

	va_end(ap);
}

/*
 * Map old nscd debug level (0 -10) to log level:
 *      -- >= 6: DBG_ALL 		--> NSCD_LOG_LEVEL_ALL
 *      -- >= 4: DBG_DBG_NETLOOKUPS 	--> NSCD_LOG_LEVEL_CANT_FIND
 *      -- >= 2: DBG_CANT_FIND 		--> NSCD_LOG_LEVEL_CANT_FIND
 *      -- >= 0: DBG_OFF 		--> NSCD_LOG_LEVEL_NONE
 */
static int
debug_to_log_level(
	int	level)
{
	if (level >= 0 && level <= 10) {
		if (level >= DBG_ALL)
			return (NSCD_LOG_LEVEL_ALL);
		else if (level >= DBG_NETLOOKUPS)
			return (NSCD_LOG_LEVEL_CANT_FIND);
		else if (level >= DBG_CANT_FIND)
			return (NSCD_LOG_LEVEL_CANT_FIND);
		else if (level >= DBG_OFF)
			return (NSCD_LOG_LEVEL_NONE);
	}
	return (level);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_log_notify(
	void				*data,
	struct nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				*cookie)
{

	nscd_cfg_global_log_t		*logcfg;
	int				off;

	/*
	 * At init time, the whole group of config params are received.
	 * At update time, group or individual parameter value could
	 * be received.
	 */

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {

		logcfg = (nscd_cfg_global_log_t *)data;

		_nscd_log_comp = logcfg->debug_comp;
		_nscd_log_level = logcfg->debug_level;

		/*
		 * logcfg->logfile should have been opened
		 * by _nscd_cfg_log_verify()
		 */

		return (NSCD_SUCCESS);
	}

	/*
	 * individual config parameter
	 */
	off = offsetof(nscd_cfg_global_log_t, debug_comp);
	if (pdesc->p_offset == off) {
		_nscd_log_comp = *(nscd_cfg_bitmap_t *)data;
		return (NSCD_SUCCESS);
	}

	off = offsetof(nscd_cfg_global_log_t, debug_level);
	if (pdesc->p_offset == off)
		_nscd_log_level = *(nscd_cfg_bitmap_t *)data;

	/*
	 * logcfg->logfile should have been opened
	 * by _nscd_cfg_log_verify()
	 */

	return (NSCD_SUCCESS);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_log_verify(
	void				*data,
	struct	nscd_cfg_param_desc	*pdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			dflag,
	nscd_cfg_error_t		**errorp,
	void				**cookie)
{
	nscd_cfg_global_log_t		*logcfg;
	nscd_cfg_bitmap_t		bt;
	int				off;

	/*
	 * There is no switch db specific config params
	 * for the nscd log component. It is a bug if
	 * the input param description is global.
	 */
	if (_nscd_cfg_flag_is_not_set(pdesc->pflag, NSCD_CFG_PFLAG_GLOBAL))
		return (NSCD_CFG_PARAM_DESC_ERROR);

	/*
	 * At init time, the whole group of config params are received.
	 * At update time, group or individual parameter value could
	 * be received.
	 */

	if (_nscd_cfg_flag_is_set(dflag, NSCD_CFG_DFLAG_GROUP)) {

		logcfg = (nscd_cfg_global_log_t *)data;

		if (_nscd_cfg_bitmap_valid(logcfg->debug_comp,
		    NSCD_LOG_ALL) == 0)
			return (NSCD_CFG_SYNTAX_ERROR);

		if (_nscd_cfg_bitmap_valid(logcfg->debug_level,
		    NSCD_LOG_LEVEL_ALL) == 0)
			return (NSCD_CFG_SYNTAX_ERROR);

		if (logcfg->logfile != NULL)
			return (_nscd_set_lf(logcfg->logfile));

		return (NSCD_SUCCESS);
	}

	/*
	 * individual config parameter
	 */

	off = offsetof(nscd_cfg_global_log_t, debug_comp);
	if (pdesc->p_offset == off) {

		bt = *(nscd_cfg_bitmap_t *)data;
		if (_nscd_cfg_bitmap_valid(bt, NSCD_LOG_ALL) == 0)
			return (NSCD_CFG_SYNTAX_ERROR);

		return (NSCD_SUCCESS);
	}

	off = offsetof(nscd_cfg_global_log_t, debug_level);
	if (pdesc->p_offset == off) {

		bt = *(nscd_cfg_bitmap_t *)data;
		if (_nscd_cfg_bitmap_valid(bt, NSCD_LOG_LEVEL_ALL) == 0)
			return (NSCD_CFG_SYNTAX_ERROR);

		return (NSCD_SUCCESS);
	}

	off = offsetof(nscd_cfg_global_log_t, logfile);
	if (pdesc->p_offset == off) {
		if (data != NULL)
			return (_nscd_set_lf((char *)data));
		else
			return (NSCD_SUCCESS);
	}

	return (NSCD_CFG_PARAM_DESC_ERROR);
}

/* ARGSUSED */
nscd_rc_t
_nscd_cfg_log_get_stat(
	void				**stat,
	struct nscd_cfg_stat_desc	*sdesc,
	nscd_cfg_id_t			*nswdb,
	nscd_cfg_flag_t			*dflag,
	void				(**free_stat)(void *stat),
	nscd_cfg_error_t		**errorp)
{

	*(nscd_cfg_stat_global_log_t **)stat = &logstats;

	/* indicate the statistics are static, i.e., do not free */
	*dflag = _nscd_cfg_flag_set(*dflag, NSCD_CFG_DFLAG_STATIC_DATA);

	return (NSCD_SUCCESS);
}

/*
 * set the name of the current log file and make it current.
 */
nscd_rc_t
_nscd_set_log_file(
	char			*name)
{
	nscd_rc_t		rc;
	nscd_cfg_handle_t	*h;

	rc = _nscd_cfg_get_handle("logfile", NULL, &h, NULL);
	if (rc != NSCD_SUCCESS)
		return (rc);

	rc = _nscd_cfg_set(h, name, NULL);
	_nscd_cfg_free_handle(h);
	if (rc != NSCD_SUCCESS)
		exit(rc);

	return (NSCD_SUCCESS);
}

/* Set debug level to the new one and make it current */
nscd_rc_t
_nscd_set_debug_level(
	int			level)
{
	nscd_rc_t		rc;
	nscd_cfg_handle_t	*h;
	int			l = 0;
	int			c = -1;

	/* old nscd debug level is 1 to 10, map it to log_level and log_comp */
	if (level >= 0 && level <= 10) {
		l = debug_to_log_level(level);
		c = NSCD_LOG_CACHE;
	} else
		l = level;

	if (level < 0)
		c = -1 * level / 1000000;

	if (c != -1) {
		rc = _nscd_cfg_get_handle("debug-components", NULL, &h, NULL);
		if (rc != NSCD_SUCCESS)
			return (rc);

		rc = _nscd_cfg_set(h, &c, NULL);
		_nscd_cfg_free_handle(h);
		if (rc != NSCD_SUCCESS)
			exit(rc);
	}

	rc = _nscd_cfg_get_handle("debug-level", NULL, &h, NULL);
	if (rc != NSCD_SUCCESS)
		return (rc);

	if (level < 0)
		l = -1 * level % 1000000;

	rc = _nscd_cfg_set(h, &l, NULL);
	_nscd_cfg_free_handle(h);
	if (rc != NSCD_SUCCESS)
		exit(rc);

	return (NSCD_SUCCESS);
}

void
_nscd_get_log_info(
	char	*level,
	int	llen,
	char	*file,
	int	flen)
{
	if (_nscd_log_level != 0)
		(void) snprintf(level, llen, "%d", _nscd_log_level);
	if (*_nscd_logfile != '\0')
		(void) strlcpy(file, _nscd_logfile, flen);
}
