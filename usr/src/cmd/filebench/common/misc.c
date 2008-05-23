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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <libgen.h>
#include <unistd.h>
#include <strings.h>
#include "filebench.h"
#include "ipc.h"
#include "eventgen.h"
#include "utils.h"

/*
 * Routines to access high resolution system time, initialize and
 * shutdown filebench, log filebench run progress and errors, and
 * access system information strings.
 */


#if !defined(sun) && defined(USE_RDTSC)
/*
 * Lets us use the rdtsc instruction to get highres time.
 * Thanks to libmicro
 */
uint64_t	cpu_hz = 0;

/*
 * Uses the rdtsc instruction to get high resolution (cpu
 * clock ticks) time. Only used for non Sun compiles.
 */
__inline__ long long
rdtsc(void)
{
	unsigned long long x;
	__asm__ volatile(".byte 0x0f, 0x31" : "=A" (x));
	return (x);
}

/*
 * Get high resolution time in nanoseconds. This is the version
 * used when not compiled for Sun systems. It uses rdtsc call to
 * get clock ticks and converts to nanoseconds
 */
uint64_t
gethrtime(void)
{
	uint64_t hrt;

	/* convert to nanosecs and return */
	hrt = 1000000000UL * rdtsc() / cpu_hz;
	return (hrt);
}

/*
 * Gets CPU clock frequency in MHz from cpuinfo file.
 * Converts to cpu_hz and stores in cpu_hz global uint64_t.
 * Only used for non Sun compiles.
 */
static uint64_t
parse_cpu_hz(void)
{
	/*
	 * Parse the following from /proc/cpuinfo.
	 * cpu MHz		: 2191.563
	 */
	FILE *cpuinfo;
	double hertz = -1;
	uint64_t hz;

	if ((cpuinfo = fopen("/proc/cpuinfo", "r")) == NULL) {
		filebench_log(LOG_ERROR, "open /proc/cpuinfo failed: %s",
		    strerror(errno));
		filebench_shutdown(1);
	}
	while (!feof(cpuinfo)) {
		char buffer[80];

		fgets(buffer, 80, cpuinfo);
		if (strlen(buffer) == 0) continue;
		if (strncasecmp(buffer, "cpu MHz", 7) == 0) {
			char *token = strtok(buffer, ":");

			if (token != NULL) {
				token = strtok((char *)NULL, ":");
				hertz = strtod(token, NULL);
			}
			break;
		}
	}
	hz = hertz * 1000000;

	return (hz);
}

#elif !defined(sun)

/*
 * Get high resolution time in nanoseconds. This is the version
 * used if compiled for Sun systems. It calls gettimeofday
 * to get current time and converts it to nanoseconds.
 */
uint64_t
gethrtime(void)
{
	struct timeval tv;
	uint64_t hrt;

	gettimeofday(&tv, NULL);

	hrt = (uint64_t)tv.tv_sec * 1000000000UL +
	    (uint64_t)tv.tv_usec * 1000UL;
	return (hrt);
}
#endif

/*
 * Main filebench initialization. Opens the random number
 * "device" file or shuts down the run if one is not found.
 * Sets the cpu clock frequency variable or shuts down the
 * run if one is not found.
 */
void
filebench_init(void)
{
	fb_random_init();

#if defined(USE_RDTSC) && (LINUX_PORT)
	cpu_hz = parse_cpu_hz();
	if (cpu_hz <= 0) {
		filebench_log(LOG_ERROR, "Error getting CPU Mhz: %s",
		    strerror(errno));
		filebench_shutdown(1);
	}
#endif /* USE_RDTSC */

}

extern int lex_lineno;

/*
 * Writes a message consisting of information formated by
 * "fmt" to the log file, dump file or stdout.  The supplied
 * "level" argument determines which file to write to and
 * what other actions to take. The level LOG_LOG writes to
 * the "log" file, and will open the file on the first
 * invocation. The level LOG_DUMP writes to the "dump" file,
 * and will open it on the first invocation. Other levels
 * print to the stdout device, with the amount of information
 * dependent on the error level and the current error level
 * setting in filebench_shm->shm_debug_level.
 */
void filebench_log
__V((int level, const char *fmt, ...))
{
	va_list args;
	hrtime_t now;
	char line[131072];
	char buf[131072];

	if (level == LOG_FATAL)
		goto fatal;

	/* open logfile if not already open and writing to it */
	if ((level == LOG_LOG) &&
	    (filebench_shm->shm_log_fd < 0)) {
		char path[MAXPATHLEN];
		char *s;

		(void) strcpy(path, filebench_shm->shm_fscriptname);
		if ((s = strstr(path, ".f")))
			*s = 0;
		else
			(void) strcpy(path, "filebench");

		(void) strcat(path, ".csv");

		filebench_shm->shm_log_fd =
		    open(path, O_RDWR | O_CREAT | O_TRUNC, 0666);
	}

	/*
	 * if logfile still not open, switch to LOG_ERROR level so
	 * it gets reported to stdout
	 */
	if ((level == LOG_LOG) &&
	    (filebench_shm->shm_log_fd < 0)) {
		(void) snprintf(line, sizeof (line),  "Open logfile failed: %s",
		    strerror(errno));
		level = LOG_ERROR;
	}

	/* open dumpfile if not already open and writing to it */
	if ((level == LOG_DUMP) &&
	    (*filebench_shm->shm_dump_filename == 0))
		return;

	if ((level == LOG_DUMP) &&
	    (filebench_shm->shm_dump_fd < 0)) {

		filebench_shm->shm_dump_fd =
		    open(filebench_shm->shm_dump_filename,
		    O_RDWR | O_CREAT | O_TRUNC, 0666);
	}

	if ((level == LOG_DUMP) &&
	    (filebench_shm->shm_dump_fd < 0)) {
		(void) snprintf(line, sizeof (line), "Open logfile failed: %s",
		    strerror(errno));
		level = LOG_ERROR;
	}

	/* Quit if this is a LOG_ERROR messages and they are disabled */
	if ((filebench_shm->shm_1st_err) && (level == LOG_ERROR))
		return;

	if (level == LOG_ERROR1) {
		if (filebench_shm->shm_1st_err)
			return;

		/* A LOG_ERROR1 temporarily disables LOG_ERROR messages */
		filebench_shm->shm_1st_err = 1;
		level = LOG_ERROR;
	}

	/* Only log greater than debug setting */
	if ((level != LOG_DUMP) && (level != LOG_LOG) &&
	    (level > filebench_shm->shm_debug_level))
		return;

	now = gethrtime();

fatal:

#ifdef __STDC__
	va_start(args, fmt);
#else
	char *fmt;
	va_start(args);
	fmt = va_arg(args, char *);
#endif

	(void) vsprintf(line, fmt, args);

	va_end(args);

	if (level == LOG_FATAL) {
		(void) fprintf(stderr, "%s\n", line);
		return;
	}

	/* Serialize messages to log */
	(void) ipc_mutex_lock(&filebench_shm->shm_msg_lock);

	if (level == LOG_LOG) {
		if (filebench_shm->shm_log_fd > 0) {
			(void) snprintf(buf, sizeof (buf), "%s\n", line);
			(void) write(filebench_shm->shm_log_fd, buf,
			    strlen(buf));
			(void) fsync(filebench_shm->shm_log_fd);
			(void) ipc_mutex_unlock(&filebench_shm->shm_msg_lock);
			return;
		}

	} else if (level == LOG_DUMP) {
		if (filebench_shm->shm_dump_fd != -1) {
			(void) snprintf(buf, sizeof (buf), "%s\n", line);
			(void) write(filebench_shm->shm_dump_fd, buf,
			    strlen(buf));
			(void) fsync(filebench_shm->shm_dump_fd);
			(void) ipc_mutex_unlock(&filebench_shm->shm_msg_lock);
			return;
		}

	} else if (filebench_shm->shm_debug_level > LOG_INFO) {
		if (level < LOG_INFO)
			(void) fprintf(stderr, "%5d: ", (int)my_pid);
		else
			(void) fprintf(stdout, "%5d: ", (int)my_pid);
	}

	if (level < LOG_INFO) {
		(void) fprintf(stderr, "%4.3f: %s",
		    (now - filebench_shm->shm_epoch) / FSECS,
		    line);

		if (my_procflow == NULL)
			(void) fprintf(stderr, " on line %d", lex_lineno);

		(void) fprintf(stderr, "\n");
		(void) fflush(stderr);
	} else {
		(void) fprintf(stdout, "%4.3f: %s",
		    (now - filebench_shm->shm_epoch) / FSECS,
		    line);
		(void) fprintf(stdout, "\n");
		(void) fflush(stdout);
	}

	(void) ipc_mutex_unlock(&filebench_shm->shm_msg_lock);
}

/*
 * Stops the run and exits filebench. If filebench is
 * currently running a workload, calls procflow_shutdown()
 * to stop the run. Also closes and deletes shared memory.
 */
void
filebench_shutdown(int error) {

	if (error) {
		filebench_log(LOG_DEBUG_IMPL, "Shutdown on error");
		filebench_shm->shm_f_abort = FILEBENCH_ABORT_ERROR;
	} else {
		filebench_log(LOG_DEBUG_IMPL, "Shutdown");
	}

	procflow_shutdown();

	(void) unlink("/tmp/filebench_shm");
	ipc_ismdelete();
	exit(error);
}

/*
 * Put the hostname in ${hostname}. The system supplied
 * host name string is copied into an allocated string and
 * the pointer to the string is placed in the supplied
 * variable "var". If var->var_val.string already points to
 * a string, the string is freed. The routine always
 * returns zero (0).
 */
var_t *
host_var(var_t *var)
{
	char hoststr[128];
	char *strptr;

	(void) gethostname(hoststr, 128);
	if (VAR_HAS_STRING(var) && var->var_val.string)
		free(var->var_val.string);

	if ((strptr = fb_stralloc(hoststr)) == NULL) {
		filebench_log(LOG_ERROR,
		    "unable to allocate string for host name");
		return (NULL);
	}

	VAR_SET_STR(var, strptr);
	return (0);
}

/*
 * Put the date string in ${date}. The system supplied date is
 * copied into an allocated string and the pointer to the string
 * is placed in the supplied var_t's var_val.string. If
 * var->var_val.string already points to a string, the string
 * is freed. The routine returns a pointer to the supplied var_t,
 * unless it is unable to allocate string for the date, in which
 * case it returns NULL.
 */
var_t *
date_var(var_t *var)
{
	char datestr[128];
	char *strptr;
#ifdef HAVE_CFTIME
	time_t t = time(NULL);
#else
	struct tm t;
#endif

#ifdef HAVE_CFTIME
	cftime(datestr, "%y%m%d%H" "%M", &t);
#else
	(void) strftime(datestr, sizeof (datestr), "%y%m%d%H %M", &t);
#endif

	if (VAR_HAS_STRING(var) && var->var_val.string)
		free(var->var_val.string);

	if ((strptr = fb_stralloc(datestr)) == NULL) {
		filebench_log(LOG_ERROR,
		    "unable to allocate string for date");
		return (NULL);
	}

	VAR_SET_STR(var, strptr);

	return (var);
}

extern char *fscriptname;

/*
 * Put the script name in ${script}. The path name of the script
 * used with this filebench run trimmed of the trailing ".f" and
 * all leading subdirectories. The remaining script name is
 * copied into the var_val.string field of the supplied variable
 * "var". The routine returns a pointer to the supplied var_t,
 * unless it is unable to allocate string space, in which case it
 * returns NULL.
 */
var_t *
script_var(var_t *var)
{
	char *scriptstr;
	char *f = fb_stralloc(fscriptname);
	char *strptr;

	/* Trim the .f suffix */
	for (scriptstr = f + strlen(f) - 1; scriptstr != f; scriptstr--) {
		if (*scriptstr == '.') {
			*scriptstr = 0;
			break;
		}
	}

	if ((strptr = fb_stralloc(basename(f))) == NULL) {
		filebench_log(LOG_ERROR,
		    "unable to allocate string for script name");
		free(f);
		return (NULL);
	}

	VAR_SET_STR(var, strptr);
	free(f);

	return (var);
}
