/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * lib/kadm/logger.c
 *
 * Copyright 1995 by the Massachusetts Institute of Technology.
 * All Rights Reserved.
 *
 * Export of this software from the United States of America may
 *   require a specific license from the United States Government.
 *   It is the responsibility of any person or organization contemplating
 *   export to obtain such a license before exporting.
 *
 * WITHIN THAT CONSTRAINT, permission to use, copy, modify, and
 * distribute this software and its documentation for any purpose and
 * without fee is hereby granted, provided that the above copyright
 * notice appear in all copies and that both that copyright notice and
 * this permission notice appear in supporting documentation, and that
 * the name of M.I.T. not be used in advertising or publicity pertaining
 * to distribution of the software without specific, written prior
 * permission.  Furthermore if you modify this software you must label
 * your software as modified software and not distribute it in such a
 * fashion that it might be confused with the original M.I.T. software.
 * M.I.T. makes no representations about the suitability of
 * this software for any purpose.  It is provided "as is" without express
 * or implied warranty.
 *
 */

/* KADM5 wants non-syslog log files to contain syslog-like entries */
#define VERBOSE_LOGS

/*
 * logger.c	- Handle logging functions for those who want it.
 */
#include "k5-int.h"
#include "adm_proto.h"
#include "com_err.h"
#include <stdio.h>
#include <ctype.h>
#include <ctype.h>
#ifdef	HAVE_SYSLOG_H
#include <syslog.h>
#endif	/* HAVE_SYSLOG_H */
#ifdef	HAVE_STDARG_H
#include <stdarg.h>
#else	/* HAVE_STDARG_H */
#include <varargs.h>
#endif	/* HAVE_STDARG_H */
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>

#define	KRB5_KLOG_MAX_ERRMSG_SIZE	2048
#ifndef	MAXHOSTNAMELEN
#define	MAXHOSTNAMELEN	256
#endif	/* MAXHOSTNAMELEN */

#define LSPEC_PARSE_ERR_1 	1
#define LSPEC_PARSE_ERR_2	2
#define LOG_FILE_ERR		3
#define LOG_DEVICE_ERR		4
#define LOG_UFO_STRING		5
#define LOG_EMERG_STRING	6
#define LOG_ALERT_STRING	7
#define LOG_CRIT_STRING		8
#define LOG_ERR_STRING		9
#define LOG_WARNING_STRING	10
#define LOG_NOTICE_STRING	11
#define LOG_INFO_STRING	12
#define LOG_DEBUG_STRING	13
/* This is to assure that we have at least one match in the syslog stuff */
/*
static const char LSPEC_PARSE_ERR_1[] =	"%s: cannot parse <%s>\n";
static const char LSPEC_PARSE_ERR_2[] =	"%s: warning - logging entry syntax error\n";
static const char LOG_FILE_ERR[] =	"%s: error writing to %s\n";
static const char LOG_DEVICE_ERR[] =	"%s: error writing to %s device\n";
static const char LOG_UFO_STRING[] =	"???";
static const char LOG_EMERG_STRING[] =	"EMERGENCY";
static const char LOG_ALERT_STRING[] =	"ALERT";
static const char LOG_CRIT_STRING[] =	"CRITICAL";
static const char LOG_ERR_STRING[] =	"Error";
static const char LOG_WARNING_STRING[] =	"Warning";
static const char LOG_NOTICE_STRING[] =	"Notice";
static const char LOG_INFO_STRING[] =	"info";
static const char LOG_DEBUG_STRING[] =	"debug";
*/


const char *
krb5_log_error_table(long errorno) {
switch (errorno) {
	case LSPEC_PARSE_ERR_1:
		return(gettext("%s: cannot parse <%s>\n"));
	case LSPEC_PARSE_ERR_2:
		return(gettext("%s: warning - logging entry syntax error\n"));
	case LOG_FILE_ERR:
		return(gettext("%s: error writing to %s\n"));
	case LOG_DEVICE_ERR:
		return(gettext("%s: error writing to %s device\n"));
	case LOG_UFO_STRING:
        default:
		return(gettext("???"));
	case LOG_EMERG_STRING:
		return(gettext("EMERGENCY"));
	case LOG_ALERT_STRING:
		return(gettext("ALERT"));
	case LOG_CRIT_STRING:
		return(gettext("CRITICAL"));
	case LOG_ERR_STRING:
		return(gettext("Error"));
	case LOG_WARNING_STRING:
		return(gettext("Warning"));
	case LOG_NOTICE_STRING:
		return(gettext("Notice"));
	case LOG_INFO_STRING:
		return(gettext("info"));
	case LOG_DEBUG_STRING:
		return(gettext("info"));
	}
}

/*
 * Output logging.
 *
 * Output logging is now controlled by the configuration file.  We can specify
 * the following syntaxes under the [logging]->entity specification.
 *	FILE<opentype><pathname>
 *	SYSLOG[=<severity>[:<facility>]]
 *	STDERR
 *	CONSOLE
 *	DEVICE=<device-spec>
 *
 * Where:
 *	<opentype> is ":" for open/append, "=" for open/create.
 *	<pathname> is a valid path name.
 *	<severity> is one of: (default = ERR)
 *		EMERG
 *		ALERT
 *		CRIT
 *		ERR
 *		WARNING
 *		NOTICE
 *		INFO
 *		DEBUG
 *	<facility> is one of: (default = AUTH)
 *		KERN
 *		USER
 *		MAIL
 *		DAEMON
 *		AUTH
 *		LPR
 *		NEWS
 *		UUCP
 *		CRON
 *		LOCAL0..LOCAL7
 *	<device-spec> is a valid device specification.
 */
struct log_entry {
    enum log_type { K_LOG_FILE,
			K_LOG_SYSLOG,
			K_LOG_STDERR,
			K_LOG_CONSOLE,
			K_LOG_DEVICE,
			K_LOG_NONE } log_type;
    krb5_pointer log_2free;
    union log_union {
	struct log_file {
	    FILE	*lf_filep;
	    char	*lf_fname;
	    char	*lf_fopen_mode; /* "a+" or "w" */
#define	K_LOG_DEF_FILE_ROTATE_PERIOD	-1	/* never */
#define	K_LOG_DEF_FILE_ROTATE_VERSIONS	0	/* no versions */
	    time_t	lf_rotate_period;
	    time_t	lf_last_rotated;
	    int		lf_rotate_versions;
	} log_file;
	struct log_syslog {
	    int		ls_facility;
	    int		ls_severity;
	} log_syslog;
	struct log_device {
	    FILE	*ld_filep;
	    char	*ld_devname;
	} log_device;
    } log_union;
};
#define	lfu_filep	log_union.log_file.lf_filep
#define	lfu_fname	log_union.log_file.lf_fname
#define	lfu_fopen_mode	log_union.log_file.lf_fopen_mode
#define	lfu_rotate_period	log_union.log_file.lf_rotate_period
#define	lfu_last_rotated	log_union.log_file.lf_last_rotated
#define	lfu_rotate_versions	log_union.log_file.lf_rotate_versions
#define	lsu_facility	log_union.log_syslog.ls_facility
#define	lsu_severity	log_union.log_syslog.ls_severity
#define	ldu_filep	log_union.log_device.ld_filep
#define	ldu_devname	log_union.log_device.ld_devname

struct log_control {
    struct log_entry	*log_entries;
    int			log_nentries;
    char		*log_whoami;
    char		*log_hostname;
    krb5_boolean	log_opened;
};

static struct log_control log_control = {
    (struct log_entry *) NULL,
    0,
    (char *) NULL,
    (char *) NULL,
    0
};
static struct log_entry	def_log_entry;

/*
 * These macros define any special processing that needs to happen for
 * devices.  For unix, of course, this is hardly anything.
 */
#define	DEVICE_OPEN(d, m)	fopen(d, m)
#define	CONSOLE_OPEN(m)		fopen("/dev/console", m)
#define	DEVICE_PRINT(f, m)	((fprintf(f, "%s\r\n", m) >= 0) ? 	\
				 (fflush(f), 0) :			\
				 -1)
#define	DEVICE_CLOSE(d)		fclose(d)


/*
 * klog_rotate() - roate a log file if we have specified rotation
 * parameters in krb5.conf.
 */
static void
klog_rotate(struct log_entry *le)
{
	time_t t;
	int i;
	char *name_buf1;
	char *name_buf2;
	char *old_name;
	char *new_name;
	char *tmp;
	FILE *fp;
	int num_vers;
	mode_t old_umask;


	/*
	 * By default we don't rotate.
	 */
	if (le->lfu_rotate_period == K_LOG_DEF_FILE_ROTATE_PERIOD)
		return;

	t = time(0);

	if (t >= le->lfu_last_rotated + le->lfu_rotate_period) {
		/*
		 * The N log file versions will be renamed X.N-1 X.N-2, ... X.0.
		 * So the allocate file name buffers that can the version
		 * number extensions.
		 * 32 extra bytes is plenty.
		 */
		name_buf1 = malloc(strlen(le->lfu_fname) + 32);

		if (name_buf1 == NULL)
			return;

		name_buf2 = malloc(strlen(le->lfu_fname) + 32);

		if (name_buf2 == NULL) {
			free(name_buf1);
			return;
		}

		old_name = name_buf1;
		new_name = name_buf2;

		/*
		 * If there N versions, then the first one has file extension
		 * of N-1.
		 */
		(void) sprintf(new_name, "%s.%d", le->lfu_fname,
			le->lfu_rotate_versions - 1);

		/*
		 * Rename file.N-2 to file.N-1, file.N-3 to file.N-2, ...
		 * file.0 to file.1
		 */
		for (i = le->lfu_rotate_versions - 1; i > 0; i--) {
			(void) sprintf(old_name, "%s.%d", le->lfu_fname, i - 1);
			(void) rename(old_name, new_name);

			/*
			 * swap old name and new name. This way,
			 * on the next iteration, new_name.X
			 * becomes new_name.X-1.
			 */
			tmp = old_name;
			old_name = new_name;
			new_name = tmp;
		}
		old_name = le->lfu_fname;

		(void) rename(old_name, new_name);

		/*
		 * Even though we don't know yet if the fopen()
		 * of the log file will succeed, we mark the log
		 * as rotated. This is so we don't repeatably
		 * rotate file.N-2 to file.N-1 ... etc without
		 * waiting for the rotate period to elapse.
		 */
		le->lfu_last_rotated = t;

		/*
		 * Default log file creation mode should be read-only
		 * by owner(root), but the admin can override with
		 * chmod(1) if desired.
		 */

		old_umask = umask(077);
		fp = fopen(old_name, le->lfu_fopen_mode);

		umask(old_umask);

		if (fp != NULL) {

			(void) fclose(le->lfu_filep);
			le->lfu_filep = fp;

			/*
			 * If the version parameter in krb5.conf was
			 * 0, then we take this to mean that rotating the
			 * log file will cause us to dispose of the
			 * old one, and created a new one. We have just
			 * renamed the old one to file.-1, so remove it.
			 */
			if (le->lfu_rotate_versions <= 0)
				(void) unlink(new_name);

		} else {
			fprintf(stderr,
		gettext("During rotate, couldn't open log file %s: %s\n"),
				old_name, error_message(errno));
			/*
			 * Put it back.
			 */
			(void) rename(new_name, old_name);
		}
		free(name_buf1);
		free(name_buf2);
	}
}

/*
 * klog_com_err_proc()	- Handle com_err(3) messages as specified by the
 *			  profile.
 */
static krb5_context err_context;
static void
klog_com_err_proc(const char *whoami, long code, const char *format, va_list ap)
{
    char	outbuf[KRB5_KLOG_MAX_ERRMSG_SIZE];
    int		lindex;
    const char	*actual_format;
#ifdef	HAVE_SYSLOG
    int		log_pri = -1;
#endif	/* HAVE_SYSLOG */
    char	*cp;
    char	*syslogp;

    /* Make the header */
    sprintf(outbuf, "%s: ", whoami);
    /*
     * Squirrel away address after header for syslog since syslog makes
     * a header
     */
    syslogp = &outbuf[strlen(outbuf)];

    /* If reporting an error message, separate it. */
    if (code) {
	/* Solaris Kerberos */
        const char *emsg;
        outbuf[sizeof(outbuf) - 1] = '\0';

	emsg = krb5_get_error_message (err_context, code);
	strncat(outbuf, emsg, sizeof(outbuf) - 1 - strlen(outbuf));
	strncat(outbuf, " - ", sizeof(outbuf) - 1 - strlen(outbuf));
	krb5_free_error_message(err_context, emsg);
    }
    cp = &outbuf[strlen(outbuf)];

    actual_format = format;
#ifdef	HAVE_SYSLOG
    /*
     * This is an unpleasant hack.  If the first character is less than
     * 8, then we assume that it is a priority.
     *
     * Since it is not guaranteed that there is a direct mapping between
     * syslog priorities (e.g. Ultrix and old BSD), we resort to this
     * intermediate representation.
     */
    if ((((unsigned char) *format) > 0) && (((unsigned char) *format) <= 8)) {
	actual_format = (format + 1);
	switch ((unsigned char) *format) {
#ifdef	LOG_EMERG
	case 1:
	    log_pri = LOG_EMERG;
	    break;
#endif /* LOG_EMERG */
#ifdef	LOG_ALERT
	case 2:
	    log_pri = LOG_ALERT;
	    break;
#endif /* LOG_ALERT */
#ifdef	LOG_CRIT
	case 3:
	    log_pri = LOG_CRIT;
	    break;
#endif /* LOG_CRIT */
	default:
	case 4:
	    log_pri = LOG_ERR;
	    break;
#ifdef	LOG_WARNING
	case 5:
	    log_pri = LOG_WARNING;
	    break;
#endif /* LOG_WARNING */
#ifdef	LOG_NOTICE
	case 6:
	    log_pri = LOG_NOTICE;
	    break;
#endif /* LOG_NOTICE */
#ifdef	LOG_INFO
	case 7:
	    log_pri = LOG_INFO;
	    break;
#endif /* LOG_INFO */
#ifdef	LOG_DEBUG
	case 8:
	    log_pri = LOG_DEBUG;
	    break;
#endif /* LOG_DEBUG */
	}
    }
#endif	/* HAVE_SYSLOG */

    /* Now format the actual message */
#if	HAVE_VSNPRINTF
    vsnprintf(cp, sizeof(outbuf) - (cp - outbuf), actual_format, ap);
#elif	HAVE_VSPRINTF
    vsprintf(cp, actual_format, ap);
#else	/* HAVE_VSPRINTF */
    sprintf(cp, actual_format, ((int *) ap)[0], ((int *) ap)[1],
	    ((int *) ap)[2], ((int *) ap)[3],
	    ((int *) ap)[4], ((int *) ap)[5]);
#endif	/* HAVE_VSPRINTF */

    /*
     * Now that we have the message formatted, perform the output to each
     * logging specification.
     */
    for (lindex = 0; lindex < log_control.log_nentries; lindex++) {
	switch (log_control.log_entries[lindex].log_type) {
	case K_LOG_FILE:

	    klog_rotate(&log_control.log_entries[lindex]);
	    /*FALLTHRU*/
	case K_LOG_STDERR:
	    /*
	     * Files/standard error.
	     */
	    if (fprintf(log_control.log_entries[lindex].lfu_filep, "%s\n",
			outbuf) < 0) {
		/* Attempt to report error */
		fprintf(stderr, krb5_log_error_table(LOG_FILE_ERR), whoami,
			log_control.log_entries[lindex].lfu_fname);
	    }
	    else {
		fflush(log_control.log_entries[lindex].lfu_filep);
	    }
	    break;
	case K_LOG_CONSOLE:
	case K_LOG_DEVICE:
	    /*
	     * Devices (may need special handling)
	     */
	    if (DEVICE_PRINT(log_control.log_entries[lindex].ldu_filep,
			     outbuf) < 0) {
		/* Attempt to report error */
		fprintf(stderr, krb5_log_error_table(LOG_DEVICE_ERR), whoami,
			log_control.log_entries[lindex].ldu_devname);
	    }
	    break;
#ifdef	HAVE_SYSLOG
	case K_LOG_SYSLOG:
	    /*
	     * System log.
	     */
	    /*
	     * If we have specified a priority through our hackery, then
	     * use it, otherwise use the default.
	     */
	    if (log_pri >= 0)
		log_pri |= log_control.log_entries[lindex].lsu_facility;
	    else
		log_pri = log_control.log_entries[lindex].lsu_facility |
		    log_control.log_entries[lindex].lsu_severity;

	    /* Log the message with our header trimmed off */
	    syslog(log_pri, "%s", syslogp);
	    break;
#endif /* HAVE_SYSLOG */
	default:
	    break;
	}
    }
}

/*
 * krb5_klog_init()	- Initialize logging.
 *
 * This routine parses the syntax described above to specify destinations for
 * com_err(3) or krb5_klog_syslog() messages generated by the caller.
 *
 * Parameters:
 *	kcontext	- Kerberos context.
 *	ename		- Entity name as it is to appear in the profile.
 *	whoami		- Entity name as it is to appear in error output.
 *	do_com_err	- Take over com_err(3) processing.
 *
 * Implicit inputs:
 *	stderr		- This is where STDERR output goes.
 *
 * Implicit outputs:
 *	log_nentries	- Number of log entries, both valid and invalid.
 *	log_control	- List of entries (log_nentries long) which contains
 *			  data for klog_com_err_proc() to use to determine
 *			  where/how to send output.
 */
krb5_error_code
krb5_klog_init(krb5_context kcontext, char *ename, char *whoami, krb5_boolean do_com_err)
{
    const char	*logging_profent[3];
    const char	*logging_defent[3];
    char	**logging_specs;
    int		i, ngood;
    char	*cp, *cp2;
    char	savec = '\0';
    int		error;
    int		do_openlog, log_facility;
    FILE	*f;
    mode_t      old_umask;

    /* Initialize */
    do_openlog = 0;
    log_facility = 0;

    err_context = kcontext;

    /*
     * Look up [logging]-><ename> in the profile.  If that doesn't
     * succeed, then look for [logging]->default.
     */
    logging_profent[0] = "logging";
    logging_profent[1] = ename;
    logging_profent[2] = (char *) NULL;
    logging_defent[0] = "logging";
    logging_defent[1] = "default";
    logging_defent[2] = (char *) NULL;
    logging_specs = (char **) NULL;
    ngood = 0;
    log_control.log_nentries = 0;
    if (!profile_get_values(kcontext->profile,
			    logging_profent,
			    &logging_specs) ||
	!profile_get_values(kcontext->profile,
			    logging_defent,
			    &logging_specs)) {
	/*
	 * We have a match, so we first count the number of elements
	 */
	for (log_control.log_nentries = 0;
	     logging_specs[log_control.log_nentries];
	     log_control.log_nentries++);

	/*
	 * Now allocate our structure.
	 */
	log_control.log_entries = (struct log_entry *)
	    malloc(log_control.log_nentries * sizeof(struct log_entry));
	if (log_control.log_entries) {
	    /*
	     * Scan through the list.
	     */
	    for (i=0; i<log_control.log_nentries; i++) {
		log_control.log_entries[i].log_type = K_LOG_NONE;
		log_control.log_entries[i].log_2free = logging_specs[i];
		/*
		 * The format is:
		 *	<whitespace><data><whitespace>
		 * so, trim off the leading and trailing whitespace here.
		 */
		for (cp = logging_specs[i]; isspace((int) *cp); cp++);
		for (cp2 = &logging_specs[i][strlen(logging_specs[i])-1];
		     isspace((int) *cp2); cp2--);
		cp2++;
		*cp2 = '\0';
		/*
		 * Is this a file?
		 */
		if (!strncasecmp(cp, "FILE", 4)) {
		    /*
		     * Check for append/overwrite, then open the file.
		     */
		    if (cp[4] == ':' || cp[4] == '=') {
			log_control.log_entries[i].lfu_fopen_mode =
				(cp[4] == ':') ? "a+F" : "wF";
			old_umask = umask(077);
			f = fopen(&cp[5],
				log_control.log_entries[i].lfu_fopen_mode);
			umask(old_umask);
			if (f) {
                            char rotate_kw[128];

			    log_control.log_entries[i].lfu_filep = f;
			    log_control.log_entries[i].log_type = K_LOG_FILE;
			    log_control.log_entries[i].lfu_fname = &cp[5];
			    log_control.log_entries[i].lfu_rotate_period =
				K_LOG_DEF_FILE_ROTATE_PERIOD;
			    log_control.log_entries[i].lfu_rotate_versions =
				K_LOG_DEF_FILE_ROTATE_VERSIONS;
			    log_control.log_entries[i].lfu_last_rotated =
				time(0);

			/*
			 * Now parse for ename_"rotate" = {
			 *	period = XXX
			 * 	versions = 10
			 * }
			 */
			    if (strlen(ename) + strlen("_rotate") <
				sizeof (rotate_kw)) {

				    char *time;
				    krb5_deltat	dt;
				    int vers;

				    strcpy(rotate_kw, ename);
				    strcat(rotate_kw, "_rotate");

				    if (!profile_get_string(kcontext->profile,
				        "logging", rotate_kw, "period",
					NULL, &time)) {

					if (time != NULL) {
					    if (!krb5_string_to_deltat(time,
						&dt)) {
			log_control.log_entries[i].lfu_rotate_period =
							(time_t) dt;
					    }
					    free(time);
					}
				    }

				    if (!profile_get_integer(
					kcontext->profile, "logging",
					rotate_kw, "versions",
					K_LOG_DEF_FILE_ROTATE_VERSIONS,
					&vers)) {
			log_control.log_entries[i].lfu_rotate_versions = vers;
				    }

			   }
			} else {
			    fprintf(stderr, gettext("Couldn't open log file %s: %s\n"),
				    &cp[5], error_message(errno));
			    continue;
			}
		    }
		}
#ifdef	HAVE_SYSLOG
		/*
		 * Is this a syslog?
		 */
		else if (!strncasecmp(cp, "SYSLOG", 6)) {
		    error = 0;
		    log_control.log_entries[i].lsu_facility = LOG_AUTH;
		    log_control.log_entries[i].lsu_severity = LOG_ERR;
		    /*
		     * Is there a severify specified?
		     */
		    if (cp[6] == ':') {
			/*
			 * Find the end of the severity.
			 */
			cp2 = strchr(&cp[7], ':');
			if (cp2) {
			    savec = *cp2;
			    *cp2 = '\0';
			    cp2++;
			}

			/*
			 * Match a severity.
			 */
			if (!strcasecmp(&cp[7], "ERR")) {
			    log_control.log_entries[i].lsu_severity = LOG_ERR;
			}
#ifdef	LOG_EMERG
			else if (!strcasecmp(&cp[7], "EMERG")) {
			    log_control.log_entries[i].lsu_severity =
				LOG_EMERG;
			}
#endif	/* LOG_EMERG */
#ifdef	LOG_ALERT
			else if (!strcasecmp(&cp[7], "ALERT")) {
			    log_control.log_entries[i].lsu_severity =
				LOG_ALERT;
			}
#endif	/* LOG_ALERT */
#ifdef	LOG_CRIT
			else if (!strcasecmp(&cp[7], "CRIT")) {
			    log_control.log_entries[i].lsu_severity = LOG_CRIT;
			}
#endif	/* LOG_CRIT */
#ifdef	LOG_WARNING
			else if (!strcasecmp(&cp[7], "WARNING")) {
			    log_control.log_entries[i].lsu_severity =
				LOG_WARNING;
			}
#endif	/* LOG_WARNING */
#ifdef	LOG_NOTICE
			else if (!strcasecmp(&cp[7], "NOTICE")) {
			    log_control.log_entries[i].lsu_severity =
				LOG_NOTICE;
			}
#endif	/* LOG_NOTICE */
#ifdef	LOG_INFO
			else if (!strcasecmp(&cp[7], "INFO")) {
			    log_control.log_entries[i].lsu_severity = LOG_INFO;
			}
#endif	/* LOG_INFO */
#ifdef	LOG_DEBUG
			else if (!strcasecmp(&cp[7], "DEBUG")) {
			    log_control.log_entries[i].lsu_severity =
				LOG_DEBUG;
			}
#endif	/* LOG_DEBUG */
			else
			    error = 1;

			/*
			 * If there is a facility present, then parse that.
			 */
			if (cp2) {
			    if (!strcasecmp(cp2, "AUTH")) {
				log_control.log_entries[i].lsu_facility = LOG_AUTH;
			    }
			    else if (!strcasecmp(cp2, "KERN")) {
				log_control.log_entries[i].lsu_facility = LOG_KERN;
			    }
			    else if (!strcasecmp(cp2, "USER")) {
				log_control.log_entries[i].lsu_facility = LOG_USER;
			    }
			    else if (!strcasecmp(cp2, "MAIL")) {
				log_control.log_entries[i].lsu_facility = LOG_MAIL;
			    }
			    else if (!strcasecmp(cp2, "DAEMON")) {
				log_control.log_entries[i].lsu_facility = LOG_DAEMON;
			    }
			    else if (!strcasecmp(cp2, "LPR")) {
				log_control.log_entries[i].lsu_facility = LOG_LPR;
			    }
			    else if (!strcasecmp(cp2, "NEWS")) {
				log_control.log_entries[i].lsu_facility = LOG_NEWS;
			    }
			    else if (!strcasecmp(cp2, "UUCP")) {
				log_control.log_entries[i].lsu_facility = LOG_UUCP;
			    }
			    else if (!strcasecmp(cp2, "CRON")) {
				log_control.log_entries[i].lsu_facility = LOG_CRON;
			    }
			    else if (!strcasecmp(cp2, "LOCAL0")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL0;
			    }
			    else if (!strcasecmp(cp2, "LOCAL1")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL1;
			    }
			    else if (!strcasecmp(cp2, "LOCAL2")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL2;
			    }
			    else if (!strcasecmp(cp2, "LOCAL3")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL3;
			    }
			    else if (!strcasecmp(cp2, "LOCAL4")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL4;
			    }
			    else if (!strcasecmp(cp2, "LOCAL5")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL5;
			    }
			    else if (!strcasecmp(cp2, "LOCAL6")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL6;
			    }
			    else if (!strcasecmp(cp2, "LOCAL7")) {
				log_control.log_entries[i].lsu_facility = LOG_LOCAL7;
			    }
			    cp2--;
			    *cp2 = savec;
			}
		    }
		    if (!error) {
			log_control.log_entries[i].log_type = K_LOG_SYSLOG;
			do_openlog = 1;
			log_facility = log_control.log_entries[i].lsu_facility;
		    }
		}
#endif	/* HAVE_SYSLOG */
		/*
		 * Is this a standard error specification?
		 */
		else if (!strcasecmp(cp, "STDERR")) {
		    log_control.log_entries[i].lfu_filep =
			fdopen(fileno(stderr), "a+F");
		    if (log_control.log_entries[i].lfu_filep) {
			log_control.log_entries[i].log_type = K_LOG_STDERR;
			log_control.log_entries[i].lfu_fname =
			    "standard error";
		    }
		}
		/*
		 * Is this a specification of the console?
		 */
		else if (!strcasecmp(cp, "CONSOLE")) {
		    log_control.log_entries[i].ldu_filep =
			CONSOLE_OPEN("a+F");
		    if (log_control.log_entries[i].ldu_filep) {
			log_control.log_entries[i].log_type = K_LOG_CONSOLE;
			log_control.log_entries[i].ldu_devname = "console";
		    }
		}
		/*
		 * Is this a specification of a device?
		 */
		else if (!strncasecmp(cp, "DEVICE", 6)) {
		    /*
		     * We handle devices very similarly to files.
		     */
		    if (cp[6] == '=') {
			log_control.log_entries[i].ldu_filep =
			    DEVICE_OPEN(&cp[7], "wF");
			if (log_control.log_entries[i].ldu_filep) {
			    log_control.log_entries[i].log_type = K_LOG_DEVICE;
			    log_control.log_entries[i].ldu_devname = &cp[7];
			}
		    }
		}
		/*
		 * See if we successfully parsed this specification.
		 */
		if (log_control.log_entries[i].log_type == K_LOG_NONE) {
		    fprintf(stderr, krb5_log_error_table(LSPEC_PARSE_ERR_1), whoami, cp);
		    fprintf(stderr, krb5_log_error_table(LSPEC_PARSE_ERR_2), whoami);
		}
		else
		    ngood++;
	    }
	}
	/*
	 * If we didn't find anything, then free our lists.
	 */
	if (ngood == 0) {
	    for (i=0; i<log_control.log_nentries; i++)
		free(logging_specs[i]);
	}
	free(logging_specs);
    }
    /*
     * If we didn't find anything, go for the default which is to log to
     * the system log.
     */
    if (ngood == 0) {
	if (log_control.log_entries)
	    free(log_control.log_entries);
	log_control.log_entries = &def_log_entry;
	log_control.log_entries->log_type = K_LOG_SYSLOG;
	log_control.log_entries->log_2free = (krb5_pointer) NULL;
	log_facility = log_control.log_entries->lsu_facility = LOG_AUTH;
	log_control.log_entries->lsu_severity = LOG_ERR;
	do_openlog = 1;
	log_control.log_nentries = 1;
    }
    if (log_control.log_nentries) {
	log_control.log_whoami = (char *) malloc(strlen(whoami)+1);
	if (log_control.log_whoami)
	    strcpy(log_control.log_whoami, whoami);

	log_control.log_hostname = (char *) malloc(MAXHOSTNAMELEN + 1);
	if (log_control.log_hostname) {
	    gethostname(log_control.log_hostname, MAXHOSTNAMELEN);
	    log_control.log_hostname[MAXHOSTNAMELEN] = '\0';
	}
#ifdef	HAVE_OPENLOG
	if (do_openlog) {
	    openlog(whoami, LOG_NDELAY|LOG_PID, log_facility);
	    log_control.log_opened = 1;
	}
#endif /* HAVE_OPENLOG */
	if (do_com_err)
	    (void) set_com_err_hook(klog_com_err_proc);
    }
    return((log_control.log_nentries) ? 0 : ENOENT);
}

/*
 * krb5_klog_close()	- Close the logging context and free all data.
 */
void
krb5_klog_close(krb5_context kcontext)
{
    int lindex;
    (void) reset_com_err_hook();
    for (lindex = 0; lindex < log_control.log_nentries; lindex++) {
	switch (log_control.log_entries[lindex].log_type) {
	case K_LOG_FILE:
	case K_LOG_STDERR:
	    /*
	     * Files/standard error.
	     */
	    fclose(log_control.log_entries[lindex].lfu_filep);
	    break;
	case K_LOG_CONSOLE:
	case K_LOG_DEVICE:
	    /*
	     * Devices (may need special handling)
	     */
	    DEVICE_CLOSE(log_control.log_entries[lindex].ldu_filep);
	    break;
#ifdef	HAVE_SYSLOG
	case K_LOG_SYSLOG:
	    /*
	     * System log.
	     */
	    break;
#endif	/* HAVE_SYSLOG */
	default:
	    break;
	}
	if (log_control.log_entries[lindex].log_2free)
	    free(log_control.log_entries[lindex].log_2free);
    }
    if (log_control.log_entries != &def_log_entry)
	free(log_control.log_entries);
    log_control.log_entries = (struct log_entry *) NULL;
    log_control.log_nentries = 0;
    if (log_control.log_whoami)
	free(log_control.log_whoami);
    log_control.log_whoami = (char *) NULL;
    if (log_control.log_hostname)
	free(log_control.log_hostname);
    log_control.log_hostname = (char *) NULL;
#ifdef	HAVE_CLOSELOG
    if (log_control.log_opened)
	closelog();
#endif	/* HAVE_CLOSELOG */
}

/*
 * severity2string()	- Convert a severity to a string.
 */
static const char *
severity2string(int severity)
{
    int s;
    const char *ss;

    s = severity & LOG_PRIMASK;
    ss = krb5_log_error_table(LOG_UFO_STRING);
    switch (s) {
#ifdef	LOG_EMERG
    case LOG_EMERG:
	ss = krb5_log_error_table(LOG_EMERG_STRING);
	break;
#endif	/* LOG_EMERG */
#ifdef	LOG_ALERT
    case LOG_ALERT:
	ss = krb5_log_error_table(LOG_ALERT_STRING);
	break;
#endif	/* LOG_ALERT */
#ifdef	LOG_CRIT
    case LOG_CRIT:
	ss = krb5_log_error_table(LOG_CRIT_STRING);
	break;
#endif	/* LOG_CRIT */
    case LOG_ERR:
	ss = krb5_log_error_table(LOG_ERR_STRING);
	break;
#ifdef	LOG_WARNING
    case LOG_WARNING:
	ss = krb5_log_error_table(LOG_WARNING_STRING);
	break;
#endif	/* LOG_WARNING */
#ifdef	LOG_NOTICE
    case LOG_NOTICE:
	ss = krb5_log_error_table(LOG_NOTICE_STRING);
	break;
#endif	/* LOG_NOTICE */
#ifdef	LOG_INFO
    case LOG_INFO:
	ss = krb5_log_error_table(LOG_INFO_STRING);
	break;
#endif	/* LOG_INFO */
#ifdef	LOG_DEBUG
    case LOG_DEBUG:
	ss = krb5_log_error_table(LOG_DEBUG_STRING);
	break;
#endif	/* LOG_DEBUG */
    }
    return((char *) ss);
}

/*
 * krb5_klog_syslog()	- Simulate the calling sequence of syslog(3), while
 *			  also performing the logging redirection as specified
 *			  by krb5_klog_init().
 */
static int
klog_vsyslog(int priority, const char *format, va_list arglist)
{
    char	outbuf[KRB5_KLOG_MAX_ERRMSG_SIZE];
    int		lindex;
    char	*syslogp;
    char	*cp;
    time_t	now;
#ifdef	HAVE_STRFTIME
    size_t	soff;
#endif	/* HAVE_STRFTIME */

    /*
     * Format a syslog-esque message of the format:
     *
     * (verbose form)
     * 		<date> <hostname> <id>[<pid>](<priority>): <message>
     *
     * (short form)
     *		<date> <message>
     */
    cp = outbuf;
    (void) time(&now);
#ifdef	HAVE_STRFTIME
    /*
     * Format the date: mon dd hh:mm:ss
     */
    soff = strftime(outbuf, sizeof(outbuf), "%b %d %H:%M:%S", localtime(&now));
    if (soff > 0)
	cp += soff;
    else
	return(-1);
#else	/* HAVE_STRFTIME */
    /*
     * Format the date:
     * We ASSUME here that the output of ctime is of the format:
     *	dow mon dd hh:mm:ss tzs yyyy\n
     *  012345678901234567890123456789
     */
    strncpy(outbuf, ctime(&now) + 4, 15);
    cp += 15;
#endif	/* HAVE_STRFTIME */
#ifdef VERBOSE_LOGS
    sprintf(cp, " %s %s[%ld](%s): ",
	    log_control.log_hostname, log_control.log_whoami, (long) getpid(),
	    severity2string(priority));
#else
    sprintf(cp, " ");
#endif
    syslogp = &outbuf[strlen(outbuf)];

    /* Now format the actual message */
#ifdef	HAVE_VSNPRINTF
    vsnprintf(syslogp, sizeof(outbuf) - (syslogp - outbuf), format, arglist);
#elif	HAVE_VSPRINTF
    vsprintf(syslogp, format, arglist);
#else	/* HAVE_VSPRINTF */
    sprintf(syslogp, format, ((int *) arglist)[0], ((int *) arglist)[1],
	    ((int *) arglist)[2], ((int *) arglist)[3],
	    ((int *) arglist)[4], ((int *) arglist)[5]);
#endif	/* HAVE_VSPRINTF */

    /*
     * If the user did not use krb5_klog_init() instead of dropping
     * the request on the floor, syslog it - if it exists
     */
#ifdef HAVE_SYSLOG
    if (log_control.log_nentries == 0) {
	/* Log the message with our header trimmed off */
	syslog(priority, "%s", syslogp);
    }
#endif

    /*
     * Now that we have the message formatted, perform the output to each
     * logging specification.
     */
    for (lindex = 0; lindex < log_control.log_nentries; lindex++) {
	switch (log_control.log_entries[lindex].log_type) {
	case K_LOG_FILE:

	    klog_rotate(&log_control.log_entries[lindex]);
	    /*FALLTHRU*/
	case K_LOG_STDERR:
	    /*
	     * Files/standard error.
	     */
	    if (fprintf(log_control.log_entries[lindex].lfu_filep, "%s\n",
			outbuf) < 0) {
		/* Attempt to report error */
		fprintf(stderr, krb5_log_error_table(LOG_FILE_ERR),
			log_control.log_whoami,
			log_control.log_entries[lindex].lfu_fname);
	    }
	    else {
		fflush(log_control.log_entries[lindex].lfu_filep);
	    }
	    break;
	case K_LOG_CONSOLE:
	case K_LOG_DEVICE:
	    /*
	     * Devices (may need special handling)
	     */
	    if (DEVICE_PRINT(log_control.log_entries[lindex].ldu_filep,
			     outbuf) < 0) {
		/* Attempt to report error */
		fprintf(stderr, krb5_log_error_table(LOG_DEVICE_ERR),
			log_control.log_whoami,
			log_control.log_entries[lindex].ldu_devname);
	    }
	    break;
#ifdef	HAVE_SYSLOG
	case K_LOG_SYSLOG:
	    /*
	     * System log.
	     */

	    /* Log the message with our header trimmed off */
	    syslog(priority, "%s", syslogp);
	    break;
#endif /* HAVE_SYSLOG */
	default:
	    break;
	}
    }
    return(0);
}

int
krb5_klog_syslog(int priority, const char *format, ...)
{
    int		retval;
    va_list	pvar;

    va_start(pvar, format);
    retval = klog_vsyslog(priority, format, pvar);
    va_end(pvar);
    return(retval);
}

/*
 * krb5_klog_reopen() - Close and reopen any open (non-syslog) log files.
 *                      This function is called when a SIGHUP is received
 *                      so that external log-archival utilities may
 *                      alert the Kerberos daemons that they should get
 *                      a new file descriptor for the give filename.
 */
void
krb5_klog_reopen(krb5_context kcontext)
{
    int lindex;
    FILE *f;

    /*
     * Only logs which are actually files need to be closed
     * and reopened in response to a SIGHUP
     */
    for (lindex = 0; lindex < log_control.log_nentries; lindex++) {
	if (log_control.log_entries[lindex].log_type == K_LOG_FILE) {
	    fclose(log_control.log_entries[lindex].lfu_filep);
	    /*
	     * In case the old logfile did not get moved out of the
	     * way, open for append to prevent squashing the old logs.
	     */
	    f = fopen(log_control.log_entries[lindex].lfu_fname, "a+F");
	    if (f) {
		log_control.log_entries[lindex].lfu_filep = f;
	    } else {
		fprintf(stderr, "Couldn't open log file %s: %s\n",
			log_control.log_entries[lindex].lfu_fname,
			error_message(errno));
	    }
	}
    }
}

/*
 * Solaris Kerberos:
 * Switch the current context to the one supplied
 */
void krb5_klog_set_context(krb5_context context) {
	err_context = context;
}

/*
 * Solaris Kerberos:
 * Return a string representation of "facility"
 */
static const char * facility2string(int facility) {
	switch (facility) {
		case (LOG_AUTH):
			return ("AUTH");
		case (LOG_KERN):
			return ("KERN");
		case (LOG_USER):
			return ("USER");
		case (LOG_MAIL):
			return ("MAIL");
		case (LOG_DAEMON):
			return ("DAEMON");
		case (LOG_LPR):
			return ("LPR");
		case (LOG_NEWS):
			return ("NEWS");
		case (LOG_UUCP):
			return ("UUCP");
		case (LOG_CRON):
			return ("CRON");
		case (LOG_LOCAL0):
			return ("LOCAL0");
		case (LOG_LOCAL1):
			return ("LOCAL1");
		case (LOG_LOCAL2):
			return ("LOCAL2");
		case (LOG_LOCAL3):
			return ("LOCAL3");
		case (LOG_LOCAL4):
			return ("LOCAL4");
		case (LOG_LOCAL5):
			return ("LOCAL6");
		case (LOG_LOCAL7):
			return ("LOCAL7");
	}
	return ("UNKNOWN");
}

/*
 * Solaris Kerberos:
 * Print to stderr where logging is being done
 */
krb5_error_code krb5_klog_list_logs(const char *whoami) {
	int lindex;

	fprintf(stderr, gettext("%s: logging to "), whoami);
	for (lindex = 0; lindex < log_control.log_nentries; lindex++) {
		if (lindex != 0 && log_control.log_entries[lindex].log_type != K_LOG_NONE)
			fprintf(stderr, ", ");
		switch (log_control.log_entries[lindex].log_type) {
			case K_LOG_FILE:
				fprintf(stderr, "FILE=%s", log_control.log_entries[lindex].lfu_fname);
				break;
			case K_LOG_STDERR:
				fprintf(stderr, "STDERR");
				break;
			case K_LOG_CONSOLE:
				fprintf(stderr, "CONSOLE");
				break;
			case K_LOG_DEVICE:
				fprintf(stderr, "DEVICE=%s", log_control.log_entries[lindex].ldu_devname);
				break;
			case K_LOG_SYSLOG:
				fprintf(stderr, "SYSLOG=%s:%s",
				    severity2string(log_control.log_entries[lindex].lsu_severity),
				    facility2string(log_control.log_entries[lindex].lsu_facility));
				break;
			case K_LOG_NONE:
				break;
			default: /* Should never get here */
				return (-1);
		}
	}
	fprintf(stderr, "\n");
	return (0);
}

/*
 * Solaris Kerberos:
 * Add logging to stderr.
 */
krb5_error_code krb5_klog_add_stderr() {

	struct log_entry *tmp_log_entries = log_control.log_entries;
	int i;

	if (log_control.log_entries != &def_log_entry) {
		log_control.log_entries = realloc(log_control.log_entries,
		    (log_control.log_nentries + 1) * sizeof(struct log_entry));
		if (log_control.log_entries == NULL) {
			log_control.log_entries = tmp_log_entries;
			return (ENOMEM);
		}
	} else {
		log_control.log_entries = malloc(2 * sizeof(struct log_entry));
		if (log_control.log_entries == NULL) {
			log_control.log_entries = &def_log_entry;
			return (ENOMEM);
		}
		(void) memcpy(&log_control.log_entries[0], &def_log_entry,
		    sizeof(struct log_entry));
	}

	i = log_control.log_nentries;
	if (log_control.log_entries[i].lfu_filep =
	    fdopen(fileno(stderr), "a+F")) {
		log_control.log_entries[i].log_type = K_LOG_STDERR;
		log_control.log_entries[i].log_2free = NULL;
		log_control.log_entries[i].lfu_fname = "standard error";
		log_control.log_nentries++;
	} else {
		/* Free the alloc'ed extra entry */
		int err = errno;
		tmp_log_entries = log_control.log_entries;
		log_control.log_entries = realloc(log_control.log_entries,
		    (log_control.log_nentries) * sizeof(struct log_entry));
		if (log_control.log_entries == NULL)
			log_control.log_entries = tmp_log_entries;
		return (err);
	}

	return (0);
}

/*
 * Solaris Kerberos
 * Remove logging to stderr.
 */
void krb5_klog_remove_stderr() {

	struct log_entry *tmp_log_entries = log_control.log_entries;
	int i;

	/* Find the entry (if it exists) */
	for (i = 0; i < log_control.log_nentries; i++) {
		if (log_control.log_entries[i].log_type == K_LOG_STDERR) {
			break;
		}
	}

	if ( i < log_control.log_nentries) {
		for (; i < log_control.log_nentries - 1; i++)
			log_control.log_entries[i] =
			    log_control.log_entries[i + 1];

		if (log_control.log_nentries > 1) {
			log_control.log_entries =
			    realloc(log_control.log_entries,
			    (log_control.log_nentries + 1) *
			    sizeof(struct log_entry));
			if (log_control.log_entries != NULL)
				log_control.log_nentries--;
			else
				log_control.log_entries = tmp_log_entries;
		} else {
			if (log_control.log_entries != NULL)
				free(log_control.log_entries);
		}
	}
}

/* Solaris Kerberos: Indicate if currently logging to stderr */
krb5_boolean krb5_klog_logging_to_stderr() {
	int i;

	/* Find the entry (if it exists) */
	for (i = 0; i < log_control.log_nentries; i++) {
		if (log_control.log_entries[i].log_type == K_LOG_STDERR) {
			return (TRUE);
		}
	}
	return (FALSE);
}

