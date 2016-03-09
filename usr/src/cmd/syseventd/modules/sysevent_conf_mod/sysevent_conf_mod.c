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

/*
 * sysevent_conf_mod - syseventd daemon sysevent.conf module
 *
 *	This module provides a configuration file registration
 *	mechanism whereby event producers can define an event
 *	specification to be matched against events, with an
 *	associated command line to be invoked for each matching event.
 *	It includes a simple macro capability for flexibility in
 *	generating arbitrary command line formats from event-associated
 *	data, and a user specification so that commands can be invoked
 *	with reduced privileges to eliminate a security risk.
 *
 *	sysevent.conf files contain event specifications and associated
 *	command path and optional arguments.  System events received
 *	from the kernel by the sysevent daemon, syseventd, are
 *	compared against the event specifications in the sysevent.conf
 *	files.  The command as specified by pathname and arguments
 *	is invoked for each matching event.
 *
 *	All sysevent.conf files reside in /etc/sysevent/config.
 *
 */


#include <stdio.h>

#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <thread.h>
#include <synch.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/sysevent.h>
#include <libsysevent.h>
#include <libnvpair.h>
#include <dirent.h>
#include <locale.h>
#include <signal.h>
#include <wait.h>

#include "syseventd.h"
#include "syseventconfd_door.h"
#include "sysevent_conf_mod.h"
#include "message_conf_mod.h"


static char	*whoami = "sysevent_conf_mod";

/*
 * Event sequencing, time stamp and retry count
 */
static int	ev_nretries;		/* retry count per event */
static uint64_t	ev_seq;			/* current event sequencing number */
static hrtime_t ev_ts;			/* current event timestamp */
static int	first_event;		/* first event since init */

/*
 * State of the sysevent conf table, derived from
 * the /etc/sysevent/config files
 */
static conftab_t		*conftab		= NULL;
static syseventtab_t		*syseventtab		= NULL;
static syseventtab_t		*syseventtab_tail	= NULL;
static sysevent_handle_t	*confd_handle 		= NULL;

/*
 * The cmd queue is a queue of commands ready to be sent
 * to syseventconfd.  Each command consists of the path
 * and arguments to be fork/exec'ed.  The daemon is unable
 * to handle events during an active fork/exec and returns
 * EAGAIN as a result.  It is grossly inefficient to bounce
 * these events back to syseventd, so we queue them here for delivery.
 */
static cmdqueue_t		*cmdq		= NULL;
static cmdqueue_t		*cmdq_tail	= NULL;
static mutex_t			cmdq_lock;
static cond_t			cmdq_cv;
static int			cmdq_cnt;
static thread_t			cmdq_thr_id;
static cond_t			cmdq_thr_cv;
static int			want_fini;

/*
 * State of the door channel to syseventconfd
 */
static int	confd_state	= CONFD_STATE_NOT_RUNNING;

/*
 * Number of times to retry event after restarting syeventconfd
 */
static int	confd_retries;

/*
 * Number of times to retry a failed transport
 */
static int	transport_retries;

/*
 * Normal sleep time when syseventconfd returns EAGAIN
 * is one second but to avoid thrashing, sleep for
 * something larger when syseventconfd not responding.
 * This should never happen of course but it seems better
 * to attempt to handle possible errors gracefully.
 */
static int	confd_err_msg_emitted;


static int sysevent_conf_dummy_event(sysevent_t *, int);

/*
 * External references
 */
extern int	debug_level;
extern char	*root_dir;
extern void	syseventd_print(int level, char *format, ...);
extern void	syseventd_err_print(char *format, ...);



static struct slm_mod_ops sysevent_conf_mod_ops = {
	SE_MAJOR_VERSION,		/* syseventd module major version */
	SE_MINOR_VERSION,		/* syseventd module minor version */
	SE_MAX_RETRY_LIMIT,		/* max retry if EAGAIN */
	&sysevent_conf_event		/* event handler */
};

static struct slm_mod_ops sysevent_conf_dummy_mod_ops = {
	SE_MAJOR_VERSION,		/* syseventd module major version */
	SE_MINOR_VERSION,		/* syseventd module minor version */
	0,				/* no retries, always succeeds */
	&sysevent_conf_dummy_event	/* dummy event handler */
};



/*
 * skip_spaces() - skip to next non-space character
 */
static char *
skip_spaces(char **cpp)
{
	char *cp = *cpp;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == 0) {
		*cpp = 0;
		return (NULL);
	}
	return (cp);
}


/*
 * Get next white-space separated field.
 * next_field() will not check any characters on next line.
 * Each entry is composed of a single line.
 */
static char *
next_field(char **cpp)
{
	char *cp = *cpp;
	char *start;

	while (*cp == ' ' || *cp == '\t')
		cp++;
	if (*cp == 0) {
		*cpp = 0;
		return (NULL);
	}
	start = cp;
	while (*cp && *cp != ' ' && *cp != '\t')
		cp++;
	if (*cp != 0)
		*cp++ = 0;
	*cpp = cp;
	return (start);
}



/*
 * The following functions are simple wrappers/equivalents
 * for malloc, realloc, free, strdup and a special free
 * for strdup.
 *
 * These functions ensure that any failed mallocs are
 * reported via syslog() so if a command is not evoked
 * in response to an event, the reason should be logged.
 * These functions also provide a convenient place for
 * hooks for checking for memory leaks.
 */

static void *
sc_malloc(size_t n)
{
	void *p;

	p = malloc(n);
	if (p == NULL) {
		syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
	}
	return (p);
}

/*ARGSUSED*/
static void *
sc_realloc(void *p, size_t current, size_t n)
{
	p = realloc(p, n);
	if (p == NULL) {
		syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
	}
	return (p);
}


/*ARGSUSED*/
static void
sc_free(void *p, size_t n)
{
	free(p);
}


static char *
sc_strdup(char *cp)
{
	char *new;

	new = malloc((unsigned)(strlen(cp) + 1));
	if (new == NULL) {
		syslog(LOG_ERR, OUT_OF_MEMORY_ERR);
		return (NULL);
	}
	(void) strcpy(new, cp);
	return (new);
}


static void
sc_strfree(char *s)
{
	if (s)
		free(s);
}


/*
 * The following functions provide some simple dynamic string
 * capability.  This module has no hard-coded maximum string
 * lengths and should be able to parse and generate arbitrarily
 * long strings, macro expansion and command lines.
 *
 * Each string must be explicitly allocated and freed.
 */

/*
 * Allocate a dynamic string, with a hint to indicate how
 * much memory to dynamically add to the string as it grows
 * beyond its existing bounds, so as to avoid excessive
 * reallocs as a string grows.
 */
static str_t *
initstr(int hint)
{
	str_t	*str;

	if ((str = sc_malloc(sizeof (str_t))) == NULL)
		return (NULL);
	str->s_str = NULL;
	str->s_len = 0;
	str->s_alloc = 0;
	str->s_hint = hint;
	return (str);
}


/*
 * Free a dynamically-allocated string
 */
static void
freestr(str_t *str)
{
	if (str->s_str) {
		sc_free(str->s_str, str->s_alloc);
	}
	sc_free(str, sizeof (str_t));
}


/*
 * Reset a dynamically-allocated string, allows reuse
 * rather than freeing the old and allocating a new one.
 */
static void
resetstr(str_t *str)
{
	str->s_len = 0;
}


/*
 * Copy a (simple) string onto a dynamically-allocated string
 */
static int
strcopys(str_t *str, char *s)
{
	char	*new_str;
	int	len = strlen(s) + 1;

	if (str->s_alloc < len) {
		new_str = (str->s_str == NULL) ?
			sc_malloc(len+str->s_hint) :
			sc_realloc(str->s_str, str->s_alloc, len+str->s_hint);
		if (new_str == NULL) {
			return (1);
		}
		str->s_str = new_str;
		str->s_alloc = len + str->s_hint;
	}
	(void) strcpy(str->s_str, s);
	str->s_len = len - 1;
	return (0);
}


/*
 * Concatenate a (simple) string onto a dynamically-allocated string
 */
static int
strcats(str_t *str, char *s)
{
	char	*new_str;
	int	len = str->s_len + strlen(s) + 1;

	if (str->s_alloc < len) {
		new_str = (str->s_str == NULL) ? sc_malloc(len+str->s_hint) :
			sc_realloc(str->s_str, str->s_alloc, len+str->s_hint);
		if (new_str == NULL) {
			return (1);
		}
		str->s_str = new_str;
		str->s_alloc = len + str->s_hint;
	}
	(void) strcpy(str->s_str + str->s_len, s);
	str->s_len = len - 1;
	return (0);
}


/*
 * Concatenate a character onto a dynamically-allocated string
 */
static int
strcatc(str_t *str, int c)
{
	char	*new_str;
	int	len = str->s_len + 2;

	if (str->s_alloc < len) {
		new_str = (str->s_str == NULL) ? sc_malloc(len+str->s_hint) :
			sc_realloc(str->s_str, str->s_alloc, len+str->s_hint);
		if (new_str == NULL) {
			return (1);
		}
		str->s_str = new_str;
		str->s_alloc = len + str->s_hint;
	}
	*(str->s_str + str->s_len) = (char)c;
	*(str->s_str + str->s_len + 1) = 0;
	str->s_len++;
	return (0);
}

/*
 * fgets() equivalent using a dynamically-allocated string
 */
static char *
fstrgets(str_t *line, FILE *fp)
{
	int	c;

	resetstr(line);
	while ((c = fgetc(fp)) != EOF) {
		if (strcatc(line, c))
			return (NULL);
		if (c == '\n')
			break;
	}
	if (line->s_len == 0)
		return (NULL);
	return (line->s_str);
}

/*
 * Truncate a dynamically-allocated string at index position 'pos'
 */
static void
strtrunc(str_t *str, int pos)
{
	if (str->s_len > pos) {
		str->s_len = pos;
		*(str->s_str + pos) = 0;
	}
}



/*
 * Parse a sysevent.conf file, adding each entry spec to the event table.
 *
 * The format of an entry in a sysevent.conf file is:
 *
 *    class subclass vendor publisher user reserved1 reserved path arguments
 *
 * Fields are separated by either SPACE or TAB characters.  A
 * '#' (number sign) at the beginning of a line indicates a
 * comment.  Comment lines and blank lines are ignored.
 *
 * class
 *    The class of the event.
 *
 * subclass
 *    The subclass of the event.
 *
 * vendor
 *    The name of the vendor defining the event, usually the
 *    stock symbol.  Events generated by system components
 *    provided by Sun Microsystems, Inc.  always define vendor
 *    as 'SUNW'.
 *
 * publisher
 *    The name of the application, driver or system module
 *    producing the event.
 *
 * user
 *    The name of the user under which the command should be
 *    run.  This allows commands to run with access privileges
 *    other than those for root.  The user field should be '-'
 *    for commands to be run as root.
 *
 * reserved1
 *    Must be '-'.
 *
 * reserved2
 *    Must be '-'.
 *
 * path
 *    Pathname of the command to be invoked for matching events.
 *
 * arguments
 *    Optional argument with possible macro substitution to permit
 *    arbitrary command line construction with event-specific data.
 */
static void
parse_conf_file(char *conf_file)
{
	char	conf_path[PATH_MAX];
	FILE	*fp;
	char	*lp;
	str_t	*line;
	int	lineno = 0;
	char	*vendor, *publisher;
	char	*class, *subclass;
	char	*user;
	char	*reserved1, *reserved2;
	char	*path, *args;
	syseventtab_t *sep;
	struct passwd pwd;
	struct passwd *pwdp;
	char	pwdbuf[1024];
	int	do_setuid;
	pid_t	saved_uid;
	gid_t	saved_gid;
	int	i, err;

	(void) snprintf(conf_path, PATH_MAX, "%s/%s",
		SYSEVENT_CONFIG_DIR, conf_file);

	syseventd_print(DBG_CONF_FILE, "%s: reading %s\n", whoami, conf_path);

	if ((fp = fopen(conf_path, "r")) == NULL) {
		syslog(LOG_ERR, CANNOT_OPEN_ERR, conf_file, strerror(errno));
		return;
	}

	if ((line = initstr(128)) == NULL)
		return;

	while ((lp = fstrgets(line, fp)) != NULL) {
		lineno++;
		if (*lp == '\n' || *lp == '#')
			continue;
		*(lp + strlen(lp)-1) = 0;

		syseventd_print(DBG_CONF_FILE, "[%d]: %s\n",
			lineno, lp);

		if ((class = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((subclass = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((vendor = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((publisher = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((user = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((reserved1 = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((reserved2 = next_field(&lp)) == NULL)
			goto mal_formed;
		if ((path = next_field(&lp)) == NULL)
			goto mal_formed;
		args = skip_spaces(&lp);

		/*
		 * validate user
		 */
		do_setuid = 0;
		if ((strcmp(user, "-") != 0) && (strcmp(user, "root") != 0)) {
			i = getpwnam_r(user, &pwd, pwdbuf,
					sizeof (pwdbuf), &pwdp);
			if (i != 0 || pwdp == NULL) {
				syslog(LOG_ERR, NO_USER_ERR,
					conf_file, lineno, user);
				continue;
			}
			do_setuid = 1;
		}

		/*
		 * validate reserved fields
		 */
		if (strcmp(reserved1, "-") != 0) {
			syslog(LOG_ERR, RESERVED_FIELD_ERR,
				conf_file, lineno, reserved1);
			continue;
		}
		if (strcmp(reserved2, "-") != 0) {
			syslog(LOG_ERR, RESERVED_FIELD_ERR,
				conf_file, lineno, reserved2);
			continue;
		}

		/*
		 * ensure path is executable by user
		 */
		err = 0;
		if (do_setuid) {
			saved_uid = getuid();
			saved_gid = getgid();
			if (setregid(pwdp->pw_gid, -1) == -1) {
				syslog(LOG_ERR, SETREGID_ERR,
					whoami, pwdp->pw_gid, strerror(errno));
				err = -1;
			}
			if (setreuid(pwdp->pw_uid, -1) == -1) {
				syslog(LOG_ERR, SETREUID_ERR,
					whoami, pwdp->pw_uid, strerror(errno));
				err = -1;
			}
		}
		if ((i = access(path, X_OK)) == -1) {
			syslog(LOG_ERR, CANNOT_EXECUTE_ERR,
				conf_file, lineno, path, strerror(errno));
		}
		if (do_setuid) {
			if (setreuid(saved_uid, -1) == -1) {
				syslog(LOG_ERR, SETREUID_ERR,
					whoami, saved_uid, strerror(errno));
				err = -1;
			}
			if (setregid(saved_gid, -1) == -1) {
				syslog(LOG_ERR, SETREGID_ERR,
					whoami, saved_gid, strerror(errno));
				err = -1;
			}
		}
		if (i == -1 || err == -1)
			continue;

		/*
		 * all sanity tests successful - perform allocations
		 * to add entry to table
		 */
		if ((sep = sc_malloc(sizeof (syseventtab_t))) == NULL)
			break;

		sep->se_conf_file = conf_file;
		sep->se_lineno = lineno;
		sep->se_vendor = sc_strdup(vendor);
		sep->se_publisher = sc_strdup(publisher);
		sep->se_class = sc_strdup(class);
		sep->se_subclass = sc_strdup(subclass);
		sep->se_user = sc_strdup(user);
		if (do_setuid) {
			sep->se_uid = pwdp->pw_uid;
			sep->se_gid = pwdp->pw_gid;
		} else {
			sep->se_uid = 0;
			sep->se_gid = 0;
		}
		sep->se_reserved1 = sc_strdup(reserved1);
		sep->se_reserved2 = sc_strdup(reserved2);
		sep->se_path = sc_strdup(path);
		sep->se_args = (args == NULL) ? NULL : sc_strdup(args);
		sep->se_next = NULL;

		if (sep->se_vendor == NULL || sep->se_publisher == NULL ||
		    sep->se_class == NULL || sep->se_subclass == NULL ||
		    sep->se_user == NULL || sep->se_reserved1 == NULL ||
		    sep->se_reserved2 == NULL || sep->se_path == NULL ||
		    (args && sep->se_args == NULL)) {
			sc_strfree(sep->se_vendor);
			sc_strfree(sep->se_publisher);
			sc_strfree(sep->se_class);
			sc_strfree(sep->se_subclass);
			sc_strfree(sep->se_user);
			sc_strfree(sep->se_reserved1);
			sc_strfree(sep->se_reserved2);
			sc_strfree(sep->se_path);
			sc_strfree(sep->se_args);
			sc_free(sep, sizeof (syseventtab_t));
			break;
		}

		/*
		 * link new entry into the table
		 */
		if (syseventtab == NULL) {
			syseventtab = sep;
			syseventtab_tail = sep;
		} else {
			syseventtab_tail->se_next = sep;
			syseventtab_tail = sep;
		}

		if (debug_level >= DBG_DETAILED) {
			syseventtab_t *sp;
			for (sp = syseventtab; sp; sp = sp->se_next) {
				syseventd_print(DBG_DETAILED,
					"    vendor=%s\n", sp->se_vendor);
				syseventd_print(DBG_DETAILED,
					"    publisher=%s\n", sp->se_publisher);
				syseventd_print(DBG_DETAILED,
					"    class=%s\n", sp->se_class);
				syseventd_print(DBG_DETAILED,
					"    subclass=%s\n", sp->se_subclass);
				syseventd_print(DBG_DETAILED,
					"    user=%s uid=%d gid=%d\n",
					sp->se_user, sp->se_uid, sp->se_gid);
				syseventd_print(DBG_DETAILED,
					"    reserved1=%s\n", sp->se_reserved1);
				syseventd_print(DBG_DETAILED,
					"    reserved2=%s\n", sp->se_reserved2);
				syseventd_print(DBG_DETAILED,
					"    path=%s\n", sp->se_path);
				if (sp->se_args != NULL) {
					syseventd_print(DBG_DETAILED,
						"    args=%s\n", sp->se_args);
				}
			}
		}

		continue;

mal_formed:
		syslog(LOG_ERR, SYNTAX_ERR, conf_file, lineno);
	}

	freestr(line);
	(void) fclose(fp);
}


/*
 * Build the events specification table, a summation of all
 * event specification found in the installed sysevent.conf
 * configuration files.
 *
 * All sysevent.conf files reside in the /etc/sysevent/config
 * and may contain zero or more event/command specifications.
 * A sysevent.conf file should be named as follows:
 *
 *        <vendor>,[<publisher>,][<class>,]sysevent.conf
 *
 * Event/command specifications delivered by the base Solaris
 * system are provided in /etc/sysevent/config/SUNW,sysevent.conf.
 * Event/command specifications delivered by optional
 * Sun-supplied packages may install additional sysevent.conf
 * files in /etc/sysevent/config using vendor SUNW, and additional
 * publisher and/or event class naming to distinguish the
 * events required for those products.  Products provided
 * by third-party hardware or software companies may
 * distinguish their sysevent.conf files by vendor, and
 * by publisher and/or event class within vendor.
 *
 * Files residing in /etc/sysevent/config with a '.' (period)
 * as the first character of the name and files with a suffix
 * of other than "sysevent.conf" are ignored.
 */
static void
build_event_table()
{
	conftab_t	*cfp = NULL;
	DIR		*dir;
	struct dirent	*result;
	conftab_t	*new_cfp;
	char		*str;

	if ((dir = opendir(SYSEVENT_CONFIG_DIR)) == NULL) {
		syslog(LOG_ERR, CANNOT_OPEN_ERR,
			SYSEVENT_CONFIG_DIR, strerror(errno));
		return;
	}

	while ((result = readdir(dir)) != NULL) {
		if (result->d_name[0] == '.')
			continue;

		/*
		 * file must have extension "sysevent.conf"
		 */
		if ((str = strrchr(result->d_name, ',')) != NULL) {
			str++;
		} else {
			str = result->d_name;
		}
		if (strcmp(str, "sysevent.conf") != 0) {
			syseventd_print(DBG_CONF_FILE,
				"%s: ignoring %s\n", whoami, str);
			continue;
		}

		/*
		 * Add to file table and parse this conf file
		 */
		if ((str = sc_strdup(result->d_name)) == NULL)
			goto err;
		if ((new_cfp = sc_malloc(sizeof (conftab_t))) == NULL) {
			sc_strfree(str);
			goto err;
		}
		if (conftab == NULL) {
			conftab = new_cfp;
		} else {
			for (cfp = conftab; cfp->cf_next; cfp = cfp->cf_next)
				;
			cfp->cf_next = new_cfp;
		}
		cfp = new_cfp;
		cfp->cf_conf_file = str;
		cfp->cf_next = NULL;

		parse_conf_file(cfp->cf_conf_file);
	}

err:
	if (closedir(dir) == -1) {
		if (errno == EAGAIN)
			goto err;
		syslog(LOG_ERR, CLOSEDIR_ERR,
			SYSEVENT_CONFIG_DIR, strerror(errno));
	}
}


static int
enter_lock(char *lock_file)
{
	struct flock	lock;
	int		lock_fd;

	(void) strlcpy(lock_file, LOCK_FILENAME, PATH_MAX);
	lock_fd = open(lock_file, O_CREAT|O_RDWR, 0644);
	if (lock_fd < 0) {
		syslog(LOG_ERR, MSG_LOCK_CREATE_ERR,
			whoami, lock_file, strerror(errno));
		return (-1);
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

retry:
	if (fcntl(lock_fd, F_SETLKW, &lock) == -1) {
		if (errno == EAGAIN || errno == EINTR)
			goto retry;
		(void) close(lock_fd);
		syslog(LOG_ERR, MSG_LOCK_SET_ERR,
			whoami, lock_file, strerror(errno));
		return (-1);
	}

	return (lock_fd);
}


static void
exit_lock(int lock_fd, char *lock_file)
{
	struct flock	lock;

	lock.l_type = F_UNLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(lock_fd, F_SETLK, &lock) == -1) {
		syslog(LOG_ERR, MSG_LOCK_CLR_ERR,
			whoami, lock_file, strerror(errno));
	}

	if (close(lock_fd) == -1) {
		syslog(LOG_ERR, MSG_LOCK_CLOSE_ERR,
			whoami, lock_file, strerror(errno));
	}
}


/*
 * Free the events specification table, constructed by
 * parsing all the sysevent.conf files found.
 *
 * The free of this table is in response to a HUP
 * given to the syseventd daemon, permitting the
 * table to be rebuilt after adding a new sysevent.conf
 * file or changing an existing one without shutting
 * down the daemon.
 */
static void
free_event_table()
{
	syseventtab_t *sep;
	syseventtab_t *sep_next;
	conftab_t *cfp;
	conftab_t *cfp_next;

	sep = syseventtab;
	while (sep) {
		sc_strfree(sep->se_vendor);
		sc_strfree(sep->se_publisher);
		sc_strfree(sep->se_class);
		sc_strfree(sep->se_subclass);
		sc_strfree(sep->se_user);
		sc_strfree(sep->se_reserved1);
		sc_strfree(sep->se_reserved2);
		sc_strfree(sep->se_path);
		if (sep->se_args)
			sc_strfree(sep->se_args);
		sep_next = sep->se_next;
		sc_free(sep, sizeof (syseventtab_t));
		sep = sep_next;
	}
	syseventtab = NULL;

	cfp = conftab;
	while (cfp) {
		sc_strfree(cfp->cf_conf_file);
		cfp_next = cfp->cf_next;
		sc_free(cfp, sizeof (conftab_t));
		cfp = cfp_next;
	}
	conftab = NULL;
}



static char ident_chars[] = "_";

/*
 * Return a dynamically-allocated string containing the
 * the next identifier in the string being parsed, pointed
 * at by 'id'.  'end' returns a pointer to the character
 * after the identifier.
 *
 * Identifiers are all alphanumeric ascii characters and
 * those contained in ident_chars.
 *
 * The returned string must be explicitly freed via
 * freestr().
 */
static str_t *
snip_identifier(char *id, char **end)
{
	str_t	*token;

	if ((token = initstr(32)) == NULL)
		return (NULL);

	while (*id != 0) {
		if (isascii(*id) &&
		    (isalnum(*id) || strchr(ident_chars, *id) != NULL)) {
			if (strcatc(token, *id++)) {
				freestr(token);
				return (NULL);
			}
		} else {
			*end = id;
			return (token);
		}
	}

	*end = id;
	return (token);
}


/*
 * Identical to snip_identifier(), but the identifier
 * is delimited by the characters { and }.
 */
static str_t *
snip_delimited_identifier(char *id, char **end)
{
	str_t	*token;

	if ((token = initstr(32)) == NULL)
		return (NULL);

	while (*id != 0) {
		if (*id == '}') {
			*end = id+1;
			return (token);
		}
		if (strcatc(token, *id++)) {
			freestr(token);
			return (NULL);
		}
	}

	if (*id == 0) {
		freestr(token);
		return (NULL);
	}

	*end = id;
	return (token);
}


/*
 * Return a string with the name of the attribute type
 */
static char *nv_attr_type_strings[] = {
	"unknown",
	"boolean",
	"byte",
	"int16",
	"uint16",
	"int32",
	"uint32",
	"int64",
	"uint64",
	"string",
	"byte-array",
	"int16-array",
	"uint16-array",
	"int32-array",
	"uint32-array",
	"int64-array",
	"uint64-array",
	"string-array",
	"hrtime"
};

static char *
se_attr_type_to_str(int se_attr_type)
{
	if (se_attr_type >= 0 &&
	    se_attr_type < sizeof (nv_attr_type_strings) / sizeof (char *)) {
		return (nv_attr_type_strings[se_attr_type]);
	}
	return (nv_attr_type_strings[DATA_TYPE_UNKNOWN]);
}


/*
 * Find and return the data matching the macro name 'token'
 *
 * Predefined macros are simply substituted with the
 * data from the event header:
 *
 *	$vendor - the vendor string defining the event.
 *
 *	$publisher - the publisher string defining the event.
 *
 *	$class - the class string defining the event.
 *
 *	$subclass - the subclass string defining the event.
 *
 *	$sequence - the sequence number of the event.
 *
 *	$timestamp - the timestamp of the event.
 *
 * Attributes with signed data types (DATA_TYPE_INT16,
 * DATA_TYPE_INT32 and DATA_TYPE_INT64) are expanded
 * as decimal digits.
 *
 * Attributes with unsigned data types (DATA_TYPE_BYTE,
 * DATA_TYPE_UINT16, DATA_TYPE_UINT32, DATA_TYPE_UINT64 and
 * DATA_TYPE_HTTIME) are expanded as hexadecimal digits
 * with a "0x" prefix.
 *
 * Attributes with string data type (DATA_TYPE_STRING)
 * are expanded with the string data.  The data is
 * not quoted.  If if it desired that the quoted strings
 * be generated on the command line, put quotes around
 * the macro call in the arguments.
 *
 * Array types are expanded with each element expanded
 * as defined for that scalar type, with a space separating
 * each element substitution.
 */

static str_t *
find_macro_definition(sysevent_t *ev, nvlist_t *nvlist, syseventtab_t *sep,
	char *token, sysevent_hdr_info_t *hdr)
{
	nvpair_t		*nvp;
	int			nmatches;
	char			num[64];
	str_t			*replacement;
	int			i;
	uint_t			nelems;
	union {
		uchar_t		x_byte;
		int16_t		x_int16;
		uint16_t	x_uint16;
		int32_t		x_int32;
		uint32_t	x_uint32;
		int64_t		x_int64;
		uint64_t	x_uint64;
		hrtime_t	x_time;
		char		*x_string;
		uchar_t		*x_byte_array;
		int16_t		*x_int16_array;
		int32_t		*x_int32_array;
		int64_t		*x_int64_array;
		uint16_t	*x_uint16_array;
		uint32_t	*x_uint32_array;
		uint64_t	*x_uint64_array;
		char		**x_string_array;
	} x;


	if ((replacement = initstr(128)) == NULL) {
		return (NULL);
	}

	if (strcmp(token, "vendor") == 0) {
		if (strcopys(replacement, hdr->vendor)) {
			freestr(replacement);
			return (NULL);
		}
		return (replacement);
	}

	if (strcmp(token, "publisher") == 0) {
		if (strcopys(replacement, hdr->publisher)) {
			freestr(replacement);
			return (NULL);
		}
		return (replacement);
	}

	if (strcmp(token, "class") == 0) {
		if (strcopys(replacement, hdr->class)) {
			freestr(replacement);
			return (NULL);
		}
		return (replacement);
	}

	if (strcmp(token, "subclass") == 0) {
		if (strcopys(replacement, hdr->subclass)) {
			freestr(replacement);
			return (NULL);
		}
		return (replacement);
	}

	if ((strcmp(token, "sequence") == 0) ||
	    (strcmp(token, "timestamp") == 0)) {
		if (strcmp(token, "sequence") == 0) {
			(void) snprintf(num, sizeof (num),
				"0x%llx", sysevent_get_seq(ev));
		} else {
			hrtime_t ts;
			sysevent_get_time(ev, &ts);
			(void) snprintf(num, sizeof (num), "0x%llx", ts);
		}
		if (strcopys(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		return (replacement);
	}

	nmatches = 0;

	if (nvlist) {
		nvpair_t *nvp_match;
		nvp = NULL;
		while ((nvp = nvlist_next_nvpair(nvlist, nvp)) != NULL) {
			if (debug_level >= DBG_DETAILED) {
				syseventd_print(DBG_DETAILED,
				"    attribute: %s %s\n", nvpair_name(nvp),
				se_attr_type_to_str(nvpair_type(nvp)));
			}
			if (strcmp(token, nvpair_name(nvp)) == 0) {
				nmatches++;
				nvp_match = nvp;
			}
		}
		nvp = nvp_match;
	}

	if (nmatches == 0) {
		syslog(LOG_ERR, MACRO_UNDEF_ERR,
			sep->se_conf_file, sep->se_lineno, token);
		freestr(replacement);
		return (NULL);
	} else if (nmatches > 1) {
		syslog(LOG_ERR, MACRO_MULT_DEF_ERR,
			sep->se_conf_file, sep->se_lineno, token);
		freestr(replacement);
		return (NULL);
	}

	switch (nvpair_type(nvp)) {
	case DATA_TYPE_BYTE:
		(void) nvpair_value_byte(nvp, &x.x_byte);
		(void) snprintf(num, sizeof (num), "0x%x", x.x_byte);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_INT16:
		(void) nvpair_value_int16(nvp, &x.x_int16);
		(void) snprintf(num, sizeof (num), "%d", x.x_int16);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_UINT16:
		(void) nvpair_value_uint16(nvp, &x.x_uint16);
		(void) snprintf(num, sizeof (num), "0x%x", x.x_uint16);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_INT32:
		(void) nvpair_value_int32(nvp, &x.x_int32);
		(void) snprintf(num, sizeof (num), "%d", x.x_int32);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_UINT32:
		(void) nvpair_value_uint32(nvp, &x.x_uint32);
		(void) snprintf(num, sizeof (num), "0x%x", x.x_uint32);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_INT64:
		(void) nvpair_value_int64(nvp, &x.x_int64);
		(void) snprintf(num, sizeof (num), "%lld", x.x_int64);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_UINT64:
		(void) nvpair_value_uint64(nvp, &x.x_uint64);
		(void) snprintf(num, sizeof (num), "0x%llx", x.x_uint64);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_STRING:
		(void) nvpair_value_string(nvp, &x.x_string);
		if (strcats(replacement, x.x_string)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	case DATA_TYPE_BYTE_ARRAY: {
			uchar_t	*p;
			(void) nvpair_value_byte_array(nvp,
				&x.x_byte_array, &nelems);
			p = x.x_byte_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num),
					"0x%x ", *p++ & 0xff);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;
	case DATA_TYPE_INT16_ARRAY: {
			int16_t *p;
			(void) nvpair_value_int16_array(nvp,
				&x.x_int16_array, &nelems);
			p = x.x_int16_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num), "%d ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_UINT16_ARRAY: {
			uint16_t *p;
			(void) nvpair_value_uint16_array(nvp,
				&x.x_uint16_array, &nelems);
			p = x.x_uint16_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num),
					"0x%x ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_INT32_ARRAY: {
			int32_t *p;
			(void) nvpair_value_int32_array(nvp,
				&x.x_int32_array, &nelems);
			p = x.x_int32_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num), "%d ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_UINT32_ARRAY: {
			uint32_t *p;
			(void) nvpair_value_uint32_array(nvp,
				&x.x_uint32_array, &nelems);
			p = x.x_uint32_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num),
					"0x%x ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_INT64_ARRAY: {
			int64_t *p;
			(void) nvpair_value_int64_array(nvp,
				&x.x_int64_array, &nelems);
			p = x.x_int64_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num),
					"%lld ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_UINT64_ARRAY: {
			uint64_t *p;
			(void) nvpair_value_uint64_array(nvp,
				&x.x_uint64_array, &nelems);
			p = x.x_uint64_array;
			for (i = 0; i < nelems; i++) {
				(void) snprintf(num, sizeof (num),
					"0x%llx ", *p++);
				if (strcats(replacement, num)) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_STRING_ARRAY: {
			char **p;
			(void) nvpair_value_string_array(nvp,
				&x.x_string_array, &nelems);
			p = x.x_string_array;
			for (i = 0; i < nelems; i++) {
				if (strcats(replacement, *p++) ||
				    strcats(replacement, " ")) {
					freestr(replacement);
					return (NULL);
				}
			}
		}
		break;

	case DATA_TYPE_HRTIME:
		(void) nvpair_value_hrtime(nvp, &x.x_time);
		(void) snprintf(num, sizeof (num), "0x%llx", x.x_time);
		if (strcats(replacement, num)) {
			freestr(replacement);
			return (NULL);
		}
		break;
	default:
		syslog(LOG_ERR, ATTR_UNSUPPORTED_ERR,
			sep->se_conf_file, sep->se_lineno,
			nvpair_type(nvp), token);
		freestr(replacement);
		return (NULL);
	}

	return (replacement);
}

/*
 * Expand macros in the command template provided in an event
 * specification with the data from the event or event attributes.
 *
 * Macros are introduced by the '$' character, with the macro
 * name being the following token separated by a SPACE or
 * TAB character.  If the macro name is embedded in text,
 * it may be delineated by '${' and "}'.  A backslash before
 * the '$' causes macro expansion not to occur.
 *
 * The following predefined macros are defined for each event:
 *
 *	$vendor - the vendor string defining the event.
 *
 *	$publisher - the publisher string defining the event.
 *
 *	$class - the class string defining the event.
 *
 *	$subclass - the subclass string defining the event.
 *
 *	$sequence - the sequence number of the event.
 *
 *	$timestamp - the timestamp of the event.
 *
 *
 * Macro names other than those predefined are compared against
 * the attribute list provided with the event.  An attribute
 * with name matching the macro name causes the value of
 * of the attribute to be substituted as ASCII text on the
 * generated command line.
 *
 * Use of a macro for which no attribute with that name
 * is defined, or for which multiple attributes with that
 * name are provided, cause an error and the command is
 * not invoked.
 */
static int
expand_macros(sysevent_t *ev, nvlist_t *nvlist, syseventtab_t *sep,
	str_t *line, sysevent_hdr_info_t *hdr)
{
	char	*p;
	int	state;
	char	*end;
	str_t	*token;
	str_t	*remainder;
	str_t	*replacement;
	int	count;
	int	dollar_position;

	syseventd_print(DBG_MACRO, "    expanding macros: '%s'\n", line->s_str);

reset:
	state = 0;
	count = 0;
	for (p = line->s_str; *p != 0; p++, count++) {
		switch (state) {
		case 0:				/* initial state */
			if (*p == '\\') {
				state = 1;
			} else if (*p == '$') {
				dollar_position = count;
				state = 2;
			}
			break;
		case 1:				/* skip characters */
			state = 0;		/* after backslash */
			break;
		case 2:				/* character after $ */
			if (*p == '{') {
				token = snip_delimited_identifier(p+1, &end);
			} else {
				token = snip_identifier(p, &end);
			}
			if (token == NULL)
				goto failed;

			if ((remainder = initstr(128)) == NULL) {
				freestr(token);
				return (1);
			}
			if (strcopys(remainder, end)) {
				freestr(token);
				freestr(remainder);
				return (1);
			}
			replacement = find_macro_definition(ev, nvlist,
				sep, token->s_str, hdr);
			if (replacement == NULL) {
				freestr(token);
				freestr(remainder);
				return (1);
			}
			syseventd_print(DBG_MACRO,
				"    '%s' expands to '%s'\n",
				token->s_str, replacement->s_str);

			strtrunc(line, dollar_position);
			if (strcats(line, replacement->s_str)) {
				freestr(token);
				freestr(replacement);
				freestr(remainder);
				return (1);
			}
			if (strcats(line, remainder->s_str)) {
				freestr(token);
				freestr(replacement);
				freestr(remainder);
				return (1);
			}

			syseventd_print(DBG_MACRO,
				"    with macro expanded: '%s'\n", line->s_str);

			freestr(token);
			freestr(replacement);
			freestr(remainder);
			goto reset;
		}
	}

failed:
	if (state != 0) {
		syslog(LOG_ERR, SYNTAX_ERR, sep->se_conf_file, sep->se_lineno);
		return (1);
	}

	return (0);
}


static void
start_syseventconfd()
{
	int	err;

	err = system1("/usr/lib/sysevent/syseventconfd",
		"/usr/lib/sysevent/syseventconfd");

	if (err != 0 && confd_err_msg_emitted == 0) {
		if (confd_state == CONFD_STATE_NOT_RUNNING) {
			syslog(LOG_ERR, SYSEVENTCONFD_START_ERR,
				strerror(errno));
		} else {
			syslog(LOG_ERR, SYSEVENTCONFD_RESTART_ERR,
				strerror(errno));
		}
	}
}


static int
system1(const char *s_path, const char *s)
{
	struct sigaction cbuf, ibuf, qbuf, ignore, dfl;
	sigset_t mask;
	sigset_t savemask;
	struct stat st;
	pid_t pid;
	int status, w;

	/* Check the requested command */
	if (s == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Check the ability to execute devfsadmd from this process */
	if (stat(s_path, &st) < 0) {
		return (-1);
	}
	if (((geteuid() == st.st_uid) && ((st.st_mode & S_IXUSR) == 0)) ||
		((getegid() == st.st_gid) && ((st.st_mode & S_IXGRP) == 0)) ||
		((st.st_mode & S_IXOTH) == 0)) {
		errno = EPERM;
		return (-1);
	}

	/*
	 * Block SIGCHLD and set up a default handler for the duration of the
	 * system1 call.
	 */
	(void) sigemptyset(&mask);
	(void) sigaddset(&mask, SIGCHLD);
	(void) sigprocmask(SIG_BLOCK, &mask, &savemask);
	(void) memset(&dfl, 0, sizeof (dfl));
	dfl.sa_handler = SIG_DFL;
	(void) sigaction(SIGCHLD, &dfl, &cbuf);

	/* Fork off the child process (using fork1(), because it's MT-safe) */
	switch (pid = fork1()) {
		case -1:
			/* Error */
			(void) sigaction(SIGCHLD, &cbuf, NULL);
			(void) sigprocmask(SIG_SETMASK, &savemask, NULL);
			return (-1);
		case 0:
			/* Set-up an initial signal mask for the child */
			(void) sigemptyset(&mask);
			(void) sigprocmask(SIG_SETMASK, &mask, NULL);
			closefrom(3);
			(void) execl(s_path, s, (char *)0);
			_exit(-1);
			break;
		default:
			/* Parent */
			break;
	}

	(void) memset(&ignore, 0, sizeof (ignore));
	ignore.sa_handler = SIG_IGN;
	(void) sigaction(SIGINT, &ignore, &ibuf);
	(void) sigaction(SIGQUIT, &ignore, &qbuf);

	do {
		w = waitpid(pid, &status, 0);
	} while (w == -1 && errno == EINTR);

	(void) sigaction(SIGINT, &ibuf, NULL);
	(void) sigaction(SIGQUIT, &qbuf, NULL);

	(void) sigaction(SIGCHLD, &cbuf, NULL);
	(void) sigprocmask(SIG_SETMASK, &savemask, NULL);

	return ((w == -1)? w: status);
}

/*
 * Free all commands on the cmd queue
 */
static void
abort_cmd_queue()
{
	cmdqueue_t	*cmd;
	cmdqueue_t	*next;
	int		nevents = 0;

	while ((cmd = cmdq) != NULL) {
		next = cmd->next;
		cmdq_cnt--;
		sysevent_free(cmd->event);
		sc_free(cmd, sizeof (cmdqueue_t));
		cmdq = next;
		nevents++;
	}
	cmdq_tail = NULL;

	/*
	 * Generate error msgs if events were discarded or
	 * we are entering the disabled state.
	 */
	if (nevents > 0) {
		syslog(LOG_ERR, N_EVENTS_DISCARDED_ERR, nevents);
	}
	if (want_fini == 0) {
		confd_state = CONFD_STATE_DISABLED;
		syslog(LOG_ERR, SERVICE_DISABLED_MSG);
	}
}

/*
 * For a matching event specification, build the command to be
 * invoked in response to the event.  Building the command involves
 * expanding macros supplied in the event specification command
 * with values from the actual event.  These macros can be
 * the class/subclass/vendor/publisher strings, or arbitrary
 * attribute data attached to the event.
 *
 * This module does not invoke (fork/exec) the command itself,
 * since this module is running in the context of the syseventd
 * daemon, and fork/exec's done here interfere with the door
 * upcall delivering events from the kernel to the daemon.
 * Instead, we build a separate event and nvlist with the
 * attributes of the command to be invoked, and pass that on
 * to the syseventconfd daemon, which is basically a fork/exec
 * server on our behalf.
 *
 * Errors queuing the event are returned to syseventd with
 * EAGAIN, allowing syseventd to manage a limited number of
 * retries after a short delay.
 */
static int
queue_event(sysevent_t *ev, syseventtab_t *sep, sysevent_hdr_info_t *hdr)
{
	str_t		*line;
	nvlist_t	*nvlist;
	char 		*argv0;
	sysevent_t	*cmd_event;
	nvlist_t	*cmd_nvlist;
	cmdqueue_t	*new_cmd;

	if ((line = initstr(128)) == NULL)
		return (1);

	if ((argv0 = strrchr(sep->se_path, '/')) == NULL) {
		argv0 = sep->se_path;
	} else {
		argv0++;
	}
	if (strcopys(line, argv0)) {
		freestr(line);
		return (1);
	}

	if (sep->se_args) {
		if (strcats(line, " ")) {
			freestr(line);
			return (1);
		}
		if (strcats(line, sep->se_args)) {
			freestr(line);
			return (1);
		}

		if (sysevent_get_attr_list(ev, &nvlist) != 0) {
			syslog(LOG_ERR, GET_ATTR_LIST_ERR,
				sep->se_conf_file, sep->se_lineno,
				strerror(errno));
			freestr(line);
			return (1);
		}
		if (expand_macros(ev, nvlist, sep, line, hdr)) {
			freestr(line);
			nvlist_free(nvlist);
			return (1);
		}
		nvlist_free(nvlist);
	}

	if (debug_level >= DBG_EXEC) {
		syseventd_print(DBG_EXEC, "%s, line %d: path = %s\n",
			sep->se_conf_file, sep->se_lineno, sep->se_path);
		syseventd_print(DBG_EXEC, "    cmd = %s\n", line->s_str);
	}

	cmd_nvlist = NULL;
	if ((errno = nvlist_alloc(&cmd_nvlist, NV_UNIQUE_NAME, 0)) != 0) {
		freestr(line);
		syslog(LOG_ERR, NVLIST_ALLOC_ERR,
			sep->se_conf_file, sep->se_lineno,
			strerror(errno));
		return (1);
	}

	if ((errno = nvlist_add_string(cmd_nvlist, "path", sep->se_path)) != 0)
		goto err;
	if ((errno = nvlist_add_string(cmd_nvlist, "cmd", line->s_str)) != 0)
		goto err;
	if ((errno = nvlist_add_string(cmd_nvlist, "file",
	    sep->se_conf_file)) != 0)
		goto err;
	if ((errno = nvlist_add_int32(cmd_nvlist, "line", sep->se_lineno)) != 0)
		goto err;
	if ((errno = nvlist_add_string(cmd_nvlist, "user", sep->se_user)) != 0)
		goto err;

	if (sep->se_uid != (uid_t)0) {
		if ((errno = nvlist_add_int32(cmd_nvlist, "uid",
		    sep->se_uid)) != 0)
			goto err;
		if ((errno = nvlist_add_int32(cmd_nvlist, "gid",
		    sep->se_gid)) != 0)
			goto err;
	}

	cmd_event = sysevent_alloc_event(hdr->class, hdr->subclass, hdr->vendor,
		hdr->publisher, cmd_nvlist);
	if (cmd_event == NULL) {
		syslog(LOG_ERR, SYSEVENT_ALLOC_ERR,
			sep->se_conf_file, sep->se_lineno,
			strerror(errno));
		nvlist_free(cmd_nvlist);
		freestr(line);
		return (1);
	}

	nvlist_free(cmd_nvlist);
	freestr(line);

	/*
	 * Place cmd_event on queue to be transported to syseventconfd
	 */
	if ((new_cmd = sc_malloc(sizeof (cmdqueue_t))) == NULL) {
		sysevent_free(cmd_event);
		return (1);
	}
	new_cmd->event = cmd_event;
	new_cmd->next = NULL;
	(void) mutex_lock(&cmdq_lock);
	if (cmdq == NULL) {
		cmdq = new_cmd;
	} else {
		cmdq_tail->next = new_cmd;
	}
	cmdq_cnt++;
	cmdq_tail = new_cmd;

	/*
	 * signal queue flush thread
	 */
	(void) cond_signal(&cmdq_cv);

	(void) mutex_unlock(&cmdq_lock);

	return (0);

err:
	syslog(LOG_ERR, NVLIST_BUILD_ERR,
		sep->se_conf_file, sep->se_lineno, strerror(errno));
	nvlist_free(cmd_nvlist);
	freestr(line);
	return (1);
}


static int
transport_event(sysevent_t *event)
{
	int	rval;

	rval = sysevent_send_event(confd_handle, event);
	if (rval != 0) {
		switch (errno) {
		case EAGAIN:
		case EINTR:
			/*
			 * syseventconfd daemon may be forking, stop
			 * attempting to empty the queue momentarily.
			 */
			rval = errno;
			break;
		case ENOENT:
		case EBADF:
			/*
			 * start/restart the syseventconfd daemon,
			 * allowing for some delay when starting
			 * up before it begins to reply.
			 */
			if (confd_state == CONFD_STATE_NOT_RUNNING ||
			    confd_state == CONFD_STATE_OK) {
				confd_state = CONFD_STATE_STARTED;
				start_syseventconfd();
				confd_retries = 0;
				rval = EAGAIN;
			} else if (confd_state == CONFD_STATE_STARTED &&
			    confd_retries < 16) {
				if (++confd_retries == 16) {
					confd_state = CONFD_STATE_ERR;
					if (confd_err_msg_emitted == 0) {
						syslog(LOG_ERR,
						    SYSEVENTCONFD_ERR);
						confd_err_msg_emitted = 1;
					}
				}
				rval = EAGAIN;
			} else {
				rval = errno;
			}
			break;
		default:
			syslog(LOG_ERR, SYSEVENTCONFD_TRAN_ERR,
				strerror(errno));
			rval = errno;
			break;
		}
	} else if (confd_state != CONFD_STATE_OK) {
		if (confd_state == CONFD_STATE_ERR) {
			syslog(LOG_ERR, SYSEVENTCONFD_OK);
			confd_err_msg_emitted = 0;
		}
		confd_state = CONFD_STATE_OK;
		confd_retries = 0;
		confd_err_msg_emitted = 0;
	}
	return (rval);
}


/*
 * Send events on queue to syseventconfd daemon.  We queue events
 * here since the daemon is unable to handle events during an
 * active fork/exec, returning EAGAIN as a result.  It is grossly
 * inefficient to bounce these events back to syseventd, so
 * we queue them here for delivery.
 *
 * EAGAIN/EINTR don't indicate errors with the transport to
 * syseventconfd itself, just the daemon is busy or some
 * other transient difficulty.  We retry EBADF and other errors
 * for some time, then eventually give up - something's broken.
 *
 * Error handling strategy:
 * If we're trying to shut down and the syseventconfd daemon isn't
 * responding, abort the queue so we don't cause the fini to hang
 * forever.  Otherwise, EAGAIN/EINTR are retried forever, as
 * we presume the daemon is active but either busy or some transient
 * state is preventing the transport.  We make considerable effort
 * to retry EBADF since the daemon may take some time to come up when
 * restarted so don't want to give up too easily.  Once we enter
 * the DISABLED state, we stop handling events altogther to
 * avoid thrashing the system if the syseventconfd binary is
 * corrupted or missing.  This state can be cleared by issuing
 * a HUP signal to the syseventd daemon.  For errors other than
 * EAGAIN/EINTR/EBADF, we just drop the event and if we get
 * a certain number of these in a row, we enter the DISABLED
 * state.
 */

static void
transport_queued_events()
{
	int		rval;
	cmdqueue_t	*cmd;

	(void) mutex_lock(&cmdq_lock);
	while (cmdq != NULL) {
		cmd = cmdq;
		(void) mutex_unlock(&cmdq_lock);
		rval = transport_event(cmd->event);
		(void) mutex_lock(&cmdq_lock);
		if (rval != 0) {
			switch (rval) {
			case EAGAIN:
			case EINTR:
				/*
				 * Limit retries in the case of fini
				 */
				if (want_fini) {
					if (++transport_retries == 16) {
						abort_cmd_queue();
					}
				}
				(void) mutex_unlock(&cmdq_lock);
				return;
			case EBADF:
				/*
				 * retry up to 16 times
				 */
				if (want_fini || ++transport_retries == 16) {
					abort_cmd_queue();
				}
				(void) mutex_unlock(&cmdq_lock);
				return;
			default:
				/*
				 * After 16 sequential errors, give up
				 */
				if (++transport_retries == 16) {
					abort_cmd_queue();
					(void) mutex_unlock(&cmdq_lock);
					return;
				}
				/*
				 * We don't retry these errors, we
				 * fall through to remove this event
				 * from the queue.
				 */
				break;
			}
		} else {
			transport_retries = 0;
		}

		/*
		 * Take completed event off queue
		 */
		cmdq_cnt--;
		cmdq = cmdq->next;
		if (cmdq == NULL) {
			cmdq_tail = NULL;
		}
		(void) mutex_unlock(&cmdq_lock);
		sysevent_free(cmd->event);
		sc_free(cmd, sizeof (cmdqueue_t));
		(void) mutex_lock(&cmdq_lock);
	}

	(void) mutex_unlock(&cmdq_lock);
}


static void
queue_flush_thr()
{
	int	n;

	(void) mutex_lock(&cmdq_lock);
	for (;;) {
		while (cmdq_cnt == 0 && want_fini == 0) {
			(void) cond_wait(&cmdq_cv, &cmdq_lock);
		}
		if (cmdq_cnt == 0 && want_fini) {
			(void) cond_signal(&cmdq_thr_cv);
			(void) mutex_unlock(&cmdq_lock);
			thr_exit(NULL);
			/*NOTREACHED*/
		}
		(void) mutex_unlock(&cmdq_lock);
		transport_queued_events();
		(void) mutex_lock(&cmdq_lock);
		if (cmdq_cnt != 0) {
			(void) mutex_unlock(&cmdq_lock);
			if (want_fini == 0 && confd_err_msg_emitted) {
				for (n = 0; n < 60; n++) {
					(void) sleep(1);
					if (want_fini)
						break;
				}
			} else {
				(void) sleep(1);
			}
			(void) mutex_lock(&cmdq_lock);
		}
	}
}


/*
 * syseventd daemon module event handler
 *
 * The syseventd daemon calls this handler with each event
 * for this module to handle the event as appropriate.
 * The task of this module is to compare the event's
 * class/subclass/publisher/vendor against the list of
 * event specifications provided in the installed
 * sysevent.conf files.  Build and execute the
 * defined command for that event specification
 * for each match.
 *
 * Events are matched against the class, subclass, vendor
 * and publisher specifications.  Any field not to be matched
 * against an event should be set to '-'.  A specification
 * of '- - - -' generates a match against every event.
 */
/*ARGSUSED*/
static int
sysevent_conf_event(sysevent_t *ev, int flag)
{
	int	ret = 0;
	char	*vendor;
	char	*publisher;
	char	*class;
	char	*subclass;
	syseventtab_t *sep;
	sysevent_hdr_info_t hdr;
	uint64_t seq;
	hrtime_t ts;

	/*
	 * If we've been completely unable to communicate with
	 * syseventconfd, there's not much we can do.
	 */
	if (confd_state == CONFD_STATE_DISABLED) {
		return (0);
	}

	/*
	 * sysevent_get_seq(ev) < ev_seq):
	 *	an event we have played before, ignore it
	 * sysevent_get_seq(ev) == ev_seq):
	 *	ev_nretries > 0, an event being retried
	 * sysevent_get_seq(ev) > ev_seq):
	 *	a new event
	 */
	if (debug_level >= DBG_EVENTS) {
		if (sysevent_get_seq(ev) == ev_seq && ev_nretries > 0) {
			syseventd_print(DBG_EVENTS,
			    "sequence: %lld/%lld, retry %d\n",
			    sysevent_get_seq(ev), ev_seq, ev_nretries);
		} else if (sysevent_get_seq(ev) > ev_seq) {
			syseventd_print(DBG_EVENTS,
			    "sequence: %lld/%lld\n",
			    sysevent_get_seq(ev), ev_seq);
		}
	}

	seq = sysevent_get_seq(ev);
	sysevent_get_time(ev, &ts);

	if (seq > ev_seq || ts > ev_ts) {
		ev_nretries = 0;
	} else if (first_event == 0 &&
	    (((seq < ev_seq) || (seq == 0 && ts > ev_ts)) ||
	    (seq == ev_seq && ev_nretries == 0))) {
		syseventd_print(DBG_TEST,
		    "out-of-order sequence: received %lld/0x%llx, "
		    "expected %lld/0x%llx\n", seq, ts, ev_seq+1, ev_ts);
		return (ret);
	}

	ev_ts = ts;
	ev_seq = seq;
	first_event = 0;

	/*
	 * sysevent_get_vendor_name() and sysevent_get_pub_name()
	 * allocate strings which must be freed.
	 */
	vendor = sysevent_get_vendor_name(ev);
	publisher = sysevent_get_pub_name(ev);
	class = sysevent_get_class_name(ev);
	subclass = sysevent_get_subclass_name(ev);

	if (vendor == NULL || publisher == NULL) {
		syseventd_print(DBG_EVENTS, "Short on memory with vendor "
		    "and/or publisher string generation\n");
		/* Temporary short on memory */
		ev_nretries++;
		free(publisher);
		free(vendor);
		return (EAGAIN);
	}

	syseventd_print(DBG_EVENTS,
		"%s event %lld: vendor='%s' publisher='%s' class='%s' "
		"subclass='%s'\n", whoami, sysevent_get_seq(ev), vendor,
		publisher, class, subclass);

	for (sep = syseventtab; sep; sep = sep->se_next) {
		if (strcmp(sep->se_vendor, "-") != 0) {
			if (strcmp(sep->se_vendor, vendor) != 0)
				continue;
		}
		if (strcmp(sep->se_publisher, "-") != 0) {
			if (strcmp(sep->se_publisher, publisher) != 0)
				continue;
		}
		if (strcmp(sep->se_class, "-") != 0) {
			if (strcmp(sep->se_class, class) != 0)
				continue;
		}
		if (strcmp(sep->se_subclass, "-") != 0) {
			if (strcmp(sep->se_subclass, subclass) != 0)
				continue;
		}
		syseventd_print(DBG_MATCHES, "    event match: %s, line %d\n",
			sep->se_conf_file, sep->se_lineno);
		hdr.class = class;
		hdr.subclass = subclass;
		hdr.vendor = vendor;
		hdr.publisher = publisher;
		if ((ret = queue_event(ev, sep, &hdr)) != 0)
			break;
	}

	if (ret == 0) {
		ev_nretries = 0;
	} else {
		/*
		 * Ask syseventd to retry any failed event.  If we have
		 * reached the limit on retries, emit a msg that we're
		 * not going to be able to service it.
		 */
		if (ev_nretries == SE_MAX_RETRY_LIMIT) {
			syslog(LOG_ERR, SYSEVENT_SEND_ERR,
				sep->se_conf_file, sep->se_lineno, errno);
		} else {
			syseventd_print(DBG_TEST, "%s event %lld: "
			    "'%s' '%s' '%s' '%s - errno %d, retry %d\n",
			    whoami, sysevent_get_seq(ev), vendor,
			    publisher, class, subclass, errno, ev_nretries);
		}
		ret = EAGAIN;
		ev_nretries++;
	}

	free(publisher);
	free(vendor);

	return (ret);
}

/*
 * syseventd daemon module initialization
 */
struct slm_mod_ops *
slm_init()
{
	char	lock_file[PATH_MAX+1];
	int	lock_fd;
	int	err;

	/*
	 * This functionality is not supported in the mini-root
	 * environment, ie install.  If root_dir is set, implying
	 * install, we quietly fail.  Return dummy ops rather
	 * than NULL to avoid error msgs out of syseventd.
	 */
	if (strcmp(root_dir, "") != 0) {
		return (&sysevent_conf_dummy_mod_ops);
	}

	ev_nretries = 0;
	first_event = 1;

	/*
	 * Initialize the channel to syseventconfd
	 */
	confd_handle = sysevent_open_channel_alt(SYSEVENTCONFD_SERVICE_DOOR);
	if (confd_handle == NULL) {
		syslog(LOG_ERR, CHANNEL_OPEN_ERR);
		return (NULL);
	}

	if (sysevent_bind_publisher(confd_handle) != 0) {
		if (errno == EBUSY) {
			sysevent_cleanup_publishers(confd_handle);
			if (sysevent_bind_publisher(confd_handle) != 0) {
				sysevent_close_channel(confd_handle);
				return (NULL);
			}
		}
	}

	sysevent_cleanup_subscribers(confd_handle);

	cmdq = NULL;
	cmdq_tail = NULL;
	cmdq_cnt = 0;
	want_fini = 0;
	confd_err_msg_emitted = 0;
	if (confd_state != CONFD_STATE_OK) {
		confd_state = CONFD_STATE_NOT_RUNNING;
	}

	confd_retries = 0;
	transport_retries = 0;

	(void) mutex_init(&cmdq_lock, USYNC_THREAD, NULL);
	(void) cond_init(&cmdq_cv, USYNC_THREAD, NULL);
	(void) cond_init(&cmdq_thr_cv, USYNC_THREAD, NULL);

	/*
	 * Create thread to flush cmd queue
	 */
	if ((err = thr_create(NULL, NULL, (void *(*)(void*))queue_flush_thr,
	    (void *)NULL, 0, &cmdq_thr_id)) != 0) {
		syslog(LOG_ERR, THR_CREATE_ERR, strerror(err));
		sysevent_close_channel(confd_handle);
		confd_handle = NULL;
		(void) mutex_destroy(&cmdq_lock);
		(void) cond_destroy(&cmdq_cv);
		(void) cond_destroy(&cmdq_thr_cv);
		return (NULL);
	}

	if ((lock_fd = enter_lock(lock_file)) == -1) {
		(void) thr_join(cmdq_thr_id, NULL, NULL);
		sysevent_close_channel(confd_handle);
		confd_handle = NULL;
		(void) mutex_destroy(&cmdq_lock);
		(void) cond_destroy(&cmdq_cv);
		(void) cond_destroy(&cmdq_thr_cv);
		return (NULL);
	}

	build_event_table();
	exit_lock(lock_fd, lock_file);
	return (&sysevent_conf_mod_ops);
}

/*
 * syseventd daemon module tear-down
 */
void
slm_fini()
{
	int	err;

	/*
	 * Nothing to clean up if we're in the install environment
	 */
	if (strcmp(root_dir, "") != 0) {
		return;
	}

	/*
	 * Wait for the queue to drain
	 */
	(void) mutex_lock(&cmdq_lock);
	want_fini = 1;
	(void) cond_signal(&cmdq_cv);
	(void) cond_wait(&cmdq_thr_cv, &cmdq_lock);
	(void) mutex_unlock(&cmdq_lock);

	/*
	 * Shut down the the queue flush thread
	 */
	if ((err = thr_join(cmdq_thr_id, NULL, NULL)) != 0) {
		syslog(LOG_ERR, THR_JOIN_ERR, strerror(err));
	}

	sysevent_close_channel(confd_handle);
	confd_handle = NULL;
	(void) mutex_destroy(&cmdq_lock);
	(void) cond_destroy(&cmdq_cv);
	(void) cond_destroy(&cmdq_thr_cv);
	free_event_table();
}

/*ARGSUSED*/
static int
sysevent_conf_dummy_event(sysevent_t *ev, int flag)
{
	return (0);
}
