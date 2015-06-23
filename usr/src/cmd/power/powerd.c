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

#include <stdio.h>			/* Standard */
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <dirent.h>
#include <thread.h>
#include <limits.h>
#include <sys/todio.h>			/* Time-Of-Day chip */
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/ipc.h>			/* IPC functions */
#include <signal.h>			/* signal handling */
#include <syslog.h>
#include <unistd.h>
#include <libdevinfo.h>
#include <poll.h>
#include <sys/pm.h>			/* power management driver */
#include <sys/uadmin.h>
#include <sys/openpromio.h>		/* for prom access */
#include <sys/sysmacros.h>		/* for MIN & MAX macros */
#include <sys/modctl.h>
#include <sys/stropts.h>		/* for INFTIM */
#include <sys/pbio.h>
#include <sys/cpr.h>
#include <sys/srn.h>
#include <stdarg.h>

#include "powerd.h"

/* External Functions */
extern struct tm *localtime_r(const time_t *, struct tm *);
extern void sysstat_init(void);
extern int check_tty(hrtime_t *, int);
extern int check_disks(hrtime_t *, int);
extern int check_load_ave(hrtime_t *, float);
extern int check_nfs(hrtime_t *, int);
extern int last_disk_activity(hrtime_t *, int);
extern int last_tty_activity(hrtime_t *, int);
extern int last_load_ave_activity(hrtime_t *);
extern int last_nfs_activity(hrtime_t *, int);

#define	PM		"/dev/pm"
#define	TOD		"/dev/tod"
#define	PROM		"/dev/openprom"
#define	PB		"/dev/power_button"
#define	SRN		"/dev/srn"
#define	LOGFILE		"./powerd.log"

#define	PBM_THREAD	0
#define	ATTACH_THREAD	1
#define	NUM_THREADS	2

#define	CHECK_INTERVAL	5
#define	IDLECHK_INTERVAL	15
#define	MINS_TO_SECS	60
#define	HOURS_TO_SECS	(60 * 60)
#define	DAYS_TO_SECS	(24 * 60 * 60)
#define	HOURS_TO_MINS	60
#define	DAYS_TO_MINS	(24 * 60)

#define	LIFETIME_SECS			(7 * 365 * DAYS_TO_SECS)
#define	DEFAULT_POWER_CYCLE_LIMIT	10000
#define	DEFAULT_SYSTEM_BOARD_DATE	804582000	/* July 1, 1995 */

#define	LLEN 80

typedef	enum {root, options} prom_node_t;

/* State Variables */
static struct cprconfig	asinfo;
static time_t		shutdown_time;	/* Time for next shutdown check */
static time_t		checkidle_time;	/* Time for next idleness check */
static time_t		last_resume;
pwr_info_t		*info;		/* private as config data buffer */
static int		pb_fd;		/* power button driver */
static int		broadcast;	/* Enables syslog messages */
static int		start_calc;
static int		autoshutdown_en;
static int		do_idlecheck;
static int		got_sighup;
static int		estar_v2_prop;
static int		estar_v3_prop;
static int		log_power_cycles_error = 0;
static int		log_system_board_date_error = 0;
static int		log_no_autoshutdown_warning = 0;
static mutex_t		poweroff_mutex;

static char *autoshutdown_cmd[] = {
	"/usr/bin/sys-suspend",
	"-n", "-d", ":0", NULL
};

static char *power_button_cmd[] = {
	"/usr/bin/sys-suspend",
	"-h", "-d", ":0", NULL
};

static char *autoS3_cmd[] = {
	"/usr/bin/sys-suspend",
	"-n", "-d", ":0", NULL
};

static char pidpath[] = PIDPATH;
static char scratch[PATH_MAX];
static char *prog;

/* Local Functions */
static void alarm_handler(int);
static void thaw_handler(int);
static void kill_handler(int);
static void work_handler(int);
static void check_shutdown(time_t *, hrtime_t *);
static void check_idleness(time_t *, hrtime_t *);
static int last_system_activity(hrtime_t *);
static int run_idlecheck(void);
static void set_alarm(time_t);
static int poweroff(const char *, char **);
static int is_ok2shutdown(time_t *);
static int get_prom(int, prom_node_t, char *, char *, size_t);
static void power_button_monitor(void *);
static int open_pidfile(char *);
static int write_pidfile(int, pid_t);
static int read_cpr_config(void);
static void system_activity_monitor(void);
static void autos3_monitor(void);
static void do_attach(void);
static void *attach_devices(void *);
static int powerd_debug;

/* PRINTFLIKE1 */
static void
logerror(const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (broadcast)
		vsyslog(LOG_ERR, fmt, args);
	va_end(args);
}


static void
estrcpy(char *dst, char *src, size_t dlen)
{
	size_t slen;

	slen = strlcpy(dst, src, dlen);
	if (slen >= dlen) {
		logerror("%s: string too long \"%s ...\"\n"
		    "(len %d, max %d)\n", prog, dst, slen, dlen - 1);
		exit(EXIT_FAILURE);
	}
}


int
main(int argc, char *argv[])
{
	pid_t		pid;
	int		pm_fd;
	struct sigaction act;
	sigset_t	sigmask;
	int		c;
	char		errmsg[PATH_MAX + 64];
	int		pid_fd;

	prog = argv[0];
	if (geteuid() != 0) {
		(void) fprintf(stderr, "%s: Must be root\n", prog);
		exit(EXIT_FAILURE);
	}

	if ((pid_fd = open_pidfile(prog)) ==  -1)
		exit(EXIT_FAILURE);

	/*
	 * Process options
	 */
	broadcast = 1;
	while ((c = getopt(argc, argv, "nd")) != EOF) {
		switch (c) {
		case 'd':
			powerd_debug = 1;
			break;
		case 'n':
			broadcast = 0;
			break;
		case '?':
			(void) fprintf(stderr, "Usage: %s [-n]\n", prog);
			exit(EXIT_FAILURE);
		}
	}

	pm_fd = open(PM, O_RDWR);
	if (pm_fd == -1) {
		(void) snprintf(errmsg, sizeof (errmsg), "%s: %s", prog, PM);
		perror(errmsg);
		exit(EXIT_FAILURE);
	}
	(void) close(pm_fd);

	/*
	 * Initialize mutex lock used to insure only one command to
	 * run at a time.
	 */
	if (mutex_init(&poweroff_mutex, USYNC_THREAD, NULL) != 0) {
		(void) fprintf(stderr,
		    "%s: Unable to initialize mutex lock\n", prog);
		exit(EXIT_FAILURE);
	}

	if ((info = (pwr_info_t *)malloc(sizeof (pwr_info_t))) == NULL) {
		(void) snprintf(errmsg, sizeof (errmsg), "%s: malloc", prog);
		perror(errmsg);
		exit(EXIT_FAILURE);
	}

	/*
	 * Daemon is set to go...
	 */
	if ((pid = fork()) < 0)
		exit(EXIT_FAILURE);
	else if (pid != 0)
		exit(EXIT_SUCCESS);

	pid = getpid();
	openlog(prog, 0, LOG_DAEMON);
	if (write_pidfile(pid_fd, pid) == -1)	/* logs errors on failure */
		exit(EXIT_FAILURE);
	(void) close(pid_fd);

	/*
	 * Close all the parent's file descriptors (Bug 1225843).
	 */
	closefrom(0);
	(void) setsid();
	(void) chdir("/");
	(void) umask(0);
#ifdef DEBUG
	/*
	 * Connect stdout to the console.
	 */
	if (dup2(open("/dev/console", O_WRONLY|O_NOCTTY), 1) == -1) {
		logerror("Unable to connect to the console.");
	}
#endif
	info->pd_flags = PD_AC;
	info->pd_idle_time = -1;
	info->pd_start_time = 0;
	info->pd_finish_time = 0;

	/*
	 * Allow SIGQUIT, SIGINT and SIGTERM signals to terminate us
	 * any time
	 */
	act.sa_handler = kill_handler;
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	(void) sigaction(SIGQUIT, &act, NULL);
	(void) sigaction(SIGINT, &act, NULL);
	(void) sigaction(SIGTERM, &act, NULL);

	(void) sigfillset(&sigmask);
	(void) sigdelset(&sigmask, SIGQUIT);
	(void) sigdelset(&sigmask, SIGINT);
	(void) sigdelset(&sigmask, SIGTERM);
	(void) thr_sigsetmask(SIG_SETMASK, &sigmask, NULL);

	/*
	 * If "power_button" device node can be opened, create a new
	 * thread to monitor the power button.
	 */
	if ((pb_fd = open(PB, O_RDONLY)) != -1) {
		if (powerd_debug)
			logerror("powerd starting power button monitor.");
		if (thr_create(NULL, NULL,
		    (void *(*)(void *))power_button_monitor, NULL,
		    THR_DAEMON, NULL) != 0) {
			logerror("Unable to monitor system's power button.");
		}
	}

	do_attach();

	/*
	 * Create a new thread to monitor system activity and suspend
	 * system if idle.
	 */
	if (powerd_debug)
		logerror("powerd starting system activity monitor.");
	if (thr_create(NULL, NULL,
	    (void *(*)(void *))system_activity_monitor, NULL,
	    THR_DAEMON, NULL) != 0) {
		logerror("Unable to create thread to monitor system activity.");
	}

	/*
	 * Create a new thread to handle autos3 trigger
	 */
	if (powerd_debug)
		logerror("powerd starting autos3 monitor.");
	if (thr_create(NULL, NULL,
	    (void *(*)(void *))autos3_monitor, NULL, THR_DAEMON, NULL) != 0) {
		logerror("Unable to create thread to monitor autos3 activity.");
	}

	/*
	 * Block until we receive an explicit terminate signal
	 */
	(void) sigsuspend(&sigmask);

	return (1);
}

static void
system_activity_monitor(void)
{
	struct sigaction act;
	sigset_t sigmask;

	/*
	 * Setup for gathering system's statistic.
	 */
	sysstat_init();

	/*
	 * In addition to the SIGQUIT, SIGINT and SIGTERM signals already
	 * being handled, this thread also needs to handle SIGHUP, SIGALRM
	 * and SIGTHAW signals.
	 */
	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = alarm_handler;
	(void) sigaction(SIGALRM, &act, NULL);
	act.sa_handler = work_handler;
	(void) sigaction(SIGHUP, &act, NULL);
	act.sa_handler = thaw_handler;
	(void) sigaction(SIGTHAW, &act, NULL);

	/*
	 * Invoke work_handler with a dummy SIGHUP signal to read
	 * cpr config file, get autoshutdown properties and schedule
	 * an alarm if needed.
	 */
	work_handler(SIGHUP);

	/*
	 * Wait for signal to read file
	 */
	(void) thr_sigsetmask(0, 0, &sigmask);
	(void) sigdelset(&sigmask, SIGHUP);
	(void) sigdelset(&sigmask, SIGALRM);
	(void) sigdelset(&sigmask, SIGTHAW);
	(void) thr_sigsetmask(SIG_SETMASK, &sigmask, NULL);
	do {
		(void) sigsuspend(&sigmask);
	} while (errno == EINTR);
}

static void
autos3_monitor(void)
{
	struct pollfd poll_fd;
	srn_event_info_t srn_event;		/* contains suspend type */
	int fd, ret;

	fd = open(SRN, O_RDWR|O_EXCL|O_NDELAY);
	if (fd == -1) {
		logerror("Unable to open %s: %s", SRN, strerror(errno));
		thr_exit((void *)(intptr_t)errno);
	}

	/*
	 * Tell device we want the special sauce
	 */
	ret = ioctl(fd, SRN_IOC_AUTOSX, NULL);
	if (ret == -1) {
		logerror("Ioctl SRN_IOC_AUTOSX failed: %s", strerror(errno));
		(void) close(fd);
		thr_exit((void *)(intptr_t)errno);
	}
	poll_fd.fd = fd;
	/*CONSTCOND*/
	while (1) {
		poll_fd.revents = 0;
		poll_fd.events = POLLIN;
		if (poll(&poll_fd, 1, -1) < 0) {
			switch (errno) {
			case EINTR:
			case EAGAIN:
				continue;
			default:
				logerror("Poll error: %s", strerror(errno));
				(void) close(fd);
				thr_exit((void *)(intptr_t)errno);
			}
		}

		ret = ioctl(fd, SRN_IOC_NEXTEVENT, &srn_event);
		if (ret == -1) {
			logerror("ioctl error: %s", strerror(errno));
			(void) close(fd);
			thr_exit((void *)(intptr_t)errno);
		}
		switch (srn_event.ae_type) {
		case 3:			/* S3 */
			if (powerd_debug)
				logerror("ioctl returns type: %d",
				    srn_event.ae_type);
			break;
		default:
			logerror("Unsupported target state %d",
			    srn_event.ae_type);
			continue;
		}
		(void) poweroff("AutoS3", autoS3_cmd);
		continue;
	}
}

static int
read_cpr_config(void)
{
	int	asfd;

	if ((asfd = open(CPR_CONFIG, O_RDONLY)) < 0) {
		logerror("Unable to open CPR config file '%s'", CPR_CONFIG);
		return (-1);
	}

	if (read(asfd, (void *)&asinfo, sizeof (asinfo)) != sizeof (asinfo)) {
		logerror("Unable to read CPR config file '%s'", CPR_CONFIG);
		(void) close(asfd);
		return (-1);
	}

	(void) close(asfd);

	return (0);
}

/*ARGSUSED*/
static void
thaw_handler(int sig)
{
	start_calc  = 0;
	last_resume = time(NULL);
}

/*ARGSUSED*/
static void
kill_handler(int sig)
{
	int ret_code = EXIT_SUCCESS;

	/*
	 * Free resources
	 */

	free(info);
	if (pb_fd != -1) {
		(void) close(pb_fd);
	}
	(void) mutex_destroy(&poweroff_mutex);
	(void) unlink(pidpath);
	closelog();
	exit(ret_code);
}

/*ARGSUSED*/
static void
alarm_handler(int sig)
{
	time_t		now;
	hrtime_t	hr_now;

	now = time(NULL);
	hr_now = gethrtime();
	if (checkidle_time <= now && checkidle_time != 0)
		check_idleness(&now, &hr_now);
	if (shutdown_time <= now && shutdown_time != 0)
		check_shutdown(&now, &hr_now);

	set_alarm(now);
}

/*ARGSUSED*/
static void
work_handler(int sig)
{
	time_t		now;
	hrtime_t	hr_now;
	struct stat	stat_buf;

	do_idlecheck = 0;
	info->pd_flags = PD_AC;

	/*
	 * Parse the config file for autoshutdown and idleness entries.
	 */
	if (read_cpr_config() < 0)
		return;

	/*
	 * Since Oct. 1, 1995, any new system shipped had root
	 * property "energystar-v2" defined in its prom.  Systems
	 * shipped after July 1, 1999, will have "energystar-v3"
	 * property.
	 */
	estar_v2_prop = asinfo.is_cpr_default;

	info->pd_flags |= asinfo.is_autowakeup_capable;

	if (strlen(asinfo.idlecheck_path) > 0) {
		if (stat(asinfo.idlecheck_path, &stat_buf) != 0) {
			logerror("unable to access idlecheck program \"%s\".",
			    asinfo.idlecheck_path);
		} else if (!(stat_buf.st_mode & S_IXUSR)) {
			logerror("idlecheck program \"%s\" is not executable.",
			    asinfo.idlecheck_path);
		} else {
			do_idlecheck = 1;
		}
	}

	if (strlen(asinfo.as_behavior) == 0 ||
	    strcmp(asinfo.as_behavior, "noshutdown") == 0 ||
	    strcmp(asinfo.as_behavior, "unconfigured") == 0) {
		info->pd_autoshutdown = 0;
	} else if (strcmp(asinfo.as_behavior, "default") == 0) {
		info->pd_autoshutdown = estar_v2_prop;
	} else if (strcmp(asinfo.as_behavior, "shutdown") == 0 ||
	    strcmp(asinfo.as_behavior, "autowakeup") == 0) {
		info->pd_autoshutdown = asinfo.is_cpr_capable;
	} else {
		logerror("autoshutdown behavior \"%s\" unrecognized.",
		    asinfo.as_behavior);
		info->pd_autoshutdown = 0;
	}

	if (info->pd_autoshutdown) {
		info->pd_idle_time = asinfo.as_idle;
		info->pd_start_time =
		    (asinfo.as_sh * 60 + asinfo.as_sm) % DAYS_TO_MINS;
		info->pd_finish_time =
		    (asinfo.as_fh * 60 + asinfo.as_fm) % DAYS_TO_MINS;
		info->pd_autoresume =
		    (strcmp(asinfo.as_behavior, "autowakeup") == 0) ? 1 : 0;
	}
	autoshutdown_en = (asinfo.as_idle >= 0 && info->pd_autoshutdown)
	    ? 1 : 0;

#ifdef DEBUG
	(void) fprintf(stderr, "autoshutdown_en = %d, as_idle = %d, "
	    "pd_autoresume = %d\n",
	    autoshutdown_en, asinfo.as_idle, info->pd_autoresume);

	(void) fprintf(stderr, " pd_start_time=%d, pd_finish_time=%d\n",
	    info->pd_start_time, info->pd_finish_time);
#endif

	got_sighup = 1;
	now = last_resume = time(NULL);
	hr_now = gethrtime();
	check_idleness(&now, &hr_now);
	check_shutdown(&now, &hr_now);
	set_alarm(now);
}

static void
check_shutdown(time_t *now, hrtime_t *hr_now)
{
	int		tod_fd = -1;
	int		kbd, mouse, system, least_idle, idlecheck_time;
	int		next_time;
	int		s, f;
	struct tm	tmp_time;
	time_t		start_of_day, time_since_last_resume;
	time_t		wakeup_time;
	extern long	conskbd_idle_time(void);
	extern long	consms_idle_time(void);
	static int	warned_kbd, warned_ms; /* print error msg one time */

	if (!autoshutdown_en) {
		shutdown_time = 0;
		return;
	}

	(void) localtime_r(now, &tmp_time);
	tmp_time.tm_sec = 0;
	tmp_time.tm_min = 0;
	tmp_time.tm_hour = 0;
	start_of_day = mktime(&tmp_time);
	s = start_of_day + info->pd_start_time * 60;
	f = start_of_day + info->pd_finish_time * 60;
	if ((s < f && *now >= s && *now < f) ||
	    (s >= f && (*now < f || *now >= s))) {
		if ((mouse = (int)consms_idle_time()) < 0) {
			if (! warned_ms) {
				warned_ms = 1;
				logerror("powerd: failed to get "
				    "idle time for console mouse");
			}
			return;
		}
		if ((kbd = (int)conskbd_idle_time()) < 0) {
			if (! warned_kbd) {
				warned_kbd = 1;
				logerror("powerd: failed to get "
				    "idle time for console keyboard");
			}
			return;
		}

		system = last_system_activity(hr_now);
		/* who is the last to go idle */
		least_idle = MIN(system, MIN(kbd, mouse));

		/*
		 * Calculate time_since_last_resume and the next_time
		 * to auto suspend.
		 */
		start_calc = 1;
		time_since_last_resume = time(NULL) - last_resume;
		next_time = info->pd_idle_time * 60 -
		    MIN(least_idle, time_since_last_resume);

#ifdef DEBUG
		fprintf(stderr, " check_shutdown: next_time=%d\n", next_time);
#endif

		/*
		 * If we have get the SIGTHAW signal at this point - our
		 * calculation of time_since_last_resume is wrong  so
		 * - we need to recalculate.
		 */
		while (start_calc == 0) {
			/* need to redo calculation */
			start_calc = 1;
			time_since_last_resume = time(NULL) - last_resume;
			next_time = info->pd_idle_time * 60 -
			    MIN(least_idle, time_since_last_resume);
		}

		/*
		 * Only when everything else is idle, run the user's idlecheck
		 * script.
		 */
		if (next_time <= 0 && do_idlecheck) {
			got_sighup = 0;
			idlecheck_time = run_idlecheck();
			next_time = info->pd_idle_time * 60 -
			    MIN(idlecheck_time, MIN(least_idle,
			    time_since_last_resume));
			/*
			 * If we have caught SIGTHAW or SIGHUP, need to
			 * recalculate.
			 */
			while (start_calc == 0 || got_sighup == 1) {
				start_calc = 1;
				got_sighup = 0;
				idlecheck_time = run_idlecheck();
				time_since_last_resume = time(NULL) -
				    last_resume;
				next_time = info->pd_idle_time * 60 -
				    MIN(idlecheck_time, MIN(least_idle,
				    time_since_last_resume));
			}
		}

		if (next_time <= 0) {
			if (is_ok2shutdown(now)) {
				/*
				 * Setup the autowakeup alarm.  Clear it
				 * right after poweroff, just in case if
				 * shutdown doesn't go through.
				 */
				if (info->pd_autoresume)
					tod_fd = open(TOD, O_RDWR);
				if (info->pd_autoresume && tod_fd != -1) {
					wakeup_time = (*now < f) ? f :
					    (f + DAYS_TO_SECS);
					/*
					 * A software fix for hardware
					 * bug 1217415.
					 */
					if ((wakeup_time - *now) < 180) {
						logerror(
		"Since autowakeup time is less than 3 minutes away, "
		"autoshutdown will not occur.");
						shutdown_time = *now + 180;
						(void) close(tod_fd);
						return;
					}
					if (ioctl(tod_fd, TOD_SET_ALARM,
					    &wakeup_time) == -1) {
						logerror("Unable to program TOD"
						    " alarm for autowakeup.");
						(void) close(tod_fd);
						return;
					}
				}

				(void) poweroff("Autoshutdown",
				    autoshutdown_cmd);

				if (info->pd_autoresume && tod_fd != -1) {
					if (ioctl(tod_fd, TOD_CLEAR_ALARM,
					    NULL) == -1)
						logerror("Unable to clear "
						    "alarm in TOD device.");
					(void) close(tod_fd);
				}

				(void) time(now);
				/* wait at least 5 mins */
				shutdown_time = *now +
				    ((info->pd_idle_time * 60) > 300 ?
				    (info->pd_idle_time * 60) : 300);
			} else {
				/* wait 5 mins */
				shutdown_time = *now + 300;
			}
		} else
			shutdown_time = *now + next_time;
	} else if (s < f && *now >= f) {
		shutdown_time = s + DAYS_TO_SECS;
	} else
		shutdown_time = s;
}

static int
is_ok2shutdown(time_t *now)
{
	int	prom_fd = -1;
	char	power_cycles_st[LLEN];
	char	power_cycle_limit_st[LLEN];
	char	system_board_date_st[LLEN];
	int	power_cycles, power_cycle_limit, free_cycles, scaled_cycles;
	time_t	life_began, life_passed;
	int	no_power_cycles = 0;
	int	no_system_board_date = 0;
	int	ret = 1;

	/* CONSTCOND */
	while (1) {
		if ((prom_fd = open(PROM, O_RDWR)) == -1 &&
		    (errno == EAGAIN))
			continue;
		break;
	}

	/*
	 * when #power-cycles property does not exist
	 * power cycles are unlimited.
	 */
	if (get_prom(prom_fd, options, "#power-cycles",
	    power_cycles_st, sizeof (power_cycles_st)) == 0)
		goto ckdone;

	if (get_prom(prom_fd, root, "power-cycle-limit",
	    power_cycle_limit_st, sizeof (power_cycle_limit_st)) == 0) {
		power_cycle_limit = DEFAULT_POWER_CYCLE_LIMIT;
	} else {
		power_cycle_limit = atoi(power_cycle_limit_st);
	}

	/*
	 * Allow 10% of power_cycle_limit as free cycles.
	 */
	free_cycles = power_cycle_limit / 10;

	power_cycles = atoi(power_cycles_st);
	if (power_cycles < 0)
		no_power_cycles++;
	else if (power_cycles <= free_cycles)
		goto ckdone;

	if (no_power_cycles && log_power_cycles_error == 0) {
		logerror("Invalid PROM property \"#power-cycles\" was found.");
		log_power_cycles_error++;
	}

	if (get_prom(prom_fd, options, "system-board-date",
	    system_board_date_st, sizeof (system_board_date_st)) == 0) {
		no_system_board_date++;
	} else {
		life_began = strtol(system_board_date_st, (char **)NULL, 16);
		if (life_began > *now) {
			no_system_board_date++;
		}
	}
	if (no_system_board_date) {
		if (log_system_board_date_error == 0) {
			logerror("No or invalid PROM property "
			    "\"system-board-date\" was found.");
			log_system_board_date_error++;
		}
		life_began = DEFAULT_SYSTEM_BOARD_DATE;
	}

	life_passed = *now - life_began;

	/*
	 * Since we don't keep the date that last free_cycle is ended, we
	 * need to spread (power_cycle_limit - free_cycles) over the entire
	 * 7-year life span instead of (lifetime - date free_cycles ended).
	 */
	scaled_cycles = (int)(((float)life_passed / (float)LIFETIME_SECS) *
	    (power_cycle_limit - free_cycles));

	if (no_power_cycles)
		goto ckdone;

#ifdef DEBUG
	(void) fprintf(stderr, "Actual power_cycles = %d\t"
	    "Scaled power_cycles = %d\n", power_cycles, scaled_cycles);
#endif
	if (power_cycles > scaled_cycles) {
		if (log_no_autoshutdown_warning == 0) {
			logerror("Automatic shutdown has been temporarily "
			    "suspended in order to preserve the reliability "
			    "of this system.");
			log_no_autoshutdown_warning++;
		}
		ret = 0;
		goto ckdone;
	}

ckdone:
	if (prom_fd != -1)
		(void) close(prom_fd);
	return (ret);
}

static void
check_idleness(time_t *now, hrtime_t *hr_now)
{

	/*
	 * Check idleness only when autoshutdown is enabled.
	 */
	if (!autoshutdown_en) {
		checkidle_time = 0;
		return;
	}

	info->pd_ttychars_idle = check_tty(hr_now, asinfo.ttychars_thold);
	info->pd_loadaverage_idle =
	    check_load_ave(hr_now, asinfo.loadaverage_thold);
	info->pd_diskreads_idle = check_disks(hr_now, asinfo.diskreads_thold);
	info->pd_nfsreqs_idle = check_nfs(hr_now, asinfo.nfsreqs_thold);

#ifdef DEBUG
	(void) fprintf(stderr, "Idle ttychars for %d secs.\n",
	    info->pd_ttychars_idle);
	(void) fprintf(stderr, "Idle loadaverage for %d secs.\n",
	    info->pd_loadaverage_idle);
	(void) fprintf(stderr, "Idle diskreads for %d secs.\n",
	    info->pd_diskreads_idle);
	(void) fprintf(stderr, "Idle nfsreqs for %d secs.\n",
	    info->pd_nfsreqs_idle);
#endif

	checkidle_time = *now + IDLECHK_INTERVAL;
}

static int
last_system_activity(hrtime_t *hr_now)
{
	int	act_idle, latest;

	latest = info->pd_idle_time * 60;
	act_idle = last_tty_activity(hr_now, asinfo.ttychars_thold);
	latest = MIN(latest, act_idle);
	act_idle = last_load_ave_activity(hr_now);
	latest = MIN(latest, act_idle);
	act_idle = last_disk_activity(hr_now, asinfo.diskreads_thold);
	latest = MIN(latest, act_idle);
	act_idle = last_nfs_activity(hr_now, asinfo.nfsreqs_thold);
	latest = MIN(latest, act_idle);

	return (latest);
}

static int
run_idlecheck()
{
	char		pm_variable[LLEN];
	char		*cp;
	int		status;
	pid_t		child;

	/*
	 * Reap any child process which has been left over.
	 */
	while (waitpid((pid_t)-1, &status, WNOHANG) > 0)
		;

	/*
	 * Execute the user's idlecheck script and set variable PM_IDLETIME.
	 * Returned exit value is the idle time in minutes.
	 */
	if ((child = fork1()) == 0) {
		(void) sprintf(pm_variable, "PM_IDLETIME=%d",
		    info->pd_idle_time);
		(void) putenv(pm_variable);
		cp = strrchr(asinfo.idlecheck_path, '/');
		if (cp == NULL)
			cp = asinfo.idlecheck_path;
		else
			cp++;
		(void) execl(asinfo.idlecheck_path, cp, NULL);
		exit(-1);
	} else if (child == -1) {
		return (info->pd_idle_time * 60);
	}

	/*
	 * Wait until the idlecheck program completes.
	 */
	if (waitpid(child, &status, 0) != child) {
		/*
		 * We get here if the calling process gets a signal.
		 */
		return (info->pd_idle_time * 60);
	}

	if (WEXITSTATUS(status) < 0) {
		return (info->pd_idle_time * 60);
	} else {
		return (WEXITSTATUS(status) * 60);
	}
}

static void
set_alarm(time_t now)
{
	time_t	itime, stime, next_time, max_time;
	int	next_alarm;

	max_time = MAX(checkidle_time, shutdown_time);
	if (max_time == 0) {
		(void) alarm(0);
		return;
	}
	itime = (checkidle_time == 0) ? max_time : checkidle_time;
	stime = (shutdown_time == 0) ? max_time : shutdown_time;
	next_time = MIN(itime, stime);
	next_alarm = (next_time <= now) ? 1 : (next_time - now);
	(void) alarm(next_alarm);

#ifdef DEBUG
	(void) fprintf(stderr, "Currently @ %s", ctime(&now));
	(void) fprintf(stderr, "Checkidle in %d secs\n", checkidle_time - now);
	(void) fprintf(stderr, "Shutdown  in %d secs\n", shutdown_time - now);
	(void) fprintf(stderr, "Next alarm goes off in %d secs\n", next_alarm);
	(void) fprintf(stderr, "************************************\n");
#endif
}

static int
poweroff(const char *msg, char **cmd_argv)
{
	struct stat	statbuf;
	pid_t		pid, child;
	struct passwd	*pwd;
	char		*home, *user;
	char		ehome[] = "HOME=";
	char		euser[] = "LOGNAME=";
	int		status;
	char		**ca;

	if (mutex_trylock(&poweroff_mutex) != 0)
		return (0);

	if (stat("/dev/console", &statbuf) == -1 ||
	    (pwd = getpwuid(statbuf.st_uid)) == NULL) {
		(void) mutex_unlock(&poweroff_mutex);
		return (1);
	}

	if (msg)
		syslog(LOG_NOTICE, msg);

	if (*cmd_argv == NULL) {
		logerror("No command to run.");
		(void) mutex_unlock(&poweroff_mutex);
		return (1);
	}

	home = malloc(strlen(pwd->pw_dir) + sizeof (ehome));
	user = malloc(strlen(pwd->pw_name) + sizeof (euser));
	if (home == NULL || user == NULL) {
		free(home);
		free(user);
		logerror("No memory.");
		(void) mutex_unlock(&poweroff_mutex);
		return (1);
	}
	(void) strcpy(home, ehome);
	(void) strcat(home, pwd->pw_dir);
	(void) strcpy(user, euser);
	(void) strcat(user, pwd->pw_name);

	/*
	 * Need to simulate the user enviroment, minimaly set HOME, and USER.
	 */
	if ((child = fork1()) == 0) {
		(void) putenv(home);
		(void) putenv(user);
		(void) setgid(pwd->pw_gid);
		(void) setuid(pwd->pw_uid);

		/*
		 * check for shutdown flag and set environment
		 */
		for (ca = cmd_argv; *ca; ca++) {
			if (strcmp("-h", *ca) == 0) {
				(void) putenv("SYSSUSPENDDODEFAULT=");
				break;
			}
		}

		(void) execv(cmd_argv[0], cmd_argv);
		exit(EXIT_FAILURE);
	} else {
		free(home);
		free(user);
		if (child == -1) {
			(void) mutex_unlock(&poweroff_mutex);
			return (1);
		}
	}
	pid = 0;
	while (pid != child)
		pid = wait(&status);
	if (WEXITSTATUS(status)) {
		(void) syslog(LOG_ERR, "Failed to exec \"%s\".", cmd_argv[0]);
		(void) mutex_unlock(&poweroff_mutex);
		return (1);
	}

	(void) mutex_unlock(&poweroff_mutex);
	return (0);
}

#define	PBUFSIZE	256

/*
 * Gets the value of a prom property at either root or options node.  It
 * returns 1 if it is successful, otherwise it returns 0 .
 */
static int
get_prom(int prom_fd, prom_node_t node_name,
	char *property_name, char *property_value, size_t len)
{
	union {
		char buf[PBUFSIZE + sizeof (uint_t)];
		struct openpromio opp;
	} oppbuf;
	register struct openpromio *opp = &(oppbuf.opp);
	int	got_it = 0;

	if (prom_fd == -1) {
		return (0);
	}

	switch (node_name) {
	case root:
		(void *) memset(oppbuf.buf, 0, PBUFSIZE);
		opp->oprom_size = PBUFSIZE;
		if (ioctl(prom_fd, OPROMNEXT, opp) < 0) {
			return (0);
		}

		/*
		 * Passing null string will give us the first property.
		 */
		(void *) memset(oppbuf.buf, 0, PBUFSIZE);
		do {
			opp->oprom_size = PBUFSIZE;
			if (ioctl(prom_fd, OPROMNXTPROP, opp) < 0) {
				return (0);
			}
			if (strcmp(opp->oprom_array, property_name) == 0) {
				got_it++;
				break;
			}
		} while (opp->oprom_size > 0);

		if (!got_it) {
			return (0);
		}
		if (got_it && property_value == NULL) {
			return (1);
		}
		opp->oprom_size = PBUFSIZE;
		if (ioctl(prom_fd, OPROMGETPROP, opp) < 0) {
			return (0);
		}
		if (opp->oprom_size == 0) {
			*property_value = '\0';
		} else {
			estrcpy(property_value, opp->oprom_array, len);
		}
		break;
	case options:
		estrcpy(opp->oprom_array, property_name, PBUFSIZE);
		opp->oprom_size = PBUFSIZE;
		if (ioctl(prom_fd, OPROMGETOPT, opp) < 0) {
			return (0);
		}
		if (opp->oprom_size == 0) {
			return (0);
		}
		if (property_value != NULL) {
			estrcpy(property_value, opp->oprom_array, len);
		}
		break;
	default:
		logerror("Only root node and options node are supported.\n");
		return (0);
	}

	return (1);
}

#define	isspace(ch)	((ch) == ' ' || (ch) == '\t')
#define	iseol(ch)	((ch) == '\n' || (ch) == '\r' || (ch) == '\f')

/*ARGSUSED*/
static void
power_button_monitor(void *arg)
{
	struct pollfd pfd;
	int events, ret;

	if (ioctl(pb_fd, PB_BEGIN_MONITOR, NULL) == -1) {
		logerror("Failed to monitor the power button.");
		thr_exit((void *) 0);
	}

	pfd.fd = pb_fd;
	pfd.events = POLLIN;

	/*CONSTCOND*/
	while (1) {
		if (poll(&pfd, 1, INFTIM) == -1) {
			logerror("Failed to poll for power button events.");
			thr_exit((void *) 0);
		}

		if (!(pfd.revents & POLLIN))
			continue;

		/*
		 * Monitor the power button, but only take action if
		 * gnome-power-manager is not running.
		 *
		 * ret greater than 0 means could not find process.
		 */
		ret = system("/usr/bin/pgrep -fx gnome-power-manager");

		if (ioctl(pfd.fd, PB_GET_EVENTS, &events) == -1) {
			logerror("Failed to get power button events.");
			thr_exit((void *) 0);
		}

		if ((ret > 0) && (events & PB_BUTTON_PRESS) &&
		    (poweroff(NULL, power_button_cmd) != 0)) {
			logerror("Power button is pressed, powering "
			    "down the system!");

			/*
			 * Send SIGPWR signal to the init process to
			 * shut down the system.
			 */
			if (kill(1, SIGPWR) == -1)
				(void) uadmin(A_SHUTDOWN, AD_POWEROFF, 0);
		}

		/*
		 * Clear any power button event that has happened
		 * meanwhile we were busy processing the last one.
		 */
		if (ioctl(pfd.fd, PB_GET_EVENTS, &events) == -1) {
			logerror("Failed to get power button events.");
			thr_exit((void *) 0);
		}
	}
}

static void
do_attach(void)
{
	if (read_cpr_config() < 0)
		return;

	/*
	 * If autopm behavior is explicitly enabled for energystar-v2, or
	 * set to default for energystar-v3, create a new thread to attach
	 * all devices.
	 */
	estar_v3_prop = asinfo.is_autopm_default;
	if ((strcmp(asinfo.apm_behavior, "enable") == 0) ||
	    (estar_v3_prop && strcmp(asinfo.apm_behavior, "default") == 0)) {
		if (powerd_debug)
			logerror("powerd starting device attach thread.");
		if (thr_create(NULL, NULL, attach_devices, NULL,
		    THR_DAEMON, NULL) != 0) {
			logerror("Unable to create thread to attach devices.");
		}
	}
}

/*ARGSUSED*/
static void *
attach_devices(void *arg)
{
	di_node_t root_node;

	(void) sleep(60);	/* let booting finish first */

	if ((root_node = di_init("/", DINFOFORCE)) == DI_NODE_NIL) {
		logerror("Failed to attach devices.");
		return (NULL);
	}
	di_fini(root_node);

	/*
	 * Unload all the modules.
	 */
	(void) modctl(MODUNLOAD, 0);

	return (NULL);
}


/*
 * Create a file which will contain our pid.  Pmconfig will check this file
 * to see if we are running and can use the pid to signal us.  Returns the
 * file descriptor if successful, -1 otherwise.
 *
 * Note: Deal with attempt to launch multiple instances and also with existence
 * of an obsolete pid file caused by an earlier abort.
 */
static int
open_pidfile(char *me)
{
	int fd;
	const char *e1 = "%s: Cannot open pid file for read: ";
	const char *e2 = "%s: Cannot unlink obsolete pid file: ";
	const char *e3 = "%s: Either another daemon is running or the"
	    " process is defunct (pid %d). \n";
	const char *e4 = "%s: Cannot create pid file: ";

again:
	if ((fd = open(pidpath, O_CREAT | O_EXCL | O_WRONLY, 0444)) == -1) {
		if (errno  == EEXIST) {
			FILE *fp;
			pid_t pid;

			if ((fp = fopen(pidpath, "r")) == NULL) {
				(void) fprintf(stderr, e1, me);
				perror(NULL);
				return (-1);
			}

			/* Read the pid */
			pid = (pid_t)-1;
			(void) fscanf(fp, "%ld", &pid);
			(void) fclose(fp);
			if (pid == -1) {
				if (unlink(pidpath) == -1) {
					(void) fprintf(stderr, e2, me);
					perror(NULL);
					return (-1);
				} else /* try without corrupted file */
					goto again;
			}

			/* Is pid for a running process */
			if (kill(pid, 0) == -1) {
				if (errno == ESRCH) {
					if (unlink(pidpath) == -1) {
						(void) fprintf(stderr, e2, me);
						perror(NULL);
						return (-1);
					} else	/* try without obsolete file */
						goto again;
				}
			} else {    /* powerd deamon still running or defunct */
				(void) fprintf(stderr, e3, me, pid);
				return (-1);
			}

		} else {	/* create failure not due to existing file */
			(void) fprintf(stderr, e4, me);
			perror(NULL);
			return (-1);
		}
	}

	(void) fchown(fd, (uid_t)-1, (gid_t)0);
	return (fd);
}

/*
 * Write a pid to the pid file.  Report errors to syslog.
 *
 */
static int
write_pidfile(int fd, pid_t pid)
{
	int	len;
	int	rc = 0;			/* assume success */

	len = sprintf(scratch, "%ld\n", pid);
	if (write(fd, scratch, len) != len) {
		logerror("Cannot write pid file: %s", strerror(errno));
		rc = -1;
	}

	return (rc);
}
