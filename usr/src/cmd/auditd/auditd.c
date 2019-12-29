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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* Audit daemon server */
/*
 * These routines make up the audit daemon server.  This daemon, called
 * auditd, handles the user level parts of auditing.  It receives buffered
 * audit records (usually one or more per buffer, potentially less than
 * one) and passes them to one or more plugins for processing.
 *
 * The major interrupts are SIGHUP (start over), SIGTERM (start shutting down),
 * SIGALRM (quit), and SIGUSR1 (start a new audit log file). SIGTERM is also
 * used for the child to tell the parent that audit is ready.
 *
 * Configuration data comes from audit service configuration
 * (AUDITD_FMRI/smf(5)) and the auditon system call.
 *
 * The major errors are EBUSY (auditing is already in use) and EINTR
 * (one of the above signals was received).  File space errors are
 * handled by the audit_binfile plugin
 */

/* #define	DEBUG    - define for debug messages to be generated */
/* #define	MEM_TEST - define to generate core dump on exit */
#define	DEBUG		0
#define	MEM_TEST	0

#include <assert.h>
#include <bsm/adt.h>
#include <bsm/audit.h>
#include <bsm/audit_record.h>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <libintl.h>
#include <locale.h>
#include <netdb.h>
#include <pwd.h>
#include <secdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>
#include "plugin.h"
#include <audit_plugin.h>
#include <audit_scf.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif
/*
 * After we get a SIGTERM, we want to set a timer for 2 seconds
 * and let c2audit write as many records as it can until the timer
 * goes off (at which point it returns to auditd with SIGALRM).
 * If any other signals are received during that time, we call
 * __audit_dowarn() to indicate that the queue may not have been fully
 * flushed.
 */
#define	ALRM_TIME	2
#define	SLEEP_TIME	20	/* # of seconds to sleep in all hard loop */

static plugin_t	*binfile = NULL;

static int	turn_audit_on  = AUC_AUDITING;
static int	turn_audit_off = AUC_NOAUDIT;

static int	running = 1;

/*
 * GLOBALS:
 */
plugin_t		*plugin_head = NULL;
static thr_data_t	main_thr;	/* auditd thread (0) */
pthread_mutex_t		plugin_mutex;	/* for plugin_t list */

static int	caught_alrm = 0;	/* number of SIGALRMs pending */
static int	caught_readc = 0;	/* number of SIGHUPs pending */
static int	caught_term = 0;	/* number of SIGTERMs pending */
static int	caught_nextd = 0;	/* number of SIGUSR1s pending */

static int	reset_list = 1;	/* 1 to re-read audit configuration */
static int	reset_file = 1; /* 1 to close/open binary log */

static int	auditing_set = 0;	/* 1 if auditon(A_SETCOND, on... */

static void	my_sleep();
static void	*signal_thread(void *);
static void	loadauditlist();
static void	block_signals();
static int	do_sethost();

static void	conf_to_kernel();
static void	scf_to_kernel_qctrl();
static void	scf_to_kernel_policy();

/*
 * err_exit() - exit function after the unsuccessful call to auditon();
 * prints_out / saves_via_syslog the necessary error messages.
 */
static void
err_exit(char *msg)
{
	if (msg != NULL) {
		DPRINT((dbfp, "%s\n", msg));
		__audit_syslog("auditd", LOG_PID | LOG_CONS | LOG_NOWAIT,
		    LOG_DAEMON, LOG_ALERT, msg);
		free(msg);
	} else {
		DPRINT((dbfp, "the memory allocation failed\n"));
		__audit_syslog("auditd", LOG_PID | LOG_CONS | LOG_NOWAIT,
		    LOG_DAEMON, LOG_ALERT, gettext("no memory"));
	}
	auditd_thread_close();
	auditd_exit(1);
}

/* common exit function */
void
auditd_exit(int status)
{
#if MEM_TEST
	DPRINT((dbfp, "mem_test intentional abort (status=%d)\n",
	    status));
	abort();
#endif
	DPRINT((dbfp, "%ld exit status = %d auditing_set = %d\n",
	    getpid(), status, auditing_set));

	if (auditing_set)
		(void) auditon(A_SETCOND, (caddr_t)&turn_audit_off,
		    sizeof (int));

#if DEBUG
	(void) fclose(dbfp);
#endif

	exit(status);
}

/* ARGSUSED */
int
main(int argc, char *argv[])
{
	auditinfo_addr_t	as_null;	/* audit state to set */
	au_id_t			auid;
	pthread_t		tid;
	plugin_t		*p;
	pid_t			pid;

#if DEBUG
#if MEM_TEST
	char	*envp;
#endif
	if (dbfp == NULL) {
		dbfp = __auditd_debug_file_open();
	}
#endif
	(void) setsid();

	/* Internationalization */
	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	/*
	 * Set the audit host-id.
	 */
	if (do_sethost() != 0) {
		__audit_dowarn("nostart", "", 0);
		auditd_exit(1);
	}

	/*
	 * Turn off all auditing for this process.
	 */
	if (getaudit_addr(&as_null, sizeof (as_null)) == -1) {
		__audit_dowarn("nostart", "", 0);
		auditd_exit(1);
	}
	as_null.ai_mask.as_success = 0;
	as_null.ai_mask.as_failure = 0;
	(void) setaudit_addr(&as_null, sizeof (as_null));
	auid = AU_NOAUDITID;
	(void) setauid(&auid);
	/*
	 * Set the audit state flag to AUDITING.
	 */
	if (auditon(A_SETCOND, (caddr_t)&turn_audit_on, sizeof (int)) !=
	    0) {
		DPRINT((dbfp, "auditon(A_SETCOND...) failed (exit)\n"));
		__audit_dowarn("nostart", "", 0);
		auditd_exit(1);
	}

	block_signals();

	/*
	 * wait for "ready" signal before exit -- for greenline
	 */
	if (fork()) {
		sigset_t	set;
		int		signal_caught = 0;

		(void) sigemptyset(&set);
		(void) sigaddset(&set, SIGTERM);

		while (signal_caught != SIGTERM)
			signal_caught = sigwait(&set);

		DPRINT((dbfp, "init complete:  parent can now exit\n"));

		auditd_exit(0);
	}
	pid = getppid();

	auditing_set = 1;

#if DEBUG && MEM_TEST
	envp = getenv("UMEM_DEBUG");
	if (envp != NULL)
		DPRINT((dbfp, "UMEM_DEBUG=%s\n", envp));
	envp = getenv("UMEM_LOGGING");
	if (envp != NULL)
		DPRINT((dbfp, "UMEM_LOGGING=%s\n", envp));
#endif
	DPRINT((dbfp, "auditd pid=%ld\n", getpid()));

	/* thread 0 sync */
	(void) pthread_mutex_init(&(main_thr.thd_mutex), NULL);
	(void) pthread_cond_init(&(main_thr.thd_cv), NULL);
	(void) pthread_mutex_init(&plugin_mutex, NULL);
	/*
	 * Set up a separate thread for signal handling.
	 */
	if (pthread_create(&tid, NULL, signal_thread, NULL)) {
		(void) fprintf(stderr, gettext(
		    "auditd can't create a thread\n"));
		auditd_exit(1);
	}
	/*
	 * Set the umask so that only audit or other users in the audit group
	 * can get to the files created by auditd.
	 */
	(void) umask(007);

	if (__logpost("")) {	/* Cannot unlink pointer to audit.log(4) file */
		DPRINT((dbfp, "logpost failed\n"));
		auditd_exit(1);
	}
	/*
	 * Here is the main body of the audit daemon. running == 0 means that
	 * after flushing out the audit queue, it is time to exit in response
	 * to SIGTERM.
	 */
	while (running) {
		/*
		 * Read auditd / auditd plugins related configuration from
		 * smf(5) repository and create plugin lists.
		 *
		 * loadauditlist() and auditd_thread_init() are called
		 * while under the plugin_mutex lock to avoid a race
		 * with unload_plugin().
		 */
		if (reset_list || reset_file) {
			if (reset_list) {
				conf_to_kernel();
				scf_to_kernel_qctrl();
				scf_to_kernel_policy();
				(void) pthread_mutex_lock(&plugin_mutex);
				loadauditlist();
			} else {
				(void) pthread_mutex_lock(&plugin_mutex);
			}

			if (auditd_thread_init()) {
				auditd_thread_close();
				/* continue; wait for audit -s */
			}
			(void) pthread_mutex_unlock(&plugin_mutex);

			if (reset_list && reset_file) {
				(void) printf(gettext("auditd started\n"));
			} else {
				(void) printf(gettext("auditd refreshed\n"));
			}

			reset_list = 0;
			reset_file = 0;
		}
		/*
		 * tell parent I'm running whether or not the initialization
		 * actually worked.  The failure case is to wait for an
		 * audit -n or audit -s to fix the problem.
		 */
		if (pid != 0) {
			(void) kill(pid, SIGTERM);
			pid = 0;
		}
		/*
		 * thread_signal() signals main (this thread) when
		 * it has received a signal.
		 */
		DPRINT((dbfp, "main thread is waiting for signal\n"));
		(void) pthread_mutex_lock(&(main_thr.thd_mutex));

		if (!(caught_readc || caught_term || caught_alrm ||
		    caught_nextd))
			(void) pthread_cond_wait(&(main_thr.thd_cv),
			    &(main_thr.thd_mutex));
		(void) pthread_mutex_unlock(&(main_thr.thd_mutex));
		/*
		 * Got here because a signal came in.
		 * Since we may have gotten more than one, we assume a
		 * priority scheme with SIGALRM being the most
		 * significant.
		 */
		if (caught_alrm) {
			/*
			 * We have returned from our timed wait for
			 * c2audit to calm down.  We need to really shut
			 * down here.
			 */
			caught_alrm = 0;
			running = 0;	/* shut down now */
		} else if (caught_term) {
			/*
			 * we are going to shut down, but need to
			 * allow time for the audit queues in
			 * c2audit and for the threads to empty.
			 */

			p = plugin_head;
			while (p != NULL) {
				DPRINT((dbfp, "signalling thread %d\n",
				    p->plg_tid));
				(void) pthread_mutex_lock(&(p->plg_mutex));
				p->plg_removed = 1;

				if (p->plg_initialized)
					(void) pthread_cond_signal(
					    &(p->plg_cv));

				(void) pthread_mutex_unlock(&(p->plg_mutex));
				p = p->plg_next;
			}

			caught_alrm = 0;
			caught_readc  = 0;
			caught_term = 0;
			caught_nextd = 0;

			DPRINT((dbfp,
			    "main thread is pausing before exit.\n"));
			(void) pthread_mutex_lock(&(main_thr.thd_mutex));
			caught_alrm = 0;
			(void) alarm(ALRM_TIME);
			while (!caught_alrm)
				(void) pthread_cond_wait(&(main_thr.thd_cv),
				    &(main_thr.thd_mutex));

			(void) pthread_mutex_unlock(&(main_thr.thd_mutex));

			running = 0;	/* Close down auditing and exit */
		} else if (caught_readc) {
			/*
			 * if both hup and usr1 are caught, the logic in
			 * loadauditlist() results in hup winning.  The
			 * result will be that the audit file is not rolled
			 * over unless audit configuration actually changed.
			 *
			 * They want to reread the audit configuration from
			 * smf(5) repository (AUDITD_FMRI). Set reset_list
			 * which will return us to the main while loop in the
			 * main routine.
			 */
			caught_readc = 0;
			reset_list = 1;
		} else if (caught_nextd) {
			/*
			 * This is a special case for the binfile plugin.
			 * (audit -n)  NULL out kvlist so binfile won't
			 * re-read audit configuration.
			 */
			caught_nextd = 0;
			reset_file = 1;
			if (binfile != NULL) {
				_kva_free(binfile->plg_kvlist);
				binfile->plg_kvlist = NULL;
				binfile->plg_reopen = 1;
			}
		}
	}	/* end while (running) */
	auditd_thread_close();

	auditd_exit(0);
	return (0);
}

/*
 * my_sleep - sleep for SLEEP_TIME seconds but only accept the signals
 *	that we want to accept.  (Premature termination just means the
 *	caller retries more often, not a big deal.)
 */

static void
my_sleep()
{
	DPRINT((dbfp, "auditd: sleeping for 20 seconds\n"));
	/*
	 * Set timer to "sleep"
	 */
	(void) alarm(SLEEP_TIME);

	DPRINT((dbfp, "main thread is waiting for SIGALRM before exit.\n"));
	(void) pthread_mutex_lock(&(main_thr.thd_mutex));
	(void) pthread_cond_wait(&(main_thr.thd_cv), &(main_thr.thd_mutex));
	(void) pthread_mutex_unlock(&(main_thr.thd_mutex));

	if (caught_term) {
		DPRINT((dbfp, "normal SIGTERM exit\n"));
		/*
		 * Exit, as requested.
		 */
		auditd_thread_close();
	}
	if (caught_readc)
		reset_list = 1;		/* Reread the audit configuration */

	caught_readc = 0;
	caught_nextd = 0;
}

/*
 * search for $ISA/ in path and replace it with "" if auditd
 * is 32 bit, else "sparcv9/"  The plugin $ISA must match however
 * auditd was compiled.
 */

static void
isa_ified(char *path, char **newpath)
{
	char	*p, *q;

	if (((p = strchr(path, '$')) != NULL) &&
	    (strncmp("$ISA/", p, 5) == 0)) {
		(void) memcpy(*newpath, path, p - path);
		q = *newpath + (p - path);
#ifdef __sparcv9
		q += strlcpy(q, "sparcv9/", avail_length);
#endif
		(void) strcpy(q, p + 5);
	} else
		*newpath = path;
}

/*
 * init_plugin first searches the existing plugin list to see if the plugin
 * already has been defined; if not, it creates it and links it into the list.
 * It returns a pointer to the found or created struct. Note, that
 * (manual/unsupported) change of path property in audit service configuration
 * for given plugin will cause a miss.
 */
/*
 * for 64 bits, the path name can grow 3 bytes (minus 5 for the
 * removed "$ISA" and plus 8 for the added "sparcv9/"
 */

#define	ISA_GROW	8 - 5

static plugin_t *
init_plugin(char *name, kva_t *list, int cnt_flag)
{
	plugin_t	*p, *q;
	char		filepath[MAXPATHLEN + 1 + ISA_GROW];
	char		*path = filepath;

	if (*name != '/') {
#ifdef  __sparcv9
		(void) strcpy(filepath, "/usr/lib/security/sparcv9/");
#else
		(void) strcpy(filepath, "/usr/lib/security/");
#endif
		if (strlcat(filepath, name, MAXPATHLEN) >= MAXPATHLEN)
			return (NULL);
	} else {
		if (strlen(name) > MAXPATHLEN + ISA_GROW)
			return (NULL);
		isa_ified(name, &path);
	}
	p = plugin_head;
	q = plugin_head;
	while (p != NULL) {
		if (p->plg_path != NULL) {
			if (strcmp(p->plg_path, path) == 0) {
				p->plg_removed = 0;
				p->plg_to_be_removed = 0;
				p->plg_cnt = cnt_flag;

				_kva_free(p->plg_kvlist);
				p->plg_kvlist = _kva_dup(list);
				if (list != NULL && p->plg_kvlist == NULL) {
					err_exit(NULL);
				}
				p->plg_reopen = 1;
				DPRINT((dbfp, "reusing %s\n", p->plg_path));
				return (p);
			}
		}
		q = p;
		p = p->plg_next;
	}
	DPRINT((dbfp, "creating new plugin structure for %s\n", path));

	p = malloc(sizeof (plugin_t));

	if (p == NULL) {
		perror("auditd");
		return (NULL);
	}
	if (q == NULL)
		plugin_head = p;
	else
		q->plg_next = p;

	p->plg_next = NULL;
	p->plg_initialized = 0;
	p->plg_reopen = 1;
	p->plg_tid = 0;
	p->plg_removed = 0;
	p->plg_to_be_removed = 0;
	p->plg_tossed = 0;
	p->plg_queued = 0;
	p->plg_output = 0;
	p->plg_sequence = 1;
	p->plg_last_seq_out = 0;
	p->plg_path = strdup(path);
	p->plg_kvlist = _kva_dup(list);
	p->plg_cnt = cnt_flag;
	p->plg_retry_time = SLEEP_TIME;
	p->plg_qmax = 0;
	p->plg_save_q_copy = NULL;

	if (list != NULL && p->plg_kvlist == NULL || p->plg_path == NULL) {
		err_exit(NULL);
	}

	DPRINT((dbfp, "created plugin:  %s\n", path));
	return (p);
}

/*
 * loadauditlist() - read the auditd plugin configuration from smf(5) and
 * prepare appropriate plugin related structures (plugin_t). Set cnt policy here
 * based on currently active policy settings. (future could have a policy =
 * {+|-}cnt entry per plugin with auditconfig providing the default)
 */
static void
loadauditlist()
{
	char			*value;
	char			*endptr;
	plugin_t		*p;
	uint32_t		policy;
	int			cnt_flag;
	struct au_qctrl		kqmax;
	scf_plugin_kva_node_t	*plugin_kva_ll;
	scf_plugin_kva_node_t	*plugin_kva_ll_head;

	if (auditon(A_GETPOLICY, (char *)&policy, 0) == -1) {
		DPRINT((dbfp, "auditon(A_GETPOLICY...) failed (exit)\n"));
		__audit_dowarn("auditoff", "", 0);
		auditd_thread_close();
		auditd_exit(1);
	}
	cnt_flag = ((policy & AUDIT_CNT) != 0) ? 1 : 0;
	DPRINT((dbfp, "loadauditlist: policy is to %s\n", (cnt_flag == 1) ?
	    "continue" : "block"));

#if DEBUG
	{
		int	acresult;
		if (auditon(A_GETCOND, (caddr_t)&acresult, sizeof (int)) != 0) {
			DPRINT((dbfp, "auditon(A_GETCOND...) failed (exit)\n"));
		}
		DPRINT((dbfp, "audit cond = %d (1 is on)\n", acresult));
	}
#endif


	if (auditon(A_GETQCTRL, (char *)&kqmax, sizeof (struct au_qctrl)) !=
	    0) {
		DPRINT((dbfp, "auditon(A_GETQCTRL...) failed (exit)\n"));
		__audit_dowarn("auditoff", "", 0);
		auditd_thread_close();
		auditd_exit(1);
	}
	kqmax.aq_hiwater *= 5;		/* RAM is cheaper in userspace */
	DPRINT((dbfp, "auditd: reading audit configuration\n"));

	p = plugin_head;
	/*
	 * two-step on setting p->plg_removed because the input thread
	 * in doorway.c uses p->plg_removed to decide if the plugin is
	 * active.
	 */
	while (p != NULL) {
		DPRINT((dbfp, "loadauditlist: %p, %s previously created\n",
		    (void *)p, p->plg_path));
		p->plg_to_be_removed = 1;	/* tentative removal */
		p = p->plg_next;
	}

	if (!do_getpluginconfig_scf(NULL, &plugin_kva_ll)) {
		DPRINT((dbfp, "Could not get plugin configuration.\n"));
		auditd_thread_close();
		auditd_exit(1);
	}
	plugin_kva_ll_head = plugin_kva_ll;

	while (plugin_kva_ll != NULL) {
		DPRINT((dbfp, "loadauditlist: starting with %s",
		    plugin_kva_ll->plugin_name));

		/* skip inactive plugins */
		value = kva_match(plugin_kva_ll->plugin_kva, PLUGIN_ACTIVE);
		if (strcmp(value, "1") != 0) {
			DPRINT((dbfp, " (inactive:%s) skipping..\n", value));
			plugin_kva_ll = plugin_kva_ll->next;
			continue;
		}
		DPRINT((dbfp, " (active)\n"));

		value = kva_match(plugin_kva_ll->plugin_kva, PLUGIN_PATH);
		DPRINT((dbfp, "loadauditlist: have an entry for %s (%s)\n",
		    plugin_kva_ll->plugin_name, value));

		p = init_plugin(value, plugin_kva_ll->plugin_kva, cnt_flag);
		if (p == NULL) {
			DPRINT((dbfp, "Unsuccessful plugin_t "
			    "initialization.\n"));
			my_sleep();
			continue;
		}

		if (strcmp(plugin_kva_ll->plugin_name, "audit_binfile") == 0) {
			binfile = p;
		}

		p->plg_qmax = kqmax.aq_hiwater; /* default */
		value = kva_match(plugin_kva_ll->plugin_kva, PLUGIN_QSIZE);
		if (value != NULL) {
			long	tmp;
			tmp = strtol(value, &endptr, 10);
			if (*endptr == '\0' && tmp != 0) {
				p->plg_qmax = tmp;
			}
		}
		DPRINT((dbfp, "%s queue max = %d\n", p->plg_path, p->plg_qmax));

		plugin_kva_ll = plugin_kva_ll->next;
	}

	p = plugin_head;
	while (p != NULL) {
		DPRINT((dbfp, "loadauditlist: %s remove flag=%d; cnt=%d\n",
		    p->plg_path, p->plg_to_be_removed, p->plg_cnt));
		p->plg_removed = p->plg_to_be_removed;
		p = p->plg_next;
	}

	plugin_kva_ll_free(plugin_kva_ll_head);
}

/*
 * block signals -- thread-specific blocking of the signals expected
 * by the main thread.
 */

static void
block_signals()
{
	sigset_t	set;

	(void) sigfillset(&set);
	(void) pthread_sigmask(SIG_BLOCK, &set, NULL);
}

/*
 * signal_thread is the designated signal catcher.  It wakes up the
 * main thread whenever it receives a signal and then goes back to
 * sleep; it does not exit.  The global variables caught_* let
 * the main thread which signal was received.
 *
 * The thread is created with all signals blocked.
 */

static void *
signal_thread(void *arg __unused)
{
	sigset_t	set;
	int		signal_caught;

	DPRINT((dbfp, "the signal thread is thread %d\n",
	    pthread_self()));

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) sigaddset(&set, SIGTERM);
	(void) sigaddset(&set, SIGHUP);
	(void) sigaddset(&set, SIGUSR1);

	for (;;) {
		signal_caught = sigwait(&set);
		switch (signal_caught) {
		case SIGALRM:
			caught_alrm++;
			DPRINT((dbfp, "caught SIGALRM\n"));
			break;
		case SIGTERM:
			caught_term++;
			DPRINT((dbfp, "caught SIGTERM\n"));
			break;
		case SIGHUP:
			caught_readc++;
			DPRINT((dbfp, "caught SIGHUP\n"));
			break;
		case SIGUSR1:
			caught_nextd++;
			DPRINT((dbfp, "caught SIGUSR1\n"));
			break;
		default:
			DPRINT((dbfp, "caught unexpected signal:  %d\n",
			    signal_caught));
			break;
		}
		(void) pthread_cond_signal(&(main_thr.thd_cv));
	}
	return (NULL);
}

/*
 * do_sethost - do auditon(2) to set the audit host-id.
 *		Returns 0 if success or -1 otherwise.
 */
static int
do_sethost(void)
{
	au_tid_addr_t	*termid;
	auditinfo_addr_t	audit_info;
	char	msg[512];

	if (adt_load_hostname(NULL, (adt_termid_t **)&termid) < 0) {
		(void) snprintf(msg, sizeof (msg), "unable to get local "
		    "IP address: %s", strerror(errno));
		goto fail;
	}
	/* Get current kernel audit info, and fill in the IP address */
	if (auditon(A_GETKAUDIT, (caddr_t)&audit_info,
	    sizeof (audit_info)) < 0) {
		(void) snprintf(msg, sizeof (msg), "unable to get kernel "
		    "audit info: %s", strerror(errno));
		goto fail;
	}

	audit_info.ai_termid = *termid;

	/* Update the kernel audit info with new IP address */
	if (auditon(A_SETKAUDIT, (caddr_t)&audit_info,
	    sizeof (audit_info)) < 0) {
		(void) snprintf(msg, sizeof (msg), "unable to set kernel "
		    "audit info: %s", strerror(errno));
		goto fail;
	}

	free(termid);
	return (0);

fail:
	free(termid);
	__audit_syslog("auditd", LOG_PID | LOG_CONS | LOG_NOWAIT, LOG_DAEMON,
	    LOG_ALERT, msg);
	return (-1);
}

/*
 * conf_to_kernel() - configure the event to class mapping; see also
 * auditconfig(1M) -conf option.
 */
static void
conf_to_kernel(void)
{
	au_event_ent_t		*evp;
	int			i;
	char			*msg;
	au_evclass_map_t	ec;
	au_stat_t		as;

	if (auditon(A_GETSTAT, (caddr_t)&as, 0) != 0) {
		(void) asprintf(&msg, gettext("Audit module does not appear "
		    "to be loaded."));
		err_exit(msg);
	}

	i = 0;
	setauevent();
	while ((evp = getauevent()) != NULL) {
		if (evp->ae_number <= as.as_numevent) {
			++i;
			ec.ec_number = evp->ae_number;
			ec.ec_class = evp->ae_class;

			if (auditon(A_SETCLASS, (caddr_t)&ec,
			    sizeof (ec)) != 0) {
				(void) asprintf(&msg,
				    gettext("Could not configure kernel audit "
				    "event to class mappings."));
				err_exit(msg);
			}
		}
	}
	endauevent();

	DPRINT((dbfp, "configured %d kernel events.\n", i));
}

/*
 * scf_to_kernel_qctrl() - update the kernel queue control parameters
 */
static void
scf_to_kernel_qctrl(void)
{
	struct au_qctrl	act_qctrl;
	struct au_qctrl	cfg_qctrl;
	char		*msg;

	if (!do_getqctrl_scf(&cfg_qctrl)) {
		(void) asprintf(&msg, gettext("Unable to gather audit queue "
		    "control parameters from the SMF repository."));
		err_exit(msg);
	}

	DPRINT((dbfp, "will check and set qctrl parameters:\n"));
	DPRINT((dbfp, "\thiwater: %d\n", cfg_qctrl.aq_hiwater));
	DPRINT((dbfp, "\tlowater: %d\n", cfg_qctrl.aq_lowater));
	DPRINT((dbfp, "\tbufsz: %d\n", cfg_qctrl.aq_bufsz));
	DPRINT((dbfp, "\tdelay: %ld\n", cfg_qctrl.aq_delay));

	if (auditon(A_GETQCTRL, (caddr_t)&act_qctrl, 0) != 0) {
		(void) asprintf(&msg, gettext("Could not retrieve "
		    "audit queue controls from kernel."));
		err_exit(msg);
	}

	/* overwrite the default (zeros) from the qctrl configuration */
	if (cfg_qctrl.aq_hiwater == 0) {
		cfg_qctrl.aq_hiwater = act_qctrl.aq_hiwater;
		DPRINT((dbfp, "hiwater changed to active value: %u\n",
		    cfg_qctrl.aq_hiwater));
	}
	if (cfg_qctrl.aq_lowater == 0) {
		cfg_qctrl.aq_lowater = act_qctrl.aq_lowater;
		DPRINT((dbfp, "lowater changed to active value: %u\n",
		    cfg_qctrl.aq_lowater));
	}
	if (cfg_qctrl.aq_bufsz == 0) {
		cfg_qctrl.aq_bufsz = act_qctrl.aq_bufsz;
		DPRINT((dbfp, "bufsz changed to active value: %u\n",
		    cfg_qctrl.aq_bufsz));
	}
	if (cfg_qctrl.aq_delay == 0) {
		cfg_qctrl.aq_delay = act_qctrl.aq_delay;
		DPRINT((dbfp, "delay changed to active value: %ld\n",
		    cfg_qctrl.aq_delay));
	}

	if (auditon(A_SETQCTRL, (caddr_t)&cfg_qctrl, 0) != 0) {
		(void) asprintf(&msg,
		    gettext("Could not configure audit queue controls."));
		err_exit(msg);
	}

	DPRINT((dbfp, "qctrl parameters set\n"));
}

/*
 * scf_to_kernel_policy() - update the audit service policies
 */
static void
scf_to_kernel_policy(void)
{
	uint32_t	policy;
	char		*msg;

	if (!do_getpolicy_scf(&policy)) {
		(void) asprintf(&msg, gettext("Unable to get audit policy "
		    "configuration from the SMF repository."));
		err_exit(msg);
	}

	if (auditon(A_SETPOLICY, (caddr_t)&policy, 0) != 0) {
		(void) asprintf(&msg,
		    gettext("Could not update active policy settings."));
		err_exit(msg);
	}

	DPRINT((dbfp, "kernel policy settings updated\n"));
}
