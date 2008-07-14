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

/* Audit daemon server */
/*
 * These routines make up the audit daemon server.  This daemon, called
 * auditd, handles the user level parts of auditing.  It receives buffered
 * audit records (usually one or more per buffer, potentially less than
 * one) and passes them to one or more plugins for processing.
 *
 * The major interrupts are AU_SIG_READ_CONTROL (start over),
 * AU_SIG_DISABLE (start shutting down), SIGALRM (quit), and
 * AU_SIG_NEXT_DIR (start a new audit log file). SIGTERM (the implementation
 * value of AU_SIG_DISABLE) is also used for the child to tell the parent
 * that audit is ready.
 *
 * Configuration data comes from /etc/security/audit_control and the auditon
 * system call.
 *
 * The major errors are EBUSY (auditing is already in use) and EINTR
 * (one of the above signals was received).  File space errors are
 * handled by the audit_binfile plugin
 */

#define	DEBUG 		0
#define	MEM_TEST	0	/* set to one to generate core dump on exit */

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
#include "audit_sig_infc.h"
#include <audit_plugin.h>

#if !defined(TEXT_DOMAIN)
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif
/*
 * After we get a AU_SIG_DISABLE, we want to set a timer for 2 seconds
 * and let c2audit write as many records as it can until the timer
 * goes off(at which point it returns to auditd with SIGALRM).  If any
 * other signals are received during that time, we call
 * __audit_dowarn() to indicate that the queue may not have been fully
 * flushed.
 */
#define	ALRM_TIME	2
#define	SLEEP_TIME	20	/* # of seconds to sleep in all hard loop */

#if DEBUG
#define	DPRINT(x) {(void) fprintf x; }
static FILE	*dbfp;	/* debug file */
#else
#define	DPRINT(x)
#endif /* DEBUG */

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
static int	caught_readc = 0;	/* number of AU_SIG_READ_CONTROLs */
static int	caught_term = 0;	/* number of AU_SIG_DISABLEs pending */
static int	caught_nextd = 0;	/* number of AU_SIG_NEXT_DIRs pending */

static int	reset_list = 1;	/* 1 to re-read audit_control */
static int	reset_file = 1; /* 1 to close/open binary log */

static int	auditing_set = 0;	/* 1 if auditon(A_SETCOND, on... */

static void	my_sleep();
static void	signal_thread();
static void	loadauditlist();
static void	block_signals();
static int	do_sethost();

/* common exit function */
void
auditd_exit(int status)
{
#if MEM_TEST
	sigset_t	set;

	DPRINT((dbfp, "mem_test intentional abort (status=%d)\n",
	    status));
	abort();
#endif
	DPRINT((dbfp, "%ld exit status = %d auditing_set = %d\n",
	    getpid(), status, auditing_set));

	if (auditing_set)
		(void) auditon(A_SETCOND, (caddr_t)&turn_audit_off,
		    (int)sizeof (int));

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
	/* LINTED */
	char			*envp;
	dbfp = __auditd_debug_file_open();
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
		auditd_exit(2);
	}
	as_null.ai_mask.as_success = 0;
	as_null.ai_mask.as_failure = 0;
	(void) setaudit_addr(&as_null, sizeof (as_null));
	auid = AU_NOAUDITID;
	(void) setauid(&auid);
	/*
	 * Set the audit state flag to AUDITING.
	 */
	if (auditon(A_SETCOND, (caddr_t)&turn_audit_on, (int)sizeof (int)) !=
	    0) {
		DPRINT((dbfp, "auditon(A_SETCOND...) failed (exit)\n"));
		__audit_dowarn("nostart", "", 0);
		auditd_exit(7);
	}

	block_signals();

#if DEBUG
	/* output to dbfp shouldn't be duplicated by parent and child */
	(void) fflush(dbfp);
#endif
	/*
	 * wait for "ready" signal before exit -- for greenline
	 */
	if (fork()) {
		sigset_t	set;
		int		signal_caught = 0;

		(void) sigemptyset(&set);
		(void) sigaddset(&set, AU_SIG_DISABLE);

		while (signal_caught != AU_SIG_DISABLE)
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
	if (pthread_create(&tid, NULL, (void *(*)(void *))signal_thread,
	    NULL)) {
		(void) fprintf(stderr, gettext(
		    "auditd can't create a thread\n"));
		auditd_exit(3);
	}
	/*
	 * Set the umask so that only audit or other users in the audit group
	 * can get to the files created by auditd.
	 */
	(void) umask(007);

	if (__logpost("")) {	/* Open the audit_data file. */
		DPRINT((dbfp, "logpost failed\n"));
		auditd_exit(4);
	}
	/*
	 * Here is the main body of the audit daemon.  running == 0 means that
	 * after flushing out the audit queue, it is time to exit in response to
	 * AU_SIG_DISABLE
	 */
	while (running) {
		/*
		 * Read audit_control and create plugin lists.
		 *
		 * loadauditlist() and auditd_thread_init() are called
		 * while under the plugin_mutex lock to avoid a race
		 * with unload_plugin().
		 */
		if (reset_list || reset_file) {
			(void) pthread_mutex_lock(&plugin_mutex);
			if (reset_list)
				loadauditlist();

			if (auditd_thread_init()) {
				auditd_thread_close();
				/* continue; wait for audit -s */
			}
			(void) pthread_mutex_unlock(&plugin_mutex);
			reset_list = 0;
		}
		/*
		 * tell parent I'm running whether or not the initialization
		 * actually worked.  The failure case is to wait for an
		 * audit -n or audit -s to fix the problem.
		 */
		if (pid != 0) {
			(void) kill(pid, AU_SIG_DISABLE);
			pid = 0;
		}
		/*
		 * thread_signal() signals main (this thread) when
		 * it has received a signal.
		 */
		DPRINT((dbfp, "main thread is waiting\n"));
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
			 * over unless audit_control actually changed.
			 *
			 * They want to reread the audit_control file.
			 * Set reset_list which will return us to the
			 * main while loop in the main routine.
			 */
			caught_readc = 0;
			reset_list = 1;
		} else if (caught_nextd) {
			/*
			 * This is a special case for the binfile
			 * plugin. (audit -n)  NULL out kvlist
			 * so binfile won't re-read audit_control
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
		DPRINT((dbfp, "normal AU_SIG_DISABLE exit\n"));
		/*
		 * Exit, as requested.
		 */
		auditd_thread_close();
	}
	if (caught_readc)
		reset_list = 1;		/* Reread the audit_control file */

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
 * init_plugin first searches the existing plugin list to see
 * if the plugin already has been defined; if not, it creates it
 * and links it into the list.  It returns a pointer to the found
 * or created struct.  A change of path in audit_control for a
 * given plugin will cause a miss.
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
				p->plg_kvlist = list;
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
	p->plg_kvlist = list;
	p->plg_cnt = cnt_flag;
	p->plg_retry_time = SLEEP_TIME;
	p->plg_qmax = 0;
	p->plg_save_q_copy = NULL;

	DPRINT((dbfp, "created plugin:  %s\n", path));
	return (p);
}

/*
 * loadauditlist - read the directory list from the audit_control file.
 *		   to determine if a binary file is to be written.
 *		 - read the plugin entries from the audit_control file
 *
 * globals -
 *
 *	plugin queues
 *
 * success is when at least one plug in is defined.
 *
 * set cnt policy here based on auditconfig setting.  future could
 * have a policy = {+|-}cnt entry per plugin with auditconfig providing the
 * default.
 */

static void
loadauditlist()
{
	char		buf[MAXPATHLEN];
	char		*value;
	plugin_t	*p;
	int		acresult;
	int		wait_count = 0;
	kva_t		*kvlist;
	long		policy;
	int		cnt_flag;
	struct au_qctrl	kqmax;
	au_acinfo_t	*ach = NULL;
	int		got_dir = 0;
	int		have_plugin = 0;
	char		*endptr;

	if (auditon(A_GETPOLICY, (char *)&policy, 0) == -1) {
		DPRINT((dbfp, "auditon(A_GETPOLICY...) failed (exit)\n"));
		__audit_dowarn("auditoff", "", 0);
		auditd_thread_close();
		auditd_exit(5);
	}
	cnt_flag = ((policy & AUDIT_CNT) != 0) ? 1 : 0;
	DPRINT((dbfp, "loadauditlist:  policy is to %s\n", (cnt_flag == 1) ?
	    "continue" : "block"));

#if DEBUG
	if (auditon(A_GETCOND, (caddr_t)&acresult, (int)sizeof (int)) !=
	    0)
		DPRINT((dbfp, "auditon(A_GETCOND...) failed (exit)\n"));
#endif
	DPRINT((dbfp, "audit cond = %d (1 is on)\n", acresult));


	if (auditon(A_GETQCTRL, (char *)&kqmax, sizeof (struct au_qctrl)) !=
	    0) {
		DPRINT((dbfp, "auditon(A_GETQCTRL...) failed (exit)\n"));
		__audit_dowarn("auditoff", "", 0);
		auditd_thread_close();
		auditd_exit(6);
	}
	kqmax.aq_hiwater *= 5;		/* RAM is cheaper in userspace */
	DPRINT((dbfp, "auditd: reading audit_control\n"));

	p = plugin_head;
	/*
	 * two-step on setting p->plg_removed because the input thread
	 * in doorway.c uses p->plg_removed to decide if the plugin is
	 * active.
	 */
	while (p != NULL) {
		DPRINT((dbfp, "loadauditlist:  %X, %s previously created\n",
		    p, p->plg_path));
		p->plg_to_be_removed = 1;	/* tentative removal */
		p = p->plg_next;
	}
	/*
	 * have_plugin may over count by one if both a "dir" entry
	 * and a "plugin" entry for binfile are found.  All that
	 * matters is that it be zero if no plugin or dir entries
	 * are found.
	 */
	have_plugin = 0;
	for (;;) {
		/* NULL == use standard path for audit_control */
		ach = _openac(NULL);
		/*
		 * loop until a directory entry is found (0) or eof (-1)
		 */
		while (((acresult = _getacdir(ach, buf, sizeof (buf))) != 0) &&
		    acresult != -1) {
		}
		if (acresult == 0) {
			DPRINT((dbfp,
			    "loadauditlist: "
			    "got binfile via old config syntax\n"));
			/*
			 * A directory entry was found.
			 */
			got_dir = 1;
			kvlist = _str2kva("name=audit_binfile.so.1",
			    "=", ";");

			p = init_plugin("audit_binfile.so.1", kvlist, cnt_flag);

			if (p != NULL) {
				binfile = p;
				p->plg_qmax = kqmax.aq_hiwater;
				have_plugin++;
			}
		}
		/*
		 * collect plugin entries.  If there is an entry for
		 * binfile.so.1, the parameters from the plugin line
		 * override those set above.  For binfile, p_dir is
		 * required only if dir wasn't specified elsewhere in
		 * audit_control
		 */
		_rewindac(ach);
		while ((acresult = _getacplug(ach, &kvlist)) == 0) {
			value = kva_match(kvlist, "name");
			if (value == NULL)
				break;
			DPRINT((dbfp, "loadauditlist: have an entry for %s\n",
			    value));
			p = init_plugin(value, kvlist, cnt_flag);
			if (p == NULL)
				continue;

			if (strstr(value, "/audit_binfile.so") != NULL) {
				binfile = p;
				if (!got_dir &&
				    (kva_match(kvlist, "p_dir") ==
				    NULL)) {
					__audit_dowarn("getacdir", "",
					    wait_count);
				}
			}
			p->plg_qmax = kqmax.aq_hiwater; /* default */
			value = kva_match(kvlist, "qsize");
			if (value != NULL) {
				long	tmp;

				tmp = strtol(value, &endptr, 10);
				if (*endptr == '\0')
					p->plg_qmax = tmp;
			}
			DPRINT((dbfp, "%s queue max = %d\n", p->plg_path,
			    p->plg_qmax));

			have_plugin++;
		}
		_endac(ach);
		if (have_plugin != 0)
			break;
		/*
		 * there was a problem getting the directory
		 * list or remote host info from the audit_control file
		 */
		wait_count++;
#if	DEBUG
		if (wait_count < 2)
			DPRINT((dbfp,
			    "auditd: problem getting directory "
			    "/ or plugin list from audit_control.\n"));
#endif	/* DEBUG */
		__audit_dowarn("getacdir", "", wait_count);
		/*
		 * sleep for SLEEP_TIME seconds.
		 */
		my_sleep();
	}    /* end for(;;) */

	p = plugin_head;
	while (p != NULL) {
		DPRINT((dbfp, "loadauditlist: %s remove flag=%d; cnt=%d\n",
		    p->plg_path, p->plg_to_be_removed, p->plg_cnt));
		p->plg_removed = p->plg_to_be_removed;
		p = p->plg_next;
	}
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

static void
signal_thread()
{
	sigset_t	set;
	int		signal_caught;

	DPRINT((dbfp, "the signal thread is thread %d\n",
	    pthread_self()));

	(void) sigemptyset(&set);
	(void) sigaddset(&set, SIGALRM);
	(void) sigaddset(&set, AU_SIG_DISABLE);
	(void) sigaddset(&set, AU_SIG_READ_CONTROL);
	(void) sigaddset(&set, AU_SIG_NEXT_DIR);

	for (;;) {
		signal_caught = sigwait(&set);
		switch (signal_caught) {
		case SIGALRM:
			caught_alrm++;
			DPRINT((dbfp, "caught SIGALRM\n"));
			break;
		case AU_SIG_DISABLE:
			caught_term++;
			DPRINT((dbfp, "caught AU_SIG_DISABLE\n"));
			break;
		case AU_SIG_READ_CONTROL:
			caught_readc++;
			DPRINT((dbfp, "caught AU_SIG_READ_CONTROL\n"));
			break;
		case AU_SIG_NEXT_DIR:
			caught_nextd++;
			DPRINT((dbfp, "caught AU_SIG_NEXT_DIR\n"));
			break;
		default:
			DPRINT((dbfp, "caught unexpected signal:  %d\n",
			    signal_caught));
			break;
		}
		(void) pthread_cond_signal(&(main_thr.thd_cv));
	}
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
