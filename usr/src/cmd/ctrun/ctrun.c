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

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ctfs.h>
#include <sys/contract.h>
#include <sys/contract/process.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <limits.h>
#include <libuutil.h>
#include <libcontract.h>
#include <libcontract_priv.h>

#include <locale.h>
#include <langinfo.h>

static int opt_verbose;
static int opt_Verbose;

#define	OPT_NORMAL	0x1
#define	OPT_FATAL	0x2

typedef struct optvect {
	const char	*opt_name;
	uint_t		opt_value;
	uint_t		opt_flags;
} optvect_t;

static optvect_t option_params[] = {
	{ "noorphan", CT_PR_NOORPHAN },
	{ "pgrponly", CT_PR_PGRPONLY },
	{ "regent", CT_PR_REGENT },
	{ "inherit", CT_PR_INHERIT },
	{ NULL }
};

static optvect_t option_events[] = {
	{ "core", CT_PR_EV_CORE, OPT_NORMAL | OPT_FATAL },
	{ "signal", CT_PR_EV_SIGNAL, OPT_NORMAL | OPT_FATAL },
	{ "hwerr", CT_PR_EV_HWERR, OPT_NORMAL | OPT_FATAL },
	{ "empty", CT_PR_EV_EMPTY, OPT_NORMAL },
	{ "fork", CT_PR_EV_FORK, OPT_NORMAL },
	{ "exit", CT_PR_EV_EXIT, OPT_NORMAL },
	{ NULL }
};

typedef enum lifetime {
	LT_NONE,
	LT_CHILD,
	LT_CONTRACT
} lifetime_t;

/*
 * Exit code to use when the child exited abnormally (i.e. exited with
 * a status we are unable to emulate).
 */
#define	EXIT_BADCHILD	123

#define	USAGESTR	\
	"Usage: %s [-i eventlist] [-f eventlist] [-l lifetime] \n" \
	"\t[-o optionlist] [-r count [-t]] [-v]\n" \
	"\t[-F fmri] [-A aux] command\n"

/*
 * usage
 *
 * Educate the user.
 */
static void
usage(void)
{
	(void) fprintf(stderr, gettext(USAGESTR), uu_getpname());
	exit(UU_EXIT_USAGE);
}

/*
 * bit2str
 *
 * Convert a bit into its string representation.
 */
static const char *
bit2str(optvect_t *options, uint_t bit)
{
	for (; options->opt_name; options++)
		if (options->opt_value == bit)
			return (options->opt_name);
	return (NULL);
}

/*
 * str2bit
 *
 * Convert a string into its bit representation.  If match is set, only
 * look at those options with the match bit set in its opt_flags
 * field.
 */
static uint_t
str2bit(optvect_t *options, int match, const char *str, int len)
{
	for (; options->opt_name; options++) {
		if (match && (options->opt_flags & match) == 0)
			continue;
		if (strncmp(str, options->opt_name, len) == 0)
			return (options->opt_value);
	}
	return (0);
}

/*
 * opt2bits
 *
 * Given a set of textual options separated by commas or spaces,
 * convert them to a set of bits.  Errors are fatal, except for empty
 * options (which are ignored) and duplicate options (which are
 * idempotent).
 */
static void
opt2bits(optvect_t *options, int match, const char *str, uint_t *bits, char c)
{
	const char *ptr, *next = str;
	uint_t result = 0;
	uint_t bit;
	int none = 0;

	while (*str) {
		int len;

		ptr = strpbrk(str, ", ");
		if (ptr != NULL) {
			len = ptr - str;
			next = ptr + 1;
		} else {
			len = strlen(str);
			next = str + len;
		}
		if (len == 0) {
			uu_warn(gettext("empty option\n"));
			bit = 0;
		} else {
			bit = str2bit(options, match, str, len);
			if (bit == 0 && strncmp(str, "none", len) == 0) {
				none = 1;
				if (result)
					goto noneerr;
			} else if (bit == 0) {
				uu_warn(gettext("unrecognized option '%.*s'\n"),
				    len, str);
				uu_warn(gettext("error parsing '-%c' option\n"),
				    c);
				usage();
			} else if (none) {
				goto noneerr;
			}
			if (result & bit)
				uu_warn(gettext("option '%.*s' "
				    "specified twice\n"), len, str);
		}
		result |= bit;
		str = next;
	}

	*bits = result;
	return;

noneerr:
	uu_warn(gettext("option is incompatible with others: '%s'\n"), "none");
	usage();
}

/*
 * close_on_exec
 *
 * Given a fd, marks it close-on-exec.
 */
static int
close_on_exec(int fd)
{
	int flags = fcntl(fd, F_GETFD, 0);
	if ((flags != -1) && (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != -1))
		return (0);
	return (-1);
}

/*
 * v_printf
 *
 * Output routine for messages printed only when -v is specified.
 */
/* PRINTFLIKE1 */
static void
v_printf(const char *format, ...)
{
	va_list va;

	if (opt_verbose) {
		(void) printf("%s(%ld): ", uu_getpname(), getpid());
		va_start(va, format);
		(void) vprintf(format, va);
		va_end(va);
	}
}

/*
 * get_event
 *
 * Reads and acknowledges an event.  Returns the event type.
 */
static uint_t
get_event(int fd, int ctfd, ctid_t ctid)
{
	ct_evthdl_t ev;
	uint_t result;
	ctevid_t evid;

	for (;;) {
		int efd;

		/*
		 * Normally we only need to look at critical messages.
		 * If we are displaying contract events, however, we
		 * have to read them all.
		 */
		errno = opt_verbose ? ct_event_read(fd, &ev) :
		    ct_event_read_critical(fd, &ev);
		if (errno != 0)
			uu_die(gettext("failed to listen to contract events"));

		/*
		 * If requested, display the event.
		 */
		if (opt_verbose) {
			v_printf(gettext("event from contract %ld: "),
			    ct_event_get_ctid(ev));
			contract_event_dump(stdout, ev, opt_Verbose);
			if ((ct_event_get_flags(ev) & CTE_INFO) != 0) {
				ct_event_free(ev);
				continue;
			}
		}

		/*
		 * We're done if this event is one of ours.
		 */
		evid = ct_event_get_evid(ev);
		if (ct_event_get_ctid(ev) == ctid)
			break;

		/*
		 * ACK events from other contracts.
		 * This shouldn't happen, but it could.
		 */
		efd = contract_open(ct_event_get_ctid(ev), "process", "ctl",
		    O_WRONLY);
		if (efd != -1) {
			(void) ct_ctl_ack(efd, evid);
			(void) close(efd);
		}
		ct_event_free(ev);
	}

	/*
	 * Note that if we want to use ctrun as a simple restarter, we
	 * need persistently keep track of fatal events so we can
	 * properly handle the death of the contract.  Rather than keep
	 * a file or somesuch lying around, it might make more sense to
	 * leave the significant fatal event sitting in the queue so
	 * that a restarted instance of ctrun can pick it up.  For now
	 * we'll just ACK all events.
	 */
	(void) ct_ctl_ack(ctfd, evid);

	result = ct_event_get_type(ev);
	ct_event_free(ev);

	return (result);
}

/*
 * abandon
 *
 * Given an fd for a contract's ctl file, abandon the contract and
 * close the file.
 */
static void
abandon(int ctfd)
{
	if (ct_ctl_abandon(ctfd) == -1)
		uu_die(gettext("failed to abandon contract %d"), ctfd);

	(void) close(ctfd);
}

static int chldstat;
static int chldexited;

/*
 * sigchld
 *
 * Our SIGCHLD handler.  Sets chldstat and chldexited so the
 * interrupted code knows what happened.
 */
/*ARGSUSED*/
static void
sigchld(int sig, struct siginfo *si, void *ucp)
{
	int err = errno;

	if (si->si_code == CLD_EXITED)
		chldstat = si->si_status;
	else
		chldstat = EXIT_BADCHILD;
	chldexited = 1;
	while (waitpid(si->si_pid, NULL, 0) == -1 && errno == EINTR)
		;
	errno = err;
}

/*
 * dowait
 *
 * Waits for the specified child to exit.  Returns the exit code ctrun
 * should return.
 */
static int
dowait(int pid)
{
	pid_t wpid;
	int wstatus;

	do
		wpid = waitpid(pid, &wstatus, 0);
	while (wpid == -1 && errno == EINTR);

	if (wpid == -1)
		uu_die(gettext("wait failed"));

	if (WIFEXITED(wstatus))
		return (WEXITSTATUS(wstatus));
	else
		return (EXIT_BADCHILD);
}

int
main(int argc, char **argv)
{
	int	fd, efd;
	pid_t	pid;
	ctid_t	ctid = 0;
	int	ctfd;
	int	pipefds[2];
	struct sigaction osact;

	int	s;
	ctid_t	opt_adopt = 0;
	int	opt_transfer = 0;
	int	opt_count = -1;
	uint_t	opt_info = CT_PR_EV_CORE;
	uint_t	opt_crit = 0;
	uint_t	eff_fatal, opt_fatal = CT_PR_EV_HWERR;
	uint_t	eff_param, opt_param = 0;
	lifetime_t opt_life = LT_CONTRACT;

	char *svc_fmri = NULL;
	char *svc_aux = NULL;

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);
	uu_alt_exit(UU_PROFILE_LAUNCHER);

	(void) uu_setpname(argv[0]);

	while ((s = getopt(argc, argv, "a:A:l:o:i:c:f:F:r:tvV")) != EOF) {
		switch (s) {
		case 'a':
			if (uu_strtoint(optarg, &opt_adopt, sizeof (opt_adopt),
			    0, 0, INT32_MAX) == -1) {
				uu_warn(gettext("invalid contract ID '%s'\n"),
				    optarg);
				usage();
			}
			break;
		case 'v':
			opt_verbose = 1;
			break;
		case 'V':
			opt_Verbose = 1;
			opt_verbose = 1;
			break;
		case 't':
			opt_transfer = 1;
			break;
		case 'r':
			if (uu_strtoint(optarg, &opt_count, sizeof (opt_adopt),
			    0, 0, INT32_MAX) == -1) {
				uu_warn(gettext("invalid count '%s'\n"),
				    optarg);
				usage();
			}
			break;
		case 'l':
			if (strcmp(optarg, "none") == 0) {
				opt_life = LT_NONE;
			} else if (strcmp(optarg, "child") == 0) {
				opt_life = LT_CHILD;
			} else if (strcmp(optarg, "contract") == 0) {
				opt_life = LT_CONTRACT;
			} else {
				uu_warn(gettext("invalid lifetime '%s'\n"),
				    optarg);
				usage();
			}

			break;
		case 'o':
			opt2bits(option_params, 0, optarg, &opt_param,
			    optopt);
			break;
		case 'i':
			opt2bits(option_events, OPT_NORMAL, optarg, &opt_info,
			    optopt);
			break;
		case 'c':
			opt2bits(option_events, OPT_NORMAL, optarg, &opt_crit,
			    optopt);
			break;
		case 'f':
			opt2bits(option_events, OPT_FATAL, optarg, &opt_fatal,
			    optopt);
			break;
		case 'F':
			svc_fmri = optarg;
			break;
		case 'A':
			svc_aux = optarg;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/*
	 * Basic argument sanity checks.
	 */
	if ((opt_life == LT_NONE) && (opt_param & CT_PR_NOORPHAN)) {
		uu_warn(gettext("cannot use option '%s' with lifetime '%s'\n"),
		    bit2str(option_params, CT_PR_NOORPHAN), "none");
		usage();
	}

	if ((opt_life != LT_CONTRACT) && (opt_count >= 0)) {
		uu_warn(gettext("cannot restart with lifetime '%s'\n"),
		    opt_life == LT_NONE ? "none" : "child");
		usage();
	}

	if ((opt_param & CT_PR_PGRPONLY) && (opt_count >= 0)) {
		uu_warn(gettext("cannot restart with option '%s'\n"),
		    bit2str(option_params, CT_PR_PGRPONLY));
		usage();
	}

	if (opt_transfer && (opt_count == -1)) {
		uu_warn(gettext("cannot transfer when not restarting\n"));
		usage();
	}

	if (argc <= 0)
		usage();

	/*
	 * Create a process contract template and our process's process
	 * contract bundle endpoint.  Mark them close-on-exec so we
	 * don't have to worry about closing them in our child.
	 */
	fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	if (fd == -1)
		uu_die(gettext("template open failed"));

	efd = open64(CTFS_ROOT "/process/pbundle", O_RDONLY);
	if (efd == -1)
		uu_die(gettext("process bundle open failed"));

	if (close_on_exec(fd) || close_on_exec(efd))
		uu_die(gettext("could not set FD_CLOEXEC"));

	/*
	 * Set the process contract's terms based on our arguments.
	 */
	if (errno = ct_pr_tmpl_set_param(fd, opt_param))
		uu_die(gettext("set param failed"));

	if (errno = ct_tmpl_set_informative(fd, opt_info))
		uu_die(gettext("set notify failed"));

	if (errno = ct_pr_tmpl_set_fatal(fd, opt_fatal))
		uu_die(gettext("set fatal failed"));

	if (opt_param & CT_PR_PGRPONLY)
		opt_crit = CT_PR_EV_EMPTY;
	else
		opt_crit |= opt_fatal | CT_PR_EV_EMPTY;
	if (errno = ct_tmpl_set_critical(fd, opt_crit))
		uu_die(gettext("set critical failed"));
	if (svc_fmri && (errno = ct_pr_tmpl_set_svc_fmri(fd, svc_fmri)))
		uu_die(gettext("set fmri failed: "
		    "insufficient privileges\n"));
	if (svc_aux && (errno = ct_pr_tmpl_set_svc_aux(fd, svc_aux)))
		uu_die(gettext("set aux failed"));

	/*
	 * Activate the template.
	 */
	if (errno = ct_tmpl_activate(fd))
		uu_die(gettext("template activate failed"));

restart:
	if (opt_adopt) {
		/*
		 * Adopt a specific contract.
		 */
		ct_stathdl_t st;
		int stfd;

		if ((ctfd = contract_open(opt_adopt, "process", "ctl",
		    O_WRONLY)) == -1)
			uu_die(gettext("could not open contract %ld"),
			    opt_adopt);

		/*
		 * Read the contract's terms so that we interpret its
		 * events properly.
		 */
		if (((stfd = contract_open(opt_adopt, "process", "status",
		    O_RDONLY)) == -1) ||
		    (errno = ct_status_read(stfd, CTD_FIXED, &st)) ||
		    (errno = ct_pr_status_get_fatal(st, &eff_fatal)) ||
		    (errno = ct_pr_status_get_param(st, &eff_param)))
			uu_die(gettext("could not stat contract %ld"),
			    opt_adopt);
		ct_status_free(st);
		(void) close(stfd);

		if (errno = ct_ctl_adopt(ctfd))
			uu_die(gettext("could not adopt contract %ld"),
			    opt_adopt);

		ctid = opt_adopt;
		opt_adopt = 0;
		v_printf(gettext("adopted contract id %ld\n"), ctid);
	} else {
		/*
		 * Create a new process.
		 */
		if (opt_life == LT_CONTRACT) {
			struct sigaction sact;

			/*
			 * Since we are going to be waiting for and
			 * reacting to contract events, install a
			 * signal handler so we capture the exit status
			 * of our child.
			 */
			chldstat = UU_EXIT_OK;
			chldexited = 0;
			sact.sa_sigaction = sigchld;
			sact.sa_flags = SA_SIGINFO | SA_RESTART |
			    SA_NOCLDSTOP;
			(void) sigemptyset(&sact.sa_mask);
			if (sigaction(SIGCHLD, &sact, &osact) == -1)
				uu_die(gettext("failed to install "
				    "sigchld handler"));
		} else if (opt_life == LT_NONE) {
			/*
			 * Though we aren't waiting for our child to
			 * exit, as a well-behaved command launcher we
			 * must wait for it to exec.  On success the
			 * pipe will simply close, and on failure the
			 * proper exit status will be sent.
			 */
			if (pipe(pipefds) == -1 ||
			    close_on_exec(pipefds[0]) == -1 ||
			    close_on_exec(pipefds[1]) == -1)
				uu_die(gettext("failed to create pipe"));
		}

		if ((pid = fork()) == -1) {
			uu_die(gettext("fork failed"));
		} else if (pid == 0) {
			int result = execvp(argv[0], argv);
			if (opt_life == LT_NONE) {
				char a = 1;
				int err = errno;

				(void) write(pipefds[1], &a, sizeof (a));
				errno = err;
			}
			if (result == -1)
				uu_xdie(errno == ENOENT ? 127 : 126,
				    gettext("exec failed"));
			uu_die(gettext("exec returned!\n"));
		}

		/*
		 * Get the newly-created contract's id and ctl fd.
		 */
		if (errno = contract_latest(&ctid))
			uu_die(gettext("could not get new contract's id"));
		if ((ctfd = contract_open(ctid, "process", "ctl",
		    O_WRONLY)) == -1)
			uu_die(gettext("could not open contract"));

		/*
		 * Clear the transfer parameter so that the contract
		 * will be freed sooner and admins won't get nervous.
		 */
		if (opt_transfer) {
			(void) ct_pr_tmpl_set_transfer(fd, 0);
			(void) ct_tmpl_activate(fd);
		}

		v_printf(gettext("created contract id %ld\n"), ctid);
		eff_param = opt_param;
		eff_fatal = opt_fatal;
	}

	if (opt_life == LT_CONTRACT) {
		uint_t event, errevent = 0;

		/*
		 * Wait until the contract empties out.
		 */
		do {
			event = get_event(efd, ctfd, ctid);
			if (event & eff_fatal) {
				if ((eff_param & CT_PR_PGRPONLY) == 0)
					errevent = event;
				v_printf(gettext(
				    "fatal \"%s\" event from contract %ld\n"),
				    bit2str(option_events, event), ctid);
			}
		} while ((event & CT_PR_EV_EMPTY) == 0);

		/*
		 * If we encountered a fatal error event, and we
		 * haven't expended our maximum loop count, restart.
		 */
		if ((errevent != 0) &&
		    ((opt_count == 0) || (opt_count-- > 1))) {
			v_printf(gettext("failure in contract %ld, "
			    "restarting command\n"), ctid);
			if (opt_transfer) {
				/*
				 * Add the failed contract to the new
				 * contract's terms so that its
				 * inherited subcontracts can be
				 * adopted by the new process.
				 */
				if (errno = ct_pr_tmpl_set_transfer(fd, ctid))
					uu_die(gettext("set transfer failed"));
				if (errno = ct_tmpl_activate(fd))
					uu_die(gettext(
					    "template activate failed"));
				(void) close(ctfd);
			} else {
				abandon(ctfd);
			}
			goto restart;
		}

		/*
		 * At this point we are done with the contract; we
		 * don't want it to be inherited when we exit.
		 */
		abandon(ctfd);

		/*
		 * In case there was a race between SIGCHLD delivery
		 * and contract event delivery, disable the signal
		 * handler and look for the child.
		 */
		(void) sigaction(SIGCHLD, &osact, NULL);
		if (chldexited == 0)
			chldstat = dowait(pid);
	} else if (opt_life == LT_NONE) {
		char a;
		int result;

		chldstat = UU_EXIT_OK;
		(void) close(pipefds[1]);
		do {
			result = read(pipefds[0], &a, sizeof (a));
			if (result == -1 && errno != EINTR)
				uu_die(gettext("read failed"));
			if (result == 1)
				chldstat = dowait(pid);
		} while (result == -1);
	} else {
		chldstat = dowait(pid);
	}

	return (chldstat);
}
