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
 * Copyright (c) 2013 Gary Mills
 *
 * Copyright (c) 1988, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/*
 * init(1M) is the general process spawning program.  Its primary job is to
 * start and restart svc.startd for smf(5).  For backwards-compatibility it also
 * spawns and respawns processes according to /etc/inittab and the current
 * run-level.  It reads /etc/default/inittab for general configuration.
 *
 * To change run-levels the system administrator runs init from the command
 * line with a level name.  init signals svc.startd via libscf and directs the
 * zone's init (pid 1 in the global zone) what to do by sending it a signal;
 * these signal numbers are commonly refered to in the code as 'states'.  Valid
 * run-levels are [sS0123456].  Additionally, init can be given directives
 * [qQabc], which indicate actions to be taken pertaining to /etc/inittab.
 *
 * When init processes inittab entries, it finds processes that are to be
 * spawned at various run-levels.  inittab contains the set of the levels for
 * which each inittab entry is valid.
 *
 * State File and Restartability
 *   Premature exit by init(1M) is handled as a special case by the kernel:
 *   init(1M) will be immediately re-executed, retaining its original PID.  (PID
 *   1 in the global zone.)  To track the processes it has previously spawned,
 *   as well as other mutable state, init(1M) regularly updates a state file
 *   such that its subsequent invocations have knowledge of its various
 *   dependent processes and duties.
 *
 * Process Contracts
 *   We start svc.startd(1M) in a contract and transfer inherited contracts when
 *   restarting it.  Everything else is started using the legacy contract
 *   template, and the created contracts are abandoned when they become empty.
 *
 * utmpx Entry Handling
 *   Because init(1M) no longer governs the startup process, its knowledge of
 *   when utmpx becomes writable is indirect.  However, spawned processes
 *   expect to be constructed with valid utmpx entries.  As a result, attempts
 *   to write normal entries will be retried until successful.
 *
 * Maintenance Mode
 *   In certain failure scenarios, init(1M) will enter a maintenance mode, in
 *   which it invokes sulogin(1M) to allow the operator an opportunity to
 *   repair the system.  Normally, this operation is performed as a
 *   fork(2)-exec(2)-waitpid(3C) sequence with the parent waiting for repair or
 *   diagnosis to be completed.  In the cases that fork(2) requests themselves
 *   fail, init(1M) will directly execute sulogin(1M), and allow the kernel to
 *   restart init(1M) on exit from the operator session.
 *
 *   One scenario where init(1M) enters its maintenance mode is when
 *   svc.startd(1M) begins to fail rapidly, defined as when the average time
 *   between recent failures drops below a given threshold.
 */

#include <sys/contract/process.h>
#include <sys/ctfs.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/stropts.h>
#include <sys/systeminfo.h>
#include <sys/time.h>
#include <sys/termios.h>
#include <sys/tty.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include <bsm/adt_event.h>
#include <bsm/libbsm.h>
#include <security/pam_appl.h>

#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libcontract.h>
#include <libcontract_priv.h>
#include <libintl.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <poll.h>
#include <procfs.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <time.h>
#include <ulimit.h>
#include <unistd.h>
#include <utmpx.h>
#include <wait.h>
#include <zone.h>
#include <ucontext.h>

#undef	sleep

#define	fioctl(p, sptr, cmd)	ioctl(fileno(p), sptr, cmd)
#define	min(a, b)		(((a) < (b)) ? (a) : (b))

#define	TRUE	1
#define	FALSE	0
#define	FAILURE	-1

#define	UT_USER_SZ	32	/* Size of a utmpx ut_user field */
#define	UT_LINE_SZ	32	/* Size of a utmpx ut_line field */

/*
 * SLEEPTIME	The number of seconds "init" sleeps between wakeups if
 *		nothing else requires this "init" wakeup.
 */
#define	SLEEPTIME	(5 * 60)

/*
 * MAXCMDL	The maximum length of a command string in inittab.
 */
#define	MAXCMDL	512

/*
 * EXEC		The length of the prefix string added to all comamnds
 *		found in inittab.
 */
#define	EXEC	(sizeof ("exec ") - 1)

/*
 * TWARN	The amount of time between warning signal, SIGTERM,
 *		and the fatal kill signal, SIGKILL.
 */
#define	TWARN	5

#define	id_eq(x, y)	((x[0] == y[0] && x[1] == y[1] && x[2] == y[2] &&\
			x[3] == y[3]) ? TRUE : FALSE)

/*
 * The kernel's default umask is 022 these days; since some processes inherit
 * their umask from init, init will set it from CMASK in /etc/default/init.
 * init gets the default umask from the kernel, it sets it to 022 whenever
 * it wants to create a file and reverts to CMASK afterwards.
 */

static int cmask;

/*
 * The following definitions, concluding with the 'lvls' array, provide a
 * common mapping between level-name (like 'S'), signal number (state),
 * run-level mask, and specific properties associated with a run-level.
 * This array should be accessed using the routines lvlname_to_state(),
 * lvlname_to_mask(), state_to_mask(), and state_to_flags().
 */

/*
 * Correspondence of signals to init actions.
 */
#define	LVLQ		SIGHUP
#define	LVL0		SIGINT
#define	LVL1		SIGQUIT
#define	LVL2		SIGILL
#define	LVL3		SIGTRAP
#define	LVL4		SIGIOT
#define	LVL5		SIGEMT
#define	LVL6		SIGFPE
#define	SINGLE_USER	SIGBUS
#define	LVLa		SIGSEGV
#define	LVLb		SIGSYS
#define	LVLc		SIGPIPE

/*
 * Bit Mask for each level.  Used to determine legal levels.
 */
#define	MASK0	0x0001
#define	MASK1	0x0002
#define	MASK2	0x0004
#define	MASK3	0x0008
#define	MASK4	0x0010
#define	MASK5	0x0020
#define	MASK6	0x0040
#define	MASKSU	0x0080
#define	MASKa	0x0100
#define	MASKb	0x0200
#define	MASKc	0x0400

#define	MASK_NUMERIC (MASK0 | MASK1 | MASK2 | MASK3 | MASK4 | MASK5 | MASK6)
#define	MASK_abc (MASKa | MASKb | MASKc)

/*
 * Flags to indicate properties of various states.
 */
#define	LSEL_RUNLEVEL	0x0001	/* runlevels you can transition to */

typedef struct lvl {
	int	lvl_state;
	int	lvl_mask;
	char	lvl_name;
	int	lvl_flags;
} lvl_t;

static lvl_t lvls[] = {
	{ LVLQ,		0,	'Q', 0					},
	{ LVLQ,		0,	'q', 0					},
	{ LVL0,		MASK0,	'0', LSEL_RUNLEVEL			},
	{ LVL1, 	MASK1,	'1', LSEL_RUNLEVEL			},
	{ LVL2, 	MASK2,	'2', LSEL_RUNLEVEL			},
	{ LVL3, 	MASK3,	'3', LSEL_RUNLEVEL			},
	{ LVL4, 	MASK4,	'4', LSEL_RUNLEVEL			},
	{ LVL5, 	MASK5,	'5', LSEL_RUNLEVEL			},
	{ LVL6, 	MASK6, 	'6', LSEL_RUNLEVEL			},
	{ SINGLE_USER, 	MASKSU, 'S', LSEL_RUNLEVEL			},
	{ SINGLE_USER, 	MASKSU, 's', LSEL_RUNLEVEL			},
	{ LVLa,		MASKa,	'a', 0					},
	{ LVLb,		MASKb,	'b', 0					},
	{ LVLc,		MASKc,	'c', 0					}
};

#define	LVL_NELEMS (sizeof (lvls) / sizeof (lvl_t))

/*
 * Legal action field values.
 */
#define	OFF		0	/* Kill process if on, else ignore */
#define	RESPAWN		1	/* Continuously restart process when it dies */
#define	ONDEMAND	RESPAWN	/* Respawn for a, b, c type processes */
#define	ONCE		2	/* Start process, do not respawn when dead */
#define	WAIT		3	/* Perform once and wait to complete */
#define	BOOT		4	/* Start at boot time only */
#define	BOOTWAIT	5	/* Start at boot time and wait to complete */
#define	POWERFAIL	6	/* Start on powerfail */
#define	POWERWAIT	7	/* Start and wait for complete on powerfail */
#define	INITDEFAULT	8	/* Default level "init" should start at */
#define	SYSINIT		9	/* Actions performed before init speaks */

#define	M_OFF		0001
#define	M_RESPAWN	0002
#define	M_ONDEMAND	M_RESPAWN
#define	M_ONCE		0004
#define	M_WAIT		0010
#define	M_BOOT		0020
#define	M_BOOTWAIT	0040
#define	M_PF		0100
#define	M_PWAIT		0200
#define	M_INITDEFAULT	0400
#define	M_SYSINIT	01000

/* States for the inittab parser in getcmd(). */
#define	ID	1
#define	LEVELS	2
#define	ACTION	3
#define	COMMAND	4
#define	COMMENT	5

/*
 * inittab entry id constants
 */
#define	INITTAB_ENTRY_ID_SIZE 4
#define	INITTAB_ENTRY_ID_STR_FORMAT "%.4s"	/* if INITTAB_ENTRY_ID_SIZE */
						/* changes, this should */
						/* change accordingly */

/*
 * Init can be in any of three main states, "normal" mode where it is
 * processing entries for the lines file in a normal fashion, "boot" mode,
 * where it is only interested in the boot actions, and "powerfail" mode,
 * where it is only interested in powerfail related actions. The following
 * masks declare the legal actions for each mode.
 */
#define	NORMAL_MODES	(M_OFF | M_RESPAWN | M_ONCE | M_WAIT)
#define	BOOT_MODES	(M_BOOT | M_BOOTWAIT)
#define	PF_MODES	(M_PF | M_PWAIT)

struct PROC_TABLE {
	char	p_id[INITTAB_ENTRY_ID_SIZE];	/* Four letter unique id of */
						/* process */
	pid_t	p_pid;		/* Process id */
	short	p_count;	/* How many respawns of this command in */
				/*   the current series */
	long	p_time;		/* Start time for a series of respawns */
	short	p_flags;
	short	p_exit;		/* Exit status of a process which died */
};

/*
 * Flags for the "p_flags" word of a PROC_TABLE entry:
 *
 *	OCCUPIED	This slot in init's proc table is in use.
 *
 *	LIVING		Process is alive.
 *
 *	NOCLEANUP	efork() is not allowed to cleanup this entry even
 *			if process is dead.
 *
 *	NAMED		This process has a name, i.e. came from inittab.
 *
 *	DEMANDREQUEST	Process started by a "telinit [abc]" command.  Processes
 *			formed this way are respawnable and immune to level
 *			changes as long as their entry exists in inittab.
 *
 *	TOUCHED		Flag used by remv() to determine whether it has looked
 *			at an entry while checking for processes to be killed.
 *
 *	WARNED		Flag used by remv() to mark processes that have been
 *			sent the SIGTERM signal.  If they don't die in 5
 *			seconds, they are sent the SIGKILL signal.
 *
 *	KILLED		Flag used by remv() to mark procs that have been sent
 *			the SIGTERM and SIGKILL signals.
 *
 *	PF_MASK		Bitwise or of legal flags, for sanity checking.
 */
#define	OCCUPIED	01
#define	LIVING		02
#define	NOCLEANUP	04
#define	NAMED		010
#define	DEMANDREQUEST	020
#define	TOUCHED		040
#define	WARNED		0100
#define	KILLED		0200
#define	PF_MASK		0377

/*
 * Respawn limits for processes that are to be respawned:
 *
 *	SPAWN_INTERVAL	The number of seconds over which "init" will try to
 *			respawn a process SPAWN_LIMIT times before it gets mad.
 *
 *	SPAWN_LIMIT	The number of respawns "init" will attempt in
 *			SPAWN_INTERVAL seconds before it generates an
 *			error message and inhibits further tries for
 *			INHIBIT seconds.
 *
 *	INHIBIT		The number of seconds "init" ignores an entry it had
 *			trouble spawning unless a "telinit Q" is received.
 */

#define	SPAWN_INTERVAL	(2*60)
#define	SPAWN_LIMIT	10
#define	INHIBIT		(5*60)

/*
 * The maximum number of decimal digits for an id_t.  (ceil(log10 (max_id)))
 */
#define	ID_MAX_STR_LEN	10

#define	NULLPROC	((struct PROC_TABLE *)(0))
#define	NO_ROOM		((struct PROC_TABLE *)(FAILURE))

struct CMD_LINE {
	char c_id[INITTAB_ENTRY_ID_SIZE];	/* Four letter unique id of */
						/* process to be affected by */
						/* action */
	short c_levels;	/* Mask of legal levels for process */
	short c_action;	/* Mask for type of action required */
	char *c_command; /* Pointer to init command */
};

struct	pidrec {
	int	pd_type;	/* Command type */
	pid_t	pd_pid;		/* pid to add or remove */
};

/*
 * pd_type's
 */
#define	ADDPID	1
#define	REMPID	2

static struct	pidlist {
	pid_t	pl_pid;		/* pid to watch for */
	int	pl_dflag;	/* Flag indicating SIGCLD from this pid */
	short	pl_exit;	/* Exit status of proc */
	struct	pidlist	*pl_next; /* Next in list */
} *Plhead, *Plfree;

/*
 * The following structure contains a set of modes for /dev/syscon
 * and should match the default contents of /etc/ioctl.syscon.  It should also
 * be kept in-sync with base_termios in uts/common/io/ttcompat.c.
 */
static struct termios	dflt_termios = {
	BRKINT|ICRNL|IXON|IMAXBEL,			/* iflag */
	OPOST|ONLCR|TAB3,				/* oflag */
	CS8|CREAD|B9600,				/* cflag */
	ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHOCTL|ECHOKE|IEXTEN, /* lflag */
	CINTR, CQUIT, CERASE, CKILL, CEOF, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0
};

static struct termios	stored_syscon_termios;
static int		write_ioctl = 0;	/* Rewrite /etc/ioctl.syscon */

static union WAKEUP {
	struct WAKEFLAGS {
		unsigned w_usersignal : 1;	/* User sent signal to "init" */
		unsigned w_childdeath : 1;	/* An "init" child died */
		unsigned w_powerhit : 1;	/* OS experienced powerfail */
	}	w_flags;
	int w_mask;
} wakeup;


struct init_state {
	int			ist_runlevel;
	int			ist_num_proc;
	int			ist_utmpx_ok;
	struct PROC_TABLE	ist_proc_table[1];
};

#define	cur_state	(g_state->ist_runlevel)
#define	num_proc	(g_state->ist_num_proc)
#define	proc_table	(g_state->ist_proc_table)
#define	utmpx_ok	(g_state->ist_utmpx_ok)

/* Contract cookies. */
#define	ORDINARY_COOKIE		0
#define	STARTD_COOKIE		1


#ifndef NDEBUG
#define	bad_error(func, err)	{					\
	(void) fprintf(stderr, "%s:%d: %s() failed with unexpected "	\
	    "error %d.  Aborting.\n", __FILE__, __LINE__, (func), (err)); \
	abort();							\
}
#else
#define	bad_error(func, err)	abort()
#endif


/*
 * Useful file and device names.
 */
static char *CONSOLE	  = "/dev/console";	/* Real system console */
static char *INITPIPE_DIR = "/var/run";
static char *INITPIPE	  = "/var/run/initpipe";

#define	INIT_STATE_DIR "/etc/svc/volatile"
static const char * const init_state_file = INIT_STATE_DIR "/init.state";
static const char * const init_next_state_file =
	INIT_STATE_DIR "/init-next.state";

static const int init_num_proc = 20;	/* Initial size of process table. */

static char *UTMPX	 = UTMPX_FILE;		/* Snapshot record file */
static char *WTMPX	 = WTMPX_FILE;		/* Long term record file */
static char *INITTAB	 = "/etc/inittab";	/* Script file for "init" */
static char *SYSTTY	 = "/dev/systty";	/* System Console */
static char *SYSCON	 = "/dev/syscon";	/* Virtual System console */
static char *IOCTLSYSCON = "/etc/ioctl.syscon";	/* Last syscon modes */
static char *ENVFILE	 = "/etc/default/init";	/* Default env. */
static char *SU	= "/etc/sulogin";	/* Super-user program for single user */
static char *SH	= "/sbin/sh";		/* Standard shell */

/*
 * Default Path.  /sbin is included in path only during sysinit phase
 */
#define	DEF_PATH	"PATH=/usr/sbin:/usr/bin"
#define	INIT_PATH	"PATH=/sbin:/usr/sbin:/usr/bin"

static int	prior_state;
static int	prev_state;	/* State "init" was in last time it woke */
static int	new_state;	/* State user wants "init" to go to. */
static int	lvlq_received;	/* Explicit request to examine state */
static int	op_modes = BOOT_MODES; /* Current state of "init" */
static int	Gchild = 0;	/* Flag to indicate "godchild" died, set in */
				/*   childeath() and cleared in cleanaux() */
static int	Pfd = -1;	/* fd to receive pids thru */
static unsigned int	spawncnt, pausecnt;
static int	rsflag;		/* Set if a respawn has taken place */
static volatile int time_up;	/* Flag set to TRUE by the alarm interrupt */
				/* routine each time an alarm interrupt */
				/* takes place. */
static int	sflg = 0;	/* Set if we were booted -s to single user */
static int	rflg = 0;	/* Set if booted -r, reconfigure devices */
static int	bflg = 0;	/* Set if booted -b, don't run rc scripts */
static pid_t	init_pid;	/* PID of "one true" init for current zone */

static struct init_state *g_state = NULL;
static size_t	g_state_sz;
static int	booting = 1;	/* Set while we're booting. */

/*
 * Array for default global environment.
 */
#define	MAXENVENT	24	/* Max number of default env variables + 1 */
				/* init can use three itself, so this leaves */
				/* 20 for the administrator in ENVFILE. */
static char	*glob_envp[MAXENVENT];	/* Array of environment strings */
static int	glob_envn;		/* Number of environment strings */


static struct pollfd	poll_fds[1];
static int		poll_nfds = 0;	/* poll_fds is uninitialized */

/*
 * Contracts constants
 */
#define	SVC_INIT_PREFIX "init:/"
#define	SVC_AUX_SIZE (INITTAB_ENTRY_ID_SIZE + 1)
#define	SVC_FMRI_SIZE (sizeof (SVC_INIT_PREFIX) + INITTAB_ENTRY_ID_SIZE)

static int	legacy_tmpl = -1;	/* fd for legacy contract template */
static int	startd_tmpl = -1;	/* fd for svc.startd's template */
static char	startd_svc_aux[SVC_AUX_SIZE];

static char	startd_cline[256] = "";	/* svc.startd's command line */
static int	do_restart_startd = 1;	/* Whether to restart svc.startd. */
static char	*smf_options = NULL;	/* Options to give to startd. */
static int	smf_debug = 0;		/* Messages for debugging smf(5) */
static time_t	init_boot_time;		/* Substitute for kernel boot time. */

#define	NSTARTD_FAILURE_TIMES	3		/* trigger after 3 failures */
#define	STARTD_FAILURE_RATE_NS	5000000000LL	/* 1 failure/5 seconds */

static hrtime_t	startd_failure_time[NSTARTD_FAILURE_TIMES];
static uint_t	startd_failure_index;


static char	*prog_name(char *);
static int	state_to_mask(int);
static int	lvlname_to_mask(char, int *);
static void	lscf_set_runlevel(char);
static int	state_to_flags(int);
static char	state_to_name(int);
static int	lvlname_to_state(char);
static int	getcmd(struct CMD_LINE *, char *);
static int	realcon();
static int	spawn_processes();
static int	get_ioctl_syscon();
static int	account(short, struct PROC_TABLE *, char *);
static void	alarmclk();
static void	childeath(int);
static void	cleanaux();
static void	clearent(pid_t, short);
static void	console(boolean_t, char *, ...);
static void	init_signals(void);
static void	setup_pipe();
static void	killproc(pid_t);
static void	init_env();
static void	boot_init();
static void	powerfail();
static void	remv();
static void	write_ioctl_syscon();
static void	spawn(struct PROC_TABLE *, struct CMD_LINE *);
static void	setimer(int);
static void	siglvl(int, siginfo_t *, ucontext_t *);
static void	sigpoll(int);
static void	enter_maintenance(void);
static void	timer(int);
static void	userinit(int, char **);
static void	notify_pam_dead(struct utmpx *);
static long	waitproc(struct PROC_TABLE *);
static struct PROC_TABLE *efork(int, struct PROC_TABLE *, int);
static struct PROC_TABLE *findpslot(struct CMD_LINE *);
static void	increase_proc_table_size();
static void	st_init();
static void	st_write();
static void	contracts_init();
static void	contract_event(struct pollfd *);
static int	startd_run(const char *, int, ctid_t);
static void	startd_record_failure();
static int	startd_failure_rate_critical();
static char	*audit_boot_msg();
static int	audit_put_record(int, int, char *);
static void	update_boot_archive(int new_state);

int
main(int argc, char *argv[])
{
	int	chg_lvl_flag = FALSE, print_banner = FALSE;
	int	may_need_audit = 1;
	int	c;
	char	*msg;

	/* Get a timestamp for use as boot time, if needed. */
	(void) time(&init_boot_time);

	/* Get the default umask */
	cmask = umask(022);
	(void) umask(cmask);

	/* Parse the arguments to init. Check for single user */
	opterr = 0;
	while ((c = getopt(argc, argv, "brsm:")) != EOF) {
		switch (c) {
		case 'b':
			rflg = 0;
			bflg = 1;
			if (!sflg)
				sflg++;
			break;
		case 'r':
			bflg = 0;
			rflg++;
			break;
		case 's':
			if (!bflg)
				sflg++;
			break;
		case 'm':
			smf_options = optarg;
			smf_debug = (strstr(smf_options, "debug") != NULL);
			break;
		}
	}

	/*
	 * Determine if we are the main init, or a user invoked init, whose job
	 * it is to inform init to change levels or perform some other action.
	 */
	if (zone_getattr(getzoneid(), ZONE_ATTR_INITPID, &init_pid,
	    sizeof (init_pid)) != sizeof (init_pid)) {
		(void) fprintf(stderr, "could not get pid for init\n");
		return (1);
	}

	/*
	 * If this PID is not the same as the "true" init for the zone, then we
	 * must be in 'user' mode.
	 */
	if (getpid() != init_pid) {
		userinit(argc, argv);
	}

	if (getzoneid() != GLOBAL_ZONEID) {
		print_banner = TRUE;
	}

	/*
	 * Initialize state (and set "booting").
	 */
	st_init();

	if (booting && print_banner) {
		struct utsname un;
		char buf[BUFSIZ], *isa;
		long ret;
		int bits = 32;

		/*
		 * We want to print the boot banner as soon as
		 * possible.  In the global zone, the kernel does it,
		 * but we do not have that luxury in non-global zones,
		 * so we will print it here.
		 */
		(void) uname(&un);
		ret = sysinfo(SI_ISALIST, buf, sizeof (buf));
		if (ret != -1L && ret <= sizeof (buf)) {
			for (isa = strtok(buf, " "); isa;
			    isa = strtok(NULL, " ")) {
				if (strcmp(isa, "sparcv9") == 0 ||
				    strcmp(isa, "amd64") == 0) {
					bits = 64;
					break;
				}
			}
		}

		console(B_FALSE,
		    "\n\n%s Release %s Version %s %d-bit\r\n",
		    un.sysname, un.release, un.version, bits);
		console(B_FALSE,
		    "Copyright (c) 1983, 2010, Oracle and/or its affiliates."
		    " All rights reserved.\r\n");
	}

	/*
	 * Get the ioctl settings for /dev/syscon from /etc/ioctl.syscon
	 * so that it can be brought up in the state it was in when the
	 * system went down; or set to defaults if ioctl.syscon isn't
	 * valid.
	 *
	 * This needs to be done even if we're restarting so reset_modes()
	 * will work in case we need to go down to single user mode.
	 */
	write_ioctl = get_ioctl_syscon();

	/*
	 * Set up all signals to be caught or ignored as appropriate.
	 */
	init_signals();

	/* Load glob_envp from ENVFILE. */
	init_env();

	contracts_init();

	if (!booting) {
		/* cur_state should have been read in. */

		op_modes = NORMAL_MODES;

		/* Rewrite the ioctl file if it was bad. */
		if (write_ioctl)
			write_ioctl_syscon();
	} else {
		/*
		 * It's fine to boot up with state as zero, because
		 * startd will later tell us the real state.
		 */
		cur_state = 0;
		op_modes = BOOT_MODES;

		boot_init();
	}

	prev_state = prior_state = cur_state;

	setup_pipe();

	/*
	 * Here is the beginning of the main process loop.
	 */
	for (;;) {
		if (lvlq_received) {
			setup_pipe();
			lvlq_received = B_FALSE;
		}

		/*
		 * Clean up any accounting records for dead "godchildren".
		 */
		if (Gchild)
			cleanaux();

		/*
		 * If in "normal" mode, check all living processes and initiate
		 * kill sequence on those that should not be there anymore.
		 */
		if (op_modes == NORMAL_MODES && cur_state != LVLa &&
		    cur_state != LVLb && cur_state != LVLc)
			remv();

		/*
		 * If a change in run levels is the reason we awoke, now do
		 * the accounting to report the change in the utmp file.
		 * Also report the change on the system console.
		 */
		if (chg_lvl_flag) {
			chg_lvl_flag = FALSE;

			if (state_to_flags(cur_state) & LSEL_RUNLEVEL) {
				char rl = state_to_name(cur_state);

				if (rl != -1)
					lscf_set_runlevel(rl);
			}

			may_need_audit = 1;
		}

		/*
		 * Scan the inittab file and spawn and respawn processes that
		 * should be alive in the current state. If inittab does not
		 * exist default to  single user mode.
		 */
		if (spawn_processes() == FAILURE) {
			prior_state = prev_state;
			cur_state = SINGLE_USER;
		}

		/* If any respawns occurred, take note. */
		if (rsflag) {
			rsflag = 0;
			spawncnt++;
		}

		/*
		 * If a powerfail signal was received during the last
		 * sequence, set mode to powerfail.  When spawn_processes() is
		 * entered the first thing it does is to check "powerhit".  If
		 * it is in PF_MODES then it clears "powerhit" and does
		 * a powerfail sequence.  If it is not in PF_MODES, then it
		 * puts itself in PF_MODES and then clears "powerhit".  Should
		 * "powerhit" get set again while spawn_processes() is working
		 * on a powerfail sequence, the following code  will see that
		 * spawn_processes() tries to execute the powerfail sequence
		 * again.  This guarantees that the powerfail sequence will be
		 * successfully completed before further processing takes
		 * place.
		 */
		if (wakeup.w_flags.w_powerhit) {
			op_modes = PF_MODES;
			/*
			 * Make sure that cur_state != prev_state so that
			 * ONCE and WAIT types work.
			 */
			prev_state = 0;
		} else if (op_modes != NORMAL_MODES) {
			/*
			 * If spawn_processes() was not just called while in
			 * normal mode, we set the mode to normal and it will
			 * be called again to check normal modes.  If we have
			 * just finished a powerfail sequence with prev_state
			 * equal to zero, we set prev_state equal to cur_state
			 * before the next pass through.
			 */
			if (op_modes == PF_MODES)
				prev_state = cur_state;
			op_modes = NORMAL_MODES;
		} else if (cur_state == LVLa || cur_state == LVLb ||
		    cur_state == LVLc) {
			/*
			 * If it was a change of levels that awakened us and the
			 * new level is one of the demand levels then reset
			 * cur_state to the previous state and do another scan
			 * to take care of the usual respawn actions.
			 */
			cur_state = prior_state;
			prior_state = prev_state;
			prev_state = cur_state;
		} else {
			prev_state = cur_state;

			if (wakeup.w_mask == 0) {
				int ret;

				if (may_need_audit && (cur_state == LVL3)) {
					msg = audit_boot_msg();

					may_need_audit = 0;
					(void) audit_put_record(ADT_SUCCESS,
					    ADT_SUCCESS, msg);
					free(msg);
				}

				/*
				 * "init" is finished with all actions for
				 * the current wakeup.
				 */
				ret = poll(poll_fds, poll_nfds,
				    SLEEPTIME * MILLISEC);
				pausecnt++;
				if (ret > 0)
					contract_event(&poll_fds[0]);
				else if (ret < 0 && errno != EINTR)
					console(B_TRUE, "poll() error: %s\n",
					    strerror(errno));
			}

			if (wakeup.w_flags.w_usersignal) {
				/*
				 * Install the new level.  This could be a real
				 * change in levels  or a telinit [Q|a|b|c] or
				 * just a telinit to the same level at which
				 * we are running.
				 */
				if (new_state != cur_state) {
					if (new_state == LVLa ||
					    new_state == LVLb ||
					    new_state == LVLc) {
						prev_state = prior_state;
						prior_state = cur_state;
						cur_state = new_state;
					} else {
						prev_state = cur_state;
						if (cur_state >= 0)
							prior_state = cur_state;
						cur_state = new_state;
						chg_lvl_flag = TRUE;
					}
				}

				new_state = 0;
			}

			if (wakeup.w_flags.w_powerhit)
				op_modes = PF_MODES;

			/*
			 * Clear all wakeup reasons.
			 */
			wakeup.w_mask = 0;
		}
	}

	/*NOTREACHED*/
}

static void
update_boot_archive(int new_state)
{
	if (new_state != LVL0 && new_state != LVL5 && new_state != LVL6)
		return;

	if (getzoneid() != GLOBAL_ZONEID)
		return;

	(void) system("/sbin/bootadm -ea update_all");
}

/*
 * void enter_maintenance()
 *   A simple invocation of sulogin(1M), with no baggage, in the case that we
 *   are unable to activate svc.startd(1M).  We fork; the child runs sulogin;
 *   we wait for it to exit.
 */
static void
enter_maintenance()
{
	struct PROC_TABLE	*su_process;

	console(B_FALSE, "Requesting maintenance mode\n"
	    "(See /lib/svc/share/README for additional information.)\n");
	(void) sighold(SIGCLD);
	while ((su_process = efork(M_OFF, NULLPROC, NOCLEANUP)) == NO_ROOM)
		(void) pause();
	(void) sigrelse(SIGCLD);
	if (su_process == NULLPROC) {
		int fd;

		(void) fclose(stdin);
		(void) fclose(stdout);
		(void) fclose(stderr);
		closefrom(0);

		fd = open(SYSCON, O_RDWR | O_NOCTTY);
		if (fd >= 0) {
			(void) dup2(fd, 1);
			(void) dup2(fd, 2);
		} else {
			/*
			 * Need to issue an error message somewhere.
			 */
			syslog(LOG_CRIT, "init[%d]: cannot open %s; %s\n",
			    getpid(), SYSCON, strerror(errno));
		}

		/*
		 * Execute the "su" program.
		 */
		(void) execle(SU, SU, "-", (char *)0, glob_envp);
		console(B_TRUE, "execle of %s failed: %s\n", SU,
		    strerror(errno));
		timer(5);
		exit(1);
	}

	/*
	 * If we are the parent, wait around for the child to die
	 * or for "init" to be signaled to change levels.
	 */
	while (waitproc(su_process) == FAILURE) {
		/*
		 * All other reasons for waking are ignored when in
		 * single-user mode.  The only child we are interested
		 * in is being waited for explicitly by waitproc().
		 */
		wakeup.w_mask = 0;
	}
}

/*
 * remv() scans through "proc_table" and performs cleanup.  If
 * there is a process in the table, which shouldn't be here at
 * the current run level, then remv() kills the process.
 */
static void
remv()
{
	struct PROC_TABLE	*process;
	struct CMD_LINE		cmd;
	char			cmd_string[MAXCMDL];
	int			change_level;

	change_level = (cur_state != prev_state ? TRUE : FALSE);

	/*
	 * Clear the TOUCHED flag on all entries so that when we have
	 * finished scanning inittab, we will be able to tell if we
	 * have any processes for which there is no entry in inittab.
	 */
	for (process = proc_table;
	    (process < proc_table + num_proc); process++) {
		process->p_flags &= ~TOUCHED;
	}

	/*
	 * Scan all inittab entries.
	 */
	while (getcmd(&cmd, &cmd_string[0]) == TRUE) {
		/* Scan for process which goes with this entry in inittab. */
		for (process = proc_table;
		    (process < proc_table + num_proc); process++) {
			if ((process->p_flags & OCCUPIED) == 0 ||
			    !id_eq(process->p_id, cmd.c_id))
				continue;

			/*
			 * This slot contains the process we are looking for.
			 */

			/*
			 * Is the cur_state SINGLE_USER or is this process
			 * marked as "off" or was this proc started by some
			 * mechanism other than LVL{a|b|c} and the current level
			 * does not support this process?
			 */
			if (cur_state == SINGLE_USER ||
			    cmd.c_action == M_OFF ||
			    ((cmd.c_levels & state_to_mask(cur_state)) == 0 &&
			    (process->p_flags & DEMANDREQUEST) == 0)) {
				if (process->p_flags & LIVING) {
					/*
					 * Touch this entry so we know we have
					 * treated it.  Note that procs which
					 * are already dead at this point and
					 * should not be restarted are left
					 * untouched.  This causes their slot to
					 * be freed later after dead accounting
					 * is done.
					 */
					process->p_flags |= TOUCHED;

					if ((process->p_flags & KILLED) == 0) {
						if (change_level) {
							process->p_flags
							    |= WARNED;
							(void) kill(
							    process->p_pid,
							    SIGTERM);
						} else {
							/*
							 * Fork a killing proc
							 * so "init" can
							 * continue without
							 * having to pause for
							 * TWARN seconds.
							 */
							killproc(
							    process->p_pid);
						}
						process->p_flags |= KILLED;
					}
				}
			} else {
				/*
				 * Process can exist at current level.  If it is
				 * still alive or a DEMANDREQUEST we touch it so
				 * it will be left alone.  Otherwise we leave it
				 * untouched so it will be accounted for and
				 * cleaned up later in remv().  Dead
				 * DEMANDREQUESTs will be accounted but not
				 * freed.
				 */
				if (process->p_flags &
				    (LIVING|NOCLEANUP|DEMANDREQUEST))
					process->p_flags |= TOUCHED;
			}

			break;
		}
	}

	st_write();

	/*
	 * If this was a change of levels call, scan through the
	 * process table for processes that were warned to die.  If any
	 * are found that haven't left yet, sleep for TWARN seconds and
	 * then send final terminations to any that haven't died yet.
	 */
	if (change_level) {

		/*
		 * Set the alarm for TWARN seconds on the assumption
		 * that there will be some that need to be waited for.
		 * This won't harm anything except we are guaranteed to
		 * wakeup in TWARN seconds whether we need to or not.
		 */
		setimer(TWARN);

		/*
		 * Scan for processes which should be dying.  We hope they
		 * will die without having to be sent a SIGKILL signal.
		 */
		for (process = proc_table;
		    (process < proc_table + num_proc); process++) {
			/*
			 * If this process should die, hasn't yet, and the
			 * TWARN time hasn't expired yet, wait for process
			 * to die or for timer to expire.
			 */
			while (time_up == FALSE &&
			    (process->p_flags & (WARNED|LIVING|OCCUPIED)) ==
			    (WARNED|LIVING|OCCUPIED))
				(void) pause();

			if (time_up == TRUE)
				break;
		}

		/*
		 * If we reached the end of the table without the timer
		 * expiring, then there are no procs which will have to be
		 * sent the SIGKILL signal.  If the timer has expired, then
		 * it is necessary to scan the table again and send signals
		 * to all processes which aren't going away nicely.
		 */
		if (time_up == TRUE) {
			for (process = proc_table;
			    (process < proc_table + num_proc); process++) {
				if ((process->p_flags &
				    (WARNED|LIVING|OCCUPIED)) ==
				    (WARNED|LIVING|OCCUPIED))
					(void) kill(process->p_pid, SIGKILL);
			}
		}
		setimer(0);
	}

	/*
	 * Rescan the proc_table for two kinds of entry, those marked LIVING,
	 * NAMED, which don't have an entry in inittab (haven't been TOUCHED
	 * by the above scanning), and haven't been sent kill signals, and
	 * those entries marked not LIVING, NAMED.  The former procs are killed.
	 * The latter have DEAD_PROCESS accounting done and the slot cleared.
	 */
	for (process = proc_table;
	    (process < proc_table + num_proc); process++) {
		if ((process->p_flags & (LIVING|NAMED|TOUCHED|KILLED|OCCUPIED))
		    == (LIVING|NAMED|OCCUPIED)) {
			killproc(process->p_pid);
			process->p_flags |= KILLED;
		} else if ((process->p_flags & (LIVING|NAMED|OCCUPIED)) ==
		    (NAMED|OCCUPIED)) {
			(void) account(DEAD_PROCESS, process, NULL);
			/*
			 * If this named proc hasn't been TOUCHED, then free the
			 * space. It has either died of it's own accord, but
			 * isn't respawnable or it was killed because it
			 * shouldn't exist at this level.
			 */
			if ((process->p_flags & TOUCHED) == 0)
				process->p_flags = 0;
		}
	}

	st_write();
}

/*
 * Extract the svc.startd command line and whether to restart it from its
 * inittab entry.
 */
/*ARGSUSED*/
static void
process_startd_line(struct CMD_LINE *cmd, char *cmd_string)
{
	size_t sz;

	/* Save the command line. */
	if (sflg || rflg) {
		/* Also append -r or -s. */
		(void) strlcpy(startd_cline, cmd_string, sizeof (startd_cline));
		(void) strlcat(startd_cline, " -", sizeof (startd_cline));
		if (sflg)
			sz = strlcat(startd_cline, "s", sizeof (startd_cline));
		if (rflg)
			sz = strlcat(startd_cline, "r", sizeof (startd_cline));
	} else {
		sz = strlcpy(startd_cline, cmd_string, sizeof (startd_cline));
	}

	if (sz >= sizeof (startd_cline)) {
		console(B_TRUE,
		    "svc.startd command line too long.  Ignoring.\n");
		startd_cline[0] = '\0';
		return;
	}
}

/*
 * spawn_processes() scans inittab for entries which should be run at this
 * mode.  Processes which should be running but are not, are started.
 */
static int
spawn_processes()
{
	struct PROC_TABLE		*pp;
	struct CMD_LINE			cmd;
	char				cmd_string[MAXCMDL];
	short				lvl_mask;
	int				status;

	/*
	 * First check the "powerhit" flag.  If it is set, make sure the modes
	 * are PF_MODES and clear the "powerhit" flag.  Avoid the possible race
	 * on the "powerhit" flag by disallowing a new powerfail interrupt
	 * between the test of the powerhit flag and the clearing of it.
	 */
	if (wakeup.w_flags.w_powerhit) {
		wakeup.w_flags.w_powerhit = 0;
		op_modes = PF_MODES;
	}
	lvl_mask = state_to_mask(cur_state);

	/*
	 * Scan through all the entries in inittab.
	 */
	while ((status = getcmd(&cmd, &cmd_string[0])) == TRUE) {
		if (id_eq(cmd.c_id, "smf")) {
			process_startd_line(&cmd, cmd_string);
			continue;
		}

retry_for_proc_slot:

		/*
		 * Find out if there is a process slot for this entry already.
		 */
		if ((pp = findpslot(&cmd)) == NULLPROC) {
			/*
			 * we've run out of proc table entries
			 * increase proc_table.
			 */
			increase_proc_table_size();

			/*
			 * Retry now as we have an empty proc slot.
			 * In case increase_proc_table_size() fails,
			 * we will keep retrying.
			 */
			goto retry_for_proc_slot;
		}

		/*
		 * If there is an entry, and it is marked as DEMANDREQUEST,
		 * one of the levels a, b, or c is in its levels mask, and
		 * the action field is ONDEMAND and ONDEMAND is a permissable
		 * mode, and the process is dead, then respawn it.
		 */
		if (((pp->p_flags & (LIVING|DEMANDREQUEST)) == DEMANDREQUEST) &&
		    (cmd.c_levels & MASK_abc) &&
		    (cmd.c_action & op_modes) == M_ONDEMAND) {
			spawn(pp, &cmd);
			continue;
		}

		/*
		 * If the action is not an action we are interested in,
		 * skip the entry.
		 */
		if ((cmd.c_action & op_modes) == 0 || pp->p_flags & LIVING ||
		    (cmd.c_levels & lvl_mask) == 0)
			continue;

		/*
		 * If the modes are the normal modes (ONCE, WAIT, RESPAWN, OFF,
		 * ONDEMAND) and the action field is either OFF or the action
		 * field is ONCE or WAIT and the current level is the same as
		 * the last level, then skip this entry.  ONCE and WAIT only
		 * get run when the level changes.
		 */
		if (op_modes == NORMAL_MODES &&
		    (cmd.c_action == M_OFF ||
		    (cmd.c_action & (M_ONCE|M_WAIT)) &&
		    cur_state == prev_state))
			continue;

		/*
		 * At this point we are interested in performing the action for
		 * this entry.  Actions fall into two categories, spinning off
		 * a process and not waiting, and spinning off a process and
		 * waiting for it to die.  If the action is ONCE, RESPAWN,
		 * ONDEMAND, POWERFAIL, or BOOT we don't wait for the process
		 * to die, for all other actions we do wait.
		 */
		if (cmd.c_action & (M_ONCE | M_RESPAWN | M_PF | M_BOOT)) {
			spawn(pp, &cmd);

		} else {
			spawn(pp, &cmd);
			while (waitproc(pp) == FAILURE)
				;
			(void) account(DEAD_PROCESS, pp, NULL);
			pp->p_flags = 0;
		}
	}
	return (status);
}

/*
 * spawn() spawns a shell, inserts the information about the process
 * process into the proc_table, and does the startup accounting.
 */
static void
spawn(struct PROC_TABLE *process, struct CMD_LINE *cmd)
{
	int		i;
	int		modes, maxfiles;
	time_t		now;
	struct PROC_TABLE tmproc, *oprocess;

	/*
	 * The modes to be sent to efork() are 0 unless we are
	 * spawning a LVLa, LVLb, or LVLc entry or we will be
	 * waiting for the death of the child before continuing.
	 */
	modes = NAMED;
	if (process->p_flags & DEMANDREQUEST || cur_state == LVLa ||
	    cur_state == LVLb || cur_state == LVLc)
		modes |= DEMANDREQUEST;
	if ((cmd->c_action & (M_SYSINIT | M_WAIT | M_BOOTWAIT | M_PWAIT)) != 0)
		modes |= NOCLEANUP;

	/*
	 * If this is a respawnable process, check the threshold
	 * information to avoid excessive respawns.
	 */
	if (cmd->c_action & M_RESPAWN) {
		/*
		 * Add NOCLEANUP to all respawnable commands so that the
		 * information about the frequency of respawns isn't lost.
		 */
		modes |= NOCLEANUP;
		(void) time(&now);

		/*
		 * If no time is assigned, then this is the first time
		 * this command is being processed in this series.  Assign
		 * the current time.
		 */
		if (process->p_time == 0L)
			process->p_time = now;

		if (process->p_count++ == SPAWN_LIMIT) {

			if ((now - process->p_time) < SPAWN_INTERVAL) {
				/*
				 * Process is respawning too rapidly.  Print
				 * message and refuse to respawn it for now.
				 */
				console(B_TRUE, "Command is respawning too "
				    "rapidly. Check for possible errors.\n"
				    "id:%4s \"%s\"\n",
				    &cmd->c_id[0], &cmd->c_command[EXEC]);
				return;
			}
			process->p_time = now;
			process->p_count = 0;

		} else if (process->p_count > SPAWN_LIMIT) {
			/*
			 * If process has been respawning too rapidly and
			 * the inhibit time limit hasn't expired yet, we
			 * refuse to respawn.
			 */
			if (now - process->p_time < SPAWN_INTERVAL + INHIBIT)
				return;
			process->p_time = now;
			process->p_count = 0;
		}
		rsflag = TRUE;
	}

	/*
	 * Spawn a child process to execute this command.
	 */
	(void) sighold(SIGCLD);
	oprocess = process;
	while ((process = efork(cmd->c_action, oprocess, modes)) == NO_ROOM)
		(void) pause();

	if (process == NULLPROC) {

		/*
		 * We are the child.  We must make sure we get a different
		 * file pointer for our references to utmpx.  Otherwise our
		 * seeks and reads will compete with those of the parent.
		 */
		endutxent();

		/*
		 * Perform the accounting for the beginning of a process.
		 * Note that all processes are initially "INIT_PROCESS"es.
		 */
		tmproc.p_id[0] = cmd->c_id[0];
		tmproc.p_id[1] = cmd->c_id[1];
		tmproc.p_id[2] = cmd->c_id[2];
		tmproc.p_id[3] = cmd->c_id[3];
		tmproc.p_pid = getpid();
		tmproc.p_exit = 0;
		(void) account(INIT_PROCESS, &tmproc,
		    prog_name(&cmd->c_command[EXEC]));
		maxfiles = ulimit(UL_GDESLIM, 0);
		for (i = 0; i < maxfiles; i++)
			(void) fcntl(i, F_SETFD, FD_CLOEXEC);

		/*
		 * Now exec a shell with the -c option and the command
		 * from inittab.
		 */
		(void) execle(SH, "INITSH", "-c", cmd->c_command, (char *)0,
		    glob_envp);
		console(B_TRUE, "Command\n\"%s\"\n failed to execute.  errno "
		    "= %d (exec of shell failed)\n", cmd->c_command, errno);

		/*
		 * Don't come back so quickly that "init" doesn't have a
		 * chance to finish putting this child in "proc_table".
		 */
		timer(20);
		exit(1);

	}

	/*
	 * We are the parent.  Insert the necessary
	 * information in the proc_table.
	 */
	process->p_id[0] = cmd->c_id[0];
	process->p_id[1] = cmd->c_id[1];
	process->p_id[2] = cmd->c_id[2];
	process->p_id[3] = cmd->c_id[3];

	st_write();

	(void) sigrelse(SIGCLD);
}

/*
 * findpslot() finds the old slot in the process table for the
 * command with the same id, or it finds an empty slot.
 */
static struct PROC_TABLE *
findpslot(struct CMD_LINE *cmd)
{
	struct PROC_TABLE	*process;
	struct PROC_TABLE	*empty = NULLPROC;

	for (process = proc_table;
	    (process < proc_table + num_proc); process++) {
		if (process->p_flags & OCCUPIED &&
		    id_eq(process->p_id, cmd->c_id))
			break;

		/*
		 * If the entry is totally empty and "empty" is still 0,
		 * remember where this hole is and make sure the slot is
		 * zeroed out.
		 */
		if (empty == NULLPROC && (process->p_flags & OCCUPIED) == 0) {
			empty = process;
			process->p_id[0] = '\0';
			process->p_id[1] = '\0';
			process->p_id[2] = '\0';
			process->p_id[3] = '\0';
			process->p_pid = 0;
			process->p_time = 0L;
			process->p_count = 0;
			process->p_flags = 0;
			process->p_exit = 0;
		}
	}

	/*
	 * If there is no entry for this slot, then there should be an
	 * empty slot.  If there is no empty slot, then we've run out
	 * of proc_table space.  If the latter is true, empty will be
	 * NULL and the caller will have to complain.
	 */
	if (process == (proc_table + num_proc))
		process = empty;

	return (process);
}

/*
 * getcmd() parses lines from inittab.  Each time it finds a command line
 * it will return TRUE as well as fill the passed CMD_LINE structure and
 * the shell command string.  When the end of inittab is reached, FALSE
 * is returned inittab is automatically opened if it is not currently open
 * and is closed when the end of the file is reached.
 */
static FILE *fp_inittab = NULL;

static int
getcmd(struct CMD_LINE *cmd, char *shcmd)
{
	char	*ptr;
	int	c, lastc, state;
	char 	*ptr1;
	int	answer, i, proceed;
	struct	stat	sbuf;
	static char *actions[] = {
		"off", "respawn", "ondemand", "once", "wait", "boot",
		"bootwait", "powerfail", "powerwait", "initdefault",
		"sysinit",
	};
	static short act_masks[] = {
		M_OFF, M_RESPAWN, M_ONDEMAND, M_ONCE, M_WAIT, M_BOOT,
		M_BOOTWAIT, M_PF, M_PWAIT, M_INITDEFAULT, M_SYSINIT,
	};
	/*
	 * Only these actions will be allowed for entries which
	 * are specified for single-user mode.
	 */
	short su_acts = M_INITDEFAULT | M_PF | M_PWAIT | M_WAIT;

	if (fp_inittab == NULL) {
		/*
		 * Before attempting to open inittab we stat it to make
		 * sure it currently exists and is not empty.  We try
		 * several times because someone may have temporarily
		 * unlinked or truncated the file.
		 */
		for (i = 0; i < 3; i++) {
			if (stat(INITTAB, &sbuf) == -1) {
				if (i == 2) {
					console(B_TRUE,
					    "Cannot stat %s, errno: %d\n",
					    INITTAB, errno);
					return (FAILURE);
				} else {
					timer(3);
				}
			} else if (sbuf.st_size < 10) {
				if (i == 2) {
					console(B_TRUE,
					    "%s truncated or corrupted\n",
					    INITTAB);
					return (FAILURE);
				} else {
					timer(3);
				}
			} else {
				break;
			}
		}

		/*
		 * If unable to open inittab, print error message and
		 * return FAILURE to caller.
		 */
		if ((fp_inittab = fopen(INITTAB, "r")) == NULL) {
			console(B_TRUE, "Cannot open %s errno: %d\n", INITTAB,
			    errno);
			return (FAILURE);
		}
	}

	/*
	 * Keep getting commands from inittab until you find a
	 * good one or run out of file.
	 */
	for (answer = FALSE; answer == FALSE; ) {
		/*
		 * Zero out the cmd itself before trying next line.
		 */
		bzero(cmd, sizeof (struct CMD_LINE));

		/*
		 * Read in lines of inittab, parsing at colons, until a line is
		 * read in which doesn't end with a backslash.  Do not start if
		 * the first character read is an EOF.  Note that this means
		 * that lines which don't end in a newline are still processed,
		 * since the "for" will terminate normally once started,
		 * regardless of whether line terminates with a newline or EOF.
		 */
		state = FAILURE;
		if ((c = fgetc(fp_inittab)) == EOF) {
			answer = FALSE;
			(void) fclose(fp_inittab);
			fp_inittab = NULL;
			break;
		}

		for (proceed = TRUE, ptr = shcmd, state = ID, lastc = '\0';
		    proceed && c != EOF;
		    lastc = c, c = fgetc(fp_inittab)) {
			/* If we're not in the FAILURE state and haven't */
			/* yet reached the shell command field, process	 */
			/* the line, otherwise just look for a real end	 */
			/* of line.					 */
			if (state != FAILURE && state != COMMAND) {
			/*
			 * Squeeze out spaces and tabs.
			 */
			if (c == ' ' || c == '\t')
				continue;

			/*
			 * Ignore characters in a comment, except for the \n.
			 */
			if (state == COMMENT) {
				if (c == '\n') {
					lastc = ' ';
					break;
				} else {
					continue;
				}
			}

			/*
			 * Detect comments (lines whose first non-whitespace
			 * character is '#') by checking that we're at the
			 * beginning of a line, have seen a '#', and haven't
			 * yet accumulated any characters.
			 */
			if (state == ID && c == '#' && ptr == shcmd) {
				state = COMMENT;
				continue;
			}

			/*
			 * If the character is a ':', then check the
			 * previous field for correctness and advance
			 * to the next field.
			 */
			if (c == ':') {
				switch (state) {

				case ID :
				/*
				 * Check to see that there are only
				 * 1 to 4 characters for the id.
				 */
				if ((i = ptr - shcmd) < 1 || i > 4) {
					state = FAILURE;
				} else {
					bcopy(shcmd, &cmd->c_id[0], i);
					ptr = shcmd;
					state = LEVELS;
				}
				break;

				case LEVELS :
				/*
				 * Build a mask for all the levels for
				 * which this command will be legal.
				 */
				for (cmd->c_levels = 0, ptr1 = shcmd;
				    ptr1 < ptr; ptr1++) {
					int mask;
					if (lvlname_to_mask(*ptr1,
					    &mask) == -1) {
						state = FAILURE;
						break;
					}
					cmd->c_levels |= mask;
				}
				if (state != FAILURE) {
					state = ACTION;
					ptr = shcmd;	/* Reset the buffer */
				}
				break;

				case ACTION :
				/*
				 * Null terminate the string in shcmd buffer and
				 * then try to match against legal actions.  If
				 * the field is of length 0, then the default of
				 * "RESPAWN" is used if the id is numeric,
				 * otherwise the default is "OFF".
				 */
				if (ptr == shcmd) {
					if (isdigit(cmd->c_id[0]) &&
					    (cmd->c_id[1] == '\0' ||
					    isdigit(cmd->c_id[1])) &&
					    (cmd->c_id[2] == '\0' ||
					    isdigit(cmd->c_id[2])) &&
					    (cmd->c_id[3] == '\0' ||
					    isdigit(cmd->c_id[3])))
						cmd->c_action = M_RESPAWN;
					else
						cmd->c_action = M_OFF;
				} else {
					for (cmd->c_action = 0, i = 0,
					    *ptr = '\0';
					    i <
					    sizeof (actions)/sizeof (char *);
					    i++) {
					if (strcmp(shcmd, actions[i]) == 0) {
						if ((cmd->c_levels & MASKSU) &&
						    !(act_masks[i] & su_acts))
							cmd->c_action = 0;
						else
							cmd->c_action =
							    act_masks[i];
						break;
					}
					}
				}

				/*
				 * If the action didn't match any legal action,
				 * set state to FAILURE.
				 */
				if (cmd->c_action == 0) {
					state = FAILURE;
				} else {
					state = COMMAND;
					(void) strcpy(shcmd, "exec ");
				}
				ptr = shcmd + EXEC;
				break;
				}
				continue;
			}
		}

		/* If the character is a '\n', then this is the end of a */
		/* line.  If the '\n' wasn't preceded by a backslash, */
		/* it is also the end of an inittab command.  If it was */
		/* preceded by a backslash then the next line is a */
		/* continuation.  Note that the continuation '\n' falls */
		/* through and is treated like other characters and is */
		/* stored in the shell command line. */
		if (c == '\n' && lastc != '\\') {
			proceed = FALSE;
			*ptr = '\0';
			break;
		}

		/* For all other characters just stuff them into the */
		/* command as long as there aren't too many of them. */
		/* Make sure there is room for a terminating '\0' also. */
		if (ptr >= shcmd + MAXCMDL - 1)
			state = FAILURE;
		else
			*ptr++ = (char)c;

		/* If the character we just stored was a quoted	*/
		/* backslash, then change "c" to '\0', so that this	*/
		/* backslash will not cause a subsequent '\n' to appear */
		/* quoted.  In otherwords '\' '\' '\n' is the real end */
		/* of a command, while '\' '\n' is a continuation. */
		if (c == '\\' && lastc == '\\')
			c = '\0';
		}

		/*
		 * Make sure all the fields are properly specified
		 * for a good command line.
		 */
		if (state == COMMAND) {
			answer = TRUE;
			cmd->c_command = shcmd;

			/*
			 * If no default level was supplied, insert
			 * all numerical levels.
			 */
			if (cmd->c_levels == 0)
				cmd->c_levels = MASK_NUMERIC;

			/*
			 * If no action has been supplied, declare this
			 * entry to be OFF.
			 */
			if (cmd->c_action == 0)
				cmd->c_action = M_OFF;

			/*
			 * If no shell command has been supplied, make sure
			 * there is a null string in the command field.
			 */
			if (ptr == shcmd + EXEC)
				*shcmd = '\0';
		} else
			answer = FALSE;

		/*
		 * If we have reached the end of inittab, then close it
		 * and quit trying to find a good command line.
		 */
		if (c == EOF) {
			(void) fclose(fp_inittab);
			fp_inittab = NULL;
			break;
		}
	}
	return (answer);
}

/*
 * lvlname_to_state(): convert the character name of a state to its level
 * (its corresponding signal number).
 */
static int
lvlname_to_state(char name)
{
	int i;
	for (i = 0; i < LVL_NELEMS; i++) {
		if (lvls[i].lvl_name == name)
			return (lvls[i].lvl_state);
	}
	return (-1);
}

/*
 * state_to_name(): convert the level to the character name.
 */
static char
state_to_name(int state)
{
	int i;
	for (i = 0; i < LVL_NELEMS; i++) {
		if (lvls[i].lvl_state == state)
			return (lvls[i].lvl_name);
	}
	return (-1);
}

/*
 * state_to_mask(): return the mask corresponding to a signal number
 */
static int
state_to_mask(int state)
{
	int i;
	for (i = 0; i < LVL_NELEMS; i++) {
		if (lvls[i].lvl_state == state)
			return (lvls[i].lvl_mask);
	}
	return (0);	/* return 0, since that represents an empty mask */
}

/*
 * lvlname_to_mask(): return the mask corresponding to a levels character name
 */
static int
lvlname_to_mask(char name, int *mask)
{
	int i;
	for (i = 0; i < LVL_NELEMS; i++) {
		if (lvls[i].lvl_name == name) {
			*mask = lvls[i].lvl_mask;
			return (0);
		}
	}
	return (-1);
}

/*
 * state_to_flags(): return the flags corresponding to a runlevel.  These
 * indicate properties of that runlevel.
 */
static int
state_to_flags(int state)
{
	int i;
	for (i = 0; i < LVL_NELEMS; i++) {
		if (lvls[i].lvl_state == state)
			return (lvls[i].lvl_flags);
	}
	return (0);
}

/*
 * killproc() creates a child which kills the process specified by pid.
 */
void
killproc(pid_t pid)
{
	struct PROC_TABLE	*process;

	(void) sighold(SIGCLD);
	while ((process = efork(M_OFF, NULLPROC, 0)) == NO_ROOM)
		(void) pause();
	(void) sigrelse(SIGCLD);

	if (process == NULLPROC) {
		/*
		 * efork() sets all signal handlers to the default, so reset
		 * the ALRM handler to make timer() work as expected.
		 */
		(void) sigset(SIGALRM, alarmclk);

		/*
		 * We are the child.  Try to terminate the process nicely
		 * first using SIGTERM and if it refuses to die in TWARN
		 * seconds kill it with SIGKILL.
		 */
		(void) kill(pid, SIGTERM);
		(void) timer(TWARN);
		(void) kill(pid, SIGKILL);
		(void) exit(0);
	}
}

/*
 * Set up the default environment for all procs to be forked from init.
 * Read the values from the /etc/default/init file, except for PATH.  If
 * there's not enough room in the environment array, the environment
 * lines that don't fit are silently discarded.
 */
void
init_env()
{
	char	line[MAXCMDL];
	FILE	*fp;
	int	inquotes, length, wslength;
	char	*tokp, *cp1, *cp2;

	glob_envp[0] = malloc((unsigned)(strlen(DEF_PATH)+2));
	(void) strcpy(glob_envp[0], DEF_PATH);
	glob_envn = 1;

	if (rflg) {
		glob_envp[1] =
		    malloc((unsigned)(strlen("_DVFS_RECONFIG=YES")+2));
		(void) strcpy(glob_envp[1], "_DVFS_RECONFIG=YES");
		++glob_envn;
	} else if (bflg == 1) {
		glob_envp[1] =
		    malloc((unsigned)(strlen("RB_NOBOOTRC=YES")+2));
		(void) strcpy(glob_envp[1], "RB_NOBOOTRC=YES");
		++glob_envn;
	}

	if ((fp = fopen(ENVFILE, "r")) == NULL) {
		console(B_TRUE,
		    "Cannot open %s. Environment not initialized.\n",
		    ENVFILE);
	} else {
		while (fgets(line, MAXCMDL - 1, fp) != NULL &&
		    glob_envn < MAXENVENT - 2) {
			/*
			 * Toss newline
			 */
			length = strlen(line);
			if (line[length - 1] == '\n')
				line[length - 1] = '\0';

			/*
			 * Ignore blank or comment lines.
			 */
			if (line[0] == '#' || line[0] == '\0' ||
			    (wslength = strspn(line, " \t\n")) ==
			    strlen(line) ||
			    strchr(line, '#') == line + wslength)
				continue;

			/*
			 * First make a pass through the line and change
			 * any non-quoted semi-colons to blanks so they
			 * will be treated as token separators below.
			 */
			inquotes = 0;
			for (cp1 = line; *cp1 != '\0'; cp1++) {
				if (*cp1 == '"') {
					if (inquotes == 0)
						inquotes = 1;
					else
						inquotes = 0;
				} else if (*cp1 == ';') {
					if (inquotes == 0)
						*cp1 = ' ';
				}
			}

			/*
			 * Tokens within the line are separated by blanks
			 *  and tabs.  For each token in the line which
			 * contains a '=' we strip out any quotes and then
			 * stick the token in the environment array.
			 */
			if ((tokp = strtok(line, " \t")) == NULL)
				continue;
			do {
				if (strchr(tokp, '=') == NULL)
					continue;
				length = strlen(tokp);
				while ((cp1 = strpbrk(tokp, "\"\'")) != NULL) {
					for (cp2 = cp1;
					    cp2 < &tokp[length]; cp2++)
						*cp2 = *(cp2 + 1);
					length--;
				}

				if (strncmp(tokp, "CMASK=",
				    sizeof ("CMASK=") - 1) == 0) {
					long t;

					/* We know there's an = */
					t = strtol(strchr(tokp, '=') + 1, NULL,
					    8);

					/* Sanity */
					if (t <= 077 && t >= 0)
						cmask = (int)t;
					(void) umask(cmask);
					continue;
				}
				glob_envp[glob_envn] =
				    malloc((unsigned)(length + 1));
				(void) strcpy(glob_envp[glob_envn], tokp);
				if (++glob_envn >= MAXENVENT - 1)
					break;
			} while ((tokp = strtok(NULL, " \t")) != NULL);
		}

		/*
		 * Append a null pointer to the environment array
		 * to mark its end.
		 */
		glob_envp[glob_envn] = NULL;
		(void) fclose(fp);
	}
}

/*
 * boot_init(): Do initialization things that should be done at boot.
 */
void
boot_init()
{
	int i;
	struct PROC_TABLE *process, *oprocess;
	struct CMD_LINE	cmd;
	char	line[MAXCMDL];
	char	svc_aux[SVC_AUX_SIZE];
	char	init_svc_fmri[SVC_FMRI_SIZE];
	char *old_path;
	int maxfiles;

	/* Use INIT_PATH for sysinit cmds */
	old_path = glob_envp[0];
	glob_envp[0] = malloc((unsigned)(strlen(INIT_PATH)+2));
	(void) strcpy(glob_envp[0], INIT_PATH);

	/*
	 * Scan inittab(4) and process the special svc.startd entry, initdefault
	 * and sysinit entries.
	 */
	while (getcmd(&cmd, &line[0]) == TRUE) {
		if (startd_tmpl >= 0 && id_eq(cmd.c_id, "smf")) {
			process_startd_line(&cmd, line);
			(void) snprintf(startd_svc_aux, SVC_AUX_SIZE,
			    INITTAB_ENTRY_ID_STR_FORMAT, cmd.c_id);
		} else if (cmd.c_action == M_INITDEFAULT) {
			/*
			 * initdefault is no longer meaningful, as the SMF
			 * milestone controls what (legacy) run level we
			 * boot to.
			 */
			console(B_TRUE,
			    "Ignoring legacy \"initdefault\" entry.\n");
		} else if (cmd.c_action == M_SYSINIT) {
			/*
			 * Execute the "sysinit" entry and wait for it to
			 * complete.  No bookkeeping is performed on these
			 * entries because we avoid writing to the file system
			 * until after there has been an chance to check it.
			 */
			if (process = findpslot(&cmd)) {
				(void) sighold(SIGCLD);
				(void) snprintf(svc_aux, SVC_AUX_SIZE,
				    INITTAB_ENTRY_ID_STR_FORMAT, cmd.c_id);
				(void) snprintf(init_svc_fmri, SVC_FMRI_SIZE,
				    SVC_INIT_PREFIX INITTAB_ENTRY_ID_STR_FORMAT,
				    cmd.c_id);
				if (legacy_tmpl >= 0) {
					(void) ct_pr_tmpl_set_svc_fmri(
					    legacy_tmpl, init_svc_fmri);
					(void) ct_pr_tmpl_set_svc_aux(
					    legacy_tmpl, svc_aux);
				}

				for (oprocess = process;
				    (process = efork(M_OFF, oprocess,
				    (NAMED|NOCLEANUP))) == NO_ROOM;
				    /* CSTYLED */)
					;
				(void) sigrelse(SIGCLD);

				if (process == NULLPROC) {
					maxfiles = ulimit(UL_GDESLIM, 0);

					for (i = 0; i < maxfiles; i++)
						(void) fcntl(i, F_SETFD,
						    FD_CLOEXEC);
					(void) execle(SH, "INITSH", "-c",
					    cmd.c_command,
					    (char *)0, glob_envp);
					console(B_TRUE,
"Command\n\"%s\"\n failed to execute.  errno = %d (exec of shell failed)\n",
					    cmd.c_command, errno);
					exit(1);
				} else
					while (waitproc(process) == FAILURE)
						;
				process->p_flags = 0;
				st_write();
			}
		}
	}

	/* Restore the path. */
	free(glob_envp[0]);
	glob_envp[0] = old_path;

	/*
	 * This will enable st_write() to complain about init_state_file.
	 */
	booting = 0;

	/*
	 * If the /etc/ioctl.syscon didn't exist or had invalid contents write
	 * out a correct version.
	 */
	if (write_ioctl)
		write_ioctl_syscon();

	/*
	 * Start svc.startd(1M), which does most of the work.
	 */
	if (startd_cline[0] != '\0' && startd_tmpl >= 0) {
		/* Start svc.startd. */
		if (startd_run(startd_cline, startd_tmpl, 0) == -1)
			cur_state = SINGLE_USER;
	} else {
		console(B_TRUE, "Absent svc.startd entry or bad "
		    "contract template.  Not starting svc.startd.\n");
		enter_maintenance();
	}
}

/*
 * init_signals(): Initialize all signals to either be caught or ignored.
 */
void
init_signals(void)
{
	struct sigaction act;
	int i;

	/*
	 * Start by ignoring all signals, then selectively re-enable some.
	 * The SIG_IGN disposition will only affect asynchronous signals:
	 * any signal that we trigger synchronously that doesn't end up
	 * being handled by siglvl() will be forcibly delivered by the kernel.
	 */
	for (i = SIGHUP; i <= SIGRTMAX; i++)
		(void) sigset(i, SIG_IGN);

	/*
	 * Handle all level-changing signals using siglvl() and set sa_mask so
	 * that all level-changing signals are blocked while in siglvl().
	 */
	act.sa_handler = siglvl;
	act.sa_flags = SA_SIGINFO;
	(void) sigemptyset(&act.sa_mask);

	(void) sigaddset(&act.sa_mask, LVLQ);
	(void) sigaddset(&act.sa_mask, LVL0);
	(void) sigaddset(&act.sa_mask, LVL1);
	(void) sigaddset(&act.sa_mask, LVL2);
	(void) sigaddset(&act.sa_mask, LVL3);
	(void) sigaddset(&act.sa_mask, LVL4);
	(void) sigaddset(&act.sa_mask, LVL5);
	(void) sigaddset(&act.sa_mask, LVL6);
	(void) sigaddset(&act.sa_mask, SINGLE_USER);
	(void) sigaddset(&act.sa_mask, LVLa);
	(void) sigaddset(&act.sa_mask, LVLb);
	(void) sigaddset(&act.sa_mask, LVLc);

	(void) sigaction(LVLQ, &act, NULL);
	(void) sigaction(LVL0, &act, NULL);
	(void) sigaction(LVL1, &act, NULL);
	(void) sigaction(LVL2, &act, NULL);
	(void) sigaction(LVL3, &act, NULL);
	(void) sigaction(LVL4, &act, NULL);
	(void) sigaction(LVL5, &act, NULL);
	(void) sigaction(LVL6, &act, NULL);
	(void) sigaction(SINGLE_USER, &act, NULL);
	(void) sigaction(LVLa, &act, NULL);
	(void) sigaction(LVLb, &act, NULL);
	(void) sigaction(LVLc, &act, NULL);

	(void) sigset(SIGALRM, alarmclk);
	alarmclk();

	(void) sigset(SIGCLD, childeath);
	(void) sigset(SIGPWR, powerfail);
}

/*
 * Set up pipe for "godchildren". If the file exists and is a pipe just open
 * it. Else, if the file system is r/w create it.  Otherwise, defer its
 * creation and open until after /var/run has been mounted.  This function is
 * only called on startup and when explicitly requested via LVLQ.
 */
void
setup_pipe()
{
	struct stat stat_buf;
	struct statvfs statvfs_buf;
	struct sigaction act;

	/*
	 * Always close the previous pipe descriptor as the mounted filesystems
	 * may have changed.
	 */
	if (Pfd >= 0)
		(void) close(Pfd);

	if ((stat(INITPIPE, &stat_buf) == 0) &&
	    ((stat_buf.st_mode & (S_IFMT|S_IRUSR)) == (S_IFIFO|S_IRUSR)))
		Pfd = open(INITPIPE, O_RDWR | O_NDELAY);
	else
		if ((statvfs(INITPIPE_DIR, &statvfs_buf) == 0) &&
		    ((statvfs_buf.f_flag & ST_RDONLY) == 0)) {
			(void) unlink(INITPIPE);
			(void) mknod(INITPIPE, S_IFIFO | 0600, 0);
			Pfd = open(INITPIPE, O_RDWR | O_NDELAY);
		}

	if (Pfd >= 0) {
		(void) ioctl(Pfd, I_SETSIG, S_INPUT);
		/*
		 * Read pipe in message discard mode.
		 */
		(void) ioctl(Pfd, I_SRDOPT, RMSGD);

		act.sa_handler = sigpoll;
		act.sa_flags = 0;
		(void) sigemptyset(&act.sa_mask);
		(void) sigaddset(&act.sa_mask, SIGCLD);
		(void) sigaction(SIGPOLL, &act, NULL);
	}
}

/*
 * siglvl - handle an asynchronous signal from init(1M) telling us that we
 * should change the current run level.  We set new_state accordingly.
 */
void
siglvl(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	struct PROC_TABLE *process;
	struct sigaction act;

	/*
	 * If the signal was from the kernel (rather than init(1M)) then init
	 * itself tripped the signal.  That is, we might have a bug and tripped
	 * a real SIGSEGV instead of receiving it as an alias for SIGLVLa.  In
	 * such a case we reset the disposition to SIG_DFL, block all signals
	 * in uc_mask but the current one, and return to the interrupted ucp
	 * to effect an appropriate death.  The kernel will then restart us.
	 *
	 * The one exception to SI_FROMKERNEL() is SIGFPE (a.k.a. LVL6), which
	 * the kernel can send us when it wants to effect an orderly reboot.
	 * For this case we must also verify si_code is zero, rather than a
	 * code such as FPE_INTDIV which a bug might have triggered.
	 */
	if (sip != NULL && SI_FROMKERNEL(sip) &&
	    (sig != SIGFPE || sip->si_code == 0)) {

		(void) sigemptyset(&act.sa_mask);
		act.sa_handler = SIG_DFL;
		act.sa_flags = 0;
		(void) sigaction(sig, &act, NULL);

		(void) sigfillset(&ucp->uc_sigmask);
		(void) sigdelset(&ucp->uc_sigmask, sig);
		ucp->uc_flags |= UC_SIGMASK;

		(void) setcontext(ucp);
	}

	/*
	 * If the signal received is a LVLQ signal, do not really
	 * change levels, just restate the current level.  If the
	 * signal is not a LVLQ, set the new level to the signal
	 * received.
	 */
	if (sig == LVLQ) {
		new_state = cur_state;
		lvlq_received = B_TRUE;
	} else {
		new_state = sig;
	}

	/*
	 * Clear all times and repeat counts in the process table
	 * since either the level is changing or the user has editted
	 * the inittab file and wants us to look at it again.
	 * If the user has fixed a typo, we don't want residual timing
	 * data preventing the fixed command line from executing.
	 */
	for (process = proc_table;
	    (process < proc_table + num_proc); process++) {
		process->p_time = 0L;
		process->p_count = 0;
	}

	/*
	 * Set the flag to indicate that a "user signal" was received.
	 */
	wakeup.w_flags.w_usersignal = 1;
}


/*
 * alarmclk
 */
static void
alarmclk()
{
	time_up = TRUE;
}

/*
 * childeath_single():
 *
 * This used to be the SIGCLD handler and it was set with signal()
 * (as opposed to sigset()).  When a child exited we'd come to the
 * handler, wait for the child, and reenable the handler with
 * signal() just before returning.  The implementation of signal()
 * checks with waitid() for waitable children and sends a SIGCLD
 * if there are some.  If children are exiting faster than the
 * handler can run we keep sending signals and the handler never
 * gets to return and eventually the stack runs out and init dies.
 * To prevent that we set the handler with sigset() so the handler
 * doesn't need to be reset, and in childeath() (see below) we
 * call childeath_single() as long as there are children to be
 * waited for.  If a child exits while init is in the handler a
 * SIGCLD will be pending and delivered on return from the handler.
 * If the child was already waited for the handler will have nothing
 * to do and return, otherwise the child will be waited for.
 */
static void
childeath_single(pid_t pid, int status)
{
	struct PROC_TABLE	*process;
	struct pidlist		*pp;

	/*
	 * Scan the process table to see if we are interested in this process.
	 */
	for (process = proc_table;
	    (process < proc_table + num_proc); process++) {
		if ((process->p_flags & (LIVING|OCCUPIED)) ==
		    (LIVING|OCCUPIED) && process->p_pid == pid) {

			/*
			 * Mark this process as having died and store the exit
			 * status.  Also set the wakeup flag for a dead child
			 * and break out of the loop.
			 */
			process->p_flags &= ~LIVING;
			process->p_exit = (short)status;
			wakeup.w_flags.w_childdeath = 1;

			return;
		}
	}

	/*
	 * No process was found above, look through auxiliary list.
	 */
	(void) sighold(SIGPOLL);
	pp = Plhead;
	while (pp) {
		if (pid > pp->pl_pid) {
			/*
			 * Keep on looking.
			 */
			pp = pp->pl_next;
			continue;
		} else if (pid < pp->pl_pid) {
			/*
			 * Not in the list.
			 */
			break;
		} else {
			/*
			 * This is a dead "godchild".
			 */
			pp->pl_dflag = 1;
			pp->pl_exit = (short)status;
			wakeup.w_flags.w_childdeath = 1;
			Gchild = 1;	/* Notice to call cleanaux(). */
			break;
		}
	}

	(void) sigrelse(SIGPOLL);
}

/* ARGSUSED */
static void
childeath(int signo)
{
	pid_t pid;
	int status;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		childeath_single(pid, status);
}

static void
powerfail()
{
	(void) nice(-19);
	wakeup.w_flags.w_powerhit = 1;
}

/*
 * efork() forks a child and the parent inserts the process in its table
 * of processes that are directly a result of forks that it has performed.
 * The child just changes the "global" with the process id for this process
 * to it's new value.
 * If efork() is called with a pointer into the proc_table it uses that slot,
 * otherwise it searches for a free slot.  Regardless of how it was called,
 * it returns the pointer to the proc_table entry
 *
 * The SIGCLD signal is blocked (held) before calling efork()
 * and is unblocked (released) after efork() returns.
 *
 * Ideally, this should be rewritten to use modern signal semantics.
 */
static struct PROC_TABLE *
efork(int action, struct PROC_TABLE *process, int modes)
{
	pid_t	childpid;
	struct PROC_TABLE *proc;
	int		i;
	/*
	 * Freshen up the proc_table, removing any entries for dead processes
	 * that don't have NOCLEANUP set.  Perform the necessary accounting.
	 */
	for (proc = proc_table; (proc < proc_table + num_proc); proc++) {
		if ((proc->p_flags & (OCCUPIED|LIVING|NOCLEANUP)) ==
		    (OCCUPIED)) {
			/*
			 * Is this a named process?
			 * If so, do the necessary bookkeeping.
			 */
			if (proc->p_flags & NAMED)
				(void) account(DEAD_PROCESS, proc, NULL);

			/*
			 * Free this entry for new usage.
			 */
			proc->p_flags = 0;
		}
	}

	while ((childpid = fork()) == FAILURE) {
		/*
		 * Shorten the alarm timer in case someone else's child dies
		 * and free up a slot in the process table.
		 */
		setimer(5);

		/*
		 * Wait for some children to die.  Since efork()
		 * is always called with SIGCLD blocked, unblock
		 * it here so that child death signals can come in.
		 */
		(void) sigrelse(SIGCLD);
		(void) pause();
		(void) sighold(SIGCLD);
		setimer(0);
	}

	if (childpid != 0) {

		if (process == NULLPROC) {
			/*
			 * No proc table pointer specified so search
			 * for a free slot.
			 */
			for (process = proc_table;  process->p_flags != 0 &&
			    (process < proc_table + num_proc); process++)
					;

			if (process == (proc_table + num_proc)) {
				int old_proc_table_size = num_proc;

				/* Increase the process table size */
				increase_proc_table_size();
				if (old_proc_table_size == num_proc) {
					/* didn't grow: memory failure */
					return (NO_ROOM);
				} else {
					process =
					    proc_table + old_proc_table_size;
				}
			}

			process->p_time = 0L;
			process->p_count = 0;
		}
		process->p_id[0] = '\0';
		process->p_id[1] = '\0';
		process->p_id[2] = '\0';
		process->p_id[3] = '\0';
		process->p_pid = childpid;
		process->p_flags = (LIVING | OCCUPIED | modes);
		process->p_exit = 0;

		st_write();
	} else {
		if ((action & (M_WAIT | M_BOOTWAIT)) == 0)
			(void) setpgrp();

		process = NULLPROC;

		/*
		 * Reset all signals to the system defaults.
		 */
		for (i = SIGHUP; i <= SIGRTMAX; i++)
			(void) sigset(i, SIG_DFL);

		/*
		 * POSIX B.2.2.2 advises that init should set SIGTTOU,
		 * SIGTTIN, and SIGTSTP to SIG_IGN.
		 *
		 * Make sure that SIGXCPU and SIGXFSZ also remain ignored,
		 * for backward compatibility.
		 */
		(void) sigset(SIGTTIN, SIG_IGN);
		(void) sigset(SIGTTOU, SIG_IGN);
		(void) sigset(SIGTSTP, SIG_IGN);
		(void) sigset(SIGXCPU, SIG_IGN);
		(void) sigset(SIGXFSZ, SIG_IGN);
	}
	return (process);
}


/*
 * waitproc() waits for a specified process to die.  For this function to
 * work, the specified process must already in the proc_table.  waitproc()
 * returns the exit status of the specified process when it dies.
 */
static long
waitproc(struct PROC_TABLE *process)
{
	int		answer;
	sigset_t	oldmask, newmask, zeromask;

	(void) sigemptyset(&zeromask);
	(void) sigemptyset(&newmask);

	(void) sigaddset(&newmask, SIGCLD);

	/* Block SIGCLD and save the current signal mask */
	if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) < 0)
		perror("SIG_BLOCK error");

	/*
	 * Wait around until the process dies.
	 */
	if (process->p_flags & LIVING)
		(void) sigsuspend(&zeromask);

	/* Reset signal mask to unblock SIGCLD */
	if (sigprocmask(SIG_SETMASK, &oldmask, NULL) < 0)
		perror("SIG_SETMASK error");

	if (process->p_flags & LIVING)
		return (FAILURE);

	/*
	 * Make sure to only return 16 bits so that answer will always
	 * be positive whenever the process of interest really died.
	 */
	answer = (process->p_exit & 0xffff);

	/*
	 * Free the slot in the proc_table.
	 */
	process->p_flags = 0;
	return (answer);
}

/*
 * notify_pam_dead(): calls into the PAM framework to close the given session.
 */
static void
notify_pam_dead(struct utmpx *up)
{
	pam_handle_t *pamh;
	char user[sizeof (up->ut_user) + 1];
	char ttyn[sizeof (up->ut_line) + 1];
	char host[sizeof (up->ut_host) + 1];

	/*
	 * PAM does not take care of updating utmpx/wtmpx.
	 */
	(void) snprintf(user, sizeof (user), "%s", up->ut_user);
	(void) snprintf(ttyn, sizeof (ttyn), "%s", up->ut_line);
	(void) snprintf(host, sizeof (host), "%s", up->ut_host);

	if (pam_start("init", user, NULL, &pamh) == PAM_SUCCESS)  {
		(void) pam_set_item(pamh, PAM_TTY, ttyn);
		(void) pam_set_item(pamh, PAM_RHOST, host);
		(void) pam_close_session(pamh, 0);
		(void) pam_end(pamh, PAM_SUCCESS);
	}
}

/*
 * Check you can access utmpx (As / may be read-only and
 * /var may not be mounted yet).
 */
static int
access_utmpx(void)
{
	do {
		utmpx_ok = (access(UTMPX, R_OK|W_OK) == 0);
	} while (!utmpx_ok && errno == EINTR);

	return (utmpx_ok);
}

/*
 * account() updates entries in utmpx and appends new entries to the end of
 * wtmpx (assuming they exist).  The program argument indicates the name of
 * program if INIT_PROCESS, otherwise should be NULL.
 *
 * account() only blocks for INIT_PROCESS requests.
 *
 * Returns non-zero if write failed.
 */
static int
account(short state, struct PROC_TABLE *process, char *program)
{
	struct utmpx utmpbuf, *u, *oldu;
	int tmplen;
	char fail_buf[UT_LINE_SZ];
	sigset_t block, unblock;

	if (!utmpx_ok && !access_utmpx()) {
		return (-1);
	}

	/*
	 * Set up the prototype for the utmp structure we want to write.
	 */
	u = &utmpbuf;
	(void) memset(u, 0, sizeof (struct utmpx));

	/*
	 * Fill in the various fields of the utmp structure.
	 */
	u->ut_id[0] = process->p_id[0];
	u->ut_id[1] = process->p_id[1];
	u->ut_id[2] = process->p_id[2];
	u->ut_id[3] = process->p_id[3];
	u->ut_pid = process->p_pid;

	/*
	 * Fill the "ut_exit" structure.
	 */
	u->ut_exit.e_termination = WTERMSIG(process->p_exit);
	u->ut_exit.e_exit = WEXITSTATUS(process->p_exit);
	u->ut_type = state;

	(void) time(&u->ut_tv.tv_sec);

	/*
	 * Block signals for utmp update.
	 */
	(void) sigfillset(&block);
	(void) sigprocmask(SIG_BLOCK, &block, &unblock);

	/*
	 * See if there already is such an entry in the "utmpx" file.
	 */
	setutxent();	/* Start at beginning of utmpx file. */

	if ((oldu = getutxid(u)) != NULL) {
		/*
		 * Copy in the old "user", "line" and "host" fields
		 * to our new structure.
		 */
		bcopy(oldu->ut_user, u->ut_user, sizeof (u->ut_user));
		bcopy(oldu->ut_line, u->ut_line, sizeof (u->ut_line));
		bcopy(oldu->ut_host, u->ut_host, sizeof (u->ut_host));
		u->ut_syslen = (tmplen = strlen(u->ut_host)) ?
		    min(tmplen + 1, sizeof (u->ut_host)) : 0;

		if (oldu->ut_type == USER_PROCESS && state == DEAD_PROCESS) {
			notify_pam_dead(oldu);
		}
	}

	/*
	 * Perform special accounting. Insert the special string into the
	 * ut_line array. For INIT_PROCESSes put in the name of the
	 * program in the "ut_user" field.
	 */
	switch (state) {
	case INIT_PROCESS:
		(void) strncpy(u->ut_user, program, sizeof (u->ut_user));
		(void) strcpy(fail_buf, "INIT_PROCESS");
		break;

	default:
		(void) strlcpy(fail_buf, u->ut_id, sizeof (u->ut_id) + 1);
		break;
	}

	/*
	 * Write out the updated entry to utmpx file.
	 */
	if (pututxline(u) == NULL) {
		console(B_TRUE, "Failed write of utmpx entry: \"%s\": %s\n",
		    fail_buf, strerror(errno));
		endutxent();
		(void) sigprocmask(SIG_SETMASK, &unblock, NULL);
		return (-1);
	}

	/*
	 * If we're able to write to utmpx, then attempt to add to the
	 * end of the wtmpx file.
	 */
	updwtmpx(WTMPX, u);

	endutxent();

	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);

	return (0);
}

static void
clearent(pid_t pid, short status)
{
	struct utmpx *up;
	sigset_t block, unblock;

	/*
	 * Block signals for utmp update.
	 */
	(void) sigfillset(&block);
	(void) sigprocmask(SIG_BLOCK, &block, &unblock);

	/*
	 * No error checking for now.
	 */

	setutxent();
	while (up = getutxent()) {
		if (up->ut_pid == pid) {
			if (up->ut_type == DEAD_PROCESS) {
				/*
				 * Cleaned up elsewhere.
				 */
				continue;
			}

			notify_pam_dead(up);

			up->ut_type = DEAD_PROCESS;
			up->ut_exit.e_termination = WTERMSIG(status);
			up->ut_exit.e_exit = WEXITSTATUS(status);
			(void) time(&up->ut_tv.tv_sec);

			(void) pututxline(up);
			/*
			 * Now attempt to add to the end of the
			 * wtmp and wtmpx files.  Do not create
			 * if they don't already exist.
			 */
			updwtmpx(WTMPX, up);

			break;
		}
	}

	endutxent();
	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);
}

/*
 * prog_name() searches for the word or unix path name and
 * returns a pointer to the last element of the pathname.
 */
static char *
prog_name(char *string)
{
	char	*ptr, *ptr2;
	static char word[UT_USER_SZ + 1];

	/*
	 * Search for the first word skipping leading spaces and tabs.
	 */
	while (*string == ' ' || *string == '\t')
		string++;

	/*
	 * If the first non-space non-tab character is not one allowed in
	 * a word, return a pointer to a null string, otherwise parse the
	 * pathname.
	 */
	if (*string != '.' && *string != '/' && *string != '_' &&
	    (*string < 'a' || *string > 'z') &&
	    (*string < 'A' || * string > 'Z') &&
	    (*string < '0' || *string > '9'))
		return ("");

	/*
	 * Parse the pathname looking forward for '/', ' ', '\t', '\n' or
	 * '\0'.  Each time a '/' is found, move "ptr" to one past the
	 * '/', thus when a ' ', '\t', '\n', or '\0' is found, "ptr" will
	 * point to the last element of the pathname.
	 */
	for (ptr = string; *string != ' ' && *string != '\t' &&
	    *string != '\n' && *string != '\0'; string++) {
		if (*string == '/')
			ptr = string+1;
	}

	/*
	 * Copy out up to the size of the "ut_user" array into "word",
	 * null terminate it and return a pointer to it.
	 */
	for (ptr2 = &word[0]; ptr2 < &word[UT_USER_SZ] &&
	    ptr < string; /* CSTYLED */)
		*ptr2++ = *ptr++;

	*ptr2 = '\0';
	return (&word[0]);
}


/*
 * realcon() returns a nonzero value if there is a character device
 * associated with SYSCON that has the same device number as CONSOLE.
 */
static int
realcon()
{
	struct stat sconbuf, conbuf;

	if (stat(SYSCON, &sconbuf) != -1 &&
	    stat(CONSOLE, &conbuf) != -1 &&
	    S_ISCHR(sconbuf.st_mode) &&
	    S_ISCHR(conbuf.st_mode) &&
	    sconbuf.st_rdev == conbuf.st_rdev) {
		return (1);
	} else {
		return (0);
	}
}


/*
 * get_ioctl_syscon() retrieves the SYSCON settings from the IOCTLSYSCON file.
 * Returns true if the IOCTLSYSCON file needs to be written (with
 * write_ioctl_syscon() below)
 */
static int
get_ioctl_syscon()
{
	FILE	*fp;
	unsigned int	iflags, oflags, cflags, lflags, ldisc, cc[18];
	int		i, valid_format = 0;

	/*
	 * Read in the previous modes for SYSCON from IOCTLSYSCON.
	 */
	if ((fp = fopen(IOCTLSYSCON, "r")) == NULL) {
		stored_syscon_termios = dflt_termios;
		console(B_TRUE,
		    "warning:%s does not exist, default settings assumed\n",
		    IOCTLSYSCON);
	} else {

		i = fscanf(fp,
	    "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
		    &iflags, &oflags, &cflags, &lflags,
		    &cc[0], &cc[1], &cc[2], &cc[3], &cc[4], &cc[5], &cc[6],
		    &cc[7], &cc[8], &cc[9], &cc[10], &cc[11], &cc[12], &cc[13],
		    &cc[14], &cc[15], &cc[16], &cc[17]);

		if (i == 22) {
			stored_syscon_termios.c_iflag = iflags;
			stored_syscon_termios.c_oflag = oflags;
			stored_syscon_termios.c_cflag = cflags;
			stored_syscon_termios.c_lflag = lflags;
			for (i = 0; i < 18; i++)
				stored_syscon_termios.c_cc[i] = (char)cc[i];
			valid_format = 1;
		} else if (i == 13) {
		rewind(fp);
		i = fscanf(fp, "%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x",
		    &iflags, &oflags, &cflags, &lflags, &ldisc, &cc[0], &cc[1],
		    &cc[2], &cc[3], &cc[4], &cc[5], &cc[6], &cc[7]);

		/*
		 * If the file is formatted properly, use the values to
		 * initialize the console terminal condition.
		 */
		stored_syscon_termios.c_iflag = (ushort_t)iflags;
		stored_syscon_termios.c_oflag = (ushort_t)oflags;
		stored_syscon_termios.c_cflag = (ushort_t)cflags;
		stored_syscon_termios.c_lflag = (ushort_t)lflags;
		for (i = 0; i < 8; i++)
			stored_syscon_termios.c_cc[i] = (char)cc[i];
		valid_format = 1;
		}
		(void) fclose(fp);

		/* If the file is badly formatted, use the default settings. */
		if (!valid_format)
			stored_syscon_termios = dflt_termios;
	}

	/* If the file had a bad format, rewrite it later. */
	return (!valid_format);
}


static void
write_ioctl_syscon()
{
	FILE *fp;
	int i;

	(void) unlink(SYSCON);
	(void) link(SYSTTY, SYSCON);
	(void) umask(022);
	fp = fopen(IOCTLSYSCON, "w");

	(void) fprintf(fp, "%x:%x:%x:%x:0", stored_syscon_termios.c_iflag,
	    stored_syscon_termios.c_oflag, stored_syscon_termios.c_cflag,
	    stored_syscon_termios.c_lflag);
	for (i = 0; i < 8; ++i)
		(void) fprintf(fp, ":%x", stored_syscon_termios.c_cc[i]);
	(void) putc('\n', fp);

	(void) fflush(fp);
	(void) fsync(fileno(fp));
	(void) fclose(fp);
	(void) umask(cmask);
}


/*
 * void console(boolean_t, char *, ...)
 *   Outputs the requested message to the system console.  Note that the number
 *   of arguments passed to console() should be determined by the print format.
 *
 *   The "prefix" parameter indicates whether or not "INIT: " should precede the
 *   message.
 *
 *   To make sure we write to the console in a sane fashion, we use the modes
 *   we keep in stored_syscon_termios (which we read out of /etc/ioctl.syscon).
 *   Afterwards we restore whatever modes were already there.
 */
/* PRINTFLIKE2 */
static void
console(boolean_t prefix, char *format, ...)
{
	char	outbuf[BUFSIZ];
	va_list	args;
	int fd, getret;
	struct termios old_syscon_termios;
	FILE *f;

	/*
	 * We open SYSCON anew each time in case it has changed (see
	 * userinit()).
	 */
	if ((fd = open(SYSCON, O_RDWR | O_NOCTTY)) < 0 ||
	    (f = fdopen(fd, "r+")) == NULL) {
		if (prefix)
			syslog(LOG_WARNING, "INIT: ");
		va_start(args, format);
		vsyslog(LOG_WARNING, format, args);
		va_end(args);
		if (fd >= 0)
			(void) close(fd);
		return;
	}
	setbuf(f, &outbuf[0]);

	getret = tcgetattr(fd, &old_syscon_termios);
	old_syscon_termios.c_cflag &= ~HUPCL;
	if (realcon())
		/* Don't overwrite cflag of real console. */
		stored_syscon_termios.c_cflag = old_syscon_termios.c_cflag;

	stored_syscon_termios.c_cflag &= ~HUPCL;

	(void) tcsetattr(fd, TCSANOW, &stored_syscon_termios);

	if (prefix)
		(void) fprintf(f, "\nINIT: ");
	va_start(args, format);
	(void) vfprintf(f, format, args);
	va_end(args);

	if (getret == 0)
		(void) tcsetattr(fd, TCSADRAIN, &old_syscon_termios);

	(void) fclose(f);
}

/*
 * timer() is a substitute for sleep() which uses alarm() and pause().
 */
static void
timer(int waitime)
{
	setimer(waitime);
	while (time_up == FALSE)
		(void) pause();
}

static void
setimer(int timelimit)
{
	alarmclk();
	(void) alarm(timelimit);
	time_up = (timelimit ? FALSE : TRUE);
}

/*
 * Fails with
 *   ENOMEM - out of memory
 *   ECONNABORTED - repository connection broken
 *   EPERM - permission denied
 *   EACCES - backend access denied
 *   EROFS - backend readonly
 */
static int
get_or_add_startd(scf_instance_t *inst)
{
	scf_handle_t *h;
	scf_scope_t *scope = NULL;
	scf_service_t *svc = NULL;
	int ret = 0;

	h = scf_instance_handle(inst);

	if (scf_handle_decode_fmri(h, SCF_SERVICE_STARTD, NULL, NULL, inst,
	    NULL, NULL, SCF_DECODE_FMRI_EXACT) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
		return (ECONNABORTED);

	case SCF_ERROR_NOT_FOUND:
		break;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_CONSTRAINT_VIOLATED:
	default:
		bad_error("scf_handle_decode_fmri", scf_error());
	}

	/* Make sure we're right, since we're adding piece-by-piece. */
	assert(strcmp(SCF_SERVICE_STARTD,
	    "svc:/system/svc/restarter:default") == 0);

	if ((scope = scf_scope_create(h)) == NULL ||
	    (svc = scf_service_create(h)) == NULL) {
		ret = ENOMEM;
		goto out;
	}

get_scope:
	if (scf_handle_get_scope(h, SCF_SCOPE_LOCAL, scope) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_NOT_FOUND:
			(void) fputs(gettext(
			    "smf(5) repository missing local scope.\n"),
			    stderr);
			exit(1);
			/* NOTREACHED */

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		default:
			bad_error("scf_handle_get_scope", scf_error());
		}
	}

get_svc:
	if (scf_scope_get_service(scope, "system/svc/restarter", svc) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			goto get_scope;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_scope_get_service", scf_error());
		}

add_svc:
		if (scf_scope_add_service(scope, "system/svc/restarter", svc) !=
		    0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_EXISTS:
				goto get_svc;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_scope_add_service", scf_error());
			}
		}
	}

get_inst:
	if (scf_service_get_instance(svc, "default", inst) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			ret = ECONNABORTED;
			goto out;

		case SCF_ERROR_DELETED:
			goto add_svc;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_service_get_instance", scf_error());
		}

		if (scf_service_add_instance(svc, "default", inst) !=
		    0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
				ret = ECONNABORTED;
				goto out;

			case SCF_ERROR_DELETED:
				goto add_svc;

			case SCF_ERROR_EXISTS:
				goto get_inst;

			case SCF_ERROR_PERMISSION_DENIED:
				ret = EPERM;
				goto out;

			case SCF_ERROR_BACKEND_ACCESS:
				ret = EACCES;
				goto out;

			case SCF_ERROR_BACKEND_READONLY:
				ret = EROFS;
				goto out;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_service_add_instance",
				    scf_error());
			}
		}
	}

	ret = 0;

out:
	scf_service_destroy(svc);
	scf_scope_destroy(scope);
	return (ret);
}

/*
 * Fails with
 *   ECONNABORTED - repository connection broken
 *   ECANCELED - the transaction's property group was deleted
 */
static int
transaction_add_set(scf_transaction_t *tx, scf_transaction_entry_t *ent,
    const char *pname, scf_type_t type)
{
change_type:
	if (scf_transaction_property_change_type(tx, ent, pname, type) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
		return (ECONNABORTED);

	case SCF_ERROR_DELETED:
		return (ECANCELED);

	case SCF_ERROR_NOT_FOUND:
		goto new;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_BOUND:
	case SCF_ERROR_NOT_SET:
	default:
		bad_error("scf_transaction_property_change_type", scf_error());
	}

new:
	if (scf_transaction_property_new(tx, ent, pname, type) == 0)
		return (0);

	switch (scf_error()) {
	case SCF_ERROR_CONNECTION_BROKEN:
		return (ECONNABORTED);

	case SCF_ERROR_DELETED:
		return (ECANCELED);

	case SCF_ERROR_EXISTS:
		goto change_type;

	case SCF_ERROR_HANDLE_MISMATCH:
	case SCF_ERROR_INVALID_ARGUMENT:
	case SCF_ERROR_NOT_BOUND:
	case SCF_ERROR_NOT_SET:
	default:
		bad_error("scf_transaction_property_new", scf_error());
		/* NOTREACHED */
	}
}

static void
scferr(void)
{
	switch (scf_error()) {
	case SCF_ERROR_NO_MEMORY:
		console(B_TRUE, gettext("Out of memory.\n"));
		break;

	case SCF_ERROR_CONNECTION_BROKEN:
		console(B_TRUE, gettext(
		    "Connection to smf(5) repository server broken.\n"));
		break;

	case SCF_ERROR_NO_RESOURCES:
		console(B_TRUE, gettext(
		    "smf(5) repository server is out of memory.\n"));
		break;

	case SCF_ERROR_PERMISSION_DENIED:
		console(B_TRUE, gettext("Insufficient privileges.\n"));
		break;

	default:
		console(B_TRUE, gettext("libscf error: %s\n"),
		    scf_strerror(scf_error()));
	}
}

static void
lscf_set_runlevel(char rl)
{
	scf_handle_t *h;
	scf_instance_t *inst = NULL;
	scf_propertygroup_t *pg = NULL;
	scf_transaction_t *tx = NULL;
	scf_transaction_entry_t *ent = NULL;
	scf_value_t *val = NULL;
	char buf[2];
	int r;

	h = scf_handle_create(SCF_VERSION);
	if (h == NULL) {
		scferr();
		return;
	}

	if (scf_handle_bind(h) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_NO_SERVER:
			console(B_TRUE,
			    gettext("smf(5) repository server not running.\n"));
			goto bail;

		default:
			scferr();
			goto bail;
		}
	}

	if ((inst = scf_instance_create(h)) == NULL ||
	    (pg = scf_pg_create(h)) == NULL ||
	    (val = scf_value_create(h)) == NULL ||
	    (tx = scf_transaction_create(h)) == NULL ||
	    (ent = scf_entry_create(h)) == NULL) {
		scferr();
		goto bail;
	}

get_inst:
	r = get_or_add_startd(inst);
	switch (r) {
	case 0:
		break;

	case ENOMEM:
	case ECONNABORTED:
	case EPERM:
	case EACCES:
	case EROFS:
		scferr();
		goto bail;
	default:
		bad_error("get_or_add_startd", r);
	}

get_pg:
	if (scf_instance_get_pg(inst, SCF_PG_OPTIONS_OVR, pg) != 0) {
		switch (scf_error()) {
		case SCF_ERROR_CONNECTION_BROKEN:
			scferr();
			goto bail;

		case SCF_ERROR_DELETED:
			goto get_inst;

		case SCF_ERROR_NOT_FOUND:
			break;

		case SCF_ERROR_HANDLE_MISMATCH:
		case SCF_ERROR_INVALID_ARGUMENT:
		case SCF_ERROR_NOT_SET:
		default:
			bad_error("scf_instance_get_pg", scf_error());
		}

add_pg:
		if (scf_instance_add_pg(inst, SCF_PG_OPTIONS_OVR,
		    SCF_PG_OPTIONS_OVR_TYPE, SCF_PG_OPTIONS_OVR_FLAGS, pg) !=
		    0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
				scferr();
				goto bail;

			case SCF_ERROR_DELETED:
				goto get_inst;

			case SCF_ERROR_EXISTS:
				goto get_pg;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_instance_add_pg", scf_error());
			}
		}
	}

	buf[0] = rl;
	buf[1] = '\0';
	r = scf_value_set_astring(val, buf);
	assert(r == 0);

	for (;;) {
		if (scf_transaction_start(tx, pg) != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
				scferr();
				goto bail;

			case SCF_ERROR_DELETED:
				goto add_pg;

			case SCF_ERROR_HANDLE_MISMATCH:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_IN_USE:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_transaction_start", scf_error());
			}
		}

		r = transaction_add_set(tx, ent, "runlevel", SCF_TYPE_ASTRING);
		switch (r) {
		case 0:
			break;

		case ECONNABORTED:
			scferr();
			goto bail;

		case ECANCELED:
			scf_transaction_reset(tx);
			goto add_pg;

		default:
			bad_error("transaction_add_set", r);
		}

		r = scf_entry_add_value(ent, val);
		assert(r == 0);

		r = scf_transaction_commit(tx);
		if (r == 1)
			break;

		if (r != 0) {
			switch (scf_error()) {
			case SCF_ERROR_CONNECTION_BROKEN:
			case SCF_ERROR_PERMISSION_DENIED:
			case SCF_ERROR_BACKEND_ACCESS:
			case SCF_ERROR_BACKEND_READONLY:
				scferr();
				goto bail;

			case SCF_ERROR_DELETED:
				scf_transaction_reset(tx);
				goto add_pg;

			case SCF_ERROR_INVALID_ARGUMENT:
			case SCF_ERROR_NOT_BOUND:
			case SCF_ERROR_NOT_SET:
			default:
				bad_error("scf_transaction_commit",
				    scf_error());
			}
		}

		scf_transaction_reset(tx);
		(void) scf_pg_update(pg);
	}

bail:
	scf_transaction_destroy(tx);
	scf_entry_destroy(ent);
	scf_value_destroy(val);
	scf_pg_destroy(pg);
	scf_instance_destroy(inst);

	(void) scf_handle_unbind(h);
	scf_handle_destroy(h);
}

/*
 * Function to handle requests from users to main init running as process 1.
 */
static void
userinit(int argc, char **argv)
{
	FILE	*fp;
	char	*ln;
	int	init_signal;
	struct stat	sconbuf, conbuf;
	const char *usage_msg = "Usage: init [0123456SsQqabc]\n";

	/*
	 * We are a user invoked init.  Is there an argument and is it
	 * a single character?  If not, print usage message and quit.
	 */
	if (argc != 2 || argv[1][1] != '\0') {
		(void) fprintf(stderr, usage_msg);
		exit(0);
	}

	if ((init_signal = lvlname_to_state((char)argv[1][0])) == -1) {
		(void) fprintf(stderr, usage_msg);
		(void) audit_put_record(ADT_FAILURE, ADT_FAIL_VALUE_BAD_CMD,
		    argv[1]);
		exit(1);
	}

	if (init_signal == SINGLE_USER) {
		/*
		 * Make sure this process is talking to a legal tty line
		 * and that /dev/syscon is linked to this line.
		 */
		ln = ttyname(0);	/* Get the name of tty */
		if (ln == NULL) {
			(void) fprintf(stderr,
			    "Standard input not a tty line\n");
			(void) audit_put_record(ADT_FAILURE,
			    ADT_FAIL_VALUE_BAD_TTY, argv[1]);
			exit(1);
		}

		if ((stat(ln, &sconbuf) != -1) &&
		    (stat(SYSCON, &conbuf) == -1 ||
		    sconbuf.st_rdev != conbuf.st_rdev)) {
			/*
			 * /dev/syscon needs to change.
			 * Unlink /dev/syscon and relink it to the current line.
			 */
			if (lstat(SYSCON, &conbuf) != -1 &&
			    unlink(SYSCON) == FAILURE) {
				perror("Can't unlink /dev/syscon");
				(void) fprintf(stderr,
				    "Run command on the system console.\n");
				(void) audit_put_record(ADT_FAILURE,
				    ADT_FAIL_VALUE_PROGRAM, argv[1]);
				exit(1);
			}
			if (symlink(ln, SYSCON) == FAILURE) {
				(void) fprintf(stderr,
				    "Can't symlink /dev/syscon to %s: %s", ln,
				    strerror(errno));

				/* Try to leave a syscon */
				(void) link(SYSTTY, SYSCON);
				(void) audit_put_record(ADT_FAILURE,
				    ADT_FAIL_VALUE_PROGRAM, argv[1]);
				exit(1);
			}

			/*
			 * Try to leave a message on system console saying where
			 * /dev/syscon is currently connected.
			 */
			if ((fp = fopen(SYSTTY, "r+")) != NULL) {
				(void) fprintf(fp,
				    "\n****	SYSCON CHANGED TO %s	****\n",
				    ln);
				(void) fclose(fp);
			}
		}
	}

	update_boot_archive(init_signal);

	(void) audit_put_record(ADT_SUCCESS, ADT_SUCCESS, argv[1]);

	/*
	 * Signal init; init will take care of telling svc.startd.
	 */
	if (kill(init_pid, init_signal) == FAILURE) {
		(void) fprintf(stderr, "Must be super-user\n");
		(void) audit_put_record(ADT_FAILURE,
		    ADT_FAIL_VALUE_AUTH, argv[1]);
		exit(1);
	}

	exit(0);
}


#define	DELTA	25	/* Number of pidlist elements to allocate at a time */

/* ARGSUSED */
void
sigpoll(int n)
{
	struct pidrec prec;
	struct pidrec *p = &prec;
	struct pidlist *plp;
	struct pidlist *tp, *savetp;
	int i;

	if (Pfd < 0) {
		return;
	}

	for (;;) {
		/*
		 * Important Note: Either read will really fail (in which case
		 * return is all we can do) or will get EAGAIN (Pfd was opened
		 * O_NDELAY), in which case we also want to return.
		 * Always return from here!
		 */
		if (read(Pfd, p, sizeof (struct pidrec)) !=
						sizeof (struct pidrec)) {
			return;
		}
		switch (p->pd_type) {

		case ADDPID:
			/*
			 * New "godchild", add to list.
			 */
			if (Plfree == NULL) {
				plp = (struct pidlist *)calloc(DELTA,
				    sizeof (struct pidlist));
				if (plp == NULL) {
					/* Can't save pid */
					break;
				}
				/*
				 * Point at 2nd record allocated, we'll use plp.
				 */
				tp = plp + 1;
				/*
				 * Link them into a chain.
				 */
				Plfree = tp;
				for (i = 0; i < DELTA - 2; i++) {
					tp->pl_next = tp + 1;
					tp++;
				}
			} else {
				plp = Plfree;
				Plfree = plp->pl_next;
			}
			plp->pl_pid = p->pd_pid;
			plp->pl_dflag = 0;
			plp->pl_next = NULL;
			/*
			 * Note - pid list is kept in increasing order of pids.
			 */
			if (Plhead == NULL) {
				Plhead = plp;
				/* Back up to read next record */
				break;
			} else {
				savetp = tp = Plhead;
				while (tp) {
					if (plp->pl_pid > tp->pl_pid) {
						savetp = tp;
						tp = tp->pl_next;
						continue;
					} else if (plp->pl_pid < tp->pl_pid) {
						if (tp == Plhead) {
							plp->pl_next = Plhead;
							Plhead = plp;
						} else {
							plp->pl_next =
							    savetp->pl_next;
							savetp->pl_next = plp;
						}
						break;
					} else {
						/* Already in list! */
						plp->pl_next = Plfree;
						Plfree = plp;
						break;
					}
				}
				if (tp == NULL) {
					/* Add to end of list */
					savetp->pl_next = plp;
				}
			}
			/* Back up to read next record. */
			break;

		case REMPID:
			/*
			 * This one was handled by someone else,
			 * purge it from the list.
			 */
			if (Plhead == NULL) {
				/* Back up to read next record. */
				break;
			}
			savetp = tp = Plhead;
			while (tp) {
				if (p->pd_pid > tp->pl_pid) {
					/* Keep on looking. */
					savetp = tp;
					tp = tp->pl_next;
					continue;
				} else if (p->pd_pid < tp->pl_pid) {
					/* Not in list. */
					break;
				} else {
					/* Found it. */
					if (tp == Plhead)
						Plhead = tp->pl_next;
					else
						savetp->pl_next = tp->pl_next;
					tp->pl_next = Plfree;
					Plfree = tp;
					break;
				}
			}
			/* Back up to read next record. */
			break;
		default:
			console(B_TRUE, "Bad message on initpipe\n");
			break;
		}
	}
}


static void
cleanaux()
{
	struct pidlist *savep, *p;
	pid_t	pid;
	short	status;

	(void) sighold(SIGCLD);
	Gchild = 0;	/* Note - Safe to do this here since no SIGCLDs */
	(void) sighold(SIGPOLL);
	savep = p = Plhead;
	while (p) {
		if (p->pl_dflag) {
			/*
			 * Found an entry to delete,
			 * remove it from list first.
			 */
			pid = p->pl_pid;
			status = p->pl_exit;
			if (p == Plhead) {
				Plhead = p->pl_next;
				p->pl_next = Plfree;
				Plfree = p;
				savep = p = Plhead;
			} else {
				savep->pl_next = p->pl_next;
				p->pl_next = Plfree;
				Plfree = p;
				p = savep->pl_next;
			}
			clearent(pid, status);
			continue;
		}
		savep = p;
		p = p->pl_next;
	}
	(void) sigrelse(SIGPOLL);
	(void) sigrelse(SIGCLD);
}


/*
 * /etc/inittab has more entries and we have run out of room in the proc_table
 * array. Double the size of proc_table to accomodate the extra entries.
 */
static void
increase_proc_table_size()
{
	sigset_t block, unblock;
	void *ptr;
	size_t delta = num_proc * sizeof (struct PROC_TABLE);


	/*
	 * Block signals for realloc.
	 */
	(void) sigfillset(&block);
	(void) sigprocmask(SIG_BLOCK, &block, &unblock);


	/*
	 * On failure we just return because callers of this function check
	 * for failure.
	 */
	do
		ptr = realloc(g_state, g_state_sz + delta);
	while (ptr == NULL && errno == EAGAIN)
		;

	if (ptr != NULL) {
		/* ensure that the new part is initialized to zero */
		bzero((caddr_t)ptr + g_state_sz, delta);

		g_state = ptr;
		g_state_sz += delta;
		num_proc <<= 1;
	}


	/* unblock our signals before returning */
	(void) sigprocmask(SIG_SETMASK, &unblock, NULL);
}



/*
 * Sanity check g_state.
 */
static int
st_sane()
{
	int i;
	struct PROC_TABLE *ptp;


	/* Note: cur_state is encoded as a signal number */
	if (cur_state < 1 || cur_state == 9 || cur_state > 13)
		return (0);

	/* Check num_proc */
	if (g_state_sz != sizeof (struct init_state) + (num_proc - 1) *
	    sizeof (struct PROC_TABLE))
		return (0);

	/* Check proc_table */
	for (i = 0, ptp = proc_table; i < num_proc; ++i, ++ptp) {
		/* skip unoccupied entries */
		if (!(ptp->p_flags & OCCUPIED))
			continue;

		/* p_flags has no bits outside of PF_MASK */
		if (ptp->p_flags & ~(PF_MASK))
			return (0);

		/* 5 <= pid <= MAXPID */
		if (ptp->p_pid < 5 || ptp->p_pid > MAXPID)
			return (0);

		/* p_count >= 0 */
		if (ptp->p_count < 0)
			return (0);

		/* p_time >= 0 */
		if (ptp->p_time < 0)
			return (0);
	}

	return (1);
}

/*
 * Initialize our state.
 *
 * If the system just booted, then init_state_file, which is located on an
 * everpresent tmpfs filesystem, should not exist.
 *
 * If we were restarted, then init_state_file should exist, in
 * which case we'll read it in, sanity check it, and use it.
 *
 * Note: You can't call console() until proc_table is ready.
 */
void
st_init()
{
	struct stat stb;
	int ret, st_fd, insane = 0;
	size_t to_be_read;
	char *ptr;


	booting = 1;

	do {
		/*
		 * If we can exclusively create the file, then we're the
		 * initial invocation of init(1M).
		 */
		st_fd = open(init_state_file, O_RDWR | O_CREAT | O_EXCL,
		    S_IRUSR | S_IWUSR);
	} while (st_fd == -1 && errno == EINTR);
	if (st_fd != -1)
		goto new_state;

	booting = 0;

	do {
		st_fd = open(init_state_file, O_RDWR, S_IRUSR | S_IWUSR);
	} while (st_fd == -1 && errno == EINTR);
	if (st_fd == -1)
		goto new_state;

	/* Get the size of the file. */
	do
		ret = fstat(st_fd, &stb);
	while (ret == -1 && errno == EINTR)
		;
	if (ret == -1)
		goto new_state;

	do
		g_state = malloc(stb.st_size);
	while (g_state == NULL && errno == EAGAIN)
		;
	if (g_state == NULL)
		goto new_state;

	to_be_read = stb.st_size;
	ptr = (char *)g_state;
	while (to_be_read > 0) {
		ssize_t read_ret;

		read_ret = read(st_fd, ptr, to_be_read);
		if (read_ret < 0) {
			if (errno == EINTR)
				continue;

			goto new_state;
		}

		to_be_read -= read_ret;
		ptr += read_ret;
	}

	(void) close(st_fd);

	g_state_sz = stb.st_size;

	if (st_sane()) {
		console(B_TRUE, "Restarting.\n");
		return;
	}

	insane = 1;

new_state:
	if (st_fd >= 0)
		(void) close(st_fd);
	else
		(void) unlink(init_state_file);

	if (g_state != NULL)
		free(g_state);

	/* Something went wrong, so allocate new state. */
	g_state_sz = sizeof (struct init_state) +
	    ((init_num_proc - 1) * sizeof (struct PROC_TABLE));
	do
		g_state = calloc(1, g_state_sz);
	while (g_state == NULL && errno == EAGAIN)
		;
	if (g_state == NULL) {
		/* Fatal error! */
		exit(errno);
	}

	g_state->ist_runlevel = -1;
	num_proc = init_num_proc;

	if (!booting) {
		console(B_TRUE, "Restarting.\n");

		/* Overwrite the bad state file. */
		st_write();

		if (!insane) {
			console(B_TRUE,
			    "Error accessing persistent state file `%s'.  "
			    "Ignored.\n", init_state_file);
		} else {
			console(B_TRUE,
			    "Persistent state file `%s' is invalid and was "
			    "ignored.\n", init_state_file);
		}
	}
}

/*
 * Write g_state out to the state file.
 */
void
st_write()
{
	static int complained = 0;

	int st_fd;
	char *cp;
	size_t sz;
	ssize_t ret;


	do {
		st_fd = open(init_next_state_file,
		    O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	} while (st_fd < 0 && errno == EINTR);
	if (st_fd < 0)
		goto err;

	cp = (char *)g_state;
	sz = g_state_sz;
	while (sz > 0) {
		ret = write(st_fd, cp, sz);
		if (ret < 0) {
			if (errno == EINTR)
				continue;

			goto err;
		}

		sz -= ret;
		cp += ret;
	}

	(void) close(st_fd);
	st_fd = -1;
	if (rename(init_next_state_file, init_state_file)) {
		(void) unlink(init_next_state_file);
		goto err;
	}
	complained = 0;

	return;

err:
	if (st_fd >= 0)
		(void) close(st_fd);

	if (!booting && !complained) {
		/*
		 * Only complain after the filesystem should have come up.
		 * And only do it once so we don't loop between console()
		 * & efork().
		 */
		complained = 1;
		if (st_fd)
			console(B_TRUE, "Couldn't write persistent state "
			    "file `%s'.\n", init_state_file);
		else
			console(B_TRUE, "Couldn't move persistent state "
			    "file `%s' to `%s'.\n", init_next_state_file,
			    init_state_file);
	}
}

/*
 * Create a contract with these parameters.
 */
static int
contract_make_template(uint_t info, uint_t critical, uint_t fatal,
    uint64_t cookie)
{
	int fd, err;

	char *ioctl_tset_emsg =
	    "Couldn't set \"%s\" contract template parameter: %s.\n";

	do
		fd = open64(CTFS_ROOT "/process/template", O_RDWR);
	while (fd < 0 && errno == EINTR)
		;
	if (fd < 0) {
		console(B_TRUE, "Couldn't create process template: %s.\n",
		    strerror(errno));
		return (-1);
	}

	if (err = ct_pr_tmpl_set_param(fd, CT_PR_INHERIT | CT_PR_REGENT))
		console(B_TRUE, "Contract set template inherit, regent "
		    "failed: %s.\n", strerror(err));

	/*
	 * These errors result in a misconfigured template, which is better
	 * than no template at all, so warn but don't abort.
	 */
	if (err = ct_tmpl_set_informative(fd, info))
		console(B_TRUE, ioctl_tset_emsg, "informative", strerror(err));

	if (err = ct_tmpl_set_critical(fd, critical))
		console(B_TRUE, ioctl_tset_emsg, "critical", strerror(err));

	if (err = ct_pr_tmpl_set_fatal(fd, fatal))
		console(B_TRUE, ioctl_tset_emsg, "fatal", strerror(err));

	if (err = ct_tmpl_set_cookie(fd, cookie))
		console(B_TRUE, ioctl_tset_emsg, "cookie", strerror(err));

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	return (fd);
}

/*
 * Create the templates and open an event file descriptor.  We use dup2(2) to
 * get these descriptors away from the stdin/stdout/stderr group.
 */
static void
contracts_init()
{
	int err, fd;

	/*
	 * Create & configure a legacy template.  We only want empty events so
	 * we know when to abandon them.
	 */
	legacy_tmpl = contract_make_template(0, CT_PR_EV_EMPTY, CT_PR_EV_HWERR,
	    ORDINARY_COOKIE);
	if (legacy_tmpl >= 0) {
		err = ct_tmpl_activate(legacy_tmpl);
		if (err != 0) {
			(void) close(legacy_tmpl);
			legacy_tmpl = -1;
			console(B_TRUE,
			    "Couldn't activate legacy template (%s); "
			    "legacy services will be in init's contract.\n",
			    strerror(err));
		}
	} else
		console(B_TRUE,
		    "Legacy services will be in init's contract.\n");

	if (dup2(legacy_tmpl, 255) == -1) {
		console(B_TRUE, "Could not duplicate legacy template: %s.\n",
		    strerror(errno));
	} else {
		(void) close(legacy_tmpl);
		legacy_tmpl = 255;
	}

	(void) fcntl(legacy_tmpl, F_SETFD, FD_CLOEXEC);

	startd_tmpl = contract_make_template(0, CT_PR_EV_EMPTY,
	    CT_PR_EV_HWERR | CT_PR_EV_SIGNAL | CT_PR_EV_CORE, STARTD_COOKIE);

	if (dup2(startd_tmpl, 254) == -1) {
		console(B_TRUE, "Could not duplicate startd template: %s.\n",
		    strerror(errno));
	} else {
		(void) close(startd_tmpl);
		startd_tmpl = 254;
	}

	(void) fcntl(startd_tmpl, F_SETFD, FD_CLOEXEC);

	if (legacy_tmpl < 0 && startd_tmpl < 0) {
		/* The creation errors have already been reported. */
		console(B_TRUE,
		    "Ignoring contract events.  Core smf(5) services will not "
		    "be restarted.\n");
		return;
	}

	/*
	 * Open an event endpoint.
	 */
	do
		fd = open64(CTFS_ROOT "/process/pbundle", O_RDONLY);
	while (fd < 0 && errno == EINTR)
		;
	if (fd < 0) {
		console(B_TRUE,
		    "Couldn't open process pbundle: %s.  Core smf(5) services "
		    "will not be restarted.\n", strerror(errno));
		return;
	}

	if (dup2(fd, 253) == -1) {
		console(B_TRUE, "Could not duplicate process bundle: %s.\n",
		    strerror(errno));
	} else {
		(void) close(fd);
		fd = 253;
	}

	(void) fcntl(fd, F_SETFD, FD_CLOEXEC);

	/* Reset in case we've been restarted. */
	(void) ct_event_reset(fd);

	poll_fds[0].fd = fd;
	poll_fds[0].events = POLLIN;
	poll_nfds = 1;
}

static int
contract_getfile(ctid_t id, const char *name, int oflag)
{
	int fd;

	do
		fd = contract_open(id, "process", name, oflag);
	while (fd < 0 && errno == EINTR)
		;

	if (fd < 0)
		console(B_TRUE, "Couldn't open %s for contract %ld: %s.\n",
		    name, id, strerror(errno));

	return (fd);
}

static int
contract_cookie(ctid_t id, uint64_t *cp)
{
	int fd, err;
	ct_stathdl_t sh;

	fd = contract_getfile(id, "status", O_RDONLY);
	if (fd < 0)
		return (-1);

	err = ct_status_read(fd, CTD_COMMON, &sh);
	if (err != 0) {
		console(B_TRUE, "Couldn't read status of contract %ld: %s.\n",
		    id, strerror(err));
		(void) close(fd);
		return (-1);
	}

	(void) close(fd);

	*cp = ct_status_get_cookie(sh);

	ct_status_free(sh);
	return (0);
}

static void
contract_ack(ct_evthdl_t e)
{
	int fd;

	if (ct_event_get_flags(e) & CTE_INFO)
		return;

	fd = contract_getfile(ct_event_get_ctid(e), "ctl", O_WRONLY);
	if (fd < 0)
		return;

	(void) ct_ctl_ack(fd, ct_event_get_evid(e));
	(void) close(fd);
}

/*
 * Process a contract event.
 */
static void
contract_event(struct pollfd *poll)
{
	ct_evthdl_t e;
	int err;
	ctid_t ctid;

	if (!(poll->revents & POLLIN)) {
		if (poll->revents & POLLERR)
			console(B_TRUE,
			    "Unknown poll error on my process contract "
			    "pbundle.\n");
		return;
	}

	err = ct_event_read(poll->fd, &e);
	if (err != 0) {
		console(B_TRUE, "Error retrieving contract event: %s.\n",
		    strerror(err));
		return;
	}

	ctid = ct_event_get_ctid(e);

	if (ct_event_get_type(e) == CT_PR_EV_EMPTY) {
		uint64_t cookie;
		int ret, abandon = 1;

		/* If it's svc.startd, restart it.  Else, abandon. */
		ret = contract_cookie(ctid, &cookie);

		if (ret == 0) {
			if (cookie == STARTD_COOKIE &&
			    do_restart_startd) {
				if (smf_debug)
					console(B_TRUE, "Restarting "
					    "svc.startd.\n");

				/*
				 * Account for the failure.  If the failure rate
				 * exceeds a threshold, then drop to maintenance
				 * mode.
				 */
				startd_record_failure();
				if (startd_failure_rate_critical())
					enter_maintenance();

				if (startd_tmpl < 0)
					console(B_TRUE,
					    "Restarting svc.startd in "
					    "improper contract (bad "
					    "template).\n");

				(void) startd_run(startd_cline, startd_tmpl,
				    ctid);

				abandon = 0;
			}
		}

		if (abandon && (err = contract_abandon_id(ctid))) {
			console(B_TRUE, "Couldn't abandon contract %ld: %s.\n",
			    ctid, strerror(err));
		}

		/*
		 * No need to acknowledge the event since either way the
		 * originating contract should be abandoned.
		 */
	} else {
		console(B_TRUE,
		    "Received contract event of unexpected type %d from "
		    "contract %ld.\n", ct_event_get_type(e), ctid);

		if ((ct_event_get_flags(e) & (CTE_INFO | CTE_ACK)) == 0)
			/* Allow unexpected critical events to be released. */
			contract_ack(e);
	}

	ct_event_free(e);
}

/*
 * svc.startd(1M) Management
 */

/*
 * (Re)start svc.startd(1M).  old_ctid should be the contract ID of the old
 * contract, or 0 if we're starting it for the first time.  If wait is true
 * we'll wait for and return the exit value of the child.
 */
static int
startd_run(const char *cline, int tmpl, ctid_t old_ctid)
{
	int err, i, ret, did_activate;
	pid_t pid;
	struct stat sb;

	if (cline[0] == '\0')
		return (-1);

	/*
	 * Don't restart startd if the system is rebooting or shutting down.
	 */
	do {
		ret = stat("/etc/svc/volatile/resetting", &sb);
	} while (ret == -1 && errno == EINTR);

	if (ret == 0) {
		if (smf_debug)
			console(B_TRUE, "Quiescing for reboot.\n");
		(void) pause();
		return (-1);
	}

	err = ct_pr_tmpl_set_transfer(tmpl, old_ctid);
	if (err == EINVAL) {
		console(B_TRUE, "Remake startd_tmpl; reattempt transfer.\n");
		tmpl = startd_tmpl = contract_make_template(0, CT_PR_EV_EMPTY,
		    CT_PR_EV_HWERR, STARTD_COOKIE);

		err = ct_pr_tmpl_set_transfer(tmpl, old_ctid);
	}
	if (err != 0) {
		console(B_TRUE,
		    "Couldn't set transfer parameter of contract template: "
		    "%s.\n", strerror(err));
	}

	if ((err = ct_pr_tmpl_set_svc_fmri(startd_tmpl,
	    SCF_SERVICE_STARTD)) != 0)
		console(B_TRUE,
		    "Can not set svc_fmri in contract template: %s\n",
		    strerror(err));
	if ((err = ct_pr_tmpl_set_svc_aux(startd_tmpl,
	    startd_svc_aux)) != 0)
		console(B_TRUE,
		    "Can not set svc_aux in contract template: %s\n",
		    strerror(err));
	did_activate = !(ct_tmpl_activate(tmpl));
	if (!did_activate)
		console(B_TRUE,
		    "Template activation failed; not starting \"%s\" in "
		    "proper contract.\n", cline);

	/* Hold SIGCLD so we can wait if necessary. */
	(void) sighold(SIGCLD);

	while ((pid = fork()) < 0) {
		if (errno == EPERM) {
			console(B_TRUE, "Insufficient permission to fork.\n");

			/* Now that's a doozy. */
			exit(1);
		}

		console(B_TRUE,
		    "fork() for svc.startd failed: %s.  Will retry in 1 "
		    "second...\n", strerror(errno));

		(void) sleep(1);

		/* Eventually give up? */
	}

	if (pid == 0) {
		/* child */

		/* See the comment in efork() */
		for (i = SIGHUP; i <= SIGRTMAX; ++i) {
			if (i == SIGTTOU || i == SIGTTIN || i == SIGTSTP)
				(void) sigset(i, SIG_IGN);
			else
				(void) sigset(i, SIG_DFL);
		}

		if (smf_options != NULL) {
			/* Put smf_options in the environment. */
			glob_envp[glob_envn] =
			    malloc(sizeof ("SMF_OPTIONS=") - 1 +
			    strlen(smf_options) + 1);

			if (glob_envp[glob_envn] != NULL) {
				/* LINTED */
				(void) sprintf(glob_envp[glob_envn],
				    "SMF_OPTIONS=%s", smf_options);
				glob_envp[glob_envn+1] = NULL;
			} else {
				console(B_TRUE,
				    "Could not set SMF_OPTIONS (%s).\n",
				    strerror(errno));
			}
		}

		if (smf_debug)
			console(B_TRUE, "Executing svc.startd\n");

		(void) execle(SH, "INITSH", "-c", cline, NULL, glob_envp);

		console(B_TRUE, "Could not exec \"%s\" (%s).\n", SH,
		    strerror(errno));

		exit(1);
	}

	/* parent */

	if (did_activate) {
		if (legacy_tmpl < 0 || ct_tmpl_activate(legacy_tmpl) != 0)
			(void) ct_tmpl_clear(tmpl);
	}

	/* Clear the old_ctid reference so the kernel can reclaim it. */
	if (old_ctid != 0)
		(void) ct_pr_tmpl_set_transfer(tmpl, 0);

	(void) sigrelse(SIGCLD);

	return (0);
}

/*
 * void startd_record_failure(void)
 *   Place the current time in our circular array of svc.startd failures.
 */
void
startd_record_failure()
{
	int index = startd_failure_index++ % NSTARTD_FAILURE_TIMES;

	startd_failure_time[index] = gethrtime();
}

/*
 * int startd_failure_rate_critical(void)
 *   Return true if the average failure interval is less than the permitted
 *   interval.  Implicit success if insufficient measurements for an average
 *   exist.
 */
int
startd_failure_rate_critical()
{
	int n = startd_failure_index;
	hrtime_t avg_ns = 0;

	if (startd_failure_index < NSTARTD_FAILURE_TIMES)
		return (0);

	avg_ns =
	    (startd_failure_time[(n - 1) % NSTARTD_FAILURE_TIMES] -
	    startd_failure_time[n % NSTARTD_FAILURE_TIMES]) /
	    NSTARTD_FAILURE_TIMES;

	return (avg_ns < STARTD_FAILURE_RATE_NS);
}

/*
 * returns string that must be free'd
 */

static char
*audit_boot_msg()
{
	char		*b, *p;
	char		desc[] = "booted";
	zoneid_t	zid = getzoneid();

	b = malloc(sizeof (desc) + MAXNAMELEN + 3);
	if (b == NULL)
		return (b);

	p = b;
	p += strlcpy(p, desc, sizeof (desc));
	if (zid != GLOBAL_ZONEID) {
		p += strlcpy(p, ": ", 3);
		(void) getzonenamebyid(zid, p, MAXNAMELEN);
	}
	return (b);
}

/*
 * Generate AUE_init_solaris audit record.  Return 1 if
 * auditing is enabled in case the caller cares.
 *
 * In the case of userint() or a local zone invocation of
 * one_true_init, the process initially contains the audit
 * characteristics of the process that invoked init.  The first pass
 * through here uses those characteristics then for the case of
 * one_true_init in a local zone, clears them so subsequent system
 * state changes won't be attributed to the person who booted the
 * zone.
 */
static int
audit_put_record(int pass_fail, int status, char *msg)
{
	adt_session_data_t	*ah;
	adt_event_data_t	*event;

	if (!adt_audit_enabled())
		return (0);

	/*
	 * the PROC_DATA picks up the context to tell whether this is
	 * an attributed record (auid = -2 is unattributed)
	 */
	if (adt_start_session(&ah, NULL, ADT_USE_PROC_DATA)) {
		console(B_TRUE, "audit failure:  %s\n", strerror(errno));
		return (1);
	}
	event = adt_alloc_event(ah, ADT_init_solaris);
	if (event == NULL) {
		console(B_TRUE, "audit failure:  %s\n", strerror(errno));
		(void) adt_end_session(ah);
		return (1);
	}
	event->adt_init_solaris.info = msg;	/* NULL is ok here */

	if (adt_put_event(event, pass_fail, status)) {
		console(B_TRUE, "audit failure:  %s\n", strerror(errno));
		(void) adt_end_session(ah);
		return (1);
	}
	adt_free_event(event);

	(void) adt_end_session(ah);

	return (1);
}
