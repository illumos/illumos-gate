/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2018 Joyent, Inc.
 */

/*
 * virtual arp daemon -- varpd
 *
 * The virtual arp daemon is the user land counterpart to the overlay driver. To
 * truly understand its purpose and how it fits into things, you should read the
 * overlay big theory statement in uts/common/io/overlay/overlay.c.
 *
 * varod's purpose it to provide a means for looking up the destination on the
 * underlay network for a host on an overlay network and to also be a door
 * server such that dladm(1M) via libdladm can configure and get useful status
 * information. The heavy lifting is all done by libvarpd and the various lookup
 * plugins.
 *
 * When varpd first starts up, we take of chdiring into /var/run/varpd, which is
 * also where we create /var/run/varpd.door, our door server. After that we
 * daemonize and only after we daemonize do we go ahead and load plugins. The
 * reason that we don't load plugins before daemonizing is that they could very
 * well be creating threads and thus lose them all. In general, we want to make
 * things easier on our children and not require them to be fork safe.
 *
 * Once it's spun up, the main varpd thread sits in sigsuspend and really just
 * hangs out waiting for something, libvarpd handles everything else.
 */

#include <libvarpd.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdlib.h>
#include <paths.h>
#include <limits.h>
#include <sys/corectl.h>
#include <signal.h>
#include <strings.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread.h>
#include <priv.h>
#include <libscf.h>

#define	VARPD_EXIT_REQUESTED	SMF_EXIT_OK
#define	VARPD_EXIT_FATAL	SMF_EXIT_ERR_FATAL
#define	VARPD_EXIT_USAGE	SMF_EXIT_ERR_CONFIG

#define	VARPD_RUNDIR	"/var/run/varpd"
#define	VARPD_DEFAULT_DOOR	"/var/run/varpd/varpd.door"

#define	VARPD_PG	"varpd"
#define	VARPD_PROP_INC	"include_path"

static varpd_handle_t *varpd_handle;
static const char *varpd_pname;
static volatile boolean_t varpd_exit = B_FALSE;

/*
 * Debug builds are automatically wired up for umem debugging.
 */
#ifdef	DEBUG
const char *
_umem_debug_init()
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}
#endif	/* DEBUG */

static void
varpd_vwarn(FILE *out, const char *fmt, va_list ap)
{
	int error = errno;

	(void) fprintf(out, "%s: ", varpd_pname);
	(void) vfprintf(out, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(out, ": %s\n", strerror(error));
}

static void
varpd_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	varpd_vwarn(stderr, fmt, ap);
	va_end(ap);

	exit(VARPD_EXIT_FATAL);
}

static void
varpd_dfatal(int dfd, const char *fmt, ...)
{
	int status = VARPD_EXIT_FATAL;
	va_list ap;

	va_start(ap, fmt);
	varpd_vwarn(stdout, fmt, ap);
	va_end(ap);

	/* Take a single shot at this */
	(void) write(dfd, &status, sizeof (status));
	exit(status);
}

/* ARGSUSED */
static int
varpd_plugin_walk_cb(varpd_handle_t *vph, const char *name, void *unused)
{
	(void) printf("loaded %s!\n", name);
	return (0);
}

static int
varpd_dir_setup(void)
{
	int fd;

	if (mkdir(VARPD_RUNDIR, 0700) != 0) {
		if (errno != EEXIST)
			varpd_fatal("failed to create %s: %s", VARPD_RUNDIR,
			    strerror(errno));
	}

	fd = open(VARPD_RUNDIR, O_RDONLY);
	if (fd < 0)
		varpd_fatal("failed to open %s: %s", VARPD_RUNDIR,
		    strerror(errno));

	if (fchown(fd, UID_NETADM, GID_NETADM) != 0)
		varpd_fatal("failed to chown %s: %s\n", VARPD_RUNDIR,
		    strerror(errno));

	return (fd);
}

/*
 * Because varpd is generally run under SMF, we opt to keep its stdout and
 * stderr to be whatever our parent set them up to be.
 */
static void
varpd_fd_setup(void)
{
	int dupfd;

	closefrom(STDERR_FILENO + 1);
	dupfd = open(_PATH_DEVNULL, O_RDONLY);
	if (dupfd < 0)
		varpd_fatal("failed to open %s: %s", _PATH_DEVNULL,
		    strerror(errno));
	if (dup2(dupfd, STDIN_FILENO) == -1)
		varpd_fatal("failed to dup out stdin: %s", strerror(errno));
}

/*
 * We borrow fmd's daemonization style. Basically, the parent waits for the
 * child to successfully set up a door and recover all of the old configurations
 * before we say that we're good to go.
 */
static int
varpd_daemonize(int dirfd)
{
	char path[PATH_MAX];
	struct rlimit rlim;
	sigset_t set, oset;
	int estatus, pfds[2];
	pid_t child;
	priv_set_t *pset;

	/*
	 * Set a per-process core path to be inside of /var/run/varpd. Make sure
	 * that we aren't limited in our dump size.
	 */
	(void) snprintf(path, sizeof (path),
	    "/var/run/varpd/core.%s.%%p", varpd_pname);
	(void) core_set_process_path(path, strlen(path) + 1, getpid());

	rlim.rlim_cur = RLIM_INFINITY;
	rlim.rlim_max = RLIM_INFINITY;
	(void) setrlimit(RLIMIT_CORE, &rlim);

	/*
	 * Claim as many file descriptors as the system will let us.
	 */
	if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
		rlim.rlim_cur = rlim.rlim_max;
		(void) setrlimit(RLIMIT_NOFILE, &rlim);
	}

	/*
	 * chdir /var/run/varpd
	 */
	if (fchdir(dirfd) != 0)
		varpd_fatal("failed to chdir to %s", VARPD_RUNDIR);


	/*
	 * At this point block all signals going in so we don't have the parent
	 * mistakingly exit when the child is running, but never block SIGABRT.
	 */
	if (sigfillset(&set) != 0)
		abort();
	if (sigdelset(&set, SIGABRT) != 0)
		abort();
	if (sigprocmask(SIG_BLOCK, &set, &oset) != 0)
		abort();

	/*
	 * Do the fork+setsid dance.
	 */
	if (pipe(pfds) != 0)
		varpd_fatal("failed to create pipe for daemonizing");

	if ((child = fork()) == -1)
		varpd_fatal("failed to fork for daemonizing");

	if (child != 0) {
		/* We'll be exiting shortly, so allow for silent failure */
		(void) close(pfds[1]);
		if (read(pfds[0], &estatus, sizeof (estatus)) ==
		    sizeof (estatus))
			_exit(estatus);

		if (waitpid(child, &estatus, 0) == child && WIFEXITED(estatus))
			_exit(WEXITSTATUS(estatus));

		_exit(VARPD_EXIT_FATAL);
	}

	/*
	 * Drop privileges here.
	 *
	 * We should make sure we keep around PRIV_NET_PRIVADDR and
	 * PRIV_SYS_DLCONFIG, but drop everything else; however, keep basic
	 * privs and have our child drop them.
	 *
	 * We should also run as netadm:netadm and drop all of our groups.
	 */
	if (setgroups(0, NULL) != 0)
		abort();
	if (setgid(GID_NETADM) == -1 || seteuid(UID_NETADM) == -1)
		abort();
	if ((pset = priv_allocset()) == NULL)
		abort();
	priv_basicset(pset);
	if (priv_delset(pset, PRIV_PROC_EXEC) == -1 ||
	    priv_delset(pset, PRIV_PROC_INFO) == -1 ||
	    priv_delset(pset, PRIV_PROC_FORK) == -1 ||
	    priv_delset(pset, PRIV_PROC_SESSION) == -1 ||
	    priv_delset(pset, PRIV_FILE_LINK_ANY) == -1 ||
	    priv_addset(pset, PRIV_SYS_DL_CONFIG) == -1 ||
	    priv_addset(pset, PRIV_NET_PRIVADDR) == -1) {
		abort();
	}
	/*
	 * Remove privs from the permitted set. That will cause them to be
	 * removed from the effective set. We want to make sure that in the case
	 * of a vulnerability, something can't get back in here and wreak more
	 * havoc. But if we want non-basic privs in the effective set, we have
	 * to request them explicitly.
	 */
	if (setppriv(PRIV_SET, PRIV_PERMITTED, pset) == -1)
		abort();
	if (setppriv(PRIV_SET, PRIV_EFFECTIVE, pset) == -1)
		abort();

	priv_freeset(pset);

	if (close(pfds[0]) != 0)
		abort();
	if (setsid() == -1)
		abort();
	if (sigprocmask(SIG_SETMASK, &oset, NULL) != 0)
		abort();
	(void) umask(0022);

	return (pfds[1]);
}

static int
varpd_setup_lookup_threads(void)
{
	int ret;
	long i, ncpus = sysconf(_SC_NPROCESSORS_ONLN) * 2 + 1;

	if (ncpus <= 0)
		abort();
	for (i = 0; i < ncpus; i++) {
		thread_t thr;

		ret = thr_create(NULL, 0,
		    (void *(*)(void *))libvarpd_overlay_lookup_run,
		    varpd_handle, THR_DETACHED | THR_DAEMON, &thr);
		if (ret != 0)
			return (ret);
	}

	return (0);
}

static void
varpd_cleanup(void)
{
	varpd_exit = B_TRUE;
}

/*
 * Load default information from SMF and apply any of if necessary. We recognize
 * the following properties:
 *
 * 	varpd/include_path		Treat these as a series of -i options.
 *
 * If we're not under SMF, just move on.
 */
static void
varpd_load_smf(int dfd)
{
	char *fmri, *inc;
	scf_simple_prop_t *prop;

	if ((fmri = getenv("SMF_FMRI")) == NULL)
		return;

	if ((prop = scf_simple_prop_get(NULL, fmri, VARPD_PG,
	    VARPD_PROP_INC)) == NULL)
		return;

	while ((inc = scf_simple_prop_next_astring(prop)) != NULL) {
		int err = libvarpd_plugin_load(varpd_handle, inc);
		if (err != 0) {
			varpd_dfatal(dfd, "failed to load from %s: %s\n",
			    inc, strerror(err));
		}
	}

	scf_simple_prop_free(prop);
}

/*
 * There are a bunch of things we need to do to be a proper daemon here.
 *
 *   o Ensure that /var/run/varpd exists or create it
 *   o make stdin /dev/null (stdout?)
 *   o Ensure any other fds that we somehow inherited are closed, eg.
 *     closefrom()
 *   o Properly daemonize
 *   o Mask all signals except sigabrt before creating our first door -- all
 *     other doors will inherit from that.
 *   o Have the main thread sigsuspend looking for most things that are
 *     actionable...
 */
int
main(int argc, char *argv[])
{
	int err, c, dirfd, dfd, i;
	const char *doorpath = VARPD_DEFAULT_DOOR;
	sigset_t set;
	struct sigaction act;
	int nincpath = 0, nextincpath = 0;
	char **incpath = NULL;

	varpd_pname = basename(argv[0]);

	/*
	 * We want to clean up our file descriptors before we do anything else
	 * as we can't assume that libvarpd won't open file descriptors, etc.
	 */
	varpd_fd_setup();

	if ((err = libvarpd_create(&varpd_handle)) != 0) {
		varpd_fatal("failed to open a libvarpd handle");
		return (1);
	}

	while ((c = getopt(argc, argv, ":i:d:")) != -1) {
		switch (c) {
		case 'i':
			if (nextincpath == nincpath) {
				if (nincpath == 0)
					nincpath = 16;
				else
					nincpath *= 2;
				incpath = realloc(incpath, sizeof (char *) *
				    nincpath);
				if (incpath == NULL) {
					(void) fprintf(stderr, "failed to "
					    "allocate memory for the %dth "
					    "-I option: %s\n", nextincpath + 1,
					    strerror(errno));
				}

			}
			incpath[nextincpath] = optarg;
			nextincpath++;
			break;
		case 'd':
			doorpath = optarg;
			break;
		default:
			(void) fprintf(stderr, "unknown option: %c\n", c);
			return (1);
		}
	}

	dirfd = varpd_dir_setup();

	(void) libvarpd_plugin_walk(varpd_handle, varpd_plugin_walk_cb, NULL);

	dfd = varpd_daemonize(dirfd);

	/*
	 * Now that we're in the child, go ahead and load all of our plug-ins.
	 * We do this, in part, because these plug-ins may need threads of their
	 * own and fork won't preserve those and we'd rather the plug-ins don't
	 * have to learn about fork-handlers.
	 */
	for (i = 0; i < nextincpath; i++) {
		err = libvarpd_plugin_load(varpd_handle, incpath[i]);
		if (err != 0) {
			varpd_dfatal(dfd, "failed to load from %s: %s\n",
			    incpath[i], strerror(err));
		}
	}

	varpd_load_smf(dfd);

	if ((err = libvarpd_persist_enable(varpd_handle, VARPD_RUNDIR)) != 0)
		varpd_dfatal(dfd, "failed to enable varpd persistence: %s\n",
		    strerror(err));

	if ((err = libvarpd_persist_restore(varpd_handle)) != 0)
		varpd_dfatal(dfd, "failed to enable varpd persistence: %s\n",
		    strerror(err));

	/*
	 * The ur-door thread will inherit from this signal mask. So set it to
	 * what we want before doing anything else. In addition, so will our
	 * threads that handle varpd lookups.
	 */
	if (sigfillset(&set) != 0)
		varpd_dfatal(dfd, "failed to fill a signal set...");

	if (sigdelset(&set, SIGABRT) != 0)
		varpd_dfatal(dfd, "failed to unmask SIGABRT");

	if (sigprocmask(SIG_BLOCK, &set, NULL) != 0)
		varpd_dfatal(dfd, "failed to set our door signal mask");

	if ((err = varpd_setup_lookup_threads()) != 0)
		varpd_dfatal(dfd, "failed to create lookup threads: %s\n",
		    strerror(err));

	if ((err = libvarpd_door_server_create(varpd_handle, doorpath)) != 0)
		varpd_dfatal(dfd, "failed to create door server at %s: %s\n",
		    doorpath, strerror(err));

	/*
	 * At this point, finish up signal intialization and finally go ahead,
	 * notify the parent that we're okay, and enter the sigsuspend loop.
	 */
	bzero(&act, sizeof (struct sigaction));
	act.sa_handler = varpd_cleanup;
	if (sigfillset(&act.sa_mask) != 0)
		varpd_dfatal(dfd, "failed to fill sigaction mask");
	act.sa_flags = 0;
	if (sigaction(SIGHUP, &act, NULL) != 0)
		varpd_dfatal(dfd, "failed to register HUP handler");
	if (sigdelset(&set, SIGHUP) != 0)
		varpd_dfatal(dfd, "failed to remove HUP from mask");
	if (sigaction(SIGQUIT, &act, NULL) != 0)
		varpd_dfatal(dfd, "failed to register QUIT handler");
	if (sigdelset(&set, SIGQUIT) != 0)
		varpd_dfatal(dfd, "failed to remove QUIT from mask");
	if (sigaction(SIGINT, &act, NULL) != 0)
		varpd_dfatal(dfd, "failed to register INT handler");
	if (sigdelset(&set, SIGINT) != 0)
		varpd_dfatal(dfd, "failed to remove INT from mask");
	if (sigaction(SIGTERM, &act, NULL) != 0)
		varpd_dfatal(dfd, "failed to register TERM handler");
	if (sigdelset(&set, SIGTERM) != 0)
		varpd_dfatal(dfd, "failed to remove TERM from mask");

	err = 0;
	(void) write(dfd, &err, sizeof (err));
	(void) close(dfd);

	for (;;) {
		if (sigsuspend(&set) == -1)
			if (errno == EFAULT)
				abort();
		if (varpd_exit == B_TRUE)
			break;
	}

	libvarpd_door_server_destroy(varpd_handle);
	libvarpd_destroy(varpd_handle);

	return (VARPD_EXIT_REQUESTED);
}
