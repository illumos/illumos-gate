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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The Solaris package installer in-memory database server.
 *
 * We'll keep the contents file as before; but we cache it
 * and we don't write it as often.  Instead, we log all
 * modifications to the log file.
 * Using the contents file and the logfile, the pkgserv can
 * rebuild the up-to-date contents file.
 * The logfile is constructed so that rebuilding the
 * contents file with the logfile is idempotent.
 *
 * The libpkg will start the daemon.
 *
 * The pkgserv will daemonize itself; the parent process
 * waits until the child process has initialized and will
 * start the door server.
 * If any error occurs during start-up, the error messages
 * are printed to stderr and the daemon will exit.
 * After start-up, any further errors are logged to syslog.
 * The parent pkgserv will exit with:
 *	0	- We've started
 *	1	- We couldn't start (locked)
 *	2	- Other problems (error on stderr)
 *     99	- Nothing reported; the caller must report.
 *
 * The daemon will timeout, by default.  It will write the
 * contents file after a first timeout; and after a further
 * timeout, the daemon will exit.
 *
 * The daemon will only timeout if the current "client" has exited;
 * to this end, we always look at the pid of the last caller.
 * If the last client is no longer around, we record the new client.
 * In the typical case of running installf/removef from a post/preinstall
 * script, we continue to follow the pkginstall/pkgremove client's pid.
 *
 * In the particular case of install, we make sure the daemon
 * sticks around.  (Install == install, (live)upgrade, zone install)
 */

#ifdef lint
#undef _FILE_OFFSET_BITS
#endif

#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <synch.h>
#include <sys/avl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <syslog.h>
#include <limits.h>
#include <thread.h>
#include <ucred.h>
#include <umem.h>
#include <unistd.h>
#include <libintl.h>
#include <locale.h>

#include <pkglib.h>

#define	SADM_DIR	"/var/sadm/install"

#define	LOCK		".pkg.lock"
#define	CLIENTLOCK	".pkg.lock.client"
#define	CONTENTS	"contents"
#define	TCONTENTS	"t.contents"
#define	BADCONTENTS	"contents.badXXXXXX"

#define	LLNANOSEC	((int64_t)NANOSEC)

#define	DUMPTIMEOUT	60
#define	EXITTIMEOUT	300

/*
 * Contents file storage format.  At install time, the amount of memory
 * might be limited, so we make sure that we use as little memory
 * as possible.  The package tools modify the entries; so we install the
 * single lines.  We also remember the length of the path; this is needed
 * for avlcmp and we return it to the tools.  This saves time.
 *
 * All strings are allocated using umem_alloc.
 */
typedef struct pkgentry {
	char *line;		/* The contents line for the file */
	avl_node_t avl;		/* The avl header */
	int pkgoff;		/* Where the packages live; start with SP */
	int pathlen;		/* The length of the pathname */
	int len;		/* Length of the line (incl NUL) */
} pkgentry_t;

static char IS_ST0[256];
static char IS_ST0Q[256];

static void pkg_door_srv(void *, char *, size_t, door_desc_t *, uint_t);
static char *file_find(pkgfilter_t *, int *);
static void parse_contents(void);
static int parse_log(void);
static void pkgdump(void);
static int logflush(void);
static int avlcmp(const void *, const void *);
static void freeentry(pkgentry_t *);
static void swapentry(pkgentry_t *, pkgentry_t *);
static int establish_lock(char *);
static int no_memory_abort(void);
static int pkgfilter(pkgfilter_t *, door_desc_t *);
static int pkgaddlines(pkgfilter_t *);
static void finish(void);
static void signal_handler(int);
static void my_cond_reltimedwait(hrtime_t, int);
static hrtime_t time_since_(hrtime_t);

/*
 * Server actions
 *	- set mode (contents file, log file)
 *	- roll log
 *	- remove package
 *	- merge package entries
 */

static FILE *log;
static char *door = PKGDOOR;

static avl_tree_t listp, *list = &listp;

/* Keep the "the last command modified the contents file ... */
static char *ccmnt[2];
static int cind = 0;

static mutex_t mtx = DEFAULTMUTEX;
static cond_t cv = DEFAULTCV;

static int flushbeforemark = 1;
static int logerrcnt = 0;
static int loglines = 0;
static int suppressed = 0;
static int logcount;
static int ndumps;
static int ncalls;
static int changes;
static hrtime_t lastchange;
static hrtime_t lastcall;
static volatile int want_to_quit;
static boolean_t read_only = B_FALSE;
static boolean_t permanent = B_FALSE;
static boolean_t one_shot = B_FALSE;
static int write_locked;
static pid_t client_pid;
static int verbose = 1;
static hrtime_t dumptimeout = DUMPTIMEOUT;
static boolean_t sync_needed = B_FALSE;

static uid_t myuid;

static char marker[] = "###Marker\n";

static umem_cache_t *ecache;

static char pkgdir[PATH_MAX];

static void
server_main(int argc, char **argv)
{
	int did;
	int c;
	struct statvfs vfsbuf;
	int imexit = 0;
	pid_t parent;
	char *root = NULL;
	char *sadmdir = NULL;
	hrtime_t delta;
	int dir = 0;
	int dfd;

	(void) set_prog_name("pkgserv");

	openlog("pkgserv", LOG_PID | LOG_ODELAY, LOG_DAEMON);

	while ((c = getopt(argc, argv, "d:eoN:pP:R:r:")) != EOF) {
		switch (c) {
		case 'e':
			imexit = 1;
			break;
		case 'd':
			sadmdir = optarg;
			if (*sadmdir != '/' || strlen(sadmdir) >= PATH_MAX ||
			    access(sadmdir, X_OK) != 0)
				exit(99);
			break;
		case 'N':
			(void) set_prog_name(optarg);
			break;
		case 'o':
			one_shot = B_TRUE;
			verbose = 0;
			break;
		case 'p':
			/*
			 * We are updating possibly many zones; so we're not
			 * dumping based on a short timeout and we will not
			 * exit.
			 */
			permanent = B_TRUE;
			dumptimeout = 3600;
			break;
		case 'P':
			client_pid = atoi(optarg);
			break;
		case 'R':
			root = optarg;
			if (*root != '/' || strlen(root) >= PATH_MAX ||
			    access(root, X_OK) != 0)
				exit(99);
			break;
		case 'r':
			read_only = B_TRUE;
			one_shot = B_TRUE;
			verbose = 0;
			door = optarg;
			break;
		default:
			exit(99);
		}
	}

	if (one_shot && permanent) {
		progerr(gettext("Incorrect Usage"));
		exit(99);
	}

	umem_nofail_callback(no_memory_abort);

	if (root != NULL && strcmp(root, "/") != 0) {
		if (snprintf(pkgdir, PATH_MAX, "%s%s", root,
		    sadmdir == NULL ? SADM_DIR : sadmdir) >= PATH_MAX) {
			exit(99);
		}
	} else {
		if (sadmdir == NULL)
			(void) strcpy(pkgdir, SADM_DIR);
		else
			(void) strcpy(pkgdir, sadmdir);
	}

	if (chdir(pkgdir) != 0) {
		progerr(gettext("can't chdir to %s"), pkgdir);
		exit(2);
	}

	closefrom(3);

	if (!read_only && establish_lock(LOCK) < 0) {
		progerr(gettext(
		    "couldn't lock in %s (server running?): %s"),
		    pkgdir, strerror(errno));
		exit(1);
	}

	did = door_create(pkg_door_srv, 0, DOOR_REFUSE_DESC);
	if (did == -1) {
		progerr("door_create: %s", strerror(errno));
		exit(2);
	}

	(void) fdetach(door);

	if ((dfd = creat(door, 0644)) < 0 || close(dfd) < 0) {
		progerr("door_create: %s", strerror(errno));
		exit(2);
	}

	(void) mutex_lock(&mtx);

	myuid = geteuid();

	(void) sigset(SIGHUP, signal_handler);
	(void) sigset(SIGTERM, signal_handler);
	(void) sigset(SIGINT, signal_handler);
	(void) sigset(SIGQUIT, signal_handler);

	(void) signal(SIGPIPE, SIG_IGN);

	(void) atexit(finish);

	if (fattach(did, door) != 0) {
		progerr(gettext("attach door: %s"), strerror(errno));
		exit(2);
	}
	(void) close(did);

	ecache = umem_cache_create("entry", sizeof (pkgentry_t),
	    sizeof (char *), NULL, NULL, NULL, NULL, NULL, 0);

	avl_create(list, avlcmp, sizeof (pkgentry_t),
	    offsetof(pkgentry_t, avl));

	IS_ST0['\0'] = 1;
	IS_ST0[' '] = 1;
	IS_ST0['\t'] = 1;

	IS_ST0Q['\0'] = 1;
	IS_ST0Q[' '] = 1;
	IS_ST0Q['\t'] = 1;
	IS_ST0Q['='] = 1;

	parse_contents();
	if (parse_log() > 0)
		pkgdump();

	if (imexit)
		exit(0);

	if (statvfs(".", &vfsbuf) != 0) {
		progerr(gettext("statvfs: %s"), strerror(errno));
		exit(2);
	}

	if (strcmp(vfsbuf.f_basetype, "zfs") == 0)
		flushbeforemark = 0;

	/* We've started, tell the parent */
	parent = getppid();
	if (parent != 1)
		(void) kill(parent, SIGUSR1);

	if (!one_shot) {
		int fd;
		(void) setsid();
		fd = open("/dev/null", O_RDWR, 0);
		if (fd >= 0) {
			(void) dup2(fd, STDIN_FILENO);
			(void) dup2(fd, STDOUT_FILENO);
			(void) dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void) close(fd);
		}
	}

	lastcall = lastchange = gethrtime();

	/*
	 * Start the main thread, here is where we unlock the mutex.
	 */
	for (;;) {
		if (want_to_quit) {
			pkgdump();
			exit(0);
		}
		/* Wait forever when root or when there's a running filter */
		if (write_locked ||
		    (!one_shot && permanent && dir == changes)) {
			(void) cond_wait(&cv, &mtx);
			continue;
		}
		delta = time_since_(lastchange);
		/* Wait until DUMPTIMEOUT after last change before we pkgdump */
		if (delta < dumptimeout * LLNANOSEC) {
			my_cond_reltimedwait(delta, dumptimeout);
			continue;
		}
		/* Client still around? Just wait then. */
		if (client_pid > 1 && kill(client_pid, 0) == 0) {
			lastchange = lastcall = gethrtime();
			continue;
		}
		/* Wait for another EXITTIMEOUT seconds before we exit */
		if ((one_shot || !permanent) && dir == changes) {
			delta = time_since_(lastcall);
			if (delta < EXITTIMEOUT * LLNANOSEC) {
				my_cond_reltimedwait(delta, EXITTIMEOUT);
				continue;
			}
			exit(0);
		}
		pkgdump();
		dir = changes;
	}

	/*NOTREACHED*/
}

/*ARGSUSED*/
static void
nothing(int sig)
{
}

int
main(int argc, char **argv)
{
	int sig;
	sigset_t sset;
	int stat;

	/*
	 * We're starting the daemon; this process exits when the door
	 * server is established or when it fails to establish.
	 * We wait until the child process sends a SIGUSR1 or when it
	 * exits.
	 * We keep around who started us and as long as it lives, we don't
	 * exit.
	 */

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	client_pid = getppid();

	(void) sigemptyset(&sset);
	(void) sigaddset(&sset, SIGUSR1);
	(void) sigaddset(&sset, SIGCLD);

	/* We need to catch the SIGCLD before we can sigwait for it. */
	(void) sigset(SIGCLD, nothing);
	/* We need to make sure that SIGUSR1 is not ignored. */
	(void) sigset(SIGUSR1, SIG_DFL);
	(void) sigprocmask(SIG_BLOCK, &sset, NULL);

	/* We install the contents file readable. */
	(void) umask(022);

	switch (fork()) {
	case -1:
		exit(99);
		/*NOTREACHED*/
	case 0:
		server_main(argc, argv);
		/*NOTREACHED*/
	default:
		/* In the parent */
		break;
	}

	for (;;) {
		sig = sigwait(&sset);

		switch (sig) {
		case SIGCLD:
			if (wait(&stat) > 0) {
				if (WIFEXITED(stat))
					_exit(WEXITSTATUS(stat));
				else if (WIFSIGNALED(stat))
					_exit(99);
			}
			break;
		case SIGUSR1:
			_exit(0);
		}
	}
}

/*ARGSUSED*/
static void
pkg_door_srv(void *cookie, char *argp, size_t asz, door_desc_t *dp,
    uint_t ndesc)
{
	char *p = NULL;
	pkgcmd_t *pcmd = (pkgcmd_t *)argp;
	ucred_t *uc = NULL;
	uid_t caller;
	pid_t pcaller;
	door_desc_t ddp;
	int dnum = 0;
	int one = 1;
	int len = -1;

	if (asz < sizeof (pkgcmd_t)) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	if (door_ucred(&uc) != 0) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	caller = ucred_geteuid(uc);
	pcaller = ucred_getpid(uc);
	ucred_free(uc);

	if (caller != myuid) {
		(void) door_return(NULL, 0, NULL, 0);
		return;
	}

	(void) mutex_lock(&mtx);
	ncalls++;

	if (pcaller != client_pid && pcaller != -1 &&
	    (client_pid == 1 || kill(client_pid, 0) != 0)) {
		client_pid = pcaller;
	}

	if (PKG_WRITE_COMMAND(pcmd->cmd))
		while (write_locked > 0)
			(void) cond_wait(&cv, &mtx);

	switch (pcmd->cmd) {
	case PKG_FINDFILE:
		p = file_find((pkgfilter_t *)argp, &len);
		break;
	case PKG_DUMP:
		if (read_only)
			goto err;
		if (logcount > 0)
			pkgdump();
		break;
	case PKG_EXIT:
		if (logcount > 0)
			pkgdump();
		exit(0);
		/*NOTREACHED*/
	case PKG_PKGSYNC:
		if (read_only || logflush() != 0)
			goto err;
		break;
	case PKG_FILTER:
		if (pkgfilter((pkgfilter_t *)argp, &ddp) == 0)
			dnum = 1;
		break;
	case PKG_ADDLINES:
		if (read_only)
			goto err;
		changes++;

		if (pkgaddlines((pkgfilter_t *)argp) != 0)
			goto err;
		/* If we've updated the database, tell the dump thread */
		lastchange = gethrtime();
		(void) cond_broadcast(&cv);
		break;
	case PKG_NOP:
		/* Do nothing but register the current client's pid. */
		break;
	default:
		goto err;
	}

	lastcall = gethrtime();
	(void) mutex_unlock(&mtx);
	(void) door_return(p, len != -1 ? len : p == NULL ? 0 : strlen(p) + 1,
	    dnum == 0 ? NULL : &ddp, dnum);
	return;

err:
	(void) mutex_unlock(&mtx);
	(void) door_return((void *)&one, 4, NULL, 0);
}

/*
 * This function returns the length of the string including exactly
 * nf fields.
 */
static ptrdiff_t
fieldoff(char *info, int nf)
{
	char *q = info;

	while (nf > 0) {
		if (IS_ST0[(unsigned char)*q++]) {
			if (q[-1] == 0)
				break;
			nf--;
		}
	}
	return (q - info - 1);
}

/*
 * The buf points into list of \n delimited lines.  We copy it,
 * removing the newline and adding a \0.
 */
static char *
mystrcpy(char *buf, int len)
{
	char *res = umem_alloc(len, UMEM_NOFAIL);

	(void) memcpy(res, buf, len - 1);
	res[len - 1] = '\0';
	return (res);
}

/*
 * Entry: a single line without the NEWLINE
 * Return: the package entry with the path determined.
 */
static pkgentry_t *
parse_line(char *buf, int blen, boolean_t full)
{
	char *t;
	pkgentry_t *p;
	int nfields;

	p = umem_cache_alloc(ecache, UMEM_NOFAIL);
	buf = p->line = mystrcpy(buf, blen + 1);
	p->len = blen + 1;

	t = buf;

	while (!IS_ST0Q[(unsigned char)*t++])
		;

	p->pathlen = t - buf - 1;
	if (p->pathlen == 0 || p->pathlen >= PATH_MAX) {
		progerr("bad entry read in contents file");
		logerr("pathname: Unknown");
		logerr("problem: unable to read pathname field");
		if (one_shot)
			exit(2);
	}
	if (t[-1] == '=')
		while (!IS_ST0[(unsigned char)*t++])
			;

	/* Partial as found in the "-" entries for log */
	if (t[-1] == '\0') {
		if (full)
			goto badline;

		p->pkgoff = -1;
		return (p);
	}

	switch (*t) {
	case '?':
		nfields = 0;
		break;
	case 's':
	case 'l':
		/* Fields: class */
		nfields = 1;
		break;
	case 'p':
	case 'x':
	case 'd':
		/* class mode owner group */
		nfields = 4;
		break;
	case 'f':
	case 'e':
	case 'v':
		/* class mode owner group size csum time */
		nfields = 7;
		break;
	case 'c':
	case 'b':
		/* class major minor mode owner group */
		nfields = 6;
		break;
	default:
		progerr("bad entry read in contents file");
		logerr("pathname: %.*s", p->pathlen, p->line);
		logerr("problem: unknown ftype");
		freeentry(p);
		if (one_shot)
			exit(2);
		return (NULL);
	}

	p->pkgoff = t + fieldoff(t, nfields + 1) - buf;

	if (p->line[p->pkgoff] != '\0' || p->pkgoff == p->len - 1)
		return (p);

badline:
	progerr(gettext("bad entry read in contents file"));
	logerr(gettext("pathname: Unknown"));
	logerr(gettext("problem: unknown ftype"));
	freeentry(p);
	if (one_shot)
		exit(2);
	return (NULL);
}

static void
handle_comments(char *buf, int len)
{
	if (cind >= 2)
		return;

	if (buf[0] != '#')
		return;

	if (ccmnt[cind] != NULL)
		umem_free(ccmnt[cind], strlen(ccmnt[cind]) + 1);
	ccmnt[cind] = mystrcpy(buf, len);
	cind++;
}

static void
parse_contents(void)
{
	int cnt;
	pkgentry_t *ent, *e2;
	avl_index_t where;
	int num = 0;
	struct stat stb;
	ptrdiff_t off;
	char *p, *q, *map;
	pkgentry_t *lastentry = NULL;
	int d;
	int cntserrs = 0;

	cnt = open(CONTENTS, O_RDONLY);

	cind = 0;

	if (cnt == -1) {
		if (errno == ENOENT)
			return;
		exit(99);
	}

	if (fstat(cnt, &stb) != 0) {
		(void) close(cnt);
		exit(99);
	}
	if (stb.st_size == 0) {
		(void) close(cnt);
		return;
	}

	map = mmap(0, stb.st_size, PROT_READ, MAP_PRIVATE, cnt, 0);
	(void) close(cnt);
	if (map == (char *)-1)
		return;

	(void) madvise(map, stb.st_size, MADV_WILLNEED);

	for (off = 0; off < stb.st_size; off += q - p) {
		p = map + off;
		q = memchr(p, '\n', stb.st_size - off);
		if (q == NULL)
			break;

		q++;
		num++;
		if (p[0] == '#' || p[0] == '\n') {
			handle_comments(p, q - p);
			continue;
		}
		ent = parse_line(p, q - p - 1, B_TRUE);

		if (ent == NULL) {
			cntserrs++;
			continue;
		}

		/*
		 * We save time by assuming the database is sorted; by
		 * using avl_insert_here(), building the tree is nearly free.
		 * lastentry always contains the last entry in the AVL tree.
		 */
		if (lastentry == NULL) {
			avl_add(list, ent);
			lastentry = ent;
		} else if ((d = avlcmp(ent, lastentry)) == 1) {
			avl_insert_here(list, ent, lastentry, AVL_AFTER);
			lastentry = ent;
		} else if (d == 0 ||
		    (e2 = avl_find(list, ent, &where)) != NULL) {
			/*
			 * This can only happen if the contents file is bad;
			 * this can, e.g., happen with the old SQL contents DB,
			 * it didn't sort properly.  Assume the first one
			 * is the correct one, but who knows?
			 */
			if (d == 0)
				e2 = lastentry;
			if (strcmp(ent->line, e2->line) != 0) {
				progerr(gettext("two entries for %.*s"),
				    ent->pathlen, ent->line);
				cntserrs++;
			}
			freeentry(ent);
		} else {
			/* Out of order: not an error for us, really. */
			progerr(gettext("bad read of contents file"));
			logerr(gettext("pathname: Unknown"));
			logerr(gettext(
			    "problem: unable to read pathname field"));
			if (one_shot)
				exit(2);
			avl_insert(list, ent, where);
		}
	}

	cind = 0;

	(void) munmap(map, stb.st_size);

	/* By default, we ignore bad lines, keep them in a copy. */
	if (cntserrs > 0 && stb.st_nlink == 1) {
		char bcf[sizeof (BADCONTENTS)];

		(void) strcpy(bcf, BADCONTENTS);
		if (mktemp(bcf) != NULL) {
			(void) link(CONTENTS, bcf);
			syslog(LOG_WARNING, "A bad contents file was saved: %s",
			    bcf);
		}
	}
}

static int
parse_log(void)
{
	pkgentry_t *ent, *look;
	avl_index_t where;
	int num = 0;
	int logfd;
	struct stat stb;
	int mlen = strlen(marker);
	off_t realend;
	ptrdiff_t off;
	char *p, *q, *map;

	logfd = open(PKGLOG, O_RDONLY);

	if (logfd < 0) {
		if (errno == ENOENT)
			return (0);
		progerr(gettext("cannot read "PKGLOG": %s"), strerror(errno));
		exit(2);
	}

	if (fstat(logfd, &stb) != 0) {
		progerr(gettext("cannot stat "PKGLOG": %s"), strerror(errno));
		exit(2);
	}

	if (stb.st_size == 0) {
		(void) close(logfd);
		/* Force pkgdump && remove of the logfile. */
		return (1);
	}

	map = mmap(0, stb.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE,
	    logfd, 0);
	(void) close(logfd);
	if (map == (char *)-1) {
		progerr(gettext("Cannot mmap the "PKGLOG": %s"),
		    strerror(errno));
		exit(2);
	}

	cind = 0;

	realend = stb.st_size;

	if (memcmp(map + realend - mlen, marker, mlen) != 0) {
		progerr(gettext(PKGLOG" is not complete"));

		map[stb.st_size - 1] = '\0'; /* for strstr() */
		realend = 0;
		for (p = map; q = strstr(p, marker); ) {
			if (q == map || q[-1] == '\n')
				realend = q - map + mlen;
			p = q + mlen;
		}
		progerr(gettext("Ignoring %ld bytes from log"),
		    (long)(stb.st_size - realend));
	}

	for (off = 0; off < realend; off += q - p) {
		p = map + off;
		q = memchr(p, '\n', realend - off);
		if (q == NULL)
			break;

		q++;
		num++;
		if (p[0] == '#' || p[0] == '\n') {
			if (memcmp(marker, p, mlen) == 0)
				cind = 0;
			else
				handle_comments(p, q - p);
			continue;
		}

		ent = parse_line(p + 1, q - (p + 1) - 1, p[0] != '-');
		if (ent == NULL)
			continue;
		look = avl_find(list, ent, &where);
		/*
		 * The log can be replayed; so any value of "look" is
		 * not unexpected.
		 */
		switch (p[0]) {
		case '+':
		case '=':
			if (look != NULL)
				swapentry(look, ent);
			else
				avl_insert(list, ent, where);
			break;
		case '-':
			if (look != NULL) {
				avl_remove(list, look);
				freeentry(look);
			}
			freeentry(ent);
			break;
		default:
			freeentry(ent);
			progerr(gettext("log %d: bad line"), num);
			break;
		}
	}
	(void) munmap(map, stb.st_size);

	/* Force pkgdump && remove of the logfile if there are no valid mods. */
	return (num == 0 ? 1 : num);
}

static char *
file_find(pkgfilter_t *cmd, int *len)
{
	pkgentry_t p;
	pkgentry_t *look;

	p.line = cmd->buf;
	p.pathlen = cmd->len;

	look = avl_find(list, &p, NULL);

	if (look == NULL)
		return (NULL);

	*len = look->len;
	return (look->line);
}

static void
pkgdump(void)
{
	FILE *cnts;
	int err = 0;
	pkgentry_t *p;

	if (read_only)
		return;

	/* We cannot dump when the current transaction is not complete. */
	if (sync_needed)
		return;

	cnts = fopen(TCONTENTS, "w");

	if (cnts == NULL)
		exit(99);

	for (p = avl_first(list); p != NULL; p = AVL_NEXT(list, p)) {
		if (fprintf(cnts, "%s\n", p->line) < 0)
			err++;
	}

	if (ccmnt[0] != NULL)
		(void) fprintf(cnts, "%s\n", ccmnt[0]);
	if (ccmnt[1] != NULL)
		(void) fprintf(cnts, "%s\n", ccmnt[1]);

	if (err != 0 || fflush(cnts) == EOF || fsync(fileno(cnts)) != 0 ||
	    fclose(cnts) == EOF || rename(TCONTENTS, CONTENTS) != 0) {
		err++;
	}

	if (err != 0) {
		progerr("cannot rewrite the contents file");
		exit(2);
	}

	(void) fclose(log);
	(void) unlink(PKGLOG);
	log = NULL;
	ndumps++;
	logcount = 0;
}

static void
freeentry(pkgentry_t *p)
{
	umem_free(p->line, p->len);
	umem_cache_free(ecache, p);
}

static void
swapentry(pkgentry_t *cur, pkgentry_t *new)
{
	if (cur->len == new->len &&
	    strcmp(cur->line + cur->pathlen,
	    new->line + new->pathlen) == 0) {
		suppressed++;
		freeentry(new);
		return;
	}

	/* Free old line */
	umem_free(cur->line, cur->len);

	/* Copy new value: pathlen is the same and avl is kept */
	cur->line = new->line;
	cur->len = new->len;
	cur->pkgoff = new->pkgoff;

	umem_cache_free(ecache, new);
}

static int
logentry(char type, pkgentry_t *p)
{
	int len;

	if (type == '-')
		len = fprintf(log, "-%.*s\n", p->pathlen, p->line);
	else
		len = fprintf(log, "%c%s\n", type, p->line);

	loglines++;
	if (len < 0) {
		logerrcnt++;
		return (-1);
	}
	logcount += len;
	return (0);
}

static int
logflush(void)
{
	int len;
	static int lastflush;

	if (log == NULL)
		return (0);

	if (lastflush == logcount)
		return (0);

	if (cind == 2) {
		(void) fprintf(log, "%s\n", ccmnt[0]);
		(void) fprintf(log, "%s\n", ccmnt[1]);
		cind = 0;
	}

	/*
	 * When using zfs, if the mark is there, then so is the rest before
	 * it.  But with ufs, we need to flush twice.
	 */
	if (flushbeforemark) {
		if (fflush(log) == EOF)
			logerrcnt++;
	}
	/* Anything before the last marker found in the log will be valid */
	len = fprintf(log, "%s", marker);
	if (len < 0)
		logerrcnt++;
	else
		logcount += len;

	if (fflush(log) == EOF)
		logerrcnt++;

	sync_needed = B_FALSE;

	if (logerrcnt > 0 || logcount > MAXLOGFILESIZE)
		pkgdump();

	if (logerrcnt > 0)
		return (-1);

	lastflush = logcount;

	return (0);
}

static int
avlcmp(const void *ca, const void *cb)
{
	const pkgentry_t *a = ca;
	const pkgentry_t *b = cb;
	int i = memcmp(a->line, b->line,
	    a->pathlen > b->pathlen ? b->pathlen : a->pathlen);

	if (i < 0)
		return (-1);
	else if (i > 0)
		return (1);
	else if (a->pathlen == b->pathlen)
		return (0);
	else if (a->pathlen > b->pathlen)
		return (1);
	else
		return (-1);
}

/*
 * Returns:
 *	0 - if we can get the lock
 *	-1 - we can't lock
 */

static int
establish_lock(char *lock)
{
	int fd = open(lock, O_RDWR|O_CREAT, 0644);
	int i;

	if (fd < 0)
		return (-1);

	for (i = 0; i < 5; i++) {
		if (lockf(fd, F_TLOCK, 0) == 0)
			return (0);
		(void) sleep(1);
	}

	(void) close(fd);
	return (-1);
}

static int
no_memory_abort(void)
{
	return (UMEM_CALLBACK_EXIT(99));
}

/*
 * Dump a part of the contents file in a pipe; grep for the "filter".
 * It doesn't matter if we return too much.
 */

static void *
thr_pkgfilter(void *v)
{
	pkgfilter_t *pf = v;
	pkgentry_t *p;
	int nums[2];
	FILE *cnts;

	cnts = fdopen(pf->cmd, "w");
	if (cnts == NULL)
		goto free;

	/*
	 * Remove wild card: don't care about extra matches; make sure
	 * we remove both the "*" and the "." in front of it.
	 */
	if (pf->len > 0) {
		char *p;

		for (p = pf->buf; *p; p++) {
			if (*p == '*') {
				*p = 0;
				if (p > pf->buf && p[-1] == '.')
					p[-1] = 0;
				break;
			}
		}
	}

	/* Disable modifications while the filter is running */
	(void) mutex_lock(&mtx);
	write_locked++;
	(void) mutex_unlock(&mtx);
	/*
	 * The protocol for the contents file for the clients:
	 * <int:len><int:pathlen><line + 0>
	 */

	for (p = avl_first(list); p != NULL; p = AVL_NEXT(list, p)) {
		if (pf->len > 0 && strstr(p->line, pf->buf) == NULL)
			continue;

		nums[0] = p->len;
		nums[1] = p->pathlen;
		if (fwrite(nums, sizeof (int), 2, cnts) != 2)
			break;
		if (fwrite(p->line, 1, p->len, cnts) != p->len)
			break;
	}

	(void) mutex_lock(&mtx);
	lastcall = gethrtime();
	write_locked--;
	(void) cond_broadcast(&cv);
	(void) mutex_unlock(&mtx);
	(void) fclose(cnts);

free:
	umem_free(pf, sizeof (pkgfilter_t) + pf->len);
	return (NULL);
}

static hrtime_t
time_since_(hrtime_t last)
{
	return (gethrtime() - last);
}

static void
my_cond_reltimedwait(hrtime_t delta, int sec)
{
	hrtime_t wait = sec * LLNANOSEC - delta;
	timestruc_t waitfor;

	waitfor.tv_nsec = wait % LLNANOSEC;
	waitfor.tv_sec = wait / LLNANOSEC;
	(void) cond_reltimedwait(&cv, &mtx, &waitfor);
}

static int
pkgfilter(pkgfilter_t *pf, door_desc_t *dp)
{

	int p[2];
	thread_t tid;
	pkgfilter_t *cpf;

	if (pipe(p) != 0)
		return (-1);

	cpf = umem_alloc(sizeof (pkgfilter_t) + pf->len, UMEM_NOFAIL);

	(void) memcpy(cpf, pf, sizeof (pkgfilter_t) + pf->len);

	/* Copy the file descriptor in the command field */
	cpf->cmd = p[1];

	if (thr_create(NULL, 0, thr_pkgfilter, cpf, THR_DETACHED,
	    &tid) != 0) {
		(void) close(p[0]);
		(void) close(p[1]);
		umem_free(cpf, sizeof (pkgfilter_t) + pf->len);
		return (-1);
	}
	(void) memset(dp, 0, sizeof (*dp));
	dp->d_attributes = DOOR_DESCRIPTOR | DOOR_RELEASE;
	dp->d_data.d_desc.d_descriptor = p[0];

	return (0);
}

static int
pkgaddlines(pkgfilter_t *pf)
{
	char *map = pf->buf;
	int len = pf->len;
	int off;
	pkgentry_t *ent, *look;
	avl_index_t where;
	char *q, *p;
	char c;
	int r = 0;

	if (log == NULL) {
		log = fopen(PKGLOG, "w");
		if (log == NULL)
			return (-1);
	}

	for (off = 0; off < len; off += q - p) {
		p = map + off;
		q = memchr(p, '\n', len - off);

		if (q == NULL)
			break;

		q++;

		if (p[0] == '#' || p[0] == '\n') {
			handle_comments(p, q - p);
			continue;
		}

		if (*p == '-')
			ent = parse_line(p + 1, q - (p + 1) - 1, B_FALSE);
		else
			ent = parse_line(p, q - p - 1, B_TRUE);

		if (ent == NULL) {
			r++;
			continue;
		}

		look = avl_find(list, ent, &where);
		if (look != NULL) {
			c = *p == '-' ? '-' : '=';
			if (c == '=') {
				swapentry(look, ent);
				ent = look;
			} else {
				avl_remove(list, look);
				freeentry(look);
			}
		} else if (*p == '-') {
			/* Remove something which isn't there: no-op */
			freeentry(ent);
			continue;
		} else {
			avl_insert(list, ent, where);
			c = '+';
		}

		sync_needed = B_TRUE;
		r += logentry(c, ent);
		if (c == '-')
			freeentry(ent);
	}

	return (r);
}

static void
finish(void)
{
	if (verbose) {
		syslog(LOG_DEBUG,
		    "finished: calls %d, pkgdumps %d, loglines %d "
		    "(suppressed %d)\n",
		    ncalls, ndumps, loglines, suppressed);
	}
	(void) fdetach(door);
	if (read_only)
		(void) unlink(door);
}

/*
 * Tell the wait thread to wake up and quit.
 */
/* ARGSUSED */
static void
signal_handler(int sig)
{
	if (read_only)
		exit(0);
	want_to_quit = 1;
	(void) cond_broadcast(&cv);
}
