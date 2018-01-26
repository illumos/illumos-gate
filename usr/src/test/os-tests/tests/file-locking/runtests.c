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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * Validate various fcntl(2) and flock(3C) operations.
 */

#include "util.h"
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>


#define	LOCKFILE_FMT	"/tmp/.lockfile-%s-%ld"
#define	LOCKDIR_FMT	"/tmp/.lockdir-%s-%ld"

typedef struct lockinfo {
	char *lf_name;
	char *lf_path;
	int lf_fd;
} lockinfo_t;


static	void	assert_write_locked_by(lockinfo_t *, pid_t);
static	void	assert_read_locked_by(lockinfo_t *, pid_t);
static	void	assert_unlocked(lockinfo_t *);
static	void	assert_all_unlocked(void);

static	int	flock_copyfil(lockinfo_t *, lockinfo_t *);
static	int	flock_mkfil(lockinfo_t *);
static	int	flock_mkdir(lockinfo_t *);
static	void	flock_rminfo(lockinfo_t *);

static	void	flock_fcntl(lockinfo_t *lf, int cmd, struct flock *fl);
static	void	flock_run(lock_style_t, boolean_t, lockinfo_t *,
		    pid_t *, int[]);
static	int	flock_wait(pid_t pid);
static	void	flock_cleanup_child(pid_t, int []);

static	void	flock_test_invalid(lockinfo_t *, int, short, short,
		    off_t, off_t);
static	void	flock_test_invalid64(lockinfo_t *, int, short, short,
		    off_t, off_t);
static	void	flock_test_exclusive(lock_style_t, lock_style_t,
		    lockinfo_t *, lockinfo_t *, boolean_t);
static	void	flock_test_shared(lock_style_t, lock_style_t, lockinfo_t *,
		    lockinfo_t *, boolean_t);
static	void	flock_test_upgrade_downgrade(void);

static char *acqprog = NULL;

static lockinfo_t flock_fileA = { "a", NULL, -1 };
static lockinfo_t flock_fileB = { "b", NULL, -1 };
static lockinfo_t flock_dirA = { "a", NULL, -1 };
static lockinfo_t flock_dirB = { "b", NULL, -1 };


static short cmds[8] = {
	F_SETLK, F_SETLKW, F_GETLK,
	F_OFD_SETLK, F_OFD_SETLKW, F_OFD_GETLK,
	F_FLOCK, F_FLOCKW
};

static short cmds64[3] = {
	F_OFD_SETLK64, F_OFD_SETLKW64, F_OFD_GETLK64
};


static void
flock_kill(pid_t pid)
{
	while (kill(pid, SIGKILL) == -1) {
		if (errno == EINTR)
			continue;

		err(EXIT_FAILURE, "kill failed");
	}
}


static void
flock_fcntl(lockinfo_t *lf, int cmd, struct flock *fl)
{
	if (fcntl(lf->lf_fd, cmd, fl) == -1) {
		err(EXIT_FAILURE, "fcntl failed");
	}
}


static void
assert_write_locked_by(lockinfo_t *lf, pid_t pid)
{
	struct flock fl;

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_WRLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_WRLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_WRLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_WRLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);
}


static void
assert_read_locked_by(lockinfo_t *lf, pid_t pid)
{
	struct flock fl;

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_RDLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_RDLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, pid, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);
}

static void
assert_unlocked(lockinfo_t *lf)
{
	struct flock fl;

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);

	flock_reinit(&fl, F_WRLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);

	flock_reinit(&fl, F_RDLCK);
	flock_fcntl(lf, F_OFD_GETLK, &fl);
	VERIFY3_IMPL(fl.l_type, ==, F_UNLCK, short);
	VERIFY3_IMPL(fl.l_sysid, ==, 0, int);
	VERIFY3_IMPL(fl.l_pid, ==, 0, pid_t);
}


static void
assert_all_unlocked(void)
{
	assert_unlocked(&flock_fileA);
	assert_unlocked(&flock_fileB);
	assert_unlocked(&flock_dirA);
	assert_unlocked(&flock_dirB);
}


static int
flock_copyfil(lockinfo_t *src, lockinfo_t *dst)
{
	dst->lf_name = NULL;
	dst->lf_path = NULL;
	if ((dst->lf_fd = open(src->lf_path, O_RDWR)) == -1) {
		warn("Failed to open %s", src->lf_path);
		return (-1);
	}

	return (0);
}


static int
flock_mkfil(lockinfo_t *lf)
{
	if (asprintf(&lf->lf_path, LOCKFILE_FMT, lf->lf_name, getpid()) < 0) {
		warnx("Failed to generate lockfile name");
		return (-1);
	}

	if ((lf->lf_fd = open(lf->lf_path, O_RDWR|O_CREAT, 0600)) == -1)  {
		warn("Failed to open %s", lf->lf_path);
		return (-1);
	}

	return (0);
}


static int
flock_mkdir(lockinfo_t *lf)
{
	if (asprintf(&lf->lf_path, LOCKDIR_FMT, lf->lf_name, getpid()) < 0) {
		warnx("Failed to generate lockfile name");
		return (-1);
	}

	if (mkdir(lf->lf_path, 0700) == -1)  {
		warn("Failed to make %s", lf->lf_path);
		return (-1);
	}

	if ((lf->lf_fd = open(lf->lf_path, O_RDONLY)) == -1)  {
		warn("Failed to open %s", lf->lf_path);
		return (-1);
	}

	return (0);
}


static void
flock_rminfo(lockinfo_t *lf)
{
	if (lf->lf_fd != -1) {
		(void) close(lf->lf_fd);
	}
	if (lf->lf_path != NULL) {
		(void) unlink(lf->lf_path);
		free(lf->lf_path);
	}
}


static void
flock_run(lock_style_t style, boolean_t is_exclusive, lockinfo_t *lf,
    pid_t *pid, int fds[])
{
	char *stylestr = flock_stylestr(style);
	char *modestr = is_exclusive ? "exclusive" : "shared";
	char *argv[5] = { acqprog, stylestr, modestr, lf->lf_path, NULL };
	int ret = pipe(fds);
	if (ret == -1) {
		err(EXIT_FAILURE, "pipe failed");
	}

	*pid = fork();
	if (*pid == (pid_t)-1) {
		err(EXIT_FAILURE, "fork failed");
	} else if (*pid == (pid_t)0) {
		/* Set up pipe for communicating with child */
		ret = dup2(fds[1], 0);
		if (ret == -1) {
			err(EXIT_FAILURE, "dup2 failed");
		}
		ret = dup2(fds[1], 1);
		if (ret == -1) {
			err(EXIT_FAILURE, "dup2 failed");
		}
		closefrom(3);

		(void) execv(acqprog, argv);
		err(EXIT_FAILURE, "Failed to execute %s", acqprog);
	}
}


static int
flock_wait(pid_t pid)
{
	int childstat = 0;

	while (waitpid(pid, &childstat, 0) == -1) {
		if (errno == EINTR)
			continue;

		err(EXIT_FAILURE, "Failed to wait on child");
	}

	if (WIFEXITED(childstat)) {
		return (WEXITSTATUS(childstat));
	} else if (WIFSIGNALED(childstat)) {
		return (1);
	} else {
		abort();
		return (1);
	}
}


static void
flock_cleanup_child(pid_t pid, int fds[])
{
	(void) flock_wait(pid);
	(void) close(fds[0]);
	(void) close(fds[1]);
}


static void
flock_test_upgrade_downgrade(void)
{
	lockinfo_t afd1, afd2, afd3;
	pid_t pid;
	int fds[2];

	VERIFY3S(flock_copyfil(&flock_fileA, &afd1), ==, 0);
	VERIFY3S(flock_copyfil(&flock_fileA, &afd2), ==, 0);
	VERIFY3S(flock_copyfil(&flock_fileA, &afd3), ==, 0);

	flock_log("Acquiring shared locks 1, 2 and 3...");
	VERIFY3S(flock(afd1.lf_fd, LOCK_SH), ==, 0);
	VERIFY3S(flock(afd2.lf_fd, LOCK_SH), ==, 0);
	VERIFY3S(flock(afd3.lf_fd, LOCK_SH), ==, 0);
	assert_read_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Upgrading lock 3 should fail w/ EWOULDBLOCK...");
	VERIFY3S(flock(afd3.lf_fd, LOCK_EX|LOCK_NB), ==, -1);
	VERIFY3U(errno, ==, EWOULDBLOCK);
	assert_read_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Upgrading 3 should succeed after releasing locks 1 & 2...");
	VERIFY3S(flock(afd1.lf_fd, LOCK_UN), ==, 0);
	VERIFY3S(flock(afd2.lf_fd, LOCK_UN), ==, 0);
	VERIFY3S(flock(afd3.lf_fd, LOCK_EX), ==, 0);
	assert_write_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");


	flock_log("Starting up child, then downgrading lock 3 to shared...");
	flock_run(LSTYLE_FLOCK, B_FALSE, &flock_fileA, &pid, fds);
	VERIFY3_IMPL(flock_nodata(fds[0]), ==, B_TRUE, boolean_t);
	VERIFY3S(flock(afd3.lf_fd, LOCK_SH), ==, 0);
	flock_block(fds[0]);
	assert_read_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Releasing child and upgrading...");
	flock_alert(fds[0]);
	flock_cleanup_child(pid, fds);
	assert_read_locked_by(&flock_fileA, -1);
	VERIFY3S(flock(afd3.lf_fd, LOCK_EX), ==, 0);
	assert_write_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Releasing lock 3...");
	VERIFY3S(flock(afd3.lf_fd, LOCK_UN), ==, 0);
	flock_rminfo(&afd1);
	flock_rminfo(&afd2);
	flock_rminfo(&afd3);
	assert_all_unlocked();
	flock_log(" ok\n");
}


static void
flock_test_invalid(lockinfo_t *lf, int cmd, short l_type, short l_whence,
    off_t l_start, off_t l_len)
{
	struct flock fl = {
		.l_type = l_type,
		.l_whence = l_whence,
		.l_start = l_start,
		.l_len = l_len
	};

	flock_log("fcntl(fd, %s, { %hd, %hd, %ld, %ld, ... })...",
	    flock_cmdname(cmd), l_type, l_whence, l_start, l_len);
	VERIFY3S(fcntl(lf->lf_fd, cmd, &fl), ==, -1);
	VERIFY3U(errno, ==, EINVAL);
	flock_log(" ok\n");
}

static void
flock_test_invalid64(lockinfo_t *lf, int cmd, short l_type, short l_whence,
    off_t l_start, off_t l_len)
{
	struct flock64 fl = {
		.l_type = l_type,
		.l_whence = l_whence,
		.l_start = l_start,
		.l_len = l_len
	};

	flock_log("fcntl(fd, %s, { %hd, %hd, %ld, %ld, ... })...",
	    flock_cmdname(cmd), l_type, l_whence, l_start, l_len);
	VERIFY3S(fcntl(lf->lf_fd, cmd, &fl), ==, -1);
	VERIFY3U(errno, ==, EINVAL);
	flock_log(" ok\n");
}

static void
flock_test_exclusive(lock_style_t styleA, lock_style_t styleB,
    lockinfo_t *lock1, lockinfo_t *lock2, boolean_t kill_firstborn)
{
	pid_t pidA, pidB;
	int fdsA[2], fdsB[2];

	flock_log("Running %s + %s tests (%s)...",
	    flock_stylename(styleA), flock_stylename(styleB),
	    kill_firstborn ? "kill child" : "child exits");

	/* Create child, and wait for it to acquire the lock */
	flock_run(styleA, B_TRUE, lock1, &pidA, fdsA);
	flock_block(fdsA[0]);

	/* Create second child, which shouldn't acquire & signal */
	flock_run(styleB, B_TRUE, lock1, &pidB, fdsB);
	VERIFY3_IMPL(flock_nodata(fdsB[0]), ==, B_TRUE, boolean_t);

	/* lock1 is blocked for reading and writing */
	assert_write_locked_by(lock1, styleA == LSTYLE_POSIX ? pidA : -1);
	assert_unlocked(lock2);

	/* Tell pidA to exit */
	if (kill_firstborn) {
		flock_kill(pidA);
	} else {
		flock_alert(fdsA[0]);
	}
	flock_cleanup_child(pidA, fdsA);

	/* Wait for pidB to signal us */
	flock_block(fdsB[0]);

	/* lock1 is blocked for reading and writing */
	assert_write_locked_by(lock1, styleB == LSTYLE_POSIX ? pidB : -1);
	assert_unlocked(lock2);

	/* Tell pidB to exit */
	flock_alert(fdsB[0]);

	flock_cleanup_child(pidB, fdsB);

	/*
	 * Tests after child has released lock
	 */
	assert_all_unlocked();

	flock_log(" ok\n");
}


static void
flock_test_shared(lock_style_t styleA, lock_style_t styleB,
    lockinfo_t *lock1, lockinfo_t *lock2, boolean_t kill_firstborn)
{
	pid_t pidA, pidB;
	int fdsA[2], fdsB[2];

	flock_log("Running %s + %s tests (%s)...",
	    flock_stylename(styleA), flock_stylename(styleB),
	    kill_firstborn ? "kill child" : "child exits");

	/* Create children, and wait for it to acquire the lock */
	flock_run(styleB, B_FALSE, lock1, &pidB, fdsB);
	flock_block(fdsB[0]);
	flock_run(styleA, B_FALSE, lock1, &pidA, fdsA);
	flock_block(fdsA[0]);

	/* testfileA is only blocked for writing */
	assert_read_locked_by(lock1, styleA == LSTYLE_POSIX ? pidA : -1);
	assert_unlocked(lock2);

	/* Tell pidA to exit */
	if (kill_firstborn) {
		flock_kill(pidA);
	} else {
		flock_alert(fdsA[0]);
	}
	flock_cleanup_child(pidA, fdsA);

	/* testfileA is still blocked for writing by pidB */
	assert_read_locked_by(lock1, styleB == LSTYLE_POSIX ? pidB : -1);
	assert_unlocked(lock2);

	/* Tell pidB to exit */
	flock_alert(fdsB[0]);
	flock_cleanup_child(pidB, fdsB);

	assert_all_unlocked();

	flock_log(" ok\n");
}


static void
flock_test_ofd_sameproc(void)
{
	lockinfo_t afd1, afd2, afd3;

	VERIFY3S(flock_copyfil(&flock_fileA, &afd1), ==, 0);
	VERIFY3S(flock_copyfil(&flock_fileA, &afd2), ==, 0);
	VERIFY3S(flock_copyfil(&flock_fileA, &afd3), ==, 0);

	flock_log("Acquiring first two shared locks...");
	VERIFY3S(flock(afd1.lf_fd, LOCK_SH), ==, 0);
	VERIFY3S(flock(afd2.lf_fd, LOCK_SH), ==, 0);
	assert_read_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Acquiring an exclusive lock should fail w/ EWOULDBLOCK...");
	VERIFY3S(flock(afd3.lf_fd, LOCK_EX|LOCK_NB), ==, -1);
	VERIFY3U(errno, ==, EWOULDBLOCK);
	flock_log(" ok\n");

	flock_log("Releasing to acquire an exclusive lock...");
	VERIFY3S(flock(afd1.lf_fd, LOCK_UN), ==, 0);
	VERIFY3S(flock(afd2.lf_fd, LOCK_UN), ==, 0);
	flock_log(" ok\n");

	flock_log("Acquiring an exclusive lock...");
	VERIFY3S(flock(afd3.lf_fd, LOCK_EX), ==, 0);
	assert_write_locked_by(&flock_fileA, -1);
	flock_log(" ok\n");

	flock_log("Acquiring a shared lock should fail w/ EWOULDBLOCK...");
	VERIFY3S(flock(afd1.lf_fd, LOCK_EX|LOCK_NB), ==, -1);
	VERIFY3U(errno, ==, EWOULDBLOCK);
	VERIFY3S(flock(afd2.lf_fd, LOCK_EX|LOCK_NB), ==, -1);
	VERIFY3U(errno, ==, EWOULDBLOCK);
	flock_log(" ok\n");

	flock_log("Releasing exclusive lock...");
	VERIFY3S(flock(afd3.lf_fd, LOCK_UN), ==, 0);
	assert_all_unlocked();
	flock_log(" ok\n");

	flock_rminfo(&afd1);
	flock_rminfo(&afd2);
	flock_rminfo(&afd3);
}


static void
flock_runtests(void)
{
	lock_style_t first, second;
	int i;

	flock_log("# Exclusive lock tests\n");
	for (first = (lock_style_t)0; first < LSTYLE_LAST; first++) {
		for (second = (lock_style_t)0; second < LSTYLE_LAST; second++) {
			flock_test_exclusive(first, second,
			    &flock_fileA, &flock_fileB, B_TRUE);
			flock_test_exclusive(first, second,
			    &flock_fileA, &flock_fileB, B_FALSE);
		}
	}

	flock_log("# Shared lock tests\n");
	for (first = (lock_style_t)0; first < LSTYLE_LAST; first++) {
		for (second = (lock_style_t)0; second < LSTYLE_LAST; second++) {
			flock_test_shared(first, second,
			    &flock_fileA, &flock_fileB, B_TRUE);
			flock_test_shared(first, second,
			    &flock_fileA, &flock_fileB, B_FALSE);
		}
	}

	flock_log("# flock(3C) directory lock tests\n");
	flock_test_exclusive(LSTYLE_FLOCK, LSTYLE_FLOCK,
	    &flock_dirA, &flock_dirB, B_TRUE);
	flock_test_exclusive(LSTYLE_FLOCK, LSTYLE_FLOCK,
	    &flock_dirA, &flock_dirB, B_FALSE);
	flock_test_shared(LSTYLE_FLOCK, LSTYLE_FLOCK,
	    &flock_dirA, &flock_dirB, B_TRUE);
	flock_test_shared(LSTYLE_FLOCK, LSTYLE_FLOCK,
	    &flock_dirA, &flock_dirB, B_FALSE);


	flock_log("# Invalid fcntl(2) parameters tests\n");
	for (i = 0; i < sizeof (cmds) / sizeof (short); i++) {
		flock_test_invalid(&flock_fileA, cmds[i], 200, 0, 0, 0);
		flock_test_invalid(&flock_fileA, cmds[i], -1, 0, 0, 0);
	}
	for (i = 3; i < sizeof (cmds) / sizeof (short); i++) {
		flock_test_invalid(&flock_fileA, cmds[i], F_WRLCK, 1, 0, 0);
		flock_test_invalid(&flock_fileA, cmds[i], F_WRLCK, 0, 1, 0);
		flock_test_invalid(&flock_fileA, cmds[i], F_WRLCK, 0, 0, 1);
	}
	for (i = 0; i < sizeof (cmds64) / sizeof (short); i++) {
		flock_test_invalid64(&flock_fileA, cmds64[i], F_WRLCK, 1, 0, 0);
		flock_test_invalid64(&flock_fileA, cmds64[i], F_WRLCK, 0, 1, 0);
		flock_test_invalid64(&flock_fileA, cmds64[i], F_WRLCK, 0, 0, 1);
	}

	flock_log("# Testing that multiple OFD locks work in a process\n");
	flock_test_ofd_sameproc();

	flock_log("# Testing flock(3C) upgrade/downgrade tests\n");
	flock_test_upgrade_downgrade();
}


int
main(int argc, char *argv[])
{
	char *basestr, *suffix, *dirstr, *dirpath;
	pid_t testrunner;
	int exval;

	LOG = B_TRUE;

	if (argc < 1) {
		errx(EXIT_FAILURE, "Can't find program name!");
	}

	dirstr = strdup(argv[0]);
	dirpath = dirname(dirstr);
	basestr = strdup(argv[0]);
	suffix = basename(basestr);

	while (*suffix != '.' && *suffix != '\0') {
		suffix += 1;
	}

	if (asprintf(&acqprog, "%s/acquire-lock%s", dirpath, suffix) < 0) {
		errx(EXIT_FAILURE,
		    "Can't generate lock acquisition program name!");
	}

	if (access(acqprog, X_OK) != 0) {
		err(EXIT_FAILURE,
		    "Can't run lock acquisition program %s", acqprog);
	}

	/* Create several lockfiles for testing */
	if (flock_mkfil(&flock_fileA) != 0 ||
	    flock_mkfil(&flock_fileB) != 0 ||
	    flock_mkdir(&flock_dirA) != 0 ||
	    flock_mkdir(&flock_dirB) != 0) {
		exval = 1;
		goto cleanup;
	}

	/*
	 * We run the tests in a child process so that when tests fail
	 * we can still clean up our temporary files.
	 */
	testrunner = fork();
	if (testrunner == (pid_t)-1) {
		err(EXIT_FAILURE, "Unable to fork to run tests");
	} else if (testrunner == (pid_t)0) {
		flock_runtests();
		return (0);
	}

	exval = flock_wait(testrunner);

cleanup:
	free(basestr);
	free(dirstr);
	flock_rminfo(&flock_fileA);
	flock_rminfo(&flock_fileB);
	flock_rminfo(&flock_dirA);
	flock_rminfo(&flock_dirB);
	return (exval);
}
