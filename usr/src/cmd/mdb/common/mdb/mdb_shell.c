/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Shell Escape I/O Backend
 *
 * The MDB parser implements two forms of shell escapes: (1) traditional adb(1)
 * style shell escapes of the form "!command", which simply allows the user to
 * invoke a command (or shell pipeline) as if they had executed sh -c command
 * and then return to the debugger, and (2) shell pipes of the form "dcmds !
 * command", in which the output of one or more MDB dcmds is sent as standard
 * input to a shell command (or shell pipeline).  Form (1) can be handled
 * entirely from the parser by calling mdb_shell_exec (below); it simply
 * forks the shell, executes the desired command, and waits for completion.
 * Form (2) is slightly more complicated: we construct a UNIX pipe, fork
 * the shell, and then built an fdio object out of the write end of the pipe.
 * We then layer a shellio object (implemented below) and iob on top, and
 * set mdb.m_out to point to this new iob.  The shellio is simply a pass-thru
 * to the fdio, except that its io_close routine performs a waitpid for the
 * forked child process.
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>

#include <mdb/mdb_shell.h>
#include <mdb/mdb_lex.h>
#include <mdb/mdb_err.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb_string.h>
#include <mdb/mdb_frame.h>
#include <mdb/mdb_io_impl.h>
#include <mdb/mdb.h>

#define	E_BADEXEC	127	/* Exit status for failed exec */

/*
 * We must manually walk the open file descriptors and set FD_CLOEXEC, because
 * we need to be able to print an error if execlp() fails.  If mdb.m_err has
 * been altered, then using closefrom() could close our output file descriptor,
 * preventing us from displaying an error message.  Using FD_CLOEXEC ensures
 * that the file descriptors are only closed if execlp() succeeds.
 */
/*ARGSUSED*/
static int
closefd_walk(void *unused, int fd)
{
	if (fd > 2)
		(void) fcntl(fd, F_SETFD, FD_CLOEXEC);
	return (0);
}

void
mdb_shell_exec(char *cmd)
{
	int status;
	pid_t pid;

	if (access(mdb.m_shell, X_OK) == -1)
		yyperror("cannot access %s", mdb.m_shell);

	if ((pid = vfork()) == -1)
		yyperror("failed to fork");

	if (pid == 0) {
		(void) fdwalk(closefd_walk, NULL);
		(void) execlp(mdb.m_shell, strbasename(mdb.m_shell),
		    "-c", cmd, NULL);

		warn("failed to exec %s", mdb.m_shell);
		_exit(E_BADEXEC);
	}

	do {
		mdb_dprintf(MDB_DBG_SHELL, "waiting for PID %d\n", (int)pid);
	} while (waitpid(pid, &status, 0) == -1 && errno == EINTR);

	mdb_dprintf(MDB_DBG_SHELL, "waitpid %d -> 0x%x\n", (int)pid, status);
	strfree(cmd);
}

/*
 * This use of the io_unlink entry point is a little strange: we have stacked
 * the shellio on top of the fdio, but before the shellio's close routine can
 * wait for the child process, we need to close the UNIX pipe file descriptor
 * in order to generate an EOF to terminate the child.  Since each io is
 * unlinked from its iob before being popped by mdb_iob_destroy, we use the
 * io_unlink entry point to release the underlying fdio (forcing its io_close
 * routine to be called) and remove it from the iob's i/o stack out of order.
 */

/*ARGSUSED*/
static void
shellio_unlink(mdb_io_t *io, mdb_iob_t *iob)
{
	mdb_io_t *fdio = io->io_next;

	ASSERT(iob->iob_iop == io);
	ASSERT(fdio != NULL);

	io->io_next = fdio->io_next;
	fdio->io_next = NULL;
	mdb_io_rele(fdio);
}

static void
shellio_close(mdb_io_t *io)
{
	pid_t pid = (pid_t)(intptr_t)io->io_data;
	int status;

	do {
		mdb_dprintf(MDB_DBG_SHELL, "waiting for PID %d\n", (int)pid);
	} while (waitpid(pid, &status, 0) == -1 && errno == EINTR);

	mdb_dprintf(MDB_DBG_SHELL, "waitpid %d -> 0x%x\n", (int)pid, status);
}

static const mdb_io_ops_t shellio_ops = {
	.io_read = no_io_read,
	.io_write = no_io_write,
	.io_seek = no_io_seek,
	.io_ctl = no_io_ctl,
	.io_close = shellio_close,
	.io_name = no_io_name,
	.io_link = no_io_link,
	.io_unlink = shellio_unlink,
	.io_setattr = no_io_setattr,
	.io_suspend = no_io_suspend,
	.io_resume = no_io_resume
};

void
mdb_shell_pipe(char *cmd)
{
	uint_t iflag = mdb_iob_getflags(mdb.m_out) & MDB_IOB_INDENT;
	mdb_iob_t *iob;
	mdb_io_t *io;
	int pfds[2];
	pid_t pid;

	if (access(mdb.m_shell, X_OK) == -1)
		yyperror("cannot access %s", mdb.m_shell);

	if (pipe(pfds) == -1)
		yyperror("failed to open pipe");

	iob = mdb_iob_create(mdb_fdio_create(pfds[1]), MDB_IOB_WRONLY | iflag);
	mdb_iob_clrflags(iob, MDB_IOB_AUTOWRAP | MDB_IOB_INDENT);
	mdb_iob_resize(iob, BUFSIZ, BUFSIZ);

	if ((pid = vfork()) == -1) {
		(void) close(pfds[0]);
		(void) close(pfds[1]);
		mdb_iob_destroy(iob);
		yyperror("failed to fork");
	}

	if (pid == 0) {
		(void) close(pfds[1]);
		(void) close(STDIN_FILENO);
		(void) dup2(pfds[0], STDIN_FILENO);

		(void) fdwalk(closefd_walk, NULL);
		(void) execlp(mdb.m_shell, strbasename(mdb.m_shell),
		    "-c", cmd, NULL);

		warn("failed to exec %s", mdb.m_shell);
		_exit(E_BADEXEC);
	}

	(void) close(pfds[0]);
	strfree(cmd);

	io = mdb_alloc(sizeof (mdb_io_t), UM_SLEEP);

	io->io_ops = &shellio_ops;
	io->io_data = (void *)(intptr_t)pid;
	io->io_next = NULL;
	io->io_refcnt = 0;

	mdb_iob_stack_push(&mdb.m_frame->f_ostk, mdb.m_out, yylineno);
	mdb_iob_push_io(iob, io);
	mdb.m_out = iob;
}
