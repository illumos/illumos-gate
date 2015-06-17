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
 * Copyright 2015 Joyent, Inc.
 */

#include <stdlib.h>
#include <stdio.h>
#include <err.h>
#include <strings.h>
#include <unistd.h>
#include <wait.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <libcmdutils.h>

#include "run_command.h"
#include "pipe_stream.h"

typedef struct cmd {
	int cmd_pid;
	int cmd_wstatus;
	pipe_stream_t *cmd_pipe[2];
	custr_t *cmd_err;
	custr_t *cmd_out;
	run_command_line_cb *cmd_func;
	boolean_t cmd_cancel;
} cmd_t;

static int cb_data(const uint8_t *, size_t, void *, void *);
static void cb_eof(void *, void *);
static void cb_error(int, void *, void *);

void
post_error(cmd_t *cmd, const char *estr)
{
	if (cmd->cmd_cancel) {
		return;
	}
	cmd->cmd_cancel = B_TRUE;

	custr_reset(cmd->cmd_err);
	(void) custr_append(cmd->cmd_err, estr);
}

int
run_command(const char *path, char *const argv[], char *const envp[],
    char *errbuf, size_t errlen, run_command_line_cb *func, int *status)
{
	pipe_stream_loop_t *psl = NULL;
	int e = 0;
	cmd_t cmd;
	pid_t wpid;

	bzero(&cmd, sizeof (cmd));

	cmd.cmd_func = func;

	/*
	 * Allocate string buffers for stdout line buffering and error
	 * messages:
	 */
	if (custr_alloc_buf(&cmd.cmd_err, errbuf, errlen) != 0 ||
	    custr_alloc(&cmd.cmd_out) != 0) {
		e = errno;
		goto out;
	}

	/*
	 * Initialise pipe stream event loop:
	 */
	if (pipe_stream_loop_init(&psl, 256, cb_data, cb_eof, cb_error) != 0) {
		e = errno;
		post_error(&cmd, "could not init pipe stream loop");
		goto out;
	}

	/*
	 * Create pipe streams for stdout and stderr communication with
	 * child process:
	 */
	if (pipe_stream_init(psl, &cmd.cmd_pipe[0], &cmd,
	    (void *)STDOUT_FILENO) != 0 ||
	    pipe_stream_init(psl, &cmd.cmd_pipe[1], &cmd,
	    (void *)STDERR_FILENO) != 0) {
		e = errno;
		post_error(&cmd, "could not init pipe streams");
		goto out;
	}

	/*
	 * Fork a child process:
	 */
	if ((cmd.cmd_pid = fork()) == -1) {
		e = errno;
		post_error(&cmd, "could not fork");
		goto out;
	}

	if (cmd.cmd_pid == 0) {
		/*
		 * This is the child process.  Clean up file descriptors, and
		 * connect stdio to the pipes we allocated:
		 */
		VERIFY0(close(STDIN_FILENO));
		VERIFY0(pipe_stream_child_afterfork(cmd.cmd_pipe[0],
		    STDOUT_FILENO));
		VERIFY0(pipe_stream_child_afterfork(cmd.cmd_pipe[1],
		    STDERR_FILENO));
		closefrom(3);

		execve(path, argv, envp);
		err(127, "exec(%s) failed", path);
	}

	/*
	 * Back in the parent.  Close the remote end of the stdio pipes:
	 */
	pipe_stream_parent_afterfork(cmd.cmd_pipe[0]);
	pipe_stream_parent_afterfork(cmd.cmd_pipe[1]);

	/*
	 * Run the pipe event loop until all streams are completely
	 * consumed:
	 */
	while (pipe_stream_loop_should_run(psl)) {
		if (pipe_stream_loop_run(psl) != 0) {
			e = errno;
			post_error(&cmd, "pipe stream loop run failure");
			goto out;
		}
	}

	/*
	 * Collect exit status of child process:
	 */
	while ((wpid = waitpid(cmd.cmd_pid, &cmd.cmd_wstatus, 0)) !=
	    cmd.cmd_pid) {
		if (wpid == -1 && errno != EINTR) {
			e = errno;
			post_error(&cmd, "waitpid failure");
			goto out;
		}
	}

	/*
	 * If the child died on a signal, fail the whole operation:
	 */
	if (WIFSIGNALED(cmd.cmd_wstatus)) {
		e = ENXIO;
		post_error(&cmd, "child process died on signal");
		(void) custr_append_printf(cmd.cmd_err, " (pid %d signal %d)",
		    cmd.cmd_pid, WTERMSIG(cmd.cmd_wstatus));
		goto out;
	}

	/*
	 * If the child did not appear to exit, fail the whole operation:
	 */
	if (!WIFEXITED(cmd.cmd_wstatus)) {
		e = ENXIO;
		post_error(&cmd, "child process did not exit");
		(void) custr_append_printf(cmd.cmd_err, " (pid %d status %x)",
		    cmd.cmd_pid, cmd.cmd_wstatus);
		goto out;
	}

	/*
	 * Report exit status to the caller:
	 */
	*status = WEXITSTATUS(cmd.cmd_wstatus);
	e = 0;

out:
	VERIFY0(pipe_stream_loop_fini(psl));
	/*
	 * Note that freeing the static error custr_t does not touch the
	 * underlying storage; we use this property to return the error
	 * message (if one exists) to the caller.
	 */
	custr_free(cmd.cmd_err);
	custr_free(cmd.cmd_out);
	errno = e;
	return (e == 0 ? 0 : -1);
}

static int
cb_data(const uint8_t *buf, size_t sz, void *arg0, void *arg1)
{
	cmd_t *cmd = arg0;
	int fd = (int)arg1;
	unsigned int i;

	if (cmd->cmd_cancel) {
		return (-1);
	}

	switch (fd) {
	case STDOUT_FILENO:
		for (i = 0; i < sz; i++) {
			if (buf[i] == '\0' || buf[i] == '\r') {
				continue;
			}

			if (buf[i] == '\n') {
				cmd->cmd_func(custr_cstr(cmd->cmd_out));
				custr_reset(cmd->cmd_out);
				continue;
			}

			if (custr_appendc(cmd->cmd_out, buf[i]) != 0) {
				/*
				 * Failed to allocate memory; returning
				 * -1 here will abort the stream.
				 */
				post_error(cmd, "custr_appendc failure");
				return (-1);
			}
		}
		break;

	case STDERR_FILENO:
		/*
		 * Collect as much stderr output as will fit in our static
		 * buffer.
		 */
		for (i = 0; i < sz; i++) {
			if (buf[i] == '\0') {
				continue;
			}

			(void) custr_appendc(cmd->cmd_err, buf[i]);
		}
		break;

	default:
		abort();
	}

	return (0);
}

static void
cb_eof(void *arg0, void *arg1)
{
	cmd_t *cmd = arg0;
	int fd = (int)arg1;

	if (cmd->cmd_cancel) {
		return;
	}

	if (fd == STDOUT_FILENO && custr_len(cmd->cmd_out) > 0) {
		cmd->cmd_func(custr_cstr(cmd->cmd_out));
		custr_reset(cmd->cmd_out);
	}
}

static void
cb_error(int e, void *arg0, void *arg1)
{
	cmd_t *cmd = arg0;
	int fd = (int)arg1;

	if (cmd->cmd_cancel) {
		return;
	}

	post_error(cmd, "stream read failure");
	(void) custr_append_printf(cmd->cmd_err, " (pid %d fd %d): %s",
	    cmd->cmd_pid, fd, strerror(e));
}
