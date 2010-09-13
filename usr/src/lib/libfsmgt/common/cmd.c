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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <poll.h>
#include <sys/wait.h>
#include <errno.h>
#include <strings.h>
#include <sys/stropts.h>
#include "libfsmgt.h"

#define	MASKVAL (POLLIN | POLLPRI | POLLRDNORM | POLLRDBAND)
#define	STDOUT 1
#define	STDERR 2

/*
 * Public methods
 */

/*
 * Method: cmd_execute_command
 *
 * Description: Executes the given command and returns the output written to
 * stdout and stderr in two separate file descriptors to be read by the caller.
 * It is recommended that the caller use the cmd_retrieve_string method or
 * another polling method to read from the file descriptors especially in the
 * case that the command output is expected to be lengthy.
 *
 * Parameters:
 *	- char *cmd - The command to execute.
 *	- int *output_filedes - The file descriptor to which the stdout output
 *	is written.
 *	- int *err_filedes -  The file descriptor to which the stderr output
 *	is written.
 *
 * Returns:
 *	- int - This value will always be zero.  This was intended to be the
 *	the exit status of the executed command, but in the case of the
 *	execution of a command with a large amount of output (ex: ls of a large
 *	directory) we can't wait for the exec'd command to exit.  This is
 *	because of the way that file descriptors work.  When the child process,
 *	or the process executing the command, writes of 'x' amount of data to
 *	a file desciptor (fd), the fd reaches a threshold and will lock and wait
 *	for a reader to read before writing anymore data.  In this case, we
 *	don't have a reader since the caller reads from the file descriptors,
 *	not the parent process.
 *	The result is that the parent process cannot be allowed to wait for the
 *	child process to exit.  Hence, cannot get the exit status of the
 *	executed command.
 */
int
cmd_execute_command(char *cmd, int *output_filedes, int *err_filedes) {
	pid_t child_pid;
	int output[2];
	int error[2];
	int ret_val;

	if (pipe(output) == -1) {
		return (errno);
	}

	if (pipe(error) == -1) {
		return (errno);
	}

	if ((child_pid = fork()) == -1) {
		return (errno);
	}

	if (child_pid == 0) {
		/*
		 * We are in the child.
		 */

		/*
		 * Close the file descriptors we aren't using.
		 */
		close(output[0]);
		close(error[0]);

		/*
		 * Close stdout and dup to output[1]
		 */
		if (close(STDOUT) == -1) {
			exit(errno);
		}

		if (dup(output[1]) == -1) {
			exit(errno);
		}

		close(output[1]);

		/*
		 * Close stderr and dup to error[1]
		 */
		if (close(STDERR) == -1) {
			exit(errno);
		}

		if (dup(error[1]) == -1) {
			exit(errno);
		}

		close(error[1]);

		if (execl("/usr/bin/sh", "sh", "-c", cmd, (char *)0) == -1) {

			exit(errno);
		} else {
			exit(0);
		}
	}

	/*
	 * We are in the parent
	 */

	/*
	 * Close the file descriptors we aren't using.
	 */
	close(output[1]);
	close(error[1]);

	*output_filedes = output[0];
	*err_filedes = error[0];

	/*
	 * Do not wait for the child process to exit.  Just return.
	 */
	ret_val = 0;
	return (ret_val);

} /* cmd_execute_command */

/*
 * Method: cmd_execute_command_and_retrieve_string
 *
 * Description: Executes the given string and returns the output as it is
 * output as it is written to stdout and stderr in the return string.
 *
 * Parameters:
 *	- char *cmd - the command to execute.
 *	- int *errp - the error indicator.  This will be set to a non-zero
 *	upon error.
 *
 * Returns:
 *	char * - The output of the command to stderr and stdout.
 */
char *
cmd_execute_command_and_retrieve_string(char *cmd, int *errp) {
	pid_t child_pid;
	int output[2];
	int err;
	int status;
	char *ret_val;

	*errp = 0;
	if (pipe(output) == -1) {
		*errp = errno;
		return (NULL);
	}

	if ((child_pid = fork()) == -1) {
		*errp = errno;
		return (NULL);
	}

	if (child_pid == 0) {
		/*
		 * We are in the child.
		 */

		/*
		 * Close the unused file descriptor.
		 */
		close(output[0]);

		/*
		 * Close stdout and dup to output[1]
		 */
		if (close(STDOUT) == -1) {
			*errp = errno;
			exit(*errp);
		}

		if (dup(output[1]) == -1) {
			*errp = errno;
			exit(*errp);
		}

		/*
		 * Close stderr and dup to output[1]
		 */
		if (close(STDERR) == -1) {
			*errp = errno;
			exit(*errp);
		}

		if (dup(output[1]) == -1) {
			*errp = errno;
			exit(*errp);
		}

		close(output[1]);

		if (execl("/usr/bin/sh", "sh", "-c", cmd, (char *)0) == -1) {

			*errp = errno;
			exit(*errp);
		} else {
			exit(0);
		}
	}

	/*
	 * We are in the parent
	 */

	/*
	 * Close the file descriptors we are not using.
	 */
	close(output[1]);

	/*
	 * Wait for the child process to exit.
	 */
	while ((wait(&status) != child_pid)) {
		ret_val = cmd_retrieve_string(output[0], &err);
	}

	/*
	 * Evaluate the wait status and set the evaluated value to
	 * the value of errp.
	 */
	*errp = WEXITSTATUS(status);

	ret_val = cmd_retrieve_string(output[0], &err);

	/*
	 * Caller must free space allocated for ret_val with free()
	 */
	return (ret_val);
} /* cmd_execute_command_and_retrieve_string */

/*
 * Method: cmd_retrieve_string
 *
 * Description: Returns the data written to the file descriptor passed in.
 *
 * Parameters:
 *	- int filedes - The file descriptor to be read.
 *	- int *errp - The error indicator.  This will be set to a non-zero
 *	value upon error.
 *
 * Returns:
 *	- char * - The data read from the file descriptor.
 */
char *
cmd_retrieve_string(int filedes, int *errp) {
	int returned_value = 0;
	int buffer_size = 1024;
	int len;
	char *ret_val;
	char *buffer;
	boolean_t stop_loop = B_FALSE;
	struct pollfd pollfds[1];

	*errp = 0;
	/*
	 * Read from the file descriptor passed into the function.  This
	 * will read data written to the file descriptor on a FIFO basis.
	 * Care must be taken to make sure to get all data from the file
	 * descriptor.
	 */

	ret_val = (char *)calloc((size_t)1, (size_t)sizeof (char));
	ret_val[0] = '\0';


	/*
	 * Set up the pollfd structure with appropriate information.
	 */
	pollfds[0].fd = filedes;
	pollfds[0].events = MASKVAL;
	pollfds[0].revents = 0;

	while (stop_loop == B_FALSE) {
		char *tmp_string;

		switch (poll(pollfds, 1, INFTIM)) {
			case -1:

			case 0:
				/*
				 * Nothing to read yet so continue.
				 */
				continue;
			default:
				buffer = (char *)calloc(
					(size_t)(buffer_size + 1),
					(size_t)sizeof (char));

				if (buffer == NULL) {
					/*
					 * Out of memory
					 */
					*errp = errno;
					return (NULL);
				}

				/*
				 * Call read to read from the filedesc.
				 */
				returned_value = read(filedes, buffer,
					buffer_size);
				if (returned_value <= 0) {
					/*
					 * Either we errored or didn't read any
					 * bytes of data.
					 * returned_value == -1 represents an
					 * error.
					 * returned value == 0 represents 0
					 * bytes read.
					 */
					stop_loop = B_TRUE;
					continue;
				}

				len = strlen(buffer);

				/*
				 * Allocate space for the new string.
				 */
				tmp_string =
				(char *)calloc((size_t)(len+strlen(ret_val)+1),
						(size_t)sizeof (char));

				if (tmp_string == NULL) {
					/*
					 * Out of memory
					 */

					*errp = errno;
					return (NULL);
				}

				/*
				 * Concatenate the the new string in 'buffer'
				 * with whatever is in the 'ret_val' buffer.
				 */
				snprintf(tmp_string, (size_t)(len +
					strlen(ret_val) + 1), "%s%s",
					ret_val, buffer);

				(void) free(ret_val);
				ret_val = strdup(tmp_string);

				if (ret_val == NULL) {
					/*
					 * Out of memory
					 */
					*errp = errno;
					return (NULL);
				}
				(void) free(tmp_string);
				(void) free(buffer);

		} /* switch (poll(pollfds, 1, INFTIM)) */

	} /* while (stop_loop == B_FALSE) */

	return (ret_val);
} /* cmd_retrieve_string */
