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

/*
 * The BrandZ Linux thunking library.
 *
 * The interfaces defined in this file form the client side of a bridge
 * to allow native Solaris process to access Linux services.  Currently
 * the Linux services that is made accessible by these interfaces here
 * are:
 *	- Linux host <-> address naming services
 *	- Linux service <-> port naming services
 *	- Linux syslog
 *
 * Currently, to use this library it must be LD_PRELOADed into the
 * application that needs to access Linux services.  Once loaded
 * Linux services are accessed by the client application in two
 * different ways:
 *
 * - Direct library calls:
 *	lxt_gethostbyname_r
 *	lxt_gethostbyaddr_r
 *	lxt_getservbyname_r
 *	lxt_getservbyport_r
 *	lxt_debug
 *
 *   These library functions are used by the BrandZ lx name services
 *   translation library (lx_nametoaddr.so) to handle libnsl.so name
 *   service requests.
 *
 * - Intercepted library calls:
 *	openlog(3c)
 *	syslog(3c)
 *	vsyslog(3c)
 *	closelog(3c)
 *
 *   Via the LD_PRELOAD mechanism this library interposes itself on
 *   these interfaces and when the application calls these interfaces
 *   (either directly or indirectly via any libraries the program may
 *   be linked against) this library intercepts the request and passes
 *   it onto a Linux process to handle the request.
 *
 * Once this library receives a request that needs to be serviced by a
 * Linux process, it packs up that request and attempts to send it
 * to a doors server.  The door server interfaces are defined in
 * lx_thunk_server.h.  If the doors server is not running or not
 * responding, this library will attempt to spawn a new doors server
 * by forking and executing the following shell script (which runs as
 * a native /bin/sh Linux process):
 *	/native/usr/lib/brand/lx/lx_thunk
 *
 * Notes:
 * - This library also intercepts the following system calls:
 *	close(2) - We intercept close(2) to prevent the caller from
 *		accidentally closing any of the file descriptors we
 *		need to do our work.
 *
 *	setppriv(2) - We intercept setppriv(2) to prevent a process
 *		from dropping any of the privileges we'll need to create
 *		a new lx_thunk server process and to deal with service
 *		requests.
 *
 * - To facilitate the running of native Solaris programs and libraries
 *   when this library is preloaded into an application it will chroot()
 *   into /native.  This way the Solaris application and libraries can
 *   access files via their expected paths and we can avoid having to
 *   either do path mapping or modifying all libraries to make them
 *   aware of "/native" so that they can pre-pend it to all their
 *   filesystem operations.
 *
 * - This library can only be used with processes that are initially
 *   run by root in a zone.  The reason is that we use the chroot()
 *   system call and this requires the PRIV_PROC_CHROOT privilege,
 *   which non-root users don't have.
 */

#include <alloca.h>
#include <assert.h>
#include <dlfcn.h>
#include <door.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netdir.h>
#include <priv.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <synch.h>
#include <sys/brand.h>
#include <sys/fcntl.h>
#include <sys/lx_thunk_server.h>
#include <sys/lx_thunk.h>
#include <sys/mman.h>
#include <sys/priv_impl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <thread.h>
#include <unistd.h>
#include <sys/varargs.h>

#define	LXT_DOOR_DIR		"/tmp"
#define	LXT_DOOR_PREFIX		"lxt"
#define	LXT_MSG_MAXLEN		(128 + MAXPATHLEN)

#pragma init(init)

typedef uintptr_t (*fp1_t)(uintptr_t);
typedef uintptr_t (*fp3_t)(uintptr_t, uintptr_t, uintptr_t);

static char	*lxt_debug_path = NULL;		/* debug output file path */
static char	lxt_debug_path_buf[MAXPATHLEN];
static int	root_fd;
static int	debug_fd = -1;

void lxt_debug(const char *msg, ...);

void
init(void)
{
	if (getenv("LX_DEBUG") != NULL) {

		/* check if there's a debug log file specified */
		lxt_debug_path = getenv("LX_DEBUG_FILE");
		if (lxt_debug_path == NULL) {
			/* send all debugging output to /dev/tty */
			lxt_debug_path = "/dev/tty";
		}

		(void) strlcpy(lxt_debug_path_buf, lxt_debug_path,
		    sizeof (lxt_debug_path_buf));
		lxt_debug_path = lxt_debug_path_buf;

		/*
		 * Open the debugging output file.  We need to open it
		 * and hold it open because we're going to call chroot()
		 * in just a second, so we won't be able to open it later.
		 */
		if ((debug_fd = open(lxt_debug_path,
		    O_WRONLY|O_APPEND|O_CREAT|O_NDELAY|O_NOCTTY,
		    0666)) != -1) {
			(void) fchmod(debug_fd, 0666);
		}
	}
	lxt_debug("lxt_init: executing native process");

	/* Get a fd that points to the root directory */
	if ((root_fd = open("/", O_RDONLY)) < 0) {
		lxt_debug("lxt_init(): "
		    "failed to open root directory: %s", strerror(errno));
		exit(-1);
	}

	/*
	 * Now, so that we can avoid having to do path mapping,
	 * just chdir() and chroot() into /native.
	 */
	if (chdir("/native") != 0) {
		lxt_debug("lxt_init(): "
		    "failed to chdir to /native: %s", strerror(errno));
		exit(-1);
	}
	if (chroot("/native") != 0) {
		lxt_debug("lxt_init(): "
		    "failed to chroot to /native: %s", strerror(errno));
		exit(-1);
	}
}

/*
 * Linux Thunking Interfaces - Client Side
 */
static mutex_t	lxt_door_lock = DEFAULTMUTEX;
static int	lxt_door_fd = -1;

static void
lxt_server_exec(int fifo_wr, int fifo_rd)
{
	extern const char	**environ;
	char 			*nullist[] = { NULL };

	lxt_debug("lxt_server_exec: server starting");

	/*
	 * First we need to dup our fifos to the file descriptors
	 * the brand library is expecting them to be at.
	 */

	/* Check if the write fifo needs to be moved aside */
	if ((fifo_wr == LXT_SERVER_FIFO_RD_FD) &&
	    ((fifo_wr = dup(fifo_wr)) < 0))
		return;

	/* Check if the read fifo needs to be moved aside */
	if ((fifo_rd == LXT_SERVER_FIFO_WR_FD) &&
	    ((fifo_rd = dup(fifo_rd)) < 0))
		return;

	if ((fifo_wr != LXT_SERVER_FIFO_WR_FD) &&
	    (dup2(fifo_wr, LXT_SERVER_FIFO_WR_FD) < 0))
		return;
	if ((fifo_rd != LXT_SERVER_FIFO_RD_FD) &&
	    (dup2(fifo_rd, LXT_SERVER_FIFO_RD_FD) < 0))
		return;

	/*
	 * We're about to execute a native Linux process.
	 * Since we've been loaded into a Solaris process with
	 * LD_PRELOAD and LD_LIBRARY_PATH we should clear these
	 * variables from the environment before calling exec.
	 */
	(void) unsetenv("LD_PRELOAD");
	(void) unsetenv("LD_LIBRARY_PATH");

	/*
	 * Now we need to exec the thunk server process.  This is a
	 * branded Linux process that will act as a doors server and
	 * service our requests to perform native Linux operations.
	 * Since we're currently running as a native Solaris process
	 * to start up the server we'll use the brand system call to
	 * the kernel that the target of the exec will be a branded
	 * process.
	 */
	lxt_debug("lxt_server_exec: execing as Linux process");
	(void) syscall(SYS_brand, B_EXEC_BRAND,
	    LXT_SERVER_BINARY, nullist, environ);
}


static void *
lxt_door_waitpid(void *arg)
{
	pid_t	child_pid = (pid_t)(uintptr_t)arg;
	int	stat;

	(void) waitpid(child_pid, &stat, 0);
	return (NULL);
}

static char *
lxt_door_mkfifo()
{
	char	*path;

	for (;;) {
		path = tempnam(LXT_DOOR_DIR, LXT_DOOR_PREFIX);
		if (path == NULL)
			return (NULL);
		if (mkfifo(path, S_IWUSR | S_IRUSR) != 0) {
			if (errno != EEXIST) {
				free(path);
				return (NULL);
			}
			/* This file path exists, pick a new name. */
			free(path);
			continue;
		}
		/* We successfully created the fifo */
		break;
	}
	return (path);
}

static void
lxt_door_init()
{
	char		*fifo1_path = NULL, *fifo2_path;
	char		fifo1_path_native[MAXPATHLEN];
	int		fifo1_rd = -1, fifo1_wr = -1;
	int		fifo2_rd = -1, fifo2_wr = -1;
	int		junk;
	pid_t		child_pid;
	thread_t	tid;

	lxt_debug("lxt_door_init: preparint to start server");

	/* Create two new fifos. */
	if (((fifo1_path = lxt_door_mkfifo()) == NULL) ||
	    ((fifo2_path = lxt_door_mkfifo()) == NULL))
		goto fail;

	(void) snprintf(fifo1_path_native, sizeof (fifo1_path_native),
	    "/native%s", fifo1_path);

	/*
	 * Open both fifos for reading and writing.  We have to open
	 * the read side of the fifo first (because the write side will
	 * fail to open if there is no reader) and we have to use the
	 * O_NONBLOCK flag (because the read open with hang without it).
	 */
	if (((fifo1_rd = open(fifo1_path, O_RDONLY | O_NONBLOCK)) < 0) ||
	    ((fifo1_wr = open(fifo1_path, O_WRONLY)) < 0) ||
	    ((fifo2_rd = open(fifo2_path, O_RDONLY | O_NONBLOCK)) < 0) ||
	    ((fifo2_wr = open(fifo2_path, O_WRONLY)) < 0))
		goto fail;

	/*
	 * Now we have to close the read side of fifo1 and fifo2 and re-open
	 * them without the O_NONBLOCK flag.  This is because we're using
	 * the fifos for synchronization and when we actually try to read
	 * from them we want to block.
	 */
	(void) close(fifo1_rd);
	if ((fifo1_rd = open(fifo1_path, O_RDONLY)) < 0)
		goto fail;
	(void) close(fifo2_rd);
	if ((fifo2_rd = open(fifo2_path, O_RDONLY)) < 0)
		goto fail;

	/*
	 * Once fifo2 is opened no one will ever need to open it again
	 * so delete it now.
	 */
	(void) unlink(fifo2_path);
	free(fifo2_path);
	fifo2_path = NULL;

	/* Attempt to fork and start the door server */
	lxt_debug("lxt_door_init: starting server");
	switch (child_pid = fork1()) {
	case -1:
		/* fork1() failed. */
		goto fail;
	case 0:
		/* Child process - new door server. */
		(void) close(fifo1_rd);
		(void) close(fifo2_wr);

		/* Need to chroot back to the real root directory */
		if (fchroot(root_fd) != 0) {
			lxt_debug("lxt_server_exec: "
			    "failed fchroot(\"/\"): %s", strerror(errno));
			exit(-1);
		}
		(void) close(root_fd);

		/* Start the server */
		lxt_server_exec(fifo1_wr, fifo2_rd);
		lxt_debug("lxt_server_exec: server init failed");
		exit(-1);
		/*NOTREACHED*/
	}
	/* Parent process - door client. */

	/*
	 * fifo2 is used to send the door path to the child.
	 * (We can't simply pass it via the address space since the
	 * child will need to exec.)  We'll write the name of the door
	 * file to fifo2 before we close the read end of the fifo2 so
	 * that if the child has exited for some reason we won't get
	 * a SIGPIPE.  Note that we're reusing the name of fifo1 as
	 * the door path.  Also note that we've pre-pended /native
	 * to the fifo/door path.  The reason is that we're chroot'ed
	 * to /native, but when the thunking server executes it will
	 * be chroot'ed back to the real root directory.
	 */
	(void) write(fifo2_wr,
	    fifo1_path_native, strlen(fifo1_path_native) + 1);
	(void) close(fifo2_wr);
	(void) close(fifo2_rd);

	/*
	 * Start up a thread that will perfom a waitpid() on the child
	 * door server process.  We do this because if the calling
	 * application that is using our interfaces is forking it's own
	 * children and using wait(), then it won't expect to see our
	 * children.  We take advantage of the fact that if there are
	 * wait() and a waitpid() calls in progress at the same time
	 * when a child exists,  preference will be given to any
	 * waitpid() calls that are explicity waiting for that child.
	 * There is of course a window of time where the child could
	 * exit after we've forked it but before we've called waitpid()
	 * where another wait() in this process could collect the result.
	 * There's nothing we can really do to prevent this short of
	 * stopping all the other threads in this process.
	 */
	(void) thr_create(NULL, 0,
	    lxt_door_waitpid, (void *)(uintptr_t)child_pid, THR_DAEMON, &tid);

	/*
	 * fifo1 is used for the child process to signal us that the
	 * door server is ready to take requests.
	 */
	(void) close(fifo1_wr);
	(void) read(fifo1_rd, &junk, 1);
	(void) close(fifo1_rd);

	/* If there was a door that was open, close it now. */

	if (lxt_door_fd >= 0)
		(void) close(lxt_door_fd);
	/*
	 * The server should be started up by now and fattach()ed the door
	 * server to the fifo/door path.  so if we re-open that path now we
	 * should get a fd to the door server.
	 */
	lxt_door_fd = open(fifo1_path, O_RDWR);

	lxt_debug("lxt_door_init: new server door = %d", lxt_door_fd);

	/* We don't need the fifo/door anymore so delete it. */
	(void) unlink(fifo1_path);
	free(fifo1_path);
	return;

fail:
	if (fifo1_path != NULL)
		(void) unlink(fifo1_path);
	if (fifo2_path != NULL)
		(void) unlink(fifo2_path);
	if (fifo1_rd != -1)
		(void) close(fifo1_rd);
	if (fifo1_wr != -1)
		(void) close(fifo1_wr);
	if (fifo2_rd != -1)
		(void) close(fifo2_rd);
	if (fifo2_wr != -1)
		(void) close(fifo2_wr);
}

static int
lxt_door_call(door_arg_t *door_arg, int lock_held)
{
	int fd;

	if (!lock_held)
		(void) mutex_lock(&lxt_door_lock);

	/* Get a copy of lxt_door_fd */
	fd = lxt_door_fd;

	if (!lock_held)
		(void) mutex_unlock(&lxt_door_lock);

	if (fd == -1) {
		lxt_debug("lxt_door_call: no door available");
		return (-1);
	}

	if (door_call(fd, door_arg) != 0) {
		lxt_debug("lxt_door_call: call failed");
		return (-1);
	}
	if (door_arg->rbuf == NULL) {
		lxt_debug("lxt_door_call: call returned NULL");
		return (-1);
	}
	return (0);
}

static int
lxt_door_request(door_arg_t *door_arg)
{
	door_arg_t		door_ping;
	lxt_server_arg_t	ping_request, *ping_result;
	int			rv, ping_success = 0;

	/* First just try the door call. */
	lxt_debug("lxt_door_request: calling server");
	if (lxt_door_call(door_arg, 0) == 0)
		return (0);

	/* Prepare a door server ping request. */
	bzero(&door_ping, sizeof (door_ping));
	bzero(&ping_request, sizeof (ping_request));
	door_ping.data_ptr	= (char *)&ping_request;
	door_ping.data_size	= sizeof (ping_request);
	ping_request.lxt_sa_op = LXT_SERVER_OP_PING;

	(void) mutex_lock(&lxt_door_lock);

	/* Ping the doors server. */
	lxt_debug("lxt_door_request: pinging server");
	if (lxt_door_call(&door_ping, 1) == 0) {
		/*LINTED*/
		ping_result = (lxt_server_arg_t *)door_ping.rbuf;
		ping_success = ping_result->lxt_sa_success;
		(void) munmap(door_ping.rbuf, door_ping.rsize);
	}

	if (!ping_success) {
		/* The server is not responding so start up a new one. */
		lxt_door_init();
	}
	(void) mutex_unlock(&lxt_door_lock);

	/* Retry the original request */
	lxt_debug("lxt_door_request: calling server, retry");
	if ((rv = lxt_door_call(door_arg, 0)) == 0)
		return (0);
	return (rv);
}

static struct hostent *
lxt_gethost(int op, const char *token, int token_len, int type,
    struct hostent *result, char *buf, int buf_len, int *h_errnop)
{
	door_arg_t		door_arg;
	lxt_gethost_arg_t	*data;
	lxt_server_arg_t	*request;
	int			request_size, errno_tmp, i;

	lxt_debug("lxt_gethost: request caught");

	request_size = sizeof (*request) + sizeof (*data) +
	    token_len + buf_len - 1;
	if ((request = calloc(1, request_size)) == NULL) {
		lxt_debug("lxt_gethost: calloc() failed");
		*h_errnop = TRY_AGAIN;
		return (NULL);
	}
	/*LINTED*/
	data = (lxt_gethost_arg_t *)&request->lxt_sa_data[0];

	/* Initialize the server request. */
	request->lxt_sa_op = op;
	data->lxt_gh_type = type;
	data->lxt_gh_token_len = token_len;
	data->lxt_gh_buf_len = buf_len;
	data->lxt_gh_storage_len = token_len + token_len;
	bcopy(token, &data->lxt_gh_storage[0], token_len);

	/* Initialize door_call() arguments. */
	bzero(&door_arg, sizeof (door_arg));
	door_arg.data_ptr	= (char *)request;
	door_arg.data_size	= request_size;

	if (lxt_door_request(&door_arg) != 0) {
		lxt_debug("lxt_gethost: door_call() failed");
		/* Don't know what caused the error so clear errno. */
		errno = 0;
		*h_errnop = ND_SYSTEM;
		free(request);
		return (NULL);
	}

	free(request);

	if (door_arg.rbuf == NULL) {
		lxt_debug("lxt_gethost: door_call() returned NULL");
		/* Don't know what caused the error so clear errno. */
		errno = 0;
		*h_errnop = ND_SYSTEM;
		return (NULL);
	}

	/*LINTED*/
	request = (lxt_server_arg_t *)door_arg.rbuf;
	/*LINTED*/
	data = (lxt_gethost_arg_t *)&request->lxt_sa_data[0];

	/* Check if the remote procedure call failed */
	if (!request->lxt_sa_success) {
		lxt_debug("lxt_gethost: remote function call failed");
		errno_tmp = request->lxt_sa_errno;
		*h_errnop = data->lxt_gh_h_errno;
		(void) munmap(door_arg.rbuf, door_arg.rsize);
		errno = errno_tmp;
		return (NULL);
	}

	/* Copy out the results and output buffer. */
	bcopy(&data->lxt_gh_result, result, sizeof (*result));
	bcopy(&data->lxt_gh_storage[token_len], buf, buf_len);
	(void) munmap(door_arg.rbuf, door_arg.rsize);

	/* Now go through the results and convert all offsets to pointers */
	result->h_name = LXT_OFFSET_TO_PTR(result->h_name, buf);
	result->h_aliases = LXT_OFFSET_TO_PTR(result->h_aliases, buf);
	result->h_addr_list = LXT_OFFSET_TO_PTR(result->h_addr_list, buf);
	for (i = 0; result->h_aliases[i] != NULL; i++) {
		result->h_aliases[i] =
		    LXT_OFFSET_TO_PTR(result->h_aliases[i], buf);
	}
	for (i = 0; result->h_addr_list[i] != NULL; i++) {
		result->h_addr_list[i] =
		    LXT_OFFSET_TO_PTR(result->h_addr_list[i], buf);
	}

	return (result);
}

static struct servent *
lxt_getserv(int op, const char *token, const int token_len, const char *proto,
    struct servent *result, char *buf, int buf_len)
{
	door_arg_t		door_arg;
	lxt_getserv_arg_t	*data;
	lxt_server_arg_t	*request;
	int			request_size, errno_tmp, i;

	lxt_debug("lxt_getserv: request caught");

	request_size = sizeof (*request) + sizeof (*data) +
	    token_len + buf_len - 1;
	if ((request = calloc(1, request_size)) == NULL) {
		lxt_debug("lxt_getserv: calloc() failed");
		return (NULL);
	}
	/*LINTED*/
	data = (lxt_getserv_arg_t *)&request->lxt_sa_data[0];

	/* Initialize the server request. */
	request->lxt_sa_op = op;
	data->lxt_gs_token_len = token_len;
	data->lxt_gs_buf_len = buf_len;
	data->lxt_gs_storage_len = token_len + token_len;
	bcopy(token, &data->lxt_gs_storage[0], token_len);

	bzero(data->lxt_gs_proto, sizeof (data->lxt_gs_proto));
	if (proto != NULL)
		(void) strncpy(data->lxt_gs_proto, proto,
		    sizeof (data->lxt_gs_proto));

	/* Initialize door_call() arguments. */
	bzero(&door_arg, sizeof (door_arg));
	door_arg.data_ptr	= (char *)request;
	door_arg.data_size	= request_size;

	/* Call the doors server */
	if (lxt_door_request(&door_arg) != 0) {
		lxt_debug("lxt_getserv: door_call() failed");
		/* Don't know what caused the error so clear errno */
		errno = 0;
		free(request);
		return (NULL);
	}
	free(request);

	if (door_arg.rbuf == NULL) {
		lxt_debug("lxt_getserv: door_call() returned NULL");
		/* Don't know what caused the error so clear errno */
		errno = 0;
		return (NULL);
	}
	/*LINTED*/
	request = (lxt_server_arg_t *)door_arg.rbuf;
	/*LINTED*/
	data = (lxt_getserv_arg_t *)&request->lxt_sa_data[0];

	/* Check if the remote procedure call failed */
	if (!request->lxt_sa_success) {
		lxt_debug("lxt_getserv: remote function call failed");
		errno_tmp = request->lxt_sa_errno;
		(void) munmap(door_arg.rbuf, door_arg.rsize);
		errno = errno_tmp;
		return (NULL);
	}

	/* Copy out the results and output buffer. */
	bcopy(&data->lxt_gs_result, result, sizeof (*result));
	bcopy(&data->lxt_gs_storage[token_len], buf, buf_len);
	(void) munmap(door_arg.rbuf, door_arg.rsize);

	/*
	 * Now go through the results and convert all offsets to pointers.
	 * See the comments in lxt_server_getserv() for why we need
	 * to subtract 1 from each offset.
	 */
	result->s_name = LXT_OFFSET_TO_PTR(result->s_name, buf);
	result->s_proto = LXT_OFFSET_TO_PTR(result->s_proto, buf);
	result->s_aliases = LXT_OFFSET_TO_PTR(result->s_aliases, buf);
	for (i = 0; result->s_aliases[i] != NULL; i++) {
		result->s_aliases[i] =
		    LXT_OFFSET_TO_PTR(result->s_aliases[i], buf);
	}

	return (result);
}

static void
lxt_openlog(const char *ident, int logopt, int facility)
{
	door_arg_t		door_arg;
	lxt_openlog_arg_t	*data;
	lxt_server_arg_t	*request;
	int			request_size;

	request_size = sizeof (*request) + sizeof (*data);
	if ((request = calloc(1, request_size)) == NULL) {
		lxt_debug("lxt_openlog: calloc() failed");
		return;
	}
	/*LINTED*/
	data = (lxt_openlog_arg_t *)&request->lxt_sa_data[0];

	/* Initialize the server request. */
	request->lxt_sa_op = LXT_SERVER_OP_OPENLOG;
	data->lxt_ol_facility = facility;
	data->lxt_ol_logopt = logopt;
	(void) strlcpy(data->lxt_ol_ident, ident, sizeof (data->lxt_ol_ident));

	/* Initialize door_call() arguments. */
	bzero(&door_arg, sizeof (door_arg));
	door_arg.data_ptr	= (char *)request;
	door_arg.data_size	= request_size;

	/* Call the doors server */
	if (lxt_door_request(&door_arg) != 0) {
		lxt_debug("lxt_openlog: door_call() failed");
		free(request);
		return;
	}
	free(request);

	if (door_arg.rbuf == NULL) {
		lxt_debug("lxt_openlog: door_call() returned NULL");
		return;
	}

	/*LINTED*/
	request = (lxt_server_arg_t *)door_arg.rbuf;

	/* Check if the remote procedure call failed */
	if (!request->lxt_sa_success) {
		lxt_debug("lxt_openlog: remote function call failed");
	}
	(void) munmap(door_arg.rbuf, door_arg.rsize);
}

static void
lxt_vsyslog(int priority, const char *message, va_list va)
{
	door_arg_t		door_arg;
	lxt_syslog_arg_t	*data;
	lxt_server_arg_t	*request;
	psinfo_t		p;
	char			procfile[PRFNSZ], *buf, *estr;
	int			buf_len, buf_i, estr_len, request_size, procfd;
	int			i, key, err_count = 0, tok_count = 0;
	int			errno_backup = errno;

	/*
	 * Here we're going to use vsnprintf() to expand the message
	 * string passed in before we hand it off to a Linux process.
	 * Before we can call vsnprintf() we'll need to do modify the
	 * string to deal with certain special tokens.
	 *
	 * syslog() supports a special '%m' format token that expands to
	 * the error message string associated with the current value
	 * of errno.  Unfortunatly if we pass this token to vsnprintf()
	 * it will choke so we need to expand that token manually here.
	 *
	 * We also need to expand any "%%" characters into "%%%%".
	 * The reason is that we'll be calling vsnprintf() which will
	 * translate "%%%%" back to "%%", which is safe to pass to the
	 * Linux version if syslog.  If we didn't do this then vsnprintf()
	 * would translate "%%" to "%" and then the Linux syslog would
	 * attempt to intrepret "%" and whatever character follows it
	 * as a printf format style token.
	 */
	for (key = i = 0; message[i] != '\0'; i++) {
		if (!key && message[i] == '%') {
			key = 1;
			continue;
		}
		if (key && message[i] == '%')
			tok_count++;
		if (key && message[i] == 'm')
			err_count++;
		key = 0;
	}

	/* We found some tokens that we need to expand. */
	if (err_count || tok_count) {
		estr = strerror(errno_backup);
		estr_len = strlen(estr);
		assert(estr_len >= 2);

		/* Allocate a buffer to hold the expanded string. */
		buf_len = i + 1 +
		    (tok_count * 2) + (err_count * (estr_len - 2));
		if ((buf = calloc(1, buf_len)) == NULL) {
			lxt_debug("lxt_vsyslog: calloc() failed");
			return;
		}

		/* Finally, expand %% and %m. */
		for (key = buf_i = i = 0; message[i] != '\0'; i++) {
			assert(buf_i < buf_len);
			if (!key && message[i] == '%') {
				buf[buf_i++] = '%';
				key = 1;
				continue;
			}
			if (key && message[i] == 'm') {
				(void) bcopy(estr, &buf[buf_i - 1], estr_len);
				buf_i += estr_len - 1;
			} else if (key && message[i] == '%') {
				(void) bcopy("%%%%", &buf[buf_i - 1], 4);
				buf_i += 4 - 1;
			} else {
				buf[buf_i++] = message[i];
			}
			key = 0;
		}
		assert(buf[buf_i] == '\0');
		assert(buf_i == (buf_len - 1));

		/* Use the expanded buffer as our format string. */
		message = buf;
	}

	/* Allocate the request we're going to send to the server */
	request_size = sizeof (*request) + sizeof (*data);
	if ((request = calloc(1, request_size)) == NULL) {
		lxt_debug("lxt_vsyslog: calloc() failed");
		return;
	}

	/*LINTED*/
	data = (lxt_syslog_arg_t *)&request->lxt_sa_data[0];

	/* Initialize the server request. */
	request->lxt_sa_op = LXT_SERVER_OP_SYSLOG;
	data->lxt_sl_priority = priority;
	data->lxt_sl_pid = getpid();
	(void) vsnprintf(data->lxt_sl_message, sizeof (data->lxt_sl_message),
	    message, va);

	/* If we did token expansion then free the intermediate buffer. */
	if (err_count || tok_count)
		free(buf);

	/* Add the current program name into the request */
	(void) sprintf(procfile, "/proc/%u/psinfo", (int)getpid());
	/* (void) sprintf(procfile, "/native/proc/%u/psinfo", (int)getpid()); */
	if ((procfd = open(procfile, O_RDONLY)) >= 0) {
		if (read(procfd, &p, sizeof (psinfo_t)) >= 0) {
			(void) strncpy(data->lxt_sl_progname, p.pr_fname,
			    sizeof (data->lxt_sl_progname));
		}
		(void) close(procfd);
	}

	/* Initialize door_call() arguments. */
	bzero(&door_arg, sizeof (door_arg));
	door_arg.data_ptr	= (char *)request;
	door_arg.data_size	= request_size;

	/* Call the doors server */
	if (lxt_door_request(&door_arg) != 0) {
		lxt_debug("lxt_vsyslog: door_call() failed");
		free(request);
		return;
	}
	free(request);

	if (door_arg.rbuf == NULL) {
		lxt_debug("lxt_vsyslog: door_call() returned NULL");
		return;
	}

	/*LINTED*/
	request = (lxt_server_arg_t *)door_arg.rbuf;

	/* Check if the remote procedure call failed */
	if (!request->lxt_sa_success) {
		lxt_debug("lxt_vsyslog: remote function call failed");
	}
	(void) munmap(door_arg.rbuf, door_arg.rsize);
}

static void
lxt_closelog(void)
{
	door_arg_t		door_arg;
	lxt_server_arg_t	*request;
	int			request_size;

	request_size = sizeof (*request);
	if ((request = calloc(1, request_size)) == NULL) {
		lxt_debug("lxt_closelog: calloc() failed");
		return;
	}

	/* Initialize the server request. */
	request->lxt_sa_op = LXT_SERVER_OP_CLOSELOG;

	/* Initialize door_call() arguments. */
	bzero(&door_arg, sizeof (door_arg));
	door_arg.data_ptr	= (char *)request;
	door_arg.data_size	= request_size;

	/* Call the doors server */
	if (lxt_door_request(&door_arg) != 0) {
		lxt_debug("lxt_closelog: door_call() failed");
		free(request);
		return;
	}
	free(request);

	if (door_arg.rbuf == NULL) {
		lxt_debug("lxt_closelog: door_call() returned NULL");
		return;
	}

	/*LINTED*/
	request = (lxt_server_arg_t *)door_arg.rbuf;

	/* Check if the remote procedure call failed */
	if (!request->lxt_sa_success) {
		lxt_debug("lxt_closelog: remote function call failed");
	}
	(void) munmap(door_arg.rbuf, door_arg.rsize);
}

static void
lxt_pset_keep(priv_op_t op, priv_ptype_t type, priv_set_t *pset,
    const char *priv)
{
	if (priv_ismember(pset, priv) == B_TRUE) {
		if (op == PRIV_OFF) {
			(void) priv_delset(pset, priv);
			lxt_debug("lxt_pset_keep: "
			    "preventing drop of \"%s\" from \"%s\" set",
			    priv, type);
		}
	} else {
		if (op == PRIV_SET) {
			(void) priv_addset(pset, priv);
			lxt_debug("lxt_pset_keep: "
			    "preventing drop of \"%s\" from \"%s\" set",
			    priv, type);
		}
	}
}

/*
 * Public interfaces - used by lx_nametoaddr
 */
void
lxt_vdebug(const char *msg, va_list va)
{
	char		buf[LXT_MSG_MAXLEN + 1];
	int		rv, n;

	if (debug_fd == -1)
		return;

	/* Prefix the message with pid/tid. */
	if ((n = snprintf(buf, sizeof (buf), "%u/%u: ",
	    getpid(), thr_self())) == -1)
		return;

	/* Format the message. */
	if (vsnprintf(&buf[n], sizeof (buf) - n, msg, va) == -1)
		return;

	/* Add a carrige return if there isn't one already. */
	if ((buf[strlen(buf) - 1] != '\n') &&
	    (strlcat(buf, "\n", sizeof (buf)) >= sizeof (buf)))
		return;

	/* We retry in case of EINTR */
	do {
		rv = write(debug_fd, buf, strlen(buf));
	} while ((rv == -1) && (errno == EINTR));
}

void
lxt_debug(const char *msg, ...)
{
	va_list		va;
	int		errno_backup;

	if (debug_fd == -1)
		return;

	errno_backup = errno;
	va_start(va, msg);
	lxt_vdebug(msg, va);
	va_end(va);
	errno = errno_backup;
}

struct hostent *
lxt_gethostbyaddr_r(const char *addr, int addr_len, int type,
    struct hostent *result, char *buf, int buf_len, int *h_errnop)
{
	lxt_debug("lxt_gethostbyaddr_r: request recieved");
	return (lxt_gethost(LXT_SERVER_OP_ADDR2HOST,
	    addr, addr_len, type, result, buf, buf_len, h_errnop));
}

struct hostent *
lxt_gethostbyname_r(const char *name,
    struct hostent *result, char *buf, int buf_len, int *h_errnop)
{
	lxt_debug("lxt_gethostbyname_r: request recieved");
	return (lxt_gethost(LXT_SERVER_OP_NAME2HOST,
	    name, strlen(name) + 1, 0, result, buf, buf_len, h_errnop));
}

struct servent *
lxt_getservbyport_r(int port, const char *proto,
    struct servent *result, char *buf, int buf_len)
{
	lxt_debug("lxt_getservbyport_r: request recieved");
	return (lxt_getserv(LXT_SERVER_OP_PORT2SERV,
	    (const char *)&port, sizeof (int), proto, result, buf, buf_len));
}

struct servent *
lxt_getservbyname_r(const char *name, const char *proto,
    struct servent *result, char *buf, int buf_len)
{
	lxt_debug("lxt_getservbyname_r: request recieved");
	return (lxt_getserv(LXT_SERVER_OP_NAME2SERV,
	    name, strlen(name) + 1, proto, result, buf, buf_len));
}

/*
 * "Public" interfaces - used to override public existing interfaces
 */
#pragma weak _close = close
int
close(int fd)
{
	static fp1_t	fp = NULL;

	/*
	 * Don't let the process close our file descriptor that points
	 * back to the root directory.
	 */
	if (fd == root_fd)
		return (0);
	if (fd == debug_fd)
		return (0);

	if (fp == NULL)
		fp = (fp1_t)dlsym(RTLD_NEXT, "close");
	return (fp((uintptr_t)fd));
}

int
_setppriv(priv_op_t op, priv_ptype_t type, const priv_set_t *pset)
{
	static fp3_t	fp = NULL;
	priv_set_t	*pset_new;
	int		rv;

	lxt_debug("_setppriv: request caught");

	if (fp == NULL)
		fp = (fp3_t)dlsym(RTLD_NEXT, "_setppriv");

	while ((pset_new = priv_allocset()) == NULL)
		(void) sleep(1);

	priv_copyset(pset, pset_new);
	lxt_pset_keep(op, type, pset_new, PRIV_PROC_EXEC);
	lxt_pset_keep(op, type, pset_new, PRIV_PROC_FORK);
	lxt_pset_keep(op, type, pset_new, PRIV_PROC_CHROOT);
	lxt_pset_keep(op, type, pset_new, PRIV_FILE_DAC_READ);
	lxt_pset_keep(op, type, pset_new, PRIV_FILE_DAC_WRITE);
	lxt_pset_keep(op, type, pset_new, PRIV_FILE_DAC_SEARCH);

	rv = fp(op, (uintptr_t)type, (uintptr_t)pset_new);
	priv_freeset(pset_new);
	return (rv);
}

void
openlog(const char *ident, int logopt, int facility)
{
	lxt_debug("openlog: request caught");
	lxt_openlog(ident, logopt, facility);
}

void
syslog(int priority, const char *message, ...)
{
	va_list	va;

	lxt_debug("syslog: request caught");
	va_start(va, message);
	lxt_vsyslog(priority, message, va);
	va_end(va);
}

void
vsyslog(int priority, const char *message, va_list va)
{
	lxt_debug("vsyslog: request caught");
	lxt_vsyslog(priority, message, va);
}

void
closelog(void)
{
	lxt_debug("closelog: request caught");
	lxt_closelog();
}
