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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <locale.h>

#include <unistd.h>
#include <termios.h>

#ifdef HAVE_SELECT
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#endif

#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>

#if HAVE_SYSV_PTY
#include <stropts.h>    /* System-V stream I/O */
char *ptsname(int fd);
int grantpt(int fd);
int unlockpt(int fd);
#endif

#include "libtecla.h"

/*
 * Pseudo-terminal devices are found in the following directory.
 */
#define PTY_DEV_DIR "/dev/"

/*
 * Pseudo-terminal controller device file names start with the following
 * prefix.
 */
#define PTY_CNTRL "pty"

/*
 * Pseudo-terminal subsidiary device file names start with the following
 * prefix.
 */
#define PTY_SUBSID "tty"

/*
 * Specify the maximum suffix length for the control and subsidiary device
 * names.
 */
#define PTY_MAX_SUFFIX 10

/*
 * Set the maximum length of the manager and subsidiary terminal device
 * filenames, including space for a terminating '\0'.
 */
#define PTY_MAX_NAME (sizeof(PTY_DEV_DIR)-1 + \
		      (sizeof(PTY_SUBSID) > sizeof(PTY_CNTRL) ? \
		       sizeof(PTY_SUBSID) : sizeof(PTY_CNTRL))-1 \
		      + PTY_MAX_SUFFIX + 1)
/*
 * Set the maximum length of an input line.
 */
#define PTY_MAX_LINE 4096

/*
 * Set the size of the buffer used for accumulating bytes written by the
 * user's terminal to its stdout.
 */
#define PTY_MAX_READ 1000

/*
 * Set the amount of memory used to record history.
 */
#define PTY_HIST_SIZE 10000

/*
 * Set the timeout delay used to check for quickly arriving
 * sequential output from the application.
 */
#define PTY_READ_TIMEOUT 100000    /* micro-seconds */

static int pty_open_manager(const char *prog, int *cntrl, char *subsid_name);
static int pty_open_subsid(const char *prog, char *subsid_name);
static int pty_child(const char *prog, int subsid, char *argv[]);
static int pty_parent(const char *prog, int cntrl);
static int pty_stop_parent(int waserr, int cntrl, GetLine *gl, char *rbuff);
static GL_FD_EVENT_FN(pty_read_from_program);
static int pty_write_to_fd(int fd, const char *string, int n);
static void pty_child_exited(int sig);
static int pty_manager_readable(int fd, long usec);

/*.......................................................................
 * Run a program with enhanced terminal editing facilities.
 *
 * Usage:
 *  enhance program [args...]
 */
int main(int argc, char *argv[])
{
  int cntrl = -1;  /* The fd of the pseudo-terminal controller device */
  int subsid = -1;  /* The fd of the pseudo-terminal subsidiary device */
  pid_t pid;       /* The return value of fork() */
  int status;      /* The return statuses of the parent and child functions */
  char subsid_name[PTY_MAX_NAME]; /* The filename of the subsidiary end of */
				 /*  the pseudo-terminal. */
  char *prog;      /* The name of the program (ie. argv[0]) */
/*
 * Check the arguments.
 */
  if(argc < 2) {
    fprintf(stderr, "Usage: %s <program> [arguments...]\n", argv[0]);
    return 1;
  };
/*
 * Get the name of the program.
 */
  prog = argv[0];
/*
 * If the user has the LC_CTYPE or LC_ALL environment variables set,
 * enable display of characters corresponding to the specified locale.
 */
  (void) setlocale(LC_CTYPE, "");
/*
 * If the program is taking its input from a pipe or a file, or
 * sending its output to something other than a terminal, run the
 * program without tecla.
 */
  if(!isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
    if(execvp(argv[1], argv + 1) < 0) {
      fprintf(stderr, "%s: Unable to execute %s (%s).\n", prog, argv[1],
	      strerror(errno));
      fflush(stderr);
      _exit(1);
    };
  };
/*
 * Open the manager side of a pseudo-terminal pair, and return
 * the corresponding file descriptor and the filename of the
 * subsidiary end of the pseudo-terminal.
 */
  if(pty_open_manager(prog, &cntrl, subsid_name))
    return 1;
/*
 * Set up a signal handler to watch for the child process exiting.
 */
  signal(SIGCHLD, pty_child_exited);
/*
 * The above signal handler sends the parent process a SIGINT signal.
 * This signal is caught by gl_get_line(), which resets the terminal
 * settings, and if the application signal handler for this signal
 * doesn't abort the process, gl_get_line() returns NULL with errno
 * set to EINTR. Arrange to ignore the signal, so that gl_get_line()
 * returns and we have a chance to cleanup.
 */
  signal(SIGINT, SIG_IGN);
/*
 * We will read user input in one process, and run the user's program
 * in a child process.
 */
  pid = fork();
  if(pid < 0) {
    fprintf(stderr, "%s: Unable to fork child process (%s).\n", prog,
	    strerror(errno));
    return 1;
  };
/*
 * Are we the parent?
 */
  if(pid!=0) {
    status = pty_parent(prog, cntrl);
    close(cntrl);
  } else {
    close(cntrl); /* The child doesn't use the subsidiary device */
    signal(SIGCHLD, pty_child_exited);
    if((subsid = pty_open_subsid(prog, subsid_name)) >= 0) {
      status = pty_child(prog, subsid, argv + 1);
      close(subsid);
    } else {
      status = 1;
    };
  };
  return status;
}

/*.......................................................................
 * Open the manager side of a pseudo-terminal pair, and return
 * the corresponding file descriptor and the filename of the
 * subsidiary end of the pseudo-terminal.
 *
 * Input/Output:
 *  prog  const char *  The name of this program.
 *  cntrl        int *  The file descriptor of the pseudo-terminal
 *                      controller device will be assigned tp *cntrl.
 *  subsid_name  char *  The file-name of the pseudo-terminal subsidiary device
 *                      will be recorded in subsid_name[], which must have
 *                      at least PTY_MAX_NAME elements.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int pty_open_manager(const char *prog, int *cntrl, char *subsid_name)
{
  char manager_name[PTY_MAX_NAME]; /* The filename of the manager device */
  DIR *dir;                       /* The directory iterator */
  struct dirent *file;            /* A file in "/dev" */
/*
 * Mark the controller device as not opened yet.
 */
  *cntrl = -1;
/*
 * On systems with the Sys-V pseudo-terminal interface, we don't
 * have to search for a free manager terminal. We just open /dev/ptmx,
 * and if there is a free manager terminal device, we are given a file
 * descriptor connected to it.
 */
#if HAVE_SYSV_PTY
  *cntrl = open("/dev/ptmx", O_RDWR);
  if(*cntrl >= 0) {
/*
 * Get the filename of the subsidiary side of the pseudo-terminal.
 */
    char *name = ptsname(*cntrl);
    if(name) {
      if(strlen(name)+1 > PTY_MAX_NAME) {
	fprintf(stderr, "%s: Subsidiary pty filename too long.\n", prog);
	return 1;
      };
      strlcpy(subsid_name, name, PTY_MAX_NAME);
/*
 * If unable to get the subsidiary name, discard the controller file
 * descriptor, ready to try a search instead.
 */
    } else {
      close(*cntrl);
      *cntrl = -1;
    };
  } else {
#endif
/*
 * On systems without /dev/ptmx, or if opening /dev/ptmx failed,
 * we open one manager terminal after another, until one that isn't
 * in use by another program is found.
 *
 * Open the devices directory.
 */
    dir = opendir(PTY_DEV_DIR);
    if(!dir) {
      fprintf(stderr, "%s: Couldn't open %s (%s)\n", prog, PTY_DEV_DIR,
	      strerror(errno));
      return 1;
    };
/*
 * Look for pseudo-terminal controller device files in the devices
 * directory.
 */
    while(*cntrl < 0 && (file = readdir(dir))) {
      if(strncmp(file->d_name, PTY_CNTRL, sizeof(PTY_CNTRL)-1) == 0) {
/*
 * Get the common extension of the control and subsidiary filenames.
 */
	const char *ext = file->d_name + sizeof(PTY_CNTRL)-1;
	if(strlen(ext) > PTY_MAX_SUFFIX)
	  continue;
/*
 * Attempt to open the control file.
 */
	strlcpy(manager_name, PTY_DEV_DIR, sizeof(manager_name));
	strlcat(manager_name, PTY_CNTRL, sizeof(manager_name));
	strlcat(manager_name, ext, sizeof(manager_name));
	*cntrl = open(manager_name, O_RDWR);
	if(*cntrl < 0)
	  continue;
/*
 * Attempt to open the matching subsidiary file.
 */
	strlcpy(subsid_name, PTY_DEV_DIR, PTY_MAX_NAME);
	strlcat(subsid_name, PTY_SUBSID, PTY_MAX_NAME);
	strlcat(subsid_name, ext, PTY_MAX_NAME);
      };
    };
    closedir(dir);
#if HAVE_SYSV_PTY
  };
#endif
/*
 * Did we fail to find a pseudo-terminal pair that we could open?
 */
  if(*cntrl < 0) {
    fprintf(stderr, "%s: Unable to find a free pseudo-terminal.\n", prog);
    return 1;
  };
/*
 * System V systems require the program that opens the manager to
 * grant access to the subsidiary side of the pseudo-terminal.
 */
#ifdef HAVE_SYSV_PTY
  if(grantpt(*cntrl) < 0 ||
     unlockpt(*cntrl) < 0) {
    fprintf(stderr, "%s: Unable to unlock terminal (%s).\n", prog,
	    strerror(errno));
    return 1;
  };
#endif
/*
 * Success.
 */
  return 0;
}

/*.......................................................................
 * Open the subsidiary end of a pseudo-terminal.
 *
 * Input:
 *  prog   const char *  The name of this program.
 *  subsid_name   char *  The filename of the subsidiary device.
 * Output:
 *  return        int    The file descriptor of the successfully opened
 *                       subsidiary device, or < 0 on error.
 */
static int pty_open_subsid(const char *prog, char *subsid_name)
{
  int fd;  /* The file descriptor of the subsidiary device */
/*
 * Place the process in its own process group. In system-V based
 * OS's, this ensures that when the pseudo-terminal is opened, it
 * becomes the controlling terminal of the process.
 */
  if(setsid() < 0) {
    fprintf(stderr, "%s: Unable to form new process group (%s).\n", prog,
	    strerror(errno));
    return -1;
  };
/*
 * Attempt to open the specified device.
 */
  fd = open(subsid_name, O_RDWR);
  if(fd < 0) {
    fprintf(stderr, "%s: Unable to open pty subsidiary device (%s).\n",
	    prog, strerror(errno));
    return -1;
  };
/*
 * On system-V streams based systems, we need to push the stream modules
 * that implement pseudo-terminal and termio interfaces. At least on
 * Solaris, which pushes these automatically when a subsidiary is opened,
 * this is redundant, so ignore errors when pushing the modules.
 */
#if HAVE_SYSV_PTY
  (void) ioctl(fd, I_PUSH, "ptem");
  (void) ioctl(fd, I_PUSH, "ldterm");
/*
 * On BSD based systems other than SunOS 4.x, the following makes the
 * pseudo-terminal the controlling terminal of the child process.
 * According to the pseudo-terminal example code in Steven's
 * Advanced programming in the unix environment, the !defined(CIBAUD)
 * part of the clause prevents this from being used under SunOS. Since
 * I only have his code with me, and won't have access to the book,
 * I don't know why this is necessary.
 */
#elif defined(TIOCSCTTY) && !defined(CIBAUD)
  if(ioctl(fd, TIOCSCTTY, (char *) 0) < 0) {
    fprintf(stderr, "%s: Unable to establish controlling terminal (%s).\n",
	    prog, strerror(errno));
    close(fd);
    return -1;
  };
#endif
  return fd;
}

/*.......................................................................
 * Read input from the controlling terminal of the program, using
 * gl_get_line(), and feed it to the user's program running in a child
 * process, via the controller side of the pseudo-terminal. Also pass
 * data received from the user's program via the conroller end of
 * the pseudo-terminal, to stdout.
 *
 * Input:
 *  prog  const char *  The name of this program.
 *  cntrl        int    The file descriptor of the controller end of the
 *                      pseudo-terminal.
 * Output:
 *  return       int    0 - OK.
 *                      1 - Error.
 */
static int pty_parent(const char *prog, int cntrl)
{
  GetLine *gl = NULL;  /* The gl_get_line() resource object */
  char *line;          /* An input line read from the user */
  char *rbuff=NULL;    /* A buffer for reading from the pseudo terminal */
/*
 * Allocate the gl_get_line() resource object.
 */
  gl = new_GetLine(PTY_MAX_LINE, PTY_HIST_SIZE);
  if(!gl)
    return pty_stop_parent(1, cntrl, gl, rbuff);
/*
 * Allocate a buffer to use to accumulate bytes read from the
 * pseudo-terminal.
 */
  rbuff = (char *) malloc(PTY_MAX_READ+1);
  if(!rbuff)
    return pty_stop_parent(1, cntrl, gl, rbuff);
  rbuff[0] = '\0';
/*
 * Register an event handler to watch for data appearing from the
 * user's program on the controller end of the pseudo terminal.
 */
  if(gl_watch_fd(gl, cntrl, GLFD_READ, pty_read_from_program, rbuff))
    return pty_stop_parent(1, cntrl, gl, rbuff);
/*
 * Read input lines from the user and pass them on to the user's program,
 * by writing to the controller end of the pseudo-terminal.
 */
  while((line=gl_get_line(gl, rbuff, NULL, 0))) {
    if(pty_write_to_fd(cntrl, line, strlen(line)))
       return pty_stop_parent(1, cntrl, gl, rbuff);
    rbuff[0] = '\0';
  };
  return pty_stop_parent(0, cntrl, gl, rbuff);
}

/*.......................................................................
 * This is a private return function of pty_parent(), used to release
 * dynamically allocated resources, close the controller end of the
 * pseudo-terminal, and wait for the child to exit. It returns the
 * exit status of the child process, unless the caller reports an
 * error itself, in which case the caller's error status is returned.
 *
 * Input:
 *  waserr   int    True if the caller is calling this function because
 *                  an error occured.
 *  cntrl    int    The file descriptor of the controller end of the
 *                  pseudo-terminal.
 *  gl   GetLine *  The resource object of gl_get_line().
 *  rbuff   char *  The buffer used to accumulate bytes read from
 *                  the pseudo-terminal.
 * Output:
 *  return  int    The desired exit status of the program.
 */
static int pty_stop_parent(int waserr, int cntrl, GetLine *gl, char *rbuff)
{
  int status;  /* The return status of the child process */
/*
 * Close the controller end of the terminal.
 */
  close(cntrl);
/*
 * Delete the resource object.
 */
  gl = del_GetLine(gl);
/*
 * Delete the read buffer.
 */
  if(rbuff)
    free(rbuff);
/*
 * Wait for the user's program to end.
 */
  (void) wait(&status);
/*
 * Return either our error status, or the return status of the child
 * program.
 */
  return waserr ? 1 : status;
}

/*.......................................................................
 * Run the user's program, with its stdin and stdout connected to the
 * subsidiary end of the psuedo-terminal.
 *
 * Input:
 *  prog  const char *   The name of this program.
 *  subsid        int     The file descriptor of the subsidiary end of the
 *                       pseudo terminal.
 *  argv        char *[] The argument vector to pass to the user's program,
 *                       where argv[0] is the name of the user's program,
 *                       and the last argument is followed by a pointer
 *                       to NULL.
 * Output:
 *  return   int         If this function returns at all, an error must
 *                       have occured when trying to overlay the process
 *                       with the user's program. In this case 1 is
 *                       returned.
 */
static int pty_child(const char *prog, int subsid, char *argv[])
{
  struct termios attr; /* The terminal attributes */
/*
 * We need to stop the pseudo-terminal from echoing everything that we send it.
 */
  if(tcgetattr(subsid, &attr)) {
    fprintf(stderr, "%s: Can't get pseudo-terminal attributes (%s).\n", prog,
	    strerror(errno));
    return 1;
  };
  attr.c_lflag &= ~(ECHO);
  while(tcsetattr(subsid, TCSADRAIN, &attr)) {
    if(errno != EINTR) {
      fprintf(stderr, "%s: tcsetattr error: %s\n", prog, strerror(errno));
      return 1;
    };
  };
/*
 * Arrange for stdin, stdout and stderr to be connected to the subsidiary
 * device, ignoring errors that imply that either stdin or stdout is closed.
 */
  while(dup2(subsid, STDIN_FILENO) < 0 && errno==EINTR)
    ;
  while(dup2(subsid, STDOUT_FILENO) < 0 && errno==EINTR)
    ;
  while(dup2(subsid, STDERR_FILENO) < 0 && errno==EINTR)
    ;
/*
 * Run the user's program.
 */
  if(execvp(argv[0], argv) < 0) {
    fprintf(stderr, "%s: Unable to execute %s (%s).\n", prog, argv[0],
	    strerror(errno));
    fflush(stderr);
    _exit(1);
  };
  return 0;  /* This should never be reached */
}

/*.......................................................................
 * This is the event-handler that is called by gl_get_line() whenever
 * there is tet waiting to be read from the user's program, via the
 * controller end of the pseudo-terminal. See libtecla.h for details
 * about its arguments.
 */
static GL_FD_EVENT_FN(pty_read_from_program)
{
  char *nlptr;   /* A pointer to the last newline in the accumulated string */
  char *crptr;   /* A pointer to the last '\r' in the accumulated string */
  char *nextp;   /* A pointer to the next unprocessed character */
/*
 * Get the read buffer in which we are accumulating a line to be
 * forwarded to stdout.
 */
  char *rbuff = (char *) data;
/*
 * New data may arrive while we are processing the current read, and
 * it is more efficient to display this here than to keep returning to
 * gl_get_line() and have it display the latest prefix as a prompt,
 * followed by the current input line, so we loop, delaying a bit at
 * the end of each iteration to check for more data arriving from
 * the application, before finally returning to gl_get_line() when
 * no more input is available.
 */
  do {
/*
 * Get the current length of the output string.
 */
    int len = strlen(rbuff);
/*
 * Read the text from the program.
 */
    int nnew = read(fd, rbuff + len, PTY_MAX_READ - len);
    if(nnew < 0)
      return GLFD_ABORT;
    len += nnew;
/*
 * Nul terminate the accumulated string.
 */
    rbuff[len] = '\0';
/*
 * Find the last newline and last carriage return in the buffer, if any.
 */
    nlptr = strrchr(rbuff, '\n');
    crptr = strrchr(rbuff, '\r');
/*
 * We want to output up to just before the last newline or carriage
 * return. If there are no newlines of carriage returns in the line,
 * and the buffer is full, then we should output the whole line. In
 * all cases a new output line will be started after the latest text
 * has been output. The intention is to leave any incomplete line
 * in the buffer, for (perhaps temporary) use as the current prompt.
 */
    if(nlptr) {
      nextp = crptr && crptr < nlptr ? crptr : nlptr;
    } else if(crptr) {
      nextp = crptr;
    } else if(len >= PTY_MAX_READ) {
      nextp = rbuff + len;
    } else {
      nextp = NULL;
    };
/*
 * Do we have any text to output yet?
 */
    if(nextp) {
/*
 * If there was already some text in rbuff before this function
 * was called, then it will have been used as a prompt. Arrange
 * to rewrite this prefix, plus the new suffix, by moving back to
 * the start of the line.
 */
      if(len > 0)
	(void) pty_write_to_fd(STDOUT_FILENO, "\r", 1);
/*
 * Write everything up to the last newline to stdout.
 */
      (void) pty_write_to_fd(STDOUT_FILENO, rbuff, nextp - rbuff);
/*
 * Start a new line.
 */
      (void) pty_write_to_fd(STDOUT_FILENO, "\r\n", 2);
/*
 * Skip trailing carriage returns and newlines.
 */
      while(*nextp=='\n' || *nextp=='\r')
	nextp++;
/*
 * Move any unwritten text following the newline, to the start of the
 * buffer.
 */
      memmove(rbuff, nextp, len - (nextp - rbuff) + 1);
    };
  } while(pty_manager_readable(fd, PTY_READ_TIMEOUT));
/*
 * Make the incomplete line in the output buffer the current prompt.
 */
  gl_replace_prompt(gl, rbuff);
  return GLFD_REFRESH;
}

/*.......................................................................
 * Write a given string to a specified file descriptor.
 *
 * Input:
 *  fd             int     The file descriptor to write to.
 *  string  const char *   The string to write (of at least 'n' characters).
 *  n              int     The number of characters to write.
 * Output:
 *  return         int     0 - OK.
 *                         1 - Error.
 */
static int pty_write_to_fd(int fd, const char *string, int n)
{
  int ndone = 0;  /* The number of characters written so far */
/*
 * Do as many writes as are needed to write the whole string.
 */
  while(ndone < n) {
    int nnew = write(fd, string + ndone, n - ndone);
    if(nnew > 0)
      ndone += nnew;
    else if(errno != EINTR)
      return 1;
  };
  return 0;
}

/*.......................................................................
 * This is the signal handler that is called when the child process
 * that is running the user's program exits for any reason. It closes
 * the subsidiary end of the terminal, so that gl_get_line() in the parent
 * process sees an end of file.
 */
static void pty_child_exited(int sig)
{
  raise(SIGINT);
}

/*.......................................................................
 * Return non-zero after a given amount of time if there is data waiting
 * to be read from a given file descriptor.
 *
 * Input:
 *  fd        int  The descriptor to watch.
 *  usec     long  The number of micro-seconds to wait for input to
 *                 arrive before giving up.
 * Output:
 *  return    int  0 - No data is waiting to be read (or select isn't
 *                     available).
 *                 1 - Data is waiting to be read.
 */
static int pty_manager_readable(int fd, long usec)
{
#if HAVE_SELECT
  fd_set rfds;             /* The set of file descriptors to check */
  struct timeval timeout;  /* The timeout */
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);
  timeout.tv_sec = 0;
  timeout.tv_usec = usec;
  return select(fd+1, &rfds, NULL, NULL, &timeout) == 1;
#else
  return 0;
#endif
}
