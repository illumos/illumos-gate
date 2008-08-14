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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#ifndef _SYSTEM_
#define	_SYSTEM_
#if defined(sun) && !defined(SOLARIS)

/* Prototypes that don't exist even as extern declarations */

char 		*mktemp(char *templt);


#if defined(_lint)

#define	toascii(c)	((c) & 0177)

extern void * __builtin_va_alist;
unsigned int	alarm(unsigned int seconds);
int		bind(int, void *, int);
int		close(int);
int		creat(char *, int);
char		*cuserid(char *);
double		drand48(void);
int		execl(char *, char *, ...);
int		execlp(char *, char *, ...);
int		execv(char *, char *[]);
int		fcntl(int, int, void *);
int		flock(int, int);
int 		fork(void);
int		fstat(int, void *);
int		ftime(void *);
int		ftok(char *, char);
int		getdtablesize(void);
unsigned short		getegid(void);
unsigned short	geteuid(void);
struct hostent *gethostbyname(char *);
int 		gethostname(char *, int);
int		getopt(int, char **, char *);
int 		getpid(void);
int		getrusage(int, void *);
int		gettimeofday(void *, void *);
int		ioctl(int, int, void *);
int		isatty(int);
int		kill(int, int);
void		longjmp(void *, int);
long		lrand48(void);
long		lseek(int, int, int);
int		open(const char *, int, ...);
int		pause(void);
void		pclose(void *);
int		read(int, void *, int);
int		scandir(char *, void *, int (*)(), int (*)());
int		semctl(int, int, int, ...);
int		semget(int, int, int);
int		semop(int, void *, int);
int		select(int, void*, void*, void*, void*);
int		setuid(int);
int		sendto(int, char *, int, int, void *, int);
int		setgid(unsigned short);
int		setjmp(void *);
int		setpgrp(int, int);
int		setreuid(int, int);
char		*shmat(int, void *, int);
int		shmctl(int, int, void *);
int		shmdt(char *);
int		shmget(int, int, int);
int		sigaction(int, void *, void *);
int		sigemptyset(int *);
int  		siginterrupt(int sig, int flag);
int		sigvec(int, void *, void *);
unsigned int	sleep(unsigned int seconds);
int		socket(int, int, int);
void		srand48(long seedval);
int		stat(char *, void *);
int		strcasecmp(const char *, const char *);
int		strncasecmp(const char *, const char *, int);
int		stty(int, void *);
char		*timezone(int, int);
unsigned short	umask(unsigned short);
int		unlink(char *);
int		wait(int *);
int		waitpid(int, int *, int);
int		wait3(int *, int, void *);
int		wclrtoeol(void *);
int		write(int, void *, int);


int		delwin(void *);
int		endwin(void);
int		setlinebuf(void *);
int		waddch(void *, char);
int		waddstr(void *, char *);
int		wdelch(void *, char);
int		wgetch(void *);
int		wmove(void *, int, int);
int		wprintw(void *, char *, ...);
int		wrefresh(void *);
int		wclear(void *);

#else

char		*shmat(int, void *, int);

#endif

#endif

#endif /* _SYSTEM_ */
