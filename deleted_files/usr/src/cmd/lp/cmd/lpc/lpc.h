/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.1	*/

/*
 * Copyright (c) 1983 Regents of the University of California.
 * All rights reserved.  The Berkeley software License Agreement
 * specifies the terms and conditions for redistribution.
 *
 */

/*
 * Line printer control program.
 */
struct	cmd {
	char	*c_name;		/* command name */
	char	*c_help;		/* help message */
	void	(*c_handler)();		/* routine to do the work */
	int	c_priv;			/* privileged command */
};

#if defined(__STDC__)
char *	get_reason(int, char **);
int	topq_reqid(char *, char *);
int	topq_user(char *, char *);
void	_abort(int, char **);
void	clean(int, char **);
void	cleanpr(char *);
void	disable(int, char **);
void	disablepr(char *);
void	disableq(char *);
void	do_all(void (*)(char *));
void	down(int, char **);
void	downpr(char *);
void	enable(int, char **);
void	enablepr(char *);
void	enableq(char *);
void	help(int, char **);
void	quit(int, char **);
void	restart(int, char **);
void	restartpr(char *);
void	start(int, char **);
void	status(int, char **);
void	statuspr(char *);
void	stop(int, char **);
void	topq(int, char **);
void	up(int, char **);
void	uppr(char *);
#else
char *	get_reason();
int	topq_reqid();
int	topq_user();
void	_abort();
void	clean();
void	cleanpr();
void	disable();
void	disablepr();
void	disableq();
void	do_all();
void	down();
void	downpr();
void	enable();
void	enablepr();
void	enableq();
void	help();
void	quit();
void	restart();
void	restartpr();
void	start();
void	status();
void	statuspr();
void	stop();
void	topq();
void	up();
void	uppr();
#endif
