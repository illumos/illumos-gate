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
 *	Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 *	Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved  	*/

/*
 *	University Copyright- Copyright (c) 1982, 1986, 1988
 *	The Regents of the University of California
 *	All Rights Reserved
 *
 *	University Acknowledgment- Portions of this document are derived from
 *	software developed by the University of California, Berkeley, and its
 *	contributors.
 */

#ifndef	_FTP_VAR_H
#define	_FTP_VAR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <sys/ttold.h>
#include <sys/stropts.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/ftp.h>
#include <arpa/telnet.h>
#include <arpa/inet.h>
#include <setjmp.h>
#include <libintl.h>
#include <string.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <widec.h>
#include <signal.h>
#include <netdb.h>
#include <pwd.h>
#include <locale.h>
#include <limits.h>
#include <fnmatch.h>
#include <dirent.h>
#include <termios.h>
#include <stdarg.h>
#include <unistd.h>
#include <malloc.h>
#include <strings.h>
#include <errno.h>
#include <ctype.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>

#define	signal(s, f)	sigset(s, f)
#define	setjmp(e)	sigsetjmp(e, 1)
#define	longjmp(e, v)	siglongjmp(e, v)
#define	jmp_buf		sigjmp_buf

/*
 * FTP global variables.
 */
#ifndef	EXTERN
#define	EXTERN	extern
#endif

#define	DEFAULTFTPFILE	"/etc/default/ftp"

/*
 * Options and other state info.
 */
EXTERN int	trace;		/* trace packets exchanged */
EXTERN int	hash;		/* print # for each buffer transferred */
EXTERN int	sendport;	/* use PORT cmd for each data connection */
EXTERN int	verbose;	/* print messages coming back from server */
EXTERN int	connected;	/* connected to server */
EXTERN int	fromatty;	/* input is from a terminal */
EXTERN int	interactive;	/* interactively prompt on m* cmds */
EXTERN int	debug;		/* debugging level */
EXTERN int	bell;		/* ring bell on cmd completion */
EXTERN int	doglob;		/* glob local file names */
EXTERN int	autologin;	/* establish user account on connection */
EXTERN int	proxy;		/* proxy server connection active */
EXTERN int	proxflag;	/* proxy connection exists */
EXTERN int	sunique;	/* store files on server with unique name */
EXTERN int	runique;	/* store local files with unique name */
EXTERN int	mcase;		/* map upper to lower case for mget names */
EXTERN int	ntflag;		/* use ntin ntout tables for name translation */
EXTERN int	mapflag;	/* use mapin mapout templates on file names */
EXTERN int	code;		/* return/reply code for ftp command */
EXTERN int	crflag;		/* if 1, strip car. rets. on ascii gets */
EXTERN char	pasv[64];	/* passive port for proxy data connection */
EXTERN char	*altarg;	/* argv[1] with no shell-like preprocessing  */
EXTERN char	ntin[17];	/* input translation table */
EXTERN char	ntout[17];	/* output translation table */
EXTERN char	mapin[MAXPATHLEN]; /* input map template */
EXTERN char	mapout[MAXPATHLEN]; /* output map template */
EXTERN char	typename[32];	/* name of file transfer type */
EXTERN int	type;		/* file transfer type */
EXTERN char	structname[32];	/* name of file transfer structure */
EXTERN int	stru;		/* file transfer structure */
EXTERN char	formname[32];	/* name of file transfer format */
EXTERN int	form;		/* file transfer format */
EXTERN char	modename[32];	/* name of file transfer mode */
EXTERN int	mode;		/* file transfer mode */
EXTERN char	bytename[32];	/* local byte size in ascii */
EXTERN int	bytesize;	/* local byte size in binary */
EXTERN int	passivemode;	/* passive transfer mode toggle */
EXTERN off_t	restart_point;	/* transfer restart offset */
EXTERN int	tcpwindowsize;	/* TCP window size for the data connection */

EXTERN boolean_t	ls_invokes_NLST;	/* behaviour of 'ls' */
EXTERN char		*hostname;		/* name of host connected to */
EXTERN char		*home;
EXTERN char		*globerr;

EXTERN struct	sockaddr_in6 myctladdr;		/* for channel bindings */
EXTERN struct	sockaddr_in6 remctladdr;	/* for channel bindings */

EXTERN int	clevel;		/* command channel protection level */
EXTERN int	dlevel;		/* data channel protection level */

EXTERN int	autoauth;	/* do authentication on connect */
EXTERN int	auth_type;	/* authentication type */
EXTERN int	auth_error;	/* one error code for all auth types */
EXTERN int	autoencrypt;	/* do encryption on connect */
EXTERN int	fflag;		/* forward credentials */
EXTERN boolean_t goteof;

EXTERN int	skipsyst;	/* enable automatic sending of SYST command */

EXTERN uchar_t	*ucbuf;		/* clear text buffer */

#define	MECH_SZ		40
#define	FTP_DEF_MECH	"kerberos_v5"
EXTERN char	mechstr[MECH_SZ];	/* mechanism type */

EXTERN gss_OID	mechoid;	/* corresponding mechanism oid type */
EXTERN gss_ctx_id_t gcontext;	/* gss security context */

#define	FTPBUFSIZ	BUFSIZ*16
#define	HASHSIZ		BUFSIZ*8

EXTERN char *buf;		/* buffer for binary sends and gets */

EXTERN jmp_buf toplevel;	/* non-local goto stuff for cmd scanner */

/*
 * BUFSIZE includes
 *	- (MAXPATHLEN)*2 to  accomodate 2 paths (remote and local file names).
 *	- MAXCMDLEN to accomodate the longest command listed in cmdtab[]
 *	  (defined in cmdtab.c) as this is stuffed into the buffer along
 *	  with the remote and local file names.
 *	- The 4 bytes are for the 2 blank separators, a carriage-return
 *	  and a NULL terminator.
 *
 * NOTE : The arguments may not be always pathnames (they can be commands
 *	  too). But, here we have considered the worst case of two pathnames.
 */
#define	MAXCMDLEN	10	/* The length of longest command in cmdtab[] */
#define	BUFSIZE	((MAXPATHLEN)*2+MAXCMDLEN+4)

EXTERN char	line[BUFSIZE];	/* input line buffer */
EXTERN char	*stringbase;	/* current scan point in line buffer */
EXTERN char	argbuf[BUFSIZE]; /* argument storage buffer */
EXTERN char	*argbase;	/* current storage point in arg buffer */
EXTERN int	margc;		/* count of arguments on input line */
EXTERN char	**margv;	/* args parsed from input line */
EXTERN int	cpend;		/* flag: if != 0, then pending server reply */
EXTERN int	mflag;		/* flag: if != 0, then active multi command */
EXTERN FILE	*tmp_nlst;	/* tmp file; holds NLST results for mget, etc */

EXTERN char	*reply_parse;	/* for parsing replies to the ADAT command */
EXTERN char	reply_buf[FTPBUFSIZ];
EXTERN char	*reply_ptr;

EXTERN int	options;	/* used during socket creation */

EXTERN int	timeout;	/* connection timeout */
EXTERN int	timeoutms;	/* connection timeout in msec */
EXTERN jmp_buf	timeralarm;	/* to recover from global timeout */


/*
 * Format of command table.
 */
struct cmd {
	char	*c_name;	/* name of command */
	char	*c_help;	/* help string */
	char	c_bell;		/* give bell when command completes */
	char	c_conn;		/* must be connected to use command */
	char	c_proxy;	/* proxy server may execute */
	void	(*c_handler)(int argc, char *argv[]); /* function to call */
};

struct macel {
	char mac_name[9];	/* macro name */
	char *mac_start;	/* start of macro in macbuf */
	char *mac_end;		/* end of macro in macbuf */
};

EXTERN int macnum;			/* number of defined macros */
EXTERN struct macel macros[16];
EXTERN char macbuf[4096];

extern void macdef(int argc, char *argv[]);
extern void doproxy(int argc, char *argv[]);
extern void setpeer(int argc, char *argv[]);
extern void rmthelp(int argc, char *argv[]);
extern void settype(int argc, char *argv[]);
extern void setbinary(int argc, char *argv[]);
extern void setascii(int argc, char *argv[]);
extern void settenex(int argc, char *argv[]);
extern void setebcdic(int argc, char *argv[]);
extern void setmode(int argc, char *argv[]);
extern void setform(int argc, char *argv[]);
extern void setstruct(int argc, char *argv[]);
extern void put(int argc, char *argv[]);
extern void mput(int argc, char *argv[]);
extern void get(int argc, char *argv[]);
extern void mget(int argc, char *argv[]);
extern void status(int argc, char *argv[]);
extern void setbell(int argc, char *argv[]);
extern void settrace(int argc, char *argv[]);
extern void sethash(int argc, char *argv[]);
extern void setverbose(int argc, char *argv[]);
extern void setport(int argc, char *argv[]);
extern void setprompt(int argc, char *argv[]);
extern void setglob(int argc, char *argv[]);
extern void setdebug(int argc, char *argv[]);
extern void cd(int argc, char *argv[]);
extern void lcd(int argc, char *argv[]);
extern void delete(int argc, char *argv[]);
extern void mdelete(int argc, char *argv[]);
extern void renamefile(int argc, char *argv[]);
extern void ls(int argc, char *argv[]);
extern void mls(int argc, char *argv[]);
extern void shell(int argc, char *argv[]);
extern void user(int argc, char *argv[]);
extern void pwd(int argc, char *argv[]);
extern void makedir(int argc, char *argv[]);
extern void removedir(int argc, char *argv[]);
extern void quote(int argc, char *argv[]);
extern void rmthelp(int argc, char *argv[]);
extern void quit(int argc, char *argv[]);
extern void disconnect(int argc, char *argv[]);
extern void account(int argc, char *argv[]);
extern void setcase(int argc, char *argv[]);
extern void setcr(int argc, char *argv[]);
extern void setntrans(int argc, char *argv[]);
extern void setnmap(int argc, char *argv[]);
extern void setsunique(int argc, char *argv[]);
extern void setrunique(int argc, char *argv[]);
extern void cdup(int argc, char *argv[]);
extern void domacro(int argc, char *argv[]);
extern void help(int argc, char *argv[]);
extern void reset(int argc, char *argv[]);
extern void reget(int argc, char *argv[]);
extern void restart(int argc, char *argv[]);
extern void setpassive(int argc, char *argv[]);
extern void settcpwindow(int argc, char *argv[]);
extern void site(int argc, char *argv[]);

extern void ccc(int argc, char *argv[]);
extern void setclear(int argc, char *argv[]);
extern void setclevel(int argc, char *argv[]);
extern void setdlevel(int argc, char *argv[]);
extern void setsafe(int argc, char *argv[]);
extern void setmech(int argc, char *argv[]);

extern int do_auth(void);
extern void setpbsz(uint_t size);
extern char *radix_error(int);
extern int radix_encode(uchar_t *, uchar_t *, size_t, int *, int);
extern void user_gss_error(OM_uint32 maj_stat, OM_uint32 min_stat,
	char *errstr);
extern void setprivate(int argc, char *argv[]);

extern int secure_flush(int);
extern int secure_getc(FILE *);
extern int secure_putc(int, FILE *);
extern ssize_t secure_read(int, void *, size_t);
extern ssize_t secure_write(int, const void *, size_t);

extern void fatal(char *msg);
extern int getreply(int expecteof);
extern void call(void (*routine)(int argc, char *argv[]), ...);
extern void sendrequest(char *cmd, char *local, char *remote, int allowpipe);
extern void recvrequest(char *cmd, char *local, char *remote, char *mode,
    int allowpipe);
extern void makeargv(void);
extern int login(char *host);
extern int command(char *fmt, ...);
extern char **glob(char *v);
extern void blkfree(char **);
extern void pswitch(int flag);

extern char *hookup(char *host, char *);
extern char *mygetpass(char *prompt);
extern void lostpeer(int sig);
extern int ruserpass(char *host, char **aname, char **apass, char **aacct);
extern FILE *mypopen(char *cmd, char *mode);
extern int mypclose(FILE *ptr);
extern struct cmd *getcmd(char *name);

extern void stop_timer(void);
extern void reset_timer(void);
extern int getpagesize(void);

#define	ENCODELEN(l)	(((4 * (l)) / 3) + 4)
#define	DECODELEN(l)	(((3 * (l)) / 4) + 4)

#ifdef	__cplusplus
}
#endif

#endif	/* _FTP_VAR_H */
