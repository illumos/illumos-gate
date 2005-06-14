/*
 * Copyright 1994-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 1988, 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)externs.h	8.1 (Berkeley) 6/6/93
 */

#ifndef _EXTERNS_H
#define	_EXTERNS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <libintl.h>
#include <stdio.h>
#include <setjmp.h>
#include <sys/filio.h>
#ifdef	USE_TERMIO
#include <sys/termios.h>
#define	termio termios
#endif
#if defined(NO_CC_T) || !defined(USE_TERMIO)
#if !defined(USE_TERMIO)
typedef char cc_t;
#else
typedef unsigned char cc_t;
#endif
#endif

#include "auth.h"
#include "encrypt.h"
#include <profile/prof_int.h>

extern profile_options_boolean	config_file_options[];
#define	forwardable_flag_set	config_file_options[0].found
#define	forward_flag_set	config_file_options[1].found
#define	encrypt_flag_set	config_file_options[2].found
#define	autologin_set		config_file_options[3].found

#include <string.h>

#ifndef	_POSIX_VDISABLE
#include <sys/param.h>	/* pick up VDISABLE definition, mayby */
#ifdef VDISABLE
#define	_POSIX_VDISABLE VDISABLE
#else
#define	_POSIX_VDISABLE ((cc_t)'\377')
#endif
#endif

#include <wait.h>
#include <stdlib.h>
#include <unistd.h>


#define	SUBBUFSIZE	256

extern int autologin;	/* Autologin enabled */
extern int skiprc;	/* Don't process the ~/.telnetrc file */
extern int eight;	/* use eight bit mode (binary in and/or out */
extern int flushout;	/* flush output */
extern int connected;	/* Are we connected to the other side? */
extern int globalmode;	/* Mode tty should be in */
extern int telnetport;	/* Are we connected to the telnet port? */
extern int localflow;	/* Flow control handled locally */
extern int restartany;	/* If flow control, restart output on any character */
extern int localchars;	/* we recognize interrupt/quit */
extern int donelclchars; /* the user has set "localchars" */
extern int showoptions;
extern int net;		/* Network file descriptor */
extern int tout;	/* Terminal output file descriptor */
extern int crlf;	/* Should '\r' be mapped to <CR><LF> (or <CR><NUL>)? */
extern int autoflush;	/* flush output when interrupting? */
extern int autosynch;	/* send interrupt characters with SYNCH? */
extern int SYNCHing;	/* Is the stream in telnet SYNCH mode? */
extern int donebinarytoggle;	/* the user has put us in binary */
extern int dontlecho;	/* do we suppress local echoing right now? */
extern int crmod;
extern int netdata;	/* Print out network data flow */
extern int prettydump;	/* Print "netdata" output in user readable format */
extern int termdata;	/* Print out terminal data flow */
extern int eof_pending;	/* Received EOF in line mode, need to send IAC-xEOF */
extern int debug;	/* Debug level */


extern int krb5auth_flag;
extern char *RemoteHostName;
extern char *UserNameRequested;
extern int forwardable_flag;
extern int forward_flag;
extern boolean_t wantencryption;	/* User has requested encryption */
extern int encrypt_flag;		/* for reading config file for Krb5 */

extern boolean_t Ambiguous(void *);
extern boolean_t intr_happened;	/* for interrupt handling */
extern boolean_t intr_waiting;

extern cc_t escape;	/* Escape to command mode */
extern cc_t rlogin;	/* Rlogin mode escape character */
extern boolean_t escape_valid;
#ifdef	KLUDGELINEMODE
extern cc_t echoc;	/* Toggle local echoing */
#endif

extern char *prompt;	/* Prompt for command. */

extern char doopt[];
extern char dont[];
extern char will[];
extern char wont[];
extern char options[];	/* All the little options */
extern char *hostname;	/* Who are we connected to? */
extern void (*encrypt_output) (unsigned char *, int);
extern int (*decrypt_input) (int);

/*
 * We keep track of each side of the option negotiation.
 */

#define	MY_STATE_WILL		0x01
#define	MY_WANT_STATE_WILL	0x02
#define	MY_STATE_DO		0x04
#define	MY_WANT_STATE_DO	0x08

/*
 * Macros to check the current state of things
 */

#define	my_state_is_do(opt)		(options[opt]&MY_STATE_DO)
#define	my_state_is_will(opt)		(options[opt]&MY_STATE_WILL)
#define	my_want_state_is_do(opt)	(options[opt]&MY_WANT_STATE_DO)
#define	my_want_state_is_will(opt)	(options[opt]&MY_WANT_STATE_WILL)

#define	my_state_is_dont(opt)		(!my_state_is_do(opt))
#define	my_state_is_wont(opt)		(!my_state_is_will(opt))
#define	my_want_state_is_dont(opt)	(!my_want_state_is_do(opt))
#define	my_want_state_is_wont(opt)	(!my_want_state_is_will(opt))

#define	set_my_state_do(opt)		{options[opt] |= MY_STATE_DO; }
#define	set_my_state_will(opt)		{options[opt] |= MY_STATE_WILL; }
#define	set_my_want_state_do(opt)	{options[opt] |= MY_WANT_STATE_DO; }
#define	set_my_want_state_will(opt)	{options[opt] |= MY_WANT_STATE_WILL; }

#define	set_my_state_dont(opt)		{options[opt] &= ~MY_STATE_DO; }
#define	set_my_state_wont(opt)		{options[opt] &= ~MY_STATE_WILL; }
#define	set_my_want_state_dont(opt)	{options[opt] &= ~MY_WANT_STATE_DO; }
#define	set_my_want_state_wont(opt)	{options[opt] &= ~MY_WANT_STATE_WILL; }

/*
 * Make everything symetrical
 */

#define	HIS_STATE_WILL			MY_STATE_DO
#define	HIS_WANT_STATE_WILL		MY_WANT_STATE_DO
#define	HIS_STATE_DO			MY_STATE_WILL
#define	HIS_WANT_STATE_DO		MY_WANT_STATE_WILL

#define	his_state_is_do			my_state_is_will
#define	his_state_is_will		my_state_is_do
#define	his_want_state_is_do		my_want_state_is_will
#define	his_want_state_is_will		my_want_state_is_do

#define	his_state_is_dont		my_state_is_wont
#define	his_state_is_wont		my_state_is_dont
#define	his_want_state_is_dont		my_want_state_is_wont
#define	his_want_state_is_wont		my_want_state_is_dont

#define	set_his_state_do		set_my_state_will
#define	set_his_state_will		set_my_state_do
#define	set_his_want_state_do		set_my_want_state_will
#define	set_his_want_state_will		set_my_want_state_do

#define	set_his_state_dont		set_my_state_wont
#define	set_his_state_wont		set_my_state_dont
#define	set_his_want_state_dont		set_my_want_state_wont
#define	set_his_want_state_wont		set_my_want_state_dont


extern FILE *NetTrace;		/* Where debugging output goes */
				/* Name of file where debugging output goes */
extern unsigned char NetTraceFile[];
extern void SetNetTrace(char *); /* Function to change where debugging goes */

extern jmp_buf peerdied;
extern jmp_buf toplevel;	/* For error conditions. */

extern char *AllocStringBuffer(char **, unsigned int *, unsigned int);
extern void ExitString(char *, int);
extern void Exit(int);
extern void command(int, char *, int);
extern void Dump(int, unsigned char *, int);
extern char *GetAndAppendString(char **, unsigned int *, char *, FILE *);
extern char *GetString(char **, unsigned int *, FILE *);
extern void init_network(void);
extern void init_terminal(void);
extern void init_sys(void);
extern void optionstatus(void);
extern void printoption(char *, int, int);
extern void printsub(int, unsigned char *, int);
extern void sendnaws(void);
extern void setconnmode(int);
extern void setcommandmode(void);
extern void setneturg(void);
extern void sys_telnet_init(void);
extern void telnet(char *);
extern void tel_enter_binary(int);
extern void tel_leave_binary(int);
extern void TerminalDefaultChars(void);
extern void TerminalFlushOutput(void);
extern void TerminalNewMode(int);
extern void TerminalSaveState(void);
extern void TerminalSpeeds(int *, int *);
extern void upcase(char *);

extern void xmitEL(void);
extern void xmitEC(void);
extern void intp(void);
extern void sendabort(void);
extern void sendsusp(void);
extern void set_escape_char(char *);
extern void fatal_tty_error(char *);

extern void send_do(int, int);
extern void send_dont(int, int);
extern void send_will(int, int);
extern void send_wont(int, int);

extern void lm_mode(unsigned char *, int, int);

extern void slcstate(void);
extern void slc_mode_export(void);
extern void slc_mode_import(int);
extern void slc_check(void);

extern void env_opt_start_info(void);
extern void env_opt_add(unsigned char *);
extern void env_opt_end(int);

extern char **genget(char *, char **, int);
extern unsigned char *env_default(int, int);
extern unsigned char *env_getvalue(unsigned char *);

extern int env_init(void);
extern int get_status(void);
extern int init_telnet(void);
extern int isprefix(register char *, register char *);
extern int netflush(void);
extern int opt_welldefined(char *);
extern int process_rings(int, int, int, int, int, int);
extern int quit(void);
extern int rlogin_susp(void);
extern int Scheduler(int);
extern int SetSockOpt(int, int, int, int);
extern int stilloob(void);
extern int telrcv(void);
extern int TerminalWindowSize(unsigned short *, unsigned short *);
extern int TerminalWrite(char *, int);
extern int TerminalSpecialChars(int);
extern int tn(int, char **);
extern int tninit(void);
extern int ttyflush(int);
extern int getconnmode(void);
extern int xmitAO(void);
extern int sendbrk(void);
extern int dosynch(void);

extern cc_t *tcval(int);

extern void	auth_encrypt_init(char *, char *, char *);
extern void	auth_encrypt_user(char *);
extern int	net_write(unsigned char *, int len);
extern void	net_encrypt(void);
extern void	telnet_spin(void);
extern void	printd(unsigned char *, int);

#ifndef	USE_TERMIO

extern struct	tchars ntc;
extern struct	ltchars nltc;
extern struct	sgttyb nttyb;

#define	termEofChar		ntc.t_eofc
#define	termEraseChar		nttyb.sg_erase
#define	termFlushChar		nltc.t_flushc
#define	termIntChar		ntc.t_intrc
#define	termKillChar		nttyb.sg_kill
#define	termLiteralNextChar	nltc.t_lnextc
#define	termQuitChar		ntc.t_quitc
#define	termSuspChar		nltc.t_suspc
#define	termRprntChar		nltc.t_rprntc
#define	termWerasChar		nltc.t_werasc
#define	termStartChar		ntc.t_startc
#define	termStopChar		ntc.t_stopc
#define	termForw1Char		ntc.t_brkc
extern cc_t termForw2Char;
extern cc_t termAytChar;

#define	termEofCharp		(cc_t *)&ntc.t_eofc
#define	termEraseCharp		(cc_t *)&nttyb.sg_erase
#define	termFlushCharp		(cc_t *)&nltc.t_flushc
#define	termIntCharp		(cc_t *)&ntc.t_intrc
#define	termKillCharp		(cc_t *)&nttyb.sg_kill
#define	termLiteralNextCharp	(cc_t *)&nltc.t_lnextc
#define	termQuitCharp		(cc_t *)&ntc.t_quitc
#define	termSuspCharp		(cc_t *)&nltc.t_suspc
#define	termRprntCharp		(cc_t *)&nltc.t_rprntc
#define	termWerasCharp		(cc_t *)&nltc.t_werasc
#define	termStartCharp		(cc_t *)&ntc.t_startc
#define	termStopCharp		(cc_t *)&ntc.t_stopc
#define	termForw1Charp		(cc_t *)&ntc.t_brkc
#define	termForw2Charp		(cc_t *)&termForw2Char
#define	termAytCharp		(cc_t *)&termAytChar

#else

extern struct	termio new_tc;

#define	termEofChar		new_tc.c_cc[VEOF]
#define	termEraseChar		new_tc.c_cc[VERASE]
#define	termIntChar		new_tc.c_cc[VINTR]
#define	termKillChar		new_tc.c_cc[VKILL]
#define	termQuitChar		new_tc.c_cc[VQUIT]

#define	termSuspChar		new_tc.c_cc[VSUSP]
#define	termFlushChar		new_tc.c_cc[VDISCARD]
#define	termWerasChar		new_tc.c_cc[VWERASE]
#define	termRprntChar		new_tc.c_cc[VREPRINT]
#define	termLiteralNextChar	new_tc.c_cc[VLNEXT]
#define	termStartChar		new_tc.c_cc[VSTART]
#define	termStopChar		new_tc.c_cc[VSTOP]
#define	termForw1Char		new_tc.c_cc[VEOL]
#define	termForw2Char		new_tc.c_cc[VEOL]
extern cc_t termAytChar;

#define	termEofCharp		&termEofChar
#define	termEraseCharp		&termEraseChar
#define	termIntCharp		&termIntChar
#define	termKillCharp		&termKillChar
#define	termQuitCharp		&termQuitChar
#define	termSuspCharp		&termSuspChar
#define	termFlushCharp		&termFlushChar
#define	termWerasCharp		&termWerasChar
#define	termRprntCharp		&termRprntChar
#define	termLiteralNextCharp	&termLiteralNextChar
#define	termStartCharp		&termStartChar
#define	termStopCharp		&termStopChar
#define	termForw1Charp		&termForw1Char
#define	termForw2Charp		&termForw2Char
#define	termAytCharp		&termAytChar
#endif


/* Ring buffer structures which are shared */

#include "ring.h"

extern Ring netoring;
extern Ring netiring;
extern Ring ttyoring;
extern Ring ttyiring;

#ifdef	__cplusplus
}
#endif

#endif	/* _EXTERNS_H */
