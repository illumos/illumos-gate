/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Listener loop for subsystem library libss.a.
 *
 *	util/ss/listen.c
 * 
 * Copyright 1987, 1988 by MIT Student Information Processing Board
 *
 * For copyright information, see copyright.h.
 */

#include "copyright.h"
#include "ss_internal.h"
#include <stdio.h>
#include <setjmp.h>
#include <signal.h>
#include <termios.h>
#include <libintl.h>
#include <sys/param.h>

static ss_data *current_info;
static jmp_buf listen_jmpb;

static RETSIGTYPE print_prompt()
{
    struct termios termbuf;

    if (tcgetattr(STDIN_FILENO, &termbuf) == 0) {
	termbuf.c_lflag |= ICANON|ISIG|ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &termbuf);
    }
    (void) fputs(current_info->prompt, stdout);
    (void) fflush(stdout);
}

static RETSIGTYPE listen_int_handler(signo)
    int signo;
{
    putc('\n', stdout);
    longjmp(listen_jmpb, 1);
}

int ss_listen (sci_idx)
    int sci_idx;
{
    register char *cp;
    register ss_data *info;
    char input[BUFSIZ];
    char buffer[BUFSIZ];
    char *volatile end = buffer;
    int code;
    jmp_buf old_jmpb;
    ss_data *old_info = current_info;
#ifdef POSIX_SIGNALS
    struct sigaction isig, csig, nsig, osig;
    sigset_t nmask, omask;
#else
    register RETSIGTYPE (*sig_cont)();
    RETSIGTYPE (*sig_int)(), (*old_sig_cont)();
    int mask;
#endif
    
    current_info = info = ss_info(sci_idx);
    info->abort = 0;

#ifdef POSIX_SIGNALS
    csig.sa_handler = (RETSIGTYPE (*)())0;
    sigemptyset(&nmask);
    sigaddset(&nmask, SIGINT);
    sigprocmask(SIG_BLOCK, &nmask, &omask);
#else
    sig_cont = (RETSIGTYPE (*)())0;
    mask = sigblock(sigmask(SIGINT));
#endif

    memcpy(old_jmpb, listen_jmpb, sizeof(jmp_buf));

#ifdef POSIX_SIGNALS
    nsig.sa_handler = listen_int_handler;
    sigemptyset(&nsig.sa_mask);
    nsig.sa_flags = 0;
    sigaction(SIGINT, &nsig, &isig);
#else
    sig_int = signal(SIGINT, listen_int_handler);
#endif

    setjmp(listen_jmpb);

#ifdef POSIX_SIGNALS
    sigprocmask(SIG_SETMASK, &omask, (sigset_t *)0);
#else
    (void) sigsetmask(mask);
#endif
    while(!info->abort) {
	print_prompt();
	*end = '\0';
#ifdef POSIX_SIGNALS
	nsig.sa_handler = listen_int_handler;	/* fgets is not signal-safe */
	osig = csig;
	sigaction(SIGCONT, &nsig, &csig);
	if ((RETSIGTYPE (*)())csig.sa_handler==(RETSIGTYPE (*)())listen_int_handler)
	    csig = osig;
#else
	old_sig_cont = sig_cont;
	sig_cont = signal(SIGCONT, print_prompt);
	if (sig_cont == print_prompt)
	    sig_cont = old_sig_cont;
#endif
	if (fgets(input, BUFSIZ, stdin) != input) {
	    code = SS_ET_EOF;
	    goto egress;
	}
	cp = strchr(input, '\n');
	if (cp) {
	    *cp = '\0';
	    if (cp == input)
		continue;
	}
#ifdef POSIX_SIGNALS
	sigaction(SIGCONT, &csig, (struct sigaction *)0);
#else
	(void) signal(SIGCONT, sig_cont);
#endif
	for (end = input; *end; end++)
	    ;

	code = ss_execute_line (sci_idx, input);
	if (code == SS_ET_COMMAND_NOT_FOUND) {
	    register char *c = input;
	    while (*c == ' ' || *c == '\t')
		c++;
	    cp = strchr (c, ' ');
	    if (cp)
		*cp = '\0';
	    cp = strchr (c, '\t');
	    if (cp)
		*cp = '\0';
	    ss_error (sci_idx, 0, dgettext(TEXT_DOMAIN,
		    "Unknown request \"%s\".  Type \"?\" for a request list."),
		       c);
	}
    }
    code = 0;
egress:
#ifdef POSIX_SIGNALS
    sigaction(SIGINT, &isig, (struct sigaction *)0);
#else
    (void) signal(SIGINT, sig_int);
#endif
    memcpy(listen_jmpb, old_jmpb, sizeof(jmp_buf));
    current_info = old_info;
    return code;
}

void ss_abort_subsystem(sci_idx, code)
    int sci_idx;
    int code;
{
    ss_info(sci_idx)->abort = 1;
    ss_info(sci_idx)->exit_status = code;
    
}

void ss_quit(argc, argv, sci_idx, infop)
    int argc;
    char const * const *argv;
    int sci_idx;
    pointer infop;
{
    ss_abort_subsystem(sci_idx, 0);
}
