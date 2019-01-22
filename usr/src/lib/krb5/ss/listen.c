/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
/* Solaris Kerberos */
#include <libtecla.h>

#define	MAX_LINE_LEN BUFSIZ
#define	MAX_HIST_LEN 8192

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
/* Solaris Kerberos */
typedef struct _ss_commands {
	int sci_idx;
	const char **cmd;
	unsigned int count;
} ss_commands;

/*
 * Solaris Kerberos
 * get_commands fills out a ss_commands structure with pointers
 * to the top-level commands (char*) that a program supports.
 * count reflects the number of commands cmd holds. Memory must
 * be allocated by the caller.
 */
void get_commands(ss_commands *commands) {
	const char * const *cmd;
	ss_request_table **table;
	ss_request_entry *request;
	ss_data *info;

	commands->count = 0;

	info = ss_info(commands->sci_idx);
	for (table = info->rqt_tables; *table; table++) {
		for (request = (*table)->requests;
		    request->command_names != NULL; request++) {
			for (cmd = request->command_names;
			    cmd != NULL && *cmd != NULL; cmd++) {
				if (commands->cmd != NULL)
					commands->cmd[commands->count] = *cmd;
				commands->count++;
			}
		}
	}
}

/*
 * Solaris Kerberos
 * Match function used by libtecla for tab-completion.
 */
CPL_MATCH_FN(cmdmatch) {
	int argc, len, ws, i;
	char **argv, *l;
	ss_commands *commands = data;
	int ret = 0;

	/* Dup the line as ss_parse will modify the string */
	l = strdup(line);
	if (l == NULL)
		return (ret);

	/* Tab-completion may happen in the middle of a line */
	if (word_end != strlen(l))
		l[word_end] = '\0';

	if (ss_parse(commands->sci_idx, l, &argc, &argv, 1)) {
		free (l);
		return (ret);
	}

	/* Don't bother if the arg count is not 1 or 0 */
	if (argc < 2) {
		len = argc ? strlen(argv[0]) : 0;
		ws = word_end - len;

		for (i = 0; i < commands->count; i++) {
			if (strncmp(commands->cmd[i], line + ws, len) == 0) {
				ret = cpl_add_completion(cpl, line, ws,
				    word_end, commands->cmd[i] + len, "", " ");
				if (ret)
					break;
			}
		}
	}

	free(argv);
	free(l);
	return (ret);
}

int ss_listen (sci_idx)
    int sci_idx;
{
    register char *cp;
    register ss_data *info;
    char buffer[BUFSIZ];
    char *volatile end = buffer;
    int code;

    /* Solaris Kerberos */
    char *input;
    GetLine *gl;
    GlReturnStatus ret;
    ss_commands commands;

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

    /* Solaris Kerberos */
    gl = new_GetLine(MAX_LINE_LEN, MAX_HIST_LEN);
    if (gl == NULL) {
	ss_error(sci_idx, 0, dgettext(TEXT_DOMAIN,
            "new_GetLine() failed.\n"));
	current_info = old_info;
	return (SS_ET_TECLA_ERR);
    }

    commands.sci_idx = sci_idx;
    commands.cmd = NULL;

    /* Find out how many commands there are */
    get_commands(&commands);

    /* Alloc space for them */
    commands.cmd = malloc(sizeof (char *) * commands.count);
    if (commands.cmd == NULL) {
	current_info = old_info;
	gl = del_GetLine(gl);
	return (ENOMEM);
    }

    /* Fill-in commands.cmd */
    get_commands(&commands);

    if (gl_customize_completion(gl, &commands, cmdmatch) != 0 ) {
	ss_error(sci_idx, 0, dgettext(TEXT_DOMAIN,
            "failed to register completion function.\n"));
	free(commands.cmd);
	current_info = old_info;
	gl = del_GetLine(gl);
	return (SS_ET_TECLA_ERR);
    }

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

    /*
     * Solaris Kerberos:
     * Let libtecla deal with SIGINT when it's doing its own processing
     * otherwise the input line won't be cleared on SIGINT.
     */
    if (gl_trap_signal(gl, SIGINT, GLS_DONT_FORWARD, GLS_ABORT, 0)) {
        ss_error(sci_idx, 0, dgettext(TEXT_DOMAIN,
            "Failed to trap SIGINT.\n"));
	code = SS_ET_TECLA_ERR;
	goto egress;
    }

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

        /* Solaris Kerberos */
        input = gl_get_line(gl, info->prompt, NULL, -1);
        ret = gl_return_status(gl);

        switch (ret) {
            case (GLR_SIGNAL):
                gl_abandon_line(gl);
                continue;
            case (GLR_EOF):
                info->abort = 1;
                continue;
            case (GLR_ERROR):
                ss_error(sci_idx, 0, dgettext(TEXT_DOMAIN,
                    "Failed to read line: %s\n"), gl_error_message(gl, NULL, 0));
                info->abort = 1;
		code = SS_ET_TECLA_ERR;
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

    /* Solaris Kerberos */
    free(commands.cmd);
    gl = del_GetLine(gl);

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
