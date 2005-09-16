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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef CACA
#define _DEBUG2	1
#endif

#define	MAX_IF_DEPTH	256	/* maximum number of nested if's */

/*
 * Possible "if" states
 */
#define	IN_A_CONDITION	1	/* we are evaluating if */
#define	IN_A_THEN	2	/* we are in the then portion */
#define	IN_AN_ELSE	4	/* we are in the else portion */
#define	IN_AN_ELIF_SKIP	8	/* we are in the elif (ignore conditional) */
#define	IF_IS_TRUE	16	/* the condition is true */

/*
 * Miscellaneous macros to set/test various "if/then/else" states
 */
#define ANY_IF_STATE 		(IN_A_CONDITION | \
				 IN_A_THEN | \
				 IN_AN_ELSE | \
				 IN_AN_ELIF_SKIP)

int	in_an_if = 0;			/* keeps track of if depth */
char	status_of_if[MAX_IF_DEPTH];	/* status and pos. of each if */

#include	<stdio.h>
#include	<fcntl.h>
#include	<sys/types.h>
#include	<sys/stat.h>
#include	<errno.h>
#include	<signal.h>
#include	<termio.h>
#include	"wish.h"
#include	"eval.h"
#include	"ctl.h"
#include	"moremacros.h"
#include 	"message.h"
#include  	"interrupt.h"
#include	"retcodes.h"	/* abs */
#include	"sizes.h"

extern void exit();		/* fmli's own exit routine */

/*
 * return value of lastly executed command within an "if" statement
 */ 
static int Lastret = SUCCESS;


#ifdef TEST
main(argc, argv)
char	*argv[];
{
	IOSTRUCT	*in, *out, *err;

	wish_init(argc, argv);
	in = io_open(EV_USE_FP, stdin);
	out = io_open(EV_USE_FP, stdout);
	err = io_open(EV_USE_FP, stderr);
	exit(evalargv(argc - 1, argv + 1, in, out, err));
}

mess_temp(s)
char	*s;
{
	fprintf(stderr, "%s\n", s);
}

mess_perm(s)
char	*s;
{
	fprintf(stderr, "%s\n", s);
}

#endif 

int	cmd_if();
int	cmd_elif();

int
cmd_fi(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	if (in_an_if <= 0) {
		mess_temp("Syntax error - \"fi\" with no pending \"if\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}
	if (((status_of_if[in_an_if] & IN_A_THEN) == 0) && 
	    ((status_of_if[in_an_if] & IN_AN_ELSE) == 0) && 
	    ((status_of_if[in_an_if] & IN_AN_ELIF_SKIP) == 0)) { 
		mess_temp("Syntax error - \"fi\" with no pending \"then\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	in_an_if--;

	if (argc > 1) {
		mess_temp("Syntax error - missing semi-colon after \"fi\" statement.");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	return(Lastret);
}

int
cmd_then(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	if (in_an_if <= 0) {
		mess_temp("Syntax error - \"then\" with no pending \"if\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (status_of_if[in_an_if] & IN_A_THEN) {
		mess_temp("Syntax error - \"then\" within \"then\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (status_of_if[in_an_if] & IN_AN_ELSE) {
		mess_temp("Syntax error - \"then\" within \"else\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (((status_of_if[in_an_if] & IN_A_CONDITION) == 0) &&
	    ((status_of_if[in_an_if] & IN_AN_ELIF_SKIP) == 0)) {
		mess_temp("Syntax error - \"then\" without a preceeding \"if\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	/*
	 * If we are in an "elif" but are NOT evaluating its condition
	 * statement(s) (i.e., a previous "if" condition already evauated
	 * to true) ... then just return SUCCESS;
	 */
	if (status_of_if[in_an_if] & IN_AN_ELIF_SKIP)
		return SUCCESS;

	status_of_if[in_an_if] &= ~(ANY_IF_STATE);
	status_of_if[in_an_if] &= ~(IN_A_CONDITION);
	status_of_if[in_an_if] |= IN_A_THEN;

	return SUCCESS;
}

int
cmd_else(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	if (in_an_if <= 0) {
		mess_temp("Syntax error - \"else\" with no pending \"if\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (status_of_if[in_an_if] & IN_AN_ELSE) {
		mess_temp("Syntax error - \"else\" within \"else\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (((status_of_if[in_an_if] & IN_A_THEN) == 0) &&  
	    ((status_of_if[in_an_if] & IN_AN_ELIF_SKIP) == 0)) {
		mess_temp("Syntax error - \"else\" with no pending \"then\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	status_of_if[in_an_if] &= ~(ANY_IF_STATE);
	status_of_if[in_an_if] |= IN_AN_ELSE;

	return SUCCESS;
}

int
shell(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	register int	i;
	register int	len;
	register char	*crunch;
	char	*myargv[4];
	char	*strnsave();

	len = 0;
	for (i = 1; i < argc; i++)
		len += strlen(argv[i]);
	crunch = strnsave(nil, len + argc - 1);
	for (i = 1; i < argc; i++) {
		strcat(crunch, " ");
		strcat(crunch, argv[i]);
	}
	myargv[0] = "sh";
	myargv[1] = "-c";
	myargv[2] = crunch;
	myargv[3] = NULL;
	i = execute(3, myargv, instr, outstr, errstr);
	free(crunch);
	return i;
}

int
execute(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
    register char	*p;
    register FILE       *errfp;
    register pid_t	pid;	/* EFT abs k16 */
    int	pfd[2];
    char	*strchr();
    unsigned char cc_vintr_sav = '\0';
    bool  changed_vintr = FALSE;

    if (strcmp(argv[0], "extern") == 0)
	argv++;
#ifdef _DEBUG2
    for (pid = 0; pid < argc; pid++)
	_debug2(stderr, "argv[%d] = '%s'\n", pid, argv[pid]);
#endif
    if (pipe(pfd))
	return FAIL;
    if (errstr == NULL)
	if ((errfp = fopen(p = tmpnam(NULL), "w+")) != NULL)
/*	if ((errfd = open(p = tmpnam(NULL), O_EXCL | O_CREAT | O_RDWR, 0600)) >= 0)
abs */
	    unlink(p);
	else
	    return FAIL;
    else
	errfp = errstr->mu.fp;

    switch (pid = fork()) {
    case -1:
	return FAIL;
    case 0:			/* child */
	close(pfd[0]);
	close(1);
	dup(pfd[1]);
	close(pfd[1]);
	close(2);
	dup(fileno(errfp));
	fclose(errfp);

    {
	if (instr->flags & EV_USE_FP) {
	    close(0);
	    dup(fileno(instr->mu.fp));
	}
	else if (instr->mu.str.count > 0) {
	    register int	c;
	    register FILE	*infp;
	    FILE	*tempfile();

	    if ((infp = tempfile(NULL, "w+")) == NULL)
		exit(1);
	    while (c = getac(instr))
		putc(c, infp);
	    close(0);
	    dup(fileno(infp));
	    fclose(infp);
	}
	if (Cur_intr.interrupt)   	/* if (interrupts enabled) */
	    sigset(SIGINT, SIG_DFL);
	else			        /* hide the interrupt key */
	{
	    struct termio  tbuf;

	    if (ioctl(stdin, TCGETA, &tbuf) != -1) /* if successful.. */
	    {
		
		cc_vintr_sav = tbuf.c_cc[VINTR];
		tbuf.c_cc[VINTR] = 0xff;
		if (ioctl(stdin, TCSETA, &tbuf) != -1)
		    changed_vintr = TRUE;
	    }
	}
	execvp(argv[0], argv);
	error_exec(errno);
	perror("fmli");
	exit(R_BAD_CHILD);	/* abs changed from exit(1).
				   This is fmli's exit not the C lib. call */
    }
	break;
    default:			/* parent (FMLI) */
    {
	register int	c;
	register int	retval;
	FILE	*fp;

	close(pfd[1]);
	if ((fp = fdopen(pfd[0], "r")) == NULL)
	    return FAIL;

	/* the errno == EINTR is added below to check for
	   system interrupts like MAILCHECK that were terminating
	   the read in progress -- added 7/89 by njp */
	while ((c = getc(fp)) != EOF || errno == EINTR)

	{
	    putac(c, outstr);
	    errno = 0;
	}
	fclose(fp);
	retval = waitspawn(pid);
/****
	if ((retval = waitspawn(pid)) && errfp != NULL && errstr != NULL)
	{
	    char	buf[MESSIZ];

	    if ((c = fread(buf, sizeof(char), MESSIZ-1, errfp)) > 0)
	    {
******/	    
/* for unknown reasons  this never worked (returns c = 0) abs
            if ((c = read(errfd, buf, sizeof(buf) - 1)) > 0) {
*/
/*****		buf[c] = '\0';
		if (p = strchr(buf, '\n'))
		    *p = '\0';
		mess_temp(buf);
	    }
	}
******/
	/* reset the interrupt key */
	if (changed_vintr == TRUE)
	{
	    struct termio  tbuf;

	    if (ioctl(stdin, TCGETA, &tbuf) != -1) /* if successful.. */
	    {
		tbuf.c_cc[VINTR] = cc_vintr_sav;
		ioctl(stdin, TCSETA, &tbuf);
	    }
	}

	if (errfp != NULL)
	    fclose(errfp);
	return retval;
    }
	break;
    }
    /*
     * lint will complain about it, but there's actually no way to
     * reach here because of the exit(), so this is not a return
     * without an expression
     */
    return (0);
}

int
get_wdw(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	int wdwnum;

	wdwnum = ar_ctl(ar_get_current(), CTGETWDW, NULL, NULL, NULL, NULL, NULL, NULL);
	putastr(itoa((long)wdwnum, 10), outstr); /* abs k16 */
	return SUCCESS;
}

int
getmod(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
    static mode_t modes;	/* EFT abs k16 */
    int i;
    struct stat	statbuf;
    long	strtol();
    char	*bsd_path_to_title();

    if (argc < 2)
	return FAIL;
    i = 1;
    if (argc > 2) {
	i++;
	if (strcmp(argv[1], "-u") == 0) {
	    register char	*p;
	    char	*getepenv();

	    if ((p = getepenv("UMASK")) == NULL || *p == '\0')
		modes = 0775;
	    else
		modes = ~(strtol(p, NULL, 8)) & 0777; 
	} else if (stat(argv[1], &statbuf) == -1) {
	    mess_temp(nstrcat("Could not access object ",
			      bsd_path_to_title(argv[1], MESS_COLS-24), NULL));
	    return FAIL;
	} else
	    modes = statbuf.st_mode;
    }
    if (strtol(argv[i], NULL, 8) & modes)
	putastr("yes", outstr);
    else
	putastr("no", outstr);
    return SUCCESS;
}

int
setmod(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
    register int	i;
    register mode_t	mode;	/* EFT abs k16 */
    char *bsd_path_to_title();

    if (argc < 2)
	return FAIL;
    for (i = 2, mode = 0; argv[i]; i++)
	mode = (mode << 1) | !strCcmp(argv[i], "yes");

    if ((mode & 0600) != 0600)
	mess_temp("WARNING: You are denying some permissions to yourself!");

    if (strcmp(argv[1], "-u") == 0) {
	char buf[20];

	mode = ~mode & 0777;
	(void) umask(mode);
	sprintf(buf, "0%o", mode);
	return chgepenv("UMASK", buf);
    } else if (chmod(argv[1], mode) < 0) {
	mess_temp(nstrcat("Unable to change security on ",
			  bsd_path_to_title(argv[1], MESS_COLS-29), NULL));
	return(FAIL);
    } else
	return SUCCESS;
}

int Long_line = -1;

int
long_line(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	register int maxcount, c, count;
	FILE *fp;

	if (argv[1]) {		/* if there is a file argument */
		if ((fp = fopen(argv[1], "r")) == NULL)
			return(FAIL);
		for (maxcount = 0, count = 0; (c = getc(fp)) != EOF; count++) {
			if (c == '\n') {
				maxcount = max(maxcount, count);
				count = -1;
			}
		}
		fclose(fp);
		Long_line = max(maxcount, count);
	}
	else if (Long_line < 0)
		return(FAIL);
	putastr(itoa((long)Long_line + 1, 10), outstr);	/* abs k16 */
	return SUCCESS;
}

int
read_file(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	char	*p, *f;
	register int c, count, maxcount;
	FILE	*fp;
	char	*path_to_full();

	if (argc > 1)
		f = path_to_full(argv[1]);
	else {
		f = path_to_full(p = io_string(instr));
		free(p);
	}
	if ((fp = fopen(f, "r")) == NULL)
		return(FAIL);
	free(f);
	for (count = 0, maxcount = 0; (c = getc(fp)) != EOF; count++) {
		if (c == '\n') {
			maxcount = max(maxcount, count);
			count = -1;
		}
		putac(c, outstr);
	}
	Long_line = max(maxcount, count);
	fclose(fp);
	return SUCCESS;
}

int
cmd_echo(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	register char	*p;
	register int	i;
	char	*strrchr();

	for (i = 1; i < argc; i++) {
		if (i > 1)
			putac(' ', outstr);
		if (i == argc - 1 && (p = strrchr(argv[i], '\\')) && strcmp(p, "\\c'") == 0) {
			*p = '\0';
			putastr(argv[i], outstr);
			return SUCCESS;
		}
		putastr(argv[i], outstr);
	}
	putac('\n', outstr);
	return SUCCESS;
}

#ifndef TEST
extern int	cocreate();
extern int	cosend();
extern int	codestroy();
extern int	cocheck();
extern int	coreceive();
extern int	genfind();
extern int	cmd_pathconv();
#endif 
extern int	cmd_set();
extern int	cmd_run();
extern int	cmd_regex();
extern int	cmd_getlist();
extern int	cmd_setcolor();
extern int	cmd_reinit();
extern int	cmd_message();
extern int	cmd_indicator();
extern int	cmd_unset();
extern int	cmd_getodi();
extern int	cmd_setodi();
extern int	cmd_cut();
extern int	cmd_grep();
extern int	cmd_test();		/* ehr3 */
extern int	cmd_expr();

#define NUM_FUNCS	(sizeof(func) / sizeof(*func))

static struct {
	char	*name;
	int	(*function)();
} func[] = {
	{ "extern",	execute },
	{ "shell",	shell },
	{ "regex",	cmd_regex },
	{ "echo",	cmd_echo },
	{ "fmlcut",	cmd_cut },
	{ "fmlgrep",	cmd_grep },
	{ "fmlexpr",	cmd_expr },
	{ "set",	cmd_set },
	{ "unset",	cmd_unset },
	{ "getmod",	getmod },
	{ "getodi",	cmd_getodi },
	{ "getfrm",	get_wdw },
	{ "getwdw",	get_wdw },	/* alias to getfrm */
	{ "setmod",	setmod },
	{ "setodi",	cmd_setodi },
	{ "readfile",	read_file },
	{ "longline",	long_line },
	{ "message",	cmd_message },
	{ "indicator", 	cmd_indicator },
	{ "run",	cmd_run },
	{ "getitems",	cmd_getlist },
	{ "genfind",	genfind },
	{ "pathconv",	cmd_pathconv },
	{ "setcolor",	cmd_setcolor},
	{ "reinit",	cmd_reinit},
	{ "test",	cmd_test},	/* ehr3 */
	{ "[",		cmd_test},	/* ehr3 */
	{ "if",		cmd_if},	/* ehr3 */
	{ "then",	cmd_then},	/* ehr3 */
	{ "else",	cmd_else},	/* ehr3 */
	{ "elif",	cmd_elif},	/* ehr3 */
	{ "fi",		cmd_fi},	/* ehr3 */
/*
 * not yet ...
 *
	{ "true",	cmd_true},
	{ "false",	cmd_false},
 */
#ifndef TEST
	{ "cocreate",	cocreate },
	{ "cosend",	cosend },
	{ "codestroy",	codestroy },
	{ "cocheck",	cocheck },
	{ "coreceive",	coreceive }
#endif 
};

int
evalargv(argc, argv, instr, outstr, errstr)
int	argc;
char	*argv[];
IOSTRUCT	*instr;
IOSTRUCT	*outstr;
IOSTRUCT	*errstr;
{
	register int	n, ret;
	int	n2;

/*	test moved to calling routine, SUCCESS is wrong here. abs
 *	if (argc < 1)
 *		return SUCCESS;
 */

	for (n = 0; n < NUM_FUNCS; n++)
		if (strcmp(argv[0], func[n].name) == 0)
			break;

	if (n >= NUM_FUNCS)
		n = 0;

	if (in_an_if) {
		switch(argv[0][0]) {
			case 'i':
				if (!strcmp(argv[0], "if")) {
					ret = cmd_if(argc, argv, instr, outstr);
					return ret;
				}
				break;

			case 't':
				if (!strcmp(argv[0], "then")) {
					ret = cmd_then(argc, argv, instr, outstr);
					return ret;
				}
				break;

			case 'e':
				if (!strcmp(argv[0], "else")) {
					ret = cmd_else(argc, argv, instr, outstr);
					return ret;
				}

				if (!strcmp(argv[0], "elif")) {
					ret = cmd_elif(argc, argv, instr, outstr);
					return ret;
				}
				break;

			case 'f':
				if (!strcmp(argv[0], "fi")) {
					ret = cmd_fi(argc, argv, instr, outstr);
					return ret;
				}
				break;
		}

		/*
			AFTER checking for if-then-else stuff 
			we need to determine if we are in 
			executable code or not. We do this by 
			checking each prior level of nesting. 
			If any of them fails, then we know 
			we should not execute this command.
		*/
		for (n2 = 1; n2 <= in_an_if; n2++) {
			if (status_of_if[n2] & IF_IS_TRUE) {
				/*
				 * The condition is TRUE ...
				 * skip the command if:
				 *
				 * we are in an "else"
				 *
				 * we are in an "elif" but a previous
				 * "if" or "elif" evaluated to true
				 */
				if ((status_of_if[n2] & IN_AN_ELSE) ||
				    (status_of_if[n2] & IN_AN_ELIF_SKIP)) 
					return SUCCESS;
			} else {
				/*
				 * The condition is FALSE ...
				 * skip the command if we are in
				 * a "then"
				 */
				if (status_of_if[n2] & IN_A_THEN)
					return SUCCESS;
			}
		}

		if (status_of_if[in_an_if] & IN_A_CONDITION) {
			int	cmd_rc;

			cmd_rc = (*func[n].function)(argc, argv, instr, outstr, errstr);
			if (cmd_rc == SUCCESS)
				status_of_if[in_an_if] |= IF_IS_TRUE;
			else 
				status_of_if[in_an_if] &= ~IF_IS_TRUE;
			return(cmd_rc);
		} else {
			/*
			 * Keep track of the return value from the
			 * lastly executed built-in/executable ...
			 * This value will determine the SUCCESS/FAILURE
			 * of the if/then/else statement (see cmd_fi).
			 */
			Lastret = (*func[n].function)(argc, argv, instr, outstr, errstr);
			return(Lastret);
		}
	}
	else return (*func[n].function)(argc, argv, instr, outstr, errstr);
}

int
cmd_if(argc, argv, in, out, err)
int	argc;
char	*argv[];
IOSTRUCT	*in;
IOSTRUCT	*out;
IOSTRUCT	*err;
{
	int	n;
	int	n2;

	in_an_if++;
	status_of_if[in_an_if] = IN_A_CONDITION;

	if (in_an_if == MAX_IF_DEPTH) {
		mess_temp("Internal error - \"if\" stack overflow");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	return SUCCESS;
}

int
cmd_elif(argc, argv, in, out, err)
int	argc;
char	*argv[];
IOSTRUCT	*in;
IOSTRUCT	*out;
IOSTRUCT	*err;
{
	int	n;
	int	n2;

	if (in_an_if <= 0) {
		mess_temp("Syntax error - \"elif\" with no pending \"if\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (status_of_if[in_an_if] & IN_AN_ELSE) {
		mess_temp("Syntax error - \"elif\" after an \"else\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}

	if (((status_of_if[in_an_if] & IN_A_THEN) == 0) &&  
	    ((status_of_if[in_an_if] & IN_AN_ELIF_SKIP) == 0)) {
		mess_temp("Syntax error - \"elif\" with no pending \"then\"");
		mess_lock();
		in_an_if = 0;
		return FAIL;
	}


	/*
	 * if a previous "if/elif" condition is TRUE 
	 * then don't evaluate the "elif" condition.
	 */
	
	if (status_of_if[in_an_if] & IF_IS_TRUE) {
		status_of_if[in_an_if] &= ~(ANY_IF_STATE);
		status_of_if[in_an_if] |= IN_AN_ELIF_SKIP;
	}
	else 
		status_of_if[in_an_if] = IN_A_CONDITION; 

	return SUCCESS;
}

/*
 * not yet ...
 *
cmd_true(argc, argv, in, out, err)
int	argc;
char	*argv[];
IOSTRUCT	*in;
IOSTRUCT	*out;
IOSTRUCT	*err;
{
	return(SUCCESS);
}

cmd_false(argc, argv, in, out, err)
int	argc;
char	*argv[];
IOSTRUCT	*in;
IOSTRUCT	*out;
IOSTRUCT	*err;
{
	return(FAIL);
}
*/
