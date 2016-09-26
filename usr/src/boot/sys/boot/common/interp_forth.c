/*-
 * Copyright (c) 1998 Michael Smith <msmith@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>

#include <sys/param.h>		/* to pick up __FreeBSD_version */
#include <string.h>
#include <stand.h>
#include "bootstrap.h"
#include "ficl.h"

extern char bootprog_rev[];

/* #define BFORTH_DEBUG */

#ifdef BFORTH_DEBUG
# define DEBUG(fmt, args...)	printf("%s: " fmt "\n" , __func__ , ## args)
#else
# define DEBUG(fmt, args...)
#endif

/*
 * Eventually, all builtin commands throw codes must be defined
 * elsewhere, possibly bootstrap.h. For now, just this code, used
 * just in this file, it is getting defined.
 */
#define BF_PARSE 100

/*
 * FreeBSD loader default dictionary cells
 */
#ifndef	BF_DICTSIZE
#define	BF_DICTSIZE	30000
#endif

/*
 * BootForth   Interface to Ficl Forth interpreter.
 */

ficlSystemInformation *fsi;
ficlSystem *bf_sys;
ficlVm	*bf_vm;
ficlWord *pInterp;

/*
 * Shim for taking commands from BF and passing them out to 'standard'
 * argv/argc command functions.
 */
static void
bf_command(ficlVm *vm)
{
    char			*name, *line, *tail, *cp;
    size_t			len;
    struct bootblk_command	**cmdp;
    bootblk_cmd_t		*cmd;
    int				nstrings, i;
    int				argc, result;
    char			**argv;

    /* Get the name of the current word */
    name = vm->runningWord->name;
    
    /* Find our command structure */
    cmd = NULL;
    SET_FOREACH(cmdp, Xcommand_set) {
	if (((*cmdp)->c_name != NULL) && !strcmp(name, (*cmdp)->c_name))
	    cmd = (*cmdp)->c_fn;
    }
    if (cmd == NULL)
	panic("callout for unknown command '%s'", name);

    /* Check whether we have been compiled or are being interpreted */
    if (ficlStackPopInteger(ficlVmGetDataStack(vm))) {
	/*
	 * Get parameters from stack, in the format:
	 * an un ... a2 u2 a1 u1 n --
	 * Where n is the number of strings, a/u are pairs of
	 * address/size for strings, and they will be concatenated
	 * in LIFO order.
	 */
	nstrings = ficlStackPopInteger(ficlVmGetDataStack(vm));
	for (i = 0, len = 0; i < nstrings; i++)
	    len += ficlStackFetch(ficlVmGetDataStack(vm), i * 2).i + 1;
	line = malloc(strlen(name) + len + 1);
	strcpy(line, name);

	if (nstrings)
	    for (i = 0; i < nstrings; i++) {
		len = ficlStackPopInteger(ficlVmGetDataStack(vm));
		cp = ficlStackPopPointer(ficlVmGetDataStack(vm));
		strcat(line, " ");
		strncat(line, cp, len);
	    }
    } else {
	/* Get remainder of invocation */
	tail = ficlVmGetInBuf(vm);

	for (cp = tail, len = 0; cp != vm->tib.end && *cp != 0 && *cp != '\n'; cp++, len++)
	    ;

	line = malloc(strlen(name) + len + 2);
	strcpy(line, name);
	if (len > 0) {
	    strcat(line, " ");
	    strncat(line, tail, len);
	    ficlVmUpdateTib(vm, tail + len);
	}
    }
    DEBUG("cmd '%s'", line);

    command_errmsg = command_errbuf;
    command_errbuf[0] = 0;
    if (!parse(&argc, &argv, line)) {
	result = (cmd)(argc, argv);
	free(argv);
    } else {
	result=BF_PARSE;
    }

    switch (result) {
    case CMD_CRIT:
	printf("%s\n", command_errmsg);
	break;
    case CMD_FATAL:
	panic("%s\n", command_errmsg);
    }

    free(line);
    /*
     * If there was error during nested ficlExec(), we may no longer have
     * valid environment to return.  Throw all exceptions from here.
     */
    if (result != CMD_OK)
	ficlVmThrow(vm, result);

    /* This is going to be thrown!!! */
    ficlStackPushInteger(ficlVmGetDataStack(vm),result);
}

/*
 * Replace a word definition (a builtin command) with another
 * one that:
 *
 *        - Throw error results instead of returning them on the stack
 *        - Pass a flag indicating whether the word was compiled or is
 *          being interpreted.
 *
 * There is one major problem with builtins that cannot be overcome
 * in anyway, except by outlawing it. We want builtins to behave
 * differently depending on whether they have been compiled or they
 * are being interpreted. Notice that this is *not* the interpreter's
 * current state. For example:
 *
 * : example ls ; immediate
 * : problem example ;		\ "ls" gets executed while compiling
 * example			\ "ls" gets executed while interpreting
 *
 * Notice that, though the current state is different in the two
 * invocations of "example", in both cases "ls" has been
 * *compiled in*, which is what we really want.
 *
 * The problem arises when you tick the builtin. For example:
 *
 * : example-1 ['] ls postpone literal ; immediate
 * : example-2 example-1 execute ; immediate
 * : problem example-2 ;
 * example-2
 *
 * We have no way, when we get EXECUTEd, of knowing what our behavior
 * should be. Thus, our only alternative is to "outlaw" this. See RFI
 * 0007, and ANS Forth Standard's appendix D, item 6.7 for a related
 * problem, concerning compile semantics.
 *
 * The problem is compounded by the fact that "' builtin CATCH" is valid
 * and desirable. The only solution is to create an intermediary word.
 * For example:
 *
 * : my-ls ls ;
 * : example ['] my-ls catch ;
 *
 * So, with the below implementation, here is a summary of the behavior
 * of builtins:
 *
 * ls -l				\ "interpret" behavior, ie,
 *					\ takes parameters from TIB
 * : ex-1 s" -l" 1 ls ;			\ "compile" behavior, ie,
 *					\ takes parameters from the stack
 * : ex-2 ['] ls catch ; immediate	\ undefined behavior
 * : ex-3 ['] ls catch ;		\ undefined behavior
 * ex-2 ex-3				\ "interpret" behavior,
 *					\ catch works
 * : ex-4 ex-2 ;			\ "compile" behavior,
 *					\ catch does not work
 * : ex-5 ex-3 ; immediate		\ same as ex-2
 * : ex-6 ex-3 ;			\ same as ex-3
 * : ex-7 ['] ex-1 catch ;		\ "compile" behavior,
 *					\ catch works
 * : ex-8 postpone ls ;	immediate	\ same as ex-2
 * : ex-9 postpone ls ;			\ same as ex-3
 *
 * As the definition below is particularly tricky, and it's side effects
 * must be well understood by those playing with it, I'll be heavy on
 * the comments.
 *
 * (if you edit this definition, pay attention to trailing spaces after
 *  each word -- I warned you! :-) )
 */
#define BUILTIN_CONSTRUCTOR \
": builtin: "		\
  ">in @ "		/* save the tib index pointer */ \
  "' "			/* get next word's xt */ \
  "swap >in ! "		/* point again to next word */ \
  "create "		/* create a new definition of the next word */ \
  ", "			/* save previous definition's xt */ \
  "immediate "		/* make the new definition an immediate word */ \
			\
  "does> "		/* Now, the *new* definition will: */ \
  "state @ if "		/* if in compiling state: */ \
    "1 postpone literal "	/* pass 1 flag to indicate compile */ \
    "@ compile, "		/* compile in previous definition */ \
    "postpone throw "		/* throw stack-returned result */ \
  "else "		/* if in interpreting state: */ \
    "0 swap "			/* pass 0 flag to indicate interpret */ \
    "@ execute "		/* call previous definition */ \
    "throw "			/* throw stack-returned result */ \
  "then ; "

/*
 * Initialise the Forth interpreter, create all our commands as words.
 */
void
bf_init(char *rc)
{
    struct bootblk_command	**cmdp;
    char create_buf[41];	/* 31 characters-long builtins */
    int fd, rv;
    ficlDictionary *dict;
    ficlDictionary *env;

    fsi = malloc(sizeof(ficlSystemInformation));
    ficlSystemInformationInitialize(fsi);
    fsi->dictionarySize = BF_DICTSIZE;

    bf_sys = ficlSystemCreate(fsi);
    bf_vm = ficlSystemCreateVm(bf_sys);

    /* Put all private definitions in a "builtins" vocabulary */
    rv = ficlVmEvaluate(bf_vm, "vocabulary builtins also builtins definitions");
    if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
	panic("error interpreting forth: %d\n", rv);
    }

    /* Builtin constructor word  */
    rv = ficlVmEvaluate(bf_vm, BUILTIN_CONSTRUCTOR);
    if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
	panic("error interpreting forth: %d\n", rv);
    }

    /* make all commands appear as Forth words */
    dict = ficlSystemGetDictionary(bf_sys);
    SET_FOREACH(cmdp, Xcommand_set) {
	ficlDictionaryAppendPrimitive(dict, (char *)(*cmdp)->c_name,
		bf_command, FICL_WORD_DEFAULT);
	rv = ficlVmEvaluate(bf_vm, "forth definitions builtins");
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		panic("error interpreting forth: %d\n", rv);
	}
	sprintf(create_buf, "builtin: %s", (*cmdp)->c_name);
	rv = ficlVmEvaluate(bf_vm, create_buf);
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		panic("error interpreting forth: %d\n", rv);
	}
	rv = ficlVmEvaluate(bf_vm, "builtins definitions");
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		panic("error interpreting forth: %d\n", rv);
	}
    }
    rv = ficlVmEvaluate(bf_vm, "only forth definitions");
    if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
	panic("error interpreting forth: %d\n", rv);
    }

    /*
     * Export some version numbers so that code can detect the loader/host
     * version
     */
    env = ficlSystemGetEnvironment(bf_sys);
    ficlDictionarySetConstant(env, "loader_version",
	       (bootprog_rev[0] - '0') * 10 + (bootprog_rev[2] - '0'));

    pInterp = ficlSystemLookup(bf_sys, "interpret");

    /* try to load and run init file if present */
    if (rc == NULL)
	rc = "/boot/forth/boot.4th";
    if (*rc != '\0') {
	fd = open(rc, O_RDONLY);
	if (fd != -1) {
	    (void)ficlExecFD(bf_vm, fd);
	    close(fd);
	}
    }

    /* Do this again, so that interpret can be redefined. */
    pInterp = ficlSystemLookup(bf_sys, "interpret");
}

/*
 * Feed a line of user input to the Forth interpreter
 */
int
bf_run(char *line)
{
    int		result;
    ficlString s;

    FICL_STRING_SET_FROM_CSTRING(s, line);
    result = ficlVmExecuteString(bf_vm, s);

    DEBUG("ficlExec '%s' = %d", line, result);
    switch (result) {
    case FICL_VM_STATUS_OUT_OF_TEXT:
    case FICL_VM_STATUS_ABORTQ:
    case FICL_VM_STATUS_QUIT:
    case FICL_VM_STATUS_ERROR_EXIT:
	break;
    case FICL_VM_STATUS_USER_EXIT:
	printf("No where to leave to!\n");
	break;
    case FICL_VM_STATUS_ABORT:
	printf("Aborted!\n");
	break;
    case BF_PARSE:
	printf("Parse error!\n");
	break;
    default:
	if (command_errmsg != NULL) {
	    printf("%s\n", command_errmsg);
	    command_errmsg = NULL;
	}
    }

    /* bye is same as reboot and will behave depending on platform */
    if (result == FICL_VM_STATUS_USER_EXIT)
	bf_run("reboot");
    setenv("interpret", bf_vm->state ? "" : "ok", 1);

    return (result);
}
