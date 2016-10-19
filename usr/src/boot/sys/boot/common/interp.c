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
__FBSDID("$FreeBSD$");

/*
 * Simple commandline interpreter, toplevel and misc.
 *
 * XXX may be obsoleted by BootFORTH or some other, better, interpreter.
 */

#include <stand.h>
#include <string.h>
#include "bootstrap.h"

#ifdef BOOT_FORTH
#include "ficl.h"
#define	RETURN(x)	ficlStackPushInteger(ficlVmGetDataStack(bf_vm),!x); return(x)

extern ficlVm *bf_vm;
#else
#define	RETURN(x)	return(x)
#endif

#include "linenoise/linenoise.h"

#define	MAXARGS	20		/* maximum number of arguments allowed */

static char *prompt(void);

#ifndef BOOT_FORTH
static int	perform(int argc, char *argv[]);

/*
 * Perform the command
 */
int
perform(int argc, char *argv[])
{
    int				result;
    struct bootblk_command	**cmdp;
    bootblk_cmd_t		*cmd;

    if (argc < 1)
	return(CMD_OK);

    /* set return defaults; a successful command will override these */
    command_errmsg = command_errbuf;
    strcpy(command_errbuf, "no error message");
    cmd = NULL;
    result = CMD_ERROR;

    /* search the command set for the command */
    SET_FOREACH(cmdp, Xcommand_set) {
	if (((*cmdp)->c_name != NULL) && !strcmp(argv[0], (*cmdp)->c_name))
	    cmd = (*cmdp)->c_fn;
    }
    if (cmd != NULL) {
	result = (cmd)(argc, argv);
    } else {
	command_errmsg = "unknown command";
    }
    RETURN(result);
}
#endif	/* ! BOOT_FORTH */

/*
 * Interactive mode
 */
void
interact(const char *rc)
{
    char *input = NULL;

    bf_init((rc) ? "" : NULL);

    if (rc == NULL) {
	/* Read our default configuration. */
	include("/boot/loader.rc");
    } else if (*rc != '\0')
	include(rc);

    printf("\n");

    /*
     * Before interacting, we might want to autoboot.
     */
    autoboot_maybe();
    
    /*
     * Not autobooting, go manual
     */
    printf("\nType '?' for a list of commands, 'help' for more detailed help.\n");
    if (getenv("prompt") == NULL)
	setenv("prompt", "${interpret}", 1);
    if (getenv("interpret") == NULL)
        setenv("interpret", "ok", 1);
    

    while ((input = linenoise(prompt())) != NULL) {
	bf_vm->sourceId.i = 0;
	bf_run(input);
	linenoiseHistoryAdd(input);
	free(input);
    }
}

/*
 * Read commands from a file, then execute them.
 *
 * We store the commands in memory and close the source file so that the media
 * holding it can safely go away while we are executing.
 *
 * Commands may be prefixed with '@' (so they aren't displayed) or '-' (so
 * that the script won't stop if they fail).
 */
COMMAND_SET(include, "include", "read commands from a file", command_include);

static int
command_include(int argc, char *argv[])
{
    int		i;
    int		res;
    char	**argvbuf;

    /* 
     * Since argv is static, we need to save it here.
     */
    argvbuf = (char**) calloc((u_int)argc, sizeof(char*));
    for (i = 0; i < argc; i++)
	argvbuf[i] = strdup(argv[i]);

    res=CMD_OK;
    for (i = 1; (i < argc) && (res == CMD_OK); i++)
	res = include(argvbuf[i]);

    for (i = 0; i < argc; i++)
	free(argvbuf[i]);
    free(argvbuf);

    return(res);
}

/*
 * Header prepended to each line. The text immediately follows the header.
 * We try to make this short in order to save memory -- the loader has
 * limited memory available, and some of the forth files are very long.
 */
struct includeline 
{
    struct includeline  *next;
    int                 line;
    char                text[0];
};

/*
 * The PXE TFTP service allows opening exactly one connection at the time,
 * so we need to read included file into memory, then process line by line
 * as it may contain embedded include commands.
 */
int
include(const char *filename)
{
    struct includeline  *script, *se, *sp;
    int res = CMD_OK;
    int	prevsrcid, fd, line;
    char *cp, input[256];		/* big enough? */

    if (((fd = open(filename, O_RDONLY)) == -1)) {
	snprintf(command_errbuf, sizeof (command_errbuf), "can't open '%s': %s",
	    filename, strerror(errno));
	return(CMD_ERROR);
    }
    /*
     * Read the script into memory.
     */
    script = se = NULL;
    line = 0;

    while (fgetstr(input, sizeof(input), fd) >= 0) {
	line++;
	cp = input;
	/* Allocate script line structure and copy line, flags */
	if (*cp == '\0')
		continue;       /* ignore empty line, save memory */
	if (cp[0] == '\\' && cp[1] == ' ')
		continue;	/* ignore comment */

	sp = malloc(sizeof(struct includeline) + strlen(cp) + 1);
	/* On malloc failure (it happens!), free as much as possible and exit */
	if (sp == NULL) {
		while (script != NULL) {
			se = script;
			script = script->next;
			free(se);
		}
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "file '%s' line %d: memory allocation failure - aborting",
		    filename, line);
		close(fd);
		return (CMD_ERROR);
	}
	strcpy(sp->text, cp);
	sp->line = line;
	sp->next = NULL;

	if (script == NULL) {
		script = sp;
	} else {
		se->next = sp;
	}
	se = sp;
    }
    close(fd);

    /*
     * Execute the script
     */

    prevsrcid = bf_vm->sourceId.i;
    bf_vm->sourceId.i = fd+1;	/* 0 is user input device */

    res = CMD_OK;

    for (sp = script; sp != NULL; sp = sp->next) {
	res = bf_run(sp->text);
	if (res != FICL_VM_STATUS_OUT_OF_TEXT) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "Error while including %s, in the line %d:\n%s",
		    filename, sp->line, sp->text);
		res = CMD_ERROR;
		break;
	} else
		res = CMD_OK;
    }

    bf_vm->sourceId.i = -1;
    (void) bf_run("");
    bf_vm->sourceId.i = prevsrcid;

    while(script != NULL) {
	se = script;
	script = script->next;
	free(se);
    }

    return(res);
}

/*
 * Emit the current prompt; use the same syntax as the parser
 * for embedding environment variables.
 */
static char *
prompt(void)
{
    static char promptbuf[20];	/* probably too large, but well... */
    char	*pr, *p, *cp, *ev;
    int n = 0;

    if ((cp = getenv("prompt")) == NULL)
	cp = (char *)(uintptr_t)">";
    pr = p = strdup(cp);

    while (*p != 0) {
	if ((*p == '$') && (*(p+1) == '{')) {
	    for (cp = p + 2; (*cp != 0) && (*cp != '}'); cp++)
		;
	    *cp = 0;
	    ev = getenv(p + 2);

	    if (ev != NULL)
		n = sprintf(promptbuf+n, "%s", ev);
	    p = cp + 1;
	    continue;
	}
	promptbuf[n++] = *p;
	p++;
    }
    if (promptbuf[n - 1] != ' ')
	promptbuf[n++] = ' ';
    promptbuf[n] = '\0';
    free(pr);
    return (promptbuf);
}
