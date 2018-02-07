/*
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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <macros.h>
#include <sys/systeminfo.h>
#include <sys/queue.h>
#include <sys/mnttab.h>
#include "ficl.h"

/* Commands and return values; nonzero return sets command_errmsg != NULL */
typedef int (bootblk_cmd_t)(int argc, char *argv[]);
#define	CMD_OK		0
#define	CMD_ERROR	1

/*
 * Support for commands
 */
struct bootblk_command
{
	const char *c_name;
	const char *c_desc;
	bootblk_cmd_t *c_fn;
	STAILQ_ENTRY(bootblk_command) next;
};

#define	MDIR_REMOVED	0x0001
#define	MDIR_NOHINTS	0x0002

struct moduledir {
	char	*d_path;	/* path of modules directory */
	uchar_t	*d_hints;	/* content of linker.hints file */
	int	d_hintsz;	/* size of hints data */
	int	d_flags;
	STAILQ_ENTRY(moduledir) d_link;
};
static STAILQ_HEAD(, moduledir) moduledir_list =
    STAILQ_HEAD_INITIALIZER(moduledir_list);

static const char *default_searchpath = "/platform/i86pc";

static char typestr[] = "?fc?d?b? ?l?s?w";
static int	ls_getdir(char **pathp);
extern char **_environ;

char	*command_errmsg;
char	command_errbuf[256];

extern void pager_open(void);
extern void pager_close(void);
extern int pager_output(const char *);
extern int pager_file(const char *);
static int page_file(char *);
static int include(const char *);

static int command_help(int argc, char *argv[]);
static int command_commandlist(int argc, char *argv[]);
static int command_show(int argc, char *argv[]);
static int command_set(int argc, char *argv[]);
static int command_setprop(int argc, char *argv[]);
static int command_unset(int argc, char *argv[]);
static int command_echo(int argc, char *argv[]);
static int command_read(int argc, char *argv[]);
static int command_more(int argc, char *argv[]);
static int command_ls(int argc, char *argv[]);
static int command_include(int argc, char *argv[]);
static int command_autoboot(int argc, char *argv[]);
static int command_boot(int argc, char *argv[]);
static int command_unload(int argc, char *argv[]);
static int command_load(int argc, char *argv[]);
static int command_reboot(int argc, char *argv[]);

#define	BF_PARSE	100
#define	BF_DICTSIZE	30000

/* update when loader version will change */
static const char bootprog_rev[] = "1.1";
STAILQ_HEAD(cmdh, bootblk_command) commands;

/*
 * BootForth   Interface to Ficl Forth interpreter.
 */

ficlSystem *bf_sys;
ficlVm	*bf_vm;

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * Jordan K. Hubbard
 * 29 August 1998
 *
 * The meat of the simple parser.
 */

static void	 clean(void);
static int	 insert(int *argcp, char *buf);

#define	PARSE_BUFSIZE	1024	/* maximum size of one element */
#define	MAXARGS		20	/* maximum number of elements */
static	char		*args[MAXARGS];

#define	DIGIT(x)	\
	(isdigit(x) ? (x) - '0' : islower(x) ? (x) + 10 - 'a' : (x) + 10 - 'A')

/*
 * backslash: Return malloc'd copy of str with all standard "backslash
 * processing" done on it.  Original can be free'd if desired.
 */
char *
backslash(char *str)
{
	/*
	 * Remove backslashes from the strings. Turn \040 etc. into a single
	 * character (we allow eight bit values). Currently NUL is not
	 * allowed.
	 *
	 * Turn "\n" and "\t" into '\n' and '\t' characters. Etc.
	 */
	char *new_str;
	int seenbs = 0;
	int i = 0;

	if ((new_str = strdup(str)) == NULL)
		return (NULL);

	while (*str) {
		if (seenbs) {
			seenbs = 0;
			switch (*str) {
			case '\\':
				new_str[i++] = '\\';
				str++;
			break;

			/* preserve backslashed quotes, dollar signs */
			case '\'':
			case '"':
			case '$':
				new_str[i++] = '\\';
				new_str[i++] = *str++;
			break;

			case 'b':
				new_str[i++] = '\b';
				str++;
			break;

			case 'f':
				new_str[i++] = '\f';
				str++;
			break;

			case 'r':
				new_str[i++] = '\r';
				str++;
			break;

			case 'n':
				new_str[i++] = '\n';
				str++;
			break;

			case 's':
				new_str[i++] = ' ';
				str++;
			break;

			case 't':
				new_str[i++] = '\t';
				str++;
			break;

			case 'v':
				new_str[i++] = '\13';
				str++;
			break;

			case 'z':
				str++;
			break;

			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9': {
				char val;

				/* Three digit octal constant? */
				if (*str >= '0' && *str <= '3' &&
				    *(str + 1) >= '0' && *(str + 1) <= '7' &&
				    *(str + 2) >= '0' && *(str + 2) <= '7') {

					val = (DIGIT(*str) << 6) +
					    (DIGIT(*(str + 1)) << 3) +
					    DIGIT(*(str + 2));

					/*
					 * Allow null value if user really
					 * wants to shoot at feet, but beware!
					 */
					new_str[i++] = val;
					str += 3;
					break;
				}

				/*
				 * One or two digit hex constant?
				 * If two are there they will both be taken.
				 * Use \z to split them up if this is not
				 * wanted.
				 */
				if (*str == '0' &&
				    (*(str + 1) == 'x' || *(str + 1) == 'X') &&
				    isxdigit(*(str + 2))) {
					val = DIGIT(*(str + 2));
					if (isxdigit(*(str + 3))) {
						val = (val << 4) +
						    DIGIT(*(str + 3));
						str += 4;
					} else
						str += 3;
					/* Yep, allow null value here too */
					new_str[i++] = val;
					break;
				}
			}
			break;

			default:
				new_str[i++] = *str++;
			break;
			}
		} else {
			if (*str == '\\') {
				seenbs = 1;
				str++;
			} else
				new_str[i++] = *str++;
		}
	}

	if (seenbs) {
		/*
		 * The final character was a '\'.
		 * Put it in as a single backslash.
		 */
		new_str[i++] = '\\';
	}
	new_str[i] = '\0';
	return (new_str);
}

/*
 * parse: accept a string of input and "parse" it for backslash
 * substitutions and environment variable expansions (${var}),
 * returning an argc/argv style vector of whitespace separated
 * arguments.  Returns 0 on success, 1 on failure (ok, ok, so I
 * wimped-out on the error codes! :).
 *
 * Note that the argv array returned must be freed by the caller, but
 * we own the space allocated for arguments and will free that on next
 * invocation.  This allows argv consumers to modify the array if
 * required.
 *
 * NB: environment variables that expand to more than one whitespace
 * separated token will be returned as a single argv[] element, not
 * split in turn.  Expanded text is also immune to further backslash
 * elimination or expansion since this is a one-pass, non-recursive
 * parser.  You didn't specify more than this so if you want more, ask
 * me. - jkh
 */

#define	PARSE_FAIL(expr)	\
if (expr) { \
    printf("fail at line %d\n", __LINE__); \
    clean(); \
    free(copy); \
    free(buf); \
    return (1); \
}

/* Accept the usual delimiters for a variable, returning counterpart */
static char
isdelim(int ch)
{
	if (ch == '{')
		return ('}');
	else if (ch == '(')
		return (')');
	return ('\0');
}

static int
isquote(int ch)
{
	return (ch == '\'');
}

static int
isdquote(int ch)
{
	return (ch == '"');
}

int
parse(int *argc, char ***argv, char *str)
{
	int ac;
	char *val, *p, *q, *copy = NULL;
	size_t i = 0;
	char token, tmp, quote, dquote, *buf;
	enum { STR, VAR, WHITE } state;

	ac = *argc = 0;
	dquote = quote = 0;
	if (!str || (p = copy = backslash(str)) == NULL)
		return (1);

	/* Initialize vector and state */
	clean();
	state = STR;
	buf = (char *)malloc(PARSE_BUFSIZE);
	token = 0;

	/* And awaaaaaaaaay we go! */
	while (*p) {
		switch (state) {
		case STR:
			if ((*p == '\\') && p[1]) {
				p++;
				PARSE_FAIL(i == (PARSE_BUFSIZE - 1));
				buf[i++] = *p++;
			} else if (isquote(*p)) {
				quote = quote ? 0 : *p;
				if (dquote) { /* keep quote */
					PARSE_FAIL(i == (PARSE_BUFSIZE - 1));
					buf[i++] = *p++;
				} else
					++p;
			} else if (isdquote(*p)) {
				dquote = dquote ? 0 : *p;
				if (quote) { /* keep dquote */
					PARSE_FAIL(i == (PARSE_BUFSIZE - 1));
					buf[i++] = *p++;
				} else
					++p;
			} else if (isspace(*p) && !quote && !dquote) {
				state = WHITE;
				if (i) {
					buf[i] = '\0';
					PARSE_FAIL(insert(&ac, buf));
					i = 0;
				}
				++p;
			} else if (*p == '$' && !quote) {
				token = isdelim(*(p + 1));
				if (token)
					p += 2;
				else
					++p;
				state = VAR;
			} else {
				PARSE_FAIL(i == (PARSE_BUFSIZE - 1));
				buf[i++] = *p++;
			}
		break;

		case WHITE:
			if (isspace(*p))
				++p;
			else
				state = STR;
		break;

		case VAR:
			if (token) {
				PARSE_FAIL((q = strchr(p, token)) == NULL);
			} else {
				q = p;
				while (*q && !isspace(*q))
				++q;
			}
			tmp = *q;
			*q = '\0';
			if ((val = getenv(p)) != NULL) {
				size_t len = strlen(val);

				strncpy(buf + i, val, PARSE_BUFSIZE - (i + 1));
				i += min(len, PARSE_BUFSIZE - 1);
			}
			*q = tmp;	/* restore value */
			p = q + (token ? 1 : 0);
			state = STR;
		break;
		}
	}
	/* missing terminating ' or " */
	PARSE_FAIL(quote || dquote);
	/* If at end of token, add it */
	if (i && state == STR) {
		buf[i] = '\0';
		PARSE_FAIL(insert(&ac, buf));
	}
	args[ac] = NULL;
	*argc = ac;
	*argv = (char **)malloc((sizeof (char *) * ac + 1));
	bcopy(args, *argv, sizeof (char *) * ac + 1);
	free(buf);
	free(copy);
	return (0);
}

#define	MAXARGS	20

/* Clean vector space */
static void
clean(void)
{
	int i;

	for (i = 0; i < MAXARGS; i++) {
		if (args[i] != NULL) {
			free(args[i]);
			args[i] = NULL;
		}
	}
}

static int
insert(int *argcp, char *buf)
{
	if (*argcp >= MAXARGS)
		return (1);
	args[(*argcp)++] = strdup(buf);
	return (0);
}

static char *
isadir(void)
{
	char *buf;
	size_t bufsize = 20;
	int ret;

	if ((buf = malloc(bufsize)) == NULL)
		return (NULL);
	ret = sysinfo(SI_ARCHITECTURE_K, buf, bufsize);
	if (ret == -1) {
		free(buf);
		return (NULL);
	}
	return (buf);
}

/*
 * Shim for taking commands from BF and passing them out to 'standard'
 * argv/argc command functions.
 */
static void
bf_command(ficlVm *vm)
{
	char *name, *line, *tail, *cp;
	size_t len;
	struct bootblk_command *cmdp;
	bootblk_cmd_t *cmd;
	int nstrings, i;
	int argc, result;
	char **argv;

	/* Get the name of the current word */
	name = vm->runningWord->name;

	/* Find our command structure */
	cmd = NULL;
	STAILQ_FOREACH(cmdp, &commands, next) {
		if ((cmdp->c_name != NULL) && strcmp(name, cmdp->c_name) == 0)
			cmd = cmdp->c_fn;
	}
	if (cmd == NULL)
		printf("callout for unknown command '%s'\n", name);

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
				len = ficlStackPopInteger(
				    ficlVmGetDataStack(vm));
				cp = ficlStackPopPointer(
				    ficlVmGetDataStack(vm));
				strcat(line, " ");
				strncat(line, cp, len);
			}
	} else {
		/* Get remainder of invocation */
		tail = ficlVmGetInBuf(vm);
		for (cp = tail, len = 0;
		    cp != vm->tib.end && *cp != 0 && *cp != '\n'; cp++, len++)
			;

		line = malloc(strlen(name) + len + 2);
		strcpy(line, name);
		if (len > 0) {
			strcat(line, " ");
			strncat(line, tail, len);
			ficlVmUpdateTib(vm, tail + len);
		}
	}

	command_errmsg = command_errbuf;
	command_errbuf[0] = 0;
	if (!parse(&argc, &argv, line)) {
		result = (cmd)(argc, argv);
		free(argv);
	} else {
		result = BF_PARSE;
	}
	free(line);
	/*
	 * If there was error during nested ficlExec(), we may no longer have
	 * valid environment to return.  Throw all exceptions from here.
	 */
	if (result != 0)
		ficlVmThrow(vm, result);
	/* This is going to be thrown!!! */
	ficlStackPushInteger(ficlVmGetDataStack(vm), result);
}

static char *
get_currdev(void)
{
	int ret;
	char *currdev;
	FILE *fp;
	struct mnttab mpref = {0};
	struct mnttab mp = {0};

	mpref.mnt_mountp = "/";
	fp = fopen(MNTTAB, "r");

	/* do the best we can to return something... */
	if (fp == NULL)
		return (strdup(":"));

	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	if (ret == 0)
		(void) asprintf(&currdev, "zfs:%s:", mp.mnt_special);
	else
		return (strdup(":"));

	return (currdev);
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
#define	BUILTIN_CONSTRUCTOR \
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

extern int ficlExecFD(ficlVm *, int);
#define	COMMAND_SET(ptr, name, desc, fn)		\
	ptr = malloc(sizeof (struct bootblk_command));	\
	ptr->c_name = (name);				\
	ptr->c_desc = (desc);				\
	ptr->c_fn = (fn);

/*
 * Initialise the Forth interpreter, create all our commands as words.
 */
ficlVm *
bf_init(const char *rc, ficlOutputFunction out)
{
	struct bootblk_command *cmdp;
	char create_buf[41];	/* 31 characters-long builtins */
	char *buf;
	int fd, rv;
	ficlSystemInformation *fsi;
	ficlDictionary *dict;
	ficlDictionary *env;

	/* set up commands list */
	STAILQ_INIT(&commands);
	COMMAND_SET(cmdp, "help", "detailed help", command_help);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "?", "list commands", command_commandlist);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "show", "show variable(s)", command_show);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "printenv", "show variable(s)", command_show);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "set", "set a variable", command_set);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "setprop", "set a variable", command_setprop);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "unset", "unset a variable", command_unset);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "echo", "echo arguments", command_echo);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "read", "read input from the terminal", command_read);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "more", "show contents of a file", command_more);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "ls", "list files", command_ls);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "include", "read commands from a file",
	    command_include);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "boot", "boot a file or loaded kernel", command_boot);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "autoboot", "boot automatically after a delay",
	    command_autoboot);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "load", "load a kernel or module", command_load);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "unload", "unload all modules", command_unload);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);
	COMMAND_SET(cmdp, "reboot", "reboot the system", command_reboot);
	STAILQ_INSERT_TAIL(&commands, cmdp, next);

	fsi = malloc(sizeof (ficlSystemInformation));
	ficlSystemInformationInitialize(fsi);
	fsi->textOut = out;
	fsi->dictionarySize = BF_DICTSIZE;

	bf_sys = ficlSystemCreate(fsi);
	free(fsi);
	ficlSystemCompileExtras(bf_sys);
	bf_vm = ficlSystemCreateVm(bf_sys);

	buf = isadir();
	if (buf == NULL || strcmp(buf, "amd64") != 0) {
		(void) setenv("ISADIR", "", 1);
	} else {
		(void) setenv("ISADIR", buf, 1);
	}
	if (buf != NULL)
		free(buf);
	buf = get_currdev();
	(void) setenv("currdev", buf, 1);
	free(buf);

	/* Put all private definitions in a "builtins" vocabulary */
	rv = ficlVmEvaluate(bf_vm,
	    "vocabulary builtins also builtins definitions");
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		printf("error interpreting forth: %d\n", rv);
		exit(1);
	}

	/* Builtin constructor word  */
	rv = ficlVmEvaluate(bf_vm, BUILTIN_CONSTRUCTOR);
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		printf("error interpreting forth: %d\n", rv);
		exit(1);
	}

	/* make all commands appear as Forth words */
	dict = ficlSystemGetDictionary(bf_sys);
	cmdp = NULL;
	STAILQ_FOREACH(cmdp, &commands, next) {
		ficlDictionaryAppendPrimitive(dict, (char *)cmdp->c_name,
		    bf_command, FICL_WORD_DEFAULT);
		rv = ficlVmEvaluate(bf_vm, "forth definitions builtins");
		if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
			printf("error interpreting forth: %d\n", rv);
			exit(1);
		}
		snprintf(create_buf, sizeof (create_buf), "builtin: %s",
		    cmdp->c_name);
		rv = ficlVmEvaluate(bf_vm, create_buf);
		if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
			printf("error interpreting forth: %d\n", rv);
			exit(1);
		}
		rv = ficlVmEvaluate(bf_vm, "builtins definitions");
		if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
			printf("error interpreting forth: %d\n", rv);
			exit(1);
		}
	}
	rv = ficlVmEvaluate(bf_vm, "only forth definitions");
	if (rv != FICL_VM_STATUS_OUT_OF_TEXT) {
		printf("error interpreting forth: %d\n", rv);
		exit(1);
	}

	/*
	 * Export some version numbers so that code can detect the
	 * loader/host version
	 */
	env = ficlSystemGetEnvironment(bf_sys);
	ficlDictionarySetConstant(env, "loader_version",
	    (bootprog_rev[0] - '0') * 10 + (bootprog_rev[2] - '0'));

	/* try to load and run init file if present */
	if (rc == NULL)
		rc = "/boot/forth/boot.4th";
	if (*rc != '\0') {
		fd = open(rc, O_RDONLY);
		if (fd != -1) {
			(void) ficlExecFD(bf_vm, fd);
			close(fd);
		}
	}

	return (bf_vm);
}

void
bf_fini(void)
{
	ficlSystemDestroy(bf_sys);
}

/*
 * Feed a line of user input to the Forth interpreter
 */
int
bf_run(char *line)
{
	int result;
	ficlString s;

	FICL_STRING_SET_FROM_CSTRING(s, line);
	result = ficlVmExecuteString(bf_vm, s);

	switch (result) {
	case FICL_VM_STATUS_OUT_OF_TEXT:
	case FICL_VM_STATUS_ABORTQ:
	case FICL_VM_STATUS_QUIT:
	case FICL_VM_STATUS_ERROR_EXIT:
	break;
	case FICL_VM_STATUS_USER_EXIT:
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

	setenv("interpret", bf_vm->state ? "" : "ok", 1);

	return (result);
}

char *
get_dev(const char *path)
{
	FILE *fp;
	struct mnttab mpref = {0};
	struct mnttab mp = {0};
	char *currdev;
	int ret;
	char *buf;
	char *tmppath;
	char *tmpdev;
	char *cwd = NULL;

	fp = fopen(MNTTAB, "r");

	/* do the best we can to return something... */
	if (fp == NULL)
		return (strdup(path));

	/*
	 * the path can have device provided, check for it
	 * and extract it.
	 */
	buf = strrchr(path, ':');
	if (buf != NULL) {
		tmppath = buf+1;		/* real path */
		buf = strchr(path, ':');	/* skip zfs: */
		buf++;
		tmpdev = strdup(buf);
		buf = strchr(tmpdev, ':');	/* get ending : */
		*buf = '\0';
	} else {
		tmppath = (char *)path;
		if (tmppath[0] != '/')
			if ((cwd = getcwd(NULL, PATH_MAX)) == NULL) {
				(void) fclose(fp);
				return (strdup(path));
			}

		currdev = getenv("currdev");
		buf = strchr(currdev, ':');	/* skip zfs: */
		if (buf == NULL) {
			(void) fclose(fp);
			return (strdup(path));
		}
		buf++;
		tmpdev = strdup(buf);
		buf = strchr(tmpdev, ':');	/* get ending : */
		*buf = '\0';
	}

	mpref.mnt_special = tmpdev;
	ret = getmntany(fp, &mp, &mpref);
	(void) fclose(fp);
	free(tmpdev);

	if (cwd == NULL)
		(void) asprintf(&buf, "%s/%s", ret? "":mp.mnt_mountp, tmppath);
	else {
		(void) asprintf(&buf, "%s/%s/%s", ret? "":mp.mnt_mountp, cwd,
		    tmppath);
		free(cwd);
	}
	return (buf);
}

static void
ngets(char *buf, int n)
{
	int c;
	char *lp;

	for (lp = buf; ; )
		switch (c = getchar() & 0177) {
		case '\n':
		case '\r':
			*lp = '\0';
			putchar('\n');
		return;
		case '\b':
		case '\177':
			if (lp > buf) {
				lp--;
				putchar('\b');
				putchar(' ');
				putchar('\b');
			}
		break;
		case 'r'&037: {
			char *p;

			putchar('\n');
			for (p = buf; p < lp; ++p)
				putchar(*p);
		break;
		}
		case 'u'&037:
		case 'w'&037:
			lp = buf;
			putchar('\n');
		break;
		default:
			if ((n < 1) || ((lp - buf) < n - 1)) {
				*lp++ = c;
				putchar(c);
			}
		}
	/*NOTREACHED*/
}

static int
fgetstr(char *buf, int size, int fd)
{
	char c;
	int err, len;

	size--;			/* leave space for terminator */
	len = 0;
	while (size != 0) {
		err = read(fd, &c, sizeof (c));
		if (err < 0)			/* read error */
			return (-1);

		if (err == 0) {	/* EOF */
			if (len == 0)
				return (-1);	/* nothing to read */
			break;
		}
		if ((c == '\r') || (c == '\n'))	/* line terminators */
			break;
		*buf++ = c;			/* keep char */
		size--;
		len++;
	}
	*buf = 0;
	return (len);
}

static char *
unargv(int argc, char *argv[])
{
	size_t hlong;
	int i;
	char *cp;

	for (i = 0, hlong = 0; i < argc; i++)
		hlong += strlen(argv[i]) + 2;

	if (hlong == 0)
		return (NULL);

	cp = malloc(hlong);
	cp[0] = 0;
	for (i = 0; i < argc; i++) {
		strcat(cp, argv[i]);
		if (i < (argc - 1))
			strcat(cp, " ");
	}

	return (cp);
}

/*
 * Help is read from a formatted text file.
 *
 * Entries in the file are formatted as:
 * # Ttopic [Ssubtopic] Ddescription
 * help
 * text
 * here
 * #
 *
 * Note that for code simplicity's sake, the above format must be followed
 * exactly.
 *
 * Subtopic entries must immediately follow the topic (this is used to
 * produce the listing of subtopics).
 *
 * If no argument(s) are supplied by the user, the help for 'help' is displayed.
 */
static int
help_getnext(int fd, char **topic, char **subtopic, char **desc)
{
	char line[81], *cp, *ep;

	*topic = *subtopic = *desc = NULL;
	for (;;) {
		if (fgetstr(line, 80, fd) < 0)
			return (0);

		if (strlen(line) < 3 || line[0] != '#' || line[1] != ' ')
			continue;

		*topic = *subtopic = *desc = NULL;
		cp = line + 2;
		while (cp != NULL && *cp != 0) {
			ep = strchr(cp, ' ');
			if (*cp == 'T' && *topic == NULL) {
				if (ep != NULL)
					*ep++ = 0;
				*topic = strdup(cp + 1);
			} else if (*cp == 'S' && *subtopic == NULL) {
				if (ep != NULL)
					*ep++ = 0;
				*subtopic = strdup(cp + 1);
			} else if (*cp == 'D') {
				*desc = strdup(cp + 1);
				ep = NULL;
			}
			cp = ep;
		}
		if (*topic == NULL) {
			free(*subtopic);
			free(*desc);
			continue;
		}
		return (1);
	}
}

static int
help_emitsummary(char *topic, char *subtopic, char *desc)
{
	int i;

	pager_output("    ");
	pager_output(topic);
	i = strlen(topic);
	if (subtopic != NULL) {
		pager_output(" ");
		pager_output(subtopic);
		i += strlen(subtopic) + 1;
	}
	if (desc != NULL) {
		do {
			pager_output(" ");
		} while (i++ < 30);
		pager_output(desc);
	}
	return (pager_output("\n"));
}

static int
command_help(int argc, char *argv[])
{
	char buf[81];	/* XXX buffer size? */
	int hfd, matched, doindex;
	char *topic, *subtopic, *t, *s, *d;

	/* page the help text from our load path */
	snprintf(buf, sizeof (buf), "/boot/loader.help");
	if ((hfd = open(buf, O_RDONLY)) < 0) {
		printf("Verbose help not available, "
		    "use '?' to list commands\n");
		return (CMD_OK);
	}

	/* pick up request from arguments */
	topic = subtopic = NULL;
	switch (argc) {
	case 3:
		subtopic = strdup(argv[2]);
		/* FALLTHROUGH */
	case 2:
		topic = strdup(argv[1]);
	break;
	case 1:
		topic = strdup("help");
	break;
	default:
		command_errmsg = "usage is 'help <topic> [<subtopic>]";
		close(hfd);
		return (CMD_ERROR);
	}

	/* magic "index" keyword */
	doindex = strcmp(topic, "index") == 0;
	matched = doindex;

	/* Scan the helpfile looking for help matching the request */
	pager_open();
	while (help_getnext(hfd, &t, &s, &d)) {
		if (doindex) {		/* dink around formatting */
			if (help_emitsummary(t, s, d))
				break;

		} else if (strcmp(topic, t)) {
			/* topic mismatch */
			/* nothing more on this topic, stop scanning */
			if (matched)
				break;
		} else {
			/* topic matched */
			matched = 1;
			if ((subtopic == NULL && s == NULL) ||
			    (subtopic != NULL && s != NULL &&
			    strcmp(subtopic, s) == 0)) {
				/* exact match, print text */
				while (fgetstr(buf, 80, hfd) >= 0 &&
				    buf[0] != '#') {
					if (pager_output(buf))
						break;
					if (pager_output("\n"))
						break;
				}
			} else if (subtopic == NULL && s != NULL) {
				/* topic match, list subtopics */
				if (help_emitsummary(t, s, d))
					break;
			}
		}
		free(t);
		free(s);
		free(d);
		t = s = d = NULL;
	}
	free(t);
	free(s);
	free(d);
	pager_close();
	close(hfd);
	if (!matched) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "no help available for '%s'", topic);
		free(topic);
		free(subtopic);
		return (CMD_ERROR);
	}
	free(topic);
	free(subtopic);
	return (CMD_OK);
}

static int
command_commandlist(int argc __unused, char *argv[] __unused)
{
	struct bootblk_command *cmdp;
	int res;
	char name[20];

	res = 0;
	pager_open();
	res = pager_output("Available commands:\n");
	cmdp = NULL;
	STAILQ_FOREACH(cmdp, &commands, next) {
		if (res)
			break;
		if (cmdp->c_name != NULL && cmdp->c_desc != NULL) {
			snprintf(name, sizeof (name), "  %-15s  ",
			    cmdp->c_name);
			pager_output(name);
			pager_output(cmdp->c_desc);
			res = pager_output("\n");
		}
	}
	pager_close();
	return (CMD_OK);
}

/*
 * XXX set/show should become set/echo if we have variable
 * substitution happening.
 */
static int
command_show(int argc, char *argv[])
{
	char **ev;
	char *cp;

	if (argc < 2) {
		/*
		 * With no arguments, print everything.
		 */
		pager_open();
		for (ev = _environ; *ev != NULL; ev++) {
			pager_output(*ev);
			cp = getenv(*ev);
			if (cp != NULL) {
				pager_output("=");
				pager_output(cp);
			}
			if (pager_output("\n"))
				break;
		}
		pager_close();
	} else {
		if ((cp = getenv(argv[1])) != NULL) {
			printf("%s\n", cp);
		} else {
			snprintf(command_errbuf, sizeof (command_errbuf),
			    "variable '%s' not found", argv[1]);
			return (CMD_ERROR);
		}
	}
	return (CMD_OK);
}

static int
command_set(int argc, char *argv[])
{
	int	err;
	char	*value, *copy;

	if (argc != 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	} else {
		copy = strdup(argv[1]);
		if (copy == NULL) {
			command_errmsg = strerror(errno);
			return (CMD_ERROR);
		}
		if ((value = strchr(copy, '=')) != NULL)
			*(value++) = 0;
		else
			value = "";
		if ((err = setenv(copy, value, 1)) != 0) {
			free(copy);
			command_errmsg = strerror(errno);
			return (CMD_ERROR);
		}
		free(copy);
	}
	return (CMD_OK);
}

static int
command_setprop(int argc, char *argv[])
{
	int err;

	if (argc != 3) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	} else {
		if ((err = setenv(argv[1], argv[2], 1)) != 0) {
			command_errmsg = strerror(err);
			return (CMD_ERROR);
		}
	}
	return (CMD_OK);
}

static int
command_unset(int argc, char *argv[])
{
	int err;

	if (argc != 2) {
		command_errmsg = "wrong number of arguments";
		return (CMD_ERROR);
	} else {
		if ((err = unsetenv(argv[1])) != 0) {
			command_errmsg = strerror(err);
			return (CMD_ERROR);
		}
	}
	return (CMD_OK);
}

static int
command_echo(int argc, char *argv[])
{
	char *s;
	int nl, ch;

	nl = 0;
	optind = 1;
	opterr = 1;
	while ((ch = getopt(argc, argv, "n")) != -1) {
		switch (ch) {
		case 'n':
			nl = 1;
		break;
		case '?':
		default:
			/* getopt has already reported an error */
		return (CMD_OK);
		}
	}
	argv += (optind);
	argc -= (optind);

	s = unargv(argc, argv);
	if (s != NULL) {
		printf("%s", s);
		free(s);
	}
	if (!nl)
		printf("\n");
	return (CMD_OK);
}

/*
 * A passable emulation of the sh(1) command of the same name.
 */
static int
ischar(void)
{
	return (1);
}

static int
command_read(int argc, char *argv[])
{
	char *prompt;
	int timeout;
	time_t when;
	char *cp;
	char *name;
	char buf[256];		/* XXX size? */
	int c;

	timeout = -1;
	prompt = NULL;
	optind = 1;
	opterr = 1;
	while ((c = getopt(argc, argv, "p:t:")) != -1) {
		switch (c) {
		case 'p':
			prompt = optarg;
		break;
		case 't':
			timeout = strtol(optarg, &cp, 0);
			if (cp == optarg) {
				snprintf(command_errbuf,
				    sizeof (command_errbuf),
				    "bad timeout '%s'", optarg);
				return (CMD_ERROR);
			}
		break;
		default:
		return (CMD_OK);
		}
	}

	argv += (optind);
	argc -= (optind);
	name = (argc > 0) ? argv[0]: NULL;

	if (prompt != NULL)
		printf("%s", prompt);
	if (timeout >= 0) {
		when = time(NULL) + timeout;
		while (!ischar())
			if (time(NULL) >= when)
				return (CMD_OK); /* is timeout an error? */
	}

	ngets(buf, sizeof (buf));

	if (name != NULL)
		setenv(name, buf, 1);
	return (CMD_OK);
}

/*
 * File pager
 */
static int
command_more(int argc, char *argv[])
{
	int i;
	int res;
	char line[80];
	char *name;

	res = 0;
	pager_open();
	for (i = 1; (i < argc) && (res == 0); i++) {
		snprintf(line, sizeof (line), "*** FILE %s BEGIN ***\n",
		    argv[i]);
		if (pager_output(line))
			break;
		name = get_dev(argv[i]);
		res = page_file(name);
		free(name);
		if (!res) {
			snprintf(line, sizeof (line), "*** FILE %s END ***\n",
			    argv[i]);
			res = pager_output(line);
		}
	}
	pager_close();

	if (res == 0)
		return (CMD_OK);
	return (CMD_ERROR);
}

static int
page_file(char *filename)
{
	int result;

	result = pager_file(filename);

	if (result == -1) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "error showing %s", filename);
	}

	return (result);
}

static int
command_ls(int argc, char *argv[])
{
	DIR *dir;
	int fd;
	struct stat sb;
	struct dirent *d;
	char *buf, *path;
	char lbuf[128];	/* one line */
	int result, ch;
	int verbose;

	result = CMD_OK;
	fd = -1;
	verbose = 0;
	optind = 1;
	opterr = 1;
	while ((ch = getopt(argc, argv, "l")) != -1) {
		switch (ch) {
		case 'l':
			verbose = 1;
		break;
		case '?':
		default:
			/* getopt has already reported an error */
		return (CMD_OK);
		}
	}
	argv += (optind - 1);
	argc -= (optind - 1);

	if (argc < 2) {
		path = "";
	} else {
		path = argv[1];
	}

	fd = ls_getdir(&path);
	if (fd == -1) {
		result = CMD_ERROR;
		goto out;
	}
	dir = fdopendir(fd);
	pager_open();
	pager_output(path);
	pager_output("\n");

	while ((d = readdir(dir)) != NULL) {
		if (strcmp(d->d_name, ".") && strcmp(d->d_name, "..")) {
			/* stat the file, if possible */
			sb.st_size = 0;
			sb.st_mode = 0;
			buf = malloc(strlen(path) + strlen(d->d_name) + 2);
			if (path[0] == '\0') {
				snprintf(buf, sizeof (buf), "%s", d->d_name);
			} else {
				snprintf(buf, sizeof (buf), "%s/%s", path,
				    d->d_name);
			}
			/* ignore return, could be symlink, etc. */
			if (stat(buf, &sb))
				sb.st_size = 0;
			free(buf);
			if (verbose) {
				snprintf(lbuf, sizeof (lbuf), " %c %8d %s\n",
				    typestr[sb.st_mode >> 12],
				    (int)sb.st_size, d->d_name);
			} else {
				snprintf(lbuf, sizeof (lbuf), " %c  %s\n",
				    typestr[sb.st_mode >> 12], d->d_name);
			}
			if (pager_output(lbuf))
				goto out;
		}
	}
out:
	pager_close();
	if (fd != -1)
		closedir(dir);
	if (path != NULL)
		free(path);
	return (result);
}

/*
 * Given (path) containing a vaguely reasonable path specification, return an fd
 * on the directory, and an allocated copy of the path to the directory.
 */
static int
ls_getdir(char **pathp)
{
	struct stat sb;
	int fd;
	char *cp, *path;

	fd = -1;

	/* one extra byte for a possible trailing slash required */
	path = malloc(strlen(*pathp) + 2);
	strcpy(path, *pathp);

	/* Make sure the path is respectable to begin with */
	if ((cp = get_dev(path)) == NULL) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "bad path '%s'", path);
		goto out;
	}

	/* If there's no path on the device, assume '/' */
	if (*cp == 0)
		strcat(path, "/");

	fd = open(cp, O_RDONLY);
	if (fd < 0) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "open '%s' failed: %s", path, strerror(errno));
		goto out;
	}
	if (fstat(fd, &sb) < 0) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "stat failed: %s", strerror(errno));
		goto out;
	}
	if (!S_ISDIR(sb.st_mode)) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "%s: %s", path, strerror(ENOTDIR));
		goto out;
	}

	free(cp);
	*pathp = path;
	return (fd);

out:
	free(cp);
	free(path);
	*pathp = NULL;
	if (fd != -1)
		close(fd);
	return (-1);
}

static int
command_include(int argc, char *argv[])
{
	int i;
	int res;
	char **argvbuf;

	/*
	 * Since argv is static, we need to save it here.
	 */
	argvbuf = (char **)calloc(argc, sizeof (char *));
	for (i = 0; i < argc; i++)
		argvbuf[i] = strdup(argv[i]);

	res = CMD_OK;
	for (i = 1; (i < argc) && (res == CMD_OK); i++)
		res = include(argvbuf[i]);

	for (i = 0; i < argc; i++)
		free(argvbuf[i]);
	free(argvbuf);

	return (res);
}

/*
 * Header prepended to each line. The text immediately follows the header.
 * We try to make this short in order to save memory -- the loader has
 * limited memory available, and some of the forth files are very long.
 */
struct includeline
{
	struct includeline *next;
	int line;
	char text[];
};

int
include(const char *filename)
{
	struct includeline *script, *se, *sp;
	int res = CMD_OK;
	int prevsrcid, fd, line;
	char *cp, input[256]; /* big enough? */
	char *path;

	path = get_dev(filename);
	if (((fd = open(path, O_RDONLY)) == -1)) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "can't open '%s': %s", filename,
		    strerror(errno));
		free(path);
		return (CMD_ERROR);
	}

	free(path);
	/*
	 * Read the script into memory.
	 */
	script = se = NULL;
	line = 0;

	while (fgetstr(input, sizeof (input), fd) >= 0) {
		line++;
		cp = input;
		/* Allocate script line structure and copy line, flags */
		if (*cp == '\0')
			continue;	/* ignore empty line, save memory */
		if (cp[0] == '\\' && cp[1] == ' ')
			continue;	/* ignore comment */

		sp = malloc(sizeof (struct includeline) + strlen(cp) + 1);
		/*
		 * On malloc failure (it happens!), free as much as possible
		 * and exit
		 */
		if (sp == NULL) {
			while (script != NULL) {
				se = script;
				script = script->next;
				free(se);
			}
			snprintf(command_errbuf, sizeof (command_errbuf),
			    "file '%s' line %d: memory allocation "
			    "failure - aborting", filename, line);
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

	while (script != NULL) {
		se = script;
		script = script->next;
		free(se);
	}

	return (res);
}

static int
command_boot(int argc, char *argv[])
{
	return (CMD_OK);
}

static int
command_autoboot(int argc, char *argv[])
{
	return (CMD_OK);
}

static void
moduledir_rebuild(void)
{
	struct moduledir *mdp, *mtmp;
	const char *path, *cp, *ep;
	int cplen;

	path = getenv("module_path");
	if (path == NULL)
		path = default_searchpath;
	/*
	 * Rebuild list of module directories if it changed
	 */
	STAILQ_FOREACH(mdp, &moduledir_list, d_link)
		mdp->d_flags |= MDIR_REMOVED;

	for (ep = path; *ep != 0;  ep++) {
		cp = ep;
		for (; *ep != 0 && *ep != ';'; ep++)
			;
		/*
		 * Ignore trailing slashes
		 */
		for (cplen = ep - cp; cplen > 1 && cp[cplen - 1] == '/';
		    cplen--)
			;
		STAILQ_FOREACH(mdp, &moduledir_list, d_link) {
			if (strlen(mdp->d_path) != cplen ||
			    bcmp(cp, mdp->d_path, cplen) != 0)
				continue;
			mdp->d_flags &= ~MDIR_REMOVED;
			break;
		}
		if (mdp == NULL) {
			mdp = malloc(sizeof (*mdp) + cplen + 1);
			if (mdp == NULL)
				return;
			mdp->d_path = (char *)(mdp + 1);
			bcopy(cp, mdp->d_path, cplen);
			mdp->d_path[cplen] = 0;
			mdp->d_hints = NULL;
			mdp->d_flags = 0;
			STAILQ_INSERT_TAIL(&moduledir_list, mdp, d_link);
		}
		if (*ep == 0)
			break;
	}
	/*
	 * Delete unused directories if any
	 */
	mdp = STAILQ_FIRST(&moduledir_list);
	while (mdp) {
		if ((mdp->d_flags & MDIR_REMOVED) == 0) {
			mdp = STAILQ_NEXT(mdp, d_link);
		} else {
			if (mdp->d_hints)
				free(mdp->d_hints);
			mtmp = mdp;
			mdp = STAILQ_NEXT(mdp, d_link);
			STAILQ_REMOVE(&moduledir_list, mtmp, moduledir, d_link);
			free(mtmp);
		}
	}
}

static char *
file_lookup(const char *path, const char *name, int namelen)
{
	struct stat st;
	char *result, *cp, *gz;
	int pathlen;

	pathlen = strlen(path);
	result = malloc(pathlen + namelen + 2);
	if (result == NULL)
		return (NULL);
	bcopy(path, result, pathlen);
	if (pathlen > 0 && result[pathlen - 1] != '/')
		result[pathlen++] = '/';
	cp = result + pathlen;
	bcopy(name, cp, namelen);
	cp += namelen;
	*cp = '\0';
	if (stat(result, &st) == 0 && S_ISREG(st.st_mode))
		return (result);
	/* also check for gz file */
	(void) asprintf(&gz, "%s.gz", result);
	if (gz != NULL) {
		int res = stat(gz, &st);
		free(gz);
		if (res == 0)
			return (result);
	}
	free(result);
	return (NULL);
}

static char *
file_search(const char *name)
{
	struct moduledir *mdp;
	struct stat sb;
	char *result;
	int namelen;

	if (name == NULL)
		return (NULL);
	if (*name == 0)
		return (strdup(name));

	if (strchr(name, '/') != NULL) {
		char *gz;
		if (stat(name, &sb) == 0)
			return (strdup(name));
		/* also check for gz file */
		(void) asprintf(&gz, "%s.gz", name);
		if (gz != NULL) {
			int res = stat(gz, &sb);
			free(gz);
			if (res == 0)
				return (strdup(name));
		}
		return (NULL);
	}

	moduledir_rebuild();
	result = NULL;
	namelen = strlen(name);
	STAILQ_FOREACH(mdp, &moduledir_list, d_link) {
		result = file_lookup(mdp->d_path, name, namelen);
		if (result)
			break;
	}
	return (result);
}

static int
command_load(int argc, char *argv[])
{
	int dofile, ch;
	char *typestr = NULL;
	char *filename;
	dofile = 0;
	optind = 1;

	if (argc == 1) {
		command_errmsg = "no filename specified";
		return (CMD_ERROR);
	}

	while ((ch = getopt(argc, argv, "kt:")) != -1) {
		switch (ch) {
		case 'k':
			break;
		case 't':
			typestr = optarg;
			dofile = 1;
			break;
		case '?':
		default:
			return (CMD_OK);
		}
	}
	argv += (optind - 1);
	argc -= (optind - 1);
	if (dofile) {
		if ((typestr == NULL) || (*typestr == 0)) {
			command_errmsg = "invalid load type";
			return (CMD_ERROR);
		}
#if 0
		return (file_loadraw(argv[1], typestr, argc - 2, argv + 2, 1)
		    ? CMD_OK : CMD_ERROR);
#endif
		return (CMD_OK);
	}

	filename = file_search(argv[1]);
	if (filename == NULL) {
		snprintf(command_errbuf, sizeof (command_errbuf),
		    "can't find '%s'", argv[1]);
		return (CMD_ERROR);
	}
	setenv("kernelname", filename, 1);

	return (CMD_OK);
}

static int
command_unload(int argc, char *argv[])
{
	unsetenv("kernelname");
	return (CMD_OK);
}

static int
command_reboot(int argc, char *argv[])
{
	exit(0);
	return (CMD_OK);
}
