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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The purpose of this lex specification is to estimate the
 * correctness of the various scripts that accompany packages. It
 * is not flawless, but it is a better review than that of prior
 * package validators. It looks for indications of interaction,
 * root calls and attempts to modify locked files.
 */
%e 1500
%p 3500
%s WHROOT
%{
#undef	input
#undef	unput
FILE *scr_fp;
#define	input()		(((yytchar=yysptr>yysbuf?U(*--yysptr):getc(scr_fp))==10?(yylineno++,yytchar):yytchar)==EOF?0:yytchar)
#define	unput(p)	ungetc(p, scr_fp)

#define	INTERACT_D	0x00000001	/* definitely */
#define	ROOT_D		0x00000002
#define	LOCKED_D	0x00000004
#define	INTERACT_M	0x00010000	/* might be true, or we ... */
#define	ROOT_M		0x00020000	/* ... might be reading it wrong. */
#define	LOCKED_M	0x00040000
#define	WPARM1_M	0x00080000	/* attempt to write to $1 */
#define	USEPARM1_M	0x00100000	/* other attempt to use $1 */
#define	ODDPARM_M	0x00200000	/* use of some other parameter */
#define	PKGDB_M		0x00400000	/* read access to DB */
#define	INITVAL		0x40000000

/* Abbreviations */
#define	INTERACT	(INTERACT_D | INTERACT_M)
#define	ROOT		(ROOT_D | ROOT_M)
#define	LOCKED		(LOCKED_D | LOCKED_M)
#define	HASPARM		(WPARM1_M | USEPARM1_M | ODDPARM_M)

/* Things the preinstall and preremove scripts can't do. */
#define	PRE_MASK	(INTERACT | LOCKED | PKGDB_M | HASPARM)
/*
 * Things the class action script can't do. Don't get the impression that
 * this means the class action script can be interactive; but, it can
 * legitimately read stdin (which is what INTERACT tests for).
 */
#define	CAS_MASK	(LOCKED | PKGDB_M | WPARM1_M | ODDPARM_M)
/* Things the postinstall and postremove scripts can't do. */
#define	POST_MASK	(INTERACT | HASPARM)
/* Things the request script can't do. */
#define	REQ_MASK	(ROOT | ODDPARM_M)
/* Things the checkinstall script can't do. */
#define	CHK_MASK	(INTERACT | ROOT | ODDPARM_M)

/* Nothing definite - not worth returning an error */
#define	MAYBE_ONLY	~(INTERACT_D | ROOT_D | LOCKED_D)

#define	WRN_INST_F	"WARNING: script <%s> uses installf but no " \
			    "installf -f was detected."
#define	WRN_REM_F	"WARNING: script <%s> uses removef but no " \
			    "removef -f was detected."
#define	WRN_INTERACT	"WARNING: script <%s> may require " \
			    "user interaction at line <%d>."
#define	WRN_LOCKED	"WARNING: script <%s> may seek access to the " \
			    "transitional package database at line <%d>. " \
			    "This is safest in the postinstall or " \
			    "postremove script."
#define	WRN_ROOT	"WARNING: script <%s> may not have permission " \
			    "to execute line <%d>."
#define	WRN_FORM_ARG	"WARNING: not sure where script <%s> gets the "\
			    "parameter at line <%d>."
#define	WRN_FORM_USE	"WARNING: script <%s> questionable usage of "\
			    "parameter at line <%d>."
#define	WRN_TRANSDB	"WARNING: script <%s> questionable read " \
			    "of package database at line <%d>. An " \
			    "intermediate buffer may be appropriate."
#define	WRN_SPACEACC	"WARNING: script <%s> updates the package database " \
			    "but provides no space file to account for " \
			    "the additional package object."
#define	ERR_INTERACT	"ERROR: script <%s> requires user " \
			    "interaction at line <%d>."
#define	ERR_LOCKED	"ERROR: script <%s> attempts to modify locked " \
			    "package database at line <%d>."
#define	ERR_ROOT	"ERROR: script <%s> requires root permission at " \
			    "line <%d>."
#define	ERR_FOPEN	"ERROR: Cannot evaluate script <%s>, errno=%d."
#define	ERR_ARGS	"ERROR: scripteval() - no script provided for " \
			    "evaluation."
extern int errno;

static int line_no;	/* current line number */
int pipe_release = 0;	/* loop level for release of pipe */
int loop_depth = 0;	/* current number of nested loops */
int case_depth = 0;	/* same for case ... */
int if_depth = 0;	/* ... and if statements */
int cur_level = 0;	/* current number of nested anything */
int braces = 0;		/* depth into a function */

int lock_level = 0;
int root_level = 0;

struct statstrct {
	unsigned int in_function:1;
	unsigned int in_pipe:1;
	unsigned int in_loop:1;
	unsigned int in_case:1;
	unsigned int in_if:1;
	unsigned int in_awk:1;
	unsigned int allow_int:1;	/* Allow an interactive function. */
	unsigned int pkg_rtn_done:1;
	unsigned int pkgchk_f:1;
	unsigned int instf:1;
	unsigned int instf_f:1;
	unsigned int remf:1;
	unsigned int remf_f:1;
	unsigned int nospacefile:1;
	unsigned int needspacefile:1;
} status = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

%}
%%
%{
/*
 * Validate a few OK patterns that look like bad patterns. These include:
 *	1. comments
 *	2. quoted strings
 *	3. writes to $1 (request script)
 *	4. reads from $1 (CAS)
 *	5. writes to /dev/null
 */
%}
#.*$ 	{
	if (status.in_awk == 0)
		return INITVAL;
	else
		REJECT; /* No comments in the middle of an awk statement */
	}

\`	unput(' ');	/* No executable matching */

%{
/* Anybody can write to /dev/null and anybody can write to /tmp. */
%}
\>[ \t]*"/dev/null"	return INITVAL;
\>[ \t]*"/tmp"		return INITVAL;

%{
/* If it's escaped, the next entry may as well be a space. */
%}
\\	{
	char ch;

	if ((ch = input()) == '\n')
		line_no++;

	unput(' ');
}

%{
/* In the quotes is OK. */
%}
\"	{
	char ch;
	while ((ch = input()) != '\"') {
		if (ch == '\\') {
			input();	/* Read this into the bit bucket. */
			continue;
		}
		if (ch == '\n')
			line_no++;
		else if (ch == '\0')
			return (0);	/* EOF */
	}
}

%{
/* In the single quotes is OK if they aren't associated with an awk script. */
%}
\'	{
	char ch;

	if (status.in_awk != 0) {
		REJECT;;
	}

	while ((ch = input()) != '\'') {
		if (ch == '\\') {
			input();	/* Read this into the bit bucket. */
			continue;
		}
		if (ch == '\n')
			line_no++;
		else if (ch == '\0')
			return (0);	/* EOF */
	}
}

%{
/*
 * Check for use of parameters passed to the script.
 *	1. writes to $1 as though it were a file
 *	2. use of $1 in any capacity
 *	3. use of other parameters
 * Within a function or an awk script, these parameters aren't
 * the one's of interest.
 */
%}
\>[\t ]*\$1/[\t\n ]	{
	if (status.in_function == 0 && status.in_awk == 0)
		return (WPARM1_M);
}

^$1/[\t\n ]	|
[\t ]$1/[\t\n ]	{
	if (status.in_function == 0 && status.in_awk == 0)
		return (USEPARM1_M);
}

\$[2-9]	|
\$[0-9][0-9]+ {
	if (status.in_function == 0 && status.in_awk == 0)
		return (ODDPARM_M);
}

%{
/*
 * Detect shell function.
 */
%}
"()"[ \t]*\n[ \t]*/\{	{ status.in_function = 1; line_no++; }
"()"[ ]*/\{	status.in_function = 1;

"{" {
	if (status.in_function == 1)
		braces++;
}

"}" {
	if (status.in_function == 1) {
		braces--;
		if (braces == 0)
			status.in_function = 0;
	}
}

%{
/*
 * Detect for or while loop.
 */
%}
^for/[\t\n ]		|
^[\t ]+for/[\t\n ]	|
^while/[\t\n ]		|
^[\t ]+while/[\t\n ] {
	status.in_loop = 1;
	loop_depth++;
	cur_level++;
	REJECT;		/* What's in the argument is important too. */
}

^done/[\t\n ] 	|
^[\t ]+done/[\t\n ]  {
	if (status.in_loop == 1) {
		loop_depth--;
		cur_level--;
		if (loop_depth == 0)
			status.in_loop = 0;
	}
}

%{
/*
 * Detect case.
 */
%}
^case/[\t\n ]	|
^[\t ]+case/[\t\n ] {
	status.in_case = 1;
	case_depth++;
	cur_level++;
	REJECT;		/* What's in the argument is important too. */
}

^esac/[\t\n ] 	|
^[\t ]+esac/[\t\n ] {
	if (status.in_case == 1) {
		case_depth--;
		cur_level--;
		if (case_depth == 0)
			status.in_case = 0;
	}
}

%{
/*
 * Detect if.
 */
%}
^if" "*"["	|
^[\t ]+if" "*"[" {
	status.in_if = 1;
	if_depth++;
	cur_level++;
	REJECT;		/* What's in the argument is important too. */
}

^fi/[\t\n ]	|
^[\t ]+fi/[\t\n ]  {
	if (status.in_if == 1) {
		if_depth--;
		cur_level--;
		if (if_depth == 0)
			status.in_if = 0;
	}
}

%{
/*
 * Detect awk or nawk function. If the function is enclosed in "`"s
 * the entire line will be grabbed., so we check for that possibility.
 */
%}
^n?awk[^\n^']*\' 	|
[\t \\\(\/]n?awk[^\n^']*\'	{status.in_awk = 1;
#ifdef VERBOSE
	printf("open awk statment, line %d\n", line_no);
#endif
}


\' {
	if (status.in_awk == 1) {
#ifdef VERBOSE
		printf("close awk statement, line %d\n", line_no);
#endif
		status.in_awk = 0;
	}
}

%{
/* Detect pipe target. */
%}
[\$A-Za-z]	{
	if (status.in_pipe == 1 && pipe_release == cur_level) {
		status.in_pipe = 0;	/* target located */
		pipe_release = 0;
#ifdef VERBOSE
		printf("end pipe, line %d\n", line_no);
#endif
		status.allow_int = 1;	/* this isn't really interactive. */
		REJECT;	/* put it back */
	}
}

%{
/* If it's a pipe, note that and continue. */
%}
"||"		|
"|"		{
	if (status.in_pipe == 0) {
		status.in_pipe = 1;
#ifdef VERBOSE
		printf("start pipe, line %d\n", line_no);
#endif
		pipe_release = cur_level;
	}
}

%{
/*
 * Test input for admin-type telltale interactive functions. Definite's
 * first, maybe's next.
 */
%}
^ckdate/[\t\n ]		|
[\t \/]ckdate/[\t\n ]	|
^ckint/[\t\n ]		|
[\t \/]ckint/[\t\n ]	|
^ckrange/[\t\n ]	|
[\t \/]ckrange/[\t\n ]	|
^cktime/[\t\n ]		|
[\t \/]cktime/[\t\n ]	|
^ckyorn/[\t\n ]		|
[\t \/]ckyorn/[\t\n ]	|
^ckgid/[\t\n ]		|
[\t \/]ckgid/[\t\n ]	|
^ckpath/[\t\n ]		|
[\t \/]ckpath/[\t\n ]	|
^ckstr/[\t\n ]		|
[\t \/]ckstr/[\t\n ]	|
^ckuid/[\t\n ]		|
[\t \/]ckuid/[\t\n ]		{
	if (status.in_pipe == 1 || status.allow_int == 1)
		return (INITVAL);
	else
		return (INTERACT_M);	/* maybe should be _D */
}

^read/[\t\n ]		|
[\t ]read/[\t\n ]	|
"=[ ]+&<"[\t ]	{
	if (status.in_pipe == 1 || status.allow_int == 1)
		return (INITVAL);
	else
		return (INTERACT_M);
}

%{
/* Scan for root authority commands. Definite's first, maybe's next. */
%}
^mkdir/[\t\n ]		|
[\t \/]mkdir/[\t\n ]	|
^mv/[\t\n ]		|
[\t \/]mv/[\t\n ]	|
^cpio/[\t\n ]		|
[\t \/]cpio/[\t\n ]	|
^tar/[\t\n ]		|
[\t \/]tar/[\t\n ]	|
^(un)?compress/[\t\n ]	|
[\t \/](un)?compress/[\t\n ]	|
^rmdir/[\t\n ]		|
[\t \/]rmdir/[\t\n ]	return (ROOT_D);

^r?cp(dir)?/[\t\n ]	|
[\t \/]r?cp(dir)?/[\t\n ]	|
^rm/[\t\n ]	|
[\t \/]rm/[\t\n ]	|
\>[ \t]*[\$\/a-zA-Z0-9]	return (ROOT_M);

%{
/* These root commands may also be locked. */

/* Here we analyze any pkgchk calls. If it's "pkgchk ... -f ..." then that calls for root authority. We then check for a "-R" argument. */
%}
^pkgchk[^\n^|^>^;]*"-f"	|
[\t \/]pkgchk[^\n^|^>^;]*"-f"	{
	status.pkgchk_f = 1;
	REJECT;		/* We need the intermediate args. */
}

%{
/* If it's "pkgchk ... -R ..." then the local package database is not being tested and no database warning is necessary. */
%}
^pkgchk[^\n^|^>^;]*"-R"[ \t][\/\$]/[^ ^\t^\n]		|
[\t \/]pkgchk[^\n^|^>^;]*"-R"[ \t][\/\$]/[^ ^\t^\n]  {
	if (status.pkgchk_f)
		return (ROOT_D);
	else
		return (INITVAL);
}

%{
/* If it's just "pkgchk ..." then we need to mention something about access to the package database. With Solaris 2.5, an improved locking mechanism is in place, so this message may be something we can drop later. */
%}
^pkgchk/[\t\n ]		|
[\t \/]pkgchk/[\t\n ]  {
	if (status.pkgchk_f) {
		status.pkgchk_f = 0;
		return (ROOT_D | PKGDB_M);
	} else
		return (PKGDB_M);
}

%{
/* The installf and removef utilities require root authority, they modify the package database and they must be invoked at least once with a "-f" argument. */

/* First test for a "-f" argument. */
%}
^installf[^\n^|^>^;]*"-f"	|
[\t \/]installf[^\n^|^>^;]*"-f"	{
	status.instf_f = 1;

	REJECT;		/* The whole line needs to be re-reviewed. */
}

^removef[^\n^|^>^;]*"-f"	|
[\t \/]removef[^\n^|^>^;]*"-f"	{
	status.remf_f = 1;

	REJECT;		/* The whole line needs to be re-reviewed. */
}

^installf/[\t\n ]	|
[\t \/]installf/[\t\n ]	{
	status.instf = 1;
	status.needspacefile = 1;

	root_level = ROOT_D;
	lock_level = LOCKED_M;

	BEGIN WHROOT;
}

^removef/[\t\n ]	|
[\t \/]removef/[\t\n ]	{
	status.remf = 1;

	root_level = ROOT_D;
	lock_level = LOCKED_M;
	BEGIN WHROOT;
}

%{
/* There's no question that use of a pkgadd or pkgrm in a script is bound to cause problems unless it is to a different root. */
%}
^pkgadd/[\t\n ]	|
[\t \/]pkgadd/[\t\n ]	|
^pkgrm/[\t\n ]		|
[\t \/]pkgrm/[\t\n ] {
	root_level = ROOT_D;
	lock_level = LOCKED_D;
	BEGIN WHROOT;
}

%{
/* The only way to get here is if we are in the middle of a pkg command. */
%}
<WHROOT>. {
	if (status.pkg_rtn_done) {
		status.pkg_rtn_done = 0;
		BEGIN 0;
	} else
		REJECT;
}
<WHROOT>[ \t]+"-R"[ \t][\/\$]/[^ ^\t^\n] {
	status.pkg_rtn_done = 1;
	return (root_level);		/* "-R" means locking is unlikely. */
}
<WHROOT>[\n]		{
	if (status.pkg_rtn_done) {
		status.pkg_rtn_done = 0;
		line_no++;
		BEGIN 0;
	} else {
		status.pkg_rtn_done = 1;
		unput('\n');
		return (root_level | lock_level); /* No "-R". */
	}
}
<WHROOT>[;|>]		{
	status.pkg_rtn_done = 1;
	return (root_level | lock_level); /* End of command without a "-R". */
}

\n	{ line_no++; status.allow_int = 0; 
#ifdef VERBOSE
	printf("allow_int = 0\n");
#endif
}

.	{
	/*
	XXX - bug - resets prematurely if we pipe into a while loop or
	other such construct
	status.allow_int = 0;
	*/ 
}

%%
#include <stdio.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <libintl.h>

#ifdef DEBUG
/*
 * Since this is a lex specification twice removed from the binary,
 * I strongly recommend leaving the DEBUG portions in place. When new
 * keywords are added, this will be very important. After modifying
 * the specification, create an executable to test in this way.
 *
 *	lex scriptvfy.l
 *	cc -o scriptvfy -g lex.yy.c $ROOT/usr/lib/libpkg.a \
 *	    -DDEBUG [-DVERBOSE] -ll -lintl
 *	scriptvfy test_directory
 */

main(int argc, char *argv[])
{
	int val;

	line_no = 1;

	if (argc == 1) {
		printf("No directory provided.\n");
		exit(1);
	}

	val = checkscripts(argv[1], 0);

	printf("return code is %d\n", val);
}
#endif

/*
 * This function evaluates the provided script and returns a bit string
 * describing what patterns were located.
 */
static int
scripteval(char *script_name, char *script_path, int mask, int silent)
{
	int val = 0;
	int error = 0;
	line_no = 1;

	if ((script_path == NULL) || (*script_path == '\0') ||
	    (script_name == NULL)) {
		logerr(gettext(ERR_ARGS));
		return (0);
	}

#ifdef VERBOSE
	printf("Evaluating %s\n", script_path);
#endif

	if ((scr_fp = fopen(script_path, "r")) == NULL) {
		logerr(gettext(ERR_FOPEN), script_path, errno);
		return (0);
	}

#ifdef VERBOSE
	printf("Opened script\n");
#endif

	while (val = yylex()) {
#ifdef VERBOSE
		printf("  Match is %s, returned 0x%x at line %d\n",
		    yytext, val, line_no);
		printf("    in_function = %d, in_awk = %d, in_loop = %d, " \
		    "in_case = %d, in_if = %d, in_pipe = %d\n",
		    status.in_function, status.in_awk, status.in_loop,
		    status.in_case, status.in_if, status.in_pipe);
		printf("    loop_depth = %d, case_depth = %d, " \
		    "if_depth = %d, pipe_release = %d, cur_level = %d\n",
		    loop_depth, case_depth, if_depth, pipe_release, cur_level);
#endif

		val &= mask;
		if (val) {
			error |= ((val & MAYBE_ONLY) ? 1 : 2);

			/*
			 * So at this point, val contains all status bits
			 * appropriate to this script.
			 */
			if (!silent) {
				char *msg_ptr;
				if (val & INTERACT_D)
					msg_ptr = gettext(ERR_INTERACT);
				else if (val & ROOT_D)
					msg_ptr = gettext(ERR_ROOT);
				else if (val & LOCKED_D)
					msg_ptr = gettext(ERR_LOCKED);
				else if (val & INTERACT_M)
					msg_ptr = gettext(WRN_INTERACT);
				else if (val & ROOT_M)
					msg_ptr = gettext(WRN_ROOT);
				else if (val & LOCKED_M)
					msg_ptr = gettext(WRN_LOCKED);
				else if (val & WPARM1_M)
					msg_ptr = gettext(WRN_FORM_USE);
				else if (val & USEPARM1_M)
					msg_ptr = gettext(WRN_FORM_USE);
				else if (val &  ODDPARM_M)
					msg_ptr = gettext(WRN_FORM_ARG);
				else if (val &  PKGDB_M)
					msg_ptr = gettext(WRN_TRANSDB);
				else
					msg_ptr = gettext("unknown error");

				logerr(msg_ptr, script_name, line_no);
			}
		}
	}

	/* Warn if required about missing "-f" calls. */
	if (status.instf && !(status.instf_f))
		logerr(gettext(WRN_INST_F), script_name);

	if (status.remf && !(status.remf_f))
		logerr(gettext(WRN_REM_F), script_name);

	status.instf = status.instf_f = status.remf = status.remf_f = 0;

	/* Warn if installf was used but no space file is in place. */
	if (status.nospacefile && status.needspacefile) {
		logerr(gettext(WRN_SPACEACC), script_name);
		status.needspacefile = 0;
	}

	status.in_pipe = 0;	/* Pipes may dangle. */
	fclose(scr_fp);

	if (error == 3)
		error = 2;

	return (error);
}

/* Test a preinstall or preremove script for validity. */
int
pre_valid(char *script_name, char *script_path, int silent)
{
	return (scripteval(script_name, script_path, PRE_MASK, silent));
}

/* Test a class action script for validity. */
int
cas_valid(char *script_name, char *script_path, int silent)
{
	return (scripteval(script_name, script_path, CAS_MASK, silent));
}

/* Test a postinstall or postremove script for validity. */
int
post_valid(char *script_name, char *script_path, int silent)
{
	return (scripteval(script_name, script_path, POST_MASK, silent));
}

/* Test a class action script for validity. */
int
req_valid(char *script_name, char *script_path, int silent)
{
	return (scripteval(script_name, script_path, REQ_MASK, silent));
}


/* Test a class action script for validity. */
int
chk_valid(char *script_name, char *script_path, int silent)
{
	return (scripteval(script_name, script_path, CHK_MASK, silent));
}

/* This tests all of the scripts in the provided directory. */
int
checkscripts(char *inst_dir, int silent)
{
	DIR *dirfp;
	struct dirent *dp;
	char path[PATH_MAX];
	int retval = 0;

	/* For future reference, determine if a space file is present. */
	sprintf(path, "%s/%s", inst_dir, "space");
	if (access(path, F_OK) != 0)
		status.nospacefile = 1;

	if ((dirfp = opendir(inst_dir)) == NULL)
		return (0);

	while ((dp = readdir(dirfp)) != NULL) {
#ifdef VERBOSE
		printf("Looking at file %s\n", dp->d_name);
#endif
#ifdef BUG_DEBUG
		if ((status.in_function != 0)
		    || (status.in_pipe != 0)
		    || (status.in_loop != 0)
		    || (status.in_case != 0)
		    || (status.in_if != 0)
		    || (status.in_awk != 0)
		    || (pipe_release != 0)
		    || (loop_depth != 0)
		    || (case_depth != 0)
		    || (if_depth != 0)
		    || (cur_level != 0)
		    || (braces != 0)) {
			printf("    in_function = %d, in_awk = %d, "
			    "in_loop = %d, in_case = %d, in_if = %d, "
			    "in_pipe = %d\n",
			    status.in_function, status.in_awk, status.in_loop,
			    status.in_case, status.in_if, status.in_pipe);
			printf("    loop_depth = %d, case_depth = %d, "
			    "if_depth = %d, pipe_release = %d, "
			    "cur_level = %d\n",
			    loop_depth, case_depth, if_depth, pipe_release,
			    cur_level);
			printf("ERROR: found a bug: variable still open\n");
			return (0);
		} else {
			printf("SUCCESS: All variables reset.\n");
		}
#endif
		/* Reset all variables before processing the next file */
		status.in_function = status.in_pipe = status.in_loop =
		    status.in_case = status.in_if = status.in_awk = 0;
		pipe_release = loop_depth = case_depth = if_depth =
		    cur_level = braces = 0;

		if (dp->d_name[0] == '.')
			continue;

		if ((strcmp(dp->d_name, "preinstall") == 0) ||
		    (strcmp(dp->d_name, "preremove") == 0)) {
			sprintf(path, "%s/%s", inst_dir, dp->d_name);
			retval |= pre_valid(dp->d_name, path, silent);
			continue;
		}

		if ((strncmp(dp->d_name, "i.", 2) == 0) ||
		    (strncmp(dp->d_name, "r.", 2) == 0)) {
			sprintf(path, "%s/%s", inst_dir, dp->d_name);
			retval |= cas_valid(dp->d_name, path, silent);
			continue;
		}

		if ((strcmp(dp->d_name, "postinstall") == 0) ||
		    (strcmp(dp->d_name, "postremove") == 0)) {
			sprintf(path, "%s/%s", inst_dir, dp->d_name);
			retval |= post_valid(dp->d_name, path, silent);
			continue;
		}

		if (strcmp(dp->d_name, "request") == 0) {
			sprintf(path, "%s/%s", inst_dir, dp->d_name);
			retval |= req_valid(dp->d_name, path, silent);
			continue;
		}
		if (strcmp(dp->d_name, "checkinstall") == 0) {
			sprintf(path, "%s/%s", inst_dir, dp->d_name);
			retval |= chk_valid(dp->d_name, path, silent);
			continue;
		}
	}

	(void) closedir(dirfp);

	return (retval);
}
