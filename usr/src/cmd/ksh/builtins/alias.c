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
 * alias.c is a C version of the alias.sh wrapper (which links ksh
 * builtins to commands in /usr/bin/, e.g. calling this wrapper as
 * /usr/bin/alias will call the ksh "alias" builtin, running it as
 * /usr/bin/cut will call the ksh "cut" builtin etc.
 */

#include <shell.h>
#include <nval.h>
#include <stdio.h>

/* Builtin script, original derived from alias.sh */
static const char *script = "\n"
/* Get name of builtin */
"typeset cmd=\"${0##*/}\"\n"
/*
 * If the requested command is not an alias load it explicitly
 * to make sure it is not bound to a path (those built-ins which
 * are mapped via shell aliases point to commands which are
 * "special shell built-ins" which cannot be bound to a specific
 * PATH element) - otherwise we may execute the wrong command
 * if an executable with the same name sits in a PATH element
 * before /usr/bin (e.g. /usr/xpg4/bin/ls would be executed
 * before /usr/bin/ls if the path was something like
 * PATH=/usr/xpg4/bin:/usr/bin).
 */
"if [[ \"${cmd}\" != ~(Elr)(alias|unalias|command) ]] && "
	"! alias \"${cmd}\" >/dev/null 2>&1 ; then\n"
	"builtin \"${cmd}\"\n"
"fi\n"
/* command is a keyword and needs to be handled separately */
"if [[ \"${cmd}\" == \"command\" ]] ; then\n"
	"command \"$@\"\n"
"else\n"
	"\"${cmd}\" \"$@\"\n"
"fi\n"
"exitval=$?";

int
main(int argc, char *argv[])
{
	int i;
	Shell_t *shp;
	Namval_t *np;
	int exitval;

	/*
	 * Create copy of |argv| array shifted by one position to
	 * emulate $ /usr/bin/sh <scriptname> <args1> <arg2> ... #.
	 * First position is set to "/usr/bin/sh" since other
	 * values may trigger special shell modes (e.g. *rsh* will
	 * trigger "restricted" shell mode etc.).
	 */
	char *xargv[argc+2];
	xargv[0] = "/usr/bin/sh";
	xargv[1] = "scriptname";
	for (i = 0; i < argc; i++) {
		xargv[i+1] = argv[i];
	}
	xargv[i+1] = NULL;

	shp = sh_init(argc+1, xargv, 0);
	if (!shp)
		error(ERROR_exit(1), "shell initialisation failed.");
	(void) sh_trap(script, 0);

	np = nv_open("exitval", shp->var_tree, 0);
	if (!np)
		error(ERROR_exit(1), "variable %s not found.", "exitval");
	exitval = (int)nv_getnum(np);
	nv_close(np);

	return (exitval);
}
