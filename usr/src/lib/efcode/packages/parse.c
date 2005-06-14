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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

void
byte_loadfile(fcode_env_t *env)
{
	int len;

	load_file(env);
	len = (int) POP(DS);
	if (len) {
		void *ptr = (void *) TOS;
		PUSH(DS, 1);
		byte_load(env);
		FREE(ptr);
	} else {
		drop(env);
	}
}

void
define_hook(fcode_env_t *env, char *name, int len, char *fcimage)
{
	static void (*byteload_ptr)(fcode_env_t *env) = byte_loadfile;

	header(env, name, len, 0);
	COMPILE_TOKEN(&do_colon);
	env->state |= 1;
	PUSH(DS, (fstack_t) fcimage);
	PUSH(DS, strlen(fcimage));
	compile_string(env);
	COMPILE_TOKEN(&byteload_ptr);
	semi(env);
}

/*
 * simple parser for builtin-driver matching.
 *
 * Consists of alias:target<CR>
 * where alias is:
 *	<Key>[;<key>[;<key>]]
 *
 * and target is:
 *	<path to fcode image>
 */

#define	PARSE_LINE	256

static void
line_error(char *where, int line, char *msg)
{
	log_message(MSG_ERROR, "%s:%d: %s\n", where, line, msg);
}

void
make_builtin_hooks(fcode_env_t *env, char *where)
{
	FILE *fd;
	int lnum = 0, len;
	char *buffer, *line, *target, *next;

	if (where == NULL)
		where = "/fcode/aliases";

	if ((fd = fopen(where, "r")) == NULL) {
		return;
	}

	buffer = MALLOC(PARSE_LINE+1);

	while ((line = fgets(buffer, PARSE_LINE, fd)) != NULL) {
		lnum++;
		if ((next = strpbrk(line, " \t#\n")) != NULL)
			*next = '\0';
		if (strlen(line) == 0)
			continue;
		if ((target = strchr(line, ':')) == NULL) {
			line_error(where, lnum, "Badly formed line");
			continue;
		}
		*target++ = 0;
		if (strlen(line) == 0) {
			line_error(where, lnum, "Badly formed alias");
			continue;
		}
		if (strlen(target) == 0) {
			line_error(where, lnum, "Badly formed target");
			continue;
		}
		for (; line; line = next) {
			if ((next = strchr(line, ';')) != NULL)
				*next++ = '\0';
			if (strlen(line) == 0)
				line_error(where, lnum, "Null key in alias");
			else
				define_hook(env, line, strlen(line), target);
		}
	}
	FREE(buffer);
	fclose(fd);
}
