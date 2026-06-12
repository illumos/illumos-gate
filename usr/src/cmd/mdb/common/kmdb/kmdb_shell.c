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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

#include <mdb/mdb_shell.h>
#include <mdb/mdb_lex.h>

void
mdb_shell_exec(char *cmd __unused)
{
	yyperror("shell escape facility not available in kmdb\n");
}

void
mdb_shell_pipe(char *cmd __unused)
{
	yyperror("shell pipe facility not available in kmdb\n");
}

void
mdb_shell_source(char *cmd __unused)
{
	yyperror("shell escape facility not available in kmdb\n");
}

void
mdb_shell_pipe_source(char *cmd __unused)
{
	yyperror("shell pipe facility not available in kmdb\n");
}

void
mdb_shell_source_run(void)
{
}

void
mdb_shell_source_discard(void)
{
}

int
mdb_shell_filter(const char *cmd __unused)
{
	yyperror("shell pipe facility not available in kmdb\n");
	return (-1);
}

void
mdb_shell_filter_pump(int fd __unused, mdb_iob_t *iob __unused)
{
}

void
mdb_shell_filter_close(int fd __unused)
{
}

void
mdb_shell_producer(struct mdb_cmd *cp __unused)
{
	yyperror("shell pipe facility not available in kmdb\n");
}
