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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * The MDB command buffer is a simple structure that keeps track of the
 * command history list, and provides operations to manipulate the current
 * buffer according to the various emacs editing options.  The terminal
 * code uses this code to keep track of the actual contents of the command
 * line, and then uses this content to perform redraw operations.
 */

#include <strings.h>
#include <stdio.h>
#include <ctype.h>

#include <mdb/mdb_modapi.h>
#include <mdb/mdb_cmdbuf.h>
#include <mdb/mdb_debug.h>
#include <mdb/mdb.h>

#define	CMDBUF_LINELEN	BUFSIZ		/* Length of each buffer line */
#define	CMDBUF_TABLEN	8		/* Length of a tab in spaces */

static void
cmdbuf_shiftr(mdb_cmdbuf_t *cmd, size_t nbytes)
{
	bcopy(&cmd->cmd_buf[cmd->cmd_bufidx],
	    &cmd->cmd_buf[cmd->cmd_bufidx + nbytes],
	    cmd->cmd_buflen - cmd->cmd_bufidx);
}

static void
mdb_cmdbuf_allocchunk(mdb_cmdbuf_t *cmd)
{
	int i;
	char **newhistory;
	ssize_t newhalloc = cmd->cmd_halloc + MDB_DEF_HISTLEN;

	if (newhalloc > cmd->cmd_histlen)
		newhalloc = cmd->cmd_histlen;
	newhistory = mdb_alloc(newhalloc * sizeof (char *), UM_SLEEP);
	bcopy(cmd->cmd_history, newhistory, cmd->cmd_halloc * sizeof (char *));
	mdb_free(cmd->cmd_history, cmd->cmd_halloc * sizeof (char *));
	for (i = cmd->cmd_halloc; i < newhalloc; i++)
		newhistory[i] = mdb_alloc(CMDBUF_LINELEN, UM_SLEEP);
	cmd->cmd_history = newhistory;
	cmd->cmd_halloc = newhalloc;
}

void
mdb_cmdbuf_create(mdb_cmdbuf_t *cmd)
{
	size_t i;

	cmd->cmd_halloc = MDB_DEF_HISTLEN < mdb.m_histlen ?
	    MDB_DEF_HISTLEN : mdb.m_histlen;

	cmd->cmd_history = mdb_alloc(cmd->cmd_halloc * sizeof (char *),
	    UM_SLEEP);
	cmd->cmd_linebuf = mdb_alloc(CMDBUF_LINELEN, UM_SLEEP);

	for (i = 0; i < cmd->cmd_halloc; i++)
		cmd->cmd_history[i] = mdb_alloc(CMDBUF_LINELEN, UM_SLEEP);

	cmd->cmd_buf = cmd->cmd_history[0];
	cmd->cmd_linelen = CMDBUF_LINELEN;
	cmd->cmd_histlen = mdb.m_histlen;
	cmd->cmd_buflen = 0;
	cmd->cmd_bufidx = 0;
	cmd->cmd_hold = 0;
	cmd->cmd_hnew = 0;
	cmd->cmd_hcur = 0;
	cmd->cmd_hlen = 0;
}

void
mdb_cmdbuf_destroy(mdb_cmdbuf_t *cmd)
{
	size_t i;

	for (i = 0; i < cmd->cmd_halloc; i++)
		mdb_free(cmd->cmd_history[i], CMDBUF_LINELEN);

	mdb_free(cmd->cmd_linebuf, CMDBUF_LINELEN);
	mdb_free(cmd->cmd_history, cmd->cmd_halloc * sizeof (char *));
}

int
mdb_cmdbuf_caninsert(mdb_cmdbuf_t *cmd, size_t nbytes)
{
	return (cmd->cmd_buflen + nbytes < cmd->cmd_linelen);
}

int
mdb_cmdbuf_atstart(mdb_cmdbuf_t *cmd)
{
	return (cmd->cmd_bufidx == 0);
}

int
mdb_cmdbuf_atend(mdb_cmdbuf_t *cmd)
{
	return (cmd->cmd_bufidx == cmd->cmd_buflen);
}

int
mdb_cmdbuf_insert(mdb_cmdbuf_t *cmd, int c)
{
	if (c == '\t') {
		if (cmd->cmd_buflen + CMDBUF_TABLEN < cmd->cmd_linelen) {
			int i;

			if (cmd->cmd_buflen != cmd->cmd_bufidx)
				cmdbuf_shiftr(cmd, CMDBUF_TABLEN);

			for (i = 0; i < CMDBUF_TABLEN; i++)
				cmd->cmd_buf[cmd->cmd_bufidx++] = ' ';

			cmd->cmd_buflen += CMDBUF_TABLEN;
			return (0);
		}

		return (-1);
	}

	if (c < ' ' || c > '~')
		return (-1);

	if (cmd->cmd_buflen < cmd->cmd_linelen) {
		if (cmd->cmd_buflen != cmd->cmd_bufidx)
			cmdbuf_shiftr(cmd, 1);

		cmd->cmd_buf[cmd->cmd_bufidx++] = (char)c;
		cmd->cmd_buflen++;

		return (0);
	}

	return (-1);
}

const char *
mdb_cmdbuf_accept(mdb_cmdbuf_t *cmd)
{
	if (cmd->cmd_bufidx < cmd->cmd_linelen) {
		int is_repeating = 0;

		cmd->cmd_buf[cmd->cmd_buflen++] = '\0';
		(void) strcpy(cmd->cmd_linebuf, cmd->cmd_buf);

		if (cmd->cmd_hold != cmd->cmd_hnew) {
			int lastidx = cmd->cmd_hnew == 0 ? cmd->cmd_halloc - 1 :
			    cmd->cmd_hnew - 1;

			is_repeating = strcmp(cmd->cmd_buf,
			    cmd->cmd_history[lastidx]) == 0;
		}

		/*
		 * Don't bother inserting empty or repeating buffers into the
		 * history ring.
		 */
		if (cmd->cmd_buflen > 1 && !is_repeating) {
			cmd->cmd_hnew = (cmd->cmd_hnew + 1) % cmd->cmd_histlen;
			if (cmd->cmd_hnew >= cmd->cmd_halloc)
				mdb_cmdbuf_allocchunk(cmd);

			cmd->cmd_buf = cmd->cmd_history[cmd->cmd_hnew];
			cmd->cmd_hcur = cmd->cmd_hnew;

			if (cmd->cmd_hlen + 1 == cmd->cmd_histlen)
				cmd->cmd_hold =
				    (cmd->cmd_hold + 1) % cmd->cmd_histlen;
			else
				cmd->cmd_hlen++;
		} else if (is_repeating) {
			cmd->cmd_hcur = cmd->cmd_hnew;
		}

		cmd->cmd_bufidx = 0;
		cmd->cmd_buflen = 0;

		return ((const char *)cmd->cmd_linebuf);
	}

	return (NULL);
}

/*ARGSUSED*/
int
mdb_cmdbuf_backspace(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx > 0) {
		if (cmd->cmd_buflen != cmd->cmd_bufidx) {
			bcopy(&cmd->cmd_buf[cmd->cmd_bufidx],
			    &cmd->cmd_buf[cmd->cmd_bufidx - 1],
			    cmd->cmd_buflen - cmd->cmd_bufidx);
		}

		cmd->cmd_bufidx--;
		cmd->cmd_buflen--;

		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_delchar(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx < cmd->cmd_buflen) {
		if (cmd->cmd_bufidx < --cmd->cmd_buflen) {
			bcopy(&cmd->cmd_buf[cmd->cmd_bufidx + 1],
			    &cmd->cmd_buf[cmd->cmd_bufidx],
			    cmd->cmd_buflen - cmd->cmd_bufidx);
		}

		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_fwdchar(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx < cmd->cmd_buflen) {
		cmd->cmd_bufidx++;
		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_backchar(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx > 0) {
		cmd->cmd_bufidx--;
		return (0);
	}

	return (-1);
}

int
mdb_cmdbuf_transpose(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx > 0 && cmd->cmd_buflen > 1) {
		c = cmd->cmd_buf[cmd->cmd_bufidx - 1];

		if (cmd->cmd_bufidx == cmd->cmd_buflen) {
			cmd->cmd_buf[cmd->cmd_bufidx - 1] =
			    cmd->cmd_buf[cmd->cmd_bufidx - 2];
			cmd->cmd_buf[cmd->cmd_bufidx - 2] = (char)c;
		} else {
			cmd->cmd_buf[cmd->cmd_bufidx - 1] =
			    cmd->cmd_buf[cmd->cmd_bufidx];
			cmd->cmd_buf[cmd->cmd_bufidx++] = (char)c;
		}

		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_home(mdb_cmdbuf_t *cmd, int c)
{
	cmd->cmd_bufidx = 0;
	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_end(mdb_cmdbuf_t *cmd, int c)
{
	cmd->cmd_bufidx = cmd->cmd_buflen;
	return (0);
}

static size_t
fwdword_index(mdb_cmdbuf_t *cmd)
{
	size_t i = cmd->cmd_bufidx + 1;

	ASSERT(cmd->cmd_bufidx < cmd->cmd_buflen);

	while (i < cmd->cmd_buflen && isspace(cmd->cmd_buf[i]))
		i++;

	while (i < cmd->cmd_buflen && !isspace(cmd->cmd_buf[i]) &&
	    !isalnum(cmd->cmd_buf[i]) && cmd->cmd_buf[i] != '_')
		i++;

	while (i < cmd->cmd_buflen &&
	    (isalnum(cmd->cmd_buf[i]) || cmd->cmd_buf[i] == '_'))
		i++;

	return (i);
}

/*ARGSUSED*/
int
mdb_cmdbuf_fwdword(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx == cmd->cmd_buflen)
		return (-1);

	cmd->cmd_bufidx = fwdword_index(cmd);

	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_killfwdword(mdb_cmdbuf_t *cmd, int c)
{
	size_t i;

	if (cmd->cmd_bufidx == cmd->cmd_buflen)
		return (-1);

	i = fwdword_index(cmd);

	bcopy(&cmd->cmd_buf[i], &cmd->cmd_buf[cmd->cmd_bufidx],
	    cmd->cmd_buflen - i);

	cmd->cmd_buflen -= i - cmd->cmd_bufidx;

	return (0);
}

static size_t
backword_index(mdb_cmdbuf_t *cmd)
{
	size_t i = cmd->cmd_bufidx - 1;

	ASSERT(cmd->cmd_bufidx != 0);

	while (i != 0 && isspace(cmd->cmd_buf[i]))
		i--;

	while (i != 0 && !isspace(cmd->cmd_buf[i]) &&
	    !isalnum(cmd->cmd_buf[i]) && cmd->cmd_buf[i] != '_')
		i--;

	while (i != 0 && (isalnum(cmd->cmd_buf[i]) || cmd->cmd_buf[i] == '_'))
		i--;

	if (i != 0)
		i++;

	return (i);
}

/*ARGSUSED*/
int
mdb_cmdbuf_backword(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_bufidx == 0)
		return (-1);

	cmd->cmd_bufidx = backword_index(cmd);

	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_killbackword(mdb_cmdbuf_t *cmd, int c)
{
	size_t i;

	if (cmd->cmd_bufidx == 0)
		return (-1);

	i = backword_index(cmd);

	bcopy(&cmd->cmd_buf[cmd->cmd_bufidx], &cmd->cmd_buf[i],
	    cmd->cmd_buflen - cmd->cmd_bufidx);

	cmd->cmd_buflen -= cmd->cmd_bufidx - i;
	cmd->cmd_bufidx = i;

	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_kill(mdb_cmdbuf_t *cmd, int c)
{
	cmd->cmd_buflen = cmd->cmd_bufidx;
	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_reset(mdb_cmdbuf_t *cmd, int c)
{
	cmd->cmd_buflen = 0;
	cmd->cmd_bufidx = 0;
	return (0);
}

/*ARGSUSED*/
int
mdb_cmdbuf_prevhist(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_hcur != cmd->cmd_hold) {
		if (cmd->cmd_hcur-- == cmd->cmd_hnew) {
			cmd->cmd_buf[cmd->cmd_buflen] = 0;
			(void) strcpy(cmd->cmd_linebuf, cmd->cmd_buf);
		}

		if (cmd->cmd_hcur < 0)
			cmd->cmd_hcur = cmd->cmd_halloc - 1;

		(void) strcpy(cmd->cmd_buf, cmd->cmd_history[cmd->cmd_hcur]);
		cmd->cmd_bufidx = strlen(cmd->cmd_buf);
		cmd->cmd_buflen = cmd->cmd_bufidx;

		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_nexthist(mdb_cmdbuf_t *cmd, int c)
{
	if (cmd->cmd_hcur != cmd->cmd_hnew) {
		cmd->cmd_hcur = (cmd->cmd_hcur + 1) % cmd->cmd_halloc;

		if (cmd->cmd_hcur == cmd->cmd_hnew) {
			(void) strcpy(cmd->cmd_buf, cmd->cmd_linebuf);
		} else {
			(void) strcpy(cmd->cmd_buf,
			    cmd->cmd_history[cmd->cmd_hcur]);
		}

		cmd->cmd_bufidx = strlen(cmd->cmd_buf);
		cmd->cmd_buflen = cmd->cmd_bufidx;

		return (0);
	}

	return (-1);
}

/*ARGSUSED*/
int
mdb_cmdbuf_findhist(mdb_cmdbuf_t *cmd, int c)
{
	ssize_t i, n;

	if (cmd->cmd_buflen != 0) {
		cmd->cmd_hcur = cmd->cmd_hnew;
		cmd->cmd_buf[cmd->cmd_buflen] = 0;
		(void) strcpy(cmd->cmd_linebuf, cmd->cmd_buf);
	}

	for (i = cmd->cmd_hcur, n = 0; n < cmd->cmd_hlen; n++) {
		if (--i < 0)
			i = cmd->cmd_halloc - 1;

		if (strstr(cmd->cmd_history[i], cmd->cmd_linebuf) != NULL) {
			(void) strcpy(cmd->cmd_buf, cmd->cmd_history[i]);
			cmd->cmd_bufidx = strlen(cmd->cmd_buf);
			cmd->cmd_buflen = cmd->cmd_bufidx;
			cmd->cmd_hcur = i;

			return (0);
		}
	}

	cmd->cmd_hcur = cmd->cmd_hnew;

	cmd->cmd_bufidx = 0;
	cmd->cmd_buflen = 0;

	return (-1);
}
