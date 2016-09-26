/*
 * stub main for testing Ficl
 * $Id: main.c,v 1.2 2010/09/10 09:01:28 asau Exp $
 */
/*
 * Copyright (c) 1997-2001 John Sadler (john_sadler@alum.mit.edu)
 * All rights reserved.
 *
 * Get the latest Ficl release at http://ficl.sourceforge.net
 *
 * I am interested in hearing from anyone who uses Ficl. If you have
 * a problem, a success story, a defect, an enhancement request, or
 * if you would like to contribute to the Ficl release, please
 * contact me by email at the address above.
 *
 * L I C E N S E  and  D I S C L A I M E R
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <termios.h>
#include <sys/errno.h>

#include <ficl.h>
#include <ficlplatform/emu.h>
#include <libtecla.h>

#define	LINELEN	1024
#define	HISTORY	2048

static char *
prompt(void)
{
	static char prompt[20]; /* probably too large, but well... */
	char *pr, *p, *cp, *ev;
	int n = 0;

	if ((cp = getenv("prompt")) == NULL)
		cp = ">";
	pr = p = strdup(cp);

	while (*p != 0) {
		if ((*p == '$') && (*(p+1) == '{')) {
			for (cp = p + 2; (*cp != 0) && (*cp != '}'); cp++)
				;
			*cp = 0;
			ev = getenv(p + 2);

			if (ev != NULL)
				n = sprintf(prompt+n, "%s", ev);
			p = cp + 1;
			continue;
		}
		prompt[n++] = *p;
		p++;
	}
	if (prompt[n - 1] != ' ')
		prompt[n++] = ' ';
	prompt[n] = '\0';
	free(pr);
	return (prompt);
}

int
main(int argc, char **argv)
{
	int returnValue = 0;
	char *buffer;
	GetLine *gl;
	ficlVm *vm;
	struct winsize ws;
	int cols = 80, rows = 24;

	if (ioctl(1, TIOCGWINSZ, &ws) != -1) {
		if (ws.ws_col)
			cols = ws.ws_col;
		if (ws.ws_row)
			rows = ws.ws_row;
	}

	clearenv();
	asprintf(&buffer, "%d", cols);
	setenv("COLUMNS", buffer, 1);
	free(buffer);
	asprintf(&buffer, "%d", rows);
	setenv("LINES", buffer, 1);
	free(buffer);

	if (getenv("prompt") == NULL)
		setenv("prompt", "${interpret}", 1);
	if (getenv("interpret") == NULL)
		setenv("interpret", "ok", 1);

	if ((vm = bf_init("", NULL)) == NULL)
		return (ENOMEM);
	returnValue = ficlVmEvaluate(vm, ".ver .( " __DATE__ " ) cr quit");

	/*
	 * load files specified on command-line
	 */
	if (argc  > 1) {
		asprintf(&buffer, ".( loading %s ) cr include %s\n cr",
		    argv[1], argv[1]);
		returnValue = ficlVmEvaluate(vm, buffer);
		free(buffer);
	}

	if ((gl = new_GetLine(LINELEN, HISTORY)) == NULL) {
		bf_fini();
		return (ENOMEM);
	}

	while (returnValue != FICL_VM_STATUS_USER_EXIT) {
		if ((buffer = gl_get_line(gl, prompt(), NULL, -1)) == NULL)
			break;
		returnValue = bf_run(buffer);
	}

	gl = del_GetLine(gl);
	bf_fini();
	return (returnValue);
}
