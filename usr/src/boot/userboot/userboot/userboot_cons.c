/*
 * Copyright (c) 2011 Google, Inc.
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

#include <stand.h>
#include "bootstrap.h"
#include "libuserboot.h"

int console;

static void userboot_cons_probe(struct console *cp);
static int userboot_cons_init(struct console *, int);
static void userboot_comcons_probe(struct console *cp);
static int userboot_comcons_init(struct console *, int);
static void userboot_cons_putchar(struct console *, int);
static int userboot_cons_getchar(struct console *);
static int userboot_cons_poll(struct console *);

struct console userboot_console = {
	.c_name = "text",
	.c_desc = "userboot",
	.c_flags = 0,
	.c_probe = userboot_cons_probe,
	.c_init = userboot_cons_init,
	.c_out = userboot_cons_putchar,
	.c_in = userboot_cons_getchar,
	.c_ready = userboot_cons_poll,
};

/*
 * Provide a simple alias to allow loader scripts to set the
 * console to comconsole without resulting in an error
 */
struct console userboot_comconsole = {
	.c_name = "ttya",
	.c_desc = "comconsole",
	.c_flags = 0,
	.c_probe = userboot_comcons_probe,
	.c_init = userboot_comcons_init,
	.c_out = userboot_cons_putchar,
	.c_in = userboot_cons_getchar,
	.c_ready = userboot_cons_poll,
};

static void
userboot_cons_probe(struct console *cp)
{

	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
}

static int
userboot_cons_init(struct console *cp __unused, int arg __unused)
{

	return (0);
}

static void
userboot_comcons_probe(struct console *cp __unused)
{
}

static int
userboot_comcons_init(struct console *cp, int arg __unused)
{

	/*
	 * Set the C_PRESENT* flags to allow the comconsole
	 * to be selected as the active console
	 */
	cp->c_flags |= (C_PRESENTIN | C_PRESENTOUT);
	return (0);
}

static void
userboot_cons_putchar(struct console *cp, int c)
{

	/*
	 * if we are ttya and text is enabled, skip output.
	 */
	if (strcmp(cp->c_name, userboot_comconsole.c_name) == 0 &&
	    (userboot_console.c_flags & C_PRESENTOUT) != 0)
		return;

	CALLBACK(putc, c);
}

static int
userboot_cons_getchar(struct console *cp __unused)
{

	/*
	 * if we are ttya and text is enabled, skip input.
	 */
	if (strcmp(cp->c_name, userboot_comconsole.c_name) == 0 &&
	    (userboot_console.c_flags & C_PRESENTIN) != 0)
		return (-1);

	return (CALLBACK(getc));
}

static int
userboot_cons_poll(struct console *cp __unused)
{

	/*
	 * if we are ttya and text is enabled, skip input.
	 */
	if (strcmp(cp->c_name, userboot_comconsole.c_name) == 0 &&
	    (userboot_console.c_flags & C_PRESENTIN) != 0)
		return (0);

	return (CALLBACK(poll));
}
