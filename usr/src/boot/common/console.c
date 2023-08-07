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
/*
 * Copyright (c) 2019, Joyent, Inc.
 */
#include <sys/cdefs.h>

#include <stand.h>
#include <string.h>

#include "bootstrap.h"
/*
 * Core console support
 */

static int	cons_set(struct env_var *ev, int flags, const void *value);
static int	cons_find(const char *name);
static int	cons_check(const char *string);
static int	cons_change(const char *string, char **);
static int	twiddle_set(struct env_var *ev, int flags, const void *value);

static int	last_input = -1;	/* input device index */

/*
 * With multiple active console devices, return index of last input
 * device, so we can set up os_console variable to denote console
 * device for kernel.
 *
 * Please note, this feature can not really work with UEFI, because
 * efi console input is returned from any device listed in ConIn,
 * and we have no way to check which device from ConIn actually was
 * generating input.
 */
int
cons_inputdev(void)
{
	int	cons;
	int	flags = C_PRESENTIN | C_ACTIVEIN;
	int	active = 0;

	for (cons = 0; consoles[cons] != NULL; cons++)
		if ((consoles[cons]->c_flags & flags) == flags)
			active++;

	/* With just one active console, we will not set os_console */
	if (active == 1)
		return (-1);

	return (last_input);
}

/*
 * Return number of array slots.
 */
uint_t
cons_array_size(void)
{
	uint_t n;

	if (consoles == NULL)
		return (0);

	for (n = 0; consoles[n] != NULL; n++)
		;
	return (n + 1);
}

static void
cons_add_dev(struct console *dev)
{
	uint_t c = cons_array_size();
	uint_t n = 1;
	struct console **tmp;

	if (c == 0)
		n++;
	tmp = realloc(consoles, (c + n) * sizeof (struct console *));
	if (tmp == NULL)
		return;
	if (c > 0)
		c--;
	consoles = tmp;
	consoles[c] = dev;
	consoles[c + 1] = NULL;
}

/*
 * Detect possible console(s) to use.  If preferred console(s) have been
 * specified, mark them as active. Else, mark the first probed console
 * as active.  Also create the console variable.
 */
void
cons_probe(void)
{
	int	cons;
	int	active;
	char	*prefconsole, *list, *console;

	/* Build list of consoles */
	consoles = NULL;
	for (cons = 0;; cons++) {
		if (ct_list[cons].ct_dev != NULL) {
			cons_add_dev(ct_list[cons].ct_dev);
			continue;
		}
		if (ct_list[cons].ct_init != NULL) {
			ct_list[cons].ct_init();
			continue;
		}
		break;
	}

	/* We want a callback to install the new value when this var changes. */
	env_setenv("twiddle_divisor", EV_VOLATILE, "1", twiddle_set,
	    env_nounset);

	/* Do all console probes */
	for (cons = 0; consoles[cons] != NULL; cons++) {
		consoles[cons]->c_flags = 0;
		consoles[cons]->c_probe(consoles[cons]);
	}
	/* Now find the first working one */
	active = -1;
	for (cons = 0; consoles[cons] != NULL; cons++) {
		if (consoles[cons]->c_flags == (C_PRESENTIN | C_PRESENTOUT)) {
			active = cons;
			break;
		}
	}

	/* Force a console even if all probes failed */
	if (active == -1)
		active = 0;

	/* Check to see if a console preference has already been registered */
	list = NULL;
	prefconsole = getenv("console");
	if (prefconsole != NULL)
		prefconsole = strdup(prefconsole);
	if (prefconsole == NULL)
		prefconsole = strdup(consoles[active]->c_name);

	/*
	 * unset "console", we need to create one with callbacks.
	 */
	unsetenv("console");
	cons_change(prefconsole, &list);

	printf("Consoles: ");
	for (cons = 0; consoles[cons] != NULL; cons++)
		if (consoles[cons]->c_flags & (C_ACTIVEIN | C_ACTIVEOUT))
			printf("%s  ", consoles[cons]->c_desc);
	printf("\n");

	if (list != NULL)
		console = list;
	else
		console = prefconsole;

	env_setenv("console", EV_VOLATILE, console, cons_set,
	    env_nounset);

	free(prefconsole);
	free(list);
}

void
cons_mode(int raw)
{
	int	cons;

	for (cons = 0; consoles[cons] != NULL; cons++) {
		if (raw == 0)
			consoles[cons]->c_flags &= ~C_MODERAW;
		else
			consoles[cons]->c_flags |= C_MODERAW;
	}
}

int
getchar(void)
{
	int	cons;
	int	flags = C_PRESENTIN | C_ACTIVEIN;
	int	rv;

	/*
	 * Loop forever polling all active consoles.  Somewhat strangely,
	 * this code expects all ->c_in() implementations to effectively do an
	 * ischar() check first, returning -1 if there's not a char ready.
	 */
	for (;;) {
		for (cons = 0; consoles[cons] != NULL; cons++) {
			if ((consoles[cons]->c_flags & flags) == flags) {
				rv = consoles[cons]->c_in(consoles[cons]);
				if (rv != -1) {
#ifndef EFI
					last_input = cons;
#endif
					return (rv);
				}
			}
		}
		delay(30 * 1000);	/* delay 30ms */
	}
}

int
ischar(void)
{
	int	cons;

	for (cons = 0; consoles[cons] != NULL; cons++)
		if ((consoles[cons]->c_flags & (C_PRESENTIN | C_ACTIVEIN)) ==
		    (C_PRESENTIN | C_ACTIVEIN) &&
		    (consoles[cons]->c_ready(consoles[cons]) != 0))
			return (1);
	return (0);
}

void
putchar(int c)
{
	int	cons;

	/* Expand newlines if not in raw mode */
	for (cons = 0; consoles[cons] != NULL; cons++)
		if ((consoles[cons]->c_flags & (C_PRESENTOUT | C_ACTIVEOUT)) ==
		    (C_PRESENTOUT | C_ACTIVEOUT)) {
			if (c == '\n' &&
			    (consoles[cons]->c_flags & C_MODERAW) == 0)
				consoles[cons]->c_out(consoles[cons], '\r');
			consoles[cons]->c_out(consoles[cons], c);
		}
}

/*
 * Find the console with the specified name.
 */
static int
cons_find(const char *name)
{
	int	cons;

	for (cons = 0; consoles[cons] != NULL; cons++)
		if (strcmp(consoles[cons]->c_name, name) == 0)
			return (cons);
	return (-1);
}

/*
 * Select one or more consoles.
 */
static int
cons_set(struct env_var *ev, int flags, const void *value)
{
	int	ret;
	char	*list;

	if ((value == NULL) || (cons_check(value) == 0)) {
		/*
		 * Return CMD_OK instead of CMD_ERROR to prevent forth syntax
		 * error, which would prevent it processing any further
		 * loader.conf entries.
		 */
		return (CMD_OK);
	}

	list = NULL;
	ret = cons_change(value, &list);
	if (ret != CMD_OK)
		return (ret);

	/*
	 * set console variable.
	 */
	if (list != NULL) {
		(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, list,
		    NULL, NULL);
	} else {
		(void) env_setenv(ev->ev_name, flags | EV_NOHOOK, value,
		    NULL, NULL);
	}
	free(list);
	return (ret);
}

/*
 * Check that at least one the consoles listed in *string is valid
 */
static int
cons_check(const char *string)
{
	int	cons, found, failed;
	char	*curpos, *dup, *next;

	dup = next = strdup(string);
	found = failed = 0;
	while (next != NULL) {
		curpos = strsep(&next, " ,");
		if (*curpos != '\0') {
			cons = cons_find(curpos);
			if (cons == -1) {
				printf("console %s is invalid!\n", curpos);
				failed++;
			} else {
				if ((consoles[cons]->c_flags &
				    (C_PRESENTIN | C_PRESENTOUT)) !=
				    (C_PRESENTIN | C_PRESENTOUT)) {
					failed++;
				} else
					found++;
			}
		}
	}

	free(dup);

	if (found == 0)
		printf("no valid consoles!\n");

	if (found == 0 || failed != 0) {
		printf("Available consoles:\n");
		for (cons = 0; consoles[cons] != NULL; cons++) {
			printf("    %s", consoles[cons]->c_name);
			if (consoles[cons]->c_devinfo != NULL)
				consoles[cons]->c_devinfo(consoles[cons]);
			printf("\n");
		}
	}

	return (found);
}

/*
 * Helper function to build string with list of console names.
 */
static char *
cons_add_list(char *list, const char *value)
{
	char *tmp;

	if (list == NULL)
		return (strdup(value));

	if (asprintf(&tmp, "%s,%s", list, value) > 0) {
		free(list);
		list = tmp;
	}
	return (list);
}

/*
 * Activate all the valid consoles listed in string and disable all others.
 * Return comma separated string with list of activated console names.
 */
static int
cons_change(const char *string, char **list)
{
	int	cons, active, rv;
	char	*curpos, *dup, *next;

	/* Disable all consoles */
	for (cons = 0; consoles[cons] != NULL; cons++) {
		consoles[cons]->c_flags &= ~(C_ACTIVEIN | C_ACTIVEOUT);
	}

	/* Enable selected consoles */
	dup = next = strdup(string);
	active = 0;
	*list = NULL;
	rv = CMD_OK;
	while (next != NULL) {
		curpos = strsep(&next, " ,");
		if (*curpos == '\0')
			continue;
		cons = cons_find(curpos);
		if (cons >= 0) {
			consoles[cons]->c_flags |= C_ACTIVEIN | C_ACTIVEOUT;
			consoles[cons]->c_init(consoles[cons], 0);
			if ((consoles[cons]->c_flags &
			    (C_ACTIVEIN | C_ACTIVEOUT)) ==
			    (C_ACTIVEIN | C_ACTIVEOUT)) {
				active++;
				*list = cons_add_list(*list, curpos);
				continue;
			}
		}
	}

	free(dup);

	if (active == 0) {
		/*
		 * All requested consoles failed to initialise, try to recover.
		 */
		for (cons = 0; consoles[cons] != NULL; cons++) {
			consoles[cons]->c_flags |= C_ACTIVEIN | C_ACTIVEOUT;
			consoles[cons]->c_init(consoles[cons], 0);
			if ((consoles[cons]->c_flags &
			    (C_ACTIVEIN | C_ACTIVEOUT)) ==
			    (C_ACTIVEIN | C_ACTIVEOUT)) {
				active++;
				*list = cons_add_list(*list,
				    consoles[cons]->c_name);
			}
		}

		if (active == 0)
			rv = CMD_ERROR; /* Recovery failed. */
	}

	return (rv);
}

/*
 * Change the twiddle divisor.
 *
 * The user can set the twiddle_divisor variable to directly control how fast
 * the progress twiddle spins, useful for folks with slow serial consoles.  The
 * code to monitor changes to the variable and propagate them to the twiddle
 * routines has to live somewhere.  Twiddling is console-related so it's here.
 */
static int
twiddle_set(struct env_var *ev, int flags, const void *value)
{
	ulong_t tdiv;
	char *eptr;

	tdiv = strtoul(value, &eptr, 0);
	if (*(const char *)value == 0 || *eptr != 0) {
		printf("invalid twiddle_divisor '%s'\n", (const char *)value);
		return (CMD_ERROR);
	}
	twiddle_divisor((uint_t)tdiv);
	env_setenv(ev->ev_name, flags | EV_NOHOOK, value, NULL, NULL);

	return (CMD_OK);
}

COMMAND_SET(console, "console", "console info", command_console);

static int
command_console(int argc, char *argv[])
{
	if (argc > 1)
		printf("%s: list info about available consoles\n", argv[0]);

	printf("Current console: %s\n", getenv("console"));
	printf("Available consoles:\n");
	for (int cons = 0; consoles[cons] != NULL; cons++) {
		printf("    %s", consoles[cons]->c_name);
		if (consoles[cons]->c_devinfo != NULL)
			consoles[cons]->c_devinfo(consoles[cons]);
		printf("\n");
	}

	return (CMD_OK);
}
