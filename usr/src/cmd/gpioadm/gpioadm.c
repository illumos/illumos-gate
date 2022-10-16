/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This command implements the basics of administering general purpose and
 * dedicated purpose I/O (GPIO and DPIO).
 */

#include <string.h>
#include <err.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ofmt.h>
#include <libdevinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/debug.h>
#include <libgen.h>

#include "gpioadm.h"

gpioadm_t gpioadm;

static void
gpioadm_vwarn(const char *fmt, va_list ap)
{
	xpio_t *xpio = gpioadm.gpio_xpio;

	(void) fprintf(stderr, "%s: ", gpioadm.gpio_progname);
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libxpio: 0x%x, sys: %u)\n",
	    xpio_errmsg(xpio), xpio_err2str(xpio, xpio_err(xpio)),
	    xpio_err(xpio), xpio_syserr(xpio));
}

void
gpioadm_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	gpioadm_vwarn(fmt, ap);
	va_end(ap);
}

void __NORETURN
gpioadm_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	gpioadm_vwarn(fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void __NORETURN
gpioadm_update_fatal(xpio_gpio_update_t *update, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	(void) fprintf(stderr, "%s: ", gpioadm.gpio_progname);
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libxpio: 0x%x, sys: %u)\n",
	    xpio_update_errmsg(update),
	    xpio_update_err2str(update, xpio_update_err(update)),
	    xpio_update_err(update), xpio_update_syserr(update));
	va_end(ap);

	exit(EXIT_FAILURE);
}
void
gpioadm_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

void
gpioadm_ctrl_gpio_init(const char *target, xpio_ctrl_t **ctrlp,
    xpio_gpio_info_t **gpiop)
{
	char *eptr, *slash, *dup;
	const char *ctrl_name, *gpio_name;
	uint32_t gpio_num;
	xpio_ctrl_t *ctrl;
	xpio_gpio_info_t *gpio;

	dup = strdup(target);
	if (dup == NULL) {
		err(EXIT_FAILURE, "failed to allocate memory for target string "
		    "processing");
	}

	slash = strchr(dup, '/');
	if (slash == NULL) {
		errx(EXIT_FAILURE, "invalid target: %s, missing '/' delimiter "
		    "to separate controller and gpio", target);
	}
	ctrl_name = dup;
	gpio_name = slash + 1;
	*slash = '\0';

	if (!xpio_ctrl_init_by_name(gpioadm.gpio_xpio, ctrl_name, &ctrl)) {
		gpioadm_fatal("failed to initialize gpio controller %s",
		    ctrl_name);
	}

	/*
	 * We always attempt to look up and translate the name to a GPIO ID
	 * first. This way if a controller does something like just name the
	 * pins 1, 2, 3, 4, etc. but has a weird relationship to the IDs, we're
	 * more likely to get what the user intended (hopefully).
	 */
	if (!xpio_gpio_lookup_id(ctrl, gpio_name, &gpio_num)) {
		long long l;

		if (xpio_err(gpioadm.gpio_xpio) != XPIO_ERR_NO_LOOKUP_MATCH) {
			gpioadm_fatal("failed to look up name %s on "
			    "controller %s", ctrl_name, gpio_name);
		}

		/*
		 * At this point, attempt to parse it as an intger.
		 */
		errno = 0;
		l = strtoll(gpio_name, &eptr, 0);
		if (errno != 0 || *eptr != '\0') {
			errx(EXIT_FAILURE, "failed to parse gpio number: %s",
			    gpio_name);
		}

		if (l < 0 || l > UINT32_MAX) {
			errx(EXIT_FAILURE, "gpio number is outside of valid "
			    "range: %s", gpio_name);
		}
		gpio_num = (uint32_t)l;
	}

	if (!xpio_gpio_info(ctrl, gpio_num, &gpio)) {
		gpioadm_fatal("failed to get gpio %u on controller %s",
		    gpio_num, ctrl_name);
	}

	*gpiop = gpio;
	*ctrlp = ctrl;
	free(dup);
}

void
gpioadm_walk_usage(const gpioadm_cmdtab_t *tab, FILE *f)
{
	for (; tab->gpct_name != NULL; tab++) {
		tab->gpct_use(f);
	}
}

static void
gpioadm_usage(const gpioadm_cmdtab_t *tab, const char *format, ...)
{
	if (format != NULL) {
		va_list ap;

		va_start(ap, format);
		vwarnx(format, ap);
		va_end(ap);
	}

	if (tab == NULL)
		return;

	fprintf(stderr, "Usage: gpioadm <subcommand> <args> ... \n\n");
	gpioadm_walk_usage(tab, stderr);
}

int
gpioadm_walk_tab(const gpioadm_cmdtab_t *tab, int argc, char *argv[])
{
	uint32_t cmd;

	if (argc == 0) {
		gpioadm_usage(tab, "missing required sub-command");
		return (EXIT_FAILURE);
	}

	for (cmd = 0; tab[cmd].gpct_name != NULL; cmd++) {
		if (strcmp(argv[0], tab[cmd].gpct_name) == 0) {
			break;
		}
	}

	if (tab[cmd].gpct_name == NULL) {
		gpioadm_usage(tab, "unknown subcommand %s", argv[0]);
		return (EXIT_USAGE);
	}

	argc--;
	argv++;
	optind = 0;

	return (tab[cmd].gpct_func(argc, argv));
}

static const gpioadm_cmdtab_t gpioadm_cmds[] = {
	{ "controller", gpioadm_controller, gpioadm_controller_usage },
	{ "dpio", gpioadm_dpio, gpioadm_dpio_usage },
	{ "gpio", gpioadm_gpio, gpioadm_gpio_usage },
	{ NULL, NULL, NULL }
};

int
main(int argc, char *argv[])
{
	gpioadm.gpio_progname = basename(argv[0]);

	if (argc < 2) {
		gpioadm_usage(gpioadm_cmds, "missing required sub-command");
		exit(EXIT_USAGE);
	}

	argc--;
	argv++;
	gpioadm.gpio_xpio = xpio_init();

	if (gpioadm.gpio_xpio == NULL) {
		err(EXIT_FAILURE, "failed to initialize libxpio");
	}

	return (gpioadm_walk_tab(gpioadm_cmds, argc, argv));
}
