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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * i2c, SMBus, and i3c administration
 */

#include <stdlib.h>
#include <strings.h>
#include <stdio.h>
#include <stdarg.h>
#include <err.h>
#include <libgen.h>
#include <sys/sysmacros.h>

#include "i2cadm.h"

i2cadm_t i2cadm;

/*
 * The number of devices per line for the pretty printed address table.
 */
#define	DEVS_PER_LINE	16

void
i2cadm_print_table(const i2cadm_table_t *table, void *arg)
{
	bool post = false;

	(void) printf("%s %s:\n\n%s\n", table->table_msg, table->table_port,
	    table->table_key);

	(void) printf("ADDR");
	for (uint32_t i = 0; i < DEVS_PER_LINE; i++) {
		(void) printf("%s0x%x", i != 0 ? " " : "\t", i);
	}
	(void) printf("\n");
	for (uint16_t i = 0; i < table->table_max; i++) {
		bool line_start = (i % DEVS_PER_LINE) == 0;

		if (line_start) {
			if (table->table_max > UINT8_MAX) {
				(void) printf("0x%03x\t", i);
			} else {
				(void) printf("0x%02x\t", i);
			}
		}

		if (!line_start) {
			(void) printf(" ");
		}

		if (table->table_cb(arg, i))
			post = true;

		if ((i % DEVS_PER_LINE) == DEVS_PER_LINE - 1) {
			(void) printf("\n");
		}
	}

	if (post) {
		table->table_post(arg, table->table_max);
	}
}

static void
i2cadm_vwarn(const char *fmt, va_list ap)
{
	i2c_hdl_t *hdl = i2cadm.i2c_hdl;

	(void) fprintf(stderr, "i2cadm: ");
	(void) vfprintf(stderr, fmt, ap);
	(void) fprintf(stderr, ": %s: %s (libi2c: 0x%x, sys: %d)\n",
	    i2c_errmsg(hdl), i2c_errtostr(hdl, i2c_err(hdl)),
	    i2c_err(hdl), i2c_syserr(hdl));
}

void
i2cadm_warn(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i2cadm_vwarn(fmt, ap);
	va_end(ap);
}

void __NORETURN
i2cadm_fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	i2cadm_vwarn(fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

void
i2cadm_ofmt_errx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrx(EXIT_FAILURE, fmt, ap);
}

void
i2cadm_walk_usage(const i2cadm_cmdtab_t *tab, size_t len, FILE *f)
{
	for (size_t i = 0; i < len; i++) {
		tab[i].icmd_use(f);
	}
}

static void
i2cadm_usage(const i2cadm_cmdtab_t *tab, size_t len, const char *format, ...)
{
	if (format != NULL) {
		va_list ap;

		va_start(ap, format);
		vwarnx(format, ap);
		va_end(ap);
	}

	if (tab == NULL)
		return;

	fprintf(stderr, "Usage: i2cadm <subcommand> <args> ... \n\n");
	i2cadm_walk_usage(tab, len, stderr);
}

int
i2cadm_walk_tab(const i2cadm_cmdtab_t *tab, size_t len, int argc, char *argv[])
{
	if (argc == 0) {
		i2cadm_usage(tab, len, "missing required sub-command");
		return (EXIT_FAILURE);
	}

	for (size_t i = 0; i < len; i++) {
		if (strcmp(argv[0], tab[i].icmd_name) != 0)
			continue;

		argc--;
		argv++;
		optind = 0;
		return (tab[i].icmd_func(argc, argv));
	}

	i2cadm_usage(tab, len, "unknown subcommand %s", argv[0]);
	return (EXIT_USAGE);
}

/*
 * The order commands are listed below impacts the order in usage and help
 * statements. We order these roughly based upon the general operations that one
 * needs to take starting with all operations that list different entities,
 * roughly ordered by importance, followed by operations which operate on the
 * device.
 */
static const i2cadm_cmdtab_t i2cadm_cmds[] = {
	{ "controller", i2cadm_controller, i2cadm_controller_usage },
	{ "device", i2cadm_device, i2cadm_device_usage },
	{ "mux", i2cadm_mux, i2cadm_mux_usage },
	{ "port", i2cadm_port, i2cadm_port_usage },
	{ "io", i2cadm_io, i2cadm_io_usage },
	{ "scan", i2cadm_scan, i2cadm_scan_usage }
};

int
main(int argc, char *argv[])
{
	i2cadm.i2c_progname = basename(argv[0]);

	if (argc < 2) {
		i2cadm_usage(i2cadm_cmds, ARRAY_SIZE(i2cadm_cmds),
		    "missing required sub-command");
		exit(EXIT_USAGE);
	}

	i2cadm.i2c_hdl = i2c_init();
	if (i2cadm.i2c_hdl == NULL) {
		err(EXIT_FAILURE, "failed to initialize libi2c");
	}

	argc--;
	argv++;

	return (i2cadm_walk_tab(i2cadm_cmds, ARRAY_SIZE(i2cadm_cmds), argc,
	    argv));
}
