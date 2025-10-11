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

#ifndef _I2CADM_H
#define	_I2CADM_H

/*
 * Common i2cadm(8) interfaces
 */

#include <stdio.h>
#include <libi2c.h>
#include <sys/ccompile.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EXIT_USAGE	2

typedef struct {
	const char *i2c_progname;
	i2c_hdl_t *i2c_hdl;
} i2cadm_t;

typedef struct i2cadm_cmdtab {
	const char *icmd_name;
	int (*icmd_func)(int, char *[]);
	void (*icmd_use)(FILE *);
} i2cadm_cmdtab_t;

extern i2cadm_t i2cadm;

extern void i2cadm_warn(const char *, ...) __PRINTFLIKE(1);
extern void i2cadm_fatal(const char *, ...) __PRINTFLIKE(1) __NORETURN;
extern void i2cadm_ofmt_errx(const char *, ...) __PRINTFLIKE(1) __NORETURN;

extern void i2cadm_walk_usage(const i2cadm_cmdtab_t *, size_t, FILE *);
extern int i2cadm_walk_tab(const i2cadm_cmdtab_t *, size_t, int, char *[]);

extern int i2cadm_controller(int, char *[]);
extern void i2cadm_controller_usage(FILE *);
extern int i2cadm_mux(int, char *[]);
extern void i2cadm_mux_usage(FILE *);
extern int i2cadm_device(int, char *[]);
extern void i2cadm_device_usage(FILE *);
extern int i2cadm_io(int, char *[]);
extern void i2cadm_io_usage(FILE *);
extern int i2cadm_port(int, char *[]);
extern void i2cadm_port_usage(FILE *);
extern int i2cadm_scan(int, char *[]);
extern void i2cadm_scan_usage(FILE *);

/*
 * Pretty print an address table.
 */
typedef struct {
	const char *table_port;
	const char *table_key;
	const char *table_msg;
	uint16_t table_max;
	bool (*table_cb)(void *, uint16_t);
	void (*table_post)(void *, uint16_t);
} i2cadm_table_t;

extern void i2cadm_print_table(const i2cadm_table_t *, void *);

#ifdef __cplusplus
}
#endif

#endif /* _I2CADM_H */
