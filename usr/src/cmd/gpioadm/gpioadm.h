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

#ifndef _GPIOADM_H
#define	_GPIOADM_H

/*
 * gpioadm(8) interfaces
 */

#include <sys/ccompile.h>
#include <stdio.h>

#include <libxpio.h>
#include <sys/gpio/kgpio_attr.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	EXIT_USAGE	2

typedef struct {
	const char *gpio_progname;
	xpio_t *gpio_xpio;
} gpioadm_t;

typedef struct gpioadm_cmdtab {
	const char *gpct_name;
	int (*gpct_func)(int, char *[]);
	void (*gpct_use)(FILE *);
} gpioadm_cmdtab_t;

extern gpioadm_t gpioadm;

extern void gpioadm_warn(const char *, ...) __PRINTFLIKE(1);
extern void gpioadm_fatal(const char *, ...) __PRINTFLIKE(1) __NORETURN;
extern void gpioadm_update_fatal(xpio_gpio_update_t *, const char *,
    ...) __PRINTFLIKE(2) __NORETURN;
extern void gpioadm_ofmt_errx(const char *, ...) __PRINTFLIKE(1) __NORETURN;
extern void gpioadm_ctrl_gpio_init(const char *, xpio_ctrl_t **,
    xpio_gpio_info_t **);

extern void gpioadm_walk_usage(const gpioadm_cmdtab_t *, FILE *);
extern int gpioadm_walk_tab(const gpioadm_cmdtab_t *, int, char *[]);

extern int gpioadm_controller(int, char *[]);
extern void gpioadm_controller_usage(FILE *);
extern int gpioadm_dpio(int, char *[]);
extern void gpioadm_dpio_usage(FILE *);
extern int gpioadm_gpio(int, char *[]);
extern void gpioadm_gpio_usage(FILE *);

#ifdef __cplusplus
}
#endif

#endif /* _GPIOADM_H */
