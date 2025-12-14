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
 * Copyright 2026 Oxide Computer Company
 */

#ifndef _PCIEADM_H
#define	_PCIEADM_H

/*
 * Common definitions for pcieadm(8).
 */

#include <libdevinfo.h>
#include <pcidb.h>
#include <priv.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pcieadm pcieadm_t;

typedef struct pcieadm_cmdtab {
	const char *pct_name;
	int (*pct_func)(pcieadm_t *, int, char **);
	void (*pct_use)(FILE *);
} pcieadm_cmdtab_t;

struct pcieadm {
	uint_t pia_indent;
	di_node_t pia_root;
	const char *pia_devstr;
	di_node_t pia_devi;
	di_node_t pia_nexus;
	pcidb_hdl_t *pia_pcidb;
	const pcieadm_cmdtab_t *pia_cmdtab;
	priv_set_t *pia_priv_init;
	priv_set_t *pia_priv_min;
	priv_set_t *pia_priv_eff;
};

typedef struct {
	void *pdw_arg;
	int (*pdw_func)(di_node_t, void *);
} pcieadm_di_walk_t;

/*
 * Config space related
 */
typedef boolean_t (*pcieadm_cfgspace_f)(uint32_t, uint8_t, void *, void *);
typedef boolean_t (*pcieadm_bar_f)(uint8_t, uint8_t, uint64_t, void *, void *,
    boolean_t);

typedef struct {
	pcieadm_cfgspace_f pop_cfg;
	pcieadm_bar_f pop_bar;
} pcieadm_ops_t;

/*
 * Utilities
 */
extern void pcieadm_di_walk(pcieadm_t *, pcieadm_di_walk_t *);
extern void pcieadm_init_ops_kernel(pcieadm_t *, const pcieadm_ops_t **,
    void **);
extern void pcieadm_fini_ops_kernel(void *);
extern void pcieadm_init_ops_file(pcieadm_t *, const char *,
    const pcieadm_ops_t **, void **);
extern void pcieadm_fini_ops_file(void *);
extern void pcieadm_find_nexus(pcieadm_t *);
extern void pcieadm_find_dip(pcieadm_t *, const char *);

/*
 * Output related
 */
extern const char *pcieadm_progname;
extern void pcieadm_indent(void);
extern void pcieadm_deindent(void);
extern void pcieadm_print(const char *, ...);
extern void pcieadm_ofmt_errx(const char *, ...);

/*
 * Command tabs
 */
extern void pcieadm_walk_usage(const pcieadm_cmdtab_t *, FILE *);
extern int pcieadm_walk_tab(pcieadm_t *, const pcieadm_cmdtab_t *, int,
    char *[]);
extern int pcieadm_bar(pcieadm_t *, int, char *[]);
extern void pcieadm_bar_usage(FILE *);
extern int pcieadm_save_cfgspace(pcieadm_t *, int, char *[]);
extern void pcieadm_save_cfgspace_usage(FILE *);
extern int pcieadm_show_cfgspace(pcieadm_t *, int, char *[]);
extern void pcieadm_show_cfgspace_usage(FILE *);
extern int pcieadm_show_devs(pcieadm_t *, int, char *[]);
extern void pcieadm_show_devs_usage(FILE *);

#define	EXIT_USAGE	2

/*
 * Privilege related. Note there are no centralized functions around raising and
 * lowering privs as that unfortunately makes ROPs more easy to execute.
 */
extern void pcieadm_init_privs(pcieadm_t *);

#ifdef __cplusplus
}
#endif

#endif /* _PCIEADM_H */
