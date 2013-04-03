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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2012 Joyent, Inc.  All rights reserved.
 */

#ifndef	_PRT_CONF_H
#define	_PRT_CONF_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <libdevinfo.h>
#include <pcidb.h>
#include <sys/utsname.h>

extern void init_priv_data(struct di_priv_data *);
extern void dump_priv_data(int, di_node_t);
extern int print_pciid(di_node_t, di_prom_handle_t, pcidb_hdl_t *);
extern void indent_to_level(int);
extern void prtconf_devinfo();
extern int do_fbname();
extern int do_promversion();
extern int do_prom_version64(void);
extern int do_prominfo();
void indent_to_level(int);
extern int do_productinfo();

extern void dprintf(const char *, ...);

struct prt_opts {
	int o_verbose;
	int o_drv_name;
	int o_pseudodevs;
	int o_fbname;
	int o_noheader;
	int o_prominfo;
	int o_productinfo;
	int o_promversion;
	int o_prom_ready64;
	int o_forcecache;
	char *o_devices_path;
	dev_t o_devt;
	int o_target;
	int o_ancestors;
	int o_children;
	int o_pciid;
	const char *o_promdev;
	const char *o_progname;
	struct utsname o_uts;
};

struct prt_dbg {
	int d_debug;
	int d_bydriver;
	int d_forceload;
	char *d_drivername;
};

extern struct prt_opts opts;
extern struct prt_dbg dbg;

#ifdef	__cplusplus
}
#endif

#endif	/* _PRT_CONF_H */
