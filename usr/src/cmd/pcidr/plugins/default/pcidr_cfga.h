/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PCIDR_CFGA_H
#define	_PCIDR_CFGA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <config_admin.h>
#include <pcidr.h>

#ifdef	__cplusplus
extern "C" {
#endif

void pcidr_print_cfga(dlvl_t, cfga_list_data_t *, char *);
char *pcidr_cfga_stat_name(cfga_stat_t);
char *pcidr_cfga_cmd_name(cfga_cmd_t);
char *pcidr_cfga_cond_name(cfga_cond_t);
char *pcidr_cfga_err_name(cfga_err_t);
int pcidr_cfga_do_cmd(cfga_cmd_t, cfga_list_data_t *);

typedef struct {
	dlvl_t dlvl;
	char *prestr;
} pcidr_cfga_msg_data_t;
int pcidr_cfga_msg_func(void *, const char *);
int pcidr_cfga_confirm_func(void *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIDR_CFGA_H */
