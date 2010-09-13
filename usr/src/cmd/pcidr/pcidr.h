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

#ifndef	_PCIDR_H
#define	_PCIDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <libnvpair.h>
#include <config_admin.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PCIDR_MALLOC_CNT	5
#define	PCIDR_MALLOC_TIME	1000000

/* .._SYM and .._SYMSTR must match */
#define	PCIDR_PLUGIN_SYM	pcidr_event_handler
#define	PCIDR_PLUGIN_SYMSTR	"pcidr_event_handler"
#define	PCIDR_PLUGIN_NAME	"pcidr_plugin.so"


/*
 * these ATTRNM_* correspond to the built-in sysevent.conf macros
 * Note that the "publisher" macro used by syseventd is only a subset (third
 * colon-delimited field) of the full publisher-id string specified in an
 * event buffer/message.
 */
#define	ATTRNM_CLASS	"class"
#define	ATTRNM_SUBCLASS	"subclass"
#define	ATTRNM_PUB_NAME	"publisher"

/* be sure to match with dpritab! */
typedef enum {DNONE = 0, DWARN, DINFO, DDEBUG} dlvl_t;
#define	MIN_DLVL DNONE
#define	MAX_DLVL DDEBUG

/* default set of DR attributes */
typedef struct {
	char *class;
	char *subclass;
	char *pub_name;
	char *dr_req_type;
	char *dr_ap_id;
} pcidr_attrs_t;


typedef struct {
	dlvl_t dlvl;
	char *prg;
	FILE *dfp;
	int dsys;
} pcidr_logopt_t;

typedef struct {
	pcidr_logopt_t logopt;
} pcidr_opt_t;

typedef int(*pcidr_plugin_t)(nvlist_t *, pcidr_opt_t *);
#define	PCIDR_PLUGIN_PROTO(a, b)	\
	int PCIDR_PLUGIN_SYM(nvlist_t *a, pcidr_opt_t *b)


void *pcidr_malloc(size_t);
void dprint(dlvl_t, char *, ...);
int pcidr_name2type(char *, data_type_t *);
void pcidr_print_attrlist(dlvl_t, nvlist_t *, char *);
int pcidr_check_string(char *, ...);
int pcidr_get_attrs(nvlist_t *, pcidr_attrs_t *);
int pcidr_check_attrs(pcidr_attrs_t *);
void pcidr_set_logopt(pcidr_logopt_t *);

extern dlvl_t dlvl;
extern char *prg;
extern FILE *dfp;
extern int dsys;
extern char *prg;
extern int dpritab_len;

#ifdef	__cplusplus
}
#endif

#endif	/* _PCIDR_H */
