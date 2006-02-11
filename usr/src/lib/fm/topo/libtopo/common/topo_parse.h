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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _TOPO_PARSE_H
#define	_TOPO_PARSE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <libxml/parser.h>
#include <libnvpair.h>
#include <fm/libtopo.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	TOPO_DTD_PATH	"topology.dtd.1"
#define	TOPO_FILE	"topology.xml"
#define	TOPO_PLATFORM_PATH	"%susr/platform/%s/lib/fm/topo/%s"
#define	TOPO_COMMON_PATH	"%susr/lib/fm/topo/%s"

/*
 * Plenty of room to hold string representation of an instance
 * number
 */
#define	MAXINSTSTRLEN	64

/*
 * Forward declaration
 */
struct tf_rdata;
struct tf_info;

/*
 * This structure summarizes an enumerator as described by an xml
 * topology file.
 */
typedef struct tf_edata {
	char *te_name;		/* name of the enumerator, if any */
	char *te_path;		/* path to the enumerator, if any */
	topo_stability_t te_stab; /* stability of the enumerator, if any */
	int te_vers;		/* version of the enumerator, if any */
	int te_amcnt;		/* number of apply-methods */
	nvlist_t **te_ams;	/* apply-methods */
} tf_edata_t;

/* properties and dependents off of an instance or a range */
typedef struct tf_pad {
	int tpad_pgcnt;		/* number of property-groups of node */
	int tpad_dcnt;		/* number of dependents groups of node */
	nvlist_t **tpad_pgs;	/* property-groups as nvlists */
	struct tf_rdata *tpad_child; /* children ranges */
	struct tf_rdata *tpad_sibs; /* sibling ranges */
} tf_pad_t;

typedef struct tf_idata {
	struct tf_idata *ti_next; /* next instance */
	topo_instance_t ti_i;	/* hard instance */
	tnode_t *ti_tn;		/* topology node representing the instance */
	tf_pad_t *ti_pad;	/* properties and dependents */
} tf_idata_t;

/*
 * This structure summarizes a topology node range as described by a
 * topology file.
 */
typedef struct tf_rdata {
	struct tf_rdata *rd_next; /* for linking a group of tf_rdatas */
	int rd_cnt;		/* number of tf_rdatas in the list */
	struct tf_info *rd_finfo; /* pointer back to .xml file details */
	topo_mod_t *rd_mod;	/* pointer to loaded enumerator */
	tnode_t *rd_pn;		/* parent topology node */
	char *rd_name;		/* node name */
	int rd_min;		/* minimum instance number of node */
	int rd_max;		/* maximum instance number of node */
	tf_edata_t *rd_einfo;	/* enumerator information, if any */
	struct tf_idata *rd_instances; /* hard instances */
	tf_pad_t *rd_pad;	/* properties and dependents */
} tf_rdata_t;

/*
 * While we're parsing we need a handy way to pass around the data
 * related to what we're currently parsing, what topology nodes may be
 * affected, etc.
 */
typedef struct tf_info {
	char *tf_fn;		/* name of file read */
	char *tf_scheme;	/* scheme of topology in file */
	/* UUID ? */
	uint_t tf_flags;	/* behavior modifiers (see values below) */
	xmlDocPtr tf_xdoc;	/* the parsed xml doc */
	tf_rdata_t *tf_rd;	/* data for forming topology nodes */
} tf_info_t;

#define	TF_LIVE	0x1	/* Parsing should create topology nodes */
#define	TF_BIN	0x2	/* Parsing should create intermediate binary */

/*
 * We store properties using nvlists as an intermediate form.  The
 * following defines are names for fields in this intermediate form.
 */
#define	INV_IMMUTE	"prop-immutable"
#define	INV_PGRP_ALLPROPS "propgrp-props"
#define	INV_PGRP_NAME	"propgrp-name"
#define	INV_PGRP_NPROP	"propgrp-numprops"
#define	INV_PGRP_STAB	"propgrp-name-stability"
#define	INV_PNAME	"prop-name"
#define	INV_PVAL	"prop-val"
#define	INV_PVALTYPE	"prop-valtype"

extern tf_idata_t *tf_idata_lookup(topo_mod_t *, tf_idata_t *, topo_instance_t);
extern tf_rdata_t *tf_rdata_new(topo_mod_t *,
    tf_info_t *, xmlNodePtr, tnode_t *);
extern tf_idata_t *tf_idata_new(topo_mod_t *, topo_instance_t, tnode_t *);
extern tf_info_t *topo_xml_read(topo_mod_t *, const char *, const char *);
extern tf_info_t *tf_info_new(topo_mod_t *,
    const char *, xmlDocPtr, xmlChar *);
extern tf_pad_t *tf_pad_new(topo_mod_t *, int, int);
extern void topo_xml_cleanup(topo_mod_t *, tf_info_t *);
extern void tf_rdata_free(topo_mod_t *, tf_rdata_t *);
extern void tf_edata_free(topo_mod_t *, tf_edata_t *);
extern void tf_idata_free(topo_mod_t *, tf_idata_t *);
extern void tf_info_free(topo_mod_t *, tf_info_t *);
extern void tf_pad_free(topo_mod_t *, tf_pad_t *);
extern int topo_xml_range_process(topo_mod_t *, xmlNodePtr, tf_rdata_t *);
extern int topo_xml_enum(topo_mod_t *, tf_info_t *, tnode_t *);
extern int tf_idata_insert(topo_mod_t *, tf_idata_t **, tf_idata_t *);
extern int xmlattr_to_int(topo_mod_t *, xmlNodePtr, const char *, uint64_t *);
extern int xmlattr_to_stab(topo_mod_t *, xmlNodePtr, topo_stability_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _TOPO_PARSE_H */
