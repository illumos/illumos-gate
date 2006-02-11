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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _INJ_H
#define	_INJ_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * FMA Error injector
 */

#include <stdio.h>
#include <libnvpair.h>
#include <sys/types.h>

#include <inj_list.h>
#include <inj_hash.h>

#include <fm/fmd_log.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The injector allows for the declaration, definition, and injection of four
 * types of things - Events, FMRIs, Authorities, and lists.  The first three
 * are essentially lists with extra membership requirements (FMRIs, for
 * example, must include a member called `scheme').  So while each has a
 * different function within the FMA framework, we can use a single struct to
 * store all three.  The inj_itemtype_t enum is used to describe which of the
 * four types is being represented by a given object.
 */
typedef enum inj_itemtype {
	ITEMTYPE_EVENT,
	ITEMTYPE_FMRI,
	ITEMTYPE_AUTH,
	ITEMTYPE_LIST
} inj_itemtype_t;

#define	ITEMTYPE_NITEMS		4

/*
 * The member name-value pairs of Events, FMRIs, and Authorities are typed.
 */
typedef enum inj_memtype {
	MEMTYPE_UNKNOWN,
	MEMTYPE_INT8,
	MEMTYPE_INT16,
	MEMTYPE_INT32,
	MEMTYPE_INT64,
	MEMTYPE_UINT8,
	MEMTYPE_UINT16,
	MEMTYPE_UINT32,
	MEMTYPE_UINT64,
	MEMTYPE_BOOL,
	MEMTYPE_STRING,
	MEMTYPE_ENUM,
	MEMTYPE_EVENT,
	MEMTYPE_FMRI,
	MEMTYPE_AUTH,
	MEMTYPE_LIST
} inj_memtype_t;

/*
 * Declarations
 *
 * Each declared item, be it an event, an fmri, or an authority, consists of
 * an inj_decl_t and a string of inj_declmem_t's, one of the latter for each
 * declared member.
 */

#define	DECL_F_AUTOENA	0x1	/* ENA member to be auto-generated for event */

typedef struct inj_decl {
	inj_list_t decl_members;	/* List of declared members */
	inj_hash_t decl_memhash;	/* Hash of said members */

	const char *decl_name;		/* Name of declared item */
	inj_itemtype_t decl_type;	/* Type of declared item */

	uint_t decl_lineno;		/* Line # of first member declared */
	uint_t decl_flags;		/* DECL_F_* */
} inj_decl_t;

#define	DECLMEM_F_ARRAY	0x1	/* This member is an array of the given type */

typedef struct inj_declmem {
	inj_list_t dlm_memlist;		/* List of declared members */

	const char *dlm_name;		/* Name of this member */
	inj_memtype_t dlm_type;		/* Type of this member */

	uint_t dlm_flags;		/* DECLMEM_F_* */
	uint_t dlm_arrdim;		/* If arr flag set, dim of array */

	union {
		inj_hash_t *_dlm_enumvals; /* If enum, hash of poss. values */
		inj_decl_t *_dlm_decl;	/* If evt, etc., ptr to decl for same */
	} _dlm_u;
} inj_declmem_t;

#define	dlm_enumvals	_dlm_u._dlm_enumvals
#define	dlm_decl	_dlm_u._dlm_decl

/*
 * Definitions
 *
 * Each defined item consists of an inj_defn_t and a string of inj_defnmem_t's,
 * one of the latter for each defined member.  The inj_defn_t also contains a
 * pointer to the corresponding declaration, thus allowing for correctness
 * checking.
 */

typedef struct inj_defn {
	inj_list_t defn_members;	/* List of defined members */
	const char *defn_name;		/* Name of this definition */
	inj_decl_t *defn_decl;		/* Ptr to decl this defn instantiates */
	uint_t defn_lineno;		/* Line # of first member defined */

	nvlist_t *defn_nvl;		/* Built from validated members */
} inj_defn_t;

/*
 * Embodiment of the information that we know about a given defined member at
 * the time of definition.  These values are assigned before the individual
 * definition members are paired with their corresponding declarations, so we
 * don't know whether a given IDENT is, for example, an enum or an fmri
 * reference.  Without these values, we wouldn't be able to distinguish between
 * a quoted string and an identifier, for example, and thus would have a harder
 * time with syntactic validation.
 */
typedef enum inj_defnmemtype {
	DEFNMEM_IMM,
	DEFNMEM_IDENT,
	DEFNMEM_QSTRING,
	DEFNMEM_EVENT,
	DEFNMEM_FMRI,
	DEFNMEM_AUTH,
	DEFNMEM_ARRAY,
	DEFNMEM_LIST
} inj_defnmemtype_t;

typedef struct inj_defnmem {
	inj_list_t dfm_memlist;		/* List of defined members */

	inj_defnmemtype_t dfm_type;	/* Type of this member, from parser */
	uint_t dfm_lineno;		/* Last line of this member's defn */

	union {
		const char *_dfm_str;	/* String value of member */
		inj_list_t _dfm_list;	/* Enum, evt, auth, arr, list vals */
	} _dfm_u;
} inj_defnmem_t;

#define	dfm_str		_dfm_u._dfm_str
#define	dfm_list	_dfm_u._dfm_list

/*
 * Operations performed by the injector (aside from declarations and
 * definitions)
 */

/* events and priorities list for the randomize command */
typedef struct inj_randelem {
	struct inj_randelem *re_next;
	inj_defn_t *re_event;
	uint_t re_prob;
} inj_randelem_t;

/*
 * Operations themselves are structured as a tree of inj_cmd_t's.  Each one has
 * a command type and type-specific command data.  The "program" is run via
 * iteration through the tree, with the injector performing the operation
 * requested by a given node.
 */
typedef enum inj_cmd_type {
	CMD_SEND_EVENT,
	CMD_SLEEP,
	CMD_REPEAT,
	CMD_RANDOM
} inj_cmd_type_t;

typedef struct inj_cmd {
	inj_list_t cmd_list;		/* List of commands */
	inj_cmd_type_t cmd_type;	/* Type of this command */

	union {
		inj_defn_t *_cmd_event;	/* If send_event, evt to send */
		inj_randelem_t **_cmd_rand;	/* List of evts & probs */
		struct inj_cmd *_cmd_subcmd;	/* If repeat, cmd to be rpt'd */
	} _cmd_u;
	uint_t		cmd_num;	/* If repeat, repeat count */
} inj_cmd_t;

#define	cmd_event	_cmd_u._cmd_event
#define	cmd_rand	_cmd_u._cmd_rand
#define	cmd_subcmd	_cmd_u._cmd_subcmd

/*
 * We support retargetable event-delivery mechanisms.  Each method implements
 * a copy of the following ops vector, thus allowing us to switch mechanisms
 * simply by switching the structure.
 */
typedef struct inj_mode_ops {
	void *(*mo_open)(const char *);		/* Init mechanism */
	void (*mo_send)(void *, nvlist_t *);	/* Send a single nvlist */
	void (*mo_close)(void *);		/* Shut down mechanism */
} inj_mode_ops_t;

extern int verbose;
extern int quiet;

extern inj_list_t *inj_logfile_read(fmd_log_t *);
extern inj_list_t *inj_program_read(const char *);
extern void inj_program_run(inj_list_t *, const inj_mode_ops_t *, void *);

extern void *inj_alloc(size_t);
extern void *inj_zalloc(size_t);
extern void inj_free(void *, size_t);

#ifdef __cplusplus
}
#endif

#endif /* _INJ_H */
