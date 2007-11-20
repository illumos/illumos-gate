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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_CMD_SVCCFG_H
#define	_CMD_SVCCFG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>

#include <libxml/tree.h>

#include <libscf.h>
#include <libtecla.h>
#include <libuutil.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Command scope bits for command tab completion */
#define	CS_SCOPE	0x01
#define	CS_SVC		0x02
#define	CS_INST		0x04
#define	CS_SNAP		0x08
#define	CS_GLOBAL	0x0f

/* Flags for lscf_bundle_import() & co. */
#define	SCI_NOREFRESH	0x01		/* Don't refresh instances */
#define	SCI_GENERALLAST 0x04		/* Add general property group last */
#define	SCI_NOENABLED	0x08		/* Don't import general/enabled. */
#define	SCI_FRESH	0x10		/* Freshly imported service */
#define	SCI_FORCE	0x20		/* Override-import. */
#define	SCI_KEEP	0x40		/* Don't delete when SCI_FORCEing */
#define	SCI_NOSNAP	0x80		/* Don't take last-import snapshot */

/* Flags for lscf_service_export() */
#define	SCE_ALL_VALUES	0x01		/* Include all property values */

#ifdef lint
extern int yyerror(const char *);
extern int yyparse(void);
#endif /* lint */

extern int lex_lineno;

#define	MANIFEST_DTD_PATH	"/usr/share/lib/xml/dtd/service_bundle.dtd.1"
/*
 * The following list must be kept in the same order as that of
 * lxml_prop_types[]
 */
typedef enum element {
	SC_ASTRING = 0x0, SC_BOOLEAN, SC_COMMON_NAME, SC_COUNT,
	SC_INSTANCE_CREATE_DEFAULT, SC_DEPENDENCY, SC_DEPENDENT, SC_DESCRIPTION,
	SC_DOC_LINK, SC_DOCUMENTATION, SC_ENABLED, SC_EXEC_METHOD, SC_FMRI,
	SC_HOST, SC_HOSTNAME, SC_INSTANCE, SC_INTEGER, SC_LOCTEXT, SC_MANPAGE,
	SC_METHOD_CONTEXT, SC_METHOD_CREDENTIAL, SC_METHOD_PROFILE,
	SC_METHOD_ENVIRONMENT, SC_METHOD_ENVVAR, SC_NET_ADDR_V4, SC_NET_ADDR_V6,
	SC_OPAQUE, SC_PROPERTY, SC_PROPERTY_GROUP, SC_PROPVAL, SC_RESTARTER,
	SC_SERVICE, SC_SERVICE_BUNDLE, SC_SERVICE_FMRI, SC_INSTANCE_SINGLE,
	SC_STABILITY, SC_TEMPLATE, SC_TIME, SC_URI, SC_USTRING, SC_VALUE_NODE,
	SC_XI_FALLBACK, SC_XI_INCLUDE
} element_t;

typedef enum bundle_type {
	SVCCFG_UNKNOWN_BUNDLE, SVCCFG_MANIFEST, SVCCFG_PROFILE, SVCCFG_ARCHIVE
} bundle_type_t;

typedef struct bundle {
	uu_list_t	*sc_bundle_services;

	xmlChar		*sc_bundle_name;
	bundle_type_t	sc_bundle_type;
} bundle_t;

typedef enum service_type {
	SVCCFG_UNKNOWN_SERVICE = 0x0, SVCCFG_SERVICE, SVCCFG_RESTARTER,
	SVCCFG_MILESTONE
} service_type_t;

typedef enum entity_type {
	SVCCFG_SERVICE_OBJECT = 0x0, SVCCFG_INSTANCE_OBJECT,
	SVCCFG_TEMPLATE_OBJECT
} entity_type_t;

enum import_state {
	IMPORT_NONE = 0,
	IMPORT_PREVIOUS,
	IMPORT_PROP_BEGUN,
	IMPORT_PROP_DONE,
	IMPORT_COMPLETE,
	IMPORT_REFRESHED
};

typedef enum svccfg_op {
	SVCCFG_OP_IMPORT = 0,
	SVCCFG_OP_APPLY,
	SVCCFG_OP_RESTORE
} svccfg_op_t;

typedef struct entity {
	uu_list_node_t	sc_node;
	entity_type_t sc_etype;

	/* Common fields to all entities. */
	const char	*sc_name;
	const char	*sc_fmri;
	uu_list_t	*sc_pgroups;
	uu_list_t	*sc_dependents;
	struct entity	*sc_parent;
	enum import_state  sc_import_state;
	int		sc_seen;

	union {
		struct {
			uu_list_t	*sc_service_instances;
			service_type_t	sc_service_type;
			uint_t		sc_service_version;

			struct entity *sc_service_template;
		} sc_service;
		struct {
			uint_t		sc_instance_dummy;
		} sc_instance;
		struct {
			uint_t		sc_template_dummy;
		} sc_template;
	} sc_u;
} entity_t;

typedef struct pgroup {
	uu_list_node_t	sc_node;
	uu_list_t	*sc_pgroup_props;

	const char	*sc_pgroup_name;
	const char	*sc_pgroup_type;
	uint_t		sc_pgroup_flags;
	struct entity	*sc_parent;

	int		sc_pgroup_delete;
	int		sc_pgroup_override;
	const char	*sc_pgroup_fmri;	/* Used for dependents */

	int		sc_pgroup_seen;
} pgroup_t;

typedef struct property {
	uu_list_node_t	sc_node;
	uu_list_t	*sc_property_values;

	char		*sc_property_name;
	scf_type_t	sc_value_type;

	int		sc_property_override;
	int		sc_seen;
} property_t;

typedef struct value {
	uu_list_node_t	sc_node;

	scf_type_t	sc_type;

	void (*sc_free)(struct value *);

	union {
		uint64_t	sc_count;
		int64_t		sc_integer;
		char		*sc_string;
	} sc_u;
} value_t;

typedef struct scf_callback {
	scf_handle_t	*sc_handle;
	void		*sc_parent;	/* immediate parent: scope, service,  */
					/* instance, property group, property */
	scf_transaction_t *sc_trans;
	int		sc_service;	/* True if sc_parent is a service. */
	uint_t		sc_flags;
	pgroup_t	*sc_general;	/* pointer to general property group */

	const char	*sc_source_fmri;
	const char	*sc_target_fmri;
	int		sc_err;
} scf_callback_t;

#ifndef NDEBUG
#define	bad_error(func, err)	{					\
	(void) fprintf(stderr, "%s:%d: %s() failed with unexpected "	\
	    "error %d.  Aborting.\n", __FILE__, __LINE__, (func), (err)); \
	abort();							\
}
#else
#define	bad_error(func, err)	abort()
#endif

#define	SC_CMD_LINE		0x0
#define	SC_CMD_FILE		0x1
#define	SC_CMD_EOF		0x2
#define	SC_CMD_IACTIVE		0x4
#define	SC_CMD_DONT_EXIT	0x8

typedef struct engine_state {
	uint_t		sc_cmd_flags;
	FILE		*sc_cmd_file;
	uint_t		sc_cmd_lineno;
	const char	*sc_cmd_filename;
	char		*sc_cmd_buf;
	size_t		sc_cmd_bufsz;
	off_t		sc_cmd_bufoff;
	GetLine		*sc_gl;

	pid_t		sc_repo_pid;
	const char	*sc_repo_filename;
	const char	*sc_repo_doordir;
	const char	*sc_repo_doorname;
	const char	*sc_repo_server;
} engine_state_t;

extern engine_state_t *est;

typedef struct string_list {
	uu_list_node_t	node;
	char		*str;
} string_list_t;

extern uu_list_pool_t *string_pool;

struct help_message {
	int		token;
	const char	*message;
};

extern struct help_message help_messages[];

extern scf_handle_t *g_hndl;	/* global repcached connection handle */
extern int g_exitcode;
extern int g_verbose;

extern ssize_t max_scf_fmri_len;
extern ssize_t max_scf_name_len;
extern ssize_t max_scf_value_len;
extern ssize_t max_scf_pg_type_len;

/* Common strings */
extern const char * const name_attr;
extern const char * const type_attr;
extern const char * const value_attr;
extern const char * const enabled_attr;
extern const char * const scf_pg_general;
extern const char * const scf_group_framework;
extern const char * const true;
extern const char * const false;

#define	uu_list_append(list, elem)	uu_list_insert_before(list, NULL, elem)
#define	uu_list_prepend(list, elem)	uu_list_insert_after(list, NULL, elem)

void *safe_malloc(size_t);
char *safe_strdup(const char *);
void warn(const char *, ...);
void synerr(int);
void semerr(const char *, ...);

void internal_init(void);
void internal_dump(bundle_t *);

int value_cmp(const void *, const void *, void *);

bundle_t *internal_bundle_new(void);
void internal_bundle_free(bundle_t *);
entity_t *internal_service_new(const char *);
void internal_service_free(entity_t *);
entity_t *internal_instance_new(const char *);
void internal_instance_free(entity_t *);
entity_t *internal_template_new(void);
pgroup_t *internal_pgroup_new(void);
void internal_pgroup_free(pgroup_t *);
pgroup_t *internal_pgroup_find(entity_t *, const char *, const char *);
pgroup_t *internal_dependent_find(entity_t *, const char *);
pgroup_t *internal_pgroup_find_or_create(entity_t *, const char *,
    const char *);
property_t *internal_property_new(void);
void internal_property_free(property_t *);
property_t *internal_property_find(pgroup_t *, const char *);
property_t *internal_property_create(const char *, scf_type_t, uint_t, ...);
value_t *internal_value_new(void);

int internal_attach_service(bundle_t *, entity_t *);
int internal_attach_entity(entity_t *, entity_t *);
int internal_attach_pgroup(entity_t *, pgroup_t *);
int internal_attach_dependent(entity_t *, pgroup_t *);
int internal_attach_property(pgroup_t *, property_t *);
void internal_attach_value(property_t *, value_t *);

int load_init(void);
void load_fini(void);
int load_pg_attrs(const scf_propertygroup_t *, pgroup_t **);
int load_pg(const scf_propertygroup_t *, pgroup_t **, const char *,
    const char *);
int prop_equal(property_t *, property_t *, const char *, const char *, int);
int pg_attrs_equal(const pgroup_t *, const pgroup_t *, const char *, int);
int pg_equal(pgroup_t *, pgroup_t *);

void lscf_cleanup(void);
void lscf_prep_hndl(void);
void lscf_init(void);
int lscf_bundle_import(bundle_t *, const char *, uint_t);
int lscf_bundle_apply(bundle_t *);
void lscf_delete(const char *, int);
void lscf_list(const char *);
void lscf_select(const char *);
void lscf_unselect();
void lscf_get_selection_str(char *, size_t);
void lscf_add(const char *);
void lscf_listpg(const char *);
void lscf_addpg(const char *, const char *, const char *);
void lscf_delpg(char *);
void lscf_listprop(const char *);
void lscf_addprop(char *, const char *, const uu_list_t *);
void lscf_delprop(char *);
void lscf_listsnap();
void lscf_selectsnap(const char *);
void lscf_revert(const char *);
char *filename_to_propname(const char *);
int lscf_retrieve_hash(const char *, unsigned char *);
int lscf_store_hash(const char *, unsigned char *);
CPL_MATCH_FN(complete_select);
CPL_MATCH_FN(complete_command);

int lxml_init(void);
int lxml_get_bundle_file(bundle_t *, const char *, svccfg_op_t);

void engine_init(void);
int engine_exec_cmd(void);
int engine_exec(char *);
int add_cmd_matches(WordCompletion *, const char *, int, uint32_t);
int engine_interp(void);
int engine_source(const char *, boolean_t);
int engine_import(uu_list_t *);
void help(int);

int engine_cmd_getc(engine_state_t *);
int engine_cmd_ungetc(engine_state_t *, char);
void engine_cmd_nputs(engine_state_t *, char *, size_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _CMD_SVCCFG_H */
