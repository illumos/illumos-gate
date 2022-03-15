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
 */

/*
 * This file provides the code that allows svccfg(8) to validate a
 * manifest against the template specifications.  svccfg uses the
 * validation facilities for the import and validate subcommands.
 *
 * There are three entry points -- tmpl_validate_bundle(),
 * tmpl_errors_print() and tmpl_errors_destroy().  svccfg calls
 * tmpl_validate_bundle() to validate a bundle.  tmpl_validate_bundle()
 * returns a pointer to a tmpl_errors_t.  This is a pointer to information
 * about any validation errors that were found.  If an error was detected,
 * svccfg calls tmpl_errors_print() to print the error information.  Once
 * the error information is printed, svccfg calls tmpl_errors_destroy() to
 * free the memory associated with the tmpl_errors_t.
 *
 * libscf's scf_tmpl.c performs similar checks to the ones described in
 * this paragraph.  Any changes to the algorithms in this file should also
 * be infcorporated into scf_tmpl.c.  The reason that there are two bodies
 * of code is that they work on different data structures.
 * tmpl_validate_bundle() validates each instance of each service in the
 * bundle.  The following checks are performed on each instance:
 *
 *	1.  Verify template consistency.
 *	    A.  No conflicting definitions of "pg_pattern" are allowed
 *		within a single instance.
 *	    B.  Templates at a narrow target (e.g. instance) which define
 *		property groups already templated at a broad target
 *		(e.g. delegate or all) are strongly discouraged.
 *	    C.  Developers may not define a template which specifies a
 *		single prop_pattern name with differing types on the same
 *		target entity.
 *	    D.  If a pg_pattern has a required attribute with a value of
 *		true, then its name and type attributes must be
 *		specified.
 *	    E.  If a prop_pattern has a required attribute with a value
 *		of true, then its type attribute must be specified.
 *	    F.  If a prop_pattern has an include_values element make sure
 *		that the appropriate constraints or values element has
 *		also been declared.
 *	2.  Validate that each property group in the instance is in
 *	    conformance with the template specifications.
 *	    A.  Verify that the types of the PG and the pg_pattern are
 *		compatible.
 *	    B.  Verify properties of the PG against the prop_patterns in
 *		the template.
 *		o Verify property's type.
 *		o Verify cardinality.
 *		o Vefiy that property values satisfy the constraints
 *		  imposed by the prop_pattern.
 *	    C.  Verify that required properties are present.
 *	3.  Verify that all required property groups are present in the
 *	    insance.
 *
 * tmpl_validate_bundle() is called after svccfg has processed the manifest
 * file.  The manifest is represented in memory by a set of entity_t,
 * pgroup_t, property_t and value_t structures.  These structures are
 * defined in svccfg.h.
 *
 * tmpl_validate_bundle() calls tmpl_validate_service() for each service in
 * the bundle, and tmpl_validate_service() then calls
 * tmpl_validate_instance() for each instance in the service.
 * tmpl_validate_instance() is the function that does the real work of
 * validation against the template specification.
 *
 * Subsystems:
 * ==========
 *
 * General Templates:
 * -----------------
 * In order to perform the validation specified by 1.B above, we need to
 * load the templates specifications for the global service and the
 * instance's restarter.  This information is loaded from the repository
 * and it is held in memory using the entity_t, pgroup_t, property_t and
 * value_t hierarchy of structures.  When a service is processed,
 * load_general_templates() is called to load the information for the
 * global service and restarter that is declared at the service level.  The
 * sc_service.sc_global and sc_service.sc_restarter members of the
 * service's entity_t point to the information for the global and restarter
 * services.
 *
 * The instance portion of a manifest can declare an instance specific
 * restarter.  If this is the case, load_instance_restarter() will load the
 * information for that restarter, and it is saved in the
 * sc_instance.sc_instance_restarter member of the entity_t that represents
 * the instance.
 *
 * Composed Properties:
 * -------------------
 * We need the ability to process the composed properties of an instance.
 * That is to say if an instance defines a property, it overrides any
 * definition in the service.  Otherwise, the service's definition is
 * inherited in the instance.
 *
 * In an entity_t, the sc_instance.sc_composed member points to a
 * uu_avl tree of composed property groups (composed_pg_t) for the
 * instance.  The composed_pg_t has two members, cpg_instance_pg and
 * cpg_service_pg, that point to the instance and service property group
 * definitions respectively.  Either of these may be NULL indicating that
 * only an instance or service definition exists in the manifest.
 *
 * In the case where both the instance and the service define a property
 * group, the properties must be composed.  This is done by
 * compose_props().  The compose_pg_t holds the composed properties in a
 * uu_avl_tree at cpf_compose_props.  This is a tree of property_t
 * structures.  If a property is defined in both the instance and service
 * property group, the tree will hold the instance definition.  If the
 * property is defined at only one level, the tree will hold the property_t
 * for that level.  Thus, the tree is truly a set of composed properties of
 * the property group.
 *
 * Property Group Iteration:
 * ------------------------
 * A number of functions must iterate through an instance's property groups
 * looking for the ones that define a pg_pattern or a prop_pattern.  To be
 * specific, the iteration starts with the composed view of the instance.
 * It then proceeds through the restarter information and finally moves on
 * to the global service.  The pg_iter_t structure holds the information
 * that is needed to implement this type of iteration.  pg_iter_create()
 * creates one of these iterators, and pg_iter_destroy() frees the memory
 * associated with the pg_iter_t.  next_pattern_pg(), is used to step
 * through the iteration.
 *
 * Error Reporting:
 * ---------------
 * While performing the templates validation checks, svccfg collects
 * information for all the errors that it finds.  Because of this you will
 * see many places in the code where a loop is not exited when an error is
 * encountered.  We note that fact that an error has occurred, but continue
 * in the loop to see if there are more validation errors.  The error code
 * of the last error that is encountered is returned.  This works, because
 * the callers of tmpl_validate_bundle() only look to see whether or not
 * the return code is TVS_SUCCESS.
 *
 * The information for reporting the errors is collected in a tmpl_errors_t
 * structure, and tmpl_validate_bundle() returns the address of this
 * structure.  The caller of tmpl_validate_bundle() can then call
 * tmpl_errors_print() to display the error information to the user.
 *
 * There are two categories of errors.  Some errors are seen when
 * processing the information in the manifest.  This type of error is only
 * seen by svccfg when it is importing or validating a manifest.  The other
 * type of error consists of template validation errors.  These errors can
 * be seen when processing a manifest or when performing a templates
 * validation of the information associated with an FMRI in the the
 * repository.  tmpl_errors_add_im() is used to capture error information
 * about the first type of error, and add_scf_error() is used to capture
 * error information about the second type of error.
 *
 * The distinction is important when printing the error information.  The
 * fuctions for printing the first type of error reside in this file, since
 * these errors will only be seen by the functions in this file.  The
 * functions for printing the template validation errors reside in libscf,
 * because these errors are of a more general nature.
 *
 * Thus, tmpl_errors_t has two lists -- one for each type of error.
 * te_list is a list of im_tmpl_error_t structures that represent the first
 * type of error.  te_scf is a list of tv_errors_t structures that hold
 * information about general template validation errors.
 * tmpl_errors_print() processes both lists to print information about all
 * errors.  In tmpl_errors_print() im_tmpl_error_print() is used to print
 * the errors that are specific to this file.  scf_tmpl_strerror() provides
 * the errors messages for general templates errors.
 *
 * As was mentioned in the previous paragraph, im_tmpl_error_print() is
 * responsible for printing the errors that are specific to this file.
 * Based on the error code, it dispatches to one of
 * im_perror_bad_conversion(), im_perror_bad_template(),
 * im_perror_invalid_type(), im_perror_missing_pg_type() or
 * im_perror_missing_type().  The rest of the im_perror_* functions provide
 * services to these error specific functions by printing common
 * information.
 *
 * im_perror_item() is the heart of this message printing subsystem.  It is
 * called directly or indirectly by all of the other im_perror_* functions.
 * im_perror_item() prints a single item of error information.  If svccfg
 * is running in interactive mode, im_perror_item() prints each item on a
 * single line, so that they are readable by a human.  In non-interactive
 * mode, all items are printed on a single line separated by semi-colons.
 */

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <libintl.h>
#include <limits.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "svccfg.h"

/*
 * Clear error_info_t structure.
 */
#define	CLEAR_ERROR_INFO(ei)	((void) memset((ei), 0, sizeof (error_info_t)))

/*
 * Retrieve the property group pointer from the composed_pg structure.
 */
#define	CPG2PG(cpg)	(cpg->cpg_instance_pg ? cpg->cpg_instance_pg : \
			    cpg->cpg_service_pg)

/*
 * Convert a pointer to an empty string into a NULL pointer.
 */
#define	EMPTY_TO_NULL(p) (((p) && (*(p) == 0)) ? NULL : (p))

/* uu_avl and uu_list debugging bits. */
#ifdef	NDEBUG
#define	TMPL_DEBUG_AVL_POOL	UU_DEFAULT
#define	TMPL_DEBUG_LIST		UU_DEFAULT
#define	TMPL_DEBUG_LIST_POOL	UU_DEFAULT
#define	TMPL_DEBUG_TREE		UU_DEFAULT
#else
#define	TMPL_DEBUG_AVL_POOL	UU_AVL_POOL_DEBUG
#define	TMPL_DEBUG_LIST		UU_LIST_DEBUG
#define	TMPL_DEBUG_LIST_POOL	UU_LIST_POOL_DEBUG
#define	TMPL_DEBUG_TREE		UU_AVL_DEBUG
#endif	/* NDEBUG */

/*
 * Structures and enums that are used in producing error messages:
 *
 * error_info_t is used to pass information about an error to
 * tmpl_errors_add_im() and add_scf_error().  tmpl_errors_add_im() collects
 * the error information and stores it in an im_tmpl_error_t.  The
 * im_tmpl_error_t is linked into the tmpl_errors_t, so that the captured
 * information can be used later when error messages are printed.
 *
 * tv_errors_t is used to keep track of error information for general
 * template errors that are known by libscf.  add_scf_error() captures the
 * error information for use in this structure.
 */
/*
 * enum to designate the type of data that is held in a err_info structure.
 */
typedef enum err_info_type {
	EIT_NONE,		/* No values in the structure */
	EIT_BAD_TEMPLATE,	/* Reason that template is bad */
	EIT_CARDINALITY,	/* Ranges for property cardinality */
	EIT_INCLUDE_VALUES,	/* include_values type attribute */
	EIT_MISSING_PG,		/* Name of missing pg */
	EIT_MISSING_PROP,	/* Name of missing property */
	EIT_PATTERN_CONFLICT, 	/* Conflicting pattern definition */
	EIT_PROP_TYPE,		/* Value with invalid type */
	EIT_RANGE		/* Value that is out of range */
} err_info_type_t;

/*
 * Structure to hold information that will be used in generating error
 * messages.
 */
typedef struct error_info {
	err_info_type_t	ei_type;	/* Type of information stored here */
	union {
		/* EIT_BAD_TEMPLATE */
		struct {
			const char	*ei_reason;
		} ei_bad_template;
		/* EIT_CARDINALITY */
		struct {
			uint64_t	ei_min;
			uint64_t	ei_max;
			uint64_t	ei_count; /* Number of prop values */
		} ei_cardinality;
		/* EIT_INCLUDE_VALUES */
		struct {
			const char	*ei_type;
		} ei_inc_values;
		/* EIT_MISSING_PG */
		struct {
			const char	*ei_pg_name;	/* Name of missing pg */
			const char	*ei_pg_type;	/* Type of missing pg */
		} ei_missing_pg;
		/* EIT_MISSING_PROP */
		struct {
			const char	*ei_prop_name; /* Name of prop */
		} ei_missing_prop;
		/* EIT_PATTERN_CONFLICT */
		struct {
			pgroup_t	*ei_pattern; /* Conficting pattern */
		} ei_pattern_conflict;
		/* EIT_PROP_TYPE */
		struct {
			scf_type_t	ei_actual;
			scf_type_t	ei_specified;
		} ei_prop_type;
		/* EIT_RANGE */
		struct {
			scf_type_t	ei_rtype;
			int64_t		ei_ivalue;
			uint64_t	ei_uvalue;
		} ei_range;
	} ei_u;
} error_info_t;

/*
 * Structure with information about a template violation.  This structure
 * is for use with in memory representations of the manifest and template.
 * See scf_tmpl_error_t for use with repository representations.  Some of
 * the pointers may be NULL for some types of errors.
 */
typedef struct im_tmpl_error {
	tmpl_validate_status_t ite_type; /* Type of error */
	entity_t	*ite_entity;	/* Instance or service */
	pgroup_t	*ite_pg;	/* Non-conforming prop. group */
	pgroup_t	*ite_pg_pattern; /* Violated pg_pattern */
	property_t	*ite_prop;	/* Non-conforming property */
	pgroup_t	*ite_prop_pattern; /* Violated prop_pattern */
	value_t		*ite_value;	/* Non-conforming value */
	error_info_t	ite_einfo;	/* Extra error information */
	uu_list_node_t	ite_node;	/* Node to link us in a list. */
} im_tmpl_error_t;

/*
 * This structure holds the data that will be used by scf_tmpl_strerror()
 * for printing template validation errors.
 */
typedef struct tv_errors {
	scf_tmpl_errors_t *tve_errors;	/* Errors for scf_tmpl_strerror() */
	uu_list_node_t	tve_node;	/* Linkage in a list. */
} tv_errors_t;

/*
 * Structure to collect template validation errors.
 */
struct tmpl_errors {
	uu_list_t	*te_list;	/* List of im_tmpl_error_t */
	im_tmpl_error_t *te_next;	/* Next error to present */
	uu_list_t	*te_scf;	/* Errors for scf_tmpl_strerror() */
	tv_errors_t	*te_cur_scf;	/* Current member of te_scf */
};

/* End of structures used in error processing. */

/*
 * Property group types that are of interest to us.  See pgroup_type().
 */
typedef enum pg_type {
	NORMAL_PG,
	PG_PATTERN_PG,
	PROP_PATTERN_PG
} pg_type_t;

/*
 * Structure to keep track of a set of ASTRING property values for a
 * property.  The consumer may wish to have the ASTRING property values
 * converted to a numeric form which is the reason for the av_v union.
 * This structure is returned by av_get_values() and is accessed by
 * av_get_integer(), av_get_string() and av_get_unsigned().
 */
typedef struct avalues {
	uint_t		av_count;	/* Number of values */
	scf_type_t	av_type;	/* Type of value representation */
	union {
		uint64_t	*av_unsigned;	/* Count & boolean values */
		int64_t		*av_integer;	/* Integer values */
		const char 	**av_string;	/* String values */
	} av_v;				/* Container for the values */
} avalues_t;

/*
 * composed_pg_t contains the information that is needed to compose a
 * property group.  See the section on Composed Properties in the block
 * comment at the beginning of this file.  The composed_pg structures are
 * linked into a uu_avl tree.  The tree is at sc_instance.sc_composed in
 * the entity_t.
 */
struct composed_pg {
	/*
	 * Property group is uniquely identified by its name and type.
	 * These two elements point to the name and type in a pgroup_t
	 * (either service or instance), so they do not need to be
	 * allocated or freed.
	 */
	const char	*cpg_name;
	const char	*cpg_type;

	/* References to the actual property group definitions. */
	pgroup_t	*cpg_instance_pg;
	pgroup_t	*cpg_service_pg;

	/* Composed properties of the property group. */
	uu_avl_t	*cpg_composed_props;

	uu_avl_node_t	cpg_node;	/* Linkage for AVL tree */
};

/*
 * Prefixes for standard property names.  Used in
 * include_values_support().
 */
typedef struct prop_prefix {
	const char	*pp_prefix;
	size_t		pp_size;
} prop_prefix_t;

/*
 * Store a legal range for a property allowing for either signed or
 * unsigned ranges.  It is used to store a range from a template
 * constraint element of a prop_pattern.  The structure is returned by
 * get_ranges() and is used by value_in_range() to validate the values of a
 * property.
 */
typedef struct range {
	union {
		struct {
			uint64_t	rng_min;
			uint64_t	rng_max;
		} rng_unsigned;
		struct {
			int64_t		rng_min;
			int64_t		rng_max;
		} rng_signed;
	} rng_u;
} range_t;

/*
 * This enum defines the levels where templates can be defined.  See the
 * pg_iter structure below.
 */
typedef enum tmpl_level {
	TL_NOLEVEL = 0,		/* No level yet specified. */
	TL_INSTANCE,		/* Instance templates. */
	TL_COMPOSED,		/* Composed instance. */
	TL_SERVICE,		/* Service wide templates. */
	TL_RESTARTER,		/* Templates from restarter manifest. */
	TL_GLOBAL		/* SMF wide templates. */
} tmpl_level_t;

/*
 * pg_iter is a structure that allows us to iterate through property groups
 * in an instance followed by the property groups of the instance's
 * service, the instance's restarter and finally the global service.  See
 * the Property Group Iteration section of the block comment at the
 * beginning of this file.
 */
typedef struct pg_iter {
	entity_t	*pgi_entity;	/* Entity being searched */
	const char	*pgi_restrict;	/* Only return PGs of this type */
	tmpl_level_t	pgi_level;	/* Current level */
	entity_t	*pgi_service;	/* Service being processed. */
	union {
		pgroup_t	*pgi_pg;
		composed_pg_t	*pgi_cpg;
	} pgi_current;			/* Current property group. */
} pg_iter_t;

/*
 * enum to distinguish between pg_patterns and prop_patterns.  It is used
 * in the ptrn_info_t structure.  See below.
 */
typedef enum ptrn_type {
	PG_PATTERN,
	PROP_PATTERN
} ptrn_type_t;

/*
 * Structure of information about a pg_pattern or a prop_pattern.  It is
 * used for template consistency checks.  gather_pattern() is used to
 * gather information for all the pg_patterns or prop_patterns in an
 * instance.  It allocates a ptrn_info_t for each of these and adds them to
 * an avl tree that is held by tmpl_consistency().
 */
typedef struct ptrn_info {
	ptrn_type_t	pi_ptrn_type;
	pgroup_t	*pi_ptrnpg;	/* pgroup_t defining the pattern. */
	const char	*pi_name;	/* Name attribute. */
	const char	*pi_type;	/* Type attribute. */
	const char	*pi_target;	/* Target attribute - only PG_PATTERN */
	const char	*pi_pgp_name;	/* Name of the pg pattern.  Only */
					/* used for PROP_PATTERN. */
	pgroup_t	*pi_enc_pgp;	/* PG of the pg_pattern that holds */
					/* the prop_pattern defined by this */
					/* structure.  Only used for */
					/* PROP_PATTERN. */
	uu_avl_node_t	pi_link;	/* Linkage into AVL tree */
} ptrn_info_t;

static const char *emesg_nomem;

/*
 * Pool for trees of composed property groups.
 */
static uu_avl_pool_t *composed_pg_pool;

/*
 * Pool for trees of composed properties.
 */
static uu_avl_pool_t *composed_prop_pool;

/*
 * Pool for lists of errors in the internal representation.
 */
static uu_list_pool_t *inmem_errors_pool;

/*
 * Pool for trees of pg_pattern info structures (ptrn_info_t).
 */
static uu_avl_pool_t *ptrn_info_pool;

/*
 * Pool for lists of template errors in the libscf representation.
 */
static uu_list_pool_t *tv_errors_pool;

/*
 * Property name prefixes for constraints and values.
 */
static const char *constraint_prefixes[] = {
	SCF_PROPERTY_TM_CONSTRAINT_NAME,
	SCF_PROPERTY_TM_CONSTRAINT_RANGE,
	NULL
};
static const char *value_prefixes[] = {
	SCF_PROPERTY_TM_VALUE_PREFIX,
	NULL
};

/*
 * Function to compare two composed_pg structures.
 */
/* ARGSUSED2 */
static int
composed_pg_compare(const void *left, const void *right, void *unused)
{
	composed_pg_t *l = (composed_pg_t *)left;
	composed_pg_t *r = (composed_pg_t *)right;
	int rc;

	if ((rc = strcmp(l->cpg_name, r->cpg_name)) == 0) {
		rc = strcmp(l->cpg_type, r->cpg_type);
	}
	return (rc);
}

/* ARGSUSED2 */
static int
composed_prop_compare(const void *left, const void *right, void *unused)
{
	property_t *l = (property_t *)left;
	property_t *r = (property_t *)right;

	return (strcmp(l->sc_property_name, r->sc_property_name));
}

static composed_pg_t *
composed_pg_create()
{
	composed_pg_t *cpg;

	cpg = safe_malloc(sizeof (*cpg));
	uu_avl_node_init(cpg, &cpg->cpg_node, composed_pg_pool);
	return (cpg);
}

static void
composed_pg_destroy(composed_pg_t *cpg)
{
	void *marker = NULL;
	pgroup_t *pg;

	if (cpg == NULL)
		return;
	/* Tear down composed property tree if we have one. */
	if ((cpg->cpg_composed_props != NULL)) {
		while (uu_avl_teardown(cpg->cpg_composed_props, &marker) !=
		    NULL) {
			/*
			 * Nothing to do other than getting the property
			 * out of the list.  This cleans up the property's
			 * uu_avl_node.
			 */
		}
		uu_avl_destroy(cpg->cpg_composed_props);
	}

	/* Clean up any pgroup_t references to us. */
	if ((pg = cpg->cpg_instance_pg) != NULL) {
		assert((pg->sc_pgroup_composed == NULL) ||
		    (pg->sc_pgroup_composed == cpg));
		pg->sc_pgroup_composed = NULL;
	}

	uu_avl_node_fini(cpg, &cpg->cpg_node, composed_pg_pool);
	free(cpg);
}

/*
 * Walk the property group at pg, and add its properties to the AVL tree at
 * tree.
 */
static void
grow_props_tree(pgroup_t *pg, uu_avl_t *tree)
{
	uu_avl_index_t marker;
	property_t *prop;

	for (prop = uu_list_first(pg->sc_pgroup_props);
	    prop != NULL;
	    prop = uu_list_next(pg->sc_pgroup_props, prop)) {
		if (uu_avl_find(tree, prop, NULL, &marker) == NULL) {
			/*
			 * If there was no match, insert the property into
			 * the tree.  If we do get a match, there is
			 * nothing to do.  That is because we rely on our
			 * caller to process the instance properties first,
			 * and the instance properties override the service
			 * properties.
			 */
			uu_avl_insert(tree, prop, marker);
		}
	}
}

/*
 * The composed properties are stored in a uu_avl_tree.  First we populate
 * the tree with properties from the instance level property group.  Then,
 * we'll add the properties from the service level property group.
 */
static void
compose_props(composed_pg_t *cpg)
{
	uu_avl_t *tree;

	tree = uu_avl_create(composed_prop_pool, cpg, TMPL_DEBUG_TREE);
	if (tree == NULL) {
		uu_die(gettext("composed_pool tree creation failed: %s\n"),
		    uu_strerror(uu_error()));
	}
	cpg->cpg_composed_props = tree;

	/*
	 * compose_props() is only called when there is both an instance
	 * and a service definition of the property group.  This implies
	 * that neither cpg->cpg_instance_pg nor cpg->cpg_service_pg can be
	 * NULL.
	 */
	/*
	 * First add instance properties to the tree.
	 */
	assert(cpg->cpg_instance_pg != NULL);
	grow_props_tree(cpg->cpg_instance_pg, tree);

	/*
	 * Add service properties to the tree.
	 */
	assert(cpg->cpg_service_pg != NULL);
	grow_props_tree(cpg->cpg_service_pg, tree);
}

/*
 * This function is a utility for build_composed_instance().
 */
static void
build_composed_property_groups(entity_t *inst, uu_avl_t *tree)
{
	composed_pg_t *cpg;
	uu_avl_index_t marker;
	composed_pg_t *match;
	pgroup_t *pg;
	entity_t *svc;

	/* First capture the instance property groups. */
	for (pg = uu_list_first(inst->sc_pgroups);
	    pg != NULL;
	    pg = uu_list_next(inst->sc_pgroups, pg)) {
		cpg = composed_pg_create();
		cpg->cpg_name = pg->sc_pgroup_name;
		cpg->cpg_type = pg->sc_pgroup_type;
		cpg->cpg_instance_pg = pg;
		match = uu_avl_find(tree, cpg, NULL, &marker);
		/* Since we do the instance first, there should be no match. */
		assert(match == NULL);
		uu_avl_insert(tree, cpg, marker);
		pg->sc_pgroup_composed = cpg;
	}

	/* Now capture the service property groups. */
	svc = inst->sc_parent;
	cpg = NULL;
	for (pg = uu_list_first(svc->sc_pgroups);
	    pg != NULL;
	    pg = uu_list_next(svc->sc_pgroups, pg)) {
		if (cpg == NULL)
			cpg = composed_pg_create();
		cpg->cpg_name = pg->sc_pgroup_name;
		cpg->cpg_type = pg->sc_pgroup_type;
		cpg->cpg_service_pg = pg;
		match = uu_avl_find(tree, cpg, NULL, &marker);
		if (match == NULL) {
			uu_avl_insert(tree, cpg, marker);
			/* Get new composed_pg_t next at top of loop. */
			cpg = NULL;
		} else {
			/*
			 * Already have a composed_pg from instance
			 * processing.  Just add the pointer to the service
			 * pg and compose the properties.
			 */
			match->cpg_service_pg = pg;
			compose_props(match);
		}
	}
	if (cpg != NULL)
		composed_pg_destroy(cpg);
}

static void
build_composed_instance(entity_t *inst)
{
	uu_avl_t *tree;

	assert(inst->sc_etype == SVCCFG_INSTANCE_OBJECT);

	if (inst->sc_u.sc_instance.sc_composed == NULL) {
		tree = uu_avl_create(composed_pg_pool, inst, TMPL_DEBUG_TREE);
		if (tree == NULL) {
			uu_die(gettext("composed_instance tree creation "
			    "failed: %s\n"), uu_strerror(uu_error()));
		}
		inst->sc_u.sc_instance.sc_composed = tree;
	}
	build_composed_property_groups(inst,
	    inst->sc_u.sc_instance.sc_composed);
}

static void
demolish_composed_instance(entity_t *inst)
{
	composed_pg_t *cpg;
	void *marker = NULL;
	uu_avl_t *tree;

	tree = inst->sc_u.sc_instance.sc_composed;
	if (tree == NULL)
		return;

	marker = NULL;
	while ((cpg = uu_avl_teardown(tree, &marker)) != NULL) {
		composed_pg_destroy(cpg);
	}
	uu_avl_destroy(tree);

	inst->sc_u.sc_instance.sc_composed = NULL;
}
/*
 * Return the number of values in prop.
 */
static size_t
count_prop_values(property_t *prop)
{
	return (uu_list_numnodes(prop->sc_property_values));
}

static int
is_numeric_type(scf_type_t type)
{
	if (type == SCF_TYPE_BOOLEAN)
		return (1);
	if (type == SCF_TYPE_COUNT)
		return (1);
	if (type == SCF_TYPE_INTEGER)
		return (1);
	return (0);
}

static pg_type_t
pgroup_type(pgroup_t *pg)
{
	if (strcmp(pg->sc_pgroup_type, SCF_GROUP_TEMPLATE_PG_PATTERN) == 0)
		return (PG_PATTERN_PG);
	if (strcmp(pg->sc_pgroup_type, SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0)
		return (PROP_PATTERN_PG);
	return (NORMAL_PG);
}

/*
 * Search the property group at pg for a property named name.  If the
 * property group has a tree of composed properties, the tree will be
 * searched for the property.  Otherwise, the property group's linked list
 * will be searched.
 */
static property_t *
property_find(pgroup_t *pg, const char *name)
{
	composed_pg_t *cpg;
	property_t look;

	cpg = pg->sc_pgroup_composed;

	if ((cpg == NULL) || (cpg->cpg_composed_props == NULL)) {
		/* This is not a composed property group. */
		return (internal_property_find(pg, name));
	}

	/*
	 * This is a composed property group, so look for the property in
	 * the AVL tree.
	 */
	look.sc_property_name = (char *)name;
	return (uu_avl_find(cpg->cpg_composed_props, &look, NULL, NULL));
}

/*
 * Functions for manipulating the avalues structure.
 */

/*
 * Free allocated memory referenced by the avalues structure.  Then, free
 * the structure itself.
 */
static void
av_destroy(avalues_t *av)
{
	if (av == NULL)
		return;
	switch (av->av_type) {
	case SCF_TYPE_BOOLEAN:
	case SCF_TYPE_COUNT:
		uu_free(av->av_v.av_unsigned);
		break;
	case SCF_TYPE_INTEGER:
		uu_free(av->av_v.av_integer);
		break;
	default:
		/*
		 * We don't need to free the strings that are referenced by
		 * av_string.  The strings are held in propery_t structures
		 * that will be freed at a later time.
		 */
		uu_free(av->av_v.av_string);
		break;
	}
	uu_free(av);
}
/*
 * Allocate and inialize an avalues structure.  count represents the
 * number of values the structure is expected to hold.  type specifies how
 * the consumer of the property values would like to see them represented.
 * See comments for the av_get_values() more details on how type is used.
 *
 * The returned structure must be freed by calling av_destroy().
 *
 * NULL is returned if memory allocation fails.
 */
static avalues_t *
av_create(size_t count, scf_type_t type)
{
	uint_t alloc_failed = 0;
	avalues_t *av;

	av = uu_zalloc(sizeof (*av));
	if (av == NULL)
		return (NULL);
	av->av_count = count;
	av->av_type = type;
	switch (type) {
	case SCF_TYPE_BOOLEAN:
	case SCF_TYPE_COUNT:
		av->av_v.av_unsigned = uu_zalloc(count * sizeof (uint64_t));
		if (av->av_v.av_unsigned == NULL)
			alloc_failed = 1;
		break;
	case SCF_TYPE_INTEGER:
		av->av_v.av_integer = uu_zalloc(count * sizeof (int64_t));
		if (av->av_v.av_integer == NULL)
			alloc_failed = 1;
		break;
	default:
		av->av_v.av_string = uu_zalloc(count * sizeof (char *));
		if (av->av_v.av_string == NULL)
			alloc_failed = 1;
	}
	if (alloc_failed) {
		av_destroy(av);
		return (NULL);
	}
	return (av);
}

/*
 * Return the ith integer value in av.
 */
static int64_t
av_get_integer(avalues_t *av, uint_t i)
{
	assert(av->av_type == SCF_TYPE_INTEGER);
	assert(i < av->av_count);
	return (*(av->av_v.av_integer + i));
}

/*
 * Return the ith string value in av.
 */
static const char *
av_get_string(avalues_t *av, uint_t i)
{
	assert(is_numeric_type(av->av_type) == 0);
	assert(i < av->av_count);
	return (*(av->av_v.av_string + i));
}

/*
 * Return the ith unsigned value in av.
 */
static uint64_t
av_get_unsigned(avalues_t *av, uint_t i)
{
	assert((av->av_type == SCF_TYPE_BOOLEAN) ||
	    (av->av_type == SCF_TYPE_COUNT));
	assert(i < av->av_count);
	return (*(av->av_v.av_unsigned + i));
}

/*
 * Store the value in the ith slot of the av structure.  If av is being
 * used to store numeric values, the string at value will be converted to
 * the appropriate numeric form.
 */
static tmpl_validate_status_t
av_set_value(avalues_t *av, uint_t i, const char *value)
{
	char *endptr;
	int64_t n;
	uint64_t un;

	if (is_numeric_type(av->av_type)) {
		switch (av->av_type) {
		case SCF_TYPE_BOOLEAN:
		case SCF_TYPE_COUNT:
			un = strtoull(value, &endptr, 0);
			if ((endptr == value) || (*endptr != 0)) {
				return (TVS_BAD_CONVERSION);
			}
			*(av->av_v.av_unsigned + i) = un;
			break;
		case SCF_TYPE_INTEGER:
			n = strtoll(value, &endptr, 0);
			if ((endptr == value) || (*endptr != 0)) {
				return (TVS_BAD_CONVERSION);
			}
			*(av->av_v.av_integer + i) = n;
		}
	} else {
		*(av->av_v.av_string + i) = value;
	}

	return (TVS_SUCCESS);
}

/*
 * Find the property whose name is prop_name in the property group at pg.
 * Read all the values of this property and return them in an avalues
 * structure placing the address of the structure in *values.  The caller
 * must free the structure by calling av_destroy().
 *
 * The type parameter is used to indicate the type of information that the
 * caller would like to consume.  If it is one of the numeric types, the
 * property value will be converted to the appropriate numeric type before
 * placing it in the avalues struct.  Decoding will be done before the
 * conversion if necessary.
 */
static tmpl_validate_status_t
av_get_values(pgroup_t *pg, const char *prop_name, scf_type_t type,
    avalues_t **values)
{
	avalues_t *av;
	uint_t i;
	property_t *prop;
	tmpl_validate_status_t rc;
	value_t *v;

	prop = property_find(pg, prop_name);
	if (prop == NULL) {
		return (TVS_NOMATCH);
	}
	assert(prop->sc_value_type == SCF_TYPE_ASTRING);
	av = av_create(count_prop_values(prop), type);
	if (av == NULL)
		uu_die(emesg_nomem);

	/* Collect the values. */
	for ((v = uu_list_first(prop->sc_property_values)), i = 0;
	    v != NULL;
	    (v = uu_list_next(prop->sc_property_values, v)), i++) {
		assert(i < av->av_count);
		assert(v->sc_type == SCF_TYPE_ASTRING);
		rc = av_set_value(av, i, v->sc_u.sc_string);
		if (rc != TVS_SUCCESS) {
			av_destroy(av);
			return (rc);
		}
	}
	*values = av;
	return (TVS_SUCCESS);
}

/*
 * Find the property in pg whose name is prop_name.  Return a pointer to
 * the first astring value in that property.
 *
 * NULL is returned if there is no property named prop_name or if it does
 * not have an astring value.
 */
static const char *
find_astring_value_in_pg(pgroup_t *pg, const char *prop_name)
{
	property_t *prop;
	value_t *v;

	prop = property_find(pg, prop_name);
	if (prop == NULL)
		return (NULL);
	if (prop->sc_value_type != SCF_TYPE_ASTRING)
		return (NULL);
	v = uu_list_first(prop->sc_property_values);
	if (v == NULL)
		return (NULL);
	assert(v->sc_type == SCF_TYPE_ASTRING);
	return (v->sc_u.sc_string);
}
/*
 * Find the first property value of type SCF_TYPE_COUNT in the property at
 * prop.  Return the value to count.
 */
static tmpl_validate_status_t
find_count_value(property_t *prop, uint64_t *count)
{
	value_t *value;

	assert(prop->sc_value_type == SCF_TYPE_COUNT);
	value = uu_list_first(prop->sc_property_values);
	if (value == NULL)
		return (TVS_NOMATCH);
	*count = value->sc_u.sc_count;
	return (TVS_SUCCESS);
}

/*
 * pattern is a property group representing a pg_pattern or a
 * prop_pattern.  This function returns the name specification from the
 * pg_pattern or prop_pattern.
 */
static const char *
find_name_specification(pgroup_t *pattern)
{
	return (find_astring_value_in_pg(pattern, SCF_PROPERTY_TM_NAME));
}

/*
 * pattern is a property group representing a pg_pattern or a prop_pattern.
 * This function returns the type specification from the pg_pattern or
 * prop_pattern.
 */
static const char *
find_type_specification(pgroup_t *pattern)
{
	return (find_astring_value_in_pg(pattern, SCF_PROPERTY_TM_TYPE));
}

/*
 * Find the FMRI of the restarter for the entity, e.  The restarter is the
 * value of the "restarter" property in the "general" property group.
 */
static const char *
find_restarter(entity_t *e)
{
	pgroup_t *pg;
	property_t *prop;
	value_t *v;

	pg = internal_pgroup_find(e, scf_pg_general, scf_group_framework);
	if (pg != NULL) {
		prop = property_find(pg, SCF_PROPERTY_RESTARTER);
		if ((prop != NULL) && (prop->sc_value_type == SCF_TYPE_FMRI)) {
			v = uu_list_first(prop->sc_property_values);
			if (v != NULL)
				return (v->sc_u.sc_string);
		}
	}

	/*
	 * Didn't find the restarter.
	 */
	return (NULL);
}

/*
 * prop_pattern points to a prop_pattern.  This function finds the
 * cardinality specification in the prop_pattern and returns the minimum
 * and maximum values of the cardinality.
 *
 * Returns TVS_NOMATCH if either the cardinality minimum or maximum are
 * missing.
 */
static tmpl_validate_status_t
get_cardinality(pgroup_t *prop_pattern, uint64_t *min, uint64_t *max)
{
	property_t *prop;
	tmpl_validate_status_t rc;

	assert(strcmp(prop_pattern->sc_pgroup_type,
	    SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0);

	prop = property_find(prop_pattern,
	    SCF_PROPERTY_TM_CARDINALITY_MIN);
	if (prop == NULL)
		return (TVS_NOMATCH);
	rc = find_count_value(prop, min);
	if (rc != TVS_SUCCESS)
		return (rc);

	prop = property_find(prop_pattern,
	    SCF_PROPERTY_TM_CARDINALITY_MAX);
	if (prop == NULL)
		return (TVS_NOMATCH);
	rc = find_count_value(prop, max);

	return (rc);
}

/*
 * Ranges are represented as ASTRING values in the property at range_prop.
 * The minimum and maximum of the range are separated by a comma.
 *
 * range_prop can contain multiple range values, so we return a pointer to
 * an allocated array of range_t in ranges.  This array must be freed by
 * the caller using free().  count receives the number of range_t
 * structures that are allocated.
 *
 * type tells us whether the range values should be treated as signed or
 * unsigned.  It must be SCF_TYPE_COUNT or SCF_TYPE_INTEGER.
 */
static tmpl_validate_status_t
get_ranges(property_t *range_prop, scf_type_t type, range_t **ranges,
    uint_t *count)
{
	char *endptr;
	char *endptr2;
	range_t *r;
	value_t *value;

	*count = uu_list_numnodes(range_prop->sc_property_values);
	assert(*count != 0);
	r = safe_malloc(*count * sizeof (*r));
	*ranges = r;
	for (value = uu_list_first(range_prop->sc_property_values);
	    value != NULL;
	    value = uu_list_next(range_prop->sc_property_values, value)) {
		assert(value->sc_type == SCF_TYPE_ASTRING);

		/* First get the minimum */
		errno = 0;
		if (type == SCF_TYPE_INTEGER) {
			r->rng_u.rng_signed.rng_min =
			    strtoll(value->sc_u.sc_string, &endptr, 0);
		} else {
			r->rng_u.rng_unsigned.rng_min =
			    strtoull(value->sc_u.sc_string, &endptr, 0);
		}
		if ((errno != 0) || (endptr == value->sc_u.sc_string))
			goto badtemplate;
		if (*endptr != ',')
			goto badtemplate;

		/* Now get the maximum */
		endptr++;
		if (type == SCF_TYPE_INTEGER) {
			r->rng_u.rng_signed.rng_max =
			    strtoll(endptr, &endptr2, 0);
		} else {
			r->rng_u.rng_unsigned.rng_max =
			    strtoull(endptr, &endptr2, 0);
		}
		if ((errno != 0) || (endptr2 == endptr) ||
		    (*endptr2 != 0))
			goto badtemplate;
		r++;
	}

	return (TVS_SUCCESS);

badtemplate:
	free(*ranges);
	*ranges = NULL;
	return (TVS_BAD_TEMPLATE);
}

static tv_errors_t *
tv_errors_create(const char *fmri)
{
	tv_errors_t *ste;

	ste = safe_malloc(sizeof (*ste));
	uu_list_node_init(ste, &ste->tve_node, tv_errors_pool);
	ste->tve_errors = _scf_create_errors(fmri, 1);
	if (ste->tve_errors == NULL)
		uu_die(emesg_nomem);

	return (ste);
}

static void
destroy_scf_errors(tv_errors_t *ste)
{
	scf_tmpl_errors_destroy(ste->tve_errors);
	uu_list_node_fini(ste, &ste->tve_node, tv_errors_pool);
	free(ste);
}

/*
 * Given a property group and the name of a property within that property
 * group, generate the name of the property group that holds the
 * prop_pattern information for the property.  The address of the generated
 * name is returned to prop_pattern_pg_name.  The memory holding the
 * generated name must be freed using uu_free().
 */
static tmpl_validate_status_t
gen_prop_pattern_pg_name(pgroup_t *pg_pattern, const char *prop_name,
    char **prop_pattern_pg_name)
{
	ssize_t limit;
	char *name;
	size_t prefix_size;
	const char *unique;

	limit = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH) + 1;
	assert(limit > 0);

	/* Get the unique part of the pg_pattern's property group name. */
	prefix_size = strlen(SCF_PG_TM_PG_PAT_BASE);
	assert(strncmp(pg_pattern->sc_pgroup_name, SCF_PG_TM_PG_PAT_BASE,
	    prefix_size) == 0);
	unique = pg_pattern->sc_pgroup_name + prefix_size;

	/* Construct the prop pattern property group name. */
	*prop_pattern_pg_name = NULL;
	name = uu_zalloc(limit);
	if (name == NULL)
		uu_die(emesg_nomem);
	if (snprintf(name, limit, "%s%s_%s", SCF_PG_TM_PROP_PATTERN_PREFIX,
	    unique, prop_name) >= limit) {
		uu_free(name);
		return (TVS_BAD_TEMPLATE);
	}
	*prop_pattern_pg_name = name;
	return (TVS_SUCCESS);
}

/*
 * Error message printing functions:
 */

/*
 * Flags for use by im_perror_item.
 */
#define	IPI_NOT_FIRST	0x1	/* Not first item to be displayed. */

/*
 * Print a single item of information about a validation failure.  This
 * function takes care of printing the appropriate decoration before the
 * first item and between subsequent items.
 *
 * Parameters:
 *	out		Stream to receive the output.
 *	desc		Text describing the items
 *	item		Address of the item to be displayed
 *	type		Type of the item
 *	flags		Used by im_perror_item to keep track of where it
 *			is.  Caller should set flags to 0 before calling
 *			this function with the first item.
 */
static void
im_perror_item(FILE *out, const char *desc, void *item, scf_type_t type,
    int *flags)
{
	const char *cp;
	const char *first_sep;
	int64_t ival;
	const char *subsequent_sep;
	uint64_t uval;

	/* Nothing to print if item is NULL. */
	if (item == NULL)
		return;

	assert(type != SCF_TYPE_INVALID);

	/* Establish separators for environment. */
	if (est->sc_cmd_flags & SC_CMD_IACTIVE) {
		/* Interactive mode - make messages readable */
		first_sep = ":\n\t";
		subsequent_sep = "\n\t";
	} else {
		/* Non-interactive - one line messages. */
		first_sep = ": ";
		subsequent_sep = "; ";
	}

	/* Print separator and description */
	if (*flags & IPI_NOT_FIRST) {
		(void) fprintf(out, subsequent_sep);
	} else {
		(void) fprintf(out, first_sep);
		*flags |= IPI_NOT_FIRST;
	}
	(void) fprintf(out, "%s=", desc);

	switch (type) {
	case SCF_TYPE_BOOLEAN:
		uval = *((uint64_t *)item);
		if (uval) {
			(void) fprintf(out, "\"%s\"", gettext("true"));
		} else {
			(void) fprintf(out, "\"%s\"", gettext("false"));
		}
		break;
	case SCF_TYPE_COUNT:
		uval = *((uint64_t *)item);
		(void) fprintf(out, "%" PRIu64, uval);
		break;
	case SCF_TYPE_INTEGER:
		ival = *((int64_t *)item);
		(void) fprintf(out, "%" PRIi64, ival);
		break;
	default:
		/*
		 * Treat everything else as a string, but escape any
		 * internal quotes.
		 */
		(void) fputc('\"', out);
		cp = (const char *)item;
		while (*cp != 0) {
			if (*cp == '\"') {
				(void) fprintf(out, "\\\"");
			} else {
				(void) fputc(*cp, out);
			}
			cp++;
		}
		(void) fputc('\"', out);
		break;
	}
}

/*
 * Print erroneous FMRI.
 */
static void
im_perror_fmri(FILE *out, im_tmpl_error_t *i, int *flags)
{
	if (i->ite_entity != NULL) {
		im_perror_item(out, "FMRI", (void *)i->ite_entity->sc_fmri,
		    SCF_TYPE_FMRI, flags);
	}
}

/*
 * Print erroneous property group name.
 */
static void
im_perror_pg_name(FILE *out, im_tmpl_error_t *i, int *flags)
{
	if (i->ite_pg != NULL) {
		im_perror_item(out, gettext("Property group"),
		    (void *)i->ite_pg->sc_pgroup_name, SCF_TYPE_ASTRING,
		    flags);
	}
}

/*
 * If srcflag is 1, print the template source of the pg_pattern or
 * prop_pattern at pattern.  Always print the name and type of the pattern.
 */
static void
im_perror_pattern_info(FILE *out, pgroup_t *pattern, int *flags, int srcflag)
{
	void *c;
	const char *name_string;
	const char *type_string;

	if (pattern == NULL)
		return;
	switch (pgroup_type(pattern)) {
	case PG_PATTERN_PG:
		name_string = gettext("pg_pattern name");
		type_string = gettext("pg_pattern type");
		break;
	case PROP_PATTERN_PG:
		name_string = gettext("prop_pattern name");
		type_string = gettext("prop_pattern type");
		break;
	default:
		assert(0);
		abort();
	}
	if (srcflag) {
		im_perror_item(out, gettext("Template source"),
		    (void *)pattern->sc_parent->sc_fmri, SCF_TYPE_FMRI, flags);
	}
	c = (void *)find_name_specification(pattern);
	im_perror_item(out, name_string,
	    (c == NULL) ? "" : c, SCF_TYPE_ASTRING, flags);
	c = (void *)find_type_specification(pattern);
	im_perror_item(out, type_string,
	    (c == NULL) ? "" : c, SCF_TYPE_ASTRING, flags);
}

/*
 * Print information about the template specifications that were violated,
 * so that the user can find the specification.
 */
static void
im_perror_template_info(FILE *out, im_tmpl_error_t *i, int *flags)
{
	pgroup_t *pg_pattern = i->ite_pg_pattern;
	pgroup_t *prop_pattern = i->ite_prop_pattern;
	int srcflag = 1;

	if (pg_pattern != NULL) {
		im_perror_pattern_info(out, pg_pattern, flags, srcflag);
		srcflag = 0;
	}
	if (prop_pattern != NULL) {
		im_perror_pattern_info(out, prop_pattern, flags, srcflag);
	}
}

/* Print error message for TVS_BAD_CONVERSION errors. */
static void
im_perror_bad_conversion(FILE *out, im_tmpl_error_t *i, const char *prefix)
{
	int flags = 0;

	(void) fprintf(out, gettext("%sUnable to convert property value"),
	    prefix);
	im_perror_fmri(out, i, &flags);
	im_perror_pg_name(out, i, &flags);
	im_perror_item(out, gettext("Property"),
	    (void *)i->ite_prop->sc_property_name, SCF_TYPE_ASTRING, &flags);
	im_perror_template_info(out, i, &flags);
	(void) fputc('\n', out);
}

/* Print error message for TVS_BAD_TEMPLATE errors. */
static void
im_perror_bad_template(FILE *out, im_tmpl_error_t *i, const char *prefix)
{
	int flags = 0;

	assert(i->ite_einfo.ei_type == EIT_BAD_TEMPLATE);
	(void) fprintf(out, gettext("%sInvalid template - %s"), prefix,
	    i->ite_einfo.ei_u.ei_bad_template.ei_reason);
	im_perror_fmri(out, i, &flags);
	im_perror_template_info(out, i, &flags);
	(void) fputc('\n', out);
}

/*
 * Print error message for TVS_INVALID_TYPE_SPECIFICATION errors.  This
 * error occurs if a prop_pattern has an invalid type specification.  Thus,
 * it is an indication of an invalid template rather than a violation of a
 * template.
 */
static void
im_perror_invalid_type(FILE *out, im_tmpl_error_t *i, const char *prefix)
{
	int flags = 0;
	const char *prop_pattern_name;

	(void) fprintf(out, gettext("%sInvalid type in prop_pattern"), prefix);
	im_perror_pg_name(out, i, &flags);
	if (i->ite_prop_pattern != NULL) {
		prop_pattern_name =
		    find_name_specification(i->ite_prop_pattern);
		im_perror_item(out, gettext("prop_pattern name"),
		    (void *)prop_pattern_name, SCF_TYPE_ASTRING, &flags);
	}
	im_perror_template_info(out, i, &flags);
	(void) fputc('\n', out);
}

/*
 * Print error message for TVS_MISSING_PG_TYPE errors.  In this case the
 * template specifies a type, but the property group itself has no type.
 */
static void
im_perror_missing_pg_type(FILE *out, im_tmpl_error_t *i, const char *prefix)
{
	int flags = 0;
	const char *type_spec;

	(void) fprintf(out, gettext("%sProperty group has no type"), prefix);
	im_perror_fmri(out, i, &flags);
	im_perror_pg_name(out, i, &flags);
	if (i->ite_pg_pattern != NULL) {
		type_spec = find_type_specification(i->ite_pg_pattern);
		im_perror_item(out, gettext("Type specified in pg_pattern"),
		    (void *)type_spec, SCF_TYPE_ASTRING, &flags);
	}
	(void) fputc('\n', out);
}

/*
 * Print error message for TVS_MISSING_TYPE_SPECIFICATION errors.  A
 * property group has a "required" attribute of true, but it does not have
 * a type specification.
 */
static void
im_perror_missing_type(FILE *out, im_tmpl_error_t *i, const char *prefix)
{
	int flags = 0;
	const char *pg_pattern_name;

	(void) fprintf(out, gettext("%sPg_pattern with true required attribute "
	    "is missing the type attribute"), prefix);
	im_perror_fmri(out, i, &flags);
	if (i->ite_pg_pattern != NULL) {
		pg_pattern_name = find_name_specification(i->ite_pg_pattern);
		im_perror_item(out, gettext("Pg_pattern name"),
		    (void *)pg_pattern_name, SCF_TYPE_ASTRING, &flags);
	}
	im_perror_template_info(out, i, &flags);
	(void) fputc('\n', out);
}

static void
im_tmpl_error_print(FILE *out, im_tmpl_error_t *ite, const char *prefix)
{
	switch (ite->ite_type) {
	case TVS_BAD_CONVERSION:
		im_perror_bad_conversion(out, ite, prefix);
		break;
	case TVS_BAD_TEMPLATE:
		im_perror_bad_template(out, ite, prefix);
		break;
	case TVS_INVALID_TYPE_SPECIFICATION:
		im_perror_invalid_type(out, ite, prefix);
		break;
	case TVS_MISSING_PG_TYPE:
		im_perror_missing_pg_type(out, ite, prefix);
		break;
	case TVS_MISSING_TYPE_SPECIFICATION:
		im_perror_missing_type(out, ite, prefix);
		break;
	case TVS_NOMATCH:
		/*
		 * TVS_NOMATCH should be handled where it occurs.  Thus,
		 * there are no error messages associated with it.
		 */
		assert(0);
		abort();
		break;
	case TVS_SUCCESS:
		break;
	default:
		assert(0);
		abort();
	}
}

static char *
int64_to_str(int64_t i)
{
	char *c;
	const char *fmt;
	int size;

	fmt = "%" PRIi64;
	size = snprintf(NULL, 0, fmt, i) + 1;
	c = safe_malloc(size);
	(void) snprintf(c, size, fmt, i);
	return (c);
}

static char *
uint64_to_str(uint64_t u)
{
	char *c;
	const char *fmt;
	int size;

	fmt = "%" PRIu64;
	size = snprintf(NULL, 0, fmt, u) + 1;
	c = safe_malloc(size);
	(void) snprintf(c, size, fmt, u);
	return (c);
}

/*
 * Convert the value to a string.  The returned value must be freed using
 * free(3C).
 */
static const char *
value_to_string(value_t *v)
{
	char *c;

	if (is_numeric_type(v->sc_type)) {
		switch (v->sc_type) {
		case SCF_TYPE_BOOLEAN:
			if (v->sc_u.sc_count == 0) {
				c = gettext("false");
			} else {
				c = gettext("true");
			}
			break;
		case SCF_TYPE_COUNT:
			c = uint64_to_str(v->sc_u.sc_count);
			return (c);
		case SCF_TYPE_INTEGER:
			c = int64_to_str(v->sc_u.sc_integer);
			return (c);
		}
	} else {
		c = v->sc_u.sc_string;
	}

	return (safe_strdup(c));
}

/*
 * Subscripts for common error data.
 */
#define	ED_PG_NAME	0
#define	ED_PROP_NAME	1
#define	ED_TMPL_FMRI	2
#define	ED_TMPL_PG_NAME	3
#define	ED_TMPL_PG_TYPE	4
#define	ED_TMPL_PROP_NAME	5
#define	ED_TMPL_PROP_TYPE	6
#define	ED_COUNT	7

/*
 * This function converts the error information specified by the function
 * parameters.  It converts it to form needed by _scf_tmpl_add_error().
 * _scf_tmpl_add_error() requires that the error information be in the form
 * of allocated strings that can be freed when it is done with them.  Thus,
 * the bulk of this function is devoted to producing those allocated
 * strings.
 *
 * Once the strings are ready, we call _scf_tmpl_add_error() to add an
 * new error structure to errs.
 */
static int
add_scf_error(tmpl_errors_t *errs, scf_tmpl_error_type_t ec,
    pgroup_t *pg_pattern, pgroup_t *pg, pgroup_t *prop_pattern,
    property_t *prop, value_t *val, error_info_t *einfo)
{
	const char *actual = NULL;
	char *c;
	pgroup_t *conflict;
	const char *ed[ED_COUNT];
	const char *ev1 = NULL;
	const char *ev2 = NULL;
	int i;
	scf_type_t prop_type;
	int rc;

	(void) memset(ed, 0, sizeof (ed));

	/* Set values that are common to most error types. */
	if (pg != NULL) {
		ed[ED_PG_NAME] = pg->sc_pgroup_name;
	}
	if (prop != NULL) {
		ed[ED_PROP_NAME] = prop->sc_property_name;
	}
	if (pg_pattern == NULL) {
		if (prop_pattern != NULL) {
			ed[ED_TMPL_FMRI] = prop_pattern->sc_parent->sc_fmri;
		}
	} else {
		ed[ED_TMPL_FMRI] = pg_pattern->sc_parent->sc_fmri;
		ed[ED_TMPL_PG_NAME] = find_name_specification(pg_pattern);
		ed[ED_TMPL_PG_TYPE] = find_type_specification(pg_pattern);
	}
	if (prop_pattern != NULL) {
		ed[ED_TMPL_PROP_NAME] = find_name_specification(prop_pattern);
		ed[ED_TMPL_PROP_TYPE] = find_type_specification(prop_pattern);
	}

	/*
	 * All of the strings that we've found must be strduped.  This is
	 * so that scf_tmpl_errors_destroy() can free them.  We cannot use
	 * the flag argument of _scf_create_errors() to indicate that the
	 * strings should not be freed.  The flag argument is an all or
	 * nothing thing.  In the code below we need to convert integers to
	 * strings, and this requires memory allocation.  Since we have to
	 * allocate memory for that data, we need to allocate it for every
	 * thing.
	 */
	for (i = 0; i < ED_COUNT; i++) {
		if (ed[i] == NULL)
			continue;
		ed[i] = safe_strdup(ed[i]);
	}

	/* actual, ev1 and ev2 are error code specific. */
	switch (ec) {
	case SCF_TERR_CARDINALITY_VIOLATION:
		assert(einfo != NULL);
		assert(einfo->ei_type == EIT_CARDINALITY);
		ev1 = uint64_to_str(einfo->ei_u.ei_cardinality.ei_min);
		ev2 = uint64_to_str(einfo->ei_u.ei_cardinality.ei_max);
		actual = uint64_to_str(einfo->ei_u.ei_cardinality.ei_count);
		break;
	case SCF_TERR_WRONG_PG_TYPE:
		/* Specified type. */
		if (pg_pattern != NULL) {
			ev1 = find_type_specification(pg_pattern);
			if (ev1 != NULL) {
				ev1 = safe_strdup(ev1);
			}
		}
		/* Actual type. */
		if (pg != NULL) {
			actual = pg->sc_pgroup_type;
			if (actual != NULL) {
				actual = safe_strdup(actual);
			}
		}
		break;
	case SCF_TERR_WRONG_PROP_TYPE:
		assert(einfo->ei_type == EIT_PROP_TYPE);
		prop_type = einfo->ei_u.ei_prop_type.ei_specified;
		ev1 = safe_strdup(scf_type_to_string(prop_type));
		prop_type = einfo->ei_u.ei_prop_type.ei_actual;
		actual = safe_strdup(scf_type_to_string(prop_type));
		break;
	case SCF_TERR_VALUE_CONSTRAINT_VIOLATED:
		actual = value_to_string(val);
		break;
	case SCF_TERR_MISSING_PG:
		assert(einfo->ei_type == EIT_MISSING_PG);
		ev1 = safe_strdup(einfo->ei_u.ei_missing_pg.ei_pg_name);
		ev2 = safe_strdup(einfo->ei_u.ei_missing_pg.ei_pg_type);
		break;
	case SCF_TERR_MISSING_PROP:
		assert(einfo->ei_type == EIT_MISSING_PROP);
		ev1 = safe_strdup(einfo->ei_u.ei_missing_prop.ei_prop_name);
		break;
	case SCF_TERR_RANGE_VIOLATION:
		assert(einfo->ei_type == EIT_RANGE);
		if (einfo->ei_u.ei_range.ei_rtype == SCF_TYPE_COUNT) {
			c = uint64_to_str(einfo->ei_u.ei_range.ei_uvalue);
		} else {
			c = int64_to_str(einfo->ei_u.ei_range.ei_ivalue);
		}
		actual = c;
		break;
	case SCF_TERR_PG_PATTERN_CONFLICT:
	case SCF_TERR_PROP_PATTERN_CONFLICT:
	case SCF_TERR_GENERAL_REDEFINE:
		assert(einfo->ei_type == EIT_PATTERN_CONFLICT);
		conflict = einfo->ei_u.ei_pattern_conflict.ei_pattern;
		ev1 = safe_strdup(conflict->sc_parent->sc_fmri);
		ev2 = find_name_specification(conflict);
		if (ev2 != NULL)
			ev2 = safe_strdup(ev2);
		actual = find_type_specification(conflict);
		if (actual != NULL)
			actual = safe_strdup(actual);
		break;
	case SCF_TERR_INCLUDE_VALUES:
		assert(einfo->ei_type == EIT_INCLUDE_VALUES);
		ev1 = safe_strdup(einfo->ei_u.ei_inc_values.ei_type);
		break;
	case SCF_TERR_PG_PATTERN_INCOMPLETE:
	case SCF_TERR_PROP_PATTERN_INCOMPLETE:
		break;
	default:
		assert(0);
		abort();
	};

	rc = _scf_tmpl_add_error(errs->te_cur_scf->tve_errors, ec,
	    ed[ED_PG_NAME], ed[ED_PROP_NAME], ev1, ev2, actual,
	    ed[ED_TMPL_FMRI], ed[ED_TMPL_PG_NAME], ed[ED_TMPL_PG_TYPE],
	    ed[ED_TMPL_PROP_NAME], ed[ED_TMPL_PROP_TYPE]);

	return (rc);
}

/*
 * Create and initialize a new im_tmpl_error structure and add it to the
 * list of errors in errs.  The rest of the parameters are used to
 * initialize the im_tmpl_error structure.
 */
static tmpl_validate_status_t
tmpl_errors_add_im(tmpl_errors_t *errs, tmpl_validate_status_t ec, entity_t *e,
    pgroup_t *pg_pattern, pgroup_t *pg, pgroup_t *prop_pattern,
    property_t *prop, value_t *val, error_info_t *einfo)
{
	im_tmpl_error_t *ite;
	int result;

	ite = uu_zalloc(sizeof (*ite));
	if (ite == NULL)
		uu_die(emesg_nomem);
	uu_list_node_init(ite, &ite->ite_node, inmem_errors_pool);
	ite->ite_type = ec;
	ite->ite_entity = e;
	ite->ite_pg = pg;
	ite->ite_pg_pattern = pg_pattern;
	ite->ite_prop = prop;
	ite->ite_prop_pattern = prop_pattern;
	ite->ite_value = val;
	if (einfo != NULL)
		ite->ite_einfo = *einfo;

	result = uu_list_insert_after(errs->te_list, NULL, ite);
	assert(result == 0);
	return (TVS_SUCCESS);
}

/*
 * pattern must point to a pg_pattern or a prop_pattern.  This function
 * finds the property named required and returns the property's value.  If
 * the property does not exist, false is return since it is the default.
 */
static int
is_required(pgroup_t *pattern)
{
	property_t *required;
	value_t *value;

	assert((strcmp(pattern->sc_pgroup_type,
	    SCF_GROUP_TEMPLATE_PG_PATTERN) == 0) ||
	    (strcmp(pattern->sc_pgroup_type,
	    SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0));

	required = property_find(pattern, SCF_PROPERTY_TM_REQUIRED);

	/* Default if there is no required property is false. */
	if (required == NULL)
		return (0);

	/* Retrieve the value of the required property. */
	value = uu_list_first(required->sc_property_values);
	if (value == NULL)
		return (0);
	if (value->sc_type == SCF_TYPE_BOOLEAN)
		return (value->sc_u.sc_count == 0 ? 0 : 1);

	/* No boolean property values, so return false. */
	return (0);
}

/*
 * Load the service's restarter instance and the global instance from the
 * repository.  This will allow us to use their templates in validating the
 * service.
 *
 * There is no function to unload the general templates.  The memory that
 * is allocated by load_general_templates() will be freed automatically in
 * internal_service_free() which is called by internal_bundle_free().
 */
static void
load_general_templates(entity_t *svc)
{
	const char *restarter;
	int is_global = 0;
	int r;

	assert(svc->sc_etype == SVCCFG_SERVICE_OBJECT);

	/*
	 * If e is the global service, we only need to load the restarter.
	 */
	if ((strcmp(svc->sc_fmri, SCF_INSTANCE_GLOBAL) == 0) ||
	    (strcmp(svc->sc_fmri, SCF_SERVICE_GLOBAL) == 0)) {
		is_global = 1;
	}

	/*
	 * Load the templates for the service's restarter.
	 */
	restarter = find_restarter(svc);
	if (restarter == NULL)
		restarter = SCF_SERVICE_STARTD;
	if ((r = load_instance(restarter, "restarter",
	    &svc->sc_u.sc_service.sc_restarter)) != 0) {
		/*
		 * During initial manifest import, restarter may
		 * not be in the repository yet.  In this case we
		 * continue on without it.
		 */
		if (r == EINVAL)
			warn(gettext("WARNING: restarter FMRI %s is invalid\n"),
			    restarter);

		if (r == ENOTSUP)
			warn(gettext("WARNING: restarter FMRI %s is not valid; "
			    "instance fmri required.\n"), restarter);

		if (r == ENOMEM)
			uu_die(emesg_nomem);

		svc->sc_u.sc_service.sc_restarter = NULL;
	}
	if (is_global == 0) {
		if ((r = load_instance(SCF_INSTANCE_GLOBAL, "global",
		    &svc->sc_u.sc_service.sc_global)) != 0) {
			/*
			 * During initial manifest import, global may not be in
			 * the repository yet.
			 */
			if (r == ENOMEM)
				uu_die(emesg_nomem);
			else
				svc->sc_u.sc_service.sc_global = NULL;
		}
	}
}

/*
 * Load the instance specific restarter if one is declared.
 *
 * There is no corresponding unload_instance_restarter() function because
 * it is not needed.  The memory will be freed in internal_instance_free()
 * when internal_bundle_free() is called.
 */
static void
load_instance_restarter(entity_t *i)
{
	const char *restarter;
	int r;

	assert(i->sc_etype == SVCCFG_INSTANCE_OBJECT);

	restarter = find_restarter(i);
	if (restarter == NULL) {
		/* No instance specific restarter */
		return;
	}
	r = load_instance(restarter, "instance_restarter",
	    &i->sc_u.sc_instance.sc_instance_restarter);
	if (r != 0) {
		/*
		 * During initial manifest import, the restarter may not be
		 * in the repository yet.  In this case we continue on
		 * without it.
		 */
		if (r == EINVAL)
			warn(gettext("WARNING: restarter FMRI %s is invalid\n"),
			    restarter);

		if (r == ENOTSUP)
			warn(gettext("WARNING: restarter FMRI %s is not valid; "
			    "instance fmri required.\n"), restarter);

		if (r == ENOMEM)
			uu_die(emesg_nomem);
	}
}

/*
 * Find the next property after current in the property group at pg.  If
 * the property group contains a tree of composed properties, that tree is
 * walked.  Otherwise, we walk through the uu_list at sc_pgroup_props.
 */
static property_t *
next_property(pgroup_t *pg, property_t *current)
{
	composed_pg_t *cpg;
	property_t *prop;

	cpg = pg->sc_pgroup_composed;
	if ((cpg != NULL) && (cpg->cpg_composed_props != NULL)) {
		/* Walk through composed property list. */
		if (current) {
			prop = uu_avl_next(cpg->cpg_composed_props, current);
		} else {
			prop = uu_avl_first(cpg->cpg_composed_props);
		}
	} else {
		/* No composition available, so walk the list of properties */
		if (current) {
			prop = uu_list_next(pg->sc_pgroup_props, current);
		} else {
			prop = uu_list_first(pg->sc_pgroup_props);
		}
	}

	return (prop);
}

static ptrn_info_t *
ptrn_info_create(pgroup_t *pat)
{
	entity_t *e;
	ptrn_info_t *info;
	composed_pg_t *match;
	composed_pg_t cpg;

	info = safe_malloc(sizeof (*info));

	switch (pgroup_type(pat)) {
	case PG_PATTERN_PG:
		info->pi_ptrn_type = PG_PATTERN;
		break;
	case PROP_PATTERN_PG:
		info->pi_ptrn_type = PROP_PATTERN;
		break;
	default:
		assert(0);
		abort();
	}
	info->pi_ptrnpg = pat;
	info->pi_name = find_name_specification(pat);
	info->pi_name = EMPTY_TO_NULL(info->pi_name);
	info->pi_type = find_type_specification(pat);
	info->pi_type = EMPTY_TO_NULL(info->pi_type);
	if (info->pi_ptrn_type == PG_PATTERN) {
		info->pi_target = find_astring_value_in_pg(pat,
		    SCF_PROPERTY_TM_TARGET);
		if (info->pi_target == NULL)
			info->pi_target = SCF_TM_TARGET_THIS;
	}
	if (info->pi_ptrn_type == PROP_PATTERN) {
		info->pi_pgp_name = find_astring_value_in_pg(pat,
		    SCF_PROPERTY_TM_PG_PATTERN);
		assert((info->pi_pgp_name != NULL) &&
		    (*(info->pi_pgp_name) != 0));

		/*
		 * Find the property group that defines the pg_pattern that
		 * holds this prop_pattern.
		 */
		e = pat->sc_parent;
		if (e->sc_etype == SVCCFG_INSTANCE_OBJECT) {
			(void) memset(&cpg, 0, sizeof (cpg));
			cpg.cpg_name = info->pi_pgp_name;
			cpg.cpg_type = SCF_GROUP_TEMPLATE_PG_PATTERN;
			match = uu_avl_find(e->sc_u.sc_instance.sc_composed,
			    &cpg, NULL, NULL);
			assert(match != NULL);
			info->pi_enc_pgp = CPG2PG(match);
		} else {
			info->pi_enc_pgp = internal_pgroup_find(e,
			    info->pi_pgp_name, SCF_GROUP_TEMPLATE_PG_PATTERN);
		}
		assert(info->pi_enc_pgp != NULL);
	}
	uu_avl_node_init(info, &info->pi_link, ptrn_info_pool);
	return (info);
}

static void
ptrn_info_destroy(ptrn_info_t *info)
{
	if (info == NULL)
		return;
	uu_avl_node_fini(info, &info->pi_link, ptrn_info_pool);
	free(info);
}

/*
 * Walk through the property groups of the instance or service at e looking
 * for definitions of pg_patterns or prop_patterns as specified by type.
 * For each property group that matches type create a ptrn_info_t and add
 * it to the avl tree at tree.  If duplicates are found add an error entry
 * to errs.
 */
static tmpl_validate_status_t
gather_pattern(entity_t *e, ptrn_type_t type, uu_avl_t *tree,
    tmpl_errors_t *errs)
{
	error_info_t einfo;
	ptrn_info_t *info = NULL;
	uu_avl_index_t marker;
	ptrn_info_t *match;
	pgroup_t *pg;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	const char *selector;

	switch (type) {
	case PG_PATTERN:
		selector = SCF_GROUP_TEMPLATE_PG_PATTERN;
		break;
	case PROP_PATTERN:
		selector = SCF_GROUP_TEMPLATE_PROP_PATTERN;
		break;
	default:
		assert(0);
		abort();
	}

	for (pg = uu_list_first(e->sc_pgroups);
	    pg != NULL;
	    pg = uu_list_next(e->sc_pgroups, pg)) {
		if (strcmp(pg->sc_pgroup_type, selector) != 0) {
			continue;
		}
		if (info != NULL) {
			/* Get rid of old structure. */
			ptrn_info_destroy(info);
		}
		info = ptrn_info_create(pg);
		match = uu_avl_find(tree, info, NULL, &marker);
		if (match == NULL) {
			/* No match.  Insert the info. */
			uu_avl_insert(tree, info, marker);
			info = NULL;
			continue;
		}

		/* Got a match.  Determine if it is a conflict. */
		if ((info->pi_name == NULL) ||
		    (info->pi_type == NULL) ||
		    (match->pi_name == NULL) ||
		    (match->pi_type == NULL)) {
			/* No conflicts if any wild cards. */
			continue;
		}

		/*
		 * Name already matches, or we wouldn't have gotten
		 * here.  Make sure that the type also matches.
		 */
		if (strcmp(info->pi_type, match->pi_type) == 0) {
			continue;
		}

		/*
		 * If we get to this point we have a conflict, and
		 * we need to generate the correct type of error.
		 */
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_PATTERN_CONFLICT;
		einfo.ei_u.ei_pattern_conflict.ei_pattern =
		    match->pi_ptrnpg;
		if (type == PG_PATTERN) {
			rc = TVS_VALIDATION;
			if (add_scf_error(errs, SCF_TERR_PG_PATTERN_CONFLICT,
			    info->pi_ptrnpg, NULL, NULL, NULL, NULL,
			    &einfo) != 0) {
				/*
				 * If we can no longer accumulate
				 * errors, break out of the loop.
				 */
				break;
			}
		} else {
			/*
			 * Possible conflicting prop_pattern.  See if the
			 * prop_patterns are declared in the same
			 * pg_pattern.
			 */
			if ((info->pi_pgp_name == NULL) ||
			    (match->pi_pgp_name == NULL)) {
				continue;
			}
			if (strcmp(info->pi_pgp_name, match->pi_pgp_name) != 0)
				continue;

			/* It is a real conflict. */
			rc = TVS_VALIDATION;
			if (add_scf_error(errs, SCF_TERR_PROP_PATTERN_CONFLICT,
			    info->pi_enc_pgp, NULL, info->pi_ptrnpg, NULL, NULL,
			    &einfo) != 0) {
				/*
				 * If we can no longer accumulate
				 * errors, break out of the loop.
				 */
				break;
			}
		}
	}

	ptrn_info_destroy(info);
	return (rc);
}

/*
 * Free the pg_iter structure.
 */
static void
pg_iter_destroy(pg_iter_t *i)
{
	if (i == NULL)
		return;

	uu_free(i);
}

/*
 * Create a property group iterator for the instance at e.  This iterator
 * will walk through the composed property groups of the instance.  It will
 * then step through the property groups of the instance's restarter and
 * finally the global service.  If you wish to iterate over a specific type
 * of property group, set restriction to point the the desired type.
 * Otherwise set restriction to NULL.
 *
 * The returned interator must be freed by calling pg_iter_destroy().  NULL
 * is returned if we are unable to allocate the necessary memory.
 */
static pg_iter_t *
pg_iter_create(entity_t *e, const char *restriction)
{
	pg_iter_t *i;

	assert(e->sc_etype == SVCCFG_INSTANCE_OBJECT);

	i = uu_zalloc(sizeof (*i));
	if (i == NULL)
		return (NULL);

	i->pgi_entity = e;
	i->pgi_restrict = restriction;
	i->pgi_level = TL_COMPOSED;
	i->pgi_service = e->sc_parent;

	return (i);
}

/*
 * Return the next property group in the iteration.  NULL is returned if we
 * reach the end of the list.  The iterator will automatically proceed from
 * most specific to most general levels.
 */
static pgroup_t *
next_pattern_pg(pg_iter_t *i)
{
	composed_pg_t *cpg;
	entity_t *e;
	pgroup_t *pg;
	uu_avl_t *composed_tree;

	assert(i->pgi_level != TL_NOLEVEL);

	while (i->pgi_entity != NULL) {
		if (i->pgi_level == TL_COMPOSED) {
			composed_tree =
			    i->pgi_entity->sc_u.sc_instance.sc_composed;
			cpg = i->pgi_current.pgi_cpg;
			if (cpg == NULL) {
				cpg = uu_avl_first(composed_tree);
			} else {
				cpg = uu_avl_next(composed_tree, cpg);
			}
			if (cpg == NULL) {
				pg = NULL;
			} else {
				pg = CPG2PG(cpg);
				i->pgi_current.pgi_cpg = cpg;
			}
		} else {
			pg = i->pgi_current.pgi_pg;
			if (pg == NULL) {
				pg = uu_list_first(i->pgi_entity->sc_pgroups);
			} else {
				pg = uu_list_next(i->pgi_entity->sc_pgroups,
				    pg);
			}
			i->pgi_current.pgi_pg = pg;
		}

		if (pg == NULL) {
			/*
			 * End of the list.  Reset current and break out of
			 * the loop.
			 */
			(void) memset(&i->pgi_current, 0,
			    sizeof (i->pgi_current));
			break;
		}

		/*
		 * If this iteration is for a specific type, verify that
		 * this pg is of that type.
		 */
		if (i->pgi_restrict) {
			if (strcmp(pg->sc_pgroup_type, i->pgi_restrict) != 0) {
				continue;
			}
		}

		return (pg);
	}

	/*
	 * End of the list in the current level.  Move up to the next
	 * level.
	 */
	switch (i->pgi_level) {
	case TL_COMPOSED:
		/* Skip service if we've finished a composed instance. */
		e = i->pgi_entity;
		if (e->sc_u.sc_instance.sc_instance_restarter == NULL) {
			/* Use service restarter */
			i->pgi_entity =
			    i->pgi_service->sc_u.sc_service.sc_restarter;
		} else {
			/* Use instance restarter */
			i->pgi_entity =
			    e->sc_u.sc_instance.sc_instance_restarter;
		}
		i->pgi_level = TL_RESTARTER;
		break;
	case TL_RESTARTER:
		i->pgi_entity = i->pgi_service->sc_u.sc_service.sc_global;
		i->pgi_level = TL_GLOBAL;
		break;
	case TL_GLOBAL:
		i->pgi_level = TL_NOLEVEL;
		return (NULL);
	default:
		assert(0);
		abort();
	}

	/* Go process the next level. */
	return (next_pattern_pg(i));
}

/*
 * Compare two pattern info structures (ptrn_info_t).  If both structures
 * have names, the comparison is based on the name.  If only one has a
 * name, the structure with no name will be first.  If neither structure
 * has a name, the comparison is based on their types using similar wild
 * card logic.
 */
/* ARGSUSED2 */
static int
ptrn_info_compare(const  void *left, const void *right, void *unused)
{
	ptrn_info_t *l = (ptrn_info_t *)left;
	ptrn_info_t *r = (ptrn_info_t *)right;

	if ((l->pi_name != NULL) && (r->pi_name != NULL))
		return (strcmp(l->pi_name, r->pi_name));
	if ((l->pi_name == NULL) && (r->pi_name == NULL)) {
		/* No names, so we need to compare types. */
		if ((l->pi_type != NULL) && (r->pi_type != NULL))
			return (strcmp(l->pi_type, r->pi_type));
		if ((l->pi_type == NULL) && (r->pi_type == NULL))
			return (0);

		/* If we get here, exactly one of the types is NULL */
		if (l->pi_type == NULL)
			return (-1);
		return (1);
	}

	/* If we get here, exactly one of the names is NULL */
	if (l->pi_name == NULL)
		return (-1);
	return (1);
}

/*
 * The target of a pg_pattern in combination with the level at which the
 * pg_pattern was defined determines whether or not it should be applied.
 * The following combinations should be ignored, and all others should be
 * applied.
 *
 *	Target		Level
 *	------		-----
 *	this		TL_RESTARTER, TL_GLOBAL
 *			"this" only applies if the pg_pattern was defined
 *			at the instance or service level
 *	delegate	TL_INSTANCE, TL_SERVICE
 *			Only restarters and the global service can
 *			delegate.
 *	instance	TL_INSTANCE, TL_RESTARTER, TL_GLOBAL
 *			Only the service level can specify the "instance"
 *			target.
 *	all		TL_INSTANCE, TL_SERVICE, TL_RESTARTER
 *			Only the global service can specify the "all"
 *			target.
 *
 * Return Values:
 *	1	apply the pg_pattern
 *	0	ignore the pg_pattern
 */
static int
target_check(const char *target, tmpl_level_t level)
{
	if ((target == NULL) || (*target == 0)) {
		/* Default is this */
		target = SCF_TM_TARGET_THIS;
	}
	if (strcmp(target, SCF_TM_TARGET_THIS) == 0) {
		if ((level == TL_RESTARTER) ||
		    (level == TL_GLOBAL)) {
			return (0);
		} else {
			return (1);
		}
	}
	if (strcmp(target, SCF_TM_TARGET_DELEGATE) == 0) {
		if ((level == TL_INSTANCE) ||
		    (level == TL_SERVICE)) {
			return (0);
		} else {
			return (1);
		}
	}
	if (strcmp(target, SCF_TM_TARGET_INSTANCE) == 0) {
		/*
		 * Note that the test is inverted from the other cases.
		 * This is because there is only one instance where apply
		 * is the correct thing to do.
		 */
		if (level == TL_SERVICE) {
			return (1);
		} else {
			return (0);
		}
	}
	if (strcmp(target, SCF_TM_TARGET_ALL) == 0) {
		if ((level == TL_INSTANCE) ||
		    (level == TL_SERVICE) ||
		    (level == TL_RESTARTER)) {
			return (0);
		}
	}
	return (1);
}

static int
pg_target_check(pgroup_t *pg_pattern, tmpl_level_t level)
{
	const char *target;

	target = find_astring_value_in_pg(pg_pattern, SCF_PROPERTY_TM_TARGET);
	if (level == TL_COMPOSED) {
		switch (pg_pattern->sc_parent->sc_etype) {
		case SVCCFG_INSTANCE_OBJECT:
			level = TL_INSTANCE;
			break;
		case SVCCFG_SERVICE_OBJECT:
			level = TL_SERVICE;
			break;
		default:
			assert(0);
			abort();
		}
	}
	return (target_check(target, level));
}

/*
 * Find the prop_pattern's type sepcification and convert it to the
 * appropriate scf_type.
 */
static tmpl_validate_status_t
prop_pattern_type(pgroup_t *pattern, scf_type_t *type)
{
	const char *type_spec;

	assert(strcmp(pattern->sc_pgroup_type,
	    SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0);

	type_spec = find_type_specification(pattern);
	if ((type_spec == NULL) || (*type_spec == 0))
		return (TVS_MISSING_TYPE_SPECIFICATION);
	*type = scf_string_to_type(type_spec);
	return (TVS_SUCCESS);
}

/*
 * This function is analagous to scf_property_is_type(3SCF), but it works
 * on the in memory representation of the property.
 *
 * RETURNS:
 *	0		The property at prop does not have the specified
 *			type.
 *	non-zero	The property at prop does have the specified type.
 */
static int
property_is_type(property_t *prop, scf_type_t type)
{
	return (scf_is_compatible_type(type, prop->sc_value_type) ==
	    SCF_SUCCESS);
}

/*
 * This function generates a property group name for a template's
 * pg_pattern.  The name and type of the pg_pattern are used to construct
 * the name, but either or both may be null.  A pointer to the constructed
 * name is returned, and the referenced memory must be freed using
 * free(3c).  NULL is returned if we are unable to allocate enough memory.
 */
static char *
gen_pg_pattern_pg_name(const char *name, const char *type)
{
	char *pg_name;
	char *rv = NULL;
	ssize_t	name_size;

	name_size = scf_limit(SCF_LIMIT_MAX_NAME_LENGTH);
	pg_name = safe_malloc(name_size);
	rv = pg_name;

	/*
	 * There are four cases -- name and type are both null, name and
	 * type are both non-null, only name is present or only type is
	 * present.
	 */
	if ((name == NULL) || (*name == 0)) {
		if ((type == NULL) || (*type == 0)) {
			/*
			 * Name and type are both null, so the PG name
			 * contains only the prefix.
			 */
			if (strlcpy(pg_name, SCF_PG_TM_PG_PATTERN_PREFIX,
			    name_size) >= name_size) {
				rv = NULL;
			}
		} else {
			/*
			 * If we have a type and no name, the type becomes
			 * part of the pg_pattern property group name.
			 */
			if (snprintf(pg_name, name_size, "%s%s",
			    SCF_PG_TM_PG_PATTERN_T_PREFIX, type) >=
			    name_size) {
				rv = NULL;
			}
		}
	} else {
		/*
		 * As long as the pg_pattern has a name, it becomes part of
		 * the name of the pg_pattern property group name.  We
		 * merely need to pick the appropriate prefix.
		 */
		const char *prefix;
		if ((type == NULL) || (*type == 0)) {
			prefix = SCF_PG_TM_PG_PATTERN_N_PREFIX;
		} else {
			prefix = SCF_PG_TM_PG_PATTERN_NT_PREFIX;
		}
		if (snprintf(pg_name, name_size, "%s%s", prefix, name) >=
		    name_size) {
			rv = NULL;
		}
	}

	if (rv == NULL) {
		/* Name was too big. */
		free(pg_name);
	}
	return (rv);
}

/*
 * pinfo contains information about a prop_pattern.  An include_values
 * element with a type of type has been included in the prop_pattern
 * specification.  We need to determine if the prop_pattern also contains
 * constraints or values specifications as determined by type.  Thus, we
 * search the prop_pattern for properties whose names start with the
 * correct prefix.
 */
static tmpl_validate_status_t
include_values_support(ptrn_info_t *pinfo, const char *type,
    tmpl_errors_t *errs)
{
	error_info_t einfo;
	int i;
	const char **prefixes;
	const char *pfx;
	property_t *prop;
	pgroup_t *ptrn;

	if (strcmp(type, "constraints") == 0) {
		prefixes = constraint_prefixes;
	} else if (strcmp(type, "values") == 0) {
		prefixes = value_prefixes;
	} else {
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_BAD_TEMPLATE;
		einfo.ei_u.ei_bad_template.ei_reason = gettext("include_values "
		    "type must be \"constraints\" or \"values\"");
		(void) tmpl_errors_add_im(errs, TVS_BAD_TEMPLATE,
		    pinfo->pi_ptrnpg->sc_parent, pinfo->pi_enc_pgp,
		    NULL, pinfo->pi_ptrnpg, NULL, NULL, &einfo);
		return (TVS_BAD_TEMPLATE);
	}

	/*
	 * Now see if the prop_pattern has a property whose name starts
	 * with one of these prefixes.
	 */
	ptrn = pinfo->pi_ptrnpg;
	for (prop = uu_list_first(ptrn->sc_pgroup_props);
	    prop != NULL;
	    prop = uu_list_next(ptrn->sc_pgroup_props, prop)) {
		for (pfx = prefixes[0], i = 0;
		    pfx != NULL;
		    ++i, pfx = prefixes[i]) {
			if (strncmp(prop->sc_property_name, pfx,
			    strlen(pfx)) == 0) {
				return (TVS_SUCCESS);
			}
		}
	}

	/* No match found.  Generate error */
	CLEAR_ERROR_INFO(&einfo);
	einfo.ei_type = EIT_INCLUDE_VALUES;
	einfo.ei_u.ei_inc_values.ei_type = type;
	(void) add_scf_error(errs, SCF_TERR_INCLUDE_VALUES, pinfo->pi_enc_pgp,
	    NULL, ptrn, NULL, NULL, &einfo);

	return (TVS_VALIDATION);
}

/*
 * Walk through the prop_patterns in tree, looking for any that have an
 * include_values, SCF_PROPERTY_TM_CHOICES_INCLUDE_VALUES, property.  For
 * the prop_patterns with the include values property, verify that the
 * prop_pattern has constraint or values declarations as specified by the
 * include_values property.
 */
static tmpl_validate_status_t
tmpl_include_values_check(uu_avl_t *tree, tmpl_errors_t *errs)
{
	ptrn_info_t *info;
	property_t *iv;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	value_t *v;

	for (info = uu_avl_first(tree);
	    info != NULL;
	    info = uu_avl_next(tree, info)) {
		iv = internal_property_find(info->pi_ptrnpg,
		    SCF_PROPERTY_TM_CHOICES_INCLUDE_VALUES);
		if (iv == NULL)
			continue;
		for (v = uu_list_first(iv->sc_property_values);
		    v != NULL;
		    v = uu_list_next(iv->sc_property_values, v)) {
			assert(is_numeric_type(v->sc_type) == 0);
			r = include_values_support(info, v->sc_u.sc_string,
			    errs);
			if (r != TVS_SUCCESS)
				rc = r;
		}
	}
	return (rc);
}

/*
 * Verify that there are no conflicting definitions of pg_pattern or
 * prop_pattern.  Two patterns are said to be in conflict if they have the
 * same name and differing types.  There is a caveat, however.  Empty
 * pattern names or types are considered to be wild cards.  There is no
 * conflict if a pattern has a wild card.
 */
static tmpl_validate_status_t
tmpl_pattern_conflict(entity_t *inst, uu_avl_t *tree, ptrn_type_t type,
    tmpl_errors_t *errs)
{
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc;

	/* First walk the instance. */
	rc = gather_pattern(inst, type, tree, errs);

	/* Now walk the service */
	r = gather_pattern(inst->sc_parent, type, tree, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	return (rc);
}

static tmpl_validate_status_t
tmpl_required_attr_present(uu_avl_t *tree, tmpl_errors_t *errs)
{
	ptrn_info_t *pinfo;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	int reported_name;
	int rv;

	for (pinfo = uu_avl_first(tree);
	    pinfo != NULL;
	    pinfo = uu_avl_next(tree, pinfo)) {
		if (is_required(pinfo->pi_ptrnpg) == 0) {
			/* Nothing to check if pattern is not required. */
			continue;
		}

		/*
		 * For pg_pattern both name and type are optional unless
		 * the required attribute has a value of true.  For
		 * prop_patterns only the type is optional, but it must be
		 * provided if the required attribute has a value of true.
		 */
		reported_name = 0;
		if ((pinfo->pi_ptrn_type == PG_PATTERN) &&
		    (pinfo->pi_name == NULL)) {
			rc = TVS_VALIDATION;
			if (add_scf_error(errs, SCF_TERR_PG_PATTERN_INCOMPLETE,
			    pinfo->pi_ptrnpg,
			    NULL, NULL, NULL, NULL, NULL) != 0) {
				/*
				 * If we're unable to report errors, break
				 * out of the loop.
				 */
				break;
			}
			/*
			 * Don't report the error twice if both name and
			 * type are missing.  One error message is
			 * adequate.
			 */
			reported_name = 1;
		}
		if ((pinfo->pi_type == NULL) && (reported_name == 0)) {
			rc = TVS_VALIDATION;
			if (pinfo->pi_ptrn_type == PG_PATTERN) {
				rv = add_scf_error(errs,
				    SCF_TERR_PG_PATTERN_INCOMPLETE,
				    pinfo->pi_ptrnpg,
				    NULL, NULL, NULL, NULL, NULL);
			} else {
				rv = add_scf_error(errs,
				    SCF_TERR_PROP_PATTERN_INCOMPLETE,
				    pinfo->pi_enc_pgp, NULL, pinfo->pi_ptrnpg,
				    NULL, NULL, NULL);
			}
			/* If we're unable to log errors, break out of loop. */
			if (rv != 0)
				break;
		}
	}
	return (rc);
}

/*
 * Look for pg_pattern definitions in general.  general is either the
 * restarter serivce for inst or it is the global service.  tree contains
 * the ptrn_info_t structures describing the pg_patterns for an instance.
 * For each general pg_pattern, see if the instance contains an overriding
 * definition in tree.  If it does generate an error entry.
 *
 * If a redefinition is found, TVS_WARN is returned.  This is because a
 * redefinition is not sufficient reason to inhibit the import operation.
 */
static tmpl_validate_status_t
tmpl_scan_general(entity_t *general, uu_avl_t *tree,
    tmpl_level_t level, tmpl_errors_t *errs)
{
	tmpl_level_t cur_level;
	error_info_t einfo;
	pgroup_t *pg;
	ptrn_info_t *ginfo = NULL;
	ptrn_info_t *match;
	tmpl_validate_status_t rc = TVS_SUCCESS;

	/*
	 * General services may not be in repository yet.  It depends on
	 * the order that manifests are imported.
	 */
	if (general == NULL)
		return (TVS_SUCCESS);

	for (pg = uu_list_first(general->sc_pgroups);
	    pg != NULL;
	    pg = uu_list_next(general->sc_pgroups, pg)) {
		if (strcmp(pg->sc_pgroup_type,
		    SCF_GROUP_TEMPLATE_PG_PATTERN) != 0) {
			/* Not a pg_pattern */
			continue;
		}
		if (ginfo != NULL)
			ptrn_info_destroy(ginfo);
		ginfo = ptrn_info_create(pg);
		match = uu_avl_find(tree, ginfo, NULL, NULL);
		if (match != NULL) {
			/* See if global pg_pattern is targeted at us. */
			if (target_check(ginfo->pi_target, level) == 0)
				continue;

			/*
			 * See if the match applies to us.  If we happen to
			 * be a restarter, the pg_pattern could have a
			 * target of delegate.  That wouldn't apply to this
			 * instance, it would only apply to our delegates.
			 * Cases such as this are not a redefinition.
			 */
			if (match->pi_ptrnpg->sc_parent->sc_etype ==
			    SVCCFG_INSTANCE_OBJECT) {
				cur_level = TL_INSTANCE;
			} else {
				cur_level = TL_SERVICE;
			}
			if (target_check(match->pi_target, cur_level) == 0)
				continue;

			/*
			 * Instance or service overrides a general
			 * definition.  We need to issue a warning message.
			 */
			rc = TVS_WARN;
			CLEAR_ERROR_INFO(&einfo);
			einfo.ei_type = EIT_PATTERN_CONFLICT;
			einfo.ei_u.ei_pattern_conflict.ei_pattern = pg;
			if (add_scf_error(errs, SCF_TERR_GENERAL_REDEFINE,
			    match->pi_ptrnpg, NULL, NULL, NULL, NULL,
			    &einfo) != 0) {
				/*
				 * No need to continue the search if we
				 * cannot record errors.
				 */
				break;
			}
		}
	}

	if (ginfo != NULL)
		ptrn_info_destroy(ginfo);
	return (rc);
}

/*
 * tree contains the pg_pattern definitions for the instance at inst.  See
 * if these pg_patterns redefine any pg_patterns in the instance's
 * restarter or in the global service.  TVS_WARN is returned if a
 * redefinition is encountered.
 */
static tmpl_validate_status_t
tmpl_level_redefine(entity_t *inst, uu_avl_t *tree, tmpl_errors_t *errs)
{
	entity_t *restarter;
	entity_t *svc = inst->sc_parent;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc;

	restarter = inst->sc_u.sc_instance.sc_instance_restarter;
	if (restarter == NULL) {
		/* No instance restarter.  Use the service restarter */
		restarter = svc->sc_u.sc_service.sc_restarter;
	}
	rc = tmpl_scan_general(restarter, tree, TL_RESTARTER, errs);
	r = tmpl_scan_general(svc->sc_u.sc_service.sc_global, tree,
	    TL_GLOBAL, errs);
	if (r != TVS_SUCCESS)
		rc = r;
	return (rc);
}

/*
 * Perform the following consistency checks on the template specifications
 * themselves:
 *
 *	- No conflicting definitions of `pg_pattern` are allowed within a
 *	  single instance.
 *
 *	- Templates at a narrow target (e.g. instance) which define
 *	  property groups already templated at a broad target
 *	  (e.g. restarter or all) are strongly discouraged.
 *
 *	- Developers may not define a template which specifies a single
 *	  prop_pattern name with differing types on the same target
 *	  entity.
 *
 *	- If a pg_pattern has a required attribute with a value of true,
 *	  then its name and type attributes must be specified.
 *
 *	- If a prop_pattern has a required attribute with a value of true,
 *	  then its type attribute must be specified.
 *
 *	- If a prop_pattern has an include values make sure that the
 *	  appropriate constraints or values element has also been
 *	  declared.
 */
static tmpl_validate_status_t
tmpl_consistency(entity_t *inst, tmpl_errors_t *errs)
{
	void *marker = NULL;
	ptrn_info_t *info;
	uu_avl_t *tree;
	tmpl_validate_status_t rc;
	tmpl_validate_status_t r;

	/* Allocate the tree. */
	tree = uu_avl_create(ptrn_info_pool, NULL, TMPL_DEBUG_TREE);
	if (tree == NULL) {
		uu_die(gettext("pg_info tree creation failed: %s\n"),
		    uu_strerror(uu_error()));
	}

	rc = tmpl_pattern_conflict(inst, tree, PG_PATTERN, errs);

	/*
	 * The tree now contains the instance and service pg_patterns.
	 * Check to see if they override any pg_pattern definitions in the
	 * restarter and global services.
	 */
	r = tmpl_level_redefine(inst, tree, errs);
	if (r != TVS_SUCCESS) {
		/*
		 * tmpl_level_redefine() can return a warning.  Don't
		 * override a serious error with a warning.
		 */
		if (r == TVS_WARN) {
			if (rc == TVS_SUCCESS)
				rc = r;
		} else {
			rc = r;
		}
	}

	/*
	 * If the pg_pattern has a required attribute with a value of true,
	 * then it must also have name and type attributes.
	 */
	r = tmpl_required_attr_present(tree, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/* Empty the tree, so that we can reuse it for prop_patterns. */
	while ((info = uu_avl_teardown(tree, &marker)) != NULL) {
		ptrn_info_destroy(info);
	}

	r = tmpl_pattern_conflict(inst, tree, PROP_PATTERN, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/*
	 * If a prop_pattern has required attribute with a value of true,
	 * then it must also have a type attribute.
	 */
	r = tmpl_required_attr_present(tree, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/*
	 * Insure that include_values have the constraint for values
	 * elements that are needed.
	 */
	r = tmpl_include_values_check(tree, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/* Tear down the tree. */
	marker = NULL;
	while ((info = uu_avl_teardown(tree, &marker)) != NULL) {
		ptrn_info_destroy(info);
	}
	uu_avl_destroy(tree);

	return (rc);
}

/*
 * Release memory associated with the tmpl_errors structure and then free
 * the structure itself.
 */
void
tmpl_errors_destroy(tmpl_errors_t *te)
{
	im_tmpl_error_t *ite;
	tv_errors_t *ste;
	void *marker = NULL;

	if (te == NULL)
		return;
	if (te->te_list) {
		while ((ite = uu_list_teardown(te->te_list, &marker)) != NULL) {
			uu_list_node_fini(ite, &ite->ite_node,
			    inmem_errors_pool);
			uu_free(ite);
		}
		uu_list_destroy(te->te_list);
	}
	if (te->te_scf) {
		marker = NULL;
		while ((ste = uu_list_teardown(te->te_scf, &marker)) != NULL) {
			destroy_scf_errors(ste);
		}
		uu_list_destroy(te->te_scf);
	}
	uu_free(te);
}

/*
 * Allocate and initialize a tmpl_errors structure.  The address of the
 * structure is returned, unless we are unable to allocate enough memory.
 * In the case of memory allocation failures, NULL is returned.
 *
 * The allocated structure should be freed by calling
 * tmpl_errors_destroy().
 */
static tmpl_errors_t *
tmpl_errors_create()
{
	tmpl_errors_t *te;

	te = uu_zalloc(sizeof (*te));
	if (te == NULL)
		return (NULL);
	te->te_list = uu_list_create(inmem_errors_pool, NULL, TMPL_DEBUG_LIST);
	if (te->te_list == NULL) {
		uu_free(te);
		return (NULL);
	}
	te->te_scf = uu_list_create(tv_errors_pool, NULL, TMPL_DEBUG_LIST);
	if (te->te_scf == NULL) {
		tmpl_errors_destroy(te);
		return (NULL);
	}

	return (te);
}

void
tmpl_errors_print(FILE *out, tmpl_errors_t *errs, const char *prefix)
{
	scf_tmpl_error_t *cur;
	size_t buf_size = 4096;
	im_tmpl_error_t *ite;
	char *s = NULL;
	scf_tmpl_errors_t *scferrs;
	tv_errors_t *scft;
	int interactive = (est->sc_cmd_flags & SC_CMD_IACTIVE) ?
	    SCF_TMPL_STRERROR_HUMAN : 0;

	for (ite = uu_list_first(errs->te_list);
	    ite != NULL;
	    ite = uu_list_next(errs->te_list, ite)) {
		im_tmpl_error_print(out, ite, prefix);
	}

	/* Now handle the errors that can be printed via libscf. */
	s = safe_malloc(buf_size);
	for (scft = uu_list_first(errs->te_scf);
	    scft != NULL;
	    scft = uu_list_next(errs->te_scf, scft)) {
		scferrs = scft->tve_errors;
		if (_scf_tmpl_error_set_prefix(scferrs, prefix) != 0)
			uu_die(emesg_nomem);
		while ((cur = scf_tmpl_next_error(scferrs)) != NULL) {
			(void) scf_tmpl_strerror(cur, s, buf_size, interactive);
			(void) fputs(s, out);
			(void) fputc('\n', out);
		}
	}

	free(s);
}

/*
 * This function finds the prop_pattern for the property, prop.  e is the
 * instance where the search for the prop_pattern will start.  pg_pattern
 * is the address of the pg_pattern that holds the prop_pattern.
 */
static tmpl_validate_status_t
tmpl_find_prop_pattern(entity_t *inst, pgroup_t *pg_pattern,
    property_t *prop, pgroup_t **prop_pattern)
{
	pgroup_t *candidate;
	pg_iter_t *iter = NULL;
	char *prop_pattern_name = NULL;
	tmpl_validate_status_t rc;

	/*
	 * Get the name of the property group that holds the prop_pattern
	 * definition.
	 */
	rc = gen_prop_pattern_pg_name(pg_pattern,
	    prop->sc_property_name, &prop_pattern_name);
	if (rc != TVS_SUCCESS)
		goto out;

	/* Find the property group. */
	iter = pg_iter_create(inst, SCF_GROUP_TEMPLATE_PROP_PATTERN);
	if (iter == NULL)
		goto out;
	while ((candidate = next_pattern_pg(iter)) != NULL) {
		const char *c;

		if (strcmp(prop_pattern_name, candidate->sc_pgroup_name) != 0)
			continue;
		c = find_astring_value_in_pg(candidate,
		    SCF_PROPERTY_TM_PG_PATTERN);
		if (c == NULL)
			continue;
		if (strcmp(pg_pattern->sc_pgroup_name, c) == 0)
			break;
	}
	*prop_pattern = candidate;
	if (candidate == NULL)
		rc = TVS_NOMATCH;

out:
	pg_iter_destroy(iter);
	uu_free((void *)prop_pattern_name);
	return (rc);
}

/*
 * Indexes for pg_pattern property group names.  Indexes are arranged
 * from most specific to least specific.
 */
#define	PGN_BOTH	0	/* both name and type */
#define	PGN_NAME	1	/* name only */
#define	PGN_TYPE	2	/* type only */
#define	PGN_NEITHER	3	/* neither name nor type */
#define	PGN_MAX		4	/* Size of array */

/*
 * Given an instance entity, e, and a propety group, pg, within the
 * instance; return the address of the pg_pattern for the property group.
 * The address of the pg_pattern is placed at pgp.  NULL indicates that no
 * pg_pattern was specified.
 */
static tmpl_validate_status_t
tmpl_find_pg_pattern(entity_t *e, pgroup_t *pg, pgroup_t **pgp)
{
	pgroup_t *cpg;		/* candidate property group */
	int i;
	pg_iter_t *iter = NULL;
	char *pg_names[PGN_MAX];
	pgroup_t *pg_patterns[PGN_MAX];
	tmpl_validate_status_t rv = TVS_SUCCESS;

	(void) memset(pg_patterns, 0, sizeof (pg_patterns));
	*pgp = NULL;

	/* Generate candidate names for pg_pattern property groups. */
	pg_names[PGN_BOTH] = gen_pg_pattern_pg_name(pg->sc_pgroup_name,
	    pg->sc_pgroup_type);
	pg_names[PGN_NAME] = gen_pg_pattern_pg_name(pg->sc_pgroup_name,
	    NULL);
	pg_names[PGN_TYPE] = gen_pg_pattern_pg_name(NULL,
	    pg->sc_pgroup_type);
	pg_names[PGN_NEITHER] = gen_pg_pattern_pg_name(NULL, NULL);
	for (i = 0; i < PGN_MAX; i++) {
		if (pg_names[i] == NULL) {
			rv = TVS_BAD_TEMPLATE;
			goto errout;
		}
	}

	/* Search for property groups that match these names */
	iter = pg_iter_create(e, SCF_GROUP_TEMPLATE_PG_PATTERN);
	if (iter == NULL) {
		uu_die(emesg_nomem);
	}
	while ((cpg = next_pattern_pg(iter)) != NULL) {
		if (pg_target_check(cpg, iter->pgi_level) == 0)
			continue;

		/* See if we have a name match. */
		for (i = 0; i < PGN_MAX; i++) {
			if (strcmp(cpg->sc_pgroup_name, pg_names[i]) == 0) {
				/*
				 * If we already have a lower level
				 * pg_pattern, keep it.
				 */
				if (pg_patterns[i] == NULL)
					pg_patterns[i] = cpg;
				break;
			}
		}
	}

	/* Find the most specific pg_pattern. */
	for (i = 0; i < PGN_MAX; i++) {
		if (pg_patterns[i] != NULL) {
			*pgp = pg_patterns[i];
			break;
		}
	}
errout:
	for (i = 0; i < PGN_MAX; i++) {
		free(pg_names[i]);
	}
	pg_iter_destroy(iter);
	return (rv);
}

/*
 * Initialize structures that are required for validation using
 * templates specifications.
 */
void
tmpl_init(void)
{
	emesg_nomem = gettext("Out of memory.\n");

	composed_pg_pool = uu_avl_pool_create("composed_pg",
	    sizeof (composed_pg_t), offsetof(composed_pg_t, cpg_node),
	    composed_pg_compare, TMPL_DEBUG_AVL_POOL);
	if (composed_pg_pool == NULL) {
		uu_die(gettext("composed_pg pool creation failed: %s\n"),
		    uu_strerror(uu_error()));
	}
	composed_prop_pool = uu_avl_pool_create("composed_prop",
	    sizeof (property_t), offsetof(property_t, sc_composed_node),
	    composed_prop_compare, TMPL_DEBUG_AVL_POOL);
	if (composed_prop_pool == NULL) {
		uu_die(gettext("composed_prop pool creation failed. %s\n"),
		    uu_strerror(uu_error()));
	}
	ptrn_info_pool = uu_avl_pool_create("ptrn_info", sizeof (ptrn_info_t),
	    offsetof(ptrn_info_t, pi_link), ptrn_info_compare,
	    TMPL_DEBUG_AVL_POOL);
	if (ptrn_info_pool == NULL) {
		uu_die(gettext("pg_pattern info pool creation failed: %s\n"),
		    uu_strerror(uu_error()));
	}
	inmem_errors_pool = uu_list_pool_create("errors-internal",
	    sizeof (im_tmpl_error_t), offsetof(im_tmpl_error_t,
	    ite_node), NULL, TMPL_DEBUG_LIST_POOL);
	if (inmem_errors_pool == NULL) {
		uu_die(gettext("inmem_errors_pool pool creation failed: "
		    "%s\n"), uu_strerror(uu_error()));
	}
	tv_errors_pool = uu_list_pool_create("scf-terrors",
	    sizeof (tv_errors_t), offsetof(tv_errors_t, tve_node),
	    NULL,  TMPL_DEBUG_LIST_POOL);
	if (tv_errors_pool == NULL) {
		uu_die(gettext("tv_errors_pool pool creation failed: %s\n"),
		    uu_strerror(uu_error()));
	}
}

/*
 * Clean up the composed property node in the property.
 */
void
tmpl_property_fini(property_t *p)
{
	uu_avl_node_fini(p, &p->sc_composed_node, composed_prop_pool);
}

/*
 * Initialize the composed property node in the property.
 */
void
tmpl_property_init(property_t *p)
{
	uu_avl_node_init(p, &p->sc_composed_node, composed_prop_pool);
}

/*
 * Use the cardinality specification in the prop_pattern to verify the
 * cardinality of the property at prop.  The cardinality of the property is
 * the number of values that it has.
 *
 * pg is the property group that holds prop, and pg_pattern is the
 * pg_pattern for the property group.  pg and pg_pattern are only used for
 * error reporting.
 */
static tmpl_validate_status_t
tmpl_validate_cardinality(pgroup_t *prop_pattern, property_t *prop,
    pgroup_t *pg, pgroup_t *pg_pattern, tmpl_errors_t *errs)
{
	size_t count;
	uint64_t max;
	uint64_t min;
	tmpl_validate_status_t rc;
	error_info_t einfo;

	assert(strcmp(prop_pattern->sc_pgroup_type,
	    SCF_GROUP_TEMPLATE_PROP_PATTERN) == 0);

	rc = get_cardinality(prop_pattern, &min, &max);
	switch (rc) {
	case TVS_NOMATCH:
		/* Nothing to check. */
		return (TVS_SUCCESS);
	case TVS_SUCCESS:
		/* Process the limits. */
		break;
	default:
		return (rc);
	}

	if ((min == 0) && (max == ULLONG_MAX)) {
		/* Any number of values is permitted.  No need to count. */
		return (TVS_SUCCESS);
	}

	count = count_prop_values(prop);
	if ((count < min) || (count > max)) {
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_CARDINALITY;
		einfo.ei_u.ei_cardinality.ei_min = min;
		einfo.ei_u.ei_cardinality.ei_max = max;
		einfo.ei_u.ei_cardinality.ei_count = count;
		(void) add_scf_error(errs, SCF_TERR_CARDINALITY_VIOLATION,
		    pg_pattern, pg, prop_pattern, prop, NULL, &einfo);
		return (TVS_VALIDATION);
	}

	return (TVS_SUCCESS);
}

/*
 * Iterate over pg_patterns in the entity, e.  If the pg_pattern's required
 * attribute is true, verify that the entity contains the corresponding
 * property group.
 */
static tmpl_validate_status_t
tmpl_required_pg_present(entity_t *e, tmpl_errors_t *errs)
{
	composed_pg_t cpg;
	composed_pg_t *match;
	error_info_t einfo;
	pg_iter_t *iter;
	pgroup_t *pg;
	const char *pg_name;
	const char *pg_type;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	uu_avl_t *tree;

	assert(e->sc_etype == SVCCFG_INSTANCE_OBJECT);

	iter = pg_iter_create(e, SCF_GROUP_TEMPLATE_PG_PATTERN);
	if (iter == NULL)
		uu_die(emesg_nomem);

	CLEAR_ERROR_INFO(&einfo);
	einfo.ei_type = EIT_MISSING_PG;

	while ((pg = next_pattern_pg(iter)) != NULL) {
		if (is_required(pg) == 0) {
			/* If pg is not required, there is nothing to check. */
			continue;
		}
		pg_name = find_astring_value_in_pg(pg, SCF_PROPERTY_TM_NAME);
		pg_type = find_astring_value_in_pg(pg, SCF_PROPERTY_TM_TYPE);
		if (pg_target_check(pg, iter->pgi_level) == 0)
			continue;
		einfo.ei_u.ei_missing_pg.ei_pg_name = pg_name;
		einfo.ei_u.ei_missing_pg.ei_pg_type = pg_type;
		tree = e->sc_u.sc_instance.sc_composed;
		(void) memset(&cpg, 0, sizeof (cpg));
		cpg.cpg_name = pg_name;
		cpg.cpg_type = pg_type;
		match = uu_avl_find(tree, &cpg, NULL, NULL);
		if (match == NULL) {
			rc = TVS_VALIDATION;
			if (add_scf_error(errs, SCF_TERR_MISSING_PG, pg,
			    NULL, NULL, NULL, NULL, &einfo) != 0) {
				break;
			}
		}
	}

	pg_iter_destroy(iter);
	return (rc);
}

/*
 * Verify that the property group, pg, contains property declarations for
 * all required properties.  Unfortunately, there is no direct way to find
 * the prop_patterns for a given property group.  Therefore, we need to
 * scan the entity at e looking for property groups with a type of
 * SCF_GROUP_TEMPLATE_PROP_PATTERN.  That is, we scan the entity looking
 * for all prop_patterns.  When we find a prop_pattern, we look at the
 * value of its pg_pattern property to see if it matches the name of the
 * pg_pattern.  If they match, this is a prop_pattern that is of interest
 * to us.
 *
 * When we find an interesting prop_pattern, we see if it's required
 * property is true.  If it is, we verify that the property group at pg
 * contains the specified property.
 */
static tmpl_validate_status_t
tmpl_required_props_present(entity_t *e, pgroup_t *pg, pgroup_t *pg_pattern,
    tmpl_errors_t *errs)
{
	error_info_t einfo;
	pg_iter_t *iter;
	const char *prop_name;
	const char *prop_pg_pattern_name;
	pgroup_t *prop_pattern;
	scf_tmpl_error_type_t ec;
	tmpl_validate_status_t rc = TVS_SUCCESS;

	/*
	 * Scan the entity's property groups looking for ones with a type
	 * of SCF_GROUP_TEMPLATE_PROP_PATTERN.
	 */
	iter = pg_iter_create(e, SCF_GROUP_TEMPLATE_PROP_PATTERN);
	if (iter == NULL)
		uu_die(emesg_nomem);
	CLEAR_ERROR_INFO(&einfo);
	for (prop_pattern = next_pattern_pg(iter);
	    prop_pattern != NULL;
	    prop_pattern = next_pattern_pg(iter)) {
		/*
		 * Find the pg_pattern property in this prop_pattern.
		 * Verify that its value matches the name of the
		 * pg_pattern.
		 */
		prop_pg_pattern_name = find_astring_value_in_pg(prop_pattern,
		    SCF_PROPERTY_TM_PG_PATTERN);
		assert(prop_pg_pattern_name != NULL);
		if (strcmp(pg_pattern->sc_pgroup_name,
		    prop_pg_pattern_name) != 0) {
			continue;
		}

		/* If the property is required, see if it is in the pg. */
		if (is_required(prop_pattern) == 0)
			continue;
		prop_name = find_astring_value_in_pg(prop_pattern,
		    SCF_PROPERTY_TM_NAME);
		assert(prop_name != NULL);
		if (property_find(pg, prop_name) == NULL) {
			ec = SCF_TERR_MISSING_PROP;
			rc = TVS_VALIDATION;
			einfo.ei_type = EIT_MISSING_PROP;
			einfo.ei_u.ei_missing_prop.ei_prop_name = prop_name;
			if (add_scf_error(errs, ec, pg_pattern, pg,
			    prop_pattern, NULL, NULL, &einfo) != 0) {
				/*
				 * If we can no longer accumulate errors,
				 * break out of the loop.
				 */
				break;
			}
		}
	}

	pg_iter_destroy(iter);
	return (rc);
}

/*
 * Check the value at v to see if it falls within any of the ranges at r.
 * count is the number of ranges at r, and type tells whether to treat the
 * value as signed or unsigned.
 *
 * Return 1 if the value falls within one of the ranges.  Otherwise return
 * 0.
 */
static int
value_in_range(value_t *v, scf_type_t type, range_t *r, size_t count)
{
	for (; count > 0; --count, r++) {
		if (type == SCF_TYPE_COUNT) {
			if ((v->sc_u.sc_count >=
			    r->rng_u.rng_unsigned.rng_min) &&
			    (v->sc_u.sc_count <=
			    r->rng_u.rng_unsigned.rng_max))
				return (1);
		} else {
			if ((v->sc_u.sc_integer >=
			    r->rng_u.rng_signed.rng_min) &&
			    (v->sc_u.sc_integer <=
			    r->rng_u.rng_signed.rng_max))
				return (1);
		}
	}
	return (0);
}

/*
 * If the template prop_pattern at pattern contains a constraint_range
 * property, use the specified range to validate all the numeric property
 * values of the property at prop.
 *
 * pg is the property group that holds prop, and pg_pattern is the
 * pg_pattern for the property group.  pg and pg_pattern are only used for
 * error reporting.
 */
static tmpl_validate_status_t
tmpl_validate_value_range(pgroup_t *pattern, property_t *prop, pgroup_t *pg,
    pgroup_t *pg_pattern, tmpl_errors_t *errs)
{
	uint_t count;
	error_info_t einfo;
	property_t *range_prop;
	range_t *ranges;
	tmpl_validate_status_t rc;
	scf_type_t type;
	value_t *v;

	/* Get the range constraints if they exist. */
	if ((range_prop = property_find(pattern,
	    SCF_PROPERTY_TM_CONSTRAINT_RANGE)) == NULL) {
		/* No range to check. */
		return (TVS_SUCCESS);
	}
	type = prop->sc_value_type;
	if ((type != SCF_TYPE_COUNT) && (type != SCF_TYPE_INTEGER)) {
		rc = TVS_BAD_TEMPLATE;
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_BAD_TEMPLATE;
		einfo.ei_u.ei_bad_template.ei_reason =
		    gettext("Property does not have correct type for "
		    "a range specification");
		(void) tmpl_errors_add_im(errs, rc, pg_pattern->sc_parent,
		    pg_pattern, pg, pattern, prop, NULL, &einfo);
		return (rc);
	}
	if ((rc = get_ranges(range_prop, prop->sc_value_type, &ranges,
	    &count)) != TVS_SUCCESS) {
		rc = TVS_BAD_TEMPLATE;
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_BAD_TEMPLATE;
		einfo.ei_u.ei_bad_template.ei_reason = gettext("Illegal range "
		    "value");
		(void) tmpl_errors_add_im(errs, rc, pg_pattern->sc_parent,
		    pg_pattern, pg, pattern, prop, NULL, &einfo);
		return (rc);
	}

	/* Set up error info before entering loop. */
	CLEAR_ERROR_INFO(&einfo);
	einfo.ei_type = EIT_RANGE;
	einfo.ei_u.ei_range.ei_rtype = type;

	/* Compare numeric values of the property to the range. */
	for (v = uu_list_first(prop->sc_property_values);
	    v != NULL;
	    v = uu_list_next(prop->sc_property_values, v)) {
		if (value_in_range(v, type, ranges, count) == 1)
			continue;
		if (type == SCF_TYPE_COUNT) {
			einfo.ei_u.ei_range.ei_uvalue = v->sc_u.sc_count;
		} else {
			einfo.ei_u.ei_range.ei_ivalue = v->sc_u.sc_integer;
		}
		rc = TVS_VALIDATION;
		if (add_scf_error(errs, SCF_TERR_RANGE_VIOLATION, pg_pattern,
		    pg, pattern, prop, v, &einfo) != 0) {
			return (rc);
		}
	}

	return (rc);
}

/*
 * If the prop_pattern has value constraints, verify that all the values
 * for the property at prop are legal values.
 *
 * pg is the property group that holds prop, and pg_pattern is the
 * pg_pattern for the property group.  pg and pg_pattern are only used for
 * error reporting.
 */
static tmpl_validate_status_t
tmpl_validate_values(pgroup_t *prop_pattern, property_t *prop, pgroup_t *pg,
    pgroup_t *pg_pattern, tmpl_errors_t *errs)
{
	int found;
	uint_t i;
	avalues_t *legal;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	value_t *v;

	/* Get list of legal values. */
	r = av_get_values(prop_pattern, SCF_PROPERTY_TM_CONSTRAINT_NAME,
	    prop->sc_value_type, &legal);
	switch (r) {
	case TVS_BAD_CONVERSION:
		(void) tmpl_errors_add_im(errs, r, pg->sc_parent, pg_pattern,
		    pg, prop_pattern, prop, NULL, NULL);
		return (r);
	case TVS_NOMATCH:
		/* No constraints in template. */
		return (TVS_SUCCESS);
	case TVS_SUCCESS:
		/* process the constraints. */
		break;
	default:
		assert(0);
		abort();
	}

	/* Check the property values against the legal values. */
	for (v = uu_list_first(prop->sc_property_values);
	    v != NULL;
	    v = uu_list_next(prop->sc_property_values, v)) {
		/* Check this property value against the legal values. */
		found = 0;
		for (i = 0; (i < legal->av_count) && (found == 0); i++) {
			switch (v->sc_type) {
			case SCF_TYPE_BOOLEAN:
			case SCF_TYPE_COUNT:
				if (av_get_unsigned(legal, i) ==
				    v->sc_u.sc_count) {
					found = 1;
				}
				break;
			case SCF_TYPE_INTEGER:
				if (av_get_integer(legal, i) ==
				    v->sc_u.sc_integer) {
					found = 1;
				}
				break;
			default:
				if (strcmp(av_get_string(legal, i),
				    v->sc_u.sc_string) == 0) {
					found = 1;
				}
				break;
			}
		}
		if (found == 0) {
			rc = TVS_VALIDATION;
			if (add_scf_error(errs,
			    SCF_TERR_VALUE_CONSTRAINT_VIOLATED, pg_pattern, pg,
			    prop_pattern, prop, v, NULL) != 0) {
				/*
				 * Exit loop if no longer able to report
				 * errors.
				 */
				break;
			}
		}
	}

out:
	av_destroy(legal);
	return (rc);
}

/*
 * Verify the following items about the values of property, prop.
 *
 *	- The values all have the type specified by the prop_pattern at
 *	  pattern.
 *	- Check numeric values against range constraints.
 *	- If the prop_pattern has one or more value constraints, validate
 *	  the property's values against the constraints.
 *
 * pg is the property group that holds prop, and pg_pattern is the
 * pg_pattern for the property group.  pg and pg_pattern are only used for
 * error reporting.
 */
static tmpl_validate_status_t
tmpl_validate_value_constraints(pgroup_t *pattern, property_t *prop,
    pgroup_t *pg, pgroup_t *pg_pattern, tmpl_errors_t *errs)
{
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc;

	rc = tmpl_validate_value_range(pattern, prop, pg, pg_pattern, errs);
	r = tmpl_validate_values(pattern, prop, pg, pg_pattern, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	return (rc);
}

/*
 * Perform the following validations on the property, prop.
 *
 *	- Verify that the property's type agrees with the type specified in
 *	  the prop_pattern template, tmpl.
 *	- Verify the cardinality.
 *	- Verify that the property values satisfy the constraints specified
 *	  by the template.
 *
 * pg is the property group that holds prop, and pg_pattern is the
 * pg_pattern for the property group.  pg and pg_pattern are only used for
 * error reporting.
 */
static tmpl_validate_status_t
tmpl_validate_prop(property_t *prop, pgroup_t *tmpl, pgroup_t *pg,
    pgroup_t *pg_pattern, tmpl_errors_t *errs)
{
	scf_tmpl_error_type_t ec;
	error_info_t einfo;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	int status;
	scf_type_t type;

	r = prop_pattern_type(tmpl, &type);
	switch (r) {
	case TVS_SUCCESS:
		if (type == SCF_TYPE_INVALID) {
			rc = TVS_INVALID_TYPE_SPECIFICATION;
			r = tmpl_errors_add_im(errs, rc, pg->sc_parent, NULL,
			    pg, tmpl, NULL, NULL, NULL);
			if (r != TVS_SUCCESS) {
				/*
				 * Give up if we can no longer accumulate
				 * errors.
				 */
				return (rc);
			}
		} else {
			if (property_is_type(prop, type) == 0) {
				CLEAR_ERROR_INFO(&einfo);
				rc = TVS_VALIDATION;
				ec = SCF_TERR_WRONG_PROP_TYPE;
				einfo.ei_type  = EIT_PROP_TYPE;
				einfo.ei_u.ei_prop_type.ei_specified = type;
				einfo.ei_u.ei_prop_type.ei_actual =
				    prop->sc_value_type;
				status = add_scf_error(errs, ec,
				    pg_pattern, pg, tmpl, prop, NULL, &einfo);
				if (status != 0) {
					/*
					 * Give up if we can no longer
					 * accumulate errors.
					 */
					return (rc);
				}
			}
		}
		break;
	case TVS_MISSING_TYPE_SPECIFICATION:
		/*
		 * A null type specification means that we do not need to
		 * check the property's type.
		 */
		break;
	default:
		rc = r;
	}

	/* Validate the cardinality */
	r = tmpl_validate_cardinality(tmpl, prop, pg, pg_pattern, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/* Validate that property values satisfy constraints. */
	r = tmpl_validate_value_constraints(tmpl, prop, pg, pg_pattern, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	return (rc);
}

/*
 * Validate the property group at pg by performing the following checks:
 *
 *	- Verify that the types of the pg and the pg_pattern are
 *	  compatible.
 *	- Verify the properties in the pg.
 *	- Verify that required properties are present.
 */
static tmpl_validate_status_t
tmpl_validate_pg(entity_t *e, pgroup_t *pg, tmpl_errors_t *errs)
{
	error_info_t einfo;
	const char *pg_pattern_type;	/* Type declared by pg_pattern. */
	pgroup_t *pg_pattern;	/* Prop. group for pg_pattern */
	property_t *prop;
	pgroup_t *prop_pattern;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	int stat;

	/*
	 * See if there is a pg_pattern for this property group.  If it
	 * exists, use it to validate the property group.  If there is no
	 * pg_pattern, then there is no validation to do.
	 */
	rc = tmpl_find_pg_pattern(e, pg, &pg_pattern);
	switch (rc) {
	case TVS_SUCCESS:
		break;
	case TVS_BAD_TEMPLATE:
		CLEAR_ERROR_INFO(&einfo);
		einfo.ei_type = EIT_BAD_TEMPLATE;
		einfo.ei_u.ei_bad_template.ei_reason = gettext("Property "
		    "group name too long");
		(void) tmpl_errors_add_im(errs, rc, e, NULL, pg, NULL, NULL,
		    NULL, &einfo);
		return (rc);
	default:
		assert(0);
		abort();
	}
	if (pg_pattern == NULL)
		return (TVS_SUCCESS);

	/*
	 * If the pg_pattern declares a type, verify that the PG has the
	 * correct type.
	 */
	pg_pattern_type = find_type_specification(pg_pattern);
	if ((pg_pattern_type != NULL) &&
	    (*pg_pattern_type != 0)) {
		if ((pg->sc_pgroup_type != NULL) &&
		    (*(pg->sc_pgroup_type) != 0)) {
			if (strcmp(pg_pattern_type,
			    pg->sc_pgroup_type) != 0) {
				rc = TVS_VALIDATION;
				stat = add_scf_error(errs,
				    SCF_TERR_WRONG_PG_TYPE, pg_pattern, pg,
				    NULL, NULL, NULL, NULL);
				if (stat != 0) {
					/*
					 * If we can no longer accumulate
					 * errors, return without trying to
					 * do further validation.
					 */
					return (rc);
				}
			}
		} else {
			rc = TVS_MISSING_PG_TYPE;
			r = tmpl_errors_add_im(errs, rc, e, pg_pattern, pg,
			    NULL, NULL, NULL, NULL);
			if (r != TVS_SUCCESS) {
				/*
				 * If we can no longer accumulate errors,
				 * return without trying to do further
				 * validation.
				 */
				return (rc);
			}
		}
	}

	/* Verify the properties in the property group. */
	prop = NULL;
	while ((prop = next_property(pg, prop)) != NULL) {
		r = tmpl_find_prop_pattern(e, pg_pattern, prop, &prop_pattern);
		switch (r) {
		case TVS_SUCCESS:
			/* Found match.  Validate property. */
			break;
		case TVS_NOMATCH:
			/* No prop_patern.  Go on to next property. */
			continue;
		case TVS_BAD_TEMPLATE:
			CLEAR_ERROR_INFO(&einfo);
			einfo.ei_type = EIT_BAD_TEMPLATE;
			einfo.ei_u.ei_bad_template.ei_reason =
			    gettext("prop_pattern name too long");
			(void) tmpl_errors_add_im(errs, r, e, NULL, pg, NULL,
			    NULL, NULL, &einfo);
			continue;
		default:
			assert(0);
			abort();
		}
		r = tmpl_validate_prop(prop, prop_pattern, pg, pg_pattern,
		    errs);
		if (r != TVS_SUCCESS)
			rc = r;
	}

	/*
	 * Confirm required properties are present.
	 */
	r = tmpl_required_props_present(e, pg, pg_pattern, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	return (rc);
}

/*
 * Validate that the property groups in the entity conform to the template
 * specifications.  Specifically, this means do the following:
 *
 *	- Loop through the property groups in the entity skipping the ones
 *	  that are of type "template".
 *
 *	- For the PG search for the corresponding template_pg_pattern
 *	  property group.  It is possible that one may not exist.
 *
 *	- Verify that the PG is in conformance with the pg_pattern
 *	  specification if it exists.
 */
static tmpl_validate_status_t
tmpl_validate_entity_pgs(entity_t *e, tmpl_errors_t *errs)
{
	composed_pg_t *cpg;
	uu_avl_t *pgroups;
	pgroup_t *pg;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;

	assert(e->sc_etype == SVCCFG_INSTANCE_OBJECT);

	pgroups = e->sc_u.sc_instance.sc_composed;
	for (cpg = uu_avl_first(pgroups);
	    cpg != NULL;
	    cpg = uu_avl_next(pgroups, cpg)) {
		if (strcmp(cpg->cpg_type, SCF_GROUP_TEMPLATE) == 0)
			continue;
		pg = CPG2PG(cpg);
		if ((r = tmpl_validate_pg(e, pg, errs)) != TVS_SUCCESS)
			rc = r;
	}

	return (rc);
}

/*
 * Validate the instance, e, by performing the following checks:
 *
 *	- Verify template consistency.
 *
 *	- Validate each property group in the entity is in conformance
 *	  with the template specifications.
 *
 *	- Verify that all required property groups are present in the
 *	  entity.
 */
static tmpl_validate_status_t
tmpl_validate_instance(entity_t *e, tmpl_errors_t *errs)
{
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;
	int status;
	tv_errors_t *ste;

	/* Prepare to collect errors for this instance. */
	ste = tv_errors_create(e->sc_fmri);
	status = uu_list_insert_after(errs->te_scf, errs->te_cur_scf, ste);
	assert(status == 0);
	errs->te_cur_scf = ste;

	/* Verify template consistency */
	rc = tmpl_consistency(e, errs);

	/* Validate the property groups in the entity. */
	r = tmpl_validate_entity_pgs(e, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	/* Verify that all required property groups are present. */
	r = tmpl_required_pg_present(e, errs);
	if (r != TVS_SUCCESS)
		rc = r;

	return (rc);
}

/*
 * First validate the instances of the service.
 */
static tmpl_validate_status_t
tmpl_validate_service(entity_t *svc, tmpl_errors_t *errs)
{
	entity_t *inst;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;

	assert(svc->sc_etype == SVCCFG_SERVICE_OBJECT);

	load_general_templates(svc);

	/* Validate the service's instances. */
	for (inst = uu_list_first(svc->sc_u.sc_service.sc_service_instances);
	    inst != NULL;
	    inst = uu_list_next(svc->sc_u.sc_service.sc_service_instances,
	    inst)) {
		load_instance_restarter(inst);
		build_composed_instance(inst);
		r = tmpl_validate_instance(inst, errs);
		if (r != TVS_SUCCESS)
			rc = r;
		demolish_composed_instance(inst);
	}

	return (rc);
}

/*
 * Validate all services and instances in the bundle against their
 * templates.  If err_list is not NULL, a tmpl_errors structure will be
 * allocated and its address will be returned to err_list.  This structure
 * can be used to generate error messages.
 */
tmpl_validate_status_t
tmpl_validate_bundle(bundle_t *bndl, tmpl_errors_t **err_list)
{
	tmpl_errors_t *errs = NULL;
	entity_t *svc;
	tmpl_validate_status_t r;
	tmpl_validate_status_t rc = TVS_SUCCESS;

	if (err_list != NULL)
		*err_list = NULL;
	if (bndl->sc_bundle_type != SVCCFG_MANIFEST) {
		semerr(gettext("Bundle is not a manifest.  Unable to validate "
		    "against templates.\n"));
		return (TVS_FATAL);
	}

	errs = tmpl_errors_create();
	if (errs == NULL)
		uu_die(emesg_nomem);

	lscf_prep_hndl();		/* Initialize g_hndl */
	if (load_init() != 0)
		uu_die(emesg_nomem);

	/*
	 * We will process all services in the bundle, unless we get a
	 * fatal error.  That way we can report all errors on all services
	 * on a single run of svccfg.
	 */
	for (svc = uu_list_first(bndl->sc_bundle_services);
	    svc != NULL;
	    svc = uu_list_next(bndl->sc_bundle_services, svc)) {
		if (svc->sc_etype != SVCCFG_SERVICE_OBJECT) {
			semerr(gettext("Manifest for %s contains an object "
			    "named \"%s\" that is not a service.\n"),
			    bndl->sc_bundle_name, svc->sc_name);
			tmpl_errors_destroy(errs);
			load_fini();
			return (TVS_FATAL);
		}
		if ((r = tmpl_validate_service(svc, errs)) != TVS_SUCCESS)
			rc = r;
		if (r == TVS_FATAL)
			break;
	}

	if (err_list == NULL) {
		tmpl_errors_destroy(errs);
	} else {
		*err_list = errs;
	}

	load_fini();

	return (rc);
}
