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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_PICL_H
#define	_PICL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * PICL Interface
 */

#include <sys/types.h>

#define	PICL_VERSION_1	0x1

/*
 * A PICL handle
 */
typedef uint64_t picl_nodehdl_t;
typedef uint64_t picl_prophdl_t;

/*
 * Maximum length of a property name
 */
#define	PICL_PROPNAMELEN_MAX	256
#define	PICL_CLASSNAMELEN_MAX	(PICL_PROPNAMELEN_MAX - sizeof ("__"))

/*
 * Maximum size of a property value
 */
#define	PICL_PROPSIZE_MAX	(512 * 1024)

/*
 * PICL property access modes
 */
#define	PICL_READ		0x1
#define	PICL_WRITE		0x2
/* Not seen by clients */
#define	PICL_VOLATILE		0x4

/*
 * PICL error numbers
 */
typedef enum {
	PICL_SUCCESS = 0x0,
	PICL_FAILURE,		/* general failure */
	PICL_NORESPONSE,	/* No response */
	PICL_UNKNOWNSERVICE,	/* unknown PICL service */
	PICL_NOTINITIALIZED,	/* interface not initialized */
	PICL_INVALIDARG,	/* invalid arguments passed */
	PICL_VALUETOOBIG,	/* value too big for buffer */
	PICL_PROPNOTFOUND,	/* property not found */
	PICL_NOTTABLE,		/* not a table */
	PICL_NOTNODE,		/* not a node */
	PICL_NOTPROP,		/* not a prop */
	PICL_ENDOFLIST,		/* end of list */
	PICL_PROPEXISTS,	/* prop already exists */
	PICL_NOTWRITABLE,	/* not writable */
	PICL_PERMDENIED,	/* permission denied */
	PICL_INVALIDHANDLE,	/* invalid handle */
	PICL_STALEHANDLE,	/* stale handle */
	PICL_NOTSUPPORTED,	/* version not supported */
	PICL_TIMEDOUT,		/* timed out */
	PICL_CANTDESTROY,	/* cannot destroy */
	PICL_TREEBUSY,		/* too busy to lock tree */
	PICL_CANTPARENT,	/* already has a parent */
	PICL_RESERVEDNAME,	/* property name is reserved */
	PICL_INVREFERENCE,	/* Invalid reference value */
	PICL_WALK_CONTINUE,	/* continue walking tree */
	PICL_WALK_TERMINATE,	/* stop walking tree */
	PICL_NODENOTFOUND,	/* node not found */
	PICL_NOSPACE,		/* not enough space available */
	PICL_NOTREADABLE,	/* property not readable */
	PICL_PROPVALUNAVAILABLE	/* property value unavailable */
} picl_errno_t;

/*
 * PICL property types
 */
typedef	enum {
	PICL_PTYPE_UNKNOWN = 0x0,
	PICL_PTYPE_VOID,		/* exists or not */
	PICL_PTYPE_INT,			/* scalar */
	PICL_PTYPE_UNSIGNED_INT,	/* scalar */
	PICL_PTYPE_FLOAT,		/* scalar */
	PICL_PTYPE_REFERENCE,		/* reference handle */
	PICL_PTYPE_TABLE,		/* table handle */
	PICL_PTYPE_TIMESTAMP,		/* time stamp */
	PICL_PTYPE_BYTEARRAY,		/* array of bytes */
	PICL_PTYPE_CHARSTRING		/* nul terminated array of chars */
} picl_prop_type_t;

typedef struct {
	picl_prop_type_t	type;
	unsigned int		accessmode;	/* always == PICL_READ */
	size_t			size;		/* item size or string size */
	char			name[PICL_PROPNAMELEN_MAX];
} picl_propinfo_t;

/*
 * -------------------------------------
 * Function prototypes of PICL Interface
 * -------------------------------------
 */

extern	int  picl_initialize(void);
extern	int  picl_shutdown(void);
extern	int  picl_get_root(picl_nodehdl_t *nodehandle);
extern	int  picl_get_propval(picl_prophdl_t proph, void *valbuf,
		size_t sz);
extern	int  picl_get_propval_by_name(picl_nodehdl_t nodeh,
		const char *propname, void *valbuf, size_t sz);
extern	int  picl_set_propval(picl_prophdl_t proph, void *valbuf,
		size_t sz);
extern	int  picl_set_propval_by_name(picl_nodehdl_t nodeh,
		const char *propname, void *valbuf, size_t sz);
extern  int  picl_get_propinfo(picl_prophdl_t proph, picl_propinfo_t *pi);
extern	int  picl_get_first_prop(picl_nodehdl_t nodeh, picl_prophdl_t *proph);
extern	int  picl_get_next_prop(picl_prophdl_t proph, picl_prophdl_t *nexth);
extern	int  picl_get_prop_by_name(picl_nodehdl_t nodeh, const char *nm,
			picl_prophdl_t *ph);
extern	int  picl_get_next_by_row(picl_prophdl_t thish, picl_prophdl_t *proph);
extern	int  picl_get_next_by_col(picl_prophdl_t thish, picl_prophdl_t *proph);
extern	int  picl_wait(unsigned int secs);
extern	char *picl_strerror(int err);
extern	int  picl_walk_tree_by_class(picl_nodehdl_t rooth,
		const char *classname, void *c_args,
		int (*callback_fn)(picl_nodehdl_t hdl, void *args));
extern	int  picl_get_propinfo_by_name(picl_nodehdl_t nodeh, const char *pname,
		picl_propinfo_t *pinfo, picl_prophdl_t *proph);

extern	int  picl_find_node(picl_nodehdl_t rooth, char *pname,
		picl_prop_type_t ptype, void *pval, size_t valsize,
		picl_nodehdl_t *retnodeh);

extern	int  picl_get_node_by_path(const char *piclpath, picl_nodehdl_t *nodeh);

extern	int  picl_get_frutree_parent(picl_nodehdl_t devh, picl_nodehdl_t *fruh);

/*
 * Standard PICL names: properties and nodes
 */
#define	PICL_NODE_ROOT		"/"
#define	PICL_NODE_PLATFORM	"platform"
#define	PICL_NODE_OBP		"obp"
#define	PICL_NODE_FRUTREE	"frutree"

#define	PICL_PROP_NAME		"name"
#define	PICL_PROP_CLASSNAME	"_class"
#define	PICL_PROP_PARENT	"_parent"
#define	PICL_PROP_CHILD		"_child"
#define	PICL_PROP_PEER		"_peer"

#define	PICL_CLASS_PICL		"picl"

#ifdef	__cplusplus
}
#endif

#endif	/* _PICL_H */
