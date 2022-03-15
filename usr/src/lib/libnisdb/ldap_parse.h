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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LDAP_PARSE_H
#define	_LDAP_PARSE_H

#include <lber.h>
#include <ldap.h>
#include <rpcsvc/nis.h>

#include "nis_hashitem.h"

/* Pick up N2L file names */
#include <ndbm.h>
#include "yptol/shim.h"
#include "yptol/yptol.h"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * New <ldap.h> doesn't define LDAP_SCOPE_UNKNOWN, but we still need it.
 */
#ifndef	LDAP_SCOPE_UNKNOWN
#define	LDAP_SCOPE_UNKNOWN	0xFF
#endif

/* Attribute/value hash list element */
typedef struct {
	__nis_hash_item_mt	item;		/* item.name is the attr name */
	int			numValues;
	char			**value;	/* Array of values */
	bool_t			isDefault;	/* True if value is a default */
} __nis_ldap_attribute_t;

/* YP Domains structure */
typedef struct {
	int	numDomains;	/* number of domains listed in mapping file */
	char	**domainLabels;	/* the labels for particular domain names */
	char	**domains;		/* Array of LDAP domains */
	int	numYppasswdd;	/* Number of yppasswddDomainLabels */
	char	**yppasswddDomainLabels;	/* yppasswdd domain labels */
} __yp_domain_context_t;

/*
 * Begin object mappings
 *
 * Note that the definitions, where necessary, proceed from the bottom
 * (i.e., the "atomic" components) up.
 */

/*
 * String match/print descriptor
 *
 * Intended for use together with a __nis_mapping_match_type_t, which will
 * determine which field of the union is valid.
 *
 * string	Pointer to a NUL-terminated string
 * single	Represents a single-character match such as '[a-bTe-w]',
 *		which would become
 *			{
 *				3,				numRange
 *				{'a', 'T', 'e'},		lo
 *				{'b', 'T', 'w'}			hi
 *			}
 *		Each pair lo[i]/hi[i] (0 <= i < numRange) defines the
 *		range of the wild-card match.
 * limit	No use currrently defined; will probably be removed
 * berString	Pointer to a string containing a single formatting
 *		character as defined by ber_printf(3LDAP). Example: "i"
 *		for a binary integer.
 */
typedef union {
	char				*string;
	struct {
		int		numRange;
		unsigned char	*lo;		/* Array of numRange elements */
		unsigned char	*hi;		/* Array of numRange elements */
	}				single;
	enum {
		bos,
		eos
	}				limit;
	char				*berString;
} __nis_mapping_match_t;

/*
 * String match/print types and descriptor
 *
 * Used to describe print or match conversions. The 'match' field has
 * the following interpretation:
 *
 * Type		__nis_mapping_match_t	Comment
 *
 * mmt_item		<unused>	Value as indicated by corresponding
 *					element in __nis_mapping_item_t or
 *					__nis_mapping_sub_element_t array
 * mmt_string		string
 * mmt_single		single
 * mmt_limit		limit		Probably not needed
 * mmt_any		<unused>	Match any number of any character
 * mmt_berstring	berString
 * mmt_begin		<unused>	Indicates beginning of format; optional
 * mmt_end		<unused>	Indicates end of format; REQUIRED to
 *					mark the end of an array of
 *					__nis_mapping_format_t's
 */
typedef enum {mmt_item, mmt_string, mmt_single, mmt_limit, mmt_any,
		mmt_berstring, mmt_begin, mmt_end}
	__nis_mapping_match_type_t;

typedef struct {
	__nis_mapping_match_type_t	type;
	__nis_mapping_match_t		match;
} __nis_mapping_format_t;

/* Forward */
struct __nis_mapping_element_struct;
struct __nis_mapping_item_struct;

/*
 * LDAP search triple
 *
 * Used to represent a search triple like
 *	ou=Group,?one?cn=staff
 * or
 *	ou=Group,?one?(&(cn=staff)(gidNumber=10))
 * or
 *	ou=Hosts,?one?("cn=%s", (cname, "%s.*"))
 *
 * base		The base DN; defaultSearchBase appended if 'base' ends with
 *		a comma.
 * scope	One of LDAP_SCOPE_BASE, LDAP_SCOPE_ONELEVEL, or
 *		LDAP_SCOPE_SUBTREE; LDAP_SCOPE_UNKNOWN means that this
 *		__nis_search_triple_t is inactive
 * attrs	Either a filter, or a list of attribute/value pairs, depending
 *		on context.
 * element	Pointer to a value element. If 'element' is non-NULL, the
 *		'attrs' value is derived by evaluating 'element'.
 */
typedef struct {
	char					*base;
	int					scope;
	char					*attrs;
	struct __nis_mapping_element_struct	*element;
} __nis_search_triple_t;

/*
 * NIS+ index spec
 *
 * Represents a NIS+ index list, such as
 *	name=staff,gid=10
 *
 * numIndexes	The number of entries in the 'name'/'value' arrays
 * name		Array of column names
 * value	Array of column values; uses __nis_mapping_format_t so that
 *		wild-cards can be represented
 *
 * Example
 *		name=staff,gid=10
 *	2,						numIndexes
 *	{						name
 *		"name",
 *		"gid"
 *	},
 *	{						value
 *		{
 *			{mmt_begin},
 *			{mmt_string, "staff"},
 *			{mmt_end}
 *		},
 *		{
 *			{mmt_begin},
 *			{mmt_string, "gid"},
 *			{mmt_end}
 *		}
 *	}
 */
typedef struct {
	int			numIndexes;
	char			**name;
	__nis_mapping_format_t	**value;
} __nis_index_t;

/* What to do with the LDAP data when a NIS+ entry is deleted */
typedef enum {dd_always, dd_perDbId, dd_never} __nis_delete_disp_t;

/* Type of an element in a mapping rule */
typedef enum {me_item, me_print, me_split, me_match, me_extract}
	__nis_mapping_element_type_t;

/* Type of an item in a mapping rule */
typedef enum {mit_any, mit_nisplus, mit_ldap}	__nis_mapping_item_type_t;

/*
 * NIS+ object name, with index
 *
 * Used to represent a name like
 *	[name = staff, gid = 10]group.org_dir
 * (Note: spaces around "=" and after "," to make cstyle happy; such spaces
 * are not usually part of the syntax, but they are allowed.)
 *
 * index	The index part of the name. numIndexes == 0 means there is
 *		no index.
 * name		The object name proper. If it doesn't end in a dot, the
 *		nisplusLDAPbaseDomain is appended.
 */
typedef struct {
	__nis_index_t		index;
	char			*name;
} __nis_obj_spec_t;

/*
 * Complete representation of a subset of either the DIT or a NIS+ object.
 * Intended for use in a __nis_mapping_item_t, where the 'type' field
 * determines which field of the __nis_triple_or_obj_t is active.
 */
typedef union {
	__nis_search_triple_t	triple;
	__nis_obj_spec_t	obj;
} __nis_triple_or_obj_t;

/*
 * Mapping item
 *
 * The mapping item is a single LDAP attribute, or a NIS+ table column, such as
 *	ldap:gidNumber:ou=Group, ?one?cn=staff
 * or
 *	nisplus:gid[name = staff]group.org_dir
 * (Note: spaces around "=" and after "," to make cstyle happy; such spaces
 * are not usually part of the syntax, but they are allowed.)
 *
 * type		mit_ldap or mit_nisplus
 * name		Attribute/column name
 * searchSpec	LDAP search triple, or NIS+ indexed object name
 * repeat	True if item should be repeated if necessary. This is used
 *		to represent implied lists, such as '(memberUid)', which
 *		denotes all values of the 'memberUid' attribute.
 * exItem forward mapping item for supporting removespec syntax.
 *
 */
typedef struct __nis_mapping_item_struct {
	__nis_mapping_item_type_t	type;
	char				*name;
	__nis_triple_or_obj_t		searchSpec;
	bool_t				repeat;
	struct				__nis_mapping_item_struct	*exItem;
} __nis_mapping_item_t;

/*
 * Sub-element of a mapping rule element
 *
 * Each element/sub-element represents the value(s) derived according to
 * the semantics of the element. Although not explicitly represented here,
 * values are either strings or BER byte sequences.
 *
 * type			Type of the 'element' union
 * element.item		A single item
 * element.print	printf(3C)-style value
 *	fmt		Array of formatting elements, terminated by 'mmt_end'
 *	numItems	Number of items in the 'item' array
 *	item		Array of 'numItems' items
 *	doElide		Should the last character of the (string) value be
 *			removed ?
 *	elide		Character to be removed
 * element.split	Item value string split into multiple values
 *	item		A single item
 *	delim		The separator character for the split
 * element.extract	Extraction of a sub-string from an item value
 *	fmt		Array of formatting elements, terminated by 'mmt_end'
 *	item		A single item
 *
 * Examples (see __nis_mapping_element_t below for examples using the 'item'
 * field of __nis_mapping_sub_element_t). For notational convenience,
 * __nis_mapping_item_t's are shortened to just the item name.
 *
 * (1)	String value consisting of the string "{crypt}" followed by the
 *	value of the 'passwd' column. The NIS+LDAPmapping(5) representation
 *	is
 *		("{crypt}%s", passwd)
 *	and the element.print contains
 *		{					fmt
 *			{mmt_begin},
 *			{mmt_string, "{crypt}"},
 *			{mmt_item},
 *			{mmt_end}
 *		},
 *		1,					numItems
 *		{					item
 *			{"passwd"}
 *		}
 *		FALSE,					doElide
 *		'\0'					elide (unused)
 *
 * (2)	Split a value such as "member1,member2,member3" into multiple
 *	(three, here) values using ',' as the separator.
 *		(members, ",")
 *	element.split
 *		{"members"},				item
 *		','					delim
 *
 * (3)	Given a 'cname' column with the value "some.dom.ain.", extract
 *	"some", which becomes the value of the expression.
 *		(cname, "%s.*")
 *	element.extract
 *		{					fmt
 *			{mmt_begin},
 *			{mmt_item},
 *			{mmt_string, "."},
 *			{mmt_any},
 *			{mmt_end}
 *		},
 *		{"cname"}				item
 */
typedef struct {
	__nis_mapping_element_type_t				type;
	union {
		__nis_mapping_item_t				item;
		struct {
			__nis_mapping_format_t		*fmt;
			int				numItems;
			__nis_mapping_item_t		*item;
			bool_t				doElide;
			unsigned char			elide;
		}						print;
		struct {
			__nis_mapping_item_t		item;
			unsigned char			delim;
		}						split;
		struct {
			__nis_mapping_format_t		*fmt;
			__nis_mapping_item_t		item;
		}						extract;
	} element;
} __nis_mapping_sub_element_t;

/*
 * Mapping rule element
 *
 * Each element/sub-element represents the value(s) derived according to
 * the semantics of the element. Although not explicitly represented here,
 * values are either strings or BER byte sequences.
 *
 * type			Type of the 'element' union
 * element.item		A single item
 * element.print	printf(3C)-style value
 *	fmt		Array of formatting elements, terminated by 'mmt_end'
 *	numSubElements	Number of sub-elements in the 'subElement' array
 *	subElement	Array of 'numSubElements' sub-elements
 *	doElide		Should the last character of the (string) value(s) be
 *			removed ?
 *	elide		Character to be removed
 * element.split	Item value string split into multiple values
 *	item		A single item
 *	delim		The separator character for the split
 * element.match	Assignment of item values by matching to a format
 *	fmt		Array of formatting elements, terminated by 'mmt_end'
 *	numItems	Number of items in the 'item' array
 *	item		Array of 'numItems' items
 * element.extract	Extraction of a sub-string from an item value
 *	fmt		Array of formatting elements, terminated by 'mmt_end'
 *	item		A single item
 *
 * Examples; items represented by just the item name.
 *
 * (1)	The value of the 'name' column.
 *		name
 *	element.item
 *		{"name"}				item
 *
 * (2)	Example (1) for a sub-element showed how to construct a value from
 *	a printf(3C)-style format string and one or more item values.
 *	However that example is only valid when used as a sub-expression
 *	(in place of an item in a 'print' list, for example). If
 *		("{crypt}%s", passwd)
 *	was part of a rule like
 *		userPassword=("{crypt}%s", passwd)
 *	the representation would use a __nis_mapping_element_t as follows.
 *	element.print
 *		{					fmt
 *			{mmt_begin},
 *			{mmt_string, "{crypt}"},
 *			{mmt_item},
 *			{mmt_end}
 *		},
 *		1,					numSubElements
 *		{					subElement
 *			me_item,				type
 *			{"passwd"}				item
 *		},
 *		FALSE,					doElide
 *		'\0'					elide (unused)
 *
 * (3)	Match a value such as "{dh-1024}abcdef000234" to a template format
 *	"{%s}%s", assign "dh-1024" to the 'auth_type' column, and
 *	"abcdef000234" to the 'public_data' column.
 *		("{%s}%s", auth_type, public_data)
 *	element.match
 *		{					fmt
 *			{mmt_begin},
 *			{mmt_string, "{"},
 *			{mmt_item},
 *			{mmt_string, "}"},
 *			{mmt_item},
 *			{mmt_end}
 *		}
 *		2,					numItems
 *		{					item
 *			{"auth_type"},
 *			{"public_data"}
 *		}
 */
typedef struct __nis_mapping_element_struct {
	__nis_mapping_element_type_t				type;
	union {
		__nis_mapping_item_t				item;
		struct {
			__nis_mapping_format_t		*fmt;
			int				numSubElements;
			__nis_mapping_sub_element_t	*subElement;
			bool_t				doElide;
			unsigned char			elide;
		}						print;
		struct {
			__nis_mapping_item_t		item;
			unsigned char			delim;
		}						split;
		struct {
			__nis_mapping_format_t		*fmt;
			int				numItems;
			__nis_mapping_item_t		*item;
		}						match;
		struct {
			__nis_mapping_format_t		*fmt;
			__nis_mapping_item_t		item;
		}						extract;
	} element;
} __nis_mapping_element_t;

/*
 * One side (left or right) of a mapping rule
 *
 * Example
 *	The rule
 *		userPassword=("{crypt}%s", passwd)
 *	would be reprsented by a __nis_mapping_rule_t as follows
 *		{					lhs
 *			1,					numElements
 *			{					element
 *				me_item,
 *				{"userPassword"}
 *			}
 *		},
 *		{					rhs
 *			1,					numElements
 *			{					element
 *				me_print,
 *				{
 *						See example (2) under
 *						__nis_mapping_element_t
 *						above
 *				}
 *			}
 *		}
 */
typedef struct {
	int			numElements;
	__nis_mapping_element_t	*element;
} __nis_mapping_rlhs_t;

/* A single mapping rule: attribute -> column or column -> attribute */
typedef struct {
	__nis_mapping_rlhs_t	lhs;
	__nis_mapping_rlhs_t	rhs;
} __nis_mapping_rule_t;

/*
 * Map (sub-set of) NIS+ object to location(s) in the LDAP DB
 *
 * read		base/scope/filter triple used to read data from LDAP;
 *		LDAP_SCOPE_UNKNOWN indicates that 'read' is unused
 * write	base/scope/attrlist triple used to write data to LDAP;
 *		LDAP_SCOPE_UNKNOWN indicates that 'write' is unused
 * delDisp	What should happen to the LDAP entry when the corresponding
 *		NIS+ data is deleted.
 * dbIdName	The dbId for the delete rule set (if any)
 * numDbIds	The number of rules in the 'dbId' rule set
 * dbId		The delete rule set; this field must point to a valid
 *		rule set if 'delDisp' is 'dd_perDbId'; ignored otherwise
 * next		Pointer to the next __nis_object_dn_t structure for this
 *		NIS+ object.
 *
 * Example
 *	The "group.org_dir.x.y.z." NIS+ table should be read from and
 *	written to the "ou=Group" container at "dc=x,dc=y,dc=z". Upon
 *	NIS+ entry deletion, we should always attempt to delete the
 *	corresponding LDAP attributes.
 *
 *	{						read
 *		"ou=Group,dc=x,dc=y,dc=z",
 *		LDAP_SCOPE_ONELEVEL,
 *		"objectClass=posixGroup"
 *	},
 *	{						write
 *		"ou=Group,dc=x,dc=y,dc=z",
 *		LDAP_SCOPE_ONELEVEL,
 *		"objectClass=posixGroup"
 *	},
 *	dd_always,					delDisp
 *	NULL,						dbIdName
 *	0,
 *	NULL,						dbId
 *	NULL						next
 */
typedef struct {
	__nis_search_triple_t	read;
	__nis_search_triple_t	write;
	__nis_delete_disp_t	delDisp;
	char			*dbIdName;
	int			numDbIds;
	__nis_mapping_rule_t	**dbId;		/* Delete rule set */
	void			*next;
} __nis_object_dn_t;

/*
 * Per-dbId or -object mapping
 *
 * Initially collected per-dbId (so that item.name=dbId), the
 * __nis_table_mapping_t's are later stored per-object (whereupon
 * item.name=objName).
 *
 * item			Structure used by the hash_item functions
 * dbId			The dbId associated with the __nis_table_mapping_t
 *			structure
 * index		Object sub-set specification; only defined for
 *			tables; index.numIndexes equal to zero means that
 *			the 'index' is unused.
 * next			Pointer to next table sub-set, if any
 * numColumns	Number of columns if the object is a table
 * column		Column names
 * initTtlLo	Lower limit on the initial TTL
 * initTtlHi	Upper limit on the initial TTL
 * ttl			TTL set after refresh
 * commentChar	NIS map comment character
 * objectDN		Location in the LDAP DB
 * numSplits	number of split fields
 * separatorStr separator string to break up NIS split field attributes
 * usedns_flag  indicates if the -b option to makedbm is used for a map.
 * securemap_flag indicates if the -s option to makedbm is used for a map.
 * __nis_mapping_element_t Parsed format strings and name fields storage
 * numRulesFromLDAP	Number of rules (and hence elements in the
 *			'ruleFromLDAP' array) for mapping LDAP entries
 *			to NIS+ objects
 * ruleFromLDAP
 * numRulesToLDAP	Number of rules (and hence elements in the
 *			'ruleToLDAP' array) for mapping NIS+ objects to
 *			LDAP entries
 * ruleToLDAP
 * objType		The NIS+ object type; NIS_BOGUS_OBJ used to indicate
 *			not set (in which case the other object data fields
 *			should be assumed to be invalid)
 * objName		The fully qualified name of the NIS+ object
 * objPath		The name used internally by libnisdb (which
 *			is path to the data file for the table/directory
 *			containing the object)
 * obj			A copy of the object itself
 * isMaster		Set if this machine is the master for the object
 *			(actually for the directory containing it)
 * seq_num	A sequence number representing the order of the maps
 *			as listed in the NISLDAPmapping.template file.
 *
 * Example
 *	Map the subset of the NIS+ 'group.org_dir.x.y.z.' table for which
 *	is true that the 'name' starts with 'a' or 'o' to location per
 *	the __nis_object_dn_t example above. No translation rules.
 *
 *		{					item
 *			"group.org_dir.x.y.z."			name
 *			<omitted>
 *		},
 *		"group_subset",				dbId
 *		1,					numIndexes
 *		{					index
 *			1,
 *			{"name"},
 *			{
 *				{mmt_begin},
 *				{
 *					mmt_single,
 *					2,
 *					{'a', 'o'},
 *					{'a', 'o'},
 *				}
 *				{mmt_any},
 *				{mmt_end}
 *			}
 *		}
 *		NULL,					next
 *		4,					numColumns
 *		{					column
 *			"name",
 *			"passwd",
 *			"gid",
 *			"members"
 *		},
 *		1800,					initTtlLo
 *		5400,					initTtlHi
 *		3600,					ttl
 *		'#',					commentChar
 *		<see __nis_object_dn_t example>,	objectDN
 *		0,						numSplits
 *		NULL,					separatorStr
 *		0,						usedns_flag
 *		0, 						securemap_flag
 *		<see __nis_mapping_element_t example>, e
 *		0,					numRulesFromLDAP
 *		NULL,					ruleFromLDAP
 *		0,					numRulesToLDAP
 *		NULL					ruleToLDAP
 *		NIS_TABLE_OBJ,				objType
 *		"group.org_dir.x.y.z.",			objName
 *		"/var/nis/data/group.org_dir"		objPath
 *		<pointer to NIS+ object>		obj
 *		1					isMaster
 */
typedef struct {
	__nis_hash_item_mt	item;		/* item.name=dbId||objName */
	char			*dbId;		/* Used during initializaton */
	__nis_index_t		index;
	void			*next;		/* Next sub-set spec */
	void			*seqNext;	/* Next in config sequence */
	int				numColumns;
	char			**column;
	time_t			initTtlLo;
	time_t			initTtlHi;
	time_t			ttl;
	char			commentChar;
	__nis_object_dn_t	*objectDN;
	int				numSplits;
	char			*separatorStr;
	int				usedns_flag;
	int				securemap_flag;
	__nis_mapping_element_t	*e;
	int			numRulesFromLDAP;
	__nis_mapping_rule_t	**ruleFromLDAP;
	int			numRulesToLDAP;
	__nis_mapping_rule_t	**ruleToLDAP;
/*
 * The following fields contain information about the mapped object.
 */
	zotypes			objType;
	char			*objName;	/* FQ object name */
	char			*objPath;	/* nisdb's internal name */
	nis_object		*obj;		/* NIS+ object */
	int			isMaster;	/* Master for this object ? */
	int			seq_num;
} __nis_table_mapping_t;

/* End object mappings */

/* Default config file paths */
#define	DEFAULTCONFFILE	"/var/nis/NIS+LDAPmapping"
#define	ETCCONFFILE	"/etc/default/rpc.nisd"
#define	YP_DEFAULTCONFFILE	NTOL_MAP_FILE
#define	YP_ETCCONFFILE	NTOL_CONFIG_FILE

/* Path to the root object dir file */
#define	ROOTDIRFILE	"/var/nis/data/root_dir"
/* Path to the root object file */
#define	ROOTOBJFILE	"/var/nis/data/root.object"

extern __nis_table_mapping_t	*ldapMappingSeq;
extern int yp2ldap;

/* Exported functions */
int			parseConfig(char **ldapCLA, char *ldapConfFile);
int			linked2hash(__nis_table_mapping_t *tlist);
int			dbids2objs(__nis_hash_table_mt *objs,
				__nis_hash_table_mt *dbids);
void			__make_legal(char *s);
char			*internal_table_name(nis_name name, char *res);
nis_name		relative_name(char *s);
char			*internalTableName(char *name);
__nis_table_mapping_t	*getObjMapping(char *name, char *intNameArg,
				int asObj,
				int *doRead, int *doWrite);

#ifdef	__cplusplus
}
#endif	/* __cplusplus */

#endif	/* _LDAP_PARSE_H */
