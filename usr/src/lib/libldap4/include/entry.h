/*
 *
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * structs for storing and updating entries
 */

#if !defined(_ENTRY_H_) && !defined(_PROTO_SLAP)
#define _ENTRY_H_

#ifndef _SLDAPD_H_

/*
 * represents an attribute (type + values + syntax + oid)
 */
typedef struct attr {
	char		*a_type;
	struct berval	**a_vals;
	int		a_syntax;
	struct attr	*a_next;
} Attribute;

/*
 * the attr_syntax() routine returns one of these values
 * telling what kind of syntax an attribute supports.
 *
 * NOTE: The syntax may not be available in libentry unless you have
 * read the slapd.conf config file.
 */
#define SYNTAX_CIS	0x01	/* case insensitive string		*/
#define SYNTAX_CES	0x02	/* case sensitive string		*/
#define SYNTAX_BIN	0x04	/* binary data 				*/
#define SYNTAX_TEL	0x08	/* telephone number string		*/
#define SYNTAX_DN	0x10	/* dn string				*/
#define SYNTAX_LONG	0x20	/* integer  				*/
#define SYNTAX_ULONG	0x40	/* integer  				*/
#define SYNTAX_CRYPT	0x80	/* crypted password */
#define SYNTAX_UTCTIME 0x0100	/* Utctime string YYMMDDhhmm[ss]Z */
#define SYNTAX_GENTIME 0x0200	/* gentime string YYYYMMDDhhmm[ss]Z */

/* These next two are used by libentry.  They are overloaded into a_syntax
 * because there's no extra room and we didn't want to enlarge the structure
 * because of the performance hit.
 */
#define ATTRIBUTE_FOUND 0x1000	/* Set if attribute was found */
#define ATTRIBUTE_ADD   0x2000  /* Set if values are to be added instead of replaced */

#define DEFAULT_SYNTAX	SYNTAX_CIS

typedef struct asyntaxinfo {
	char	**asi_names;
	char *asi_oid;
	int asi_options;
#define ATTR_OPT_SINGLE 0x01 /* Single Valued attr */
#define ATTR_OPT_OPERATIONAL 0x02 /* Operational attr */
#define ATTR_OPT_NAMING 0x10 /* Naming Attribute */
	char *asi_default_oc;
	int asi_maxlen;
	int	asi_syntax;
} AttrSyntaxInfo;

/*
 * the id used in the indexes to refer to an entry
 */
typedef unsigned int	ID;
#define NOID	((unsigned int)-1)

/*
 * represents an entry in core
 */
typedef struct entry {
	char		*e_dn;		/* DN of this entry 		  */
	Attribute	*e_attrs;	/* list of attributes + values    */

	ID		e_id;		/* not used in libentry */
	char		e_state;	/* only ENTRY_FOUND is used below */
#define ENTRY_STATE_DELETED	0x01    /* value not used in libentry */
#define ENTRY_STATE_CREATING	0x02    /* value not used in libentry */
	int		e_refcnt;	/* # threads ref'ing this entry   */
	pthread_mutex_t e_mutex;	/* to lock for add/modify */
	struct entry	*e_lrunext;
	struct entry	*e_lruprev;	/* not used in libentry, (could be added) */
} Entry;

/* This next #define is used by libentry.  It is overloaded into e_state.
 * It is used to mark entries as found/not found so that they can be deleted
 * if they are not found (for example on a remote replica).
 */
#define ENTRY_FOUND             0x80

#endif _SLDAPD_H_

/* entry.c */

/* output_ldif takes a modlist structure and prints out ldif.  Since there are 3 ways
 * you can use a modlist structure, you need to tell this routine what you're doing.
 * The three choices are:
 *	LDAP_MODIFY_ENTRY
 *	LDAP_ADD_ENTRY
 *	LDAP_DELETE_ENTRY
 * ldif suitable for feeding to ldapmodify will be produced.
 */

/* op arg to output_ldif() */
#define LDAP_MODIFY_ENTRY   1
#define LDAP_ADD_ENTRY      2
#define LDAP_DELETE_ENTRY   3

void output_ldif(char *dn, int op, LDAPMod **modlist, FILE *out);

/* Checks that base exist.  If not, create it.
 * ld - ldap context, you must supply it because it's used in ldap_search
 * out - file to output ldif to.  If supplied, ldif will be printed here,
 * if not supplied, ldap_mod will be called for you (using ld).
 *
 * returns number of entries created if all is ok, -1 if an error occured.
 *
 * mutex locks: if you are outputting to out from other threads, you need
 * to lock output_mutex.  output_ldif locks this mutex before outputting.
 */

int make_base(LDAP *ld, FILE *out, char *base);

/* Add an entry to ldap.  You supply an Entry struct.  Will either add entry
 * to ldap or output ldif to an open file (stdout for example).
 *
 * ld - ldap context.  Must be valid if you want entry_add to add entries to ldap
 * for you.
 * out - open file where to send ldif output.  One of ld or out should be valid.
 * new_entry is an Entry which you want added to ldap
 *
 * returns number of entries created or -1 if an error occured in ldap_add()
 */

int entry_add(LDAP *ld, FILE *out, Entry *new_entry);

/* Compares two entries and issue changes to make old look like new.
 *
 * ld - ldap context.  Must be valid if you want entry_update to add entries to ldap
 * for you.
 * out - open file where to send ldif output.  One of ld or out should be valid.
 * new_entry is an Entry which you want old_entry to look like
 *
 * returns number of entries modified or -1 if an error occured in ldap_modify()
 */

int entry_update(LDAP *ld, FILE *out, Entry *old_entry, Entry *new_entry);

/* Deletes an entry.
 * ld - ldap context.  Must be valid if you want delete_entry to call ldap
 * for you.
 * out - open file where to send ldif output.  One of ld or out should be valid.
 * ldap_entry is an Entry which you want to delete
 *
 * returns number of entries deleted or -1 if an error occured in ldap_modify()
 * usually one, but for future it might delete more than one.
 */

int entry_delete(LDAP *ld, FILE *out, Entry *ldap_entry);

/* attr.c */
void attr_free( Attribute *a );
int attr_merge_fast(
    Entry		*e,
    char		*type,
    struct berval	**vals,
    int			nvals,
    int			naddvals,
    int			*maxvals,
    Attribute		***a
);
int attr_merge(
    Entry		*e,
    char		*type,
    struct berval	**vals
);

Attribute *attr_find(
    Attribute	*a,
    char	*type,
    int 	ignoreOpt
);
int attr_delete(
    Attribute	**attrs,
    char	*type
);
int attr_syntax( char *type );
int attr_syntax_by_oid( char *oid );
void attr_syntax_config(
    char	*fname,
    int		lineno,
    int		argc,
    char	**argv
);
char * attr_normalize( char *s );
char * alias_normalize( char *s );
int type_compare(char * t1, char *t2);
int type_list_compare(
    char	**a,
    char	*s
);

int attr_cmp(Attribute *attr1, Attribute *attr2);
char * get_type_from_list(char  **a, char  *s);
int attr_single_valued_check(char *type, struct berval **vals);
AttrSyntaxInfo *get_attrSyntaxInfo(char *type);
char * attr_syntax2oid(int aSyntax);

/* value.c */
int value_add_fast( 
    struct berval	***vals,
    struct berval	**addvals,
    int			nvals,
    int			naddvals,
    int			*maxvals
);
int value_delete( 
    struct berval	***vals,
    struct berval	*v,
    int			syntax,
    int			normalize
);
int value_add_one( 
    struct berval	***vals,
    struct berval	*v,
    int			syntax,
    int			normalize
);
time_t utc2seconds(char * utctime);
int value_add( 
    struct berval	***vals,
    struct berval	**addvals
);
void value_normalize(
    char	*s,
    int		syntax
);
int value_cmp(
    struct berval	*v1,
    struct berval	*v2,
    int			syntax,
    int			normalize	/* 1 => arg 1; 2 => arg 2; 3 => both */
);
int value_ncmp(
    struct berval	*v1,
    struct berval	*v2,
    int			syntax,
    int			len,
    int			normalize
);
int value_find(
    struct berval	**vals,
    struct berval	*v,
    int			syntax,
    int			normalize
);
int value_cnt(struct berval **vals);

/* dn.c */
char *dn_normalize( char *dn );
char *dn_normalize_case( char *dn );
int dn_issuffix(char *dn, char *suffix);
char *dn_upcase( char *dn );

#endif _ENTRY_H_
