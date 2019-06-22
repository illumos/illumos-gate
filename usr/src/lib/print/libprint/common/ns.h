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

#ifndef _NS_H
#define	_NS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 *		Name Service Common Keys/types for lookup
 */
#define	NS_KEY_BSDADDR			"bsdaddr"
#define	NS_KEY_USE			"use"
#define	NS_KEY_ALL			"all"
#define	NS_KEY_GROUP			"group"
#define	NS_KEY_LIST			"list"

#define	NS_KEY_PRINTER_TYPE		"printer-type"
#define	NS_KEY_DESCRIPTION		"description"

/*
 *		Name Service reserved names for lookup
 */
#define	NS_NAME_DEFAULT		"_default"
#define	NS_NAME_ALL		"_all"

/*
 *		Name Services supported
 */
#define	NS_SVC_USER		"user"
#define	NS_SVC_PRINTCAP		"printcap"
#define	NS_SVC_ETC		"etc"
#define	NS_SVC_NIS		"nis"
#define	NS_SVC_LDAP		"ldap"

/*
 *		Known Protocol Extensions
 */
#define	NS_EXT_SOLARIS		"solaris"
#define	NS_EXT_GENERIC		"extensions" /* same as SOLARIS */
#define	NS_EXT_HPUX		"hpux"
#define	NS_EXT_DEC		"dec"

/*
 *	get unique or full list of printer bindings
 */
#define	NOTUNIQUE	0
#define	UNIQUE		1
#define	LOCAL_UNIQUE	2	/* include alias names */

/*  BSD binding address structure */
struct ns_bsd_addr {
	char	*server;	/* server name */
	char	*printer;	/* printer name or NULL */
	char	*extension;	/* RFC-1179 conformance */
	char  *pname;		/* Local printer name */
};
typedef struct ns_bsd_addr ns_bsd_addr_t;

/* Key/Value pair structure */
struct ns_kvp {
	char *key;		/* key */
	char *value;		/* value string */
};
typedef struct ns_kvp ns_kvp_t;


/* LDAP specific result codes */

typedef enum NSL_RESULT
{
	NSL_OK			= 0,	/* Operation successful */
	NSL_ERR_INTERNAL	= 1,	/* Internal coding Error */
	NSL_ERR_ADD_FAILED	= 2,	/* LDAP add failed */
	NSL_ERR_MOD_FAILED	= 3,	/* LDAP modify failed */
	NSL_ERR_DEL_FAILED	= 4,	/* LDAP delete failed */
	NSL_ERR_UNKNOWN_PRINTER	= 5,	/* Unknown Printer object */
	NSL_ERR_CREDENTIALS	= 6,	/* LDAP credentials invalid */
	NSL_ERR_CONNECT		= 7,	/* LDAP server connect failed */
	NSL_ERR_BIND		= 8,	/* LDAP bind failed */
	NSL_ERR_RENAME		= 9,	/* Object rename is not allowed */
	NSL_ERR_KVP		= 10,	/* sun-printer-kvp not allowed */
	NSL_ERR_BSDADDR		= 11,	/* sun-printer-bsdaddr not allowed */
	NSL_ERR_PNAME		= 12,	/* printer-name not allowed */
	NSL_ERR_MEMORY		= 13,	/* memory allocation failed */
	NSL_ERR_MULTIOP		= 14,	/* Replace and delete operation */
	NSL_ERR_NOTALLOWED	= 15,	/* KVP attribute not allowed */
	NSL_ERROR		= -1	/* General error */
} NSL_RESULT;


/* LDAP bind password security type */

typedef enum NS_PASSWD_TYPE {
	NS_PW_INSECURE = 0,
	NS_PW_SECURE = 1
} NS_PASSWD_TYPE;


/*
 * Information needed to update a name service.
 * Currently only used for ldap.
 */
struct ns_cred {
	char	*binddn;
	char	*passwd;
	char	*host;
	int	port;			/* LDAP port, 0 = default */
	NS_PASSWD_TYPE passwdType;	/* password security type */
	uchar_t  *domainDN;		/* NS domain DN */
};
typedef struct ns_cred ns_cred_t;

/* LDAP specific NS Data */

typedef struct NS_LDAPDATA {
	char **attrList;	/* list of user defined Key Value Pairs */
} NS_LDAPDATA;

/* Printer Object structure */
struct ns_printer {
	char	*name;	 /* primary name of printer */
	char	**aliases;	/* aliases for printer */
	char	*source;	/* name service derived from */
	ns_kvp_t  **attributes;  /* key/value pairs. */
	ns_cred_t *cred;	 /* info to update name service */
	void	*nsdata;	/* name service specific data */
};
typedef struct ns_printer ns_printer_t;

/* functions to get/put printer objects */
extern ns_printer_t *ns_printer_create(char *, char **, char *, ns_kvp_t **);
extern ns_printer_t *ns_printer_get_name(const char *, const char *);
extern ns_printer_t **ns_printer_get_list(const char *);
extern int	  ns_printer_put(const ns_printer_t *);
extern void	 ns_printer_destroy(ns_printer_t *);

extern int setprinterentry(int, char *);
extern int endprinterentry();
extern int getprinterentry(char *, int, char *);
extern int getprinterbyname(char *, char *, int, char *);

extern char *_cvt_printer_to_entry(ns_printer_t *, char *, int);

extern ns_printer_t *_cvt_nss_entry_to_printer(char *, char *);
extern ns_printer_t *posix_name(const char *);



/* functions to manipulate key/value pairs */
extern void	 *ns_get_value(const char *, const ns_printer_t *);
extern char	 *ns_get_value_string(const char *, const ns_printer_t *);
extern int	  ns_set_value(const char *, const void *, ns_printer_t *);
extern int	  ns_set_value_from_string(const char *, const char *,
						ns_printer_t *);
extern ns_kvp_t	*ns_kvp_create(const char *, const char *);
extern void ns_kvp_destroy(ns_kvp_t *);

/* for BSD bindings only */
extern ns_bsd_addr_t *ns_bsd_addr_get_default();
extern ns_bsd_addr_t *ns_bsd_addr_get_name(char *name);
extern ns_bsd_addr_t **ns_bsd_addr_get_all(int);
extern ns_bsd_addr_t **ns_bsd_addr_get_list(int);

/* others */
extern int ns_printer_match_name(ns_printer_t *, const char *);
extern char *ns_printer_name_list(const ns_printer_t *);
extern char *value_to_string(const char *, void *);
extern void *string_to_value(const char *, char *);
extern char *normalize_ns_name(char *);
extern char *strncat_escaped(char *, char *, int, char *);



#ifdef __cplusplus
}
#endif

#endif /* _NS_H */
