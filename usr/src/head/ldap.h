/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * The contents of this file are subject to the Netscape Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/NPL/
 *
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 *
 * The Original Code is Mozilla Communicator client code, released
 * March 31, 1998.
 *
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation. Portions created by Netscape are
 * Copyright (C) 1998-1999 Netscape Communications Corporation. All
 * Rights Reserved.
 *
 * Contributor(s):
 */

#ifndef	_LDAP_H
#define	_LDAP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	_SOLARIS_SDK
#define	_SOLARIS_SDK
#endif

#ifndef	LDAP_TYPE_TIMEVAL_DEFINED
#include <sys/time.h>
#endif
#ifndef	LDAP_TYPE_SOCKET_DEFINED	/* API extension */
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <lber.h>

#define	LDAP_PORT		389
#define	LDAPS_PORT		636
#define	LDAP_PORT_MAX		65535		/* API extension */
#define	LDAP_VERSION1		1		/* API extension */
#define	LDAP_VERSION2		2
#define	LDAP_VERSION3		3
#define	LDAP_VERSION		LDAP_VERSION2	/* API extension */
#define	LDAP_VERSION_MIN	LDAP_VERSION3
#define	LDAP_VERSION_MAX	LDAP_VERSION3

#define	LDAP_VENDOR_VERSION	500	/* version # * 100 */
#define	LDAP_VENDOR_NAME	"Sun Microsystems Inc."
/*
 * The following will be an RFC number once the LDAP C API Internet Draft
 * is published as a Proposed Standard RFC.  For now we use 2000 + the
 * draft revision number (currently 5) since we are close to compliance
 * with revision 5 of the draft.
 */
#define	LDAP_API_VERSION	2005

/*
 * C LDAP features we support that are not (yet) part of the LDAP C API
 * Internet Draft.  Use the ldap_get_option() call with an option value of
 * LDAP_OPT_API_FEATURE_INFO to retrieve information about a feature.
 *
 * Note that this list is incomplete; it includes only the most widely
 * used extensions.  Also, the version is 1 for all of these for now.
 */
#define	LDAP_API_FEATURE_SERVER_SIDE_SORT	1
#define	LDAP_API_FEATURE_VIRTUAL_LIST_VIEW	1
#define	LDAP_API_FEATURE_PERSISTENT_SEARCH	1
#define	LDAP_API_FEATURE_PROXY_AUTHORIZATION	1
#define	LDAP_API_FEATURE_X_LDERRNO		1
#define	LDAP_API_FEATURE_X_MEMCACHE		1
#define	LDAP_API_FEATURE_X_IO_FUNCTIONS		1
#define	LDAP_API_FEATURE_X_EXTIO_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_DNS_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_MEMALLOC_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_THREAD_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_EXTHREAD_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_GETLANGVALUES	1
#define	LDAP_API_FEATURE_X_CLIENT_SIDE_SORT	1
#define	LDAP_API_FEATURE_X_URL_FUNCTIONS	1
#define	LDAP_API_FEATURE_X_FILTER_FUNCTIONS	1

#define	LDAP_ROOT_DSE		""		/* API extension */
#define	LDAP_NO_ATTRS		"1.1"
#define	LDAP_ALL_USER_ATTRS	"*"

/*
 * Standard options (used with ldap_set_option() and ldap_get_option):
 */
#define	LDAP_OPT_API_INFO		0x00	/*  0 */
#define	LDAP_OPT_DESC			0x01	/*  1 */
#define	LDAP_OPT_DEREF			0x02	/*  2 */
#define	LDAP_OPT_SIZELIMIT		0x03	/*  3 */
#define	LDAP_OPT_TIMELIMIT		0x04	/*  4 */
#define	LDAP_OPT_REFERRALS		0x08	/*  8 */
#define	LDAP_OPT_RESTART		0x09	/*  9 */
#define	LDAP_OPT_PROTOCOL_VERSION	0x11	/* 17 */
#define	LDAP_OPT_SERVER_CONTROLS	0x12	/* 18 */
#define	LDAP_OPT_CLIENT_CONTROLS	0x13	/* 19 */
#define	LDAP_OPT_API_FEATURE_INFO	0x15	/* 21 */
#define	LDAP_OPT_HOST_NAME		0x30	/* 48 */
#define	LDAP_OPT_ERROR_NUMBER		0x31	/* 49 */
#define	LDAP_OPT_ERROR_STRING		0x32	/* 50 */
#define	LDAP_OPT_MATCHED_DN		0x33	/* 51 */

/*
 * Well-behaved private and experimental extensions will use option values
 * between 0x4000 (16384) and 0x7FFF (32767) inclusive.
 */
#define	LDAP_OPT_PRIVATE_EXTENSION_BASE	0x4000	/* to 0x7FFF inclusive */
/*
 * Special timeout values for poll and connect:
 */
#define	LDAP_X_IO_TIMEOUT_NO_WAIT	0	/* return immediately */
#define	LDAP_X_IO_TIMEOUT_NO_TIMEOUT    (-1)    /* block indefinitely */
/*
 * Timeout value for nonblocking connect call
 */
#define	LDAP_X_OPT_CONNECT_TIMEOUT    (LDAP_OPT_PRIVATE_EXTENSION_BASE + 0x0F01)
	/* 0x4000 + 0x0F01 = 0x4F01 = 20225 - API extension */

/* for on/off options */
#define	LDAP_OPT_ON	((void *)1)
#define	LDAP_OPT_OFF	((void *)0)

typedef struct ldap	LDAP;		/* opaque connection handle */
typedef struct ldapmsg  LDAPMessage;    /* opaque result/entry handle */

#define	NULLMSG ((LDAPMessage *)0)

/* structure representing an LDAP modification */
typedef struct ldapmod {
	int		mod_op;		/* kind of mod + form of values */
#define	LDAP_MOD_ADD		0x00
#define	LDAP_MOD_DELETE		0x01
#define	LDAP_MOD_REPLACE	0x02
#define	LDAP_MOD_BVALUES	0x80
	char			*mod_type;	/* attribute name to modify */
	union mod_vals_u {
		char		**modv_strvals;
		struct berval   **modv_bvals;
	} mod_vals;		/* values to add/delete/replace */
#define	mod_values	mod_vals.modv_strvals
#define	mod_bvalues	mod_vals.modv_bvals
} LDAPMod;


/*
 * structure for holding ldapv3 controls
 */
typedef struct ldapcontrol {
    char		*ldctl_oid;
    struct berval	ldctl_value;
    char		ldctl_iscritical;
} LDAPControl;


/*
 * LDAP API information.  Can be retrieved by using a sequence like:
 *
 *    LDAPAPIInfo ldai;
 *    ldai.ldapai_info_version = LDAP_API_INFO_VERSION;
 *    if ( ldap_get_option( NULL, LDAP_OPT_API_INFO, &ldia ) == 0 ) ...
 */
#define	LDAP_API_INFO_VERSION		1
typedef struct ldapapiinfo {
    int	 ldapai_info_version;	  /* version of this struct (1) */
    int	ldapai_api_version;	/* revision of API supported */
    int  ldapai_protocol_version; /* highest LDAP version supported */
    char **ldapai_extensions;	/* names of API extensions */
    char *ldapai_vendor_name;	/* name of supplier */
    int  ldapai_vendor_version;   /* supplier-specific version times 100 */
} LDAPAPIInfo;


/*
 * LDAP API extended features info.  Can be retrieved by using a sequence like:
 *
 *    LDAPAPIFeatureInfo ldfi;
 *    ldfi.ldapaif_info_version = LDAP_FEATURE_INFO_VERSION;
 *    ldfi.ldapaif_name = "VIRTUAL_LIST_VIEW";
 *    if ( ldap_get_option( NULL, LDAP_OPT_API_FEATURE_INFO, &ldfi ) == 0 ) ...
 */
#define	LDAP_FEATURE_INFO_VERSION	1
typedef struct ldap_apifeature_info {
    int   ldapaif_info_version;	/* version of this struct (1) */
    char  *ldapaif_name;	/* name of supported feature */
    int   ldapaif_version;	/* revision of supported feature */
} LDAPAPIFeatureInfo;


/* possible result types a server can return */
#define	LDAP_RES_BIND			0x61	/* 97 */
#define	LDAP_RES_SEARCH_ENTRY		0x64	/* 100 */
#define	LDAP_RES_SEARCH_RESULT		0x65	/* 101 */
#define	LDAP_RES_MODIFY			0x67	/* 103 */
#define	LDAP_RES_ADD			0x69	/* 105 */
#define	LDAP_RES_DELETE			0x6b	/* 107 */
#define	LDAP_RES_MODDN			0x6d	/* 109 */
#define	LDAP_RES_COMPARE		0x6f	/* 111 */
#define	LDAP_RES_SEARCH_REFERENCE	0x73	/* 115 */
#define	LDAP_RES_EXTENDED		0x78	/* 120 */

/* Special values for ldap_result() "msgid" parameter */
#define	LDAP_RES_ANY			(-1)
#define	LDAP_RES_UNSOLICITED		0

/* built-in SASL methods */
#define	LDAP_SASL_SIMPLE	0	/* special value used for simple bind */
#define	LDAP_SASL_EXTERNAL	"EXTERNAL"	/* TLS/SSL extension */

#ifdef	_SOLARIS_SDK
#define	LDAP_SASL_CRAM_MD5	"CRAM-MD5"
#define	LDAP_SASL_DIGEST_MD5	"DIGEST-MD5"
#define	LDAP_SASL_BIND_INPROGRESS	0x0e    /* for backward compatibility */
#endif

/* search scopes */
#define	LDAP_SCOPE_BASE		0x00
#define	LDAP_SCOPE_ONELEVEL	0x01
#define	LDAP_SCOPE_SUBTREE	0x02

/* alias dereferencing */
#define	LDAP_DEREF_NEVER	0
#define	LDAP_DEREF_SEARCHING	1
#define	LDAP_DEREF_FINDING	2
#define	LDAP_DEREF_ALWAYS	3

/* predefined size/time limits */
#define	LDAP_NO_LIMIT		0

/* allowed values for "all" ldap_result() parameter */
#define	LDAP_MSG_ONE		0
#define	LDAP_MSG_ALL		1
#define	LDAP_MSG_RECEIVED	2

/* possible error codes we can be returned */
#define	LDAP_SUCCESS			0x00	/* 0 */
#define	LDAP_OPERATIONS_ERROR		0x01	/* 1 */
#define	LDAP_PROTOCOL_ERROR		0x02	/* 2 */
#define	LDAP_TIMELIMIT_EXCEEDED		0x03	/* 3 */
#define	LDAP_SIZELIMIT_EXCEEDED		0x04	/* 4 */
#define	LDAP_COMPARE_FALSE		0x05	/* 5 */
#define	LDAP_COMPARE_TRUE		0x06	/* 6 */
#define	LDAP_STRONG_AUTH_NOT_SUPPORTED	0x07	/* 7 */
#define	LDAP_STRONG_AUTH_REQUIRED	0x08	/* 8 */
#define	LDAP_PARTIAL_RESULTS		0x09	/* 9 (UMich LDAPv2 extn) */
#define	LDAP_REFERRAL			0x0a	/* 10 - LDAPv3 */
#define	LDAP_ADMINLIMIT_EXCEEDED	0x0b	/* 11 - LDAPv3 */
#define	LDAP_UNAVAILABLE_CRITICAL_EXTENSION  0x0c /* 12 - LDAPv3 */
#define	LDAP_CONFIDENTIALITY_REQUIRED	0x0d	/* 13 */
#define	LDAP_SASL_BIND_IN_PROGRESS	0x0e	/* 14 - LDAPv3 */

#define	LDAP_NO_SUCH_ATTRIBUTE		0x10	/* 16 */
#define	LDAP_UNDEFINED_TYPE		0x11	/* 17 */
#define	LDAP_INAPPROPRIATE_MATCHING	0x12	/* 18 */
#define	LDAP_CONSTRAINT_VIOLATION	0x13	/* 19 */
#define	LDAP_TYPE_OR_VALUE_EXISTS	0x14	/* 20 */
#define	LDAP_INVALID_SYNTAX		0x15	/* 21 */

#define	LDAP_NO_SUCH_OBJECT		0x20	/* 32 */
#define	LDAP_ALIAS_PROBLEM		0x21	/* 33 */
#define	LDAP_INVALID_DN_SYNTAX		0x22	/* 34 */
#define	LDAP_IS_LEAF			0x23	/* 35 (not used in LDAPv3) */
#define	LDAP_ALIAS_DEREF_PROBLEM	0x24	/* 36 */

#define	NAME_ERROR(n)   ((n & 0xf0) == 0x20)

#define	LDAP_INAPPROPRIATE_AUTH		0x30	/* 48 */
#define	LDAP_INVALID_CREDENTIALS	0x31	/* 49 */
#define	LDAP_INSUFFICIENT_ACCESS	0x32	/* 50 */
#define	LDAP_BUSY			0x33	/* 51 */
#define	LDAP_UNAVAILABLE		0x34	/* 52 */
#define	LDAP_UNWILLING_TO_PERFORM	0x35	/* 53 */
#define	LDAP_LOOP_DETECT		0x36	/* 54 */

#define	LDAP_SORT_CONTROL_MISSING	0x3C	/* 60 (server side sort extn) */
#define	LDAP_INDEX_RANGE_ERROR		0x3D    /* 61 (VLV extn) */

#define	LDAP_NAMING_VIOLATION		0x40	/* 64 */
#define	LDAP_OBJECT_CLASS_VIOLATION	0x41	/* 65 */
#define	LDAP_NOT_ALLOWED_ON_NONLEAF	0x42	/* 66 */
#define	LDAP_NOT_ALLOWED_ON_RDN		0x43	/* 67 */
#define	LDAP_ALREADY_EXISTS		0x44	/* 68 */
#define	LDAP_NO_OBJECT_CLASS_MODS	0x45	/* 69 */
#define	LDAP_RESULTS_TOO_LARGE		0x46	/* 70 - CLDAP */
#define	LDAP_AFFECTS_MULTIPLE_DSAS	0x47	/* 71 */

#define	LDAP_OTHER			0x50	/* 80 */
#define	LDAP_SERVER_DOWN		0x51	/* 81 */
#define	LDAP_LOCAL_ERROR		0x52	/* 82 */
#define	LDAP_ENCODING_ERROR		0x53	/* 83 */
#define	LDAP_DECODING_ERROR		0x54	/* 84 */
#define	LDAP_TIMEOUT			0x55	/* 85 */
#define	LDAP_AUTH_UNKNOWN		0x56	/* 86 */
#define	LDAP_FILTER_ERROR		0x57	/* 87 */
#define	LDAP_USER_CANCELLED		0x58	/* 88 */
#define	LDAP_PARAM_ERROR		0x59	/* 89 */
#define	LDAP_NO_MEMORY			0x5a	/* 90 */
#define	LDAP_CONNECT_ERROR		0x5b	/* 91 */
#define	LDAP_NOT_SUPPORTED		0x5c	/* 92 - LDAPv3 */
#define	LDAP_CONTROL_NOT_FOUND		0x5d	/* 93 - LDAPv3 */
#define	LDAP_NO_RESULTS_RETURNED	0x5e	/* 94 - LDAPv3 */
#define	LDAP_MORE_RESULTS_TO_RETURN	0x5f	/* 95 - LDAPv3 */
#define	LDAP_CLIENT_LOOP		0x60	/* 96 - LDAPv3 */
#define	LDAP_REFERRAL_LIMIT_EXCEEDED	0x61	/* 97 - LDAPv3 */

/*
 * LDAPv3 unsolicited notification messages we know about
 */
#define	LDAP_NOTICE_OF_DISCONNECTION	"1.3.6.1.4.1.1466.20036"

/*
 * LDAPv3 server controls we know about
 */
#define	LDAP_CONTROL_MANAGEDSAIT	"2.16.840.1.113730.3.4.2"
#define	LDAP_CONTROL_SORTREQUEST	"1.2.840.113556.1.4.473"
#define	LDAP_CONTROL_SORTRESPONSE	"1.2.840.113556.1.4.474"
#define	LDAP_CONTROL_PERSISTENTSEARCH	"2.16.840.1.113730.3.4.3"
#define	LDAP_CONTROL_ENTRYCHANGE	"2.16.840.1.113730.3.4.7"
#define	LDAP_CONTROL_VLVREQUEST		"2.16.840.1.113730.3.4.9"
#define	LDAP_CONTROL_VLVRESPONSE	"2.16.840.1.113730.3.4.10"
#define	LDAP_CONTROL_PROXYAUTH		"2.16.840.1.113730.3.4.12"
	/* version 1 */
#define	LDAP_CONTROL_PROXIEDAUTH	"2.16.840.1.113730.3.4.18"
	/* version 2 */

#ifdef	_SOLARIS_SDK
/*
 * Simple Page control OID
 */
#define	LDAP_CONTROL_SIMPLE_PAGE	"1.2.840.113556.1.4.319"

/*
 * Begin LDAP Display Template Definitions
 */
#define	LDAP_TEMPLATE_VERSION   1

/*
 * general types of items (confined to most significant byte)
 */
#define	LDAP_SYN_TYPE_TEXT		0x01000000L
#define	LDAP_SYN_TYPE_IMAGE		0x02000000L
#define	LDAP_SYN_TYPE_BOOLEAN		0x04000000L
#define	LDAP_SYN_TYPE_BUTTON		0x08000000L
#define	LDAP_SYN_TYPE_ACTION		0x10000000L

/*
 * syntax options (confined to second most significant byte)
 */
#define	LDAP_SYN_OPT_DEFER		0x00010000L

/*
 * display template item syntax ids (defined by common agreement)
 * these are the valid values for the ti_syntaxid of the tmplitem
 * struct (defined below).  A general type is encoded in the
 * most-significant 8 bits, and some options are encoded in the next
 * 8 bits.  The lower 16 bits are reserved for the distinct types.
 */
#define	LDAP_SYN_CASEIGNORESTR  (1 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_MULTILINESTR   (2 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_DN		(3 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_BOOLEAN	(4 | LDAP_SYN_TYPE_BOOLEAN)
#define	LDAP_SYN_JPEGIMAGE	(5 | LDAP_SYN_TYPE_IMAGE)
#define	LDAP_SYN_JPEGBUTTON	(6 | LDAP_SYN_TYPE_BUTTON | LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_FAXIMAGE	(7 | LDAP_SYN_TYPE_IMAGE)
#define	LDAP_SYN_FAXBUTTON	(8 | LDAP_SYN_TYPE_BUTTON | LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_AUDIOBUTTON	(9 | LDAP_SYN_TYPE_BUTTON | LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_TIME		(10 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_DATE		(11 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_LABELEDURL	(12 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_SEARCHACTION	(13 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_LINKACTION	(14 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_ADDDNACTION	(15 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_VERIFYDNACTION	(16 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_RFC822ADDR	(17 | LDAP_SYN_TYPE_TEXT)

/*
 * handy macros
 */
#define	LDAP_GET_SYN_TYPE(syid)		((syid) & 0xFF000000UL)
#define	LDAP_GET_SYN_OPTIONS(syid)	((syid) & 0x00FF0000UL)


/*
 * display options for output routines (used by entry2text and friends)
 */
/*
 * use calculated label width (based on length of longest label in
 * template) instead of contant width
 */
#define	LDAP_DISP_OPT_AUTOLABELWIDTH    0x00000001L
#define	LDAP_DISP_OPT_HTMLBODYONLY	0x00000002L

/*
 * perform search actions (applies to ldap_entry2text_search only)
 */
#define	LDAP_DISP_OPT_DOSEARCHACTIONS   0x00000002L

/*
 * include additional info. relevant to "non leaf" entries only
 * used by ldap_entry2html and ldap_entry2html_search to include "Browse"
 * and "Move Up" HREFs
 */
#define	LDAP_DISP_OPT_NONLEAF		0x00000004L

/*
 * display template item options (may not apply to all types)
 * if this bit is set in ti_options, it applies.
 */
#define	LDAP_DITEM_OPT_READONLY		0x00000001L
#define	LDAP_DITEM_OPT_SORTVALUES	0x00000002L
#define	LDAP_DITEM_OPT_SINGLEVALUED	0x00000004L
#define	LDAP_DITEM_OPT_HIDEIFEMPTY	0x00000008L
#define	LDAP_DITEM_OPT_VALUEREQUIRED	0x00000010L
#define	LDAP_DITEM_OPT_HIDEIFFALSE	0x00000020L	/* booleans only */

#endif	/* _SOLARIS_SDK */

/* Authentication request and response controls */
#define	LDAP_CONTROL_AUTH_REQUEST	"2.16.840.1.113730.3.4.16"
#define	LDAP_CONTROL_AUTH_RESPONSE	"2.16.840.1.113730.3.4.15"

/* Password information sent back to client */
#define	LDAP_CONTROL_PWEXPIRED		"2.16.840.1.113730.3.4.4"
#define	LDAP_CONTROL_PWEXPIRING		"2.16.840.1.113730.3.4.5"


/*
 * Client controls we know about
 */
#define	LDAP_CONTROL_REFERRALS		"1.2.840.113556.1.4.616"


/*
 * LDAP_API macro definition:
 */
#ifndef	LDAP_API
#define	LDAP_API(rt) rt
#endif	/* LDAP_API */

#ifdef	_SOLARIS_SDK
/* Simple Page Control functions for Solaris SDK */
int ldap_create_page_control(LDAP *ld, unsigned int pagesize,
	struct berval *cookie, char isCritical, LDAPControl **output);
int ldap_parse_page_control(LDAP *ld, LDAPControl **controls,
	unsigned int *totalcount, struct berval **cookie);

/* CRAM-MD5 functions */
int ldap_sasl_cram_md5_bind_s(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls);
/* DIGEST-MD5 Function */
int ldap_x_sasl_digest_md5_bind_s(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls);
int ldap_x_sasl_digest_md5_bind(LDAP *ld, char *dn,
	struct berval *cred, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeout,
	LDAPMessage **result);

#endif	/* _SOLARIS_SDK */

LDAP_API(LDAP *) LDAP_CALL ldap_open(const char *host, int port);
LDAP_API(LDAP *) LDAP_CALL ldap_init(const char *defhost, int defport);
int LDAP_CALL ldap_set_option(LDAP *ld, int option,
	const void *optdata);
int LDAP_CALL ldap_get_option(LDAP *ld, int option, void *optdata);
int LDAP_CALL ldap_unbind(LDAP *ld);
int LDAP_CALL ldap_unbind_s(LDAP *ld);

/*
 * perform ldap operations and obtain results
 */
int LDAP_CALL ldap_abandon(LDAP *ld, int msgid);
int LDAP_CALL ldap_add(LDAP *ld, const char *dn, LDAPMod **attrs);
int LDAP_CALL ldap_add_s(LDAP *ld, const char *dn, LDAPMod **attrs);
int LDAP_CALL ldap_simple_bind(LDAP *ld, const char *who,
	const char *passwd);
int LDAP_CALL ldap_simple_bind_s(LDAP *ld, const char *who,
	const char *passwd);
int LDAP_CALL ldap_modify(LDAP *ld, const char *dn, LDAPMod **mods);
int LDAP_CALL ldap_modify_s(LDAP *ld, const char *dn,
	LDAPMod **mods);
int LDAP_CALL ldap_modrdn(LDAP *ld, const char *dn,
	const char *newrdn);
int LDAP_CALL ldap_modrdn_s(LDAP *ld, const char *dn,
	const char *newrdn);

/* The following 2 functions are deprecated */
int LDAP_CALL ldap_modrdn2(LDAP *ld, const char *dn,
	const char *newrdn, int deleteoldrdn);
int LDAP_CALL ldap_modrdn2_s(LDAP *ld, const char *dn,
	const char *newrdn, int deleteoldrdn);

int LDAP_CALL ldap_compare(LDAP *ld, const char *dn,
	const char *attr, const char *value);
int LDAP_CALL ldap_compare_s(LDAP *ld, const char *dn,
	const char *attr, const char *value);
int LDAP_CALL ldap_delete(LDAP *ld, const char *dn);
int LDAP_CALL ldap_delete_s(LDAP *ld, const char *dn);
int LDAP_CALL ldap_search(LDAP *ld, const char *base, int scope,
	const char *filter, char **attrs, int attrsonly);
int LDAP_CALL ldap_search_s(LDAP *ld, const char *base, int scope,
	const char *filter, char **attrs, int attrsonly, LDAPMessage **res);
int LDAP_CALL ldap_search_st(LDAP *ld, const char *base, int scope,
	const char *filter, char **attrs, int attrsonly,
	struct timeval *timeout, LDAPMessage **res);
int LDAP_CALL ldap_result(LDAP *ld, int msgid, int all,
	struct timeval *timeout, LDAPMessage **result);
int LDAP_CALL ldap_msgfree(LDAPMessage *lm);
int LDAP_CALL ldap_msgid(LDAPMessage *lm);
int LDAP_CALL ldap_msgtype(LDAPMessage *lm);


/*
 * Routines to parse/deal with results and errors returned
 */
int LDAP_CALL ldap_result2error(LDAP *ld, LDAPMessage *r,
	int freeit);
char *LDAP_CALL ldap_err2string(int err);
LDAP_API(void) LDAP_CALL ldap_perror(LDAP *ld, const char *s);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_first_entry(LDAP *ld,
    LDAPMessage *chain);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_next_entry(LDAP *ld,
    LDAPMessage *entry);
int LDAP_CALL ldap_count_entries(LDAP *ld, LDAPMessage *chain);
char *LDAP_CALL ldap_get_dn(LDAP *ld, LDAPMessage *entry);
char *LDAP_CALL ldap_dn2ufn(const char *dn);
char **LDAP_CALL ldap_explode_dn(const char *dn,
	const int notypes);
char **LDAP_CALL ldap_explode_rdn(const char *rdn,
	const int notypes);
char *LDAP_CALL ldap_first_attribute(LDAP *ld, LDAPMessage *entry,
	BerElement **ber);
char *LDAP_CALL ldap_next_attribute(LDAP *ld, LDAPMessage *entry,
	BerElement *ber);

/* The following function is deprecated */
LDAP_API(void) LDAP_CALL ldap_ber_free(BerElement *ber, int freebuf);

char **LDAP_CALL ldap_get_values(LDAP *ld, LDAPMessage *entry,
	const char *target);
struct berval **LDAP_CALL ldap_get_values_len(LDAP *ld,
	LDAPMessage *entry, const char *target);
int LDAP_CALL ldap_count_values(char **vals);
int LDAP_CALL ldap_count_values_len(struct berval **vals);
LDAP_API(void) LDAP_CALL ldap_value_free(char **vals);
LDAP_API(void) LDAP_CALL ldap_value_free_len(struct berval **vals);
LDAP_API(void) LDAP_CALL ldap_memfree(void *p);


/*
 * LDAPv3 extended operation calls
 */
/*
 * Note: all of the new asynchronous calls return an LDAP error code,
 * not a message id.  A message id is returned via the int *msgidp
 * parameter (usually the last parameter) if appropriate.
 */
int LDAP_CALL ldap_abandon_ext(LDAP *ld, int msgid,
	LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_add_ext(LDAP *ld, const char *dn, LDAPMod **attrs,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_add_ext_s(LDAP *ld, const char *dn,
	LDAPMod **attrs, LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_sasl_bind(LDAP *ld, const char *dn,
	const char *mechanism, const struct berval *cred,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_sasl_bind_s(LDAP *ld, const char *dn,
	const char *mechanism, const struct berval *cred,
	LDAPControl **serverctrls, LDAPControl **clientctrls,
	struct berval **servercredp);
int LDAP_CALL ldap_modify_ext(LDAP *ld, const char *dn,
	LDAPMod **mods, LDAPControl **serverctrls, LDAPControl **clientctrls,
	int *msgidp);
int LDAP_CALL ldap_modify_ext_s(LDAP *ld, const char *dn,
	LDAPMod **mods, LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_rename(LDAP *ld, const char *dn,
	const char *newrdn, const char *newparent, int deleteoldrdn,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_rename_s(LDAP *ld, const char *dn,
	const char *newrdn, const char *newparent, int deleteoldrdn,
	LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_compare_ext(LDAP *ld, const char *dn,
	const char *attr, const struct berval *bvalue,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_compare_ext_s(LDAP *ld, const char *dn,
	const char *attr, const struct berval *bvalue,
	LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_delete_ext(LDAP *ld, const char *dn,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_delete_ext_s(LDAP *ld, const char *dn,
	LDAPControl **serverctrls, LDAPControl **clientctrls);
int LDAP_CALL ldap_search_ext(LDAP *ld, const char *base,
	int scope, const char *filter, char **attrs, int attrsonly,
	LDAPControl **serverctrls, LDAPControl **clientctrls,
	struct timeval *timeoutp, int sizelimit, int *msgidp);
int LDAP_CALL ldap_search_ext_s(LDAP *ld, const char *base,
	int scope, const char *filter, char **attrs, int attrsonly,
	LDAPControl **serverctrls, LDAPControl **clientctrls,
	struct timeval *timeoutp, int sizelimit, LDAPMessage **res);
int LDAP_CALL ldap_extended_operation(LDAP *ld,
	const char *requestoid, const struct berval *requestdata,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int LDAP_CALL ldap_extended_operation_s(LDAP *ld,
	const char *requestoid, const struct berval *requestdata,
	LDAPControl **serverctrls, LDAPControl **clientctrls,
	char **retoidp, struct berval **retdatap);
int LDAP_CALL ldap_unbind_ext(LDAP *ld, LDAPControl **serverctrls,
	LDAPControl **clientctrls);


/*
 * LDAPv3 extended parsing / result handling calls
 */
int LDAP_CALL ldap_parse_sasl_bind_result(LDAP *ld,
	LDAPMessage *res, struct berval **servercredp, int freeit);
int LDAP_CALL ldap_parse_result(LDAP *ld, LDAPMessage *res,
	int *errcodep, char **matcheddnp, char **errmsgp, char ***referralsp,
	LDAPControl ***serverctrlsp, int freeit);
int LDAP_CALL ldap_parse_extended_result(LDAP *ld, LDAPMessage *res,
	char **retoidp, struct berval **retdatap, int freeit);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_first_message(LDAP *ld,
    LDAPMessage *res);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_next_message(LDAP *ld,
    LDAPMessage *msg);
int LDAP_CALL ldap_count_messages(LDAP *ld, LDAPMessage *res);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_first_reference(LDAP *ld,
    LDAPMessage *res);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_next_reference(LDAP *ld,
    LDAPMessage *ref);
int LDAP_CALL ldap_count_references(LDAP *ld, LDAPMessage *res);
int LDAP_CALL ldap_parse_reference(LDAP *ld, LDAPMessage *ref,
	char ***referralsp, LDAPControl ***serverctrlsp, int freeit);
int LDAP_CALL ldap_get_entry_controls(LDAP *ld, LDAPMessage *entry,
	LDAPControl ***serverctrlsp);
LDAP_API(void) LDAP_CALL ldap_control_free(LDAPControl *ctrl);
LDAP_API(void) LDAP_CALL ldap_controls_free(LDAPControl **ctrls);

#ifdef  _SOLARIS_SDK
char ** ldap_get_reference_urls(LDAP *ld, LDAPMessage *res);
#endif

LDAP_API(void) LDAP_CALL ldap_add_result_entry(
	LDAPMessage **list, LDAPMessage *e);
LDAP_API(LDAPMessage *) LDAP_CALL ldap_delete_result_entry(
	LDAPMessage **list, LDAPMessage *e);


/* End of core standard C LDAP API definitions */

/*
 * Server side sorting of search results (an LDAPv3 extension --
 * LDAP_API_FEATURE_SERVER_SIDE_SORT)
 */
typedef struct LDAPsortkey {	/* structure for a sort-key */
	char *sk_attrtype;
	char *sk_matchruleoid;
	int	sk_reverseorder;
} LDAPsortkey;

int LDAP_CALL ldap_create_sort_control(LDAP *ld,
	LDAPsortkey **sortKeyList, const char ctl_iscritical,
	LDAPControl **ctrlp);
int LDAP_CALL ldap_parse_sort_control(LDAP *ld,
	LDAPControl **ctrls, unsigned long *result, char **attribute);

LDAP_API(void) LDAP_CALL ldap_free_sort_keylist(LDAPsortkey **sortKeyList);
int LDAP_CALL ldap_create_sort_keylist(LDAPsortkey ***sortKeyList,
	const char *string_rep);


/*
 * Virtual list view (an LDAPv3 extension -- LDAP_API_FEATURE_VIRTUAL_LIST_VIEW)
 */
/*
 * structure that describes a VirtualListViewRequest control.
 * note that ldvlist_index and ldvlist_size are only relevant to
 * ldap_create_virtuallist_control() if ldvlist_attrvalue is NULL.
 */
typedef struct ldapvirtuallist {
    unsigned long	ldvlist_before_count;	/* # entries before target */
    unsigned long   ldvlist_after_count;	/* # entries after target */
    char	    *ldvlist_attrvalue;		/* jump to this value */
    unsigned long   ldvlist_index;		/* list offset */
    unsigned long   ldvlist_size;		/* number of items in vlist */
    void	*ldvlist_extradata;		/* for use by application */
} LDAPVirtualList;

/*
 * VLV functions:
 */
int LDAP_CALL ldap_create_virtuallist_control(LDAP *ld,
	LDAPVirtualList *ldvlistp, LDAPControl **ctrlp);

int LDAP_CALL ldap_parse_virtuallist_control(LDAP *ld,
	LDAPControl **ctrls, unsigned long *target_posp,
	unsigned long *list_sizep, int *errcodep);


/*
 * Routines for creating persistent search controls and for handling
 * "entry changed notification" controls (an LDAPv3 extension --
 * LDAP_API_FEATURE_PERSISTENT_SEARCH)
 */
#define	LDAP_CHANGETYPE_ADD		1
#define	LDAP_CHANGETYPE_DELETE		2
#define	LDAP_CHANGETYPE_MODIFY		4
#define	LDAP_CHANGETYPE_MODDN		8
#define	LDAP_CHANGETYPE_ANY		(1|2|4|8)
int LDAP_CALL ldap_create_persistentsearch_control(LDAP *ld,
	int changetypes, int changesonly, int return_echg_ctls,
	char ctl_iscritical, LDAPControl **ctrlp);
int LDAP_CALL ldap_parse_entrychange_control(LDAP *ld,
	LDAPControl **ctrls, int *chgtypep, char **prevdnp,
	int *chgnumpresentp, ber_int_t *chgnump);


/*
 * Routines for creating Proxied Authorization controls (an LDAPv3
 * extension -- LDAP_API_FEATURE_PROXY_AUTHORIZATION)
 * ldap_create_proxyauth_control() is for the old (version 1) control.
 * ldap_create_proxiedauth_control() is for the newer (version 2) control.
 * Version 1 is supported by iPlanet Directory Server 4.1 and later.
 * Version 2 is supported by iPlanet Directory Server 5.0 and later.
 */
int LDAP_CALL ldap_create_proxyauth_control(LDAP *ld,
	const char *dn, const char ctl_iscritical, LDAPControl **ctrlp);
int LDAP_CALL ldap_create_proxiedauth_control(LDAP *ld,
	const char *authzid, LDAPControl **ctrlp);


/*
 * Functions to get and set LDAP error information (API extension --
 * LDAP_API_FEATURE_X_LDERRNO )
 */
int LDAP_CALL ldap_get_lderrno(LDAP *ld, char **m, char **s);
int LDAP_CALL ldap_set_lderrno(LDAP *ld, int e, char *m, char *s);


/*
 * LDAP URL functions and definitions (an API extension --
 * LDAP_API_FEATURE_X_URL_FUNCTIONS)
 */
/*
 * types for ldap URL handling
 */
typedef struct ldap_url_desc {
    char		*lud_host;
    int			lud_port;
    char		*lud_dn;
    char		**lud_attrs;
    int			lud_scope;
    char		*lud_filter;
    unsigned long	lud_options;
#define	LDAP_URL_OPT_SECURE	0x01
    char	*lud_string;    /* for internal use only */
} LDAPURLDesc;

#define	NULLLDAPURLDESC ((LDAPURLDesc *)NULL)

/*
 * possible errors returned by ldap_url_parse()
 */
#define	LDAP_URL_ERR_NOTLDAP	1	/* URL doesn't begin with "ldap://" */
#define	LDAP_URL_ERR_NODN	2	/* URL has no DN (required) */
#define	LDAP_URL_ERR_BADSCOPE	3	/* URL scope string is invalid */
#define	LDAP_URL_ERR_MEM	4	/* can't allocate memory space */
#define	LDAP_URL_ERR_PARAM	5	/* bad parameter to an URL function */
#define	LDAP_URL_ERR_HOSTPORT	6	/* URL hostcode is invalid */

/*
 * URL functions:
 */
int LDAP_CALL ldap_is_ldap_url(const char *url);
int LDAP_CALL ldap_url_parse(const char *url, LDAPURLDesc **ludpp);
int LDAP_CALL ldap_url_parse_nodn(const char *url, LDAPURLDesc **ludpp);
LDAP_API(void) LDAP_CALL ldap_free_urldesc(LDAPURLDesc *ludp);
int LDAP_CALL ldap_url_search(LDAP *ld, const char *url,
	int attrsonly);
int LDAP_CALL ldap_url_search_s(LDAP *ld, const char *url,
	int attrsonly, LDAPMessage **res);
int LDAP_CALL ldap_url_search_st(LDAP *ld, const char *url,
	int attrsonly, struct timeval *timeout, LDAPMessage **res);

#ifdef	_SOLARIS_SDK
/*
 * Additional URL functions plus Character set, Search Preference
 * and Display Template functions moved from internal header files
 */

/*
 * URL functions
 */
char *ldap_dns_to_url(LDAP *ld, char *dns_name, char *attrs,
	char *scope, char *filter);
char *ldap_dn_to_url(LDAP *ld, char *dn, int nameparts);

/*
 * Character set functions
 */
#ifdef	STR_TRANSLATION
void ldap_set_string_translators(LDAP *ld,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc);
int ldap_translate_from_t61(LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input);
int ldap_translate_to_t61(LDAP *ld, char **bufp,
	unsigned long *lenp, int free_input);
void ldap_enable_translation(LDAP *ld, LDAPMessage *entry,
	int enable);
#ifdef	LDAP_CHARSET_8859
int ldap_t61_to_8859(char **bufp, unsigned long *buflenp,
	int free_input);
int ldap_8859_to_t61(char **bufp, unsigned long *buflenp,
	int free_input);
#endif	/* LDAP_CHARSET_8859 */
#endif	/* STR_TRANSLATION */

/*
 * Display Temple functions/structures
 */
/*
 * display template item structure
 */
struct ldap_tmplitem {
    unsigned long		ti_syntaxid;
    unsigned long		ti_options;
    char			*ti_attrname;
    char			*ti_label;
    char			**ti_args;
    struct ldap_tmplitem	*ti_next_in_row;
    struct ldap_tmplitem	*ti_next_in_col;
    void			*ti_appdata;
};

#define	NULLTMPLITEM	((struct ldap_tmplitem *)0)

#define	LDAP_SET_TMPLITEM_APPDATA(ti, datap)  \
	(ti)->ti_appdata = (void *)(datap)

#define	LDAP_GET_TMPLITEM_APPDATA(ti, type)   \
	(type)((ti)->ti_appdata)

#define	LDAP_IS_TMPLITEM_OPTION_SET(ti, option)       \
	(((ti)->ti_options & option) != 0)

/*
 * object class array structure
 */
struct ldap_oclist {
    char		**oc_objclasses;
    struct ldap_oclist	*oc_next;
};

#define	NULLOCLIST	((struct ldap_oclist *)0)


/*
 * add defaults list
 */
struct ldap_adddeflist {
    int			ad_source;
#define	LDAP_ADSRC_CONSTANTVALUE	1
#define	LDAP_ADSRC_ADDERSDN		2
    char		*ad_attrname;
    char		*ad_value;
    struct ldap_adddeflist	*ad_next;
};

#define	NULLADLIST	((struct ldap_adddeflist *)0)


/*
 * display template global options
 * if this bit is set in dt_options, it applies.
 */
/*
 * users should be allowed to try to add objects of these entries
 */
#define	LDAP_DTMPL_OPT_ADDABLE		0x00000001L

/*
 * users should be allowed to do "modify RDN" operation of these entries
 */
#define	LDAP_DTMPL_OPT_ALLOWMODRDN	0x00000002L

/*
 * this template is an alternate view, not a primary view
 */
#define	LDAP_DTMPL_OPT_ALTVIEW	0x00000004L


/*
 * display template structure
 */
struct ldap_disptmpl {
    char			*dt_name;
    char			*dt_pluralname;
    char			*dt_iconname;
    unsigned long		dt_options;
    char			*dt_authattrname;
    char			*dt_defrdnattrname;
    char			*dt_defaddlocation;
    struct ldap_oclist		*dt_oclist;
    struct ldap_adddeflist	*dt_adddeflist;
    struct ldap_tmplitem	*dt_items;
    void			*dt_appdata;
    struct ldap_disptmpl	*dt_next;
};

#define	NULLDISPTMPL	((struct ldap_disptmpl *)0)

#define	LDAP_SET_DISPTMPL_APPDATA(dt, datap)  \
	(dt)->dt_appdata = (void *)(datap)

#define	LDAP_GET_DISPTMPL_APPDATA(dt, type)   \
	(type)((dt)->dt_appdata)

#define	LDAP_IS_DISPTMPL_OPTION_SET(dt, option)       \
	(((dt)->dt_options & option) != 0)

#define	LDAP_TMPL_ERR_VERSION   1
#define	LDAP_TMPL_ERR_MEM	2
#define	LDAP_TMPL_ERR_SYNTAX    3
#define	LDAP_TMPL_ERR_FILE	4

/*
 * buffer size needed for entry2text and vals2text
 */
#define	LDAP_DTMPL_BUFSIZ	8192

typedef int (*writeptype)(void *writeparm, char *p, int len);

LDAP_API(int) LDAP_CALL ldap_init_templates(char *file,
    struct ldap_disptmpl **tmpllistp);

LDAP_API(int) LDAP_CALL ldap_init_templates_buf(char *buf, long buflen,
    struct ldap_disptmpl **tmpllistp);

LDAP_API(void) LDAP_CALL ldap_free_templates(struct ldap_disptmpl *tmpllist);

LDAP_API(struct ldap_disptmpl *) LDAP_CALL ldap_first_disptmpl(
    struct ldap_disptmpl *tmpllist);

LDAP_API(struct ldap_disptmpl *) LDAP_CALL ldap_next_disptmpl(
    struct ldap_disptmpl *tmpllist,
    struct ldap_disptmpl *tmpl);

LDAP_API(struct ldap_disptmpl *) LDAP_CALL ldap_name2template(char *name,
    struct ldap_disptmpl *tmpllist);

LDAP_API(struct ldap_disptmpl *) LDAP_CALL ldap_oc2template(char **oclist,
    struct ldap_disptmpl *tmpllist);

LDAP_API(char **) LDAP_CALL ldap_tmplattrs(struct ldap_disptmpl *tmpl,
    char **includeattrs, int exclude,
    unsigned long syntaxmask);

LDAP_API(struct ldap_tmplitem *) LDAP_CALL ldap_first_tmplrow(
    struct ldap_disptmpl *tmpl);

LDAP_API(struct ldap_tmplitem *) LDAP_CALL ldap_next_tmplrow(
    struct ldap_disptmpl *tmpl, struct ldap_tmplitem *row);

LDAP_API(struct ldap_tmplitem *) LDAP_CALL ldap_first_tmplcol(
    struct ldap_disptmpl *tmpl, struct ldap_tmplitem *row);

LDAP_API(struct ldap_tmplitem *) LDAP_CALL ldap_next_tmplcol(
    struct ldap_disptmpl *tmpl, struct ldap_tmplitem *row,
    struct ldap_tmplitem *col);

LDAP_API(int) LDAP_CALL ldap_entry2text(LDAP *ld, char *buf, LDAPMessage *entry,
    struct ldap_disptmpl *tmpl, char **defattrs, char ***defvals,
    writeptype writeproc, void *writeparm, char *eol, int rdncount,
    unsigned long opts);

LDAP_API(int) LDAP_CALL ldap_vals2text(LDAP *ld, char *buf, char **vals,
    char *label, int labelwidth,
    unsigned long syntaxid, writeptype writeproc, void *writeparm,
    char *eol, int rdncount);

LDAP_API(int) LDAP_CALL ldap_entry2text_search(LDAP *ld, char *dn, char *base,
    LDAPMessage *entry,
    struct ldap_disptmpl *tmpllist, char **defattrs, char ***defvals,
    writeptype writeproc, void *writeparm, char *eol, int rdncount,
    unsigned long opts);

LDAP_API(int) LDAP_CALL ldap_entry2html(LDAP *ld, char *buf, LDAPMessage *entry,
    struct ldap_disptmpl *tmpl, char **defattrs, char ***defvals,
    writeptype writeproc, void *writeparm, char *eol, int rdncount,
    unsigned long opts, char *urlprefix, char *base);

LDAP_API(int) LDAP_CALL ldap_vals2html(LDAP *ld, char *buf, char **vals,
    char *label, int labelwidth,
    unsigned long syntaxid, writeptype writeproc, void *writeparm,
    char *eol, int rdncount, char *urlprefix);

LDAP_API(int) LDAP_CALL ldap_entry2html_search(LDAP *ld, char *dn, char *base,
    LDAPMessage *entry,
    struct ldap_disptmpl *tmpllist, char **defattrs, char ***defvals,
    writeptype writeproc, void *writeparm, char *eol, int rdncount,
    unsigned long opts, char *urlprefix);

/*
 * Search Preference Definitions
 */

struct ldap_searchattr {
	char				*sa_attrlabel;
	char				*sa_attr;
					/* max 32 matchtypes for now */
	unsigned long			sa_matchtypebitmap;
	char				*sa_selectattr;
	char				*sa_selecttext;
	struct ldap_searchattr		*sa_next;
};

struct ldap_searchmatch {
	char				*sm_matchprompt;
	char				*sm_filter;
	struct ldap_searchmatch		*sm_next;
};

struct ldap_searchobj {
	char				*so_objtypeprompt;
	unsigned long			so_options;
	char				*so_prompt;
	short				so_defaultscope;
	char				*so_filterprefix;
	char				*so_filtertag;
	char				*so_defaultselectattr;
	char				*so_defaultselecttext;
	struct ldap_searchattr		*so_salist;
	struct ldap_searchmatch		*so_smlist;
	struct ldap_searchobj		*so_next;
};

#define	NULLSEARCHOBJ			((struct ldap_searchobj *)0)

/*
 * global search object options
 */
#define	LDAP_SEARCHOBJ_OPT_INTERNAL	0x00000001

#define	LDAP_IS_SEARCHOBJ_OPTION_SET(so, option)      \
	(((so)->so_options & option) != 0)

#define	LDAP_SEARCHPREF_VERSION_ZERO    0
#define	LDAP_SEARCHPREF_VERSION		1

#define	LDAP_SEARCHPREF_ERR_VERSION	1
#define	LDAP_SEARCHPREF_ERR_MEM		2
#define	LDAP_SEARCHPREF_ERR_SYNTAX	3
#define	LDAP_SEARCHPREF_ERR_FILE	4

LDAP_API(int) LDAP_CALL ldap_init_searchprefs(char *file,
    struct ldap_searchobj **solistp);

LDAP_API(int) LDAP_CALL ldap_init_searchprefs_buf(char *buf, long buflen,
    struct ldap_searchobj **solistp);

LDAP_API(void) LDAP_CALL ldap_free_searchprefs(struct ldap_searchobj *solist);

LDAP_API(struct ldap_searchobj *) LDAP_CALL ldap_first_searchobj(
    struct ldap_searchobj *solist);

LDAP_API(struct ldap_searchobj *) LDAP_CALL ldap_next_searchobj(
    struct ldap_searchobj *sollist, struct ldap_searchobj *so);

/*
 * specific LDAP instantiations of BER types we know about
 */

/* general stuff */
#define	LDAP_TAG_MESSAGE	0x30   /* tag is 16 + constructed bit */
#define	LDAP_TAG_MSGID		0x02   /* INTEGER */
#define	LDAP_TAG_CONTROLS	0xa0   /* context specific + constructed + 0 */
#define	LDAP_TAG_REFERRAL	0xa3   /* context specific + constructed + 3 */
#define	LDAP_TAG_NEWSUPERIOR    0x80   /* context specific + primitive + 0 */
#define	LDAP_TAG_SASL_RES_CREDS 0x87   /* context specific + primitive + 7 */
#define	LDAP_TAG_VLV_BY_INDEX   0xa0   /* context specific + constructed + 0 */
#define	LDAP_TAG_VLV_BY_VALUE   0x81   /* context specific + primitive + 1 */
/* tag for sort control */
#define	LDAP_TAG_SK_MATCHRULE   0x80L   /* context specific + primitive + 0 */
#define	LDAP_TAG_SK_REVERSE	0x81L   /* context specific + primitive + 1 */
#define	LDAP_TAG_SR_ATTRTYPE    0x80L   /* context specific + primitive + 0 */

/* possible operations a client can invoke */
#define	LDAP_REQ_BIND	0x60   /* application + constructed + 0 */
#define	LDAP_REQ_UNBIND		0x42   /* application + primitive   + 2 */
#define	LDAP_REQ_SEARCH		0x63   /* application + constructed + 3 */
#define	LDAP_REQ_MODIFY		0x66   /* application + constructed + 6 */
#define	LDAP_REQ_ADD		0x68   /* application + constructed + 8 */
#define	LDAP_REQ_DELETE		0x4a   /* application + primitive   + 10 */
#define	LDAP_REQ_MODRDN		0x6c   /* application + constructed + 12 */
#define	LDAP_REQ_MODDN		0x6c   /* application + constructed + 12 */
#define	LDAP_REQ_RENAME		0x6c   /* application + constructed + 12 */
#define	LDAP_REQ_COMPARE	0x6e   /* application + constructed + 14 */
#define	LDAP_REQ_ABANDON	0x50   /* application + primitive   + 16 */
#define	LDAP_REQ_EXTENDED	0x77   /* application + constructed + 23 */

/* U-M LDAP release 3.0 compatibility stuff */
#define	LDAP_REQ_UNBIND_30	0x62
#define	LDAP_REQ_DELETE_30	0x6a
#define	LDAP_REQ_ABANDON_30	0x70

/* U-M LDAP 3.0 compatibility auth methods */
#define	LDAP_AUTH_SIMPLE_30	0xa0   /* context specific + constructed */
#define	LDAP_AUTH_KRBV41_30	0xa1   /* context specific + constructed */
#define	LDAP_AUTH_KRBV42_30	0xa2   /* context specific + constructed */

/* filter types */
#define	LDAP_FILTER_AND		0xa0   /* context specific + constructed + 0 */
#define	LDAP_FILTER_OR		0xa1   /* context specific + constructed + 1 */
#define	LDAP_FILTER_NOT		0xa2   /* context specific + constructed + 2 */
#define	LDAP_FILTER_EQUALITY	0xa3   /* context specific + constructed + 3 */
#define	LDAP_FILTER_SUBSTRINGS	0xa4   /* context specific + constructed + 4 */
#define	LDAP_FILTER_GE		0xa5   /* context specific + constructed + 5 */
#define	LDAP_FILTER_LE		0xa6   /* context specific + constructed + 6 */
#define	LDAP_FILTER_PRESENT	0x87   /* context specific + primitive   + 7 */
#define	LDAP_FILTER_APPROX	0xa8   /* context specific + constructed + 8 */
#define	LDAP_FILTER_EXTENDED	0xa9   /* context specific + constructed + 0 */

/* U-M LDAP 3.0 compatibility filter types */
#define	LDAP_FILTER_PRESENT_30	0xa7   /* context specific + constructed */

/* substring filter component types */
#define	LDAP_SUBSTRING_INITIAL	0x80   /* context specific + primitive + 0 */
#define	LDAP_SUBSTRING_ANY	0x81   /* context specific + primitive + 1 */
#define	LDAP_SUBSTRING_FINAL    0x82   /* context specific + primitive + 2 */

/* U-M LDAP 3.0 compatibility substring filter component types */
#define	LDAP_SUBSTRING_INITIAL_30	0xa0   /* context specific */
#define	LDAP_SUBSTRING_ANY_30		0xa1   /* context specific */
#define	LDAP_SUBSTRING_FINAL_30		0xa2   /* context specific */

#endif	/* _SOLARIS_SDK */

/*
 * Function to dispose of an array of LDAPMod structures (an API extension).
 * Warning: don't use this unless the mods array was allocated using the
 * same memory allocator as is being used by libldap.
 */
LDAP_API(void) LDAP_CALL ldap_mods_free(LDAPMod **mods, int freemods);

/*
 * Preferred language and get_lang_values (an API extension --
 * LDAP_API_FEATURE_X_GETLANGVALUES)
 *
 * The following two APIs are deprecated
 */

char **LDAP_CALL ldap_get_lang_values(LDAP *ld, LDAPMessage *entry,
	const char *target, char **type);
struct berval **LDAP_CALL ldap_get_lang_values_len(LDAP *ld,
	LDAPMessage *entry, const char *target, char **type);


/*
 * Rebind callback function (an API extension)
 */
#define	LDAP_OPT_REBIND_FN		0x06	/* 6 - API extension */
#define	LDAP_OPT_REBIND_ARG		0x07	/* 7 - API extension */
typedef int (LDAP_CALL LDAP_CALLBACK LDAP_REBINDPROC_CALLBACK)(LDAP *ld,
	char **dnp, char **passwdp, int *authmethodp, int freeit, void *arg);
LDAP_API(void) LDAP_CALL ldap_set_rebind_proc(LDAP *ld,
    LDAP_REBINDPROC_CALLBACK *rebindproc, void *arg);

/*
 * Thread function callbacks (an API extension --
 * LDAP_API_FEATURE_X_THREAD_FUNCTIONS).
 */
#define	LDAP_OPT_THREAD_FN_PTRS		0x05	/* 5 - API extension */

/*
 * Thread callback functions:
 */
typedef void *(LDAP_C LDAP_CALLBACK LDAP_TF_MUTEX_ALLOC_CALLBACK)(void);
typedef void (LDAP_C LDAP_CALLBACK LDAP_TF_MUTEX_FREE_CALLBACK)(void *m);
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_MUTEX_LOCK_CALLBACK)(void *m);
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_MUTEX_UNLOCK_CALLBACK)(void *m);
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_GET_ERRNO_CALLBACK)(void);
typedef void (LDAP_C LDAP_CALLBACK LDAP_TF_SET_ERRNO_CALLBACK)(int e);
typedef int (LDAP_C LDAP_CALLBACK LDAP_TF_GET_LDERRNO_CALLBACK)(
	char **matchedp, char **errmsgp, void *arg);
typedef void    (LDAP_C LDAP_CALLBACK LDAP_TF_SET_LDERRNO_CALLBACK)(int err,
	char *matched, char *errmsg, void *arg);

/*
 * Structure to hold thread function pointers:
 */
struct ldap_thread_fns {
	LDAP_TF_MUTEX_ALLOC_CALLBACK *ltf_mutex_alloc;
	LDAP_TF_MUTEX_FREE_CALLBACK *ltf_mutex_free;
	LDAP_TF_MUTEX_LOCK_CALLBACK *ltf_mutex_lock;
	LDAP_TF_MUTEX_UNLOCK_CALLBACK *ltf_mutex_unlock;
	LDAP_TF_GET_ERRNO_CALLBACK *ltf_get_errno;
	LDAP_TF_SET_ERRNO_CALLBACK *ltf_set_errno;
	LDAP_TF_GET_LDERRNO_CALLBACK *ltf_get_lderrno;
	LDAP_TF_SET_LDERRNO_CALLBACK *ltf_set_lderrno;
	void    *ltf_lderrno_arg;
};

/*
 * Client side sorting of entries (an API extension --
 * LDAP_API_FEATURE_X_CLIENT_SIDE_SORT)
 */
/*
 * Client side sorting callback functions:
 */
typedef const struct berval *(LDAP_C LDAP_CALLBACK
	LDAP_KEYGEN_CALLBACK)(void *arg, LDAP *ld, LDAPMessage *entry);
typedef int (LDAP_C LDAP_CALLBACK
	LDAP_KEYCMP_CALLBACK)(void *arg, const struct berval *,
	const struct berval *);
typedef void (LDAP_C LDAP_CALLBACK
	LDAP_KEYFREE_CALLBACK)(void *arg, const struct berval *);
typedef int (LDAP_C LDAP_CALLBACK
	LDAP_CMP_CALLBACK)(const char *val1, const char *val2);
typedef int (LDAP_C LDAP_CALLBACK
	LDAP_VALCMP_CALLBACK)(const char **val1p, const char **val2p);

/*
 * Client side sorting functions:
 */
int LDAP_CALL ldap_multisort_entries(LDAP *ld, LDAPMessage **chain,
	char **attr, LDAP_CMP_CALLBACK *cmp);
int LDAP_CALL ldap_sort_entries(LDAP *ld, LDAPMessage **chain,
	char *attr, LDAP_CMP_CALLBACK *cmp);
int LDAP_CALL ldap_sort_values(LDAP *ld, char **vals,
	LDAP_VALCMP_CALLBACK *cmp);
int LDAP_C LDAP_CALLBACK ldap_sort_strcasecmp(const char **a,
	const char **b);


/*
 * Filter functions and definitions (an API extension --
 * LDAP_API_FEATURE_X_FILTER_FUNCTIONS)
 */
/*
 * Structures, constants, and types for filter utility routines:
 */
typedef struct ldap_filt_info {
	char			*lfi_filter;
	char			*lfi_desc;
	int			lfi_scope;	/* LDAP_SCOPE_BASE, etc */
	int			lfi_isexact;    /* exact match filter? */
	struct ldap_filt_info   *lfi_next;
} LDAPFiltInfo;

#define	LDAP_FILT_MAXSIZ	1024

typedef struct ldap_filt_list LDAPFiltList; /* opaque filter list handle */
typedef struct ldap_filt_desc LDAPFiltDesc; /* opaque filter desc handle */

/*
 * Filter utility functions:
 */
LDAP_API(LDAPFiltDesc *) LDAP_CALL ldap_init_getfilter(char *fname);
LDAP_API(LDAPFiltDesc *) LDAP_CALL ldap_init_getfilter_buf(char *buf,
    ssize_t buflen);
LDAP_API(LDAPFiltInfo *) LDAP_CALL ldap_getfirstfilter(LDAPFiltDesc *lfdp,
    char *tagpat, char *value);
LDAP_API(LDAPFiltInfo *) LDAP_CALL ldap_getnextfilter(LDAPFiltDesc *lfdp);
int LDAP_CALL ldap_set_filter_additions(LDAPFiltDesc *lfdp,
	char *prefix, char *suffix);
int LDAP_CALL ldap_create_filter(char *buf, unsigned long buflen,
	char *pattern, char *prefix, char *suffix, char *attr,
	char *value, char **valwords);
LDAP_API(void) LDAP_CALL ldap_getfilter_free(LDAPFiltDesc *lfdp);


/*
 * Friendly mapping structure and routines (an API extension)
 */
typedef struct friendly {
	char    *f_unfriendly;
	char    *f_friendly;
} *FriendlyMap;
char *LDAP_CALL ldap_friendly_name(char *filename, char *name,
	FriendlyMap *map);
LDAP_API(void) LDAP_CALL ldap_free_friendlymap(FriendlyMap *map);


/*
 * In Memory Cache (an API extension -- LDAP_API_FEATURE_X_MEMCACHE)
 */
typedef struct ldapmemcache  LDAPMemCache;  /* opaque in-memory cache handle */

int LDAP_CALL ldap_memcache_init(unsigned long ttl,
	unsigned long size, char **baseDNs, struct ldap_thread_fns *thread_fns,
	LDAPMemCache **cachep);
int LDAP_CALL ldap_memcache_set(LDAP *ld, LDAPMemCache *cache);
int LDAP_CALL ldap_memcache_get(LDAP *ld, LDAPMemCache **cachep);
LDAP_API(void) LDAP_CALL ldap_memcache_flush(LDAPMemCache *cache, char *dn,
    int scope);
LDAP_API(void) LDAP_CALL ldap_memcache_destroy(LDAPMemCache *cache);
LDAP_API(void) LDAP_CALL ldap_memcache_update(LDAPMemCache *cache);

/*
 * Server reconnect (an API extension).
 */
#define	LDAP_OPT_RECONNECT		0x62    /* 98 - API extension */

/*
 * Asynchronous I/O (an API extension).
 */
/*
 * This option enables completely asynchronous IO.  It works by using ioctl()
 * on the fd, (or tlook())
 */
#define	LDAP_OPT_ASYNC_CONNECT		0x63    /* 99 - API extension */

/*
 * I/O function callbacks option (an API extension --
 * LDAP_API_FEATURE_X_IO_FUNCTIONS).
 * Use of the extended I/O functions instead is recommended; see above.
 */
#define	LDAP_OPT_IO_FN_PTRS		0x0B    /* 11 - API extension */

/*
 * Extended I/O function callbacks option (an API extension --
 * LDAP_API_FEATURE_X_EXTIO_FUNCTIONS).
 */
#define	LDAP_X_OPT_EXTIO_FN_PTRS   (LDAP_OPT_PRIVATE_EXTENSION_BASE + 0x0F00)
	/* 0x4000 + 0x0F00 = 0x4F00 = 20224 - API extension */



/*
 * generalized bind
 */
/*
 * Authentication methods:
 */
#define	LDAP_AUTH_NONE		0x00
#define	LDAP_AUTH_SIMPLE	0x80
#define	LDAP_AUTH_SASL		0xa3
int LDAP_CALL ldap_bind(LDAP *ld, const char *who,
	const char *passwd, int authmethod);
int LDAP_CALL ldap_bind_s(LDAP *ld, const char *who,
	const char *cred, int method);

/*
 * experimental DN format support
 */
char **LDAP_CALL ldap_explode_dns(const char *dn);
int LDAP_CALL ldap_is_dns_dn(const char *dn);

#ifdef	_SOLARIS_SDK
char *ldap_dns_to_dn(char *dns_name, int *nameparts);
#endif


/*
 * user friendly naming/searching routines
 */
typedef int (LDAP_C LDAP_CALLBACK LDAP_CANCELPROC_CALLBACK)(void *cl);
int LDAP_CALL ldap_ufn_search_c(LDAP *ld, char *ufn,
	char **attrs, int attrsonly, LDAPMessage **res,
	LDAP_CANCELPROC_CALLBACK *cancelproc, void *cancelparm);
int LDAP_CALL ldap_ufn_search_ct(LDAP *ld, char *ufn,
	char **attrs, int attrsonly, LDAPMessage **res,
	LDAP_CANCELPROC_CALLBACK *cancelproc, void *cancelparm,
	char *tag1, char *tag2, char *tag3);
int LDAP_CALL ldap_ufn_search_s(LDAP *ld, char *ufn,
	char **attrs, int attrsonly, LDAPMessage **res);
LDAP_API(LDAPFiltDesc *) LDAP_CALL ldap_ufn_setfilter(LDAP *ld, char *fname);
LDAP_API(void) LDAP_CALL ldap_ufn_setprefix(LDAP *ld, char *prefix);
int LDAP_C ldap_ufn_timeout(void *tvparam);

/*
 * functions and definitions that have been replaced by new improved ones
 */
/*
 * Use ldap_get_option() with LDAP_OPT_API_INFO and an LDAPAPIInfo structure
 * instead of ldap_version(). The use of this API is deprecated.
 */
typedef struct _LDAPVersion {
	int sdk_version;	/* Version of the SDK, * 100 */
	int protocol_version;	/* Highest protocol version supported, * 100 */
	int SSL_version;	/* SSL version if this SDK supports it, * 100 */
	int security_level;	/* highest level available */
	int reserved[4];
} LDAPVersion;
#define	LDAP_SECURITY_NONE	0
int LDAP_CALL ldap_version(LDAPVersion *ver);

/* use ldap_create_filter() instead of ldap_build_filter() */
LDAP_API(void) LDAP_CALL ldap_build_filter(char *buf, size_t buflen,
    char *pattern, char *prefix, char *suffix, char *attr,
    char *value, char **valwords);
/* use ldap_set_filter_additions() instead of ldap_setfilteraffixes() */
LDAP_API(void) LDAP_CALL ldap_setfilteraffixes(LDAPFiltDesc *lfdp,
    char *prefix, char *suffix);

/* older result types a server can return -- use LDAP_RES_MODDN instead */
#define	LDAP_RES_MODRDN			LDAP_RES_MODDN
#define	LDAP_RES_RENAME			LDAP_RES_MODDN

/* older error messages */
#define	LDAP_AUTH_METHOD_NOT_SUPPORTED  LDAP_STRONG_AUTH_NOT_SUPPORTED

/* end of unsupported functions */

#ifdef	_SOLARIS_SDK

/* SSL Functions */

/*
 * these three defines resolve the SSL strength
 * setting auth weak, diables all cert checking
 * the CNCHECK tests for the man in the middle hack
 */
#define	LDAPSSL_AUTH_WEAK	0
#define	LDAPSSL_AUTH_CERT	1
#define	LDAPSSL_AUTH_CNCHECK    2

/*
 * Initialize LDAP library for SSL
 */
LDAP * LDAP_CALL ldapssl_init(const char *defhost, int defport,
	int defsecure);

/*
 * Install I/O routines to make SSL over LDAP possible.
 * Use this after ldap_init() or just use ldapssl_init() instead.
 */
int LDAP_CALL ldapssl_install_routines(LDAP *ld);


/*
 * The next three functions initialize the security code for SSL
 * The first one ldapssl_client_init() does initialization for SSL only
 * The next one supports ldapssl_clientauth_init() intializes security
 * for SSL for client authentication. The third function initializes
 * security for doing SSL with client authentication, and PKCS, that is,
 * the third function initializes the security module database(secmod.db).
 * The parameters are as follows:
 * const char *certdbpath - path to the cert file.  This can be a shortcut
 * to the directory name, if so cert7.db will be postfixed to the string.
 * void *certdbhandle - Normally this is NULL.  This memory will need
 * to be freed.
 * int needkeydb - boolean.  Must be ! = 0 if client Authentification
 * is required
 * char *keydbpath - path to the key database.  This can be a shortcut
 * to the directory name, if so key3.db will be postfixed to the string.
 * void *keydbhandle - Normally this is NULL, This memory will need
 * to be freed
 * int needsecmoddb - boolean.  Must be ! = 0 to assure that the correct
 * security module is loaded into memory
 * char *secmodpath - path to the secmod.  This can be a shortcut to the
 * directory name, if so secmod.db will be postfixed to the string.
 *
 * These three functions are mutually exclusive.  You can only call
 * one.  This means that, for a given process, you must call the
 * appropriate initialization function for the life of the process.
 */


/*
 * Initialize the secure parts (Security and SSL) of the runtime for use
 * by a client application.  This is only called once.
 */
int LDAP_CALL ldapssl_client_init(
    const char *certdbpath, void *certdbhandle);

/*
 * Initialize the secure parts (Security and SSL) of the runtime for use
 * by a client application that may want to do SSL client authentication.
 */
int LDAP_CALL ldapssl_clientauth_init(
    const char *certdbpath, void *certdbhandle,
    const int needkeydb, const char *keydbpath, void *keydbhandle);

/*
 * Initialize the secure parts (Security and SSL) of the runtime for use
 * by a client application that may want to do SSL client authentication.
 */
int LDAP_CALL ldapssl_advclientauth_init(
    const char *certdbpath, void *certdbhandle,
    const int needkeydb, const char *keydbpath, void *keydbhandle,
    const int needsecmoddb, const char *secmoddbpath,
    const int sslstrength);

/*
 * get a meaningful error string back from the security library
 * this function should be called, if ldap_err2string doesn't
 * identify the error code.
 */
const char *LDAP_CALL ldapssl_err2string(const int prerrno);

/*
 * Enable SSL client authentication on the given ld.
 */
int LDAP_CALL ldapssl_enable_clientauth(LDAP *ld, char *keynickname,
	char *keypasswd, char *certnickname);

typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_TOKEN_CALLBACK)
	(void *context, char **tokenname);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_PIN_CALLBACK)
	(void *context, const char *tokenname, char **tokenpin);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_CERTPATH_CALLBACK)
	(void *context, char **certpath);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_KEYPATH_CALLBACK)
	(void *context, char **keypath);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_MODPATH_CALLBACK)
	(void *context, char **modulepath);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_CERTNAME_CALLBACK)
	(void *context, char **certname);
typedef int (LDAP_C LDAP_CALLBACK LDAP_PKCS_GET_DONGLEFILENAME_CALLBACK)
	(void *context, char **filename);

#define	PKCS_STRUCTURE_ID 1
struct ldapssl_pkcs_fns {
    int local_structure_id;
    void *local_data;
    LDAP_PKCS_GET_CERTPATH_CALLBACK *pkcs_getcertpath;
    LDAP_PKCS_GET_CERTNAME_CALLBACK *pkcs_getcertname;
    LDAP_PKCS_GET_KEYPATH_CALLBACK *pkcs_getkeypath;
    LDAP_PKCS_GET_MODPATH_CALLBACK *pkcs_getmodpath;
    LDAP_PKCS_GET_PIN_CALLBACK *pkcs_getpin;
    LDAP_PKCS_GET_TOKEN_CALLBACK *pkcs_gettokenname;
    LDAP_PKCS_GET_DONGLEFILENAME_CALLBACK *pkcs_getdonglefilename;

};


int LDAP_CALL ldapssl_pkcs_init(const struct ldapssl_pkcs_fns *pfns);

/* end of SSL functions */
#endif	/* _SOLARIS_SDK */

/* SASL options */
#define	LDAP_OPT_X_SASL_MECH		0x6100
#define	LDAP_OPT_X_SASL_REALM		0x6101
#define	LDAP_OPT_X_SASL_AUTHCID		0x6102
#define	LDAP_OPT_X_SASL_AUTHZID		0x6103
#define	LDAP_OPT_X_SASL_SSF		0x6104 /* read-only */
#define	LDAP_OPT_X_SASL_SSF_EXTERNAL	0x6105 /* write-only */
#define	LDAP_OPT_X_SASL_SECPROPS	0x6106 /* write-only */
#define	LDAP_OPT_X_SASL_SSF_MIN		0x6107
#define	LDAP_OPT_X_SASL_SSF_MAX		0x6108
#define	LDAP_OPT_X_SASL_MAXBUFSIZE	0x6109

/*
 * ldap_interactive_bind_s Interaction flags
 *  Interactive: prompt always - REQUIRED
 */
#define	LDAP_SASL_INTERACTIVE		1U

/*
 * V3 SASL Interaction Function Callback Prototype
 *      when using SASL, interact is pointer to sasl_interact_t
 *  should likely passed in a control (and provided controls)
 */
typedef int (LDAP_SASL_INTERACT_PROC)
	(LDAP *ld, unsigned flags, void* defaults, void *interact);

int LDAP_CALL ldap_sasl_interactive_bind_s(LDAP *ld, const char *dn,
	const char *saslMechanism, LDAPControl **serverControls,
	LDAPControl **clientControls, unsigned flags,
	LDAP_SASL_INTERACT_PROC *proc, void *defaults);

#ifdef	__cplusplus
}
#endif

#endif	/* _LDAP_H */
