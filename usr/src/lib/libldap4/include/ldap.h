/*
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

/*
 * Copyright (c) 1990 Regents of the University of Michigan.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of Michigan at Ann Arbor. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#ifndef _LDAP_H
#define	_LDAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef LDAP_SSL
#include <security/ssl.h>
#endif /* LDAP_SSL */


#include <pthread.h>

#ifdef LDAP_SSL
#define	SSL_LDAP_PORT 636
#endif

#if !defined(NEEDPROTOS) && defined(__STDC__)
#define	NEEDPROTOS	1
#endif

#define	LDAP_API_VERSION	2004
#define	LDAP_VERSION_MIN	2
#define	LDAP_VERSION_MAX	3
#define	LDAP_VENDOR_NAME	"Sun Microsystems Inc."
#define	LDAP_VENDOR_VERSION	400

#define	LDAP_PORT	389
#define	LDAP_VERSION1	1
#define	LDAP_VERSION2	2
#define	LDAP_VERSION3	3
#define	LDAP_VERSION	LDAP_VERSION2

/* OPTIONS to use with ldap_set_option and ldap_get_option */
#define	LDAP_OPT_API_INFO	0x00
#define	LDAP_OPT_DESC	0x01	/* Use of this option is depricated */
/* int, control how aliases are handled during search */
#define	LDAP_OPT_DEREF	0x02
/* Deref values */
#define	LDAP_DEREF_NEVER	0x00
#define	LDAP_DEREF_SEARCHING	0x01
#define	LDAP_DEREF_FINDING	0x02
#define	LDAP_DEREF_ALWAYS	0x03

#define	LDAP_OPT_SIZELIMIT	0x03	/* int, size limit of a search */
#define	LDAP_OPT_TIMELIMIT	0x04	/* int, time limit of a search */
#define	LDAP_OPT_REBIND_FN	0x06	/* Use of this options is depricated */
#define	LDAP_OPT_REBIND_ARG	0x07	/* Use of this options is depricated */
#define	LDAP_OPT_REFERRALS	0x08	/* ON/OFF, chase referrals */
#define	LDAP_OPT_RESTART	0x09	/* ON/OFF, restart if EINTR occurs */
/* int, protocol version, default 2 */
#define	LDAP_OPT_PROTOCOL_VERSION	0x11
/* List of ldap controls to be sent with each request */
#define	LDAP_OPT_SERVER_CONTROLS	0x12
/* List of ldap controls that affect the session */
#define	LDAP_OPT_CLIENT_CONTROLS	0x13
#define	LDAP_OPT_API_FEATURE_INFO	0x15
/* The hostname of the default ldap server */
#define	LDAP_OPT_HOST_NAME	0x30
/* The code of the most recent ldap error that occured for this session */
#define	LDAP_OPT_ERROR_NUMBER	0x31
/* The message returned with the most recent ldap error */
#define	LDAP_OPT_ERROR_STRING	0x32
/* The Matching DN in case of a naming error */
#define	LDAP_OPT_MATCHED_DN	0x33
#define	LDAP_OPT_ERROR_MATCHED	0x33	/* Use of this options is depricated */

/* The timeout while trying to connect to a server */
#define	LDAP_X_OPT_CONNECT_TIMEOUT	0x4F01
#define	LDAP_X_IO_TIMEOUT_NO_WAIT	0
#define	LDAP_X_IO_TIMEOUT_NO_TIMEOUT	-1

/* The Filter List Desc used by UFN functions */
/* #define LDAP_OPT_FILTERDESC 0x80	 */
/* For on/off options */
#define	LDAP_OPT_ON		((void *)1)
#define	LDAP_OPT_OFF	((void *)0)

/* Used for NO limitation is TIMELIMIT or SIZELIMIT */
#define	LDAP_NO_LIMIT		0

#define	LDAP_MAX_ATTR_LEN	100
#define	LDAP_RETURN_NO_ATTR "1.1"
#define	LDAP_RETURN_ALL_ATTR ""
#define	LDAP_RETURN_ALL_ATTR_OPS "*"

/* Begin LDAP Display Template Definitions */
#define	LDAP_TEMPLATE_VERSION   1

/*
 * general types of items (confined to most significant byte)
 */
#define	LDAP_SYN_TYPE_TEXT	0x01000000
#define	LDAP_SYN_TYPE_IMAGE	0x02000000
#define	LDAP_SYN_TYPE_BOOLEAN	0x04000000
#define	LDAP_SYN_TYPE_BUTTON	0x08000000
#define	LDAP_SYN_TYPE_ACTION	0x10000000

/*
 * syntax options (confined to second most significant byte)
 */
#define	LDAP_SYN_OPT_DEFER	0x00010000


/*
 * display template item syntax ids (defined by common agreement)
 * these are the valid values for the ti_syntaxid of the tmplitem
 * struct (defined below).  A general type is encoded in the
 * most-significant 8 bits, and some options are encoded in the next
 * 8 bits.  The lower 16 bits are reserved for the distinct types.
 */
#define	LDAP_SYN_CASEIGNORESTR	(1 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_MULTILINESTR	(2 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_DN		(3 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_BOOLEAN	(4 | LDAP_SYN_TYPE_BOOLEAN)
#define	LDAP_SYN_JPEGIMAGE	(5 | LDAP_SYN_TYPE_IMAGE)
#define	LDAP_SYN_JPEGBUTTON	(6 | LDAP_SYN_TYPE_BUTTON | \
				LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_FAXIMAGE	(7 | LDAP_SYN_TYPE_IMAGE)
#define	LDAP_SYN_FAXBUTTON	(8 | LDAP_SYN_TYPE_BUTTON | \
				LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_AUDIOBUTTON	(9 | LDAP_SYN_TYPE_BUTTON | \
				LDAP_SYN_OPT_DEFER)
#define	LDAP_SYN_TIME		(10 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_DATE		(11 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_LABELEDURL	(12 | LDAP_SYN_TYPE_TEXT)
#define	LDAP_SYN_SEARCHACTION	(13 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_LINKACTION	(14 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_ADDDNACTION	(15 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_VERIFYDNACTION	(16 | LDAP_SYN_TYPE_ACTION)
#define	LDAP_SYN_RFC822ADDR	(17 | LDAP_SYN_TYPE_TEXT)
#ifdef	SUN
#define	LDAP_SYN_PROTECTED	(18 | LDAP_SYN_TYPE_TEXT)
#endif

/*
 * handy macros
 */
#define	LDAP_GET_SYN_TYPE(syid)		((syid) & 0xFF000000)
#define	LDAP_GET_SYN_OPTIONS(syid)	((syid) & 0x00FF0000)

/*
 * display options for output routines (used by entry2text and friends)
 */
/*
 * use calculated label width (based on length of longest label in
 * template) instead of contant width
 */
#define	LDAP_DISP_OPT_AUTOLABELWIDTH	0x00000001
#define	LDAP_DISP_OPT_HTMLBODYONLY	0x00000002

/*
 * perform search actions (applies to ldap_entry2text_search only)
 */
#define	LDAP_DISP_OPT_DOSEARCHACTIONS	0x00000002

/*
 * include additional info. relevant to "non leaf" entries only
 * used by ldap_entry2html and ldap_entry2html_search to include "Browse"
 * and "Move Up" HREFs
 */
#define	LDAP_DISP_OPT_NONLEAF		0x00000004


/*
 * display template item options (may not apply to all types)
 * if this bit is set in ti_options, it applies.
 */
#define	LDAP_DITEM_OPT_READONLY		0x00000001
#define	LDAP_DITEM_OPT_SORTVALUES	0x00000002
#define	LDAP_DITEM_OPT_SINGLEVALUED	0x00000004
#define	LDAP_DITEM_OPT_HIDEIFEMPTY	0x00000008
#define	LDAP_DITEM_OPT_VALUEREQUIRED	0x00000010
#define	LDAP_DITEM_OPT_HIDEIFFALSE	0x00000020 /* booleans only */


/*
 * LDAP API Information structure
 */
typedef struct ldapapiinfo {
	int ldapai_info_version;	/* version of this struct (1) */
	int ldapai_api_version;		/* revision of API supported */
	int ldapai_protocol_version;	/* highest LDAP version supported */
	char **ldapai_extensions;	/* names of API extensions */
	char *ldapai_vendor_name;	/* name of supplier */
	int ldapai_vendor_version;	/* supplier-specific version * 100 */
} LDAPAPIInfo;
#define	LDAP_API_INFO_VERSION	1


/*
 * LDAP API Feature Information
 */
typedef struct ldap_apifeature_info {
	int  ldapaif_info_version;	/* version of this struct (1) */
	char *ldapaif_name;		/* name of supported feature */
	int  ldapaif_version;		/* revision of supported feature */
} LDAPAPIFeatureInfo;
#define	LDAP_FEATURE_INFO_VERSION	1


/*
 * display template item structure
 */
struct ldap_tmplitem {
	unsigned int		ti_syntaxid;
	unsigned int		ti_options;
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
	char			**oc_objclasses;
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
	char			*ad_attrname;
	char			*ad_value;
	struct ldap_adddeflist	*ad_next;
};

#define	NULLADLIST		((struct ldap_adddeflist *)0)


/*
 * display template global options
 * if this bit is set in dt_options, it applies.
 */
/*
 * users should be allowed to try to add objects of these entries
 */
#define	LDAP_DTMPL_OPT_ADDABLE	0x00000001

/*
 * users should be allowed to do "modify RDN" operation of these entries
 */
#define	LDAP_DTMPL_OPT_ALLOWMODRDN	0x00000002

/*
 * this template is an alternate view, not a primary view
 */
#define	LDAP_DTMPL_OPT_ALTVIEW		0x00000004


/*
 * display template structure
 */
struct ldap_disptmpl {
	char				*dt_name;
	char				*dt_pluralname;
	char				*dt_iconname;
	unsigned int			dt_options;
	char				*dt_authattrname;
	char				*dt_defrdnattrname;
	char				*dt_defaddlocation;
	struct ldap_oclist		*dt_oclist;
	struct ldap_adddeflist		*dt_adddeflist;
	struct ldap_tmplitem		*dt_items;
	void				*dt_appdata;
	struct ldap_disptmpl		*dt_next;
};

#define	NULLDISPTMPL	((struct ldap_disptmpl *)0)

#define	LDAP_SET_DISPTMPL_APPDATA(dt, datap)  \
	(dt)->dt_appdata = (void *)(datap)

#define	LDAP_GET_DISPTMPL_APPDATA(dt, type)   \
	(type)((dt)->dt_appdata)

#define	LDAP_IS_DISPTMPL_OPTION_SET(dt, option)       \
	(((dt)->dt_options & option) != 0)

#define	LDAP_TMPL_ERR_VERSION	1
#define	LDAP_TMPL_ERR_MEM	2
#define	LDAP_TMPL_ERR_SYNTAX	3
#define	LDAP_TMPL_ERR_FILE	4

/*
 * buffer size needed for entry2text and vals2text
 */
#define	LDAP_DTMPL_BUFSIZ	8192

/* END Display Template Definitions */

/* BEGIN Search Prefrences Definitions */

struct ldap_searchattr {
	char				*sa_attrlabel;
	char				*sa_attr;
					/* max 32 matchtypes for now */
	unsigned int			sa_matchtypebitmap;
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
	unsigned int			so_options;
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

#define	LDAP_IS_SEARCHOBJ_OPTION_SET(so, option)	\
	(((so)->so_options & option) != 0)

#define	LDAP_SEARCHPREF_VERSION_ZERO	0
#define	LDAP_SEARCHPREF_VERSION		1

#define	LDAP_SEARCHPREF_ERR_VERSION	1
#define	LDAP_SEARCHPREF_ERR_MEM		2
#define	LDAP_SEARCHPREF_ERR_SYNTAX	3
#define	LDAP_SEARCHPREF_ERR_FILE	4


/* END Search Prefrences Definitions */

/*
 * Structure for LDAP modifications
 */
typedef struct ldapmod {
	int		mod_op;
#define	LDAP_MOD_ADD		0x00
#define	LDAP_MOD_DELETE		0x01
#define	LDAP_MOD_REPLACE	0x02
#define	LDAP_MOD_BVALUES	0x80
	char		*mod_type;
	union {
		char		**modv_strvals;
		struct berval	**modv_bvals;
	} mod_vals;
#define	mod_values	mod_vals.modv_strvals
#define	mod_bvalues	mod_vals.modv_bvals
/*
 * The following field is commented out since no functions use it in
 * the library and also not part of c-api draft.
 */
/*	struct ldapmod	*mod_next */
} LDAPMod;

typedef struct ldap LDAP; /* Opaque LDAP connection handle */

typedef struct ldapmsg LDAPMessage; /* Opaque Result / Entry handle */

#define	NULLMSG	((LDAPMessage *) NULL)

/* Call back to get info needed for re-bind */
typedef int (LDAP_REBIND_FUNCTION)(LDAP *ld, char **dn, char **passwd,
			int *authmethod, int freeit, void *extraArg);

/*
 * structures for ldap getfilter routines
 */

typedef struct ldap_filt_info {
	char			*lfi_filter;
	char			*lfi_desc;
	int			lfi_scope;	/* LDAP_SCOPE_BASE, etc */
	int			lfi_isexact;	/* exact match filter? */
	struct ldap_filt_info	*lfi_next;
} LDAPFiltInfo;


#define	LDAP_FILT_MAXSIZ	1024

typedef struct ldap_filt_list LDAPFiltList;
typedef struct ldap_filt_desc LDAPFiltDesc;


/*
 * Simple Page control OID
 */
#define	LDAP_CONTROL_SIMPLE_PAGE		"1.2.840.113556.1.4.319"

/*
 * Server Sort Control
 */
#define	LDAP_CONTROL_SORTREQUEST		"1.2.840.113556.1.4.473"
#define	LDAP_CONTROL_SORTRESPONSE		"1.2.840.113556.1.4.474"
/*
 * structure for a sort-key
 */
typedef struct LDAPsortkey {
	char	*sk_attrtype;
	char	*sk_matchruleoid;
	int	sk_reverseorder;
} LDAPsortkey;

/*
 * Virtual List View (vlv) control
 */
#define	LDAP_CONTROL_VLVREQUEST			"2.16.840.1.113730.3.4.9"
#define	LDAP_CONTROL_VLVRESPONSE		"2.16.840.1.113730.3.4.10"
/*
 * structure that describes a VirtualListViewRequest control.
 * note that ldvlist_index and ldvlist_size are only relevant to
 * ldap_create_virtuallist_control() if ldvlist_attrvalue is NULL.
 */
typedef struct ldapvirtuallist {
	unsigned long	ldvlist_before_count;	/* # entries before target */
	unsigned long	ldvlist_after_count;	/* # entries after target */
	char		*ldvlist_attrvalue;	/* jump to this value */
	unsigned long	ldvlist_index;		/* list offset */
	unsigned long	ldvlist_size;		/* number of items in vlist */
	void		*ldvlist_extradata;	/* for use by application */
} LDAPVirtualList;

/*
 * ldapv3 LDAPControl
 */
typedef struct ldapcontrol
{
	char *ldctl_oid;
/*
 * the "ldctl_value" field of this structure used to be a pointer to
 * struct berval.  To make this structure compliant to the latest c-api
 * draft, it is changed to "struct berval ldctl_value"
 */
	struct berval ldctl_value;
	char ldctl_iscritical;
} LDAPControl, *PLDAPControl;

/*
 * specific LDAP instantiations of BER types we know about
 */

/* general stuff */
#define	LDAP_TAG_MESSAGE	0x30	/* tag is 16 + constructed bit */
#define	LDAP_TAG_MSGID		0x02
#define	LDAP_TAG_CONTROL_LIST	0xA0	/* Context 0 + constructed */
#define	LDAP_TAG_REFERRAL	0xA3	/* Context 3 + constructed */
#define	LDAP_TAG_SASLCREDS	0x87	/* Context 7 + primitive */
#define	LDAP_TAG_AUTH_SIMPLE 0x80	/* Context 0 + primitive */
#define	LDAP_TAG_AUTH_SASL	0xA3	/* Context 3 + constructed */
/* Tag for modrdn request */
#define	LDAP_TAG_NEWPARENT	0x80	/* Context 0 + primitive */
/* Tags for Extensible filter match */
#define	LDAP_TAG_FEXT_RULE	0x81	/* Context 1 + primitive */
#define	LDAP_TAG_FEXT_TYPE	0x82	/* Context 2 + primitive */
#define	LDAP_TAG_FEXT_VAL	0x83	/* Context 3 + primitive */
#define	LDAP_TAG_FEXT_DN	0x84	/* Context 4 + primitive */
/* tags for EXTENDED OPERATIONS */
#define	LDAP_TAG_EXT_NAME	0x80	/* Context 0 + primitive */
#define	LDAP_TAG_EXT_VAL	0x81	/* Context 1 + primitive */
#define	LDAP_TAG_EXT_RESPNAME	0x8a	/* Context 10 + primitive */
#define	LDAP_TAG_EXT_RESPONSE	0x8b	/* Context 11 + primitive */
/* tags for Virtual List View control */
#define	LDAP_TAG_VLV_BY_INDEX	0xa0    /* context specific + constructed + 0 */
#define	LDAP_TAG_VLV_BY_VALUE	0x81    /* context specific + primitive + 1 */
/* tag for sort control */
#define	LDAP_TAG_SK_MATCHRULE	0x80L   /* context specific + primitive */
#define	LDAP_TAG_SK_REVERSE	0x81L   /* context specific + primitive */
#define	LDAP_TAG_SR_ATTRTYPE	0x80L   /* context specific + primitive */

/* possible operations a client can invoke */
#define	LDAP_REQ_BIND			0x60	/* application + constructed */
#define	LDAP_REQ_UNBIND			0x42	/* application + primitive   */
#define	LDAP_REQ_SEARCH			0x63	/* application + constructed */
#define	LDAP_REQ_MODIFY			0x66	/* application + constructed */
#define	LDAP_REQ_ADD			0x68	/* application + constructed */
#define	LDAP_REQ_DELETE			0x4a	/* application + primitive   */
#define	LDAP_REQ_MODRDN			0x6c	/* application + constructed */
#define	LDAP_REQ_COMPARE		0x6e	/* application + constructed */
#define	LDAP_REQ_ABANDON		0x50	/* application + primitive   */
/* New in ldapv3 application + constructed */
#define	LDAP_REQ_EXTENDED		0x77
/* version 3.0 compatibility stuff */
#define	LDAP_REQ_UNBIND_30		0x62
#define	LDAP_REQ_DELETE_30		0x6a
#define	LDAP_REQ_ABANDON_30		0x70

/* possible result types a server can return */
#define	LDAP_RES_BIND			0x61	/* application + constructed */
#define	LDAP_RES_SEARCH_ENTRY		0x64	/* application + constructed */
/* new in ldapv3, application + constructed */
#define	LDAP_RES_SEARCH_REFERENCE	0x73
#define	LDAP_RES_SEARCH_RESULT		0x65	/* application + constructed */
#define	LDAP_RES_MODIFY			0x67	/* application + constructed */
#define	LDAP_RES_ADD			0x69	/* application + constructed */
#define	LDAP_RES_DELETE			0x6b	/* application + constructed */
#define	LDAP_RES_MODRDN			0x6d	/* application + constructed */
#define	LDAP_RES_COMPARE		0x6f	/* application + constructed */
/* new in ldapv3, application + constructed */
#define	LDAP_RES_EXTENDED		0x78
#define	LDAP_RES_ANY			(-1)

/* authentication methods available */
#define	LDAP_AUTH_NONE		0x00	/* no authentication		  */
#define	LDAP_AUTH_SIMPLE	0x80	/* context specific + primitive   */
#define	LDAP_AUTH_KRBV4		0xff	/* means do both of the following */
#define	LDAP_AUTH_KRBV41	0x81	/* context specific + primitive   */
#define	LDAP_AUTH_KRBV42	0x82	/* context specific + primitive   */
/* New with ldapv3 */
#define	LDAP_AUTH_SASL		0xa3	/* context specific + constructed */

/* 3.0 compatibility auth methods */
#define	LDAP_AUTH_SIMPLE_30	0xa0	/* context specific + constructed */
#define	LDAP_AUTH_KRBV41_30	0xa1	/* context specific + constructed */
#define	LDAP_AUTH_KRBV42_30	0xa2	/* context specific + constructed */

/* filter types */
#define	LDAP_FILTER_AND		0xa0	/* context specific + constructed */
#define	LDAP_FILTER_OR		0xa1	/* context specific + constructed */
#define	LDAP_FILTER_NOT		0xa2	/* context specific + constructed */
#define	LDAP_FILTER_EQUALITY	0xa3	/* context specific + constructed */
#define	LDAP_FILTER_SUBSTRINGS	0xa4	/* context specific + constructed */
#define	LDAP_FILTER_GE		0xa5	/* context specific + constructed */
#define	LDAP_FILTER_LE		0xa6	/* context specific + constructed */
#define	LDAP_FILTER_PRESENT	0x87	/* context specific + primitive   */
#define	LDAP_FILTER_APPROX	0xa8	/* context specific + constructed */
#define	LDAP_FILTER_EXTENSIBLE	0xa9	/* context specific + constructed */

/* 3.0 compatibility filter types */
#define	LDAP_FILTER_PRESENT_30	0xa7	/* context specific + constructed */

/* substring filter component types */
#define	LDAP_SUBSTRING_INITIAL	0x80	/* context specific */
#define	LDAP_SUBSTRING_ANY	0x81	/* context specific */
#define	LDAP_SUBSTRING_FINAL	0x82	/* context specific */

/* 3.0 compatibility substring filter component types */
#define	LDAP_SUBSTRING_INITIAL_30	0xa0	/* context specific */
#define	LDAP_SUBSTRING_ANY_30		0xa1	/* context specific */
#define	LDAP_SUBSTRING_FINAL_30		0xa2	/* context specific */

/* search scopes */
#define	LDAP_SCOPE_BASE		0x00
#define	LDAP_SCOPE_ONELEVEL	0x01
#define	LDAP_SCOPE_SUBTREE	0x02
/* Used when parsing URL, if scope not found. *LDAP_SCOPE_BASE is to use then */
#define	LDAP_SCOPE_UNKNOWN  0xFF

/* ldap_result number of messages that should be returned */
#define	LDAP_MSG_ONE 0x00
#define	LDAP_MSG_ALL 0x01
#define	LDAP_MSG_RECEIVED 0x02


/* default limit on nesting of referrals */
#define	LDAP_DEFAULT_REFHOPLIMIT	5


/* SASL mechanisms */
#define	LDAP_SASL_SIMPLE ""
#define	LDAP_SASL_CRAM_MD5 "CRAM-MD5"
#define	LDAP_SASL_EXTERNAL "EXTERNAL"
/* Next ones are not supported so far by SunDS 2.0 */
#define	LDAP_SASL_X511_PROTECTED "X.511-Protected"
#define	LDAP_SASL_X511_STRONG "X.511-Strong"
#define	LDAP_SASL_KERBEROS_V4 "KERBEROS_V4"
#define	LDAP_SASL_GSSAPI "GSSAPI"
#define	LDAP_SASL_SKEY "SKEY"

/*
 * structure for ldap friendly mapping routines
 */

typedef struct friendly {
	char	*f_unfriendly;
	char	*f_friendly;
} FriendlyMap;


/*
 * Structures for URL handling
 */
typedef struct ldap_url_extension {
	char *lue_type;
	char *lue_value;
	int lue_iscritical;
} LDAPURLExt;

typedef struct ldap_url_desc {
    char	*lud_host;
    int		lud_port;
    char	*lud_dn;
    char	**lud_attrs;
    int		lud_scope;
    char	*lud_filter;
	LDAPURLExt **lud_extensions;
    char	*lud_string;	/* for internal use only */
} LDAPURLDesc;

#define	NULLLDAPURLDESC	((LDAPURLDesc *)NULL)

#define	LDAP_URL_ERR_NOTLDAP	1	/* URL doesn't begin with "ldap://" */
#define	LDAP_URL_ERR_NODN	2	/* URL has no DN (required) */
#define	LDAP_URL_ERR_BADSCOPE	3	/* URL scope string is invalid */
#define	LDAP_URL_ERR_MEM	4	/* can't allocate memory space */


/*
 * possible error codes we can return
 */

#define	LDAP_SUCCESS			0x00
#define	LDAP_OPERATIONS_ERROR		0x01
#define	LDAP_PROTOCOL_ERROR		0x02
#define	LDAP_TIMELIMIT_EXCEEDED		0x03
#define	LDAP_SIZELIMIT_EXCEEDED		0x04
#define	LDAP_COMPARE_FALSE		0x05
#define	LDAP_COMPARE_TRUE		0x06
#define	LDAP_AUTH_METHOD_NOT_SUPPORTED	0x07
#define	LDAP_STRONG_AUTH_REQUIRED	0x08
/* Not used in ldapv3 */
#define	LDAP_PARTIAL_RESULTS		0x09

/* New in ldapv3 */
#define	LDAP_REFERRAL		0x0a
#define	LDAP_ADMINLIMIT_EXCEEDED	0x0b
#define	LDAP_UNAVAILABLE_CRITICAL_EXTENSION	0x0c
#define	LDAP_CONFIDENTIALITY_REQUIRED	0x0d
#define	LDAP_SASL_BIND_INPROGRESS	0x0e
/* End of new */

#define	LDAP_NO_SUCH_ATTRIBUTE		0x10
#define	LDAP_UNDEFINED_TYPE		0x11
#define	LDAP_INAPPROPRIATE_MATCHING	0x12
#define	LDAP_CONSTRAINT_VIOLATION	0x13
#define	LDAP_TYPE_OR_VALUE_EXISTS	0x14
#define	LDAP_INVALID_SYNTAX		0x15

#define	ATTRIBUTE_ERROR(n) ((n & 0xf0) == 0x10)

#define	LDAP_NO_SUCH_OBJECT		0x20
#define	LDAP_ALIAS_PROBLEM		0x21
#define	LDAP_INVALID_DN_SYNTAX		0x22
/* Following in not used in ldapv3 */
#define	LDAP_IS_LEAF			0x23
#define	LDAP_ALIAS_DEREF_PROBLEM	0x24

#define	NAME_ERROR(n)	((n & 0xf0) == 0x20)

#define	LDAP_INAPPROPRIATE_AUTH		0x30
#define	LDAP_INVALID_CREDENTIALS	0x31
#define	LDAP_INSUFFICIENT_ACCESS	0x32
#define	LDAP_BUSY			0x33
#define	LDAP_UNAVAILABLE		0x34
#define	LDAP_UNWILLING_TO_PERFORM	0x35
#define	LDAP_LOOP_DETECT		0x36

#define	LDAP_SORT_CONTROL_MISSING	0x3C	/* 60 */
#define	LDAP_INDEX_RANGE_ERROR		0x3D	/* 61 */

#define	LDAP_NAMING_VIOLATION		0x40
#define	LDAP_OBJECT_CLASS_VIOLATION	0x41
#define	LDAP_NOT_ALLOWED_ON_NONLEAF	0x42
#define	LDAP_NOT_ALLOWED_ON_RDN		0x43
#define	LDAP_ALREADY_EXISTS		0x44
#define	LDAP_NO_OBJECT_CLASS_MODS	0x45
#define	LDAP_RESULTS_TOO_LARGE		0x46
/* Following is new in ldapv3 */
#define	LDAP_AFFECTS_MULTIPLE_DSAS	0x47
#define	LDAP_OTHER			0x50

/* Reserved for API */
#define	LDAP_SERVER_DOWN		0x51
#define	LDAP_LOCAL_ERROR		0x52
#define	LDAP_ENCODING_ERROR		0x53
#define	LDAP_DECODING_ERROR		0x54
#define	LDAP_TIMEOUT			0x55
#define	LDAP_AUTH_UNKNOWN		0x56
#define	LDAP_FILTER_ERROR		0x57
#define	LDAP_USER_CANCELLED		0x58
#define	LDAP_PARAM_ERROR		0x59
#define	LDAP_NO_MEMORY			0x5a

/* New code with ldapv3 ? */
#define	LDAP_CONNECT_ERROR 		0x5b
#define	LDAP_NOT_SUPPORTED		0x5c
#define	LDAP_CONTROL_NOT_FOUND	0x5d
#define	LDAP_NO_RESULTS_RETURNED	0x5e
#define	LDAP_MORE_RESULTS_TO_RETURN	0x5f
#define	LDAP_CLIENT_LOOP	0x60
#define	LDAP_REFERRAL_LIMIT_EXCEEDED	0x61

/* debugging stuff */
#ifdef LDAP_DEBUG
extern int	ldap_debug;
#ifdef LDAP_SYSLOG
extern int	ldap_syslog;
extern int	ldap_syslog_level;
#endif
#define	LDAP_DEBUG_TRACE	0x001
#define	LDAP_DEBUG_PACKETS	0x002
#define	LDAP_DEBUG_ARGS		0x004
#define	LDAP_DEBUG_CONNS	0x008
#define	LDAP_DEBUG_BER		0x010
#define	LDAP_DEBUG_FILTER	0x020
#define	LDAP_DEBUG_CONFIG	0x040
#define	LDAP_DEBUG_ACL		0x080
#define	LDAP_DEBUG_STATS	0x100
#define	LDAP_DEBUG_STATS2	0x200
#define	LDAP_DEBUG_SHELL	0x400
#define	LDAP_DEBUG_PARSE	0x800
/* More values for http gateway */
#define	LDAP_DEBUG_GWAY		0x1000
#define	LDAP_DEBUG_GWAYMORE 	0x2000

#define	LDAP_DEBUG_ANY		0xffff

#ifdef LDAP_SYSLOG
/* ldaplog is a general logging function that is defined in liblber/i18n.c */
#define	Debug(level, fmt, arg1, arg2, arg3)	\
	{ \
		if (ldap_debug & level) \
			fprintf(stderr, fmt, arg1, arg2, arg3); \
		if (ldap_syslog & level) \
			ldaplog(level, fmt, arg1, arg2, arg3); \
	}
#else /* LDAP_SYSLOG */
#ifndef WINSOCK
#define	Debug(level, fmt, arg1, arg2, arg3) \
		if (ldap_debug & level) \
			fprintf(stderr, fmt, arg1, arg2, arg3);
#else /* !WINSOCK */
extern void Debug(int level, char *fmt, ...);
#endif /* !WINSOCK */
#endif /* LDAP_SYSLOG */
#else /* LDAP_DEBUG */
#define	Debug(level, fmt, arg1, arg2, arg3)
#endif /* LDAP_DEBUG */


#ifndef NEEDPROTOS
extern LDAP *ldap_open();
#ifdef LDAP_SSL
extern LDAP *ldap_ssl_open();
#endif /* LDAP_SSL */
extern LDAP *ldap_init();
#ifdef STR_TRANSLATION
extern void ldap_set_string_translators();
#ifdef LDAP_CHARSET_8859
extern int ldap_t61_to_8859();
extern int ldap_8859_to_t61();
#endif /* LDAP_CHARSET_8859 */
#endif /* STR_TRANSLATION */
extern LDAPMessage *ldap_first_entry();
extern LDAPMessage *ldap_next_entry();
extern char *ldap_get_dn();
extern char *ldap_dn2ufn();
extern char **ldap_explode_dn();
extern char *ldap_first_attribute();
extern char *ldap_next_attribute();
extern char **ldap_get_values();
extern struct berval **ldap_get_values_len();
extern void ldap_value_free();
extern void ldap_value_free_len();
extern int ldap_count_values();
extern int ldap_count_values_len();
extern char *ldap_err2string();
extern void ldap_getfilter_free();
extern LDAPFiltDesc *ldap_init_getfilter();
extern LDAPFiltDesc *ldap_init_getfilter_buf();
extern LDAPFiltInfo *ldap_getfirstfilter();
extern LDAPFiltInfo *ldap_getnextfilter();
extern void ldap_setfilteraffixes();
extern void ldap_build_filter();
extern void ldap_flush_cache();
extern void ldap_set_cache_options();
extern void ldap_uncache_entry();
extern void ldap_uncache_request();
extern char *ldap_friendly_name();
extern void ldap_free_friendlymap();
extern LDAP *cldap_open();
extern void cldap_setretryinfo();
extern void cldap_close();
extern LDAPFiltDesc *ldap_ufn_setfilter();
extern int ldap_ufn_timeout();
extern int ldap_sort_entries();
extern int ldap_sort_values();
extern int ldap_sort_strcasecmp();
void ldap_free_urldesc();
void ldap_free_urlexts();
void ldap_set_rebind_proc();
void ldap_enable_translation();
/* Begin Display Template Prototypes */
typedef int (*writeptype)();

int ldap_init_templates();
int ldap_init_templates_buf();
void ldap_free_templates();
struct ldap_disptmpl *ldap_first_disptmpl();
struct ldap_disptmpl *ldap_next_disptmpl();
struct ldap_disptmpl *ldap_name2template();
struct ldap_disptmpl *ldap_oc2template();
char **ldap_tmplattrs();
struct ldap_tmplitem *ldap_first_tmplrow();
struct ldap_tmplitem *ldap_next_tmplrow();
struct ldap_tmplitem *ldap_first_tmplcol();
struct ldap_tmplitem *ldap_next_tmplcol();
int ldap_entry2text_search();
int ldap_entry2text();
int ldap_vals2text();
int ldap_entry2html_search();
int ldap_entry2html();
int ldap_vals2html();

int ldap_init_searchprefs();
int ldap_init_searchprefs_buf();
void ldap_free_searchprefs();
struct ldap_searchobj	*ldap_first_searchobj();
struct ldap_searchobj	*ldap_next_searchobj();

#else /* NEEDPROTOS */
#if !defined(MACOS) && !defined(DOS) && !defined(_WIN32) && !defined(WINSOCK)
#include <sys/time.h>
#endif


/*
 * Abandon functions
 */
int ldap_abandon_ext(LDAP *ld, int msgid, LDAPControl **serverctrls,
	LDAPControl ** clientctrls);
int ldap_abandon(LDAP *ld, int msgid);

/*
 * Add functions
 */
int ldap_add_ext(LDAP *ld, char *dn, LDAPMod **attrs,
	LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp);
int ldap_add_ext_s(LDAP *ld, char *dn, LDAPMod **attrs,
	LDAPControl ** serverctrls, LDAPControl **clientctrls);
int ldap_add(LDAP *ld, char *dn, LDAPMod **attrs);
int ldap_add_s(LDAP *ld, char *dn, LDAPMod **attrs);

/*
 * Bind functions
 */
/* DEPRECATED */
int ldap_bind(LDAP *ld, char *who, char *passwd, int authmethod);
/* DEPRECATED */
int ldap_bind_s(LDAP *ld, char *who, char *cred, int method);
#ifdef LDAP_REFERRALS
/* DEPRECATED */
void ldap_set_rebind_proc(LDAP *ld, LDAP_REBIND_FUNCTION *rebindproc,
	void *extra_arg);
#endif /* LDAP_REFERRALS */

/*
 * Simple bind functions
 */
int ldap_simple_bind(LDAP *ld, char *who, char *passwd);
int ldap_simple_bind_s(LDAP *ld, char *who, char *passwd);

/*
 * SASL functions
 */
int ldap_sasl_bind(LDAP *ld, char *dn, char *mechanism, struct berval *cred,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int ldap_sasl_bind_s(LDAP *ld, char *dn, char *mechanism, struct berval *cred,
	LDAPControl **serverctrls, LDAPControl **clientctrls,
	struct berval **servercredp);

/*
 * Kerberos functions
 */
/* DEPRECATED */
int ldap_kerberos_bind_s(LDAP *ld, char *who);
/* DEPRECATED */
int ldap_kerberos_bind1(LDAP *ld, char *who);
/* DEPRECATED */
int ldap_kerberos_bind1_s(LDAP *ld, char *who);
/* DEPRECATED */
int ldap_kerberos_bind2(LDAP *ld, char *who);
/* DEPRECATED */
int ldap_kerberos_bind2_s(LDAP *ld, char *who);

#ifndef NO_CACHE
/*
 * Cache functions
 */
int ldap_enable_cache(LDAP *ld, time_t timeout, ssize_t maxmem);
void ldap_disable_cache(LDAP *ld);
void ldap_set_cache_options(LDAP *ld, unsigned int opts);
void ldap_destroy_cache(LDAP *ld);
void ldap_flush_cache(LDAP *ld);
void ldap_uncache_entry(LDAP *ld, char *dn);
void ldap_uncache_request(LDAP *ld, int msgid);
#endif /* !NO_CACHE */

/*
 * Compare functions
 */
int ldap_compare_ext(LDAP *ld, char *dn, char *attr, struct berval *bvalue,
	LDAPControl ** serverctrls, LDAPControl **clientctrls, int *msgidp);
int ldap_compare_ext_s(LDAP *ld, char *dn, char *attr, struct berval *bvalue,
	LDAPControl ** serverctrls, LDAPControl **clientctrls);
int ldap_compare(LDAP *ld, char *dn, char *attr, char *value);
int ldap_compare_s(LDAP *ld, char *dn, char *attr, char *value);

/*
 * Delete functions
 */
int ldap_delete_ext(LDAP *ld, char *dn, LDAPControl **serverctrls,
	LDAPControl **clientctrls, int *msgidp);
int ldap_delete_ext_s(LDAP *ld, char *dn, LDAPControl **serverctrls,
	LDAPControl **clientctrls);
int ldap_delete(LDAP *ld, char *dn);
int ldap_delete_s(LDAP *ld, char *dn);

/*
 * Error functions
 */
char *ldap_err2string(int err);

/* DEPRECATED */
int ldap_result2error(LDAP *ld, LDAPMessage *r, int freeit);
/* DEPRECATED */
void ldap_perror(LDAP *ld, char *s);

/*
 * Modify functions
 */
int ldap_modify_ext(LDAP *ld, char *dn, LDAPMod **mods,
	LDAPControl **serverctrls, LDAPControl **clientctrls, int *msgidp);
int ldap_modify_ext_s(LDAP *ld, char *dn, LDAPMod **mods,
	LDAPControl **serverctrls, LDAPControl **clientctrls);
int ldap_modify(LDAP *ld, char *dn, LDAPMod **mods);
int ldap_modify_s(LDAP *ld, char *dn, LDAPMod **mods);

/*
 * Modrdn functions
 */

/* DEPRECATED : use ldap_rename instead */
int ldap_modrdn0(LDAP *ld, char *dn, char *newrdn);
/* DEPRECATED : use ldap_rename_s instead */
int ldap_modrdn0_s(LDAP *ld, char *dn, char *newrdn);
/* DEPRECATED : use ldap_rename instead */
int ldap_modrdn(LDAP *ld, char *dn, char *newrdn,
	int deleteoldrdn);
/* DEPRECATED : use ldap_rename_s instead */
int ldap_modrdn_s(LDAP *ld, char *dn, char *newrdn,
	int deleteoldrdn);

/*
 * Rename functions
 */
int ldap_rename(LDAP *ld, char *dn, char *newrdn, char *newparent,
	int deleteoldrdn, LDAPControl ** serverctrls,
	LDAPControl **clientctrls, int *msgidp);
int ldap_rename_s(LDAP *ld, char *dn, char *newrdn, char *newparent,
	int deleteoldrdn, LDAPControl ** serverctrls,
	LDAPControl **clientctrls);

/*
 * Init/Open functions
 */
LDAP *ldap_init(char *defhost, int defport);

/* DEPRECATED : use ldap_init instead */
LDAP *ldap_open(char *host, int port);

#ifdef LDAP_SSL
LDAP *ldap_ssl_init(char *defhost, int defport, char *keyname);

/* DEPRECATED : use ldap_ssl_init instead */
LDAP *ldap_ssl_open(char *host, int port, char *keyname);
#endif

/*
 * Entry functions
 */
LDAPMessage *ldap_first_entry(LDAP *ld, LDAPMessage *res);
LDAPMessage *ldap_next_entry(LDAP *ld, LDAPMessage *entry);
int ldap_count_entries(LDAP *ld, LDAPMessage *res);

/*
 * Message functions
 */
LDAPMessage *ldap_first_message(LDAP *ld, LDAPMessage *res);
LDAPMessage *ldap_next_message(LDAP *ld, LDAPMessage *msg);
int ldap_count_messages(LDAP *ld, LDAPMessage *res);

/*
 * Reference functions
 */
LDAPMessage *ldap_first_reference(LDAP *ld, LDAPMessage *res);
LDAPMessage *ldap_next_reference(LDAP *ld, LDAPMessage *msg);
int ldap_count_references(LDAP *ld, LDAPMessage *res);
char ** ldap_get_reference_urls(LDAP *ld, LDAPMessage *res);

/*
 * Entry functions
 */
LDAPMessage *ldap_delete_result_entry(LDAPMessage **list,
	LDAPMessage *e);
void ldap_add_result_entry(LDAPMessage **list, LDAPMessage *e);

/*
 * DN functions
 */
char *ldap_get_dn(LDAP *ld, LDAPMessage *entry);
char **ldap_explode_dn(char *dn, int notypes);
char ** ldap_explode_rdn(char *rdn, int notypes);
char *ldap_dn2ufn(char *dn);

char **ldap_explode_dns(char *dn);
int ldap_is_dns_dn(char *dn);
char *ldap_dns_to_dn(char *dns_name, int *nameparts);

/*
 * Attribute parsing functions
 */
char *ldap_first_attribute(LDAP *ld, LDAPMessage *entry,
	BerElement **ber);
char *ldap_next_attribute(LDAP *ld, LDAPMessage *entry,
	BerElement *ber);
void ldap_memfree(char *mem);

/*
 * Attribute Value functions
 */
char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *target);
struct berval **ldap_get_values_len(LDAP *ld, LDAPMessage *entry,
	char *target);
int ldap_count_values(char **vals);
int ldap_count_values_len(struct berval **vals);
void ldap_value_free(char **vals);
void ldap_value_free_len(struct berval **vals);

/*
 * Result functions
 */
int ldap_result(LDAP *ld, int msgid, int all,
	struct timeval *timeout, LDAPMessage **result);
int ldap_msgdelete(LDAP *ld, int msgid);
int ldap_msgfree(LDAPMessage *lm);
int ldap_msgtype(LDAPMessage *res);
int ldap_msgid(LDAPMessage *res);
int ldap_parse_result(LDAP *ld, LDAPMessage *res, int *errcodep,
	char **matcheddnp, char **errmsgp, char ***referralsp,
	LDAPControl ***serverctrlsp, int freeit);
int ldap_parse_sasl_bind_result(LDAP *ld, LDAPMessage *res,
	struct berval **servercredp, int freeit);
int ldap_parse_extended_result(LDAP *ld, LDAPMessage *res,
	char **resultoidp, struct berval **resultdata, int freeit);
int cldap_getmsg(LDAP *ld, struct timeval *timeout, BerElement *ber);


/*
 * Search functions
 */
int ldap_search_ext(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp,
	int sizelimit, int *msgidp);
int ldap_search_ext_s(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPControl **serverctrls,
	LDAPControl **clientctrls, struct timeval *timeoutp, int sizelimit,
	LDAPMessage **res);

int ldap_search(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly);
int ldap_search_s(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPMessage **res);
int ldap_search_st(LDAP *ld, char *base, int scope, char *filter,
    char **attrs, int attrsonly, struct timeval *timeout, LDAPMessage **res);

/*
 * UFN functions
 */
int ldap_ufn_search_c(LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res, int (*cancelproc)(void *cl),
	void *cancelparm);
int ldap_ufn_search_ct(LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res, int (*cancelproc)(void *cl),
	void *cancelparm, char *tag1, char *tag2, char *tag3);
int ldap_ufn_search_s(LDAP *ld, char *ufn, char **attrs,
	int attrsonly, LDAPMessage **res);
LDAPFiltDesc *ldap_ufn_setfilter(LDAP *ld, char *fname);
void ldap_ufn_setprefix(LDAP *ld, char *prefix);
int ldap_ufn_timeout(void *tvparam);


/*
 * Unbind functions
 */
int ldap_unbind(LDAP *ld);
int ldap_unbind_s(LDAP *ld);


/*
 * Filter functions
 */
LDAPFiltDesc *ldap_init_getfilter(char *fname);
LDAPFiltDesc *ldap_init_getfilter_buf(char *buf, ssize_t buflen);
LDAPFiltInfo *ldap_getfirstfilter(LDAPFiltDesc *lfdp, char *tagpat,
	char *value);
LDAPFiltInfo *ldap_getnextfilter(LDAPFiltDesc *lfdp);
void ldap_setfilteraffixes(LDAPFiltDesc *lfdp, char *prefix, char *suffix);
void ldap_build_filter(char *buf, size_t buflen,
	char *pattern, char *prefix, char *suffix, char *attr,
	char *value, char **valwords);

/*
 *  Functions to free LDAPFiltDesc and LDAPmod
 */
void ldap_getfilter_free(LDAPFiltDesc *lfdp);
void ldap_mods_free(LDAPMod **mods, int freemods);

/*
 * Friendly name functions
 */
char *ldap_friendly_name(char *filename, char *uname,
	FriendlyMap **map);
void ldap_free_friendlymap(FriendlyMap **map);


/*
 * Connectionless LDAP functions
 */
LDAP *cldap_open(char *host, int port);
void cldap_close(LDAP *ld);
int cldap_search_s(LDAP *ld, char *base, int scope, char *filter,
	char **attrs, int attrsonly, LDAPMessage **res, char *logdn);
void cldap_setretryinfo(LDAP *ld, int tries, time_t timeout);


/*
 * Sort functions
 */
int ldap_sort_entries(LDAP *ld, LDAPMessage **chain, char *attr,
	int (*cmp)());
int ldap_sort_values(LDAP *ld, char **vals, int (*cmp)());
int ldap_sort_strcasecmp(char **a, char **b);


/*
 * URL functions
 */
int ldap_is_ldap_url(char *url);
int ldap_url_parse(char *url, LDAPURLDesc **ludpp);
void ldap_free_urlexts(LDAPURLExt **lues);
void ldap_free_urldesc(LDAPURLDesc *ludp);
int ldap_url_search(LDAP *ld, char *url, int attrsonly);
int ldap_url_search_s(LDAP *ld, char *url, int attrsonly,
	LDAPMessage **res);
int ldap_url_search_st(LDAP *ld, char *url, int attrsonly,
	struct timeval *timeout, LDAPMessage **res);
char *ldap_dns_to_url(LDAP *ld, char *dns_name, char *attrs,
char *scope, char *filter);
char *ldap_dn_to_url(LDAP *ld, char *dn, int nameparts);


/*
 * in Character Set functions
 */
#ifdef STR_TRANSLATION
void ldap_set_string_translators(LDAP *ld,
	BERTranslateProc encode_proc, BERTranslateProc decode_proc);
int ldap_translate_from_t61(LDAP *ld, char **bufp,
	unsigned int *lenp, int free_input);
int ldap_translate_to_t61(LDAP *ld, char **bufp,
	unsigned int *lenp, int free_input);
void ldap_enable_translation(LDAP *ld, LDAPMessage *entry,
	int enable);

#ifdef LDAP_CHARSET_8859
int ldap_t61_to_8859(char **bufp, unsigned int *buflenp,
	int free_input);
int ldap_8859_to_t61(char **bufp, unsigned int *buflenp,
	int free_input);
#endif /* LDAP_CHARSET_8859 */
#endif /* STR_TRANSLATION */

/*
 * Diplay Template functions
 */
typedef int (*writeptype)(void *writeparm, char *p, int len);

int ldap_init_templates(char *file,
	struct ldap_disptmpl **tmpllistp);

int ldap_init_templates_buf(char *buf, ssize_t buflen,
	struct ldap_disptmpl **tmpllistp);

void ldap_free_templates(struct ldap_disptmpl *tmpllist);

struct ldap_disptmpl *ldap_first_disptmpl(
	struct ldap_disptmpl *tmpllist);

struct ldap_disptmpl *ldap_next_disptmpl(
	struct ldap_disptmpl *tmpllist, struct ldap_disptmpl *tmpl);

struct ldap_disptmpl *ldap_name2template(char *name,
	struct ldap_disptmpl *tmpllist);

struct ldap_disptmpl *ldap_oc2template(char **oclist,
	struct ldap_disptmpl *tmpllist);

char **ldap_tmplattrs(struct ldap_disptmpl *tmpl,
	char **includeattrs, int exclude, unsigned int syntaxmask);

struct ldap_tmplitem *ldap_first_tmplrow(struct ldap_disptmpl *tmpl);

struct ldap_tmplitem *ldap_next_tmplrow(struct ldap_disptmpl *tmpl,
	struct ldap_tmplitem *row);

struct ldap_tmplitem *ldap_first_tmplcol(struct ldap_disptmpl *tmpl,
	struct ldap_tmplitem *row);

struct ldap_tmplitem *ldap_next_tmplcol(struct ldap_disptmpl *tmpl,
	struct ldap_tmplitem *row, struct ldap_tmplitem *col);

int ldap_entry2text(LDAP *ld, char *buf, LDAPMessage *entry,
	struct ldap_disptmpl *tmpl, char **defattrs, char ***defvals,
	writeptype writeproc, void *writeparm, char *eol,
	int rdncount, unsigned int opts);

int ldap_vals2text(LDAP *ld, char *buf, char **vals, char *label,
	int labelwidth, unsigned int syntaxid, writeptype writeproc,
	void *writeparm, char *eol, int rdncount);

int ldap_entry2text_search(LDAP *ld, char *dn, char *base,
	LDAPMessage *entry, struct ldap_disptmpl *tmpllist,
	char **defattrs, char ***defvals, writeptype writeproc,
	void *writeparm, char *eol, int rdncount, unsigned int opts);

int ldap_entry2html(LDAP *ld, char *buf, LDAPMessage *entry,
	struct ldap_disptmpl *tmpl, char **defattrs, char ***defvals,
	writeptype writeproc, void *writeparm, char *eol,
	int rdncount, unsigned int opts, char *urlprefix, char *base);

int ldap_vals2html(LDAP *ld, char *buf, char **vals, char *label,
	int labelwidth, unsigned int syntaxid, writeptype writeproc,
	void *writeparm, char *eol, int rdncount, char *urlprefix);

int ldap_entry2html_search(LDAP *ld, char *dn, char *base,
	LDAPMessage *entry, struct ldap_disptmpl *tmpllist,
	char **defattrs, char ***defvals, writeptype writeproc,
	void *writeparm, char *eol, int rdncount, unsigned int opts,
	char *urlprefix);


/*
 * Search Preferences functions
 */
int ldap_init_searchprefs(char *file,
	struct ldap_searchobj **solistp);

int ldap_init_searchprefs_buf(char *buf, ssize_t buflen,
	struct ldap_searchobj **solistp);

void ldap_free_searchprefs(struct ldap_searchobj *solist);

struct ldap_searchobj *ldap_first_searchobj(
	struct ldap_searchobj *solist);

struct ldap_searchobj *ldap_next_searchobj(
	struct ldap_searchobj *sollist, struct ldap_searchobj *so);


/*
 * Option functions
 */
int ldap_get_option(LDAP *ld, int option, void *outvalue);
int ldap_set_option(LDAP *ld, int option, void *invalue);


/*
 * Control functions
 */
void ldap_control_free(LDAPControl *ctrl);
void ldap_controls_free(LDAPControl **ctrls);


/*
 * Simple Page Control functions
 */
int ldap_create_page_control(LDAP *ld, unsigned int pagesize,
	struct berval *cookie, char isCritical, LDAPControl **output);
int ldap_parse_page_control(LDAP *ld, LDAPControl **controls,
	unsigned int *totalcount, struct berval **cookie);

/*
 * Server Side Sort control functions
 */
int ldap_create_sort_control(LDAP *ld, LDAPsortkey **sortKeyList,
	const char ctl_iscritical, LDAPControl **ctrlp);
int ldap_parse_sort_control(LDAP *ld, LDAPControl **ctrlp,
	unsigned long *result, char **attribute);
int ldap_create_sort_keylist(LDAPsortkey ***sortKeyList, char *string_rep);
void ldap_free_sort_keylist(LDAPsortkey **sortKeyList);

/*
 * Virtual List View control functions
 */
int ldap_create_virtuallist_control(LDAP *ld, LDAPVirtualList *ldvlistp,
	LDAPControl **ctrlp);
int ldap_parse_virtuallist_control(LDAP *ld, LDAPControl **ctrls,
	unsigned long *target_posp, unsigned long *list_sizep,
	int *errcodep);

#endif /* NEEDPROTOS */

#ifdef __cplusplus
}
#endif

#endif /* _LDAP_H */
