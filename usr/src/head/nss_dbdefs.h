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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Database-specific definitions for the getXXXbyYYY routines
 * (e.g getpwuid_r(), ether_ntohost()) that use the name-service switch.
 * Database-independent definitions are in <nss_common.h>
 *
 * Ideally, this is the only switch header file one would add things
 * to in order to support a new database.
 *
 * NOTE:  The interfaces documented in this file may change in a minor
 *	  release.  It is intended that in the future a stronger committment
 *	  will be made to these interface definitions which will guarantee
 *	  them across minor releases.
 */

#ifndef _NSS_DBDEFS_H
#define	_NSS_DBDEFS_H

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>		/* MAXALIASES, MAXADDRS */
#include <limits.h>		/* LOGNAME_MAX */
#include <nss_common.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef	NSS_INCLUDE_UNSAFE
#define	NSS_INCLUDE_UNSAFE	1	/* Build old, MT-unsafe interfaces, */
#endif	/* NSS_INCLUDE_UNSAFE */	/*  e.g. getpwnam (c.f. getpwnam_r) */

/*
 * Names of the well-known databases.
 */

#define	NSS_DBNAM_ALIASES	"aliases"	/* E-mail aliases, that is */
#define	NSS_DBNAM_AUTOMOUNT	"automount"
#define	NSS_DBNAM_BOOTPARAMS	"bootparams"
#define	NSS_DBNAM_ETHERS	"ethers"
#define	NSS_DBNAM_GROUP		"group"
#define	NSS_DBNAM_HOSTS		"hosts"
#define	NSS_DBNAM_IPNODES	"ipnodes"
#define	NSS_DBNAM_NETGROUP	"netgroup"
#define	NSS_DBNAM_NETMASKS	"netmasks"
#define	NSS_DBNAM_NETWORKS	"networks"
#define	NSS_DBNAM_PASSWD	"passwd"
#define	NSS_DBNAM_PRINTERS	"printers"
#define	NSS_DBNAM_PROJECT	"project"
#define	NSS_DBNAM_PROTOCOLS	"protocols"
#define	NSS_DBNAM_PUBLICKEY	"publickey"
#define	NSS_DBNAM_RPC		"rpc"
#define	NSS_DBNAM_SERVICES	"services"
#define	NSS_DBNAM_AUDITUSER	"audit_user"
#define	NSS_DBNAM_AUTHATTR	"auth_attr"
#define	NSS_DBNAM_EXECATTR	"exec_attr"
#define	NSS_DBNAM_PROFATTR	"prof_attr"
#define	NSS_DBNAM_USERATTR	"user_attr"

#define	NSS_DBNAM_TSOL_TP	"tnrhtp"
#define	NSS_DBNAM_TSOL_RH	"tnrhdb"
#define	NSS_DBNAM_TSOL_ZC	"tnzonecfg"

/* getspnam() et al use the "passwd" config entry but the "shadow" backend */
#define	NSS_DBNAM_SHADOW	"shadow"

/* The "compat" backend gets config entries for these pseudo-databases */
#define	NSS_DBNAM_PASSWD_COMPAT	"passwd_compat"
#define	NSS_DBNAM_GROUP_COMPAT	"group_compat"

/*
 * Default switch configuration, compiled into the front-ends.
 *
 * Absent good reasons to the contrary, this should be compatible with the
 * default /etc/nsswitch.conf file.
 */
#define	NSS_FILES_ONLY		"files"
#define	NSS_FILES_NS		"files nis"
#define	NSS_NS_FALLBACK		"nis [NOTFOUND=return] files"
#define	NSS_NS_ONLY		"nis"
#define	NSS_TSOL_FALLBACK	"files ldap"

#define	NSS_DEFCONF_ALIASES	NSS_FILES_NS
#define	NSS_DEFCONF_AUTOMOUNT	NSS_FILES_NS
#define	NSS_DEFCONF_BOOTPARAMS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_ETHERS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_GROUP	NSS_FILES_NS
#define	NSS_DEFCONF_HOSTS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_IPNODES	NSS_NS_FALLBACK
#define	NSS_DEFCONF_NETGROUP	NSS_NS_ONLY
#define	NSS_DEFCONF_NETMASKS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_NETWORKS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_PASSWD	NSS_FILES_NS
#define	NSS_DEFCONF_PRINTERS	"user files nis"
#define	NSS_DEFCONF_PROJECT	NSS_FILES_NS
#define	NSS_DEFCONF_PROTOCOLS	NSS_NS_FALLBACK
#define	NSS_DEFCONF_PUBLICKEY	NSS_FILES_NS
#define	NSS_DEFCONF_RPC		NSS_NS_FALLBACK
#define	NSS_DEFCONF_SERVICES	NSS_FILES_NS	/* speeds up byname() */

#define	NSS_DEFCONF_GROUP_COMPAT	NSS_NS_ONLY
#define	NSS_DEFCONF_PASSWD_COMPAT	NSS_NS_ONLY

#define	NSS_DEFCONF_ATTRDB	NSS_FILES_NS

#define	NSS_DEFCONF_AUDITUSER	NSS_DEFCONF_PASSWD
#define	NSS_DEFCONF_USERATTR	NSS_DEFCONF_PASSWD
#define	NSS_DEFCONF_AUTHATTR	NSS_DEFCONF_ATTRDB
#define	NSS_DEFCONF_PROFATTR	NSS_DEFCONF_ATTRDB
#define	NSS_DEFCONF_EXECATTR	NSS_DEFCONF_PROFATTR

#define	NSS_DEFCONF_TSOL_TP	NSS_TSOL_FALLBACK
#define	NSS_DEFCONF_TSOL_RH	NSS_TSOL_FALLBACK
#define	NSS_DEFCONF_TSOL_ZC	NSS_TSOL_FALLBACK

/*
 * Line-lengths that the "files" and "compat" backends will try to support.
 * It may be reasonable (even advisable) to use smaller values than these.
 */

#define	NSS_BUFSIZ		1024

#define	NSS_LINELEN_GROUP	((NSS_BUFSIZ) * 8)
#define	NSS_LINELEN_HOSTS	((NSS_BUFSIZ) * 8)
#define	NSS_LINELEN_IPNODES	((NSS_BUFSIZ) * 8)
#define	NSS_LINELEN_NETMASKS	NSS_BUFSIZ
#define	NSS_LINELEN_NETWORKS	NSS_BUFSIZ
#define	NSS_LINELEN_PASSWD	NSS_BUFSIZ
#define	NSS_LINELEN_PRINTERS	NSS_BUFSIZ
#define	NSS_LINELEN_PROJECT	((NSS_BUFSIZ) * 4)
#define	NSS_LINELEN_PROTOCOLS	NSS_BUFSIZ
#define	NSS_LINELEN_PUBLICKEY	NSS_BUFSIZ
#define	NSS_LINELEN_RPC		NSS_BUFSIZ
#define	NSS_LINELEN_SERVICES	NSS_BUFSIZ
#define	NSS_LINELEN_SHADOW	NSS_BUFSIZ
#define	NSS_LINELEN_ETHERS	NSS_BUFSIZ
#define	NSS_LINELEN_BOOTPARAMS	NSS_BUFSIZ

#define	NSS_LINELEN_ATTRDB	NSS_BUFSIZ

#define	NSS_LINELEN_AUDITUSER	NSS_LINELEN_ATTRDB
#define	NSS_LINELEN_AUTHATTR	NSS_LINELEN_ATTRDB
#define	NSS_LINELEN_EXECATTR	NSS_LINELEN_ATTRDB
#define	NSS_LINELEN_PROFATTR	NSS_LINELEN_ATTRDB
#define	NSS_LINELEN_USERATTR	NSS_LINELEN_ATTRDB

#define	NSS_MMAPLEN_EXECATTR	NSS_LINELEN_EXECATTR * 8

#define	NSS_LINELEN_TSOL	NSS_BUFSIZ

#define	NSS_LINELEN_TSOL_TP	NSS_LINELEN_TSOL
#define	NSS_LINELEN_TSOL_RH	NSS_LINELEN_TSOL
#define	NSS_LINELEN_TSOL_ZC	NSS_LINELEN_TSOL

/*
 * Reasonable defaults for 'buflen' values passed to _r functions.  The BSD
 * and SunOS 4.x implementations of the getXXXbyYYY() functions used hard-
 * coded array sizes;  the values here are meant to handle anything that
 * those implementations handled.
 * === These might more reasonably go in <pwd.h>, <netdb.h> et al
 */

#define	NSS_BUFLEN_GROUP	NSS_LINELEN_GROUP
#define	NSS_BUFLEN_HOSTS	\
	(NSS_LINELEN_HOSTS + (MAXALIASES + MAXADDRS + 2) * sizeof (char *))
#define	NSS_BUFLEN_IPNODES	\
	(NSS_LINELEN_IPNODES + (MAXALIASES + MAXADDRS + 2) * sizeof (char *))
#define	NSS_BUFLEN_NETGROUP	(MAXHOSTNAMELEN * 2 + LOGNAME_MAX + 3)
#define	NSS_BUFLEN_NETWORKS	NSS_LINELEN_NETWORKS	/* === ?  + 35 * 4 */
#define	NSS_BUFLEN_PASSWD	NSS_LINELEN_PASSWD
#define	NSS_BUFLEN_PROJECT	(NSS_LINELEN_PROJECT + 800 * sizeof (char *))
#define	NSS_BUFLEN_PROTOCOLS	NSS_LINELEN_PROTOCOLS	/* === ?  + 35 * 4 */
#define	NSS_BUFLEN_PUBLICKEY	NSS_LINELEN_PUBLICKEY
#define	NSS_BUFLEN_RPC		NSS_LINELEN_RPC		/* === ?  + 35 * 4 */
#define	NSS_BUFLEN_SERVICES	NSS_LINELEN_SERVICES	/* === ?  + 35 * 4 */
#define	NSS_BUFLEN_SHADOW	NSS_LINELEN_SHADOW
#define	NSS_BUFLEN_ETHERS	NSS_LINELEN_ETHERS
#define	NSS_BUFLEN_BOOTPARAMS	NSS_LINELEN_BOOTPARAMS

#define	NSS_BUFLEN_ATTRDB	NSS_LINELEN_ATTRDB

#define	NSS_BUFLEN_AUDITUSER	NSS_BUFLEN_ATTRDB
#define	NSS_BUFLEN_AUTHATTR	NSS_BUFLEN_ATTRDB
#define	NSS_BUFLEN_EXECATTR	NSS_BUFLEN_ATTRDB
#define	NSS_BUFLEN_PROFATTR	NSS_BUFLEN_ATTRDB
#define	NSS_BUFLEN_USERATTR	((NSS_BUFLEN_ATTRDB) * 8)

#define	NSS_BUFLEN_TSOL		NSS_LINELEN_TSOL
#define	NSS_BUFLEN_TSOL_TP	NSS_BUFLEN_TSOL
#define	NSS_BUFLEN_TSOL_RH	NSS_BUFLEN_TSOL
#define	NSS_BUFLEN_TSOL_ZC	NSS_BUFLEN_TSOL

/*
 * Default cache door buffer size (2x largest buffer)
 */

#define	NSS_BUFLEN_DOOR		((NSS_BUFSIZ) * 16)

/*
 * Arguments and results, passed between the frontends and backends for
 * the well-known databases.  The getXbyY_r() and getXent_r() routines
 * use a common format that is further described below;  other routines
 * use their own formats.
 */

/*
 * The nss_str2ent_t routine is the data marshaller for the nsswitch.
 * it converts 'native files' format into 'entry' format as part of the
 * return processing for a getXbyY interface.
 *
 * The nss_groupstr_t routine does the real work for any backend
 * that can supply a netgroup entry as a string in /etc/group format
 */
typedef int		(*nss_str2ent_t)(const char *in, int inlen,
				void *ent, char *buf, int buflen);

struct nss_groupsbymem;		/* forward definition */
typedef nss_status_t	(*nss_groupstr_t)(const char *instr, int inlen,
				struct nss_groupsbymem *);

/*
 * The initgroups() function [see initgroups(3c)] needs to find all the
 *   groups to which a given user belongs.  To do this it calls
 *   _getgroupsbymember(), which is part of the frontend for the "group"
 *   database.
 * We want the same effect as if we used getgrent_r() to enumerate the
 *   entire groups database (possibly from multiple sources), but getgrent_r()
 *   is too inefficient.  Most backends can do better if they know they're
 *   meant to scan all groups;  hence there's a separate backend operation,
 *   NSS_DBOP_GROUP_BYMEMBER, which uses the nss_groupsbymem struct.
 * Note that the normal return-value from such a backend, even when it
 *   successfully finds matching group entries, is NSS_NOTFOUND, because
 *   this tells the switch engine to keep searching in any more sources.
 *   In fact, the backends only return NSS_SUCCESS if they find enough
 *   matching entries that the gid_array is completely filled, in which
 *   case the switch engine should stop searching.
 * If the force_slow_way field is set, the backend should eschew any cached
 *   information (e.g. the YP netid.byname map or the NIS+ cred.org_dir table)
 *   and should instead grind its way through the group map/table/whatever.
 */

struct nss_groupsbymem {			/* For _getgroupsbymember() */
/* in: */
	const char	*username;
	gid_t		*gid_array;
	int		maxgids;
	int		force_slow_way;
	nss_str2ent_t	str2ent;
	nss_groupstr_t	process_cstr;

/* in_out: */
	int		numgids;
};

/*
 * The netgroup routines are handled as follows:
 *
 *   Policy decision:
 *	If netgroup A refers to netgroup B, both must occur in the same
 *	source (other choices give very confusing semantics).  This
 *	assumption is deeply embedded in the frontend and backends.
 *
 *    -	setnetgrent(), despite its name, is really a getXXXbyYYY operation:
 *	it takes a name and finds a netgroup with that name (see the
 *	nss_setnetgrent_args struct below).  The "result" that it returns
 *	to the frontend is an nss_backend_t for a pseudo-backend that allows
 *	one to enumerate the members of that netgroup.
 *
 *    -	getnetgrent() calls the 'getXXXent' function in the pseudo-backend;
 *	it doesn't go through the switch engine at all.  It uses the
 *	nss_getnetgrent_args struct below.
 *
 *    -	innetgr() is implemented on top of __multi_innetgr(), which replaces
 *	each (char *) argument of innetgr() with a counted vector of (char *).
 *	The semantics are the same as an OR of the results of innetgr()
 *	operations on each possible 4-tuple picked from the arguments, but
 *	it's possible to implement some cases more efficiently.  This is
 *	important for mountd, which used to read YP netgroup.byhost directly
 *	in order to determine efficiently whether a given host belonged to any
 *	one of a long list of netgroups.  Wildcarded arguments are indicated
 *	by a count of zero.
 *
 *    -	__multi_innetgr() uses the nss_innetgr_args struct.  A backend whose
 *	source contains at least one of the groups listed in the 'groups'
 *	vector will return NSS_SUCCESS and will set the 'status' field to
 *	indicate whether any 4-tuple was satisfied.  A backend will only
 *	return NSS_NOTFOUND if the source contained none of the groups
 *	listed in the 'groups' vector.
 */

enum nss_netgr_argn {		/* We need (machine, user, domain) triples */
	NSS_NETGR_MACHINE = 0,
	NSS_NETGR_USER = 1,
	NSS_NETGR_DOMAIN = 2,
	NSS_NETGR_N = 3
};

enum nss_netgr_status {		/* Status from setnetgrent, multi_innetgr */
	NSS_NETGR_FOUND = 0,
	NSS_NETGR_NO = 1,
	NSS_NETGR_NOMEM = 2
};

struct nss_setnetgrent_args {
/* in: */
	const char		*netgroup;
/* out: */
	nss_backend_t		*iterator;	/* <==== Explain */
};

struct nss_getnetgrent_args {
/* in: */
	char			*buffer;
	int			buflen;
/* out: */
	enum nss_netgr_status	status;
	char			*retp[NSS_NETGR_N];
};

typedef unsigned	nss_innetgr_argc;    /* 0 means wildcard */
typedef char **		nss_innetgr_argv;    /* === Do we really need these? */

struct nss_innetgr_1arg {
	nss_innetgr_argc	argc;
	nss_innetgr_argv	argv;
};

struct nss_innetgr_args {
/* in: */
	struct nss_innetgr_1arg	arg[NSS_NETGR_N];
	struct nss_innetgr_1arg groups;
/* out: */
	enum nss_netgr_status	status;
};

/*
 * nss_XbyY_buf_t -- structure containing the generic arguments passwd to
 *   getXXXbyYYY_r() and getXXXent_r() routines.  The (void *) value points to
 *   a struct of the appropriate type, e.g. struct passwd or struct hostent.
 *
 * The functions that allocate and free these structures do no locking at
 * all, since the routines that use them are inherently MT-unsafe anyway.
 */

typedef struct {
	void		*result;	/* "result" parameter to getXbyY_r() */
	char		*buffer;	/* "buffer"     "             "      */
	int		buflen;		/* "buflen"     "             "      */
} nss_XbyY_buf_t;

extern nss_XbyY_buf_t	*_nss_XbyY_buf_alloc(int struct_size, int buffer_size);
extern void		 _nss_XbyY_buf_free(nss_XbyY_buf_t *);

#define	NSS_XbyY_ALLOC(bufpp, str_size, buf_size)		(\
	(*bufpp) == 0						\
	? (*bufpp) = _nss_XbyY_buf_alloc(str_size, buf_size)	\
	: (*bufpp))

#define	NSS_XbyY_FREE(bufpp)	(_nss_XbyY_buf_free(*bufpp), (*bufpp) = 0)

/*
 * The nss_XbyY_args_t struct contains all the information passed between
 * frontends and backends for the getXbyY_r() and getXent() routines,
 * including an nss_XbyY_buf_t and the lookup key (unused for getXXXent_r).
 *
 * The (*str2ent)() member converts a single XXXent from ASCII text to the
 * appropriate struct, storing any pointer data (strings, in_addrs, arrays
 * of these) in the buffer.  The ASCII text is a counted string (*not* a
 * zero-terminated string) whose length is specified by the instr_len
 * parameter.  The text is found at the address specified by instr and
 * the string is treated as readonly. buffer and instr must be non-
 * intersecting memory areas.
 *
 * With the exception of passwd, shadow and group, the text form for these
 * databases allows trailing comments and arbitrary whitespace.  The
 * corresponding str2ent routine assumes that comments, leading whitespace
 * and trailing whitespace have been stripped (and thus assumes that entries
 * consisting only of these have been discarded).
 *
 * The text entries for "rpc" and for the databases described in <netdb.h>
 * follow a common format (a canonical name with a possibly empty list
 * of aliases, and some other value), albeit with minor variations.
 * The function _nss_netdb_aliases() does most of the generic work involved
 * in parsing and marshalling these into the buffer.
 */

typedef union nss_XbyY_key {	/* No tag; backend should know what to expect */
	uid_t		uid;
	gid_t		gid;
	projid_t	projid;
	const char	*name;
	int		number;
	struct {
		int	net;
		int		type;
	}	netaddr;
	struct {
		const char	*addr;
		int		len;
		int		type;
	}	hostaddr;
	struct {
		union {
			const char	*name;
			int		port;
		}		serv;
		const char	*proto;
	}	serv;
	void *ether;
	struct {
		const char	*name;
		const char	*keytype;
	} pkey;
	struct {
		const char	*name;
		int		af_family;
		int		flags;
	}	ipnode;
	void *attrp;	/* for the new attr databases */
} nss_XbyY_key_t;


typedef int		(*nss_key2str_t)(void *buffer, size_t buflen,
				nss_XbyY_key_t *key, size_t *len);


typedef struct nss_XbyY_args {

/* IN */
	nss_XbyY_buf_t	buf;
	int		stayopen;
			/*
			 * Support for setXXXent(stayopen)
			 * Used only in hosts, protocols,
			 * networks, rpc, and services.
			 */
	nss_str2ent_t	str2ent;
	union nss_XbyY_key key;

/* OUT */
	void		*returnval;
	int		erange;
	int		h_errno;	/* For gethost*_r() */
	nss_status_t	status;		/* from the backend last called */
/* NSS2 */
	nss_key2str_t	key2str;	/* IN */
	size_t		returnlen;	/* OUT */

/* NSCD/DOOR data */

/* ... buffer arena follows... */
} nss_XbyY_args_t;



/*
 * nss/nscd v2 interface, packed buffer format
 *
 * A key component of the v2 name service switch is the redirection
 * of all activity to nscd for actual processing.  In the original
 * switch most activity took place in each application, and the nscd
 * cache component was an add-on optional interface.
 *
 * The nscd v1 format was a completely private interface that
 * implemented specific bufferiing formats on a per getXbyY API basis.
 *
 * The nss/nscd v2 interface uses a common header and commonalizes
 * the buffering format as consistently as possible.  The general rule
 * of thumb is that backends are required to assemble their results in
 * "files based" format [IE the format used on a per result basis as
 * returned by the files backend] and then call the standard str2ent
 * interface.  This is the original intended design as used in the files
 * and nis backends.
 *
 * The benefit of this is that the application side library can assemble
 * a request and provide a header and a variable length result buffer via
 * a doors API, and then the nscd side switch can assemble a a getXbyY
 * request providing the result buffer and a str2ent function that copies
 * but does not unpack the result.
 *
 * This results is returned back via the door, and unpacked using the
 * native library side str2ent interface.
 *
 * Additionally, the common header allows extensibility to add new
 * getXbyYs, putXbyYs or other maintenance APIs to/from nscd without
 * changing the existing "old style" backend interfaces.
 *
 * Finally new style getXbyY, putXbyY and backend interfaces can be
 * by adding new operation requests to the header, while old style
 * backwards compatability.
 */

/*
 * nss/nscd v2 callnumber definitions
 */

/*
 * callnumbers are separated by categories, such as:
 * application to nscd requests, nscd to nscd requests,
 * smf to nscd requests, etc.
 */

#define	NSCDV2CATMASK	(0xFF000000)
#define	NSCDV2CALLMASK	(0x00FFFFFF)

/*
 * nss/nscd v2 categories
 */

#define	NSCD_CALLCAT_APP	('a'<<24)
#define	NSCD_CALLCAT_N2N	('n'<<24)

/* nscd v2 app-> nscd callnumbers */

#define	NSCD_SEARCH	(NSCD_CALLCAT_APP|0x01)
#define	NSCD_SETENT	(NSCD_CALLCAT_APP|0x02)
#define	NSCD_GETENT	(NSCD_CALLCAT_APP|0x03)
#define	NSCD_ENDENT	(NSCD_CALLCAT_APP|0x04)
#define	NSCD_PUT	(NSCD_CALLCAT_APP|0x05)
#define	NSCD_GETHINTS	(NSCD_CALLCAT_APP|0x06)

/* nscd v2 SETENT cookie markers */

#define	NSCD_NEW_COOKIE		0
#define	NSCD_LOCAL_COOKIE	1

/* nscd v2 header revision */
/* treated as 0xMMMMmmmm MMMM - Major Rev, mmmm - Minor Rev */

#define	NSCD_HEADER_REV		0x00020000

/*
 * ptr/uint data type used to calculate shared nscd buffer struct sizes
 * sizes/offsets are arbitrarily limited to 32 bits for 32/64 compatibility
 * datatype is 64 bits for possible pointer storage and future use
 */

typedef uint64_t	nssuint_t;

/*
 * nscd v2 buffer layout overview
 *
 * The key interface to nscd moving forward is the doors interface
 * between applications and nscd (NSCD_CALLCAT_APP), and nscd and
 * it's children (NSCD_CALLCAT_N2N).
 *
 * Regardless of the interface used, the buffer layout is consistent.
 * The General Layout is:
 *   [nss_pheader_t][IN key][OUT data results]{extend results}
 *
 *   The header (nss_pheader_t) remains constant.
 *   Keys and key layouts vary between call numbers/requests
 *	NSCD_CALLCAT_APP use key layouts mimics/defines in nss_dbdefs.h
 *	NSCD_CALLCAT_NSN use layouts defined by nscd headers
 *   Data and data results vary between results
 *	NSCD_CALLCAT_APP return "file standard format" output buffers
 *	NSCD_CALLCAT_NSN return data defined by nscd headers
 *   extended results are optional and vary
 *
 */

/*
 * nss_pheader_t -- buffer header structure that contains switch data
 * "packed" by the client into a buffer suitable for transport over
 * nscd's door, and that can be unpacked into a native form within
 * nscd's switch.  Capable of packing and unpacking data ans results.
 *
 * NSCD_HEADER_REV: 0x00020000		16 x uint64 = (128 byte header)
 */

typedef struct {
	uint32_t	nsc_callnumber;		/* packed buffer request */
	uint32_t	nss_dbop;		/* old nss dbop */
	uint32_t	p_ruid;			/* real uid */
	uint32_t	p_euid;			/* effective uid */
	uint32_t	p_version;		/* 0xMMMMmmmm Major/minor */
	uint32_t	p_status;		/* nss_status_t */
	uint32_t	p_errno;		/* errno */
	uint32_t	p_herrno;		/* h_errno */
	nssuint_t	libpriv;		/* reserved (for lib/client) */
	nssuint_t	pbufsiz;		/* buffer size */
	nssuint_t	dbd_off;		/* IN: db desc off */
	nssuint_t	dbd_len;		/* IN: db desc len */
	nssuint_t	key_off;		/* IN: key off */
	nssuint_t	key_len;		/* IN: key len */
	nssuint_t	data_off;		/* OUT: data off */
	nssuint_t	data_len;		/* OUT: data len */
	nssuint_t	ext_off;		/* OUT: extended results off */
	nssuint_t	ext_len;		/* OUT: extended results len */
	nssuint_t	nscdpriv;		/* reserved (for nscd) */
	nssuint_t	reserved1;		/* reserved (TBD) */
} nss_pheader_t;

/*
 * nss_pnetgr_t -- packed offset structure for holding keys used
 * by innetgr (__multi_innetgr) key
 * Key format is:
 *    nss_pnetgr_t
 *     (nssuint_t)[machine_argc] offsets to strings
 *     (nssuint_t)[user_argc] offsets to strings
 *     (nssuint_t)[domain_argc] offsets to strings
 *     (nssuint_t)[groups_argc] offsets to strings
 *     machine,user,domain,groups strings
 */

typedef struct {
	uint32_t	machine_argc;
	uint32_t	user_argc;
	uint32_t	domain_argc;
	uint32_t	groups_argc;
	nssuint_t	machine_offv;
	nssuint_t	user_offv;
	nssuint_t	domain_offv;
	nssuint_t	groups_offv;
} nss_pnetgr_t;


/* status returned by the str2ent parsing routines */
#define	NSS_STR_PARSE_SUCCESS 0
#define	NSS_STR_PARSE_PARSE 1
#define	NSS_STR_PARSE_ERANGE 2

#define	NSS_XbyY_INIT(str, res, bufp, len, func)	(\
	(str)->buf.result = (res),			\
	(str)->buf.buffer = (bufp),			\
	(str)->buf.buflen = (len),			\
	(str)->stayopen  = 0,				\
	(str)->str2ent  = (func),			\
	(str)->key2str  = NULL,				\
	(str)->returnval = 0,				\
	(str)->returnlen = 0,				\
	(str)->h_errno    = 0,				\
	(str)->erange    = 0)

#define	NSS_XbyY_INIT_EXT(str, res, bufp, len, func, kfunc)	(\
	(str)->buf.result = (res),			\
	(str)->buf.buffer = (bufp),			\
	(str)->buf.buflen = (len),			\
	(str)->stayopen  = 0,				\
	(str)->str2ent  = (func),			\
	(str)->key2str  = (kfunc),			\
	(str)->returnval = 0,				\
	(str)->returnlen = 0,				\
	(str)->h_errno    = 0,				\
	(str)->erange    = 0)

#define	NSS_XbyY_FINI(str)				(\
	(str)->returnval == 0 && (str)->erange && (errno = ERANGE), \
	(str)->returnval)

#define	NSS_PACKED_CRED_CHECK(buf, ruid, euid)		(\
	((nss_pheader_t *)(buf))->p_ruid == (ruid) && \
	((nss_pheader_t *)(buf))->p_euid == (euid))

extern char		**_nss_netdb_aliases(const char *, int, char *, int);
extern nss_status_t	nss_default_key2str(void *, size_t, nss_XbyY_args_t *,
					const char *, int, size_t *);
extern nss_status_t	nss_packed_arg_init(void *, size_t, nss_db_root_t *,
					nss_db_initf_t *, int *,
					nss_XbyY_args_t *);
extern nss_status_t	nss_packed_context_init(void *, size_t, nss_db_root_t *,
					nss_db_initf_t *, nss_getent_t **,
					nss_XbyY_args_t *);
extern void		nss_packed_set_status(void *, size_t, nss_status_t,
					nss_XbyY_args_t *);
extern nss_status_t	nss_packed_getkey(void *, size_t, char **, int *,
					nss_XbyY_args_t *);

/*
 * nss_dbop_t values for searches with various keys;  values for
 * destructor/endent/setent/getent are defined in <nss_common.h>
 */

/*
 * These are part of the "Over the wire" IE app->nscd getXbyY
 * op for well known getXbyY's.  Cannot use NSS_DBOP_X_Y directly
 * because NSS_DBOP_next_iter is NOT an incrementing counter value
 * it's a starting offset into an array value.
 */

#define	NSS_DBOP_X(x)			((x)<<16)
#define	NSS_DBOP_XY(x, y)		((x)|(y))

#define	NSS_DBOP_ALIASES	NSS_DBOP_X(1)
#define	NSS_DBOP_AUTOMOUNT	NSS_DBOP_X(2)
#define	NSS_DBOP_BOOTPARAMS	NSS_DBOP_X(3)
#define	NSS_DBOP_ETHERS		NSS_DBOP_X(4)
#define	NSS_DBOP_GROUP		NSS_DBOP_X(5)
#define	NSS_DBOP_HOSTS		NSS_DBOP_X(6)
#define	NSS_DBOP_IPNODES	NSS_DBOP_X(7)
#define	NSS_DBOP_NETGROUP	NSS_DBOP_X(8)
#define	NSS_DBOP_NETMASKS	NSS_DBOP_X(9)
#define	NSS_DBOP_NETWORKS	NSS_DBOP_X(10)
#define	NSS_DBOP_PASSWD		NSS_DBOP_X(11)
#define	NSS_DBOP_PRINTERS	NSS_DBOP_X(12)
#define	NSS_DBOP_PROJECT	NSS_DBOP_X(13)
#define	NSS_DBOP_PROTOCOLS	NSS_DBOP_X(14)
#define	NSS_DBOP_PUBLICKEY	NSS_DBOP_X(15)
#define	NSS_DBOP_RPC		NSS_DBOP_X(16)
#define	NSS_DBOP_SERVICES	NSS_DBOP_X(17)
#define	NSS_DBOP_AUDITUSER	NSS_DBOP_X(18)
#define	NSS_DBOP_AUTHATTR	NSS_DBOP_X(19)
#define	NSS_DBOP_EXECATTR	NSS_DBOP_X(20)
#define	NSS_DBOP_PROFATTR	NSS_DBOP_X(21)
#define	NSS_DBOP_USERATTR	NSS_DBOP_X(22)

#define	NSS_DBOP_GROUP_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_GROUP_BYGID		(NSS_DBOP_GROUP_BYNAME + 1)
#define	NSS_DBOP_GROUP_BYMEMBER		(NSS_DBOP_GROUP_BYGID  + 1)

#define	NSS_DBOP_PASSWD_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_PASSWD_BYUID		(NSS_DBOP_PASSWD_BYNAME + 1)

/* The "compat" backend requires that PASSWD_BYNAME == SHADOW_BYNAME */
/*   (it also requires that both use key.name to pass the username). */
#define	NSS_DBOP_SHADOW_BYNAME		(NSS_DBOP_PASSWD_BYNAME)

#define	NSS_DBOP_PROJECT_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_PROJECT_BYID		(NSS_DBOP_PROJECT_BYNAME + 1)

#define	NSS_DBOP_HOSTS_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_HOSTS_BYADDR		(NSS_DBOP_HOSTS_BYNAME + 1)

#define	NSS_DBOP_IPNODES_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_IPNODES_BYADDR		(NSS_DBOP_IPNODES_BYNAME + 1)

/*
 * NSS_DBOP_NAME_2ADDR
 * NSS_DBOP_ADDR_2NAME
 *                                : are defines for ipv6 api's
 */

#define	NSS_DBOP_NAME_2ADDR		(NSS_DBOP_next_ipv6_iter)
#define	NSS_DBOP_ADDR_2NAME		(NSS_DBOP_NAME_2ADDR + 1)

#define	NSS_DBOP_RPC_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_RPC_BYNUMBER		(NSS_DBOP_RPC_BYNAME + 1)

#define	NSS_DBOP_NETWORKS_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_NETWORKS_BYADDR		(NSS_DBOP_NETWORKS_BYNAME + 1)

#define	NSS_DBOP_SERVICES_BYNAME	(NSS_DBOP_next_iter)
#define	NSS_DBOP_SERVICES_BYPORT	(NSS_DBOP_SERVICES_BYNAME + 1)

#define	NSS_DBOP_PROTOCOLS_BYNAME	(NSS_DBOP_next_iter)
#define	NSS_DBOP_PROTOCOLS_BYNUMBER	(NSS_DBOP_PROTOCOLS_BYNAME + 1)

#define	NSS_DBOP_ETHERS_HOSTTON	(NSS_DBOP_next_noiter)
#define	NSS_DBOP_ETHERS_NTOHOST	(NSS_DBOP_ETHERS_HOSTTON + 1)

#define	NSS_DBOP_BOOTPARAMS_BYNAME	(NSS_DBOP_next_noiter)
#define	NSS_DBOP_NETMASKS_BYNET	(NSS_DBOP_next_noiter)

#define	NSS_DBOP_PRINTERS_BYNAME	(NSS_DBOP_next_iter)

/*
 * The "real" backend for netgroup (__multi_innetgr, setnetgrent)
 */
#define	NSS_DBOP_NETGROUP_IN		(NSS_DBOP_next_iter)
#define	NSS_DBOP_NETGROUP_SET		(NSS_DBOP_NETGROUP_IN  + 1)

/*
 * The backend for getpublickey and getsecretkey (getkeys)
 */
#define	NSS_DBOP_KEYS_BYNAME		(NSS_DBOP_next_iter)

/*
 * The pseudo-backend for netgroup (returned by setnetgrent) doesn't have
 *   any getXXXbyYYY operations, just the usual destr/end/set/get ops,
 *   so needs no definitions here.
 */

#define	NSS_DBOP_ATTRDB_BYNAME		(NSS_DBOP_next_iter)

#define	NSS_DBOP_AUDITUSER_BYNAME	NSS_DBOP_ATTRDB_BYNAME
#define	NSS_DBOP_AUTHATTR_BYNAME	NSS_DBOP_ATTRDB_BYNAME
#define	NSS_DBOP_EXECATTR_BYNAME	NSS_DBOP_ATTRDB_BYNAME
#define	NSS_DBOP_EXECATTR_BYID		(NSS_DBOP_EXECATTR_BYNAME + 1)
#define	NSS_DBOP_EXECATTR_BYNAMEID	(NSS_DBOP_EXECATTR_BYID + 1)
#define	NSS_DBOP_PROFATTR_BYNAME	NSS_DBOP_ATTRDB_BYNAME
#define	NSS_DBOP_USERATTR_BYNAME	NSS_DBOP_ATTRDB_BYNAME

#define	NSS_DBOP_TSOL_TP_BYNAME		(NSS_DBOP_next_iter)
#define	NSS_DBOP_TSOL_RH_BYADDR		(NSS_DBOP_next_iter)
#define	NSS_DBOP_TSOL_ZC_BYNAME		(NSS_DBOP_next_iter)

/*
 * Used all over in the switch code. The best home for it I can think of.
 * Power-of-two alignments only.
 */
#define	ROUND_DOWN(n, align)	(((uintptr_t)n) & ~((align) - 1l))
#define	ROUND_UP(n, align)	ROUND_DOWN(((uintptr_t)n) + (align) - 1l, \
				(align))

#ifdef	__cplusplus
}
#endif

#endif /* _NSS_DBDEFS_H */
