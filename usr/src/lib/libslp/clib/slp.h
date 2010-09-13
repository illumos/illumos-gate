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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef	_SLP_H
#define	_SLP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains definitions for the Service Location Protocol
 * C API bindings. More detailed descriptions can be found in the
 * slp_api(3n) man page.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The SLPURLLifetime enum contains URL lifetime values, in seconds,
 * that are frequently used. If a service is registered with a lifetime
 * of SLP_LIFETIME_MAXIMUM, the registration will be effectively
 * permanent, never aging out as long as the SA process is alive.
 */
typedef enum {
	SLP_LIFETIME_DEFAULT = 10800,
	SLP_LIFETIME_MAXIMUM = 65535
} SLPURLLifetime;

/*
 *   The SLPBoolean enum is used as a boolean flag.
 */
typedef enum {
	SLP_FALSE = 0,
	SLP_TRUE = 1
} SLPBoolean;

/*
 *   The SLPSrvURL structure is filled in by the SLPParseSrvURL() function
 *   with information parsed from a character buffer containing URL.
 *   The fields correspond to different parts of the URL. Note that
 *   the structure is conformant with the standard Berkeley sockets
 *   struct servent, with the exception that the pointer to an array of
 *   characters for aliases (s_aliases field) is replaced by the pointer
 *   to host name (s_pcHost field).
 */
typedef struct srvurl {
	char	*s_pcSrvType;	/* service type name */
	char	*s_pcHost;	/* host identification information */
	int	s_iPort;	/* port number, or zero if none */
	char	*s_pcNetFamily;	/* network address family identifier */
	char	*s_pcSrvPart;	/* remainder of the URL */
} SLPSrvURL;

/*
 *   The SLPHandle type is returned by SLPOpen() and is a parameter to all
 *   SLP functions.  It serves as a handle for all resources allocated on
 *   behalf of the process by the SLP library.  The type is opaque, since
 *   the exact nature differs depending on the implementation.
 */
typedef void* SLPHandle;

/*
 *   The SLPError enum contains error codes that are returned from API
 *   functions.
 */
typedef enum {
	SLP_LAST_CALL			= 1,
	SLP_OK				= 0,
	SLP_LANGUAGE_NOT_SUPPORTED	= -1,
	SLP_PARSE_ERROR			= -2,
	SLP_INVALID_REGISTRATION	= -3,
	SLP_SCOPE_NOT_SUPPORTED		= -4,
	SLP_AUTHENTICATION_ABSENT	= -6,
	SLP_AUTHENTICATION_FAILED	= -7,
	SLP_INVALID_UPDATE		= -13,
	SLP_NOT_IMPLEMENTED		= -17,
	SLP_BUFFER_OVERFLOW		= -18,
	SLP_NETWORK_TIMED_OUT		= -19,
	SLP_NETWORK_INIT_FAILED		= -20,
	SLP_MEMORY_ALLOC_FAILED		= -21,
	SLP_PARAMETER_BAD		= -22,
	SLP_NETWORK_ERROR		= -23,
	SLP_INTERNAL_SYSTEM_ERROR	= -24,
	SLP_HANDLE_IN_USE		= -25,
	SLP_TYPE_ERROR			= -26,
	SLP_SECURITY_UNAVAILABLE	= -128
} SLPError;

/*
 *   The SLPRegReport callback type is the type of the callback function
 *   to the SLPReg(), SLPDereg(), and SLPDelAttrs() functions.
 */
typedef void
SLPRegReport(
	SLPHandle	hSLP,		/* operation SLPHandle */
	SLPError	errCode,	/* error code */
	void		*pvCookie	/* client code cookie */
);

/*
 *   The SLPSrvTypeCallback type is the type of the callback function
 *   parameter to SLPFindSrvTypes() function.
 */
typedef SLPBoolean
SLPSrvTypeCallback(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcSrvTypes,	/* list of service types */
	SLPError	errCode,	/* error code */
	void		*pvCookie	/* client code cookie */
);

/*
 *   The SLPSrvURLCallback type is the type of the callback function
 *   parameter to SLPFindSrvs() function.  The client should return a
 */
typedef SLPBoolean
SLPSrvURLCallback(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcSrvURL,	/* the returned service URL */
	unsigned short	usLifetime,	/* life time of the service advert */
	SLPError	errCode,	/* error code */
	void		*pvCookie	/* client code cookie */
);

/*
 *   The SLPAttrCallback type is the type of the callback function
 *   parameter to SLPFindAttrs() function.
 */
typedef SLPBoolean
SLPAttrCallback(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcAttrList,	/* attribute id/value assignments */
	SLPError	errCode,	/* error code */
	void		*pvCookie	/* client code cookie */
);

extern SLPError
SLPOpen(
	const char	*pcLang,	/* natural language locale */
	SLPBoolean	isAsync,	/* asynchronous if true */
	SLPHandle	*phSLP		/* pointer to resulting handle */
);

/*
 * Frees all resources associated with the handle
 */
extern void SLPClose(
	SLPHandle	hSLP		/* handle to be closed */
);

/*
 *   Registers the URL in pcSrvURL having the lifetime usLifetime with the
 *   attribute list in pcAttrs.
 */
extern SLPError
SLPReg(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcSrvURL,	/* the URL to register */
	const unsigned short usLifetime, /* life time of the service advert */
	const char	*pcSrvType,	/* the service type */
	const char	*pcAttrs,	/* attributes of the advertisement */
	SLPBoolean	fresh,		/* fresh registration if true */
	SLPRegReport	callback,	/* receives completion status */
	void		*pvCookie	/* client code cookie */
);

/*
 *   Deregisters the advertisment for URL pURL in all scopes where the
 *   service is registered and all language locales, not just the locale
 *   of the SLPHandle.
 */
extern SLPError
SLPDereg(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcURL,		/* the URL to deregister */
	SLPRegReport	callback,	/* receives completion status */
	void		*pvCookie	/* client code cookie */
);

/*
 *   Delete the selected attributes in the locale of the SLPHandle.
 */
extern SLPError
SLPDelAttrs(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcURL,		/* URL for attrs to deregister */
	const char	*pcAttrs,	/* attributes to deregister */
	SLPRegReport	callback,	/* receives completion status */
	void		*pvCookie	/* client code cookie */
);

/*
 *   The SLPFindSrvType() function issues an SLP service type request
 *   for service types in the scopes indicated by the pcScopeList.  The
 *   results are returned through the callback parameter.
 */
extern SLPError
SLPFindSrvTypes(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcNamingAuthority, /* naming authority to search */
	const char	*pcScopeList,	/* scopes to search */
	SLPSrvTypeCallback callback,	/* receives results */
	void		*pvCookie	/* client code cookie */
);

/*
 *   Issue the query for services on the language specific SLPHandle and
 *   return the results through the callback.
 */
extern SLPError
SLPFindSrvs(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcServiceType,	/* service type string */
	const char	*pcScopeList,	/* scopes to search */
	const char	*pcSearchFilter, /* LDAPv3 Search Filter */
	SLPSrvURLCallback callback,	/* receives results */
	void		*pvCookie	/* client code cookie */
);

/*
 *   This function returns service attributes matching the attribute ids
 *   for the indicated full or partial URL.
 */
extern SLPError
SLPFindAttrs(
	SLPHandle	hSLP,		/* operation SLPHandle */
	const char	*pcURL,		/* the full or partial URL */
	const char	*pcScopeList,	/* scopes to search */
	const char	*pcAttrIds,	/* which attribute values to return */
	SLPAttrCallback	callback,	/* receives results */
	void		*pvCookie	/* client code cookie */
);

/*
 *   Returns the minimum refresh interval, in seconds, that any SA
 *   should use when refreshing registrations. If 0, there is no
 *   minimum interval, and the SA can use what it pleases.
 */
extern unsigned short
SLPGetRefreshInterval();

/*
 *   Sets ppcScopeList parameter to a pointer to a comma separated list
 *   including all available scope values.
 */
extern SLPError
SLPFindScopes(
	SLPHandle	hSLP,		/* operation SLPHandle */
	char		**ppcScopeList	/* pointer to result */
);

/*
 *   Parses the URL passed in as the argument into a service URL structure
 *   and return it in the ppSrvURL pointer.
 */
extern SLPError
SLPParseSrvURL(
	char		*pcSrvURL,	/* URL string to parse */
	SLPSrvURL	**ppSrvURL	/* pointer to result */
);

/*
 *   Frees memory returned from SLPParseSrvURL(), SLPEscape(),
 *   SLPUnescape(), and SLPFindScopes().
 */
extern void
SLPFree(
	void	*pvMem			/* pointer to memory to free */
);

/*
 *   Process the input string in pcInbuf and escape any SLP reserved
 *   characters.
 */
extern SLPError
SLPEscape(
	const char	*pcInbuf,	/* buffer to process */
	char		**ppcOutBuf,	/* pointer to result */
	SLPBoolean	isTag		/* if true, check for bad tag chars */
);

/*
 *   Process the input string in pcInbuf and unescape any SLP reserved
 *   characters.
 */
extern SLPError
SLPUnescape(
	const char	*pcInbuf,	/* buffer to process */
	char		**ppcOutbuf,	/* pointer to result */
	SLPBoolean	isTag		/* if true, check for bad tag chars */
);

/*
 *   Returns the value of the corresponding SLP property name.  The
 *   returned string is owned by the library and MUST NOT be freed.
 */
extern const char *
SLPGetProperty(
	const char	*pcName		/* property name */
);

/*
 *   Sets the value of the SLP property to the new value.  The pcValue
 *   parameter should be the property value as a string.
 */
extern void
SLPSetProperty(
	const char	*pcName,	/* property name */
	const char	*pcValue	/* property value */
);

/*
 * Maps err_code to an SLP error string. The returned string should not
 * be overwritten.
 */
extern const char *
slp_strerror(
	SLPError err_code		/* SLP error code */
);

#ifdef __cplusplus
}
#endif

#endif	/* _SLP_H */
