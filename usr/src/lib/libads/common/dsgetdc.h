/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Declarations intentionally similar to the MSDN SDK file
 * winsdk/Include/DsGetDC.h
 */


#ifndef	_ADS_DSGETDC_H
#define	_ADS_DSGETDC_H

#include <sys/types.h>
#include <sys/uuid.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Flags to passed to DsGetDcName
 */

#define	DS_FORCE_REDISCOVERY		0x00000001

#define	DS_DIRECTORY_SERVICE_REQUIRED	0x00000010
#define	DS_DIRECTORY_SERVICE_PREFERRED	0x00000020
#define	DS_GC_SERVER_REQUIRED		0x00000040
#define	DS_PDC_REQUIRED			0x00000080
#define	DS_BACKGROUND_ONLY		0x00000100
#define	DS_IP_REQUIRED			0x00000200
#define	DS_KDC_REQUIRED			0x00000400
#define	DS_TIMESERV_REQUIRED		0x00000800
#define	DS_WRITABLE_REQUIRED		0x00001000
#define	DS_GOOD_TIMESERV_PREFERRED	0x00002000
#define	DS_AVOID_SELF			0x00004000
#define	DS_ONLY_LDAP_NEEDED		0x00008000


#define	DS_IS_FLAT_NAME			0x00010000
#define	DS_IS_DNS_NAME			0x00020000

#define	DS_RETURN_DNS_NAME		0x40000000
#define	DS_RETURN_FLAT_NAME		0x80000000

/*
 * Structure returned from DsGetDcName
 * NB: Keep same as adspriv_dcinfo
 */

typedef struct _DOMAIN_CONTROLLER_INFO {
	char *DomainControllerName;
	char *DomainControllerAddress;
	uint32_t DomainControllerAddressType;
	uuid_t DomainGuid;
	char *DomainName;
	char *DnsForestName;
	uint32_t Flags;
	char *DcSiteName;
	char *ClientSiteName;
	uint8_t _sockaddr[256];
} DOMAIN_CONTROLLER_INFO, *PDOMAIN_CONTROLLER_INFO;

/*
 * Values for DomainControllerAddressType
 */

#define	DS_INET_ADDRESS		1
#define	DS_NETBIOS_ADDRESS	2

/*
 * Values for returned Flags
 */

#define	DS_PDC_FLAG		0x00000001	/* DC is PDC of Domain */
#define	DS_GC_FLAG		0x00000004	/* DC is a GC of forest */
#define	DS_LDAP_FLAG		0x00000008	/* supports an LDAP server */
#define	DS_DS_FLAG		0x00000010	/* supports a DS and is a */
						/*   Domain Controller */
#define	DS_KDC_FLAG		0x00000020	/* is running KDC service */
#define	DS_TIMESERV_FLAG	0x00000040	/* is running time service */
#define	DS_CLOSEST_FLAG		0x00000080	/* DC is in closest site */
						/*   to the client */
#define	DS_WRITABLE_FLAG	0x00000100	/* DC has a writable DS */
#define	DS_GOOD_TIMESERV_FLAG	0x00000200	/* is running time service */
						/* (and has clock hardware) */
#define	DS_NDNC_FLAG		0x00000400	/* DomainName is non-domain */
						/* NC serviced by the */
						/* LDAP server */
#define	DS_PING_FLAGS		0x0000FFFF	/* Flags returned on ping */

#define	DS_DNS_CONTROLLER_FLAG	0x20000000	/* DC Name is a DNS name */
#define	DS_DNS_DOMAIN_FLAG	0x40000000	/* DomainName is a DNS name */
#define	DS_DNS_FOREST_FLAG	0x80000000	/* ForestName is a DNS name */


/*
 * Function Prototypes
 */

/* Offial API.  Returns an NT error number. */
extern int
DsGetDcName(const char *ComputerName,
    const char *DomainName, const struct uuid *DomainGuid,
    const char *SiteName, uint32_t Flags,
    DOMAIN_CONTROLLER_INFO **dcinfo);

/* internal version of above - returns a detailed NT status */
extern uint32_t
_DsGetDcName(const char *ComputerName,
    const char *DomainName, const struct uuid *DomainGuid,
    const char *SiteName, uint32_t Flags,
    DOMAIN_CONTROLLER_INFO **dcinfo);

extern int
DsGetSiteName(
    const char *ComputerName,
    char **SiteName);

/*
 * XXX: Others from DsGetDc.h we may want later:
 * DsValidateSubnetName()
 * DsAddressToSiteNames()
 * DsAddressToSiteNamesEx()
 * DsEnumerateDomainTrusts()
 * DsGetForestTrustInformation()
 * DsGetDcSiteCoverage()
 * DsDeregisterDnsHostRecords()
 * DsGetDcOpen(), DsGetDcNext(), DsGetDcClose()
 */

/*
 * Until we can easily allocate a DC Info as one big hunk.
 * This will free a DC Info returned by DsGetDcName().
 */
extern void
DsFreeDcInfo(DOMAIN_CONTROLLER_INFO *);

/*
 * Internal function to force DC Rediscovery.
 */
extern int
_DsForceRediscovery(char *domain, int flags);

#ifdef	__cplusplus
}
#endif

#endif	/* _ADS_DSGETDC_H */
