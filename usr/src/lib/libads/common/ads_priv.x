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

%/*
% * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
% */

%/*
% * from ads_priv.x
% * Active Directory Services (ADS) Private interface between
% * libads and the ADS deamon.  (RPC over doors)
% */

#ifdef RPC_HDR
%/*
% *  Declarations for the ADS API
% */

#elif RPC_SVC
%
%/*
% *  Server side stubs for the ADS API
% */
%
#elif RPC_CLNT
%
%/*
% *  Client side stubs for the ADS API
% */
%
#elif RPC_XDR
%/*
% * XDR routines for the ADS API
% */
#endif

const ADSPRIV_MAX_XFER = 16384;
const ADSPRIV_GUID_LEN = 16;
const ADSPRIV_SOCKADDR_LEN = 256;
const ADSPRIV_STR_MAX = 256;

typedef opaque	adspriv_guid[ADSPRIV_GUID_LEN];
typedef opaque	adspriv_sockaddr[ADSPRIV_SOCKADDR_LEN];

/*
 * Structure returned from DsGetDcName
 * NB: Keep same as DOMAIN_CONTROLLER_INFO
 */
struct adspriv_dcinfo {
    string dci_DcName<ADSPRIV_STR_MAX>;
    string dci_DcAddr<ADSPRIV_STR_MAX>;
    unsigned int dci_AddrType;
    adspriv_guid dci_guid;
    string dci_DomainName<ADSPRIV_STR_MAX>;
    string dci_DnsForestName<ADSPRIV_STR_MAX>;
    unsigned int dci_Flags;
    string dci_DcSiteName<ADSPRIV_STR_MAX>;
    string dci_ClientSiteName<ADSPRIV_STR_MAX>;
    adspriv_sockaddr dci_sockaddr;
};

/*
 * DsForceRediscovery args
 */
struct DsForceRediscoveryArgs {
	unsigned int Flags;
	string DomainName<ADSPRIV_STR_MAX>;
};

/*
 * DsGetDcName args, result
 */
struct DsGetDcNameArgs {
	string ComputerName<ADSPRIV_STR_MAX>;
	string DomainName<ADSPRIV_STR_MAX>;
	string DomainGuid<ADSPRIV_STR_MAX>;
	string SiteName<ADSPRIV_STR_MAX>;
	unsigned int Flags;
};

union DsGetDcNameRes switch (int status) {
case 0:
	adspriv_dcinfo res0;
default:
	void;
};

program ADSPRIV_PROGRAM {
	version ADSPRIV_V1 {
		void 
		ADSPRIV_NULL(void) = 0;

		int
		ADSPRIV_ForceRediscovery(DsForceRediscoveryArgs) = 1;

		DsGetDcNameRes
		ADSPRIV_GetDcName(DsGetDcNameArgs) = 2;
	} = 1;
} = 100001;
