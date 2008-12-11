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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_BROWSER_H_
#define	_BROWSER_H_

/*
 * NetBIOS name types describe the functionality of the registration.
 * A following list of NetBIOS suffixes (16th Character of the NetBIOS
 * Name) is detailed in Microsoft knowledge base article Q163409.
 *
 * Name                Number(h)  Type  Usage
 * --------------------------------------------------------------------------
 * <computername>         00       U    Workstation Service
 * <computername>         01       U    Messenger Service
 * <\\--__MSBROWSE__>     01       G    Master Browser
 * <computername>         03       U    Messenger Service
 * <computername>         06       U    RAS Server Service
 * <computername>         1F       U    NetDDE Service
 * <computername>         20       U    File Server Service
 * <computername>         21       U    RAS Client Service
 * <computername>         22       U    Microsoft Exchange Interchange(MSMail
 *                                      Connector)
 * <computername>         23       U    Microsoft Exchange Store
 * <computername>         24       U    Microsoft Exchange Directory
 * <computername>         30       U    Modem Sharing Server Service
 * <computername>         31       U    Modem Sharing Client Service
 * <computername>         43       U    SMS Clients Remote Control
 * <computername>         44       U    SMS Administrators Remote Control
 *                                      Tool
 * <computername>         45       U    SMS Clients Remote Chat
 * <computername>         46       U    SMS Clients Remote Transfer
 * <computername>         4C       U    DEC Pathworks TCPIP service on
 *                                      Windows NT
 * <computername>         52       U    DEC Pathworks TCPIP service on
 *                                      Windows NT
 * <computername>         87       U    Microsoft Exchange Message Transfer
 *                                      Agent
 * <computername>         6A       U    Microsoft Exchange IMC
 * <computername>         BE       U    Network Monitor Agent
 * <computername>         BF       U    Network Monitor Application
 * <username>             03       U    Messenger Service
 * <domain>               00       G    Domain Name
 * <domain>               1B       U    Domain Master Browser
 * <domain>               1C       G    Domain Controllers
 * <domain>               1D       U    Master Browser
 * <domain>               1E       G    Browser Service Elections
 * <INet~Services>        1C       G    IIS
 * <IS~computer name>     00       U    IIS
 * <computername>         [2B]     U    Lotus Notes Server Service
 * IRISMULTICAST          [2F]     G    Lotus Notes
 * IRISNAMESERVER         [33]     G    Lotus Notes
 * Forte_$ND800ZA         [20]     U    DCA IrmaLan Gateway Server Service
 *
 * Unique (U): The name may have only one IP address assigned to it. On
 * a network device multiple occurrences of a single name may appear to
 * be registered. The suffix may be the only unique character in the name.
 *
 * Group (G): A normal group; the single name may exist with many IP
 * addresses. WINS responds to a name query on a group name with the
 * limited broadcast address (255.255.255.255). Because routers block
 * the transmission of these addresses, the Internet Group was designed
 * to service communications between subnets.
 *
 * Multihomed (M): The name is unique, but due to multiple network
 * interfaces on the same computer this configuration is necessary to
 * permit the registration. The maximum number of addresses is 25.
 *
 * Internet Group (I): This is a special configuration of the group name
 * used to manage Windows NT Domain names.
 *
 * Domain Name (D): New in Windows NT 4.0.
 */


#ifdef __cplusplus
extern "C" {
#endif


/*
 * Message flags used when building the SMB transact headers.
 */
#define	TWO_WAY_TRANSACTION			0x00
#define	END_SESSION_TRANSACTION			0x01
#define	ONE_WAY_TRANSACTION				0x02


/*
 * Browser commands associated with the BROWSE and MSBROWSE mailslots.
 */
#define	HOST_ANNOUNCEMENT			0x01
#define	ANNOUNCEMENT_REQUEST			0x02
#define	REQUEST_ELECTION			0x08
#define	GET_BACKUP_LIST_REQ			0x09
#define	GET_BACKUP_LIST_RESP			0x0A
#define	BECOME_BACKUP				0x0B
#define	DOMAIN_ANNOUNCEMENT			0x0C
#define	MASTER_ANNOUNCEMENT			0x0D
#define	LOCAL_MASTER_ANNOUNCEMENT		0x0F


/*
 * Opcodes associated with NETLOGON or NTLOGON mailslots (KB 109626).
 *	LOGON_REQUEST			LM1.0/2.0 LOGON Request from client
 *	LOGON_RESPONSE			LM1.0 Response to LOGON_REQUEST
 *	LOGON_CENTRAL_QUERY		LM1.0 QUERY for centralized init
 *	LOGON_DISTRIB_QUERY		LM1.0 QUERY for non-centralized init
 *	LOGON_CENTRAL_RESPONSE		LM1.0 response to LOGON_CENTRAL_QUERY
 *	LOGON_DISTRIB_RESPONSE		LM1.0 resp to LOGON_DISTRIB_QUERY
 *	LOGON_RESPONSE2			LM2.0 Response to LOGON_REQUEST
 *	LOGON_PRIMARY_QUERY		QUERY for Primary DC
 *	LOGON_START_PRIMARY		announce startup of Primary DC
 *	LOGON_FAIL_PRIMARY		announce failed  Primary DC
 *	LOGON_UAS_CHANGE		announce change to UAS or SAM
 *	LOGON_NO_USER			announce no user on machine
 *	LOGON_PRIMARY_RESPONSE		response to LOGON_PRIMARY_QUERY
 *	LOGON_RELOGON_RESPONSE		LM1.0/2.0 resp to relogon request
 *	LOGON_WKSTINFO_RESPONSE		LM1.0/2.0 resp to interrogate request
 *	LOGON_PAUSE_RESPONSE		LM2.0 resp when NETLOGON is paused
 *	LOGON_USER_UNKNOWN		LM2.0 response when user is unknown
 *	LOGON_UPDATE_ACCOUNT		LM2.1 announce account updates
 *	LOGON_SAM_LOGON_REQUEST		SAM LOGON request from client
 *	LOGON_SAM_LOGON_RESPONSE	SAM Response to SAM logon request
 *	LOGON_SAM_PAUSE_RESPONSE	SAM response when NETLOGON is paused
 *	LOGON_SAM_USER_UNKNOWN		SAM response when user is unknown
 *	LOGON_SAM_WKSTINFO_RESPONSE	SAM response to interrogate request
 */
#define	LOGON_REQUEST			0
#define	LOGON_RESPONSE			1
#define	LOGON_CENTRAL_QUERY		2
#define	LOGON_DISTRIB_QUERY		3
#define	LOGON_CENTRAL_RESPONSE		4
#define	LOGON_DISTRIB_RESPONSE		5
#define	LOGON_RESPONSE2			6
#define	LOGON_PRIMARY_QUERY		7
#define	LOGON_START_PRIMARY		8
#define	LOGON_FAIL_PRIMARY		9
#define	LOGON_UAS_CHANGE		10
#define	LOGON_NO_USER			11
#define	LOGON_PRIMARY_RESPONSE		12
#define	LOGON_RELOGON_RESPONSE		13
#define	LOGON_WKSTINFO_RESPONSE		14
#define	LOGON_PAUSE_RESPONSE		15
#define	LOGON_USER_UNKNOWN		16
#define	LOGON_UPDATE_ACCOUNT		17
#define	LOGON_SAM_LOGON_REQUEST		18
#define	LOGON_SAM_LOGON_RESPONSE	19
#define	LOGON_SAM_PAUSE_RESPONSE	20
#define	LOGON_SAM_USER_UNKNOWN		21
#define	LOGON_SAM_WKSTINFO_RESPONSE	22


/*
 * Local protocol flags used to indicate which version of the
 * netlogon protocol to use when attempting to find the PDC.
 */
#define	NETLOGON_PROTO_NETLOGON			0x01
#define	NETLOGON_PROTO_SAMLOGON			0x02

typedef struct smb_ntdomain_t {
	char 		n_domain[SMB_PI_MAX_DOMAIN];
	char 		n_name[SMB_PI_MAX_DOMAIN];
	uint32_t	n_ipaddr;
} smb_ntdomain_t;

#ifdef __cplusplus
}
#endif


#endif /* _BROWSER_H_ */
