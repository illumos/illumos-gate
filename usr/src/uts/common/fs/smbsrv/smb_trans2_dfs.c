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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <smbsrv/smb_incl.h>


/*
 * trans2_get_dfs_referral
 *
 * The client sends this request to ask the server to convert
 * RequestFilename into an alternate name for this file.  This request can
 * be sent to the server if the server response to the NEGOTIATE SMB
 * included the CAP_DFS capability.  The TID of the request must be IPC$.
 * Bit15 of Flags2 in the SMB header must be set, indicating this is a
 * UNICODE request.
 *
 * Client Request              Description
 * ==========================  =========================================
 * WordCount                   15
 * TotalDataCount              0
 * SetupCount                  1
 * Setup[0]                    TRANS2_GET_DFS_REFERRAL
 *
 * Parameter Block Encoding    Description
 * ==========================  =========================================
 * USHORT MaxReferralLevel     Latest referral version number understood
 * WCHAR RequestFileName;      DFS name of file for which referral is
 *                             sought
 *
 * Response Data Block         Description
 * ==========================  =========================================
 * USHORT PathConsumed;        Number of RequestFilename bytes client
 * USHORT NumberOfReferrals;   Number of referrals contained in this
 *                             response
 * USHORT Flags;               bit0 - The servers in Referrals are
 *                             capable of fielding
 *                             TRANS2_GET_DFS_REFERRAL.
 *                             bit1 - The servers in Referrals should
 *                             hold the storage for the requested file.
 * REFERRAL_LIST Referrals[]   Set of referrals for this file
 * UNICODESTRINGE Strings      Used to hold the strings pointed to by
 *                             Version 2 Referrals in REFERRALS.
 *
 * The server response is a list of Referrals which inform the client where
 * it should resubmit the request to obtain access to the file.
 * PathConsumed in the response indicates to the client how many characters
 * of  RequestFilename have been consumed by the server.  When the client
 * chooses one of the referrals to use for file access, the client may need
 * to strip the leading PathConsumed characters from the front of
 * RequestFileName before submitting the name to the target server.
 * Whether or not the pathname should be trimmed is indicated by the
 * individual referral as detailed below.
 *
 * Flags indicates how this referral should be treated.  If bit0 is clear,
 * any entity in the Referrals list holds the storage for RequestFileName.
 * If bit0 is set, any entity in the Referrals list has further referral
 * information for RequestFilename – a TRANS2_GET_DFS_REFERRAL request
 * should be sent to an entity in the Referrals list for further
 * resolution.
 *
 * The format of an individual referral contains version and  length
 * information allowing the client to skip referrals it does not
 * understand.  MaxReferralLevel indicates to the server the latest version
 * of referral which the client can digest.  Since each referral has a
 * uniform element, MaxReferralLevel is advisory only. Each element in
 * Referrals has this envelope:
 *
 * REFERRAL_LIST element
 * ======================================================================
 *
 * USHORT VersionNumber        Version of this referral element
 *
 * USHORT ReferralSize         Size of this referral element
 *
 * The following referral element versions are defined:
 *
 * Version 1 Referral Element Format
 * ======================================================================
 *
 * USHORT ServerType           Type of Node handling referral:
 *                             0 - Don't know
 *                             1 - SMB Server
 *                             2 - Netware Server
 *                             3 - Domain
 *
 * USHORT ReferralFlags        Flags which describe this referral:
 *                             01 - Strip off PathConsumed characters
 *                             before submitting RequestFileName to Node
 *
 * UNICODESTRING Node          Name of entity to visit next
 *
 * Version 2 Referral Element Format
 * ======================================================================
 *
 * USHORT ServerType              Type of Node handling referral:
 *                                 0 - Don't know
 *                                 1 - SMB Server
 *                                 2 - Netware Server
 *                                 3 - Domain
 *
 * USHORT ReferralFlags           Flags which describe this referral:
 *                                 01 - Strip off PathConsumed characters
 *                                 before submitting RequestFileName to
 *                                 Node
 *
 * ULONG Proximity                A hint describing the proximity of this
 *                                 server to the client. 0 indicates the
 *                                 closest, higher numbers indicate
 *                                 increasingly "distant" servers. The
 *                                 number is only relevant within the
 *                                 context of the servers listed in this
 *                                 particular SMB.
 *
 * ULONG TimeToLive               Number of seconds for which the client
 *                                 can cache this referral.
 *
 * USHORT DfsPathOffset           Offset, in bytes from the beginning of
 *                                 this referral, of  the DFS Path that
 *                                 matched PathConsumed bytes of the
 *                                 RequestFileName.
 *
 * USHORT DfsAlternatePathOffset  Offset, in bytes from the beginning of
 *                                 this referral, of an alternate name
 *                                 (8.3 format) of the DFS Path that
 *                                 matched PathConsumed bytes of the
 *                                 RequestFileName.
 *
 * USHORT NetworkAddressOffset    Offset, in bytes from the beginning of
 *                                 this referral, of the entity to visit
 *                                 next.
 *
 * The CIFS protocol imposes no referral selection policy.
 */
int /*ARGSUSED*/
smb_com_trans2_get_dfs_referral(struct smb_request *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}


/*
 * SMB: trans2_report_dfs_inconsistency
 *
 * As part of the Distributed Name Resolution algorithm, a DFS client may
 * discover a  knowledge inconsistency between the referral server (i.e.,
 * the server that handed out a referral), and the storage server (i.e.,
 * the server to which the client was redirected to by the referral
 * server). When such an inconsistency is discovered, the DFS client
 * optionally sends this SMB to the referral server, allowing the referral
 * server to take corrective action.
 *
 * Client Request                     Description
 * ================================== ==================================
 * WordCount                          15
 * MaxParameterCount                  0
 * SetupCount                         1
 * Setup[0]                           TRANS2_REPORT_DFS_INCONSISTENCY
 *
 * Parameter Block Encoding           Description
 * ================================== ==================================
 *
 * UNICODESTRING RequestFileName;     DFS Name of file for which
 *                                     referral was sought
 *
 * The data part of this request contains the referral element (Version 1
 * format only) believed to be in error.  These are encoded as described in
 * the TRANS2_GET_DFS_REFERRAL response.  If the server returns success,
 * the client can resubmit the TRANS2_GET_DFS_REFERRAL request to this
 * server to get a new referral.  It is not mandatory for the DFS knowledge
 * to be automatically repaired – the client must be prepared to receive
 * further errant referrals and must not wind up looping between this
 * request and the TRANS2_GET_DFS_REFERRAL request.
 *
 * Bit15 of Flags2 in the SMB header must be set, indicating this is a
 * UNICODE request.
 */
int /*ARGSUSED*/
smb_com_trans2_report_dfs_inconsistency(struct smb_request *sr)
{
	return (SDRC_NOT_IMPLEMENTED);
}
