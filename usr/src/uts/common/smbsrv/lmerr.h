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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SMBSRV_LMERR_H
#define	_SMBSRV_LMERR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the LAN Manager network error definitions. All
 * network error codes are relative to NERR_BASE (2100), assigned by
 * Microsoft, to avoid conflicts with system and redirector error
 * codes. It should be safe to mix NERR error codes with the Win32
 * error codes defined in nterror.h.
 *
 * This file defines error codes in the range 2100 - 2999. NERR values
 * must not exceed MAX_NERR (2999); values above this are used by other
 * services.
 *
 * The range 2750-2799 has been allocated to the IBM LAN Server.
 * The range 2900-2999 has been reserved for Microsoft OEMs.
 *
 * See lmcons.h for information on the full LANMAN error code range.
 *
 * See msdn.microsoft.com for additional information on the meaning
 * of each error code.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	NERR_Success		0

#define	NERR_BASE		2100

/* UNUSED BASE+0 */
/* UNUSED BASE+1 */
#define	NERR_NetNotStarted	(NERR_BASE+2)
#define	NERR_UnknownServer	(NERR_BASE+3)
#define	NERR_ShareMem		(NERR_BASE+4)

#define	NERR_NoNetworkResource	(NERR_BASE+5)
#define	NERR_RemoteOnly		(NERR_BASE+6)
#define	NERR_DevNotRedirected	(NERR_BASE+7)
/* NERR_BASE+8 is used for ERROR_CONNECTED_OTHER_PASSWORD */
/* UNUSED BASE+9 */
/* UNUSED BASE+10 */
/* UNUSED BASE+11 */
/* UNUSED BASE+12 */
/* UNUSED BASE+13 */
#define	NERR_ServerNotStarted	(NERR_BASE+14)
#define	NERR_ItemNotFound	(NERR_BASE+15)
#define	NERR_UnknownDevDir	(NERR_BASE+16)
#define	NERR_RedirectedPath	(NERR_BASE+17)
#define	NERR_DuplicateShare	(NERR_BASE+18)
#define	NERR_NoRoom		(NERR_BASE+19)
/* UNUSED BASE+20 */
#define	NERR_TooManyItems	(NERR_BASE+21)
#define	NERR_InvalidMaxUsers	(NERR_BASE+22)
#define	NERR_BufTooSmall	(NERR_BASE+23)
/* UNUSED BASE+24 */
/* UNUSED BASE+25 */
/* UNUSED BASE+26 */
#define	NERR_RemoteErr		(NERR_BASE+27)
/* UNUSED BASE+28 */
/* UNUSED BASE+29 */
/* UNUSED BASE+30 */
#define	NERR_LanmanIniError	(NERR_BASE+31)
/* UNUSED BASE+32 */
/* UNUSED BASE+33 */
/* UNUSED BASE+34 */
/* UNUSED BASE+35 */
#define	NERR_NetworkError	(NERR_BASE+36)
#define	NERR_WkstaInconsistentState (NERR_BASE+37)
#define	NERR_WkstaNotStarted	(NERR_BASE+38)
#define	NERR_BrowserNotStarted	(NERR_BASE+39)
#define	NERR_InternalError	(NERR_BASE+40)
#define	NERR_BadTransactConfig	(NERR_BASE+41)
#define	NERR_InvalidAPI		(NERR_BASE+42)
#define	NERR_BadEventName	(NERR_BASE+43)
#define	NERR_DupNameReboot	(NERR_BASE+44)

/*
 * Config API related
 * Error codes from BASE+45 to BASE+49
 */
/* UNUSED BASE+45 */
#define	NERR_CfgCompNotFound	(NERR_BASE+46)
#define	NERR_CfgParamNotFound	(NERR_BASE+47)
#define	NERR_LineTooLong	(NERR_BASE+49)

/*
 * Spooler API related
 * Error codes from BASE+50 to BASE+79
 */
#define	NERR_QNotFound		(NERR_BASE+50)
#define	NERR_JobNotFound	(NERR_BASE+51)
#define	NERR_DestNotFound	(NERR_BASE+52)
#define	NERR_DestExists		(NERR_BASE+53)
#define	NERR_QExists		(NERR_BASE+54)
#define	NERR_QNoRoom		(NERR_BASE+55)
#define	NERR_JobNoRoom		(NERR_BASE+56)
#define	NERR_DestNoRoom		(NERR_BASE+57)
#define	NERR_DestIdle		(NERR_BASE+58)
#define	NERR_DestInvalidOp	(NERR_BASE+59)
#define	NERR_ProcNoRespond	(NERR_BASE+60)
#define	NERR_SpoolerNotLoaded	(NERR_BASE+61)
#define	NERR_DestInvalidState	(NERR_BASE+62)
#define	NERR_QInvalidState	(NERR_BASE+63)
#define	NERR_JobInvalidState	(NERR_BASE+64)
#define	NERR_SpoolNoMemory	(NERR_BASE+65)
#define	NERR_DriverNotFound	(NERR_BASE+66)
#define	NERR_DataTypeInvalid	(NERR_BASE+67)
#define	NERR_ProcNotFound	(NERR_BASE+68)

/*
 * Service API related
 * Error codes from BASE+80 to BASE+99
 */
#define	NERR_ServiceTableLocked (NERR_BASE+80)
#define	NERR_ServiceTableFull	(NERR_BASE+81)
#define	NERR_ServiceInstalled	(NERR_BASE+82)
#define	NERR_ServiceEntryLocked (NERR_BASE+83)
#define	NERR_ServiceNotInstalled (NERR_BASE+84)
#define	NERR_BadServiceName	(NERR_BASE+85)
#define	NERR_ServiceCtlTimeout	(NERR_BASE+86)
#define	NERR_ServiceCtlBusy	(NERR_BASE+87)
#define	NERR_BadServiceProgName (NERR_BASE+88)
#define	NERR_ServiceNotCtrl	(NERR_BASE+89)
#define	NERR_ServiceKillProc	(NERR_BASE+90)
#define	NERR_ServiceCtlNotValid (NERR_BASE+91)
#define	NERR_NotInDispatchTbl	(NERR_BASE+92)
#define	NERR_BadControlRecv	(NERR_BASE+93)
#define	NERR_ServiceNotStarting (NERR_BASE+94)

/*
 * Wksta and Logon API related
 * Error codes from BASE+100 to BASE+118
 */
#define	NERR_AlreadyLoggedOn	(NERR_BASE+100)
#define	NERR_NotLoggedOn	(NERR_BASE+101)
#define	NERR_BadUsername	(NERR_BASE+102)
#define	NERR_BadPassword	(NERR_BASE+103)
#define	NERR_UnableToAddName_W	(NERR_BASE+104)
#define	NERR_UnableToAddName_F	(NERR_BASE+105)
#define	NERR_UnableToDelName_W	(NERR_BASE+106)
#define	NERR_UnableToDelName_F	(NERR_BASE+107)
/* UNUSED BASE+108 */
#define	NERR_LogonsPaused	(NERR_BASE+109)
#define	NERR_LogonServerConflict (NERR_BASE+110)
#define	NERR_LogonNoUserPath	(NERR_BASE+111)
#define	NERR_LogonScriptError	(NERR_BASE+112)
/* UNUSED BASE+113 */
#define	NERR_StandaloneLogon	(NERR_BASE+114)
#define	NERR_LogonServerNotFound (NERR_BASE+115)
#define	NERR_LogonDomainExists	(NERR_BASE+116)
#define	NERR_NonValidatedLogon	(NERR_BASE+117)

/*
 * ACF API related (access, user, group)
 * Error codes from BASE+119 to BASE+149
 */
#define	NERR_ACFNotFound	(NERR_BASE+119)
#define	NERR_GroupNotFound	(NERR_BASE+120)
#define	NERR_UserNotFound	(NERR_BASE+121)
#define	NERR_ResourceNotFound	(NERR_BASE+122)
#define	NERR_GroupExists	(NERR_BASE+123)
#define	NERR_UserExists		(NERR_BASE+124)
#define	NERR_ResourceExists	(NERR_BASE+125)
#define	NERR_NotPrimary		(NERR_BASE+126)
#define	NERR_ACFNotLoaded	(NERR_BASE+127)
#define	NERR_ACFNoRoom		(NERR_BASE+128)
#define	NERR_ACFFileIOFail	(NERR_BASE+129)
#define	NERR_ACFTooManyLists	(NERR_BASE+130)
#define	NERR_UserLogon		(NERR_BASE+131)
#define	NERR_ACFNoParent	(NERR_BASE+132)
#define	NERR_CanNotGrowSegment	(NERR_BASE+133)
#define	NERR_SpeGroupOp		(NERR_BASE+134)
#define	NERR_NotInCache		(NERR_BASE+135)
#define	NERR_UserInGroup	(NERR_BASE+136)
#define	NERR_UserNotInGroup	(NERR_BASE+137)
#define	NERR_AccountUndefined	(NERR_BASE+138)
#define	NERR_AccountExpired	(NERR_BASE+139)
#define	NERR_InvalidWorkstation (NERR_BASE+140)
#define	NERR_InvalidLogonHours	(NERR_BASE+141)
#define	NERR_PasswordExpired	(NERR_BASE+142)
#define	NERR_PasswordCantChange (NERR_BASE+143)
#define	NERR_PasswordHistConflict (NERR_BASE+144)
#define	NERR_PasswordTooShort	(NERR_BASE+145)
#define	NERR_PasswordTooRecent	(NERR_BASE+146)
#define	NERR_InvalidDatabase	(NERR_BASE+147)
#define	NERR_DatabaseUpToDate	(NERR_BASE+148)
#define	NERR_SyncRequired	(NERR_BASE+149)

/*
 * Use API related
 * Error codes from BASE+150 to BASE+169
 */
#define	NERR_UseNotFound	(NERR_BASE+150)
#define	NERR_BadAsgType		(NERR_BASE+151)
#define	NERR_DeviceIsShared	(NERR_BASE+152)

/*
 * Message Server related
 * Error codes BASE+170 to BASE+209
 */
#define	NERR_NoComputerName	(NERR_BASE+170)
#define	NERR_MsgAlreadyStarted	(NERR_BASE+171)
#define	NERR_MsgInitFailed	(NERR_BASE+172)
#define	NERR_NameNotFound	(NERR_BASE+173)
#define	NERR_AlreadyForwarded	(NERR_BASE+174)
#define	NERR_AddForwarded	(NERR_BASE+175)
#define	NERR_AlreadyExists	(NERR_BASE+176)
#define	NERR_TooManyNames	(NERR_BASE+177)
#define	NERR_DelComputerName	(NERR_BASE+178)
#define	NERR_LocalForward	(NERR_BASE+179)
#define	NERR_GrpMsgProcessor	(NERR_BASE+180)
#define	NERR_PausedRemote	(NERR_BASE+181)
#define	NERR_BadReceive		(NERR_BASE+182)
#define	NERR_NameInUse		(NERR_BASE+183)
#define	NERR_MsgNotStarted	(NERR_BASE+184)
#define	NERR_NotLocalName	(NERR_BASE+185)
#define	NERR_NoForwardName	(NERR_BASE+186)
#define	NERR_RemoteFull		(NERR_BASE+187)
#define	NERR_NameNotForwarded	(NERR_BASE+188)
#define	NERR_TruncatedBroadcast (NERR_BASE+189)
#define	NERR_InvalidDevice	(NERR_BASE+194)
#define	NERR_WriteFault		(NERR_BASE+195)
/* UNUSED BASE+196 */
#define	NERR_DuplicateName	(NERR_BASE+197)
#define	NERR_DeleteLater	(NERR_BASE+198)
#define	NERR_IncompleteDel	(NERR_BASE+199)
#define	NERR_MultipleNets	(NERR_BASE+200)

/*
 * Server API related
 * Error codes BASE+210 to BASE+229
 */
#define	NERR_NetNameNotFound	(NERR_BASE+210)
#define	NERR_DeviceNotShared	(NERR_BASE+211)
#define	NERR_ClientNameNotFound (NERR_BASE+212)
#define	NERR_FileIdNotFound	(NERR_BASE+214)
#define	NERR_ExecFailure	(NERR_BASE+215)
#define	NERR_TmpFile		(NERR_BASE+216)
#define	NERR_TooMuchData	(NERR_BASE+217)
#define	NERR_DeviceShareConflict (NERR_BASE+218)
#define	NERR_BrowserTableIncomplete (NERR_BASE+219)
#define	NERR_NotLocalDomain	(NERR_BASE+220)
#define	NERR_IsDfsShare		(NERR_BASE+221)

/*
 * CharDev API related
 * Error codes BASE+230 to BASE+249
 */
/* UNUSED BASE+230 */
#define	NERR_DevInvalidOpCode	(NERR_BASE+231)
#define	NERR_DevNotFound	(NERR_BASE+232)
#define	NERR_DevNotOpen		(NERR_BASE+233)
#define	NERR_BadQueueDevString	(NERR_BASE+234)
#define	NERR_BadQueuePriority	(NERR_BASE+235)
#define	NERR_NoCommDevs		(NERR_BASE+237)
#define	NERR_QueueNotFound	(NERR_BASE+238)
#define	NERR_BadDevString	(NERR_BASE+240)
#define	NERR_BadDev		(NERR_BASE+241)
#define	NERR_InUseBySpooler	(NERR_BASE+242)
#define	NERR_CommDevInUse	(NERR_BASE+243)

/*
 * NetICanonicalize and NetIType and NetIMakeLMFileName
 * NetIListCanon and NetINameCheck
 * Error codes BASE+250 to BASE+269
 */
#define	NERR_InvalidComputer   (NERR_BASE+251)
/* UNUSED BASE+252 */
/* UNUSED BASE+253 */
#define	NERR_MaxLenExceeded    (NERR_BASE+254)
/* UNUSED BASE+255 */
#define	NERR_BadComponent	(NERR_BASE+256)
#define	NERR_CantType		(NERR_BASE+257)
/* UNUSED BASE+258 */
/* UNUSED BASE+259 */
#define	NERR_TooManyEntries    (NERR_BASE+262)

/*
 * NetProfile
 * Error codes BASE+270 to BASE+276
 */
#define	NERR_ProfileFileTooBig	(NERR_BASE+270)
#define	NERR_ProfileOffset	(NERR_BASE+271)
#define	NERR_ProfileCleanup	(NERR_BASE+272)
#define	NERR_ProfileUnknownCmd	(NERR_BASE+273)
#define	NERR_ProfileLoadErr	(NERR_BASE+274)
#define	NERR_ProfileSaveErr	(NERR_BASE+275)

/*
 * NetAudit and NetErrorLog
 * Error codes BASE+277 to BASE+279
 */
#define	NERR_LogOverflow	(NERR_BASE+277)
#define	NERR_LogFileChanged	(NERR_BASE+278)
#define	NERR_LogFileCorrupt	(NERR_BASE+279)

/*
 * NetRemote
 * Error codes BASE+280 to BASE+299
 */
#define	NERR_SourceIsDir	(NERR_BASE+280)
#define	NERR_BadSource		(NERR_BASE+281)
#define	NERR_BadDest		(NERR_BASE+282)
#define	NERR_DifferentServers	(NERR_BASE+283)
/* UNUSED BASE+284 */
#define	NERR_RunSrvPaused	(NERR_BASE+285)
/* UNUSED BASE+286 */
/* UNUSED BASE+287 */
/* UNUSED BASE+288 */
#define	NERR_ErrCommRunSrv	(NERR_BASE+289)
/* UNUSED BASE+290 */
#define	NERR_ErrorExecingGhost	(NERR_BASE+291)
#define	NERR_ShareNotFound	(NERR_BASE+292)
/* UNUSED BASE+293 */
/* UNUSED BASE+294 */


/*
 * NetWksta.sys (redir) returned error codes.
 * NERR_BASE + (300-329)
 */
#define	NERR_InvalidLana	(NERR_BASE+300)
#define	NERR_OpenFiles		(NERR_BASE+301)
#define	NERR_ActiveConns	(NERR_BASE+302)
#define	NERR_BadPasswordCore	(NERR_BASE+303)
#define	NERR_DevInUse		(NERR_BASE+304)
#define	NERR_LocalDrive		(NERR_BASE+305)

/*
 * Alert error codes.
 * NERR_BASE + (330-339)
 */
#define	NERR_AlertExists	(NERR_BASE+330)
#define	NERR_TooManyAlerts	(NERR_BASE+331)
#define	NERR_NoSuchAlert	(NERR_BASE+332)
#define	NERR_BadRecipient	(NERR_BASE+333)
#define	NERR_AcctLimitExceeded	(NERR_BASE+334)

/*
 * Additional Error and Audit log codes.
 * NERR_BASE +(340-343)
 */
#define	NERR_InvalidLogSeek	(NERR_BASE+340)
/* UNUSED BASE+341 */
/* UNUSED BASE+342 */
/* UNUSED BASE+343 */

/*
 * Additional UAS and NETLOGON codes
 * NERR_BASE +(350-359)
 */
#define	NERR_BadUasConfig	(NERR_BASE+350)
#define	NERR_InvalidUASOp	(NERR_BASE+351)
#define	NERR_LastAdmin		(NERR_BASE+352)
#define	NERR_DCNotFound		(NERR_BASE+353)
#define	NERR_LogonTrackingError (NERR_BASE+354)
#define	NERR_NetlogonNotStarted (NERR_BASE+355)
#define	NERR_CanNotGrowUASFile	(NERR_BASE+356)
#define	NERR_TimeDiffAtDC	(NERR_BASE+357)
#define	NERR_PasswordMismatch	(NERR_BASE+358)

/*
 * Server Integration error codes.
 * NERR_BASE +(360-369)
 */
#define	NERR_NoSuchServer	(NERR_BASE+360)
#define	NERR_NoSuchSession	(NERR_BASE+361)
#define	NERR_NoSuchConnection	(NERR_BASE+362)
#define	NERR_TooManyServers	(NERR_BASE+363)
#define	NERR_TooManySessions	(NERR_BASE+364)
#define	NERR_TooManyConnections (NERR_BASE+365)
#define	NERR_TooManyFiles	(NERR_BASE+366)
#define	NERR_NoAlternateServers (NERR_BASE+367)
/* UNUSED BASE+368 */
/* UNUSED BASE+369 */
#define	NERR_TryDownLevel		   (NERR_BASE+370)

/*
 * UPS error codes.
 * NERR_BASE + (380-384)
 */
#define	NERR_UPSDriverNotStarted	   (NERR_BASE+380)
#define	NERR_UPSInvalidConfig		   (NERR_BASE+381)
#define	NERR_UPSInvalidCommPort		   (NERR_BASE+382)
#define	NERR_UPSSignalAsserted		   (NERR_BASE+383)
#define	NERR_UPSShutdownFailed		   (NERR_BASE+384)

/*
 * Remoteboot error codes.
 * NERR_BASE + (400-419)
 * Error codes 400 - 405 are used by RPLBOOT.SYS.
 * Error codes 403, 407 - 416 are used by RPLLOADR.COM,
 * Error code 417 is the alerter message of REMOTEBOOT (RPLSERVR.EXE).
 * Error code 418 is for when REMOTEBOOT can't start
 * Error code 419 is for a disallowed 2nd rpl connection
 */
#define	NERR_BadDosRetCode		   (NERR_BASE+400)
#define	NERR_ProgNeedsExtraMem		   (NERR_BASE+401)
#define	NERR_BadDosFunction		   (NERR_BASE+402)
#define	NERR_RemoteBootFailed		   (NERR_BASE+403)
#define	NERR_BadFileCheckSum		   (NERR_BASE+404)
#define	NERR_NoRplBootSystem		   (NERR_BASE+405)
#define	NERR_RplLoadrNetBiosErr		   (NERR_BASE+406)
#define	NERR_RplLoadrDiskErr		   (NERR_BASE+407)
#define	NERR_ImageParamErr		   (NERR_BASE+408)
#define	NERR_TooManyImageParams		   (NERR_BASE+409)
#define	NERR_NonDosFloppyUsed		   (NERR_BASE+410)
#define	NERR_RplBootRestart		   (NERR_BASE+411)
#define	NERR_RplSrvrCallFailed		   (NERR_BASE+412)
#define	NERR_CantConnectRplSrvr		   (NERR_BASE+413)
#define	NERR_CantOpenImageFile		   (NERR_BASE+414)
#define	NERR_CallingRplSrvr		   (NERR_BASE+415)
#define	NERR_StartingRplBoot		   (NERR_BASE+416)
#define	NERR_RplBootServiceTerm		   (NERR_BASE+417)
#define	NERR_RplBootStartFailed		   (NERR_BASE+418)
#define	NERR_RPL_CONNECTED		   (NERR_BASE+419)

/*
 * FTADMIN API error codes
 * NERR_BASE + (425-434)
 * (Currently not used in NT)
 */

/*
 * Browser service API error codes
 * NERR_BASE + (450-475)
 */
#define	NERR_BrowserConfiguredToNotRun	   (NERR_BASE+450)

/*
 * Additional Remoteboot error codes.
 * NERR_BASE + (510-550)
 */
#define	NERR_RplNoAdaptersStarted	   (NERR_BASE+510)
#define	NERR_RplBadRegistry		   (NERR_BASE+511)
#define	NERR_RplBadDatabase		   (NERR_BASE+512)
#define	NERR_RplRplfilesShare		   (NERR_BASE+513)
#define	NERR_RplNotRplServer		   (NERR_BASE+514)
#define	NERR_RplCannotEnum		   (NERR_BASE+515)
#define	NERR_RplWkstaInfoCorrupted	   (NERR_BASE+516)
#define	NERR_RplWkstaNotFound		   (NERR_BASE+517)
#define	NERR_RplWkstaNameUnavailable	   (NERR_BASE+518)
#define	NERR_RplProfileInfoCorrupted	   (NERR_BASE+519)
#define	NERR_RplProfileNotFound		   (NERR_BASE+520)
#define	NERR_RplProfileNameUnavailable	   (NERR_BASE+521)
#define	NERR_RplProfileNotEmpty		   (NERR_BASE+522)
#define	NERR_RplConfigInfoCorrupted	   (NERR_BASE+523)
#define	NERR_RplConfigNotFound		   (NERR_BASE+524)
#define	NERR_RplAdapterInfoCorrupted	   (NERR_BASE+525)
#define	NERR_RplInternal		   (NERR_BASE+526)
#define	NERR_RplVendorInfoCorrupted	   (NERR_BASE+527)
#define	NERR_RplBootInfoCorrupted	   (NERR_BASE+528)
#define	NERR_RplWkstaNeedsUserAcct	   (NERR_BASE+529)
#define	NERR_RplNeedsRPLUSERAcct	   (NERR_BASE+530)
#define	NERR_RplBootNotFound		   (NERR_BASE+531)
#define	NERR_RplIncompatibleProfile	   (NERR_BASE+532)
#define	NERR_RplAdapterNameUnavailable	   (NERR_BASE+533)
#define	NERR_RplConfigNotEmpty		   (NERR_BASE+534)
#define	NERR_RplBootInUse		   (NERR_BASE+535)
#define	NERR_RplBackupDatabase		   (NERR_BASE+536)
#define	NERR_RplAdapterNotFound		   (NERR_BASE+537)
#define	NERR_RplVendorNotFound		   (NERR_BASE+538)
#define	NERR_RplVendorNameUnavailable	   (NERR_BASE+539)
#define	NERR_RplBootNameUnavailable	   (NERR_BASE+540)
#define	NERR_RplConfigNameUnavailable	   (NERR_BASE+541)

/*
 * Dfs API error codes.
 * NERR_BASE + (560-590)
 */
#define	NERR_DfsInternalCorruption	   (NERR_BASE+560)
#define	NERR_DfsVolumeDataCorrupt	   (NERR_BASE+561)
#define	NERR_DfsNoSuchVolume		   (NERR_BASE+562)
#define	NERR_DfsVolumeAlreadyExists	   (NERR_BASE+563)
#define	NERR_DfsAlreadyShared		   (NERR_BASE+564)
#define	NERR_DfsNoSuchShare		   (NERR_BASE+565)
#define	NERR_DfsNotALeafVolume		   (NERR_BASE+566)
#define	NERR_DfsLeafVolume		   (NERR_BASE+567)
#define	NERR_DfsVolumeHasMultipleServers   (NERR_BASE+568)
#define	NERR_DfsCantCreateJunctionPoint	   (NERR_BASE+569)
#define	NERR_DfsServerNotDfsAware	   (NERR_BASE+570)
#define	NERR_DfsBadRenamePath		   (NERR_BASE+571)
#define	NERR_DfsVolumeIsOffline		   (NERR_BASE+572)
#define	NERR_DfsNoSuchServer		   (NERR_BASE+573)
#define	NERR_DfsCyclicalName		   (NERR_BASE+574)
#define	NERR_DfsNotSupportedInServerDfs	   (NERR_BASE+575)
#define	NERR_DfsInternalError		   (NERR_BASE+590)

/*
 * Net setup error codes.
 * NERR_BASE + (591-595)
 */
#define	NERR_SetupAlreadyJoined		   (NERR_BASE+591)
#define	NERR_SetupNotJoined		   (NERR_BASE+592)
#define	NERR_SetupDomainController	   (NERR_BASE+593)

/*
 * MAX_NERR is the last value in the NERR range.
 * Do not exceed this value here.
 */
#define	MAX_NERR			   (NERR_BASE+899)

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_LMERR_H */
