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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_MM_COMMANDS_H
#define	_MM_COMMANDS_H


#ifdef	__cplusplus
extern "C" {
#endif

#define	RESPONSE_STR "response"
#define	SUCCESS_STR "success"
#define	ERROR_STR "error"
#define	UNACCEPTABLE_STR "unacceptable"
#define	ACCEPTED_STR "accepted"

/* activate */
#define	ACTIVATE_ENABLE "activate task[\"%s\"] enable;"
#define	ACTIVATE_DISABLE "activate task[\"%s\"] disable;"
#define	ACTIVATE_RESERVE "activate task[\"%s\"] reserve;"
#define	ACTIVATE_RELEASE "activate task[\"%s\"] release;"

/* lmp mount */
#define	LMP_MOUNT "mount task[\"%s\"] slot [\"%s\" \"%s\" \"%s\"] "\
			"drive [\"%s\"];"

/* lmp unmount */
#define	LMP_UNMOUNT "unmount task[\"%s\"] fromslot [\"%s\" \"%s\" \"%s\"] "\
			"drive [\"%s\"] toslot [\"%s\" \"%s\" \"%s\"];"

/* lmp private */
#define	LMP_PVT_SET_DRV_GEO "private task[\"%s\"] set [\"drive\" \"%s\" "\
			"\"geometry\" \"%s\"];"
#define	EDRVNODMCONFIGURED	"EDRVNODMCONFIGURED"

/* lmp inject */
#define	LMP_INJECT "inject task[\"%s\"] slotgroup[\"%s\"];"

/* lmp eject */
#define	LMP_EJECT "eject task[\"%s\"] slotgroup[\"%s\"] "
#define	LMP_EJECT_SLOT "slot[\"%s\" \"%s\"] "
#define	LMP_EJECT_END ";"

/* notify events */
#define	NOTIFY_EVENT_CFG "event config [\"%s\" \"%s\" \"%s\"];"
#define	EVENT_CFG_NEW "new"
#define	EVENT_CFG_DELETE "delete"
#define	NOTIFY_EVENT_CFG_CHG "event config [\"%s\" \"change\" \"%s\" \"%s\"];"

/* hello */
#define	MMS_WELCOME "welcome version[\"%s\"] servername[\"%s\"];"
#define	WELCOME_PASS "welcome version[\"%s\"] servername[\"%s\"] "\
			"password[\"%s\"];"
#define	WELCOME_CERT "welcome version[\"%s\"] servername[\"%s\"] "\
			"certificate[\"\n%s\n\" \"%s\"];"
#define	UNWELCOME_DENIED "unwelcome \"SSAI_E_ACCESS_DENIED\";"
#define	UNWELCOME_LANG "unwelcome \"SSAI_E_UNKNOWN_LANGUAGE\";"
#define	UNWELCOME_UNSUP "unwelcome \"SSAI_E_UNSUPPORTED_LANGUAGE\";"
#define	UNWELCOME_DUP "unwelcome \"SSAI_E_DUPLICATE_SESSION\";"
#define	UNWELCOME_PROTO "unwelcome \"SSAI_E_PROTOCOL_ERROR\";"

/* goodbye */
#define	EACCHANDLESTILLINUSE	"EACCHANDLESTILLINUSE"
#define	ENOINSTANCE		"ENOINSTANCE"
#define	ENOSESSION 		"ENOSESSION"
#define	ECONNDELETE		"ECONNDELETE"

/* shutdown */

/* response */
#define	RESPONSE_ACCEPTED "response task[\"%s\"] accepted;"
#define	RESPONSE_UNACCEPTABLE "response unacceptable;"
#define	RESPONSE_SUCCESS "response task[\"%s\"] success;"
#define	RESPONSE_INTERMEDIATE "response task[\"%s\"] intermediate %s;"
#define	RESPONSE_SUCCESS_TEXT "response task[\"%s\"] success text [%s];"
#define	RESPONSE_SUCCESS_TEXT_DQ "response task[\"%s\"] success text [\"%s\"];"
#define	RESPONSE_SUCCESS_STR "response task[\"%s\"] success %s;"
#define	RESPONSE_ERROR "response task[\"%s\"] error [%s %s];"
#define	RESPONSE_ERROR_STR "response task[\"%s\"] error [%s %s] %s;"
#define	RESPONSE_ERROR_TEXT "response task[\"%s\"] error [%s %s] "\
	"message [ id [ \"%s\" \"%s\" \"%d\" ] arguments [ %s ] "\
	"loctext [ \"%s\" \"%s\" ] ];"
#define	SIMPLE_RESPONSE_ERROR_TEXT "response task[\"%s\"] error [%s %s] "\
	"message [ id [ \"ieee\" \"1244\" \"5001\" ] "\
	"loctext [ \"en\" \"%s\" ] ];"
#define	RESPONSE_ERROR_ARG "response task[\"%s\"] error [%s %s] "\
	"message [ id [ \"%s\" \"%s\" \"%d\" ] arguments [ %s ] ];"
#define	RESPONSE_CANCELLED "response task[\"%s\"] cancelled;"

/* library/drive online */
#define	ELIBRARYNOEXIST "ELIBRARYNOEXIST"
#define	EDRIVENOEXIST "EDRIVENOEXIST"
#define	ELMNOEXIST "ELMNOEXIST"
#define	ETOOMANYCLAUSES "ETOOMANYCLAUSES"


/* attribute */
#define	EOBJATTRTOOMANY		"EOBJATTRTOOMANY"
#define	EOBJSYSATTRMODDISALLOWED "EOBJSYSATTRMODDISALLOWED"
#define	EOBJSYSATTRMODNOPRIV	"EOBJSYSATTRMODNOPRIV"
#define	EOBJUSRATTRCREATEDISALLOWED "EOBJUSRATTRCREATEDISALLOWED"
#define	EOBJUSRATTRCREATENOPRIV	"EOBJUSRATTRCREATENOPRIV"
#define	EOBJATTRVALNULLSTRING	"EOBJATTRVALNULLSTRING"
#define	EOBJATTRVALNOTNUM	"EOBJATTRVALNOTNUM"
#define	EOBJATTRVALNOTENUM	"EOBJATTRVALNOTENUM"
#define	EOBJKEYCHANGE		"EOBJKEYCHANGE"
#define	EOBJKEYNOTUNIQUE	"EOBJKEYNOTUNIQUE"
#define	EOBJDEPENDNOEXIST	"EOBJDEPENDNOEXIST"
#define	ETRANSACTIONFAILED	"ETRANSACTIONFAILED"
#define	EOBJATTRMODDISALLOWED	"EOBJATTRMODDISALLOWED"
#define	ESYSATTRUNSETDISALLOWED	"ESYSATTRUNSETDISALLOWED"
#define	ESYSTEM			"ESYSTEM"

/* create */
#define	EOBJCREATEDISALLOWED	"EOBJCREATEDISALLOWED"

/* rename */
#define	EVOLINUSE		"EVOLINUSE"
#define	EVOLNAMEREWRITE		"EVOLNAMEREWRITE"
#define	ETRANSACTIONFAILED	"ETRANSACTIONFAILED"
#define	ERENAMEDVOLEXISTS	"ERENAMEDVOLEXISTS"

/* mm_mount */
#define	IMMEDIATE		"immediate"
#define	VOLUME			"VOLUME"
#define	SIDE			"SIDE"
#define	PARTITION		"PARTITION"
#define	EINVALIDTYPE		"EINVALIDTYPE"
#define	ENOMATCH		"ENOMATCH"
#define	ELIBRARYOFFLINE		"ELIBRARYOFFLINE"
#define	EDRIVEOFFLINE		"EDRIVEOFFLINE"

/* shutdown */
#define	ECOMMANDNOPRIVILEGE	"ECOMMANDNOPRIVILEGE"
#define	ESHUTDOWNFAILED		"ESHUTDOWNFAILED"

/* locale */
#define	ELANGNOTSUPPORTED	"ELANGNOTSUPPORTED"
#define	ESORTNOTSUPPORTED	"ESORTNOTSUPPORTED"

#define	LANG_EN			"en"
#define	LANG_EN_US		"en-US"

/* message */
#define	MM_E_CMDARGS		"MM_E_CMDARGS"
#define	MM_E_INTERNAL		"MM_E_INTERNAL"

/* privilege */
#define	ENOSUCHPRIV		"ENOSUCHPRIV"
#define	EPRIVCHANGEDISALLOWED	"EPRIVCHANGEDISALLOWED"
#define	ENOPRIVCHANGE		"ENOPRIVCHANGE"

#define	STANDARD		"standard"
#define	ADMINISTRATOR		"administrator"
#define	SYSTEM_PRIV		"system"

/* begin */
#define	BLOCKING		"blocking"

/* cpscan */
#define	ELIBNOLMCONFIGURED	"ELIBNOLMCONFIGURED"
#define	ELMNOTCONNECTED		"ELMNOTCONNECTED"
#define	ELMDMCOMMUNICATION	"ELMDMCOMMUNICATION"
#define	ETOOMANY		"ETOOMANY"
#define	ELMNOTREADY		"ELMNOTREADY"

/* cpreset */
#define	EDRVNODMCONFIGURED	"EDRVNODMCONFIGURED"
#define	EDMNOTCONNECTED		"EDMNOTCONNECTED"
#define	EDMNOTREADY		"EDMNOTREADY"
#define	EDRIVEONLINE		"EDRIVEONLINE"
#define	ELIBRARYONLINE		"ELIBRARYONLINE"

/* move */
#define	ENOSUCHCART		"ENOSUCHCART"
#define	ECARTNOTLOCATED		"ECARTNOTLOCATED"

/* eject */
#define	EINVALCLAUSEARG		"EINVALCLAUSEARG"
#define	ENOSUCHPCL		"ENOSUCHPCL"
#define	ECARTINUSE		"ECARTINUSE"
#define	ENOSLOT			"ENOSLOT"
#define	ESLOTNOTOCCUPIED	"ESLOTNOTOCCUPIED"

/* allocate */
#define	ENEWVOLEXISTS		"ENEWVOLEXISTS"
#define	ENEWVOLNAMECOUNT	"ENEWVOLNAMECOUNT"
#define	ENOTENOUGHPARTITIONS	"ENOTENOUGHPARTITIONS"
#define	EPARTITIONSTATECHANGE	"EPARTITIONSTATECHANGE"
#define	ECARTRIDGESTATECHANGE	"ECARTRIDGESTATECHANGE"

/* lm */
#define	ELMSTILLBOOTING		"ELMSTILLBOOTING"
#define	ELMNOTCONNECTED		"ELMNOTCONNECTED"
#define	ELMDMCOMMUNICATION	"ELMDMCOMMUNICATION"

/* accept */
#define	ENOSUCHREQ		"ENOSUCHREQ"
#define	EREQUESTALREADYACCEPTED	"EREQUESTALREADYACCEPTED"
#define	EREQUESTALREADYSATISFIED "EREQUESTALREADYSATISFIED"
#define	EREQSTATECHANGEFAILED	"EREQSTATECHANGEFAILED"

/* respond */
#define	EREQUESTNOTACCEPTED	"EREQUESTNOTACCEPTED"
#define	EREQACCEPTEDBYDIFFSESS	"EREQACCEPTEDBYDIFFSESS"

/* release */
#define	EREQUESTNOTACCEPTED	"EREQUESTNOTACCEPTED"

/* cancel */
#define	ENOCANCELLABLETASKS	"ENOCANCELLABLETASKS"
#define	EDM_E_NOTASK		"EDM_E_NOTASK"
#define	EDM_E_NOCANC		"EDM_E_NOCANC"
#define	ELM_E_NOTASK		"ELM_E_NOTASK"
#define	ELM_E_NOCANC		"ELM_E_NOCANC"

/* direct */
#define	ECOMMUNICATION		"ECOMMUNICATION"
#define	ENOTCONNECTED		"ENOTCONNECTED"

/* Error classes */
#define	ECLASS_LANGUAGE		"language"
#define	ECLASS_EXPLICIT		"explicit"
#define	ECLASS_INTERNAL		"internal"
#define	ECLASS_INVALID		"invalid"
#define	ECLASS_DM_INVALID	"dm_invalid"
#define	ECLASS_DM_CONFIG	"dm_config"
#define	ECLASS_RETRY		"retry"
#define	ECLASS_EXIST		"exist"
#define	ECLASS_SUBOP		"subop"
#define	ECLASS_CONFIG		"config"
#define	ECLASS_STATE		"state"
#define	ECLASS_PERMPRIV		"permpriv"
#define	ECLASS_COMPAT		"compat"

/*
 * Vendor-defined error codes
 */

/* Sun MM System error codes */
#define	EDATABASE		"EDATABASE"
#define	ESYNTAX			"ESYNTAX"
#define	ENOTFOUND		"ENOTFOUND"
#define	ERESTRICTED		"ERESTRICTED"
#define	EPRIVNOTMMSADMIN	"EPRIVNOTMMSADMIN"
#define	MM_E_NOTASK		"MM_E_NOTASK"
#define	MM_E_TOOMANYTASKS	"MM_E_TOOMANYTASKS"
#define	ESYSTEMCONFIGCHANGE	"ESYSTEMCONFIGCHANGE"


#ifdef	__cplusplus
}
#endif


#endif	/* _MM_COMMANDS_H */
