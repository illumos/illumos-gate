%{
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


/*
 * A parser for MMS protocols
 * This parser is called by "mms_parse()".
 *
 *
 * NAME
 *
 * Parser for MMP.
 *
 * SYNOPSIS
 *
 * libpar.a - library of parser functions.
 *
 * #include <mms_list.h>
 * #include <mms_parser.h>
 *
 * int	mms_mmp_parse(mms_par_node_t **cmd_node,
 *			void (*input_func)(char *buf, int *result, int max,
 *			void *callback_parm),
 *			mms_list_t *err_list,
 *			void *callback_parm);
 *
 * void	mms_pn_destroy(mms_par_node_t *cmd_node);
 *
 * void	mms_pe_destroy(mms_list_t *err_list);
 *
 *
 * DESCRIPTION
 *
 * mms_mmp_parse parses an MMP command in XML form and constructs a parse tree.
 *
 *
 * mms_par_node_t **cmd_node
 * 	cmd_node specify the mms_address of a pointer to the root of the
 * 	parse tree. mms_mmp_parse will put the mms_address of the root node
 * 	in pointer.
 *
 * 	After processing the parse tree, mms_pn_destroy() must be called
 * 	to delete resources allocated where the command was parsed.
 *
 * void (*input_func)(char *buf, int *result, int max, void *callback_parm)
 * 	specifies a function that the parser will call when it needs more
 * 	input. input_func() should put additional data into buf. The number
 * 	of bytes should not be more than the value in max. The number of
 * 	bytes is returned in *result. callback_parm is the callback_parm passed
 * 	to mms_mmp_parse.
 * 	If there is no more data, *result should be set to 0.
 *
 * mms_list_t *err_list
 * 	specifies the mms_address of a mms_list_t
 *      which holds a list of mms_par_err_t.
 * 	The parser will add mms_par_err_t to the list when it discovers errors.
 * 	The definition of mms_par_err_t is:
 *
 * 	typedef	struct	mms_par_err {
 * 		mms_list_node_t	pe_next;
 * 		int		pe_code;
 * 		int		pe_line;
 * 		int		pe_col;
 * 		char		*pe_token;
 * 		char		*pe_msg;
 * 	}	mms_par_err_t;
 *
 * 	pe_code has the following values:
 *
 * 	MMS_PE_NOMEM		1			- no memory
 * 	MMS_PE_SYNTAX		2			- Syntax error
 * 	MMS_PE_MAX_LEVEL	3			- max level reached
 * 	MMS_PE_INVAL_CALLBACK	4			- bad return value
 * 	MMS_PE_USERABORT	5			- User abort
 *
 *
 * 	pe_line, pe_col and pe_token indicate the location
 * 	and the token near where the error occured.
 *
 * 	mms_pe_msg is the error message. If the error was MMS_PE_NOMEM,
 * 	mms_pe_msg may be NULL because the parser was unable to obtain
 * 	memory to store the message.
 *
 * 	It is up to the caller to print and examine the mms_par_err_t.
 *
 * 	After the parse tree is processed, mms_pe_destroy() must be
 * 	called to remove the resource allocated for errors.
 *
 * void *callback_parm
 * 	specifies the arguement that should be passed to the callback function.
 * 	If no callback arguement is needed or if no callback processing
 * 	is required, specify NULL.
 *
 * Return value
 * 	mms_mmp_parse returns 0 is ther is no error, returns 1 if the parser
 *         entered an error, the error code is in mms_par_err_t and returns -1
 * 	if mms_mmp_parse was unable to allocate memory for a work area.
 *
 * Parse Tree
 * 	The parser discards the prolog of the XML file. The root of the
 * 	parse tree is the root element of the XML file. Arguements to a
 * 	command, clause and operations are stored in the arglist of the node.
 *
 */

#include <thread.h>
#include <synch.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/int_types.h>
#include <mms_sym.h>
#include "mms_list.h"
#include "mms_parser.h"
#include "mms_par_impl.h"

#define	YYPARSE_PARAM	wka
#define	YYLEX_PARAM	wka
#define	YYERROR_VERBOSE	1

#undef	YYSTYPE
#define		YYSTYPE	mms_stype_t

int	yylex(YYSTYPE * lvalp, void *wka);

#define		mms_mmsp_error(msg)	{				\
		mms_pwka->par_wka_flags |= MMS_PW_ERROR;		\
		mms_par_error(mms_pwka, msg);				\
		if (mms_pwka->par_wka_err_count >= MMS_PE_MAX) {	\
			mms_par_error(mms_pwka, "Too many errors");	\
			YYABORT;					\
		}							\
	}

char *mms_mmp_validate_object(mms_par_node_t *recv);

/*
 * The symbol table will be sorted in ascending order when the parser
 * is initialized. There is no need to add new symbols in any particular order.
 */

mms_sym_t	mms_sym_tab[] = {
	"setpassword", SETPASSWORD,
	"oldpassword", OLDPASSWORD,
	"name", NAME,
	"identity", IDENTITY,
	"online", ONLINE,
	"offline", OFFLINE,
	"event", EVENT,
	"newdrive", NEWDRIVE,
	"newcartridge", NEWCARTRIDGE,
	"request", REQUEST,
	"cartridge", CARTRIDGE,
	"volume", VOLUME,
	"application", APPLICATION,
	"global", GLOBAL,
	"user", USER,
	"direct", DIRECT,
	"data", DATA,
	"volumeid", VOLUMEID,
	"filename", FILENAME,
	"blocksize", BLOCKSIZE,
	"retention", RETENTION,
	"msgfile", MSGFILE,
	"filesequence", FILESEQUENCE,
	"bay", BAY,
	"where", WHERE,
	"CLEAN", CLEAN,
	"signature", SIGNATURE,
	"physicalunmount", PHYSICALUNMOUNT,
	"unmount", UNMOUNT,
	"from", FROM,
	"to", TO,
	"priority", PRIORITY,
	"disconnected", DISCONNECTED,
	"present", PRESENT,
	"broken", BROKEN,
	"response", RESPONSE,
	"hello", HELLO,
	"tag", TAG,
	"alert", ALERT,
	"warning", WARNING,
	"who", WHO,
	"operator", OPERATOR,
	"notice", NOTICE,
	"severity", SEVERITY,
	"debug", DEBUG,
	"log", LOG,
	"emergency", EMERGENCY,
	"critical", CRITICAL,
	"information", INFORMATION,
	"developer", DEVELOPER,
	"get", GET,
	"none", NONE,
	"ansilabel", ANSILABEL,
	"stale", STALE,
	"drivehandle", DRIVEHANDLE,
	"drive", DRIVE_CL,
	"whichtask", WHICHTASK,
	"partition", PARTITION,
	"modename", MODENAME,
	"caplist", CAPLIST,
	"scope", SCOPE,
	"bitformat", BITFORMAT,
	"group", GROUP,
	"cap", CAP,
	"shapepriority", SHAPEPRIORITY,
	"densitypriority", DENSITYPRIORITY,
	"enable", ENABLE,
	"disable", DISABLE,
	"reserve", RESERVE,
	"release", RELEASE,
	"force", FORCE,
	"restart", RESTART,
	"nonewapps", NONEWAPPS,
	"nonewmounts", NONEWMOUNTS,
	"abortqueue", ABORTQUEUE,
	"level", LEVEL,
	"standard", STANDARD,
	"administrator", ADMINISTRATOR,
	"system", SYSTEM_PRIV,
	"sort", SORT,
	"slotgroup", SLOTGROUP,
	"slot", SLOT,
	"abort", ABORT,
	"cartid", CARTID,
	"cart", CART,
	"all", ALL,
	"fromslot", FROMSLOT,
	"toslot", TOSLOT,
	"partial", PARTIAL,
	"full", FULL,
	"AI", AI,
	"APPLICATION", APPLICATION,
	"BAY", BAY,
	"CARTRIDGE", CARTRIDGE,
	"CARTRIDGEGROUP", CARTRIDGEGROUP,
	"CARTRIDGEGROUPAPPLICATION", CARTRIDGEGROUPAPPLICATION,
	"CARTRIDGETYPE", CARTRIDGETYPE,
	"CONNECTION", CONNECTION,
	"LIBRARYACCESS", LIBRARYACCESS,
	"DM", DM,
	"DMBITFORMAT", DMBITFORMAT,
	"DMBITFORMATTOKEN", DMBITFORMATTOKEN,
	"DMCAPABILITY", DMCAPABILITY,
	"DMCAPABILITYDEFAULTTOKEN", DMCAPABILITYDEFAULTTOKEN,
	"DMCAPABILITYGROUP", DMCAPABILITYGROUP,
	"DMCAPABILITYGROUPTOKEN", DMCAPABILITYGROUPTOKEN,
	"DMCAPABILITYTOKEN", DMCAPABILITYTOKEN,
	"DMP", DMP,
	"DRIVE", DRIVE,
	"DRIVECARTRIDGEACCESS", DRIVECARTRIDGEACCESS,
	"DRIVECARTRIDGEERROR", DRIVECARTRIDGEERROR,
	"DRIVEGROUP", DRIVEGROUP,
	"DRIVEGROUPAPPLICATION", DRIVEGROUPAPPLICATION,
	"FIRST", FIRST,
	"LAST", LAST,
	"LIBRARY", LIBRARY,
	"LM", LM,
	"LMP", LMP,
	"MESSAGE", MESSAGE,
	"MMP", MMP,
	"MOUNTLOGICAL", MOUNTLOGICAL,
	"MOUNTPHYSICAL", MOUNTPHYSICAL,
	"NOTIFY", NOTIFY,
	"PARTITION", PARTITION,
	"REQUEST", REQUEST,
	"SESSION", SESSION,
	"SIDE", SIDE,
	"SLOT", SLOT_OBJ,
	"SLOTCONFIG", SLOTCONFIG,
	"SLOTGROUP", SLOTGROUP,
	"SLOTTYPE", SLOTTYPE,
	"STALEHANDLE", STALEHANDLE,
	"SYSTEM", SYSTEM,
	"TASK", TASK,
	"TASKCARTRIDGE", TASKCARTRIDGE,
	"TASKDRIVE", TASKDRIVE,
	"TASKLIBRARY", TASKLIBRARY,
	"VOLUME", VOLUME,
	"message", MESSAGE,
	"accessmode", ACCESSMODE,
	"and", AND,
	"arg", ARG,
	"attr", ATTR,
	"bigendian", BIGENDIAN,
	"block", BLOCK,
	"blocking", BLOCKING,
	"certificate", CERTIFICATE,
	"client", CLIENT,
	"false", FALSE,
	"firstmount", FIRSTMOUNT,
	"immediate", IMMEDIATE,
	"instance", INSTANCE,
	"isattr", ISATTR,
	"isset", ISSET,
	"notset", NOTSET,
	"language", LANGUAGE,
	"littleendian", LITTLEENDIAN,
	"match", MATCH,
	"name", NAME,
	"namevalue", NAMEVALUE,
	"newvolname", NEWVOLNAME,
	"noattr", NOATTR,
	"not", NOT,
	"hosteq", HOSTEQ,
	"hostne", HOSTNE,
	"timeeq", TIMEEQ,
	"timene", TIMENE,
	"timelt", TIMELT,
	"timele", TIMELE,
	"timegt", TIMEGT,
	"timege", TIMEGE,
	"number", NUMBER,
	"numeq", NUMEQ,
	"numge", NUMGE,
	"numgt", NUMGT,
	"numhilo", NUMHILO,
	"numle", NUMLE,
	"numlohi", NUMLOHI,
	"numlt", NUMLT,
	"numne", NUMNE,
	"object", OBJECT,
	"action", ACTION,
	"or", OR,
	"order", ORDER,
	"password", PASSWORD,
	"range", RANGE,
	"regex", REGEX,
	"report", REPORT,
	"reportmode", REPORTMODE,
	"set", SET,
	"streq", STREQ,
	"strge", STRGE,
	"strgt", STRGT,
	"strhilo", STRHILO,
	"strle", STRLE,
	"strlohi", STRLOHI,
	"strlt", STRLT,
	"strne", STRNE,
	"task", TASK,
	"true", TRUE,
	"type", TYPE,
	"unique", UNIQUE,
	"unset", UNSET,
	"value", VALUE,
	"version", VERSION,
	"volname", VOLNAME,
	"when", WHEN,
	"servername", SERVERNAME,
	"id", ID,
	"cancelled", CANCELLED,
	"canceled", CANCELED,
	"success", SUCCESS,
	"intermediate", INTERMEDIATE,
	"loctext", LOCTEXT,
	"text", TEXT,
	"unacceptable", UNACCEPTABLE,
	"arguments", ARGUMENTS,
	"error", ERROR,
	"accepted", ACCEPTED,
	"attrlist", ATTRLIST,
	"reqid", REQID,
	"cpset", CPSET,
	"cpunset", CPUNSET,
	"cpreport", CPREPORT,
	"cpreportmode", CPREPORTMODE,
	"cptype", CPTYPE,
	"receive", RECEIVE,
	"volumeadd", VOLUMEADD,
	"volumedelete", VOLUMEDELETE,
	"dmup", DMUP,
	"dmdown", DMDOWN,
	"driveonline", DRIVEONLINE,
	"driveoffline", DRIVEOFFLINE,
	"lmup", LMUP,
	"lmdown", LMDOWN,
	"volumeinject", VOLUMEINJECT,
	"volumeeject", VOLUMEEJECT,
	"status", STATUS,
	"librarycreate", LIBRARYCREATE,
	"librarydelete", LIBRARYDELETE,
	"drivedelete", DRIVEDELETE,
	"LIBRARYLIST", LIBRARYLIST,
	"DRIVELIST", DRIVELIST,
	"CARTRIDGELIST", CARTRIDGELIST,

#if 0
	/*
	 * These are Error codes
	 */
	"DM_E_ENABLED", ERROR_CODE,
	"DM_E_COMMAND", ERROR_CODE,
	"EOUTOFMEMORY", ERROR_CODE,
	"DM_E_VIDMISMATCH", ERROR_CODE,
	"DM_E_AGAIN", ERROR_CODE,
	"DM_E_BADHANDLE", ERROR_CODE,
	"DM_E_BADVAL", ERROR_CODE,
	"DM_E_CMDARGS", ERROR_CODE,
	"DM_E_DEVADMINCLT", ERROR_CODE,
	"DM_E_DEVCMD", ERROR_CODE,
	"DM_E_DEVCMDABORT", ERROR_CODE,
	"DM_E_DEVCMDILLEGAL", ERROR_CODE,
	"DM_E_DEVCMDTEMEOUT", ERROR_CODE,
	"DM_E_DEVCOMMERR", ERROR_CODE,
	"DM_E_DEVDET", ERROR_CODE,
	"DM_E_DEVEMPTY", ERROR_CODE,
	"DM_E_DEVFULL", ERROR_CODE,
	"DM_E_DEVNORESPONSE", ERROR_CODE,
	"DM_E_DEVOPERATOR", ERROR_CODE,
	"DM_E_DEVOVERFLOW", ERROR_CODE,
	"DM_E_DEVPERM", ERROR_CODE,
	"DM_E_DEVPREV", ERROR_CODE,
	"DM_E_DEVRESET", ERROR_CODE,
	"DM_E_DEVSYNCHERR", ERROR_CODE,
	"DM_E_DRIVE", ERROR_CODE,
	"DM_E_HANDLEBUSY", ERROR_CODE,
	"DM_E_HANDLEINUSE", ERROR_CODE,
	"DM_E_INTERNAL", ERROR_CODE,
	"DM_E_LIBRARY", ERROR_CODE,
	"DM_E_MODE", ERROR_CODE,
	"DM_E_NOCANC", ERROR_CODE,
	"DM_E_NOCART", ERROR_CODE,
	"DM_E_NOELT", ERROR_CODE,
	"DM_E_NOEXISTHANDLE", ERROR_CODE,
	"DM_E_NOID", ERROR_CODE,
	"DM_E_NOTASK", ERROR_CODE,
	"DM_E_READY", ERROR_CODE,
	"DM_E_UNKNOWN", ERROR_CODE,
	"EACCHANDLESTILLINUSE", ERROR_CODE,
	"EAPPACCESSTOCART", ERROR_CODE,
	"EAPPCARTNOACC", ERROR_CODE,
	"EAPPDMDIFFHOSTS", ERROR_CODE,
	"EAPPDRVNOACC", ERROR_CODE,
	"EAPPHASNOVOLS", ERROR_CODE,
	"EAPPLIBNOACCESS", ERROR_CODE,
	"EAPPMOUNTNOTIUSSUED", ERROR_CODE,
	"EAPPSESS", ERROR_CODE,
	"EAPPTASKNOTISSUED", ERROR_CODE,
	"EAUTOCREATEFAILED", ERROR_CODE,
	"ECANCELLED", ERROR_CODE,
	"ECANCELNUMRANGEDISALLOWED", ERROR_CODE,
	"ECANTCANCEL", ERROR_CODE,
	"ECARTDRVNOTCOMPATIBLE", ERROR_CODE,
	"ECARTDRVSLOTMISMATCH", ERROR_CODE,
	"ECARTINSLOT", ERROR_CODE,
	"ECARTINUSE", ERROR_CODE,
	"ECARTMOUNTNOTINVOLVED", ERROR_CODE,
	"ECARTNOACC", ERROR_CODE,
	"ECARTNOCGA", ERROR_CODE,
	"ECARTNOFREEPARTS", ERROR_CODE,
	"ECARTNOTINSLOT", ERROR_CODE,
	"ECARTNOTLOCATED", ERROR_CODE,
	"ECARTNOTOWNEDBYAP", ERROR_CODE,
	"ECARTNOTOWNEDBYAPP", ERROR_CODE,
	"ECLAUSEMISSING", ERROR_CODE,
	"ECLAUSEMUTEX", ERROR_CODE,
	"ECLAUSENEEDSARG", ERROR_CODE,
	"ECLAUSENOPRIVILEGE", ERROR_CODE,
	"ECOMMANDBEINGSUBMITTED", ERROR_CODE,
	"ECOMMANDFAILED", ERROR_CODE,
	"ECOMMANDNOPRIVILEGE", ERROR_CODE,
	"ECONNDELETE", ERROR_CODE,
	"EDMCONFIG", ERROR_CODE,
	"EDMNOTCONNECTED", ERROR_CODE,
	"EDMNOTREADY", ERROR_CODE,
	"EDMPATTACH", ERROR_CODE,
	"EDMPDETACH", ERROR_CODE,
	"EDMPLOAD", ERROR_CODE,
	"EDMPUNLOAD", ERROR_CODE,
	"EDMRECOVERING", ERROR_CODE,
	"EDMSTATE", ERROR_CODE,
	"EDMSTILLBOOTING", ERROR_CODE,
	"EDRIVEEMPTY", ERROR_CODE,
	"EDRIVESET", ERROR_CODE,
	"EDRVBROKEN", ERROR_CODE,
	"EDRVCARTNOTREADABLE", ERROR_CODE,
	"EDRVDISABLEDPERM", ERROR_CODE,
	"EDRVDISABLEDTEMP", ERROR_CODE,
	"EDRVEJECTING", ERROR_CODE,
	"EDRVINUSE", ERROR_CODE,
	"EDRVLOADED", ERROR_CODE,
	"EDRVMOUNTNOTINVOLVED", ERROR_CODE,
	"EDRVNODMCONFIGURED", ERROR_CODE,
	"EDRVNOTINBAY", ERROR_CODE,
	"EDRVNOTLOADED", ERROR_CODE,
	"EDRVSESSNOUSE", ERROR_CODE,
	"EDRVTASKNOTREQUIRED", ERROR_CODE,
	"EDRVUNKNOWN", ERROR_CODE,
	"EHANDLEINUSE", ERROR_CODE,
	"EHANDLENOTDESTROY", ERROR_CODE,
	"EINVALCLAUSEARG", ERROR_CODE,
	"ELANGNOTSUPPORTED", ERROR_CODE,
	"ELIBBROKEN", ERROR_CODE,
	"ELIBCARTNOCONTAINMENT", ERROR_CODE,
	"ELIBDISABLEDPERM", ERROR_CODE,
	"ELIBDISABLEDTEMP", ERROR_CODE,
	"ELIBDRVNOCONTAINMENT", ERROR_CODE,
	"ELIBINUSE", ERROR_CODE,
	"ELIBNOLMCONFIGURED", ERROR_CODE,
	"ELMADD", ERROR_CODE,
	"ELMCARTBAYNOTACCESS", ERROR_CODE,
	"ELMCONFIG", ERROR_CODE,
	"ELMDMCOMMUNICATION", ERROR_CODE,
	"ELMDRVBAYNOTACCESS", ERROR_CODE,
	"ELMDRVNOTACCESS", ERROR_CODE,
	"ELMNOTCONNECTED", ERROR_CODE,
	"ELMNOTREADY", ERROR_CODE,
	"ELMPMOUNT", ERROR_CODE,
	"ELMPORTNOTREADY", ERROR_CODE,
	"ELMPUNMOUNT", ERROR_CODE,
	"ELMSLOTNOTACCESS", ERROR_CODE,
	"ELMSTATE", ERROR_CODE,
	"ELMSTILLBOOTING", ERROR_CODE,
	"EMLOGCREATE", ERROR_CODE,
	"EMLOGDELETE", ERROR_CODE,
	"EMNTCARTPRES", ERROR_CODE,
	"EMOUNTLIBNOTINVOLVED", ERROR_CODE,
	"EMPCREATE", ERROR_CODE,
	"EMPHYSDEL", ERROR_CODE,
	"ENEWVOLEXISTS", ERROR_CODE,
	"ENEWVOLNAMECOUNT", ERROR_CODE,
	"ENOALLOCATABLEPARTS", ERROR_CODE,
	"ENOCANCELLABLETASKS", ERROR_CODE,
	"ENOCARTRIDGE", ERROR_CODE,
	"ENOINSTANCE", ERROR_CODE,
	"ENOMATCH", ERROR_CODE,
	"ENOMEMORY", ERROR_CODE,
	"ENOPRIVCHANGE", ERROR_CODE,
	"ENOSESSION", ERROR_CODE,
	"ENOSLOT", ERROR_CODE,
	"ENOSOLUTIONS", ERROR_CODE,
	"ENOSUCHCART", ERROR_CODE,
	"ENOSUCHLANG", ERROR_CODE,
	"ENOSUCHPRIV", ERROR_CODE,
	"ENOSUCHREQ", ERROR_CODE,
	"ENOSUCHSIDE", ERROR_CODE,
	"ENOSUCHSORT", ERROR_CODE,
	"ENOSUCHVOLUME", ERROR_CODE,
	"EOBJATTRMODDISALLOWED", ERROR_CODE,
	"EOBJATTRTOOMANY", ERROR_CODE,
	"EOBJATTRVALNOTENUM", ERROR_CODE,
	"EOBJATTRVALNOTNUM", ERROR_CODE,
	"EOBJATTRVALNULLSTRING", ERROR_CODE,
	"EOBJCREATEDISALLOWED", ERROR_CODE,
	"EOBJCREATEINVALREPORT", ERROR_CODE,
	"EOBJCREATESYSATTRREQUIRED", ERROR_CODE,
	"EOBJDELDISALLOWED", ERROR_CODE,
	"EOBJDELNUMRANGEDISALLOWED", ERROR_CODE,
	"EOBJDEPENDNOEXIST", ERROR_CODE,
	"EOBJKEYCHANGE", ERROR_CODE,
	"EOBJKEYNOTUNIQUE", ERROR_CODE,
	"EOBJNOTVISIBLE", ERROR_CODE,
	"EOBJREFERENCES", ERROR_CODE,
	"EOBJSYSATTRCREATEDISALLOWED", ERROR_CODE,
	"EOBJSYSATTRMODDISALLOWED", ERROR_CODE,
	"EOBJSYSATTRMODNOPRIV", ERROR_CODE,
	"EOBJUSRATTRCREATEDISALLOWED", ERROR_CODE,
	"EOBJUSRATTRCREATENOPRIV", ERROR_CODE,
	"EPARTNOTALLOCABLE", ERROR_CODE,
	"EPRIVCHANGEDISALLOWED", ERROR_CODE,
	"ERENAMEDVOLEXISTS", ERROR_CODE,
	"EREPLACEFAILED", ERROR_CODE,
	"EREQACCEPTEDBYDIFFSESS", ERROR_CODE,
	"EREQSTATECHANGEFAILED", ERROR_CODE,
	"EREQUESTALREADYACCEPTED", ERROR_CODE,
	"EREQUESTALREADYSATISFIED", ERROR_CODE,
	"EREQUESTNOTACCEPTED", ERROR_CODE,
	"ESESSCARTNOTUSED", ERROR_CODE,
	"ESESSLIBNOTUSED", ERROR_CODE,
	"ESESSMNTNOTISSUED", ERROR_CODE,
	"ESESSTASKNOISSUED", ERROR_CODE,
	"ESHUTDOWNFAILED", ERROR_CODE,
	"ESLOTNOTOCCUPIED", ERROR_CODE,
	"ESLOTOCCUPIED", ERROR_CODE,
	"ESORTNOTSUPPORTED", ERROR_CODE,
	"ESYSATTRUNSETDISALLOWED", ERROR_CODE,
	"ESYSTEM", ERROR_CODE,
	"ETABLELIMIT", ERROR_CODE,
	"ETASKCARTNOUSE", ERROR_CODE,
	"ETASKLIBNOUSE", ERROR_CODE,
	"ETASKMNTNOUSE", ERROR_CODE,
	"ETMPUNAVAIL", ERROR_CODE,
	"ETMPINUSE", ERROR_CODE,
	"ETOOMANY", ERROR_CODE,
	"ETOOMANYCLAUSES", ERROR_CODE,
	"ETRANSACTIONFAILED", ERROR_CODE,
	"EUNKNOWNERROR", ERROR_CODE,
	"EVOLEXISTS", ERROR_CODE,
	"EVOLINUSE", ERROR_CODE,
	"EVOLNAMEREWRITE", ERROR_CODE,
	"EVOLNOTOWNEDBYAPP", ERROR_CODE,
	"EWOULDDEADLOCK", ERROR_CODE,
	"LM_E_ACCESS", ERROR_CODE,
	"LM_E_AGAIN", ERROR_CODE,
	"LM_E_BADVAL", ERROR_CODE,
	"LM_E_CMDARGS", ERROR_CODE,
	"LM_E_DESTFULL", ERROR_CODE,
	"LM_E_DEVADMINCLT", ERROR_CODE,
	"LM_E_DEVCMD", ERROR_CODE,
	"LM_E_DEVCMDABORT", ERROR_CODE,
	"LM_E_DEVCMDILLEGAL", ERROR_CODE,
	"LM_E_DEVCMDTEMEOUT", ERROR_CODE,
	"LM_E_DEVCOMMERR", ERROR_CODE,
	"LM_E_DEVEJ", ERROR_CODE,
	"LM_E_DEVINJ", ERROR_CODE,
	"LM_E_DEVNORESPONSE", ERROR_CODE,
	"LM_E_DEVOPERATOR", ERROR_CODE,
	"LM_E_DEVOVERFLOW", ERROR_CODE,
	"LM_E_DEVPREM", ERROR_CODE,
	"LM_E_DEVPREV", ERROR_CODE,
	"LM_E_DEVRESET", ERROR_CODE,
	"LM_E_DEVSYNCHERR", ERROR_CODE,
	"LM_E_DIRECTION", ERROR_CODE,
	"LM_E_INTERNAL", ERROR_CODE,
	"LM_E_LIBRARY", ERROR_CODE,
	"LM_E_MOVE", ERROR_CODE,
	"LM_E_NOCANC", ERROR_CODE,
	"LM_E_NODRIVE", ERROR_CODE,
	"LM_E_NOELT", ERROR_CODE,
	"LM_E_NOPCL", ERROR_CODE,
	"LM_E_NOSLOT", ERROR_CODE,
	"LM_E_NOTASK", ERROR_CODE,
	"LM_E_PCL", ERROR_CODE,
	"LM_E_PORT", ERROR_CODE,
	"LM_E_PORTDIR", ERROR_CODE,
	"LM_E_READY", ERROR_CODE,
	"LM_E_SCREMPTY", ERROR_CODE,
	"LM_E_SHAPE", ERROR_CODE,
	"LM_E_SLOTGROUP", ERROR_CODE,
	"LM_E_UNKNOWN", ERROR_CODE,
	"LM_E_SUBCMDFAILED", ERROR_CODE,
	"LM_E_CONFIG", ERROR_CODE,
	"MM_E_AGAIN", ERROR_CODE,
	"MM_E_BADVAL", ERROR_CODE,
	"MM_E_CMDARGS", ERROR_CODE,
	"MM_E_DEVCMD", ERROR_CODE,
	"MM_E_DEVCMDABORT", ERROR_CODE,
	"MM_E_DEVCMDILLEGAL", ERROR_CODE,
	"MM_E_DEVCMDTEMEOUT", ERROR_CODE,
	"MM_E_DEVOVERFLOW", ERROR_CODE,
	"MM_E_DEVPREM", ERROR_CODE,
	"MM_E_DEVPREV", ERROR_CODE,
	"MM_E_INTERNAL", ERROR_CODE,
	"MM_E_NOELT", ERROR_CODE,






	/*
	 * Sun MM System vendor-defined error codes.
	 */
	"EDATABASE", ERROR_CODE,
	"ENOTFOUND", ERROR_CODE,
	"ESYNTAX", ERROR_CODE,
	"EPRIVNOTMMSADMIN", ERROR_CODE,
	"MM_E_NOTASK", ERROR_CODE,
	"MM_E_TOOMANYTASKS", ERROR_CODE,
	"ENOSUCHPCL", ERROR_CODE,
	"ENOTENOUGHPARTITIONS", ERROR_CODE,
	"EPARTITIONSTATECHANGE", ERROR_CODE,
	"ECARTRIDGESTATECHANGE", ERROR_CODE,
	"ESYSTEMCONFIGCHANGE", ERROR_CODE,
	"ENOTCONNECTED", ERROR_CODE,
	"ECOMMUNICATION", ERROR_CODE,

	/* New error codes for library/drive online */
	"ELIBRARYNOEXIST", ERROR_CODE,
	"ELMNOEXIST", ERROR_CODE,
	"ELIBALREADYONLINE", ERROR_CODE,
	"ELIBALREADYOFFLINE", ERROR_CODE,
	"EDRIVENOEXIST", ERROR_CODE,
	"EDRIVEALREADYONLINE", ERROR_CODE,
	"EDRIVEALREADYOFFLINE", ERROR_CODE,
	"EDRIVEONLINE", ERROR_CODE,
	"EDRIVEOFFLINE", ERROR_CODE,
	"ELIBRARYONLINE", ERROR_CODE,
	"ELIBRARYOFFLINE", ERROR_CODE,
	"ELIBRARYDEPENDS", ERROR_CODE,
#endif
	/*
	 * These are error classes
	 */
	"compat", COMPAT,
	"config", CONFIG,
	"exist", EXIST,
	"explicit", EXPLICIT,
	"internal", INTERNAL,
	"invalid", INVALID,
	"permpriv", PERMPRIV,
	"retry", RETRY,
	"subop", SUBOP,
	"state", STATE,
	"LM_C_INVALID", LM_C_INVALID,
	"LM_C_COMMAND", LM_C_COMMAND,
	"DM_C_INVALID", DM_C_INVALID,
	"DM_C_COMMAND", DM_C_COMMAND,
	"MM_C_INVALID", MM_C_INVALID,
	"MM_C_MANAGEMENT", MM_C_MANAGEMENT,
};
mms_sym_t	*mms_symtab = mms_sym_tab;
int	mms_num_syms = sizeof (mms_sym_tab) / sizeof (mms_sym_t);

/*
 * The following is the symbols for all the MMP commands.
 */
mms_sym_t	mms_mmp_sym_tab[] = {
	"request", MMP_REQUEST,
	"message", MMP_MESSAGE,
	"library", LIBRARY,
	"drive", DRIVE,
	"notify", NOTIFY_CMD,
	"respond", RESPOND,
	"accept", ACCEPT,
	"allocate", ALLOCATE,
	"attribute", ATTRIBUTE,
	"show", SHOW,
	"begin", BEGIN_CMD,
	"cancel", CANCEL,
	"add", ADD,
	"change", CHANGE,
	"cpattribute", CPATTRIBUTE,
	"cpreset", CPRESET,
	"cpstart", CPSTART,
	"cpexit", CPEXIT,
	"cpscan", CPSCAN,
	"cpshow", CPSHOW,
	"create", CREATE,
	"deallocate", DEALLOCATE,
	"delete", DELETE,
	"eject", EJECT,
	"end", END,
	"goodbye", GOODBYE,
	"inject", INJECT,
	"locale", LOCALE,
	"mount", MMP_MOUNT,
	"move", MOVE,
	"privilege", PRIVILEGE,
	"release", RELEASE,
	"rename", RENAME,
	"shutdown", SHUTDOWN,
	"unwelcome", MMS_UNWELCOME,
	"welcome", MMS_WELCOME,
};
mms_sym_t	*mms_mmp_symtab = mms_mmp_sym_tab;
int	mms_num_mmsp_syms = sizeof (mms_mmp_sym_tab) / sizeof (mms_sym_t);

/*
 * These are the DMPM commands
 */
static mms_sym_t	mms_dmpm_sym_tab[] = {
	"unload", UNLOAD,
	"reset", XMPM_RESET,
	"private", XMPM_PRIVATE,
	"load", LOAD,
	"exit", EXIT,
	"identify", IDENTIFY,
	"detach", DETACH,
	"cancel", XMPX_CANCEL,
	"activate", ACTIVATE,
	"attach", ATTACH,
	"event", EVENT,
};
mms_sym_t	*mms_dmpm_symtab = mms_dmpm_sym_tab;
int	mms_num_dmpm_syms = sizeof (mms_dmpm_sym_tab) / sizeof (mms_sym_t);

/*
 * These are the DMPD commands
 */
mms_sym_t	mms_dmpd_sym_tab[] = {
	"notify", NOTIFY_CMD,
	"config", DMPD_CONFIG,
	"message", XMPD_MESSAGE,
	"private", DMPD_PRIVATE,
	"ready", XMPD_READY,
	"request", DMPD_REQUEST,
	"cancel", XMPX_CANCEL,
	"shutdown", SHUTDOWN,
	"attribute", ATTRIBUTE,
	"create", CREATE,
	"show", SHOW,
};
mms_sym_t	*mms_dmpd_symtab = mms_dmpd_sym_tab;
int	mms_num_dmpd_syms = sizeof (mms_dmpd_sym_tab) / sizeof (mms_sym_t);

/*
 * These are the LMPM commands
 */
mms_sym_t	mms_lmpm_sym_tab[] = {
	"activate", LMPM_ACTIVATE,
	"barrier", BARRIER,
	"eject", LMPM_EJECT,
	"exit", LMPM_EXIT,
	"inject", LMPM_INJECT,
	"mount", LMPM_MOUNT,
	"move", LMPM_MOVE,
	"private", XMPM_PRIVATE,
	"reset", XMPM_RESET,
	"scan", LMPM_SCAN,
	"unmount", LMPM_UNMOUNT,
	"cancel", XMPX_CANCEL,
	"event", EVENT,
};
mms_sym_t	*mms_lmpm_symtab = mms_lmpm_sym_tab;
int	mms_num_lmpm_syms = sizeof (mms_lmpm_sym_tab) / sizeof (mms_sym_t);

/*
 * These are the LMPD commands
 */
mms_sym_t	mms_lmpl_sym_tab[] = {
	"notify", NOTIFY_CMD,
	"cancel", XMPX_CANCEL,
	"config", LMPD_CONFIG,
	"freeslots", FREESLOTS,
	"delslots", DELSLOTS,
	"in", IN,
	"out", OUT,
	"both", BOTH,
	"perf", PERF,
	"message", XMPD_MESSAGE,
	"private", LMPD_PRIVATE,
	"ready", XMPD_READY,
	"request", LMPD_REQUEST,
	"shutdown", SHUTDOWN,
	"attribute", ATTRIBUTE,
	"show", SHOW,
};
mms_sym_t	*mms_lmpl_symtab = mms_lmpl_sym_tab;
int	mms_num_lmpl_syms = sizeof (mms_lmpl_sym_tab) / sizeof (mms_sym_t);

uchar_t	mms_tokflags[(TOKEN_MAX - TOKEN_MIN ) / 8 + 1];
uchar_t	*mms_token_flags = mms_tokflags;

%}

%name-prefix = "mms_mmsp_"
%defines
%pure_parser

%token	TOKEN_MIN

%token	STRING NUMERIC SLASH_GT LT_SLASH ERR_TOKEN_TOO_BIG NO_ENDING_QUOTE
%token	NUMERIC_STR
%token	MMS_EOF INCORRECT_INPUT_SIZE NO_MEM
%token	MMP_MOUNT DMPM_MOUNT UNKNOWN_KEYWORD

%token	ERROR_CLASS ERROR_CODE
%token	AI APPLICATION BAY CARTRIDGE CARTRIDGEGROUP CARTRIDGEGROUPAPPLICATION
%token	CARTRIDGETYPE CONNECTION DM DMBITFORMAT DMBITFORMATTOKEN DMCAPABILITY
%token	DMCAPABILITYDEFAULTTOKEN DMCAPABILITYGROUP DMCAPABILITYGROUPTOKEN
%token	DMCAPABILITYTOKEN DMP DRIVE DRIVECARTRIDGEACCESS DRIVEGROUP
%token	DRIVEGROUPAPPLICATION FIRST LAST LIBRARY LM LMP MESSAGE MMP
%token	MOUNTLOGICAL MOUNTPHYSICAL PARTITION REQUEST SESSION SIDE
%token	SLOT_OBJ SLOTCONFIG SLOTGROUP SLOTTYPE STALEHANDLE SYSTEM
%token	TASK TASKCARTRIDGE TASKDRIVE TASKLIBRARY VOLUME ACCESSMODE
%token	ALLOCATE AND ARG ATTR ATTRIBUTE BEGIN_CMD
%token	BIGENDIAN BLOCK BLOCKING CERTIFICATE CLIENT
%token	CREATE DELETE FALSE FIRSTMOUNT HELLO TAG IMMEDIATE
%token	INSTANCE ISATTR LANGUAGE LITTLEENDIAN MATCH
%token	NAMEVALUE NEWVOLNAME NOATTR
%token	HOSTEQ HOSTNE TIMEEQ TIMENE TIMELT TIMELE TIMEGT TIMEGE
%token	NOREWIND NOT NUMBER NUMEQ NUMGE NUMGT
%token	NUMHILO NUMLE NUMLOHI NUMLT NUMNE OBJECT
%token	OR ORDER PASSWORD RANGE READONLY READWRITE
%token	REGEX RENAME REPORT REPORTMODE REWIND SET
%token	SHOW STREQ STRGE STRGT STRHILO STRLE
%token	STRLOHI STRLT STRNE TRUE TYPE
%token	UNIQUE UNSET VALUE VERSION VOLNAME WHEN
%token	MMS_WELCOME SERVERNAME MMS_UNWELCOME XMPX_CANCEL
%token	ID CANCELLED CANCELED SUCCESS INTERMEDIATE LOCTEXT RESPONSE
%token  TEXT UNACCEPTABLE ACTION ADD CHANGE
%token	ARGUMENTS ERROR ACCEPTED ATTRLIST ACCEPT REQID CANCEL RESPOND
%token	CPSET CPUNSET CPATTRIBUTE CPREPORT CPREPORTMODE CPTYPE
%token	CPRESET CPEXIT CPSTART PARTIAL FULL XMPM_PRIVATE
%token	ALL FROMSLOT TOSLOT CPSCAN CPSHOW DEALLOCATE EJECT CARTID CART
%token	ABORT END INJECT GOODBYE SORT LOCALE MOVE PRIVILEGE STANDARD
%token	ADMINISTRATOR LEVEL SYSTEM_PRIV RELEASE RESERVE USER
%token	SHUTDOWN FORCE RESTART NONEWAPPS NONEWMOUNTS ABORTQUEUE
%token	ACTIVATE ENABLE DISABLE UNMOUNT NOTIFY QUOTE_IN_STRING
%token	DMPD_CONFIG SCOPE BITFORMAT GROUP CAP CAPLIST ATTACH MODENAME
%token	WHICHTASK DETACH STALE DRIVEHANDLE EXIT
%token	IDENTIFY NONE ANSILABEL LOAD GET PRIVATE RESET UNLOAD
%token	ALERT WARNING WHO OPERATOR NOTICE SEVERITY DEBUG LOG EMERGENCY
%token	CRITICAL INFORMATION DEVELOPER READY XMPD_MESSAGE DMPD_PRIVATE
%token	XMPD_READY DISCONNECTED BROKEN PRIORITY DMPD_REQUEST
%token	LMPM_ACTIVATE BARRIER LMPM_EJECT SLOT LMPM_EXIT STATE EVENT
%token	LMPM_INJECT DRIVE_CL LMPM_MOVE TO FROM LMPM_MOUNT XMPM_RESET
%token	LMPM_SCAN SIGNATURE PHYSICALUNMOUNT CLEAN LMPM_UNMOUNT LMPD_REQUEST
%token	FREESLOTS DELSLOTS IN OUT BOTH PERF LMPD_CONFIG LMPD_PRIVATE WHERE
%token	CAPABILITY FILENAME FILESEQUENCE BLOCKSIZE VOLUMEID UID GID
%token	NEWDRIVE NEWCARTRIDGE NOTIFY_CMD RECEIVE GLOBAL
%token	PRESENT ONLINE OFFLINE SHAPEPRIORITY DENSITYPRIORITY
%token	ISSET NOTSET IDENTITY MMP_REQUEST MMP_MESSAGE NAME
%token	VOLUMEADD VOLUMEDELETE RETENTION MSGFILE SETPASSWORD OLDPASSWORD
%token	DMUP DMDOWN DRIVEONLINE DRIVEOFFLINE DRIVECARTRIDGEERROR
%token	LMUP LMDOWN VOLUMEINJECT VOLUMEEJECT STATUS LIBRARYCREATE LIBRARYDELETE
%token	DRIVEDELETE DIRECT DATA LIBRARYLIST DRIVELIST CARTRIDGELIST
%token	LIBRARYACCESS

%token	LM_C_INVALID LM_C_COMMAND MM_C_INVALID MM_C_MANAGEMENT
%token	DM_C_INVALID DM_C_COMMAND

%token	COMPAT
%token	CONFIG
%token	EXIST
%token	EXPLICIT
%token	INTERNAL
%token	INVALID
%token	PERMPRIV
%token	RETRY
%token	SUBOP

%token	HAVE_STR_ARG HAVE_SUB_CLAUSE TO_MATCH




%token	TOKEN_MAX


%%

command :	{
			 memset(mms_tokflags, 0, sizeof (mms_tokflags));
		}
	  cmd
		{
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cmd	/* MMP commands */
	: accept_cmd
	| allocate_cmd
	| attribute_cmd
	| begin_cmd
	| cancel_cmd
	| cpattribute_cmd
	| cpreset_cmd
	| cpexit_cmd
	| cpstart_cmd
	| cpscan_cmd
	| cpshow_cmd
	| create_cmd
	| deallocate_cmd
	| delete_cmd
	| drive_cmd
	| eject_cmd
	| end_cmd
	| event_cmd
	| goodbye_cmd
	| hello_cmd
	| identity_cmd
	| inject_cmd
	| internal_cmd
	| library_cmd
	| locale_cmd
	| mmp_message_cmd
	| mmp_mount_cmd
	| mmp_request_cmd
	| move_cmd
	| notify_cmd
	| privilege_cmd
	| release_cmd
	| rename_cmd
	| respond_cmd
	| response_cmd
	| setpassword_cmd
	| show_cmd
	| shutdown_cmd
	| unmount_cmd
	| unwelcome_cmd
	| welcome_cmd
	| direct_cmd
	/*
	 * XMP/M commands
	 * Commands common to both DMP/M and LMP/M
	 */
	| xmpm_private_cmd
	| xmpm_reset_cmd
	/*
	 * XMP/D commands
	 * Commands common to both DMP/D and LMP/D
	 */
	| xmpd_message_cmd
	| xmpd_ready_cmd
	/*
	 * XMP/X commands
	 * Commands common to dmpm, dmpd, lmpm and lmpd
	 */
	| xmpx_cancel_cmd
	/*
	 * DMP/M commands
	 */
	| dmpm_activate_cmd
	| dmpm_attach_cmd
	| dmpm_detach_cmd
	| dmpm_exit_cmd
	| dmpm_identify_cmd
	| dmpm_load_cmd
	| dmpm_unload_cmd
	/*
	 * DMP/D commands
	 */
	| dmpd_config_cmd
	| dmpd_private_cmd
	| dmpd_request_cmd
	/*
	 * LMP/M commands
	 */
	| lmpm_activate_cmd
	| lmpm_barrier_cmd
	| lmpm_eject_cmd
	| lmpm_exit_cmd
	| lmpm_inject_cmd
	| lmpm_mount_cmd
	| lmpm_move_cmd
	| lmpm_scan_cmd
	| lmpm_unmount_cmd
	/*
	 * LMP/D commands
	 */
	| lmpl_config_cmd
	| lmpl_private_cmd
	| lmpl_request_cmd

	;

setpassword_cmd
	: SETPASSWORD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "setpassword", MMS_PN_CMD);
		}
	  setpassword_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(PASSWORD) == 0) {
				yyerror("a password clause is required");
			}
			if (MMS_PAR_CHK_FLAG(OLDPASSWORD) &&
			    MMS_PAR_CHK_FLAG(NAME)) {
				yyerror("oldpassword and name clauses are "
				    "incompatible");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

setpassword_arg_list
	: setpassword_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| setpassword_arg_list setpassword_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

setpassword_arg
	: task_clause
	| passwd_clause
	| oldpassword_clause
	| name_clause
	;

oldpassword_clause
	: OLDPASSWORD
		{
			MMS_PAR_CHK_DUP(OLDPASSWORD);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "oldpassword",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

passwd_clause
	: PASSWORD
		{
			MMS_PAR_CHK_DUP(PASSWORD);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "password", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

name_clause
	: NAME
		{
			MMS_PAR_CHK_DUP(NAME);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "name", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

identity_cmd
	: IDENTITY
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "identity", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

direct_cmd
	: DIRECT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "direct", MMS_PN_CMD);
		}
	  direct_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TO) == 0) {
				yyerror("a to clause is required");
			}
			if (MMS_PAR_CHK_FLAG(DATA) == 0) {
				yyerror("a data clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

direct_arg_list
	: direct_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| direct_arg_list direct_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

direct_arg
	: task_clause
	| direct_to_clause
	| direct_data_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

direct_to_clause
	: TO
		{
			MMS_PAR_CHK_DUP(TO);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "to", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

direct_data_clause
	: DATA
		{
			MMS_PAR_CHK_DUP(DATA);
		}
	  '[' str_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "data", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

drive_cmd
	: DRIVE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "drive", MMS_PN_CMD);
		}
	  drive_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ONLINE) +
			    MMS_PAR_CHK_FLAG(OFFLINE) == 0) {
				yyerror("One of online or offline clauses "
				    "is required");
			}
		}
	;

drive_arg_list
	: drive_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| drive_arg_list drive_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

drive_arg
	: task_clause
	| online_clause
	| offline_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

online_clause
	: ONLINE
		{
			MMS_PAR_CHK_DUP(ONLINE);
			if (MMS_PAR_CHK_FLAG(OFFLINE)) {
				yyerror("online and offline clauses are "
				    "imcompatible");
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "online", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

offline_clause
	: OFFLINE
		{
			MMS_PAR_CHK_DUP(OFFLINE);
			if (MMS_PAR_CHK_FLAG(ONLINE)) {
				yyerror("online and offline clauses are "
				    "imcompatible");
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "offline",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

library_cmd
	: LIBRARY
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "library", MMS_PN_CMD);
		}
	  library_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ONLINE) +
			    MMS_PAR_CHK_FLAG(OFFLINE) == 0) {
				yyerror("one of online or offline clauses "
				    "is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

library_arg_list
	: library_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| library_arg_list library_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

library_arg
	: task_clause
	| lib_online_clause
	| lib_offline_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lib_online_clause
	: ONLINE
		{
			MMS_PAR_CHK_DUP(ONLINE);
			if (MMS_PAR_CHK_FLAG(OFFLINE)) {
				yyerror("online and offline clauses are "
				    "imcompatible");
			}
		}
	  '[' str_arg opt_str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "online", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

lib_offline_clause
	: OFFLINE
		{
			MMS_PAR_CHK_DUP(OFFLINE);
			if (MMS_PAR_CHK_FLAG(ONLINE)) {
				yyerror("online and offline clauses are "
				    "imcompatible");
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "offline",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

notify_cmd
	: NOTIFY_CMD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "notify", MMS_PN_CMD);
		}
	  notify_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(HAVE_STR_ARG) &&
			    MMS_PAR_CHK_FLAG(HAVE_SUB_CLAUSE)) {
				yyerror("cannot have old style and new style "
				    "receive or cancel clauses");
			}
			if (MMS_PAR_CHK_FLAG(RECEIVE) == 0 &&
			    MMS_PAR_CHK_FLAG(CANCEL) == 0) {
				yyerror("a receive or a cancel clause "
				    "is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

notify_arg_list
	: notify_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| notify_arg_list notify_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

notify_arg
	: task_clause
	| receive_clause
	| cancel_clause
	| notify_scope_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

notify_scope_clause
	: SCOPE
		{
			MMS_PAR_CHK_DUP(SCOPE);
		}
	  '[' notify_scope_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "scope", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

notify_scope_arg
	: global_or_app
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

global_or_app
	: GLOBAL
		{
			MMS_PAR_CHK_DUP(GLOBAL);
		}
	| APPLICATION
		{
			MMS_PAR_CHK_DUP(APPLICATION);
		}
	| STRING
		{
			if (strcmp($1.str, "global") == 0) {
				MMS_PAR_CHK_DUP(GLOBAL);
			} else if (strcmp($1.str, "application") == 0) {
				MMS_PAR_CHK_DUP(APPLICATION);
			} else {
				yyerror("unexpected STRING, expecting "
				    "global or application");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

receive_clause
	: RECEIVE
		{
			MMS_PAR_UNSET_FLAG(OBJECT);
			MMS_PAR_UNSET_FLAG(TAG);
			MMS_PAR_UNSET_FLAG(ACTION);
			MMS_PAR_UNSET_FLAG(MATCH);
			MMS_PAR_UNSET_FLAG(TO_MATCH);
			MMS_PAR_UNSET_FLAG(TO);
			MMS_PAR_UNSET_FLAG(FROM);
			MMS_PAR_UNSET_FLAG(ADD);
			MMS_PAR_UNSET_FLAG(DELETE);
			MMS_PAR_UNSET_FLAG(CHANGE);
			MMS_PAR_UNSET_FLAG(DATA);
			MMS_PAR_SET_FLAG(RECEIVE);
		}
	 '[' receive_arg_list ']'
		{
			mms_par_node_t	*node;
			char		*msg;

			MMS_PAR_ALLOC_NODE($$.nodep, "receive", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist, $4.listp);

			if (MMS_PAR_CHK_FLAG(HAVE_SUB_CLAUSE) != 0) {
				if (MMS_PAR_CHK_FLAG(OBJECT) == 0) {
					yyerror("an object clause is required "
					    "in a receive clause");
				}
				if (MMS_PAR_CHK_FLAG(ADD) != 0 ||
				    MMS_PAR_CHK_FLAG(DELETE) != 0) {
					/* "add" or "delete" action */
					if (MMS_PAR_CHK_FLAG(TO) != 0) {
						yyerror("to clause not "
						    "allowed with action 'add' "
						    "or 'delete'");
					}
				}
				/*
				 * If 'change' verify that only one object
				 * is referenced in the match clause and it
				 * matches the object specified in the
				 * onject clause.
				 */
				if (msg = mms_mmp_validate_object($$.nodep)) {
					yyerror(msg);
				}
			}

		}
	;

receive_arg_list
	: str_arg_list
		{
			MMS_PAR_SET_FLAG(HAVE_STR_ARG);
			$$.listp = $1.listp;
		}
	| receive_subclause_list
		{
			MMS_PAR_SET_FLAG(HAVE_SUB_CLAUSE);
			$$.listp = $1.listp;
		}
	;

receive_subclause_list
	: receive_subclause
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| receive_subclause_list receive_subclause
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

receive_subclause
	: recv_object_clause
	| recv_tag_clause
	| action_clause
	| match_clause
	| recv_to_clause
	| recv_data_clause
	;

recv_data_clause
	: direct_data_clause
	;

recv_to_clause
	: TO
		{
			MMS_PAR_CHK_DUP(TO);
			MMS_PAR_UNSET_FLAG(MATCH);
		}
	  '[' match_clause ']'
		{
			MMS_PAR_SET_FLAG(TO_MATCH);
			MMS_PAR_ALLOC_NODE($$.nodep, "to", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

recv_object_clause
	: OBJECT
		{
			MMS_PAR_CHK_DUP(OBJECT);
		}
	  '[' object_spec opt_attr_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "object", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			if ($5.listp != NULL) {
				mms_list_move_tail(&$$.nodep->pn_arglist,
				    $5.listp);
			}
		}
	;

opt_attr_list
	: opt_str_arg_list
	;


recv_tag_clause
	: TAG
		{
			MMS_PAR_CHK_DUP(TAG);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "tag", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

action_clause
	: ACTION
		{
			MMS_PAR_CHK_DUP(ACTION);
		}
	  '[' action ']'
		{
			mms_par_node_t	*node;

			if (strcmp($4.str, "add") == 0) {
				MMS_PAR_SET_FLAG(ADD);
			} else if (strcmp($4.str, "delete") == 0) {
				MMS_PAR_SET_FLAG(DELETE);
			} else if (strcmp($4.str, "change") == 0) {
				MMS_PAR_SET_FLAG(CHANGE);
			}
			MMS_PAR_ALLOC_NODE($$.nodep, "action", MMS_PN_CLAUSE);
			MMS_PAR_ALLOC_NODE(node, $4.str, MMS_PN_KEYWORD);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist, node);
		}
	;

action	: ADD
	| DELETE
	| CHANGE
	| STRING
		{
			if (strcmp($1.str, "add") &&
			    strcmp($1.str, "delete") &&
			    strcmp($1.str, "change")) {
				yyerror("unexpected STRING, "
				    "expecting add, delete, chage or all");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

cancel_clause
	: CANCEL '[' cancel_arg_list ']'
		{
			MMS_PAR_SET_FLAG(CANCEL);
			MMS_PAR_ALLOC_NODE($$.nodep, "cancel", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist, $3.listp);
		}
	;

cancel_arg_list
	: str_arg_list
		{
			MMS_PAR_SET_FLAG(HAVE_STR_ARG);
			$$.listp = $1.listp;
		}
	| cancel_subclause
		{
			MMS_PAR_SET_FLAG(HAVE_SUB_CLAUSE);
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	;

cancel_subclause
	: tag_clause
	| cancel_object_clause
	;

cancel_object_clause
	: event_object_clause
	;

event_cmd
	: EVENT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "event", MMS_PN_CMD);
		}
	  event_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

event_arg_list
	: event_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| event_arg_list event_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

event_arg
	: event_config
	| event_newdrive
	| event_newcartridge
	| event_message
	| event_request
	| event_volumeadd
	| event_volumedelete
	| event_dmup
	| event_dmdown
	| event_driveonline
	| event_driveoffline
	| event_lmup
	| event_lmdown
	| event_volumeinject
	| event_volumeeject
	| event_status
	| event_librarycreate
	| event_librarydelete
	| event_drivedelete
	| event_cartridge
	| event_volume
	| event_direct
	| event_object_clause
	| recv_tag_clause
	| event_data_clause
	| error { yyclearin; $$.nodep = NULL; }
	;


event_driveoffline
	: DRIVEOFFLINE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "driveoffline",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

event_driveonline
	: DRIVEONLINE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "driveonline",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

event_lmup
	: LMUP '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "lmup", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_lmdown
	: LMDOWN '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "lmdown", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_dmup
	: DMUP '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "dmup", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

event_dmdown
	: DMDOWN '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "dmdown", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;


event_volumeinject
	: VOLUMEINJECT '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volumeinject",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_volumeeject
	: VOLUMEEJECT '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volumeeject",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

	;

event_data_clause
	: direct_data_clause
	;

event_object_clause
	: OBJECT
		{
			MMS_PAR_CHK_DUP(OBJECT);
		}
	  '[' object_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "object", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_status
	: STATUS '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "status", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_librarycreate
	: LIBRARYCREATE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "librarycreate",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

event_librarydelete
	: LIBRARYDELETE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "librarydelete",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

event_drivedelete
	: DRIVEDELETE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "drivedelete",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;




event_volumeadd
	: VOLUMEADD '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volumeadd",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_volumedelete
	: VOLUMEDELETE '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volumedelete",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_config
	: CONFIG '[' str_arg str_arg str_arg opt_str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "config", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

event_newdrive
	: NEWDRIVE '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "newdrive",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_newcartridge
	: NEWCARTRIDGE '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "newcartridge",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_message
	: MESSAGE '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "message",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

event_request
	: REQUEST '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "request",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

event_cartridge
	: CARTRIDGE '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cartridge",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

event_volume
	: VOLUME '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volume", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

event_direct
	: DIRECT
		{
			MMS_PAR_CHK_DUP(DIRECT);
		}
	  '[' str_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "direct", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

mmp_request_cmd
	: MMP_REQUEST
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "request", MMS_PN_CMD);
		}
	  mmp_request_arg_list ';'
		{
			int	count;

			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(PRIORITY) == 0) {
				yyerror("a priority clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

mmp_request_arg_list
	: mmp_request_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| mmp_request_arg_list mmp_request_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

mmp_request_arg
	: task_clause
	| mmp_type_clause
	| mmp_priority_clause
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

mmp_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' object_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			if (strcmp(mms_pn_token($4.nodep), "AI")) {
				yyerror("unexpected objectname. "
				    "AI required");
				YYERROR;
			}
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

mmp_priority_clause
	: PRIORITY
		{
			MMS_PAR_CHK_DUP(PRIORITY);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "priority",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

mmp_message_cmd
	: MMP_MESSAGE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "message", MMS_PN_CMD);
		}
	  mmp_message_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(WHO) == 0) {
				yyerror("a who clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SEVERITY) == 0) {
				yyerror("a severity clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

mmp_message_arg_list
	: mmp_message_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| mmp_message_arg_list mmp_message_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

mmp_message_arg
	: task_clause
	| who_clause
	| severity_clause
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lmpl_request_cmd
	: LMPD_REQUEST
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "request", MMS_PN_CMD);
		}
	  lmpl_request_arg_list ';'
		{
			int	count;

			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(PRIORITY) == 0) {
				yyerror("a priority clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpl_request_arg_list
	: lmpl_request_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpl_request_arg_list lmpl_request_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpl_request_arg
	: task_clause
	| lmpl_type_clause
	| lmpl_priority_clause
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lmpl_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' lm_spec ']'
		{
			mms_par_node_t *node;

			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			MMS_PAR_ALLOC_NODE($$.nodep, $4.str, MMS_PN_OBJ);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    node);
		}
	;

lm_spec	: LM
	| STRING
		{
			if (strcmp($1.str, "LM")) {
				yyerror("unexpected type. LM expected");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

lmpl_priority_clause
	: PRIORITY
		{
			MMS_PAR_CHK_DUP(PRIORITY);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "priority",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;




lmpl_private_cmd
	: LMPD_PRIVATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "private", MMS_PN_CMD);
		}
	  lmpl_private_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SET) + MMS_PAR_CHK_FLAG(UNSET) +
			    MMS_PAR_CHK_FLAG(GET) == 0) {
				yyerror("a set, unset or get clause is "
				    "required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpl_private_arg_list
	: lmpl_private_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpl_private_arg_list lmpl_private_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpl_private_arg
	: task_clause
	| lmpl_set_clause
	| lmpl_unset_clause
	| lmpl_get_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lmpl_set_clause
	: SET '[' lmpl_set_arglist ']'
		{
			MMS_PAR_SET_FLAG(SET);
			MMS_PAR_ALLOC_NODE($$.nodep, "set", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

lmpl_set_arglist
	: lmpl_object_id str_arg str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
			mms_par_list_insert_tail($$.listp, $3.nodep);
		}
	| lmpl_set_arglist lmpl_object_id str_arg str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			mms_par_list_insert_tail($1.listp, $4.nodep);
			$$.listp = $1.listp;
		}
	;

lmpl_object_id
	: object_spec
		{
			char    msg[100];
			if (strcmp(mms_pn_token($1.nodep), "LM") &&
			    strcmp(mms_pn_token($1.nodep), "LIBRARY")) {
				sprintf(msg,
				    "Unexpected object \"%s\", only "
				    "\"LM\" or \"LIBRARY\" object is "
				    "allowed", mms_pn_token($1.nodep));
				yyerror(msg);
				YYERROR;
			}
		}
	;

lmpl_unset_clause
	: UNSET '[' lmpl_unset_arglist ']'
		{
			MMS_PAR_SET_FLAG(UNSET);
			MMS_PAR_ALLOC_NODE($$.nodep, "unset", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

lmpl_unset_arglist
	:  lmpl_object_id str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| lmpl_unset_arglist lmpl_object_id str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;

lmpl_get_clause
	: GET '[' lmpl_get_arglist ']'
		{
			MMS_PAR_SET_FLAG(GET);
			MMS_PAR_ALLOC_NODE($$.nodep, "get", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

lmpl_get_arglist
	: lmpl_object_id str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| lmpl_get_arglist lmpl_object_id str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;




lmpl_config_cmd
	: LMPD_CONFIG
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "config", MMS_PN_CMD);
		}
	  lmpl_config_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpl_config_arg_list
	: lmpl_config_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpl_config_arg_list lmpl_config_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpl_config_arg
	: task_clause
	| lmpl_slot_clause
	| scope_clause
	| bay_clause
	| lmpl_drive_clause
	| freeslots_clause
	| delslots_clause
	| lmpl_slotgroup_clause
	| perf_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

perf_clause
	: PERF '[' num_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "perf", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

lmpl_slotgroup_clause
	: SLOTGROUP '[' str_arg str_arg direction_spec str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "slotgroup",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

direction_spec
	: direction
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

direction
	: IN | OUT | BOTH | NONE
	| STRING
		{
			if (strcmp($1.str, "in") &&
			    strcmp($1.str, "out") &&
			    strcmp($1.str, "both") &&
			    strcmp($1.str, "none")) {
				yyerror("unexpected STRING, "
				    "expecting in, out, both or none");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

lmpl_drive_clause
	: DRIVE_CL '[' str_arg str_arg str_arg str_arg
	  true_or_false_spec true_or_false_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "drive", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $7.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $8.nodep);
		}
	;

freeslots_clause
	: FREESLOTS '[' str_arg str_arg num_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "freeslots",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

delslots_clause
	: DELSLOTS '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "delslots",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

bay_clause
	: BAY '[' str_arg true_or_false_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "bay", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;



lmpl_slot_clause
	: SLOT '[' str_arg str_arg str_arg str_arg str_arg true_or_false_spec
		true_or_false_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "slot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $7.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $8.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $9.nodep);
		}
	;

lmpm_unmount_cmd
	: LMPM_UNMOUNT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "unmount", MMS_PN_CMD);
		}
	  lmpm_unmount_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ALL) == 0 &&
			    MMS_PAR_CHK_FLAG(FROMSLOT) == 0) {
				yyerror("either all or fromslot clause is "
				    "required");
			}
			if (MMS_PAR_CHK_FLAG(ALL) &&
			    MMS_PAR_CHK_FLAG(FROMSLOT)) {
				yyerror("all and fromslot clauses are "
				    "incompatible");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_unmount_arg_list
	: lmpm_unmount_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_unmount_arg_list lmpm_unmount_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_unmount_arg
	: task_clause
	| drive_clause
	| lmpm_fromslot_clause
	| lmpm_toslot_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lmpm_fromslot_clause
	: FROMSLOT
		{
			MMS_PAR_CHK_DUP(FROMSLOT);
		}
	  '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "fromslot",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

lmpm_toslot_clause
	: TOSLOT
		{
			MMS_PAR_CHK_DUP(TOSLOT);
		}
	  '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "toslot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

lmpm_scan_cmd
	: LMPM_SCAN
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "scan", MMS_PN_CMD);
		}
	  lmpm_scan_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ALL)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(SLOT) ||
				    MMS_PAR_CHK_FLAG(DRIVE)) {
					yyerror("all is incompatible with "
					    "fromslot, toslot, "
					    "drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(SLOT)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(DRIVE)) {
					yyerror("slot is incompatible with "
					    "fromslot, toslot, "
					    "drive and all");
				}
			}
			if (MMS_PAR_CHK_FLAG(DRIVE)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("drive is incompatible with "
					    "fromslot, toslot, "
					    "all and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(FROMSLOT)) {
				if (MMS_PAR_CHK_FLAG(DRIVE) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("fromslot is incompatible with "
					    "all, drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(TOSLOT)) {
				if (MMS_PAR_CHK_FLAG(DRIVE) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("toslot is incompatible with "
					    "all, drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(FROMSLOT) +
			    MMS_PAR_CHK_FLAG(TOSLOT) ==
			    1) {
				yyerror("fromslot and toslot must be "
				    "specified together");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_scan_arg_list
	: lmpm_scan_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_scan_arg_list lmpm_scan_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_scan_arg
	: task_clause
	| all_spec
	| from_spec
	| to_spec
	| scan_slot_clause
	| drive_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

scan_slot_clause
	: SLOT '[' str_arg ']'
		{
			MMS_PAR_SET_FLAG(SLOT);
			MMS_PAR_ALLOC_NODE($$.nodep, "slot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

lmpm_move_cmd
	: LMPM_MOVE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "move", MMS_PN_CMD);
		}
	  lmpm_move_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(FROM) == 0) {
				yyerror("a from clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TO) == 0) {
				yyerror("a to clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_move_arg_list
	: lmpm_move_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_move_arg_list lmpm_move_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_move_arg
	: task_clause
	| from_clause
	| to_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

from_clause
	: FROM
		{
			MMS_PAR_CHK_DUP(FROM);
		}
	  '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "from", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

to_clause
	: TO
		{
			MMS_PAR_CHK_DUP(TO);
		}
	  '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "to", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

lmpm_mount_cmd
	: LMPM_MOUNT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "mount", MMS_PN_CMD);
		}
	  lmpm_mount_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(DRIVE) == 0) {
				yyerror("a drive clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SLOT) == 0) {
				yyerror("a slot clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_mount_arg_list
	: lmpm_mount_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_mount_arg_list lmpm_mount_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_mount_arg
	: task_clause
	| drive_clause
	| mount_slot_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

drive_clause
	: DRIVE_CL '[' str_arg ']'
		{
			MMS_PAR_SET_FLAG(DRIVE);
			MMS_PAR_ALLOC_NODE($$.nodep, "drive", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

mount_slot_clause
	: SLOT '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_SET_FLAG(SLOT);
			MMS_PAR_ALLOC_NODE($$.nodep, "slot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

lmpm_inject_cmd
	: LMPM_INJECT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "inject", MMS_PN_CMD);
		}
	  lmpm_inject_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SLOTGROUP) == 0) {
				yyerror("a slotgroup clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_inject_arg_list
	: lmpm_inject_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_inject_arg_list lmpm_inject_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_inject_arg
	: task_clause
	| slotgroup_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

lmpm_exit_cmd
	: LMPM_EXIT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "exit", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_eject_cmd
	: LMPM_EJECT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "eject", MMS_PN_CMD);
		}
	  lmpm_eject_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SLOTGROUP) == 0) {
				yyerror("a slotgroup clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SLOT) == 0) {
				yyerror("a slot clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_eject_arg_list
	: lmpm_eject_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| lmpm_eject_arg_list lmpm_eject_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

lmpm_eject_arg
	: task_clause
	| slotgroup_clause
	| slot_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

slot_clause
	: SLOT '[' str_arg str_arg ']'
		{
			MMS_PAR_SET_FLAG(SLOT);
			MMS_PAR_ALLOC_NODE($$.nodep, "slot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

lmpm_barrier_cmd
	: BARRIER
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "barrier", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

lmpm_activate_cmd
	: LMPM_ACTIVATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "activate", MMS_PN_CMD);
		}
	  activate_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ENABLE) == 0 &&
			    MMS_PAR_CHK_FLAG(DISABLE)
			    == 0) {
				yyerror("one of enable and disable is "
				    "required");
			}
			if (MMS_PAR_CHK_FLAG(ENABLE) == 1 &&
			    MMS_PAR_CHK_FLAG(DISABLE)
			    == 1) {
				yyerror
				    ("enable and disable are incompatible");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

dmpd_request_cmd
	: DMPD_REQUEST
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "request", MMS_PN_CMD);
		}
	  dmpd_request_arg_list ';'
		{
			int	count;

			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(PRIORITY) == 0) {
				yyerror("a priority clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

dmpd_request_arg_list
	: dmpd_request_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| dmpd_request_arg_list dmpd_request_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

dmpd_request_arg
	: task_clause
	| dmpd_type_clause
	| dmpd_priority_clause
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

dmpd_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' dm_spec ']'
		{
			mms_par_node_t *node;

			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			MMS_PAR_ALLOC_NODE(node, $4.str, MMS_PN_OBJ);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    node);
		}
	;

dm_spec	: DM
	| STRING
		{
			if (strcmp($1.str, "DM")) {
				yyerror("unexpected type. DM expected");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

dmpd_priority_clause
	: PRIORITY
		{
			MMS_PAR_CHK_DUP(PRIORITY);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "priority",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

xmpd_ready_cmd
	: XMPD_READY
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "ready", MMS_PN_CMD);
		}
	  xmpd_ready_arg_list ';'
		{
			int	count;

			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
				YYERROR;
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

xmpd_ready_arg_list
	: xmpd_ready_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| xmpd_ready_arg_list xmpd_ready_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

xmpd_ready_arg
	: task_clause
	| ready_state_spec
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

ready_state_spec
	: ready_state
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

ready_state
	: NOT
		{
			MMS_PAR_CHK_DUP(NOT);
		}
	| BROKEN
		{
			MMS_PAR_CHK_DUP(BROKEN);
		}
	| DISCONNECTED
		{
			MMS_PAR_CHK_DUP(DISCONNECTED);
		}
	| PRESENT
		{
			MMS_PAR_CHK_DUP(PRESENT);
		}
	| STRING
		{
			if (strcmp($1.str, "not") &&
			    strcmp($1.str, "present") &&
			    strcmp($1.str, "broken") &&
			    strcmp($1.str, "disconnected")) {
				yyerror("unexpected STRING, "
				    "expecting not, present, broken or "
				    "disconnected");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

dmpd_private_cmd
	: DMPD_PRIVATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "private", MMS_PN_CMD);
		}
	  dmpd_private_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SET) + MMS_PAR_CHK_FLAG(UNSET) +
			    MMS_PAR_CHK_FLAG(GET) == 0) {
				yyerror("a set, unset or get clause is "
				    "required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

dmpd_private_arg_list
	: dmpd_private_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| dmpd_private_arg_list dmpd_private_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

dmpd_private_arg
	: task_clause
	| dmpd_set_clause
	| dmpd_unset_clause
	| dmpd_get_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

dmpd_set_clause
	: SET '[' dmpd_set_arglist ']'
		{
			MMS_PAR_SET_FLAG(SET);
			MMS_PAR_ALLOC_NODE($$.nodep, "set", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpd_set_arglist
	: dmpd_object_id str_arg str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
			mms_par_list_insert_tail($$.listp, $3.nodep);
		}
	| dmpd_set_arglist dmpd_object_id str_arg str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			mms_par_list_insert_tail($1.listp, $4.nodep);
			$$.listp = $1.listp;
		}
	;

dmpd_object_id
	: object_spec
		{
			char    msg[100];
			if (strcmp(mms_pn_token($1.nodep), "DM") &&
			    strcmp(mms_pn_token($1.nodep), "DRIVE")) {
				sprintf(msg,
				    "Unexpected object \"%s\", only "
				    "\"DM\" or \"DRIVE\" object is "
				    "allowed", mms_pn_token($1.nodep));
				yyerror(msg);
				YYERROR;
			}
		}
	;

dmpd_unset_clause
	: UNSET '[' dmpd_unset_arglist ']'
		{
			MMS_PAR_SET_FLAG(UNSET);
			MMS_PAR_ALLOC_NODE($$.nodep, "unset", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpd_unset_arglist
	:  dmpd_object_id str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| dmpd_unset_arglist dmpd_object_id str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;

dmpd_get_clause
	: GET '[' dmpd_get_arglist ']'
		{
			MMS_PAR_SET_FLAG(GET);
			MMS_PAR_ALLOC_NODE($$.nodep, "get", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpd_get_arglist
	: dmpd_object_id str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| dmpd_get_arglist dmpd_object_id str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;

xmpd_message_cmd
	: XMPD_MESSAGE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "message", MMS_PN_CMD);
		}
	  xmpd_message_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(WHO) == 0) {
				yyerror("a who clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SEVERITY) == 0) {
				yyerror("a severity clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

xmpd_message_arg_list
	: xmpd_message_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| xmpd_message_arg_list xmpd_message_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

xmpd_message_arg
	: task_clause
	| who_clause
	| severity_clause
	| message_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

who_clause
	: WHO
		{
			MMS_PAR_CHK_DUP(WHO);
		}
	  '[' receiver ']'
		{
			mms_par_node_t *node;

			MMS_PAR_ALLOC_NODE($$.nodep, "who", MMS_PN_CLAUSE);
			MMS_PAR_ALLOC_NODE(node, $4.str, MMS_PN_KEYWORD);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    node);
		}
	;

receiver: OPERATOR | ADMINISTRATOR | LOG
	| STRING
		{
			if (strcmp($1.str, "operator") &&
			    strcmp($1.str, "administrator") &&
			    strcmp($1.str, "log")) {
				yyerror("unexpected STRING, expecting "
				    "operator, administrator or log");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

severity_clause
	: SEVERITY
		{
			MMS_PAR_CHK_DUP(SEVERITY);
		}
	  '[' severity ']'
		{
			mms_par_node_t *node;

			MMS_PAR_ALLOC_NODE($$.nodep, "severity",
			    MMS_PN_CLAUSE);
			MMS_PAR_ALLOC_NODE(node, $4.str, MMS_PN_KEYWORD);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    node);
		}
	;

severity: EMERGENCY | ALERT | CRITICAL | ERROR | WARNING | NOTICE
	| INFORMATION | DEBUG | DEVELOPER
	| STRING
		{
			if (strcmp($1.str, "emergency") &&
			    strcmp($1.str, "alert") &&
			    strcmp($1.str, "critical") &&
			    strcmp($1.str, "error") &&
			    strcmp($1.str, "warning") &&
			    strcmp($1.str, "notice") &&
			    strcmp($1.str, "information") &&
			    strcmp($1.str, "debug") &&
			    strcmp($1.str, "developer")) {
				yyerror("unexpected STRING, expecting "
				    "emergency, alert, critical, "
				    "error, warning, notice, "
				    "information, debug or developer");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

dmpm_unload_cmd
	: UNLOAD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "unload", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

xmpm_reset_cmd
	: XMPM_RESET
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "reset", MMS_PN_CMD);
		}
	  xmpm_reset_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(FULL) == 0 &&
			    MMS_PAR_CHK_FLAG(PARTIAL) == 0) {
				yyerror("full or partial is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

xmpm_reset_arg_list
	: xmpm_reset_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| xmpm_reset_arg_list xmpm_reset_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

xmpm_reset_arg
	: task_clause
	| scope_arg
	| error { yyclearin; $$.nodep = NULL; }
	;

xmpm_private_cmd
	: XMPM_PRIVATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "private", MMS_PN_CMD);
		}
	  dmpm_private_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SET) + MMS_PAR_CHK_FLAG(UNSET) +
			    MMS_PAR_CHK_FLAG(GET) == 0) {
				yyerror("a set, unset or get clause is "
				    "required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

dmpm_private_arg_list
	: dmpm_private_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| dmpm_private_arg_list dmpm_private_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

dmpm_private_arg
	: task_clause
	| dmpm_set_clause
	| dmpm_unset_clause
	| dmpm_get_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

dmpm_set_clause
	: SET '[' dmpm_set_arglist ']'
		{
			MMS_PAR_SET_FLAG(SET);
			MMS_PAR_ALLOC_NODE($$.nodep, "set", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpm_set_arglist
	: str_arg str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| dmpm_set_arglist str_arg str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;

dmpm_unset_clause
	: UNSET '[' dmpm_unset_arglist ']'
		{
			MMS_PAR_SET_FLAG(UNSET);
			MMS_PAR_ALLOC_NODE($$.nodep, "unset", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpm_unset_arglist
	: str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| dmpm_unset_arglist str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

dmpm_get_clause
	: GET '[' dmpm_get_arglist ']'
		{
			MMS_PAR_SET_FLAG(GET);
			MMS_PAR_ALLOC_NODE($$.nodep, "get", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

dmpm_get_arglist
	: str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| dmpm_get_arglist str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

dmpm_load_cmd
	: LOAD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "load", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;


dmpm_identify_cmd
	: IDENTIFY
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "identify", MMS_PN_CMD);
		}
	  identify_dmpm_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

identify_dmpm_arg_list
	: identify_dmpm_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| identify_dmpm_arg_list identify_dmpm_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

identify_dmpm_arg
	: task_clause
	| identify_type_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

identify_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' partition_signature_type_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

partition_signature_type_spec
	: partition_signature_type
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

partition_signature_type
	: NONE
	| ANSILABEL
	| STRING
		{
			if (strcmp($1.str, "none") &&
			    strcmp($1.str, "ansilabel")) {
				yyerror("unexpected STRING, expecting "
				    "none or ansilabel");
			}
			$$.str = $1.str;
		}
	;

dmpm_exit_cmd
	: EXIT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "exit", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

dmpm_detach_cmd
	: DETACH
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "detach", MMS_PN_CMD);
		}
	  detach_dmpm_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(STALE) == 0) {
				yyerror("a stale clause is required");
			}
			if (MMS_PAR_CHK_FLAG(DRIVEHANDLE) == 0) {
				yyerror("a drivehandle clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

detach_dmpm_arg_list
	: detach_dmpm_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| detach_dmpm_arg_list detach_dmpm_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

detach_dmpm_arg
	: task_clause
	| drivehandle_clause
	| stale_clause
	| error { yyclearin; $$.nodep = NULL; }
	;


drivehandle_clause
	: DRIVEHANDLE
		{
			MMS_PAR_CHK_DUP(DRIVEHANDLE);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "drivehandle",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

stale_clause
	: STALE
		{
			MMS_PAR_CHK_DUP(STALE);
		}
	  '[' stale_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "stale", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

stale_arg
	: true_or_false_spec
	;

internal_cmd
	: INTERNAL
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "internal", MMS_PN_CMD);
		}
	  str_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

xmpx_cancel_cmd
	: XMPX_CANCEL
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cancel", MMS_PN_CMD);
		}
	  xmpx_cancel_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(WHICHTASK) == 0) {
				yyerror("a whichtask clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

xmpx_cancel_arg_list
	: xmpx_cancel_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| xmpx_cancel_arg_list xmpx_cancel_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

xmpx_cancel_arg
	: task_clause
	| whichtask_clause
	;

whichtask_clause
	: WHICHTASK
		{
			MMS_PAR_CHK_DUP(WHICHTASK);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "whichtask",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

dmpm_attach_cmd
	: ATTACH
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "attach", MMS_PN_CMD);
		}
	  attach_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MODENAME) == 0) {
				yyerror("a scope clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

attach_arg_list
	: attach_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| attach_arg_list attach_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

attach_arg
	: task_clause
	| modename_clause
	| partition_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

modename_clause
	: MODENAME
		{
			MMS_PAR_CHK_DUP(MODENAME);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "modename",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

partition_clause
	: PARTITION
		{
			MMS_PAR_CHK_DUP(PARTITION);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "partition",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

dmpd_config_cmd
	: DMPD_CONFIG
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "config", MMS_PN_CMD);
		}
	  config_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SCOPE) == 0) {
				yyerror("a scope clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

config_arg_list
	: config_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| config_arg_list config_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

config_arg
	: task_clause
	| scope_clause
	| group_clause
	| bit_clause
	| cap_clause
	| shape_pri_clause
	| den_pri_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

shape_pri_clause
	: SHAPEPRIORITY
		{
			MMS_PAR_CHK_DUP(SHAPEPRIORITY);
		}
	 '[' str_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "shapepriority",
			    MMS_PN_CLAUSE);
			mms_list_move(&$$.nodep->pn_arglist, $4.listp);
		}
	;

den_pri_clause
	: DENSITYPRIORITY
		{
			MMS_PAR_CHK_DUP(DENSITYPRIORITY);
		}
	 '[' str_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "densitypriority",
			    MMS_PN_CLAUSE);
			mms_list_move(&$$.nodep->pn_arglist, $4.listp);
		}
	;

scope_clause
	: SCOPE
		{
			MMS_PAR_CHK_DUP(SCOPE);
		}
	  '[' scope_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "scope", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

scope_arg
	: full_or_partial
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

full_or_partial
	: FULL
		{
			MMS_PAR_CHK_DUP(FULL);
		}
	| PARTIAL
		{
			MMS_PAR_CHK_DUP(PARTIAL);
		}
	| STRING
		{
			if (strcmp($1.str, "full") == 0) {
				MMS_PAR_CHK_DUP(FULL);
			} else if (strcmp($1.str, "partial") == 0) {
				MMS_PAR_CHK_DUP(PARTIAL);
			} else {
				yyerror("unexpected STRING, expecting "
				    "full or partial");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

group_clause
	: GROUP '[' str_arg_list ']'
		{
			MMS_PAR_SET_FLAG(GROUP);
			MMS_PAR_ALLOC_NODE($$.nodep, "group", MMS_PN_CLAUSE);
			mms_list_move(&$$.nodep->pn_arglist, $3.listp);
		}
	;

str_arg_list
	: str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| str_arg_list str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

bit_clause
	: BITFORMAT '[' str_arg str_arg opt_str_arg_list ']'
		{
			MMS_PAR_SET_FLAG(BITFORMAT);
			MMS_PAR_ALLOC_NODE($$.nodep, "bitformat",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			if ($5.listp != NULL) {
				mms_list_move_tail(&$$.nodep->pn_arglist,
				    $5.listp);
			}
		}
	;

cap_clause
	: CAP '['
		{
			MMS_PAR_UNSET_FLAG(CAPLIST);
		}
	  str_arg cap_arg_list ']'
		{
			MMS_PAR_SET_FLAG(CAP);
			MMS_PAR_ALLOC_NODE($$.nodep, "cap", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $5.listp);
		}
	;

cap_arg_list
	: cap_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cap_arg_list cap_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cap_arg	: cap_attr_clause
	| caplist_clause
	;

cap_attr_clause
	: ATTR '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "attr", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

caplist_clause
	: CAPLIST
		{
			MMS_PAR_CHK_DUP(CAPLIST);
		}
	  '[' cap_token_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "caplist",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

cap_token_list
	: str_arg_list
	;

dmpm_activate_cmd
	: ACTIVATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "activate", MMS_PN_CMD);
		}
	  activate_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ENABLE) == 0 &&
			    MMS_PAR_CHK_FLAG(DISABLE) == 0 &&
			    MMS_PAR_CHK_FLAG(RESERVE) == 0 &&
			    MMS_PAR_CHK_FLAG(RELEASE) == 0) {
				yyerror("one of enable, disable, "
				    "reserve or release is " "required");
			}
			if (MMS_PAR_CHK_FLAG(ENABLE) +
			    MMS_PAR_CHK_FLAG(DISABLE) +
			    MMS_PAR_CHK_FLAG(RESERVE) +
			    MMS_PAR_CHK_FLAG(RELEASE) >
			    1) {
				yyerror("enable, disable, "
				    "reserve and release are incompatible");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

activate_arg_list
	: activate_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| activate_arg_list activate_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

activate_arg
	: task_clause
	| activate_type_spec
	| error { yyclearin; $$.nodep = NULL; }
	;

activate_type_spec
	: activate_type
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

activate_type
	: ENABLE
		{
			MMS_PAR_CHK_DUP(ENABLE);
		}
	| DISABLE
		{
			MMS_PAR_CHK_DUP(DISABLE);
		}
	| RELEASE
		{
			MMS_PAR_CHK_DUP(RELEASE);
		}
	| RESERVE
		{
			MMS_PAR_CHK_DUP(RESERVE);
		}
	;

shutdown_cmd
	: SHUTDOWN
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "shutdown", MMS_PN_CMD);
		}
	  shutdown_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

shutdown_arg_list
	: shutdown_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| shutdown_arg_list shutdown_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

shutdown_arg
	: task_clause
	| shutdown_type_clause
	| restart_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

shutdown_type_clause
	: TYPE '['
		{
			MMS_PAR_UNSET_FLAG(RESTART);
			MMS_PAR_CHK_DUP(TYPE);
		}
	  shutdown_type_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			if (MMS_PAR_CHK_FLAG(NONEWAPPS) +
			    MMS_PAR_CHK_FLAG(NONEWMOUNTS)
			    + MMS_PAR_CHK_FLAG(ABORTQUEUE) +
			    MMS_PAR_CHK_FLAG(FORCE) > 1) {
				yyerror
				    ("nonewapps, nonewmounts, abortqueue "
				    "and force are imcompatible");
				YYERROR;
			}
			MMS_PAR_UNSET_FLAG(RESTART);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

shutdown_type_arg_list
	: shutdown_type_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| shutdown_type_arg_list shutdown_type_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

shutdown_type_arg
	: shutdown_type
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

shutdown_type
	: NONEWAPPS
		{
			MMS_PAR_CHK_DUP(NONEWAPPS);
		}
	| NONEWMOUNTS
		{
			MMS_PAR_CHK_DUP(NONEWMOUNTS);
		}
	| ABORTQUEUE

		{
			MMS_PAR_CHK_DUP(ABORTQUEUE);
		}
	| FORCE
		{
			MMS_PAR_CHK_DUP(FORCE);
		}
	| RESTART
		{
			MMS_PAR_CHK_DUP(RESTART);
		}
	| STRING
		{
			if (strcmp($1.str, "nonewapps") == 0) {
				MMS_PAR_CHK_DUP(NONEWAPPS);
			} else if (strcmp($1.str, "nonewmounts") == 0) {
				MMS_PAR_CHK_DUP(NONEWMOUNTS);
			} else if (strcmp($1.str, "abortqueue") == 0) {
				MMS_PAR_CHK_DUP(ABORTQUEUE);
			} else if (strcmp($1.str, "force") == 0) {
				MMS_PAR_CHK_DUP(FORCE);
			} else if (strcmp($1.str, "restart") == 0) {
				MMS_PAR_CHK_DUP(RESTART);
			} else {
				yyerror("unexpected STRING, expecting "
				    "nonewapps, nonewmounts, abortqueue "
				    "force or restart");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

restart_clause
	: restart
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

restart	: RESTART
		{
			MMS_PAR_CHK_DUP(RESTART);
		}
	| STRING
		{
			if (strcmp($1.str, "restart")) {
				yyerror("unexpected STRING, expecting "
				    "restart");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

release_cmd
	: RELEASE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "release", MMS_PN_CMD);
		}
	  release_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) &&
			    MMS_PAR_CHK_FLAG(REQID)) {
				yyerror("match and reqid clauses are "
				    "incompatible");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

release_arg_list
	: release_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| release_arg_list release_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

release_arg
	: task_clause
	| reqid_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

privilege_cmd
	: PRIVILEGE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "privilege", MMS_PN_CMD);
		}
	  privilege_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(LEVEL) == 0) {
				yyerror("a level clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

privilege_arg_list
	: privilege_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| privilege_arg_list privilege_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

privilege_arg
	: task_clause
	| level_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

level_clause
	: LEVEL
		{
			MMS_PAR_CHK_DUP(LEVEL);
		}
	  '[' level_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "level", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

level_arg
	: level
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

level	: STANDARD
	| ADMINISTRATOR
	| SYSTEM_PRIV
	| STRING
		{
			if (strcmp($1.str, "standard") &&
			    strcmp($1.str, "administrator") &&
			    strcmp($1.str, "system")) {
				yyerror("unexpected STRING, expecting "
				    "standard or administrator or "
				    "system_priv");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;


move_cmd
	: MOVE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "move", MMS_PN_CMD);
		}
	  move_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TOSLOT) == 0) {
				yyerror("a toslot clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CART) &&
			    MMS_PAR_CHK_FLAG(CARTID)) {
				yyerror("cart and cartid clauses are "
				    "incompatible");
			}
			if ((MMS_PAR_CHK_FLAG(CART) +
			    MMS_PAR_CHK_FLAG(CARTID)) &&
			    (MMS_PAR_CHK_FLAG(MATCH) + MMS_PAR_CHK_FLAG(ORDER) +
			    MMS_PAR_CHK_FLAG(NUMBER))) {
				yyerror("cart and cartid clauses are "
				    "incompatible with match, order and "
				    "number clauses");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

move_arg_list
	: move_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| move_arg_list move_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

move_arg
	: task_clause
	| to_slot_clause
	| move_cart_id_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

to_slot_clause
	: TOSLOT
		{
			MMS_PAR_CHK_DUP(TOSLOT);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "toslot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

move_cart_id_clause
	: move_id_clause
	| move_cart_clause
	;

move_id_clause
	: CARTID
		{
			MMS_PAR_CHK_DUP(CARTID);
		}
	  '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cartid", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

move_cart_clause
	: CART
		{
			MMS_PAR_CHK_DUP(CART);
		}
	  '[' str_arg str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cart", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;



locale_cmd
	: LOCALE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "locale", MMS_PN_CMD);
		}
	  locale_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

locale_arg_list
	: locale_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| locale_arg_list locale_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

locale_arg
	: task_clause
	| locale_language_clause
	| sortorder_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

locale_language_clause
	: LANGUAGE
		{
			MMS_PAR_CHK_DUP(LANGUAGE);
		}
	  '[' language_name opt_language_flavor_name ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "language",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

language_name
	: str_arg
	;

opt_language_flavor_name
	: /* Empty */ { $$.nodep = NULL; }
	| str_arg
	;

sortorder_clause
	: SORT
		{
			MMS_PAR_CHK_DUP(SORT);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "sort", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

inject_cmd
	: INJECT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "inject", MMS_PN_CMD);
		}
	  inject_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

inject_arg_list
	: inject_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| inject_arg_list inject_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

inject_arg
	: task_clause
	| slotgroup_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

goodbye_cmd
	: GOODBYE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "goodbye", MMS_PN_CMD);
		}
	  task_clause ';'
		{
			$$.nodep = $2.nodep;
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

end_cmd	: END
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "end", MMS_PN_CMD);
		}
	  end_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

end_arg_list
	: end_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| end_arg_list end_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

end_arg	: task_clause
	| abort_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

abort_clause
	: abort
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

abort	: ABORT
		{
			MMS_PAR_CHK_DUP(ABORT);
		}
	| STRING
		  {
			  if (strcmp($1.str, "abort")) {
				  yyerror("unexpected STRING, expecting "
					  "abort");
				  YYERROR;
			  }
			  $$.str = $1.str;
		  }
	;

eject_cmd
	: EJECT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "eject", MMS_PN_CMD);
		}
	  eject_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "REPORTMODE clause");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) +
			    (MMS_PAR_CHK_FLAG(CARTID) ||
			    MMS_PAR_CHK_FLAG(CART)) > 1) {
				yyerror("match is incompatible with cartid "
				    "and cart");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

eject_arg_list
	: eject_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| eject_arg_list eject_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

eject_arg
	: task_clause
	| slotgroup_clause
	| match_clause
	| cartridge_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cartridge_clause
	: cartid_clause
	| cart_spec
	;

cartid_clause
	: CARTID '[' cartid_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cartid", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

cartid_list
	: str_arg_list
	;

cart_spec
	: CART '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cart", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

slotgroup_clause
	: SLOTGROUP
		{
			MMS_PAR_CHK_DUP(SLOTGROUP);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "slotgroup",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

deallocate_cmd
	: DEALLOCATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "deallocate",
			    MMS_PN_CMD);
		}
	  deallocate_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

deallocate_arg_list
	: deallocate_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| deallocate_arg_list deallocate_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

deallocate_arg
	: task_clause
	| volname_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cpshow_cmd
	: CPSHOW
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpshow", MMS_PN_CMD);
		}
	  cpshow_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPTYPE) == 0) {
				yyerror("a cptype clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpshow_arg_list
	: cpshow_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpshow_arg_list cpshow_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpshow_arg
	: task_clause
	| cptype_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| cpreport_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cpscan_cmd
	: CPSCAN
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpscan", MMS_PN_CMD);
		}
	  cpscan_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(ALL)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(SLOT) ||
				    MMS_PAR_CHK_FLAG(DRIVE)) {
					yyerror("all is incompatible with "
					    "fromslot, toslot, "
					    "drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(SLOT)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(DRIVE)) {
					yyerror("slot is incompatible with "
					    "fromslot, toslot, "
					    "drive and all");
				}
			}
			if (MMS_PAR_CHK_FLAG(DRIVE)) {
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("drive is incompatible with "
					    "fromslot, toslot, "
					    "all and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(FROMSLOT)) {
				if (MMS_PAR_CHK_FLAG(DRIVE) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("fromslot is incompatible with "
					    "all, drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(TOSLOT)) {
				if (MMS_PAR_CHK_FLAG(DRIVE) ||
				    MMS_PAR_CHK_FLAG(ALL) ||
				    MMS_PAR_CHK_FLAG(SLOT)) {
					yyerror
					    ("toslot is incompatible with "
					    "all, drive and slot");
				}
			}
			if (MMS_PAR_CHK_FLAG(FROMSLOT) +
			    MMS_PAR_CHK_FLAG(TOSLOT) ==
			    1) {
				yyerror("fromslot and toslot must be "
				    "specified together");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpscan_arg_list
	: cpscan_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpscan_arg_list cpscan_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpscan_arg
	: task_clause
	| all_spec
	| from_spec
	| to_spec
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| scan_slot_clause
	| drive_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

all_spec
	: all
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

all	: ALL
		{
			MMS_PAR_CHK_DUP(ALL);
			if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
			    MMS_PAR_CHK_FLAG(TOSLOT)) {
				yyerror("all is incompatible with "
				    "fromslot and toslot");
				YYERROR;
			}
		}
	| STRING
		{
			if (strcmp($1.str, "all") == 0) {
				MMS_PAR_CHK_DUP(ALL);
				if (MMS_PAR_CHK_FLAG(FROMSLOT) ||
				    MMS_PAR_CHK_FLAG(TOSLOT)) {
					yyerror("all is incompatible with "
					    "fromslot and toslot");
					YYERROR;
				}
			} else {
				yyerror("unexpected STRING, expecting "
				    "full or partial");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

from_spec
	: FROMSLOT
		{
			MMS_PAR_CHK_DUP(FROMSLOT);
			if (MMS_PAR_CHK_FLAG(ALL)) {
				yyerror("all is incompatible with "
				    "fromslot and toslot");
				YYERROR;
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "fromslot",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

to_spec	: TOSLOT
		{
			MMS_PAR_CHK_DUP(TOSLOT);
			if (MMS_PAR_CHK_FLAG(ALL)) {
				yyerror("all is incompatible with "
				    "fromslot and toslot");
				YYERROR;
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "toslot", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

cpreset_cmd
	: CPRESET
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpreset", MMS_PN_CMD);
		}
	  cpreset_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPTYPE) == 0) {
				yyerror("a cptype clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpreset_arg_list
	: cpreset_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpreset_arg_list cpreset_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpreset_arg
	: task_clause
	| cptype_clause
	| scope_arg
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| cpreport_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cpstart_cmd
	: CPSTART
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpstart", MMS_PN_CMD);
		}
	  cpstart_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPTYPE) == 0) {
				yyerror("a cptype clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpstart_arg_list
	: cpstart_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpstart_arg_list cpstart_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpstart_arg
	: task_clause
	| cptype_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| cpreport_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cpexit_cmd
	: CPEXIT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpexit", MMS_PN_CMD);
		}
	  cpexit_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPTYPE) == 0) {
				yyerror("a cptype clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpexit_arg_list
	: cpexit_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpexit_arg_list cpexit_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpexit_arg
	: task_clause
	| cptype_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| cpreport_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cpattribute_cmd
	: CPATTRIBUTE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpattribute",
			    MMS_PN_CMD);
		}
	  cpattribute_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPTYPE) == 0) {
				yyerror("a cptype clause is required");
			}
			if (MMS_PAR_CHK_FLAG(CPSET) == 0 &&
			    MMS_PAR_CHK_FLAG(CPUNSET)
			    == 0) {
				yyerror("a cpset or cpunset clause is "
				    "required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (MMS_PAR_CHK_FLAG(CPREPORTMODE) &&
			    MMS_PAR_CHK_FLAG(CPREPORT) == 0) {
				yyerror
				    ("a cpreport clause is required with a "
				    "cpreportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cpattribute_arg_list
	: cpattribute_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpattribute_arg_list cpattribute_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpattribute_arg
	: task_clause
	| cptype_clause
	| cpset_clause
	| cpunset_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| cpreport_group
	| error { yyclearin; $$.nodep = NULL; }
	;

cptype_clause
	: CPTYPE
		{
			MMS_PAR_CHK_DUP(CPTYPE);
		}
	  '[' cptype_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cptype", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

cptype_spec
	: cptype
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

cptype	: LM
	| DM
	| STRING
		{
			if (strcmp($1.str, "LM") && strcmp($1.str, "DM")) {
				yyerror("unexpected STRING, expecting "
				    "LM or DM");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

cpset_clause
	: CPSET '[' cpattrname cpattrvalue ']'
		{
			MMS_PAR_SET_FLAG(CPSET);
			MMS_PAR_ALLOC_NODE($$.nodep, "cpset", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

cpunset_clause
	: CPUNSET '[' cpattrname ']'
		{
			MMS_PAR_SET_FLAG(CPUNSET);
			MMS_PAR_ALLOC_NODE($$.nodep, "cpunset",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

cpreport_group
	: cpreport_clause
	| cpreportmode_clause
	;

cpreport_clause
	: CPREPORT
		{
			MMS_PAR_CHK_DUP(CPREPORT);
		}
	  '[' cpattrname_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpreport",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

cpattrname_list
	: cpattrname
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cpattrname_list cpattrname
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cpreportmode_clause
	: CPREPORTMODE
		{
			MMS_PAR_CHK_DUP(CPREPORTMODE);
		}
	  '[' reportmode_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cpreportmode",
			    MMS_PN_CLAUSE);
			if ((MMS_PAR_CHK_FLAG(NAME) +
			    MMS_PAR_CHK_FLAG(NAMEVALUE) +
			    MMS_PAR_CHK_FLAG(UNIQUE)) > 2) {
				yyerror("only two of name, "
				    "namevalue and unique are allowed");
				YYERROR;
			}
			MMS_PAR_UNSET_FLAG(NAME);
			MMS_PAR_UNSET_FLAG(NAMEVALUE);
			MMS_PAR_UNSET_FLAG(UNIQUE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

cpattrname
	: str_arg
	;

cpattrvalue
	: str_arg
	;

cancel_cmd
	: CANCEL
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "cancel", MMS_PN_CMD);
		}
	  cancel_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

cancel_arg_list
	: cancel_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| cancel_arg_list cancel_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

cancel_arg
	: task_clause
	| match_clause
	| order_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

accept_cmd
	: ACCEPT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "accept", MMS_PN_CMD);
		}
	  accept_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) &&
			    MMS_PAR_CHK_FLAG(REQID)) {
				yyerror("match and reqid are incompatible");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

accept_arg_list
	: accept_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| accept_arg_list accept_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

accept_arg
	: task_clause
	| match_clause
	| reqid_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

reqid_clause
	: REQID
		{
			MMS_PAR_CHK_DUP(REQID);
		}
	  '[' reqid_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "reqid", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

reqid_list
	: str_arg_list
	;

respond_cmd
	: RESPOND
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "respond", MMS_PN_CMD);
		}
	  respond_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REQID) == 0) {
				yyerror("a reqid clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MESSAGE) == 0) {
				yyerror("a message clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

respond_arg_list
	: respond_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| respond_arg_list respond_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

respond_arg
	: task_clause
	| message_clause
	| respond_reqid_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

respond_reqid_clause
	: REQID
		{
			MMS_PAR_CHK_DUP(REQID);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "reqid", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

response_cmd
	: RESPONSE
		{
			mms_mmsp_allow_quote(1);
			MMS_PAR_ALLOC_NODE($$.nodep, "response", MMS_PN_CMD);
		}
	  response_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) == 0 &&
			    MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE)) {
				if (MMS_PAR_CHK_FLAG(TEXT)) {
					yyerror
					    ("unacceptable is incompatible "
					    "with text and task");
				}
			} else if (MMS_PAR_CHK_FLAG(ACCEPTED)) {
				if (MMS_PAR_CHK_FLAG(MESSAGE) ||
				    MMS_PAR_CHK_FLAG(TEXT)) {
					yyerror("accepted is incompatible "
					    "with message and task");
				}
			} else if (MMS_PAR_CHK_FLAG(SUCCESS)) {
				;
			} else if (MMS_PAR_CHK_FLAG(INTERMEDIATE)) {
				;
			} else if (MMS_PAR_CHK_FLAG(CANCELLED)) {
				if (MMS_PAR_CHK_FLAG(TEXT)) {
					yyerror("cancelled is incompatible "
					    "with text");
				}
			} else if (MMS_PAR_CHK_FLAG(ERROR)) {
				if (MMS_PAR_CHK_FLAG(TEXT)) {
					yyerror("error is incompatible "
					    "with text");
				}
			} else {
				yyerror("one of unacceptable, accepted, "
				    "success, intermediate, "
				    "cancelled or error is " "required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

response_arg_list
	: response_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| response_arg_list response_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

response_arg
	: UNACCEPTABLE
		{
			MMS_PAR_CHK_DUP(UNACCEPTABLE);
			if (MMS_PAR_CHK_FLAG(ACCEPTED) ||
			    MMS_PAR_CHK_FLAG(SUCCESS) ||
			    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
			    MMS_PAR_CHK_FLAG(CANCELLED) ||
			    MMS_PAR_CHK_FLAG(ERROR)) {
				yyerror("unacceptable is incompatible with "
				    "accepted, intermediate,"
				    "success, cancelled and error");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	| ACCEPTED
		{
			MMS_PAR_CHK_DUP(ACCEPTED);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
			    MMS_PAR_CHK_FLAG(SUCCESS) ||
			    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
			    MMS_PAR_CHK_FLAG(CANCELLED) ||
			    MMS_PAR_CHK_FLAG(ERROR)) {
				yyerror("accepted is incompatible with "
				    "unacceptable, intermediate,"
				    "success, cancelled and error");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	| SUCCESS
		{
			MMS_PAR_CHK_DUP(SUCCESS);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
			    MMS_PAR_CHK_FLAG(ACCEPTED) ||
			    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
			    MMS_PAR_CHK_FLAG(CANCELLED) ||
			    MMS_PAR_CHK_FLAG(ERROR)) {
				yyerror("success is incompatible with "
				    "unacceptable, intermediate,"
				    "accepted, cancelled and error");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	| INTERMEDIATE
		{
			MMS_PAR_CHK_DUP(INTERMEDIATE);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
			    MMS_PAR_CHK_FLAG(ACCEPTED) ||
			    MMS_PAR_CHK_FLAG(SUCCESS) ||
			    MMS_PAR_CHK_FLAG(CANCELLED) ||
			    MMS_PAR_CHK_FLAG(ERROR)) {
				yyerror("intermediate is incompatible with "
				    "unacceptable, success, "
				    "accepted, cancelled and error");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}

	| cancelled
		{
			MMS_PAR_CHK_DUP(CANCELLED);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
			    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
			    MMS_PAR_CHK_FLAG(ACCEPTED) ||
			    MMS_PAR_CHK_FLAG(SUCCESS) ||
			    MMS_PAR_CHK_FLAG(ERROR)) {
				yyerror("cancelled is incompatible with "
				    "unacceptable, intermediate,"
				    "accepted, cancelled and error");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	| STRING
		{
			if (strcmp($1.str, "unacceptable") == 0) {
				MMS_PAR_CHK_DUP(UNACCEPTABLE);
				if (MMS_PAR_CHK_FLAG(ACCEPTED) ||
				    MMS_PAR_CHK_FLAG(SUCCESS) ||
				    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
				    MMS_PAR_CHK_FLAG(CANCELLED) ||
				    MMS_PAR_CHK_FLAG(ERROR)) {
					yyerror
					    ("unacceptable is incompatible "
					    "with "
					    "accepted, intermediate,"
					    "success, cancelled and error");
					YYERROR;
				}
				MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
				    MMS_PN_KEYWORD);
			} else if (strcmp($1.str, "accepted") == 0) {
				MMS_PAR_CHK_DUP(ACCEPTED);
				if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
				    MMS_PAR_CHK_FLAG(SUCCESS) ||
				    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
				    MMS_PAR_CHK_FLAG(CANCELLED) ||
				    MMS_PAR_CHK_FLAG(ERROR)) {
					yyerror
					    ("accepted is incompatible with "
					    "unacceptable, intermediate,"
					    "success, cancelled and error");
					YYERROR;
				}
				MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
				    MMS_PN_KEYWORD);
			} else if (strcmp($1.str, "success") == 0) {
				MMS_PAR_CHK_DUP(SUCCESS);
				if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
				    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
				    MMS_PAR_CHK_FLAG(ACCEPTED) ||
				    MMS_PAR_CHK_FLAG(CANCELLED) ||
				    MMS_PAR_CHK_FLAG(ERROR)) {
					yyerror
					    ("success is incompatible with "
					    "unacceptable, intermediate,"
					    "accepted, cancelled and "
					    "error");
					YYERROR;
				}
				MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
				    MMS_PN_KEYWORD);
			} else if (strcmp($1.str, "intermediate") == 0) {
				MMS_PAR_CHK_DUP(INTERMEDIATE);
				if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
				    MMS_PAR_CHK_FLAG(SUCCESS) ||
				    MMS_PAR_CHK_FLAG(ACCEPTED) ||
				    MMS_PAR_CHK_FLAG(CANCELLED) ||
				    MMS_PAR_CHK_FLAG(ERROR)) {
					yyerror
					    ("intermediate is incompatible "
					    "with unacceptable, success,"
					    "accepted, cancelled and "
					    "error");
					YYERROR;
				}
				MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
				    MMS_PN_KEYWORD);
			} else if (strcmp($1.str, "cancelled") == 0) {
				MMS_PAR_CHK_DUP(CANCELLED);
				if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
				    MMS_PAR_CHK_FLAG(ACCEPTED) ||
				    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
				    MMS_PAR_CHK_FLAG(SUCCESS) ||
				    MMS_PAR_CHK_FLAG(ERROR)) {
					yyerror("cancelled is incompatible "
					    "with "
					    "unacceptable, intermediate,"
					    "accepted, cancelled and "
					    "error");
					YYERROR;
				}
				MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
				    MMS_PN_KEYWORD);
			} else {
				yyerror("unexpected STRING, expecting "
				    "unacceptable, accepted, success, "
				    "intermediate, "
				    "cancelled, error, text, task or "
				    "message");
				YYERROR;
			}
		}
	| ERROR '[' err_class_spec
		{
			/* Looking for an error code */
			mms_pwka->par_wka_flags |= MMS_PW_ERROR_CODE;
		}
	  err_code_spec ']'
		{
			MMS_PAR_CHK_DUP(ERROR);
			if (MMS_PAR_CHK_FLAG(UNACCEPTABLE) ||
			    MMS_PAR_CHK_FLAG(ACCEPTED) ||
			    MMS_PAR_CHK_FLAG(INTERMEDIATE) ||
			    MMS_PAR_CHK_FLAG(SUCCESS) ||
			    MMS_PAR_CHK_FLAG(CANCELLED)) {
				yyerror("error is incompatible with "
				    "unacceptable, intermediate, "
				    "accepted, success and cancelled");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, "error", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	| TEXT '[' text_arg_list ']'
		{
			MMS_PAR_SET_FLAG(TEXT);
			MMS_PAR_ALLOC_NODE($$.nodep, "text", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	| task_clause
	| message_clause
	| error
		{
			yyclearin;
			$$.nodep = NULL;
		}
	;

cancelled
	: CANCELLED
	| CANCELED
		{
			$$.str = "cancelled";
		}
	;

text_arg_list
	: text_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| text_arg_list text_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

text_arg: str_arg
	| ATTRLIST '[' str_arg_list ']'
		{
			MMS_PAR_SET_FLAG(ATTRLIST);
			MMS_PAR_ALLOC_NODE($$.nodep, "attrlist",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

err_class_spec
	: error_class
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

error_class
	: COMPAT | CONFIG | EXIST | EXPLICIT | INTERNAL | INVALID | PERMPRIV
	| RETRY | SUBOP | LANGUAGE | STATE | MM_C_MANAGEMENT | MM_C_INVALID
	| LM_C_INVALID | LM_C_COMMAND | DM_C_INVALID | DM_C_COMMAND
	| STRING
		{
			if (strcmp($1.str, "compat") &&
			    strcmp($1.str, "config") &&
			    strcmp($1.str, "exist") &&
			    strcmp($1.str, "explicit") &&
			    strcmp($1.str, "internal") &&
			    strcmp($1.str, "invalid") &&
			    strcmp($1.str, "permpriv") &&
			    strcmp($1.str, "retry") &&
			    strcmp($1.str, "subop") &&
			    strcmp($1.str, "language") &&
			    strcmp($1.str, "state") &&
			    strcmp($1.str, "MM_C_MANAGEMENT") &&
			    strcmp($1.str, "MM_C_INVALID") &&
			    strcmp($1.str, "DM_C_INVALID") &&
			    strcmp($1.str, "DM_C_COMMAND") &&
			    strcmp($1.str, "LM_C_INVALID") &&
			    strcmp($1.str, "LM_C_COMMAND")) {
				yyerror("unexpected STRING, expecting "
				    "compat, config, exist, explicit, "
				    "internal, invalid, permpriv, "
				    "retry, subop, language, state, "
				    "MM_C_MANAGEMENT, MM_C_INVALID, "
				    "DM_C_INVALID, "
				    "DM_C_COMMAND, LM_C_INVALID, "
				    "or LM_C_COMMAND");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

err_code_spec
	: err_code
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;


err_code: ERROR_CODE
	| STRING
	;

message_clause
	: MESSAGE
		{
			MMS_PAR_CHK_DUP(MESSAGE);
		}
	  '[' message_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "message",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

message_arg_list
	: message_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| message_arg_list message_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

message_arg
	: id_clause
	| arg_clause
	| locale_text_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

id_clause
	: ID
		{
			MMS_PAR_CHK_DUP(ID);
		}
	  '[' manufacturer model messageid ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "id", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $6.nodep);
		}
	;

manufacturer
	: str_arg
	;

model	: str_arg
	;

messageid
	: str_arg
	;

arg_clause
	: ARGUMENTS
		{
			MMS_PAR_CHK_DUP(ARGUMENTS);
		}
	  '[' arg_pair_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "arguments",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

arg_pair_list
	: str_arg str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	| arg_pair_list str_arg str_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			mms_par_list_insert_tail($1.listp, $3.nodep);
			$$.listp = $1.listp;
		}
	;

locale_text_clause
	: LOCTEXT
		{
			MMS_PAR_CHK_DUP(LOCTEXT);
		}
	  '[' language localized_string ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "loctext",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

localized_string
	: str_arg
	;

language: str_arg
	;

unmount_cmd
	: UNMOUNT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "unmount", MMS_PN_CMD);
		}
	  unmount_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) == 0 &&
			    MMS_PAR_CHK_FLAG(VOLNAME) == 0) {
				yyerror("a match or volname clause "
				    "is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

unmount_arg_list
	: unmount_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| unmount_arg_list unmount_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

unmount_arg
	: task_clause
	| mount_type_clause
	| volname_clause
	| match_clause
	| signature_clause
	| order_clause
	| number_clause
	| report_clause
	| reportmode_clause
	| physicalunmount_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

signature_clause
	: SIGNATURE
		{
			MMS_PAR_CHK_DUP(SIGNATURE);
		}
	  '[' signature_spec_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "signature",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

signature_spec_list
	: clean_spec
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| partition_signature_type str_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
			mms_par_list_insert_tail($$.listp, $2.nodep);
		}
	;

clean_spec
	: clean
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

clean	: CLEAN
		{
			MMS_PAR_CHK_DUP(CLEAN);
		}
	| STRING
		{
			if (strcmp($1.str, "clean")) {
				yyerror("unexpected STRING, expecting "
				    "clean");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

physicalunmount_clause
	: physicalunmount
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

physicalunmount
	: PHYSICALUNMOUNT
		{
			MMS_PAR_CHK_DUP(PHYSICALUNMOUNT);
		}
	| STRING
		{
			if (strcmp($1.str, "physicalunmount")) {
				yyerror("unexpected STRING, expecting "
				    "physicalunmount");
				YYERROR;
			}
		$$.str = $1.str}

		;

unwelcome_cmd
	: MMS_UNWELCOME
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "unwelcome", MMS_PN_CMD);
		}
	  unwelcome_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

unwelcome_arg_list
	: unwelcome_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| unwelcome_arg_list unwelcome_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

unwelcome_arg
	: str_arg
		{
			char   *err_list[] = {
				"SSAI_E_PROTOCOL_ERROR",
				"SSAI_E_ACCESS_DENIED",
				"SSAI_E_DUPLICATE_SESSION",
				"SSAI_E_UNKNOWN_LANGUAGE",
				"SSAI_E_UNSUPPORTED_LANGUAGE",
				"SSAI_E_SSL"
			};
			int	num_errs = sizeof (err_list) / sizeof (char *);
			int	i;

			$$.nodep = $1.nodep;
			for (i = 0; i < num_errs; i++) {
				if (strcmp(mms_pn_token($$.nodep),
				    err_list[i]) == 0) {
					break;
				}
			}
			if (i == num_errs) {
				/* Invalid error */
				char    msg[200];
				sprintf(msg, "Invalid error %s",
				    mms_pn_token($$.nodep));
				yyerror(msg);
				YYERROR;
			}
		}
	;

welcome_cmd
	: MMS_WELCOME
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "welcome", MMS_PN_CMD);
		}
	  welcome_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(VERSION) == 0) {
				yyerror("a version clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

welcome_arg_list
	: welcome_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| welcome_arg_list welcome_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

welcome_arg
	: version_clause
	| servername_clause
	| auth_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

servername_clause
	: SERVERNAME
		{
			MMS_PAR_CHK_DUP(SERVERNAME);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "servername",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

mmp_mount_cmd
	: MMP_MOUNT
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "mount", MMS_PN_CMD);
		}
	  mmp_mount_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

mmp_mount_arg_list
	: mmp_mount_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| mmp_mount_arg_list mmp_mount_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

mmp_mount_arg
	: task_clause
	| mount_type_clause
	| volname_clause
	| firstmount_clause
	| accessmode_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| when_clause
	| where_clause
	| retention_clause
	| filename_clause
	| blocksize_clause
	| filesequence_clause
	| volumeid_clause
	| user_clause
	| msgfile_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

msgfile_clause
	: MSGFILE '[' str_arg ']'
		{
			MMS_PAR_CHK_DUP(MSGFILE);
			MMS_PAR_ALLOC_NODE($$.nodep, "msgfile",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

retention_clause
	: RETENTION '[' num_arg ']'
		{
			MMS_PAR_CHK_DUP(RETENTION);
			MMS_PAR_ALLOC_NODE($$.nodep, "retention",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

user_clause
	: USER '[' str_arg ']'
		{
			MMS_PAR_CHK_DUP(USER);
			MMS_PAR_ALLOC_NODE($$.nodep, "user", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

volumeid_clause
	: VOLUMEID
		{
			MMS_PAR_CHK_DUP(VOLUMEID);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volumeid",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			if (strlen(mms_pn_token($4.nodep)) > 6) {
				yyerror
				    ("Volume ID greater than 6 characters");
			}
		}
	;

filename_clause
	: FILENAME
		{
			MMS_PAR_CHK_DUP(FILENAME);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "filename",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			if (strlen(mms_pn_token($4.nodep)) > 17) {
				yyerror
				    ("Filename greater than 17 characters");
			}
		}
	;

blocksize_clause
	: BLOCKSIZE
		{
			MMS_PAR_CHK_DUP(BLOCKSIZE);
		}
	  '[' num_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "blocksize",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

filesequence_clause
	: FILESEQUENCE
		{
			MMS_PAR_CHK_DUP(FILESEQUENCE);
		}
	  '[' num_arg ']'
		{
			int	fseq;
			MMS_PAR_ALLOC_NODE($$.nodep, "filesequence",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			fseq = 0;
			sscanf(mms_pn_token($4.nodep), "%d", &fseq);
			if (fseq == 0 || (fseq > 1)) {
				char    msg[100];
				sprintf("Unsupported filesequence: %s",
				    mms_pn_token($4.nodep));
				yyerror(msg);
			}
		}
	;

where_clause
	: WHERE
		{
			MMS_PAR_CHK_DUP(WHERE);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "where", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

mount_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' mount_type_arg_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

mount_type_arg_spec
	: mount_type_arg
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

mount_type_arg
	: SIDE | PARTITION | VOLUME
	| STRING
		{
			if (strcmp($1.str, "side") &&
			    strcmp($1.str, "partition") &&
			    strcmp($1.str, "volume")) {
				yyerror("unexpected STRING, expecting "
				    "side, partition or volume");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

firstmount_clause
	: FIRSTMOUNT '[' cap_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "firstmount",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

accessmode_clause
	: ACCESSMODE '[' cap_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "accessmode",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

cap_list
	: str_arg_list
	;

rename_cmd
	: RENAME
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "rename", MMS_PN_CMD);
		}
	  rename_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(NEWVOLNAME) == 0) {
				yyerror("a newvolname clause is required");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) &&
			    MMS_PAR_CHK_FLAG(VOLNAME)) {
				yyerror("match and volname clauses are "
				    "incompatible");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT)
			    == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

rename_arg_list
	: rename_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| rename_arg_list rename_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

rename_arg
	: task_clause
	| newvolname_clause
	| volname_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;


attribute_cmd
	: ATTRIBUTE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "attribute", MMS_PN_CMD);
		}
	  attribute_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if ((MMS_PAR_CHK_FLAG(SET) +
			    MMS_PAR_CHK_FLAG(UNSET)) == 0) {
				yyerror("one of set and unset clauses is "
				    "required");
			}
			if (MMS_PAR_CHK_FLAG(MATCH) &&
			    MMS_PAR_CHK_FLAG(VOLNAME)) {
				yyerror("only one of match and volname is "
				    "allowed");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT)
			    == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

attribute_arg_list
	: attribute_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| attribute_arg_list attribute_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

attribute_arg
	: task_clause
	| set_clause
	| unset_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

unset_clause
	: UNSET '[' unset_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "unset", MMS_PN_CLAUSE);
			MMS_PAR_SET_FLAG(UNSET);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

unset_arg
	: object_attribute_spec
	;

allocate_cmd
	: ALLOCATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "allocate", MMS_PN_CMD);
		}
	  allocate_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(NEWVOLNAME) == 0) {
				yyerror("a newvolname clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

allocate_arg_list
	: allocate_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| allocate_arg_list allocate_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

allocate_arg
	: task_clause
	| newvolname_clause
	| allocate_who_clause
	| match_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

allocate_who_clause
	: WHO
		{
			MMS_PAR_CHK_DUP(WHO);
		}
	  '[' str_arg opt_str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "who", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

newvolname_clause
	: NEWVOLNAME
		{
			MMS_PAR_CHK_DUP(NEWVOLNAME);
		}
	  '[' newvolname_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "newvolname",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

newvolname_arg_list
	: newvolname_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| newvolname_arg_list newvolname_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

newvolname_arg
	: str_arg
	;

delete_cmd
	: DELETE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "delete", MMS_PN_CMD);
		}
	  delete_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

delete_arg_list
	: delete_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| delete_arg_list delete_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

delete_arg
	: task_clause
	| object_type_clause
	| match_clause
	| volname_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

create_cmd
	: CREATE
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "create", MMS_PN_CMD);
		}
	  create_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(TYPE) == 0) {
				yyerror("a type clause is required");
			}
			if (MMS_PAR_CHK_FLAG(SET) == 0) {
				yyerror("a set clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

create_arg_list
	: create_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| create_arg_list create_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

create_arg
	: task_clause
	| object_type_clause
	| set_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

object_type_clause
	: TYPE
		{
			MMS_PAR_CHK_DUP(TYPE);
		}
	  '[' object_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "type", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

set_clause
	: SET '[' object_attribute_spec set_arg ']'
		{
			MMS_PAR_SET_FLAG(SET);
			MMS_PAR_ALLOC_NODE($$.nodep, "set", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

set_arg	: str_arg
	;

show_cmd: SHOW
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "show", MMS_PN_CMD);
		}
	  show_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (MMS_PAR_CHK_FLAG(REPORTMODE) &&
			    MMS_PAR_CHK_FLAG(REPORT) == 0) {
				yyerror
				    ("a report clause is required with a "
				    "reportmode clause");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

show_arg_list
	: show_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| show_arg_list show_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

show_arg
	: task_clause
	| match_clause
	| volname_clause
	| order_clause
	| number_clause
	| report_group
	| error { yyclearin; $$.nodep = NULL; }
	;

match_clause
	: MATCH
		{
			MMS_PAR_CHK_DUP(MATCH);
			if (MMS_PAR_CHK_FLAG(VOLNAME) == 1) {
				yyerror("a volname clause is incompatible "
				    "with the match clause");
				YYERROR;
			}
		}
	  '[' base_match ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "match", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

volname_clause
	: VOLNAME
		{
			MMS_PAR_CHK_DUP(VOLNAME);
			if (MMS_PAR_CHK_FLAG(MATCH) == 1) {
				yyerror("a volname clause is incompatible "
				    "with the match clause");
				YYERROR;
			}
		}
	  '[' volname_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "volname",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

order_clause
	: ORDER
		{
			MMS_PAR_CHK_DUP(ORDER);
		}
	  '[' order_one ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "order", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

number_clause
	: NUMBER
		{
			MMS_PAR_CHK_DUP(NUMBER);
		}
	  '[' number_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "number", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

number_spec
	: number_arg opt_range_spec
		{
			if ($2.nodep == NULL) {
				/* Not a range spec */
				$$.nodep = $1.nodep;
			} else {
				$$.nodep = $2.nodep;
				mms_list_insert_head(&$$.nodep->
				    pn_arglist, $1.nodep);
			}
		}
	;

opt_range_spec
	: /* nothing */
		{
			$$.nodep = NULL;
		}
	| RANGE
		{
			if (MMS_PAR_CHK_FLAG(LAST)) {
				/* Last canot be start of range */
				yyerror
				    ("range cannot be started with LAST");
				YYERROR;
			}
			mms_pwka->par_wka_flags |= MMS_PW_KEYWORD;
		}
	  number_arg
		{
			if (strcmp(mms_pn_token($3.nodep), "FIRST") == 0) {
				yyerror("range cannot be terminated "
				    "with FIRST");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, "..", MMS_PN_RANGE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

number_arg
	: NUMERIC
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
			    MMS_PN_NUMERIC | MMS_PN_STRING);
		}
	| NUMERIC_STR
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
			    MMS_PN_NUMERIC | MMS_PN_STRING);
		}
	| FIRST
		{
			MMS_PAR_CHK_DUP(FIRST);
			MMS_PAR_ALLOC_NODE($$.nodep, "FIRST", MMS_PN_KEYWORD);
		}
	| LAST
		{
			MMS_PAR_CHK_DUP(LAST);
			MMS_PAR_ALLOC_NODE($$.nodep, "LAST", MMS_PN_KEYWORD);
		}
	| STRING
		{
			if (strcmp($1.str, "FIRST") == 0) {
				MMS_PAR_CHK_DUP(FIRST);
			} else if (strcmp($1.str, "LAST") == 0) {
				MMS_PAR_CHK_DUP(LAST);
			} else {
				yyerror("unexpected STRING, expecting "
				    "first, last or NUMBER");
				YYERROR;
			}
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

report_group
	: report_clause
	| reportmode_clause
	;

report_clause
	: REPORT
		{
			MMS_PAR_CHK_DUP(REPORT);
		}
	  '[' report_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "report", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

report_arg_list
	: report_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| report_arg_list report_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

report_arg
	: object_attribute_spec
	| object_spec
	;

reportmode_clause
	: REPORTMODE
		{
			MMS_PAR_CHK_DUP(REPORTMODE);
		}
	  '[' reportmode_arg_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "reportmode",
			    MMS_PN_CLAUSE);
			if ((MMS_PAR_CHK_FLAG(NAME) +
			    MMS_PAR_CHK_FLAG(NAMEVALUE) +
			    MMS_PAR_CHK_FLAG(UNIQUE)) > 2) {
				yyerror("only two of name, "
				    "namevalue and unique are allowed");
				YYERROR;
			}
			MMS_PAR_UNSET_FLAG(NAME);
			MMS_PAR_UNSET_FLAG(NAMEVALUE);
			MMS_PAR_UNSET_FLAG(UNIQUE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

reportmode_arg_list
	: reportmode_arg_spec
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| reportmode_arg_list reportmode_arg_spec
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

reportmode_arg_spec
	: reportmode_arg
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

reportmode_arg
	: NAME
		{
			MMS_PAR_CHK_DUP(NAME);
		}
	| NAMEVALUE
		{
			MMS_PAR_CHK_DUP(NAMEVALUE);
		}
	| UNIQUE
		{
			MMS_PAR_CHK_DUP(UNIQUE);
		}
	| VALUE
		{
			MMS_PAR_CHK_DUP(VALUE);
		}
	| NUMBER
		{
			MMS_PAR_CHK_DUP(NUMBER);
		}
	| STRING
		{
			if (strcmp($1.str, "name") &&
			    strcmp($1.str, "namevalue") &&
			    strcmp($1.str, "unique") &&
			    strcmp($1.str, "number") &&
			    strcmp($1.str, "value")) {
				yyerror("unexpected STRING, expecting "
				    "name, namevalue, unique or value");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

order_one
	: STRLOHI '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strlohi", MMS_PN_OPS);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	| STRHILO '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strhilo", MMS_PN_OPS);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	| NUMLOHI '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numlohi", MMS_PN_OPS);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	| NUMHILO '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numhilo", MMS_PN_OPS);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

object_attribute_spec
	: object_spec '.' attr_name_spec
		{
			$3.nodep->pn_type = MMS_PN_ATTR;
			mms_par_list_insert_tail(&$1.nodep->pn_arglist,
			    $3.nodep);
			$$.nodep = $1.nodep;
		}
	;

attr_name_spec
	: str_arg
	;

object_spec
	: objectname_token
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_OBJ);
		}
	;

base_match
	: unaryattrop
	| unarynegop
	| unarysetop
	| topmatch
	;

unaryattrop
	: ISATTR '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "isattr", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_UNARYOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	| NOATTR '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "noattr", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_UNARYOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

unarynegop
	: NOT '(' matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "not", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_UNARYOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

unarysetop
	: ISSET '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "isset", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_UNARYOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	| NOTSET '(' object_attribute_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "notset", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_UNARYOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

topmatch: binaryop
	| multiop
	;

binaryop: REGEX '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "regex", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    (MMS_PN_MULTIOPS | MMS_PN_REGEX);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STREQ '(' streq_spec streq_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "streq", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STRNE '(' streq_spec streq_spec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strne", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STRLT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strlt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STRLE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strle", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STRGT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strgt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| STRGE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "strge", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| HOSTEQ '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "hosteq", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| HOSTNE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "hostne", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMEEQ '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timeeq", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMENE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timene", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMELT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timelt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMELE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timele", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMEGT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timegt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| TIMEGE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "timege", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMEQ '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numeq", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMNE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numne", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMLT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numlt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMLE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numle", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMGT '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numgt", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	| NUMGE '(' matchspec matchspec ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "numge", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

multiop	: AND '(' matchspec_list ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "and", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	| OR '(' matchspec_list ')'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "or", MMS_PN_OPS);
			mms_pwka->par_wka_cur_node->pn_flags |=
			    MMS_PN_MULTIOPS;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
		}
	;

matchspec_list
	: matchspec
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| matchspec_list matchspec
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

streq_spec
	: matchspec
	;

matchspec
	: topmatch
	| unaryattrop
	| unarysetop
	| unarynegop
	| object_attribute_spec
	| str_arg
	;

volname_arg_list
	: str_arg_list
	;

begin_cmd
	: BEGIN_CMD
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "begin", MMS_PN_CMD);
		}
	  begin_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (MMS_PAR_CHK_FLAG(TASK) == 0) {
				yyerror("a task clause is required");
			}
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

begin_arg_list
	: begin_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| begin_arg_list begin_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

begin_arg
	: task_clause
	| when_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

task_clause
	: TASK
		{
			MMS_PAR_CHK_DUP(TASK);
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "task", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

when_clause
	: WHEN
		{
			MMS_PAR_CHK_DUP(WHEN);
		}
	  '[' when_arg_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "when", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

when_arg_spec
	: when_arg
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

when_arg: IMMEDIATE
		{
			MMS_PAR_CHK_DUP(IMMEDIATE);
			if (MMS_PAR_CHK_FLAG(BLOCKING) == 1) {
				yyerror("blocking and immediate are "
				    "incompatible");
				YYERROR;
			}
		}
	| BLOCKING
		{
			MMS_PAR_CHK_DUP(BLOCKING);
			if (MMS_PAR_CHK_FLAG(IMMEDIATE) == 1) {
				yyerror("blocking and immediate are "
				    "incompatible");
				YYERROR;
			}
		}
	| STRING
		{
			if (strcmp($1.str, "immediate") == 0) {
				MMS_PAR_CHK_DUP(IMMEDIATE);
				if (MMS_PAR_CHK_FLAG(BLOCKING) == 1) {
					yyerror
					    ("blocking and immediate are "
					    "incompatible");
					YYERROR;
				}
			} else if (strcmp($1.str, "blocking") == 0) {
				MMS_PAR_CHK_DUP(BLOCKING);
				if (MMS_PAR_CHK_FLAG(IMMEDIATE) == 1) {
					yyerror
					    ("blocking and immediate are "
					    "incompatible");
					YYERROR;
				}
			} else {
				yyerror("unexpected STRING, expecting "
				    "immediate or blocking");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

hello_cmd
	: HELLO
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "hello", MMS_PN_CMD);
		}
	  hello_arg_list ';'
		{
			$$.nodep = $2.nodep;
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $3.listp);
			if (mms_pwka->par_wka_flags & MMS_PW_ERROR) {
				YYERROR;
			}
		}
	;

hello_arg_list
	: hello_arg
		{
			MMS_PAR_ALLOC_LIST($$.listp);
			mms_par_list_insert_tail($$.listp, $1.nodep);
		}
	| hello_arg_list hello_arg
		{
			mms_par_list_insert_tail($1.listp, $2.nodep);
			$$.listp = $1.listp;
		}
	;

hello_arg
	: client_clause
	| instance_clause
	| language_clause
	| version_clause
	| auth_clause
	| tag_clause
	| error { yyclearin; $$.nodep = NULL; }
	;

client_clause
	: CLIENT '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "client", MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}
	;

instance_clause
	: INSTANCE '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "instance",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}

	;

language_clause
	: LANGUAGE '[' lang_arg_spec ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "language",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $3.nodep);
		}

	;

lang_arg_spec
	: lang_arg
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

lang_arg: MMP
	| DMP
	| LMP
	| STRING
		{
			if (strcmp($1.str, "MMP") &&
			    strcmp($1.str, "DMP") &&
			    strcmp($1.str, "LMP")) {
				yyerror("unexpected STRING, expecting "
				    "MMP, DMP or LMP");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

version_clause
	: VERSION
		{
			MMS_PAR_CHK_DUP(VERSION);
		}
	  '[' version_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "version",
			    MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

version_list
	: str_arg_list
	;

auth_clause
	: password_clause
	| certificate_clause
	;

tag_clause
	: TAG
		{
			MMS_PAR_CHK_DUP(TAG);
		}
	  '[' tag_list ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "tag", MMS_PN_CLAUSE);
			mms_list_move_tail(&$$.nodep->pn_arglist,
			    $4.listp);
		}
	;

tag_list
	: str_arg_list
	;


password_clause
	: PASSWORD
		{
			MMS_PAR_CHK_DUP(PASSWORD);
			if (MMS_PAR_CHK_FLAG(CERTIFICATE)) {
				yyerror("certificate and password "
				    "clauses are incompatible");
				YYERROR;
			}
		}
	  '[' str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "password",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
		}
	;

certificate_clause
	: CERTIFICATE
		{
			MMS_PAR_CHK_DUP(CERTIFICATE);
			if (MMS_PAR_CHK_FLAG(PASSWORD)) {
				yyerror("certificate and password "
				    "clauses are incompatible");
				YYERROR;
			}
		}
	  '[' str_arg str_arg ']'
		{
			MMS_PAR_ALLOC_NODE($$.nodep, "certificate",
			    MMS_PN_CLAUSE);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $4.nodep);
			mms_par_list_insert_tail(&$$.nodep->pn_arglist,
			    $5.nodep);
		}
	;

str_arg	: string
	| numeric_string
	;

num_arg	: number
	| numeric_string
	;

string	: STRING
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_STRING);
		}
	;

number	: NUMERIC
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
			    MMS_PN_NUMERIC | MMS_PN_STRING);
		}
	;

numeric_string
	: NUMERIC_STR
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str,
			    MMS_PN_NUMERIC | MMS_PN_STRING);
		}
	;

opt_str_arg_list
	: /* Empty */ { $$.listp = NULL; }
	| str_arg_list
	;

opt_str_arg
	: /* Empty */ { $$.nodep = NULL; }
	| str_arg
	;

objectname_token
	: APPLICATION | AI | BAY | CARTRIDGE |
	  CARTRIDGEGROUP | CARTRIDGEGROUPAPPLICATION |
	  CARTRIDGETYPE | CONNECTION | DM | DMBITFORMAT |
	  DMBITFORMATTOKEN | DMCAPABILITY | DMCAPABILITYTOKEN |
	  DMCAPABILITYDEFAULTTOKEN | DMCAPABILITYGROUP |
	  DMCAPABILITYGROUPTOKEN | DRIVE | DRIVEGROUP |
	  DRIVEGROUPAPPLICATION | DRIVECARTRIDGEACCESS | LM |
	  LIBRARY | MESSAGE | MOUNTLOGICAL | MOUNTPHYSICAL |
	  PARTITION | REQUEST | SESSION | SIDE | SLOT_OBJ |
	  SLOTCONFIG | SLOTGROUP | SLOTTYPE | STALEHANDLE |
	  SYSTEM | TASK | TASKCARTRIDGE | TASKDRIVE |
	  TASKLIBRARY | VOLUME | NOTIFY | LIBRARYLIST |
	  DRIVELIST | CARTRIDGELIST | DRIVECARTRIDGEERROR |
	  LIBRARYACCESS
	;

true_or_false_spec
	: true_or_false
		{
			MMS_PAR_ALLOC_NODE($$.nodep, $1.str, MMS_PN_KEYWORD);
		}
	;

true_or_false
	: TRUE | FALSE
	| STRING
		{
			if (strcmp($1.str, "true") &&
			    strcmp($1.str, "false")) {
				yyerror("unexpected STRING, expecting "
				    "true or false");
				YYERROR;
			}
			$$.str = $1.str;
		}
	;

%%

/*
 * If 'change' verify that only one object is  referenced in the match
 * clause and it matches the object specified in the object clause.
 */
char *
mms_mmp_validate_object(mms_par_node_t *recv)
{
	mms_par_node_t	*to;
	mms_par_node_t	*match;
	mms_par_node_t	*obj_cl;
	char		*cur_obj;
	mms_par_node_t	*obj;
	mms_par_node_t	*work = NULL;

	mms_pn_fini(recv);
	obj_cl = mms_pn_lookup(recv, "object", MMS_PN_CLAUSE, NULL);
	if (obj_cl == NULL) {
		return ("no object clause");
	}
	obj_cl = mms_pn_lookup(obj_cl, "", MMS_PN_OBJ, NULL);
	cur_obj = mms_pn_token(obj_cl);
	to = mms_pn_lookup(recv, "to", MMS_PN_CLAUSE, NULL);
	if (to == NULL) {
		return (NULL);
	}
	if (match = mms_pn_lookup(to, "match", MMS_PN_CLAUSE, NULL)) {
		work = NULL;
		while (obj = mms_pn_lookup(match, "", MMS_PN_OBJ, &work)) {
			if (strcmp(cur_obj, mms_pn_token(obj))) {
				return ("object in to clause does not "
				    "match object in object clause");
			}
		}
	}
	return (NULL);
}
