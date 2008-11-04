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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <unistd.h>
#include <libintl.h>
#include <limits.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <sys/stat.h>
#include <zone.h>
#include <netdb.h>

#include <iscsitgt_impl.h>
#include "cmdparse.h"
#include "helper.h"

#define	CREATE	SUBCOMMAND(0)
#define	LIST	SUBCOMMAND(1)
#define	MODIFY	SUBCOMMAND(2)
#define	DELETE	SUBCOMMAND(3)
#define	SHOW	SUBCOMMAND(4)

#define	TARGET		OBJECT(0)
#define	INITIATOR	OBJECT(1)
#define	ADMIN		OBJECT(2)
#define	TPGT		OBJECT(3)
#define	STATS		OBJECT(4)

#define	VERSION_STRING_MAX_LEN	10
#define	MAX_IPADDRESS_LEN	128

/*
 * Version number:
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
#define	VERSION_STRING_MAJOR	    "1"
#define	VERSION_STRING_MINOR	    "0"

#define	OPT_ENABLE	"enable"
#define	OPT_DISABLE	"disable"
#define	OPT_TRUE	"true"
#define	OPT_FALSE	"false"

/* subcommand functions */
static int createFunc(int, char **, int, cmdOptions_t *, void *);
static int listFunc(int, char **, int, cmdOptions_t *, void *);
static int modifyFunc(int, char **, int, cmdOptions_t *, void *);
static int deleteFunc(int, char **, int, cmdOptions_t *, void *);
static int showFunc(int, char **, int, cmdOptions_t *, void *);

/* object functions per subcommand */
static int createTarget(int, char *[], cmdOptions_t *);
static int createInitiator(int, char *[], cmdOptions_t *);
static int createTpgt(int, char *[], cmdOptions_t *);
static int modifyTarget(int, char *[], cmdOptions_t *);
static int modifyInitiator(int, char *[], cmdOptions_t *);
static int modifyTpgt(int, char *[], cmdOptions_t *);
static int modifyAdmin(int, char *[], cmdOptions_t *);
static int deleteTarget(int, char *[], cmdOptions_t *);
static int deleteInitiator(int, char *[], cmdOptions_t *);
static int deleteTpgt(int, char *[], cmdOptions_t *);
static int listTarget(int, char *[], cmdOptions_t *);
static int listInitiator(int, char *[], cmdOptions_t *);
static int listTpgt(int, char *[], cmdOptions_t *);
static int showAdmin(int, char *[], cmdOptions_t *);
static int showStats(int, char *[], cmdOptions_t *);

/* globals */
char *cmdName;

/*
 * Add new options here
 */
optionTbl_t longOptions[] = {
	{"size", required_arg, 'z', "size k/m/g/t"},
	{"type", required_arg, 't', "disk/tape/osd/raw"},
	{"lun", required_arg, 'u', "number"},
	{"alias", required_arg, 'a', "value"},
	{"backing-store", required_arg, 'b', "pathname"},
	{"tpgt", required_arg, 'p', "tpgt number"},
	{"acl", required_arg, 'l', "local initiator"},
	{"maxrecv", required_arg, 'm', "max recv data segment length"},
	{"chap-secret", no_arg, 'C', NULL},
	{"chap-name", required_arg, 'H', "chap username"},
	{"iqn", required_arg, 'n', "iSCSI node name"},
	{"ip-address", required_arg, 'i', "ip address"},
	{"base-directory", required_arg, 'd', "directory"},
	{"radius-access", required_arg, 'R', "enable/disable"},
	{"radius-server", required_arg, 'r', "hostname[:port]"},
	{"radius-secret", no_arg, 'P', NULL},
	{"isns-access", required_arg, 'S', "enable/disable"},
	{"isns-server", required_arg, 's', "hostname[:port]"},
	{"fast-write-ack", required_arg, 'f', "enable/disable"},
	{"verbose", no_arg, 'v', NULL},
	{"interval", required_arg, 'I', "seconds"},
	{"count", required_arg, 'N', "number"},
	{"all", no_arg, 'A', NULL},
	{NULL, 0, 0, 0}
};

/*
 * Add new subcommands here
 */
subcommand_t subcommands[] = {
	{"create", CREATE, createFunc},
	{"list", LIST, listFunc},
	{"modify", MODIFY, modifyFunc},
	{"delete", DELETE, deleteFunc},
	{"show", SHOW, showFunc},
	{NULL, 0, NULL}
};

/*
 * Add objects here
 */
object_t objects[] = {
	{"target", TARGET},
	{"initiator", INITIATOR},
	{"admin", ADMIN},
	{"tpgt", TPGT},
	{"stats", STATS},
	{NULL, 0}
};

/*
 * Rules for subcommands and objects
 * ReqiredOp, OptioalOp, NoOp, InvalidOp, MultiOp
 */
objectRules_t objectRules[] = {
	/*
	 * create/modify/delete subcmd requires an operand
	 * list subcmd optionally requires an operand
	 * no subcmd requires no operand
	 * no subcmd is invalid for this operand
	 * no subcmd can accept multiple operands
	 */
	{TARGET, CREATE|MODIFY|DELETE, LIST, 0, SHOW, 0, "local-target"},
	/*
	 * create/modify/delete subcmd requires an operand
	 * list subcmd optionally requires an operand
	 * no subcmd requires no operand
	 * no subcmd is invalid for this operand
	 * no subcmd can accept multiple operands
	 */
	{INITIATOR, CREATE|MODIFY|DELETE, LIST, 0, SHOW, 0, "local-initiator"},
	/*
	 * no subcmd requires an operand
	 * no subcmd optionally requires an operand
	 * modify/list subcmd requires no operand
	 * create/delete subcmd are invlaid for this operand
	 * no subcmd can accept multiple operands
	 */
	{ADMIN, 0, 0, MODIFY|SHOW, CREATE|DELETE|LIST, 0, NULL},
	/*
	 * create/modify/delete subcmd requires an operand
	 * list subcmd optionally requires an operand
	 * no subcmd requires no operand
	 * no subcmd is invalid for this operand
	 * no subcmd can accept multiple operands
	 */
	{TPGT, CREATE|MODIFY|DELETE, LIST, 0, SHOW, 0, "local-tpgt"},
	/*
	 * no subcmd requires an operand
	 * list subcmd optionally requires an operand
	 * no subcmd requires no operand
	 * create/delete/modify subcmd are invalid for this operand
	 * no subcmd can accept multiple operands
	 */
	{STATS, 0, SHOW, 0, CREATE|MODIFY|DELETE|LIST, 0, "local-target"},
	{0, 0, 0, 0, 0, NULL}
};

/*
 * list of objects, subcommands, valid short options, required flag and
 * exclusive option string
 *
 * If it's not here, there are no options for that object.
 */
optionRules_t optionRules[] = {
	{TARGET, CREATE, "tuzab", B_TRUE, NULL},
	{TARGET, MODIFY, "plamzu", B_TRUE, NULL},
	{TARGET, DELETE, "ulp", B_TRUE, NULL},
	{TARGET, LIST,   "v", B_FALSE, NULL},
	{INITIATOR, CREATE, "n", B_TRUE, NULL},
	{INITIATOR, MODIFY, "CH", B_TRUE, NULL},
	{INITIATOR, DELETE, "A", B_TRUE, NULL},
	{INITIATOR, LIST,   "v", B_FALSE, NULL},
	{TPGT, MODIFY, "i", B_TRUE, NULL},
	{TPGT, DELETE, "Ai", B_TRUE, NULL},
	{TPGT, LIST,   "v", B_FALSE, NULL},
	{ADMIN, MODIFY, "dHCRrPSsf", B_TRUE, NULL},
	{STATS, SHOW, "IN", B_FALSE, NULL},
};



/*ARGSUSED*/
static int
createFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int ret;

	switch (object) {
		case TARGET:
			ret = createTarget(operandLen, operand, options);
			break;
		case INITIATOR:
			ret = createInitiator(operandLen, operand, options);
			break;
		case TPGT:
			ret = createTpgt(operandLen, operand, options);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
listFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int ret;

	switch (object) {
		case TARGET:
			ret = listTarget(operandLen, operand, options);
			break;
		case INITIATOR:
			ret = listInitiator(operandLen, operand, options);
			break;
		case TPGT:
			ret = listTpgt(operandLen, operand, options);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
showFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int ret;

	switch (object) {
		case STATS:
			ret = showStats(operandLen, operand, options);
			break;
		case ADMIN:
			ret = showAdmin(operandLen, operand, options);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
modifyFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int ret;

	switch (object) {
		case TARGET:
			ret = modifyTarget(operandLen, operand, options);
			break;
		case INITIATOR:
			ret = modifyInitiator(operandLen, operand, options);
			break;
		case TPGT:
			ret = modifyTpgt(operandLen, operand, options);
			break;
		case ADMIN:
			ret = modifyAdmin(operandLen, operand, options);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

/*ARGSUSED*/
static int
deleteFunc(int operandLen, char *operand[], int object, cmdOptions_t *options,
    void *addArgs)
{
	int ret;

	switch (object) {
		case TARGET:
			ret = deleteTarget(operandLen, operand, options);
			break;
		case INITIATOR:
			ret = deleteInitiator(operandLen, operand, options);
			break;
		case TPGT:
			ret = deleteTpgt(operandLen, operand, options);
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n",
			    cmdName, gettext("unknown object"));
			ret = 1;
			break;
	}
	return (ret);
}

static int
formatErrString(tgt_node_t *node)
{
	int	code	= 0;
	int	rtn	= 0;
	char	*msg	= NULL;

	if (node == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Unable to contact target daemon"));
		return (1);
	}
	if ((strcmp(node->x_name, XML_ELEMENT_ERROR) == 0) &&
	    (tgt_find_value_int(node, XML_ELEMENT_CODE, &code) == B_TRUE) &&
	    (tgt_find_value_str(node, XML_ELEMENT_MESSAGE, &msg) == B_TRUE)) {

		/*
		 * 1000 is the success code, so we don't need to display
		 * the success message.
		 */
		if (code != 1000) {
			(void) fprintf(stderr, "%s: %s %s\n",
			    cmdName, gettext("Error"), msg);
			rtn = 1;
		}
	} else {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		rtn = 1;
	}
	if (msg)
		free(msg);
	return (rtn);
}

/*ARGSUSED*/
static int
createTarget(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList = options;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "create", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 't': /* type */
				if ((strcmp(optionList->optarg, "disk")) &&
				    (strcmp(optionList->optarg, "tape")) &&
				    (strcmp(optionList->optarg, "raw")) &&
				    (strcmp(optionList->optarg, "osd"))) {
					(void) fprintf(stderr, "%s: %c: %s\n",
					    cmdName, optionList->optval,
					    gettext("unknown type"));
					free(first_str);
					return (1);
				} else {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_TYPE,
					    optionList->optarg);
				}
				break;
			case 'z': /* size */
				tgt_buf_add(&first_str, XML_ELEMENT_SIZE,
				    optionList->optarg);
				break;
			case 'u': /* lun number */
				tgt_buf_add(&first_str, XML_ELEMENT_LUN,
				    optionList->optarg);
				break;
			case 'a': /* alias */
				tgt_buf_add(&first_str, XML_ELEMENT_ALIAS,
				    optionList->optarg);
				break;
			case 'b': /* backing store */
				tgt_buf_add(&first_str, XML_ELEMENT_BACK,
				    optionList->optarg);
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				free(first_str);
				return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_End);
	tgt_buf_add_tag(&first_str, "create", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
createInitiator(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList	= options;

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "create", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	switch (optionList->optval) {
	case 'n': /* iqn */
		tgt_buf_add(&first_str, XML_ELEMENT_INAME, optionList->optarg);
		break;
	default:
		(void) fprintf(stderr, "%s: %c: %s\n",
		    cmdName, optionList->optval,
		    gettext("unknown option"));
		free(first_str);
		return (1);
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_End);
	tgt_buf_add_tag(&first_str, "create", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
createTpgt(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "create", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_End);
	tgt_buf_add_tag(&first_str, "create", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
modifyTarget(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList	= options;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "modify", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'p': /* tpgt number */
				tgt_buf_add(&first_str, XML_ELEMENT_TPGT,
				    optionList->optarg);
				break;
			case 'l': /* acl */
				tgt_buf_add(&first_str, XML_ELEMENT_ACL,
				    optionList->optarg);
				break;
			case 'a': /* alias */
				tgt_buf_add(&first_str, XML_ELEMENT_ALIAS,
				    optionList->optarg);
				break;
			case 'm': /* max recv */
				tgt_buf_add(&first_str, XML_ELEMENT_MAXRECV,
				    optionList->optarg);
				break;
			case 'z': /* grow lun size */
				tgt_buf_add(&first_str, XML_ELEMENT_SIZE,
				    optionList->optarg);
				break;
			case 'u':
				tgt_buf_add(&first_str, XML_ELEMENT_LUN,
				    optionList->optarg);
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				free(first_str);
				return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_End);
	tgt_buf_add_tag(&first_str, "modify", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
modifyInitiator(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList	= options;
	char		chapSecret[MAX_CHAP_SECRET_LEN+1];
	int		secretLen	= 0;
	int		ret		= 0;

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "modify", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
		case 'H': /* chap-name */
			if (strlen(optionList->optarg) != 0) {
				tgt_buf_add(&first_str, XML_ELEMENT_CHAPNAME,
				    optionList->optarg);
			} else {
				tgt_buf_add(&first_str,
				    XML_ELEMENT_DELETE_CHAPNAME,
				    OPT_TRUE);
			}
			break;
		case 'C': /* chap-secret */
			ret = getSecret((char *)&chapSecret[0], &secretLen,
			    MIN_CHAP_SECRET_LEN, MAX_CHAP_SECRET_LEN);
			if (ret != 0) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("Cannot read CHAP secret"));
				return (ret);
			}
			chapSecret[secretLen] = '\0';
			if (secretLen != 0) {
				tgt_buf_add(&first_str, XML_ELEMENT_CHAPSECRET,
				    chapSecret);
			} else {
				tgt_buf_add(&first_str,
				    XML_ELEMENT_DELETE_CHAPSECRET,
				    OPT_TRUE);
			}
			break;
		default:
			(void) fprintf(stderr, "%s: %c: %s\n",
			    cmdName, optionList->optval,
			    gettext("unknown option"));
			free(first_str);
			return (1);
		}
	}
	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_End);
	tgt_buf_add_tag(&first_str, "modify", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
modifyTpgt(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList	= options;
	boolean_t	isIpv6 = B_FALSE;
	uint16_t	port;
	char		IpAddress[MAX_IPADDRESS_LEN];

	if (operand == NULL)
		return (1);
	if (optionList == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "modify", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	switch (optionList->optval) {
	case 'i': /* ip address */
		if (parseAddress(optionList->optarg, 0,
		    IpAddress, 256, &port, &isIpv6) !=
		    PARSE_ADDR_OK) {
			return (1);
		}
		tgt_buf_add(&first_str, XML_ELEMENT_IPADDR, IpAddress);
		break;
	default:
		(void) fprintf(stderr, "%s: %c: %s\n",
		    cmdName, optionList->optval,
		    gettext("unknown option"));
		free(first_str);
		return (1);
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_End);
	tgt_buf_add_tag(&first_str, "modify", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
modifyAdmin(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList	= options;
	char		chapSecret[MAX_CHAP_SECRET_LEN+1];
	char		olddir[MAXPATHLEN];
	char		newdir[MAXPATHLEN];
	int		secretLen	= 0;
	int		ret		= 0;

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "modify", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_ADMIN, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'd': /* base directory */
				(void) getcwd(olddir, sizeof (olddir));

				/*
				 * Attempt to create the new base directory.
				 * This may fail for one of two reasons.
				 * (a) The path given is invalid or (b) it
				 * already exists. If (a) is true then then
				 * following chdir() will fail and the user
				 * notified. If (b) is true, then chdir() will
				 * succeed.
				 */
				(void) mkdir(optionList->optarg, 0700);

				if (chdir(optionList->optarg) == -1) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName, gettext("Invalid path"));
					free(first_str);
					return (1);
				}
				(void) getcwd(newdir, sizeof (newdir));
				tgt_buf_add(&first_str, XML_ELEMENT_BASEDIR,
				    newdir);
				(void) chdir(olddir);
				break;
			case 'H': /* chap name */
				if (strlen(optionList->optarg) != 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_CHAPNAME,
					    optionList->optarg);
				} else {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_DELETE_CHAPNAME,
					    OPT_TRUE);
				}
				break;
			case 'C': /* chap secert */
				ret = getSecret((char *)&chapSecret[0],
				    &secretLen,
				    MIN_CHAP_SECRET_LEN,
				    MAX_CHAP_SECRET_LEN);
				if (ret != 0) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("Cannot read CHAP secret"));
					free(first_str);
					return (ret);
				}
				chapSecret[secretLen] = '\0';
				if (secretLen != 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_CHAPSECRET,
					    chapSecret);
				} else {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_DELETE_CHAPSECRET,
					    OPT_TRUE);
				}
				break;
			case 'R': /* radius access */
				if (strcmp(optionList->optarg,
				    OPT_ENABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_RAD_ACCESS, OPT_TRUE);
				} else
					if (strcmp(optionList->optarg,
					    OPT_DISABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_RAD_ACCESS, OPT_FALSE);
				} else {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("Option value should be"
					    "enable/disable"));
					free(first_str);
					return (1);
				}
				break;
			case 'r': /* radius server */
				if (strlen(optionList->optarg) != 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_RAD_SERV,
					    optionList->optarg);
				} else {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_DELETE_RAD_SERV,
					    OPT_TRUE);
				}
				break;
			case 'P': /* radius secret */
				ret = getSecret((char *)&chapSecret[0],
				    &secretLen, MIN_CHAP_SECRET_LEN,
				    MAX_CHAP_SECRET_LEN);
				if (ret != 0) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("Cannot read RADIUS "
					    "secret"));
					free(first_str);
					return (ret);
				}
				chapSecret[secretLen] = '\0';
				if (secretLen != 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_RAD_SECRET,
					    chapSecret);
				} else {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_DELETE_RAD_SECRET,
					    OPT_TRUE);
				}
				break;
			case 'S': /* iSNS access */
				if (strcmp(optionList->optarg,
				    OPT_ENABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_ISNS_ACCESS, OPT_TRUE);
				} else
					if (strcmp(optionList->optarg,
					    OPT_DISABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_ISNS_ACCESS, OPT_FALSE);
				} else {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("Option value should be"
					    "enable/disable"));
					free(first_str);
					return (1);
				}
				break;
			case 's': /* iSNS server */
				if (strlen(optionList->optarg) >
				    MAXHOSTNAMELEN) {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("option too long"));
					return (1);
				}
				tgt_buf_add(&first_str, XML_ELEMENT_ISNS_SERV,
				    optionList->optarg);
				break;
			case 'f': /* fast write back */
				if (strcmp(optionList->optarg,
				    OPT_ENABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_FAST, OPT_TRUE);
				} else
					if (strcmp(optionList->optarg,
					    OPT_DISABLE) == 0) {
					tgt_buf_add(&first_str,
					    XML_ELEMENT_FAST, OPT_FALSE);
				} else {
					(void) fprintf(stderr, "%s: %s\n",
					    cmdName,
					    gettext("Option value should be"
					    "enable/disable"));
					free(first_str);
					return (1);
				}
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, optionList->optval,
				    gettext("unknown option"));
				free(first_str);
				return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_ADMIN, Tag_End);
	tgt_buf_add_tag(&first_str, "modify", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
deleteTarget(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList = options;

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "delete", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	switch (optionList->optval) {
	case 'u': /* all */
		tgt_buf_add(&first_str, XML_ELEMENT_LUN, optionList->optarg);
		break;
	case 'l': /* acl */
		tgt_buf_add(&first_str, XML_ELEMENT_ACL, optionList->optarg);
		break;
	case 'p': /* tpgt number */
		tgt_buf_add(&first_str, XML_ELEMENT_TPGT, optionList->optarg);
		break;
	default:
		(void) fprintf(stderr, "%s: %c: %s\n",
		    cmdName, optionList->optval,
		    gettext("unknown option"));
		free(first_str);
		return (1);
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_End);
	tgt_buf_add_tag(&first_str, "delete", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
deleteInitiator(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList = options;

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "delete", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	switch (optionList->optval) {
	case 'A': /* all */
		tgt_buf_add(&first_str, XML_ELEMENT_ALL, optionList->optarg);
		break;
	default:
		(void) fprintf(stderr, "%s: %c: %s\n",
		    cmdName, optionList->optval,
		    gettext("unknown option"));
		free(first_str);
		return (1);
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_End);
	tgt_buf_add_tag(&first_str, "delete", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

/*ARGSUSED*/
static int
deleteTpgt(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	cmdOptions_t	*optionList = options;
	boolean_t	isIpv6 = B_FALSE;
	uint16_t	port;
	char		IpAddress[MAX_IPADDRESS_LEN];

	if (operand == NULL)
		return (1);
	if (options == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "delete", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_Start);
	tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	switch (optionList->optval) {
	case 'A': /* all */
		tgt_buf_add(&first_str, XML_ELEMENT_ALL, optionList->optarg);
		break;
	case 'i': /* ip address */
		if (parseAddress(optionList->optarg, 0,
		    IpAddress, 256, &port, &isIpv6) !=
		    PARSE_ADDR_OK) {
			return (1);
		}
		tgt_buf_add(&first_str, XML_ELEMENT_IPADDR, IpAddress);
		break;
	default:
		(void) fprintf(stderr, "%s: %c: %s\n",
		    cmdName, optionList->optval,
		    gettext("unknown option"));
		free(first_str);
		return (1);
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_End);
	tgt_buf_add_tag(&first_str, "delete", Tag_End);

	node = tgt_door_call(first_str, 0);
	free(first_str);
	return (formatErrString(node));
}

static int
listTarget(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*n1		= NULL; /* pointer to node (depth=1) */
	tgt_node_t	*n2		= NULL; /* pointer to node (depth=2) */
	tgt_node_t	*n3		= NULL; /* pointer to node (depth=3) */
	tgt_node_t	*n4		= NULL; /* pointer to node (depth=4) */
	int		conns;
	char		buf[32];
	Boolean_t	verbose		= False;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "list", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_Start);

	if (operandLen)
		tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	/*
	 * Always retrieve the iostats which will give us the
	 * connection count information even if we're not doing
	 * a verbose output.
	 */
	tgt_buf_add(&first_str, XML_ELEMENT_IOSTAT, OPT_TRUE);

	if (options) {
		switch (options->optval) {
		case 0:
			break;
		case 'v':
			tgt_buf_add(&first_str, XML_ELEMENT_LUNINFO, OPT_TRUE);
			verbose = True;
			break;
		default:
			(void) fprintf(stderr, "%s: %c: %s\n", cmdName,
			    options->optval, gettext("unknown option"));
			free(first_str);
			return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_End);
	tgt_buf_add_tag(&first_str, "list", Tag_End);

	if ((node = tgt_door_call(first_str, 0)) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("No reponse from daemon"));
		return (1);
	}
	free(first_str);

	if (strcmp(node->x_name, XML_ELEMENT_RESULT)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		return (1);
	}

	n1 = NULL;
	while ((n1 = tgt_node_next_child(node, XML_ELEMENT_TARG, n1)) != NULL) {
		(void) printf("%s: %s\n", gettext("Target"), n1->x_value);
		n2 = tgt_node_next_child(n1, XML_ELEMENT_INAME, NULL);
		(void) printf("%s%s: %s\n", dospace(1), gettext("iSCSI Name"),
		    n2 ? n2->x_value : gettext("Not set"));

		if ((n2 = tgt_node_next_child(n1, XML_ELEMENT_ALIAS, NULL)) !=
		    NULL)
			(void) printf("%s%s: %s\n", dospace(1),
			    gettext("Alias"), n2->x_value);

		if ((n2 = tgt_node_next_child(n1, XML_ELEMENT_MAXRECV, NULL)) !=
		    NULL)
			(void) printf("%s%s: %s\n", dospace(1),
			    gettext("MaxRecv"), n2->x_value);

		/*
		 * Count the number of connections available.
		 */
		n2 = NULL;
		conns = 0;
		while (n2 = tgt_node_next_child(n1, XML_ELEMENT_CONN, n2))
			conns++;
		(void) printf("%s%s: %d\n", dospace(1), gettext("Connections"),
		    conns);

		if (verbose == False)
			continue;

		/*
		 * Displaying the individual connections must be done
		 * first when verbose is turned on because you'll notice
		 * above that we've left the output hanging with a label
		 * indicating connections are coming next.
		 */
		n2 = NULL;
		while (n2 = tgt_node_next_child(n1, XML_ELEMENT_CONN, n2)) {
			(void) printf("%s%s:\n", dospace(2),
			    gettext("Initiator"));
			(void) printf("%s%s: %s\n", dospace(3),
			    gettext("iSCSI Name"), n2->x_value);
			n3 = tgt_node_next_child(n2, XML_ELEMENT_ALIAS, NULL);
			(void) printf("%s%s: %s\n", dospace(3),
			    gettext("Alias"),
			    n3 ? n3->x_value : gettext("unknown"));
		}

		(void) printf("%s%s:\n", dospace(1), gettext("ACL list"));
		n2 = tgt_node_next_child(n1, XML_ELEMENT_ACLLIST, NULL);
		n3 = NULL;
		while (n3 = tgt_node_next_child(n2, XML_ELEMENT_INIT, n3)) {
			(void) printf("%s%s: %s\n", dospace(2),
			    gettext("Initiator"),
			    n3->x_value);
		}

		(void) printf("%s%s:\n", dospace(1), gettext("TPGT list"));
		n2 = tgt_node_next_child(n1, XML_ELEMENT_TPGTLIST, NULL);
		n3 = NULL;
		while (n3 = tgt_node_next_child(n2, XML_ELEMENT_TPGT, n3)) {
			(void) printf("%s%s: %s\n", dospace(2),
			    gettext("TPGT"),
			    n3->x_value);
		}

		(void) printf("%s%s:\n", dospace(1),
		    gettext("LUN information"));
		n2 = tgt_node_next_child(n1, XML_ELEMENT_LUNINFO, NULL);
		n3 = NULL;
		while (n3 = tgt_node_next_child(n2, XML_ELEMENT_LUN, n3)) {
			(void) printf("%s%s: %s\n", dospace(2), gettext("LUN"),
			    n3->x_value);

			n4 = tgt_node_next_child(n3, XML_ELEMENT_GUID, NULL);
			(void) printf("%s%s: %s\n", dospace(3), gettext("GUID"),
			    n4 ? n4->x_value : gettext("unknown"));

			n4 = tgt_node_next_child(n3, XML_ELEMENT_VID, NULL);
			(void) printf("%s%s: %s\n", dospace(3), gettext("VID"),
			    n4 ? n4->x_value : gettext("unknown"));

			n4 = tgt_node_next_child(n3, XML_ELEMENT_PID, NULL);
			(void) printf("%s%s: %s\n", dospace(3), gettext("PID"),
			    n4 ? n4->x_value : gettext("unknown"));

			n4 = tgt_node_next_child(n3, XML_ELEMENT_DTYPE, NULL);
			(void) printf("%s%s: %s\n", dospace(3), gettext("Type"),
			    n4 ? n4->x_value : gettext("unknown"));

			n4 = tgt_node_next_child(n3, XML_ELEMENT_SIZE, NULL);
			if (n4 && (strtol(n4->x_value, NULL, 0) != 0)) {
				(void) printf("%s%s: %s\n", dospace(3),
				    gettext("Size"),
				    number_to_scaled_string(buf,
				    strtoll(n4->x_value,
				    NULL, 0), 512, 1024));
			} else {
				(void) printf("%s%s: %s\n", dospace(3),
				    gettext("Size"), gettext("unknown"));
			}

			n4 = tgt_node_next_child(n3, XML_ELEMENT_BACK, NULL);
			if (n4) {
				(void) printf("%s%s: %s\n", dospace(3),
				    gettext("Backing store"), n4->x_value);
			}

			n4 = tgt_node_next_child(n3, XML_ELEMENT_STATUS, NULL);
			(void) printf("%s%s: %s\n", dospace(3),
			    gettext("Status"),
			    n4 ? n4->x_value : gettext("unknown"));
		}
	}

	return (0);
}

static int
listInitiator(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node;
	tgt_node_t	*n1		= NULL; /* pointer to node (depth=1) */
	tgt_node_t	*n2		= NULL; /* pointer to node (depth=2) */
	Boolean_t	verbose		= False;
	cmdOptions_t	*optionList	= options;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "list", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_Start);

	if (operandLen) {
		tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);
	}
	if (optionList) {
		switch (optionList->optval) {
		case 0:
			break;
		case 'v':
			verbose = True;
			tgt_buf_add(&first_str,
			    XML_ELEMENT_VERBOSE, OPT_TRUE);
			break;

		default:
			(void) fprintf(stderr, "%s: %c: %s\n",
			    cmdName, optionList->optval,
			    gettext("unknown option"));
			free(first_str);
			return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_INIT, Tag_End);
	tgt_buf_add_tag(&first_str, "list", Tag_End);

	if ((node = tgt_door_call(first_str, 0)) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("No reponse from daemon"));
		return (1);
	}
	free(first_str);

	if (strcmp(node->x_name, XML_ELEMENT_RESULT)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		return (1);
	}

	n1 = NULL;
	while (n1 = tgt_node_next_child(node, XML_ELEMENT_INIT, n1)) {
		(void) printf("%s: %s\n", gettext("Initiator"), n1->x_value);

		n2 = tgt_node_next_child(n1, XML_ELEMENT_INAME, NULL);
		(void) printf("%s%s: %s\n", dospace(1), gettext("iSCSI Name"),
		    n2 ? n2->x_value : gettext("Not set"));

		n2 = tgt_node_next_child(n1, XML_ELEMENT_CHAPNAME, NULL);
		(void) printf("%s%s: %s\n", dospace(1), gettext("CHAP Name"),
		    n2 ? n2->x_value : gettext("Not set"));

		if (verbose == True) {
			n2 = tgt_node_next_child(n1, XML_ELEMENT_CHAPSECRET,
			    NULL);
			(void) printf("%s%s: %s\n", dospace(1),
			    gettext("CHAP Secret"),
			    n2 ? gettext("Set") : gettext("Not set"));
		}

	}

	return (0);
}

static int
listTpgt(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*n1		= NULL; /* pointer to node (depth=1) */
	tgt_node_t	*n2		= NULL; /* pointer to node (depth=2) */
	cmdOptions_t	*optionList	= options;
	Boolean_t	verbose		= False;
	int		addrs;

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "list", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_Start);

	if (operandLen)
		tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);
	if (optionList) {
		switch (optionList->optval) {
		case 0: /* no options, treat as --verbose */
			break;
		case 'v':
			verbose = True;
			tgt_buf_add(&first_str,
			    XML_ELEMENT_VERBOSE, OPT_TRUE);
			break;
		default:
			(void) fprintf(stderr, "%s: %c: %s\n",
			    cmdName, optionList->optval,
			    gettext("unknown option"));
			free(first_str);
			return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TPGT, Tag_End);
	tgt_buf_add_tag(&first_str, "list", Tag_End);

	if ((node = tgt_door_call(first_str, 0)) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("No reponse from daemon"));
		return (1);
	}
	free(first_str);

	if (strcmp(node->x_name, XML_ELEMENT_RESULT)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		return (1);
	}

	n1 = NULL;
	while (n1 = tgt_node_next_child(node, XML_ELEMENT_TPGT, n1)) {
		(void) printf("%s: %s\n", gettext("TPGT"), n1->x_value);
		n2 = NULL;
		addrs = 0;
		while (n2 = tgt_node_next(n1, XML_ELEMENT_IPADDR, n2)) {
			if (verbose == True)
				(void) printf("%s%s: %s\n", dospace(1),
				    gettext("IP Address"),
				    n2 ? n2->x_value : gettext("Not set"));
			addrs++;
		}

		if (verbose == False) {
			(void) printf("%s%s: %d\n", dospace(1),
			    gettext("IP Address count"), addrs);
		} else if (addrs == 0) {

			/*
			 * Verbose is true, but there where no addresses
			 * for this TPGT. To keep the output consistent
			 * dump a "Not set" string out.
			 */
			(void) printf("%s%s: %s\n", dospace(1),
			    gettext("IP Address"), gettext("Not set"));
		}
	}

	return (0);
}

/*ARGSUSED*/
static int
showAdmin(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	tgt_node_t	*node		= NULL;
	tgt_node_t	*n1		= NULL; /* pointer to node (depth=1) */
	tgt_node_t	*n2		= NULL; /* pointer to node (depth=2) */

	if (operand == NULL)
		return (1);

	tgt_buf_add_tag(&first_str, "list", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_ADMIN, Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_ADMIN, Tag_End);
	tgt_buf_add_tag(&first_str, "list", Tag_End);

	if ((node = tgt_door_call(first_str, 0)) == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("No reponse from daemon"));
		return (1);
	}
	free(first_str);

	if (strcmp(node->x_name, XML_ELEMENT_RESULT)) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		return (1);
	}

	(void) printf("%s:\n", cmdName);

	n1 = tgt_node_next_child(node, XML_ELEMENT_ADMIN, NULL);
	if (n1 == NULL) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("Bad XML response"));
		return (1);
	}

	n2 = tgt_node_next_child(n1, XML_ELEMENT_BASEDIR, NULL);
	(void) printf("%s%s: %s\n", dospace(1), gettext("Base Directory"),
	    n2 ? n2->x_value : gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_CHAPNAME, NULL);
	(void) printf("%s%s: %s\n", dospace(1), gettext("CHAP Name"),
	    n2 ? n2->x_value : gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_RAD_ACCESS, NULL);
	(void) printf("%s%s: ", dospace(1), gettext("RADIUS Access"));
	if (n2) {
		if (strcmp(n2->x_value, OPT_TRUE) == 0)
			(void) printf("%s\n", gettext("Enabled"));
		else
			(void) printf("%s\n", gettext("Disabled"));
	} else
		(void) printf("%s\n", gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_RAD_SERV, NULL);
	(void) printf("%s%s: %s\n", dospace(1), gettext("RADIUS Server"),
	    n2 ? n2->x_value : gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_ISNS_ACCESS, NULL);
	(void) printf("%s%s: ", dospace(1), gettext("iSNS Access"));
	if (n2) {
		if (strcmp(n2->x_value, OPT_TRUE) == 0)
			(void) printf("%s\n", gettext("Enabled"));
		else
			(void) printf("%s\n", gettext("Disabled"));
	} else
		(void) printf("%s\n", gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_ISNS_SERV, NULL);
	(void) printf("%s%s: %s\n", dospace(1), gettext("iSNS Server"),
	    n2 ? n2->x_value : gettext("Not set"));

	n2 = tgt_node_next_child(n1, XML_ELEMENT_ISNS_SERVER_STATUS, NULL);
	if (n2) {
		/*
		 * if NULL, that means either the isns discovery is
		 * disabled or the server address is not set.
		 */
		if (n2->x_value != NULL) {
			(void) printf("%s%s: ", dospace(1),
			    gettext("iSNS Server Status"));
			(void) printf("%s\n", n2->x_value);
		}
	}

	n2 = tgt_node_next_child(n1, XML_ELEMENT_FAST, NULL);
	(void) printf("%s%s: ", dospace(1), gettext("Fast Write ACK"));
	if (n2) {
		if (strcmp(n2->x_value, OPT_TRUE) == 0)
			(void) printf("%s\n", gettext("Enabled"));
		else
			(void) printf("%s\n", gettext("Disabled"));
	} else
		(void) printf("%s\n", gettext("Not set"));

	return (0);
}

static int
showStats(int operandLen, char *operand[], cmdOptions_t *options)
{
	char		*first_str	= NULL;
	char		scale_buf[16];
	tgt_node_t	*node, *n1;
	int		interval	= -1;
	int		count		= -1;
	int		header;
	stat_delta_t	cur_data, *pd;

	tgt_buf_add_tag(&first_str, "list", Tag_Start);
	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_Start);

	tgt_buf_add(&first_str, XML_ELEMENT_IOSTAT, OPT_TRUE);
	if (operandLen)
		tgt_buf_add(&first_str, XML_ELEMENT_NAME, operand[0]);

	for (; options->optval; options++) {
		switch (options->optval) {
		case 0:
			break;
		case 'I': /* optarg = refresh interval */
			interval = atoi(options->optarg);
			if (interval == 0) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("interval must be non-zero"));
				free(first_str);
				return (1);
			}
			break;
		case 'N':
			count = atoi(options->optarg);
			if (count == 0) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("count must be non-zero"));
				free(first_str);
				return (1);
			}
			break;
		default:
			(void) fprintf(stderr, "%s: %c: %s\n", cmdName,
			    options->optval, gettext("unknown option"));
			free(first_str);
			return (1);
		}
	}

	tgt_buf_add_tag(&first_str, XML_ELEMENT_TARG, Tag_End);
	tgt_buf_add_tag(&first_str, "list", Tag_End);

	header = 1;
	/*CONSTANTCONDITION*/
	while (1) {
		if (--header == 0) {
			(void) printf("%20s  %12s  %12s\n", " ",
			    gettext("operations"), gettext("bandwidth "));
			(void) printf("%-20s  %5s  %5s  %5s  %5s\n",
			    gettext("device"), gettext("read"),
			    gettext("write"), gettext("read"),
			    gettext("write"));
			(void) printf("%-20s  %5s  %5s  %5s  %5s\n",
			    "--------------------", "-----", "-----",
			    "-----", "-----");
			header = 20;
		}
		if ((node = tgt_door_call(first_str, 0)) == NULL) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("No reponse from daemon"));
			return (1);
		}

		if (strcmp(node->x_name, XML_ELEMENT_RESULT)) {
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("Bad XML response"));
			free(first_str);
			tgt_node_free(node);
			stats_free();
			return (1);
		}

		n1 = NULL;
		while (n1 = tgt_node_next_child(node, XML_ELEMENT_TARG, n1)) {
			stats_load_counts(n1, &cur_data);
			if ((pd = stats_prev_counts(&cur_data)) == NULL) {
				free(first_str);
				tgt_node_free(node);
				return (1);
			}
			(void) printf("%-20s  ", pd->device);
			(void) printf("%5s  ",
			    number_to_scaled_string(scale_buf,
			    cur_data.read_cmds - pd->read_cmds, 1, 1024));
			(void) printf("%5s  ",
			    number_to_scaled_string(scale_buf,
			    cur_data.write_cmds - pd->write_cmds, 1, 1024));
			(void) printf("%5s  ",
			    number_to_scaled_string(scale_buf,
			    cur_data.read_blks - pd->read_blks, 512, 1024));
			(void) printf("%5s\n",
			    number_to_scaled_string(scale_buf,
			    cur_data.write_blks - pd->write_blks, 512, 1024));
			stats_update_counts(pd, &cur_data);
		}
		tgt_node_free(node);

		if (count == -1) {
			if (interval == -1)
				/* No count or internal, do it just once */
				break;
			else
				(void) sleep(interval);
		} else if (--count) {
			if (interval == -1)
				break;
			else
				(void) sleep(interval);
		} else
			break;
	}

	stats_free();
	free(first_str);
	return (0);
}

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}

/*
 * main calls a parser that checks syntax of the input command against
 * various rules tables.
 *
 * The parser provides usage feedback based upon same tables by calling
 * two usage functions, usage and subUsage, handling command and subcommand
 * usage respectively.
 *
 * The parser handles all printing of usage syntactical errors
 *
 * When syntax is successfully validated, the parser calls the associated
 * function using the subcommands table functions.
 *
 * Syntax is as follows:
 *	command subcommand [options] resource-type [<object>]
 *
 * The return value from the function is placed in funcRet
 */
int
main(int argc, char *argv[])
{
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	int ret;
	int funcRet;
	void *subcommandArgs = NULL;

	/* set global command name */
	cmdName = getExecBasename(argv[0]);

	if (getzoneid() != GLOBAL_ZONEID) {
		(void) fprintf(stderr,
		    "%s: this command is only available in the 'global' "
		    "zone\n", cmdName);
		exit(1);
	}

	(void) snprintf(versionString, sizeof (versionString), "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subcommandTbl = &subcommands[0];
	synTables.objectTbl = &objects[0];
	synTables.objectRulesTbl = &objectRules[0];
	synTables.optionRulesTbl = &optionRules[0];

	/* call the CLI parser */
	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret == 1) {
		(void) printf("%s %s(1M)\n",
		    gettext("For more information, please see"), cmdName);
		return (1);
	} else if (ret == -1) {
		perror(cmdName);
		return (1);
	}

	return (funcRet);
}
