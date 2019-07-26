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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This module implements the routine to parse the configuration file.
 */


#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <alloca.h>
#include <limits.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <sys/types.h>
#include <libintl.h>
#include <syslog.h>
#include <locale.h>
#include <picl.h>
#include <picltree.h>
#include "picld_pluginutil.h"
#include "picld_pluginutil_impl.h"

/* error codes returned from syntax checking */
#define	EC_SYNTAX_OK		0
#define	EC_INSUFFICIENT_TOKEN	1
#define	EC_SYNTAX_ERR		2
#define	EC_UNSUPPORTED		3
#define	EC_PATH_ERR		4
#define	EC_NODE_MISMATCH	5
#define	EC_FAILURE		6
#define	EC_PICL_ERR		7
#define	EC_TABLE_MISMATCH	8
#define	EC_ROW_MISMATCH		9
#define	EC_ROW_EMPTY		10

/*
 * Error message texts
 */
static	char	*err_msg[] = {
	"%s: Syntax OK",					/* 0 */
	"%s::%s[line %d]: Insufficient token\n",		/* 1 */
	"%s::%s[line %d]: Syntax error\n",			/* 2 */
	"%s::%s[line %d]: Unsupported or missing version\n",	/* 3 */
	"%s::%s[line %d]: Illegal use of nodepath or namepath\n",	/* 4 */
	"%s::%s[line %d]: Node and endnode mismatch\n",		/* 5 */
	"%s::%s[line %d]: General system failure\n",		/* 6 */
	"%s: PICL error code %d\n",				/* 7 */
	"%s::%s[line %d]: Table and endtable mismatch\n",	/* 8 */
	"%s::%s[line %d]: Row and endrow mismatch\n",		/* 9 */
	"%s::%s[line %d]: Row has no entries \n"		/* 10 */
};

/* token per directive */
#define	TOK_CLASSPATH	0
#define	TOK_NAMEPATH	1
#define	TOK_NODE	2
#define	TOK_ENDNODE	3
#define	TOK_PROP	4
#define	TOK_REFPROP	5
#define	TOK_VERSION	6
#define	TOK_REFNODE	7
#define	TOK_VERBOSE	8
#define	TOK_TABLE	9
#define	TOK_ENDTABLE	10
#define	TOK_ROW		11
#define	TOK_ENDROW	12

static const char	*tokens[] = {
	"_class",	/* _CLASS:<classpath> */
	"name",		/* NAME:<namepath> */
	"node",		/* NODE <name> <class> */
	"endnode",	/* ENDNODE */
	"prop",		/* PROP <name> <type> <access_mode> <size> <value> */
	"refprop",	/* REFPROP <prop> <destnode> */
	"version",	/* VERSION <version_number> */
	"refnode",	/* REFNODE <node> <class> WITH <destnode> */
	"verbose",	/* VERBOSE <level> */
	"table",	/* TABLE   <table_prop_name> */
	"endtable",	/* ENDTABLE */
	"row",		/* ROW  */
	"endrow"	/* ENDROW */
};

#define	BUF_SIZE_MAX	1024

/*
 * print error message
 */
/*VARARGS2*/
static void
verbose_log(int pri, const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vsyslog(pri, fmt, ap);
	va_end(ap);
}

/*
 * Undo the commands which have created valid node/prop handle
 * The undo order is from last command to the first command.
 */
static void
undo_commands(cmdbuf_t *cmds, int last_cmd_index)
{
	int		i;
	command_t	*com = cmds->commands;

	for (i = last_cmd_index; i >= 0; i--) {
		switch (com[i].type) {
		case TOK_NODE:
			if (com[i].nodecmd_nodeh == 0)
				break;

			(void) ptree_delete_node(com[i].nodecmd_nodeh);
			(void) ptree_destroy_node(com[i].nodecmd_nodeh);
			break;
		case TOK_REFNODE:
			if (com[i].refnodecmd_nodeh == 0)
				break;
			(void) ptree_delete_node(com[i].refnodecmd_nodeh);
			(void) ptree_destroy_node(com[i].refnodecmd_nodeh);
			break;
		case TOK_PROP:
			if (com[i].propcmd_proph == 0)
				break;
			(void) ptree_delete_prop(com[i].propcmd_proph);
			(void) ptree_destroy_prop(com[i].propcmd_proph);
			break;
		case TOK_REFPROP:
			if (com[i].refpropcmd_proph == 0)
				break;
			(void) ptree_delete_prop(com[i].refpropcmd_proph);
			(void) ptree_destroy_prop(com[i].refpropcmd_proph);
			break;
		case TOK_TABLE:
			if ((com[i].tablecmd_tblh == 0) ||
			    (com[i].tablecmd_newtbl == 0))
				break;
			(void) ptree_delete_prop(com[i].tablecmd_tblh);
			(void) ptree_destroy_prop(com[i].tablecmd_tblh);
			break;
		case TOK_ENDTABLE:
			/*FALLTHROUGH*/
		case TOK_ROW:
			/*FALLTHROUGH*/
		case TOK_ENDROW:
			/*FALLTHROUGH*/
		case TOK_NAMEPATH:
			/*FALLTHROUGH*/
		case TOK_CLASSPATH:
			/*FALLTHROUGH*/
		case TOK_ENDNODE:
			/*FALLTHROUGH*/
		case TOK_VERBOSE:
			/*FALLTHROUGH*/
		default:
			break;
		}
	}
}

/*
 * Get the token index from the tokens table
 */
static int
get_token_id(char *t)
{
	int	i;

	for (i = 0; i < sizeof (tokens)/ sizeof (char *); ++i)
		if (strcasecmp(tokens[i], t) == 0)
			return (i);

	return (-1);
}

/*
 * Check the version syntax and set the version_no
 *
 * VERSION <version_num> --   specify the configuration version
 */
static int
parse_version(cmdbuf_t *cmds, char *line)
{
	char	*tok;
	char	*vertok;
	char	*last;
	char	*endptr;

	/* get the VERSION directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the version number */
	vertok = strtok_r(last, WHITESPACE, &last);
	if (vertok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	cmds->version_no = (float)strtod(vertok, &endptr);
	if (endptr != (vertok + strlen(vertok)))
		return (EC_UNSUPPORTED);

	if (cmds->version_no > (float)SUPPORTED_VERSION_NUM)
		return (EC_UNSUPPORTED);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	return (EC_SYNTAX_OK);
}

/*
 * free path_cmd_t
 */
static void
free_path(command_t *command)
{
	free(command->pathcmd_name);
}

/*
 * Check the path syntax
 * NAMEPATH:<namepath> --     gives the anchor node
 * or
 * CLASSPATH:<classpath> --   gives the anchor node
 */
static int
parse_path(char *line, command_t *command)
{
	char	*tok;
	char	*pathtok;
	char	*last;

	pathtok = strtok_r(line, WHITESPACE, &last);
	if (pathtok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	command->pathcmd_name = strdup(pathtok);
	if (command->pathcmd_name == NULL)
		return (EC_FAILURE);

	return (EC_SYNTAX_OK);
}

/*
 * Process the path command and return PICL node handle
 */
static int
process_path(command_t *command, picl_nodehdl_t *nodeh)
{
	int	err;

	err = ptree_get_node_by_path(command->pathcmd_name, nodeh);
	return (err);
}

/*
 * free node_cmd_t
 */
static void
free_node(command_t *command)
{
	free(command->nodecmd_nodename);
	free(command->nodecmd_classname);
}

/*
 * Check the NODE syntax
 * NODE <name> <class>
 */
static int
parse_node(char *line, command_t *command)
{
	char	*tok;
	char	*nametok;
	char	*classtok;
	char	*last;

	/* get the NODE directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get name */
	nametok = strtok_r(last, WHITESPACE, &last);
	if (nametok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	classtok = strtok_r(last, WHITESPACE, &last);
	if (classtok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	command->nodecmd_nodename = strdup(nametok);
	command->nodecmd_classname = strdup(classtok);
	command->nodecmd_nodeh = 0;
	if ((command->nodecmd_nodename == NULL) ||
	    (command->nodecmd_classname == NULL))
		return (EC_FAILURE);

	return (EC_SYNTAX_OK);
}

/*
 * Process the NODE command and return PICL node handle
 */
static int
process_node(command_t *command, picl_nodehdl_t parh, picl_nodehdl_t *nodeh)
{
	int	err;

	err = ptree_create_and_add_node(parh, command->nodecmd_nodename,
	    command->nodecmd_classname, nodeh);

	if (err == PICL_SUCCESS)
		command->nodecmd_nodeh = *nodeh;

	return (err);
}

/*
 * get the PICL property type
 */
static int
getpicltype(char *type)
{
	if (strcasecmp(type, KEYWORD_INT_TYPE) == 0)
		return (PICL_PTYPE_INT);
	else if (strcasecmp(type, KEYWORD_UINT_TYPE) == 0)
		return (PICL_PTYPE_UNSIGNED_INT);
	else if (strcasecmp(type, KEYWORD_FLOAT_TYPE) == 0)
		return (PICL_PTYPE_FLOAT);
	else if (strcasecmp(type, KEYWORD_STRING_TYPE) == 0)
		return (PICL_PTYPE_CHARSTRING);
	else if (strcasecmp(type, KEYWORD_VOID_TYPE) == 0)
		return (PICL_PTYPE_VOID);
	else
		return (-1);
}

/*
 * get the PICL accessmode mode
 */
static int
getpiclmode(char *mode)
{
	if (strcasecmp(mode, KEYWORD_READ_MODE) == 0)
		return (PICL_READ);
	else if (strcasecmp(mode, KEYWORD_WRITE_MODE) == 0)
		return (PICL_WRITE);
	else if (strcasecmp(mode, KEYWORD_READWRITE_MODE) == 0)
		return (PICL_READ|PICL_WRITE);
	else
		return (-1);
}

/*
 * check if the size and value are valid given by the prop type
 */
static int
validate_size_and_cvt_val(void *outbuf, size_t size, int type, char *val)
{
	int64_t		llval;
	int32_t		intval;
	int16_t		sval;
	int8_t		cval;
	uint64_t	ullval;
	uint32_t	uintval;
	uint16_t	usval;
	uint8_t		ucval;
	float		fval;
	double		dval;
	char		*endptr;

	switch (type) {
	case PICL_PTYPE_CHARSTRING:
		break;
	case PICL_PTYPE_INT:
		switch (size) {
		case sizeof (int64_t):
			llval = strtoll(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &llval, size);
			break;
		case sizeof (int32_t):
			intval = strtol(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &intval, size);
			break;
		case sizeof (int16_t):
			sval = (int16_t)strtol(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &sval, size);
			break;
		case sizeof (int8_t):
			cval = (int8_t)strtol(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &cval, size);
			break;
		default:	/* invalid size */
			return (EC_SYNTAX_ERR);
		}
		break;
	case PICL_PTYPE_UNSIGNED_INT:
		switch (size) {
		case sizeof (uint64_t):
			ullval = strtoull(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &ullval, size);
			break;
		case sizeof (uint32_t):
			uintval = strtoul(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &uintval, size);
			break;
		case sizeof (uint16_t):
			usval = (uint16_t)strtoul(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &usval, size);
			break;
		case sizeof (uint8_t):
			ucval = (uint8_t)strtoul(val, &endptr, 0);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &ucval, size);
			break;
		default:	/* invalid size */
			return (EC_SYNTAX_ERR);
		}
		break;
	case PICL_PTYPE_FLOAT:
		switch (size) {
		case sizeof (double):
			dval = strtod(val, &endptr);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &dval, size);
			break;
		case sizeof (float):
			fval = (float)strtod(val, &endptr);
			if (endptr != (val + strlen(val)))
				return (EC_SYNTAX_ERR);
			(void) memcpy(outbuf, &fval, size);
			break;
		default:	/* invalid size */
			return (EC_SYNTAX_ERR);
		}
		break;
	default:	/* not supported type */
		return (EC_SYNTAX_ERR);
	}

	return (EC_SYNTAX_OK);
}

/*
 * free prop_cmd_t
 */
static void
free_prop(command_t *command)
{
	free(command->propcmd_pname);
	if (command->propcmd_type != PICL_PTYPE_VOID)
		free(command->propcmd_valbuf);
}

/*
 * return the string token in two double quotes
 * The current version won't support multiple-line string
 */
static int
get_string_token(char *line, char **valtok)
{
	char	*optr;	/* ptr to the open quote */
	char	*cptr;	/* ptr to the close quote */
	char	*ptr;
	char	*tmpbuf;

	if (line == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* skipping leading white spaces */
	optr = line;
	while ((*optr == ' ') || (*optr == '\t') || (*optr == '\n'))
		optr++;

	/* reach end of string */
	if (*optr == '\0')
		return (EC_INSUFFICIENT_TOKEN);

	/* it's not an open double quote */
	if (*optr != '"')
		return (EC_SYNTAX_ERR);

	/* skipping ending white spaces */
	cptr = line + strlen(line) - 1;
	while ((*cptr == ' ') || (*cptr == '\t') || (*cptr == '\n'))
		cptr--;

	/* it's not an close double quote */
	if (*cptr != '"')
		return (EC_SYNTAX_ERR);

	/* close double quote is missing */
	if (cptr == optr)
		return (EC_SYNTAX_ERR);

	/* replace close qoute by null to make a string */
	*cptr = '\0';
	/* move the begin pointer to the first char of string */
	optr++;

	tmpbuf = malloc(strlen(optr) + 1);
	if (tmpbuf == NULL)
		return (EC_FAILURE);

	for (ptr = tmpbuf; *optr != '\0'; ptr++, optr++) {
		/* if escape character, go to next character */
		if (*optr == '\\') {
			optr++;
			if (*optr == '\0') {	/* for exampe, "xxx\" */
				free(tmpbuf);
				return (EC_SYNTAX_ERR);
			}
		}
		*ptr = *optr;
	}

	*ptr = '\0';
	*valtok = tmpbuf;
	return (EC_SYNTAX_OK);
}

/*
 * Check the PROP syntax
 * PROP <name> <type> <access_mode> [<size> <value>]
 * supported prop types: void, int, uint, float, string
 * supported prop access_modes: r, w, rw
 * For void prop, <size> and <value> are not needed
 * For string prop, <size> will be set the actual string size if <size>
 * is 0
 */
static int
parse_prop(char *line, command_t *command)
{
	char	*tok;
	char	*pnametok;
	int	typetok;
	size_t	sizetok;
	int	modetok;
	char	*valtok;
	char	*last;
	char	*endptr;
	int	err;

	/* get the PROP directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the property name */
	pnametok = strtok_r(last, WHITESPACE, &last);
	if (pnametok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the type */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	if ((typetok = getpicltype(tok)) < 0)
		return (EC_SYNTAX_ERR);

	/* get mode */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	if ((modetok = getpiclmode(tok)) < 0)
		return (EC_SYNTAX_ERR);

	if (typetok == PICL_PTYPE_VOID) {
		/* ignore the rest of arguments */
		command->propcmd_valbuf = NULL;
		command->propcmd_pname = strdup(pnametok);
		if (command->propcmd_pname == NULL)
			return (EC_FAILURE);
		command->propcmd_type = typetok;
		command->propcmd_accessmode = modetok;
		command->propcmd_size = 0;
		command->propcmd_proph = 0;
		return (EC_SYNTAX_OK);
	}

	/* get size */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	sizetok = (size_t)strtol(tok, &endptr, 0);
	if (endptr != (tok + strlen(tok)))
		return (EC_SYNTAX_ERR);

	/* get val */
	if (typetok == PICL_PTYPE_CHARSTRING) {
		err = get_string_token(last, &valtok);
		if (err != EC_SYNTAX_OK)
			return (err);
		if (sizetok == 0)
			sizetok = strlen(valtok) + 1;
		command->propcmd_valbuf = valtok;
	} else {
		valtok = strtok_r(last, WHITESPACE, &last);
		if (valtok == NULL)
			return (EC_INSUFFICIENT_TOKEN);
		/* check if more tokens */
		tok = strtok_r(last, WHITESPACE, &last);
		if (tok != NULL)
			return (EC_SYNTAX_ERR);
		command->propcmd_valbuf = malloc(sizetok);
		if (command->propcmd_valbuf == NULL)
			return (EC_FAILURE);
		err = validate_size_and_cvt_val(command->propcmd_valbuf,
		    sizetok, typetok, valtok);
		if (err != EC_SYNTAX_OK) {
			free(command->propcmd_valbuf);
			return (err);
		}
	}

	command->propcmd_pname = strdup(pnametok);
	if (command->propcmd_pname == NULL)
		return (EC_FAILURE);
	command->propcmd_type = typetok;
	command->propcmd_accessmode = modetok;
	command->propcmd_size = sizetok;
	command->propcmd_proph = 0;
	return (EC_SYNTAX_OK);
}

/*
 * Add a property to the row, the row gets added to the node at endrow
 */
static int
add_proph_to_row(command_t *command, picl_prophdl_t proph)
{
	if (command->rowcmd_index >= command->rowcmd_nproph)
		return (PICL_FAILURE);
	command->rowcmd_prophs[command->rowcmd_index] = proph;
	command->rowcmd_index++;
	return (PICL_SUCCESS);
}

/*
 * Process the PROP command and add the specified property under the given
 * node handle
 */
static int
process_prop(cmdbuf_t *cmds, command_t *command, picl_nodehdl_t nodeh)
{
	ptree_propinfo_t	propinfo;
	picl_prophdl_t		proph;
	int			err;

	/* prop in discarded row */
	if (cmds->inside_row_block &&
	    cmds->commands[cmds->current_row].rowcmd_nproph == 0)
		return (PICL_SUCCESS);

	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    command->propcmd_type, command->propcmd_accessmode,
	    command->propcmd_size, command->propcmd_pname, NULL,
	    NULL);

	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_prop(&propinfo, command->propcmd_valbuf, &proph);

	if (err != PICL_SUCCESS)
		return (err);

	command->propcmd_proph = proph;

	if (cmds->inside_row_block) {
		err = add_proph_to_row(&cmds->commands[cmds->current_row],
		    proph);
	} else {
		err = ptree_add_prop(nodeh, proph);
	}

	return (err);
}

/*
 * free refnode_cmd_t
 */
static void
free_refnode(command_t *command)
{
	free(command->refnodecmd_name);
	free(command->refnodecmd_class);
	free(command->refnodecmd_dstnode);
}

/*
 * Check the REFNODE syntax
 *
 * REFNODE <name> <class> with <destnode> -- if <destnode> exists,
 * create node with nodename <name> and piclclass <class>
 */
static int
parse_refnode(char *line, command_t *command)
{
	char	*tok;
	char	*dsttok;
	char	*classnm;
	char	*nodenm;
	char	*last;

	/* get the directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the nodename */
	nodenm = strtok_r(last, WHITESPACE, &last);
	if (nodenm == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the class */
	classnm = strtok_r(last, WHITESPACE, &last);
	if (classnm == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the WITH keyword */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	if (strcasecmp(tok, KEYWORD_WITH_STR) != 0)
		return (EC_SYNTAX_ERR);

	/* get the dst node */
	dsttok = strtok_r(last, WHITESPACE, &last);
	if (dsttok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	command->refnodecmd_name = strdup(nodenm);
	command->refnodecmd_class = strdup(classnm);
	command->refnodecmd_dstnode = strdup(dsttok);
	command->refnodecmd_nodeh = 0;
	if ((command->refnodecmd_name == NULL) ||
	    (command->refnodecmd_class == NULL) ||
	    (command->refnodecmd_dstnode == NULL))
		return (EC_FAILURE);

	return (EC_SYNTAX_OK);
}

/*
 * Process the REFNODE command
 */
static int
process_refnode(command_t *command, picl_nodehdl_t parh)
{
	picl_nodehdl_t	dsth;
	picl_nodehdl_t	nodeh;
	int		err;

	if ((ptree_get_node_by_path(command->refnodecmd_dstnode,
	    &dsth) == PICL_SUCCESS)) {
		err = ptree_create_and_add_node(parh, command->refnodecmd_name,
		    command->refnodecmd_class, &nodeh);
		if (err == PICL_SUCCESS)
			command->refnodecmd_nodeh = nodeh;

		return (err);
	}

	return (PICL_SUCCESS);
}

/*
 * free refprop_cmd_t
 */
static void
free_refprop(command_t *command)
{
	free(command->refpropcmd_pname);
	free(command->refpropcmd_dstnode);
}

/*
 * Check the REFPROP syntax
 *
 * REFPROP <prop> <destnode> -- creates a reference property to <destnode>
 */
static int
parse_refprop(char *line, command_t *command)
{
	char	*tok;
	char	*pnametok;
	char	*dsttok;
	char	*last;

	/* get the REFPROP directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the propname  */
	pnametok = strtok_r(last, WHITESPACE, &last);
	if (pnametok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	dsttok = strtok_r(last, WHITESPACE, &last);
	if (dsttok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	command->refpropcmd_pname = strdup(pnametok);
	command->refpropcmd_dstnode = strdup(dsttok);
	command->refpropcmd_proph = 0;
	if ((command->refpropcmd_pname == NULL) ||
	    (command->refpropcmd_dstnode == NULL))
		return (EC_FAILURE);

	return (EC_SYNTAX_OK);
}

/*
 * Process the REFPROP command
 */
static int
process_refprop(cmdbuf_t *cmds, command_t *command, picl_nodehdl_t nodeh)
{
	int			err;
	picl_nodehdl_t		dsth;
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;

	/* refprop in discarded row */
	if (cmds->inside_row_block &&
	    cmds->commands[cmds->current_row].rowcmd_nproph == 0)
		return (PICL_SUCCESS);

	/* try finding the refprop's dstnode */
	err = ptree_get_node_by_path(command->refpropcmd_dstnode, &dsth);

	/* dstnode doesn't exist, return */
	if (err != PICL_SUCCESS)
		return (err);

	/* dstnode exists, try adding the refprop to nodeh */
	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_REFERENCE, PICL_READ, sizeof (picl_nodehdl_t),
	    command->refpropcmd_pname, NULL, NULL);

	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_prop(&propinfo, &dsth, &proph);

	if (err != PICL_SUCCESS)
		return (err);

	command->refpropcmd_proph = proph;

	if (cmds->inside_row_block) {
		err = add_proph_to_row(&cmds->commands[cmds->current_row],
		    proph);
	} else {
		err = ptree_add_prop(nodeh, proph);
	}

	return (err);
}

/*
 * free table_cmd_t
 */
static void
free_table(command_t *command)
{
	if (command->tablecmd_tname)
		free(command->tablecmd_tname);
}

/*
 * Check the TABLE syntax
 * TABLE <table_prop_name>
 *
 */
static int
parse_table(char *line, command_t *command)
{
	char	*tok = NULL;
	char	*tnametok = NULL;
	char	*last = NULL;

	/* get the TABLE directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get the property name */
	tnametok = strtok_r(last, WHITESPACE, &last);
	if (tnametok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	command->tablecmd_tname = strdup(tnametok);
	if (command->tablecmd_tname == NULL)
		return (EC_FAILURE);

	command->tablecmd_newtbl = 0;
	command->tablecmd_tblh = 0;

	return (EC_SYNTAX_OK);
}

/*
 * Process the TABLE command and add the specified property under the given
 * node handle
 */
static int
process_table(command_t *command, picl_nodehdl_t nodeh)
{
	int			err;
	picl_prophdl_t		tblh;
	picl_prophdl_t		proph;
	ptree_propinfo_t	propinfo;

	/* find if table already exists */
	err = ptree_get_prop_by_name(nodeh, command->tablecmd_tname, &tblh);
	if (err == PICL_SUCCESS) {
		err = ptree_get_propinfo(tblh, &propinfo);
		if (err != PICL_SUCCESS)
			return (err);
		/* prop with the same name as table? */
		if (propinfo.piclinfo.type != PICL_PTYPE_TABLE)
			return (EC_SYNTAX_ERR);
		command->tablecmd_newtbl = 0;
		command->tablecmd_tblh = tblh;
		return (PICL_SUCCESS);
	}

	/* init and create a new table */
	err = ptree_init_propinfo(&propinfo, PTREE_PROPINFO_VERSION,
	    PICL_PTYPE_TABLE, PICL_READ|PICL_WRITE,
	    sizeof (picl_prophdl_t), command->tablecmd_tname, NULL, NULL);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_create_table(&tblh);
	if (err != PICL_SUCCESS)
		return (err);

	command->tablecmd_newtbl = 1;
	command->tablecmd_tblh = tblh;

	err = ptree_create_prop(&propinfo, &tblh, &proph);
	if (err != PICL_SUCCESS)
		return (err);

	err = ptree_add_prop(nodeh, proph);

	return (err);
}

/*
 * Process the ROW command by alloc'ing space to store the prop handles for
 * the whole row. The number of props in the row gets known while parsing.
 */
static int
process_row(command_t *command)
{
	command->rowcmd_index = 0;
	command->rowcmd_prophs =
	    malloc(command->rowcmd_nproph * sizeof (picl_prophdl_t));

	if (command->rowcmd_prophs == NULL)
		return (PICL_FAILURE);

	return (PICL_SUCCESS);
}

/*
 * Process the ENDROW command. If a valid row, add the row to the ptree.
 */
static int
process_endrow(cmdbuf_t *cmds)
{
	int		err;
	int		i;
	command_t	*curr_row;

	curr_row = &cmds->commands[cmds->current_row];

	/* if nproph == 0, some row prop had problems, don't add  */
	if (curr_row->rowcmd_nproph == 0) {
		for (i = 0; i < curr_row->rowcmd_index; i++) {
			(void) ptree_delete_prop(curr_row->rowcmd_prophs[i]);
			(void) ptree_destroy_prop(curr_row->rowcmd_prophs[i]);
		}
		err = PICL_SUCCESS;
	} else
		err = ptree_add_row_to_table(
		    cmds->commands[cmds->current_tbl].tablecmd_tblh,
		    curr_row->rowcmd_nproph,
		    curr_row->rowcmd_prophs);

	/* let go the space alloc'd in process_row */
	free(curr_row->rowcmd_prophs);
	curr_row->rowcmd_prophs = NULL;

	return (err);
}

/*
 * Check the VERBOSE syntax
 * VERBOSE <level>
 */
static int
parse_verbose(cmdbuf_t *cmds, char *line, command_t *command)
{
	char	*tok;
	char	*level;
	char	*last;
	char	*endptr;
	int	verbose_level;

	/* get the VERBOSE directive */
	tok = strtok_r(line, WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	/* get verbose level */
	level = strtok_r(last, WHITESPACE, &last);
	if (level == NULL)
		return (EC_INSUFFICIENT_TOKEN);
	verbose_level = strtol(level, &endptr, 0);
	if (endptr != (level + strlen(level)))
		return (EC_SYNTAX_ERR);

	/* check if more tokens */
	tok = strtok_r(last, WHITESPACE, &last);
	if (tok != NULL)
		return (EC_SYNTAX_ERR);

	cmds->verbose = verbose_level;
	command->verbosecmd_level = verbose_level;

	return (EC_SYNTAX_OK);
}

/*
 * Process the VERBOSE command to set the verbose level
 */
static int
process_verbose(cmdbuf_t *cmds, command_t *command)
{
	cmds->verbose = command->verbosecmd_level;
	return (PICL_SUCCESS);
}

/*
 * parse and tokenize the line
 */
static int
parse_and_tokenize_line(cmdbuf_t *cmds, char *buf, command_t *command)
{
	char		rec[RECORD_SIZE_MAX];
	char		*tok;
	int		err;
	char		*last;
	int		id;

	(void) strcpy(rec, buf);
	tok = strtok_r(rec, RECORD_WHITESPACE, &last);
	if (tok == NULL)
		return (EC_INSUFFICIENT_TOKEN);

	id = get_token_id(tok);

	(void) strcpy(rec, buf);

	switch (id) {
	case TOK_VERSION:
		err = parse_version(cmds, rec);
		break;
	case TOK_CLASSPATH:
	case TOK_NAMEPATH:
		if (cmds->inside_node_block != 0)
			return (EC_PATH_ERR);

		err = parse_path(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		break;
	case TOK_NODE:
		/* Check for NODE outside of TABLE, ROW */
		if ((cmds->inside_table_block != 0) ||
		    (cmds->inside_row_block != 0))
			return (EC_SYNTAX_ERR);
		err = parse_node(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		cmds->inside_node_block++;
		break;
	case TOK_ENDNODE:
		/* Check for ENDNODE outside of TABLE, ROW */
		if ((cmds->inside_table_block != 0) ||
		    (cmds->inside_row_block != 0))
			return (EC_SYNTAX_ERR);
		cmds->inside_node_block--;
		err = EC_SYNTAX_OK;
		break;
	case TOK_PROP:
		/* Check if inside TABLE, but not in ROW */
		if ((cmds->inside_table_block != 0) &&
		    (cmds->inside_row_block == 0))
			return (EC_SYNTAX_ERR);
		err = parse_prop(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		if (cmds->inside_row_block) {
			cmds->commands[cmds->current_row].rowcmd_nproph++;
		}
		break;
	case TOK_REFNODE:
		err = parse_refnode(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		break;
	case TOK_REFPROP:
		/* Check if inside TABLE, but not in ROW */
		if ((cmds->inside_table_block != 0) &&
		    (cmds->inside_row_block == 0))
			return (EC_SYNTAX_ERR);
		err = parse_refprop(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		if (cmds->inside_row_block) {
			cmds->commands[cmds->current_row].rowcmd_nproph++;
		}
		break;
	case TOK_TABLE:
		/* Table/Row supported in version 1.1 and above */
		if (cmds->version_no < (float)SUPPORTED_VERSION_NUM)
			return (EC_UNSUPPORTED);
		if (cmds->inside_table_block != 0)
			return (EC_SYNTAX_ERR);
		err = parse_table(rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		cmds->inside_table_block = 1;
		break;
	case TOK_ENDTABLE:
		/* Check for ENDTABLE before TABLE */
		if (cmds->inside_table_block == 0)
			return (EC_SYNTAX_ERR);

		cmds->inside_table_block = 0;

		break;
	case TOK_ROW:
		/* Check for ROW outside of TABLE, ROW inside ROW */
		if ((cmds->inside_table_block == 0) ||
		    (cmds->inside_row_block != 0))
			return (EC_SYNTAX_ERR);
		cmds->inside_row_block = 1;
		break;
	case TOK_ENDROW:
		/* Check for ENDROW outside of TABLE, ENDROW before ROW */
		if ((cmds->inside_table_block == 0) ||
		    (cmds->inside_row_block == 0))
			return (EC_SYNTAX_ERR);
		else
			err = EC_SYNTAX_OK;

		cmds->inside_row_block = 0;

		/* error if row is empty */
		if (cmds->commands[cmds->current_row].rowcmd_nproph <= 0)
			return (EC_ROW_EMPTY);
		break;
	case TOK_VERBOSE:
		err = parse_verbose(cmds, rec, command);
		if (err != EC_SYNTAX_OK)
			return (err);
		break;
	default:	/* unsupported command */
		return (EC_SYNTAX_ERR);
	}

	command->type = id;
	return (EC_SYNTAX_OK);
}

/*
 * Check the syntax and save the tokens in the commands buffer
 */
static int
check_line_syntax(cmdbuf_t *cmds, char *buf)
{
	int		err;
	command_t	command;

	(void) memset(&command, 0, sizeof (command_t));
	err = parse_and_tokenize_line(cmds, buf, &command);
	if (err != EC_SYNTAX_OK)
		return (err);

	/*
	 * don't add and count version command in the command buffer
	 */
	if (command.type == TOK_VERSION)
		return (EC_SYNTAX_OK);

	/*
	 * check if the commands buffer has been filled
	 * If it is full, reallocate the buffer.
	 */
	if (cmds->count == cmds->allocated) {
		cmds->commands = realloc(cmds->commands,
		    sizeof (command_t) * (cmds->allocated + PER_ALLOC_COUNT));
		if (cmds->commands == NULL)
			return (EC_FAILURE);
		cmds->allocated += PER_ALLOC_COUNT;
	}

	cmds->commands[cmds->count] = command;	/* copy */

	/*
	 * make a note of the row/endrow command, to keep track of # of props
	 */
	if (command.type == TOK_ROW)
		cmds->current_row = cmds->count;

	if (command.type == TOK_ENDROW)
		cmds->current_row = 0;

	cmds->count++;

	return (EC_SYNTAX_OK);
}

/*
 * get the line control information
 * return 1 if it's the line control information, else return 0
 */
static int
get_line_control_info(char *buf, uint32_t *linenum, char *filename)
{
	char		*ptr;
	char		*last;
	uint32_t	num;
	char		*fname;
	char		*endptr;

	/* skip # and get next string */
	ptr = strtok_r(buf + 1, WHITESPACE, &last);
	if (ptr == NULL) {
		return (0);
	}

	num = strtoul(ptr, &endptr, 0);

	/*
	 * It's not the line control information
	 */
	if (endptr != (ptr + strlen(ptr))) {
		return (0);
	}

	/*
	 * get the filename
	 */

	/* get the beginning double quote */
	last = strchr(last, '"');
	if (last == NULL)
		return (0);

	last++;

	/* get the ending double quote */
	fname = strtok_r(last, DOUBLE_QUOTE, &last);
	if (fname == NULL)
		return (0);

	*linenum = num;
	(void) strlcpy(filename, fname, PATH_MAX);
	return (1);
}

/*
 * check the syntax of the configuration file
 */
static int
check_conffile_syntax(cmdbuf_t *cmds, FILE *fp)
{
	char		lbuf[RECORD_SIZE_MAX];
	char		buf[RECORD_SIZE_MAX];
	uint32_t	linenum;
	char		cppfile[PATH_MAX] = "";
	int		err = EC_SYNTAX_OK;

	linenum = 0;
	while (fgets(buf, sizeof (buf), fp) != NULL) {
		/*
		 * get cpp line control information, if any
		 */
		if (buf[0] == '#') {
			if (!get_line_control_info(buf, &linenum, cppfile))
				++linenum;
			continue;
		}

		++linenum;
		/*
		 * skip line whose first char is a newline char
		 */
		if (buf[0] == '\n') {
			continue;
		}

		if (err == EC_SYNTAX_OK)
			(void) strlcpy(lbuf, buf, RECORD_SIZE_MAX);
		else if (strlcat(lbuf, buf, RECORD_SIZE_MAX) >=
		    RECORD_SIZE_MAX) {	/* buffer overflow */
			err = EC_FAILURE;
			break;
		}

		err = check_line_syntax(cmds, lbuf);
		if ((err != EC_INSUFFICIENT_TOKEN) && (err != EC_SYNTAX_OK))
			break;
	}

	if (err != EC_SYNTAX_OK) {
		if (cmds->verbose) {
			verbose_log(LOG_ERR, err_msg[err],
			    cmds->fname, cppfile, linenum);
		}
		return (err);
	}

	/*
	 * check if the version has been set
	 */
	if (cmds->version_no > (float)SUPPORTED_VERSION_NUM) {
		if (cmds->verbose) {
			verbose_log(LOG_ERR, err_msg[EC_UNSUPPORTED],
			    cmds->fname, cppfile, linenum);
		}
		return (EC_UNSUPPORTED);
	}

	/*
	 * check if node and endnode command mismatch
	 */
	if (cmds->inside_node_block != 0) {
		if (cmds->verbose) {
			verbose_log(LOG_ERR, err_msg[EC_NODE_MISMATCH],
			    cmds->fname, cppfile, linenum);
		}
		return (EC_NODE_MISMATCH);
	}

	/*
	 * check if row and endrow command mismatch
	 */
	if (cmds->inside_row_block != 0) {
		if (cmds->verbose) {
			verbose_log(LOG_ERR, err_msg[EC_ROW_MISMATCH],
			    cmds->fname, cppfile, linenum);
		}
		return (EC_ROW_MISMATCH);
	}

	/*
	 * check if table and endtable command mismatch
	 */
	if (cmds->inside_table_block != 0) {
		if (cmds->verbose) {
			verbose_log(LOG_ERR, err_msg[EC_TABLE_MISMATCH],
			    cmds->fname, cppfile, linenum);
		}
		return (EC_TABLE_MISMATCH);
	}

	return (EC_SYNTAX_OK);
}

/*
 * If classpath/namepath given is not found in the picl tree,
 * skip the whole blocks until next valid classpath or namepath
 */
static void
skip_to_next_valid_path(cmdbuf_t *cmds, int starting_index,
    picl_nodehdl_t *parent, int *last_processed_index)
{
	int	err;
	int	index;

	for (index = starting_index; index < cmds->count; ++index) {
		switch (cmds->commands[index].type) {
		case TOK_CLASSPATH:
		case TOK_NAMEPATH:
			err = process_path(&cmds->commands[index], parent);
			if (err == PICL_SUCCESS) {
				*last_processed_index = index;
				return;
			}
		default:
			/* skipped this line */
			break;
		}
	}

	/* reach last command  */
	*last_processed_index = cmds->count - 1;
}

/*
 * Process the command buffer and return last command index and the new head of
 * the handle list
 */
static int
process_commands(cmdbuf_t *cmds, int starting_index, picl_nodehdl_t parent,
    int *last_processed_index)
{
	int		err;
	int		index;
	picl_nodehdl_t	rooth;
	picl_nodehdl_t	nodeh;
	command_t	*commands = cmds->commands;

	for (index = starting_index; index < cmds->count; ++index) {
		switch (commands[index].type) {
		case TOK_CLASSPATH:
		case TOK_NAMEPATH:
			err = process_path(&commands[index], &rooth);
			if (err != PICL_SUCCESS) {
				index++;
				(void) skip_to_next_valid_path(cmds, index,
				    &rooth, &index);
			}
			parent = rooth;
			continue;
		case TOK_NODE:
			err = process_node(&commands[index], parent, &nodeh);
			if (err == PICL_SUCCESS) {
				index++;
				err = process_commands(cmds, index, nodeh,
				    &index);
			}
			break;
		case TOK_ENDNODE:
			*last_processed_index = index;
			return (PICL_SUCCESS);
		case TOK_PROP:
			err =  process_prop(cmds, &commands[index], parent);
			break;
		case TOK_REFPROP:
			err = process_refprop(cmds, &commands[index], parent);
			/* no reference node */
			if (err == PICL_NOTNODE) {
				err = PICL_SUCCESS;	/* discard prop */
				/* discard row by setting nproph = 0 */
				if (cmds->inside_row_block)
					cmds->commands[cmds->current_row]
					    .rowcmd_nproph = 0;
			}
			break;
		case TOK_REFNODE:
			err =  process_refnode(&commands[index], parent);
			break;
		case TOK_TABLE:
			cmds->inside_table_block = 1;
			err = process_table(&commands[index], parent);
			cmds->current_tbl = index;
			break;
		case TOK_ENDTABLE:
			cmds->inside_table_block = 0;
			cmds->current_tbl = 0;
			break;
		case TOK_ROW:
			cmds->inside_row_block = 1;
			err = process_row(&commands[index]);
			cmds->current_row = index;
			break;
		case TOK_ENDROW:
			err = process_endrow(cmds);
			cmds->inside_row_block = 0;
			cmds->current_row = 0;
			break;
		case TOK_VERBOSE:
			err = process_verbose(cmds, &commands[index]);
			break;
		default:	/* won't reach here */
			err =  PICL_FAILURE;
			break;
		}

		if ((err != PICL_SUCCESS) && (err != PICL_PROPEXISTS)) {
			*last_processed_index = index;
			return (err);
		}
	}

	/* reach last command */
	*last_processed_index = cmds->count - 1;
	return (PICL_SUCCESS);
}

/*
 * clean up the commands buffer
 */
static void
clean_up(cmdbuf_t *cmds)
{
	int	cmd_index;

	for (cmd_index = 0; cmd_index < cmds->count; cmd_index++) {
		switch (cmds->commands[cmd_index].type) {
		case TOK_CLASSPATH:
		case TOK_NAMEPATH:
			free_path(&cmds->commands[cmd_index]);
			break;
		case TOK_NODE:
			free_node(&cmds->commands[cmd_index]);
			break;
		case TOK_PROP:
			free_prop(&cmds->commands[cmd_index]);
			break;
		case TOK_REFPROP:
			free_refprop(&cmds->commands[cmd_index]);
			break;
		case TOK_REFNODE:
			free_refnode(&cmds->commands[cmd_index]);
			break;
		case TOK_TABLE:
			free_table(&cmds->commands[cmd_index]);
			break;
		case TOK_ENDTABLE:
		case TOK_ROW:
		case TOK_ENDROW:
		case TOK_ENDNODE:
		case TOK_VERBOSE:
		default:
			break;
		}
	}
	if (cmds->commands)
		free(cmds->commands);
}

/*
 * Parse the configuration file and create nodes/properties under nh
 *
 * It checks the syntax first.  If there is any syntax error,
 * it returns 1 and won't continue processing the file to add nodes or props.
 *
 * If any error happens during command processing, all nodes
 * and properties just created will be deleted, i.e. undo
 * commands which have been processed.  It returns 1.
 *
 * If success, return 0.
 */
int
picld_pluginutil_parse_config_file(picl_nodehdl_t nh, const char *filename)
{
	FILE		*ifp;
	int		last_processed_index;
	int		err;
	cmdbuf_t	*cmds;

	/* set correct locale for use inside pluginutil */
	setlocale(LC_ALL, "C");

	/*
	 * Initialize the command buffer
	 */

	cmds = malloc(sizeof (*cmds));
	if (cmds == NULL) {
		setlocale(LC_ALL, "");
		return (1);
	}

	memset(cmds, 0, sizeof (cmdbuf_t));

	cmds->fname = filename;

	ifp = fopen(filename, "r");
	if (ifp == NULL) {
		setlocale(LC_ALL, "");
		free(cmds);
		return (1);
	}

	/*
	 * check the syntax of the configuration file
	 */
	err = check_conffile_syntax(cmds, ifp);

	(void) fclose(ifp);

	if (err != EC_SYNTAX_OK) {
		clean_up(cmds);
		free(cmds);
		setlocale(LC_ALL, "");
		return (1);
	}

	/*
	 * Process the commands
	 */
	err = process_commands(cmds, STARTING_INDEX, nh, &last_processed_index);

	/*
	 * If any PICL error, remove the newly created node/prop
	 * handles from the PICL tree.
	 */
	if (err != PICL_SUCCESS) {
		undo_commands(cmds, last_processed_index);
		if (cmds->verbose)
			verbose_log(LOG_ERR, err_msg[EC_PICL_ERR], filename,
			    err);
	}

	clean_up(cmds);
	free(cmds);

	/* reset the locale */
	setlocale(LC_ALL, "");

	return ((err == PICL_SUCCESS) ? 0 : 1);
}
