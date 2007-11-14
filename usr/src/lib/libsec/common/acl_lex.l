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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

%{
#include <sys/acl.h>
#include <aclutils.h>
#include <errno.h>
#include "acl.tab.h"

#ifdef input
#undef input
#endif

#ifdef unput
#undef unput
#endif

int grab_string(char *terminators);
static int input();
static void unput(int);

int 
yyerror(const char *s)
{
	return (0);
}

int
yywrap(void)
{
	return (1);
}

extern char *yybuf;
int yybufpos;

/*
 * Used for tracking allocated strings while walking through an ACL.
 */
struct yystrings {
	char *y_logname;	/* user/group name from LOGNAME */
	char *y_perms;		/* permssions from PERM_TOK */
	char *y_iflags;		/* iflags from INHERIT_TOK */
} yystrings;

%}

%e 1500
%s TS NS PS AIS AS US ES
/*
 * TS = type state
 * NS = name state
 * PS = Permission state
 * AIS = Allow/deny/inheritance state
 * AS = Allow state (only used when inheritance detected)
 * US = UID/GID state
 * ES = End state
 */

ID	[0-9]+
LOGNAME [^:]+:
PERM_STR [rRwWxpdDaAcCos-]+
INHERIT_STR [fdinFSI-]+

%%

<TS>user:		{
				BEGIN NS;
				yylval.val = USER_TOK;
				return (ENTRY_TYPE);
			}
<TS>owner@:		{
				BEGIN PS;
				yylval.val = OWNERAT_TOK;
				return (ENTRY_TYPE);
			}
<TS>group@:		{
				BEGIN PS;
				yylval.val = GROUPAT_TOK;
				return (ENTRY_TYPE);
			}
<TS>everyone@:		{
				BEGIN PS;
				yylval.val = EVERYONEAT_TOK;
				return (ENTRY_TYPE);
			}
<TS>group:		{
				BEGIN NS;
				yylval.val = GROUP_TOK;
				return (ENTRY_TYPE);
			}
<TS>mask:		{
				BEGIN PS;
				yylval.val = MASK_TOK;
				return (ENTRY_TYPE);
			}
<TS>mask::		{
				BEGIN PS;
				yylval.val = MASK_TOK;
				return (ENTRY_TYPE);
			}
<TS>other:		{
				BEGIN PS;
				yylval.val = OTHER_TOK;
				return (ENTRY_TYPE);
			}
<TS>other::		{
				BEGIN PS;
				yylval.val = OTHER_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultuser: 	{
				BEGIN NS;
				yylval.val = DEFAULT_USER_TOK;
				return (ENTRY_TYPE);
			}
<TS>default:user:	{
				BEGIN NS;
				yylval.val = DEFAULT_USER_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultgroup: 	{
				BEGIN NS;
				yylval.val = DEFAULT_GROUP_TOK;
				return (ENTRY_TYPE);
			}
<TS>default:group:	{
				BEGIN NS;
				yylval.val = DEFAULT_GROUP_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultother: 	{
				BEGIN PS;
				yylval.val = DEFAULT_OTHER_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultother:: 	{
				BEGIN PS;
				yylval.val = DEFAULT_OTHER_TOK;
				return (ENTRY_TYPE);
			}
<TS>default:other:	{
				BEGIN PS;
				yylval.val = DEFAULT_OTHER_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultmask: 	{
				BEGIN PS;
				yylval.val = DEFAULT_MASK_TOK;
				return (ENTRY_TYPE);
			}
<TS>defaultmask:: 	{
				BEGIN PS;
				yylval.val = DEFAULT_MASK_TOK;
				return (ENTRY_TYPE);
			}
<TS>default:mask:		{
				BEGIN PS;
				yylval.val = DEFAULT_MASK_TOK;
				return (ENTRY_TYPE);
			}
<TS>"\n"		{
				return (NL);
			}
<TS>.			{
				if (grab_string(":,\n") != 0) {
					acl_error(dgettext(TEXT_DOMAIN,
					    "Failed to retrieve"
					    " error string.\n"));
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				acl_error(dgettext(TEXT_DOMAIN,
				    "Invalid ACL entry "
				    "type '%s' specified.\n"), yylval.str);
				free(yylval.str);
				yylval.val = EACL_ENTRY_ERROR;
				return (ERROR);
			}
<NS>:			{
				BEGIN PS;
				return (COLON);
			}
<NS>{LOGNAME}		{
				yylval.str = strdup(yytext);
				if (yylval.str == NULL) {
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				yylval.str[strlen(yylval.str) -1] = '\0';
				yystrings.y_logname = yylval.str;
				BEGIN PS;
				return (IDNAME);
			}
<NS>"\n"		{
				acl_error(dgettext(TEXT_DOMAIN,
				    "Missing user/group name"
				    " from ACL specification.\n"));
				yylval.val = EACL_MISSING_FIELDS;
				return (ERROR);
			}
<NS>.			{
				int error;
				
				error = grab_string(":,\n");
				if (error != 0) {
					acl_error(dgettext(TEXT_DOMAIN,
					    "Invalid user/group "
					    "name specification.\n"));
					yylval.val = EACL_INVALID_USER_GROUP;
				} else {
					acl_error(dgettext(TEXT_DOMAIN,
					    "User/Group name "
					    "'%s' not specified correctly.\n"),
					    yylval.str);
					free(yylval.str);
					yylval.val = EACL_ENTRY_ERROR;
				}
				return (ERROR);
			}
<PS>read_data/[:/,]	{
				yylval.val = ACE_READ_DATA;
				return (ACE_PERM);
			}
<PS>list_directory/[:/,] {
				yylval.val = ACE_LIST_DIRECTORY;
			 	return (ACE_PERM);
			}
<PS>write_data/[:/,]	{
				yylval.val = ACE_WRITE_DATA;
				return (ACE_PERM);
			}
<PS>add_file/[:/,]	{
				yylval.val = ACE_ADD_FILE;
				return (ACE_PERM);
			}
<PS>append_data/[:/,]	{
				yylval.val = ACE_APPEND_DATA;
				return (ACE_PERM);
			}
<PS>add_subdirectory/[:/,] {
				yylval.val = ACE_ADD_SUBDIRECTORY;
				return (ACE_PERM);
			}
<PS>read_xattr/[:/,]	{
				yylval.val = ACE_READ_NAMED_ATTRS;
				return (ACE_PERM);
			}
<PS>write_xattr/[:/,]	{
				yylval.val = ACE_WRITE_NAMED_ATTRS;
				return (ACE_PERM);
			}
<PS>execute/[:/,]	{
				yylval.val = ACE_EXECUTE;
				return (ACE_PERM);
			}
<PS>delete_child/[:/,]	{
				yylval.val = ACE_DELETE_CHILD;
				return (ACE_PERM);
			}
<PS>read_attributes/[:/,] {
				yylval.val = ACE_READ_ATTRIBUTES;
				return (ACE_PERM);
			}
<PS>write_attributes/[:/,] {
				yylval.val = ACE_WRITE_ATTRIBUTES;
			 	return (ACE_PERM);
			}
<PS>delete/[:/,]		{
				yylval.val = ACE_DELETE;
				return (ACE_PERM);
			}
<PS>read_acl/[:/,]	{
				yylval.val = ACE_READ_ACL;
				return (ACE_PERM);
			}
<PS>write_acl/[:/,]	{
				yylval.val = ACE_WRITE_ACL;
				return (ACE_PERM);
			}
<PS>write_owner/[:/,]	{
				yylval.val = ACE_WRITE_OWNER;
				return (ACE_PERM);
			}
<PS>synchronize/[:/,]	{
				yylval.val = ACE_SYNCHRONIZE;
				return (ACE_PERM);
			}
<PS>{PERM_STR}/[:,\n]	{
				int c;

				c = input();
				unput(c);
				yylval.str = strdup(yytext);
				if (yylval.str == NULL) {
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				yystrings.y_perms = yylval.str;

				/*
				 * aclent are done after permissions.
				 */
				if (isdigit(c))
					BEGIN US;
				else if (c != ':')
					BEGIN ES;
				
				return (PERM_TOK);	
			}
<PS>"/:"		{
				acl_error(dgettext(TEXT_DOMAIN,
				    "Invalid permission /: specified.\n"));
				yylval.val = EACL_ENTRY_ERROR;
				return (ERROR);
			}
<PS>:			{
				int c;

				c = input();
				unput(c);
				if (isdigit(c))
					BEGIN (US);
				else
					BEGIN AIS;
				return (COLON);
			}
<PS>"/"			{
				return (SLASH);
			}
<PS>"\n"		{
				acl_error(dgettext(TEXT_DOMAIN,
				    "ACL entry is missing "
				    "permission fields.\n"));
				yylval.val = EACL_MISSING_FIELDS;
				return (ERROR);
			}
<PS>","			{
				acl_error(
				    dgettext(TEXT_DOMAIN,
				    "The ',' is not a valid permission field "
				    "separator.\nThe comma is used to separate "
				    "access control entries.\nSee acl(5) for "
				    "examples of specifying ACL entries.\n"));
				yylval.val = EACL_PERM_MASK_ERROR;
				return (ERROR);
			}
<PS>. 			{
				if (grab_string("/:,\n") != 0) {
					acl_error(dgettext(TEXT_DOMAIN,
					    "Failed to retrieve"
					    " error string.\n"));
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				acl_error(dgettext(TEXT_DOMAIN,
				    "Invalid permission(s) '%s' "
				    "specified.\n"), yylval.str); 
				free(yylval.str);
				yylval.val = EACL_PERM_MASK_ERROR;
				return (ERROR);
			}
<AS>allow/[:,\n]	{

				int c;
			
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;
				yylval.val = ACE_ACCESS_ALLOWED_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AS>deny/[:,\n]		{

				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_ACCESS_DENIED_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AS>audit/[:,\n]	{
				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_SYSTEM_AUDIT_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AS>alarm/[:,\n]	{
				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_SYSTEM_ALARM_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AS>:			{
				
				acl_error(dgettext(TEXT_DOMAIN,
				    "Invalid Access type "
				    "specified.\nThe field is blank, when"
				    " it should be either allow or deny.\n"));
				yylval.val = EACL_INVALID_ACCESS_TYPE;
				return (ERROR);
			}
<AS>"\n"		{
				acl_error(dgettext(TEXT_DOMAIN,
				    "ACL access type must be specified.\n"));
				yylval.val = EACL_INVALID_ACCESS_TYPE;
				return (ERROR);
			}
<AS>.			{
				if (yytext[0] != '\n' && yytext[0] != '\0') {
					if (grab_string(":,\n") != 0) {
						acl_error(dgettext(TEXT_DOMAIN,
						    "Failed to "
						    "retrieve error "
						    "string.\n"));
						yylval.val = EACL_MEM_ERROR;
						return (ERROR);
					}
					acl_error(
					    dgettext(TEXT_DOMAIN,
					    "Invalid access "
					    "type '%s' specified.\n"),
					    yylval.str);
				} else {
					acl_error(
					    dgettext(TEXT_DOMAIN,
					    "No access "
					    "type specified.\n"), yylval.str);
				}

				free(yylval.str);
				yylval.val = EACL_INVALID_ACCESS_TYPE;
				return (ERROR);
			}
<AIS>allow/[:,\n]	{

				int c;
			
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;
				yylval.val = ACE_ACCESS_ALLOWED_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AIS>deny/[:,\n]	{

				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_ACCESS_DENIED_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AIS>audit/[:,\n]	{
				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_SYSTEM_AUDIT_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AIS>alarm/[:,\n]	{

				int c;
				
				c = input();
				unput(c);
				if (c == ',' || c == '\n')
					BEGIN ES;
				else
					BEGIN US;

				yylval.val = ACE_SYSTEM_ALARM_ACE_TYPE;
				return (ACCESS_TYPE);
			}
<AIS>file_inherit/[:/,] {
				yylval.val = ACE_FILE_INHERIT_ACE;
				return (ACE_INHERIT);
			}
<AIS>dir_inherit/[:/,]	{
				yylval.val = ACE_DIRECTORY_INHERIT_ACE;
				return (ACE_INHERIT);
			}
<AIS>no_propagate/[/:,]	{
				yylval.val = ACE_NO_PROPAGATE_INHERIT_ACE;
				return (ACE_INHERIT);
			}
<AIS>inherit_only/[/:,]	{
				yylval.val = ACE_INHERIT_ONLY_ACE;
				return (ACE_INHERIT);
			}

<AIS>successful_access/[/:,] {
				yylval.val = ACE_SUCCESSFUL_ACCESS_ACE_FLAG;
				return (ACE_INHERIT);
			}
<AIS>failed_access/[/:,] {
				yylval.val = ACE_FAILED_ACCESS_ACE_FLAG;
				return (ACE_INHERIT);
			}
<AIS>inherited/[/:,] {
				yylval.val = ACE_INHERITED_ACE;
				return (ACE_INHERIT);
			}
<AIS>{INHERIT_STR}/[:]	{
				yylval.str = strdup(yytext);
				if (yylval.str == NULL) {
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				yystrings.y_iflags = yylval.str;
				return (INHERIT_TOK);
			}
<AIS>:			{
				/*
				 * Only inheritance fields should hit this.
				 * allow/deny fields match on ":" as part
				 * of the regexp.
				 */
				BEGIN AS;
				return (COLON);
			}
<AIS>"/"		{
				return (SLASH);
			}
<AIS>"\n"		{
				acl_error(
				    dgettext(TEXT_DOMAIN,
				    "Invalid ACL specification."
				    "\nWas expecting to find"
				    " access type or inheritance flags.\n"),
				    yylval.str);
				yylval.val = EACL_UNKNOWN_DATA;
				return (ERROR);
			}
<AIS>","		{
				acl_error(
				    dgettext(TEXT_DOMAIN,
				    "The ',' is not a valid inheritance field "
				    "separator.\nThe comma is used to separate "
				    "access control entries.\nSee acl(5) for "
				    "examples of specifying ACL entries.\n"));
				yylval.val = EACL_INVALID_ACCESS_TYPE;
				return (ERROR);
			}
<AIS>.			{
				if (yytext[0] != '\n' && yytext[0] != '\0') {
					if (grab_string(":,\n") != 0) {
						acl_error(dgettext(TEXT_DOMAIN,
						    "Failed to "
						    "retrieve error "
						    "string.\n"));
						yylval.val = EACL_MEM_ERROR;
						return (ERROR);
					}
					acl_error(
					    dgettext(TEXT_DOMAIN,
					    "Invalid inheritance or"
				    	    " access type '%s' specified.\n"),
				    	    yylval.str);
				} else {
					acl_error(
					    dgettext(TEXT_DOMAIN,
					    "No inheritance or "
					    "access type specified.\n"),
					    yylval.str);
				}

				free(yylval.str);
				yylval.val = EACL_INVALID_ACCESS_TYPE;
				return (ERROR);
			}
<US>{ID}/[,\n]		{
				BEGIN ES;
				yylval.val = atoi(yytext);
				return (ID);
			}
<US>:			{
				return (COLON);
			}
<US>{INHERIT_STR}	{	/*
				 * Catch specific error to produce
				 * nice message for users who are trying
				 * to use old syntax format which had
				 * inheritance flags as the last field.
				 */
				acl_error(dgettext(TEXT_DOMAIN,
				    "Access type should be final"
				    " field in ACL specification.\n"));
				yylval.val = EACL_ENTRY_ERROR;
				return (ERROR);
			}
<US>.			{ 
				if (grab_string(",\n") != 0) {
					acl_error(dgettext(TEXT_DOMAIN,
					    "Failed to retrieve"
					    " error string.\n"));	
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				acl_error(
				    dgettext(TEXT_DOMAIN,
				    "Invalid data ':%s' specified"	
				    " on end of ACL.\n"), yylval.str);
				free(yylval.str);
				yylval.val = EACL_ENTRY_ERROR;
				return (ERROR);
			}
<US>"\n"		{
				acl_error(dgettext(TEXT_DOMAIN,
				    "Missing fields in ACL "
				    "specification.\nWas expecting to find "
				    "uid/gid.\n"));
				yylval.val = EACL_ENTRY_ERROR;
				return (ERROR);
			}
<ES>","			{
				BEGIN TS;
				return (COMMA);
			}
<ES>.			{
				if (grab_string("/:,\n") != 0) {
					acl_error(
					    dgettext(TEXT_DOMAIN,
					    "Failed to retrieve error"
				    	    " string.\n"));
					yylval.val = EACL_MEM_ERROR;
					return (ERROR);
				}
				acl_error(
				    dgettext(TEXT_DOMAIN,
				    "Unrecognized data '%s' found"
			    	    " in ACL specification.\n"), yylval.str);
				free(yylval.str);
				yylval.val = EACL_UNKNOWN_DATA;
				return (ERROR);
			}
<ES>"\n"		{
				return (NL);
			}
%%


/*
 * Pull string up to terminator off of input string.
 * used for retrieving illegal data in ACL specification.
 *
 * The first set of characters is retrieved from yytext.
 * subsequent characters are pulled from the input stream,
 * until either EOF or one of the requested terminators is scene.
 * Result is returned in yylval.str which is malloced.
 */
int
grab_string(char *terminators)
{
		int c;
		int done = 0;
		int cnt;
		int alloced;
		int error = 0;
		char *ptr;
			
		cnt = strlen(yytext);
		yylval.str = calloc(cnt + 1, sizeof (char));
		if (yylval.str == NULL) {
			return (1);
		}
		alloced = cnt + 1;
		strcpy(yylval.str, yytext);

		do {
			c = input();
			if (c == EOF) 
				break;

			for (ptr = terminators; *ptr; ptr++) {
				if (c == *ptr) {
					done = 1;
					break;
				}
			}
			
			if (done)
				break;
				
			if (cnt + 1 >= alloced) {
				yylval.str = realloc(yylval.str,
				    alloced + 80);
					alloced += 80;
				if (yylval.str == NULL)
					return (1);

				memset(yylval.str + cnt, 0,
				    alloced - strlen(yylval.str));
			}
			yylval.str[strlen(yylval.str)] = c;
			cnt++;
		} while (!done);

		return (error);
}

static int
input(void)
{
	int c;

	c = yybuf[yybufpos++];
	if (c == '\0') {
		return (EOF);
	}

	return (c);	
}

static void
unput(int c)
{
	if (c == '\0') {
		return;
	}

	if (yybufpos > 0) {
		--yybufpos;
	}
}

/*
 * return ACE entry type
 */
int
ace_entry_type(int type)
{
	int ret = -1;
	switch (type) {
		case USER_TOK:
			ret = 0;
			break;
		case GROUP_TOK:
			ret = ACE_IDENTIFIER_GROUP;
			break;
		case OWNERAT_TOK:
			ret = ACE_OWNER;
			break;
		case GROUPAT_TOK:
			ret = ACE_IDENTIFIER_GROUP | ACE_GROUP;
			break;
		case EVERYONEAT_TOK:
			ret = ACE_EVERYONE;
			break;
	}
	return (ret);
}


/*
 * return aclent entry type
 */
int
aclent_entry_type(int type, int owning, int *ret)
{

	*ret = 0;

	switch (type) {
	case USER_TOK:
		*ret = (owning == 0) ? USER : USER_OBJ;
		break;
	case GROUP_TOK:
		*ret = (owning == 0) ? GROUP : GROUP_OBJ;
		break;
	case OTHER_TOK:
		*ret = OTHER_OBJ;
		break;
	case MASK_TOK:
		*ret = CLASS_OBJ;
		break;
	case DEFAULT_USER_TOK:
		*ret = (owning == 0) ? DEF_USER : DEF_USER_OBJ;
		break;
	case DEFAULT_GROUP_TOK:
		*ret = (owning == 0) ? DEF_GROUP : DEF_GROUP_OBJ;
		break;
	case DEFAULT_MASK_TOK:
		*ret = DEF_CLASS_OBJ;
		break;
	case DEFAULT_OTHER_TOK:
		*ret = DEF_OTHER_OBJ;
		break;
	default:
		return (EACL_ENTRY_ERROR);
	}

	return (0);
}

/*
 * convert string into numeric id.
 */
static int
acl_str_to_id(char *str, int *id)
{
	char *end;
	uid_t value;

	errno = 0;
	value = strtoul(str, &end, 10);

	if (errno != 0 || *end != '\0')
		return (EACL_INVALID_USER_GROUP);

	*id = value;

	return (0);
}

/*
 * determine either uid/gid for given entry type
 */
int
get_id(int entry_type, char *name, int *id)
{
	struct passwd *pw;
	struct group *gr;
	int error;

	/*
	 * First see if uid/gid is an all-numeric value
	 * otherwise, try getpwnam/getgrnam.
	 */
	error = acl_str_to_id(name, id);

	if (error != 0) {
		if (entry_type == USER_TOK || entry_type == DEFAULT_USER_TOK) {
			pw = getpwnam(name);
			if (pw) {
				*id = pw->pw_uid;
				error = 0;
			} 
		} else {
			gr = getgrnam(name);
			if (gr) {
				*id = gr->gr_gid;
				error = 0;
			} 
		}
	} 

	return (error);
}
/*
 * reset beginning state to TS and set character position
 * back to zero.
 */
void
yyreset()
{
	yybufpos = 0;
	memset(&yystrings, 0, sizeof (yystrings));
	BEGIN TS;
}

void
yycleanup()
{
	if (yystrings.y_logname)
		free(yystrings.y_logname);
	if (yystrings.y_perms)
		free(yystrings.y_perms);
	if (yystrings.y_iflags)
		free(yystrings.y_iflags);
	yystrings.y_logname = NULL;
	yystrings.y_perms = NULL;
	yystrings.y_iflags = NULL;
}
