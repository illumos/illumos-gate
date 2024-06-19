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
 *
 * Copyright 2022 RackTop Systems, Inc.
 */

#include <acl_common.h>
#include <aclutils.h>

extern int yyinteractive;
extern acl_t *yyacl;
extern int yylex(void);

%}

%union {
	char *str;
	int val;
	struct acl_perm_type acl_perm;
	ace_t ace;
	aclent_t aclent;
	acl_t *acl;
}

%token BARE_SID_TOK
%token USER_TOK USER_SID_TOK GROUP_TOK GROUP_SID_TOK MASK_TOK OTHER_TOK
%token OWNERAT_TOK GROUPAT_TOK EVERYONEAT_TOK DEFAULT_USER_TOK
%token DEFAULT_GROUP_TOK DEFAULT_MASK_TOK DEFAULT_OTHER_TOK
%token COLON COMMA NL SLASH
%token <str> ID IDNAME PERM_TOK INHERIT_TOK SID
%token <val> ERROR ACE_PERM ACE_INHERIT ENTRY_TYPE ACCESS_TYPE

%type <str> idname id
%type <acl_perm> perms perm aclent_perm ace_perms
%type <acl> acl_entry
%type <ace> ace
%type <aclent> aclent
%type <val> iflags verbose_iflag compact_iflag access_type entry_type

%left ERROR COLON

%%

acl:	acl_entry NL
	{
		yyacl = $1;
		return (0);
	}

	/* This seems illegal, but the old aclfromtext() allows it */
	| acl_entry COMMA NL
	{
		yyacl = $1;
		return (0);
	}
	| acl_entry COMMA acl
	{
		yyacl = $1;
		return (0);
	}

acl_entry: ace
	{
		ace_t *acep;

		if (yyacl == NULL) {
			yyacl = acl_alloc(ACE_T);
			if (yyacl == NULL) {
				yycleanup();
				return (EACL_MEM_ERROR);
			}
		}

		$$ = yyacl;
		if ($$->acl_type == ACLENT_T) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Cannot have POSIX draft ACL entries"
			    " with NFSv4/ZFS ACL entries.\n"));
			acl_free(yyacl);
			yyacl = NULL;
			yycleanup();
			return (EACL_DIFF_TYPE);
		}

		$$->acl_aclp = realloc($$->acl_aclp,
		    ($$->acl_entry_size * ($$->acl_cnt + 1)));
		if ($$->acl_aclp == NULL) {
			free (yyacl);
			yycleanup();
			return (EACL_MEM_ERROR);
		}
		acep = $$->acl_aclp;
		acep[$$->acl_cnt] = $1;
		$$->acl_cnt++;
		yycleanup();
	}
	| aclent
	{
		aclent_t *aclent;

		if (yyacl == NULL) {
			yyacl = acl_alloc(ACLENT_T);
			if (yyacl == NULL) {
				yycleanup();
				return (EACL_MEM_ERROR);
			}
		}

		$$ = yyacl;
		if ($$->acl_type == ACE_T) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Cannot have NFSv4/ZFS ACL entries"
			    " with POSIX draft ACL entries.\n"));
			acl_free(yyacl);
			yyacl = NULL;
			yycleanup();
			return (EACL_DIFF_TYPE);
		}

		$$->acl_aclp = realloc($$->acl_aclp,
		    ($$->acl_entry_size  * ($$->acl_cnt +1)));
		if ($$->acl_aclp == NULL) {
			free (yyacl);
			yycleanup();
			return (EACL_MEM_ERROR);
		}
		aclent = $$->acl_aclp;
		aclent[$$->acl_cnt] = $1;
		$$->acl_cnt++;
		yycleanup();
	}

ace:	entry_type idname ace_perms access_type
	{
		int error;
		uid_t id;
		int mask;

		error = get_id($1, $2, &id);
		if (error) {
			bad_entry_type($1, $2);
			yycleanup();
			return (EACL_INVALID_USER_GROUP);
		}

		$$.a_who = id;
		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$3, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}
		$$.a_type = $4;

	}
	| entry_type idname ace_perms access_type COLON id
	{
		int error;
		uid_t id;

		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of "
			    "ACL specification.\n"));
			yycleanup();
			return (EACL_UNKNOWN_DATA);
		}
		error = get_id($1, $2, &id);
		if (error) {
			$$.a_who = get_id_nofail($1, $6);
		} else {
			$$.a_who = id;
		}
		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$3, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}
		$$.a_type = $4;
	}
	| entry_type idname ace_perms iflags access_type
	{
		int error;
		uid_t id;

		error = get_id($1, $2, &id);
		if (error) {
			bad_entry_type($1, $2);
			yycleanup();
			return (EACL_INVALID_USER_GROUP);
		}

		$$.a_who = id;
		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$3, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}
		$$.a_type = $5;
		$$.a_flags |= $4;
	}
	| entry_type idname ace_perms iflags access_type COLON id
	{
		int error;
		uid_t  id;

		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of "
			    "ACL specification.\n"));
			yycleanup();
			return (EACL_UNKNOWN_DATA);
		}
		error = get_id($1, $2, &id);
		if (error) {
			$$.a_who = get_id_nofail($1, $7);
		} else {
			$$.a_who = id;
		}

		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$3, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}

		$$.a_type = $5;
		$$.a_flags |= $4;
	}
	| entry_type ace_perms access_type
	{
		int error;

		$$.a_who = -1;
		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$2, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}
		$$.a_type = $3;
	}
	| entry_type ace_perms access_type COLON id
	{
		yycleanup();
		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of "
			    "ACL specification.\n"));
			return (EACL_UNKNOWN_DATA);
		}

		return (EACL_ENTRY_ERROR);
	}
	| entry_type ace_perms iflags access_type
	{
		int error;

		$$.a_who = -1;
		$$.a_flags = ace_entry_type($1);
		error = ace_perm_mask(&$2, &$$.a_access_mask);
		if (error) {
			yycleanup();
			return (error);
		}
		$$.a_type = $4;
		$$.a_flags |= $3;

	}
	| entry_type ace_perms iflags access_type COLON id
	{
		yycleanup();
		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of "
			    "ACL specification.\n"));
			return (EACL_UNKNOWN_DATA);
		}
		return (EACL_ENTRY_ERROR);
	}

aclent: entry_type idname aclent_perm	/* user or group */
	{
		int error;
		uid_t id;

		error = get_id($1, $2, &id);
		if (error) {
			bad_entry_type($1, $2);
			yycleanup();
			return (EACL_INVALID_USER_GROUP);
		}

		error = compute_aclent_perms($3.perm_str, &$$.a_perm);
		if (error) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Invalid permission(s) '%s' specified.\n"),
			    $3.perm_str);
			yycleanup();
			return (error);
		}
		$$.a_id = id;
		error = aclent_entry_type($1, 0, &$$.a_type);
		if (error) {
			acl_error(
			    dgettext(TEXT_DOMAIN,
			    "Invalid ACL entry type '%s' specified.\n"), $1);
			yycleanup();
			return (error);
		}
	}
	| entry_type COLON aclent_perm		/* owner group other */
	{
		int error;

		error = compute_aclent_perms($3.perm_str, &$$.a_perm);
		if (error) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Invalid permission(s) '%s' specified.\n"),
			    $3.perm_str);
			yycleanup();
			return (error);
		}
		$$.a_id = -1;
		error = aclent_entry_type($1, 1, &$$.a_type);
		if (error) {
			acl_error(
			    dgettext(TEXT_DOMAIN,
			    "Invalid ACL entry type '%s' specified.\n"), $1);
			yycleanup();
			return (error);
		}
	}
	| entry_type COLON aclent_perm COLON id
	{
		yycleanup();
		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of ACL specification.\n"));
			return (EACL_UNKNOWN_DATA);
		}
		return (EACL_ENTRY_ERROR);
	}
	| entry_type idname aclent_perm COLON id	/* user or group */
	{
		int error;
		uid_t id;

		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of ACL specification.\n"));
			yycleanup();
			return (EACL_UNKNOWN_DATA);
		}
		error = compute_aclent_perms($3.perm_str, &$$.a_perm);
		if (error) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Invalid permission(s) '%s' specified.\n"),
			    $3.perm_str);
			yycleanup();
			return (error);
		}
		error = get_id($1, $2, &id);
		if (error) {
			$$.a_id = get_id_nofail($1, $5);
		} else
			$$.a_id = id;

		error = aclent_entry_type($1, 0, &$$.a_type);
		if (error) {
			acl_error(
			    dgettext(TEXT_DOMAIN,
			    "Invalid ACL entry type '%s' specified.\n"), $1);
			yycleanup();
			return (error);
		}
	}
	| entry_type aclent_perm  /* mask entry */
	{
		int error;

		error = compute_aclent_perms($2.perm_str, &$$.a_perm);
		if (error) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Invalid permission(s) '%s' specified.\n"),
			    $2.perm_str);
			yycleanup();
			return (error);
		}
		$$.a_id = -1;
		error = aclent_entry_type($1, 0, &$$.a_type);
		if (error) {
			acl_error(
			    dgettext(TEXT_DOMAIN,
			    "Invalid ACL entry type specified %d.\n"),
			    error);
			yycleanup();
			return (error);
		}
	}
	| entry_type aclent_perm COLON id
	{
		yycleanup();
		if (yyinteractive) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Extra fields on the end of ACL specification.\n"));
			return (EACL_UNKNOWN_DATA);
		}
		return (EACL_ENTRY_ERROR);
	}

iflags: compact_iflag COLON {$$ = $1;}
	| verbose_iflag COLON {$$ = $1;}
	| COLON {$$ = 0;}

compact_iflag : INHERIT_TOK
	{
		int error;
		uint32_t iflags;

		error = compute_ace_inherit($1, &iflags);
		if (error) {
			acl_error(dgettext(TEXT_DOMAIN,
			    "Invalid inheritance flags '%s' specified.\n"), $1);
			yycleanup();
			return (error);
		}
		$$ = iflags;
	}
	| INHERIT_TOK SLASH verbose_iflag
	{
		acl_error(dgettext(TEXT_DOMAIN,
		    "Can't mix compact inherit flags with"
		    " verbose inheritance flags.\n"));
		yycleanup();
		return (EACL_INHERIT_ERROR);
	}

verbose_iflag: ACE_INHERIT	{$$ |= $1;}
	| ACE_INHERIT SLASH verbose_iflag {$$ = $1 | $3;}
	| ACE_INHERIT SLASH compact_iflag
	{
		acl_error(dgettext(TEXT_DOMAIN,
		    "Can't mix verbose inherit flags with"
		    " compact inheritance flags.\n"));
		yycleanup();
		return (EACL_INHERIT_ERROR);
	}
	| ACE_INHERIT SLASH ACCESS_TYPE
	{
		acl_error(dgettext(TEXT_DOMAIN,
		    "Inheritance flags can't be mixed with access type.\n"));
		yycleanup();
		return (EACL_INHERIT_ERROR);
	}
	| ACE_INHERIT SLASH ERROR
	{
		yycleanup();
		return ($3);
	}

aclent_perm: PERM_TOK
	{
		$$.perm_style = PERM_TYPE_UNKNOWN;
		$$.perm_str = $1;
		$$.perm_val = 0;
	}
	| PERM_TOK ERROR
	{
		acl_error(dgettext(TEXT_DOMAIN,
		    "ACL entry permissions are incorrectly specified.\n"));
		yycleanup();
		return ($2);
	}

access_type: ACCESS_TYPE {$$ = $1;}
	| ERROR
	{
		yycleanup();
		return ($1);
	}

id: ID {$$ = $1;}
	| SID {$$ = $1;}
	| COLON
	{
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid uid/gid specified.\nThe field"
		    " should be a numeric value.\n"));
		yycleanup();
		return (EACL_UNKNOWN_DATA);
	}
	| ERROR
	{
		yycleanup();
		return ($1);
	}

ace_perms: perm {$$ = $1;}
	| aclent_perm COLON {$$ = $1;}
	| ERROR
	{
		yycleanup();
		return ($1);
	}

perm: perms COLON {$$ = $1;}
	| COLON {$$.perm_style = PERM_TYPE_EMPTY;}

perms: ACE_PERM
	{
		$$.perm_style = PERM_TYPE_ACE;
		$$.perm_val |= $1;
	}
	| ACE_PERM SLASH perms
	{
		$$.perm_style = PERM_TYPE_ACE;
		$$.perm_val = $1 | $3.perm_val;
	}
	| ACE_PERM SLASH aclent_perm
	{

		acl_error(dgettext(TEXT_DOMAIN,
		   "Can't mix verbose permissions with"
		    " compact permission.\n"));
		yycleanup();
		return (EACL_PERM_MASK_ERROR);

	}
	| ACE_PERM SLASH ERROR
	{
		yycleanup();
		return ($3);
	}


idname: IDNAME {$$ = $1;}

entry_type: ENTRY_TYPE {$$ = $1;}
	| ERROR
	{
		yycleanup();
		return ($1);
	}

%%
static void
bad_entry_type(int toketype, char *str)
{
	switch(toketype) {
	case USER_TOK:
	case DEFAULT_USER_TOK:
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid user %s specified.\n"), str);
		break;

	case GROUP_TOK:
	case DEFAULT_GROUP_TOK:
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid group %s specified.\n"), str);
		break;

	case USER_SID_TOK:
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid user SID %s specified.\n"), str);
		break;

	case GROUP_SID_TOK:
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid group SID %s specified.\n"), str);
		break;

	case BARE_SID_TOK:
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid SID %s specified.\n"), str);
		break;
	}
}
