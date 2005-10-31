/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*LINTLIBRARY*/

#include <grp.h>
#include <pwd.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/acl.h>
#include <aclutils.h>
#include <libintl.h>


extern acl_t *acl_alloc(enum acl_type);

/*
 * acltotext() converts each ACL entry to look like this:
 *
 *    entry_type:uid^gid^name:perms
 *
 * The maximum length of entry_type is 14 ("defaultgroup::" and
 * "defaultother::") hence ENTRYTYPELEN is set to 14.
 *
 * The max length of a uid^gid^name entry (in theory) is 8, hence we use
 * LOGNAME_MAX.
 *
 * The length of a perms entry is 4 to allow for the comma appended to each
 * to each acl entry.  Hence PERMS is set to 4.
 */

#define	ENTRYTYPELEN	14
#define	PERMS		4
#define	ACL_ENTRY_SIZE	(ENTRYTYPELEN + LOGNAME_MAX + PERMS)

struct dynaclstr {
	size_t bufsize;		/* current size of aclexport */
	char *aclexport;
};

static char *strappend(char *, char *);
static char *convert_perm(char *, o_mode_t);
static int increase_length(struct dynaclstr *, size_t);

static int
acl_str_to_id(char *str, int *id)
{
	char *end;
	uid_t value;

	value = strtol(str, &end, 10);

	if (errno != 0 || *end != '\0')
		return (EACL_INVALID_USER_GROUP);

	*id = value;

	return (0);
}

/*
 * Convert internal acl representation to external representation.
 *
 * The length of a non-owning user name or non-owning group name ie entries
 * of type DEF_USER, USER, DEF_GROUP or GROUP, can exceed LOGNAME_MAX.  We
 * thus check the length of these entries, and if greater than LOGNAME_MAX,
 * we realloc() via increase_length().
 *
 * The LOGNAME_MAX, ENTRYTYPELEN and PERMS limits are otherwise always
 * adhered to.
 */
char *
acltotext(aclent_t *aclp, int aclcnt)
{
	char		*aclexport;
	char		*where;
	struct group	*groupp;
	struct passwd	*passwdp;
	struct dynaclstr *dstr;
	int		i, rtn;
	size_t		excess = 0;

	if (aclp == NULL)
		return (NULL);
	if ((dstr = malloc(sizeof (struct dynaclstr))) == NULL)
		return (NULL);
	dstr->bufsize = aclcnt * ACL_ENTRY_SIZE;
	if ((dstr->aclexport = malloc(dstr->bufsize)) == NULL) {
		free(dstr);
		return (NULL);
	}
	*dstr->aclexport = '\0';
	where = dstr->aclexport;

	for (i = 0; i < aclcnt; i++, aclp++) {
		switch (aclp->a_type) {
		case DEF_USER_OBJ:
		case USER_OBJ:
			if (aclp->a_type == USER_OBJ)
				where = strappend(where, "user::");
			else
				where = strappend(where, "defaultuser::");
			where = convert_perm(where, aclp->a_perm);
			break;
		case DEF_USER:
		case USER:
			if (aclp->a_type == USER)
				where = strappend(where, "user:");
			else
				where = strappend(where, "defaultuser:");
			passwdp = getpwuid(aclp->a_id);
			if (passwdp == (struct passwd *)NULL) {
				/* put in uid instead */
				(void) sprintf(where, "%d", aclp->a_id);
			} else {
				excess = strlen(passwdp->pw_name) - LOGNAME_MAX;
				if (excess > 0) {
					rtn = increase_length(dstr, excess);
					if (rtn == 1) {
						/* reset where */
						where = dstr->aclexport +
							strlen(dstr->aclexport);
					} else {
						free(dstr->aclexport);
						free(dstr);
						return (NULL);
					}
				}
				where = strappend(where, passwdp->pw_name);
			}
			where = strappend(where, ":");
			where = convert_perm(where, aclp->a_perm);
			break;
		case DEF_GROUP_OBJ:
		case GROUP_OBJ:
			if (aclp->a_type == GROUP_OBJ)
				where = strappend(where, "group::");
			else
				where = strappend(where, "defaultgroup::");
			where = convert_perm(where, aclp->a_perm);
			break;
		case DEF_GROUP:
		case GROUP:
			if (aclp->a_type == GROUP)
				where = strappend(where, "group:");
			else
				where = strappend(where, "defaultgroup:");
			groupp = getgrgid(aclp->a_id);
			if (groupp == (struct group *)NULL) {
				/* put in gid instead */
				(void) sprintf(where, "%d", aclp->a_id);
			} else {
				excess = strlen(groupp->gr_name) - LOGNAME_MAX;
				if (excess > 0) {
					rtn = increase_length(dstr, excess);
					if (rtn == 1) {
						/* reset where */
						where = dstr->aclexport +
							strlen(dstr->aclexport);
					} else {
						free(dstr->aclexport);
						free(dstr);
						return (NULL);
					}
				}
				where = strappend(where, groupp->gr_name);
			}
			where = strappend(where, ":");
			where = convert_perm(where, aclp->a_perm);
			break;
		case DEF_CLASS_OBJ:
		case CLASS_OBJ:
			if (aclp->a_type == CLASS_OBJ)
				where = strappend(where, "mask:");
			else
				where = strappend(where, "defaultmask:");
			where = convert_perm(where, aclp->a_perm);
			break;
		case DEF_OTHER_OBJ:
		case OTHER_OBJ:
			if (aclp->a_type == OTHER_OBJ)
				where = strappend(where, "other:");
			else
				where = strappend(where, "defaultother:");
			where = convert_perm(where, aclp->a_perm);
			break;
		default:
			free(dstr->aclexport);
			free(dstr);
			return (NULL);

		}
		if (i < aclcnt - 1)
			where = strappend(where, ",");
	}
	aclexport = dstr->aclexport;
	free(dstr);
	return (aclexport);
}

/*
 * Convert external acl representation to internal representation.
 * The accepted syntax is: <acl_entry>[,<acl_entry>]*[,]
 * The comma at the end is not prescribed by the man pages.
 * But it is needed not to break the old programs.
 */
static int
aclent_aclfromtext(char *aclstr, acl_t **ret_aclp)
{
	char		*fieldp;
	char		*tp;
	char		*nextp;
	char		*allocp;
	char		*aclimport;
	int		entry_type;
	int		id;
	int		len;
	int		error;
	o_mode_t	perm;
	aclent_t	*tmpaclp;
	acl_t		*aclp;
	struct group	*groupp;
	struct passwd	*passwdp;

	aclp = NULL;

	if (! aclstr)
		return (NULL);

	aclp = acl_alloc(ACLENT_T);
	if (aclp == NULL) {
		return (EACL_MEM_ERROR);
	}

	*ret_aclp = NULL;

	len = strlen(aclstr);

	if ((aclimport = allocp = strdup(aclstr)) == NULL) {
		return (EACL_MEM_ERROR);
	}

	if (aclimport[len - 1] == ',')
		aclimport[len - 1] = '\0';

	for (; aclimport; ) {
		/* look for an ACL entry */
		tp = strchr(aclimport, ',');
		if (tp == NULL) {
			nextp = NULL;
		} else {
			*tp = '\0';
			nextp = tp + 1;
		}

		aclp->acl_cnt += 1;

		/*
		 * get additional memory:
		 * can be more efficient by allocating a bigger block
		 * each time.
		 */
		if (aclp->acl_cnt > 1)
			tmpaclp = (aclent_t *)realloc(aclp->acl_aclp,
			    sizeof (aclent_t) * (aclp->acl_cnt));
		else
			tmpaclp = (aclent_t *)malloc(sizeof (aclent_t));
		if (tmpaclp == NULL) {
			free(allocp);
			acl_free(aclp);
			return (EACL_MEM_ERROR);
		}
		aclp->acl_aclp = tmpaclp;
		tmpaclp = (aclent_t *)aclp->acl_aclp + (aclp->acl_cnt - 1);

		/* look for entry type field */
		tp = strchr(aclimport, ':');
		if (tp == NULL) {
			free(allocp);
			if (aclp)
				acl_free(aclp);
			return (EACL_ENTRY_ERROR);
		} else
			*tp = '\0';
		if (strcmp(aclimport, "user") == 0) {
			if (*(tp+1) == ':')
				entry_type = USER_OBJ;
			else
				entry_type = USER;
		} else if (strcmp(aclimport, "group") == 0) {
			if (*(tp+1) == ':')
				entry_type = GROUP_OBJ;
			else
				entry_type = GROUP;
		} else if (strcmp(aclimport, "other") == 0)
			entry_type = OTHER_OBJ;
		else if (strcmp(aclimport, "mask") == 0)
			entry_type = CLASS_OBJ;
		else if (strcmp(aclimport, "defaultuser") == 0) {
			if (*(tp+1) == ':')
				entry_type = DEF_USER_OBJ;
			else
				entry_type = DEF_USER;
		} else if (strcmp(aclimport, "defaultgroup") == 0) {
			if (*(tp+1) == ':')
				entry_type = DEF_GROUP_OBJ;
			else
				entry_type = DEF_GROUP;
		} else if (strcmp(aclimport, "defaultmask") == 0)
			entry_type = DEF_CLASS_OBJ;
		else if (strcmp(aclimport, "defaultother") == 0)
			entry_type = DEF_OTHER_OBJ;
		else {
			free(allocp);
			acl_free(aclp);
			return (EACL_ENTRY_ERROR);
		}

		/* look for user/group name */
		if (entry_type != CLASS_OBJ && entry_type != OTHER_OBJ &&
		    entry_type != DEF_CLASS_OBJ &&
		    entry_type != DEF_OTHER_OBJ) {
			fieldp = tp + 1;
			tp = strchr(fieldp, ':');
			if (tp == NULL) {
				free(allocp);
				acl_free(aclp);
				return (EACL_INVALID_USER_GROUP);
			} else
				*tp = '\0';
			if (fieldp != tp) {
				/*
				 * The second field could be empty. We only care
				 * when the field has user/group name.
				 */
				if (entry_type == USER ||
				    entry_type == DEF_USER) {
					/*
					 * The reentrant interface getpwnam_r()
					 * is uncommitted and subject to
					 * change. Use the friendlier interface
					 * getpwnam().
					 */
					error = 0;
					passwdp = getpwnam(fieldp);
					if (passwdp == NULL) {
						error = acl_str_to_id(fieldp,
						    &id);
					} else {
						id = passwdp->pw_uid;
					}

					if (error) {
						free(allocp);
						acl_free(aclp);
						return (error);
					}

				} else {
					error = 0;
					if (entry_type == GROUP ||
					    entry_type == DEF_GROUP) {
						groupp = getgrnam(fieldp);
						if (groupp == NULL) {
							error = acl_str_to_id(
							    fieldp, &id);
						}
						if (error == 0)
							id = groupp->gr_gid;
					}
					if (error) {
						free(allocp);
						acl_free(aclp);
						return (error);
					}
				}
			} else {
				/*
				 * The second field is empty.
				 * Treat it as undefined (-1)
				 */
				id = -1;
			}
		} else {
			/*
			 * Let's not break the old applications
			 * that use mask::rwx, other::rwx format,
			 * though they violate the man pages.
			 */
			if (*(tp + 1) == ':')
				*++tp = 0;
		}

		/* next field: permission */
		fieldp = tp + 1;
		if (strlen(fieldp) != 3) {
			/*  not "rwx" format */
			free(allocp);
			acl_free(aclp);
			return (EACL_PERM_MASK_ERROR);
		} else {
			char	s[] = "rwx";
			int	mask = 0x04;
			int	i;
			perm = 0;

			for (i = 0; i < 3; i++, mask /= 2) {
				if (fieldp[i] == s[i])
					perm |= mask;
				else if (fieldp[i] != '-') {
					free(allocp);
					acl_free(aclp);
					return (EACL_PERM_MASK_ERROR);
				}
			}
		}

		tmpaclp->a_type = entry_type;
		tmpaclp->a_id = id;
		tmpaclp->a_perm = perm;
		aclimport = nextp;
	}
	free(allocp);
	*ret_aclp = aclp;
	return (0);
}

aclent_t *
aclfromtext(char *aclstr, int *aclcnt)
{
	acl_t *aclp;
	aclent_t *aclentp;
	int error;

	error = aclent_aclfromtext(aclstr, &aclp);
	if (error)
		return (NULL);

	aclentp = aclp->acl_aclp;
	aclp->acl_aclp = NULL;
	acl_free(aclp);

	*aclcnt = aclp->acl_cnt;
	return (aclentp);
}


static char *
strappend(char *where, char *newstr)
{
	(void) strcat(where, newstr);
	return (where + strlen(newstr));
}

static char *
convert_perm(char *where, o_mode_t perm)
{
	if (perm & 04)
		where = strappend(where, "r");
	else
		where = strappend(where, "-");
	if (perm & 02)
		where = strappend(where, "w");
	else
		where = strappend(where, "-");
	if (perm & 01)
		where = strappend(where, "x");
	else
		where = strappend(where, "-");
	/* perm is the last field */
	return (where);
}

static char *
ace_convert_perm(char *where, mode_t perm, int isdir, int iflags)
{
	char *start = where;

	/*
	 * The following mneumonics all have the
	 * same value.  The only difference is the
	 * first value is for files and second for directories
	 * ACE_READ_DATA/ACE_LIST_DIRECTORY
	 * ACE_WRITE_DATA/ACE_ADD_FILE
	 * ACE_APPEND_DATA/ACE_ADD_SUBDIRECTORY
	 */

	/*
	 * If ACE is a directory, but inheritance indicates its
	 * for a file then print permissions for file rather than
	 * dir.
	 */
	if (isdir) {
		if (perm & ACE_LIST_DIRECTORY) {
			if (iflags == ACE_FILE_INHERIT_ACE)
				where = strappend(where, "read_data/");
			else
				where = strappend(where,
				    "list_directory/read_data/");
		}
		if (perm & ACE_ADD_FILE) {
			if (iflags == ACE_FILE_INHERIT_ACE)
				where = strappend(where, "write_data/");
			else
				where = strappend(where,
				    "add_file/write_data/");
		}
		if (perm & ACE_ADD_SUBDIRECTORY) {
			if (iflags == ACE_FILE_INHERIT_ACE)
				where = strappend(where, "append_data/");
			else
				where = strappend(where,
				    "add_subdirectory/append_data/");
		}
	} else {
		if (perm & ACE_READ_DATA)
			where = strappend(where, "read_data/");
		if (perm & ACE_WRITE_DATA)
			where = strappend(where, "write_data/");
		if (perm & ACE_APPEND_DATA)
			where = strappend(where, "append_data/");
	}
	if (perm & ACE_READ_NAMED_ATTRS)
		where = strappend(where, "read_xattr/");
	if (perm & ACE_WRITE_NAMED_ATTRS)
		where = strappend(where, "write_xattr/");
	if (perm & ACE_EXECUTE)
		where = strappend(where, "execute/");
	if (perm & ACE_DELETE_CHILD)
		where = strappend(where, "delete_child/");
	if (perm & ACE_READ_ATTRIBUTES)
		where = strappend(where, "read_attributes/");
	if (perm & ACE_WRITE_ATTRIBUTES)
		where = strappend(where, "write_attributes/");
	if (perm & ACE_DELETE)
		where = strappend(where, "delete/");
	if (perm & ACE_READ_ACL)
		where = strappend(where, "read_acl/");
	if (perm & ACE_WRITE_ACL)
		where = strappend(where, "write_acl/");
	if (perm & ACE_WRITE_OWNER)
		where = strappend(where, "write_owner/");
	if (perm & ACE_SYNCHRONIZE)
		where = strappend(where, "synchronize");

	if (start[strlen(start) - 1] == '/') {
		start[strlen(start) - 1] = '\0';
		where = start + strlen(start);
	}
	return (where);
}

int
ace_permask(char *perm_tok, int *perm)
{
	if (strcmp(perm_tok, "read_data") == 0)
		*perm |= ACE_READ_DATA;
	else if (strcmp(perm_tok, "list_directory") == 0)
		*perm |= ACE_LIST_DIRECTORY;
	else if (strcmp(perm_tok, "write_data") == 0)
		*perm |= ACE_WRITE_DATA;
	else if (strcmp(perm_tok, "add_file") == 0)
		*perm |= ACE_ADD_FILE;
	else if (strcmp(perm_tok, "append_data") == 0)
		*perm |= ACE_APPEND_DATA;
	else if (strcmp(perm_tok, "add_subdirectory") == 0)
		*perm |= ACE_ADD_SUBDIRECTORY;
	else if (strcmp(perm_tok, "read_xattr") == 0)
		*perm |= ACE_READ_NAMED_ATTRS;
	else if (strcmp(perm_tok, "write_xattr") == 0)
		*perm |= ACE_WRITE_NAMED_ATTRS;
	else if (strcmp(perm_tok, "execute") == 0)
		*perm |= ACE_EXECUTE;
	else if (strcmp(perm_tok, "delete_child") == 0)
		*perm |= ACE_DELETE_CHILD;
	else if (strcmp(perm_tok, "read_attributes") == 0)
		*perm |= ACE_READ_ATTRIBUTES;
	else if (strcmp(perm_tok, "write_attributes") == 0)
		*perm |= ACE_WRITE_ATTRIBUTES;
	else if (strcmp(perm_tok, "delete") == 0)
		*perm |= ACE_DELETE;
	else if (strcmp(perm_tok, "read_acl") == 0)
		*perm |= ACE_READ_ACL;
	else if (strcmp(perm_tok, "write_acl") == 0)
		*perm |= ACE_WRITE_ACL;
	else if (strcmp(perm_tok, "write_owner") == 0)
		*perm |= ACE_WRITE_OWNER;
	else if (strcmp(perm_tok, "synchronize") == 0)
		*perm |= ACE_SYNCHRONIZE;
	else {
		return (1);
	}

	return (0);
}

/*
 * Callers should check the return code as this routine may change the string
 * pointer in dynaclstr.
 */
static int
increase_length(struct dynaclstr *dacl, size_t increase)
{
	char *tptr;
	size_t newsize;

	newsize = dacl->bufsize + increase;
	tptr = realloc(dacl->aclexport, newsize);
	if (tptr != NULL) {
		dacl->aclexport = tptr;
		dacl->bufsize = newsize;
		return (1);
	} else
		return (0);
}

/*
 * ace_acltotext() conver each ace formatted acl to look like this:
 *
 * entry_type:uid^gid^name:perms:allow^deny[:flags][,]
 *
 * The maximum length of entry_type is 5 ("group")
 *
 * The max length of a uid^gid^name entry (in theory) is 8, hence we use
 * LOGNAME_MAX.
 *
 * The length of a perms entry is 144 i.e read_data/write_data...
 * to each acl entry.
 *
 * iflags: file_inherit/dir_inherit/inherit_only/no_propagate
 *
 */

#define	ACE_ENTRYTYPLEN		6
#define	IFLAGS_SIZE		51
#define	ACCESS_TYPE_SIZE	5
#define	COLON_CNT		3
#define	PERMS_LEN		216
#define	ACE_ENTRY_SIZE	(ACE_ENTRYTYPLEN + LOGNAME_MAX + PERMS_LEN +\
    ACCESS_TYPE_SIZE + IFLAGS_SIZE + COLON_CNT)

static char *
ace_acltotext(acl_t *aceaclp)
{
	ace_t		*aclp = aceaclp->acl_aclp;
	int		aclcnt = aceaclp->acl_cnt;
	char		*aclexport;
	char		*where;
	char		*start;
	struct group	*groupp;
	struct passwd	*passwdp;
	struct dynaclstr *dstr;
	int		i, rtn;
	int		isdir = (aceaclp->acl_flags & ACL_IS_DIR);
	size_t		excess = 0;

	if (aclp == NULL)
		return (NULL);
	if ((dstr = malloc(sizeof (struct dynaclstr))) == NULL)
		return (NULL);
	dstr->bufsize = aclcnt * ACE_ENTRY_SIZE;
	if ((dstr->aclexport = malloc(dstr->bufsize)) == NULL)
		return (NULL);
	*dstr->aclexport = '\0';
	where = dstr->aclexport;

	for (i = 0; i < aclcnt; i++, aclp++) {
		switch (aclp->a_flags & 0xf040) {
		case ACE_OWNER:
		case 0:
			if ((aclp->a_flags & 0xf040) == ACE_OWNER)
				where = strappend(where, "owner@");
			else
				where = strappend(where, "user:");
			if ((aclp->a_flags & 0xf040) == 0) {
				passwdp = getpwuid(aclp->a_who);
				if (passwdp == (struct passwd *)NULL) {
					/* put in uid instead */
					(void) sprintf(where, "%d",
					    aclp->a_who);
				} else {
					excess = strlen(passwdp->pw_name) -
					    LOGNAME_MAX;
					if (excess > 0) {
						rtn = increase_length(dstr,
						    excess);
						if (rtn == 1)
							/* reset where */
							where =
							    dstr->aclexport +
							    strlen(
							    dstr->aclexport);
						else
							return (NULL);
					}
					where = strappend(where,
					    passwdp->pw_name);
				}
			} else {
				where = strappend(where, "");
			}
			where = strappend(where, ":");
			break;
		case ACE_GROUP|ACE_IDENTIFIER_GROUP:
		case ACE_IDENTIFIER_GROUP:
			if ((aclp->a_flags & 0xf040) ==
			    (ACE_GROUP | ACE_IDENTIFIER_GROUP))
				where = strappend(where, "group@");
			else
				where = strappend(where, "group:");
			if (!(aclp->a_flags & ACE_GROUP)) {
				groupp = getgrgid(aclp->a_who);
				if (groupp == (struct group *)NULL) {
					/* put in gid instead */
					(void) sprintf(where,
					    "%d", aclp->a_who);
				} else {
					excess = strlen(groupp->gr_name) -
					    LOGNAME_MAX;
					if (excess > 0) {
						rtn = increase_length(dstr,
						    excess);
						if (rtn == 1)
							/* reset where */
							where =
							    dstr->aclexport +
							    strlen(
							    dstr->aclexport);
						else
							return (NULL);
					}
					where = strappend(where,
					    groupp->gr_name);
				}
			} else {
					where = strappend(where, "");
			}
			where = strappend(where, ":");
			break;
		case ACE_EVERYONE:
			where = strappend(where, "everyone@:");
			break;
		default:
			free(dstr->aclexport);
			free(dstr);
			return (NULL);

		}
		where = ace_convert_perm(where, aclp->a_access_mask,
		    isdir, (aclp->a_flags &
		    (ACE_FILE_INHERIT_ACE|ACE_DIRECTORY_INHERIT_ACE)));
		where = strappend(where,
		    (aclp->a_type == ACE_ACCESS_ALLOWED_ACE_TYPE) ?
		    ":allow" : ":deny");

		/*
		 * slap on inheritance flags if we have any
		 */

		if (aclp->a_flags & 0xf) {
			where = strappend(where, ":");
			start = where;
			if (aclp->a_flags & ACE_FILE_INHERIT_ACE)
				where = strappend(where, "file_inherit/");
			if (aclp->a_flags & ACE_DIRECTORY_INHERIT_ACE)
				where = strappend(where, "dir_inherit/");
			if (aclp->a_flags & ACE_NO_PROPAGATE_INHERIT_ACE)
				where = strappend(where, "no_propagate/");
			if (aclp->a_flags & ACE_INHERIT_ONLY_ACE)
				where = strappend(where, "inherit_only");

			/*
			 * chop off trailing slash, if present
			 */
			if (start[strlen(start) - 1] == '/') {
				start[strlen(start) - 1] = '\0';
				where = start + strlen(start);
			}
		}
		if (i < aclcnt - 1)
			where = strappend(where, ",");
	}
	aclexport = dstr->aclexport;
	free(dstr);
	return (aclexport);
}

static int
build_iflags(char *str, int *iflags)
{

	char *tok;
	*iflags = 0;

	tok = strtok(str, "/");

	if (tok == NULL)
		return (1);

	do {
		if (strcmp(tok, "file_inherit") == 0)
			*iflags |= ACE_FILE_INHERIT_ACE;
		else if (strcmp(tok, "dir_inherit") == 0)
			*iflags |= ACE_DIRECTORY_INHERIT_ACE;
		else if (strcmp(tok, "inherit_only") == 0)
			*iflags |= ACE_INHERIT_ONLY_ACE;
		else if (strcmp(tok, "no_propagate") == 0)
			*iflags |= ACE_NO_PROPAGATE_INHERIT_ACE;
		else
			return (1);
	} while (tok = strtok(NULL, "/"));
	return (0);
}

/*
 * Convert external acl representation to internal representation.
 * The accepted syntax is: <acl_entry>[,<acl_entry>]*[,]
 * The comma at the end is not prescribed by the man pages.
 * But it is needed not to break the old programs.
 */

int
ace_aclfromtext(char *aclstr, acl_t **ret_aclp)
{
	char		*fieldp;
	char		*tp;
	char		*nextp;
	char		*allocp;
	char		*aclimport;
	char 		*str;
	char		*perm_tok;
	int		entry_type;
	int		id;
	int		type;
	int		iflags;
	int		len;
	int		error;
	int32_t		perm;
	ace_t		*tmpaclp;
	acl_t		*aclp;
	struct group	*groupp;
	struct passwd	*passwdp;

	if (! aclstr)
		return (EACL_INVALID_STR);

	len = strlen(aclstr);

	aclp = acl_alloc(ACE_T);
	if (aclp == NULL) {
		return (EACL_MEM_ERROR);
	}

	*ret_aclp = NULL;

	if ((aclimport = allocp = strdup(aclstr)) == NULL) {
		return (EACL_MEM_ERROR);
	}


	if (aclimport[len - 1] == ',')
		aclimport[len - 1] = '\0';

	for (; aclimport; ) {
		/* look for an ACL entry */
		tp = strchr(aclimport, ',');
		if (tp == NULL) {
			nextp = NULL;
		} else {
			*tp = '\0';
			nextp = tp + 1;
		}

		aclp->acl_cnt += 1;

		/*
		 * get additional memory:
		 * can be more efficient by allocating a bigger block
		 * each time.
		 */
		if (aclp->acl_cnt > 1)
			tmpaclp = (ace_t *)realloc(aclp->acl_aclp,
			    sizeof (ace_t) * (aclp->acl_cnt));
		else
			tmpaclp = (ace_t *)malloc(sizeof (ace_t));
		if (tmpaclp == NULL) {
			free(allocp);
			acl_free(aclp);
			return (EACL_MEM_ERROR);
		}
		aclp->acl_aclp = tmpaclp;
		tmpaclp = (ace_t *)aclp->acl_aclp + (aclp->acl_cnt - 1);

		/* look for entry type field */
		tp = strchr(aclimport, ':');
		if (tp == NULL) {
			free(allocp);
			acl_free(aclp);
			return (EACL_ENTRY_ERROR);
		} else
			*tp = '\0';
		if (strcmp(aclimport, "owner@") == 0) {
			entry_type = ACE_OWNER;
		} else if (strcmp(aclimport, "group@") == 0) {
			entry_type = ACE_GROUP | ACE_IDENTIFIER_GROUP;
		} else if (strcmp(aclimport, "everyone@") == 0) {
			entry_type = ACE_EVERYONE;
		} else if (strcmp(aclimport, "group") == 0) {
			entry_type = ACE_IDENTIFIER_GROUP;
		} else if (strcmp(aclimport, "user") == 0) {
			entry_type = 0;
		} else {
			free(allocp);
			acl_free(aclp);
			return (EACL_ENTRY_ERROR);
		}

		/*
		 * If not an abstraction owner@, group@ or everyone@
		 * then we must have a user/group name next
		 */

		if (entry_type == 0 || entry_type == ACE_IDENTIFIER_GROUP) {
			fieldp = tp + 1;
			tp = strchr(fieldp, ':');
			if (tp == NULL) {
				free(allocp);
				acl_free(aclp);
				return (EACL_INVALID_USER_GROUP);
			} else
				*tp = '\0';
			if (fieldp != tp) {
				/*
				 * The second field could be empty. We only care
				 * when the field has user/group name.
				 */
				if (entry_type == 0) {
					/*
					 * The reentrant interface getpwnam_r()
					 * is uncommitted and subject to
					 * change. Use the friendlier interface
					 * getpwnam().
					 */
					error = 0;
					passwdp = getpwnam(fieldp);
					if (passwdp == NULL) {
						error = acl_str_to_id(
						    fieldp, &id);
					} else {
						id = passwdp->pw_uid;
					}

					if (error) {
						free(allocp);
						acl_free(aclp);
						return (error);
					}
				} else {
					error = 0;
					if (entry_type ==
					    ACE_IDENTIFIER_GROUP) {
						groupp = getgrnam(fieldp);
						if (groupp == NULL) {
							/* no group? */
							error = acl_str_to_id(
							    fieldp, &id);
						} else
							id = groupp->gr_gid;

					} else if ((entry_type == ACE_OWNER) ||
					    (entry_type ==
					    (ACE_IDENTIFIER_GROUP|ACE_GROUP)) ||
					    (entry_type != ACE_EVERYONE)) {
						error = EACL_FIELD_NOT_BLANK;
					} else {
						error = EACL_ENTRY_ERROR;
					}

					if (error) {
						free(allocp);
						acl_free(aclp);
						return (error);
					}
				}
			}
		} else {
			id = -1;
		}

		/* next field: permission */
		fieldp = tp + 1;
		tp = strchr(fieldp, ':');
		if (tp == NULL) {
			free(allocp);
			acl_free(aclp);
			return (EACL_PERM_MASK_ERROR);
		} else
			*tp = '\0';

		perm = 0;

		perm_tok = strtok(fieldp, "/");
		if (perm_tok == NULL) {
			perm = 0;
		} else {
			do {
				if (ace_permask(perm_tok, &perm) != 0) {
					free(allocp);
					acl_free(aclp);
					return (EACL_PERM_MASK_ERROR);
				}
			} while (perm_tok = strtok(NULL, "/"));
		}

		/* grab allow/deny */
		fieldp = tp + 1;
		tp = strchr(fieldp, ':');
		if (tp != NULL)
			*tp = '\0';

		if (strcmp(fieldp, "allow") == 0)
			type = ACE_ACCESS_ALLOWED_ACE_TYPE;
		else if (strcmp(fieldp, "deny") == 0)
			type = ACE_ACCESS_DENIED_ACE_TYPE;
		else {
			free(allocp);
			acl_free(aclp);
			return (EACL_INVALID_ACCESS_TYPE);
		}

		/* grab option inherit flags */

		iflags = 0;
		if (tp != NULL) {
			fieldp = tp + 1;
			if (fieldp != NULL) {
				*tp = '\0';
				str = fieldp;
				if (build_iflags(str, &iflags) != 0) {
					free(allocp);
					acl_free(aclp);
					return (EACL_INHERIT_ERROR);
				}
			} else {
				free(allocp);
				acl_free(aclp);
				return (EACL_UNKNOWN_DATA);
			}
		}
		/* slap fields into ace_t structure */

		tmpaclp->a_flags = entry_type;
		tmpaclp->a_flags |= iflags;
		tmpaclp->a_who = id;
		tmpaclp->a_access_mask = perm;
		tmpaclp->a_type = type;
		aclimport = nextp;
	}
	free(allocp);
	*ret_aclp = aclp;
	return (0);
}

char
*acl_totext(acl_t *aclp)
{
	if (aclp == NULL)
		return (NULL);

	switch (aclp->acl_type) {
	case ACE_T:
		return (ace_acltotext(aclp));
	case ACLENT_T:
		return (acltotext(aclp->acl_aclp, aclp->acl_cnt));
	}
	return (NULL);
}

int
acl_fromtext(const char *acltextp, acl_t **ret_aclp)
{
	acl_t *aclp;
	char *token;
	char *ptr;
	char *textp;
	enum acl_type flavor;
	int colon_cnt = 0;
	int error;

	/*
	 * first try and detect what type of acl entries we have
	 *
	 * aclent_t can have 1, 2 or 3 colons
	 * if 3 then must have word default:
	 *
	 * ace_t can have 2, 3 or 4
	 * for 2 then must be owner@, group@ or everyone@
	 */

	textp = strdup(acltextp);
	if (textp == NULL)
		return (-1);

	token = strtok(textp, ",");
	if (token == NULL) {
		free(textp);
		return (-1);
	}

	for (ptr = token; *ptr; ptr++) {
		if (*ptr == ':')
			colon_cnt++;
	}

	if (colon_cnt == 1 || colon_cnt == 2) {
		if ((strncmp(acltextp, "owner@", 6) == 0) ||
		    (strncmp(acltextp, "group@", 6) == 0) ||
		    (strncmp(acltextp, "everyone@", 9) == 0))
			flavor = ACE_T;
		else
			flavor = ACLENT_T;
	} else if (colon_cnt == 3) {
		ptr = strtok(token, ":");
		if (ptr == NULL) {
			free(textp);
			return (EACL_MISSING_FIELDS);
		} else if (strcmp(ptr, "default") == 0) {
			flavor = ACLENT_T;
		} else {
			flavor = ACE_T;
		}
	} else if (colon_cnt == 4) {
		flavor = ACE_T;
	} else {
		free(textp);
		return (EACL_MISSING_FIELDS);
	}


	free(textp);

	if (flavor == ACLENT_T)
		error = aclent_aclfromtext((char *)acltextp, &aclp);
	else
		error = ace_aclfromtext((char *)acltextp, &aclp);

	*ret_aclp = aclp;
	return (error);
}
