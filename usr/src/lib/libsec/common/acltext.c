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
#include <sys/stat.h>
#include <sys/acl.h>
#include <aclutils.h>

#define	ID_STR_MAX	20	/* digits in LONG_MAX */

#define	APPENDED_ID_MAX	ID_STR_MAX + 1		/* id + colon */
/*
 * yyinteractive controls whether yyparse should print out
 * error messages to stderr, and whether or not id's should be
 * allowed from acl_fromtext().
 */
int	yyinteractive;
acl_t	*yyacl;
char	*yybuf;

extern acl_t *acl_alloc(enum acl_type);


struct dynaclstr {
	size_t bufsize;		/* current size of aclexport */
	char *aclexport;
};

static char *strappend(char *, char *);
static char *convert_perm(char *, o_mode_t);
static int increase_length(struct dynaclstr *, size_t);

static void
aclent_perms(int perm, char *txt_perms)
{
	if (perm & S_IROTH)
		txt_perms[0] = 'r';
	else
		txt_perms[0] = '-';
	if (perm & S_IWOTH)
		txt_perms[1] = 'w';
	else
		txt_perms[1] = '-';
	if (perm & S_IXOTH)
		txt_perms[2] = 'x';
	else
		txt_perms[2] = '-';
	txt_perms[3] = '\0';
}

static char *
pruname(uid_t uid, char *uidp, size_t buflen, int noresolve)
{
	struct passwd	*passwdp = NULL;

	if (noresolve == 0)
		passwdp = getpwuid(uid);
	if (passwdp == (struct passwd *)NULL) {
		/* could not get passwd information: display uid instead */
		(void) snprintf(uidp, buflen, "%u", uid);
	} else {
		(void) strlcpy(uidp, passwdp->pw_name, buflen);
	}
	return (uidp);
}

static char *
prgname(gid_t gid, char *gidp, size_t buflen, int noresolve)
{
	struct group	*groupp = NULL;

	if (noresolve == 0)
		groupp = getgrgid(gid);
	if (groupp == (struct group *)NULL) {
		/* could not get group information: display gid instead */
		(void) snprintf(gidp, buflen, "%u", gid);
	} else {
		(void) strlcpy(gidp, groupp->gr_name, buflen);
	}
	return (gidp);
}
static void
aclent_printacl(acl_t *aclp)
{
	aclent_t *tp;
	int aclcnt;
	int mask;
	int slot = 0;
	char perm[4];
	char uidp[ID_STR_MAX];
	char gidp[ID_STR_MAX];

	/* display ACL: assume it is sorted. */
	aclcnt = aclp->acl_cnt;
	for (tp = aclp->acl_aclp; tp && aclcnt--; tp++) {
		if (tp->a_type == CLASS_OBJ)
			mask = tp->a_perm;
	}
	aclcnt = aclp->acl_cnt;
	for (tp = aclp->acl_aclp; aclcnt--; tp++) {
		(void) printf("     %d:", slot++);
		switch (tp->a_type) {
		case USER:
			aclent_perms(tp->a_perm, perm);
			(void) printf("user:%s:%s\t\t",
			    pruname(tp->a_id, uidp, sizeof (uidp), 0), perm);
			aclent_perms((tp->a_perm & mask), perm);
			(void) printf("#effective:%s\n", perm);
			break;
		case USER_OBJ:
			/* no need to display uid */
			aclent_perms(tp->a_perm, perm);
			(void) printf("user::%s\n", perm);
			break;
		case GROUP:
			aclent_perms(tp->a_perm, perm);
			(void) printf("group:%s:%s\t\t",
			    prgname(tp->a_id, gidp, sizeof (gidp), 0), perm);
			aclent_perms(tp->a_perm & mask, perm);
			(void) printf("#effective:%s\n", perm);
			break;
		case GROUP_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("group::%s\t\t", perm);
			aclent_perms(tp->a_perm & mask, perm);
			(void) printf("#effective:%s\n", perm);
			break;
		case CLASS_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("mask:%s\n", perm);
			break;
		case OTHER_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("other:%s\n", perm);
			break;
		case DEF_USER:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:user:%s:%s\n",
			    pruname(tp->a_id, uidp, sizeof (uidp), 0), perm);
			break;
		case DEF_USER_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:user::%s\n", perm);
			break;
		case DEF_GROUP:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:group:%s:%s\n",
			    prgname(tp->a_id, gidp, sizeof (gidp), 0), perm);
			break;
		case DEF_GROUP_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:group::%s\n", perm);
			break;
		case DEF_CLASS_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:mask:%s\n", perm);
			break;
		case DEF_OTHER_OBJ:
			aclent_perms(tp->a_perm, perm);
			(void) printf("default:other:%s\n", perm);
			break;
		default:
			(void) fprintf(stderr,
			    dgettext(TEXT_DOMAIN, "unrecognized entry\n"));
			break;
		}
	}
}

static void
split_line(char *str, int cols)
{
	char *ptr;
	int len;
	int i;
	int last_split;
	char *pad = "";
	int pad_len;

	len = strlen(str);
	ptr = str;
	pad_len = 0;

	ptr = str;
	last_split = 0;
	for (i = 0; i != len; i++) {
		if ((i + pad_len + 4) >= cols) {
			(void) printf("%s%.*s\n", pad, last_split, ptr);
			ptr = &ptr[last_split];
			len = strlen(ptr);
			i = 0;
			pad_len = 4;
			pad = "         ";
		} else {
			if (ptr[i] == '/' || ptr[i] == ':') {
				last_split = i;
			}
		}
	}
	if (i == len) {
		(void) printf("%s%s\n", pad, ptr);
	}
}

char *
ace_type_txt(char *buf, char **endp, ace_t *acep, int flags)
{

	char idp[ID_STR_MAX];

	if (buf == NULL)
		return (NULL);

	switch (acep->a_flags & ACE_TYPE_FLAGS) {
	case ACE_OWNER:
		strcpy(buf, OWNERAT_TXT);
		*endp = buf + sizeof (OWNERAT_TXT) - 1;
		break;

	case ACE_GROUP|ACE_IDENTIFIER_GROUP:
		strcpy(buf, GROUPAT_TXT);
		*endp = buf + sizeof (GROUPAT_TXT) - 1;
		break;

	case ACE_IDENTIFIER_GROUP:
		strcpy(buf, GROUP_TXT);
		strcat(buf, prgname(acep->a_who, idp,
		    sizeof (idp), flags & ACL_NORESOLVE));
		*endp = buf + strlen(buf);
		break;

	case ACE_EVERYONE:
		strcpy(buf, EVERYONEAT_TXT);
		*endp = buf + sizeof (EVERYONEAT_TXT) - 1;
		break;

	case 0:
		strcpy(buf, USER_TXT);
		strcat(buf, pruname(acep->a_who, idp,
		    sizeof (idp), flags & ACL_NORESOLVE));
		*endp = buf + strlen(buf);
		break;
	}

	return (buf);
}

char *
ace_perm_txt(char *buf, char **endp, uint32_t mask,
    uint32_t iflags, int isdir, int flags)
{
	char *lend = buf;		/* local end */

	if (buf == NULL)
		return (NULL);

	if (flags & ACL_COMPACT_FMT) {

		if (mask & ACE_READ_DATA)
			buf[0] = 'r';
		else
			buf[0] = '-';
		if (mask & ACE_WRITE_DATA)
			buf[1] = 'w';
		else
			buf[1] = '-';
		if (mask & ACE_EXECUTE)
			buf[2] = 'x';
		else
			buf[2] = '-';
		if (mask & ACE_APPEND_DATA)
			buf[3] = 'p';
		else
			buf[3] = '-';
		if (mask & ACE_DELETE)
			buf[4] = 'd';
		else
			buf[4] = '-';
		if (mask & ACE_DELETE_CHILD)
			buf[5] = 'D';
		else
			buf[5] = '-';
		if (mask & ACE_READ_ATTRIBUTES)
			buf[6] = 'a';
		else
			buf[6] = '-';
		if (mask & ACE_WRITE_ATTRIBUTES)
			buf[7] = 'A';
		else
			buf[7] = '-';
		if (mask & ACE_READ_NAMED_ATTRS)
			buf[8] = 'R';
		else
			buf[8] = '-';
		if (mask & ACE_WRITE_NAMED_ATTRS)
			buf[9] = 'W';
		else
			buf[9] = '-';
		if (mask & ACE_READ_ACL)
			buf[10] = 'c';
		else
			buf[10] = '-';
		if (mask & ACE_WRITE_ACL)
			buf[11] = 'C';
		else
			buf[11] = '-';
		if (mask & ACE_WRITE_OWNER)
			buf[12] = 'o';
		else
			buf[12] = '-';
		if (mask & ACE_SYNCHRONIZE)
			buf[13] = 's';
		else
			buf[13] = '-';
		buf[14] = '\0';
		*endp = buf + 14;
		return (buf);
	} else {
		/*
		 * If ACE is a directory, but inheritance indicates its
		 * for a file then print permissions for file rather than
		 * dir.
		 */
		if (isdir) {
			if (mask & ACE_LIST_DIRECTORY) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					strcpy(lend, READ_DATA_TXT);
					lend += sizeof (READ_DATA_TXT) - 1;
				} else {
					strcpy(lend, READ_DIR_TXT);
					lend += sizeof (READ_DIR_TXT) - 1;
				}
			}
			if (mask & ACE_ADD_FILE) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					strcpy(lend, WRITE_DATA_TXT);
					lend += sizeof (WRITE_DATA_TXT) - 1;
				} else {
					strcpy(lend, ADD_FILE_TXT);
					lend +=
					    sizeof (ADD_FILE_TXT) -1;
				}
			}
			if (mask & ACE_ADD_SUBDIRECTORY) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					strcpy(lend, APPEND_DATA_TXT);
					lend += sizeof (APPEND_DATA_TXT) - 1;
				} else {
					strcpy(lend, ADD_DIR_TXT);
					lend += sizeof (ADD_DIR_TXT) - 1;
				}
			}
		} else {
			if (mask & ACE_READ_DATA) {
				strcpy(lend, READ_DATA_TXT);
				lend += sizeof (READ_DATA_TXT) - 1;
			}
			if (mask & ACE_WRITE_DATA) {
				strcpy(lend, WRITE_DATA_TXT);
				lend += sizeof (WRITE_DATA_TXT) - 1;
			}
			if (mask & ACE_APPEND_DATA) {
				strcpy(lend, APPEND_DATA_TXT);
				lend += sizeof (APPEND_DATA_TXT) - 1;
			}
		}
		if (mask & ACE_READ_NAMED_ATTRS) {
			strcpy(lend, READ_XATTR_TXT);
			lend += sizeof (READ_XATTR_TXT) - 1;
		}
		if (mask & ACE_WRITE_NAMED_ATTRS) {
			strcpy(lend, WRITE_XATTR_TXT);
			lend += sizeof (WRITE_XATTR_TXT) - 1;
		}
		if (mask & ACE_EXECUTE) {
			strcpy(lend, EXECUTE_TXT);
			lend += sizeof (EXECUTE_TXT) - 1;
		}
		if (mask & ACE_DELETE_CHILD) {
			strcpy(lend, DELETE_CHILD_TXT);
			lend += sizeof (DELETE_CHILD_TXT) - 1;
		}
		if (mask & ACE_READ_ATTRIBUTES) {
			strcpy(lend, READ_ATTRIBUTES_TXT);
			lend += sizeof (READ_ATTRIBUTES_TXT) - 1;
		}
		if (mask & ACE_WRITE_ATTRIBUTES) {
			strcpy(lend, WRITE_ATTRIBUTES_TXT);
			lend += sizeof (WRITE_ATTRIBUTES_TXT) - 1;
		}
		if (mask & ACE_DELETE) {
			strcpy(lend, DELETE_TXT);
			lend += sizeof (DELETE_TXT) - 1;
		}
		if (mask & ACE_READ_ACL) {
			strcpy(lend, READ_ACL_TXT);
			lend += sizeof (READ_ACL_TXT) - 1;
		}
		if (mask & ACE_WRITE_ACL) {
			strcpy(lend, WRITE_ACL_TXT);
			lend += sizeof (WRITE_ACL_TXT) - 1;
		}
		if (mask & ACE_WRITE_OWNER) {
			strcpy(lend, WRITE_OWNER_TXT);
			lend += sizeof (WRITE_OWNER_TXT) - 1;
		}
		if (mask & ACE_SYNCHRONIZE) {
			strcpy(lend, SYNCHRONIZE_TXT);
			lend += sizeof (SYNCHRONIZE_TXT) - 1;
		}

		if (*(lend - 1) == '/')
			*--lend = '\0';
	}

	*endp = lend;
	return (buf);
}

char *
ace_access_txt(char *buf, char **endp, int type)
{

	if (buf == NULL)
		return (NULL);

	if (type == ACE_ACCESS_ALLOWED_ACE_TYPE) {
		strcpy(buf, ALLOW_TXT);
		*endp += sizeof (ALLOW_TXT) - 1;
	} else if (type == ACE_ACCESS_DENIED_ACE_TYPE) {
		strcpy(buf, DENY_TXT);
		*endp += sizeof (DENY_TXT) - 1;
	} else if (type == ACE_SYSTEM_AUDIT_ACE_TYPE) {
		strcpy(buf, AUDIT_TXT);
		*endp += sizeof (AUDIT_TXT) - 1;
	} else if (type == ACE_SYSTEM_ALARM_ACE_TYPE) {
		strcpy(buf, ALARM_TXT);
		*endp += sizeof (ALARM_TXT) - 1;
	} else {
		strcpy(buf, UNKNOWN_TXT);
		*endp += sizeof (UNKNOWN_TXT) - 1;
	}

	return (buf);
}

static char *
ace_inherit_txt(char *buf, char **endp, uint32_t iflags, int flags)
{

	char *lend = buf;

	if (buf == NULL) {
		return (NULL);
	}

	if (flags & ACL_COMPACT_FMT) {
		if (iflags & ACE_FILE_INHERIT_ACE)
			buf[0] = 'f';
		else
			buf[0] = '-';
		if (iflags & ACE_DIRECTORY_INHERIT_ACE)
			buf[1] = 'd';
		else
			buf[1] = '-';
		if (iflags & ACE_INHERIT_ONLY_ACE)
			buf[2] = 'i';
		else
			buf[2] = '-';
		if (iflags & ACE_NO_PROPAGATE_INHERIT_ACE)
			buf[3] = 'n';
		else
			buf[3] = '-';
		if (iflags & ACE_SUCCESSFUL_ACCESS_ACE_FLAG)
			buf[4] = 'S';
		else
			buf[4] = '-';
		if (iflags & ACE_FAILED_ACCESS_ACE_FLAG)
			buf[5] = 'F';
		else
			buf[5] = '-';
		if (iflags & ACE_INHERITED_ACE)
			buf[6] = 'I';
		else
			buf[6] = '-';
		buf[7] = '\0';
		*endp = buf + 7;
	} else {
		if (iflags & ACE_FILE_INHERIT_ACE) {
			strcpy(lend, "file_inherit/");
			lend += sizeof ("file_inherit/") - 1;
		}
		if (iflags & ACE_DIRECTORY_INHERIT_ACE) {
			strcpy(lend, "dir_inherit/");
			lend += sizeof ("dir_inherit/") - 1;
		}
		if (iflags & ACE_NO_PROPAGATE_INHERIT_ACE) {
			strcpy(lend, "no_propagate/");
			lend += sizeof ("no_propagate/") - 1;
		}
		if (iflags & ACE_INHERIT_ONLY_ACE) {
			strcpy(lend, "inherit_only/");
			lend += sizeof ("inherit_only/") - 1;
		}
		if (iflags & ACE_SUCCESSFUL_ACCESS_ACE_FLAG) {
			strcpy(lend, "successful_access/");
			lend += sizeof ("successful_access/") - 1;
		}
		if (iflags & ACE_FAILED_ACCESS_ACE_FLAG) {
			strcpy(lend, "failed_access/");
			lend += sizeof ("failed_access/") - 1;
		}
		if (iflags & ACE_INHERITED_ACE) {
			strcpy(lend, "inherited/");
			lend += sizeof ("inherited/") - 1;
		}

		if (*(lend - 1) == '/')
			*--lend = '\0';
		*endp = lend;
	}

	return (buf);
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

/*
 * acltotext() converts each ACL entry to look like this:
 *
 *    entry_type:uid^gid^name:perms[:id]
 *
 * The maximum length of entry_type is 14 ("defaultgroup::" and
 * "defaultother::") hence ENTRYTYPELEN is set to 14.
 *
 * The max length of a uid^gid^name entry (in theory) is 8, hence we use,
 * however the ID could be a number so we therefore use ID_STR_MAX
 *
 * The length of a perms entry is 4 to allow for the comma appended to each
 * to each acl entry.  Hence PERMS is set to 4.
 */

#define	ENTRYTYPELEN	14
#define	PERMS		4
#define	ACL_ENTRY_SIZE	(ENTRYTYPELEN + ID_STR_MAX + PERMS + APPENDED_ID_MAX)
#define	UPDATE_WHERE	where = dstr->aclexport + strlen(dstr->aclexport)

char *
aclent_acltotext(aclent_t  *aclp, int aclcnt, int flags)
{
	char		*aclexport;
	char		*where;
	struct group	*groupp = NULL;
	struct passwd	*passwdp = NULL;
	struct dynaclstr *dstr;
	int		i, rtn;
	size_t		excess = 0;
	char		id[ID_STR_MAX], *idstr;

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
			if ((flags & ACL_NORESOLVE) == 0)
				passwdp = getpwuid(aclp->a_id);
			if (passwdp == (struct passwd *)NULL) {
				/* put in uid instead */
				(void) sprintf(where, "%d", aclp->a_id);
				UPDATE_WHERE;
			} else {
				excess = strlen(passwdp->pw_name) - LOGNAME_MAX;
				if (excess > 0) {
					rtn = increase_length(dstr, excess);
					if (rtn == 1) {
						UPDATE_WHERE;
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
			if ((flags & ACL_NORESOLVE) == 0)
				groupp = getgrgid(aclp->a_id);
			if (groupp == (struct group *)NULL) {
				/* put in gid instead */
				(void) sprintf(where, "%d", aclp->a_id);
				UPDATE_WHERE;
			} else {
				excess = strlen(groupp->gr_name) - LOGNAME_MAX;
				if (excess > 0) {
					rtn = increase_length(dstr, excess);
					if (rtn == 1) {
						UPDATE_WHERE;
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

		if ((flags & ACL_APPEND_ID) && ((aclp->a_type == USER) ||
		    (aclp->a_type == DEF_USER) || (aclp->a_type == GROUP) ||
		    (aclp->a_type == DEF_GROUP))) {
			where = strappend(where, ":");
			id[ID_STR_MAX - 1] = '\0'; /* null terminate buffer */
			idstr = lltostr(aclp->a_id, &id[ID_STR_MAX - 1]);
			where = strappend(where, idstr);
		}
		if (i < aclcnt - 1)
			where = strappend(where, ",");
	}
	aclexport = dstr->aclexport;
	free(dstr);
	return (aclexport);




}

char *
acltotext(aclent_t *aclp, int aclcnt)
{
	return (aclent_acltotext(aclp, aclcnt, 0));
}


aclent_t *
aclfromtext(char *aclstr, int *aclcnt)
{
	acl_t *aclp;
	aclent_t *aclentp;
	int error;

	error = acl_fromtext(aclstr, &aclp);
	if (error)
		return (NULL);

	aclentp = aclp->acl_aclp;
	aclp->acl_aclp = NULL;
	*aclcnt = aclp->acl_cnt;

	acl_free(aclp);
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
	if (perm & S_IROTH)
		where = strappend(where, "r");
	else
		where = strappend(where, "-");
	if (perm & S_IWOTH)
		where = strappend(where, "w");
	else
		where = strappend(where, "-");
	if (perm & S_IXOTH)
		where = strappend(where, "x");
	else
		where = strappend(where, "-");
	/* perm is the last field */
	return (where);
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
 * ace_acltotext() convert each ace formatted acl to look like this:
 *
 * entry_type:uid^gid^name:perms[:flags]:<allow|deny>[:id][,]
 *
 * The maximum length of entry_type is 5 ("group")
 *
 * The max length of a uid^gid^name entry (in theory) is 8,
 * however id could be a number so we therefore use ID_STR_MAX
 *
 * The length of a perms entry is 144 i.e read_data/write_data...
 * to each acl entry.
 *
 * iflags: file_inherit/dir_inherit/inherit_only/no_propagate/successful_access
 *         /failed_access
 *
 */

#define	ACE_ENTRYTYPLEN		6
#define	IFLAGS_STR "file_inherit/dir_inherit/inherit_only/no_propagate/" \
	"successful_access/failed_access/inherited"
#define	IFLAGS_SIZE		(sizeof (IFLAGS_STR) - 1)
#define	ACCESS_TYPE_SIZE	7	/* if unknown */
#define	COLON_CNT		3
#define	PERMS_LEN		216
#define	ACE_ENTRY_SIZE	(ACE_ENTRYTYPLEN + ID_STR_MAX + PERMS_LEN + \
    ACCESS_TYPE_SIZE + IFLAGS_SIZE + COLON_CNT + APPENDED_ID_MAX)

static char *
ace_acltotext(acl_t *aceaclp, int flags)
{
	ace_t		*aclp = aceaclp->acl_aclp;
	int		aclcnt = aceaclp->acl_cnt;
	char		*aclexport;
	char		*endp;
	int		i;
	char		id[ID_STR_MAX], *idstr;
	int		isdir = (aceaclp->acl_flags & ACL_IS_DIR);

	if (aclp == NULL)
		return (NULL);
	if ((aclexport = malloc(aclcnt * ACE_ENTRY_SIZE)) == NULL)
		return (NULL);

	aclexport[0] = '\0';
	endp = aclexport;
	for (i = 0; i < aclcnt; i++, aclp++) {

		(void) ace_type_txt(endp, &endp, aclp, flags);
		*endp++ = ':';
		*endp = '\0';
		(void) ace_perm_txt(endp, &endp, aclp->a_access_mask,
		    aclp->a_flags, isdir, flags);
		*endp++ = ':';
		*endp = '\0';
		(void) ace_inherit_txt(endp, &endp, aclp->a_flags, flags);
		if (flags & ACL_COMPACT_FMT || aclp->a_flags &
		    (ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE |
		    (ACE_INHERIT_ONLY_ACE | ACE_NO_PROPAGATE_INHERIT_ACE |
		    ACE_INHERITED_ACE | ACE_SUCCESSFUL_ACCESS_ACE_FLAG |
		    ACE_FAILED_ACCESS_ACE_FLAG))) {
			*endp++ = ':';
			*endp = '\0';
		}
		(void) ace_access_txt(endp, &endp, aclp->a_type);

		if ((flags & ACL_APPEND_ID) &&
		    (((aclp->a_flags & ACE_TYPE_FLAGS) == 0) ||
		    ((aclp->a_flags & ACE_TYPE_FLAGS) ==
		    ACE_IDENTIFIER_GROUP))) {
			*endp++ = ':';
			*endp = '\0';
			id[ID_STR_MAX -1] = '\0'; /* null terminate buffer */
			idstr = lltostr(aclp->a_who, &id[ID_STR_MAX - 1]);
			strcpy(endp, idstr);
			endp += strlen(idstr);
		}
		if (i < aclcnt - 1) {
			*endp++ = ',';
			*(endp + 1) = '\0';
		}
	}
	return (aclexport);
}

char *
acl_totext(acl_t *aclp, int flags)
{

	char *txtp;

	if (aclp == NULL)
		return (NULL);

	switch (aclp->acl_type) {
	case ACE_T:
		txtp = ace_acltotext(aclp, flags);
		break;
	case ACLENT_T:
		txtp = aclent_acltotext(aclp->acl_aclp, aclp->acl_cnt, flags);
		break;
	}

	return (txtp);
}

int
acl_fromtext(const char *acltextp, acl_t **ret_aclp)
{
	int error;
	char *buf;

	buf = malloc(strlen(acltextp) + 2);
	if (buf == NULL)
		return (EACL_MEM_ERROR);
	strcpy(buf, acltextp);
	strcat(buf, "\n");
	yybuf = buf;
	yyreset();
	error = yyparse();
	free(buf);

	if (yyacl) {
		if (error == 0)
			*ret_aclp = yyacl;
		else {
			acl_free(yyacl);
		}
		yyacl = NULL;
	}
	return (error);
}

int
acl_parse(const char *acltextp, acl_t **aclp)
{
	int error;

	yyinteractive = 1;
	error = acl_fromtext(acltextp, aclp);
	yyinteractive = 0;
	return (error);
}

static void
ace_compact_printacl(acl_t *aclp)
{
	int cnt;
	ace_t *acep;
	char *endp;
	char buf[ACE_ENTRY_SIZE];

	for (cnt = 0, acep = aclp->acl_aclp;
	    cnt != aclp->acl_cnt; cnt++, acep++) {
		buf[0] = '\0';
		(void) printf("    %14s:", ace_type_txt(buf, &endp, acep, 0));
		(void) printf("%s:", ace_perm_txt(endp, &endp,
		    acep->a_access_mask, acep->a_flags,
		    aclp->acl_flags & ACL_IS_DIR, ACL_COMPACT_FMT));
		(void) printf("%s:",
		    ace_inherit_txt(endp, &endp, acep->a_flags,
		    ACL_COMPACT_FMT));
		(void) printf("%s\n", ace_access_txt(endp, &endp,
		    acep->a_type));
	}
}

static void
ace_printacl(acl_t *aclp, int cols, int compact)
{
	int  slot = 0;
	char *token;
	char *acltext;

	if (compact) {
		ace_compact_printacl(aclp);
		return;
	}

	acltext = acl_totext(aclp, 0);

	if (acltext == NULL)
		return;

	token = strtok(acltext, ",");
	if (token == NULL) {
		free(acltext);
		return;
	}

	do {
		(void) printf("     %d:", slot++);
		split_line(token, cols - 5);
	} while (token = strtok(NULL, ","));
	free(acltext);
}

/*
 * pretty print an ACL.
 * For aclent_t ACL's the format is
 * similar to the old format used by getfacl,
 * with the addition of adding a "slot" number
 * before each entry.
 *
 * for ace_t ACL's the cols variable will break up
 * the long lines into multiple lines and will also
 * print a "slot" number.
 */
void
acl_printacl(acl_t *aclp, int cols, int compact)
{

	switch (aclp->acl_type) {
	case ACLENT_T:
		aclent_printacl(aclp);
		break;
	case ACE_T:
		ace_printacl(aclp, cols, compact);
		break;
	}
}

typedef struct value_table {
	char		p_letter; /* perm letter such as 'r' */
	uint32_t	p_value; /* value for perm when pletter found */
} value_table_t;

/*
 * The permission tables are laid out in positional order
 * a '-' character will indicate a permission at a given
 * position is not specified.  The '-' is not part of the
 * table, but will be checked for in the permission computation
 * routine.
 */
value_table_t ace_perm_table[] = {
	{ 'r', ACE_READ_DATA},
	{ 'w', ACE_WRITE_DATA},
	{ 'x', ACE_EXECUTE},
	{ 'p', ACE_APPEND_DATA},
	{ 'd', ACE_DELETE},
	{ 'D', ACE_DELETE_CHILD},
	{ 'a', ACE_READ_ATTRIBUTES},
	{ 'A', ACE_WRITE_ATTRIBUTES},
	{ 'R', ACE_READ_NAMED_ATTRS},
	{ 'W', ACE_WRITE_NAMED_ATTRS},
	{ 'c', ACE_READ_ACL},
	{ 'C', ACE_WRITE_ACL},
	{ 'o', ACE_WRITE_OWNER},
	{ 's', ACE_SYNCHRONIZE}
};

#define	ACE_PERM_COUNT (sizeof (ace_perm_table) / sizeof (value_table_t))

value_table_t aclent_perm_table[] = {
	{ 'r', S_IROTH},
	{ 'w', S_IWOTH},
	{ 'x', S_IXOTH}
};

#define	ACLENT_PERM_COUNT (sizeof (aclent_perm_table) / sizeof (value_table_t))

value_table_t inherit_table[] = {
	{'f', ACE_FILE_INHERIT_ACE},
	{'d', ACE_DIRECTORY_INHERIT_ACE},
	{'i', ACE_INHERIT_ONLY_ACE},
	{'n', ACE_NO_PROPAGATE_INHERIT_ACE},
	{'S', ACE_SUCCESSFUL_ACCESS_ACE_FLAG},
	{'F', ACE_FAILED_ACCESS_ACE_FLAG},
	{'I', ACE_INHERITED_ACE}
};

#define	IFLAG_COUNT (sizeof (inherit_table) / sizeof (value_table_t))

/*
 * compute value from a permission table or inheritance table
 * based on string passed in.  If positional is set then
 * string must match order in permtab, otherwise any order
 * is allowed.
 */
int
compute_values(value_table_t *permtab, int count,
    char *permstr, int positional, uint32_t *mask)
{
	uint32_t perm_val = 0;
	char *pstr;
	int i, found;

	if (count < 0)
		return (1);

	if (positional) {
		for (i = 0, pstr = permstr; i != count && pstr &&
		    *pstr; i++, pstr++) {
			if (*pstr == permtab[i].p_letter) {
				perm_val |= permtab[i].p_value;
			} else if (*pstr != '-') {
				return (1);
			}
		}
	} else {  /* random order single letters with no '-' */
		for (pstr = permstr; pstr && *pstr; pstr++) {
			for (found = 0, i = 0; i != count; i++) {
				if (*pstr == permtab[i].p_letter) {
					perm_val |= permtab[i].p_value;
					found = 1;
					break;
				}
			}
			if (found == 0)
				return (1);
		}
	}

	*mask = perm_val;
	return (0);
}

/*
 * compute value for inheritance flags.
 */
int
compute_ace_inherit(char *str, uint32_t *imask)
{
	int error;
	int positional = 0;

	if (strlen(str) == IFLAG_COUNT)
		positional = 1;

	error = compute_values(inherit_table, IFLAG_COUNT,
	    str, positional, imask);

	if (error)
		return (EACL_INHERIT_ERROR);

	return (error);
}


/*
 * compute value for ACE permissions.
 */
int
compute_ace_perms(char *str, uint32_t *mask)
{
	int positional = 0;
	int error;

	if (strlen(str) == ACE_PERM_COUNT)
		positional = 1;

	error = compute_values(ace_perm_table, ACE_PERM_COUNT,
	    str, positional, mask);

	if (error && positional) {
		/*
		 * If positional was set, then make sure permissions
		 * aren't actually valid in non positional case where
		 * all permissions are specified, just in random order.
		 */
		error = compute_values(ace_perm_table,
		    ACE_PERM_COUNT, str, 0, mask);
	}
	if (error)
		error = EACL_PERM_MASK_ERROR;

	return (error);
}



/*
 * compute values for aclent permissions.
 */
int
compute_aclent_perms(char *str, o_mode_t *mask)
{
	int error;
	uint32_t pmask;

	if (strlen(str) != ACLENT_PERM_COUNT)
		return (EACL_PERM_MASK_ERROR);

	*mask = 0;
	error = compute_values(aclent_perm_table, ACLENT_PERM_COUNT,
	    str, 1, &pmask);
	if (error == 0) {
		*mask = (o_mode_t)pmask;
	} else
		error = EACL_PERM_MASK_ERROR;
	return (error);
}

/*
 * determine ACE permissions.
 */
int
ace_perm_mask(struct acl_perm_type *aclperm, uint32_t *mask)
{
	int error;

	if (aclperm->perm_style == PERM_TYPE_EMPTY) {
		*mask = 0;
		return (0);
	}

	if (aclperm->perm_style == PERM_TYPE_ACE) {
		*mask = aclperm->perm_val;
		return (0);
	}

	error = compute_ace_perms(aclperm->perm_str, mask);
	if (error) {
		acl_error(dgettext(TEXT_DOMAIN,
		    "Invalid permission(s) '%s' specified\n"),
		    aclperm->perm_str);
		return (EACL_PERM_MASK_ERROR);
	}

	return (0);
}
