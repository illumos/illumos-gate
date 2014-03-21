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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

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
#include <idmap.h>
#include <synch.h>

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
mutex_t	yymutex;

extern acl_t *acl_alloc(enum acl_type);

/*
 * dynamic string that will increase in size on an
 * as needed basis.
 */
typedef struct dynaclstr {
	size_t d_bufsize;		/* current size of aclexport */
	char *d_aclexport;
	int d_pos;
} dynaclstr_t;

static int str_append(dynaclstr_t *, char *);
static int aclent_perm_txt(dynaclstr_t *, o_mode_t);

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

static int
getsidname(uid_t who, boolean_t user, char **sidp, boolean_t noresolve)
{
	idmap_get_handle_t *get_hdl = NULL;
	idmap_stat status;
	idmap_rid_t rid;
	int error = IDMAP_ERR_NORESULT;
	int len;
	char *domain = NULL;

	*sidp = NULL;

	/*
	 * First try and get windows name
	 */

	if (!noresolve) {
		if (user)
			error = idmap_getwinnamebyuid(who,
			    IDMAP_REQ_FLG_USE_CACHE, sidp, NULL);
		else
			error = idmap_getwinnamebygid(who,
			    IDMAP_REQ_FLG_USE_CACHE, sidp, NULL);
	}
	if (error != IDMAP_SUCCESS) {
		if (idmap_get_create(&get_hdl) == IDMAP_SUCCESS) {
			if (user)
				error = idmap_get_sidbyuid(get_hdl, who,
				    IDMAP_REQ_FLG_USE_CACHE, &domain, &rid,
				    &status);
			else
				error = idmap_get_sidbygid(get_hdl, who,
				    IDMAP_REQ_FLG_USE_CACHE, &domain, &rid,
				    &status);
			if (error == IDMAP_SUCCESS &&
			    idmap_get_mappings(get_hdl) == 0) {
				if (status == IDMAP_SUCCESS) {
					len = snprintf(NULL, 0,
					    "%s-%d", domain, rid);
					if (*sidp = malloc(len + 1)) {
						(void) snprintf(*sidp, len + 1,
						    "%s-%d", domain, rid);
					}
				}
			}
		}
		if (get_hdl)
			idmap_get_destroy(get_hdl);
	}

	free(domain);

	return (*sidp ? 0 : 1);
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

/*
 * compute entry type string, such as user:joe, group:staff,...
 */
static int
aclent_type_txt(dynaclstr_t *dstr, aclent_t *aclp, int flags)
{
	char idp[ID_STR_MAX];
	int error;

	switch (aclp->a_type) {
	case DEF_USER_OBJ:
	case USER_OBJ:
		if (aclp->a_type == USER_OBJ)
			error = str_append(dstr, "user::");
		else
			error = str_append(dstr, "defaultuser::");
		break;

	case DEF_USER:
	case USER:
		if (aclp->a_type == USER)
			error = str_append(dstr, "user:");
		else
			error = str_append(dstr, "defaultuser:");
		if (error)
			break;
		error = str_append(dstr, pruname(aclp->a_id, idp,
		    sizeof (idp), flags & ACL_NORESOLVE));
		if (error == 0)
			error = str_append(dstr, ":");
		break;

	case DEF_GROUP_OBJ:
	case GROUP_OBJ:
		if (aclp->a_type == GROUP_OBJ)
			error = str_append(dstr, "group::");
		else
			error = str_append(dstr, "defaultgroup::");
		break;

	case DEF_GROUP:
	case GROUP:
		if (aclp->a_type == GROUP)
			error = str_append(dstr, "group:");
		else
			error = str_append(dstr, "defaultgroup:");
		if (error)
			break;
		error = str_append(dstr, prgname(aclp->a_id, idp,
		    sizeof (idp), flags & ACL_NORESOLVE));
		if (error == 0)
			error = str_append(dstr, ":");
		break;

	case DEF_CLASS_OBJ:
	case CLASS_OBJ:
		if (aclp->a_type == CLASS_OBJ)
			error = str_append(dstr, "mask:");
		else
			error = str_append(dstr, "defaultmask:");
		break;

	case DEF_OTHER_OBJ:
	case OTHER_OBJ:
		if (aclp->a_type == OTHER_OBJ)
			error = str_append(dstr, "other:");
		else
			error = str_append(dstr, "defaultother:");
		break;

	default:
		error = 1;
		break;
	}

	return (error);
}

/*
 * compute entry type string such as, owner@:, user:joe, group:staff,...
 */
static int
ace_type_txt(dynaclstr_t *dynstr, ace_t *acep, int flags)
{
	char idp[ID_STR_MAX];
	int error;
	char *sidp = NULL;

	switch (acep->a_flags & ACE_TYPE_FLAGS) {
	case ACE_OWNER:
		error = str_append(dynstr, OWNERAT_TXT);
		break;

	case ACE_GROUP|ACE_IDENTIFIER_GROUP:
		error = str_append(dynstr, GROUPAT_TXT);
		break;

	case ACE_IDENTIFIER_GROUP:
		if ((flags & ACL_SID_FMT) && acep->a_who > MAXUID) {
			if (error = str_append(dynstr,
			    GROUPSID_TXT))
				break;
			if (error = getsidname(acep->a_who, B_FALSE,
			    &sidp, flags & ACL_NORESOLVE))
				break;
			error = str_append(dynstr, sidp);
		} else {
			if (error = str_append(dynstr, GROUP_TXT))
				break;
			error = str_append(dynstr, prgname(acep->a_who, idp,
			    sizeof (idp), flags & ACL_NORESOLVE));
		}
		if (error == 0)
			error = str_append(dynstr, ":");
		break;

	case ACE_EVERYONE:
		error = str_append(dynstr, EVERYONEAT_TXT);
		break;

	case 0:
		if ((flags & ACL_SID_FMT) && acep->a_who > MAXUID) {
			if (error = str_append(dynstr, USERSID_TXT))
				break;
			if (error = getsidname(acep->a_who, B_TRUE,
			    &sidp, flags & ACL_NORESOLVE))
				break;
			error = str_append(dynstr, sidp);
		} else {
			if (error = str_append(dynstr, USER_TXT))
				break;
			error = str_append(dynstr, pruname(acep->a_who, idp,
			    sizeof (idp), flags & ACL_NORESOLVE));
		}
		if (error == 0)
			error = str_append(dynstr, ":");
		break;
	default:
		error = 0;
		break;
	}

	if (sidp)
		free(sidp);
	return (error);
}

/*
 * compute string of permissions, such as read_data/write_data or
 * rwxp,...
 * The format depends on the flags field which indicates whether the compact
 * or verbose format should be used.
 */
static int
ace_perm_txt(dynaclstr_t *dstr, uint32_t mask,
    uint32_t iflags, int isdir, int flags)
{
	int error = 0;

	if (flags & ACL_COMPACT_FMT) {
		char buf[16];

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
		buf[14] = ':';
		buf[15] = '\0';
		error = str_append(dstr, buf);
	} else {
		/*
		 * If ACE is a directory, but inheritance indicates its
		 * for a file then print permissions for file rather than
		 * dir.
		 */
		if (isdir) {
			if (mask & ACE_LIST_DIRECTORY) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					error = str_append(dstr,
					    READ_DATA_TXT);
				} else {
					error =
					    str_append(dstr, READ_DIR_TXT);
				}
			}
			if (error == 0 && (mask & ACE_ADD_FILE)) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					error =
					    str_append(dstr, WRITE_DATA_TXT);
				} else {
					error =
					    str_append(dstr, ADD_FILE_TXT);
				}
			}
			if (error == 0 && (mask & ACE_ADD_SUBDIRECTORY)) {
				if (iflags == ACE_FILE_INHERIT_ACE) {
					error = str_append(dstr,
					    APPEND_DATA_TXT);
				} else {
					error = str_append(dstr,
					    ADD_DIR_TXT);
				}
			}
		} else {
			if (mask & ACE_READ_DATA) {
				error = str_append(dstr, READ_DATA_TXT);
			}
			if (error == 0 && (mask & ACE_WRITE_DATA)) {
				error = str_append(dstr, WRITE_DATA_TXT);
			}
			if (error == 0 && (mask & ACE_APPEND_DATA)) {
				error = str_append(dstr, APPEND_DATA_TXT);
			}
		}
		if (error == 0 && (mask & ACE_READ_NAMED_ATTRS)) {
			error = str_append(dstr, READ_XATTR_TXT);
		}
		if (error == 0 && (mask & ACE_WRITE_NAMED_ATTRS)) {
			error = str_append(dstr, WRITE_XATTR_TXT);
		}
		if (error == 0 && (mask & ACE_EXECUTE)) {
			error = str_append(dstr, EXECUTE_TXT);
		}
		if (error == 0 && (mask & ACE_DELETE_CHILD)) {
			error = str_append(dstr, DELETE_CHILD_TXT);
		}
		if (error == 0 && (mask & ACE_READ_ATTRIBUTES)) {
			error = str_append(dstr, READ_ATTRIBUTES_TXT);
		}
		if (error == 0 && (mask & ACE_WRITE_ATTRIBUTES)) {
			error = str_append(dstr, WRITE_ATTRIBUTES_TXT);
		}
		if (error == 0 && (mask & ACE_DELETE)) {
			error = str_append(dstr, DELETE_TXT);
		}
		if (error == 0 && (mask & ACE_READ_ACL)) {
			error = str_append(dstr, READ_ACL_TXT);
		}
		if (error == 0 && (mask & ACE_WRITE_ACL)) {
			error = str_append(dstr, WRITE_ACL_TXT);
		}
		if (error == 0 && (mask & ACE_WRITE_OWNER)) {
			error = str_append(dstr, WRITE_OWNER_TXT);
		}
		if (error == 0 && (mask & ACE_SYNCHRONIZE)) {
			error = str_append(dstr, SYNCHRONIZE_TXT);
		}
		if (error == 0 && dstr->d_aclexport[dstr->d_pos-1] == '/') {
			dstr->d_aclexport[--dstr->d_pos] = '\0';
		}
		if (error == 0)
			error = str_append(dstr, ":");
	}
	return (error);
}

/*
 * compute string of access type, such as allow, deny, ...
 */
static int
ace_access_txt(dynaclstr_t *dstr, int type)
{
	int error;

	if (type == ACE_ACCESS_ALLOWED_ACE_TYPE)
		error = str_append(dstr, ALLOW_TXT);
	else if (type == ACE_ACCESS_DENIED_ACE_TYPE)
		error = str_append(dstr, DENY_TXT);
	else if (type == ACE_SYSTEM_AUDIT_ACE_TYPE)
		error = str_append(dstr, AUDIT_TXT);
	else if (type == ACE_SYSTEM_ALARM_ACE_TYPE)
		error = str_append(dstr, ALARM_TXT);
	else
		error = str_append(dstr, UNKNOWN_TXT);

	return (error);
}

static int
ace_inherit_txt(dynaclstr_t *dstr, uint32_t iflags, int flags)
{
	int error = 0;

	if (flags & ACL_COMPACT_FMT) {
		char buf[9];

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
		buf[7] = ':';
		buf[8] = '\0';
		error = str_append(dstr, buf);
	} else {
		if (iflags & ACE_FILE_INHERIT_ACE) {
			error = str_append(dstr, FILE_INHERIT_TXT);
		}
		if (error == 0 && (iflags & ACE_DIRECTORY_INHERIT_ACE)) {
			error = str_append(dstr, DIR_INHERIT_TXT);
		}
		if (error == 0 && (iflags & ACE_NO_PROPAGATE_INHERIT_ACE)) {
			error = str_append(dstr, NO_PROPAGATE_TXT);
		}
		if (error == 0 && (iflags & ACE_INHERIT_ONLY_ACE)) {
			error = str_append(dstr, INHERIT_ONLY_TXT);
		}
		if (error == 0 && (iflags & ACE_SUCCESSFUL_ACCESS_ACE_FLAG)) {
			error = str_append(dstr, SUCCESSFUL_ACCESS_TXT);
		}
		if (error == 0 && (iflags & ACE_FAILED_ACCESS_ACE_FLAG)) {
			error = str_append(dstr, FAILED_ACCESS_TXT);
		}
		if (error == 0 && (iflags & ACE_INHERITED_ACE)) {
			error = str_append(dstr, INHERITED_ACE_TXT);
		}
		if (error == 0 && dstr->d_aclexport[dstr->d_pos-1] == '/') {
			dstr->d_aclexport[--dstr->d_pos] = '\0';
			error = str_append(dstr, ":");
		}
	}

	return (error);
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

char *
aclent_acltotext(aclent_t  *aclp, int aclcnt, int flags)
{
	dynaclstr_t 	*dstr;
	char		*aclexport = NULL;
	int		i;
	int 		error = 0;

	if (aclp == NULL)
		return (NULL);
	if ((dstr = malloc(sizeof (dynaclstr_t))) == NULL)
		return (NULL);
	dstr->d_bufsize = aclcnt * ACL_ENTRY_SIZE;
	if ((dstr->d_aclexport = malloc(dstr->d_bufsize)) == NULL) {
		free(dstr);
		return (NULL);
	}
	*dstr->d_aclexport = '\0';
	dstr->d_pos = 0;

	for (i = 0; i < aclcnt; i++, aclp++) {
		if (error = aclent_type_txt(dstr, aclp, flags))
			break;
		if (error = aclent_perm_txt(dstr, aclp->a_perm))
			break;

		if ((flags & ACL_APPEND_ID) && ((aclp->a_type == USER) ||
		    (aclp->a_type == DEF_USER) || (aclp->a_type == GROUP) ||
		    (aclp->a_type == DEF_GROUP))) {
			char id[ID_STR_MAX], *idstr;

			if (error = str_append(dstr, ":"))
				break;
			id[ID_STR_MAX - 1] = '\0'; /* null terminate buffer */
			idstr = lltostr(aclp->a_id, &id[ID_STR_MAX - 1]);
			if (error = str_append(dstr, idstr))
				break;
		}
		if (i < aclcnt - 1)
			if (error = str_append(dstr, ","))
				break;
	}
	if (error) {
		if (dstr->d_aclexport)
			free(dstr->d_aclexport);
	} else {
		aclexport = dstr->d_aclexport;
	}
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


/*
 * Append string onto dynaclstr_t.
 *
 * Return 0 on success, 1 for failure.
 */
static int
str_append(dynaclstr_t *dstr, char *newstr)
{
	size_t len = strlen(newstr);

	if ((len + dstr->d_pos) >= dstr->d_bufsize) {
		dstr->d_aclexport = realloc(dstr->d_aclexport,
		    dstr->d_bufsize + len + 1);
		if (dstr->d_aclexport == NULL)
			return (1);
		dstr->d_bufsize += len;
	}
	(void) strcat(&dstr->d_aclexport[dstr->d_pos], newstr);
	dstr->d_pos += len;
	return (0);
}

static int
aclent_perm_txt(dynaclstr_t *dstr, o_mode_t perm)
{
	char buf[4];

	if (perm & S_IROTH)
		buf[0] = 'r';
	else
		buf[0] = '-';
	if (perm & S_IWOTH)
		buf[1] = 'w';
	else
		buf[1] = '-';
	if (perm & S_IXOTH)
		buf[2] = 'x';
	else
		buf[2] = '-';
	buf[3] = '\0';
	return (str_append(dstr, buf));
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
	int		i;
	int		error = 0;
	int		isdir = (aceaclp->acl_flags & ACL_IS_DIR);
	dynaclstr_t 	*dstr;
	char		*aclexport = NULL;
	char		*rawsidp = NULL;

	if (aclp == NULL)
		return (NULL);

	if ((dstr = malloc(sizeof (dynaclstr_t))) == NULL)
		return (NULL);
	dstr->d_bufsize = aclcnt * ACL_ENTRY_SIZE;
	if ((dstr->d_aclexport = malloc(dstr->d_bufsize)) == NULL) {
		free(dstr);
		return (NULL);
	}
	*dstr->d_aclexport = '\0';
	dstr->d_pos = 0;

	for (i = 0; i < aclcnt; i++, aclp++) {

		if (error = ace_type_txt(dstr, aclp, flags))
			break;
		if (error = ace_perm_txt(dstr, aclp->a_access_mask,
		    aclp->a_flags, isdir, flags))
			break;
		if (error = ace_inherit_txt(dstr, aclp->a_flags, flags))
			break;
		if (error = ace_access_txt(dstr, aclp->a_type))
			break;

		if ((flags & ACL_APPEND_ID) &&
		    (((aclp->a_flags & ACE_TYPE_FLAGS) == 0) ||
		    ((aclp->a_flags & ACE_TYPE_FLAGS) ==
		    ACE_IDENTIFIER_GROUP))) {
			char id[ID_STR_MAX], *idstr;

			if (error = str_append(dstr, ":"))
				break;

			rawsidp = NULL;
			id[ID_STR_MAX -1] = '\0'; /* null terminate */
			if (aclp->a_who > MAXUID && (flags & ACL_SID_FMT)) {

				error = getsidname(aclp->a_who,
				    ((aclp->a_flags & ACE_TYPE_FLAGS) == 0) ?
				    B_TRUE : B_FALSE, &idstr, 1);
				rawsidp = idstr;
				if (error)
					break;
			} else if (aclp->a_who > MAXUID &&
			    !(flags & ACL_NORESOLVE)) {
				idstr = lltostr(UID_NOBODY,
				    &id[ID_STR_MAX - 1]);
			} else {
				idstr = lltostr(aclp->a_who,
				    &id[ID_STR_MAX - 1]);
			}
			if (error = str_append(dstr, idstr))
				break;
			if (rawsidp) {
				free(rawsidp);
				rawsidp = NULL;
			}
		}
		if (i < aclcnt - 1) {
			if (error = str_append(dstr, ","))
				break;
		}
	}

	if (rawsidp)
		free(rawsidp);
	if (error) {
		if (dstr->d_aclexport)
			free(dstr->d_aclexport);
	} else {
		aclexport = dstr->d_aclexport;
	}
	free(dstr);
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

	(void) mutex_lock(&yymutex);
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
	(void) mutex_unlock(&yymutex);

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
	dynaclstr_t *dstr;
	int len;

	if ((dstr = malloc(sizeof (dynaclstr_t))) == NULL)
		return;
	dstr->d_bufsize = ACE_ENTRY_SIZE;
	if ((dstr->d_aclexport = malloc(dstr->d_bufsize)) == NULL) {
		free(dstr);
		return;
	}
	*dstr->d_aclexport = '\0';

	dstr->d_pos = 0;
	for (cnt = 0, acep = aclp->acl_aclp;
	    cnt != aclp->acl_cnt; cnt++, acep++) {
		dstr->d_aclexport[0] = '\0';
		dstr->d_pos = 0;

		if (ace_type_txt(dstr, acep, 0))
			break;
		len = strlen(&dstr->d_aclexport[0]);
		if (ace_perm_txt(dstr, acep->a_access_mask, acep->a_flags,
		    aclp->acl_flags & ACL_IS_DIR, ACL_COMPACT_FMT))
			break;
		if (ace_inherit_txt(dstr, acep->a_flags, ACL_COMPACT_FMT))
			break;
		if (ace_access_txt(dstr, acep->a_type) == -1)
			break;
		(void) printf("    %20.*s%s\n", len, dstr->d_aclexport,
		    &dstr->d_aclexport[len]);
	}

	if (dstr->d_aclexport)
		free(dstr->d_aclexport);
	free(dstr);
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
#define	IFLAG_COUNT_V1 6 /* Older version compatibility */

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


int
ace_inherit_helper(char *str, uint32_t *imask, int table_length)
{
	int rc = 0;

	if (strlen(str) == table_length) {
		/*
		 * If the string == table_length then first check to see it's
		 * in positional format.  If that fails then see if it's in
		 * non-positional format.
		 */
		if (compute_values(inherit_table, table_length, str,
		    1, imask) && compute_values(inherit_table,
		    table_length, str, 0, imask)) {
			rc = 1;
		}
	} else {
		rc = compute_values(inherit_table, table_length, str, 0, imask);
	}

	return (rc ? EACL_INHERIT_ERROR : 0);
}

/*
 * compute value for inheritance flags.
 */
int
compute_ace_inherit(char *str, uint32_t *imask)
{
	int rc = 0;

	rc = ace_inherit_helper(str, imask, IFLAG_COUNT);

	if (rc && strlen(str) != IFLAG_COUNT) {

		/* is it an old formatted inherit string? */
		rc = ace_inherit_helper(str, imask, IFLAG_COUNT_V1);
	}

	return (rc);
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
