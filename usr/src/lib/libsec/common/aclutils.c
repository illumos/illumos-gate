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
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <strings.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/varargs.h>
#include <locale.h>
#include <aclutils.h>
#include <sys/avl.h>
#include <acl_common.h>
#include <idmap.h>

#define	ACL_PATH	0
#define	ACL_FD		1


typedef union {
	const char *file;
	int  fd;
} acl_inp;


/*
 * Determine whether a file has a trivial ACL
 * returns: 	0 = trivial
 *		1 = nontrivial
 *		<0 some other system failure, such as ENOENT or EPERM
 */
int
acl_trivial(const char *filename)
{
	int acl_flavor;
	int aclcnt;
	int cntcmd;
	int val = 0;
	ace_t *acep;

	acl_flavor = pathconf(filename, _PC_ACL_ENABLED);

	if (acl_flavor == _ACL_ACE_ENABLED)
		cntcmd = ACE_GETACLCNT;
	else
		cntcmd = GETACLCNT;

	aclcnt = acl(filename, cntcmd, 0, NULL);
	if (aclcnt > 0) {
		if (acl_flavor == _ACL_ACE_ENABLED) {
			acep = malloc(sizeof (ace_t) * aclcnt);
			if (acep == NULL)
				return (-1);
			if (acl(filename, ACE_GETACL,
			    aclcnt, acep) < 0) {
				free(acep);
				return (-1);
			}

			val = ace_trivial(acep, aclcnt);
			free(acep);

		} else if (aclcnt > MIN_ACL_ENTRIES)
			val = 1;
	}
	return (val);
}


static int
cacl_get(acl_inp inp, int get_flag, int type, acl_t **aclp)
{
	const char *fname;
	int fd;
	int ace_acl = 0;
	int error;
	int getcmd, cntcmd;
	acl_t *acl_info;
	int	save_errno;
	int	stat_error;
	struct stat64 statbuf;

	*aclp = NULL;
	if (type == ACL_PATH) {
		fname = inp.file;
		ace_acl = pathconf(fname, _PC_ACL_ENABLED);
	} else {
		fd = inp.fd;
		ace_acl = fpathconf(fd, _PC_ACL_ENABLED);
	}

	/*
	 * if acl's aren't supported then
	 * send it through the old GETACL interface
	 */
	if (ace_acl == 0 || ace_acl == -1) {
		ace_acl = _ACL_ACLENT_ENABLED;
	}

	if (ace_acl & _ACL_ACE_ENABLED) {
		cntcmd = ACE_GETACLCNT;
		getcmd = ACE_GETACL;
		acl_info = acl_alloc(ACE_T);
	} else {
		cntcmd = GETACLCNT;
		getcmd = GETACL;
		acl_info = acl_alloc(ACLENT_T);
	}

	if (acl_info == NULL)
		return (-1);

	if (type == ACL_PATH) {
		acl_info->acl_cnt = acl(fname, cntcmd, 0, NULL);
	} else {
		acl_info->acl_cnt = facl(fd, cntcmd, 0, NULL);
	}

	save_errno = errno;
	if (acl_info->acl_cnt < 0) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}

	if (acl_info->acl_cnt == 0) {
		acl_free(acl_info);
		errno = save_errno;
		return (0);
	}

	acl_info->acl_aclp =
	    malloc(acl_info->acl_cnt * acl_info->acl_entry_size);
	save_errno = errno;

	if (acl_info->acl_aclp == NULL) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}

	if (type == ACL_PATH) {
		stat_error = stat64(fname, &statbuf);
		error = acl(fname, getcmd, acl_info->acl_cnt,
		    acl_info->acl_aclp);
	} else {
		stat_error = fstat64(fd, &statbuf);
		error = facl(fd, getcmd, acl_info->acl_cnt,
		    acl_info->acl_aclp);
	}

	save_errno = errno;
	if (error == -1) {
		acl_free(acl_info);
		errno = save_errno;
		return (-1);
	}


	if (stat_error == 0) {
		acl_info->acl_flags =
		    (S_ISDIR(statbuf.st_mode) ? ACL_IS_DIR : 0);
	} else
		acl_info->acl_flags = 0;

	switch (acl_info->acl_type) {
	case ACLENT_T:
		if (acl_info->acl_cnt <= MIN_ACL_ENTRIES)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;
		break;
	case ACE_T:
		if (ace_trivial(acl_info->acl_aclp, acl_info->acl_cnt) == 0)
			acl_info->acl_flags |= ACL_IS_TRIVIAL;
		break;
	default:
		errno = EINVAL;
		acl_free(acl_info);
		return (-1);
	}

	if ((acl_info->acl_flags & ACL_IS_TRIVIAL) &&
	    (get_flag & ACL_NO_TRIVIAL)) {
		acl_free(acl_info);
		errno = 0;
		return (0);
	}

	*aclp = acl_info;
	return (0);
}

/*
 * return -1 on failure, otherwise the number of acl
 * entries is returned
 */
int
acl_get(const char *path, int get_flag, acl_t **aclp)
{
	acl_inp acl_inp;
	acl_inp.file = path;

	return (cacl_get(acl_inp, get_flag, ACL_PATH, aclp));
}

int
facl_get(int fd, int get_flag, acl_t **aclp)
{

	acl_inp acl_inp;
	acl_inp.fd = fd;

	return (cacl_get(acl_inp, get_flag, ACL_FD, aclp));
}

/*
 * Set an ACL, translates acl to ace_t when appropriate.
 */
static int
cacl_set(acl_inp *acl_inp, acl_t *aclp, int type)
{
	int error = 0;
	int acl_flavor_target;
	struct stat64 statbuf;
	int stat_error;
	int isdir;


	if (type == ACL_PATH) {
		stat_error = stat64(acl_inp->file, &statbuf);
		if (stat_error)
			return (-1);
		acl_flavor_target = pathconf(acl_inp->file, _PC_ACL_ENABLED);
	} else {
		stat_error = fstat64(acl_inp->fd, &statbuf);
		if (stat_error)
			return (-1);
		acl_flavor_target = fpathconf(acl_inp->fd, _PC_ACL_ENABLED);
	}

	/*
	 * If target returns an error or 0 from pathconf call then
	 * fall back to UFS/POSIX Draft interface.
	 * In the case of 0 we will then fail in either acl(2) or
	 * acl_translate().  We could erroneously get 0 back from
	 * a file system that is using fs_pathconf() and not answering
	 * the _PC_ACL_ENABLED question itself.
	 */
	if (acl_flavor_target == 0 || acl_flavor_target == -1)
		acl_flavor_target = _ACL_ACLENT_ENABLED;

	isdir = S_ISDIR(statbuf.st_mode);

	if ((error = acl_translate(aclp, acl_flavor_target, isdir,
	    statbuf.st_uid, statbuf.st_gid)) != 0) {
		return (error);
	}

	if (type == ACL_PATH) {
		error = acl(acl_inp->file,
		    (aclp->acl_type == ACE_T) ? ACE_SETACL : SETACL,
		    aclp->acl_cnt, aclp->acl_aclp);
	} else {
		error = facl(acl_inp->fd,
		    (aclp->acl_type == ACE_T) ? ACE_SETACL : SETACL,
		    aclp->acl_cnt, aclp->acl_aclp);
	}

	return (error);
}

int
acl_set(const char *path, acl_t *aclp)
{
	acl_inp acl_inp;

	acl_inp.file = path;

	return (cacl_set(&acl_inp, aclp, ACL_PATH));
}

int
facl_set(int fd, acl_t *aclp)
{
	acl_inp acl_inp;

	acl_inp.fd = fd;

	return (cacl_set(&acl_inp, aclp, ACL_FD));
}

int
acl_cnt(acl_t *aclp)
{
	return (aclp->acl_cnt);
}

int
acl_type(acl_t *aclp)
{
	return (aclp->acl_type);
}

acl_t *
acl_dup(acl_t *aclp)
{
	acl_t *newaclp;

	newaclp = acl_alloc(aclp->acl_type);
	if (newaclp == NULL)
		return (NULL);

	newaclp->acl_aclp = malloc(aclp->acl_entry_size * aclp->acl_cnt);
	if (newaclp->acl_aclp == NULL) {
		acl_free(newaclp);
		return (NULL);
	}

	(void) memcpy(newaclp->acl_aclp,
	    aclp->acl_aclp, aclp->acl_entry_size * aclp->acl_cnt);
	newaclp->acl_cnt = aclp->acl_cnt;

	return (newaclp);
}

int
acl_flags(acl_t *aclp)
{
	return (aclp->acl_flags);
}

void *
acl_data(acl_t *aclp)
{
	return (aclp->acl_aclp);
}

/*
 * Take an acl array and build an acl_t.
 */
acl_t *
acl_to_aclp(enum acl_type type, void *acl, int count)
{
	acl_t *aclp;


	aclp = acl_alloc(type);
	if (aclp == NULL)
		return (aclp);

	aclp->acl_aclp = acl;
	aclp->acl_cnt = count;

	return (aclp);
}

/*
 * Remove an ACL from a file and create a trivial ACL based
 * off of the mode argument.  After acl has been set owner/group
 * are updated to match owner,group arguments
 */
int
acl_strip(const char *file, uid_t owner, gid_t group, mode_t mode)
{
	int	error = 0;
	aclent_t min_acl[MIN_ACL_ENTRIES];
	ace_t	min_ace_acl[6];	/* owner, group, everyone + complement denies */
	int	acl_flavor;
	int	aclcnt;

	acl_flavor = pathconf(file, _PC_ACL_ENABLED);

	/*
	 * force it through aclent flavor when file system doesn't
	 * understand question
	 */
	if (acl_flavor == 0 || acl_flavor == -1)
		acl_flavor = _ACL_ACLENT_ENABLED;

	if (acl_flavor & _ACL_ACLENT_ENABLED) {
		min_acl[0].a_type = USER_OBJ;
		min_acl[0].a_id   = owner;
		min_acl[0].a_perm = ((mode & 0700) >> 6);
		min_acl[1].a_type = GROUP_OBJ;
		min_acl[1].a_id   = group;
		min_acl[1].a_perm = ((mode & 0070) >> 3);
		min_acl[2].a_type = CLASS_OBJ;
		min_acl[2].a_id   = (uid_t)-1;
		min_acl[2].a_perm = ((mode & 0070) >> 3);
		min_acl[3].a_type = OTHER_OBJ;
		min_acl[3].a_id   = (uid_t)-1;
		min_acl[3].a_perm = (mode & 0007);
		aclcnt = 4;
		error = acl(file, SETACL, aclcnt, min_acl);
	} else if (acl_flavor & _ACL_ACE_ENABLED) {
		(void) memcpy(min_ace_acl, trivial_acl, sizeof (ace_t) * 6);

		/*
		 * Make aces match request mode
		 */
		adjust_ace_pair(&min_ace_acl[0], (mode & 0700) >> 6);
		adjust_ace_pair(&min_ace_acl[2], (mode & 0070) >> 3);
		adjust_ace_pair(&min_ace_acl[4], mode & 0007);

		error = acl(file, ACE_SETACL, 6, min_ace_acl);
	} else {
		errno = EINVAL;
		error = 1;
	}

	if (error == 0)
		error = chown(file, owner, group);
	return (error);
}

static int
ace_match(void *entry1, void *entry2)
{
	ace_t *p1 = (ace_t *)entry1;
	ace_t *p2 = (ace_t *)entry2;
	ace_t ace1, ace2;

	ace1 = *p1;
	ace2 = *p2;

	/*
	 * Need to fixup who field for abstrations for
	 * accurate comparison, since field is undefined.
	 */
	if (ace1.a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE))
		ace1.a_who = (uid_t)-1;
	if (ace2.a_flags & (ACE_OWNER|ACE_GROUP|ACE_EVERYONE))
		ace2.a_who = (uid_t)-1;
	return (memcmp(&ace1, &ace2, sizeof (ace_t)));
}

static int
aclent_match(void *entry1, void *entry2)
{
	aclent_t *aclent1 = (aclent_t *)entry1;
	aclent_t *aclent2 = (aclent_t *)entry2;

	return (memcmp(aclent1, aclent2, sizeof (aclent_t)));
}

/*
 * Find acl entries in acl that correspond to removeacl.  Search
 * is started from slot.  The flag argument indicates whether to
 * remove all matches or just the first match.
 */
int
acl_removeentries(acl_t *acl, acl_t *removeacl, int start_slot, int flag)
{
	int i, j;
	int match;
	int (*acl_match)(void *acl1, void *acl2);
	void *acl_entry, *remove_entry;
	void *start;
	int found = 0;

	if (flag != ACL_REMOVE_ALL && flag != ACL_REMOVE_FIRST)
		flag = ACL_REMOVE_FIRST;

	if (acl == NULL || removeacl == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (acl->acl_type != removeacl->acl_type)
		return (EACL_DIFF_TYPE);

	if (acl->acl_type == ACLENT_T)
		acl_match = aclent_match;
	else
		acl_match = ace_match;

	for (i = 0, remove_entry = removeacl->acl_aclp;
	    i != removeacl->acl_cnt; i++) {

		j = 0;
		acl_entry = (char *)acl->acl_aclp +
		    (acl->acl_entry_size * start_slot);
		for (;;) {
			match = acl_match(acl_entry, remove_entry);
			if (match == 0)  {
				found++;
				start = (char *)acl_entry +
				    acl->acl_entry_size;
				(void) memmove(acl_entry, start,
				    acl->acl_entry_size *
				    acl->acl_cnt-- - (j + 1));

				if (flag == ACL_REMOVE_FIRST)
					break;
				/*
				 * List has changed, just continue so this
				 * slot gets checked with it's new contents.
				 */
				continue;
			}
			acl_entry = ((char *)acl_entry + acl->acl_entry_size);
			if (++j >= acl->acl_cnt) {
				break;
			}
		}
		remove_entry = (char *)remove_entry + removeacl->acl_entry_size;
	}

	return ((found == 0) ? EACL_NO_ACL_ENTRY : 0);
}

/*
 * Replace entires entries in acl1 with the corresponding entries
 * in newentries.  The where argument specifies where to begin
 * the replacement.  If the where argument is 1 greater than the
 * number of acl entries in acl1 then they are appended.  If the
 * where argument is 2+ greater than the number of acl entries then
 * EACL_INVALID_SLOT is returned.
 */
int
acl_modifyentries(acl_t *acl1, acl_t *newentries, int where)
{

	int slot;
	int slots_needed;
	int slots_left;
	int newsize;

	if (acl1 == NULL || newentries == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (where < 0 || where >= acl1->acl_cnt)
		return (EACL_INVALID_SLOT);

	if (acl1->acl_type != newentries->acl_type)
		return (EACL_DIFF_TYPE);

	slot = where;

	slots_left = acl1->acl_cnt - slot + 1;
	if (slots_left < newentries->acl_cnt) {
		slots_needed = newentries->acl_cnt - slots_left;
		newsize = (acl1->acl_entry_size * acl1->acl_cnt) +
		    (acl1->acl_entry_size * slots_needed);
		acl1->acl_aclp = realloc(acl1->acl_aclp, newsize);
		if (acl1->acl_aclp == NULL)
			return (-1);
	}
	(void) memcpy((char *)acl1->acl_aclp + (acl1->acl_entry_size * slot),
	    newentries->acl_aclp,
	    newentries->acl_entry_size * newentries->acl_cnt);

	/*
	 * Did ACL grow?
	 */

	if ((slot + newentries->acl_cnt) > acl1->acl_cnt) {
		acl1->acl_cnt = slot + newentries->acl_cnt;
	}

	return (0);
}

/*
 * Add acl2 entries into acl1.  The where argument specifies where
 * to add the entries.
 */
int
acl_addentries(acl_t *acl1, acl_t *acl2, int where)
{

	int newsize;
	int len;
	void *start;
	void *to;

	if (acl1 == NULL || acl2 == NULL)
		return (EACL_NO_ACL_ENTRY);

	if (acl1->acl_type != acl2->acl_type)
		return (EACL_DIFF_TYPE);

	/*
	 * allow where to specify 1 past last slot for an append operation
	 * but anything greater is an error.
	 */
	if (where < 0 || where > acl1->acl_cnt)
		return (EACL_INVALID_SLOT);

	newsize = (acl2->acl_entry_size * acl2->acl_cnt) +
	    (acl1->acl_entry_size * acl1->acl_cnt);
	acl1->acl_aclp = realloc(acl1->acl_aclp, newsize);
	if (acl1->acl_aclp == NULL)
		return (-1);

	/*
	 * first push down entries where new ones will be inserted
	 */

	to = (void *)((char *)acl1->acl_aclp +
	    ((where + acl2->acl_cnt) * acl1->acl_entry_size));

	start = (void *)((char *)acl1->acl_aclp +
	    where * acl1->acl_entry_size);

	if (where < acl1->acl_cnt) {
		len = (acl1->acl_cnt - where) * acl1->acl_entry_size;
		(void) memmove(to, start, len);
	}

	/*
	 * now stick in new entries.
	 */

	(void) memmove(start, acl2->acl_aclp,
	    acl2->acl_cnt * acl2->acl_entry_size);

	acl1->acl_cnt += acl2->acl_cnt;
	return (0);
}

/*
 * return text for an ACL error.
 */
char *
acl_strerror(int errnum)
{
	switch (errnum) {
	case EACL_GRP_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one group or default group entry"));
	case EACL_USER_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one user or default user entry"));
	case EACL_OTHER_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one other entry"));
	case EACL_CLASS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "There is more than one mask entry"));
	case EACL_DUPLICATE_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Duplicate user or group entries"));
	case EACL_MISS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Missing user/group owner, other, mask entry"));
	case EACL_MEM_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Memory error"));
	case EACL_ENTRY_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Unrecognized entry type"));
	case EACL_INHERIT_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid inheritance flags"));
	case EACL_FLAGS_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Unrecognized entry flags"));
	case EACL_PERM_MASK_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL permissions"));
	case EACL_COUNT_ERROR:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL count"));
	case EACL_INVALID_SLOT:
		return (dgettext(TEXT_DOMAIN,
		    "Invalid ACL entry number specified"));
	case EACL_NO_ACL_ENTRY:
		return (dgettext(TEXT_DOMAIN,
		    "ACL entry doesn't exist"));
	case EACL_DIFF_TYPE:
		return (dgettext(TEXT_DOMAIN,
		    "ACL type's are different"));
	case EACL_INVALID_USER_GROUP:
		return (dgettext(TEXT_DOMAIN, "Invalid user or group"));
	case EACL_INVALID_STR:
		return (dgettext(TEXT_DOMAIN, "ACL string is invalid"));
	case EACL_FIELD_NOT_BLANK:
		return (dgettext(TEXT_DOMAIN, "Field expected to be blank"));
	case EACL_INVALID_ACCESS_TYPE:
		return (dgettext(TEXT_DOMAIN, "Invalid access type"));
	case EACL_UNKNOWN_DATA:
		return (dgettext(TEXT_DOMAIN, "Unrecognized entry"));
	case EACL_MISSING_FIELDS:
		return (dgettext(TEXT_DOMAIN,
		    "ACL specification missing required fields"));
	case EACL_INHERIT_NOTDIR:
		return (dgettext(TEXT_DOMAIN,
		    "Inheritance flags are only allowed on directories"));
	case -1:
		return (strerror(errno));
	default:
		errno = EINVAL;
		return (dgettext(TEXT_DOMAIN, "Unknown error"));
	}
}

extern int yyinteractive;

/* PRINTFLIKE1 */
void
acl_error(const char *fmt, ...)
{
	va_list va;

	if (yyinteractive == 0)
		return;

	va_start(va, fmt);
	(void) vfprintf(stderr, fmt, va);
	va_end(va);
}

int
sid_to_id(char *sid, boolean_t user, uid_t *id)
{
	idmap_handle_t *idmap_hdl = NULL;
	idmap_get_handle_t *get_hdl = NULL;
	char *rid_start = NULL;
	idmap_stat status;
	char *end;
	int error = 1;
	char *domain_start;

	if ((domain_start = strchr(sid, '@')) == NULL) {
		idmap_rid_t rid;

		if ((rid_start = strrchr(sid, '-')) == NULL)
			return (1);
		*rid_start++ = '\0';
		errno = 0;
		rid = strtoul(rid_start--, &end, 10);
		if (errno == 0 && *end == '\0') {
			if (idmap_init(&idmap_hdl) == IDMAP_SUCCESS &&
			    idmap_get_create(idmap_hdl, &get_hdl) ==
			    IDMAP_SUCCESS) {
				if (user)
					error = idmap_get_uidbysid(get_hdl,
					    sid, rid, IDMAP_REQ_FLG_USE_CACHE,
					    id, &status);
				else
					error = idmap_get_gidbysid(get_hdl,
					    sid, rid, IDMAP_REQ_FLG_USE_CACHE,
					    id, &status);
				if (error == IDMAP_SUCCESS) {
					error = idmap_get_mappings(get_hdl);
					if (error == IDMAP_SUCCESS &&
					    status != IDMAP_SUCCESS)
						error = 1;
					else
						error = 0;
				}
			} else {
				error = 1;
			}
			if (get_hdl)
				idmap_get_destroy(get_hdl);
			if (idmap_hdl)
				(void) idmap_fini(idmap_hdl);
		} else {
			error = 1;
		}
		*rid_start = '-'; /* putback character removed earlier */
	} else {
		char *name = sid;
		*domain_start++ = '\0';

		if (user)
			error = idmap_getuidbywinname(name, domain_start,
			    IDMAP_REQ_FLG_USE_CACHE, id);
		else
			error = idmap_getgidbywinname(name, domain_start,
			    IDMAP_REQ_FLG_USE_CACHE, id);
		*--domain_start = '@';
		error = (error == IDMAP_SUCCESS) ? 0 : 1;
	}

	return (error);
}
