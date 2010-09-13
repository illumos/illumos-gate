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
 * Copyright (c) 1995 Sun Microsystems, Inc.  All Rights Reserved
 *
 * module:
 *	acls.c
 *
 * purpose:
 * 	routines to manipulate access control lists, mapping between
 *	the data structures required by the filesystem ACL system calls
 *	and the representation used in our fileinfo structure.
 *
 */
#ident	"%W%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>

#include "filesync.h"
#include "database.h"

#ifdef NO_ACLS
/*
 * Solaris 2.4 libc.so does not contain this entry point, so if we
 * want to build a 2.4 version of filesync, we need to provide a
 * dummy entry point that will fail when-ever it is called.
 */
#define	acl	bogus_acl

static int acl(const char *name, int opcode, int count, aclent_t *acls)
{
	return (-1);
}
#endif

/*
 * routine:
 *	get_acls
 *
 * purpose:
 *	to read the ACL (if any) from a file into a fileinfo structure
 *
 * parameters:
 *	name of file
 * 	pointer to fileinfo structure
 *
 * returns:
 *	number of ACL entries
 */
int
get_acls(const char *name, struct fileinfo *ip)
{	int count;
	int i;
	static aclent_t acls[MAX_ACL_ENTRIES];
	aclent_t *list;

	count = acl(name, GETACL, MAX_ACL_ENTRIES, acls);
	if (count <= 0)
		return (0);

	/* with a count of 3 or 4 there may not be any real ones */
	if (count > 4)
		goto gotsome;

	/* look for anything beyond the normal unix protection	*/
	for (i = 0; i < count; i++)
		switch (acls[i].a_type) {
			default:	/* weird types are real */
				goto gotsome;

			case USER_OBJ:
			case GROUP_OBJ:
			case OTHER_OBJ:
			case CLASS_OBJ:
				continue; /* all file have these */
		}

	return (0);	/* nothing interesting	*/

gotsome:
	/* allocate an array to hold the acls		*/
	list = (aclent_t *) malloc(count * sizeof (*list));
	if (list == 0)
		nomem("Access Control List");

	/* copy the acls into the new list		*/
	for (i = 0; i < count; i++) {
		list[i].a_type = acls[i].a_type;
		list[i].a_id = acls[i].a_id;
		list[i].a_perm = acls[i].a_perm;
	}

	ip->f_acls = list;
	ip->f_numacls = count;
	return (ip->f_numacls);
}

/*
 * routine:
 *	cmp_acls
 *
 * purpose:
 *	determine whether or not two ACLs are the same
 *
 * parameters:
 *	pointer to first fileinfo
 *	pointer to second fileinfo
 *
 * returns:
 *	true 	equal
 *	false	different
 */
int
cmp_acls(struct fileinfo *f1, struct fileinfo *f2)
{	int i;

	if (f1->f_numacls != f2->f_numacls)
		return (0);

	if (f1->f_numacls == 0)
		return (1);

	for (i = 0; i < f1->f_numacls; i++) {
		if (f1->f_acls[i].a_type != f2->f_acls[i].a_type)
			return (0);
		if (f1->f_acls[i].a_id != f2->f_acls[i].a_id)
			return (0);
		if (f1->f_acls[i].a_perm != f2->f_acls[i].a_perm)
			return (0);
	}

	return (1);
}

/*
 * routine:
 *	set_acls
 *
 * purpose:
 *	to write the ACL of a file
 *
 * parameters:
 *	name of file
 *	fileinfo pointer (which contains an acl pointer)
 *
 * returns:
 *	retcode and errno
 */
int
set_acls(const char *name, struct fileinfo *fp)
{	int rc;
	int nacl;
	aclent_t acls[4], *list;

	if (fp->f_numacls == 0) {
		/* fabricate a standard set of bogus ACLs */
		acls[0].a_type = USER_OBJ;
		acls[0].a_id = fp->f_uid;
		acls[0].a_perm = (fp->f_mode >> 6) & 7;

		acls[1].a_type = GROUP_OBJ;
		acls[1].a_id = fp->f_gid;
		acls[1].a_perm = (fp->f_mode >> 3) & 7;

		acls[2].a_type = CLASS_OBJ;
		acls[2].a_id = 0;
		acls[2].a_perm = (fp->f_mode >> 6) & 7;

		acls[3].a_type = OTHER_OBJ;
		acls[3].a_id = 0;
		acls[3].a_perm = fp->f_mode & 7;

		nacl = 4;
		list = acls;
	} else {
		nacl = fp->f_numacls;
		list = fp->f_acls;
	}

	rc = acl(name, SETACL, nacl, list);

	/* non-negative number mean success		*/
	if (rc < 0)
		return (rc);
	else
		return (0);
}

/*
 * routine:
 *	show_acls
 *
 * purpose:
 *	to map an acl into arguments for a setfacl command
 *
 * paramters:
 *	number of elements in list
 *	pointer to list
 *
 * returns:
 *	pointer to character buffer containing arguments
 */
char
*show_acls(int numacl, aclent_t *list)
{	int i, j;
	int type, perm, id;
	char *s;
	static char buf[ MAX_LINE ];

	s = buf;

	if (numacl > 0) {
		*s++ = '-';
		*s++ = 's';
		*s++ = ' ';
	} else {
		*s++ = '-';
		*s++ = 'd';
	}

	for (i = 0; i < numacl; i++) {
		type = list[i].a_type;
		id = list[i].a_id;
		perm = list[i].a_perm;

		if (i > 0)
			*s++ = ',';

		/* note whether this is per-file or default	*/
		if (type & ACL_DEFAULT) {
			*s++ = 'd';
			*s++ = ':';
		}

		/* print out the entry type			*/
		if (type & (USER_OBJ|USER)) {
			*s++ = 'u';
			*s++ = ':';
		} else if (type & (GROUP_OBJ|GROUP)) {
			*s++ = 'g';
			*s++ = ':';
		} else if (type & OTHER_OBJ) {
			*s++ = 'o';
			*s++ = ':';
		} else if (type & CLASS_OBJ) {
			*s++ = 'm';
			*s++ = ':';
		}

		/* print out the ID for this ACL		*/
		if (type & (USER_OBJ|GROUP_OBJ))
			*s++ = ':';
		else if (type & (USER|GROUP)) {
			for (j = 1; id/j > 10; j *= 10);

			while (j > 0) {
				*s++ = '0' + (id/j);
				id %= j*10;
				j /= 10;
			}

			*s++ = ':';
		}

		/* print out the permissions for this ACL	*/
		*s++ = (perm & 04) ? 'r' : '-';
		*s++ = (perm & 02) ? 'w' : '-';
		*s++ = (perm & 01) ? 'x' : '-';
	}

	*s = 0;
	return (buf);
}
