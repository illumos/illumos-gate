/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2024 RackTop Systems, Inc.
 */

/*
 * ACL data for libsec tests
 */

#include <sys/types.h>
#include <sys/acl.h>

#define	AF_U	ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE
#define	AF_G	ACE_FILE_INHERIT_ACE | ACE_DIRECTORY_INHERIT_ACE |\
		ACE_IDENTIFIER_GROUP

/*
 * This ACL contains a wide variety of users and groups,
 * some without names, or SIDs, etc. for test coverage.
 * See known users and groups in lib_stubs.c
 */
ace_t aces_canned[] = {
	{
		.a_who = -1,
		.a_access_mask = ACE_ALL_PERMS,
		.a_flags = AF_U | ACE_OWNER,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = -1,
		.a_access_mask = ACE_WRITE_PERMS,
		.a_flags = AF_G | ACE_GROUP,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = -1,
		.a_access_mask = ACE_WRITE_PERMS,
		.a_flags = ACE_EVERYONE,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 501,
		.a_access_mask = ACE_ALL_PERMS,
		.a_flags = AF_U,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 502,
		.a_access_mask = ACE_WRITE_PERMS,
		.a_flags = AF_G,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 0x80000001,
		.a_access_mask = ACE_ALL_PERMS,
		.a_flags = AF_U,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 0x80000002,
		.a_access_mask = ACE_WRITE_PERMS,
		.a_flags = AF_G,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 0x80000003,
		.a_access_mask = ACE_READ_PERMS,
		.a_flags = AF_G,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 0x80000004,
		.a_access_mask = ACE_READ_PERMS,
		.a_flags = AF_G,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	},
	{
		.a_who = 0x80000005,
		.a_access_mask = ACE_READ_PERMS,
		.a_flags = AF_G,
		.a_type = ACE_ACCESS_ALLOWED_ACE_TYPE
	}
};

acl_t acl_canned = {
	.acl_type = ACE_T,
	.acl_cnt = sizeof (aces_canned) / sizeof (aces_canned[0]),
	.acl_entry_size = sizeof (ace_t),
	.acl_flags = 0,
	.acl_aclp = aces_canned
};
