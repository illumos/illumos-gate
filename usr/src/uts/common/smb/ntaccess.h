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
 *
 * Copyright 2018 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_NTACCESS_H
#define	_SMBSRV_NTACCESS_H

/*
 * This file defines the NT compatible access control masks and values.
 * An access mask as a 32-bit value arranged as shown below.
 *
 *   31-28    Generic bits, interpreted per object type
 *   27-26    Reserved, must-be-zero
 *   25       Maximum allowed
 *   24       System Security rights (SACL is SD)
 *   23-16    Standard access rights, generic to all object types
 *   15-0     Specific access rights, object specific
 *
 *   3 3 2 2 2 2 2 2 2 2 2 2 1 1 1 1 1 1 1 1 1 1
 *   1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0 9 8 7 6 5 4 3 2 1 0
 *   +---------------+---------------+-------------------------------+
 *   |G|G|G|G|Res'd|A| StandardRights|         SpecificRights        |
 *   |R|W|E|A|     |S|               |                               |
 *   +-+-------------+---------------+-------------------------------+
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Specific rights for files, pipes and directories.
 */
#define	FILE_READ_DATA			(0x0001) /* file & pipe */
#define	FILE_LIST_DIRECTORY		(0x0001) /* directory */
#define	FILE_WRITE_DATA			(0x0002) /* file & pipe */
#define	FILE_ADD_FILE			(0x0002) /* directory */
#define	FILE_APPEND_DATA		(0x0004) /* file */
#define	FILE_ADD_SUBDIRECTORY		(0x0004) /* directory */
#define	FILE_CREATE_PIPE_INSTANCE	(0x0004) /* named pipe */
#define	FILE_READ_EA			(0x0008) /* file & directory */
#define	FILE_READ_PROPERTIES		(0x0008) /* pipe */
#define	FILE_WRITE_EA			(0x0010) /* file & directory */
#define	FILE_WRITE_PROPERTIES		(0x0010) /* pipe */
#define	FILE_EXECUTE			(0x0020) /* file */
#define	FILE_TRAVERSE			(0x0020) /* directory */
#define	FILE_DELETE_CHILD		(0x0040) /* directory */
#define	FILE_READ_ATTRIBUTES		(0x0080) /* all */
#define	FILE_WRITE_ATTRIBUTES		(0x0100) /* all */
#define	FILE_SPECIFIC_ALL		(0x000001FFL)
#define	SPECIFIC_RIGHTS_ALL		(0x0000FFFFL)


/*
 * Standard rights:
 *
 * DELETE	The right to delete the object.
 *
 * READ_CONTROL The right to read the information in the object's security
 *              descriptor, not including the information in the SACL.
 *
 * WRITE_DAC    The right to modify the DACL in the object's security
 *	        descriptor.
 *
 * WRITE_OWNER  The right to change the owner in the object's security
 *	        descriptor.
 *
 * SYNCHRONIZE  The right to use the object for synchronization. This enables
 *              a thread to wait until the object is in the signaled state.
 */
#define	DELETE				(0x00010000L)
#define	READ_CONTROL			(0x00020000L)
#define	WRITE_DAC			(0x00040000L)
#define	WRITE_OWNER			(0x00080000L) /* take ownership */
#define	SYNCHRONIZE			(0x00100000L)
#define	STANDARD_RIGHTS_REQUIRED	(0x000F0000L)
#define	STANDARD_RIGHTS_ALL		(0x001F0000L)


#define	STANDARD_RIGHTS_READ		(READ_CONTROL)
#define	STANDARD_RIGHTS_WRITE		(READ_CONTROL)
#define	STANDARD_RIGHTS_EXECUTE		(READ_CONTROL)

#define	FILE_METADATA_ALL		(FILE_READ_EA		|\
					FILE_READ_ATTRIBUTES	|\
					READ_CONTROL		|\
					FILE_WRITE_EA		|\
					FILE_WRITE_ATTRIBUTES	|\
					WRITE_DAC		|\
					WRITE_OWNER		|\
					SYNCHRONIZE)

#define	FILE_DATA_ALL			(FILE_READ_DATA		|\
					FILE_WRITE_DATA		|\
					FILE_APPEND_DATA	|\
					FILE_EXECUTE		|\
					DELETE)

#define	FILE_ALL_ACCESS (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0x1FF)


/*
 * Miscellaneous bits: SACL access and maximum allowed access.
 */
#define	ACCESS_SYSTEM_SECURITY		(0x01000000L)
#define	MAXIMUM_ALLOWED			(0x02000000L)


/*
 * Generic rights. These are shorthands that are interpreted as
 * appropriate for the type of secured object being accessed.
 */
#define	GENERIC_ALL			(0x10000000UL)
#define	GENERIC_EXECUTE			(0x20000000UL)
#define	GENERIC_WRITE			(0x40000000UL)
#define	GENERIC_READ			(0x80000000UL)

#define	FILE_GENERIC_READ (STANDARD_RIGHTS_READ |		\
	    FILE_READ_DATA		|			\
	    FILE_READ_ATTRIBUTES	|			\
	    FILE_READ_EA		|			\
	    SYNCHRONIZE)

#define	FILE_GENERIC_WRITE (STANDARD_RIGHTS_WRITE |		\
	    FILE_WRITE_DATA		|			\
	    FILE_WRITE_ATTRIBUTES	|			\
	    FILE_WRITE_EA		|			\
	    FILE_APPEND_DATA		|			\
	    SYNCHRONIZE)

#define	FILE_GENERIC_EXECUTE (STANDARD_RIGHTS_EXECUTE |		\
	    FILE_READ_ATTRIBUTES	|			\
	    FILE_EXECUTE		|			\
	    SYNCHRONIZE)

#define	FILE_GENERIC_ALL (FILE_GENERIC_READ |			\
	    FILE_GENERIC_WRITE		|			\
	    FILE_GENERIC_EXECUTE)


/*
 * LSA policy desired access masks.
 */
#define	POLICY_VIEW_LOCAL_INFORMATION		0x00000001L
#define	POLICY_VIEW_AUDIT_INFORMATION		0x00000002L
#define	POLICY_GET_PRIVATE_INFORMATION		0x00000004L
#define	POLICY_TRUST_ADMIN			0x00000008L
#define	POLICY_CREATE_ACCOUNT			0x00000010L
#define	POLICY_CREATE_SECRET			0x00000020L
#define	POLICY_CREATE_PRIVILEGE			0x00000040L
#define	POLICY_SET_DEFAULT_QUOTA_LIMITS		0x00000080L
#define	POLICY_SET_AUDIT_REQUIREMENTS		0x00000100L
#define	POLICY_AUDIT_LOG_ADMIN			0x00000200L
#define	POLICY_SERVER_ADMIN			0x00000400L
#define	POLICY_LOOKUP_NAMES			0x00000800L


/*
 * SAM specific rights desired access masks. These definitions are listed
 * mostly as a convenience; they don't seem to be documented. Setting the
 * desired access mask to GENERIC_EXECUTE and STANDARD_RIGHTS_EXECUTE
 * seems to work when just looking up information.
 */
#define	SAM_LOOKUP_INFORMATION (GENERIC_EXECUTE		\
	    | STANDARD_RIGHTS_EXECUTE)

#define	SAM_ACCESS_USER_READ		0x0000031BL
#define	SAM_ACCESS_USER_UPDATE		0x0000031FL
#define	SAM_ACCESS_USER_SETPWD		0x0000037FL
#define	SAM_CONNECT_CREATE_ACCOUNT	0x00000020L
#define	SAM_ENUM_LOCAL_DOMAIN		0x00000030L
#define	SAM_DOMAIN_CREATE_ACCOUNT	0x00000211L


/*
 * File attributes
 *
 * Note:  0x00000008 is reserved for use for the old DOS VOLID (volume ID)
 *        and is therefore not considered valid in NT.
 *
 * Note:  0x00000010 is reserved for use for the old DOS SUBDIRECTORY flag
 *        and is therefore not considered valid in NT.  This flag has
 *        been disassociated with file attributes since the other flags are
 *        protected with READ_ and WRITE_ATTRIBUTES access to the file.
 *
 * Note:  Note also that the order of these flags is set to allow both the
 *        FAT and the Pinball File Systems to directly set the attributes
 *        flags in attributes words without having to pick each flag out
 *        individually.  The order of these flags should not be changed!
 *
 * The file attributes are defined in smbsrv/smb_vops.h
 */

/* Filesystem Attributes */
#define	FILE_CASE_SENSITIVE_SEARCH	0x00000001
#define	FILE_CASE_PRESERVED_NAMES	0x00000002
#define	FILE_UNICODE_ON_DISK		0x00000004
#define	FILE_PERSISTENT_ACLS		0x00000008
#define	FILE_FILE_COMPRESSION		0x00000010
#define	FILE_VOLUME_QUOTAS		0x00000020
#define	FILE_SUPPORTS_SPARSE_FILES	0x00000040
#define	FILE_SUPPORTS_REPARSE_POINTS	0x00000080
#define	FILE_SUPPORTS_REMOTE_STORAGE	0x00000100
#define	FILE_VOLUME_IS_COMPRESSED	0x00008000
#define	FILE_SUPPORTS_OBJECT_IDS	0x00010000
#define	FILE_SUPPORTS_ENCRYPTION	0x00020000
#define	FILE_NAMED_STREAMS		0x00040000
#define	FILE_READ_ONLY_VOLUME		0x00080000

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_NTACCESS_H */
