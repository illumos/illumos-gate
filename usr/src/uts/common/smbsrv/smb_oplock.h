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
 * Copyright 2017 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef _SMBSRV_SMB_OPLOCK_H
#define	_SMBSRV_SMB_OPLOCK_H

#include <smbsrv/ntifs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 2.1.1.10 Per Oplock
 *
 *
 * ExclusiveOpen: The Open used to request the opportunistic lock.
 *
 * IIOplocks: A list of zero or more Opens used to request a LEVEL_TWO
 *  opportunistic lock, as specified in section 2.1.5.17.1.
 *
 * ROplocks: A list of zero or more Opens used to request a LEVEL_GRANULAR
 *  (RequestedOplockLevel: READ_CACHING) opportunistic lock, as specified in
 *   section 2.1.5.17.1.
 *
 * RHOplocks: A list of zero or more Opens used to request a LEVEL_GRANULAR
 *  (RequestedOplockLevel: (READ_CACHING|HANDLE_CACHING)) opportunistic lock,
 *  as specified in section 2.1.5.17.1.
 *
 * RHBreakQueue: A list of zero or more RHOpContext objects. This queue is
 *  used to track (READ_CACHING|HANDLE_CACHING) oplocks as they are breaking.
 *
 * WaitList: A list of zero or more Opens belonging to operations that are
 *  waiting for an oplock to break, as specified in section 2.1.4.12.
 *
 * State: The current state of the oplock, expressed as a combination of
 *  one or more flags. Valid flags are:
 *	[ As follows;  Re-ordered a bit from the spec. ]
 */

/*
 * READ_CACHING - Indicates that this Oplock represents an oplock
 * that provides caching of reads; this provides the SMB 2.1 read
 * caching lease, as described in [MS-SMB2] section 2.2.13.2.8.
 */
#define	READ_CACHING	OPLOCK_LEVEL_CACHE_READ		/* 1 */

/*
 * HANDLE_CACHING - Indicates that this Oplock represents an oplock
 * that provides caching of handles; this provides the SMB 2.1 handle
 * caching lease, as described in [MS-SMB2] section 2.2.13.2.8.
 */
#define	HANDLE_CACHING	OPLOCK_LEVEL_CACHE_HANDLE	/* 2 */

/*
 * WRITE_CACHING - Indicates that this Oplock represents an oplock
 * that provides caching of writes; this provides the SMB 2.1 write
 * caching lease, as described in [MS-SMB2] section 2.2.13.2.8.
 */
#define	WRITE_CACHING	OPLOCK_LEVEL_CACHE_WRITE	/* 4 */

/*
 * EXCLUSIVE - Indicates that this Oplock represents an oplock that
 * can be held by exactly one client at a time. This flag always appears
 * in combination with other flags that indicate the actual oplock level.
 * For example, (READ_CACHING|WRITE_CACHING|EXCLUSIVE) represents a
 * read caching and write caching oplock, which can be held by only
 * one client at a time.
 */
#define	EXCLUSIVE			0x00000010

/*
 * MIXED_R_AND_RH - Always appears together with READ_CACHING and
 * HANDLE_CACHING.  Indicates that this Oplock represents an oplock
 * on which at least one client has been granted a read caching oplock,
 * and at least one other client has been granted a read caching and
 * handle caching oplock.
 */
#define	MIXED_R_AND_RH			0x00000020

/*
 * LEVEL_TWO_OPLOCK - Indicates that this Oplock represents a
 * Level 2 (also called Shared) oplock.
 * Corresponds to SMB2_OPLOCK_LEVEL_II
 */
#define	LEVEL_TWO_OPLOCK	OPLOCK_LEVEL_TWO	/* 0x100 */

/*
 * LEVEL_ONE_OPLOCK - Indicates that this Oplock represents a
 * Level 1 (also called Exclusive) oplock.
 * Corresponds to SMB2_OPLOCK_LEVEL_EXCLUSIVE
 */
#define	LEVEL_ONE_OPLOCK	OPLOCK_LEVEL_ONE	/* 0x200 */

/*
 * BATCH_OPLOCK - Indicates that this Oplock represents a Batch oplock.
 * Corresponds to SMB2_OPLOCK_LEVEL_BATCH
 */
#define	BATCH_OPLOCK		OPLOCK_LEVEL_BATCH	/* 0x400 */

/* Note: ntifs.h		OPLOCK_LEVEL_GRANULAR	   0x800 */

/*
 * Note that the oplock leasing implementation uses this shift
 * to convert (i.e.) CACHE_READ to BREAK_TO_READ_CACHING etc.
 * This relationship is checked in smb_srv_oplock.c
 */
#define	BREAK_SHIFT 16

/*
 * BREAK_TO_READ_CACHING - Indicates that this Oplock represents an
 * oplock that is currently breaking to an oplock that provides
 * caching of reads; the oplock has broken but the break has not yet
 * been acknowledged.
 */
#define	BREAK_TO_READ_CACHING		0x00010000

/*
 * BREAK_TO_HANDLE_CACHING - Indicates that this Oplock represents an
 * oplock that is currently breaking to an oplock that provides
 * caching of handles; the oplock has broken but the break has not yet
 * been acknowledged.  Note: == (CACHE_HANDLE << BREAK_SHIFT)
 */
#define	BREAK_TO_HANDLE_CACHING		0x00020000

/*
 * BREAK_TO_WRITE_CACHING - Indicates that this Oplock represents an
 * oplock that is currently breaking to an oplock that provides
 * caching of writes; the oplock has broken but the break has
 * not yet been acknowledged.
 */
#define	BREAK_TO_WRITE_CACHING		0x00040000

/*
 * BREAK_TO_NO_CACHING - Indicates that this Oplock represents an
 * oplock that is currently breaking to None (that is, no oplock);
 * the oplock has broken but the break has not yet been acknowledged.
 */
#define	BREAK_TO_NO_CACHING		0x00080000

/*
 * BREAK_TO_TWO - Indicates that this Oplock represents an oplock
 * that is currently breaking from either Level 1 or Batch to Level 2;
 * the oplock has broken but the break has not yet been acknowledged.
 */
#define	BREAK_TO_TWO			0x00100000

/*
 * BREAK_TO_NONE - Indicates that this Oplock represents an oplock
 * that is currently breaking from either Level 1 or Batch to None
 * (that is, no oplock); the oplock has broken but the break has
 * not yet been acknowledged.
 */
#define	BREAK_TO_NONE			0x00200000

/*
 * BREAK_TO_TWO_TO_NONE - Indicates that this Oplock represents an
 * oplock that is currently breaking from either Level 1 or Batch to
 * None (that is, no oplock), and was previously breaking from Level 1
 *  or Batch to Level 2; the oplock has broken but the break has
 * not yet been acknowledged.
 */
#define	BREAK_TO_TWO_TO_NONE		0x00400000

/*
 * NO_OPLOCK - Indicates that this Oplock does not represent a
 * currently granted or breaking oplock. This is semantically
 * equivalent to the Oplock object being entirely absent from a
 * Stream. This flag always appears alone.
 * Note we also have OPLOCK_LEVEL_NONE == 0 from ntifs.h
 */
#define	NO_OPLOCK			0x10000000

/*
 * An internal flag, non-overlapping wth other oplock flags,
 * used only in smb_cmn_oplock.c (and here only to make clear
 * that it does not overlap with an other flags above).
 */
#define	PARENT_OBJECT			0x40000000

/*
 * Also not in the spec, but convenient
 */
#define	BREAK_LEVEL_MASK (\
	BREAK_TO_READ_CACHING |\
	BREAK_TO_WRITE_CACHING |\
	BREAK_TO_HANDLE_CACHING |\
	BREAK_TO_NO_CACHING)

#define	BREAK_ANY (\
	BREAK_LEVEL_MASK |\
	BREAK_TO_TWO |\
	BREAK_TO_NONE |\
	BREAK_TO_TWO_TO_NONE)


/*
 * Convenience macro to walk ofiles on a give node.
 * Used as follows:
 *	FOREACH_NODE_OFILE(node, o) { muck_with(o); }
 */
#define	FOREACH_NODE_OFILE(node, o)	for \
	(o = smb_llist_head(&node->n_ofile_list); \
	o != NULL; \
	o = smb_llist_next(&node->n_ofile_list, o))

/*
 * Some short-hand names used in the oplock code.
 */

#define	STATUS_NEW_HANDLE	NT_STATUS_OPLOCK_SWITCHED_TO_NEW_HANDLE
#define	STATUS_CANT_GRANT	NT_STATUS_CANNOT_GRANT_REQUESTED_OPLOCK

typedef enum oplock_type {
	LEVEL_NONE = OPLOCK_LEVEL_NONE,
	LEVEL_TWO = OPLOCK_LEVEL_TWO,
	LEVEL_ONE = OPLOCK_LEVEL_ONE,
	LEVEL_BATCH = OPLOCK_LEVEL_BATCH,
	LEVEL_GRANULAR = OPLOCK_LEVEL_GRANULAR
} oplock_type_t;

typedef enum oplock_cache_level {
	CACHE_R =	READ_CACHING,

	CACHE_RH =	READ_CACHING |
			HANDLE_CACHING,

	CACHE_RW =	READ_CACHING |
			WRITE_CACHING,

	CACHE_RWH =	READ_CACHING |
			WRITE_CACHING |
			HANDLE_CACHING,
} oplock_cache_t;

#ifdef __cplusplus
}
#endif

#endif /* _SMBSRV_SMB_OPLOCK_H */
