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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
/*
 * Audit trail structures;
 */

#ifndef _sys_audit_h
#define _sys_audit_h

/*
 * Maximum size for audit data passed from the audit system call
 * This value is arbitrary, so offers of better numbers are invited.
 */

#define AUP_USER	(0x8000)
#define MAXAUDITDATA	(AUP_USER - 1)
#define AUDITMAGIC	0x00070009

/*
 * Audit conditions, statements reguarding what's to be done with
 * audit records.
 */
#define AUC_UNSET	0	/* on/off hasn't been decided */
#define AUC_AUDITING	1	/* auditing is being done */
#define AUC_NOAUDIT	2	/* auditing is not being done */
#define AUC_FCHDONE	3	/* no auditing, and you never can */

/*
 * Minimum and maximum record type values.  Change AUR_MAXRECTYPE when
 * adding new record types.
 */
#define	AUR_MINRECTYPE		1
#define	AUR_MAXRECTYPE		63

/*
 * Audit record type codes
 */
#define AUR_ACCESS		1
#define AUR_CHMOD		2
#define AUR_CHOWN		3
#define AUR_CREAT		4
#define AUR_FCHMOD		5
#define AUR_FCHOWN		6
#define AUR_FTRUNCATE		7
#define AUR_LINK		8
#define AUR_MKDIR		9
#define AUR_MKNOD		10
#define AUR_OPEN		11
#define AUR_RMDIR		12
#define AUR_RENAME		13
#define AUR_STAT		14
#define AUR_SYMLINK		15
#define AUR_TRUNCATE		16
#define AUR_UNLINK		17
#define AUR_UTIMES		18
#define AUR_EXECV		19
#define AUR_MSGCONV		20
#define AUR_MSGCTL		21
#define AUR_MSGGET		22
#define AUR_MSGRCV		23
#define AUR_MSGSND		24
#define AUR_SEMCTL		25
#define AUR_SEMGET		26
#define AUR_SEMOP		27
#define AUR_SHMAT		28
#define AUR_SHMCTL		29
#define AUR_SHMDT		30
#define AUR_SHMGET		31
#define AUR_SOCKET		32
#define AUR_PTRACE		33
#define AUR_KILL		34
#define AUR_KILLPG		35
#define AUR_EXECVE		36
#define AUR_CORE		37
#define AUR_ADJTIME		38
#define AUR_SETTIMEOFDAY	39
#define AUR_SETHOSTNAME		40
#define AUR_SETDOMAINNAME	41
#define AUR_REBOOT		42
#define AUR_REBOOTFAIL		43
#define AUR_SYSACCT		44
#define AUR_MOUNT_UFS		45
#define AUR_MOUNT_NFS		46
#define AUR_MOUNT		47
#define AUR_UNMOUNT		48
#define AUR_READLINK		49
#define AUR_QUOTA_ON		50
#define AUR_QUOTA_OFF		51
#define AUR_QUOTA_SET		52
#define AUR_QUOTA_LIM		53
#define AUR_QUOTA_SYNC		54
#define AUR_QUOTA		55
#define AUR_STATFS		56
#define AUR_CHROOT		57
#define AUR_TEXT		58
#define AUR_CHDIR		59
#define AUR_MSGCTLRMID		60
#define AUR_SEMCTL3		61
#define AUR_SEMCTLALL		62
#define AUR_SHMCTLRMID		63

#define AUR_TRAILER		1000

/*
 * The classes of audit events
 */
#define AU_DREAD	0x00000001
#define AU_DWRITE	0x00000002
#define AU_DACCESS	0x00000004
#define AU_DCREATE	0x00000008
#define AU_LOGIN	0x00000010
#define AU_SREAD	0x00000020
#define AU_SCTL		0x00000040
#define AU_MINPRIV	0x00000080
#define AU_MAJPRIV	0x00000100
#define AU_ADMIN	0x00000200
#define AU_ASSIGN	0x00000400

/*
 * Success and failure are defined here because not everyone agrees on
 * which values rate success and which failure.
 */
#define AU_EITHER	-1
#define AU_SUCCESS	0
#define AU_FAILURE	1

/*
 * The user id -2(0xfffe) is never audited - in fact, a setauid(AU_NOAUDITID)
 * will turn off auditing.
 */
#define AU_NOAUDITID	-2

/*
 * The sturcture of the audit state
 */
struct audit_state {
	unsigned int	as_success;	/* success bits */
	unsigned int	as_failure;	/* failure bits */
};
typedef struct audit_state audit_state_t;

/*
 * The audit file header structure.
 * In the file it will be followed by a path name, the length of which is
 * kept in the ah_namelen field.
 */
struct audit_header {
	int	ah_magic;	/* magic number */
	time_t	ah_time;	/* the time */
	short	ah_namelen;	/* length of file name */
};
typedef struct audit_header audit_header_t;

/*
 * The audit file trailer record structure.
 * In the file it will be followed by a path name, the length of which is
 * kept in the at_namelen field.
 */
struct audit_trailer {
	short	at_record_size;		/* size of this */
	short	at_record_type;		/* its type, a trailer */
	time_t	at_time;		/* the time */
	short	at_namelen;		/* length of file name */
};
typedef struct audit_trailer audit_trailer_t;

/*
 * The audit file record structure.
 * au_record_size is the size of the entire record.
 * au_param_count is the number of data items which follow the record.
 * There is a short ( 16 bit ) length for each of the following
 * parameters, then the parameters themselves. There is no way to know
 * what the parameters are from the data, unless the au_record_type
 * is understood.
 * The first parameter is the group list, hence au_param_count will
 * always be at least one.
 */
struct audit_record {
	short		au_record_size;		/* size of this */
	short		au_record_type;		/* its type */
	unsigned int	au_event;		/* the event */
	time_t		au_time;		/* the time */
	uid_t		au_uid;			/* real uid */
	uid_t		au_auid;		/* audit uid */
	uid_t		au_euid;		/* effective */
	gid_t		au_gid;			/* real group */
	short		au_pid;			/* process id */
	int		au_errno;		/* error code */
	int		au_return;		/* a return value */
	blabel_t	au_label;		/* also ... */
	short		au_param_count;		/* # of parameters */
};
typedef struct audit_record audit_record_t;

/*
 * This structure controls a buffer for generating full pathnames
 * for filenames.
 */
struct au_path_s {
	u_int		ap_size;		/* Size of buffer	     */
	caddr_t		ap_buf;			/* Address of buffer	     */
	caddr_t		ap_ptr;			/* Current position	     */
};
typedef struct au_path_s au_path_t;

#define AU_ALIGN(x)	(((x) + 1) & ~1)

#endif /*!_sys_audit_h*/
