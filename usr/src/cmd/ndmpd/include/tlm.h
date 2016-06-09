/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015 by Delphix. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef	_TLM_H_
#define	_TLM_H_

#include <sys/types.h>
#include <synch.h>
#include <limits.h>
#include <cstack.h>
#include <sys/acl.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/queue.h>
#include <sys/fs/zfs.h>
#include <libzfs.h>

#define	IS_SET(f, m)	(((f) & (m)) != 0)

#define	TLM_MAX_BACKUP_JOB_NAME	32	/* max size of a job's name */
#define	TLM_TAPE_BUFFERS	10	/* number of rotating tape buffers */
#define	TLM_LINE_SIZE		128	/* size of text messages */


#define	TLM_BACKUP_RUN		0x00000001
#define	TLM_RESTORE_RUN		0x00000002
#define	TLM_STOP		0x00000009	/* graceful stop */
#define	TLM_ABORT		0x99999999	/* abandon the run */

#define	TLM_EXTRA_SPACE		64
#define	TLM_MAX_PATH_NAME	(PATH_MAX + TLM_EXTRA_SPACE)

#define	ENTRYTYPELEN	14
#define	PERMS		4
#define	ID_STR_MAX	20
#define	APPENDED_ID_MAX	(ID_STR_MAX + 1)
#define	ACL_ENTRY_SIZE	(ENTRYTYPELEN + ID_STR_MAX + PERMS + APPENDED_ID_MAX)
#define	TLM_MAX_ACL_TXT	MAX_ACL_ENTRIES * ACL_ENTRY_SIZE


/* operation flags */
#define	TLM_OP_CHOOSE_ARCHIVE	0x00000001	/* look for archive bit */

/*
 * Synchronization flags used when launching the TLM threads.
 */
#define	TLM_TAPE_READER		0x00000001
#define	TLM_TAPE_WRITER		0x00000002
#define	TLM_SOCK_READER		0x00000004
#define	TLM_SOCK_WRITER		0x00000008
#define	TLM_BUF_READER		0x00000010
#define	TLM_BUF_WRITER		0x00000020
#define	TLM_TAR_READER		0x00000040
#define	TLM_TAR_WRITER		0x00000080

#define	SCSI_SERIAL_PAGE	0x80
#define	SCSI_DEVICE_IDENT_PAGE	0x83
#define	SCMD_READ_ELEMENT_STATUS	0xB8

#define	OCTAL7CHAR	07777777
#define	SYSATTR_RDONLY	"SUNWattr_ro"
#define	SYSATTR_RW	"SUNWattr_rw"

typedef	int (*func_t)();

typedef struct scsi_serial {
	int sr_flags;
	char sr_num[16];
} scsi_serial_t;

typedef struct fs_fhandle {
	int fh_fid;
	char *fh_fpath;
} fs_fhandle_t;

typedef struct scsi_link {
	struct scsi_link 	*sl_next;
	struct scsi_link 	*sl_prev;
	struct scsi_adapter 	*sl_sa;
	unsigned int		sl_sid;
	unsigned int		sl_lun;
	unsigned int		sl_requested_max_active;
	unsigned int		sl_granted_max_active;
	unsigned int		sl_n_active;
	unsigned int		sl_type; /* SCSI device type */
} scsi_link_t;

typedef struct scsi_adapter {
	struct scsi_adapter	*sa_next;
	char			sa_name[16];
	struct scsi_link	sa_link_head;
} scsi_adapter_t;

typedef struct sasd_drive {
	char		sd_name[256];
	char		sd_vendor[8 + 1];
	char		sd_id[16 + 1];
	char		sd_rev[4 + 1];
	char		sd_serial[16 + 1];
	char		sd_wwn[32 + 1];
} sasd_drive_t;

typedef struct scsi_sasd_drive {
	sasd_drive_t	ss_sd;
	scsi_link_t	ss_slink;
} scsi_sasd_drive_t;


#define	DEFAULT_SLINK_MAX_XFER	(64*1024)

typedef struct	tlm_info {
	int			ti_init_done;	/* initialization done ? */
	int			ti_library_count; /* number of libraries */
	struct tlm_library	*ti_library;	/* first in chain */
	struct tlm_chain_link	*ti_job_stats;  /* chain of job statistics */
} tlm_info_t;

typedef struct	tlm_chain_link {
	struct tlm_chain_link	*tc_next;	/* next blob of statistics */
	struct tlm_chain_link	*tc_prev;	/* previous blob in the chain */
	int	tc_ref_count;			/* number of routines */
	void	*tc_data;			/* the data blob */
} tlm_chain_link_t;

typedef struct	tlm_robot {
	struct tlm_robot	*tr_next;
	struct tlm_library	*tr_library;
	int	tr_number;
} tlm_robot_t;

typedef struct	tlm_drive {
	struct tlm_drive	*td_next;
	struct tlm_library	*td_library;
	char	td_job_name[TLM_MAX_BACKUP_JOB_NAME];
	int	td_number;		/* number of this tape drive */
	int	td_element;		/* the library's number for the drive */
	struct	scsi_link *td_slink;	/* because the drive may be connected */
					/* to a different SCSI card than the */
					/* library */
	short	td_scsi_id;
	short	td_lun;
	short	td_volume_number;	/* for current job */
					/*  an index into the tape set */
	int	td_fd;			/* I/O file descriptor */
	int	td_errno;		/* system error number */
	long	td_exists	: 1;

} tlm_drive_t;

typedef struct	tlm_slot {
	struct tlm_slot		*ts_next;
	struct tlm_library	*ts_library;
	int	ts_number;		/* number of this slot */
	int	ts_element;
	short	ts_use_count;		/* number of times used since loaded */
	long	ts_status_full		: 1;
} tlm_slot_t;

typedef struct	tlm_library {
	struct tlm_library	*tl_next;
	int	tl_number;		/* number of this tape library */
	long	tl_capability_robot	: 1,
		tl_capability_door	: 1,
		tl_capability_lock	: 1,
		tl_capability_slots	: 1,
		tl_capability_export	: 1,
		tl_capability_drives	: 1,
		tl_capability_barcodes	: 1,
		tl_ghost_drives		: 1;
		/*
		 * "ghost_drives" is used to make sure that
		 * all drives claimed by the library really
		 * exist ... libraries have been known to lie.
		 */
	struct	scsi_link *tl_slink;

	int		tl_robot_count;
	tlm_robot_t	*tl_robot;
	int		tl_drive_count;
	tlm_drive_t	*tl_drive;
	int		tl_slot_count;
	tlm_slot_t	*tl_slot;
} tlm_library_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t	di_peripheral_qual	: 3,
		di_peripheral_dev_type	: 5;
	uint8_t	di_page_code;
	uint16_t	di_page_length;
#else
	uint8_t	di_peripheral_dev_type	: 5,
		di_peripheral_qual	: 3;
	uint8_t	di_page_code;
	uint16_t	di_page_length;
#endif
} device_ident_header_t;

typedef struct {
#ifdef _BIG_ENDIAN
	uint8_t	ni_proto_ident	: 4,
		ni_code_set	: 4;

	uint8_t	ni_PIV		: 1,
				: 1,
		ni_asso		: 2,
		ni_ident_type	: 4;

	uint8_t	ni_reserved;
	uint8_t	ni_ident_length;
#else
	uint8_t	ni_code_set	: 4,
		ni_proto_ident	: 4;

	uint8_t	ni_ident_type	: 4,
		ni_asso		: 2,
				: 1,
		ni_PIV		: 1;
	uint8_t	ni_reserved;
	uint8_t	ni_ident_length;
#endif
} name_ident_t;

#define	TLM_NO_ERRORS			0x00000000
#define	TLM_ERROR_BUSY			0x00000001
#define	TLM_ERROR_INTERNAL		0x00000002
#define	TLM_ERROR_NO_ROBOTS		0x00000003
#define	TLM_TIMEOUT			0x00000004
#define	TLM_ERROR_RANGE			0x00000005
#define	TLM_EMPTY			0x00000006
#define	TLM_DRIVE_NOT_ASSIGNED		0x00000007
#define	TLM_NO_TAPE_NAME		0x00000008
#define	TLM_NO_BACKUP_DIR		0x00000009
#define	TLM_NO_BACKUP_HARDWARE		0x0000000a
#define	TLM_NO_SOURCE_FILE		0x0000000b
#define	TLM_NO_FREE_TAPES		0x0000000c
#define	TLM_EOT				0x0000000d
#define	TLM_SERIAL_NOT_FOUND		0x0000000e
#define	TLM_SMALL_READ			0x0000000f
#define	TLM_NO_RESTORE_FILE		0x00000010
#define	TLM_EOF				0x00000011
#define	TLM_NO_DIRECTORY		0x00000012
#define	TLM_NO_MEMORY			0x00000013
#define	TLM_WRITE_ERROR			0x00000014
#define	TLM_NO_SCRATCH_SPACE		0x00000015
#define	TLM_INVALID			0x00000016
#define	TLM_MOVE			0x00000017
#define	TLM_SKIP			0x00000018
#define	TLM_OPEN_ERR			0x00000019


#define	TLM_MAX_TAPE_DRIVES	16
#define	TLM_NAME_SIZE		100
#define	TLM_MAX_TAR_IMAGE	017777777770

#define	TLM_VOLNAME_MAX_LENGTH	255
#define	NAME_MAX		255

#define	TLM_MAGIC		"ustar  "
#define	TLM_SNAPSHOT_PREFIX	".zfs"
#define	TLM_SNAPSHOT_DIR	".zfs/snapshot"

#define	RECORDSIZE	512
#define	NAMSIZ	100

typedef struct	tlm_tar_hdr {
	char	th_name[TLM_NAME_SIZE];
	char	th_mode[8];
	char	th_uid[8];
	char	th_gid[8];
	char	th_size[12];
	char	th_mtime[12];
	char	th_chksum[8];
	char	th_linkflag;
	char	th_linkname[TLM_NAME_SIZE];
	char	th_magic[8];
	char	th_uname[32];
	char	th_gname[32];
	union {
		struct {
			char	th_devmajor[8];
			char	th_devminor[8];
		} th_dev;
		char	th_hlink_ino[12];
	} th_shared;
} tlm_tar_hdr_t;



/*
 * The linkflag defines the type of file
 */
#define	LF_OLDNORMAL	'\0'		/* Normal disk file, Unix compat */
#define	LF_NORMAL	'0'		/* Normal disk file */
#define	LF_LINK		'1'		/* Link to previously dumped file */
#define	LF_SYMLINK	'2'		/* Symbolic link */
#define	LF_CHR		'3'		/* Character special file */
#define	LF_BLK		'4'		/* Block special file */
#define	LF_DIR		'5'		/* Directory */
#define	LF_FIFO		'6'		/* FIFO special file */
#define	LF_CONTIG	'7'		/* Contiguous file */
/* Further link types may be defined later. */

#define	LF_DUMPDIR	'D'
					/*
					 * This is a dir entry that contains
					 * the names of files that were in
					 * the dir at the time the dump
					 * was made
					 */
#define	LF_HUMONGUS	'H'
					/*
					 * Identifies the NEXT file on the tape
					 * as a HUGE file
					 */
#define	LF_LONGLINK	'K'
					/*
					 * Identifies the NEXT file on the tape
					 * as having a long linkname
					 */
#define	LF_LONGNAME	'L'
					/*
					 * Identifies the NEXT file on the tape
					 * as having a long name.
					 */
#define	LF_MULTIVOL	'M'
					/*
					 * This is the continuation
					 * of a file that began on another
					 * volume
					 */

#define	LF_VOLHDR	'V'		/* This file is a tape/volume header */
					/* Ignore it on extraction */

#define	LF_ACL		'A'		/* Access Control List */

#define	LF_XATTR	'E'		/* Extended attribute */

#define	KILOBYTE	1024


/*
 * ACL support structure
 */
typedef struct sec_attr {
	char attr_type;
	char attr_len[7];
	char attr_info[TLM_MAX_ACL_TXT];
} sec_attr_t;

typedef struct	tlm_acls {
	int	acl_checkpointed	: 1,	/* are checkpoints active ? */
		acl_clear_archive	: 1,	/* clear archive bit ? */
		acl_overwrite		: 1,	/* always overwrite ? */
		acl_update		: 1,	/* only update ? */
		acl_non_trivial		: 1;	/* real ACLs? */
		/*
		 * The following fields are here to allow
		 * the backup reader to open a file one time
		 * and keep the information for ACL, ATTRs,
		 * and reading the file.
		 */
	sec_attr_t acl_info;

	char acl_root_dir[TLM_VOLNAME_MAX_LENGTH]; /* name of root filesystem */
	fs_fhandle_t acl_dir_fh;		/* parent dir's info */
	fs_fhandle_t acl_fil_fh;		/* file's info */
	struct stat64 acl_attr;			/* file system attributes */
	char uname[32];
	char gname[32];
} tlm_acls_t;


/*
 * Tape manager's data archiving ops vector
 *
 * This vector represents the granular operations for
 * performing backup/restore. Each backend should provide
 * such a vector interface in order to be invoked by NDMP
 * server.
 * The reserved callbacks are kept for different backup
 * types which are volume-based rather than file-based
 * e.g. zfs send.
 */
typedef struct tm_ops {
	char *tm_name;
	int (*tm_putfile)();
	int (*tm_putdir)();
	int (*tm_putvol)();	/* Reserved */
	int (*tm_getfile)();
	int (*tm_getdir)();
	int (*tm_getvol)();	/* Reserved */
} tm_ops_t;

/* The checksum field is filled with this while the checksum is computed. */
#define	CHKBLANKS	"        "	/* 8 blanks, no null */

#define	LONGNAME_PREFIX	"././_LoNg_NaMe_"
extern void ndmp_log(ulong_t, char *, char *, ...);
char ndmp_log_info[256];
#define	NDMP_LOG(p, ...) { \
				(void) snprintf(ndmp_log_info, \
				    sizeof (ndmp_log_info), \
				    "[%d][%s:%d]", \
				    (int)pthread_self(), __func__, __LINE__); \
				ndmp_log(p, ndmp_log_info, __VA_ARGS__); \
			}
extern void *ndmp_malloc(size_t size);

/*
 * ZFS metadata plug-in module structures
 */
#define	ZFS_MAX_PROPS		100
#define	ZFS_META_MAGIC		"ZFSMETA"
#define	ZFS_META_MAGIC_EXT	"ZFSMETA2"

/* Add new major/minor for header changes */
typedef enum {
	META_HDR_MAJOR_0,	/* Original format */
	META_HDR_MAJOR_1,	/* Extended format */
} ndmp_metadata_header_major_t;

#define	META_HDR_MAJOR_VERSION	META_HDR_MAJOR_1

typedef enum {
	META_HDR_MINOR_0,
} ndmp_metadata_header_minor_t;

#define	META_HDR_MINOR_VERSION	META_HDR_MINOR_0

/* To support older backups */
typedef struct ndmp_metadata_property {
	char mp_name[NAME_MAX];
	char mp_value[NAME_MAX];
	char mp_source[NAME_MAX];
} ndmp_metadata_property_t;

typedef struct ndmp_metadata_property_ext {
	char mp_name[ZFS_MAX_DATASET_NAME_LEN];
	char mp_value[ZFS_MAXPROPLEN];
	char mp_source[ZFS_MAXPROPLEN];
} ndmp_metadata_property_ext_t;

typedef struct ndmp_metadata_top_header {
	char th_plname[100];
	uint_t th_plversion;
	char th_magic[10];
	void *th_reserved_1;
	int th_count;
} ndmp_metadata_top_header_t;

/* Original metadata format */
typedef struct ndmp_metadata_header {
	ndmp_metadata_top_header_t nh_hdr;
	char nh_dataset[NAME_MAX];
	ndmp_metadata_property_t nh_property[1];
} ndmp_metadata_header_t;

/* Extended metadata format */
typedef struct ndmp_metadata_header_ext {
	ndmp_metadata_top_header_t nh_hdr;
	char nh_dataset[ZFS_MAX_DATASET_NAME_LEN];
	int32_t nh_total_bytes;
	int32_t nh_major;
	int32_t nh_minor;
	ndmp_metadata_property_ext_t nh_property[1];
} ndmp_metadata_header_ext_t;

#define	nh_plname	nh_hdr.th_plname
#define	nh_plversion	nh_hdr.th_plversion
#define	nh_magic	nh_hdr.th_magic
#define	nh_count	nh_hdr.th_count

typedef struct ndmp_metadata_handle {
	void *ml_handle;
	int32_t ml_quota_prop;
	union {
		ndmp_metadata_header_t *u_hdr;
		ndmp_metadata_header_ext_t *u_xhdr;
	} ml_hdr_u;
} ndmp_metadata_handle_t;

#define	ml_hdr	ml_hdr_u.u_hdr
#define	ml_xhdr	ml_hdr_u.u_xhdr

/*
 * Node in struct hardlink_q
 *
 * inode: the inode of the hardlink
 * path: the name of the hardlink, used during restore
 * offset: tape offset of the data records for the hardlink, used during backup
 * is_tmp: indicate whether the file was created temporarily for restoring
 * other links during a non-DAR partial restore
 */
struct hardlink_node {
	unsigned long inode;
	char *path;
	unsigned long long offset;
	int is_tmp;
	SLIST_ENTRY(hardlink_node) next_hardlink;
};

/*
 * Hardlinks that have been backed up or restored.
 *
 * During backup, each node represents a file whose
 *   (1) inode has multiple links
 *   (2) data has been backed up
 *
 * When we run into a file with multiple links during backup,
 * we first check the list to see whether a file with the same inode
 * has been backed up.  If yes, we backup an empty record, while
 * making the file history of this file contain the data offset
 * of the offset of the file that has been backed up.  If no,
 * we backup this file, and add an entry to the list.
 *
 * During restore, each node represents an LF_LINK type record whose
 * data has been restored (v.s. a hard link has been created).
 *
 * During restore, when we run into a record of LF_LINK type, we
 * first check the queue to see whether a file with the same inode
 * has been restored.  If yes, we create a hardlink to it.
 * If no, we restore the data, and add an entry to the list.
 */
struct hardlink_q {
	struct hardlink_node *slh_first;
};

/* Utility functions from handling hardlink */
extern struct hardlink_q *hardlink_q_init();
extern void hardlink_q_cleanup(struct hardlink_q *qhead);
extern int hardlink_q_get(struct hardlink_q *qhead, unsigned long inode,
    unsigned long long *offset, char **path);
extern int hardlink_q_add(struct hardlink_q *qhead, unsigned long inode,
    unsigned long long offset, char *path, int is_tmp);

#endif	/* !_TLM_H_ */
