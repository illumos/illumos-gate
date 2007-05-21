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
 * ISO 9660 RRIP extension filesystem specifications
 */
/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FS_HSFS_RRIP_H
#define	_SYS_FS_HSFS_RRIP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Mount options specific to HSFS.
 * This is not a good place for them; we should probably have a file
 * named hsfs_mount.h for such stuff.
 */
#define	HSFSMNT_NORRIP		0x1	/* -nrr option found		 */
#define	HSFSMNT_NOTRAILDOT	0x2	/* ignore trailing '.'		 */
#define	HSFSMNT_NOMAPLCASE	0x4	/* do not map filenames to lcase */
#define	HSFSMNT_NOTRAILSPACE	0x8	/* no trailing space in iso 9660 */
#define	HSFSMNT_NOVERSION	0x10	/* no version info in iso 9660 */
#define	HSFSMNT_NOJOLIET	0x20	/* ignore Joliet even if present */
#define	HSFSMNT_JOLIETLONG	0x40	/* do not truncate Joliet filenames */
#define	HSFSMNT_NOVERS2		0x80	/* ignore ISO-9660:1999		 */
#define	HSFSMNT_INODE		0x1000	/* May use ext_lbn as inode #, */
					/* FS is from a recent mkisofs */

/*
 * XXX: The following flag was used in the past to instruct the kernel to
 *	ignore Rock Ridge extensions on a CD. Unfortunately, this was
 *	implemented as part of the generic mount flags, a bad idea.
 *	This flag should not be used anymore. The HSFSMNT_NORRIP
 *	flag should be used in its place. The hsfs_mount code currently
 *	understands this flag, but this functionality should go
 *	away in the future.
 */
#define	MS_NO_RRIP		0x800000  /* if set, don't use Rock Ridge */


#define	MIN(a, b)   ((a) < (b) ? (a) : (b))

/*
 * Make sure we have this first
 */

#define	RRIP_VERSION		1
#define	RRIP_SUF_VERSION	1
#define	RRIP_EXT_VERSION	1

#define	RRIP_BIT	1	/* loc. in extension_name_table in susp.c */

#define	IS_RRIP_IMPLEMENTED(fsp) (IS_IMPL_BIT_SET(fsp, RRIP_BIT) ? 1 : 0)



/*
 * RRIP signature macros
 */
#define	RRIP_CL		"CL"
#define	RRIP_NM		"NM"
#define	RRIP_PL		"PL"
#define	RRIP_PN		"PN"
#define	RRIP_PX		"PX"
#define	RRIP_RE		"RE"
#define	RRIP_RR		"RR"
#define	RRIP_SL		"SL"
#define	RRIP_TF		"TF"

/*
 * RRIP ER extension fields
 */
#define	RRIP_ER_EXT_ID		"RRIP_1991A"

#define	RRIP_ER_EXT_DES		"THE ROCK RIDGE INTERCHANGE PROTOCOL PROVIDES \
SUPPORT FOR POSIX FILE SYSTEM SEMANTICS."

#define	RRIP_ER_EXT_SRC		"PLEASE CONTACT DISC PUBLISHER FOR \
SPECIFICATION SOURCE.  SEE PUBLISHER IDENTIFIER IN PRIMARY VOLUME DESCRIPTOR \
FOR CONTACT INFORMATION."

/*
 * "TF" time macros
 */
#define	RRIP_TF_FLAGS(x)	*(RRIP_tf_flags(x))
#define	RRIP_tf_flags(x)	(&((uchar_t *)(x))[4])

#define	RRIP_TIME_START_BP	5

#define	RRIP_TF_TIME_LENGTH(x)	(IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
					RRIP_TF_LONG_BIT) ? \
					ISO_DATE_LEN : ISO_SHORT_DATE_LEN)

/*
 * Time location bits
 */
#define	RRIP_TF_CREATION_BIT	0x01
#define	RRIP_TF_MODIFY_BIT	0x02
#define	RRIP_TF_ACCESS_BIT	0x04
#define	RRIP_TF_ATTRIBUTES_BIT	0x08
#define	RRIP_TF_BACKUP_BIT	0x10
#define	RRIP_TF_EXPIRATION_BIT	0x20
#define	RRIP_TF_EFFECTIVE_BIT	0x40
#define	RRIP_TF_LONG_BIT	0x80



#define	RRIP_tf_creation(x)	(&((uchar_t *)x)[RRIP_TIME_START_BP])
#define	RRIP_tf_modify(x)	(&((uchar_t *)x)[RRIP_TIME_START_BP + \
			(RRIP_TF_TIME_LENGTH(x) * \
				(IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
				RRIP_TF_CREATION_BIT)))])

#define	RRIP_tf_access(x)	(&((uchar_t *)x)[RRIP_TIME_START_BP + \
			(RRIP_TF_TIME_LENGTH(x) * \
			(IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
					RRIP_TF_CREATION_BIT) + \
			IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
					RRIP_TF_MODIFY_BIT)))])

#define	RRIP_tf_attributes(x)	(&((uchar_t *)x)[RRIP_TIME_START_BP + \
			(RRIP_TF_TIME_LENGTH(x) * \
				(IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
						RRIP_TF_CREATION_BIT) + \
				IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
						RRIP_TF_MODIFY_BIT) + \
				IS_TIME_BIT_SET(RRIP_TF_FLAGS(x), \
						RRIP_TF_ACCESS_BIT)))])



/*
 * Check if TF Bits are set.
 *
 * Note : IS_TIME_BIT_SET(x, y)  must be kept returning 1 and 0.
 * 	see RRIP_tf_*(x) Macros
 */
#define	IS_TIME_BIT_SET(x, y)	(((x) & (y))  ? 1 : 0)
#define	SET_TIME_BIT(x, y)	((x) |= (y))


/*
 * "PX" Posix attibutes
 */
#define	RRIP_mode(x)		(&((uchar_t *)x)[4])
#define	RRIP_MODE(x)		(mode_t)BOTH_INT(RRIP_mode(x))

#define	RRIP_nlink(x)		(&((uchar_t *)x)[12])
#define	RRIP_NLINK(x)		(short)BOTH_INT(RRIP_nlink(x))

#define	RRIP_uid(x)		(&((uchar_t *)x)[20])
#define	RRIP_UID(x)		(uid_t)BOTH_INT(RRIP_uid(x))

#define	RRIP_gid(x)		(&((uchar_t *)x)[28])
#define	RRIP_GID(x)		(gid_t)BOTH_INT(RRIP_gid(x))

#define	RRIP_ino(x)		(&((uchar_t *)x)[36])
#define	RRIP_INO(x)		(uint32_t)BOTH_INT(RRIP_ino(x))

#define	RRIP_PX_OLD_SIZE	36
#define	RRIP_PX_SIZE		44

/*
 * "PN" Posix major/minor numbers
 */

#define	RRIP_major(x)		(&((uchar_t *)x)[4])
#define	RRIP_MAJOR(x)		BOTH_INT(RRIP_major(x))

#define	RRIP_minor(x)		(&((uchar_t *)x)[12])
#define	RRIP_MINOR(x)		BOTH_INT(RRIP_minor(x))


/*
 *  "NM" alternate name and "SL" symbolic link macros...
 */

#define	SYM_LINK_LEN(x)		(strlen(x) + 1)
#define	RRIP_NAME_LEN_BASE	5
#define	RRIP_NAME_LEN(x)	(SUF_LEN(x) - RRIP_NAME_LEN_BASE)

#define	RRIP_NAME_FLAGS(x)	(((uchar_t *)x)[4])

/*
 * These are for the flag bits in the NM and SL and must remain <= 8 bits
 */
#define	RRIP_NAME_CONTINUE	0x01
#define	RRIP_NAME_CURRENT	0x02
#define	RRIP_NAME_PARENT	0x04
#define	RRIP_NAME_ROOT		0x08
#define	RRIP_NAME_VOLROOT	0x10
#define	RRIP_NAME_HOST		0x20


/*
 * These are unique to use in the > 8 bits of sig_args.name_flags
 * They are > 8 so that we can share bits from above.
 * This can grow to 32 bits.
 */
#define	RRIP_NAME_CHANGE	0x40
#define	RRIP_SYM_LINK_COMPLETE	0x80	/* set if sym link already read */
					/* from SUA (no longer than a short) */

/*
 * Bit handling....
 */
#define	SET_NAME_BIT(x, y)	((x) |= (y))
#define	UNSET_NAME_BIT(x, y)	((x) &= ~(y))
#define	IS_NAME_BIT_SET(x, y)	((x) & (y))
#define	NAME_HAS_CHANGED(flag)	\
			(IS_NAME_BIT_SET(flag, RRIP_NAME_CHANGE) ? 1 : 0)

#define	RRIP_name(x)		(&((uchar_t *)x)[5])
#define	RRIP_NAME(x)		RRIP_name(x)

/*
 * This is the maximum filename length that we support
 */
#define	RRIP_FILE_NAMELEN	255


/*
 * SL Symbolic link macros (in addition to common name flag macos
 */
/* these two macros are from the SL SUF pointer */
#define	RRIP_sl_comp(x)		(&((uchar_t *)x)[5])
#define	RRIP_SL_COMP(x)		RRIP_sl_comp(x)
#define	RRIP_SL_FLAGS(x)	(((uchar_t *)x)[4])


/* these macros are from the component pointer within the SL SUF */
#define	RRIP_comp(x)		(&((uchar_t *)x)[2])
#define	RRIP_COMP(x)		RRIP_comp(x)
#define	RRIP_COMP_FLAGS(x)	(((uchar_t *)x)[0])
#define	RRIP_COMP_LEN(x)	(RRIP_COMP_NAME_LEN(x) + 2)
#define	RRIP_COMP_NAME_LEN(x)	(((uchar_t *)x)[1])


/*
 * Directory hierarchy macros
 */

/*
 * Macros for checking relocation bits in flags member of dlist
 * structure defined in iso_impl.h
 */
#define	IS_RELOC_BIT_SET(x, y)	(((x) & (y))  ? 1 : 0)
#define	SET_RELOC_BIT(x, y)	((x) |= (y))

#define	CHILD_LINK		0x01
#define	PARENT_LINK		0x02
#define	RELOCATED_DIR		0x04

#define	RRIP_child_lbn(x)	(&((uchar_t *)x)[4])
#define	RRIP_CHILD_LBN(x)	(uint_t)BOTH_INT(RRIP_child_lbn(x))

#define	RRIP_parent_lbn(x)	(&((uchar_t *)x)[4])
#define	RRIP_PARENT_LBN(x)	(uint_t)BOTH_INT(RRIP_parent_lbn(x))


#ifdef _KERNEL

/*
 * Forward declarations
 */
extern uchar_t *rrip_name(sig_args_t *);
extern uchar_t *rrip_file_attr(sig_args_t *);
extern uchar_t *rrip_dev_nodes(sig_args_t *);
extern uchar_t *rrip_file_time(sig_args_t *);
extern uchar_t *rrip_sym_link(sig_args_t *);
extern uchar_t *rrip_parent_link(sig_args_t *);
extern uchar_t *rrip_child_link(sig_args_t *);
extern uchar_t *rrip_reloc_dir(sig_args_t *);
extern uchar_t *rrip_rock_ridge(sig_args_t *);
extern void hs_check_root_dirent(struct vnode *vp, struct hs_direntry *hdp);
extern int rrip_namecopy(char *from, char *to, char *tmp_name,
				uchar_t *dirp, uint_t last_offset,
				struct hsfs *fsp, struct hs_direntry *hdp);
#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FS_HSFS_RRIP_H */
