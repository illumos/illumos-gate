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

#ifndef	_SV_H
#define	_SV_H

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Storage Volume Character and Block Driver (SV)
 * Public header file.
 * SPARC case 1998/036.
 * PSARC case 1999/023.
 */

#define	SV_MAXPATH	NSC_MAXPATH
#define	SV_DEVICE	"/dev/sv"


/*
 * Ioctl structures
 */

typedef struct sv_name_s {
	char	svn_path[SV_MAXPATH];	/* path to underlying raw device */
	time_t	svn_timestamp;		/* timestamp of successful enable */
	int	svn_nblocks;		/* size of device */
	int	svn_mode;		/* NSC_DEVICE | NSC_CACHE */
} sv_name_t;


#ifdef _KERNEL

typedef struct sv_name32_s {
	char	svn_path[SV_MAXPATH];	/* path to underlying raw device */
	int32_t	svn_timestamp;		/* timestamp of successful enable */
	int32_t	svn_nblocks;		/* size of device */
	int32_t	svn_mode;		/* NSC_DEVICE | NSC_CACHE */
} sv_name32_t;

#endif	/* _KERNEL */


typedef struct sv_list_s {
	spcs_s_info_t	svl_error;	/* Error information */
	time_t		svl_timestamp;	/* time of successful {en,dis}able */
	int		svl_count;	/* Count of elements in svl_names */
	int		svl_maxdevs;	/* Max # of devices that can be used */
	sv_name_t	*svl_names;	/* pointer to names array */
} sv_list_t;


#ifdef _KERNEL

typedef struct sv_list32_s {
	spcs_s_info32_t	svl_error;	/* Error information */
	int32_t		svl_timestamp;	/* time of successful {en,dis}able */
	int32_t		svl_count;	/* Count of elements in svl_names */
	int32_t		svl_maxdevs;	/* Max # of devices that can be used */
	uint32_t	svl_names;	/* pointer to names array */
} sv_list32_t;

#endif	/* _KERNEL */


typedef struct sv_conf_s {
	spcs_s_info_t	svc_error;	/* Error information */
	char	svc_path[SV_MAXPATH];	/* path to underlying raw device */
	int	svc_flag;		/* NSC_DEVICE | NSC_CACHE */
	major_t	svc_major;		/* major_t of underlying raw device */
	minor_t	svc_minor;		/* minor_t of underlying raw device */
} sv_conf_t;

#ifdef _KERNEL

typedef struct sv_conf32_s {
	spcs_s_info32_t	svc_error;	/* Error information */
	char	svc_path[SV_MAXPATH];	/* path to underlying raw device */
	int32_t	svc_flag;		/* NSC_DEVICE | NSC_CACHE */
	major_t	svc_major;		/* major_t of underlying raw device */
	minor_t	svc_minor;		/* minor_t of underlying raw device */
} sv_conf32_t;

#endif	/* _KERNEL */


typedef struct sv_version_s {
	spcs_s_info_t	svv_error;		/* Error information */
	int		svv_major_rev;		/* Major revision */
	int		svv_minor_rev;		/* Minor revision */
	int		svv_micro_rev;		/* Micro revision */
	int		svv_baseline_rev;	/* Baseline revision */
} sv_version_t;

#ifdef _KERNEL

typedef struct sv_version32_s {
	spcs_s_info32_t	svv_error;	/* Error information */
	int32_t		svv_major_rev;	/* Major revision */
	int32_t		svv_minor_rev;	/* Minor revision */
	int32_t		svv_micro_rev;		/* Micro revision */
	int32_t		svv_baseline_rev;	/* Baseline revision */
} sv_version32_t;

#endif	/* _KERNEL */


#ifdef _KERNEL

/*
 * SV guard devices.
 */

typedef struct sv_guard_s {
	int		sg_magic;	/* Magic # */
	int		sg_version;	/* Version # */
	char		*sg_pathname;	/* Pathname of device to guard */
	char		*sg_module;	/* Module name of client */
	int		sg_kernel;	/* Prevent user access if true */
	spcs_s_info_t	sg_error;	/* Error to be returned to client */
} sv_guard_t;

#define	SV_SG_MAGIC	0x47554152
#define	SV_SG_VERSION	1

#endif	/* _KERNEL */


/*
 * Ioctl numbers.
 */

#define	__SV__(x)	(('S'<<16)|('V'<<8)|(x))

#define	SVIOC_ENABLE		__SV__(1)
#define	SVIOC_DISABLE		__SV__(2)
#define	SVIOC_LIST		__SV__(3)
#define	SVIOC_VERSION		__SV__(4)
#define	SVIOC_UNLOAD		__SV__(5)

/*
 * seconds to wait before unload, to drain lingering IOs.
 */
#define	SV_WAIT_UNLOAD	10

#ifdef	__cplusplus
}
#endif

#endif	/* _SV_H */
