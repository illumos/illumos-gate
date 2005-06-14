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
 * Copyright (c) 1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _NFS_NFSLOG_CONFIG_H
#define	_NFS_NFSLOG_CONFIG_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Internal configuration file API for NFS logging.
 *
 * Warning: This code is likely to change drastically in future releases.
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef LINTHAPPY
#define	LINTHAPPY
#endif

#define	MAX_LINESZ		4096

#define	NFSL_CONFIG_FILE_PATH	"/etc/nfs/nfslog.conf"
#define	DEFAULTTAG		"global"
#define	DEFAULTRAWTAG		"global-raw"
#define	DEFAULTDIR		"/var/nfs"
#define	BUFFERPATH		"nfslog_workbuffer"
#define	FHPATH			"fhtable"
#define	LOGPATH			"nfslog"

enum translog_format {
	TRANSLOG_BASIC, TRANSLOG_EXTENDED
};

/*
 * This struct is used to get or set the logging state for a filesystem.
 * Using a single struct like this is okay for for releases where it's
 * private, but it's questionable as a
 * public API, because of extensibility and binary compatibility issues.
 *
 * Relative paths are interpreted relative to the root of the exported
 * directory tree.
 */
typedef struct nfsl_config {
	uint_t			nc_flags;
	char			*nc_name;	/* tag or "global" */
	char			*nc_defaultdir;
	char			*nc_logpath;
	char			*nc_fhpath;
	char			*nc_bufferpath;
	char			*nc_rpclogpath;
	enum translog_format	nc_logformat;
	void			*nc_elfcookie;	/* for rpclogfile processing */
	void			*nc_transcookie; /* for logfile processing */
	struct nfsl_config	*nc_next;
} nfsl_config_t;

#define	NC_UPDATED		0x001	/* set when an existing entry is */
					/* modified after detecting changes */
					/* in the configuration file. */
					/* Not set on creation of entry. */

#define	NC_NOTAG_PRINTED	0x002	/* 'missing tag' syslogged */

extern boolean_t	nfsl_errs_to_syslog;

extern int	nfsl_getconfig_list(nfsl_config_t **listpp);
extern int	nfsl_checkconfig_list(nfsl_config_t **listpp, boolean_t *);
extern void	nfsl_freeconfig_list(nfsl_config_t **listpp);
extern nfsl_config_t *nfsl_findconfig(nfsl_config_t *, char *, int *);
#ifndef	LINTHAPPY
extern void	nfsl_printconfig_list(nfsl_config_t *config);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _NFS_NFSLOG_CONFIG_H */
