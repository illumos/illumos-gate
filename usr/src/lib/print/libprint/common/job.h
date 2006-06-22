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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_JOB_H
#define	_JOB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/va_list.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 *	Sequence number space
 */
#define	JOB_ID_START		   0
#define	JOB_ID_END		   999

/*
 *	Job related files
 */
#define	SEQUENCE_FILE		".seq"  /* sequence numbers */
#define	TEMP_FILE_PREFIX	"tf"    /* printer:server */
#define	XFER_FILE_PREFIX	"xf"    /* printer:server */
#define	CONTROL_FILE_PREFIX	"cf"    /* job control data */
#define	DATA_FILE_PREFIX	"df"    /* job data file */

/*
 *	RFC-1179 Control File Primatives
 */
#define	CF_CLASS	'C'	 /* C(ClassName)\n - for banner page */
#define	CF_HOST		'H'	 /* H(Hostname)\n - host submitting job */
#define	CF_INDENT	'I'	 /* I(indent)\n - # of spaces for 'f' */
#define	CF_JOBNAME	'J'	 /* J(Jobname)\n - name of job for banner */
#define	CF_PRINT_BANNER	'L'	 /* L[User]\n - User name on burst page */
#define	CF_MAIL		'M'	 /* M(user)\n - User to mail when done */
#define	CF_SOURCE_NAME	'N'	 /* N(name)\n - source of data file */
#define	CF_USER		'P'	 /* P(name)\n - requesting user */
#define	CF_SYMLINK	'S'	 /* S(device) (inode)\n - foget it */
#define	CF_TITLE	'T'	 /* T(title)\n - for pr */
#define	CF_UNLINK	'U'	 /* U(file)\n - unlink file */
#define	CF_WIDTH	'W'	 /* W(width)\n - column width */
#define	CF_FONT_TROFF_R	'1'	 /* 1(file)\n - file with Times Roman font */
#define	CF_FONT_TROFF_I	'2'	 /* 2(file)\n - file with Times Italic font */
#define	CF_FONT_TROFF_B	'3'	 /* 3(file)\n - file with Times Bold font */
#define	CF_FONT_TROFF_S	'4'	 /* 4(file)\n - file with Times Special font */
#define	CF_PRINT_CIF	'c'	 /* c(file)\n - print/plot file as CIF data */
#define	CF_PRINT_DVI	'd'	 /* d(file)\n - print file as DVI data */
#define	CF_PRINT_ASCII	'f'	 /* f(file)\n - print file as ASCII */
#define	CF_PRINT_PLOT	'g'	 /* g(file)\n - print file as plot data */
#define	CF_KERBERIZED	'k'	 /* k...\n - for Kerberos */
#define	CF_PRINT_RAW	'l'	 /* l(file)\n - print file dammit */
#define	CF_PRINT_DROFF	'n'	 /* n(file)\n - print file as ditroff output */
#define	CF_PRINT_PS	'o'	 /* o(file)\n - print file as PostScript */
#define	CF_PRINT_PR	'p'	 /* p(file)\n - print file thru "pr" */
#define	CF_PRINT_FORT	'r'	 /* r(file)\n - print file as fortran */
#define	CF_PRINT_TROFF	't'	 /* n(file)\n - print file as troff output */
#define	CF_PRINT_RAS	'v'	 /* v(file)\n - print file as raster image */
#define	CF_PRINT_PLDM	'z'	 /* z...\n - for Palladium ??? */

/*
 *	Solaris 2.X LP - BSD protocol extensions
 */
#define	CF_SYSV_OPTION  'O'		/* for SVR4 LP '-o' option */
#define	CF_SYSV_FEATURE '5'		/* for SVR4 LP features */
#define	CF_SYSV_FORM		'f'	/* for SVR4 Forms */
#define	CF_SYSV_HANDLING	'H'	/* for SVR4 Handling */
#define	CF_SYSV_NOTIFICATION	'p'	/* for SVR4 Notification */
#define	CF_SYSV_PAGES		'P'	/* for SVR4 Pages */
#define	CF_SYSV_PRIORITY	'q'	/* for SVR4 Priority */
#define	CF_SYSV_CHARSET		'S'	/* for SVR4 Charset */
#define	CF_SYSV_TYPE		'T'	/* for SVR4 Type */
#define	CF_SYSV_MODE		'y'	/* for SVR4 Mode */


typedef struct _jobfile jobfile_t;
typedef struct _job job_t;

struct _jobfile {
	char	*jf_spl_path;	/* df file */
	char	*jf_src_path;	/* source file */
	char	*jf_name;	/* title/name */
	char	*jf_data;	/* ptr to mmapped file */
	long	jf_size;	/* size of data */
	char	jf_mmapped;	/* is this mmapped or malloced */
};

struct _job {
	int	job_id;
	char	*job_printer;
	char	*job_server;
	char	*job_user;
	char	*job_host;
	char	*job_spool_dir;
	jobfile_t *job_cf;
	char 	job_df_next;
	jobfile_t **job_df_list;
};


extern int	job_store(job_t *job);
extern void	job_free(job_t *job);
extern void	job_destroy(job_t *job);
extern job_t	*job_retrieve(char *xfer_file, char *spool);
extern job_t	**job_list_append(job_t **list, char *printer,
					char *server, char *spool);
extern int	vjob_match_attribute(char *attribute, __va_list ap);
extern int	vjob_cancel(job_t *job, __va_list ap);

#ifdef __cplusplus
}
#endif

#endif /* !_JOB_H */
