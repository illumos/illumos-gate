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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_NETPR_H
#define	_NETPR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	BSD	0
#define	TCP	1
#define	NOBANNER	0
#define	BANNER	1

#define	CONTROL_FIRST	0
#define	DATA_FIRST	1

#define	ERRORMSG	0
#define	OKMSG		1

#define	DEST_SEP	":"

#define	MAX_REQ_ID	3

#define	ASCII_UULONG_MAX 22

#define	XFER_REQUEST	2	/* \2printer\n */
#define	XFER_CLEANUP	1 	/* \1 */
#define	XFER_CONTROL	2	/* \2size name\n */
#define	XFER_DATA	3	/* \3size name\n */
#define	PRINT_REQUEST	1   	/* \1printer\n */
#define	REMOVE_REQUEST	5   	/* \5printer person [users|jobs ...]\n */
#define	SHOW_QUEUE_SHORT_REQUEST  3	/* \3printer [users|jobs ...]\n */
#define	SHOW_QUEUE_LONG_REQUEST  4	/* \4printer [users|jobs ...]\n */


#define	E_SUCCESS			0
#define	E_FAILURE			1
#define	E_SYSTEM_ERROR			2
#define	E_BAD_FILE			3
#define	E_BAD_INPUT			4
#define	E_SYSTEM_ERR			5
#define	E_SEND_OK			6
#define	E_RETRY				129
#define	E_SIGPIPE			130


#define	NETWORK_ERROR_UNKNOWN		20
#define	NETWORK_ERROR_HOST		21
#define	NETWORK_ERROR_SERVICE		22
#define	NETWORK_ERROR_PORT		23
#define	NETWORK_ERROR_SEND_RESPONSE	24
#define	NETWORK_ERROR_SEND_FAILED	25
#define	NETWORK_ERROR_MSG_FAILED	26
#define	NETWORK_ERROR_WRITE_FAILED	27
#define	NETWORK_PRINTER_REFUSED_CONN	28
#define	NETWORK_READ_RESPONSE_FAILED	29


#define	MALLOC	(int size, char * msg)	\
	{ \
		printf("File %s line %d\n", __FILE__, __LINE__); \
		printf("malloc: size: <%d>, for <%s>\n"); \
		malloc(size); \
	}


typedef struct np_data np_data_t;
typedef struct np_bsdjob np_bsdjob_t;
typedef struct job	np_job_t;
typedef struct np_tcp_job np_tcpjob_t;

/*
 * Contains the input data for this job.
 * Data is independent of protocol
 */

struct job {
	char	*filename;
	char	*request_id;
	char	*printer;
	char	*dest;
	char	*title;
	int	protocol;
	char	*username;
	int	timeout;
	int	banner;
	int	filesize;
};

struct np_tcp_job {
	np_job_t * gen_data;
	char * np_port;
	char * np_host;
};

struct np_data {
	char	*np_dfAfilename;
	char	*np_path_file;	/* /<path>/<filename> we are printing 	*/
	long	np_data_size;	/* using stat, XXX mmap better??	*/
	char	*jobfile_data;
};


struct np_bsdjob {
	char		*np_filename;
	char 		*np_request_id;
	char		*np_printer;
	char		*np_destination;
	char		*np_title;
	char		*np_username;
	int		np_timeout;
	int		np_banner;
	char		*np_host;
	int		np_print_order;
	char		*np_cfAfilename;
	char		*np_cfAfile;
	uint		np_cfAfilesize;
	char		np_df_letter;		/* [A-Z][a-z] use this one */
	np_data_t	*np_data;
};

extern char * long2str(long, char *);
extern void null_sighandler(int);
extern int open_network(char *, int);
extern int xfer_file(int, caddr_t, int, int);
extern int add_bsd_file(char *, np_bsdjob_t *);
extern int start_bsd_job(int, char *);
extern void done_and_close(int);
extern void panic();
extern char * alloc_str(char *);
extern np_bsdjob_t * create_bsd_job(np_job_t *, int, int);
extern np_tcpjob_t * create_tcp_job(np_job_t *, int);
extern int net_send_cmd(int, char *, ...);
extern np_job_t * init_job(void);
extern int bsd_print(int, caddr_t, np_bsdjob_t *);
extern int tcp_print(int, caddr_t, np_tcpjob_t *);
extern int tcp_open(char *, np_tcpjob_t *, int);
extern void tell_lptell(int, char *, ...);
extern int net_open(char *, int);
extern void parse_dest(char *, char **, char **, char *);
extern int check_file(char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _NETPR_H */
