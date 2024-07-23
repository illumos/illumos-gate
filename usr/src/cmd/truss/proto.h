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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

#ifndef	_PROTO_H
#define	_PROTO_H

#include <sys/procset.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* avoid a bit of stdio locking */
#define	fputc	putc_unlocked

/* force (via setvbuf()) a reasonably large output file buffer size */
#define	MYBUFSIZ	8192

/*
 * Function prototypes for most external functions.
 */

extern	private_t *get_private(void);
extern	void	*my_malloc(size_t, const char *);
extern	void	*my_realloc(void *, size_t, const char *);
extern	void	*my_calloc(size_t, size_t, const char *);
extern	void	make_pname(private_t *, id_t);
extern	int	requested(private_t *, int, int);
extern	int	jobcontrol(private_t *, int);
extern	int	signalled(private_t *, int, int);
extern	int	faulted(private_t *, int);
extern	int	sysentry(private_t *, int);
extern	int	sysexit(private_t *, int);
extern	void	showbuffer(private_t *, long, long);
extern	void	showbytes(const char *, int, char *);
extern	void	accumulate(timestruc_t *,
			const timestruc_t *, const timestruc_t *);

extern	const char *ioctlname(private_t *, uint_t);
extern	const char *ioctldatastruct(uint_t);
extern	const char *fcntlname(int);
extern	const char *sfsname(int);
extern	const char *si86name(int);
extern	const char *utscode(int);
extern	const char *openarg(private_t *, int);
extern	const char *whencearg(int);
extern	const char *msgflags(private_t *, int);
extern	const char *semflags(private_t *, int);
extern	const char *shmflags(private_t *, int);
extern	const char *msgcmd(int);
extern	const char *semcmd(int);
extern	const char *shmcmd(int);
extern	const char *strrdopt(int);
extern	const char *strevents(private_t *, int);
extern	const char *tiocflush(private_t *, int);
extern	const char *strflush(int);
extern	const char *mountflags(private_t *, int);
extern	const char *svfsflags(private_t *, ulong_t);
extern	const char *sconfname(int);
extern	const char *pathconfname(int);
extern	const char *fuiname(int);
extern	const char *fuflags(private_t *, int);
extern	const char *ipprotos(int);
extern	const char *rctlsyscode(int);
extern	const char *rctl_local_flags(private_t *, uint_t val);
extern	const char *rctl_local_action(private_t *, uint_t val);

extern	void	expound(private_t *, long, int);
extern	void	prtimestruc(private_t *, const char *, timestruc_t *);
extern	void	print_siginfo(private_t *, const siginfo_t *);

extern	void	Flush(void);
extern	void	Eserialize(void);
extern	void	Xserialize(void);
extern	void	procadd(pid_t, const char *lwplist);
extern	int	lwptrace(pid_t, lwpid_t);
extern	void	procdel(void);
extern	int	checkproc(private_t *);

extern	int	syslist(char *, sysset_t *, int *);
extern	int	siglist(private_t *, char *, sigset_t *, int *);
extern	int	fltlist(char *, fltset_t *, int *);
extern	int	fdlist(char *, fileset_t *);
extern	int	liblist(char *, int);

extern	char	*fetchstring(private_t *, long, int);
extern	void	show_cred(private_t *, int, int);
extern	void	errmsg(const char *, const char *);
extern	void	abend(const char *, const char *);

extern	void	outstring(private_t *, const char *);
extern	void	grow(private_t *, int);

extern	void	show_procset(private_t *, long);
extern	const char *idtype_enum(private_t *, long);
extern	const char *woptions(private_t *, int);

extern	void	putpname(private_t *);
extern	void	timestamp(private_t *);

extern	const char *errname(int);
extern	const char *sysname(private_t *, int, int);
extern	const char *rawsigname(private_t *, int);
extern	const char *signame(private_t *, int);

extern	int	getsubcode(private_t *);
extern	int	maxsyscalls(void);
extern	int	nsubcodes(int);

extern	void	show_stat(private_t *, long);
extern	void	show_stat64_32(private_t *, long);

extern	void	establish_breakpoints(void);
extern	void	establish_stacks(void);
extern	void	reset_breakpoints(void);
extern	void	clear_breakpoints(void);
extern	int	function_trace(private_t *, int, int, int);
extern	void	reestablish_traps(void);
extern	void	report_htable_stats(void);

extern	const char *door_flags(private_t *, long);
extern	void	prt_ffg(private_t *, int, long);
extern	void	prt_ffd(private_t *, int, long);
extern	void	escape_string(private_t *, const char *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PROTO_H */
