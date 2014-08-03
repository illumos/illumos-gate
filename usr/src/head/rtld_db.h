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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_RTLD_DB_H
#define	_RTLD_DB_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/lwp.h>
#include <sys/elf.h>
#include <link.h>
#include <proc_service.h>


/*
 * librtld_db interface versions
 */
#define	RD_VERSION1	1
#define	RD_VERSION2	2
#define	RD_VERSION3	3
#define	RD_VERSION4	4
#define	RD_VERSION	RD_VERSION4

typedef enum {
	RD_ERR,		/* generic */
	RD_OK,		/* generic "call" succeeded */
	RD_NOCAPAB,	/* capability not available */
	RD_DBERR,	/* import service failed */
	RD_NOBASE,	/* 5.x: aux tag AT_BASE not found */
	RD_NODYNAM,	/* symbol 'DYNAMIC' not found */
	RD_NOMAPS	/* link-maps are not yet available */
} rd_err_e;


/*
 * ways that the event notification can take place:
 */
typedef enum {
	RD_NOTIFY_BPT,		/* set break-point at address */
	RD_NOTIFY_AUTOBPT,	/* 4.x compat. not used in 5.x */
	RD_NOTIFY_SYSCALL	/* watch for syscall */
} rd_notify_e;

/*
 * information on ways that the event notification can take place:
 */
typedef struct rd_notify {
	rd_notify_e	type;
	union {
		psaddr_t	bptaddr;	/* break point address */
		long		syscallno;	/* system call id */
	} u;
} rd_notify_t;

/*
 * information about event instance:
 */
typedef enum {
	RD_NOSTATE = 0,		/* no state information */
	RD_CONSISTENT,		/* link-maps are stable */
	RD_ADD,			/* currently adding object to link-maps */
	RD_DELETE		/* currently deleteing object from link-maps */
} rd_state_e;

typedef struct rd_event_msg {
	rd_event_e	type;
	union {
		rd_state_e	state;	/* for DLACTIVITY */
	} u;
} rd_event_msg_t;


/*
 * iteration over load objects
 */
typedef struct rd_loadobj {
	psaddr_t	rl_nameaddr;	/* address of the name in user space */
	unsigned	rl_flags;
	psaddr_t	rl_base;	/* base of address of code */
	psaddr_t	rl_data_base;	/* base of address of data */
	Lmid_t		rl_lmident;	/* ident of link map */
	psaddr_t	rl_refnameaddr;	/* reference name of filter in user */
					/* space.  If non null object is a */
					/* filter. */
	psaddr_t	rl_plt_base;	/* These fields are present for 4.x */
	unsigned	rl_plt_size;	/* compatibility and are not */
					/* currently used  in SunOS5.x */
	psaddr_t	rl_bend;	/* end of image (text+data+bss) */
	psaddr_t	rl_padstart;	/* start of padding */
	psaddr_t	rl_padend;	/* end of image after padding */
	psaddr_t	rl_dynamic;	/* points to the DYNAMIC section */
					/* in the target process */
	unsigned long	rl_tlsmodid;	/* module ID for TLS references */
} rd_loadobj_t;

/*
 * Values for rl_flags
 */
#define	RD_FLG_MEM_OBJECT	0x0001	/* Identifies this object as */
					/* originating from a relocatable */
					/* module which was dynamically */
					/* loaded */

/*
 * Commands for rd_ctl()
 */
#define	RD_CTL_SET_HELPPATH	0x01	/* Set the path used to find helpers */

typedef struct rd_agent rd_agent_t;
typedef int rl_iter_f(const rd_loadobj_t *, void *);


/*
 * PLT skipping
 */
typedef enum {
    RD_RESOLVE_NONE,		/* don't do anything special */
    RD_RESOLVE_STEP,		/* step 'pi_nstep' instructions */
    RD_RESOLVE_TARGET,		/* resolved target is in 'pi_target' */
    RD_RESOLVE_TARGET_STEP	/* put a bpt on target, then step nstep times */
} rd_skip_e;


typedef struct rd_plt_info {
	rd_skip_e	pi_skip_method;
	long		pi_nstep;
	psaddr_t	pi_target;
	psaddr_t	pi_baddr;
	unsigned int	pi_flags;
} rd_plt_info_t;


/*
 * Values for pi_flags
 */
#define	RD_FLG_PI_PLTBOUND	0x0001	/* Indicates that the PLT */
					/* has been bound - and that */
					/* pi_baddr will contain its */
					/* destination address */

struct	ps_prochandle;

/*
 * librtld_db.so entry points
 */
extern void		rd_delete(rd_agent_t *);
extern char		*rd_errstr(rd_err_e rderr);
extern rd_err_e		rd_event_addr(rd_agent_t *, rd_event_e, rd_notify_t *);
extern rd_err_e		rd_event_enable(rd_agent_t *, int);
extern rd_err_e		rd_event_getmsg(rd_agent_t *, rd_event_msg_t *);
extern rd_err_e		rd_init(int);
extern rd_err_e		rd_ctl(int, void *);
extern rd_err_e		rd_loadobj_iter(rd_agent_t *, rl_iter_f *,
				void *);
extern void		rd_log(const int);
extern rd_agent_t	*rd_new(struct ps_prochandle *);
extern rd_err_e		rd_objpad_enable(struct rd_agent *, size_t);
extern rd_err_e		rd_plt_resolution(rd_agent_t *, psaddr_t, lwpid_t,
				psaddr_t, rd_plt_info_t *);
extern rd_err_e		rd_get_dyns(rd_agent_t *, psaddr_t, void **, size_t *);
extern rd_err_e		rd_reset(struct rd_agent *);

#ifdef	__cplusplus
}
#endif

#endif	/* _RTLD_DB_H */
