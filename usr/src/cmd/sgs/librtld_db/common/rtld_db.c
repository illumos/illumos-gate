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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include	<stdlib.h>
#include	<stdio.h>
#include	<string.h>
#include	<proc_service.h>
#include	<link.h>
#include	<rtld_db.h>
#include	<rtld.h>
#include	<_rtld_db.h>
#include	<msg.h>
#include	<sys/param.h>

/*
 * Mutex to protect global data
 */
mutex_t	glob_mutex = DEFAULTMUTEX;
int	rtld_db_version = RD_VERSION1;
int	rtld_db_logging = 0;
char	rtld_db_helper_path[MAXPATHLEN];


void
rd_log(const int on_off)
{
	(void) mutex_lock(&glob_mutex);
	rtld_db_logging = on_off;
	(void) mutex_unlock(&glob_mutex);
	LOG(ps_plog(MSG_ORIG(MSG_DB_LOGENABLE)));
}

/*
 * Versioning Notes.
 *
 * The following have been added as the versions of librtld_db
 * have grown:
 *
 *	RD_VERSION1:
 *		o baseline version
 *
 *	RD_VERSION2:
 *		o added support for the use of the AT_SUN_LDBASE auxvector
 *		  to find the initialial debugging (r_debug) structures
 *		  in ld.so.1
 *		o added the rl_dynamic field to rd_loadobj_t
 *		o added the RD_FLG_MEM_OBJECT to be used with the
 *		  rl_dynamic->rl_flags field.
 *
 *	RD_VERSION3:
 *		o added the following fields/flags to the rd_plt_info_t
 *		  type:
 *			pi_baddr	- bound address of PLT (if bound)
 *			pi_flags	- flag field
 *			RD_FLG_PI_PLTBOUND	(flag for pi_flags)
 *				if set - the PLT is bound and pi_baddr
 *				is filled in with the destination of the PLT.
 *
 *	RD_VERSION4:
 *		o added the following field to the rd_loadobj_t structure:
 *			rl_tlsmodid	- module ID for TLS references
 */
rd_err_e
rd_init(int version)
{
	if ((version < RD_VERSION1) ||
	    (version > RD_VERSION))
		return (RD_NOCAPAB);
	rtld_db_version = version;
	LOG(ps_plog(MSG_ORIG(MSG_DB_RDINIT), rtld_db_version));

	return (RD_OK);
}

rd_err_e
rd_ctl(int cmd, void *arg)
{
	if (cmd != RD_CTL_SET_HELPPATH || arg == NULL ||
	    strlen((char *)arg) >= MAXPATHLEN)
		return (RD_ERR);

	(void) strcpy(rtld_db_helper_path, (char *)arg);

	return (RD_OK);
}

rd_err_e
rd_get_dyns(rd_agent_t *rap, psaddr_t addr, void **dynpp, size_t *dynpp_sz)
{
	if (rap->rd_helper.rh_ops != NULL)
		return (rap->rd_helper.rh_ops->rho_get_dyns(
		    rap->rd_helper.rh_data, addr, dynpp, dynpp_sz));

#ifdef _LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		return (_rd_get_dyns64(rap,
		    addr, (Elf64_Dyn **)dynpp, dynpp_sz));
	else
#endif
		return (_rd_get_dyns32(rap,
		    addr, (Dyn **)dynpp, dynpp_sz));
}

rd_err_e
rd_reset(struct rd_agent *rap)
{
	rd_err_e			err;

	RDAGLOCK(rap);

	rap->rd_flags = 0;

#ifdef _LP64
	/*
	 * Determine if client is 32-bit or 64-bit.
	 */
	if (ps_pdmodel(rap->rd_psp, &rap->rd_dmodel) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_DMLOOKFAIL)));
		RDAGUNLOCK(rap);
		return (RD_DBERR);
	}

	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = _rd_reset64(rap);
	else
#endif
		err = _rd_reset32(rap);

	RDAGUNLOCK(rap);
	return (err);
}


rd_agent_t *
rd_new(struct ps_prochandle *php)
{
	rd_agent_t	*rap;

	LOG(ps_plog(MSG_ORIG(MSG_DB_RDNEW), php));
	if ((rap = (rd_agent_t *)calloc(1, sizeof (rd_agent_t))) == NULL)
		return (0);

	rap->rd_psp = php;
	(void) mutex_init(&rap->rd_mutex, USYNC_THREAD, 0);
	if (rd_reset(rap) != RD_OK) {
		if (rap->rd_helper.rh_dlhandle != NULL) {
			rap->rd_helper.rh_ops->rho_fini(rap->rd_helper.rh_data);
			(void) dlclose(rap->rd_helper.rh_dlhandle);
		}
		free(rap);
		LOG(ps_plog(MSG_ORIG(MSG_DB_RESETFAIL)));
		return ((rd_agent_t *)0);
	}

	return (rap);
}


void
rd_delete(rd_agent_t *rap)
{
	LOG(ps_plog(MSG_ORIG(MSG_DB_RDDELETE), rap));
	if (rap->rd_helper.rh_dlhandle != NULL) {
		rap->rd_helper.rh_ops->rho_fini(rap->rd_helper.rh_data);
		(void) dlclose(rap->rd_helper.rh_dlhandle);
	}
	free(rap);
}


rd_err_e
rd_loadobj_iter(rd_agent_t *rap, rl_iter_f *cb, void *client_data)
{
	rd_err_e	err;

	RDAGLOCK(rap);

#ifdef _LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = _rd_loadobj_iter64(rap, cb, client_data);
	else
#endif
		err = _rd_loadobj_iter32(rap, cb, client_data);

	RDAGUNLOCK(rap);
	return (err);
}


rd_err_e
rd_plt_resolution(rd_agent_t *rap, psaddr_t pc, lwpid_t lwpid,
	psaddr_t pltbase, rd_plt_info_t *rpi)
{
	rd_err_e	err;
	RDAGLOCK(rap);
#ifdef	_LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = plt64_resolution(rap, pc, lwpid, pltbase,
		    rpi);
	else
#endif
		err = plt32_resolution(rap, pc, lwpid, pltbase,
		    rpi);
	RDAGUNLOCK(rap);
	return (err);
}

rd_err_e
rd_event_addr(rd_agent_t *rap, rd_event_e num, rd_notify_t *np)
{
	rd_err_e	rc = RD_OK;

	RDAGLOCK(rap);
	switch (num) {
	case RD_NONE:
		break;
	case RD_PREINIT:
		np->type = RD_NOTIFY_BPT;
		np->u.bptaddr = rap->rd_preinit;
		break;
	case RD_POSTINIT:
		np->type = RD_NOTIFY_BPT;
		np->u.bptaddr = rap->rd_postinit;
		break;
	case RD_DLACTIVITY:
		np->type = RD_NOTIFY_BPT;
		np->u.bptaddr = rap->rd_dlact;
		break;
	default:
		LOG(ps_plog(MSG_ORIG(MSG_DB_UNEXPEVENT), num));
		rc = RD_ERR;
		break;
	}
	if (rc == RD_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_RDEVENTADDR), num,
		    EC_ADDR(np->u.bptaddr)));
	}

	RDAGUNLOCK(rap);
	return (rc);
}


/* ARGSUSED 0 */
rd_err_e
rd_event_enable(rd_agent_t *rap, int onoff)
{
	rd_err_e	err;

	RDAGLOCK(rap);

#ifdef _LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = _rd_event_enable64(rap, onoff);
	else
#endif
		err = _rd_event_enable32(rap, onoff);

	RDAGUNLOCK(rap);
	return (err);
}


rd_err_e
rd_event_getmsg(rd_agent_t *rap, rd_event_msg_t *emsg)
{
	rd_err_e	err;

	RDAGLOCK(rap);

#ifdef _LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = _rd_event_getmsg64(rap, emsg);
	else
#endif
		err = _rd_event_getmsg32(rap, emsg);

	RDAGUNLOCK(rap);
	return (err);
}


rd_err_e
rd_binder_exit_addr(struct rd_agent *rap, const char *bname, psaddr_t *beaddr)
{
	ps_sym_t	sym;

	if (rap->rd_tbinder) {
		*beaddr = rap->rd_tbinder;
		return (RD_OK);
	}
	if (ps_pglobal_sym(rap->rd_psp, PS_OBJ_LDSO, bname, &sym) != PS_OK) {
		LOG(ps_plog(MSG_ORIG(MSG_DB_UNFNDSYM),
		    bname));
		return (RD_ERR);
	}

	rap->rd_tbinder = *beaddr = sym.st_value + sym.st_size - M_BIND_ADJ;

	return (RD_OK);
}


rd_err_e
rd_objpad_enable(struct rd_agent *rap, size_t padsize)
{
	rd_err_e	err;

	RDAGLOCK(rap);

#ifdef _LP64
	if (rap->rd_dmodel == PR_MODEL_LP64)
		err = _rd_objpad_enable64(rap, padsize);
	else
#endif
		err = _rd_objpad_enable32(rap, padsize);

	RDAGUNLOCK(rap);
	return (err);
}


char *
rd_errstr(rd_err_e rderr)
{
	/*
	 * Convert an 'rd_err_e' to a string
	 */
	switch (rderr) {
	case RD_OK:
		return ((char *)MSG_ORIG(MSG_ER_OK));
	case RD_ERR:
		return ((char *)MSG_ORIG(MSG_ER_ERR));
	case RD_DBERR:
		return ((char *)MSG_ORIG(MSG_ER_DBERR));
	case RD_NOCAPAB:
		return ((char *)MSG_ORIG(MSG_ER_NOCAPAB));
	case RD_NODYNAM:
		return ((char *)MSG_ORIG(MSG_ER_NODYNAM));
	case RD_NOBASE:
		return ((char *)MSG_ORIG(MSG_ER_NOBASE));
	case RD_NOMAPS:
		return ((char *)MSG_ORIG(MSG_ER_NOMAPS));
	default:
		return ((char *)MSG_ORIG(MSG_ER_DEFAULT));
	}
}
