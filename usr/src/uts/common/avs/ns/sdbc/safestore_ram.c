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
 * RAM Safe Store Module
 */

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>

#include <sys/nsc_thread.h>
#include "sd_cache.h"
#include "sd_trace.h"
#include <sys/unistat/spcs_s.h>
#include <sys/unistat/spcs_s_k.h>
#include <sys/unistat/spcs_errors.h>

#include "safestore.h"
#include "safestore_impl.h"
#include "safestore_ram.h"

extern void _sd_print(int level, char *fmt, ...);

static int ss_ram_configure(ss_common_config_t *, spcs_s_info_t);
static int ss_ram_deconfigure(int);
static int ss_ram_getvdir(const ss_vdirkey_t *, ss_vdir_t *);
static int ss_ram_getvdirent(const ss_vdir_t *, ss_voldata_t *);
static int ss_ram_getvol(ss_voldata_t *);
static int ss_ram_setvol(const ss_voldata_t *);
static int ss_ram_getcdir(const ss_cdirkey_t *, ss_cdir_t *);
static int ss_ram_getcdirent(ss_cdir_t *, ss_centry_info_t *);
static int ss_ram_allocresource(int, int *, ss_resourcelist_t **);
static void ss_ram_deallocresource(ss_resource_t *);
static int ss_ram_getresource(ss_resourcelist_t **, ss_resource_t **);
static int ss_ram_getcentry(ss_centry_info_t *);
static int ss_ram_setcentry(const ss_centry_info_t *);
static int ss_ram_cblock_read(const ss_resource_t *, void *, int, int);
static int ss_ram_cblock_write(const ss_resource_t *, const void *, int, int);
static int ss_ram_ctl(uint_t, uintptr_t);


safestore_ops_t ss_ram_ops = {
	"safestore_ram",
	SS_M_RAM | SS_T_NONE,
	0,
	ss_ram_configure,
	ss_ram_deconfigure,
	ss_ram_getvdir,
	ss_ram_getvdirent,
	ss_ram_getvol,
	ss_ram_setvol,
	ss_ram_getcdir,
	ss_ram_getcdirent,
	ss_ram_allocresource,
	ss_ram_deallocresource,
	ss_ram_getresource,
	ss_ram_getcentry,
	ss_ram_setcentry,
	ss_ram_cblock_read,
	ss_ram_cblock_write,
	ss_ram_ctl
};

static void ss_ram_vol_deconfigure();
static int ss_ram_vol_configure(int);
static int ss_ram_wctl_configure();
static void ss_ram_wctl_deconfigure(void);
static int ss_ram_deconfigure_locked();

static kmutex_t ss_ram_config_lock;

static ss_common_config_t ss_ramcommon_config;
static ss_ram_config_t ss_ram_config;

static char default_cblock [8192];


#define	MEGABYTE (1024*1024)

void
ss_ram_init()
{
	mutex_init(&ss_ram_config_lock, NULL, MUTEX_DRIVER, NULL);
	bzero(&ss_ram_config, sizeof (ss_ram_config_t));
	bzero(&ss_ramcommon_config, sizeof (ss_common_config_t));
	sst_register_mod(&ss_ram_ops);

	ss_ram_config.ss_configured = SS_INITTED;
}

void
ss_ram_deinit()
{
	mutex_destroy(&ss_ram_config_lock);
	sst_unregister_mod(&ss_ram_ops);
}


/* ARGSUSED */
static int
ss_ram_configure(ss_common_config_t *clientptr, spcs_s_info_t kstatus)
{

	if (clientptr->ssc_wsize == 0) /* choose a default? */
		return (EINVAL);

	mutex_enter(&ss_ram_config_lock);

	/* read in the parameters */
	bcopy(clientptr, &ss_ramcommon_config, sizeof (ss_common_config_t));

	/* set the page size */
	ss_ramcommon_config.ssc_ss_psize = BLK_SIZE(1);

	/* initialize client page size if not set */
	if (ss_ramcommon_config.ssc_client_psize == 0)
		ss_ramcommon_config.ssc_client_psize =
					ss_ramcommon_config.ssc_ss_psize;

	/* setup volume directory */
	if (ss_ram_vol_configure(clientptr->ssc_maxfiles)) {
		(void) ss_ram_deconfigure_locked();
		mutex_exit(&ss_ram_config_lock);
		return (SDBC_ENONETMEM);
	}

	/* setup write q */
	if (ss_ram_wctl_configure()) {
		(void) ss_ram_deconfigure_locked();
		mutex_exit(&ss_ram_config_lock);
		return (SDBC_ENONETMEM);
	}

	if (ss_ramcommon_config.ssc_flag & SS_GENPATTERN) {
		(void) _sd_fill_pattern(default_cblock,
					ss_ramcommon_config.ssc_pattern,
					sizeof (default_cblock));
	}

	ss_ram_config.ss_configured = SS_CONFIGURED;
	/* update client */
	bcopy(&ss_ramcommon_config, clientptr, sizeof (ss_common_config_t));

	mutex_exit(&ss_ram_config_lock);
	return (SS_OK);
}

/* acquires the ss_ram_config_lock and calls ss_ram_deconfigure_locked() */
/* ARGSUSED */
static int
ss_ram_deconfigure(int dirty)
{
	int rc;

	if (ss_ram_config.ss_configured != SS_CONFIGURED)
		return (SS_ERR);

	mutex_enter(&ss_ram_config_lock);
	rc = ss_ram_deconfigure_locked();
	mutex_exit(&ss_ram_config_lock);

	return (rc);
}

/*
 * internal use only
 * caller should acquire config lock before calling this function
 */
static int
ss_ram_deconfigure_locked()
{
	ss_ram_wctl_deconfigure();
	ss_ram_vol_deconfigure();

	ss_ram_config.ss_configured = 0;
	return (SS_OK);
}

static int
ss_ram_getvdir(const ss_vdirkey_t *key, ss_vdir_t *vdir)
{
	ss_ram_vdir_t *ram_vdir = (ss_ram_vdir_t *)vdir;
	int rc = SS_OK;

	if ((key == NULL) || (vdir == NULL))
		return (SS_ERR);

	switch (key->vk_type) {
		case VDIR_ALL:
			ram_vdir->rv_type = VDIR_ALL;
			ram_vdir->rv_u.rv_all.rv_current =
						ss_ram_config.sn_volumes;
			ram_vdir->rv_u.rv_all.rv_end =
					ss_ram_config.sn_volumes +
					ss_ramcommon_config.ssc_maxfiles;
			break;
		case VDIR_VOL:
		case VDIR_NODE:
		default:
			rc = SS_ERR;
			break;
	}

	return (rc);
}


static int
ss_ram_getvdirent(const ss_vdir_t *vdir, ss_voldata_t *vol)
{
	int rc = SS_OK;

	ss_ram_vdir_t *ram_vdir = (ss_ram_vdir_t *)vdir;

	if (vol == NULL)
		return (SS_ERR);

	if (vdir == NULL)
		return (SS_ERR);

	switch (ram_vdir->rv_type) {
		case VDIR_ALL:
			if (ram_vdir->rv_u.rv_all.rv_current ==
					ram_vdir->rv_u.rv_all.rv_end) {
				rc = SS_EOF;
			} else {
				/* stuff client copy with token */
				vol->sv_vol = (ss_vol_t *)
					ram_vdir->rv_u.rv_all.rv_current++;

				/* get the volume data */
				rc = ss_ram_getvol(vol);
			}
			break;
		case VDIR_VOL:
		case VDIR_NODE:
		default:
			rc = SS_ERR;
			break;
	}

	return (rc);
}

static int
ss_ram_getvol(ss_voldata_t *voldata)
{
	ss_voldata_impl_t *ramvoldata;

	if (voldata == NULL)
		return (SS_ERR);

	/* get the pointer to the volume entry */
	ramvoldata = (ss_voldata_impl_t *)voldata->sv_vol;

	if (ramvoldata == NULL)
		return (SS_ERR);

	/* stuff the client structure from the ram entry */
	voldata->sv_cd = ramvoldata->svi_cd;
	voldata->sv_pinned = ramvoldata->svi_pinned;
	voldata->sv_attached = ramvoldata->svi_attached;
	voldata->sv_devidsz = ramvoldata->svi_devidsz;

	bcopy(ramvoldata->svi_volname, voldata->sv_volname,
				sizeof (voldata->sv_volname));

	bcopy(ramvoldata->svi_devid, voldata->sv_devid,
				sizeof (voldata->sv_devid));
	return (SS_OK);
}

static int
ss_ram_setvol(const ss_voldata_t *voldata)
{
	ss_voldata_impl_t *ramvoldata;

	if (voldata == NULL)
		return (SS_ERR);

	/* get the pointer to the volume entry */
	ramvoldata = (ss_voldata_impl_t *)voldata->sv_vol;

	if (ramvoldata == NULL)
		return (SS_ERR);

	/* load the volume entry from the client structure */
	ramvoldata->svi_cd = voldata->sv_cd;
	ramvoldata->svi_pinned = voldata->sv_pinned;
	ramvoldata->svi_attached = voldata->sv_attached;
	ramvoldata->svi_devidsz = voldata->sv_devidsz;
	bcopy(voldata->sv_volname, ramvoldata->svi_volname,
				sizeof (ramvoldata->svi_volname));

	bcopy(voldata->sv_devid, ramvoldata->svi_devid,
				sizeof (ramvoldata->svi_devid));
	return (SS_OK);
}

static int
ss_ram_getcdir(const ss_cdirkey_t *key, ss_cdir_t *cdir)
{
	ss_ram_cdir_t *ram_cdir = (ss_ram_cdir_t *)cdir;
	int rc = 0;

	if ((key == NULL) || (cdir == NULL))
		return (SS_ERR);

	switch (key->ck_type) {
		case CDIR_ALL:
			{ int blocks;

				blocks = ss_ramcommon_config.ssc_wsize /
					ss_ramcommon_config.ssc_client_psize;

				ram_cdir->rc_type = CDIR_ALL;
				ram_cdir->rc_u.rc_all.rc_current =
						ss_ram_config.sn_wr_cctl;
				ram_cdir->rc_u.rc_all.rc_end =
					ss_ram_config.sn_wr_cctl + blocks;
			}
			break;
		case CDIR_VOL:
		case CDIR_NODE:
		default:
			rc = SS_ERR;
			break;
	}

	return (rc);
}

static int
ss_ram_getcdirent(ss_cdir_t *cdir, ss_centry_info_t *centry)
{
	int rc = SS_OK;

	ss_ram_cdir_t *ram_cdir = (ss_ram_cdir_t *)cdir;

	if (centry == NULL)
		return (SS_ERR);

	if (cdir == NULL)
		return (SS_ERR);

	switch (ram_cdir->rc_type) {
		case CDIR_ALL:
			if (ram_cdir->rc_u.rc_all.rc_current ==
						ram_cdir->rc_u.rc_all.rc_end) {
				rc = SS_EOF;
			} else {
				/* stuff client copy with token */
				centry->sc_res = (ss_resource_t *)
					ram_cdir->rc_u.rc_all.rc_current++;

				/* get the centry data */
				rc = ss_ram_getcentry(centry);
			}
			break;
		case CDIR_VOL:
		case CDIR_NODE:
		default:
			rc = SS_ERR;
			break;
	}

	return (rc);
}

static int
ss_ram_allocresource(int need, int *stall, ss_resourcelist_t **reslist)
{
	if (reslist == NULL)
		return (SS_ERR);

	*reslist = ((ss_resourcelist_t *)ss_alloc_write(need, stall,
					&(ss_ram_config.sn_wr_queue)));
	if (*reslist == NULL)    /* do sync write */
		return (SS_ERR);

	return (SS_OK);
}

static void
ss_ram_deallocresource(ss_resource_t *res)
{
	ss_release_write((ss_wr_cctl_t *)res, &(ss_ram_config.sn_wr_queue));
}

static int
ss_ram_getresource(ss_resourcelist_t **reslist, ss_resource_t **res)
{
	if ((res == NULL) || (reslist == NULL)) {
		return (SS_ERR);
	}

	if (*reslist == NULL)
		return (SS_EOF);

	*res = (ss_resource_t *)(*reslist);
	*reslist = (ss_resourcelist_t *)
		((ss_wr_cctl_t *)(*reslist))->wc_next;

	return (SS_OK);
}

static int
ss_ram_getcentry(ss_centry_info_t *centry)
{
	ss_wr_cctl_t *wctl;
	ss_centry_info_impl_t *ramcentry = (ss_centry_info_impl_t *)centry;

	if (centry == NULL)
		return (SS_ERR);
	else
		wctl = (ss_wr_cctl_t *)centry->sc_res;

	if (wctl == NULL)
		return (SS_ERR);

	if (wctl->wc_gl_info)
		bcopy(wctl->wc_gl_info, ramcentry,
			sizeof (ss_centry_info_impl_t));
	else
		return (SS_ERR);

	return (SS_OK);
}

static int
ss_ram_setcentry(const ss_centry_info_t *centry)
{
	ss_wr_cctl_t *wctl;
	ss_centry_info_impl_t *ramcentry = (ss_centry_info_impl_t *)centry;

	if (centry == NULL)
		return (SS_ERR);
	else
		wctl = (ss_wr_cctl_t *)centry->sc_res;

	if (wctl == NULL)
		return (SS_ERR);

	if (wctl->wc_gl_info)
		bcopy(ramcentry, wctl->wc_gl_info,
				sizeof (ss_centry_info_impl_t));
	else
		return (SS_ERR);

	return (SS_OK);
}


static int
ss_ram_cblock_read(const ss_resource_t *res, void *buf,
				int count, int srcoffset)
{
	if ((res == NULL) || (buf == NULL))
		return (SS_ERR);

	if ((srcoffset < 0) ||
			(srcoffset > ss_ramcommon_config.ssc_client_psize))
		return (SS_ERR);

	bcopy(default_cblock + srcoffset, buf, count);

	return (SS_OK);
}

static int
ss_ram_cblock_write(const ss_resource_t *res,
			const void *buf, int count, int destoffset)
{
	if ((res == NULL) || (buf == NULL))
		return (SS_ERR);

	if ((destoffset < 0) ||
			(destoffset > ss_ramcommon_config.ssc_client_psize))
		return (SS_ERR);

	bcopy(buf, default_cblock + destoffset, count);

	return (SS_OK);
}

static int
ss_ram_ctl(uint_t cmd, uintptr_t arg)
{
	int rc = SS_OK;

	switch (cmd) {
		case SSIOC_STATS:
			((ssioc_stats_t *)arg)->wq_inq =
					ss_ram_config.sn_wr_queue.wq_inq;
			break;
		default:
			cmn_err(CE_WARN, "ss_nvs_ctl: cmd %x not supported",
							cmd);
			rc = ENOTTY;
			break;
	}

	return (rc);
}

static int
ss_ram_vol_configure(int maxvols)
{
	if ((ss_ram_config.sn_volumes = kmem_zalloc(maxvols *
			sizeof (ss_voldata_impl_t), KM_NOSLEEP)) == NULL)
		return (-1);

	return (0);
}

static void
ss_ram_vol_deconfigure()
{
	int maxvols = ss_ramcommon_config.ssc_maxfiles;

	if (ss_ram_config.sn_volumes)
		kmem_free(ss_ram_config.sn_volumes,
					maxvols * sizeof (ss_voldata_impl_t));
}

static int
ss_ram_wctl_configure()
{
	int blocks;
	ss_wr_cctl_t *wentry;
	static ss_centry_info_impl_t *gl;
	int i;

	blocks = ss_ramcommon_config.ssc_wsize /
			ss_ramcommon_config.ssc_client_psize;

	if ((ss_ram_config.sn_wr_cctl = (ss_wr_cctl_t *)
		kmem_zalloc(blocks * sizeof (ss_wr_cctl_t), KM_NOSLEEP))
								== NULL) {
		return (-1);
	}

	if ((ss_ram_config.sn_gl_centry_info = (ss_centry_info_impl_t *)
		kmem_zalloc(blocks * sizeof (ss_centry_info_impl_t),
					KM_NOSLEEP)) == NULL) {
		return (-1);
	}

	/*
	 * Mini-DSP: no write/ft area
	 * (ie forced_wrthru clear)
	 */

	if (_sdbc_writeq_configure(&(ss_ram_config.sn_wr_queue)) != 0)
		return (-1);

	gl = ss_ram_config.sn_gl_centry_info;

	wentry = ss_ram_config.sn_wr_cctl;
	for (i = 0; i < blocks; ++i, ++wentry) {
		wentry->wc_gl_info = gl++;
		ss_release_write(wentry, &(ss_ram_config.sn_wr_queue));
	}

	ss_ram_config.sn_wr_queue.wq_nentries = blocks;

	return (0);
}

static void
ss_ram_wctl_deconfigure()
{
	int blocks;

	_sdbc_writeq_deconfigure(&(ss_ram_config.sn_wr_queue));

	blocks = ss_ramcommon_config.ssc_wsize /
			ss_ramcommon_config.ssc_client_psize;

	if (ss_ram_config.sn_wr_cctl) {
		kmem_free(ss_ram_config.sn_wr_cctl,
				blocks * sizeof (ss_wr_cctl_t));
	}

	if (ss_ram_config.sn_gl_centry_info) {
		kmem_free(ss_ram_config.sn_gl_centry_info,
				blocks * sizeof (ss_centry_info_impl_t));
	}
}
