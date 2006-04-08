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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kstat.h>

#include <sys/scfd/scfparam.h>


/*
 * for kstat_named_create(9F)
 */
typedef struct _scf_kstat_named_list {
	char		*name;
	uchar_t		data_type;
} scf_kstat_named_list;

static scf_kstat_named_list scf_kstat_system_list[] = {
	{SCF_STATUS_KSTAT_NAMED,	KSTAT_DATA_CHAR},
	{SCF_BOOT_MODE_KSTAT_NAMED,	KSTAT_DATA_CHAR},
	{SCF_SECURE_MODE_KSTAT_NAMED,	KSTAT_DATA_CHAR},
	{SCF_EVENT_KSTAT_NAMED,		KSTAT_DATA_CHAR},
	{SCF_ALIVE_KSTAT_NAMED,		KSTAT_DATA_CHAR},
};


/*
 * prototype
 */
static	kstat_t	*scf_kstat_named_init(char *name,
	scf_kstat_named_list *kstat_list, int ndata,
	int (*update)(struct kstat *, int));
static	int	scf_kstat_sys_update(kstat_t *ksp, int rw);


/*
 * from scf_attach()
 */
/* DDI_ATTACH */
void
scf_kstat_init()
{
#define	SCF_FUNC_NAME		"scf_kstat_init() "
	scf_kstat_private_t	*private;

	ASSERT(MUTEX_HELD(&scf_comtbl.attach_mutex));

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": start");

	private = scf_comtbl.kstat_private =
		kmem_zalloc(sizeof (scf_kstat_private_t), KM_SLEEP);

	/* NAMED state */
	private->ksp_scf = scf_kstat_named_init(SCF_SYSTEM_KSTAT_NAME,
		scf_kstat_system_list, SCF_KSTAT_SYS_NAMED_NDATA,
		scf_kstat_sys_update);

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": end");
}


/*
 * from scf_detach()
 */
/* DDI_DETACH */
void
scf_kstat_fini()
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_kstat_fini() "
	scf_kstat_private_t	*private = scf_comtbl.kstat_private;

	ASSERT(MUTEX_HELD(&scf_comtbl.attach_mutex));

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": start");

	if (private->ksp_scf != NULL) {
		kstat_delete(private->ksp_scf);
	}

	kmem_free(private, sizeof (scf_kstat_private_t));

	scf_comtbl.kstat_private = NULL;

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": end");
}


/*
 * scf_kstat_named_init()
 *	  kstat_create(KSTAT_TYPE_NAMED) + kstat_named_init() + kstat_install()
 */
static kstat_t *
scf_kstat_named_init(char *name, scf_kstat_named_list *kstat_list, int ndata,
	int (*update)(struct kstat *, int))
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_kstat_named_init() "
	kstat_t			*scf_ksp;
	kstat_named_t		*scf_named_ksp;
	int			ii;

	ASSERT(MUTEX_HELD(&scf_comtbl.attach_mutex));

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": start");

	scf_ksp = kstat_create(SCF_DRIVER_NAME, 0, name, "misc",
		KSTAT_TYPE_NAMED, ndata, KSTAT_FLAG_PERSISTENT);
	if (scf_ksp == NULL) {
		cmn_err(CE_WARN, "%s: kstat_create failed.", scf_driver_name);
		return (NULL);
	}
	scf_named_ksp = (kstat_named_t *)(scf_ksp->ks_data);

	/*
	 * initialize the named kstat
	 */
	for (ii = 0; ii < ndata; ii++, scf_named_ksp++) {
		kstat_named_init(scf_named_ksp, kstat_list[ii].name,
			kstat_list[ii].data_type);
	}

	scf_ksp->ks_update = update;
	scf_ksp->ks_lock = (void *)&(scf_comtbl.all_mutex);

	scf_ksp->ks_private = &scf_comtbl;

	kstat_install(scf_ksp);

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": end");
	return (scf_ksp);
}


/*
 * "scf" update
 */
static int
scf_kstat_sys_update(kstat_t *ksp, int rw)
{
#undef	SCF_FUNC_NAME
#define	SCF_FUNC_NAME		"scf_kstat_sys_update() "
	kstat_named_t		*sysksp;
	scf_comtbl_t		*softsp;

	ASSERT(MUTEX_HELD(&scf_comtbl.all_mutex));

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": start");

	sysksp = (kstat_named_t *)ksp->ks_data;
	softsp = (scf_comtbl_t *)ksp->ks_private;

	/* this is a read-only kstat */
	if (rw == KSTAT_WRITE) {
		return (EACCES);
	}

	if (softsp->scf_status == SCF_STATUS_ONLINE) {
		sysksp[SCF_KSTAT_SYS_NAMED_STATUS].value.c[0] =
			SCF_STAT_STATUS_ONLINE;
	} else {
		sysksp[SCF_KSTAT_SYS_NAMED_STATUS].value.c[0] =
			SCF_STAT_STATUS_OFFLINE;
	}

	if ((softsp->scf_mode_sw & STATUS_BOOT_MODE) == STATUS_MODE_AUTO_BOOT) {
		sysksp[SCF_KSTAT_SYS_NAMED_BOOT_MODE].value.c[0] =
			SCF_STAT_MODE_LOCK;
	} else {
		sysksp[SCF_KSTAT_SYS_NAMED_BOOT_MODE].value.c[0] =
			SCF_STAT_MODE_UNLOCK;
	}

	if ((softsp->scf_mode_sw & STATUS_SECURE_MODE) == STATUS_MODE_LOCK) {
		sysksp[SCF_KSTAT_SYS_NAMED_SECURE_MODE].value.c[0] =
			SCF_STAT_MODE_AUTO_BOOT;
	} else {
		sysksp[SCF_KSTAT_SYS_NAMED_SECURE_MODE].value.c[0] =
			SCF_STAT_MODE_OBP_STOP;
	}

	sysksp[SCF_KSTAT_SYS_NAMED_EVENT].value.c[0] =
		(char)softsp->last_event[4];
	sysksp[SCF_KSTAT_SYS_NAMED_ALIVE].value.c[0] =
		softsp->alive_running;

	SCFDBGMSG(SCF_DBGFLAG_KSTAT, SCF_FUNC_NAME ": end");
	return (0);
}
