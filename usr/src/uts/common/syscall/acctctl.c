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

#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/user.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/pathname.h>
#include <sys/modctl.h>
#include <sys/acctctl.h>
#include <sys/bitmap.h>
#include <sys/exacct.h>
#include <sys/policy.h>

/*
 * acctctl(2)
 *
 *   acctctl() provides the administrative interface to the extended accounting
 *   subsystem.  The process and task accounting facilities are configurable:
 *   resources can be individually specified for recording in the appropriate
 *   accounting file.
 *
 *   The current implementation of acctctl() requires that the process and task
 *   and flow files be distinct across all zones.
 *
 * Locking
 *   Each accounting species has an ac_info_t which contains a mutex,
 *   used to protect the ac_info_t's contents, and to serialize access to the
 *   appropriate file.
 */

static list_t exacct_globals_list;
static kmutex_t exacct_globals_list_lock;

static int
ac_state_set(ac_info_t *info, void *buf, size_t bufsz)
{
	int state;

	if (buf == NULL || (bufsz != sizeof (int)))
		return (EINVAL);

	if (copyin(buf, &state, bufsz) != 0)
		return (EFAULT);

	if (state != AC_ON && state != AC_OFF)
		return (EINVAL);

	mutex_enter(&info->ac_lock);
	info->ac_state = state;
	mutex_exit(&info->ac_lock);
	return (0);
}

static int
ac_state_get(ac_info_t *info, void *buf, size_t bufsz)
{
	if (buf == NULL || (bufsz != sizeof (int)))
		return (EINVAL);

	mutex_enter(&info->ac_lock);
	if (copyout(&info->ac_state, buf, bufsz) != 0) {
		mutex_exit(&info->ac_lock);
		return (EFAULT);
	}
	mutex_exit(&info->ac_lock);
	return (0);
}

static boolean_t
ac_file_in_use(vnode_t *vp)
{
	boolean_t in_use = B_FALSE;
	struct exacct_globals *acg;

	if (vp == NULL)
		return (B_FALSE);
	mutex_enter(&exacct_globals_list_lock);
	/*
	 * Start off by grabbing all locks.
	 */
	for (acg = list_head(&exacct_globals_list); acg != NULL;
	    acg = list_next(&exacct_globals_list, acg)) {
		mutex_enter(&acg->ac_proc.ac_lock);
		mutex_enter(&acg->ac_task.ac_lock);
		mutex_enter(&acg->ac_flow.ac_lock);
		mutex_enter(&acg->ac_net.ac_lock);
	}

	for (acg = list_head(&exacct_globals_list); !in_use && acg != NULL;
	    acg = list_next(&exacct_globals_list, acg)) {
		/*
		 * We need to verify that we aren't already using this file for
		 * accounting in any zone.
		 */
		if (vn_compare(acg->ac_proc.ac_vnode, vp) ||
		    vn_compare(acg->ac_task.ac_vnode, vp) ||
		    vn_compare(acg->ac_flow.ac_vnode, vp) ||
		    vn_compare(acg->ac_net.ac_vnode, vp))
			in_use = B_TRUE;
	}

	/*
	 * Drop all locks.
	 */
	for (acg = list_head(&exacct_globals_list); acg != NULL;
	    acg = list_next(&exacct_globals_list, acg)) {
		mutex_exit(&acg->ac_proc.ac_lock);
		mutex_exit(&acg->ac_task.ac_lock);
		mutex_exit(&acg->ac_flow.ac_lock);
		mutex_exit(&acg->ac_net.ac_lock);
	}
	mutex_exit(&exacct_globals_list_lock);
	return (in_use);
}

static int
ac_file_set(ac_info_t *info, void *ubuf, size_t bufsz)
{
	int error = 0;
	void *kbuf;
	void *namebuf;
	int namelen;
	vnode_t *vp;
	void *hdr;
	size_t hdrsize;
	vattr_t va;

	if (ubuf == NULL) {
		mutex_enter(&info->ac_lock);

		/*
		 * Closing accounting file
		 */
		if (info->ac_vnode != NULL) {
			error = VOP_CLOSE(info->ac_vnode, FWRITE, 1, 0,
			    CRED(), NULL);
			if (error) {
				mutex_exit(&info->ac_lock);
				return (error);
			}
			VN_RELE(info->ac_vnode);
			info->ac_vnode = NULL;
		}
		if (info->ac_file != NULL) {
			kmem_free(info->ac_file, strlen(info->ac_file) + 1);
			info->ac_file = NULL;
		}

		mutex_exit(&info->ac_lock);
		return (error);
	}

	if (bufsz < 2 || bufsz > MAXPATHLEN)
		return (EINVAL);

	/*
	 * We have to copy in the whole buffer since we can't tell the length
	 * of the string in user's address space.
	 */
	kbuf = kmem_zalloc(bufsz, KM_SLEEP);
	if ((error = copyinstr((char *)ubuf, (char *)kbuf, bufsz, NULL)) != 0) {
		kmem_free(kbuf, bufsz);
		return (error);
	}
	if (*((char *)kbuf) != '/') {
		kmem_free(kbuf, bufsz);
		return (EINVAL);
	}

	/*
	 * Now, allocate the space where we are going to save the
	 * name of the accounting file and kmem_free kbuf. We have to do this
	 * now because it is not good to sleep in kmem_alloc() while
	 * holding ac_info's lock.
	 */
	namelen = strlen(kbuf) + 1;
	namebuf = kmem_alloc(namelen, KM_SLEEP);
	(void) strcpy(namebuf, kbuf);
	kmem_free(kbuf, bufsz);

	/*
	 * Check if this file already exists.
	 */
	error = lookupname(namebuf, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);

	/*
	 * Check if the file is already in use.
	 */
	if (!error) {
		if (ac_file_in_use(vp)) {
			/*
			 * If we're already using it then return EBUSY
			 */
			kmem_free(namebuf, namelen);
			VN_RELE(vp);
			return (EBUSY);
		}
		VN_RELE(vp);
	}

	/*
	 * Create an exacct header here because exacct_create_header() may
	 * sleep so we should not be holding ac_lock. At this point we cannot
	 * reliably know if we need the header or not, so we may end up not
	 * using the header.
	 */
	hdr = exacct_create_header(&hdrsize);

	/*
	 * Now, grab info's ac_lock and try to set up everything.
	 */
	mutex_enter(&info->ac_lock);

	if ((error = vn_open(namebuf, UIO_SYSSPACE,
	    FCREAT | FWRITE | FOFFMAX, 0600, &vp, CRCREAT, 0)) != 0) {
		mutex_exit(&info->ac_lock);
		kmem_free(namebuf, namelen);
		kmem_free(hdr, hdrsize);
		return (error);
	}

	if (vp->v_type != VREG) {
		VN_RELE(vp);
		mutex_exit(&info->ac_lock);
		kmem_free(namebuf, namelen);
		kmem_free(hdr, hdrsize);
		return (EACCES);
	}

	if (info->ac_vnode != NULL) {
		/*
		 * Switch from an old file to a new file by swapping
		 * their vnode pointers.
		 */
		vnode_t *oldvp;
		oldvp = info->ac_vnode;
		info->ac_vnode = vp;
		vp = oldvp;
	} else {
		/*
		 * Start writing accounting records to a new file.
		 */
		info->ac_vnode = vp;
		vp = NULL;
	}
	if (vp) {
		/*
		 * We still need to close the old file.
		 */
		if ((error = VOP_CLOSE(vp, FWRITE, 1, 0, CRED(), NULL)) != 0) {
			VN_RELE(vp);
			mutex_exit(&info->ac_lock);
			kmem_free(namebuf, namelen);
			kmem_free(hdr, hdrsize);
			return (error);
		}
		VN_RELE(vp);
		if (info->ac_file != NULL) {
			kmem_free(info->ac_file,
			    strlen(info->ac_file) + 1);
			info->ac_file = NULL;
		}
	}
	info->ac_file = namebuf;

	/*
	 * Write the exacct header only if the file is empty.
	 */
	error = VOP_GETATTR(info->ac_vnode, &va, AT_SIZE, CRED(), NULL);
	if (error == 0 && va.va_size == 0)
		error = exacct_write_header(info, hdr, hdrsize);

	mutex_exit(&info->ac_lock);
	kmem_free(hdr, hdrsize);
	return (error);
}

static int
ac_file_get(ac_info_t *info, void *buf, size_t bufsz)
{
	int error = 0;
	vnode_t *vnode;
	char *file;

	mutex_enter(&info->ac_lock);
	file = info->ac_file;
	vnode = info->ac_vnode;

	if (file == NULL || vnode == NULL) {
		mutex_exit(&info->ac_lock);
		return (ENOTACTIVE);
	}

	if (strlen(file) >= bufsz)
		error = ENOMEM;
	else
		error = copyoutstr(file, buf, MAXPATHLEN, NULL);

	mutex_exit(&info->ac_lock);
	return (error);
}

static int
ac_res_set(ac_info_t *info, void *buf, size_t bufsz, int maxres)
{
	ac_res_t *res;
	ac_res_t *tmp;
	ulong_t *maskp;
	int id;
	uint_t counter = 0;

	/*
	 * Validate that a non-zero buffer, sized within limits and to an
	 * integral number of ac_res_t's has been specified.
	 */
	if (bufsz == 0 ||
	    bufsz > sizeof (ac_res_t) * (AC_MAX_RES + 1) ||
	    (bufsz / sizeof (ac_res_t)) * sizeof (ac_res_t) != bufsz)
		return (EINVAL);

	tmp = res = kmem_alloc(bufsz, KM_SLEEP);
	if (copyin(buf, res, bufsz) != 0) {
		kmem_free(res, bufsz);
		return (EFAULT);
	}

	maskp = (ulong_t *)&info->ac_mask;

	mutex_enter(&info->ac_lock);
	while ((id = tmp->ar_id) != AC_NONE && counter < maxres + 1) {
		if (id > maxres || id < 0) {
			mutex_exit(&info->ac_lock);
			kmem_free(res, bufsz);
			return (EINVAL);
		}
		if (tmp->ar_state == AC_ON) {
			BT_SET(maskp, id);
		} else if (tmp->ar_state == AC_OFF) {
			BT_CLEAR(maskp, id);
		} else {
			mutex_exit(&info->ac_lock);
			kmem_free(res, bufsz);
			return (EINVAL);
		}
		tmp++;
		counter++;
	}
	mutex_exit(&info->ac_lock);
	kmem_free(res, bufsz);
	return (0);
}

static int
ac_res_get(ac_info_t *info, void *buf, size_t bufsz, int maxres)
{
	int error = 0;
	ac_res_t *res;
	ac_res_t *tmp;
	size_t ressz = sizeof (ac_res_t) * (maxres + 1);
	ulong_t *maskp;
	int id;

	if (bufsz < ressz)
		return (EINVAL);
	tmp = res = kmem_alloc(ressz, KM_SLEEP);

	mutex_enter(&info->ac_lock);
	maskp = (ulong_t *)&info->ac_mask;
	for (id = 1; id <= maxres; id++) {
		tmp->ar_id = id;
		tmp->ar_state = BT_TEST(maskp, id);
		tmp++;
	}
	tmp->ar_id = AC_NONE;
	tmp->ar_state = AC_OFF;
	mutex_exit(&info->ac_lock);
	error = copyout(res, buf, ressz);
	kmem_free(res, ressz);
	return (error);
}

/*
 * acctctl()
 *
 * Overview
 *   acctctl() is the entry point for the acctctl(2) system call.
 *
 * Return values
 *   On successful completion, return 0; otherwise -1 is returned and errno is
 *   set appropriately.
 *
 * Caller's context
 *   Called from the system call path.
 */
int
acctctl(int cmd, void *buf, size_t bufsz)
{
	int error = 0;
	int mode = AC_MODE(cmd);
	int option = AC_OPTION(cmd);
	int maxres;
	ac_info_t *info;
	zone_t *zone = curproc->p_zone;
	struct exacct_globals *acg;

	acg = zone_getspecific(exacct_zone_key, zone);
	/*
	 * exacct_zone_key and associated per-zone state were initialized when
	 * the module was loaded.
	 */
	ASSERT(exacct_zone_key != ZONE_KEY_UNINITIALIZED);
	ASSERT(acg != NULL);

	switch (mode) {	/* sanity check */
	case AC_TASK:
		info = &acg->ac_task;
		maxres = AC_TASK_MAX_RES;
		break;
	case AC_PROC:
		info = &acg->ac_proc;
		maxres = AC_PROC_MAX_RES;
		break;
	/*
	 * Flow/net accounting isn't configurable in non-global
	 * zones, but we have this field on a per-zone basis for future
	 * expansion as well as the ability to return default "unset"
	 * values for the various AC_*_GET queries.  AC_*_SET commands
	 * fail with EPERM for AC_FLOW and AC_NET in non-global zones.
	 */
	case AC_FLOW:
		info = &acg->ac_flow;
		maxres = AC_FLOW_MAX_RES;
		break;
	case AC_NET:
		info = &acg->ac_net;
		maxres = AC_NET_MAX_RES;
		break;
	default:
		return (set_errno(EINVAL));
	}

	switch (option) {
	case AC_STATE_SET:
		if ((error = secpolicy_acct(CRED())) != 0)
			break;
		if ((mode == AC_FLOW || mode == AC_NET) &&
		    getzoneid() != GLOBAL_ZONEID) {
			error = EPERM;
			break;
		}
		error = ac_state_set(info, buf, bufsz);
		break;
	case AC_STATE_GET:
		error = ac_state_get(info, buf, bufsz);
		break;
	case AC_FILE_SET:
		if ((error = secpolicy_acct(CRED())) != 0)
			break;
		if ((mode == AC_FLOW || mode == AC_NET) &&
		    getzoneid() != GLOBAL_ZONEID) {
			error = EPERM;
			break;
		}
		error = ac_file_set(info, buf, bufsz);
		break;
	case AC_FILE_GET:
		error = ac_file_get(info, buf, bufsz);
		break;
	case AC_RES_SET:
		if ((error = secpolicy_acct(CRED())) != 0)
			break;
		if ((mode == AC_FLOW || mode == AC_NET) &&
		    getzoneid() != GLOBAL_ZONEID) {
			error = EPERM;
			break;
		}
		error = ac_res_set(info, buf, bufsz, maxres);
		break;
	case AC_RES_GET:
		error = ac_res_get(info, buf, bufsz, maxres);
		break;
	default:
		return (set_errno(EINVAL));
	}
	if (error)
		return (set_errno(error));
	return (0);
}

static struct sysent ac_sysent = {
	3,
	SE_NOUNLOAD | SE_ARGC | SE_32RVAL1,
	acctctl
};

static struct modlsys modlsys = {
	&mod_syscallops,
	"acctctl system call",
	&ac_sysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32,
	"32-bit acctctl system call",
	&ac_sysent
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

/* ARGSUSED */
static void *
exacct_zone_init(zoneid_t zoneid)
{
	struct exacct_globals *acg;

	acg = kmem_zalloc(sizeof (*acg), KM_SLEEP);
	mutex_enter(&exacct_globals_list_lock);
	list_insert_tail(&exacct_globals_list, acg);
	mutex_exit(&exacct_globals_list_lock);
	return (acg);
}

static void
exacct_free_info(ac_info_t *info)
{
	mutex_enter(&info->ac_lock);
	if (info->ac_vnode) {
		(void) VOP_CLOSE(info->ac_vnode, FWRITE, 1, 0, kcred, NULL);
		VN_RELE(info->ac_vnode);
		kmem_free(info->ac_file, strlen(info->ac_file) + 1);
	}
	info->ac_state = AC_OFF;
	info->ac_vnode = NULL;
	info->ac_file = NULL;
	mutex_exit(&info->ac_lock);
}

/* ARGSUSED */
static void
exacct_zone_shutdown(zoneid_t zoneid, void *data)
{
	struct exacct_globals *acg = data;

	/*
	 * The accounting files need to be closed during shutdown rather than
	 * destroy, since otherwise the filesystem they reside on may fail to
	 * unmount, thus causing the entire zone halt/reboot to fail.
	 */
	exacct_free_info(&acg->ac_proc);
	exacct_free_info(&acg->ac_task);
	exacct_free_info(&acg->ac_flow);
	exacct_free_info(&acg->ac_net);
}

/* ARGSUSED */
static void
exacct_zone_fini(zoneid_t zoneid, void *data)
{
	struct exacct_globals *acg = data;

	mutex_enter(&exacct_globals_list_lock);
	list_remove(&exacct_globals_list, acg);
	mutex_exit(&exacct_globals_list_lock);

	mutex_destroy(&acg->ac_proc.ac_lock);
	mutex_destroy(&acg->ac_task.ac_lock);
	mutex_destroy(&acg->ac_flow.ac_lock);
	mutex_destroy(&acg->ac_net.ac_lock);
	kmem_free(acg, sizeof (*acg));
}

int
_init()
{
	int error;

	mutex_init(&exacct_globals_list_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&exacct_globals_list, sizeof (struct exacct_globals),
	    offsetof(struct exacct_globals, ac_link));
	zone_key_create(&exacct_zone_key, exacct_zone_init,
	    exacct_zone_shutdown, exacct_zone_fini);

	if ((error = mod_install(&modlinkage)) != 0) {
		(void) zone_key_delete(exacct_zone_key);
		exacct_zone_key = ZONE_KEY_UNINITIALIZED;
		mutex_destroy(&exacct_globals_list_lock);
		list_destroy(&exacct_globals_list);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini()
{
	return (EBUSY);
}
