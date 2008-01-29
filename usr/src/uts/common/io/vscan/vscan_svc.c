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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/time.h>
#include <sys/varargs.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/cmn_err.h>
#include <sys/vnode.h>
#include <fs/fs_subr.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/sdt.h>
#include <sys/cred.h>
#include <sys/vscan.h>

#define	VS_TASKQ_NUM_THREADS	VS_DRV_MAX_FILES
#define	VS_EXT_RECURSE_DEPTH	8
#define	tolower(C)	(((C) >= 'A' && (C) <= 'Z') ? (C) - 'A' + 'a' : (C))

/* represents request received from filesystem - currently only use vp */
typedef struct vscan_fs_req {
	vnode_t *vsr_vp;
} vscan_fs_req_t;

/*
 * vscan_svc_files - table of files being scanned
 *
 * The index into this table is passed in the door call to
 * vscand. vscand uses the idx to determine which minor node
 * to open to read the file data. Within the kernel driver
 * the minor device number can thus be used to identify the
 * table index to get the appropriate vnode.
 *
 * Instance 0 is reserved for the daemon/driver control
 * interface: enable/configure/disable
 */
typedef struct vscan_file {
	vscan_fs_req_t vsf_req;
	uint32_t vsf_wait_count;
	kcondvar_t vsf_cv; /* wait for in progress scan */
	uint8_t vsf_quarantined;
	uint8_t vsf_modified;
	uint64_t vsf_size;
	timestruc_t vsf_mtime;
	vs_scanstamp_t vsf_scanstamp;
	uint32_t vsf_result;
	uint32_t vsf_access;
} vscan_file_t;

static vscan_file_t vscan_svc_files[VS_DRV_MAX_FILES + 1];
static kcondvar_t vscan_svc_cv; /* wait for slot in vscan_svc_files */
static int vscan_svc_wait_count = 0; /* # waiting for slot in vscan_svc_files */
static int vscan_svc_req_count = 0; /* # scan requests */

static taskq_t *vscan_svc_taskq = NULL;
static boolean_t vscan_svc_enabled = B_FALSE;

/*
 * vscan_svc_mutex protects the data pertaining to scan requests:
 * file table - vscan_svc_files
 * counts - vscan_svc_wait_count, vscan_svc_req_count
 */
static kmutex_t vscan_svc_mutex;

/*
 * vscan_svc_cfg_mutex protects the configuration data:
 * vscan_svc_config, vscan_svc_types
 */
static kmutex_t vscan_svc_cfg_mutex;

/* configuration data - for virus scan exemption */
static vs_config_t vscan_svc_config;
static char *vscan_svc_types[VS_TYPES_MAX];

/* local functions */
int vscan_svc_scan_file(vnode_t *, cred_t *, int);
void vscan_svc_taskq_callback(void *);
static int vscan_svc_exempt_file(vnode_t *, boolean_t *);
static int vscan_svc_exempt_filetype(char *);
static int vscan_svc_match_ext(char *, char *, int);
static int vscan_svc_do_scan(vscan_fs_req_t *);
static int vscan_svc_wait_for_scan(vnode_t *);
static int vscan_svc_insert_file(vscan_fs_req_t *);
static void vscan_svc_release_file(int);
static int vscan_svc_find_slot(void);
static void vscan_svc_process_scan_result(int);
static void vscan_svc_notify_scan_complete(int);
static int vscan_svc_getattr(int);
static int vscan_svc_setattr(int, int);

static vs_scan_req_t *vscan_svc_populate_req(int);
static void vscan_svc_parse_rsp(int, vs_scan_req_t *);


/*
 * vscan_svc_init
 */
int
vscan_svc_init()
{
	mutex_init(&vscan_svc_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vscan_svc_cfg_mutex, NULL, MUTEX_DRIVER, NULL);
	(void) memset(&vscan_svc_files, 0, sizeof (vscan_svc_files));
	cv_init(&vscan_svc_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*
 * vscan_svc_fini
 */
void
vscan_svc_fini()
{
	ASSERT(vscan_svc_enabled == B_FALSE);
	ASSERT(vscan_svc_in_use() == B_FALSE);

	cv_destroy(&vscan_svc_cv);
	mutex_destroy(&vscan_svc_mutex);
	mutex_destroy(&vscan_svc_cfg_mutex);
}

/*
 * vscan_svc_enable
 */
void
vscan_svc_enable(void)
{
	mutex_enter(&vscan_svc_mutex);
	vscan_svc_enabled = B_TRUE;

	if (vscan_svc_taskq == NULL) {
		if ((vscan_svc_taskq = taskq_create("vscan",
		    VS_TASKQ_NUM_THREADS, MINCLSYSPRI, 1,
		    INT_MAX, TASKQ_DYNAMIC)) == NULL) {
			cmn_err(CE_WARN, "All scan requests "
			    "will be processed synchronously");
		}
	}

	fs_vscan_register(vscan_svc_scan_file);
	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_disable
 */
void
vscan_svc_disable(void)
{
	mutex_enter(&vscan_svc_mutex);
	vscan_svc_enabled = B_FALSE;
	fs_vscan_register(NULL);

	if (vscan_svc_taskq) {
		taskq_destroy(vscan_svc_taskq);
		vscan_svc_taskq = NULL;
	}
	mutex_exit(&vscan_svc_mutex);
}



/*
 * vscan_svc_is_enabled
 */
boolean_t
vscan_svc_is_enabled()
{
	return (vscan_svc_enabled);
}


/*
 * vscan_svc_in_use
 *
 * The vscan driver is considered to be in use if it is
 * enabled or if there are in-progress scan requests.
 * Used to determine whether the driver can be unloaded.
 */
boolean_t
vscan_svc_in_use()
{
	boolean_t rc;

	mutex_enter(&vscan_svc_mutex);
	rc = (vscan_svc_enabled == B_TRUE) || (vscan_svc_req_count > 0);
	mutex_exit(&vscan_svc_mutex);

	return (rc);
}

/*
 * vscan_svc_get_vnode
 *
 * Get the file vnode indexed by idx.
 * Returns NULL if idx not valid.
 */
vnode_t *
vscan_svc_get_vnode(int idx)
{
	ASSERT(idx > 0);
	ASSERT(idx <= VS_DRV_MAX_FILES);

	if ((idx <= 0) || (idx > VS_DRV_MAX_FILES))
		return (NULL);
	else
		return (vscan_svc_files[idx].vsf_req.vsr_vp);
}


/*
 * vscan_svc_scan_file
 *
 * This function is the entry point for the file system to
 * request that a file be virus scanned.
 *
 * Asynchronous requests:
 * If an async scan request cannot be queued it is discarded.
 *   By definition the caller of an async request is not dependent
 *   on the outcome of the result. Although the file will thus
 *   not be scanned at this time, it will be scanned
 *   (synchronously) on subsequent access.
 *   This scenario should not occur during normal operation.
 *
 * Before queuing an async request do VN_HOLD(vp). VN_RELE(vp)
 *   will be done when the scan completes or if the request
 *   couldn't be queued.
 *
 * The vscan_fs_req_t, allocated to hold the request information
 * passed from the fs, will be free'd when the scan completes.
 */
int
vscan_svc_scan_file(vnode_t *vp, cred_t *cr, int async)
{
	int rc = 0;
	vscan_fs_req_t *req;
	boolean_t allow;

	mutex_enter(&vscan_svc_mutex);

	if ((vp == NULL) || (vp->v_path == NULL) || cr == NULL) {
		mutex_exit(&vscan_svc_mutex);
		return (0);
	}

	DTRACE_PROBE2(vscan__scan__file, char *, vp->v_path, int, async);

	/* check if size or type exempts file from scanning */
	if (vscan_svc_exempt_file(vp, &allow)) {
		mutex_exit(&vscan_svc_mutex);
		if ((allow == B_TRUE) || (async != 0))
			return (0);

		return (EACCES);
	}

	vscan_svc_req_count++;
	mutex_exit(&vscan_svc_mutex);

	req = kmem_zalloc(sizeof (vscan_fs_req_t), KM_SLEEP);
	req->vsr_vp = vp;

	if (async) {
		VN_HOLD(vp);
		if (vscan_svc_taskq &&
		    taskq_dispatch(vscan_svc_taskq, vscan_svc_taskq_callback,
		    (void *)req, TQ_SLEEP)) {
			return (0);
		} else {
			VN_RELE(vp);
			kmem_free(req, sizeof (vscan_fs_req_t));
		}
	} else {
		rc = vscan_svc_do_scan(req);
		kmem_free(req, sizeof (vscan_fs_req_t));
	}

	mutex_enter(&vscan_svc_mutex);
	vscan_svc_req_count--;
	mutex_exit(&vscan_svc_mutex);

	return (rc);
}


/*
 * vscan_svc_taskq_callback
 *
 * Callback function for async scan requests
 */
void
vscan_svc_taskq_callback(void *data)
{
	vscan_fs_req_t *req = (vscan_fs_req_t *)data;

	(void) vscan_svc_do_scan(req);
	VN_RELE(req->vsr_vp); /* VN_HOLD done before request queued */
	kmem_free(req, sizeof (vscan_fs_req_t));

	mutex_enter(&vscan_svc_mutex);
	vscan_svc_req_count--;
	mutex_exit(&vscan_svc_mutex);
}


/*
 * vscan_svc_do_scan
 *
 * Should never be called directly. Invoke via vscan_svc_scan_file()
 * If scan is in progress wait for it to complete, otherwise
 * initiate door call to scan the file.
 */
static int
vscan_svc_do_scan(vscan_fs_req_t *req)
{
	int rc = -1, idx;
	vs_scan_req_t *scan_req;
	vscan_file_t *svc_file;

	mutex_enter(&vscan_svc_mutex);

	/*
	 * if a scan is in progress on the files vscan_svc_wait_for_scan will
	 * wait for it to complete and return the idx of the scan request.
	 * Otherwise it will return -1 and we will initiate a scan here.
	 */
	if ((idx = vscan_svc_wait_for_scan(req->vsr_vp)) != -1) {
		svc_file = &vscan_svc_files[idx];
	} else {
		/* insert the scan request into vscan_svc_files */
		idx = vscan_svc_insert_file(req);
		svc_file = &vscan_svc_files[idx];

		if (vscan_svc_enabled) {
			if (vscan_svc_getattr(idx) == 0) {
				/* valid scan_req ptr guaranteed */
				scan_req = vscan_svc_populate_req(idx);
				mutex_exit(&vscan_svc_mutex);
				if (vscan_drv_create_node(idx) == B_TRUE)
					rc = vscan_door_scan_file(scan_req);
				mutex_enter(&vscan_svc_mutex);
				if (rc == 0)
					vscan_svc_parse_rsp(idx, scan_req);
				kmem_free(scan_req, sizeof (vs_scan_req_t));

				/* process scan result */
				vscan_svc_process_scan_result(idx);
				DTRACE_PROBE2(vscan__result, int,
				    svc_file->vsf_result, int,
				    svc_file->vsf_access);
			} else {
				/* if getattr fails: log error, deny access */
				cmn_err(CE_WARN, "Can't access xattr for %s\n",
				    svc_file->vsf_req.vsr_vp->v_path);
				svc_file->vsf_access = VS_ACCESS_DENY;
			}
		} else {
			/* if vscan not enabled (shutting down), allow ACCESS */
			svc_file->vsf_access = VS_ACCESS_ALLOW;
		}
	}

	/* When a scan completes the result is saved in vscan_svc_files */
	rc = (svc_file->vsf_access == VS_ACCESS_ALLOW) ? 0 : EACCES;

	/* wake threads waiting for result, or for a slot in vscan_svc_files */
	vscan_svc_notify_scan_complete(idx);

	/* remove the entry from vscan_svc_files if nobody else is waiting */
	vscan_svc_release_file(idx);

	mutex_exit(&vscan_svc_mutex);

	return (rc);
}


/*
 * vscan_svc_process_scan_result
 *
 * Sets vsf_access and updates file attributes based on vsf_result,
 * as follows:
 *
 * VS_STATUS_INFECTED
 *  deny access, set quarantine attribute, clear scanstamp
 * VS_STATUS_CLEAN
 *  allow access, set scanstamp,
 *  if file not modified since scan initiated, clear modified attribute
 * VS_STATUS_NO_SCAN
 *  deny access if file quarantined, otherwise allow access
 * VS_STATUS_UNDEFINED, VS_STATUS_ERROR
 *  deny access if file quarantined, modified or no scanstamp
 *  otherwise, allow access
 */
static void
vscan_svc_process_scan_result(int idx)
{
	struct vattr attr;
	vnode_t *vp;
	timestruc_t *mtime;
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];

	switch (svc_file->vsf_result) {
	case VS_STATUS_INFECTED:
		svc_file->vsf_access = VS_ACCESS_DENY;
		svc_file->vsf_quarantined = 1;
		svc_file->vsf_scanstamp[0] = '\0';
		(void) vscan_svc_setattr(idx,
		    XAT_AV_QUARANTINED | XAT_AV_SCANSTAMP);
		return;

	case VS_STATUS_CLEAN:
		svc_file->vsf_access = VS_ACCESS_ALLOW;

		/* if mtime has changed, don't clear the modified attribute */
		vp = svc_file->vsf_req.vsr_vp;
		mtime = &(svc_file->vsf_mtime);
		attr.va_mask = AT_MTIME;
		if ((VOP_GETATTR(vp, &attr, 0, kcred, NULL) != 0) ||
		    (mtime->tv_sec != attr.va_mtime.tv_sec) ||
		    (mtime->tv_nsec != attr.va_mtime.tv_nsec)) {
			DTRACE_PROBE1(vscan__mtime__changed, vscan_file_t *,
			    svc_file);
			(void) vscan_svc_setattr(idx, XAT_AV_SCANSTAMP);
			return;
		}

		svc_file->vsf_modified = 0;
		(void) vscan_svc_setattr(idx,
		    XAT_AV_SCANSTAMP | XAT_AV_MODIFIED);
		return;

	case VS_STATUS_NO_SCAN:
		if (svc_file->vsf_quarantined)
			svc_file->vsf_access = VS_ACCESS_DENY;
		else
			svc_file->vsf_access = VS_ACCESS_ALLOW;
		return;

	case VS_STATUS_ERROR:
	case VS_STATUS_UNDEFINED:
	default:
		if ((svc_file->vsf_quarantined) ||
		    (svc_file->vsf_modified) ||
		    (svc_file->vsf_scanstamp[0] == '\0'))
			svc_file->vsf_access = VS_ACCESS_DENY;
		else
			svc_file->vsf_access = VS_ACCESS_ALLOW;
		return;
	}
}


/*
 * vscan_svc_wait_for_scan
 *
 * Search for vp in vscan_svc_files. If vp already exists in
 * vscan_svc_files scan is already in progress on file so wait
 * for the inprogress scan to complete.
 *
 * Returns: idx of file waited for
 *          -1 if file not already scanning
 */
static int
vscan_svc_wait_for_scan(vnode_t *vp)
{
	int idx;
	vscan_file_t *svc_file;

	ASSERT(vp);
	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	for (idx = 1; idx <= VS_DRV_MAX_FILES; idx++) {
		if (vscan_svc_files[idx].vsf_req.vsr_vp == vp)
			break;
	}

	/* file not found in table thus not currently being scanned */
	if (idx > VS_DRV_MAX_FILES)
		return (-1);

	/* file found - wait for scan to complete */
	svc_file = &vscan_svc_files[idx];
	svc_file->vsf_wait_count++;

	DTRACE_PROBE2(vscan__wait__scan, vscan_file_t *, svc_file, int, idx);

	while (svc_file->vsf_access == VS_ACCESS_UNDEFINED)
		cv_wait(&(svc_file->vsf_cv), &vscan_svc_mutex);

	svc_file->vsf_wait_count--;

	return (idx);
}


/*
 * vscan_svc_find_slot
 *
 * Find empty slot in vscan_svc_files table.
 *
 * Returns idx of slot, or -1 if not found
 */
static int
vscan_svc_find_slot(void)
{
	int idx;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));
	for (idx = 1; idx <= VS_DRV_MAX_FILES; idx++) {
		if (vscan_svc_files[idx].vsf_req.vsr_vp == NULL)
			return (idx);
	}

	return (-1);
}


/*
 * vscan_svc_insert_file
 *
 * Find the next available flot in vscan_svc_files and
 * initialize it for the scan request. If no slot is
 * available, vscan_svc_find_slot will wait for one.
 *
 * Returns: idx of scan request in vscan_svc_files table
 */
static int
vscan_svc_insert_file(vscan_fs_req_t *req)
{
	int idx;
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	while ((idx = vscan_svc_find_slot()) == -1) {
		DTRACE_PROBE1(vscan__wait__slot, char *, req->vsr_vp->v_path);
		vscan_svc_wait_count++;
		cv_wait(&(vscan_svc_cv), &vscan_svc_mutex);
		vscan_svc_wait_count--;
	}

	svc_file = &vscan_svc_files[idx];

	(void) memset(svc_file, 0, sizeof (vscan_file_t));
	svc_file->vsf_req = *req;
	svc_file->vsf_modified = 1;
	svc_file->vsf_result = VS_STATUS_UNDEFINED;
	svc_file->vsf_access = VS_ACCESS_UNDEFINED;
	cv_init(&(svc_file->vsf_cv), NULL, CV_DEFAULT, NULL);

	DTRACE_PROBE2(vscan__insert, char *, req->vsr_vp->v_path, int, idx);
	return (idx);
}


/*
 * vscan_svc_release_file
 *
 * Release the file (free the slot in vscan_svc_files)
 * if no thread is waiting on it.
 */
static void
vscan_svc_release_file(int idx)
{
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));
	svc_file = &vscan_svc_files[idx];

	if (svc_file->vsf_wait_count != 0)
		return;

	DTRACE_PROBE2(vscan__release, char *,
	    svc_file->vsf_req.vsr_vp->v_path, int, idx);

	cv_destroy(&(svc_file->vsf_cv));
	(void) memset(svc_file, 0, sizeof (vscan_file_t));
}


/*
 * vscan_svc_populate_req
 *
 * Allocate a scan request to be sent to vscand, populating it
 * from the data in vscan_svc_files[idx].
 *
 * Returns: scan request object
 */
static vs_scan_req_t *
vscan_svc_populate_req(int idx)
{
	vs_scan_req_t *scan_req;
	vscan_fs_req_t *req;
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];
	req = &(svc_file->vsf_req);
	scan_req = kmem_zalloc(sizeof (vs_scan_req_t), KM_SLEEP);

	scan_req->vsr_id = idx;
	(void) strncpy(scan_req->vsr_path, req->vsr_vp->v_path, MAXPATHLEN);
	scan_req->vsr_size = svc_file->vsf_size;
	scan_req->vsr_modified = svc_file->vsf_modified;
	scan_req->vsr_quarantined = svc_file->vsf_quarantined;
	scan_req->vsr_flags = 0;
	(void) strncpy(scan_req->vsr_scanstamp,
	    svc_file->vsf_scanstamp, sizeof (vs_scanstamp_t));

	return (scan_req);
}


/*
 * vscan_svc_parse_rsp
 *
 * Parse scan response data and save in vscan_svc_files[idx]
 */
static void
vscan_svc_parse_rsp(int idx, vs_scan_req_t *scan_req)
{
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];
	svc_file->vsf_result = scan_req->vsr_result;
	(void) strncpy(svc_file->vsf_scanstamp,
	    scan_req->vsr_scanstamp, sizeof (vs_scanstamp_t));
}


/*
 * vscan_svc_notify_scan_complete
 *
 * signal vscan_svc_files.vsf_cv and vscan_svc_cv to wake
 * threads waiting for the scan result for the specified
 * file (vscan_svc_files[idx].vsf_cv) or for a slot in
 * vscan_svc_files table (vscan_svc_cv)
 */
static void
vscan_svc_notify_scan_complete(int idx)
{
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];

	/* if someone waiting for result, cv_signal */
	if (svc_file->vsf_wait_count > 0)
		cv_signal(&(svc_file->vsf_cv));

	/* signal vscan_svc_cv if any threads waiting for a slot */
	if (vscan_svc_wait_count > 0)
		cv_signal(&vscan_svc_cv);
}


/*
 * vscan_svc_getattr
 *
 * Get the vscan related system attributes, AT_SIZE & AT_MTIME.
 */
static int
vscan_svc_getattr(int idx)
{
	xvattr_t xvattr;
	xoptattr_t *xoap = NULL;
	vnode_t *vp;
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];
	if ((vp = svc_file->vsf_req.vsr_vp) == NULL)
		return (-1);

	/* get the attributes */
	xva_init(&xvattr); /* sets AT_XVATTR */

	xvattr.xva_vattr.va_mask |= AT_SIZE;
	xvattr.xva_vattr.va_mask |= AT_MTIME;
	XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
	XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
	XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);

	if (VOP_GETATTR(vp, (vattr_t *)&xvattr, 0, kcred, NULL) != 0)
		return (-1);

	if ((xoap = xva_getxoptattr(&xvattr)) == NULL) {
		cmn_err(CE_NOTE, "Virus scan request failed; "
		    "file system does not support virus scanning");
		return (-1);
	}

	svc_file->vsf_size = xvattr.xva_vattr.va_size;
	svc_file->vsf_mtime.tv_sec = xvattr.xva_vattr.va_mtime.tv_sec;
	svc_file->vsf_mtime.tv_nsec = xvattr.xva_vattr.va_mtime.tv_nsec;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_MODIFIED) == 0)
		return (-1);
	svc_file->vsf_modified = xoap->xoa_av_modified;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_QUARANTINED) == 0)
		return (-1);
	svc_file->vsf_quarantined = xoap->xoa_av_quarantined;

	if (XVA_ISSET_RTN(&xvattr, XAT_AV_SCANSTAMP) != 0) {
		(void) memcpy(svc_file->vsf_scanstamp,
		    xoap->xoa_av_scanstamp, AV_SCANSTAMP_SZ);
	}

	DTRACE_PROBE1(vscan__getattr, vscan_file_t *, svc_file);
	return (0);
}


/*
 * vscan_svc_setattr
 *
 * Set the vscan related system attributes.
 */
static int
vscan_svc_setattr(int idx, int which)
{
	xvattr_t xvattr;
	xoptattr_t *xoap = NULL;
	vnode_t *vp;
	int len;
	vscan_file_t *svc_file;

	ASSERT(MUTEX_HELD(&vscan_svc_mutex));

	svc_file = &vscan_svc_files[idx];
	if ((vp = svc_file->vsf_req.vsr_vp) == NULL)
		return (-1);

	/* update the attributes */
	xva_init(&xvattr); /* sets AT_XVATTR */
	if ((xoap = xva_getxoptattr(&xvattr)) == NULL)
		return (-1);

	if (which & XAT_AV_MODIFIED) {
		XVA_SET_REQ(&xvattr, XAT_AV_MODIFIED);
		xoap->xoa_av_modified = svc_file->vsf_modified;
	}

	if (which & XAT_AV_QUARANTINED) {
		XVA_SET_REQ(&xvattr, XAT_AV_QUARANTINED);
		xoap->xoa_av_quarantined = svc_file->vsf_quarantined;
	}

	if (which & XAT_AV_SCANSTAMP) {
		XVA_SET_REQ(&xvattr, XAT_AV_SCANSTAMP);
		len = strlen(svc_file->vsf_scanstamp);
		(void) memcpy(xoap->xoa_av_scanstamp,
		    svc_file->vsf_scanstamp, len);
	}

	/* if access is denied, set mtime to invalidate client cache */
	if (svc_file->vsf_access != VS_ACCESS_ALLOW) {
		xvattr.xva_vattr.va_mask |= AT_MTIME;
		gethrestime(&xvattr.xva_vattr.va_mtime);
	}

	if (VOP_SETATTR(vp, (vattr_t *)&xvattr, 0, kcred, NULL) != 0)
		return (-1);

	DTRACE_PROBE2(vscan__setattr,
	    vscan_file_t *, svc_file, int, which);

	return (0);
}


/*
 * vscan_svc_configure
 *
 * store configuration in vscan_svc_config
 * set up vscan_svc_types array of pointers into
 * vscan_svc_config.vsc_types for efficient searching
 */
int
vscan_svc_configure(vs_config_t *conf)
{
	int count = 0;
	char *p, *beg, *end;

	mutex_enter(&vscan_svc_cfg_mutex);

	vscan_svc_config = *conf;

	(void) memset(vscan_svc_types, 0, sizeof (vscan_svc_types));

	beg = vscan_svc_config.vsc_types;
	end = beg + vscan_svc_config.vsc_types_len;

	for (p = beg; p < end; p += strlen(p) + 1) {
		if (count >= VS_TYPES_MAX) {
			mutex_exit(&vscan_svc_mutex);
			return (-1);
		}

		vscan_svc_types[count] = p;
		++count;
	}

	mutex_exit(&vscan_svc_cfg_mutex);
	return (0);
}


/*
 * vscan_svc_exempt_file
 *
 * check if a file's size or type exempts it from virus scanning
 *
 * If the file is exempt from virus scanning, allow will be set
 * to define whether files access should be allowed (B_TRUE) or
 * denied (B_FALSE)
 *
 * Returns: 1 exempt
 *          0 scan required
 */
static int
vscan_svc_exempt_file(vnode_t *vp, boolean_t *allow)
{
	struct vattr attr;

	ASSERT(vp != NULL);
	ASSERT(vp->v_path != NULL);

	attr.va_mask = AT_SIZE;

	if (VOP_GETATTR(vp, &attr, 0, kcred, NULL) != 0) {
		*allow = B_FALSE;
		return (0);
	}

	mutex_enter(&vscan_svc_cfg_mutex);

	if (attr.va_size > vscan_svc_config.vsc_max_size) {
		DTRACE_PROBE2(vscan__exempt__filesize, char *,
		    vp->v_path, int, *allow);

		*allow = (vscan_svc_config.vsc_allow) ? B_TRUE : B_FALSE;
		mutex_exit(&vscan_svc_cfg_mutex);
		return (1);
	}

	if (vscan_svc_exempt_filetype(vp->v_path)) {
		DTRACE_PROBE1(vscan__exempt__filetype, char *, vp->v_path);
		*allow = B_TRUE;
		mutex_exit(&vscan_svc_cfg_mutex);
		return (1);
	}

	mutex_exit(&vscan_svc_cfg_mutex);
	return (0);
}


/*
 * vscan_svc_exempt_filetype
 *
 * Each entry in vscan_svc_types includes a rule indicator (+,-)
 * followed by the match string for file types to which the rule
 * applies. Look for first match of file type in vscan_svc_types
 * and return 1 (exempt) if the indicator is '-', and 0 (not exempt)
 * if the indicator is '+'.
 * If vscan_svc_match_ext fails, or no match is found, return 0
 * (not exempt)
 *
 * Returns 1: exempt, 0: not exempt
 */
static int
vscan_svc_exempt_filetype(char *filepath)
{
	int i, rc, exempt = 0;
	char *filename, *ext;

	ASSERT(MUTEX_HELD(&vscan_svc_cfg_mutex));

	if ((filename = strrchr(filepath, '/')) == 0)
		filename = filepath;
	else
		filename++;

	if ((ext = strrchr(filename, '.')) == NULL)
		ext = "";
	else
		ext++;


	for (i = 0; i < VS_TYPES_MAX; i ++) {
		if (vscan_svc_types[i] == 0)
			break;

		rc = vscan_svc_match_ext(vscan_svc_types[i] + 1, ext, 1);
		if (rc == -1)
			break;
		if (rc > 0) {
			DTRACE_PROBE2(vscan__type__match, char *, ext,
			    char *, vscan_svc_types[i]);
			exempt = (vscan_svc_types[i][0] == '-');
			break;
		}
	}

	return (exempt);
}


/*
 *  vscan_svc_match_ext
 *
 * Performs a case-insensitive match for two strings.  The first string
 * argument can contain the wildcard characters '?' and '*'
 *
 * Returns: 0 no match
 *          1 match
 *         -1 recursion error
 */
static int
vscan_svc_match_ext(char *patn, char *str, int depth)
{
	int c1, c2;
	if (depth > VS_EXT_RECURSE_DEPTH)
		return (-1);

	for (;;) {
		switch (*patn) {
		case 0:
			return (*str == 0);

		case '?':
			if (*str != 0) {
				str++;
				patn++;
				continue;
			}
			return (0);

		case '*':
			patn++;
			if (*patn == 0)
				return (1);

			while (*str) {
				if (vscan_svc_match_ext(patn, str, depth + 1))
					return (1);
				str++;
			}
			return (0);

		default:
			if (*str != *patn) {
				c1 = *str;
				c2 = *patn;

				c1 = tolower(c1);
				c2 = tolower(c2);
				if (c1 != c2)
					return (0);
			}
			str++;
			patn++;
			continue;
		}
	}
	/* NOT REACHED */
}
