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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * The ioctl interface for cryptographic commands.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/kmem.h>
#include <sys/errno.h>
#include <sys/ksynch.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/proc.h>
#include <sys/task.h>
#include <sys/mkdev.h>
#include <sys/model.h>
#include <sys/sysmacros.h>
#include <sys/crypto/common.h>
#include <sys/crypto/api.h>
#include <sys/crypto/impl.h>
#include <sys/crypto/sched_impl.h>
#include <sys/crypto/ioctl.h>

extern int kcf_des3_threshold;
extern int kcf_aes_threshold;
extern int kcf_rc4_threshold;
extern int kcf_md5_threshold;
extern int kcf_sha1_threshold;

/*
 * Locking notes:
 *
 * crypto_locks protects the global array of minor structures.
 * crypto_locks is an array of locks indexed by the cpuid. A reader needs
 * to hold a single lock while a writer needs to hold all locks.
 * krwlock_t is not an option here because the hold time
 * is very small for these locks.
 *
 * The fields in the minor structure are protected by the cm_lock member
 * of the minor structure. The cm_cv is used to signal decrements
 * in the cm_refcnt, and is used with the cm_lock.
 *
 * The locking order is crypto_locks followed by cm_lock.
 */

/*
 * DDI entry points.
 */
static int crypto_attach(dev_info_t *, ddi_attach_cmd_t);
static int crypto_detach(dev_info_t *, ddi_detach_cmd_t);
static int crypto_getinfo(dev_info_t *, ddi_info_cmd_t, void *, void **);
static int crypto_open(dev_t *, int, int, cred_t *);
static int crypto_close(dev_t, int, int, cred_t *);
static int crypto_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int cipher_init(dev_t, caddr_t, int, int (*)(crypto_provider_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_ctx_template_t, crypto_context_t *, crypto_call_req_t *));

static int common_digest(dev_t, caddr_t, int, int (*)(crypto_context_t,
    crypto_data_t *, crypto_data_t *, crypto_call_req_t *));

static int cipher(dev_t, caddr_t, int, int (*)(crypto_context_t,
    crypto_data_t *, crypto_data_t *, crypto_call_req_t *));

static int cipher_update(dev_t, caddr_t, int, int (*)(crypto_context_t,
    crypto_data_t *, crypto_data_t *, crypto_call_req_t *));

static int common_final(dev_t, caddr_t, int, int (*)(crypto_context_t,
    crypto_data_t *, crypto_call_req_t *));

static int sign_verify_init(dev_t, caddr_t, int, int (*)(crypto_provider_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_ctx_template_t, crypto_context_t *, crypto_call_req_t *));

static int sign_verify_update(dev_t dev, caddr_t arg, int mode,
    int (*)(crypto_context_t, crypto_data_t *, crypto_call_req_t *));

static void crypto_release_provider_session(crypto_minor_t *,
    crypto_provider_session_t *);
static int crypto_buffer_check(size_t);
static int crypto_free_find_ctx(crypto_session_data_t *);
static int crypto_get_provider_list(crypto_minor_t *, uint_t *,
    crypto_provider_entry_t **, boolean_t);

/* number of minor numbers to allocate at a time */
#define	CRYPTO_MINOR_CHUNK	16

/*
 * There are two limits associated with kernel memory. The first,
 * CRYPTO_MAX_BUFFER_LEN, is the maximum number of bytes that can be
 * allocated for a single copyin/copyout buffer. The second limit is
 * the total number of bytes that can be allocated by a process
 * for copyin/copyout buffers. The latter is enforced by the
 * project.max-crypto-memory resource control.
 */

#define	CRYPTO_MAX_BUFFER_LEN	(2 * 1024 * 1024)
#define	CRYPTO_MAX_FIND_COUNT	512

/*
 * We preapprove some bytes for each session to avoid making the costly
 * crypto_buffer_check() calls. The preapproval is done when a new session
 * is created and that cost is amortized over later crypto calls.
 * Most applications create a session and then do a bunch of crypto calls
 * in that session. So, they benefit from this optimization.
 *
 * Note that we may hit the project.max-crypto-memory limit a bit sooner
 * because of this preapproval. But it is acceptable since the preapproved
 * amount is insignificant compared to the default max-crypto-memory limit
 * which is quarter of the machine's memory. The preapproved amount is
 * roughly 2 * 16K(maximum SSL record size).
 */
#define	CRYPTO_PRE_APPROVED_LIMIT	(32 * 1024)

/* The session table grows by CRYPTO_SESSION_CHUNK increments */
#define	CRYPTO_SESSION_CHUNK	100

size_t crypto_max_buffer_len = CRYPTO_MAX_BUFFER_LEN;
size_t crypto_pre_approved_limit = CRYPTO_PRE_APPROVED_LIMIT;

#define	INIT_RAW_CRYPTO_DATA(data, len)				\
	(data).cd_format = CRYPTO_DATA_RAW;			\
	(data).cd_raw.iov_base = kmem_alloc(len, KM_SLEEP);	\
	(data).cd_raw.iov_len = len;				\
	(data).cd_offset = 0;					\
	(data).cd_length = len;

static struct kmem_cache *crypto_session_cache;
static crypto_minor_t **crypto_minors = NULL;
static dev_info_t *crypto_dip = NULL;
static minor_t crypto_minor_chunk = CRYPTO_MINOR_CHUNK;
static minor_t crypto_minors_table_count = 0;

/*
 * Minors are started from 1 because vmem_alloc()
 * returns 0 in case of failure.
 */
static vmem_t *crypto_arena = NULL;	/* Arena for device minors */
static minor_t crypto_minors_count = 0;
static kcf_lock_withpad_t *crypto_locks;

#define	CRYPTO_ENTER_ALL_LOCKS()		\
	for (i = 0; i < max_ncpus; i++)		\
		mutex_enter(&crypto_locks[i].kl_lock);

#define	CRYPTO_EXIT_ALL_LOCKS()			\
	for (i = 0; i < max_ncpus; i++)		\
		mutex_exit(&crypto_locks[i].kl_lock);

#define	RETURN_LIST			B_TRUE
#define	DONT_RETURN_LIST		B_FALSE

#define	CRYPTO_OPS_OFFSET(f)		offsetof(crypto_ops_t, co_##f)
#define	CRYPTO_RANDOM_OFFSET(f)		offsetof(crypto_random_number_ops_t, f)
#define	CRYPTO_SESSION_OFFSET(f)	offsetof(crypto_session_ops_t, f)
#define	CRYPTO_OBJECT_OFFSET(f)		offsetof(crypto_object_ops_t, f)
#define	CRYPTO_PROVIDER_OFFSET(f)	\
	offsetof(crypto_provider_management_ops_t, f)

#define	CRYPTO_CANCEL_CTX(spp) {	\
	crypto_cancel_ctx(*(spp));	\
	*(spp) = NULL;			\
}

#define	CRYPTO_CANCEL_ALL_CTX(sp) {				\
	if ((sp)->sd_digest_ctx != NULL) {			\
		crypto_cancel_ctx((sp)->sd_digest_ctx);		\
		(sp)->sd_digest_ctx = NULL;			\
	}							\
	if ((sp)->sd_encr_ctx != NULL) {			\
		crypto_cancel_ctx((sp)->sd_encr_ctx);		\
		(sp)->sd_encr_ctx = NULL;			\
	}							\
	if ((sp)->sd_decr_ctx != NULL) {			\
		crypto_cancel_ctx((sp)->sd_decr_ctx);		\
		(sp)->sd_decr_ctx = NULL;			\
	}							\
	if ((sp)->sd_sign_ctx != NULL) {			\
		crypto_cancel_ctx((sp)->sd_sign_ctx);		\
		(sp)->sd_sign_ctx = NULL;			\
	}							\
	if ((sp)->sd_verify_ctx != NULL) {			\
		crypto_cancel_ctx((sp)->sd_verify_ctx);		\
		(sp)->sd_verify_ctx = NULL;			\
	}							\
	if ((sp)->sd_sign_recover_ctx != NULL) {		\
		crypto_cancel_ctx((sp)->sd_sign_recover_ctx);	\
		(sp)->sd_sign_recover_ctx = NULL;		\
	}							\
	if ((sp)->sd_verify_recover_ctx != NULL) {		\
		crypto_cancel_ctx((sp)->sd_verify_recover_ctx);	\
		(sp)->sd_verify_recover_ctx = NULL;		\
	}							\
}

#define	CRYPTO_DECREMENT_RCTL(val)	if ((val) != 0) {	\
	kproject_t *projp;					\
	mutex_enter(&curproc->p_lock);				\
	projp = curproc->p_task->tk_proj;			\
	ASSERT(projp != NULL);					\
	mutex_enter(&(projp->kpj_data.kpd_crypto_lock));	\
	projp->kpj_data.kpd_crypto_mem -= (val);		\
	mutex_exit(&(projp->kpj_data.kpd_crypto_lock));		\
	curproc->p_crypto_mem -= (val);				\
	mutex_exit(&curproc->p_lock);				\
}

/*
 * We do not need to hold sd_lock in the macros below
 * as they are called after doing a get_session_ptr() which
 * sets the CRYPTO_SESSION_IS_BUSY flag.
 */
#define	CRYPTO_DECREMENT_RCTL_SESSION(sp, val, rctl_chk) 	\
	if (((val) != 0) && ((sp) != NULL)) {			\
		ASSERT(((sp)->sd_flags & CRYPTO_SESSION_IS_BUSY) != 0);	\
		if (rctl_chk) {				\
			CRYPTO_DECREMENT_RCTL(val);		\
		} else {					\
			(sp)->sd_pre_approved_amount += (val);	\
		}						\
	}

#define	CRYPTO_BUFFER_CHECK(sp, need, rctl_chk)		\
	((sp->sd_pre_approved_amount >= need) ?			\
	(sp->sd_pre_approved_amount -= need,			\
	    rctl_chk = B_FALSE, CRYPTO_SUCCESS) :		\
	    (rctl_chk = B_TRUE, crypto_buffer_check(need)))

/*
 * Module linkage.
 */
static struct cb_ops cbops = {
	crypto_open,		/* cb_open */
	crypto_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	crypto_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_streamtab */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops devops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	crypto_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	crypto_attach,		/* devo_attach */
	crypto_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&cbops,			/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,					/* drv_modops */
	"Cryptographic Library Interface",	/* drv_linkinfo */
	&devops,
};

static struct modlinkage modlinkage = {
	MODREV_1,		/* ml_rev */
	&modldrv,		/* ml_linkage */
	NULL
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/* ARGSUSED */
static int
crypto_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = crypto_dip;
		return (DDI_SUCCESS);

	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}

static int
crypto_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int i;

	if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		/* we only allow instance 0 to attach */
		return (DDI_FAILURE);
	}

	crypto_session_cache = kmem_cache_create("crypto_session_cache",
	    sizeof (crypto_session_data_t), 0, NULL, NULL, NULL, NULL, NULL, 0);

	if (crypto_session_cache == NULL)
		return (DDI_FAILURE);

	/* create the minor node */
	if (ddi_create_minor_node(dip, "crypto", S_IFCHR, 0,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		kmem_cache_destroy(crypto_session_cache);
		crypto_session_cache = NULL;
		cmn_err(CE_WARN, "crypto_attach: failed creating minor node");
		ddi_remove_minor_node(dip, NULL);
		return (DDI_FAILURE);
	}

	crypto_locks = kmem_zalloc(max_ncpus * sizeof (kcf_lock_withpad_t),
	    KM_SLEEP);
	for (i = 0; i < max_ncpus; i++)
		mutex_init(&crypto_locks[i].kl_lock, NULL, MUTEX_DRIVER, NULL);

	crypto_dip = dip;

	/* allocate integer space for minor numbers */
	crypto_arena = vmem_create("crypto", (void *)1,
	    CRYPTO_MINOR_CHUNK, 1, NULL, NULL, NULL, 0,
	    VM_SLEEP | VMC_IDENTIFIER);

	return (DDI_SUCCESS);
}

static int
crypto_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	minor_t i;
	kcf_lock_withpad_t *mp;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mp = &crypto_locks[CPU_SEQID];
	mutex_enter(&mp->kl_lock);

	/* check if device is open */
	for (i = 0; i < crypto_minors_table_count; i++) {
		if (crypto_minors[i] != NULL) {
			mutex_exit(&mp->kl_lock);
			return (DDI_FAILURE);
		}
	}
	mutex_exit(&mp->kl_lock);

	crypto_dip = NULL;
	ddi_remove_minor_node(dip, NULL);

	kmem_cache_destroy(crypto_session_cache);
	crypto_session_cache = NULL;

	kmem_free(crypto_minors,
	    sizeof (crypto_minor_t *) * crypto_minors_table_count);
	crypto_minors = NULL;
	crypto_minors_table_count = 0;
	for (i = 0; i < max_ncpus; i++)
		mutex_destroy(&crypto_locks[i].kl_lock);
	kmem_free(crypto_locks, max_ncpus * sizeof (kcf_lock_withpad_t));
	crypto_locks = NULL;

	vmem_destroy(crypto_arena);
	crypto_arena = NULL;

	return (DDI_SUCCESS);
}

/* ARGSUSED3 */
static int
crypto_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	crypto_minor_t *cm = NULL;
	minor_t mn;
	kcf_lock_withpad_t *mp;
	int i;

	if (otyp != OTYP_CHR)
		return (ENXIO);

	if (crypto_dip == NULL)
		return (ENXIO);

	/* exclusive opens are not supported */
	if (flag & FEXCL)
		return (ENOTSUP);

again:
	mp = &crypto_locks[CPU_SEQID];
	mutex_enter(&mp->kl_lock);

	/* grow the minors table if needed */
	if (crypto_minors_count >= crypto_minors_table_count) {
		crypto_minor_t **newtable;
		minor_t chunk = crypto_minor_chunk;
		minor_t saved_count;
		size_t new_size;
		ulong_t big_count;

		big_count = crypto_minors_count + chunk;
		if (big_count > MAXMIN) {
			mutex_exit(&mp->kl_lock);
			return (ENOMEM);
		}

		saved_count = crypto_minors_table_count;
		new_size = sizeof (crypto_minor_t *) *
		    (crypto_minors_table_count + chunk);

		mutex_exit(&mp->kl_lock);

		newtable = kmem_zalloc(new_size, KM_SLEEP);
		CRYPTO_ENTER_ALL_LOCKS();
		/*
		 * Check if table grew while we were sleeping.
		 * The minors table never shrinks.
		 */
		if (crypto_minors_table_count > saved_count) {
			CRYPTO_EXIT_ALL_LOCKS();
			kmem_free(newtable, new_size);
			goto again;
		}

		/* we assume that bcopy() will return if count is 0 */
		bcopy(crypto_minors, newtable,
		    sizeof (crypto_minor_t *) * crypto_minors_table_count);

		kmem_free(crypto_minors,
		    sizeof (crypto_minor_t *) * crypto_minors_table_count);

		/* grow the minors number space */
		if (crypto_minors_table_count != 0) {
			(void) vmem_add(crypto_arena,
			    (void *)(uintptr_t)(crypto_minors_table_count + 1),
			    crypto_minor_chunk, VM_SLEEP);
		}

		crypto_minors = newtable;
		crypto_minors_table_count += chunk;
		CRYPTO_EXIT_ALL_LOCKS();
	} else {
		mutex_exit(&mp->kl_lock);
	}

	/* allocate a new minor number starting with 1 */
	mn = (minor_t)(uintptr_t)vmem_alloc(crypto_arena, 1, VM_SLEEP);

	cm = kmem_zalloc(sizeof (crypto_minor_t), KM_SLEEP);
	mutex_init(&cm->cm_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cm->cm_cv, NULL, CV_DRIVER, NULL);

	CRYPTO_ENTER_ALL_LOCKS();
	cm->cm_refcnt = 1;
	crypto_minors[mn - 1] = cm;
	crypto_minors_count++;
	CRYPTO_EXIT_ALL_LOCKS();

	*devp = makedevice(getmajor(*devp), mn);

	return (0);
}

/* ARGSUSED1 */
static int
crypto_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	crypto_minor_t *cm = NULL;
	crypto_session_data_t *sp;
	minor_t mn = getminor(dev);
	uint_t i;
	size_t total = 0;
	kcf_lock_withpad_t *mp;

	mp = &crypto_locks[CPU_SEQID];
	mutex_enter(&mp->kl_lock);

	if (mn > crypto_minors_table_count) {
		mutex_exit(&mp->kl_lock);
		cmn_err(CE_WARN, "crypto_close: bad minor (too big) %d", mn);
		return (ENODEV);
	}

	cm = crypto_minors[mn - 1];
	if (cm == NULL) {
		mutex_exit(&mp->kl_lock);
		cmn_err(CE_WARN, "crypto_close: duplicate close of minor %d",
		    getminor(dev));
		return (ENODEV);
	}

	mutex_exit(&mp->kl_lock);

	CRYPTO_ENTER_ALL_LOCKS();
	/*
	 * We free the minor number, mn, from the crypto_arena
	 * only later. This ensures that we won't race with another
	 * thread in crypto_open with the same minor number.
	 */
	crypto_minors[mn - 1] = NULL;
	crypto_minors_count--;
	CRYPTO_EXIT_ALL_LOCKS();

	mutex_enter(&cm->cm_lock);
	cm->cm_refcnt --;		/* decrement refcnt held in open */
	while (cm->cm_refcnt > 0) {
		cv_wait(&cm->cm_cv, &cm->cm_lock);
	}

	vmem_free(crypto_arena, (void *)(uintptr_t)mn, 1);

	/* free all session table entries starting with 1 */
	for (i = 1; i < cm->cm_session_table_count; i++) {
		if (cm->cm_session_table[i] == NULL)
			continue;

		sp = cm->cm_session_table[i];
		ASSERT((sp->sd_flags & CRYPTO_SESSION_IS_BUSY) == 0);
		ASSERT(sp->sd_pre_approved_amount == 0 ||
		    sp->sd_pre_approved_amount == crypto_pre_approved_limit);
		total += sp->sd_pre_approved_amount;
		if (sp->sd_find_init_cookie != NULL) {
			(void) crypto_free_find_ctx(sp);
		}
		crypto_release_provider_session(cm, sp->sd_provider_session);
		KCF_PROV_REFRELE(sp->sd_provider);
		CRYPTO_CANCEL_ALL_CTX(sp);
		mutex_destroy(&sp->sd_lock);
		cv_destroy(&sp->sd_cv);
		kmem_cache_free(crypto_session_cache, sp);
		cm->cm_session_table[i] = NULL;
	}

	/* free the session table */
	if (cm->cm_session_table != NULL && cm->cm_session_table_count > 0)
		kmem_free(cm->cm_session_table, cm->cm_session_table_count *
		    sizeof (void *));

	total += (cm->cm_session_table_count * sizeof (void *));
	CRYPTO_DECREMENT_RCTL(total);

	kcf_free_provider_tab(cm->cm_provider_count,
	    cm->cm_provider_array);

	mutex_exit(&cm->cm_lock);
	mutex_destroy(&cm->cm_lock);
	cv_destroy(&cm->cm_cv);
	kmem_free(cm, sizeof (crypto_minor_t));

	return (0);
}

static crypto_minor_t *
crypto_hold_minor(minor_t minor)
{
	crypto_minor_t *cm;
	kcf_lock_withpad_t *mp;

	if (minor > crypto_minors_table_count)
		return (NULL);

	mp = &crypto_locks[CPU_SEQID];
	mutex_enter(&mp->kl_lock);

	if ((cm = crypto_minors[minor - 1]) != NULL) {
		atomic_inc_32(&cm->cm_refcnt);
	}
	mutex_exit(&mp->kl_lock);
	return (cm);
}

static void
crypto_release_minor(crypto_minor_t *cm)
{
	if (atomic_dec_32_nv(&cm->cm_refcnt) == 0) {
		cv_signal(&cm->cm_cv);
	}
}

/*
 * Build a list of functions and other information for the provider, pd.
 */
static void
crypto_build_function_list(crypto_function_list_t *fl, kcf_provider_desc_t *pd)
{
	crypto_ops_t *ops;
	crypto_digest_ops_t *digest_ops;
	crypto_cipher_ops_t *cipher_ops;
	crypto_mac_ops_t *mac_ops;
	crypto_sign_ops_t *sign_ops;
	crypto_verify_ops_t *verify_ops;
	crypto_dual_ops_t *dual_ops;
	crypto_random_number_ops_t *random_number_ops;
	crypto_session_ops_t *session_ops;
	crypto_object_ops_t *object_ops;
	crypto_key_ops_t *key_ops;
	crypto_provider_management_ops_t *provider_ops;

	if ((ops = pd->pd_ops_vector) == NULL)
		return;

	if ((digest_ops = ops->co_digest_ops) != NULL) {
		if (digest_ops->digest_init != NULL)
			fl->fl_digest_init = B_TRUE;
		if (digest_ops->digest != NULL)
			fl->fl_digest = B_TRUE;
		if (digest_ops->digest_update != NULL)
			fl->fl_digest_update = B_TRUE;
		if (digest_ops->digest_key != NULL)
			fl->fl_digest_key = B_TRUE;
		if (digest_ops->digest_final != NULL)
			fl->fl_digest_final = B_TRUE;
	}
	if ((cipher_ops = ops->co_cipher_ops) != NULL) {
		if (cipher_ops->encrypt_init != NULL)
			fl->fl_encrypt_init = B_TRUE;
		if (cipher_ops->encrypt != NULL)
			fl->fl_encrypt = B_TRUE;
		if (cipher_ops->encrypt_update != NULL)
			fl->fl_encrypt_update = B_TRUE;
		if (cipher_ops->encrypt_final != NULL)
			fl->fl_encrypt_final = B_TRUE;
		if (cipher_ops->decrypt_init != NULL)
			fl->fl_decrypt_init = B_TRUE;
		if (cipher_ops->decrypt != NULL)
			fl->fl_decrypt = B_TRUE;
		if (cipher_ops->decrypt_update != NULL)
			fl->fl_decrypt_update = B_TRUE;
		if (cipher_ops->decrypt_final != NULL)
			fl->fl_decrypt_final = B_TRUE;
	}
	if ((mac_ops = ops->co_mac_ops) != NULL) {
		if (mac_ops->mac_init != NULL)
			fl->fl_mac_init = B_TRUE;
		if (mac_ops->mac != NULL)
			fl->fl_mac = B_TRUE;
		if (mac_ops->mac_update != NULL)
			fl->fl_mac_update = B_TRUE;
		if (mac_ops->mac_final != NULL)
			fl->fl_mac_final = B_TRUE;
	}
	if ((sign_ops = ops->co_sign_ops) != NULL) {
		if (sign_ops->sign_init != NULL)
			fl->fl_sign_init = B_TRUE;
		if (sign_ops->sign != NULL)
			fl->fl_sign = B_TRUE;
		if (sign_ops->sign_update != NULL)
			fl->fl_sign_update = B_TRUE;
		if (sign_ops->sign_final != NULL)
			fl->fl_sign_final = B_TRUE;
		if (sign_ops->sign_recover_init != NULL)
			fl->fl_sign_recover_init = B_TRUE;
		if (sign_ops->sign_recover != NULL)
			fl->fl_sign_recover = B_TRUE;
	}
	if ((verify_ops = ops->co_verify_ops) != NULL) {
		if (verify_ops->verify_init != NULL)
			fl->fl_verify_init = B_TRUE;
		if (verify_ops->verify != NULL)
			fl->fl_verify = B_TRUE;
		if (verify_ops->verify_update != NULL)
			fl->fl_verify_update = B_TRUE;
		if (verify_ops->verify_final != NULL)
			fl->fl_verify_final = B_TRUE;
		if (verify_ops->verify_recover_init != NULL)
			fl->fl_verify_recover_init = B_TRUE;
		if (verify_ops->verify_recover != NULL)
			fl->fl_verify_recover = B_TRUE;
	}
	if ((dual_ops = ops->co_dual_ops) != NULL) {
		if (dual_ops->digest_encrypt_update != NULL)
			fl->fl_digest_encrypt_update = B_TRUE;
		if (dual_ops->decrypt_digest_update != NULL)
			fl->fl_decrypt_digest_update = B_TRUE;
		if (dual_ops->sign_encrypt_update != NULL)
			fl->fl_sign_encrypt_update = B_TRUE;
		if (dual_ops->decrypt_verify_update != NULL)
			fl->fl_decrypt_verify_update = B_TRUE;
	}
	if ((random_number_ops = ops->co_random_ops) != NULL) {
		if (random_number_ops->seed_random != NULL)
			fl->fl_seed_random = B_TRUE;
		if (random_number_ops->generate_random != NULL)
			fl->fl_generate_random = B_TRUE;
	}
	if ((session_ops = ops->co_session_ops) != NULL) {
		if (session_ops->session_open != NULL)
			fl->fl_session_open = B_TRUE;
		if (session_ops->session_close != NULL)
			fl->fl_session_close = B_TRUE;
		if (session_ops->session_login != NULL)
			fl->fl_session_login = B_TRUE;
		if (session_ops->session_logout != NULL)
			fl->fl_session_logout = B_TRUE;
	}
	if ((object_ops = ops->co_object_ops) != NULL) {
		if (object_ops->object_create != NULL)
			fl->fl_object_create = B_TRUE;
		if (object_ops->object_copy != NULL)
			fl->fl_object_copy = B_TRUE;
		if (object_ops->object_destroy != NULL)
			fl->fl_object_destroy = B_TRUE;
		if (object_ops->object_get_size != NULL)
			fl->fl_object_get_size = B_TRUE;
		if (object_ops->object_get_attribute_value != NULL)
			fl->fl_object_get_attribute_value = B_TRUE;
		if (object_ops->object_set_attribute_value != NULL)
			fl->fl_object_set_attribute_value = B_TRUE;
		if (object_ops->object_find_init != NULL)
			fl->fl_object_find_init = B_TRUE;
		if (object_ops->object_find != NULL)
			fl->fl_object_find = B_TRUE;
		if (object_ops->object_find_final != NULL)
			fl->fl_object_find_final = B_TRUE;
	}
	if ((key_ops = ops->co_key_ops) != NULL) {
		if (key_ops->key_generate != NULL)
			fl->fl_key_generate = B_TRUE;
		if (key_ops->key_generate_pair != NULL)
			fl->fl_key_generate_pair = B_TRUE;
		if (key_ops->key_wrap != NULL)
			fl->fl_key_wrap = B_TRUE;
		if (key_ops->key_unwrap != NULL)
			fl->fl_key_unwrap = B_TRUE;
		if (key_ops->key_derive != NULL)
			fl->fl_key_derive = B_TRUE;
	}
	if ((provider_ops = ops->co_provider_ops) != NULL) {
		if (provider_ops->init_token != NULL)
			fl->fl_init_token = B_TRUE;
		if (provider_ops->init_pin != NULL)
			fl->fl_init_pin = B_TRUE;
		if (provider_ops->set_pin != NULL)
			fl->fl_set_pin = B_TRUE;
	}

	fl->prov_is_hash_limited = pd->pd_flags & CRYPTO_HASH_NO_UPDATE;
	if (fl->prov_is_hash_limited) {
		fl->prov_hash_limit = min(pd->pd_hash_limit,
		    min(CRYPTO_MAX_BUFFER_LEN,
		    curproc->p_task->tk_proj->kpj_data.kpd_crypto_mem_ctl));
	}

	fl->prov_is_hmac_limited = pd->pd_flags & CRYPTO_HMAC_NO_UPDATE;
	if (fl->prov_is_hmac_limited) {
		fl->prov_hmac_limit = min(pd->pd_hmac_limit,
		    min(CRYPTO_MAX_BUFFER_LEN,
		    curproc->p_task->tk_proj->kpj_data.kpd_crypto_mem_ctl));
	}

	if (fl->prov_is_hash_limited || fl->prov_is_hmac_limited) {
		/*
		 * XXX - The threshold should ideally be per hash/HMAC
		 * mechanism. For now, we use the same value for all
		 * hash/HMAC mechanisms. Empirical evidence suggests this
		 * is fine.
		 */
		fl->prov_hash_threshold = kcf_md5_threshold;
	}

	fl->total_threshold_count = MAX_NUM_THRESHOLD;
	fl->fl_threshold[0].mech_type = CKM_DES3_CBC;
	fl->fl_threshold[0].mech_threshold = kcf_des3_threshold;
	fl->fl_threshold[1].mech_type = CKM_DES3_ECB;
	fl->fl_threshold[1].mech_threshold = kcf_des3_threshold;
	fl->fl_threshold[2].mech_type = CKM_AES_CBC;
	fl->fl_threshold[2].mech_threshold = kcf_aes_threshold;
	fl->fl_threshold[3].mech_type = CKM_AES_ECB;
	fl->fl_threshold[3].mech_threshold = kcf_aes_threshold;
	fl->fl_threshold[4].mech_type = CKM_RC4;
	fl->fl_threshold[4].mech_threshold = kcf_rc4_threshold;
	fl->fl_threshold[5].mech_type = CKM_MD5;
	fl->fl_threshold[5].mech_threshold = kcf_md5_threshold;
	fl->fl_threshold[6].mech_type = CKM_SHA_1;
	fl->fl_threshold[6].mech_threshold = kcf_sha1_threshold;
}

/* ARGSUSED */
static int
get_function_list(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_get_function_list_t get_function_list;
	crypto_minor_t *cm;
	crypto_provider_id_t provider_id;
	crypto_function_list_t *fl;
	kcf_provider_desc_t *provider;
	int rv;

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "get_function_list: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, &get_function_list, sizeof (get_function_list)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	/* initialize provider_array */
	if (cm->cm_provider_array == NULL) {
		rv = crypto_get_provider_list(cm, NULL, NULL, DONT_RETURN_LIST);
		if (rv != CRYPTO_SUCCESS) {
			goto release_minor;
		}
	}

	provider_id = get_function_list.fl_provider_id;
	mutex_enter(&cm->cm_lock);
	/* index must be less than count of providers */
	if (provider_id >= cm->cm_provider_count) {
		mutex_exit(&cm->cm_lock);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	ASSERT(cm->cm_provider_array != NULL);
	provider = cm->cm_provider_array[provider_id];
	mutex_exit(&cm->cm_lock);

	fl = &get_function_list.fl_list;
	bzero(fl, sizeof (crypto_function_list_t));

	if (provider->pd_prov_type != CRYPTO_LOGICAL_PROVIDER) {
		crypto_build_function_list(fl, provider);
	} else {
		kcf_provider_desc_t *prev = NULL, *pd;

		mutex_enter(&provider->pd_lock);
		while (kcf_get_next_logical_provider_member(provider,
		    prev, &pd)) {
			prev = pd;
			crypto_build_function_list(fl, pd);
			KCF_PROV_REFRELE(pd);
		}
		mutex_exit(&provider->pd_lock);
	}

	rv = CRYPTO_SUCCESS;

release_minor:
	crypto_release_minor(cm);

	get_function_list.fl_return_value = rv;

	if (copyout(&get_function_list, arg, sizeof (get_function_list)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * This ioctl maps a PKCS#11 mechanism string into an internal number
 * that is used by the kernel.  pn_internal_number is set to the
 * internal number.
 */
/* ARGSUSED */
static int
get_mechanism_number(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_mechanism_number, get_number);
	crypto_mech_type_t number;
	size_t len;
	char *mechanism_name;
	int rv;

	STRUCT_INIT(get_number, mode);

	if (copyin(arg, STRUCT_BUF(get_number), STRUCT_SIZE(get_number)) != 0)
		return (EFAULT);

	len = STRUCT_FGET(get_number, pn_mechanism_len);
	if (len == 0 || len > CRYPTO_MAX_MECH_NAME) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}
	mechanism_name = kmem_alloc(len, KM_SLEEP);

	if (copyin(STRUCT_FGETP(get_number, pn_mechanism_string),
	    mechanism_name, len) != 0) {
		kmem_free(mechanism_name, len);
		return (EFAULT);
	}

	/*
	 * Get mechanism number from kcf. We set the load_module
	 * flag to false since we use only hardware providers.
	 */
	number = crypto_mech2id_common(mechanism_name, B_FALSE);
	kmem_free(mechanism_name, len);
	if (number == CRYPTO_MECH_INVALID) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	bcopy((char *)&number, (char *)STRUCT_FADDR(get_number,
	    pn_internal_number), sizeof (number));

	rv = CRYPTO_SUCCESS;
out:
	STRUCT_FSET(get_number, pn_return_value, rv);

	if (copyout(STRUCT_BUF(get_number), arg,
	    STRUCT_SIZE(get_number)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * This ioctl returns an array of crypto_mech_name_t entries.
 * It lists all the PKCS#11 mechanisms available in the kernel.
 */
/* ARGSUSED */
static int
get_mechanism_list(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_mechanism_list, get_list);
	crypto_mech_name_t *entries;
	size_t copyout_size;
	uint_t req_count;
	uint_t count;
	ulong_t offset;
	int error = 0;

	STRUCT_INIT(get_list, mode);

	if (copyin(arg, STRUCT_BUF(get_list), STRUCT_SIZE(get_list)) != 0) {
		return (EFAULT);
	}

	entries = crypto_get_mech_list(&count, KM_SLEEP);

	/* Number of entries caller thinks we have */
	req_count = STRUCT_FGET(get_list, ml_count);

	STRUCT_FSET(get_list, ml_count, count);
	STRUCT_FSET(get_list, ml_return_value, CRYPTO_SUCCESS);

	/* check if buffer is too small */
	if (count > req_count) {
		STRUCT_FSET(get_list, ml_return_value, CRYPTO_BUFFER_TOO_SMALL);
	}

	/* copyout the first stuff */
	if (copyout(STRUCT_BUF(get_list), arg, STRUCT_SIZE(get_list)) != 0) {
		error = EFAULT;
	}

	/*
	 * If only requesting number of entries or buffer too small or an
	 * error occurred, stop here
	 */
	if (req_count == 0 || count > req_count || error != 0) {
		goto out;
	}

	copyout_size = count * sizeof (crypto_mech_name_t);

	/* copyout entries */
	offset = (ulong_t)STRUCT_FADDR(get_list, ml_list);
	offset -= (ulong_t)STRUCT_BUF(get_list);
	if (copyout(entries, arg + offset, copyout_size) != 0) {
		error = EFAULT;
	}

out:
	crypto_free_mech_list(entries, count);
	return (error);
}

/*
 * Copyout kernel array of mech_infos to user space.
 */
/* ARGSUSED */
static int
copyout_mechinfos(int mode, caddr_t out, uint_t count,
    crypto_mechanism_info_t *k_minfos, caddr_t u_minfos)
{
	STRUCT_DECL(crypto_mechanism_info, mi);
	caddr_t p;
	size_t len;
	int i;

	if (count == 0)
		return (0);

	STRUCT_INIT(mi, mode);

	len = count * STRUCT_SIZE(mi);

	ASSERT(u_minfos != NULL);
	p = u_minfos;
	for (i = 0; i < count; i++) {
		STRUCT_FSET(mi, mi_min_key_size, k_minfos[i].mi_min_key_size);
		STRUCT_FSET(mi, mi_max_key_size, k_minfos[i].mi_max_key_size);
		STRUCT_FSET(mi, mi_keysize_unit, k_minfos[i].mi_keysize_unit);
		STRUCT_FSET(mi, mi_usage, k_minfos[i].mi_usage);
		bcopy(STRUCT_BUF(mi), p, STRUCT_SIZE(mi));
		p += STRUCT_SIZE(mi);
	}

	if (copyout(u_minfos, out, len) != 0)
		return (EFAULT);

	return (0);
}

/*
 * This ioctl returns information for the specified mechanism.
 */
/* ARGSUSED */
static int
get_all_mechanism_info(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_all_mechanism_info, get_all_mech);
#ifdef _LP64
	STRUCT_DECL(crypto_mechanism_info, mi);
#else
	/* LINTED E_FUNC_SET_NOT_USED */
	STRUCT_DECL(crypto_mechanism_info, mi);
#endif
	crypto_mech_name_t mech_name;
	crypto_mech_type_t mech_type;
	crypto_mechanism_info_t *mech_infos = NULL;
	uint_t num_mech_infos = 0;
	uint_t req_count;
	caddr_t u_minfos;
	ulong_t offset;
	int error = 0;
	int rv;

	STRUCT_INIT(get_all_mech, mode);
	STRUCT_INIT(mi, mode);

	if (copyin(arg, STRUCT_BUF(get_all_mech),
	    STRUCT_SIZE(get_all_mech)) != 0) {
		return (EFAULT);
	}

	(void) strncpy(mech_name, STRUCT_FGET(get_all_mech, mi_mechanism_name),
	    CRYPTO_MAX_MECH_NAME);
	mech_type = crypto_mech2id(mech_name);

	if (mech_type == CRYPTO_MECH_INVALID) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out1;
	}

	rv = crypto_get_all_mech_info(mech_type, &mech_infos, &num_mech_infos,
	    KM_SLEEP);
	if (rv != CRYPTO_SUCCESS) {
		goto out1;
	}
	/* rv is CRYPTO_SUCCESS at this point */

	/* Number of entries caller thinks we have */
	req_count = STRUCT_FGET(get_all_mech, mi_count);

	STRUCT_FSET(get_all_mech, mi_count, num_mech_infos);

	/* check if buffer is too small */
	if (num_mech_infos > req_count) {
		rv = CRYPTO_BUFFER_TOO_SMALL;
	}

out1:
	STRUCT_FSET(get_all_mech, mi_return_value, rv);

	/* copy the first part */
	if (copyout(STRUCT_BUF(get_all_mech), arg,
	    STRUCT_SIZE(get_all_mech)) != 0) {
		error = EFAULT;
	}

	/*
	 * If only requesting number of entries, or there are no entries,
	 * or rv is not CRYPTO_SUCCESS due to buffer too small or some other
	 * crypto error, or an error occurred with copyout, stop here
	 */
	if (req_count == 0 || num_mech_infos == 0 || rv != CRYPTO_SUCCESS ||
	    error != 0) {
		goto out2;
	}

	/* copyout mech_infos */
	offset = (ulong_t)STRUCT_FADDR(get_all_mech, mi_list);
	offset -= (ulong_t)STRUCT_BUF(get_all_mech);

	u_minfos = kmem_alloc(num_mech_infos * STRUCT_SIZE(mi), KM_SLEEP);
	error = copyout_mechinfos(mode, arg + offset, num_mech_infos,
	    mech_infos, u_minfos);
	kmem_free(u_minfos, num_mech_infos * STRUCT_SIZE(mi));
out2:
	if (mech_infos != NULL)
		crypto_free_all_mech_info(mech_infos, num_mech_infos);
	return (error);
}

/*
 * Side-effects:
 *  1. This routine stores provider descriptor pointers in an array
 *     and increments each descriptor's reference count.  The array
 *     is stored in per-minor number storage.
 *  2. Destroys the old array and creates a new one every time
 *     this routine is called.
 */
int
crypto_get_provider_list(crypto_minor_t *cm, uint_t *count,
    crypto_provider_entry_t **array, boolean_t return_slot_list)
{
	kcf_provider_desc_t **provider_array;
	crypto_provider_entry_t *p = NULL;
	uint_t provider_count;
	int rval;
	int i;

	/*
	 * Take snapshot of provider table returning only HW entries
	 * that are in a usable state. Also returns logical provider entries.
	 */
	rval =  kcf_get_slot_list(&provider_count, &provider_array, B_FALSE);
	if (rval != CRYPTO_SUCCESS)
		return (rval);

	/* allocate memory before taking cm->cm_lock */
	if (return_slot_list) {
		if (provider_count != 0) {
			p = kmem_alloc(provider_count *
			    sizeof (crypto_provider_entry_t), KM_SLEEP);
			for (i = 0; i < provider_count; i++) {
				p[i].pe_provider_id = i;
				p[i].pe_mechanism_count =
				    provider_array[i]->pd_mech_list_count;
			}
		}
		*array = p;
		*count = provider_count;
	}

	/*
	 * Free existing array of providers and replace with new list.
	 */
	mutex_enter(&cm->cm_lock);
	if (cm->cm_provider_array != NULL) {
		ASSERT(cm->cm_provider_count > 0);
		kcf_free_provider_tab(cm->cm_provider_count,
		    cm->cm_provider_array);
	}

	cm->cm_provider_array = provider_array;
	cm->cm_provider_count = provider_count;
	mutex_exit(&cm->cm_lock);

	return (CRYPTO_SUCCESS);
}

/*
 * This ioctl returns an array of crypto_provider_entry_t entries.
 * This is how consumers learn which hardware providers are available.
 */
/* ARGSUSED */
static int
get_provider_list(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_provider_list, get_list);
	crypto_provider_entry_t *entries;
	crypto_minor_t *cm;
	size_t copyout_size;
	uint_t req_count;
	uint_t count;
	ulong_t offset;
	int rv;

	STRUCT_INIT(get_list, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "get_provider_list: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(get_list), STRUCT_SIZE(get_list)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	rv = crypto_get_provider_list(cm, &count, &entries, RETURN_LIST);
	if (rv != CRYPTO_SUCCESS) {
		crypto_release_minor(cm);
		STRUCT_FSET(get_list, pl_return_value, rv);
		if (copyout(STRUCT_BUF(get_list), arg,
		    STRUCT_SIZE(get_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	crypto_release_minor(cm);

	/* Number of slots caller thinks we have */
	req_count = STRUCT_FGET(get_list, pl_count);

	/* Check if only requesting number of slots */
	if (req_count == 0) {

		STRUCT_FSET(get_list, pl_count, count);
		STRUCT_FSET(get_list, pl_return_value, CRYPTO_SUCCESS);

		crypto_free_provider_list(entries, count);
		if (copyout(STRUCT_BUF(get_list), arg,
		    STRUCT_SIZE(get_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	req_count = STRUCT_FGET(get_list, pl_count);
	if (count > req_count) {
		STRUCT_FSET(get_list, pl_count, count);
		STRUCT_FSET(get_list, pl_return_value, CRYPTO_BUFFER_TOO_SMALL);
		crypto_free_provider_list(entries, count);
		if (copyout(STRUCT_BUF(get_list), arg,
		    STRUCT_SIZE(get_list)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	STRUCT_FSET(get_list, pl_count, count);
	STRUCT_FSET(get_list, pl_return_value, CRYPTO_SUCCESS);

	copyout_size = count * sizeof (crypto_provider_entry_t);

	/* copyout the first stuff */
	if (copyout(STRUCT_BUF(get_list), arg, STRUCT_SIZE(get_list)) != 0) {
		crypto_free_provider_list(entries, count);
		return (EFAULT);
	}

	if (count == 0) {
		crypto_free_provider_list(entries, count);
		return (0);
	}

	/* copyout entries */
	offset = (ulong_t)STRUCT_FADDR(get_list, pl_list);
	offset -= (ulong_t)STRUCT_BUF(get_list);
	if (copyout(entries, arg + offset, copyout_size) != 0) {
		crypto_free_provider_list(entries, count);
		return (EFAULT);
	}

	crypto_free_provider_list(entries, count);
	return (0);
}

static void
ext_to_provider_data(int mode, kcf_provider_desc_t *provider,
    crypto_provider_ext_info_t *ei, void *out)
{
	STRUCT_DECL(crypto_provider_data, pd);
	STRUCT_DECL(crypto_version, version);

	STRUCT_INIT(pd, mode);
	STRUCT_INIT(version, mode);

	bcopy(provider->pd_description, STRUCT_FGET(pd, pd_prov_desc),
	    CRYPTO_PROVIDER_DESCR_MAX_LEN);

	bcopy(ei->ei_label, STRUCT_FGET(pd, pd_label), CRYPTO_EXT_SIZE_LABEL);
	bcopy(ei->ei_manufacturerID, STRUCT_FGET(pd, pd_manufacturerID),
	    CRYPTO_EXT_SIZE_MANUF);
	bcopy(ei->ei_model, STRUCT_FGET(pd, pd_model), CRYPTO_EXT_SIZE_MODEL);
	bcopy(ei->ei_serial_number, STRUCT_FGET(pd, pd_serial_number),
	    CRYPTO_EXT_SIZE_SERIAL);
	/*
	 * We do not support ioctls for dual-function crypto operations yet.
	 * So, we clear this flag as it might have been set by a provider.
	 */
	ei->ei_flags &= ~CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS;

	STRUCT_FSET(pd, pd_flags, ei->ei_flags);
	STRUCT_FSET(pd, pd_max_session_count, ei->ei_max_session_count);
	STRUCT_FSET(pd, pd_session_count, (int)CRYPTO_UNAVAILABLE_INFO);
	STRUCT_FSET(pd, pd_max_rw_session_count, ei->ei_max_session_count);
	STRUCT_FSET(pd, pd_rw_session_count, (int)CRYPTO_UNAVAILABLE_INFO);
	STRUCT_FSET(pd, pd_max_pin_len, ei->ei_max_pin_len);
	STRUCT_FSET(pd, pd_min_pin_len, ei->ei_min_pin_len);
	STRUCT_FSET(pd, pd_total_public_memory, ei->ei_total_public_memory);
	STRUCT_FSET(pd, pd_free_public_memory, ei->ei_free_public_memory);
	STRUCT_FSET(pd, pd_total_private_memory, ei->ei_total_private_memory);
	STRUCT_FSET(pd, pd_free_private_memory, ei->ei_free_private_memory);
	STRUCT_FSET(version, cv_major, ei->ei_hardware_version.cv_major);
	STRUCT_FSET(version, cv_minor, ei->ei_hardware_version.cv_minor);
	bcopy(STRUCT_BUF(version), STRUCT_FADDR(pd, pd_hardware_version),
	    STRUCT_SIZE(version));
	STRUCT_FSET(version, cv_major, ei->ei_firmware_version.cv_major);
	STRUCT_FSET(version, cv_minor, ei->ei_firmware_version.cv_minor);
	bcopy(STRUCT_BUF(version), STRUCT_FADDR(pd, pd_firmware_version),
	    STRUCT_SIZE(version));
	bcopy(ei->ei_time, STRUCT_FGET(pd, pd_time), CRYPTO_EXT_SIZE_TIME);
	bcopy(STRUCT_BUF(pd), out, STRUCT_SIZE(pd));
}

/*
 * Utility routine to construct a crypto_provider_ext_info structure. Some
 * of the fields are constructed from information in the provider structure.
 * The rest of the fields have default values. We need to do this for
 * providers which do not support crypto_provider_management_ops routines.
 */
static void
fabricate_ext_info(kcf_provider_desc_t *provider,
    crypto_provider_ext_info_t *ei)
{
	/* empty label */
	(void) memset(ei->ei_label, ' ', CRYPTO_EXT_SIZE_LABEL);

	(void) memset(ei->ei_manufacturerID, ' ', CRYPTO_EXT_SIZE_MANUF);
	(void) strncpy((char *)ei->ei_manufacturerID, "Unknown", 7);

	(void) memset(ei->ei_model, ' ', CRYPTO_EXT_SIZE_MODEL);
	(void) strncpy((char *)ei->ei_model, "Unknown", 7);

	(void) memset(ei->ei_serial_number, ' ', CRYPTO_EXT_SIZE_SERIAL);
	(void) strncpy((char *)ei->ei_serial_number, "Unknown", 7);

	if (KCF_PROV_RANDOM_OPS(provider) != NULL)
		ei->ei_flags |= CRYPTO_EXTF_RNG;
	if (KCF_PROV_DUAL_OPS(provider) != NULL)
		ei->ei_flags |= CRYPTO_EXTF_DUAL_CRYPTO_OPERATIONS;

	ei->ei_max_session_count = CRYPTO_UNAVAILABLE_INFO;
	ei->ei_max_pin_len = 0;
	ei->ei_min_pin_len = 0;
	ei->ei_total_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ei->ei_free_public_memory = CRYPTO_UNAVAILABLE_INFO;
	ei->ei_total_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ei->ei_free_private_memory = CRYPTO_UNAVAILABLE_INFO;
	ei->ei_hardware_version.cv_major = 1;
	ei->ei_hardware_version.cv_minor = 0;
	ei->ei_firmware_version.cv_major = 1;
	ei->ei_firmware_version.cv_minor = 0;
}

/* ARGSUSED */
static int
get_provider_info(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_provider_info, get_info);
	crypto_minor_t *cm;
	crypto_provider_id_t provider_id;
	kcf_provider_desc_t *provider, *real_provider;
	crypto_provider_ext_info_t *ext_info = NULL;
	size_t need;
	int error = 0;
	int rv;
	kcf_req_params_t params;

	STRUCT_INIT(get_info, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "get_provider_info: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(get_info), STRUCT_SIZE(get_info)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	need = sizeof (crypto_provider_ext_info_t);
	if ((rv = crypto_buffer_check(need)) != CRYPTO_SUCCESS) {
		need = 0;
		goto release_minor;
	}

	/* initialize provider_array */
	if (cm->cm_provider_array == NULL) {
		rv = crypto_get_provider_list(cm, NULL, NULL, DONT_RETURN_LIST);
		if (rv != CRYPTO_SUCCESS) {
			goto release_minor;
		}
	}

	ext_info = kmem_zalloc(need, KM_SLEEP);

	provider_id = STRUCT_FGET(get_info, gi_provider_id);
	mutex_enter(&cm->cm_lock);
	/* index must be less than count of providers */
	if (provider_id >= cm->cm_provider_count) {
		mutex_exit(&cm->cm_lock);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	ASSERT(cm->cm_provider_array != NULL);
	provider = cm->cm_provider_array[provider_id];
	KCF_PROV_REFHOLD(provider);
	mutex_exit(&cm->cm_lock);

	(void) kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(provider_ops), CRYPTO_PROVIDER_OFFSET(ext_info),
	    provider, &real_provider);

	if (real_provider != NULL) {
		ASSERT(real_provider == provider ||
		    provider->pd_prov_type == CRYPTO_LOGICAL_PROVIDER);
		KCF_WRAP_PROVMGMT_OPS_PARAMS(&params, KCF_OP_MGMT_EXTINFO,
		    0, NULL, 0, NULL, 0, NULL, ext_info, provider);
		rv = kcf_submit_request(real_provider, NULL, NULL, &params,
		    B_FALSE);
		ASSERT(rv != CRYPTO_NOT_SUPPORTED);
		KCF_PROV_REFRELE(real_provider);
	} else {
		/* do the best we can */
		fabricate_ext_info(provider, ext_info);
		rv = CRYPTO_SUCCESS;
	}
	KCF_PROV_REFRELE(provider);

	if (rv == CRYPTO_SUCCESS) {
		ext_to_provider_data(mode, provider, ext_info,
		    STRUCT_FADDR(get_info, gi_provider_data));
	}

release_minor:
	CRYPTO_DECREMENT_RCTL(need);
	crypto_release_minor(cm);

	if (ext_info != NULL)
		kmem_free(ext_info, sizeof (crypto_provider_ext_info_t));

	if (error != 0)
		return (error);

	STRUCT_FSET(get_info, gi_return_value, rv);
	if (copyout(STRUCT_BUF(get_info), arg, STRUCT_SIZE(get_info)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * This ioctl returns an array of crypto_mech_name_t entries.
 * This is how consumers learn which mechanisms are permitted
 * by a provider.
 */
/* ARGSUSED */
static int
get_provider_mechanisms(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_get_provider_mechanisms, get_mechanisms);
	crypto_mech_name_t *entries;
	crypto_minor_t *cm;
	size_t copyout_size;
	uint_t req_count;
	uint_t count;
	ulong_t offset;
	int err;

	STRUCT_INIT(get_mechanisms, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "get_provider_mechanisms: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(get_mechanisms),
	    STRUCT_SIZE(get_mechanisms)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	/* get array of mechanisms from the core module */
	if ((err = crypto_get_provider_mechanisms(cm,
	    STRUCT_FGET(get_mechanisms, pm_provider_id),
	    &count, &entries)) != 0) {
		crypto_release_minor(cm);
		STRUCT_FSET(get_mechanisms, pm_return_value, err);
		if (copyout(STRUCT_BUF(get_mechanisms), arg,
		    STRUCT_SIZE(get_mechanisms)) != 0) {
			return (EFAULT);
		}
		return (0);
	}
	crypto_release_minor(cm);
	/* Number of mechs caller thinks we have */
	req_count = STRUCT_FGET(get_mechanisms, pm_count);

	/* Check if caller is just requesting a count of mechanisms */
	if (req_count == 0) {
		STRUCT_FSET(get_mechanisms, pm_count, count);
		STRUCT_FSET(get_mechanisms, pm_return_value, CRYPTO_SUCCESS);

		crypto_free_mech_list(entries, count);
		if (copyout(STRUCT_BUF(get_mechanisms), arg,
		    STRUCT_SIZE(get_mechanisms)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	/* check if buffer is too small */
	if (count > req_count) {
		STRUCT_FSET(get_mechanisms, pm_count, count);
		STRUCT_FSET(get_mechanisms, pm_return_value,
		    CRYPTO_BUFFER_TOO_SMALL);
		crypto_free_mech_list(entries, count);
		if (copyout(STRUCT_BUF(get_mechanisms), arg,
		    STRUCT_SIZE(get_mechanisms)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	STRUCT_FSET(get_mechanisms, pm_count, count);
	STRUCT_FSET(get_mechanisms, pm_return_value, CRYPTO_SUCCESS);

	copyout_size = count * sizeof (crypto_mech_name_t);

	/* copyout the first stuff */
	if (copyout(STRUCT_BUF(get_mechanisms), arg,
	    STRUCT_SIZE(get_mechanisms)) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}

	if (count == 0) {
		return (0);
	}

	/* copyout entries */
	offset = (ulong_t)STRUCT_FADDR(get_mechanisms, pm_list);
	offset -= (ulong_t)STRUCT_BUF(get_mechanisms);
	if (copyout(entries, arg + offset, copyout_size) != 0) {
		crypto_free_mech_list(entries, count);
		return (EFAULT);
	}

	crypto_free_mech_list(entries, count);
	return (0);
}

/*
 * This ioctl returns information about a provider's mechanism.
 */
/* ARGSUSED */
static int
get_provider_mechanism_info(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_get_provider_mechanism_info_t mechanism_info;
	crypto_minor_t *cm;
	kcf_provider_desc_t *pd;
	crypto_mech_info_t *mi = NULL;
	int rv = CRYPTO_SUCCESS;
	int i;

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "get_provider_mechanism_info: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, &mechanism_info, sizeof (mechanism_info)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	/* initialize provider table */
	if (cm->cm_provider_array == NULL) {
		rv = crypto_get_provider_list(cm, NULL, NULL, DONT_RETURN_LIST);
		if (rv != CRYPTO_SUCCESS) {
			mutex_enter(&cm->cm_lock);
			goto fail;
		}
	}

	/*
	 * Provider ID must be less than the count of providers
	 * obtained by calling get_provider_list().
	 */
	mutex_enter(&cm->cm_lock);
	if (mechanism_info.mi_provider_id >= cm->cm_provider_count) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto fail;
	}

	pd = cm->cm_provider_array[mechanism_info.mi_provider_id];

	/* First check if the provider supports the mechanism. */
	for (i = 0; i < pd->pd_mech_list_count; i++) {
		if (strncmp(pd->pd_mechanisms[i].cm_mech_name,
		    mechanism_info.mi_mechanism_name,
		    CRYPTO_MAX_MECH_NAME) == 0) {
			mi = &pd->pd_mechanisms[i];
			break;
		}
	}

	if (mi == NULL) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto fail;
	}

	/* Now check if the mechanism is enabled for the provider. */
	if (is_mech_disabled(pd, mechanism_info.mi_mechanism_name)) {
		rv = CRYPTO_MECHANISM_INVALID;
		goto fail;
	}

	mechanism_info.mi_min_key_size = mi->cm_min_key_length;
	mechanism_info.mi_max_key_size = mi->cm_max_key_length;
	mechanism_info.mi_flags = mi->cm_func_group_mask;

fail:
	mutex_exit(&cm->cm_lock);
	crypto_release_minor(cm);
	mechanism_info.mi_return_value = rv;
	if (copyout(&mechanism_info, arg, sizeof (mechanism_info)) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Every open of /dev/crypto multiplexes all PKCS#11 sessions across
 * a single session to each provider. Calls to open and close session
 * are not made to providers that do not support sessions. For these
 * providers, a session number of 0 is passed during subsequent operations,
 * and it is ignored by the provider.
 */
static int
crypto_get_provider_session(crypto_minor_t *cm,
    crypto_provider_id_t provider_index, crypto_provider_session_t **output_ps)
{
	kcf_provider_desc_t *pd, *real_provider;
	kcf_req_params_t params;
	crypto_provider_session_t *ps, *new_ps;
	crypto_session_id_t provider_session_id = 0;
	int rv;

	ASSERT(MUTEX_HELD(&cm->cm_lock));

	/* pd may be a logical provider */
	pd = cm->cm_provider_array[provider_index];

again:
	/*
	 * Check if there is already a session to the provider.
	 * Sessions may be to a logical provider or a real provider.
	 */
	for (ps = cm->cm_provider_session; ps != NULL; ps = ps->ps_next) {
		if (ps->ps_provider == pd)
			break;
	}

	/* found existing session */
	if (ps != NULL) {
		ps->ps_refcnt++;
		*output_ps = ps;
		return (CRYPTO_SUCCESS);
	}
	mutex_exit(&cm->cm_lock);

	/* find a hardware provider that supports session ops */
	(void) kcf_get_hardware_provider_nomech(CRYPTO_OPS_OFFSET(session_ops),
	    CRYPTO_SESSION_OFFSET(session_open), pd, &real_provider);

	if (real_provider != NULL) {
		ASSERT(real_provider == pd ||
		    pd->pd_prov_type == CRYPTO_LOGICAL_PROVIDER);
		/* open session to provider */
		KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_OPEN,
		    &provider_session_id, 0, CRYPTO_USER, NULL, 0, pd);
		rv = kcf_submit_request(real_provider, NULL, NULL, &params,
		    B_FALSE);
		if (rv != CRYPTO_SUCCESS) {
			mutex_enter(&cm->cm_lock);
			KCF_PROV_REFRELE(real_provider);
			return (rv);
		}
	}

	/* allocate crypto_provider_session structure */
	new_ps = kmem_zalloc(sizeof (crypto_provider_session_t), KM_SLEEP);

	/*
	 * Check if someone opened a session to the provider
	 * while we dropped the lock.
	 */
	mutex_enter(&cm->cm_lock);
	for (ps = cm->cm_provider_session; ps != NULL; ps = ps->ps_next) {
		if (ps->ps_provider == pd) {
			mutex_exit(&cm->cm_lock);
			kmem_free(new_ps, sizeof (crypto_provider_session_t));
			if (real_provider != NULL) {
				KCF_WRAP_SESSION_OPS_PARAMS(&params,
				    KCF_OP_SESSION_CLOSE, NULL,
				    provider_session_id, CRYPTO_USER, NULL, 0,
				    pd);
				(void) kcf_submit_request(real_provider, NULL,
				    NULL, &params, B_FALSE);
				KCF_PROV_REFRELE(real_provider);
			}
			mutex_enter(&cm->cm_lock);
			goto again;

		}
	}

	/* increment refcnt and attach to crypto_minor structure */
	new_ps->ps_session = provider_session_id;
	new_ps->ps_refcnt = 1;
	KCF_PROV_REFHOLD(pd);
	new_ps->ps_provider = pd;
	if (real_provider != NULL) {
		new_ps->ps_real_provider = real_provider;
	}
	new_ps->ps_next = cm->cm_provider_session;
	cm->cm_provider_session = new_ps;

	*output_ps = new_ps;
	return (CRYPTO_SUCCESS);
}

/*
 * Release a provider session.
 * If the reference count goes to zero, then close the session
 * to the provider.
 */
static void
crypto_release_provider_session(crypto_minor_t *cm,
    crypto_provider_session_t *provider_session)
{
	kcf_req_params_t params;
	crypto_provider_session_t *ps = NULL, **prev;

	ASSERT(MUTEX_HELD(&cm->cm_lock));

	/* verify that provider_session is valid */
	for (ps = cm->cm_provider_session, prev = &cm->cm_provider_session;
	    ps != NULL; prev = &ps->ps_next, ps = ps->ps_next) {
		if (ps == provider_session) {
			break;
		}
	}

	if (ps == NULL)
		return;

	ps->ps_refcnt--;

	if (ps->ps_refcnt > 0)
		return;

	if (ps->ps_real_provider != NULL) {
		/* close session with provider */
		KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_CLOSE, NULL,
		    ps->ps_session, CRYPTO_USER, NULL, 0, ps->ps_provider);
		(void) kcf_submit_request(ps->ps_real_provider,
		    NULL, NULL, &params, B_FALSE);
		KCF_PROV_REFRELE(ps->ps_real_provider);
	}
	KCF_PROV_REFRELE(ps->ps_provider);
	*prev = ps->ps_next;
	kmem_free(ps, sizeof (*ps));
}

static int
grow_session_table(crypto_minor_t *cm)
{
	crypto_session_data_t **session_table;
	crypto_session_data_t **new;
	uint_t session_table_count;
	uint_t need;
	size_t current_allocation;
	size_t new_allocation;
	int rv;

	ASSERT(MUTEX_HELD(&cm->cm_lock));

	session_table_count = cm->cm_session_table_count;
	session_table = cm->cm_session_table;
	need = session_table_count + CRYPTO_SESSION_CHUNK;

	current_allocation = session_table_count * sizeof (void *);
	new_allocation = need * sizeof (void *);

	/*
	 * Memory needed to grow the session table is checked
	 * against the project.max-crypto-memory resource control.
	 */
	if ((rv = crypto_buffer_check(new_allocation - current_allocation)) !=
	    CRYPTO_SUCCESS) {
		return (rv);
	}

	/* drop lock while we allocate memory */
	mutex_exit(&cm->cm_lock);
	new = kmem_zalloc(new_allocation, KM_SLEEP);
	mutex_enter(&cm->cm_lock);

	/* check if another thread increased the table size */
	if (session_table_count != cm->cm_session_table_count) {
		kmem_free(new, new_allocation);
		return (CRYPTO_SUCCESS);
	}

	bcopy(session_table, new, current_allocation);
	kmem_free(session_table, current_allocation);
	cm->cm_session_table = new;
	cm->cm_session_table_count += CRYPTO_SESSION_CHUNK;

	return (CRYPTO_SUCCESS);
}

/*
 * Find unused entry in session table and return it's index.
 * Initialize session table entry.
 */
/* ARGSUSED */
static int
crypto_open_session(dev_t dev, uint_t flags, crypto_session_id_t *session_index,
    crypto_provider_id_t provider_id)
{
	crypto_session_data_t **session_table;
	crypto_session_data_t *sp;
	crypto_minor_t *cm;
	uint_t session_table_count;
	uint_t i;
	int rv;
	crypto_provider_session_t *ps;
	kcf_provider_desc_t *provider;

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "crypto_open_session: failed holding minor");
		return (CRYPTO_FAILED);
	}

	/* initialize provider_array */
	if (cm->cm_provider_array == NULL) {
		rv = crypto_get_provider_list(cm, NULL, NULL, DONT_RETURN_LIST);
		if (rv != 0) {
			crypto_release_minor(cm);
			return (rv);
		}
	}

	mutex_enter(&cm->cm_lock);
	/* index must be less than count of providers */
	if (provider_id >= cm->cm_provider_count) {
		mutex_exit(&cm->cm_lock);
		crypto_release_minor(cm);
		return (CRYPTO_INVALID_PROVIDER_ID);
	}
	ASSERT(cm->cm_provider_array != NULL);

	rv = crypto_get_provider_session(cm, provider_id, &ps);
	if (rv != CRYPTO_SUCCESS) {
		mutex_exit(&cm->cm_lock);
		crypto_release_minor(cm);
		return (rv);
	}
	provider = cm->cm_provider_array[provider_id];

again:
	session_table_count = cm->cm_session_table_count;
	session_table = cm->cm_session_table;

	/* session handles start with 1 */
	for (i = 1; i < session_table_count; i++) {
		if (session_table[i] == NULL)
			break;
	}

	if (i == session_table_count || session_table_count == 0) {
		if ((rv = grow_session_table(cm)) != CRYPTO_SUCCESS) {
			crypto_release_provider_session(cm, ps);
			mutex_exit(&cm->cm_lock);
			crypto_release_minor(cm);
			return (rv);
		}
		goto again;
	}

	sp = kmem_cache_alloc(crypto_session_cache, KM_SLEEP);
	sp->sd_flags = 0;
	sp->sd_find_init_cookie = NULL;
	sp->sd_digest_ctx = NULL;
	sp->sd_encr_ctx = NULL;
	sp->sd_decr_ctx = NULL;
	sp->sd_sign_ctx = NULL;
	sp->sd_verify_ctx = NULL;
	sp->sd_sign_recover_ctx = NULL;
	sp->sd_verify_recover_ctx = NULL;
	mutex_init(&sp->sd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&sp->sd_cv, NULL, CV_DRIVER, NULL);
	KCF_PROV_REFHOLD(provider);
	sp->sd_provider = provider;
	sp->sd_provider_session = ps;

	/* See the comment for CRYPTO_PRE_APPROVED_LIMIT. */
	if ((rv = crypto_buffer_check(crypto_pre_approved_limit)) !=
	    CRYPTO_SUCCESS) {
		sp->sd_pre_approved_amount = 0;
	} else {
		sp->sd_pre_approved_amount = (int)crypto_pre_approved_limit;
	}

	cm->cm_session_table[i] = sp;
	mutex_exit(&cm->cm_lock);
	crypto_release_minor(cm);
	*session_index = i;

	return (CRYPTO_SUCCESS);
}

/*
 * Close a session.
 */
static int
crypto_close_session(dev_t dev, crypto_session_id_t session_index)
{
	crypto_session_data_t **session_table;
	crypto_session_data_t *sp;
	crypto_minor_t *cm;

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "crypto_close_session: failed holding minor");
		return (CRYPTO_FAILED);
	}

	mutex_enter(&cm->cm_lock);
	session_table = cm->cm_session_table;

	if ((session_index) == 0 ||
	    (session_index >= cm->cm_session_table_count)) {
		mutex_exit(&cm->cm_lock);
		crypto_release_minor(cm);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}

	sp = session_table[session_index];
	if (sp == NULL) {
		mutex_exit(&cm->cm_lock);
		crypto_release_minor(cm);
		return (CRYPTO_SESSION_HANDLE_INVALID);
	}
	/*
	 * If session is in use, free it when the thread
	 * finishes with the session.
	 */
	mutex_enter(&sp->sd_lock);
	if (sp->sd_flags & CRYPTO_SESSION_IS_BUSY) {
		sp->sd_flags |= CRYPTO_SESSION_IS_CLOSED;
		mutex_exit(&sp->sd_lock);
	} else {
		ASSERT(sp->sd_pre_approved_amount == 0 ||
		    sp->sd_pre_approved_amount == crypto_pre_approved_limit);
		CRYPTO_DECREMENT_RCTL(sp->sd_pre_approved_amount);

		if (sp->sd_find_init_cookie != NULL) {
			(void) crypto_free_find_ctx(sp);
		}

		crypto_release_provider_session(cm, sp->sd_provider_session);
		KCF_PROV_REFRELE(sp->sd_provider);
		CRYPTO_CANCEL_ALL_CTX(sp);
		mutex_destroy(&sp->sd_lock);
		cv_destroy(&sp->sd_cv);
		kmem_cache_free(crypto_session_cache, sp);
		session_table[session_index] = NULL;
	}

	mutex_exit(&cm->cm_lock);
	crypto_release_minor(cm);

	return (CRYPTO_SUCCESS);
}

/*
 * This ioctl opens a session and returns the session ID in os_session.
 */
/* ARGSUSED */
static int
open_session(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_open_session_t open_session;
	crypto_session_id_t session;
	int rv;

	if (copyin(arg, &open_session, sizeof (open_session)) != 0)
		return (EFAULT);

	rv = crypto_open_session(dev, open_session.os_flags,
	    &session, open_session.os_provider_id);
	if (rv != CRYPTO_SUCCESS) {
		open_session.os_return_value = rv;
		if (copyout(&open_session, arg, sizeof (open_session)) != 0) {
			return (EFAULT);
		}
		return (0);
	}

	open_session.os_session = session;
	open_session.os_return_value = CRYPTO_SUCCESS;

	if (copyout(&open_session, arg, sizeof (open_session)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * This ioctl closes a session.
 */
/* ARGSUSED */
static int
close_session(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_close_session_t close_session;
	int rv;

	if (copyin(arg, &close_session, sizeof (close_session)) != 0)
		return (EFAULT);

	rv = crypto_close_session(dev, close_session.cs_session);
	close_session.cs_return_value = rv;
	if (copyout(&close_session, arg, sizeof (close_session)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * Copy data model dependent mechanism structure into a kernel mechanism
 * structure.  Allocate param storage if necessary.
 */
static boolean_t
copyin_mech(int mode, crypto_session_data_t *sp, crypto_mechanism_t *in_mech,
    crypto_mechanism_t *out_mech, size_t *out_rctl_bytes,
    boolean_t *out_rctl_chk, int *out_rv, int *out_error)
{
	STRUCT_DECL(crypto_mechanism, mech);
	caddr_t param;
	size_t param_len;
	size_t rctl_bytes = 0;
	int error = 0;
	int rv = 0;

	STRUCT_INIT(mech, mode);
	bcopy(in_mech, STRUCT_BUF(mech), STRUCT_SIZE(mech));
	param = STRUCT_FGETP(mech, cm_param);
	param_len = STRUCT_FGET(mech, cm_param_len);
	out_mech->cm_type = STRUCT_FGET(mech, cm_type);
	out_mech->cm_param = NULL;
	out_mech->cm_param_len = 0;
	if (param != NULL && param_len != 0) {
		if (param_len > crypto_max_buffer_len) {
			cmn_err(CE_NOTE, "copyin_mech: buffer greater than "
			    "%ld bytes, pid = %d", crypto_max_buffer_len,
			    curproc->p_pid);
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}

		rv = CRYPTO_BUFFER_CHECK(sp, param_len, *out_rctl_chk);
		if (rv != CRYPTO_SUCCESS) {
			goto out;
		}
		rctl_bytes = param_len;

		out_mech->cm_param = kmem_alloc(param_len, KM_SLEEP);
		if (copyin((char *)param, out_mech->cm_param, param_len) != 0) {
			kmem_free(out_mech->cm_param, param_len);
			out_mech->cm_param = NULL;
			error = EFAULT;
			goto out;
		}
		out_mech->cm_param_len = param_len;
	}
out:
	*out_rctl_bytes = rctl_bytes;
	*out_rv = rv;
	*out_error = error;
	return ((rv | error) ? B_FALSE : B_TRUE);
}

/*
 * Free key attributes when key type is CRYPTO_KEY_ATTR_LIST.
 * The crypto_key structure is not freed.
 */
static void
crypto_free_key_attributes(crypto_key_t *key)
{
	crypto_object_attribute_t *attrs;
	size_t len = 0;
	int i;

	ASSERT(key->ck_format == CRYPTO_KEY_ATTR_LIST);
	if (key->ck_count == 0 || key->ck_attrs == NULL)
		return;

	/* compute the size of the container */
	len = key->ck_count * sizeof (crypto_object_attribute_t);

	/* total up the size of all attributes in the container */
	for (i = 0; i < key->ck_count; i++) {
		attrs = &key->ck_attrs[i];
		if (attrs->oa_value_len != 0 &&
		    attrs->oa_value != NULL) {
			len += roundup(attrs->oa_value_len, sizeof (caddr_t));
		}
	}

	bzero(key->ck_attrs, len);
	kmem_free(key->ck_attrs, len);
}

/*
 * Frees allocated storage in the key structure, but doesn't free
 * the key structure.
 */
static void
free_crypto_key(crypto_key_t *key)
{
	switch (key->ck_format) {
	case CRYPTO_KEY_RAW: {
		size_t len;

		if (key->ck_length == 0 || key->ck_data == NULL)
			break;

		len = CRYPTO_BITS2BYTES(key->ck_length);
		bzero(key->ck_data, len);
		kmem_free(key->ck_data, len);
		break;
	}

	case CRYPTO_KEY_ATTR_LIST:
		crypto_free_key_attributes(key);
		break;

	default:
		break;
	}
}

/*
 * Copy in an array of crypto_object_attribute structures from user-space.
 * Kernel memory is allocated for the array and the value of each attribute
 * in the array.  Since unprivileged users can specify the size of attributes,
 * the amount of memory needed is charged against the
 * project.max-crypto-memory resource control.
 *
 * Attribute values are copied in from user-space if copyin_value is set to
 * B_TRUE.  This routine returns B_TRUE if the copyin was successful.
 */
static boolean_t
copyin_attributes(int mode, crypto_session_data_t *sp,
    uint_t count, caddr_t oc_attributes,
    crypto_object_attribute_t **k_attrs_out, size_t *k_attrs_size_out,
    caddr_t *u_attrs_out, int *out_rv, int *out_error, size_t *out_rctl_bytes,
    boolean_t *out_rctl_chk, boolean_t copyin_value)
{
	STRUCT_DECL(crypto_object_attribute, oa);
	crypto_object_attribute_t *k_attrs = NULL;
	caddr_t attrs = NULL, ap, p, value;
	caddr_t k_attrs_buf;
	size_t k_attrs_len;
	size_t k_attrs_buf_len = 0;
	size_t k_attrs_total_len = 0;
	size_t tmp_len;
	size_t rctl_bytes = 0;
	size_t len = 0;
	size_t value_len;
	int error = 0;
	int rv = 0;
	int i;

	STRUCT_INIT(oa, mode);

	if (count == 0) {
		rv = CRYPTO_SUCCESS;
		goto out;
	}

	if (count > CRYPTO_MAX_ATTRIBUTE_COUNT) {
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	/* compute size of crypto_object_attribute array */
	len = count * STRUCT_SIZE(oa);

	/* this allocation is not charged against the user's resource limit */
	attrs = kmem_alloc(len, KM_SLEEP);
	if (copyin(oc_attributes, attrs, len) != 0) {
		error = EFAULT;
		goto out;
	}

	/* figure out how much memory to allocate for all of the attributes */
	ap = attrs;
	for (i = 0; i < count; i++) {
		bcopy(ap, STRUCT_BUF(oa), STRUCT_SIZE(oa));
		tmp_len = roundup(STRUCT_FGET(oa, oa_value_len),
		    sizeof (caddr_t));
		if (tmp_len > crypto_max_buffer_len) {
			cmn_err(CE_NOTE, "copyin_attributes: buffer greater "
			    "than %ld bytes, pid = %d", crypto_max_buffer_len,
			    curproc->p_pid);
			rv = CRYPTO_ARGUMENTS_BAD;
			goto out;
		}
		if (STRUCT_FGETP(oa, oa_value) != NULL)
			k_attrs_buf_len += tmp_len;
		ap += STRUCT_SIZE(oa);
	}

	k_attrs_len = count * sizeof (crypto_object_attribute_t);
	k_attrs_total_len = k_attrs_buf_len + k_attrs_len;

	rv = CRYPTO_BUFFER_CHECK(sp, k_attrs_total_len, *out_rctl_chk);
	if (rv != CRYPTO_SUCCESS) {
		goto out;
	}
	rctl_bytes = k_attrs_total_len;

	/* one big allocation for everything */
	k_attrs = kmem_alloc(k_attrs_total_len, KM_SLEEP);
	k_attrs_buf = (char *)k_attrs + k_attrs_len;

	ap = attrs;
	p = k_attrs_buf;
	for (i = 0; i < count; i++) {
		bcopy(ap, STRUCT_BUF(oa), STRUCT_SIZE(oa));
		k_attrs[i].oa_type = STRUCT_FGET(oa, oa_type);
		value = STRUCT_FGETP(oa, oa_value);
		value_len = STRUCT_FGET(oa, oa_value_len);
		if (value != NULL && value_len != 0 && copyin_value) {
			if (copyin(value, p, value_len) != 0) {
				kmem_free(k_attrs, k_attrs_total_len);
				k_attrs = NULL;
				error = EFAULT;
				goto out;
			}
		}

		if (value != NULL) {
			k_attrs[i].oa_value = p;
			p += roundup(value_len, sizeof (caddr_t));
		} else {
			k_attrs[i].oa_value = NULL;
		}
		k_attrs[i].oa_value_len = value_len;
		ap += STRUCT_SIZE(oa);
	}
out:
	if (attrs != NULL) {
		/*
		 * Free the array if there is a failure or the caller
		 * doesn't want the array to be returned.
		 */
		if (error != 0 || rv != CRYPTO_SUCCESS || u_attrs_out == NULL) {
			kmem_free(attrs, len);
			attrs = NULL;
		}
	}

	if (u_attrs_out != NULL)
		*u_attrs_out = attrs;
	if (k_attrs_size_out != NULL)
		*k_attrs_size_out = k_attrs_total_len;
	*k_attrs_out = k_attrs;
	*out_rctl_bytes = rctl_bytes;
	*out_rv = rv;
	*out_error = error;
	return ((rv | error) ? B_FALSE : B_TRUE);
}

/*
 * Copy data model dependent raw key into a kernel key
 * structure.  Checks key length or attribute lengths against
 * resource controls before allocating memory.  Returns B_TRUE
 * if both error and rv are set to 0.
 */
static boolean_t
copyin_key(int mode, crypto_session_data_t *sp, crypto_key_t *in_key,
    crypto_key_t *out_key, size_t *out_rctl_bytes,
    boolean_t *out_rctl_chk, int *out_rv, int *out_error)
{
	STRUCT_DECL(crypto_key, key);
	crypto_object_attribute_t *k_attrs = NULL;
	size_t key_bits;
	size_t key_bytes = 0;
	size_t rctl_bytes = 0;
	int count;
	int error = 0;
	int rv = CRYPTO_SUCCESS;

	STRUCT_INIT(key, mode);
	bcopy(in_key, STRUCT_BUF(key), STRUCT_SIZE(key));
	out_key->ck_format = STRUCT_FGET(key, ck_format);
	switch (out_key->ck_format) {
	case CRYPTO_KEY_RAW:
		key_bits = STRUCT_FGET(key, ck_length);
		if (key_bits != 0) {
			if (key_bits >
			    (CRYPTO_BYTES2BITS(crypto_max_buffer_len))) {
				cmn_err(CE_NOTE, "copyin_key: buffer greater "
				    "than %ld bytes, pid = %d",
				    crypto_max_buffer_len, curproc->p_pid);
				rv = CRYPTO_ARGUMENTS_BAD;
				goto out;
			}
			key_bytes = CRYPTO_BITS2BYTES(key_bits);

			rv = CRYPTO_BUFFER_CHECK(sp, key_bytes,
			    *out_rctl_chk);
			if (rv != CRYPTO_SUCCESS) {
				goto out;
			}
			rctl_bytes = key_bytes;

			out_key->ck_data = kmem_alloc(key_bytes, KM_SLEEP);

			if (copyin((char *)STRUCT_FGETP(key, ck_data),
			    out_key->ck_data, key_bytes) != 0) {
				kmem_free(out_key->ck_data, key_bytes);
				out_key->ck_data = NULL;
				out_key->ck_length = 0;
				error = EFAULT;
				goto out;
			}
		}
		out_key->ck_length = (ulong_t)key_bits;
		break;

	case CRYPTO_KEY_ATTR_LIST:
		count = STRUCT_FGET(key, ck_count);

		if (copyin_attributes(mode, sp, count,
		    (caddr_t)STRUCT_FGETP(key, ck_attrs), &k_attrs, NULL, NULL,
		    &rv, &error, &rctl_bytes, out_rctl_chk, B_TRUE)) {
			out_key->ck_count = count;
			out_key->ck_attrs = k_attrs;
			k_attrs = NULL;
		} else {
			out_key->ck_count = 0;
			out_key->ck_attrs = NULL;
		}
		break;

	case CRYPTO_KEY_REFERENCE:
		out_key->ck_obj_id = STRUCT_FGET(key, ck_obj_id);
		break;

	default:
		rv = CRYPTO_ARGUMENTS_BAD;
	}

out:
	*out_rctl_bytes = rctl_bytes;
	*out_rv = rv;
	*out_error = error;
	return ((rv | error) ? B_FALSE : B_TRUE);
}

/*
 * This routine does two things:
 * 1. Given a crypto_minor structure and a session ID, it returns
 *    a valid session pointer.
 * 2. It checks that the provider, to which the session has been opened,
 *    has not been removed.
 */
static boolean_t
get_session_ptr(crypto_session_id_t i, crypto_minor_t *cm,
    crypto_session_data_t **session_ptr, int *out_error, int *out_rv)
{
	crypto_session_data_t *sp = NULL;
	int rv = CRYPTO_SESSION_HANDLE_INVALID;
	int error = 0;

	mutex_enter(&cm->cm_lock);
	if ((i < cm->cm_session_table_count) &&
	    (cm->cm_session_table[i] != NULL)) {
		sp = cm->cm_session_table[i];
		mutex_enter(&sp->sd_lock);
		mutex_exit(&cm->cm_lock);
		while (sp->sd_flags & CRYPTO_SESSION_IS_BUSY) {
			if (cv_wait_sig(&sp->sd_cv, &sp->sd_lock) == 0) {
				mutex_exit(&sp->sd_lock);
				sp = NULL;
				error = EINTR;
				goto out;
			}
		}

		if (sp->sd_flags & CRYPTO_SESSION_IS_CLOSED) {
			mutex_exit(&sp->sd_lock);
			sp = NULL;
			goto out;
		}

		if (KCF_IS_PROV_REMOVED(sp->sd_provider)) {
			mutex_exit(&sp->sd_lock);
			sp = NULL;
			rv = CRYPTO_DEVICE_ERROR;
			goto out;
		}

		rv = CRYPTO_SUCCESS;
		sp->sd_flags |= CRYPTO_SESSION_IS_BUSY;
		mutex_exit(&sp->sd_lock);
	} else {
		mutex_exit(&cm->cm_lock);
	}
out:
	*session_ptr = sp;
	*out_error = error;
	*out_rv = rv;
	return ((rv == CRYPTO_SUCCESS && error == 0) ? B_TRUE : B_FALSE);
}

#define	CRYPTO_SESSION_RELE(s)	if ((s) != NULL) {	\
	mutex_enter(&((s)->sd_lock));			\
	(s)->sd_flags &= ~CRYPTO_SESSION_IS_BUSY;	\
	cv_broadcast(&(s)->sd_cv);			\
	mutex_exit(&((s)->sd_lock));			\
}

/* ARGSUSED */
static int
encrypt_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher_init(dev, arg, mode, crypto_encrypt_init_prov));
}

/* ARGSUSED */
static int
decrypt_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher_init(dev, arg, mode, crypto_decrypt_init_prov));
}

/*
 * umech is a mechanism structure that has been copied from user address
 * space into kernel address space. Only one copyin has been done.
 * The mechanism parameter, if non-null, still points to user address space.
 * If the mechanism parameter contains pointers, they are pointers into
 * user address space.
 *
 * kmech is a umech with all pointers and structures in kernel address space.
 *
 * This routine calls the provider's entry point to copy a umech parameter
 * into kernel address space. Kernel memory is allocated by the provider.
 */
static int
crypto_provider_copyin_mech_param(kcf_provider_desc_t *pd,
    crypto_mechanism_t *umech, crypto_mechanism_t *kmech, int mode, int *error)
{
	crypto_mech_type_t provider_mech_type;
	int rv;

	/* get the provider's mech number */
	provider_mech_type = KCF_TO_PROV_MECHNUM(pd, umech->cm_type);

	kmech->cm_param = NULL;
	kmech->cm_param_len = 0;
	kmech->cm_type = provider_mech_type;
	rv = KCF_PROV_COPYIN_MECH(pd, umech, kmech, error, mode);
	kmech->cm_type = umech->cm_type;

	return (rv);
}

/*
 * umech is a mechanism structure that has been copied from user address
 * space into kernel address space. Only one copyin has been done.
 * The mechanism parameter, if non-null, still points to user address space.
 * If the mechanism parameter contains pointers, they are pointers into
 * user address space.
 *
 * kmech is a umech with all pointers and structures in kernel address space.
 *
 * This routine calls the provider's entry point to copy a kmech parameter
 * into user address space using umech as a template containing
 * user address pointers.
 */
static int
crypto_provider_copyout_mech_param(kcf_provider_desc_t *pd,
    crypto_mechanism_t *kmech, crypto_mechanism_t *umech, int mode, int *error)
{
	crypto_mech_type_t provider_mech_type;
	int rv;

	/* get the provider's mech number */
	provider_mech_type = KCF_TO_PROV_MECHNUM(pd, umech->cm_type);

	kmech->cm_type = provider_mech_type;
	rv = KCF_PROV_COPYOUT_MECH(pd, kmech, umech, error, mode);
	kmech->cm_type = umech->cm_type;

	return (rv);
}

/*
 * Call the provider's entry point to free kernel memory that has been
 * allocated for the mechanism's parameter.
 */
static void
crypto_free_mech(kcf_provider_desc_t *pd, boolean_t allocated_by_crypto_module,
    crypto_mechanism_t *mech)
{
	crypto_mech_type_t provider_mech_type;

	if (allocated_by_crypto_module) {
		if (mech->cm_param != NULL)
			kmem_free(mech->cm_param, mech->cm_param_len);
	} else {
		/* get the provider's mech number */
		provider_mech_type = KCF_TO_PROV_MECHNUM(pd, mech->cm_type);

		if (mech->cm_param != NULL && mech->cm_param_len != 0) {
			mech->cm_type = provider_mech_type;
			(void) KCF_PROV_FREE_MECH(pd, mech);
		}
	}
}

/*
 * ASSUMPTION: crypto_encrypt_init and crypto_decrypt_init
 * structures are identical except for field names.
 */
static int
cipher_init(dev_t dev, caddr_t arg, int mode, int (*init)(crypto_provider_t,
    crypto_session_id_t, crypto_mechanism_t *, crypto_key_t *,
    crypto_ctx_template_t, crypto_context_t *, crypto_call_req_t *))
{
	STRUCT_DECL(crypto_encrypt_init, encrypt_init);
	kcf_provider_desc_t *real_provider = NULL;
	crypto_session_id_t session_id;
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_context_t cc;
	crypto_ctx_t **ctxpp;
	size_t mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	size_t key_rctl_bytes = 0;
	boolean_t key_rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	crypto_func_group_t fg;

	STRUCT_INIT(encrypt_init, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "cipher_init: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(encrypt_init),
	    STRUCT_SIZE(encrypt_init)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	mech.cm_param = NULL;
	bzero(&key, sizeof (crypto_key_t));

	session_id = STRUCT_FGET(encrypt_init, ei_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto out;
	}

	bcopy(STRUCT_FADDR(encrypt_init, ei_mech), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	if (init == crypto_encrypt_init_prov) {
		fg = CRYPTO_FG_ENCRYPT;
	} else {
		fg = CRYPTO_FG_DECRYPT;
	}

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(encrypt_init, ei_key), &key,
	    &key_rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto out;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &key,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider, &real_provider, fg))
	    != CRYPTO_SUCCESS) {
		goto out;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(encrypt_init, ei_mech), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(encrypt_init, ei_mech),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto out;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto out;
	}

	rv = (init)(real_provider, sp->sd_provider_session->ps_session,
	    &mech, &key, NULL, &cc, NULL);

	/*
	 * Check if a context already exists. If so, it means it is being
	 * abandoned. So, cancel it to avoid leaking it.
	 */
	ctxpp = (init == crypto_encrypt_init_prov) ?
	    &sp->sd_encr_ctx : &sp->sd_decr_ctx;

	if (*ctxpp != NULL)
		CRYPTO_CANCEL_CTX(ctxpp);
	*ctxpp = (rv == CRYPTO_SUCCESS) ? cc : NULL;

out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}

	free_crypto_key(&key);

	if (error != 0)
		/* XXX free context */
		return (error);

	STRUCT_FSET(encrypt_init, ei_return_value, rv);
	if (copyout(STRUCT_BUF(encrypt_init), arg,
	    STRUCT_SIZE(encrypt_init)) != 0) {
		/* XXX free context */
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
encrypt(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher(dev, arg, mode, crypto_encrypt_single));
}

/* ARGSUSED */
static int
decrypt(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher(dev, arg, mode, crypto_decrypt_single));
}

/*
 * ASSUMPTION: crypto_encrypt and crypto_decrypt structures
 * are identical except for field names.
 */
static int
cipher(dev_t dev, caddr_t arg, int mode,
    int (*single)(crypto_context_t, crypto_data_t *, crypto_data_t *,
    crypto_call_req_t *))
{
	STRUCT_DECL(crypto_encrypt, encrypt);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_ctx_t **ctxpp;
	crypto_data_t data, encr;
	size_t datalen, encrlen, need = 0;
	boolean_t do_inplace;
	char *encrbuf;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(encrypt, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "cipher: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(encrypt), STRUCT_SIZE(encrypt)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_raw.iov_base = NULL;
	encr.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(encrypt, ce_datalen);
	encrlen = STRUCT_FGET(encrypt, ce_encrlen);

	/*
	 * Don't allocate output buffer unless both buffer pointer and
	 * buffer length are not NULL or 0 (length).
	 */
	encrbuf = STRUCT_FGETP(encrypt, ce_encrbuf);
	if (encrbuf == NULL || encrlen == 0) {
		encrlen = 0;
	}

	if (datalen > crypto_max_buffer_len ||
	    encrlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "cipher: buffer greater than %ld bytes, "
		    "pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(encrypt, ce_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto release_minor;
	}

	do_inplace = (STRUCT_FGET(encrypt, ce_flags) &
	    CRYPTO_INPLACE_OPERATION) != 0;
	need = do_inplace ? datalen : datalen + encrlen;

	if ((rv = CRYPTO_BUFFER_CHECK(sp, need, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		need = 0;
		goto release_minor;
	}

	INIT_RAW_CRYPTO_DATA(data, datalen);
	data.cd_miscdata = NULL;

	if (datalen != 0 && copyin(STRUCT_FGETP(encrypt, ce_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	if (do_inplace) {
		/* set out = in for in-place */
		encr = data;
	} else {
		INIT_RAW_CRYPTO_DATA(encr, encrlen);
	}

	ctxpp = (single == crypto_encrypt_single) ?
	    &sp->sd_encr_ctx : &sp->sd_decr_ctx;

	if (do_inplace)
		/* specify in-place buffers with output = NULL */
		rv = (single)(*ctxpp, &encr, NULL, NULL);
	else
		rv = (single)(*ctxpp, &data, &encr, NULL);

	if (KCF_CONTEXT_DONE(rv))
		*ctxpp = NULL;

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(encr.cd_length <= encrlen);
		if (encr.cd_length != 0 && copyout(encr.cd_raw.iov_base,
		    encrbuf, encr.cd_length) != 0) {
			error = EFAULT;
			goto release_minor;
		}
		STRUCT_FSET(encrypt, ce_encrlen,
		    (ulong_t)encr.cd_length);
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (STRUCT_FGETP(encrypt, ce_encrbuf) == NULL)
			rv = CRYPTO_SUCCESS;
		STRUCT_FSET(encrypt, ce_encrlen,
		    (ulong_t)encr.cd_length);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (!do_inplace && encr.cd_raw.iov_base != NULL)
		kmem_free(encr.cd_raw.iov_base, encrlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(encrypt, ce_return_value, rv);
	if (copyout(STRUCT_BUF(encrypt), arg, STRUCT_SIZE(encrypt)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
encrypt_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher_update(dev, arg, mode, crypto_encrypt_update));
}

/* ARGSUSED */
static int
decrypt_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (cipher_update(dev, arg, mode, crypto_decrypt_update));
}

/*
 * ASSUMPTION: crypto_encrypt_update and crypto_decrypt_update
 * structures are identical except for field names.
 */
static int
cipher_update(dev_t dev, caddr_t arg, int mode,
    int (*update)(crypto_context_t, crypto_data_t *, crypto_data_t *,
    crypto_call_req_t *))
{
	STRUCT_DECL(crypto_encrypt_update, encrypt_update);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_ctx_t **ctxpp;
	crypto_data_t data, encr;
	size_t datalen, encrlen, need = 0;
	boolean_t do_inplace;
	char *encrbuf;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(encrypt_update, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "cipher_update: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(encrypt_update),
	    STRUCT_SIZE(encrypt_update)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_raw.iov_base = NULL;
	encr.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(encrypt_update, eu_datalen);
	encrlen = STRUCT_FGET(encrypt_update, eu_encrlen);

	/*
	 * Don't allocate output buffer unless both buffer pointer and
	 * buffer length are not NULL or 0 (length).
	 */
	encrbuf = STRUCT_FGETP(encrypt_update, eu_encrbuf);
	if (encrbuf == NULL || encrlen == 0) {
		encrlen = 0;
	}

	if (datalen > crypto_max_buffer_len ||
	    encrlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "cipher_update: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	session_id = STRUCT_FGET(encrypt_update, eu_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto out;
	}

	do_inplace = (STRUCT_FGET(encrypt_update, eu_flags) &
	    CRYPTO_INPLACE_OPERATION) != 0;
	need = do_inplace ? datalen : datalen + encrlen;

	if ((rv = CRYPTO_BUFFER_CHECK(sp, need, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		need = 0;
		goto out;
	}

	INIT_RAW_CRYPTO_DATA(data, datalen);
	data.cd_miscdata = NULL;

	if (datalen != 0 && copyin(STRUCT_FGETP(encrypt_update, eu_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto out;
	}

	if (do_inplace) {
		/* specify in-place buffers with output = input */
		encr = data;
	} else {
		INIT_RAW_CRYPTO_DATA(encr, encrlen);
	}

	ctxpp = (update == crypto_encrypt_update) ?
	    &sp->sd_encr_ctx : &sp->sd_decr_ctx;

	if (do_inplace)
		/* specify in-place buffers with output = NULL */
		rv = (update)(*ctxpp, &encr, NULL, NULL);
	else
		rv = (update)(*ctxpp, &data, &encr, NULL);

	if (rv == CRYPTO_SUCCESS || rv == CRYPTO_BUFFER_TOO_SMALL) {
		if (rv == CRYPTO_SUCCESS) {
			ASSERT(encr.cd_length <= encrlen);
			if (encr.cd_length != 0 && copyout(encr.cd_raw.iov_base,
			    encrbuf, encr.cd_length) != 0) {
				error = EFAULT;
				goto out;
			}
		} else {
			/*
			 * The providers return CRYPTO_BUFFER_TOO_SMALL even
			 * for case 1 of section 11.2 of the pkcs11 spec.
			 * We catch it here and provide the correct pkcs11
			 * return value.
			 */
			if (STRUCT_FGETP(encrypt_update, eu_encrbuf) == NULL)
				rv = CRYPTO_SUCCESS;
		}
		STRUCT_FSET(encrypt_update, eu_encrlen,
		    (ulong_t)encr.cd_length);
	} else {
		CRYPTO_CANCEL_CTX(ctxpp);
	}
out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (!do_inplace && (encr.cd_raw.iov_base != NULL))
		kmem_free(encr.cd_raw.iov_base, encrlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(encrypt_update, eu_return_value, rv);
	if (copyout(STRUCT_BUF(encrypt_update), arg,
	    STRUCT_SIZE(encrypt_update)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
encrypt_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_final(dev, arg, mode, crypto_encrypt_final));
}

/* ARGSUSED */
static int
decrypt_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_final(dev, arg, mode, crypto_decrypt_final));
}

/*
 * ASSUMPTION: crypto_encrypt_final, crypto_decrypt_final, crypto_sign_final,
 * and crypto_digest_final structures are identical except for field names.
 */
static int
common_final(dev_t dev, caddr_t arg, int mode,
    int (*final)(crypto_context_t, crypto_data_t *, crypto_call_req_t *))
{
	STRUCT_DECL(crypto_encrypt_final, encrypt_final);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_ctx_t **ctxpp;
	crypto_data_t encr;
	size_t encrlen, need = 0;
	char *encrbuf;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(encrypt_final, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "common_final: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(encrypt_final),
	    STRUCT_SIZE(encrypt_final)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	encr.cd_format = CRYPTO_DATA_RAW;
	encr.cd_raw.iov_base = NULL;

	encrlen = STRUCT_FGET(encrypt_final, ef_encrlen);

	/*
	 * Don't allocate output buffer unless both buffer pointer and
	 * buffer length are not NULL or 0 (length).
	 */
	encrbuf = STRUCT_FGETP(encrypt_final, ef_encrbuf);
	if (encrbuf == NULL || encrlen == 0) {
		encrlen = 0;
	}

	if (encrlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "common_final: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(encrypt_final, ef_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, encrlen, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	need = encrlen;
	encr.cd_raw.iov_base = kmem_alloc(encrlen, KM_SLEEP);
	encr.cd_raw.iov_len = encrlen;

	encr.cd_offset = 0;
	encr.cd_length = encrlen;

	ASSERT(final == crypto_encrypt_final ||
	    final == crypto_decrypt_final || final == crypto_sign_final ||
	    final == crypto_digest_final);

	if (final == crypto_encrypt_final) {
		ctxpp = &sp->sd_encr_ctx;
	} else if (final == crypto_decrypt_final) {
		ctxpp = &sp->sd_decr_ctx;
	} else if (final == crypto_sign_final) {
		ctxpp = &sp->sd_sign_ctx;
	} else {
		ctxpp = &sp->sd_digest_ctx;
	}

	rv = (final)(*ctxpp, &encr, NULL);
	if (KCF_CONTEXT_DONE(rv))
		*ctxpp = NULL;

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(encr.cd_length <= encrlen);
		if (encr.cd_length != 0 && copyout(encr.cd_raw.iov_base,
		    encrbuf, encr.cd_length) != 0) {
			error = EFAULT;
			goto release_minor;
		}
		STRUCT_FSET(encrypt_final, ef_encrlen,
		    (ulong_t)encr.cd_length);
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (STRUCT_FGETP(encrypt_final, ef_encrbuf) == NULL)
			rv = CRYPTO_SUCCESS;
		STRUCT_FSET(encrypt_final, ef_encrlen,
		    (ulong_t)encr.cd_length);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (encr.cd_raw.iov_base != NULL)
		kmem_free(encr.cd_raw.iov_base, encrlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(encrypt_final, ef_return_value, rv);
	if (copyout(STRUCT_BUF(encrypt_final), arg,
	    STRUCT_SIZE(encrypt_final)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
digest_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_digest_init, digest_init);
	kcf_provider_desc_t *real_provider = NULL;
	crypto_session_id_t session_id;
	crypto_mechanism_t mech;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_context_t cc;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;

	STRUCT_INIT(digest_init, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "digest_init: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(digest_init),
	    STRUCT_SIZE(digest_init)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	mech.cm_param = NULL;

	session_id = STRUCT_FGET(digest_init, di_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto out;
	}

	if (!copyin_mech(mode, sp, STRUCT_FADDR(digest_init, di_mech), &mech,
	    &rctl_bytes, &rctl_chk, &rv, &error)) {
		goto out;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, NULL,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider, &real_provider,
	    CRYPTO_FG_DIGEST)) != CRYPTO_SUCCESS) {
		goto out;
	}

	rv = crypto_digest_init_prov(real_provider,
	    sp->sd_provider_session->ps_session, &mech, &cc, NULL);

	/*
	 * Check if a context already exists. If so, it means it is being
	 * abandoned. So, cancel it to avoid leaking it.
	 */
	if (sp->sd_digest_ctx != NULL)
		CRYPTO_CANCEL_CTX(&sp->sd_digest_ctx);
	sp->sd_digest_ctx = (rv == CRYPTO_SUCCESS) ? cc : NULL;
out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);

	if (mech.cm_param != NULL)
		kmem_free(mech.cm_param, mech.cm_param_len);

	if (error != 0)
		return (error);

	STRUCT_FSET(digest_init, di_return_value, rv);
	if (copyout(STRUCT_BUF(digest_init), arg,
	    STRUCT_SIZE(digest_init)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
digest_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_digest_update, digest_update);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_data_t data;
	size_t datalen, need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(digest_update, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "digest_update: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(digest_update),
	    STRUCT_SIZE(digest_update)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_format = CRYPTO_DATA_RAW;
	data.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(digest_update, du_datalen);
	if (datalen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "digest_update: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(digest_update, du_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, datalen, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}

	need = datalen;
	data.cd_raw.iov_base = kmem_alloc(datalen, KM_SLEEP);
	data.cd_raw.iov_len = datalen;

	if (datalen != 0 && copyin(STRUCT_FGETP(digest_update, du_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	data.cd_offset = 0;
	data.cd_length = datalen;

	rv = crypto_digest_update(sp->sd_digest_ctx, &data, NULL);
	if (rv != CRYPTO_SUCCESS)
		CRYPTO_CANCEL_CTX(&sp->sd_digest_ctx);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (error != 0)
		return (error);

	STRUCT_FSET(digest_update, du_return_value, rv);
	if (copyout(STRUCT_BUF(digest_update), arg,
	    STRUCT_SIZE(digest_update)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
digest_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_digest_key, digest_key);
	crypto_session_id_t session_id;
	crypto_key_t key;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	size_t rctl_bytes = 0;
	boolean_t key_rctl_chk = B_FALSE;
	int error = 0;
	int rv;

	STRUCT_INIT(digest_key, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "digest_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(digest_key), STRUCT_SIZE(digest_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	bzero(&key, sizeof (crypto_key_t));

	session_id = STRUCT_FGET(digest_key, dk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto out;
	}

	if (!copyin_key(mode, sp, STRUCT_FADDR(digest_key, dk_key), &key,
	    &rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto out;
	}

	rv = crypto_digest_key_prov(sp->sd_digest_ctx, &key, NULL);
	if (rv != CRYPTO_SUCCESS)
		CRYPTO_CANCEL_CTX(&sp->sd_digest_ctx);
out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, key_rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	free_crypto_key(&key);

	if (error != 0)
		return (error);

	STRUCT_FSET(digest_key, dk_return_value, rv);
	if (copyout(STRUCT_BUF(digest_key), arg,
	    STRUCT_SIZE(digest_key)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
digest_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_final(dev, arg, mode, crypto_digest_final));
}

/* ARGSUSED */
static int
digest(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_digest(dev, arg, mode, crypto_digest_single));
}

/*
 * ASSUMPTION: crypto_digest, crypto_sign, crypto_sign_recover,
 * and crypto_verify_recover are identical except for field names.
 */
static int
common_digest(dev_t dev, caddr_t arg, int mode,
    int (*single)(crypto_context_t, crypto_data_t *, crypto_data_t *,
    crypto_call_req_t *))
{
	STRUCT_DECL(crypto_digest, crypto_digest);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_data_t data, digest;
	crypto_ctx_t **ctxpp;
	size_t datalen, digestlen, need = 0;
	char *digestbuf;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(crypto_digest, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "common_digest: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(crypto_digest),
	    STRUCT_SIZE(crypto_digest)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_raw.iov_base = NULL;
	digest.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(crypto_digest, cd_datalen);
	digestlen = STRUCT_FGET(crypto_digest, cd_digestlen);

	/*
	 * Don't allocate output buffer unless both buffer pointer and
	 * buffer length are not NULL or 0 (length).
	 */
	digestbuf = STRUCT_FGETP(crypto_digest, cd_digestbuf);
	if (digestbuf == NULL || digestlen == 0) {
		digestlen = 0;
	}

	if (datalen > crypto_max_buffer_len ||
	    digestlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "common_digest: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(crypto_digest, cd_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv))  {
		goto release_minor;
	}

	need = datalen + digestlen;
	if ((rv = CRYPTO_BUFFER_CHECK(sp, need, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		need = 0;
		goto release_minor;
	}

	INIT_RAW_CRYPTO_DATA(data, datalen);

	if (datalen != 0 && copyin(STRUCT_FGETP(crypto_digest, cd_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	INIT_RAW_CRYPTO_DATA(digest, digestlen);

	ASSERT(single == crypto_digest_single ||
	    single == crypto_sign_single ||
	    single == crypto_verify_recover_single ||
	    single == crypto_sign_recover_single);

	if (single == crypto_digest_single) {
		ctxpp = &sp->sd_digest_ctx;
	} else if (single == crypto_sign_single) {
		ctxpp = &sp->sd_sign_ctx;
	} else if (single == crypto_verify_recover_single) {
		ctxpp = &sp->sd_verify_recover_ctx;
	} else {
		ctxpp = &sp->sd_sign_recover_ctx;
	}
	rv = (single)(*ctxpp, &data, &digest, NULL);
	if (KCF_CONTEXT_DONE(rv))
		*ctxpp = NULL;

	if (rv == CRYPTO_SUCCESS) {
		ASSERT(digest.cd_length <= digestlen);
		if (digest.cd_length != 0 && copyout(digest.cd_raw.iov_base,
		    digestbuf, digest.cd_length) != 0) {
			error = EFAULT;
			goto release_minor;
		}
		STRUCT_FSET(crypto_digest, cd_digestlen,
		    (ulong_t)digest.cd_length);
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (STRUCT_FGETP(crypto_digest, cd_digestbuf) == NULL)
			rv = CRYPTO_SUCCESS;
		STRUCT_FSET(crypto_digest, cd_digestlen,
		    (ulong_t)digest.cd_length);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (digest.cd_raw.iov_base != NULL)
		kmem_free(digest.cd_raw.iov_base, digestlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(crypto_digest, cd_return_value, rv);
	if (copyout(STRUCT_BUF(crypto_digest), arg,
	    STRUCT_SIZE(crypto_digest)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * A helper function that does what the name suggests.
 * Returns 0 on success and non-zero otherwise.
 * On failure, out_pin is set to 0.
 */
int
get_pin_and_session_ptr(char *in_pin, char **out_pin, size_t pin_len,
    crypto_minor_t *cm, crypto_session_id_t sid, crypto_session_data_t **sp,
    int *rv, int *error)
{
	char *tmp_pin = NULL;
	int tmp_error = 0, tmp_rv = 0;

	if (pin_len > KCF_MAX_PIN_LEN) {
		tmp_rv = CRYPTO_PIN_LEN_RANGE;
		goto out;
	}
	tmp_pin = kmem_alloc(pin_len, KM_SLEEP);

	if (pin_len != 0 && copyin(in_pin, tmp_pin, pin_len) != 0) {
		tmp_error = EFAULT;
		goto out;
	}

	(void) get_session_ptr(sid, cm, sp, &tmp_error, &tmp_rv);
out:
	*out_pin = tmp_pin;
	*rv = tmp_rv;
	*error = tmp_error;
	return (tmp_rv | tmp_error);
}

/* ARGSUSED */
static int
set_pin(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_set_pin, set_pin);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_minor_t *cm;
	crypto_session_data_t *sp;
	char *old_pin = NULL;
	char *new_pin = NULL;
	size_t old_pin_len;
	size_t new_pin_len;
	int error = 0;
	int rv;

	STRUCT_INIT(set_pin, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "set_pin: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(set_pin),
	    STRUCT_SIZE(set_pin)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	old_pin_len = STRUCT_FGET(set_pin, sp_old_len);

	if (get_pin_and_session_ptr(STRUCT_FGETP(set_pin, sp_old_pin),
	    &old_pin, old_pin_len, cm, STRUCT_FGET(set_pin, sp_session),
	    &sp, &rv, &error) != 0)
		goto release_minor;

	new_pin_len = STRUCT_FGET(set_pin, sp_new_len);
	if (new_pin_len > KCF_MAX_PIN_LEN) {
		rv = CRYPTO_PIN_LEN_RANGE;
		goto out;
	}
	new_pin = kmem_alloc(new_pin_len, KM_SLEEP);

	if (new_pin_len != 0 && copyin(STRUCT_FGETP(set_pin, sp_new_pin),
	    new_pin, new_pin_len) != 0) {
		error = EFAULT;
		goto out;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(provider_ops), CRYPTO_PROVIDER_OFFSET(set_pin),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto out;
	}

	KCF_WRAP_PROVMGMT_OPS_PARAMS(&params, KCF_OP_MGMT_SETPIN,
	    sp->sd_provider_session->ps_session, old_pin, old_pin_len,
	    new_pin, new_pin_len, NULL, NULL, real_provider);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

out:
	CRYPTO_SESSION_RELE(sp);

release_minor:
	crypto_release_minor(cm);

	if (old_pin != NULL) {
		bzero(old_pin, old_pin_len);
		kmem_free(old_pin, old_pin_len);
	}

	if (new_pin != NULL) {
		bzero(new_pin, new_pin_len);
		kmem_free(new_pin, new_pin_len);
	}

	if (error != 0)
		return (error);

	STRUCT_FSET(set_pin, sp_return_value, rv);
	if (copyout(STRUCT_BUF(set_pin), arg, STRUCT_SIZE(set_pin)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
login(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_login, login);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_minor_t *cm;
	crypto_session_data_t *sp;
	size_t pin_len;
	char *pin;
	uint_t user_type;
	int error = 0;
	int rv;

	STRUCT_INIT(login, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "login: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(login), STRUCT_SIZE(login)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	user_type = STRUCT_FGET(login, co_user_type);

	pin_len = STRUCT_FGET(login, co_pin_len);

	if (get_pin_and_session_ptr(STRUCT_FGETP(login, co_pin),
	    &pin, pin_len, cm, STRUCT_FGET(login, co_session),
	    &sp, &rv, &error) != 0) {
		if (rv == CRYPTO_PIN_LEN_RANGE)
			rv = CRYPTO_PIN_INCORRECT;
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(session_ops),
	    CRYPTO_SESSION_OFFSET(session_login), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto out;
	}

	KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_LOGIN, NULL,
	    sp->sd_provider_session->ps_session, user_type, pin, pin_len,
	    real_provider);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

out:
	CRYPTO_SESSION_RELE(sp);

release_minor:
	crypto_release_minor(cm);

	if (pin != NULL) {
		bzero(pin, pin_len);
		kmem_free(pin, pin_len);
	}

	if (error != 0)
		return (error);

	STRUCT_FSET(login, co_return_value, rv);
	if (copyout(STRUCT_BUF(login), arg, STRUCT_SIZE(login)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
logout(dev_t dev, caddr_t arg, int mode, int *rval)
{
	crypto_logout_t logout;
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_minor_t *cm;
	crypto_session_data_t *sp;
	int error = 0;
	int rv;

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "logout: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, &logout, sizeof (logout)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	if (!get_session_ptr(logout.cl_session, cm, &sp, &error, &rv))  {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(session_ops),
	    CRYPTO_SESSION_OFFSET(session_logout), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto out;
	}

	KCF_WRAP_SESSION_OPS_PARAMS(&params, KCF_OP_SESSION_LOGOUT, NULL,
	    sp->sd_provider_session->ps_session, 0, NULL, 0, real_provider);
	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

out:
	CRYPTO_SESSION_RELE(sp);

release_minor:
	crypto_release_minor(cm);

	if (error != 0)
		return (error);

	logout.cl_return_value = rv;
	if (copyout(&logout, arg, sizeof (logout)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
sign_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_init(dev, arg, mode, crypto_sign_init_prov));
}

/* ARGSUSED */
static int
sign_recover_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_init(dev, arg, mode,
	    crypto_sign_recover_init_prov));
}

/* ARGSUSED */
static int
verify_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_init(dev, arg, mode, crypto_verify_init_prov));
}

/* ARGSUSED */
static int
verify_recover_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_init(dev, arg, mode,
	    crypto_verify_recover_init_prov));
}

/*
 * ASSUMPTION: crypto_sign_init, crypto_verify_init, crypto_sign_recover_init,
 * and crypto_verify_recover_init structures are identical
 * except for field names.
 */
static int
sign_verify_init(dev_t dev, caddr_t arg, int mode,
    int (*init)(crypto_provider_t, crypto_session_id_t,
    crypto_mechanism_t *, crypto_key_t *, crypto_ctx_template_t,
    crypto_context_t *, crypto_call_req_t *))
{
	STRUCT_DECL(crypto_sign_init, sign_init);
	kcf_provider_desc_t *real_provider = NULL;
	crypto_session_id_t session_id;
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_context_t cc;
	crypto_ctx_t **ctxpp;
	size_t mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	size_t key_rctl_bytes = 0;
	boolean_t key_rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	crypto_func_group_t fg;

	STRUCT_INIT(sign_init, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "sign_verify_init: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(sign_init), STRUCT_SIZE(sign_init)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	mech.cm_param = NULL;
	bzero(&key, sizeof (key));

	session_id = STRUCT_FGET(sign_init, si_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto out;
	}

	bcopy(STRUCT_FADDR(sign_init, si_mech), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	ASSERT(init == crypto_sign_init_prov ||
	    init == crypto_verify_init_prov ||
	    init == crypto_sign_recover_init_prov ||
	    init == crypto_verify_recover_init_prov);

	if (init == crypto_sign_init_prov) {
		fg =  CRYPTO_FG_SIGN;
		ctxpp = &sp->sd_sign_ctx;
	} else if (init == crypto_verify_init_prov) {
		fg =  CRYPTO_FG_VERIFY;
		ctxpp = &sp->sd_verify_ctx;
	} else if (init == crypto_sign_recover_init_prov) {
		fg =  CRYPTO_FG_SIGN_RECOVER;
		ctxpp = &sp->sd_sign_recover_ctx;
	} else {
		fg =  CRYPTO_FG_VERIFY_RECOVER;
		ctxpp = &sp->sd_verify_recover_ctx;
	}

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(sign_init, si_key), &key,
	    &key_rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto out;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &key,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider, &real_provider,
	    fg)) != CRYPTO_SUCCESS) {
		goto out;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(sign_init, si_mech), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(sign_init, si_mech),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto out;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto out;
	}

	rv = (init)(real_provider, sp->sd_provider_session->ps_session,
	    &mech, &key, NULL, &cc, NULL);

	/*
	 * Check if a context already exists. If so, it means it is being
	 * abandoned. So, cancel it to avoid leaking it.
	 */
	if (*ctxpp != NULL)
		CRYPTO_CANCEL_CTX(ctxpp);
	*ctxpp = (rv == CRYPTO_SUCCESS) ? cc : NULL;

out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}

	free_crypto_key(&key);

	if (error != 0)
		return (error);

	STRUCT_FSET(sign_init, si_return_value, rv);
	if (copyout(STRUCT_BUF(sign_init), arg, STRUCT_SIZE(sign_init)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
sign(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_digest(dev, arg, mode, crypto_sign_single));
}

/* ARGSUSED */
static int
sign_recover(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_digest(dev, arg, mode, crypto_sign_recover_single));
}

/* ARGSUSED */
static int
verify(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_verify, verify);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_data_t data, sign;
	size_t datalen, signlen, need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(verify, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "verify: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(verify), STRUCT_SIZE(verify)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_raw.iov_base = NULL;
	sign.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(verify, cv_datalen);
	signlen = STRUCT_FGET(verify, cv_signlen);
	if (datalen > crypto_max_buffer_len ||
	    signlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "verify: buffer greater than %ld bytes, "
		"pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(verify, cv_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	need = datalen + signlen;
	if ((rv = CRYPTO_BUFFER_CHECK(sp, need, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		need = 0;
		goto release_minor;
	}

	INIT_RAW_CRYPTO_DATA(data, datalen);
	INIT_RAW_CRYPTO_DATA(sign, signlen);

	if (datalen != 0 && copyin(STRUCT_FGETP(verify, cv_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	if (signlen != 0 && copyin(STRUCT_FGETP(verify, cv_signbuf),
	    sign.cd_raw.iov_base, signlen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	rv = crypto_verify_single(sp->sd_verify_ctx, &data, &sign, NULL);
	if (KCF_CONTEXT_DONE(rv))
		sp->sd_verify_ctx = NULL;

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (sign.cd_raw.iov_base != NULL)
		kmem_free(sign.cd_raw.iov_base, signlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(verify, cv_return_value, rv);
	if (copyout(STRUCT_BUF(verify), arg, STRUCT_SIZE(verify)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
verify_recover(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_digest(dev, arg, mode, crypto_verify_recover_single));
}

/* ARGSUSED */
static int
sign_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_update(dev, arg, mode, crypto_sign_update));
}

/* ARGSUSED */
static int
verify_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (sign_verify_update(dev, arg, mode, crypto_verify_update));
}

/*
 * ASSUMPTION: crypto_sign_update and crypto_verify_update structures
 * are identical except for field names.
 */
static int
sign_verify_update(dev_t dev, caddr_t arg, int mode,
    int (*update)(crypto_context_t, crypto_data_t *, crypto_call_req_t *))
{
	STRUCT_DECL(crypto_sign_update, sign_update);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_ctx_t **ctxpp;
	crypto_data_t data;
	size_t datalen, need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(sign_update, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "sign_verify_update: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(sign_update),
	    STRUCT_SIZE(sign_update)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	data.cd_raw.iov_base = NULL;

	datalen = STRUCT_FGET(sign_update, su_datalen);
	if (datalen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "sign_verify_update: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(sign_update, su_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, datalen, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	need = datalen;

	INIT_RAW_CRYPTO_DATA(data, datalen);

	if (datalen != 0 && copyin(STRUCT_FGETP(sign_update, su_databuf),
	    data.cd_raw.iov_base, datalen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	ctxpp = (update == crypto_sign_update) ?
	    &sp->sd_sign_ctx : &sp->sd_verify_ctx;

	rv = (update)(*ctxpp, &data, NULL);
	if (rv != CRYPTO_SUCCESS)
		CRYPTO_CANCEL_CTX(ctxpp);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (data.cd_raw.iov_base != NULL)
		kmem_free(data.cd_raw.iov_base, datalen);

	if (error != 0)
		return (error);

	STRUCT_FSET(sign_update, su_return_value, rv);
	if (copyout(STRUCT_BUF(sign_update), arg,
	    STRUCT_SIZE(sign_update)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
sign_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	return (common_final(dev, arg, mode, crypto_sign_final));
}

/*
 * Can't use the common final because it does a copyout of
 * the final part.
 */
/* ARGSUSED */
static int
verify_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_verify_final, verify_final);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_data_t sign;
	size_t signlen, need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(verify_final, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "verify_final: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(verify_final),
	    STRUCT_SIZE(verify_final)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	sign.cd_raw.iov_base = NULL;

	signlen = STRUCT_FGET(verify_final, vf_signlen);
	if (signlen > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "verify_final: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(verify_final, vf_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, signlen, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	need = signlen;

	INIT_RAW_CRYPTO_DATA(sign, signlen);

	if (signlen != 0 && copyin(STRUCT_FGETP(verify_final, vf_signbuf),
	    sign.cd_raw.iov_base, signlen) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	rv = crypto_verify_final(sp->sd_verify_ctx, &sign, NULL);
	if (KCF_CONTEXT_DONE(rv))
		sp->sd_verify_ctx = NULL;

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (sign.cd_raw.iov_base != NULL)
		kmem_free(sign.cd_raw.iov_base, signlen);

	if (error != 0)
		return (error);

	STRUCT_FSET(verify_final, vf_return_value, rv);
	if (copyout(STRUCT_BUF(verify_final), arg,
	    STRUCT_SIZE(verify_final)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
seed_random(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_seed_random, seed_random);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	uchar_t *seed_buffer = NULL;
	size_t seed_len;
	size_t need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(seed_random, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "seed_random: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(seed_random),
	    STRUCT_SIZE(seed_random)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	seed_len = STRUCT_FGET(seed_random, sr_seedlen);
	if (seed_len > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "seed_random: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(seed_random, sr_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, seed_len, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	need = seed_len;
	seed_buffer = kmem_alloc(seed_len, KM_SLEEP);

	if (seed_len != 0 && copyin(STRUCT_FGETP(seed_random, sr_seedbuf),
	    seed_buffer, seed_len) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(random_ops), CRYPTO_RANDOM_OFFSET(seed_random),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	KCF_WRAP_RANDOM_OPS_PARAMS(&params, KCF_OP_RANDOM_SEED,
	    sp->sd_provider_session->ps_session, seed_buffer, seed_len, 0,
	    CRYPTO_SEED_NOW);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);

	if (seed_buffer != NULL)
		kmem_free(seed_buffer, seed_len);

	if (error != 0)
		return (error);

	STRUCT_FSET(seed_random, sr_return_value, rv);
	if (copyout(STRUCT_BUF(seed_random), arg,
	    STRUCT_SIZE(seed_random)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
generate_random(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_generate_random, generate_random);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	uchar_t *buffer = NULL;
	size_t len;
	size_t need = 0;
	int error = 0;
	int rv;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(generate_random, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "generate_random: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(generate_random),
	    STRUCT_SIZE(generate_random)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	len = STRUCT_FGET(generate_random, gr_buflen);
	if (len > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "generate_random: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	session_id = STRUCT_FGET(generate_random, gr_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, len, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	need = len;
	buffer = kmem_alloc(len, KM_SLEEP);

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(random_ops),
	    CRYPTO_RANDOM_OFFSET(generate_random), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	KCF_WRAP_RANDOM_OPS_PARAMS(&params, KCF_OP_RANDOM_GENERATE,
	    sp->sd_provider_session->ps_session, buffer, len, 0, 0);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		if (len != 0 && copyout(buffer,
		    STRUCT_FGETP(generate_random, gr_buf), len) != 0) {
			error = EFAULT;
		}
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, need, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);

	if (buffer != NULL) {
		/* random numbers are often used to create keys */
		bzero(buffer, len);
		kmem_free(buffer, len);
	}

	if (error != 0)
		return (error);

	STRUCT_FSET(generate_random, gr_return_value, rv);
	if (copyout(STRUCT_BUF(generate_random), arg,
	    STRUCT_SIZE(generate_random)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * Copyout a kernel array of attributes to user space.
 * u_attrs is the corresponding user space array containing
 * user space pointers necessary for the copyout.
 */
/* ARGSUSED */
static int
copyout_attributes(int mode, caddr_t out, uint_t count,
    crypto_object_attribute_t *k_attrs, caddr_t u_attrs)
{
	STRUCT_DECL(crypto_object_attribute, oa);
	caddr_t p, valuep;
	size_t value_len;
	size_t len;
	int i;
	int error = 0;

	if (count == 0)
		return (0);

	STRUCT_INIT(oa, mode);

	len = count * STRUCT_SIZE(oa);

	ASSERT(u_attrs != NULL);
	p = u_attrs;
	for (i = 0; i < count; i++) {
		/* can this bcopy be eliminated? */
		bcopy(p, STRUCT_BUF(oa), STRUCT_SIZE(oa));
		value_len = k_attrs[i].oa_value_len;
		STRUCT_FSET(oa, oa_type, k_attrs[i].oa_type);
		STRUCT_FSET(oa, oa_value_len, (ssize_t)value_len);
		valuep = STRUCT_FGETP(oa, oa_value);
		if ((valuep != NULL) && (value_len != (size_t)-1)) {
			if (copyout(k_attrs[i].oa_value,
			    valuep, value_len) != 0) {
				error = EFAULT;
				goto out;
			}
		}
		bcopy(STRUCT_BUF(oa), p, STRUCT_SIZE(oa));
		p += STRUCT_SIZE(oa);
	}
	if (copyout(u_attrs, out, len)) {
		error = EFAULT;
	}
out:
	return (error);
}


/* ARGSUSED */
static int
object_create(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_create, object_create);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t object_handle;
	caddr_t oc_attributes;
	size_t k_attrs_size;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	uint_t count;

	STRUCT_INIT(object_create, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_create: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(object_create),
	    STRUCT_SIZE(object_create)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	count = STRUCT_FGET(object_create, oc_count);
	oc_attributes = STRUCT_FGETP(object_create, oc_attributes);

	session_id = STRUCT_FGET(object_create, oc_session);
	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if (!copyin_attributes(mode, sp, count, oc_attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &rctl_bytes,
	    &rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_create), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_CREATE,
	    sp->sd_provider_session->ps_session, 0, k_attrs, count,
	    &object_handle, 0, NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS)
		STRUCT_FSET(object_create, oc_handle, object_handle);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (error != 0)
		goto out;

	STRUCT_FSET(object_create, oc_return_value, rv);
	if (copyout(STRUCT_BUF(object_create), arg,
	    STRUCT_SIZE(object_create)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, object_handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			error = EFAULT;
		}
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);
	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);
	return (error);
}

/* ARGSUSED */
static int
object_copy(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_copy, object_copy);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle, new_handle;
	caddr_t oc_new_attributes;
	size_t k_attrs_size;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	uint_t count;

	STRUCT_INIT(object_copy, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_copy: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(object_copy),
	    STRUCT_SIZE(object_copy)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	count = STRUCT_FGET(object_copy, oc_count);
	oc_new_attributes = STRUCT_FGETP(object_copy, oc_new_attributes);

	session_id = STRUCT_FGET(object_copy, oc_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if (!copyin_attributes(mode, sp, count, oc_new_attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &rctl_bytes,
	    &rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_copy), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	handle = STRUCT_FGET(object_copy, oc_handle);
	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_COPY,
	    sp->sd_provider_session->ps_session, handle, k_attrs, count,
	    &new_handle, 0, NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS)
		STRUCT_FSET(object_copy, oc_new_handle, new_handle);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (error != 0)
		goto out;

	STRUCT_FSET(object_copy, oc_return_value, rv);
	if (copyout(STRUCT_BUF(object_copy), arg,
	    STRUCT_SIZE(object_copy)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, new_handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			error = EFAULT;
		}
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);
	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);
	return (error);
}

/* ARGSUSED */
static int
object_destroy(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_destroy, object_destroy);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp;
	crypto_object_id_t handle;
	int error = 0;
	int rv;

	STRUCT_INIT(object_destroy, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_destroy: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(object_destroy),
	    STRUCT_SIZE(object_destroy)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(object_destroy, od_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_destroy), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto out;
	}

	handle = STRUCT_FGET(object_destroy, od_handle);
	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_DESTROY,
	    sp->sd_provider_session->ps_session, handle, NULL, 0, NULL, 0,
	    NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

out:
	CRYPTO_SESSION_RELE(sp);

release_minor:
	crypto_release_minor(cm);

	if (error != 0)
		return (error);

	STRUCT_FSET(object_destroy, od_return_value, rv);

	if (copyout(STRUCT_BUF(object_destroy), arg,
	    STRUCT_SIZE(object_destroy)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_get_attribute_value(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_get_attribute_value, get_attribute_value);
#ifdef _LP64
	STRUCT_DECL(crypto_object_attribute, oa);
#else
	/* LINTED E_FUNC_SET_NOT_USED */
	STRUCT_DECL(crypto_object_attribute, oa);
#endif
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle;
	caddr_t og_attributes;
	caddr_t u_attrs = NULL;
	size_t k_attrs_size;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	uint_t count;

	STRUCT_INIT(get_attribute_value, mode);
	STRUCT_INIT(oa, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "object_get_attribute_value: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(get_attribute_value),
	    STRUCT_SIZE(get_attribute_value)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	count = STRUCT_FGET(get_attribute_value, og_count);
	og_attributes = STRUCT_FGETP(get_attribute_value, og_attributes);

	session_id = STRUCT_FGET(get_attribute_value, og_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if (!copyin_attributes(mode, sp, count, og_attributes, &k_attrs,
	    &k_attrs_size, &u_attrs, &rv, &error, &rctl_bytes,
	    &rctl_chk, B_FALSE)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_get_attribute_value),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto out;
	}

	handle = STRUCT_FGET(get_attribute_value, og_handle);
	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_GET_ATTRIBUTE_VALUE,
	    sp->sd_provider_session->ps_session, handle, k_attrs, count, NULL,
	    0, NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

out:
	if (rv == CRYPTO_SUCCESS || rv == CRYPTO_ATTRIBUTE_SENSITIVE ||
	    rv == CRYPTO_ATTRIBUTE_TYPE_INVALID ||
	    rv == CRYPTO_BUFFER_TOO_SMALL) {
		error = copyout_attributes(mode,
		    STRUCT_FGETP(get_attribute_value, og_attributes),
		    count, k_attrs, u_attrs);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (u_attrs != NULL)
		kmem_free(u_attrs, count * STRUCT_SIZE(oa));

	if (error != 0)
		return (error);

	STRUCT_FSET(get_attribute_value, og_return_value, rv);
	if (copyout(STRUCT_BUF(get_attribute_value), arg,
	    STRUCT_SIZE(get_attribute_value)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_get_size(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_get_size, object_get_size);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle;
	size_t size;
	int error = 0;
	int rv;

	STRUCT_INIT(object_get_size, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_get_size: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(object_get_size),
	    STRUCT_SIZE(object_get_size)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(object_get_size, gs_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_get_size),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	handle = STRUCT_FGET(object_get_size, gs_handle);
	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_GET_SIZE,
	    sp->sd_provider_session->ps_session, handle, NULL, 0, NULL, &size,
	    NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

	if (rv == CRYPTO_SUCCESS) {
		STRUCT_FSET(object_get_size, gs_size, (ulong_t)size);
	}

release_minor:
	crypto_release_minor(cm);
	CRYPTO_SESSION_RELE(sp);

	if (error != 0)
		return (error);

	STRUCT_FSET(object_get_size, gs_return_value, rv);
	if (copyout(STRUCT_BUF(object_get_size), arg,
	    STRUCT_SIZE(object_get_size)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_set_attribute_value(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_set_attribute_value, set_attribute_value);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t object_handle;
	caddr_t sa_attributes;
	size_t k_attrs_size;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	uint_t count;

	STRUCT_INIT(set_attribute_value, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "object_set_attribute_value: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(set_attribute_value),
	    STRUCT_SIZE(set_attribute_value)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	count = STRUCT_FGET(set_attribute_value, sa_count);
	sa_attributes = STRUCT_FGETP(set_attribute_value, sa_attributes);

	session_id = STRUCT_FGET(set_attribute_value, sa_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if (!copyin_attributes(mode, sp, count, sa_attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &rctl_bytes,
	    &rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_set_attribute_value),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	object_handle = STRUCT_FGET(set_attribute_value, sa_handle);
	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_SET_ATTRIBUTE_VALUE,
	    sp->sd_provider_session->ps_session, object_handle, k_attrs, count,
	    NULL, 0, NULL, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (error != 0)
		return (error);

	STRUCT_FSET(set_attribute_value, sa_return_value, rv);
	if (copyout(STRUCT_BUF(set_attribute_value), arg,
	    STRUCT_SIZE(set_attribute_value)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_find_init(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_find_init, find_init);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	caddr_t attributes;
	size_t k_attrs_size;
	size_t rctl_bytes = 0;
	boolean_t rctl_chk = B_FALSE;
	int error = 0;
	int rv;
	uint_t count;
	void *cookie;

	STRUCT_INIT(find_init, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_find_init: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(find_init), STRUCT_SIZE(find_init)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	count = STRUCT_FGET(find_init, fi_count);
	attributes = STRUCT_FGETP(find_init, fi_attributes);

	session_id = STRUCT_FGET(find_init, fi_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if (!copyin_attributes(mode, sp, count, attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &rctl_bytes,
	    &rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_find_init),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	/* check for an active find */
	if (sp->sd_find_init_cookie != NULL) {
		rv = CRYPTO_OPERATION_IS_ACTIVE;
		goto release_minor;
	}

	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND_INIT,
	    sp->sd_provider_session->ps_session, 0, k_attrs, count, NULL, 0,
	    &cookie, NULL, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		/*
		 * The cookie is allocated by a provider at the start of an
		 * object search.  It is freed when the search is terminated
		 * by a final operation, or when the session is closed.
		 * It contains state information about which object handles
		 * have been returned to the caller.
		 */
		sp->sd_find_init_cookie = cookie;
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL)
		KCF_PROV_REFRELE(real_provider);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (error != 0)
		return (error);

	STRUCT_FSET(find_init, fi_return_value, rv);
	if (copyout(STRUCT_BUF(find_init), arg, STRUCT_SIZE(find_init)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_find_update(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_find_update, find_update);
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t *buffer = NULL;
	crypto_session_id_t session_id;
	size_t len, rctl_bytes = 0;
	uint_t count, max_count;
	int rv, error = 0;
	boolean_t rctl_chk = B_FALSE;

	STRUCT_INIT(find_update, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_find_update: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(find_update),
	    STRUCT_SIZE(find_update)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	max_count = STRUCT_FGET(find_update, fu_max_count);
	if (max_count > CRYPTO_MAX_FIND_COUNT) {
		cmn_err(CE_NOTE, "object_find_update: count greater than %d, "
		    "pid = %d", CRYPTO_MAX_FIND_COUNT, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}
	len = max_count * sizeof (crypto_object_id_t);
	session_id = STRUCT_FGET(find_update, fu_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}
	if ((rv = CRYPTO_BUFFER_CHECK(sp, len, rctl_chk)) !=
	    CRYPTO_SUCCESS) {
		goto release_minor;
	}
	rctl_bytes = len;
	buffer = kmem_alloc(len, KM_SLEEP);

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_find), sp->sd_provider,
	    &real_provider)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND,
	    sp->sd_provider_session->ps_session, 0, NULL, 0, buffer, 0,
	    NULL, sp->sd_find_init_cookie, max_count, &count);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);

	if (rv == CRYPTO_SUCCESS) {
		if (count > max_count) {
			/* bad bad provider */
			rv = CRYPTO_FAILED;
			goto release_minor;
		}
		if (count != 0) {
			/* copyout handles */
			if (copyout(buffer,
			    STRUCT_FGETP(find_update, fu_handles),
			    count * sizeof (crypto_object_id_t)) != 0) {
				error = EFAULT;
			}
		}
		STRUCT_FSET(find_update, fu_count, count);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, rctl_bytes, rctl_chk);
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (buffer != NULL)
		kmem_free(buffer, len);

	if (error != 0)
		return (error);

	STRUCT_FSET(find_update, fu_return_value, rv);
	if (copyout(STRUCT_BUF(find_update), arg,
	    STRUCT_SIZE(find_update)) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Free provider-allocated storage used for find object searches.
 */
static int
crypto_free_find_ctx(crypto_session_data_t *sp)
{
	kcf_provider_desc_t *real_provider;
	kcf_req_params_t params;
	int rv;

	if ((rv = kcf_get_hardware_provider_nomech(
	    CRYPTO_OPS_OFFSET(object_ops),
	    CRYPTO_OBJECT_OFFSET(object_find_final),
	    sp->sd_provider, &real_provider)) != CRYPTO_SUCCESS) {
		return (rv);
	}

	KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_FIND_FINAL,
	    sp->sd_provider_session->ps_session, 0, NULL, 0, NULL, 0,
	    NULL, sp->sd_find_init_cookie, 0, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);
	KCF_PROV_REFRELE(real_provider);
	return (rv);
}

/* ARGSUSED */
static int
object_find_final(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_find_final, object_find_final);
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp;
	int error = 0;
	int rv;

	STRUCT_INIT(object_find_final, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_find_final: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(object_find_final),
	    STRUCT_SIZE(object_find_final)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(object_find_final, ff_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	if ((rv = crypto_free_find_ctx(sp)) == CRYPTO_SUCCESS) {
		sp->sd_find_init_cookie = NULL;
	}

	CRYPTO_SESSION_RELE(sp);

release_minor:
	crypto_release_minor(cm);

	if (error != 0)
		return (error);

	STRUCT_FSET(object_find_final, ff_return_value, rv);

	if (copyout(STRUCT_BUF(object_find_final), arg,
	    STRUCT_SIZE(object_find_final)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_generate_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_generate_key, generate_key);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t key_handle;
	caddr_t attributes;
	size_t k_attrs_size;
	size_t mech_rctl_bytes = 0, key_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	boolean_t key_rctl_chk = B_FALSE;
	uint_t count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;

	STRUCT_INIT(generate_key, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_generate_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(generate_key),
	    STRUCT_SIZE(generate_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(generate_key, gk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(generate_key, gk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	if ((rv = kcf_get_hardware_provider(mech.cm_type, NULL,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_GENERATE)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(generate_key, gk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp,
		    STRUCT_FADDR(generate_key, gk_mechanism),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	count = STRUCT_FGET(generate_key, gk_count);
	attributes = STRUCT_FGETP(generate_key, gk_attributes);
	if (!copyin_attributes(mode, sp, count, attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &key_rctl_bytes,
	    &key_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE,
	    sp->sd_provider_session->ps_session, &mech, k_attrs, count,
	    &key_handle, NULL, 0, NULL, NULL, NULL, 0);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS)
		STRUCT_FSET(generate_key, gk_handle, key_handle);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (error != 0)
		goto out;

	STRUCT_FSET(generate_key, gk_return_value, rv);
	if (copyout(STRUCT_BUF(generate_key), arg,
	    STRUCT_SIZE(generate_key)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, key_handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			error = EFAULT;
		}
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
nostore_generate_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_nostore_generate_key, generate_key);
#ifdef _LP64
	STRUCT_DECL(crypto_object_attribute, oa);
#else
	/* LINTED E_FUNC_SET_NOT_USED */
	STRUCT_DECL(crypto_object_attribute, oa);
#endif
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_in_attrs = NULL;
	crypto_object_attribute_t *k_out_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	caddr_t in_attributes;
	caddr_t out_attributes;
	size_t k_in_attrs_size;
	size_t k_out_attrs_size;
	size_t mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	size_t in_key_rctl_bytes = 0, out_key_rctl_bytes = 0;
	boolean_t in_key_rctl_chk = B_FALSE;
	boolean_t out_key_rctl_chk = B_FALSE;
	uint_t in_count;
	uint_t out_count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	caddr_t u_attrs = NULL;

	STRUCT_INIT(generate_key, mode);
	STRUCT_INIT(oa, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "nostore_generate_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(generate_key),
	    STRUCT_SIZE(generate_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(generate_key, ngk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(generate_key, ngk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	if ((rv = kcf_get_hardware_provider(mech.cm_type, NULL,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_GENERATE)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(generate_key, ngk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(generate_key,
		    ngk_mechanism), &mech, &mech_rctl_bytes,
		    &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	in_count = STRUCT_FGET(generate_key, ngk_in_count);
	in_attributes = STRUCT_FGETP(generate_key, ngk_in_attributes);
	if (!copyin_attributes(mode, sp, in_count, in_attributes, &k_in_attrs,
	    &k_in_attrs_size, NULL, &rv, &error, &in_key_rctl_bytes,
	    &in_key_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	out_count = STRUCT_FGET(generate_key, ngk_out_count);
	out_attributes = STRUCT_FGETP(generate_key, ngk_out_attributes);
	if (!copyin_attributes(mode, sp, out_count, out_attributes,
	    &k_out_attrs,
	    &k_out_attrs_size, &u_attrs, &rv, &error, &out_key_rctl_bytes,
	    &out_key_rctl_chk, B_FALSE)) {
		goto release_minor;
	}

	KCF_WRAP_NOSTORE_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE,
	    sp->sd_provider_session->ps_session, &mech, k_in_attrs, in_count,
	    NULL, 0, NULL, k_out_attrs, out_count, NULL, 0);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		error = copyout_attributes(mode, out_attributes,
		    out_count, k_out_attrs, u_attrs);
	}
release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, in_key_rctl_bytes, in_key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, out_key_rctl_bytes,
	    out_key_rctl_chk);

	if (k_in_attrs != NULL)
		kmem_free(k_in_attrs, k_in_attrs_size);
	if (k_out_attrs != NULL) {
		bzero(k_out_attrs, k_out_attrs_size);
		kmem_free(k_out_attrs, k_out_attrs_size);
	}

	if (u_attrs != NULL)
		kmem_free(u_attrs, out_count * STRUCT_SIZE(oa));

	if (error != 0)
		goto out;

	STRUCT_FSET(generate_key, ngk_return_value, rv);
	if (copyout(STRUCT_BUF(generate_key), arg,
	    STRUCT_SIZE(generate_key)) != 0) {
		error = EFAULT;
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
object_generate_key_pair(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_generate_key_pair, generate_key_pair);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_pub_attrs = NULL;
	crypto_object_attribute_t *k_pri_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t pub_handle;
	crypto_object_id_t pri_handle;
	caddr_t pri_attributes;
	caddr_t pub_attributes;
	size_t k_pub_attrs_size, k_pri_attrs_size;
	size_t mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	size_t pub_rctl_bytes = 0;
	boolean_t pub_rctl_chk = B_FALSE;
	size_t pri_rctl_bytes = 0;
	boolean_t pri_rctl_chk = B_FALSE;
	uint_t pub_count;
	uint_t pri_count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;

	STRUCT_INIT(generate_key_pair, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "object_generate_key_pair: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(generate_key_pair),
	    STRUCT_SIZE(generate_key_pair)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(generate_key_pair, kp_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(generate_key_pair, kp_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	if ((rv = kcf_get_hardware_provider(mech.cm_type, NULL,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_GENERATE_KEY_PAIR)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(generate_key_pair, kp_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(generate_key_pair,
		    kp_mechanism), &mech, &mech_rctl_bytes,
		    &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	pub_count = STRUCT_FGET(generate_key_pair, kp_public_count);
	pri_count = STRUCT_FGET(generate_key_pair, kp_private_count);

	pub_attributes = STRUCT_FGETP(generate_key_pair, kp_public_attributes);
	if (!copyin_attributes(mode, sp, pub_count, pub_attributes,
	    &k_pub_attrs, &k_pub_attrs_size, NULL, &rv, &error, &pub_rctl_bytes,
	    &pub_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	pri_attributes = STRUCT_FGETP(generate_key_pair, kp_private_attributes);
	if (!copyin_attributes(mode, sp, pri_count, pri_attributes,
	    &k_pri_attrs, &k_pri_attrs_size, NULL, &rv, &error,
	    &pri_rctl_bytes, &pri_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE_PAIR,
	    sp->sd_provider_session->ps_session, &mech, k_pub_attrs,
	    pub_count, &pub_handle, k_pri_attrs, pri_count, &pri_handle,
	    NULL, NULL, 0);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		STRUCT_FSET(generate_key_pair, kp_public_handle, pub_handle);
		STRUCT_FSET(generate_key_pair, kp_private_handle, pri_handle);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, pub_rctl_bytes, pub_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, pri_rctl_bytes, pri_rctl_chk);

	if (k_pub_attrs != NULL)
		kmem_free(k_pub_attrs, k_pub_attrs_size);

	if (k_pri_attrs != NULL)
		kmem_free(k_pri_attrs, k_pri_attrs_size);

	if (error != 0)
		goto out;

	STRUCT_FSET(generate_key_pair, kp_return_value, rv);
	if (copyout(STRUCT_BUF(generate_key_pair), arg,
	    STRUCT_SIZE(generate_key_pair)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, pub_handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, pri_handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			error = EFAULT;
		}
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
nostore_generate_key_pair(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_nostore_generate_key_pair, generate_key_pair);
#ifdef _LP64
	STRUCT_DECL(crypto_object_attribute, oa);
#else
	/* LINTED E_FUNC_SET_NOT_USED */
	STRUCT_DECL(crypto_object_attribute, oa);
#endif
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_object_attribute_t *k_in_pub_attrs = NULL;
	crypto_object_attribute_t *k_in_pri_attrs = NULL;
	crypto_object_attribute_t *k_out_pub_attrs = NULL;
	crypto_object_attribute_t *k_out_pri_attrs = NULL;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	caddr_t in_pri_attributes;
	caddr_t in_pub_attributes;
	caddr_t out_pri_attributes;
	caddr_t out_pub_attributes;
	size_t k_in_pub_attrs_size, k_in_pri_attrs_size;
	size_t k_out_pub_attrs_size, k_out_pri_attrs_size;
	size_t mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	size_t in_pub_rctl_bytes = 0;
	boolean_t in_pub_rctl_chk = B_FALSE;
	size_t in_pri_rctl_bytes = 0;
	boolean_t in_pri_rctl_chk = B_FALSE;
	size_t out_pub_rctl_bytes = 0;
	boolean_t out_pub_rctl_chk = B_FALSE;
	size_t out_pri_rctl_bytes = 0;
	boolean_t out_pri_rctl_chk = B_FALSE;
	uint_t in_pub_count;
	uint_t in_pri_count;
	uint_t out_pub_count;
	uint_t out_pri_count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	caddr_t u_pub_attrs = NULL;
	caddr_t u_pri_attrs = NULL;

	STRUCT_INIT(generate_key_pair, mode);
	STRUCT_INIT(oa, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN,
		    "nostore_generate_key_pair: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(generate_key_pair),
	    STRUCT_SIZE(generate_key_pair)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	session_id = STRUCT_FGET(generate_key_pair, nkp_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(generate_key_pair, nkp_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	if ((rv = kcf_get_hardware_provider(mech.cm_type, NULL,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_GENERATE_KEY_PAIR)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(generate_key_pair, nkp_mechanism), &mech, mode,
	    &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(generate_key_pair,
		    nkp_mechanism), &mech, &mech_rctl_bytes,
		    &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	in_pub_count = STRUCT_FGET(generate_key_pair, nkp_in_public_count);
	in_pri_count = STRUCT_FGET(generate_key_pair, nkp_in_private_count);

	in_pub_attributes = STRUCT_FGETP(generate_key_pair,
	    nkp_in_public_attributes);
	if (!copyin_attributes(mode, sp, in_pub_count, in_pub_attributes,
	    &k_in_pub_attrs, &k_in_pub_attrs_size, NULL, &rv, &error,
	    &in_pub_rctl_bytes, &in_pub_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	in_pri_attributes = STRUCT_FGETP(generate_key_pair,
	    nkp_in_private_attributes);
	if (!copyin_attributes(mode, sp, in_pri_count, in_pri_attributes,
	    &k_in_pri_attrs, &k_in_pri_attrs_size, NULL, &rv, &error,
	    &in_pri_rctl_bytes, &in_pri_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	out_pub_count = STRUCT_FGET(generate_key_pair, nkp_out_public_count);
	out_pri_count = STRUCT_FGET(generate_key_pair, nkp_out_private_count);

	out_pub_attributes = STRUCT_FGETP(generate_key_pair,
	    nkp_out_public_attributes);
	if (!copyin_attributes(mode, sp, out_pub_count, out_pub_attributes,
	    &k_out_pub_attrs, &k_out_pub_attrs_size, &u_pub_attrs, &rv, &error,
	    &out_pub_rctl_bytes, &out_pub_rctl_chk, B_FALSE)) {
		goto release_minor;
	}

	out_pri_attributes = STRUCT_FGETP(generate_key_pair,
	    nkp_out_private_attributes);
	if (!copyin_attributes(mode, sp, out_pri_count, out_pri_attributes,
	    &k_out_pri_attrs, &k_out_pri_attrs_size, &u_pri_attrs, &rv, &error,
	    &out_pri_rctl_bytes, &out_pri_rctl_chk, B_FALSE)) {
		goto release_minor;
	}

	KCF_WRAP_NOSTORE_KEY_OPS_PARAMS(&params, KCF_OP_KEY_GENERATE_PAIR,
	    sp->sd_provider_session->ps_session, &mech, k_in_pub_attrs,
	    in_pub_count, k_in_pri_attrs, in_pri_count, NULL, k_out_pub_attrs,
	    out_pub_count, k_out_pri_attrs, out_pri_count);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		error = copyout_attributes(mode, out_pub_attributes,
		    out_pub_count, k_out_pub_attrs, u_pub_attrs);
		if (error != CRYPTO_SUCCESS)
			goto release_minor;
		error = copyout_attributes(mode, out_pri_attributes,
		    out_pri_count, k_out_pri_attrs, u_pri_attrs);
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, in_pub_rctl_bytes, in_pub_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, in_pri_rctl_bytes, in_pri_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, out_pub_rctl_bytes,
	    out_pub_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, out_pri_rctl_bytes,
	    out_pri_rctl_chk);

	if (k_in_pub_attrs != NULL)
		kmem_free(k_in_pub_attrs, k_in_pub_attrs_size);

	if (k_in_pri_attrs != NULL)
		kmem_free(k_in_pri_attrs, k_in_pri_attrs_size);

	if (k_out_pub_attrs != NULL)
		kmem_free(k_out_pub_attrs, k_out_pub_attrs_size);

	if (k_out_pri_attrs != NULL) {
		bzero(k_out_pri_attrs, k_out_pri_attrs_size);
		kmem_free(k_out_pri_attrs, k_out_pri_attrs_size);
	}

	if (u_pub_attrs != NULL)
		kmem_free(u_pub_attrs, out_pub_count * STRUCT_SIZE(oa));

	if (u_pri_attrs != NULL)
		kmem_free(u_pri_attrs, out_pri_count * STRUCT_SIZE(oa));

	if (error != 0)
		goto out;

	STRUCT_FSET(generate_key_pair, nkp_return_value, rv);
	if (copyout(STRUCT_BUF(generate_key_pair), arg,
	    STRUCT_SIZE(generate_key_pair)) != 0) {
		error = EFAULT;
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
object_wrap_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_wrap_key, wrap_key);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_key_t key;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle;
	size_t mech_rctl_bytes = 0, key_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	boolean_t key_rctl_chk = B_FALSE;
	size_t wrapped_key_rctl_bytes = 0;
	boolean_t wrapped_key_rctl_chk = B_FALSE;
	size_t wrapped_key_len, new_wrapped_key_len;
	uchar_t *wrapped_key = NULL;
	char *wrapped_key_buffer;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;

	STRUCT_INIT(wrap_key, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_wrap_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(wrap_key), STRUCT_SIZE(wrap_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	bzero(&key, sizeof (crypto_key_t));

	session_id = STRUCT_FGET(wrap_key, wk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto out;
	}

	bcopy(STRUCT_FADDR(wrap_key, wk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(wrap_key, wk_wrapping_key), &key,
	    &key_rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto out;
	}

	wrapped_key_len = STRUCT_FGET(wrap_key, wk_wrapped_key_len);

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &key,
	    CRYPTO_MECH_INVALID, NULL,  sp->sd_provider,
	    &real_provider, CRYPTO_FG_WRAP)) != CRYPTO_SUCCESS) {
		goto out;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(wrap_key, wk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp, STRUCT_FADDR(wrap_key, wk_mechanism),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto out;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto out;
	}

	/*
	 * Don't allocate output buffer unless both buffer pointer and
	 * buffer length are not NULL or 0 (length).
	 */
	wrapped_key_buffer = STRUCT_FGETP(wrap_key, wk_wrapped_key);
	if (wrapped_key_buffer == NULL || wrapped_key_len == 0) {
		wrapped_key_len = 0;
	}

	if (wrapped_key_len > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "object_wrap_key: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto out;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, wrapped_key_len,
	    wrapped_key_rctl_chk)) != CRYPTO_SUCCESS) {
		goto out;
	}

	/* new_wrapped_key_len can be modified by the provider */
	wrapped_key_rctl_bytes = new_wrapped_key_len = wrapped_key_len;
	wrapped_key = kmem_alloc(wrapped_key_len, KM_SLEEP);

	handle = STRUCT_FGET(wrap_key, wk_object_handle);
	KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_WRAP,
	    sp->sd_provider_session->ps_session, &mech, NULL, 0, &handle,
	    NULL, 0, NULL, &key, wrapped_key, &new_wrapped_key_len);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		if (wrapped_key_len != 0 && copyout(wrapped_key,
		    wrapped_key_buffer, new_wrapped_key_len) != 0) {
			error = EFAULT;
		}
		STRUCT_FSET(wrap_key, wk_wrapped_key_len,
		    (ulong_t)new_wrapped_key_len);
	}

	if (rv == CRYPTO_BUFFER_TOO_SMALL) {
		/*
		 * The providers return CRYPTO_BUFFER_TOO_SMALL even for case 1
		 * of section 11.2 of the pkcs11 spec. We catch it here and
		 * provide the correct pkcs11 return value.
		 */
		if (STRUCT_FGETP(wrap_key, wk_wrapped_key) == NULL)
			rv = CRYPTO_SUCCESS;
		STRUCT_FSET(wrap_key, wk_wrapped_key_len,
		    (ulong_t)new_wrapped_key_len);
	}

out:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, wrapped_key_rctl_bytes,
	    wrapped_key_rctl_chk);
	CRYPTO_SESSION_RELE(sp);

	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}

	if (wrapped_key != NULL)
		kmem_free(wrapped_key, wrapped_key_len);

	free_crypto_key(&key);

	if (error != 0)
		return (error);

	STRUCT_FSET(wrap_key, wk_return_value, rv);
	if (copyout(STRUCT_BUF(wrap_key), arg, STRUCT_SIZE(wrap_key)) != 0) {
		return (EFAULT);
	}
	return (0);
}

/* ARGSUSED */
static int
object_unwrap_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_object_unwrap_key, unwrap_key);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_mechanism_t mech;
	crypto_key_t unwrapping_key;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle;
	crypto_object_attribute_t *k_attrs = NULL;
	size_t k_attrs_size;
	size_t mech_rctl_bytes = 0, unwrapping_key_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	boolean_t unwrapping_key_rctl_chk = B_FALSE;
	size_t wrapped_key_rctl_bytes = 0, k_attrs_rctl_bytes = 0;
	boolean_t wrapped_key_rctl_chk = B_FALSE;
	boolean_t k_attrs_rctl_chk = B_FALSE;
	size_t wrapped_key_len;
	uchar_t *wrapped_key = NULL;
	int error = 0;
	int rv;
	uint_t count;
	caddr_t uk_attributes;
	boolean_t allocated_by_crypto_module = B_FALSE;

	STRUCT_INIT(unwrap_key, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_unwrap_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(unwrap_key), STRUCT_SIZE(unwrap_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	bzero(&unwrapping_key, sizeof (unwrapping_key));

	session_id = STRUCT_FGET(unwrap_key, uk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(unwrap_key, uk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(unwrap_key, uk_unwrapping_key),
	    &unwrapping_key, &unwrapping_key_rctl_bytes,
	    &unwrapping_key_rctl_chk, &rv, &error)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &unwrapping_key,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_UNWRAP)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(unwrap_key, uk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp,
		    STRUCT_FADDR(unwrap_key, uk_mechanism),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	count = STRUCT_FGET(unwrap_key, uk_count);
	uk_attributes = STRUCT_FGETP(unwrap_key, uk_attributes);
	if (!copyin_attributes(mode, sp, count, uk_attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error, &k_attrs_rctl_bytes,
	    &k_attrs_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	wrapped_key_len = STRUCT_FGET(unwrap_key, uk_wrapped_key_len);
	if (wrapped_key_len > crypto_max_buffer_len) {
		cmn_err(CE_NOTE, "object_unwrap_key: buffer greater than %ld "
		    "bytes, pid = %d", crypto_max_buffer_len, curproc->p_pid);
		rv = CRYPTO_ARGUMENTS_BAD;
		goto release_minor;
	}

	if ((rv = CRYPTO_BUFFER_CHECK(sp, wrapped_key_len,
	    wrapped_key_rctl_chk)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}
	wrapped_key_rctl_bytes = wrapped_key_len;
	wrapped_key = kmem_alloc(wrapped_key_len, KM_SLEEP);

	if (wrapped_key_len != 0 && copyin(STRUCT_FGETP(unwrap_key,
	    uk_wrapped_key), wrapped_key, wrapped_key_len) != 0) {
		error = EFAULT;
		goto release_minor;
	}

	/* wrapped_key_len is not modified by the unwrap operation */
	KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_UNWRAP,
	    sp->sd_provider_session->ps_session, &mech, k_attrs, count, &handle,
	    NULL, 0, NULL, &unwrapping_key, wrapped_key, &wrapped_key_len);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS)
		STRUCT_FSET(unwrap_key, uk_object_handle, handle);

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, unwrapping_key_rctl_bytes,
	    unwrapping_key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, wrapped_key_rctl_bytes,
	    wrapped_key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, k_attrs_rctl_bytes,
	    k_attrs_rctl_chk);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	if (wrapped_key != NULL)
		kmem_free(wrapped_key, wrapped_key_len);

	free_crypto_key(&unwrapping_key);

	if (error != 0)
		goto out;

	STRUCT_FSET(unwrap_key, uk_return_value, rv);
	if (copyout(STRUCT_BUF(unwrap_key), arg,
	    STRUCT_SIZE(unwrap_key)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			KCF_WRAP_OBJECT_OPS_PARAMS(&params,
			    KCF_OP_OBJECT_DESTROY,
			    sp->sd_provider_session->ps_session, handle,
			    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

			(void) kcf_submit_request(real_provider, NULL,
			    NULL, &params, B_FALSE);

			error = EFAULT;
		}
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}

	return (error);
}

/* ARGSUSED */
static int
object_derive_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_derive_key, derive_key);
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_attrs = NULL;
	crypto_mechanism_t mech;
	crypto_key_t base_key;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	crypto_object_id_t handle;
	size_t k_attrs_size;
	size_t key_rctl_bytes = 0, mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	boolean_t key_rctl_chk = B_FALSE;
	size_t attributes_rctl_bytes = 0;
	boolean_t attributes_rctl_chk = B_FALSE;
	caddr_t attributes;
	uint_t count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	boolean_t please_destroy_object = B_FALSE;

	STRUCT_INIT(derive_key, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "object_derive_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(derive_key), STRUCT_SIZE(derive_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	bzero(&base_key, sizeof (base_key));

	session_id = STRUCT_FGET(derive_key, dk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(derive_key, dk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(derive_key, dk_base_key),
	    &base_key, &key_rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &base_key,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_DERIVE)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(derive_key, dk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp,
		    STRUCT_FADDR(derive_key, dk_mechanism),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	count = STRUCT_FGET(derive_key, dk_count);

	attributes = STRUCT_FGETP(derive_key, dk_attributes);
	if (!copyin_attributes(mode, sp, count, attributes, &k_attrs,
	    &k_attrs_size, NULL, &rv, &error,
	    &attributes_rctl_bytes, &attributes_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	KCF_WRAP_KEY_OPS_PARAMS(&params, KCF_OP_KEY_DERIVE,
	    sp->sd_provider_session->ps_session, &mech, k_attrs, count,
	    &handle, NULL, 0, NULL, &base_key, NULL, NULL);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		STRUCT_FSET(derive_key, dk_object_handle, handle);

		rv = crypto_provider_copyout_mech_param(real_provider,
		    &mech, STRUCT_FADDR(derive_key, dk_mechanism),
		    mode, &error);

		if (rv == CRYPTO_NOT_SUPPORTED) {
			rv = CRYPTO_SUCCESS;
			goto release_minor;
		}

		if (rv != CRYPTO_SUCCESS)
			please_destroy_object = B_TRUE;
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, attributes_rctl_bytes,
	    attributes_rctl_chk);

	if (k_attrs != NULL)
		kmem_free(k_attrs, k_attrs_size);

	free_crypto_key(&base_key);

	if (error != 0)
		goto out;

	STRUCT_FSET(derive_key, dk_return_value, rv);
	if (copyout(STRUCT_BUF(derive_key), arg,
	    STRUCT_SIZE(derive_key)) != 0) {
		if (rv == CRYPTO_SUCCESS) {
			please_destroy_object = B_TRUE;
			error = EFAULT;
		}
	}
out:
	if (please_destroy_object) {
		KCF_WRAP_OBJECT_OPS_PARAMS(&params, KCF_OP_OBJECT_DESTROY,
		    sp->sd_provider_session->ps_session, handle,
		    NULL, 0, NULL, 0, NULL, NULL, 0, NULL);

		(void) kcf_submit_request(real_provider, NULL,
		    NULL, &params, B_FALSE);
	}

	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
nostore_derive_key(dev_t dev, caddr_t arg, int mode, int *rval)
{
	STRUCT_DECL(crypto_nostore_derive_key, derive_key);
#ifdef _LP64
	STRUCT_DECL(crypto_object_attribute, oa);
#else
	/* LINTED E_FUNC_SET_NOT_USED */
	STRUCT_DECL(crypto_object_attribute, oa);
#endif
	kcf_provider_desc_t *real_provider = NULL;
	kcf_req_params_t params;
	crypto_object_attribute_t *k_in_attrs = NULL;
	crypto_object_attribute_t *k_out_attrs = NULL;
	crypto_mechanism_t mech;
	crypto_key_t base_key;
	crypto_session_id_t session_id;
	crypto_minor_t *cm;
	crypto_session_data_t *sp = NULL;
	size_t k_in_attrs_size, k_out_attrs_size;
	size_t key_rctl_bytes = 0, mech_rctl_bytes = 0;
	boolean_t mech_rctl_chk = B_FALSE;
	boolean_t key_rctl_chk = B_FALSE;
	size_t in_attributes_rctl_bytes = 0;
	size_t out_attributes_rctl_bytes = 0;
	boolean_t in_attributes_rctl_chk = B_FALSE;
	boolean_t out_attributes_rctl_chk = B_FALSE;
	caddr_t in_attributes, out_attributes;
	uint_t in_count, out_count;
	int error = 0;
	int rv;
	boolean_t allocated_by_crypto_module = B_FALSE;
	caddr_t u_attrs = NULL;

	STRUCT_INIT(derive_key, mode);
	STRUCT_INIT(oa, mode);

	if ((cm = crypto_hold_minor(getminor(dev))) == NULL) {
		cmn_err(CE_WARN, "nostore_derive_key: failed holding minor");
		return (ENXIO);
	}

	if (copyin(arg, STRUCT_BUF(derive_key), STRUCT_SIZE(derive_key)) != 0) {
		crypto_release_minor(cm);
		return (EFAULT);
	}

	bzero(&base_key, sizeof (base_key));

	session_id = STRUCT_FGET(derive_key, ndk_session);

	if (!get_session_ptr(session_id, cm, &sp, &error, &rv)) {
		goto release_minor;
	}

	bcopy(STRUCT_FADDR(derive_key, ndk_mechanism), &mech.cm_type,
	    sizeof (crypto_mech_type_t));

	/* We need the key length for provider selection so copy it in now. */
	if (!copyin_key(mode, sp, STRUCT_FADDR(derive_key, ndk_base_key),
	    &base_key, &key_rctl_bytes, &key_rctl_chk, &rv, &error)) {
		goto release_minor;
	}

	if ((rv = kcf_get_hardware_provider(mech.cm_type, &base_key,
	    CRYPTO_MECH_INVALID, NULL, sp->sd_provider,
	    &real_provider, CRYPTO_FG_DERIVE)) != CRYPTO_SUCCESS) {
		goto release_minor;
	}

	rv = crypto_provider_copyin_mech_param(real_provider,
	    STRUCT_FADDR(derive_key, ndk_mechanism), &mech, mode, &error);

	if (rv == CRYPTO_NOT_SUPPORTED) {
		allocated_by_crypto_module = B_TRUE;
		if (!copyin_mech(mode, sp,
		    STRUCT_FADDR(derive_key, ndk_mechanism),
		    &mech, &mech_rctl_bytes, &mech_rctl_chk, &rv, &error)) {
			goto release_minor;
		}
	} else {
		if (rv != CRYPTO_SUCCESS)
			goto release_minor;
	}

	in_count = STRUCT_FGET(derive_key, ndk_in_count);
	out_count = STRUCT_FGET(derive_key, ndk_out_count);

	in_attributes = STRUCT_FGETP(derive_key, ndk_in_attributes);
	if (!copyin_attributes(mode, sp, in_count, in_attributes, &k_in_attrs,
	    &k_in_attrs_size, NULL, &rv, &error, &in_attributes_rctl_bytes,
	    &in_attributes_rctl_chk, B_TRUE)) {
		goto release_minor;
	}

	out_attributes = STRUCT_FGETP(derive_key, ndk_out_attributes);
	if (!copyin_attributes(mode, sp, out_count, out_attributes,
	    &k_out_attrs, &k_out_attrs_size, &u_attrs, &rv, &error,
	    &out_attributes_rctl_bytes,
	    &out_attributes_rctl_chk, B_FALSE)) {
		goto release_minor;
	}

	KCF_WRAP_NOSTORE_KEY_OPS_PARAMS(&params, KCF_OP_KEY_DERIVE,
	    sp->sd_provider_session->ps_session, &mech, k_in_attrs, in_count,
	    NULL, 0, &base_key, k_out_attrs, out_count, NULL, 0);

	rv = kcf_submit_request(real_provider, NULL, NULL, &params, B_FALSE);

	if (rv == CRYPTO_SUCCESS) {
		rv = crypto_provider_copyout_mech_param(real_provider,
		    &mech, STRUCT_FADDR(derive_key, ndk_mechanism),
		    mode, &error);

		if (rv == CRYPTO_NOT_SUPPORTED) {
			rv = CRYPTO_SUCCESS;
		}
		/* copyout the derived secret */
		if (copyout_attributes(mode, out_attributes, out_count,
		    k_out_attrs, u_attrs) != 0)
			error = EFAULT;
	}

release_minor:
	CRYPTO_DECREMENT_RCTL_SESSION(sp, mech_rctl_bytes, mech_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, key_rctl_bytes, key_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, in_attributes_rctl_bytes,
	    in_attributes_rctl_chk);
	CRYPTO_DECREMENT_RCTL_SESSION(sp, out_attributes_rctl_bytes,
	    out_attributes_rctl_chk);

	if (k_in_attrs != NULL)
		kmem_free(k_in_attrs, k_in_attrs_size);
	if (k_out_attrs != NULL) {
		bzero(k_out_attrs, k_out_attrs_size);
		kmem_free(k_out_attrs, k_out_attrs_size);
	}

	if (u_attrs != NULL)
		kmem_free(u_attrs, out_count * STRUCT_SIZE(oa));

	free_crypto_key(&base_key);

	if (error != 0)
		goto out;

	STRUCT_FSET(derive_key, ndk_return_value, rv);
	if (copyout(STRUCT_BUF(derive_key), arg,
	    STRUCT_SIZE(derive_key)) != 0) {
		error = EFAULT;
	}
out:
	CRYPTO_SESSION_RELE(sp);
	crypto_release_minor(cm);

	if (real_provider != NULL) {
		crypto_free_mech(real_provider,
		    allocated_by_crypto_module, &mech);
		KCF_PROV_REFRELE(real_provider);
	}
	return (error);
}

/* ARGSUSED */
static int
crypto_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *c,
    int *rval)
{
#define	ARG	((caddr_t)arg)

	switch (cmd) {
	case CRYPTO_GET_FUNCTION_LIST:
		return (get_function_list(dev, ARG, mode, rval));

	case CRYPTO_GET_MECHANISM_NUMBER:
		return (get_mechanism_number(dev, ARG, mode, rval));

	case CRYPTO_GET_MECHANISM_LIST:
		return (get_mechanism_list(dev, ARG, mode, rval));

	case CRYPTO_GET_ALL_MECHANISM_INFO:
		return (get_all_mechanism_info(dev, ARG, mode, rval));

	case CRYPTO_GET_PROVIDER_LIST:
		return (get_provider_list(dev, ARG, mode, rval));

	case CRYPTO_GET_PROVIDER_INFO:
		return (get_provider_info(dev, ARG, mode, rval));

	case CRYPTO_GET_PROVIDER_MECHANISMS:
		return (get_provider_mechanisms(dev, ARG, mode, rval));

	case CRYPTO_GET_PROVIDER_MECHANISM_INFO:
		return (get_provider_mechanism_info(dev, ARG, mode, rval));

	case CRYPTO_OPEN_SESSION:
		return (open_session(dev, ARG, mode, rval));

	case CRYPTO_CLOSE_SESSION:
		return (close_session(dev, ARG, mode, rval));

	case CRYPTO_ENCRYPT_INIT:
		return (encrypt_init(dev, ARG, mode, rval));

	case CRYPTO_DECRYPT_INIT:
		return (decrypt_init(dev, ARG, mode, rval));

	case CRYPTO_ENCRYPT:
		return (encrypt(dev, ARG, mode, rval));

	case CRYPTO_DECRYPT:
		return (decrypt(dev, ARG, mode, rval));

	case CRYPTO_ENCRYPT_UPDATE:
		return (encrypt_update(dev, ARG, mode, rval));

	case CRYPTO_DECRYPT_UPDATE:
		return (decrypt_update(dev, ARG, mode, rval));

	case CRYPTO_ENCRYPT_FINAL:
		return (encrypt_final(dev, ARG, mode, rval));

	case CRYPTO_DECRYPT_FINAL:
		return (decrypt_final(dev, ARG, mode, rval));

	case CRYPTO_DIGEST_INIT:
		return (digest_init(dev, ARG, mode, rval));

	case CRYPTO_DIGEST:
		return (digest(dev, ARG, mode, rval));

	case CRYPTO_DIGEST_UPDATE:
		return (digest_update(dev, ARG, mode, rval));

	case CRYPTO_DIGEST_KEY:
		return (digest_key(dev, ARG, mode, rval));

	case CRYPTO_DIGEST_FINAL:
		return (digest_final(dev, ARG, mode, rval));

	case CRYPTO_SIGN_INIT:
		return (sign_init(dev, ARG, mode, rval));

	case CRYPTO_SIGN:
		return (sign(dev, ARG, mode, rval));

	case CRYPTO_SIGN_UPDATE:
		return (sign_update(dev, ARG, mode, rval));

	case CRYPTO_SIGN_FINAL:
		return (sign_final(dev, ARG, mode, rval));

	case CRYPTO_SIGN_RECOVER_INIT:
		return (sign_recover_init(dev, ARG, mode, rval));

	case CRYPTO_SIGN_RECOVER:
		return (sign_recover(dev, ARG, mode, rval));

	case CRYPTO_VERIFY_INIT:
		return (verify_init(dev, ARG, mode, rval));

	case CRYPTO_VERIFY:
		return (verify(dev, ARG, mode, rval));

	case CRYPTO_VERIFY_UPDATE:
		return (verify_update(dev, ARG, mode, rval));

	case CRYPTO_VERIFY_FINAL:
		return (verify_final(dev, ARG, mode, rval));

	case CRYPTO_VERIFY_RECOVER_INIT:
		return (verify_recover_init(dev, ARG, mode, rval));

	case CRYPTO_VERIFY_RECOVER:
		return (verify_recover(dev, ARG, mode, rval));

	case CRYPTO_SET_PIN:
		return (set_pin(dev, ARG, mode, rval));

	case CRYPTO_LOGIN:
		return (login(dev, ARG, mode, rval));

	case CRYPTO_LOGOUT:
		return (logout(dev, ARG, mode, rval));

	case CRYPTO_SEED_RANDOM:
		return (seed_random(dev, ARG, mode, rval));

	case CRYPTO_GENERATE_RANDOM:
		return (generate_random(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_CREATE:
		return (object_create(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_COPY:
		return (object_copy(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_DESTROY:
		return (object_destroy(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_GET_ATTRIBUTE_VALUE:
		return (object_get_attribute_value(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_GET_SIZE:
		return (object_get_size(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_SET_ATTRIBUTE_VALUE:
		return (object_set_attribute_value(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_FIND_INIT:
		return (object_find_init(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_FIND_UPDATE:
		return (object_find_update(dev, ARG, mode, rval));

	case CRYPTO_OBJECT_FIND_FINAL:
		return (object_find_final(dev, ARG, mode, rval));

	case CRYPTO_GENERATE_KEY:
		return (object_generate_key(dev, ARG, mode, rval));

	case CRYPTO_GENERATE_KEY_PAIR:
		return (object_generate_key_pair(dev, ARG, mode, rval));

	case CRYPTO_WRAP_KEY:
		return (object_wrap_key(dev, ARG, mode, rval));

	case CRYPTO_UNWRAP_KEY:
		return (object_unwrap_key(dev, ARG, mode, rval));

	case CRYPTO_DERIVE_KEY:
		return (object_derive_key(dev, ARG, mode, rval));

	case CRYPTO_NOSTORE_GENERATE_KEY:
		return (nostore_generate_key(dev, ARG, mode, rval));

	case CRYPTO_NOSTORE_GENERATE_KEY_PAIR:
		return (nostore_generate_key_pair(dev, ARG, mode, rval));

	case CRYPTO_NOSTORE_DERIVE_KEY:
		return (nostore_derive_key(dev, ARG, mode, rval));
	}
	return (EINVAL);
}

/*
 * Check for the project.max-crypto-memory resource control.
 */
static int
crypto_buffer_check(size_t need)
{
	kproject_t *kpj;

	if (need == 0)
		return (CRYPTO_SUCCESS);

	mutex_enter(&curproc->p_lock);
	kpj = curproc->p_task->tk_proj;
	mutex_enter(&(kpj->kpj_data.kpd_crypto_lock));

	if (kpj->kpj_data.kpd_crypto_mem + need >
	    kpj->kpj_data.kpd_crypto_mem_ctl) {
		if (rctl_test(rc_project_crypto_mem,
		    kpj->kpj_rctls, curproc, need, 0) & RCT_DENY) {
			mutex_exit(&(kpj->kpj_data.kpd_crypto_lock));
			mutex_exit(&curproc->p_lock);
			return (CRYPTO_HOST_MEMORY);
		}
	}

	kpj->kpj_data.kpd_crypto_mem += need;
	mutex_exit(&(kpj->kpj_data.kpd_crypto_lock));

	curproc->p_crypto_mem += need;
	mutex_exit(&curproc->p_lock);

	return (CRYPTO_SUCCESS);
}
