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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * LDoms virtual disk client (vdc) device driver
 *
 * This driver runs on a guest logical domain and communicates with the virtual
 * disk server (vds) driver running on the service domain which is exporting
 * virtualized "disks" to the guest logical domain.
 *
 * The driver can be divided into four sections:
 *
 * 1) generic device driver housekeeping
 *	_init, _fini, attach, detach, ops structures, etc.
 *
 * 2) communication channel setup
 *	Setup the communications link over the LDC channel that vdc uses to
 *	talk to the vDisk server. Initialise the descriptor ring which
 *	allows the LDC clients to transfer data via memory mappings.
 *
 * 3) Support exported to upper layers (filesystems, etc)
 *	The upper layers call into vdc via strategy(9E) and DKIO(7I)
 *	ioctl calls. vdc will copy the data to be written to the descriptor
 *	ring or maps the buffer to store the data read by the vDisk
 *	server into the descriptor ring. It then sends a message to the
 *	vDisk server requesting it to complete the operation.
 *
 * 4) Handling responses from vDisk server.
 *	The vDisk server will ACK some or all of the messages vdc sends to it
 *	(this is configured during the handshake). Upon receipt of an ACK
 *	vdc will check the descriptor ring and signal to the upper layer
 *	code waiting on the IO.
 */

#include <sys/atomic.h>
#include <sys/conf.h>
#include <sys/disp.h>
#include <sys/ddi.h>
#include <sys/dkio.h>
#include <sys/efi_partition.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/kstat.h>
#include <sys/mach_descrip.h>
#include <sys/modctl.h>
#include <sys/mdeg.h>
#include <sys/note.h>
#include <sys/open.h>
#include <sys/random.h>
#include <sys/sdt.h>
#include <sys/stat.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/promif.h>
#include <sys/var.h>
#include <sys/vtoc.h>
#include <sys/archsystm.h>
#include <sys/sysmacros.h>

#include <sys/cdio.h>
#include <sys/dktp/fdisk.h>
#include <sys/dktp/dadkio.h>
#include <sys/fs/dv_node.h>
#include <sys/mhd.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/impl/services.h>
#include <sys/scsi/targets/sddef.h>

#include <sys/ldoms.h>
#include <sys/ldc.h>
#include <sys/vio_common.h>
#include <sys/vio_mailbox.h>
#include <sys/vio_util.h>
#include <sys/vdsk_common.h>
#include <sys/vdsk_mailbox.h>
#include <sys/vdc.h>

#define	VD_OLDVTOC_LIMIT	0x7fffffff

/*
 * function prototypes
 */

/* standard driver functions */
static int	vdc_open(dev_t *dev, int flag, int otyp, cred_t *cred);
static int	vdc_close(dev_t dev, int flag, int otyp, cred_t *cred);
static int	vdc_strategy(struct buf *buf);
static int	vdc_print(dev_t dev, char *str);
static int	vdc_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk);
static int	vdc_read(dev_t dev, struct uio *uio, cred_t *cred);
static int	vdc_write(dev_t dev, struct uio *uio, cred_t *cred);
static int	vdc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode,
			cred_t *credp, int *rvalp);
static int	vdc_aread(dev_t dev, struct aio_req *aio, cred_t *cred);
static int	vdc_awrite(dev_t dev, struct aio_req *aio, cred_t *cred);

static int	vdc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,
			void *arg, void **resultp);
static int	vdc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd);
static int	vdc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd);
static int	vdc_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op,
		    int mod_flags, char *name, caddr_t valuep, int *lengthp);

/* setup */
static void	vdc_min(struct buf *bufp);
static int	vdc_send(vdc_t *vdc, caddr_t pkt, size_t *msglen);
static int	vdc_do_ldc_init(vdc_t *vdc, vdc_server_t *srvr);
static int	vdc_start_ldc_connection(vdc_t *vdc);
static int	vdc_create_device_nodes(vdc_t *vdc);
static int	vdc_create_device_nodes_efi(vdc_t *vdc);
static int	vdc_create_device_nodes_vtoc(vdc_t *vdc);
static void	vdc_create_io_kstats(vdc_t *vdc);
static void	vdc_create_err_kstats(vdc_t *vdc);
static void	vdc_set_err_kstats(vdc_t *vdc);
static int	vdc_get_md_node(dev_info_t *dip, md_t **mdpp,
		    mde_cookie_t *vd_nodep);
static int	vdc_init_ports(vdc_t *vdc, md_t *mdp, mde_cookie_t vd_nodep);
static void	vdc_fini_ports(vdc_t *vdc);
static void	vdc_switch_server(vdc_t *vdcp);
static int	vdc_do_ldc_up(vdc_t *vdc);
static void	vdc_terminate_ldc(vdc_t *vdc, vdc_server_t *srvr);
static int	vdc_init_descriptor_ring(vdc_t *vdc);
static void	vdc_destroy_descriptor_ring(vdc_t *vdc);
static int	vdc_setup_devid(vdc_t *vdc);
static void	vdc_store_label_efi(vdc_t *, efi_gpt_t *, efi_gpe_t *);
static void	vdc_store_label_vtoc(vdc_t *, struct dk_geom *,
		    struct extvtoc *);
static void	vdc_store_label_unk(vdc_t *vdc);
static boolean_t vdc_is_opened(vdc_t *vdc);
static void	vdc_update_size(vdc_t *vdc, size_t, size_t, size_t);
static int	vdc_update_vio_bsize(vdc_t *vdc, uint32_t);

/* handshake with vds */
static int		vdc_init_ver_negotiation(vdc_t *vdc, vio_ver_t ver);
static int		vdc_ver_negotiation(vdc_t *vdcp);
static int		vdc_init_attr_negotiation(vdc_t *vdc);
static int		vdc_attr_negotiation(vdc_t *vdcp);
static int		vdc_init_dring_negotiate(vdc_t *vdc);
static int		vdc_dring_negotiation(vdc_t *vdcp);
static int		vdc_send_rdx(vdc_t *vdcp);
static int		vdc_rdx_exchange(vdc_t *vdcp);
static boolean_t	vdc_is_supported_version(vio_ver_msg_t *ver_msg);

/* processing incoming messages from vDisk server */
static void	vdc_process_msg_thread(vdc_t *vdc);
static int	vdc_recv(vdc_t *vdc, vio_msg_t *msgp, size_t *nbytesp);

static uint_t	vdc_handle_cb(uint64_t event, caddr_t arg);
static int	vdc_process_data_msg(vdc_t *vdc, vio_msg_t *msg);
static int	vdc_handle_ver_msg(vdc_t *vdc, vio_ver_msg_t *ver_msg);
static int	vdc_handle_attr_msg(vdc_t *vdc, vd_attr_msg_t *attr_msg);
static int	vdc_handle_dring_reg_msg(vdc_t *vdc, vio_dring_reg_msg_t *msg);
static int	vdc_send_request(vdc_t *vdcp, int operation,
		    caddr_t addr, size_t nbytes, int slice, diskaddr_t offset,
		    buf_t *bufp, vio_desc_direction_t dir, int flags);
static int	vdc_map_to_shared_dring(vdc_t *vdcp, int idx);
static int	vdc_populate_descriptor(vdc_t *vdcp, int operation,
		    caddr_t addr, size_t nbytes, int slice, diskaddr_t offset,
		    buf_t *bufp, vio_desc_direction_t dir, int flags);
static int	vdc_do_sync_op(vdc_t *vdcp, int operation, caddr_t addr,
		    size_t nbytes, int slice, diskaddr_t offset,
		    vio_desc_direction_t dir, boolean_t);
static int	vdc_do_op(vdc_t *vdc, int op, caddr_t addr, size_t nbytes,
		    int slice, diskaddr_t offset, struct buf *bufp,
		    vio_desc_direction_t dir, int flags);

static int	vdc_wait_for_response(vdc_t *vdcp, vio_msg_t *msgp);
static int	vdc_drain_response(vdc_t *vdcp, struct buf *buf);
static int	vdc_depopulate_descriptor(vdc_t *vdc, uint_t idx);
static int	vdc_populate_mem_hdl(vdc_t *vdcp, vdc_local_desc_t *ldep);
static int	vdc_verify_seq_num(vdc_t *vdc, vio_dring_msg_t *dring_msg);

/* dkio */
static int	vd_process_ioctl(dev_t dev, int cmd, caddr_t arg, int mode,
		    int *rvalp);
static int	vd_process_efi_ioctl(void *vdisk, int cmd, uintptr_t arg);
static void	vdc_create_fake_geometry(vdc_t *vdc);
static int	vdc_validate_geometry(vdc_t *vdc);
static void	vdc_validate(vdc_t *vdc);
static void	vdc_validate_task(void *arg);
static int	vdc_null_copy_func(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_get_wce_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_set_wce_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_get_vtoc_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_set_vtoc_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_get_extvtoc_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_set_extvtoc_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_get_geom_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_set_geom_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_get_efi_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);
static int	vdc_set_efi_convert(vdc_t *vdc, void *from, void *to,
		    int mode, int dir);

static void	vdc_ownership_update(vdc_t *vdc, int ownership_flags);
static int	vdc_access_set(vdc_t *vdc, uint64_t flags);
static vdc_io_t	*vdc_eio_queue(vdc_t *vdc, int index);
static void	vdc_eio_unqueue(vdc_t *vdc, clock_t deadline,
		    boolean_t complete_io);
static int	vdc_eio_check(vdc_t *vdc, int flags);
static void	vdc_eio_thread(void *arg);

/*
 * Module variables
 */

/*
 * Number of handshake retries with the current server before switching to
 * a different server. These retries are done so that we stick with the same
 * server if vdc receives a LDC reset event during the initiation of the
 * handshake. This can happen if vdc reset the LDC channel and then immediately
 * retry a connexion before it has received the LDC reset event.
 *
 * If there is only one server then we "switch" to the same server. We also
 * switch if the handshake has reached the attribute negotiate step whatever
 * the number of handshake retries might be.
 */
static uint_t vdc_hshake_retries = VDC_HSHAKE_RETRIES;

/*
 * If the handshake done during the attach fails then the two following
 * variables will also be used to control the number of retries for the
 * next handshakes. In that case, when a handshake is done after the
 * attach (i.e. the vdc lifecycle is VDC_ONLINE_PENDING) then the handshake
 * will be retried until we have done an attribution negotiation with each
 * server, with a specified minimum total number of negotations (the value
 * of the vdc_hattr_min_initial or vdc_hattr_min variable).
 *
 * This prevents new I/Os on a newly used vdisk to block forever if the
 * attribute negotiations can not be done, and to limit the amount of time
 * before I/Os will fail. Basically, attribute negotiations will fail when
 * the service is up but the backend does not exist. In that case, vds will
 * typically retry to access the backend during 50 seconds. So I/Os will fail
 * after the following amount of time:
 *
 *	50 seconds x max(number of servers, vdc->hattr_min)
 *
 * After that the handshake done during the attach has failed then the next
 * handshake will use vdc_attr_min_initial. This handshake will correspond to
 * the very first I/O to the device. If this handshake also fails then
 * vdc_hattr_min will be used for subsequent handshakes. We typically allow
 * more retries for the first handshake (VDC_HATTR_MIN_INITIAL = 3) to give more
 * time for the backend to become available (50s x VDC_HATTR_MIN_INITIAL = 150s)
 * in case this is a critical vdisk (e.g. vdisk access during boot). Then we use
 * a smaller value (VDC_HATTR_MIN = 1) to avoid waiting too long for each I/O.
 */
static uint_t vdc_hattr_min_initial = VDC_HATTR_MIN_INITIAL;
static uint_t vdc_hattr_min = VDC_HATTR_MIN;

/*
 * Tunable variables to control how long vdc waits before timing out on
 * various operations
 */
static int	vdc_timeout = 0; /* units: seconds */
static int	vdc_ldcup_timeout = 1; /* units: seconds */

static uint64_t vdc_hz_min_ldc_delay;
static uint64_t vdc_min_timeout_ldc = 1 * MILLISEC;
static uint64_t vdc_hz_max_ldc_delay;
static uint64_t vdc_max_timeout_ldc = 100 * MILLISEC;

static uint64_t vdc_ldc_read_init_delay = 1 * MILLISEC;
static uint64_t vdc_ldc_read_max_delay = 100 * MILLISEC;

/* values for dumping - need to run in a tighter loop */
static uint64_t	vdc_usec_timeout_dump = 100 * MILLISEC;	/* 0.1s units: ns */
static int	vdc_dump_retries = 100;

static uint16_t	vdc_scsi_timeout = 60;	/* 60s units: seconds  */

static uint64_t vdc_ownership_delay = 6 * MICROSEC; /* 6s units: usec */

/* Count of the number of vdc instances attached */
static volatile uint32_t	vdc_instance_count = 0;

/* Tunable to log all SCSI errors */
static boolean_t vdc_scsi_log_error = B_FALSE;

/* Soft state pointer */
static void	*vdc_state;

/*
 * Controlling the verbosity of the error/debug messages
 *
 * vdc_msglevel - controls level of messages
 * vdc_matchinst - 64-bit variable where each bit corresponds
 *                 to the vdc instance the vdc_msglevel applies.
 */
int		vdc_msglevel = 0x0;
uint64_t	vdc_matchinst = 0ull;

/*
 * Supported vDisk protocol version pairs.
 *
 * The first array entry is the latest and preferred version.
 */
static const vio_ver_t	vdc_version[] = {{1, 1}};

static struct cb_ops vdc_cb_ops = {
	vdc_open,	/* cb_open */
	vdc_close,	/* cb_close */
	vdc_strategy,	/* cb_strategy */
	vdc_print,	/* cb_print */
	vdc_dump,	/* cb_dump */
	vdc_read,	/* cb_read */
	vdc_write,	/* cb_write */
	vdc_ioctl,	/* cb_ioctl */
	nodev,		/* cb_devmap */
	nodev,		/* cb_mmap */
	nodev,		/* cb_segmap */
	nochpoll,	/* cb_chpoll */
	vdc_prop_op,	/* cb_prop_op */
	NULL,		/* cb_str */
	D_MP | D_64BIT,	/* cb_flag */
	CB_REV,		/* cb_rev */
	vdc_aread,	/* cb_aread */
	vdc_awrite	/* cb_awrite */
};

static struct dev_ops vdc_ops = {
	DEVO_REV,	/* devo_rev */
	0,		/* devo_refcnt */
	vdc_getinfo,	/* devo_getinfo */
	nulldev,	/* devo_identify */
	nulldev,	/* devo_probe */
	vdc_attach,	/* devo_attach */
	vdc_detach,	/* devo_detach */
	nodev,		/* devo_reset */
	&vdc_cb_ops,	/* devo_cb_ops */
	NULL,		/* devo_bus_ops */
	nulldev,	/* devo_power */
	ddi_quiesce_not_needed,	/* devo_quiesce */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"virtual disk client",
	&vdc_ops,
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

/* -------------------------------------------------------------------------- */

/*
 * Device Driver housekeeping and setup
 */

int
_init(void)
{
	int	status;

	if ((status = ddi_soft_state_init(&vdc_state, sizeof (vdc_t), 1)) != 0)
		return (status);
	if ((status = mod_install(&modlinkage)) != 0)
		ddi_soft_state_fini(&vdc_state);
	return (status);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int	status;

	if ((status = mod_remove(&modlinkage)) != 0)
		return (status);
	ddi_soft_state_fini(&vdc_state);
	return (0);
}

static int
vdc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd,  void *arg, void **resultp)
{
	_NOTE(ARGUNUSED(dip))

	int	instance = VDCUNIT((dev_t)arg);
	vdc_t	*vdc = NULL;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
			*resultp = NULL;
			return (DDI_FAILURE);
		}
		*resultp = vdc->dip;
		return (DDI_SUCCESS);
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)instance;
		return (DDI_SUCCESS);
	default:
		*resultp = NULL;
		return (DDI_FAILURE);
	}
}

static int
vdc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	kt_did_t eio_tid, ownership_tid;
	int	instance;
	int	rv;
	vdc_server_t *srvr;
	vdc_t	*vdc = NULL;

	switch (cmd) {
	case DDI_DETACH:
		/* the real work happens below */
		break;
	case DDI_SUSPEND:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	ASSERT(cmd == DDI_DETACH);
	instance = ddi_get_instance(dip);
	DMSGX(1, "[%d] Entered\n", instance);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		return (DDI_FAILURE);
	}

	if (vdc_is_opened(vdc)) {
		DMSG(vdc, 0, "[%d] Cannot detach: device is open", instance);
		return (DDI_FAILURE);
	}

	if (vdc->dkio_flush_pending) {
		DMSG(vdc, 0,
		    "[%d] Cannot detach: %d outstanding DKIO flushes\n",
		    instance, vdc->dkio_flush_pending);
		return (DDI_FAILURE);
	}

	if (vdc->validate_pending) {
		DMSG(vdc, 0,
		    "[%d] Cannot detach: %d outstanding validate request\n",
		    instance, vdc->validate_pending);
		return (DDI_FAILURE);
	}

	DMSG(vdc, 0, "[%d] proceeding...\n", instance);

	/* If we took ownership, release ownership */
	mutex_enter(&vdc->ownership_lock);
	if (vdc->ownership & VDC_OWNERSHIP_GRANTED) {
		rv = vdc_access_set(vdc, VD_ACCESS_SET_CLEAR);
		if (rv == 0) {
			vdc_ownership_update(vdc, VDC_OWNERSHIP_NONE);
		}
	}
	mutex_exit(&vdc->ownership_lock);

	/* mark instance as detaching */
	mutex_enter(&vdc->lock);
	vdc->lifecycle	= VDC_LC_DETACHING;
	mutex_exit(&vdc->lock);

	/*
	 * Try and disable callbacks to prevent another handshake. We have to
	 * disable callbacks for all servers.
	 */
	for (srvr = vdc->server_list; srvr != NULL; srvr = srvr->next) {
		rv = ldc_set_cb_mode(srvr->ldc_handle, LDC_CB_DISABLE);
		DMSG(vdc, 0, "callback disabled (ldc=%lu, rv=%d)\n",
		    srvr->ldc_id, rv);
	}

	if (vdc->initialized & VDC_THREAD) {
		mutex_enter(&vdc->read_lock);
		if ((vdc->read_state == VDC_READ_WAITING) ||
		    (vdc->read_state == VDC_READ_RESET)) {
			vdc->read_state = VDC_READ_RESET;
			cv_signal(&vdc->read_cv);
		}

		mutex_exit(&vdc->read_lock);

		/* wake up any thread waiting for connection to come online */
		mutex_enter(&vdc->lock);
		if (vdc->state == VDC_STATE_INIT_WAITING) {
			DMSG(vdc, 0,
			    "[%d] write reset - move to resetting state...\n",
			    instance);
			vdc->state = VDC_STATE_RESETTING;
			cv_signal(&vdc->initwait_cv);
		} else if (vdc->state == VDC_STATE_FAILED) {
			vdc->io_pending = B_TRUE;
			cv_signal(&vdc->io_pending_cv);
		}
		mutex_exit(&vdc->lock);

		/* now wait until state transitions to VDC_STATE_DETACH */
		thread_join(vdc->msg_proc_thr->t_did);
		ASSERT(vdc->state == VDC_STATE_DETACH);
		DMSG(vdc, 0, "[%d] Reset thread exit and join ..\n",
		    vdc->instance);
	}

	mutex_enter(&vdc->lock);

	if (vdc->initialized & VDC_DRING)
		vdc_destroy_descriptor_ring(vdc);

	vdc_fini_ports(vdc);

	if (vdc->eio_thread) {
		eio_tid = vdc->eio_thread->t_did;
		vdc->failfast_interval = 0;
		ASSERT(vdc->num_servers == 0);
		cv_signal(&vdc->eio_cv);
	} else {
		eio_tid = 0;
	}

	if (vdc->ownership & VDC_OWNERSHIP_WANTED) {
		ownership_tid = vdc->ownership_thread->t_did;
		vdc->ownership = VDC_OWNERSHIP_NONE;
		cv_signal(&vdc->ownership_cv);
	} else {
		ownership_tid = 0;
	}

	mutex_exit(&vdc->lock);

	if (eio_tid != 0)
		thread_join(eio_tid);

	if (ownership_tid != 0)
		thread_join(ownership_tid);

	if (vdc->initialized & VDC_MINOR)
		ddi_remove_minor_node(dip, NULL);

	if (vdc->io_stats) {
		kstat_delete(vdc->io_stats);
		vdc->io_stats = NULL;
	}

	if (vdc->err_stats) {
		kstat_delete(vdc->err_stats);
		vdc->err_stats = NULL;
	}

	if (vdc->initialized & VDC_LOCKS) {
		mutex_destroy(&vdc->lock);
		mutex_destroy(&vdc->read_lock);
		mutex_destroy(&vdc->ownership_lock);
		cv_destroy(&vdc->initwait_cv);
		cv_destroy(&vdc->dring_free_cv);
		cv_destroy(&vdc->membind_cv);
		cv_destroy(&vdc->sync_blocked_cv);
		cv_destroy(&vdc->read_cv);
		cv_destroy(&vdc->running_cv);
		cv_destroy(&vdc->io_pending_cv);
		cv_destroy(&vdc->ownership_cv);
		cv_destroy(&vdc->eio_cv);
	}

	if (vdc->minfo)
		kmem_free(vdc->minfo, sizeof (struct dk_minfo));

	if (vdc->cinfo)
		kmem_free(vdc->cinfo, sizeof (struct dk_cinfo));

	if (vdc->vtoc)
		kmem_free(vdc->vtoc, sizeof (struct extvtoc));

	if (vdc->geom)
		kmem_free(vdc->geom, sizeof (struct dk_geom));

	if (vdc->devid) {
		ddi_devid_unregister(dip);
		ddi_devid_free(vdc->devid);
	}

	if (vdc->initialized & VDC_SOFT_STATE)
		ddi_soft_state_free(vdc_state, instance);

	DMSG(vdc, 0, "[%d] End %p\n", instance, (void *)vdc);

	return (DDI_SUCCESS);
}


static int
vdc_do_attach(dev_info_t *dip)
{
	int		instance;
	vdc_t		*vdc = NULL;
	int		status;
	md_t		*mdp;
	mde_cookie_t	vd_node;

	ASSERT(dip != NULL);

	instance = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(vdc_state, instance) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "[%d] Couldn't alloc state structure",
		    instance);
		return (DDI_FAILURE);
	}

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		return (DDI_FAILURE);
	}

	/*
	 * We assign the value to initialized in this case to zero out the
	 * variable and then set bits in it to indicate what has been done
	 */
	vdc->initialized = VDC_SOFT_STATE;

	vdc_hz_min_ldc_delay = drv_usectohz(vdc_min_timeout_ldc);
	vdc_hz_max_ldc_delay = drv_usectohz(vdc_max_timeout_ldc);

	vdc->dip	= dip;
	vdc->instance	= instance;
	vdc->vdisk_type	= VD_DISK_TYPE_UNK;
	vdc->vdisk_label = VD_DISK_LABEL_UNK;
	vdc->state	= VDC_STATE_INIT;
	vdc->lifecycle	= VDC_LC_ATTACHING;
	vdc->session_id = 0;
	vdc->vdisk_bsize = DEV_BSIZE;
	vdc->vio_bmask = 0;
	vdc->vio_bshift = 0;
	vdc->max_xfer_sz = maxphys / vdc->vdisk_bsize;

	/*
	 * We assume, for now, that the vDisk server will export 'read'
	 * operations to us at a minimum (this is needed because of checks
	 * in vdc for supported operations early in the handshake process).
	 * The vDisk server will return ENOTSUP if this is not the case.
	 * The value will be overwritten during the attribute exchange with
	 * the bitmask of operations exported by server.
	 */
	vdc->operations = VD_OP_MASK_READ;

	vdc->vtoc = NULL;
	vdc->geom = NULL;
	vdc->cinfo = NULL;
	vdc->minfo = NULL;

	mutex_init(&vdc->lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vdc->initwait_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->dring_free_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->membind_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->running_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->io_pending_cv, NULL, CV_DRIVER, NULL);

	vdc->io_pending = B_FALSE;
	vdc->threads_pending = 0;
	vdc->sync_op_blocked = B_FALSE;
	cv_init(&vdc->sync_blocked_cv, NULL, CV_DRIVER, NULL);

	mutex_init(&vdc->ownership_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vdc->ownership_cv, NULL, CV_DRIVER, NULL);
	cv_init(&vdc->eio_cv, NULL, CV_DRIVER, NULL);

	/* init blocking msg read functionality */
	mutex_init(&vdc->read_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vdc->read_cv, NULL, CV_DRIVER, NULL);
	vdc->read_state = VDC_READ_IDLE;

	vdc->initialized |= VDC_LOCKS;

	/* get device and port MD node for this disk instance */
	if (vdc_get_md_node(dip, &mdp, &vd_node) != 0) {
		cmn_err(CE_NOTE, "[%d] Could not get machine description node",
		    instance);
		return (DDI_FAILURE);
	}

	if (vdc_init_ports(vdc, mdp, vd_node) != 0) {
		cmn_err(CE_NOTE, "[%d] Error initialising ports", instance);
		return (DDI_FAILURE);
	}

	(void) md_fini_handle(mdp);

	/* Create the kstats for saving the I/O statistics used by iostat(1M) */
	vdc_create_io_kstats(vdc);
	vdc_create_err_kstats(vdc);

	/* Initialize remaining structures before starting the msg thread */
	vdc->vdisk_label = VD_DISK_LABEL_UNK;
	vdc->vtoc = kmem_zalloc(sizeof (struct extvtoc), KM_SLEEP);
	vdc->geom = kmem_zalloc(sizeof (struct dk_geom), KM_SLEEP);
	vdc->minfo = kmem_zalloc(sizeof (struct dk_minfo), KM_SLEEP);

	/* initialize the thread responsible for managing state with server */
	vdc->msg_proc_thr = thread_create(NULL, 0, vdc_process_msg_thread,
	    vdc, 0, &p0, TS_RUN, minclsyspri);
	if (vdc->msg_proc_thr == NULL) {
		cmn_err(CE_NOTE, "[%d] Failed to create msg processing thread",
		    instance);
		return (DDI_FAILURE);
	}

	/*
	 * If there are multiple servers then start the eio thread.
	 */
	if (vdc->num_servers > 1) {
		vdc->eio_thread = thread_create(NULL, 0, vdc_eio_thread, vdc, 0,
		    &p0, TS_RUN, v.v_maxsyspri - 2);
		if (vdc->eio_thread == NULL) {
			cmn_err(CE_NOTE, "[%d] Failed to create error "
			    "I/O thread", instance);
			return (DDI_FAILURE);
		}
	}

	vdc->initialized |= VDC_THREAD;

	atomic_inc_32(&vdc_instance_count);

	/*
	 * Check the disk label. This will send requests and do the handshake.
	 * We don't really care about the disk label now. What we really need is
	 * the handshake do be done so that we know the type of the disk (slice
	 * or full disk) and the appropriate device nodes can be created.
	 */

	mutex_enter(&vdc->lock);
	(void) vdc_validate_geometry(vdc);
	mutex_exit(&vdc->lock);

	/*
	 * Now that we have the device info we can create the device nodes
	 */
	status = vdc_create_device_nodes(vdc);
	if (status) {
		DMSG(vdc, 0, "[%d] Failed to create device nodes",
		    instance);
		goto return_status;
	}

	/*
	 * Fill in the fields of the error statistics kstat that were not
	 * available when creating the kstat
	 */
	vdc_set_err_kstats(vdc);
	ddi_report_dev(dip);
	ASSERT(vdc->lifecycle == VDC_LC_ONLINE ||
	    vdc->lifecycle == VDC_LC_ONLINE_PENDING);
	DMSG(vdc, 0, "[%d] Attach tasks successful\n", instance);

return_status:
	DMSG(vdc, 0, "[%d] Attach completed\n", instance);
	return (status);
}

static int
vdc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int	status;

	switch (cmd) {
	case DDI_ATTACH:
		if ((status = vdc_do_attach(dip)) != 0)
			(void) vdc_detach(dip, DDI_DETACH);
		return (status);
	case DDI_RESUME:
		/* nothing to do for this non-device */
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}
}

static int
vdc_do_ldc_init(vdc_t *vdc, vdc_server_t *srvr)
{
	int			status = 0;
	ldc_status_t		ldc_state;
	ldc_attr_t		ldc_attr;

	ASSERT(vdc != NULL);
	ASSERT(srvr != NULL);

	ldc_attr.devclass = LDC_DEV_BLK;
	ldc_attr.instance = vdc->instance;
	ldc_attr.mode = LDC_MODE_UNRELIABLE;	/* unreliable transport */
	ldc_attr.mtu = VD_LDC_MTU;

	if ((srvr->state & VDC_LDC_INIT) == 0) {
		status = ldc_init(srvr->ldc_id, &ldc_attr,
		    &srvr->ldc_handle);
		if (status != 0) {
			DMSG(vdc, 0, "[%d] ldc_init(chan %ld) returned %d",
			    vdc->instance, srvr->ldc_id, status);
			return (status);
		}
		srvr->state |= VDC_LDC_INIT;
	}
	status = ldc_status(srvr->ldc_handle, &ldc_state);
	if (status != 0) {
		DMSG(vdc, 0, "[%d] Cannot discover LDC status [err=%d]",
		    vdc->instance, status);
		goto init_exit;
	}
	srvr->ldc_state = ldc_state;

	if ((srvr->state & VDC_LDC_CB) == 0) {
		status = ldc_reg_callback(srvr->ldc_handle, vdc_handle_cb,
		    (caddr_t)srvr);
		if (status != 0) {
			DMSG(vdc, 0, "[%d] LDC callback reg. failed (%d)",
			    vdc->instance, status);
			goto init_exit;
		}
		srvr->state |= VDC_LDC_CB;
	}

	/*
	 * At this stage we have initialised LDC, we will now try and open
	 * the connection.
	 */
	if (srvr->ldc_state == LDC_INIT) {
		status = ldc_open(srvr->ldc_handle);
		if (status != 0) {
			DMSG(vdc, 0, "[%d] ldc_open(chan %ld) returned %d",
			    vdc->instance, srvr->ldc_id, status);
			goto init_exit;
		}
		srvr->state |= VDC_LDC_OPEN;
	}

init_exit:
	if (status) {
		vdc_terminate_ldc(vdc, srvr);
	}

	return (status);
}

static int
vdc_start_ldc_connection(vdc_t *vdc)
{
	int		status = 0;

	ASSERT(vdc != NULL);

	ASSERT(MUTEX_HELD(&vdc->lock));

	status = vdc_do_ldc_up(vdc);

	DMSG(vdc, 0, "[%d] Finished bringing up LDC\n", vdc->instance);

	return (status);
}

static int
vdc_stop_ldc_connection(vdc_t *vdcp)
{
	int	status;

	ASSERT(vdcp != NULL);

	ASSERT(MUTEX_HELD(&vdcp->lock));

	DMSG(vdcp, 0, ": Resetting connection to vDisk server : state %d\n",
	    vdcp->state);

	status = ldc_down(vdcp->curr_server->ldc_handle);
	DMSG(vdcp, 0, "ldc_down() = %d\n", status);

	vdcp->initialized &= ~VDC_HANDSHAKE;
	DMSG(vdcp, 0, "initialized=%x\n", vdcp->initialized);

	return (status);
}

static void
vdc_create_io_kstats(vdc_t *vdc)
{
	if (vdc->io_stats != NULL) {
		DMSG(vdc, 0, "[%d] I/O kstat already exists\n", vdc->instance);
		return;
	}

	vdc->io_stats = kstat_create(VDC_DRIVER_NAME, vdc->instance, NULL,
	    "disk", KSTAT_TYPE_IO, 1, KSTAT_FLAG_PERSISTENT);
	if (vdc->io_stats != NULL) {
		vdc->io_stats->ks_lock = &vdc->lock;
		kstat_install(vdc->io_stats);
	} else {
		cmn_err(CE_NOTE, "[%d] Failed to create kstat: I/O statistics"
		    " will not be gathered", vdc->instance);
	}
}

static void
vdc_create_err_kstats(vdc_t *vdc)
{
	vd_err_stats_t	*stp;
	char	kstatmodule_err[KSTAT_STRLEN];
	char	kstatname[KSTAT_STRLEN];
	int	ndata = (sizeof (vd_err_stats_t) / sizeof (kstat_named_t));
	int	instance = vdc->instance;

	if (vdc->err_stats != NULL) {
		DMSG(vdc, 0, "[%d] ERR kstat already exists\n", vdc->instance);
		return;
	}

	(void) snprintf(kstatmodule_err, sizeof (kstatmodule_err),
	    "%serr", VDC_DRIVER_NAME);
	(void) snprintf(kstatname, sizeof (kstatname),
	    "%s%d,err", VDC_DRIVER_NAME, instance);

	vdc->err_stats = kstat_create(kstatmodule_err, instance, kstatname,
	    "device_error", KSTAT_TYPE_NAMED, ndata, KSTAT_FLAG_PERSISTENT);

	if (vdc->err_stats == NULL) {
		cmn_err(CE_NOTE, "[%d] Failed to create kstat: Error statistics"
		    " will not be gathered", instance);
		return;
	}

	stp = (vd_err_stats_t *)vdc->err_stats->ks_data;
	kstat_named_init(&stp->vd_softerrs,	"Soft Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->vd_transerrs,	"Transport Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->vd_protoerrs,	"Protocol Errors",
	    KSTAT_DATA_UINT32);
	kstat_named_init(&stp->vd_vid,		"Vendor",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->vd_pid,		"Product",
	    KSTAT_DATA_CHAR);
	kstat_named_init(&stp->vd_capacity,	"Size",
	    KSTAT_DATA_ULONGLONG);

	vdc->err_stats->ks_update  = nulldev;

	kstat_install(vdc->err_stats);
}

static void
vdc_set_err_kstats(vdc_t *vdc)
{
	vd_err_stats_t  *stp;

	if (vdc->err_stats == NULL)
		return;

	mutex_enter(&vdc->lock);

	stp = (vd_err_stats_t *)vdc->err_stats->ks_data;
	ASSERT(stp != NULL);

	stp->vd_capacity.value.ui64 = vdc->vdisk_size * vdc->vdisk_bsize;
	(void) strcpy(stp->vd_vid.value.c, "SUN");
	(void) strcpy(stp->vd_pid.value.c, "VDSK");

	mutex_exit(&vdc->lock);
}

static int
vdc_create_device_nodes_efi(vdc_t *vdc)
{
	ddi_remove_minor_node(vdc->dip, "h");
	ddi_remove_minor_node(vdc->dip, "h,raw");

	if (ddi_create_minor_node(vdc->dip, "wd", S_IFBLK,
	    VD_MAKE_DEV(vdc->instance, VD_EFI_WD_SLICE),
	    DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "[%d] Couldn't add block node 'wd'",
		    vdc->instance);
		return (EIO);
	}

	/* if any device node is created we set this flag */
	vdc->initialized |= VDC_MINOR;

	if (ddi_create_minor_node(vdc->dip, "wd,raw", S_IFCHR,
	    VD_MAKE_DEV(vdc->instance, VD_EFI_WD_SLICE),
	    DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "[%d] Couldn't add block node 'wd,raw'",
		    vdc->instance);
		return (EIO);
	}

	return (0);
}

static int
vdc_create_device_nodes_vtoc(vdc_t *vdc)
{
	ddi_remove_minor_node(vdc->dip, "wd");
	ddi_remove_minor_node(vdc->dip, "wd,raw");

	if (ddi_create_minor_node(vdc->dip, "h", S_IFBLK,
	    VD_MAKE_DEV(vdc->instance, VD_EFI_WD_SLICE),
	    DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "[%d] Couldn't add block node 'h'",
		    vdc->instance);
		return (EIO);
	}

	/* if any device node is created we set this flag */
	vdc->initialized |= VDC_MINOR;

	if (ddi_create_minor_node(vdc->dip, "h,raw", S_IFCHR,
	    VD_MAKE_DEV(vdc->instance, VD_EFI_WD_SLICE),
	    DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
		cmn_err(CE_NOTE, "[%d] Couldn't add block node 'h,raw'",
		    vdc->instance);
		return (EIO);
	}

	return (0);
}

/*
 * Function:
 *	vdc_create_device_nodes
 *
 * Description:
 *	This function creates the block and character device nodes under
 *	/devices. It is called as part of the attach(9E) of the instance
 *	during the handshake with vds after vds has sent the attributes
 *	to vdc.
 *
 *	If the device is of type VD_DISK_TYPE_SLICE then the minor node
 *	of 2 is used in keeping with the Solaris convention that slice 2
 *	refers to a whole disk. Slices start at 'a'
 *
 * Parameters:
 *	vdc		- soft state pointer
 *
 * Return Values
 *	0		- Success
 *	EIO		- Failed to create node
 */
static int
vdc_create_device_nodes(vdc_t *vdc)
{
	char		name[sizeof ("s,raw")];
	dev_info_t	*dip = NULL;
	int		instance, status;
	int		num_slices = 1;
	int		i;

	ASSERT(vdc != NULL);

	instance = vdc->instance;
	dip = vdc->dip;

	switch (vdc->vdisk_type) {
	case VD_DISK_TYPE_DISK:
	case VD_DISK_TYPE_UNK:
		num_slices = V_NUMPAR;
		break;
	case VD_DISK_TYPE_SLICE:
		num_slices = 1;
		break;
	default:
		ASSERT(0);
	}

	/*
	 * Minor nodes are different for EFI disks: EFI disks do not have
	 * a minor node 'g' for the minor number corresponding to slice
	 * VD_EFI_WD_SLICE (slice 7) instead they have a minor node 'wd'
	 * representing the whole disk.
	 */
	for (i = 0; i < num_slices; i++) {

		if (i == VD_EFI_WD_SLICE) {
			if (vdc->vdisk_label == VD_DISK_LABEL_EFI)
				status = vdc_create_device_nodes_efi(vdc);
			else
				status = vdc_create_device_nodes_vtoc(vdc);
			if (status != 0)
				return (status);
			continue;
		}

		(void) snprintf(name, sizeof (name), "%c", 'a' + i);
		if (ddi_create_minor_node(dip, name, S_IFBLK,
		    VD_MAKE_DEV(instance, i), DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "[%d] Couldn't add block node '%s'",
			    instance, name);
			return (EIO);
		}

		/* if any device node is created we set this flag */
		vdc->initialized |= VDC_MINOR;

		(void) snprintf(name, sizeof (name), "%c%s", 'a' + i, ",raw");

		if (ddi_create_minor_node(dip, name, S_IFCHR,
		    VD_MAKE_DEV(instance, i), DDI_NT_BLOCK, 0) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "[%d] Couldn't add raw node '%s'",
			    instance, name);
			return (EIO);
		}
	}

	return (0);
}

/*
 * Driver prop_op(9e) entry point function. Return the number of blocks for
 * the partition in question or forward the request to the property facilities.
 */
static int
vdc_prop_op(dev_t dev, dev_info_t *dip, ddi_prop_op_t prop_op, int mod_flags,
    char *name, caddr_t valuep, int *lengthp)
{
	int instance = ddi_get_instance(dip);
	vdc_t *vdc;
	uint64_t nblocks;
	uint_t blksize;

	vdc = ddi_get_soft_state(vdc_state, instance);

	if (dev == DDI_DEV_T_ANY || vdc == NULL) {
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	}

	mutex_enter(&vdc->lock);
	(void) vdc_validate_geometry(vdc);
	if (vdc->vdisk_label == VD_DISK_LABEL_UNK) {
		mutex_exit(&vdc->lock);
		return (ddi_prop_op(dev, dip, prop_op, mod_flags,
		    name, valuep, lengthp));
	}
	nblocks = vdc->slice[VDCPART(dev)].nblocks;
	blksize = vdc->vdisk_bsize;
	mutex_exit(&vdc->lock);

	return (ddi_prop_op_nblocks_blksize(dev, dip, prop_op, mod_flags,
	    name, valuep, lengthp, nblocks, blksize));
}

/*
 * Function:
 *	vdc_is_opened
 *
 * Description:
 *	This function checks if any slice of a given virtual disk is
 *	currently opened.
 *
 * Parameters:
 *	vdc		- soft state pointer
 *
 * Return Values
 *	B_TRUE		- at least one slice is opened.
 *	B_FALSE		- no slice is opened.
 */
static boolean_t
vdc_is_opened(vdc_t *vdc)
{
	int i;

	/* check if there's any layered open */
	for (i = 0; i < V_NUMPAR; i++) {
		if (vdc->open_lyr[i] > 0)
			return (B_TRUE);
	}

	/* check if there is any other kind of open */
	for (i = 0; i < OTYPCNT; i++) {
		if (vdc->open[i] != 0)
			return (B_TRUE);
	}

	return (B_FALSE);
}

static int
vdc_mark_opened(vdc_t *vdc, int slice, int flag, int otyp)
{
	uint8_t slicemask;
	int i;

	ASSERT(otyp < OTYPCNT);
	ASSERT(slice < V_NUMPAR);
	ASSERT(MUTEX_HELD(&vdc->lock));

	slicemask = 1 << slice;

	/*
	 * If we have a single-slice disk which was unavailable during the
	 * attach then a device was created for each 8 slices. Now that
	 * the type is known, we prevent opening any slice other than 0
	 * even if a device still exists.
	 */
	if (vdc->vdisk_type == VD_DISK_TYPE_SLICE && slice != 0)
		return (EIO);

	/* check if slice is already exclusively opened */
	if (vdc->open_excl & slicemask)
		return (EBUSY);

	/* if open exclusive, check if slice is already opened */
	if (flag & FEXCL) {
		if (vdc->open_lyr[slice] > 0)
			return (EBUSY);
		for (i = 0; i < OTYPCNT; i++) {
			if (vdc->open[i] & slicemask)
				return (EBUSY);
		}
		vdc->open_excl |= slicemask;
	}

	/* mark slice as opened */
	if (otyp == OTYP_LYR) {
		vdc->open_lyr[slice]++;
	} else {
		vdc->open[otyp] |= slicemask;
	}

	return (0);
}

static void
vdc_mark_closed(vdc_t *vdc, int slice, int flag, int otyp)
{
	uint8_t slicemask;

	ASSERT(otyp < OTYPCNT);
	ASSERT(slice < V_NUMPAR);
	ASSERT(MUTEX_HELD(&vdc->lock));

	slicemask = 1 << slice;

	if (otyp == OTYP_LYR) {
		ASSERT(vdc->open_lyr[slice] > 0);
		vdc->open_lyr[slice]--;
	} else {
		vdc->open[otyp] &= ~slicemask;
	}

	if (flag & FEXCL)
		vdc->open_excl &= ~slicemask;
}

static int
vdc_open(dev_t *dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	int	instance, nodelay;
	int	slice, status = 0;
	vdc_t	*vdc;

	ASSERT(dev != NULL);
	instance = VDCUNIT(*dev);

	if (otyp >= OTYPCNT)
		return (EINVAL);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		return (ENXIO);
	}

	DMSG(vdc, 0, "minor = %d flag = %x, otyp = %x\n",
	    getminor(*dev), flag, otyp);

	slice = VDCPART(*dev);

	nodelay = flag & (FNDELAY | FNONBLOCK);

	if ((flag & FWRITE) && (!nodelay) &&
	    !(VD_OP_SUPPORTED(vdc->operations, VD_OP_BWRITE))) {
		return (EROFS);
	}

	mutex_enter(&vdc->lock);

	status = vdc_mark_opened(vdc, slice, flag, otyp);

	if (status != 0) {
		mutex_exit(&vdc->lock);
		return (status);
	}

	/*
	 * If the disk type is unknown then we have to wait for the
	 * handshake to complete because we don't know if the slice
	 * device we are opening effectively exists.
	 */
	if (vdc->vdisk_type != VD_DISK_TYPE_UNK && nodelay) {

		/* don't resubmit a validate request if there's already one */
		if (vdc->validate_pending > 0) {
			mutex_exit(&vdc->lock);
			return (0);
		}

		/* call vdc_validate() asynchronously to avoid blocking */
		if (taskq_dispatch(system_taskq, vdc_validate_task,
		    (void *)vdc, TQ_NOSLEEP) == TASKQID_INVALID) {
			vdc_mark_closed(vdc, slice, flag, otyp);
			mutex_exit(&vdc->lock);
			return (ENXIO);
		}

		vdc->validate_pending++;
		mutex_exit(&vdc->lock);
		return (0);
	}

	mutex_exit(&vdc->lock);

	vdc_validate(vdc);

	mutex_enter(&vdc->lock);

	if (vdc->vdisk_type == VD_DISK_TYPE_UNK ||
	    (vdc->vdisk_type == VD_DISK_TYPE_SLICE && slice != 0) ||
	    (!nodelay && (vdc->vdisk_label == VD_DISK_LABEL_UNK ||
	    vdc->slice[slice].nblocks == 0))) {
		vdc_mark_closed(vdc, slice, flag, otyp);
		status = EIO;
	}

	mutex_exit(&vdc->lock);

	return (status);
}

static int
vdc_close(dev_t dev, int flag, int otyp, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	int	instance;
	int	slice;
	int	rv, rval;
	vdc_t	*vdc;

	instance = VDCUNIT(dev);

	if (otyp >= OTYPCNT)
		return (EINVAL);

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		return (ENXIO);
	}

	DMSG(vdc, 0, "[%d] flag = %x, otyp = %x\n", instance, flag, otyp);

	slice = VDCPART(dev);

	/*
	 * Attempt to flush the W$ on a close operation. If this is
	 * not a supported IOCTL command or the backing device is read-only
	 * do not fail the close operation.
	 */
	rv = vd_process_ioctl(dev, DKIOCFLUSHWRITECACHE, NULL, FKIOCTL, &rval);

	if (rv != 0 && rv != ENOTSUP && rv != ENOTTY && rv != EROFS) {
		DMSG(vdc, 0, "[%d] flush failed with error %d on close\n",
		    instance, rv);
		return (EIO);
	}

	mutex_enter(&vdc->lock);
	vdc_mark_closed(vdc, slice, flag, otyp);
	mutex_exit(&vdc->lock);

	return (0);
}

static int
vdc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	_NOTE(ARGUNUSED(credp))

	return (vd_process_ioctl(dev, cmd, (caddr_t)arg, mode, rvalp));
}

static int
vdc_print(dev_t dev, char *str)
{
	cmn_err(CE_NOTE, "vdc%d:  %s", VDCUNIT(dev), str);
	return (0);
}

static int
vdc_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	int	rv, flags;
	size_t	nbytes = nblk * DEV_BSIZE;
	int	instance = VDCUNIT(dev);
	vdc_t	*vdc = NULL;
	diskaddr_t vio_blkno;

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		return (ENXIO);
	}

	DMSG(vdc, 2, "[%d] dump %ld bytes at block 0x%lx : addr=0x%p\n",
	    instance, nbytes, blkno, (void *)addr);

	/* convert logical block to vio block */
	if ((blkno & vdc->vio_bmask) != 0) {
		DMSG(vdc, 0, "Misaligned block number (%lu)\n", blkno);
		return (EINVAL);
	}
	vio_blkno = blkno >> vdc->vio_bshift;

	/*
	 * If we are panicking, we need the state to be "running" so that we
	 * can submit I/Os, but we don't want to check for any backend error.
	 */
	flags = (ddi_in_panic())? VDC_OP_STATE_RUNNING : VDC_OP_NORMAL;

	rv = vdc_do_op(vdc, VD_OP_BWRITE, addr, nbytes, VDCPART(dev),
	    vio_blkno, NULL, VIO_write_dir, flags);

	if (rv) {
		DMSG(vdc, 0, "Failed to do a disk dump (err=%d)\n", rv);
		return (rv);
	}

	DMSG(vdc, 0, "[%d] End\n", instance);

	return (0);
}

/* -------------------------------------------------------------------------- */

/*
 * Disk access routines
 *
 */

/*
 * vdc_strategy()
 *
 * Return Value:
 *	0:	As per strategy(9E), the strategy() function must return 0
 *		[ bioerror(9f) sets b_flags to the proper error code ]
 */
static int
vdc_strategy(struct buf *buf)
{
	diskaddr_t vio_blkno;
	vdc_t	*vdc = NULL;
	int	instance = VDCUNIT(buf->b_edev);
	int	op = (buf->b_flags & B_READ) ? VD_OP_BREAD : VD_OP_BWRITE;
	int	slice;

	if ((vdc = ddi_get_soft_state(vdc_state, instance)) == NULL) {
		cmn_err(CE_NOTE, "[%d] Couldn't get state structure", instance);
		bioerror(buf, ENXIO);
		biodone(buf);
		return (0);
	}

	DMSG(vdc, 2, "[%d] %s %ld bytes at block %llx : b_addr=0x%p\n",
	    instance, (buf->b_flags & B_READ) ? "Read" : "Write",
	    buf->b_bcount, buf->b_lblkno, (void *)buf->b_un.b_addr);

	bp_mapin(buf);

	if ((long)buf->b_private == VD_SLICE_NONE) {
		/* I/O using an absolute disk offset */
		slice = VD_SLICE_NONE;
	} else {
		slice = VDCPART(buf->b_edev);
	}

	/*
	 * In the buf structure, b_lblkno represents a logical block number
	 * using a block size of 512 bytes. For the VIO request, this block
	 * number has to be converted to be represented with the block size
	 * used by the VIO protocol.
	 */
	if ((buf->b_lblkno & vdc->vio_bmask) != 0) {
		bioerror(buf, EINVAL);
		biodone(buf);
		return (0);
	}
	vio_blkno = buf->b_lblkno >> vdc->vio_bshift;

	/* submit the I/O, any error will be reported in the buf structure */
	(void) vdc_do_op(vdc, op, (caddr_t)buf->b_un.b_addr,
	    buf->b_bcount, slice, vio_blkno,
	    buf, (op == VD_OP_BREAD) ? VIO_read_dir : VIO_write_dir,
	    VDC_OP_NORMAL);

	return (0);
}

/*
 * Function:
 *	vdc_min
 *
 * Description:
 *	Routine to limit the size of a data transfer. Used in
 *	conjunction with physio(9F).
 *
 * Arguments:
 *	bp - pointer to the indicated buf(9S) struct.
 *
 */
static void
vdc_min(struct buf *bufp)
{
	vdc_t	*vdc = NULL;
	int	instance = VDCUNIT(bufp->b_edev);

	vdc = ddi_get_soft_state(vdc_state, instance);
	VERIFY(vdc != NULL);

	if (bufp->b_bcount > (vdc->max_xfer_sz * vdc->vdisk_bsize)) {
		bufp->b_bcount = vdc->max_xfer_sz * vdc->vdisk_bsize;
	}
}

static int
vdc_read(dev_t dev, struct uio *uio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	DMSGX(1, "[%d] Entered", VDCUNIT(dev));
	return (physio(vdc_strategy, NULL, dev, B_READ, vdc_min, uio));
}

static int
vdc_write(dev_t dev, struct uio *uio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	DMSGX(1, "[%d] Entered", VDCUNIT(dev));
	return (physio(vdc_strategy, NULL, dev, B_WRITE, vdc_min, uio));
}

static int
vdc_aread(dev_t dev, struct aio_req *aio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	DMSGX(1, "[%d] Entered", VDCUNIT(dev));
	return (aphysio(vdc_strategy, anocancel, dev, B_READ, vdc_min, aio));
}

static int
vdc_awrite(dev_t dev, struct aio_req *aio, cred_t *cred)
{
	_NOTE(ARGUNUSED(cred))

	DMSGX(1, "[%d] Entered", VDCUNIT(dev));
	return (aphysio(vdc_strategy, anocancel, dev, B_WRITE, vdc_min, aio));
}


/* -------------------------------------------------------------------------- */

/*
 * Handshake support
 */


/*
 * Function:
 *	vdc_init_ver_negotiation()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_init_ver_negotiation(vdc_t *vdc, vio_ver_t ver)
{
	vio_ver_msg_t	pkt;
	size_t		msglen = sizeof (pkt);
	int		status = -1;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	DMSG(vdc, 0, "[%d] Entered.\n", vdc->instance);

	/*
	 * set the Session ID to a unique value
	 * (the lower 32 bits of the clock tick)
	 */
	vdc->session_id = ((uint32_t)gettick() & 0xffffffff);
	DMSG(vdc, 0, "[%d] Set SID to 0x%lx\n", vdc->instance, vdc->session_id);

	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_VER_INFO;
	pkt.tag.vio_sid = vdc->session_id;
	pkt.dev_class = VDEV_DISK;
	pkt.ver_major = ver.major;
	pkt.ver_minor = ver.minor;

	status = vdc_send(vdc, (caddr_t)&pkt, &msglen);
	DMSG(vdc, 0, "[%d] Ver info sent (status = %d)\n",
	    vdc->instance, status);
	if ((status != 0) || (msglen != sizeof (vio_ver_msg_t))) {
		DMSG(vdc, 0, "[%d] Failed to send Ver negotiation info: "
		    "id(%lx) rv(%d) size(%ld)", vdc->instance,
		    vdc->curr_server->ldc_handle, status, msglen);
		if (msglen != sizeof (vio_ver_msg_t))
			status = ENOMSG;
	}

	return (status);
}

/*
 * Function:
 *	vdc_ver_negotiation()
 *
 * Description:
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_ver_negotiation(vdc_t *vdcp)
{
	vio_msg_t vio_msg;
	int status;

	if (status = vdc_init_ver_negotiation(vdcp, vdc_version[0]))
		return (status);

	/* release lock and wait for response */
	mutex_exit(&vdcp->lock);
	status = vdc_wait_for_response(vdcp, &vio_msg);
	mutex_enter(&vdcp->lock);
	if (status) {
		DMSG(vdcp, 0,
		    "[%d] Failed waiting for Ver negotiation response, rv(%d)",
		    vdcp->instance, status);
		return (status);
	}

	/* check type and sub_type ... */
	if (vio_msg.tag.vio_msgtype != VIO_TYPE_CTRL ||
	    vio_msg.tag.vio_subtype == VIO_SUBTYPE_INFO) {
		DMSG(vdcp, 0, "[%d] Invalid ver negotiation response\n",
		    vdcp->instance);
		return (EPROTO);
	}

	return (vdc_handle_ver_msg(vdcp, (vio_ver_msg_t *)&vio_msg));
}

/*
 * Function:
 *	vdc_init_attr_negotiation()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_init_attr_negotiation(vdc_t *vdc)
{
	vd_attr_msg_t	pkt;
	size_t		msglen = sizeof (pkt);
	int		status;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	DMSG(vdc, 0, "[%d] entered\n", vdc->instance);

	/* fill in tag */
	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_ATTR_INFO;
	pkt.tag.vio_sid = vdc->session_id;
	/* fill in payload */
	pkt.max_xfer_sz = vdc->max_xfer_sz;
	pkt.vdisk_block_size = vdc->vdisk_bsize;
	pkt.xfer_mode = VIO_DRING_MODE_V1_0;
	pkt.operations = 0;	/* server will set bits of valid operations */
	pkt.vdisk_type = 0;	/* server will set to valid device type */
	pkt.vdisk_media = 0;	/* server will set to valid media type */
	pkt.vdisk_size = 0;	/* server will set to valid size */

	status = vdc_send(vdc, (caddr_t)&pkt, &msglen);
	DMSG(vdc, 0, "Attr info sent (status = %d)\n", status);

	if ((status != 0) || (msglen != sizeof (vd_attr_msg_t))) {
		DMSG(vdc, 0, "[%d] Failed to send Attr negotiation info: "
		    "id(%lx) rv(%d) size(%ld)", vdc->instance,
		    vdc->curr_server->ldc_handle, status, msglen);
		if (msglen != sizeof (vd_attr_msg_t))
			status = ENOMSG;
	}

	return (status);
}

/*
 * Function:
 *	vdc_attr_negotiation()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_attr_negotiation(vdc_t *vdcp)
{
	int status;
	vio_msg_t vio_msg;

	if (status = vdc_init_attr_negotiation(vdcp))
		return (status);

	/* release lock and wait for response */
	mutex_exit(&vdcp->lock);
	status = vdc_wait_for_response(vdcp, &vio_msg);
	mutex_enter(&vdcp->lock);
	if (status) {
		DMSG(vdcp, 0,
		    "[%d] Failed waiting for Attr negotiation response, rv(%d)",
		    vdcp->instance, status);
		return (status);
	}

	/* check type and sub_type ... */
	if (vio_msg.tag.vio_msgtype != VIO_TYPE_CTRL ||
	    vio_msg.tag.vio_subtype == VIO_SUBTYPE_INFO) {
		DMSG(vdcp, 0, "[%d] Invalid attr negotiation response\n",
		    vdcp->instance);
		return (EPROTO);
	}

	return (vdc_handle_attr_msg(vdcp, (vd_attr_msg_t *)&vio_msg));
}


/*
 * Function:
 *	vdc_init_dring_negotiate()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_init_dring_negotiate(vdc_t *vdc)
{
	vio_dring_reg_msg_t	pkt;
	size_t			msglen = sizeof (pkt);
	int			status = -1;
	int			retry;
	int			nretries = 10;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	for (retry = 0; retry < nretries; retry++) {
		status = vdc_init_descriptor_ring(vdc);
		if (status != EAGAIN)
			break;
		drv_usecwait(vdc_min_timeout_ldc);
	}

	if (status != 0) {
		DMSG(vdc, 0, "[%d] Failed to init DRing (status = %d)\n",
		    vdc->instance, status);
		return (status);
	}

	DMSG(vdc, 0, "[%d] Init of descriptor ring completed (status = %d)\n",
	    vdc->instance, status);

	/* fill in tag */
	pkt.tag.vio_msgtype = VIO_TYPE_CTRL;
	pkt.tag.vio_subtype = VIO_SUBTYPE_INFO;
	pkt.tag.vio_subtype_env = VIO_DRING_REG;
	pkt.tag.vio_sid = vdc->session_id;
	/* fill in payload */
	pkt.dring_ident = 0;
	pkt.num_descriptors = vdc->dring_len;
	pkt.descriptor_size = vdc->dring_entry_size;
	pkt.options = (VIO_TX_DRING | VIO_RX_DRING);
	pkt.ncookies = vdc->dring_cookie_count;
	pkt.cookie[0] = vdc->dring_cookie[0];	/* for now just one cookie */

	status = vdc_send(vdc, (caddr_t)&pkt, &msglen);
	if (status != 0) {
		DMSG(vdc, 0, "[%d] Failed to register DRing (err = %d)",
		    vdc->instance, status);
	}

	return (status);
}


/*
 * Function:
 *	vdc_dring_negotiation()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_dring_negotiation(vdc_t *vdcp)
{
	int status;
	vio_msg_t vio_msg;

	if (status = vdc_init_dring_negotiate(vdcp))
		return (status);

	/* release lock and wait for response */
	mutex_exit(&vdcp->lock);
	status = vdc_wait_for_response(vdcp, &vio_msg);
	mutex_enter(&vdcp->lock);
	if (status) {
		DMSG(vdcp, 0,
		    "[%d] Failed waiting for Dring negotiation response,"
		    " rv(%d)", vdcp->instance, status);
		return (status);
	}

	/* check type and sub_type ... */
	if (vio_msg.tag.vio_msgtype != VIO_TYPE_CTRL ||
	    vio_msg.tag.vio_subtype == VIO_SUBTYPE_INFO) {
		DMSG(vdcp, 0, "[%d] Invalid Dring negotiation response\n",
		    vdcp->instance);
		return (EPROTO);
	}

	return (vdc_handle_dring_reg_msg(vdcp,
	    (vio_dring_reg_msg_t *)&vio_msg));
}


/*
 * Function:
 *	vdc_send_rdx()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_send_rdx(vdc_t *vdcp)
{
	vio_msg_t	msg;
	size_t		msglen = sizeof (vio_msg_t);
	int		status;

	/*
	 * Send an RDX message to vds to indicate we are ready
	 * to send data
	 */
	msg.tag.vio_msgtype = VIO_TYPE_CTRL;
	msg.tag.vio_subtype = VIO_SUBTYPE_INFO;
	msg.tag.vio_subtype_env = VIO_RDX;
	msg.tag.vio_sid = vdcp->session_id;
	status = vdc_send(vdcp, (caddr_t)&msg, &msglen);
	if (status != 0) {
		DMSG(vdcp, 0, "[%d] Failed to send RDX message (%d)",
		    vdcp->instance, status);
	}

	return (status);
}

/*
 * Function:
 *	vdc_handle_rdx()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	msgp	- received msg
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_handle_rdx(vdc_t *vdcp, vio_rdx_msg_t *msgp)
{
	_NOTE(ARGUNUSED(vdcp))
	_NOTE(ARGUNUSED(msgp))

	ASSERT(msgp->tag.vio_msgtype == VIO_TYPE_CTRL);
	ASSERT(msgp->tag.vio_subtype == VIO_SUBTYPE_ACK);
	ASSERT(msgp->tag.vio_subtype_env == VIO_RDX);

	DMSG(vdcp, 1, "[%d] Got an RDX msg", vdcp->instance);

	return (0);
}

/*
 * Function:
 *	vdc_rdx_exchange()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_rdx_exchange(vdc_t *vdcp)
{
	int status;
	vio_msg_t vio_msg;

	if (status = vdc_send_rdx(vdcp))
		return (status);

	/* release lock and wait for response */
	mutex_exit(&vdcp->lock);
	status = vdc_wait_for_response(vdcp, &vio_msg);
	mutex_enter(&vdcp->lock);
	if (status) {
		DMSG(vdcp, 0, "[%d] Failed waiting for RDX response, rv(%d)",
		    vdcp->instance, status);
		return (status);
	}

	/* check type and sub_type ... */
	if (vio_msg.tag.vio_msgtype != VIO_TYPE_CTRL ||
	    vio_msg.tag.vio_subtype != VIO_SUBTYPE_ACK) {
		DMSG(vdcp, 0, "[%d] Invalid RDX response\n", vdcp->instance);
		return (EPROTO);
	}

	return (vdc_handle_rdx(vdcp, (vio_rdx_msg_t *)&vio_msg));
}


/* -------------------------------------------------------------------------- */

/*
 * LDC helper routines
 */

static int
vdc_recv(vdc_t *vdc, vio_msg_t *msgp, size_t *nbytesp)
{
	int		status;
	uint64_t	delay_time;
	size_t		len;

	/*
	 * Until we get a blocking ldc read we have to retry until the entire
	 * LDC message has arrived before ldc_read() will return that message.
	 * If ldc_read() succeed but returns a zero length message then that
	 * means that the LDC queue is empty and we have to wait for a
	 * notification from the LDC callback which will set the read_state to
	 * VDC_READ_PENDING. Note we also bail out if the channel is reset or
	 * goes away.
	 */
	delay_time = vdc_ldc_read_init_delay;

	for (;;) {

		len = *nbytesp;
		/*
		 * vdc->curr_server is protected by vdc->lock but to avoid
		 * contentions we don't take the lock here. We can do this
		 * safely because vdc_recv() is only called from thread
		 * process_msg_thread() which is also the only thread that
		 * can change vdc->curr_server.
		 */
		status = ldc_read(vdc->curr_server->ldc_handle,
		    (caddr_t)msgp, &len);

		if (status == EAGAIN) {
			delay_time *= 2;
			if (delay_time >= vdc_ldc_read_max_delay)
				delay_time = vdc_ldc_read_max_delay;
			delay(delay_time);
			continue;
		}

		if (status != 0) {
			DMSG(vdc, 0, "ldc_read returned %d\n", status);
			break;
		}

		if (len != 0) {
			*nbytesp = len;
			break;
		}

		mutex_enter(&vdc->read_lock);

		while (vdc->read_state != VDC_READ_PENDING) {

			/* detect if the connection has been reset */
			if (vdc->read_state == VDC_READ_RESET) {
				mutex_exit(&vdc->read_lock);
				return (ECONNRESET);
			}

			vdc->read_state = VDC_READ_WAITING;
			cv_wait(&vdc->read_cv, &vdc->read_lock);
		}

		vdc->read_state = VDC_READ_IDLE;
		mutex_exit(&vdc->read_lock);

		delay_time = vdc_ldc_read_init_delay;
	}

	return (status);
}



#ifdef DEBUG
void
vdc_decode_tag(vdc_t *vdcp, vio_msg_t *msg)
{
	char *ms, *ss, *ses;
	switch (msg->tag.vio_msgtype) {
#define	Q(_s)	case _s : ms = #_s; break;
	Q(VIO_TYPE_CTRL)
	Q(VIO_TYPE_DATA)
	Q(VIO_TYPE_ERR)
#undef Q
	default: ms = "unknown"; break;
	}

	switch (msg->tag.vio_subtype) {
#define	Q(_s)	case _s : ss = #_s; break;
	Q(VIO_SUBTYPE_INFO)
	Q(VIO_SUBTYPE_ACK)
	Q(VIO_SUBTYPE_NACK)
#undef Q
	default: ss = "unknown"; break;
	}

	switch (msg->tag.vio_subtype_env) {
#define	Q(_s)	case _s : ses = #_s; break;
	Q(VIO_VER_INFO)
	Q(VIO_ATTR_INFO)
	Q(VIO_DRING_REG)
	Q(VIO_DRING_UNREG)
	Q(VIO_RDX)
	Q(VIO_PKT_DATA)
	Q(VIO_DESC_DATA)
	Q(VIO_DRING_DATA)
#undef Q
	default: ses = "unknown"; break;
	}

	DMSG(vdcp, 3, "(%x/%x/%x) message : (%s/%s/%s)\n",
	    msg->tag.vio_msgtype, msg->tag.vio_subtype,
	    msg->tag.vio_subtype_env, ms, ss, ses);
}
#endif

/*
 * Function:
 *	vdc_send()
 *
 * Description:
 *	The function encapsulates the call to write a message using LDC.
 *	If LDC indicates that the call failed due to the queue being full,
 *	we retry the ldc_write(), otherwise we return the error returned by LDC.
 *
 * Arguments:
 *	ldc_handle	- LDC handle for the channel this instance of vdc uses
 *	pkt		- address of LDC message to be sent
 *	msglen		- the size of the message being sent. When the function
 *			  returns, this contains the number of bytes written.
 *
 * Return Code:
 *	0		- Success.
 *	EINVAL		- pkt or msglen were NULL
 *	ECONNRESET	- The connection was not up.
 *	EWOULDBLOCK	- LDC queue is full
 *	xxx		- other error codes returned by ldc_write
 */
static int
vdc_send(vdc_t *vdc, caddr_t pkt, size_t *msglen)
{
	size_t	size = 0;
	int	status = 0;
	clock_t delay_ticks;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));
	ASSERT(msglen != NULL);
	ASSERT(*msglen != 0);

#ifdef DEBUG
	vdc_decode_tag(vdc, (vio_msg_t *)(uintptr_t)pkt);
#endif
	/*
	 * Wait indefinitely to send if channel
	 * is busy, but bail out if we succeed or
	 * if the channel closes or is reset.
	 */
	delay_ticks = vdc_hz_min_ldc_delay;
	do {
		size = *msglen;
		status = ldc_write(vdc->curr_server->ldc_handle, pkt, &size);
		if (status == EWOULDBLOCK) {
			delay(delay_ticks);
			/* geometric backoff */
			delay_ticks *= 2;
			if (delay_ticks > vdc_hz_max_ldc_delay)
				delay_ticks = vdc_hz_max_ldc_delay;
		}
	} while (status == EWOULDBLOCK);

	/* if LDC had serious issues --- reset vdc state */
	if (status == EIO || status == ECONNRESET) {
		/* LDC had serious issues --- reset vdc state */
		mutex_enter(&vdc->read_lock);
		if ((vdc->read_state == VDC_READ_WAITING) ||
		    (vdc->read_state == VDC_READ_RESET))
			cv_signal(&vdc->read_cv);
		vdc->read_state = VDC_READ_RESET;
		mutex_exit(&vdc->read_lock);

		/* wake up any waiters in the reset thread */
		if (vdc->state == VDC_STATE_INIT_WAITING) {
			DMSG(vdc, 0, "[%d] write reset - "
			    "vdc is resetting ..\n", vdc->instance);
			vdc->state = VDC_STATE_RESETTING;
			cv_signal(&vdc->initwait_cv);
		}

		return (ECONNRESET);
	}

	/* return the last size written */
	*msglen = size;

	return (status);
}

/*
 * Function:
 *	vdc_get_md_node
 *
 * Description:
 *	Get the MD, the device node for the given disk instance. The
 *	caller is responsible for cleaning up the reference to the
 *	returned MD (mdpp) by calling md_fini_handle().
 *
 * Arguments:
 *	dip	- dev info pointer for this instance of the device driver.
 *	mdpp	- the returned MD.
 *	vd_nodep - the returned device node.
 *
 * Return Code:
 *	0	- Success.
 *	ENOENT	- Expected node or property did not exist.
 *	ENXIO	- Unexpected error communicating with MD framework
 */
static int
vdc_get_md_node(dev_info_t *dip, md_t **mdpp, mde_cookie_t *vd_nodep)
{
	int		status = ENOENT;
	char		*node_name = NULL;
	md_t		*mdp = NULL;
	int		num_nodes;
	int		num_vdevs;
	mde_cookie_t	rootnode;
	mde_cookie_t	*listp = NULL;
	boolean_t	found_inst = B_FALSE;
	int		listsz;
	int		idx;
	uint64_t	md_inst;
	int		obp_inst;
	int		instance = ddi_get_instance(dip);

	/*
	 * Get the OBP instance number for comparison with the MD instance
	 *
	 * The "cfg-handle" property of a vdc node in an MD contains the MD's
	 * notion of "instance", or unique identifier, for that node; OBP
	 * stores the value of the "cfg-handle" MD property as the value of
	 * the "reg" property on the node in the device tree it builds from
	 * the MD and passes to Solaris.  Thus, we look up the devinfo node's
	 * "reg" property value to uniquely identify this device instance.
	 * If the "reg" property cannot be found, the device tree state is
	 * presumably so broken that there is no point in continuing.
	 */
	if (!ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, OBP_REG)) {
		cmn_err(CE_WARN, "'%s' property does not exist", OBP_REG);
		return (ENOENT);
	}
	obp_inst = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    OBP_REG, -1);
	DMSGX(1, "[%d] OBP inst=%d\n", instance, obp_inst);

	/*
	 * We now walk the MD nodes to find the node for this vdisk.
	 */
	if ((mdp = md_get_handle()) == NULL) {
		cmn_err(CE_WARN, "unable to init machine description");
		return (ENXIO);
	}

	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);

	/* allocate memory for nodes */
	listp = kmem_zalloc(listsz, KM_SLEEP);

	rootnode = md_root_node(mdp);
	ASSERT(rootnode != MDE_INVAL_ELEM_COOKIE);

	/*
	 * Search for all the virtual devices, we will then check to see which
	 * ones are disk nodes.
	 */
	num_vdevs = md_scan_dag(mdp, rootnode,
	    md_find_name(mdp, VDC_MD_VDEV_NAME),
	    md_find_name(mdp, "fwd"), listp);

	if (num_vdevs <= 0) {
		cmn_err(CE_NOTE, "No '%s' node found", VDC_MD_VDEV_NAME);
		status = ENOENT;
		goto done;
	}

	DMSGX(1, "[%d] num_vdevs=%d\n", instance, num_vdevs);
	for (idx = 0; idx < num_vdevs; idx++) {
		status = md_get_prop_str(mdp, listp[idx], "name", &node_name);
		if ((status != 0) || (node_name == NULL)) {
			cmn_err(CE_NOTE, "Unable to get name of node type '%s'"
			    ": err %d", VDC_MD_VDEV_NAME, status);
			continue;
		}

		DMSGX(1, "[%d] Found node '%s'\n", instance, node_name);
		if (strcmp(VDC_MD_DISK_NAME, node_name) == 0) {
			status = md_get_prop_val(mdp, listp[idx],
			    VDC_MD_CFG_HDL, &md_inst);
			DMSGX(1, "[%d] vdc inst in MD=%lx\n",
			    instance, md_inst);
			if ((status == 0) && (md_inst == obp_inst)) {
				found_inst = B_TRUE;
				break;
			}
		}
	}

	if (!found_inst) {
		DMSGX(0, "Unable to find correct '%s' node", VDC_MD_DISK_NAME);
		status = ENOENT;
		goto done;
	}
	DMSGX(0, "[%d] MD inst=%lx\n", instance, md_inst);

	*vd_nodep = listp[idx];
	*mdpp = mdp;
done:
	kmem_free(listp, listsz);
	return (status);
}

/*
 * Function:
 *	vdc_init_ports
 *
 * Description:
 *	Initialize all the ports for this vdisk instance.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	mdp	- md pointer
 *	vd_nodep - device md node.
 *
 * Return Code:
 *	0	- Success.
 *	ENOENT	- Expected node or property did not exist.
 */
static int
vdc_init_ports(vdc_t *vdc, md_t *mdp, mde_cookie_t vd_nodep)
{
	int		status = 0;
	int		idx;
	int		num_nodes;
	int		num_vports;
	int		num_chans;
	int		listsz;
	mde_cookie_t	vd_port;
	mde_cookie_t	*chanp = NULL;
	mde_cookie_t	*portp = NULL;
	vdc_server_t	*srvr;
	vdc_server_t	*prev_srvr = NULL;

	/*
	 * We now walk the MD nodes to find the port nodes for this vdisk.
	 */
	num_nodes = md_node_count(mdp);
	ASSERT(num_nodes > 0);

	listsz = num_nodes * sizeof (mde_cookie_t);

	/* allocate memory for nodes */
	portp = kmem_zalloc(listsz, KM_SLEEP);
	chanp = kmem_zalloc(listsz, KM_SLEEP);

	num_vports = md_scan_dag(mdp, vd_nodep,
	    md_find_name(mdp, VDC_MD_PORT_NAME),
	    md_find_name(mdp, "fwd"), portp);
	if (num_vports == 0) {
		DMSGX(0, "Found no '%s' node for '%s' port\n",
		    VDC_MD_PORT_NAME, VDC_MD_VDEV_NAME);
		status = ENOENT;
		goto done;
	}

	DMSGX(1, "Found %d '%s' node(s) for '%s' port\n",
	    num_vports, VDC_MD_PORT_NAME, VDC_MD_VDEV_NAME);

	vdc->num_servers = 0;
	for (idx = 0; idx < num_vports; idx++) {

		/* initialize this port */
		vd_port = portp[idx];
		srvr = kmem_zalloc(sizeof (vdc_server_t), KM_SLEEP);
		srvr->vdcp = vdc;
		srvr->svc_state = VDC_SERVICE_OFFLINE;
		srvr->log_state = VDC_SERVICE_NONE;

		/* get port id */
		if (md_get_prop_val(mdp, vd_port, VDC_MD_ID, &srvr->id) != 0) {
			cmn_err(CE_NOTE, "vDisk port '%s' property not found",
			    VDC_MD_ID);
			kmem_free(srvr, sizeof (vdc_server_t));
			continue;
		}

		/* set the connection timeout */
		if (md_get_prop_val(mdp, vd_port, VDC_MD_TIMEOUT,
		    &srvr->ctimeout) != 0) {
			srvr->ctimeout = 0;
		}

		/* get the ldc id */
		num_chans = md_scan_dag(mdp, vd_port,
		    md_find_name(mdp, VDC_MD_CHAN_NAME),
		    md_find_name(mdp, "fwd"), chanp);

		/* expecting at least one channel */
		if (num_chans <= 0) {
			cmn_err(CE_NOTE, "No '%s' node for '%s' port",
			    VDC_MD_CHAN_NAME, VDC_MD_VDEV_NAME);
			kmem_free(srvr, sizeof (vdc_server_t));
			continue;
		} else if (num_chans != 1) {
			DMSGX(0, "Expected 1 '%s' node for '%s' port, "
			    "found %d\n", VDC_MD_CHAN_NAME, VDC_MD_VDEV_NAME,
			    num_chans);
		}

		/*
		 * We use the first channel found (index 0), irrespective of how
		 * many are there in total.
		 */
		if (md_get_prop_val(mdp, chanp[0], VDC_MD_ID,
		    &srvr->ldc_id) != 0) {
			cmn_err(CE_NOTE, "Channel '%s' property not found",
			    VDC_MD_ID);
			kmem_free(srvr, sizeof (vdc_server_t));
			continue;
		}

		/*
		 * now initialise LDC channel which will be used to
		 * communicate with this server
		 */
		if (vdc_do_ldc_init(vdc, srvr) != 0) {
			kmem_free(srvr, sizeof (vdc_server_t));
			continue;
		}

		/* add server to list */
		if (prev_srvr)
			prev_srvr->next = srvr;
		else
			vdc->server_list = srvr;

		prev_srvr = srvr;

		/* inc numbers of servers */
		vdc->num_servers++;
	}

	/* pick first server as current server */
	if (vdc->server_list != NULL) {
		vdc->curr_server = vdc->server_list;
		status = 0;
	} else {
		status = ENOENT;
	}

done:
	kmem_free(chanp, listsz);
	kmem_free(portp, listsz);
	return (status);
}


/*
 * Function:
 *	vdc_do_ldc_up
 *
 * Description:
 *	Bring the channel for the current server up.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0		- Success.
 *	EINVAL		- Driver is detaching / LDC error
 *	ECONNREFUSED	- Other end is not listening
 */
static int
vdc_do_ldc_up(vdc_t *vdc)
{
	int		status;
	ldc_status_t	ldc_state;

	ASSERT(MUTEX_HELD(&vdc->lock));

	DMSG(vdc, 0, "[%d] Bringing up channel %lx\n",
	    vdc->instance, vdc->curr_server->ldc_id);

	if (vdc->lifecycle == VDC_LC_DETACHING)
		return (EINVAL);

	if ((status = ldc_up(vdc->curr_server->ldc_handle)) != 0) {
		switch (status) {
		case ECONNREFUSED:	/* listener not ready at other end */
			DMSG(vdc, 0, "[%d] ldc_up(%lx,...) return %d\n",
			    vdc->instance, vdc->curr_server->ldc_id, status);
			status = 0;
			break;
		default:
			DMSG(vdc, 0, "[%d] Failed to bring up LDC: "
			    "channel=%ld, err=%d", vdc->instance,
			    vdc->curr_server->ldc_id, status);
			break;
		}
	}

	if (ldc_status(vdc->curr_server->ldc_handle, &ldc_state) == 0) {
		vdc->curr_server->ldc_state = ldc_state;
		if (ldc_state == LDC_UP) {
			DMSG(vdc, 0, "[%d] LDC channel already up\n",
			    vdc->instance);
			vdc->seq_num = 1;
			vdc->seq_num_reply = 0;
		}
	}

	return (status);
}

/*
 * Function:
 *	vdc_terminate_ldc()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	srvr	- vdc per-server info structure
 *
 * Return Code:
 *	None
 */
static void
vdc_terminate_ldc(vdc_t *vdc, vdc_server_t *srvr)
{
	int	instance = ddi_get_instance(vdc->dip);

	if (srvr->state & VDC_LDC_OPEN) {
		DMSG(vdc, 0, "[%d] ldc_close()\n", instance);
		(void) ldc_close(srvr->ldc_handle);
	}
	if (srvr->state & VDC_LDC_CB) {
		DMSG(vdc, 0, "[%d] ldc_unreg_callback()\n", instance);
		(void) ldc_unreg_callback(srvr->ldc_handle);
	}
	if (srvr->state & VDC_LDC_INIT) {
		DMSG(vdc, 0, "[%d] ldc_fini()\n", instance);
		(void) ldc_fini(srvr->ldc_handle);
		srvr->ldc_handle = 0;
	}

	srvr->state &= ~(VDC_LDC_INIT | VDC_LDC_CB | VDC_LDC_OPEN);
}

/*
 * Function:
 *	vdc_fini_ports()
 *
 * Description:
 *	Finalize all ports by closing the channel associated with each
 *	port and also freeing the server structure.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	None
 */
static void
vdc_fini_ports(vdc_t *vdc)
{
	int		instance = ddi_get_instance(vdc->dip);
	vdc_server_t	*srvr, *prev_srvr;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	DMSG(vdc, 0, "[%d] initialized=%x\n", instance, vdc->initialized);

	srvr = vdc->server_list;

	while (srvr) {

		vdc_terminate_ldc(vdc, srvr);

		/* next server */
		prev_srvr = srvr;
		srvr = srvr->next;

		/* free server */
		kmem_free(prev_srvr, sizeof (vdc_server_t));
	}

	vdc->server_list = NULL;
	vdc->num_servers = 0;
}

/* -------------------------------------------------------------------------- */

/*
 * Descriptor Ring helper routines
 */

/*
 * Function:
 *	vdc_init_descriptor_ring()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_init_descriptor_ring(vdc_t *vdc)
{
	vd_dring_entry_t	*dep = NULL;	/* DRing Entry pointer */
	int	status = 0;
	int	i;

	DMSG(vdc, 0, "[%d] initialized=%x\n", vdc->instance, vdc->initialized);

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	/* ensure we have enough room to store max sized block */
	ASSERT(maxphys <= VD_MAX_BLOCK_SIZE);

	if ((vdc->initialized & VDC_DRING_INIT) == 0) {
		DMSG(vdc, 0, "[%d] ldc_mem_dring_create\n", vdc->instance);
		/*
		 * Calculate the maximum block size we can transmit using one
		 * Descriptor Ring entry from the attributes returned by the
		 * vDisk server. This is subject to a minimum of 'maxphys'
		 * as we do not have the capability to split requests over
		 * multiple DRing entries.
		 */
		if ((vdc->max_xfer_sz * vdc->vdisk_bsize) < maxphys) {
			DMSG(vdc, 0, "[%d] using minimum DRing size\n",
			    vdc->instance);
			vdc->dring_max_cookies = maxphys / PAGESIZE;
		} else {
			vdc->dring_max_cookies =
			    (vdc->max_xfer_sz * vdc->vdisk_bsize) / PAGESIZE;
		}
		vdc->dring_entry_size = (sizeof (vd_dring_entry_t) +
		    (sizeof (ldc_mem_cookie_t) *
		    (vdc->dring_max_cookies - 1)));
		vdc->dring_len = VD_DRING_LEN;

		status = ldc_mem_dring_create(vdc->dring_len,
		    vdc->dring_entry_size, &vdc->dring_hdl);
		if ((vdc->dring_hdl == 0) || (status != 0)) {
			DMSG(vdc, 0, "[%d] Descriptor ring creation failed",
			    vdc->instance);
			return (status);
		}
		vdc->initialized |= VDC_DRING_INIT;
	}

	if ((vdc->initialized & VDC_DRING_BOUND) == 0) {
		DMSG(vdc, 0, "[%d] ldc_mem_dring_bind\n", vdc->instance);
		vdc->dring_cookie =
		    kmem_zalloc(sizeof (ldc_mem_cookie_t), KM_SLEEP);

		status = ldc_mem_dring_bind(vdc->curr_server->ldc_handle,
		    vdc->dring_hdl,
		    LDC_SHADOW_MAP|LDC_DIRECT_MAP, LDC_MEM_RW,
		    &vdc->dring_cookie[0],
		    &vdc->dring_cookie_count);
		if (status != 0) {
			DMSG(vdc, 0, "[%d] Failed to bind descriptor ring "
			    "(%lx) to channel (%lx) status=%d\n",
			    vdc->instance, vdc->dring_hdl,
			    vdc->curr_server->ldc_handle, status);
			return (status);
		}
		ASSERT(vdc->dring_cookie_count == 1);
		vdc->initialized |= VDC_DRING_BOUND;
	}

	status = ldc_mem_dring_info(vdc->dring_hdl, &vdc->dring_mem_info);
	if (status != 0) {
		DMSG(vdc, 0,
		    "[%d] Failed to get info for descriptor ring (%lx)\n",
		    vdc->instance, vdc->dring_hdl);
		return (status);
	}

	if ((vdc->initialized & VDC_DRING_LOCAL) == 0) {
		DMSG(vdc, 0, "[%d] local dring\n", vdc->instance);

		/* Allocate the local copy of this dring */
		vdc->local_dring =
		    kmem_zalloc(vdc->dring_len * sizeof (vdc_local_desc_t),
		    KM_SLEEP);
		vdc->initialized |= VDC_DRING_LOCAL;
	}

	/*
	 * Mark all DRing entries as free and initialize the private
	 * descriptor's memory handles. If any entry is initialized,
	 * we need to free it later so we set the bit in 'initialized'
	 * at the start.
	 */
	vdc->initialized |= VDC_DRING_ENTRY;
	for (i = 0; i < vdc->dring_len; i++) {
		dep = VDC_GET_DRING_ENTRY_PTR(vdc, i);
		dep->hdr.dstate = VIO_DESC_FREE;

		status = ldc_mem_alloc_handle(vdc->curr_server->ldc_handle,
		    &vdc->local_dring[i].desc_mhdl);
		if (status != 0) {
			DMSG(vdc, 0, "![%d] Failed to alloc mem handle for"
			    " descriptor %d", vdc->instance, i);
			return (status);
		}
		vdc->local_dring[i].is_free = B_TRUE;
		vdc->local_dring[i].dep = dep;
	}

	/* Initialize the starting index */
	vdc->dring_curr_idx = VDC_DRING_FIRST_ENTRY;

	return (status);
}

/*
 * Function:
 *	vdc_destroy_descriptor_ring()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	None
 */
static void
vdc_destroy_descriptor_ring(vdc_t *vdc)
{
	vdc_local_desc_t	*ldep = NULL;	/* Local Dring Entry Pointer */
	ldc_mem_handle_t	mhdl = 0;
	ldc_mem_info_t		minfo;
	int			status = -1;
	int			i;	/* loop */

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	DMSG(vdc, 0, "[%d] Entered\n", vdc->instance);

	if (vdc->initialized & VDC_DRING_ENTRY) {
		DMSG(vdc, 0,
		    "[%d] Removing Local DRing entries\n", vdc->instance);
		for (i = 0; i < vdc->dring_len; i++) {
			ldep = &vdc->local_dring[i];
			mhdl = ldep->desc_mhdl;

			if (mhdl == 0)
				continue;

			if ((status = ldc_mem_info(mhdl, &minfo)) != 0) {
				DMSG(vdc, 0,
				    "ldc_mem_info returned an error: %d\n",
				    status);

				/*
				 * This must mean that the mem handle
				 * is not valid. Clear it out so that
				 * no one tries to use it.
				 */
				ldep->desc_mhdl = 0;
				continue;
			}

			if (minfo.status == LDC_BOUND) {
				(void) ldc_mem_unbind_handle(mhdl);
			}

			(void) ldc_mem_free_handle(mhdl);

			ldep->desc_mhdl = 0;
		}
		vdc->initialized &= ~VDC_DRING_ENTRY;
	}

	if (vdc->initialized & VDC_DRING_LOCAL) {
		DMSG(vdc, 0, "[%d] Freeing Local DRing\n", vdc->instance);
		kmem_free(vdc->local_dring,
		    vdc->dring_len * sizeof (vdc_local_desc_t));
		vdc->initialized &= ~VDC_DRING_LOCAL;
	}

	if (vdc->initialized & VDC_DRING_BOUND) {
		DMSG(vdc, 0, "[%d] Unbinding DRing\n", vdc->instance);
		status = ldc_mem_dring_unbind(vdc->dring_hdl);
		if (status == 0) {
			vdc->initialized &= ~VDC_DRING_BOUND;
		} else {
			DMSG(vdc, 0, "[%d] Error %d unbinding DRing %lx",
			    vdc->instance, status, vdc->dring_hdl);
		}
		kmem_free(vdc->dring_cookie, sizeof (ldc_mem_cookie_t));
	}

	if (vdc->initialized & VDC_DRING_INIT) {
		DMSG(vdc, 0, "[%d] Destroying DRing\n", vdc->instance);
		status = ldc_mem_dring_destroy(vdc->dring_hdl);
		if (status == 0) {
			vdc->dring_hdl = 0;
			bzero(&vdc->dring_mem_info, sizeof (ldc_mem_info_t));
			vdc->initialized &= ~VDC_DRING_INIT;
		} else {
			DMSG(vdc, 0, "[%d] Error %d destroying DRing (%lx)",
			    vdc->instance, status, vdc->dring_hdl);
		}
	}
}

/*
 * Function:
 *	vdc_map_to_shared_dring()
 *
 * Description:
 *	Copy contents of the local descriptor to the shared
 *	memory descriptor.
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *	idx	- descriptor ring index
 *
 * Return Code:
 *	None
 */
static int
vdc_map_to_shared_dring(vdc_t *vdcp, int idx)
{
	vdc_local_desc_t	*ldep;
	vd_dring_entry_t	*dep;
	int			rv;

	ldep = &(vdcp->local_dring[idx]);

	/* for now leave in the old pop_mem_hdl stuff */
	if (ldep->nbytes > 0) {
		rv = vdc_populate_mem_hdl(vdcp, ldep);
		if (rv) {
			DMSG(vdcp, 0, "[%d] Cannot populate mem handle\n",
			    vdcp->instance);
			return (rv);
		}
	}

	/*
	 * fill in the data details into the DRing
	 */
	dep = ldep->dep;
	ASSERT(dep != NULL);

	dep->payload.req_id = VDC_GET_NEXT_REQ_ID(vdcp);
	dep->payload.operation = ldep->operation;
	dep->payload.addr = ldep->offset;
	dep->payload.nbytes = ldep->nbytes;
	dep->payload.status = (uint32_t)-1;	/* vds will set valid value */
	dep->payload.slice = ldep->slice;
	dep->hdr.dstate = VIO_DESC_READY;
	dep->hdr.ack = 1;		/* request an ACK for every message */

	return (0);
}

/*
 * Function:
 *	vdc_send_request
 *
 * Description:
 *	This routine writes the data to be transmitted to vds into the
 *	descriptor, notifies vds that the ring has been updated and
 *	then waits for the request to be processed.
 *
 * Arguments:
 *	vdcp	  - the soft state pointer
 *	operation - operation we want vds to perform (VD_OP_XXX)
 *	addr	  - address of data buf to be read/written.
 *	nbytes	  - number of bytes to read/write
 *	slice	  - the disk slice this request is for
 *	offset	  - relative disk offset
 *	bufp	  - buf of operation
 *	dir	  - direction of operation (READ/WRITE/BOTH)
 *
 * Return Codes:
 *	0
 *	ENXIO
 */
static int
vdc_send_request(vdc_t *vdcp, int operation, caddr_t addr,
    size_t nbytes, int slice, diskaddr_t offset, buf_t *bufp,
    vio_desc_direction_t dir, int flags)
{
	int	rv = 0;

	ASSERT(vdcp != NULL);
	ASSERT(slice == VD_SLICE_NONE || slice < V_NUMPAR);

	mutex_enter(&vdcp->lock);

	/*
	 * If this is a block read/write operation we update the I/O statistics
	 * to indicate that the request is being put on the waitq to be
	 * serviced. Operations which are resubmitted are already in the waitq.
	 *
	 * We do it here (a common routine for both synchronous and strategy
	 * calls) for performance reasons - we are already holding vdc->lock
	 * so there is no extra locking overhead. We would have to explicitly
	 * grab the 'lock' mutex to update the stats if we were to do this
	 * higher up the stack in vdc_strategy() et. al.
	 */
	if (((operation == VD_OP_BREAD) || (operation == VD_OP_BWRITE)) &&
	    !(flags & VDC_OP_RESUBMIT)) {
		DTRACE_IO1(start, buf_t *, bufp);
		VD_KSTAT_WAITQ_ENTER(vdcp);
	}

	/*
	 * If the request does not expect the state to be VDC_STATE_RUNNING
	 * then we just try to populate the descriptor ring once.
	 */
	if (!(flags & VDC_OP_STATE_RUNNING)) {
		rv = vdc_populate_descriptor(vdcp, operation, addr,
		    nbytes, slice, offset, bufp, dir, flags);
		goto done;
	}

	do {
		while (vdcp->state != VDC_STATE_RUNNING) {

			/* return error if detaching */
			if (vdcp->state == VDC_STATE_DETACH) {
				rv = ENXIO;
				goto done;
			}

			/*
			 * If we are panicking and the disk is not ready then
			 * we can't send any request because we can't complete
			 * the handshake now.
			 */
			if (ddi_in_panic()) {
				rv = EIO;
				goto done;
			}

			/*
			 * If the state is faulted, notify that a new I/O is
			 * being submitted to force the system to check if any
			 * server has recovered.
			 */
			if (vdcp->state == VDC_STATE_FAILED) {
				vdcp->io_pending = B_TRUE;
				cv_signal(&vdcp->io_pending_cv);
			}

			cv_wait(&vdcp->running_cv, &vdcp->lock);

			/* if service is still faulted then fail the request */
			if (vdcp->state == VDC_STATE_FAILED) {
				rv = EIO;
				goto done;
			}
		}

	} while (vdc_populate_descriptor(vdcp, operation, addr,
	    nbytes, slice, offset, bufp, dir, flags & ~VDC_OP_RESUBMIT));

done:
	/*
	 * If this is a block read/write we update the I/O statistics kstat
	 * to indicate that this request has been placed on the queue for
	 * processing (i.e sent to the vDisk server) - iostat(1M) will
	 * report the time waiting for the vDisk server under the %b column
	 *
	 * In the case of an error we take it off the wait queue only if
	 * the I/O was not resubmited.
	 */
	if ((operation == VD_OP_BREAD) || (operation == VD_OP_BWRITE)) {
		if (rv == 0) {
			VD_KSTAT_WAITQ_TO_RUNQ(vdcp);
			DTRACE_PROBE1(send, buf_t *, bufp);
		} else {
			VD_UPDATE_ERR_STATS(vdcp, vd_transerrs);
			if (!(flags & VDC_OP_RESUBMIT)) {
				VD_KSTAT_WAITQ_EXIT(vdcp);
				DTRACE_IO1(done, buf_t *, bufp);
			}
		}
	}

	mutex_exit(&vdcp->lock);

	return (rv);
}


/*
 * Function:
 *	vdc_populate_descriptor
 *
 * Description:
 *	This routine writes the data to be transmitted to vds into the
 *	descriptor, notifies vds that the ring has been updated and
 *	then waits for the request to be processed.
 *
 * Arguments:
 *	vdcp	  - the soft state pointer
 *	operation - operation we want vds to perform (VD_OP_XXX)
 *	addr	  - address of data buf to be read/written.
 *	nbytes	  - number of bytes to read/write
 *	slice	  - the disk slice this request is for
 *	offset	  - relative disk offset
 *	bufp	  - buf of operation
 *	dir	  - direction of operation (READ/WRITE/BOTH)
 *
 * Return Codes:
 *	0
 *	EAGAIN
 *	ECONNRESET
 *	ENXIO
 */
static int
vdc_populate_descriptor(vdc_t *vdcp, int operation, caddr_t addr,
    size_t nbytes, int slice, diskaddr_t offset,
    buf_t *bufp, vio_desc_direction_t dir, int flags)
{
	vdc_local_desc_t	*local_dep = NULL; /* Local Dring Pointer */
	int			idx;		/* Index of DRing entry used */
	int			next_idx;
	vio_dring_msg_t		dmsg;
	size_t			msglen;
	int			rv;

	ASSERT(MUTEX_HELD(&vdcp->lock));
	vdcp->threads_pending++;
loop:
	DMSG(vdcp, 2, ": dring_curr_idx = %d\n", vdcp->dring_curr_idx);

	if (flags & VDC_OP_DRING_RESERVED) {
		/* use D-Ring reserved entry */
		idx = VDC_DRING_FIRST_RESV;
		local_dep = &(vdcp->local_dring[idx]);
	} else {
		/* Get next available D-Ring entry */
		idx = vdcp->dring_curr_idx;
		local_dep = &(vdcp->local_dring[idx]);

		if (!local_dep->is_free) {
			DMSG(vdcp, 2, "[%d]: dring full - waiting for space\n",
			    vdcp->instance);
			cv_wait(&vdcp->dring_free_cv, &vdcp->lock);
			if (vdcp->state == VDC_STATE_RUNNING ||
			    vdcp->state == VDC_STATE_HANDLE_PENDING) {
				goto loop;
			}
			vdcp->threads_pending--;
			return (ECONNRESET);
		}

		next_idx = idx + 1;
		if (next_idx >= vdcp->dring_len)
			next_idx = VDC_DRING_FIRST_ENTRY;
		vdcp->dring_curr_idx = next_idx;
	}

	ASSERT(local_dep->is_free);

	local_dep->operation = operation;
	local_dep->addr = addr;
	local_dep->nbytes = nbytes;
	local_dep->slice = slice;
	local_dep->offset = offset;
	local_dep->buf = bufp;
	local_dep->dir = dir;
	local_dep->flags = flags;

	local_dep->is_free = B_FALSE;

	rv = vdc_map_to_shared_dring(vdcp, idx);
	if (rv) {
		if (flags & VDC_OP_DRING_RESERVED) {
			DMSG(vdcp, 0, "[%d]: cannot bind memory - error\n",
			    vdcp->instance);
			/*
			 * We can't wait if we are using reserved slot.
			 * Free the descriptor and return.
			 */
			local_dep->is_free = B_TRUE;
			vdcp->threads_pending--;
			return (rv);
		}
		DMSG(vdcp, 0, "[%d]: cannot bind memory - waiting ..\n",
		    vdcp->instance);
		/* free the descriptor */
		local_dep->is_free = B_TRUE;
		vdcp->dring_curr_idx = idx;
		cv_wait(&vdcp->membind_cv, &vdcp->lock);
		if (vdcp->state == VDC_STATE_RUNNING ||
		    vdcp->state == VDC_STATE_HANDLE_PENDING) {
			goto loop;
		}
		vdcp->threads_pending--;
		return (ECONNRESET);
	}

	/*
	 * Send a msg with the DRing details to vds
	 */
	VIO_INIT_DRING_DATA_TAG(dmsg);
	VDC_INIT_DRING_DATA_MSG_IDS(dmsg, vdcp);
	dmsg.dring_ident = vdcp->dring_ident;
	dmsg.start_idx = idx;
	dmsg.end_idx = idx;
	vdcp->seq_num++;

	DTRACE_PROBE2(populate, int, vdcp->instance,
	    vdc_local_desc_t *, local_dep);
	DMSG(vdcp, 2, "ident=0x%lx, st=%u, end=%u, seq=%ld\n",
	    vdcp->dring_ident, dmsg.start_idx, dmsg.end_idx, dmsg.seq_num);

	/*
	 * note we're still holding the lock here to
	 * make sure the message goes out in order !!!...
	 */
	msglen = sizeof (dmsg);
	rv = vdc_send(vdcp, (caddr_t)&dmsg, &msglen);
	switch (rv) {
	case ECONNRESET:
		/*
		 * vdc_send initiates the reset on failure.
		 * Since the transaction has already been put
		 * on the local dring, it will automatically get
		 * retried when the channel is reset. Given that,
		 * it is ok to just return success even though the
		 * send failed.
		 */
		rv = 0;
		break;

	case 0: /* EOK */
		DMSG(vdcp, 1, "sent via LDC: rv=%d\n", rv);
		break;

	default:
		DMSG(vdcp, 0, "unexpected error, rv=%d\n", rv);
		rv = ENXIO;
		break;
	}

	vdcp->threads_pending--;
	return (rv);
}

/*
 * Function:
 *	vdc_do_op
 *
 * Description:
 *	Wrapper around vdc_submit_request(). Each request is associated with a
 *	buf structure. If a buf structure is provided (bufp != NULL) then the
 *	request will be submitted with that buf, and the caller can wait for
 *	completion of the request with biowait(). If a buf structure is not
 *	provided (bufp == NULL) then a buf structure is created and the function
 *	waits for the completion of the request.
 *
 *	If the flag VD_OP_STATE_RUNNING is set then vdc_submit_request() will
 *	submit the request only when the vdisk is in state VD_STATE_RUNNING.
 *	If the vdisk is not in that state then the vdc_submit_request() will
 *	wait for that state to be reached. After the request is submitted, the
 *	reply will be processed asynchronously by the vdc_process_msg_thread()
 *	thread.
 *
 *	If the flag VD_OP_STATE_RUNNING is not set then vdc_submit_request()
 *	submit the request whatever the state of the vdisk is. Then vdc_do_op()
 *	will wait for a reply message, process the reply and complete the
 *	request.
 *
 * Arguments:
 *	vdc	- the soft state pointer
 *	op	- operation we want vds to perform (VD_OP_XXX)
 *	addr	- address of data buf to be read/written.
 *	nbytes	- number of bytes to read/write
 *	slice	- the disk slice this request is for
 *	offset	- relative disk offset
 *	bufp	- buf structure associated with the request (can be NULL).
 *	dir	- direction of operation (READ/WRITE/BOTH)
 *	flags	- flags for the request.
 *
 * Return Codes:
 *	0	- the request has been succesfully submitted and completed.
 *	!= 0	- the request has failed. In that case, if a buf structure
 *		  was provided (bufp != NULL) then the B_ERROR flag is set
 *		  and the b_error field of the buf structure is set to EIO.
 */
static int
vdc_do_op(vdc_t *vdc, int op, caddr_t addr, size_t nbytes, int slice,
    diskaddr_t offset, struct buf *bufp, vio_desc_direction_t dir, int flags)
{
	vio_msg_t vio_msg;
	struct buf buf;
	int rv;

	if (bufp == NULL) {
		/*
		 * We use buf just as a convenient way to get a notification
		 * that the request is completed, so we initialize buf to the
		 * minimum we need.
		 */
		bioinit(&buf);
		buf.b_bcount = nbytes;
		buf.b_flags = B_BUSY;
		bufp = &buf;
	}

	rv = vdc_send_request(vdc, op, addr, nbytes, slice, offset, bufp,
	    dir, flags);

	if (rv != 0)
		goto done;

	/*
	 * If the request should be done in VDC_STATE_RUNNING state then the
	 * reply will be received and processed by vdc_process_msg_thread()
	 * and we just have to handle the panic case. Otherwise we have to
	 * wait for the reply message and process it.
	 */
	if (flags & VDC_OP_STATE_RUNNING) {

		if (ddi_in_panic()) {
			rv = vdc_drain_response(vdc, bufp);
			goto done;
		}

	} else {
		/* wait for the response message */
		rv = vdc_wait_for_response(vdc, &vio_msg);

		if (rv == 0)
			rv = vdc_process_data_msg(vdc, &vio_msg);

		if (rv) {
			/*
			 * If this is a block read/write we update the I/O
			 * statistics kstat to take it off the run queue.
			 * If it is a resubmit then it needs to stay in
			 * in the waitq, and it will be removed when the
			 * I/O is eventually completed or cancelled.
			 */
			mutex_enter(&vdc->lock);
			if (op == VD_OP_BREAD || op == VD_OP_BWRITE) {
				if (flags & VDC_OP_RESUBMIT) {
					VD_KSTAT_RUNQ_BACK_TO_WAITQ(vdc);
				} else {
					VD_KSTAT_RUNQ_EXIT(vdc);
					DTRACE_IO1(done, buf_t *, bufp);
				}
			}
			mutex_exit(&vdc->lock);
			goto done;
		}

	}

	if (bufp == &buf)
		rv = biowait(bufp);

done:
	if (bufp == &buf) {
		biofini(bufp);
	} else if (rv != 0) {
		bioerror(bufp, EIO);
		biodone(bufp);
	}

	return (rv);
}

/*
 * Function:
 *	vdc_do_sync_op
 *
 * Description:
 *	Wrapper around vdc_do_op that serializes requests.
 *
 * Arguments:
 *	vdcp	  - the soft state pointer
 *	operation - operation we want vds to perform (VD_OP_XXX)
 *	addr	  - address of data buf to be read/written.
 *	nbytes	  - number of bytes to read/write
 *	slice	  - the disk slice this request is for
 *	offset	  - relative disk offset
 *	dir	  - direction of operation (READ/WRITE/BOTH)
 *	rconflict - check for reservation conflict in case of failure
 *
 * rconflict should be set to B_TRUE by most callers. Callers invoking the
 * VD_OP_SCSICMD operation can set rconflict to B_FALSE if they check the
 * result of a successful operation with vdc_scsi_status().
 *
 * Return Codes:
 *	0
 *	EAGAIN
 *	EFAULT
 *	ENXIO
 *	EIO
 */
static int
vdc_do_sync_op(vdc_t *vdcp, int operation, caddr_t addr, size_t nbytes,
    int slice, diskaddr_t offset, vio_desc_direction_t dir, boolean_t rconflict)
{
	int status;
	int flags = VDC_OP_NORMAL;

	/*
	 * Grab the lock, if blocked wait until the server
	 * response causes us to wake up again.
	 */
	mutex_enter(&vdcp->lock);
	vdcp->sync_op_cnt++;
	while (vdcp->sync_op_blocked && vdcp->state != VDC_STATE_DETACH) {
		if (ddi_in_panic()) {
			/* don't block if we are panicking */
			vdcp->sync_op_cnt--;
			mutex_exit(&vdcp->lock);
			return (EIO);
		} else {
			cv_wait(&vdcp->sync_blocked_cv, &vdcp->lock);
		}
	}

	if (vdcp->state == VDC_STATE_DETACH) {
		cv_broadcast(&vdcp->sync_blocked_cv);
		vdcp->sync_op_cnt--;
		mutex_exit(&vdcp->lock);
		return (ENXIO);
	}

	/* now block anyone other thread entering after us */
	vdcp->sync_op_blocked = B_TRUE;

	mutex_exit(&vdcp->lock);

	if (!rconflict)
		flags &= ~VDC_OP_ERRCHK_CONFLICT;

	status = vdc_do_op(vdcp, operation, addr, nbytes, slice, offset,
	    NULL, dir, flags);

	mutex_enter(&vdcp->lock);

	DMSG(vdcp, 2, ": operation returned %d\n", status);

	if (vdcp->state == VDC_STATE_DETACH) {
		status = ENXIO;
	}

	vdcp->sync_op_blocked = B_FALSE;
	vdcp->sync_op_cnt--;

	/* signal the next waiting thread */
	cv_signal(&vdcp->sync_blocked_cv);

	mutex_exit(&vdcp->lock);

	return (status);
}


/*
 * Function:
 *	vdc_drain_response()
 *
 * Description:
 *	When a guest is panicking, the completion of requests needs to be
 *	handled differently because interrupts are disabled and vdc
 *	will not get messages. We have to poll for the messages instead.
 *
 *	Note: since we are panicking we don't implement	the io:::done
 *	DTrace probe or update the I/O statistics kstats.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	buf	- if buf is NULL then we drain all responses, otherwise we
 *		  poll until we receive a ACK/NACK for the specific I/O
 *		  described by buf.
 *
 * Return Code:
 *	0	- Success. If we were expecting a response to a particular
 *		  request then this means that a response has been received.
 */
static int
vdc_drain_response(vdc_t *vdc, struct buf *buf)
{
	int			rv, idx, retries;
	size_t			msglen;
	vdc_local_desc_t	*ldep = NULL;	/* Local Dring Entry Pointer */
	vio_dring_msg_t		dmsg;
	struct buf		*mbuf;
	boolean_t		ack;

	mutex_enter(&vdc->lock);

	retries = 0;
	for (;;) {
		msglen = sizeof (dmsg);
		rv = ldc_read(vdc->curr_server->ldc_handle, (caddr_t)&dmsg,
		    &msglen);
		if (rv) {
			rv = EINVAL;
			break;
		}

		/*
		 * if there are no packets wait and check again
		 */
		if ((rv == 0) && (msglen == 0)) {
			if (retries++ > vdc_dump_retries) {
				rv = EAGAIN;
				break;
			}

			drv_usecwait(vdc_usec_timeout_dump);
			continue;
		}

		/*
		 * Ignore all messages that are not ACKs/NACKs to
		 * DRing requests.
		 */
		if ((dmsg.tag.vio_msgtype != VIO_TYPE_DATA) ||
		    (dmsg.tag.vio_subtype_env != VIO_DRING_DATA)) {
			DMSG(vdc, 0, "discard pkt: type=%d sub=%d env=%d\n",
			    dmsg.tag.vio_msgtype,
			    dmsg.tag.vio_subtype,
			    dmsg.tag.vio_subtype_env);
			continue;
		}

		/*
		 * Record if the packet was ACK'ed or not. If the packet was not
		 * ACK'ed then we will just mark the request as failed; we don't
		 * want to reset the connection at this point.
		 */
		switch (dmsg.tag.vio_subtype) {
		case VIO_SUBTYPE_ACK:
			ack = B_TRUE;
			break;
		case VIO_SUBTYPE_NACK:
			ack = B_FALSE;
			break;
		default:
			continue;
		}

		idx = dmsg.start_idx;
		if (idx >= vdc->dring_len) {
			DMSG(vdc, 0, "[%d] Bogus ack data : start %d\n",
			    vdc->instance, idx);
			continue;
		}
		ldep = &vdc->local_dring[idx];
		if (ldep->dep->hdr.dstate != VIO_DESC_DONE) {
			DMSG(vdc, 0, "[%d] Entry @ %d - state !DONE %d\n",
			    vdc->instance, idx, ldep->dep->hdr.dstate);
			continue;
		}

		mbuf = ldep->buf;
		ASSERT(mbuf != NULL);
		mbuf->b_resid = mbuf->b_bcount - ldep->dep->payload.nbytes;
		bioerror(mbuf, ack ? ldep->dep->payload.status : EIO);
		biodone(mbuf);

		rv = vdc_depopulate_descriptor(vdc, idx);
		if (buf != NULL && buf == mbuf) {
			rv = 0;
			goto done;
		}

		/* if this is the last descriptor - break out of loop */
		if ((idx + 1) % vdc->dring_len == vdc->dring_curr_idx) {
			/*
			 * If we were expecting a response for a particular
			 * request then we return with an error otherwise we
			 * have successfully completed the drain.
			 */
			rv = (buf != NULL)? ESRCH: 0;
			break;
		}
	}

done:
	mutex_exit(&vdc->lock);
	DMSG(vdc, 0, "End idx=%d\n", idx);

	return (rv);
}


/*
 * Function:
 *	vdc_depopulate_descriptor()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	idx	- Index of the Descriptor Ring entry being modified
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_depopulate_descriptor(vdc_t *vdc, uint_t idx)
{
	vd_dring_entry_t *dep = NULL;		/* Dring Entry Pointer */
	vdc_local_desc_t *ldep = NULL;		/* Local Dring Entry Pointer */
	int		status = ENXIO;
	int		rv = 0;

	ASSERT(vdc != NULL);
	ASSERT(idx < vdc->dring_len);
	ldep = &vdc->local_dring[idx];
	ASSERT(ldep != NULL);
	ASSERT(MUTEX_HELD(&vdc->lock));

	DTRACE_PROBE2(depopulate, int, vdc->instance, vdc_local_desc_t *, ldep);
	DMSG(vdc, 2, ": idx = %d\n", idx);

	dep = ldep->dep;
	ASSERT(dep != NULL);
	ASSERT((dep->hdr.dstate == VIO_DESC_DONE) ||
	    (dep->payload.status == ECANCELED));

	VDC_MARK_DRING_ENTRY_FREE(vdc, idx);

	ldep->is_free = B_TRUE;
	status = dep->payload.status;
	DMSG(vdc, 2, ": is_free = %d : status = %d\n", ldep->is_free, status);

	/*
	 * If no buffers were used to transfer information to the server when
	 * populating the descriptor then no memory handles need to be unbound
	 * and we can return now.
	 */
	if (ldep->nbytes == 0) {
		cv_signal(&vdc->dring_free_cv);
		return (status);
	}

	/*
	 * If the upper layer passed in a misaligned address we copied the
	 * data into an aligned buffer before sending it to LDC - we now
	 * copy it back to the original buffer.
	 */
	if (ldep->align_addr) {
		ASSERT(ldep->addr != NULL);

		if (dep->payload.nbytes > 0)
			bcopy(ldep->align_addr, ldep->addr,
			    dep->payload.nbytes);
		kmem_free(ldep->align_addr,
		    sizeof (caddr_t) * P2ROUNDUP(ldep->nbytes, 8));
		ldep->align_addr = NULL;
	}

	rv = ldc_mem_unbind_handle(ldep->desc_mhdl);
	if (rv != 0) {
		DMSG(vdc, 0, "?[%d] unbind mhdl 0x%lx @ idx %d failed (%d)",
		    vdc->instance, ldep->desc_mhdl, idx, rv);
		/*
		 * The error returned by the vDisk server is more informative
		 * and thus has a higher priority but if it isn't set we ensure
		 * that this function returns an error.
		 */
		if (status == 0)
			status = EINVAL;
	}

	cv_signal(&vdc->membind_cv);
	cv_signal(&vdc->dring_free_cv);

	return (status);
}

/*
 * Function:
 *	vdc_populate_mem_hdl()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	idx	- Index of the Descriptor Ring entry being modified
 *	addr	- virtual address being mapped in
 *	nybtes	- number of bytes in 'addr'
 *	operation - the vDisk operation being performed (VD_OP_xxx)
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_populate_mem_hdl(vdc_t *vdcp, vdc_local_desc_t *ldep)
{
	vd_dring_entry_t	*dep = NULL;
	ldc_mem_handle_t	mhdl;
	caddr_t			vaddr;
	size_t			nbytes;
	uint8_t			perm = LDC_MEM_RW;
	uint8_t			maptype;
	int			rv = 0;
	int			i;

	ASSERT(vdcp != NULL);

	dep = ldep->dep;
	mhdl = ldep->desc_mhdl;

	switch (ldep->dir) {
	case VIO_read_dir:
		perm = LDC_MEM_W;
		break;

	case VIO_write_dir:
		perm = LDC_MEM_R;
		break;

	case VIO_both_dir:
		perm = LDC_MEM_RW;
		break;

	default:
		ASSERT(0);	/* catch bad programming in vdc */
	}

	/*
	 * LDC expects any addresses passed in to be 8-byte aligned. We need
	 * to copy the contents of any misaligned buffers to a newly allocated
	 * buffer and bind it instead (and copy the the contents back to the
	 * original buffer passed in when depopulating the descriptor)
	 */
	vaddr = ldep->addr;
	nbytes = ldep->nbytes;
	if (((uint64_t)vaddr & 0x7) != 0) {
		ASSERT(ldep->align_addr == NULL);
		ldep->align_addr =
		    kmem_alloc(sizeof (caddr_t) *
		    P2ROUNDUP(nbytes, 8), KM_SLEEP);
		DMSG(vdcp, 0, "[%d] Misaligned address %p reallocating "
		    "(buf=%p nb=%ld op=%d)\n",
		    vdcp->instance, (void *)vaddr, (void *)ldep->align_addr,
		    nbytes, ldep->operation);
		if (perm != LDC_MEM_W)
			bcopy(vaddr, ldep->align_addr, nbytes);
		vaddr = ldep->align_addr;
	}

	maptype = LDC_IO_MAP|LDC_SHADOW_MAP;
	rv = ldc_mem_bind_handle(mhdl, vaddr, P2ROUNDUP(nbytes, 8),
	    maptype, perm, &dep->payload.cookie[0], &dep->payload.ncookies);
	DMSG(vdcp, 2, "[%d] bound mem handle; ncookies=%d\n",
	    vdcp->instance, dep->payload.ncookies);
	if (rv != 0) {
		DMSG(vdcp, 0, "[%d] Failed to bind LDC memory handle "
		    "(mhdl=%p, buf=%p, err=%d)\n",
		    vdcp->instance, (void *)mhdl, (void *)vaddr, rv);
		if (ldep->align_addr) {
			kmem_free(ldep->align_addr,
			    sizeof (caddr_t) * P2ROUNDUP(nbytes, 8));
			ldep->align_addr = NULL;
		}
		return (EAGAIN);
	}

	/*
	 * Get the other cookies (if any).
	 */
	for (i = 1; i < dep->payload.ncookies; i++) {
		rv = ldc_mem_nextcookie(mhdl, &dep->payload.cookie[i]);
		if (rv != 0) {
			(void) ldc_mem_unbind_handle(mhdl);
			DMSG(vdcp, 0, "?[%d] Failed to get next cookie "
			    "(mhdl=%lx cnum=%d), err=%d",
			    vdcp->instance, mhdl, i, rv);
			if (ldep->align_addr) {
				kmem_free(ldep->align_addr,
				    sizeof (caddr_t) * ldep->nbytes);
				ldep->align_addr = NULL;
			}
			return (EAGAIN);
		}
	}

	return (rv);
}

/*
 * Interrupt handlers for messages from LDC
 */

/*
 * Function:
 *	vdc_handle_cb()
 *
 * Description:
 *
 * Arguments:
 *	event	- Type of event (LDC_EVT_xxx) that triggered the callback
 *	arg	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static uint_t
vdc_handle_cb(uint64_t event, caddr_t arg)
{
	ldc_status_t	ldc_state;
	int		rv = 0;
	vdc_server_t	*srvr = (vdc_server_t *)(void *)arg;
	vdc_t		*vdc = srvr->vdcp;

	ASSERT(vdc != NULL);

	DMSG(vdc, 1, "evt=%lx seqID=%ld\n", event, vdc->seq_num);

	/* If callback is not for the current server, ignore it */
	mutex_enter(&vdc->lock);

	if (vdc->curr_server != srvr) {
		DMSG(vdc, 0, "[%d] Ignoring event 0x%lx for port@%ld\n",
		    vdc->instance, event, srvr->id);
		mutex_exit(&vdc->lock);
		return (LDC_SUCCESS);
	}

	/*
	 * Depending on the type of event that triggered this callback,
	 * we modify the handshake state or read the data.
	 *
	 * NOTE: not done as a switch() as event could be triggered by
	 * a state change and a read request. Also the ordering	of the
	 * check for the event types is deliberate.
	 */
	if (event & LDC_EVT_UP) {
		DMSG(vdc, 0, "[%d] Received LDC_EVT_UP\n", vdc->instance);

		/* get LDC state */
		rv = ldc_status(srvr->ldc_handle, &ldc_state);
		if (rv != 0) {
			DMSG(vdc, 0, "[%d] Couldn't get LDC status %d",
			    vdc->instance, rv);
			mutex_exit(&vdc->lock);
			return (LDC_SUCCESS);
		}
		if (srvr->ldc_state != LDC_UP &&
		    ldc_state == LDC_UP) {
			/*
			 * Reset the transaction sequence numbers when
			 * LDC comes up. We then kick off the handshake
			 * negotiation with the vDisk server.
			 */
			vdc->seq_num = 1;
			vdc->seq_num_reply = 0;
			vdc->io_pending = B_TRUE;
			srvr->ldc_state = ldc_state;
			cv_signal(&vdc->initwait_cv);
			cv_signal(&vdc->io_pending_cv);
		}
	}

	if (event & LDC_EVT_READ) {
		DMSG(vdc, 1, "[%d] Received LDC_EVT_READ\n", vdc->instance);
		mutex_enter(&vdc->read_lock);
		cv_signal(&vdc->read_cv);
		vdc->read_state = VDC_READ_PENDING;
		mutex_exit(&vdc->read_lock);
		mutex_exit(&vdc->lock);

		/* that's all we have to do - no need to handle DOWN/RESET */
		return (LDC_SUCCESS);
	}

	if (event & (LDC_EVT_RESET|LDC_EVT_DOWN)) {

		DMSG(vdc, 0, "[%d] Received LDC RESET event\n", vdc->instance);

		/*
		 * Need to wake up any readers so they will
		 * detect that a reset has occurred.
		 */
		mutex_enter(&vdc->read_lock);
		if ((vdc->read_state == VDC_READ_WAITING) ||
		    (vdc->read_state == VDC_READ_RESET))
			cv_signal(&vdc->read_cv);
		vdc->read_state = VDC_READ_RESET;
		mutex_exit(&vdc->read_lock);

		/* wake up any threads waiting for connection to come up */
		if (vdc->state == VDC_STATE_INIT_WAITING) {
			vdc->state = VDC_STATE_RESETTING;
			cv_signal(&vdc->initwait_cv);
		} else if (vdc->state == VDC_STATE_FAILED) {
			vdc->io_pending = B_TRUE;
			cv_signal(&vdc->io_pending_cv);
		}

	}

	mutex_exit(&vdc->lock);

	if (event & ~(LDC_EVT_UP | LDC_EVT_RESET | LDC_EVT_DOWN | LDC_EVT_READ))
		DMSG(vdc, 0, "![%d] Unexpected LDC event (%lx) received",
		    vdc->instance, event);

	return (LDC_SUCCESS);
}

/*
 * Function:
 *	vdc_wait_for_response()
 *
 * Description:
 *	Block waiting for a response from the server. If there is
 *	no data the thread block on the read_cv that is signalled
 *	by the callback when an EVT_READ occurs.
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_wait_for_response(vdc_t *vdcp, vio_msg_t *msgp)
{
	size_t		nbytes = sizeof (*msgp);
	int		status;

	ASSERT(vdcp != NULL);

	DMSG(vdcp, 1, "[%d] Entered\n", vdcp->instance);

	status = vdc_recv(vdcp, msgp, &nbytes);
	DMSG(vdcp, 3, "vdc_read() done.. status=0x%x size=0x%x\n",
	    status, (int)nbytes);
	if (status) {
		DMSG(vdcp, 0, "?[%d] Error %d reading LDC msg\n",
		    vdcp->instance, status);
		return (status);
	}

	if (nbytes < sizeof (vio_msg_tag_t)) {
		DMSG(vdcp, 0, "?[%d] Expect %lu bytes; recv'd %lu\n",
		    vdcp->instance, sizeof (vio_msg_tag_t), nbytes);
		return (ENOMSG);
	}

	DMSG(vdcp, 2, "[%d] (%x/%x/%x)\n", vdcp->instance,
	    msgp->tag.vio_msgtype,
	    msgp->tag.vio_subtype,
	    msgp->tag.vio_subtype_env);

	/*
	 * Verify the Session ID of the message
	 *
	 * Every message after the Version has been negotiated should
	 * have the correct session ID set.
	 */
	if ((msgp->tag.vio_sid != vdcp->session_id) &&
	    (msgp->tag.vio_subtype_env != VIO_VER_INFO)) {
		DMSG(vdcp, 0, "[%d] Invalid SID: received 0x%x, "
		    "expected 0x%lx [seq num %lx @ %d]",
		    vdcp->instance, msgp->tag.vio_sid,
		    vdcp->session_id,
		    ((vio_dring_msg_t *)msgp)->seq_num,
		    ((vio_dring_msg_t *)msgp)->start_idx);
		return (ENOMSG);
	}
	return (0);
}


/*
 * Function:
 *	vdc_resubmit_backup_dring()
 *
 * Description:
 *	Resubmit each descriptor in the backed up dring to
 *	vDisk server. The Dring was backed up during connection
 *	reset.
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_resubmit_backup_dring(vdc_t *vdcp)
{
	int		processed = 0;
	int		count;
	int		b_idx;
	int		rv = 0;
	int		dring_size;
	vdc_local_desc_t	*curr_ldep;

	ASSERT(MUTEX_NOT_HELD(&vdcp->lock));
	ASSERT(vdcp->state == VDC_STATE_HANDLE_PENDING);

	if (vdcp->local_dring_backup == NULL) {
		/* the pending requests have already been processed */
		return (0);
	}

	DMSG(vdcp, 1, "restoring pending dring entries (len=%d, tail=%d)\n",
	    vdcp->local_dring_backup_len, vdcp->local_dring_backup_tail);

	/*
	 * Walk the backup copy of the local descriptor ring and
	 * resubmit all the outstanding transactions.
	 */
	b_idx = vdcp->local_dring_backup_tail;
	for (count = 0; count < vdcp->local_dring_backup_len; count++) {

		curr_ldep = &(vdcp->local_dring_backup[b_idx]);

		/* only resubmit outstanding transactions */
		if (!curr_ldep->is_free) {

			DMSG(vdcp, 1, "resubmitting entry idx=%x\n", b_idx);

			rv = vdc_do_op(vdcp, curr_ldep->operation,
			    curr_ldep->addr, curr_ldep->nbytes,
			    curr_ldep->slice, curr_ldep->offset,
			    curr_ldep->buf, curr_ldep->dir,
			    (curr_ldep->flags & ~VDC_OP_STATE_RUNNING) |
			    VDC_OP_RESUBMIT);

			if (rv) {
				DMSG(vdcp, 1, "[%d] resubmit entry %d failed\n",
				    vdcp->instance, b_idx);
				goto done;
			}

			/*
			 * Mark this entry as free so that we will not resubmit
			 * this "done" request again, if we were to use the same
			 * backup_dring again in future. This could happen when
			 * a reset happens while processing the backup_dring.
			 */
			curr_ldep->is_free = B_TRUE;
			processed++;
		}

		/* get the next element to submit */
		if (++b_idx >= vdcp->local_dring_backup_len)
			b_idx = 0;
	}

	/* all done - now clear up pending dring copy */
	dring_size = vdcp->local_dring_backup_len *
	    sizeof (vdcp->local_dring_backup[0]);

	(void) kmem_free(vdcp->local_dring_backup, dring_size);

	vdcp->local_dring_backup = NULL;

done:
	DTRACE_PROBE2(processed, int, processed, vdc_t *, vdcp);

	return (rv);
}

/*
 * Function:
 *	vdc_cancel_backup_dring
 *
 * Description:
 *	Cancel each descriptor in the backed up dring to vDisk server.
 *	The Dring was backed up during connection reset.
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	None
 */
void
vdc_cancel_backup_dring(vdc_t *vdcp)
{
	vdc_local_desc_t *ldep;
	struct buf	*bufp;
	int		count;
	int		b_idx;
	int		dring_size;
	int		cancelled = 0;

	ASSERT(MUTEX_HELD(&vdcp->lock));
	ASSERT(vdcp->state == VDC_STATE_FAILED);

	if (vdcp->local_dring_backup == NULL) {
		/* the pending requests have already been processed */
		return;
	}

	DMSG(vdcp, 1, "cancelling pending dring entries (len=%d, tail=%d)\n",
	    vdcp->local_dring_backup_len, vdcp->local_dring_backup_tail);

	/*
	 * Walk the backup copy of the local descriptor ring and
	 * cancel all the outstanding transactions.
	 */
	b_idx = vdcp->local_dring_backup_tail;
	for (count = 0; count < vdcp->local_dring_backup_len; count++) {

		ldep = &(vdcp->local_dring_backup[b_idx]);

		/* only cancel outstanding transactions */
		if (!ldep->is_free) {

			DMSG(vdcp, 1, "cancelling entry idx=%x\n", b_idx);
			cancelled++;

			/*
			 * All requests have already been cleared from the
			 * local descriptor ring and the LDC channel has been
			 * reset so we will never get any reply for these
			 * requests. Now we just have to notify threads waiting
			 * for replies that the request has failed.
			 */
			bufp = ldep->buf;
			ASSERT(bufp != NULL);
			bufp->b_resid = bufp->b_bcount;
			if (ldep->operation == VD_OP_BREAD ||
			    ldep->operation == VD_OP_BWRITE) {
				VD_UPDATE_ERR_STATS(vdcp, vd_softerrs);
				VD_KSTAT_WAITQ_EXIT(vdcp);
				DTRACE_IO1(done, buf_t *, bufp);
			}
			bioerror(bufp, EIO);
			biodone(bufp);
		}

		/* get the next element to cancel */
		if (++b_idx >= vdcp->local_dring_backup_len)
			b_idx = 0;
	}

	/* all done - now clear up pending dring copy */
	dring_size = vdcp->local_dring_backup_len *
	    sizeof (vdcp->local_dring_backup[0]);

	(void) kmem_free(vdcp->local_dring_backup, dring_size);

	vdcp->local_dring_backup = NULL;

	DTRACE_PROBE2(cancelled, int, cancelled, vdc_t *, vdcp);
}

/*
 * Function:
 *	vdc_connection_timeout
 *
 * Description:
 *	This function is invoked if the timeout set to establish the connection
 *	with vds expires. This will happen if we spend too much time in the
 *	VDC_STATE_INIT_WAITING, VDC_STATE_NEGOTIATE or VDC_STATE_HANDLE_PENDING
 *	states.
 *
 * Arguments:
 *	arg	- argument of the timeout function actually a soft state
 *		  pointer for the instance of the device driver.
 *
 * Return Code:
 *	None
 */
void
vdc_connection_timeout(void *arg)
{
	vdc_t		*vdcp = (vdc_t *)arg;

	mutex_enter(&vdcp->lock);

	vdcp->ctimeout_reached = B_TRUE;

	mutex_exit(&vdcp->lock);
}

/*
 * Function:
 *	vdc_backup_local_dring()
 *
 * Description:
 *	Backup the current dring in the event of a reset. The Dring
 *	transactions will be resubmitted to the server when the
 *	connection is restored.
 *
 * Arguments:
 *	vdcp	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	NONE
 */
static void
vdc_backup_local_dring(vdc_t *vdcp)
{
	int b_idx, count, dring_size;
	vdc_local_desc_t *curr_ldep;

	ASSERT(MUTEX_HELD(&vdcp->lock));
	ASSERT(vdcp->state == VDC_STATE_RESETTING);

	/*
	 * If the backup dring is stil around, it means
	 * that the last restore did not complete. However,
	 * since we never got back into the running state,
	 * the backup copy we have is still valid.
	 */
	if (vdcp->local_dring_backup != NULL) {
		DMSG(vdcp, 1, "reusing local descriptor ring backup "
		    "(len=%d, tail=%d)\n", vdcp->local_dring_backup_len,
		    vdcp->local_dring_backup_tail);
		return;
	}

	/*
	 * The backup dring can be NULL and the local dring may not be
	 * initialized. This can happen if we had a reset while establishing
	 * a new connection but after the connection has timed out. In that
	 * case the backup dring is NULL because the requests have been
	 * cancelled and the request occured before the local dring is
	 * initialized.
	 */
	if (!(vdcp->initialized & VDC_DRING_LOCAL))
		return;

	DMSG(vdcp, 1, "backing up the local descriptor ring (len=%d, "
	    "tail=%d)\n", vdcp->dring_len, vdcp->dring_curr_idx);

	dring_size = vdcp->dring_len * sizeof (vdcp->local_dring[0]);

	vdcp->local_dring_backup = kmem_alloc(dring_size, KM_SLEEP);
	bcopy(vdcp->local_dring, vdcp->local_dring_backup, dring_size);

	vdcp->local_dring_backup_tail = vdcp->dring_curr_idx;
	vdcp->local_dring_backup_len = vdcp->dring_len;

	/*
	 * At this point, pending read or write I/Os are recorded in the
	 * runq. We update the I/O statistics to indicate that they are now
	 * back in the waitq.
	 */
	b_idx = vdcp->local_dring_backup_tail;
	for (count = 0; count < vdcp->local_dring_backup_len; count++) {

		curr_ldep = &(vdcp->local_dring_backup[b_idx]);

		if (!curr_ldep->is_free &&
		    (curr_ldep->operation == VD_OP_BREAD ||
		    curr_ldep->operation == VD_OP_BWRITE)) {
			VD_KSTAT_RUNQ_BACK_TO_WAITQ(vdcp);
		}

		/* get the next element */
		if (++b_idx >= vdcp->local_dring_backup_len)
			b_idx = 0;
	}

}

static void
vdc_switch_server(vdc_t *vdcp)
{
	int		rv;
	vdc_server_t	*curr_server, *new_server;

	ASSERT(MUTEX_HELD(&vdcp->lock));

	/* if there is only one server return back */
	if (vdcp->num_servers == 1) {
		return;
	}

	/* Get current and next server */
	curr_server = vdcp->curr_server;
	new_server =
	    (curr_server->next) ? curr_server->next : vdcp->server_list;
	ASSERT(curr_server != new_server);

	/* bring current server's channel down */
	rv = ldc_down(curr_server->ldc_handle);
	if (rv) {
		DMSG(vdcp, 0, "[%d] Cannot bring channel down, port %ld\n",
		    vdcp->instance, curr_server->id);
		return;
	}

	/* switch the server */
	vdcp->curr_server = new_server;

	DMSG(vdcp, 0, "[%d] Switched to next vdisk server, port@%ld, ldc@%ld\n",
	    vdcp->instance, vdcp->curr_server->id, vdcp->curr_server->ldc_id);
}

static void
vdc_print_svc_status(vdc_t *vdcp)
{
	int instance;
	uint64_t ldc_id, port_id;
	vdc_service_state_t svc_state;

	ASSERT(mutex_owned(&vdcp->lock));

	svc_state = vdcp->curr_server->svc_state;

	if (vdcp->curr_server->log_state == svc_state)
		return;

	instance = vdcp->instance;
	ldc_id = vdcp->curr_server->ldc_id;
	port_id = vdcp->curr_server->id;

	switch (svc_state) {

	case VDC_SERVICE_OFFLINE:
		cmn_err(CE_CONT, "?vdisk@%d is offline\n", instance);
		break;

	case VDC_SERVICE_CONNECTED:
		cmn_err(CE_CONT, "?vdisk@%d is connected using ldc@%ld,%ld\n",
		    instance, ldc_id, port_id);
		break;

	case VDC_SERVICE_ONLINE:
		cmn_err(CE_CONT, "?vdisk@%d is online using ldc@%ld,%ld\n",
		    instance, ldc_id, port_id);
		break;

	case VDC_SERVICE_FAILED:
		cmn_err(CE_CONT, "?vdisk@%d access to service failed "
		    "using ldc@%ld,%ld\n", instance, ldc_id, port_id);
		break;

	case VDC_SERVICE_FAULTED:
		cmn_err(CE_CONT, "?vdisk@%d access to backend failed "
		    "using ldc@%ld,%ld\n", instance, ldc_id, port_id);
		break;

	default:
		ASSERT(0);
		break;
	}

	vdcp->curr_server->log_state = svc_state;
}

/*
 * Function:
 *	vdc_handshake_retry
 *
 * Description:
 *	This function indicates if the handshake should be retried or not.
 *	This depends on the lifecycle of the driver:
 *
 *	VDC_LC_ATTACHING: the handshake is retried until we have tried
 *	a handshake with each server. We don't care how far each handshake
 *	went, the goal is just to try the handshake. We want to minimize the
 *	the time spent doing the attach because this is locking the device
 *	tree.
 *
 *	VDC_LC_ONLINE_PENDING: the handshake is retried while we haven't done
 *	consecutive attribute negotiations with each server, and we haven't
 *	reached a minimum total of consecutive negotiations (hattr_min). The
 *	number of attribution negotiations determines the time spent before
 *	failing	pending I/Os if the handshake is not successful.
 *
 *	VDC_LC_ONLINE: the handshake is always retried, until we have a
 *	successful handshake with a server.
 *
 *	VDC_LC_DETACHING: N/A
 *
 * Arguments:
 *	hshake_cnt	- number of handshake attempts
 *	hattr_cnt	- number of attribute negotiation attempts
 *
 * Return Code:
 *	B_TRUE		- handshake should be retried
 *	B_FALSE		- handshake should not be retried
 */
static boolean_t
vdc_handshake_retry(vdc_t *vdcp, int hshake_cnt, int hattr_cnt)
{
	int		hattr_total = 0;
	vdc_server_t	*srvr;

	ASSERT(vdcp->lifecycle != VDC_LC_DETACHING);

	/* update handshake counters */
	vdcp->curr_server->hshake_cnt = hshake_cnt;
	vdcp->curr_server->hattr_cnt = hattr_cnt;

	/*
	 * If no attribute negotiation was done then we reset the total
	 *  number otherwise we cumulate the number.
	 */
	if (hattr_cnt == 0)
		vdcp->curr_server->hattr_total = 0;
	else
		vdcp->curr_server->hattr_total += hattr_cnt;

	/*
	 * If we are online (i.e. at least one handshake was successfully
	 * completed) then we always retry the handshake.
	 */
	if (vdcp->lifecycle == VDC_LC_ONLINE)
		return (B_TRUE);

	/*
	 * If we are attaching then we retry the handshake only if we haven't
	 * tried with all servers.
	 */
	if (vdcp->lifecycle == VDC_LC_ATTACHING) {

		for (srvr = vdcp->server_list; srvr != NULL;
		    srvr = srvr->next) {
			if (srvr->hshake_cnt == 0) {
				return (B_TRUE);
			}
		}

		return (B_FALSE);
	}

	/*
	 * Here we are in the case where we haven't completed any handshake
	 * successfully yet.
	 */
	ASSERT(vdcp->lifecycle == VDC_LC_ONLINE_PENDING);

	/*
	 * We retry the handshake if we haven't done an attribute negotiation
	 * with each server. This is to handle the case where one service domain
	 * is down.
	 */
	for (srvr = vdcp->server_list; srvr != NULL; srvr = srvr->next) {
		if (srvr->hattr_cnt == 0) {
			return (B_TRUE);
		}
		hattr_total += srvr->hattr_total;
	}

	/*
	 * We retry the handshake if we haven't reached the minimum number of
	 * attribute negotiation.
	 */
	return (hattr_total < vdcp->hattr_min);
}

/* -------------------------------------------------------------------------- */

/*
 * The following functions process the incoming messages from vds
 */

/*
 * Function:
 *      vdc_process_msg_thread()
 *
 * Description:
 *
 *	Main VDC message processing thread. Each vDisk instance
 *	consists of a copy of this thread. This thread triggers
 *	all the handshakes and data exchange with the server. It
 *	also handles all channel resets
 *
 * Arguments:
 *      vdc     - soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *      None
 */
static void
vdc_process_msg_thread(vdc_t *vdcp)
{
	boolean_t	failure_msg = B_FALSE;
	int		status;
	int		ctimeout;
	timeout_id_t	tmid = 0;
	clock_t		ldcup_timeout = 0;
	vdc_server_t	*srvr;
	vdc_service_state_t svc_state;
	int		hshake_cnt = 0;
	int		hattr_cnt = 0;

	mutex_enter(&vdcp->lock);

	ASSERT(vdcp->lifecycle == VDC_LC_ATTACHING);

	for (;;) {

#define	Q(_s)	(vdcp->state == _s) ? #_s :
		DMSG(vdcp, 3, "state = %d (%s)\n", vdcp->state,
		    Q(VDC_STATE_INIT)
		    Q(VDC_STATE_INIT_WAITING)
		    Q(VDC_STATE_NEGOTIATE)
		    Q(VDC_STATE_HANDLE_PENDING)
		    Q(VDC_STATE_FAULTED)
		    Q(VDC_STATE_FAILED)
		    Q(VDC_STATE_RUNNING)
		    Q(VDC_STATE_RESETTING)
		    Q(VDC_STATE_DETACH)
		    "UNKNOWN");
#undef Q

		switch (vdcp->state) {
		case VDC_STATE_INIT:

			/*
			 * If requested, start a timeout to check if the
			 * connection with vds is established in the
			 * specified delay. If the timeout expires, we
			 * will cancel any pending request.
			 *
			 * If some reset have occurred while establishing
			 * the connection, we already have a timeout armed
			 * and in that case we don't need to arm a new one.
			 *
			 * The same rule applies when there are multiple vds'.
			 * If either a connection cannot be established or
			 * the handshake times out, the connection thread will
			 * try another server. The 'ctimeout' will report
			 * back an error after it expires irrespective of
			 * whether the vdisk is trying to connect to just
			 * one or multiple servers.
			 */
			ctimeout = (vdc_timeout != 0)?
			    vdc_timeout : vdcp->curr_server->ctimeout;

			if (ctimeout != 0 && tmid == 0) {
				tmid = timeout(vdc_connection_timeout, vdcp,
				    ctimeout * drv_usectohz(MICROSEC));
			}

			/* Switch to STATE_DETACH if drv is detaching */
			if (vdcp->lifecycle == VDC_LC_DETACHING) {
				vdcp->state = VDC_STATE_DETACH;
				break;
			}

			/* Check if the timeout has been reached */
			if (vdcp->ctimeout_reached) {
				ASSERT(tmid != 0);
				tmid = 0;
				vdcp->state = VDC_STATE_FAILED;
				break;
			}

			/*
			 * Switch to another server when we reach the limit of
			 * the number of handshake per server or if we have done
			 * an attribute negotiation.
			 */
			if (hshake_cnt >= vdc_hshake_retries || hattr_cnt > 0) {

				if (!vdc_handshake_retry(vdcp, hshake_cnt,
				    hattr_cnt)) {
					DMSG(vdcp, 0, "[%d] too many "
					    "handshakes", vdcp->instance);
					vdcp->state = VDC_STATE_FAILED;
					break;
				}

				vdc_switch_server(vdcp);

				hshake_cnt = 0;
				hattr_cnt = 0;
			}

			hshake_cnt++;

			/* Bring up connection with vds via LDC */
			status = vdc_start_ldc_connection(vdcp);
			if (status != EINVAL) {
				vdcp->state = VDC_STATE_INIT_WAITING;
			} else {
				vdcp->curr_server->svc_state =
				    VDC_SERVICE_FAILED;
				vdc_print_svc_status(vdcp);
			}
			break;

		case VDC_STATE_INIT_WAITING:

			/* if channel is UP, start negotiation */
			if (vdcp->curr_server->ldc_state == LDC_UP) {
				vdcp->state = VDC_STATE_NEGOTIATE;
				break;
			}

			/*
			 * Wait for LDC_UP. If it times out and we have multiple
			 * servers then we will retry using a different server.
			 */
			ldcup_timeout = ddi_get_lbolt() + (vdc_ldcup_timeout *
			    drv_usectohz(MICROSEC));
			status = cv_timedwait(&vdcp->initwait_cv, &vdcp->lock,
			    ldcup_timeout);
			if (status == -1 &&
			    vdcp->state == VDC_STATE_INIT_WAITING &&
			    vdcp->curr_server->ldc_state != LDC_UP) {
				/* timed out & still waiting */
				vdcp->curr_server->svc_state =
				    VDC_SERVICE_FAILED;
				vdc_print_svc_status(vdcp);
				vdcp->state = VDC_STATE_INIT;
				break;
			}

			if (vdcp->state != VDC_STATE_INIT_WAITING) {
				DMSG(vdcp, 0,
				    "state moved to %d out from under us...\n",
				    vdcp->state);
			}
			break;

		case VDC_STATE_NEGOTIATE:
			switch (status = vdc_ver_negotiation(vdcp)) {
			case 0:
				break;
			default:
				DMSG(vdcp, 0, "ver negotiate failed (%d)..\n",
				    status);
				goto reset;
			}

			hattr_cnt++;

			switch (status = vdc_attr_negotiation(vdcp)) {
			case 0:
				break;
			default:
				DMSG(vdcp, 0, "attr negotiate failed (%d)..\n",
				    status);
				goto reset;
			}

			switch (status = vdc_dring_negotiation(vdcp)) {
			case 0:
				break;
			default:
				DMSG(vdcp, 0, "dring negotiate failed (%d)..\n",
				    status);
				goto reset;
			}

			switch (status = vdc_rdx_exchange(vdcp)) {
			case 0:
				vdcp->state = VDC_STATE_HANDLE_PENDING;
				goto done;
			default:
				DMSG(vdcp, 0, "RDX xchg failed ..(%d)\n",
				    status);
				goto reset;
			}
reset:
			DMSG(vdcp, 0, "negotiation failed: resetting (%d)\n",
			    status);
			vdcp->state = VDC_STATE_RESETTING;
			vdcp->self_reset = B_TRUE;
			vdcp->curr_server->svc_state = VDC_SERVICE_FAILED;
			vdc_print_svc_status(vdcp);
done:
			DMSG(vdcp, 0, "negotiation complete (state=0x%x)...\n",
			    vdcp->state);
			break;

		case VDC_STATE_HANDLE_PENDING:

			DMSG(vdcp, 0, "[%d] connection to service domain is up",
			    vdcp->instance);
			vdcp->curr_server->svc_state = VDC_SERVICE_CONNECTED;

			mutex_exit(&vdcp->lock);

			/*
			 * If we have multiple servers, check that the backend
			 * is effectively available before resubmitting any IO.
			 */
			if (vdcp->num_servers > 1 &&
			    vdc_eio_check(vdcp, 0) != 0) {
				mutex_enter(&vdcp->lock);
				vdcp->curr_server->svc_state =
				    VDC_SERVICE_FAULTED;
				vdcp->state = VDC_STATE_FAULTED;
				break;
			}

			if (tmid != 0) {
				(void) untimeout(tmid);
				tmid = 0;
				vdcp->ctimeout_reached = B_FALSE;
			}

			/*
			 * Setup devid
			 */
			(void) vdc_setup_devid(vdcp);

			status = vdc_resubmit_backup_dring(vdcp);

			mutex_enter(&vdcp->lock);

			if (status) {
				vdcp->state = VDC_STATE_RESETTING;
				vdcp->self_reset = B_TRUE;
				vdcp->curr_server->svc_state =
				    VDC_SERVICE_FAILED;
				vdc_print_svc_status(vdcp);
			} else {
				vdcp->state = VDC_STATE_RUNNING;
			}
			break;

		case VDC_STATE_FAULTED:
			/*
			 * Server is faulted because the backend is unavailable.
			 * If all servers are faulted then we mark the service
			 * as failed, otherwise we reset to switch to another
			 * server.
			 */
			vdc_print_svc_status(vdcp);

			/* check if all servers are faulted */
			for (srvr = vdcp->server_list; srvr != NULL;
			    srvr = srvr->next) {
				svc_state = srvr->svc_state;
				if (svc_state != VDC_SERVICE_FAULTED)
					break;
			}

			if (srvr != NULL) {
				vdcp->state = VDC_STATE_RESETTING;
				vdcp->self_reset = B_TRUE;
			} else {
				vdcp->state = VDC_STATE_FAILED;
			}
			break;

		case VDC_STATE_FAILED:
			/*
			 * We reach this state when we are unable to access the
			 * backend from any server, either because of a maximum
			 * connection retries or timeout, or because the backend
			 * is unavailable.
			 *
			 * Then we cancel the backup DRing so that errors get
			 * reported and we wait for a new I/O before attempting
			 * another connection.
			 */

			cmn_err(CE_NOTE, "vdisk@%d disk access failed",
			    vdcp->instance);
			failure_msg = B_TRUE;

			if (vdcp->lifecycle == VDC_LC_ATTACHING) {
				vdcp->lifecycle = VDC_LC_ONLINE_PENDING;
				vdcp->hattr_min = vdc_hattr_min_initial;
			} else {
				vdcp->hattr_min = vdc_hattr_min;
			}

			/* cancel any timeout */
			if (tmid != 0) {
				(void) untimeout(tmid);
				tmid = 0;
			}

			/* cancel pending I/Os */
			cv_broadcast(&vdcp->running_cv);
			vdc_cancel_backup_dring(vdcp);

			/* wait for new I/O */
			while (!vdcp->io_pending)
				cv_wait(&vdcp->io_pending_cv, &vdcp->lock);

			/*
			 * There's a new IO pending. Try to re-establish a
			 * connection. Mark all services as offline, so that
			 * we don't stop again before having retried all
			 * servers.
			 */
			for (srvr = vdcp->server_list; srvr != NULL;
			    srvr = srvr->next) {
				srvr->svc_state = VDC_SERVICE_OFFLINE;
				srvr->hshake_cnt = 0;
				srvr->hattr_cnt = 0;
				srvr->hattr_total = 0;
			}

			/* reset variables */
			hshake_cnt = 0;
			hattr_cnt = 0;
			vdcp->ctimeout_reached = B_FALSE;

			vdcp->state = VDC_STATE_RESETTING;
			vdcp->self_reset = B_TRUE;
			break;

		/* enter running state */
		case VDC_STATE_RUNNING:

			if (vdcp->lifecycle == VDC_LC_DETACHING) {
				vdcp->state = VDC_STATE_DETACH;
				break;
			}

			vdcp->lifecycle = VDC_LC_ONLINE;

			if (failure_msg) {
				cmn_err(CE_NOTE, "vdisk@%d disk access "
				    "recovered", vdcp->instance);
				failure_msg = B_FALSE;
			}

			/*
			 * Signal anyone waiting for the connection
			 * to come on line.
			 */
			cv_broadcast(&vdcp->running_cv);

			/* backend has to be checked after reset */
			if (vdcp->failfast_interval != 0 ||
			    vdcp->num_servers > 1)
				cv_signal(&vdcp->eio_cv);

			/* ownership is lost during reset */
			if (vdcp->ownership & VDC_OWNERSHIP_WANTED)
				vdcp->ownership |= VDC_OWNERSHIP_RESET;
			cv_signal(&vdcp->ownership_cv);

			vdcp->curr_server->svc_state = VDC_SERVICE_ONLINE;
			vdc_print_svc_status(vdcp);

			mutex_exit(&vdcp->lock);

			for (;;) {
				vio_msg_t msg;
				status = vdc_wait_for_response(vdcp, &msg);
				if (status) break;

				DMSG(vdcp, 1, "[%d] new pkt(s) available\n",
				    vdcp->instance);
				status = vdc_process_data_msg(vdcp, &msg);
				if (status) {
					DMSG(vdcp, 1, "[%d] process_data_msg "
					    "returned err=%d\n", vdcp->instance,
					    status);
					break;
				}

			}

			mutex_enter(&vdcp->lock);

			/* all servers are now offline */
			for (srvr = vdcp->server_list; srvr != NULL;
			    srvr = srvr->next) {
				srvr->svc_state = VDC_SERVICE_OFFLINE;
				srvr->log_state = VDC_SERVICE_NONE;
				srvr->hshake_cnt = 0;
				srvr->hattr_cnt = 0;
				srvr->hattr_total = 0;
			}

			hshake_cnt = 0;
			hattr_cnt = 0;

			vdc_print_svc_status(vdcp);

			vdcp->state = VDC_STATE_RESETTING;
			vdcp->self_reset = B_TRUE;
			break;

		case VDC_STATE_RESETTING:
			/*
			 * When we reach this state, we either come from the
			 * VDC_STATE_RUNNING state and we can have pending
			 * request but no timeout is armed; or we come from
			 * the VDC_STATE_INIT_WAITING, VDC_NEGOTIATE or
			 * VDC_HANDLE_PENDING state and there is no pending
			 * request or pending requests have already been copied
			 * into the backup dring. So we can safely keep the
			 * connection timeout armed while we are in this state.
			 */

			DMSG(vdcp, 0, "Initiating channel reset "
			    "(pending = %d)\n", (int)vdcp->threads_pending);

			if (vdcp->self_reset) {
				DMSG(vdcp, 0,
				    "[%d] calling stop_ldc_connection.\n",
				    vdcp->instance);
				status = vdc_stop_ldc_connection(vdcp);
				vdcp->self_reset = B_FALSE;
			}

			/*
			 * Wait for all threads currently waiting
			 * for a free dring entry to use.
			 */
			while (vdcp->threads_pending) {
				cv_broadcast(&vdcp->membind_cv);
				cv_broadcast(&vdcp->dring_free_cv);
				mutex_exit(&vdcp->lock);
				/* give the waiters enough time to wake up */
				delay(vdc_hz_min_ldc_delay);
				mutex_enter(&vdcp->lock);
			}

			ASSERT(vdcp->threads_pending == 0);

			/* Sanity check that no thread is receiving */
			ASSERT(vdcp->read_state != VDC_READ_WAITING);

			vdcp->read_state = VDC_READ_IDLE;
			vdcp->io_pending = B_FALSE;

			/*
			 * Cleanup any pending eio. These I/Os are going to
			 * be resubmitted.
			 */
			vdc_eio_unqueue(vdcp, 0, B_FALSE);

			vdc_backup_local_dring(vdcp);

			/* cleanup the old d-ring */
			vdc_destroy_descriptor_ring(vdcp);

			/* go and start again */
			vdcp->state = VDC_STATE_INIT;

			break;

		case VDC_STATE_DETACH:
			DMSG(vdcp, 0, "[%d] Reset thread exit cleanup ..\n",
			    vdcp->instance);

			/* cancel any pending timeout */
			mutex_exit(&vdcp->lock);
			if (tmid != 0) {
				(void) untimeout(tmid);
				tmid = 0;
			}
			mutex_enter(&vdcp->lock);

			/*
			 * Signal anyone waiting for connection
			 * to come online
			 */
			cv_broadcast(&vdcp->running_cv);

			while (vdcp->sync_op_cnt > 0) {
				cv_broadcast(&vdcp->sync_blocked_cv);
				mutex_exit(&vdcp->lock);
				/* give the waiters enough time to wake up */
				delay(vdc_hz_min_ldc_delay);
				mutex_enter(&vdcp->lock);
			}

			mutex_exit(&vdcp->lock);

			DMSG(vdcp, 0, "[%d] Msg processing thread exiting ..\n",
			    vdcp->instance);
			thread_exit();
			break;
		}
	}
}


/*
 * Function:
 *	vdc_process_data_msg()
 *
 * Description:
 *	This function is called by the message processing thread each time
 *	a message with a msgtype of VIO_TYPE_DATA is received. It will either
 *	be an ACK or NACK from vds[1] which vdc handles as follows.
 *		ACK	- wake up the waiting thread
 *		NACK	- resend any messages necessary
 *
 *	[1] Although the message format allows it, vds should not send a
 *	    VIO_SUBTYPE_INFO message to vdc asking it to read data; if for
 *	    some bizarre reason it does, vdc will reset the connection.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	msg	- the LDC message sent by vds
 *
 * Return Code:
 *	0	- Success.
 *	> 0	- error value returned by LDC
 */
static int
vdc_process_data_msg(vdc_t *vdcp, vio_msg_t *msg)
{
	int			status = 0;
	vio_dring_msg_t		*dring_msg;
	vdc_local_desc_t	*ldep = NULL;
	int			start, end;
	int			idx;
	int			op;

	dring_msg = (vio_dring_msg_t *)msg;

	ASSERT(msg->tag.vio_msgtype == VIO_TYPE_DATA);
	ASSERT(vdcp != NULL);

	mutex_enter(&vdcp->lock);

	/*
	 * Check to see if the message has bogus data
	 */
	idx = start = dring_msg->start_idx;
	end = dring_msg->end_idx;
	if ((start >= vdcp->dring_len) ||
	    (end >= vdcp->dring_len) || (end < -1)) {
		/*
		 * Update the I/O statistics to indicate that an error ocurred.
		 * No need to update the wait/run queues as no specific read or
		 * write request is being completed in response to this 'msg'.
		 */
		VD_UPDATE_ERR_STATS(vdcp, vd_softerrs);
		DMSG(vdcp, 0, "[%d] Bogus ACK data : start %d, end %d\n",
		    vdcp->instance, start, end);
		mutex_exit(&vdcp->lock);
		return (EINVAL);
	}

	/*
	 * Verify that the sequence number is what vdc expects.
	 */
	switch (vdc_verify_seq_num(vdcp, dring_msg)) {
	case VDC_SEQ_NUM_TODO:
		break;	/* keep processing this message */
	case VDC_SEQ_NUM_SKIP:
		mutex_exit(&vdcp->lock);
		return (0);
	case VDC_SEQ_NUM_INVALID:
		/*
		 * Update the I/O statistics to indicate that an error ocurred.
		 * No need to update the wait/run queues as no specific read or
		 * write request is being completed in response to this 'msg'.
		 */
		VD_UPDATE_ERR_STATS(vdcp, vd_softerrs);
		DMSG(vdcp, 0, "[%d] invalid seqno\n", vdcp->instance);
		mutex_exit(&vdcp->lock);
		return (ENXIO);
	}

	if (msg->tag.vio_subtype == VIO_SUBTYPE_NACK) {
		/*
		 * Update the I/O statistics to indicate that an error ocurred.
		 * No need to update the wait/run queues, this will be done by
		 * the thread calling this function.
		 */
		VD_UPDATE_ERR_STATS(vdcp, vd_softerrs);
		VDC_DUMP_DRING_MSG(dring_msg);
		DMSG(vdcp, 0, "[%d] DATA NACK\n", vdcp->instance);
		mutex_exit(&vdcp->lock);
		return (EIO);

	} else if (msg->tag.vio_subtype == VIO_SUBTYPE_INFO) {
		/*
		 * Update the I/O statistics to indicate that an error occurred.
		 * No need to update the wait/run queues as no specific read or
		 * write request is being completed in response to this 'msg'.
		 */
		VD_UPDATE_ERR_STATS(vdcp, vd_protoerrs);
		mutex_exit(&vdcp->lock);
		return (EPROTO);
	}

	DMSG(vdcp, 1, ": start %d end %d\n", start, end);
	ASSERT(start == end);

	ldep = &vdcp->local_dring[idx];

	DMSG(vdcp, 1, ": state 0x%x\n", ldep->dep->hdr.dstate);

	if (ldep->dep->hdr.dstate == VIO_DESC_DONE) {
		struct buf *bufp;

		status = ldep->dep->payload.status;

		bufp = ldep->buf;
		ASSERT(bufp != NULL);

		bufp->b_resid = bufp->b_bcount - ldep->dep->payload.nbytes;
		bioerror(bufp, status);

		if (status != 0) {
			DMSG(vdcp, 1, "I/O status=%d\n", status);
		}

		DMSG(vdcp, 1,
		    "I/O complete req=%ld bytes resp=%ld bytes\n",
		    bufp->b_bcount, ldep->dep->payload.nbytes);

		/*
		 * If the request has failed and we have multiple servers or
		 * failfast is enabled then we will have to defer the completion
		 * of the request until we have checked that the vdisk backend
		 * is effectively available (if multiple server) or that there
		 * is no reservation conflict (if failfast).
		 */
		if (status != 0 &&
		    ((vdcp->num_servers > 1 &&
		    (ldep->flags & VDC_OP_ERRCHK_BACKEND)) ||
		    (vdcp->failfast_interval != 0 &&
		    (ldep->flags & VDC_OP_ERRCHK_CONFLICT)))) {
			/*
			 * The I/O has failed and we need to check the error.
			 */
			(void) vdc_eio_queue(vdcp, idx);
		} else {
			op = ldep->operation;
			if (op == VD_OP_BREAD || op == VD_OP_BWRITE) {
				if (status == 0) {
					VD_UPDATE_IO_STATS(vdcp, op,
					    ldep->dep->payload.nbytes);
				} else {
					VD_UPDATE_ERR_STATS(vdcp, vd_softerrs);
				}
				VD_KSTAT_RUNQ_EXIT(vdcp);
				DTRACE_IO1(done, buf_t *, bufp);
			}
			(void) vdc_depopulate_descriptor(vdcp, idx);
			biodone(bufp);
		}
	}

	/* let the arrival signal propogate */
	mutex_exit(&vdcp->lock);

	/* probe gives the count of how many entries were processed */
	DTRACE_PROBE2(processed, int, 1, vdc_t *, vdcp);

	return (0);
}


/*
 * Function:
 *	vdc_handle_ver_msg()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	ver_msg	- LDC message sent by vDisk server
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_handle_ver_msg(vdc_t *vdc, vio_ver_msg_t *ver_msg)
{
	int status = 0;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	if (ver_msg->tag.vio_subtype_env != VIO_VER_INFO) {
		return (EPROTO);
	}

	if (ver_msg->dev_class != VDEV_DISK_SERVER) {
		return (EINVAL);
	}

	switch (ver_msg->tag.vio_subtype) {
	case VIO_SUBTYPE_ACK:
		/*
		 * We check to see if the version returned is indeed supported
		 * (The server may have also adjusted the minor number downwards
		 * and if so 'ver_msg' will contain the actual version agreed)
		 */
		if (vdc_is_supported_version(ver_msg)) {
			vdc->ver.major = ver_msg->ver_major;
			vdc->ver.minor = ver_msg->ver_minor;
			ASSERT(vdc->ver.major > 0);
		} else {
			status = EPROTO;
		}
		break;

	case VIO_SUBTYPE_NACK:
		/*
		 * call vdc_is_supported_version() which will return the next
		 * supported version (if any) in 'ver_msg'
		 */
		(void) vdc_is_supported_version(ver_msg);
		if (ver_msg->ver_major > 0) {
			size_t len = sizeof (*ver_msg);

			ASSERT(vdc->ver.major > 0);

			/* reset the necessary fields and resend */
			ver_msg->tag.vio_subtype = VIO_SUBTYPE_INFO;
			ver_msg->dev_class = VDEV_DISK;

			status = vdc_send(vdc, (caddr_t)ver_msg, &len);
			DMSG(vdc, 0, "[%d] Resend VER info (LDC status = %d)\n",
			    vdc->instance, status);
			if (len != sizeof (*ver_msg))
				status = EBADMSG;
		} else {
			DMSG(vdc, 0, "[%d] No common version with vDisk server",
			    vdc->instance);
			status = ENOTSUP;
		}

		break;
	case VIO_SUBTYPE_INFO:
		/*
		 * Handle the case where vds starts handshake
		 * (for now only vdc is the instigator)
		 */
		status = ENOTSUP;
		break;

	default:
		status = EINVAL;
		break;
	}

	return (status);
}

/*
 * Function:
 *	vdc_handle_attr_msg()
 *
 * Description:
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *	attr_msg	- LDC message sent by vDisk server
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_handle_attr_msg(vdc_t *vdc, vd_attr_msg_t *attr_msg)
{
	int status = 0;
	vd_disk_type_t old_type;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	if (attr_msg->tag.vio_subtype_env != VIO_ATTR_INFO) {
		return (EPROTO);
	}

	switch (attr_msg->tag.vio_subtype) {
	case VIO_SUBTYPE_ACK:
		/*
		 * We now verify the attributes sent by vds.
		 */
		if (attr_msg->vdisk_size == 0) {
			DMSG(vdc, 0, "[%d] Invalid disk size from vds",
			    vdc->instance);
			status = EINVAL;
			break;
		}

		if (attr_msg->max_xfer_sz == 0) {
			DMSG(vdc, 0, "[%d] Invalid transfer size from vds",
			    vdc->instance);
			status = EINVAL;
			break;
		}

		if (attr_msg->vdisk_size == VD_SIZE_UNKNOWN) {
			DMSG(vdc, 0, "[%d] Unknown disk size from vds",
			    vdc->instance);
			attr_msg->vdisk_size = 0;
		}

		/* update the VIO block size */
		if (attr_msg->vdisk_block_size > 0 &&
		    vdc_update_vio_bsize(vdc,
		    attr_msg->vdisk_block_size) != 0) {
			DMSG(vdc, 0, "[%d] Invalid block size (%u) from vds",
			    vdc->instance, attr_msg->vdisk_block_size);
			status = EINVAL;
			break;
		}

		/* update disk, block and transfer sizes */
		old_type = vdc->vdisk_type;
		vdc_update_size(vdc, attr_msg->vdisk_size,
		    attr_msg->vdisk_block_size, attr_msg->max_xfer_sz);
		vdc->vdisk_type = attr_msg->vdisk_type;
		vdc->operations = attr_msg->operations;
		if (vio_ver_is_supported(vdc->ver, 1, 1))
			vdc->vdisk_media = attr_msg->vdisk_media;
		else
			vdc->vdisk_media = 0;

		DMSG(vdc, 0, "[%d] max_xfer_sz: sent %lx acked %lx\n",
		    vdc->instance, vdc->max_xfer_sz, attr_msg->max_xfer_sz);
		DMSG(vdc, 0, "[%d] vdisk_block_size: sent %lx acked %x\n",
		    vdc->instance, vdc->vdisk_bsize,
		    attr_msg->vdisk_block_size);

		if ((attr_msg->xfer_mode != VIO_DRING_MODE_V1_0) ||
		    (attr_msg->vdisk_size > INT64_MAX) ||
		    (attr_msg->operations == 0) ||
		    (attr_msg->vdisk_type > VD_DISK_TYPE_DISK)) {
			DMSG(vdc, 0, "[%d] Invalid attributes from vds",
			    vdc->instance);
			status = EINVAL;
			break;
		}

		/*
		 * Now that we have received all attributes we can create a
		 * fake geometry for the disk.
		 */
		vdc_create_fake_geometry(vdc);

		/*
		 * If the disk type was previously unknown and device nodes
		 * were created then the driver would have created 8 device
		 * nodes. If we now find out that this is a single-slice disk
		 * then we need to re-create the appropriate device nodes.
		 */
		if (old_type == VD_DISK_TYPE_UNK &&
		    (vdc->initialized & VDC_MINOR) &&
		    vdc->vdisk_type == VD_DISK_TYPE_SLICE) {
			ddi_remove_minor_node(vdc->dip, NULL);
			(void) devfs_clean(ddi_get_parent(vdc->dip),
			    NULL, DV_CLEAN_FORCE);
			if (vdc_create_device_nodes(vdc) != 0) {
				DMSG(vdc, 0, "![%d] Failed to update "
				    "device nodes", vdc->instance);
			}
		}

		break;

	case VIO_SUBTYPE_NACK:
		/*
		 * vds could not handle the attributes we sent so we
		 * stop negotiating.
		 */
		status = EPROTO;
		break;

	case VIO_SUBTYPE_INFO:
		/*
		 * Handle the case where vds starts the handshake
		 * (for now; vdc is the only supported instigatior)
		 */
		status = ENOTSUP;
		break;

	default:
		status = ENOTSUP;
		break;
	}

	return (status);
}

/*
 * Function:
 *	vdc_handle_dring_reg_msg()
 *
 * Description:
 *
 * Arguments:
 *	vdc		- soft state pointer for this instance of the driver.
 *	dring_msg	- LDC message sent by vDisk server
 *
 * Return Code:
 *	0	- Success
 */
static int
vdc_handle_dring_reg_msg(vdc_t *vdc, vio_dring_reg_msg_t *dring_msg)
{
	int		status = 0;

	ASSERT(vdc != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	if (dring_msg->tag.vio_subtype_env != VIO_DRING_REG) {
		return (EPROTO);
	}

	switch (dring_msg->tag.vio_subtype) {
	case VIO_SUBTYPE_ACK:
		/* save the received dring_ident */
		vdc->dring_ident = dring_msg->dring_ident;
		DMSG(vdc, 0, "[%d] Received dring ident=0x%lx\n",
		    vdc->instance, vdc->dring_ident);
		break;

	case VIO_SUBTYPE_NACK:
		/*
		 * vds could not handle the DRing info we sent so we
		 * stop negotiating.
		 */
		DMSG(vdc, 0, "[%d] server could not register DRing\n",
		    vdc->instance);
		status = EPROTO;
		break;

	case VIO_SUBTYPE_INFO:
		/*
		 * Handle the case where vds starts handshake
		 * (for now only vdc is the instigatior)
		 */
		status = ENOTSUP;
		break;
	default:
		status = ENOTSUP;
	}

	return (status);
}

/*
 * Function:
 *	vdc_verify_seq_num()
 *
 * Description:
 *	This functions verifies that the sequence number sent back by the vDisk
 *	server with the latest message is what is expected (i.e. it is greater
 *	than the last seq num sent by the vDisk server and less than or equal
 *	to the last seq num generated by vdc).
 *
 *	It then checks the request ID to see if any requests need processing
 *	in the DRing.
 *
 * Arguments:
 *	vdc		- soft state pointer for this instance of the driver.
 *	dring_msg	- pointer to the LDC message sent by vds
 *
 * Return Code:
 *	VDC_SEQ_NUM_TODO	- Message needs to be processed
 *	VDC_SEQ_NUM_SKIP	- Message has already been processed
 *	VDC_SEQ_NUM_INVALID	- The seq numbers are so out of sync,
 *				  vdc cannot deal with them
 */
static int
vdc_verify_seq_num(vdc_t *vdc, vio_dring_msg_t *dring_msg)
{
	ASSERT(vdc != NULL);
	ASSERT(dring_msg != NULL);
	ASSERT(mutex_owned(&vdc->lock));

	/*
	 * Check to see if the messages were responded to in the correct
	 * order by vds.
	 */
	if ((dring_msg->seq_num <= vdc->seq_num_reply) ||
	    (dring_msg->seq_num > vdc->seq_num)) {
		DMSG(vdc, 0, "?[%d] Bogus sequence_number %lu: "
		    "%lu > expected <= %lu (last proc req %lu sent %lu)\n",
		    vdc->instance, dring_msg->seq_num,
		    vdc->seq_num_reply, vdc->seq_num,
		    vdc->req_id_proc, vdc->req_id);
		return (VDC_SEQ_NUM_INVALID);
	}
	vdc->seq_num_reply = dring_msg->seq_num;

	if (vdc->req_id_proc < vdc->req_id)
		return (VDC_SEQ_NUM_TODO);
	else
		return (VDC_SEQ_NUM_SKIP);
}


/*
 * Function:
 *	vdc_is_supported_version()
 *
 * Description:
 *	This routine checks if the major/minor version numbers specified in
 *	'ver_msg' are supported. If not it finds the next version that is
 *	in the supported version list 'vdc_version[]' and sets the fields in
 *	'ver_msg' to those values
 *
 * Arguments:
 *	ver_msg	- LDC message sent by vDisk server
 *
 * Return Code:
 *	B_TRUE	- Success
 *	B_FALSE	- Version not supported
 */
static boolean_t
vdc_is_supported_version(vio_ver_msg_t *ver_msg)
{
	int vdc_num_versions = sizeof (vdc_version) / sizeof (vdc_version[0]);

	for (int i = 0; i < vdc_num_versions; i++) {
		ASSERT(vdc_version[i].major > 0);
		ASSERT((i == 0) ||
		    (vdc_version[i].major < vdc_version[i-1].major));

		/*
		 * If the major versions match, adjust the minor version, if
		 * necessary, down to the highest value supported by this
		 * client. The server should support all minor versions lower
		 * than the value it sent
		 */
		if (ver_msg->ver_major == vdc_version[i].major) {
			if (ver_msg->ver_minor > vdc_version[i].minor) {
				DMSGX(0,
				    "Adjusting minor version from %u to %u",
				    ver_msg->ver_minor, vdc_version[i].minor);
				ver_msg->ver_minor = vdc_version[i].minor;
			}
			return (B_TRUE);
		}

		/*
		 * If the message contains a higher major version number, set
		 * the message's major/minor versions to the current values
		 * and return false, so this message will get resent with
		 * these values, and the server will potentially try again
		 * with the same or a lower version
		 */
		if (ver_msg->ver_major > vdc_version[i].major) {
			ver_msg->ver_major = vdc_version[i].major;
			ver_msg->ver_minor = vdc_version[i].minor;
			DMSGX(0, "Suggesting major/minor (0x%x/0x%x)\n",
			    ver_msg->ver_major, ver_msg->ver_minor);

			return (B_FALSE);
		}

		/*
		 * Otherwise, the message's major version is less than the
		 * current major version, so continue the loop to the next
		 * (lower) supported version
		 */
	}

	/*
	 * No common version was found; "ground" the version pair in the
	 * message to terminate negotiation
	 */
	ver_msg->ver_major = 0;
	ver_msg->ver_minor = 0;

	return (B_FALSE);
}
/* -------------------------------------------------------------------------- */

/*
 * DKIO(7) support
 */

typedef struct vdc_dk_arg {
	struct dk_callback	dkc;
	int			mode;
	dev_t			dev;
	vdc_t			*vdc;
} vdc_dk_arg_t;

/*
 * Function:
 *	vdc_dkio_flush_cb()
 *
 * Description:
 *	This routine is a callback for DKIOCFLUSHWRITECACHE which can be called
 *	by kernel code.
 *
 * Arguments:
 *	arg	- a pointer to a vdc_dk_arg_t structure.
 */
void
vdc_dkio_flush_cb(void *arg)
{
	struct vdc_dk_arg	*dk_arg = (struct vdc_dk_arg *)arg;
	struct dk_callback	*dkc = NULL;
	vdc_t			*vdc = NULL;
	int			rv;

	if (dk_arg == NULL) {
		cmn_err(CE_NOTE, "?[Unk] DKIOCFLUSHWRITECACHE arg is NULL\n");
		return;
	}
	dkc = &dk_arg->dkc;
	vdc = dk_arg->vdc;
	ASSERT(vdc != NULL);

	rv = vdc_do_sync_op(vdc, VD_OP_FLUSH, NULL, 0,
	    VDCPART(dk_arg->dev), 0, VIO_both_dir, B_TRUE);
	if (rv != 0) {
		DMSG(vdc, 0, "[%d] DKIOCFLUSHWRITECACHE failed %d : model %x\n",
		    vdc->instance, rv,
		    ddi_model_convert_from(dk_arg->mode & FMODELS));
	}

	/*
	 * Trigger the call back to notify the caller the the ioctl call has
	 * been completed.
	 */
	if ((dk_arg->mode & FKIOCTL) &&
	    (dkc != NULL) &&
	    (dkc->dkc_callback != NULL)) {
		ASSERT(dkc->dkc_cookie != NULL);
		(*dkc->dkc_callback)(dkc->dkc_cookie, rv);
	}

	/* Indicate that one less DKIO write flush is outstanding */
	mutex_enter(&vdc->lock);
	vdc->dkio_flush_pending--;
	ASSERT(vdc->dkio_flush_pending >= 0);
	mutex_exit(&vdc->lock);

	/* free the mem that was allocated when the callback was dispatched */
	kmem_free(arg, sizeof (vdc_dk_arg_t));
}

/*
 * Function:
 *	vdc_dkio_gapart()
 *
 * Description:
 *	This function implements the DKIOCGAPART ioctl.
 *
 * Arguments:
 *	vdc	- soft state pointer
 *	arg	- a pointer to a dk_map[NDKMAP] or dk_map32[NDKMAP] structure
 *	flag	- ioctl flags
 */
static int
vdc_dkio_gapart(vdc_t *vdc, caddr_t arg, int flag)
{
	struct dk_geom *geom;
	struct extvtoc *vtoc;
	union {
		struct dk_map map[NDKMAP];
		struct dk_map32 map32[NDKMAP];
	} data;
	int i, rv, size;

	mutex_enter(&vdc->lock);

	if ((rv = vdc_validate_geometry(vdc)) != 0) {
		mutex_exit(&vdc->lock);
		return (rv);
	}

	if (vdc->vdisk_size > VD_OLDVTOC_LIMIT) {
		mutex_exit(&vdc->lock);
		return (EOVERFLOW);
	}

	vtoc = vdc->vtoc;
	geom = vdc->geom;

	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {

		for (i = 0; i < vtoc->v_nparts; i++) {
			data.map32[i].dkl_cylno = vtoc->v_part[i].p_start /
			    (geom->dkg_nhead * geom->dkg_nsect);
			data.map32[i].dkl_nblk = vtoc->v_part[i].p_size;
		}
		size = NDKMAP * sizeof (struct dk_map32);

	} else {

		for (i = 0; i < vtoc->v_nparts; i++) {
			data.map[i].dkl_cylno = vtoc->v_part[i].p_start /
			    (geom->dkg_nhead * geom->dkg_nsect);
			data.map[i].dkl_nblk = vtoc->v_part[i].p_size;
		}
		size = NDKMAP * sizeof (struct dk_map);

	}

	mutex_exit(&vdc->lock);

	if (ddi_copyout(&data, arg, size, flag) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Function:
 *	vdc_dkio_partition()
 *
 * Description:
 *	This function implements the DKIOCPARTITION ioctl.
 *
 * Arguments:
 *	vdc	- soft state pointer
 *	arg	- a pointer to a struct partition64 structure
 *	flag	- ioctl flags
 */
static int
vdc_dkio_partition(vdc_t *vdc, caddr_t arg, int flag)
{
	struct partition64 p64;
	efi_gpt_t *gpt;
	efi_gpe_t *gpe;
	vd_efi_dev_t edev;
	uint_t partno;
	int rv;

	if (ddi_copyin(arg, &p64, sizeof (struct partition64), flag)) {
		return (EFAULT);
	}

	VDC_EFI_DEV_SET(edev, vdc, vd_process_efi_ioctl);

	if ((rv = vd_efi_alloc_and_read(&edev, &gpt, &gpe)) != 0) {
		return (rv);
	}

	partno = p64.p_partno;

	if (partno >= gpt->efi_gpt_NumberOfPartitionEntries) {
		vd_efi_free(&edev, gpt, gpe);
		return (ESRCH);
	}

	bcopy(&gpe[partno].efi_gpe_PartitionTypeGUID, &p64.p_type,
	    sizeof (struct uuid));
	p64.p_start = gpe[partno].efi_gpe_StartingLBA;
	p64.p_size = gpe[partno].efi_gpe_EndingLBA - p64.p_start + 1;

	if (ddi_copyout(&p64, arg, sizeof (struct partition64), flag)) {
		vd_efi_free(&edev, gpt, gpe);
		return (EFAULT);
	}

	vd_efi_free(&edev, gpt, gpe);
	return (0);
}

/*
 * Function:
 *	vdc_dioctl_rwcmd()
 *
 * Description:
 *	This function implements the DIOCTL_RWCMD ioctl. This ioctl is used
 *	for DKC_DIRECT disks to read or write at an absolute disk offset.
 *
 * Arguments:
 *	dev	- device
 *	arg	- a pointer to a dadkio_rwcmd or dadkio_rwcmd32 structure
 *	flag	- ioctl flags
 */
static int
vdc_dioctl_rwcmd(vdc_t *vdc, caddr_t arg, int flag)
{
	struct dadkio_rwcmd32 rwcmd32;
	struct dadkio_rwcmd rwcmd;
	struct iovec aiov;
	struct uio auio;
	int rw, status;
	struct buf *buf;

	if (ddi_model_convert_from(flag & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd32,
		    sizeof (struct dadkio_rwcmd32), flag)) {
			return (EFAULT);
		}
		rwcmd.cmd = rwcmd32.cmd;
		rwcmd.flags = rwcmd32.flags;
		rwcmd.blkaddr = (daddr_t)rwcmd32.blkaddr;
		rwcmd.buflen = rwcmd32.buflen;
		rwcmd.bufaddr = (caddr_t)(uintptr_t)rwcmd32.bufaddr;
	} else {
		if (ddi_copyin((caddr_t)arg, (caddr_t)&rwcmd,
		    sizeof (struct dadkio_rwcmd), flag)) {
			return (EFAULT);
		}
	}

	switch (rwcmd.cmd) {
	case DADKIO_RWCMD_READ:
		rw = B_READ;
		break;
	case DADKIO_RWCMD_WRITE:
		rw = B_WRITE;
		break;
	default:
		return (EINVAL);
	}

	bzero((caddr_t)&aiov, sizeof (struct iovec));
	aiov.iov_base   = rwcmd.bufaddr;
	aiov.iov_len    = rwcmd.buflen;

	bzero((caddr_t)&auio, sizeof (struct uio));
	auio.uio_iov    = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_loffset = rwcmd.blkaddr * vdc->vdisk_bsize;
	auio.uio_resid  = rwcmd.buflen;
	auio.uio_segflg = flag & FKIOCTL ? UIO_SYSSPACE : UIO_USERSPACE;

	buf = kmem_alloc(sizeof (buf_t), KM_SLEEP);
	bioinit(buf);
	/*
	 * We use the private field of buf to specify that this is an
	 * I/O using an absolute offset.
	 */
	buf->b_private = (void *)VD_SLICE_NONE;

	status = physio(vdc_strategy, buf, VD_MAKE_DEV(vdc->instance, 0),
	    rw, vdc_min, &auio);

	biofini(buf);
	kmem_free(buf, sizeof (buf_t));

	return (status);
}

/*
 * Allocate a buffer for a VD_OP_SCSICMD operation. The size of the allocated
 * buffer is returned in alloc_len.
 */
static vd_scsi_t *
vdc_scsi_alloc(int cdb_len, int sense_len, int datain_len, int dataout_len,
    int *alloc_len)
{
	vd_scsi_t *vd_scsi;
	int vd_scsi_len = VD_SCSI_SIZE;

	vd_scsi_len += P2ROUNDUP(cdb_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(sense_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(datain_len, sizeof (uint64_t));
	vd_scsi_len += P2ROUNDUP(dataout_len, sizeof (uint64_t));

	ASSERT(vd_scsi_len % sizeof (uint64_t) == 0);

	vd_scsi = kmem_zalloc(vd_scsi_len, KM_SLEEP);

	vd_scsi->cdb_len = cdb_len;
	vd_scsi->sense_len = sense_len;
	vd_scsi->datain_len = datain_len;
	vd_scsi->dataout_len = dataout_len;

	*alloc_len = vd_scsi_len;

	return (vd_scsi);
}

/*
 * Convert the status of a SCSI command to a Solaris return code.
 *
 * Arguments:
 *	vd_scsi		- The SCSI operation buffer.
 *	log_error	- indicate if an error message should be logged.
 *
 * Note that our SCSI error messages are rather primitive for the moment
 * and could be improved by decoding some data like the SCSI command and
 * the sense key.
 *
 * Return value:
 *	0		- Status is good.
 *	EACCES		- Status reports a reservation conflict.
 *	ENOTSUP		- Status reports a check condition and sense key
 *			  reports an illegal request.
 *	EIO		- Any other status.
 */
static int
vdc_scsi_status(vdc_t *vdc, vd_scsi_t *vd_scsi, boolean_t log_error)
{
	int rv;
	char path_str[MAXPATHLEN];
	char panic_str[VDC_RESV_CONFLICT_FMT_LEN + MAXPATHLEN];
	union scsi_cdb *cdb;
	struct scsi_extended_sense *sense;

	if (vd_scsi->cmd_status == STATUS_GOOD)
		/* no error */
		return (0);

	/* when the tunable vdc_scsi_log_error is true we log all errors */
	if (vdc_scsi_log_error)
		log_error = B_TRUE;

	if (log_error) {
		cmn_err(CE_WARN, "%s (vdc%d):\tError for Command: 0x%x)\n",
		    ddi_pathname(vdc->dip, path_str), vdc->instance,
		    GETCMD(VD_SCSI_DATA_CDB(vd_scsi)));
	}

	/* default returned value */
	rv = EIO;

	switch (vd_scsi->cmd_status) {

	case STATUS_CHECK:
	case STATUS_TERMINATED:
		if (log_error)
			cmn_err(CE_CONT, "\tCheck Condition Error\n");

		/* check sense buffer */
		if (vd_scsi->sense_len == 0 ||
		    vd_scsi->sense_status != STATUS_GOOD) {
			if (log_error)
				cmn_err(CE_CONT, "\tNo Sense Data Available\n");
			break;
		}

		sense = VD_SCSI_DATA_SENSE(vd_scsi);

		if (log_error) {
			cmn_err(CE_CONT, "\tSense Key:  0x%x\n"
			    "\tASC: 0x%x, ASCQ: 0x%x\n",
			    scsi_sense_key((uint8_t *)sense),
			    scsi_sense_asc((uint8_t *)sense),
			    scsi_sense_ascq((uint8_t *)sense));
		}

		if (scsi_sense_key((uint8_t *)sense) == KEY_ILLEGAL_REQUEST)
			rv = ENOTSUP;
		break;

	case STATUS_BUSY:
		if (log_error)
			cmn_err(CE_NOTE, "\tDevice Busy\n");
		break;

	case STATUS_RESERVATION_CONFLICT:
		/*
		 * If the command was PERSISTENT_RESERVATION_[IN|OUT] then
		 * reservation conflict could be due to various reasons like
		 * incorrect keys, not registered or not reserved etc. So,
		 * we should not panic in that case.
		 */
		cdb = VD_SCSI_DATA_CDB(vd_scsi);
		if (vdc->failfast_interval != 0 &&
		    cdb->scc_cmd != SCMD_PERSISTENT_RESERVE_IN &&
		    cdb->scc_cmd != SCMD_PERSISTENT_RESERVE_OUT) {
			/* failfast is enabled so we have to panic */
			(void) snprintf(panic_str, sizeof (panic_str),
			    VDC_RESV_CONFLICT_FMT_STR "%s",
			    ddi_pathname(vdc->dip, path_str));
			panic(panic_str);
		}
		if (log_error)
			cmn_err(CE_NOTE, "\tReservation Conflict\n");
		rv = EACCES;
		break;

	case STATUS_QFULL:
		if (log_error)
			cmn_err(CE_NOTE, "\tQueue Full\n");
		break;

	case STATUS_MET:
	case STATUS_INTERMEDIATE:
	case STATUS_SCSI2:
	case STATUS_INTERMEDIATE_MET:
	case STATUS_ACA_ACTIVE:
		if (log_error)
			cmn_err(CE_CONT,
			    "\tUnexpected SCSI status received: 0x%x\n",
			    vd_scsi->cmd_status);
		break;

	default:
		if (log_error)
			cmn_err(CE_CONT,
			    "\tInvalid SCSI status received: 0x%x\n",
			    vd_scsi->cmd_status);
		break;
	}

	return (rv);
}

/*
 * Implemented the USCSICMD uscsi(7I) ioctl. This ioctl is converted to
 * a VD_OP_SCSICMD operation which is sent to the vdisk server. If a SCSI
 * reset is requested (i.e. a flag USCSI_RESET* is set) then the ioctl is
 * converted to a VD_OP_RESET operation.
 */
static int
vdc_uscsi_cmd(vdc_t *vdc, caddr_t arg, int mode)
{
	struct uscsi_cmd	uscsi;
	struct uscsi_cmd32	uscsi32;
	vd_scsi_t		*vd_scsi;
	int			vd_scsi_len;
	union scsi_cdb		*cdb;
	struct scsi_extended_sense *sense;
	char			*datain, *dataout;
	size_t			cdb_len, datain_len, dataout_len, sense_len;
	int			rv;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin(arg, &uscsi32, sizeof (struct uscsi_cmd32),
		    mode) != 0)
			return (EFAULT);
		uscsi_cmd32touscsi_cmd((&uscsi32), (&uscsi));
	} else {
		if (ddi_copyin(arg, &uscsi, sizeof (struct uscsi_cmd),
		    mode) != 0)
			return (EFAULT);
	}

	/* a uscsi reset is converted to a VD_OP_RESET operation */
	if (uscsi.uscsi_flags & (USCSI_RESET | USCSI_RESET_LUN |
	    USCSI_RESET_ALL)) {
		rv = vdc_do_sync_op(vdc, VD_OP_RESET, NULL, 0, 0, 0,
		    VIO_both_dir, B_TRUE);
		return (rv);
	}

	/* cdb buffer length */
	cdb_len = uscsi.uscsi_cdblen;

	/* data in and out buffers length */
	if (uscsi.uscsi_flags & USCSI_READ) {
		datain_len = uscsi.uscsi_buflen;
		dataout_len = 0;
	} else {
		datain_len = 0;
		dataout_len = uscsi.uscsi_buflen;
	}

	/* sense buffer length */
	if (uscsi.uscsi_flags & USCSI_RQENABLE)
		sense_len = uscsi.uscsi_rqlen;
	else
		sense_len = 0;

	/* allocate buffer for the VD_SCSICMD_OP operation */
	vd_scsi = vdc_scsi_alloc(cdb_len, sense_len, datain_len, dataout_len,
	    &vd_scsi_len);

	/*
	 * The documentation of USCSI_ISOLATE and USCSI_DIAGNOSE is very vague,
	 * but basically they prevent a SCSI command from being retried in case
	 * of an error.
	 */
	if ((uscsi.uscsi_flags & USCSI_ISOLATE) ||
	    (uscsi.uscsi_flags & USCSI_DIAGNOSE))
		vd_scsi->options |= VD_SCSI_OPT_NORETRY;

	/* set task attribute */
	if (uscsi.uscsi_flags & USCSI_NOTAG) {
		vd_scsi->task_attribute = 0;
	} else {
		if (uscsi.uscsi_flags & USCSI_HEAD)
			vd_scsi->task_attribute = VD_SCSI_TASK_ACA;
		else if (uscsi.uscsi_flags & USCSI_HTAG)
			vd_scsi->task_attribute = VD_SCSI_TASK_HQUEUE;
		else if (uscsi.uscsi_flags & USCSI_OTAG)
			vd_scsi->task_attribute = VD_SCSI_TASK_ORDERED;
		else
			vd_scsi->task_attribute = 0;
	}

	/* set timeout */
	vd_scsi->timeout = uscsi.uscsi_timeout;

	/* copy-in cdb data */
	cdb = VD_SCSI_DATA_CDB(vd_scsi);
	if (ddi_copyin(uscsi.uscsi_cdb, cdb, cdb_len, mode) != 0) {
		rv = EFAULT;
		goto done;
	}

	/* keep a pointer to the sense buffer */
	sense = VD_SCSI_DATA_SENSE(vd_scsi);

	/* keep a pointer to the data-in buffer */
	datain = (char *)VD_SCSI_DATA_IN(vd_scsi);

	/* copy-in request data to the data-out buffer */
	dataout = (char *)VD_SCSI_DATA_OUT(vd_scsi);
	if (!(uscsi.uscsi_flags & USCSI_READ)) {
		if (ddi_copyin(uscsi.uscsi_bufaddr, dataout, dataout_len,
		    mode)) {
			rv = EFAULT;
			goto done;
		}
	}

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv != 0)
		goto done;

	/* update scsi status */
	uscsi.uscsi_status = vd_scsi->cmd_status;

	/* update sense data */
	if ((uscsi.uscsi_flags & USCSI_RQENABLE) &&
	    (uscsi.uscsi_status == STATUS_CHECK ||
	    uscsi.uscsi_status == STATUS_TERMINATED)) {

		uscsi.uscsi_rqstatus = vd_scsi->sense_status;

		if (uscsi.uscsi_rqstatus == STATUS_GOOD) {
			uscsi.uscsi_rqresid = uscsi.uscsi_rqlen -
			    vd_scsi->sense_len;
			if (ddi_copyout(sense, uscsi.uscsi_rqbuf,
			    vd_scsi->sense_len, mode) != 0) {
				rv = EFAULT;
				goto done;
			}
		}
	}

	/* update request data */
	if (uscsi.uscsi_status == STATUS_GOOD) {
		if (uscsi.uscsi_flags & USCSI_READ) {
			uscsi.uscsi_resid = uscsi.uscsi_buflen -
			    vd_scsi->datain_len;
			if (ddi_copyout(datain, uscsi.uscsi_bufaddr,
			    vd_scsi->datain_len, mode) != 0) {
				rv = EFAULT;
				goto done;
			}
		} else {
			uscsi.uscsi_resid = uscsi.uscsi_buflen -
			    vd_scsi->dataout_len;
		}
	}

	/* copy-out result */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		uscsi_cmdtouscsi_cmd32((&uscsi), (&uscsi32));
		if (ddi_copyout(&uscsi32, arg, sizeof (struct uscsi_cmd32),
		    mode) != 0) {
			rv = EFAULT;
			goto done;
		}
	} else {
		if (ddi_copyout(&uscsi, arg, sizeof (struct uscsi_cmd),
		    mode) != 0) {
			rv = EFAULT;
			goto done;
		}
	}

	/* get the return code from the SCSI command status */
	rv = vdc_scsi_status(vdc, vd_scsi,
	    !(uscsi.uscsi_flags & USCSI_SILENT));

done:
	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * Create a VD_OP_SCSICMD buffer for a SCSI PERSISTENT IN command.
 *
 * Arguments:
 *	cmd		- SCSI PERSISTENT IN command
 *	len		- length of the SCSI input buffer
 *	vd_scsi_len	- return the length of the allocated buffer
 *
 * Returned Value:
 *	a pointer to the allocated VD_OP_SCSICMD buffer.
 */
static vd_scsi_t *
vdc_scsi_alloc_persistent_in(uchar_t cmd, int len, int *vd_scsi_len)
{
	int cdb_len, sense_len, datain_len, dataout_len;
	vd_scsi_t *vd_scsi;
	union scsi_cdb *cdb;

	cdb_len = CDB_GROUP1;
	sense_len = sizeof (struct scsi_extended_sense);
	datain_len = len;
	dataout_len = 0;

	vd_scsi = vdc_scsi_alloc(cdb_len, sense_len, datain_len, dataout_len,
	    vd_scsi_len);

	cdb = VD_SCSI_DATA_CDB(vd_scsi);

	/* set cdb */
	cdb->scc_cmd = SCMD_PERSISTENT_RESERVE_IN;
	cdb->cdb_opaque[1] = cmd;
	FORMG1COUNT(cdb, datain_len);

	vd_scsi->timeout = vdc_scsi_timeout;

	return (vd_scsi);
}

/*
 * Create a VD_OP_SCSICMD buffer for a SCSI PERSISTENT OUT command.
 *
 * Arguments:
 *	cmd		- SCSI PERSISTENT OUT command
 *	len		- length of the SCSI output buffer
 *	vd_scsi_len	- return the length of the allocated buffer
 *
 * Returned Code:
 *	a pointer to the allocated VD_OP_SCSICMD buffer.
 */
static vd_scsi_t *
vdc_scsi_alloc_persistent_out(uchar_t cmd, int len, int *vd_scsi_len)
{
	int cdb_len, sense_len, datain_len, dataout_len;
	vd_scsi_t *vd_scsi;
	union scsi_cdb *cdb;

	cdb_len = CDB_GROUP1;
	sense_len = sizeof (struct scsi_extended_sense);
	datain_len = 0;
	dataout_len = len;

	vd_scsi = vdc_scsi_alloc(cdb_len, sense_len, datain_len, dataout_len,
	    vd_scsi_len);

	cdb = VD_SCSI_DATA_CDB(vd_scsi);

	/* set cdb */
	cdb->scc_cmd = SCMD_PERSISTENT_RESERVE_OUT;
	cdb->cdb_opaque[1] = cmd;
	FORMG1COUNT(cdb, dataout_len);

	vd_scsi->timeout = vdc_scsi_timeout;

	return (vd_scsi);
}

/*
 * Implement the MHIOCGRP_INKEYS mhd(7i) ioctl. The ioctl is converted
 * to a SCSI PERSISTENT IN READ KEYS command which is sent to the vdisk
 * server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_inkeys(vdc_t *vdc, caddr_t arg, int mode)
{
	vd_scsi_t *vd_scsi;
	mhioc_inkeys_t inkeys;
	mhioc_key_list_t klist;
	struct mhioc_inkeys32 inkeys32;
	struct mhioc_key_list32 klist32;
	sd_prin_readkeys_t *scsi_keys;
	void *user_keys;
	int vd_scsi_len;
	int listsize, listlen, rv;

	/* copyin arguments */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		rv = ddi_copyin(arg, &inkeys32, sizeof (inkeys32), mode);
		if (rv != 0)
			return (EFAULT);

		rv = ddi_copyin((caddr_t)(uintptr_t)inkeys32.li, &klist32,
		    sizeof (klist32), mode);
		if (rv != 0)
			return (EFAULT);

		listsize = klist32.listsize;
	} else {
		rv = ddi_copyin(arg, &inkeys, sizeof (inkeys), mode);
		if (rv != 0)
			return (EFAULT);

		rv = ddi_copyin(inkeys.li, &klist, sizeof (klist), mode);
		if (rv != 0)
			return (EFAULT);

		listsize = klist.listsize;
	}

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_in(SD_READ_KEYS,
	    sizeof (sd_prin_readkeys_t) - sizeof (caddr_t) +
	    (sizeof (mhioc_resv_key_t) * listsize), &vd_scsi_len);

	scsi_keys = (sd_prin_readkeys_t *)VD_SCSI_DATA_IN(vd_scsi);

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv != 0)
		goto done;

	listlen = scsi_keys->len / MHIOC_RESV_KEY_SIZE;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		inkeys32.generation = scsi_keys->generation;
		rv = ddi_copyout(&inkeys32, arg, sizeof (inkeys32), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		klist32.listlen = listlen;
		rv = ddi_copyout(&klist32, (caddr_t)(uintptr_t)inkeys32.li,
		    sizeof (klist32), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		user_keys = (caddr_t)(uintptr_t)klist32.list;
	} else {
		inkeys.generation = scsi_keys->generation;
		rv = ddi_copyout(&inkeys, arg, sizeof (inkeys), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		klist.listlen = listlen;
		rv = ddi_copyout(&klist, inkeys.li, sizeof (klist), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		user_keys = klist.list;
	}

	/* copy out keys */
	if (listlen > 0 && listsize > 0) {
		if (listsize < listlen)
			listlen = listsize;
		rv = ddi_copyout(&scsi_keys->keylist, user_keys,
		    listlen * MHIOC_RESV_KEY_SIZE, mode);
		if (rv != 0)
			rv = EFAULT;
	}

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

done:
	kmem_free(vd_scsi, vd_scsi_len);

	return (rv);
}

/*
 * Implement the MHIOCGRP_INRESV mhd(7i) ioctl. The ioctl is converted
 * to a SCSI PERSISTENT IN READ RESERVATION command which is sent to
 * the vdisk server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_inresv(vdc_t *vdc, caddr_t arg, int mode)
{
	vd_scsi_t *vd_scsi;
	mhioc_inresvs_t inresv;
	mhioc_resv_desc_list_t rlist;
	struct mhioc_inresvs32 inresv32;
	struct mhioc_resv_desc_list32 rlist32;
	mhioc_resv_desc_t mhd_resv;
	sd_prin_readresv_t *scsi_resv;
	sd_readresv_desc_t *resv;
	mhioc_resv_desc_t *user_resv;
	int vd_scsi_len;
	int listsize, listlen, i, rv;

	/* copyin arguments */
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		rv = ddi_copyin(arg, &inresv32, sizeof (inresv32), mode);
		if (rv != 0)
			return (EFAULT);

		rv = ddi_copyin((caddr_t)(uintptr_t)inresv32.li, &rlist32,
		    sizeof (rlist32), mode);
		if (rv != 0)
			return (EFAULT);

		listsize = rlist32.listsize;
	} else {
		rv = ddi_copyin(arg, &inresv, sizeof (inresv), mode);
		if (rv != 0)
			return (EFAULT);

		rv = ddi_copyin(inresv.li, &rlist, sizeof (rlist), mode);
		if (rv != 0)
			return (EFAULT);

		listsize = rlist.listsize;
	}

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_in(SD_READ_RESV,
	    sizeof (sd_prin_readresv_t) - sizeof (caddr_t) +
	    (SCSI3_RESV_DESC_LEN * listsize), &vd_scsi_len);

	scsi_resv = (sd_prin_readresv_t *)VD_SCSI_DATA_IN(vd_scsi);

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv != 0)
		goto done;

	listlen = scsi_resv->len / SCSI3_RESV_DESC_LEN;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		inresv32.generation = scsi_resv->generation;
		rv = ddi_copyout(&inresv32, arg, sizeof (inresv32), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		rlist32.listlen = listlen;
		rv = ddi_copyout(&rlist32, (caddr_t)(uintptr_t)inresv32.li,
		    sizeof (rlist32), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		user_resv = (mhioc_resv_desc_t *)(uintptr_t)rlist32.list;
	} else {
		inresv.generation = scsi_resv->generation;
		rv = ddi_copyout(&inresv, arg, sizeof (inresv), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		rlist.listlen = listlen;
		rv = ddi_copyout(&rlist, inresv.li, sizeof (rlist), mode);
		if (rv != 0) {
			rv = EFAULT;
			goto done;
		}

		user_resv = rlist.list;
	}

	/* copy out reservations */
	if (listsize > 0 && listlen > 0) {
		if (listsize < listlen)
			listlen = listsize;
		resv = (sd_readresv_desc_t *)&scsi_resv->readresv_desc;

		for (i = 0; i < listlen; i++) {
			mhd_resv.type = resv->type;
			mhd_resv.scope = resv->scope;
			mhd_resv.scope_specific_addr =
			    BE_32(resv->scope_specific_addr);
			bcopy(&resv->resvkey, &mhd_resv.key,
			    MHIOC_RESV_KEY_SIZE);

			rv = ddi_copyout(&mhd_resv, user_resv,
			    sizeof (mhd_resv), mode);
			if (rv != 0) {
				rv = EFAULT;
				goto done;
			}
			resv++;
			user_resv++;
		}
	}

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

done:
	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * Implement the MHIOCGRP_REGISTER mhd(7i) ioctl. The ioctl is converted
 * to a SCSI PERSISTENT OUT REGISTER command which is sent to the vdisk
 * server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_register(vdc_t *vdc, caddr_t arg, int mode)
{
	vd_scsi_t *vd_scsi;
	sd_prout_t *scsi_prout;
	mhioc_register_t mhd_reg;
	int vd_scsi_len, rv;

	/* copyin arguments */
	rv = ddi_copyin(arg, &mhd_reg, sizeof (mhd_reg), mode);
	if (rv != 0)
		return (EFAULT);

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_out(SD_SCSI3_REGISTER,
	    sizeof (sd_prout_t), &vd_scsi_len);

	/* set parameters */
	scsi_prout = (sd_prout_t *)VD_SCSI_DATA_OUT(vd_scsi);
	bcopy(mhd_reg.oldkey.key, scsi_prout->res_key, MHIOC_RESV_KEY_SIZE);
	bcopy(mhd_reg.newkey.key, scsi_prout->service_key, MHIOC_RESV_KEY_SIZE);
	scsi_prout->aptpl = (uchar_t)mhd_reg.aptpl;

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * Implement the MHIOCGRP_RESERVE mhd(7i) ioctl. The ioctl is converted
 * to a SCSI PERSISTENT OUT RESERVE command which is sent to the vdisk
 * server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_reserve(vdc_t *vdc, caddr_t arg, int mode)
{
	union scsi_cdb *cdb;
	vd_scsi_t *vd_scsi;
	sd_prout_t *scsi_prout;
	mhioc_resv_desc_t mhd_resv;
	int vd_scsi_len, rv;

	/* copyin arguments */
	rv = ddi_copyin(arg, &mhd_resv, sizeof (mhd_resv), mode);
	if (rv != 0)
		return (EFAULT);

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_out(SD_SCSI3_RESERVE,
	    sizeof (sd_prout_t), &vd_scsi_len);

	/* set parameters */
	cdb = VD_SCSI_DATA_CDB(vd_scsi);
	scsi_prout = (sd_prout_t *)VD_SCSI_DATA_OUT(vd_scsi);
	bcopy(mhd_resv.key.key, scsi_prout->res_key, MHIOC_RESV_KEY_SIZE);
	scsi_prout->scope_address = mhd_resv.scope_specific_addr;
	cdb->cdb_opaque[2] = mhd_resv.type;

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * Implement the MHIOCGRP_PREEMPTANDABORT mhd(7i) ioctl. The ioctl is
 * converted to a SCSI PERSISTENT OUT PREEMPT AND ABORT command which
 * is sent to the vdisk server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_preemptabort(vdc_t *vdc, caddr_t arg, int mode)
{
	union scsi_cdb *cdb;
	vd_scsi_t *vd_scsi;
	sd_prout_t *scsi_prout;
	mhioc_preemptandabort_t mhd_preempt;
	int vd_scsi_len, rv;

	/* copyin arguments */
	rv = ddi_copyin(arg, &mhd_preempt, sizeof (mhd_preempt), mode);
	if (rv != 0)
		return (EFAULT);

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_out(SD_SCSI3_PREEMPTANDABORT,
	    sizeof (sd_prout_t), &vd_scsi_len);

	/* set parameters */
	vd_scsi->task_attribute = VD_SCSI_TASK_ACA;
	cdb = VD_SCSI_DATA_CDB(vd_scsi);
	scsi_prout = (sd_prout_t *)VD_SCSI_DATA_OUT(vd_scsi);
	bcopy(mhd_preempt.resvdesc.key.key, scsi_prout->res_key,
	    MHIOC_RESV_KEY_SIZE);
	bcopy(mhd_preempt.victim_key.key, scsi_prout->service_key,
	    MHIOC_RESV_KEY_SIZE);
	scsi_prout->scope_address = mhd_preempt.resvdesc.scope_specific_addr;
	cdb->cdb_opaque[2] = mhd_preempt.resvdesc.type;

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * Implement the MHIOCGRP_REGISTERANDIGNOREKEY mhd(7i) ioctl. The ioctl
 * is converted to a SCSI PERSISTENT OUT REGISTER AND IGNORE EXISTING KEY
 * command which is sent to the vdisk server with a VD_OP_SCSICMD operation.
 */
static int
vdc_mhd_registerignore(vdc_t *vdc, caddr_t arg, int mode)
{
	vd_scsi_t *vd_scsi;
	sd_prout_t *scsi_prout;
	mhioc_registerandignorekey_t mhd_regi;
	int vd_scsi_len, rv;

	/* copyin arguments */
	rv = ddi_copyin(arg, &mhd_regi, sizeof (mhd_regi), mode);
	if (rv != 0)
		return (EFAULT);

	/* build SCSI VD_OP request */
	vd_scsi = vdc_scsi_alloc_persistent_out(SD_SCSI3_REGISTERANDIGNOREKEY,
	    sizeof (sd_prout_t), &vd_scsi_len);

	/* set parameters */
	scsi_prout = (sd_prout_t *)VD_SCSI_DATA_OUT(vd_scsi);
	bcopy(mhd_regi.newkey.key, scsi_prout->service_key,
	    MHIOC_RESV_KEY_SIZE);
	scsi_prout->aptpl = (uchar_t)mhd_regi.aptpl;

	/* submit the request */
	rv = vdc_do_sync_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, VIO_both_dir, B_FALSE);

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * This function is used to send a (simple) SCSI command and check errors.
 */
static int
vdc_eio_scsi_cmd(vdc_t *vdc, uchar_t scmd, int flags)
{
	int cdb_len, sense_len, vd_scsi_len;
	vd_scsi_t *vd_scsi;
	union scsi_cdb *cdb;
	int rv;

	ASSERT(scmd == SCMD_TEST_UNIT_READY || scmd == SCMD_WRITE_G1);

	if (scmd == SCMD_WRITE_G1)
		cdb_len = CDB_GROUP1;
	else
		cdb_len = CDB_GROUP0;

	sense_len = sizeof (struct scsi_extended_sense);

	vd_scsi = vdc_scsi_alloc(cdb_len, sense_len, 0, 0, &vd_scsi_len);

	/* set cdb */
	cdb = VD_SCSI_DATA_CDB(vd_scsi);
	cdb->scc_cmd = scmd;

	vd_scsi->timeout = vdc_scsi_timeout;

	/*
	 * Submit the request. Note the operation should not request that any
	 * error is checked because this function is precisely called when
	 * checking errors.
	 */
	ASSERT((flags & VDC_OP_ERRCHK) == 0);

	rv = vdc_do_op(vdc, VD_OP_SCSICMD, (caddr_t)vd_scsi, vd_scsi_len,
	    0, 0, NULL, VIO_both_dir, flags);

	if (rv == 0)
		rv = vdc_scsi_status(vdc, vd_scsi, B_FALSE);

	kmem_free(vd_scsi, vd_scsi_len);
	return (rv);
}

/*
 * This function is used to check if a SCSI backend is accessible. It will
 * also detect reservation conflict if failfast is enabled, and panic the
 * system in that case.
 *
 * Returned Code:
 *	0	- disk is accessible
 *	!= 0	- disk is inaccessible or unable to check if disk is accessible
 */
static int
vdc_eio_scsi_check(vdc_t *vdc, int flags)
{
	int failure = 0;
	int rv;

	/*
	 * Send a TEST UNIT READY command. The command will panic
	 * the system if it fails with a reservation conflict and
	 * failfast is enabled. If there is a reservation conflict
	 * and failfast is not enabled then the function will return
	 * EACCES. In that case, there's no problem with accessing
	 * the backend, it is just reserved.
	 */
	rv = vdc_eio_scsi_cmd(vdc, SCMD_TEST_UNIT_READY, flags);
	if (rv != 0 && rv != EACCES)
		failure++;

	/* we don't need to do more checking if failfast is not enabled */
	if (vdc->failfast_interval == 0)
		return (failure);

	/*
	 * With SPC-3 compliant devices TEST UNIT READY will succeed on
	 * a reserved device, so we also do a WRITE(10) of zero byte in
	 * order to provoke a Reservation Conflict status on those newer
	 * devices.
	 */
	if (vdc_eio_scsi_cmd(vdc, SCMD_WRITE_G1, flags) != 0)
		failure++;

	return (failure);
}

/*
 * This function is used to check if a backend is effectively accessible.
 *
 * Returned Code:
 *	0	- disk is accessible
 *	!= 0	- disk is inaccessible or unable to check if disk is accessible
 */
static int
vdc_eio_check(vdc_t *vdc, int flags)
{
	char *buffer;
	diskaddr_t blkno;
	int rv;

	ASSERT((flags & VDC_OP_ERRCHK) == 0);

	flags |= VDC_OP_DRING_RESERVED;

	if (VD_OP_SUPPORTED(vdc->operations, VD_OP_SCSICMD))
		return (vdc_eio_scsi_check(vdc, flags));

	ASSERT(vdc->failfast_interval == 0);

	/*
	 * If the backend does not support SCSI operations then we simply
	 * check if the backend is accessible by reading some data blocks.
	 * We first try to read a random block, to try to avoid getting
	 * a block that might have been cached on the service domain. Then
	 * we try the last block, and finally the first block.
	 *
	 * We return success as soon as we are able to read any block.
	 */
	buffer = kmem_alloc(vdc->vdisk_bsize, KM_SLEEP);

	if (vdc->vdisk_size > 0) {

		/* try a random block */
		(void) random_get_pseudo_bytes((uint8_t *)&blkno,
		    sizeof (diskaddr_t));
		blkno = blkno % vdc->vdisk_size;
		rv = vdc_do_op(vdc, VD_OP_BREAD, (caddr_t)buffer,
		    vdc->vdisk_bsize, VD_SLICE_NONE, blkno, NULL,
		    VIO_read_dir, flags);

		if (rv == 0)
			goto done;

		/* try the last block */
		blkno = vdc->vdisk_size - 1;
		rv = vdc_do_op(vdc, VD_OP_BREAD, (caddr_t)buffer,
		    vdc->vdisk_bsize, VD_SLICE_NONE, blkno, NULL,
		    VIO_read_dir, flags);

		if (rv == 0)
			goto done;
	}

	/* try block 0 */
	blkno = 0;
	rv = vdc_do_op(vdc, VD_OP_BREAD, (caddr_t)buffer, vdc->vdisk_bsize,
	    VD_SLICE_NONE, blkno, NULL, VIO_read_dir, flags);

done:
	kmem_free(buffer, vdc->vdisk_bsize);
	return (rv);
}

/*
 * Add a pending I/O to the eio queue. An I/O is added to this queue
 * when it has failed and failfast is enabled or the vdisk has multiple
 * servers. It will then be handled by the eio thread (vdc_eio_thread).
 * The eio queue is ordered starting with the most recent I/O added.
 */
static vdc_io_t *
vdc_eio_queue(vdc_t *vdc, int index)
{
	vdc_io_t *vio;

	ASSERT(MUTEX_HELD(&vdc->lock));

	vio = kmem_alloc(sizeof (vdc_io_t), KM_SLEEP);
	vio->vio_next = vdc->eio_queue;
	vio->vio_index = index;
	vio->vio_qtime = ddi_get_lbolt();

	vdc->eio_queue = vio;

	/* notify the eio thread that a new I/O is queued */
	cv_signal(&vdc->eio_cv);

	return (vio);
}

/*
 * Remove I/Os added before the indicated deadline from the eio queue. A
 * deadline of 0 means that all I/Os have to be unqueued. The complete_io
 * boolean specifies if unqueued I/Os should be marked as completed or not.
 */
static void
vdc_eio_unqueue(vdc_t *vdc, clock_t deadline, boolean_t complete_io)
{
	struct buf *buf;
	vdc_io_t *vio, *vio_tmp;
	int index, op;

	ASSERT(MUTEX_HELD(&vdc->lock));

	vio_tmp = NULL;
	vio = vdc->eio_queue;

	if (deadline != 0) {
		/*
		 * Skip any io queued after the deadline. The eio queue is
		 * ordered starting with the last I/O added to the queue.
		 */
		while (vio != NULL && vio->vio_qtime > deadline) {
			vio_tmp = vio;
			vio = vio->vio_next;
		}
	}

	if (vio == NULL)
		/* nothing to unqueue */
		return;

	/* update the queue */
	if (vio_tmp == NULL)
		vdc->eio_queue = NULL;
	else
		vio_tmp->vio_next = NULL;

	/*
	 * Free and complete unqueued I/Os if this was requested. All I/Os
	 * have a block I/O data transfer structure (buf) and they are
	 * completed by calling biodone().
	 */
	while (vio != NULL) {
		vio_tmp = vio->vio_next;

		if (complete_io) {
			index = vio->vio_index;
			op = vdc->local_dring[index].operation;
			buf = vdc->local_dring[index].buf;
			(void) vdc_depopulate_descriptor(vdc, index);
			ASSERT(buf->b_flags & B_ERROR);
			if (op == VD_OP_BREAD || op == VD_OP_BWRITE) {
				VD_UPDATE_ERR_STATS(vdc, vd_softerrs);
				VD_KSTAT_RUNQ_EXIT(vdc);
				DTRACE_IO1(done, buf_t *, buf);
			}
			biodone(buf);
		}

		kmem_free(vio, sizeof (vdc_io_t));
		vio = vio_tmp;
	}
}

/*
 * Error I/O Thread.  There is one eio thread for each virtual disk that
 * has multiple servers or for which failfast is enabled. Failfast can only
 * be enabled for vdisk supporting SCSI commands.
 *
 * While failfast is enabled, the eio thread sends a TEST UNIT READY
 * and a zero size WRITE(10) SCSI commands on a regular basis to check that
 * we still have access to the disk. If a command fails with a RESERVATION
 * CONFLICT error then the system will immediatly panic.
 *
 * The eio thread is also woken up when an I/O has failed. It then checks
 * the access to the disk to ensure that the I/O failure was not due to a
 * reservation conflict or to the backend been inaccessible.
 *
 */
static void
vdc_eio_thread(void *arg)
{
	int status;
	vdc_t *vdc = (vdc_t *)arg;
	clock_t starttime, timeout = drv_usectohz(vdc->failfast_interval);

	mutex_enter(&vdc->lock);

	while (vdc->failfast_interval != 0 || vdc->num_servers > 1) {
		/*
		 * Wait if there is nothing in the eio queue or if the state
		 * is not VDC_STATE_RUNNING.
		 */
		if (vdc->eio_queue == NULL || vdc->state != VDC_STATE_RUNNING) {
			if (vdc->failfast_interval != 0) {
				timeout = ddi_get_lbolt() +
				    drv_usectohz(vdc->failfast_interval);
				(void) cv_timedwait(&vdc->eio_cv, &vdc->lock,
				    timeout);
			} else {
				ASSERT(vdc->num_servers > 1);
				(void) cv_wait(&vdc->eio_cv, &vdc->lock);
			}

			if (vdc->state != VDC_STATE_RUNNING)
				continue;
		}

		mutex_exit(&vdc->lock);

		starttime = ddi_get_lbolt();

		/* check error */
		status = vdc_eio_check(vdc, VDC_OP_STATE_RUNNING);

		mutex_enter(&vdc->lock);
		/*
		 * We have dropped the lock to check the backend so we have
		 * to check that the eio thread is still enabled.
		 */
		if (vdc->failfast_interval == 0 && vdc->num_servers <= 1)
			break;

		/*
		 * If the eio queue is empty or we are not in running state
		 * anymore then there is nothing to do.
		 */
		if (vdc->state != VDC_STATE_RUNNING || vdc->eio_queue == NULL)
			continue;

		if (status == 0) {
			/*
			 * The backend access has been successfully checked,
			 * we can complete any I/O queued before the last check.
			 */
			vdc_eio_unqueue(vdc, starttime, B_TRUE);

		} else if (vdc->num_servers > 1) {
			/*
			 * The backend is inaccessible for a disk with multiple
			 * servers. So we force a reset to switch to another
			 * server. The reset will also clear the eio queue and
			 * resubmit all pending I/Os.
			 */
			mutex_enter(&vdc->read_lock);
			vdc->read_state = VDC_READ_RESET;
			cv_signal(&vdc->read_cv);
			mutex_exit(&vdc->read_lock);
		} else {
			/*
			 * There is only one path and the backend is not
			 * accessible, so I/Os are actually failing because
			 * of that. So we can complete I/O queued before the
			 * last check.
			 */
			vdc_eio_unqueue(vdc, starttime, B_TRUE);
		}
	}

	/*
	 * The thread is being stopped so we can complete any queued I/O.
	 */
	vdc_eio_unqueue(vdc, 0, B_TRUE);
	vdc->eio_thread = NULL;
	mutex_exit(&vdc->lock);
	thread_exit();
}

/*
 * Implement the MHIOCENFAILFAST mhd(7i) ioctl.
 */
static int
vdc_failfast(vdc_t *vdc, caddr_t arg, int mode)
{
	unsigned int mh_time;

	if (ddi_copyin((void *)arg, &mh_time, sizeof (int), mode))
		return (EFAULT);

	mutex_enter(&vdc->lock);
	if (mh_time != 0 && vdc->eio_thread == NULL) {
		vdc->eio_thread = thread_create(NULL, 0,
		    vdc_eio_thread, vdc, 0, &p0, TS_RUN,
		    v.v_maxsyspri - 2);
	}

	vdc->failfast_interval = ((long)mh_time) * MILLISEC;
	cv_signal(&vdc->eio_cv);
	mutex_exit(&vdc->lock);

	return (0);
}

/*
 * Implement the MHIOCTKOWN and MHIOCRELEASE mhd(7i) ioctls. These ioctls are
 * converted to VD_OP_SET_ACCESS operations.
 */
static int
vdc_access_set(vdc_t *vdc, uint64_t flags)
{
	int rv;

	/* submit owership command request */
	rv = vdc_do_sync_op(vdc, VD_OP_SET_ACCESS, (caddr_t)&flags,
	    sizeof (uint64_t), 0, 0, VIO_both_dir, B_TRUE);

	return (rv);
}

/*
 * Implement the MHIOCSTATUS mhd(7i) ioctl. This ioctl is converted to a
 * VD_OP_GET_ACCESS operation.
 */
static int
vdc_access_get(vdc_t *vdc, uint64_t *status)
{
	int rv;

	/* submit owership command request */
	rv = vdc_do_sync_op(vdc, VD_OP_GET_ACCESS, (caddr_t)status,
	    sizeof (uint64_t), 0, 0, VIO_both_dir, B_TRUE);

	return (rv);
}

/*
 * Disk Ownership Thread.
 *
 * When we have taken the ownership of a disk, this thread waits to be
 * notified when the LDC channel is reset so that it can recover the
 * ownership.
 *
 * Note that the thread handling the LDC reset (vdc_process_msg_thread())
 * can not be used to do the ownership recovery because it has to be
 * running to handle the reply message to the ownership operation.
 */
static void
vdc_ownership_thread(void *arg)
{
	vdc_t *vdc = (vdc_t *)arg;
	clock_t timeout;
	uint64_t status;

	mutex_enter(&vdc->ownership_lock);
	mutex_enter(&vdc->lock);

	while (vdc->ownership & VDC_OWNERSHIP_WANTED) {

		if ((vdc->ownership & VDC_OWNERSHIP_RESET) ||
		    !(vdc->ownership & VDC_OWNERSHIP_GRANTED)) {
			/*
			 * There was a reset so the ownership has been lost,
			 * try to recover. We do this without using the preempt
			 * option so that we don't steal the ownership from
			 * someone who has preempted us.
			 */
			DMSG(vdc, 0, "[%d] Ownership lost, recovering",
			    vdc->instance);

			vdc->ownership &= ~(VDC_OWNERSHIP_RESET |
			    VDC_OWNERSHIP_GRANTED);

			mutex_exit(&vdc->lock);

			status = vdc_access_set(vdc, VD_ACCESS_SET_EXCLUSIVE |
			    VD_ACCESS_SET_PRESERVE);

			mutex_enter(&vdc->lock);

			if (status == 0) {
				DMSG(vdc, 0, "[%d] Ownership recovered",
				    vdc->instance);
				vdc->ownership |= VDC_OWNERSHIP_GRANTED;
			} else {
				DMSG(vdc, 0, "[%d] Fail to recover ownership",
				    vdc->instance);
			}

		}

		/*
		 * If we have the ownership then we just wait for an event
		 * to happen (LDC reset), otherwise we will retry to recover
		 * after a delay.
		 */
		if (vdc->ownership & VDC_OWNERSHIP_GRANTED)
			timeout = 0;
		else
			timeout = drv_usectohz(vdc_ownership_delay);

		/* Release the ownership_lock and wait on the vdc lock */
		mutex_exit(&vdc->ownership_lock);

		if (timeout == 0)
			(void) cv_wait(&vdc->ownership_cv, &vdc->lock);
		else
			(void) cv_reltimedwait(&vdc->ownership_cv, &vdc->lock,
			    timeout, TR_CLOCK_TICK);

		mutex_exit(&vdc->lock);

		mutex_enter(&vdc->ownership_lock);
		mutex_enter(&vdc->lock);
	}

	vdc->ownership_thread = NULL;
	mutex_exit(&vdc->lock);
	mutex_exit(&vdc->ownership_lock);

	thread_exit();
}

static void
vdc_ownership_update(vdc_t *vdc, int ownership_flags)
{
	ASSERT(MUTEX_HELD(&vdc->ownership_lock));

	mutex_enter(&vdc->lock);
	vdc->ownership = ownership_flags;
	if ((vdc->ownership & VDC_OWNERSHIP_WANTED) &&
	    vdc->ownership_thread == NULL) {
		/* start ownership thread */
		vdc->ownership_thread = thread_create(NULL, 0,
		    vdc_ownership_thread, vdc, 0, &p0, TS_RUN,
		    v.v_maxsyspri - 2);
	} else {
		/* notify the ownership thread */
		cv_signal(&vdc->ownership_cv);
	}
	mutex_exit(&vdc->lock);
}

/*
 * Get the size and the block size of a virtual disk from the vdisk server.
 */
static int
vdc_get_capacity(vdc_t *vdc, size_t *dsk_size, size_t *blk_size)
{
	int rv = 0;
	size_t alloc_len;
	vd_capacity_t *vd_cap;

	ASSERT(MUTEX_NOT_HELD(&vdc->lock));

	alloc_len = P2ROUNDUP(sizeof (vd_capacity_t), sizeof (uint64_t));

	vd_cap = kmem_zalloc(alloc_len, KM_SLEEP);

	rv = vdc_do_sync_op(vdc, VD_OP_GET_CAPACITY, (caddr_t)vd_cap, alloc_len,
	    0, 0, VIO_both_dir, B_TRUE);

	*dsk_size = vd_cap->vdisk_size;
	*blk_size = vd_cap->vdisk_block_size;

	kmem_free(vd_cap, alloc_len);
	return (rv);
}

/*
 * Check the disk capacity. Disk size information is updated if size has
 * changed.
 *
 * Return 0 if the disk capacity is available, or non-zero if it is not.
 */
static int
vdc_check_capacity(vdc_t *vdc)
{
	size_t dsk_size, blk_size;
	int rv;

	/*
	 * If the vdisk does not support the VD_OP_GET_CAPACITY operation
	 * then the disk capacity has been retrieved during the handshake
	 * and there's nothing more to do here.
	 */
	if (!VD_OP_SUPPORTED(vdc->operations, VD_OP_GET_CAPACITY))
		return (0);

	if ((rv = vdc_get_capacity(vdc, &dsk_size, &blk_size)) != 0)
		return (rv);

	if (dsk_size == VD_SIZE_UNKNOWN || dsk_size == 0 || blk_size == 0)
		return (EINVAL);

	mutex_enter(&vdc->lock);
	/*
	 * First try to update the VIO block size (which is the same as the
	 * vdisk block size). If this returns an error then that means that
	 * we can not use that block size so basically the vdisk is unusable
	 * and we return an error.
	 */
	rv = vdc_update_vio_bsize(vdc, blk_size);
	if (rv == 0)
		vdc_update_size(vdc, dsk_size, blk_size, vdc->max_xfer_sz);

	mutex_exit(&vdc->lock);

	return (rv);
}

/*
 * This structure is used in the DKIO(7I) array below.
 */
typedef struct vdc_dk_ioctl {
	uint8_t		op;		/* VD_OP_XXX value */
	int		cmd;		/* Solaris ioctl operation number */
	size_t		nbytes;		/* size of structure to be copied */

	/* function to convert between vDisk and Solaris structure formats */
	int	(*convert)(vdc_t *vdc, void *vd_buf, void *ioctl_arg,
	    int mode, int dir);
} vdc_dk_ioctl_t;

/*
 * Subset of DKIO(7I) operations currently supported
 */
static vdc_dk_ioctl_t	dk_ioctl[] = {
	{VD_OP_FLUSH,		DKIOCFLUSHWRITECACHE,	0,
		vdc_null_copy_func},
	{VD_OP_GET_WCE,		DKIOCGETWCE,		sizeof (int),
		vdc_get_wce_convert},
	{VD_OP_SET_WCE,		DKIOCSETWCE,		sizeof (int),
		vdc_set_wce_convert},
	{VD_OP_GET_VTOC,	DKIOCGVTOC,		sizeof (vd_vtoc_t),
		vdc_get_vtoc_convert},
	{VD_OP_SET_VTOC,	DKIOCSVTOC,		sizeof (vd_vtoc_t),
		vdc_set_vtoc_convert},
	{VD_OP_GET_VTOC,	DKIOCGEXTVTOC,		sizeof (vd_vtoc_t),
		vdc_get_extvtoc_convert},
	{VD_OP_SET_VTOC,	DKIOCSEXTVTOC,		sizeof (vd_vtoc_t),
		vdc_set_extvtoc_convert},
	{VD_OP_GET_DISKGEOM,	DKIOCGGEOM,		sizeof (vd_geom_t),
		vdc_get_geom_convert},
	{VD_OP_GET_DISKGEOM,	DKIOCG_PHYGEOM,		sizeof (vd_geom_t),
		vdc_get_geom_convert},
	{VD_OP_GET_DISKGEOM,	DKIOCG_VIRTGEOM,	sizeof (vd_geom_t),
		vdc_get_geom_convert},
	{VD_OP_SET_DISKGEOM,	DKIOCSGEOM,		sizeof (vd_geom_t),
		vdc_set_geom_convert},
	{VD_OP_GET_EFI,		DKIOCGETEFI,		0,
		vdc_get_efi_convert},
	{VD_OP_SET_EFI,		DKIOCSETEFI,		0,
		vdc_set_efi_convert},

	/* DIOCTL_RWCMD is converted to a read or a write */
	{0, DIOCTL_RWCMD,  sizeof (struct dadkio_rwcmd), NULL},

	/* mhd(7I) non-shared multihost disks ioctls */
	{0, MHIOCTKOWN,				0, vdc_null_copy_func},
	{0, MHIOCRELEASE,			0, vdc_null_copy_func},
	{0, MHIOCSTATUS,			0, vdc_null_copy_func},
	{0, MHIOCQRESERVE,			0, vdc_null_copy_func},

	/* mhd(7I) shared multihost disks ioctls */
	{0, MHIOCGRP_INKEYS,			0, vdc_null_copy_func},
	{0, MHIOCGRP_INRESV,			0, vdc_null_copy_func},
	{0, MHIOCGRP_REGISTER,			0, vdc_null_copy_func},
	{0, MHIOCGRP_RESERVE,			0, vdc_null_copy_func},
	{0, MHIOCGRP_PREEMPTANDABORT,		0, vdc_null_copy_func},
	{0, MHIOCGRP_REGISTERANDIGNOREKEY,	0, vdc_null_copy_func},

	/* mhd(7I) failfast ioctl */
	{0, MHIOCENFAILFAST,			0, vdc_null_copy_func},

	/*
	 * These particular ioctls are not sent to the server - vdc fakes up
	 * the necessary info.
	 */
	{0, DKIOCINFO, sizeof (struct dk_cinfo), vdc_null_copy_func},
	{0, DKIOCGMEDIAINFO, sizeof (struct dk_minfo), vdc_null_copy_func},
	{0, USCSICMD,	sizeof (struct uscsi_cmd), vdc_null_copy_func},
	{0, DKIOCPARTITION, 0, vdc_null_copy_func },
	{0, DKIOCGAPART, 0, vdc_null_copy_func },
	{0, DKIOCREMOVABLE, 0, vdc_null_copy_func},
	{0, CDROMREADOFFSET, 0, vdc_null_copy_func}
};

/*
 * This function handles ioctl requests from the vd_efi_alloc_and_read()
 * function and forward them to the vdisk.
 */
static int
vd_process_efi_ioctl(void *vdisk, int cmd, uintptr_t arg)
{
	vdc_t *vdc = (vdc_t *)vdisk;
	dev_t dev;
	int rval;

	dev = makedevice(ddi_driver_major(vdc->dip),
	    VD_MAKE_DEV(vdc->instance, 0));

	return (vd_process_ioctl(dev, cmd, (caddr_t)arg, FKIOCTL, &rval));
}

/*
 * Function:
 *	vd_process_ioctl()
 *
 * Description:
 *	This routine processes disk specific ioctl calls
 *
 * Arguments:
 *	dev	- the device number
 *	cmd	- the operation [dkio(7I)] to be processed
 *	arg	- pointer to user provided structure
 *		  (contains data to be set or reference parameter for get)
 *	mode	- bit flag, indicating open settings, 32/64 bit type, etc
 *	rvalp	- pointer to return value for calling process.
 *
 * Return Code:
 *	0
 *	EFAULT
 *	ENXIO
 *	EIO
 *	ENOTSUP
 */
static int
vd_process_ioctl(dev_t dev, int cmd, caddr_t arg, int mode, int *rvalp)
{
	int		instance = VDCUNIT(dev);
	vdc_t		*vdc = NULL;
	int		rv = -1;
	int		idx = 0;		/* index into dk_ioctl[] */
	size_t		len = 0;		/* #bytes to send to vds */
	size_t		alloc_len = 0;		/* #bytes to allocate mem for */
	caddr_t		mem_p = NULL;
	size_t		nioctls = (sizeof (dk_ioctl)) / (sizeof (dk_ioctl[0]));
	vdc_dk_ioctl_t	*iop;

	vdc = ddi_get_soft_state(vdc_state, instance);
	if (vdc == NULL) {
		cmn_err(CE_NOTE, "![%d] Could not get soft state structure",
		    instance);
		return (ENXIO);
	}

	DMSG(vdc, 0, "[%d] Processing ioctl(%x) for dev %lx : model %x\n",
	    instance, cmd, dev, ddi_model_convert_from(mode & FMODELS));

	if (rvalp != NULL) {
		/* the return value of the ioctl is 0 by default */
		*rvalp = 0;
	}

	/*
	 * Validate the ioctl operation to be performed.
	 *
	 * If we have looped through the array without finding a match then we
	 * don't support this ioctl.
	 */
	for (idx = 0; idx < nioctls; idx++) {
		if (cmd == dk_ioctl[idx].cmd)
			break;
	}

	if (idx >= nioctls) {
		DMSG(vdc, 0, "[%d] Unsupported ioctl (0x%x)\n",
		    vdc->instance, cmd);
		return (ENOTSUP);
	}

	iop = &(dk_ioctl[idx]);

	if (cmd == DKIOCGETEFI || cmd == DKIOCSETEFI) {
		/* size is not fixed for EFI ioctls, it depends on ioctl arg */
		dk_efi_t	dk_efi;

		rv = ddi_copyin(arg, &dk_efi, sizeof (dk_efi_t), mode);
		if (rv != 0)
			return (EFAULT);

		len = sizeof (vd_efi_t) - 1 + dk_efi.dki_length;
	} else {
		len = iop->nbytes;
	}

	/* check if the ioctl is applicable */
	switch (cmd) {
	case CDROMREADOFFSET:
	case DKIOCREMOVABLE:
		return (ENOTTY);

	case USCSICMD:
	case MHIOCTKOWN:
	case MHIOCSTATUS:
	case MHIOCQRESERVE:
	case MHIOCRELEASE:
	case MHIOCGRP_INKEYS:
	case MHIOCGRP_INRESV:
	case MHIOCGRP_REGISTER:
	case MHIOCGRP_RESERVE:
	case MHIOCGRP_PREEMPTANDABORT:
	case MHIOCGRP_REGISTERANDIGNOREKEY:
	case MHIOCENFAILFAST:
		if (vdc->cinfo == NULL)
			return (ENXIO);
		if (vdc->cinfo->dki_ctype != DKC_SCSI_CCS)
			return (ENOTTY);
		break;

	case DIOCTL_RWCMD:
		if (vdc->cinfo == NULL)
			return (ENXIO);
		if (vdc->cinfo->dki_ctype != DKC_DIRECT)
			return (ENOTTY);
		break;

	case DKIOCINFO:
		if (vdc->cinfo == NULL)
			return (ENXIO);
		break;

	case DKIOCGMEDIAINFO:
		if (vdc->minfo == NULL)
			return (ENXIO);
		if (vdc_check_capacity(vdc) != 0)
			/* disk capacity is not available */
			return (EIO);
		break;
	}

	/*
	 * Deal with ioctls which require a processing different than
	 * converting ioctl arguments and sending a corresponding
	 * VD operation.
	 */
	switch (cmd) {

	case USCSICMD:
	{
		return (vdc_uscsi_cmd(vdc, arg, mode));
	}

	case MHIOCTKOWN:
	{
		mutex_enter(&vdc->ownership_lock);
		/*
		 * We have to set VDC_OWNERSHIP_WANTED now so that the ownership
		 * can be flagged with VDC_OWNERSHIP_RESET if the LDC is reset
		 * while we are processing the ioctl.
		 */
		vdc_ownership_update(vdc, VDC_OWNERSHIP_WANTED);

		rv = vdc_access_set(vdc, VD_ACCESS_SET_EXCLUSIVE |
		    VD_ACCESS_SET_PREEMPT | VD_ACCESS_SET_PRESERVE);
		if (rv == 0) {
			vdc_ownership_update(vdc, VDC_OWNERSHIP_WANTED |
			    VDC_OWNERSHIP_GRANTED);
		} else {
			vdc_ownership_update(vdc, VDC_OWNERSHIP_NONE);
		}
		mutex_exit(&vdc->ownership_lock);
		return (rv);
	}

	case MHIOCRELEASE:
	{
		mutex_enter(&vdc->ownership_lock);
		rv = vdc_access_set(vdc, VD_ACCESS_SET_CLEAR);
		if (rv == 0) {
			vdc_ownership_update(vdc, VDC_OWNERSHIP_NONE);
		}
		mutex_exit(&vdc->ownership_lock);
		return (rv);
	}

	case MHIOCSTATUS:
	{
		uint64_t status;

		rv = vdc_access_get(vdc, &status);
		if (rv == 0 && rvalp != NULL)
			*rvalp = (status & VD_ACCESS_ALLOWED)? 0 : 1;
		return (rv);
	}

	case MHIOCQRESERVE:
	{
		rv = vdc_access_set(vdc, VD_ACCESS_SET_EXCLUSIVE);
		return (rv);
	}

	case MHIOCGRP_INKEYS:
	{
		return (vdc_mhd_inkeys(vdc, arg, mode));
	}

	case MHIOCGRP_INRESV:
	{
		return (vdc_mhd_inresv(vdc, arg, mode));
	}

	case MHIOCGRP_REGISTER:
	{
		return (vdc_mhd_register(vdc, arg, mode));
	}

	case MHIOCGRP_RESERVE:
	{
		return (vdc_mhd_reserve(vdc, arg, mode));
	}

	case MHIOCGRP_PREEMPTANDABORT:
	{
		return (vdc_mhd_preemptabort(vdc, arg, mode));
	}

	case MHIOCGRP_REGISTERANDIGNOREKEY:
	{
		return (vdc_mhd_registerignore(vdc, arg, mode));
	}

	case MHIOCENFAILFAST:
	{
		rv = vdc_failfast(vdc, arg, mode);
		return (rv);
	}

	case DIOCTL_RWCMD:
	{
		return (vdc_dioctl_rwcmd(vdc, arg, mode));
	}

	case DKIOCGAPART:
	{
		return (vdc_dkio_gapart(vdc, arg, mode));
	}

	case DKIOCPARTITION:
	{
		return (vdc_dkio_partition(vdc, arg, mode));
	}

	case DKIOCINFO:
	{
		struct dk_cinfo	cinfo;

		bcopy(vdc->cinfo, &cinfo, sizeof (struct dk_cinfo));
		cinfo.dki_partition = VDCPART(dev);

		rv = ddi_copyout(&cinfo, (void *)arg,
		    sizeof (struct dk_cinfo), mode);
		if (rv != 0)
			return (EFAULT);

		return (0);
	}

	case DKIOCGMEDIAINFO:
	{
		ASSERT(vdc->vdisk_size != 0);
		ASSERT(vdc->minfo->dki_capacity != 0);
		rv = ddi_copyout(vdc->minfo, (void *)arg,
		    sizeof (struct dk_minfo), mode);
		if (rv != 0)
			return (EFAULT);

		return (0);
	}

	case DKIOCFLUSHWRITECACHE:
		{
			struct dk_callback *dkc =
			    (struct dk_callback *)(uintptr_t)arg;
			vdc_dk_arg_t	*dkarg = NULL;

			DMSG(vdc, 1, "[%d] Flush W$: mode %x\n",
			    instance, mode);

			/*
			 * If arg is NULL, then there is no callback function
			 * registered and the call operates synchronously; we
			 * break and continue with the rest of the function and
			 * wait for vds to return (i.e. after the request to
			 * vds returns successfully, all writes completed prior
			 * to the ioctl will have been flushed from the disk
			 * write cache to persistent media.
			 *
			 * If a callback function is registered, we dispatch
			 * the request on a task queue and return immediately.
			 * The callback will deal with informing the calling
			 * thread that the flush request is completed.
			 */
			if (dkc == NULL)
				break;

			/*
			 * the asynchronous callback is only supported if
			 * invoked from within the kernel
			 */
			if ((mode & FKIOCTL) == 0)
				return (ENOTSUP);

			dkarg = kmem_zalloc(sizeof (vdc_dk_arg_t), KM_SLEEP);

			dkarg->mode = mode;
			dkarg->dev = dev;
			bcopy(dkc, &dkarg->dkc, sizeof (*dkc));

			mutex_enter(&vdc->lock);
			vdc->dkio_flush_pending++;
			dkarg->vdc = vdc;
			mutex_exit(&vdc->lock);

			/* put the request on a task queue */
			rv = taskq_dispatch(system_taskq, vdc_dkio_flush_cb,
			    (void *)dkarg, DDI_SLEEP);
			if (rv == TASKQID_INVALID) {
				/* clean up if dispatch fails */
				mutex_enter(&vdc->lock);
				vdc->dkio_flush_pending--;
				mutex_exit(&vdc->lock);
				kmem_free(dkarg, sizeof (vdc_dk_arg_t));
				return (ENOMEM);
			}

			return (0);
		}
	}

	/* catch programming error in vdc - should be a VD_OP_XXX ioctl */
	ASSERT(iop->op != 0);

	/* check if the vDisk server handles the operation for this vDisk */
	if (VD_OP_SUPPORTED(vdc->operations, iop->op) == B_FALSE) {
		DMSG(vdc, 0, "[%d] Unsupported VD_OP operation (0x%x)\n",
		    vdc->instance, iop->op);
		return (ENOTSUP);
	}

	/* LDC requires that the memory being mapped is 8-byte aligned */
	alloc_len = P2ROUNDUP(len, sizeof (uint64_t));
	DMSG(vdc, 1, "[%d] struct size %ld alloc %ld\n",
	    instance, len, alloc_len);

	if (alloc_len > 0)
		mem_p = kmem_zalloc(alloc_len, KM_SLEEP);

	/*
	 * Call the conversion function for this ioctl which, if necessary,
	 * converts from the Solaris format to the format ARC'ed
	 * as part of the vDisk protocol (FWARC 2006/195)
	 */
	ASSERT(iop->convert != NULL);
	rv = (iop->convert)(vdc, arg, mem_p, mode, VD_COPYIN);
	if (rv != 0) {
		DMSG(vdc, 0, "[%d] convert func returned %d for ioctl 0x%x\n",
		    instance, rv, cmd);
		if (mem_p != NULL)
			kmem_free(mem_p, alloc_len);
		return (rv);
	}

	/*
	 * send request to vds to service the ioctl.
	 */
	rv = vdc_do_sync_op(vdc, iop->op, mem_p, alloc_len,
	    VDCPART(dev), 0, VIO_both_dir, B_TRUE);

	if (rv != 0) {
		/*
		 * This is not necessarily an error. The ioctl could
		 * be returning a value such as ENOTTY to indicate
		 * that the ioctl is not applicable.
		 */
		DMSG(vdc, 0, "[%d] vds returned %d for ioctl 0x%x\n",
		    instance, rv, cmd);
		if (mem_p != NULL)
			kmem_free(mem_p, alloc_len);

		return (rv);
	}

	/*
	 * Call the conversion function (if it exists) for this ioctl
	 * which converts from the format ARC'ed as part of the vDisk
	 * protocol (FWARC 2006/195) back to a format understood by
	 * the rest of Solaris.
	 */
	rv = (iop->convert)(vdc, mem_p, arg, mode, VD_COPYOUT);
	if (rv != 0) {
		DMSG(vdc, 0, "[%d] convert func returned %d for ioctl 0x%x\n",
		    instance, rv, cmd);
		if (mem_p != NULL)
			kmem_free(mem_p, alloc_len);
		return (rv);
	}

	if (mem_p != NULL)
		kmem_free(mem_p, alloc_len);

	return (rv);
}

/*
 * Function:
 *
 * Description:
 *	This is an empty conversion function used by ioctl calls which
 *	do not need to convert the data being passed in/out to userland
 */
static int
vdc_null_copy_func(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))
	_NOTE(ARGUNUSED(from))
	_NOTE(ARGUNUSED(to))
	_NOTE(ARGUNUSED(mode))
	_NOTE(ARGUNUSED(dir))

	return (0);
}

static int
vdc_get_wce_convert(vdc_t *vdc, void *from, void *to,
    int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	if (dir == VD_COPYIN)
		return (0);		/* nothing to do */

	if (ddi_copyout(from, to, sizeof (int), mode) != 0)
		return (EFAULT);

	return (0);
}

static int
vdc_set_wce_convert(vdc_t *vdc, void *from, void *to,
    int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	if (dir == VD_COPYOUT)
		return (0);		/* nothing to do */

	if (ddi_copyin(from, to, sizeof (int), mode) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Function:
 *	vdc_get_vtoc_convert()
 *
 * Description:
 *	This routine performs the necessary convertions from the DKIOCGVTOC
 *	Solaris structure to the format defined in FWARC 2006/195.
 *
 *	In the struct vtoc definition, the timestamp field is marked as not
 *	supported so it is not part of vDisk protocol (FWARC 2006/195).
 *	However SVM uses that field to check it can write into the VTOC,
 *	so we fake up the info of that field.
 *
 * Arguments:
 *	vdc	- the vDisk client
 *	from	- the buffer containing the data to be copied from
 *	to	- the buffer to be copied to
 *	mode	- flags passed to ioctl() call
 *	dir	- the "direction" of the copy - VD_COPYIN or VD_COPYOUT
 *
 * Return Code:
 *	0	- Success
 *	ENXIO	- incorrect buffer passed in.
 *	EFAULT	- ddi_copyout routine encountered an error.
 */
static int
vdc_get_vtoc_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	int		i;
	struct vtoc	vtoc;
	struct vtoc32	vtoc32;
	struct extvtoc	evtoc;
	int		rv;

	if (dir != VD_COPYOUT)
		return (0);	/* nothing to do */

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	if (vdc->vdisk_size > VD_OLDVTOC_LIMIT)
		return (EOVERFLOW);

	VD_VTOC2VTOC((vd_vtoc_t *)from, &evtoc);

	/* fake the VTOC timestamp field */
	for (i = 0; i < V_NUMPAR; i++) {
		evtoc.timestamp[i] = vdc->vtoc->timestamp[i];
	}

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		/* LINTED E_ASSIGN_NARROW_CONV */
		extvtoctovtoc32(evtoc, vtoc32);
		rv = ddi_copyout(&vtoc32, to, sizeof (vtoc32), mode);
		if (rv != 0)
			rv = EFAULT;
	} else {
		extvtoctovtoc(evtoc, vtoc);
		rv = ddi_copyout(&vtoc, to, sizeof (vtoc), mode);
		if (rv != 0)
			rv = EFAULT;
	}

	return (rv);
}

/*
 * Function:
 *	vdc_set_vtoc_convert()
 *
 * Description:
 *	This routine performs the necessary convertions from the DKIOCSVTOC
 *	Solaris structure to the format defined in FWARC 2006/195.
 *
 * Arguments:
 *	vdc	- the vDisk client
 *	from	- Buffer with data
 *	to	- Buffer where data is to be copied to
 *	mode	- flags passed to ioctl
 *	dir	- direction of copy (in or out)
 *
 * Return Code:
 *	0	- Success
 *	ENXIO	- Invalid buffer passed in
 *	EFAULT	- ddi_copyin of data failed
 */
static int
vdc_set_vtoc_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	void		*uvtoc;
	struct vtoc	vtoc;
	struct vtoc32	vtoc32;
	struct extvtoc	evtoc;
	int		i, rv;

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	if (vdc->vdisk_size > VD_OLDVTOC_LIMIT)
		return (EOVERFLOW);

	uvtoc = (dir == VD_COPYIN)? from : to;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		rv = ddi_copyin(uvtoc, &vtoc32, sizeof (vtoc32), mode);
		if (rv != 0)
			return (EFAULT);
		vtoc32toextvtoc(vtoc32, evtoc);
	} else {
		rv = ddi_copyin(uvtoc, &vtoc, sizeof (vtoc), mode);
		if (rv != 0)
			return (EFAULT);
		vtoctoextvtoc(vtoc, evtoc);
	}

	if (dir == VD_COPYOUT) {
		/*
		 * The disk label may have changed. Revalidate the disk
		 * geometry. This will also update the device nodes.
		 */
		vdc_validate(vdc);

		/*
		 * We also need to keep track of the timestamp fields.
		 */
		for (i = 0; i < V_NUMPAR; i++) {
			vdc->vtoc->timestamp[i] = evtoc.timestamp[i];
		}

	} else {
		VTOC2VD_VTOC(&evtoc, (vd_vtoc_t *)to);
	}

	return (0);
}

static int
vdc_get_extvtoc_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	int		i, rv;
	struct extvtoc	evtoc;

	if (dir != VD_COPYOUT)
		return (0);	/* nothing to do */

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	VD_VTOC2VTOC((vd_vtoc_t *)from, &evtoc);

	/* fake the VTOC timestamp field */
	for (i = 0; i < V_NUMPAR; i++) {
		evtoc.timestamp[i] = vdc->vtoc->timestamp[i];
	}

	rv = ddi_copyout(&evtoc, to, sizeof (struct extvtoc), mode);
	if (rv != 0)
		rv = EFAULT;

	return (rv);
}

static int
vdc_set_extvtoc_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	void		*uvtoc;
	struct extvtoc	evtoc;
	int		i, rv;

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	uvtoc = (dir == VD_COPYIN)? from : to;

	rv = ddi_copyin(uvtoc, &evtoc, sizeof (struct extvtoc), mode);
	if (rv != 0)
		return (EFAULT);

	if (dir == VD_COPYOUT) {
		/*
		 * The disk label may have changed. Revalidate the disk
		 * geometry. This will also update the device nodes.
		 */
		vdc_validate(vdc);

		/*
		 * We also need to keep track of the timestamp fields.
		 */
		for (i = 0; i < V_NUMPAR; i++) {
			vdc->vtoc->timestamp[i] = evtoc.timestamp[i];
		}

	} else {
		VTOC2VD_VTOC(&evtoc, (vd_vtoc_t *)to);
	}

	return (0);
}

/*
 * Function:
 *	vdc_get_geom_convert()
 *
 * Description:
 *	This routine performs the necessary convertions from the DKIOCGGEOM,
 *	DKIOCG_PHYSGEOM and DKIOG_VIRTGEOM Solaris structures to the format
 *	defined in FWARC 2006/195
 *
 * Arguments:
 *	vdc	- the vDisk client
 *	from	- Buffer with data
 *	to	- Buffer where data is to be copied to
 *	mode	- flags passed to ioctl
 *	dir	- direction of copy (in or out)
 *
 * Return Code:
 *	0	- Success
 *	ENXIO	- Invalid buffer passed in
 *	EFAULT	- ddi_copyout of data failed
 */
static int
vdc_get_geom_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	struct dk_geom	geom;
	int	copy_len = sizeof (struct dk_geom);
	int	rv = 0;

	if (dir != VD_COPYOUT)
		return (0);	/* nothing to do */

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	VD_GEOM2DK_GEOM((vd_geom_t *)from, &geom);
	rv = ddi_copyout(&geom, to, copy_len, mode);
	if (rv != 0)
		rv = EFAULT;

	return (rv);
}

/*
 * Function:
 *	vdc_set_geom_convert()
 *
 * Description:
 *	This routine performs the necessary convertions from the DKIOCSGEOM
 *	Solaris structure to the format defined in FWARC 2006/195.
 *
 * Arguments:
 *	vdc	- the vDisk client
 *	from	- Buffer with data
 *	to	- Buffer where data is to be copied to
 *	mode	- flags passed to ioctl
 *	dir	- direction of copy (in or out)
 *
 * Return Code:
 *	0	- Success
 *	ENXIO	- Invalid buffer passed in
 *	EFAULT	- ddi_copyin of data failed
 */
static int
vdc_set_geom_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	vd_geom_t	vdgeom;
	void		*tmp_mem = NULL;
	int		copy_len = sizeof (struct dk_geom);
	int		rv = 0;

	if (dir != VD_COPYIN)
		return (0);	/* nothing to do */

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	tmp_mem = kmem_alloc(copy_len, KM_SLEEP);

	rv = ddi_copyin(from, tmp_mem, copy_len, mode);
	if (rv != 0) {
		kmem_free(tmp_mem, copy_len);
		return (EFAULT);
	}
	DK_GEOM2VD_GEOM((struct dk_geom *)tmp_mem, &vdgeom);
	bcopy(&vdgeom, to, sizeof (vdgeom));
	kmem_free(tmp_mem, copy_len);

	return (0);
}

static int
vdc_get_efi_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	vd_efi_t	*vd_efi;
	dk_efi_t	dk_efi;
	int		rv = 0;
	void		*uaddr;

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	if (dir == VD_COPYIN) {

		vd_efi = (vd_efi_t *)to;

		rv = ddi_copyin(from, &dk_efi, sizeof (dk_efi_t), mode);
		if (rv != 0)
			return (EFAULT);

		vd_efi->lba = dk_efi.dki_lba;
		vd_efi->length = dk_efi.dki_length;
		bzero(vd_efi->data, vd_efi->length);

	} else {

		rv = ddi_copyin(to, &dk_efi, sizeof (dk_efi_t), mode);
		if (rv != 0)
			return (EFAULT);

		uaddr = dk_efi.dki_data;

		dk_efi.dki_data = kmem_alloc(dk_efi.dki_length, KM_SLEEP);

		VD_EFI2DK_EFI((vd_efi_t *)from, &dk_efi);

		rv = ddi_copyout(dk_efi.dki_data, uaddr, dk_efi.dki_length,
		    mode);
		if (rv != 0)
			return (EFAULT);

		kmem_free(dk_efi.dki_data, dk_efi.dki_length);
	}

	return (0);
}

static int
vdc_set_efi_convert(vdc_t *vdc, void *from, void *to, int mode, int dir)
{
	_NOTE(ARGUNUSED(vdc))

	dk_efi_t	dk_efi;
	void		*uaddr;

	if (dir == VD_COPYOUT) {
		/*
		 * The disk label may have changed. Revalidate the disk
		 * geometry. This will also update the device nodes.
		 */
		vdc_validate(vdc);
		return (0);
	}

	if ((from == NULL) || (to == NULL))
		return (ENXIO);

	if (ddi_copyin(from, &dk_efi, sizeof (dk_efi_t), mode) != 0)
		return (EFAULT);

	uaddr = dk_efi.dki_data;

	dk_efi.dki_data = kmem_alloc(dk_efi.dki_length, KM_SLEEP);

	if (ddi_copyin(uaddr, dk_efi.dki_data, dk_efi.dki_length, mode) != 0)
		return (EFAULT);

	DK_EFI2VD_EFI(&dk_efi, (vd_efi_t *)to);

	kmem_free(dk_efi.dki_data, dk_efi.dki_length);

	return (0);
}


/* -------------------------------------------------------------------------- */

/*
 * Function:
 *	vdc_create_fake_geometry()
 *
 * Description:
 *	This routine fakes up the disk info needed for some DKIO ioctls such
 *	as DKIOCINFO and DKIOCGMEDIAINFO [just like lofi(7D) and ramdisk(7D) do]
 *
 *	Note: This function must not be called until the vDisk attributes have
 *	been exchanged as part of the handshake with the vDisk server.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	none.
 */
static void
vdc_create_fake_geometry(vdc_t *vdc)
{
	ASSERT(vdc != NULL);
	ASSERT(vdc->max_xfer_sz != 0);

	/*
	 * DKIOCINFO support
	 */
	if (vdc->cinfo == NULL)
		vdc->cinfo = kmem_zalloc(sizeof (struct dk_cinfo), KM_SLEEP);

	(void) strcpy(vdc->cinfo->dki_cname, VDC_DRIVER_NAME);
	(void) strcpy(vdc->cinfo->dki_dname, VDC_DRIVER_NAME);
	/* max_xfer_sz is #blocks so we don't need to divide by vdisk_bsize */
	vdc->cinfo->dki_maxtransfer = vdc->max_xfer_sz;

	/*
	 * We set the controller type to DKC_SCSI_CCS only if the VD_OP_SCSICMD
	 * operation is supported, otherwise the controller type is DKC_DIRECT.
	 * Version 1.0 does not support the VD_OP_SCSICMD operation, so the
	 * controller type is always DKC_DIRECT in that case.
	 *
	 * If the virtual disk is backed by a physical CD/DVD device or
	 * an ISO image, modify the controller type to indicate this
	 */
	switch (vdc->vdisk_media) {
	case VD_MEDIA_CD:
	case VD_MEDIA_DVD:
		vdc->cinfo->dki_ctype = DKC_CDROM;
		break;
	case VD_MEDIA_FIXED:
		if (VD_OP_SUPPORTED(vdc->operations, VD_OP_SCSICMD))
			vdc->cinfo->dki_ctype = DKC_SCSI_CCS;
		else
			vdc->cinfo->dki_ctype = DKC_DIRECT;
		break;
	default:
		/* in the case of v1.0 we default to a fixed disk */
		vdc->cinfo->dki_ctype = DKC_DIRECT;
		break;
	}
	vdc->cinfo->dki_flags = DKI_FMTVOL;
	vdc->cinfo->dki_cnum = 0;
	vdc->cinfo->dki_addr = 0;
	vdc->cinfo->dki_space = 0;
	vdc->cinfo->dki_prio = 0;
	vdc->cinfo->dki_vec = 0;
	vdc->cinfo->dki_unit = vdc->instance;
	vdc->cinfo->dki_slave = 0;
	/*
	 * The partition number will be created on the fly depending on the
	 * actual slice (i.e. minor node) that is used to request the data.
	 */
	vdc->cinfo->dki_partition = 0;

	/*
	 * DKIOCGMEDIAINFO support
	 */
	if (vdc->minfo == NULL)
		vdc->minfo = kmem_zalloc(sizeof (struct dk_minfo), KM_SLEEP);

	if (vio_ver_is_supported(vdc->ver, 1, 1)) {
		vdc->minfo->dki_media_type =
		    VD_MEDIATYPE2DK_MEDIATYPE(vdc->vdisk_media);
	} else {
		vdc->minfo->dki_media_type = DK_FIXED_DISK;
	}

	vdc->minfo->dki_capacity = vdc->vdisk_size;
	vdc->minfo->dki_lbsize = vdc->vdisk_bsize;
}

static ushort_t
vdc_lbl2cksum(struct dk_label *label)
{
	int	count;
	ushort_t sum, *sp;

	count =	(sizeof (struct dk_label)) / (sizeof (short)) - 1;
	sp = (ushort_t *)label;
	sum = 0;
	while (count--) {
		sum ^= *sp++;
	}

	return (sum);
}

static void
vdc_update_size(vdc_t *vdc, size_t dsk_size, size_t blk_size, size_t xfr_size)
{
	vd_err_stats_t  *stp;

	ASSERT(MUTEX_HELD(&vdc->lock));
	ASSERT(xfr_size != 0);

	/*
	 * If the disk size is unknown or sizes are unchanged then don't
	 * update anything.
	 */
	if (dsk_size == VD_SIZE_UNKNOWN || dsk_size == 0 ||
	    (blk_size == vdc->vdisk_bsize && dsk_size == vdc->vdisk_size &&
	    xfr_size == vdc->max_xfer_sz))
		return;

	/*
	 * We don't know at compile time what the vDisk server will think
	 * are good values but we apply a large (arbitrary) upper bound to
	 * prevent memory exhaustion in vdc if it was allocating a DRing
	 * based of huge values sent by the server. We probably will never
	 * exceed this except if the message was garbage.
	 */
	if ((xfr_size * blk_size) > (PAGESIZE * DEV_BSIZE)) {
		DMSG(vdc, 0, "[%d] vds block transfer size too big;"
		    " using max supported by vdc", vdc->instance);
		xfr_size = maxphys / blk_size;
	}

	vdc->max_xfer_sz = xfr_size;
	vdc->vdisk_bsize = blk_size;
	vdc->vdisk_size = dsk_size;

	stp = (vd_err_stats_t *)vdc->err_stats->ks_data;
	stp->vd_capacity.value.ui64 = dsk_size * blk_size;

	vdc->minfo->dki_capacity = dsk_size;
	vdc->minfo->dki_lbsize = (uint_t)blk_size;
}

/*
 * Update information about the VIO block size. The VIO block size is the
 * same as the vdisk block size which is stored in vdc->vdisk_bsize so we
 * do not store that information again.
 *
 * However, buf structures will always use a logical block size of 512 bytes
 * (DEV_BSIZE) and we will need to convert logical block numbers to VIO block
 * numbers for each read or write operation using vdc_strategy(). To speed up
 * this conversion, we expect the VIO block size to be a power of 2 and a
 * multiple 512 bytes (DEV_BSIZE), and we cache some useful information.
 *
 * The function return EINVAL if the new VIO block size (blk_size) is not a
 * power of 2 or not a multiple of 512 bytes, otherwise it returns 0.
 */
static int
vdc_update_vio_bsize(vdc_t *vdc, uint32_t blk_size)
{
	uint32_t ratio, n;
	int nshift = 0;

	vdc->vio_bmask = 0;
	vdc->vio_bshift = 0;

	ASSERT(blk_size > 0);

	if ((blk_size % DEV_BSIZE) != 0)
		return (EINVAL);

	ratio = blk_size / DEV_BSIZE;

	for (n = ratio; n > 1; n >>= 1) {
		if ((n & 0x1) != 0) {
			/* blk_size is not a power of 2 */
			return (EINVAL);
		}
		nshift++;
	}

	vdc->vio_bshift = nshift;
	vdc->vio_bmask = ratio - 1;

	return (0);
}

/*
 * Function:
 *	vdc_validate_geometry
 *
 * Description:
 *	This routine discovers the label and geometry of the disk. It stores
 *	the disk label and related information in the vdc structure. If it
 *	fails to validate the geometry or to discover the disk label then
 *	the label is marked as unknown (VD_DISK_LABEL_UNK).
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- success.
 *	EINVAL	- unknown disk label.
 *	ENOTSUP	- geometry not applicable (EFI label).
 *	EIO	- error accessing the disk.
 */
static int
vdc_validate_geometry(vdc_t *vdc)
{
	dev_t	dev;
	int	rv, rval;
	struct dk_label *label;
	struct dk_geom geom;
	struct extvtoc vtoc;
	efi_gpt_t *gpt;
	efi_gpe_t *gpe;
	vd_efi_dev_t edev;

	ASSERT(vdc != NULL);
	ASSERT(vdc->vtoc != NULL && vdc->geom != NULL);
	ASSERT(MUTEX_HELD(&vdc->lock));

	mutex_exit(&vdc->lock);
	/*
	 * Check the disk capacity in case it has changed. If that fails then
	 * we proceed and we will be using the disk size we currently have.
	 */
	(void) vdc_check_capacity(vdc);
	dev = makedevice(ddi_driver_major(vdc->dip),
	    VD_MAKE_DEV(vdc->instance, 0));

	rv = vd_process_ioctl(dev, DKIOCGGEOM, (caddr_t)&geom, FKIOCTL, &rval);
	if (rv == 0)
		rv = vd_process_ioctl(dev, DKIOCGEXTVTOC, (caddr_t)&vtoc,
		    FKIOCTL, &rval);

	if (rv == ENOTSUP) {
		/*
		 * If the device does not support VTOC then we try
		 * to read an EFI label.
		 *
		 * We need to know the block size and the disk size to
		 * be able to read an EFI label.
		 */
		if (vdc->vdisk_size == 0) {
			mutex_enter(&vdc->lock);
			vdc_store_label_unk(vdc);
			return (EIO);
		}

		VDC_EFI_DEV_SET(edev, vdc, vd_process_efi_ioctl);

		rv = vd_efi_alloc_and_read(&edev, &gpt, &gpe);

		if (rv) {
			DMSG(vdc, 0, "[%d] Failed to get EFI (err=%d)",
			    vdc->instance, rv);
			mutex_enter(&vdc->lock);
			vdc_store_label_unk(vdc);
			return (EIO);
		}

		mutex_enter(&vdc->lock);
		vdc_store_label_efi(vdc, gpt, gpe);
		vd_efi_free(&edev, gpt, gpe);
		return (ENOTSUP);
	}

	if (rv != 0) {
		DMSG(vdc, 0, "[%d] Failed to get VTOC (err=%d)",
		    vdc->instance, rv);
		mutex_enter(&vdc->lock);
		vdc_store_label_unk(vdc);
		if (rv != EINVAL)
			rv = EIO;
		return (rv);
	}

	/* check that geometry and vtoc are valid */
	if (geom.dkg_nhead == 0 || geom.dkg_nsect == 0 ||
	    vtoc.v_sanity != VTOC_SANE) {
		mutex_enter(&vdc->lock);
		vdc_store_label_unk(vdc);
		return (EINVAL);
	}

	/*
	 * We have a disk and a valid VTOC. However this does not mean
	 * that the disk currently have a VTOC label. The returned VTOC may
	 * be a default VTOC to be used for configuring the disk (this is
	 * what is done for disk image). So we read the label from the
	 * beginning of the disk to ensure we really have a VTOC label.
	 *
	 * FUTURE: This could be the default way for reading the VTOC
	 * from the disk as opposed to sending the VD_OP_GET_VTOC
	 * to the server. This will be the default if vdc is implemented
	 * ontop of cmlb.
	 */

	/*
	 * Single slice disk does not support read using an absolute disk
	 * offset so we just rely on the DKIOCGVTOC ioctl in that case.
	 */
	if (vdc->vdisk_type == VD_DISK_TYPE_SLICE) {
		mutex_enter(&vdc->lock);
		if (vtoc.v_nparts != 1) {
			vdc_store_label_unk(vdc);
			return (EINVAL);
		}
		vdc_store_label_vtoc(vdc, &geom, &vtoc);
		return (0);
	}

	if (vtoc.v_nparts != V_NUMPAR) {
		mutex_enter(&vdc->lock);
		vdc_store_label_unk(vdc);
		return (EINVAL);
	}

	/*
	 * Most CD/DVDs do not have a disk label and the label is
	 * generated by the disk driver.  So the on-disk label check
	 * below may fail and we return now to avoid this problem.
	 */
	if (vdc->vdisk_media == VD_MEDIA_CD ||
	    vdc->vdisk_media == VD_MEDIA_DVD) {
		mutex_enter(&vdc->lock);
		vdc_store_label_vtoc(vdc, &geom, &vtoc);
		return (0);
	}

	/*
	 * Read disk label from start of disk
	 */
	label = kmem_alloc(vdc->vdisk_bsize, KM_SLEEP);

	rv = vdc_do_op(vdc, VD_OP_BREAD, (caddr_t)label, vdc->vdisk_bsize,
	    VD_SLICE_NONE, 0, NULL, VIO_read_dir, VDC_OP_NORMAL);

	if (rv != 0 || label->dkl_magic != DKL_MAGIC ||
	    label->dkl_cksum != vdc_lbl2cksum(label)) {
		DMSG(vdc, 1, "[%d] Got VTOC with invalid label\n",
		    vdc->instance);
		kmem_free(label, vdc->vdisk_bsize);
		mutex_enter(&vdc->lock);
		vdc_store_label_unk(vdc);
		return (EINVAL);
	}

	kmem_free(label, vdc->vdisk_bsize);
	mutex_enter(&vdc->lock);
	vdc_store_label_vtoc(vdc, &geom, &vtoc);
	return (0);
}

/*
 * Function:
 *	vdc_validate
 *
 * Description:
 *	This routine discovers the label of the disk and create the
 *	appropriate device nodes if the label has changed.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	none.
 */
static void
vdc_validate(vdc_t *vdc)
{
	vd_disk_label_t old_label;
	vd_slice_t old_slice[V_NUMPAR];
	int rv;

	ASSERT(!MUTEX_HELD(&vdc->lock));

	mutex_enter(&vdc->lock);

	/* save the current label and vtoc */
	old_label = vdc->vdisk_label;
	bcopy(vdc->slice, &old_slice, sizeof (vd_slice_t) * V_NUMPAR);

	/* check the geometry */
	(void) vdc_validate_geometry(vdc);

	/* if the disk label has changed, update device nodes */
	if (vdc->vdisk_type == VD_DISK_TYPE_DISK &&
	    vdc->vdisk_label != old_label) {

		if (vdc->vdisk_label == VD_DISK_LABEL_EFI)
			rv = vdc_create_device_nodes_efi(vdc);
		else
			rv = vdc_create_device_nodes_vtoc(vdc);

		if (rv != 0) {
			DMSG(vdc, 0, "![%d] Failed to update device nodes",
			    vdc->instance);
		}
	}

	mutex_exit(&vdc->lock);
}

static void
vdc_validate_task(void *arg)
{
	vdc_t *vdc = (vdc_t *)arg;

	vdc_validate(vdc);

	mutex_enter(&vdc->lock);
	ASSERT(vdc->validate_pending > 0);
	vdc->validate_pending--;
	mutex_exit(&vdc->lock);
}

/*
 * Function:
 *	vdc_setup_devid()
 *
 * Description:
 *	This routine discovers the devid of a vDisk. It requests the devid of
 *	the underlying device from the vDisk server, builds an encapsulated
 *	devid based on the retrieved devid and registers that new devid to
 *	the vDisk.
 *
 * Arguments:
 *	vdc	- soft state pointer for this instance of the device driver.
 *
 * Return Code:
 *	0	- A devid was succesfully registered for the vDisk
 */
static int
vdc_setup_devid(vdc_t *vdc)
{
	int rv;
	vd_devid_t *vd_devid;
	size_t bufsize, bufid_len;
	ddi_devid_t vdisk_devid;
	char *devid_str;

	/*
	 * At first sight, we don't know the size of the devid that the
	 * server will return but this size will be encoded into the
	 * reply. So we do a first request using a default size then we
	 * check if this size was large enough. If not then we do a second
	 * request with the correct size returned by the server. Note that
	 * ldc requires size to be 8-byte aligned.
	 */
	bufsize = P2ROUNDUP(VD_DEVID_SIZE(VD_DEVID_DEFAULT_LEN),
	    sizeof (uint64_t));
	vd_devid = kmem_zalloc(bufsize, KM_SLEEP);
	bufid_len = bufsize - sizeof (vd_efi_t) - 1;

	rv = vdc_do_op(vdc, VD_OP_GET_DEVID, (caddr_t)vd_devid,
	    bufsize, 0, 0, NULL, VIO_both_dir, 0);

	DMSG(vdc, 2, "do_op returned %d\n", rv);

	if (rv) {
		kmem_free(vd_devid, bufsize);
		return (rv);
	}

	if (vd_devid->length > bufid_len) {
		/*
		 * The returned devid is larger than the buffer used. Try again
		 * with a buffer with the right size.
		 */
		kmem_free(vd_devid, bufsize);
		bufsize = P2ROUNDUP(VD_DEVID_SIZE(vd_devid->length),
		    sizeof (uint64_t));
		vd_devid = kmem_zalloc(bufsize, KM_SLEEP);
		bufid_len = bufsize - sizeof (vd_efi_t) - 1;

		rv = vdc_do_sync_op(vdc, VD_OP_GET_DEVID, (caddr_t)vd_devid,
		    bufsize, 0, 0, VIO_both_dir, B_TRUE);

		if (rv) {
			kmem_free(vd_devid, bufsize);
			return (rv);
		}
	}

	/*
	 * The virtual disk should have the same device id as the one associated
	 * with the physical disk it is mapped on, otherwise sharing a disk
	 * between a LDom and a non-LDom may not work (for example for a shared
	 * SVM disk set).
	 *
	 * The DDI framework does not allow creating a device id with any
	 * type so we first create a device id of type DEVID_ENCAP and then
	 * we restore the orignal type of the physical device.
	 */

	DMSG(vdc, 2, ": devid length = %d\n", vd_devid->length);

	/* build an encapsulated devid based on the returned devid */
	if (ddi_devid_init(vdc->dip, DEVID_ENCAP, vd_devid->length,
	    vd_devid->id, &vdisk_devid) != DDI_SUCCESS) {
		DMSG(vdc, 1, "[%d] Fail to created devid\n", vdc->instance);
		kmem_free(vd_devid, bufsize);
		return (1);
	}

	DEVID_FORMTYPE((impl_devid_t *)vdisk_devid, vd_devid->type);

	ASSERT(ddi_devid_valid(vdisk_devid) == DDI_SUCCESS);

	kmem_free(vd_devid, bufsize);

	if (vdc->devid != NULL) {
		/* check that the devid hasn't changed */
		if (ddi_devid_compare(vdisk_devid, vdc->devid) == 0) {
			ddi_devid_free(vdisk_devid);
			return (0);
		}

		cmn_err(CE_WARN, "vdisk@%d backend devid has changed",
		    vdc->instance);

		devid_str = ddi_devid_str_encode(vdc->devid, NULL);

		cmn_err(CE_CONT, "vdisk@%d backend initial devid: %s",
		    vdc->instance,
		    (devid_str)? devid_str : "<encoding error>");

		if (devid_str)
			ddi_devid_str_free(devid_str);

		devid_str = ddi_devid_str_encode(vdisk_devid, NULL);

		cmn_err(CE_CONT, "vdisk@%d backend current devid: %s",
		    vdc->instance,
		    (devid_str)? devid_str : "<encoding error>");

		if (devid_str)
			ddi_devid_str_free(devid_str);

		ddi_devid_free(vdisk_devid);
		return (1);
	}

	if (ddi_devid_register(vdc->dip, vdisk_devid) != DDI_SUCCESS) {
		DMSG(vdc, 1, "[%d] Fail to register devid\n", vdc->instance);
		ddi_devid_free(vdisk_devid);
		return (1);
	}

	vdc->devid = vdisk_devid;

	return (0);
}

static void
vdc_store_label_efi(vdc_t *vdc, efi_gpt_t *gpt, efi_gpe_t *gpe)
{
	int i, nparts;

	ASSERT(MUTEX_HELD(&vdc->lock));

	vdc->vdisk_label = VD_DISK_LABEL_EFI;
	bzero(vdc->vtoc, sizeof (struct extvtoc));
	bzero(vdc->geom, sizeof (struct dk_geom));
	bzero(vdc->slice, sizeof (vd_slice_t) * V_NUMPAR);

	nparts = gpt->efi_gpt_NumberOfPartitionEntries;

	for (i = 0; i < nparts && i < VD_EFI_WD_SLICE; i++) {

		if (gpe[i].efi_gpe_StartingLBA == 0 &&
		    gpe[i].efi_gpe_EndingLBA == 0) {
			continue;
		}

		vdc->slice[i].start = gpe[i].efi_gpe_StartingLBA;
		vdc->slice[i].nblocks = gpe[i].efi_gpe_EndingLBA -
		    gpe[i].efi_gpe_StartingLBA + 1;
	}

	ASSERT(vdc->vdisk_size != 0);
	vdc->slice[VD_EFI_WD_SLICE].start = 0;
	vdc->slice[VD_EFI_WD_SLICE].nblocks = vdc->vdisk_size;

}

static void
vdc_store_label_vtoc(vdc_t *vdc, struct dk_geom *geom, struct extvtoc *vtoc)
{
	int i;

	ASSERT(MUTEX_HELD(&vdc->lock));
	ASSERT(vdc->vdisk_bsize == vtoc->v_sectorsz);

	vdc->vdisk_label = VD_DISK_LABEL_VTOC;
	bcopy(vtoc, vdc->vtoc, sizeof (struct extvtoc));
	bcopy(geom, vdc->geom, sizeof (struct dk_geom));
	bzero(vdc->slice, sizeof (vd_slice_t) * V_NUMPAR);

	for (i = 0; i < vtoc->v_nparts; i++) {
		vdc->slice[i].start = vtoc->v_part[i].p_start;
		vdc->slice[i].nblocks = vtoc->v_part[i].p_size;
	}
}

static void
vdc_store_label_unk(vdc_t *vdc)
{
	ASSERT(MUTEX_HELD(&vdc->lock));

	vdc->vdisk_label = VD_DISK_LABEL_UNK;
	bzero(vdc->vtoc, sizeof (struct extvtoc));
	bzero(vdc->geom, sizeof (struct dk_geom));
	bzero(vdc->slice, sizeof (vd_slice_t) * V_NUMPAR);
}
