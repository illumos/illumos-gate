/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Toomas Soome <tsoome@me.com>
 */

/*
 * Virtio random data device.
 */

#include <sys/types.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/crypto/spi.h>
#include <sys/time.h>
#include <virtio.h>

#define	VIORAND_FEATURES	0
#define	VIORAND_RQ		0

typedef struct viorand_state viorand_state_t;

typedef struct viorand_rdbuf {
	viorand_state_t		*rb_viornd;
	virtio_dma_t		*rb_dma;
	virtio_chain_t		*rb_chain;
	size_t			rb_recv_len;
	uchar_t			*rb_req_buf;
	size_t			rb_req_len;
	crypto_req_handle_t	rb_req_handle;
	list_node_t		rb_link;
} viorand_rdbuf_t;

struct viorand_state {
	dev_info_t	*vio_dip;
	kmutex_t	vio_mutex;
	kcondvar_t	vio_cv;
	crypto_kcf_provider_handle_t vio_handle;
	taskq_t		*vio_taskq;
	virtio_t	*vio_virtio;
	virtio_queue_t	*vio_rq;
	uint64_t	vio_features;

	uint_t		vio_rdbufs_capacity;
	uint_t		vio_rdbufs_alloc;
	list_t		vio_rdbufs_free;	/* Free list */
	viorand_rdbuf_t	*vio_rdbuf_mem;
};

static const ddi_dma_attr_t viorand_dma_attr = {
	.dma_attr_version =	DMA_ATTR_V0,
	.dma_attr_addr_lo =	0x0000000000000000,
	.dma_attr_addr_hi =	0xFFFFFFFFFFFFFFFF,
	.dma_attr_count_max =	0x00000000FFFFFFFF,
	.dma_attr_align =	1,
	.dma_attr_burstsizes =	1,
	.dma_attr_minxfer =	1,
	.dma_attr_maxxfer =	0x00000000FFFFFFFF,
	.dma_attr_seg =		0x00000000FFFFFFFF,
	.dma_attr_sgllen =	64,
	.dma_attr_granular =	1,
	.dma_attr_flags =	0
};

/* If set, we do not allow to detach ourselves. */
boolean_t virtio_registered = B_TRUE;
static void *viorand_statep;

static int viorand_attach(dev_info_t *, ddi_attach_cmd_t);
static int viorand_detach(dev_info_t *, ddi_detach_cmd_t);
static int viorand_quiesce(dev_info_t *);

static void viorand_provider_status(crypto_provider_handle_t, uint_t *);
static int viorand_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static uint_t viorand_interrupt(caddr_t, caddr_t);

/*
 * Module linkage information for the kernel.
 */

static struct dev_ops devops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = ddi_no_info,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = viorand_attach,
	.devo_detach = viorand_detach,
	.devo_reset = nodev,
	.devo_cb_ops = NULL,
	.devo_bus_ops = NULL,
	.devo_power = NULL,
	.devo_quiesce = viorand_quiesce
};

static struct modldrv modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "VirtIO Random Number Driver",
	.drv_dev_ops = &devops
};

static struct modlcrypto modlcrypto = {
	.crypto_modops = &mod_cryptoops,
	.crypto_linkinfo = "VirtIO Random Number Provider"
};

static struct modlinkage modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &modldrv, &modlcrypto, NULL }
};

/*
 * CSPI information (entry points, provider info, etc.)
 */
static void viorand_provider_status(crypto_provider_handle_t, uint_t *);

static crypto_control_ops_t viorand_control_ops = {
	.provider_status = viorand_provider_status
};

static int viorand_generate_random(crypto_provider_handle_t,
    crypto_session_id_t, uchar_t *, size_t, crypto_req_handle_t);

static crypto_random_number_ops_t viorand_random_number_ops = {
	.generate_random = viorand_generate_random
};

static crypto_ops_t viorand_crypto_ops = {
	.co_control_ops = &viorand_control_ops,
	.co_random_ops = &viorand_random_number_ops
};

static crypto_provider_info_t viorand_prov_info = {
	.pi_interface_version = CRYPTO_SPI_VERSION_1,
	.pi_provider_description = "VirtIO Random Number Provider",
	.pi_provider_type = CRYPTO_HW_PROVIDER,
	.pi_ops_vector = &viorand_crypto_ops,
};

/*
 * DDI entry points.
 */
int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&viorand_statep,
	    sizeof (viorand_state_t), 0);
	if (error != 0)
		return (error);

	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error == 0)
		ddi_soft_state_fini(&viorand_statep);

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * return buffer from free list.
 */
static viorand_rdbuf_t *
viorand_rbuf_alloc(viorand_state_t *state)
{
	viorand_rdbuf_t *rb;

	VERIFY(MUTEX_HELD(&state->vio_mutex));

	while ((rb = list_remove_head(&state->vio_rdbufs_free)) == NULL)
		cv_wait(&state->vio_cv, &state->vio_mutex);

	state->vio_rdbufs_alloc++;
	return (rb);
}

/*
 * return buffer to free list
 */
static void
viorand_rbuf_free(viorand_state_t *state, viorand_rdbuf_t *rb)
{
	VERIFY(MUTEX_HELD(&state->vio_mutex));
	VERIFY3U(state->vio_rdbufs_alloc, >, 0);

	state->vio_rdbufs_alloc--;
	virtio_chain_clear(rb->rb_chain);
	if (rb->rb_dma != NULL) {
		virtio_dma_free(rb->rb_dma);
		rb->rb_dma = NULL;
	}
	list_insert_head(&state->vio_rdbufs_free, rb);
}

/*
 * Free all allocated buffers. This is called to clean everything up,
 * so we do not want to leave anything around.
 */
static void
viorand_free_bufs(viorand_state_t *state)
{
	VERIFY(MUTEX_HELD(&state->vio_mutex));

	for (uint_t i = 0; i < state->vio_rdbufs_capacity; i++) {
		viorand_rdbuf_t *rb = &state->vio_rdbuf_mem[i];

		if (rb->rb_dma != NULL) {
			virtio_dma_free(rb->rb_dma);
			rb->rb_dma = NULL;
		}

		if (rb->rb_chain != NULL) {
			virtio_chain_free(rb->rb_chain);
			rb->rb_chain = NULL;
		}
	}

	if (state->vio_rdbuf_mem != NULL) {
		kmem_free(state->vio_rdbuf_mem,
		    sizeof (viorand_rdbuf_t) * state->vio_rdbufs_capacity);
		state->vio_rdbuf_mem = NULL;
		state->vio_rdbufs_capacity = 0;
		state->vio_rdbufs_alloc = 0;
	}
}

static int
viorand_alloc_bufs(viorand_state_t *state)
{
	VERIFY(MUTEX_HELD(&state->vio_mutex));

	state->vio_rdbufs_capacity = virtio_queue_size(state->vio_rq);
	state->vio_rdbuf_mem = kmem_zalloc(sizeof (viorand_rdbuf_t) *
	    state->vio_rdbufs_capacity, KM_SLEEP);
	list_create(&state->vio_rdbufs_free, sizeof (viorand_rdbuf_t),
	    offsetof(viorand_rdbuf_t, rb_link));

	/* Put everything in free list. */
	for (uint_t i = 0; i < state->vio_rdbufs_capacity; i++)
		list_insert_tail(&state->vio_rdbufs_free,
		    &state->vio_rdbuf_mem[i]);

	for (viorand_rdbuf_t *rb = list_head(&state->vio_rdbufs_free);
	    rb != NULL; rb = list_next(&state->vio_rdbufs_free, rb)) {
		rb->rb_viornd = state;
		rb->rb_chain = virtio_chain_alloc(state->vio_rq, KM_SLEEP);
		if (rb->rb_chain == NULL)
			goto fail;

		virtio_chain_data_set(rb->rb_chain, rb);
	}
	return (0);

fail:
	viorand_free_bufs(state);
	return (ENOMEM);
}

static int
viorand_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	int rv = 0;
	viorand_state_t *state;
	virtio_t *vio;

	switch (cmd) {
	case DDI_ATTACH:
		break;

	case DDI_RESUME:
	default:
		return (DDI_FAILURE);
	}

	if (ddi_soft_state_zalloc(viorand_statep, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	vio = virtio_init(dip, VIORAND_FEATURES, B_TRUE);
	if (vio == NULL) {
		ddi_soft_state_free(viorand_statep, instance);
		return (DDI_FAILURE);
	}

	state = ddi_get_soft_state(viorand_statep, instance);
	state->vio_dip = dip;
	state->vio_virtio = vio;
	state->vio_rq = virtio_queue_alloc(vio, VIORAND_RQ, "requestq",
	    viorand_interrupt, state, B_FALSE, 1);
	if (state->vio_rq == NULL) {
		virtio_fini(state->vio_virtio, B_TRUE);
		ddi_soft_state_free(viorand_statep, instance);
		return (DDI_FAILURE);
	}

	if (virtio_init_complete(state->vio_virtio, VIRTIO_ANY_INTR_TYPE) !=
	    DDI_SUCCESS) {
		virtio_fini(state->vio_virtio, B_TRUE);
		ddi_soft_state_free(viorand_statep, instance);
		return (DDI_FAILURE);
	}

	cv_init(&state->vio_cv, NULL, CV_DRIVER, NULL);
	mutex_init(&state->vio_mutex, NULL, MUTEX_DRIVER, virtio_intr_pri(vio));
	mutex_enter(&state->vio_mutex);

	if (viorand_alloc_bufs(state) != 0) {
		mutex_exit(&state->vio_mutex);
		dev_err(dip, CE_WARN, "failed to allocate memory");
		goto fail;
	}
	mutex_exit(&state->vio_mutex);

	viorand_prov_info.pi_provider_dev.pd_hw = dip;
	viorand_prov_info.pi_provider_handle = state;

	if (virtio_interrupts_enable(state->vio_virtio) != DDI_SUCCESS)
		goto fail;

	rv = crypto_register_provider(&viorand_prov_info, &state->vio_handle);
	if (rv == CRYPTO_SUCCESS) {
		return (DDI_SUCCESS);
	}

fail:
	virtio_interrupts_disable(state->vio_virtio);
	mutex_enter(&state->vio_mutex);
	viorand_free_bufs(state);
	mutex_exit(&state->vio_mutex);
	cv_destroy(&state->vio_cv);
	mutex_destroy(&state->vio_mutex);
	virtio_fini(state->vio_virtio, B_TRUE);
	ddi_soft_state_free(viorand_statep, instance);
	return (DDI_FAILURE);
}

static int
viorand_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance = ddi_get_instance(dip);
	viorand_state_t *state = ddi_get_soft_state(viorand_statep, instance);

	switch (cmd) {
	case DDI_DETACH:
		if (!virtio_registered)
			break;

		/* FALLTHROUGH */
	case DDI_SUSPEND:
	default:
		return (DDI_FAILURE);
	}

	if (crypto_unregister_provider(state->vio_handle) != CRYPTO_SUCCESS)
		return (DDI_FAILURE);

	virtio_interrupts_disable(state->vio_virtio);
	virtio_shutdown(state->vio_virtio);

	mutex_enter(&state->vio_mutex);
	for (;;) {
		virtio_chain_t *vic;

		vic = virtio_queue_evacuate(state->vio_rq);
		if (vic == NULL)
			break;

		viorand_rbuf_free(state, virtio_chain_data(vic));
	}

	viorand_free_bufs(state);
	mutex_exit(&state->vio_mutex);
	cv_destroy(&state->vio_cv);
	mutex_destroy(&state->vio_mutex);
	(void) virtio_fini(state->vio_virtio, B_FALSE);
	ddi_soft_state_free(viorand_statep, instance);
	return (DDI_SUCCESS);
}

static int
viorand_quiesce(dev_info_t *dip)
{
	int instance = ddi_get_instance(dip);
	viorand_state_t *state = ddi_get_soft_state(viorand_statep, instance);

	if (state == NULL)
		return (DDI_FAILURE);

	return (virtio_quiesce(state->vio_virtio));
}

/*
 * Control entry points.
 */
static void
viorand_provider_status(crypto_provider_handle_t provider __unused,
    uint_t *status)
{
	*status = CRYPTO_PROVIDER_READY;
}

static boolean_t
viorand_submit_request(viorand_rdbuf_t *rb)
{
	if (virtio_chain_append(rb->rb_chain,
	    virtio_dma_cookie_pa(rb->rb_dma, 0),
	    rb->rb_req_len,
	    VIRTIO_DIR_DEVICE_WRITES) != DDI_SUCCESS) {
		return (B_FALSE);
	}

	virtio_dma_sync(rb->rb_dma, DDI_DMA_SYNC_FORDEV);
	virtio_chain_submit(rb->rb_chain, B_TRUE);
	return (B_TRUE);
}

/* We got portion of data, process it */
static void
viorand_process_data(viorand_rdbuf_t *rb)
{
	size_t len;
	int error = CRYPTO_SUCCESS;

	len = MIN(rb->rb_req_len, rb->rb_recv_len);
	bcopy(virtio_dma_va(rb->rb_dma, 0), rb->rb_req_buf, len);
	bzero(virtio_dma_va(rb->rb_dma, 0), len);
	if (len < rb->rb_req_len) {
		rb->rb_req_len -= len;
		rb->rb_req_buf += len;
		/* Try to get reminder */
		if (viorand_submit_request(rb))
			return;

		/* Release our buffer and return error */
		viorand_rbuf_free(rb->rb_viornd, rb);
		error = CRYPTO_HOST_MEMORY;
	} else {
		/* Got all the data, free our buffer */
		viorand_rbuf_free(rb->rb_viornd, rb);
	}
	crypto_op_notification(rb->rb_req_handle, error);
}

static uint_t
viorand_interrupt(caddr_t a, caddr_t b __unused)
{
	viorand_state_t *state = (viorand_state_t *)a;
	virtio_chain_t *vic;
	boolean_t notify = B_FALSE;

	mutex_enter(&state->vio_mutex);
	while ((vic = virtio_queue_poll(state->vio_rq)) != NULL) {
		/* Actual received len and our read buffer */
		size_t len = virtio_chain_received_length(vic);
		viorand_rdbuf_t *rb = virtio_chain_data(vic);

		virtio_dma_sync(rb->rb_dma, DDI_DMA_SYNC_FORCPU);
		rb->rb_recv_len = len;
		viorand_process_data(rb);
		notify = B_TRUE;
	}
	if (notify)
		cv_broadcast(&state->vio_cv);
	mutex_exit(&state->vio_mutex);
	if (notify)
		return (DDI_INTR_CLAIMED);
	return (DDI_INTR_UNCLAIMED);
}

/*
 * Random number entry point.
 */
static int
viorand_generate_random(crypto_provider_handle_t provider,
    crypto_session_id_t sid __unused, uchar_t *buf, size_t len,
    crypto_req_handle_t req)
{
	viorand_state_t *state = provider;
	viorand_rdbuf_t *rb;

	mutex_enter(&state->vio_mutex);
	rb = viorand_rbuf_alloc(state);
	mutex_exit(&state->vio_mutex);

	rb->rb_req_buf = buf;
	rb->rb_req_len = len;
	rb->rb_req_handle = req;

	rb->rb_dma = virtio_dma_alloc(state->vio_virtio, len,
	    &viorand_dma_attr, DDI_DMA_READ | DDI_DMA_STREAMING, KM_SLEEP);
	if (rb->rb_dma == NULL) {
		goto error;
	}

	if (viorand_submit_request(rb))
		return (CRYPTO_QUEUED);

error:
	mutex_enter(&state->vio_mutex);
	viorand_rbuf_free(state, rb);
	mutex_exit(&state->vio_mutex);
	return (CRYPTO_HOST_MEMORY);
}
