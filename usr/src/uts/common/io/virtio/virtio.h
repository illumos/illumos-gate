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
 * Copyright 2019 Joyent, Inc.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2025 Oxide Computer Company
 * Copyright 2026 Hans Rosenfeld
 */

#ifndef _VIRTIO_H
#define	_VIRTIO_H

/*
 * VIRTIO FRAMEWORK
 *
 * This framework handles the initialisation and operation common to all Virtio
 * device types; e.g., Virtio Block (vioblk), Virtio Network (vioif), etc.  The
 * framework provides a driver for what is known as a "legacy", "modern" or
 * "transitional" device and will use the modern VirtIO interface when talking
 * to modern or transitional devices.
 *
 * FRAMEWORK INITIALISATION: STARTING
 *
 * Client drivers will, in their attach(9E) routine, make an early call to
 * virtio_init().  This causes the framework to allocate some base resources
 * and begin initialising the device.  This routine determine which mode the
 * device will operate in. A failure here means that we cannot presently
 * support this device.
 *
 * Once virtio_init() returns, the initialisation phase has begun and the
 * driver can examine the features advertised by the device and may read (but
 * NOT write) the device-specific configuration to determine which features it
 * wishes to advertise, or whether it wants to support the device at all. When
 * ready, the driver will call virtio_init_features() to complete feature
 * negotiation. The initialisation phase ends when the driver calls either
 * virtio_init_complete() or virtio_fini().
 *
 * FRAMEWORK INITIALISATION: FEATURE NEGOTIATION
 *
 * The virtio_init_features() call accepts a bitmask of desired features that
 * the driver supports.  The framework will negotiate the common set of
 * features supported by both the driver and the device.  The presence of any
 * individual feature can be tested after the initialisation phase has begun
 * using virtio_feature_present(). Feature negotiation may fail, indicated by
 * virtio_init_features() returning false.
 *
 * The framework will additionally negotiate some set of features that are not
 * specific to a device type on behalf of the client driver; e.g., support for
 * indirect descriptors.
 *
 * Some features allow the driver to read additional configuration values from
 * the device-specific regions of the device register space.  These can be
 * accessed via the virtio_dev_get*() and virtio_dev_put*() family of
 * functions. The modern interface also provides a configuration generation
 * number which can be retrieved via virtio_dev_getgen(). This allows drivers
 * to check if something in the configuration space has changed while reading
 * values in separate transactions.
 *
 * FRAMEWORK INITIALISATION: VIRTQUEUE CONFIGURATION
 *
 * During the initialisation phase, the client driver may configure some number
 * of virtqueues with virtio_queue_alloc().  Once initialisation has been
 * completed, no further queues can be configured without destroying the
 * framework object and beginning again from scratch.
 *
 * When configuring a queue, the driver must know the queue index number.  This
 * generally comes from the section of the specification describing the
 * specific device type; e.g., Unless they negotiate multi-queue, virtio
 * Network devices have a receive queue at index 0, and a transmit queue at
 * index 1.  The name given to the queue is informational and has no impact on
 * device operation.
 *
 * Most queues will require an interrupt handler function.  When a queue
 * notification interrupt is received, the provided handler will be called with
 * two arguments: first, the provided user data argument; and second, a pointer
 * to the "virtio_t" object for this instance.
 *
 * A maximum segment count must be selected for each queue.  This count is the
 * upper bound on the number of scatter-gather cookies that will be accepted,
 * and applies to both direct and indirect descriptor based queues.  This cap
 * is usually either negotiated with the device, or determined structurally
 * based on the shape of the buffers required for device operation.
 *
 * FRAMEWORK INITIALISATION: CONFIGURATION SPACE CHANGE HANDLER
 *
 * During the initialisation phase, the client driver may register a handler
 * function for receiving device configuration space change events.  Once
 * initialisation has been completed, this cannot be changed without destroying
 * the framework object and beginning again from scratch.
 *
 * When a configuration space change interrupt is received, the provided
 * handler will be called with two arguments: first, the provided user data
 * argument; and second, a pointer to the "virtio_t" object for this instance.
 * The handler is called in an interrupt context.
 *
 * FRAMEWORK INITIALISATION: FINISHING
 *
 * Once queue configuration has been completed, the client driver calls
 * virtio_init_complete() to finalise resource allocation and set the device to
 * the running state (DRIVER_OK).  The framework will allocate any interrupts
 * needed for queue notifications at this time.
 *
 * If the client driver cannot complete initialisation, the instance may
 * instead be torn down with virtio_fini().  Signalling failure to this routine
 * will report failure to the device instead of resetting it, which may be
 * reported by the hypervisor as a fault.
 *
 * DESCRIPTOR CHAINS
 *
 * Most devices accept I/O requests from the driver through a least one queue.
 * Some devices are operated by submission of synchronous requests.  The device
 * is expected to process the request and return some kind of status; e.g., a
 * block device accepts write requests from the file system and signals when
 * they have completed or failed.
 *
 * Other devices operate by asynchronous delivery of I/O requests to the
 * driver; e.g., a network device may receive incoming frames at any time.
 * Inbound asynchronous delivery is usually achieved by populating a queue with
 * a series of memory buffers where the incoming data will be written by the
 * device at some later time.
 *
 * Whether for inbound or outbound transfers, buffers are inserted into the
 * ring through chains of one or more descriptors.  Each descriptor has a
 * transfer direction (to or from the device), and a physical address and
 * length (i.e., a DMA cookie).  The framework automatically manages the slight
 * differences in operation between direct and indirect descriptor usage on
 * behalf of the client driver.
 *
 * A chain of descriptors is allocated by calling virtio_chain_alloc() against
 * a particular queue.  This function accepts a kmem flag as per
 * kmem_alloc(9F).  A client driver specific void pointer may be attached to
 * the chain with virtio_chain_data_set() and read back later with
 * virtio_chain_data(); e.g., after it is returned by a call to
 * virtio_queue_poll().
 *
 * Cookies are added to a chain by calling virtio_chain_append() with the
 * appropriate physical address and transfer direction.  This function may fail
 * if the chain is already using the maximum number of cookies for this queue.
 * Client drivers are responsible for appropriate use of virtio_dma_sync()
 * or ddi_dma_sync(9F) on any memory appended to a descriptor chain prior to
 * chain submission.
 *
 * Once fully constructed and synced, a chain can be submitted to the device by
 * calling virtio_chain_submit().  The caller may choose to flush the queue
 * contents to the device on each submission, or to batch notifications until
 * later to amortise the notification cost over more requests.  If batching
 * notifications, outstanding submissions can be flushed with a call to
 * virtio_queue_flush().  Note that the framework will insert an appropriate
 * memory barrier to ensure writes by the driver complete before making the
 * submitted descriptor visible to the device.
 *
 * A chain may be reset for reuse with new cookies by calling
 * virtio_chain_clear().  The chain may be freed completely by calling
 * virtio_chain_free().
 *
 * When a descriptor chain is returned to the driver by the device, it may
 * include a received data length value.  This value can be accessed via
 * virtio_chain_received_length().  There is some suggestion in more recent
 * Virtio specifications that, depending on the device type and the hypervisor
 * this value may not always be accurate or useful.
 *
 * VIRTQUEUE OPERATION
 *
 * The queue size (i.e., the number of direct descriptor entries) can be
 * found with virtio_queue_size().  This value is static over the lifetime
 * of the queue.
 *
 * The number of descriptor chains presently submitted to the device and not
 * yet returned can be obtained via virtio_queue_nactive().
 *
 * Over time the device will return descriptor chains to the driver in response
 * to device activity.  Any newly returned chains may be retrieved by the
 * driver by calling virtio_queue_poll().  See the DESCRIPTOR CHAINS section
 * for more detail about managing descriptor chain objects.  Note that the
 * framework will insert an appropriate memory barrier to ensure that writes by
 * the host are complete before returning the chain to the client driver.
 *
 * The NO_INTERRUPT flag on a queue may be set or cleared with
 * virtio_queue_no_interrupt().  Note that this flag is purely advisory, and
 * may not actually stop interrupts from the device in a timely fashion.
 *
 * INTERRUPT MANAGEMENT
 *
 * A mutex used within an interrupt handler must be initialised with the
 * correct interrupt priority.  After the initialisation phase is complete, the
 * client should use virtio_intr_pri() to get a value suitable to pass to
 * mutex_init(9F).
 *
 * When the driver is ready to receive notifications from the device, the
 * virtio_interrupts_enable() routine may be called.  Interrupts may be
 * disabled again by calling virtio_interrupts_disable().  Interrupt resources
 * will be deallocated as part of a subsequent call to virtio_fini().
 *
 * DMA MEMORY MANAGEMENT: ALLOCATION AND FREE
 *
 * Client drivers may allocate memory suitable for communication with the
 * device by using virtio_dma_alloc().  This function accepts an allocation
 * size, a DMA attribute template, a set of DMA flags, and a kmem flag.
 * A "virtio_dma_t" object is returned to track and manage the allocation.
 *
 * The DMA flags value will be a combination of direction flags (e.g.,
 * DDI_DMA_READ or DDI_DMA_WRITE) and mapping flags (e.g., DDI_DMA_CONSISTENT
 * or DDI_DMA_STREAMING).  The kmem flag is either KM_SLEEP or KM_NOSLEEP,
 * as described in kmem_alloc(9F).
 *
 * Memory that is no longer required can be freed using virtio_dma_free().
 *
 * DMA MEMORY MANAGEMENT: BINDING WITHOUT ALLOCATION
 *
 * If another subsystem has loaned memory to your client driver, you may need
 * to allocate and bind a handle without additional backing memory.  The
 * virtio_dma_alloc_nomem() function can be used for this purpose, returning a
 * "virtio_dma_t" object.
 *
 * Once allocated, an arbitrary kernel memory location can be bound for DMA
 * with virtio_dma_bind().  The binding can be subsequently undone with
 * virtio_dma_unbind(), allowing the "virtio_dma_t" object to be reused for
 * another binding.
 *
 * DMA MEMORY MANAGEMENT: VIRTUAL AND PHYSICAL ADDRESSES
 *
 * The total size of a mapping (with or without own backing memory) can be
 * found with virtio_dma_size().  A void pointer to a kernel virtual address
 * within the buffer can be obtained via virtio_dma_va(); this function accepts
 * a linear offset into the VA range and performs bounds checking.
 *
 * The number of physical memory addresses (DMA cookies) can be found with
 * virtio_dma_ncookies().  The physical address and length of each cookie can
 * be found with virtio_dma_cookie_pa() and virtio_dma_cookie_size(); these
 * functions are keyed on the zero-indexed cookie number.
 *
 * DMA MEMORY MANAGEMENT: SYNCHRONISATION
 *
 * When passing memory to the device, or reading memory returned from the
 * device, DMA synchronisation must be performed in case it is required by the
 * underlying platform.  A convenience wrapper exists: virtio_dma_sync().  This
 * routine synchronises the entire binding and accepts the same synchronisation
 * type values as ddi_dma_sync(9F).
 *
 * QUIESCE
 *
 * As quiesce(9E) merely requires that the device come to a complete stop, most
 * client drivers will be able to call virtio_quiesce() without additional
 * actions.  This will reset the device, immediately halting all queue
 * activity, and return a value suitable for returning from the client driver
 * quiesce(9E) entrypoint.  This routine must only be called from quiesce
 * context as it performs no synchronisation with other threads.
 *
 * DETACH
 *
 * Some devices are effectively long-polled; that is, they submit some number
 * of descriptor chains to the device that are not returned to the driver until
 * some asynchronous event occurs such as the receipt of an incoming packet or
 * a device hot plug event.  When detaching the device the return of these
 * outstanding buffers must be arranged.  Some device types may have task
 * management commands that can force the orderly return of these chains, but
 * the only way to do so uniformly is to reset the device and claw back the
 * memory.
 *
 * If the client driver has outstanding descriptors and needs a hard stop on
 * device activity it can call virtio_shutdown().  This routine will bring
 * queue processing to an orderly stop and then reset the device, causing it to
 * cease use of any DMA resources.  Once this function returns, the driver may
 * call virtio_queue_evacuate() on each queue to retrieve any previously
 * submitted chains.
 *
 * To tear down resources (e.g., interrupts and allocated memory) the client
 * driver must finally call virtio_fini().  If virtio_shutdown() was not
 * needed, this routine will also reset the device.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct virtio virtio_t;
typedef struct virtio_queue virtio_queue_t;
typedef struct virtio_chain virtio_chain_t;
typedef struct virtio_dma virtio_dma_t;

typedef enum virtio_direction {
	/*
	 * In the base specification, a descriptor is either set up to be
	 * written by the device or to be read by the device, but not both.
	 */
	VIRTIO_DIR_DEVICE_WRITES = 1,
	VIRTIO_DIR_DEVICE_READS
} virtio_direction_t;

void virtio_fini(virtio_t *, boolean_t);
virtio_t *virtio_init(dev_info_t *);
boolean_t virtio_init_features(virtio_t *, uint64_t, boolean_t);
int virtio_init_complete(virtio_t *, int);
int virtio_quiesce(virtio_t *);
void virtio_shutdown(virtio_t *);

void virtio_register_cfgchange_handler(virtio_t *, ddi_intr_handler_t *,
    void *);

void *virtio_intr_pri(virtio_t *);

void virtio_device_reset(virtio_t *);

uint8_t virtio_dev_getgen(virtio_t *);
uint8_t virtio_dev_get8(virtio_t *, uintptr_t);
uint16_t virtio_dev_get16(virtio_t *, uintptr_t);
uint32_t virtio_dev_get32(virtio_t *, uintptr_t);
uint64_t virtio_dev_get64(virtio_t *, uintptr_t);

void virtio_dev_put8(virtio_t *, uintptr_t, uint8_t);
void virtio_dev_put16(virtio_t *, uintptr_t, uint16_t);
void virtio_dev_put32(virtio_t *, uintptr_t, uint32_t);

boolean_t virtio_features_present(virtio_t *, uint64_t);
uint32_t virtio_features(virtio_t *);
boolean_t virtio_modern(virtio_t *);

virtio_queue_t *virtio_queue_alloc(virtio_t *, uint16_t, const char *,
    ddi_intr_handler_t *, void *, boolean_t, uint_t);

virtio_chain_t *virtio_queue_poll(virtio_queue_t *);
virtio_chain_t *virtio_queue_evacuate(virtio_queue_t *);
void virtio_queue_flush(virtio_queue_t *);
void virtio_queue_no_interrupt(virtio_queue_t *, boolean_t);
uint_t virtio_queue_nactive(virtio_queue_t *);
uint_t virtio_queue_size(virtio_queue_t *);

virtio_chain_t *virtio_chain_alloc(virtio_queue_t *, int);
void virtio_chain_clear(virtio_chain_t *);
void virtio_chain_free(virtio_chain_t *);
int virtio_chain_append(virtio_chain_t *, uint64_t, size_t, virtio_direction_t);

void *virtio_chain_data(virtio_chain_t *);
void virtio_chain_data_set(virtio_chain_t *, void *);

void virtio_chain_submit(virtio_chain_t *, boolean_t);
size_t virtio_chain_received_length(virtio_chain_t *);

int virtio_interrupts_enable(virtio_t *);
void virtio_interrupts_disable(virtio_t *);

virtio_dma_t *virtio_dma_alloc(virtio_t *, size_t, const ddi_dma_attr_t *, int,
    int);
virtio_dma_t *virtio_dma_alloc_nomem(virtio_t *, const ddi_dma_attr_t *, int);
void virtio_dma_free(virtio_dma_t *);
int virtio_dma_bind(virtio_dma_t *, void *, size_t, int, int);
void virtio_dma_unbind(virtio_dma_t *);
void virtio_dma_sync(virtio_dma_t *, int);

void *virtio_dma_va(virtio_dma_t *, size_t);
size_t virtio_dma_size(virtio_dma_t *);
uint_t virtio_dma_ncookies(virtio_dma_t *);
uint64_t virtio_dma_cookie_pa(virtio_dma_t *, uint_t);
size_t virtio_dma_cookie_size(virtio_dma_t *, uint_t);

/*
 * virtio_init_complete() accepts a mask of allowed interrupt types using the
 * DDI_INTR_TYPE_* family of constants.  If no specific interrupt type is
 * required, pass VIRTIO_ANY_INTR_TYPE instead:
 */
#define	VIRTIO_ANY_INTR_TYPE	0

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_H */
