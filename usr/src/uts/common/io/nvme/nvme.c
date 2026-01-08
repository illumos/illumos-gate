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
 * Copyright (c) 2016 The MathWorks, Inc.  All rights reserved.
 * Copyright 2019 Unix Software Ltd.
 * Copyright 2020 Joyent, Inc.
 * Copyright 2020 Racktop Systems.
 * Copyright 2026 Oxide Computer Company.
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2022 Tintri by DDN, Inc. All rights reserved.
 */

/*
 * blkdev driver for NVMe compliant storage devices
 *
 * This driver targets and is designed to support all NVMe 1.x and NVMe 2.x
 * devices. Features are added to the driver as we encounter devices that
 * require them and our needs, so some commands or log pages may not take
 * advantage of newer features that devices support at this time. When you
 * encounter such a case, it is generally fine to add that support to the driver
 * as long as you take care to ensure that the requisite device version is met
 * before using it.
 *
 * The driver has only been tested on x86 systems and will not work on big-
 * endian systems without changes to the code accessing registers and data
 * structures used by the hardware.
 *
 * ---------------
 * Interrupt Usage
 * ---------------
 *
 * The driver will use a single interrupt while configuring the device as the
 * specification requires, but contrary to the specification it will try to use
 * a single-message MSI(-X) or FIXED interrupt. Later in the attach process it
 * will switch to multiple-message MSI(-X) if supported. The driver wants to
 * have one interrupt vector per CPU, but it will work correctly if less are
 * available. Interrupts can be shared by queues, the interrupt handler will
 * iterate through the I/O queue array by steps of n_intr_cnt. Usually only
 * the admin queue will share an interrupt with one I/O queue. The interrupt
 * handler will retrieve completed commands from all queues sharing an interrupt
 * vector and will post them to a taskq for completion processing.
 *
 * ------------------
 * Command Processing
 * ------------------
 *
 * NVMe devices can have up to 65535 I/O queue pairs, with each queue holding up
 * to 65536 I/O commands. The driver will configure one I/O queue pair per
 * available interrupt vector, with the queue length usually much smaller than
 * the maximum of 65536. If the hardware doesn't provide enough queues, fewer
 * interrupt vectors will be used.
 *
 * Additionally the hardware provides a single special admin queue pair that can
 * hold up to 4096 admin commands.
 *
 * From the hardware perspective both queues of a queue pair are independent,
 * but they share some driver state: the command array (holding pointers to
 * commands currently being processed by the hardware) and the active command
 * counter. Access to a submission queue and the shared state is protected by
 * nq_mutex; completion queue is protected by ncq_mutex.
 *
 * When a command is submitted to a queue pair the active command counter is
 * incremented and a pointer to the command is stored in the command array. The
 * array index is used as command identifier (CID) in the submission queue
 * entry. Some commands may take a very long time to complete, and if the queue
 * wraps around in that time a submission may find the next array slot to still
 * be used by a long-running command. In this case the array is sequentially
 * searched for the next free slot. The length of the command array is the same
 * as the configured queue length. Queue overrun is prevented by the semaphore,
 * so a command submission may block if the queue is full.
 *
 * ------------------
 * Polled I/O Support
 * ------------------
 *
 * For kernel core dump support the driver can do polled I/O. As interrupts are
 * turned off while dumping the driver will just submit a command in the regular
 * way, and then repeatedly attempt a command retrieval until it gets the
 * command back.
 *
 * -----------------
 * Namespace Support
 * -----------------
 *
 * NVMe devices can have multiple namespaces, each being a independent data
 * store. The driver supports multiple namespaces and creates a blkdev interface
 * for each namespace found. Namespaces can have various attributes to support
 * protection information. This driver does not support any of this and ignores
 * namespaces that have these attributes.
 *
 * As of NVMe 1.1 namespaces can have an 64bit Extended Unique Identifier
 * (EUI64), and NVMe 1.2 introduced an additional 128bit Namespace Globally
 * Unique Identifier (NGUID). This driver uses either the NGUID or the EUI64
 * if present to generate the devid, and passes the EUI64 to blkdev to use it
 * in the device node names.
 *
 * When a device has more than (2 << NVME_MINOR_INST_SHIFT) - 2 namespaces in a
 * single controller, additional namespaces will not have minor nodes created.
 * They can still be used and specified by the controller and libnvme. This
 * limit is trying to balance the number of controllers and namespaces while
 * fitting within the constraints of MAXMIN32, aka a 32-bit device number which
 * only has 18-bits for the minor number. See the minor node section for more
 * information.
 *
 * The driver supports namespace management, meaning the ability to create and
 * destroy namespaces, and to attach and detach namespaces from controllers.
 * Each namespace has an associated nvme_ns_state_t, which transitions through
 * several states. The UNALLOCATED, ALLOCATED, and ACTIVE states are states that
 * are defined by the NVMe specification. Not all ACTIVE namespaces may be
 * attached to blkdev(4D) due to the use of features we don't support, for
 * example, metadata protection. Such namespaces are automatically in the
 * NOT_IGNORED state. Once they are attached to blkdev they enter the ATTACHED
 * state.
 *
 * By default, a device can only transition one such state at a time. Each
 * command that transitions between states has a corresponding array of errnos
 * to use to transition. Examples of this are the nvme_ns_delete_states[],
 * nvme_ctrl_attach_states[], etc. These dictate whether it is okay or not for a
 * command that changes state to occur or not based on the current state. Each
 * of these returns a specific error allowing one to understand why something
 * isn't in the proper state. This allows library consumers to determine whether
 * or not a namespace is already in the current state it's targeting to be
 * ignored or not. The following diagram summarizes namespace transitions:
 *
 *                       +-------------+
 *                       |             |
 *                       | Unallocated |
 *                       |             |
 *                       +-------------+
 *                          |       ^
 *                          |       |
 * Namespace Management: . .*       * . . . Namespace Management:
 * Create                   |       |       Delete
 * NVME_IOC_NS_CREATE       |       |       NVME_IOC_NS_DELETE
 *                          v       |
 *                       +-------------+
 *                       |             |
 *                       |  Allocated  |
 *                       |             |
 *                       +-------------+
 *                          |       ^
 *                          |       |
 * Namespace Attachment: . .*       * . . . Namespace Attachment:
 * Controller Attach        |       |       Controller Detach
 * NVME_IOC_CTRL_ATTACH     |       |       NVME_IOC_CTRL_DETACH
 *                          v       |
 *              +------------+      |
 *              |            |      |     +----------+
 *              |   Active   |>-----+----<|   Not    |
 *              |            |--*-------->| Ignored  |
 *              +------------+  .         +----------+
 *                              .           |      ^
 *    automatic kernel transition           |      |
 *                                          |      * . . blkdev Detach
 *                       blkdev attach  . . *      |     NVME_IOC_BD_DETACH
 *                       NVME_IOC_BD_ATTACH |      |
 *                                          v      |
 *                                        +----------+
 *                                        |          |
 *                                        |  blkdev  |
 *                                        | attached |
 *                                        |          |
 *                                        +----------+
 *
 * -----------
 * Minor nodes
 * -----------
 *
 * For each NVMe device the driver exposes one minor node for the controller and
 * one minor node for each namespace. The only operations supported by those
 * minor nodes are open(9E), close(9E), and ioctl(9E). This serves as the
 * primary control interface for the devices. The character device is a private
 * interface and we attempt stability through libnvme and more so nvmeadm.
 *
 * The controller minor node is much more flexible than the namespace minor node
 * and should be preferred. The controller node allows one to target any
 * namespace that the device has, while the namespace is limited in what it can
 * acquire. While the namespace minor exists, it should not be relied upon and
 * is not by libnvme.
 *
 * The minor number space is split in two. We use the lower part to support the
 * controller and namespaces as described above in the 'Namespace Support'
 * section. The second set is used for cloning opens. We set aside one million
 * minors for this purpose. We utilize a cloning open so that way we can have
 * per-file_t state. This is how we end up implementing and tracking locking
 * state and related.
 *
 * When we have this cloned open, then we allocate a new nvme_minor_t which gets
 * its minor number from the nvme_open_minors id_space_t and is stored in the
 * nvme_open_minors_avl. While someone calls open on a controller or namespace
 * minor, everything else occurs in the context of one of these ephemeral
 * minors.
 *
 * ------------------------------------
 * ioctls, Errors, and Exclusive Access
 * ------------------------------------
 *
 * All of the logical commands that one can issue are driven through the
 * ioctl(9E) interface. All of our ioctls have a similar shape where they
 * all include the 'nvme_ioctl_common_t' as their first member.
 *
 * This common ioctl structure is used to communicate the namespace that should
 * be targeted. When the namespace is left as 0, then that indicates that it
 * should target whatever the default is of the minor node. For a namespace
 * minor, that will be transparently rewritten to the namespace's namespace id.
 *
 * In addition, the nvme_ioctl_common_t structure also has a standard error
 * return. Our goal in our ioctl path is to ensure that we have useful semantic
 * errors as much as possible. EINVAL, EIO, etc. are all overloaded. Instead as
 * long as we can copy in our structure, then we will set a semantic error. If
 * we have an error from the controller, then that will be included there.
 *
 * Each command has a specific policy that controls whether or not it is allowed
 * on the namespace or controller minor, whether the broadcast namespace is
 * allowed, various settings around what kind of exclusive access is allowed,
 * and more. Each of these is wrapped up in a bit of policy described by the
 * 'nvme_ioctl_check_t' structure.
 *
 * The device provides a form of exclusion in the form of both a
 * controller-level and namespace-level read and write lock. Most operations do
 * not require a lock (e.g. get log page, identify, etc.), but a few do (e.g.
 * format nvm, firmware related activity, etc.). A read lock guarantees that you
 * can complete your operation without interference, but read locks are not
 * required. If you don't take a read lock and someone comes in with a write
 * lock, then subsequent operations will fail with a semantic error indicating
 * that you were blocked due to this.
 *
 * Here are some of the rules that govern our locks:
 *
 * 1. Writers starve readers. Any readers are allowed to finish when there is a
 *    pending writer; however, all subsequent readers will be blocked upon that
 *    writer.
 * 2. A controller write lock takes priority over all other locks. Put
 *    differently a controller writer not only starves subsequent controller
 *    readers, but also all namespace read and write locks.
 * 3. Each namespace lock is independent.
 * 4. At most a single namespace lock may be owned.
 * 5. If you own a namespace lock, you may not take a controller lock (to help
 *    with lock ordering).
 * 6. In a similar spirit, if you own a controller write lock, you may not take
 *    any namespace lock. Someone with the controller write lock can perform any
 *    operations that they need to. However, if you have a controller read lock
 *    you may take any namespace lock.
 * 7. There is no ability to upgrade a read lock to a write lock.
 * 8. There is no recursive locking.
 *
 * While there's a lot there to keep track of, the goals of these are to
 * constrain things so as to avoid deadlock. This is more complex than the
 * original implementation in the driver which only allowed for an exclusive
 * open that was tied to the thread. The first issue with tying this to the
 * thread was that that didn't work well for software that utilized thread
 * pools, like complex daemons. The second issue is that we want the ability for
 * daemons, such as a FRU monitor, to be able to retain a file descriptor to the
 * device without blocking others from taking action except during critical
 * periods.
 *
 * In particular to enable something like libnvme, we didn't want someone to
 * have to open and close the file descriptor to change what kind of exclusive
 * access they desired.
 *
 * There are two different sets of data structures that we employ for tracking
 * locking information:
 *
 * 1) The nvme_lock_t structure is contained in both the nvme_t and the
 * nvme_namespace_t and tracks the current writer, readers, and pending writers
 * and readers. Each of these lists or the writer pointer all refer to our
 * second data structure.
 *
 * When a lock is owned by a single writer, then the nl_writer field is set to a
 * specific minor's lock data structure. If instead readers are present, then
 * the nl_readers list_t is not empty. An invariant of the system is that if
 * nl_writer is non-NULL, nl_readers must be empty and conversely, if nl_readers
 * is not empty, nl_writer must be NULL.
 *
 * 2) The nvme_minor_lock_info_t exists in the nvme_minor_t. There is one
 * information structure which represents the minor's controller lock and a
 * second one that represents the minor's namespace lock. The members of this
 * are broken into tracking what the current lock is and what it targets. It
 * also several members that are intended for debugging (nli_last_change,
 * nli_acq_kthread, etc.).
 *
 * While the minor has two different lock information structures, our rules
 * ensure that only one of the two can be pending and that they shouldn't result
 * in a deadlock. When a lock is pending, the caller is sleeping on the minor's
 * nm_cv member.
 *
 * These relationships are represented in the following image which shows a
 * controller write lock being held with a pending readers on the controller
 * lock and pending writers on one of the controller's namespaces.
 *
 *  +---------+
 *  | nvme_t  |
 *  |         |
 *  | n_lock -|-------+
 *  | n_ns -+ |       |                          +-----------------------------+
 *  +-------|-+   +-----------------+            | nvme_minor_t                |
 *          |     | nvme_lock_t     |            |                             |
 *          |     |                 |            |  +------------------------+ |
 *          |     | writer        --|-------------->| nvme_minor_lock_info_t | |
 *          |     | reader list     |            |  | nm_ctrl_lock           | |
 *          |     | pending writers |            |  +------------------------+ |
 *          |     | pending readers |------+     |  +------------------------+ |
 *          |     +-----------------+      |     |  | nvme_minor_lock_info_t | |
 *          |                              |     |  | nm_ns_lock             | |
 *          |                              |     |  +------------------------+ |
 *          |                              |     +-----------------------------+
 *  +------------------+                   |                 +-----------------+
 *  | nvme_namespace_t |                   |                 | nvme_minor_t    |
 *  |                  |                   |                 |                 |
 *  | ns_lock ---+     |                   |                 | +-------------+ |
 *  +------------|-----+                   +-----------------|>|nm_ctrl_lock | |
 *               |                                           | +-------------+ |
 *               v                                           +-----------------+
 *     +------------------+                                         ...
 *     | nvme_lock_t      |                                  +-----------------+
 *     |                  |                                  | nvme_minor_t    |
 *     | writer           |                                  |                 |
 *     | reader list      |                                  | +-------------+ |
 *     | pending writers -|-----------------+                | |nm_ctrl_lock | |
 *     | pending readers  |                 |                | +-------------+ |
 *     +------------------+                 |                +-----------------+
 *         +-----------------------------+  |  +-----------------------------+
 *         | nvme_minor_t                |  |  | nvme_minor_t                |
 *         |                             |  |  |                             |
 *         |  +------------------------+ |  |  |  +------------------------+ |
 *         |  | nvme_minor_lock_info_t | |  |  |  | nvme_minor_lock_info_t | |
 *         |  | nm_ctrl_lock           | |  |  |  | nm_ctrl_lock           | |
 *         |  +------------------------+ |  |  |  +------------------------+ |
 *         |  +------------------------+ |  v  |  +------------------------+ |
 *         |  | nvme_minor_lock_info_t |-|-----|->| nvme_minor_lock_info_t | |
 *         |  | nm_ns_lock             | |     |  | nm_ns_lock             | |
 *         |  +------------------------+ |     |  +------------------------+ |
 *         +-----------------------------+     +-----------------------------+
 *
 * ----------------
 * Blkdev Interface
 * ----------------
 *
 * This driver uses blkdev to do all the heavy lifting involved with presenting
 * a disk device to the system. As a result, the processing of I/O requests is
 * relatively simple as blkdev takes care of partitioning, boundary checks, DMA
 * setup, and splitting of transfers into manageable chunks.
 *
 * I/O requests coming in from blkdev are turned into NVM commands and posted to
 * an I/O queue. The queue is selected by taking the CPU id modulo the number of
 * queues. There is currently no timeout handling of I/O commands.
 *
 * Blkdev also supports querying device/media information and generating a
 * devid. The driver reports the best block size as determined by the namespace
 * format back to blkdev as physical block size to support partition and block
 * alignment. The devid is either based on the namespace GUID or EUI64, if
 * present, or composed using the device vendor ID, model number, serial number,
 * and the namespace ID.
 *
 * --------------
 * Error Handling
 * --------------
 *
 * Error handling is currently limited to detecting fatal hardware errors,
 * either by asynchronous events, or synchronously through command status or
 * admin command timeouts. In case of severe errors the device is fenced off,
 * all further requests will return EIO. FMA is then called to fault the device.
 *
 * The hardware has a limit for outstanding asynchronous event requests. Before
 * this limit is known the driver assumes it is at least 1 and posts a single
 * asynchronous request. Later when the limit is known more asynchronous event
 * requests are posted to allow quicker reception of error information. When an
 * asynchronous event is posted by the hardware the driver will parse the error
 * status fields and log information or fault the device, depending on the
 * severity of the asynchronous event. The asynchronous event request is then
 * reused and posted to the admin queue again.
 *
 * On command completion the command status is checked for errors. In case of
 * errors indicating a driver bug the driver panics. Almost all other error
 * status values just cause EIO to be returned.
 *
 * Command timeouts are currently detected for all admin commands except
 * asynchronous event requests. If a command times out and the hardware appears
 * to be healthy the driver attempts to abort the command. The abort command
 * timeout is a separate tunable but the original command timeout will be used
 * if it is greater. If the abort times out too the driver assumes the device
 * to be dead, fences it off, and calls FMA to retire it. In all other cases
 * the aborted command should return immediately with a status indicating it
 * was aborted, and the driver will wait indefinitely for that to happen. No
 * timeout handling of normal I/O commands is presently done.
 *
 * Any command that times out due to the controller dropping dead will be put on
 * nvme_lost_cmds list if it references DMA memory. This will prevent the DMA
 * memory being reused by the system and later being written to by a "dead"
 * NVMe controller.
 *
 * -------
 * Locking
 * -------
 *
 * Each queue pair has a nq_mutex and ncq_mutex. The nq_mutex must be held
 * when accessing shared state and submission queue registers, ncq_mutex
 * is held when accessing completion queue state and registers.
 * Callers of nvme_unqueue_cmd() must make sure that nq_mutex is held, while
 * nvme_submit_{admin,io}_cmd() and nvme_retrieve_cmd() take care of both
 * mutexes themselves.
 *
 * Each command also has its own nc_mutex, which is associated with the
 * condition variable nc_cv. It is only used on admin commands which are run
 * synchronously. In that case it must be held across calls to
 * nvme_submit_{admin,io}_cmd() and nvme_wait_cmd(), which is taken care of by
 * nvme_admin_cmd(). It must also be held whenever the completion state of the
 * command is changed or while an admin command timeout is handled.
 *
 * If both nc_mutex and nq_mutex must be held, nc_mutex must be acquired first.
 * More than one nc_mutex may only be held when aborting commands. In this case,
 * the nc_mutex of the command to be aborted must be held across the call to
 * nvme_abort_cmd() to prevent the command from completing while the abort is in
 * progress.
 *
 * If both nq_mutex and ncq_mutex need to be held, ncq_mutex must be
 * acquired first. More than one nq_mutex is never held by a single thread.
 * The ncq_mutex is only held by nvme_retrieve_cmd() and
 * nvme_process_iocq(). nvme_process_iocq() is only called from the
 * interrupt thread and nvme_retrieve_cmd() during polled I/O, so the
 * mutex is non-contentious but is required for implementation completeness
 * and safety.
 *
 * Each nvme_t has an n_admin_stat_mutex that protects the admin command
 * statistics structure. If this is taken in conjunction with any other locks,
 * then it must be taken last.
 *
 * There is one mutex n_minor_mutex which protects all open flags nm_open and
 * exclusive-open thread pointers nm_oexcl of each minor node associated with a
 * controller and its namespaces.
 *
 * In addition, there is a logical namespace management mutex which protects the
 * data about namespaces. When interrogating the metadata of any namespace, this
 * lock must be held. This gets tricky as we need to call into blkdev, which may
 * issue callbacks into us which want this and it is illegal to hold locks
 * across those blkdev calls as otherwise they might lead to deadlock (blkdev
 * leverages ndi_devi_enter()).
 *
 * The lock exposes two levels, one that we call 'NVME' and one 'BDRO' or blkdev
 * read-only. The idea is that most callers will use the NVME level which says
 * this is a full traditional mutex operation. The BDRO level is used by blkdev
 * callback functions and is a promise to only only read the data. When a blkdev
 * operation starts, the lock holder will use nvme_mgmt_bd_start(). This
 * strictly speaking drops the mutex, but records that the lock is logically
 * held by the thread that did the start() operation.
 *
 * During this time, other threads (or even the same one) may end up calling
 * into nvme_mgmt_lock(). Only one person may still hold the lock at any time;
 * however, the BRDO level will be allowed to proceed during this time. This
 * allows us to make consistent progress and honor the blkdev lock ordering
 * requirements, albeit it is not as straightforward as a simple mutex.
 *
 * ---------------------
 * Quiesce / Fast Reboot
 * ---------------------
 *
 * The driver currently does not support fast reboot. A quiesce(9E) entry point
 * is still provided which is used to send a shutdown notification to the
 * device.
 *
 *
 * ------------
 * NVMe Hotplug
 * ------------
 *
 * The driver supports hot removal. The driver uses the NDI event framework
 * to register a callback, nvme_remove_callback, to clean up when a disk is
 * removed. In particular, the driver will unqueue outstanding I/O commands and
 * set n_dead on the softstate to true so that other operations, such as ioctls
 * and command submissions, fail as well.
 *
 * While the callback registration relies on the NDI event framework, the
 * removal event itself is kicked off in the PCIe hotplug framework, when the
 * PCIe bridge driver ("pcieb") gets a hotplug interrupt indicating that a
 * device was removed from the slot.
 *
 * The NVMe driver instance itself will remain until the final close of the
 * device.
 *
 * ---------------
 * DDI UFM Support
 * ---------------
 *
 * The driver supports the DDI UFM framework for reporting information about
 * the device's firmware image and slot configuration. This data can be
 * queried by userland software via ioctls to the ufm driver. For more
 * information, see ddi_ufm(9E).
 *
 * --------------------
 * Driver Configuration
 * --------------------
 *
 * The following driver properties can be changed to control some aspects of the
 * drivers operation:
 * - strict-version: can be set to 0 to allow devices conforming to newer
 *   major versions to be used
 * - ignore-unknown-vendor-status: can be set to 1 to not handle any vendor
 *   specific command status as a fatal error leading device faulting
 * - admin-queue-len: the maximum length of the admin queue (16-4096)
 * - io-squeue-len: the maximum length of the I/O submission queues (16-65536)
 * - io-cqueue-len: the maximum length of the I/O completion queues (16-65536)
 * - async-event-limit: the maximum number of asynchronous event requests to be
 *   posted by the driver
 * - volatile-write-cache-enable: can be set to 0 to disable the volatile write
 *   cache
 * - min-phys-block-size: the minimum physical block size to report to blkdev,
 *   which is among other things the basis for ZFS vdev ashift
 * - max-submission-queues: the maximum number of I/O submission queues.
 * - max-completion-queues: the maximum number of I/O completion queues,
 *   can be less than max-submission-queues, in which case the completion
 *   queues are shared.
 *
 * In addition to the above properties, some device-specific tunables can be
 * configured using the nvme-config-list global property. The value of this
 * property is a list of triplets. The formal syntax is:
 *
 *   nvme-config-list ::= <triplet> [, <triplet>]* ;
 *   <triplet>        ::= "<model>" , "<rev-list>" , "<tuple-list>"
 *   <rev-list>       ::= [ <fwrev> [, <fwrev>]*]
 *   <tuple-list>     ::= <tunable> [, <tunable>]*
 *   <tunable>        ::= <name> : <value>
 *
 * The <model> and <fwrev> are the strings in nvme_identify_ctrl_t`id_model and
 * nvme_identify_ctrl_t`id_fwrev, respectively. The remainder of <tuple-list>
 * contains one or more tunables to apply to all controllers that match the
 * specified model number and optionally firmware revision. Each <tunable> is a
 * <name> : <value> pair.  Supported tunables are:
 *
 * - ignore-unknown-vendor-status:  can be set to "on" to not handle any vendor
 *   specific command status as a fatal error leading device faulting
 *
 * - min-phys-block-size: the minimum physical block size to report to blkdev,
 *   which is among other things the basis for ZFS vdev ashift
 *
 * - volatile-write-cache: can be set to "on" or "off" to enable or disable the
 *   volatile write cache, if present
 *
 *
 * TODO:
 * - figure out sane default for I/O queue depth reported to blkdev
 * - FMA handling of media errors
 * - support for devices supporting very large I/O requests using chained PRPs
 * - support for configuring hardware parameters like interrupt coalescing
 * - support for big-endian systems
 * - support for fast reboot
 * - support for NVMe Subsystem Reset (1.1)
 * - support for Scatter/Gather lists (1.1)
 * - support for Reservations (1.1)
 * - support for power management
 */

#include <sys/byteorder.h>
#ifdef _BIG_ENDIAN
#error nvme driver needs porting for big-endian platforms
#endif

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/ddi_ufm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/bitmap.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/varargs.h>
#include <sys/cpuvar.h>
#include <sys/disp.h>
#include <sys/blkdev.h>
#include <sys/atomic.h>
#include <sys/archsystm.h>
#include <sys/sata/sata_hba.h>
#include <sys/stat.h>
#include <sys/policy.h>
#include <sys/list.h>
#include <sys/dkio.h>
#include <sys/pci.h>
#include <sys/mkdev.h>

#include <sys/nvme.h>

#ifdef __x86
#include <sys/x86_archext.h>
#endif

#include "nvme_reg.h"
#include "nvme_var.h"

/*
 * Assertions to make sure that we've properly captured various aspects of the
 * packed structures and haven't broken them during updates.
 */
CTASSERT(sizeof (nvme_identify_ctrl_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_oacs) == 256);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_sqes) == 512);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_oncs) == 520);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_subnqn) == 768);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_nvmof) == 1792);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_psd) == 2048);
CTASSERT(offsetof(nvme_identify_ctrl_t, id_vs) == 3072);

CTASSERT(sizeof (nvme_identify_nsid_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_nsid_t, id_fpi) == 32);
CTASSERT(offsetof(nvme_identify_nsid_t, id_anagrpid) == 92);
CTASSERT(offsetof(nvme_identify_nsid_t, id_nguid) == 104);
CTASSERT(offsetof(nvme_identify_nsid_t, id_lbaf) == 128);
CTASSERT(offsetof(nvme_identify_nsid_t, id_vs) == 384);

CTASSERT(sizeof (nvme_identify_nsid_list_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(sizeof (nvme_identify_ctrl_list_t) == NVME_IDENTIFY_BUFSIZE);

CTASSERT(sizeof (nvme_identify_primary_caps_t) == NVME_IDENTIFY_BUFSIZE);
CTASSERT(offsetof(nvme_identify_primary_caps_t, nipc_vqfrt) == 32);
CTASSERT(offsetof(nvme_identify_primary_caps_t, nipc_vifrt) == 64);

CTASSERT(sizeof (nvme_nschange_list_t) == 4096);

/* NVMe spec version supported */
static const int nvme_version_major = 2;

/* Tunable for FORMAT NVM command timeout in seconds, default is 600s */
uint32_t nvme_format_cmd_timeout = 600;

/* Tunable for firmware commit with NVME_FWC_SAVE, default is 15s */
uint32_t nvme_commit_save_cmd_timeout = 15;

/*
 * Tunable for the admin command timeout used for commands other than those
 * with their own timeouts defined above; in seconds. While most commands are
 * expected to complete very quickly (sub-second), experience has shown that
 * some controllers can occasionally be a bit slower, and not always consistent
 * in the time taken - times of up to around 4.2s have been observed. Setting
 * this to 15s by default provides headroom.
 */
uint32_t nvme_admin_cmd_timeout = 15;

/*
 * Tunable for abort command timeout in seconds, default is 60s. This timeout
 * is used when issuing an abort command, currently only in response to a
 * different admin command timing out. Aborts always complete after the command
 * that they are attempting to abort so we need to allow enough time for the
 * controller to process the long running command that we are attempting to
 * abort. The abort timeout here is only used if it is greater than the timeout
 * for the command that is being aborted.
 */
uint32_t nvme_abort_cmd_timeout = 60;

/*
 * Tunable for the size of arbitrary vendor specific admin commands,
 * default is 16MiB.
 */
uint32_t nvme_vendor_specific_admin_cmd_size = 1 << 24;

/*
 * Tunable for the max timeout of arbitary vendor specific admin commands,
 * default is 60s.
 */
uint_t nvme_vendor_specific_admin_cmd_max_timeout = 60;

/*
 * This ID space, AVL, and lock are used for keeping track of minor state across
 * opens between different devices.
 */
static id_space_t *nvme_open_minors;
static avl_tree_t nvme_open_minors_avl;
kmutex_t nvme_open_minors_mutex;

/*
 * Removal taskq used for n_dead callback processing.
 */
taskq_t *nvme_dead_taskq;

/*
 * This enumeration is used in tandem with nvme_mgmt_lock() to describe which
 * form of the lock is being taken. See the theory statement for more context.
 */
typedef enum {
	/*
	 * This is the primary form of taking the management lock and indicates
	 * that the user intends to do a read/write of it. This should always be
	 * used for any ioctl paths or truly anything other than a blkdev
	 * information operation.
	 */
	NVME_MGMT_LOCK_NVME,
	/*
	 * This is a subordinate form of the lock whereby the user is in blkdev
	 * callback context and will only intend to read the namespace data.
	 */
	NVME_MGMT_LOCK_BDRO
} nvme_mgmt_lock_level_t;

static int nvme_attach(dev_info_t *, ddi_attach_cmd_t);
static int nvme_detach(dev_info_t *, ddi_detach_cmd_t);
static int nvme_quiesce(dev_info_t *);
static int nvme_fm_errcb(dev_info_t *, ddi_fm_error_t *, const void *);
static int nvme_setup_interrupts(nvme_t *, int, int);
static void nvme_release_interrupts(nvme_t *);
static uint_t nvme_intr(caddr_t, caddr_t);

static void nvme_shutdown(nvme_t *, boolean_t);
static boolean_t nvme_reset(nvme_t *, boolean_t);
static int nvme_init(nvme_t *);
static nvme_cmd_t *nvme_alloc_cmd(nvme_t *, int);
static void nvme_free_cmd(nvme_cmd_t *);
static nvme_cmd_t *nvme_create_nvm_cmd(nvme_namespace_t *, uint8_t,
    bd_xfer_t *);
static void nvme_admin_cmd(nvme_cmd_t *, uint32_t);
static void nvme_submit_admin_cmd(nvme_qpair_t *, nvme_cmd_t *, uint32_t *);
static int nvme_submit_io_cmd(nvme_qpair_t *, nvme_cmd_t *);
static void nvme_submit_cmd_common(nvme_qpair_t *, nvme_cmd_t *, uint32_t *);
static nvme_cmd_t *nvme_unqueue_cmd(nvme_t *, nvme_qpair_t *, int);
static nvme_cmd_t *nvme_retrieve_cmd(nvme_t *, nvme_qpair_t *);
static void nvme_wait_cmd(nvme_cmd_t *, uint_t);
static void nvme_wakeup_cmd(void *);
static void nvme_async_event_task(void *);

static int nvme_check_unknown_cmd_status(nvme_cmd_t *);
static int nvme_check_vendor_cmd_status(nvme_cmd_t *);
static int nvme_check_integrity_cmd_status(nvme_cmd_t *);
static int nvme_check_specific_cmd_status(nvme_cmd_t *);
static int nvme_check_generic_cmd_status(nvme_cmd_t *);
static inline int nvme_check_cmd_status(nvme_cmd_t *);
static boolean_t nvme_check_cmd_status_ioctl(nvme_cmd_t *,
    nvme_ioctl_common_t *);

static int nvme_abort_cmd(nvme_cmd_t *, const uint32_t);
static void nvme_async_event(nvme_t *);
static boolean_t nvme_format_nvm(nvme_t *, nvme_ioctl_format_t *);
static boolean_t nvme_get_logpage_int(nvme_t *, boolean_t, void **, size_t *,
    uint8_t);
static boolean_t nvme_identify(nvme_t *, boolean_t, nvme_ioctl_identify_t *,
    void **);
static boolean_t nvme_identify_int(nvme_t *, uint32_t, uint8_t, void **);
static int nvme_set_features(nvme_t *, boolean_t, uint32_t, uint8_t, uint32_t,
    uint32_t *);
static int nvme_write_cache_set(nvme_t *, boolean_t);
static int nvme_set_nqueues(nvme_t *);

static void nvme_free_dma(nvme_dma_t *);
static int nvme_zalloc_dma(nvme_t *, size_t, uint_t, ddi_dma_attr_t *,
    nvme_dma_t **);
static int nvme_zalloc_queue_dma(nvme_t *, uint32_t, uint16_t, uint_t,
    nvme_dma_t **);
static void nvme_free_qpair(nvme_qpair_t *);
static int nvme_alloc_qpair(nvme_t *, uint32_t, nvme_qpair_t **, uint_t);
static int nvme_create_io_qpair(nvme_t *, nvme_qpair_t *, uint16_t);

static inline void nvme_put64(nvme_t *, uintptr_t, uint64_t);
static inline void nvme_put32(nvme_t *, uintptr_t, uint32_t);
static inline uint64_t nvme_get64(nvme_t *, uintptr_t);
static inline uint32_t nvme_get32(nvme_t *, uintptr_t);

static boolean_t nvme_check_regs_hdl(nvme_t *);
static boolean_t nvme_check_dma_hdl(nvme_dma_t *);

static int nvme_fill_prp(nvme_cmd_t *, ddi_dma_handle_t);

static void nvme_bd_xfer_done(void *);
static void nvme_bd_driveinfo(void *, bd_drive_t *);
static int nvme_bd_mediainfo(void *, bd_media_t *);
static int nvme_bd_cmd(nvme_namespace_t *, bd_xfer_t *, uint8_t);
static int nvme_bd_read(void *, bd_xfer_t *);
static int nvme_bd_write(void *, bd_xfer_t *);
static int nvme_bd_sync(void *, bd_xfer_t *);
static int nvme_bd_devid(void *, dev_info_t *, ddi_devid_t *);
static int nvme_bd_free_space(void *, bd_xfer_t *);

static int nvme_prp_dma_constructor(void *, void *, int);
static void nvme_prp_dma_destructor(void *, void *);

static void nvme_prepare_devid(nvme_t *, uint32_t);

/* DDI UFM callbacks */
static int nvme_ufm_fill_image(ddi_ufm_handle_t *, void *, uint_t,
    ddi_ufm_image_t *);
static int nvme_ufm_fill_slot(ddi_ufm_handle_t *, void *, uint_t, uint_t,
    ddi_ufm_slot_t *);
static int nvme_ufm_getcaps(ddi_ufm_handle_t *, void *, ddi_ufm_cap_t *);

static int nvme_open(dev_t *, int, int, cred_t *);
static int nvme_close(dev_t, int, int, cred_t *);
static int nvme_ioctl(dev_t, int, intptr_t, int, cred_t *, int *);

static int nvme_init_ns(nvme_t *, uint32_t);
static boolean_t nvme_bd_attach_ns(nvme_t *, nvme_ioctl_common_t *);
static boolean_t nvme_bd_detach_ns(nvme_t *, nvme_ioctl_common_t *);

static int nvme_minor_comparator(const void *, const void *);

typedef struct {
	nvme_sqe_t *ica_sqe;
	void *ica_data;
	uint32_t ica_data_len;
	uint_t ica_dma_flags;
	int ica_copy_flags;
	uint32_t ica_timeout;
	uint32_t ica_cdw0;
} nvme_ioc_cmd_args_t;
static boolean_t nvme_ioc_cmd(nvme_t *, nvme_ioctl_common_t *,
    nvme_ioc_cmd_args_t *);

static ddi_ufm_ops_t nvme_ufm_ops = {
	NULL,
	nvme_ufm_fill_image,
	nvme_ufm_fill_slot,
	nvme_ufm_getcaps
};

/*
 * Minor numbers are split amongst those used for controllers and for device
 * opens. The number of controller minors are limited based open MAXMIN32 per
 * the theory statement. We allocate 1 million minors as a total guess at a
 * number that'll probably be enough. The starting point of the open minors can
 * be shifted to accommodate future expansion of the NVMe device minors.
 */
#define	NVME_MINOR_INST_SHIFT	9
#define	NVME_MINOR(inst, nsid)	(((inst) << NVME_MINOR_INST_SHIFT) | (nsid))
#define	NVME_MINOR_INST(minor)	((minor) >> NVME_MINOR_INST_SHIFT)
#define	NVME_MINOR_NSID(minor)	((minor) & ((1 << NVME_MINOR_INST_SHIFT) - 1))
#define	NVME_MINOR_MAX		(NVME_MINOR(1, 0) - 2)

#define	NVME_OPEN_NMINORS		(1024 * 1024)
#define	NVME_OPEN_MINOR_MIN		(MAXMIN32 + 1)
#define	NVME_OPEN_MINOR_MAX_EXCL	(NVME_OPEN_MINOR_MIN + \
    NVME_OPEN_NMINORS)

#define	NVME_BUMP_STAT(nvme, stat)	\
	atomic_inc_64(&nvme->n_device_stat.nds_ ## stat.value.ui64)

static void *nvme_state;
static kmem_cache_t *nvme_cmd_cache;

/*
 * DMA attributes for queue DMA memory
 *
 * Queue DMA memory must be page aligned. The maximum length of a queue is
 * 65536 entries, and an entry can be 64 bytes long.
 */
static const ddi_dma_attr_t nvme_queue_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= (UINT16_MAX + 1) * sizeof (nvme_sqe_t) - 1,
	.dma_attr_align		= 0x1000,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x1000,
	.dma_attr_maxxfer	= (UINT16_MAX + 1) * sizeof (nvme_sqe_t),
	.dma_attr_seg		= 0xffffffffffffffffULL,
	.dma_attr_sgllen	= 1,
	.dma_attr_granular	= 1,
	.dma_attr_flags		= 0,
};

/*
 * DMA attributes for transfers using Physical Region Page (PRP) entries
 *
 * A PRP entry describes one page of DMA memory using the page size specified
 * in the controller configuration's memory page size register (CC.MPS). It uses
 * a 64bit base address aligned to this page size. There is no limitation on
 * chaining PRPs together for arbitrarily large DMA transfers. These DMA
 * attributes will be copied into the nvme_t during nvme_attach() and the
 * dma_attr_maxxfer will be updated.
 */
static const ddi_dma_attr_t nvme_prp_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= 0xfff,
	.dma_attr_align		= 0x1000,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x1000,
	.dma_attr_maxxfer	= 0x1000,
	.dma_attr_seg		= 0xfff,
	.dma_attr_sgllen	= -1,
	.dma_attr_granular	= 1,
	.dma_attr_flags		= 0,
};

/*
 * DMA attributes for transfers using scatter/gather lists
 *
 * A SGL entry describes a chunk of DMA memory using a 64bit base address and a
 * 32bit length field. SGL Segment and SGL Last Segment entries require the
 * length to be a multiple of 16 bytes. While the SGL DMA attributes are copied
 * into the nvme_t, they are not currently used for any I/O.
 */
static const ddi_dma_attr_t nvme_sgl_dma_attr = {
	.dma_attr_version	= DMA_ATTR_V0,
	.dma_attr_addr_lo	= 0,
	.dma_attr_addr_hi	= 0xffffffffffffffffULL,
	.dma_attr_count_max	= 0xffffffffUL,
	.dma_attr_align		= 1,
	.dma_attr_burstsizes	= 0x7ff,
	.dma_attr_minxfer	= 0x10,
	.dma_attr_maxxfer	= 0xfffffffffULL,
	.dma_attr_seg		= 0xffffffffffffffffULL,
	.dma_attr_sgllen	= -1,
	.dma_attr_granular	= 0x10,
	.dma_attr_flags		= 0
};

static ddi_device_acc_attr_t nvme_reg_acc_attr = {
	.devacc_attr_version	= DDI_DEVICE_ATTR_V0,
	.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC,
	.devacc_attr_dataorder	= DDI_STRICTORDER_ACC
};

/*
 * ioctl validation policies. These are policies that determine which namespaces
 * are allowed or disallowed for various operations. Note, all policy items
 * should be explicitly listed here to help make it clear what our intent is.
 * That is also why some of these are identical or repeated when they cover
 * different ioctls.
 */

/*
 * The controller information ioctl generally contains read-only information
 * about the controller that is sourced from multiple different pieces of
 * information. This does not operate on a namespace and none are accepted.
 */
static const nvme_ioctl_check_t nvme_check_ctrl_info = {
	.nck_ns_ok = B_FALSE, .nck_ns_minor_ok = B_FALSE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * The kernel namespace information requires a namespace ID to be specified. It
 * does not allow for the broadcast ID to be specified.
 */
static const nvme_ioctl_check_t nvme_check_ns_info = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * Identify commands are allowed to operate on a namespace minor. Unfortunately,
 * the namespace field in identify commands is a bit, weird. In particular, some
 * commands need a valid namespace, while others are namespace listing
 * operations, which means illegal namespaces like zero are allowed.
 */
static const nvme_ioctl_check_t nvme_check_identify = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_TRUE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_TRUE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * The get log page command requires the ability to specify namespaces. When
 * targeting the controller, one must use the broadcast NSID.
 */
static const nvme_ioctl_check_t nvme_check_get_logpage = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_TRUE,
	.nck_bcast_ok = B_TRUE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * When getting a feature, we do not want rewriting behavior as most features do
 * not require a namespace to be specified. Specific instances are checked in
 * nvme_validate_get_feature().
 */
static const nvme_ioctl_check_t nvme_check_get_feature = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_TRUE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * Format commands must target a namespace. The broadcast namespace must be used
 * when referring to the controller.
 */
static const nvme_ioctl_check_t nvme_check_format = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_TRUE,
	.nck_bcast_ok = B_TRUE, .nck_excl = NVME_IOCTL_EXCL_WRITE
};

/*
 * blkdev and controller attach and detach must always target a namespace.
 * However, the broadcast namespace is not allowed. We still perform rewriting
 * so that way specifying the controller node with 0 will be caught.
 */
static const nvme_ioctl_check_t nvme_check_attach_detach = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_TRUE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_WRITE
};

/*
 * Namespace creation operations cannot target a namespace as the new namespace
 * ID will be returned in the operation. This operation requires the entire
 * controller lock to be owned as one has to coordinate this operation with all
 * of the actual namespace logic that's present.
 */
static const nvme_ioctl_check_t nvme_check_ns_create = {
	.nck_ns_ok = B_FALSE, .nck_ns_minor_ok = B_FALSE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_CTRL
};

/*
 * NVMe namespace delete must always target a namespace. The broadcast namespace
 * isn't allowed. We perform rewriting so that way we can catch this.
 * Importantly this only requires holding an exclusive lock on the namespace,
 * not on the whole device like creating a namespace does. Note, we don't allow
 * this on the namespace minor itself as part of our path towards transitioning
 * away from its use.
 */
static const nvme_ioctl_check_t nvme_check_ns_delete = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_FALSE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_TRUE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_WRITE
};

/*
 * Firmware operations must not target a namespace and are only allowed from the
 * controller.
 */
static const nvme_ioctl_check_t nvme_check_firmware = {
	.nck_ns_ok = B_FALSE, .nck_ns_minor_ok = B_FALSE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_WRITE
};

/*
 * Passthru commands are an odd set. We only allow them from the primary
 * controller; however, we allow a namespace to be specified in them and allow
 * the broadcast namespace. We do not perform rewriting because we don't know
 * what the semantics are. We explicitly exempt passthru commands from needing
 * an exclusive lock and leave it up to them to tell us the impact of the
 * command and semantics. As this is a privileged interface and the semantics
 * are arbitrary, there's not much we can do without some assistance from the
 * consumer.
 */
static const nvme_ioctl_check_t nvme_check_passthru = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_FALSE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_TRUE, .nck_excl = NVME_IOCTL_EXCL_NONE
};

/*
 * Lock operations are allowed to target a namespace, but must not be rewritten.
 * There is no support for the broadcast namespace. This is the only ioctl that
 * should skip exclusive checking as it's used to grant it.
 */
static const nvme_ioctl_check_t nvme_check_locking = {
	.nck_ns_ok = B_TRUE, .nck_ns_minor_ok = B_TRUE,
	.nck_skip_ctrl = B_FALSE, .nck_ctrl_rewrite = B_FALSE,
	.nck_bcast_ok = B_FALSE, .nck_excl = NVME_IOCTL_EXCL_SKIP
};

/*
 * These data tables indicate how we handle the various states a namespace may
 * be in before we put it through the namespace state transition diagram. Note,
 * namespace creation does not allow one to specify a namespace ID, therefore
 * there it doesn't have a set of entries here.
 *
 * See Namespace Support in the theory statement for more information.
 */
static const nvme_ioctl_errno_t nvme_ns_delete_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_NS_BLKDEV_ATTACH
};

static const nvme_ioctl_errno_t nvme_ctrl_attach_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_NS_BLKDEV_ATTACH
};

static const nvme_ioctl_errno_t nvme_ctrl_detach_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_NS_CTRL_NOT_ATTACHED,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_NS_BLKDEV_ATTACH
};

static const nvme_ioctl_errno_t nvme_bd_attach_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_NS_CTRL_NOT_ATTACHED,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_UNSUP_ATTACH_NS,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_NS_BLKDEV_ATTACH,
};

static const nvme_ioctl_errno_t nvme_bd_detach_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_NS_CTRL_NOT_ATTACHED,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_NS_CTRL_ATTACHED,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_OK,
};

static const nvme_ioctl_errno_t nvme_format_nvm_states[] = {
	[NVME_NS_STATE_UNALLOCATED] = NVME_IOCTL_E_NS_NO_NS,
	[NVME_NS_STATE_ALLOCATED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ACTIVE] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_NOT_IGNORED] = NVME_IOCTL_E_OK,
	[NVME_NS_STATE_ATTACHED] = NVME_IOCTL_E_NS_BLKDEV_ATTACH
};

static struct cb_ops nvme_cb_ops = {
	.cb_open	= nvme_open,
	.cb_close	= nvme_close,
	.cb_strategy	= nodev,
	.cb_print	= nodev,
	.cb_dump	= nodev,
	.cb_read	= nodev,
	.cb_write	= nodev,
	.cb_ioctl	= nvme_ioctl,
	.cb_devmap	= nodev,
	.cb_mmap	= nodev,
	.cb_segmap	= nodev,
	.cb_chpoll	= nochpoll,
	.cb_prop_op	= ddi_prop_op,
	.cb_str		= 0,
	.cb_flag	= D_NEW | D_MP,
	.cb_rev		= CB_REV,
	.cb_aread	= nodev,
	.cb_awrite	= nodev
};

static struct dev_ops nvme_dev_ops = {
	.devo_rev	= DEVO_REV,
	.devo_refcnt	= 0,
	.devo_getinfo	= ddi_no_info,
	.devo_identify	= nulldev,
	.devo_probe	= nulldev,
	.devo_attach	= nvme_attach,
	.devo_detach	= nvme_detach,
	.devo_reset	= nodev,
	.devo_cb_ops	= &nvme_cb_ops,
	.devo_bus_ops	= NULL,
	.devo_power	= NULL,
	.devo_quiesce	= nvme_quiesce,
};

static struct modldrv nvme_modldrv = {
	.drv_modops	= &mod_driverops,
	.drv_linkinfo	= "NVMe driver",
	.drv_dev_ops	= &nvme_dev_ops
};

static struct modlinkage nvme_modlinkage = {
	.ml_rev		= MODREV_1,
	.ml_linkage	= { &nvme_modldrv, NULL }
};

static bd_ops_t nvme_bd_ops = {
	.o_version	= BD_OPS_CURRENT_VERSION,
	.o_drive_info	= nvme_bd_driveinfo,
	.o_media_info	= nvme_bd_mediainfo,
	.o_devid_init	= nvme_bd_devid,
	.o_sync_cache	= nvme_bd_sync,
	.o_read		= nvme_bd_read,
	.o_write	= nvme_bd_write,
	.o_free_space	= nvme_bd_free_space,
};

/*
 * This list will hold commands that have timed out and couldn't be aborted.
 * As we don't know what the hardware may still do with the DMA memory we can't
 * free them, so we'll keep them forever on this list where we can easily look
 * at them with mdb.
 */
static struct list nvme_lost_cmds;
static kmutex_t nvme_lc_mutex;

int
_init(void)
{
	int error;

	error = ddi_soft_state_init(&nvme_state, sizeof (nvme_t), 1);
	if (error != DDI_SUCCESS)
		return (error);

	if ((nvme_open_minors = id_space_create("nvme_open_minors",
	    NVME_OPEN_MINOR_MIN, NVME_OPEN_MINOR_MAX_EXCL)) == NULL) {
		ddi_soft_state_fini(&nvme_state);
		return (ENOMEM);
	}

	nvme_cmd_cache = kmem_cache_create("nvme_cmd_cache",
	    sizeof (nvme_cmd_t), 64, NULL, NULL, NULL, NULL, NULL, 0);

	mutex_init(&nvme_lc_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&nvme_lost_cmds, sizeof (nvme_cmd_t),
	    offsetof(nvme_cmd_t, nc_list));

	mutex_init(&nvme_open_minors_mutex, NULL, MUTEX_DRIVER, NULL);
	avl_create(&nvme_open_minors_avl, nvme_minor_comparator,
	    sizeof (nvme_minor_t), offsetof(nvme_minor_t, nm_avl));

	nvme_dead_taskq = taskq_create("nvme_dead_taskq", 1, minclsyspri, 1, 1,
	    TASKQ_PREPOPULATE);

	bd_mod_init(&nvme_dev_ops);

	error = mod_install(&nvme_modlinkage);
	if (error != DDI_SUCCESS) {
		ddi_soft_state_fini(&nvme_state);
		id_space_destroy(nvme_open_minors);
		mutex_destroy(&nvme_lc_mutex);
		list_destroy(&nvme_lost_cmds);
		bd_mod_fini(&nvme_dev_ops);
		mutex_destroy(&nvme_open_minors_mutex);
		avl_destroy(&nvme_open_minors_avl);
		taskq_destroy(nvme_dead_taskq);
	}

	return (error);
}

int
_fini(void)
{
	int error;

	if (!list_is_empty(&nvme_lost_cmds))
		return (DDI_FAILURE);

	error = mod_remove(&nvme_modlinkage);
	if (error == DDI_SUCCESS) {
		ddi_soft_state_fini(&nvme_state);
		id_space_destroy(nvme_open_minors);
		kmem_cache_destroy(nvme_cmd_cache);
		mutex_destroy(&nvme_lc_mutex);
		list_destroy(&nvme_lost_cmds);
		bd_mod_fini(&nvme_dev_ops);
		mutex_destroy(&nvme_open_minors_mutex);
		avl_destroy(&nvme_open_minors_avl);
		taskq_destroy(nvme_dead_taskq);
	}

	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&nvme_modlinkage, modinfop));
}

static inline void
nvme_put64(nvme_t *nvme, uintptr_t reg, uint64_t val)
{
	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x7) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	ddi_put64(nvme->n_regh, (uint64_t *)(nvme->n_regs + reg), val);
}

static inline void
nvme_put32(nvme_t *nvme, uintptr_t reg, uint32_t val)
{
	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x3) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	ddi_put32(nvme->n_regh, (uint32_t *)(nvme->n_regs + reg), val);
}

static inline uint64_t
nvme_get64(nvme_t *nvme, uintptr_t reg)
{
	uint64_t val;

	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x7) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	val = ddi_get64(nvme->n_regh, (uint64_t *)(nvme->n_regs + reg));

	return (val);
}

static inline uint32_t
nvme_get32(nvme_t *nvme, uintptr_t reg)
{
	uint32_t val;

	ASSERT(((uintptr_t)(nvme->n_regs + reg) & 0x3) == 0);

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	val = ddi_get32(nvme->n_regh, (uint32_t *)(nvme->n_regs + reg));

	return (val);
}

static void
nvme_mgmt_lock_fini(nvme_mgmt_lock_t *lock)
{
	ASSERT3U(lock->nml_bd_own, ==, 0);
	mutex_destroy(&lock->nml_lock);
	cv_destroy(&lock->nml_cv);
}

static void
nvme_mgmt_lock_init(nvme_mgmt_lock_t *lock)
{
	mutex_init(&lock->nml_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&lock->nml_cv, NULL, CV_DRIVER, NULL);
	lock->nml_bd_own = 0;
}

static void
nvme_mgmt_unlock(nvme_t *nvme)
{
	nvme_mgmt_lock_t *lock = &nvme->n_mgmt;

	cv_broadcast(&lock->nml_cv);
	mutex_exit(&lock->nml_lock);
}

static boolean_t
nvme_mgmt_lock_held(const nvme_t *nvme)
{
	return (MUTEX_HELD(&nvme->n_mgmt.nml_lock) != 0);
}

static void
nvme_mgmt_lock(nvme_t *nvme, nvme_mgmt_lock_level_t level)
{
	nvme_mgmt_lock_t *lock = &nvme->n_mgmt;
	mutex_enter(&lock->nml_lock);
	while (lock->nml_bd_own != 0) {
		if (level == NVME_MGMT_LOCK_BDRO)
			break;
		cv_wait(&lock->nml_cv, &lock->nml_lock);
	}
}

/*
 * This and nvme_mgmt_bd_end() are used to indicate that the driver is going to
 * be calling into a re-entrant blkdev related function. We cannot hold the lock
 * across such an operation and therefore must indicate that this is logically
 * held, while allowing other operations to proceed. This nvme_mgmt_bd_end() may
 * only be called by a thread that already holds the nmve_mgmt_lock().
 */
static void
nvme_mgmt_bd_start(nvme_t *nvme)
{
	nvme_mgmt_lock_t *lock = &nvme->n_mgmt;

	VERIFY(MUTEX_HELD(&lock->nml_lock));
	VERIFY3U(lock->nml_bd_own, ==, 0);
	lock->nml_bd_own = (uintptr_t)curthread;
	mutex_exit(&lock->nml_lock);
}

static void
nvme_mgmt_bd_end(nvme_t *nvme)
{
	nvme_mgmt_lock_t *lock = &nvme->n_mgmt;

	mutex_enter(&lock->nml_lock);
	VERIFY3U(lock->nml_bd_own, ==, (uintptr_t)curthread);
	lock->nml_bd_own = 0;
}

static boolean_t
nvme_ns_state_check(const nvme_namespace_t *ns, nvme_ioctl_common_t *ioc,
    const nvme_ioctl_errno_t states[NVME_NS_NSTATES])
{
	VERIFY(nvme_mgmt_lock_held(ns->ns_nvme));
	VERIFY3U(ns->ns_state, <, NVME_NS_NSTATES);

	if (states[ns->ns_state] == NVME_IOCTL_E_OK) {
		return (B_TRUE);
	}

	return (nvme_ioctl_error(ioc, states[ns->ns_state], 0, 0));
}

/*
 * This is a central clearing house for marking an NVMe controller dead and/or
 * removed. This takes care of setting the flag, taking care of outstanding
 * blocked locks, and sending a DDI FMA impact. This is called from a precarious
 * place where locking is suspect. The only guarantee we have is that the nvme_t
 * is valid and won't disappear until we return.
 */
static void
nvme_ctrl_mark_dead(nvme_t *nvme, boolean_t removed)
{
	boolean_t was_dead;

	/*
	 * See if we win the race to set things up here. If someone beat us to
	 * it, we do not do anything.
	 */
	was_dead = atomic_cas_32((volatile uint32_t *)&nvme->n_dead, B_FALSE,
	    B_TRUE);

	/*
	 * If we were removed, note this in our death status, regardless of
	 * whether or not we were already dead.  We need to know this so that we
	 * can decide if it is safe to try and interact the the device in e.g.
	 * reset and shutdown.
	 */
	if (removed) {
		nvme->n_dead_status = NVME_IOCTL_E_CTRL_GONE;
	}

	if (was_dead) {
		return;
	}

	/*
	 * If this was removed, there is no reason to change the service impact.
	 * Otherwise, we need to change our default return code to indicate that
	 * the device is truly dead, and not simply gone.
	 */
	if (!removed) {
		ASSERT3U(nvme->n_dead_status, ==, NVME_IOCTL_E_CTRL_DEAD);
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
	}

	taskq_dispatch_ent(nvme_dead_taskq, nvme_rwlock_ctrl_dead, nvme,
	    TQ_NOSLEEP, &nvme->n_dead_tqent);
}

static boolean_t
nvme_ctrl_is_gone(const nvme_t *nvme)
{
	if (nvme->n_dead && nvme->n_dead_status == NVME_IOCTL_E_CTRL_GONE)
		return (B_TRUE);

	return (B_FALSE);
}

static boolean_t
nvme_check_regs_hdl(nvme_t *nvme)
{
	ddi_fm_error_t error;

	ddi_fm_acc_err_get(nvme->n_regh, &error, DDI_FME_VERSION);

	if (error.fme_status != DDI_FM_OK)
		return (B_TRUE);

	return (B_FALSE);
}

static boolean_t
nvme_check_dma_hdl(nvme_dma_t *dma)
{
	ddi_fm_error_t error;

	if (dma == NULL)
		return (B_FALSE);

	ddi_fm_dma_err_get(dma->nd_dmah, &error, DDI_FME_VERSION);

	if (error.fme_status != DDI_FM_OK)
		return (B_TRUE);

	return (B_FALSE);
}

static void
nvme_free_dma_common(nvme_dma_t *dma)
{
	if (dma->nd_dmah != NULL)
		(void) ddi_dma_unbind_handle(dma->nd_dmah);
	if (dma->nd_acch != NULL)
		ddi_dma_mem_free(&dma->nd_acch);
	if (dma->nd_dmah != NULL)
		ddi_dma_free_handle(&dma->nd_dmah);
}

static void
nvme_free_dma(nvme_dma_t *dma)
{
	nvme_free_dma_common(dma);
	kmem_free(dma, sizeof (*dma));
}

static void
nvme_prp_dma_destructor(void *buf, void *private __unused)
{
	nvme_dma_t *dma = (nvme_dma_t *)buf;

	nvme_free_dma_common(dma);
}

static int
nvme_alloc_dma_common(nvme_t *nvme, nvme_dma_t *dma,
    size_t len, uint_t flags, ddi_dma_attr_t *dma_attr)
{
	if (ddi_dma_alloc_handle(nvme->n_dip, dma_attr, DDI_DMA_SLEEP, NULL,
	    &dma->nd_dmah) != DDI_SUCCESS) {
		/*
		 * Due to DDI_DMA_SLEEP this can't be DDI_DMA_NORESOURCES, and
		 * the only other possible error is DDI_DMA_BADATTR which
		 * indicates a driver bug which should cause a panic.
		 */
		dev_err(nvme->n_dip, CE_PANIC,
		    "!failed to get DMA handle, check DMA attributes");
		return (DDI_FAILURE);
	}

	/*
	 * ddi_dma_mem_alloc() can only fail when DDI_DMA_NOSLEEP is specified
	 * or the flags are conflicting, which isn't the case here.
	 */
	(void) ddi_dma_mem_alloc(dma->nd_dmah, len, &nvme->n_reg_acc_attr,
	    DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL, &dma->nd_memp,
	    &dma->nd_len, &dma->nd_acch);

	if (ddi_dma_addr_bind_handle(dma->nd_dmah, NULL, dma->nd_memp,
	    dma->nd_len, flags | DDI_DMA_CONSISTENT, DDI_DMA_SLEEP, NULL,
	    &dma->nd_cookie, &dma->nd_ncookie) != DDI_DMA_MAPPED) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to bind DMA memory");
		NVME_BUMP_STAT(nvme, dma_bind_err);
		nvme_free_dma_common(dma);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
nvme_zalloc_dma(nvme_t *nvme, size_t len, uint_t flags,
    ddi_dma_attr_t *dma_attr, nvme_dma_t **ret)
{
	nvme_dma_t *dma = kmem_zalloc(sizeof (nvme_dma_t), KM_SLEEP);

	if (nvme_alloc_dma_common(nvme, dma, len, flags, dma_attr) !=
	    DDI_SUCCESS) {
		*ret = NULL;
		kmem_free(dma, sizeof (nvme_dma_t));
		return (DDI_FAILURE);
	}

	bzero(dma->nd_memp, dma->nd_len);

	*ret = dma;
	return (DDI_SUCCESS);
}

static int
nvme_prp_dma_constructor(void *buf, void *private, int flags __unused)
{
	nvme_dma_t *dma = (nvme_dma_t *)buf;
	nvme_t *nvme = (nvme_t *)private;

	dma->nd_dmah = NULL;
	dma->nd_acch = NULL;

	if (nvme_alloc_dma_common(nvme, dma, nvme->n_pagesize,
	    DDI_DMA_READ, &nvme->n_prp_dma_attr) != DDI_SUCCESS) {
		return (-1);
	}

	ASSERT(dma->nd_ncookie == 1);

	dma->nd_cached = B_TRUE;

	return (0);
}

static int
nvme_zalloc_queue_dma(nvme_t *nvme, uint32_t nentry, uint16_t qe_len,
    uint_t flags, nvme_dma_t **dma)
{
	uint32_t len = nentry * qe_len;
	ddi_dma_attr_t q_dma_attr = nvme->n_queue_dma_attr;

	len = roundup(len, nvme->n_pagesize);

	if (nvme_zalloc_dma(nvme, len, flags, &q_dma_attr, dma)
	    != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to get DMA memory for queue");
		goto fail;
	}

	if ((*dma)->nd_ncookie != 1) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!got too many cookies for queue DMA");
		goto fail;
	}

	return (DDI_SUCCESS);

fail:
	if (*dma) {
		nvme_free_dma(*dma);
		*dma = NULL;
	}

	return (DDI_FAILURE);
}

static void
nvme_free_cq(nvme_cq_t *cq)
{
	mutex_destroy(&cq->ncq_mutex);

	if (cq->ncq_cmd_taskq != NULL)
		taskq_destroy(cq->ncq_cmd_taskq);

	if (cq->ncq_dma != NULL)
		nvme_free_dma(cq->ncq_dma);

	kmem_free(cq, sizeof (*cq));
}

static void
nvme_free_qpair(nvme_qpair_t *qp)
{
	int i;

	mutex_destroy(&qp->nq_mutex);
	sema_destroy(&qp->nq_sema);

	if (qp->nq_sqdma != NULL)
		nvme_free_dma(qp->nq_sqdma);

	if (qp->nq_active_cmds > 0)
		for (i = 0; i != qp->nq_nentry; i++)
			if (qp->nq_cmd[i] != NULL)
				nvme_free_cmd(qp->nq_cmd[i]);

	if (qp->nq_cmd != NULL)
		kmem_free(qp->nq_cmd, sizeof (nvme_cmd_t *) * qp->nq_nentry);

	kmem_free(qp, sizeof (nvme_qpair_t));
}

/*
 * Destroy the pre-allocated cq array, but only free individual completion
 * queues from the given starting index.
 */
static void
nvme_destroy_cq_array(nvme_t *nvme, uint_t start)
{
	uint_t i;

	for (i = start; i < nvme->n_cq_count; i++)
		if (nvme->n_cq[i] != NULL)
			nvme_free_cq(nvme->n_cq[i]);

	kmem_free(nvme->n_cq, sizeof (*nvme->n_cq) * nvme->n_cq_count);
}

static int
nvme_alloc_cq(nvme_t *nvme, uint32_t nentry, nvme_cq_t **cqp, uint16_t idx,
    uint_t nthr)
{
	nvme_cq_t *cq = kmem_zalloc(sizeof (*cq), KM_SLEEP);
	char name[64];		/* large enough for the taskq name */

	mutex_init(&cq->ncq_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(nvme->n_intr_pri));

	if (nvme_zalloc_queue_dma(nvme, nentry, sizeof (nvme_cqe_t),
	    DDI_DMA_READ, &cq->ncq_dma) != DDI_SUCCESS)
		goto fail;

	cq->ncq_cq = (nvme_cqe_t *)cq->ncq_dma->nd_memp;
	cq->ncq_nentry = nentry;
	cq->ncq_id = idx;
	cq->ncq_hdbl = NVME_REG_CQHDBL(nvme, idx);

	/*
	 * Each completion queue has its own command taskq.
	 */
	(void) snprintf(name, sizeof (name), "%s%d_cmd_taskq%u",
	    ddi_driver_name(nvme->n_dip), ddi_get_instance(nvme->n_dip), idx);

	cq->ncq_cmd_taskq = taskq_create(name, nthr, minclsyspri, 64, INT_MAX,
	    TASKQ_PREPOPULATE);

	if (cq->ncq_cmd_taskq == NULL) {
		dev_err(nvme->n_dip, CE_WARN, "!failed to create cmd "
		    "taskq for cq %u", idx);
		goto fail;
	}

	*cqp = cq;
	return (DDI_SUCCESS);

fail:
	nvme_free_cq(cq);
	*cqp = NULL;

	return (DDI_FAILURE);
}

/*
 * Create the n_cq array big enough to hold "ncq" completion queues.
 * If the array already exists it will be re-sized (but only larger).
 * The admin queue is included in this array, which boosts the
 * max number of entries to UINT16_MAX + 1.
 */
static int
nvme_create_cq_array(nvme_t *nvme, uint_t ncq, uint32_t nentry, uint_t nthr)
{
	nvme_cq_t **cq;
	uint_t i, cq_count;

	ASSERT3U(ncq, >, nvme->n_cq_count);

	cq = nvme->n_cq;
	cq_count = nvme->n_cq_count;

	nvme->n_cq = kmem_zalloc(sizeof (*nvme->n_cq) * ncq, KM_SLEEP);
	nvme->n_cq_count = ncq;

	for (i = 0; i < cq_count; i++)
		nvme->n_cq[i] = cq[i];

	for (; i < nvme->n_cq_count; i++)
		if (nvme_alloc_cq(nvme, nentry, &nvme->n_cq[i], i, nthr) !=
		    DDI_SUCCESS)
			goto fail;

	if (cq != NULL)
		kmem_free(cq, sizeof (*cq) * cq_count);

	return (DDI_SUCCESS);

fail:
	nvme_destroy_cq_array(nvme, cq_count);
	/*
	 * Restore the original array
	 */
	nvme->n_cq_count = cq_count;
	nvme->n_cq = cq;

	return (DDI_FAILURE);
}

static int
nvme_alloc_qpair(nvme_t *nvme, uint32_t nentry, nvme_qpair_t **nqp,
    uint_t idx)
{
	nvme_qpair_t *qp = kmem_zalloc(sizeof (*qp), KM_SLEEP);
	uint_t cq_idx;

	mutex_init(&qp->nq_mutex, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(nvme->n_intr_pri));

	/*
	 * The NVMe spec defines that a full queue has one empty (unused) slot;
	 * initialize the semaphore accordingly.
	 */
	sema_init(&qp->nq_sema, nentry - 1, NULL, SEMA_DRIVER, NULL);

	if (nvme_zalloc_queue_dma(nvme, nentry, sizeof (nvme_sqe_t),
	    DDI_DMA_WRITE, &qp->nq_sqdma) != DDI_SUCCESS)
		goto fail;

	/*
	 * idx == 0 is adminq, those above 0 are shared io completion queues.
	 */
	cq_idx = idx == 0 ? 0 : 1 + (idx - 1) % (nvme->n_cq_count - 1);
	qp->nq_cq = nvme->n_cq[cq_idx];
	qp->nq_sq = (nvme_sqe_t *)qp->nq_sqdma->nd_memp;
	qp->nq_nentry = nentry;

	qp->nq_sqtdbl = NVME_REG_SQTDBL(nvme, idx);

	qp->nq_cmd = kmem_zalloc(sizeof (nvme_cmd_t *) * nentry, KM_SLEEP);
	qp->nq_next_cmd = 0;

	*nqp = qp;
	return (DDI_SUCCESS);

fail:
	nvme_free_qpair(qp);
	*nqp = NULL;

	return (DDI_FAILURE);
}

/*
 * One might reasonably consider that the nvme_cmd_cache should have a cache
 * constructor and destructor that takes care of the mutex/cv init/destroy, and
 * that nvme_free_cmd should reset more fields such that allocation becomes
 * simpler. This is not currently implemented as:
 * - nvme_cmd_cache is a global cache, shared across nvme instances and
 *   therefore there is no easy access to the corresponding nvme_t in the
 *   constructor to determine the required interrupt priority.
 * - Most fields in nvme_cmd_t would need to be zeroed in nvme_free_cmd while
 *   preserving the mutex/cv. It is easier to able to zero the entire
 *   structure and then init the mutex/cv only in the unlikely event that we
 *   want an admin command.
 */
static nvme_cmd_t *
nvme_alloc_cmd(nvme_t *nvme, int kmflag)
{
	nvme_cmd_t *cmd = kmem_cache_alloc(nvme_cmd_cache, kmflag);

	if (cmd != NULL) {
		bzero(cmd, sizeof (nvme_cmd_t));
		cmd->nc_nvme = nvme;
	}

	return (cmd);
}

static nvme_cmd_t *
nvme_alloc_admin_cmd(nvme_t *nvme, int kmflag)
{
	nvme_cmd_t *cmd = nvme_alloc_cmd(nvme, kmflag);

	if (cmd != NULL) {
		cmd->nc_flags |= NVME_CMD_F_USELOCK;
		mutex_init(&cmd->nc_mutex, NULL, MUTEX_DRIVER,
		    DDI_INTR_PRI(nvme->n_intr_pri));
		cv_init(&cmd->nc_cv, NULL, CV_DRIVER, NULL);
	}

	return (cmd);
}

static void
nvme_free_cmd(nvme_cmd_t *cmd)
{
	/* Don't free commands on the lost commands list. */
	if (list_link_active(&cmd->nc_list))
		return;

	if (cmd->nc_dma) {
		nvme_free_dma(cmd->nc_dma);
		cmd->nc_dma = NULL;
	}

	if (cmd->nc_prp) {
		kmem_cache_free(cmd->nc_nvme->n_prp_cache, cmd->nc_prp);
		cmd->nc_prp = NULL;
	}

	if ((cmd->nc_flags & NVME_CMD_F_USELOCK) != 0) {
		cv_destroy(&cmd->nc_cv);
		mutex_destroy(&cmd->nc_mutex);
	}

	kmem_cache_free(nvme_cmd_cache, cmd);
}

static void
nvme_submit_admin_cmd(nvme_qpair_t *qp, nvme_cmd_t *cmd, uint32_t *qtimeoutp)
{
	sema_p(&qp->nq_sema);
	nvme_submit_cmd_common(qp, cmd, qtimeoutp);
}

static int
nvme_submit_io_cmd(nvme_qpair_t *qp, nvme_cmd_t *cmd)
{
	if (cmd->nc_nvme->n_dead) {
		return (EIO);
	}

	sema_p(&qp->nq_sema);
	nvme_submit_cmd_common(qp, cmd, NULL);
	return (0);
}

/*
 * Common command submission routine. If `qtimeoutp` is not NULL then it will
 * be set to the sum of the timeouts of any active commands ahead of the one
 * being submitted.
 */
static void
nvme_submit_cmd_common(nvme_qpair_t *qp, nvme_cmd_t *cmd, uint32_t *qtimeoutp)
{
	nvme_reg_sqtdbl_t tail = { 0 };

	/*
	 * We don't need to take a lock on cmd since it is not yet enqueued.
	 */
	cmd->nc_submit_ts = gethrtime();
	cmd->nc_state = NVME_CMD_SUBMITTED;

	mutex_enter(&qp->nq_mutex);

	/*
	 * Now that we hold the queue pair lock, we must check whether or not
	 * the controller has been listed as dead (e.g. was removed due to
	 * hotplug). This is necessary as otherwise we could race with
	 * nvme_remove_callback(). Because this has not been enqueued, we don't
	 * call nvme_unqueue_cmd(), which is why we must manually decrement the
	 * semaphore.
	 */
	if (cmd->nc_nvme->n_dead) {
		cmd->nc_queue_ts = gethrtime();
		cmd->nc_state = NVME_CMD_QUEUED;
		taskq_dispatch_ent(qp->nq_cq->ncq_cmd_taskq, cmd->nc_callback,
		    cmd, TQ_NOSLEEP, &cmd->nc_tqent);
		sema_v(&qp->nq_sema);
		mutex_exit(&qp->nq_mutex);
		return;
	}

	/*
	 * Try to insert the cmd into the active cmd array at the nq_next_cmd
	 * slot. If the slot is already occupied advance to the next slot and
	 * try again. This can happen for long running commands like async event
	 * requests.
	 */
	while (qp->nq_cmd[qp->nq_next_cmd] != NULL)
		qp->nq_next_cmd = (qp->nq_next_cmd + 1) % qp->nq_nentry;
	qp->nq_cmd[qp->nq_next_cmd] = cmd;

	/*
	 * We keep track of the number of active commands in this queue, and
	 * the sum of the timeouts for those active commands.
	 */
	qp->nq_active_cmds++;
	if (qtimeoutp != NULL)
		*qtimeoutp = qp->nq_active_timeout;
	qp->nq_active_timeout += cmd->nc_timeout;

	cmd->nc_sqe.sqe_cid = qp->nq_next_cmd;
	bcopy(&cmd->nc_sqe, &qp->nq_sq[qp->nq_sqtail], sizeof (nvme_sqe_t));
	(void) ddi_dma_sync(qp->nq_sqdma->nd_dmah,
	    sizeof (nvme_sqe_t) * qp->nq_sqtail,
	    sizeof (nvme_sqe_t), DDI_DMA_SYNC_FORDEV);
	qp->nq_next_cmd = (qp->nq_next_cmd + 1) % qp->nq_nentry;

	tail.b.sqtdbl_sqt = qp->nq_sqtail = (qp->nq_sqtail + 1) % qp->nq_nentry;
	nvme_put32(cmd->nc_nvme, qp->nq_sqtdbl, tail.r);

	mutex_exit(&qp->nq_mutex);
}

static nvme_cmd_t *
nvme_unqueue_cmd(nvme_t *nvme, nvme_qpair_t *qp, int cid)
{
	nvme_cmd_t *cmd;

	ASSERT(mutex_owned(&qp->nq_mutex));
	ASSERT3S(cid, <, qp->nq_nentry);

	cmd = qp->nq_cmd[cid];
	/*
	 * Some controllers will erroneously add things to the completion queue
	 * for which there is no matching outstanding command. If this happens,
	 * it is almost certainly a controller firmware bug since nq_mutex
	 * is held across command submission and ringing the queue doorbell,
	 * and is also held in this function.
	 *
	 * If we see such an unexpected command, there is not much we can do.
	 * These will be logged and counted in nvme_get_completed(), but
	 * otherwise ignored.
	 */
	if (cmd == NULL)
		return (NULL);
	qp->nq_cmd[cid] = NULL;
	ASSERT3U(qp->nq_active_cmds, >, 0);
	qp->nq_active_cmds--;
	ASSERT3U(qp->nq_active_timeout, >=, cmd->nc_timeout);
	qp->nq_active_timeout -= cmd->nc_timeout;
	sema_v(&qp->nq_sema);

	ASSERT3P(cmd, !=, NULL);
	ASSERT3P(cmd->nc_nvme, ==, nvme);
	ASSERT3S(cmd->nc_sqe.sqe_cid, ==, cid);

	return (cmd);
}

/*
 * This is called when an admin abort has failed to complete, once for the
 * original command and once for the abort itself. At this point the controller
 * has been marked dead. The commands are considered lost, de-queued if
 * possible, and placed on a global lost commands list so that they cannot be
 * freed and so that any DMA memory they have have is not re-used.
 */
static void
nvme_lost_cmd(nvme_t *nvme, nvme_cmd_t *cmd)
{
	ASSERT(mutex_owned(&cmd->nc_mutex));

	switch (cmd->nc_state) {
	case NVME_CMD_SUBMITTED: {
		nvme_qpair_t *qp = nvme->n_ioq[cmd->nc_sqid];

		/*
		 * The command is still in the submitted state, meaning that we
		 * have not processed a completion queue entry for it. De-queue
		 * should be successful and if the hardware does later report
		 * completion we'll skip it as a command for which we aren't
		 * expecting a response (see nvme_unqueue_cmd()).
		 */
		mutex_enter(&qp->nq_mutex);
		(void) nvme_unqueue_cmd(nvme, qp, cmd->nc_sqe.sqe_cid);
		mutex_exit(&qp->nq_mutex);
	}
	case NVME_CMD_ALLOCATED:
	case NVME_CMD_COMPLETED:
		/*
		 * If the command has not been submitted, or has completed,
		 * there is nothing to do here. In the event of an abort
		 * command timeout, we can end up here in the process of
		 * "losing" the original command. It's possible that command
		 * has actually completed (or been queued on the taskq) in the
		 * interim.
		 */
		break;
	case NVME_CMD_QUEUED:
		/*
		 * The command is on the taskq, awaiting callback. This should
		 * be fairly rapid so wait for completion.
		 */
		while (cmd->nc_state != NVME_CMD_COMPLETED)
			cv_wait(&cmd->nc_cv, &cmd->nc_mutex);
		break;
	case NVME_CMD_LOST:
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC,
		    "%s: command %p already lost", __func__, (void *)cmd);
		break;
	}

	cmd->nc_state = NVME_CMD_LOST;

	mutex_enter(&nvme_lc_mutex);
	list_insert_head(&nvme_lost_cmds, cmd);
	mutex_exit(&nvme_lc_mutex);
}

/*
 * Get the command tied to the next completed cqe and bump along completion
 * queue head counter.
 */
static nvme_cmd_t *
nvme_get_completed(nvme_t *nvme, nvme_cq_t *cq)
{
	nvme_qpair_t *qp;
	nvme_cqe_t *cqe;
	nvme_cmd_t *cmd;

	ASSERT(mutex_owned(&cq->ncq_mutex));

retry:
	cqe = &cq->ncq_cq[cq->ncq_head];

	/* Check phase tag of CQE. Hardware inverts it for new entries. */
	if (cqe->cqe_sf.sf_p == cq->ncq_phase)
		return (NULL);

	qp = nvme->n_ioq[cqe->cqe_sqid];

	mutex_enter(&qp->nq_mutex);
	cmd = nvme_unqueue_cmd(nvme, qp, cqe->cqe_cid);
	mutex_exit(&qp->nq_mutex);

	qp->nq_sqhead = cqe->cqe_sqhd;
	cq->ncq_head = (cq->ncq_head + 1) % cq->ncq_nentry;

	/* Toggle phase on wrap-around. */
	if (cq->ncq_head == 0)
		cq->ncq_phase = cq->ncq_phase != 0 ? 0 : 1;

	if (cmd == NULL) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!received completion for unknown cid 0x%x", cqe->cqe_cid);
		NVME_BUMP_STAT(nvme, unknown_cid);
		/*
		 * We want to ignore this unexpected completion entry as it
		 * is most likely a result of a bug in the controller firmware.
		 * However, if we return NULL, then callers will assume there
		 * are no more pending commands for this wakeup. Retry to keep
		 * enumerating commands until the phase tag indicates there are
		 * no more and we are really done.
		 */
		goto retry;
	}

	ASSERT3U(cmd->nc_sqid, ==, cqe->cqe_sqid);
	bcopy(cqe, &cmd->nc_cqe, sizeof (nvme_cqe_t));

	return (cmd);
}

/*
 * Process all completed commands on the io completion queue.
 */
static uint_t
nvme_process_iocq(nvme_t *nvme, nvme_cq_t *cq)
{
	nvme_reg_cqhdbl_t head = { 0 };
	nvme_cmd_t *cmd;
	uint_t completed = 0;

	if (ddi_dma_sync(cq->ncq_dma->nd_dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL) !=
	    DDI_SUCCESS)
		dev_err(nvme->n_dip, CE_WARN, "!ddi_dma_sync() failed in %s",
		    __func__);

	mutex_enter(&cq->ncq_mutex);

	while ((cmd = nvme_get_completed(nvme, cq)) != NULL) {
		/*
		 * NVME_CMD_F_USELOCK is applied to all commands which are
		 * going to be waited for by another thread in nvme_wait_cmd
		 * and indicates that the lock should be taken before modifying
		 * protected fields, and that the mutex has been initialised.
		 * Commands which do not require the mutex to be held have not
		 * initialised it (to reduce overhead).
		 */
		if ((cmd->nc_flags & NVME_CMD_F_USELOCK) != 0) {
			mutex_enter(&cmd->nc_mutex);
			/*
			 * The command could have been de-queued as lost while
			 * we waited on the lock, in which case we drop it.
			 */
			if (cmd->nc_state == NVME_CMD_LOST) {
				mutex_exit(&cmd->nc_mutex);
				completed++;
				continue;
			}
		}
		cmd->nc_queue_ts = gethrtime();
		cmd->nc_state = NVME_CMD_QUEUED;
		if ((cmd->nc_flags & NVME_CMD_F_USELOCK) != 0)
			mutex_exit(&cmd->nc_mutex);
		taskq_dispatch_ent(cq->ncq_cmd_taskq, cmd->nc_callback, cmd,
		    TQ_NOSLEEP, &cmd->nc_tqent);

		completed++;
	}

	if (completed > 0) {
		/*
		 * Update the completion queue head doorbell.
		 */
		head.b.cqhdbl_cqh = cq->ncq_head;
		nvme_put32(nvme, cq->ncq_hdbl, head.r);
	}

	mutex_exit(&cq->ncq_mutex);

	return (completed);
}

static nvme_cmd_t *
nvme_retrieve_cmd(nvme_t *nvme, nvme_qpair_t *qp)
{
	nvme_cq_t *cq = qp->nq_cq;
	nvme_reg_cqhdbl_t head = { 0 };
	nvme_cmd_t *cmd;

	if (ddi_dma_sync(cq->ncq_dma->nd_dmah, 0, 0, DDI_DMA_SYNC_FORKERNEL) !=
	    DDI_SUCCESS)
		dev_err(nvme->n_dip, CE_WARN, "!ddi_dma_sync() failed in %s",
		    __func__);

	mutex_enter(&cq->ncq_mutex);

	if ((cmd = nvme_get_completed(nvme, cq)) != NULL) {
		head.b.cqhdbl_cqh = cq->ncq_head;
		nvme_put32(nvme, cq->ncq_hdbl, head.r);
	}

	mutex_exit(&cq->ncq_mutex);

	return (cmd);
}

static int
nvme_check_unknown_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	dev_err(cmd->nc_nvme->n_dip, CE_WARN,
	    "!unknown command status received: opc = %x, sqid = %d, cid = %d, "
	    "sc = %x, sct = %x, dnr = %d, m = %d", cmd->nc_sqe.sqe_opc,
	    cqe->cqe_sqid, cqe->cqe_cid, cqe->cqe_sf.sf_sc, cqe->cqe_sf.sf_sct,
	    cqe->cqe_sf.sf_dnr, cqe->cqe_sf.sf_m);

	if (cmd->nc_xfer != NULL)
		bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);

	/*
	 * User commands should never cause us to mark the controller dead.
	 * Though whether we ever should mark it dead as there currently isn't a
	 * useful recovery path is another question.
	 */
	if (((cmd->nc_flags & NVME_CMD_F_DONTPANIC) == 0) &&
	    cmd->nc_nvme->n_strict_version) {
		nvme_ctrl_mark_dead(cmd->nc_nvme, B_FALSE);
	}

	return (EIO);
}

static int
nvme_check_vendor_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	dev_err(cmd->nc_nvme->n_dip, CE_WARN,
	    "!unknown command status received: opc = %x, sqid = %d, cid = %d, "
	    "sc = %x, sct = %x, dnr = %d, m = %d", cmd->nc_sqe.sqe_opc,
	    cqe->cqe_sqid, cqe->cqe_cid, cqe->cqe_sf.sf_sc, cqe->cqe_sf.sf_sct,
	    cqe->cqe_sf.sf_dnr, cqe->cqe_sf.sf_m);
	if (!cmd->nc_nvme->n_ignore_unknown_vendor_status) {
		nvme_ctrl_mark_dead(cmd->nc_nvme, B_FALSE);
	}

	return (EIO);
}

static int
nvme_check_integrity_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_INT_NVM_WRITE:
		/* write fail */
		/* TODO: post ereport */
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	case NVME_CQE_SC_INT_NVM_READ:
		/* read fail */
		/* TODO: post ereport */
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static int
nvme_check_generic_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_GEN_SUCCESS:
		return (0);

	/*
	 * Errors indicating a bug in the driver should cause a panic.
	 */
	case NVME_CQE_SC_GEN_INV_OPC:
		/* Invalid Command Opcode */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_cmd_err);
		if ((cmd->nc_flags & NVME_CMD_F_DONTPANIC) == 0) {
			dev_err(cmd->nc_nvme->n_dip, CE_PANIC,
			    "programming error: invalid opcode in cmd %p",
			    (void *)cmd);
		}
		return (EINVAL);

	case NVME_CQE_SC_GEN_INV_FLD:
		/* Invalid Field in Command */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_field_err);
		if ((cmd->nc_flags & NVME_CMD_F_DONTPANIC) == 0) {
			dev_err(cmd->nc_nvme->n_dip, CE_PANIC,
			    "programming error: invalid field in cmd %p",
			    (void *)cmd);
		}
		return (EIO);

	case NVME_CQE_SC_GEN_ID_CNFL:
		/* Command ID Conflict */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "cmd ID conflict in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_GEN_INV_NS:
		/* Invalid Namespace or Format */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_nsfmt_err);
		if ((cmd->nc_flags & NVME_CMD_F_DONTPANIC) == 0) {
			dev_err(cmd->nc_nvme->n_dip, CE_PANIC,
			    "programming error: invalid NS/format in cmd %p",
			    (void *)cmd);
		}
		return (EINVAL);

	case NVME_CQE_SC_GEN_CMD_SEQ_ERR:
		/*
		 * Command Sequence Error
		 *
		 * This can be generated normally by user log page requests that
		 * come out of order (e.g. getting the persistent event log
		 * without establishing the context). If the kernel manages this
		 * on its own then that's problematic.
		 */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_cmdseq_err);
		if ((cmd->nc_flags & NVME_CMD_F_DONTPANIC) == 0) {
			dev_err(cmd->nc_nvme->n_dip, CE_PANIC,
			    "programming error: command sequencing error %p",
			    (void *)cmd);
		}
		return (EINVAL);

	case NVME_CQE_SC_GEN_NVM_LBA_RANGE:
		/* LBA Out Of Range */
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "LBA out of range in cmd %p", (void *)cmd);
		return (0);

	/*
	 * Non-fatal errors, handle gracefully.
	 */
	case NVME_CQE_SC_GEN_DATA_XFR_ERR:
		/* Data Transfer Error (DMA) */
		/* TODO: post ereport */
		NVME_BUMP_STAT(cmd->nc_nvme, data_xfr_err);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	case NVME_CQE_SC_GEN_INTERNAL_ERR:
		/*
		 * Internal Error. The spec (v1.0, section 4.5.1.2) says
		 * detailed error information is returned as async event,
		 * so we pretty much ignore the error here and handle it
		 * in the async event handler.
		 */
		NVME_BUMP_STAT(cmd->nc_nvme, internal_err);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	case NVME_CQE_SC_GEN_ABORT_REQUEST:
		/*
		 * Command Abort Requested. This normally happens only when a
		 * command times out.
		 */
		/* TODO: post ereport or change blkdev to handle this? */
		NVME_BUMP_STAT(cmd->nc_nvme, abort_rq_err);
		return (ECANCELED);

	case NVME_CQE_SC_GEN_ABORT_PWRLOSS:
		/* Command Aborted due to Power Loss Notification */
		NVME_BUMP_STAT(cmd->nc_nvme, abort_pwrloss_err);
		nvme_ctrl_mark_dead(cmd->nc_nvme, B_FALSE);
		return (EIO);

	case NVME_CQE_SC_GEN_ABORT_SQ_DEL:
		/* Command Aborted due to SQ Deletion */
		NVME_BUMP_STAT(cmd->nc_nvme, abort_sq_del);
		return (EIO);

	case NVME_CQE_SC_GEN_NVM_CAP_EXC:
		/* Capacity Exceeded */
		NVME_BUMP_STAT(cmd->nc_nvme, nvm_cap_exc);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_MEDIA);
		return (EIO);

	case NVME_CQE_SC_GEN_NVM_NS_NOTRDY:
		/* Namespace Not Ready */
		NVME_BUMP_STAT(cmd->nc_nvme, nvm_ns_notrdy);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	case NVME_CQE_SC_GEN_NVM_FORMATTING:
		/* Format in progress (1.2) */
		if (!NVME_VERSION_ATLEAST(&cmd->nc_nvme->n_version, 1, 2))
			return (nvme_check_unknown_cmd_status(cmd));
		NVME_BUMP_STAT(cmd->nc_nvme, nvm_ns_formatting);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_NTRDY);
		return (EIO);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static int
nvme_check_specific_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	switch (cqe->cqe_sf.sf_sc) {
	case NVME_CQE_SC_SPC_INV_CQ:
		/* Completion Queue Invalid */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_cq_err);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_QID:
		/* Invalid Queue Identifier */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_CQUEUE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_qid_err);
		return (EINVAL);

	case NVME_CQE_SC_SPC_MAX_QSZ_EXC:
		/* Max Queue Size Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_SQUEUE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE);
		NVME_BUMP_STAT(cmd->nc_nvme, max_qsz_exc);
		return (EINVAL);

	case NVME_CQE_SC_SPC_ABRT_CMD_EXC:
		/* Abort Command Limit Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_ABORT);
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "abort command limit exceeded in cmd %p", (void *)cmd);
		return (0);

	case NVME_CQE_SC_SPC_ASYNC_EVREQ_EXC:
		/* Async Event Request Limit Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_ASYNC_EVENT);
		dev_err(cmd->nc_nvme->n_dip, CE_PANIC, "programming error: "
		    "async event request limit exceeded in cmd %p",
		    (void *)cmd);
		return (0);

	case NVME_CQE_SC_SPC_INV_INT_VECT:
		/* Invalid Interrupt Vector */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_CREATE_CQUEUE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_int_vect);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_LOG_PAGE:
		/* Invalid Log Page */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_GET_LOG_PAGE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_log_page);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_FORMAT:
		/* Invalid Format */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_FORMAT ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NS_MGMT);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_format);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_Q_DEL:
		/* Invalid Queue Deletion */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_DELETE_CQUEUE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_q_del);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_CNFL_ATTR:
		/* Conflicting Attributes */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_DSET_MGMT ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_READ ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		NVME_BUMP_STAT(cmd->nc_nvme, cnfl_attr);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_INV_PROT:
		/* Invalid Protection Information */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_COMPARE ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_READ ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		NVME_BUMP_STAT(cmd->nc_nvme, inv_prot);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NVM_READONLY:
		/* Write to Read Only Range */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NVM_WRITE);
		NVME_BUMP_STAT(cmd->nc_nvme, readonly);
		if (cmd->nc_xfer != NULL)
			bd_error(cmd->nc_xfer, BD_ERR_ILLRQ);
		return (EROFS);

	case NVME_CQE_SC_SPC_INV_FW_SLOT:
		/* Invalid Firmware Slot */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_fwslot);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (EINVAL);

	case NVME_CQE_SC_SPC_INV_FW_IMG:
		/* Invalid Firmware Image */
		NVME_BUMP_STAT(cmd->nc_nvme, inv_fwimg);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (EINVAL);

	case NVME_CQE_SC_SPC_FW_RESET:
		/* Conventional Reset Required */
		NVME_BUMP_STAT(cmd->nc_nvme, fwact_creset);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (0);

	case NVME_CQE_SC_SPC_FW_NSSR:
		/* NVMe Subsystem Reset Required */
		NVME_BUMP_STAT(cmd->nc_nvme, fwact_nssr);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (0);

	case NVME_CQE_SC_SPC_FW_NEXT_RESET:
		/* Activation Requires Reset */
		NVME_BUMP_STAT(cmd->nc_nvme, fwact_reset);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (0);

	case NVME_CQE_SC_SPC_FW_MTFA:
		/* Activation Requires Maximum Time Violation */
		NVME_BUMP_STAT(cmd->nc_nvme, fwact_mtfa);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (EAGAIN);

	case NVME_CQE_SC_SPC_FW_PROHIBITED:
		/* Activation Prohibited */
		NVME_BUMP_STAT(cmd->nc_nvme, fwact_prohibited);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (EINVAL);

	case NVME_CQE_SC_SPC_FW_OVERLAP:
		/* Overlapping Firmware Ranges */
		NVME_BUMP_STAT(cmd->nc_nvme, fw_overlap);
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_FW_IMAGE_LOAD ||
		    cmd->nc_sqe.sqe_opc == NVME_OPC_FW_ACTIVATE);
		return (EINVAL);

	case NVME_CQE_SC_SPC_NS_ATTACHED:
		/* Namespace Already Attached */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ns_attached);
		return (EEXIST);

	case NVME_CQE_SC_SPC_NS_PRIV:
		/* Namespace Is Private */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ns_priv);
		return (EACCES);

	case NVME_CQE_SC_SPC_NS_NOT_ATTACH:
		/* Namespace Not Attached */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ns_not_attached);
		return (ENOENT);

	case NVME_CQE_SC_SPC_INV_CTRL_LIST:
		/* Controller List Invalid */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ana_attach);
		return (EINVAL);

	case NVME_CQE_SC_SPC_ANA_ATTACH:
		/* ANA Attach Failed */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ana_attach);
		return (EIO);

	case NVME_CQE_SC_SPC_NS_ATTACH_LIM:
		/* Namespace Attachment Limit Exceeded */
		ASSERT(cmd->nc_sqe.sqe_opc == NVME_OPC_NS_ATTACH);
		NVME_BUMP_STAT(cmd->nc_nvme, ns_attach_lim);
		return (EOVERFLOW);

	default:
		return (nvme_check_unknown_cmd_status(cmd));
	}
}

static inline int
nvme_check_cmd_status(nvme_cmd_t *cmd)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;

	/*
	 * Take a shortcut if the controller is dead, or if
	 * command status indicates no error.
	 */
	if (cmd->nc_nvme->n_dead)
		return (EIO);

	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
	    cqe->cqe_sf.sf_sc == NVME_CQE_SC_GEN_SUCCESS)
		return (0);

	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC)
		return (nvme_check_generic_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_SPECIFIC)
		return (nvme_check_specific_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_INTEGRITY)
		return (nvme_check_integrity_cmd_status(cmd));
	else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_VENDOR)
		return (nvme_check_vendor_cmd_status(cmd));

	return (nvme_check_unknown_cmd_status(cmd));
}

/*
 * Check the command status as used by an ioctl path and do not convert it to an
 * errno. We still allow all the command status checking to occur, but otherwise
 * will pass back the controller error as is.
 */
static boolean_t
nvme_check_cmd_status_ioctl(nvme_cmd_t *cmd, nvme_ioctl_common_t *ioc)
{
	nvme_cqe_t *cqe = &cmd->nc_cqe;
	nvme_t *nvme = cmd->nc_nvme;

	if (nvme->n_dead) {
		return (nvme_ioctl_error(ioc, nvme->n_dead_status, 0, 0));
	}

	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
	    cqe->cqe_sf.sf_sc == NVME_CQE_SC_GEN_SUCCESS)
		return (B_TRUE);

	if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC) {
		(void) nvme_check_generic_cmd_status(cmd);
	} else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_SPECIFIC) {
		(void) nvme_check_specific_cmd_status(cmd);
	} else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_INTEGRITY) {
		(void) nvme_check_integrity_cmd_status(cmd);
	} else if (cqe->cqe_sf.sf_sct == NVME_CQE_SCT_VENDOR) {
		(void) nvme_check_vendor_cmd_status(cmd);
	} else {
		(void) nvme_check_unknown_cmd_status(cmd);
	}

	return (nvme_ioctl_error(ioc, NVME_IOCTL_E_CTRL_ERROR,
	    cqe->cqe_sf.sf_sct, cqe->cqe_sf.sf_sc));
}

static int
nvme_abort_cmd(nvme_cmd_t *cmd, const uint32_t sec)
{
	nvme_t *nvme = cmd->nc_nvme;
	nvme_cmd_t *abort_cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	nvme_abort_cmd_t ac = { 0 };
	int ret = 0;

	sema_p(&nvme->n_abort_sema);

	ac.b.ac_cid = cmd->nc_sqe.sqe_cid;
	ac.b.ac_sqid = cmd->nc_sqid;

	abort_cmd->nc_sqid = 0;
	abort_cmd->nc_sqe.sqe_opc = NVME_OPC_ABORT;
	abort_cmd->nc_callback = nvme_wakeup_cmd;
	abort_cmd->nc_sqe.sqe_cdw10 = ac.r;

	/*
	 * Send the ABORT to the hardware. The ABORT command will return _after_
	 * the aborted command has completed (aborted or otherwise) so we must
	 * drop the aborted command's lock to allow it to complete.
	 * We want to allow at least `nvme_abort_cmd_timeout` seconds for the
	 * abort to be processed, but more if we are aborting a long-running
	 * command to give that time to complete/abort too.
	 */
	mutex_exit(&cmd->nc_mutex);
	nvme_admin_cmd(abort_cmd, MAX(nvme_abort_cmd_timeout, sec));
	mutex_enter(&cmd->nc_mutex);

	sema_v(&nvme->n_abort_sema);

	/* BEGIN CSTYLED */
	/*
	 * If the abort command itself has timed out, it will have been
	 * de-queued so that its callback will not be called after this point,
	 * and its state will be NVME_CMD_LOST.
	 *
	 * nvme_admin_cmd(abort_cmd)
	 *   -> nvme_wait_cmd(abort_cmd)
	 *     -> nvme_cmd(abort_cmd)
	 *     | -> nvme_admin_cmd(cmd)
	 *     |   -> nvme_wait_cmd(cmd)
	 *     |     -> nvme_ctrl_mark_dead()
	 *     |     -> nvme_lost_cmd(cmd)
	 *     |       -> cmd->nc_stat = NVME_CMD_LOST
	 *     and here we are.
	 */
	/* END CSTYLED */
	if (abort_cmd->nc_state == NVME_CMD_LOST) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!ABORT of command %d/%d timed out",
		    cmd->nc_sqe.sqe_cid, cmd->nc_sqid);
		NVME_BUMP_STAT(nvme, abort_timeout);
		ret = EIO;
	} else if ((ret = nvme_check_cmd_status(abort_cmd)) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!ABORT of command %d/%d "
		    "failed with sct = %x, sc = %x",
		    cmd->nc_sqe.sqe_cid, cmd->nc_sqid,
		    abort_cmd->nc_cqe.cqe_sf.sf_sct,
		    abort_cmd->nc_cqe.cqe_sf.sf_sc);
		NVME_BUMP_STAT(nvme, abort_failed);
	} else {
		boolean_t success = ((abort_cmd->nc_cqe.cqe_dw0 & 1) == 0);

		dev_err(nvme->n_dip, CE_WARN,
		    "!ABORT of command %d/%d %ssuccessful",
		    cmd->nc_sqe.sqe_cid, cmd->nc_sqid,
		    success ? "" : "un");

		if (success) {
			NVME_BUMP_STAT(nvme, abort_successful);
		} else {
			NVME_BUMP_STAT(nvme, abort_unsuccessful);
		}
	}

	/*
	 * This abort abort_cmd has either completed or been de-queued as
	 * lost in nvme_wait_cmd. Either way it's safe to free it here.
	 */
	nvme_free_cmd(abort_cmd);

	return (ret);
}

/*
 * nvme_wait_cmd -- wait for command completion or timeout
 *
 * In case of a serious error or a timeout of the abort command the hardware
 * will be declared dead and FMA will be notified.
 */
static void
nvme_wait_cmd(nvme_cmd_t *cmd, uint32_t sec)
{
	nvme_t *nvme = cmd->nc_nvme;
	nvme_reg_csts_t csts;

	ASSERT(mutex_owned(&cmd->nc_mutex));

	while (cmd->nc_state != NVME_CMD_COMPLETED) {
		clock_t timeout = ddi_get_lbolt() +
		    drv_usectohz((long)sec * MICROSEC);

		if (cv_timedwait(&cmd->nc_cv, &cmd->nc_mutex, timeout) == -1) {
			/*
			 * If this command is on the task queue then we don't
			 * consider it to have timed out. We are waiting for
			 * the callback to be invoked, the timing of which can
			 * be affected by system load and should not count
			 * against the device; continue to wait.
			 * While this doesn't help deal with the possibility of
			 * a command timing out between being placed on the CQ
			 * and arriving on the taskq, we expect interrupts to
			 * run fairly promptly making this a small window.
			 */
			if (cmd->nc_state != NVME_CMD_QUEUED)
				break;
		}
	}

	if (cmd->nc_state == NVME_CMD_COMPLETED) {
		DTRACE_PROBE1(nvme_admin_cmd_completed, nvme_cmd_t *, cmd);
		nvme_admin_stat_cmd(nvme, cmd);
		return;
	}

	/*
	 * The command timed out.
	 */

	DTRACE_PROBE1(nvme_admin_cmd_timeout, nvme_cmd_t *, cmd);
	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	dev_err(nvme->n_dip, CE_WARN, "!command %d/%d timeout, "
	    "OPC = %x, CFS = %d", cmd->nc_sqe.sqe_cid, cmd->nc_sqid,
	    cmd->nc_sqe.sqe_opc, csts.b.csts_cfs);
	NVME_BUMP_STAT(nvme, cmd_timeout);

	/*
	 * Check controller for fatal status, any errors associated with the
	 * register or DMA handle, or for a double timeout (abort command timed
	 * out). If necessary log a warning and call FMA.
	 */
	if (csts.b.csts_cfs ||
	    nvme_check_regs_hdl(nvme) ||
	    nvme_check_dma_hdl(cmd->nc_dma) ||
	    cmd->nc_sqe.sqe_opc == NVME_OPC_ABORT) {
		nvme_ctrl_mark_dead(cmd->nc_nvme, B_FALSE);
		nvme_lost_cmd(nvme, cmd);
		return;
	}

	/* Issue an abort for the command that has timed out */
	if (nvme_abort_cmd(cmd, sec) == 0) {
		/*
		 * If the abort completed, whether or not it was
		 * successful in aborting the command, that command
		 * will also have completed with an appropriate
		 * status.
		 */
		while (cmd->nc_state != NVME_CMD_COMPLETED)
			cv_wait(&cmd->nc_cv, &cmd->nc_mutex);
		return;
	}

	/*
	 * Otherwise, the abort has also timed out or failed, which
	 * will have marked the controller dead. De-queue the original command
	 * and add it to the lost commands list.
	 */
	VERIFY(cmd->nc_nvme->n_dead);
	nvme_lost_cmd(nvme, cmd);
}

static void
nvme_wakeup_cmd(void *arg)
{
	nvme_cmd_t *cmd = arg;

	ASSERT(cmd->nc_flags & NVME_CMD_F_USELOCK);

	mutex_enter(&cmd->nc_mutex);
	cmd->nc_state = NVME_CMD_COMPLETED;
	cv_signal(&cmd->nc_cv);
	mutex_exit(&cmd->nc_mutex);
}

static void
nvme_async_event_task(void *arg)
{
	nvme_cmd_t *cmd = arg;
	nvme_t *nvme = cmd->nc_nvme;
	nvme_error_log_entry_t *error_log = NULL;
	nvme_health_log_t *health_log = NULL;
	nvme_nschange_list_t *nslist = NULL;
	size_t logsize = 0;
	nvme_async_event_t event;

	/*
	 * Check for errors associated with the async request itself. The only
	 * command-specific error is "async event limit exceeded", which
	 * indicates a programming error in the driver and causes a panic in
	 * nvme_check_cmd_status().
	 *
	 * Other possible errors are various scenarios where the async request
	 * was aborted, or internal errors in the device. Internal errors are
	 * reported to FMA, the command aborts need no special handling here.
	 *
	 * And finally, at least qemu nvme does not support async events,
	 * and will return NVME_CQE_SC_GEN_INV_OPC | DNR. If so, we
	 * will avoid posting async events.
	 */

	if (nvme_check_cmd_status(cmd) != 0) {
		dev_err(cmd->nc_nvme->n_dip, CE_WARN,
		    "!async event request returned failure, sct = 0x%x, "
		    "sc = 0x%x, dnr = %d, m = %d", cmd->nc_cqe.cqe_sf.sf_sct,
		    cmd->nc_cqe.cqe_sf.sf_sc, cmd->nc_cqe.cqe_sf.sf_dnr,
		    cmd->nc_cqe.cqe_sf.sf_m);

		if (cmd->nc_cqe.cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
		    cmd->nc_cqe.cqe_sf.sf_sc == NVME_CQE_SC_GEN_INTERNAL_ERR) {
			nvme_ctrl_mark_dead(cmd->nc_nvme, B_FALSE);
		}

		if (cmd->nc_cqe.cqe_sf.sf_sct == NVME_CQE_SCT_GENERIC &&
		    cmd->nc_cqe.cqe_sf.sf_sc == NVME_CQE_SC_GEN_INV_OPC &&
		    cmd->nc_cqe.cqe_sf.sf_dnr == 1) {
			nvme->n_async_event_supported = B_FALSE;
		}

		nvme_free_cmd(cmd);
		return;
	}

	event.r = cmd->nc_cqe.cqe_dw0;

	/* Clear CQE and re-submit the async request. */
	bzero(&cmd->nc_cqe, sizeof (nvme_cqe_t));
	nvme_submit_admin_cmd(nvme->n_adminq, cmd, NULL);
	cmd = NULL;	/* cmd can no longer be used after resubmission */

	switch (event.b.ae_type) {
	case NVME_ASYNC_TYPE_ERROR:
		if (event.b.ae_logpage == NVME_LOGPAGE_ERROR) {
			if (!nvme_get_logpage_int(nvme, B_FALSE,
			    (void **)&error_log, &logsize,
			    NVME_LOGPAGE_ERROR)) {
				return;
			}
		} else {
			dev_err(nvme->n_dip, CE_WARN, "!wrong logpage in "
			    "async event reply: type=0x%x logpage=0x%x",
			    event.b.ae_type, event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, wrong_logpage);
			return;
		}

		switch (event.b.ae_info) {
		case NVME_ASYNC_ERROR_INV_SQ:
			dev_err(nvme->n_dip, CE_PANIC, "programming error: "
			    "invalid submission queue");
			return;

		case NVME_ASYNC_ERROR_INV_DBL:
			dev_err(nvme->n_dip, CE_PANIC, "programming error: "
			    "invalid doorbell write value");
			return;

		case NVME_ASYNC_ERROR_DIAGFAIL:
			dev_err(nvme->n_dip, CE_WARN, "!diagnostic failure");
			nvme_ctrl_mark_dead(nvme, B_FALSE);
			NVME_BUMP_STAT(nvme, diagfail_event);
			break;

		case NVME_ASYNC_ERROR_PERSISTENT:
			dev_err(nvme->n_dip, CE_WARN, "!persistent internal "
			    "device error");
			nvme_ctrl_mark_dead(nvme, B_FALSE);
			NVME_BUMP_STAT(nvme, persistent_event);
			break;

		case NVME_ASYNC_ERROR_TRANSIENT:
			dev_err(nvme->n_dip, CE_WARN, "!transient internal "
			    "device error");
			/* TODO: send ereport */
			NVME_BUMP_STAT(nvme, transient_event);
			break;

		case NVME_ASYNC_ERROR_FW_LOAD:
			dev_err(nvme->n_dip, CE_WARN,
			    "!firmware image load error");
			NVME_BUMP_STAT(nvme, fw_load_event);
			break;
		}
		break;

	case NVME_ASYNC_TYPE_HEALTH:
		if (event.b.ae_logpage == NVME_LOGPAGE_HEALTH) {
			if (!nvme_get_logpage_int(nvme, B_FALSE,
			    (void **)&health_log, &logsize,
			    NVME_LOGPAGE_HEALTH)) {
				return;
			}
		} else {
			dev_err(nvme->n_dip, CE_WARN, "!wrong logpage in "
			    "type=0x%x logpage=0x%x", event.b.ae_type,
			    event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, wrong_logpage);
			return;
		}

		switch (event.b.ae_info) {
		case NVME_ASYNC_HEALTH_RELIABILITY:
			dev_err(nvme->n_dip, CE_WARN,
			    "!device reliability compromised");
			/* TODO: send ereport */
			NVME_BUMP_STAT(nvme, reliability_event);
			break;

		case NVME_ASYNC_HEALTH_TEMPERATURE:
			dev_err(nvme->n_dip, CE_WARN,
			    "!temperature above threshold");
			/* TODO: send ereport */
			NVME_BUMP_STAT(nvme, temperature_event);
			break;

		case NVME_ASYNC_HEALTH_SPARE:
			dev_err(nvme->n_dip, CE_WARN,
			    "!spare space below threshold");
			/* TODO: send ereport */
			NVME_BUMP_STAT(nvme, spare_event);
			break;
		}
		break;

	case NVME_ASYNC_TYPE_NOTICE:
		switch (event.b.ae_info) {
		case NVME_ASYNC_NOTICE_NS_CHANGE:
			if (event.b.ae_logpage != NVME_LOGPAGE_NSCHANGE) {
				dev_err(nvme->n_dip, CE_WARN,
				    "!wrong logpage in async event reply: "
				    "type=0x%x logpage=0x%x",
				    event.b.ae_type, event.b.ae_logpage);
				NVME_BUMP_STAT(nvme, wrong_logpage);
				break;
			}

			dev_err(nvme->n_dip, CE_NOTE,
			    "namespace attribute change event, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);

			if (!nvme_get_logpage_int(nvme, B_FALSE,
			    (void **)&nslist, &logsize,
			    NVME_LOGPAGE_NSCHANGE)) {
				break;
			}

			if (nslist->nscl_ns[0] == UINT32_MAX) {
				dev_err(nvme->n_dip, CE_CONT,
				    "more than %u namespaces have changed.\n",
				    NVME_NSCHANGE_LIST_SIZE);
				break;
			}

			nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
			for (uint_t i = 0; i < NVME_NSCHANGE_LIST_SIZE; i++) {
				uint32_t nsid = nslist->nscl_ns[i];
				nvme_namespace_t *ns;

				if (nsid == 0)	/* end of list */
					break;

				dev_err(nvme->n_dip, CE_NOTE,
				    "!namespace nvme%d/%u has changed.",
				    ddi_get_instance(nvme->n_dip), nsid);

				if (nvme_init_ns(nvme, nsid) != DDI_SUCCESS)
					continue;

				ns = nvme_nsid2ns(nvme, nsid);
				if (ns->ns_state <= NVME_NS_STATE_NOT_IGNORED)
					continue;

				nvme_mgmt_bd_start(nvme);
				bd_state_change(ns->ns_bd_hdl);
				nvme_mgmt_bd_end(nvme);
			}
			nvme_mgmt_unlock(nvme);

			break;

		case NVME_ASYNC_NOTICE_FW_ACTIVATE:
			dev_err(nvme->n_dip, CE_NOTE,
			    "firmware activation starting, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		case NVME_ASYNC_NOTICE_TELEMETRY:
			dev_err(nvme->n_dip, CE_NOTE,
			    "telemetry log changed, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		case NVME_ASYNC_NOTICE_NS_ASYMM:
			dev_err(nvme->n_dip, CE_NOTE,
			    "asymmetric namespace access change, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		case NVME_ASYNC_NOTICE_LATENCYLOG:
			dev_err(nvme->n_dip, CE_NOTE,
			    "predictable latency event aggregate log change, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		case NVME_ASYNC_NOTICE_LBASTATUS:
			dev_err(nvme->n_dip, CE_NOTE,
			    "LBA status information alert, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		case NVME_ASYNC_NOTICE_ENDURANCELOG:
			dev_err(nvme->n_dip, CE_NOTE,
			    "endurance group event aggregate log page change, "
			    "logpage = 0x%x", event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, notice_event);
			break;

		default:
			dev_err(nvme->n_dip, CE_WARN,
			    "!unknown notice async event received, "
			    "info = 0x%x, logpage = 0x%x", event.b.ae_info,
			    event.b.ae_logpage);
			NVME_BUMP_STAT(nvme, unknown_event);
			break;
		}
		break;

	case NVME_ASYNC_TYPE_VENDOR:
		dev_err(nvme->n_dip, CE_WARN, "!vendor specific async event "
		    "received, info = 0x%x, logpage = 0x%x", event.b.ae_info,
		    event.b.ae_logpage);
		NVME_BUMP_STAT(nvme, vendor_event);
		break;

	default:
		dev_err(nvme->n_dip, CE_WARN, "!unknown async event received, "
		    "type = 0x%x, info = 0x%x, logpage = 0x%x", event.b.ae_type,
		    event.b.ae_info, event.b.ae_logpage);
		NVME_BUMP_STAT(nvme, unknown_event);
		break;
	}

	if (error_log != NULL)
		kmem_free(error_log, logsize);

	if (health_log != NULL)
		kmem_free(health_log, logsize);

	if (nslist != NULL)
		kmem_free(nslist, logsize);
}

static void
nvme_admin_cmd(nvme_cmd_t *cmd, uint32_t sec)
{
	uint32_t qtimeout;

	ASSERT(cmd->nc_flags & NVME_CMD_F_USELOCK);

	mutex_enter(&cmd->nc_mutex);
	cmd->nc_timeout = sec;
	nvme_submit_admin_cmd(cmd->nc_nvme->n_adminq, cmd, &qtimeout);
	/*
	 * We will wait for a total of this command's specified timeout plus
	 * the sum of the timeouts of any commands queued ahead of this one. If
	 * we aren't first in the queue, this will inflate the timeout somewhat
	 * but these times are not critical and it means that if we get stuck
	 * behind a long running command such as a namespace format then we
	 * won't time out and trigger an abort.
	 */
	nvme_wait_cmd(cmd, sec + qtimeout);
	mutex_exit(&cmd->nc_mutex);
}

static void
nvme_async_event(nvme_t *nvme)
{
	nvme_cmd_t *cmd;

	cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	cmd->nc_sqid = 0;
	cmd->nc_sqe.sqe_opc = NVME_OPC_ASYNC_EVENT;
	cmd->nc_callback = nvme_async_event_task;
	cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	nvme_submit_admin_cmd(nvme->n_adminq, cmd, NULL);
}

/*
 * There are commands such as format or vendor unique commands that are going to
 * manipulate the data in a namespace or destroy them, we make sure that none of
 * the ones that will be impacted are actually attached.
 */
static boolean_t
nvme_no_blkdev_attached(nvme_t *nvme, uint32_t nsid)
{
	ASSERT(nvme_mgmt_lock_held(nvme));
	ASSERT3U(nsid, !=, 0);

	if (nsid != NVME_NSID_BCAST) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, nsid);
		return (ns->ns_state < NVME_NS_STATE_ATTACHED);
	}

	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);

		if (ns->ns_state >= NVME_NS_STATE_ATTACHED) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
nvme_format_nvm(nvme_t *nvme, nvme_ioctl_format_t *ioc)
{
	nvme_cmd_t *cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	nvme_format_nvm_t format_nvm = { 0 };
	boolean_t ret;

	format_nvm.b.fm_lbaf = bitx32(ioc->nif_lbaf, 3, 0);
	format_nvm.b.fm_ses = bitx32(ioc->nif_ses, 2, 0);

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_nsid = ioc->nif_common.nioc_nsid;
	cmd->nc_sqe.sqe_opc = NVME_OPC_NVM_FORMAT;
	cmd->nc_sqe.sqe_cdw10 = format_nvm.r;

	/*
	 * We don't want to panic on any format commands. There are two reasons
	 * for this:
	 *
	 * 1) All format commands are initiated by users. We don't want to panic
	 * on user commands.
	 *
	 * 2) Several devices like the Samsung SM951 don't allow formatting of
	 * all namespaces in one command and we'd prefer to handle that
	 * gracefully.
	 */
	cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	nvme_admin_cmd(cmd, nvme_format_cmd_timeout);

	if (!nvme_check_cmd_status_ioctl(cmd, &ioc->nif_common) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!FORMAT failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		ret = B_FALSE;
		goto fail;
	}

	ret = B_TRUE;
fail:
	nvme_free_cmd(cmd);
	return (ret);
}

/*
 * Retrieve a specific log page. The contents of the log page request should
 * have already been validated by the system.
 */
static boolean_t
nvme_get_logpage(nvme_t *nvme, boolean_t user, nvme_ioctl_get_logpage_t *log,
    void **buf)
{
	nvme_cmd_t *cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	nvme_getlogpage_dw10_t dw10;
	uint32_t offlo, offhi;
	nvme_getlogpage_dw11_t dw11;
	nvme_getlogpage_dw14_t dw14;
	uint32_t ndw;
	boolean_t ret = B_FALSE;

	bzero(&dw10, sizeof (dw10));
	bzero(&dw11, sizeof (dw11));
	bzero(&dw14, sizeof (dw14));

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_GET_LOG_PAGE;
	cmd->nc_sqe.sqe_nsid = log->nigl_common.nioc_nsid;

	if (user)
		cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	/*
	 * The size field is the number of double words, but is a zeros based
	 * value. We need to store our actual value minus one.
	 */
	ndw = (uint32_t)(log->nigl_len / 4);
	ASSERT3U(ndw, >, 0);
	ndw--;

	dw10.b.lp_lid = bitx32(log->nigl_lid, 7, 0);
	dw10.b.lp_lsp = bitx32(log->nigl_lsp, 6, 0);
	dw10.b.lp_rae = bitx32(log->nigl_lsp, 0, 0);
	dw10.b.lp_lnumdl = bitx32(ndw, 15, 0);

	dw11.b.lp_numdu = bitx32(ndw, 31, 16);
	dw11.b.lp_lsi = bitx32(log->nigl_lsi, 15, 0);

	offlo = bitx64(log->nigl_offset, 31, 0);
	offhi = bitx64(log->nigl_offset, 63, 32);

	dw14.b.lp_csi = bitx32(log->nigl_csi, 7, 0);

	cmd->nc_sqe.sqe_cdw10 = dw10.r;
	cmd->nc_sqe.sqe_cdw11 = dw11.r;
	cmd->nc_sqe.sqe_cdw12 = offlo;
	cmd->nc_sqe.sqe_cdw13 = offhi;
	cmd->nc_sqe.sqe_cdw14 = dw14.r;

	if (nvme_zalloc_dma(nvme, log->nigl_len, DDI_DMA_READ,
	    &nvme->n_prp_dma_attr, &cmd->nc_dma) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_zalloc_dma failed for GET LOG PAGE");
		ret = nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_NO_DMA_MEM, 0, 0);
		goto fail;
	}

	if (nvme_fill_prp(cmd, cmd->nc_dma->nd_dmah) != 0) {
		ret = nvme_ioctl_error(&log->nigl_common,
		    NVME_IOCTL_E_NO_DMA_MEM, 0, 0);
		goto fail;
	}
	nvme_admin_cmd(cmd, nvme_admin_cmd_timeout);

	if (!nvme_check_cmd_status_ioctl(cmd, &log->nigl_common)) {
		if (!user) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!GET LOG PAGE failed with sct = %x, sc = %x",
			    cmd->nc_cqe.cqe_sf.sf_sct,
			    cmd->nc_cqe.cqe_sf.sf_sc);
		}
		ret = B_FALSE;
		goto fail;
	}

	*buf = kmem_alloc(log->nigl_len, KM_SLEEP);
	bcopy(cmd->nc_dma->nd_memp, *buf, log->nigl_len);

	ret = B_TRUE;
fail:
	nvme_free_cmd(cmd);

	return (ret);
}

/*
 * This is an internal wrapper for when the kernel wants to get a log page.
 * Currently this assumes that the only thing that is required is the log page
 * ID. If more information is required, we'll be better served to just use the
 * general ioctl interface.
 */
static boolean_t
nvme_get_logpage_int(nvme_t *nvme, boolean_t user, void **buf, size_t *bufsize,
    uint8_t lid)
{
	const nvme_log_page_info_t *info = NULL;
	nvme_ioctl_get_logpage_t log;
	nvme_valid_ctrl_data_t data;
	boolean_t bret;
	bool var;

	for (size_t i = 0; i < nvme_std_log_npages; i++) {
		if (nvme_std_log_pages[i].nlpi_lid == lid &&
		    nvme_std_log_pages[i].nlpi_csi == NVME_CSI_NVM) {
			info = &nvme_std_log_pages[i];
			break;
		}
	}

	if (info == NULL) {
		return (B_FALSE);
	}

	data.vcd_vers = &nvme->n_version;
	data.vcd_id = nvme->n_idctl;
	bzero(&log, sizeof (log));
	log.nigl_common.nioc_nsid = NVME_NSID_BCAST;
	log.nigl_csi = info->nlpi_csi;
	log.nigl_lid = info->nlpi_lid;
	log.nigl_len = nvme_log_page_info_size(info, &data, &var);

	/*
	 * We only support getting standard fixed-length log pages through the
	 * kernel interface at this time. If a log page either has an unknown
	 * size or has a variable length, then we cannot get it.
	 */
	if (log.nigl_len == 0 || var) {
		return (B_FALSE);
	}

	bret = nvme_get_logpage(nvme, user, &log, buf);
	if (!bret) {
		return (B_FALSE);
	}

	*bufsize = log.nigl_len;
	return (B_TRUE);
}

static boolean_t
nvme_identify(nvme_t *nvme, boolean_t user, nvme_ioctl_identify_t *ioc,
    void **buf)
{
	nvme_cmd_t *cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	boolean_t ret = B_FALSE;
	nvme_identify_dw10_t dw10;

	ASSERT3P(buf, !=, NULL);

	bzero(&dw10, sizeof (dw10));

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_IDENTIFY;
	cmd->nc_sqe.sqe_nsid = ioc->nid_common.nioc_nsid;

	dw10.b.id_cns = bitx32(ioc->nid_cns, 7, 0);
	dw10.b.id_cntid = bitx32(ioc->nid_ctrlid, 15, 0);

	cmd->nc_sqe.sqe_cdw10 = dw10.r;

	if (nvme_zalloc_dma(nvme, NVME_IDENTIFY_BUFSIZE, DDI_DMA_READ,
	    &nvme->n_prp_dma_attr, &cmd->nc_dma) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme_zalloc_dma failed for IDENTIFY");
		ret = nvme_ioctl_error(&ioc->nid_common,
		    NVME_IOCTL_E_NO_DMA_MEM, 0, 0);
		goto fail;
	}

	if (cmd->nc_dma->nd_ncookie > 2) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!too many DMA cookies for IDENTIFY");
		NVME_BUMP_STAT(nvme, too_many_cookies);
		ret = nvme_ioctl_error(&ioc->nid_common,
		    NVME_IOCTL_E_BAD_PRP, 0, 0);
		goto fail;
	}

	cmd->nc_sqe.sqe_dptr.d_prp[0] = cmd->nc_dma->nd_cookie.dmac_laddress;
	if (cmd->nc_dma->nd_ncookie > 1) {
		ddi_dma_nextcookie(cmd->nc_dma->nd_dmah,
		    &cmd->nc_dma->nd_cookie);
		cmd->nc_sqe.sqe_dptr.d_prp[1] =
		    cmd->nc_dma->nd_cookie.dmac_laddress;
	}

	if (user)
		cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	nvme_admin_cmd(cmd, nvme_admin_cmd_timeout);

	if (!nvme_check_cmd_status_ioctl(cmd, &ioc->nid_common)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!IDENTIFY failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
		ret = B_FALSE;
		goto fail;
	}

	*buf = kmem_alloc(NVME_IDENTIFY_BUFSIZE, KM_SLEEP);
	bcopy(cmd->nc_dma->nd_memp, *buf, NVME_IDENTIFY_BUFSIZE);
	ret = B_TRUE;

fail:
	nvme_free_cmd(cmd);

	return (ret);
}

static boolean_t
nvme_identify_int(nvme_t *nvme, uint32_t nsid, uint8_t cns, void **buf)
{
	nvme_ioctl_identify_t id;

	bzero(&id, sizeof (nvme_ioctl_identify_t));
	id.nid_common.nioc_nsid = nsid;
	id.nid_cns = cns;

	return (nvme_identify(nvme, B_FALSE, &id, buf));
}

static int
nvme_set_features(nvme_t *nvme, boolean_t user, uint32_t nsid, uint8_t feature,
    uint32_t val, uint32_t *res)
{
	_NOTE(ARGUNUSED(nsid));
	nvme_cmd_t *cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	int ret = EINVAL;

	ASSERT(res != NULL);

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_SET_FEATURES;
	cmd->nc_sqe.sqe_cdw10 = feature;
	cmd->nc_sqe.sqe_cdw11 = val;

	if (user)
		cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	switch (feature) {
	case NVME_FEAT_WRITE_CACHE:
		if (!nvme->n_write_cache_present)
			goto fail;
		break;

	case NVME_FEAT_NQUEUES:
		break;

	default:
		goto fail;
	}

	nvme_admin_cmd(cmd, nvme_admin_cmd_timeout);

	if ((ret = nvme_check_cmd_status(cmd)) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!SET FEATURES %d failed with sct = %x, sc = %x",
		    feature, cmd->nc_cqe.cqe_sf.sf_sct,
		    cmd->nc_cqe.cqe_sf.sf_sc);
		goto fail;
	}

	*res = cmd->nc_cqe.cqe_dw0;

fail:
	nvme_free_cmd(cmd);
	return (ret);
}

static int
nvme_write_cache_set(nvme_t *nvme, boolean_t enable)
{
	nvme_write_cache_t nwc = { 0 };

	if (enable)
		nwc.b.wc_wce = 1;

	/*
	 * We've seen some cases where this fails due to us being told we've
	 * specified an invalid namespace when operating against the Xen xcp-ng
	 * qemu NVMe virtual device. As such, we generally ensure that trying to
	 * enable this doesn't lead us to panic. It's not completely clear why
	 * specifying namespace zero here fails, but not when we're setting the
	 * number of queues below.
	 */
	return (nvme_set_features(nvme, B_TRUE, 0, NVME_FEAT_WRITE_CACHE,
	    nwc.r, &nwc.r));
}

static int
nvme_set_nqueues(nvme_t *nvme)
{
	nvme_nqueues_t nq = { 0 };
	int ret;

	/*
	 * The default is to allocate one completion queue per vector.
	 */
	if (nvme->n_completion_queues == -1)
		nvme->n_completion_queues = nvme->n_intr_cnt;

	/*
	 * There is no point in having more completion queues than
	 * interrupt vectors.
	 */
	nvme->n_completion_queues = MIN(nvme->n_completion_queues,
	    nvme->n_intr_cnt);

	/*
	 * The default is to use one submission queue per completion queue.
	 */
	if (nvme->n_submission_queues == -1)
		nvme->n_submission_queues = nvme->n_completion_queues;

	/*
	 * There is no point in having more completion queues than
	 * submission queues.
	 */
	nvme->n_completion_queues = MIN(nvme->n_completion_queues,
	    nvme->n_submission_queues);

	ASSERT(nvme->n_submission_queues > 0);
	ASSERT(nvme->n_completion_queues > 0);

	nq.b.nq_nsq = nvme->n_submission_queues - 1;
	nq.b.nq_ncq = nvme->n_completion_queues - 1;

	ret = nvme_set_features(nvme, B_FALSE, 0, NVME_FEAT_NQUEUES, nq.r,
	    &nq.r);

	if (ret == 0) {
		/*
		 * Never use more than the requested number of queues.
		 */
		nvme->n_submission_queues = MIN(nvme->n_submission_queues,
		    nq.b.nq_nsq + 1);
		nvme->n_completion_queues = MIN(nvme->n_completion_queues,
		    nq.b.nq_ncq + 1);
	}

	return (ret);
}

static int
nvme_create_completion_queue(nvme_t *nvme, nvme_cq_t *cq)
{
	nvme_cmd_t *cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	nvme_create_queue_dw10_t dw10 = { 0 };
	nvme_create_cq_dw11_t c_dw11 = { 0 };
	int ret;

	dw10.b.q_qid = cq->ncq_id;
	dw10.b.q_qsize = cq->ncq_nentry - 1;

	c_dw11.b.cq_pc = 1;
	c_dw11.b.cq_ien = 1;
	c_dw11.b.cq_iv = cq->ncq_id % nvme->n_intr_cnt;

	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_CREATE_CQUEUE;
	cmd->nc_sqe.sqe_cdw10 = dw10.r;
	cmd->nc_sqe.sqe_cdw11 = c_dw11.r;
	cmd->nc_sqe.sqe_dptr.d_prp[0] = cq->ncq_dma->nd_cookie.dmac_laddress;

	nvme_admin_cmd(cmd, nvme_admin_cmd_timeout);

	if ((ret = nvme_check_cmd_status(cmd)) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!CREATE CQUEUE failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
	}

	nvme_free_cmd(cmd);

	return (ret);
}

static int
nvme_create_io_qpair(nvme_t *nvme, nvme_qpair_t *qp, uint16_t idx)
{
	nvme_cq_t *cq = qp->nq_cq;
	nvme_cmd_t *cmd;
	nvme_create_queue_dw10_t dw10 = { 0 };
	nvme_create_sq_dw11_t s_dw11 = { 0 };
	int ret;

	/*
	 * It is possible to have more qpairs than completion queues,
	 * and when the idx > ncq_id, that completion queue is shared
	 * and has already been created.
	 */
	if (idx <= cq->ncq_id &&
	    nvme_create_completion_queue(nvme, cq) != DDI_SUCCESS)
		return (DDI_FAILURE);

	dw10.b.q_qid = idx;
	dw10.b.q_qsize = qp->nq_nentry - 1;

	s_dw11.b.sq_pc = 1;
	s_dw11.b.sq_cqid = cq->ncq_id;

	cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	cmd->nc_sqid = 0;
	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe.sqe_opc = NVME_OPC_CREATE_SQUEUE;
	cmd->nc_sqe.sqe_cdw10 = dw10.r;
	cmd->nc_sqe.sqe_cdw11 = s_dw11.r;
	cmd->nc_sqe.sqe_dptr.d_prp[0] = qp->nq_sqdma->nd_cookie.dmac_laddress;

	nvme_admin_cmd(cmd, nvme_admin_cmd_timeout);

	if ((ret = nvme_check_cmd_status(cmd)) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!CREATE SQUEUE failed with sct = %x, sc = %x",
		    cmd->nc_cqe.cqe_sf.sf_sct, cmd->nc_cqe.cqe_sf.sf_sc);
	}

	nvme_free_cmd(cmd);

	return (ret);
}

static boolean_t
nvme_reset(nvme_t *nvme, boolean_t quiesce)
{
	nvme_reg_csts_t csts;
	int i;

	/*
	 * If the device is gone, do not try to interact with it.  We define
	 * that resetting such a device is impossible, and always fails.
	 */
	if (nvme_ctrl_is_gone(nvme)) {
		return (B_FALSE);
	}

	nvme_put32(nvme, NVME_REG_CC, 0);

	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	if (csts.b.csts_rdy == 1) {
		nvme_put32(nvme, NVME_REG_CC, 0);

		/*
		 * The timeout value is from the Controller Capabilities
		 * register (CAP.TO, section 3.1.1). This is the worst case
		 * time to wait for CSTS.RDY to transition from 1 to 0 after
		 * CC.EN transitions from 1 to 0.
		 *
		 * The timeout units are in 500 ms units, and we are delaying
		 * in 50ms chunks, hence counting to n_timeout * 10.
		 */
		for (i = 0; i < nvme->n_timeout * 10; i++) {
			csts.r = nvme_get32(nvme, NVME_REG_CSTS);
			if (csts.b.csts_rdy == 0)
				break;

			/*
			 * Quiescing drivers should not use locks or timeouts,
			 * so if this is the quiesce path, use a quiesce-safe
			 * delay.
			 */
			if (quiesce) {
				drv_usecwait(50000);
			} else {
				delay(drv_usectohz(50000));
			}
		}
	}

	nvme_put32(nvme, NVME_REG_AQA, 0);
	nvme_put32(nvme, NVME_REG_ASQ, 0);
	nvme_put32(nvme, NVME_REG_ACQ, 0);

	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	return (csts.b.csts_rdy == 0 ? B_TRUE : B_FALSE);
}

static void
nvme_shutdown(nvme_t *nvme, boolean_t quiesce)
{
	nvme_reg_cc_t cc;
	nvme_reg_csts_t csts;
	int i;

	/*
	 * Do not try to interact with the device if it is gone.  Since it is
	 * not there, in some sense it must already be shut down anyway.
	 */
	if (nvme_ctrl_is_gone(nvme)) {
		return;
	}

	cc.r = nvme_get32(nvme, NVME_REG_CC);
	cc.b.cc_shn = NVME_CC_SHN_NORMAL;
	nvme_put32(nvme, NVME_REG_CC, cc.r);

	for (i = 0; i < 10; i++) {
		csts.r = nvme_get32(nvme, NVME_REG_CSTS);
		if (csts.b.csts_shst == NVME_CSTS_SHN_COMPLETE)
			break;

		if (quiesce) {
			drv_usecwait(100000);
		} else {
			delay(drv_usectohz(100000));
		}
	}
}

/*
 * Return length of string without trailing spaces.
 */
static size_t
nvme_strlen(const char *str, size_t len)
{
	if (len <= 0)
		return (0);

	while (str[--len] == ' ')
		;

	return (++len);
}

static void
nvme_config_min_block_size(nvme_t *nvme, char *model, char *val)
{
	ulong_t bsize = 0;
	char *msg = "";

	if (ddi_strtoul(val, NULL, 0, &bsize) != 0)
		goto err;

	if (!ISP2(bsize)) {
		msg = ": not a power of 2";
		goto err;
	}

	if (bsize < NVME_DEFAULT_MIN_BLOCK_SIZE) {
		msg = ": too low";
		goto err;
	}

	nvme->n_min_block_size = bsize;
	return;

err:
	dev_err(nvme->n_dip, CE_WARN,
	    "!nvme-config-list: ignoring invalid min-phys-block-size '%s' "
	    "for model '%s'%s", val, model, msg);

	nvme->n_min_block_size = NVME_DEFAULT_MIN_BLOCK_SIZE;
}

static void
nvme_config_boolean(nvme_t *nvme, char *model, char *name, char *val,
    boolean_t *b)
{
	if (strcmp(val, "on") == 0 ||
	    strcmp(val, "true") == 0)
		*b = B_TRUE;
	else if (strcmp(val, "off") == 0 ||
	    strcmp(val, "false") == 0)
		*b = B_FALSE;
	else
		dev_err(nvme->n_dip, CE_WARN,
		    "!nvme-config-list: invalid value for %s '%s'"
		    " for model '%s', ignoring", name, val, model);
}

static void
nvme_config_list(nvme_t *nvme)
{
	char	**config_list;
	uint_t	nelem;
	int	rv;

	/*
	 * We're following the pattern of 'sd-config-list' here, but extend it.
	 * Instead of two we have three separate strings for "model", "fwrev",
	 * and "name-value-list".
	 */
	rv = ddi_prop_lookup_string_array(DDI_DEV_T_ANY, nvme->n_dip,
	    DDI_PROP_DONTPASS, "nvme-config-list", &config_list, &nelem);

	if (rv != DDI_PROP_SUCCESS) {
		if (rv == DDI_PROP_CANNOT_DECODE) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!nvme-config-list: cannot be decoded");
		}

		return;
	}

	if ((nelem % 3) != 0) {
		dev_err(nvme->n_dip, CE_WARN, "!nvme-config-list: must be "
		    "triplets of <model>/<fwrev>/<name-value-list> strings ");
		goto out;
	}

	for (uint_t i = 0; i < nelem; i += 3) {
		char	*model = config_list[i];
		char	*fwrev = config_list[i + 1];
		char	*nvp, *save_nv;
		size_t	id_model_len, id_fwrev_len;

		id_model_len = nvme_strlen(nvme->n_idctl->id_model,
		    sizeof (nvme->n_idctl->id_model));

		if (strlen(model) != id_model_len)
			continue;

		if (strncmp(model, nvme->n_idctl->id_model, id_model_len) != 0)
			continue;

		id_fwrev_len = nvme_strlen(nvme->n_idctl->id_fwrev,
		    sizeof (nvme->n_idctl->id_fwrev));

		if (strlen(fwrev) != 0) {
			boolean_t match = B_FALSE;
			char *fwr, *last_fw;

			for (fwr = strtok_r(fwrev, ",", &last_fw);
			    fwr != NULL;
			    fwr = strtok_r(NULL, ",", &last_fw)) {
				if (strlen(fwr) != id_fwrev_len)
					continue;

				if (strncmp(fwr, nvme->n_idctl->id_fwrev,
				    id_fwrev_len) == 0)
					match = B_TRUE;
			}

			if (!match)
				continue;
		}

		/*
		 * We should now have a comma-separated list of name:value
		 * pairs.
		 */
		for (nvp = strtok_r(config_list[i + 2], ",", &save_nv);
		    nvp != NULL; nvp = strtok_r(NULL, ",", &save_nv)) {
			char	*name = nvp;
			char	*val = strchr(nvp, ':');

			if (val == NULL || name == val) {
				dev_err(nvme->n_dip, CE_WARN,
				    "!nvme-config-list: <name-value-list> "
				    "for model '%s' is malformed", model);
				goto out;
			}

			/*
			 * Null-terminate 'name', move 'val' past ':' sep.
			 */
			*val++ = '\0';

			/*
			 * Process the name:val pairs that we know about.
			 */
			if (strcmp(name, "ignore-unknown-vendor-status") == 0) {
				nvme_config_boolean(nvme, model, name, val,
				    &nvme->n_ignore_unknown_vendor_status);
			} else if (strcmp(name, "min-phys-block-size") == 0) {
				nvme_config_min_block_size(nvme, model, val);
			} else if (strcmp(name, "volatile-write-cache") == 0) {
				nvme_config_boolean(nvme, model, name, val,
				    &nvme->n_write_cache_enabled);
			} else {
				/*
				 * Unknown 'name'.
				 */
				dev_err(nvme->n_dip, CE_WARN,
				    "!nvme-config-list: unknown config '%s' "
				    "for model '%s', ignoring", name, model);
			}
		}
	}

out:
	ddi_prop_free(config_list);
}

static void
nvme_prepare_devid(nvme_t *nvme, uint32_t nsid)
{
	/*
	 * Section 7.7 of the spec describes how to get a unique ID for
	 * the controller: the vendor ID, the model name and the serial
	 * number shall be unique when combined.
	 *
	 * If a namespace has no EUI64 we use the above and add the hex
	 * namespace ID to get a unique ID for the namespace.
	 */
	char model[sizeof (nvme->n_idctl->id_model) + 1];
	char serial[sizeof (nvme->n_idctl->id_serial) + 1];

	bcopy(nvme->n_idctl->id_model, model, sizeof (nvme->n_idctl->id_model));
	bcopy(nvme->n_idctl->id_serial, serial,
	    sizeof (nvme->n_idctl->id_serial));

	model[sizeof (nvme->n_idctl->id_model)] = '\0';
	serial[sizeof (nvme->n_idctl->id_serial)] = '\0';

	nvme_nsid2ns(nvme, nsid)->ns_devid = kmem_asprintf("%4X-%s-%s-%X",
	    nvme->n_idctl->id_vid, model, serial, nsid);
}

static nvme_identify_nsid_list_t *
nvme_update_nsid_list(nvme_t *nvme, int cns)
{
	nvme_identify_nsid_list_t *nslist;

	/*
	 * We currently don't handle cases where there are more than
	 * 1024 active namespaces, requiring several IDENTIFY commands.
	 */
	if (nvme_identify_int(nvme, 0, cns, (void **)&nslist))
		return (nslist);

	return (NULL);
}

nvme_namespace_t *
nvme_nsid2ns(nvme_t *nvme, uint32_t nsid)
{
	ASSERT3U(nsid, !=, 0);
	ASSERT3U(nsid, <=, nvme->n_namespace_count);
	return (&nvme->n_ns[nsid - 1]);
}

static boolean_t
nvme_allocated_ns(nvme_namespace_t *ns)
{
	nvme_t *nvme = ns->ns_nvme;
	uint32_t i;

	ASSERT(nvme_mgmt_lock_held(nvme));

	/*
	 * If supported, update the list of allocated namespace IDs.
	 */
	if (NVME_VERSION_ATLEAST(&nvme->n_version, 1, 2) &&
	    nvme->n_idctl->id_oacs.oa_nsmgmt != 0) {
		nvme_identify_nsid_list_t *nslist = nvme_update_nsid_list(nvme,
		    NVME_IDENTIFY_NSID_ALLOC_LIST);
		boolean_t found = B_FALSE;

		/*
		 * When namespace management is supported, this really shouldn't
		 * be NULL. Treat all namespaces as allocated if it is.
		 */
		if (nslist == NULL)
			return (B_TRUE);

		for (i = 0; i < ARRAY_SIZE(nslist->nl_nsid); i++) {
			if (ns->ns_id == 0)
				break;

			if (ns->ns_id == nslist->nl_nsid[i])
				found = B_TRUE;
		}

		kmem_free(nslist, NVME_IDENTIFY_BUFSIZE);
		return (found);
	} else {
		/*
		 * If namespace management isn't supported, report all
		 * namespaces as allocated.
		 */
		return (B_TRUE);
	}
}

static boolean_t
nvme_active_ns(nvme_namespace_t *ns)
{
	nvme_t *nvme = ns->ns_nvme;
	uint64_t *ptr;
	uint32_t i;

	ASSERT(nvme_mgmt_lock_held(nvme));

	/*
	 * If supported, update the list of active namespace IDs.
	 */
	if (NVME_VERSION_ATLEAST(&nvme->n_version, 1, 1)) {
		nvme_identify_nsid_list_t *nslist = nvme_update_nsid_list(nvme,
		    NVME_IDENTIFY_NSID_LIST);
		boolean_t found = B_FALSE;

		/*
		 * When namespace management is supported, this really shouldn't
		 * be NULL. Treat all namespaces as allocated if it is.
		 */
		if (nslist == NULL)
			return (B_TRUE);

		for (i = 0; i < ARRAY_SIZE(nslist->nl_nsid); i++) {
			if (ns->ns_id == 0)
				break;

			if (ns->ns_id == nslist->nl_nsid[i])
				found = B_TRUE;
		}

		kmem_free(nslist, NVME_IDENTIFY_BUFSIZE);
		return (found);
	}

	/*
	 * Workaround for revision 1.0:
	 * Check whether the IDENTIFY NAMESPACE data is zero-filled.
	 */
	for (ptr = (uint64_t *)ns->ns_idns;
	    ptr != (uint64_t *)(ns->ns_idns + 1);
	    ptr++) {
		if (*ptr != 0) {
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

static int
nvme_init_ns(nvme_t *nvme, uint32_t nsid)
{
	nvme_namespace_t *ns = nvme_nsid2ns(nvme, nsid);
	nvme_identify_nsid_t *idns;
	nvme_ns_state_t orig_state;

	ns->ns_nvme = nvme;

	ASSERT(nvme_mgmt_lock_held(nvme));

	/*
	 * Because we might rescan a namespace and this will fail after boot
	 * that'd leave us in a bad spot. We need to do something about this
	 * longer term, but it's not clear how exactly we would recover right
	 * now.
	 */
	if (!nvme_identify_int(nvme, nsid, NVME_IDENTIFY_NSID,
	    (void **)&idns)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to identify namespace %d", nsid);
		return (DDI_FAILURE);
	}

	if (ns->ns_idns != NULL)
		kmem_free(ns->ns_idns, sizeof (nvme_identify_nsid_t));

	ns->ns_idns = idns;
	ns->ns_id = nsid;

	/*
	 * Save the current state so we can tell what changed. Look at the
	 * current state of the device. We will flag active devices that should
	 * be ignored after this.
	 */
	orig_state = ns->ns_state;
	if (nvme_active_ns(ns)) {
		/*
		 * If the device previously had blkdev active, then that is its
		 * current state. Otherwise, we consider this an upgrade and
		 * just set it to not ignored.
		 */
		if (orig_state == NVME_NS_STATE_ATTACHED) {
			ns->ns_state = NVME_NS_STATE_ATTACHED;
		} else {
			ns->ns_state = NVME_NS_STATE_NOT_IGNORED;
		}
	} else if (nvme_allocated_ns(ns)) {
		ns->ns_state = NVME_NS_STATE_ALLOCATED;
	} else {
		ns->ns_state = NVME_NS_STATE_UNALLOCATED;
	}

	ns->ns_block_count = idns->id_nsize;
	ns->ns_block_size =
	    1 << idns->id_lbaf[idns->id_flbas.lba_format].lbaf_lbads;
	ns->ns_best_block_size = ns->ns_block_size;

	/*
	 * Get the EUI64 if present.
	 */
	if (NVME_VERSION_ATLEAST(&nvme->n_version, 1, 1))
		bcopy(idns->id_eui64, ns->ns_eui64, sizeof (ns->ns_eui64));

	/*
	 * Get the NGUID if present.
	 */
	if (NVME_VERSION_ATLEAST(&nvme->n_version, 1, 2))
		bcopy(idns->id_nguid, ns->ns_nguid, sizeof (ns->ns_nguid));

	/*LINTED: E_BAD_PTR_CAST_ALIGN*/
	if (*(uint64_t *)ns->ns_eui64 == 0)
		nvme_prepare_devid(nvme, ns->ns_id);

	(void) snprintf(ns->ns_name, sizeof (ns->ns_name), "%u", ns->ns_id);

	/*
	 * Find the LBA format with no metadata and the best relative
	 * performance. A value of 3 means "degraded", 0 is best.
	 */
	for (uint32_t j = 0, last_rp = 3; j <= idns->id_nlbaf; j++) {
		if (idns->id_lbaf[j].lbaf_lbads == 0)
			break;
		if (idns->id_lbaf[j].lbaf_ms != 0)
			continue;
		if (idns->id_lbaf[j].lbaf_rp >= last_rp)
			continue;
		last_rp = idns->id_lbaf[j].lbaf_rp;
		ns->ns_best_block_size =
		    1 << idns->id_lbaf[j].lbaf_lbads;
	}

	if (ns->ns_best_block_size < nvme->n_min_block_size)
		ns->ns_best_block_size = nvme->n_min_block_size;

	/*
	 * We currently don't support namespaces that are inactive, or use
	 * either:
	 * - protection information
	 * - illegal block size (< 512)
	 */
	if (ns->ns_state >= NVME_NS_STATE_NOT_IGNORED) {
		if (idns->id_dps.dp_pinfo) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!ignoring namespace %d, unsupported feature: "
			    "pinfo = %d", nsid, idns->id_dps.dp_pinfo);
			ns->ns_state = NVME_NS_STATE_ACTIVE;
		}

		if (ns->ns_block_size < 512) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!ignoring namespace %d, unsupported block size "
			    "%"PRIu64, nsid, (uint64_t)ns->ns_block_size);
			ns->ns_state = NVME_NS_STATE_ACTIVE;
		}
	}

	/*
	 * If we were previously in a state where blkdev was active and suddenly
	 * we think it should not be because ignore is set, then something has
	 * gone behind our backs and this is not going to be recoverable.
	 */
	if (orig_state == NVME_NS_STATE_ATTACHED &&
	    ns->ns_state != NVME_NS_STATE_ATTACHED) {
		dev_err(nvme->n_dip, CE_PANIC, "namespace %u state "
		    "unexpectedly changed and removed blkdev support!", nsid);
	}

	/*
	 * Keep a count of namespaces which are attachable.
	 * See comments in nvme_bd_driveinfo() to understand its effect.
	 */
	if (orig_state > NVME_NS_STATE_ACTIVE) {
		/*
		 * Wasn't attachable previously, but now needs to be.
		 * Discount it.
		 */
		if (ns->ns_state < NVME_NS_STATE_NOT_IGNORED)
			nvme->n_namespaces_attachable--;
	} else if (ns->ns_state >= NVME_NS_STATE_NOT_IGNORED) {
		/*
		 * Previously ignored, but now not. Count it.
		 */
		nvme->n_namespaces_attachable++;
	}

	return (DDI_SUCCESS);
}

static boolean_t
nvme_bd_attach_ns(nvme_t *nvme, nvme_ioctl_common_t *com)
{
	nvme_namespace_t *ns = nvme_nsid2ns(nvme, com->nioc_nsid);
	int ret;

	ASSERT(nvme_mgmt_lock_held(nvme));

	if (!nvme_ns_state_check(ns, com, nvme_bd_attach_states)) {
		return (B_FALSE);
	}

	if (ns->ns_bd_hdl == NULL) {
		bd_ops_t ops = nvme_bd_ops;

		if (!nvme->n_idctl->id_oncs.on_dset_mgmt)
			ops.o_free_space = NULL;

		ns->ns_bd_hdl = bd_alloc_handle(ns, &ops, &nvme->n_prp_dma_attr,
		    KM_SLEEP);

		if (ns->ns_bd_hdl == NULL) {
			dev_err(nvme->n_dip, CE_WARN, "!Failed to get blkdev "
			    "handle for namespace id %u", com->nioc_nsid);
			return (nvme_ioctl_error(com,
			    NVME_IOCTL_E_BLKDEV_ATTACH, 0, 0));
		}
	}

	nvme_mgmt_bd_start(nvme);
	ret = bd_attach_handle(nvme->n_dip, ns->ns_bd_hdl);
	nvme_mgmt_bd_end(nvme);
	if (ret != DDI_SUCCESS) {
		return (nvme_ioctl_error(com, NVME_IOCTL_E_BLKDEV_ATTACH,
		    0, 0));
	}

	ns->ns_state = NVME_NS_STATE_ATTACHED;

	return (B_TRUE);
}

static boolean_t
nvme_bd_detach_ns(nvme_t *nvme, nvme_ioctl_common_t *com)
{
	nvme_namespace_t *ns = nvme_nsid2ns(nvme, com->nioc_nsid);
	int ret;

	ASSERT(nvme_mgmt_lock_held(nvme));

	if (!nvme_ns_state_check(ns, com, nvme_bd_detach_states)) {
		return (B_FALSE);
	}

	nvme_mgmt_bd_start(nvme);
	ASSERT3P(ns->ns_bd_hdl, !=, NULL);
	ret = bd_detach_handle(ns->ns_bd_hdl);
	nvme_mgmt_bd_end(nvme);

	if (ret != DDI_SUCCESS) {
		return (nvme_ioctl_error(com, NVME_IOCTL_E_BLKDEV_DETACH, 0,
		    0));
	}

	ns->ns_state = NVME_NS_STATE_NOT_IGNORED;
	return (B_TRUE);

}

/*
 * Rescan the namespace information associated with the namespaces indicated by
 * ioc. They should not be attached to blkdev right now.
 */
static void
nvme_rescan_ns(nvme_t *nvme, uint32_t nsid)
{
	ASSERT(nvme_mgmt_lock_held(nvme));
	ASSERT3U(nsid, !=, 0);

	if (nsid != NVME_NSID_BCAST) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, nsid);

		ASSERT3U(ns->ns_state, <, NVME_NS_STATE_ATTACHED);
		(void) nvme_init_ns(nvme, nsid);
		return;
	}

	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);

		ASSERT3U(ns->ns_state, <, NVME_NS_STATE_ATTACHED);
		(void) nvme_init_ns(nvme, i);
	}
}

typedef struct nvme_quirk_table {
	uint16_t nq_vendor_id;
	uint16_t nq_device_id;
	nvme_quirk_t nq_quirks;
} nvme_quirk_table_t;

static const nvme_quirk_table_t nvme_quirks[] = {
	{ 0x1987, 0x5018, NVME_QUIRK_START_CID },	/* Phison E18 */
};

static void
nvme_detect_quirks(nvme_t *nvme)
{
	for (uint_t i = 0; i < ARRAY_SIZE(nvme_quirks); i++) {
		const nvme_quirk_table_t *nqt = &nvme_quirks[i];

		if (nqt->nq_vendor_id == nvme->n_vendor_id &&
		    nqt->nq_device_id == nvme->n_device_id) {
			nvme->n_quirks = nqt->nq_quirks;
			return;
		}
	}
}

/*
 * Indicate to the controller that we support various behaviors. These are
 * things the controller needs to be proactively told. We only will do this if
 * the controller indicates support for something that we care about, otherwise
 * there is no need to talk to the controller and there is no separate way to
 * know that this feature is otherwise supported. Support for most features is
 * indicated by setting it to 1.
 *
 * The current behaviors we enable are:
 *
 *  - Extended Telemetry Data Area 4: This enables additional telemetry to be
 *    possibly generated and depends on the DA4S bit in the log page attributes.
 */
static void
nvme_enable_host_behavior(nvme_t *nvme)
{
	nvme_host_behavior_t *hb;
	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe = {
		.sqe_opc = NVME_OPC_SET_FEATURES,
		.sqe_cdw10 = NVME_FEAT_HOST_BEHAVE,
		.sqe_nsid = 0
	};
	nvme_ioctl_common_t err;

	if (nvme->n_idctl->id_lpa.lp_da4s == 0)
		return;

	hb = kmem_zalloc(sizeof (nvme_host_behavior_t), KM_SLEEP);
	hb->nhb_etdas = 1;

	args.ica_sqe = &sqe;
	args.ica_data = hb;
	args.ica_data_len = sizeof (nvme_host_behavior_t);
	args.ica_dma_flags = DDI_DMA_WRITE;
	args.ica_copy_flags = FKIOCTL;
	args.ica_timeout = nvme_admin_cmd_timeout;

	if (!nvme_ioc_cmd(nvme, &err, &args)) {
		dev_err(nvme->n_dip, CE_WARN, "failed to enable host behavior "
		    "feature: 0x%x/0x%x/0x%x", err.nioc_drv_err,
		    err.nioc_ctrl_sct, err.nioc_ctrl_sc);
	}

	kmem_free(hb, sizeof (nvme_host_behavior_t));
}

static int
nvme_init(nvme_t *nvme)
{
	nvme_reg_cc_t cc = { 0 };
	nvme_reg_aqa_t aqa = { 0 };
	nvme_reg_asq_t asq = { 0 };
	nvme_reg_acq_t acq = { 0 };
	nvme_reg_cap_t cap;
	nvme_reg_vs_t vs;
	nvme_reg_csts_t csts;
	int i = 0;
	uint16_t nqueues;
	uint_t tq_threads;
	char model[sizeof (nvme->n_idctl->id_model) + 1];
	char *vendor, *product;
	uint32_t nsid;

	/* Check controller version */
	vs.r = nvme_get32(nvme, NVME_REG_VS);
	nvme->n_version.v_major = vs.b.vs_mjr;
	nvme->n_version.v_minor = vs.b.vs_mnr;
	dev_err(nvme->n_dip, CE_CONT, "?NVMe spec version %d.%d\n",
	    nvme->n_version.v_major, nvme->n_version.v_minor);

	if (nvme->n_version.v_major > nvme_version_major) {
		dev_err(nvme->n_dip, CE_WARN, "!no support for version > %d.x",
		    nvme_version_major);
		if (nvme->n_strict_version)
			goto fail;
	}

	/* retrieve controller configuration */
	cap.r = nvme_get64(nvme, NVME_REG_CAP);

	if ((cap.b.cap_css & NVME_CAP_CSS_NVM) == 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!NVM command set not supported by hardware");
		goto fail;
	}

	nvme->n_nssr_supported = cap.b.cap_nssrs;
	nvme->n_doorbell_stride = 4 << cap.b.cap_dstrd;
	nvme->n_timeout = cap.b.cap_to;
	nvme->n_arbitration_mechanisms = cap.b.cap_ams;
	nvme->n_cont_queues_reqd = cap.b.cap_cqr;
	nvme->n_max_queue_entries = cap.b.cap_mqes + 1;

	/*
	 * The MPSMIN and MPSMAX fields in the CAP register use 0 to specify
	 * the base page size of 4k (1<<12), so add 12 here to get the real
	 * page size value.
	 */
	nvme->n_pageshift = MIN(MAX(cap.b.cap_mpsmin + 12, PAGESHIFT),
	    cap.b.cap_mpsmax + 12);
	nvme->n_pagesize = 1UL << (nvme->n_pageshift);

	/*
	 * Set up Queue DMA to transfer at least 1 page-aligned page at a time.
	 */
	nvme->n_queue_dma_attr.dma_attr_align = nvme->n_pagesize;
	nvme->n_queue_dma_attr.dma_attr_minxfer = nvme->n_pagesize;

	/*
	 * Set up PRP DMA to transfer 1 page-aligned page at a time.
	 * Maxxfer may be increased after we identified the controller limits.
	 */
	nvme->n_prp_dma_attr.dma_attr_maxxfer = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_minxfer = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_align = nvme->n_pagesize;
	nvme->n_prp_dma_attr.dma_attr_seg = nvme->n_pagesize - 1;

	/*
	 * Reset controller if it's still in ready state.
	 */
	if (nvme_reset(nvme, B_FALSE) == B_FALSE) {
		dev_err(nvme->n_dip, CE_WARN, "!unable to reset controller");
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
		nvme->n_dead = B_TRUE;
		goto fail;
	}

	/*
	 * Create the cq array with one completion queue to be assigned
	 * to the admin queue pair and a limited number of taskqs (4).
	 */
	if (nvme_create_cq_array(nvme, 1, nvme->n_admin_queue_len, 4) !=
	    DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to pre-allocate admin completion queue");
		goto fail;
	}
	/*
	 * Create the admin queue pair.
	 */
	if (nvme_alloc_qpair(nvme, nvme->n_admin_queue_len, &nvme->n_adminq, 0)
	    != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!unable to allocate admin qpair");
		goto fail;
	}
	nvme->n_ioq = kmem_alloc(sizeof (nvme_qpair_t *), KM_SLEEP);
	nvme->n_ioq[0] = nvme->n_adminq;

	if (nvme->n_quirks & NVME_QUIRK_START_CID)
		nvme->n_adminq->nq_next_cmd++;

	nvme->n_progress |= NVME_ADMIN_QUEUE;

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "admin-queue-len", nvme->n_admin_queue_len);

	aqa.b.aqa_asqs = aqa.b.aqa_acqs = nvme->n_admin_queue_len - 1;
	asq = nvme->n_adminq->nq_sqdma->nd_cookie.dmac_laddress;
	acq = nvme->n_adminq->nq_cq->ncq_dma->nd_cookie.dmac_laddress;

	ASSERT((asq & (nvme->n_pagesize - 1)) == 0);
	ASSERT((acq & (nvme->n_pagesize - 1)) == 0);

	nvme_put32(nvme, NVME_REG_AQA, aqa.r);
	nvme_put64(nvme, NVME_REG_ASQ, asq);
	nvme_put64(nvme, NVME_REG_ACQ, acq);

	cc.b.cc_ams = 0;	/* use Round-Robin arbitration */
	cc.b.cc_css = 0;	/* use NVM command set */
	cc.b.cc_mps = nvme->n_pageshift - 12;
	cc.b.cc_shn = 0;	/* no shutdown in progress */
	cc.b.cc_en = 1;		/* enable controller */
	cc.b.cc_iosqes = 6;	/* submission queue entry is 2^6 bytes long */
	cc.b.cc_iocqes = 4;	/* completion queue entry is 2^4 bytes long */

	nvme_put32(nvme, NVME_REG_CC, cc.r);

	/*
	 * Wait for the controller to become ready.
	 */
	csts.r = nvme_get32(nvme, NVME_REG_CSTS);
	if (csts.b.csts_rdy == 0) {
		for (i = 0; i != nvme->n_timeout * 10; i++) {
			delay(drv_usectohz(50000));
			csts.r = nvme_get32(nvme, NVME_REG_CSTS);

			if (csts.b.csts_cfs == 1) {
				dev_err(nvme->n_dip, CE_WARN,
				    "!controller fatal status at init");
				ddi_fm_service_impact(nvme->n_dip,
				    DDI_SERVICE_LOST);
				nvme->n_dead = B_TRUE;
				goto fail;
			}

			if (csts.b.csts_rdy == 1)
				break;
		}
	}

	if (csts.b.csts_rdy == 0) {
		dev_err(nvme->n_dip, CE_WARN, "!controller not ready");
		ddi_fm_service_impact(nvme->n_dip, DDI_SERVICE_LOST);
		nvme->n_dead = B_TRUE;
		goto fail;
	}

	/*
	 * Assume an abort command limit of 1. We'll destroy and re-init
	 * that later when we know the true abort command limit.
	 */
	sema_init(&nvme->n_abort_sema, 1, NULL, SEMA_DRIVER, NULL);

	/*
	 * Set up initial interrupt for admin queue.
	 */
	if ((nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSIX, 1)
	    != DDI_SUCCESS) &&
	    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSI, 1)
	    != DDI_SUCCESS) &&
	    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_FIXED, 1)
	    != DDI_SUCCESS)) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to set up initial interrupt");
		goto fail;
	}

	/*
	 * Initialize the failure status we should use if we mark the controller
	 * dead. Do this ahead of issuing any commands.
	 */
	nvme->n_dead_status = NVME_IOCTL_E_CTRL_DEAD;

	/*
	 * Identify Controller
	 */
	if (!nvme_identify_int(nvme, 0, NVME_IDENTIFY_CTRL,
	    (void **)&nvme->n_idctl)) {
		dev_err(nvme->n_dip, CE_WARN, "!failed to identify controller");
		goto fail;
	}

	/*
	 * Process nvme-config-list (if present) in nvme.conf.
	 */
	nvme_config_list(nvme);

	/*
	 * Get Vendor & Product ID
	 */
	bcopy(nvme->n_idctl->id_model, model, sizeof (nvme->n_idctl->id_model));
	model[sizeof (nvme->n_idctl->id_model)] = '\0';
	sata_split_model(model, &vendor, &product);

	if (vendor == NULL)
		nvme->n_vendor = strdup("NVMe");
	else
		nvme->n_vendor = strdup(vendor);

	nvme->n_product = strdup(product);

	/*
	 * Get controller limits.
	 */
	nvme->n_async_event_limit = MAX(NVME_MIN_ASYNC_EVENT_LIMIT,
	    MIN(nvme->n_admin_queue_len / 10,
	    MIN(nvme->n_idctl->id_aerl + 1, nvme->n_async_event_limit)));

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "async-event-limit", nvme->n_async_event_limit);

	nvme->n_abort_command_limit = nvme->n_idctl->id_acl + 1;

	/*
	 * Reinitialize the semaphore with the true abort command limit
	 * supported by the hardware. It's not necessary to disable interrupts
	 * as only command aborts use the semaphore, and no commands are
	 * executed or aborted while we're here.
	 */
	sema_destroy(&nvme->n_abort_sema);
	sema_init(&nvme->n_abort_sema, nvme->n_abort_command_limit - 1, NULL,
	    SEMA_DRIVER, NULL);

	nvme->n_progress |= NVME_CTRL_LIMITS;

	if (nvme->n_idctl->id_mdts == 0)
		nvme->n_max_data_transfer_size = nvme->n_pagesize * 65536;
	else
		nvme->n_max_data_transfer_size =
		    1ull << (nvme->n_pageshift + nvme->n_idctl->id_mdts);

	nvme->n_error_log_len = nvme->n_idctl->id_elpe + 1;

	/*
	 * Limit n_max_data_transfer_size to what we can handle in one PRP.
	 * Chained PRPs are currently unsupported.
	 *
	 * This is a no-op on hardware which doesn't support a transfer size
	 * big enough to require chained PRPs.
	 */
	nvme->n_max_data_transfer_size = MIN(nvme->n_max_data_transfer_size,
	    (nvme->n_pagesize / sizeof (uint64_t) * nvme->n_pagesize));

	nvme->n_prp_dma_attr.dma_attr_maxxfer = nvme->n_max_data_transfer_size;

	/*
	 * Make sure the minimum/maximum queue entry sizes are not
	 * larger/smaller than the default.
	 */

	if (((1 << nvme->n_idctl->id_sqes.qes_min) > sizeof (nvme_sqe_t)) ||
	    ((1 << nvme->n_idctl->id_sqes.qes_max) < sizeof (nvme_sqe_t)) ||
	    ((1 << nvme->n_idctl->id_cqes.qes_min) > sizeof (nvme_cqe_t)) ||
	    ((1 << nvme->n_idctl->id_cqes.qes_max) < sizeof (nvme_cqe_t)))
		goto fail;

	/*
	 * Check for the presence of a Volatile Write Cache. If present,
	 * enable or disable based on the value of the property
	 * volatile-write-cache-enable (default is enabled).
	 */
	nvme->n_write_cache_present =
	    nvme->n_idctl->id_vwc.vwc_present == 0 ? B_FALSE : B_TRUE;

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "volatile-write-cache-present",
	    nvme->n_write_cache_present ? 1 : 0);

	if (!nvme->n_write_cache_present) {
		nvme->n_write_cache_enabled = B_FALSE;
	} else if (nvme_write_cache_set(nvme, nvme->n_write_cache_enabled)
	    != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to %sable volatile write cache",
		    nvme->n_write_cache_enabled ? "en" : "dis");
		/*
		 * Assume the cache is (still) enabled.
		 */
		nvme->n_write_cache_enabled = B_TRUE;
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip,
	    "volatile-write-cache-enable",
	    nvme->n_write_cache_enabled ? 1 : 0);

	/*
	 * Get number of supported namespaces and allocate namespace array.
	 */
	nvme->n_namespace_count = nvme->n_idctl->id_nn;

	if (nvme->n_namespace_count == 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!controllers without namespaces are not supported");
		goto fail;
	}

	nvme->n_ns = kmem_zalloc(sizeof (nvme_namespace_t) *
	    nvme->n_namespace_count, KM_SLEEP);

	/*
	 * Get the common namespace information if available. If not, we use the
	 * information for nsid 1.
	 */
	if (nvme_ctrl_atleast(nvme, &nvme_vers_1v2) &&
	    nvme->n_idctl->id_oacs.oa_nsmgmt != 0) {
		nsid = NVME_NSID_BCAST;
	} else {
		nsid = 1;
	}

	if (!nvme_identify_int(nvme, nsid, NVME_IDENTIFY_NSID,
	    (void **)&nvme->n_idcomns)) {
		dev_err(nvme->n_dip, CE_WARN, "!failed to identify common "
		    "namespace information");
		goto fail;
	}

	/*
	 * Try to set up MSI/MSI-X interrupts.
	 */
	if ((nvme->n_intr_types & (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX))
	    != 0) {
		nvme_release_interrupts(nvme);

		nqueues = MIN(UINT16_MAX, ncpus);

		if ((nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSIX,
		    nqueues) != DDI_SUCCESS) &&
		    (nvme_setup_interrupts(nvme, DDI_INTR_TYPE_MSI,
		    nqueues) != DDI_SUCCESS)) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to set up MSI/MSI-X interrupts");
			goto fail;
		}
	}

	/*
	 * Create I/O queue pairs.
	 */

	if (nvme_set_nqueues(nvme) != 0) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to set number of I/O queues to %d",
		    nvme->n_intr_cnt);
		goto fail;
	}

	/*
	 * Reallocate I/O queue array
	 */
	kmem_free(nvme->n_ioq, sizeof (nvme_qpair_t *));
	nvme->n_ioq = kmem_zalloc(sizeof (nvme_qpair_t *) *
	    (nvme->n_submission_queues + 1), KM_SLEEP);
	nvme->n_ioq[0] = nvme->n_adminq;

	/*
	 * There should always be at least as many submission queues
	 * as completion queues.
	 */
	ASSERT(nvme->n_submission_queues >= nvme->n_completion_queues);

	nvme->n_ioq_count = nvme->n_submission_queues;

	nvme->n_io_squeue_len =
	    MIN(nvme->n_io_squeue_len, nvme->n_max_queue_entries);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip, "io-squeue-len",
	    nvme->n_io_squeue_len);

	/*
	 * Pre-allocate completion queues.
	 * When there are the same number of submission and completion
	 * queues there is no value in having a larger completion
	 * queue length.
	 */
	if (nvme->n_submission_queues == nvme->n_completion_queues)
		nvme->n_io_cqueue_len = MIN(nvme->n_io_cqueue_len,
		    nvme->n_io_squeue_len);

	nvme->n_io_cqueue_len = MIN(nvme->n_io_cqueue_len,
	    nvme->n_max_queue_entries);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, nvme->n_dip, "io-cqueue-len",
	    nvme->n_io_cqueue_len);

	/*
	 * Assign the equal quantity of taskq threads to each completion
	 * queue, capping the total number of threads to the number
	 * of CPUs.
	 */
	tq_threads = MIN(UINT16_MAX, ncpus) / nvme->n_completion_queues;

	/*
	 * In case the calculation above is zero, we need at least one
	 * thread per completion queue.
	 */
	tq_threads = MAX(1, tq_threads);

	if (nvme_create_cq_array(nvme, nvme->n_completion_queues + 1,
	    nvme->n_io_cqueue_len, tq_threads) != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN,
		    "!failed to pre-allocate completion queues");
		goto fail;
	}

	/*
	 * If we use less completion queues than interrupt vectors return
	 * some of the interrupt vectors back to the system.
	 */
	if (nvme->n_completion_queues + 1 < nvme->n_intr_cnt) {
		nvme_release_interrupts(nvme);

		if (nvme_setup_interrupts(nvme, nvme->n_intr_type,
		    nvme->n_completion_queues + 1) != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!failed to reduce number of interrupts");
			goto fail;
		}
	}

	/*
	 * Alloc & register I/O queue pairs
	 */

	for (i = 1; i != nvme->n_ioq_count + 1; i++) {
		if (nvme_alloc_qpair(nvme, nvme->n_io_squeue_len,
		    &nvme->n_ioq[i], i) != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!unable to allocate I/O qpair %d", i);
			goto fail;
		}

		if (nvme_create_io_qpair(nvme, nvme->n_ioq[i], i) != 0) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!unable to create I/O qpair %d", i);
			goto fail;
		}
	}

	/*
	 * Enable any host behavior features that make sense for us.
	 */
	nvme_enable_host_behavior(nvme);

	return (DDI_SUCCESS);

fail:
	(void) nvme_reset(nvme, B_FALSE);
	return (DDI_FAILURE);
}

static uint_t
nvme_intr(caddr_t arg1, caddr_t arg2)
{
	nvme_t *nvme = (nvme_t *)arg1;
	int inum = (int)(uintptr_t)arg2;
	int ccnt = 0;
	int qnum;

	if (inum >= nvme->n_intr_cnt)
		return (DDI_INTR_UNCLAIMED);

	if (nvme->n_dead) {
		return (nvme->n_intr_type == DDI_INTR_TYPE_FIXED ?
		    DDI_INTR_UNCLAIMED : DDI_INTR_CLAIMED);
	}

	/*
	 * The interrupt vector a queue uses is calculated as queue_idx %
	 * intr_cnt in nvme_create_io_qpair(). Iterate through the queue array
	 * in steps of n_intr_cnt to process all queues using this vector.
	 */
	for (qnum = inum;
	    qnum < nvme->n_cq_count && nvme->n_cq[qnum] != NULL;
	    qnum += nvme->n_intr_cnt) {
		ccnt += nvme_process_iocq(nvme, nvme->n_cq[qnum]);
	}

	return (ccnt > 0 ? DDI_INTR_CLAIMED : DDI_INTR_UNCLAIMED);
}

static void
nvme_release_interrupts(nvme_t *nvme)
{
	int i;

	for (i = 0; i < nvme->n_intr_cnt; i++) {
		if (nvme->n_inth[i] == NULL)
			break;

		if (nvme->n_intr_cap & DDI_INTR_FLAG_BLOCK)
			(void) ddi_intr_block_disable(&nvme->n_inth[i], 1);
		else
			(void) ddi_intr_disable(nvme->n_inth[i]);

		(void) ddi_intr_remove_handler(nvme->n_inth[i]);
		(void) ddi_intr_free(nvme->n_inth[i]);
	}

	kmem_free(nvme->n_inth, nvme->n_inth_sz);
	nvme->n_inth = NULL;
	nvme->n_inth_sz = 0;

	nvme->n_progress &= ~NVME_INTERRUPTS;
}

static int
nvme_setup_interrupts(nvme_t *nvme, int intr_type, int nqpairs)
{
	int nintrs, navail, count;
	int ret;
	int i;

	if (nvme->n_intr_types == 0) {
		ret = ddi_intr_get_supported_types(nvme->n_dip,
		    &nvme->n_intr_types);
		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: ddi_intr_get_supported types failed",
			    __func__);
			return (ret);
		}
#ifdef __x86
		if (get_hwenv() == HW_VMWARE)
			nvme->n_intr_types &= ~DDI_INTR_TYPE_MSIX;
#endif
	}

	if ((nvme->n_intr_types & intr_type) == 0)
		return (DDI_FAILURE);

	ret = ddi_intr_get_nintrs(nvme->n_dip, intr_type, &nintrs);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_nintrs failed",
		    __func__);
		return (ret);
	}

	ret = ddi_intr_get_navail(nvme->n_dip, intr_type, &navail);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_navail failed",
		    __func__);
		return (ret);
	}

	/* We want at most one interrupt per queue pair. */
	if (navail > nqpairs)
		navail = nqpairs;

	nvme->n_inth_sz = sizeof (ddi_intr_handle_t) * navail;
	nvme->n_inth = kmem_zalloc(nvme->n_inth_sz, KM_SLEEP);

	ret = ddi_intr_alloc(nvme->n_dip, nvme->n_inth, intr_type, 0, navail,
	    &count, 0);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_alloc failed",
		    __func__);
		goto fail;
	}

	nvme->n_intr_cnt = count;

	ret = ddi_intr_get_pri(nvme->n_inth[0], &nvme->n_intr_pri);
	if (ret != DDI_SUCCESS) {
		dev_err(nvme->n_dip, CE_WARN, "!%s: ddi_intr_get_pri failed",
		    __func__);
		goto fail;
	}

	for (i = 0; i < count; i++) {
		ret = ddi_intr_add_handler(nvme->n_inth[i], nvme_intr,
		    (void *)nvme, (void *)(uintptr_t)i);
		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: ddi_intr_add_handler failed", __func__);
			goto fail;
		}
	}

	(void) ddi_intr_get_cap(nvme->n_inth[0], &nvme->n_intr_cap);

	for (i = 0; i < count; i++) {
		if (nvme->n_intr_cap & DDI_INTR_FLAG_BLOCK)
			ret = ddi_intr_block_enable(&nvme->n_inth[i], 1);
		else
			ret = ddi_intr_enable(nvme->n_inth[i]);

		if (ret != DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!%s: enabling interrupt %d failed", __func__, i);
			goto fail;
		}
	}

	nvme->n_intr_type = intr_type;

	nvme->n_progress |= NVME_INTERRUPTS;

	return (DDI_SUCCESS);

fail:
	nvme_release_interrupts(nvme);

	return (ret);
}

static int
nvme_fm_errcb(dev_info_t *dip, ddi_fm_error_t *fm_error, const void *arg)
{
	_NOTE(ARGUNUSED(arg));

	pci_ereport_post(dip, fm_error, NULL);
	return (fm_error->fme_status);
}

static void
nvme_remove_callback(dev_info_t *dip, ddi_eventcookie_t cookie, void *a,
    void *b)
{
	nvme_t *nvme = a;

	nvme_ctrl_mark_dead(nvme, B_TRUE);

	/*
	 * Fail all outstanding commands, including those in the admin queue
	 * (queue 0).
	 */
	for (uint_t i = 0; i < nvme->n_ioq_count + 1; i++) {
		nvme_qpair_t *qp = nvme->n_ioq[i];

		mutex_enter(&qp->nq_mutex);
		for (size_t j = 0; j < qp->nq_nentry; j++) {
			nvme_cmd_t *cmd = qp->nq_cmd[j];
			nvme_cmd_t *u_cmd;

			if (cmd == NULL) {
				continue;
			}

			/*
			 * Since we have the queue lock held the entire time we
			 * iterate over it, it's not possible for the queue to
			 * change underneath us. Thus, we don't need to check
			 * that the return value of nvme_unqueue_cmd matches the
			 * requested cmd to unqueue.
			 */
			u_cmd = nvme_unqueue_cmd(nvme, qp, cmd->nc_sqe.sqe_cid);
			taskq_dispatch_ent(qp->nq_cq->ncq_cmd_taskq,
			    cmd->nc_callback, cmd, TQ_NOSLEEP, &cmd->nc_tqent);

			ASSERT3P(u_cmd, ==, cmd);
		}
		mutex_exit(&qp->nq_mutex);
	}
}

/*
 * Open minor management
 */
static int
nvme_minor_comparator(const void *l, const void *r)
{
	const nvme_minor_t *lm = l;
	const nvme_minor_t *rm = r;

	if (lm->nm_minor > rm->nm_minor) {
		return (1);
	} else if (lm->nm_minor < rm->nm_minor) {
		return (-1);
	} else {
		return (0);
	}
}

static void
nvme_minor_free(nvme_minor_t *minor)
{
	if (minor->nm_minor > 0) {
		ASSERT3S(minor->nm_minor, >=, NVME_OPEN_MINOR_MIN);
		id_free(nvme_open_minors, minor->nm_minor);
		minor->nm_minor = 0;
	}
	VERIFY0(list_link_active(&minor->nm_ctrl_lock.nli_node));
	VERIFY0(list_link_active(&minor->nm_ns_lock.nli_node));
	cv_destroy(&minor->nm_cv);
	kmem_free(minor, sizeof (nvme_minor_t));
}

static nvme_minor_t *
nvme_minor_find_by_dev(dev_t dev)
{
	id_t id = (id_t)getminor(dev);
	nvme_minor_t search = { .nm_minor = id };
	nvme_minor_t *ret;

	mutex_enter(&nvme_open_minors_mutex);
	ret = avl_find(&nvme_open_minors_avl, &search, NULL);
	mutex_exit(&nvme_open_minors_mutex);

	return (ret);
}

static int
nvme_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	nvme_t *nvme;
	int instance;
	int nregs;
	off_t regsize;
	char name[32];

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	if (ddi_soft_state_zalloc(nvme_state, instance) != DDI_SUCCESS)
		return (DDI_FAILURE);

	nvme = ddi_get_soft_state(nvme_state, instance);
	ddi_set_driver_private(dip, nvme);
	nvme->n_dip = dip;

	/*
	 * Map PCI config space
	 */
	if (pci_config_setup(dip, &nvme->n_pcicfg_handle) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to map PCI config space");
		goto fail;
	}
	nvme->n_progress |= NVME_PCI_CONFIG;

	/*
	 * Get the various PCI IDs from config space
	 */
	nvme->n_vendor_id =
	    pci_config_get16(nvme->n_pcicfg_handle, PCI_CONF_VENID);
	nvme->n_device_id =
	    pci_config_get16(nvme->n_pcicfg_handle, PCI_CONF_DEVID);
	nvme->n_revision_id =
	    pci_config_get8(nvme->n_pcicfg_handle, PCI_CONF_REVID);
	nvme->n_subsystem_device_id =
	    pci_config_get16(nvme->n_pcicfg_handle, PCI_CONF_SUBSYSID);
	nvme->n_subsystem_vendor_id =
	    pci_config_get16(nvme->n_pcicfg_handle, PCI_CONF_SUBVENID);

	nvme_detect_quirks(nvme);

	/*
	 * Set up event handlers for hot removal. While npe(4D) supports the hot
	 * removal event being injected for devices, the same is not true of all
	 * of our possible parents (i.e. pci(4D) as of this writing). The most
	 * common case this shows up is in some virtualization environments. We
	 * should treat this as non-fatal so that way devices work but leave
	 * this set up in such a way that if a nexus does grow support for this
	 * we're good to go.
	 */
	if (ddi_get_eventcookie(nvme->n_dip, DDI_DEVI_REMOVE_EVENT,
	    &nvme->n_rm_cookie) == DDI_SUCCESS) {
		if (ddi_add_event_handler(nvme->n_dip, nvme->n_rm_cookie,
		    nvme_remove_callback, nvme, &nvme->n_ev_rm_cb_id) !=
		    DDI_SUCCESS) {
			goto fail;
		}
	} else {
		nvme->n_ev_rm_cb_id = NULL;
	}

	mutex_init(&nvme->n_minor_mutex, NULL, MUTEX_DRIVER, NULL);
	nvme->n_progress |= NVME_MUTEX_INIT;

	nvme->n_strict_version = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "strict-version", 1) == 1 ? B_TRUE : B_FALSE;
	nvme->n_ignore_unknown_vendor_status = ddi_prop_get_int(DDI_DEV_T_ANY,
	    dip, DDI_PROP_DONTPASS, "ignore-unknown-vendor-status", 0) == 1 ?
	    B_TRUE : B_FALSE;
	nvme->n_admin_queue_len = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "admin-queue-len", NVME_DEFAULT_ADMIN_QUEUE_LEN);
	nvme->n_io_squeue_len = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "io-squeue-len", NVME_DEFAULT_IO_QUEUE_LEN);
	/*
	 * Double up the default for completion queues in case of
	 * queue sharing.
	 */
	nvme->n_io_cqueue_len = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "io-cqueue-len", 2 * NVME_DEFAULT_IO_QUEUE_LEN);
	nvme->n_async_event_limit = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "async-event-limit",
	    NVME_DEFAULT_ASYNC_EVENT_LIMIT);
	nvme->n_write_cache_enabled = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "volatile-write-cache-enable", 1) != 0 ?
	    B_TRUE : B_FALSE;
	nvme->n_min_block_size = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "min-phys-block-size",
	    NVME_DEFAULT_MIN_BLOCK_SIZE);
	nvme->n_submission_queues = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "max-submission-queues", -1);
	nvme->n_completion_queues = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "max-completion-queues", -1);

	if (!ISP2(nvme->n_min_block_size) ||
	    (nvme->n_min_block_size < NVME_DEFAULT_MIN_BLOCK_SIZE)) {
		dev_err(dip, CE_WARN, "!min-phys-block-size %s, "
		    "using default %d", ISP2(nvme->n_min_block_size) ?
		    "too low" : "not a power of 2",
		    NVME_DEFAULT_MIN_BLOCK_SIZE);
		nvme->n_min_block_size = NVME_DEFAULT_MIN_BLOCK_SIZE;
	}

	if (nvme->n_submission_queues != -1 &&
	    (nvme->n_submission_queues < 1 ||
	    nvme->n_submission_queues > UINT16_MAX)) {
		dev_err(dip, CE_WARN, "!\"submission-queues\"=%d is not "
		    "valid. Must be [1..%d]", nvme->n_submission_queues,
		    UINT16_MAX);
		nvme->n_submission_queues = -1;
	}

	if (nvme->n_completion_queues != -1 &&
	    (nvme->n_completion_queues < 1 ||
	    nvme->n_completion_queues > UINT16_MAX)) {
		dev_err(dip, CE_WARN, "!\"completion-queues\"=%d is not "
		    "valid. Must be [1..%d]", nvme->n_completion_queues,
		    UINT16_MAX);
		nvme->n_completion_queues = -1;
	}

	if (nvme->n_admin_queue_len < NVME_MIN_ADMIN_QUEUE_LEN)
		nvme->n_admin_queue_len = NVME_MIN_ADMIN_QUEUE_LEN;
	else if (nvme->n_admin_queue_len > NVME_MAX_ADMIN_QUEUE_LEN)
		nvme->n_admin_queue_len = NVME_MAX_ADMIN_QUEUE_LEN;

	if (nvme->n_io_squeue_len < NVME_MIN_IO_QUEUE_LEN)
		nvme->n_io_squeue_len = NVME_MIN_IO_QUEUE_LEN;
	if (nvme->n_io_cqueue_len < NVME_MIN_IO_QUEUE_LEN)
		nvme->n_io_cqueue_len = NVME_MIN_IO_QUEUE_LEN;

	if (nvme->n_async_event_limit < 1)
		nvme->n_async_event_limit = NVME_DEFAULT_ASYNC_EVENT_LIMIT;

	nvme->n_reg_acc_attr = nvme_reg_acc_attr;
	nvme->n_queue_dma_attr = nvme_queue_dma_attr;
	nvme->n_prp_dma_attr = nvme_prp_dma_attr;
	nvme->n_sgl_dma_attr = nvme_sgl_dma_attr;

	/*
	 * Set up FMA support.
	 */
	nvme->n_fm_cap = ddi_getprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS, "fm-capable",
	    DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE);

	ddi_fm_init(dip, &nvme->n_fm_cap, &nvme->n_fm_ibc);

	if (nvme->n_fm_cap) {
		if (nvme->n_fm_cap & DDI_FM_ACCCHK_CAPABLE)
			nvme->n_reg_acc_attr.devacc_attr_access =
			    DDI_FLAGERR_ACC;

		if (nvme->n_fm_cap & DDI_FM_DMACHK_CAPABLE) {
			nvme->n_prp_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
			nvme->n_sgl_dma_attr.dma_attr_flags |= DDI_DMA_FLAGERR;
		}

		if (DDI_FM_EREPORT_CAP(nvme->n_fm_cap) ||
		    DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			pci_ereport_setup(dip);

		if (DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			ddi_fm_handler_register(dip, nvme_fm_errcb,
			    (void *)nvme);
	}

	nvme->n_progress |= NVME_FMA_INIT;

	/*
	 * The spec defines several register sets. Only the controller
	 * registers (set 1) are currently used.
	 */
	if (ddi_dev_nregs(dip, &nregs) == DDI_FAILURE ||
	    nregs < 2 ||
	    ddi_dev_regsize(dip, 1, &regsize) == DDI_FAILURE)
		goto fail;

	if (ddi_regs_map_setup(dip, 1, &nvme->n_regs, 0, regsize,
	    &nvme->n_reg_acc_attr, &nvme->n_regh) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to map regset 1");
		goto fail;
	}

	nvme->n_progress |= NVME_REGS_MAPPED;

	/*
	 * Set up kstats
	 */
	if (!nvme_stat_init(nvme)) {
		dev_err(dip, CE_WARN, "!failed to create device kstats");
		goto fail;
	}
	nvme->n_progress |= NVME_STAT_INIT;

	/*
	 * Create PRP DMA cache
	 */
	(void) snprintf(name, sizeof (name), "%s%d_prp_cache",
	    ddi_driver_name(dip), ddi_get_instance(dip));
	nvme->n_prp_cache = kmem_cache_create(name, sizeof (nvme_dma_t),
	    0, nvme_prp_dma_constructor, nvme_prp_dma_destructor,
	    NULL, (void *)nvme, NULL, 0);

	if (nvme_init(nvme) != DDI_SUCCESS)
		goto fail;

	/*
	 * Initialize the driver with the UFM subsystem
	 */
	if (ddi_ufm_init(dip, DDI_UFM_CURRENT_VERSION, &nvme_ufm_ops,
	    &nvme->n_ufmh, nvme) != 0) {
		dev_err(dip, CE_WARN, "!failed to initialize UFM subsystem");
		goto fail;
	}
	mutex_init(&nvme->n_fwslot_mutex, NULL, MUTEX_DRIVER, NULL);
	ddi_ufm_update(nvme->n_ufmh);
	nvme->n_progress |= NVME_UFM_INIT;

	nvme_mgmt_lock_init(&nvme->n_mgmt);
	nvme_lock_init(&nvme->n_lock);
	nvme->n_progress |= NVME_MGMT_INIT;

	/*
	 * Identify namespaces.
	 */
	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);

	boolean_t minor_logged = B_FALSE;
	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);

		nvme_lock_init(&ns->ns_lock);
		ns->ns_progress |= NVME_NS_LOCK;

		/*
		 * Namespaces start out in the active state. This is the
		 * default state until we find out information about the
		 * namespaces in more detail. nvme_init_ns() will go through and
		 * determine what the proper state should be. It will also use
		 * this state change to keep an accurate count of attachable
		 * namespaces.
		 */
		ns->ns_state = NVME_NS_STATE_ACTIVE;
		if (nvme_init_ns(nvme, i) != 0) {
			nvme_mgmt_unlock(nvme);
			goto fail;
		}

		/*
		 * We only create compat minor nodes for the namespace for the
		 * first NVME_MINOR_MAX namespaces. Those that are beyond this
		 * can only be accessed through the primary controller node,
		 * which is generally fine as that's what libnvme uses and is
		 * our preferred path. Not having a minor is better than not
		 * having the namespace!
		 */
		if (i > NVME_MINOR_MAX) {
			if (!minor_logged) {
				dev_err(dip, CE_WARN, "namespace minor "
				    "creation limited to the first %u "
				    "namespaces, device has %u",
				    NVME_MINOR_MAX, nvme->n_namespace_count);
				minor_logged = B_TRUE;
			}
			continue;
		}

		if (ddi_create_minor_node(nvme->n_dip, ns->ns_name, S_IFCHR,
		    NVME_MINOR(ddi_get_instance(nvme->n_dip), i),
		    DDI_NT_NVME_ATTACHMENT_POINT, 0) != DDI_SUCCESS) {
			nvme_mgmt_unlock(nvme);
			dev_err(dip, CE_WARN,
			    "!failed to create minor node for namespace %d", i);
			goto fail;
		}
		ns->ns_progress |= NVME_NS_MINOR;
	}

	/*
	 * Indicate that namespace initialization is complete and therefore
	 * marking the controller dead can evaluate every namespace lock.
	 */
	nvme->n_progress |= NVME_NS_INIT;

	if (ddi_create_minor_node(dip, "devctl", S_IFCHR,
	    NVME_MINOR(ddi_get_instance(dip), 0), DDI_NT_NVME_NEXUS, 0) !=
	    DDI_SUCCESS) {
		nvme_mgmt_unlock(nvme);
		dev_err(dip, CE_WARN, "nvme_attach: "
		    "cannot create devctl minor node");
		goto fail;
	}

	/*
	 * Attempt to attach all namespaces that are in a reasonable state. This
	 * should not fail attach.
	 */
	for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);
		nvme_ioctl_common_t com = { .nioc_nsid = i };

		if (ns->ns_state < NVME_NS_STATE_NOT_IGNORED)
			continue;

		if (!nvme_bd_attach_ns(nvme, &com) && com.nioc_drv_err !=
		    NVME_IOCTL_E_UNSUP_ATTACH_NS) {
			dev_err(nvme->n_dip, CE_WARN, "!failed to attach "
			    "namespace %d due to blkdev error (0x%x)", i,
			    com.nioc_drv_err);
		}
	}

	nvme_mgmt_unlock(nvme);

	/*
	 * As the last thing that we do, we finally go ahead and enable
	 * asynchronous event notifications. Currently we rely upon whatever
	 * defaults the device has for the events that we will receive. If we
	 * enable this earlier, it's possible that we'll get events that we
	 * cannot handle yet because all of our data structures are not valid.
	 * The device will queue all asynchronous events on a per-log page basis
	 * until we submit this. If the device is totally broken, it will have
	 * likely failed our commands already. If we add support for configuring
	 * which asynchronous events we would like to receive via the SET
	 * FEATURES command, then we should do that as one of the first commands
	 * we send in nvme_init().
	 *
	 * We start by assuming asynchronous events are supported. However, not
	 * all devices (e.g. some versions of QEMU) support this, so we end up
	 * tracking whether or not we think these actually work.
	 */
	nvme->n_async_event_supported = B_TRUE;
	for (uint16_t i = 0; i < nvme->n_async_event_limit; i++) {
		nvme_async_event(nvme);
	}


	return (DDI_SUCCESS);

fail:
	/* attach successful anyway so that FMA can retire the device */
	if (nvme->n_dead)
		return (DDI_SUCCESS);

	(void) nvme_detach(dip, DDI_DETACH);

	return (DDI_FAILURE);
}

static int
nvme_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	int instance;
	nvme_t *nvme;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	instance = ddi_get_instance(dip);

	nvme = ddi_get_soft_state(nvme_state, instance);

	if (nvme == NULL)
		return (DDI_FAILURE);

	/*
	 * Remove all minor nodes from the device regardless of the source in
	 * one swoop.
	 */
	ddi_remove_minor_node(dip, NULL);

	/*
	 * We need to remove the event handler as one of the first things that
	 * we do. If we proceed with other teardown without removing the event
	 * handler, we could end up in a very unfortunate race with ourselves.
	 * The DDI does not serialize these with detach (just like timeout(9F)
	 * and others).
	 */
	if (nvme->n_ev_rm_cb_id != NULL) {
		(void) ddi_remove_event_handler(nvme->n_ev_rm_cb_id);
	}
	nvme->n_ev_rm_cb_id = NULL;

	/*
	 * If the controller was marked dead, there is a slight chance that we
	 * are asynchronusly processing the removal taskq. Because we have
	 * removed the callback handler above and all minor nodes and commands
	 * are closed, there is no other way to get in here. As such, we wait on
	 * the nvme_dead_taskq to complete so we can avoid tracking if it's
	 * running or not.
	 */
	taskq_wait(nvme_dead_taskq);

	if (nvme->n_ns) {
		for (uint32_t i = 1; i <= nvme->n_namespace_count; i++) {
			nvme_namespace_t *ns = nvme_nsid2ns(nvme, i);

			if (ns->ns_bd_hdl) {
				(void) bd_detach_handle(ns->ns_bd_hdl);
				bd_free_handle(ns->ns_bd_hdl);
			}

			if (ns->ns_idns)
				kmem_free(ns->ns_idns,
				    sizeof (nvme_identify_nsid_t));
			if (ns->ns_devid)
				strfree(ns->ns_devid);

			if ((ns->ns_progress & NVME_NS_LOCK) != 0)
				nvme_lock_fini(&ns->ns_lock);
		}

		kmem_free(nvme->n_ns, sizeof (nvme_namespace_t) *
		    nvme->n_namespace_count);
	}

	if (nvme->n_progress & NVME_MGMT_INIT) {
		nvme_lock_fini(&nvme->n_lock);
		nvme_mgmt_lock_fini(&nvme->n_mgmt);
	}

	if (nvme->n_progress & NVME_UFM_INIT) {
		ddi_ufm_fini(nvme->n_ufmh);
		mutex_destroy(&nvme->n_fwslot_mutex);
	}

	if (nvme->n_progress & NVME_INTERRUPTS)
		nvme_release_interrupts(nvme);

	for (uint_t i = 0; i < nvme->n_cq_count; i++) {
		if (nvme->n_cq[i]->ncq_cmd_taskq != NULL)
			taskq_wait(nvme->n_cq[i]->ncq_cmd_taskq);
	}

	if (nvme->n_progress & NVME_MUTEX_INIT) {
		mutex_destroy(&nvme->n_minor_mutex);
	}

	if (nvme->n_ioq_count > 0) {
		for (uint_t i = 1; i != nvme->n_ioq_count + 1; i++) {
			if (nvme->n_ioq[i] != NULL) {
				/* TODO: send destroy queue commands */
				nvme_free_qpair(nvme->n_ioq[i]);
			}
		}

		kmem_free(nvme->n_ioq, sizeof (nvme_qpair_t *) *
		    (nvme->n_ioq_count + 1));
	}

	if (nvme->n_prp_cache != NULL) {
		kmem_cache_destroy(nvme->n_prp_cache);
	}

	if (nvme->n_progress & NVME_REGS_MAPPED) {
		nvme_shutdown(nvme, B_FALSE);
		(void) nvme_reset(nvme, B_FALSE);
	}

	if (nvme->n_progress & NVME_CTRL_LIMITS)
		sema_destroy(&nvme->n_abort_sema);

	if (nvme->n_progress & NVME_ADMIN_QUEUE)
		nvme_free_qpair(nvme->n_adminq);

	if (nvme->n_cq_count > 0) {
		nvme_destroy_cq_array(nvme, 0);
		nvme->n_cq = NULL;
		nvme->n_cq_count = 0;
	}

	if (nvme->n_idcomns)
		kmem_free(nvme->n_idcomns, NVME_IDENTIFY_BUFSIZE);

	if (nvme->n_idctl)
		kmem_free(nvme->n_idctl, NVME_IDENTIFY_BUFSIZE);

	if (nvme->n_progress & NVME_REGS_MAPPED)
		ddi_regs_map_free(&nvme->n_regh);

	if (nvme->n_progress & NVME_STAT_INIT)
		nvme_stat_cleanup(nvme);

	if (nvme->n_progress & NVME_FMA_INIT) {
		if (DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			ddi_fm_handler_unregister(nvme->n_dip);

		if (DDI_FM_EREPORT_CAP(nvme->n_fm_cap) ||
		    DDI_FM_ERRCB_CAP(nvme->n_fm_cap))
			pci_ereport_teardown(nvme->n_dip);

		ddi_fm_fini(nvme->n_dip);
	}

	if (nvme->n_progress & NVME_PCI_CONFIG)
		pci_config_teardown(&nvme->n_pcicfg_handle);

	if (nvme->n_vendor != NULL)
		strfree(nvme->n_vendor);

	if (nvme->n_product != NULL)
		strfree(nvme->n_product);

	ddi_soft_state_free(nvme_state, instance);

	return (DDI_SUCCESS);
}

static int
nvme_quiesce(dev_info_t *dip)
{
	int instance;
	nvme_t *nvme;

	instance = ddi_get_instance(dip);

	nvme = ddi_get_soft_state(nvme_state, instance);

	if (nvme == NULL)
		return (DDI_FAILURE);

	nvme_shutdown(nvme, B_TRUE);

	(void) nvme_reset(nvme, B_TRUE);

	return (DDI_SUCCESS);
}

static int
nvme_fill_prp(nvme_cmd_t *cmd, ddi_dma_handle_t dma)
{
	nvme_t *nvme = cmd->nc_nvme;
	uint_t nprp_per_page, nprp;
	uint64_t *prp;
	const ddi_dma_cookie_t *cookie;
	uint_t idx;
	uint_t ncookies = ddi_dma_ncookies(dma);

	if (ncookies == 0)
		return (DDI_FAILURE);

	if ((cookie = ddi_dma_cookie_get(dma, 0)) == NULL)
		return (DDI_FAILURE);
	cmd->nc_sqe.sqe_dptr.d_prp[0] = cookie->dmac_laddress;

	if (ncookies == 1) {
		cmd->nc_sqe.sqe_dptr.d_prp[1] = 0;
		return (DDI_SUCCESS);
	} else if (ncookies == 2) {
		if ((cookie = ddi_dma_cookie_get(dma, 1)) == NULL)
			return (DDI_FAILURE);
		cmd->nc_sqe.sqe_dptr.d_prp[1] = cookie->dmac_laddress;
		return (DDI_SUCCESS);
	}

	/*
	 * At this point, we're always operating on cookies at
	 * index >= 1 and writing the addresses of those cookies
	 * into a new page. The address of that page is stored
	 * as the second PRP entry.
	 */
	nprp_per_page = nvme->n_pagesize / sizeof (uint64_t);
	ASSERT(nprp_per_page > 0);

	/*
	 * We currently don't support chained PRPs and set up our DMA
	 * attributes to reflect that. If we still get an I/O request
	 * that needs a chained PRP something is very wrong. Account
	 * for the first cookie here, which we've placed in d_prp[0].
	 */
	nprp = howmany(ncookies - 1, nprp_per_page);
	VERIFY(nprp == 1);

	/*
	 * Allocate a page of pointers, in which we'll write the
	 * addresses of cookies 1 to `ncookies`.
	 */
	cmd->nc_prp = kmem_cache_alloc(nvme->n_prp_cache, KM_SLEEP);
	bzero(cmd->nc_prp->nd_memp, cmd->nc_prp->nd_len);
	cmd->nc_sqe.sqe_dptr.d_prp[1] = cmd->nc_prp->nd_cookie.dmac_laddress;

	prp = (uint64_t *)cmd->nc_prp->nd_memp;
	for (idx = 1; idx < ncookies; idx++) {
		if ((cookie = ddi_dma_cookie_get(dma, idx)) == NULL)
			return (DDI_FAILURE);
		*prp++ = cookie->dmac_laddress;
	}

	(void) ddi_dma_sync(cmd->nc_prp->nd_dmah, 0, cmd->nc_prp->nd_len,
	    DDI_DMA_SYNC_FORDEV);
	return (DDI_SUCCESS);
}

/*
 * The maximum number of requests supported for a deallocate request is
 * NVME_DSET_MGMT_MAX_RANGES (256) -- this is from the NVMe 1.1 spec (and
 * unchanged through at least 1.4a). The definition of nvme_range_t is also
 * from the NVMe 1.1 spec. Together, the result is that all of the ranges for
 * a deallocate request will fit into the smallest supported namespace page
 * (4k).
 */
CTASSERT(sizeof (nvme_range_t) * NVME_DSET_MGMT_MAX_RANGES == 4096);

static int
nvme_fill_ranges(nvme_cmd_t *cmd, bd_xfer_t *xfer, uint64_t blocksize,
    int allocflag)
{
	const dkioc_free_list_t *dfl = xfer->x_dfl;
	const dkioc_free_list_ext_t *exts = dfl->dfl_exts;
	nvme_t *nvme = cmd->nc_nvme;
	nvme_range_t *ranges = NULL;
	uint_t i;

	/*
	 * The number of ranges in the request is 0s based (that is
	 * word10 == 0 -> 1 range, word10 == 1 -> 2 ranges, ...,
	 * word10 == 255 -> 256 ranges). Therefore the allowed values are
	 * [1..NVME_DSET_MGMT_MAX_RANGES]. If blkdev gives us a bad request,
	 * we either provided bad info in nvme_bd_driveinfo() or there is a bug
	 * in blkdev.
	 */
	VERIFY3U(dfl->dfl_num_exts, >, 0);
	VERIFY3U(dfl->dfl_num_exts, <=, NVME_DSET_MGMT_MAX_RANGES);
	cmd->nc_sqe.sqe_cdw10 = (dfl->dfl_num_exts - 1) & 0xff;

	cmd->nc_sqe.sqe_cdw11 = NVME_DSET_MGMT_ATTR_DEALLOCATE;

	cmd->nc_prp = kmem_cache_alloc(nvme->n_prp_cache, allocflag);
	if (cmd->nc_prp == NULL)
		return (DDI_FAILURE);

	bzero(cmd->nc_prp->nd_memp, cmd->nc_prp->nd_len);
	ranges = (nvme_range_t *)cmd->nc_prp->nd_memp;

	cmd->nc_sqe.sqe_dptr.d_prp[0] = cmd->nc_prp->nd_cookie.dmac_laddress;
	cmd->nc_sqe.sqe_dptr.d_prp[1] = 0;

	for (i = 0; i < dfl->dfl_num_exts; i++) {
		uint64_t lba, len;

		lba = (dfl->dfl_offset + exts[i].dfle_start) / blocksize;
		len = exts[i].dfle_length / blocksize;

		VERIFY3U(len, <=, UINT32_MAX);

		/* No context attributes for a deallocate request */
		ranges[i].nr_ctxattr = 0;
		ranges[i].nr_len = len;
		ranges[i].nr_lba = lba;
	}

	(void) ddi_dma_sync(cmd->nc_prp->nd_dmah, 0, cmd->nc_prp->nd_len,
	    DDI_DMA_SYNC_FORDEV);

	return (DDI_SUCCESS);
}

static nvme_cmd_t *
nvme_create_nvm_cmd(nvme_namespace_t *ns, uint8_t opc, bd_xfer_t *xfer)
{
	nvme_t *nvme = ns->ns_nvme;
	nvme_cmd_t *cmd;
	int allocflag;

	/*
	 * Blkdev only sets BD_XFER_POLL when dumping, so don't sleep.
	 */
	allocflag = (xfer->x_flags & BD_XFER_POLL) ? KM_NOSLEEP : KM_SLEEP;
	cmd = nvme_alloc_cmd(nvme, allocflag);

	if (cmd == NULL)
		return (NULL);

	cmd->nc_sqe.sqe_opc = opc;
	cmd->nc_callback = nvme_bd_xfer_done;
	cmd->nc_xfer = xfer;

	switch (opc) {
	case NVME_OPC_NVM_WRITE:
	case NVME_OPC_NVM_READ:
		VERIFY(xfer->x_nblks <= 0x10000);

		cmd->nc_sqe.sqe_nsid = ns->ns_id;

		cmd->nc_sqe.sqe_cdw10 = xfer->x_blkno & 0xffffffffu;
		cmd->nc_sqe.sqe_cdw11 = (xfer->x_blkno >> 32);
		cmd->nc_sqe.sqe_cdw12 = (uint16_t)(xfer->x_nblks - 1);

		if (nvme_fill_prp(cmd, xfer->x_dmah) != DDI_SUCCESS)
			goto fail;
		break;

	case NVME_OPC_NVM_FLUSH:
		cmd->nc_sqe.sqe_nsid = ns->ns_id;
		break;

	case NVME_OPC_NVM_DSET_MGMT:
		cmd->nc_sqe.sqe_nsid = ns->ns_id;

		if (nvme_fill_ranges(cmd, xfer,
		    (uint64_t)ns->ns_block_size, allocflag) != DDI_SUCCESS)
			goto fail;
		break;

	default:
		goto fail;
	}

	return (cmd);

fail:
	nvme_free_cmd(cmd);
	return (NULL);
}

static void
nvme_bd_xfer_done(void *arg)
{
	nvme_cmd_t *cmd = arg;
	bd_xfer_t *xfer = cmd->nc_xfer;
	int error = 0;

	error = nvme_check_cmd_status(cmd);
	nvme_free_cmd(cmd);

	bd_xfer_done(xfer, error);
}

static void
nvme_bd_driveinfo(void *arg, bd_drive_t *drive)
{
	nvme_namespace_t *ns = arg;
	nvme_t *nvme = ns->ns_nvme;
	uint_t ns_count = MAX(1, nvme->n_namespaces_attachable);

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_BDRO);

	/*
	 * Set the blkdev qcount to the number of submission queues.
	 * It will then create one waitq/runq pair for each submission
	 * queue and spread I/O requests across the queues.
	 */
	drive->d_qcount = nvme->n_ioq_count;

	/*
	 * I/O activity to individual namespaces is distributed across
	 * each of the d_qcount blkdev queues (which has been set to
	 * the number of nvme submission queues). d_qsize is the number
	 * of submitted and not completed I/Os within each queue that blkdev
	 * will allow before it starts holding them in the waitq.
	 *
	 * Each namespace will create a child blkdev instance, for each one
	 * we try and set the d_qsize so that each namespace gets an
	 * equal portion of the submission queue.
	 *
	 * If post instantiation of the nvme drive, n_namespaces_attachable
	 * changes and a namespace is attached it could calculate a
	 * different d_qsize. It may even be that the sum of the d_qsizes is
	 * now beyond the submission queue size. Should that be the case
	 * and the I/O rate is such that blkdev attempts to submit more
	 * I/Os than the size of the submission queue, the excess I/Os
	 * will be held behind the semaphore nq_sema.
	 */
	drive->d_qsize = nvme->n_io_squeue_len / ns_count;

	/*
	 * Don't let the queue size drop below the minimum, though.
	 */
	drive->d_qsize = MAX(drive->d_qsize, NVME_MIN_IO_QUEUE_LEN);

	/*
	 * d_maxxfer is not set, which means the value is taken from the DMA
	 * attributes specified to bd_alloc_handle.
	 */

	drive->d_removable = B_FALSE;
	drive->d_hotpluggable = B_FALSE;

	bcopy(ns->ns_eui64, drive->d_eui64, sizeof (drive->d_eui64));
	drive->d_target = ns->ns_id;
	drive->d_lun = 0;

	drive->d_model = nvme->n_idctl->id_model;
	drive->d_model_len = sizeof (nvme->n_idctl->id_model);
	drive->d_vendor = nvme->n_vendor;
	drive->d_vendor_len = strlen(nvme->n_vendor);
	drive->d_product = nvme->n_product;
	drive->d_product_len = strlen(nvme->n_product);
	drive->d_serial = nvme->n_idctl->id_serial;
	drive->d_serial_len = sizeof (nvme->n_idctl->id_serial);
	drive->d_revision = nvme->n_idctl->id_fwrev;
	drive->d_revision_len = sizeof (nvme->n_idctl->id_fwrev);

	/*
	 * If we support the dataset management command, the only restrictions
	 * on a discard request are the maximum number of ranges (segments)
	 * per single request.
	 */
	if (nvme->n_idctl->id_oncs.on_dset_mgmt)
		drive->d_max_free_seg = NVME_DSET_MGMT_MAX_RANGES;

	nvme_mgmt_unlock(nvme);
}

static int
nvme_bd_mediainfo(void *arg, bd_media_t *media)
{
	nvme_namespace_t *ns = arg;
	nvme_t *nvme = ns->ns_nvme;

	if (nvme->n_dead) {
		return (EIO);
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_BDRO);

	media->m_nblks = ns->ns_block_count;
	media->m_blksize = ns->ns_block_size;
	media->m_readonly = B_FALSE;
	media->m_solidstate = B_TRUE;

	media->m_pblksize = ns->ns_best_block_size;

	nvme_mgmt_unlock(nvme);

	return (0);
}

static int
nvme_bd_cmd(nvme_namespace_t *ns, bd_xfer_t *xfer, uint8_t opc)
{
	nvme_t *nvme = ns->ns_nvme;
	nvme_cmd_t *cmd;
	nvme_qpair_t *ioq;
	boolean_t poll;
	int ret;

	if (nvme->n_dead) {
		return (EIO);
	}

	cmd = nvme_create_nvm_cmd(ns, opc, xfer);
	if (cmd == NULL)
		return (ENOMEM);

	cmd->nc_sqid = xfer->x_qnum + 1;
	ASSERT(cmd->nc_sqid <= nvme->n_ioq_count);
	ioq = nvme->n_ioq[cmd->nc_sqid];

	/*
	 * Get the polling flag before submitting the command. The command may
	 * complete immediately after it was submitted, which means we must
	 * treat both cmd and xfer as if they have been freed already.
	 */
	poll = (xfer->x_flags & BD_XFER_POLL) != 0;

	ret = nvme_submit_io_cmd(ioq, cmd);

	if (ret != 0)
		return (ret);

	if (!poll)
		return (0);

	do {
		cmd = nvme_retrieve_cmd(nvme, ioq);
		if (cmd != NULL) {
			ASSERT0(cmd->nc_flags & NVME_CMD_F_USELOCK);
			cmd->nc_callback(cmd);
		} else {
			drv_usecwait(10);
		}
	} while (ioq->nq_active_cmds != 0);

	return (0);
}

static int
nvme_bd_read(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_READ));
}

static int
nvme_bd_write(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_WRITE));
}

static int
nvme_bd_sync(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	if (ns->ns_nvme->n_dead)
		return (EIO);

	/*
	 * If the volatile write cache is not present or not enabled the FLUSH
	 * command is a no-op, so we can take a shortcut here.
	 */
	if (!ns->ns_nvme->n_write_cache_present) {
		bd_xfer_done(xfer, ENOTSUP);
		return (0);
	}

	if (!ns->ns_nvme->n_write_cache_enabled) {
		bd_xfer_done(xfer, 0);
		return (0);
	}

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_FLUSH));
}

static int
nvme_bd_devid(void *arg, dev_info_t *devinfo, ddi_devid_t *devid)
{
	nvme_namespace_t *ns = arg;
	nvme_t *nvme = ns->ns_nvme;

	if (nvme->n_dead) {
		return (EIO);
	}

	if (*(uint64_t *)ns->ns_nguid != 0 ||
	    *(uint64_t *)(ns->ns_nguid + 8) != 0) {
		return (ddi_devid_init(devinfo, DEVID_NVME_NGUID,
		    sizeof (ns->ns_nguid), ns->ns_nguid, devid));
	} else if (*(uint64_t *)ns->ns_eui64 != 0) {
		return (ddi_devid_init(devinfo, DEVID_NVME_EUI64,
		    sizeof (ns->ns_eui64), ns->ns_eui64, devid));
	} else {
		return (ddi_devid_init(devinfo, DEVID_NVME_NSID,
		    strlen(ns->ns_devid), ns->ns_devid, devid));
	}
}

static int
nvme_bd_free_space(void *arg, bd_xfer_t *xfer)
{
	nvme_namespace_t *ns = arg;

	if (xfer->x_dfl == NULL)
		return (EINVAL);

	if (!ns->ns_nvme->n_idctl->id_oncs.on_dset_mgmt)
		return (ENOTSUP);

	return (nvme_bd_cmd(ns, xfer, NVME_OPC_NVM_DSET_MGMT));
}

static int
nvme_open(dev_t *devp, int flag, int otyp, cred_t *cred_p)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(cred_p));
#endif
	nvme_t *nvme;
	nvme_minor_t *minor = NULL;
	uint32_t nsid;
	minor_t m = getminor(*devp);
	int rv = 0;

	if (otyp != OTYP_CHR)
		return (EINVAL);

	if (m >= NVME_OPEN_MINOR_MIN)
		return (ENXIO);

	nvme = ddi_get_soft_state(nvme_state, NVME_MINOR_INST(m));
	nsid = NVME_MINOR_NSID(m);

	if (nvme == NULL)
		return (ENXIO);

	if (nsid > MIN(nvme->n_namespace_count, NVME_MINOR_MAX))
		return (ENXIO);

	if (nvme->n_dead)
		return (EIO);

	/*
	 * At this point, we're going to allow an open to proceed on this
	 * device. We need to allocate a new instance for this (presuming one is
	 * available).
	 */
	minor = kmem_zalloc(sizeof (nvme_minor_t), KM_NOSLEEP_LAZY);
	if (minor == NULL) {
		return (ENOMEM);
	}

	cv_init(&minor->nm_cv, NULL, CV_DRIVER, NULL);
	list_link_init(&minor->nm_ctrl_lock.nli_node);
	minor->nm_ctrl_lock.nli_nvme = nvme;
	minor->nm_ctrl_lock.nli_minor = minor;
	list_link_init(&minor->nm_ns_lock.nli_node);
	minor->nm_ns_lock.nli_nvme = nvme;
	minor->nm_ns_lock.nli_minor = minor;
	minor->nm_minor = id_alloc_nosleep(nvme_open_minors);
	if (minor->nm_minor == -1) {
		nvme_minor_free(minor);
		return (ENOSPC);
	}

	minor->nm_ctrl = nvme;
	if (nsid != 0) {
		minor->nm_ns = nvme_nsid2ns(nvme, nsid);
	}

	/*
	 * Before we check for exclusive access and attempt a lock if requested,
	 * ensure that this minor is persisted.
	 */
	mutex_enter(&nvme_open_minors_mutex);
	avl_add(&nvme_open_minors_avl, minor);
	mutex_exit(&nvme_open_minors_mutex);

	/*
	 * A request for opening this FEXCL, is translated into a non-blocking
	 * write lock of the appropriate entity. This honors the original
	 * semantics here. In the future, we should see if we can remove this
	 * and turn a request for FEXCL at open into ENOTSUP.
	 */
	mutex_enter(&nvme->n_minor_mutex);
	if ((flag & FEXCL) != 0) {
		nvme_ioctl_lock_t lock = {
			.nil_level = NVME_LOCK_L_WRITE,
			.nil_flags = NVME_LOCK_F_DONT_BLOCK
		};

		if (minor->nm_ns != NULL) {
			lock.nil_ent = NVME_LOCK_E_NS;
			lock.nil_common.nioc_nsid = nsid;
		} else {
			lock.nil_ent = NVME_LOCK_E_CTRL;
		}
		nvme_rwlock(minor, &lock);
		if (lock.nil_common.nioc_drv_err != NVME_IOCTL_E_OK) {
			mutex_exit(&nvme->n_minor_mutex);

			mutex_enter(&nvme_open_minors_mutex);
			avl_remove(&nvme_open_minors_avl, minor);
			mutex_exit(&nvme_open_minors_mutex);

			nvme_minor_free(minor);
			return (EBUSY);
		}
	}
	mutex_exit(&nvme->n_minor_mutex);

	*devp = makedevice(getmajor(*devp), (minor_t)minor->nm_minor);
	return (rv);

}

static int
nvme_close(dev_t dev, int flag __unused, int otyp, cred_t *cred_p __unused)
{
	nvme_minor_t *minor;
	nvme_t *nvme;

	if (otyp != OTYP_CHR) {
		return (ENXIO);
	}

	minor = nvme_minor_find_by_dev(dev);
	if (minor == NULL) {
		return (ENXIO);
	}

	mutex_enter(&nvme_open_minors_mutex);
	avl_remove(&nvme_open_minors_avl, minor);
	mutex_exit(&nvme_open_minors_mutex);

	/*
	 * When this device is being closed, we must ensure that any locks held
	 * by this are dealt with.
	 */
	nvme = minor->nm_ctrl;
	mutex_enter(&nvme->n_minor_mutex);
	ASSERT3U(minor->nm_ctrl_lock.nli_state, !=, NVME_LOCK_STATE_BLOCKED);
	ASSERT3U(minor->nm_ns_lock.nli_state, !=, NVME_LOCK_STATE_BLOCKED);

	if (minor->nm_ctrl_lock.nli_state == NVME_LOCK_STATE_ACQUIRED) {
		VERIFY3P(minor->nm_ctrl_lock.nli_lock, !=, NULL);
		nvme_rwunlock(&minor->nm_ctrl_lock,
		    minor->nm_ctrl_lock.nli_lock);
	}

	if (minor->nm_ns_lock.nli_state == NVME_LOCK_STATE_ACQUIRED) {
		VERIFY3P(minor->nm_ns_lock.nli_lock, !=, NULL);
		nvme_rwunlock(&minor->nm_ns_lock, minor->nm_ns_lock.nli_lock);
	}
	mutex_exit(&nvme->n_minor_mutex);

	nvme_minor_free(minor);

	return (0);
}

void
nvme_ioctl_success(nvme_ioctl_common_t *ioc)
{
	ioc->nioc_drv_err = NVME_IOCTL_E_OK;
	ioc->nioc_ctrl_sc = NVME_CQE_SC_GEN_SUCCESS;
	ioc->nioc_ctrl_sct = NVME_CQE_SCT_GENERIC;
}

boolean_t
nvme_ioctl_error(nvme_ioctl_common_t *ioc, nvme_ioctl_errno_t err, uint32_t sct,
    uint32_t sc)
{
	ioc->nioc_drv_err = err;
	ioc->nioc_ctrl_sct = sct;
	ioc->nioc_ctrl_sc = sc;

	return (B_FALSE);
}

static int
nvme_ioctl_copyout_error(nvme_ioctl_errno_t err, intptr_t uaddr, int mode)
{
	nvme_ioctl_common_t ioc;

	ASSERT3U(err, !=, NVME_IOCTL_E_CTRL_ERROR);
	bzero(&ioc, sizeof (ioc));
	if (ddi_copyout(&ioc, (void *)uaddr, sizeof (nvme_ioctl_common_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}
	return (0);
}

/*
 * The companion to the namespace checking. This occurs after any rewriting
 * occurs. This is the primary point that we attempt to enforce any operation's
 * exclusivity. Note, it is theoretically possible for an operation to be
 * ongoing and to have someone with an exclusive lock ask to unlock it for some
 * reason. This does not maintain the number of such events that are going on.
 * While perhaps this is leaving too much up to the user, by the same token we
 * don't try to stop them from issuing two different format NVM commands
 * targeting the whole device at the same time either, even though the
 * controller would really rather that didn't happen.
 */
static boolean_t
nvme_ioctl_excl_check(nvme_minor_t *minor, nvme_ioctl_common_t *ioc,
    const nvme_ioctl_check_t *check)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_namespace_t *ns;
	boolean_t have_ctrl, have_ns, ctrl_is_excl, ns_is_excl;

	/*
	 * If the command doesn't require anything, then we're done.
	 */
	if (check->nck_excl == NVME_IOCTL_EXCL_SKIP) {
		return (B_TRUE);
	}

	if (ioc->nioc_nsid == 0 || ioc->nioc_nsid == NVME_NSID_BCAST) {
		ns = NULL;
	} else {
		ns = nvme_nsid2ns(nvme, ioc->nioc_nsid);
	}

	mutex_enter(&nvme->n_minor_mutex);
	ctrl_is_excl = nvme->n_lock.nl_writer != NULL;
	have_ctrl = nvme->n_lock.nl_writer == &minor->nm_ctrl_lock;
	if (ns != NULL) {
		/*
		 * We explicitly test the namespace lock's writer versus asking
		 * the minor because the minor's namespace lock may apply to a
		 * different namespace.
		 */
		ns_is_excl = ns->ns_lock.nl_writer != NULL;
		have_ns = ns->ns_lock.nl_writer == &minor->nm_ns_lock;
		ASSERT0(have_ctrl && have_ns);
#ifdef	DEBUG
		if (have_ns) {
			ASSERT3P(minor->nm_ns_lock.nli_ns, ==, ns);
		}
#endif
	} else {
		ns_is_excl = B_FALSE;
		have_ns = B_FALSE;
	}
	ASSERT0(ctrl_is_excl && ns_is_excl);
	mutex_exit(&nvme->n_minor_mutex);

	if (check->nck_excl == NVME_IOCTL_EXCL_CTRL) {
		if (have_ctrl) {
			return (B_TRUE);
		}

		return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NEED_CTRL_WRLOCK,
		    0, 0));
	}

	if (check->nck_excl == NVME_IOCTL_EXCL_WRITE) {
		if (ns == NULL) {
			if (have_ctrl) {
				return (B_TRUE);
			}
			return (nvme_ioctl_error(ioc,
			    NVME_IOCTL_E_NEED_CTRL_WRLOCK, 0, 0));
		} else {
			if (have_ctrl || have_ns) {
				return (B_TRUE);
			}
			return (nvme_ioctl_error(ioc,
			    NVME_IOCTL_E_NEED_NS_WRLOCK, 0, 0));
		}
	}

	/*
	 * Now we have an operation that does not require exclusive access. We
	 * can proceed as long as no one else has it or if someone does it is
	 * us. Regardless of what we target, a controller lock will stop us.
	 */
	if (ctrl_is_excl && !have_ctrl) {
		return (nvme_ioctl_error(ioc, NVME_IOCTL_E_CTRL_LOCKED, 0, 0));
	}

	/*
	 * Only check namespace exclusivity if we are targeting one.
	 */
	if (ns != NULL && ns_is_excl && !have_ns) {
		return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NS_LOCKED, 0, 0));
	}

	return (B_TRUE);
}

/*
 * Perform common checking as to whether or not an ioctl operation may proceed.
 * We check in this function various aspects of the namespace attributes that
 * it's calling on. Once the namespace attributes and any possible rewriting
 * have been performed, then we proceed to check whether or not the requisite
 * exclusive access is present in nvme_ioctl_excl_check().
 */
static boolean_t
nvme_ioctl_check(nvme_minor_t *minor, nvme_ioctl_common_t *ioc,
    const nvme_ioctl_check_t *check)
{
	/*
	 * If the minor has a namespace pointer, then it is constrained to that
	 * namespace. If a namespace is allowed, then there are only two valid
	 * values that we can find. The first is matching the minor. The second
	 * is our value zero, which will be transformed to the current
	 * namespace.
	 */
	if (minor->nm_ns != NULL) {
		if (!check->nck_ns_ok || !check->nck_ns_minor_ok) {
			return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NOT_CTRL, 0,
			    0));
		}

		if (ioc->nioc_nsid == 0) {
			ioc->nioc_nsid = minor->nm_ns->ns_id;
		} else if (ioc->nioc_nsid != minor->nm_ns->ns_id) {
			return (nvme_ioctl_error(ioc,
			    NVME_IOCTL_E_MINOR_WRONG_NS, 0, 0));
		}

		return (nvme_ioctl_excl_check(minor, ioc, check));
	}

	/*
	 * If we've been told to skip checking the controller, here's where we
	 * do that. This should really only be for commands which use the
	 * namespace ID for listing purposes and therefore can have
	 * traditionally illegal values here.
	 */
	if (check->nck_skip_ctrl) {
		return (nvme_ioctl_excl_check(minor, ioc, check));
	}

	/*
	 * At this point, we know that we're on the controller's node. We first
	 * deal with the simple case, is a namespace allowed at all or not. If
	 * it is not allowed, then the only acceptable value is zero.
	 */
	if (!check->nck_ns_ok) {
		if (ioc->nioc_nsid != 0) {
			return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NS_UNUSE, 0,
			    0));
		}

		return (nvme_ioctl_excl_check(minor, ioc, check));
	}

	/*
	 * At this point, we know that a controller is allowed to use a
	 * namespace. If we haven't been given zero or the broadcast namespace,
	 * check to see if it's actually a valid namespace ID. If is outside of
	 * range, then it is an error. Next, if we have been requested to
	 * rewrite 0 (the this controller indicator) as the broadcast namespace,
	 * do so.
	 *
	 * While we validate that this namespace is within the valid range, we
	 * do not check if it is active or inactive. That is left to our callers
	 * to determine.
	 */
	if (ioc->nioc_nsid > minor->nm_ctrl->n_namespace_count &&
	    ioc->nioc_nsid != NVME_NSID_BCAST) {
		return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NS_RANGE, 0, 0));
	}

	if (ioc->nioc_nsid == 0 && check->nck_ctrl_rewrite) {
		ioc->nioc_nsid = NVME_NSID_BCAST;
	}

	/*
	 * Finally, see if we have ended up with a broadcast namespace ID
	 * whether through specification or rewriting. If that is not allowed,
	 * then that is an error.
	 */
	if (!check->nck_bcast_ok && ioc->nioc_nsid == NVME_NSID_BCAST) {
		return (nvme_ioctl_error(ioc, NVME_IOCTL_E_NO_BCAST_NS, 0, 0));
	}

	return (nvme_ioctl_excl_check(minor, ioc, check));
}

static int
nvme_ioctl_ctrl_info(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_ctrl_info_t *info;
	nvme_reg_cap_t cap = { 0 };
	nvme_ioctl_identify_t id = { .nid_cns = NVME_IDENTIFY_CTRL };
	void *idbuf;

	if ((mode & FREAD) == 0)
		return (EBADF);

	info = kmem_alloc(sizeof (nvme_ioctl_ctrl_info_t), KM_NOSLEEP_LAZY);
	if (info == NULL) {
		return (nvme_ioctl_copyout_error(NVME_IOCTL_E_NO_KERN_MEM, arg,
		    mode));
	}

	if (ddi_copyin((void *)arg, info, sizeof (nvme_ioctl_ctrl_info_t),
	    mode & FKIOCTL) != 0) {
		kmem_free(info, sizeof (nvme_ioctl_ctrl_info_t));
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &info->nci_common,
	    &nvme_check_ctrl_info)) {
		goto copyout;
	}

	/*
	 * We explicitly do not use the identify controller copy in the kernel
	 * right now so that way we can get a snapshot of the controller's
	 * current capacity and values. While it's tempting to try to use this
	 * to refresh the kernel's version we don't just to simplify the rest of
	 * the driver right now.
	 */
	if (!nvme_identify(nvme, B_TRUE, &id, &idbuf)) {
		info->nci_common = id.nid_common;
		goto copyout;
	}
	bcopy(idbuf, &info->nci_ctrl_id, sizeof (nvme_identify_ctrl_t));
	kmem_free(idbuf, NVME_IDENTIFY_BUFSIZE);

	/*
	 * Use the kernel's cached common namespace information for this.
	 */
	bcopy(nvme->n_idcomns, &info->nci_common_ns,
	    sizeof (nvme_identify_nsid_t));

	info->nci_vers = nvme->n_version;

	/*
	 * The MPSMIN and MPSMAX fields in the CAP register use 0 to
	 * specify the base page size of 4k (1<<12), so add 12 here to
	 * get the real page size value.
	 */
	cap.r = nvme_get64(nvme, NVME_REG_CAP);
	info->nci_caps.cap_mpsmax = 1 << (12 + cap.b.cap_mpsmax);
	info->nci_caps.cap_mpsmin = 1 << (12 + cap.b.cap_mpsmin);

	info->nci_nintrs = (uint32_t)nvme->n_intr_cnt;

copyout:
	if (ddi_copyout(info, (void *)arg, sizeof (nvme_ioctl_ctrl_info_t),
	    mode & FKIOCTL) != 0) {
		kmem_free(info, sizeof (nvme_ioctl_ctrl_info_t));
		return (EFAULT);
	}

	kmem_free(info, sizeof (nvme_ioctl_ctrl_info_t));
	return (0);
}

static int
nvme_ioctl_ns_info(nvme_minor_t *minor, intptr_t arg, int mode, cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_ns_info_t *ns_info;
	nvme_namespace_t *ns;
	nvme_ioctl_identify_t id = { .nid_cns = NVME_IDENTIFY_NSID };
	void *idbuf;

	if ((mode & FREAD) == 0)
		return (EBADF);

	ns_info = kmem_zalloc(sizeof (nvme_ioctl_ns_info_t), KM_NOSLEEP_LAZY);
	if (ns_info == NULL) {
		return (nvme_ioctl_copyout_error(NVME_IOCTL_E_NO_KERN_MEM, arg,
		    mode));
	}

	if (ddi_copyin((void *)arg, ns_info, sizeof (nvme_ioctl_ns_info_t),
	    mode & FKIOCTL) != 0) {
		kmem_free(ns_info, sizeof (nvme_ioctl_ns_info_t));
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &ns_info->nni_common,
	    &nvme_check_ns_info)) {
		goto copyout;
	}

	ASSERT3U(ns_info->nni_common.nioc_nsid, >, 0);
	ns = nvme_nsid2ns(nvme, ns_info->nni_common.nioc_nsid);

	/*
	 * First fetch a fresh copy of the namespace information. Most callers
	 * are using this because they will want a mostly accurate snapshot of
	 * capacity and utilization.
	 */
	id.nid_common.nioc_nsid = ns_info->nni_common.nioc_nsid;
	if (!nvme_identify(nvme, B_TRUE, &id, &idbuf)) {
		ns_info->nni_common = id.nid_common;
		goto copyout;
	}
	bcopy(idbuf, &ns_info->nni_id, sizeof (nvme_identify_nsid_t));
	kmem_free(idbuf, NVME_IDENTIFY_BUFSIZE);

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	ns_info->nni_state = ns->ns_state;
	if (ns->ns_state >= NVME_NS_STATE_ATTACHED) {
		const char *addr;

		ns_info->nni_state = NVME_NS_STATE_ATTACHED;
		addr = bd_address(ns->ns_bd_hdl);
		if (strlcpy(ns_info->nni_addr, addr,
		    sizeof (ns_info->nni_addr)) >= sizeof (ns_info->nni_addr)) {
			nvme_mgmt_unlock(nvme);
			(void) nvme_ioctl_error(&ns_info->nni_common,
			    NVME_IOCTL_E_BD_ADDR_OVER, 0, 0);
			goto copyout;
		}
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(ns_info, (void *)arg, sizeof (nvme_ioctl_ns_info_t),
	    mode & FKIOCTL) != 0) {
		kmem_free(ns_info, sizeof (nvme_ioctl_ns_info_t));
		return (EFAULT);
	}

	kmem_free(ns_info, sizeof (nvme_ioctl_ns_info_t));
	return (0);
}

static int
nvme_ioctl_identify(nvme_minor_t *minor, intptr_t arg, int mode, cred_t *cred_p)
{
	_NOTE(ARGUNUSED(cred_p));
	nvme_t *const nvme = minor->nm_ctrl;
	void *idctl;
	uint_t model;
	nvme_ioctl_identify_t id;
#ifdef	_MULTI_DATAMODEL
	nvme_ioctl_identify32_t id32;
#endif
	boolean_t ns_minor;

	if ((mode & FREAD) == 0)
		return (EBADF);

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&id, sizeof (id));
		if (ddi_copyin((void *)arg, &id32, sizeof (id32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		id.nid_common.nioc_nsid = id32.nid_common.nioc_nsid;
		id.nid_cns = id32.nid_cns;
		id.nid_ctrlid = id32.nid_ctrlid;
		id.nid_data = id32.nid_data;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &id, sizeof (id),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	if (!nvme_ioctl_check(minor, &id.nid_common, &nvme_check_identify)) {
		goto copyout;
	}

	ns_minor = minor->nm_ns != NULL;
	if (!nvme_validate_identify(nvme, &id, ns_minor)) {
		goto copyout;
	}

	if (nvme_identify(nvme, B_TRUE, &id, &idctl)) {
		int ret = ddi_copyout(idctl, (void *)id.nid_data,
		    NVME_IDENTIFY_BUFSIZE, mode & FKIOCTL);
		kmem_free(idctl, NVME_IDENTIFY_BUFSIZE);
		if (ret != 0) {
			(void) nvme_ioctl_error(&id.nid_common,
			    NVME_IOCTL_E_BAD_USER_DATA, 0, 0);
			goto copyout;
		}

		nvme_ioctl_success(&id.nid_common);
	}

copyout:
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		id32.nid_common = id.nid_common;

		if (ddi_copyout(&id32, (void *)arg, sizeof (id32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&id, (void *)arg, sizeof (id),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Execute commands on behalf of the various ioctls.
 *
 * If this returns true then the command completed successfully. Otherwise error
 * information is returned in the nvme_ioctl_common_t arguments.
 */
static boolean_t
nvme_ioc_cmd(nvme_t *nvme, nvme_ioctl_common_t *ioc, nvme_ioc_cmd_args_t *args)
{
	nvme_cmd_t *cmd;
	boolean_t ret = B_FALSE;

	cmd = nvme_alloc_admin_cmd(nvme, KM_SLEEP);
	cmd->nc_sqid = 0;

	/*
	 * This function is used to facilitate requests from
	 * userspace, so don't panic if the command fails. This
	 * is especially true for admin passthru commands, where
	 * the actual command data structure is entirely defined
	 * by userspace.
	 */
	cmd->nc_flags |= NVME_CMD_F_DONTPANIC;

	cmd->nc_callback = nvme_wakeup_cmd;
	cmd->nc_sqe = *args->ica_sqe;

	if ((args->ica_dma_flags & DDI_DMA_RDWR) != 0) {
		if (args->ica_data == NULL) {
			ret = nvme_ioctl_error(ioc, NVME_IOCTL_E_NO_DMA_MEM,
			    0, 0);
			goto free_cmd;
		}

		if (nvme_zalloc_dma(nvme, args->ica_data_len,
		    args->ica_dma_flags, &nvme->n_prp_dma_attr, &cmd->nc_dma) !=
		    DDI_SUCCESS) {
			dev_err(nvme->n_dip, CE_WARN,
			    "!nvme_zalloc_dma failed for nvme_ioc_cmd()");
			ret = nvme_ioctl_error(ioc,
			    NVME_IOCTL_E_NO_DMA_MEM, 0, 0);
			goto free_cmd;
		}

		if (nvme_fill_prp(cmd, cmd->nc_dma->nd_dmah) != 0) {
			ret = nvme_ioctl_error(ioc,
			    NVME_IOCTL_E_NO_DMA_MEM, 0, 0);
			goto free_cmd;
		}

		if ((args->ica_dma_flags & DDI_DMA_WRITE) != 0 &&
		    ddi_copyin(args->ica_data, cmd->nc_dma->nd_memp,
		    args->ica_data_len, args->ica_copy_flags) != 0) {
			ret = nvme_ioctl_error(ioc, NVME_IOCTL_E_BAD_USER_DATA,
			    0, 0);
			goto free_cmd;
		}
	}

	nvme_admin_cmd(cmd, args->ica_timeout);

	if (!nvme_check_cmd_status_ioctl(cmd, ioc)) {
		ret = B_FALSE;
		goto free_cmd;
	}

	args->ica_cdw0 = cmd->nc_cqe.cqe_dw0;

	if ((args->ica_dma_flags & DDI_DMA_READ) != 0 &&
	    ddi_copyout(cmd->nc_dma->nd_memp, args->ica_data,
	    args->ica_data_len, args->ica_copy_flags) != 0) {
		ret = nvme_ioctl_error(ioc, NVME_IOCTL_E_BAD_USER_DATA, 0, 0);
		goto free_cmd;
	}

	ret = B_TRUE;
	nvme_ioctl_success(ioc);

free_cmd:
	nvme_free_cmd(cmd);

	return (ret);
}

static int
nvme_ioctl_get_logpage(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	void *buf;
	nvme_ioctl_get_logpage_t log;
	uint_t model;
#ifdef	_MULTI_DATAMODEL
	nvme_ioctl_get_logpage32_t log32;
#endif

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&log, sizeof (log));
		if (ddi_copyin((void *)arg, &log32, sizeof (log32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}

		log.nigl_common.nioc_nsid = log32.nigl_common.nioc_nsid;
		log.nigl_csi = log32.nigl_csi;
		log.nigl_lid = log32.nigl_lid;
		log.nigl_lsp = log32.nigl_lsp;
		log.nigl_len = log32.nigl_len;
		log.nigl_offset = log32.nigl_offset;
		log.nigl_data = log32.nigl_data;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &log, sizeof (log),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	/*
	 * Eventually we'd like to do a soft lock on the namespaces from
	 * changing out from us during this operation in the future. But we
	 * haven't implemented that yet.
	 */
	if (!nvme_ioctl_check(minor, &log.nigl_common,
	    &nvme_check_get_logpage)) {
		goto copyout;
	}

	if (!nvme_validate_logpage(nvme, &log)) {
		goto copyout;
	}

	if (nvme_get_logpage(nvme, B_TRUE, &log, &buf)) {
		int copy;

		copy = ddi_copyout(buf, (void *)log.nigl_data, log.nigl_len,
		    mode & FKIOCTL);
		kmem_free(buf, log.nigl_len);
		if (copy != 0) {
			(void) nvme_ioctl_error(&log.nigl_common,
			    NVME_IOCTL_E_BAD_USER_DATA, 0, 0);
			goto copyout;
		}

		nvme_ioctl_success(&log.nigl_common);
	}

copyout:
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&log32, sizeof (log32));

		log32.nigl_common = log.nigl_common;
		log32.nigl_csi = log.nigl_csi;
		log32.nigl_lid = log.nigl_lid;
		log32.nigl_lsp = log.nigl_lsp;
		log32.nigl_len = log.nigl_len;
		log32.nigl_offset = log.nigl_offset;
		log32.nigl_data = log.nigl_data;
		if (ddi_copyout(&log32, (void *)arg, sizeof (log32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&log, (void *)arg, sizeof (log),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	return (0);
}

static int
nvme_ioctl_get_feature(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_get_feature_t feat;
	uint_t model;
#ifdef	_MULTI_DATAMODEL
	nvme_ioctl_get_feature32_t feat32;
#endif
	nvme_get_features_dw10_t gf_dw10 = { 0 };
	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe = {
	    .sqe_opc	= NVME_OPC_GET_FEATURES
	};

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&feat, sizeof (feat));
		if (ddi_copyin((void *)arg, &feat32, sizeof (feat32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}

		feat.nigf_common.nioc_nsid = feat32.nigf_common.nioc_nsid;
		feat.nigf_fid = feat32.nigf_fid;
		feat.nigf_sel = feat32.nigf_sel;
		feat.nigf_cdw11 = feat32.nigf_cdw11;
		feat.nigf_data = feat32.nigf_data;
		feat.nigf_len = feat32.nigf_len;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &feat, sizeof (feat),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	if (!nvme_ioctl_check(minor, &feat.nigf_common,
	    &nvme_check_get_feature)) {
		goto copyout;
	}

	if (!nvme_validate_get_feature(nvme, &feat)) {
		goto copyout;
	}

	gf_dw10.b.gt_fid = bitx32(feat.nigf_fid, 7, 0);
	gf_dw10.b.gt_sel = bitx32(feat.nigf_sel, 2, 0);
	sqe.sqe_cdw10 = gf_dw10.r;
	sqe.sqe_cdw11 = feat.nigf_cdw11;
	sqe.sqe_nsid = feat.nigf_common.nioc_nsid;

	args.ica_sqe = &sqe;
	if (feat.nigf_len != 0) {
		args.ica_data = (void *)feat.nigf_data;
		args.ica_data_len = feat.nigf_len;
		args.ica_dma_flags = DDI_DMA_READ;
	}
	args.ica_copy_flags = mode;
	args.ica_timeout = nvme_admin_cmd_timeout;

	if (!nvme_ioc_cmd(nvme, &feat.nigf_common, &args)) {
		goto copyout;
	}

	feat.nigf_cdw0 = args.ica_cdw0;

copyout:
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		bzero(&feat32, sizeof (feat32));

		feat32.nigf_common = feat.nigf_common;
		feat32.nigf_fid = feat.nigf_fid;
		feat32.nigf_sel = feat.nigf_sel;
		feat32.nigf_cdw11 = feat.nigf_cdw11;
		feat32.nigf_data = feat.nigf_data;
		feat32.nigf_len = feat.nigf_len;
		feat32.nigf_cdw0 = feat.nigf_cdw0;
		if (ddi_copyout(&feat32, (void *)arg, sizeof (feat32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&feat, (void *)arg, sizeof (feat),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	return (0);
}

static int
nvme_ioctl_format(nvme_minor_t *minor, intptr_t arg, int mode, cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_format_t ioc;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &ioc,
	    sizeof (nvme_ioctl_format_t), mode & FKIOCTL) != 0)
		return (EFAULT);

	if (!nvme_ioctl_check(minor, &ioc.nif_common, &nvme_check_format)) {
		goto copyout;
	}

	if (!nvme_validate_format(nvme, &ioc)) {
		goto copyout;
	}

	/*
	 * The broadcast namespace can format all namespaces attached to the
	 * controller, meaning active namespaces. However, a targeted format can
	 * impact any allocated namespace, even one not attached. As such, we
	 * need different checks for each situation.
	 */
	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	if (ioc.nif_common.nioc_nsid == NVME_NSID_BCAST) {
		if (!nvme_no_blkdev_attached(nvme, ioc.nif_common.nioc_nsid)) {
			nvme_mgmt_unlock(nvme);
			(void) nvme_ioctl_error(&ioc.nif_common,
			    NVME_IOCTL_E_NS_BLKDEV_ATTACH, 0, 0);
			goto copyout;
		}
	} else {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme,
		    ioc.nif_common.nioc_nsid);

		if (!nvme_ns_state_check(ns, &ioc.nif_common,
		    nvme_format_nvm_states)) {
			nvme_mgmt_unlock(nvme);
			goto copyout;
		}
	}

	if (nvme_format_nvm(nvme, &ioc)) {
		nvme_ioctl_success(&ioc.nif_common);
		nvme_rescan_ns(nvme, ioc.nif_common.nioc_nsid);
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&ioc, (void *)(uintptr_t)arg, sizeof (ioc),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_bd_detach(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_common_t com;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &com, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &com, &nvme_check_attach_detach)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	if (nvme_bd_detach_ns(nvme, &com)) {
		nvme_ioctl_success(&com);
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&com, (void *)(uintptr_t)arg, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_bd_attach(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_common_t com;
	nvme_namespace_t *ns;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &com, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &com, &nvme_check_attach_detach)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	ns = nvme_nsid2ns(nvme, com.nioc_nsid);

	/*
	 * Strictly speaking we shouldn't need to call nvme_init_ns() here as
	 * we should be properly refreshing the internal state when we are
	 * issuing commands that change things. However, we opt to still do so
	 * as a bit of a safety check lest we give the kernel something bad or a
	 * vendor unique command somehow did something behind our backs.
	 */
	if (ns->ns_state < NVME_NS_STATE_ATTACHED) {
		nvme_rescan_ns(nvme, com.nioc_nsid);
	}

	if (nvme_bd_attach_ns(nvme, &com)) {
		nvme_ioctl_success(&com);
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&com, (void *)(uintptr_t)arg, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Attach or detach a controller from the specified namespace. While this in
 * theory allows for multiple controllers to be specified, currently we only
 * support using the controller that we've issued this ioctl on. In the future
 * when we have better ways to test dual-attached controllers then this should
 * be extended to take the controller list from userland.
 */
static boolean_t
nvme_ctrl_attach_detach_ns(nvme_t *nvme, nvme_namespace_t *ns,
    nvme_ioctl_common_t *ioc, boolean_t attach)
{
	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe;
	nvme_ns_mgmt_dw10_t dw10;
	uint16_t ctrlids[2];

	ASSERT(nvme_mgmt_lock_held(nvme));

	bzero(&sqe, sizeof (sqe));
	sqe.sqe_nsid = ioc->nioc_nsid;
	sqe.sqe_opc = NVME_OPC_NS_ATTACH;

	dw10.r = 0;
	dw10.b.nsm_sel = attach ? NVME_NS_ATTACH_CTRL_ATTACH :
	    NVME_NS_ATTACH_CTRL_DETACH;
	sqe.sqe_cdw10 = dw10.r;

	/*
	 * As we only support sending our current controller's id along, we can
	 * simplify this and don't need both allocating a full
	 * nvme_identify_ctrl_list_t for two items.
	 */
	ctrlids[0] = 1;
	ctrlids[1] = nvme->n_idctl->id_cntlid;

	args.ica_sqe = &sqe;
	args.ica_data = ctrlids;
	args.ica_data_len = sizeof (ctrlids);
	args.ica_dma_flags = DDI_DMA_WRITE;
	args.ica_copy_flags = FKIOCTL;
	args.ica_timeout = nvme_admin_cmd_timeout;

	return (nvme_ioc_cmd(nvme, ioc, &args));
}

static int
nvme_ioctl_ctrl_detach(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_common_t com;
	nvme_namespace_t *ns;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &com, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &com, &nvme_check_attach_detach)) {
		goto copyout;
	}

	if (!nvme_validate_ctrl_attach_detach_ns(nvme, &com)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	ns = nvme_nsid2ns(nvme, com.nioc_nsid);

	if (nvme_ns_state_check(ns, &com, nvme_ctrl_detach_states)) {
		if (nvme_ctrl_attach_detach_ns(nvme, ns, &com, B_FALSE)) {
			nvme_rescan_ns(nvme, com.nioc_nsid);
			nvme_ioctl_success(&com);
		}
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&com, (void *)(uintptr_t)arg, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_ns_create(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_ns_create_t create;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &create, sizeof (create),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &create.nnc_common,
	    &nvme_check_ns_create)) {
		goto copyout;
	}

	if (!nvme_validate_ns_create(nvme, &create)) {
		goto copyout;
	}

	/*
	 * Now that we've validated this, proceed to build up the actual data
	 * request. We need to fill out the relevant identify namespace data
	 * structure fields.
	 */
	nvme_identify_nsid_t *idns = kmem_zalloc(sizeof (nvme_identify_nsid_t),
	    KM_NOSLEEP_LAZY);
	if (idns == NULL) {
		(void) nvme_ioctl_error(&create.nnc_common,
		    NVME_IOCTL_E_NO_KERN_MEM, 0, 0);
		goto copyout;
	}

	idns->id_nsize = create.nnc_nsze;
	idns->id_ncap = create.nnc_ncap;
	idns->id_flbas.lba_format = create.nnc_flbas;
	idns->id_nmic.nm_shared = bitx32(create.nnc_nmic, 0, 0);

	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe;
	nvme_ns_mgmt_dw10_t dw10;
	nvme_ns_mgmt_dw11_t dw11;

	bzero(&sqe, sizeof (sqe));
	sqe.sqe_nsid = create.nnc_common.nioc_nsid;
	sqe.sqe_opc = NVME_OPC_NS_MGMT;

	dw10.r = 0;
	dw10.b.nsm_sel = NVME_NS_MGMT_NS_CREATE;
	sqe.sqe_cdw10 = dw10.r;

	dw11.r = 0;
	dw11.b.nsm_csi = create.nnc_csi;
	sqe.sqe_cdw11 = dw11.r;

	args.ica_sqe = &sqe;
	args.ica_data = idns;
	args.ica_data_len = sizeof (nvme_identify_nsid_t);
	args.ica_dma_flags = DDI_DMA_WRITE;
	args.ica_copy_flags = FKIOCTL;
	args.ica_timeout = nvme_format_cmd_timeout;

	/*
	 * This command manipulates our understanding of a namespace's state.
	 * While we don't need to check anything before we proceed, we still
	 * logically require the lock.
	 */
	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	if (nvme_ioc_cmd(nvme, &create.nnc_common, &args)) {
		create.nnc_nsid = args.ica_cdw0;
		nvme_rescan_ns(nvme, create.nnc_nsid);
		nvme_ioctl_success(&create.nnc_common);
	}
	nvme_mgmt_unlock(nvme);
	kmem_free(idns, sizeof (nvme_identify_nsid_t));

copyout:
	if (ddi_copyout(&create, (void *)(uintptr_t)arg, sizeof (create),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);

}

static int
nvme_ioctl_ns_delete(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_common_t com;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &com, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &com, &nvme_check_ns_delete)) {
		goto copyout;
	}

	if (!nvme_validate_ns_delete(nvme, &com)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	if (com.nioc_nsid == NVME_NSID_BCAST) {
		if (!nvme_no_blkdev_attached(nvme, com.nioc_nsid)) {
			nvme_mgmt_unlock(nvme);
			(void) nvme_ioctl_error(&com,
			    NVME_IOCTL_E_NS_BLKDEV_ATTACH, 0, 0);
			goto copyout;
		}
	} else {
		nvme_namespace_t *ns = nvme_nsid2ns(nvme, com.nioc_nsid);

		if (!nvme_ns_state_check(ns, &com, nvme_ns_delete_states)) {
			nvme_mgmt_unlock(nvme);
			goto copyout;
		}
	}

	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe;
	nvme_ns_mgmt_dw10_t dw10;

	bzero(&sqe, sizeof (sqe));
	sqe.sqe_nsid = com.nioc_nsid;
	sqe.sqe_opc = NVME_OPC_NS_MGMT;

	dw10.r = 0;
	dw10.b.nsm_sel = NVME_NS_MGMT_NS_DELETE;
	sqe.sqe_cdw10 = dw10.r;

	args.ica_sqe = &sqe;
	args.ica_data = NULL;
	args.ica_data_len = 0;
	args.ica_dma_flags = 0;
	args.ica_copy_flags = 0;
	args.ica_timeout = nvme_format_cmd_timeout;

	if (nvme_ioc_cmd(nvme, &com, &args)) {
		nvme_rescan_ns(nvme, com.nioc_nsid);
		nvme_ioctl_success(&com);
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&com, (void *)(uintptr_t)arg, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_ctrl_attach(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_common_t com;
	nvme_namespace_t *ns;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &com, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &com, &nvme_check_attach_detach)) {
		goto copyout;
	}

	if (!nvme_validate_ctrl_attach_detach_ns(nvme, &com)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	ns = nvme_nsid2ns(nvme, com.nioc_nsid);

	if (nvme_ns_state_check(ns, &com, nvme_ctrl_attach_states)) {
		if (nvme_ctrl_attach_detach_ns(nvme, ns, &com, B_TRUE)) {
			nvme_rescan_ns(nvme, com.nioc_nsid);
			nvme_ioctl_success(&com);
		}
	}
	nvme_mgmt_unlock(nvme);

copyout:
	if (ddi_copyout(&com, (void *)(uintptr_t)arg, sizeof (com),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static void
nvme_ufm_update(nvme_t *nvme)
{
	mutex_enter(&nvme->n_fwslot_mutex);
	ddi_ufm_update(nvme->n_ufmh);
	if (nvme->n_fwslot != NULL) {
		kmem_free(nvme->n_fwslot, sizeof (nvme_fwslot_log_t));
		nvme->n_fwslot = NULL;
	}
	mutex_exit(&nvme->n_fwslot_mutex);
}

/*
 * Download new firmware to the device's internal staging area. We do not call
 * nvme_ufm_update() here because after a firmware download, there has been no
 * change to any of the actual persistent firmware data. That requires a
 * subsequent ioctl (NVME_IOC_FIRMWARE_COMMIT) to commit the firmware to a slot
 * or to activate a slot.
 */
static int
nvme_ioctl_firmware_download(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_fw_load_t fw;
	uint64_t len, maxcopy;
	offset_t offset;
	uint32_t gran;
	nvme_valid_ctrl_data_t data;
	uintptr_t buf;
	nvme_sqe_t sqe = {
	    .sqe_opc	= NVME_OPC_FW_IMAGE_LOAD
	};

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &fw, sizeof (fw),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &fw.fwl_common, &nvme_check_firmware)) {
		goto copyout;
	}

	if (!nvme_validate_fw_load(nvme, &fw)) {
		goto copyout;
	}

	len = fw.fwl_len;
	offset = fw.fwl_off;
	buf = fw.fwl_buf;

	/*
	 * We need to determine the minimum and maximum amount of data that we
	 * will send to the device in a given go. Starting in NMVe 1.3 this must
	 * be a multiple of the firmware update granularity (FWUG), but must not
	 * exceed the maximum data transfer that we've set. Many devices don't
	 * report something here, which means we'll end up getting our default
	 * value. Our policy is a little simple, but it's basically if the
	 * maximum data transfer is evenly divided by the granularity, then use
	 * it. Otherwise we use the granularity itself. The granularity is
	 * always in page sized units, so trying to find another optimum point
	 * isn't worth it. If we encounter a contradiction, then we will have to
	 * error out.
	 */
	data.vcd_vers = &nvme->n_version;
	data.vcd_id = nvme->n_idctl;
	gran = nvme_fw_load_granularity(&data);

	if ((nvme->n_max_data_transfer_size % gran) == 0) {
		maxcopy = nvme->n_max_data_transfer_size;
	} else if (gran <= nvme->n_max_data_transfer_size) {
		maxcopy = gran;
	} else {
		(void) nvme_ioctl_error(&fw.fwl_common,
		    NVME_IOCTL_E_FW_LOAD_IMPOS_GRAN, 0, 0);
		goto copyout;
	}

	while (len > 0) {
		nvme_ioc_cmd_args_t args = { NULL };
		uint64_t copylen = MIN(maxcopy, len);

		sqe.sqe_cdw10 = (uint32_t)(copylen >> NVME_DWORD_SHIFT) - 1;
		sqe.sqe_cdw11 = (uint32_t)(offset >> NVME_DWORD_SHIFT);

		args.ica_sqe = &sqe;
		args.ica_data = (void *)buf;
		args.ica_data_len = copylen;
		args.ica_dma_flags = DDI_DMA_WRITE;
		args.ica_copy_flags = mode;
		args.ica_timeout = nvme_admin_cmd_timeout;

		if (!nvme_ioc_cmd(nvme, &fw.fwl_common, &args)) {
			break;
		}

		buf += copylen;
		offset += copylen;
		len -= copylen;
	}

copyout:
	if (ddi_copyout(&fw, (void *)(uintptr_t)arg, sizeof (fw),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_firmware_commit(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	nvme_ioctl_fw_commit_t fw;
	nvme_firmware_commit_dw10_t fc_dw10 = { 0 };
	nvme_ioc_cmd_args_t args = { NULL };
	nvme_sqe_t sqe = {
	    .sqe_opc	= NVME_OPC_FW_ACTIVATE
	};

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &fw, sizeof (fw),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (!nvme_ioctl_check(minor, &fw.fwc_common, &nvme_check_firmware)) {
		goto copyout;
	}

	if (!nvme_validate_fw_commit(nvme, &fw)) {
		goto copyout;
	}

	fc_dw10.b.fc_slot = fw.fwc_slot;
	fc_dw10.b.fc_action = fw.fwc_action;
	sqe.sqe_cdw10 = fc_dw10.r;

	args.ica_sqe = &sqe;
	args.ica_timeout = nvme_commit_save_cmd_timeout;

	/*
	 * There are no conditional actions to take based on this succeeding or
	 * failing. A failure is recorded in the ioctl structure returned to the
	 * user.
	 */
	(void) nvme_ioc_cmd(nvme, &fw.fwc_common, &args);

	/*
	 * Let the DDI UFM subsystem know that the firmware information for
	 * this device has changed. We perform this unconditionally as an
	 * invalidation doesn't particularly hurt us.
	 */
	nvme_ufm_update(nvme);

copyout:
	if (ddi_copyout(&fw, (void *)(uintptr_t)arg, sizeof (fw),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

/*
 * Helper to copy in a passthru command from userspace, handling
 * different data models.
 */
static int
nvme_passthru_copyin_cmd(const void *buf, nvme_ioctl_passthru_t *cmd, int mode)
{
	switch (ddi_model_convert_from(mode & FMODELS)) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32: {
		nvme_ioctl_passthru32_t cmd32;

		if (ddi_copyin(buf, (void*)&cmd32, sizeof (cmd32), mode) != 0)
			return (EFAULT);

		bzero(cmd, sizeof (nvme_ioctl_passthru_t));

		cmd->npc_common.nioc_nsid = cmd32.npc_common.nioc_nsid;
		cmd->npc_opcode = cmd32.npc_opcode;
		cmd->npc_timeout = cmd32.npc_timeout;
		cmd->npc_flags = cmd32.npc_flags;
		cmd->npc_impact = cmd32.npc_impact;
		cmd->npc_cdw12 = cmd32.npc_cdw12;
		cmd->npc_cdw13 = cmd32.npc_cdw13;
		cmd->npc_cdw14 = cmd32.npc_cdw14;
		cmd->npc_cdw15 = cmd32.npc_cdw15;
		cmd->npc_buflen = cmd32.npc_buflen;
		cmd->npc_buf = cmd32.npc_buf;
		break;
	}
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin(buf, (void *)cmd, sizeof (nvme_ioctl_passthru_t),
		    mode) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Helper to copy out a passthru command result to userspace, handling
 * different data models.
 */
static int
nvme_passthru_copyout_cmd(const nvme_ioctl_passthru_t *cmd, void *buf, int mode)
{
	switch (ddi_model_convert_from(mode & FMODELS)) {
#ifdef _MULTI_DATAMODEL
	case DDI_MODEL_ILP32: {
		nvme_ioctl_passthru32_t cmd32;

		bzero(&cmd32, sizeof (nvme_ioctl_passthru32_t));

		cmd32.npc_common = cmd->npc_common;
		cmd32.npc_opcode = cmd->npc_opcode;
		cmd32.npc_timeout = cmd->npc_timeout;
		cmd32.npc_flags = cmd->npc_flags;
		cmd32.npc_impact = cmd->npc_impact;
		cmd32.npc_cdw0 = cmd->npc_cdw0;
		cmd32.npc_cdw12 = cmd->npc_cdw12;
		cmd32.npc_cdw13 = cmd->npc_cdw13;
		cmd32.npc_cdw14 = cmd->npc_cdw14;
		cmd32.npc_cdw15 = cmd->npc_cdw15;
		cmd32.npc_buflen = (size32_t)cmd->npc_buflen;
		cmd32.npc_buf = (uintptr32_t)cmd->npc_buf;
		if (ddi_copyout(&cmd32, buf, sizeof (cmd32), mode) != 0)
			return (EFAULT);
		break;
	}
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(cmd, buf, sizeof (nvme_ioctl_passthru_t),
		    mode) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}
	return (0);
}

/*
 * Run an arbitrary vendor-specific admin command on the device.
 */
static int
nvme_ioctl_passthru(nvme_minor_t *minor, intptr_t arg, int mode, cred_t *cred_p)
{
	nvme_t *const nvme = minor->nm_ctrl;
	int rv;
	nvme_ioctl_passthru_t pass;
	nvme_sqe_t sqe;
	nvme_ioc_cmd_args_t args = { NULL };

	/*
	 * Basic checks: permissions, data model, argument size.
	 */
	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if ((rv = nvme_passthru_copyin_cmd((void *)(uintptr_t)arg, &pass,
	    mode)) != 0) {
		return (rv);
	}

	if (!nvme_ioctl_check(minor, &pass.npc_common, &nvme_check_passthru)) {
		goto copyout;
	}

	if (!nvme_validate_vuc(nvme, &pass)) {
		goto copyout;
	}

	nvme_mgmt_lock(nvme, NVME_MGMT_LOCK_NVME);
	if ((pass.npc_impact & NVME_IMPACT_NS) != 0) {
		/*
		 * We've been told this has ns impact. Right now force that to
		 * be every ns until we have more use cases and reason to trust
		 * the nsid field.
		 */
		if (!nvme_no_blkdev_attached(nvme, NVME_NSID_BCAST)) {
			nvme_mgmt_unlock(nvme);
			(void) nvme_ioctl_error(&pass.npc_common,
			    NVME_IOCTL_E_NS_BLKDEV_ATTACH, 0, 0);
			goto copyout;
		}
	}

	bzero(&sqe, sizeof (sqe));

	sqe.sqe_opc = pass.npc_opcode;
	sqe.sqe_nsid = pass.npc_common.nioc_nsid;
	sqe.sqe_cdw10 = (uint32_t)(pass.npc_buflen >> NVME_DWORD_SHIFT);
	sqe.sqe_cdw12 = pass.npc_cdw12;
	sqe.sqe_cdw13 = pass.npc_cdw13;
	sqe.sqe_cdw14 = pass.npc_cdw14;
	sqe.sqe_cdw15 = pass.npc_cdw15;

	args.ica_sqe = &sqe;
	args.ica_data = (void *)pass.npc_buf;
	args.ica_data_len = pass.npc_buflen;
	args.ica_copy_flags = mode;
	args.ica_timeout = pass.npc_timeout;

	if ((pass.npc_flags & NVME_PASSTHRU_READ) != 0)
		args.ica_dma_flags |= DDI_DMA_READ;
	else if ((pass.npc_flags & NVME_PASSTHRU_WRITE) != 0)
		args.ica_dma_flags |= DDI_DMA_WRITE;

	if (nvme_ioc_cmd(nvme, &pass.npc_common, &args)) {
		pass.npc_cdw0 = args.ica_cdw0;
		if ((pass.npc_impact & NVME_IMPACT_NS) != 0) {
			nvme_rescan_ns(nvme, NVME_NSID_BCAST);
		}
	}
	nvme_mgmt_unlock(nvme);

copyout:
	rv = nvme_passthru_copyout_cmd(&pass, (void *)(uintptr_t)arg,
	    mode);

	return (rv);
}

static int
nvme_ioctl_lock(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_ioctl_lock_t lock;
	const nvme_lock_flags_t all_flags = NVME_LOCK_F_DONT_BLOCK;
	nvme_t *nvme = minor->nm_ctrl;

	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (secpolicy_sys_config(cred_p, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)(uintptr_t)arg, &lock, sizeof (lock),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (lock.nil_ent != NVME_LOCK_E_CTRL &&
	    lock.nil_ent != NVME_LOCK_E_NS) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_BAD_LOCK_ENTITY, 0, 0);
		goto copyout;
	}

	if (lock.nil_level != NVME_LOCK_L_READ &&
	    lock.nil_level != NVME_LOCK_L_WRITE) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_BAD_LOCK_LEVEL, 0, 0);
		goto copyout;
	}

	if ((lock.nil_flags & ~all_flags) != 0) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_BAD_LOCK_FLAGS, 0, 0);
		goto copyout;
	}

	if (!nvme_ioctl_check(minor, &lock.nil_common, &nvme_check_locking)) {
		goto copyout;
	}

	/*
	 * If we're on a namespace, confirm that we're not asking for the
	 * controller.
	 */
	if (lock.nil_common.nioc_nsid != 0 &&
	    lock.nil_ent == NVME_LOCK_E_CTRL) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_NS_CANNOT_LOCK_CTRL, 0, 0);
		goto copyout;
	}

	/*
	 * We've reached the point where we can no longer actually check things
	 * without serializing state. First, we need to check to make sure that
	 * none of our invariants are being broken for locking:
	 *
	 * 1) The caller isn't already blocking for a lock operation to
	 * complete.
	 *
	 * 2) The caller is attempting to grab a lock that they already have.
	 * While there are other rule violations that this might create, we opt
	 * to check this ahead of it so we can have slightly better error
	 * messages for our callers.
	 *
	 * 3) The caller is trying to grab a controller lock, while holding a
	 * namespace lock.
	 *
	 * 4) The caller has a controller write lock and is trying to get a
	 * namespace lock. For now, we disallow this case. Holding a controller
	 * read lock is allowed, but the write lock allows you to operate on all
	 * namespaces anyways. In addition, this simplifies the locking logic;
	 * however, this constraint may be loosened in the future.
	 *
	 * 5) The caller is trying to acquire a second namespace lock when they
	 * already have one.
	 */
	mutex_enter(&nvme->n_minor_mutex);
	if (minor->nm_ctrl_lock.nli_state == NVME_LOCK_STATE_BLOCKED ||
	    minor->nm_ns_lock.nli_state == NVME_LOCK_STATE_BLOCKED) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_LOCK_PENDING, 0, 0);
		mutex_exit(&nvme->n_minor_mutex);
		goto copyout;
	}

	if ((lock.nil_ent == NVME_LOCK_E_CTRL &&
	    minor->nm_ctrl_lock.nli_state == NVME_LOCK_STATE_ACQUIRED) ||
	    (lock.nil_ent == NVME_LOCK_E_NS &&
	    minor->nm_ns_lock.nli_state == NVME_LOCK_STATE_ACQUIRED &&
	    minor->nm_ns_lock.nli_ns->ns_id == lock.nil_common.nioc_nsid)) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_LOCK_ALREADY_HELD, 0, 0);
		mutex_exit(&nvme->n_minor_mutex);
		goto copyout;
	}

	if (lock.nil_ent == NVME_LOCK_E_CTRL &&
	    minor->nm_ns_lock.nli_state != NVME_LOCK_STATE_UNLOCKED) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_LOCK_NO_CTRL_WITH_NS, 0, 0);
		mutex_exit(&nvme->n_minor_mutex);
		goto copyout;
	}

	if (lock.nil_ent == NVME_LOCK_E_NS &&
	    (minor->nm_ctrl_lock.nli_state == NVME_LOCK_STATE_ACQUIRED &&
	    minor->nm_ctrl_lock.nli_curlevel == NVME_LOCK_L_WRITE)) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_LOCK_NO_NS_WITH_CTRL_WRLOCK, 0, 0);
		mutex_exit(&nvme->n_minor_mutex);
		goto copyout;
	}

	if (lock.nil_ent == NVME_LOCK_E_NS &&
	    minor->nm_ns_lock.nli_state != NVME_LOCK_STATE_UNLOCKED) {
		(void) nvme_ioctl_error(&lock.nil_common,
		    NVME_IOCTL_E_LOCK_NO_2ND_NS, 0, 0);
		mutex_exit(&nvme->n_minor_mutex);
		goto copyout;
	}

#ifdef	DEBUG
	/*
	 * This is a big block of sanity checks to make sure that we haven't
	 * allowed anything bad to happen.
	 */
	if (lock.nil_ent == NVME_LOCK_E_NS) {
		ASSERT3P(minor->nm_ns_lock.nli_lock, ==, NULL);
		ASSERT3U(minor->nm_ns_lock.nli_state, ==,
		    NVME_LOCK_STATE_UNLOCKED);
		ASSERT3U(minor->nm_ns_lock.nli_curlevel, ==, 0);
		ASSERT3P(minor->nm_ns_lock.nli_ns, ==, NULL);

		if (minor->nm_ns != NULL) {
			ASSERT3U(minor->nm_ns->ns_id, ==,
			    lock.nil_common.nioc_nsid);
		}

		ASSERT0(list_link_active(&minor->nm_ns_lock.nli_node));
	} else {
		ASSERT3P(minor->nm_ctrl_lock.nli_lock, ==, NULL);
		ASSERT3U(minor->nm_ctrl_lock.nli_state, ==,
		    NVME_LOCK_STATE_UNLOCKED);
		ASSERT3U(minor->nm_ctrl_lock.nli_curlevel, ==, 0);
		ASSERT3P(minor->nm_ns_lock.nli_ns, ==, NULL);
		ASSERT0(list_link_active(&minor->nm_ctrl_lock.nli_node));

		ASSERT3P(minor->nm_ns_lock.nli_lock, ==, NULL);
		ASSERT3U(minor->nm_ns_lock.nli_state, ==,
		    NVME_LOCK_STATE_UNLOCKED);
		ASSERT3U(minor->nm_ns_lock.nli_curlevel, ==, 0);
		ASSERT3P(minor->nm_ns_lock.nli_ns, ==, NULL);
		ASSERT0(list_link_active(&minor->nm_ns_lock.nli_node));
	}
#endif	/* DEBUG */

	/*
	 * At this point we should actually attempt a locking operation.
	 */
	nvme_rwlock(minor, &lock);
	mutex_exit(&nvme->n_minor_mutex);

copyout:
	if (ddi_copyout(&lock, (void *)(uintptr_t)arg, sizeof (lock),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl_unlock(nvme_minor_t *minor, intptr_t arg, int mode,
    cred_t *cred_p)
{
	nvme_ioctl_unlock_t unlock;
	nvme_t *const nvme = minor->nm_ctrl;
	boolean_t is_ctrl;
	nvme_lock_t *lock;
	nvme_minor_lock_info_t *info;

	/*
	 * Note, we explicitly don't check for privileges for unlock. The idea
	 * being that if you have the lock, that's what matters. If you don't
	 * have the lock, it doesn't matter what privileges that you have at
	 * all.
	 */
	if ((mode & FWRITE) == 0)
		return (EBADF);

	if (ddi_copyin((void *)(uintptr_t)arg, &unlock, sizeof (unlock),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (unlock.niu_ent != NVME_LOCK_E_CTRL &&
	    unlock.niu_ent != NVME_LOCK_E_NS) {
		(void) nvme_ioctl_error(&unlock.niu_common,
		    NVME_IOCTL_E_BAD_LOCK_ENTITY, 0, 0);
		goto copyout;
	}

	if (!nvme_ioctl_check(minor, &unlock.niu_common, &nvme_check_locking)) {
		goto copyout;
	}

	/*
	 * If we're on a namespace, confirm that we're not asking for the
	 * controller.
	 */
	if (unlock.niu_common.nioc_nsid != 0 &&
	    unlock.niu_ent == NVME_LOCK_E_CTRL) {
		(void) nvme_ioctl_error(&unlock.niu_common,
		    NVME_IOCTL_E_NS_CANNOT_UNLOCK_CTRL, 0, 0);
		goto copyout;
	}

	mutex_enter(&nvme->n_minor_mutex);
	if (unlock.niu_ent == NVME_LOCK_E_CTRL) {
		if (minor->nm_ctrl_lock.nli_state != NVME_LOCK_STATE_ACQUIRED) {
			mutex_exit(&nvme->n_minor_mutex);
			(void) nvme_ioctl_error(&unlock.niu_common,
			    NVME_IOCTL_E_LOCK_NOT_HELD, 0, 0);
			goto copyout;
		}
	} else {
		if (minor->nm_ns_lock.nli_ns == NULL) {
			mutex_exit(&nvme->n_minor_mutex);
			(void) nvme_ioctl_error(&unlock.niu_common,
			    NVME_IOCTL_E_LOCK_NOT_HELD, 0, 0);
			goto copyout;
		}

		/*
		 * Check that our unlock request corresponds to the namespace ID
		 * that is currently locked. This could happen if we're using
		 * the controller node and it specified a valid, but not locked,
		 * namespace ID.
		 */
		if (minor->nm_ns_lock.nli_ns->ns_id !=
		    unlock.niu_common.nioc_nsid) {
			mutex_exit(&nvme->n_minor_mutex);
			ASSERT3P(minor->nm_ns, ==, NULL);
			(void) nvme_ioctl_error(&unlock.niu_common,
			    NVME_IOCTL_E_LOCK_WRONG_NS, 0, 0);
			goto copyout;
		}

		if (minor->nm_ns_lock.nli_state != NVME_LOCK_STATE_ACQUIRED) {
			mutex_exit(&nvme->n_minor_mutex);
			(void) nvme_ioctl_error(&unlock.niu_common,
			    NVME_IOCTL_E_LOCK_NOT_HELD, 0, 0);
			goto copyout;
		}
	}

	/*
	 * Finally, perform the unlock.
	 */
	is_ctrl = unlock.niu_ent == NVME_LOCK_E_CTRL;
	if (is_ctrl) {
		lock = &nvme->n_lock;
		info = &minor->nm_ctrl_lock;
	} else {
		nvme_namespace_t *ns;
		const uint32_t nsid = unlock.niu_common.nioc_nsid;

		ns = nvme_nsid2ns(nvme, nsid);
		lock = &ns->ns_lock;
		info = &minor->nm_ns_lock;
		VERIFY3P(ns, ==, info->nli_ns);
	}
	nvme_rwunlock(info, lock);
	mutex_exit(&nvme->n_minor_mutex);
	nvme_ioctl_success(&unlock.niu_common);

copyout:
	if (ddi_copyout(&unlock, (void *)(uintptr_t)arg, sizeof (unlock),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
nvme_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *cred_p,
    int *rval_p)
{
#ifndef __lock_lint
	_NOTE(ARGUNUSED(rval_p));
#endif
	int ret;
	nvme_minor_t *minor;
	nvme_t *nvme;

	minor = nvme_minor_find_by_dev(dev);
	if (minor == NULL) {
		return (ENXIO);
	}

	nvme = minor->nm_ctrl;
	if (nvme == NULL)
		return (ENXIO);

	if (IS_DEVCTL(cmd))
		return (ndi_devctl_ioctl(nvme->n_dip, cmd, arg, mode, 0));

	if (nvme->n_dead && (cmd != NVME_IOC_BD_DETACH && cmd !=
	    NVME_IOC_UNLOCK)) {
		if (IS_NVME_IOC(cmd) == 0) {
			return (EIO);
		}

		return (nvme_ioctl_copyout_error(nvme->n_dead_status, arg,
		    mode));
	}

	/*
	 * ioctls that are no longer using the original ioctl structure.
	 */
	switch (cmd) {
	case NVME_IOC_CTRL_INFO:
		ret = nvme_ioctl_ctrl_info(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_IDENTIFY:
		ret = nvme_ioctl_identify(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_GET_LOGPAGE:
		ret = nvme_ioctl_get_logpage(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_GET_FEATURE:
		ret = nvme_ioctl_get_feature(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_BD_DETACH:
		ret = nvme_ioctl_bd_detach(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_BD_ATTACH:
		ret = nvme_ioctl_bd_attach(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_FORMAT:
		ret = nvme_ioctl_format(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_FIRMWARE_DOWNLOAD:
		ret = nvme_ioctl_firmware_download(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_FIRMWARE_COMMIT:
		ret = nvme_ioctl_firmware_commit(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_NS_INFO:
		ret = nvme_ioctl_ns_info(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_PASSTHRU:
		ret = nvme_ioctl_passthru(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_LOCK:
		ret = nvme_ioctl_lock(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_UNLOCK:
		ret = nvme_ioctl_unlock(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_CTRL_DETACH:
		ret = nvme_ioctl_ctrl_detach(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_CTRL_ATTACH:
		ret = nvme_ioctl_ctrl_attach(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_NS_CREATE:
		ret = nvme_ioctl_ns_create(minor, arg, mode, cred_p);
		break;
	case NVME_IOC_NS_DELETE:
		ret = nvme_ioctl_ns_delete(minor, arg, mode, cred_p);
		break;
	default:
		ret = ENOTTY;
		break;
	}

	ASSERT(!nvme_mgmt_lock_held(nvme));
	return (ret);
}

/*
 * DDI UFM Callbacks
 */
static int
nvme_ufm_fill_image(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    ddi_ufm_image_t *img)
{
	nvme_t *nvme = arg;

	if (imgno != 0)
		return (EINVAL);

	ddi_ufm_image_set_desc(img, "Firmware");
	ddi_ufm_image_set_nslots(img, nvme->n_idctl->id_frmw.fw_nslot);

	return (0);
}

/*
 * Fill out firmware slot information for the requested slot.  The firmware
 * slot information is gathered by requesting the Firmware Slot Information log
 * page.  The format of the page is described in section 5.10.1.3.
 *
 * We lazily cache the log page on the first call and then invalidate the cache
 * data after a successful firmware download or firmware commit command.
 * The cached data is protected by a mutex as the state can change
 * asynchronous to this callback.
 */
static int
nvme_ufm_fill_slot(ddi_ufm_handle_t *ufmh, void *arg, uint_t imgno,
    uint_t slotno, ddi_ufm_slot_t *slot)
{
	nvme_t *nvme = arg;
	void *log = NULL;
	size_t bufsize;
	ddi_ufm_attr_t attr = 0;
	char fw_ver[NVME_FWVER_SZ + 1];

	if (imgno > 0 || slotno > (nvme->n_idctl->id_frmw.fw_nslot - 1))
		return (EINVAL);

	mutex_enter(&nvme->n_fwslot_mutex);
	if (nvme->n_fwslot == NULL) {
		if (!nvme_get_logpage_int(nvme, B_TRUE, &log, &bufsize,
		    NVME_LOGPAGE_FWSLOT) ||
		    bufsize != sizeof (nvme_fwslot_log_t)) {
			if (log != NULL)
				kmem_free(log, bufsize);
			mutex_exit(&nvme->n_fwslot_mutex);
			return (EIO);
		}
		nvme->n_fwslot = (nvme_fwslot_log_t *)log;
	}

	/*
	 * NVMe numbers firmware slots starting at 1
	 */
	if (slotno == (nvme->n_fwslot->fw_afi - 1))
		attr |= DDI_UFM_ATTR_ACTIVE;

	if (slotno != 0 || nvme->n_idctl->id_frmw.fw_readonly == 0)
		attr |= DDI_UFM_ATTR_WRITEABLE;

	if (nvme->n_fwslot->fw_frs[slotno][0] == '\0') {
		attr |= DDI_UFM_ATTR_EMPTY;
	} else {
		(void) strncpy(fw_ver, nvme->n_fwslot->fw_frs[slotno],
		    NVME_FWVER_SZ);
		fw_ver[NVME_FWVER_SZ] = '\0';
		ddi_ufm_slot_set_version(slot, fw_ver);
	}
	mutex_exit(&nvme->n_fwslot_mutex);

	ddi_ufm_slot_set_attrs(slot, attr);

	return (0);
}

static int
nvme_ufm_getcaps(ddi_ufm_handle_t *ufmh, void *arg, ddi_ufm_cap_t *caps)
{
	*caps = DDI_UFM_CAP_REPORT;
	return (0);
}

boolean_t
nvme_ctrl_atleast(nvme_t *nvme, const nvme_version_t *min)
{
	return (nvme_vers_atleast(&nvme->n_version, min) ? B_TRUE : B_FALSE);
}
