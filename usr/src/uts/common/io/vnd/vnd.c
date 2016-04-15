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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * vnd - virtual (machine) networking datapath
 *
 * vnd's purpose is to provide a highly performant data path for Layer 2 network
 * traffic and exist side by side an active IP netstack, each servicing
 * different datalinks. vnd provides many of the same capabilities as the
 * current TCP/IP stack does and some specific to layer two. Specifically:
 *
 * 	o Use of the DLD fastpath
 * 	o Packet capture hooks
 * 	o Ability to use hardware capabilities
 * 	o Useful interfaces for handling multiple frames
 *
 * The following image shows where vnd fits into today's networking stack:
 *
 *             +---------+----------+----------+
 *             | libdlpi |  libvnd  | libsocket|
 *             +---------+----------+----------+
 *             |         ·          ·    VFS   |
 *             |   VFS   ·    VFS   +----------+
 *             |         ·          |  sockfs  |
 *             +---------+----------+----------+
 *             |         |    VND   |    IP    |
 *             |         +----------+----------+
 *             |            DLD/DLS            |
 *             +-------------------------------+
 *             |              MAC              |
 *             +-------------------------------+
 *             |             GLDv3             |
 *             +-------------------------------+
 *
 * -----------------------------------------
 * A Tale of Two Devices - DDI Device Basics
 * -----------------------------------------
 *
 * vnd presents itself to userland as a character device; however, it also is a
 * STREAMS device so that it can interface with dld and the rest of the
 * networking stack. Users never interface with the STREAMs devices directly and
 * they are purely an implementation detail of vnd. Opening the STREAMS device
 * require kcred and as such userland cannot interact with it or push it onto
 * the stream head.
 *
 * The main vnd character device, /dev/vnd/ctl, is a self-cloning device. Every
 * clone gets its own minor number; however, minor nodes are not created in the
 * devices tree for these instances. In this state a user may do two different
 * things. They may issue ioctls that affect global state or they may issue
 * ioctls that try to attach it to a given datalink. Once a minor device has
 * been attached to a datalink, all operations on it are scoped to that context,
 * therefore subsequent global operations are not permitted.
 *
 * A given device can be linked into the /devices and /dev name space via a link
 * ioctl. That ioctl causes a minor node to be created in /devices and then it
 * will also appear under /dev/vnd/ due to vnd's sdev plugin. This is similar
 * to, but simpler than, IP's persistence mechanism.
 *
 * ---------------------
 * Binding to a datalink
 * ---------------------
 *
 * Datalinks are backed by the dld (datalink device) and dls (datalink services)
 * drivers. These drivers provide a STREAMS device for datalinks on the system
 * which are exposed through /dev/net. Userland generally manipulates datalinks
 * through libdlpi. When an IP interface is being plumbed up what actually
 * happens is that someone does a dlpi_open(3DLPI) of the underlying datalink
 * and then pushes on the ip STREAMS module with an I_PUSH ioctl.  Modules may
 * then can negotiate with dld and dls to obtain access to various capabilities
 * and fast paths via a series of STREAMS messages.
 *
 * In vnd, we do the same thing, but we leave our STREAMS module as an
 * implementation detail of the system. We don't want users to be able to
 * arbitrarily push vnd STREAMS module onto any stream, so we explicitly require
 * kcred to manipulate it. Thus, when a user issues a request to attach a
 * datalink to a minor instance of the character device, that vnd minor instance
 * itself does a layered open (ldi_open_by_name(9F)) of the specified datalink.
 * vnd does that open using the passed in credentials from the ioctl, not kcred.
 * This ensures that users who doesn't have permissions to open the device
 * cannot. Once that's been opened, we push on the vnd streams module.
 *
 * Once the vnd STREAMS instance has been created for this device, eg. the
 * I_PUSH ioctl returns, we explicitly send a STREAMS ioctl
 * (VND_STRIOC_ASSOCIATE) to associate the vnd STREAMS and character devices.
 * This association begins the STREAM device's initialization. We start up an
 * asynchronous state machine that takes care of all the different aspects of
 * plumbing up the device with dld and dls and enabling the MAC fast path. We
 * need to guarantee to consumers of the character device that by the time their
 * ioctl returns, the data path has been fully initialized.
 *
 * The state progression is fairly linear. There are two general steady states.
 * The first is VND_S_ONLINE, which means that everything is jacked up and good
 * to go. The alternative is VND_S_ZOMBIE, which means that the streams device
 * encountered an error or we have finished tearing it down and the character
 * device can clean it up. The following is our state progression and the
 * meaning of each state:
 *
 *                |
 *                |
 *                V
 *        +---------------+
 *        | VNS_S_INITIAL |                  This is our initial state. Every
 *        +---------------+                  vnd STREAMS device starts here.
 *                |                          While in this state, only dlpi
 *                |                          M_PROTO and M_IOCTL messages can be
 *                |                          sent or received. All STREAMS based
 *                |                          data messages are dropped.
 *                |                          We transition out of this state by
 *                |                          sending a DL_INFO_REQ to obtain
 *                |                          information about the underlying
 *                |                          link.
 *                v
 *        +-----------------+
 *   +--<-| VNS_S_INFO_SENT |                In this state, we verify and
 *   |    +-----------------+                record information about the
 *   |            |                          underlying device. If the device is
 *   |            |                          not suitable, eg. not of type
 *   v            |                          DL_ETHER, then we immediately
 *   |            |                          become a ZOMBIE. To leave this
 *   |            |                          state we request exclusive active
 *   |            |                          access to the device via
 *   v            |                          DL_EXCLUSIVE_REQ.
 *   |            v
 *   |    +----------------------+
 *   +--<-| VNS_S_EXCLUSIVE_SENT |           In this state, we verify whether
 *   |    +----------------------+           or not we were able to obtain
 *   |       |             |                 exclusive access to the device. If
 *   |       |             |                 we were not able to, then we leave,
 *   v       |             |                 as that means that something like
 *   |       |             |                 IP is already plumbed up on top of
 *   |       |             |                 the datalink. We leave this state
 *   |       |             |                 by progressing through to the
 *   |       |             |                 appropriate DLPI primitive, either
 *   v       |             |                 DLPI_ATTACH_REQ or DLPI_BIND_REQ
 *   |       |             |                 depending on the style of the
 *   |       |             |                 datalink.
 *   |       |             v
 *   |       |    +-------------------+
 *   +------ |--<-| VNS_S_ATTACH_SENT |      In this state, we verify we were
 *   |       |    +-------------------+      able to perform a standard DLPI
 *   |       |          |                    attach and if so, go ahead and
 *   v       |          |                    send a DLPI_BIND_REQ.
 *   |       v          v
 *   |    +-------------------+
 *   +--<-| VNS_S_BIND_SENT   |              In this state we see the result of
 *   |    +-------------------+              our attempt to bind to PPA 0 of the
 *   v             |                         underlying device. Because we're
 *   |             |                         trying to be a layer two datapath,
 *   |             |                         the specific attachment point isn't
 *   |             |                         too important as we're going to
 *   v             |                         have to enable promiscuous mode. We
 *   |             |                         transition out of this by sending
 *   |             |                         our first of three promiscuous mode
 *   |             |                         requests.
 *   v             v
 *   |    +------------------------+
 *   +--<-| VNS_S_SAP_PROMISC_SENT |         In this state we verify that we
 *   |    +------------------------+         were able to enable promiscuous
 *   |             |                         mode at the physical level. We
 *   |             |                         transition out of this by enabling
 *   |             |                         multicast and broadcast promiscuous
 *   v             |                         mode.
 *   |             v
 *   |    +--------------------------+
 *   +--<-| VNS_S_MULTI_PROMISC_SENT |       In this state we verify that we
 *   |    +--------------------------+       have enabled DL_PROMISC_MULTI and
 *   v             |                         move onto the second promiscuous
 *   |             |                         mode request.
 *   |             v
 *   |    +----------------------------+
 *   +--<-| VNS_S_RX_ONLY_PROMISC_SENT |     In this state we verify that we
 *   |    +----------------------------+     enabled RX_ONLY promiscuous mode.
 *   |             |                         We specifically do this as we don't
 *   v             |                         want to receive our own traffic
 *   |             |                         that we'll send out. We leave this
 *   |             |                         state by enabling the final flag
 *   |             |                         DL_PROMISC_FIXUPS.
 *   |             v
 *   |    +--------------------------+
 *   +--<-| VNS_S_FIXUP_PROMISC_SENT |       In this state we verify that we
 *   |    +--------------------------+       enabled FIXUP promiscuous mode.
 *   |             |                         We specifically do this as we need
 *   v             |                         to ensure that traffic which is
 *   |             |                         received by being looped back to us
 *   |             |                         correctly has checksums fixed. We
 *   |             |                         leave this state by requesting the
 *   |             |                         dld/dls capabilities that we can
 *   v             |                         process.
 *   |             v
 *   |    +--------------------+
 *   +--<-| VNS_S_CAPAB_Q_SENT |             We loop over the set of
 *   |    +--------------------+             capabilities that dld advertised
 *   |             |                         and enable the ones that currently
 *   v             |                         support for use. See the section
 *   |             |                         later on regarding capabilities
 *   |             |                         for more information. We leave this
 *   |             |                         state by sending an enable request.
 *   v             v
 *   |    +--------------------+
 *   +--<-| VNS_S_CAPAB_E_SENT |             Here we finish all capability
 *   |    +--------------------+             initialization. Once finished, we
 *   |             |                         transition to the next state. If
 *   v             |                         the dld fast path is not available,
 *   |             |                         we become a zombie.
 *   |             v
 *   |    +--------------+
 *   |    | VNS_S_ONLINE |                   This is a vnd STREAMS device's
 *   |    +--------------+                   steady state. It will normally
 *   |             |                         reside in this state while it is in
 *   |             |                         active use. It will only transition
 *   v             |                         to the next state when the STREAMS
 *   |             |                         device is closed by the character
 *   |             |                         device. In this state, all data
 *   |             |                         flows over the dld fast path.
 *   |             v
 *   |    +---------------------+
 *   +--->| VNS_S_SHUTTING_DOWN |            This vnd state takes care of
 *   |    +---------------------+            disabling capabilities and
 *   |             |                         flushing all data. At this point
 *   |             |                         any additional data that we receive
 *   |             |                         will be dropped. We leave this
 *   v             |                         state by trying to remove multicast
 *   |             |                         promiscuity.
 *   |             |
 *   |             v
 *   |   +---------------------------------+
 *   +-->| VNS_S_MULTICAST_PROMISCOFF_SENT | In this state, we check if we have
 *   |   +---------------------------------+ successfully removed multicast
 *   |             |                         promiscuous mode. If we have
 *   |             |                         failed, we still carry on but only
 *   |             |                         warn. We leave this state by trying
 *   |             |                         to disable SAP level promiscuous
 *   |             |                         mode.
 *   |             v
 *   |   +---------------------------+
 *   +-->| VNS_S_SAP_PROMISCOFF_SENT |       In this state, we check if we have
 *   |   +---------------------------+       successfully removed SAP level
 *   |             |                         promiscuous mode. If we have
 *   |             |                         failed, we still carry on but only
 *   |             |                         warn. Note that we don't worry
 *   |             |                         about either of
 *   |             |                         DL_PROMISC_FIXUPS or
 *   |             |                         DL_PROMISC_RX_ONLY. If these are
 *   |             |                         the only two entries left, then we
 *   |             |                         should have anything that MAC is
 *   |             |                         doing for us at this point,
 *   |             |                         therefore it's safe for us to
 *   |             |                         proceed to unbind, which is how we
 *   |             |                         leave this state via a
 *   |             v                         DL_UNBIND_REQ.
 *   |    +-------------------+
 *   +--->| VNS_S_UNBIND_SENT |              Here, we check how the unbind
 *   |    +-------------------+              request went. Regardless of its
 *   |             |                         success, we always transition to
 *   |             |                         a zombie state.
 *   |             v
 *   |    +--------------+
 *   +--->| VNS_S_ZOMBIE |                   In this state, the vnd STREAMS
 *        +--------------+                   device is waiting to finish being
 *                                           reaped. Because we have no more
 *                                           ways to receive data it should be
 *                                           safe to destroy all remaining data
 *                                           structures.
 *
 * If the stream association fails for any reason the state machine reaches
 * VNS_S_ZOMBIE. A more detailed vnd_errno_t will propagate back through the
 * STREAMS ioctl to the character device. That will fail the user ioctl and
 * propagate the vnd_errno_t back to userland. If, on the other hand, the
 * association succeeds, then the vnd STREAMS device will be fully plumbed up
 * and ready to transmit and receive message blocks. Consumers will be able to
 * start using the other cbops(9E) entry points once the attach has fully
 * finished, which will occur after the original user attach ioctl to the
 * character device returns.
 *
 * It's quite important that we end up sending the full series of STREAMS
 * messages when tearing down. While it's tempting to say that we should just
 * rely on the STREAMS device being closed to properly ensure that we have no
 * more additional data, that's not sufficient due to our use of direct
 * callbacks.  DLS does not ensure that by the time we change the direct
 * callback (vnd_mac_input) that all callers to it will have been quiesced.
 * However, it does guarantee that if we disable promiscuous mode ourselves and
 * we turn off the main data path via DL_UNBIND_REQ that it will work.
 * Therefore, we make sure to do this ourselves rather than letting DLS/DLD do
 * it as part of tearing down the STREAMS device. This ensures that we'll
 * quiesce all data before we destroy our data structures and thus we should
 * eliminate the race in changing the data function.
 *
 * --------------------
 * General Architecture
 * --------------------
 *
 * There are several different devices and structures in the vnd driver. There
 * is a per-netstack component, pieces related to the character device that
 * consumers see, the internal STREAMS device state, and the data queues
 * themselves. The following ASCII art picture describes their relationships and
 * some of the major pieces of data that contain them. These are not exhaustive,
 * e.g. synchronization primitives are left out.
 *
 *  +----------------+     +-----------------+
 *  | global         |     | global          |
 *  | device list    |     | netstack list   |
 *  | vnd_dev_list   |     | vnd_nsd_list    |
 *  +----------------+     +-----------------+
 *      |                    |
 *      |                    v
 *      |    +-------------------+      +-------------------+
 *      |    | per-netstack data | ---> | per-netstack data | --> ...
 *      |    | vnd_pnsd_t        |      | vnd_pnsd_t        |
 *      |    |                   |      +-------------------+
 *      |    |                   |
 *      |    | nestackid_t    ---+----> Netstack ID
 *      |    | vnd_pnsd_flags_t -+----> Status flags
 *      |    | zoneid_t       ---+----> Zone ID for this netstack
 *      |    | hook_family_t  ---+----> VND IPv4 Hooks
 *      |    | hook_family_t  ---+----> VND IPv6 Hooks
 *      |    | list_t ----+      |
 *      |    +------------+------+
 *      |                 |
 *      |                 v
 *      |           +------------------+       +------------------+
 *      |           | character device |  ---> | character device | -> ...
 *      +---------->| vnd_dev_t        |       | vnd_dev_t        |
 *                  |                  |       +------------------+
 *                  |                  |
 *                  | minor_t       ---+--> device minor number
 *                  | ldi_handle_t  ---+--> handle to /dev/net/%datalink
 *                  | vnd_dev_flags_t -+--> device flags, non blocking, etc.
 *                  | char[]        ---+--> name if linked
 *                  | vnd_str_t * -+   |
 *                  +--------------+---+
 *                                 |
 *                                 v
 *          +-------------------------+
 *          | STREAMS device          |
 *          | vnd_str_t               |
 *          |                         |
 *          | vnd_str_state_t      ---+---> State machine state
 *          | gsqueue_t *          ---+---> mblk_t Serialization queue
 *          | vnd_str_stat_t       ---+---> per-device kstats
 *          | vnd_str_capab_t      ---+----------------------------+
 *          | vnd_data_queue_t ---+   |                            |
 *          | vnd_data_queue_t -+ |   |                            v
 *          +-------------------+-+---+                  +---------------------+
 *                              | |                      | Stream capabilities |
 *                              | |                      | vnd_str_capab_t     |
 *                              | |                      |                     |
 *                              | |    supported caps <--+-- vnd_capab_flags_t |
 *                              | |    dld cap handle <--+-- void *            |
 *                              | |    direct tx func <--+-- vnd_dld_tx_t      |
 *                              | |                      +---------------------+
 *                              | |
 *             +----------------+ +-------------+
 *             |                                |
 *             v                                v
 *  +-------------------+                  +-------------------+
 *  | Read data queue   |                  | Write data queue  |
 *  | vnd_data_queue_t  |                  | vnd_data_queue_t  |
 *  |                   |                  |                   |
 *  | size_t        ----+--> Current size  | size_t        ----+--> Current size
 *  | size_t        ----+--> Max size      | size_t        ----+--> Max size
 *  | mblk_t *      ----+--> Queue head    | mblk_t *      ----+--> Queue head
 *  | mblk_t *      ----+--> Queue tail    | mblk_t *      ----+--> Queue tail
 *  +-------------------+                  +-------------------+
 *
 *
 * Globally, we maintain two lists. One list contains all of the character
 * device soft states. The other maintains a list of all our netstack soft
 * states. Each netstack maintains a list of active devices that have been
 * associated with a datalink in its netstack.
 *
 * Recall that a given minor instance of the character device exists in one of
 * two modes. It can either be a cloned open of /dev/vnd/ctl, the control node,
 * or it can be associated with a given datalink. When minor instances are in
 * the former state, they do not exist in a given vnd_pnsd_t's list of devices.
 * As part of attaching to a datalink, the given vnd_dev_t will be inserted into
 * the appropriate vnd_pnsd_t. In addition, this will cause a STREAMS device, a
 * vnd_str_t, to be created and associated to a vnd_dev_t.
 *
 * The character device, and its vnd_dev_t, is the interface to the rest of the
 * system. The vnd_dev_t keeps track of various aspects like whether various
 * operations, such as read, write and the frameio ioctls, are considered
 * blocking or non-blocking in the O_NONBLOCK sense. It also is responsible for
 * keeping track of things like the name of the device, if any, in /dev. The
 * vnd_str_t, on the other hand manages aspects like buffer sizes and the actual
 * data queues. However, ioctls that manipulate these properties all go through
 * the vnd_dev_t to its associated vnd_str_t.
 *
 * Each of the STREAMS devices, the vnd_str_t, maintains two data queues. One
 * for frames to transmit (write queue) and one for frames received (read
 * queue). These data queues have a maximum size and attempting to add data
 * beyond that maximum size will result in data being dropped. The sizes are
 * configurable via ioctls VND_IOC_SETTXBUF, VND_IOC_SETRXBUF. Data either sits
 * in those buffers or has a reservation in those buffers while they are in vnd
 * and waiting to be consumed by the user or by mac.
 *
 * Finally, the vnd_str_t also has a vnd_str_capab_t which we use to manage the
 * available, negotiated, and currently active features.
 *
 * ----------------------
 * Data Path and gsqueues
 * ----------------------
 *
 * There's a lot of plumbing in vnd to get to the point where we can send data,
 * but vnd's bread and butter is the data path, so it's worth diving into it in
 * more detail. Data enters and exits the system from two ends.
 *
 * The first end is the vnd consumer. This comes in the form of read and write
 * system calls as well as the frame I/O ioctls. The read and write system calls
 * operate on a single frame at a time. Think of a frame as a single message
 * that has come in off the wire, which may itself comprise multiple mblk_t's
 * linked together in the kernel. readv(2) and writev(2) have the same
 * limitations as read(2) and write(2). We enforce this as the system is
 * required to fill up every uio(9S) buffer before moving onto the next one.
 * This means that if you have a MTU sized buffer and two frames come in which
 * are less than half of the MTU they must fill up the given iovec. Even if we
 * didn't want to do this, we have no way of informing the supplier of the
 * iovecs that they were only partially filled or where one frame ends and
 * another begins.  That's life, as such we have frame I/O which solves this
 * problem. It allows for multiple frames to be consumed as well as for frames
 * to be broken down into multiple vector components.
 *
 * The second end is the mac direct calls. As part of negotiating capabilities
 * via dld, we give mac a function of ours to call when packets are received
 * [vnd_mac_input()] and a callback to indicate that flow has been restored
 * [vnd_mac_flow_control()]. In turn, we also get a function pointer that we can
 * transmit data with. As part of the contract with mac, mac is allowed to flow
 * control us by returning a cookie to the transmit function. When that happens,
 * all outbound traffic is halted until our callback function is called and we
 * can schedule drains.
 *
 * It's worth looking at these in further detail. We'll start with the rx path.
 *
 *
 *                                |
 *                                * . . . packets from gld
 *                                |
 *                                v
 *                         +-------------+
 *                         |     mac     |
 *                         +-------------+
 *                                |
 *                                v
 *                         +-------------+
 *                         |     dld     |
 *                         +-------------+
 *                                |
 *                                * . . . dld direct callback
 *                                |
 *                                v
 *                        +---------------+
 *                        | vnd_mac_input |
 *                        +---------------+
 *                                |
 *                                v
 * +---------+             +-------------+
 * | dropped |<--*---------|  vnd_hooks  |
 * |   by    |   .         +-------------+
 * |  hooks  |   . drop probe     |
 * +---------+     kstat bump     * . . . Do we have free
 *                                |         buffer space?
 *                                |
 *                          no .  |      . yes
 *                             .  +      .
 *                         +---*--+------*-------+
 *                         |                     |
 *                         * . . drop probe      * . . recv probe
 *                         |     kstat bump      |     kstat bump
 *                         v                     |
 *                      +---------+              * . . fire pollin
 *                      | freemsg |              v
 *                      +---------+   +-----------------------+
 *                                    | vnd_str_t`vns_dq_read |
 *                                    +-----------------------+
 *                                             ^ ^
 *                             +----------+    | |     +---------+
 *                             | read(9E) |-->-+ +--<--| frameio |
 *                             +----------+            +---------+
 *
 * The rx path is rather linear. Packets come into us from mac. We always run
 * them through the various hooks, and if they come out of that, we inspect the
 * read data queue. If there is not enough space for a packet, we drop it.
 * Otherwise, we append it to the data queue, and fire read notifications
 * targetting anyone polling or doing blocking I/O on this device. Those
 * consumers then drain the head of the data queue.
 *
 * The tx path is more complicated due to mac flow control. After any call into
 * mac, we may have to potentially suspend writes and buffer data for an
 * arbitrary amount of time. As such, we need to carefully track the total
 * amount of outstanding data so that we don't waste kernel memory. This is
 * further complicated by the fact that mac will asynchronously tell us when our
 * flow has been resumed.
 *
 * For data to be able to enter the system, it needs to be able to take a
 * reservation from the write data queue. Once the reservation has been
 * obtained, we enter the gsqueue so that we can actually append it. We use
 * gsqueues (serialization queues) to ensure that packets are manipulated in
 * order as we deal with the draining and appending packets. We also leverage
 * its worker thread to help us do draining after mac has restorted our flow.
 *
 * The following image describes the flow:
 *
 * +-----------+   +--------------+       +-------------------------+   +------+
 * | write(9E) |-->| Space in the |--*--->| gsqueue_enter_one()     |-->| Done |
 * | frameio   |   | write queue? |  .    | +->vnd_squeue_tx_append |   +------+
 * +-----------+   +--------------+  .    +-------------------------+
 *                         |   ^     .
 *                         |   |     . reserve space           from gsqueue
 *                         |   |                                   |
 *            queue  . . . *   |       space                       v
 *             full        |   * . . . avail          +------------------------+
 *                         v   |                      | vnd_squeue_tx_append() |
 * +--------+          +------------+                 +------------------------+
 * | EAGAIN |<--*------| Non-block? |<-+                           |
 * +--------+   .      +------------+  |                           v
 *              . yes             v    |     wait          +--------------+
 *                          no . .*    * . . for           | append chain |
 *                                +----+     space         | to outgoing  |
 *                                                         |  mblk chain  |
 *   from gsqueue                                          +--------------+
 *       |                                                        |
 *       |      +-------------------------------------------------+
 *       |      |
 *       |      |                            yes . . .
 *       v      v                                    .
 *  +-----------------------+    +--------------+    .     +------+
 *  | vnd_squeue_tx_drain() |--->| mac blocked? |----*---->| Done |
 *  +-----------------------+    +--------------+          +------+
 *                                       |                     |
 *     +---------------------------------|---------------------+
 *     |                                 |           tx        |
 *     |                          no . . *           queue . . *
 *     | flow controlled .               |           empty     * . fire pollout
 *     |                 .               v                     |   if mblk_t's
 *   +-------------+     .      +---------------------+        |   sent
 *   | set blocked |<----*------| vnd_squeue_tx_one() |--------^-------+
 *   | flags       |            +---------------------+                |
 *   +-------------+    More data       |    |      |      More data   |
 *                      and limit       ^    v      * . .  and limit   ^
 *                      not reached . . *    |      |      reached     |
 *                                      +----+      |                  |
 *                                                  v                  |
 *   +----------+          +-------------+    +---------------------------+
 *   | mac flow |--------->| remove mac  |--->| gsqueue_enter_one() with  |
 *   | control  |          | block flags |    | vnd_squeue_tx_drain() and |
 *   | callback |          +-------------+    | GSQUEUE_FILL flag, iff    |
 *   +----------+                             | not already scheduled     |
 *                                            +---------------------------+
 *
 * The final path taken for a given write(9E)/frameio ioctl depends on whether
 * or not the vnd_dev_t is non-blocking. That controls the initial path of
 * trying to take a reservation in write data queue. If the device is in
 * non-blocking mode, we'll return EAGAIN when there is not enough space
 * available, otherwise, the calling thread blocks on the data queue.
 *
 * Today when we call into vnd_squeue_tx_drain() we will not try to drain the
 * entire queue, as that could be quite large and we don't want to necessarily
 * keep the thread that's doing the drain until it's been finished. Not only
 * could more data be coming in, but the draining thread could be a userland
 * thread that has more work to do. We have two limits today. There is an upper
 * bound on the total amount of data and the total number of mblk_t chains. If
 * we hit either limit, then we will schedule another drain in the gsqueue and
 * go from there.
 *
 * It's worth taking some time to describe how we interact with gsqueues. vnd
 * has a gsqueue_set_t for itself. It's important that it has its own set, as
 * the profile of work that vnd does is different from other sub-systems in the
 * kernel. When we open a STREAMS device in vnd_s_open, we get a random gsqueue.
 * Unlike TCP/IP which uses an gsqueue for per TCP connection, we end up
 * maintaining one for a given device. Because of that, we want to use a
 * pseudo-random one to try and spread out the load, and picking one at random
 * is likely to be just as good as any fancy algorithm we might come up with,
 * especially as any two devices could have radically different transmit
 * profiles.
 *
 * While some of the write path may seem complicated, it does allow us to
 * maintain an important property. Once we have acknowledged a write(9E) or
 * frameio ioctl, we will not drop the packet, excepting something like ipf via
 * the firewall hooks.
 *
 * There is one other source of flow control that can exist in the system which
 * is in the form of a barrier. The barrier is an internal mechanism used for
 * ensuring that an gsqueue is drained for a given device. We use this as part
 * of tearing down. Specifically we disable the write path so nothing new can be
 * inserted into the gsqueue and then insert a barrier block. Once the barrier
 * block comes out of the gsqueue, then we know nothing else in the gsqueue that
 * could refer to the vnd_str_t, being destroyed, exists.
 *
 * ---------------------
 * vnd, zones, netstacks
 * ---------------------
 *
 * vnd devices are scoped to datalinks and datalinks are scoped to a netstack.
 * Because of that, vnd is also a netstack module. It registers with the
 * netstack sub-system and receives callbacks every time a netstack is created,
 * being shutdown, and destroyed. The netstack callbacks drive the creation and
 * destruction of the vnd_pnsd_t structures.
 *
 * Recall from the earlier architecture diagrams that every vnd device is scoped
 * to a netstack and known about by a given vnd_pnsd_t. When that netstack is
 * torn down, we also tear down any vnd devices that are hanging around. When
 * the netstack is torn down, we know that any zones that are scoped to that
 * netstack are being shut down and have no processes remaining. This is going
 * to be the case whether they are shared or exclusive stack zones. We have to
 * perform a careful dance.
 *
 * There are two different callbacks that happen on tear down, the first is a
 * shutdown callback, the second is a destroy callback. When the shutdown
 * callback is fired we need to prepare for the netstack to go away and ensure
 * that nothing can continue to persist itself.
 *
 * More specifically, when we get notice of a stack being shutdown we first
 * remove the netstack from the global netstack list to ensure that no one new
 * can come in and find the netstack and get a reference to it. After that, we
 * notify the neti hooks that they're going away. Once that's all done, we get
 * to the heart of the matter.
 *
 * When shutting down there could be any number of outstanding contexts that
 * have a reference on the vnd_pnsd_t and on the individual links. However, we
 * know that no one new will be able to find the vnd_pnsd_t. To account for
 * things that have existing references we mark the vnd_pnsd_t`vpnd_flags with
 * VND_NS_CONDEMNED. This is checked by code paths that wish to append a device
 * to the netstack's list. If this is set, then they must not append to it.
 * Once this is set, we know that the netstack's list of devices can never grow,
 * only shrink.
 *
 * Next, for each device we tag it with VND_D_ZONE_DYING. This indicates that
 * the container for the device is being destroyed and that we should not allow
 * additional references to the device to be created, whether via open, or
 * linking. The presence of this bit also allows things like the list ioctl and
 * sdev to know not to consider its existence. At the conclusion of this being
 * set, we know that no one else should be able to obtain a new reference to the
 * device.
 *
 * Once that has been set for all devices, we go through and remove any existing
 * links that have been established in sdev. Because doing that may cause the
 * final reference for the device to be dropped, which still has a reference to
 * the netstack, we have to restart our walk due to dropped locks. We know that
 * this walk will eventually complete because the device cannot be relinked and
 * no new devices will be attached in this netstack due to VND_NS_CONDEMNED.
 * Once that's finished, the shutdown callback returns.
 *
 * When we reach the destroy callback, we simply wait for references on the
 * netstack to disappear. Because the zone has been shut down, all processes in
 * it that have open references have been terminated and reaped. Any threads
 * that are newly trying to reference it will fail. However, there is one thing
 * that can halt this that we have no control over, which is the global zone
 * holding open a reference to the device. In this case the zone halt will hang
 * in vnd_stack_destroy. Once the last references is dropped we finish destroy
 * the netinfo hooks and free the vnd_pnsd_t.
 *
 * ----
 * sdev
 * ----
 *
 * vnd registers a sdev plugin which allows it to dynamically fill out /dev/vnd
 * for both the global and non-global zones. In any given zone we always supply
 * a control node via /dev/vnd/ctl. This is the self-cloning node. Each zone
 * will also have an entry per-link in that zone under /dev/vnd/%datalink, eg.
 * if a link was named net0, there would be a /dev/vnd/net0. The global zone can
 * also see every link for every zone, ala /dev/net, under
 * /dev/vnd/%zonename/%datalink, eg. if a zone named 'turin' had a vnd device
 * named net0, the global zone would have /dev/vnd/turin/net0.
 *
 * The sdev plugin has three interfaces that it supplies back to sdev. One is to
 * validate that a given node is still valid. The next is a callback from sdev
 * to say that it is no longer using the node. The third and final one is from
 * sdev where it asks us to fill a directory. All of the heavy lifting is done
 * in directory filling and in valiation. We opt not to maintain a reference on
 * the device while there is an sdev node present. This makes the removal of
 * nodes much simpler and most of the possible failure modes shouldn't cause any
 * real problems. For example, the open path has to handle both dev_t's which no
 * longer exist and which are no longer linked.
 *
 * -----
 * hooks
 * -----
 *
 * Like IP, vnd sends all L3 packets through its firewall hooks. Currently vnd
 * provides these for L3 IP and IPv6 traffic. Each netstack provides these hooks
 * in a minimal fashion. While we will allow traffic to be filtered through the
 * hooks, we do not provide means for packet injection or additional inspection
 * at this time. There are a total of four different events created:
 *
 *   o IPv4 physical in
 *   o IPv4 physical out
 *   o IPv6 physical in
 *   o IPv6 physical out
 *
 * ---------------
 * Synchronization
 * ---------------
 *
 * To make our synchronization simpler, we've put more effort into making the
 * metadata/setup paths do more work. That work allows the data paths to make
 * assumptions around synchronization that simplify the general case. Each major
 * structure, the vnd_pnsd_t, vnd_dev_t, vnd_str_t, and vnd_data_queue_t is
 * annotated with the protection that its members receives.  The following
 * annotations are used:
 *
 * 	A	Atomics; these values are only modified using atomics values.
 *		Currently this only applies to kstat values.
 * 	E	Existence; no lock is needed to access this member, it does not
 *		change while the structure is valid.
 * 	GL	Global Lock; these members are protected by the global
 *		vnd_dev_lock.
 * 	L	Locked; access to the member is controlled by a lock that is in
 * 		the structure.
 * 	NSL	netstack lock; this member is protected by the containing
 * 		netstack. This only applies to the vnd_dev_t`vdd_nslink.
 *	X	This member is special, and is discussed in this section.
 *
 * In addition to locking, we also have reference counts on the vnd_dev_t and
 * the vnd_pnsd_t. The reference counts describe the lifetimes of the structure.
 * With rare exception, once a reference count is decremented, the consumer
 * should not assume that the data is valid any more. The only exception to this
 * is the case where we're removing an extant reference count from a link into
 * /devices or /dev. Reference counts are obtained on these structures as a part
 * of looking them up.
 *
 * 	# Global Lock Ordering
 * 	######################
 *
 * The following is the order that you must take locks in vnd:
 *
 * 1) vnd`vnd_dev_lock
 * 2) vnd_pnsd_t`vpnd_lock
 * 3) vnd_dev_t`vnd_lock
 * 4) vnd_str_t`vns_lock
 * 5) vnd_data_queue_t`vdq_lock
 *
 * One must adhere to the following rules:
 *
 *   o You must acquire a lower numbered lock before a high numbered lock.
 *   o It is NOT legal to hold two locks of the same level concurrently, eg. you
 *     can not hold two different vnd_dev_t's vnd_lock at the same time.
 *   o You may release locks in any order.
 *   o If you release a lock, you must honor the locking rules before acquiring
 *     it again.
 *   o You should not hold any locks when calling any of the rele functions.
 *
 * 	# Special Considerations
 * 	########################
 *
 * While most of the locking is what's expected, it's worth going into the
 * special nature that a few members hold.  Today, only two structures have
 * special considerations: the vnd_dev_t and the vnd_str_t. All members with
 * special considerations have an additional annotation that describes how you
 * should interact with it.
 *
 * vnd_dev_t: The vdd_nsd and vdd_cr are only valid when the minor node is
 * attached or in the process of attaching. If the code path that goes through
 * requires an attached vnd_dev_t, eg. the data path and tear down path, then it
 * is always legal to dereference that member without a lock held. When they are
 * added to the system, they should be done under the vdd_lock and done as part
 * of setting the VND_D_ATTACH_INFLIGHT flag. These should not change during the
 * lifetime of the vnd_dev_t.
 *
 * vnd_dev_t: The vdd_ldih is similar to the vdd_nsd and vdd_cr, except that it
 * always exists as it is a part of the structure. The only time that it's valid
 * to be using it is during the attach path with the VND_D_ATTACH_INFLIGHT flag
 * set or during tear down. Outside of those paths which are naturally
 * serialized, there is no explicit locking around the member.
 *
 * vnd_str_t: The vns_dev and vns_nsd work in similar ways. They are not
 * initially set as part of creating the structure, but are set as part of
 * responding to the association ioctl. Anything in the data path or metadata
 * path that requires association may assume that they exist, as we do not kick
 * off the state machine until they're set.
 *
 * vnd_str_t: The vns_drainblk and vns_barrierblk are similarly special. The
 * members are designed to be used as part of various operations with the
 * gsqueues. A lock isn't needed to use them, but to work with them, the
 * appropriate flag in the vnd_str_t`vns_flags must have been set by the current
 * thread. Otherwise, it is always fair game to refer to their addresses. Their
 * contents are ignored by vnd, but some members are manipulated by the gsqueue
 * subsystem.
 */

#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/ddi.h>
#include <sys/ethernet.h>
#include <sys/stropts.h>
#include <sys/sunddi.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/ksynch.h>
#include <sys/taskq_impl.h>
#include <sys/sdt.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/dlpi.h>
#include <sys/cred.h>
#include <sys/id_space.h>
#include <sys/list.h>
#include <sys/ctype.h>
#include <sys/policy.h>
#include <sys/sunldi.h>
#include <sys/cred.h>
#include <sys/strsubr.h>
#include <sys/poll.h>
#include <sys/neti.h>
#include <sys/hook.h>
#include <sys/hook_event.h>
#include <sys/vlan.h>
#include <sys/dld.h>
#include <sys/mac_client.h>
#include <sys/netstack.h>
#include <sys/fs/sdev_plugin.h>
#include <sys/kstat.h>
#include <sys/atomic.h>
#include <sys/disp.h>
#include <sys/random.h>
#include <sys/gsqueue.h>

#include <inet/ip.h>
#include <inet/ip6.h>

#include <sys/vnd.h>

/*
 * Globals
 */
static dev_info_t *vnd_dip;
static taskq_t *vnd_taskq;
static kmem_cache_t *vnd_str_cache;
static kmem_cache_t *vnd_dev_cache;
static kmem_cache_t *vnd_pnsd_cache;
static id_space_t *vnd_minors;
static int vnd_list_init = 0;
static sdev_plugin_hdl_t vnd_sdev_hdl;
static gsqueue_set_t *vnd_sqset;

static kmutex_t vnd_dev_lock;
static list_t vnd_dev_list;	/* Protected by the vnd_dev_lock */
static list_t vnd_nsd_list;	/* Protected by the vnd_dev_lock */

/*
 * STREAMs ioctls
 *
 * The STREAMs ioctls are internal to vnd. No one should be seeing them, as such
 * they aren't a part of the header file.
 */
#define	VND_STRIOC	(('v' << 24) | ('n' << 16) | ('d' << 8) | 0x80)

/*
 * Private ioctl to associate a given streams instance with a minor instance of
 * the character device.
 */
#define	VND_STRIOC_ASSOCIATE	(VND_STRIOC | 0x1)

typedef struct vnd_strioc_associate {
	minor_t	vsa_minor;	/* minor device node */
	netstackid_t vsa_nsid;	/* netstack id */
	vnd_errno_t vsa_errno;	/* errno */
} vnd_strioc_associate_t;

typedef enum vnd_strioc_state {
	VSS_UNKNOWN = 0,
	VSS_COPYIN = 1,
	VSS_COPYOUT = 2,
} vnd_strioc_state_t;

typedef struct vnd_strioc {
	vnd_strioc_state_t vs_state;
	caddr_t vs_addr;
} vnd_strioc_t;

/*
 * VND SQUEUE TAGS, start at 0x42 so we don't overlap with extent tags. Though
 * really, overlap is at the end of the day, inevitable.
 */
#define	VND_SQUEUE_TAG_TX_DRAIN		0x42
#define	VND_SQUEUE_TAG_MAC_FLOW_CONTROL	0x43
#define	VND_SQUEUE_TAG_VND_WRITE	0x44
#define	VND_SQUEUE_TAG_ND_FRAMEIO_WRITE	0x45
#define	VND_SQUEUE_TAG_STRBARRIER	0x46

/*
 * vnd reserved names. These are names which are reserved by vnd and thus
 * shouldn't be used by some external program.
 */
static char *vnd_reserved_names[] = {
	"ctl",
	"zone",
	NULL
};

/*
 * vnd's DTrace probe macros
 *
 * DTRACE_VND* are all for a stable provider. We also have an unstable internal
 * set of probes for reference count manipulation.
 */
#define	DTRACE_VND3(name, type1, arg1, type2, arg2, type3, arg3) \
    DTRACE_PROBE3(__vnd_##name, type1, arg1, type2, arg2, type3, arg3);

#define	DTRACE_VND4(name, type1, arg1, type2, arg2, type3, arg3, type4, arg4) \
    DTRACE_PROBE4(__vnd_##name, type1, arg1, type2, arg2, type3, arg3, \
	type4, arg4);

#define	DTRACE_VND5(name, type1, arg1, type2, arg2, type3, arg3,	\
    type4, arg4, type5, arg5)						\
    DTRACE_PROBE5(__vnd_##name, type1, arg1, type2, arg2, type3, arg3,	\
	type4, arg4, type5, arg5);

#define	DTRACE_VND_REFINC(vdp) \
    DTRACE_PROBE2(vnd__ref__inc, vnd_dev_t *, vdp, int, vdp->vdd_ref);
#define	DTRACE_VND_REFDEC(vdp) \
    DTRACE_PROBE2(vnd__ref__dec, vnd_dev_t *, vdp, int, vdp->vdd_ref);


/*
 * Tunables
 */
size_t vnd_vdq_default_size = 1024 * 64;	/* 64 KB */
size_t vnd_vdq_hard_max = 1024 * 1024 * 4;	/* 4 MB */

/*
 * These numbers are designed as per-device tunables that are applied when a new
 * vnd device is attached. They're a rough stab at what may be a reasonable
 * amount of work to do in one burst in an squeue.
 */
size_t vnd_flush_burst_size = 1520 * 10;	/* 10 1500 MTU packets */
size_t vnd_flush_nburst = 10;			/* 10 frames */

/*
 * Constants related to our sdev plugins
 */
#define	VND_SDEV_NAME	"vnd"
#define	VND_SDEV_ROOT	"/dev/vnd"
#define	VND_SDEV_ZROOT	"/dev/vnd/zone"

/*
 * Statistic macros
 */
#define	VND_STAT_INC(vsp, field, val) \
    atomic_add_64(&(vsp)->vns_ksdata.field.value.ui64, val)
#define	VND_LATENCY_1MS		1000000
#define	VND_LATENCY_10MS	10000000
#define	VND_LATENCY_100MS	100000000
#define	VND_LATENCY_1S		1000000000
#define	VND_LATENCY_10S		10000000000

/*
 * Constants for vnd hooks
 */
static uint8_t vnd_bcast_addr[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
#define	IPV4_MCAST_LEN	3
static uint8_t vnd_ipv4_mcast[3] = { 0x01, 0x00, 0x5E };
#define	IPV6_MCAST_LEN	2
static uint8_t vnd_ipv6_mcast[2] = { 0x33, 0x33 };

/*
 * vnd internal data structures and types
 */

struct vnd_str;
struct vnd_dev;
struct vnd_pnsd;

/*
 * As part of opening the device stream we need to properly communicate with our
 * underlying stream. This is a bit of an asynchronous dance and we need to
 * properly work with dld to get everything set up. We have to initiate the
 * conversation with dld and as such we keep track of our state here.
 */
typedef enum vnd_str_state {
	VNS_S_INITIAL = 0,
	VNS_S_INFO_SENT,
	VNS_S_EXCLUSIVE_SENT,
	VNS_S_ATTACH_SENT,
	VNS_S_BIND_SENT,
	VNS_S_SAP_PROMISC_SENT,
	VNS_S_MULTI_PROMISC_SENT,
	VNS_S_RX_ONLY_PROMISC_SENT,
	VNS_S_FIXUP_PROMISC_SENT,
	VNS_S_CAPAB_Q_SENT,
	VNS_S_CAPAB_E_SENT,
	VNS_S_ONLINE,
	VNS_S_SHUTTING_DOWN,
	VNS_S_MULTICAST_PROMISCOFF_SENT,
	VNS_S_SAP_PROMISCOFF_SENT,
	VNS_S_UNBIND_SENT,
	VNS_S_ZOMBIE
} vnd_str_state_t;

typedef enum vnd_str_flags {
	VNS_F_NEED_ZONE = 0x1,
	VNS_F_TASKQ_DISPATCHED = 0x2,
	VNS_F_CONDEMNED = 0x4,
	VNS_F_FLOW_CONTROLLED = 0x8,
	VNS_F_DRAIN_SCHEDULED = 0x10,
	VNS_F_BARRIER = 0x20,
	VNS_F_BARRIER_DONE = 0x40
} vnd_str_flags_t;

typedef enum vnd_capab_flags {
	VNS_C_HCKSUM = 0x1,
	VNS_C_DLD = 0x2,
	VNS_C_DIRECT = 0x4,
	VNS_C_HCKSUM_BADVERS = 0x8
} vnd_capab_flags_t;

/*
 * Definitions to interact with direct callbacks
 */
typedef void (*vnd_rx_t)(struct vnd_str *, mac_resource_t *, mblk_t *,
    mac_header_info_t *);
typedef uintptr_t vnd_mac_cookie_t;
/* DLD Direct capability function */
typedef int (*vnd_dld_cap_t)(void *, uint_t, void *, uint_t);
/* DLD Direct tx function */
typedef vnd_mac_cookie_t (*vnd_dld_tx_t)(void *, mblk_t *, uint64_t, uint16_t);
/* DLD Direct function to set flow control callback */
typedef void *(*vnd_dld_set_fcb_t)(void *, void (*)(void *, vnd_mac_cookie_t),
    void *);
/* DLD Direct function to see if flow controlled still */
typedef int (*vnd_dld_is_fc_t)(void *, vnd_mac_cookie_t);

/*
 * The vnd_str_capab_t is always protected by the vnd_str_t it's a member of.
 */
typedef struct vnd_str_capab {
	vnd_capab_flags_t vsc_flags;
	t_uscalar_t vsc_hcksum_opts;
	vnd_dld_cap_t vsc_capab_f;
	void *vsc_capab_hdl;
	vnd_dld_tx_t vsc_tx_f;
	void *vsc_tx_hdl;
	vnd_dld_set_fcb_t vsc_set_fcb_f;
	void *vsc_set_fcb_hdl;
	vnd_dld_is_fc_t vsc_is_fc_f;
	void *vsc_is_fc_hdl;
	vnd_mac_cookie_t vsc_fc_cookie;
	void *vsc_tx_fc_hdl;
} vnd_str_capab_t;

/*
 * The vnd_data_queue is a simple construct for storing a series of messages in
 * a queue.
 *
 * See synchronization section of the big theory statement for member
 * annotations.
 */
typedef struct vnd_data_queue {
	struct vnd_str *vdq_vns;	/* E */
	kmutex_t vdq_lock;
	kcondvar_t vdq_ready;		/* Uses vdq_lock */
	ssize_t vdq_max;		/* L */
	ssize_t vdq_cur;		/* L */
	mblk_t *vdq_head;		/* L */
	mblk_t *vdq_tail;		/* L */
} vnd_data_queue_t;

typedef struct vnd_str_stat {
	kstat_named_t	vks_rbytes;
	kstat_named_t	vks_rpackets;
	kstat_named_t	vks_obytes;
	kstat_named_t	vks_opackets;
	kstat_named_t	vks_nhookindrops;
	kstat_named_t	vks_nhookoutdrops;
	kstat_named_t	vks_ndlpidrops;
	kstat_named_t	vks_ndataindrops;
	kstat_named_t	vks_ndataoutdrops;
	kstat_named_t	vks_tdrops;
	kstat_named_t	vks_linkname;
	kstat_named_t	vks_zonename;
	kstat_named_t	vks_nmacflow;
	kstat_named_t	vks_tmacflow;
	kstat_named_t	vks_mac_flow_1ms;
	kstat_named_t	vks_mac_flow_10ms;
	kstat_named_t	vks_mac_flow_100ms;
	kstat_named_t	vks_mac_flow_1s;
	kstat_named_t	vks_mac_flow_10s;
} vnd_str_stat_t;

/*
 * vnd stream structure
 *
 * See synchronization section of the big theory statement for member
 * annotations.
 */
typedef struct vnd_str {
	kmutex_t 	vns_lock;
	kcondvar_t	vns_cancelcv;		/* Uses vns_lock */
	kcondvar_t	vns_barriercv;		/* Uses vns_lock */
	kcondvar_t	vns_stcv;		/* Uses vns_lock */
	vnd_str_state_t	vns_state;		/* L */
	vnd_str_state_t	vns_laststate;		/* L */
	vnd_errno_t	vns_errno;		/* L */
	vnd_str_flags_t	vns_flags;		/* L */
	vnd_str_capab_t vns_caps;		/* L */
	taskq_ent_t	vns_tqe;		/* L */
	vnd_data_queue_t vns_dq_read;		/* E */
	vnd_data_queue_t vns_dq_write;		/* E */
	mblk_t		*vns_dlpi_inc;		/* L */
	queue_t		*vns_rq;		/* E */
	queue_t		*vns_wq;		/* E */
	queue_t		*vns_lrq;		/* E */
	t_uscalar_t	vns_dlpi_style;		/* L */
	t_uscalar_t	vns_minwrite;		/* L */
	t_uscalar_t	vns_maxwrite;		/* L */
	hrtime_t	vns_fclatch;		/* L */
	hrtime_t	vns_fcupdate;		/* L */
	kstat_t		*vns_kstat;		/* E */
	gsqueue_t	*vns_squeue;		/* E */
	mblk_t		vns_drainblk;		/* E + X */
	mblk_t		vns_barrierblk;		/* E + X */
	vnd_str_stat_t	vns_ksdata;		/* A */
	size_t		vns_nflush;		/* L */
	size_t 		vns_bsize;		/* L */
	struct vnd_dev	*vns_dev;		/* E + X */
	struct vnd_pnsd	*vns_nsd;		/* E + X */
} vnd_str_t;

typedef enum vnd_dev_flags {
	VND_D_ATTACH_INFLIGHT =	0x001,
	VND_D_ATTACHED =	0x002,
	VND_D_LINK_INFLIGHT =	0x004,
	VND_D_LINKED =		0x008,
	VND_D_CONDEMNED =	0x010,
	VND_D_ZONE_DYING =	0x020,
	VND_D_OPENED =		0x040
} vnd_dev_flags_t;

/*
 * This represents the data associated with a minor device instance.
 *
 * See synchronization section of the big theory statement for member
 * annotations.
 */
typedef struct vnd_dev {
	kmutex_t	vdd_lock;
	list_node_t	vdd_link;			/* GL */
	list_node_t	vdd_nslink;			/* NSL */
	int		vdd_ref;			/* L */
	vnd_dev_flags_t	vdd_flags;			/* L */
	minor_t		vdd_minor;			/* E */
	dev_t		vdd_devid;			/* E */
	ldi_ident_t	vdd_ldiid;			/* E */
	ldi_handle_t	vdd_ldih;			/* X */
	cred_t		*vdd_cr;			/* X */
	vnd_str_t	*vdd_str;			/* L */
	struct pollhead	vdd_ph;				/* E */
	struct vnd_pnsd *vdd_nsd;			/* E + X */
	char		vdd_datalink[VND_NAMELEN];	/* L */
	char		vdd_lname[VND_NAMELEN];		/* L */
} vnd_dev_t;

typedef enum vnd_pnsd_flags {
	VND_NS_CONDEMNED = 0x1
} vnd_pnsd_flags_t;

/*
 * Per netstack data structure.
 *
 * See synchronization section of the big theory statement for member
 * annotations.
 */
typedef struct vnd_pnsd {
	list_node_t vpnd_link;	/* protected by global dev lock */
	zoneid_t vpnd_zid;			/* E */
	netstackid_t vpnd_nsid;			/* E */
	boolean_t vpnd_hooked;			/* E */
	net_handle_t vpnd_neti_v4;		/* E */
	hook_family_t vpnd_family_v4;		/* E */
	hook_event_t vpnd_event_in_v4;		/* E */
	hook_event_t vpnd_event_out_v4;		/* E */
	hook_event_token_t vpnd_token_in_v4;	/* E */
	hook_event_token_t vpnd_token_out_v4;	/* E */
	net_handle_t vpnd_neti_v6;		/* E */
	hook_family_t vpnd_family_v6;		/* E */
	hook_event_t vpnd_event_in_v6;		/* E */
	hook_event_t vpnd_event_out_v6;		/* E */
	hook_event_token_t vpnd_token_in_v6;	/* E */
	hook_event_token_t vpnd_token_out_v6;	/* E */
	kmutex_t vpnd_lock;		/* Protects remaining members */
	kcondvar_t vpnd_ref_change;		/* Uses vpnd_lock */
	int vpnd_ref;				/* L */
	vnd_pnsd_flags_t vpnd_flags;		/* L */
	list_t vpnd_dev_list;			/* L */
} vnd_pnsd_t;

static void vnd_squeue_tx_drain(void *, mblk_t *, gsqueue_t *, void *);

/*
 * Drop function signature.
 */
typedef void (*vnd_dropper_f)(vnd_str_t *, mblk_t *, const char *);

static void
vnd_drop_ctl(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	DTRACE_VND4(drop__ctl, mblk_t *, mp, vnd_str_t *, vsp, mblk_t *,
	    mp, const char *, reason);
	if (mp != NULL) {
		freemsg(mp);
	}
	VND_STAT_INC(vsp, vks_ndlpidrops, 1);
	VND_STAT_INC(vsp, vks_tdrops, 1);
}

static void
vnd_drop_in(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	DTRACE_VND4(drop__in, mblk_t *, mp, vnd_str_t *, vsp, mblk_t *,
	    mp, const char *, reason);
	if (mp != NULL) {
		freemsg(mp);
	}
	VND_STAT_INC(vsp, vks_ndataindrops, 1);
	VND_STAT_INC(vsp, vks_tdrops, 1);
}

static void
vnd_drop_out(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	DTRACE_VND4(drop__out, mblk_t *, mp, vnd_str_t *, vsp, mblk_t *,
	    mp, const char *, reason);
	if (mp != NULL) {
		freemsg(mp);
	}
	VND_STAT_INC(vsp, vks_ndataoutdrops, 1);
	VND_STAT_INC(vsp, vks_tdrops, 1);
}

static void
vnd_drop_hook_in(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	DTRACE_VND4(drop__in, mblk_t *, mp, vnd_str_t *, vsp, mblk_t *,
	    mp, const char *, reason);
	if (mp != NULL) {
		freemsg(mp);
	}
	VND_STAT_INC(vsp, vks_nhookindrops, 1);
	VND_STAT_INC(vsp, vks_tdrops, 1);
}

static void
vnd_drop_hook_out(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	DTRACE_VND4(drop__out, mblk_t *, mp, vnd_str_t *, vsp, mblk_t *,
	    mp, const char *, reason);
	if (mp != NULL) {
		freemsg(mp);
	}
	VND_STAT_INC(vsp, vks_nhookoutdrops, 1);
	VND_STAT_INC(vsp, vks_tdrops, 1);
}

static void
vnd_drop_panic(vnd_str_t *vsp, mblk_t *mp, const char *reason)
{
	panic("illegal vnd drop");
}

static void
vnd_mac_drop_input(vnd_str_t *vsp, mac_resource_t *unused, mblk_t *mp_chain,
    mac_header_info_t *mhip)
{
	mblk_t *mp;

	while (mp_chain != NULL) {
		mp = mp_chain;
		mp_chain = mp->b_next;
		vnd_drop_hook_in(vsp, mp, "stream not associated");
	}
}

static vnd_pnsd_t *
vnd_nsd_lookup(netstackid_t nsid)
{
	vnd_pnsd_t *nsp;

	mutex_enter(&vnd_dev_lock);
	for (nsp = list_head(&vnd_nsd_list); nsp != NULL;
	    nsp = list_next(&vnd_nsd_list, nsp)) {
		if (nsp->vpnd_nsid == nsid) {
			mutex_enter(&nsp->vpnd_lock);
			VERIFY(nsp->vpnd_ref >= 0);
			nsp->vpnd_ref++;
			mutex_exit(&nsp->vpnd_lock);
			break;
		}
	}
	mutex_exit(&vnd_dev_lock);
	return (nsp);
}

static vnd_pnsd_t *
vnd_nsd_lookup_by_zid(zoneid_t zid)
{
	netstack_t *ns;
	vnd_pnsd_t *nsp;
	ns = netstack_find_by_zoneid(zid);
	if (ns == NULL)
		return (NULL);
	nsp = vnd_nsd_lookup(ns->netstack_stackid);
	netstack_rele(ns);
	return (nsp);
}

static vnd_pnsd_t *
vnd_nsd_lookup_by_zonename(char *zname)
{
	zone_t *zonep;
	vnd_pnsd_t *nsp;

	zonep = zone_find_by_name(zname);
	if (zonep == NULL)
		return (NULL);

	nsp = vnd_nsd_lookup_by_zid(zonep->zone_id);
	zone_rele(zonep);
	return (nsp);
}

static void
vnd_nsd_ref(vnd_pnsd_t *nsp)
{
	mutex_enter(&nsp->vpnd_lock);
	/*
	 * This can only be used on something that has been obtained through
	 * some other means. As such, the caller should already have a reference
	 * before adding another one. This function should not be used as a
	 * means of creating the initial reference.
	 */
	VERIFY(nsp->vpnd_ref > 0);
	nsp->vpnd_ref++;
	mutex_exit(&nsp->vpnd_lock);
	cv_broadcast(&nsp->vpnd_ref_change);
}

static void
vnd_nsd_rele(vnd_pnsd_t *nsp)
{
	mutex_enter(&nsp->vpnd_lock);
	VERIFY(nsp->vpnd_ref > 0);
	nsp->vpnd_ref--;
	mutex_exit(&nsp->vpnd_lock);
	cv_broadcast(&nsp->vpnd_ref_change);
}

static vnd_dev_t *
vnd_dev_lookup(minor_t m)
{
	vnd_dev_t *vdp;
	mutex_enter(&vnd_dev_lock);
	for (vdp = list_head(&vnd_dev_list); vdp != NULL;
	    vdp = list_next(&vnd_dev_list, vdp)) {
		if (vdp->vdd_minor == m) {
			mutex_enter(&vdp->vdd_lock);
			VERIFY(vdp->vdd_ref > 0);
			vdp->vdd_ref++;
			DTRACE_VND_REFINC(vdp);
			mutex_exit(&vdp->vdd_lock);
			break;
		}
	}
	mutex_exit(&vnd_dev_lock);
	return (vdp);
}

static void
vnd_dev_free(vnd_dev_t *vdp)
{
	/*
	 * When the STREAM exists we need to go through and make sure
	 * communication gets torn down. As part of closing the stream, we
	 * guarantee that nothing else should be able to enter the stream layer
	 * at this point. That means no one should be able to call
	 * read(),write() or one of the frameio ioctls.
	 */
	if (vdp->vdd_flags & VND_D_ATTACHED) {
		ldi_close(vdp->vdd_ldih, FREAD | FWRITE, vdp->vdd_cr);
		crfree(vdp->vdd_cr);
		vdp->vdd_cr = NULL;

		/*
		 * We have to remove ourselves from our parents list now. It is
		 * really quite important that we have already set the condemend
		 * flag here so that our containing netstack basically knows
		 * that we're on the way down and knows not to wait for us. It's
		 * also important that we do that before we put a rele on the
		 * the device as that is the point at which it will check again.
		 */
		mutex_enter(&vdp->vdd_nsd->vpnd_lock);
		list_remove(&vdp->vdd_nsd->vpnd_dev_list, vdp);
		mutex_exit(&vdp->vdd_nsd->vpnd_lock);
		vnd_nsd_rele(vdp->vdd_nsd);
		vdp->vdd_nsd = NULL;
	}
	ASSERT(vdp->vdd_flags & VND_D_CONDEMNED);
	id_free(vnd_minors, vdp->vdd_minor);
	mutex_destroy(&vdp->vdd_lock);
	kmem_cache_free(vnd_dev_cache, vdp);
}

static void
vnd_dev_ref(vnd_dev_t *vdp)
{
	mutex_enter(&vdp->vdd_lock);
	VERIFY(vdp->vdd_ref > 0);
	vdp->vdd_ref++;
	DTRACE_VND_REFINC(vdp);
	mutex_exit(&vdp->vdd_lock);
}

/*
 * As part of releasing the hold on this we may tear down a given vnd_dev_t As
 * such we need to make sure that we grab the list lock first before grabbing
 * the vnd_dev_t's lock to ensure proper lock ordering.
 */
static void
vnd_dev_rele(vnd_dev_t *vdp)
{
	mutex_enter(&vnd_dev_lock);
	mutex_enter(&vdp->vdd_lock);
	VERIFY(vdp->vdd_ref > 0);
	vdp->vdd_ref--;
	DTRACE_VND_REFDEC(vdp);
	if (vdp->vdd_ref > 0) {
		mutex_exit(&vdp->vdd_lock);
		mutex_exit(&vnd_dev_lock);
		return;
	}

	/*
	 * Now that we've removed this from the list, we can go ahead and
	 * drop the list lock. No one else can find this device and reference
	 * it. As its reference count is zero, it by definition does not have
	 * any remaining entries in /devices that could lead someone back to
	 * this.
	 */
	vdp->vdd_flags |= VND_D_CONDEMNED;
	list_remove(&vnd_dev_list, vdp);
	mutex_exit(&vdp->vdd_lock);
	mutex_exit(&vnd_dev_lock);

	vnd_dev_free(vdp);
}

/*
 * Insert a mesage block chain if there's space, otherwise drop it. Return one
 * so someone who was waiting for data would now end up having found it. eg.
 * caller should consider a broadcast.
 */
static int
vnd_dq_push(vnd_data_queue_t *vqp, mblk_t *mp, boolean_t reserved,
    vnd_dropper_f dropf)
{
	size_t msize;

	ASSERT(MUTEX_HELD(&vqp->vdq_lock));
	if (reserved == B_FALSE) {
		msize = msgsize(mp);
		if (vqp->vdq_cur + msize > vqp->vdq_max) {
			dropf(vqp->vdq_vns, mp, "buffer full");
			return (0);
		}
		vqp->vdq_cur += msize;
	}

	if (vqp->vdq_head == NULL) {
		ASSERT(vqp->vdq_tail == NULL);
		vqp->vdq_head = mp;
		vqp->vdq_tail = mp;
	} else {
		vqp->vdq_tail->b_next = mp;
		vqp->vdq_tail = mp;
	}

	return (1);
}

/*
 * Remove a message message block chain. If the amount of space in the buffer
 * has changed we return 1. We have no way of knowing whether or not there is
 * enough space overall for a given writer who is blocked, so we always end up
 * having to return true and thus tell consumers that they should consider
 * signalling.
 */
static int
vnd_dq_pop(vnd_data_queue_t *vqp, mblk_t **mpp)
{
	size_t msize;
	mblk_t *mp;

	ASSERT(MUTEX_HELD(&vqp->vdq_lock));
	ASSERT(mpp != NULL);
	if (vqp->vdq_head == NULL) {
		ASSERT(vqp->vdq_tail == NULL);
		*mpp = NULL;
		return (0);
	}

	mp = vqp->vdq_head;
	msize = msgsize(mp);

	vqp->vdq_cur -= msize;
	if (mp->b_next == NULL) {
		vqp->vdq_head = NULL;
		vqp->vdq_tail = NULL;
		/*
		 * We can't be certain that this is always going to be zero.
		 * Someone may have basically taken a reservation of space on
		 * the data queue, eg. claimed spae but not yet pushed it on
		 * yet.
		 */
		ASSERT(vqp->vdq_cur >= 0);
	} else {
		vqp->vdq_head = mp->b_next;
		ASSERT(vqp->vdq_cur > 0);
	}
	mp->b_next = NULL;
	*mpp = mp;
	return (1);
}

/*
 * Reserve space in the queue. This will bump up the size of the queue and
 * entitle the user to push something on later without bumping the space.
 */
static int
vnd_dq_reserve(vnd_data_queue_t *vqp, ssize_t size)
{
	ASSERT(MUTEX_HELD(&vqp->vdq_lock));
	ASSERT(size >= 0);

	if (size == 0)
		return (0);

	if (size + vqp->vdq_cur > vqp->vdq_max)
		return (0);

	vqp->vdq_cur += size;
	return (1);
}

static void
vnd_dq_unreserve(vnd_data_queue_t *vqp, ssize_t size)
{
	ASSERT(MUTEX_HELD(&vqp->vdq_lock));
	ASSERT(size > 0);
	ASSERT(size <= vqp->vdq_cur);

	vqp->vdq_cur -= size;
}

static void
vnd_dq_flush(vnd_data_queue_t *vqp, vnd_dropper_f dropf)
{
	mblk_t *mp, *next;

	mutex_enter(&vqp->vdq_lock);
	for (mp = vqp->vdq_head; mp != NULL; mp = next) {
		next = mp->b_next;
		mp->b_next = NULL;
		dropf(vqp->vdq_vns, mp, "vnd_dq_flush");
	}
	vqp->vdq_cur = 0;
	vqp->vdq_head = NULL;
	vqp->vdq_tail = NULL;
	mutex_exit(&vqp->vdq_lock);
}

static boolean_t
vnd_dq_is_empty(vnd_data_queue_t *vqp)
{
	boolean_t ret;

	mutex_enter(&vqp->vdq_lock);
	if (vqp->vdq_head == NULL)
		ret = B_TRUE;
	else
		ret = B_FALSE;
	mutex_exit(&vqp->vdq_lock);

	return (ret);
}

/*
 * Get a network uint16_t from the message and translate it into something the
 * host understands.
 */
static int
vnd_mbc_getu16(mblk_t *mp, off_t off, uint16_t *out)
{
	size_t mpsize;
	uint8_t *bp;

	mpsize = msgsize(mp);
	/* Check for overflow */
	if (off + sizeof (uint16_t) > mpsize)
		return (1);

	mpsize = MBLKL(mp);
	while (off >= mpsize) {
		mp = mp->b_cont;
		off -= mpsize;
		mpsize = MBLKL(mp);
	}

	/*
	 * Data is in network order. Note the second byte of data might be in
	 * the next mp.
	 */
	bp = mp->b_rptr + off;
	*out = *bp << 8;
	if (off + 1 == mpsize) {
		mp = mp->b_cont;
		bp = mp->b_rptr;
	} else {
		bp++;
	}

	*out |= *bp;
	return (0);
}

/*
 * Given an mblk chain find the mblk and address of a particular offset.
 */
static int
vnd_mbc_getoffset(mblk_t *mp, off_t off, mblk_t **mpp, uintptr_t *offp)
{
	size_t mpsize;

	if (off >= msgsize(mp))
		return (1);

	mpsize = MBLKL(mp);
	while (off >= mpsize) {
		mp = mp->b_cont;
		off -= mpsize;
		mpsize = MBLKL(mp);
	}
	*mpp = mp;
	*offp = (uintptr_t)mp->b_rptr + off;

	return (0);
}

/*
 * Fetch the destination mac address. Set *dstp to that mac address. If the data
 * is not contiguous in the first mblk_t, fill in datap and set *dstp to it.
 */
static int
vnd_mbc_getdstmac(mblk_t *mp, uint8_t **dstpp, uint8_t *datap)
{
	int i;

	if (MBLKL(mp) >= ETHERADDRL) {
		*dstpp = mp->b_rptr;
		return (0);
	}

	*dstpp = datap;
	for (i = 0; i < ETHERADDRL; i += 2, datap += 2) {
		if (vnd_mbc_getu16(mp, i, (uint16_t *)datap) != 0)
			return (1);
	}

	return (0);
}

static int
vnd_hook(vnd_str_t *vsp, mblk_t **mpp, net_handle_t netiv4, hook_event_t hev4,
    hook_event_token_t hetv4, net_handle_t netiv6, hook_event_t hev6,
    hook_event_token_t hetv6, vnd_dropper_f hdrop, vnd_dropper_f ddrop)
{
	uint16_t etype;
	int vlan = 0;
	hook_pkt_event_t info;
	size_t offset, mblen;
	uint8_t *dstp;
	uint8_t dstaddr[6];
	hook_event_t he;
	hook_event_token_t het;
	net_handle_t neti;

	/*
	 * Before we can ask if we're interested we have to do enough work to
	 * determine the ethertype.
	 */

	/* Byte 12 is either the VLAN tag or the ethertype */
	if (vnd_mbc_getu16(*mpp, 12, &etype) != 0) {
		ddrop(vsp, *mpp, "packet has incomplete ethernet header");
		*mpp = NULL;
		return (1);
	}

	if (etype == ETHERTYPE_VLAN) {
		vlan = 1;
		/* Actual ethertype is another four bytes in */
		if (vnd_mbc_getu16(*mpp, 16, &etype) != 0) {
			ddrop(vsp, *mpp,
			    "packet has incomplete ethernet vlan header");
			*mpp = NULL;
			return (1);
		}
		offset = sizeof (struct ether_vlan_header);
	} else {
		offset = sizeof (struct ether_header);
	}

	/*
	 * At the moment we only hook on the kinds of things that the IP module
	 * would normally.
	 */
	if (etype != ETHERTYPE_IP && etype != ETHERTYPE_IPV6)
		return (0);

	if (etype == ETHERTYPE_IP) {
		neti = netiv4;
		he = hev4;
		het = hetv4;
	} else {
		neti = netiv6;
		he = hev6;
		het = hetv6;
	}

	if (!he.he_interested)
		return (0);


	if (vnd_mbc_getdstmac(*mpp, &dstp, dstaddr) != 0) {
		ddrop(vsp, *mpp, "packet has incomplete ethernet header");
		*mpp = NULL;
		return (1);
	}

	/*
	 * Now that we know we're interested, we have to do some additional
	 * sanity checking for IPF's sake, ala ip_check_length(). Specifically
	 * we need to check to make sure that the remaining packet size,
	 * excluding MAC, is at least the size of an IP header.
	 */
	mblen = msgsize(*mpp);
	if ((etype == ETHERTYPE_IP &&
	    mblen - offset < IP_SIMPLE_HDR_LENGTH) ||
	    (etype == ETHERTYPE_IPV6 && mblen - offset < IPV6_HDR_LEN)) {
		ddrop(vsp, *mpp, "packet has invalid IP header");
		*mpp = NULL;
		return (1);
	}

	info.hpe_protocol = neti;
	info.hpe_ifp = (phy_if_t)vsp;
	info.hpe_ofp = (phy_if_t)vsp;
	info.hpe_mp = mpp;
	info.hpe_flags = 0;

	if (bcmp(vnd_bcast_addr, dstp, ETHERADDRL) == 0)
		info.hpe_flags |= HPE_BROADCAST;
	else if (etype == ETHERTYPE_IP &&
	    bcmp(vnd_ipv4_mcast, vnd_bcast_addr, IPV4_MCAST_LEN) == 0)
		info.hpe_flags |= HPE_MULTICAST;
	else if (etype == ETHERTYPE_IPV6 &&
	    bcmp(vnd_ipv6_mcast, vnd_bcast_addr, IPV6_MCAST_LEN) == 0)
		info.hpe_flags |= HPE_MULTICAST;

	if (vnd_mbc_getoffset(*mpp, offset, &info.hpe_mb,
	    (uintptr_t *)&info.hpe_hdr) != 0) {
		ddrop(vsp, *mpp, "packet too small -- "
		    "unable to find payload");
		*mpp = NULL;
		return (1);
	}

	if (hook_run(neti->netd_hooks, het, (hook_data_t)&info) != 0) {
		hdrop(vsp, *mpp, "drooped by hooks");
		return (1);
	}

	return (0);
}

/*
 * This should not be used for DL_INFO_REQ.
 */
static mblk_t *
vnd_dlpi_alloc(size_t len, t_uscalar_t prim)
{
	mblk_t *mp;
	mp = allocb(len, BPRI_MED);
	if (mp == NULL)
		return (NULL);

	mp->b_datap->db_type = M_PROTO;
	mp->b_wptr = mp->b_rptr + len;
	bzero(mp->b_rptr, len);
	((dl_unitdata_req_t *)mp->b_rptr)->dl_primitive = prim;

	return (mp);
}

static void
vnd_dlpi_inc_push(vnd_str_t *vsp, mblk_t *mp)
{
	mblk_t **mpp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	ASSERT(mp->b_next == NULL);
	mpp = &vsp->vns_dlpi_inc;
	while (*mpp != NULL)
		mpp = &((*mpp)->b_next);
	*mpp = mp;
}

static mblk_t *
vnd_dlpi_inc_pop(vnd_str_t *vsp)
{
	mblk_t *mp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vsp->vns_dlpi_inc;
	if (mp != NULL) {
		VERIFY(mp->b_next == NULL || mp->b_next != mp);
		vsp->vns_dlpi_inc = mp->b_next;
		mp->b_next = NULL;
	}
	return (mp);
}

static int
vnd_st_sinfo(vnd_str_t *vsp)
{
	mblk_t *mp;
	dl_info_req_t *dlir;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = allocb(MAX(sizeof (dl_info_req_t), sizeof (dl_info_ack_t)),
	    BPRI_HI);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}
	vsp->vns_state = VNS_S_INFO_SENT;
	cv_broadcast(&vsp->vns_stcv);

	mp->b_datap->db_type = M_PCPROTO;
	dlir = (dl_info_req_t *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)&dlir[1];
	dlir->dl_primitive = DL_INFO_REQ;
	putnext(vsp->vns_wq, mp);

	return (0);
}

static int
vnd_st_info(vnd_str_t *vsp)
{
	dl_info_ack_t *dlia;
	mblk_t *mp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);
	dlia = (dl_info_ack_t *)mp->b_rptr;
	vsp->vns_dlpi_style = dlia->dl_provider_style;
	vsp->vns_minwrite = dlia->dl_min_sdu;
	vsp->vns_maxwrite = dlia->dl_max_sdu;

	/*
	 * At this time we only support DL_ETHER devices.
	 */
	if (dlia->dl_mac_type != DL_ETHER) {
		freemsg(mp);
		vsp->vns_errno = VND_E_NOTETHER;
		return (1);
	}

	/*
	 * Because vnd operates on entire packets, we need to manually account
	 * for the ethernet header information. We add the size of the
	 * ether_vlan_header to account for this, regardless if it is using
	 * vlans or not.
	 */
	vsp->vns_maxwrite += sizeof (struct ether_vlan_header);

	freemsg(mp);
	return (0);
}

static int
vnd_st_sexclusive(vnd_str_t *vsp)
{
	mblk_t *mp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_alloc(sizeof (dl_attach_req_t), DL_EXCLUSIVE_REQ);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}

	vsp->vns_state = VNS_S_EXCLUSIVE_SENT;
	cv_broadcast(&vsp->vns_stcv);
	putnext(vsp->vns_wq, mp);
	return (0);
}

static int
vnd_st_exclusive(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim, cprim;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);
	prim = ((dl_error_ack_t *)mp->b_rptr)->dl_primitive;
	cprim = ((dl_ok_ack_t *)mp->b_rptr)->dl_correct_primitive;

	if (prim != DL_OK_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp,
		    "wrong dlpi primitive for vnd_st_exclusive");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (cprim != DL_EXCLUSIVE_REQ) {
		vnd_drop_ctl(vsp, mp,
		    "vnd_st_exclusive: got ack/nack for wrong primitive");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (prim == DL_ERROR_ACK)
		vsp->vns_errno = VND_E_DLEXCL;

	freemsg(mp);
	return (prim == DL_ERROR_ACK);
}

/*
 * Send down a DLPI_ATTACH_REQ.
 */
static int
vnd_st_sattach(vnd_str_t *vsp)
{
	mblk_t *mp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_alloc(sizeof (dl_attach_req_t), DL_ATTACH_REQ);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}

	((dl_attach_req_t *)mp->b_rptr)->dl_ppa = 0;
	vsp->vns_state = VNS_S_ATTACH_SENT;
	cv_broadcast(&vsp->vns_stcv);
	putnext(vsp->vns_wq, mp);

	return (0);
}

static int
vnd_st_attach(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim, cprim;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);
	prim = ((dl_ok_ack_t *)mp->b_rptr)->dl_primitive;
	cprim = ((dl_ok_ack_t *)mp->b_rptr)->dl_correct_primitive;


	if (prim != DL_OK_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp, "vnd_st_attach: unknown primitive type");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (cprim != DL_ATTACH_REQ) {
		vnd_drop_ctl(vsp, mp,
		    "vnd_st_attach: Got ack/nack for wrong primitive");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (prim == DL_ERROR_ACK)
		vsp->vns_errno = VND_E_ATTACHFAIL;

	freemsg(mp);
	return (prim == DL_ERROR_ACK);
}

static int
vnd_st_sbind(vnd_str_t *vsp)
{
	mblk_t *mp;
	dl_bind_req_t *dbrp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_alloc(sizeof (dl_bind_req_t) + sizeof (long),
	    DL_BIND_REQ);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}
	dbrp = (dl_bind_req_t *)(mp->b_rptr);
	dbrp->dl_sap = 0;
	dbrp->dl_service_mode = DL_CLDLS;

	vsp->vns_state = VNS_S_BIND_SENT;
	cv_broadcast(&vsp->vns_stcv);
	putnext(vsp->vns_wq, mp);

	return (0);
}

static int
vnd_st_bind(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);
	prim = ((dl_error_ack_t *)mp->b_rptr)->dl_primitive;

	if (prim != DL_BIND_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp, "wrong dlpi primitive for vnd_st_bind");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (prim == DL_ERROR_ACK)
		vsp->vns_errno = VND_E_BINDFAIL;

	freemsg(mp);
	return (prim == DL_ERROR_ACK);
}

static int
vnd_st_spromisc(vnd_str_t *vsp, int type, vnd_str_state_t next)
{
	mblk_t *mp;
	dl_promiscon_req_t *dprp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_alloc(sizeof (dl_promiscon_req_t), DL_PROMISCON_REQ);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}

	dprp = (dl_promiscon_req_t *)mp->b_rptr;
	dprp->dl_level = type;

	vsp->vns_state = next;
	cv_broadcast(&vsp->vns_stcv);
	putnext(vsp->vns_wq, mp);

	return (0);
}

static int
vnd_st_promisc(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim, cprim;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);
	prim = ((dl_ok_ack_t *)mp->b_rptr)->dl_primitive;
	cprim = ((dl_ok_ack_t *)mp->b_rptr)->dl_correct_primitive;

	if (prim != DL_OK_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp,
		    "wrong dlpi primitive for vnd_st_promisc");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (cprim != DL_PROMISCON_REQ) {
		vnd_drop_ctl(vsp, mp,
		    "vnd_st_promisc: Got ack/nack for wrong primitive");
		vsp->vns_errno = VND_E_DLPIINVAL;
		return (1);
	}

	if (prim == DL_ERROR_ACK)
		vsp->vns_errno = VND_E_PROMISCFAIL;

	freemsg(mp);
	return (prim == DL_ERROR_ACK);
}

static int
vnd_st_scapabq(vnd_str_t *vsp)
{
	mblk_t *mp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));

	mp = vnd_dlpi_alloc(sizeof (dl_capability_req_t), DL_CAPABILITY_REQ);
	if (mp == NULL) {
		vsp->vns_errno = VND_E_NOMEM;
		return (1);
	}

	vsp->vns_state = VNS_S_CAPAB_Q_SENT;
	cv_broadcast(&vsp->vns_stcv);
	putnext(vsp->vns_wq, mp);

	return (0);
}

static void
vnd_mac_input(vnd_str_t *vsp, mac_resource_t *unused, mblk_t *mp_chain,
    mac_header_info_t *mhip)
{
	int signal = 0;
	mblk_t *mp;
	vnd_pnsd_t *nsp = vsp->vns_nsd;

	ASSERT(vsp != NULL);
	ASSERT(mp_chain != NULL);

	for (mp = mp_chain; mp != NULL; mp = mp_chain) {
		uint16_t vid;
		mp_chain = mp->b_next;
		mp->b_next = NULL;

		/*
		 * If we were operating in a traditional dlpi context then we
		 * would have enabled DLIOCRAW and rather than the fast path, we
		 * would come through dld_str_rx_raw. That function does two
		 * things that we have to consider doing ourselves. The first is
		 * that it adjusts the b_rptr back to account for dld bumping us
		 * past the mac header. It also tries to account for cases where
		 * mac provides an illusion of the mac header. Fortunately, dld
		 * only allows the fastpath when the media type is the same as
		 * the native type. Therefore all we have to do here is adjust
		 * the b_rptr.
		 */
		ASSERT(mp->b_rptr >= DB_BASE(mp) + mhip->mhi_hdrsize);
		mp->b_rptr -= mhip->mhi_hdrsize;
		vid = VLAN_ID(mhip->mhi_tci);
		if (mhip->mhi_istagged && vid != VLAN_ID_NONE) {
			bcopy(mp->b_rptr, mp->b_rptr + 4, 12);
			mp->b_rptr += 4;
		}

		if (nsp->vpnd_hooked && vnd_hook(vsp, &mp, nsp->vpnd_neti_v4,
		    nsp->vpnd_event_in_v4, nsp->vpnd_token_in_v4,
		    nsp->vpnd_neti_v6, nsp->vpnd_event_in_v6,
		    nsp->vpnd_token_in_v6, vnd_drop_hook_in, vnd_drop_in) != 0)
			continue;

		VND_STAT_INC(vsp, vks_rpackets, 1);
		VND_STAT_INC(vsp, vks_rbytes, msgsize(mp));
		DTRACE_VND5(recv, mblk_t *, mp, void *, NULL, void *, NULL,
		    vnd_str_t *, vsp, mblk_t *, mp);
		mutex_enter(&vsp->vns_dq_read.vdq_lock);
		signal |= vnd_dq_push(&vsp->vns_dq_read, mp, B_FALSE,
		    vnd_drop_in);
		mutex_exit(&vsp->vns_dq_read.vdq_lock);

	}

	if (signal != 0) {
		cv_broadcast(&vsp->vns_dq_read.vdq_ready);
		pollwakeup(&vsp->vns_dev->vdd_ph, POLLIN | POLLRDNORM);
	}

}

static void
vnd_mac_flow_control_stat(vnd_str_t *vsp, hrtime_t diff)
{
	VND_STAT_INC(vsp, vks_nmacflow, 1);
	VND_STAT_INC(vsp, vks_tmacflow, diff);
	if (diff >= VND_LATENCY_1MS)
		VND_STAT_INC(vsp, vks_mac_flow_1ms, 1);
	if (diff >= VND_LATENCY_10MS)
		VND_STAT_INC(vsp, vks_mac_flow_10ms, 1);
	if (diff >= VND_LATENCY_100MS)
		VND_STAT_INC(vsp, vks_mac_flow_100ms, 1);
	if (diff >= VND_LATENCY_1S)
		VND_STAT_INC(vsp, vks_mac_flow_1s, 1);
	if (diff >= VND_LATENCY_10S)
		VND_STAT_INC(vsp, vks_mac_flow_10s, 1);
}

/*
 * This is a callback from MAC that indicates that we are allowed to send
 * packets again.
 */
static void
vnd_mac_flow_control(void *arg, vnd_mac_cookie_t cookie)
{
	vnd_str_t *vsp = arg;
	hrtime_t now, diff;

	mutex_enter(&vsp->vns_lock);
	now = gethrtime();

	/*
	 * Check for the case that we beat vnd_squeue_tx_one to the punch.
	 * There's also an additional case here that we got notified because
	 * we're sharing a device that ran out of tx descriptors, even though it
	 * wasn't because of us.
	 */
	if (!(vsp->vns_flags & VNS_F_FLOW_CONTROLLED)) {
		vsp->vns_fcupdate = now;
		mutex_exit(&vsp->vns_lock);
		return;
	}

	ASSERT(vsp->vns_flags & VNS_F_FLOW_CONTROLLED);
	ASSERT(vsp->vns_caps.vsc_fc_cookie == cookie);
	vsp->vns_flags &= ~VNS_F_FLOW_CONTROLLED;
	vsp->vns_caps.vsc_fc_cookie = NULL;
	diff = now - vsp->vns_fclatch;
	vsp->vns_fclatch = 0;
	DTRACE_VND3(flow__resumed, vnd_str_t *, vsp, uint64_t,
	    vsp->vns_dq_write.vdq_cur, uintptr_t, cookie);
	/*
	 * If someone has asked to flush the squeue and thus inserted a barrier,
	 * than we shouldn't schedule a drain.
	 */
	if (!(vsp->vns_flags & (VNS_F_DRAIN_SCHEDULED | VNS_F_BARRIER))) {
		vsp->vns_flags |= VNS_F_DRAIN_SCHEDULED;
		gsqueue_enter_one(vsp->vns_squeue, &vsp->vns_drainblk,
		    vnd_squeue_tx_drain, vsp, GSQUEUE_FILL,
		    VND_SQUEUE_TAG_MAC_FLOW_CONTROL);
	}
	mutex_exit(&vsp->vns_lock);
}

static void
vnd_mac_enter(vnd_str_t *vsp, mac_perim_handle_t *mphp)
{
	ASSERT(MUTEX_HELD(&vsp->vns_lock));
	VERIFY(vsp->vns_caps.vsc_capab_f(vsp->vns_caps.vsc_capab_hdl,
	    DLD_CAPAB_PERIM, mphp, DLD_ENABLE) == 0);
}

static void
vnd_mac_exit(vnd_str_t *vsp, mac_perim_handle_t mph)
{
	ASSERT(MUTEX_HELD(&vsp->vns_lock));
	VERIFY(vsp->vns_caps.vsc_capab_f(vsp->vns_caps.vsc_capab_hdl,
	    DLD_CAPAB_PERIM, mph, DLD_DISABLE) == 0);
}

static int
vnd_dld_cap_enable(vnd_str_t *vsp, vnd_rx_t rxfunc)
{
	int ret;
	dld_capab_direct_t d;
	mac_perim_handle_t mph;
	vnd_str_capab_t *c = &vsp->vns_caps;

	bzero(&d, sizeof (d));
	d.di_rx_cf = (uintptr_t)rxfunc;
	d.di_rx_ch = vsp;
	d.di_flags = DI_DIRECT_RAW;

	vnd_mac_enter(vsp, &mph);

	/*
	 * If we're coming in here for a second pass, we need to make sure that
	 * we remove an existing flow control notification callback, otherwise
	 * we'll create a duplicate that will remain with garbage data.
	 */
	if (c->vsc_tx_fc_hdl != NULL) {
		ASSERT(c->vsc_set_fcb_hdl != NULL);
		(void) c->vsc_set_fcb_f(c->vsc_set_fcb_hdl, NULL,
		    c->vsc_tx_fc_hdl);
		c->vsc_tx_fc_hdl = NULL;
	}

	if (vsp->vns_caps.vsc_capab_f(c->vsc_capab_hdl,
	    DLD_CAPAB_DIRECT, &d, DLD_ENABLE) == 0) {
		c->vsc_tx_f = (vnd_dld_tx_t)d.di_tx_df;
		c->vsc_tx_hdl = d.di_tx_dh;
		c->vsc_set_fcb_f = (vnd_dld_set_fcb_t)d.di_tx_cb_df;
		c->vsc_set_fcb_hdl = d.di_tx_cb_dh;
		c->vsc_is_fc_f = (vnd_dld_is_fc_t)d.di_tx_fctl_df;
		c->vsc_is_fc_hdl = d.di_tx_fctl_dh;
		c->vsc_tx_fc_hdl = c->vsc_set_fcb_f(c->vsc_set_fcb_hdl,
		    vnd_mac_flow_control, vsp);
		c->vsc_flags |= VNS_C_DIRECT;
		ret = 0;
	} else {
		vsp->vns_errno = VND_E_DIRECTFAIL;
		ret = 1;
	}
	vnd_mac_exit(vsp, mph);
	return (ret);
}

static int
vnd_st_capabq(vnd_str_t *vsp)
{
	mblk_t *mp;
	dl_capability_ack_t *cap;
	dl_capability_sub_t *subp;
	dl_capab_hcksum_t *hck;
	dl_capab_dld_t *dld;
	unsigned char *rp;
	int ret = 0;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_inc_pop(vsp);

	rp = mp->b_rptr;
	cap = (dl_capability_ack_t *)rp;
	if (cap->dl_sub_length == 0)
		goto done;

	/* Don't try to process something too big */
	if (sizeof (dl_capability_ack_t) + cap->dl_sub_length > MBLKL(mp)) {
		VND_STAT_INC(vsp, vks_ndlpidrops, 1);
		VND_STAT_INC(vsp, vks_tdrops, 1);
		vsp->vns_errno = VND_E_CAPACKINVAL;
		ret = 1;
		goto done;
	}

	rp += cap->dl_sub_offset;

	while (cap->dl_sub_length > 0) {
		subp = (dl_capability_sub_t *)rp;
		/* Sanity check something crazy from down below */
		if (subp->dl_length + sizeof (dl_capability_sub_t) >
		    cap->dl_sub_length) {
			VND_STAT_INC(vsp, vks_ndlpidrops, 1);
			VND_STAT_INC(vsp, vks_tdrops, 1);
			vsp->vns_errno = VND_E_SUBCAPINVAL;
			ret = 1;
			goto done;
		}

		switch (subp->dl_cap) {
		case DL_CAPAB_HCKSUM:
			hck = (dl_capab_hcksum_t *)(rp +
			    sizeof (dl_capability_sub_t));
			if (hck->hcksum_version != HCKSUM_CURRENT_VERSION) {
				vsp->vns_caps.vsc_flags |= VNS_C_HCKSUM_BADVERS;
				break;
			}
			if (dlcapabcheckqid(&hck->hcksum_mid, vsp->vns_lrq) !=
			    B_TRUE) {
				vsp->vns_errno = VND_E_CAPABPASS;
				ret = 1;
				goto done;
			}
			vsp->vns_caps.vsc_flags |= VNS_C_HCKSUM;
			vsp->vns_caps.vsc_hcksum_opts = hck->hcksum_txflags;
			break;
		case DL_CAPAB_DLD:
			dld = (dl_capab_dld_t *)(rp +
			    sizeof (dl_capability_sub_t));
			if (dld->dld_version != DLD_CURRENT_VERSION) {
				vsp->vns_errno = VND_E_DLDBADVERS;
				ret = 1;
				goto done;
			}
			if (dlcapabcheckqid(&dld->dld_mid, vsp->vns_lrq) !=
			    B_TRUE) {
				vsp->vns_errno = VND_E_CAPABPASS;
				ret = 1;
				goto done;
			}
			vsp->vns_caps.vsc_flags |= VNS_C_DLD;
			vsp->vns_caps.vsc_capab_f =
			    (vnd_dld_cap_t)dld->dld_capab;
			vsp->vns_caps.vsc_capab_hdl =
			    (void *)dld->dld_capab_handle;
			/*
			 * At this point in time, we have to set up a direct
			 * function that drops all input. This validates that
			 * we'll be able to set up direct input and that we can
			 * easily switch it earlier to the real data function
			 * when we've plumbed everything up.
			 */
			if (vnd_dld_cap_enable(vsp, vnd_mac_drop_input) != 0) {
				/* vns_errno set by vnd_dld_cap_enable */
				ret = 1;
				goto done;
			}
			break;
		default:
			/* Ignore unsupported cap */
			break;
		}

		rp += sizeof (dl_capability_sub_t) + subp->dl_length;
		cap->dl_sub_length -= sizeof (dl_capability_sub_t) +
		    subp->dl_length;
	}

done:
	/* Make sure we enabled direct callbacks */
	if (ret == 0 && !(vsp->vns_caps.vsc_flags & VNS_C_DIRECT)) {
		vsp->vns_errno = VND_E_DIRECTNOTSUP;
		ret = 1;
	}

	freemsg(mp);
	return (ret);
}

static void
vnd_st_sonline(vnd_str_t *vsp)
{
	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	vsp->vns_state = VNS_S_ONLINE;
	cv_broadcast(&vsp->vns_stcv);
}

static void
vnd_st_shutdown(vnd_str_t *vsp)
{
	mac_perim_handle_t mph;
	vnd_str_capab_t *vsc = &vsp->vns_caps;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));

	/*
	 * At this point in time we know that there is no one transmitting as
	 * our final reference has been torn down and that vnd_s_close inserted
	 * a barrier to validate that everything is flushed.
	 */
	if (vsc->vsc_flags & VNS_C_DIRECT) {
		vnd_mac_enter(vsp, &mph);
		vsc->vsc_flags &= ~VNS_C_DIRECT;
		(void) vsc->vsc_set_fcb_f(vsc->vsc_set_fcb_hdl, NULL,
		    vsc->vsc_tx_fc_hdl);
		vsc->vsc_tx_fc_hdl = NULL;
		(void) vsc->vsc_capab_f(vsc->vsc_capab_hdl, DLD_CAPAB_DIRECT,
		    NULL, DLD_DISABLE);
		vnd_mac_exit(vsp, mph);
	}
}

static boolean_t
vnd_st_spromiscoff(vnd_str_t *vsp, int type, vnd_str_state_t next)
{
	boolean_t ret = B_TRUE;
	mblk_t *mp;
	dl_promiscoff_req_t *dprp;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));
	mp = vnd_dlpi_alloc(sizeof (dl_promiscon_req_t), DL_PROMISCOFF_REQ);
	if (mp == NULL) {
		cmn_err(CE_NOTE, "!vnd failed to allocate mblk_t for "
		    "promiscoff request");
		ret = B_FALSE;
		goto next;
	}

	dprp = (dl_promiscoff_req_t *)mp->b_rptr;
	dprp->dl_level = type;

	putnext(vsp->vns_wq, mp);
next:
	vsp->vns_state = next;
	cv_broadcast(&vsp->vns_stcv);
	return (ret);
}

static void
vnd_st_promiscoff(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim, cprim;

	VERIFY(MUTEX_HELD(&vsp->vns_lock));

	/*
	 * Unlike other cases where we guard against the incoming packet being
	 * NULL, during tear down we try to keep driving and therefore we may
	 * have gotten here due to an earlier failure, so there's nothing to do.
	 */
	mp = vnd_dlpi_inc_pop(vsp);
	if (mp == NULL)
		return;

	prim = ((dl_ok_ack_t *)mp->b_rptr)->dl_primitive;
	cprim = ((dl_ok_ack_t *)mp->b_rptr)->dl_correct_primitive;

	if (prim != DL_OK_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp,
		    "wrong dlpi primitive for vnd_st_promiscoff");
		return;
	}

	if (cprim != DL_PROMISCOFF_REQ) {
		vnd_drop_ctl(vsp, mp,
		    "vnd_st_promiscoff: Got ack/nack for wrong primitive");
		return;
	}

	if (prim == DL_ERROR_ACK) {
		cmn_err(CE_WARN, "!failed to disable promiscuos mode during "
		    "vnd teardown");
	}
}

static boolean_t
vnd_st_sunbind(vnd_str_t *vsp)
{
	mblk_t *mp;
	boolean_t ret = B_TRUE;

	mp = vnd_dlpi_alloc(sizeof (dl_unbind_req_t), DL_UNBIND_REQ);
	if (mp == NULL) {
		cmn_err(CE_NOTE, "!vnd failed to allocate mblk_t for "
		    "unbind request");
		ret = B_FALSE;
		goto next;
	}

	putnext(vsp->vns_wq, mp);
next:
	vsp->vns_state = VNS_S_UNBIND_SENT;
	cv_broadcast(&vsp->vns_stcv);
	return (ret);
}

static void
vnd_st_unbind(vnd_str_t *vsp)
{
	mblk_t *mp;
	t_uscalar_t prim, cprim;

	/*
	 * Unlike other cases where we guard against the incoming packet being
	 * NULL, during tear down we try to keep driving and therefore we may
	 * have gotten here due to an earlier failure, so there's nothing to do.
	 */
	mp = vnd_dlpi_inc_pop(vsp);
	if (mp == NULL)
		goto next;

	prim = ((dl_ok_ack_t *)mp->b_rptr)->dl_primitive;
	cprim = ((dl_ok_ack_t *)mp->b_rptr)->dl_correct_primitive;

	if (prim != DL_OK_ACK && prim != DL_ERROR_ACK) {
		vnd_drop_ctl(vsp, mp,
		    "wrong dlpi primitive for vnd_st_unbind");
		goto next;
	}

	if (cprim != DL_UNBIND_REQ) {
		vnd_drop_ctl(vsp, mp,
		    "vnd_st_unbind: Got ack/nack for wrong primitive");
		goto next;
	}

	if (prim == DL_ERROR_ACK) {
		cmn_err(CE_WARN, "!failed to unbind stream during vnd "
		    "teardown");
	}

next:
	vsp->vns_state = VNS_S_ZOMBIE;
	cv_broadcast(&vsp->vns_stcv);
}

/*
 * Perform state transitions. This is a one way shot down the flow chart
 * described in the big theory statement.
 */
static void
vnd_str_state_transition(void *arg)
{
	boolean_t died = B_FALSE;
	vnd_str_t *vsp = arg;
	mblk_t *mp;

	mutex_enter(&vsp->vns_lock);
	if (vsp->vns_dlpi_inc == NULL && (vsp->vns_state != VNS_S_INITIAL &&
	    vsp->vns_state != VNS_S_SHUTTING_DOWN)) {
		mutex_exit(&vsp->vns_lock);
		return;
	}

	/*
	 * When trying to shut down, or unwinding from a failed enabling, rather
	 * than immediately entering the ZOMBIE state, we may instead opt to try
	 * and enter the next state in the progression. This is especially
	 * important when trying to tear everything down.
	 */
loop:
	DTRACE_PROBE2(vnd__state__transition, uintptr_t, vsp,
	    vnd_str_state_t, vsp->vns_state);
	switch (vsp->vns_state) {
	case VNS_S_INITIAL:
		VERIFY(vsp->vns_dlpi_inc == NULL);
		if (vnd_st_sinfo(vsp) != 0)
			died = B_TRUE;
		break;
	case VNS_S_INFO_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_info(vsp) == 0) {
			if (vnd_st_sexclusive(vsp) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_EXCLUSIVE_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_exclusive(vsp) == 0) {
			if (vsp->vns_dlpi_style == DL_STYLE2) {
				if (vnd_st_sattach(vsp) != 0)
					died = B_TRUE;
			} else {
				if (vnd_st_sbind(vsp) != 0)
					died = B_TRUE;
			}
		} else  {
			died = B_TRUE;
		}
		break;
	case VNS_S_ATTACH_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_attach(vsp) == 0) {
			if (vnd_st_sbind(vsp) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_BIND_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_bind(vsp) == 0) {
			if (vnd_st_spromisc(vsp, DL_PROMISC_SAP,
			    VNS_S_SAP_PROMISC_SENT) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_SAP_PROMISC_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_promisc(vsp) == 0) {
			if (vnd_st_spromisc(vsp, DL_PROMISC_MULTI,
			    VNS_S_MULTI_PROMISC_SENT) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_MULTI_PROMISC_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_promisc(vsp) == 0) {
			if (vnd_st_spromisc(vsp, DL_PROMISC_RX_ONLY,
			    VNS_S_RX_ONLY_PROMISC_SENT) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_RX_ONLY_PROMISC_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_promisc(vsp) == 0) {
			if (vnd_st_spromisc(vsp, DL_PROMISC_FIXUPS,
			    VNS_S_FIXUP_PROMISC_SENT) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_FIXUP_PROMISC_SENT:
		VERIFY(vsp->vns_dlpi_inc != NULL);
		if (vnd_st_promisc(vsp) == 0) {
			if (vnd_st_scapabq(vsp) != 0)
				died = B_TRUE;
		} else {
			died = B_TRUE;
		}
		break;
	case VNS_S_CAPAB_Q_SENT:
		if (vnd_st_capabq(vsp) != 0)
			died = B_TRUE;
		else
			vnd_st_sonline(vsp);
		break;
	case VNS_S_SHUTTING_DOWN:
		vnd_st_shutdown(vsp);
		if (vnd_st_spromiscoff(vsp, DL_PROMISC_MULTI,
		    VNS_S_MULTICAST_PROMISCOFF_SENT) == B_FALSE)
			goto loop;
		break;
	case VNS_S_MULTICAST_PROMISCOFF_SENT:
		vnd_st_promiscoff(vsp);
		if (vnd_st_spromiscoff(vsp, DL_PROMISC_SAP,
		    VNS_S_SAP_PROMISCOFF_SENT) == B_FALSE)
			goto loop;
		break;
	case VNS_S_SAP_PROMISCOFF_SENT:
		vnd_st_promiscoff(vsp);
		if (vnd_st_sunbind(vsp) == B_FALSE)
			goto loop;
		break;
	case VNS_S_UNBIND_SENT:
		vnd_st_unbind(vsp);
		break;
	case VNS_S_ZOMBIE:
		while ((mp = vnd_dlpi_inc_pop(vsp)) != NULL)
			vnd_drop_ctl(vsp, mp, "vsp received data as a zombie");
		break;
	default:
		panic("vnd_str_t entered an unknown state");
	}

	if (died == B_TRUE) {
		ASSERT(vsp->vns_errno != VND_E_SUCCESS);
		vsp->vns_laststate = vsp->vns_state;
		vsp->vns_state = VNS_S_ZOMBIE;
		cv_broadcast(&vsp->vns_stcv);
	}

	mutex_exit(&vsp->vns_lock);
}

static void
vnd_dlpi_taskq_dispatch(void *arg)
{
	vnd_str_t *vsp = arg;
	int run = 1;

	while (run != 0) {
		vnd_str_state_transition(vsp);
		mutex_enter(&vsp->vns_lock);
		if (vsp->vns_flags & VNS_F_CONDEMNED ||
		    vsp->vns_dlpi_inc == NULL) {
			run = 0;
			vsp->vns_flags &= ~VNS_F_TASKQ_DISPATCHED;
		}
		if (vsp->vns_flags & VNS_F_CONDEMNED)
			cv_signal(&vsp->vns_cancelcv);
		mutex_exit(&vsp->vns_lock);
	}
}

static int
vnd_neti_getifname(net_handle_t neti, phy_if_t phy, char *buf, const size_t len)
{
	return (-1);
}

static int
vnd_neti_getmtu(net_handle_t neti, phy_if_t phy, lif_if_t ifdata)
{
	return (-1);
}

static int
vnd_neti_getptmue(net_handle_t neti)
{
	return (-1);
}

static int
vnd_neti_getlifaddr(net_handle_t neti, phy_if_t phy, lif_if_t ifdata,
    size_t nelem, net_ifaddr_t type[], void *storage)
{
	return (-1);
}

static int
vnd_neti_getlifzone(net_handle_t neti, phy_if_t phy, lif_if_t ifdata,
    zoneid_t *zid)
{
	return (-1);
}

static int
vnd_neti_getlifflags(net_handle_t neti, phy_if_t phy, lif_if_t ifdata,
    uint64_t *flags)
{
	return (-1);
}

static phy_if_t
vnd_neti_phygetnext(net_handle_t neti, phy_if_t phy)
{
	return (-1);
}

static phy_if_t
vnd_neti_phylookup(net_handle_t neti, const char *name)
{
	return (-1);
}

static lif_if_t
vnd_neti_lifgetnext(net_handle_t neti, phy_if_t phy, lif_if_t ifdata)
{
	return (-1);
}

static int
vnd_neti_inject(net_handle_t neti, inject_t style, net_inject_t *packet)
{
	return (-1);
}

static phy_if_t
vnd_neti_route(net_handle_t neti, struct sockaddr *address,
    struct sockaddr *next)
{
	return ((phy_if_t)-1);
}

static int
vnd_neti_ispchksum(net_handle_t neti, mblk_t *mp)
{
	return (-1);
}

static int
vnd_neti_isvchksum(net_handle_t neti, mblk_t *mp)
{
	return (-1);
}

static net_protocol_t vnd_neti_info_v4 = {
	NETINFO_VERSION,
	NHF_VND_INET,
	vnd_neti_getifname,
	vnd_neti_getmtu,
	vnd_neti_getptmue,
	vnd_neti_getlifaddr,
	vnd_neti_getlifzone,
	vnd_neti_getlifflags,
	vnd_neti_phygetnext,
	vnd_neti_phylookup,
	vnd_neti_lifgetnext,
	vnd_neti_inject,
	vnd_neti_route,
	vnd_neti_ispchksum,
	vnd_neti_isvchksum
};

static net_protocol_t vnd_neti_info_v6 = {
	NETINFO_VERSION,
	NHF_VND_INET6,
	vnd_neti_getifname,
	vnd_neti_getmtu,
	vnd_neti_getptmue,
	vnd_neti_getlifaddr,
	vnd_neti_getlifzone,
	vnd_neti_getlifflags,
	vnd_neti_phygetnext,
	vnd_neti_phylookup,
	vnd_neti_lifgetnext,
	vnd_neti_inject,
	vnd_neti_route,
	vnd_neti_ispchksum,
	vnd_neti_isvchksum
};


static int
vnd_netinfo_init(vnd_pnsd_t *nsp)
{
	nsp->vpnd_neti_v4 = net_protocol_register(nsp->vpnd_nsid,
	    &vnd_neti_info_v4);
	ASSERT(nsp->vpnd_neti_v4 != NULL);

	nsp->vpnd_neti_v6 = net_protocol_register(nsp->vpnd_nsid,
	    &vnd_neti_info_v6);
	ASSERT(nsp->vpnd_neti_v6 != NULL);

	nsp->vpnd_family_v4.hf_version = HOOK_VERSION;
	nsp->vpnd_family_v4.hf_name = "vnd_inet";

	if (net_family_register(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4) != 0) {
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_family_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	nsp->vpnd_family_v6.hf_version = HOOK_VERSION;
	nsp->vpnd_family_v6.hf_name = "vnd_inet6";

	if (net_family_register(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6) != 0) {
		net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_family_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	nsp->vpnd_event_in_v4.he_version = HOOK_VERSION;
	nsp->vpnd_event_in_v4.he_name = NH_PHYSICAL_IN;
	nsp->vpnd_event_in_v4.he_flags = 0;
	nsp->vpnd_event_in_v4.he_interested = B_FALSE;

	nsp->vpnd_token_in_v4 = net_event_register(nsp->vpnd_neti_v4,
	    &nsp->vpnd_event_in_v4);
	if (nsp->vpnd_token_in_v4 == NULL) {
		net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
		net_family_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6);
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_event_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	nsp->vpnd_event_in_v6.he_version = HOOK_VERSION;
	nsp->vpnd_event_in_v6.he_name = NH_PHYSICAL_IN;
	nsp->vpnd_event_in_v6.he_flags = 0;
	nsp->vpnd_event_in_v6.he_interested = B_FALSE;

	nsp->vpnd_token_in_v6 = net_event_register(nsp->vpnd_neti_v6,
	    &nsp->vpnd_event_in_v6);
	if (nsp->vpnd_token_in_v6 == NULL) {
		net_event_shutdown(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_event_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
		net_family_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6);
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_event_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	nsp->vpnd_event_out_v4.he_version = HOOK_VERSION;
	nsp->vpnd_event_out_v4.he_name = NH_PHYSICAL_OUT;
	nsp->vpnd_event_out_v4.he_flags = 0;
	nsp->vpnd_event_out_v4.he_interested = B_FALSE;

	nsp->vpnd_token_out_v4 = net_event_register(nsp->vpnd_neti_v4,
	    &nsp->vpnd_event_out_v4);
	if (nsp->vpnd_token_out_v4 == NULL) {
		net_event_shutdown(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_shutdown(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_event_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
		net_family_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6);
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_event_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	nsp->vpnd_event_out_v6.he_version = HOOK_VERSION;
	nsp->vpnd_event_out_v6.he_name = NH_PHYSICAL_OUT;
	nsp->vpnd_event_out_v6.he_flags = 0;
	nsp->vpnd_event_out_v6.he_interested = B_FALSE;

	nsp->vpnd_token_out_v6 = net_event_register(nsp->vpnd_neti_v6,
	    &nsp->vpnd_event_out_v6);
	if (nsp->vpnd_token_out_v6 == NULL) {
		net_event_shutdown(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_shutdown(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
		net_event_shutdown(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_event_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
		net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
		net_family_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6);
		net_protocol_unregister(nsp->vpnd_neti_v4);
		net_protocol_unregister(nsp->vpnd_neti_v6);
		cmn_err(CE_NOTE, "vnd_netinfo_init: net_event_register "
		    "failed for stack %d", nsp->vpnd_nsid);
		return (1);
	}

	return (0);
}

static void
vnd_netinfo_shutdown(vnd_pnsd_t *nsp)
{
	int ret;

	ret = net_event_shutdown(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
	VERIFY(ret == 0);
	ret = net_event_shutdown(nsp->vpnd_neti_v4, &nsp->vpnd_event_out_v4);
	VERIFY(ret == 0);
	ret = net_event_shutdown(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
	VERIFY(ret == 0);
	ret = net_event_shutdown(nsp->vpnd_neti_v6, &nsp->vpnd_event_out_v6);
	VERIFY(ret == 0);
}

static void
vnd_netinfo_fini(vnd_pnsd_t *nsp)
{
	int ret;

	ret = net_event_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_event_in_v4);
	VERIFY(ret == 0);
	ret = net_event_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_event_out_v4);
	VERIFY(ret == 0);
	ret = net_event_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_event_in_v6);
	VERIFY(ret == 0);
	ret = net_event_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_event_out_v6);
	VERIFY(ret == 0);
	ret = net_family_unregister(nsp->vpnd_neti_v4, &nsp->vpnd_family_v4);
	VERIFY(ret == 0);
	ret = net_family_unregister(nsp->vpnd_neti_v6, &nsp->vpnd_family_v6);
	VERIFY(ret == 0);
	ret = net_protocol_unregister(nsp->vpnd_neti_v4);
	VERIFY(ret == 0);
	ret = net_protocol_unregister(nsp->vpnd_neti_v6);
	VERIFY(ret == 0);
}

static void
vnd_strbarrier_cb(void *arg, mblk_t *bmp, gsqueue_t *gsp, void *dummy)
{
	vnd_str_t *vsp = arg;

	VERIFY(bmp == &vsp->vns_barrierblk);
	mutex_enter(&vsp->vns_lock);
	VERIFY(vsp->vns_flags & VNS_F_BARRIER);
	VERIFY(!(vsp->vns_flags & VNS_F_BARRIER_DONE));
	vsp->vns_flags |= VNS_F_BARRIER_DONE;
	mutex_exit(&vsp->vns_lock);

	/*
	 * For better or worse, we have to broadcast here as we could have a
	 * thread that's blocked for completion as well as one that's blocked
	 * waiting to do a barrier itself.
	 */
	cv_broadcast(&vsp->vns_barriercv);
}

/*
 * This is a data barrier for the stream while it is in fastpath mode. It blocks
 * and ensures that there is nothing else in the squeue.
 */
static void
vnd_strbarrier(vnd_str_t *vsp)
{
	mutex_enter(&vsp->vns_lock);
	while (vsp->vns_flags & VNS_F_BARRIER)
		cv_wait(&vsp->vns_barriercv, &vsp->vns_lock);
	vsp->vns_flags |= VNS_F_BARRIER;
	mutex_exit(&vsp->vns_lock);

	gsqueue_enter_one(vsp->vns_squeue, &vsp->vns_barrierblk,
	    vnd_strbarrier_cb, vsp, GSQUEUE_PROCESS, VND_SQUEUE_TAG_STRBARRIER);

	mutex_enter(&vsp->vns_lock);
	while (!(vsp->vns_flags & VNS_F_BARRIER_DONE))
		cv_wait(&vsp->vns_barriercv, &vsp->vns_lock);
	vsp->vns_flags &= ~VNS_F_BARRIER;
	vsp->vns_flags &= ~VNS_F_BARRIER_DONE;
	mutex_exit(&vsp->vns_lock);

	/*
	 * We have to broadcast in case anyone is waiting for the barrier
	 * themselves.
	 */
	cv_broadcast(&vsp->vns_barriercv);
}

/*
 * Based on the type of message that we're dealing with we're going to want to
 * do one of several things. Basically if it looks like it's something we know
 * about, we should probably handle it in one of our transition threads.
 * Otherwise, we should just simply putnext.
 */
static int
vnd_s_rput(queue_t *q, mblk_t *mp)
{
	t_uscalar_t prim;
	int dispatch = 0;
	vnd_str_t *vsp = q->q_ptr;

	switch (DB_TYPE(mp)) {
	case M_PROTO:
	case M_PCPROTO:
		if (MBLKL(mp) < sizeof (t_uscalar_t)) {
			vnd_drop_ctl(vsp, mp, "PROTO message too short");
			break;
		}

		prim = ((union DL_primitives *)mp->b_rptr)->dl_primitive;
		if (prim == DL_UNITDATA_REQ || prim == DL_UNITDATA_IND) {
			vnd_drop_ctl(vsp, mp,
			    "recieved an unsupported dlpi DATA req");
			break;
		}

		/*
		 * Enqueue the entry and fire off a taskq dispatch.
		 */
		mutex_enter(&vsp->vns_lock);
		vnd_dlpi_inc_push(vsp, mp);
		if (!(vsp->vns_flags & VNS_F_TASKQ_DISPATCHED)) {
			dispatch = 1;
			vsp->vns_flags |= VNS_F_TASKQ_DISPATCHED;
		}
		mutex_exit(&vsp->vns_lock);
		if (dispatch != 0)
			taskq_dispatch_ent(vnd_taskq, vnd_dlpi_taskq_dispatch,
			    vsp, 0, &vsp->vns_tqe);
		break;
	case M_DATA:
		vnd_drop_in(vsp, mp, "M_DATA via put(9E)");
		break;
	default:
		putnext(vsp->vns_rq, mp);
	}
	return (0);
}

static void
vnd_strioctl(queue_t *q, vnd_str_t *vsp, mblk_t *mp, struct iocblk *iocp)
{
	int error;
	vnd_strioc_t *visp;

	if (iocp->ioc_cmd != VND_STRIOC_ASSOCIATE ||
	    iocp->ioc_count != TRANSPARENT) {
		error = EINVAL;
		goto nak;
	}

	/*
	 * All streams ioctls that we support must use kcred as a means to
	 * distinguish that this is a layered open by the kernel as opposed to
	 * one by a user who has done an I_PUSH of the module.
	 */
	if (iocp->ioc_cr != kcred) {
		error = EPERM;
		goto nak;
	}

	if (mp->b_cont == NULL) {
		error = EAGAIN;
		goto nak;
	}

	visp = kmem_alloc(sizeof (vnd_strioc_t), KM_SLEEP);
	ASSERT(MBLKL(mp->b_cont) == sizeof (caddr_t));
	visp->vs_addr = *(caddr_t *)mp->b_cont->b_rptr;
	visp->vs_state = VSS_COPYIN;

	mcopyin(mp, (void *)visp, sizeof (vnd_strioc_associate_t), NULL);
	qreply(q, mp);

	return;

nak:
	if (mp->b_cont != NULL) {
		freemsg(mp->b_cont);
		mp->b_cont = NULL;
	}

	iocp->ioc_error = error;
	mp->b_datap->db_type = M_IOCNAK;
	iocp->ioc_count = 0;
	qreply(q, mp);
}

static void
vnd_striocdata(queue_t *q, vnd_str_t *vsp, mblk_t *mp, struct copyresp *csp)
{
	int error;
	vnd_str_state_t state;
	struct copyreq *crp;
	vnd_strioc_associate_t *vss;
	vnd_dev_t *vdp = NULL;
	vnd_pnsd_t *nsp = NULL;
	char iname[2*VND_NAMELEN];
	zone_t *zone;
	vnd_strioc_t *visp;

	visp = (vnd_strioc_t *)csp->cp_private;

	/* If it's not ours, it's not our problem */
	if (csp->cp_cmd != VND_STRIOC_ASSOCIATE) {
		if (q->q_next != NULL) {
			putnext(q, mp);
		} else {
			VND_STAT_INC(vsp, vks_ndlpidrops, 1);
			VND_STAT_INC(vsp, vks_tdrops, 1);
			vnd_drop_ctl(vsp, mp, "uknown cmd for M_IOCDATA");
		}
		kmem_free(visp, sizeof (vnd_strioc_t));
		return;
	}

	/* The nak is already sent for us */
	if (csp->cp_rval != 0) {
		vnd_drop_ctl(vsp, mp, "M_COPYIN failed");
		kmem_free(visp, sizeof (vnd_strioc_t));
		return;
	}

	/* Data is sitting for us in b_cont */
	if (mp->b_cont == NULL ||
	    MBLKL(mp->b_cont) != sizeof (vnd_strioc_associate_t)) {
		kmem_free(visp, sizeof (vnd_strioc_t));
		miocnak(q, mp, 0, EINVAL);
		return;
	}

	vss = (vnd_strioc_associate_t *)mp->b_cont->b_rptr;
	vdp = vnd_dev_lookup(vss->vsa_minor);
	if (vdp == NULL) {
		error = EIO;
		vss->vsa_errno = VND_E_NODEV;
		goto nak;
	}

	nsp = vnd_nsd_lookup(vss->vsa_nsid);
	if (nsp == NULL) {
		error = EIO;
		vss->vsa_errno = VND_E_NONETSTACK;
		goto nak;
	}

	mutex_enter(&vsp->vns_lock);
	if (!(vsp->vns_flags & VNS_F_NEED_ZONE)) {
		mutex_exit(&vsp->vns_lock);
		error = EEXIST;
		vss->vsa_errno = VND_E_ASSOCIATED;
		goto nak;
	}

	vsp->vns_nsd = nsp;
	vsp->vns_flags &= ~VNS_F_NEED_ZONE;
	vsp->vns_flags |= VNS_F_TASKQ_DISPATCHED;
	mutex_exit(&vsp->vns_lock);

	taskq_dispatch_ent(vnd_taskq, vnd_dlpi_taskq_dispatch, vsp, 0,
	    &vsp->vns_tqe);


	/* At this point we need to wait until we have transitioned to ONLINE */
	mutex_enter(&vsp->vns_lock);
	while (vsp->vns_state != VNS_S_ONLINE && vsp->vns_state != VNS_S_ZOMBIE)
		cv_wait(&vsp->vns_stcv, &vsp->vns_lock);
	state = vsp->vns_state;
	mutex_exit(&vsp->vns_lock);

	if (state == VNS_S_ZOMBIE) {
		vss->vsa_errno = vsp->vns_errno;
		error = EIO;
		goto nak;
	}

	mutex_enter(&vdp->vdd_lock);
	mutex_enter(&vsp->vns_lock);
	VERIFY(vdp->vdd_str == NULL);
	/*
	 * Now initialize the remaining kstat properties and let's go ahead and
	 * create it.
	 */
	(void) snprintf(iname, sizeof (iname), "z%d_%d",
	    vdp->vdd_nsd->vpnd_zid, vdp->vdd_minor);
	vsp->vns_kstat = kstat_create_zone("vnd", vdp->vdd_minor, iname, "net",
	    KSTAT_TYPE_NAMED, sizeof (vnd_str_stat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, GLOBAL_ZONEID);
	if (vsp->vns_kstat == NULL) {
		error = EIO;
		vss->vsa_errno = VND_E_KSTATCREATE;
		mutex_exit(&vsp->vns_lock);
		mutex_exit(&vdp->vdd_lock);
		goto nak;
	}
	vdp->vdd_str = vsp;
	vsp->vns_dev = vdp;

	/*
	 * Now, it's time to do the las thing that can fail, changing out the
	 * input function. After this we know that we can receive data, so we
	 * should make sure that we're ready.
	 */
	if (vnd_dld_cap_enable(vsp, vnd_mac_input) != 0) {
		error = EIO;
		vss->vsa_errno = VND_E_DIRECTFAIL;
		vdp->vdd_str = NULL;
		vsp->vns_dev = NULL;
		mutex_exit(&vsp->vns_lock);
		mutex_exit(&vdp->vdd_lock);
		goto nak;
	}

	zone = zone_find_by_id(vdp->vdd_nsd->vpnd_zid);
	ASSERT(zone != NULL);
	vsp->vns_kstat->ks_data = &vsp->vns_ksdata;
	/* Account for zone name */
	vsp->vns_kstat->ks_data_size += strlen(zone->zone_name) + 1;
	/* Account for eventual link name */
	vsp->vns_kstat->ks_data_size += VND_NAMELEN;
	kstat_named_setstr(&vsp->vns_ksdata.vks_zonename, zone->zone_name);
	kstat_named_setstr(&vdp->vdd_str->vns_ksdata.vks_linkname,
	    vdp->vdd_lname);
	zone_rele(zone);
	kstat_install(vsp->vns_kstat);

	mutex_exit(&vsp->vns_lock);
	mutex_exit(&vdp->vdd_lock);

	/*
	 * Note that the vnd_str_t does not keep a permanent hold on the
	 * vnd_pnsd_t. We leave that up to the vnd_dev_t as that's also what
	 * the nestack goes through to take care of everything.
	 */
	vss->vsa_errno = VND_E_SUCCESS;
nak:
	if (vdp != NULL)
		vnd_dev_rele(vdp);
	if (nsp != NULL)
		vnd_nsd_rele(nsp);
	/*
	 * Change the copyin request to a copyout. Note that we can't use
	 * mcopyout here as it only works when the DB_TYPE is M_IOCTL. That's
	 * okay, as the copyin vs. copyout is basically the same.
	 */
	DB_TYPE(mp) = M_COPYOUT;
	visp->vs_state = VSS_COPYOUT;
	crp = (struct copyreq *)mp->b_rptr;
	crp->cq_private = (void *)visp;
	crp->cq_addr = visp->vs_addr;
	crp->cq_size = sizeof (vnd_strioc_associate_t);
	qreply(q, mp);
}

static void
vnd_stroutdata(queue_t *q, vnd_str_t *vsp, mblk_t *mp, struct copyresp *csp)
{
	ASSERT(csp->cp_private != NULL);
	kmem_free(csp->cp_private, sizeof (vnd_strioc_t));
	if (csp->cp_cmd != VND_STRIOC_ASSOCIATE) {
		if (q->q_next != NULL) {
			putnext(q, mp);
		} else {
			VND_STAT_INC(vsp, vks_ndlpidrops, 1);
			VND_STAT_INC(vsp, vks_tdrops, 1);
			vnd_drop_ctl(vsp, mp, "uknown cmd for M_IOCDATA");
		}
		return;
	}

	/* The nak is already sent for us */
	if (csp->cp_rval != 0) {
		vnd_drop_ctl(vsp, mp, "M_COPYOUT failed");
		return;
	}

	/* Ack and let's be done with it all */
	miocack(q, mp, 0, 0);
}

static int
vnd_s_wput(queue_t *q, mblk_t *mp)
{
	vnd_str_t *vsp = q->q_ptr;
	struct copyresp *crp;
	vnd_strioc_state_t vstate;
	vnd_strioc_t *visp;

	switch (DB_TYPE(mp)) {
	case M_IOCTL:
		vnd_strioctl(q, vsp, mp, (struct iocblk *)mp->b_rptr);
		return (0);
	case M_IOCDATA:
		crp = (struct copyresp *)mp->b_rptr;
		ASSERT(crp->cp_private != NULL);
		visp = (vnd_strioc_t *)crp->cp_private;
		vstate = visp->vs_state;
		ASSERT(vstate == VSS_COPYIN || vstate == VSS_COPYOUT);
		if (vstate == VSS_COPYIN)
			vnd_striocdata(q, vsp, mp,
			    (struct copyresp *)mp->b_rptr);
		else
			vnd_stroutdata(q, vsp, mp,
			    (struct copyresp *)mp->b_rptr);
		return (0);
	default:
		break;
	}
	if (q->q_next != NULL)
		putnext(q, mp);
	else
		vnd_drop_ctl(vsp, mp, "!M_IOCTL in wput");

	return (0);
}

static int
vnd_s_open(queue_t *q, dev_t *devp, int oflag, int sflag, cred_t *credp)
{
	vnd_str_t *vsp;
	uint_t rand;

	if (q->q_ptr != NULL)
		return (EINVAL);

	if (!(sflag & MODOPEN))
		return (ENXIO);

	if (credp != kcred)
		return (EPERM);

	vsp = kmem_cache_alloc(vnd_str_cache, KM_SLEEP);
	bzero(vsp, sizeof (*vsp));
	mutex_init(&vsp->vns_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&vsp->vns_cancelcv, NULL, CV_DRIVER, NULL);
	cv_init(&vsp->vns_barriercv, NULL, CV_DRIVER, NULL);
	cv_init(&vsp->vns_stcv, NULL, CV_DRIVER, NULL);
	vsp->vns_state = VNS_S_INITIAL;

	mutex_init(&vsp->vns_dq_read.vdq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&vsp->vns_dq_write.vdq_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_enter(&vnd_dev_lock);
	vsp->vns_dq_read.vdq_max = vnd_vdq_default_size;
	vsp->vns_dq_read.vdq_vns = vsp;
	vsp->vns_dq_write.vdq_max = vnd_vdq_default_size;
	vsp->vns_dq_write.vdq_vns = vsp;
	mutex_exit(&vnd_dev_lock);
	vsp->vns_rq = q;
	vsp->vns_wq = WR(q);
	q->q_ptr = WR(q)->q_ptr = vsp;
	vsp->vns_flags = VNS_F_NEED_ZONE;
	vsp->vns_nflush = vnd_flush_nburst;
	vsp->vns_bsize = vnd_flush_burst_size;

	(void) random_get_pseudo_bytes((uint8_t *)&rand, sizeof (rand));
	vsp->vns_squeue = gsqueue_set_get(vnd_sqset, rand);

	/*
	 * We create our kstat and initialize all of its fields now, but we
	 * don't install it until we actually do the zone association so we can
	 * get everything.
	 */
	kstat_named_init(&vsp->vns_ksdata.vks_rbytes, "rbytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_rpackets, "rpackets",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_obytes, "obytes",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_opackets, "opackets",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_nhookindrops, "nhookindrops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_nhookoutdrops, "nhookoutdrops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_ndlpidrops, "ndlpidrops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_ndataindrops, "ndataindrops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_ndataoutdrops, "ndataoutdrops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_tdrops, "total_drops",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_linkname, "linkname",
	    KSTAT_DATA_STRING);
	kstat_named_init(&vsp->vns_ksdata.vks_zonename, "zonename",
	    KSTAT_DATA_STRING);
	kstat_named_init(&vsp->vns_ksdata.vks_nmacflow, "flowcontrol_events",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_tmacflow, "flowcontrol_time",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_mac_flow_1ms, "flowcontrol_1ms",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_mac_flow_10ms, "flowcontrol_10ms",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_mac_flow_100ms,
	    "flowcontrol_100ms", KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_mac_flow_1s, "flowcontrol_1s",
	    KSTAT_DATA_UINT64);
	kstat_named_init(&vsp->vns_ksdata.vks_mac_flow_10s, "flowcontrol_10s",
	    KSTAT_DATA_UINT64);
	qprocson(q);
	/*
	 * Now that we've called qprocson, grab the lower module for making sure
	 * that we don't have any pass through modules.
	 */
	vsp->vns_lrq = RD(vsp->vns_wq->q_next);

	return (0);
}

static int
vnd_s_close(queue_t *q, int flag, cred_t *credp)
{
	vnd_str_t *vsp;
	mblk_t *mp;

	VERIFY(WR(q)->q_next != NULL);

	vsp = q->q_ptr;
	ASSERT(vsp != NULL);

	/*
	 * We need to transition ourselves down.  This means that we have a few
	 * important different things to do in the process of tearing down our
	 * input and output buffers, making sure we've drained the current
	 * squeue, and disabling the fast path. Before we disable the fast path,
	 * we should make sure the squeue is drained. Because we're in streams
	 * close, we know that no packets can come into us from userland, but we
	 * can receive more. As such, the following is the exact order of things
	 * that we do:
	 *
	 * 1) flush the vns_dq_read
	 * 2) Insert the drain mblk
	 * 3) When it's been received, tear down the fast path by kicking
	 * off the state machine.
	 * 4) One final flush of both the vns_dq_read,vns_dq_write
	 */

	vnd_dq_flush(&vsp->vns_dq_read, vnd_drop_in);
	vnd_strbarrier(vsp);
	mutex_enter(&vsp->vns_lock);
	vsp->vns_state = VNS_S_SHUTTING_DOWN;
	if (!(vsp->vns_flags & VNS_F_TASKQ_DISPATCHED)) {
		vsp->vns_flags |= VNS_F_TASKQ_DISPATCHED;
		taskq_dispatch_ent(vnd_taskq, vnd_dlpi_taskq_dispatch, vsp,
		    0, &vsp->vns_tqe);
	}
	while (vsp->vns_state != VNS_S_ZOMBIE)
		cv_wait(&vsp->vns_stcv, &vsp->vns_lock);
	mutex_exit(&vsp->vns_lock);

	qprocsoff(q);
	mutex_enter(&vsp->vns_lock);
	vsp->vns_flags |= VNS_F_CONDEMNED;
	while (vsp->vns_flags & VNS_F_TASKQ_DISPATCHED)
		cv_wait(&vsp->vns_cancelcv, &vsp->vns_lock);

	while ((mp = vnd_dlpi_inc_pop(vsp)) != NULL)
		vnd_drop_ctl(vsp, mp, "vnd_s_close");
	mutex_exit(&vsp->vns_lock);

	q->q_ptr = NULL;
	vnd_dq_flush(&vsp->vns_dq_read, vnd_drop_in);
	vnd_dq_flush(&vsp->vns_dq_write, vnd_drop_out);
	mutex_destroy(&vsp->vns_dq_read.vdq_lock);
	mutex_destroy(&vsp->vns_dq_write.vdq_lock);

	if (vsp->vns_kstat != NULL)
		kstat_delete(vsp->vns_kstat);
	mutex_destroy(&vsp->vns_lock);
	cv_destroy(&vsp->vns_stcv);
	cv_destroy(&vsp->vns_barriercv);
	cv_destroy(&vsp->vns_cancelcv);
	kmem_cache_free(vnd_str_cache, vsp);

	return (0);
}

static vnd_mac_cookie_t
vnd_squeue_tx_one(vnd_str_t *vsp, mblk_t *mp)
{
	hrtime_t txtime;
	vnd_mac_cookie_t vc;

	VND_STAT_INC(vsp, vks_opackets, 1);
	VND_STAT_INC(vsp, vks_obytes, msgsize(mp));
	DTRACE_VND5(send, mblk_t *, mp, void *, NULL, void *, NULL,
	    vnd_str_t *, vsp, mblk_t *, mp);
	/* Actually tx now */
	txtime = gethrtime();
	vc = vsp->vns_caps.vsc_tx_f(vsp->vns_caps.vsc_tx_hdl,
	    mp, 0, MAC_DROP_ON_NO_DESC);

	/*
	 * We need to check two different conditions before we immediately set
	 * the flow control lock. The first thing that we need to do is verify
	 * that this is an instance of hard flow control, so to say. The flow
	 * control callbacks won't always fire in cases where we still get a
	 * cookie returned. The explicit check for flow control will guarantee
	 * us that we'll get a subsequent notification callback.
	 *
	 * The second case comes about because we do not hold the
	 * vnd_str_t`vns_lock across calls to tx, we need to determine if a flow
	 * control notification already came across for us in a different thread
	 * calling vnd_mac_flow_control(). To deal with this, we record a
	 * timestamp every time that we change the flow control state. We grab
	 * txtime here before we transmit because that guarantees that the
	 * hrtime_t of the call to vnd_mac_flow_control() will be after txtime.
	 *
	 * If the flow control notification beat us to the punch, the value of
	 * vns_fcupdate will be larger than the value of txtime, and we should
	 * just record the statistics. However, if we didn't beat it to the
	 * punch (txtime > vns_fcupdate), then we know that it's safe to wait
	 * for a notification.
	 */
	if (vc != NULL) {
		hrtime_t diff;

		if (vsp->vns_caps.vsc_is_fc_f(vsp->vns_caps.vsc_is_fc_hdl,
		    vc) == 0)
			return (NULL);
		mutex_enter(&vsp->vns_lock);
		diff = vsp->vns_fcupdate - txtime;
		if (diff > 0) {
			mutex_exit(&vsp->vns_lock);
			vnd_mac_flow_control_stat(vsp, diff);
			return (NULL);
		}
		vsp->vns_flags |= VNS_F_FLOW_CONTROLLED;
		vsp->vns_caps.vsc_fc_cookie = vc;
		vsp->vns_fclatch = txtime;
		vsp->vns_fcupdate = txtime;
		DTRACE_VND3(flow__blocked, vnd_str_t *, vsp,
		    uint64_t, vsp->vns_dq_write.vdq_cur, uintptr_t, vc);
		mutex_exit(&vsp->vns_lock);
	}

	return (vc);
}

static void
vnd_squeue_tx_drain(void *arg, mblk_t *drain_mp, gsqueue_t *gsp, void *dummy)
{
	mblk_t *mp;
	int nmps;
	size_t mptot, nflush, bsize;
	boolean_t blocked, empty;
	vnd_data_queue_t *vqp;
	vnd_str_t *vsp = arg;

	mutex_enter(&vsp->vns_lock);
	/*
	 * We either enter here via an squeue or via vnd_squeue_tx_append(). In
	 * the former case we need to mark that there is no longer an active
	 * user of the drain block.
	 */
	if (drain_mp != NULL) {
		VERIFY(drain_mp == &vsp->vns_drainblk);
		VERIFY(vsp->vns_flags & VNS_F_DRAIN_SCHEDULED);
		vsp->vns_flags &= ~VNS_F_DRAIN_SCHEDULED;
	}

	/*
	 * If we're still flow controlled or under a flush barrier, nothing to
	 * do.
	 */
	if (vsp->vns_flags & (VNS_F_FLOW_CONTROLLED | VNS_F_BARRIER)) {
		mutex_exit(&vsp->vns_lock);
		return;
	}

	nflush = vsp->vns_nflush;
	bsize = vsp->vns_bsize;
	mutex_exit(&vsp->vns_lock);

	nmps = 0;
	mptot = 0;
	blocked = B_FALSE;
	vqp = &vsp->vns_dq_write;
	while (nmps < nflush && mptot <= bsize) {
		mutex_enter(&vqp->vdq_lock);
		if (vnd_dq_pop(vqp, &mp) == 0) {
			mutex_exit(&vqp->vdq_lock);
			break;
		}
		mutex_exit(&vqp->vdq_lock);

		nmps++;
		mptot += msgsize(mp);
		if (vnd_squeue_tx_one(vsp, mp) != NULL) {
			blocked = B_TRUE;
			break;
		}
	}

	empty = vnd_dq_is_empty(&vsp->vns_dq_write);

	/*
	 * If the queue is not empty, we're not blocked, and there isn't a drain
	 * scheduled, put it into the squeue with the drain block and
	 * GSQUEUE_FILL.
	 */
	if (blocked == B_FALSE && empty == B_FALSE) {
		mutex_enter(&vsp->vns_lock);
		if (!(vsp->vns_flags & VNS_F_DRAIN_SCHEDULED)) {
			mblk_t *mp = &vsp->vns_drainblk;
			vsp->vns_flags |= VNS_F_DRAIN_SCHEDULED;
			gsqueue_enter_one(vsp->vns_squeue,
			    mp, vnd_squeue_tx_drain, vsp,
			    GSQUEUE_FILL, VND_SQUEUE_TAG_TX_DRAIN);
		}
		mutex_exit(&vsp->vns_lock);
	}

	/*
	 * If we drained some amount of data, we need to signal the data queue.
	 */
	if (nmps > 0) {
		cv_broadcast(&vsp->vns_dq_write.vdq_ready);
		pollwakeup(&vsp->vns_dev->vdd_ph, POLLOUT);
	}
}

static void
vnd_squeue_tx_append(void *arg, mblk_t *mp, gsqueue_t *gsp, void *dummy)
{
	vnd_str_t *vsp = arg;
	vnd_data_queue_t *vqp = &vsp->vns_dq_write;
	vnd_pnsd_t *nsp = vsp->vns_nsd;
	size_t len = msgsize(mp);

	/*
	 * Before we append this packet, we should run it through the firewall
	 * rules.
	 */
	if (nsp->vpnd_hooked && vnd_hook(vsp, &mp, nsp->vpnd_neti_v4,
	    nsp->vpnd_event_out_v4, nsp->vpnd_token_out_v4, nsp->vpnd_neti_v6,
	    nsp->vpnd_event_out_v6, nsp->vpnd_token_out_v6, vnd_drop_hook_out,
	    vnd_drop_out) != 0) {
		/*
		 * Because we earlier reserved space for this packet and it's
		 * not making the cut, we need to go through and unreserve that
		 * space. Also note that the message block will likely be freed
		 * by the time we return from vnd_hook so we cannot rely on it.
		 */
		mutex_enter(&vqp->vdq_lock);
		vnd_dq_unreserve(vqp, len);
		mutex_exit(&vqp->vdq_lock);
		return;
	}

	/*
	 * We earlier reserved space for this packet. So for now simply append
	 * it and call drain. We know that no other drain can be going on right
	 * now thanks to the squeue.
	 */
	mutex_enter(&vqp->vdq_lock);
	(void) vnd_dq_push(&vsp->vns_dq_write, mp, B_TRUE, vnd_drop_panic);
	mutex_exit(&vqp->vdq_lock);
	vnd_squeue_tx_drain(vsp, NULL, NULL, NULL);
}

/*
 * We need to see if this is a valid name of sorts for us. That means a few
 * things. First off, we can't assume that what we've been given has actually
 * been null terminated. More importantly, that it's a valid name as far as
 * ddi_create_minor_node is concerned (that means no '@', '/', or ' '). We
 * further constrain ourselves to simply alphanumeric characters and a few
 * additional ones, ':', '-', and '_'.
 */
static int
vnd_validate_name(const char *buf, size_t buflen)
{
	int i, len;

	/* First make sure a null terminator exists */
	for (i = 0; i < buflen; i++)
		if (buf[i] == '\0')
			break;
	len = i;
	if (i == 0 || i == buflen)
		return (0);

	for (i = 0; i < len; i++)
		if (!isalnum(buf[i]) && buf[i] != ':' && buf[i] != '-' &&
		    buf[i] != '_')
			return (0);

	return (1);
}

static int
vnd_ioctl_attach(vnd_dev_t *vdp, uintptr_t arg, cred_t *credp, int cpflag)
{
	vnd_ioc_attach_t via;
	vnd_strioc_associate_t vss;
	vnd_pnsd_t *nsp;
	zone_t *zonep;
	zoneid_t zid;
	char buf[2*VND_NAMELEN];
	int ret, rp;

	if (secpolicy_net_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (secpolicy_net_rawaccess(credp) != 0)
		return (EPERM);

	if (ddi_copyin((void *)arg, &via, sizeof (via), cpflag) != 0)
		return (EFAULT);
	via.via_errno = VND_E_SUCCESS;

	if (vnd_validate_name(via.via_name, VND_NAMELEN) == 0) {
		via.via_errno = VND_E_BADNAME;
		ret = EIO;
		goto errcopyout;
	}

	/*
	 * Only the global zone can request to create a device in a different
	 * zone.
	 */
	zid = crgetzoneid(credp);
	if (zid != GLOBAL_ZONEID && via.via_zoneid != -1 &&
	    zid != via.via_zoneid) {
		via.via_errno = VND_E_PERM;
		ret = EIO;
		goto errcopyout;
	}

	if (via.via_zoneid == -1)
		via.via_zoneid = zid;

	/*
	 * Establish the name we'll use now. We want to be extra paranoid about
	 * the device we're opening so check that now.
	 */
	if (zid == GLOBAL_ZONEID && via.via_zoneid != zid) {
		zonep = zone_find_by_id(via.via_zoneid);
		if (zonep == NULL) {
			via.via_errno = VND_E_NOZONE;
			ret = EIO;
			goto errcopyout;
		}
		if (snprintf(NULL, 0, "/dev/net/zone/%s/%s", zonep->zone_name,
		    via.via_name) >= sizeof (buf)) {
			zone_rele(zonep);
			via.via_errno = VND_E_BADNAME;
			ret = EIO;
			goto errcopyout;
		}
		(void) snprintf(buf, sizeof (buf), "/dev/net/zone/%s/%s",
		    zonep->zone_name, via.via_name);
		zone_rele(zonep);
		zonep = NULL;
	} else {
		if (snprintf(NULL, 0, "/dev/net/%s", via.via_name) >=
		    sizeof (buf)) {
			via.via_errno = VND_E_BADNAME;
			ret = EIO;
			goto errcopyout;
		}
		(void) snprintf(buf, sizeof (buf), "/dev/net/%s", via.via_name);
	}

	/*
	 * If our zone is dying then the netstack will have been removed from
	 * this list.
	 */
	nsp = vnd_nsd_lookup_by_zid(via.via_zoneid);
	if (nsp == NULL) {
		via.via_errno = VND_E_NOZONE;
		ret = EIO;
		goto errcopyout;
	}

	/*
	 * Note we set the attached handle even though we haven't actually
	 * finished the process of attaching the ldi handle.
	 */
	mutex_enter(&vdp->vdd_lock);
	if (vdp->vdd_flags & (VND_D_ATTACHED | VND_D_ATTACH_INFLIGHT)) {
		mutex_exit(&vdp->vdd_lock);
		vnd_nsd_rele(nsp);
		via.via_errno = VND_E_ATTACHED;
		ret = EIO;
		goto errcopyout;
	}
	vdp->vdd_flags |= VND_D_ATTACH_INFLIGHT;
	ASSERT(vdp->vdd_cr == NULL);
	crhold(credp);
	vdp->vdd_cr = credp;
	ASSERT(vdp->vdd_nsd == NULL);
	vdp->vdd_nsd = nsp;
	mutex_exit(&vdp->vdd_lock);

	/*
	 * Place an additional hold on the vnd_pnsd_t as we go through and do
	 * all of the rest of our work. This will be the hold that we keep for
	 * as long as this thing is attached.
	 */
	vnd_nsd_ref(nsp);

	ret = ldi_open_by_name(buf, FREAD | FWRITE, vdp->vdd_cr,
	    &vdp->vdd_ldih, vdp->vdd_ldiid);
	if (ret != 0) {
		if (ret == ENODEV)
			via.via_errno = VND_E_NODATALINK;
		goto err;
	}

	/*
	 * Unfortunately the I_PUSH interface doesn't allow us a way to detect
	 * whether or not we're coming in from a layered device. We really want
	 * to make sure that a normal user can't push on our streams module.
	 * Currently the only idea I have for this is to make sure that the
	 * credp is kcred which is really terrible.
	 */
	ret = ldi_ioctl(vdp->vdd_ldih, I_PUSH, (intptr_t)"vnd", FKIOCTL,
	    kcred, &rp);
	if (ret != 0) {
		rp = ldi_close(vdp->vdd_ldih, FREAD | FWRITE, vdp->vdd_cr);
		VERIFY(rp == 0);
		via.via_errno = VND_E_STRINIT;
		ret = EIO;
		goto err;
	}

	vss.vsa_minor = vdp->vdd_minor;
	vss.vsa_nsid = nsp->vpnd_nsid;

	ret = ldi_ioctl(vdp->vdd_ldih, VND_STRIOC_ASSOCIATE, (intptr_t)&vss,
	    FKIOCTL, kcred, &rp);
	if (ret != 0 || vss.vsa_errno != VND_E_SUCCESS) {
		rp = ldi_close(vdp->vdd_ldih, FREAD | FWRITE, vdp->vdd_cr);
		VERIFY(rp == 0);
		if (ret == 0) {
			via.via_errno = vss.vsa_errno;
			ret = EIO;
		}
		goto err;
	}

	mutex_enter(&vdp->vdd_nsd->vpnd_lock);

	/*
	 * There's a chance that our netstack was condemned while we've had a
	 * hold on it. As such we need to check and if so, error out.
	 */
	if (vdp->vdd_nsd->vpnd_flags & VND_NS_CONDEMNED) {
		mutex_exit(&vdp->vdd_nsd->vpnd_lock);
		rp = ldi_close(vdp->vdd_ldih, FREAD | FWRITE, vdp->vdd_cr);
		VERIFY(rp == 0);
		ret = EIO;
		via.via_errno = VND_E_NOZONE;
		goto err;
	}

	mutex_enter(&vdp->vdd_lock);
	VERIFY(vdp->vdd_str != NULL);
	vdp->vdd_flags &= ~VND_D_ATTACH_INFLIGHT;
	vdp->vdd_flags |= VND_D_ATTACHED;
	(void) strlcpy(vdp->vdd_datalink, via.via_name,
	    sizeof (vdp->vdd_datalink));
	list_insert_tail(&vdp->vdd_nsd->vpnd_dev_list, vdp);
	mutex_exit(&vdp->vdd_lock);
	mutex_exit(&vdp->vdd_nsd->vpnd_lock);
	vnd_nsd_rele(nsp);

	return (0);

err:
	mutex_enter(&vdp->vdd_lock);
	vdp->vdd_flags &= ~VND_D_ATTACH_INFLIGHT;
	crfree(vdp->vdd_cr);
	vdp->vdd_cr = NULL;
	vdp->vdd_nsd = NULL;
	mutex_exit(&vdp->vdd_lock);

	/*
	 * We have two holds to drop here. One for our original reference and
	 * one for the hold this operation would have represented.
	 */
	vnd_nsd_rele(nsp);
	vnd_nsd_rele(nsp);
errcopyout:
	if (ddi_copyout(&via, (void *)arg, sizeof (via), cpflag) != 0)
		ret = EFAULT;

	return (ret);
}

static int
vnd_ioctl_link(vnd_dev_t *vdp, intptr_t arg, cred_t *credp, int cpflag)
{
	int ret = 0;
	vnd_ioc_link_t vil;
	char mname[2*VND_NAMELEN];
	char **c;
	vnd_dev_t *v;
	zoneid_t zid;

	/* Not anyone can link something */
	if (secpolicy_net_config(credp, B_FALSE) != 0)
		return (EPERM);

	if (ddi_copyin((void *)arg, &vil, sizeof (vil), cpflag) != 0)
		return (EFAULT);

	if (vnd_validate_name(vil.vil_name, VND_NAMELEN) == 0) {
		ret = EIO;
		vil.vil_errno = VND_E_BADNAME;
		goto errcopyout;
	}

	c = vnd_reserved_names;
	while (*c != NULL) {
		if (strcmp(vil.vil_name, *c) == 0) {
			ret = EIO;
			vil.vil_errno = VND_E_BADNAME;
			goto errcopyout;
		}
		c++;
	}

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		ret = EIO;
		vil.vil_errno = VND_E_NOTATTACHED;
		goto errcopyout;
	}

	if (vdp->vdd_flags & VND_D_ZONE_DYING) {
		mutex_exit(&vdp->vdd_lock);
		ret = EIO;
		vil.vil_errno = VND_E_NOZONE;
		goto errcopyout;
	}

	if (vdp->vdd_flags & (VND_D_LINK_INFLIGHT | VND_D_LINKED)) {
		mutex_exit(&vdp->vdd_lock);
		ret = EIO;
		vil.vil_errno = VND_E_LINKED;
		goto errcopyout;
	}
	vdp->vdd_flags |= VND_D_LINK_INFLIGHT;
	zid = vdp->vdd_nsd->vpnd_zid;
	mutex_exit(&vdp->vdd_lock);

	if (snprintf(NULL, 0, "z%d:%s", zid, vil.vil_name) >=
	    sizeof (mname)) {
		ret = EIO;
		vil.vil_errno = VND_E_BADNAME;
		goto errcopyout;
	}

	mutex_enter(&vnd_dev_lock);
	for (v = list_head(&vnd_dev_list); v != NULL;
	    v = list_next(&vnd_dev_list, v)) {
		if (!(v->vdd_flags & VND_D_LINKED))
			continue;

		if (v->vdd_nsd->vpnd_zid == zid &&
		    strcmp(v->vdd_lname, vil.vil_name) == 0) {
			mutex_exit(&vnd_dev_lock);
			ret = EIO;
			vil.vil_errno = VND_E_LINKEXISTS;
			goto error;
		}
	}

	/*
	 * We set the name and mark ourselves attached while holding the list
	 * lock to ensure that no other user can mistakingly find our name.
	 */
	(void) snprintf(mname, sizeof (mname), "z%d:%s", zid,
	    vil.vil_name);
	mutex_enter(&vdp->vdd_lock);

	/*
	 * Because we dropped our lock, we need to double check whether or not
	 * the zone was marked as dying while we were here. If it hasn't, then
	 * it's safe for us to link it in.
	 */
	if (vdp->vdd_flags & VND_D_ZONE_DYING) {
		mutex_exit(&vdp->vdd_lock);
		mutex_exit(&vnd_dev_lock);
		ret = EIO;
		vil.vil_errno = VND_E_NOZONE;
		goto error;
	}

	(void) strlcpy(vdp->vdd_lname, vil.vil_name, sizeof (vdp->vdd_lname));
	if (ddi_create_minor_node(vnd_dip, mname, S_IFCHR, vdp->vdd_minor,
	    DDI_PSEUDO, 0) != DDI_SUCCESS) {
		ret = EIO;
		vil.vil_errno = VND_E_MINORNODE;
	} else {
		vdp->vdd_flags &= ~VND_D_LINK_INFLIGHT;
		vdp->vdd_flags |= VND_D_LINKED;
		kstat_named_setstr(&vdp->vdd_str->vns_ksdata.vks_linkname,
		    vdp->vdd_lname);
		ret = 0;
	}
	mutex_exit(&vdp->vdd_lock);
	mutex_exit(&vnd_dev_lock);

	if (ret == 0) {
		/*
		 * Add a reference to represent that this device is linked into
		 * the file system name space to ensure that it doesn't
		 * disappear.
		 */
		vnd_dev_ref(vdp);
		return (0);
	}

error:
	mutex_enter(&vdp->vdd_lock);
	vdp->vdd_flags &= ~VND_D_LINK_INFLIGHT;
	vdp->vdd_lname[0] = '\0';
	mutex_exit(&vdp->vdd_lock);

errcopyout:
	if (ddi_copyout(&vil, (void *)arg, sizeof (vil), cpflag) != 0)
		ret = EFAULT;
	return (ret);
}

/*
 * Common unlink function. This is used both from the ioctl path and from the
 * netstack shutdown path. The caller is required to hold the mutex on the
 * vnd_dev_t, but they basically will have it relinquished for them. The only
 * thing the caller is allowed to do afterward is to potentially rele the
 * vnd_dev_t if they have their own hold. Note that only the ioctl path has its
 * own hold.
 */
static void
vnd_dev_unlink(vnd_dev_t *vdp)
{
	char mname[2*VND_NAMELEN];

	ASSERT(MUTEX_HELD(&vdp->vdd_lock));

	(void) snprintf(mname, sizeof (mname), "z%d:%s",
	    vdp->vdd_nsd->vpnd_zid, vdp->vdd_lname);
	ddi_remove_minor_node(vnd_dip, mname);
	vdp->vdd_lname[0] = '\0';
	vdp->vdd_flags &= ~VND_D_LINKED;
	kstat_named_setstr(&vdp->vdd_str->vns_ksdata.vks_linkname,
	    vdp->vdd_lname);
	mutex_exit(&vdp->vdd_lock);

	/*
	 * This rele corresponds to the reference that we took in
	 * vnd_ioctl_link.
	 */
	vnd_dev_rele(vdp);
}

static int
vnd_ioctl_unlink(vnd_dev_t *vdp, intptr_t arg, cred_t *credp, int cpflag)
{
	int ret;
	zoneid_t zid;
	vnd_ioc_unlink_t viu;

	/* Not anyone can unlink something */
	if (secpolicy_net_config(credp, B_FALSE) != 0)
		return (EPERM);

	zid = crgetzoneid(credp);

	if (ddi_copyin((void *)arg, &viu, sizeof (viu), cpflag) != 0)
		return (EFAULT);

	viu.viu_errno = VND_E_SUCCESS;

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_LINKED)) {
		mutex_exit(&vdp->vdd_lock);
		ret = EIO;
		viu.viu_errno = VND_E_NOTLINKED;
		goto err;
	}
	VERIFY(vdp->vdd_flags & VND_D_ATTACHED);

	if (zid != GLOBAL_ZONEID && zid != vdp->vdd_nsd->vpnd_zid) {
		mutex_exit(&vdp->vdd_lock);
		ret = EIO;
		viu.viu_errno = VND_E_PERM;
		goto err;
	}

	/* vnd_dev_unlink releases the vdp mutex for us */
	vnd_dev_unlink(vdp);
	ret = 0;
err:
	if (ddi_copyout(&viu, (void *)arg, sizeof (viu), cpflag) != 0)
		return (EFAULT);

	return (ret);
}

static int
vnd_ioctl_setrxbuf(vnd_dev_t *vdp, intptr_t arg, int cpflag)
{
	int ret;
	vnd_ioc_buf_t vib;

	if (ddi_copyin((void *)arg, &vib, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	mutex_enter(&vnd_dev_lock);
	if (vib.vib_size > vnd_vdq_hard_max) {
		mutex_exit(&vnd_dev_lock);
		vib.vib_errno = VND_E_BUFTOOBIG;
		ret = EIO;
		goto err;
	}
	mutex_exit(&vnd_dev_lock);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_NOTATTACHED;
		ret = EIO;
		goto err;
	}

	mutex_enter(&vdp->vdd_str->vns_lock);
	if (vib.vib_size < vdp->vdd_str->vns_minwrite) {
		mutex_exit(&vdp->vdd_str->vns_lock);
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_BUFTOOSMALL;
		ret = EIO;
		goto err;
	}

	mutex_exit(&vdp->vdd_str->vns_lock);
	mutex_enter(&vdp->vdd_str->vns_dq_read.vdq_lock);
	vdp->vdd_str->vns_dq_read.vdq_max = vib.vib_size;
	mutex_exit(&vdp->vdd_str->vns_dq_read.vdq_lock);
	mutex_exit(&vdp->vdd_lock);
	ret = 0;

err:
	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	return (ret);
}

static int
vnd_ioctl_getrxbuf(vnd_dev_t *vdp, intptr_t arg, int cpflag)
{
	int ret;
	vnd_ioc_buf_t vib;

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_NOTATTACHED;
		ret = EIO;
		goto err;
	}

	mutex_enter(&vdp->vdd_str->vns_dq_read.vdq_lock);
	vib.vib_size = vdp->vdd_str->vns_dq_read.vdq_max;
	mutex_exit(&vdp->vdd_str->vns_dq_read.vdq_lock);
	mutex_exit(&vdp->vdd_lock);
	ret = 0;

err:
	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	return (ret);
}

static int
vnd_ioctl_getmaxbuf(vnd_dev_t *vdp, intptr_t arg, int cpflag)
{
	vnd_ioc_buf_t vib;

	mutex_enter(&vnd_dev_lock);
	vib.vib_size = vnd_vdq_hard_max;
	mutex_exit(&vnd_dev_lock);

	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	return (0);
}

static int
vnd_ioctl_gettxbuf(vnd_dev_t *vdp, intptr_t arg, int cpflag)
{
	int ret;
	vnd_ioc_buf_t vib;

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_NOTATTACHED;
		ret = EIO;
		goto err;
	}

	mutex_enter(&vdp->vdd_str->vns_dq_write.vdq_lock);
	vib.vib_size = vdp->vdd_str->vns_dq_write.vdq_max;
	mutex_exit(&vdp->vdd_str->vns_dq_write.vdq_lock);
	mutex_exit(&vdp->vdd_lock);
	ret = 0;

err:
	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	return (ret);
}

static int
vnd_ioctl_settxbuf(vnd_dev_t *vdp, intptr_t arg, int cpflag)
{
	int ret;
	vnd_ioc_buf_t vib;

	if (ddi_copyin((void *)arg, &vib, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	mutex_enter(&vnd_dev_lock);
	if (vib.vib_size > vnd_vdq_hard_max) {
		mutex_exit(&vnd_dev_lock);
		vib.vib_errno = VND_E_BUFTOOBIG;
		ret = EIO;
		goto err;
	}
	mutex_exit(&vnd_dev_lock);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_NOTATTACHED;
		ret = EIO;
		goto err;
	}

	mutex_enter(&vdp->vdd_str->vns_lock);
	if (vib.vib_size < vdp->vdd_str->vns_minwrite) {
		mutex_exit(&vdp->vdd_str->vns_lock);
		mutex_exit(&vdp->vdd_lock);
		vib.vib_errno = VND_E_BUFTOOSMALL;
		ret = EIO;
		goto err;
	}
	mutex_exit(&vdp->vdd_str->vns_lock);

	mutex_enter(&vdp->vdd_str->vns_dq_write.vdq_lock);
	vdp->vdd_str->vns_dq_write.vdq_max = vib.vib_size;
	mutex_exit(&vdp->vdd_str->vns_dq_write.vdq_lock);
	mutex_exit(&vdp->vdd_lock);
	ret = 0;

err:
	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), cpflag) != 0)
		return (EFAULT);

	return (ret);
}

static int
vnd_ioctl_gettu(vnd_dev_t *vdp, intptr_t arg, int mode, boolean_t min)
{
	vnd_ioc_buf_t vib;

	vib.vib_errno = 0;
	mutex_enter(&vdp->vdd_lock);
	if (vdp->vdd_flags & VND_D_ATTACHED) {
		mutex_enter(&vdp->vdd_str->vns_lock);
		if (min == B_TRUE)
			vib.vib_size = vdp->vdd_str->vns_minwrite;
		else
			vib.vib_size = vdp->vdd_str->vns_maxwrite;
		mutex_exit(&vdp->vdd_str->vns_lock);
	} else {
		vib.vib_errno = VND_E_NOTATTACHED;
	}
	mutex_exit(&vdp->vdd_lock);

	if (ddi_copyout(&vib, (void *)arg, sizeof (vib), mode & FKIOCTL) != 0)
		return (EFAULT);

	return (0);
}

static int
vnd_frameio_read(vnd_dev_t *vdp, intptr_t addr, int mode)
{
	int ret, nonblock, nwrite;
	frameio_t *fio;
	vnd_data_queue_t *vqp;
	mblk_t *mp;

	fio = frameio_alloc(KM_NOSLEEP | KM_NORMALPRI);
	if (fio == NULL)
		return (EAGAIN);

	ret = frameio_hdr_copyin(fio, FRAMEIO_NVECS_MAX, (const void *)addr,
	    mode);
	if (ret != 0) {
		frameio_free(fio);
		return (ret);
	}

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		frameio_free(fio);
		return (ENXIO);
	}
	mutex_exit(&vdp->vdd_lock);

	nonblock = mode & (FNONBLOCK | FNDELAY);

	vqp = &vdp->vdd_str->vns_dq_read;
	mutex_enter(&vqp->vdq_lock);

	/* Check empty case */
	if (vqp->vdq_cur == 0) {
		if (nonblock != 0) {
			mutex_exit(&vqp->vdq_lock);
			frameio_free(fio);
			return (EWOULDBLOCK);
		}
		while (vqp->vdq_cur == 0) {
			if (cv_wait_sig(&vqp->vdq_ready, &vqp->vdq_lock) <= 0) {
				mutex_exit(&vqp->vdq_lock);
				frameio_free(fio);
				return (EINTR);
			}
		}
	}

	ret = frameio_mblk_chain_write(fio, MAP_BLK_FRAME, vqp->vdq_head,
	    &nwrite, mode & FKIOCTL);
	if (ret != 0) {
		mutex_exit(&vqp->vdq_lock);
		frameio_free(fio);
		return (ret);
	}

	ret = frameio_hdr_copyout(fio, nwrite, (void *)addr, mode);
	if (ret != 0) {
		mutex_exit(&vqp->vdq_lock);
		frameio_free(fio);
		return (ret);
	}

	while (nwrite > 0) {
		(void) vnd_dq_pop(vqp, &mp);
		freemsg(mp);
		nwrite--;
	}
	mutex_exit(&vqp->vdq_lock);
	frameio_free(fio);

	return (0);
}

static int
vnd_frameio_write(vnd_dev_t *vdp, intptr_t addr, int mode)
{
	frameio_t *fio;
	int ret, nonblock, nframes, i, nread;
	size_t maxwrite, minwrite, total, flen;
	mblk_t *mp_chain, *mp, *nmp;
	vnd_data_queue_t *vqp;

	fio = frameio_alloc(KM_NOSLEEP | KM_NORMALPRI);
	if (fio == NULL)
		return (EAGAIN);

	ret = frameio_hdr_copyin(fio, FRAMEIO_NVECS_MAX, (void *)addr, mode);
	if (ret != 0) {
		frameio_free(fio);
		return (ret);
	}

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		frameio_free(fio);
		return (ENXIO);
	}
	mutex_exit(&vdp->vdd_lock);

	nonblock = mode & (FNONBLOCK | FNDELAY);

	/*
	 * Make sure no single frame is larger than we can accept.
	 */
	mutex_enter(&vdp->vdd_str->vns_lock);
	minwrite = vdp->vdd_str->vns_minwrite;
	maxwrite = vdp->vdd_str->vns_maxwrite;
	mutex_exit(&vdp->vdd_str->vns_lock);

	nframes = fio->fio_nvpf / fio->fio_nvecs;
	total = 0;
	for (i = 0; i < nframes; i++) {
		flen = frameio_frame_length(fio,
		    &fio->fio_vecs[i*fio->fio_nvpf]);
		if (flen < minwrite || flen > maxwrite) {
			frameio_free(fio);
			return (ERANGE);
		}
		total += flen;
	}

	vqp = &vdp->vdd_str->vns_dq_write;
	mutex_enter(&vqp->vdq_lock);
	while (vnd_dq_reserve(vqp, total) == 0) {
		if (nonblock != 0) {
			frameio_free(fio);
			mutex_exit(&vqp->vdq_lock);
			return (EAGAIN);
		}
		if (cv_wait_sig(&vqp->vdq_ready, &vqp->vdq_lock) <= 0) {
			mutex_exit(&vqp->vdq_lock);
			frameio_free(fio);
			return (EINTR);
		}
	}
	mutex_exit(&vqp->vdq_lock);

	/*
	 * We've reserved our space, let's copyin and go from here.
	 */
	ret = frameio_mblk_chain_read(fio, &mp_chain, &nread, mode & FKIOCTL);
	if (ret != 0) {
		frameio_free(fio);
		vnd_dq_unreserve(vqp, total);
		cv_broadcast(&vqp->vdq_ready);
		pollwakeup(&vdp->vdd_ph, POLLOUT);
		return (ret);
	}

	for (mp = mp_chain; mp != NULL; mp = nmp) {
		nmp = mp->b_next;
		mp->b_next = NULL;
		gsqueue_enter_one(vdp->vdd_str->vns_squeue, mp,
		    vnd_squeue_tx_append, vdp->vdd_str, GSQUEUE_PROCESS,
		    VND_SQUEUE_TAG_VND_WRITE);
	}

	/*
	 * Update the frameio structure to indicate that we wrote those frames.
	 */
	frameio_mark_consumed(fio, nread);
	ret = frameio_hdr_copyout(fio, nread, (void *)addr, mode);
	frameio_free(fio);

	return (ret);
}

static int
vnd_ioctl_list_copy_info(vnd_dev_t *vdp, vnd_ioc_info_t *arg, int mode)
{
	const char *link;
	uint32_t vers = 1;
	ASSERT(MUTEX_HELD(&vdp->vdd_lock));

	/*
	 * Copy all of the members out to userland.
	 */
	if (ddi_copyout(&vers, &arg->vii_version, sizeof (uint32_t),
	    mode & FKIOCTL) != 0)
		return (EFAULT);

	if (vdp->vdd_flags & VND_D_LINKED)
		link = vdp->vdd_lname;
	else
		link = "<anonymous>";
	if (ddi_copyout(link, arg->vii_name, sizeof (arg->vii_name),
	    mode & FKIOCTL) != 0)
		return (EFAULT);

	if (ddi_copyout(vdp->vdd_datalink, arg->vii_datalink,
	    sizeof (arg->vii_datalink), mode & FKIOCTL) != 0)
		return (EFAULT);

	if (ddi_copyout(&vdp->vdd_nsd->vpnd_zid, &arg->vii_zone,
	    sizeof (zoneid_t), mode & FKIOCTL) != 0)
		return (EFAULT);
	return (0);
}

static int
vnd_ioctl_list(intptr_t arg, cred_t *credp, int mode)
{
	vnd_ioc_list_t vl;
	vnd_ioc_list32_t vl32;
	zoneid_t zid;
	vnd_dev_t *vdp;
	vnd_ioc_info_t *vip;
	int found, cancopy, ret;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		if (ddi_copyin((void *)arg, &vl32, sizeof (vnd_ioc_list32_t),
		    mode & FKIOCTL) != 0)
			return (EFAULT);
		vl.vl_nents = vl32.vl_nents;
		vl.vl_actents = vl32.vl_actents;
		vl.vl_ents = (void *)(uintptr_t)vl32.vl_ents;
	} else {
		if (ddi_copyin((void *)arg, &vl, sizeof (vnd_ioc_list_t),
		    mode & FKIOCTL) != 0)
			return (EFAULT);
	}

	cancopy = vl.vl_nents;
	vip = vl.vl_ents;
	found = 0;
	zid = crgetzoneid(credp);
	mutex_enter(&vnd_dev_lock);
	for (vdp = list_head(&vnd_dev_list); vdp != NULL;
	    vdp = list_next(&vnd_dev_list, vdp)) {
		mutex_enter(&vdp->vdd_lock);
		if (vdp->vdd_flags & VND_D_ATTACHED &&
		    !(vdp->vdd_flags & (VND_D_CONDEMNED | VND_D_ZONE_DYING)) &&
		    (zid == GLOBAL_ZONEID || zid == vdp->vdd_nsd->vpnd_zid)) {
			found++;
			if (cancopy > 0) {
				ret = vnd_ioctl_list_copy_info(vdp, vip, mode);
				if (ret != 0) {
					mutex_exit(&vdp->vdd_lock);
					mutex_exit(&vnd_dev_lock);
					return (ret);
				}
				cancopy--;
				vip++;
			}
		}
		mutex_exit(&vdp->vdd_lock);
	}
	mutex_exit(&vnd_dev_lock);

	if (ddi_copyout(&found, &((vnd_ioc_list_t *)arg)->vl_actents,
	    sizeof (uint_t), mode & FKIOCTL) != 0)
		return (EFAULT);

	return (0);
}


static int
vnd_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;
	minor_t m;
	vnd_dev_t *vdp;

	m = getminor(dev);
	ASSERT(m != 0);

	/*
	 * Make sure no one has come in on an ioctl from the strioc case.
	 */
	if ((cmd & VND_STRIOC) == VND_STRIOC)
		return (ENOTTY);

	/*
	 * Like close, seems like if this minor isn't found, it's a programmer
	 * error somehow.
	 */
	vdp = vnd_dev_lookup(m);
	if (vdp == NULL)
		return (ENXIO);

	switch (cmd) {
	case VND_IOC_ATTACH:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_attach(vdp, arg, credp, mode);
		break;
	case VND_IOC_LINK:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_link(vdp, arg, credp, mode);
		break;
	case VND_IOC_UNLINK:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_unlink(vdp, arg, credp, mode);
		break;
	case VND_IOC_GETRXBUF:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_getrxbuf(vdp, arg, mode);
		break;
	case VND_IOC_SETRXBUF:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_setrxbuf(vdp, arg, mode);
		break;
	case VND_IOC_GETTXBUF:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_gettxbuf(vdp, arg, mode);
		break;
	case VND_IOC_SETTXBUF:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_settxbuf(vdp, arg, mode);
		break;
	case VND_IOC_GETMAXBUF:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		if (crgetzoneid(credp) != GLOBAL_ZONEID) {
			ret = EPERM;
			break;
		}
		ret = vnd_ioctl_getmaxbuf(vdp, arg, mode);
		break;
	case VND_IOC_GETMINTU:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_gettu(vdp, arg, mode, B_TRUE);
		break;
	case VND_IOC_GETMAXTU:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_gettu(vdp, arg, mode, B_FALSE);
		break;
	case VND_IOC_FRAMEIO_READ:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_frameio_read(vdp, arg, mode);
		break;
	case VND_IOC_FRAMEIO_WRITE:
		if (!(mode & FWRITE)) {
			ret = EBADF;
			break;
		}
		ret = vnd_frameio_write(vdp, arg, mode);
		break;
	case VND_IOC_LIST:
		if (!(mode & FREAD)) {
			ret = EBADF;
			break;
		}
		ret = vnd_ioctl_list(arg, credp, mode);
		break;
	default:
		ret = ENOTTY;
		break;
	}

	vnd_dev_rele(vdp);
	return (ret);
}

static int
vnd_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	vnd_dev_t *vdp;
	minor_t m;
	zoneid_t zid;

	if (flag & (FEXCL | FNDELAY))
		return (ENOTSUP);

	if (otyp & OTYP_BLK)
		return (ENOTSUP);

	zid = crgetzoneid(credp);
	m = getminor(*devp);

	/*
	 * If we have an open of a non-zero instance then we need to look that
	 * up in our list of entries.
	 */
	if (m != 0) {

		/*
		 * We don't check for rawaccess globally as a user could be
		 * doing a list ioctl on the control node which doesn't require
		 * this privilege.
		 */
		if (secpolicy_net_rawaccess(credp) != 0)
			return (EPERM);


		vdp = vnd_dev_lookup(m);
		if (vdp == NULL)
			return (ENOENT);

		/*
		 * We need to check to make sure that the user is allowed to
		 * open this node. At this point it should be an attached handle
		 * as that's all we're allowed to access.
		 */
		mutex_enter(&vdp->vdd_lock);
		if (!(vdp->vdd_flags & VND_D_LINKED)) {
			mutex_exit(&vdp->vdd_lock);
			vnd_dev_rele(vdp);
			return (ENOENT);
		}

		if (vdp->vdd_flags & VND_D_ZONE_DYING) {
			mutex_exit(&vdp->vdd_lock);
			vnd_dev_rele(vdp);
			return (ENOENT);
		}

		if (zid != GLOBAL_ZONEID && zid != vdp->vdd_nsd->vpnd_zid) {
			mutex_exit(&vdp->vdd_lock);
			vnd_dev_rele(vdp);
			return (ENOENT);
		}

		if ((flag & FEXCL) && (vdp->vdd_flags & VND_D_OPENED)) {
			mutex_exit(&vdp->vdd_lock);
			vnd_dev_rele(vdp);
			return (EBUSY);
		}

		if (!(vdp->vdd_flags & VND_D_OPENED)) {
			vdp->vdd_flags |= VND_D_OPENED;
			vdp->vdd_ref++;
			DTRACE_VND_REFINC(vdp);
		}
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);

		return (0);
	}

	if (flag & FEXCL)
		return (ENOTSUP);

	/*
	 * We need to clone ourselves and set up new a state.
	 */
	vdp = kmem_cache_alloc(vnd_dev_cache, KM_SLEEP);
	bzero(vdp, sizeof (vnd_dev_t));

	if (ldi_ident_from_dev(*devp, &vdp->vdd_ldiid) != 0) {
		kmem_cache_free(vnd_dev_cache, vdp);
		return (EINVAL);
	}

	vdp->vdd_minor = id_alloc(vnd_minors);
	mutex_init(&vdp->vdd_lock, NULL, MUTEX_DRIVER, NULL);
	list_link_init(&vdp->vdd_link);
	vdp->vdd_ref = 1;
	*devp = makedevice(getmajor(*devp), vdp->vdd_minor);
	vdp->vdd_devid = *devp;
	DTRACE_VND_REFINC(vdp);
	vdp->vdd_flags |= VND_D_OPENED;

	mutex_enter(&vnd_dev_lock);
	list_insert_head(&vnd_dev_list, vdp);
	mutex_exit(&vnd_dev_lock);

	return (0);
}

static int
vnd_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	minor_t m;
	vnd_dev_t *vdp;

	m = getminor(dev);
	if (m == 0)
		return (ENXIO);

	vdp = vnd_dev_lookup(m);
	if (vdp == NULL)
		return (ENXIO);

	mutex_enter(&vdp->vdd_lock);
	VERIFY(vdp->vdd_flags & VND_D_OPENED);
	vdp->vdd_flags &= ~VND_D_OPENED;
	mutex_exit(&vdp->vdd_lock);

	/* Remove the hold from the previous open. */
	vnd_dev_rele(vdp);

	/* And now from lookup */
	vnd_dev_rele(vdp);
	return (0);
}

static int
vnd_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int nonblock, error = 0;
	size_t mpsize;
	vnd_dev_t *vdp;
	vnd_data_queue_t *vqp;
	mblk_t *mp = NULL;
	offset_t u_loffset;

	/*
	 * If we have more than one uio we refuse to do anything. That's for
	 * frameio.
	 */
	if (uiop->uio_iovcnt > 1)
		return (EINVAL);

	vdp = vnd_dev_lookup(getminor(dev));
	if (vdp == NULL)
		return (ENXIO);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);
		return (ENXIO);
	}
	mutex_exit(&vdp->vdd_lock);
	nonblock = uiop->uio_fmode & (FNONBLOCK | FNDELAY);

	vqp = &vdp->vdd_str->vns_dq_read;
	mutex_enter(&vqp->vdq_lock);

	/* Check empty case */
	if (vqp->vdq_cur == 0) {
		if (nonblock != 0) {
			error = EWOULDBLOCK;
			goto err;
		}
		while (vqp->vdq_cur == 0) {
			if (cv_wait_sig(&vqp->vdq_ready, &vqp->vdq_lock) <= 0) {
				error = EINTR;
				goto err;
			}
		}
	}

	/* Ensure our buffer is big enough */
	mp = vqp->vdq_head;
	ASSERT(mp != NULL);
	mpsize = msgsize(mp);
	if (mpsize > uiop->uio_resid) {
		error = EOVERFLOW;
		goto err;
	}

	u_loffset = uiop->uio_loffset;
	while (mp != NULL) {
		if (uiomove(mp->b_rptr, MBLKL(mp), UIO_READ, uiop) != 0) {
			error = EFAULT;
			uiop->uio_loffset = u_loffset;
			mp = NULL;
			goto err;
		}
		mpsize -= MBLKL(mp);
		mp = mp->b_cont;
	}
	ASSERT(mpsize == 0);
	(void) vnd_dq_pop(vqp, &mp);
	freemsg(mp);
err:
	mutex_exit(&vqp->vdq_lock);
	vnd_dev_rele(vdp);

	return (error);
}

static int
vnd_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int nonblock, error;
	vnd_dev_t *vdp;
	mblk_t *mp;
	ssize_t iosize, origsize;
	vnd_data_queue_t *vqp;

	if (uiop->uio_iovcnt > 1)
		return (EINVAL);

	vdp = vnd_dev_lookup(getminor(dev));
	if (vdp == NULL)
		return (ENXIO);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);
		return (ENXIO);
	}
	mutex_exit(&vdp->vdd_lock);
	nonblock = uiop->uio_fmode & (FNONBLOCK | FNDELAY);

	mutex_enter(&vdp->vdd_str->vns_lock);
	if (uiop->uio_resid > vdp->vdd_str->vns_maxwrite ||
	    uiop->uio_resid < vdp->vdd_str->vns_minwrite) {
		mutex_exit(&vdp->vdd_str->vns_lock);
		vnd_dev_rele(vdp);
		return (ERANGE);
	}
	mutex_exit(&vdp->vdd_str->vns_lock);
	VERIFY(vdp->vdd_str != NULL);

	/*
	 * Reserve space in the data queue if we can. If we can't, block or
	 * return EAGAIN. If we can, go and squeue_enter.
	 */
	vqp = &vdp->vdd_str->vns_dq_write;
	mutex_enter(&vqp->vdq_lock);
	while (vnd_dq_reserve(vqp, uiop->uio_resid) == 0) {
		if (nonblock != 0) {
			mutex_exit(&vqp->vdq_lock);
			vnd_dev_rele(vdp);
			return (EAGAIN);
		}
		if (cv_wait_sig(&vqp->vdq_ready, &vqp->vdq_lock) <= 0) {
			mutex_exit(&vqp->vdq_lock);
			vnd_dev_rele(vdp);
			return (EINTR);
		}
	}
	mutex_exit(&vqp->vdq_lock);

	/*
	 * Now that we've reserved the space, try to allocate kernel space for
	 * and copy in the block. To take care of all this we use the
	 * strmakedata subroutine for now.
	 */
	origsize = iosize = uiop->uio_resid;
	error = strmakedata(&iosize, uiop, vdp->vdd_str->vns_wq->q_stream, 0,
	    &mp);

	/*
	 * strmakedata() will return an error or it may only consume a portion
	 * of the data.
	 */
	if (error != 0 || uiop->uio_resid != 0) {
		vnd_dq_unreserve(vqp, origsize);
		cv_broadcast(&vqp->vdq_ready);
		pollwakeup(&vdp->vdd_ph, POLLOUT);
		vnd_dev_rele(vdp);
		return (ENOSR);
	}

	gsqueue_enter_one(vdp->vdd_str->vns_squeue, mp,
	    vnd_squeue_tx_append, vdp->vdd_str, GSQUEUE_PROCESS,
	    VND_SQUEUE_TAG_VND_WRITE);

	vnd_dev_rele(vdp);
	return (0);
}

static int
vnd_chpoll(dev_t dev, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	int ready = 0;
	vnd_dev_t *vdp;
	vnd_data_queue_t *vqp;

	vdp = vnd_dev_lookup(getminor(dev));
	if (vdp == NULL)
		return (ENXIO);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_ATTACHED)) {
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);
		return (ENXIO);
	}
	mutex_exit(&vdp->vdd_lock);

	if ((events & POLLIN) || (events & POLLRDNORM)) {
		vqp = &vdp->vdd_str->vns_dq_read;
		mutex_enter(&vqp->vdq_lock);
		if (vqp->vdq_head != NULL)
			ready |= events & (POLLIN | POLLRDNORM);
		mutex_exit(&vqp->vdq_lock);
	}

	if (events & POLLOUT) {
		vqp = &vdp->vdd_str->vns_dq_write;
		mutex_enter(&vqp->vdq_lock);
		if (vqp->vdq_cur != vqp->vdq_max)
			ready |= POLLOUT;
		mutex_exit(&vqp->vdq_lock);
	}

	if (ready != 0) {
		*reventsp = ready;
		vnd_dev_rele(vdp);
		return (0);
	}

	*reventsp = 0;
	if (!anyyet)
		*phpp = &vdp->vdd_ph;

	vnd_dev_rele(vdp);
	return (0);
}

static void *
vnd_stack_init(netstackid_t stackid, netstack_t *ns)
{
	vnd_pnsd_t *nsp;

	nsp = kmem_cache_alloc(vnd_pnsd_cache, KM_SLEEP);
	bzero(nsp, sizeof (*nsp));
	nsp->vpnd_nsid = stackid;
	nsp->vpnd_zid = netstackid_to_zoneid(stackid);
	nsp->vpnd_flags = 0;
	mutex_init(&nsp->vpnd_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&nsp->vpnd_dev_list, sizeof (vnd_dev_t),
	    offsetof(vnd_dev_t, vdd_nslink));
	if (vnd_netinfo_init(nsp) == 0)
		nsp->vpnd_hooked = B_TRUE;

	mutex_enter(&vnd_dev_lock);
	list_insert_tail(&vnd_nsd_list, nsp);
	mutex_exit(&vnd_dev_lock);

	return (nsp);
}

static void
vnd_stack_shutdown(netstackid_t stackid, void *arg)
{
	vnd_pnsd_t *nsp = arg;
	vnd_dev_t *vdp;

	ASSERT(nsp != NULL);
	/*
	 * After shut down no one should be able to find their way to this
	 * netstack again.
	 */
	mutex_enter(&vnd_dev_lock);
	list_remove(&vnd_nsd_list, nsp);
	mutex_exit(&vnd_dev_lock);

	/*
	 * Make sure hooks know that they're going away.
	 */
	if (nsp->vpnd_hooked == B_TRUE)
		vnd_netinfo_shutdown(nsp);

	/*
	 * Now we need to go through and notify each zone that they are in
	 * teardown phase.  See the big theory statement section on vnd, zones,
	 * netstacks, and sdev for more information about this.
	 */
	mutex_enter(&nsp->vpnd_lock);
	nsp->vpnd_flags |= VND_NS_CONDEMNED;
	for (vdp = list_head(&nsp->vpnd_dev_list); vdp != NULL;
	    vdp = list_next(&nsp->vpnd_dev_list, vdp)) {
		mutex_enter(&vdp->vdd_lock);
		if (!(vdp->vdd_flags & VND_D_CONDEMNED))
			vdp->vdd_flags |= VND_D_ZONE_DYING;
		mutex_exit(&vdp->vdd_lock);
	}
	mutex_exit(&nsp->vpnd_lock);

	/*
	 * Next we remove all the links as we know nothing new can be added to
	 * the list and that none of the extent devices can obtain additional
	 * links.
	 */
restart:
	mutex_enter(&nsp->vpnd_lock);
	for (vdp = list_head(&nsp->vpnd_dev_list); vdp != NULL;
	    vdp = list_next(&nsp->vpnd_dev_list, vdp)) {
		mutex_enter(&vdp->vdd_lock);
		if ((vdp->vdd_flags & VND_D_CONDEMNED) ||
		    !(vdp->vdd_flags & VND_D_LINKED)) {
			mutex_exit(&vdp->vdd_lock);
			continue;
		}

		/*
		 * We drop our lock here and restart afterwards. Note that as
		 * part of unlinking we end up doing a rele of the vnd_dev_t. If
		 * this is the final hold on the vnd_dev_t then it might try and
		 * remove itself. Our locking rules requires not to be holding
		 * any locks when we call any of the rele functions.
		 *
		 * Note that the unlink function requires holders to call into
		 * it with the vnd_dev_t->vdd_lock held and will take care of it
		 * for us. Because we don't have a hold on it, we're done at
		 * this point.
		 */
		mutex_exit(&nsp->vpnd_lock);
		/* Forcibly unlink */
		vnd_dev_unlink(vdp);
		goto restart;
	}
	mutex_exit(&nsp->vpnd_lock);
}

static void
vnd_stack_destroy(netstackid_t stackid, void *arg)
{
	vnd_pnsd_t *nsp = arg;

	ASSERT(nsp != NULL);

	/*
	 * Now that we've unlinked everything we just have to hang out for
	 * it to finish exiting. Now that it's no longer the kernel itself
	 * that's doing this we just need to wait for our reference count to
	 * equal zero and then we're free. If the global zone is holding open a
	 * reference to a vnd device for another zone, that's bad, but there's
	 * nothing much we can do. See the section on 'vnd, zones, netstacks' in
	 * the big theory statement for more information.
	 */
	mutex_enter(&nsp->vpnd_lock);
	while (nsp->vpnd_ref != 0)
		cv_wait(&nsp->vpnd_ref_change, &nsp->vpnd_lock);
	mutex_exit(&nsp->vpnd_lock);

	/*
	 * During shutdown we removed ourselves from the list and now we have no
	 * more references so we can safely say that there is nothing left and
	 * destroy everything that we had sitting around.
	 */
	if (nsp->vpnd_hooked == B_TRUE)
		vnd_netinfo_fini(nsp);

	mutex_destroy(&nsp->vpnd_lock);
	list_destroy(&nsp->vpnd_dev_list);
	kmem_cache_free(vnd_pnsd_cache, nsp);
}

/*
 * Convert a node with a name of the form /dev/vnd/zone/%zonename and
 * /dev/vnd/zone/%zonename/%linkname to the corresponding vnd netstack.
 */
static vnd_pnsd_t *
vnd_sdev_ctx_to_ns(sdev_ctx_t ctx)
{
	enum vtype vt;
	const char *path = sdev_ctx_path(ctx);
	char *zstart, *dup;
	size_t duplen;
	vnd_pnsd_t *nsp;

	vt = sdev_ctx_vtype(ctx);
	ASSERT(strncmp(path, VND_SDEV_ZROOT, strlen(VND_SDEV_ZROOT)) == 0);

	if (vt == VDIR) {
		zstart = strrchr(path, '/');
		ASSERT(zstart != NULL);
		zstart++;
		return (vnd_nsd_lookup_by_zonename(zstart));
	}

	ASSERT(vt == VCHR);

	dup = strdup(path);
	duplen = strlen(dup) + 1;
	zstart = strrchr(dup, '/');
	*zstart = '\0';
	zstart--;
	zstart = strrchr(dup, '/');
	zstart++;
	nsp = vnd_nsd_lookup_by_zonename(zstart);
	kmem_free(dup, duplen);

	return (nsp);
}

static sdev_plugin_validate_t
vnd_sdev_validate_dir(sdev_ctx_t ctx)
{
	vnd_pnsd_t *nsp;

	if (strcmp(sdev_ctx_path(ctx), VND_SDEV_ROOT) == 0)
		return (SDEV_VTOR_VALID);

	if (strcmp(sdev_ctx_path(ctx), VND_SDEV_ZROOT) == 0) {
		ASSERT(getzoneid() == GLOBAL_ZONEID);
		ASSERT(sdev_ctx_flags(ctx) & SDEV_CTX_GLOBAL);
		return (SDEV_VTOR_VALID);
	}

	nsp = vnd_sdev_ctx_to_ns(ctx);
	if (nsp == NULL)
		return (SDEV_VTOR_INVALID);
	vnd_nsd_rele(nsp);

	return (SDEV_VTOR_VALID);
}

static sdev_plugin_validate_t
vnd_sdev_validate(sdev_ctx_t ctx)
{
	enum vtype vt;
	dev_t dev;
	vnd_dev_t *vdp;

	vt = sdev_ctx_vtype(ctx);
	if (vt == VDIR)
		return (vnd_sdev_validate_dir(ctx));
	ASSERT(vt == VCHR);

	if (strcmp("ctl", sdev_ctx_name(ctx)) == 0)
		return (SDEV_VTOR_VALID);

	dev = (uintptr_t)sdev_ctx_vtype_data(ctx);
	vdp = vnd_dev_lookup(getminor(dev));
	if (vdp == NULL)
		return (SDEV_VTOR_STALE);

	mutex_enter(&vdp->vdd_lock);
	if (!(vdp->vdd_flags & VND_D_LINKED) ||
	    (vdp->vdd_flags & (VND_D_CONDEMNED | VND_D_ZONE_DYING))) {
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);
		return (SDEV_VTOR_STALE);
	}

	if (strcmp(sdev_ctx_name(ctx), vdp->vdd_lname) != 0) {
		mutex_exit(&vdp->vdd_lock);
		vnd_dev_rele(vdp);
		return (SDEV_VTOR_STALE);
	}

	mutex_exit(&vdp->vdd_lock);
	vnd_dev_rele(vdp);
	return (SDEV_VTOR_VALID);
}

/*
 * This function is a no-op. sdev never has holds on our devices as they can go
 * away at any time and specfs has to deal with that fact.
 */
static void
vnd_sdev_inactive(sdev_ctx_t ctx)
{
}

static int
vnd_sdev_fillzone(vnd_pnsd_t *nsp, sdev_ctx_t ctx)
{
	int ret;
	vnd_dev_t *vdp;

	mutex_enter(&nsp->vpnd_lock);
	for (vdp = list_head(&nsp->vpnd_dev_list); vdp != NULL;
	    vdp = list_next(&nsp->vpnd_dev_list, vdp)) {
		mutex_enter(&vdp->vdd_lock);
		if ((vdp->vdd_flags & VND_D_LINKED) &&
		    !(vdp->vdd_flags & (VND_D_CONDEMNED | VND_D_ZONE_DYING))) {
			ret = sdev_plugin_mknod(ctx, vdp->vdd_lname, S_IFCHR,
			    vdp->vdd_devid);
			if (ret != 0 && ret != EEXIST) {
				mutex_exit(&vdp->vdd_lock);
				mutex_exit(&nsp->vpnd_lock);
				vnd_nsd_rele(nsp);
				return (ret);
			}
		}
		mutex_exit(&vdp->vdd_lock);
	}
	mutex_exit(&nsp->vpnd_lock);

	return (0);
}

static int
vnd_sdev_filldir_root(sdev_ctx_t ctx)
{
	zoneid_t zid;
	vnd_pnsd_t *nsp;
	int ret;

	zid = getzoneid();
	nsp = vnd_nsd_lookup(zoneid_to_netstackid(zid));
	ASSERT(nsp != NULL);
	ret = vnd_sdev_fillzone(nsp, ctx);
	vnd_nsd_rele(nsp);
	if (ret != 0)
		return (ret);

	/*
	 * Checking the zone id is not sufficient as the global zone could be
	 * reaching down into a non-global zone's mounted /dev.
	 */
	if (zid == GLOBAL_ZONEID && (sdev_ctx_flags(ctx) & SDEV_CTX_GLOBAL)) {
		ret = sdev_plugin_mkdir(ctx, "zone");
		if (ret != 0 && ret != EEXIST)
			return (ret);
	}

	/*
	 * Always add a reference to the control node. There's no need to
	 * reference it since it always exists and is always what we clone from.
	 */
	ret = sdev_plugin_mknod(ctx, "ctl", S_IFCHR,
	    makedevice(ddi_driver_major(vnd_dip), 0));
	if (ret != 0 && ret != EEXIST)
		return (ret);

	return (0);
}

static int
vnd_sdev_filldir_zroot(sdev_ctx_t ctx)
{
	int ret;
	vnd_pnsd_t *nsp;
	zone_t *zonep;

	ASSERT(getzoneid() == GLOBAL_ZONEID);
	ASSERT(sdev_ctx_flags(ctx) & SDEV_CTX_GLOBAL);

	mutex_enter(&vnd_dev_lock);
	for (nsp = list_head(&vnd_nsd_list); nsp != NULL;
	    nsp = list_next(&vnd_nsd_list, nsp)) {
		mutex_enter(&nsp->vpnd_lock);
		if (list_is_empty(&nsp->vpnd_dev_list)) {
			mutex_exit(&nsp->vpnd_lock);
			continue;
		}
		mutex_exit(&nsp->vpnd_lock);
		zonep = zone_find_by_id(nsp->vpnd_zid);
		/*
		 * This zone must be being torn down, so skip it.
		 */
		if (zonep == NULL)
			continue;
		ret = sdev_plugin_mkdir(ctx, zonep->zone_name);
		zone_rele(zonep);
		if (ret != 0 && ret != EEXIST) {
			mutex_exit(&vnd_dev_lock);
			return (ret);
		}
	}
	mutex_exit(&vnd_dev_lock);
	return (0);
}

static int
vnd_sdev_filldir(sdev_ctx_t ctx)
{
	int ret;
	vnd_pnsd_t *nsp;

	ASSERT(sdev_ctx_vtype(ctx) == VDIR);
	if (strcmp(VND_SDEV_ROOT, sdev_ctx_path(ctx)) == 0)
		return (vnd_sdev_filldir_root(ctx));

	if (strcmp(VND_SDEV_ZROOT, sdev_ctx_path(ctx)) == 0)
		return (vnd_sdev_filldir_zroot(ctx));

	ASSERT(strncmp(VND_SDEV_ZROOT, sdev_ctx_path(ctx),
	    strlen(VND_SDEV_ZROOT)) == 0);
	nsp = vnd_sdev_ctx_to_ns(ctx);
	if (nsp == NULL)
		return (0);

	ret = vnd_sdev_fillzone(nsp, ctx);
	vnd_nsd_rele(nsp);

	return (ret);
}

static sdev_plugin_ops_t vnd_sdev_ops = {
	SDEV_PLUGIN_VERSION,
	SDEV_PLUGIN_SUBDIR,
	vnd_sdev_validate,
	vnd_sdev_filldir,
	vnd_sdev_inactive
};

static int
vnd_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int errp = 0;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	/*
	 * Only allow one instance.
	 */
	if (vnd_dip != NULL)
		return (DDI_FAILURE);

	vnd_dip = dip;
	if (ddi_create_minor_node(vnd_dip, "vnd", S_IFCHR, 0, DDI_PSEUDO, 0) !=
	    DDI_SUCCESS) {
		vnd_dip = NULL;
		return (DDI_FAILURE);
	}

	if (ddi_prop_create(DDI_DEV_T_NONE, dip, DDI_PROP_CANSLEEP,
	    DDI_KERNEL_IOCTL, NULL, 0) != DDI_PROP_SUCCESS) {
		ddi_remove_minor_node(vnd_dip, NULL);
		vnd_dip = NULL;
		return (DDI_FAILURE);
	}

	vnd_sdev_hdl = sdev_plugin_register(VND_SDEV_NAME, &vnd_sdev_ops,
	    &errp);
	if (vnd_sdev_hdl == NULL) {
		ddi_remove_minor_node(vnd_dip, NULL);
		ddi_prop_remove_all(vnd_dip);
		vnd_dip = NULL;
		return (DDI_FAILURE);
	}

	vnd_sqset = gsqueue_set_create(GSQUEUE_DEFAULT_WAIT,
	    GSQUEUE_DEFAULT_PRIORITY);

	return (DDI_SUCCESS);
}

static int
vnd_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&vnd_dev_lock);
	if (!list_is_empty(&vnd_dev_list)) {
		mutex_exit(&vnd_dev_lock);
		return (DDI_FAILURE);
	}
	mutex_exit(&vnd_dev_lock);

	return (DDI_FAILURE);
}

static int
vnd_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*result = (void *)vnd_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*result = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}
	return (error);
}



static void
vnd_ddi_fini(void)
{
	netstack_unregister(NS_VND);
	if (vnd_taskq != NULL)
		taskq_destroy(vnd_taskq);
	if (vnd_str_cache != NULL)
		kmem_cache_destroy(vnd_str_cache);
	if (vnd_dev_cache != NULL)
		kmem_cache_destroy(vnd_dev_cache);
	if (vnd_pnsd_cache != NULL)
		kmem_cache_destroy(vnd_pnsd_cache);
	if (vnd_minors != NULL)
		id_space_destroy(vnd_minors);
	if (vnd_list_init != 0) {
		list_destroy(&vnd_nsd_list);
		list_destroy(&vnd_dev_list);
		mutex_destroy(&vnd_dev_lock);
		vnd_list_init = 0;
	}
	frameio_fini();
}

static int
vnd_ddi_init(void)
{
	if (frameio_init() != 0)
		return (DDI_FAILURE);

	vnd_str_cache = kmem_cache_create("vnd_str_cache", sizeof (vnd_str_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	if (vnd_str_cache == NULL) {
		frameio_fini();
		return (DDI_FAILURE);
	}
	vnd_dev_cache = kmem_cache_create("vnd_dev_cache", sizeof (vnd_dev_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);
	if (vnd_dev_cache == NULL) {
		kmem_cache_destroy(vnd_str_cache);
		frameio_fini();
		return (DDI_FAILURE);
	}
	vnd_pnsd_cache = kmem_cache_create("vnd_pnsd_cache",
	    sizeof (vnd_pnsd_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	if (vnd_pnsd_cache == NULL) {
		kmem_cache_destroy(vnd_dev_cache);
		kmem_cache_destroy(vnd_str_cache);
		frameio_fini();
		return (DDI_FAILURE);
	}

	vnd_taskq = taskq_create_instance("vnd", -1, 1, minclsyspri, 0, 0, 0);
	if (vnd_taskq == NULL) {
		kmem_cache_destroy(vnd_pnsd_cache);
		kmem_cache_destroy(vnd_dev_cache);
		kmem_cache_destroy(vnd_str_cache);
		frameio_fini();
		return (DDI_FAILURE);
	}

	vnd_minors = id_space_create("vnd_minors", 1, INT32_MAX);
	if (vnd_minors == NULL) {
		taskq_destroy(vnd_taskq);
		kmem_cache_destroy(vnd_pnsd_cache);
		kmem_cache_destroy(vnd_dev_cache);
		kmem_cache_destroy(vnd_str_cache);
		frameio_fini();
		return (DDI_FAILURE);
	}

	mutex_init(&vnd_dev_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&vnd_dev_list, sizeof (vnd_dev_t),
	    offsetof(vnd_dev_t, vdd_link));
	list_create(&vnd_nsd_list, sizeof (vnd_pnsd_t),
	    offsetof(vnd_pnsd_t, vpnd_link));
	vnd_list_init = 1;

	netstack_register(NS_VND, vnd_stack_init, vnd_stack_shutdown,
	    vnd_stack_destroy);

	return (DDI_SUCCESS);
}

static struct module_info vnd_minfo = {
	0,		/* module id */
	"vnd",		/* module name */
	1,		/* smallest packet size */
	INFPSZ,		/* largest packet size (infinite) */
	1,		/* high watermark */
	0		/* low watermark */
};

static struct qinit vnd_r_qinit = {
	vnd_s_rput,
	NULL,
	vnd_s_open,
	vnd_s_close,
	NULL,
	&vnd_minfo,
	NULL
};

static struct qinit vnd_w_qinit = {
	vnd_s_wput,
	NULL,
	NULL,
	NULL,
	NULL,
	&vnd_minfo,
	NULL
};

static struct streamtab vnd_strtab = {
	&vnd_r_qinit,
	&vnd_w_qinit,
	NULL,
	NULL
};


static struct cb_ops vnd_cb_ops = {
	vnd_open,		/* open */
	vnd_close,		/* close */
	nulldev,		/* strategy */
	nulldev,		/* print */
	nodev,			/* dump */
	vnd_read,		/* read */
	vnd_write,		/* write */
	vnd_ioctl,		/* ioctl */
	nodev,			/* devmap */
	nodev,			/* mmap */
	nodev,			/* segmap */
	vnd_chpoll,		/* poll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* streamtab  */
	D_MP			/* Driver compatibility flag */
};

static struct dev_ops vnd_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* refcnt */
	vnd_info,		/* get_dev_info */
	nulldev,		/* identify */
	nulldev,		/* probe */
	vnd_attach,		/* attach */
	vnd_detach,		/* detach */
	nodev,			/* reset */
	&vnd_cb_ops,		/* driver operations */
	NULL,			/* bus operations */
	nodev,			/* dev power */
	ddi_quiesce_not_needed	/* quiesce */
};

static struct modldrv vnd_modldrv = {
	&mod_driverops,
	"Virtual Networking Datapath Driver",
	&vnd_dev_ops
};

static struct fmodsw vnd_fmodfsw = {
	"vnd",
	&vnd_strtab,
	D_NEW | D_MP
};

static struct modlstrmod vnd_modlstrmod = {
	&mod_strmodops,
	"Virtual Networking Datapath Driver",
	&vnd_fmodfsw
};

static struct modlinkage vnd_modlinkage = {
	MODREV_1,
	&vnd_modldrv,
	&vnd_modlstrmod,
	NULL
};

int
_init(void)
{
	int error;

	/*
	 * We need to do all of our global initialization in init as opposed to
	 * attach and detach. The problem here is that because vnd can be used
	 * from a stream context while being detached, we can not rely on having
	 * run attach to create everything, alas. so it goes in _init, just like
	 * our friend ip.
	 */
	if ((error = vnd_ddi_init()) != DDI_SUCCESS)
		return (error);
	error = mod_install((&vnd_modlinkage));
	if (error != 0)
		vnd_ddi_fini();
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&vnd_modlinkage, modinfop));
}

int
_fini(void)
{
	int error;

	error = mod_remove(&vnd_modlinkage);
	if (error == 0)
		vnd_ddi_fini();
	return (error);
}
