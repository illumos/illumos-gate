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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 * Copyright 2013 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * MAC data path
 *
 * The MAC data path is concerned with the flow of traffic from mac clients --
 * DLS, IP, etc. -- to various GLDv3 device drivers -- e1000g, vnic, aggr,
 * ixgbe, etc. -- and from the GLDv3 device drivers back to clients.
 *
 * -----------
 * Terminology
 * -----------
 *
 * MAC uses a lot of different, but related terms that are associated with the
 * design and structure of the data path. Before we cover other aspects, first
 * let's review the terminology that MAC uses.
 *
 * MAC
 *
 * 	This driver. It interfaces with device drivers and provides abstractions
 * 	that the rest of the system consumes. All data links -- things managed
 * 	with dladm(1M), are accessed through MAC.
 *
 * GLDv3 DEVICE DRIVER
 *
 * 	A GLDv3 device driver refers to a driver, both for pseudo-devices and
 * 	real devices, which implement the GLDv3 driver API. Common examples of
 * 	these are igb and ixgbe, which are drivers for various Intel networking
 * 	cards. These devices may or may not have various features, such as
 * 	hardware rings and checksum offloading. For MAC, a GLDv3 device is the
 * 	final point for the transmission of a packet and the starting point for
 * 	the receipt of a packet.
 *
 * FLOWS
 *
 * 	At a high level, a flow refers to a series of packets that are related.
 * 	Often times the term is used in the context of TCP to indicate a unique
 * 	TCP connection and the traffic over it. However, a flow can exist at
 * 	other levels of the system as well. MAC has a notion of a default flow
 * 	which is used for all unicast traffic addressed to the address of a MAC
 * 	device. For example, when a VNIC is created, a default flow is created
 * 	for the VNIC's MAC address. In addition, flows are created for broadcast
 * 	groups and a user may create a flow with flowadm(1M).
 *
 * CLASSIFICATION
 *
 * 	Classification refers to the notion of identifying an incoming frame
 * 	based on its destination address and optionally its source addresses and
 * 	doing different processing based on that information. Classification can
 * 	be done in both hardware and software. In general, we usually only
 * 	classify based on the layer two destination, eg. for Ethernet, the
 * 	destination MAC address.
 *
 * 	The system also will do classification based on layer three and layer
 * 	four properties. This is used to support things like flowadm(1M), which
 * 	allows setting QoS and other properties on a per-flow basis.
 *
 * RING
 *
 * 	Conceptually, a ring represents a series of framed messages, often in a
 * 	contiguous chunk of memory that acts as a circular buffer. Rings come in
 * 	a couple of forms. Generally they are either a hardware construct (hw
 * 	ring) or they are a software construct (sw ring) maintained by MAC.
 *
 * HW RING
 *
 * 	A hardware ring is a set of resources provided by a GLDv3 device driver
 * 	(even if it is a pseudo-device). A hardware ring comes in two different
 * 	forms: receive (rx) rings and transmit (tx) rings. An rx hw ring is
 * 	something that has a unique DMA (direct memory access) region and
 * 	generally supports some form of classification (though it isn't always
 * 	used), as well as a means of generating an interrupt specific to that
 * 	ring. For example, the device may generate a specific MSI-X for a PCI
 * 	express device. A tx ring is similar, except that it is dedicated to
 * 	transmission. It may also be a vector for enabling features such as VLAN
 * 	tagging and large transmit offloading. It usually has its own dedicated
 * 	interrupts for transmit being completed.
 *
 * SW RING
 *
 * 	A software ring is a construction of MAC. It represents the same thing
 * 	that a hardware ring generally does, a collection of frames. However,
 * 	instead of being in a contiguous ring of memory, they're instead linked
 * 	by using the mblk_t's b_next pointer. Each frame may itself be multiple
 * 	mblk_t's linked together by the b_cont pointer. A software ring always
 * 	represents a collection of classified packets; however, it varies as to
 * 	whether it uses only layer two information, or a combination of that and
 * 	additional layer three and layer four data.
 *
 * FANOUT
 *
 * 	Fanout is the idea of spreading out the load of processing frames based
 * 	on the source and destination information contained in the layer two,
 * 	three, and four headers, such that the data can then be processed in
 * 	parallel using multiple hardware threads.
 *
 * 	A fanout algorithm hashes the headers and uses that to place different
 * 	flows into a bucket. The most important thing is that packets that are
 * 	in the same flow end up in the same bucket. If they do not, performance
 * 	can be adversely affected. Consider the case of TCP.  TCP severely
 * 	penalizes a connection if the data arrives out of order. If a given flow
 * 	is processed on different CPUs, then the data will appear out of order,
 * 	hence the invariant that fanout always hash a given flow to the same
 * 	bucket and thus get processed on the same CPU.
 *
 * RECEIVE SIDE SCALING (RSS)
 *
 *
 * 	Receive side scaling is a term that isn't common in illumos, but is used
 * 	by vendors and was popularized by Microsoft. It refers to the idea of
 * 	spreading the incoming receive load out across multiple interrupts which
 * 	can be directed to different CPUs. This allows a device to leverage
 * 	hardware rings even when it doesn't support hardware classification. The
 * 	hardware uses an algorithm to perform fanout that ensures the flow
 * 	invariant is maintained.
 *
 * SOFT RING SET
 *
 * 	A soft ring set, commonly abbreviated SRS, is a collection of rings and
 * 	is used for both transmitting and receiving. It is maintained in the
 * 	structure mac_soft_ring_set_t. A soft ring set is usually associated
 * 	with flows, and coordinates both the use of hardware and software rings.
 * 	Because the use of hardware rings can change as devices such as VNICs
 * 	come and go, we always ensure that the set has software classification
 * 	rules that correspond to the hardware classification rules from rings.
 *
 * 	Soft ring sets are also used for the enforcement of various QoS
 * 	properties. For example, if a bandwidth limit has been placed on a
 * 	specific flow or device, then that will be enforced by the soft ring
 * 	set.
 *
 * SERVICE ATTACHMENT POINT (SAP)
 *
 * 	The service attachment point is a DLPI (Data Link Provider Interface)
 * 	concept; however, it comes up quite often in MAC. Most MAC devices speak
 * 	a protocol that has some notion of different channels or message type
 * 	identifiers. For example, Ethernet defines an EtherType which is a part
 * 	of the Ethernet header and defines the particular protocol of the data
 * 	payload. If the EtherType is set to 0x0800, then it defines that the
 * 	contents of that Ethernet frame is IPv4 traffic. For Ethernet, the
 * 	EtherType is the SAP.
 *
 * 	In DLPI, a given consumer attaches to a specific SAP. In illumos, the ip
 * 	and arp drivers attach to the EtherTypes for IPv4, IPv6, and ARP. Using
 * 	libdlpi(3LIB) user software can attach to arbitrary SAPs. With the
 * 	exception of 802.1Q VLAN tagged traffic, MAC itself does not directly
 * 	consume the SAP; however, it uses that information as part of hashing
 * 	and it may be used as part of the construction of flows.
 *
 * PRIMARY MAC CLIENT
 *
 * 	The primary mac client refers to a mac client whose unicast address
 * 	matches the address of the device itself. For example, if the system has
 * 	instance of the e1000g driver such as e1000g0, e1000g1, etc., the
 * 	primary mac client is the one named after the device itself. VNICs that
 * 	are created on top of such devices are not the primary client.
 *
 * TRANSMIT DESCRIPTORS
 *
 * 	Transmit descriptors are a resource that most GLDv3 device drivers have.
 * 	Generally, a GLDv3 device driver takes a frame that's meant to be output
 * 	and puts a copy of it into a region of memory. Each region of memory
 * 	usually has an associated descriptor that the device uses to manage
 * 	properties of the frames. Devices have a limited number of such
 * 	descriptors. They get reclaimed once the device finishes putting the
 * 	frame on the wire.
 *
 * 	If the driver runs out of transmit descriptors, for example, the OS is
 * 	generating more frames than it can put on the wire, then it will return
 * 	them back to the MAC layer.
 *
 * ---------------------------------
 * Rings, Classification, and Fanout
 * ---------------------------------
 *
 * The heart of MAC is made up of rings, and not those that Elven-kings wear.
 * When receiving a packet, MAC breaks the work into two different, though
 * interrelated phases. The first phase is generally classification and then the
 * second phase is generally fanout. When a frame comes in from a GLDv3 Device,
 * MAC needs to determine where that frame should be delivered. If it's a
 * unicast frame (say a normal TCP/IP packet), then it will be delivered to a
 * single MAC client; however, if it's a broadcast or multicast frame, then MAC
 * may need to deliver it to multiple MAC clients.
 *
 * On transmit, classification isn't quite as important, but may still be used.
 * Unlike with the receive path, the classification is not used to determine
 * devices that should transmit something, but rather is used for special
 * properties of a flow, eg. bandwidth limits for a given IP address, device, or
 * connection.
 *
 * MAC employs a software classifier and leverages hardware classification as
 * well. The software classifier can leverage the full layer two information,
 * source, destination, VLAN, and SAP. If the SAP indicates that IP traffic is
 * being sent, it can classify based on the IP header, and finally, it also
 * knows how to classify based on the local and remote ports of TCP, UDP, and
 * SCTP.
 *
 * Hardware classifiers vary in capability. Generally all hardware classifiers
 * provide the capability to classify based on the destination MAC address. Some
 * hardware has additional filters built in for performing more in-depth
 * classification; however, it often has much more limited resources for these
 * activities as compared to the layer two destination address classification.
 *
 * The modus operandi in MAC is to always ensure that we have software-based
 * capabilities and rules in place and then to supplement that with hardware
 * resources when available. In general, simple layer two classification is
 * sufficient and nothing else is used, unless a specific flow is created with
 * tools such as flowadm(1M) or bandwidth limits are set on a device with
 * dladm(1M).
 *
 * RINGS AND GROUPS
 *
 * To get into how rings and classification play together, it's first important
 * to understand how hardware devices commonly associate rings and allow them to
 * be programmed. Recall that a hardware ring should be thought of as a DMA
 * buffer and an interrupt resource. Rings are then collected into groups. A
 * group itself has a series of classification rules. One or more MAC addresses
 * are assigned to a group.
 *
 * Hardware devices vary in terms of what capabilities they provide. Sometimes
 * they allow for a dynamic assignment of rings to a group and sometimes they
 * have a static assignment of rings to a group. For example, the ixgbe driver
 * has a static assignment of rings to groups such that every group has exactly
 * one ring and the number of groups is equal to the number of rings.
 *
 * Classification and receive side scaling both come into play with how a device
 * advertises itself to MAC and how MAC uses it. If a device supports layer two
 * classification of frames, then MAC will assign MAC addresses to a group as a
 * form of primary classification. If a single MAC address is assigned to a
 * group, a common case, then MAC will consider packets that come in from rings
 * on that group to be fully classified and will not need to do any software
 * classification unless a specific flow has been created.
 *
 * If a device supports receive side scaling, then it may advertise or support
 * groups with multiple rings. In those cases, then receive side scaling will
 * come into play and MAC will use that as a means of fanning out received
 * frames across multiple CPUs. This can also be combined with groups that
 * support layer two classification.
 *
 * If a device supports dynamic assignments of rings to groups, then MAC will
 * change around the way that rings are assigned to various groups as devices
 * come and go from the system. For example, when a VNIC is created, a new flow
 * will be created for the VNIC's MAC address. If a hardware ring is available,
 * MAC may opt to reassign it from one group to another.
 *
 * ASSIGNMENT OF HARDWARE RINGS
 *
 * This is a bit of a complicated subject that varies depending on the device,
 * the use of aggregations, the special nature of the primary mac client. This
 * section deserves being fleshed out.
 *
 * FANOUT
 *
 * illumos uses fanout to help spread out the incoming processing load of chains
 * of frames away from a single CPU. If a device supports receive side scaling,
 * then that provides an initial form of fanout; however, what we're concerned
 * with all happens after the context of a given set of frames being classified
 * to a soft ring set.
 *
 * After frames reach a soft ring set and account for any potential bandwidth
 * related accounting, they may be fanned out based on one of the following
 * three modes:
 *
 *     o No Fanout
 *     o Protocol level fanout
 *     o Full software ring protocol fanout
 *
 * MAC makes the determination as to which of these modes a given soft ring set
 * obtains based on parameters such as whether or not it's the primary mac
 * client, whether it's on a 10 GbE or faster device, user controlled dladm(1M)
 * properties, and the nature of the hardware and the resources that it has.
 *
 * When there is no fanout, MAC does not create any soft rings for a device and
 * the device has frames delivered directly to the MAC client.
 *
 * Otherwise, all fanout is performed by software. MAC divides incoming frames
 * into one of three buckets -- IPv4 TCP traffic, IPv4 UDP traffic, and
 * everything else. Note, VLAN tagged traffic is considered other, regardless of
 * the interior EtherType. Regardless of the type of fanout, these three
 * categories or buckets are always used.
 *
 * The difference between protocol level fanout and full software ring protocol
 * fanout is the number of software rings that end up getting created. The
 * system always uses the same number of software rings per protocol bucket. So
 * in the first case when we're just doing protocol level fanout, we just create
 * one software ring each for IPv4 TCP traffic, IPv4 UDP traffic, and everything
 * else.
 *
 * In the case where we do full software ring protocol fanout, we generally use
 * mac_compute_soft_ring_count() to determine the number of rings. There are
 * other combinations of properties and devices that may send us down other
 * paths, but this is a common starting point. If it's a non-bandwidth enforced
 * device and we're on at least a 10 GbE link, then we'll use eight soft rings
 * per protocol bucket as a starting point. See mac_compute_soft_ring_count()
 * for more information on the total number.
 *
 * For each of these rings, we create a mac_soft_ring_t and an associated worker
 * thread. Particularly when doing full software ring protocol fanout, we bind
 * each of the worker threads to individual CPUs.
 *
 * The other advantage of these software rings is that it allows upper layers to
 * optionally poll on them. For example, TCP can leverage an squeue to poll on
 * the software ring, see squeue.c for more information.
 *
 * DLS BYPASS
 *
 * DLS is the data link services module. It interfaces with DLPI, which is the
 * primary way that other parts of the system such as IP interface with the MAC
 * layer. While DLS is traditionally a STREAMS-based interface, it allows for
 * certain modules such as IP to negotiate various more modern interfaces to be
 * used, which are useful for higher performance and allow it to use direct
 * function calls to DLS instead of using STREAMS.
 *
 * When we have IPv4 TCP or UDP software rings, then traffic on those rings is
 * eligible for what we call the dls bypass. In those cases, rather than going
 * out mac_rx_deliver() to DLS, DLS instead registers them to go directly via
 * the direct callback registered with DLS, generally ip_input().
 *
 * HARDWARE RING POLLING
 *
 * GLDv3 devices with hardware rings generally deliver chains of messages
 * (mblk_t chain) during the context of a single interrupt. However, interrupts
 * are not the only way that these devices may be used. As part of implementing
 * ring support, a GLDv3 device driver must have a way to disable the generation
 * of that interrupt and allow for the operating system to poll on that ring.
 *
 * To implement this, every soft ring set has a worker thread and a polling
 * thread. If a sufficient packet rate comes into the system, MAC will 'blank'
 * (disable) interrupts on that specific ring and the polling thread will start
 * consuming packets from the hardware device and deliver them to the soft ring
 * set, where the worker thread will take over.
 *
 * Once the rate of packet intake drops down below a certain threshold, then
 * polling on the hardware ring will be quiesced and interrupts will be
 * re-enabled for the given ring. This effectively allows the system to shift
 * how it handles a ring based on its load. At high packet rates, polling on the
 * device as opposed to relying on interrupts can actually reduce overall system
 * load due to the minimization of interrupt activity.
 *
 * Note the importance of each ring having its own interrupt source. The whole
 * idea here is that we do not disable interrupts on the device as a whole, but
 * rather each ring can be independently toggled.
 *
 * USE OF WORKER THREADS
 *
 * Both the soft ring set and individual soft rings have a worker thread
 * associated with them that may be bound to a specific CPU in the system. Any
 * such assignment will get reassessed as part of dynamic reconfiguration events
 * in the system such as the onlining and offlining of CPUs and the creation of
 * CPU partitions.
 *
 * In many cases, while in an interrupt, we try to deliver a frame all the way
 * through the stack in the context of the interrupt itself. However, if the
 * amount of queued frames has exceeded a threshold, then we instead defer to
 * the worker thread to do this work and signal it. This is particularly useful
 * when you have the soft ring set delivering frames into multiple software
 * rings. If it was only delivering frames into a single software ring then
 * there'd be no need to have another thread take over. However, if it's
 * delivering chains of frames to multiple rings, then it's worthwhile to have
 * the worker for the software ring take over so that the different software
 * rings can be processed in parallel.
 *
 * In a similar fashion to the hardware polling thread, if we don't have a
 * backlog or there's nothing to do, then the worker thread will go back to
 * sleep and frames can be delivered all the way from an interrupt. This
 * behavior is useful as it's designed to minimize latency and the default
 * disposition of MAC is to optimize for latency.
 *
 * MAINTAINING CHAINS
 *
 * Another useful idea that MAC uses is to try and maintain frames in chains for
 * as long as possible. The idea is that all of MAC can handle chains of frames
 * structured as a series of mblk_t structures linked with the b_next pointer.
 * When performing software classification and software fanout, MAC does not
 * simply determine the destination and send the frame along. Instead, in the
 * case of classification, it tries to maintain a chain for as long as possible
 * before passing it along and performing additional processing.
 *
 * In the case of fanout, MAC first determines what the target software ring is
 * for every frame in the original chain and constructs a new chain for each
 * target. MAC then delivers the new chain to each software ring in succession.
 *
 * The whole rationale for doing this is that we want to try and maintain the
 * pipe as much as possible and deliver as many frames through the stack at once
 * that we can, rather than just pushing a single frame through. This can often
 * help bring down latency and allows MAC to get a better sense of the overall
 * activity in the system and properly engage worker threads.
 *
 * --------------------
 * Bandwidth Management
 * --------------------
 *
 * Bandwidth management is something that's built into the soft ring set itself.
 * When bandwidth limits are placed on a flow, a corresponding soft ring set is
 * toggled into bandwidth mode. This changes how we transmit and receive the
 * frames in question.
 *
 * Bandwidth management is done on a per-tick basis. We translate the user's
 * requested bandwidth from a quantity per-second into a quantity per-tick. MAC
 * cannot process a frame across more than one tick, thus it sets a lower bound
 * for the bandwidth cap to be a single MTU. This also means that when
 * hires ticks are enabled (hz is set to 1000), that the minimum amount of
 * bandwidth is higher, because the number of ticks has increased and MAC has to
 * go from accepting 100 packets / sec to 1000 / sec.
 *
 * The bandwidth counter is reset by either the soft ring set's worker thread or
 * a thread that is doing an inline transmit or receive if they discover that
 * the current tick is in the future from the recorded tick.
 *
 * Whenever we're receiving or transmitting data, we end up leaving most of the
 * work to the soft ring set's worker thread. This forces data inserted into the
 * soft ring set to be effectively serialized and allows us to exhume bandwidth
 * at a reasonable rate. If there is nothing in the soft ring set at the moment
 * and the set has available bandwidth, then it may processed inline.
 * Otherwise, the worker is responsible for taking care of the soft ring set.
 *
 * ---------------------
 * The Receive Data Path
 * ---------------------
 *
 * The following series of ASCII art images breaks apart the way that a frame
 * comes in and is processed in MAC.
 *
 * Part 1 -- Initial frame receipt, SRS classification
 *
 * Here, a frame is received by a GLDv3 driver, generally in the context of an
 * interrupt, and it ends up in mac_rx_common(). A driver calls either mac_rx or
 * mac_rx_ring, depending on whether or not it supports rings and can identify
 * the interrupt as having come from a specific ring. Here we determine whether
 * or not it's fully classified and perform software classification as
 * appropriate. From here, everything always ends up going to either entry [A]
 * or entry [B] based on whether or not they have subflow processing needed. We
 * leave via fanout or delivery.
 *
 *           +===========+
 *           v hardware  v
 *           v interrupt v
 *           +===========+
 *                 |
 *                 * . . appropriate
 *                 |     upcall made
 *                 |     by GLDv3 driver  . . always
 *                 |                      .
 *  +--------+     |     +----------+     .    +---------------+
 *  | GLDv3  |     +---->| mac_rx   |-----*--->| mac_rx_common |
 *  | Driver |-->--+     +----------+          +---------------+
 *  +--------+     |        ^                         |
 *      |          |        ^                         v
 *      ^          |        * . . always   +----------------------+
 *      |          |        |              | mac_promisc_dispatch |
 *      |          |    +-------------+    +----------------------+
 *      |          +--->| mac_rx_ring |               |
 *      |               +-------------+               * . . hw classified
 *      |                                             v     or single flow?
 *      |                                             |
 *      |                                   +--------++--------------+
 *      |                                   |        |               * hw class,
 *      |                                   |        * hw classified | subflows
 *      |                 no hw class and . *        | or single     | exist
 *      |                 subflows          |        | flow          |
 *      |                                   |        v               v
 *      |                                   |   +-----------+   +-----------+
 *      |                                   |   |   goto    |   |  goto     |
 *      |                                   |   | entry [A] |   | entry [B] |
 *      |                                   |   +-----------+   +-----------+
 *      |                                   v          ^
 *      |                            +-------------+   |
 *      |                            | mac_rx_flow |   * SRS and flow found,
 *      |                            +-------------+   | call flow cb
 *      |                                   |          +------+
 *      |                                   v                 |
 *      v                             +==========+    +-----------------+
 *      |                             v For each v--->| mac_rx_classify |
 * +----------+                       v  mblk_t  v    +-----------------+
 * |   srs    |                       +==========+
 * | pollling |
 * |  thread  |->------------------------------------------+
 * +----------+                                            |
 *                                                         v       . inline
 *            +--------------------+   +----------+   +---------+  .
 *    [A]---->| mac_rx_srs_process |-->| check bw |-->| enqueue |--*---------+
 *            +--------------------+   |  limits  |   | frames  |            |
 *               ^                     +----------+   | to SRS  |            |
 *               |                                    +---------+            |
 *               |  send chain              +--------+    |                  |
 *               *  when clasified          | signal |    * BW limits,       |
 *               |  flow changes            |  srs   |<---+ loopback,        |
 *               |                          | worker |      stack too        |
 *               |                          +--------+      deep             |
 *      +-----------------+        +--------+                                |
 *      | mac_flow_lookup |        |  srs   |     +---------------------+    |
 *      +-----------------+        | worker |---->| mac_rx_srs_drain    |<---+
 *               ^                 | thread |     | mac_rx_srs_drain_bw |
 *               |                 +--------+     +---------------------+
 *               |                                          |
 *         +----------------------------+                   * software rings
 *   [B]-->| mac_rx_srs_subflow_process |                   | for fanout?
 *         +----------------------------+                   |
 *                                               +----------+-----------+
 *                                               |                      |
 *                                               v                      v
 *                                          +--------+             +--------+
 *                                          |  goto  |             |  goto  |
 *                                          | Part 2 |             | Part 3 |
 *                                          +--------+             +--------+
 *
 * Part 2 -- Fanout
 *
 * This part is concerned with using software fanout to assign frames to
 * software rings and then deliver them to MAC clients or allow those rings to
 * be polled upon. While there are two different primary fanout entry points,
 * mac_rx_fanout and mac_rx_proto_fanout, they behave in similar ways, and aside
 * from some of the individual hashing techniques used, most of the general
 * flow is the same.
 *
 *  +--------+              +-------------------+
 *  |  From  |---+--------->| mac_rx_srs_fanout |----+
 *  | Part 1 |   |          +-------------------+    |    +=================+
 *  +--------+   |                                   |    v for each mblk_t v
 *               * . . protocol only                 +--->v assign to new   v
 *               |     fanout                        |    v chain based on  v
 *               |                                   |    v hash % nrings   v
 *               |    +-------------------------+    |    +=================+
 *               +--->| mac_rx_srs_proto_fanout |----+             |
 *                    +-------------------------+                  |
 *                                                                 v
 *    +------------+    +--------------------------+       +================+
 *    | enqueue in |<---| mac_rx_soft_ring_process |<------v for each chain v
 *    | soft ring  |    +--------------------------+       +================+
 *    +------------+
 *         |                                    +-----------+
 *         * soft ring set                      | soft ring |
 *         | empty and no                       |  worker   |
 *         | worker?                            |  thread   |
 *         |                                    +-----------+
 *         +------*----------------+                  |
 *         |      .                |                  v
 *    No . *      . Yes            |       +------------------------+
 *         |                       +----<--| mac_rx_soft_ring_drain |
 *         |                       |       +------------------------+
 *         v                       |
 *   +-----------+                 v
 *   |   signal  |         +---------------+
 *   | soft ring |         | Deliver chain |
 *   |   worker  |         | goto Part 3   |
 *   +-----------+         +---------------+
 *
 *
 * Part 3 -- Packet Delivery
 *
 * Here, we go through and deliver the mblk_t chain directly to a given
 * processing function. In a lot of cases this is mac_rx_deliver(). In the case
 * of DLS bypass being used, then instead we end up going ahead and deliver it
 * to the direct callback registered with DLS, generally ip_input.
 *
 *
 *   +---------+            +----------------+    +------------------+
 *   |  From   |---+------->| mac_rx_deliver |--->| Off to DLS, or   |
 *   | Parts 1 |   |        +----------------+    | other MAC client |
 *   |  and 2  |   * DLS bypass                   +------------------+
 *   +---------+   | enabled   +----------+    +-------------+
 *                 +---------->| ip_input |--->|    To IP    |
 *                             +----------+    | and beyond! |
 *                                             +-------------+
 *
 * ----------------------
 * The Transmit Data Path
 * ----------------------
 *
 * Before we go into the images, it's worth talking about a problem that is a
 * bit different from the receive data path. GLDv3 device drivers have a finite
 * amount of transmit descriptors. When they run out, they return unused frames
 * back to MAC. MAC, at this point has several options about what it will do,
 * which vary based upon the settings that the client uses.
 *
 * When a device runs out of descriptors, the next thing that MAC does is
 * enqueue them off of the soft ring set or a software ring, depending on the
 * configuration of the soft ring set. MAC will enqueue up to a high watermark
 * of mblk_t chains, at which point it will indicate flow control back to the
 * client. Once this condition is reached, any mblk_t chains that were not
 * enqueued will be returned to the caller and they will have to decide what to
 * do with them. There are various flags that control this behavior that a
 * client may pass, which are discussed below.
 *
 * When this condition is hit, MAC also returns a cookie to the client in
 * addition to unconsumed frames. Clients can poll on that cookie and register a
 * callback with MAC to be notified when they are no longer subject to flow
 * control, at which point they may continue to call mac_tx(). This flow control
 * actually manages to work itself all the way up the stack, back through dls,
 * to ip, through the various protocols, and to sockfs.
 *
 * While the behavior described above is the default, this behavior can be
 * modified. There are two alternate modes, described below, which are
 * controlled with flags.
 *
 * DROP MODE
 *
 * This mode is controlled by having the client pass the MAC_DROP_ON_NO_DESC
 * flag. When this is passed, if a device driver runs out of transmit
 * descriptors, then the MAC layer will drop any unsent traffic. The client in
 * this case will never have any frames returned to it.
 *
 * DON'T ENQUEUE
 *
 * This mode is controlled by having the client pass the MAC_TX_NO_ENQUEUE flag.
 * If the MAC_DROP_ON_NO_DESC flag is also passed, it takes precedence. In this
 * mode, when we hit a case where a driver runs out of transmit descriptors,
 * then instead of enqueuing packets in a soft ring set or software ring, we
 * instead return the mblk_t chain back to the caller and immediately put the
 * soft ring set into flow control mode.
 *
 * The following series of ASCII art images describe the transmit data path that
 * MAC clients enter into based on calling into mac_tx(). A soft ring set has a
 * transmission function associated with it. There are seven possible
 * transmission modes, some of which share function entry points. The one that a
 * soft ring set gets depends on properties such as whether there are
 * transmission rings for fanout, whether the device involves aggregations,
 * whether any bandwidth limits exist, etc.
 *
 *
 * Part 1 -- Initial checks
 *
 *      * . called by
 *      |   MAC clients
 *      v                     . . No
 *  +--------+  +-----------+ .   +-------------------+  +====================+
 *  | mac_tx |->| device    |-*-->| mac_protect_check |->v Is this the simple v
 *  +--------+  | quiesced? |     +-------------------+  v case? See [1]      v
 *              +-----------+            |               +====================+
 *                  * . Yes              * failed                 |
 *                  v                    | frames                 |
 *             +--------------+          |                +-------+---------+
 *             | freemsgchain |<---------+          Yes . *            No . *
 *             +--------------+                           v                 v
 *                                                  +-----------+     +--------+
 *                                                  |   goto    |     |  goto  |
 *                                                  |  Part 2   |     | SRS TX |
 *                                                  | Entry [A] |     |  func  |
 *                                                  +-----------+     +--------+
 *                                                        |                 |
 *                                                        |                 v
 *                                                        |           +--------+
 *                                                        +---------->| return |
 *                                                                    | cookie |
 *                                                                    +--------+
 *
 * [1] The simple case refers to the SRS being configured with the
 * SRS_TX_DEFAULT transmission mode, having a single mblk_t (not a chain), their
 * being only a single active client, and not having a backlog in the srs.
 *
 *
 * Part 2 -- The SRS transmission functions
 *
 * This part is a bit more complicated. The different transmission paths often
 * leverage one another. In this case, we'll draw out the more common ones
 * before the parts that depend upon them. Here, we're going to start with the
 * workings of mac_tx_send() a common function that most of the others end up
 * calling.
 *
 *      +-------------+
 *      | mac_tx_send |
 *      +-------------+
 *            |
 *            v
 *      +=============+    +==============+
 *      v  more than  v--->v    check     v
 *      v one client? v    v VLAN and add v
 *      +=============+    v  VLAN tags   v
 *            |            +==============+
 *            |                  |
 *            +------------------+
 *            |
 *            |                 [A]
 *            v                  |
 *       +============+ . No     v
 *       v more than  v .     +==========+     +--------------------------+
 *       v one active v-*---->v for each v---->| mac_promisc_dispatch_one |---+
 *       v  client?   v       v mblk_t   v     +--------------------------+   |
 *       +============+       +==========+        ^                           |
 *            |                                   |       +==========+        |
 *            * . Yes                             |       v hardware v<-------+
 *            v                      +------------+       v  rings?  v
 *       +==========+                |                    +==========+
 *       v for each v       No . . . *                         |
 *       v mblk_t   v       specific |                         |
 *       +==========+       flow     |                   +-----+-----+
 *            |                      |                   |           |
 *            v                      |                   v           v
 *    +-----------------+            |               +-------+  +---------+
 *    | mac_tx_classify |------------+               | GLDv3 |  |  GLDv3  |
 *    +-----------------+                            |TX func|  | ring tx |
 *            |                                      +-------+  |  func   |
 *            * Specific flow, generally                 |      +---------+
 *            | bcast, mcast, loopback                   |           |
 *            v                                          +-----+-----+
 *      +==========+       +---------+                         |
 *      v valid L2 v--*--->| freemsg |                         v
 *      v  header  v  . No +---------+               +-------------------+
 *      +==========+                                 | return unconsumed |
 *            * . Yes                                |   frames to the   |
 *            v                                      |      caller       |
 *      +===========+                                +-------------------+
 *      v braodcast v      +----------------+                  ^
 *      v   flow?   v--*-->| mac_bcast_send |------------------+
 *      +===========+  .   +----------------+                  |
 *            |        . . Yes                                 |
 *       No . *                                                v
 *            |  +---------------------+  +---------------+  +----------+
 *            +->|mac_promisc_dispatch |->| mac_fix_cksum |->|   flow   |
 *               +---------------------+  +---------------+  | callback |
 *                                                           +----------+
 *
 *
 * In addition, many but not all of the routines, all rely on
 * mac_tx_softring_process as an entry point.
 *
 *
 *                                           . No             . No
 * +--------------------------+   +========+ .  +===========+ .  +-------------+
 * | mac_tx_soft_ring_process |-->v worker v-*->v out of tx v-*->|    goto     |
 * +--------------------------+   v only?  v    v  descr.?  v    | mac_tx_send |
 *                                +========+    +===========+    +-------------+
 *                              Yes . *               * . Yes           |
 *                   . No             v               |                 v
 *     v=========+   .          +===========+ . Yes   |     Yes .  +==========+
 *     v apppend v<--*----------v out of tx v-*-------+---------*--v returned v
 *     v mblk_t  v              v  descr.?  v         |            v frames?  v
 *     v chain   v              +===========+         |            +==========+
 *     +=========+                                    |                 *. No
 *         |                                          |                 v
 *         v                                          v           +------------+
 * +===================+           +----------------------+       |   done     |
 * v worker scheduled? v           | mac_tx_sring_enqueue |       | processing |
 * v Out of tx descr?  v           +----------------------+       +------------+
 * +===================+                      |
 *    |           |           . Yes           v
 *    * Yes       * No        .         +============+
 *    |           v         +-*---------v drop on no v
 *    |      +========+     v           v  TX desc?  v
 *    |      v  wake  v  +----------+   +============+
 *    |      v worker v  | mac_pkt_ |         * . No
 *    |      +========+  | drop     |         |         . Yes         . No
 *    |           |      +----------+         v         .             .
 *    |           |         v   ^     +===============+ .  +========+ .
 *    +--+--------+---------+   |     v Don't enqueue v-*->v ring   v-*----+
 *       |                      |     v     Set?      v    v empty? v      |
 *       |      +---------------+     +===============+    +========+      |
 *       |      |                            |                |            |
 *       |      |        +-------------------+                |            |
 *       |      *. Yes   |                          +---------+            |
 *       |      |        v                          v                      v
 *       |      |  +===========+               +========+      +--------------+
 *       |      +<-v At hiwat? v               v append v      |    return    |
 *       |         +===========+               v mblk_t v      | mblk_t chain |
 *       |                  * No               v chain  v      |   and flow   |
 *       |                  v                  +========+      |    control   |
 *       |               +=========+                |          |    cookie    |
 *       |               v  append v                v          +--------------+
 *       |               v  mblk_t v           +========+
 *       |               v  chain  v           v  wake  v   +------------+
 *       |               +=========+           v worker v-->|    done    |
 *       |                    |                +========+   | processing |
 *       |                    v       .. Yes                +------------+
 *       |               +=========+  .   +========+
 *       |               v  first  v--*-->v  wake  v
 *       |               v append? v      v worker v
 *       |               +=========+      +========+
 *       |                   |                |
 *       |              No . *                |
 *       |                   v                |
 *       |       +--------------+             |
 *       +------>|   Return     |             |
 *               | flow control |<------------+
 *               |   cookie     |
 *               +--------------+
 *
 *
 * The remaining images are all specific to each of the different transmission
 * modes.
 *
 * SRS TX DEFAULT
 *
 *      [ From Part 1 ]
 *             |
 *             v
 * +-------------------------+
 * | mac_tx_single_ring_mode |
 * +-------------------------+
 *            |
 *            |       . Yes
 *            v       .
 *       +==========+ .  +============+
 *       v   SRS    v-*->v   Try to   v---->---------------------+
 *       v backlog? v    v enqueue in v                          |
 *       +==========+    v     SRS    v-->------+                * . . Queue too
 *            |          +============+         * don't enqueue  |     deep or
 *            * . No         ^     |            | flag or at     |     drop flag
 *            |              |     v            | hiwat,         |
 *            v              |     |            | return    +---------+
 *     +-------------+       |     |            | cookie    | freemsg |
 *     |    goto     |-*-----+     |            |           +---------+
 *     | mac_tx_send | . returned  |            |                |
 *     +-------------+   mblk_t    |            |                |
 *            |                    |            |                |
 *            |                    |            |                |
 *            * . . all mblk_t     * queued,    |                |
 *            v     consumed       | may return |                |
 *     +-------------+             | tx cookie  |                |
 *     | SRS TX func |<------------+------------+----------------+
 *     |  completed  |
 *     +-------------+
 *
 * SRS_TX_SERIALIZE
 *
 *   +------------------------+
 *   | mac_tx_serializer_mode |
 *   +------------------------+
 *               |
 *               |        . No
 *               v        .
 *         +============+ .  +============+    +-------------+   +============+
 *         v srs being  v-*->v  set SRS   v--->|    goto     |-->v remove SRS v
 *         v processed? v    v proc flags v    | mac_tx_send |   v proc flag  v
 *         +============+    +============+    +-------------+   +============+
 *               |                                                     |
 *               * Yes                                                 |
 *               v                                       . No          v
 *      +--------------------+                           .        +==========+
 *      | mac_tx_srs_enqueue |  +------------------------*-----<--v returned v
 *      +--------------------+  |                                 v frames?  v
 *               |              |   . Yes                         +==========+
 *               |              |   .                                  |
 *               |              |   . +=========+                      v
 *               v              +-<-*-v queued  v     +--------------------+
 *        +-------------+       |     v frames? v<----| mac_tx_srs_enqueue |
 *        | SRS TX func |       |     +=========+     +--------------------+
 *        | completed,  |<------+         * . Yes
 *        | may return  |       |         v
 *        |   cookie    |       |     +========+
 *        +-------------+       +-<---v  wake  v
 *                                    v worker v
 *                                    +========+
 *
 *
 * SRS_TX_FANOUT
 *
 *                                             . Yes
 *   +--------------------+    +=============+ .   +--------------------------+
 *   | mac_tx_fanout_mode |--->v Have fanout v-*-->|           goto           |
 *   +--------------------+    v   hint?     v     | mac_rx_soft_ring_process |
 *                             +=============+     +--------------------------+
 *                                   * . No                    |
 *                                   v                         ^
 *                             +===========+                   |
 *                        +--->v for each  v           +===============+
 *                        |    v   mblk_t  v           v pick softring v
 *                 same   *    +===========+           v   from hash   v
 *                 hash   |          |                 +===============+
 *                        |          v                         |
 *                        |   +--------------+                 |
 *                        +---| mac_pkt_hash |--->*------------+
 *                            +--------------+    . different
 *                                                  hash or
 *                                                  done proc.
 * SRS_TX_AGGR                                      chain
 *
 *   +------------------+    +================================+
 *   | mac_tx_aggr_mode |--->v Use aggr capab function to     v
 *   +------------------+    v find appropriate tx ring.      v
 *                           v Applies hash based on aggr     v
 *                           v policy, see mac_tx_aggr_mode() v
 *                           +================================+
 *                                          |
 *                                          v
 *                           +-------------------------------+
 *                           |            goto               |
 *                           |  mac_rx_srs_soft_ring_process |
 *                           +-------------------------------+
 *
 *
 * SRS_TX_BW, SRS_TX_BW_FANOUT, SRS_TX_BW_AGGR
 *
 * Note, all three of these tx functions start from the same place --
 * mac_tx_bw_mode().
 *
 *  +----------------+
 *  | mac_tx_bw_mode |
 *  +----------------+
 *         |
 *         v          . No               . No               . Yes
 *  +==============+  .  +============+  .  +=============+ .  +=========+
 *  v  Out of BW?  v--*->v SRS empty? v--*->v  reset BW   v-*->v Bump BW v
 *  +==============+     +============+     v tick count? v    v Usage   v
 *         |                   |            +=============+    +=========+
 *         |         +---------+                   |                |
 *         |         |        +--------------------+                |
 *         |         |        |              +----------------------+
 *         v         |        v              v
 * +===============+ |  +==========+   +==========+      +------------------+
 * v Don't enqueue v |  v  set bw  v   v Is aggr? v--*-->|       goto       |
 * v   flag set?   v |  v enforced v   +==========+  .   | mac_tx_aggr_mode |-+
 * +===============+ |  +==========+         |       .   +------------------+ |
 *   |    Yes .*     |        |         No . *       .                        |
 *   |         |     |        |              |       . Yes                    |
 *   * . No    |     |        v              |                                |
 *   |  +---------+  |   +========+          v              +======+          |
 *   |  | freemsg |  |   v append v   +============+  . Yes v pick v          |
 *   |  +---------+  |   v mblk_t v   v Is fanout? v--*---->v ring v          |
 *   |      |        |   v chain  v   +============+        +======+          |
 *   +------+        |   +========+          |                  |             |
 *          v        |        |              v                  v             |
 *    +---------+    |        v       +-------------+ +--------------------+  |
 *    | return  |    |   +========+   |    goto     | |       goto         |  |
 *    |  flow   |    |   v wakeup v   | mac_tx_send | | mac_tx_fanout_mode |  |
 *    | control |    |   v worker v   +-------------+ +--------------------+  |
 *    | cookie  |    |   +========+          |                  |             |
 *    +---------+    |        |              |                  +------+------+
 *                   |        v              |                         |
 *                   |   +---------+         |                         v
 *                   |   | return  |   +============+           +------------+
 *                   |   |  flow   |   v unconsumed v-------+   |   done     |
 *                   |   | control |   v   frames?  v       |   | processing |
 *                   |   | cookie  |   +============+       |   +------------+
 *                   |   +---------+         |              |
 *                   |                  Yes  *              |
 *                   |                       |              |
 *                   |                 +===========+        |
 *                   |                 v subtract  v        |
 *                   |                 v unused bw v        |
 *                   |                 +===========+        |
 *                   |                       |              |
 *                   |                       v              |
 *                   |              +--------------------+  |
 *                   +------------->| mac_tx_srs_enqueue |  |
 *                                  +--------------------+  |
 *                                           |              |
 *                                           |              |
 *                                     +------------+       |
 *                                     |  return fc |       |
 *                                     | cookie and |<------+
 *                                     |    mblk_t  |
 *                                     +------------+
 */

#include <sys/types.h>
#include <sys/callb.h>
#include <sys/sdt.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/vlan.h>
#include <sys/stack.h>
#include <sys/archsystm.h>
#include <inet/ipsec_impl.h>
#include <inet/ip_impl.h>
#include <inet/sadb.h>
#include <inet/ipsecesp.h>
#include <inet/ipsecah.h>
#include <inet/ip6.h>

#include <sys/mac_impl.h>
#include <sys/mac_client_impl.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_soft_ring.h>
#include <sys/mac_flow_impl.h>

static mac_tx_cookie_t mac_tx_single_ring_mode(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);
static mac_tx_cookie_t mac_tx_serializer_mode(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);
static mac_tx_cookie_t mac_tx_fanout_mode(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);
static mac_tx_cookie_t mac_tx_bw_mode(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);
static mac_tx_cookie_t mac_tx_aggr_mode(mac_soft_ring_set_t *, mblk_t *,
    uintptr_t, uint16_t, mblk_t **);

typedef struct mac_tx_mode_s {
	mac_tx_srs_mode_t	mac_tx_mode;
	mac_tx_func_t		mac_tx_func;
} mac_tx_mode_t;

/*
 * There are seven modes of operation on the Tx side. These modes get set
 * in mac_tx_srs_setup(). Except for the experimental TX_SERIALIZE mode,
 * none of the other modes are user configurable. They get selected by
 * the system depending upon whether the link (or flow) has multiple Tx
 * rings or a bandwidth configured, or if the link is an aggr, etc.
 *
 * When the Tx SRS is operating in aggr mode (st_mode) or if there are
 * multiple Tx rings owned by Tx SRS, then each Tx ring (pseudo or
 * otherwise) will have a soft ring associated with it. These soft rings
 * are stored in srs_tx_soft_rings[] array.
 *
 * Additionally in the case of aggr, there is the st_soft_rings[] array
 * in the mac_srs_tx_t structure. This array is used to store the same
 * set of soft rings that are present in srs_tx_soft_rings[] array but
 * in a different manner. The soft ring associated with the pseudo Tx
 * ring is saved at mr_index (of the pseudo ring) in st_soft_rings[]
 * array. This helps in quickly getting the soft ring associated with the
 * Tx ring when aggr_find_tx_ring() returns the pseudo Tx ring that is to
 * be used for transmit.
 */
mac_tx_mode_t mac_tx_mode_list[] = {
	{SRS_TX_DEFAULT,	mac_tx_single_ring_mode},
	{SRS_TX_SERIALIZE,	mac_tx_serializer_mode},
	{SRS_TX_FANOUT,		mac_tx_fanout_mode},
	{SRS_TX_BW,		mac_tx_bw_mode},
	{SRS_TX_BW_FANOUT,	mac_tx_bw_mode},
	{SRS_TX_AGGR,		mac_tx_aggr_mode},
	{SRS_TX_BW_AGGR,	mac_tx_bw_mode}
};

/*
 * Soft Ring Set (SRS) - The Run time code that deals with
 * dynamic polling from the hardware, bandwidth enforcement,
 * fanout etc.
 *
 * We try to use H/W classification on NIC and assign traffic for
 * a MAC address to a particular Rx ring or ring group. There is a
 * 1-1 mapping between a SRS and a Rx ring. The SRS dynamically
 * switches the underlying Rx ring between interrupt and
 * polling mode and enforces any specified B/W control.
 *
 * There is always a SRS created and tied to each H/W and S/W rule.
 * Whenever we create a H/W rule, we always add the the same rule to
 * S/W classifier and tie a SRS to it.
 *
 * In case a B/W control is specified, it is broken into bytes
 * per ticks and as soon as the quota for a tick is exhausted,
 * the underlying Rx ring is forced into poll mode for remainder of
 * the tick. The SRS poll thread only polls for bytes that are
 * allowed to come in the SRS. We typically let 4x the configured
 * B/W worth of packets to come in the SRS (to prevent unnecessary
 * drops due to bursts) but only process the specified amount.
 *
 * A MAC client (e.g. a VNIC or aggr) can have 1 or more
 * Rx rings (and corresponding SRSs) assigned to it. The SRS
 * in turn can have softrings to do protocol level fanout or
 * softrings to do S/W based fanout or both. In case the NIC
 * has no Rx rings, we do S/W classification to respective SRS.
 * The S/W classification rule is always setup and ready. This
 * allows the MAC layer to reassign Rx rings whenever needed
 * but packets still continue to flow via the default path and
 * getting S/W classified to correct SRS.
 *
 * The SRS's are used on both Tx and Rx side. They use the same
 * data structure but the processing routines have slightly different
 * semantics due to the fact that Rx side needs to do dynamic
 * polling etc.
 *
 * Dynamic Polling Notes
 * =====================
 *
 * Each Soft ring set is capable of switching its Rx ring between
 * interrupt and poll mode and actively 'polls' for packets in
 * poll mode. If the SRS is implementing a B/W limit, it makes
 * sure that only Max allowed packets are pulled in poll mode
 * and goes to poll mode as soon as B/W limit is exceeded. As
 * such, there are no overheads to implement B/W limits.
 *
 * In poll mode, its better to keep the pipeline going where the
 * SRS worker thread keeps processing packets and poll thread
 * keeps bringing more packets (specially if they get to run
 * on different CPUs). This also prevents the overheads associated
 * by excessive signalling (on NUMA machines, this can be
 * pretty devastating). The exception is latency optimized case
 * where worker thread does no work and interrupt and poll thread
 * are allowed to do their own drain.
 *
 * We use the following policy to control Dynamic Polling:
 * 1) We switch to poll mode anytime the processing
 *    thread causes a backlog to build up in SRS and
 *    its associated Soft Rings (sr_poll_pkt_cnt > 0).
 * 2) As long as the backlog stays under the low water
 *    mark (sr_lowat), we poll the H/W for more packets.
 * 3) If the backlog (sr_poll_pkt_cnt) exceeds low
 *    water mark, we stay in poll mode but don't poll
 *    the H/W for more packets.
 * 4) Anytime in polling mode, if we poll the H/W for
 *    packets and find nothing plus we have an existing
 *    backlog (sr_poll_pkt_cnt > 0), we stay in polling
 *    mode but don't poll the H/W for packets anymore
 *    (let the polling thread go to sleep).
 * 5) Once the backlog is relived (packets are processed)
 *    we reenable polling (by signalling the poll thread)
 *    only when the backlog dips below sr_poll_thres.
 * 6) sr_hiwat is used exclusively when we are not
 *    polling capable and is used to decide when to
 *    drop packets so the SRS queue length doesn't grow
 *    infinitely.
 *
 * NOTE: Also see the block level comment on top of mac_soft_ring.c
 */

/*
 * mac_latency_optimize
 *
 * Controls whether the poll thread can process the packets inline
 * or let the SRS worker thread do the processing. This applies if
 * the SRS was not being processed. For latency sensitive traffic,
 * this needs to be true to allow inline processing. For throughput
 * under load, this should be false.
 *
 * This (and other similar) tunable should be rolled into a link
 * or flow specific workload hint that can be set using dladm
 * linkprop (instead of multiple such tunables).
 */
boolean_t mac_latency_optimize = B_TRUE;

/*
 * MAC_RX_SRS_ENQUEUE_CHAIN and MAC_TX_SRS_ENQUEUE_CHAIN
 *
 * queue a mp or chain in soft ring set and increment the
 * local count (srs_count) for the SRS and the shared counter
 * (srs_poll_pkt_cnt - shared between SRS and its soft rings
 * to track the total unprocessed packets for polling to work
 * correctly).
 *
 * The size (total bytes queued) counters are incremented only
 * if we are doing B/W control.
 */
#define	MAC_SRS_ENQUEUE_CHAIN(mac_srs, head, tail, count, sz) {		\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	if ((mac_srs)->srs_last != NULL)				\
		(mac_srs)->srs_last->b_next = (head);			\
	else								\
		(mac_srs)->srs_first = (head);				\
	(mac_srs)->srs_last = (tail);					\
	(mac_srs)->srs_count += count;					\
}

#define	MAC_RX_SRS_ENQUEUE_CHAIN(mac_srs, head, tail, count, sz) {	\
	mac_srs_rx_t	*srs_rx = &(mac_srs)->srs_rx;			\
									\
	MAC_SRS_ENQUEUE_CHAIN(mac_srs, head, tail, count, sz);		\
	srs_rx->sr_poll_pkt_cnt += count;				\
	ASSERT(srs_rx->sr_poll_pkt_cnt > 0);				\
	if ((mac_srs)->srs_type & SRST_BW_CONTROL) {			\
		(mac_srs)->srs_size += (sz);				\
		mutex_enter(&(mac_srs)->srs_bw->mac_bw_lock);		\
		(mac_srs)->srs_bw->mac_bw_sz += (sz);			\
		mutex_exit(&(mac_srs)->srs_bw->mac_bw_lock);		\
	}								\
}

#define	MAC_TX_SRS_ENQUEUE_CHAIN(mac_srs, head, tail, count, sz) {	\
	mac_srs->srs_state |= SRS_ENQUEUED;				\
	MAC_SRS_ENQUEUE_CHAIN(mac_srs, head, tail, count, sz);		\
	if ((mac_srs)->srs_type & SRST_BW_CONTROL) {			\
		(mac_srs)->srs_size += (sz);				\
		(mac_srs)->srs_bw->mac_bw_sz += (sz);			\
	}								\
}

/*
 * Turn polling on routines
 */
#define	MAC_SRS_POLLING_ON(mac_srs) {					\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	if (((mac_srs)->srs_state &					\
	    (SRS_POLLING_CAPAB|SRS_POLLING)) == SRS_POLLING_CAPAB) {	\
		(mac_srs)->srs_state |= SRS_POLLING;			\
		(void) mac_hwring_disable_intr((mac_ring_handle_t)	\
		    (mac_srs)->srs_ring);				\
		(mac_srs)->srs_rx.sr_poll_on++;				\
	}								\
}

#define	MAC_SRS_WORKER_POLLING_ON(mac_srs) {				\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	if (((mac_srs)->srs_state &					\
	    (SRS_POLLING_CAPAB|SRS_WORKER|SRS_POLLING)) == 		\
	    (SRS_POLLING_CAPAB|SRS_WORKER)) {				\
		(mac_srs)->srs_state |= SRS_POLLING;			\
		(void) mac_hwring_disable_intr((mac_ring_handle_t)	\
		    (mac_srs)->srs_ring);				\
		(mac_srs)->srs_rx.sr_worker_poll_on++;			\
	}								\
}

/*
 * MAC_SRS_POLL_RING
 *
 * Signal the SRS poll thread to poll the underlying H/W ring
 * provided it wasn't already polling (SRS_GET_PKTS was set).
 *
 * Poll thread gets to run only from mac_rx_srs_drain() and only
 * if the drain was being done by the worker thread.
 */
#define	MAC_SRS_POLL_RING(mac_srs) {					\
	mac_srs_rx_t	*srs_rx = &(mac_srs)->srs_rx;			\
									\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	srs_rx->sr_poll_thr_sig++;					\
	if (((mac_srs)->srs_state & 					\
	    (SRS_POLLING_CAPAB|SRS_WORKER|SRS_GET_PKTS)) ==		\
		(SRS_WORKER|SRS_POLLING_CAPAB)) {			\
		(mac_srs)->srs_state |= SRS_GET_PKTS;			\
		cv_signal(&(mac_srs)->srs_cv);   			\
	} else {							\
		srs_rx->sr_poll_thr_busy++;				\
	}								\
}

/*
 * MAC_SRS_CHECK_BW_CONTROL
 *
 * Check to see if next tick has started so we can reset the
 * SRS_BW_ENFORCED flag and allow more packets to come in the
 * system.
 */
#define	MAC_SRS_CHECK_BW_CONTROL(mac_srs) {				\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	ASSERT(((mac_srs)->srs_type & SRST_TX) ||			\
	    MUTEX_HELD(&(mac_srs)->srs_bw->mac_bw_lock));		\
	clock_t now = ddi_get_lbolt();					\
	if ((mac_srs)->srs_bw->mac_bw_curr_time != now) {		\
		(mac_srs)->srs_bw->mac_bw_curr_time = now;		\
		(mac_srs)->srs_bw->mac_bw_used = 0;	       		\
		if ((mac_srs)->srs_bw->mac_bw_state & SRS_BW_ENFORCED)	\
			(mac_srs)->srs_bw->mac_bw_state &= ~SRS_BW_ENFORCED; \
	}								\
}

/*
 * MAC_SRS_WORKER_WAKEUP
 *
 * Wake up the SRS worker thread to process the queue as long as
 * no one else is processing the queue. If we are optimizing for
 * latency, we wake up the worker thread immediately or else we
 * wait mac_srs_worker_wakeup_ticks before worker thread gets
 * woken up.
 */
int mac_srs_worker_wakeup_ticks = 0;
#define	MAC_SRS_WORKER_WAKEUP(mac_srs) {				\
	ASSERT(MUTEX_HELD(&(mac_srs)->srs_lock));			\
	if (!((mac_srs)->srs_state & SRS_PROC) &&			\
		(mac_srs)->srs_tid == NULL) {				\
		if (((mac_srs)->srs_state & SRS_LATENCY_OPT) ||		\
			(mac_srs_worker_wakeup_ticks == 0))		\
			cv_signal(&(mac_srs)->srs_async);		\
		else							\
			(mac_srs)->srs_tid =				\
				timeout(mac_srs_fire, (mac_srs),	\
					mac_srs_worker_wakeup_ticks);	\
	}								\
}

#define	TX_BANDWIDTH_MODE(mac_srs)				\
	((mac_srs)->srs_tx.st_mode == SRS_TX_BW ||		\
	    (mac_srs)->srs_tx.st_mode == SRS_TX_BW_FANOUT ||	\
	    (mac_srs)->srs_tx.st_mode == SRS_TX_BW_AGGR)

#define	TX_SRS_TO_SOFT_RING(mac_srs, head, hint) {			\
	if (tx_mode == SRS_TX_BW_FANOUT)				\
		(void) mac_tx_fanout_mode(mac_srs, head, hint, 0, NULL);\
	else								\
		(void) mac_tx_aggr_mode(mac_srs, head, hint, 0, NULL);	\
}

/*
 * MAC_TX_SRS_BLOCK
 *
 * Always called from mac_tx_srs_drain() function. SRS_TX_BLOCKED
 * will be set only if srs_tx_woken_up is FALSE. If
 * srs_tx_woken_up is TRUE, it indicates that the wakeup arrived
 * before we grabbed srs_lock to set SRS_TX_BLOCKED. We need to
 * attempt to transmit again and not setting SRS_TX_BLOCKED does
 * that.
 */
#define	MAC_TX_SRS_BLOCK(srs, mp)	{			\
	ASSERT(MUTEX_HELD(&(srs)->srs_lock));			\
	if ((srs)->srs_tx.st_woken_up) {			\
		(srs)->srs_tx.st_woken_up = B_FALSE;		\
	} else {						\
		ASSERT(!((srs)->srs_state & SRS_TX_BLOCKED));	\
		(srs)->srs_state |= SRS_TX_BLOCKED;		\
		(srs)->srs_tx.st_stat.mts_blockcnt++;		\
	}							\
}

/*
 * MAC_TX_SRS_TEST_HIWAT
 *
 * Called before queueing a packet onto Tx SRS to test and set
 * SRS_TX_HIWAT if srs_count exceeds srs_tx_hiwat.
 */
#define	MAC_TX_SRS_TEST_HIWAT(srs, mp, tail, cnt, sz, cookie) {		\
	boolean_t enqueue = 1;						\
									\
	if ((srs)->srs_count > (srs)->srs_tx.st_hiwat) {		\
		/*							\
		 * flow-controlled. Store srs in cookie so that it	\
		 * can be returned as mac_tx_cookie_t to client		\
		 */							\
		(srs)->srs_state |= SRS_TX_HIWAT;			\
		cookie = (mac_tx_cookie_t)srs;				\
		(srs)->srs_tx.st_hiwat_cnt++;				\
		if ((srs)->srs_count > (srs)->srs_tx.st_max_q_cnt) {	\
			/* increment freed stats */			\
			(srs)->srs_tx.st_stat.mts_sdrops += cnt;	\
			/*						\
			 * b_prev may be set to the fanout hint		\
			 * hence can't use freemsg directly		\
			 */						\
			mac_pkt_drop(NULL, NULL, mp_chain, B_FALSE);	\
			DTRACE_PROBE1(tx_queued_hiwat,			\
			    mac_soft_ring_set_t *, srs);		\
			enqueue = 0;					\
		}							\
	}								\
	if (enqueue)							\
		MAC_TX_SRS_ENQUEUE_CHAIN(srs, mp, tail, cnt, sz);	\
}

/* Some utility macros */
#define	MAC_SRS_BW_LOCK(srs)						\
	if (!(srs->srs_type & SRST_TX))					\
		mutex_enter(&srs->srs_bw->mac_bw_lock);

#define	MAC_SRS_BW_UNLOCK(srs)						\
	if (!(srs->srs_type & SRST_TX))					\
		mutex_exit(&srs->srs_bw->mac_bw_lock);

#define	MAC_TX_SRS_DROP_MESSAGE(srs, mp, cookie) {		\
	mac_pkt_drop(NULL, NULL, mp, B_FALSE);			\
	/* increment freed stats */				\
	mac_srs->srs_tx.st_stat.mts_sdrops++;			\
	cookie = (mac_tx_cookie_t)srs;				\
}

#define	MAC_TX_SET_NO_ENQUEUE(srs, mp_chain, ret_mp, cookie) {		\
	mac_srs->srs_state |= SRS_TX_WAKEUP_CLIENT;			\
	cookie = (mac_tx_cookie_t)srs;					\
	*ret_mp = mp_chain;						\
}

/*
 * MAC_RX_SRS_TOODEEP
 *
 * Macro called as part of receive-side processing to determine if handling
 * can occur in situ (in the interrupt thread) or if it should be left to a
 * worker thread.  Note that the constant used to make this determination is
 * not entirely made-up, and is a result of some emprical validation. That
 * said, the constant is left as a static variable to allow it to be
 * dynamically tuned in the field if and as needed.
 */
static uintptr_t mac_rx_srs_stack_needed = 10240;
static uint_t mac_rx_srs_stack_toodeep;

#ifndef STACK_GROWTH_DOWN
#error Downward stack growth assumed.
#endif

#define	MAC_RX_SRS_TOODEEP() (STACK_BIAS + (uintptr_t)getfp() - \
	(uintptr_t)curthread->t_stkbase < mac_rx_srs_stack_needed && \
	++mac_rx_srs_stack_toodeep)


/*
 * Drop the rx packet and advance to the next one in the chain.
 */
static void
mac_rx_drop_pkt(mac_soft_ring_set_t *srs, mblk_t *mp)
{
	mac_srs_rx_t	*srs_rx = &srs->srs_rx;

	ASSERT(mp->b_next == NULL);
	mutex_enter(&srs->srs_lock);
	MAC_UPDATE_SRS_COUNT_LOCKED(srs, 1);
	MAC_UPDATE_SRS_SIZE_LOCKED(srs, msgdsize(mp));
	mutex_exit(&srs->srs_lock);

	srs_rx->sr_stat.mrs_sdrops++;
	freemsg(mp);
}

/* DATAPATH RUNTIME ROUTINES */

/*
 * mac_srs_fire
 *
 * Timer callback routine for waking up the SRS worker thread.
 */
static void
mac_srs_fire(void *arg)
{
	mac_soft_ring_set_t *mac_srs = (mac_soft_ring_set_t *)arg;

	mutex_enter(&mac_srs->srs_lock);
	if (mac_srs->srs_tid == 0) {
		mutex_exit(&mac_srs->srs_lock);
		return;
	}

	mac_srs->srs_tid = 0;
	if (!(mac_srs->srs_state & SRS_PROC))
		cv_signal(&mac_srs->srs_async);

	mutex_exit(&mac_srs->srs_lock);
}

/*
 * 'hint' is fanout_hint (type of uint64_t) which is given by the TCP/IP stack,
 * and it is used on the TX path.
 */
#define	HASH_HINT(hint)	\
	((hint) ^ ((hint) >> 24) ^ ((hint) >> 16) ^ ((hint) >> 8))


/*
 * hash based on the src address, dst address and the port information.
 */
#define	HASH_ADDR(src, dst, ports)					\
	(ntohl((src) + (dst)) ^ ((ports) >> 24) ^ ((ports) >> 16) ^	\
	((ports) >> 8) ^ (ports))

#define	COMPUTE_INDEX(key, sz)	(key % sz)

#define	FANOUT_ENQUEUE_MP(head, tail, cnt, bw_ctl, sz, sz0, mp) {	\
	if ((tail) != NULL) {						\
		ASSERT((tail)->b_next == NULL);				\
		(tail)->b_next = (mp);					\
	} else {							\
		ASSERT((head) == NULL);					\
		(head) = (mp);						\
	}								\
	(tail) = (mp);							\
	(cnt)++;							\
	if ((bw_ctl))							\
		(sz) += (sz0);						\
}

#define	MAC_FANOUT_DEFAULT	0
#define	MAC_FANOUT_RND_ROBIN	1
int mac_fanout_type = MAC_FANOUT_DEFAULT;

#define	MAX_SR_TYPES	3
/* fanout types for port based hashing */
enum pkt_type {
	V4_TCP = 0,
	V4_UDP,
	OTH,
	UNDEF
};

/*
 * Pair of local and remote ports in the transport header
 */
#define	PORTS_SIZE 4

/*
 * mac_rx_srs_proto_fanout
 *
 * This routine delivers packets destined to an SRS into one of the
 * protocol soft rings.
 *
 * Given a chain of packets we need to split it up into multiple sub chains
 * destined into TCP, UDP or OTH soft ring. Instead of entering
 * the soft ring one packet at a time, we want to enter it in the form of a
 * chain otherwise we get this start/stop behaviour where the worker thread
 * goes to sleep and then next packets comes in forcing it to wake up etc.
 */
static void
mac_rx_srs_proto_fanout(mac_soft_ring_set_t *mac_srs, mblk_t *head)
{
	struct ether_header		*ehp;
	struct ether_vlan_header	*evhp;
	uint32_t			sap;
	ipha_t				*ipha;
	uint8_t				*dstaddr;
	size_t				hdrsize;
	mblk_t				*mp;
	mblk_t				*headmp[MAX_SR_TYPES];
	mblk_t				*tailmp[MAX_SR_TYPES];
	int				cnt[MAX_SR_TYPES];
	size_t				sz[MAX_SR_TYPES];
	size_t				sz1;
	boolean_t			bw_ctl;
	boolean_t			hw_classified;
	boolean_t			dls_bypass;
	boolean_t			is_ether;
	boolean_t			is_unicast;
	enum pkt_type			type;
	mac_client_impl_t		*mcip = mac_srs->srs_mcip;

	is_ether = (mcip->mci_mip->mi_info.mi_nativemedia == DL_ETHER);
	bw_ctl = ((mac_srs->srs_type & SRST_BW_CONTROL) != 0);

	/*
	 * If we don't have a Rx ring, S/W classification would have done
	 * its job and its a packet meant for us. If we were polling on
	 * the default ring (i.e. there was a ring assigned to this SRS),
	 * then we need to make sure that the mac address really belongs
	 * to us.
	 */
	hw_classified = mac_srs->srs_ring != NULL &&
	    mac_srs->srs_ring->mr_classify_type == MAC_HW_CLASSIFIER;

	/*
	 * Special clients (eg. VLAN, non ether, etc) need DLS
	 * processing in the Rx path. SRST_DLS_BYPASS will be clear for
	 * such SRSs. Another way of disabling bypass is to set the
	 * MCIS_RX_BYPASS_DISABLE flag.
	 */
	dls_bypass = ((mac_srs->srs_type & SRST_DLS_BYPASS) != 0) &&
	    ((mcip->mci_state_flags & MCIS_RX_BYPASS_DISABLE) == 0);

	bzero(headmp, MAX_SR_TYPES * sizeof (mblk_t *));
	bzero(tailmp, MAX_SR_TYPES * sizeof (mblk_t *));
	bzero(cnt, MAX_SR_TYPES * sizeof (int));
	bzero(sz, MAX_SR_TYPES * sizeof (size_t));

	/*
	 * We got a chain from SRS that we need to send to the soft rings.
	 * Since squeues for TCP & IPv4 sap poll their soft rings (for
	 * performance reasons), we need to separate out v4_tcp, v4_udp
	 * and the rest goes in other.
	 */
	while (head != NULL) {
		mp = head;
		head = head->b_next;
		mp->b_next = NULL;

		type = OTH;
		sz1 = (mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp);

		if (is_ether) {
			/*
			 * At this point we can be sure the packet at least
			 * has an ether header.
			 */
			if (sz1 < sizeof (struct ether_header)) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}
			ehp = (struct ether_header *)mp->b_rptr;

			/*
			 * Determine if this is a VLAN or non-VLAN packet.
			 */
			if ((sap = ntohs(ehp->ether_type)) == VLAN_TPID) {
				evhp = (struct ether_vlan_header *)mp->b_rptr;
				sap = ntohs(evhp->ether_type);
				hdrsize = sizeof (struct ether_vlan_header);
				/*
				 * Check if the VID of the packet, if any,
				 * belongs to this client.
				 */
				if (!mac_client_check_flow_vid(mcip,
				    VLAN_ID(ntohs(evhp->ether_tci)))) {
					mac_rx_drop_pkt(mac_srs, mp);
					continue;
				}
			} else {
				hdrsize = sizeof (struct ether_header);
			}
			is_unicast =
			    ((((uint8_t *)&ehp->ether_dhost)[0] & 0x01) == 0);
			dstaddr = (uint8_t *)&ehp->ether_dhost;
		} else {
			mac_header_info_t		mhi;

			if (mac_header_info((mac_handle_t)mcip->mci_mip,
			    mp, &mhi) != 0) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}
			hdrsize = mhi.mhi_hdrsize;
			sap = mhi.mhi_bindsap;
			is_unicast = (mhi.mhi_dsttype == MAC_ADDRTYPE_UNICAST);
			dstaddr = (uint8_t *)mhi.mhi_daddr;
		}

		if (!dls_bypass) {
			FANOUT_ENQUEUE_MP(headmp[type], tailmp[type],
			    cnt[type], bw_ctl, sz[type], sz1, mp);
			continue;
		}

		if (sap == ETHERTYPE_IP) {
			/*
			 * If we are H/W classified, but we have promisc
			 * on, then we need to check for the unicast address.
			 */
			if (hw_classified && mcip->mci_promisc_list != NULL) {
				mac_address_t		*map;

				rw_enter(&mcip->mci_rw_lock, RW_READER);
				map = mcip->mci_unicast;
				if (bcmp(dstaddr, map->ma_addr,
				    map->ma_len) == 0)
					type = UNDEF;
				rw_exit(&mcip->mci_rw_lock);
			} else if (is_unicast) {
				type = UNDEF;
			}
		}

		/*
		 * This needs to become a contract with the driver for
		 * the fast path.
		 *
		 * In the normal case the packet will have at least the L2
		 * header and the IP + Transport header in the same mblk.
		 * This is usually the case when the NIC driver sends up
		 * the packet. This is also true when the stack generates
		 * a packet that is looped back and when the stack uses the
		 * fastpath mechanism. The normal case is optimized for
		 * performance and may bypass DLS. All other cases go through
		 * the 'OTH' type path without DLS bypass.
		 */

		ipha = (ipha_t *)(mp->b_rptr + hdrsize);
		if ((type != OTH) && MBLK_RX_FANOUT_SLOWPATH(mp, ipha))
			type = OTH;

		if (type == OTH) {
			FANOUT_ENQUEUE_MP(headmp[type], tailmp[type],
			    cnt[type], bw_ctl, sz[type], sz1, mp);
			continue;
		}

		ASSERT(type == UNDEF);
		/*
		 * We look for at least 4 bytes past the IP header to get
		 * the port information. If we get an IP fragment, we don't
		 * have the port information, and we use just the protocol
		 * information.
		 */
		switch (ipha->ipha_protocol) {
		case IPPROTO_TCP:
			type = V4_TCP;
			mp->b_rptr += hdrsize;
			break;
		case IPPROTO_UDP:
			type = V4_UDP;
			mp->b_rptr += hdrsize;
			break;
		default:
			type = OTH;
			break;
		}

		FANOUT_ENQUEUE_MP(headmp[type], tailmp[type], cnt[type],
		    bw_ctl, sz[type], sz1, mp);
	}

	for (type = V4_TCP; type < UNDEF; type++) {
		if (headmp[type] != NULL) {
			mac_soft_ring_t			*softring;

			ASSERT(tailmp[type]->b_next == NULL);
			switch (type) {
			case V4_TCP:
				softring = mac_srs->srs_tcp_soft_rings[0];
				break;
			case V4_UDP:
				softring = mac_srs->srs_udp_soft_rings[0];
				break;
			case OTH:
				softring = mac_srs->srs_oth_soft_rings[0];
			}
			mac_rx_soft_ring_process(mcip, softring,
			    headmp[type], tailmp[type], cnt[type], sz[type]);
		}
	}
}

int	fanout_unaligned = 0;

/*
 * mac_rx_srs_long_fanout
 *
 * The fanout routine for VLANs, and for anything else that isn't performing
 * explicit dls bypass.  Returns -1 on an error (drop the packet due to a
 * malformed packet), 0 on success, with values written in *indx and *type.
 */
static int
mac_rx_srs_long_fanout(mac_soft_ring_set_t *mac_srs, mblk_t *mp,
    uint32_t sap, size_t hdrsize, enum pkt_type *type, uint_t *indx)
{
	ip6_t		*ip6h;
	ipha_t		*ipha;
	uint8_t		*whereptr;
	uint_t		hash;
	uint16_t	remlen;
	uint8_t		nexthdr;
	uint16_t	hdr_len;
	uint32_t	src_val, dst_val;
	boolean_t	modifiable = B_TRUE;
	boolean_t	v6;

	ASSERT(MBLKL(mp) >= hdrsize);

	if (sap == ETHERTYPE_IPV6) {
		v6 = B_TRUE;
		hdr_len = IPV6_HDR_LEN;
	} else if (sap == ETHERTYPE_IP) {
		v6 = B_FALSE;
		hdr_len = IP_SIMPLE_HDR_LENGTH;
	} else {
		*indx = 0;
		*type = OTH;
		return (0);
	}

	ip6h = (ip6_t *)(mp->b_rptr + hdrsize);
	ipha = (ipha_t *)ip6h;

	if ((uint8_t *)ip6h == mp->b_wptr) {
		/*
		 * The first mblk_t only includes the mac header.
		 * Note that it is safe to change the mp pointer here,
		 * as the subsequent operation does not assume mp
		 * points to the start of the mac header.
		 */
		mp = mp->b_cont;

		/*
		 * Make sure the IP header points to an entire one.
		 */
		if (mp == NULL)
			return (-1);

		if (MBLKL(mp) < hdr_len) {
			modifiable = (DB_REF(mp) == 1);

			if (modifiable && !pullupmsg(mp, hdr_len))
				return (-1);
		}

		ip6h = (ip6_t *)mp->b_rptr;
		ipha = (ipha_t *)ip6h;
	}

	if (!modifiable || !(OK_32PTR((char *)ip6h)) ||
	    ((uint8_t *)ip6h + hdr_len > mp->b_wptr)) {
		/*
		 * If either the IP header is not aligned, or it does not hold
		 * the complete simple structure (a pullupmsg() is not an
		 * option since it would result in an unaligned IP header),
		 * fanout to the default ring.
		 *
		 * Note that this may cause packet reordering.
		 */
		*indx = 0;
		*type = OTH;
		fanout_unaligned++;
		return (0);
	}

	/*
	 * Extract next-header, full header length, and source-hash value
	 * using v4/v6 specific fields.
	 */
	if (v6) {
		remlen = ntohs(ip6h->ip6_plen);
		nexthdr = ip6h->ip6_nxt;
		src_val = V4_PART_OF_V6(ip6h->ip6_src);
		dst_val = V4_PART_OF_V6(ip6h->ip6_dst);
		/*
		 * Do src based fanout if below tunable is set to B_TRUE or
		 * when mac_ip_hdr_length_v6() fails because of malformed
		 * packets or because mblks need to be concatenated using
		 * pullupmsg().
		 */
		if (!mac_ip_hdr_length_v6(ip6h, mp->b_wptr, &hdr_len, &nexthdr,
		    NULL)) {
			goto src_dst_based_fanout;
		}
	} else {
		hdr_len = IPH_HDR_LENGTH(ipha);
		remlen = ntohs(ipha->ipha_length) - hdr_len;
		nexthdr = ipha->ipha_protocol;
		src_val = (uint32_t)ipha->ipha_src;
		dst_val = (uint32_t)ipha->ipha_dst;
		/*
		 * Catch IPv4 fragment case here.  IPv6 has nexthdr == FRAG
		 * for its equivalent case.
		 */
		if ((ntohs(ipha->ipha_fragment_offset_and_flags) &
		    (IPH_MF | IPH_OFFSET)) != 0) {
			goto src_dst_based_fanout;
		}
	}
	if (remlen < MIN_EHDR_LEN)
		return (-1);
	whereptr = (uint8_t *)ip6h + hdr_len;

	/* If the transport is one of below, we do port/SPI based fanout */
	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
	case IPPROTO_ESP:
		/*
		 * If the ports or SPI in the transport header is not part of
		 * the mblk, do src_based_fanout, instead of calling
		 * pullupmsg().
		 */
		if (mp->b_cont == NULL || whereptr + PORTS_SIZE <= mp->b_wptr)
			break;	/* out of switch... */
		/* FALLTHRU */
	default:
		goto src_dst_based_fanout;
	}

	switch (nexthdr) {
	case IPPROTO_TCP:
		hash = HASH_ADDR(src_val, dst_val, *(uint32_t *)whereptr);
		*indx = COMPUTE_INDEX(hash, mac_srs->srs_tcp_ring_count);
		*type = OTH;
		break;
	case IPPROTO_UDP:
	case IPPROTO_SCTP:
	case IPPROTO_ESP:
		if (mac_fanout_type == MAC_FANOUT_DEFAULT) {
			hash = HASH_ADDR(src_val, dst_val,
			    *(uint32_t *)whereptr);
			*indx = COMPUTE_INDEX(hash,
			    mac_srs->srs_udp_ring_count);
		} else {
			*indx = mac_srs->srs_ind % mac_srs->srs_udp_ring_count;
			mac_srs->srs_ind++;
		}
		*type = OTH;
		break;
	}
	return (0);

src_dst_based_fanout:
	hash = HASH_ADDR(src_val, dst_val, (uint32_t)0);
	*indx = COMPUTE_INDEX(hash, mac_srs->srs_oth_ring_count);
	*type = OTH;
	return (0);
}

/*
 * mac_rx_srs_fanout
 *
 * This routine delivers packets destined to an SRS into a soft ring member
 * of the set.
 *
 * Given a chain of packets we need to split it up into multiple sub chains
 * destined for one of the TCP, UDP or OTH soft rings. Instead of entering
 * the soft ring one packet at a time, we want to enter it in the form of a
 * chain otherwise we get this start/stop behaviour where the worker thread
 * goes to sleep and then next packets comes in forcing it to wake up etc.
 *
 * Note:
 * Since we know what is the maximum fanout possible, we create a 2D array
 * of 'softring types * MAX_SR_FANOUT' for the head, tail, cnt and sz
 * variables so that we can enter the softrings with chain. We need the
 * MAX_SR_FANOUT so we can allocate the arrays on the stack (a kmem_alloc
 * for each packet would be expensive). If we ever want to have the
 * ability to have unlimited fanout, we should probably declare a head,
 * tail, cnt, sz with each soft ring (a data struct which contains a softring
 * along with these members) and create an array of this uber struct so we
 * don't have to do kmem_alloc.
 */
int	fanout_oth1 = 0;
int	fanout_oth2 = 0;
int	fanout_oth3 = 0;
int	fanout_oth4 = 0;
int	fanout_oth5 = 0;

static void
mac_rx_srs_fanout(mac_soft_ring_set_t *mac_srs, mblk_t *head)
{
	struct ether_header		*ehp;
	struct ether_vlan_header	*evhp;
	uint32_t			sap;
	ipha_t				*ipha;
	uint8_t				*dstaddr;
	uint_t				indx;
	size_t				ports_offset;
	size_t				ipha_len;
	size_t				hdrsize;
	uint_t				hash;
	mblk_t				*mp;
	mblk_t				*headmp[MAX_SR_TYPES][MAX_SR_FANOUT];
	mblk_t				*tailmp[MAX_SR_TYPES][MAX_SR_FANOUT];
	int				cnt[MAX_SR_TYPES][MAX_SR_FANOUT];
	size_t				sz[MAX_SR_TYPES][MAX_SR_FANOUT];
	size_t				sz1;
	boolean_t			bw_ctl;
	boolean_t			hw_classified;
	boolean_t			dls_bypass;
	boolean_t			is_ether;
	boolean_t			is_unicast;
	int				fanout_cnt;
	enum pkt_type			type;
	mac_client_impl_t		*mcip = mac_srs->srs_mcip;

	is_ether = (mcip->mci_mip->mi_info.mi_nativemedia == DL_ETHER);
	bw_ctl = ((mac_srs->srs_type & SRST_BW_CONTROL) != 0);

	/*
	 * If we don't have a Rx ring, S/W classification would have done
	 * its job and its a packet meant for us. If we were polling on
	 * the default ring (i.e. there was a ring assigned to this SRS),
	 * then we need to make sure that the mac address really belongs
	 * to us.
	 */
	hw_classified = mac_srs->srs_ring != NULL &&
	    mac_srs->srs_ring->mr_classify_type == MAC_HW_CLASSIFIER;

	/*
	 * Special clients (eg. VLAN, non ether, etc) need DLS
	 * processing in the Rx path. SRST_DLS_BYPASS will be clear for
	 * such SRSs. Another way of disabling bypass is to set the
	 * MCIS_RX_BYPASS_DISABLE flag.
	 */
	dls_bypass = ((mac_srs->srs_type & SRST_DLS_BYPASS) != 0) &&
	    ((mcip->mci_state_flags & MCIS_RX_BYPASS_DISABLE) == 0);

	/*
	 * Since the softrings are never destroyed and we always
	 * create equal number of softrings for TCP, UDP and rest,
	 * its OK to check one of them for count and use it without
	 * any lock. In future, if soft rings get destroyed because
	 * of reduction in fanout, we will need to ensure that happens
	 * behind the SRS_PROC.
	 */
	fanout_cnt = mac_srs->srs_tcp_ring_count;

	bzero(headmp, MAX_SR_TYPES * MAX_SR_FANOUT * sizeof (mblk_t *));
	bzero(tailmp, MAX_SR_TYPES * MAX_SR_FANOUT * sizeof (mblk_t *));
	bzero(cnt, MAX_SR_TYPES * MAX_SR_FANOUT * sizeof (int));
	bzero(sz, MAX_SR_TYPES * MAX_SR_FANOUT * sizeof (size_t));

	/*
	 * We got a chain from SRS that we need to send to the soft rings.
	 * Since squeues for TCP & IPv4 sap poll their soft rings (for
	 * performance reasons), we need to separate out v4_tcp, v4_udp
	 * and the rest goes in other.
	 */
	while (head != NULL) {
		mp = head;
		head = head->b_next;
		mp->b_next = NULL;

		type = OTH;
		sz1 = (mp->b_cont == NULL) ? MBLKL(mp) : msgdsize(mp);

		if (is_ether) {
			/*
			 * At this point we can be sure the packet at least
			 * has an ether header.
			 */
			if (sz1 < sizeof (struct ether_header)) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}
			ehp = (struct ether_header *)mp->b_rptr;

			/*
			 * Determine if this is a VLAN or non-VLAN packet.
			 */
			if ((sap = ntohs(ehp->ether_type)) == VLAN_TPID) {
				evhp = (struct ether_vlan_header *)mp->b_rptr;
				sap = ntohs(evhp->ether_type);
				hdrsize = sizeof (struct ether_vlan_header);
				/*
				 * Check if the VID of the packet, if any,
				 * belongs to this client.
				 */
				if (!mac_client_check_flow_vid(mcip,
				    VLAN_ID(ntohs(evhp->ether_tci)))) {
					mac_rx_drop_pkt(mac_srs, mp);
					continue;
				}
			} else {
				hdrsize = sizeof (struct ether_header);
			}
			is_unicast =
			    ((((uint8_t *)&ehp->ether_dhost)[0] & 0x01) == 0);
			dstaddr = (uint8_t *)&ehp->ether_dhost;
		} else {
			mac_header_info_t		mhi;

			if (mac_header_info((mac_handle_t)mcip->mci_mip,
			    mp, &mhi) != 0) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}
			hdrsize = mhi.mhi_hdrsize;
			sap = mhi.mhi_bindsap;
			is_unicast = (mhi.mhi_dsttype == MAC_ADDRTYPE_UNICAST);
			dstaddr = (uint8_t *)mhi.mhi_daddr;
		}

		if (!dls_bypass) {
			if (mac_rx_srs_long_fanout(mac_srs, mp, sap,
			    hdrsize, &type, &indx) == -1) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}

			FANOUT_ENQUEUE_MP(headmp[type][indx],
			    tailmp[type][indx], cnt[type][indx], bw_ctl,
			    sz[type][indx], sz1, mp);
			continue;
		}


		/*
		 * If we are using the default Rx ring where H/W or S/W
		 * classification has not happened, we need to verify if
		 * this unicast packet really belongs to us.
		 */
		if (sap == ETHERTYPE_IP) {
			/*
			 * If we are H/W classified, but we have promisc
			 * on, then we need to check for the unicast address.
			 */
			if (hw_classified && mcip->mci_promisc_list != NULL) {
				mac_address_t		*map;

				rw_enter(&mcip->mci_rw_lock, RW_READER);
				map = mcip->mci_unicast;
				if (bcmp(dstaddr, map->ma_addr,
				    map->ma_len) == 0)
					type = UNDEF;
				rw_exit(&mcip->mci_rw_lock);
			} else if (is_unicast) {
				type = UNDEF;
			}
		}

		/*
		 * This needs to become a contract with the driver for
		 * the fast path.
		 */

		ipha = (ipha_t *)(mp->b_rptr + hdrsize);
		if ((type != OTH) && MBLK_RX_FANOUT_SLOWPATH(mp, ipha)) {
			type = OTH;
			fanout_oth1++;
		}

		if (type != OTH) {
			uint16_t	frag_offset_flags;

			switch (ipha->ipha_protocol) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
			case IPPROTO_SCTP:
			case IPPROTO_ESP:
				ipha_len = IPH_HDR_LENGTH(ipha);
				if ((uchar_t *)ipha + ipha_len + PORTS_SIZE >
				    mp->b_wptr) {
					type = OTH;
					break;
				}
				frag_offset_flags =
				    ntohs(ipha->ipha_fragment_offset_and_flags);
				if ((frag_offset_flags &
				    (IPH_MF | IPH_OFFSET)) != 0) {
					type = OTH;
					fanout_oth3++;
					break;
				}
				ports_offset = hdrsize + ipha_len;
				break;
			default:
				type = OTH;
				fanout_oth4++;
				break;
			}
		}

		if (type == OTH) {
			if (mac_rx_srs_long_fanout(mac_srs, mp, sap,
			    hdrsize, &type, &indx) == -1) {
				mac_rx_drop_pkt(mac_srs, mp);
				continue;
			}

			FANOUT_ENQUEUE_MP(headmp[type][indx],
			    tailmp[type][indx], cnt[type][indx], bw_ctl,
			    sz[type][indx], sz1, mp);
			continue;
		}

		ASSERT(type == UNDEF);

		/*
		 * XXX-Sunay: We should hold srs_lock since ring_count
		 * below can change. But if we are always called from
		 * mac_rx_srs_drain and SRS_PROC is set, then we can
		 * enforce that ring_count can't be changed i.e.
		 * to change fanout type or ring count, the calling
		 * thread needs to be behind SRS_PROC.
		 */
		switch (ipha->ipha_protocol) {
		case IPPROTO_TCP:
			/*
			 * Note that for ESP, we fanout on SPI and it is at the
			 * same offset as the 2x16-bit ports. So it is clumped
			 * along with TCP, UDP and SCTP.
			 */
			hash = HASH_ADDR(ipha->ipha_src, ipha->ipha_dst,
			    *(uint32_t *)(mp->b_rptr + ports_offset));
			indx = COMPUTE_INDEX(hash, mac_srs->srs_tcp_ring_count);
			type = V4_TCP;
			mp->b_rptr += hdrsize;
			break;
		case IPPROTO_UDP:
		case IPPROTO_SCTP:
		case IPPROTO_ESP:
			if (mac_fanout_type == MAC_FANOUT_DEFAULT) {
				hash = HASH_ADDR(ipha->ipha_src, ipha->ipha_dst,
				    *(uint32_t *)(mp->b_rptr + ports_offset));
				indx = COMPUTE_INDEX(hash,
				    mac_srs->srs_udp_ring_count);
			} else {
				indx = mac_srs->srs_ind %
				    mac_srs->srs_udp_ring_count;
				mac_srs->srs_ind++;
			}
			type = V4_UDP;
			mp->b_rptr += hdrsize;
			break;
		default:
			indx = 0;
			type = OTH;
		}

		FANOUT_ENQUEUE_MP(headmp[type][indx], tailmp[type][indx],
		    cnt[type][indx], bw_ctl, sz[type][indx], sz1, mp);
	}

	for (type = V4_TCP; type < UNDEF; type++) {
		int	i;

		for (i = 0; i < fanout_cnt; i++) {
			if (headmp[type][i] != NULL) {
				mac_soft_ring_t	*softring;

				ASSERT(tailmp[type][i]->b_next == NULL);
				switch (type) {
				case V4_TCP:
					softring =
					    mac_srs->srs_tcp_soft_rings[i];
					break;
				case V4_UDP:
					softring =
					    mac_srs->srs_udp_soft_rings[i];
					break;
				case OTH:
					softring =
					    mac_srs->srs_oth_soft_rings[i];
					break;
				}
				mac_rx_soft_ring_process(mcip,
				    softring, headmp[type][i], tailmp[type][i],
				    cnt[type][i], sz[type][i]);
			}
		}
	}
}

#define	SRS_BYTES_TO_PICKUP	150000
ssize_t	max_bytes_to_pickup = SRS_BYTES_TO_PICKUP;

/*
 * mac_rx_srs_poll_ring
 *
 * This SRS Poll thread uses this routine to poll the underlying hardware
 * Rx ring to get a chain of packets. It can inline process that chain
 * if mac_latency_optimize is set (default) or signal the SRS worker thread
 * to do the remaining processing.
 *
 * Since packets come in the system via interrupt or poll path, we also
 * update the stats and deal with promiscous clients here.
 */
void
mac_rx_srs_poll_ring(mac_soft_ring_set_t *mac_srs)
{
	kmutex_t 		*lock = &mac_srs->srs_lock;
	kcondvar_t 		*async = &mac_srs->srs_cv;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;
	mblk_t 			*head, *tail, *mp;
	callb_cpr_t 		cprinfo;
	ssize_t 		bytes_to_pickup;
	size_t 			sz;
	int			count;
	mac_client_impl_t	*smcip;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "mac_srs_poll");
	mutex_enter(lock);

start:
	for (;;) {
		if (mac_srs->srs_state & SRS_PAUSE)
			goto done;

		CALLB_CPR_SAFE_BEGIN(&cprinfo);
		cv_wait(async, lock);
		CALLB_CPR_SAFE_END(&cprinfo, lock);

		if (mac_srs->srs_state & SRS_PAUSE)
			goto done;

check_again:
		if (mac_srs->srs_type & SRST_BW_CONTROL) {
			/*
			 * We pick as many bytes as we are allowed to queue.
			 * Its possible that we will exceed the total
			 * packets queued in case this SRS is part of the
			 * Rx ring group since > 1 poll thread can be pulling
			 * upto the max allowed packets at the same time
			 * but that should be OK.
			 */
			mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
			bytes_to_pickup =
			    mac_srs->srs_bw->mac_bw_drop_threshold -
			    mac_srs->srs_bw->mac_bw_sz;
			/*
			 * We shouldn't have been signalled if we
			 * have 0 or less bytes to pick but since
			 * some of the bytes accounting is driver
			 * dependant, we do the safety check.
			 */
			if (bytes_to_pickup < 0)
				bytes_to_pickup = 0;
			mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		} else {
			/*
			 * ToDO: Need to change the polling API
			 * to add a packet count and a flag which
			 * tells the driver whether we want packets
			 * based on a count, or bytes, or all the
			 * packets queued in the driver/HW. This
			 * way, we never have to check the limits
			 * on poll path. We truly let only as many
			 * packets enter the system as we are willing
			 * to process or queue.
			 *
			 * Something along the lines of
			 * pkts_to_pickup = mac_soft_ring_max_q_cnt -
			 *	mac_srs->srs_poll_pkt_cnt
			 */

			/*
			 * Since we are not doing B/W control, pick
			 * as many packets as allowed.
			 */
			bytes_to_pickup = max_bytes_to_pickup;
		}

		/* Poll the underlying Hardware */
		mutex_exit(lock);
		head = MAC_HWRING_POLL(mac_srs->srs_ring, (int)bytes_to_pickup);
		mutex_enter(lock);

		ASSERT((mac_srs->srs_state & SRS_POLL_THR_OWNER) ==
		    SRS_POLL_THR_OWNER);

		mp = tail = head;
		count = 0;
		sz = 0;
		while (mp != NULL) {
			tail = mp;
			sz += msgdsize(mp);
			mp = mp->b_next;
			count++;
		}

		if (head != NULL) {
			tail->b_next = NULL;
			smcip = mac_srs->srs_mcip;

			SRS_RX_STAT_UPDATE(mac_srs, pollbytes, sz);
			SRS_RX_STAT_UPDATE(mac_srs, pollcnt, count);

			/*
			 * If there are any promiscuous mode callbacks
			 * defined for this MAC client, pass them a copy
			 * if appropriate and also update the counters.
			 */
			if (smcip != NULL) {
				if (smcip->mci_mip->mi_promisc_list != NULL) {
					mutex_exit(lock);
					mac_promisc_dispatch(smcip->mci_mip,
					    head, NULL);
					mutex_enter(lock);
				}
			}
			if (mac_srs->srs_type & SRST_BW_CONTROL) {
				mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
				mac_srs->srs_bw->mac_bw_polled += sz;
				mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
			}
			MAC_RX_SRS_ENQUEUE_CHAIN(mac_srs, head, tail,
			    count, sz);
			if (count <= 10)
				srs_rx->sr_stat.mrs_chaincntundr10++;
			else if (count > 10 && count <= 50)
				srs_rx->sr_stat.mrs_chaincnt10to50++;
			else
				srs_rx->sr_stat.mrs_chaincntover50++;
		}

		/*
		 * We are guaranteed that SRS_PROC will be set if we
		 * are here. Also, poll thread gets to run only if
		 * the drain was being done by a worker thread although
		 * its possible that worker thread is still running
		 * and poll thread was sent down to keep the pipeline
		 * going instead of doing a complete drain and then
		 * trying to poll the NIC.
		 *
		 * So we need to check SRS_WORKER flag to make sure
		 * that the worker thread is not processing the queue
		 * in parallel to us. The flags and conditions are
		 * protected by the srs_lock to prevent any race. We
		 * ensure that we don't drop the srs_lock from now
		 * till the end and similarly we don't drop the srs_lock
		 * in mac_rx_srs_drain() till similar condition check
		 * are complete. The mac_rx_srs_drain() needs to ensure
		 * that SRS_WORKER flag remains set as long as its
		 * processing the queue.
		 */
		if (!(mac_srs->srs_state & SRS_WORKER) &&
		    (mac_srs->srs_first != NULL)) {
			/*
			 * We have packets to process and worker thread
			 * is not running. Check to see if poll thread is
			 * allowed to process.
			 */
			if (mac_srs->srs_state & SRS_LATENCY_OPT) {
				mac_srs->srs_drain_func(mac_srs, SRS_POLL_PROC);
				if (!(mac_srs->srs_state & SRS_PAUSE) &&
				    srs_rx->sr_poll_pkt_cnt <=
				    srs_rx->sr_lowat) {
					srs_rx->sr_poll_again++;
					goto check_again;
				}
				/*
				 * We are already above low water mark
				 * so stay in the polling mode but no
				 * need to poll. Once we dip below
				 * the polling threshold, the processing
				 * thread (soft ring) will signal us
				 * to poll again (MAC_UPDATE_SRS_COUNT)
				 */
				srs_rx->sr_poll_drain_no_poll++;
				mac_srs->srs_state &= ~(SRS_PROC|SRS_GET_PKTS);
				/*
				 * In B/W control case, its possible
				 * that the backlog built up due to
				 * B/W limit being reached and packets
				 * are queued only in SRS. In this case,
				 * we should schedule worker thread
				 * since no one else will wake us up.
				 */
				if ((mac_srs->srs_type & SRST_BW_CONTROL) &&
				    (mac_srs->srs_tid == NULL)) {
					mac_srs->srs_tid =
					    timeout(mac_srs_fire, mac_srs, 1);
					srs_rx->sr_poll_worker_wakeup++;
				}
			} else {
				/*
				 * Wakeup the worker thread for more processing.
				 * We optimize for throughput in this case.
				 */
				mac_srs->srs_state &= ~(SRS_PROC|SRS_GET_PKTS);
				MAC_SRS_WORKER_WAKEUP(mac_srs);
				srs_rx->sr_poll_sig_worker++;
			}
		} else if ((mac_srs->srs_first == NULL) &&
		    !(mac_srs->srs_state & SRS_WORKER)) {
			/*
			 * There is nothing queued in SRS and
			 * no worker thread running. Plus we
			 * didn't get anything from the H/W
			 * as well (head == NULL);
			 */
			ASSERT(head == NULL);
			mac_srs->srs_state &=
			    ~(SRS_PROC|SRS_GET_PKTS);

			/*
			 * If we have a packets in soft ring, don't allow
			 * more packets to come into this SRS by keeping the
			 * interrupts off but not polling the H/W. The
			 * poll thread will get signaled as soon as
			 * srs_poll_pkt_cnt dips below poll threshold.
			 */
			if (srs_rx->sr_poll_pkt_cnt == 0) {
				srs_rx->sr_poll_intr_enable++;
				MAC_SRS_POLLING_OFF(mac_srs);
			} else {
				/*
				 * We know nothing is queued in SRS
				 * since we are here after checking
				 * srs_first is NULL. The backlog
				 * is entirely due to packets queued
				 * in Soft ring which will wake us up
				 * and get the interface out of polling
				 * mode once the backlog dips below
				 * sr_poll_thres.
				 */
				srs_rx->sr_poll_no_poll++;
			}
		} else {
			/*
			 * Worker thread is already running.
			 * Nothing much to do. If the polling
			 * was enabled, worker thread will deal
			 * with that.
			 */
			mac_srs->srs_state &= ~SRS_GET_PKTS;
			srs_rx->sr_poll_goto_sleep++;
		}
	}
done:
	mac_srs->srs_state |= SRS_POLL_THR_QUIESCED;
	cv_signal(&mac_srs->srs_async);
	/*
	 * If this is a temporary quiesce then wait for the restart signal
	 * from the srs worker. Then clear the flags and signal the srs worker
	 * to ensure a positive handshake and go back to start.
	 */
	while (!(mac_srs->srs_state & (SRS_CONDEMNED | SRS_POLL_THR_RESTART)))
		cv_wait(async, lock);
	if (mac_srs->srs_state & SRS_POLL_THR_RESTART) {
		ASSERT(!(mac_srs->srs_state & SRS_CONDEMNED));
		mac_srs->srs_state &=
		    ~(SRS_POLL_THR_QUIESCED | SRS_POLL_THR_RESTART);
		cv_signal(&mac_srs->srs_async);
		goto start;
	} else {
		mac_srs->srs_state |= SRS_POLL_THR_EXITED;
		cv_signal(&mac_srs->srs_async);
		CALLB_CPR_EXIT(&cprinfo);
		thread_exit();
	}
}

/*
 * mac_srs_pick_chain
 *
 * In Bandwidth control case, checks how many packets can be processed
 * and return them in a sub chain.
 */
static mblk_t *
mac_srs_pick_chain(mac_soft_ring_set_t *mac_srs, mblk_t **chain_tail,
    size_t *chain_sz, int *chain_cnt)
{
	mblk_t 			*head = NULL;
	mblk_t 			*tail = NULL;
	size_t			sz;
	size_t 			tsz = 0;
	int			cnt = 0;
	mblk_t 			*mp;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));
	mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
	if (((mac_srs->srs_bw->mac_bw_used + mac_srs->srs_size) <=
	    mac_srs->srs_bw->mac_bw_limit) ||
	    (mac_srs->srs_bw->mac_bw_limit == 0)) {
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		head = mac_srs->srs_first;
		mac_srs->srs_first = NULL;
		*chain_tail = mac_srs->srs_last;
		mac_srs->srs_last = NULL;
		*chain_sz = mac_srs->srs_size;
		*chain_cnt = mac_srs->srs_count;
		mac_srs->srs_count = 0;
		mac_srs->srs_size = 0;
		return (head);
	}

	/*
	 * Can't clear the entire backlog.
	 * Need to find how many packets to pick
	 */
	ASSERT(MUTEX_HELD(&mac_srs->srs_bw->mac_bw_lock));
	while ((mp = mac_srs->srs_first) != NULL) {
		sz = msgdsize(mp);
		if ((tsz + sz + mac_srs->srs_bw->mac_bw_used) >
		    mac_srs->srs_bw->mac_bw_limit) {
			if (!(mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED))
				mac_srs->srs_bw->mac_bw_state |=
				    SRS_BW_ENFORCED;
			break;
		}

		/*
		 * The _size & cnt is  decremented from the softrings
		 * when they send up the packet for polling to work
		 * properly.
		 */
		tsz += sz;
		cnt++;
		mac_srs->srs_count--;
		mac_srs->srs_size -= sz;
		if (tail != NULL)
			tail->b_next = mp;
		else
			head = mp;
		tail = mp;
		mac_srs->srs_first = mac_srs->srs_first->b_next;
	}
	mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
	if (mac_srs->srs_first == NULL)
		mac_srs->srs_last = NULL;

	if (tail != NULL)
		tail->b_next = NULL;
	*chain_tail = tail;
	*chain_cnt = cnt;
	*chain_sz = tsz;

	return (head);
}

/*
 * mac_rx_srs_drain
 *
 * The SRS drain routine. Gets to run to clear the queue. Any thread
 * (worker, interrupt, poll) can call this based on processing model.
 * The first thing we do is disable interrupts if possible and then
 * drain the queue. we also try to poll the underlying hardware if
 * there is a dedicated hardware Rx ring assigned to this SRS.
 *
 * There is a equivalent drain routine in bandwidth control mode
 * mac_rx_srs_drain_bw. There is some code duplication between the two
 * routines but they are highly performance sensitive and are easier
 * to read/debug if they stay separate. Any code changes here might
 * also apply to mac_rx_srs_drain_bw as well.
 */
void
mac_rx_srs_drain(mac_soft_ring_set_t *mac_srs, uint_t proc_type)
{
	mblk_t 			*head;
	mblk_t			*tail;
	timeout_id_t 		tid;
	int			cnt = 0;
	mac_client_impl_t	*mcip = mac_srs->srs_mcip;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));
	ASSERT(!(mac_srs->srs_type & SRST_BW_CONTROL));

	/* If we are blanked i.e. can't do upcalls, then we are done */
	if (mac_srs->srs_state & (SRS_BLANK | SRS_PAUSE)) {
		ASSERT((mac_srs->srs_type & SRST_NO_SOFT_RINGS) ||
		    (mac_srs->srs_state & SRS_PAUSE));
		goto out;
	}

	if (mac_srs->srs_first == NULL)
		goto out;

	if (!(mac_srs->srs_state & SRS_LATENCY_OPT) &&
	    (srs_rx->sr_poll_pkt_cnt <= srs_rx->sr_lowat)) {
		/*
		 * In the normal case, the SRS worker thread does no
		 * work and we wait for a backlog to build up before
		 * we switch into polling mode. In case we are
		 * optimizing for throughput, we use the worker thread
		 * as well. The goal is to let worker thread process
		 * the queue and poll thread to feed packets into
		 * the queue. As such, we should signal the poll
		 * thread to try and get more packets.
		 *
		 * We could have pulled this check in the POLL_RING
		 * macro itself but keeping it explicit here makes
		 * the architecture more human understandable.
		 */
		MAC_SRS_POLL_RING(mac_srs);
	}

again:
	head = mac_srs->srs_first;
	mac_srs->srs_first = NULL;
	tail = mac_srs->srs_last;
	mac_srs->srs_last = NULL;
	cnt = mac_srs->srs_count;
	mac_srs->srs_count = 0;

	ASSERT(head != NULL);
	ASSERT(tail != NULL);

	if ((tid = mac_srs->srs_tid) != 0)
		mac_srs->srs_tid = 0;

	mac_srs->srs_state |= (SRS_PROC|proc_type);


	/*
	 * mcip is NULL for broadcast and multicast flows. The promisc
	 * callbacks for broadcast and multicast packets are delivered from
	 * mac_rx() and we don't need to worry about that case in this path
	 */
	if (mcip != NULL) {
		if (mcip->mci_promisc_list != NULL) {
			mutex_exit(&mac_srs->srs_lock);
			mac_promisc_client_dispatch(mcip, head);
			mutex_enter(&mac_srs->srs_lock);
		}
		if (MAC_PROTECT_ENABLED(mcip, MPT_IPNOSPOOF)) {
			mutex_exit(&mac_srs->srs_lock);
			mac_protect_intercept_dhcp(mcip, head);
			mutex_enter(&mac_srs->srs_lock);
		}
	}

	/*
	 * Check if SRS itself is doing the processing
	 * This direct path does not apply when subflows are present. In this
	 * case, packets need to be dispatched to a soft ring according to the
	 * flow's bandwidth and other resources contraints.
	 */
	if (mac_srs->srs_type & SRST_NO_SOFT_RINGS) {
		mac_direct_rx_t		proc;
		void			*arg1;
		mac_resource_handle_t	arg2;

		/*
		 * This is the case when a Rx is directly
		 * assigned and we have a fully classified
		 * protocol chain. We can deal with it in
		 * one shot.
		 */
		proc = srs_rx->sr_func;
		arg1 = srs_rx->sr_arg1;
		arg2 = srs_rx->sr_arg2;

		mac_srs->srs_state |= SRS_CLIENT_PROC;
		mutex_exit(&mac_srs->srs_lock);
		if (tid != 0) {
			(void) untimeout(tid);
			tid = 0;
		}

		proc(arg1, arg2, head, NULL);
		/*
		 * Decrement the size and count here itelf
		 * since the packet has been processed.
		 */
		mutex_enter(&mac_srs->srs_lock);
		MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
		if (mac_srs->srs_state & SRS_CLIENT_WAIT)
			cv_signal(&mac_srs->srs_client_cv);
		mac_srs->srs_state &= ~SRS_CLIENT_PROC;
	} else {
		/* Some kind of softrings based fanout is required */
		mutex_exit(&mac_srs->srs_lock);
		if (tid != 0) {
			(void) untimeout(tid);
			tid = 0;
		}

		/*
		 * Since the fanout routines can deal with chains,
		 * shoot the entire chain up.
		 */
		if (mac_srs->srs_type & SRST_FANOUT_SRC_IP)
			mac_rx_srs_fanout(mac_srs, head);
		else
			mac_rx_srs_proto_fanout(mac_srs, head);
		mutex_enter(&mac_srs->srs_lock);
	}

	if (!(mac_srs->srs_state & (SRS_BLANK|SRS_PAUSE)) &&
	    (mac_srs->srs_first != NULL)) {
		/*
		 * More packets arrived while we were clearing the
		 * SRS. This can be possible because of one of
		 * three conditions below:
		 * 1) The driver is using multiple worker threads
		 *    to send the packets to us.
		 * 2) The driver has a race in switching
		 *    between interrupt and polling mode or
		 * 3) Packets are arriving in this SRS via the
		 *    S/W classification as well.
		 *
		 * We should switch to polling mode and see if we
		 * need to send the poll thread down. Also, signal
		 * the worker thread to process whats just arrived.
		 */
		MAC_SRS_POLLING_ON(mac_srs);
		if (srs_rx->sr_poll_pkt_cnt <= srs_rx->sr_lowat) {
			srs_rx->sr_drain_poll_sig++;
			MAC_SRS_POLL_RING(mac_srs);
		}

		/*
		 * If we didn't signal the poll thread, we need
		 * to deal with the pending packets ourselves.
		 */
		if (proc_type == SRS_WORKER) {
			srs_rx->sr_drain_again++;
			goto again;
		} else {
			srs_rx->sr_drain_worker_sig++;
			cv_signal(&mac_srs->srs_async);
		}
	}

out:
	if (mac_srs->srs_state & SRS_GET_PKTS) {
		/*
		 * Poll thread is already running. Leave the
		 * SRS_RPOC set and hand over the control to
		 * poll thread.
		 */
		mac_srs->srs_state &= ~proc_type;
		srs_rx->sr_drain_poll_running++;
		return;
	}

	/*
	 * Even if there are no packets queued in SRS, we
	 * need to make sure that the shared counter is
	 * clear and any associated softrings have cleared
	 * all the backlog. Otherwise, leave the interface
	 * in polling mode and the poll thread will get
	 * signalled once the count goes down to zero.
	 *
	 * If someone is already draining the queue (SRS_PROC is
	 * set) when the srs_poll_pkt_cnt goes down to zero,
	 * then it means that drain is already running and we
	 * will turn off polling at that time if there is
	 * no backlog.
	 *
	 * As long as there are packets queued either
	 * in soft ring set or its soft rings, we will leave
	 * the interface in polling mode (even if the drain
	 * was done being the interrupt thread). We signal
	 * the poll thread as well if we have dipped below
	 * low water mark.
	 *
	 * NOTE: We can't use the MAC_SRS_POLLING_ON macro
	 * since that turn polling on only for worker thread.
	 * Its not worth turning polling on for interrupt
	 * thread (since NIC will not issue another interrupt)
	 * unless a backlog builds up.
	 */
	if ((srs_rx->sr_poll_pkt_cnt > 0) &&
	    (mac_srs->srs_state & SRS_POLLING_CAPAB)) {
		mac_srs->srs_state &= ~(SRS_PROC|proc_type);
		srs_rx->sr_drain_keep_polling++;
		MAC_SRS_POLLING_ON(mac_srs);
		if (srs_rx->sr_poll_pkt_cnt <= srs_rx->sr_lowat)
			MAC_SRS_POLL_RING(mac_srs);
		return;
	}

	/* Nothing else to do. Get out of poll mode */
	MAC_SRS_POLLING_OFF(mac_srs);
	mac_srs->srs_state &= ~(SRS_PROC|proc_type);
	srs_rx->sr_drain_finish_intr++;
}

/*
 * mac_rx_srs_drain_bw
 *
 * The SRS BW drain routine. Gets to run to clear the queue. Any thread
 * (worker, interrupt, poll) can call this based on processing model.
 * The first thing we do is disable interrupts if possible and then
 * drain the queue. we also try to poll the underlying hardware if
 * there is a dedicated hardware Rx ring assigned to this SRS.
 *
 * There is a equivalent drain routine in non bandwidth control mode
 * mac_rx_srs_drain. There is some code duplication between the two
 * routines but they are highly performance sensitive and are easier
 * to read/debug if they stay separate. Any code changes here might
 * also apply to mac_rx_srs_drain as well.
 */
void
mac_rx_srs_drain_bw(mac_soft_ring_set_t *mac_srs, uint_t proc_type)
{
	mblk_t 			*head;
	mblk_t			*tail;
	timeout_id_t 		tid;
	size_t			sz = 0;
	int			cnt = 0;
	mac_client_impl_t	*mcip = mac_srs->srs_mcip;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;
	clock_t			now;

	ASSERT(MUTEX_HELD(&mac_srs->srs_lock));
	ASSERT(mac_srs->srs_type & SRST_BW_CONTROL);
again:
	/* Check if we are doing B/W control */
	mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
	now = ddi_get_lbolt();
	if (mac_srs->srs_bw->mac_bw_curr_time != now) {
		mac_srs->srs_bw->mac_bw_curr_time = now;
		mac_srs->srs_bw->mac_bw_used = 0;
		if (mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED)
			mac_srs->srs_bw->mac_bw_state &= ~SRS_BW_ENFORCED;
	} else if (mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED) {
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		goto done;
	} else if (mac_srs->srs_bw->mac_bw_used >
	    mac_srs->srs_bw->mac_bw_limit) {
		mac_srs->srs_bw->mac_bw_state |= SRS_BW_ENFORCED;
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		goto done;
	}
	mutex_exit(&mac_srs->srs_bw->mac_bw_lock);

	/* If we are blanked i.e. can't do upcalls, then we are done */
	if (mac_srs->srs_state & (SRS_BLANK | SRS_PAUSE)) {
		ASSERT((mac_srs->srs_type & SRST_NO_SOFT_RINGS) ||
		    (mac_srs->srs_state & SRS_PAUSE));
		goto done;
	}

	sz = 0;
	cnt = 0;
	if ((head = mac_srs_pick_chain(mac_srs, &tail, &sz, &cnt)) == NULL) {
		/*
		 * We couldn't pick up a single packet.
		 */
		mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
		if ((mac_srs->srs_bw->mac_bw_used == 0) &&
		    (mac_srs->srs_size != 0) &&
		    !(mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED)) {
			/*
			 * Seems like configured B/W doesn't
			 * even allow processing of 1 packet
			 * per tick.
			 *
			 * XXX: raise the limit to processing
			 * at least 1 packet per tick.
			 */
			mac_srs->srs_bw->mac_bw_limit +=
			    mac_srs->srs_bw->mac_bw_limit;
			mac_srs->srs_bw->mac_bw_drop_threshold +=
			    mac_srs->srs_bw->mac_bw_drop_threshold;
			cmn_err(CE_NOTE, "mac_rx_srs_drain: srs(%p) "
			    "raised B/W limit to %d since not even a "
			    "single packet can be processed per "
			    "tick %d\n", (void *)mac_srs,
			    (int)mac_srs->srs_bw->mac_bw_limit,
			    (int)msgdsize(mac_srs->srs_first));
		}
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		goto done;
	}

	ASSERT(head != NULL);
	ASSERT(tail != NULL);

	/* zero bandwidth: drop all and return to interrupt mode */
	mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
	if (mac_srs->srs_bw->mac_bw_limit == 0) {
		srs_rx->sr_stat.mrs_sdrops += cnt;
		ASSERT(mac_srs->srs_bw->mac_bw_sz >= sz);
		mac_srs->srs_bw->mac_bw_sz -= sz;
		mac_srs->srs_bw->mac_bw_drop_bytes += sz;
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		mac_pkt_drop(NULL, NULL, head, B_FALSE);
		goto leave_poll;
	} else {
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
	}

	if ((tid = mac_srs->srs_tid) != 0)
		mac_srs->srs_tid = 0;

	mac_srs->srs_state |= (SRS_PROC|proc_type);
	MAC_SRS_WORKER_POLLING_ON(mac_srs);

	/*
	 * mcip is NULL for broadcast and multicast flows. The promisc
	 * callbacks for broadcast and multicast packets are delivered from
	 * mac_rx() and we don't need to worry about that case in this path
	 */
	if (mcip != NULL) {
		if (mcip->mci_promisc_list != NULL) {
			mutex_exit(&mac_srs->srs_lock);
			mac_promisc_client_dispatch(mcip, head);
			mutex_enter(&mac_srs->srs_lock);
		}
		if (MAC_PROTECT_ENABLED(mcip, MPT_IPNOSPOOF)) {
			mutex_exit(&mac_srs->srs_lock);
			mac_protect_intercept_dhcp(mcip, head);
			mutex_enter(&mac_srs->srs_lock);
		}
	}

	/*
	 * Check if SRS itself is doing the processing
	 * This direct path does not apply when subflows are present. In this
	 * case, packets need to be dispatched to a soft ring according to the
	 * flow's bandwidth and other resources contraints.
	 */
	if (mac_srs->srs_type & SRST_NO_SOFT_RINGS) {
		mac_direct_rx_t		proc;
		void			*arg1;
		mac_resource_handle_t	arg2;

		/*
		 * This is the case when a Rx is directly
		 * assigned and we have a fully classified
		 * protocol chain. We can deal with it in
		 * one shot.
		 */
		proc = srs_rx->sr_func;
		arg1 = srs_rx->sr_arg1;
		arg2 = srs_rx->sr_arg2;

		mac_srs->srs_state |= SRS_CLIENT_PROC;
		mutex_exit(&mac_srs->srs_lock);
		if (tid != 0) {
			(void) untimeout(tid);
			tid = 0;
		}

		proc(arg1, arg2, head, NULL);
		/*
		 * Decrement the size and count here itelf
		 * since the packet has been processed.
		 */
		mutex_enter(&mac_srs->srs_lock);
		MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
		MAC_UPDATE_SRS_SIZE_LOCKED(mac_srs, sz);

		if (mac_srs->srs_state & SRS_CLIENT_WAIT)
			cv_signal(&mac_srs->srs_client_cv);
		mac_srs->srs_state &= ~SRS_CLIENT_PROC;
	} else {
		/* Some kind of softrings based fanout is required */
		mutex_exit(&mac_srs->srs_lock);
		if (tid != 0) {
			(void) untimeout(tid);
			tid = 0;
		}

		/*
		 * Since the fanout routines can deal with chains,
		 * shoot the entire chain up.
		 */
		if (mac_srs->srs_type & SRST_FANOUT_SRC_IP)
			mac_rx_srs_fanout(mac_srs, head);
		else
			mac_rx_srs_proto_fanout(mac_srs, head);
		mutex_enter(&mac_srs->srs_lock);
	}

	/*
	 * Send the poll thread to pick up any packets arrived
	 * so far. This also serves as the last check in case
	 * nothing else is queued in the SRS. The poll thread
	 * is signalled only in the case the drain was done
	 * by the worker thread and SRS_WORKER is set. The
	 * worker thread can run in parallel as long as the
	 * SRS_WORKER flag is set. We we have nothing else to
	 * process, we can exit while leaving SRS_PROC set
	 * which gives the poll thread control to process and
	 * cleanup once it returns from the NIC.
	 *
	 * If we have nothing else to process, we need to
	 * ensure that we keep holding the srs_lock till
	 * all the checks below are done and control is
	 * handed to the poll thread if it was running.
	 */
	mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
	if (!(mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED)) {
		if (mac_srs->srs_first != NULL) {
			if (proc_type == SRS_WORKER) {
				mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
				if (srs_rx->sr_poll_pkt_cnt <=
				    srs_rx->sr_lowat)
					MAC_SRS_POLL_RING(mac_srs);
				goto again;
			} else {
				cv_signal(&mac_srs->srs_async);
			}
		}
	}
	mutex_exit(&mac_srs->srs_bw->mac_bw_lock);

done:

	if (mac_srs->srs_state & SRS_GET_PKTS) {
		/*
		 * Poll thread is already running. Leave the
		 * SRS_RPOC set and hand over the control to
		 * poll thread.
		 */
		mac_srs->srs_state &= ~proc_type;
		return;
	}

	/*
	 * If we can't process packets because we have exceeded
	 * B/W limit for this tick, just set the timeout
	 * and leave.
	 *
	 * Even if there are no packets queued in SRS, we
	 * need to make sure that the shared counter is
	 * clear and any associated softrings have cleared
	 * all the backlog. Otherwise, leave the interface
	 * in polling mode and the poll thread will get
	 * signalled once the count goes down to zero.
	 *
	 * If someone is already draining the queue (SRS_PROC is
	 * set) when the srs_poll_pkt_cnt goes down to zero,
	 * then it means that drain is already running and we
	 * will turn off polling at that time if there is
	 * no backlog. As long as there are packets queued either
	 * is soft ring set or its soft rings, we will leave
	 * the interface in polling mode.
	 */
	mutex_enter(&mac_srs->srs_bw->mac_bw_lock);
	if ((mac_srs->srs_state & SRS_POLLING_CAPAB) &&
	    ((mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED) ||
	    (srs_rx->sr_poll_pkt_cnt > 0))) {
		MAC_SRS_POLLING_ON(mac_srs);
		mac_srs->srs_state &= ~(SRS_PROC|proc_type);
		if ((mac_srs->srs_first != NULL) &&
		    (mac_srs->srs_tid == NULL))
			mac_srs->srs_tid = timeout(mac_srs_fire,
			    mac_srs, 1);
		mutex_exit(&mac_srs->srs_bw->mac_bw_lock);
		return;
	}
	mutex_exit(&mac_srs->srs_bw->mac_bw_lock);

leave_poll:

	/* Nothing else to do. Get out of poll mode */
	MAC_SRS_POLLING_OFF(mac_srs);
	mac_srs->srs_state &= ~(SRS_PROC|proc_type);
}

/*
 * mac_srs_worker
 *
 * The SRS worker routine. Drains the queue when no one else is
 * processing it.
 */
void
mac_srs_worker(mac_soft_ring_set_t *mac_srs)
{
	kmutex_t 		*lock = &mac_srs->srs_lock;
	kcondvar_t 		*async = &mac_srs->srs_async;
	callb_cpr_t		cprinfo;
	boolean_t		bw_ctl_flag;

	CALLB_CPR_INIT(&cprinfo, lock, callb_generic_cpr, "srs_worker");
	mutex_enter(lock);

start:
	for (;;) {
		bw_ctl_flag = B_FALSE;
		if (mac_srs->srs_type & SRST_BW_CONTROL) {
			MAC_SRS_BW_LOCK(mac_srs);
			MAC_SRS_CHECK_BW_CONTROL(mac_srs);
			if (mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED)
				bw_ctl_flag = B_TRUE;
			MAC_SRS_BW_UNLOCK(mac_srs);
		}
		/*
		 * The SRS_BW_ENFORCED flag may change since we have dropped
		 * the mac_bw_lock. However the drain function can handle both
		 * a drainable SRS or a bandwidth controlled SRS, and the
		 * effect of scheduling a timeout is to wakeup the worker
		 * thread which in turn will call the drain function. Since
		 * we release the srs_lock atomically only in the cv_wait there
		 * isn't a fear of waiting for ever.
		 */
		while (((mac_srs->srs_state & SRS_PROC) ||
		    (mac_srs->srs_first == NULL) || bw_ctl_flag ||
		    (mac_srs->srs_state & SRS_TX_BLOCKED)) &&
		    !(mac_srs->srs_state & SRS_PAUSE)) {
			/*
			 * If we have packets queued and we are here
			 * because B/W control is in place, we better
			 * schedule the worker wakeup after 1 tick
			 * to see if bandwidth control can be relaxed.
			 */
			if (bw_ctl_flag && mac_srs->srs_tid == NULL) {
				/*
				 * We need to ensure that a timer  is already
				 * scheduled or we force  schedule one for
				 * later so that we can continue processing
				 * after this  quanta is over.
				 */
				mac_srs->srs_tid = timeout(mac_srs_fire,
				    mac_srs, 1);
			}
wait:
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(async, lock);
			CALLB_CPR_SAFE_END(&cprinfo, lock);

			if (mac_srs->srs_state & SRS_PAUSE)
				goto done;
			if (mac_srs->srs_state & SRS_PROC)
				goto wait;

			if (mac_srs->srs_first != NULL &&
			    mac_srs->srs_type & SRST_BW_CONTROL) {
				MAC_SRS_BW_LOCK(mac_srs);
				if (mac_srs->srs_bw->mac_bw_state &
				    SRS_BW_ENFORCED) {
					MAC_SRS_CHECK_BW_CONTROL(mac_srs);
				}
				bw_ctl_flag = mac_srs->srs_bw->mac_bw_state &
				    SRS_BW_ENFORCED;
				MAC_SRS_BW_UNLOCK(mac_srs);
			}
		}

		if (mac_srs->srs_state & SRS_PAUSE)
			goto done;
		mac_srs->srs_drain_func(mac_srs, SRS_WORKER);
	}
done:
	/*
	 * The Rx SRS quiesce logic first cuts off packet supply to the SRS
	 * from both hard and soft classifications and waits for such threads
	 * to finish before signaling the worker. So at this point the only
	 * thread left that could be competing with the worker is the poll
	 * thread. In the case of Tx, there shouldn't be any thread holding
	 * SRS_PROC at this point.
	 */
	if (!(mac_srs->srs_state & SRS_PROC)) {
		mac_srs->srs_state |= SRS_PROC;
	} else {
		ASSERT((mac_srs->srs_type & SRST_TX) == 0);
		/*
		 * Poll thread still owns the SRS and is still running
		 */
		ASSERT((mac_srs->srs_poll_thr == NULL) ||
		    ((mac_srs->srs_state & SRS_POLL_THR_OWNER) ==
		    SRS_POLL_THR_OWNER));
	}
	mac_srs_worker_quiesce(mac_srs);
	/*
	 * Wait for the SRS_RESTART or SRS_CONDEMNED signal from the initiator
	 * of the quiesce operation
	 */
	while (!(mac_srs->srs_state & (SRS_CONDEMNED | SRS_RESTART)))
		cv_wait(&mac_srs->srs_async, &mac_srs->srs_lock);

	if (mac_srs->srs_state & SRS_RESTART) {
		ASSERT(!(mac_srs->srs_state & SRS_CONDEMNED));
		mac_srs_worker_restart(mac_srs);
		mac_srs->srs_state &= ~SRS_PROC;
		goto start;
	}

	if (!(mac_srs->srs_state & SRS_CONDEMNED_DONE))
		mac_srs_worker_quiesce(mac_srs);

	mac_srs->srs_state &= ~SRS_PROC;
	/* The macro drops the srs_lock */
	CALLB_CPR_EXIT(&cprinfo);
	thread_exit();
}

/*
 * mac_rx_srs_subflow_process
 *
 * Receive side routine called from interrupt path when there are
 * sub flows present on this SRS.
 */
/* ARGSUSED */
void
mac_rx_srs_subflow_process(void *arg, mac_resource_handle_t srs,
    mblk_t *mp_chain, boolean_t loopback)
{
	flow_entry_t		*flent = NULL;
	flow_entry_t		*prev_flent = NULL;
	mblk_t			*mp = NULL;
	mblk_t			*tail = NULL;
	mac_soft_ring_set_t	*mac_srs = (mac_soft_ring_set_t *)srs;
	mac_client_impl_t	*mcip;

	mcip = mac_srs->srs_mcip;
	ASSERT(mcip != NULL);

	/*
	 * We need to determine the SRS for every packet
	 * by walking the flow table, if we don't get any,
	 * then we proceed using the SRS we came with.
	 */
	mp = tail = mp_chain;
	while (mp != NULL) {

		/*
		 * We will increment the stats for the mactching subflow.
		 * when we get the bytes/pkt count for the classified packets
		 * later in mac_rx_srs_process.
		 */
		(void) mac_flow_lookup(mcip->mci_subflow_tab, mp,
		    FLOW_INBOUND, &flent);

		if (mp == mp_chain || flent == prev_flent) {
			if (prev_flent != NULL)
				FLOW_REFRELE(prev_flent);
			prev_flent = flent;
			flent = NULL;
			tail = mp;
			mp = mp->b_next;
			continue;
		}
		tail->b_next = NULL;
		/*
		 * A null indicates, this is for the mac_srs itself.
		 * XXX-venu : probably assert for fe_rx_srs_cnt == 0.
		 */
		if (prev_flent == NULL || prev_flent->fe_rx_srs_cnt == 0) {
			mac_rx_srs_process(arg,
			    (mac_resource_handle_t)mac_srs, mp_chain,
			    loopback);
		} else {
			(prev_flent->fe_cb_fn)(prev_flent->fe_cb_arg1,
			    prev_flent->fe_cb_arg2, mp_chain, loopback);
			FLOW_REFRELE(prev_flent);
		}
		prev_flent = flent;
		flent = NULL;
		mp_chain = mp;
		tail = mp;
		mp = mp->b_next;
	}
	/* Last chain */
	ASSERT(mp_chain != NULL);
	if (prev_flent == NULL || prev_flent->fe_rx_srs_cnt == 0) {
		mac_rx_srs_process(arg,
		    (mac_resource_handle_t)mac_srs, mp_chain, loopback);
	} else {
		(prev_flent->fe_cb_fn)(prev_flent->fe_cb_arg1,
		    prev_flent->fe_cb_arg2, mp_chain, loopback);
		FLOW_REFRELE(prev_flent);
	}
}

/*
 * mac_rx_srs_process
 *
 * Receive side routine called from the interrupt path.
 *
 * loopback is set to force a context switch on the loopback
 * path between MAC clients.
 */
/* ARGSUSED */
void
mac_rx_srs_process(void *arg, mac_resource_handle_t srs, mblk_t *mp_chain,
    boolean_t loopback)
{
	mac_soft_ring_set_t	*mac_srs = (mac_soft_ring_set_t *)srs;
	mblk_t			*mp, *tail, *head;
	int			count = 0;
	int			count1;
	size_t			sz = 0;
	size_t			chain_sz, sz1;
	mac_bw_ctl_t		*mac_bw;
	mac_srs_rx_t		*srs_rx = &mac_srs->srs_rx;

	/*
	 * Set the tail, count and sz. We set the sz irrespective
	 * of whether we are doing B/W control or not for the
	 * purpose of updating the stats.
	 */
	mp = tail = mp_chain;
	while (mp != NULL) {
		tail = mp;
		count++;
		sz += msgdsize(mp);
		mp = mp->b_next;
	}

	mutex_enter(&mac_srs->srs_lock);

	if (loopback) {
		SRS_RX_STAT_UPDATE(mac_srs, lclbytes, sz);
		SRS_RX_STAT_UPDATE(mac_srs, lclcnt, count);

	} else {
		SRS_RX_STAT_UPDATE(mac_srs, intrbytes, sz);
		SRS_RX_STAT_UPDATE(mac_srs, intrcnt, count);
	}

	/*
	 * If the SRS in already being processed; has been blanked;
	 * can be processed by worker thread only; or the B/W limit
	 * has been reached, then queue the chain and check if
	 * worker thread needs to be awakend.
	 */
	if (mac_srs->srs_type & SRST_BW_CONTROL) {
		mac_bw = mac_srs->srs_bw;
		ASSERT(mac_bw != NULL);
		mutex_enter(&mac_bw->mac_bw_lock);
		mac_bw->mac_bw_intr += sz;
		if (mac_bw->mac_bw_limit == 0) {
			/* zero bandwidth: drop all */
			srs_rx->sr_stat.mrs_sdrops += count;
			mac_bw->mac_bw_drop_bytes += sz;
			mutex_exit(&mac_bw->mac_bw_lock);
			mutex_exit(&mac_srs->srs_lock);
			mac_pkt_drop(NULL, NULL, mp_chain, B_FALSE);
			return;
		} else {
			if ((mac_bw->mac_bw_sz + sz) <=
			    mac_bw->mac_bw_drop_threshold) {
				mutex_exit(&mac_bw->mac_bw_lock);
				MAC_RX_SRS_ENQUEUE_CHAIN(mac_srs, mp_chain,
				    tail, count, sz);
			} else {
				mp = mp_chain;
				chain_sz = 0;
				count1 = 0;
				tail = NULL;
				head = NULL;
				while (mp != NULL) {
					sz1 = msgdsize(mp);
					if (mac_bw->mac_bw_sz + chain_sz + sz1 >
					    mac_bw->mac_bw_drop_threshold)
						break;
					chain_sz += sz1;
					count1++;
					tail = mp;
					mp = mp->b_next;
				}
				mutex_exit(&mac_bw->mac_bw_lock);
				if (tail != NULL) {
					head = tail->b_next;
					tail->b_next = NULL;
					MAC_RX_SRS_ENQUEUE_CHAIN(mac_srs,
					    mp_chain, tail, count1, chain_sz);
					sz -= chain_sz;
					count -= count1;
				} else {
					/* Can't pick up any */
					head = mp_chain;
				}
				if (head != NULL) {
					/* Drop any packet over the threshold */
					srs_rx->sr_stat.mrs_sdrops += count;
					mutex_enter(&mac_bw->mac_bw_lock);
					mac_bw->mac_bw_drop_bytes += sz;
					mutex_exit(&mac_bw->mac_bw_lock);
					freemsgchain(head);
				}
			}
			MAC_SRS_WORKER_WAKEUP(mac_srs);
			mutex_exit(&mac_srs->srs_lock);
			return;
		}
	}

	/*
	 * If the total number of packets queued in the SRS and
	 * its associated soft rings exceeds the max allowed,
	 * then drop the chain. If we are polling capable, this
	 * shouldn't be happening.
	 */
	if (!(mac_srs->srs_type & SRST_BW_CONTROL) &&
	    (srs_rx->sr_poll_pkt_cnt > srs_rx->sr_hiwat)) {
		mac_bw = mac_srs->srs_bw;
		srs_rx->sr_stat.mrs_sdrops += count;
		mutex_enter(&mac_bw->mac_bw_lock);
		mac_bw->mac_bw_drop_bytes += sz;
		mutex_exit(&mac_bw->mac_bw_lock);
		freemsgchain(mp_chain);
		mutex_exit(&mac_srs->srs_lock);
		return;
	}

	MAC_RX_SRS_ENQUEUE_CHAIN(mac_srs, mp_chain, tail, count, sz);

	if (!(mac_srs->srs_state & SRS_PROC)) {
		/*
		 * If we are coming via loopback, if we are not optimizing for
		 * latency, or if our stack is running deep, we should signal
		 * the worker thread.
		 */
		if (loopback || !(mac_srs->srs_state & SRS_LATENCY_OPT) ||
		    MAC_RX_SRS_TOODEEP()) {
			/*
			 * For loopback, We need to let the worker take
			 * over as we don't want to continue in the same
			 * thread even if we can. This could lead to stack
			 * overflows and may also end up using
			 * resources (cpu) incorrectly.
			 */
			cv_signal(&mac_srs->srs_async);
		} else {
			/*
			 * Seems like no one is processing the SRS and
			 * there is no backlog. We also inline process
			 * our packet if its a single packet in non
			 * latency optimized case (in latency optimized
			 * case, we inline process chains of any size).
			 */
			mac_srs->srs_drain_func(mac_srs, SRS_PROC_FAST);
		}
	}
	mutex_exit(&mac_srs->srs_lock);
}

/* TX SIDE ROUTINES (RUNTIME) */

/*
 * mac_tx_srs_no_desc
 *
 * This routine is called by Tx single ring default mode
 * when Tx ring runs out of descs.
 */
mac_tx_cookie_t
mac_tx_srs_no_desc(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uint16_t flag, mblk_t **ret_mp)
{
	mac_tx_cookie_t cookie = NULL;
	mac_srs_tx_t *srs_tx = &mac_srs->srs_tx;
	boolean_t wakeup_worker = B_TRUE;
	uint32_t tx_mode = srs_tx->st_mode;
	int cnt, sz;
	mblk_t *tail;

	ASSERT(tx_mode == SRS_TX_DEFAULT || tx_mode == SRS_TX_BW);
	if (flag & MAC_DROP_ON_NO_DESC) {
		MAC_TX_SRS_DROP_MESSAGE(mac_srs, mp_chain, cookie);
	} else {
		if (mac_srs->srs_first != NULL)
			wakeup_worker = B_FALSE;
		MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
		if (flag & MAC_TX_NO_ENQUEUE) {
			/*
			 * If TX_QUEUED is not set, queue the
			 * packet and let mac_tx_srs_drain()
			 * set the TX_BLOCKED bit for the
			 * reasons explained above. Otherwise,
			 * return the mblks.
			 */
			if (wakeup_worker) {
				MAC_TX_SRS_ENQUEUE_CHAIN(mac_srs,
				    mp_chain, tail, cnt, sz);
			} else {
				MAC_TX_SET_NO_ENQUEUE(mac_srs,
				    mp_chain, ret_mp, cookie);
			}
		} else {
			MAC_TX_SRS_TEST_HIWAT(mac_srs, mp_chain,
			    tail, cnt, sz, cookie);
		}
		if (wakeup_worker)
			cv_signal(&mac_srs->srs_async);
	}
	return (cookie);
}

/*
 * mac_tx_srs_enqueue
 *
 * This routine is called when Tx SRS is operating in either serializer
 * or bandwidth mode. In serializer mode, a packet will get enqueued
 * when a thread cannot enter SRS exclusively. In bandwidth mode,
 * packets gets queued if allowed byte-count limit for a tick is
 * exceeded. The action that gets taken when MAC_DROP_ON_NO_DESC and
 * MAC_TX_NO_ENQUEUE is set is different than when operaing in either
 * the default mode or fanout mode. Here packets get dropped or
 * returned back to the caller only after hi-watermark worth of data
 * is queued.
 */
static mac_tx_cookie_t
mac_tx_srs_enqueue(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uint16_t flag, uintptr_t fanout_hint, mblk_t **ret_mp)
{
	mac_tx_cookie_t cookie = NULL;
	int cnt, sz;
	mblk_t *tail;
	boolean_t wakeup_worker = B_TRUE;

	/*
	 * Ignore fanout hint if we don't have multiple tx rings.
	 */
	if (!MAC_TX_SOFT_RINGS(mac_srs))
		fanout_hint = 0;

	if (mac_srs->srs_first != NULL)
		wakeup_worker = B_FALSE;
	MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
	if (flag & MAC_DROP_ON_NO_DESC) {
		if (mac_srs->srs_count > mac_srs->srs_tx.st_hiwat) {
			MAC_TX_SRS_DROP_MESSAGE(mac_srs, mp_chain, cookie);
		} else {
			MAC_TX_SRS_ENQUEUE_CHAIN(mac_srs,
			    mp_chain, tail, cnt, sz);
		}
	} else if (flag & MAC_TX_NO_ENQUEUE) {
		if ((mac_srs->srs_count > mac_srs->srs_tx.st_hiwat) ||
		    (mac_srs->srs_state & SRS_TX_WAKEUP_CLIENT)) {
			MAC_TX_SET_NO_ENQUEUE(mac_srs, mp_chain,
			    ret_mp, cookie);
		} else {
			mp_chain->b_prev = (mblk_t *)fanout_hint;
			MAC_TX_SRS_ENQUEUE_CHAIN(mac_srs,
			    mp_chain, tail, cnt, sz);
		}
	} else {
		/*
		 * If you are BW_ENFORCED, just enqueue the
		 * packet. srs_worker will drain it at the
		 * prescribed rate. Before enqueueing, save
		 * the fanout hint.
		 */
		mp_chain->b_prev = (mblk_t *)fanout_hint;
		MAC_TX_SRS_TEST_HIWAT(mac_srs, mp_chain,
		    tail, cnt, sz, cookie);
	}
	if (wakeup_worker)
		cv_signal(&mac_srs->srs_async);
	return (cookie);
}

/*
 * There are seven tx modes:
 *
 * 1) Default mode (SRS_TX_DEFAULT)
 * 2) Serialization mode (SRS_TX_SERIALIZE)
 * 3) Fanout mode (SRS_TX_FANOUT)
 * 4) Bandwdith mode (SRS_TX_BW)
 * 5) Fanout and Bandwidth mode (SRS_TX_BW_FANOUT)
 * 6) aggr Tx mode (SRS_TX_AGGR)
 * 7) aggr Tx bw mode (SRS_TX_BW_AGGR)
 *
 * The tx mode in which an SRS operates is decided in mac_tx_srs_setup()
 * based on the number of Tx rings requested for an SRS and whether
 * bandwidth control is requested or not.
 *
 * The default mode (i.e., no fanout/no bandwidth) is used when the
 * underlying NIC does not have Tx rings or just one Tx ring. In this mode,
 * the SRS acts as a pass-thru. Packets will go directly to mac_tx_send().
 * When the underlying Tx ring runs out of Tx descs, it starts queueing up
 * packets in SRS. When flow-control is relieved, the srs_worker drains
 * the queued packets and informs blocked clients to restart sending
 * packets.
 *
 * In the SRS_TX_SERIALIZE mode, all calls to mac_tx() are serialized. This
 * mode is used when the link has no Tx rings or only one Tx ring.
 *
 * In the SRS_TX_FANOUT mode, packets will be fanned out to multiple
 * Tx rings. Each Tx ring will have a soft ring associated with it.
 * These soft rings will be hung off the Tx SRS. Queueing if it happens
 * due to lack of Tx desc will be in individual soft ring (and not srs)
 * associated with Tx ring.
 *
 * In the TX_BW mode, tx srs will allow packets to go down to Tx ring
 * only if bw is available. Otherwise the packets will be queued in
 * SRS. If fanout to multiple Tx rings is configured, the packets will
 * be fanned out among the soft rings associated with the Tx rings.
 *
 * In SRS_TX_AGGR mode, mac_tx_aggr_mode() routine is called. This routine
 * invokes an aggr function, aggr_find_tx_ring(), to find a pseudo Tx ring
 * belonging to a port on which the packet has to be sent. Aggr will
 * always have a pseudo Tx ring associated with it even when it is an
 * aggregation over a single NIC that has no Tx rings. Even in such a
 * case, the single pseudo Tx ring will have a soft ring associated with
 * it and the soft ring will hang off the SRS.
 *
 * If a bandwidth is specified for an aggr, SRS_TX_BW_AGGR mode is used.
 * In this mode, the bandwidth is first applied on the outgoing packets
 * and later mac_tx_addr_mode() function is called to send the packet out
 * of one of the pseudo Tx rings.
 *
 * Four flags are used in srs_state for indicating flow control
 * conditions : SRS_TX_BLOCKED, SRS_TX_HIWAT, SRS_TX_WAKEUP_CLIENT.
 * SRS_TX_BLOCKED indicates out of Tx descs. SRS expects a wakeup from the
 * driver below.
 * SRS_TX_HIWAT indicates packet count enqueued in Tx SRS exceeded Tx hiwat
 * and flow-control pressure is applied back to clients. The clients expect
 * wakeup when flow-control is relieved.
 * SRS_TX_WAKEUP_CLIENT get set when (flag == MAC_TX_NO_ENQUEUE) and mblk
 * got returned back to client either due to lack of Tx descs or due to bw
 * control reasons. The clients expect a wakeup when condition is relieved.
 *
 * The fourth argument to mac_tx() is the flag. Normally it will be 0 but
 * some clients set the following values too: MAC_DROP_ON_NO_DESC,
 * MAC_TX_NO_ENQUEUE
 * Mac clients that do not want packets to be enqueued in the mac layer set
 * MAC_DROP_ON_NO_DESC value. The packets won't be queued in the Tx SRS or
 * Tx soft rings but instead get dropped when the NIC runs out of desc. The
 * behaviour of this flag is different when the Tx is running in serializer
 * or bandwidth mode. Under these (Serializer, bandwidth) modes, the packet
 * get dropped when Tx high watermark is reached.
 * There are some mac clients like vsw, aggr that want the mblks to be
 * returned back to clients instead of being queued in Tx SRS (or Tx soft
 * rings) under flow-control (i.e., out of desc or exceeding bw limits)
 * conditions. These clients call mac_tx() with MAC_TX_NO_ENQUEUE flag set.
 * In the default and Tx fanout mode, the un-transmitted mblks will be
 * returned back to the clients when the driver runs out of Tx descs.
 * SRS_TX_WAKEUP_CLIENT (or S_RING_WAKEUP_CLIENT) will be set in SRS (or
 * soft ring) so that the clients can be woken up when Tx desc become
 * available. When running in serializer or bandwidth mode mode,
 * SRS_TX_WAKEUP_CLIENT will be set when tx hi-watermark is reached.
 */

mac_tx_func_t
mac_tx_get_func(uint32_t mode)
{
	return (mac_tx_mode_list[mode].mac_tx_func);
}

/* ARGSUSED */
static mac_tx_cookie_t
mac_tx_single_ring_mode(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uintptr_t fanout_hint, uint16_t flag, mblk_t **ret_mp)
{
	mac_srs_tx_t		*srs_tx = &mac_srs->srs_tx;
	mac_tx_stats_t		stats;
	mac_tx_cookie_t		cookie = NULL;

	ASSERT(srs_tx->st_mode == SRS_TX_DEFAULT);

	/* Regular case with a single Tx ring */
	/*
	 * SRS_TX_BLOCKED is set when underlying NIC runs
	 * out of Tx descs and messages start getting
	 * queued. It won't get reset until
	 * tx_srs_drain() completely drains out the
	 * messages.
	 */
	if ((mac_srs->srs_state & SRS_ENQUEUED) != 0) {
		/* Tx descs/resources not available */
		mutex_enter(&mac_srs->srs_lock);
		if ((mac_srs->srs_state & SRS_ENQUEUED) != 0) {
			cookie = mac_tx_srs_no_desc(mac_srs, mp_chain,
			    flag, ret_mp);
			mutex_exit(&mac_srs->srs_lock);
			return (cookie);
		}
		/*
		 * While we were computing mblk count, the
		 * flow control condition got relieved.
		 * Continue with the transmission.
		 */
		mutex_exit(&mac_srs->srs_lock);
	}

	mp_chain = mac_tx_send(srs_tx->st_arg1, srs_tx->st_arg2,
	    mp_chain, &stats);

	/*
	 * Multiple threads could be here sending packets.
	 * Under such conditions, it is not possible to
	 * automically set SRS_TX_BLOCKED bit to indicate
	 * out of tx desc condition. To atomically set
	 * this, we queue the returned packet and do
	 * the setting of SRS_TX_BLOCKED in
	 * mac_tx_srs_drain().
	 */
	if (mp_chain != NULL) {
		mutex_enter(&mac_srs->srs_lock);
		cookie = mac_tx_srs_no_desc(mac_srs, mp_chain, flag, ret_mp);
		mutex_exit(&mac_srs->srs_lock);
		return (cookie);
	}
	SRS_TX_STATS_UPDATE(mac_srs, &stats);

	return (NULL);
}

/*
 * mac_tx_serialize_mode
 *
 * This is an experimental mode implemented as per the request of PAE.
 * In this mode, all callers attempting to send a packet to the NIC
 * will get serialized. Only one thread at any time will access the
 * NIC to send the packet out.
 */
/* ARGSUSED */
static mac_tx_cookie_t
mac_tx_serializer_mode(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uintptr_t fanout_hint, uint16_t flag, mblk_t **ret_mp)
{
	mac_tx_stats_t		stats;
	mac_tx_cookie_t		cookie = NULL;
	mac_srs_tx_t		*srs_tx = &mac_srs->srs_tx;

	/* Single ring, serialize below */
	ASSERT(srs_tx->st_mode == SRS_TX_SERIALIZE);
	mutex_enter(&mac_srs->srs_lock);
	if ((mac_srs->srs_first != NULL) ||
	    (mac_srs->srs_state & SRS_PROC)) {
		/*
		 * In serialization mode, queue all packets until
		 * TX_HIWAT is set.
		 * If drop bit is set, drop if TX_HIWAT is set.
		 * If no_enqueue is set, still enqueue until hiwat
		 * is set and return mblks after TX_HIWAT is set.
		 */
		cookie = mac_tx_srs_enqueue(mac_srs, mp_chain,
		    flag, NULL, ret_mp);
		mutex_exit(&mac_srs->srs_lock);
		return (cookie);
	}
	/*
	 * No packets queued, nothing on proc and no flow
	 * control condition. Fast-path, ok. Do inline
	 * processing.
	 */
	mac_srs->srs_state |= SRS_PROC;
	mutex_exit(&mac_srs->srs_lock);

	mp_chain = mac_tx_send(srs_tx->st_arg1, srs_tx->st_arg2,
	    mp_chain, &stats);

	mutex_enter(&mac_srs->srs_lock);
	mac_srs->srs_state &= ~SRS_PROC;
	if (mp_chain != NULL) {
		cookie = mac_tx_srs_enqueue(mac_srs,
		    mp_chain, flag, NULL, ret_mp);
	}
	if (mac_srs->srs_first != NULL) {
		/*
		 * We processed inline our packet and a new
		 * packet/s got queued while we were
		 * processing. Wakeup srs worker
		 */
		cv_signal(&mac_srs->srs_async);
	}
	mutex_exit(&mac_srs->srs_lock);

	if (cookie == NULL)
		SRS_TX_STATS_UPDATE(mac_srs, &stats);

	return (cookie);
}

/*
 * mac_tx_fanout_mode
 *
 * In this mode, the SRS will have access to multiple Tx rings to send
 * the packet out. The fanout hint that is passed as an argument is
 * used to find an appropriate ring to fanout the traffic. Each Tx
 * ring, in turn,  will have a soft ring associated with it. If a Tx
 * ring runs out of Tx desc's the returned packet will be queued in
 * the soft ring associated with that Tx ring. The srs itself will not
 * queue any packets.
 */

#define	MAC_TX_SOFT_RING_PROCESS(chain) {		       		\
	index = COMPUTE_INDEX(hash, mac_srs->srs_tx_ring_count),	\
	softring = mac_srs->srs_tx_soft_rings[index];			\
	cookie = mac_tx_soft_ring_process(softring, chain, flag, ret_mp); \
	DTRACE_PROBE2(tx__fanout, uint64_t, hash, uint_t, index);	\
}

static mac_tx_cookie_t
mac_tx_fanout_mode(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uintptr_t fanout_hint, uint16_t flag, mblk_t **ret_mp)
{
	mac_soft_ring_t		*softring;
	uint64_t		hash;
	uint_t			index;
	mac_tx_cookie_t		cookie = NULL;

	ASSERT(mac_srs->srs_tx.st_mode == SRS_TX_FANOUT ||
	    mac_srs->srs_tx.st_mode == SRS_TX_BW_FANOUT);
	if (fanout_hint != 0) {
		/*
		 * The hint is specified by the caller, simply pass the
		 * whole chain to the soft ring.
		 */
		hash = HASH_HINT(fanout_hint);
		MAC_TX_SOFT_RING_PROCESS(mp_chain);
	} else {
		mblk_t *last_mp, *cur_mp, *sub_chain;
		uint64_t last_hash = 0;
		uint_t media = mac_srs->srs_mcip->mci_mip->mi_info.mi_media;

		/*
		 * Compute the hash from the contents (headers) of the
		 * packets of the mblk chain. Split the chains into
		 * subchains of the same conversation.
		 *
		 * Since there may be more than one ring used for
		 * sub-chains of the same call, and since the caller
		 * does not maintain per conversation state since it
		 * passed a zero hint, unsent subchains will be
		 * dropped.
		 */

		flag |= MAC_DROP_ON_NO_DESC;
		ret_mp = NULL;

		ASSERT(ret_mp == NULL);

		sub_chain = NULL;
		last_mp = NULL;

		for (cur_mp = mp_chain; cur_mp != NULL;
		    cur_mp = cur_mp->b_next) {
			hash = mac_pkt_hash(media, cur_mp, MAC_PKT_HASH_L4,
			    B_TRUE);
			if (last_hash != 0 && hash != last_hash) {
				/*
				 * Starting a different subchain, send current
				 * chain out.
				 */
				ASSERT(last_mp != NULL);
				last_mp->b_next = NULL;
				MAC_TX_SOFT_RING_PROCESS(sub_chain);
				sub_chain = NULL;
			}

			/* add packet to subchain */
			if (sub_chain == NULL)
				sub_chain = cur_mp;
			last_mp = cur_mp;
			last_hash = hash;
		}

		if (sub_chain != NULL) {
			/* send last subchain */
			ASSERT(last_mp != NULL);
			last_mp->b_next = NULL;
			MAC_TX_SOFT_RING_PROCESS(sub_chain);
		}

		cookie = NULL;
	}

	return (cookie);
}

/*
 * mac_tx_bw_mode
 *
 * In the bandwidth mode, Tx srs will allow packets to go down to Tx ring
 * only if bw is available. Otherwise the packets will be queued in
 * SRS. If the SRS has multiple Tx rings, then packets will get fanned
 * out to a Tx rings.
 */
static mac_tx_cookie_t
mac_tx_bw_mode(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uintptr_t fanout_hint, uint16_t flag, mblk_t **ret_mp)
{
	int			cnt, sz;
	mblk_t			*tail;
	mac_tx_cookie_t		cookie = NULL;
	mac_srs_tx_t		*srs_tx = &mac_srs->srs_tx;
	clock_t			now;

	ASSERT(TX_BANDWIDTH_MODE(mac_srs));
	ASSERT(mac_srs->srs_type & SRST_BW_CONTROL);
	mutex_enter(&mac_srs->srs_lock);
	if (mac_srs->srs_bw->mac_bw_limit == 0) {
		/*
		 * zero bandwidth, no traffic is sent: drop the packets,
		 * or return the whole chain if the caller requests all
		 * unsent packets back.
		 */
		if (flag & MAC_TX_NO_ENQUEUE) {
			cookie = (mac_tx_cookie_t)mac_srs;
			*ret_mp = mp_chain;
		} else {
			MAC_TX_SRS_DROP_MESSAGE(mac_srs, mp_chain, cookie);
		}
		mutex_exit(&mac_srs->srs_lock);
		return (cookie);
	} else if ((mac_srs->srs_first != NULL) ||
	    (mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED)) {
		cookie = mac_tx_srs_enqueue(mac_srs, mp_chain, flag,
		    fanout_hint, ret_mp);
		mutex_exit(&mac_srs->srs_lock);
		return (cookie);
	}
	MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
	now = ddi_get_lbolt();
	if (mac_srs->srs_bw->mac_bw_curr_time != now) {
		mac_srs->srs_bw->mac_bw_curr_time = now;
		mac_srs->srs_bw->mac_bw_used = 0;
	} else if (mac_srs->srs_bw->mac_bw_used >
	    mac_srs->srs_bw->mac_bw_limit) {
		mac_srs->srs_bw->mac_bw_state |= SRS_BW_ENFORCED;
		MAC_TX_SRS_ENQUEUE_CHAIN(mac_srs,
		    mp_chain, tail, cnt, sz);
		/*
		 * Wakeup worker thread. Note that worker
		 * thread has to be woken up so that it
		 * can fire up the timer to be woken up
		 * on the next tick. Also once
		 * BW_ENFORCED is set, it can only be
		 * reset by srs_worker thread. Until then
		 * all packets will get queued up in SRS
		 * and hence this this code path won't be
		 * entered until BW_ENFORCED is reset.
		 */
		cv_signal(&mac_srs->srs_async);
		mutex_exit(&mac_srs->srs_lock);
		return (cookie);
	}

	mac_srs->srs_bw->mac_bw_used += sz;
	mutex_exit(&mac_srs->srs_lock);

	if (srs_tx->st_mode == SRS_TX_BW_FANOUT) {
		mac_soft_ring_t *softring;
		uint_t indx, hash;

		hash = HASH_HINT(fanout_hint);
		indx = COMPUTE_INDEX(hash,
		    mac_srs->srs_tx_ring_count);
		softring = mac_srs->srs_tx_soft_rings[indx];
		return (mac_tx_soft_ring_process(softring, mp_chain, flag,
		    ret_mp));
	} else if (srs_tx->st_mode == SRS_TX_BW_AGGR) {
		return (mac_tx_aggr_mode(mac_srs, mp_chain,
		    fanout_hint, flag, ret_mp));
	} else {
		mac_tx_stats_t		stats;

		mp_chain = mac_tx_send(srs_tx->st_arg1, srs_tx->st_arg2,
		    mp_chain, &stats);

		if (mp_chain != NULL) {
			mutex_enter(&mac_srs->srs_lock);
			MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
			if (mac_srs->srs_bw->mac_bw_used > sz)
				mac_srs->srs_bw->mac_bw_used -= sz;
			else
				mac_srs->srs_bw->mac_bw_used = 0;
			cookie = mac_tx_srs_enqueue(mac_srs, mp_chain, flag,
			    fanout_hint, ret_mp);
			mutex_exit(&mac_srs->srs_lock);
			return (cookie);
		}
		SRS_TX_STATS_UPDATE(mac_srs, &stats);

		return (NULL);
	}
}

/*
 * mac_tx_aggr_mode
 *
 * This routine invokes an aggr function, aggr_find_tx_ring(), to find
 * a (pseudo) Tx ring belonging to a port on which the packet has to
 * be sent. aggr_find_tx_ring() first finds the outgoing port based on
 * L2/L3/L4 policy and then uses the fanout_hint passed to it to pick
 * a Tx ring from the selected port.
 *
 * Note that a port can be deleted from the aggregation. In such a case,
 * the aggregation layer first separates the port from the rest of the
 * ports making sure that port (and thus any Tx rings associated with
 * it) won't get selected in the call to aggr_find_tx_ring() function.
 * Later calls are made to mac_group_rem_ring() passing pseudo Tx ring
 * handles one by one which in turn will quiesce the Tx SRS and remove
 * the soft ring associated with the pseudo Tx ring. Unlike Rx side
 * where a cookie is used to protect against mac_rx_ring() calls on
 * rings that have been removed, no such cookie is needed on the Tx
 * side as the pseudo Tx ring won't be available anymore to
 * aggr_find_tx_ring() once the port has been removed.
 */
static mac_tx_cookie_t
mac_tx_aggr_mode(mac_soft_ring_set_t *mac_srs, mblk_t *mp_chain,
    uintptr_t fanout_hint, uint16_t flag, mblk_t **ret_mp)
{
	mac_srs_tx_t		*srs_tx = &mac_srs->srs_tx;
	mac_tx_ring_fn_t	find_tx_ring_fn;
	mac_ring_handle_t	ring = NULL;
	void			*arg;
	mac_soft_ring_t		*sringp;

	find_tx_ring_fn = srs_tx->st_capab_aggr.mca_find_tx_ring_fn;
	arg = srs_tx->st_capab_aggr.mca_arg;
	if (find_tx_ring_fn(arg, mp_chain, fanout_hint, &ring) == NULL)
		return (NULL);
	sringp = srs_tx->st_soft_rings[((mac_ring_t *)ring)->mr_index];
	return (mac_tx_soft_ring_process(sringp, mp_chain, flag, ret_mp));
}

void
mac_tx_invoke_callbacks(mac_client_impl_t *mcip, mac_tx_cookie_t cookie)
{
	mac_cb_t *mcb;
	mac_tx_notify_cb_t *mtnfp;

	/* Wakeup callback registered clients */
	MAC_CALLBACK_WALKER_INC(&mcip->mci_tx_notify_cb_info);
	for (mcb = mcip->mci_tx_notify_cb_list; mcb != NULL;
	    mcb = mcb->mcb_nextp) {
		mtnfp = (mac_tx_notify_cb_t *)mcb->mcb_objp;
		mtnfp->mtnf_fn(mtnfp->mtnf_arg, cookie);
	}
	MAC_CALLBACK_WALKER_DCR(&mcip->mci_tx_notify_cb_info,
	    &mcip->mci_tx_notify_cb_list);
}

/* ARGSUSED */
void
mac_tx_srs_drain(mac_soft_ring_set_t *mac_srs, uint_t proc_type)
{
	mblk_t			*head, *tail;
	size_t			sz;
	uint32_t		tx_mode;
	uint_t			saved_pkt_count;
	mac_tx_stats_t		stats;
	mac_srs_tx_t		*srs_tx = &mac_srs->srs_tx;
	clock_t			now;

	saved_pkt_count = 0;
	ASSERT(mutex_owned(&mac_srs->srs_lock));
	ASSERT(!(mac_srs->srs_state & SRS_PROC));

	mac_srs->srs_state |= SRS_PROC;

	tx_mode = srs_tx->st_mode;
	if (tx_mode == SRS_TX_DEFAULT || tx_mode == SRS_TX_SERIALIZE) {
		if (mac_srs->srs_first != NULL) {
			head = mac_srs->srs_first;
			tail = mac_srs->srs_last;
			saved_pkt_count = mac_srs->srs_count;
			mac_srs->srs_first = NULL;
			mac_srs->srs_last = NULL;
			mac_srs->srs_count = 0;
			mutex_exit(&mac_srs->srs_lock);

			head = mac_tx_send(srs_tx->st_arg1, srs_tx->st_arg2,
			    head, &stats);

			mutex_enter(&mac_srs->srs_lock);
			if (head != NULL) {
				/* Device out of tx desc, set block */
				if (head->b_next == NULL)
					VERIFY(head == tail);
				tail->b_next = mac_srs->srs_first;
				mac_srs->srs_first = head;
				mac_srs->srs_count +=
				    (saved_pkt_count - stats.mts_opackets);
				if (mac_srs->srs_last == NULL)
					mac_srs->srs_last = tail;
				MAC_TX_SRS_BLOCK(mac_srs, head);
			} else {
				srs_tx->st_woken_up = B_FALSE;
				SRS_TX_STATS_UPDATE(mac_srs, &stats);
			}
		}
	} else if (tx_mode == SRS_TX_BW) {
		/*
		 * We are here because the timer fired and we have some data
		 * to tranmit. Also mac_tx_srs_worker should have reset
		 * SRS_BW_ENFORCED flag
		 */
		ASSERT(!(mac_srs->srs_bw->mac_bw_state & SRS_BW_ENFORCED));
		head = tail = mac_srs->srs_first;
		while (mac_srs->srs_first != NULL) {
			tail = mac_srs->srs_first;
			tail->b_prev = NULL;
			mac_srs->srs_first = tail->b_next;
			if (mac_srs->srs_first == NULL)
				mac_srs->srs_last = NULL;
			mac_srs->srs_count--;
			sz = msgdsize(tail);
			mac_srs->srs_size -= sz;
			saved_pkt_count++;
			MAC_TX_UPDATE_BW_INFO(mac_srs, sz);

			if (mac_srs->srs_bw->mac_bw_used <
			    mac_srs->srs_bw->mac_bw_limit)
				continue;

			now = ddi_get_lbolt();
			if (mac_srs->srs_bw->mac_bw_curr_time != now) {
				mac_srs->srs_bw->mac_bw_curr_time = now;
				mac_srs->srs_bw->mac_bw_used = sz;
				continue;
			}
			mac_srs->srs_bw->mac_bw_state |= SRS_BW_ENFORCED;
			break;
		}

		ASSERT((head == NULL && tail == NULL) ||
		    (head != NULL && tail != NULL));
		if (tail != NULL) {
			tail->b_next = NULL;
			mutex_exit(&mac_srs->srs_lock);

			head = mac_tx_send(srs_tx->st_arg1, srs_tx->st_arg2,
			    head, &stats);

			mutex_enter(&mac_srs->srs_lock);
			if (head != NULL) {
				uint_t size_sent;

				/* Device out of tx desc, set block */
				if (head->b_next == NULL)
					VERIFY(head == tail);
				tail->b_next = mac_srs->srs_first;
				mac_srs->srs_first = head;
				mac_srs->srs_count +=
				    (saved_pkt_count - stats.mts_opackets);
				if (mac_srs->srs_last == NULL)
					mac_srs->srs_last = tail;
				size_sent = sz - stats.mts_obytes;
				mac_srs->srs_size += size_sent;
				mac_srs->srs_bw->mac_bw_sz += size_sent;
				if (mac_srs->srs_bw->mac_bw_used > size_sent) {
					mac_srs->srs_bw->mac_bw_used -=
					    size_sent;
				} else {
					mac_srs->srs_bw->mac_bw_used = 0;
				}
				MAC_TX_SRS_BLOCK(mac_srs, head);
			} else {
				srs_tx->st_woken_up = B_FALSE;
				SRS_TX_STATS_UPDATE(mac_srs, &stats);
			}
		}
	} else if (tx_mode == SRS_TX_BW_FANOUT || tx_mode == SRS_TX_BW_AGGR) {
		mblk_t *prev;
		uint64_t hint;

		/*
		 * We are here because the timer fired and we
		 * have some quota to tranmit.
		 */
		prev = NULL;
		head = tail = mac_srs->srs_first;
		while (mac_srs->srs_first != NULL) {
			tail = mac_srs->srs_first;
			mac_srs->srs_first = tail->b_next;
			if (mac_srs->srs_first == NULL)
				mac_srs->srs_last = NULL;
			mac_srs->srs_count--;
			sz = msgdsize(tail);
			mac_srs->srs_size -= sz;
			mac_srs->srs_bw->mac_bw_used += sz;
			if (prev == NULL)
				hint = (ulong_t)tail->b_prev;
			if (hint != (ulong_t)tail->b_prev) {
				prev->b_next = NULL;
				mutex_exit(&mac_srs->srs_lock);
				TX_SRS_TO_SOFT_RING(mac_srs, head, hint);
				head = tail;
				hint = (ulong_t)tail->b_prev;
				mutex_enter(&mac_srs->srs_lock);
			}

			prev = tail;
			tail->b_prev = NULL;
			if (mac_srs->srs_bw->mac_bw_used <
			    mac_srs->srs_bw->mac_bw_limit)
				continue;

			now = ddi_get_lbolt();
			if (mac_srs->srs_bw->mac_bw_curr_time != now) {
				mac_srs->srs_bw->mac_bw_curr_time = now;
				mac_srs->srs_bw->mac_bw_used = 0;
				continue;
			}
			mac_srs->srs_bw->mac_bw_state |= SRS_BW_ENFORCED;
			break;
		}
		ASSERT((head == NULL && tail == NULL) ||
		    (head != NULL && tail != NULL));
		if (tail != NULL) {
			tail->b_next = NULL;
			mutex_exit(&mac_srs->srs_lock);
			TX_SRS_TO_SOFT_RING(mac_srs, head, hint);
			mutex_enter(&mac_srs->srs_lock);
		}
	}
	/*
	 * SRS_TX_FANOUT case not considered here because packets
	 * won't be queued in the SRS for this case. Packets will
	 * be sent directly to soft rings underneath and if there
	 * is any queueing at all, it would be in Tx side soft
	 * rings.
	 */

	/*
	 * When srs_count becomes 0, reset SRS_TX_HIWAT and
	 * SRS_TX_WAKEUP_CLIENT and wakeup registered clients.
	 */
	if (mac_srs->srs_count == 0 && (mac_srs->srs_state &
	    (SRS_TX_HIWAT | SRS_TX_WAKEUP_CLIENT | SRS_ENQUEUED))) {
		mac_client_impl_t *mcip = mac_srs->srs_mcip;
		boolean_t wakeup_required = B_FALSE;

		if (mac_srs->srs_state &
		    (SRS_TX_HIWAT|SRS_TX_WAKEUP_CLIENT)) {
			wakeup_required = B_TRUE;
		}
		mac_srs->srs_state &= ~(SRS_TX_HIWAT |
		    SRS_TX_WAKEUP_CLIENT | SRS_ENQUEUED);
		mutex_exit(&mac_srs->srs_lock);
		if (wakeup_required) {
			mac_tx_invoke_callbacks(mcip, (mac_tx_cookie_t)mac_srs);
			/*
			 * If the client is not the primary MAC client, then we
			 * need to send the notification to the clients upper
			 * MAC, i.e. mci_upper_mip.
			 */
			mac_tx_notify(mcip->mci_upper_mip != NULL ?
			    mcip->mci_upper_mip : mcip->mci_mip);
		}
		mutex_enter(&mac_srs->srs_lock);
	}
	mac_srs->srs_state &= ~SRS_PROC;
}

/*
 * Given a packet, get the flow_entry that identifies the flow
 * to which that packet belongs. The flow_entry will contain
 * the transmit function to be used to send the packet. If the
 * function returns NULL, the packet should be sent using the
 * underlying NIC.
 */
static flow_entry_t *
mac_tx_classify(mac_impl_t *mip, mblk_t *mp)
{
	flow_entry_t		*flent = NULL;
	mac_client_impl_t	*mcip;
	int	err;

	/*
	 * Do classification on the packet.
	 */
	err = mac_flow_lookup(mip->mi_flow_tab, mp, FLOW_OUTBOUND, &flent);
	if (err != 0)
		return (NULL);

	/*
	 * This flent might just be an additional one on the MAC client,
	 * i.e. for classification purposes (different fdesc), however
	 * the resources, SRS et. al., are in the mci_flent, so if
	 * this isn't the mci_flent, we need to get it.
	 */
	if ((mcip = flent->fe_mcip) != NULL && mcip->mci_flent != flent) {
		FLOW_REFRELE(flent);
		flent = mcip->mci_flent;
		FLOW_TRY_REFHOLD(flent, err);
		if (err != 0)
			return (NULL);
	}

	return (flent);
}

/*
 * This macro is only meant to be used by mac_tx_send().
 */
#define	CHECK_VID_AND_ADD_TAG(mp) {			\
	if (vid_check) {				\
		int err = 0;				\
							\
		MAC_VID_CHECK(src_mcip, (mp), err);	\
		if (err != 0) {				\
			freemsg((mp));			\
			(mp) = next;			\
			oerrors++;			\
			continue;			\
		}					\
	}						\
	if (add_tag) {					\
		(mp) = mac_add_vlan_tag((mp), 0, vid);	\
		if ((mp) == NULL) {			\
			(mp) = next;			\
			oerrors++;			\
			continue;			\
		}					\
	}						\
}

mblk_t *
mac_tx_send(mac_client_handle_t mch, mac_ring_handle_t ring, mblk_t *mp_chain,
    mac_tx_stats_t *stats)
{
	mac_client_impl_t *src_mcip = (mac_client_impl_t *)mch;
	mac_impl_t *mip = src_mcip->mci_mip;
	uint_t obytes = 0, opackets = 0, oerrors = 0;
	mblk_t *mp = NULL, *next;
	boolean_t vid_check, add_tag;
	uint16_t vid = 0;

	if (mip->mi_nclients > 1) {
		vid_check = MAC_VID_CHECK_NEEDED(src_mcip);
		add_tag = MAC_TAG_NEEDED(src_mcip);
		if (add_tag)
			vid = mac_client_vid(mch);
	} else {
		ASSERT(mip->mi_nclients == 1);
		vid_check = add_tag = B_FALSE;
	}

	/*
	 * Fastpath: if there's only one client, we simply send
	 * the packet down to the underlying NIC.
	 */
	if (mip->mi_nactiveclients == 1) {
		DTRACE_PROBE2(fastpath,
		    mac_client_impl_t *, src_mcip, mblk_t *, mp_chain);

		mp = mp_chain;
		while (mp != NULL) {
			next = mp->b_next;
			mp->b_next = NULL;
			opackets++;
			obytes += (mp->b_cont == NULL ? MBLKL(mp) :
			    msgdsize(mp));

			CHECK_VID_AND_ADD_TAG(mp);
			MAC_TX(mip, ring, mp, src_mcip);

			/*
			 * If the driver is out of descriptors and does a
			 * partial send it will return a chain of unsent
			 * mblks. Adjust the accounting stats.
			 */
			if (mp != NULL) {
				opackets--;
				obytes -= msgdsize(mp);
				mp->b_next = next;
				break;
			}
			mp = next;
		}
		goto done;
	}

	/*
	 * No fastpath, we either have more than one MAC client
	 * defined on top of the same MAC, or one or more MAC
	 * client promiscuous callbacks.
	 */
	DTRACE_PROBE3(slowpath, mac_client_impl_t *,
	    src_mcip, int, mip->mi_nclients, mblk_t *, mp_chain);

	mp = mp_chain;
	while (mp != NULL) {
		flow_entry_t *dst_flow_ent;
		void *flow_cookie;
		size_t	pkt_size;
		mblk_t *mp1;

		next = mp->b_next;
		mp->b_next = NULL;
		opackets++;
		pkt_size = (mp->b_cont == NULL ? MBLKL(mp) : msgdsize(mp));
		obytes += pkt_size;
		CHECK_VID_AND_ADD_TAG(mp);

		/*
		 * Find the destination.
		 */
		dst_flow_ent = mac_tx_classify(mip, mp);

		if (dst_flow_ent != NULL) {
			size_t	hdrsize;
			int	err = 0;

			if (mip->mi_info.mi_nativemedia == DL_ETHER) {
				struct ether_vlan_header *evhp =
				    (struct ether_vlan_header *)mp->b_rptr;

				if (ntohs(evhp->ether_tpid) == ETHERTYPE_VLAN)
					hdrsize = sizeof (*evhp);
				else
					hdrsize = sizeof (struct ether_header);
			} else {
				mac_header_info_t	mhi;

				err = mac_header_info((mac_handle_t)mip,
				    mp, &mhi);
				if (err == 0)
					hdrsize = mhi.mhi_hdrsize;
			}

			/*
			 * Got a matching flow. It's either another
			 * MAC client, or a broadcast/multicast flow.
			 * Make sure the packet size is within the
			 * allowed size. If not drop the packet and
			 * move to next packet.
			 */
			if (err != 0 ||
			    (pkt_size - hdrsize) > mip->mi_sdu_max) {
				oerrors++;
				DTRACE_PROBE2(loopback__drop, size_t, pkt_size,
				    mblk_t *, mp);
				freemsg(mp);
				mp = next;
				FLOW_REFRELE(dst_flow_ent);
				continue;
			}
			flow_cookie = mac_flow_get_client_cookie(dst_flow_ent);
			if (flow_cookie != NULL) {
				/*
				 * The vnic_bcast_send function expects
				 * to receive the sender MAC client
				 * as value for arg2.
				 */
				mac_bcast_send(flow_cookie, src_mcip, mp,
				    B_TRUE);
			} else {
				/*
				 * loopback the packet to a local MAC
				 * client. We force a context switch
				 * if both source and destination MAC
				 * clients are used by IP, i.e.
				 * bypass is set.
				 */
				boolean_t do_switch;
				mac_client_impl_t *dst_mcip =
				    dst_flow_ent->fe_mcip;

				/*
				 * Check if there are promiscuous mode
				 * callbacks defined. This check is
				 * done here in the 'else' case and
				 * not in other cases because this
				 * path is for local loopback
				 * communication which does not go
				 * through MAC_TX(). For paths that go
				 * through MAC_TX(), the promisc_list
				 * check is done inside the MAC_TX()
				 * macro.
				 */
				if (mip->mi_promisc_list != NULL)
					mac_promisc_dispatch(mip, mp, src_mcip);

				do_switch = ((src_mcip->mci_state_flags &
				    dst_mcip->mci_state_flags &
				    MCIS_CLIENT_POLL_CAPABLE) != 0);

				if ((mp1 = mac_fix_cksum(mp)) != NULL) {
					(dst_flow_ent->fe_cb_fn)(
					    dst_flow_ent->fe_cb_arg1,
					    dst_flow_ent->fe_cb_arg2,
					    mp1, do_switch);
				}
			}
			FLOW_REFRELE(dst_flow_ent);
		} else {
			/*
			 * Unknown destination, send via the underlying
			 * NIC.
			 */
			MAC_TX(mip, ring, mp, src_mcip);
			if (mp != NULL) {
				/*
				 * Adjust for the last packet that
				 * could not be transmitted
				 */
				opackets--;
				obytes -= pkt_size;
				mp->b_next = next;
				break;
			}
		}
		mp = next;
	}

done:
	stats->mts_obytes = obytes;
	stats->mts_opackets = opackets;
	stats->mts_oerrors = oerrors;
	return (mp);
}

/*
 * mac_tx_srs_ring_present
 *
 * Returns whether the specified ring is part of the specified SRS.
 */
boolean_t
mac_tx_srs_ring_present(mac_soft_ring_set_t *srs, mac_ring_t *tx_ring)
{
	int i;
	mac_soft_ring_t *soft_ring;

	if (srs->srs_tx.st_arg2 == tx_ring)
		return (B_TRUE);

	for (i = 0; i < srs->srs_tx_ring_count; i++) {
		soft_ring =  srs->srs_tx_soft_rings[i];
		if (soft_ring->s_ring_tx_arg2 == tx_ring)
			return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * mac_tx_srs_get_soft_ring
 *
 * Returns the TX soft ring associated with the given ring, if present.
 */
mac_soft_ring_t *
mac_tx_srs_get_soft_ring(mac_soft_ring_set_t *srs, mac_ring_t *tx_ring)
{
	int		i;
	mac_soft_ring_t	*soft_ring;

	if (srs->srs_tx.st_arg2 == tx_ring)
		return (NULL);

	for (i = 0; i < srs->srs_tx_ring_count; i++) {
		soft_ring =  srs->srs_tx_soft_rings[i];
		if (soft_ring->s_ring_tx_arg2 == tx_ring)
			return (soft_ring);
	}

	return (NULL);
}

/*
 * mac_tx_srs_wakeup
 *
 * Called when Tx desc become available. Wakeup the appropriate worker
 * thread after resetting the SRS_TX_BLOCKED/S_RING_BLOCK bit in the
 * state field.
 */
void
mac_tx_srs_wakeup(mac_soft_ring_set_t *mac_srs, mac_ring_handle_t ring)
{
	int i;
	mac_soft_ring_t *sringp;
	mac_srs_tx_t *srs_tx = &mac_srs->srs_tx;

	mutex_enter(&mac_srs->srs_lock);
	/*
	 * srs_tx_ring_count == 0 is the single ring mode case. In
	 * this mode, there will not be Tx soft rings associated
	 * with the SRS.
	 */
	if (!MAC_TX_SOFT_RINGS(mac_srs)) {
		if (srs_tx->st_arg2 == ring &&
		    mac_srs->srs_state & SRS_TX_BLOCKED) {
			mac_srs->srs_state &= ~SRS_TX_BLOCKED;
			srs_tx->st_stat.mts_unblockcnt++;
			cv_signal(&mac_srs->srs_async);
		}
		/*
		 * A wakeup can come before tx_srs_drain() could
		 * grab srs lock and set SRS_TX_BLOCKED. So
		 * always set woken_up flag when we come here.
		 */
		srs_tx->st_woken_up = B_TRUE;
		mutex_exit(&mac_srs->srs_lock);
		return;
	}

	/*
	 * If you are here, it is for FANOUT, BW_FANOUT,
	 * AGGR_MODE or AGGR_BW_MODE case
	 */
	for (i = 0; i < mac_srs->srs_tx_ring_count; i++) {
		sringp = mac_srs->srs_tx_soft_rings[i];
		mutex_enter(&sringp->s_ring_lock);
		if (sringp->s_ring_tx_arg2 == ring) {
			if (sringp->s_ring_state & S_RING_BLOCK) {
				sringp->s_ring_state &= ~S_RING_BLOCK;
				sringp->s_st_stat.mts_unblockcnt++;
				cv_signal(&sringp->s_ring_async);
			}
			sringp->s_ring_tx_woken_up = B_TRUE;
		}
		mutex_exit(&sringp->s_ring_lock);
	}
	mutex_exit(&mac_srs->srs_lock);
}

/*
 * Once the driver is done draining, send a MAC_NOTE_TX notification to unleash
 * the blocked clients again.
 */
void
mac_tx_notify(mac_impl_t *mip)
{
	i_mac_notify(mip, MAC_NOTE_TX);
}

/*
 * RX SOFTRING RELATED FUNCTIONS
 *
 * These functions really belong in mac_soft_ring.c and here for
 * a short period.
 */

#define	SOFT_RING_ENQUEUE_CHAIN(ringp, mp, tail, cnt, sz) {	       	\
	/*								\
	 * Enqueue our mblk chain.					\
	 */								\
	ASSERT(MUTEX_HELD(&(ringp)->s_ring_lock));			\
									\
	if ((ringp)->s_ring_last != NULL)				\
		(ringp)->s_ring_last->b_next = (mp);			\
	else								\
		(ringp)->s_ring_first = (mp);				\
	(ringp)->s_ring_last = (tail);					\
	(ringp)->s_ring_count += (cnt);					\
	ASSERT((ringp)->s_ring_count > 0);				\
	if ((ringp)->s_ring_type & ST_RING_BW_CTL) {			\
		(ringp)->s_ring_size += sz;				\
	}								\
}

/*
 * Default entry point to deliver a packet chain to a MAC client.
 * If the MAC client has flows, do the classification with these
 * flows as well.
 */
/* ARGSUSED */
void
mac_rx_deliver(void *arg1, mac_resource_handle_t mrh, mblk_t *mp_chain,
    mac_header_info_t *arg3)
{
	mac_client_impl_t *mcip = arg1;

	if (mcip->mci_nvids == 1 &&
	    !(mcip->mci_state_flags & MCIS_STRIP_DISABLE)) {
		/*
		 * If the client has exactly one VID associated with it
		 * and striping of VLAN header is not disabled,
		 * remove the VLAN tag from the packet before
		 * passing it on to the client's receive callback.
		 * Note that this needs to be done after we dispatch
		 * the packet to the promiscuous listeners of the
		 * client, since they expect to see the whole
		 * frame including the VLAN headers.
		 */
		mp_chain = mac_strip_vlan_tag_chain(mp_chain);
	}

	mcip->mci_rx_fn(mcip->mci_rx_arg, mrh, mp_chain, B_FALSE);
}

/*
 * mac_rx_soft_ring_process
 *
 * process a chain for a given soft ring. The number of packets queued
 * in the SRS and its associated soft rings (including this one) is
 * very small (tracked by srs_poll_pkt_cnt), then allow the entering
 * thread (interrupt or poll thread) to do inline processing. This
 * helps keep the latency down under low load.
 *
 * The proc and arg for each mblk is already stored in the mblk in
 * appropriate places.
 */
/* ARGSUSED */
void
mac_rx_soft_ring_process(mac_client_impl_t *mcip, mac_soft_ring_t *ringp,
    mblk_t *mp_chain, mblk_t *tail, int cnt, size_t sz)
{
	mac_direct_rx_t		proc;
	void			*arg1;
	mac_resource_handle_t	arg2;
	mac_soft_ring_set_t	*mac_srs = ringp->s_ring_set;

	ASSERT(ringp != NULL);
	ASSERT(mp_chain != NULL);
	ASSERT(tail != NULL);
	ASSERT(MUTEX_NOT_HELD(&ringp->s_ring_lock));

	mutex_enter(&ringp->s_ring_lock);
	ringp->s_ring_total_inpkt += cnt;
	ringp->s_ring_total_rbytes += sz;
	if ((mac_srs->srs_rx.sr_poll_pkt_cnt <= 1) &&
	    !(ringp->s_ring_type & ST_RING_WORKER_ONLY)) {
		/* If on processor or blanking on, then enqueue and return */
		if (ringp->s_ring_state & S_RING_BLANK ||
		    ringp->s_ring_state & S_RING_PROC) {
			SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, cnt, sz);
			mutex_exit(&ringp->s_ring_lock);
			return;
		}
		proc = ringp->s_ring_rx_func;
		arg1 = ringp->s_ring_rx_arg1;
		arg2 = ringp->s_ring_rx_arg2;
		/*
		 * See if anything is already queued. If we are the
		 * first packet, do inline processing else queue the
		 * packet and do the drain.
		 */
		if (ringp->s_ring_first == NULL) {
			/*
			 * Fast-path, ok to process and nothing queued.
			 */
			ringp->s_ring_run = curthread;
			ringp->s_ring_state |= (S_RING_PROC);

			mutex_exit(&ringp->s_ring_lock);

			/*
			 * We are the chain of 1 packet so
			 * go through this fast path.
			 */
			ASSERT(mp_chain->b_next == NULL);

			(*proc)(arg1, arg2, mp_chain, NULL);

			ASSERT(MUTEX_NOT_HELD(&ringp->s_ring_lock));
			/*
			 * If we have a soft ring set which is doing
			 * bandwidth control, we need to decrement
			 * srs_size and count so it the SRS can have a
			 * accurate idea of what is the real data
			 * queued between SRS and its soft rings. We
			 * decrement the counters only when the packet
			 * gets processed by both SRS and the soft ring.
			 */
			mutex_enter(&mac_srs->srs_lock);
			MAC_UPDATE_SRS_COUNT_LOCKED(mac_srs, cnt);
			MAC_UPDATE_SRS_SIZE_LOCKED(mac_srs, sz);
			mutex_exit(&mac_srs->srs_lock);

			mutex_enter(&ringp->s_ring_lock);
			ringp->s_ring_run = NULL;
			ringp->s_ring_state &= ~S_RING_PROC;
			if (ringp->s_ring_state & S_RING_CLIENT_WAIT)
				cv_signal(&ringp->s_ring_client_cv);

			if ((ringp->s_ring_first == NULL) ||
			    (ringp->s_ring_state & S_RING_BLANK)) {
				/*
				 * We processed inline our packet and
				 * nothing new has arrived or our
				 * receiver doesn't want to receive
				 * any packets. We are done.
				 */
				mutex_exit(&ringp->s_ring_lock);
				return;
			}
		} else {
			SOFT_RING_ENQUEUE_CHAIN(ringp,
			    mp_chain, tail, cnt, sz);
		}

		/*
		 * We are here because either we couldn't do inline
		 * processing (because something was already
		 * queued), or we had a chain of more than one
		 * packet, or something else arrived after we were
		 * done with inline processing.
		 */
		ASSERT(MUTEX_HELD(&ringp->s_ring_lock));
		ASSERT(ringp->s_ring_first != NULL);

		ringp->s_ring_drain_func(ringp);
		mutex_exit(&ringp->s_ring_lock);
		return;
	} else {
		/* ST_RING_WORKER_ONLY case */
		SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, cnt, sz);
		mac_soft_ring_worker_wakeup(ringp);
		mutex_exit(&ringp->s_ring_lock);
	}
}

/*
 * TX SOFTRING RELATED FUNCTIONS
 *
 * These functions really belong in mac_soft_ring.c and here for
 * a short period.
 */

#define	TX_SOFT_RING_ENQUEUE_CHAIN(ringp, mp, tail, cnt, sz) {	       	\
	ASSERT(MUTEX_HELD(&ringp->s_ring_lock));			\
	ringp->s_ring_state |= S_RING_ENQUEUED;				\
	SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, cnt, sz);	\
}

/*
 * mac_tx_sring_queued
 *
 * When we are out of transmit descriptors and we already have a
 * queue that exceeds hiwat (or the client called us with
 * MAC_TX_NO_ENQUEUE or MAC_DROP_ON_NO_DESC flag), return the
 * soft ring pointer as the opaque cookie for the client enable
 * flow control.
 */
static mac_tx_cookie_t
mac_tx_sring_enqueue(mac_soft_ring_t *ringp, mblk_t *mp_chain, uint16_t flag,
    mblk_t **ret_mp)
{
	int cnt;
	size_t sz;
	mblk_t *tail;
	mac_soft_ring_set_t *mac_srs = ringp->s_ring_set;
	mac_tx_cookie_t cookie = NULL;
	boolean_t wakeup_worker = B_TRUE;

	ASSERT(MUTEX_HELD(&ringp->s_ring_lock));
	MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
	if (flag & MAC_DROP_ON_NO_DESC) {
		mac_pkt_drop(NULL, NULL, mp_chain, B_FALSE);
		/* increment freed stats */
		ringp->s_ring_drops += cnt;
		cookie = (mac_tx_cookie_t)ringp;
	} else {
		if (ringp->s_ring_first != NULL)
			wakeup_worker = B_FALSE;

		if (flag & MAC_TX_NO_ENQUEUE) {
			/*
			 * If QUEUED is not set, queue the packet
			 * and let mac_tx_soft_ring_drain() set
			 * the TX_BLOCKED bit for the reasons
			 * explained above. Otherwise, return the
			 * mblks.
			 */
			if (wakeup_worker) {
				TX_SOFT_RING_ENQUEUE_CHAIN(ringp,
				    mp_chain, tail, cnt, sz);
			} else {
				ringp->s_ring_state |= S_RING_WAKEUP_CLIENT;
				cookie = (mac_tx_cookie_t)ringp;
				*ret_mp = mp_chain;
			}
		} else {
			boolean_t enqueue = B_TRUE;

			if (ringp->s_ring_count > ringp->s_ring_tx_hiwat) {
				/*
				 * flow-controlled. Store ringp in cookie
				 * so that it can be returned as
				 * mac_tx_cookie_t to client
				 */
				ringp->s_ring_state |= S_RING_TX_HIWAT;
				cookie = (mac_tx_cookie_t)ringp;
				ringp->s_ring_hiwat_cnt++;
				if (ringp->s_ring_count >
				    ringp->s_ring_tx_max_q_cnt) {
					/* increment freed stats */
					ringp->s_ring_drops += cnt;
					/*
					 * b_prev may be set to the fanout hint
					 * hence can't use freemsg directly
					 */
					mac_pkt_drop(NULL, NULL,
					    mp_chain, B_FALSE);
					DTRACE_PROBE1(tx_queued_hiwat,
					    mac_soft_ring_t *, ringp);
					enqueue = B_FALSE;
				}
			}
			if (enqueue) {
				TX_SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain,
				    tail, cnt, sz);
			}
		}
		if (wakeup_worker)
			cv_signal(&ringp->s_ring_async);
	}
	return (cookie);
}


/*
 * mac_tx_soft_ring_process
 *
 * This routine is called when fanning out outgoing traffic among
 * multipe Tx rings.
 * Note that a soft ring is associated with a h/w Tx ring.
 */
mac_tx_cookie_t
mac_tx_soft_ring_process(mac_soft_ring_t *ringp, mblk_t *mp_chain,
    uint16_t flag, mblk_t **ret_mp)
{
	mac_soft_ring_set_t *mac_srs = ringp->s_ring_set;
	int	cnt;
	size_t	sz;
	mblk_t	*tail;
	mac_tx_cookie_t cookie = NULL;

	ASSERT(ringp != NULL);
	ASSERT(mp_chain != NULL);
	ASSERT(MUTEX_NOT_HELD(&ringp->s_ring_lock));
	/*
	 * The following modes can come here: SRS_TX_BW_FANOUT,
	 * SRS_TX_FANOUT, SRS_TX_AGGR, SRS_TX_BW_AGGR.
	 */
	ASSERT(MAC_TX_SOFT_RINGS(mac_srs));
	ASSERT(mac_srs->srs_tx.st_mode == SRS_TX_FANOUT ||
	    mac_srs->srs_tx.st_mode == SRS_TX_BW_FANOUT ||
	    mac_srs->srs_tx.st_mode == SRS_TX_AGGR ||
	    mac_srs->srs_tx.st_mode == SRS_TX_BW_AGGR);

	if (ringp->s_ring_type & ST_RING_WORKER_ONLY) {
		/* Serialization mode */

		mutex_enter(&ringp->s_ring_lock);
		if (ringp->s_ring_count > ringp->s_ring_tx_hiwat) {
			cookie = mac_tx_sring_enqueue(ringp, mp_chain,
			    flag, ret_mp);
			mutex_exit(&ringp->s_ring_lock);
			return (cookie);
		}
		MAC_COUNT_CHAIN(mac_srs, mp_chain, tail, cnt, sz);
		TX_SOFT_RING_ENQUEUE_CHAIN(ringp, mp_chain, tail, cnt, sz);
		if (ringp->s_ring_state & (S_RING_BLOCK | S_RING_PROC)) {
			/*
			 * If ring is blocked due to lack of Tx
			 * descs, just return. Worker thread
			 * will get scheduled when Tx desc's
			 * become available.
			 */
			mutex_exit(&ringp->s_ring_lock);
			return (cookie);
		}
		mac_soft_ring_worker_wakeup(ringp);
		mutex_exit(&ringp->s_ring_lock);
		return (cookie);
	} else {
		/* Default fanout mode */
		/*
		 * S_RING_BLOCKED is set when underlying NIC runs
		 * out of Tx descs and messages start getting
		 * queued. It won't get reset until
		 * tx_srs_drain() completely drains out the
		 * messages.
		 */
		mac_tx_stats_t		stats;

		if (ringp->s_ring_state & S_RING_ENQUEUED) {
			/* Tx descs/resources not available */
			mutex_enter(&ringp->s_ring_lock);
			if (ringp->s_ring_state & S_RING_ENQUEUED) {
				cookie = mac_tx_sring_enqueue(ringp, mp_chain,
				    flag, ret_mp);
				mutex_exit(&ringp->s_ring_lock);
				return (cookie);
			}
			/*
			 * While we were computing mblk count, the
			 * flow control condition got relieved.
			 * Continue with the transmission.
			 */
			mutex_exit(&ringp->s_ring_lock);
		}

		mp_chain = mac_tx_send(ringp->s_ring_tx_arg1,
		    ringp->s_ring_tx_arg2, mp_chain, &stats);

		/*
		 * Multiple threads could be here sending packets.
		 * Under such conditions, it is not possible to
		 * automically set S_RING_BLOCKED bit to indicate
		 * out of tx desc condition. To atomically set
		 * this, we queue the returned packet and do
		 * the setting of S_RING_BLOCKED in
		 * mac_tx_soft_ring_drain().
		 */
		if (mp_chain != NULL) {
			mutex_enter(&ringp->s_ring_lock);
			cookie =
			    mac_tx_sring_enqueue(ringp, mp_chain, flag, ret_mp);
			mutex_exit(&ringp->s_ring_lock);
			return (cookie);
		}
		SRS_TX_STATS_UPDATE(mac_srs, &stats);
		SOFTRING_TX_STATS_UPDATE(ringp, &stats);

		return (NULL);
	}
}
