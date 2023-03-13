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
 * Copyright 2022 MNX Cloud, Inc.
 */

/*
 * Overlay Devices
 *
 * Overlay devices provide a means for creating overlay networks, a means of
 * multiplexing multiple logical, isolated, and discrete layer two and layer
 * three networks on top of one physical network.
 *
 * In general, these overlay devices encapsulate the logic to answer two
 * different questions:
 *
 *   1) How should I transform a packet to put it on the wire?
 *   2) Where should I send a transformed packet?
 *
 * Each overlay device is presented to the user as a GLDv3 device. While the
 * link itself cannot have an IP interface created on top of it, it allows for
 * additional GLDv3 devices, such as a VNIC, to be created on top of it which
 * can be plumbed up with IP interfaces.
 *
 *
 * --------------------
 * General Architecture
 * --------------------
 *
 * The logical overlay device that a user sees in dladm(8) is a combination of
 * two different components that work together. The first component is this
 * kernel module, which is responsible for answering question one -- how should
 * I transform a packet to put it on the wire.
 *
 * The second component is what we call the virtual ARP daemon, or varpd. It is
 * a userland component that is responsible for answering the second question --
 * Where should I send a transformed packet. Instances of the kernel overlay
 * GLDv3 device ask varpd the question of where should a packet go.
 *
 * The split was done for a few reasons. Importantly, we wanted to keep the act
 * of generating encapsulated packets in the kernel so as to ensure that the
 * general data path was fast and also kept simple. On the flip side, while the
 * question of where should something go may be simple, it may often be
 * complicated and need to interface with several different external or
 * distributed systems. In those cases, it's simpler to allow for the full
 * flexibility of userland to be brought to bear to solve that problem and in
 * general, the path isn't very common.
 *
 * The following is what makes up the logical overlay device that a user would
 * create with dladm(8).
 *
 *       Kernel                                     Userland
 *   . . . . . . . . . . . . . . . . . . . . .   . . . . . . . . . . . . .
 *   . +--------+   +--------+  +--------+   .   .                       .
 *   . | VNIC 0 |   | VNIC 1 |  | VNIC 2 |   .   .                       .
 *   . +--------+   +--------+  +--------+   .   .                       .
 *   .     |            |           |        .   .                       .
 *   .     |            |           |        .   .                       .
 *   .     +------------+-----------+        .   .                       .
 *   .                  |              . . /dev/overlay                  .
 *   .           +--------------+      .     .   .       +------------+  .
 *   .           |              |      .     .   .       |            |  .
 *   .           |    Overlay   |======*=================|   Virtual  |  .
 *   .           | GLDv3 Device |========================| ARP Daemon |  .
 *   .           |              |            .   .       |            |  .
 *   .           +--------------+            .   .       +------------+  .
 *   .                  |                    .   .              |        .
 *   .                  |                    .   .              |        .
 *   .           +----------------+          .   .         +--------+    .
 *   .           |  Overlay       |          .   .         | varpd  |    .
 *   .           |  Encapsulation |          .   .         | Lookup |    .
 *   .           |  Plugin        |          .   .         | Plugin |    .
 *   .           +----------------+          .   .         +--------+    .
 *   . . . . . . . . . . . . . . . . . . . . .   . . . . . . . . . . . . .
 *
 *
 * This image shows the two different components and where they live.
 * Importantly, it also shows that both the kernel overlay device and the
 * userland varpd both support plugins. The plugins actually implement the
 * things that users care about and the APIs have been designed to try to
 * minimize the amount of things that a module writer needs to worry about it.
 *
 * IDENTIFIERS
 *
 * Every overlay device is defined by a unique identifier which is the overlay
 * identifier. Its purpose is similar to that of a VLAN identifier, it's a
 * unique number that is used to differentiate between different entries on the
 * wire.
 *
 * ENCAPSULATION
 *
 * An overlay encapsulation plugin is a kernel miscellaneous module whose
 * purpose is to contain knowledge about how to transform packets to put them
 * onto the wire and to take them off. An example of an encapsulation plugin is
 * vxlan. It's also how support for things like nvgre or geneve would be brought
 * into the system.
 *
 * Each encapsulation plugins defines a series of operation vectors and
 * properties. For the full details on everything they should provide, please
 * read uts/common/sys/overlay_plugin.h. The encapsulation plugin is responsible
 * for telling the system what information is required to send a packet. For
 * example, vxlan is defined to send everything over a UDP packet and therefore
 * requires a port and an IP address, while nvgre on the other hand is its own
 * IP type and therefore just requires an IP address. In addition, it also
 * provides information about the kind of socket that should be created. This is
 * used by the kernel multiplexor, more of that in the Kernel Components
 * section.
 *
 * LOOKUPS
 *
 * The kernel communicates requests for lookups over the character device
 * /dev/overlay. varpd is responsible for listening for requests on that device
 * and answering them. The character device is specific to the target path and
 * varpd.
 *
 * Much as the kernel overlay module handles the bulk of the scaffolding but
 * leaves the important work to the encapsulation plugin, varpd provides a
 * similar role and leaves the full brunt of lookups to a userland dynamic
 * shared object which implements the logic of lookups.
 *
 * Each lookup plugin defines a series of operation vectors and properties. For
 * the full details on everything that they should provide, please read
 * lib/varpd/libvarpd/libvarpd_provider.h. Essentially, they are given a MAC
 * address and asked to give an address on the physical network that it should
 * be sent to. In addition, they handle questions related to how to handle
 * things like broadcast and multicast traffic, etc.
 *
 * ----------
 * Properties
 * ----------
 *
 * A device from a dladm perspective has a unique set of properties that are
 * combined from three different sources:
 *
 *   1) Generic properties that every overlay device has
 *   2) Properties that are specific to the encapsulation plugin
 *   3) Properties that are specific to the lookup plugin
 *
 * All of these are exposed in a single set of properties in dladm. Note that
 * these are not necessarily traditional link properties. However, if something
 * is both a traditional GLDv3 link property, say the MTU of a device, and a
 * specific property here, than the driver ensures that all existing GLDv3
 * specific means of manipulating it are used and wraps up its private property
 * interfaces to ensure that works.
 *
 * Properties in the second and third category are prefixed with the name of
 * their module. For example, the vxlan encapsulation module has a property
 * called the 'listen_ip'. This property would show up in dladm as
 * 'vxlan/listen_ip'. This allows different plugins to both use similar names
 * for similar properties and to also have independent name spaces so that
 * overlapping names do not conflict with anything else.
 *
 * While the kernel combines both sets one and two into a single coherent view,
 * it does not do anything with respect to the properties that are owned by the
 * lookup plugin -- those are owned wholly by varpd. Instead, libdladm is in
 * charge of bridging these two worlds into one magical experience for the user.
 * It carries the burden of knowing about both overlay specific and varpd
 * specific properties. Importantly, we want to maintain this distinction. We
 * don't want to treat the kernel as an arbitrary key/value store for varpd and
 * we want the kernel to own its own data and not have to ask userland for
 * information that it owns.
 *
 * Every property in the system has the following attributes:
 *
 *   o A name
 *   o A type
 *   o A size
 *   o Permissions
 *   o Default value
 *   o Valid value ranges
 *   o A value
 *
 * Everything except for the value is obtained by callers through the propinfo
 * callbacks and a property has a maximum size of OVERLAY_PROP_SIZEMAX,
 * currently 256 bytes.
 *
 * The following are the supported types of properties:
 *
 *	OVERLAY_PROP_T_INT
 *
 *		A signed integer, its length is 8 bytes, corresponding to a
 *		int64_t.
 *
 *	OVERLAY_PROP_T_UINT
 *
 *		An unsigned integer, its length is 8 bytes, corresponding to a
 *		uint64_t.
 *
 *	OVERLAY_PROP_T_IP
 *
 *		A struct in6_addr, it has a fixed size.
 *
 *	OVERLAY_PROP_T_STRING
 *
 *		A null-terminated character string encoded in either ASCII or
 *		UTF-8. Note that the size of the string includes the null
 *		terminator.
 *
 * The next thing that we apply to a property is its permission. The permissions
 * are put together by the bitwise or of the following flags and values.
 *
 *	OVERLAY_PROP_PERM_REQ
 *
 *		This indicates a required property. A property that is required
 *		must be set by a consumer before the device can be created. If a
 *		required property has a default property, this constraint is
 *		loosened because the default property defines the value.
 *
 *	OVERLAY_PORP_PERM_READ
 *
 *		This indicates that a property can be read. All properties will
 *		have this value set.
 *
 *	OVERLAY_PROP_PERM_WRITE
 *
 *		This indicates that a property can be written to and thus
 *		updated by userland. Properties that are only intended to
 *		display information, will not have OVERLAY_PROP_PERM_WRITE set.
 *
 * In addition, a few additional values are defined as a convenience to
 * consumers. The first, OVERLAY_PROP_PERM_RW, is a combination of
 * OVERLAY_PROP_PERM_READ and OVERLAY_PERM_PROP_WRITE. The second,
 * OVERLAY_PROP_PERM_RRW, is a combination of OVERLAY_PROP_PERM_REQ,
 * OVERLAY_PROP_PERM_READ, and OVERLAY_PROP_PERM_WRITE. The protection mode of a
 * property should generally be a constant across its lifetime.
 *
 * A property may optionally have a default value. If it does have a default
 * value, and that property is not set to be a different value, then the default
 * value is inherited automatically. It also means that if the default value is
 * acceptable, there is no need to set the value for a required property. For
 * example, the vxlan module has the vxlan/listen_port property which is
 * required, but has a default value of 4789 (the IANA assigned port). Because
 * of that default value, there is no need for it to be set.
 *
 * Finally, a property may declare a list of valid values. These valid values
 * are used for display purposes, they are not enforced by the broader system,
 * but merely allow a means for the information to be communicated to the user
 * through dladm(8). Like a default value, this is optional.
 *
 * The general scaffolding does not do very much with respect to the getting and
 * setting of properties. That is really owned by the individual plugins
 * themselves.
 *
 * -----------------------------
 * Destinations and Plugin Types
 * -----------------------------
 *
 * Both encapsulation and lookup plugins define the kinds of destinations that
 * they know how to support. There are three different pieces of information
 * that can be used to address to a destination currently, all of which is
 * summarized in the type overlay_point_t. Any combination of these is
 * supported.
 *
 *	OVERLAY_PLUGIN_D_ETHERNET
 *
 *		An Ethernet MAC address is required.
 *
 *	OVERLAY_PLUGIN_D_IP
 *
 *		An IP address is required. All IP addresses used by the overlay
 *		system are transmitted as IPv6 addresses. IPv4 addresses can be
 *		represented by using IPv4-mapped IPv6 addresses.
 *
 *	OVERLAY_PLUGIN_D_PORT
 *
 *		A TCP/UDP port is required.
 *
 * A kernel encapsulation plugin declares which of these that it requires, it's
 * a static set. On the other hand, a userland lookup plugin can be built to
 * support all of these or any combination thereof. It gets passed the required
 * destination type, based on the kernel encapsulation method, and then it makes
 * the determination as to whether or not it supports it. For example, the
 * direct plugin can support either an IP or both an IP and a port, it simply
 * doesn't display the direct/dest_port property in the cases where a port is
 * not required to support this.
 *
 * The user lookup plugins have two different modes of operation which
 * determines how they interact with the broader system and how look ups are
 * performed. These types are:
 *
 *	OVERLAY_TARGET_POINT
 *
 *		A point to point plugin has a single static definition for where
 *		to send all traffic. Every packet in the system always gets sent
 *		to the exact same destination which is programmed into the
 *		kernel when the general device is activated.
 *
 *	OVERLAY_TARGET_DYNAMIC
 *
 *		A dynamic plugin does not have a single static definition.
 *		Instead, for each destination, the kernel makes an asynchronous
 *		request to varpd to determine where the packet should be routed,
 *		and if a specific destination is found, then that destination is
 *		cached in the overlay device's target cache.
 *
 * This distinction, while important for the general overlay device's operation,
 * is not important to the encapsulation plugins. They don't need to know about
 * any of these pieces. It's just a concern for varpd, the userland plugin, and
 * the general overlay scaffolding.
 *
 * When an overlay device is set to OVERLAY_TARGET_POINT, then it does not
 * maintain a target cache, and instead just keeps track of the destination and
 * always sends encapsulated packets to that address. When the target type is of
 * OVERLAY_TARGET_DYNAMIC, then the kernel maintains a cache of all such
 * destinations. These destinations are kept around in an instance of a
 * reference hash that is specific to the given overlay device. Entries in the
 * cache can be invalidated and replaced by varpd and its lookup plugins.
 *
 * ----------------------------------
 * Kernel Components and Architecture
 * ----------------------------------
 *
 * There are multiple pieces inside the kernel that work together, there is the
 * general overlay_dev_t structure, which is the logical GLDv3 device, but it
 * itself has references to things like an instance of an encapsulation plugin,
 * a pointer to a mux and a target cache. It can roughly be summarized in the
 * following image:
 *
 *     +------------------+
 *     | global           |
 *     | overlay list     |
 *     | overlay_dev_list |
 *     +------------------+
 *        |
 *        |  +-----------------------+            +---------------+
 *        +->| GLDv3 Device          |----------->| GLDv3 Device  | -> ...
 *           | overlay_dev_t         |            | overlay_dev_t |
 *           |                       |            +---------------+
 *           |                       |
 *           | mac_handle_t     -----+---> GLDv3 handle to MAC
 *           | datalink_id_t    -----+---> Datalink ID used by DLS
 *           | overlay_dev_flag_t ---+---> Device state
 *           | uint_t           -----+---> Current device MTU
 *           | uint_t           -----+---> In-progress RX operations
 *           | uint_t           -----+---> In-progress TX operations
 *           | char[]           -----+---> FMA degraded message
 *           | void *           -----+---> plugin private data
 *           | overlay_target_t * ---+---------------------+
 *           | overlay_plugin_t * ---+---------+           |
 *           +-----------------------+         |           |
 *                           ^                 |           |
 *   +--------------------+  |                 |           |
 *   | Kernel Socket      |  |                 |           |
 *   | Multiplexor        |  |                 |           |
 *   | overlay_mux_t      |  |                 |           |
 *   |                    |  |                 |           |
 *   | avl_tree_t        -+--+                 |           |
 *   | uint_t            -+--> socket family   |           |
 *   | uint_t            -+--> socket type     |           |
 *   | uint_t            -+--> socket protocol |           |
 *   | ksocket_t         -+--> I/O socket      |           |
 *   | struct sockaddr * -+--> ksocket address |           |
 *   | overlay_plugin_t --+--------+           |           |
 *   +--------------------+        |           |           |
 *                                 |           |           |
 *   +-------------------------+   |           |           |
 *   | Encap Plugin            |<--+-----------+           |
 *   | overlay_plugin_t        |                           |
 *   |                         |                           |
 *   | char *               ---+--> plugin name            |
 *   | overlay_plugin_ops_t * -+--> plugin downcalls       |
 *   | char ** (props)      ---+--> property list          |
 *   | uint_t               ---+--> id length              |
 *   | overlay_plugin_flags_t -+--> plugin flags           |
 *   | overlay_plugin_dest_t --+--> destination type       v
 *   +-------------------------+                    +-------------------------+
 *                                                  |   Target Cache          |
 *                                                  |   overlay_target_t      |
 *                                                  |                         |
 *                                    cache mode <--+- overlay_target_mode_t  |
 *                                     dest type <--+- overlay_plugin_dest_t  |
 *                                   cache flags <--+- overlay_target_flag_t  |
 *                                     varpd id  <--+- uint64_t               |
 *                       outstanding varpd reqs. <--+- uint_t                 |
 *                   OVERLAY_TARGET_POINT state  <--+- overlay_target_point_t |
 *               OVERLAY_TARGET_DYNAMIC state <-+---+- overlay_target_dyn_t   |
 *                                              |   +-------------------------+
 *                      +-----------------------+
 *                      |
 *                      v
 *   +-------------------------------+   +------------------------+
 *   | Target Entry                  |-->| Target Entry           |--> ...
 *   | overlay_target_entry_t        |   | overlay_target_entry_t |
 *   |                               |   +------------------------+
 *   |                               |
 *   | overlay_target_entry_flags_t -+--> Entry flags
 *   | uint8_t[ETHERADDRL]        ---+--> Target MAC address
 *   | overlay_target_point_t     ---+--> Target underlay address
 *   | mblk_t *                   ---+--> outstanding mblk head
 *   | mblk_t *                   ---+--> outstanding mblk tail
 *   | size_t                     ---+--> outstanding mblk size
 *   +-------------------------------+
 *
 * The primary entries that we care about are the overlay_dev_t, which
 * correspond to each overlay device that is created with dladm(8). Globally,
 * these devices are maintained in a simple list_t which is protected with a
 * lock.  Hence, these include important information such as the mac_handle_t
 * and a datalink_id_t which is used to interact with the broader MAC and DLS
 * ecosystem. We also maintain additional information such as the current state,
 * outstanding operations, the mtu, and importantly, the plugin's private data.
 * This is the instance of an encapsulation plugin that gets created as part of
 * creating an overlay device. Another aspect of this is that the overlay_dev_t
 * also includes information with respect to FMA. For more information, see the
 * FMA section.
 *
 * Each overlay_dev_t has a pointer to a plugin, a mux, and a target. The plugin
 * is the encapsulation plugin. This allows the device to make downcalls into it
 * based on doing things like getting and setting properties. Otherwise, the
 * plugin itself is a fairly straightforward entity. They are maintained in an
 * (not pictured above) list. The plugins themselves mostly maintain things like
 * the static list of properties, what kind of destination they require, and the
 * operations vector. A given module may contain more if necessary.
 *
 * The next piece of the puzzle is the mux, or a multiplexor. The mux itself
 * maintains a ksocket and it is through the mux that we send and receive
 * message blocks. The mux represents a socket type and address, as well as a
 * plugin. Multiple overlay_dev_t devices may then share the same mux. For
 * example, consider the case where you have different instances of vxlan all on
 * the same underlay network. These would all logically share the same IP
 * address and port that packets are sent and received on; however, what differs
 * is the decapuslation ID.
 *
 * Each mux maintains a ksocket_t which is similar to a socket(3SOCKET). Unlike
 * a socket, we enable a direct callback on the ksocket. This means that
 * whenever a message block chain is received, rather than sitting there and
 * getting a callback in a context and kicking that back out to a taskq. Instead
 * data comes into the callback function overlay_mux_recv().
 *
 * The mux is given encapsulated packets (via overlay_m_tx, the GLDv3 tx
 * function) to transmit. It receives encapsulated packets, decapsulates them to
 * determine the overlay identifier, looks up the given device that matches that
 * identifier, and then causes the broader MAC world to receive the packet with
 * a call to mac_rx().
 *
 * Today, we don't do too much that's special with the ksocket; however, as
 * hardware is gaining understanding for these encapsulation protocols, we'll
 * probably want to think of better ways to get those capabilities passed down
 * and potentially better ways to program receive filters so they get directly
 * to us. Though, that's all fantasy future land.
 *
 * The next part of the puzzle is the target cache. The purpose of the target
 * cache is to cache where we should send a packet on the underlay network,
 * given its mac address. The target cache operates in two modes depending on
 * whether the lookup module was declared to OVERLAY_TARGET_POINT or
 * OVERLAY_TARGET_DYANMIC.
 *
 * In the case where the target cache has been programmed to be
 * OVERLAY_TARGET_POINT, then we only maintain a single overlay_target_point_t
 * which has the destination that we send everything, no matter the destination
 * mac address.
 *
 * On the other hand, when we have an instance of OVERLAY_TARGET_DYNAMIC, things
 * are much more interesting and as a result, more complicated. We primarily
 * store lists of overlay_target_entry_t's which are stored in both an avl tree
 * and a refhash_t. The primary look up path uses the refhash_t and the avl tree
 * is only used for a few of the target ioctls used to dump data such that we
 * can get a consistent iteration order for things like dladm show-overlay -t.
 * The key that we use for the reference hashtable is based on the mac address
 * in the cache and currently we just do a simple CRC32 to transform it into a
 * hash.
 *
 * Each entry maintains a set of flags to indicate the current status of the
 * request. The flags may indicate one of three states: that current cache entry
 * is valid, that the current cache entry has been directed to drop all output,
 * and that the current cache entry is invalid and may be being looked up. In
 * the case where it's valid, we just take the destination address and run with
 * it.
 *
 * If it's invalid and a lookup has not been made, then we start the process
 * that prepares a query that will make its way up to varpd. The cache entry
 * entry maintains a message block chain of outstanding message blocks and a
 * size. These lists are populated only when we don't know the answer as to
 * where should these be sent. The size entry is used to cap the amount of
 * outstanding data that we don't know the answer to. If we exceed a cap on the
 * amount of outstanding data (currently 1 Mb), then we'll drop any additional
 * packets. Once we get an answer indicating a valid destination, we transmit
 * any outstanding data to that place. For the full story on how we look that up
 * will be discussed in the section on the Target Cache Lifecycle.
 *
 * ------------------------
 * FMA and Degraded Devices
 * ------------------------
 *
 * Every kernel overlay device keeps track of its FMA state. Today in FMA we
 * cannot represent partitions between resources nor can we represent that a
 * given minor node of a pseudo device has failed -- if we degrade the overlay
 * device, then the entire dev_info_t is degraded. However, we still want to be
 * able to indicate to administrators that things may go wrong.
 *
 * To this end, we've added a notion of a degraded state to every overlay
 * device. This state is primarily dictated by userland and it can happen for
 * various reasons. Generally, because a userland lookup plugin has been
 * partitioned, or something has gone wrong such that there is no longer any
 * userland lookup module for a device, then we'll mark it degraded.
 *
 * As long as any of our minor instances is degraded, then we'll fire off the
 * FMA event to note that. Once the last degraded instance is no longer
 * degraded, then we'll end up telling FMA that we're all clean.
 *
 * To help administrators get a better sense of which of the various minor
 * devices is wrong, we store the odd_fmamsg[] character array. This character
 * array can be fetched with doing a dladm show-overlay -f.
 *
 * Note, that it's important that we do not update the link status of the
 * devices. We want to remain up as much as possible. By changing the link in a
 * degraded state, this may end up making things worse. We may still actually
 * have information in the target cache and if we mark the link down, that'll
 * result in not being able to use it. The reason being that this'll mark all
 * the downstream VNICs down which will go to IP and from there we end up
 * dealing with sadness.
 *
 * -----------------------
 * Target Cache Life Cycle
 * -----------------------
 *
 * This section only applies when we have a lookup plugin of
 * OVERLAY_TARGET_DYNAMIC. None of this applies to those of type
 * OVERLAY_TARGET_POINT.
 *
 * While we got into the target cache in the general architecture section, it's
 * worth going into more details as to how this actually works and showing some
 * examples and state machines. Recall that a target cache entry basically has
 * the following state transition diagram:
 *
 * Initial state
 *    . . .           . . . first access       . . . varpd lookup enqueued
 *        .           .                        .
 *        .           .                        .
 *     +-------+      .     +----------+       .
 *     |  No   |------*---->| Invalid  |-------*----+
 *     | Entry |            |  Entry   |            |
 *     +-------+            +----------+            |
 *                 varpd      ^      ^   varpd      |
 *                 invalidate |      |   drop       |
 *                      . . . *      * . .          v
 *          +-------+         |      |         +---------+
 *          | Entry |--->-----+      +----<----| Entry   |
 *          | Valid |<----------*---------<----| Pending |->-+     varpd
 *          +-------+           .              +---------+   * . . drop, but
 *                              . varpd                ^     |     other queued
 *                              . success              |     |     entries
 *                                                     +-----+
 *
 * When the table is first created, it is empty. As we attempt to lookup entries
 * and we find there is no entry at all, we'll create a new table entry for it.
 * At that point the entry is technically in an invalid state, that means that
 * we have no valid data from varpd. In that case, we'll go ahead and queue the
 * packet into the entry's pending chain, and queue a varpd lookup, setting the
 * OVERLAY_ENTRY_F_PENDING flag in the progress.
 *
 * If additional mblk_t's come in for this entry, we end up appending them to
 * the tail of the chain, if and only if, we don't exceed the threshold for the
 * amount of space they can take up. An entry remains pending until we get a
 * varpd reply. If varpd replies with a valid results, we move to the valid
 * entry state, and remove the OVERLAY_ENTRY_F_PENDING flag and set it with one
 * of OVERLAY_ENTRY_F_VALID or OVERLAY_ENTRY_F_DROP as appropriate.
 *
 * Once an entry is valid, it stays valid until user land tells us to invalidate
 * it with an ioctl or replace it, OVERLAY_TARG_CACHE_REMOE and
 * OVERLAY_TARG_CACHE_SET respectively.
 *
 * If the lookup fails with a call to drop the packet, then the next state is
 * determined by the state of the queue. If the set of outstanding entries is
 * empty, then we just transition back to the invalid state. If instead, the
 * set of outstanding entries is not empty, then we'll queue another entry and
 * stay in the same state, repeating this until the number of requests is
 * drained.
 *
 * The following images describes the flow of a given lookup and where the
 * overlay_target_entry_t is at any given time.
 *
 *     +-------------------+
 *     | Invalid Entry     |		An entry starts off as an invalid entry
 *     | de:ad:be:ef:00:00 |		and only exists in the target cache.
 *     +-------------------+
 *
 *	~~~~
 *
 *     +---------------------+
 *     | Global list_t       |		A mblk_t comes in for an entry. We
 *     | overlay_target_list |		append it to the overlay_target_list.
 *     +---------------------+
 *                   |
 *                   v
 *             +-------------------+      +-------------------+
 *             | Pending Entry     |----->| Pending Entry     |--->...
 *             | 42:5e:1a:10:d6:2d |      | de:ad:be:ef:00:00 |
 *             +-------------------+      +-------------------+
 *
 *	~~~~
 *
 *     +--------------------------+
 *     | /dev/overlay minor state |	User land said that it would look up an
 *     | overlay_target_hdl_t     |	entry for us. We remove it from the
 *     +--------------------------+	global list and add it to the handle's
 *                  |			outstanding list.
 *                  |
 *                  v
 *            +-------------------+      +-------------------+
 *            | Pending Entry     |----->| Pending Entry     |
 *            | 90:b8:d0:79:02:dd |      | de:ad:be:ef:00:00 |
 *            +-------------------+      +-------------------+
 *
 *	~~~~
 *
 *     +-------------------+
 *     | Valid Entry       |		varpd returned an answer with
 *     | de:ad:be:ef:00:00 |		OVERLAY_IOC_RESPOND and the target cache
 *     | 10.169.23.42:4789 |		entry is now populated with a
 *     +-------------------+		destination and marked as valid
 *
 *
 * The lookup mechanism is performed via a series of operations on the character
 * pseudo-device /dev/overlay. The only thing that uses this device is the
 * userland daemon varpd. /dev/overlay is a cloneable device, each open of it
 * granting a new minor number which maintains its own state. We maintain this
 * state so that way if an outstanding lookup was queued to something that
 * crashed or closed its handle without responding, we can know about this and
 * thus handle it appropriately.
 *
 * When a lookup is first created it's added to our global list of outstanding
 * lookups. To service requests, userland is required to perform an ioctl to ask
 * for a request. We will block it in the kernel a set amount of time waiting
 * for a request. When we give a request to a given minor instance of the
 * device, we remove it from the global list and append the request to the
 * device's list of outstanding entries, for the reasons we discussed above.
 * When a lookup comes in, we give user land a smaller amount of information
 * specific to that packet, the overlay_targ_lookup_t. It includes a request id
 * to identify this, and then the overlay id, the varpd id, the header and
 * packet size, the source and destination mac address, the SAP, and any
 * potential VLAN header.
 *
 * At that point, it stays in that outstanding list until one of two ioctls are
 * returned: OVERLAY_TARG_RESPOND or OVERLAY_TARG_DROP. During this time,
 * userland may also perform other operations. For example, it may use
 * OVERLAY_TARG_PKT to get a copy of this packet so it can perform more in-depth
 * analysis of what to do beyond what we gave it initially. This is useful for
 * providing proxy arp and the like. Finally, there are two other ioctls that
 * varpd can then do. The first is OVERLAY_TARG_INJECT which injects the
 * non-jumbo frame packet up into that mac device and OVERLAY_TARG_RESEND which
 * causes us to encapsulate and send out the packet they've given us.
 *
 *
 * Finally, through the target cache, several ioctls are provided to allow for
 * interrogation and management of the cache. They allow for individual entries
 * to be retrieved, set, or have the entire table flushed. For the full set of
 * ioctls here and what they do, take a look at uts/common/sys/overlay_target.h.
 *
 * ------------------
 * Sample Packet Flow
 * ------------------
 *
 * There's a lot of pieces here, hopefully an example of how this all fits
 * together will help clarify and elucidate what's going on. We're going to
 * first track an outgoing packet, eg. one that is sent from an IP interface on
 * a VNIC on top of an overlay device, and then we'll look at what it means to
 * respond to that.
 *
 *
 *    +----------------+        +--------------+            +------------------+
 *    | IP/DLS send    |------->| MAC sends it |----------->| mblk_t reaches   |
 *    | packet to MAC  |        | to the GLDv3 |            | overlay GLDv3 tx |
 *    +----------------+        | VNIC device  |            | overlay_m_tx()   |
 *                              +--------------+            +------------------+
 *                                                                   |
 *                             . lookup              . cache         |
 *                             . drop                . miss          v
 *            +---------+      .       +--------+    .      +------------------+
 *            | freemsg |<-----*-------| varpd  |<---*------| Lookup each mblk |
 *            | mblk_t  |              | lookup |           | in the target    |
 *            +---------+              | queued |           | cache            |
 *                ^                    +--------+           +------------------+
 *      on send   |                        |                         |     cache
 *      error . . *                        *. . lookup               * . . hit
 *                |                        |    success              v
 *                |                        |                +------------------+
 *    +-----------------+                  +--------------->| call plugin      |
 *    | Send out        |                                   | ovpo_encap() to  |
 *    | overlay_mux_t's |<----------------------------------| get encap mblk_t |
 *    | ksocket         |                                   +------------------+
 *    +-----------------+
 *
 * The receive end point looks a little different and looks more like:
 *
 *  +------------------+     +----------------+    +-----------+
 *  | mblk_t comes off |---->| enter netstack |--->| delivered |---+
 *  | the physical     |     | IP stack       |    |     to    |   * . . direct
 *  | device           |     +----------------+    |  ksocket  |   |   callback
 *  +------------------+                           +-----------+   |
 *                       . overlay id                              |
 *                       . not found                               v
 *       +-----------+   .      +-----------------+       +--------------------+
 *       | freemsg   |<--*------| call plugin     |<------| overlay_mux_recv() |
 *       | mblk_t    |          | ovpo_decap() to |       +--------------------+
 *       +-----------+          | decap mblk_t    |
 *                              +-----------------+
 *                                     |
 *                                     * . . overlay id
 *                                     v     found
 *                                 +--------+      +----------------+
 *                                 | adjust |----->| call mac_rx    |
 *                                 | mblk_t |      | on original    |
 *                                 +--------+      | decaped packet |
 *                                                 +----------------+
 *
 * ------------------
 * Netstack Awareness
 * ------------------
 *
 * In the above image we note that this enters a netstack. Today the only
 * netstack that can be is the global zone as the overlay driver itself is not
 * exactly netstack aware. What this really means is that varpd cannot run in a
 * non-global zone and an overlay device cannot belong to a non-global zone.
 * Non-global zones can still have a VNIC assigned to them that's been created
 * over the overlay device the same way they would if it had been created over
 * an etherstub or a physical device.
 *
 * The majority of the work to make it netstack aware is straightforward and the
 * biggest thing is to create a netstack module that allows us to hook into
 * netstack (and thus zone) creation and destruction.  From there, we need to
 * amend the target cache lookup routines that we discussed earlier to not have
 * a global outstanding list and a global list of handles, but rather, one per
 * netstack.
 *
 * For the mux, we'll need to open the ksocket in the context of the zone, we
 * can likely do this with a properly composed credential, but we'll need to do
 * some more work on that path. Finally, we'll want to make sure the dld ioctls
 * are aware of the zoneid of the caller and we use that appropriately and store
 * it in the overlay_dev_t.
 *
 * -----------
 * GLDv3 Notes
 * -----------
 *
 * The overlay driver implements a GLDv3 device. Parts of GLDv3 are more
 * relevant and other parts are much less relevant for us. For example, the
 * GLDv3 is used to toggle the device being put into and out of promiscuous
 * mode, to program MAC addresses for unicast and multicast hardware filters.
 * Today, an overlay device doesn't have a notion of promiscuous mode nor does
 * it have a notion of unicast and multicast addresses programmed into the
 * device. Instead, for the purposes of the hardware filter, we don't do
 * anything and just always accept new addresses being added and removed.
 *
 * If the GLDv3 start function has not been called, then we will not use this
 * device for I/O purposes. Any calls to transmit or receive should be dropped,
 * though the GLDv3 guarantees us that transmit will not be called without
 * calling start. Similarly, once stop is called, then no packets can be dealt
 * with.
 *
 * Today we don't support the stat interfaces, though there's no good reason
 * that we shouldn't assemble some of the stats based on what we have in the
 * future.
 *
 * When it comes to link properties, many of the traditional link properties do
 * not apply and many others MAC handles for us. For example, we don't need to
 * implement anything for overlay_m_getprop() to deal with returning the MTU, as
 * MAC never calls into us for that. As such, there isn't much of anything to
 * support in terms of properties.
 *
 * Today, we don't support any notion of hardware capabilities. However, if
 * future NIC hardware or other changes to the system cause it to make sense for
 * us to emulate logical groups, then we should do that. However, we still do
 * implement a capab function so that we can identify ourselves as an overlay
 * device to the broader MAC framework. This is done mostly so that a device
 * created on top of us can have fanout rings as we don't try to lie about a
 * speed for our device.
 *
 * The other question is what should be done for a device's MTU and margin. We
 * set our minimum supported MTU to be the minimum value that an IP network may
 * be set to 576 -- which mimics what an etherstub does. On the flip side, we
 * have our upper bound set to 8900. This value comes from the fact that a lot
 * of jumbo networks use their maximum as 9000. As such, we want to reserve 100
 * bytes, which isn't exactly the most accurate number, but it'll be good enough
 * for now. Because of that, our default MTU off of these devices is 1400, as
 * the default MTU for everything is usually 1500 or whatever the underlying
 * device is at; however, this is a bit simpler than asking the netstack what
 * are all the IP interfaces at. It also calls into question how PMTU and PMTU
 * discovery should work here. The challenge, especially for
 * OVERLAY_TARG_DYNAMIC is that the MTU to any of the places will vary and it's
 * not clear that if you have a single bad entry that the overall MTU should be
 * lowered. Instead, we should figure out a better way of determining these
 * kinds of PMTU errors and appropriately alerting the administrator via FMA.
 *
 * Regarding margin, we allow a margin of up to VLAN_TAGSZ depending on whether
 * or not the underlying encapsulation device supports VLAN tags. If it does,
 * then we'll set the margin to allow for it, otherwise, we will not.
 */

#include <sys/conf.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/policy.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/ddifm.h>

#include <sys/dls.h>
#include <sys/dld_ioc.h>
#include <sys/mac_provider.h>
#include <sys/mac_client_priv.h>
#include <sys/mac_ether.h>
#include <sys/vlan.h>

#include <sys/overlay_impl.h>

dev_info_t *overlay_dip;
static kmutex_t overlay_dev_lock;
static list_t overlay_dev_list;
static uint8_t overlay_macaddr[ETHERADDRL] =
	{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

typedef enum overlay_dev_prop {
	OVERLAY_DEV_P_MTU = 0,
	OVERLAY_DEV_P_VNETID,
	OVERLAY_DEV_P_ENCAP,
	OVERLAY_DEV_P_VARPDID
} overlay_dev_prop_t;

#define	OVERLAY_DEV_NPROPS	4
static const char *overlay_dev_props[] = {
	"mtu",
	"vnetid",
	"encap",
	"varpd/id"
};

#define	OVERLAY_MTU_MIN	576
#define	OVERLAY_MTU_DEF	1400
#define	OVERLAY_MTU_MAX	8900

overlay_dev_t *
overlay_hold_by_dlid(datalink_id_t id)
{
	overlay_dev_t *o;

	mutex_enter(&overlay_dev_lock);
	for (o = list_head(&overlay_dev_list); o != NULL;
	    o = list_next(&overlay_dev_list, o)) {
		if (id == o->odd_linkid) {
			mutex_enter(&o->odd_lock);
			o->odd_ref++;
			mutex_exit(&o->odd_lock);
			mutex_exit(&overlay_dev_lock);
			return (o);
		}
	}

	mutex_exit(&overlay_dev_lock);
	return (NULL);
}

void
overlay_hold_rele(overlay_dev_t *odd)
{
	mutex_enter(&odd->odd_lock);
	ASSERT(odd->odd_ref > 0);
	odd->odd_ref--;
	mutex_exit(&odd->odd_lock);
}

void
overlay_io_start(overlay_dev_t *odd, overlay_dev_flag_t flag)
{
	ASSERT(flag == OVERLAY_F_IN_RX || flag == OVERLAY_F_IN_TX);
	ASSERT(MUTEX_HELD(&odd->odd_lock));

	if (flag & OVERLAY_F_IN_RX)
		odd->odd_rxcount++;
	if (flag & OVERLAY_F_IN_TX)
		odd->odd_txcount++;
	odd->odd_flags |= flag;
}

void
overlay_io_done(overlay_dev_t *odd, overlay_dev_flag_t flag)
{
	boolean_t signal = B_FALSE;

	ASSERT(flag == OVERLAY_F_IN_RX || flag == OVERLAY_F_IN_TX);
	ASSERT(MUTEX_HELD(&odd->odd_lock));

	if (flag & OVERLAY_F_IN_RX) {
		ASSERT(odd->odd_rxcount > 0);
		odd->odd_rxcount--;
		if (odd->odd_rxcount == 0) {
			signal = B_TRUE;
			odd->odd_flags &= ~OVERLAY_F_IN_RX;
		}
	}
	if (flag & OVERLAY_F_IN_TX) {
		ASSERT(odd->odd_txcount > 0);
		odd->odd_txcount--;
		if (odd->odd_txcount == 0) {
			signal = B_TRUE;
			odd->odd_flags &= ~OVERLAY_F_IN_TX;
		}
	}

	if (signal == B_TRUE)
		cv_broadcast(&odd->odd_iowait);
}

static void
overlay_io_wait(overlay_dev_t *odd, overlay_dev_flag_t flag)
{
	ASSERT((flag & ~OVERLAY_F_IOMASK) == 0);
	ASSERT(MUTEX_HELD(&odd->odd_lock));

	while (odd->odd_flags & flag) {
		cv_wait(&odd->odd_iowait, &odd->odd_lock);
	}
}

void
overlay_dev_iter(overlay_dev_iter_f func, void *arg)
{
	overlay_dev_t *odd;

	mutex_enter(&overlay_dev_lock);
	for (odd = list_head(&overlay_dev_list); odd != NULL;
	    odd = list_next(&overlay_dev_list, odd)) {
		if (func(odd, arg) != 0) {
			mutex_exit(&overlay_dev_lock);
			return;
		}
	}
	mutex_exit(&overlay_dev_lock);
}

/* ARGSUSED */
static int
overlay_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	return (ENOTSUP);
}

static int
overlay_m_start(void *arg)
{
	overlay_dev_t *odd = arg;
	overlay_mux_t *mux;
	int ret, domain, family, prot;
	struct sockaddr_storage storage;
	socklen_t slen;

	mutex_enter(&odd->odd_lock);
	if ((odd->odd_flags & OVERLAY_F_ACTIVATED) == 0) {
		mutex_exit(&odd->odd_lock);
		return (EAGAIN);
	}
	mutex_exit(&odd->odd_lock);

	ret = odd->odd_plugin->ovp_ops->ovpo_socket(odd->odd_pvoid, &domain,
	    &family, &prot, (struct sockaddr *)&storage, &slen);
	if (ret != 0)
		return (ret);

	mux = overlay_mux_open(odd->odd_plugin, domain, family, prot,
	    (struct sockaddr *)&storage, slen, &ret);
	if (mux == NULL)
		return (ret);

	overlay_mux_add_dev(mux, odd);
	odd->odd_mux = mux;
	mutex_enter(&odd->odd_lock);
	ASSERT(!(odd->odd_flags & OVERLAY_F_IN_MUX));
	odd->odd_flags |= OVERLAY_F_IN_MUX;
	mutex_exit(&odd->odd_lock);

	return (0);
}

static void
overlay_m_stop(void *arg)
{
	overlay_dev_t *odd = arg;

	/*
	 * The MAC Perimeter is held here, so we don't have to worry about
	 * synchronizing this with respect to metadata operations.
	 */
	mutex_enter(&odd->odd_lock);
	VERIFY(odd->odd_flags & OVERLAY_F_IN_MUX);
	VERIFY(!(odd->odd_flags & OVERLAY_F_MDDROP));
	odd->odd_flags |= OVERLAY_F_MDDROP;
	overlay_io_wait(odd, OVERLAY_F_IOMASK);
	mutex_exit(&odd->odd_lock);

	overlay_mux_remove_dev(odd->odd_mux, odd);
	overlay_mux_close(odd->odd_mux);
	odd->odd_mux = NULL;

	mutex_enter(&odd->odd_lock);
	odd->odd_flags &= ~OVERLAY_F_IN_MUX;
	odd->odd_flags &= ~OVERLAY_F_MDDROP;
	VERIFY((odd->odd_flags & OVERLAY_F_STOPMASK) == 0);
	mutex_exit(&odd->odd_lock);
}

/*
 * For more info on this, see the big theory statement.
 */
/* ARGSUSED */
static int
overlay_m_promisc(void *arg, boolean_t on)
{
	return (0);
}

/*
 * For more info on this, see the big theory statement.
 */
/* ARGSUSED */
static int
overlay_m_multicast(void *arg, boolean_t add, const uint8_t *addrp)
{
	return (0);
}

/*
 * For more info on this, see the big theory statement.
 */
/* ARGSUSED */
static int
overlay_m_unicast(void *arg, const uint8_t *macaddr)
{
	return (0);
}

mblk_t *
overlay_m_tx(void *arg, mblk_t *mp_chain)
{
	overlay_dev_t *odd = arg;
	mblk_t *mp, *ep;
	int ret;
	ovep_encap_info_t einfo;
	struct msghdr hdr;

	mutex_enter(&odd->odd_lock);
	if ((odd->odd_flags & OVERLAY_F_MDDROP) ||
	    !(odd->odd_flags & OVERLAY_F_IN_MUX)) {
		mutex_exit(&odd->odd_lock);
		freemsgchain(mp_chain);
		return (NULL);
	}
	overlay_io_start(odd, OVERLAY_F_IN_TX);
	mutex_exit(&odd->odd_lock);

	bzero(&hdr, sizeof (struct msghdr));

	bzero(&einfo, sizeof (ovep_encap_info_t));
	einfo.ovdi_id = odd->odd_vid;
	mp = mp_chain;
	while (mp != NULL) {
		socklen_t slen;
		struct sockaddr_storage storage;

		mp_chain = mp->b_next;
		mp->b_next = NULL;
		ep = NULL;

		ret = overlay_target_lookup(odd, mp,
		    (struct sockaddr *)&storage, &slen);
		if (ret != OVERLAY_TARGET_OK) {
			if (ret == OVERLAY_TARGET_DROP)
				freemsg(mp);
			mp = mp_chain;
			continue;
		}

		hdr.msg_name = &storage;
		hdr.msg_namelen = slen;

		ret = odd->odd_plugin->ovp_ops->ovpo_encap(odd->odd_mh, mp,
		    &einfo, &ep);
		if (ret != 0 || ep == NULL) {
			freemsg(mp);
			goto out;
		}

		ASSERT(ep->b_cont == mp || ep == mp);
		ret = overlay_mux_tx(odd->odd_mux, &hdr, ep);
		if (ret != 0)
			goto out;

		mp = mp_chain;
	}

out:
	mutex_enter(&odd->odd_lock);
	overlay_io_done(odd, OVERLAY_F_IN_TX);
	mutex_exit(&odd->odd_lock);
	return (mp_chain);
}

/* ARGSUSED */
static void
overlay_m_ioctl(void *arg, queue_t *q, mblk_t *mp)
{
	miocnak(q, mp, 0, ENOTSUP);
}

/* ARGSUSED */
static boolean_t
overlay_m_getcapab(void *arg, mac_capab_t cap, void *cap_data)
{
	/*
	 * Tell MAC we're an overlay.
	 */
	if (cap == MAC_CAPAB_OVERLAY)
		return (B_TRUE);
	return (B_FALSE);
}

/* ARGSUSED */
static int
overlay_m_setprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, const void *pr_val)
{
	uint32_t mtu, old;
	int err;
	overlay_dev_t *odd = arg;

	if (pr_num != MAC_PROP_MTU)
		return (ENOTSUP);

	bcopy(pr_val, &mtu, sizeof (mtu));
	if (mtu < OVERLAY_MTU_MIN || mtu > OVERLAY_MTU_MAX)
		return (EINVAL);

	mutex_enter(&odd->odd_lock);
	old = odd->odd_mtu;
	odd->odd_mtu = mtu;
	err = mac_maxsdu_update(odd->odd_mh, mtu);
	if (err != 0)
		odd->odd_mtu = old;
	mutex_exit(&odd->odd_lock);

	return (err);
}

/* ARGSUSED */
static int
overlay_m_getprop(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    uint_t pr_valsize, void *pr_val)
{
	return (ENOTSUP);
}

/* ARGSUSED */
static void
overlay_m_propinfo(void *arg, const char *pr_name, mac_prop_id_t pr_num,
    mac_prop_info_handle_t prh)
{
	if (pr_num != MAC_PROP_MTU)
		return;

	mac_prop_info_set_default_uint32(prh, OVERLAY_MTU_DEF);
	mac_prop_info_set_range_uint32(prh, OVERLAY_MTU_MIN, OVERLAY_MTU_MAX);
}

static mac_callbacks_t overlay_m_callbacks = {
	.mc_callbacks = (MC_IOCTL | MC_GETCAPAB | MC_SETPROP | MC_GETPROP |
	    MC_PROPINFO),
	.mc_getstat = overlay_m_stat,
	.mc_start = overlay_m_start,
	.mc_stop = overlay_m_stop,
	.mc_setpromisc = overlay_m_promisc,
	.mc_multicst = overlay_m_multicast,
	.mc_unicst = overlay_m_unicast,
	.mc_tx = overlay_m_tx,
	.mc_ioctl = overlay_m_ioctl,
	.mc_getcapab = overlay_m_getcapab,
	.mc_getprop = overlay_m_getprop,
	.mc_setprop = overlay_m_setprop,
	.mc_propinfo = overlay_m_propinfo
};

static boolean_t
overlay_valid_name(const char *name, size_t buflen)
{
	size_t actlen;
	int err, i;

	for (i = 0; i < buflen; i++) {
		if (name[i] == '\0')
			break;
	}

	if (i == 0 || i == buflen)
		return (B_FALSE);
	actlen = i;
	if (strchr(name, '/') != NULL)
		return (B_FALSE);
	if (u8_validate((char *)name, actlen, NULL,
	    U8_VALIDATE_ENTIRE, &err) < 0)
		return (B_FALSE);
	return (B_TRUE);
}

/* ARGSUSED */
static int
overlay_i_create(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	int err;
	uint64_t maxid;
	overlay_dev_t *odd, *o;
	mac_register_t *mac;
	overlay_ioc_create_t *oicp = karg;

	if (overlay_valid_name(oicp->oic_encap, MAXLINKNAMELEN) == B_FALSE)
		return (EINVAL);

	odd = kmem_zalloc(sizeof (overlay_dev_t), KM_SLEEP);
	odd->odd_linkid = oicp->oic_linkid;
	odd->odd_plugin = overlay_plugin_lookup(oicp->oic_encap);
	if (odd->odd_plugin == NULL) {
		kmem_free(odd, sizeof (overlay_dev_t));
		return (ENOENT);
	}
	err = odd->odd_plugin->ovp_ops->ovpo_init((overlay_handle_t)odd,
	    &odd->odd_pvoid);
	if (err != 0) {
		odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (EINVAL);
	}

	/*
	 * Make sure that our virtual network id is valid for the given plugin
	 * that we're working with.
	 */
	ASSERT(odd->odd_plugin->ovp_id_size <= 8);
	maxid = UINT64_MAX;
	if (odd->odd_plugin->ovp_id_size != 8)
		maxid = (1ULL << (odd->odd_plugin->ovp_id_size * 8)) - 1ULL;
	if (oicp->oic_vnetid > maxid) {
		odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (EINVAL);
	}
	odd->odd_vid = oicp->oic_vnetid;

	mac = mac_alloc(MAC_VERSION);
	if (mac == NULL) {
		mutex_exit(&overlay_dev_lock);
		odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (EINVAL);
	}

	mac->m_type_ident = MAC_PLUGIN_IDENT_ETHER;
	mac->m_driver = odd;
	mac->m_dip = overlay_dip;
	mac->m_dst_addr = NULL;
	mac->m_callbacks = &overlay_m_callbacks;
	mac->m_pdata = NULL;
	mac->m_pdata_size = 0;

	mac->m_priv_props = NULL;

	/* Let mac handle this itself. */
	mac->m_instance = (uint_t)-1;

	/*
	 * There is no real source address that should be used here, but saying
	 * that we're not ethernet is going to cause its own problems. At the
	 * end of the say, this is fine.
	 */
	mac->m_src_addr = overlay_macaddr;

	/*
	 * Start with the default MTU as the max SDU. If the MTU is changed, the
	 * SDU will be changed to reflect that.
	 */
	mac->m_min_sdu = 1;
	mac->m_max_sdu = OVERLAY_MTU_DEF;
	mac->m_multicast_sdu = 0;

	/*
	 * The underlying device doesn't matter, instead this comes from the
	 * encapsulation protocol and whether or not they allow VLAN tags.
	 */
	if (odd->odd_plugin->ovp_flags & OVEP_F_VLAN_TAG) {
		mac->m_margin = VLAN_TAGSZ;
	} else {
		mac->m_margin = 0;
	}

	/*
	 * Today, we have no MAC virtualization, it may make sense in the future
	 * to go ahead and emulate some subset of this, but it doesn't today.
	 */
	mac->m_v12n = MAC_VIRT_NONE;

	mutex_enter(&overlay_dev_lock);
	for (o = list_head(&overlay_dev_list); o != NULL;
	    o = list_next(&overlay_dev_list, o)) {
		if (o->odd_linkid == oicp->oic_linkid) {
			mutex_exit(&overlay_dev_lock);
			odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
			overlay_plugin_rele(odd->odd_plugin);
			kmem_free(odd, sizeof (overlay_dev_t));
			return (EEXIST);
		}

		if (o->odd_vid == oicp->oic_vnetid &&
		    o->odd_plugin == odd->odd_plugin) {
			mutex_exit(&overlay_dev_lock);
			odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
			overlay_plugin_rele(odd->odd_plugin);
			kmem_free(odd, sizeof (overlay_dev_t));
			return (EEXIST);
		}
	}

	err = mac_register(mac, &odd->odd_mh);
	mac_free(mac);
	if (err != 0) {
		mutex_exit(&overlay_dev_lock);
		odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (err);
	}

	err = dls_devnet_create(odd->odd_mh, odd->odd_linkid,
	    crgetzoneid(cred));
	if (err != 0) {
		mutex_exit(&overlay_dev_lock);
		(void) mac_unregister(odd->odd_mh);
		odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
		overlay_plugin_rele(odd->odd_plugin);
		kmem_free(odd, sizeof (overlay_dev_t));
		return (err);
	}

	mutex_init(&odd->odd_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&odd->odd_iowait, NULL, CV_DRIVER, NULL);
	odd->odd_ref = 0;
	odd->odd_flags = 0;
	list_insert_tail(&overlay_dev_list, odd);
	mutex_exit(&overlay_dev_lock);

	return (0);
}

/* ARGSUSED */
static int
overlay_i_activate(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	int i, ret;
	overlay_dev_t *odd;
	mac_perim_handle_t mph;
	overlay_ioc_activate_t *oiap = karg;
	overlay_ioc_propinfo_t *infop;
	overlay_ioc_prop_t *oip;
	overlay_prop_handle_t phdl;

	odd = overlay_hold_by_dlid(oiap->oia_linkid);
	if (odd == NULL)
		return (ENOENT);

	infop = kmem_alloc(sizeof (overlay_ioc_propinfo_t), KM_SLEEP);
	oip = kmem_alloc(sizeof (overlay_ioc_prop_t), KM_SLEEP);
	phdl = (overlay_prop_handle_t)infop;

	mac_perim_enter_by_mh(odd->odd_mh, &mph);
	mutex_enter(&odd->odd_lock);
	if (odd->odd_flags & OVERLAY_F_ACTIVATED) {
		mutex_exit(&odd->odd_lock);
		mac_perim_exit(mph);
		overlay_hold_rele(odd);
		kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
		kmem_free(oip, sizeof (overlay_ioc_prop_t));
		return (EEXIST);
	}
	mutex_exit(&odd->odd_lock);

	for (i = 0; i < odd->odd_plugin->ovp_nprops; i++) {
		const char *pname = odd->odd_plugin->ovp_props[i];
		bzero(infop, sizeof (overlay_ioc_propinfo_t));
		overlay_prop_init(phdl);
		ret = odd->odd_plugin->ovp_ops->ovpo_propinfo(pname, phdl);
		if (ret != 0) {
			mac_perim_exit(mph);
			overlay_hold_rele(odd);
			kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
			kmem_free(oip, sizeof (overlay_ioc_prop_t));
			return (ret);
		}

		if ((infop->oipi_prot & OVERLAY_PROP_PERM_REQ) == 0)
			continue;
		bzero(oip, sizeof (overlay_ioc_prop_t));
		oip->oip_size = sizeof (oip->oip_value);
		ret = odd->odd_plugin->ovp_ops->ovpo_getprop(odd->odd_pvoid,
		    pname, oip->oip_value, &oip->oip_size);
		if (ret != 0) {
			mac_perim_exit(mph);
			overlay_hold_rele(odd);
			kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
			kmem_free(oip, sizeof (overlay_ioc_prop_t));
			return (ret);
		}
		if (oip->oip_size == 0) {
			mac_perim_exit(mph);
			overlay_hold_rele(odd);
			kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
			kmem_free(oip, sizeof (overlay_ioc_prop_t));
			return (EINVAL);
		}
	}

	mutex_enter(&odd->odd_lock);
	if ((odd->odd_flags & OVERLAY_F_VARPD) == 0) {
		mutex_exit(&odd->odd_lock);
		mac_perim_exit(mph);
		overlay_hold_rele(odd);
		kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
		kmem_free(oip, sizeof (overlay_ioc_prop_t));
		return (ENXIO);
	}

	ASSERT((odd->odd_flags & OVERLAY_F_ACTIVATED) == 0);
	odd->odd_flags |= OVERLAY_F_ACTIVATED;

	/*
	 * Now that we've activated ourselves, we should indicate to the world
	 * that we're up. Note that we may not be able to perform lookups at
	 * this time, but our notion of being 'up' isn't dependent on that
	 * ability.
	 */
	mac_link_update(odd->odd_mh, LINK_STATE_UP);
	mutex_exit(&odd->odd_lock);

	mac_perim_exit(mph);
	overlay_hold_rele(odd);
	kmem_free(infop, sizeof (overlay_ioc_propinfo_t));
	kmem_free(oip, sizeof (overlay_ioc_prop_t));

	return (0);
}

/* ARGSUSED */
static int
overlay_i_delete(void *karg, intptr_t arg, int mode, cred_t *cred, int *rvalp)
{
	overlay_ioc_delete_t *oidp = karg;
	overlay_dev_t *odd;
	datalink_id_t tid;
	int ret;

	odd = overlay_hold_by_dlid(oidp->oid_linkid);
	if (odd == NULL) {
		return (ENOENT);
	}

	mutex_enter(&odd->odd_lock);
	/* If we're not the only hold, we're busy */
	if (odd->odd_ref != 1) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (EBUSY);
	}

	if (odd->odd_flags & OVERLAY_F_IN_MUX) {
		mutex_exit(&odd->odd_lock);
		overlay_hold_rele(odd);
		return (EBUSY);
	}

	/*
	 * To remove this, we need to first remove it from dls and then remove
	 * it from mac. The act of removing it from mac will check if there are
	 * devices on top of this, eg. vnics. If there are, then that will fail
	 * and we'll have to go through and recreate the dls entry. Only after
	 * mac_unregister has succeeded, then we'll go through and actually free
	 * everything and drop the dev lock.
	 */
	ret = dls_devnet_destroy(odd->odd_mh, &tid, B_TRUE);
	if (ret != 0) {
		overlay_hold_rele(odd);
		return (ret);
	}

	ASSERT(oidp->oid_linkid == tid);
	ret = mac_disable(odd->odd_mh);
	if (ret != 0) {
		(void) dls_devnet_create(odd->odd_mh, odd->odd_linkid,
		    crgetzoneid(cred));
		overlay_hold_rele(odd);
		return (ret);
	}

	overlay_target_quiesce(odd->odd_target);

	mutex_enter(&overlay_dev_lock);
	list_remove(&overlay_dev_list, odd);
	mutex_exit(&overlay_dev_lock);

	cv_destroy(&odd->odd_iowait);
	mutex_destroy(&odd->odd_lock);
	overlay_target_free(odd);
	odd->odd_plugin->ovp_ops->ovpo_fini(odd->odd_pvoid);
	overlay_plugin_rele(odd->odd_plugin);
	kmem_free(odd, sizeof (overlay_dev_t));

	return (0);
}

/* ARGSUSED */
static int
overlay_i_nprops(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	overlay_dev_t *odd;
	overlay_ioc_nprops_t *on = karg;

	odd = overlay_hold_by_dlid(on->oipn_linkid);
	if (odd == NULL)
		return (ENOENT);
	on->oipn_nprops = odd->odd_plugin->ovp_nprops + OVERLAY_DEV_NPROPS;
	overlay_hold_rele(odd);

	return (0);
}

static int
overlay_propinfo_plugin_cb(overlay_plugin_t *opp, void *arg)
{
	overlay_prop_handle_t phdl = arg;
	overlay_prop_set_range_str(phdl, opp->ovp_name);
	return (0);
}

static int
overlay_i_name_to_propid(overlay_dev_t *odd, const char *name, uint_t *id)
{
	int i;

	for (i = 0; i < OVERLAY_DEV_NPROPS; i++) {
		if (strcmp(overlay_dev_props[i], name) == 0) {
			*id = i;
			return (0);
		}
	}

	for (i = 0; i < odd->odd_plugin->ovp_nprops; i++) {
		if (strcmp(odd->odd_plugin->ovp_props[i], name) == 0) {
			*id = i + OVERLAY_DEV_NPROPS;
			return (0);
		}
	}

	return (ENOENT);
}

static void
overlay_i_propinfo_mtu(overlay_dev_t *odd, overlay_prop_handle_t phdl)
{
	uint32_t def;
	mac_propval_range_t range;
	uint_t perm;

	ASSERT(MAC_PERIM_HELD(odd->odd_mh));

	bzero(&range, sizeof (mac_propval_range_t));
	range.mpr_count = 1;
	if (mac_prop_info(odd->odd_mh, MAC_PROP_MTU, "mtu", &def,
	    sizeof (def), &range, &perm) != 0)
		return;

	if (perm == MAC_PROP_PERM_READ)
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_READ);
	else if (perm == MAC_PROP_PERM_WRITE)
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_WRITE);
	else if (perm == MAC_PROP_PERM_RW)
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_RW);

	overlay_prop_set_type(phdl, OVERLAY_PROP_T_UINT);
	overlay_prop_set_default(phdl, &def, sizeof (def));
	overlay_prop_set_range_uint32(phdl, range.mpr_range_uint32[0].mpur_min,
	    range.mpr_range_uint32[0].mpur_max);
}

/* ARGSUSED */
static int
overlay_i_propinfo(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	overlay_dev_t *odd;
	int ret;
	mac_perim_handle_t mph;
	uint_t propid = UINT_MAX;
	overlay_ioc_propinfo_t *oip = karg;
	overlay_prop_handle_t phdl = (overlay_prop_handle_t)oip;

	odd = overlay_hold_by_dlid(oip->oipi_linkid);
	if (odd == NULL)
		return (ENOENT);

	overlay_prop_init(phdl);
	mac_perim_enter_by_mh(odd->odd_mh, &mph);

	/*
	 * If the id is -1, then the property that we're looking for is named in
	 * oipi_name and we should fill in its id. Otherwise, we've been given
	 * an id and we need to turn that into a name for our plugin's sake. The
	 * id is our own fabrication for property discovery.
	 */
	if (oip->oipi_id == -1) {
		/*
		 * Determine if it's a known generic property or it belongs to a
		 * module by checking against the list of known names.
		 */
		oip->oipi_name[OVERLAY_PROP_NAMELEN-1] = '\0';
		if ((ret = overlay_i_name_to_propid(odd, oip->oipi_name,
		    &propid)) != 0) {
			overlay_hold_rele(odd);
			mac_perim_exit(mph);
			return (ret);
		}
		oip->oipi_id = propid;
		if (propid >= OVERLAY_DEV_NPROPS) {
			ret = odd->odd_plugin->ovp_ops->ovpo_propinfo(
			    oip->oipi_name, phdl);
			overlay_hold_rele(odd);
			mac_perim_exit(mph);
			return (ret);

		}
	} else if (oip->oipi_id >= OVERLAY_DEV_NPROPS) {
		uint_t id = oip->oipi_id - OVERLAY_DEV_NPROPS;

		if (id >= odd->odd_plugin->ovp_nprops) {
			overlay_hold_rele(odd);
			mac_perim_exit(mph);
			return (EINVAL);
		}
		ret = odd->odd_plugin->ovp_ops->ovpo_propinfo(
		    odd->odd_plugin->ovp_props[id], phdl);
		overlay_hold_rele(odd);
		mac_perim_exit(mph);
		return (ret);
	} else if (oip->oipi_id < -1) {
		overlay_hold_rele(odd);
		mac_perim_exit(mph);
		return (EINVAL);
	} else {
		ASSERT(oip->oipi_id < OVERLAY_DEV_NPROPS);
		ASSERT(oip->oipi_id >= 0);
		propid = oip->oipi_id;
		(void) strlcpy(oip->oipi_name, overlay_dev_props[propid],
		    sizeof (oip->oipi_name));
	}

	switch (propid) {
	case OVERLAY_DEV_P_MTU:
		overlay_i_propinfo_mtu(odd, phdl);
		break;
	case OVERLAY_DEV_P_VNETID:
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_RW);
		overlay_prop_set_type(phdl, OVERLAY_PROP_T_UINT);
		overlay_prop_set_nodefault(phdl);
		break;
	case OVERLAY_DEV_P_ENCAP:
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_READ);
		overlay_prop_set_type(phdl, OVERLAY_PROP_T_STRING);
		overlay_prop_set_nodefault(phdl);
		overlay_plugin_walk(overlay_propinfo_plugin_cb, phdl);
		break;
	case OVERLAY_DEV_P_VARPDID:
		overlay_prop_set_prot(phdl, OVERLAY_PROP_PERM_READ);
		overlay_prop_set_type(phdl, OVERLAY_PROP_T_UINT);
		overlay_prop_set_nodefault(phdl);
		break;
	default:
		overlay_hold_rele(odd);
		mac_perim_exit(mph);
		return (ENOENT);
	}

	overlay_hold_rele(odd);
	mac_perim_exit(mph);
	return (0);
}

/* ARGSUSED */
static int
overlay_i_getprop(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	int ret;
	overlay_dev_t *odd;
	mac_perim_handle_t mph;
	overlay_ioc_prop_t *oip = karg;
	uint_t propid, mtu;

	odd = overlay_hold_by_dlid(oip->oip_linkid);
	if (odd == NULL)
		return (ENOENT);

	mac_perim_enter_by_mh(odd->odd_mh, &mph);
	oip->oip_size = OVERLAY_PROP_SIZEMAX;
	oip->oip_name[OVERLAY_PROP_NAMELEN-1] = '\0';
	if (oip->oip_id == -1) {
		int i;

		for (i = 0; i < OVERLAY_DEV_NPROPS; i++) {
			if (strcmp(overlay_dev_props[i], oip->oip_name) == 0)
				break;
			if (i == OVERLAY_DEV_NPROPS) {
				ret = odd->odd_plugin->ovp_ops->ovpo_getprop(
				    odd->odd_pvoid, oip->oip_name,
				    oip->oip_value, &oip->oip_size);
				overlay_hold_rele(odd);
				mac_perim_exit(mph);
				return (ret);
			}
		}

		propid = i;
	} else if (oip->oip_id >= OVERLAY_DEV_NPROPS) {
		uint_t id = oip->oip_id - OVERLAY_DEV_NPROPS;

		if (id > odd->odd_plugin->ovp_nprops) {
			overlay_hold_rele(odd);
			mac_perim_exit(mph);
			return (EINVAL);
		}
		ret = odd->odd_plugin->ovp_ops->ovpo_getprop(odd->odd_pvoid,
		    odd->odd_plugin->ovp_props[id], oip->oip_value,
		    &oip->oip_size);
		overlay_hold_rele(odd);
		mac_perim_exit(mph);
		return (ret);
	} else if (oip->oip_id < -1) {
		overlay_hold_rele(odd);
		mac_perim_exit(mph);
		return (EINVAL);
	} else {
		ASSERT(oip->oip_id < OVERLAY_DEV_NPROPS);
		ASSERT(oip->oip_id >= 0);
		propid = oip->oip_id;
	}

	ret = 0;
	switch (propid) {
	case OVERLAY_DEV_P_MTU:
		/*
		 * The MTU is always set and retrieved through MAC, to allow for
		 * MAC to do whatever it wants, as really that property belongs
		 * to MAC. This is important for things where vnics have hold on
		 * the MTU.
		 */
		mac_sdu_get(odd->odd_mh, NULL, &mtu);
		bcopy(&mtu, oip->oip_value, sizeof (uint_t));
		oip->oip_size = sizeof (uint_t);
		break;
	case OVERLAY_DEV_P_VNETID:
		/*
		 * While it's read-only while inside of a mux, we're not in a
		 * context that can guarantee that. Therefore we always grab the
		 * overlay_dev_t's odd_lock.
		 */
		mutex_enter(&odd->odd_lock);
		bcopy(&odd->odd_vid, oip->oip_value, sizeof (uint64_t));
		mutex_exit(&odd->odd_lock);
		oip->oip_size = sizeof (uint64_t);
		break;
	case OVERLAY_DEV_P_ENCAP:
		oip->oip_size = strlcpy((char *)oip->oip_value,
		    odd->odd_plugin->ovp_name, oip->oip_size);
		break;
	case OVERLAY_DEV_P_VARPDID:
		mutex_enter(&odd->odd_lock);
		if (odd->odd_flags & OVERLAY_F_VARPD) {
			const uint64_t val = odd->odd_target->ott_id;
			bcopy(&val, oip->oip_value, sizeof (uint64_t));
			oip->oip_size = sizeof (uint64_t);
		} else {
			oip->oip_size = 0;
		}
		mutex_exit(&odd->odd_lock);
		break;
	default:
		ret = ENOENT;
	}

	overlay_hold_rele(odd);
	mac_perim_exit(mph);
	return (ret);
}

static void
overlay_setprop_vnetid(overlay_dev_t *odd, uint64_t vnetid)
{
	mutex_enter(&odd->odd_lock);

	/* Simple case, not active */
	if (!(odd->odd_flags & OVERLAY_F_IN_MUX)) {
		odd->odd_vid = vnetid;
		mutex_exit(&odd->odd_lock);
		return;
	}

	/*
	 * In the hard case, we need to set the drop flag, quiesce I/O and then
	 * we can go ahead and do everything.
	 */
	odd->odd_flags |= OVERLAY_F_MDDROP;
	overlay_io_wait(odd, OVERLAY_F_IOMASK);
	mutex_exit(&odd->odd_lock);

	overlay_mux_remove_dev(odd->odd_mux, odd);

	mutex_enter(&odd->odd_lock);
	odd->odd_vid = vnetid;
	mutex_exit(&odd->odd_lock);

	overlay_mux_add_dev(odd->odd_mux, odd);

	mutex_enter(&odd->odd_lock);
	ASSERT(odd->odd_flags & OVERLAY_F_IN_MUX);
	odd->odd_flags &= ~OVERLAY_F_MDDROP;
	mutex_exit(&odd->odd_lock);
}

/* ARGSUSED */
static int
overlay_i_setprop(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	int ret;
	overlay_dev_t *odd;
	overlay_ioc_prop_t *oip = karg;
	uint_t propid = UINT_MAX;
	mac_perim_handle_t mph;
	uint64_t maxid, *vidp;

	if (oip->oip_size > OVERLAY_PROP_SIZEMAX)
		return (EINVAL);

	odd = overlay_hold_by_dlid(oip->oip_linkid);
	if (odd == NULL)
		return (ENOENT);

	oip->oip_name[OVERLAY_PROP_NAMELEN-1] = '\0';
	mac_perim_enter_by_mh(odd->odd_mh, &mph);
	mutex_enter(&odd->odd_lock);
	if (odd->odd_flags & OVERLAY_F_ACTIVATED) {
		mac_perim_exit(mph);
		mutex_exit(&odd->odd_lock);
		return (ENOTSUP);
	}
	mutex_exit(&odd->odd_lock);
	if (oip->oip_id == -1) {
		int i;

		for (i = 0; i < OVERLAY_DEV_NPROPS; i++) {
			if (strcmp(overlay_dev_props[i], oip->oip_name) == 0)
				break;
			if (i == OVERLAY_DEV_NPROPS) {
				ret = odd->odd_plugin->ovp_ops->ovpo_setprop(
				    odd->odd_pvoid, oip->oip_name,
				    oip->oip_value, oip->oip_size);
				overlay_hold_rele(odd);
				mac_perim_exit(mph);
				return (ret);
			}
		}

		propid = i;
	} else if (oip->oip_id >= OVERLAY_DEV_NPROPS) {
		uint_t id = oip->oip_id - OVERLAY_DEV_NPROPS;

		if (id > odd->odd_plugin->ovp_nprops) {
			mac_perim_exit(mph);
			overlay_hold_rele(odd);
			return (EINVAL);
		}
		ret = odd->odd_plugin->ovp_ops->ovpo_setprop(odd->odd_pvoid,
		    odd->odd_plugin->ovp_props[id], oip->oip_value,
		    oip->oip_size);
		mac_perim_exit(mph);
		overlay_hold_rele(odd);
		return (ret);
	} else if (oip->oip_id < -1) {
		mac_perim_exit(mph);
		overlay_hold_rele(odd);
		return (EINVAL);
	} else {
		ASSERT(oip->oip_id < OVERLAY_DEV_NPROPS);
		ASSERT(oip->oip_id >= 0);
		propid = oip->oip_id;
	}

	ret = 0;
	switch (propid) {
	case OVERLAY_DEV_P_MTU:
		ret = mac_set_prop(odd->odd_mh, MAC_PROP_MTU, "mtu",
		    oip->oip_value, oip->oip_size);
		break;
	case OVERLAY_DEV_P_VNETID:
		if (oip->oip_size != sizeof (uint64_t)) {
			ret = EINVAL;
			break;
		}
		vidp = (uint64_t *)oip->oip_value;
		ASSERT(odd->odd_plugin->ovp_id_size <= 8);
		maxid = UINT64_MAX;
		if (odd->odd_plugin->ovp_id_size != 8)
			maxid = (1ULL << (odd->odd_plugin->ovp_id_size * 8)) -
			    1ULL;
		if (*vidp >= maxid) {
			ret = EINVAL;
			break;
		}
		overlay_setprop_vnetid(odd, *vidp);
		break;
	case OVERLAY_DEV_P_ENCAP:
	case OVERLAY_DEV_P_VARPDID:
		ret = EPERM;
		break;
	default:
		ret = ENOENT;
	}

	mac_perim_exit(mph);
	overlay_hold_rele(odd);
	return (ret);
}

/* ARGSUSED */
static int
overlay_i_status(void *karg, intptr_t arg, int mode, cred_t *cred,
    int *rvalp)
{
	overlay_dev_t *odd;
	overlay_ioc_status_t *os = karg;

	odd = overlay_hold_by_dlid(os->ois_linkid);
	if (odd == NULL)
		return (ENOENT);

	mutex_enter(&odd->odd_lock);
	if ((odd->odd_flags & OVERLAY_F_DEGRADED) != 0) {
		os->ois_status = OVERLAY_I_DEGRADED;
		(void) strlcpy(os->ois_message, odd->odd_fmamsg,
		    OVERLAY_STATUS_BUFLEN);
	} else {
		os->ois_status = OVERLAY_I_OK;
		os->ois_message[0] = '\0';
	}
	mutex_exit(&odd->odd_lock);
	overlay_hold_rele(odd);

	return (0);
}

static dld_ioc_info_t overlay_ioc_list[] = {
	{ OVERLAY_IOC_CREATE, DLDCOPYIN, sizeof (overlay_ioc_create_t),
		overlay_i_create, secpolicy_dl_config },
	{ OVERLAY_IOC_ACTIVATE, DLDCOPYIN, sizeof (overlay_ioc_activate_t),
		overlay_i_activate, secpolicy_dl_config },
	{ OVERLAY_IOC_DELETE, DLDCOPYIN, sizeof (overlay_ioc_delete_t),
		overlay_i_delete, secpolicy_dl_config },
	{ OVERLAY_IOC_PROPINFO, DLDCOPYIN | DLDCOPYOUT,
		sizeof (overlay_ioc_propinfo_t), overlay_i_propinfo,
		secpolicy_dl_config },
	{ OVERLAY_IOC_GETPROP, DLDCOPYIN | DLDCOPYOUT,
		sizeof (overlay_ioc_prop_t), overlay_i_getprop,
		secpolicy_dl_config },
	{ OVERLAY_IOC_SETPROP, DLDCOPYIN,
		sizeof (overlay_ioc_prop_t), overlay_i_setprop,
		secpolicy_dl_config },
	{ OVERLAY_IOC_NPROPS, DLDCOPYIN | DLDCOPYOUT,
		sizeof (overlay_ioc_nprops_t), overlay_i_nprops,
		secpolicy_dl_config },
	{ OVERLAY_IOC_STATUS, DLDCOPYIN | DLDCOPYOUT,
		sizeof (overlay_ioc_status_t), overlay_i_status,
		NULL }
};

static int
overlay_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int fmcap = DDI_FM_EREPORT_CAPABLE;
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (overlay_dip != NULL || ddi_get_instance(dip) != 0)
		return (DDI_FAILURE);

	ddi_fm_init(dip, &fmcap, NULL);

	if (ddi_create_minor_node(dip, OVERLAY_CTL, S_IFCHR,
	    ddi_get_instance(dip), DDI_PSEUDO, 0) == DDI_FAILURE)
		return (DDI_FAILURE);

	if (dld_ioc_register(OVERLAY_IOC, overlay_ioc_list,
	    DLDIOCCNT(overlay_ioc_list)) != 0) {
		ddi_remove_minor_node(dip, OVERLAY_CTL);
		return (DDI_FAILURE);
	}

	overlay_dip = dip;
	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
overlay_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	int error;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resp = (void *)overlay_dip;
		error = DDI_SUCCESS;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resp = (void *)0;
		error = DDI_SUCCESS;
		break;
	default:
		error = DDI_FAILURE;
		break;
	}

	return (error);
}

static int
overlay_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	mutex_enter(&overlay_dev_lock);
	if (!list_is_empty(&overlay_dev_list) || overlay_target_busy()) {
		mutex_exit(&overlay_dev_lock);
		return (EBUSY);
	}
	mutex_exit(&overlay_dev_lock);


	dld_ioc_unregister(OVERLAY_IOC);
	ddi_remove_minor_node(dip, OVERLAY_CTL);
	ddi_fm_fini(dip);
	overlay_dip = NULL;
	return (DDI_SUCCESS);
}

static struct cb_ops overlay_cbops = {
	overlay_target_open,	/* cb_open */
	overlay_target_close,	/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	overlay_target_ioctl,	/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP,			/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev,			/* cb_awrite */
};

static struct dev_ops overlay_dev_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	overlay_getinfo,	/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	overlay_attach,		/* devo_attach */
	overlay_detach,		/* devo_detach */
	nulldev,		/* devo_reset */
	&overlay_cbops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL,			/* devo_power */
	ddi_quiesce_not_supported	/* devo_quiesce */
};

static struct modldrv overlay_modldrv = {
	&mod_driverops,
	"Overlay Network Driver",
	&overlay_dev_ops
};

static struct modlinkage overlay_linkage = {
	MODREV_1,
	&overlay_modldrv
};

static int
overlay_init(void)
{
	mutex_init(&overlay_dev_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&overlay_dev_list, sizeof (overlay_dev_t),
	    offsetof(overlay_dev_t, odd_link));
	overlay_mux_init();
	overlay_plugin_init();
	overlay_target_init();

	return (DDI_SUCCESS);
}

static void
overlay_fini(void)
{
	overlay_target_fini();
	overlay_plugin_fini();
	overlay_mux_fini();
	mutex_destroy(&overlay_dev_lock);
	list_destroy(&overlay_dev_list);
}

int
_init(void)
{
	int err;

	if ((err = overlay_init()) != DDI_SUCCESS)
		return (err);

	mac_init_ops(NULL, "overlay");
	err = mod_install(&overlay_linkage);
	if (err != DDI_SUCCESS) {
		overlay_fini();
		return (err);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&overlay_linkage, modinfop));
}

int
_fini(void)
{
	int err;

	err = mod_remove(&overlay_linkage);
	if (err != 0)
		return (err);

	overlay_fini();
	return (0);
}
