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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * Core nexus driver for I2C, SMBus, and someday I3C
 * -------------------------------------------------
 *
 * The i2cnex driver is the heart of the I2C subsystem and is both a nexus
 * driver and provides a series of character devices. This driver implements and
 * provides:
 *
 *  - Interfaces that our three primary driver classes plug into:
 *
 *    1) Controllers (<sys/i2c/controller.h>)
 *    2) I2C Devices (<sys/i2c/client.h>)
 *    3) Muxes       (sys/i2c/mux.h>
 *
 *  - Provides abstractions in the devices tree for the above as well as a
 *    series of minor nodes that users can interact with to add and remove
 *    devices as well as perform I/O. (<sys/i2c/ioctl.h>)
 *
 *  - Implements the core synchronization and transaction processing on a
 *    per-I2C bus basis.
 *
 * ----------
 * Background
 * ----------
 *
 * I2C is a common form of two-wire bus protocol. The two wires refer to a
 * shared data line and a separate shared clock line. To perform a transaction,
 * an I2C controller drives the clock at a fixed frequency, and devices on the
 * bus latch logical bits as the clock progresses based on whether the data line
 * is a logic high or logic low. Transactions on the bus are framed in terms of
 * a Start condition and Stop condition, which allows the controller to indicate
 * it is taking control of the bus.
 *
 * I/O on the bus is generally framed as a series of 8-bit I/O segments followed
 * by an explicit acknowledgement from the other end, which occurs by either the
 * device (when writing) or the controller (when reading) driving the bus low.
 * This is called an 'ack'. When there is no acknowledgement on the bus, this is
 * called a 'nack'. Nacks can show up at different times in the protocol and
 * have different meanings.
 *
 * The I2C bus is a shared bus, meaning the data and clock wires go to all
 * devices on the bus. This requires a way for devices to distinguish
 * themselves. This is done in I2C with a 7-bit address (though there are some
 * extensions for 10-bit addresses). In general, addresses are not discoverable
 * and instead you need to come with knowledge of what addresses belong to what
 * devices on the bus.  This is very different from PCIe or USB, where there is
 * a standard way to discover what is at the other end of a connection. In
 * addition, there are addresses that are explicitly reserved for special use
 * cases at the beginning and end of the 7-bit address space.
 *
 * SMBus, or the System Management Bus, is similar to I2C and was created by
 * Intel and Duracell in the 1990s. Originally it targeted batteries, but was
 * gradually expanded and has been the primary interface in decades of Intel
 * chipsets (though they do also have I2C and I3C now).
 *
 * SMBus is mostly compatible with I2C. It uses the same principles on the
 * physical layer; however, SMBus has a fixed number of commands that can be
 * sent on the wire with very explicit data payloads. Generally speaking, any
 * SMBus transaction can be represented as an I2C transaction; however, the
 * opposite is not true. Many SMBus controllers will only output the specific
 * commands defined by the SMBus specification.
 *
 * In general, every SMBus command has a fixed command code that it includes.
 * This is generally analogous to the register number. SMBus 2.0 is the most
 * ubiquitous version of the standard. It defines 8-bit and 16-bit register
 * reads and writes. It also has the notion of block reads and writes which
 * include the number of bytes to be read or written in addition to the command
 * register. Note, while I2C controllers can write this pattern, many devices do
 * not support this.
 *
 * An example tree of devices might look something like:
 *
 * +------------+     +--------+    +-------------+   +-------------------+
 * | Controller |     | EEPROM |    | Temp Sensor |   | Voltage Regulator |
 * +------------+     |  0x5e  |    |     0x48    |   |       0x76        |
 *       |            +--------+    +-------------+   +-------------------+
 *       |                |                |                    |
 *       +----------------+----------------+--------------------+
 *                 |
 *              +-------+      +--------------------------+
 *              |     0 |---+--| DIMM A, 0x10, 0x30, 0x50 |
 *              |       |   |  +---------------------------+
 *              |  Mux  |   +---| DIMM B, 0x11, 0x31, 0x51 |
 *              | 0x72  |       +--------------------------+
 *              |       |      +--------------------------+
 *              |     1 |---+--| DIMM C, 0x10, 0x30, 0x50 |
 *              +-------+   |  +---------------------------+
 *                          +---| DIMM D, 0x11, 0x31, 0x51 |
 *                              +--------------------------+
 *
 * Here, we have a controller. The multiplexor (mux), EEPROM, voltage regulator
 * (VR) temperature sensor are all on the same bus with different addresses.
 * Downstream of the two mux ports, 0 and 1, are devices that have the same
 * address (DIMM A and C, B and D). The mux may have either leg 0 enabled, leg 1
 * enabled, or neither. However, it critically can't have both which helps avoid
 * the address conflict.
 *
 * An important property to emphasize is that only one I/O may be going on at
 * any time on the bus and all I/O is initiated by the controller (ignoring
 * SMBus host notifications). This ends up playing a lot into the overall system
 * design. If someone else tries to talk on the bus at the same time, this is
 * considered a collision and will cause an error.
 *
 * ------------
 * Key Concepts
 * ------------
 *
 * This section introduces the different entities and concepts that are used
 * thought the broader I2C framework.
 *
 * CONTROLLER
 *
 *	Controllers are devices that know how to speak the I2C or SMBus
 *	protocol. Requests go through these devices to get on the wire. These
 *	are generally PCI or MMIO devices themselves. Controllers implement the
 *	I2C controller interface in <sys/i2c/controller.h>. Controllers are
 *	enumerated based upon discovering the aforementioned PCI or MMIO devices
 *	and as a result are the start of this portion of the /devices tree.
 *
 *	In addition to the standard device node that exists for the PCI/MMIO
 *	device, there is an instance of i2cnex created under the controller,
 *	which represents the root of the I2C tree. A controller is represented
 *	by the i2c_ctrl_t structure.
 *
 * DEVICE
 *
 *	A device is a target on the bus that speaks the I2C or SMBus protocol
 *	and provides some functionality. Common devices include EEPROMs,
 *	temperature sensors, GPIO controllers, power controllers, and more. Each
 *	device has a unique address. A plethora of device drivers are used to
 *	implement support for devices, which leverage the kernel’s I2C/SMBus
 *	Client interfaces. Devices are discovered and instantiated through a
 *	combination of system firmware such as Device Tree or by users manually
 *	creating them in userland. A device is represented by the i2c_dev_t.
 *
 * MULTIPLEXOR
 *
 *	A multiplexor is a device that allows one to switch between multiple
 *	different downstream buses. A multiplexor must implement the kernel’s
 *	Mux APIs in <sys/i2c/mux.h>. While a mux commonly is an I2C device
 *	itself, it does not have to be. A multiplexor may have other features
 *	beyond just the mux. For example, the LTC4306 also has GPIOs. Like the
 *	controller, a device node for the mux will be created for it bound to
 *	i2cnex. A mux is represented by the i2c_nex_t structure.
 *
 *	Multiplexors are enabled and disabled when I/O is performed by the
 *	system. Users or drivers don't need to explicitly control them.
 *
 * PORT
 *
 *	Controllers and multiplexors both are devices that have a varying number
 *	of ports under them. Devices can be created or enumerated under ports.
 *	In broader I2C parlance, the top-level ports under a controller are
 *	sometimes called a bus. There is a device node created for each port. A
 *	port is represented by the i2c_port_t structure.
 *
 * ADDRESS
 *
 *	An address uniquely identifies a device. An address is represented by
 *	the i2c_addr_t. The address consists of two pieces, an address type and
 *	the address itself. The current address types are 7-bit and 10-bit
 *	addresses. However, it's worth noting that only 7-bit addresses are
 *	commonly found and implemented currently.
 *
 * I2C ERROR
 *
 *	Errors are currently broken into two different categories: general
 *	errors that can occur in the framework and errors specific to
 *	controllers performing I/O. These are represented by the i2c_error_t. In
 *	general, a pointer to this structure is used to collect error
 *	information. A few of the client APIs may only use the general,
 *	non-controller-specific error.
 *
 *	The general errors are further broken into different categories. These
 *	include errors that may be relevant across multiple different types of
 *	consumers or are shared. Otherwise, each group of errors is tailored to
 *	a specific set of operations such as multiplexors, device driver
 *	clients, and userland clients, to name a few examples.
 *
 * NEXUS
 *
 *	While the term nexus is overloaded, here we refer to the i2c_nexus_t,
 *	which is a type that is associated with every dev_info_t that is I2C
 *	related other than the PCIe/MMIO controller itself. Even the various
 *	I2C device nodes that we create which don't bind to this driver, still
 *	end up having an i2c_nexus_t that relates to them.
 *
 *	In addition to the metadata about a node such as its name, bus address,
 *	and type, every nexus has a minor node which is used by libi2c to
 *	perform I/O.
 *
 * CLIENT
 *
 *	When a device driver for an EEPROM, sensor, GPIO controller, etc. wants
 *	to communicate with an I2C device, it creates an i2c_client_t. The
 *	client inherently refers to a single address on the bus and our I/O
 *	operations generally target a specific client. Drivers can always get
 *	clients that refer to addresses in their reg[] property. However, there
 *	are many cases where there are shared addresses (e.g. DDR4 SPD) or a
 *	device may have more addresses than are present in the reg[] (certain
 *	EEPROMs).
 *
 * TRANSACTION
 *
 *	A transaction represents the ability to perform I/O on the I2C bus and
 *	indicates that the caller has exclusive access to the bus. This is
 *	represented with the i2c_txn_t structure. A transaction is required for
 *	all I/O operations or to set properties.
 *
 *	Certain I/O operations want to ensure that no one else intervenes on the
 *	bus while performing said I/O. For example, the DDR5 SPD driver
 *	(spd511x) has to change the page register to switch between the 8
 *	different 128 byte regions in the device. When the driver does this, it
 *	wants to ensure that no one else can get in and change the page register
 *	again before it's finished its I/O.
 *
 *	To facilitate this, every I/O operation takes the i2c_txn_t * as its
 *	first argument. If callers don't have an active transaction and just
 *	pass NULL, the system will block and acquire one. However, if the
 *	transaction is non-NULL, then it will be used. When callers do have an
 *	active transaction, they they can use it across multiple clients.
 *	Similarly, the framework will pass the transaction to the various mux
 *	select and deselect APIs, allowing in-band based devices to get access
 *	to the transaction and simplifying those drivers design.
 *
 * REGISTER HANDLE
 *
 *	Many I2C devices have a notion of registers inside of them. Each
 *	register is at a given address. The number of bytes per address can vary
 *	from device to device and even the number of bytes that make up an
 *	address can too. While many devices use a single byte address to try to
 *	fit within the constraints of an SMBus controller, several EEPROMs use a
 *	2-byte address to minimize the number of addresses they consume on the
 *	bus.
 *
 *	To deal with these differences and to drivers not to have to think about
 *	how to construct these types of requests, the device driver client
 *	interface has the i2c_reg_hdl_t. This takes a number of attributes at
 *	creation time and then allows callers to read or write one or more
 *	registers in one go.
 *
 * ROOT
 *
 *	To facilitate the bus configuration operation of the initial controller,
 *	we have the idea of an i2c_root_t, which is basically a per-dev_info_t
 *	list of controllers.
 *
 * -----------
 * Device Tree
 * -----------
 *
 * To help make the representation of all of these different entities concrete,
 * let's walk through an example I2C system and how the different device nodes
 * end up looking:
 *
 *   +------------+
 *   | Controller |-----------------------------------------+
 *   | pchsmbus0  |                |                        |
 *   +------------+                v                        v
 *                          +------------+            +------------+
 *                          | 8-port mux |            | 8-port mux |
 *                          |  pca9548   |            |  pca9548   |
 *                          |    0x72    |            |    0x73    |
 *                          |            |            |            |
 *                          | 012345678  |            | 012345678  |
 *                          +------------+            +------------+
 *      +--------+                  |                    |          +--------+
 *      | Sensor |                  |                    |          | Sensor |
 *      | tmp431 |<-----------------+                    +--------->|  lm75  |
 *      |  0x4c  |                                       |          |  0x48  |
 *      +--------+                                       |          +--------+
 *                                                       |          +--------+
 *                                                       |          | Sensor |
 *                                                       +--------->|  lm75  |
 *                                                                  |  0x49  |
 *                                                                  +--------+
 *
 * Here we have an instance of the pchsmbus I2C controller. At the top-level
 * there are two 8-port muxes. These are the pca9548 device. Under bux 6 on the
 * first one, there is a tmp431 sensor. Under the second one, there are a pair
 * of lm75 temperature sensors. Here is what the device tree will look like on
 * this system. We name each node based on its name and address and then follow
 * up with information about the driver, instance, and I2C nexus type.
 *
 * i86pc (rootnex)
 *   pci@0,0 npe0
 *     pci8086,7270@1f,4 pchsmbus0
 *       i2cnex@pchsmbus0 i2cnex0		I2C_NEXUS_T_CTRL
 *         i2cnex@0 i2cnex1			I2C_NEXUS_T_PORT
 *           pca9548@0,72 pca954x0		I2C_NEXUS_T_DEV
 *             i2cnex@pca954x0 i2cnex2		I2C_NEXUS_T_MUX
 *               i2cnex@0 i2cnex3		I2C_NEXUS_T_PORT
 *               i2cnex@1 i2cnex4		I2C_NEXUS_T_PORT
 *               i2cnex@2 i2cnex5		I2C_NEXUS_T_PORT
 *               i2cnex@3 i2cnex6		I2C_NEXUS_T_PORT
 *               i2cnex@4 i2cnex7		I2C_NEXUS_T_PORT
 *               i2cnex@5 i2cnex8		I2C_NEXUS_T_PORT
 *               i2cnex@6 i2cnex9		I2C_NEXUS_T_PORT
 *                 tmp431@0,4c			I2C_NEXUS_T_DEV
 *               i2cnex@7 i2cnex10		I2C_NEXUS_T_PORT
 *           pca9548@0,73 pca954x1		I2C_NEXUS_T_DEV
 *             i2cnex@pca954x1 i2cnex11		I2C_NEXUS_T_MUX
 *               i2cnex@0 i2cnex12		I2C_NEXUS_T_PORT
 *               i2cnex@1 i2cnex13		I2C_NEXUS_T_PORT
 *                 lm75@0,48 lm7x0		I2C_NEXUS_T_DEV
 *                 lm75@0,49 lm7x1		I2C_NEXUS_T_DEV
 *               i2cnex@2 i2cnex14		I2C_NEXUS_T_PORT
 *               i2cnex@3 i2cnex15		I2C_NEXUS_T_PORT
 *               i2cnex@4 i2cnex16		I2C_NEXUS_T_PORT
 *               i2cnex@5 i2cnex17		I2C_NEXUS_T_PORT
 *               i2cnex@6 i2cnex18		I2C_NEXUS_T_PORT
 *               i2cnex@7 i2cnex19		I2C_NEXUS_T_PORT
 *
 * The controller is the root of the tree and we create an explicit I2C nexus to
 * represent it. The bus addresses vary with each type. For controllers and
 * muxes it is is the specific thing they are a child of unless they provide an
 * alternate name during registration to allow multiple to exist. For ports, it
 * is the name of the port itself. The pca9548 uses 0-based port names, so we
 * end up with 0-7.
 *
 * We see there is a nexus per port and there is similarly a nexus to represent
 * the start of the mux. While you may ask why is there a repetitive instance of
 * the controller and mux, this allows us to manage the minor nodes consistently
 * within the i2cnex driver and simplify the various providers.
 *
 * Devices are usually named based on the actual device that they represent.
 * Their address is the encoded version of their primary address, aka reg[0] as
 * a series of two hex values, the address type and value. Drivers generally
 * have a compatible entry that represents the actual device. Unlike PCI or
 * USB devices, most I2C devices are not self-describing. Someone needs to
 * inform us what type of device it is. The pca954x mux driver supports muxes
 * with a varying number of ports and there is no real way to safely determine
 * it without user input. While there is an instance of the i2c_nexus_t that
 * exists for each device node, we never bind the i2cnex driver to devices.
 *
 * ---------------------
 * I/O and Mux Tracking
 * --------------------
 *
 * To perform I/O on a given device we must walk down the tree to select any
 * ports so that the bus can access it. First, we wake up the device tree to the
 * root port of the controller and record all of the ports that are required to
 * be set up. Then we walk that path back down to the leaf, activating all muxes
 * along the way.
 *
 * To make this a bit more concrete, let's use the example from the prior
 * section. To perform I/O to lm75@0,48 we need to make sure that no other muxes
 * are active other than port 1 on pca9548@0x73. If this is already the active
 * segment, there is nothing else to do. If you do I/O to one of the two lm75s,
 * there's nothing to change to activate the other one. However, to send a
 * request to the tmp431, the current mux needs to be deselected (disabled) and
 * then the new one activated.
 *
 * To facilitate this, we have a pair of list_t structures on the i2c_ctrl_t. We
 * have one that represents the current set of ports that are active on the
 * controller. This is ordered starting from the controller's port followed by
 * all of the mux ports required to get to the device. In the case where we were
 * alternating between the two LM75s, this list would be the same, so there's
 * nothing else to do.
 *
 * When we're switching, we first deselect muxes starting from the tail walking
 * towards the head, aka the port on the controller. If we detect the current
 * port that we're targeting, then we're done right there. After we have figured
 * out what we're deselecting towards, we then build up the new plan by walking
 * the new path up towards the controller, recording all of the ports that we
 * encountered along the way. This enters the planning list. Once that is
 * generated, we go back the other way, head to tail activating all of the muxes
 * along the way on the proper port for the I/O .
 *
 * Right now this errs on the side of some simplicity. While we'll keep the same
 * mux segments active until needing to change, we don't try to find the longest
 * common subset and therefore may undo some ports that we would have to do
 * again. However, we find the depth of these trees on the smaller side and if
 * this proves problematic we can change it.
 *
 * ------------------
 * Address Management
 * ------------------
 *
 * Each port under a controller has a unique set of addresses. This is described
 * in greater detail in i2cnex_addr.c, which implements the address tracking
 * structures and logic.
 *
 * -------
 * Locking
 * -------
 *
 * By its nature I2C and related only support a single transaction going on at
 * any given time. This reality greatly shapes the locking and synchronization
 * design of the framework. At its core is a simple idea: only one transaction
 * can be going on at any given time on the bus.
 *
 * Of course, like most things in I2C, this simple thing is much more
 * complicated in practice. First, we extend the notion of the scope here to be
 * much larger. In particular, we want to serial device addition and removals,
 * address assignments and claims, and setting properties with respect to I/O.
 * We only ever want one of these going on at any given time. You could
 * summarize this as activities that require one to talk the device tree or
 * modify the controller's behavior. You don't want to change the controller's
 * clock frequency in the middle of performing an I/O!
 *
 * We ultimately pick each controller instance as this synchronization point.
 * Each controller should generally be independent from one another and is a
 * natural point to break things apart here. There is no reason an I/O can't be
 * going on on one controller while another controller is adding a device.
 * Before we get into the specifics of our design, let's describe some
 * complications and design considerations.
 *
 * COMPLEXITY 1: The NDI
 *
 * The NDI is the first wrinkle here. We can have our bus_ops called at any
 * arbitrary point with various holds potentially already in place. Therefore we
 * establish the rule that any calls to ndi_devi_enter() must happen prior to
 * anything that wants to enter the overall controller synchronization.
 *
 * The second NDI complexity comes in the fact that our general nexus bus
 * configuration entry points can lead to recursive entry into the framework.
 * For example, if we are performing a bus config on a controller, then we will
 * go to create its ports, which will call the port's i2cnex attach(9E) and want
 * to call the port naming operation. Similarly most I2C device drivers will
 * perform some I/O in attach.
 *
 * The third NDI complexity is that MT-config thread can make it so other
 * threads will need to complete activities, which could involve I2C behavior,
 * before the parent is done. For example, if we have a thread that creates a
 * device and calls ndi_bus_config() on it, if that device also creates its own
 * children, then the original caller will not be finished until the
 * grandchildren are done configuring.
 *
 * The fourth NDI complexity is that we can be going through a series of
 * multiple recursive operations: a user can ask to add a device. That in turn
 * will call into our bus operations. That can then cause a driver to attach
 * which asks to perform a transaction.
 *
 * COMPLEXITY 2: Driver Exclusion
 *
 * There are several cases where a driver wants to have exclusive access to the
 * bus across multiple I/O transactions. For example, one might want to change a
 * paging register and then do a read or write and ensure that no one else can
 * sneak in while this is going on. This isn't optional, but required for device
 * correctness.
 *
 * This is further complicated by our goal to make these interfaces something
 * that drivers don't have to think too much about. If an EEPROM driver or
 * sensor driver has multiple threads calling into its operations, we don't want
 * the driver to have to think too much about additional locking if it needs to
 * perform these transactions, assuming it is across a single instance of the
 * device.
 *
 * Finally, while we need to have APIs to be able to perform extended locking,
 * even the basic I/O operations need to ultimately take a hold on the
 * controller. If a driver doesn't need to have a coherent view across multiple
 * transactions, then we should take care of that for them transparently.
 *
 * COMPLEXITY 3: MUXES
 *
 * Muxes cause some challenges in our model. In particular, when a device that
 * we want to perform I/O on is under one or more muxes, we must walk from the
 * controller down the tree to the device activating each mux segment in turn.
 * There are a few things to call out about muxes that makes them special:
 *
 * 1. The <sys/i2c/mux.h> APIs are only ever called when we're in the context of
 *    performing an I/O operations. That is, the call to enable or disable a mux
 *    segment only ever happens while we're already in the context of a leaf
 *    device driver trying to do something.
 * 2. Some muxes actually provide more facilities than just the raw I/O mux. For
 *    example the LTC4306 has not only a built-in I2C Mux, but also supports a
 *    few GPIOs. So while item (1) is still true, other threads may still be
 *    trying to perform operations here in parallel.
 * 3. If a mux has multiple I/O operations it must perform without anyone
 *    getting in the way of it, then driver writers want to use the same bus
 *    lock client APIs.
 *
 * COMPLEXITY 4: Userland
 *
 * Userland also wants the ability to take a hold on a bus and allow that to
 * persist across multiple calls. An important constraint of userland is that
 * it ties something like a controller hold to an open file descriptor that can
 * be moved around. We cannot assume that the thread that opened the file
 * descriptor, issued a lock, issued an unlock, and closed the file descriptor
 * will be the same at all. In particular, this means that we cannot rely on a
 * thread to be the same across operations. Even if userland didn't have this
 * feature, it's still worthwhile to try to avoid this so that different kernel
 * device drivers can have their own designs. For example, something could be
 * using timeout(9F).
 *
 * LOCKING DESIGN
 *
 * The core of the locking design here is an attempt to satisfy several of the
 * different complexities. First and foremost because only one transaction can
 * occur on the bus we have the i2c_txn_t. This basically represents an
 * exclusive hold on the controller. This is designed to not be a
 * thread-specific value, but something that can be passed around from operation
 * to operation. Cases where this is passed around include:
 *
 * 1) Drivers that need to make multiple calls. They basically have a pattern
 *    that looks like:
 *
 *	i2c_txn_t *txn = i2c_bus_lock(...);
 *	op1(txn, ...);
 *	op2(txn, ...);
 *	op3(txn, ...);
 *	i2c_bus_unlock(txn);
 *
 * 2) The mux I/O path. As part of the transaction being taken as part of an
 *    operation, this'll end up passed to all of the mux framework APIs. This
 *    allows us to easily distinguish a case where the mux driver has its own
 *    features (e.g. GPIOs) that are independent from this.
 *
 * 3) When a user wants to take a hold that is tied to their file descriptor so
 *    they can issue multiple independent transactions, then that is stored in
 *    the minor state for the fd and will move around which thread it belongs
 *    to.
 *
 * Effectively the i2c_txn_t is required to do any operation on the controller
 * and is the general serialization point for all operations. This exists on a
 * per-i2c_ctrl_t basis. There is no other lock in the controller structure at
 * this time (though the i2c_ctrl_lock_t embeds one for synchronization and cv
 * purposes).
 *
 * In general, many other parts of the system are designed under the assumption
 * that the calling thread has an active transaction. This includes setting
 * properties, device addition and removal, and client manipulation. For
 * example, the i2c_client_t that device drivers use includes embedded
 * structures and buffers. The first step in using these other structures is to
 * have an active transaction.
 *
 * Transaction structures are allocated through i2c_txn_alloc() and
 * i2c_txn_free(). All i2c_txn_t structures are tracked in a controller-specific
 * list for debugging purposes and require the caller to specify a tag and a
 * void * to give context as to who the owner is and the corresponding code
 * path. These are not used otherwise as part of the locking logic. To take an
 * actual lock, one uses the i2c_ctrl_lock() and i2c_ctrl_unlock() operations.
 * We generally try not to have the i2c_txn_t * exposed to code outside of the
 * nexus if it doesn't actively indicate a held controller.
 *
 * NDI RECURSION
 *
 * There are two main design pieces that we put in place to deal with the NDI.
 *
 *  1. When performing bus configuration we need to serialize activity in the
 *     I2C tree and bus. This requires taking a transaction. When we call into
 *     attach(9E) of our children, they also may take a transactions. We
 *     facilitate this by making the lock recursive in this scenario. During bus
 *     operations, i2cnex begins by calling i2c_txn_nexus_op_begin(). This
 *     causes us to store the current thread that entered this as the active
 *     nexus thread.
 *
 *     If that thread was to call i2c_txn_ctrl_lock() again in a different
 *     context, we would notice both that it is the current owner and that we
 *     are in nexus mode. In this case, we would push the current owner into a
 *     stack of locks and grant the current caller the transaction. When a
 *     transaction ends, the prior holder is popped from the stack. This special
 *     mode of operation ends when someone calls i2c_txn_nexus_op_end().
 *
 *  2. When calling into an NDI operation, one is not allowed to hold a
 *     controller lock. A transaction may occur while within the context of a
 *     single operation; however, it cannot occur across it. In prototypes, the
 *     logic in i2c_user.c held the transaction across the initial NDI
 *     configuration call and this caused deadlocks when mux grandchildren were
 *     then trying to later attach due to the multi-threaded config logic in the
 *     kernel.
 *
 * OTHER LOCKS
 *
 * There are a few other locks in the driver to be aware of. These locks for the
 * most part all follow the pattern where once you acquire them, no other locks
 * are allowed to be acquired. They generally protect a specific piece of data
 * and are designed to be held for a short time.
 *
 *   - im_mutex in the i2cnex_minors_t.  This is used to protect all of the
 *     shared minor number allocations across all nexi and all users.
 *
 *   - cl_mutex in the i2c_ctrl_lock_t. This is only used in the implementation
 *     of the locking routines.
 *
 *   - ic_txn_lock in the i2c_ctrl_t. This protects the per-controller list of
 *     transactions and is only used when allocating and freeing transactions.
 *
 *   - ir_mutex in the i2c_root_t. This used to protect the list of controllers
 *     assosciated with a dev_info_t. This is only used during controller
 *     registration, deregistration, and bus configuration of the top-level
 *     controller.
 *
 *   - iu_user in the i2c_user_t. This only protects a small amount of data in
 *     the i2c_user_t.
 *
 * RULE SUMMARY
 *
 * 1) Always start with NDI locks if required (i.e. ndi_devi_enter()).
 * 2) The next highest priority acquisition is the overall transaction. You may
 *    acquire a transaction after performing all ndi_devi_enter() calls.
 *    However, no other i2c related locks can be held.
 * 3) The remaining mutexes can only be held for a short term to manipulate the
 *    data they protect. No other mutexes, the controller lock, or NDI stuff may
 *    be done during this. You are allowed to already hold an NDI lock or the
 *    controller lock.
 *
 * Effectively this boils down to NDI before i2c_txn_t before kmutex_t.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/stddef.h>
#include <sys/mkdev.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/stat.h>
#include <sys/ctype.h>
#include <sys/fs/dv_node.h>

#include "i2cnex.h"

/*
 * Extern declaration for pseudo-device related functions that aren't part of a
 * header file.
 */
extern int is_pseudo_device(dev_info_t *);

i2cnex_minors_t i2cnex_minors;

static i2c_root_t *
i2c_dip_to_root_common(dev_info_t *dip, bool alloc)
{
	mutex_enter(&i2cnex_minors.im_mutex);
	for (i2c_root_t *r = list_head(&i2cnex_minors.im_roots); r != NULL;
	    r = list_next(&i2cnex_minors.im_roots, r)) {
		if (r->ir_dip == dip) {
			mutex_exit(&i2cnex_minors.im_mutex);
			return (r);
		}
	}

	if (!alloc) {
		mutex_exit(&i2cnex_minors.im_mutex);
		return (NULL);
	}

	i2c_root_t *root = kmem_zalloc(sizeof (i2c_root_t), KM_SLEEP);
	root->ir_dip = dip;
	list_create(&root->ir_ctrls, sizeof (i2c_ctrl_t),
	    offsetof(i2c_ctrl_t, ic_link));
	mutex_init(&root->ir_mutex, NULL, MUTEX_DRIVER, NULL);

	list_insert_tail(&i2cnex_minors.im_roots, root);
	mutex_exit(&i2cnex_minors.im_mutex);

	return (root);

}

void
i2c_root_fini(i2c_root_t *root)
{
	VERIFY(MUTEX_HELD(&i2cnex_minors.im_mutex));
	list_remove(&i2cnex_minors.im_roots, root);
	list_destroy(&root->ir_ctrls);
	mutex_destroy(&root->ir_mutex);
	kmem_free(root, sizeof (i2c_root_t));
}

i2c_root_t *
i2c_root_init(dev_info_t *dip)
{
	return (i2c_dip_to_root_common(dip, true));
}

i2c_root_t *
i2c_dip_to_root(dev_info_t *dip)
{
	return (i2c_dip_to_root_common(dip, false));
}

void
i2cnex_nex_free(i2c_nexus_t *nex)
{
	if (nex == NULL) {
		return;
	}

	VERIFY0(nex->in_flags);
	if (nex->in_minor > 0) {
		id_free(i2cnex_minors.im_ids, nex->in_minor);
		nex->in_minor = 0;
	}
	kmem_free(nex, sizeof (i2c_nexus_t));
}

i2c_nexus_t *
i2cnex_nex_alloc(i2c_nexus_type_t type, dev_info_t *pdip, i2c_nexus_t *pnex,
    const char *name, const char *addr, i2c_ctrl_t *ctrl)
{
	i2c_nexus_t *nex;
	nex = kmem_zalloc(sizeof (i2c_nexus_t), KM_SLEEP);
	nex->in_type = type;
	nex->in_pnex = pnex;
	nex->in_ctrl = ctrl;

#ifdef	DEBUG
	if (type == I2C_NEXUS_T_CTRL) {
		ASSERT3P(pnex, ==, NULL);
	} else {
		ASSERT3P(pnex, !=, NULL);
	}
#endif
	nex->in_pdip = pdip;

	if (name == NULL) {
		name = "i2cnex";
	}

	if (strlcpy(nex->in_name, name, sizeof (nex->in_name)) >=
	    sizeof (nex->in_name)) {
		i2cnex_nex_free(nex);
		return (NULL);
	}

	if (strlcpy(nex->in_addr, addr, sizeof (nex->in_addr)) >=
	    sizeof (nex->in_addr)) {
		i2cnex_nex_free(nex);
		return (NULL);
	}

	nex->in_minor = id_alloc_nosleep(i2cnex_minors.im_ids);
	if (nex->in_minor == -1) {
		i2cnex_nex_free(nex);
		return (NULL);
	}

	return (nex);
}

i2c_nexus_t *
i2c_nex_find_by_minor(minor_t m)
{
	const i2c_nexus_t n = {
		.in_minor = m
	};
	i2c_nexus_t *ret;

	mutex_enter(&i2cnex_minors.im_mutex);
	ret = avl_find(&i2cnex_minors.im_nexi, &n, NULL);
	mutex_exit(&i2cnex_minors.im_mutex);

	return (ret);
}

/*
 * Common minor number based sort.
 */
static int
i2c_minor_compare(minor_t left, minor_t right)
{
	if (left > right)
		return (1);
	if (left < right)
		return (-1);
	return (0);
}

static int
i2c_nexus_compare(const void *left, const void *right)
{
	const i2c_nexus_t *ln = left;
	const i2c_nexus_t *rn = right;

	return (i2c_minor_compare(ln->in_minor, rn->in_minor));
}

static int
i2c_user_compare(const void *left, const void *right)
{
	const i2c_user_t *lu = left;
	const i2c_user_t *ru = right;

	return (i2c_minor_compare(lu->iu_minor, ru->iu_minor));
}


/*
 * Sort devices. Device sorting first happens based on the raw address and then
 * is disambiguated by the address type, e.g. 7-bit vs. 10-bit.
 */
static int
i2c_device_compare(const void *left, const void *right)
{
	const i2c_dev_t *ld = left;
	const i2c_dev_t *rd = right;

	if (ld->id_addr.ia_addr > rd->id_addr.ia_addr) {
		return (1);
	}

	if (ld->id_addr.ia_addr < rd->id_addr.ia_addr) {
		return (-1);
	}

	if (ld->id_addr.ia_type > rd->id_addr.ia_type) {
		return (1);
	}

	if (ld->id_addr.ia_type < rd->id_addr.ia_type) {
		return (-1);
	}

	return (0);
}

static void
i2c_port_fini(i2c_port_t *port)
{
	i2cnex_nex_free(port->ip_nex);
	avl_destroy(&port->ip_devices);
}

static bool
i2c_port_init(i2c_ctrl_t *ctrl, dev_info_t *pdip, i2c_nexus_t *pnex,
    i2c_port_t *port, uint32_t portno,
    bool (*name_f)(void *, uint32_t, char *, size_t), void *drv)
{
	char name[I2C_NAME_MAX];

	port->ip_portno = portno;

	avl_create(&port->ip_devices, i2c_device_compare, sizeof (i2c_dev_t),
	    offsetof(i2c_dev_t, id_link));
	list_link_init(&port->ip_ctrl_link);

	/*
	 * Ask the controller or mux for the name for this port. Right now we're
	 * not defending against duplicate names on a device. We need to do that
	 * at some point. Note, as these are calls into the driver, we want to
	 * serialize them per the general provider rules. Muxes and Controllers
	 * have the same style API for setting this.
	 */
	bzero(name, sizeof (name));

	VERIFY3P(name_f, !=, NULL);
	if (!name_f(drv, portno, name, sizeof (name))) {
		dev_err(pdip, CE_WARN, "failed to name child port %u", portno);
		return (false);
	}

	if (name[0] == '\0' || name[sizeof (name) - 1] != '\0') {
		dev_err(pdip, CE_WARN, "port %u ended up with invalid name",
		    portno);
		return (false);
	}

	for (size_t i = 0; i < sizeof (name) && name[i] != '\0'; i++) {
		if (!isalnum(name[i])) {
			dev_err(pdip, CE_WARN, "port %u name %s uses invalid "
			    "character at byte %zu", portno, name, i);
			return (false);
		}
	}

	port->ip_nex = i2cnex_nex_alloc(I2C_NEXUS_T_PORT, pdip, pnex, NULL,
	    name, ctrl);
	if (port->ip_nex == NULL) {
		dev_err(pdip, CE_WARN, "failed to allocate i2c nexus for port "
		    "%u", portno);
		return (false);
	}
	port->ip_nex->in_data.in_port = port;

	return (true);
}

/*
 * See the DDI_CTLOPS_INITCHILD case below for an explanation of why this
 * mimicry of pseudonex_auto_assign() is here.
 */
static bool
i2c_nex_assign_instance(dev_info_t *cdip)
{
	const char *drv = ddi_driver_name(cdip);
	major_t major = ddi_name_to_major(drv);

	LOCK_DEV_OPS(&devnamesp[major].dn_lock);
	for (int inst = 0; inst <= MAXMIN32; inst++) {
		dev_info_t *tdip;
		for (tdip = devnamesp[major].dn_head; tdip != NULL;
		    tdip = ddi_get_next(tdip)) {
			if (tdip == cdip)
				continue;
			if (inst == ddi_get_instance(tdip)) {
				break;
			}
		}

		if (tdip == NULL) {
			DEVI(cdip)->devi_instance = inst;
			UNLOCK_DEV_OPS(&devnamesp[major].dn_lock);
			return (true);
		}
	}

	/*
	 * No major available, fail the initialization.
	 */
	UNLOCK_DEV_OPS(&devnamesp[major].dn_lock);
	return (false);
}

/*
 * Unlike the other bus ops, this is shared by both the controller bus ops and
 * the normal i2c_nex_bus_ops.
 */
int
i2c_nex_bus_ctl(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	dev_info_t *cdip;
	i2c_nexus_t *nex;
	const char *type;

	switch (ctlop) {
	case DDI_CTLOPS_REPORTDEV:
		if (rdip == NULL) {
			return (DDI_FAILURE);
		}

		switch (nex->in_type) {
		case I2C_NEXUS_T_CTRL:
			type = "Controller";
			break;
		case I2C_NEXUS_T_PORT:
			type = "Port";
			break;
		case I2C_NEXUS_T_DEV:
			type = "Dev";
			break;
		case I2C_NEXUS_T_MUX:
			type = "Mux";
			break;
		default:
			type = "Unknown";
			break;
		}

		cmn_err(CE_CONT, "I2C %s: %s@%s, %s%d\n", type,
		    ddi_node_name(rdip), ddi_get_name_addr(rdip),
		    ddi_driver_name(rdip), ddi_get_instance(rdip));
		break;
	case DDI_CTLOPS_INITCHILD:
		cdip = arg;
		if (cdip == NULL) {
			return (DDI_FAILURE);
		}

		/*
		 * We need to check if we're a child of pseudo. If so, we won't
		 * get an instance number assigned to us due to the logic of how
		 * instance assignment works. Once something is a child of
		 * pseudo, the system expects psuedo to take charge of assigning
		 * instances. This means that we have to basically do the same
		 * thing that pseudonex_auto_assign() does. We can't really ask
		 * psuedo to do this as it would want to name our child and we
		 * can't assume that the path between us and pseudo will keep
		 * calling all the way up to pseudo. This is unfortunate, but
		 * not as unfortunate as instance -1! This uses the same logic
		 * as pseudo.
		 */
		if (is_pseudo_device(cdip) && !i2c_nex_assign_instance(cdip)) {
			return (NDI_FAILURE);
		}

		nex = ddi_get_parent_data(cdip);
		VERIFY3P(nex, !=, NULL);
		ddi_set_name_addr(cdip, nex->in_addr);
		break;
	case DDI_CTLOPS_UNINITCHILD:
		cdip = arg;
		if (cdip == NULL) {
			return (DDI_FAILURE);
		}

		ddi_set_name_addr(cdip, NULL);
		break;
	default:
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));
	}

	return (DDI_SUCCESS);
}

void
i2c_nex_bus_config_fini(i2c_nex_bus_config_t *conf)
{
	if (conf->inbc_duplen != 0) {
		kmem_free(conf->inbc_dup, conf->inbc_duplen);
		conf->inbc_dup = NULL;
		conf->inbc_duplen = 0;
		conf->inbc_addr = NULL;
	}
}

bool
i2c_nex_bus_config_init(i2c_nex_bus_config_t *conf, ddi_bus_config_op_t op,
    const void *arg)
{
	bzero(conf, sizeof (i2c_nex_bus_config_t));
	conf->inbc_op = op;
	conf->inbc_arg = arg;
	conf->inbc_ret = NDI_SUCCESS;

	if (op == BUS_CONFIG_ONE || op == BUS_UNCONFIG_ONE) {
		char *name, *addr;

		conf->inbc_duplen = strlen(arg) + 1;
		conf->inbc_dup = kmem_alloc(conf->inbc_duplen, KM_SLEEP);
		bcopy(arg, conf->inbc_dup, conf->inbc_duplen);

		i_ddi_parse_name(conf->inbc_dup, &name, &addr, NULL);
		if (name == NULL || addr == NULL || *addr == '\0') {
			i2c_nex_bus_config_fini(conf);
			return (false);
		}
		conf->inbc_name = name;
		conf->inbc_addr = addr;
	}

	return (true);
}

/*
 * This is used to clean up devices at different points.
 */
void
i2c_nex_dev_cleanup(i2c_nexus_t *nex)
{
	VERIFY3U(nex->in_type, ==, I2C_NEXUS_T_DEV);

	mutex_enter(&i2cnex_minors.im_mutex);
	if ((nex->in_flags & I2C_NEXUS_F_DISC) != 0) {
		avl_remove(&i2cnex_minors.im_nexi, nex);
		nex->in_flags &= ~I2C_NEXUS_F_DISC;
	}
	mutex_exit(&i2cnex_minors.im_mutex);

	/*
	 * We're removing this minor node outside of attach/detach context. We
	 * must inform /devices that it must clean up and rebuild so that way it
	 * can pick up the correct set of minors after this. You'll note that
	 * we're traversing one directory higher in the tree. When we pass in a
	 * dip, devfs will find the directory node for it. The devfs character
	 * devices that correspond to a minor node are in its parent's
	 * directory. Therefore to mark the proper thing to clean / rebuild, we
	 * must go up to it. Let's make this clearer with an example. Consider
	 * the following nodes:
	 *
	 *  i2csim0 (pseudo device)
	 *    i2cnex@i2csim0 (controller i2c nexus)
	 *	i2cnex@0 (port i2c nexus)
	 *	  at24c0@0,10 (i2c device)
	 *
	 * This code would be called as part of removing the at24c0@0,10 device
	 * node. When our nexus creates a minor node to perform actions on the
	 * device, it is created as i2cnex@0:0,10. Specifically device minors
	 * are on their parent nodes. In /devices, this minor node is in the
	 * i2cnex@i2csim0 directory. So if we did a devfs_clean() call to the
	 * i2cnex@0 directory, we would never find this and never rebuild it.
	 * Instead, we must call it up one parent.
	 */
	ddi_remove_minor_node(nex->in_pdip, nex->in_addr);
	(void) devfs_clean(nex->in_pnex->in_pdip, NULL, 0);
}

/*
 * Attempt to unconfigure one of our nexi. This is trickier than it might
 * appear. We have just called ndi_busop_bus_config(). This can result in
 * several different things happening:
 *
 *  - If we had BUS_UNCONFIG_ONE and we had a node that was successfully bound
 *    to a driver, then it will have been unconfigured and freed (assuming the
 *    reference count allowed it). This means that the nex->in_dip pointer is
 *    dangling!
 *  - If we had a BUS_UNCONFIG_ONE and we had a node that was never bound to a
 *    driver, then it will have failed to look up the name and address in the
 *    NDI operation. We still want to clean this up as we can identify it.
 *    A dev_info_t will only call the DDI_CTLOPS_INITCHILD entry point after it
 *    has identified a major_t to bind the driver to. If it doesn't do this it
 *    will never have an instance.
 *  - If we were called with BUS_UNCONFIG_DRIVER or BUS_UNCONFIG_ONE then it
 *    will have found the node and removed it, putting us in the first case.
 *
 * The moral of this story is that we can't assume nex->in_dip is valid. We
 * can't assume that ndi_devi_free() will succeed as we may still have a
 * reference count. We can't assume that the node has been detached either. So
 * if the node is still active and has a reference count we will return failure.
 */
static int
i2c_nex_bus_unconfig_i2cnex(i2c_nexus_t *nex)
{
	/*
	 * It's possible we're doing a sweep via a BUS_CONFIG_ALL and we've
	 * already done our work. Don't try again.
	 */
	if (nex->in_dip == NULL) {
		return (NDI_SUCCESS);
	}

	/*
	 * At this point we can't rely on the current nex->in_dip pointer to be
	 * valid. See if we can find the dip or not.
	 */
	dev_info_t *cdip;
	for (cdip = ddi_get_child(nex->in_pdip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (ddi_get_parent_data(cdip) == nex) {
			VERIFY3P(cdip, ==, nex->in_dip);
			break;
		}
	}

	/*
	 * The kernel didn't delete the dev_info_t for whatever reason. Go
	 * through and see if we should.
	 */
	if (cdip != NULL) {

		/*
		 * If we have a driver attached right now or there is still a
		 * reference count on this node, then we can't tear it down. The
		 * former is most common for our nexus drivers. The latter is
		 * when we have a child which is a device.
		 */
		if (i_ddi_devi_attached(nex->in_dip) ||
		    e_ddi_devi_holdcnt(nex->in_dip) > 0) {
			return (NDI_FAILURE);
		}

		ddi_set_parent_data(nex->in_dip, NULL);

		/*
		 * There are no registers or other properties to free at this
		 * time, so we just attempt to free the node. We expect that
		 * ndi_devi_free should not fail, but if it it does, we warn
		 * about it, but don't propagate that fact.
		 */
		if (ndi_devi_free(nex->in_dip) != NDI_SUCCESS) {
			dev_err(nex->in_dip, CE_WARN, "failed to free dip in "
			    "unconfig");
		}
	}
	nex->in_dip = NULL;

	if (nex->in_type == I2C_NEXUS_T_DEV) {
		i2c_nex_dev_cleanup(nex);
	}

	return (NDI_SUCCESS);
}

static bool
i2c_nex_bus_config_nex(i2c_nexus_t *nex)
{
	char *prop;

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		prop = I2C_NEXUS_TYPE_CTRL;
		break;
	case I2C_NEXUS_T_PORT:
		prop = I2C_NEXUS_TYPE_PORT;
		break;
	case I2C_NEXUS_T_MUX:
		prop = I2C_NEXUS_TYPE_MUX;
		break;
	default:
		panic("invalid nexus type encountered: 0x%x", nex->in_type);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, nex->in_dip,
	    I2C_NEXUS_TYPE_PROP, prop) != NDI_SUCCESS) {
		return (false);
	}

	return (true);
}

static bool
i2c_nex_bus_config_dev(i2c_nexus_t *nex)
{
	i2c_dev_t *dev = nex->in_data.in_dev;

	/*
	 * First set the #address-cells and #size-cells we have decided to use.
	 * This is slightly different from flattened device tree. We made need
	 * to revisit this at some point.
	 */
	if (ndi_prop_update_int(DDI_DEV_T_NONE, nex->in_dip, "#address-cells",
	    2) != NDI_SUCCESS) {
		return (false);
	}

	if (ndi_prop_update_int(DDI_DEV_T_NONE, nex->in_dip, "#size-cells",
	    0) != NDI_SUCCESS) {
		return (false);
	}

	if (ndi_prop_update_string(DDI_DEV_T_NONE, nex->in_dip, "device_type",
	    "i2c") != NDI_SUCCESS) {
		return (false);
	}

	/*
	 * Set up the regs[]. Right now we only track one address for a device;
	 * however, some devices end up using more than one address and/or a
	 * mask of such things. Currently those are grabbed out by clients being
	 * able to claim more addresses.
	 */
	int regs[2] = { dev->id_addr.ia_type, dev->id_addr.ia_addr };
	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, nex->in_dip, "reg", regs,
	    2) != NDI_SUCCESS) {
		return (false);
	}

	if (dev->id_nucompat > 0) {
		if (ndi_prop_update_string_array(DDI_DEV_T_NONE, nex->in_dip,
		    "compatible", dev->id_ucompat, dev->id_nucompat) !=
		    NDI_SUCCESS) {
			return (false);
		}
	}

	/*
	 * Create the minor for this device in the parent, not on the device
	 * itself.
	 */
	if (ddi_create_minor_node(nex->in_pdip, nex->in_addr, S_IFCHR,
	    nex->in_minor, DDI_NT_I2C_DEV, 0) != DDI_SUCCESS) {
		dev_err(nex->in_pdip, CE_WARN, "failed to create minor node "
		    "for child %s", nex->in_addr);
		return (false);
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_add(&i2cnex_minors.im_nexi, nex);
	nex->in_flags |= I2C_NEXUS_F_DISC;
	mutex_exit(&i2cnex_minors.im_mutex);

	return (true);
}

void
i2c_nex_bus_config_one(i2c_nexus_t *nex, i2c_nex_bus_config_t *conf)
{
	if (conf->inbc_op == BUS_CONFIG_ONE) {
		if (conf->inbc_matched) {
			return;

		}

		if (strcmp(nex->in_name, conf->inbc_name) != 0 ||
		    strcmp(nex->in_addr, conf->inbc_addr) != 0) {
			return;
		}
	}

	conf->inbc_matched = true;

	/*
	 * We're going to go ahead and create something. If this is a device,
	 * then we also need to set a bunch of properties on this. Note, it is
	 * possible that this has already been created as we're being asked to
	 * config something that already exists. In that case, we need to stop
	 * here.
	 */
	dev_info_t *cdip;
	for (cdip = ddi_get_child(nex->in_pdip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {
		if (ddi_get_parent_data(cdip) == nex) {
			VERIFY3P(cdip, ==, nex->in_dip);
			return;
		}
	}
	nex->in_dip = NULL;
	ndi_devi_alloc_sleep(nex->in_pdip, nex->in_name, DEVI_SID_NODEID,
	    &nex->in_dip);
	switch (nex->in_type) {
	case I2C_NEXUS_T_DEV:
		if (!i2c_nex_bus_config_dev(nex)) {
			goto err;
		}
		break;
	case I2C_NEXUS_T_CTRL:
	case I2C_NEXUS_T_PORT:
	case I2C_NEXUS_T_MUX:
		if (!i2c_nex_bus_config_nex(nex)) {
			goto err;
		}
		break;
	}

	ddi_set_parent_data(nex->in_dip, nex);
	(void) ndi_devi_bind_driver(nex->in_dip, 0);
	return;

err:
	(void) ndi_devi_free(nex->in_dip);
	nex->in_dip = NULL;
	conf->inbc_ret = NDI_FAILURE;
}

void
i2c_nex_bus_unconfig_one(i2c_nexus_t *nex, i2c_nex_bus_config_t *conf)
{
	if (conf->inbc_op == BUS_UNCONFIG_ONE) {
		if (conf->inbc_matched) {
			return;

		}

		if (strcmp(nex->in_name, conf->inbc_name) != 0 ||
		    strcmp(nex->in_addr, conf->inbc_addr) != 0) {
			return;
		}
	} else if (conf->inbc_op == BUS_UNCONFIG_DRIVER) {
		major_t major = (major_t)(uintptr_t)conf->inbc_arg;
		if (major != DDI_MAJOR_T_NONE && nex->in_dip != NULL &&
		    major != ddi_driver_major(nex->in_dip)) {
			return;
		}
	}

	conf->inbc_matched = true;

	int ret = i2c_nex_bus_unconfig_i2cnex(nex);
	if (ret != NDI_SUCCESS && conf->inbc_ret == NDI_SUCCESS) {
		conf->inbc_ret = ret;
	}
}

/*
 * This is our general bus configuration entry point for the i2c nexus. This is
 * used by all of the i2cnex logical nodes themselves and by the root which is a
 * specific PCI, MMIO, or some other bus controller. If pdip corresponds to a
 * driver named "i2cnex" then that is us and we know that we have an i2c_nexus_t
 * in our parent data. Otherwise, we are at the top of the tree and refer to a
 * controller and need to create the single instance.
 *
 * Like other folks, because we don't know what driver will be applied
 * (generally speaking) we treat BUS_CONFIG_ALL and BUS_CONFIG_DRIVER as the
 * same. Here's what we create and the unit address scheme at various points in
 * the tree:
 *
 * pciXXX,YYYY - i2c provider
 *    i2cnex@<ctrl name>
 *      i2cnex@port0
 *         <dev>@<i2c addr>
 *         <dev>@<i2c addr>
 *         pca9545@<addr> driver=pca954x
 *           i2cnex@pca954x0
 *             i2nex@port0
 *             i2nex@port1
 *             i2nex@port2
 *             i2nex@port3
 *               <dev>@<i2c addr>
 *      i2cnex@port1
 *
 * Our bus config operation may be called from different contexts:
 *
 * 1) It may be invoked as a result of a specific user device addition ioctl.
 *    That ends up in i2c_device_config() which makes an explicit call to
 *    bus_config.
 *
 * 2) We may be invoked by the kernel due to having finished enumeration in
 *    attach(9E) and have a bus_ops.
 *
 * 3) We may be invoked to enumerate a specific device that is in /devices. This
 *    is part of how modules can be unloaded and reloaded again.
 *
 * In the case of (2) or (3) we need to make sure we begin an i2c transaction to
 * effectively hold the controller and ensure that no one else can change the
 * current state of it. In the case of (1) though, if our thread is the one that
 * has taken action, then led us to (1), then we'll allow the use of this.
 */
static int
i2c_nex_bus_config(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg, dev_info_t **childp)
{
	i2c_port_t *port;
	i2c_dev_t *dev;
	i2c_mux_t *mux;
	i2c_nex_bus_config_t conf;
	i2c_txn_t *txn = NULL;
	i2c_nexus_t *nex = ddi_get_parent_data(pdip);
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	VERIFY3P(nex, !=, NULL);

	switch (op) {
	case BUS_CONFIG_ONE:
	case BUS_CONFIG_ALL:
	case BUS_CONFIG_DRIVER:
		ndi_devi_enter(pdip);
		break;
	default:
		return (NDI_FAILURE);
	}

	if (!i2c_nex_bus_config_init(&conf, op, arg)) {
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}

	txn = i2c_txn_alloc(ctrl, I2C_LOCK_TAG_BUS_CONFIG, pdip);
	if (i2c_txn_ctrl_lock(txn, true) != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}
	i2c_txn_nexus_op_begin(txn);

	/*
	 * Our device type determines what we should iterate over. If we're
	 * working on the controller node, it's ports. If it's a port, devices.
	 * If it's a device, then it's the ports the mux has.
	 */
	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		for (uint32_t i = 0; i < nex->in_ctrl->ic_nports; i++) {
			i2c_nex_bus_config_one(nex->in_ctrl->ic_ports[i].ip_nex,
			    &conf);
		}
		break;
	case I2C_NEXUS_T_PORT:
		port = nex->in_data.in_port;
		for (i2c_dev_t *dev = avl_first(&port->ip_devices); dev != NULL;
		    dev = AVL_NEXT(&port->ip_devices, dev)) {
			i2c_nex_bus_config_one(dev->id_nex, &conf);
		}
		break;
	case I2C_NEXUS_T_DEV:
		dev = nex->in_data.in_dev;
		if (dev->id_mux != NULL) {
			i2c_nex_bus_config_one(dev->id_mux->im_nex, &conf);
		}
		break;
	case I2C_NEXUS_T_MUX:
		mux = nex->in_data.in_mux;
		for (uint32_t i = 0; i < mux->im_nports; i++) {
			i2c_nex_bus_config_one(mux->im_ports[i].ip_nex, &conf);
		}
		break;
	}

	/*
	 * txn is non-NULL only if we didn't inherit the transaction. In that
	 * case, proceed to release it.
	 */
	i2c_txn_nexus_op_end(txn);
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);

	i2c_nex_bus_config_fini(&conf);
	ndi_devi_exit(pdip);

	if (op == BUS_CONFIG_ONE) {
		if (!conf.inbc_matched) {
			return (NDI_EINVAL);
		}

		if (conf.inbc_ret != NDI_SUCCESS) {
			return (conf.inbc_ret);
		}
	}

	flags |= NDI_ONLINE_ATTACH;
	return (ndi_busop_bus_config(pdip, flags, op, arg, childp, 0));
}

static int
i2c_nex_bus_unconfig(dev_info_t *pdip, uint_t flags, ddi_bus_config_op_t op,
    void *arg)
{
	i2c_port_t *port;
	i2c_dev_t *dev;
	i2c_mux_t *mux;
	int ret;
	i2c_nex_bus_config_t conf;
	i2c_txn_t *txn = NULL;
	i2c_nexus_t *nex = ddi_get_parent_data(pdip);
	i2c_ctrl_t *ctrl = nex->in_ctrl;

	VERIFY3P(nex, !=, NULL);

	switch (op) {
	case BUS_UNCONFIG_ONE:
	case BUS_UNCONFIG_ALL:
	case BUS_UNCONFIG_DRIVER:
		ndi_devi_enter(pdip);
		flags |= NDI_UNCONFIG;
		ret = ndi_busop_bus_unconfig(pdip, flags, op, arg);
		if (ret != NDI_SUCCESS) {
			ndi_devi_exit(pdip);
			return (ret);
		}
		break;
	default:
		return (NDI_FAILURE);
	}

	/*
	 * If we do not have a request to remove the device nodes, then there is
	 * no need for us to proceed with bus unconfig. The call to
	 * ndi_busop_bus_unconfig() will have taken care of detaching any nodes
	 * that are required.
	 */
	if ((flags & NDI_DEVI_REMOVE) == 0) {
		ndi_devi_exit(pdip);
		return (NDI_SUCCESS);
	}

	if (!i2c_nex_bus_config_init(&conf, op, arg)) {
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}

	txn = i2c_txn_alloc(ctrl, I2C_LOCK_TAG_BUS_UNCONFIG, pdip);
	if (i2c_txn_ctrl_lock(txn, true) != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		ndi_devi_exit(pdip);
		return (NDI_EINVAL);
	}
	i2c_txn_nexus_op_begin(txn);

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		for (uint32_t i = 0; i < nex->in_ctrl->ic_nports; i++) {
			i2c_port_t *port = &nex->in_ctrl->ic_ports[i];
			i2c_nex_bus_unconfig_one(port->ip_nex, &conf);
		}
		break;
	case I2C_NEXUS_T_PORT:
		port = nex->in_data.in_port;
		for (i2c_dev_t *dev = avl_first(&port->ip_devices); dev != NULL;
		    dev = AVL_NEXT(&port->ip_devices, dev)) {
			i2c_nex_bus_unconfig_one(dev->id_nex, &conf);
		}
		break;
	case I2C_NEXUS_T_DEV:
		dev = nex->in_data.in_dev;
		if (dev->id_mux != NULL) {
			i2c_nex_bus_unconfig_one(dev->id_mux->im_nex, &conf);
		}
		break;
	case I2C_NEXUS_T_MUX:
		mux = nex->in_data.in_mux;
		for (uint32_t i = 0; i < mux->im_nports; i++) {
			i2c_nex_bus_unconfig_one(mux->im_ports[i].ip_nex,
			    &conf);
		}
		break;
	}

	/*
	 * txn is non-NULL only if we didn't inherit the transaction. In that
	 * case, proceed to release it.
	 */
	i2c_txn_nexus_op_end(txn);
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);

	i2c_nex_bus_config_fini(&conf);
	ndi_devi_exit(pdip);

	if (op == BUS_UNCONFIG_ONE) {

		if (!conf.inbc_matched) {
			return (NDI_EINVAL);
		}

		if (conf.inbc_ret != NDI_SUCCESS) {
			return (conf.inbc_ret);
		}
	}

	return (NDI_SUCCESS);
}

static bool
i2c_nex_port_empty(i2c_nexus_t *nex)
{
	i2c_port_t *ports;
	uint32_t nports;

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		ports = nex->in_ctrl->ic_ports;
		nports = nex->in_ctrl->ic_nports;
		break;
	case I2C_NEXUS_T_PORT:
		ports = nex->in_data.in_port;
		nports = 1;
		break;
	case I2C_NEXUS_T_MUX:
		ports = nex->in_data.in_mux->im_ports;
		nports = nex->in_data.in_mux->im_nports;
		break;
	default:
		panic("unknown i2c nexus type: 0x%x", nex->in_type);
	}

	for (uint32_t i = 0; i < nports; i++) {
		if (avl_numnodes(&ports[i].ip_devices) > 0 ||
		    ports[i].ip_ndevs_ds > 0) {
			return (false);
		}
	}
	return (true);
}

/*
 * An I2C port may be actively used by a controller as part of its active mux
 * selection path. As part of detaching we need to inform the I/O subsystem that
 * this path is going away and to remove the port from the list of what's
 * active.
 */
static void
i2c_nex_port_deactivate(i2c_txn_t *txn, i2c_nexus_t *nex)
{
	i2c_port_t *ports;
	uint32_t nports;

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		ports = nex->in_ctrl->ic_ports;
		nports = nex->in_ctrl->ic_nports;
		break;
	case I2C_NEXUS_T_MUX:
		ports = nex->in_data.in_mux->im_ports;
		nports = nex->in_data.in_mux->im_nports;
		break;
	default:
		return;
	}

	for (uint32_t i = 0; i < nports; i++) {
		i2c_mux_remove_port(txn, nex->in_ctrl, &ports[i]);
	}
}

static void
i2c_nex_detach_ctrl(i2c_ctrl_t *ctrl)
{
	i2c_nexus_t *nex = ctrl->ic_nexus;

	mutex_enter(&i2cnex_minors.im_mutex);
	if ((nex->in_flags & I2C_NEXUS_F_DISC) != 0) {
		avl_remove(&i2cnex_minors.im_nexi, nex);
		nex->in_flags &= ~I2C_NEXUS_F_DISC;
	}
	mutex_exit(&i2cnex_minors.im_mutex);

	for (uint32_t i = 0; i < ctrl->ic_nports; i++) {
		i2c_port_fini(&ctrl->ic_ports[i]);
	}

	ddi_remove_minor_node(nex->in_dip, NULL);
}

static int
i2c_nex_attach_ctrl(i2c_ctrl_t *ctrl)
{
	i2c_nexus_t *nex = ctrl->ic_nexus;

	if (ddi_create_minor_node(nex->in_dip, "devctl", S_IFCHR, nex->in_minor,
	    DDI_NT_I2C_CTRL, 0) != DDI_SUCCESS) {
		dev_err(nex->in_dip, CE_WARN, "failed to create minor node "
		    "%s:%s", DDI_NT_I2C_CTRL, nex->in_addr);
		goto err;
	}

	for (uint32_t i = 0; i < ctrl->ic_nports; i++) {
		if (!i2c_port_init(ctrl, nex->in_dip, nex, &ctrl->ic_ports[i],
		    i, ctrl->ic_ops->i2c_port_name_f, ctrl->ic_drv)) {
			goto err;
		}
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_add(&i2cnex_minors.im_nexi, nex);
	nex->in_flags |= I2C_NEXUS_F_DISC;
	mutex_exit(&i2cnex_minors.im_mutex);

	return (DDI_SUCCESS);

err:
	i2c_nex_detach_ctrl(ctrl);
	return (DDI_FAILURE);
}

static void
i2c_nex_detach_mux(i2c_mux_t *mux)
{
	i2c_nexus_t *nex = mux->im_nex;

	mutex_enter(&i2cnex_minors.im_mutex);
	if ((nex->in_flags & I2C_NEXUS_F_DISC) != 0) {
		avl_remove(&i2cnex_minors.im_nexi, nex);
		nex->in_flags &= ~I2C_NEXUS_F_DISC;
	}
	mutex_exit(&i2cnex_minors.im_mutex);

	for (uint32_t i = 0; i < mux->im_nports; i++) {
		i2c_port_fini(&mux->im_ports[i]);
	}

	ddi_remove_minor_node(nex->in_dip, NULL);
}

static int
i2c_nex_attach_mux(i2c_mux_t *mux)
{
	i2c_nexus_t *nex = mux->im_nex;

	if (ddi_create_minor_node(nex->in_dip, "devctl", S_IFCHR, nex->in_minor,
	    DDI_NT_I2C_MUX, 0) != DDI_SUCCESS) {
		dev_err(nex->in_dip, CE_WARN, "failed to create minor node "
		    "%s:%s", DDI_NT_I2C_MUX, nex->in_addr);
		goto err;
	}

	for (uint32_t i = 0; i < mux->im_nports; i++) {
		if (!i2c_port_init(nex->in_ctrl, nex->in_dip, nex,
		    &mux->im_ports[i], i, mux->im_ops->mux_port_name_f,
		    mux->im_drv)) {
			goto err;
		}
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_add(&i2cnex_minors.im_nexi, nex);
	nex->in_flags |= I2C_NEXUS_F_DISC;
	mutex_exit(&i2cnex_minors.im_mutex);

	return (DDI_SUCCESS);

err:
	i2c_nex_detach_mux(mux);
	return (DDI_FAILURE);
}

static void
i2c_nex_detach_port(i2c_port_t *port)
{
	i2c_nexus_t *nex = port->ip_nex;

	mutex_enter(&i2cnex_minors.im_mutex);
	if ((nex->in_flags & I2C_NEXUS_F_DISC) != 0) {
		avl_remove(&i2cnex_minors.im_nexi, nex);
		nex->in_flags &= ~I2C_NEXUS_F_DISC;
	}
	mutex_exit(&i2cnex_minors.im_mutex);

	ddi_remove_minor_node(port->ip_nex->in_dip, NULL);
}

static int
i2c_nex_attach_port(i2c_port_t *port)
{
	i2c_nexus_t *nex = port->ip_nex;

	if (ddi_create_minor_node(nex->in_dip, "devctl", S_IFCHR, nex->in_minor,
	    DDI_NT_I2C_PORT, 0) != DDI_SUCCESS) {
		dev_err(nex->in_dip, CE_WARN, "failed to create minor node "
		    "%s:%s", DDI_NT_I2C_PORT, nex->in_addr);
		goto err;
	}

	mutex_enter(&i2cnex_minors.im_mutex);
	avl_add(&i2cnex_minors.im_nexi, nex);
	nex->in_flags |= I2C_NEXUS_F_DISC;
	mutex_exit(&i2cnex_minors.im_mutex);

	return (DDI_SUCCESS);

err:
	i2c_nex_detach_port(port);
	return (DDI_FAILURE);
}

static int
i2c_nex_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	i2c_nexus_t *nex;

	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	nex = ddi_get_parent_data(dip);
	if (nex == NULL) {
		dev_err(dip, CE_WARN, "missing expected i2c nexus parent "
		    "data");
		return (DDI_FAILURE);
	}

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		return (i2c_nex_attach_ctrl(nex->in_ctrl));
	case I2C_NEXUS_T_PORT:
		return (i2c_nex_attach_port(nex->in_data.in_port));
	case I2C_NEXUS_T_MUX:
		return (i2c_nex_attach_mux(nex->in_data.in_mux));
	default:
		panic("cannot attach i2c nexus type: 0x%x", nex->in_type);
	}
}

static int
i2c_nex_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resp)
{
	i2c_nexus_t *nex;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		nex = i2c_nex_find_by_minor(getminor((dev_t)arg));
		if (nex == NULL) {
			return (DDI_FAILURE);
		}

		*resp = (void *)nex->in_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		nex = i2c_nex_find_by_minor(getminor((dev_t)arg));
		if (nex == NULL) {
			return (DDI_FAILURE);
		}

		*resp = (void *)(uintptr_t)ddi_get_instance(nex->in_dip);
		break;
	}

	return (DDI_SUCCESS);
}

static int
i2c_nex_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	i2c_nexus_t *nex;

	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	nex = ddi_get_parent_data(dip);
	if (nex == NULL) {
		dev_err(dip, CE_WARN, "missing expected i2c nexus parent "
		    "data");
		return (DDI_FAILURE);
	}

	/*
	 * Ensure there are no devices active on this before we proceed to
	 * detach it. The controller lock is also required for port teardown as
	 * ports may be currently active on the controller's mux list.
	 */
	i2c_ctrl_t *ctrl = nex->in_ctrl;
	i2c_txn_t *txn = i2c_txn_alloc(ctrl, I2C_LOCK_TAG_DIP_DETACH, dip);
	if (i2c_txn_ctrl_lock(txn, true) != I2C_CORE_E_OK) {
		i2c_txn_free(txn);
		return (DDI_FAILURE);
	}

	if (!i2c_nex_port_empty(nex)) {
		i2c_txn_ctrl_unlock(txn);
		i2c_txn_free(txn);
		return (DDI_FAILURE);
	}

	i2c_nex_port_deactivate(txn, nex);

	switch (nex->in_type) {
	case I2C_NEXUS_T_CTRL:
		i2c_nex_detach_ctrl(nex->in_ctrl);
		break;
	case I2C_NEXUS_T_PORT:
		i2c_nex_detach_port(nex->in_data.in_port);
		break;
	case I2C_NEXUS_T_MUX:
		i2c_nex_detach_mux(nex->in_data.in_mux);
		break;
	default:
		panic("cannot detach i2c nexus type: 0x%x", nex->in_type);
	}
	i2c_txn_ctrl_unlock(txn);
	i2c_txn_free(txn);

	return (DDI_SUCCESS);
}

static struct cb_ops i2c_nex_cb_ops = {
	.cb_open = i2c_nex_open,
	.cb_close = i2c_nex_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = i2c_nex_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

struct bus_ops i2c_nex_bus_ops = {
	.busops_rev = BUSO_REV,
	.bus_dma_map = ddi_no_dma_map,
	.bus_dma_allochdl = ddi_no_dma_allochdl,
	.bus_dma_freehdl = ddi_no_dma_freehdl,
	.bus_dma_bindhdl = ddi_no_dma_bindhdl,
	.bus_dma_unbindhdl = ddi_no_dma_unbindhdl,
	.bus_dma_flush = ddi_no_dma_flush,
	.bus_dma_win = ddi_no_dma_win,
	.bus_dma_ctl = ddi_no_dma_mctl,
	.bus_prop_op = ddi_bus_prop_op,
	.bus_ctl = i2c_nex_bus_ctl,
	.bus_config = i2c_nex_bus_config,
	.bus_unconfig = i2c_nex_bus_unconfig
};

static struct dev_ops i2c_nex_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = i2c_nex_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = i2c_nex_attach,
	.devo_detach = i2c_nex_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_bus_ops = &i2c_nex_bus_ops,
	.devo_cb_ops = &i2c_nex_cb_ops
};

static struct modldrv i2c_nex_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "I2C Nexus",
	.drv_dev_ops = &i2c_nex_dev_ops
};

static struct modlinkage i2c_nex_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &i2c_nex_modldrv, NULL }
};

static void
i2c_nex_fini(void)
{
	mutex_destroy(&i2cnex_minors.im_mutex);
	avl_destroy(&i2cnex_minors.im_users);
	avl_destroy(&i2cnex_minors.im_nexi);
	list_destroy(&i2cnex_minors.im_roots);
	id_space_destroy(i2cnex_minors.im_user_ids);
	id_space_destroy(i2cnex_minors.im_ids);
	i2cnex_minors.im_ids = NULL;
}

static int
i2c_nex_init(void)
{
	i2cnex_minors.im_ids = id_space_create("i2cnex_minors",
	    I2C_DEV_MINOR_MIN, I2C_DEV_MINOR_MAX);
	if (i2cnex_minors.im_ids == NULL) {
		return (ENOMEM);
	}

	i2cnex_minors.im_user_ids = id_space_create("i2cnex_user_minors",
	    I2C_USER_MINOR_MIN, I2C_USER_MINOR_MAX);
	if (i2cnex_minors.im_ids == NULL) {
		id_space_destroy(i2cnex_minors.im_ids);
		return (ENOMEM);
	}

	list_create(&i2cnex_minors.im_roots, sizeof (i2c_root_t),
	    offsetof(i2c_root_t, ir_link));
	avl_create(&i2cnex_minors.im_nexi, i2c_nexus_compare,
	    sizeof (i2c_nexus_t), offsetof(i2c_nexus_t, in_avl));
	avl_create(&i2cnex_minors.im_users, i2c_user_compare,
	    sizeof (i2c_user_t), offsetof(i2c_user_t, iu_avl));
	mutex_init(&i2cnex_minors.im_mutex, NULL, MUTEX_DRIVER, NULL);

	return (0);
}

int
_init(void)
{
	int ret;

	if ((ret = i2c_nex_init()) != 0) {
		return (ret);
	}

	if ((ret = mod_install(&i2c_nex_modlinkage)) != 0) {
		i2c_nex_fini();
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&i2c_nex_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&i2c_nex_modlinkage)) == 0) {
		i2c_nex_fini();
	}

	return (ret);
}
