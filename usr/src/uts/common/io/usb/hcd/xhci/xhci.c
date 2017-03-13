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
 * Extensible Host Controller Interface (xHCI) USB Driver
 *
 * The xhci driver is an HCI driver for USB that bridges the gap between client
 * device drivers and implements the actual way that we talk to devices. The
 * xhci specification provides access to USB 3.x capable devices, as well as all
 * prior generations. Like other host controllers, it both provides the way to
 * talk to devices and also is treated like a hub (often called the root hub).
 *
 * This driver is part of the USBA (USB Architecture). It implements the HCDI
 * (host controller device interface) end of USBA. These entry points are used
 * by the USBA on behalf of client device drivers to access their devices. The
 * driver also provides notifications to deal with hot plug events, which are
 * quite common in USB.
 *
 * ----------------
 * USB Introduction
 * ----------------
 *
 * To properly understand the xhci driver and the design of the USBA HCDI
 * interfaces it implements, it helps to have a bit of background into how USB
 * devices are structured and understand how they work at a high-level.
 *
 * USB devices, like PCI devices, are broken down into different classes of
 * device. For example, with USB you have hubs, human-input devices (keyboards,
 * mice, etc.), mass storage, etc. Every device also has a vendor and device ID.
 * Many client drivers bind to an entire class of device, for example, the hubd
 * driver (to hubs) or scsa2usb (USB storage). However, there are other drivers
 * that bind to explicit IDs such as usbsprl (specific USB to Serial devices).
 *
 * USB SPEEDS AND VERSIONS
 *
 * USB devices are often referred to in two different ways. One way they're
 * described is with the USB version that they conform to. In the wild, you're
 * most likely going to see USB 1.1, 2.0, 2.1, and 3.0. However, you may also
 * see devices referred to as 'full-', 'low-', 'high-', and 'super-' speed
 * devices.
 *
 * The latter description describes the maximum theoretical speed of a given
 * device. For example, a super-speed device theoretically caps out around 5
 * Gbit/s, whereas a low-speed device caps out at 1.5 Mbit/s.
 *
 * In general, each speed usually corresponds to a specific USB protocol
 * generation. For example, all USB 3.0 devices are super-speed devices. All
 * 'high-speed' devices are USB 2.x devices. Full-speed devices are special in
 * that they can either be USB 1.x or USB 2.x devices. Low-speed devices are
 * only a USB 1.x thing, they did not jump the fire line to USB 2.x.
 *
 * USB 3.0 devices and ports generally have the wiring for both USB 2.0 and USB
 * 3.0. When a USB 3.x device is plugged into a USB 2.0 port or hub, then it
 * will report its version as USB 2.1, to indicate that it is actually a USB 3.x
 * device.
 *
 * USB ENDPOINTS
 *
 * A given USB device is made up of endpoints. A request, or transfer, is made
 * to a specific USB endpoint. These endpoints can provide different services
 * and have different expectations around the size of the data that'll be used
 * in a given request and the periodicity of requests. Endpoints themselves are
 * either used to make one-shot requests, for example, making requests to a mass
 * storage device for a given sector, or for making periodic requests where you
 * end up polling on the endpoint, for example, polling on a USB keyboard for
 * keystrokes.
 *
 * Each endpoint encodes two different pieces of information: a direction and a
 * type. There are two different directions: IN and OUT. These refer to the
 * general direction that data moves relative to the operating system. For
 * example, an IN transfer transfers data in to the operating system, from the
 * device. An OUT transfer transfers data from the operating system, out to the
 * device.
 *
 * There are four different kinds of endpoints:
 *
 * 	BULK		These transfers are large transfers of data to or from
 * 			a device. The most common use for bulk transfers is for
 * 			mass storage devices. Though they are often also used by
 * 			network devices and more. Bulk endpoints do not have an
 * 			explicit time component to them. They are always used
 * 			for one-shot transfers.
 *
 * 	CONTROL		These transfers are used to manipulate devices
 * 			themselves and are used for USB protocol level
 * 			operations (whether device-specific, class-specific, or
 * 			generic across all of USB). Unlike other transfers,
 * 			control transfers are always bi-directional and use
 * 			different kinds of transfers.
 *
 * 	INTERRUPT	Interrupt transfers are used for small transfers that
 * 			happen infrequently, but need reasonable latency. A good
 * 			example of interrupt transfers is to receive input from
 * 			a USB keyboard. Interrupt-IN transfers are generally
 * 			polled. Meaning that a client (device driver) opens up
 * 			an interrupt-IN pipe to poll on it, and receives
 * 			periodic updates whenever there is information
 * 			available. However, Interrupt transfers can be used
 * 			as one-shot transfers both going IN and OUT.
 *
 * 	ISOCHRONOUS	These transfers are things that happen once per
 * 			time-interval at a very regular rate. A good example of
 * 			these transfers are for audio and video. A device may
 * 			describe an interval as 10ms at which point it will read
 * 			or write the next batch of data every 10ms and transform
 * 			it for the user. There are no one-shot Isochronous-IN
 * 			transfers. There are one-shot Isochronous-OUT transfers,
 * 			but these are used by device drivers to always provide
 * 			the system with sufficient data.
 *
 * To find out information about the endpoints, USB devices have a series of
 * descriptors that cover different aspects of the device. For example, there
 * are endpoint descriptors which cover the properties of endpoints such as the
 * maximum packet size or polling interval.
 *
 * Descriptors exist at all levels of USB. For example, there are general
 * descriptors for every device. The USB device descriptor is described in
 * usb_dev_descr(9S). Host controllers will look at these descriptors to ensure
 * that they program the device correctly; however, they are more often used by
 * client device drivers. There are also descriptors that exist at a class
 * level. For example, the hub class has a class-specific descriptor which
 * describes properties of the hub. That information is requested for and used
 * by the hub driver.
 *
 * All of the different descriptors are gathered by the system and placed into a
 * tree which USBA sometimes calls the 'Configuration Cloud'. Client device
 * drivers gain access to this cloud and then use them to open endpoints, which
 * are called pipes in USBA (and some revisions of the USB specification).
 *
 * Each pipe gives access to a specific endpoint on the device which can be used
 * to perform transfers of a specific type and direction. For example, a mass
 * storage device often has three different endpoints, the default control
 * endpoint (which every device has), a Bulk-IN endpoint, and a Bulk-OUT
 * endpoint. The device driver ends up with three open pipes. One to the default
 * control endpoint to configure the device, and then the other two are used to
 * perform I/O.
 *
 * These routines translate more or less directly into calls to a host
 * controller driver. A request to open a pipe takes an endpoint descriptor that
 * describes the properties of the pipe, and the host controller driver (this
 * driver) goes through and does any work necessary to allow the client device
 * driver to access it. Once the pipe is open, it either makes one-shot
 * transfers specific to the transfer type or it starts performing a periodic
 * poll of an endpoint.
 *
 * All of these different actions translate into requests to the host
 * controller. The host controller driver itself is in charge of making sure
 * that all of the required resources for polling are allocated with a request
 * and then proceed to give the driver's periodic callbacks.
 *
 * HUBS AND HOST CONTROLLERS
 *
 * Every device is always plugged into a hub, even if the device is itself a
 * hub. This continues until we reach what we call the root-hub. The root-hub is
 * special in that it is not an actual USB hub, but is integrated into the host
 * controller and is manipulated in its own way. For example, the host
 * controller is used to turn on and off a given port's power. This may happen
 * over any interface, though the most common way is through PCI.
 *
 * In addition to the normal character device that exists for a host controller
 * driver, as part of attaching, the host controller binds to an instance of the
 * hubd driver. While the root-hub is a bit of a fiction, everyone models the
 * root-hub as the same as any other hub that's plugged in. The hub kernel
 * module doesn't know that the hub isn't a physical device that's been plugged
 * in. The host controller driver simulates that view by taking hub requests
 * that are made and translating them into corresponding requests that are
 * understood by the host controller, for example, reading and writing to a
 * memory mapped register.
 *
 * The hub driver polls for changes in device state using an Interrupt-IN
 * request, which is the same as is done for the root-hub. This allows the host
 * controller driver to not have to know about the implementation of device hot
 * plug, merely react to requests from a hub, the same as if it were an external
 * device. When the hub driver detects a change, it will go through the
 * corresponding state machine and attach or detach the corresponding client
 * device driver, depending if the device was inserted or removed.
 *
 * We detect the changes for the Interrupt-IN primarily based on the port state
 * change events that are delivered to the event ring. Whenever any event is
 * fired, we use this to update the hub driver about _all_ ports with
 * outstanding events. This more closely matches how a hub is supposed to behave
 * and leaves things less likely for the hub driver to end up without clearing a
 * flag on a port.
 *
 * PACKET SIZES AND BURSTING
 *
 * A given USB endpoint has an explicit packet size and a number of packets that
 * can be sent per time interval. These concepts are abstracted away from client
 * device drives usually, though they sometimes inform the upper bounds of what
 * a device can perform.
 *
 * The host controller uses this information to transform arbitrary transfer
 * requests into USB protocol packets. One of the nice things about the host
 * controllers is that they abstract away all of the signaling and semantics of
 * the actual USB protocols, allowing for life to be slightly easier in the
 * operating system.
 *
 * That said, if the host controller is not programmed correctly, these can end
 * up causing transaction errors and other problems in response to the data that
 * the host controller is trying to send or receive.
 *
 * ------------
 * Organization
 * ------------
 *
 * The driver is made up of the following files. Many of these have their own
 * theory statements to describe what they do. Here, we touch on each of the
 * purpose of each of these files.
 *
 * xhci_command.c:	This file contains the logic to issue commands to the
 * 			controller as well as the actual functions that the
 * 			other parts of the driver use to cause those commands.
 *
 * xhci_context.c:	This file manages various data structures used by the
 * 			controller to manage the controller's and device's
 * 			context data structures. See more in the xHCI Overview
 * 			and General Design for more information.
 *
 * xhci_dma.c:		This manages the allocation of DMA memory and DMA
 * 			attributes for controller, whether memory is for a
 * 			transfer or something else. This file also deals with
 * 			all the logic of getting data in and out of DMA buffers.
 *
 * xhci_endpoint.c:	This manages all of the logic of handling endpoints or
 * 			pipes. It deals with endpoint configuration, I/O
 * 			scheduling, timeouts, and callbacks to USBA.
 *
 * xhci_event.c:	This manages callbacks from the hardware to the driver.
 * 			This covers command completion notifications and I/O
 * 			notifications.
 *
 * xhci_hub.c:		This manages the virtual root-hub. It basically
 * 			implements and translates all of the USB level requests
 * 			into xhci specific implements. It also contains the
 * 			functions to register this hub with USBA.
 *
 * xhci_intr.c:		This manages the underlying interrupt allocation,
 * 			interrupt moderation, and interrupt routines.
 *
 * xhci_quirks.c:	This manages information about buggy hardware that's
 * 			been collected and experienced primarily from other
 * 			systems.
 *
 * xhci_ring.c:		This manages the abstraction of a ring in xhci, which is
 * 			the primary of communication between the driver and the
 * 			hardware, whether for the controller or a device.
 *
 * xhci_usba.c:		This implements all of the HCDI functions required by
 * 			USBA. This is the main entry point that drivers and the
 * 			kernel frameworks will reach to start any operation.
 * 			Many functions here will end up in the command and
 * 			endpoint code.
 *
 * xhci.c:		This provides the main kernel DDI interfaces and
 * 			performs device initialization.
 *
 * xhci.h:		This is the primary header file which defines
 * 			illumos-specific data structures and constants to manage
 * 			the system.
 *
 * xhcireg.h:		This header file defines all of the register offsets,
 * 			masks, and related macros. It also contains all of the
 * 			constants that are used in various structures as defined
 * 			by the specification, such as command offsets, etc.
 *
 * xhci_ioctl.h:	This contains a few private ioctls that are used by a
 * 			private debugging command. These are private.
 *
 * cmd/xhci/xhci_portsc:	This is a private utility that can be useful for
 * 				debugging xhci state. It is the only consumer of
 * 				xhci_ioctl.h and the private ioctls.
 *
 * ----------------------------------
 * xHCI Overview and Structure Layout
 * ----------------------------------
 *
 * The design and structure of this driver follows from the way that the xHCI
 * specification tells us that we have to work with hardware. First we'll give a
 * rough summary of how that works, though the xHCI 1.1 specification should be
 * referenced when going through this.
 *
 * There are three primary parts of the hardware -- registers, contexts, and
 * rings. The registers are memory mapped registers that come in four sets,
 * though all are found within the first BAR. These are used to program and
 * control the hardware and aspects of the devices. Beyond more traditional
 * device programming there are two primary sets of registers that are
 * important:
 *
 *   o Port Status and Control Registers (XHCI_PORTSC)
 *   o Doorbell Array (XHCI_DOORBELL)
 *
 * The port status and control registers are used to get and manipulate the
 * status of a given device. For example, turning on and off the power to it.
 * The Doorbell Array is used to kick off I/O operations and start the
 * processing of an I/O ring.
 *
 * The contexts are data structures that represent various pieces of information
 * in the controller. These contexts are generally filled out by the driver and
 * then acknowledged and consumed by the hardware. There are controller-wide
 * contexts (mostly managed in xhci_context.c) that are used to point to the
 * contexts that exist for each device in the system. The primary context is
 * called the Device Context Base Address Array (DCBAA).
 *
 * Each device in the system is allocated a 'slot', which is used to index into
 * the DCBAA. Slots are assigned based on issuing commands to the controller.
 * There are a fixed number of slots that determine the maximum number of
 * devices that can end up being supported in the system. Note this includes all
 * the devices plugged into the USB device tree, not just devices plugged into
 * ports on the chassis.
 *
 * For each device, there is a context structure that describes properties of
 * the device. For example, what speed is the device, is it a hub, etc. The
 * context has slots for the device and for each endpoint on the device. As
 * endpoints are enabled, their context information which describes things like
 * the maximum packet size, is filled in and enabled. The mapping between these
 * contexts look like:
 *
 *
 *      DCBAA
 *    +--------+                    Device Context
 *    | Slot 0 |------------------>+--------------+
 *    +--------+                   | Slot Context |
 *    |  ...   |                   +--------------+       +----------+
 *    +--------+   +------+        |  Endpoint 0  |------>| I/O Ring |
 *    | Slot n |-->| NULL |        | Context (Bi) |       +----------+
 *    +--------+   +------+        +--------------+
 *                                 |  Endpoint 1  |
 *                                 | Context (Out)|
 *                                 +--------------+
 *                                 |  Endpoint 1  |
 *                                 | Context (In) |
 *                                 +--------------+
 *                                 |      ...     |
 *                                 +--------------+
 *                                 | Endpoint 15  |
 *                                 | Context (In) |
 *                                 +--------------+
 *
 * These contexts are always owned by the controller, though we can read them
 * after various operations complete. Commands that toggle device state use a
 * specific input context, which is a variant of the device context. The only
 * difference is that it has an input context structure ahead of it to say which
 * sections of the device context should be evaluated.
 *
 * Each active endpoint points us to an I/O ring, which leads us to the third
 * main data structure that's used by the device: rings. Rings are made up of
 * transfer request blocks (TRBs), which are joined together to form a given
 * transfer description (TD) which represents a single I/O request.
 *
 * These rings are used to issue I/O to individual endpoints, to issue commands
 * to the controller, and to receive notification of changes and completions.
 * Issued commands go on the special ring called the command ring while the
 * change and completion notifications go on the event ring.  More details are
 * available in xhci_ring.c. Each of these structures is represented by an
 * xhci_ring_t.
 *
 * Each ring can be made up of one or more disjoint regions of DMA; however, we
 * only use a single one. This also impacts some additional registers and
 * structures that exist. The event ring has an indirection table called the
 * Event Ring Segment Table (ERST). Each entry in the table (a segment)
 * describes a chunk of the event ring.
 *
 * One other thing worth calling out is the scratchpad. The scratchpad is a way
 * for the controller to be given arbitrary memory by the OS that it can use.
 * There are two parts to the scratchpad. The first part is an array whose
 * entries contain pointers to the actual addresses for the pages. The second
 * part that we allocate are the actual pages themselves.
 *
 * -----------------------------
 * Endpoint State and Management
 * -----------------------------
 *
 * Endpoint management is one of the key parts to the xhci driver as every
 * endpoint is a pipe that a device driver uses, so they are our primary
 * currency. Endpoints are enabled and disabled when the client device drivers
 * open and close a pipe. When an endpoint is enabled, we have to fill in an
 * endpoint's context structure with information about the endpoint. These
 * basically tell the controller important properties which it uses to ensure
 * that there is adequate bandwidth for the device.
 *
 * Each endpoint has its own ring as described in the previous section. We place
 * TRBs (transfer request blocks) onto a given ring to request I/O be performed.
 * Responses are placed on the event ring, in other words, the rings associated
 * with an endpoint are purely for producing I/O.
 *
 * Endpoints have a defined state machine as described in xHCI 1.1 / 4.8.3.
 * These states generally correspond with the state of the endpoint to process
 * I/O and handle timeouts. The driver basically follows a similar state machine
 * as described there. There are some deviations. For example, what they
 * describe as 'running' we break into both the Idle and Running states below.
 * We also have a notion of timed out and quiescing. The following image
 * summarizes the states and transitions:
 *
 *     +------+                                +-----------+
 *     | Idle |---------*--------------------->|  Running  |<-+
 *     +------+         . I/O queued on        +-----------+  |
 *        ^               ring and timeout        |  |  |     |
 *        |               scheduled.              |  |  |     |
 *        |                                       |  |  |     |
 *        +-----*---------------------------------+  |  |     |
 *        |     . No I/Os remain                     |  |     |
 *        |                                          |  |     |
 *        |                +------*------------------+  |     |
 *        |                |      . Timeout             |     |
 *        |                |        fires for           |     |
 *        |                |        I/O                 |     |
 *        |                v                            v     |
 *        |          +-----------+                +--------+  |
 *        |          | Timed Out |                | Halted |  |
 *        |          +-----------+                +--------+  |
 *        |             |                           |         |
 *        |             |   +-----------+           |         |
 *        |             +-->| Quiescing |<----------+         |
 *        |                 +-----------+                     |
 *        |   No TRBs.           |                . TRBs      |
 *        |   remain .           |                . Remain    |
 *        +----------*----<------+-------->-------*-----------+
 *
 * Normally, a given endpoint will oscillate between having TRBs scheduled and
 * not. Every time a new I/O is added to the endpoint, we'll ring the doorbell,
 * making sure that we're processing the ring, presuming that the endpoint isn't
 * in one of the error states.
 *
 * To detect device hangs, we have an active timeout(9F) per active endpoint
 * that ticks at a one second rate while we still have TRBs outstanding on an
 * endpoint. Once all outstanding TRBs have been processed, the timeout will
 * stop itself and there will be no active checking until the endpoint has I/O
 * scheduled on it again.
 *
 * There are two primary ways that things can go wrong on the endpoint. We can
 * either have a timeout or an event that transitions the endpoint to the Halted
 * state. In the halted state, we need to issue explicit commands to reset the
 * endpoint before removing the I/O.
 *
 * The way we handle both a timeout and a halted condition is similar, but the
 * way they are triggered is different. When we detect a halted condition, we
 * don't immediately clean it up, and wait for the client device driver (or USBA
 * on its behalf) to issue a pipe reset. When we detect a timeout, we
 * immediately take action (assuming no other action is ongoing).
 *
 * In both cases, we quiesce the device, which takes care of dealing with taking
 * the endpoint from whatever state it may be in and taking the appropriate
 * actions based on the state machine in xHCI 1.1 / 4.8.3. The end of quiescing
 * leaves the device stopped, which allows us to update the ring's pointer and
 * remove any TRBs that are causing problems.
 *
 * As part of all this, we ensure that we can only be quiescing the device from
 * a given path at a time. Any requests to schedule I/O during this time will
 * generally fail.
 *
 * The following image describes the state machine for the timeout logic. It
 * ties into the image above.
 *
 *         +----------+                            +---------+
 *         | Disabled |-----*--------------------->| Enabled |<--+
 *         +----------+     . TRBs scheduled       +---------+   *. 1 sec timer
 *             ^              and no active          |  |  |     |  fires and
 *             |              timer.                 |  |  |     |  another
 *             |                                     |  |  +--+--+  quiesce, in
 *             |                                     |  |     |     a bad state,
 *             +------*------------------------------+  |     ^     or decrement
 *             |      . 1 sec timer                     |     |     I/O timeout
 *             |        fires and                       |     |
 *             |        no TRBs or                      |     +--------------+
 *             |        endpoint shutdown               |                    |
 *             |                                        *. . timer counter   |
 *             ^                                        |    reaches zero    |
 *             |                                        v                    |
 *             |                                +--------------+             |
 *             +-------------*---------------<--| Quiesce ring |->---*-------+
 *                           . No more          | and fail I/O |     . restart
 *                             I/Os             +--------------+       timer as
 *                                                                     more I/Os
 *
 * As we described above, when there are active TRBs and I/Os, a 1 second
 * timeout(9F) will be active. Each second, we decrement a counter on the
 * current, active I/O until either a new I/O takes the head, or the counter
 * reaches zero. If the counter reaches zero, then we go through, quiesce the
 * ring, and then clean things up.
 *
 * ------------------
 * Periodic Endpoints
 * ------------------
 *
 * It's worth calling out periodic endpoints explicitly, as they operate
 * somewhat differently. Periodic endpoints are limited to Interrupt-IN and
 * Isochronous-IN. The USBA often uses the term polling for these. That's
 * because the client only needs to make a single API call; however, they'll
 * receive multiple callbacks until either an error occurs or polling is
 * requested to be terminated.
 *
 * When we have one of these periodic requests, we end up always rescheduling
 * I/O requests, as well as, having a specific number of pre-existing I/O
 * requests to cover the periodic needs, in case of latency spikes. Normally,
 * when replying to a request, we use the request handle that we were given.
 * However, when we have a periodic request, we're required to duplicate the
 * handle before giving them data.
 *
 * However, the duplication is a bit tricky. For everything that was duplicated,
 * the framework expects us to submit data. Because of that we, don't duplicate
 * them until they are needed. This minimizes the likelihood that we have
 * outstanding requests to deal with when we encounter a fatal polling failure.
 *
 * Most of the polling setup logic happens in xhci_usba.c in
 * xhci_hcdi_periodic_init(). The consumption and duplication is handled in
 * xhci_endpoint.c.
 *
 * ----------------
 * Structure Layout
 * ----------------
 *
 * The following images relate the core data structures. The primary structure
 * in the system is the xhci_t. This is the per-controller data structure that
 * exists for each instance of the driver. From there, each device in the system
 * is represented by an xhci_device_t and each endpoint is represented by an
 * xhci_endpoint_t. For each client that opens a given endpoint, there is an
 * xhci_pipe_t. For each I/O related ring, there is an xhci_ring_t in the
 * system.
 *
 *     +------------------------+
 *     | Per-Controller         |
 *     | Structure              |
 *     | xhci_t                 |
 *     |                        |
 *     | uint_t              ---+--> Capability regs offset
 *     | uint_t              ---+--> Operational regs offset
 *     | uint_t              ---+--> Runtime regs offset
 *     | uint_t              ---+--> Doorbell regs offset
 *     | xhci_state_flags_t  ---+--> Device state flags
 *     | xhci_quirks_t       ---+--> Device quirk flags
 *     | xhci_capability_t   ---+--> Controller capability structure
 *     | xhci_dcbaa_t        ---+----------------------------------+
 *     | xhci_scratchpad_t   ---+---------+                        |
 *     | xhci_command_ing_t  ---+------+  |                        v
 *     | xhci_event_ring_t   ---+----+ |  |              +---------------------+
 *     | xhci_usba_t         ---+--+ | |  |              | Device Context      |
 *     +------------------------+  | | |  |              | Base Address        |
 *                                 | | |  |              | Array Structure     |
 *                                 | | |  |              | xhci_dcbaa_t        |
 * +-------------------------------+ | |  |              |                     |
 * | +-------------------------------+ |  |  DCBAA KVA <-+--        uint64_t * |
 * | |    +----------------------------+  | DMA Buffer <-+-- xhci_dma_buffer_t |
 * | |    v                               |              +---------------------+
 * | | +--------------------------+       +-----------------------+
 * | | | Event Ring               |                               |
 * | | | Management               |                               |
 * | | | xhci_event_ring_t        |                               v
 * | | |                          |   Event Ring        +----------------------+
 * | | | xhci_event_segment_t * --|-> Segment VA        |   Scratchpad (Extra  |
 * | | | xhci_dma_buffer_t      --|-> Segment DMA Buf.  |   Controller Memory) |
 * | | | xhci_ring_t            --|--+                  |    xhci_scratchpad_t |
 * | | +--------------------------+  |      Scratchpad  |                      |
 * | |                               | Base Array KVA <-+-          uint64_t * |
 * | +------------+                  | Array DMA Buf. <-+-   xhci_dma_buffer_t |
 * |              v                  | Scratchpad DMA <-+- xhci_dma_buffer_t * |
 * |   +---------------------------+ | Buffer per page  +----------------------+
 * |   | Command Ring              | |
 * |   | xhci_command_ring_t       | +------------------------------+
 * |   |                           |                                |
 * |   | xhci_ring_t             --+-> Command Ring --->------------+
 * |   | list_t                  --+-> Command List                 v
 * |   | timeout_id_t            --+-> Timeout State     +---------------------+
 * |   | xhci_command_ring_state_t +-> State Flags       | I/O Ring            |
 * |   +---------------------------+                     | xhci_ring_t         |
 * |                                                     |                     |
 * |                                     Ring DMA Buf. <-+-- xhci_dma_buffer_t |
 * |                                       Ring Length <-+--            uint_t |
 * |                                    Ring Entry KVA <-+--      xhci_trb_t * |
 * |    +---------------------------+        Ring Head <-+--            uint_t |
 * +--->| USBA State                |        Ring Tail <-+--            uint_t |
 *      | xhci_usba_t               |       Ring Cycle <-+--            uint_t |
 *      |                           |                    +---------------------+
 *      | usba_hcdi_ops_t *        -+-> USBA Ops Vector                       ^
 *      | usb_dev_dscr_t           -+-> USB Virtual Device Descriptor         |
 *      | usb_ss_hub_descr_t       -+-> USB Virtual Hub Descriptor            |
 *      | usba_pipe_handle_data_t * +-> Interrupt polling client              |
 *      | usb_intr_req_t           -+-> Interrupt polling request             |
 *      | uint32_t                --+-> Interrupt polling device mask         |
 *      | list_t                  --+-> Pipe List (Active Users)              |
 *      | list_t                  --+-------------------+                     |
 *      +---------------------------+                   |                     ^
 *                                                      |                     |
 *                                                      v                     |
 *     +-------------------------------+             +---------------+        |
 *     | USB Device                    |------------>| USB Device    |--> ... |
 *     | xhci_device_t                 |             | xhci_device_t |        |
 *     |                               |             +---------------+        |
 *     | usb_port_t                  --+-> USB Port plugged into              |
 *     | uint8_t                     --+-> Slot Number                        |
 *     | boolean_t                   --+-> Address Assigned                   |
 *     | usba_device_t *             --+-> USBA Device State                  |
 *     | xhci_dma_buffer_t           --+-> Input Context DMA Buffer           |
 *     | xhci_input_context_t *      --+-> Input Context KVA                  |
 *     | xhci_slot_contex_t *        --+-> Input Slot Context KVA             |
 *     | xhci_endpoint_context_t *[] --+-> Input Endpoint Context KVA         |
 *     | xhci_dma_buffer_t           --+-> Output Context DMA Buffer          |
 *     | xhci_slot_context_t *       --+-> Output Slot Context KVA            ^
 *     | xhci_endpoint_context_t *[] --+-> Output Endpoint Context KVA        |
 *     | xhci_endpoint_t *[]         --+-> Endpoint Tracking ---+             |
 *     +-------------------------------+                        |             |
 *                                                              |             |
 *                                                              v             |
 *     +------------------------------+            +-----------------+        |
 *     | Endpoint Data                |----------->| Endpoint Data   |--> ... |
 *     | xhci_endpoint_t              |            | xhci_endpoint_t |        |
 *     |                              |            +-----------------+        |
 *     | int                        --+-> Endpoint Number                     |
 *     | int                        --+-> Endpoint Type                       |
 *     | xhci_endpoint_state_t      --+-> Endpoint State                      |
 *     | timeout_id_t               --+-> Endpoint Timeout State              |
 *     | usba_pipe_handle_data_t *  --+-> USBA Client Handle                  |
 *     | xhci_ring_t                --+-> Endpoint I/O Ring  -------->--------+
 *     | list_t                     --+-> Transfer List --------+
 *     +------------------------------+                         |
 *                                                              v
 *     +-------------------------+                  +--------------------+
 *     | Transfer Structure      |----------------->| Transfer Structure |-> ...
 *     | xhci_transfer_t         |                  | xhci_transfer_t    |
 *     |                         |                  +--------------------+
 *     | xhci_dma_buffer_t     --+-> I/O DMA Buffer
 *     | uint_t                --+-> Number of TRBs
 *     | uint_t                --+-> Short transfer data
 *     | uint_t                --+-> Timeout seconds remaining
 *     | usb_cr_t              --+-> USB Transfer return value
 *     | boolean_t             --+-> Data direction
 *     | xhci_trb_t *          --+-> Host-order transfer requests for I/O
 *     | usb_isoc_pkt_descr_t * -+-> Isochronous only response data
 *     | usb_opaque_t          --+-> USBA Request Handle
 *     +-------------------------+
 *
 * -------------
 * Lock Ordering
 * -------------
 *
 * There are three different tiers of locks that exist in the driver. First,
 * there is a lock for each controller: xhci_t`xhci_lock. This protects all the
 * data for that instance of the controller. If there are multiple instances of
 * the xHCI controller in the system, each one is independent and protected
 * separately. The two do not share any data.
 *
 * From there, there are two other, specific locks in the system:
 *
 *   o xhci_command_ring_t`xcr_lock
 *   o xhci_device_t`xd_imtx
 *
 * There is only one xcr_lock per controller, like the xhci_lock. It protects
 * the state of the command ring. However, there is on xd_imtx per device.
 * Recall that each device is scoped to a given controller. This protects the
 * input slot context for a given device.
 *
 * There are a few important rules to keep in mind here that are true
 * universally throughout the driver:
 *
 * 1) Always grab the xhci_t`xhci_lock, before grabbing any of the other locks.
 * 2) A given xhci_device_t`xd_imtx, must be taken before grabbing the
 *    xhci_command_ring_t`xcr_lock.
 * 3) A given thread can only hold one of the given xhci_device_t`xd_imtx locks
 *    at a given time. In other words, we should never be manipulating the input
 *    context of two different devices at once.
 * 4) It is safe to hold the xhci_device_t`xd_imtx while tearing down the
 *    endpoint timer. Conversely, the endpoint specific logic should never enter
 *    this lock.
 *
 * --------------------
 * Relationship to EHCI
 * --------------------
 *
 * On some Intel chipsets, a given physical port on the system may be routed to
 * one of the EHCI or xHCI controllers. This association can be dynamically
 * changed by writing to platform specific registers as handled by the quirk
 * logic in xhci_quirk.c.
 *
 * As these ports may support USB 3.x speeds, we always route all such ports to
 * the xHCI controller, when supported. In addition, to minimize disruptions
 * from devices being enumerated and attached to the EHCI driver and then
 * disappearing, we generally attempt to load the xHCI controller before the
 * EHCI controller. This logic is not done in the driver; however, it is done in
 * other parts of the kernel like in uts/common/io/consconfig_dacf.c in the
 * function consconfig_load_drivres().
 *
 * -----------
 * Future Work
 * -----------
 *
 * The primary future work in this driver spans two different, but related
 * areas. The first area is around controller resets and how they tie into FM.
 * Presently, we do not have a good way to handle controllers coming and going
 * in the broader USB stack or properly reconfigure the device after a reset.
 * Secondly, we don't handle the suspend and resume of devices and drivers.
 */

#include <sys/param.h>
#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/ddifm.h>
#include <sys/pci.h>
#include <sys/class.h>
#include <sys/policy.h>

#include <sys/usb/hcd/xhci/xhci.h>
#include <sys/usb/hcd/xhci/xhci_ioctl.h>

/*
 * We want to use the first BAR to access its registers. The regs[] array is
 * ordered based on the rules for the PCI supplement to IEEE 1275. So regs[1]
 * will always be the first BAR.
 */
#define	XHCI_REG_NUMBER	1

/*
 * This task queue exists as a global taskq that is used for resetting the
 * device in the face of FM or runtime errors. Each instance of the device
 * (xhci_t) happens to have a single taskq_dispatch_ent already allocated so we
 * know that we should always be able to dispatch such an event.
 */
static taskq_t *xhci_taskq;

/*
 * Global soft state for per-instance data. Note that we must use the soft state
 * routines and cannot use the ddi_set_driver_private() routines. The USB
 * framework presumes that it can use the dip's private data.
 */
void *xhci_soft_state;

/*
 * This is the time in us that we wait after a controller resets before we
 * consider reading any register. There are some controllers that want at least
 * 1 ms, therefore we default to 10 ms.
 */
clock_t xhci_reset_delay = 10000;

void
xhci_error(xhci_t *xhcip, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (xhcip != NULL && xhcip->xhci_dip != NULL) {
		vdev_err(xhcip->xhci_dip, CE_WARN, fmt, ap);
	} else {
		vcmn_err(CE_WARN, fmt, ap);
	}
	va_end(ap);
}

void
xhci_log(xhci_t *xhcip, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (xhcip != NULL && xhcip->xhci_dip != NULL) {
		vdev_err(xhcip->xhci_dip, CE_NOTE, fmt, ap);
	} else {
		vcmn_err(CE_NOTE, fmt, ap);
	}
	va_end(ap);
}

/*
 * USBA is in charge of creating device nodes for us. USBA explicitly ORs in the
 * constant HUBD_IS_ROOT_HUB, so we have to undo that when we're looking at
 * things here. A simple bitwise-and will take care of this. And hey, it could
 * always be more complex, USBA could clone!
 */
static dev_info_t *
xhci_get_dip(dev_t dev)
{
	xhci_t *xhcip;
	int instance = getminor(dev) & ~HUBD_IS_ROOT_HUB;

	xhcip = ddi_get_soft_state(xhci_soft_state, instance);
	if (xhcip != NULL)
		return (xhcip->xhci_dip);
	return (NULL);
}

uint8_t
xhci_get8(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	return (ddi_get8(xhcip->xhci_regs_handle, (void *)addr));
}

uint16_t
xhci_get16(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	return (ddi_get16(xhcip->xhci_regs_handle, (void *)addr));
}

uint32_t
xhci_get32(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	return (ddi_get32(xhcip->xhci_regs_handle, (void *)addr));
}

uint64_t
xhci_get64(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	return (ddi_get64(xhcip->xhci_regs_handle, (void *)addr));
}

void
xhci_put8(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off, uint8_t val)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	ddi_put8(xhcip->xhci_regs_handle, (void *)addr, val);
}

void
xhci_put16(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off, uint16_t val)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	ddi_put16(xhcip->xhci_regs_handle, (void *)addr, val);
}

void
xhci_put32(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off, uint32_t val)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	ddi_put32(xhcip->xhci_regs_handle, (void *)addr, val);
}

void
xhci_put64(xhci_t *xhcip, xhci_reg_type_t rtt, uintptr_t off, uint64_t val)
{
	uintptr_t addr, roff;

	switch (rtt) {
	case XHCI_R_CAP:
		roff = xhcip->xhci_regs_capoff;
		break;
	case XHCI_R_OPER:
		roff = xhcip->xhci_regs_operoff;
		break;
	case XHCI_R_RUN:
		roff = xhcip->xhci_regs_runoff;
		break;
	case XHCI_R_DOOR:
		roff = xhcip->xhci_regs_dooroff;
		break;
	default:
		panic("called %s with bad reg type: %d", __func__, rtt);
	}
	ASSERT(roff != PCI_EINVAL32);
	addr = roff + off + (uintptr_t)xhcip->xhci_regs_base;

	ddi_put64(xhcip->xhci_regs_handle, (void *)addr, val);
}

int
xhci_check_regs_acc(xhci_t *xhcip)
{
	ddi_fm_error_t de;

	/*
	 * Treat the case where we can't check as fine so we can treat the code
	 * more simply.
	 */
	if (!DDI_FM_ACC_ERR_CAP(xhcip->xhci_fm_caps))
		return (DDI_FM_OK);

	ddi_fm_acc_err_get(xhcip->xhci_regs_handle, &de, DDI_FME_VERSION);
	ddi_fm_acc_err_clear(xhcip->xhci_regs_handle, DDI_FME_VERSION);
	return (de.fme_status);
}

/*
 * As a leaf PCIe driver, we just post the ereport and continue on.
 */
/* ARGSUSED */
static int
xhci_fm_error_cb(dev_info_t *dip, ddi_fm_error_t *err, const void *impl_data)
{
	pci_ereport_post(dip, err, NULL);
	return (err->fme_status);
}

static void
xhci_fm_fini(xhci_t *xhcip)
{
	if (xhcip->xhci_fm_caps == 0)
		return;

	if (DDI_FM_ERRCB_CAP(xhcip->xhci_fm_caps))
		ddi_fm_handler_unregister(xhcip->xhci_dip);

	if (DDI_FM_EREPORT_CAP(xhcip->xhci_fm_caps) ||
	    DDI_FM_ERRCB_CAP(xhcip->xhci_fm_caps))
		pci_ereport_teardown(xhcip->xhci_dip);

	ddi_fm_fini(xhcip->xhci_dip);
}

static void
xhci_fm_init(xhci_t *xhcip)
{
	ddi_iblock_cookie_t iblk;
	int def = DDI_FM_EREPORT_CAPABLE | DDI_FM_ACCCHK_CAPABLE |
	    DDI_FM_DMACHK_CAPABLE | DDI_FM_ERRCB_CAPABLE;

	xhcip->xhci_fm_caps = ddi_prop_get_int(DDI_DEV_T_ANY, xhcip->xhci_dip,
	    DDI_PROP_DONTPASS, "fm_capable", def);

	if (xhcip->xhci_fm_caps < 0) {
		xhcip->xhci_fm_caps = 0;
	} else if (xhcip->xhci_fm_caps & ~def) {
		xhcip->xhci_fm_caps &= def;
	}

	if (xhcip->xhci_fm_caps == 0)
		return;

	ddi_fm_init(xhcip->xhci_dip, &xhcip->xhci_fm_caps, &iblk);
	if (DDI_FM_EREPORT_CAP(xhcip->xhci_fm_caps) ||
	    DDI_FM_ERRCB_CAP(xhcip->xhci_fm_caps)) {
		pci_ereport_setup(xhcip->xhci_dip);
	}

	if (DDI_FM_ERRCB_CAP(xhcip->xhci_fm_caps)) {
		ddi_fm_handler_register(xhcip->xhci_dip,
		    xhci_fm_error_cb, xhcip);
	}
}

static int
xhci_reg_poll(xhci_t *xhcip, xhci_reg_type_t rt, int reg, uint32_t mask,
    uint32_t targ, uint_t tries, int delay_ms)
{
	uint_t i;

	for (i = 0; i < tries; i++) {
		uint32_t val = xhci_get32(xhcip, rt, reg);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			return (EIO);
		}

		if ((val & mask) == targ)
			return (0);

		delay(drv_usectohz(delay_ms * 1000));
	}
	return (ETIMEDOUT);
}

static boolean_t
xhci_regs_map(xhci_t *xhcip)
{
	off_t memsize;
	int ret;
	ddi_device_acc_attr_t da;

	if (ddi_dev_regsize(xhcip->xhci_dip, XHCI_REG_NUMBER, &memsize) !=
	    DDI_SUCCESS) {
		xhci_error(xhcip, "failed to get register set size");
		return (B_FALSE);
	}

	bzero(&da, sizeof (ddi_device_acc_attr_t));
	da.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	da.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	da.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	if (DDI_FM_ACC_ERR_CAP(xhcip->xhci_fm_caps)) {
		da.devacc_attr_access = DDI_FLAGERR_ACC;
	} else {
		da.devacc_attr_access = DDI_DEFAULT_ACC;
	}

	ret = ddi_regs_map_setup(xhcip->xhci_dip, XHCI_REG_NUMBER,
	    &xhcip->xhci_regs_base, 0, memsize, &da, &xhcip->xhci_regs_handle);

	if (ret != DDI_SUCCESS) {
		xhci_error(xhcip, "failed to map device registers: %d", ret);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
xhci_regs_init(xhci_t *xhcip)
{
	/*
	 * The capabilities always begin at offset zero.
	 */
	xhcip->xhci_regs_capoff = 0;
	xhcip->xhci_regs_operoff = xhci_get8(xhcip, XHCI_R_CAP, XHCI_CAPLENGTH);
	xhcip->xhci_regs_runoff = xhci_get32(xhcip, XHCI_R_CAP, XHCI_RTSOFF);
	xhcip->xhci_regs_runoff &= ~0x1f;
	xhcip->xhci_regs_dooroff = xhci_get32(xhcip, XHCI_R_CAP, XHCI_DBOFF);
	xhcip->xhci_regs_dooroff &= ~0x3;

	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to initialize controller register "
		    "offsets: encountered FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Read various parameters from PCI configuration space and from the Capability
 * registers that we'll need to register the device. We cache all of the
 * Capability registers.
 */
static boolean_t
xhci_read_params(xhci_t *xhcip)
{
	uint8_t usb;
	uint16_t vers;
	uint32_t struc1, struc2, struc3, cap1, cap2, pgsz;
	uint32_t psize, pbit;
	xhci_capability_t *xcap;
	unsigned long ps;

	usb = pci_config_get8(xhcip->xhci_cfg_handle, PCI_XHCI_USBREV);
	vers = xhci_get16(xhcip, XHCI_R_CAP, XHCI_HCIVERSION);
	struc1 = xhci_get32(xhcip, XHCI_R_CAP, XHCI_HCSPARAMS1);
	struc2 = xhci_get32(xhcip, XHCI_R_CAP, XHCI_HCSPARAMS2);
	struc3 = xhci_get32(xhcip, XHCI_R_CAP, XHCI_HCSPARAMS3);
	cap1 = xhci_get32(xhcip, XHCI_R_CAP, XHCI_HCCPARAMS1);
	cap2 = xhci_get32(xhcip, XHCI_R_CAP, XHCI_HCCPARAMS2);
	pgsz = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PAGESIZE);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read controller parameters: "
		    "encountered FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}

	xcap = &xhcip->xhci_caps;
	xcap->xcap_usb_vers = usb;
	xcap->xcap_hci_vers = vers;
	xcap->xcap_max_slots = XHCI_HCS1_DEVSLOT_MAX(struc1);
	xcap->xcap_max_intrs = XHCI_HCS1_IRQ_MAX(struc1);
	xcap->xcap_max_ports = XHCI_HCS1_N_PORTS(struc1);
	if (xcap->xcap_max_ports > MAX_PORTS) {
		xhci_error(xhcip, "Root hub has %d ports, but system only "
		    "supports %d, limiting to %d\n", xcap->xcap_max_ports,
		    MAX_PORTS, MAX_PORTS);
		xcap->xcap_max_ports = MAX_PORTS;
	}

	xcap->xcap_ist_micro = XHCI_HCS2_IST_MICRO(struc2);
	xcap->xcap_ist = XHCI_HCS2_IST(struc2);
	xcap->xcap_max_esrt = XHCI_HCS2_ERST_MAX(struc2);
	xcap->xcap_scratch_restore = XHCI_HCS2_SPR(struc2);
	xcap->xcap_max_scratch = XHCI_HCS2_SPB_MAX(struc2);

	xcap->xcap_u1_lat = XHCI_HCS3_U1_DEL(struc3);
	xcap->xcap_u2_lat = XHCI_HCS3_U2_DEL(struc3);

	xcap->xcap_flags = XHCI_HCC1_FLAGS_MASK(cap1);
	xcap->xcap_max_psa = XHCI_HCC1_PSA_SZ_MAX(cap1);
	xcap->xcap_xecp_off = XHCI_HCC1_XECP(cap1);
	xcap->xcap_flags2 = XHCI_HCC2_FLAGS_MASK(cap2);

	/*
	 * We don't have documentation for what changed from before xHCI 0.96,
	 * so we just refuse to support versions before 0.96. We also will
	 * ignore anything with a major version greater than 1.
	 */
	if (xcap->xcap_hci_vers < 0x96 || xcap->xcap_hci_vers >= 0x200) {
		xhci_error(xhcip, "Encountered unsupported xHCI version 0.%2x",
		    xcap->xcap_hci_vers);
		return (B_FALSE);
	}

	/*
	 * Determine the smallest size page that the controller supports and
	 * make sure that it matches our pagesize. We basically check here for
	 * the presence of 4k and 8k pages. The basis of the pagesize is used
	 * extensively throughout the code and specification. While we could
	 * support other page sizes here, given that we don't support systems
	 * with it at this time, it doesn't make much sense.
	 */
	ps = PAGESIZE;
	if (ps == 0x1000) {
		pbit = XHCI_PAGESIZE_4K;
		psize = 0x1000;
	} else if (ps == 0x2000) {
		pbit = XHCI_PAGESIZE_8K;
		psize = 0x2000;
	} else {
		xhci_error(xhcip, "Encountered host page size that the driver "
		    "doesn't know how to handle: %lx\n", ps);
		return (B_FALSE);
	}

	if (!(pgsz & pbit)) {
		xhci_error(xhcip, "Encountered controller that didn't support "
		    "the host page size (%d), supports: %x", psize, pgsz);
		return (B_FALSE);
	}
	xcap->xcap_pagesize = psize;

	return (B_TRUE);
}

/*
 * Apply known workarounds and issues. These reports come from other
 * Operating Systems and have been collected over time.
 */
static boolean_t
xhci_identify(xhci_t *xhcip)
{
	xhci_quirks_populate(xhcip);

	if (xhcip->xhci_quirks & XHCI_QUIRK_NO_MSI) {
		xhcip->xhci_caps.xcap_intr_types = DDI_INTR_TYPE_FIXED;
	} else {
		xhcip->xhci_caps.xcap_intr_types = DDI_INTR_TYPE_FIXED |
		    DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_MSIX;
	}

	if (xhcip->xhci_quirks & XHCI_QUIRK_32_ONLY) {
		xhcip->xhci_caps.xcap_flags &= ~XCAP_AC64;
	}

	return (B_TRUE);
}

static boolean_t
xhci_alloc_intr_handle(xhci_t *xhcip, int type)
{
	int ret;

	/*
	 * Normally a well-behaving driver would more carefully request an
	 * amount of interrupts based on the number available, etc. But since we
	 * only actually want a single interrupt, we're just going to go ahead
	 * and ask for a single interrupt.
	 */
	ret = ddi_intr_alloc(xhcip->xhci_dip, &xhcip->xhci_intr_hdl, type, 0,
	    XHCI_NINTR, &xhcip->xhci_intr_num, DDI_INTR_ALLOC_NORMAL);
	if (ret != DDI_SUCCESS) {
		xhci_log(xhcip, "!failed to allocate interrupts of type %d: %d",
		    type, ret);
		return (B_FALSE);
	}
	xhcip->xhci_intr_type = type;

	return (B_TRUE);
}

static boolean_t
xhci_alloc_intrs(xhci_t *xhcip)
{
	int intr_types, ret;

	if (XHCI_NINTR > xhcip->xhci_caps.xcap_max_intrs) {
		xhci_error(xhcip, "controller does not support the minimum "
		    "number of interrupts required (%d), supports %d",
		    XHCI_NINTR, xhcip->xhci_caps.xcap_max_intrs);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_supported_types(xhcip->xhci_dip,
	    &intr_types)) != DDI_SUCCESS) {
		xhci_error(xhcip, "failed to get supported interrupt types: "
		    "%d", ret);
		return (B_FALSE);
	}

	/*
	 * Mask off interrupt types we've already ruled out due to quirks or
	 * other reasons.
	 */
	intr_types &= xhcip->xhci_caps.xcap_intr_types;
	if (intr_types & DDI_INTR_TYPE_MSIX) {
		if (xhci_alloc_intr_handle(xhcip, DDI_INTR_TYPE_MSIX))
			return (B_TRUE);
	}

	if (intr_types & DDI_INTR_TYPE_MSI) {
		if (xhci_alloc_intr_handle(xhcip, DDI_INTR_TYPE_MSI))
			return (B_TRUE);
	}

	if (intr_types & DDI_INTR_TYPE_FIXED) {
		if (xhci_alloc_intr_handle(xhcip, DDI_INTR_TYPE_FIXED))
			return (B_TRUE);
	}

	xhci_error(xhcip, "failed to allocate an interrupt, supported types: "
	    "0x%x", intr_types);
	return (B_FALSE);
}

static boolean_t
xhci_add_intr_handler(xhci_t *xhcip)
{
	int ret;

	if ((ret = ddi_intr_get_pri(xhcip->xhci_intr_hdl,
	    &xhcip->xhci_intr_pri)) != DDI_SUCCESS) {
		xhci_error(xhcip, "failed to get interrupt priority: %d", ret);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_get_cap(xhcip->xhci_intr_hdl,
	    &xhcip->xhci_intr_caps)) != DDI_SUCCESS) {
		xhci_error(xhcip, "failed to get interrupt capabilities: %d",
		    ret);
		return (B_FALSE);
	}

	if ((ret = ddi_intr_add_handler(xhcip->xhci_intr_hdl, xhci_intr, xhcip,
	    (uintptr_t)0)) != DDI_SUCCESS) {
		xhci_error(xhcip, "failed to add interrupt handler: %d", ret);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/*
 * Find a capability with an identifier whose value is 'id'. The 'init' argument
 * gives us the offset to start searching at. See xHCI 1.1 / 7 for more
 * information. This is more or less exactly like PCI capabilities.
 */
static boolean_t
xhci_find_ext_cap(xhci_t *xhcip, uint32_t id, uint32_t init, uint32_t *outp)
{
	uint32_t off;
	uint8_t next = 0;

	/*
	 * If we have no offset, we're done.
	 */
	if (xhcip->xhci_caps.xcap_xecp_off == 0)
		return (B_FALSE);

	off = xhcip->xhci_caps.xcap_xecp_off << 2;
	do {
		uint32_t cap_hdr;

		off += next << 2;
		cap_hdr = xhci_get32(xhcip, XHCI_R_CAP, off);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "failed to read xhci extended "
			    "capabilities at offset 0x%x: encountered FM "
			    "register error", off);
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			break;
		}

		if (cap_hdr == PCI_EINVAL32)
			break;
		if (XHCI_XECP_ID(cap_hdr) == id &&
		    (init == UINT32_MAX || off > init)) {
			*outp = off;
			return (B_TRUE);
		}
		next = XHCI_XECP_NEXT(cap_hdr);
		/*
		 * Watch out for overflow if we somehow end up with a more than
		 * 2 GiB space.
		 */
		if (next << 2 > (INT32_MAX - off))
			return (B_FALSE);
	} while (next != 0);

	return (B_FALSE);
}

/*
 * For mostly information purposes, we'd like to walk to augment the devinfo
 * tree with the number of ports that support USB 2 and USB 3. Note though that
 * these ports may be overlapping. Many ports can support both USB 2 and USB 3
 * and are wired up to the same physical port, even though they show up as
 * separate 'ports' in the xhci sense.
 */
static boolean_t
xhci_port_count(xhci_t *xhcip)
{
	uint_t nusb2 = 0, nusb3 = 0;
	uint32_t off = UINT32_MAX;

	while (xhci_find_ext_cap(xhcip, XHCI_ID_PROTOCOLS, off, &off) ==
	    B_TRUE) {
		uint32_t rvers, rport;

		/*
		 * See xHCI 1.1 / 7.2 for the format of this. The first uint32_t
		 * has version information while the third uint32_t has the port
		 * count.
		 */
		rvers = xhci_get32(xhcip, XHCI_R_CAP, off);
		rport = xhci_get32(xhcip, XHCI_R_CAP, off + 8);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "failed to read xhci port counts: "
			    "encountered fatal FM register error");
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			return (B_FALSE);
		}

		rvers = XHCI_XECP_PROT_MAJOR(rvers);
		rport = XHCI_XECP_PROT_PCOUNT(rport);

		if (rvers == 3) {
			nusb3 += rport;
		} else if (rvers <= 2) {
			nusb2 += rport;
		} else {
			xhci_error(xhcip, "encountered port capabilities with "
			    "unknown major USB version: %d\n", rvers);
		}
	}

	(void) ddi_prop_update_int(DDI_DEV_T_NONE, xhcip->xhci_dip,
	    "usb2-capable-ports", nusb2);
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, xhcip->xhci_dip,
	    "usb3-capable-ports", nusb3);

	return (B_TRUE);
}

/*
 * Take over control from the BIOS or other firmware, if applicable.
 */
static boolean_t
xhci_controller_takeover(xhci_t *xhcip)
{
	int ret;
	uint32_t val, off;

	/*
	 * If we can't find the legacy capability, then there's nothing to do.
	 */
	if (xhci_find_ext_cap(xhcip, XHCI_ID_USB_LEGACY, UINT32_MAX, &off) ==
	    B_FALSE)
		return (B_TRUE);
	val = xhci_get32(xhcip, XHCI_R_CAP, off);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read BIOS take over registers: "
		    "encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}

	if (val & XHCI_BIOS_OWNED) {
		val |= XHCI_OS_OWNED;
		xhci_put32(xhcip, XHCI_R_CAP, off, val);
		if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
			xhci_error(xhcip, "failed to write BIOS take over "
			    "registers: encountered fatal FM register error");
			ddi_fm_service_impact(xhcip->xhci_dip,
			    DDI_SERVICE_LOST);
			return (B_FALSE);
		}

		/*
		 * Wait up to 5 seconds for things to change. While this number
		 * isn't specified in the xHCI spec, it seems to be the de facto
		 * value that various systems are using today. We'll use a 10ms
		 * interval to check.
		 */
		ret = xhci_reg_poll(xhcip, XHCI_R_CAP, off,
		    XHCI_BIOS_OWNED | XHCI_OS_OWNED, XHCI_OS_OWNED, 500, 10);
		if (ret == EIO)
			return (B_FALSE);
		if (ret == ETIMEDOUT) {
			xhci_log(xhcip, "!timed out waiting for firmware to "
			    "hand off, taking over");
			val &= ~XHCI_BIOS_OWNED;
			xhci_put32(xhcip, XHCI_R_CAP, off, val);
			if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
				xhci_error(xhcip, "failed to write forced "
				    "takeover: encountered fatal FM register "
				    "error");
				ddi_fm_service_impact(xhcip->xhci_dip,
				    DDI_SERVICE_LOST);
				return (B_FALSE);
			}
		}
	}

	val = xhci_get32(xhcip, XHCI_R_CAP, off + XHCI_XECP_LEGCTLSTS);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read legacy control registers: "
		    "encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}
	val &= XHCI_XECP_SMI_MASK;
	val |= XHCI_XECP_CLEAR_SMI;
	xhci_put32(xhcip, XHCI_R_CAP, off + XHCI_XECP_LEGCTLSTS, val);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write legacy control registers: "
		    "encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
xhci_controller_stop(xhci_t *xhcip)
{
	uint32_t cmdreg;

	cmdreg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBCMD);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read USB Command register: "
		    "encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	cmdreg &= ~(XHCI_CMD_RS | XHCI_CMD_INTE);
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_USBCMD, cmdreg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write USB Command register: "
		    "encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	/*
	 * Wait up to 50ms for this to occur. The specification says that this
	 * should stop within 16ms, but we give ourselves a bit more time just
	 * in case.
	 */
	return (xhci_reg_poll(xhcip, XHCI_R_OPER, XHCI_USBSTS, XHCI_STS_HCH,
	    XHCI_STS_HCH, 50, 10));
}

static int
xhci_controller_reset(xhci_t *xhcip)
{
	int ret;
	uint32_t cmdreg;

	cmdreg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBCMD);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read USB Command register for "
		    "reset: encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	cmdreg |= XHCI_CMD_HCRST;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_USBCMD, cmdreg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write USB Command register for "
		    "reset: encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	/*
	 * Some controllers apparently don't want to be touched for at least 1ms
	 * after we initiate the reset. Therefore give all controllers this
	 * moment to breathe.
	 */
	delay(drv_usectohz(xhci_reset_delay));

	/*
	 * To tell that the reset has completed we first verify that the reset
	 * has finished and that the USBCMD register no longer has the reset bit
	 * asserted. However, once that's done we have to go verify that CNR
	 * (Controller Not Ready) is no longer asserted.
	 */
	if ((ret = xhci_reg_poll(xhcip, XHCI_R_OPER, XHCI_USBCMD,
	    XHCI_CMD_HCRST, 0, 500, 10)) != 0)
		return (ret);

	return (xhci_reg_poll(xhcip, XHCI_R_OPER, XHCI_USBSTS,
	    XHCI_STS_CNR, 0, 500, 10));
}

/*
 * Take care of all the required initialization before we can actually enable
 * the controller. This means that we need to:
 *
 *    o Program the maximum number of slots
 *    o Program the DCBAAP and allocate the scratchpad
 *    o Program the Command Ring
 *    o Initialize the Event Ring
 *    o Enable interrupts (set imod)
 */
static int
xhci_controller_configure(xhci_t *xhcip)
{
	int ret;
	uint32_t config;

	config = xhci_get32(xhcip, XHCI_R_OPER, XHCI_CONFIG);
	config &= ~XHCI_CONFIG_SLOTS_MASK;
	config |= xhcip->xhci_caps.xcap_max_slots;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_CONFIG, config);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	if ((ret = xhci_context_init(xhcip)) != 0) {
		const char *reason;
		if (ret == EIO) {
			reason = "fatal FM I/O error occurred";
		} else if (ret == ENOMEM) {
			reason = "unable to allocate DMA memory";
		} else {
			reason = "unexpected error occurred";
		}

		xhci_error(xhcip, "failed to initialize xhci context "
		    "registers: %s (%d)", reason, ret);
		return (ret);
	}

	if ((ret = xhci_command_ring_init(xhcip)) != 0) {
		xhci_error(xhcip, "failed to initialize commands: %d", ret);
		return (ret);
	}

	if ((ret = xhci_event_init(xhcip)) != 0) {
		xhci_error(xhcip, "failed to initialize events: %d", ret);
		return (ret);
	}

	if ((ret = xhci_intr_conf(xhcip)) != 0) {
		xhci_error(xhcip, "failed to configure interrupts: %d", ret);
		return (ret);
	}

	return (0);
}

static int
xhci_controller_start(xhci_t *xhcip)
{
	uint32_t reg;

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_USBCMD);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to read USB Command register for "
		    "start: encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	reg |= XHCI_CMD_RS;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_USBCMD, reg);
	if (xhci_check_regs_acc(xhcip) != DDI_FM_OK) {
		xhci_error(xhcip, "failed to write USB Command register for "
		    "start: encountered fatal FM register error");
		ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
		return (EIO);
	}

	return (xhci_reg_poll(xhcip, XHCI_R_OPER, XHCI_USBSTS,
	    XHCI_STS_HCH, 0, 500, 10));
}

/* ARGSUSED */
static void
xhci_reset_task(void *arg)
{
	/*
	 * Longer term, we'd like to properly perform a controller reset.
	 * However, that requires a bit more assistance from USBA to work
	 * properly and tear down devices. In the meantime, we panic.
	 */
	panic("XHCI runtime reset required");
}

/*
 * This function is called when we've detected a fatal FM condition that has
 * resulted in a loss of service and we need to force a reset of the controller
 * as a whole. Only one such reset may be ongoing at a time.
 */
void
xhci_fm_runtime_reset(xhci_t *xhcip)
{
	boolean_t locked = B_FALSE;

	if (mutex_owned(&xhcip->xhci_lock)) {
		locked = B_TRUE;
	} else {
		mutex_enter(&xhcip->xhci_lock);
	}

	/*
	 * If we're already in the error state than a reset is already ongoing
	 * and there is nothing for us to do here.
	 */
	if (xhcip->xhci_state & XHCI_S_ERROR) {
		goto out;
	}

	xhcip->xhci_state |= XHCI_S_ERROR;
	ddi_fm_service_impact(xhcip->xhci_dip, DDI_SERVICE_LOST);
	taskq_dispatch_ent(xhci_taskq, xhci_reset_task, xhcip, 0,
	    &xhcip->xhci_tqe);
out:
	if (!locked) {
		mutex_exit(&xhcip->xhci_lock);
	}
}

static int
xhci_ioctl_portsc(xhci_t *xhcip, intptr_t arg)
{
	int i;
	xhci_ioctl_portsc_t xhi;

	bzero(&xhi, sizeof (xhci_ioctl_portsc_t));
	xhi.xhi_nports = xhcip->xhci_caps.xcap_max_ports;
	for (i = 1; i <= xhcip->xhci_caps.xcap_max_ports; i++) {
		xhi.xhi_portsc[i] = xhci_get32(xhcip, XHCI_R_OPER,
		    XHCI_PORTSC(i));
	}

	if (ddi_copyout(&xhi, (void *)(uintptr_t)arg, sizeof (xhi), 0) != 0)
		return (EFAULT);

	return (0);
}

static int
xhci_ioctl_clear(xhci_t *xhcip, intptr_t arg)
{
	uint32_t reg;
	xhci_ioctl_clear_t xic;

	if (ddi_copyin((const void *)(uintptr_t)arg, &xic, sizeof (xic),
	    0) != 0)
		return (EFAULT);

	if (xic.xic_port == 0 || xic.xic_port >
	    xhcip->xhci_caps.xcap_max_ports)
		return (EINVAL);

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(xic.xic_port));
	reg &= ~XHCI_PS_CLEAR;
	reg |= XHCI_PS_CSC | XHCI_PS_PEC | XHCI_PS_WRC | XHCI_PS_OCC |
	    XHCI_PS_PRC | XHCI_PS_PLC | XHCI_PS_CEC;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_PORTSC(xic.xic_port), reg);

	return (0);
}

static int
xhci_ioctl_setpls(xhci_t *xhcip, intptr_t arg)
{
	uint32_t reg;
	xhci_ioctl_setpls_t xis;

	if (ddi_copyin((const void *)(uintptr_t)arg, &xis, sizeof (xis),
	    0) != 0)
		return (EFAULT);

	if (xis.xis_port == 0 || xis.xis_port >
	    xhcip->xhci_caps.xcap_max_ports)
		return (EINVAL);

	if (xis.xis_pls & ~0xf)
		return (EINVAL);

	reg = xhci_get32(xhcip, XHCI_R_OPER, XHCI_PORTSC(xis.xis_port));
	reg &= ~XHCI_PS_CLEAR;
	reg |= XHCI_PS_PLS_SET(xis.xis_pls);
	reg |= XHCI_PS_LWS;
	xhci_put32(xhcip, XHCI_R_OPER, XHCI_PORTSC(xis.xis_port), reg);

	return (0);
}

static int
xhci_open(dev_t *devp, int flags, int otyp, cred_t *credp)
{
	dev_info_t *dip = xhci_get_dip(*devp);

	return (usba_hubdi_open(dip, devp, flags, otyp, credp));
}

static int
xhci_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	dev_info_t *dip = xhci_get_dip(dev);

	if (cmd == XHCI_IOCTL_PORTSC ||
	    cmd == XHCI_IOCTL_CLEAR ||
	    cmd == XHCI_IOCTL_SETPLS) {
		xhci_t *xhcip = ddi_get_soft_state(xhci_soft_state,
		    getminor(dev) & ~HUBD_IS_ROOT_HUB);

		if (secpolicy_xhci(credp) != 0 ||
		    crgetzoneid(credp) != GLOBAL_ZONEID)
			return (EPERM);

		if (mode & FKIOCTL)
			return (ENOTSUP);

		if (!(mode & FWRITE))
			return (EBADF);

		if (cmd == XHCI_IOCTL_PORTSC)
			return (xhci_ioctl_portsc(xhcip, arg));
		else if (cmd == XHCI_IOCTL_CLEAR)
			return (xhci_ioctl_clear(xhcip, arg));
		else
			return (xhci_ioctl_setpls(xhcip, arg));
	}

	return (usba_hubdi_ioctl(dip, dev, cmd, arg, mode, credp, rvalp));
}

static int
xhci_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	dev_info_t *dip = xhci_get_dip(dev);

	return (usba_hubdi_close(dip, dev, flag, otyp, credp));
}

/*
 * We try to clean up everything that we can. The only thing that we let stop us
 * at this time is a failure to remove the root hub, which is realistically the
 * equivalent of our EBUSY case.
 */
static int
xhci_cleanup(xhci_t *xhcip)
{
	int ret, inst;

	if (xhcip->xhci_seq & XHCI_ATTACH_ROOT_HUB) {
		if ((ret = xhci_root_hub_fini(xhcip)) != 0)
			return (ret);
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_USBA) {
		xhci_hcd_fini(xhcip);
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_STARTED) {
		mutex_enter(&xhcip->xhci_lock);
		while (xhcip->xhci_state & XHCI_S_ERROR)
			cv_wait(&xhcip->xhci_statecv, &xhcip->xhci_lock);
		mutex_exit(&xhcip->xhci_lock);

		(void) xhci_controller_stop(xhcip);
	}

	/*
	 * Always release the context, command, and event data. They handle the
	 * fact that they me be in an arbitrary state or unallocated.
	 */
	xhci_event_fini(xhcip);
	xhci_command_ring_fini(xhcip);
	xhci_context_fini(xhcip);

	if (xhcip->xhci_seq & XHCI_ATTACH_INTR_ENABLE) {
		(void) xhci_ddi_intr_disable(xhcip);
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_SYNCH) {
		cv_destroy(&xhcip->xhci_statecv);
		mutex_destroy(&xhcip->xhci_lock);
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_INTR_ADD) {
		if ((ret = ddi_intr_remove_handler(xhcip->xhci_intr_hdl)) !=
		    DDI_SUCCESS) {
			xhci_error(xhcip, "failed to remove interrupt "
			    "handler: %d", ret);
		}
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_INTR_ALLOC) {
		if ((ret = ddi_intr_free(xhcip->xhci_intr_hdl)) !=
		    DDI_SUCCESS) {
			xhci_error(xhcip, "failed to free interrupts: %d", ret);
		}
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_REGS_MAP) {
		ddi_regs_map_free(&xhcip->xhci_regs_handle);
		xhcip->xhci_regs_handle = NULL;
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_PCI_CONFIG) {
		pci_config_teardown(&xhcip->xhci_cfg_handle);
		xhcip->xhci_cfg_handle = NULL;
	}

	if (xhcip->xhci_seq & XHCI_ATTACH_FM) {
		xhci_fm_fini(xhcip);
		xhcip->xhci_fm_caps = 0;
	}

	inst = ddi_get_instance(xhcip->xhci_dip);
	xhcip->xhci_dip = NULL;
	ddi_soft_state_free(xhci_soft_state, inst);

	return (DDI_SUCCESS);
}

static int
xhci_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret, inst, route;
	xhci_t *xhcip;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	inst = ddi_get_instance(dip);
	if (ddi_soft_state_zalloc(xhci_soft_state, inst) != 0)
		return (DDI_FAILURE);
	xhcip = ddi_get_soft_state(xhci_soft_state, ddi_get_instance(dip));
	xhcip->xhci_dip = dip;

	xhcip->xhci_regs_capoff = PCI_EINVAL32;
	xhcip->xhci_regs_operoff = PCI_EINVAL32;
	xhcip->xhci_regs_runoff = PCI_EINVAL32;
	xhcip->xhci_regs_dooroff = PCI_EINVAL32;

	xhci_fm_init(xhcip);
	xhcip->xhci_seq |= XHCI_ATTACH_FM;

	if (pci_config_setup(xhcip->xhci_dip, &xhcip->xhci_cfg_handle) !=
	    DDI_SUCCESS) {
		goto err;
	}
	xhcip->xhci_seq |= XHCI_ATTACH_PCI_CONFIG;
	xhcip->xhci_vendor_id = pci_config_get16(xhcip->xhci_cfg_handle,
	    PCI_CONF_VENID);
	xhcip->xhci_device_id = pci_config_get16(xhcip->xhci_cfg_handle,
	    PCI_CONF_DEVID);

	if (xhci_regs_map(xhcip) == B_FALSE) {
		goto err;
	}

	xhcip->xhci_seq |= XHCI_ATTACH_REGS_MAP;

	if (xhci_regs_init(xhcip) == B_FALSE)
		goto err;

	if (xhci_read_params(xhcip) == B_FALSE)
		goto err;

	if (xhci_identify(xhcip) == B_FALSE)
		goto err;

	if (xhci_alloc_intrs(xhcip) == B_FALSE)
		goto err;
	xhcip->xhci_seq |= XHCI_ATTACH_INTR_ALLOC;

	if (xhci_add_intr_handler(xhcip) == B_FALSE)
		goto err;
	xhcip->xhci_seq |= XHCI_ATTACH_INTR_ADD;

	mutex_init(&xhcip->xhci_lock, NULL, MUTEX_DRIVER,
	    (void *)(uintptr_t)xhcip->xhci_intr_pri);
	cv_init(&xhcip->xhci_statecv, NULL, CV_DRIVER, NULL);
	xhcip->xhci_seq |= XHCI_ATTACH_SYNCH;

	if (xhci_port_count(xhcip) == B_FALSE)
		goto err;

	if (xhci_controller_takeover(xhcip) == B_FALSE)
		goto err;

	/*
	 * We don't enable interrupts until after we take over the controller
	 * from the BIOS. We've observed cases where this can cause spurious
	 * interrupts.
	 */
	if (xhci_ddi_intr_enable(xhcip) == B_FALSE)
		goto err;
	xhcip->xhci_seq |= XHCI_ATTACH_INTR_ENABLE;

	if ((ret = xhci_controller_stop(xhcip)) != 0) {
		xhci_error(xhcip, "failed to stop controller: %s",
		    ret == EIO ? "encountered FM register error" :
		    "timed out while waiting for controller");
		goto err;
	}

	if ((ret = xhci_controller_reset(xhcip)) != 0) {
		xhci_error(xhcip, "failed to reset controller: %s",
		    ret == EIO ? "encountered FM register error" :
		    "timed out while waiting for controller");
		goto err;
	}

	if ((ret = xhci_controller_configure(xhcip)) != 0) {
		xhci_error(xhcip, "failed to configure controller: %d", ret);
		goto err;
	}

	/*
	 * Some systems support having ports routed to both an ehci and xhci
	 * controller. If we support it and the user hasn't requested otherwise
	 * via a driver.conf tuning, we reroute it now.
	 */
	route = ddi_prop_get_int(DDI_DEV_T_ANY, xhcip->xhci_dip,
	    DDI_PROP_DONTPASS, "xhci-reroute", XHCI_PROP_REROUTE_DEFAULT);
	if (route != XHCI_PROP_REROUTE_DISABLE &&
	    (xhcip->xhci_quirks & XHCI_QUIRK_INTC_EHCI))
		(void) xhci_reroute_intel(xhcip);

	if ((ret = xhci_controller_start(xhcip)) != 0) {
		xhci_log(xhcip, "failed to reset controller: %s",
		    ret == EIO ? "encountered FM register error" :
		    "timed out while waiting for controller");
		goto err;
	}
	xhcip->xhci_seq |= XHCI_ATTACH_STARTED;

	/*
	 * Finally, register ourselves with the USB framework itself.
	 */
	if ((ret = xhci_hcd_init(xhcip)) != 0) {
		xhci_error(xhcip, "failed to register hcd with usba");
		goto err;
	}
	xhcip->xhci_seq |= XHCI_ATTACH_USBA;

	if ((ret = xhci_root_hub_init(xhcip)) != 0) {
		xhci_error(xhcip, "failed to load the root hub driver");
		goto err;
	}
	xhcip->xhci_seq |= XHCI_ATTACH_ROOT_HUB;

	return (DDI_SUCCESS);

err:
	(void) xhci_cleanup(xhcip);
	return (DDI_FAILURE);
}

static int
xhci_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	xhci_t *xhcip;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	xhcip = ddi_get_soft_state(xhci_soft_state, ddi_get_instance(dip));
	if (xhcip == NULL) {
		dev_err(dip, CE_WARN, "detach called without soft state!");
		return (DDI_FAILURE);
	}

	return (xhci_cleanup(xhcip));
}

/* ARGSUSED */
static int
xhci_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **outp)
{
	dev_t dev;
	int inst;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		dev = (dev_t)arg;
		*outp = xhci_get_dip(dev);
		if (*outp == NULL)
			return (DDI_FAILURE);
		break;
	case DDI_INFO_DEVT2INSTANCE:
		dev = (dev_t)arg;
		inst = getminor(dev) & ~HUBD_IS_ROOT_HUB;
		*outp = (void *)(uintptr_t)inst;
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static struct cb_ops xhci_cb_ops = {
	xhci_open,		/* cb_open */
	xhci_close,		/* cb_close */
	nodev,			/* cb_strategy */
	nodev,			/* cb_print */
	nodev,			/* cb_dump */
	nodev,			/* cb_read */
	nodev,			/* cb_write */
	xhci_ioctl,		/* cb_ioctl */
	nodev,			/* cb_devmap */
	nodev,			/* cb_mmap */
	nodev,			/* cb_segmap */
	nochpoll,		/* cb_chpoll */
	ddi_prop_op,		/* cb_prop_op */
	NULL,			/* cb_stream */
	D_MP | D_HOTPLUG,	/* cb_flag */
	CB_REV,			/* cb_rev */
	nodev,			/* cb_aread */
	nodev			/* cb_awrite */
};

static struct dev_ops xhci_dev_ops = {
	DEVO_REV,			/* devo_rev */
	0,				/* devo_refcnt */
	xhci_getinfo,			/* devo_getinfo */
	nulldev,			/* devo_identify */
	nulldev,			/* devo_probe */
	xhci_attach,			/* devo_attach */
	xhci_detach,			/* devo_detach */
	nodev,				/* devo_reset */
	&xhci_cb_ops,			/* devo_cb_ops */
	&usba_hubdi_busops,		/* devo_bus_ops */
	usba_hubdi_root_hub_power,	/* devo_power */
	ddi_quiesce_not_supported 	/* devo_quiesce */
};

static struct modldrv xhci_modldrv = {
	&mod_driverops,
	"USB xHCI Driver",
	&xhci_dev_ops
};

static struct modlinkage xhci_modlinkage = {
	MODREV_1,
	&xhci_modldrv,
	NULL
};

int
_init(void)
{
	int ret;

	if ((ret = ddi_soft_state_init(&xhci_soft_state, sizeof (xhci_t),
	    0)) != 0) {
		return (ret);
	}

	xhci_taskq = taskq_create("xhci_taskq", 1, minclsyspri, 0, 0, 0);
	if (xhci_taskq == NULL) {
		ddi_soft_state_fini(&xhci_soft_state);
		return (ENOMEM);
	}

	if ((ret = mod_install(&xhci_modlinkage)) != 0) {
		taskq_destroy(xhci_taskq);
		xhci_taskq = NULL;
	}

	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&xhci_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&xhci_modlinkage)) != 0)
		return (ret);

	if (xhci_taskq != NULL) {
		taskq_destroy(xhci_taskq);
		xhci_taskq = NULL;
	}

	ddi_soft_state_fini(&xhci_soft_state);

	return (0);
}
