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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * Kernel GPIO Framework
 * ---------------------
 *
 * This driver, kgpio(4D), implements the general kernel general purpose I/O
 * (GPIO) and dedicated purpose I/O (dpio) framework discussed in gpio(7).
 * Before we jump into the organization and specifics here, let's go into a few
 * definitions and overviews of what all is going on:
 *
 * GPIO -- General Purpose I/O
 *
 *	A GPIO is something that allows software to directly understand and
 *	manipulate the state of a particular pin on an ASIC. For example, this
 *	allows software to do things like to read the logical level on a pin or
 *	to set the logical output value. In addition, there are often other
 *	properties that can be changed such as things like whether internal pull
 *	ups are used, controls around interrupt behavior, drive strength, etc.
 *	Each of these different controls vary from controller to controller.
 *	Each of these is represented as an 'attribute', which is defined below.
 *
 * GPIO CONTROLLER / PROVIDER
 *
 *	A GPIO controller is a piece of hardware that provides accesses to and
 *	control over GPIOs. In the OS, we call a device driver for a GPIO
 *	controller a kgpio provider, as it provides access to and the
 *	functionality around this. Device drivers themselves use the
 *	<sys/gpio/kgpio_provider.h> header and related functions.
 *
 *	Each controller is exposed to userland through its own character device
 *	in /devices. There are not entries in /dev for these. The providing
 *	device driver does not have to worry about this and this takes care of
 *	ensuring that the provider is present, allowing them to detach like
 *	other classes of loadable modules.
 *
 * ATTRIBUTE
 *
 *	An attribute refers to a setting or property of a GPIO. While many
 *	controllers have similar attributes, in many cases the actual set of
 *	valid values varies between them (or potentially even from GPIO to GPIO
 *	on a device). Attributes are stored inside of nvlist_t's (more on that
 *	later) and consist of a few different pieces of information:
 *
 *	  o Name	This is how software and humans generally refer to a
 *			name for this attribute. The attribute name is generally
 *			made up of two parts: the provider's name and then the
 *			actual name. This allows different providers to not
 *			conflict with one another. These are both separated by
 *			a ':' character. Examples here are things like
 *			'sim:pull' which is used by the gpio_sim driver. Here
 *			'sim' refers to the provider and 'pull' the name.
 *
 *	  o Value	This is the actual value of the attribute for a given
 *			GPIO. It generally is a uint32_t (representing an enum)
 *			or a string.
 *
 *	  o Protection	This indicates whether the attribute is read-only or
 *			read-write. A read-write attribute can be updated by a
 *			consumer.
 *
 *	  o Possible	This is an array of values that are valid for this
 *			particular attribute. This information is specific to a
 *			GPIO.
 *
 * DPIO -- Dedicated Purpose I/O
 *
 *	A DPIO is a construct that wraps up a GPIO, constraining what it can do
 *	and freezing the ability to set all of its attributes except a small
 *	set. Their reason for existence is to try and solve the problem that
 *	while a GPIO controller is specific to a given piece of hardware (like a
 *	specific CPU or ASIC), what is safe to use depends entirely on the
 *	specifics of the way that is used. For example, which GPIOs are safe to
 *	use on a CPU depends on the specific motherboard it's found in and the
 *	surrounding pieces. Instead, this is where we offer the idea of the DPIO
 *	as its purpose is dedicated.
 *
 *	DPIOs show up to the system as their own character device with basic
 *	semantics around read(2), write(2), and poll(2). The DPIO devices show
 *	up in /dev/dpio/<name> and all of the specifics of them are defined in
 *	their own header <sys/gpio/dpio.h>.
 *
 *	An important part that we'll get into in the driver organization is that
 *	each DPIO points to its corresponding GPIO controller.
 *
 * IOMUX -- I/O Multiplexer
 *
 *	An I/O multiplexer is something that exists in hardware that maps which
 *	peripherals are actually connected to which pins. Many SoCs are designed
 *	such that an actual pin on the device can be pointed at one of several
 *	different peripherals.
 *
 *	Right now, the GPIO framework is not integrated into any kind of I/O or
 *	pin muxing framework. This means that GPIOs that are visible may or may
 *	not do anything based on the state of that mux. This is a known missing
 *	piece and is something that will see further consolidation.
 *
 * -------------------
 * Driver Organization
 * -------------------
 *
 * To understand how this driver is organized, it's worth going into a bit more
 * detail about the framework and what entities we track.
 *
 * Fundamentally a GPIO controller and is mapped to its provider driver. More
 * specifically, the dev_info_t is the key that we used to build up and manage a
 * controller in the kgpio_t structure. These providers will register with the
 * kgpio kernel module when they call attach(9E) and detach(9E).
 *
 * When a provider registers with us, they tell us how many GPIOs they support.
 * This gives us a set of unsigned integer GPIO IDs that are in the set [0,
 * kgpio_ngpios). The general framework always refers to a GPIO on a controller
 * by its numeric ID.  This ID space is contiguous, which may not be true of the
 * actual hardware. It is not our intent that this is the same thing. Instead,
 * for more semantics, GPIOs have a common 'name' attribute which providers fill
 * in that userland can consume. However, the kernel identifies all GPIOs by
 * their controller and a provider-supplied opaque ID. The kgpio driver does
 * not track individual GPIOs.
 *
 * Because we need to provide character devices ourselves, the kgpio driver has
 * its own instance which is a child of the pseudo nexus. Importantly, krtld
 * guarantees that our module is loaded before anything that would call into us;
 * however, it does not guarantee anything about whether a particular instance
 * will be present. This in turn leads to us keeping global structure and state
 * in the driver which is independent from our actual instance because the
 * instance may come and go.
 *
 * In turn, the framework does keep track of all of the DPIOs that are created
 * because these are independent character devices and minors. These are stored
 * in data that isn't tied to the instance mostly for the reason as the core of
 * the GPIO framework. Each DPIO's information is tracked in a 'dpio_t'
 * structure.
 *
 * To facilitate the fact that the character device entry points all operate in
 * terms of minors, we have a shared structure that is embedded in both the
 * kgpio_t and dpio_t called a kgpio_minor_t. These are stored in a global
 * avl_tree_t and is how minors are mapped back to their device type and actual
 * information.
 *
 * The organization of data is roughly as follows (some members elided):
 *
 *
 *     +-----------------------+
 *     | Global DPIO List      |
 *     |                       |       +-------------+   +-------------+
 *     | list_t kgpio_g_dpios -+------>| DPIO dpio_t |-->| DPIO dpio_t |--> ...
 *     +-----------------------+       | "foo"       |   | "bar"       |
 *                                     |             |   |             |
 *                                     | gpio ID     |   | gpio ID     |
 *  +--------------------------------->| kgpio_t *   |   | kgpio_t *   |
 *  |                                  +-------------+   +-------------+
 *  |                                      |                |
 *  |  +------------------------+          |   +------------+
 *  |  | Global Controller List |          v   v
 *  |  |                        |     +-------------+   +-------------+
 *  |  | list_t kgpio_g_gpios --+---->| kgpio_t     |-->| kgpio_t     |--> ...
 *  |  +------------------------+     |             |   |             |
 *  |                                 | dev_info_t  |   | dev_info_t  |
 *  +-------------------------------->| kgpio_ops_t |   | kgpio_ops_t |
 *  |                                 +-------------+   +-------------+
 *  |                                                      |
 *  |  +-------------------------+                         |
 *  |  | Global Minor Tracking   |                         v
 *  |  |                         |                    +---------------------+
 *  +--| avl_tree_t kgpio_minors |                    | GPIO Provider       |
 *     +-------------------------+                    |                     |
 *                                                    | A hardware-specific |
 *                                                    | driver              |
 *                                                    +---------------------+
 *
 * In more detail, all of our global data is protected by the kgpio_g_mutex and
 * all such data is prefixed with 'kgpio_g_'. As GPIO Provider drivers register
 * with kgpio framework via kgpio_register(), we create a kgpio_t for them and
 * insert them into the global kgpio_g_dpios list. At that point, we do a few
 * additional things:
 *
 *   o If our main kgpio(4D) instance is attached, then we will go through and
 *     create a minor node for the controller. If not, this will be deferred
 *     until it does attach.
 *
 *   o We will register a DDI callback for when the module is removed from the
 *     system, which is a step past being detached. This is what allows us to
 *     call back a provider when someone wants to use it, just as the /devices
 *     devfs file system normally does.
 *
 * At that point, we will flow data and back and forth via ioctls on the
 * controller minor nodes. As information is asked for by userland, the kgpio
 * driver will call back into the provider with the provided kgpio_ops_t
 * operations vector and the driver's private data (both passed in at
 * registration time).
 *
 * Only when a user comes and asks to create a DPIO via the
 * KGPIO_IOC_DPIO_CREATE ioctl will we go through and at that point create a
 * dpio_t. The dpio_t is stored in its own global list and each dpio_t points to
 * the corresponding kgpio_t controller and contains the GPIO that it should
 * use. In addition, there are a number of fields set at creation time which
 * relate to the capabilities of the DPIO which are what govern whether the DPIO
 * supports read(9E), write(9E), etc.
 *
 * When a DPIO is created a minor node is created with the type
 * DDI_NT_GPIO_DPIO. While users can give a DPIO any name they want, we prefix
 * each name in /devices with 'dpio:'. This ensures that a user's name for a
 * DPIO will not conflict with any controllers that may come and go in the
 * system. The devfsadm(8) plugs for GPIO subsystem will ensure that a DPIO is
 * created under /dev/dpio with the user's requested name. The 'dpio:' leading
 * portion of the /devices minor node will not be present.
 *
 * There is one final type of minor node that exists, which is called 'dpinfo'
 * which is used to provide static, creation-time based information about DPIOs.
 * This exists because we generally want to support the ability to both create
 * DPIOs that honor O_EXCL/FEXCL and DPIOs that only the kernel can open. As
 * such, this minor can be used to query about basic information about a DPIO
 * without requiring one to be able to open it (which may not be possible).
 *
 * ---------
 * Data Flow
 * ---------
 *
 * There are two different high-leveling goals in the data design in this
 * system:
 *
 *   o Hardware should be the single source of truth (where possible) for the
 *     current values of a GPIO's attributes. That is why there is no caching of
 *     data either in this driver or in the individual providers. Doing
 *     anything else allows for things to get out of sync.
 *
 *   o Where possible, all data about a GPIO should be something that we can
 *     atomically change. In general, it can be very hard to trace a series of
 *     valid steps from point a to point b for a GPIO, if you cannot change
 *     multiple attributes at once. While there are always complications here
 *     because of pin and I/O muxing, this is why there is no individual
 *     attribute get and set routines.
 *
 * When getting and setting information, a GPIO's attributes are all stored in a
 * single nvlist_t. Here, each key is the name of an attribute which points to
 * its corresponding value -- generally a string or uint32_t. In addition, there
 * is an embedded metadata nvlist_t that has information such as the protection
 * or supported values for a given GPIO.
 *
 * All of this information is considered GPIO-specific because each GPIO in a
 * system may have readily different capabilities and functionality. While there
 * are common attributes which are defined in <sys/gpio/kgpio_provider.h>, the
 * expectation is that each provider defines its own attributes (other than
 * name) in their own header file that generally should be found in
 * <sys/gpio/driver.h>, where driver is the name of the driver. Let's look at an
 * example of this structure if we had four attributes present:
 *
 * nvlist_t
 *	"name"		-> string
 *	"zen:output"	-> uint32
 *	"zen:input"	-> uint32
 *	"zen:pull"	-> uint32
 *	"metadata"	-> nvlist_t
 *			"name"		-> nvlist_t
 *					"protection"	-> uint32
 *			"zen:output":	-> nvlist_t
 *					"protection"	-> uint32
 *					"possible"	-> uint32[]
 *			"zen:input":	-> nvlist_t
 *					"protection"	-> uint32
 *					"possible"	-> uint32[]
 *			"zen:pull":	-> nvlist_t
 *					"protection"	-> uint32
 *					"possible"	-> uint32[]
 *
 * Basically what we see here is that every attribute is a top-level key. The
 * metadata is an nvlist_t where each key is the of an attribute which points to
 * an nvlist_t. The type of "possible" will match its underlying data type. The
 * metadata information is only provided by providers themselves when getting an
 * attribute. When an attribute is set, there is no metadata present. As in the
 * case of "name", something like the possible values can be omitted (in this
 * case because it's read-only). While metadata is strictly optional, it is
 * useful to include as it helps users understand what is going on.
 *
 * When coming up with attributes, there is no need for there to be a strict 1:1
 * mapping with hardware fields. In fact, providers should try to phrase things
 * such that people cannot create a state that is unsupported. For example, some
 * hardware may have two register settings: one for whether something is level
 * triggered and one for which edges should generate the interrupt. In this
 * case, if done simply, one could set an illegal value which is level triggered
 * on both the rising and falling edge which the hardware warns against. Rather
 * than allowing this to happen, the provider should instead come up with a
 * single semantic attribute so that way users can't end up in illegal states.
 *
 * Next we should turn our attention to the data flow for DPIOs. Where as GPIOs
 * allow the provider to define everything about them, DPIOs are different.
 * Instead, our DPIO operation vectors are all about taking narrowly defined
 * types in <sys/gpio/dpio.h> such as the dpio_input_t and the dpio_output_t and
 * having the provider map that to hardware states. Right now we have a limited
 * number of input and output values. Providers may not have a way to map every
 * possible state to one of our values. Similarly, there may be values that they
 * cannot represent in their hardware implementation. In these cases, providers
 * must fail the various DPIO requests. We require that consumers always read
 * and write a uint32_t value and that is enforced for providers. This is done
 * to give us future flexibility in the set of values we may support.
 *
 * ------------------------------------------
 * Provider Lifecycle, Locking, and Lifetimes
 * ------------------------------------------
 *
 * The most nuanced piece of this driver and framework is that we have to refer
 * to other driver's dev_info_t data structures and we want to allow those
 * things to be detached normally. A normal driver would attach and create minor
 * nodes, then detach when it no longer exists. However, when this detach is not
 * the driver being removed, devfs would notice this and when a minor node is
 * accessed bring it back to life. While this is a nice feature, like with the
 * kernel sensor subsystem, we end up having to do a bunch of this ourselves
 * because we are responsible for all the minors.
 *
 * This tradeoff centralizes the complexity in one spot rather than having each
 * provider have to reimplement cb_ops and more that they otherwise wouldn't
 * even need to or have to think about minors (which helps if they have their
 * own for any reason). With that in mind, it's worth laying out some
 * understanding of how this works and when we need to check and worry about
 * this:
 *
 *   o If a GPIO controller is actively open, that is someone called open(9E) on
 *     its minor, then we know that the dev_info_t is attached and present.
 *
 *   o Whenever a DPIO exists, it always has a hold on its underlying
 *     controller, regardless of whether the controller is open or not.
 *
 *   o When a GPIO provider driver detaches, it will call back into us. At that
 *     point we consider it invalid.
 *
 *   o When a GPIO provider driver registers with us, we know it is valid.
 *
 *   o The DDI will call back into us when the device driver is actually removed
 *     from the system (e.g. rem_drv), giving us a cue as to when everything is
 *     fully gone and we can finally tear down our state.
 *
 * With this in mind, our actual task and rules are fairly straightforward and
 * can be summarized as: when we are in open(9E) and are opening a controller,
 * we must check if it is valid (KGPIO_F_VALID) and if not, attempt to make it
 * valid again. Any other character device operation that is coming in we don't
 * have to worry about it because it is in that state by definition. This state
 * diagram can be summarized as:
 *
 *           |
 *           +-------<-----------------------------------<---------+
 *           |                                                     |
 *           | . . driver calls kgpio_register()                   |
 *           v                                                     |
 *       +-------+                                                 |
 *       | Valid |                                                 |
 *       +-------+                                                 ^
 *           |                                                     |
 *           | . . driver calls kgpio_unregister().                |
 *           v                                                     |
 *      +---------+                                                |
 *      | Invalid |                                                |
 *      +---------+                                                |
 *        |     |                                                  |
 *        |     | . . user calls open on a controller              |
 *        |     |     minor node                                   |
 *        |     +------------------+                               |
 *        |                        |                               ^
 *        |                        |                               |
 *        |                        v                               |
 *        |               +-------------------+                    |
 *        |               | ndi_devi_config() |-->-.---------------+
 *        |               +-------------------+    . . driver attach(9E) called
 *        |                                |
 *        | . . DDI's unbind callback      |
 *        |     fires as driver is         |
 *        |     being removed              |
 *        v                                | . . attach failed or there
 *   +---------+                           |     was no call to
 *   | kgpio_t |<--------------------------+     kgpio_register() again
 *   | Deleted |
 *   +---------+
 *
 * The heavy lifting is done in the rather involved function, kgpio_hold_by_id.
 * In that, if we find that the KGPIO_F_VALID and KGPIO_F_HELD are both present,
 * then we're in the earlier simple case described above. Otherwise, if not, we
 * then have to consider the fact that multiple threads may all be trying to get
 * here for some reason (e.g. concurrent calls to open(9E)).
 *
 * The first thread that takes control of the process of validating something
 * sets the KGPIO_F_META_WORK flag. Any other thread that finds this flag set
 * simply waits on it to finish. When these blocked threads are signaled, they
 * restart the entire validation process again. Once the meta flag is owned, we
 * proceed to take the NDI hold which ensures that the dev_info_t shouldn't be
 * able to go away. At that point, we will attempt to attach the driver if it's
 * not attached. If it is, then we are done.
 *
 * The NDI hold will persist as long as the device is open. Similarly, as
 * mentioned above, each DPIO that exists puts a similar NDI hold on the
 * underlying dev_info_t.
 *
 * The benefit of this whole dance is that it guarantees that an open controller
 * node cannot disappear at all during any other cb_ops, simplifying lifetime
 * considerations. Basically when calling open(9E) we need to consider it, but
 * once open, we're good until close(9E).
 *
 * This ties in directly into the locking hierarchy in the system. There are
 * three classes of locks that exist, which are ordered by the order in which
 * they should be taken.
 *
 *  1. The global kgpio_g_mutex, which protects all of the global data
 *     structures.
 *  2. The mutex embedded in the dpio_t structure.
 *  3. The mutex embedded in the kgpio_t structure.
 *
 * When dealing with locking, one must always take the kgpio_g_mutex before one
 * ever takes either of the kgpio_mutex or dpio_mutex inside the kgpio_t and
 * dpio_t. Most of the data that is required for the DPIO to perform I/O on the
 * underlying GPIO is read-only data. In general, one should not hold both a
 * dpio_t and kgpio_t mutex at the same time. Finally, if you need to call into
 * the NDI or enter a parent, none of our locks should be held.
 *
 * The lifetime of the dpio_t structure is tied to someone creating and
 * destroying it with ioctls (KGPIO_IOC_DPIO_CREATE and KGPIO_IOC_DPIO_DESTROY).
 * A DPIO cannot be destroyed if someone is using it. This means that like the
 * kgpio_t, once you get through the open(9E) call, you can assume that it will
 * always be valid. In addition, the kgpio_t that is attached to it always will
 * be. Unlike the kgpio_t, the dpio_t hold process is much simpler. As long as
 * the dpio is findable in the global list (with the global mutex held), then it
 * is valid.
 *
 * Ideally, the combination of these two pieces leads to making the actual
 * design and implementation here much simpler in other parts and ultimately,
 * makes the system easier to reason about.
 *
 * ---------------------------------
 * Future Integrations, Shortcomings
 * ---------------------------------
 *
 * At this time, the implementation of the framework has been designed around
 * erring on the side of simplicity and enabling end to end functionality.
 * Several of the choices such as using nvlist_t's, the presence of metadata,
 * and the design of DPIOs are focused on that. Here are things that this
 * currently doesn't do and may have varying degrees of challenges:
 *
 *   o The attribute and DPIO interface are not designed around the need to
 *     sometimes implement various peripherals via bit-banging GPIOs. For such
 *     cases, an alternative set of interfaces which allows a consumer to batch
 *     up a series of changes to a GPIO with any optional delays that are all
 *     executed at once is probably what should be used. Because the initial
 *     needs do not require this, we have not pretended to come up with a good
 *     consumerless API.
 *
 *   o Right now we are using simple intrusive lists for DPIOs and GPIOs. There
 *     is no easy way to go from a GPIO and see which DPIOs point into it. When
 *     this becomes a bottelneck (e.g. as part of delivering polling results),
 *     then that would be the time to improve things here and add something akin
 *     to an AVL to the kgpio_t that includes all of its DPIOs.
 *
 *   o We currently don't support any chpoll(9E) interfaces. The intent here is
 *     that there would be a single pollhead per dpio_t that is shared between
 *     anyone who calls chpoll(9E) on the dpio_t. This would be paired with a
 *     callback function for a provider to call back into us. Importantly
 *     though, when that is added, we should ensure that the providers are
 *     instructed not to hold any locks across the call.
 *
 *   o Right now there is no integration with pin and I/O muxing, meaning that
 *     it is possible that anything set in the GPIO controller's hardware may
 *     have no effect. This is an area of future research and work.
 *
 *   o There is currently a forced 1:1 relationship between the provider and the
 *     dev_info_t. The provider also can't determine its own name. While these
 *     are simpler problems to solve, the broader problem (which extends beyond
 *     just the GPIO framework) is how to name and relate providers to semantic
 *     things that a user actually knows about and may not have a stable
 *     /devices path for the consumer to rely upon.
 */

#include <sys/types.h>
#include <sys/file.h>
#include <sys/errno.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/stddef.h>
#include <sys/sunndi.h>
#include <sys/esunddi.h>
#include <sys/taskq.h>
#include <sys/id_space.h>
#include <sys/sysmacros.h>
#include <sys/avl.h>
#include <sys/stdbool.h>
#include <sys/ctype.h>
#include <sys/fs/dv_node.h>

#include <sys/gpio/kgpio_provider.h>
#include <sys/gpio/kgpio.h>
#include <sys/gpio/dpio.h>

#define	KGPIO_CTRL_NAMELEN	DPIO_NAMELEN

typedef enum {
	/*
	 * This flag is used to indicate that the minor node is registered. It
	 * is possible for this not to happen if a provider comes in before the
	 * kgpio instance is force attached.
	 */
	KGPIO_F_MINOR_VALID	= 1 << 0,
	/*
	 * This flag tracks the notion of whether or not we believe the
	 * underlying driver instance is active and attached. When the producer
	 * is deatching this will be cleared and this is our call to try to open
	 * it up again.
	 */
	KGPIO_F_VALID		= 1 << 1,
	/*
	 * This indicates that the underlying driver instance represented by the
	 * kgpio_t has a DDI hold on it. This is established in a controller's
	 * first open and removed when it is closed. Note, this is used as part
	 * of manipulating the controller node. DPIOs will also have holds on
	 * the underlying dev_info_t that are tracked with their lifetime.
	 */
	KGPIO_F_HELD		= 1 << 2,
	/*
	 * This flag is a stage beyond having cleared KGPIO_F_VALID. At this
	 * point, the driver this is associated with is actually going away and
	 * therefore this truly is getting cleaned up.
	 */
	KGPIO_F_REMOVED		= 1 << 3,
	/*
	 * This flag is used to synchronize the act of holding and/or attaching
	 * a given kgpio. There can only be one at a time. This is only ever
	 * used in open. close(9E) does not require this because of the
	 * exclusion guarantees of the kernel.
	 */
	KGPIO_F_META_WORK	= 1 << 4
} kgpio_flags_t;

struct kgpio;
struct dpio;

typedef enum {
	/*
	 * This is a GPIO controller. It is represented by a kgpio_t.
	 */
	KGPIO_MINOR_T_CTRL,
	/*
	 * This is a DPIO entry. It is represented by a dpio_t.
	 */
	KGPIO_MINOR_T_DPIO,
	/*
	 * This is a general interface that is used to get static information
	 * about DPIOs. Nothing in the kminor_data is valid.
	 */
	KGPIO_MINOR_T_DPINFO
} kgpio_minor_type_t;

typedef struct kgpio_minor {
	avl_node_t kminor_avl;
	id_t kminor_id;
	kgpio_minor_type_t kminor_type;
	union {
		struct dpio *kminor_dpio;
		struct kgpio *kminor_ctrl;
	} kminor_data;
} kgpio_minor_t;

typedef struct kgpio {
	kgpio_minor_t kgpio_minor;
	list_node_t kgpio_link;
	dev_info_t *kgpio_dip;
	uint32_t kgpio_ngpios;
	const kgpio_ops_t *kgpio_ops;
	void *kgpio_drv;
	ddi_unbind_callback_t kgpio_cb;
	char kgpio_mname[KGPIO_CTRL_NAMELEN];
	kmutex_t kgpio_mutex;
	kcondvar_t kgpio_cv;
	kgpio_flags_t kgpio_flags;
	uint32_t kgpio_ndpios;
} kgpio_t;

/*
 * This is designed to give us space for 'dpio:' and then whatever name
 * the user gives us. This is done to avoid having someone try to create a dpio
 * that would conflict with a controller name.
 */
#define	KGPIO_DPIO_INT_NAMELEN	(KGPIO_DPIO_NAMELEN + 8)

typedef enum {
	/*
	 * This is used to indicate that the dpio is actually open.
	 */
	DPIO_S_OPEN		= 1 << 0,
	/*
	 * This indicates that the DPIO is open exclusively right now.
	 */
	DPIO_S_EXCL		= 1 << 1
} dpio_status_t;

typedef struct dpio {
	kgpio_minor_t dpio_minor;
	list_node_t dpio_link;
	char dpio_name[KGPIO_DPIO_INT_NAMELEN];
	kgpio_t *dpio_kgpio;
	uint32_t dpio_gpio_num;
	dpio_caps_t dpio_caps;
	dpio_flags_t dpio_flags;
	/*
	 * All fields above this point are read-only and set at DPIO creation
	 * time.
	 */
	kmutex_t dpio_mutex;
	hrtime_t dpio_last_intr;
	hrtime_t dpio_last_write;
	dpio_status_t dpio_status;
} dpio_t;

/*
 * Various definitions related to minor numbers. The first minor is what we use
 * for the kgpio id_space. This starts at two as we reserve the minor number 1
 * for the dpinfo entry and we assume that 0 is reserved to aid in debugging /
 * initialization.
 */
#define	KGPIO_MINOR_DPINFO	1
#define	KGPIO_MINOR_FIRST	2
#define	KGPIO_MINOR_NAME_DPINFO	"dpinfo"

/*
 * This is the maximum size of a user nvlist_t that we're willing to consider in
 * the kernel. This value is a rough swag of what we think the maximum size
 * nvlist would ever be for a single GPIO with headroom. This is here in case
 * someone has need to tune it to unblock something.
 */
size_t kgpio_max_user_nvl = 512 * 1024;

static dev_info_t *kgpio_g_dip;
static kmutex_t kgpio_g_mutex;
static list_t kgpio_g_gpios;
static list_t kgpio_g_dpios;
static avl_tree_t kgpio_g_minors;
static id_space_t *kgpio_g_ids;
static kgpio_minor_t kgpio_g_dpinfo;

static int
kgpio_minor_comparator(const void *l, const void *r)
{
	const kgpio_minor_t *kml = l;
	const kgpio_minor_t *kmr = r;

	if (kml->kminor_id > kmr->kminor_id) {
		return (1);
	} else if (kml->kminor_id < kmr->kminor_id) {
		return (-1);
	} else {
		return (0);
	}
}

static kgpio_t *
kgpio_find_by_dip(dev_info_t *dip)
{
	kgpio_t *k;

	ASSERT(MUTEX_HELD(&kgpio_g_mutex));
	for (k = list_head(&kgpio_g_gpios); k != NULL;
	    k = list_next(&kgpio_g_gpios, k)) {
		if (k->kgpio_dip == dip) {
			return (k);
		}
	}

	return (NULL);
}

static kgpio_minor_t *
kgpio_minor_find(id_t minor)
{
	kgpio_minor_t idx = { 0 };

	ASSERT(MUTEX_HELD(&kgpio_g_mutex));
	idx.kminor_id = minor;

	return (avl_find(&kgpio_g_minors, &idx, NULL));
}

static void
kgpio_dpio_cleanup(dpio_t *dpio)
{
	if (dpio->dpio_minor.kminor_id > 0) {
		id_free(kgpio_g_ids, dpio->dpio_minor.kminor_id);
		dpio->dpio_minor.kminor_id = 0;
	}
	ddi_remove_minor_node(kgpio_g_dip, dpio->dpio_name);
	mutex_destroy(&dpio->dpio_mutex);
	kmem_free(dpio, sizeof (dpio_t));
}

static void
kgpio_cleanup(kgpio_t *kgpio)
{
	if (kgpio->kgpio_minor.kminor_id > 0) {
		id_free(kgpio_g_ids, kgpio->kgpio_minor.kminor_id);
		kgpio->kgpio_minor.kminor_id = 0;
	}
	cv_destroy(&kgpio->kgpio_cv);
	mutex_destroy(&kgpio->kgpio_mutex);
	kmem_free(kgpio, sizeof (kgpio_t));
}

static void
kgpio_unbind_taskq(void *arg)
{
	kgpio_t *kgpio = arg;

	mutex_enter(&kgpio_g_mutex);
	if ((kgpio->kgpio_flags & KGPIO_F_MINOR_VALID) != 0) {
		kgpio->kgpio_flags &= ~KGPIO_F_MINOR_VALID;
		(void) ddi_remove_minor_node(kgpio_g_dip, kgpio->kgpio_mname);
	}
	mutex_exit(&kgpio_g_mutex);

	kgpio_cleanup(kgpio);
}

static void
kgpio_unbind_cb(void *arg, dev_info_t *dip)
{
	kgpio_t *kgpio = arg;

	/*
	 * We have reached here because a driver that was registered with us is
	 * actually going away. As such it is now time for us to finally let go
	 * of it and free it so as to no longer attempt to keep it around and
	 * reattach it. At this point in time we are still in the context of the
	 * detaching thread in the devinfo tree. As such, here we note that it
	 * is going away and in the system taskq do the work to finish cleaning
	 * it up. After this point it cannot be looked up and held, so only
	 * existing opens that are racing with us will be here.
	 */
	mutex_enter(&kgpio_g_mutex);
	list_remove(&kgpio_g_gpios, kgpio);
	avl_remove(&kgpio_g_minors, &kgpio->kgpio_minor);
	kgpio->kgpio_flags |= KGPIO_F_REMOVED;
	mutex_exit(&kgpio_g_mutex);

	(void) taskq_dispatch(system_taskq, kgpio_unbind_taskq, kgpio,
	    TQ_SLEEP);
}

int
kgpio_unregister(dev_info_t *dip)
{
	kgpio_t *kgpio;

	if (dip == NULL) {
		return (EINVAL);
	}

	if (!DEVI_IS_ATTACHING(dip) && !DEVI_IS_DETACHING(dip)) {
		return (EAGAIN);
	}

	mutex_enter(&kgpio_g_mutex);
	kgpio = kgpio_find_by_dip(dip);
	if (kgpio == NULL) {
		mutex_exit(&kgpio_g_mutex);
		return (ENOENT);
	}
	kgpio->kgpio_flags &= ~KGPIO_F_VALID;
	mutex_exit(&kgpio_g_mutex);

	return (0);
}

/*
 * Attempt to create a minor node for the kgpio. Because of the fact that the
 * producer can register before we have a dev_info_t there's not a lot we can do
 * other than complain and hope someone notices on failure.
 */
static void
kgpio_create_minor(kgpio_t *kgpio)
{
	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if (ddi_create_minor_node(kgpio_g_dip, kgpio->kgpio_mname, S_IFCHR,
	    (minor_t)kgpio->kgpio_minor.kminor_id, DDI_NT_GPIO_CTRL, 0) != 0) {
		dev_err(kgpio_g_dip, CE_WARN, "failed to create minor node "
		    "%s", kgpio->kgpio_mname);
	} else {
		kgpio->kgpio_flags |= KGPIO_F_MINOR_VALID;
	}
}

int
kgpio_register(dev_info_t *dip, const kgpio_ops_t *ops, void *arg,
    uint32_t ngpio)
{
	kgpio_t *kgpio;

	if (dip == NULL || ops == NULL || ops->kgo_get == NULL ||
	    ops->kgo_set == NULL || ngpio == 0) {
		return (EINVAL);
	}

	if (!DEVI_IS_ATTACHING(dip)) {
		return (EAGAIN);
	}

	mutex_enter(&kgpio_g_mutex);
	kgpio = kgpio_find_by_dip(dip);
	if (kgpio != NULL) {
		mutex_enter(&kgpio->kgpio_mutex);
		if ((kgpio->kgpio_flags & KGPIO_F_VALID) != 0) {
			mutex_exit(&kgpio->kgpio_mutex);
			mutex_exit(&kgpio_g_mutex);
			return (EEXIST);
		}

		if (kgpio->kgpio_ngpios != ngpio) {
			dev_err(dip, CE_WARN, "failed to register with gpio "
			    "framework, number of GPIOs changed from %u to %u",
			    kgpio->kgpio_ngpios, ngpio);
			mutex_exit(&kgpio->kgpio_mutex);
			mutex_exit(&kgpio_g_mutex);
			return (ESTALE);
		}

		/*
		 * We've found a match for this gpio. Assume that the pointers
		 * it's given us have changed, but otherwise, we don't need to
		 * recreate anything in the kgpio_t.
		 */
		kgpio->kgpio_flags |= KGPIO_F_VALID;
		kgpio->kgpio_ops = ops;
		kgpio->kgpio_drv = arg;
		mutex_exit(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		return (0);
	}

	kgpio = kmem_zalloc(sizeof (kgpio_t), KM_SLEEP);
	kgpio->kgpio_dip = dip;
	kgpio->kgpio_ngpios = ngpio;
	kgpio->kgpio_ops = ops;
	kgpio->kgpio_drv = arg;

	mutex_init(&kgpio->kgpio_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&kgpio->kgpio_cv, NULL, CV_DRIVER, NULL);

	if (snprintf(kgpio->kgpio_mname, sizeof (kgpio->kgpio_mname), "%s%d",
	    ddi_driver_name(dip), ddi_get_instance(dip)) >=
	    sizeof (kgpio->kgpio_mname)) {
		mutex_exit(&kgpio_g_mutex);
		dev_err(dip, CE_WARN, "failed to register with gpio framework: "
		    "controller minor name overflow");
		kgpio_cleanup(kgpio);
		return (EOVERFLOW);
	}

	kgpio->kgpio_minor.kminor_id = id_alloc_nosleep(kgpio_g_ids);
	if (kgpio->kgpio_minor.kminor_id == -1) {
		mutex_exit(&kgpio_g_mutex);
		kgpio_cleanup(kgpio);
		return (ENOSPC);
	}
	kgpio->kgpio_minor.kminor_type = KGPIO_MINOR_T_CTRL;
	kgpio->kgpio_minor.kminor_data.kminor_ctrl = kgpio;

	kgpio->kgpio_cb.ddiub_cb = kgpio_unbind_cb;
	kgpio->kgpio_cb.ddiub_arg = kgpio;
	e_ddi_register_unbind_callback(dip, &kgpio->kgpio_cb);
	kgpio->kgpio_flags |= KGPIO_F_VALID;

	/*
	 * At this point the kgpio_t is set up. The last thing we need to see is
	 * if we actually have our dev_info_t so we can create minors. It is
	 * possible for this not to be the case when the first gpio provider is
	 * attaching because the krtld reference only guarantees that the kgpio
	 * _init() entry point has been called and not attach. We attempt to use
	 * a ddi-forceattach attribute to make this less likely.
	 */
	if (kgpio_g_dip != NULL) {
		mutex_enter(&kgpio->kgpio_mutex);
		kgpio_create_minor(kgpio);
		mutex_exit(&kgpio->kgpio_mutex);
	}

	list_insert_tail(&kgpio_g_gpios, kgpio);
	avl_add(&kgpio_g_minors, &kgpio->kgpio_minor);

	mutex_exit(&kgpio_g_mutex);

	return (0);
}

void
kgpio_nvl_attr_fill_str(nvlist_t *nvl, nvlist_t *meta, const char *key,
    const char *val, uint_t npos, char *const *pos, kgpio_prot_t prot)
{
	nvlist_t *info = fnvlist_alloc();

	fnvlist_add_string(nvl, key, val);

	fnvlist_add_uint32(info, KGPIO_ATTR_PROT, (uint32_t)prot);
	if (npos > 0) {
		fnvlist_add_string_array(info, KGPIO_ATTR_POS, pos, npos);
	}
	fnvlist_add_nvlist(meta, key, info);
	fnvlist_free(info);

}

void
kgpio_nvl_attr_fill_u32(nvlist_t *nvl, nvlist_t *meta, const char *key,
    uint32_t val, uint_t npos, uint32_t *pos, kgpio_prot_t prot)
{
	nvlist_t *info = fnvlist_alloc();

	fnvlist_add_uint32(nvl, key, val);

	fnvlist_add_uint32(info, KGPIO_ATTR_PROT, (uint32_t)prot);
	if (npos > 0) {
		fnvlist_add_uint32_array(info, KGPIO_ATTR_POS, pos, npos);
	}
	fnvlist_add_nvlist(meta, key, info);
	fnvlist_free(info);
}

static void
kgpio_release(kgpio_t *kgpio)
{
	ddi_release_devi(kgpio->kgpio_dip);

	mutex_enter(&kgpio->kgpio_mutex);
	VERIFY(kgpio->kgpio_flags & KGPIO_F_HELD);
	kgpio->kgpio_flags &= ~KGPIO_F_HELD;
	mutex_exit(&kgpio->kgpio_mutex);
}

static void
kgpio_release_meta(kgpio_t *kgpio)
{
	mutex_enter(&kgpio->kgpio_mutex);
	VERIFY(kgpio->kgpio_flags & KGPIO_F_META_WORK);
	kgpio->kgpio_flags &= ~KGPIO_F_META_WORK;
	cv_broadcast(&kgpio->kgpio_cv);
	mutex_exit(&kgpio->kgpio_mutex);
}

static int
kgpio_hold_by_id(id_t id)
{
	kgpio_t *kgpio;
	dev_info_t *pdip;
	kgpio_minor_t *minor;

restart:
	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find(id);
	if (minor == NULL) {
		mutex_exit(&kgpio_g_mutex);
		return (ESTALE);
	}
	if (minor->kminor_type != KGPIO_MINOR_T_CTRL) {
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}
	kgpio = minor->kminor_data.kminor_ctrl;

	mutex_enter(&kgpio->kgpio_mutex);
	if ((kgpio->kgpio_flags & KGPIO_F_REMOVED) != 0) {
		mutex_exit(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		return (ESTALE);
	}

	/*
	 * First, check if the node that we're looking at is both active and
	 * held. If it is then there is nothing more that we need to do and can
	 * acknowledge the open. We don't need to account for how many folks
	 * have opened it due to the kernel's accounting.
	 */
	if ((kgpio->kgpio_flags & (KGPIO_F_VALID | KGPIO_F_HELD)) ==
	    (KGPIO_F_VALID | KGPIO_F_HELD)) {
		mutex_exit(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		return (0);
	}

	/*
	 * This driver is either inactive and needs to be attached or it's not
	 * held. In either case we need to make sure that only one open(9E) can
	 * end up in here at a time. Note, while doing all this we drop the
	 * global and local lock. This will cause us to restart this entire
	 * loop.
	 */
	if ((kgpio->kgpio_flags & KGPIO_F_META_WORK) != 0) {
		mutex_exit(&kgpio_g_mutex);
		while ((kgpio->kgpio_flags & KGPIO_F_META_WORK) != 0) {
			int cv = cv_wait_sig(&kgpio->kgpio_cv,
			    &kgpio->kgpio_mutex);
			if (cv == 0) {
				mutex_exit(&kgpio->kgpio_mutex);
				return (EINTR);
			}
		}

		/*
		 * We're no longer waiting. However, we basically have to take
		 * another lap through here to check through all the core state
		 * again because we dropped the kgpio_g_mutex.
		 */
		mutex_exit(&kgpio->kgpio_mutex);
		goto restart;
	}

	/*
	 * At this point we can obtain ownership for performing meta work on
	 * this kgpio. Once we claim this we will need to drop our locks and
	 * related to perform all of the related NDI operations. However,
	 * because the meta work flag is set, this structure can't disappear.
	 */
	kgpio->kgpio_flags |= KGPIO_F_META_WORK;
	pdip = ddi_get_parent(kgpio->kgpio_dip);
	mutex_exit(&kgpio->kgpio_mutex);
	mutex_exit(&kgpio_g_mutex);

	/*
	 * This is required to ensure that the driver can't go away.
	 */
	ndi_devi_enter(pdip);
	e_ddi_hold_devi(kgpio->kgpio_dip);
	ndi_devi_exit(pdip);

	/*
	 * Because we dropped the main lock, we need to see if we lost a race
	 * again and if so unwind.
	 */
	mutex_enter(&kgpio->kgpio_mutex);
	kgpio->kgpio_flags |= KGPIO_F_HELD;
	if ((kgpio->kgpio_flags & KGPIO_F_REMOVED) != 0) {
		mutex_exit(&kgpio->kgpio_mutex);
		kgpio_release(kgpio);
		kgpio_release_meta(kgpio);
		return (ESTALE);
	}

	/*
	 * If the instance isn't valid yet, try to go and prod it via the NDI to
	 * wake up. This needs to happen if an instance gets detached, for
	 * example.
	 */
	if ((kgpio->kgpio_flags & KGPIO_F_VALID) == 0) {
		mutex_exit(&kgpio->kgpio_mutex);
		(void) ndi_devi_config(pdip, NDI_NO_EVENT);
		mutex_enter(&kgpio->kgpio_mutex);

		/*
		 * Check one last time for validity. If this has failed or its
		 * been removed, finally give up.
		 */
		ASSERT(kgpio->kgpio_flags & KGPIO_F_META_WORK);
		if ((kgpio->kgpio_flags & KGPIO_F_REMOVED) != 0 ||
		    (kgpio->kgpio_flags & KGPIO_F_VALID) == 0) {
			mutex_exit(&kgpio->kgpio_mutex);
			kgpio_release(kgpio);
			kgpio_release_meta(kgpio);
			return (ESTALE);
		}
	}

	/*
	 * OK, at this point we actually did it. We should be both VALID and
	 * HELD. We can release the meta work flag and we now should be good to
	 * go.
	 */
	ASSERT(kgpio->kgpio_flags & KGPIO_F_META_WORK);
	ASSERT(kgpio->kgpio_flags & KGPIO_F_HELD);
	ASSERT(kgpio->kgpio_flags & KGPIO_F_VALID);
	mutex_exit(&kgpio->kgpio_mutex);

	kgpio_release_meta(kgpio);

	return (0);
}

static int
kgpio_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	kgpio_minor_t *minor;
	dpio_t *dpio;

	if (drv_priv(credp) != 0)
		return (EPERM);

	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find((id_t)getminor(*devp));
	if (minor == NULL) {
		mutex_exit(&kgpio_g_mutex);
		return (ESTALE);
	}

	switch (minor->kminor_type) {
	case KGPIO_MINOR_T_CTRL:
		/*
		 * Opening a controller is awkward. By definition we have a
		 * valid minor number and we have kgpio; however, depending on
		 * the state of the actual controller it may not be held right
		 * now. In addition, while we have found a minor right now for
		 * this, when we go to potentially reattach it, if required, it
		 * may disappear. So, as weird as this is, now that we believe
		 * that this is a controller, we're going to call into the kgpio
		 * hold logic, which will itself end up taking and dropping the
		 * global locks across ndi calls. This mean that we're going to
		 * drop the lock and must ignore the minor we just found. This
		 * is ok, because the hold logic will validate the type and
		 * related again.
		 */
		mutex_exit(&kgpio_g_mutex);

		if (otyp != OTYP_CHR)
			return (ENOTSUP);

		if ((flag & (FNDELAY | FNONBLOCK | FEXCL)) != 0)
			return (EINVAL);

		if ((flag & FREAD) != FREAD)
			return (EINVAL);

		return (kgpio_hold_by_id((id_t)getminor(*devp)));
	case KGPIO_MINOR_T_DPIO:
		dpio = minor->kminor_data.kminor_dpio;
		mutex_enter(&dpio->dpio_mutex);
		mutex_exit(&kgpio_g_mutex);

		/*
		 * Verify the basics that we expect for a DPIO.
		 *  o It must be a character device.
		 *  o If a DPIO has been flagged with requiring kernel access
		 *    then FKLYR must be specified. If it is not, then it is an
		 *    error.
		 *  o We don't care about FNDELAY | FNONBLOCK, they will be
		 *    honored for read(9E) and write(9E) and checked in the
		 *    uio(9S).
		 *  o If the DPIO_S_EXCL status flag is set, then we have to
		 *    return that this device is already busy.
		 *  o If someone has asked for FEXCL, it is only allowed to
		 *    succeed if the device isn't already open.
		 */
		if ((dpio->dpio_flags & DPIO_F_KERNEL) != 0 &&
		    (flag & FKLYR) == 0) {
			mutex_exit(&dpio->dpio_mutex);
			return (EPERM);
		}

		if (otyp != OTYP_CHR) {
			mutex_exit(&dpio->dpio_mutex);
			return (ENOTSUP);
		}

		if ((dpio->dpio_status & DPIO_S_EXCL) != 0) {
			mutex_exit(&dpio->dpio_mutex);
			return (EBUSY);
		}

		if ((flag & FEXCL) != 0) {
			if ((dpio->dpio_status & DPIO_S_OPEN) != 0) {
				mutex_exit(&dpio->dpio_mutex);
				return (EBUSY);
			}
			dpio->dpio_status |= DPIO_S_EXCL;
		}

		dpio->dpio_status |= DPIO_S_OPEN;
		mutex_exit(&dpio->dpio_mutex);
		return (0);
	case KGPIO_MINOR_T_DPINFO:
		mutex_exit(&kgpio_g_mutex);

		/*
		 * For the DPIO Information device, this really just is used to
		 * get information and read-only ioctls. There is no special
		 * support for anything here. We do require read access as
		 * without that there isn't much to really do.
		 */
		if (otyp != OTYP_CHR) {
			return (ENOTSUP);
		}

		if ((flag & (FNDELAY | FNONBLOCK | FEXCL)) != 0) {
			return (EINVAL);
		}

		if ((flag & FREAD) != FREAD) {
			return (EINVAL);
		}

		return (0);
	default:
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}
}

static int
kgpio_ioctl_ctrl_info(kgpio_t *kgpio, intptr_t arg, int mode)
{
	kgpio_ctrl_info_t info;

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&info, sizeof (info));
	info.kci_ngroups = 0;
	info.kci_ngpios = kgpio->kgpio_ngpios;
	info.kci_ndpios = kgpio->kgpio_ndpios;
	(void) ddi_pathname(kgpio->kgpio_dip, info.kci_devpath);

	if (ddi_copyout(&info, (void *)arg, sizeof (info), mode & FKIOCTL) !=
	    0) {
		return (EFAULT);
	}

	return (0);
}

static int
kgpio_ioctl_gpio_info(kgpio_t *kgpio, intptr_t arg, int mode)
{
	int ret;
	uint_t model;
	char *pack = NULL;
	size_t pack_size = 0;
	kgpio_gpio_info_t info;
#ifdef	_MULTI_DATAMODEL
	kgpio_gpio_info32_t info32;
#endif

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &info32, sizeof (info32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}

		info.kgi_id = info32.kgi_id;
		info.kgi_flags = info32.kgi_flags;
		info.kgi_attr = info32.kgi_attr;
		info.kgi_attr_len = info32.kgi_attr_len;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &info, sizeof (info),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	if (info.kgi_id >= kgpio->kgpio_ngpios) {
		return (ENOENT);
	}

	nvlist_t *attr = fnvlist_alloc();
	ret = kgpio->kgpio_ops->kgo_get(kgpio->kgpio_drv, info.kgi_id, attr);
	if (ret != 0) {
		goto out;
	}

	pack = fnvlist_pack(attr, &pack_size);
	if (info.kgi_attr_len >= pack_size) {
		if (ddi_copyout(pack, (void *)info.kgi_attr, pack_size,
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
			goto out;
		}
		ret = 0;
	} else {
		ret = EOVERFLOW;
	}

	info.kgi_attr_len = pack_size;
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (info.kgi_attr_len > UINT32_MAX) {
			info32.kgi_attr_len = UINT32_MAX;
			ret = EOVERFLOW;
		} else {
			info32.kgi_attr_len = info.kgi_attr_len;
		}

		if (ddi_copyout(&info32, (void *)arg, sizeof (info32),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
			goto out;
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&info, (void *)arg, sizeof (info),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
			goto out;
		}
	}

out:
	if (pack != NULL) {
		ASSERT3U(pack_size, !=, 0);
		fnvlist_pack_free(pack, pack_size);
	}
	nvlist_free(attr);
	return (ret);
}

static int
kgpio_ioctl_gpio_update(kgpio_t *kgpio, intptr_t arg, int mode)
{
	int ret;
	uint_t model;
	char *user_data = NULL;
	nvlist_t *attr_nvl = NULL, *err_nvl = NULL;
	kgpio_update_t kgu;
#ifdef	_MULTI_DATAMODEL
	kgpio_update32_t kgu32;
#endif

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	model = ddi_model_convert_from(mode);
	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		if (ddi_copyin((void *)arg, &kgu32, sizeof (kgu32),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}

		kgu.kgu_id = kgu32.kgu_id;
		kgu.kgu_flags = kgu32.kgu_flags;
		kgu.kgu_attr = kgu32.kgu_attr;
		kgu.kgu_attr_len = kgu32.kgu_attr_len;
		kgu.kgu_err = kgu32.kgu_err;
		kgu.kgu_err_len = kgu32.kgu_err_len;
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyin((void *)arg, &kgu, sizeof (kgu),
		    mode & FKIOCTL) != 0) {
			return (EFAULT);
		}
		break;
	default:
		return (ENOTSUP);
	}

	/*
	 * We need to go back and verify that this GPIO doesn't correspond to a
	 * DPIO at all. This means we need the global mutex again. It's safe for
	 * us to drop and reacquire the kgpio's lock as because we're in the
	 * context of the open device, it can't go away.
	 */
	mutex_exit(&kgpio->kgpio_mutex);
	mutex_enter(&kgpio_g_mutex);
	mutex_enter(&kgpio->kgpio_mutex);

	for (dpio_t *dpio = list_head(&kgpio_g_dpios); dpio != NULL;
	    dpio = list_next(&kgpio_g_dpios, dpio)) {
		if (dpio->dpio_kgpio == kgpio &&
		    dpio->dpio_gpio_num == kgu.kgu_id) {
			mutex_exit(&kgpio_g_mutex);
			return (EROFS);
		}
	}
	mutex_exit(&kgpio_g_mutex);

	if (kgu.kgu_attr_len > kgpio_max_user_nvl) {
		return (E2BIG);
	}

	if (kgu.kgu_id >= kgpio->kgpio_ngpios) {
		return (ENOENT);
	}

	user_data = kmem_alloc(kgpio_max_user_nvl, KM_NOSLEEP_LAZY);
	if (user_data == NULL) {
		return (ENOMEM);
	}

	if (ddi_copyin((void *)kgu.kgu_attr, user_data, kgu.kgu_attr_len,
	    mode & FKIOCTL) != 0) {
		ret = EFAULT;
		goto err;
	}

	if (nvlist_unpack(user_data, kgu.kgu_attr_len, &attr_nvl, 0) != 0) {
		ret = EINVAL;
		goto err;
	}

	err_nvl = fnvlist_alloc();
	ret = kgpio->kgpio_ops->kgo_set(kgpio->kgpio_drv, kgu.kgu_id, attr_nvl,
	    err_nvl);
	/*
	 * If this failed and we had an error nvlist, then we don't return an
	 * errno and instead translate this into the structure that we copy out.
	 * We always zero out the flags and then will set what appropriate bits
	 * we need. This next if statement will zero out ret, indicating to us
	 * that we should attempt to copy out this structure. If anything in the
	 * process of trying to copy out errors fails, then we don't worry about
	 * that and return a larger error because that is indicative of failure
	 * it just means userland can't get as much info as we wished.
	 */
	kgu.kgu_flags = 0;
	if (ret != 0 && nvlist_next_nvpair(err_nvl, NULL) != NULL) {
		size_t err_len;

		kgu.kgu_flags |= KGPIO_UPDATE_ERROR;
		ret = nvlist_size(err_nvl, &err_len, NV_ENCODE_NATIVE);

		if (ret == 0 && err_len <= MIN(kgu.kgu_err_len,
		    kgpio_max_user_nvl)) {
			ret = nvlist_pack(err_nvl, &user_data, &err_len,
			    NV_ENCODE_NATIVE, 0);
			if (ret != 0) {
				goto err;
			}

			kgu.kgu_err_len = err_len;
			if (ddi_copyout(user_data, (void *)kgu.kgu_err, err_len,
			    mode & FKIOCTL) != 0) {
				ret = EFAULT;
			} else {
				kgu.kgu_flags |= KGPIO_UPDATE_ERR_NVL_VALID;
				ret = 0;
			}
		}
	}

	if (ret != 0) {
		goto err;
	}

	switch (model) {
#ifdef	_MULTI_DATAMODEL
	case DDI_MODEL_ILP32:
		/*
		 * Other values should still hold from copyin, hence we only
		 * update those that we would have changed here.
		 */
		kgu32.kgu_flags = kgu.kgu_flags;
		kgu32.kgu_err_len = kgu.kgu_err_len;

		if (ddi_copyout(&kgu32, (void *)arg, sizeof (kgu32),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
		}
		break;
#endif	/* _MULTI_DATAMODEL */
	case DDI_MODEL_NONE:
		if (ddi_copyout(&kgu, (void *)arg, sizeof (kgu),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
		}
		break;
	default:
		ret = ENOTSUP;
	}

err:
	if (err_nvl != NULL) {
		nvlist_free(err_nvl);
	}

	if (attr_nvl != NULL) {
		nvlist_free(attr_nvl);
	}

	if (user_data != NULL) {
		kmem_free(user_data, kgpio_max_user_nvl);
	}
	return (ret);
}

static bool
kgpio_valid_name(const char *name, size_t buflen)
{
	size_t i;

	for (i = 0; i < buflen; i++) {
		if (name[i] == '\0')
			break;

		/*
		 * Right now we constrain GPIO names to be alphanumeric and
		 * allow for separators to exist. However, for file system
		 * simplicity we constrain the first character to be
		 * alphanumeric.
		 */
		if (i == 0 && !isalnum(name[i])) {
			return (false);
		} else if (!isalnum(name[i]) && name[i] != '_' &&
		    name[i] != '.' && name[i] != '-' && name[i] != '+') {
			return (false);
		}
	}

	if (i == 0 || i == buflen) {
		return (false);
	}

	return (true);
}

static int
kgpio_ioctl_dpio_create(kgpio_t *kgpio, intptr_t arg, int mode)
{
	int ret;
	dpio_caps_t sup_caps, caps = 0;
	const kgpio_dpio_flags_t all_flags = KGPIO_DPIO_F_READ |
	    KGPIO_DPIO_F_WRITE | KGPIO_DPIO_F_KERNEL;
	kgpio_dpio_create_t create;
	char name[KGPIO_DPIO_INT_NAMELEN];
	size_t namelen;

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &create, sizeof (kgpio_dpio_create_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (create.kdc_id >= kgpio->kgpio_ngpios) {
		return (ENOENT);
	}

	if (!kgpio_valid_name(create.kdc_name, sizeof (create.kdc_name))) {
		return (EINVAL);
	}
	namelen = snprintf(name, sizeof (name), "dpio:%s", create.kdc_name);
	ASSERT3U(namelen, <, KGPIO_DPIO_INT_NAMELEN);

	/*
	 * It is perfectly fine to create a DPIO with no flags. That is then
	 * something which is constrained with its current attributes, providing
	 * the system guarantees that it should not change, though it is a
	 * little weird.
	 */
	if ((create.kdc_flags & ~all_flags) != 0) {
		return (EINVAL);
	}

	if (kgpio->kgpio_ops->kgo_cap == NULL) {
		return (ENOTSUP);
	}
	ret = kgpio->kgpio_ops->kgo_cap(kgpio->kgpio_drv, create.kdc_id,
	    &sup_caps);
	if (ret != 0) {
		return (ret);
	}

	if ((create.kdc_flags & KGPIO_DPIO_F_READ) != 0) {
		if (kgpio->kgpio_ops->kgo_input == NULL ||
		    (sup_caps & DPIO_C_READ) == 0) {
			return (ENOTSUP);
		}
		caps |= DPIO_C_READ;
	}

	if ((create.kdc_flags & KGPIO_DPIO_F_WRITE) != 0) {
		if (kgpio->kgpio_ops->kgo_output_state == NULL ||
		    kgpio->kgpio_ops->kgo_output == NULL ||
		    (sup_caps & DPIO_C_WRITE) == 0) {
			return (ENOTSUP);
		}
		caps |= DPIO_C_WRITE;
	}

	if ((caps & DPIO_C_READ) != 0 && (sup_caps & DPIO_C_POLL) != 0) {
		caps |= DPIO_C_POLL;
	}

	/*
	 * At this point, everything that we have for the DPIO is valid. The
	 * remaining things we need to try and do are:
	 *
	 *  o Ensure that there isn't a DPIO with this name already.
	 *  o Ensure that there isn't a DPIO already using this particular
	 *    GPIO.
	 *  o Create our DPIO structure, get underlying caps, and ultimately
	 *    create our minor.
	 *
	 * To do this, we need to acquire the global lock to ensure that we
	 * don't end up racing with anyone else. We've already gotten all
	 * information that we need from the kgpio controller and because we
	 * looked up and ensured the underlying controller is held, it should
	 * not disappear on us as we drop the lock.
	 */
	mutex_exit(&kgpio->kgpio_mutex);
	mutex_enter(&kgpio_g_mutex);
	mutex_enter(&kgpio->kgpio_mutex);

	for (dpio_t *dpio = list_head(&kgpio_g_dpios); dpio != NULL;
	    dpio = list_next(&kgpio_g_dpios, dpio)) {
		if (dpio->dpio_kgpio == kgpio &&
		    dpio->dpio_gpio_num == create.kdc_id) {
			mutex_exit(&kgpio_g_mutex);
			return (EBUSY);
		}

		if (strcmp(name, dpio->dpio_name) == 0) {
			mutex_exit(&kgpio_g_mutex);
			return (EEXIST);
		}
	}

	dpio_t *dpio = kmem_zalloc(sizeof (dpio_t), KM_NOSLEEP_LAZY);
	if (dpio == NULL) {
		mutex_exit(&kgpio_g_mutex);
		return (ENOMEM);
	}

	dpio->dpio_kgpio = kgpio;
	dpio->dpio_gpio_num = create.kdc_id;
	dpio->dpio_caps = caps;
	if ((create.kdc_flags & KGPIO_DPIO_F_KERNEL) != 0) {
		dpio->dpio_flags |= DPIO_F_KERNEL;
	}
	/*
	 * Note, we have a guarantee that the name length here is less than the
	 * actual buffer size. The NUL termination comes from the kmem_zalloc
	 * earlier.
	 */
	bcopy(name, dpio->dpio_name, namelen);
	mutex_init(&dpio->dpio_mutex, NULL, MUTEX_DRIVER, NULL);

	dpio->dpio_minor.kminor_id = id_alloc_nosleep(kgpio_g_ids);
	if (dpio->dpio_minor.kminor_id == -1) {
		mutex_exit(&kgpio_g_mutex);
		kgpio_dpio_cleanup(dpio);
		return (ENOSPC);
	}
	dpio->dpio_minor.kminor_type = KGPIO_MINOR_T_DPIO;
	dpio->dpio_minor.kminor_data.kminor_dpio = dpio;

	if (ddi_create_minor_node(kgpio_g_dip, dpio->dpio_name, S_IFCHR,
	    (minor_t)dpio->dpio_minor.kminor_id, DDI_NT_GPIO_DPIO, 0) !=
	    DDI_SUCCESS) {
		mutex_exit(&kgpio_g_mutex);
		kgpio_dpio_cleanup(dpio);
		return (EIO);
	}

	list_insert_tail(&kgpio_g_dpios, dpio);
	avl_add(&kgpio_g_minors, &dpio->dpio_minor);
	kgpio->kgpio_ndpios++;
	mutex_exit(&kgpio_g_mutex);

	/*
	 * This was successful, there is one last dance that we must do. We must
	 * place a hold on the kgpio's dip. And of course, no lock holding
	 * across the ndi hold.
	 */
	mutex_exit(&kgpio->kgpio_mutex);
	e_ddi_hold_devi(kgpio->kgpio_dip);
	mutex_enter(&kgpio->kgpio_mutex);

	return (0);
}

static int
kgpio_ioctl_dpio_destroy(kgpio_t *kgpio, intptr_t arg, int mode)
{
	dpio_t *dpio;
	kgpio_dpio_destroy_t destroy;

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FWRITE) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &destroy, sizeof (kgpio_dpio_destroy_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	if (destroy.kdd_id >= kgpio->kgpio_ngpios) {
		return (ENOENT);
	}

	mutex_exit(&kgpio->kgpio_mutex);
	mutex_enter(&kgpio_g_mutex);
	for (dpio = list_head(&kgpio_g_dpios); dpio != NULL;
	    dpio = list_next(&kgpio_g_dpios, dpio)) {
		if (dpio->dpio_kgpio == kgpio &&
		    dpio->dpio_gpio_num == destroy.kdd_id) {
			break;
		}
	}

	if (dpio == NULL) {
		mutex_enter(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		return (ENOENT);
	}

	if ((dpio->dpio_status & DPIO_S_OPEN) != 0) {
		mutex_enter(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		return (EBUSY);
	}

	/*
	 * OK, time to tear all this down. Remove it from global visibility as
	 * it's not open. After this point, we no longer need the kgpio_g_lock.
	 */
	list_remove(&kgpio_g_dpios, dpio);
	avl_remove(&kgpio_g_minors, &dpio->dpio_minor);
	mutex_exit(&kgpio_g_mutex);

	/*
	 * At this point, it should be safe to destroy the dpio and then clean
	 * up the remaining tracking on the kgpio. Over there, we need to need
	 * to drop our corresponding hold and decrement the overall count.
	 *
	 * To ensure that devfs notices that the minor goes away, we basically
	 * have to flag the directory for rebuild. As such, we do this somewhat
	 * via a constrained max power way -- by asking it to clean up after
	 * ourselves. This will of course be busy, but it does mean that a
	 * rebuild flag will show up.
	 */
	kgpio_dpio_cleanup(dpio);
	(void) devfs_clean(ddi_get_parent(kgpio_g_dip), "kgpio@0", 0);
	ddi_release_devi(kgpio->kgpio_dip);

	mutex_enter(&kgpio->kgpio_mutex);
	VERIFY3P(kgpio->kgpio_ndpios, >, 0);
	kgpio->kgpio_ndpios--;

	return (0);
}

static int
kgpio_ioctl_dpio_info_common(const dpio_t *dpio, dpio_info_t *infop,
    intptr_t arg, int mode)
{
	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bcopy(dpio->dpio_kgpio->kgpio_mname, infop->dpi_ctrl,
	    sizeof (dpio->dpio_kgpio->kgpio_mname));
	infop->dpi_gpio = dpio->dpio_gpio_num;
	infop->dpi_caps = dpio->dpio_caps;
	infop->dpi_flags = dpio->dpio_flags;

	if (ddi_copyout(infop, (void *)arg, sizeof (dpio_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
kgpio_ioctl_dpio_info_specific(dpio_t *dpio, intptr_t arg, int mode)
{
	dpio_info_t info;

	ASSERT(MUTEX_HELD(&dpio->dpio_mutex));

	bzero(&info, sizeof (info));
	bcopy(dpio->dpio_name, info.dpi_dpio, sizeof (dpio->dpio_name));
	return (kgpio_ioctl_dpio_info_common(dpio, &info, arg, mode));
}

static int
kgpio_ioctl_dpio_time(dpio_t *dpio, intptr_t arg, int mode)
{
	dpio_timing_t time;

	ASSERT(MUTEX_HELD(&dpio->dpio_mutex));

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&time, sizeof (time));
	time.dpt_last_input_intr = dpio->dpio_last_intr;
	time.dpt_last_write = dpio->dpio_last_write;

	if (ddi_copyout(&time, (void *)arg, sizeof (dpio_timing_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
kgpio_ioctl_dpio_curout(dpio_t *dpio, intptr_t arg, int mode)
{
	int ret;
	dpio_curout_t curout;
	kgpio_t *kgpio = dpio->dpio_kgpio;

	ASSERT(MUTEX_HELD(&dpio->dpio_mutex));

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	bzero(&curout, sizeof (curout));
	if ((dpio->dpio_caps & DPIO_C_WRITE) == 0) {
		return (ENOTSUP);
	}

	mutex_exit(&dpio->dpio_mutex);
	mutex_enter(&kgpio->kgpio_mutex);
	ret = kgpio->kgpio_ops->kgo_output_state(kgpio->kgpio_drv,
	    dpio->dpio_gpio_num, &curout.dps_curout);
	mutex_exit(&kgpio->kgpio_mutex);
	mutex_enter(&dpio->dpio_mutex);

	if (ret != 0) {
		return (ret);

	}

	if (ddi_copyout(&curout, (void *)arg, sizeof (dpio_curout_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
kgpio_ioctl_dpio_info_search(intptr_t arg, int mode)
{
	size_t len;
	dpio_info_t info;

	ASSERT(MUTEX_HELD(&kgpio_g_mutex));

	if (ddi_copyin((void *)arg, &info, sizeof (dpio_info_t),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	len = strnlen(info.dpi_dpio, sizeof (info.dpi_dpio));
	if (len == 0 || len == sizeof (info.dpi_dpio)) {
		return (EINVAL);
	}

	for (dpio_t *dpio = list_head(&kgpio_g_dpios); dpio != NULL;
	    dpio = list_next(&kgpio_g_dpios, dpio)) {
		if (strcmp(dpio->dpio_name, info.dpi_dpio) == 0) {
			return (kgpio_ioctl_dpio_info_common(dpio, &info, arg,
			    mode));
		}
	}

	return (ENOENT);
}

static int
kgpio_ioctl_gpio_name2id(kgpio_t *kgpio, intptr_t arg, int mode)
{
	int ret;
	kgpio_ioc_name2id_t id;
	size_t len;

	ASSERT(MUTEX_HELD(&kgpio->kgpio_mutex));

	if ((mode & FREAD) == 0) {
		return (EBADF);
	}

	if (ddi_copyin((void *)arg, &id, sizeof (id), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	len = strnlen(id.kin_name, sizeof (id.kin_name));
	if (len == 0 || len == sizeof (id.kin_name)) {
		return (EINVAL);
	}

	ret = kgpio->kgpio_ops->kgo_name2id(kgpio->kgpio_drv, id.kin_name,
	    &id.kin_id);
	if (ret != 0) {
		return (ret);
	}

	if (ddi_copyout(&id, (void *)arg, sizeof (id), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
kgpio_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;
	kgpio_minor_t *minor;
	kgpio_t *kgpio;
	dpio_t *dpio;

	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find((id_t)getminor(dev));
	VERIFY3P(minor, !=, NULL);
	switch (minor->kminor_type) {
	case KGPIO_MINOR_T_CTRL:
		kgpio = minor->kminor_data.kminor_ctrl;
		VERIFY3P(kgpio, !=, NULL);

		mutex_enter(&kgpio->kgpio_mutex);
		mutex_exit(&kgpio_g_mutex);
		ASSERT(kgpio->kgpio_flags & KGPIO_F_VALID);
		ASSERT(kgpio->kgpio_flags & KGPIO_F_HELD);

		switch (cmd) {
		case KGPIO_IOC_CTRL_INFO:
			ret = kgpio_ioctl_ctrl_info(kgpio, arg, mode);
			break;
		case KGPIO_IOC_GPIO_INFO:
			ret = kgpio_ioctl_gpio_info(kgpio, arg, mode);
			break;
		case KGPIO_IOC_GPIO_UPDATE:
			ret = kgpio_ioctl_gpio_update(kgpio, arg, mode);
			break;
		case KGPIO_IOC_DPIO_CREATE:
			ret = kgpio_ioctl_dpio_create(kgpio, arg, mode);
			break;
		case KGPIO_IOC_DPIO_DESTROY:
			ret = kgpio_ioctl_dpio_destroy(kgpio, arg, mode);
			break;
		case KGPIO_IOC_GPIO_NAME2ID:
			ret = kgpio_ioctl_gpio_name2id(kgpio, arg, mode);
			break;
		default:
			ret = ENOTTY;
			break;
		}

		mutex_exit(&kgpio->kgpio_mutex);
		break;
	case KGPIO_MINOR_T_DPIO:
		dpio = minor->kminor_data.kminor_dpio;
		VERIFY3P(dpio, !=, NULL);
		mutex_enter(&dpio->dpio_mutex);
		mutex_exit(&kgpio_g_mutex);

		switch (cmd) {
		case DPIO_IOC_INFO:
			ret = kgpio_ioctl_dpio_info_specific(dpio, arg, mode);
			break;
		case DPIO_IOC_TIMING:
			ret = kgpio_ioctl_dpio_time(dpio, arg, mode);
			break;
		case DPIO_IOC_CUROUT:
			ret = kgpio_ioctl_dpio_curout(dpio, arg, mode);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		mutex_exit(&dpio->dpio_mutex);
		break;
	case KGPIO_MINOR_T_DPINFO:
		switch (cmd) {
		case DPIO_IOC_INFO:
			ret = kgpio_ioctl_dpio_info_search(arg, mode);
			break;
		default:
			ret = ENOTTY;
			break;
		}
		mutex_exit(&kgpio_g_mutex);
		break;
	default:
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}
	return (ret);
}

static int
kgpio_read(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	kgpio_minor_t *minor;
	dpio_t *dpio;
	kgpio_t *kgpio;
	dpio_input_t input;
	offset_t off;

	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find((id_t)getminor(dev));
	VERIFY3P(minor, !=, NULL);

	if (minor->kminor_type != KGPIO_MINOR_T_DPIO) {
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}

	dpio = minor->kminor_data.kminor_dpio;
	VERIFY3P(dpio, !=, NULL);
	mutex_exit(&kgpio_g_mutex);

	if ((dpio->dpio_caps & DPIO_C_READ) == 0) {
		return (ENOTSUP);
	}

	if (uiop->uio_resid <= 0) {
		return (EINVAL);
	}

	if (uiop->uio_resid < sizeof (input)) {
		return (EOVERFLOW);
	}

	kgpio = dpio->dpio_kgpio;
	mutex_enter(&kgpio->kgpio_mutex);
	ret = kgpio->kgpio_ops->kgo_input(kgpio->kgpio_drv, dpio->dpio_gpio_num,
	    &input);
	mutex_exit(&kgpio->kgpio_mutex);
	if (ret != 0) {
		return (ret);
	}

	off = uiop->uio_loffset;
	ret = uiomove(&input, sizeof (input), UIO_READ, uiop);
	uiop->uio_loffset = off;

	return (ret);
}

static int
kgpio_write(dev_t dev, struct uio *uiop, cred_t *credp)
{
	int ret;
	kgpio_minor_t *minor;
	dpio_t *dpio;
	kgpio_t *kgpio;
	dpio_output_t output;
	offset_t off;

	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find((id_t)getminor(dev));
	VERIFY3P(minor, !=, NULL);

	if (minor->kminor_type != KGPIO_MINOR_T_DPIO) {
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}

	dpio = minor->kminor_data.kminor_dpio;
	VERIFY3P(dpio, !=, NULL);
	mutex_exit(&kgpio_g_mutex);

	if ((dpio->dpio_caps & DPIO_C_WRITE) == 0) {
		return (ENOTSUP);
	}

	if (uiop->uio_resid < sizeof (output)) {
		return (EINVAL);
	}

	off = uiop->uio_loffset;
	ret = uiomove(&output, sizeof (output), UIO_WRITE, uiop);
	uiop->uio_loffset = off;
	if (ret != 0) {
		return (ret);
	}

	switch (output) {
	case DPIO_OUTPUT_LOW:
	case DPIO_OUTPUT_HIGH:
	case DPIO_OUTPUT_DISABLE:
		break;
	default:
		return (EINVAL);
	}

	kgpio = dpio->dpio_kgpio;
	mutex_enter(&kgpio->kgpio_mutex);
	ret = kgpio->kgpio_ops->kgo_output(kgpio->kgpio_drv,
	    dpio->dpio_gpio_num, output);
	mutex_exit(&kgpio->kgpio_mutex);

	if (ret == 0) {
		mutex_enter(&dpio->dpio_mutex);
		dpio->dpio_last_write = gethrtime();
		mutex_exit(&dpio->dpio_mutex);
	}

	return (ret);
}

static int
kgpio_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	kgpio_minor_t *minor;
	kgpio_t *kgpio;
	dpio_t *dpio;

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	mutex_enter(&kgpio_g_mutex);
	minor = kgpio_minor_find((id_t)getminor(dev));
	VERIFY3P(minor, !=, NULL);
	switch (minor->kminor_type) {
	case KGPIO_MINOR_T_CTRL:
		kgpio = minor->kminor_data.kminor_ctrl;
		VERIFY3P(kgpio, !=, NULL);

		mutex_enter(&kgpio->kgpio_mutex);
		ASSERT(kgpio->kgpio_flags & KGPIO_F_VALID);
		ASSERT(kgpio->kgpio_flags & KGPIO_F_HELD);

		/*
		 * The system guarantees that we are mutually exclusive with
		 * open(9E).  As such, it's safe for us to go ahead and clear
		 * this out. Note, we drop all of our locks to honor the general
		 * lock ordering of no NDI activity with locks held.
		 */
		mutex_exit(&kgpio_g_mutex);
		mutex_exit(&kgpio->kgpio_mutex);

		kgpio_release(kgpio);
		return (0);
	case KGPIO_MINOR_T_DPIO:
		dpio = minor->kminor_data.kminor_dpio;
		VERIFY3P(dpio, !=, NULL);
		mutex_enter(&dpio->dpio_mutex);
		mutex_exit(&kgpio_g_mutex);

		/*
		 * Because of the last-close style behavior, the only thing that
		 * we need to do is to make sure that we clear out our state
		 * flags and indicate that we are no longer open and no longer
		 * exclusive, if we were.
		 */
		dpio->dpio_status &= ~(DPIO_S_EXCL | DPIO_S_OPEN);
		mutex_exit(&dpio->dpio_mutex);
		return (0);
	case KGPIO_MINOR_T_DPINFO:
		mutex_exit(&kgpio_g_mutex);
		/*
		 * There is nothing special to do to close the dpio information
		 * based minor device as there is no state or other logic
		 * associated with it.
		 */
		return (0);
	default:
		mutex_exit(&kgpio_g_mutex);
		return (ENXIO);
	}
}

static int
kgpio_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_ATTACH:
		break;
	case DDI_RESUME:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	if (ddi_get_instance(dip) != 0) {
		dev_err(dip, CE_WARN, "asked to attach non-zero instance");
		return (DDI_FAILURE);
	}

	mutex_enter(&kgpio_g_mutex);
	if (kgpio_g_dip != NULL) {
		mutex_exit(&kgpio_g_mutex);
		dev_err(dip, CE_WARN, "asked to attach a second kgpio "
		    "instance");
		return (DDI_FAILURE);
	}

	/*
	 * Set up the dpio minor, which always uses minor number 1, note this is
	 * reserved outside of the id_space, so we don't have to allocate or
	 * worry about failure.
	 */
	if (ddi_create_minor_node(dip, KGPIO_MINOR_NAME_DPINFO, S_IFCHR,
	    KGPIO_MINOR_DPINFO, DDI_PSEUDO, 0) != 0) {
		dev_err(dip, CE_WARN, "failed to create dpinfo minor");
		mutex_exit(&kgpio_g_mutex);
		return (DDI_FAILURE);
	}

	kgpio_g_dpinfo.kminor_id = KGPIO_MINOR_DPINFO;
	kgpio_g_dpinfo.kminor_type = KGPIO_MINOR_T_DPINFO;
	avl_add(&kgpio_g_minors, &kgpio_g_dpinfo);
	kgpio_g_dip = dip;

	/*
	 * At this point, we need to check for any drivers that beat us and
	 * register them.
	 */
	for (kgpio_t *k = list_head(&kgpio_g_gpios); k != NULL;
	    k = list_next(&kgpio_g_gpios, k)) {
		mutex_enter(&k->kgpio_mutex);
		ASSERT0(k->kgpio_flags & KGPIO_F_MINOR_VALID);
		kgpio_create_minor(k);
		mutex_exit(&k->kgpio_mutex);
	}
	mutex_exit(&kgpio_g_mutex);
	return (DDI_SUCCESS);
}

static int
kgpio_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = kgpio_g_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)ddi_get_instance(kgpio_g_dip);
		break;
	default:
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static int
kgpio_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	switch (cmd) {
	case DDI_DETACH:
		break;
	case DDI_SUSPEND:
		return (DDI_SUCCESS);
	default:
		return (DDI_FAILURE);
	}

	mutex_enter(&kgpio_g_mutex);
	if (dip != kgpio_g_dip) {
		mutex_exit(&kgpio_g_mutex);
		dev_err(dip, CE_WARN, "asked to detach dip that is not the "
		    "current kgpio dip");
		return (DDI_FAILURE);
	}

	if (list_is_empty(&kgpio_g_gpios) == 0) {
		mutex_exit(&kgpio_g_mutex);
		return (DDI_FAILURE);
	}

	avl_remove(&kgpio_g_minors, &kgpio_g_dpinfo);
	ddi_remove_minor_node(dip, KGPIO_MINOR_NAME_DPINFO);
	kgpio_g_dip = NULL;
	mutex_exit(&kgpio_g_mutex);
	return (DDI_SUCCESS);
}

static struct cb_ops kgpio_cb_ops = {
	.cb_open = kgpio_open,
	.cb_close = kgpio_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = kgpio_read,
	.cb_write = kgpio_write,
	.cb_ioctl = kgpio_ioctl,
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

static struct dev_ops kgpio_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = kgpio_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = kgpio_attach,
	.devo_detach = kgpio_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &kgpio_cb_ops
};

static struct modldrv kgpio_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "Kernel GPIO Framework",
	.drv_dev_ops = &kgpio_dev_ops
};

static struct modlinkage kgpio_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &kgpio_modldrv, NULL }
};

static void
kgpio_init(void)
{
	mutex_init(&kgpio_g_mutex, NULL, MUTEX_DRIVER, NULL);
	list_create(&kgpio_g_gpios, sizeof (kgpio_t),
	    offsetof(kgpio_t, kgpio_link));
	list_create(&kgpio_g_dpios, sizeof (dpio_t),
	    offsetof(dpio_t, dpio_link));
	avl_create(&kgpio_g_minors, kgpio_minor_comparator,
	    sizeof (kgpio_minor_t), offsetof(kgpio_minor_t, kminor_avl));
	kgpio_g_ids = id_space_create("kgpios", KGPIO_MINOR_FIRST, L_MAXMIN32);
}

static void
kgpio_fini(void)
{
	id_space_destroy(kgpio_g_ids);
	avl_destroy(&kgpio_g_minors);
	list_destroy(&kgpio_g_dpios);
	list_destroy(&kgpio_g_gpios);
	mutex_destroy(&kgpio_g_mutex);
}

int
_init(void)
{
	int err;

	kgpio_init();
	err = mod_install(&kgpio_modlinkage);
	if (err != 0) {
		kgpio_fini();
		return (err);
	}

	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&kgpio_modlinkage, modinfop));
}

int
_fini(void)
{
	int err;

	mutex_enter(&kgpio_g_mutex);
	if (list_is_empty(&kgpio_g_gpios) == 0) {
		mutex_exit(&kgpio_g_mutex);
		return (EBUSY);
	}
	mutex_exit(&kgpio_g_mutex);


	err = mod_remove(&kgpio_modlinkage);
	if (err != 0) {
		return (err);
	}

	kgpio_fini();
	return (0);
}
