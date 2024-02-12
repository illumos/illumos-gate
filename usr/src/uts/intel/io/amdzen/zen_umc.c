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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * AMD Zen Unified Memory Controller Driver
 *
 * This file forms the core logic around transforming a physical address that
 * we're used to using into a specific location on a DIMM. This has support for
 * a wide range of AMD CPUs and APUs ranging from Zen 1 - Zen 4.
 *
 * The goal of this driver is to implement the infrastructure and support
 * necessary to understand how DRAM requests are being routed in the system and
 * to be able to map those to particular channels and then DIMMs. This is used
 * as part of RAS (reliability, availability, and serviceability) to enable
 * aspects around understanding ECC errors, hardware topology, and more. Like
 * with any software project, there is more to do here. Please see the Future
 * Work section at the end of this big theory statement for more information.
 *
 * -------------------
 * Driver Organization
 * -------------------
 *
 * This driver is organized into two major pieces:
 *
 *   1. Logic to interface with hardware, discover the data fabric, memory
 *      controller configuration, and transform that into a normalized fashion
 *      that can be used across all different Zen family CPUs. This is
 *      implemented generally in this file, and is designed to assume it is in
 *      the kernel (as it requires access to the SMN, DF PCI registers, and the
 *      amdzen nexus driver client services).
 *
 *   2. Logic that can take the above normalized memory information and perform
 *      decoding (e.g. physical address to DIMM information). This generally
 *      lives in common/mc/zen_uc/zen_umc_decode.c. This file is in common/,
 *      meaning it is designed to be shared by userland and the kernel. Even
 *      more so, it is designed to operate on a const version of our primary
 *      data structure (zen_umc_t), not allowing it to be modified. This allows
 *      us to more easily unit test the decoding logic and utilize it in other
 *      circumstances such as with the mcdecode utility.
 *
 * There is corresponding traditional dev_ops(9S) and cb_ops(9S) logic in the
 * driver (currently this file) which take care of interfacing with the broader
 * operating system environment.
 *
 * There is only ever one instance of this driver, e.g. it is a singleton in
 * design pattern parlance. There is a single struct, the zen_umc_t found in the
 * global (albeit static) variable zen_umc. This structure itself contains a
 * hierarchical set of structures that describe the system. To make management
 * of memory simpler, all of the nested structures that we discover from
 * hardware are allocated in the same structure. The only exception to this rule
 * is when we cache serialized nvlists for dumping.
 *
 * The organization of the structures inside the zen_umc_t, generally mimics the
 * hardware organization and is structured as follows:
 *
 *   +-----------+
 *   | zen_umc_t |
 *   +-----------+
 *        |
 *        +-------------------------------+
 *        v                               v
 *   +--------------+             +--------------+        One instance of the
 *   | zen_umc_df_t |     ...     | zen_umc_df_t |        zen_umc_df_t per
 *   +--------------+             +--------------+        discovered DF.
 *     |||
 *     |||
 *     |||    +----------------+         +----------------+  Global DRAM
 *     ||+--->| df_dram_rule_t |   ...   | df_dram_rule_t |  rules for the
 *     ||     +----------------+         +----------------+  platform.
 *     ||
 *     ||    +--------------------+       +--------------------+  UMC remap
 *     |+--->| zen_umc_cs_remap_t |  ...  | zen_umc_cs_remap_t |  rule arrays.
 *     |     +--------------------+       +--------------------+
 *     |
 *     v
 *    +----------------+         +----------------+   One structure per
 *    | zen_umc_chan_t |   ...   | zen_umc_chan_t |   discovered DDR4/5
 *    +----------------+         +----------------+   memory channel.
 *     ||||
 *     ||||
 *     ||||    +----------------+       +----------------+   Channel specific
 *     |||+--->| df_dram_rule_t |  ...  | df_dram_rule_t |   copy of DRAM rules.
 *     |||     +----------------+       +----------------+   Less than global.
 *     |||
 *     |||     +---------------+       +---------------+   Per-Channel DRAM
 *     ||+---->| chan_offset_t |  ...  | chan_offset_t |   offset that is used
 *     ||      +---------------+       +---------------+   for normalization.
 *     ||
 *     ||      +-----------------+                         Channel-specific
 *     |+----->| umc_chan_hash_t |                         hashing rules.
 *     |       +-----------------+
 *     |
 *     |       +------------+         +------------+    One structure for
 *     +------>| umc_dimm_t |   ...   | umc_dimm_t |    each DIMM in the
 *             +------------+         +------------+    channel. Always two.
 *                |
 *                |     +----------+         +----------+   Per chip-select
 *                +---> | umc_cs_t |   ...   | umc_cs_t |   data. Always two.
 *                      +----------+         +----------+
 *
 * In the data structures themselves you'll often find several pieces of data
 * that have the term 'raw' in their name. The point of these is to basically
 * capture the original value that we read from the register before processing
 * it. These are generally used either for debugging or to help answer future
 * curiosity with resorting to the udf and usmn tooling, which hopefully aren't
 * actually installed on systems.
 *
 * With the exception of some of the members in the zen_umc_t that are around
 * management of state for userland ioctls, everything in the structure is
 * basically write-once and from that point on should be treated as read-only.
 *
 * ---------------
 * Memory Decoding
 * ---------------
 *
 * To understand the process of memory decoding, it's worth going through and
 * understanding a bunch of the terminology that is used in this process. As an
 * additional reference when understanding this, you may want to turn to either
 * an older generation AMD BIOS and Kernel Developer's Guide or the more current
 * Processor Programming Reference. In addition, the imc driver, which is the
 * Intel equivalent, also provides an additional bit of reference.
 *
 * SYSTEM ADDRESS
 *
 *	This is a physical address and is the way that the operating system
 *	normally thinks of memory. System addresses can refer to many different
 *	things. For example, you have traditional DRAM, memory-mapped PCIe
 *	devices, peripherals that the processor exposes such as the xAPIC, data
 *	from the FCH (Fusion Controller Hub), etc.
 *
 * TOM, TOM2, and the DRAM HOLE
 *
 *	Physical memory has a complicated layout on x86 in part because of
 *	support for traditional 16-bit and 32-bit systems. As a result, contrary
 *	to popular belief, DRAM is not at a consistent address range in the
 *	processor. AMD processors have a few different ranges. There is a 32-bit
 *	region that starts at effectively physical address zero and goes to the
 *	TOM MSR (top of memory -- Core::X86::Msr::TOP_MEM). This indicates a
 *	limit below 4 GiB, generally around 2 GiB.
 *
 *	From there, the next region of DRAM starts at 4 GiB and goes to TOM2
 *	(top of memory 2 -- Core::X86::Msr::TOM2). The region between TOM and
 *	4 GiB is called the DRAM hole. Physical addresses in this region are
 *	used for memory mapped I/O. This breaks up contiguous physical
 *	addresses being used for DRAM, creating a "hole".
 *
 * DATA FABRIC
 *
 *	The data fabric (DF) is the primary interface that different parts of
 *	the system use to communicate with one another. This includes the I/O
 *	engines (where PCIe traffic goes), CPU caches and their cores, memory
 *	channels, cross-socket communication, and a whole lot more. The first
 *	part of decoding addresses and figuring out which DRAM channel an
 *	address should be directed to all come from the data fabric.
 *
 *	The data fabric is comprised of instances. So there is one instance for
 *	each group of cores, each memory channel, etc. Each instance has its own
 *	independent set of register information. As the data fabric is a series
 *	of devices exposed over PCI, if you do a normal PCI configuration space
 *	read or write that'll end up broadcasting the I/O. Instead, to access a
 *	particular instance's register information there is an indirect access
 *	mechanism. The primary way that this driver accesses data fabric
 *	registers is via these indirect reads.
 *
 *	There is one instance of the Data Fabric per socket starting with Zen 2.
 *	In Zen 1, there was one instance of the data fabric per CCD -- core
 *	complex die (see cpuid.c's big theory statement for more information).
 *
 * DF INSTANCE ID
 *
 *	A DF instance ID is an identifier for a single entity or component in a
 *	data fabric.  The set of instance IDs is unique only with a single data
 *	fabric. So for example, each memory channel, I/O endpoint (e.g. PCIe
 *	logic), group of cores, has its own instance ID. Anything within the
 *	same data fabric (e.g. the same die) can be reached via its instance ID.
 *	The instance ID is used to indicate which instance to contact when
 *	performing indirect accesses.
 *
 *	Not everything that has an instance ID will be globally routable (e.g.
 *	between multiple sockets). For things that are, such as the memory
 *	channels and coherent core initiators, there is a second ID called a
 *	fabric ID.
 *
 * DF FABRIC ID
 *
 *	A DF fabric ID is an identifier that combines information to indicate
 *	both which instance of the data fabric a component is on and a component
 *	itself. So with this number you can distinguish between a memory channel
 *	on one of two sockets. A Fabric ID is made up of two parts. The upper
 *	part indicates which DF we are talking to and is referred to as a Node
 *	ID. The Node ID is itself broken into two parts: one that identifies a
 *	socket, and one that identifies a die. The lower part of a fabric ID is
 *	called a component ID and indicates which component in a particular data
 *	fabric that we are talking to. While only a subset of the total
 *	components in the data fabric are routable, for everything that is, its
 *	component ID matches its instance ID.
 *
 *	Put differently, the component portion of a fabric ID and a component's
 *	instance ID are always the same for routable entities. For things which
 *	cannot be routed, they only have an instance ID and no fabric ID.
 *	Because this code is always interacting with data fabric components that
 *	are routable, sometimes instance ID and the component ID portion of the
 *	data fabric ID may be used interchangeably.
 *
 *	Finally, it's worth calling out that the number of bits that are used to
 *	indicate the socket, die, and component in a fabric ID changes from
 *	hardware generation to hardware generation.
 *
 *	Inside the code here, the socket and die decomposition information is
 *	always relative to the node ID. AMD phrases the decomposition
 *	information in terms of a series of masks and shifts. This is
 *	information that can be retrieved from the data fabric itself, allowing
 *	us to avoid hardcoding too much information other than which registers
 *	actually have which fields. With both masks and shifts, it's important
 *	to establish which comes first. We follow AMD's convention and always
 *	apply masks before shifts. With that, let's look at an example of a
 *	made up bit set:
 *
 *	Assumptions (to make this example simple):
 *	  o The fabric ID is 16 bits
 *	  o The component ID is 8 bits
 *	  o The node ID is 8 bits
 *	  o The socket and die ID are both 4 bits
 *
 *	Here, let's say that we have the ID 0x2106. This decomposes into a
 *	socket 0x2, die 0x1, and component 0x6. Here is how that works in more
 *	detail:
 *
 *	          0x21      0x06
 *	        |------|  |------|
 *	        Node ID   Component ID
 *	Mask:    0xff00    0x00ff
 *	Shift:   8         0
 *
 *	Next we would decompose the Node ID as:
 *	         0x2        0x1
 *	       |------|  |------|
 *	       Sock ID    Die ID
 *	Mask:   0xf0      0x0f
 *	Shift:  4         0
 *
 *	Composing a fabric ID from its parts would work in a similar way by
 *	applying masks and shifts.
 *
 * NORMAL ADDRESS
 *
 *	A normal address is one of the primary address types that AMD uses in
 *	memory decoding. It takes into account the DRAM hole, interleave
 *	settings, and is basically the address that is dispatched to the broader
 *	data fabric towards a particular DRAM channel.
 *
 *	Often, phrases like 'normalizing the address' or normalization refer to
 *	the process of transforming a system address into the channel address.
 *
 * INTERLEAVING
 *
 *	The idea of interleaving is to take a contiguous range and weave it
 *	between multiple different actual entities. Generally certain bits in
 *	the range are used to select one of several smaller regions. For
 *	example, if you have 8 regions each that are 4 GiB in size, that creates
 *	a single 32 GiB region. You can use three bits in that 32 GiB space to
 *	select one of the 8 regions. For a more visual example, see the
 *	definition of this in uts/intel/io/imc/imc.c.
 *
 * CHANNEL
 *
 *	A channel is used to refer to a single memory channel. This is sometimes
 *	called a DRAM channel as well. A channel operates in a specific mode
 *	based on the JEDEC DRAM standards (e.g. DDR4, LPDDR5, etc.). A
 *	(LP)DDR4/5 channel may support up to two DIMMs inside the channel. The
 *	number of slots is platform dependent and from there the number of DIMMs
 *	installed can vary. Generally speaking, a DRAM channel defines a set
 *	number of signals, most of which go to all DIMMs in the channel, what
 *	varies is which "chip-select" is activated which causes a given DIMM to
 *	pay attention or not.
 *
 * DIMM
 *
 *	A DIMM refers to a physical hardware component that is installed into a
 *	computer to provide access to dynamic memory. Originally this stood for
 *	dual-inline memory module, though the DIMM itself has evolved beyond
 *	that. A DIMM is organized into various pages, which are addressed by
 *	a combination of rows, columns, banks, bank groups, and ranks. How this
 *	fits together changes from generation to generation and is standardized
 *	in something like DDR4, LPDDR4, DDR5, LPDDR5, etc. These standards
 *	define the general individual modules that are assembled into a DIMM.
 *	There are slightly different standards for combined memory modules
 *	(which is what we use the term DIMM for). Examples of those include
 *	things like registered DIMMs (RDIMMs).
 *
 *	A DDR4 DIMM contains a single channel that is 64-bits wide with 8 check
 *	bits. A DDR5 DIMM has a notable change in this scheme from earlier DDR
 *	standards. It breaks a single DDR5 DIMM into two sub-channels. Each
 *	sub-channel is independently addressed and contains 32-bits of data and
 *	8-bits of check data.
 *
 * ROW AND COLUMN
 *
 *	The most basic building block of a DIMM is a die. A DIMM consists of
 *	multiple dies that are organized together (we'll discuss the
 *	organization next). A given die is organized into a series of rows and
 *	columns. First, one selects a row. At which point one is able to select
 *	a specific column. It is more expensive to change rows than columns,
 *	leading a given row to contain approximately 1 KiB of data spread across
 *	its columns. The exact size depends on the device. Each row/column is a
 *	series of capacitors and transistors. The transistor is used to select
 *	data from the capacitor and the capacitor actually contains the logical
 *	0/1 value.
 *
 * BANKS AND BANK GROUPS
 *
 *	An individual DRAM die is organized in something called a bank. A DIMM
 *	has a number of banks that sit in series. These are then grouped into
 *	larger bank groups. Generally speaking, each bank group has the same
 *	number of banks. Let's take a look at an example of a system with 4
 *	bank groups, each with 4 banks.
 *
 *         +-----------------------+           +-----------------------+
 *         | Bank Group 0          |           | Bank Group 1          |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | | Bank 0 | | Bank 1 | |           | | Bank 0 | | Bank 1 | |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | | Bank 2 | | Bank 3 | |           | | Bank 2 | | Bank 3 | |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         +-----------------------+           +-----------------------+
 *
 *         +-----------------------+           +-----------------------+
 *         | Bank Group 2          |           | Bank Group 3          |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | | Bank 0 | | Bank 1 | |           | | Bank 0 | | Bank 1 | |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         | | Bank 2 | | Bank 3 | |           | | Bank 2 | | Bank 3 | |
 *         | +--------+ +--------+ |           | +--------+ +--------+ |
 *         +-----------------------+           +-----------------------+
 *
 *	On a DIMM, only a single bank and bank group can be active at a time for
 *	reading or writing an 8 byte chunk of data. However, these are still
 *	pretty important and useful because of the time involved to switch
 *	between them. It is much cheaper to switch between bank groups than
 *	between banks and that time can be cheaper than activating a new row.
 *	This allows memory controllers to pipeline this substantially.
 *
 * RANK AND CHIP-SELECT
 *
 *	The next level of organization is a rank. A rank is effectively an
 *	independent copy of all the bank and bank groups on a DIMM. That is,
 *	there are additional copies of the DIMM's organization, but not the data
 *	itself. Originally a
 *	single or dual rank DIMM was built such that one copy of everything was
 *	on each physical side of the DIMM. As the number of ranks has increased
 *	this has changed as well. Generally speaking, the contents of the rank
 *	are equivalent. That is, you have the same number of bank groups, banks,
 *	and each bank has the same number of rows and columns.
 *
 *	Ranks are selected by what's called a chip-select, often abbreviated as
 *	CS_L in the various DRAM standards. AMD also often abbreviates this as a
 *	CS (which is not to be confused with the DF class of device called a
 *	CS). These signals are used to select a rank to activate on a DIMM.
 *	There are some number of these for each DIMM which is how the memory
 *	controller chooses which of the DIMMs it's actually going to activate in
 *	the system.
 *
 *	One interesting gotcha here is how AMD organizes things. Each DIMM
 *	logically is broken into two chip-selects in hardware. Between DIMMs
 *	with more than 2 ranks and 3D stacked RDIMMs, there are ways to
 *	potentially activate more bits. Ultimately these are mapped to a series
 *	of rank multiplication logic internally. These ultimately then control
 *	some of these extra pins, though the exact method isn't 100% clear at
 *	this time.
 *
 * -----------------------
 * Rough Hardware Process
 * -----------------------
 *
 * To better understand how everything is implemented and structured, it's worth
 * briefly describing what happens when hardware wants to read a given physical
 * address. This is roughly summarized in the following chart. In the left hand
 * side is the type of address, which is transformed and generally shrinks along
 * the way. Next to it is the actor that is taking action and the type of
 * address that it starts with.
 *
 * +---------+   +------+
 * | Virtual |   | CPU  |
 * | Address |   | Core |
 * +---------+   +------+
 *      |           |          The CPU core receives a memory request and then
 *      |           * . . . .  determines whether this request is DRAM or MMIO
 *      |           |          (memory-mapped I/O) and then sends it to the data
 *      v           v          fabric.
 * +----------+ +--------+
 * | Physical | | Data   |
 * | Address  | | Fabric |
 * +----------+ +--------+
 *      |           |          The data fabric instance in the CCX/D uses the
 *      |           * . . . .  programmed DRAM rules to determine what DRAM
 *      |           |          channel to direct a request to and what the
 *      |           |          channel-relative address is. It then sends the
 *      |           |          request through the fabric. Note, the number of
 *      |           |          DRAM rules varies based on the processor SoC.
 *      |           |          Server parts like Milan have many more rules than
 *      |           |          an APU like Cezanne. The DRAM rules tell us both
 *      v           v          how to find and normalize the physical address.
 * +---------+  +---------+
 * | Channel |  | DRAM    |
 * | Address |  | Channel |
 * +---------+  +---------+
 *      |           |          The UMC (unified memory controller) receives the
 *      |           * . . . .  DRAM request and determines which DIMM to send
 *      |           |          the request to along with the rank, banks, row,
 *      |           |          column, etc. It initiates a DRAM transaction and
 *      |           |          then sends the results back through the data
 *      v           v          fabric to the CPU core.
 * +---------+  +--------+
 * | DIMM    |  | Target |
 * | Address |  | DIMM   |
 * +---------+  +--------+
 *
 * The above is all generally done in hardware. There are multiple steps
 * internal to this that we end up mimicking in software. This includes things
 * like, applying hashing logic, address transformations, and related.
 * Thankfully the hardware is fairly generic and programmed with enough
 * information that we can pull out to figure this out. The rest of this theory
 * statement covers the major parts of this: interleaving, the act of
 * determining which memory channel to actually go to, and normalization, the
 * act of removing some portion of the physical address bits to determine the
 * address relative to a channel.
 *
 * ------------------------
 * Data Fabric Interleaving
 * ------------------------
 *
 * One of the major parts of address decoding is to understand how the
 * interleaving features work in the data fabric. This is used to allow an
 * address range to be spread out between multiple memory channels and then,
 * later on, when normalizing the address. As mentioned above, a system address
 * matches a rule which has information on interleaving. Interleaving comes in
 * many different flavors. It can be used to just switch between channels,
 * sockets, and dies. It can also end up involving some straightforward and some
 * fairly complex hashing operations.
 *
 * Each DRAM rule has instructions on how to perform this interleaving. The way
 * this works is that the rule first says to start at a given address bit,
 * generally ranging from bit 8-12. These influence the granularity of the
 * interleaving going on. From there, the rules determine how many bits to use
 * from the address to determine the die, socket, and channel. In the simplest
 * form, these perform a log2 of the actual number of things you're interleaving
 * across (we'll come back to non-powers of two). So let's work a few common
 * examples:
 *
 *   o 8-channel interleave, 1-die interleave, 2-socket interleave
 *     Start at bit 9
 *
 *	In this case we have 3 bits that determine the channel to use, 0 bits
 *	for the die, 1 bit for the socket. Here we would then use the following
 *	bits to determine what the channel, die, and socket IDs are:
 *
 *	[12]    - Socket ID
 *	[11:9]  - Channel ID
 *
 *	You'll note that there was no die-interleave, which means the die ID is
 *	always zero. This is the general thing you expect to see in Zen 2 and 3
 *	based systems as they only have one die or a Zen 1 APU.
 *
 *   o 2-channel interleave, 4-die interleave, 2-socket interleave
 *     Start at bit 10
 *
 *	In this case we have 1 bit for the channel and socket interleave. We
 *	have 2 bits for the die. This is something you might see on a Zen 1
 *	system. This results in the following bits:
 *
 *      [13]    - Socket ID
 *      [12:11] - Die ID
 *      [10]    - Channel ID
 *
 *
 * COD and NPS HASHING
 *
 * However, this isn't the only primary extraction rule of the above values. The
 * other primary method is using a hash. While the exact hash methods vary
 * between Zen 2/3 and Zen 4 based systems, they follow a general scheme. In the
 * system there are three interleaving configurations that are either global or
 * enabled on a per-rule basis. These indicate whether one should perform the
 * XOR computation using addresses at:
 *
 *   o 64 KiB (starting at bit 16)
 *   o 2 MiB (starting at bit 21)
 *   o 1 GiB (starting at bit 30)
 *
 * In this world, you take the starting address bit defined by the rule and XOR
 * it with each enabled interleave address. If you have more than one bit to
 * select (e.g. because you are hashing across more than 2 channels), then you
 * continue taking subsequent bits from each enabled region. So the second bit
 * would use 17, 21, and 31 if all three ranges were enabled while the third bit
 * would use 18, 22, and 32. While these are straightforward, there is a catch.
 *
 * While the DRAM rule contains what the starting address bit, you don't
 * actually use subsequent bits in the same way. Instead subsequent bits are
 * deterministic and use bits 12 and 13 from the address.  This is not the same
 * consecutive thing that one might expect. Let's look at a Rome/Milan based
 * example:
 *
 *   o 8-channel "COD" hashing, starting at address 9. All three ranges enabled.
 *     1-die and 1-socket interleaving.
 *
 *      In this model we are using 3 bits for the channel, 0 bits for the socket
 *      and die.
 *
 *	Channel ID[0] = addr[9]  ^ addr[16] ^ addr[21] ^ addr[30]
 *	Channel ID[1] = addr[12] ^ addr[17] ^ addr[22] ^ addr[31]
 *	Channel ID[2] = addr[13] ^ addr[18] ^ addr[23] ^ addr[32]
 *
 *	So through this scheme we'd have a socket/die of 0, and then the channel
 *	ID is computed based on that. The number of bits that we use here
 *	depends on how many channels the hash is going across.
 *
 * The Genoa and related variants, termed "NPS", has a few wrinkles. First,
 * rather than 3 bits being used for the channel, up to 4 bits are. Second,
 * while the Rome/Milan "COD" hash above does not support socket or die
 * interleaving, the "NPS" hash actually supports socket interleaving. However,
 * unlike the straightforward non-hashing scheme, the first bit is used to
 * determine the socket when enabled as opposed to the last one. In addition, if
 * we're not performing socket interleaving, then we end up throwing address bit
 * 14 into the mix here. Let's look at examples:
 *
 *   o 4-channel "NPS" hashing, starting at address 8. All three ranges enabled.
 *     1-die and 1-socket interleaving.
 *
 *      In this model we are using 2 bits for the channel, 0 bits for the socket
 *      and die. Because socket interleaving is not being used, bit 14 ends up
 *      being added into the first bit of the channel selection. Presumably this
 *      is to improve the address distribution in some form.
 *
 *      Channel ID[0] = addr[8] ^ addr[16] ^ addr[21] ^ addr[30] ^ addr[14]
 *      Channel ID[1] = addr[12] ^ addr[17] ^ addr[22] ^ addr[31]
 *
 *   o 8-channel "NPS" hashing, starting at address 9. All three ranges enabled.
 *     1-die and 2-socket interleaving.
 *
 *      In this model we are using 3 bits for the channel and 1 for the socket.
 *      The die is always set to 0. Unlike the above, address bit 14 is not used
 *      because it ends up being required for the 4th address bit.
 *
 *	Socket ID[0]  = addr[9]  ^ addr[16] ^ addr[21] ^ addr[30]
 *	Channel ID[0] = addr[12] ^ addr[17] ^ addr[22] ^ addr[31]
 *	Channel ID[1] = addr[13] ^ addr[18] ^ addr[23] ^ addr[32]
 *	Channel ID[2] = addr[14] ^ addr[19] ^ addr[24] ^ addr[33]
 *
 *
 * ZEN 3 6-CHANNEL
 *
 * These were the simple cases. Things get more complex when we move to
 * non-power of 2 based hashes between channels. There are two different sets of
 * these schemes. The first of these is 6-channel hashing that was added in Zen
 * 3. The second of these is a more complex and general form that was added in
 * Zen 4. Let's start with the Zen 3 case. The Zen 3 6-channel hash requires
 * starting at address bits 11 or 12 and varies its logic somewhat from there.
 * In the 6-channel world, the socket and die interleaving must be disabled.
 * Let's walk through an example:
 *
 *   o 6-channel Zen 3, starting at address 11. 2M and 1G range enabled.
 *     1-die and 1-socket interleaving.
 *
 *      Regardless of the starting address, we will always use three bits to
 *      determine a channel address. However, it's worth calling out that the
 *      64K range is not considered for this at all. Another oddity is that when
 *      calculating the hash bits the order of the extracted 2M and 1G addresses
 *      are different.
 *
 *	This flow starts by calculating the three hash bits. This is defined
 *	below. In the following, all bits marked with an '@' are ones that will
 *	change when starting at address bit 12. In those cases the value will
 *	increase by 1. Here's how we calculate the hash bits:
 *
 *      hash[0] = addr[11@] ^ addr[14@] ^ addr[23] ^ addr[32]
 *      hash[1] = addr[12@] ^ addr[21] ^ addr[30]
 *      hash[2] = addr[13@] ^ addr[22] ^ addr[31]
 *
 *      With this calculated, we always assign the first bit of the channel
 *      based on the hash. The other bits are more complicated as we have to
 *      deal with that gnarly power of two problem. We determine whether or not
 *      to use the hash bits directly in the channel based on their value. If
 *      they are not equal to 3, then we use it, otherwise if they are, then we
 *      need to go back to the physical address and we take its modulus.
 *      Basically:
 *
 *      Channel Id[0] = hash[0]
 *      if (hash[2:1] == 3)
 *		Channel ID[2:1] = (addr >> [11@+3]) % 3
 *      else
 *		Channel ID[2:1] = hash[2:1]
 *
 *
 * ZEN 4 NON-POWER OF 2
 *
 * I hope you like modulus calculations, because things get even more complex
 * here now in Zen 4 which has many more modulus variations. These function in a
 * similar way to the older 6-channel hash in Milan. They require one to start
 * at address bit 8, they require that there is no die interleaving, and they
 * support socket interleaving. The different channel arrangements end up in one
 * of two sets of modulus values: a mod % 3 and a mod % 5 based on the number
 * of channels used. Unlike the Milan form, all three address ranges (64 KiB, 2
 * MiB, 1 GiB) are allowed to be used.
 *
 *   o 6-channel Zen 4, starting at address 8. 64K, 2M, and 1G range enabled.
 *     1-die and 2-socket interleaving.
 *
 *      We start by calculating the following set of hash bits regardless of
 *      the number of channels that exist. The set of hash bits that is actually
 *      used in various computations ends up varying based upon the number of
 *      channels used. In 3-5 configs, only hash[0] is used. 6-10, both hash[0]
 *      and hash[2] (yes, not hash[1]). The 12 channel config uses all three.
 *
 *      hash[0] = addr[8]  ^ addr[16] ^ addr[21] ^ addr[30] ^ addr[14]
 *      hash[1] = addr[12] ^ addr[17] ^ addr[22] ^ addr[31]
 *      hash[2] = addr[13] ^ addr[18] ^ addr[23] ^ addr[32]
 *
 *      Unlike other schemes where bits directly map here, they instead are used
 *      to seed the overall value. Depending on whether hash[0] is a 0 or 1, the
 *      system goes through two different calculations entirely. Though all of
 *      them end up involving the remainder of the system address going through
 *      the modulus. In the following, a '3@' indicates the modulus value would
 *      be swapped to 5 in a different scenario.
 *
 *      Channel ID = addr[63:14] % 3@
 *      if (hash[0] == 1)
 *		Channel ID = (Channel ID + 1) % 3@
 *
 *      Once this base has for the channel ID has been calculated, additional
 *      portions are added in. As this is the 6-channel form, we say:
 *
 *      Channel ID = Channel ID + (hash[2] * 3@)
 *
 *      Finally the socket is deterministic and always comes from hash[0].
 *      Basically:
 *
 *      Socket ID = hash[0]
 *
 *   o 12-channel Zen 4, starting at address 8. 64K, 2M, and 1G range enabled.
 *     1-die and 1-socket interleaving.
 *
 *       This is a variant of the above. The hash is calculated the same way.
 *       The base Channel ID is the same and if socket interleaving were enabled
 *       it would also be hash[0]. What instead differs is how we use hash[1]
 *       and hash[2]. The following logic is used instead of the final
 *       calculation above.
 *
 *       Channel ID = Channel ID + (hash[2:1] * 3@)
 *
 *
 * POST BIT EXTRACTION
 *
 * Now, all of this was done to concoct up a series of indexes used. However,
 * you'll note that a given DRAM rule actually already has a fabric target. So
 * what do we do here? We add them together.
 *
 * The data fabric has registers that describe which bits in a fabric ID
 * correspond to a socket, die, and channel. Taking the channel, die, and socket
 * IDs above, one can construct a fabric ID. From there, we add the two data
 * fabric IDs together and can then get to the fabric ID of the actual logical
 * target. This is why all of the socket and die interleaving examples with no
 * interleaving are OK to result in a zero. The idea here is that the base
 * fabric ID in the DRAM rule will take care of indicating those other things as
 * required.
 *
 * You'll note the use of the term "logical target" up above. That's because
 * some platforms have the ability to remap logical targets to physical targets
 * (identified by the use of the ZEN_UMC_FAM_F_TARG_REMAP flag in the family
 * data). The way that remapping works changes based on the hardware generation.
 * This was first added in Milan (Zen 3) CPUs. In that model, you would use the
 * socket and component information from the target ID to identify which
 * remapping rules to use. On Genoa (Zen 4) CPUs, you would instead use
 * information in the rule itself to determine which of the remap rule sets to
 * use and then uses the component ID to select which rewrite rule to use.
 *
 * Finally, there's one small wrinkle with this whole scheme that we haven't
 * discussed: what actually is the address that we plug into this calculation.
 * While you might think it actually is just the system address itself, that
 * isn't actually always the case. Sometimes rather than using the address
 * itself, it gets normalized based on the DRAM rule, which involves subtracting
 * out the base address and potentially subtracting out the size of the DRAM
 * hole (if the address is above the hole and hoisting is active for that
 * range). When this is performed appears to tie to the DF generation. After Zen
 * 3, it is always the default (e.g. Zen 4 and things from DF gen 3.5). At and
 * before Zen 3, it only occurs if we are doing a non-power of 2 based hashing.
 *
 * --------------------------------------------
 * Data Fabric Interleave Address Normalization
 * --------------------------------------------
 *
 * While you may have thought that we were actually done with the normalization
 * fun in the last section, there's still a bit more here that we need to
 * consider. In particular, there's a secondary transformation beyond
 * interleaving that occurs as part of constructing the channel normalized
 * address. Effectively, we need to account for all the bits that were used in
 * the interleaving and generally speaking remove them from our normalized
 * address.
 *
 * While this may sound weird on paper, the way to think about it is that
 * interleaving at some granularity means that each device is grabbing the same
 * set of addresses, the interleave just is used to direct it to its own
 * location. When working with a channel normalized address, we're effectively
 * creating a new region of addresses that have meaning within the DIMMs
 * themselves. The channel doesn't care about what got it there, mainly just
 * what it is now. So with that in mind, we need to discuss how we remove all
 * the interleaving information in our different modes.
 *
 * Just to make sure it's clear, we are _removing_ all bits that were used for
 * interleaving. This causes all bits above the removed ones to be shifted
 * right.
 *
 * First, we have the case of standard power of 2 interleaving that applies to
 * the 1, 2, 4, 8, 16, and 32 channel configurations. Here, we need to account
 * for the total number of bits that are used for the channel, die, and socket
 * interleaving and we simply remove all those bits starting from the starting
 * address.
 *
 *   o 8-channel interleave, 1-die interleave, 2-socket interleave
 *     Start at bit 9
 *
 *     If we look at this example, we are using 3 bits for the channel, 1 for
 *     the socket, for a total of 4 bits. Because this is starting at bit 9,
 *     this means that interleaving covers the bit range [12:9]. In this case
 *     our new address would be (orig[63:13] >> 4) | orig[8:0].
 *
 *
 * COD and NPS HASHING
 *
 * That was the simple case, next we have the COD/NPS hashing case that we need
 * to consider. If we look at these, the way that they work is that they split
 * which bits they use for determining the channel address and then hash others
 * in. Here, we need to extract the starting address bit, then continue at bit
 * 12 based on the number of bits in use and whether or not socket interleaving
 * is at play for the NPS variant. Let's look at an example here:
 *
 *   o 8-channel "COD" hashing, starting at address 9. All three ranges enabled.
 *     1-die and 1-socket interleaving.
 *
 *     Here we have three total bits being used. Because we start at bit 9, this
 *     means we need to drop bits [13:12], [9]. So our new address would be:
 *
 *     orig[63:14] >> 3 | orig[11:10] >> 1 | orig[8:0]
 *     |                  |                  +-> stays the same
 *     |                  +-> relocated to bit 9 -- shifted by 1 because we
 *     |                      removed bit 9.
 *     +--> Relocated to bit 11 -- shifted by 3 because we removed bits, 9, 12,
 *          and 13.
 *
 *   o 8-channel "NPS" hashing, starting at address 8. All three ranges enabled.
 *     1-die and 2-socket interleaving.
 *
 *     Here we need to remove bits [14:12], [8]. We're removing an extra bit
 *     because we have 2-socket interleaving. This results in a new address of:
 *
 *     orig[63:15] >> 4 | orig[11:9] >> 1 | orig[7:0]
 *     |                  |                 +-> stays the same
 *     |                  +-> relocated to bit 8 -- shifted by 1 because we
 *     |                      removed bit 8.
 *     +--> Relocated to bit 11 -- shifted by 4 because we removed bits, 8, 12,
 *          13, and 14.
 *
 *
 * ZEN 3 6-CHANNEL
 *
 * Now, to the real fun stuff, our non-powers of two. First, let's start with
 * our friend, the Zen 3 6-channel hash. So, the first thing that we need to do
 * here is start by recomputing our hash again based on the current normalized
 * address. Regardless of the hash value, this first removes all three bits from
 * the starting address, so that's removing either [14:12] or [13:11].
 *
 * The rest of the normalization process here is quite complex and somewhat mind
 * bending. Let's start working through an example here and build this up.
 * First, let's assume that each channel has a single 16 GiB RDIMM. This would
 * mean that the channel itself has 96 GiB RDIMM. However, by removing 3 bits
 * worth, that technically corresponds to an 8-channel configuration that
 * normally suggest a 128 GiB configuration. The processor requires us to record
 * this fact in the DF::Np2ChannelConfig register. The value that it wants us a
 * bit weird. We believe it's calculated by the following:
 *
 *   1. Round the channel size up to the next power of 2.
 *   2. Divide this total size by 64 KiB.
 *   3. Determine the log base 2 that satisfies this value.
 *
 * In our particular example above. We have a 96 GiB channel, so for (1) we end
 * up with 128 GiB (2^37). We now divide that by 64 KiB (2^16), so this becomes
 * 2^(37 - 16) or 2^21. Because we want the log base 2 of 2^21 from (2), this
 * simply becomes 21. The DF::Np2ChannelConfig has two members, a 'space 0' and
 * 'space 1'. Near as we can tell, in this mode only 'space 0' is used.
 *
 * Before we get into the actual normalization scheme, we have to ask ourselves
 * how do we actually interleave data 6 ways. The scheme here is involved.
 * First, it's important to remember like with other normalization schemes, we
 * do adjust for the address for the base address in the DRAM rule and then also
 * take into account the DRAM hole if present.
 *
 * If we delete 3 bits, let's take a sample address and see where it would end
 * up in the above scheme. We're going to take our 3 address bits and say that
 * they start at bit 12, so this means that the bits removed are [14:12]. So the
 * following are the 8 addresses that we have here and where they end up
 * starting with 1ff:
 *
 *   o 0x01ff  -> 0x1ff, Channel 0 (hash 0b000)
 *   o 0x11ff  -> 0x1ff, Channel 1 (hash 0b001)
 *   o 0x21ff  -> 0x1ff, Channel 2 (hash 0b010)
 *   o 0x31ff  -> 0x1ff, Channel 3 (hash 0b011)
 *   o 0x41ff  -> 0x1ff, Channel 4 (hash 0b100)
 *   o 0x51ff  -> 0x1ff, Channel 5 (hash 0b101)
 *   o 0x61ff  -> 0x3000001ff, Channel 0 (hash 0b110)
 *   o 0x71ff  -> 0x3000001ff, Channel 1 (hash 0b111)
 *
 * Yes, we did just jump to near the top of what is a 16 GiB DIMM's range for
 * those last two. The way we determine when to do this jump is based on our
 * hash. Effectively we ask what is hash[2:1]. If it is 0b11, then we need to
 * do something different and enter this special case, basically jumping to the
 * top of the range. If we think about a 6-channel configuration for a moment,
 * the thing that doesn't exist are the traditional 8-channel hash DIMMs 0b110
 * and 0b111.
 *
 * If you go back to the interleave this kind of meshes, that tried to handle
 * the case of the hash being 0, 1, and 2, normally, and then did special things
 * with the case of the hash being in this upper quadrant. The hash then
 * determined where it went by shifting over the upper address and doing a mod
 * 3 and using that to determine the upper two bits. With that weird address at
 * the top of the range, let's go through and see what else actually goes to
 * those weird addresses:
 *
 *   o 0x08000061ff -> 0x3000001ff, Channel 2 (hash 0b110)
 *   o 0x08000071ff -> 0x3000001ff, Channel 3 (hash 0b111)
 *   o 0x10000061ff -> 0x3000001ff, Channel 4 (hash 0b110)
 *   o 0x10000071ff -> 0x3000001ff, Channel 5 (hash 0b111)
 *
 * Based on the above you can see that we've split the 16 GiB DIMM into a 12 GiB
 * region (e.g. [ 0x0, 0x300000000 ), and a 4 GiB region [ 0x300000000,
 * 0x400000000 ). What seems to happen is that the CPU algorithmically is going
 * to put things in this upper range. To perform that action it goes back to the
 * register information that we stored in DF::Np2ChannelConfig. The way this
 * seems to be thought of is it wants to set the upper two bits of a 64 KiB
 * chunk (e.g. bits [15:14]) to 0b11 and then shift that over based on the DIMM
 * size.
 *
 * Our 16 GiB DIMM has 34 bits, so effectively we want to set bits [33:32] in
 * this case. The channel is 37 bits wide, which the CPU again knows as 2^21 *
 * 2^16. So it constructs the 64 KiB value of [15:14] = 0b11 and fills the rest
 * with zeros. It then multiplies it by 2^(21 - 3), or 2^18. The - 3 comes from
 * the fact that we removed 3 address bits. This when added to the above gets
 * us bits [33,32] = 0b11.
 *
 * While this appears to be the logic, I don't have a proof that this scheme
 * actually evenly covers the entire range, but a few examples appear to work
 * out.
 *
 * With this, the standard example flow that we give, results in something like:
 *
 *   o 6-channel Zen 3, starting at address 11. 2M and 1G range enabled. Here,
 *     we assume that the value of the NP2 space0 is 21 bits. This example
 *     assumes we have 96 GiB total memory, which means rounding up to 128 GiB.
 *
 *     Step 1 here is to adjust our address to remove the three bits indicated.
 *     So we simply always set our new address to:
 *
 *     orig[63:14] >> 3 | orig[10:0]
 *     |                  +-> stays the same
 *     +--> Relocated to bit 11 because a 6-channel config always uses 3 bits to
 *          perform interleaving.
 *
 *     At this step, one would need to consult the hash of the normalized
 *     address before removing bits (but after adjusting for the base / DRAM
 *     hole). If hash[2:1] == 3, then we would say that the address is actually:
 *
 *     0b11 << 32 | orig[63:14] >> 3 | orig[10:0]
 *
 *
 * ZEN 4 NON-POWER OF 2
 *
 * Next, we have the DFv4 versions of the 3, 5, 6, 10, and 12 channel hashing.
 * An important part of this is whether or not there is any socket hashing going
 * on. Recall there, that if socket hashing was going on, then it is part of the
 * interleave logic; however, if it is not, then its hash actually becomes
 * part of the normalized address, but not in the same spot!
 *
 * In this mode, we always remove the bits that are actually used by the hash.
 * Recall that some modes use hash[0], others hash[0] and hash[2], and then only
 * the 12-channel config uses hash[2:0]. This means we need to be careful in how
 * we actually remove address bits. All other bits in this lower range we end up
 * keeping and using. The top bits, e.g. addr[63:14] are kept and divided by the
 * actual channel-modulus. If we're not performing socket interleaving and
 * therefore need to keep the value of hash[0], then it is appended as the least
 * significant bit of that calculation.
 *
 * Let's look at an example of this to try to make sense of it all.
 *
 *   o 6-channel Zen 4, starting at address 8. 64K, 2M, and 1G range enabled.
 *     1-die and 2-socket interleaving.
 *
 *     Here we'd start by calculating hash[2:0] as described in the earlier
 *     interleaving situation. Because we're using a socket interleave, we will
 *     not opt to include hash[0] in the higher-level address calculation.
 *     Because this is a 6-channel calculation, our modulus is 3. Here, we will
 *     strip out bits 8 and 13 (recall in the interleaving 6-channel example we
 *     ignored hash[1], thus no bit 12 here). Our new address will be:
 *
 *     (orig[63:14] / 3) >> 2 | orig[12:9] >> 1 | orig[7:0]
 *      |                       |                 +-> stays the same
 *      |                       +-> relocated to bit 8 -- shifted by 1 because
 *      |                           we removed bit 8.
 *      +--> Relocated to bit 12 -- shifted by 2 because we removed bits 8 and
 *           13.
 *
 *   o 12-channel Zen 4, starting at address 8. 64K, 2M, and 1G range enabled.
 *     1-die and 1-socket interleaving.
 *
 *     This is a slightly different case from the above in two ways. First, we
 *     will end up removing bits 8, 12, and 13, but then we'll also reuse
 *     hash[0]. Our new address will be:
 *
 *     ((orig[63:14] / 3) << 1 | hash[0]) >> 3 | orig[11:9] >> 1 | orig[7:0]
 *      |                                   |                      +-> stays the
 *      |                                   |                          same
 *      |                                   +-> relocated to bit 8 -- shifted by
 *      |                                       1 because we removed bit 8.
 *      +--> Relocated to bit 11 -- shifted by 3 because we removed bits 8, 12,
 *           and 13.
 *
 * That's most of the normalization process for the time being. We will have to
 * revisit this when we have to transform a normal address into a system address
 * and undo all this.
 *
 * -------------------------------------
 * Selecting a DIMM and UMC Organization
 * -------------------------------------
 *
 * One of the more nuanced things in decoding and encoding is the question of
 * where do we send a channel normalized address. That is, now that we've gotten
 * to a given channel, we need to transform the address into something
 * meaningful for a DIMM, and select a DIMM as well. The UMC SMN space contains
 * a number of Base Address and Mask registers which they describe as activating
 * a chip-select. A given UMC has up to four primary chip-selects (we'll come
 * back to DDR5 sub-channels later). The first two always go to the first DIMM
 * in the channel and the latter two always go to the second DIMM in the
 * channel. Put another way, you can always determine which DIMM you are
 * referring to by taking the chip-select and shifting it by 1.
 *
 * The UMC Channel registers are organized a bit differently in different
 * hardware generations. In a DDR5 based UMC, almost all of our settings are on
 * a per-chip-select basis while as in a DDR4 based system only the bases and
 * masks are. While gathering data we normalize this such that each logical
 * chip-select (umc_cs_t) that we have in the system has the same data so that
 * way DDR4 and DDR5 based systems are the same to the decoding logic. There is
 * also channel-wide data such as hash configurations and related.
 *
 * Each channel has a set of base and mask registers (and secondary ones as
 * well). To determine if we activate a given one, we first check if the
 * enabled bit is set. The enabled bit is set on a per-base basis, so both the
 * primary and secondary registers have separate enables. As there are four of
 * each base, mask, secondary base, and secondary mask, we say that if a
 * normalized address matches either a given indexes primary or secondary index,
 * then it activates that given UMC index. The basic formula for an enabled
 * selection is:
 *
 *	NormAddr & ~Mask[i] == Base[i] & ~Mask[i]
 *
 * Once this is selected, this index in the UMC is what it always used to derive
 * the rest of the information that is specific to a given chip-select or DIMM.
 * An important thing to remember is that from this point onwards, while there
 * is a bunch of hashing and interleaving logic it doesn't change which UMC
 * channel we read the data from. Though the particular DIMM, rank, and address
 * we access will change as we go through hashing and interleaving.
 *
 * ------------------------
 * Row and Column Selection
 * ------------------------
 *
 * The number of bits that are used for the row and column address of a DIMM
 * varies based on the type of module itself. These depend on the density of a
 * DIMM module, e.g. how large an individual DRAM block is, a value such as 16
 * Gbit, and the number of these wide it is, which is generally phrased as X4,
 * X8, and X16. The memory controller encodes the number of bits (derived from
 * the DIMM's SPD data) and then determines which bits are used for addresses.
 *
 * Based on this information we can initially construct a row and a column
 * address by leveraging the information about the number of bits and then
 * extracting the correct bits out of the normalized channel address.
 *
 * If you've made it this far, you know nothing is quite this simple, despite it
 * seeming so. Importantly, not all DIMMs actually have storage that is a power
 * of 2. As such, there's another bit that we have to consult to transform the
 * actual value that we have for a row, remarkably the column somehow has no
 * transformations applied to it.
 *
 * The hardware gives us information on inverting the two 'most significant
 * bits' of the row address which we store in 'ucs_inv_msbs'. First, we have the
 * question of what are our most significant bits here. This is basically
 * determined by the number of low and high row bits. In this case higher
 * actually is what we want. Note, the high row bits only exist in DDR4. Next,
 * we need to know whether we used the primary or secondary base/mask pair for
 * this as there is a primary and secondary inversion bits. The higher bit of
 * the inversion register (e.g ucs_inv_msbs[1]) corresponds to the highest row
 * bit. A zero in the bit position indicates that we should not perform an
 * inversion where as a one says that we should invert this.
 *
 * To actually make this happen we can take advantage of the fact that the
 * meaning of a 0/1 above means that this can be implemented with a binary
 * exclusive-OR (XOR). Logically speaking if we have a don't invert setting
 * present, a 0, then x ^ 0 is always x. However, if we have a 1 present, then
 * we know that (for a single bit) x ^ 1 = ~x. We take advantage of this fact in
 * the row logic.
 *
 * ---------------------
 * Banks and Bank Groups
 * ---------------------
 *
 * While addressing within a given module is done by the use of a row and column
 * address, to increase storage density a module generally has a number of
 * banks, which may be organized into one or more bank groups. While a given
 * DDR4/5 access happens in some prefetched chunk of say 64 bytes (what do you
 * know, that's a cacheline), that all occurs within a single bank. The addition
 * of bank groups makes it easier to access data in parallel -- it is often
 * faster to read from another bank group than to read another region inside a
 * bank group.
 *
 * Based on the DIMMs internal configuration, there will be a specified number
 * of bits used for the overall bank address (including bank group bits)
 * followed by a number of bits actually used for bank groups. There are
 * separately an array of bits used to concoct the actual address. It appears,
 * mostly through experimental evidence, that the bank group bits occur first
 * and then are followed by the bank selection itself.  This makes some sense if
 * you assume that switching bank groups is faster than switching banks.
 *
 * So if we see the UMC noting 4 bank bits and 2 bank groups bits, that means
 * that the umc_cs_t's ucs_bank_bits[1:0] correspond to bank_group[1:0] and
 * ucs_bank_bits[3:2] correspond to bank_address[1:0]. However, if there were no
 * bank bits indicated, then all of the address bits would correspond to the
 * bank address.
 *
 * Now, this would all be straightforward if not for hashing, our favorite.
 * There are five bank hashing registers per channel (UMC_BANK_HASH_DDR4,
 * UMC_BANK_HASH_DDR5), one that corresponds to the five possible bank bits. To
 * do this we need to use the calculated row and column that we previously
 * determined. This calculation happens in a few steps:
 *
 *   1) First check if the enable bit is set in the rule. If not, just use the
 *      normal bank address bit and we're done.
 *   2) Take a bitwise-AND of the calculated row and hash register's row value.
 *      Next do the same thing for the column.
 *   3) For each bit in the row, progressively XOR it, e.g. row[0] ^ row[1] ^
 *      row[2] ^ ... to calculate a net bit value for the row. This then
 *      repeats itself for the column. What basically has happened is that we're
 *      using the hash register to select which bits to impact our decision.
 *      Think of this as a traditional bitwise functional reduce.
 *   4) XOR the combined rank bit with the column bit and the actual bank
 *      address bit from the normalized address. So if this were bank bit 0,
 *      which indicated we should use bit 15 for bank[0], then we would
 *      ultimately say our new bit is norm_addr[15] ^ row_xor ^ col_xor
 *
 * An important caveat is that we would only consult all this if we actually
 * were told that the bank bit was being used. For example if we had 3 bank
 * bits, then we'd only check the first 3 hash registers. The latter two would
 * be ignored.
 *
 * Once this process is done, then we can go back and split the activated bank
 * into the actual bank used and the bank group used based on the first bits
 * going to the bank group.
 *
 * ---------------
 * DDR5 Sub-channel
 * ---------------
 *
 * As described in the definitions section, DDR5 has the notion of a
 * sub-channel. Here, a single bit is used to determine which of the
 * sub-channels to actually operate and utilize. Importantly the same
 * chip-select seems to apply to both halves of a given sub-channel.
 *
 * There is also a hash that is used here. The hash here utilizes the calculated
 * bank, column, and row and follows the same pattern used in the bank
 * calculation where we do a bunch of running exclusive-ORs and then do that
 * with the original value we found to get the new value. Because there's only
 * one bit for the sub-channel, we only have a single hash to consider.
 *
 * -------------------------------------------
 * Ranks, Chip-Select, and Rank Multiplication
 * -------------------------------------------
 *
 * The notion of ranks and the chip-select are interwoven. From a strict DDR4
 * RDIMM perspective, there are two lines that are dedicated for chip-selects
 * and then another two that are shared with three 'chip-id' bits that are used
 * in 3DS RDIMMs. In all cases the controller starts with two logical chip
 * selects and then uses something called rank multiplication to figure out how
 * to multiplex that and map to the broader set of things. Basically, in
 * reality, DDR4 RDIMMs allow for 4 bits to determine a rank and then 3DS RDIMMs
 * use 2 bits for a rank and 3 bits to select a stacked chip. In DDR5 this is
 * different and you just have 2 bits for a rank.
 *
 * It's not entirely clear from what we know from AMD, but it seems that we use
 * the RM bits as a way to basically go beyond the basic 2 bits of chip-select
 * which is determined based on which channel we logically activate. Initially
 * we treat this as two distinct things, here as that's what we get from the
 * hardware. There are two hashes here a chip-select and rank-multiplication
 * hash. Unlike the others, which rely on the bank, row, and column addresses,
 * this hash relies on the normalized address. So we calculate that mask and do
 * our same xor dance.
 *
 * There is one hash for each rank multiplication bit and chip-select bit. The
 * number of rank multiplication bits is given to us. The number of chip-select
 * bits is fixed, it's simply two because there are four base/mask registers and
 * logical chip-selects in a given UMC channel. The chip-select on some DDR5
 * platforms has a secondary exclusive-OR hash that can be applied. As this only
 * exists in some families, for any where it does exist, we seed it to be zero
 * so that it becomes a no-op.
 *
 * -----------
 * Future Work
 * -----------
 *
 * As the road goes ever on and on, down from the door where it began, there are
 * still some stops on the journey for this driver. In particular, here are the
 * major open areas that could be implemented to extend what this can do:
 *
 *   o The ability to transform a normalized channel address back to a system
 *     address. This is required for MCA/MCA-X error handling as those generally
 *     work in terms of channel addresses.
 *   o Integrating with the MCA/MCA-X error handling paths so that way we can
 *     take correct action in the face of ECC errors and allowing recovery from
 *     uncorrectable errors.
 *   o Providing memory controller information to FMA so that way it can opt to
 *     do predictive failure or give us more information about what is fault
 *     with ECC errors.
 *   o Figuring out if we will get MCEs for privilged address decoding and if so
 *     mapping those back to system addresses and related.
 *   o 3DS RDIMMs likely will need a little bit of work to ensure we're handling
 *     the resulting combination of the RM bits and CS and reporting it
 *     intelligently.
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
#include <sys/x86_archext.h>
#include <sys/sysmacros.h>
#include <sys/mc.h>

#include <zen_umc.h>
#include <sys/amdzen/df.h>
#include <sys/amdzen/umc.h>

static zen_umc_t *zen_umc;

/*
 * Per-CPU family information that describes the set of capabilities that they
 * implement. When adding support for new CPU generations, you must go through
 * what documentation you have and validate these. The best bet is to find a
 * similar processor and see what has changed. Unfortunately, there really isn't
 * a substitute for just basically checking every register. The family name
 * comes from the amdzen_c_family(). One additional note for new CPUs, if our
 * parent amdzen nexus driver does not attach (because the DF has changed PCI
 * IDs or more), then just adding something here will not be sufficient to make
 * it work.
 */
static const zen_umc_fam_data_t zen_umc_fam_data[] = {
	{
		.zufd_family = X86_PF_AMD_NAPLES,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_HYGON_DHYANA,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_DALI,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4_APU,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_ROME,
		.zufd_flags = ZEN_UMC_FAM_F_NP2 | ZEN_UMC_FAM_F_NORM_HASH |
		    ZEN_UMC_FAM_F_UMC_HASH,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_RENOIR,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4_APU,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_PC |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_MATISSE,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH | ZEN_UMC_FAM_F_UMC_HASH,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_VAN_GOGH,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_HYBRID_LPDDR5,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_MENDOCINO,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_HYBRID_LPDDR5,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_MILAN,
		.zufd_flags = ZEN_UMC_FAM_F_TARG_REMAP | ZEN_UMC_FAM_F_NP2 |
		    ZEN_UMC_FAM_F_NORM_HASH | ZEN_UMC_FAM_F_UMC_HASH,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_GENOA,
		.zufd_flags = ZEN_UMC_FAM_F_TARG_REMAP |
		    ZEN_UMC_FAM_F_UMC_HASH | ZEN_UMC_FAM_F_UMC_EADDR |
		    ZEN_UMC_FAM_F_CS_XOR,
		.zufd_dram_nrules = 20,
		.zufd_cs_nrules = 4,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR5,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_PC | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_VERMEER,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH | ZEN_UMC_FAM_F_UMC_HASH,
		.zufd_dram_nrules = 16,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_CS,
	}, {
		.zufd_family = X86_PF_AMD_REMBRANDT,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR5_APU,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_CEZANNE,
		.zufd_flags = ZEN_UMC_FAM_F_NORM_HASH,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR4_APU,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_PC |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_RAPHAEL,
		.zufd_flags = ZEN_UMC_FAM_F_TARG_REMAP | ZEN_UMC_FAM_F_CS_XOR,
		.zufd_dram_nrules = 2,
		.zufd_cs_nrules = 2,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR5,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_PC |
		    UMC_CHAN_HASH_F_CS
	}, {
		.zufd_family = X86_PF_AMD_BERGAMO,
		.zufd_flags = ZEN_UMC_FAM_F_TARG_REMAP |
		    ZEN_UMC_FAM_F_UMC_HASH | ZEN_UMC_FAM_F_UMC_EADDR |
		    ZEN_UMC_FAM_F_CS_XOR,
		.zufd_dram_nrules = 20,
		.zufd_cs_nrules = 4,
		.zufd_umc_style = ZEN_UMC_UMC_S_DDR5,
		.zufd_chan_hash = UMC_CHAN_HASH_F_BANK | UMC_CHAN_HASH_F_RM |
		    UMC_CHAN_HASH_F_PC | UMC_CHAN_HASH_F_CS
	}
};

/*
 * We use this for the DDR4 and Hybrid DDR4 + LPDDR5 tables to map between the
 * specific enumerated speeds which are encoded values and the corresponding
 * memory clock and speed. For all DDR4 and LPDDR5 items we assume a a 1:2 ratio
 * between them. This is not used for the pure DDR5 / LPDDR5 entries because of
 * how the register just encodes the raw value in MHz.
 */
typedef struct zen_umc_freq_map {
	uint32_t zufm_reg;
	uint32_t zufm_mhz;
	uint32_t zufm_mts2;
	uint32_t zufm_mts4;
} zen_umc_freq_map_t;

static const zen_umc_freq_map_t zen_umc_ddr4_map[] = {
	{ UMC_DRAMCFG_DDR4_MEMCLK_667, 667, 1333, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_800, 800, 1600, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_933, 933, 1866, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_1067, 1067, 2133, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_1200, 1200, 2400, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_1333, 1333, 2666, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_1467, 1467, 2933, 0 },
	{ UMC_DRAMCFG_DDR4_MEMCLK_1600, 1600, 3200, 0 }
};

static const zen_umc_freq_map_t zen_umc_lpddr5_map[] = {
	{ UMC_DRAMCFG_HYB_MEMCLK_333, 333, 667, 1333 },
	{ UMC_DRAMCFG_HYB_MEMCLK_400, 400, 800, 1600 },
	{ UMC_DRAMCFG_HYB_MEMCLK_533, 533, 1066, 2133 },
	{ UMC_DRAMCFG_HYB_MEMCLK_687, 687, 1375, 2750 },
	{ UMC_DRAMCFG_HYB_MEMCLK_750, 750, 1500, 3000 },
	{ UMC_DRAMCFG_HYB_MEMCLK_800, 800, 1600, 3200 },
	{ UMC_DRAMCFG_HYB_MEMCLK_933, 933, 1866, 3733 },
	{ UMC_DRAMCFG_HYB_MEMCLK_1066, 1066, 2133, 4267 },
	{ UMC_DRAMCFG_HYB_MEMCLK_1200, 1200, 2400, 4800 },
	{ UMC_DRAMCFG_HYB_MEMCLK_1375, 1375, 2750, 5500 },
	{ UMC_DRAMCFG_HYB_MEMCLK_1500, 1500, 3000, 6000 },
	{ UMC_DRAMCFG_HYB_MEMCLK_1600, 1600, 3200, 6400 }

};

static boolean_t
zen_umc_identify(zen_umc_t *umc)
{
	for (uint_t i = 0; i < ARRAY_SIZE(zen_umc_fam_data); i++) {
		if (zen_umc_fam_data[i].zufd_family == umc->umc_family) {
			umc->umc_fdata = &zen_umc_fam_data[i];
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}

/*
 * This operates on DFv2, DFv3, and DFv3.5 DRAM rules, which generally speaking
 * are in similar register locations and meanings, but the size of bits in
 * memory is not consistent.
 */
static int
zen_umc_read_dram_rule_df_23(zen_umc_t *umc, const uint_t dfno,
    const uint_t inst, const uint_t ruleno, df_dram_rule_t *rule)
{
	int ret;
	uint32_t base, limit;
	uint64_t dbase, dlimit;
	uint16_t addr_ileave, chan_ileave, sock_ileave, die_ileave, dest;
	boolean_t hash = B_FALSE;
	zen_umc_df_t *df = &umc->umc_dfs[dfno];

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_BASE_V2(ruleno),
	    &base)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM base "
		    "register %u on 0x%x/0x%x: %d", ruleno, dfno, inst, ret);
		return (ret);
	}

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_LIMIT_V2(ruleno),
	    &limit)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM limit "
		    "register %u on 0x%x/0x%x: %d", ruleno, dfno, inst, ret);
		return (ret);
	}


	rule->ddr_raw_base = base;
	rule->ddr_raw_limit = limit;
	rule->ddr_raw_ileave = rule->ddr_raw_ctrl = 0;

	if (!DF_DRAM_BASE_V2_GET_VALID(base)) {
		return (0);
	}

	/*
	 * Extract all values from the registers and then normalize. While there
	 * are often different bit patterns for the values, the interpretation
	 * is the same across all the Zen 1-3 parts. That is while which bits
	 * may be used for say channel interleave vary, the values of them are
	 * consistent.
	 */
	rule->ddr_flags |= DF_DRAM_F_VALID;
	if (DF_DRAM_BASE_V2_GET_HOLE_EN(base)) {
		rule->ddr_flags |= DF_DRAM_F_HOLE;
	}

	dbase = DF_DRAM_BASE_V2_GET_BASE(base);
	dlimit = DF_DRAM_LIMIT_V2_GET_LIMIT(limit);
	switch (umc->umc_df_rev) {
	case DF_REV_2:
		addr_ileave = DF_DRAM_BASE_V2_GET_ILV_ADDR(base);
		chan_ileave = DF_DRAM_BASE_V2_GET_ILV_CHAN(base);
		die_ileave = DF_DRAM_LIMIT_V2_GET_ILV_DIE(limit);
		sock_ileave = DF_DRAM_LIMIT_V2_GET_ILV_SOCK(limit);
		dest = DF_DRAM_LIMIT_V2_GET_DEST_ID(limit);
		break;
	case DF_REV_3:
		addr_ileave = DF_DRAM_BASE_V3_GET_ILV_ADDR(base);
		sock_ileave = DF_DRAM_BASE_V3_GET_ILV_SOCK(base);
		die_ileave = DF_DRAM_BASE_V3_GET_ILV_DIE(base);
		chan_ileave = DF_DRAM_BASE_V3_GET_ILV_CHAN(base);
		dest = DF_DRAM_LIMIT_V3_GET_DEST_ID(limit);
		break;
	case DF_REV_3P5:
		addr_ileave = DF_DRAM_BASE_V3P5_GET_ILV_ADDR(base);
		sock_ileave = DF_DRAM_BASE_V3P5_GET_ILV_SOCK(base);
		die_ileave = DF_DRAM_BASE_V3P5_GET_ILV_DIE(base);
		chan_ileave = DF_DRAM_BASE_V3P5_GET_ILV_CHAN(base);
		dest = DF_DRAM_LIMIT_V3P5_GET_DEST_ID(limit);
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered unsupported "
		    "DF revision processing DRAM rules: 0x%x", umc->umc_df_rev);
		return (-1);
	}

	rule->ddr_base = dbase << DF_DRAM_BASE_V2_BASE_SHIFT;
	rule->ddr_sock_ileave_bits = sock_ileave;
	rule->ddr_die_ileave_bits = die_ileave;
	switch (addr_ileave) {
	case DF_DRAM_ILV_ADDR_8:
	case DF_DRAM_ILV_ADDR_9:
	case DF_DRAM_ILV_ADDR_10:
	case DF_DRAM_ILV_ADDR_11:
	case DF_DRAM_ILV_ADDR_12:
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered invalid address "
		    "interleave on rule %u, df/inst 0x%x/0x%x: 0x%x", ruleno,
		    dfno, inst, addr_ileave);
		return (EINVAL);
	}
	rule->ddr_addr_start = DF_DRAM_ILV_ADDR_BASE + addr_ileave;

	switch (chan_ileave) {
	case DF_DRAM_BASE_V2_ILV_CHAN_1:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_1CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_2:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_2CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_4:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_4CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_8:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_8CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_6:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_6CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_COD4_2:
		hash = B_TRUE;
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_COD4_2CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_COD2_4:
		hash = B_TRUE;
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH;
		break;
	case DF_DRAM_BASE_V2_ILV_CHAN_COD1_8:
		hash = B_TRUE;
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_COD1_8CH;
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered invalid channel "
		    "interleave on rule %u, df/inst 0x%x/0x%x: 0x%x", ruleno,
		    dfno, inst, chan_ileave);
		return (EINVAL);
	}

	/*
	 * If hashing is enabled, note which hashing rules apply to this
	 * address. This is done to smooth over the differences between DFv3 and
	 * DFv4, where the flags are in the rules themselves in the latter, but
	 * global today.
	 */
	if (hash) {
		if ((df->zud_flags & ZEN_UMC_DF_F_HASH_16_18) != 0) {
			rule->ddr_flags |= DF_DRAM_F_HASH_16_18;
		}

		if ((df->zud_flags & ZEN_UMC_DF_F_HASH_21_23) != 0) {
			rule->ddr_flags |= DF_DRAM_F_HASH_21_23;
		}

		if ((df->zud_flags & ZEN_UMC_DF_F_HASH_30_32) != 0) {
			rule->ddr_flags |= DF_DRAM_F_HASH_30_32;
		}
	}

	/*
	 * While DFv4 makes remapping explicit, it is basically always enabled
	 * and used on supported platforms prior to that point. So flag such
	 * supported platforms as ones that need to do this. On those systems
	 * there is only one set of remap rules for an entire DF that are
	 * determined based on the target socket. To indicate that we use the
	 * DF_DRAM_F_REMAP_SOCK flag below and skip setting a remap target.
	 */
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_TARG_REMAP) != 0) {
		rule->ddr_flags |= DF_DRAM_F_REMAP_EN | DF_DRAM_F_REMAP_SOCK;
	}

	rule->ddr_limit = (dlimit << DF_DRAM_LIMIT_V2_LIMIT_SHIFT) +
	    DF_DRAM_LIMIT_V2_LIMIT_EXCL;
	rule->ddr_dest_fabid = dest;

	return (0);
}

static int
zen_umc_read_dram_rule_df_4(zen_umc_t *umc, const uint_t dfno,
    const uint_t inst, const uint_t ruleno, df_dram_rule_t *rule)
{
	int ret;
	uint16_t addr_ileave;
	uint32_t base, limit, ilv, ctl;

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_BASE_V4(ruleno),
	    &base)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM base "
		    "register %u on 0x%x/0x%x: %d", ruleno, dfno, inst, ret);
		return (ret);
	}

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_LIMIT_V4(ruleno),
	    &limit)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM limit "
		    "register %u on 0x%x/0x%x: %d", ruleno, dfno, inst, ret);
		return (ret);
	}

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_ILV_V4(ruleno),
	    &ilv)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM "
		    "interleave register %u on 0x%x/0x%x: %d", ruleno, dfno,
		    inst, ret);
		return (ret);
	}

	if ((ret = amdzen_c_df_read32(dfno, inst, DF_DRAM_CTL_V4(ruleno),
	    &ctl)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM control "
		    "register %u on 0x%x/0x%x: %d", ruleno, dfno, inst, ret);
		return (ret);
	}

	rule->ddr_raw_base = base;
	rule->ddr_raw_limit = limit;
	rule->ddr_raw_ileave = ilv;
	rule->ddr_raw_ctrl = ctl;

	if (!DF_DRAM_CTL_V4_GET_VALID(ctl)) {
		return (0);
	}

	rule->ddr_flags |= DF_DRAM_F_VALID;
	rule->ddr_base = DF_DRAM_BASE_V4_GET_ADDR(base);
	rule->ddr_base = rule->ddr_base << DF_DRAM_BASE_V4_BASE_SHIFT;
	rule->ddr_limit = DF_DRAM_LIMIT_V4_GET_ADDR(limit);
	rule->ddr_limit = (rule->ddr_limit << DF_DRAM_LIMIT_V4_LIMIT_SHIFT) +
	    DF_DRAM_LIMIT_V4_LIMIT_EXCL;
	rule->ddr_dest_fabid = DF_DRAM_CTL_V4_GET_DEST_ID(ctl);

	if (DF_DRAM_CTL_V4_GET_HASH_1G(ctl) != 0) {
		rule->ddr_flags |= DF_DRAM_F_HASH_30_32;
	}

	if (DF_DRAM_CTL_V4_GET_HASH_2M(ctl) != 0) {
		rule->ddr_flags |= DF_DRAM_F_HASH_21_23;
	}

	if (DF_DRAM_CTL_V4_GET_HASH_64K(ctl) != 0) {
		rule->ddr_flags |= DF_DRAM_F_HASH_16_18;
	}

	if (DF_DRAM_CTL_V4_GET_REMAP_EN(ctl) != 0) {
		rule->ddr_flags |= DF_DRAM_F_REMAP_EN;
		rule->ddr_remap_ent = DF_DRAM_CTL_V4_GET_REMAP_SEL(ctl);
	}

	if (DF_DRAM_CTL_V4_GET_HOLE_EN(ctl) != 0) {
		rule->ddr_flags |= DF_DRAM_F_HOLE;
	}

	rule->ddr_sock_ileave_bits = DF_DRAM_ILV_V4_GET_SOCK(ilv);
	rule->ddr_die_ileave_bits = DF_DRAM_ILV_V4_GET_DIE(ilv);
	switch (DF_DRAM_ILV_V4_GET_CHAN(ilv)) {
	case DF_DRAM_ILV_V4_CHAN_1:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_1CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_2:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_2CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_4:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_4CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_8:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_8CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_16:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_16CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_32:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_32CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS4_2CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_2CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS2_4CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_COD2_4CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS1_8CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_8CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS4_3CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS4_3CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS2_6CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_6CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS1_12CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_12CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS2_5CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS2_5CH;
		break;
	case DF_DRAM_ILV_V4_CHAN_NPS1_10CH:
		rule->ddr_chan_ileave = DF_CHAN_ILEAVE_NPS1_10CH;
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered invalid channel "
		    "interleave on rule %u, df/inst 0x%x/0x%x: 0x%x", ruleno,
		    dfno, inst, DF_DRAM_ILV_V4_GET_CHAN(ilv));

		break;
	}

	addr_ileave = DF_DRAM_ILV_V4_GET_ADDR(ilv);
	switch (addr_ileave) {
	case DF_DRAM_ILV_ADDR_8:
	case DF_DRAM_ILV_ADDR_9:
	case DF_DRAM_ILV_ADDR_10:
	case DF_DRAM_ILV_ADDR_11:
	case DF_DRAM_ILV_ADDR_12:
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered invalid address "
		    "interleave on rule %u, df/inst 0x%x/0x%x: 0x%x", ruleno,
		    dfno, inst, addr_ileave);
		return (EINVAL);
	}
	rule->ddr_addr_start = DF_DRAM_ILV_ADDR_BASE + addr_ileave;

	return (0);
}

static int
zen_umc_read_dram_rule(zen_umc_t *umc, const uint_t dfno, const uint_t instid,
    const uint_t ruleno, df_dram_rule_t *rule)
{
	int ret;

	switch (umc->umc_df_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
		ret = zen_umc_read_dram_rule_df_23(umc, dfno, instid, ruleno,
		    rule);
		break;
	case DF_REV_4:
		ret = zen_umc_read_dram_rule_df_4(umc, dfno, instid, ruleno,
		    rule);
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered unsupported "
		    "DF revision processing DRAM rules: 0x%x", umc->umc_df_rev);
		return (-1);
	}

	if (ret != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM "
		    "rule %u on df/inst 0x%x/0x%x: %d", ruleno,
		    dfno, instid, ret);
		return (-1);
	}

	return (0);
}

static int
zen_umc_read_remap(zen_umc_t *umc, zen_umc_df_t *df, const uint_t instid)
{
	uint_t nremaps, nents;
	uint_t dfno = df->zud_dfno;
	const df_reg_def_t milan_remap0[ZEN_UMC_MILAN_CS_NREMAPS] = {
	    DF_SKT0_CS_REMAP0_V3, DF_SKT1_CS_REMAP0_V3 };
	const df_reg_def_t milan_remap1[ZEN_UMC_MILAN_CS_NREMAPS] = {
	    DF_SKT0_CS_REMAP1_V3, DF_SKT1_CS_REMAP1_V3 };
	const df_reg_def_t dfv4_remapA[ZEN_UMC_MAX_CS_REMAPS] = {
	    DF_CS_REMAP0A_V4, DF_CS_REMAP1A_V4, DF_CS_REMAP2A_V4,
	    DF_CS_REMAP3A_V4 };
	const df_reg_def_t dfv4_remapB[ZEN_UMC_MAX_CS_REMAPS] = {
	    DF_CS_REMAP0B_V4, DF_CS_REMAP1B_V4, DF_CS_REMAP2B_V4,
	    DF_CS_REMAP3B_V4 };
	const df_reg_def_t *remapA, *remapB;


	switch (umc->umc_df_rev) {
	case DF_REV_3:
		nremaps = ZEN_UMC_MILAN_CS_NREMAPS;
		nents = ZEN_UMC_MILAN_REMAP_ENTS;
		remapA = milan_remap0;
		remapB = milan_remap1;
		break;
	case DF_REV_4:
		nremaps = ZEN_UMC_MAX_CS_REMAPS;
		nents = ZEN_UMC_MAX_REMAP_ENTS;
		remapA = dfv4_remapA;
		remapB = dfv4_remapB;
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered unsupported DF "
		    "revision processing remap rules: 0x%x", umc->umc_df_rev);
		return (-1);
	}

	df->zud_cs_nremap = nremaps;
	for (uint_t i = 0; i < nremaps; i++) {
		int ret;
		uint32_t rmA, rmB;
		zen_umc_cs_remap_t *remap = &df->zud_remap[i];

		if ((ret = amdzen_c_df_read32(dfno, instid, remapA[i],
		    &rmA)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "!failed to read "
			    "df/inst 0x%x/0x%x remap socket %u-0/A: %d", dfno,
			    instid, i, ret);
			return (-1);
		}

		if ((ret = amdzen_c_df_read32(dfno, instid, remapB[i],
		    &rmB)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "!failed to read "
			    "df/inst 0x%x/0x%x remap socket %u-1/B: %d", dfno,
			    instid, i, ret);
			return (-1);
		}

		remap->csr_nremaps = nents;
		for (uint_t ent = 0; ent < ZEN_UMC_REMAP_PER_REG; ent++) {
			uint_t alt = ent + ZEN_UMC_REMAP_PER_REG;
			boolean_t do_alt = alt < nents;
			remap->csr_remaps[ent] = DF_CS_REMAP_GET_CSX(rmA,
			    ent);
			if (do_alt) {
				remap->csr_remaps[alt] =
				    DF_CS_REMAP_GET_CSX(rmB, ent);
			}
		}
	}

	return (0);
}

/*
 * Now that we have a CCM, we have several different tasks ahead of us:
 *
 *   o Determine whether or not the DRAM hole is valid.
 *   o Snapshot all of the system address rules and translate them into our
 *     generic format.
 *   o Determine if there are any rules to retarget things (currently
 *     Milan/Genoa).
 *   o Determine if there are any other hashing rules enabled.
 *
 * We only require this from a single CCM as these are currently required to be
 * the same across all of them.
 */
static int
zen_umc_fill_ccm_cb(const uint_t dfno, const uint32_t fabid,
    const uint32_t instid, void *arg)
{
	zen_umc_t *umc = arg;
	zen_umc_df_t *df = &umc->umc_dfs[dfno];
	df_reg_def_t hole;
	int ret;
	uint32_t val;

	df->zud_dfno = dfno;
	df->zud_ccm_inst = instid;

	/*
	 * First get the DRAM hole. This has the same layout, albeit different
	 * registers across our different platforms.
	 */
	switch (umc->umc_df_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
		hole = DF_DRAM_HOLE_V2;
		break;
	case DF_REV_4:
		hole = DF_DRAM_HOLE_V4;
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered unsupported "
		    "DF version: 0x%x", umc->umc_df_rev);
		return (-1);
	}

	if ((ret = amdzen_c_df_read32(dfno, instid, hole, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM Hole: %d",
		    ret);
		return (-1);
	}

	df->zud_hole_raw = val;
	if (DF_DRAM_HOLE_GET_VALID(val)) {
		uint64_t t;

		df->zud_flags |= ZEN_UMC_DF_F_HOLE_VALID;
		t = DF_DRAM_HOLE_GET_BASE(val);
		df->zud_hole_base = t << DF_DRAM_HOLE_BASE_SHIFT;
	}

	/*
	 * Prior to Zen 4, the hash information was global and applied to all
	 * COD rules globally. Check if we're on such a system and snapshot this
	 * so we can use it during the rule application. Note, this was added in
	 * DFv3.
	 */
	if (umc->umc_df_rev == DF_REV_3 || umc->umc_df_rev == DF_REV_3P5) {
		uint32_t globctl;

		if ((ret = amdzen_c_df_read32(dfno, instid, DF_GLOB_CTL_V3,
		    &globctl)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "!failed to read global "
			    "control: %d", ret);
			return (-1);
		}

		df->zud_glob_ctl_raw = globctl;
		if (DF_GLOB_CTL_V3_GET_HASH_1G(globctl) != 0) {
			df->zud_flags |= ZEN_UMC_DF_F_HASH_30_32;
		}

		if (DF_GLOB_CTL_V3_GET_HASH_2M(globctl) != 0) {
			df->zud_flags |= ZEN_UMC_DF_F_HASH_21_23;
		}

		if (DF_GLOB_CTL_V3_GET_HASH_64K(globctl) != 0) {
			df->zud_flags |= ZEN_UMC_DF_F_HASH_16_18;
		}
	}

	df->zud_dram_nrules = umc->umc_fdata->zufd_dram_nrules;
	for (uint_t i = 0; i < umc->umc_fdata->zufd_dram_nrules; i++) {
		if (zen_umc_read_dram_rule(umc, dfno, instid, i,
		    &df->zud_rules[i]) != 0) {
			return (-1);
		}
	}

	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_TARG_REMAP) != 0) {
		if (zen_umc_read_remap(umc, df, instid) != 0) {
			return (-1);
		}
	}

	/*
	 * We only want a single entry, so always return 1 to terminate us
	 * early.
	 */
	return (1);
}

/*
 * At this point we can go through and calculate the size of the DIMM that we've
 * found. While it would be nice to determine this from the SPD data, we can
 * figure this out entirely based upon the information in the memory controller.
 *
 * This works by first noting that DDR4, LPDDR4, DDR5, and LPDDR5 are all built
 * around 64-bit data channels. This means that each row and column provides up
 * 64-bits (ignoring ECC) of data. There are a number of banks and bank groups.
 * The memory controller tracks the total number of bits that are used for each.
 * While DDR5 introduces sub-channels, we don't need to worry about those here,
 * because ultimately the sub-channel just splits the 64-bit bus we're assuming
 * into 2x 32-bit buses. While they can be independently selected, they should
 * have equivalent capacities.
 *
 * The most confusing part of this is that there is one of these related to each
 * rank on the device. The UMC natively has two 'chip-selects', each of which is
 * used to correspond to a rank. There are then separately multiple rm bits in
 * each chip-select. As far as we can tell the PSP or SMU programs the number of
 * rm bits to be zero when you have a dual-rank device.
 *
 * We end up summing each chip-select rather than assuming that the chip-selects
 * are identical. In theory some amount of asymmetric DIMMs exist in the wild,
 * but we don't know of many systems using them.
 */
static void
zen_umc_calc_dimm_size(umc_dimm_t *dimm)
{
	dimm->ud_dimm_size = 0;
	for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_BASE; i++) {
		uint64_t nrc;
		const umc_cs_t *cs = &dimm->ud_cs[i];

		if (!cs->ucs_base.udb_valid && !cs->ucs_sec.udb_valid) {
			continue;
		}

		nrc = cs->ucs_nrow_lo + cs->ucs_nrow_hi + cs->ucs_ncol;
		dimm->ud_dimm_size += (8ULL << nrc) * (1 << cs->ucs_nbanks) *
		    (1 << cs->ucs_nrm);
	}
}

/*
 * This is used to fill in the common properties about a DIMM. This should occur
 * after the rank information has been filled out. The information used is the
 * same between DDR4 and DDR5 DIMMs. The only major difference is the register
 * offset.
 */
static boolean_t
zen_umc_fill_dimm_common(zen_umc_t *umc, zen_umc_df_t *df, zen_umc_chan_t *chan,
    const uint_t dimmno, boolean_t ddr4_style)
{
	umc_dimm_t *dimm;
	int ret;
	smn_reg_t reg;
	uint32_t val;
	const uint32_t id = chan->chan_logid;

	dimm = &chan->chan_dimms[dimmno];
	dimm->ud_dimmno = dimmno;

	if (ddr4_style) {
		reg = UMC_DIMMCFG_DDR4(id, dimmno);
	} else {
		reg = UMC_DIMMCFG_DDR5(id, dimmno);
	}
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read DIMM "
		    "configuration register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	dimm->ud_dimmcfg_raw = val;

	if (UMC_DIMMCFG_GET_X16(val) != 0) {
		dimm->ud_width = UMC_DIMM_W_X16;
	} else if (UMC_DIMMCFG_GET_X4(val) != 0) {
		dimm->ud_width = UMC_DIMM_W_X4;
	} else {
		dimm->ud_width = UMC_DIMM_W_X8;
	}

	if (UMC_DIMMCFG_GET_3DS(val) != 0) {
		dimm->ud_kind = UMC_DIMM_K_3DS_RDIMM;
	} else if (UMC_DIMMCFG_GET_LRDIMM(val) != 0) {
		dimm->ud_kind = UMC_DIMM_K_LRDIMM;
	} else if (UMC_DIMMCFG_GET_RDIMM(val) != 0) {
		dimm->ud_kind = UMC_DIMM_K_RDIMM;
	} else {
		dimm->ud_kind = UMC_DIMM_K_UDIMM;
	}

	/*
	 * DIMM information in a UMC can be somewhat confusing. There are quite
	 * a number of non-zero reset values that are here. Flag whether or not
	 * we think this entry should be usable based on enabled chip-selects.
	 */
	for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_BASE; i++) {
		if (dimm->ud_cs[i].ucs_base.udb_valid ||
		    dimm->ud_cs[i].ucs_sec.udb_valid) {
			dimm->ud_flags |= UMC_DIMM_F_VALID;
			break;
		}
	}

	/*
	 * The remaining calculations we only want to perform if we have actual
	 * data for a DIMM.
	 */
	if ((dimm->ud_flags & UMC_DIMM_F_VALID) == 0) {
		return (B_TRUE);
	}

	zen_umc_calc_dimm_size(dimm);

	return (B_TRUE);
}

/*
 * Fill all the information about a DDR4 DIMM. In the DDR4 UMC, some of this
 * information is on a per-chip select basis while at other times it is on a
 * per-DIMM basis.  In general, chip-selects 0/1 correspond to DIMM 0, and
 * chip-selects 2/3 correspond to DIMM 1. To normalize things with the DDR5 UMC
 * which generally has things stored on a per-rank/chips-select basis, we
 * duplicate information that is DIMM-wide into the chip-select data structure
 * (umc_cs_t).
 */
static boolean_t
zen_umc_fill_chan_dimm_ddr4(zen_umc_t *umc, zen_umc_df_t *df,
    zen_umc_chan_t *chan, const uint_t dimmno)
{
	umc_dimm_t *dimm;
	umc_cs_t *cs0, *cs1;
	const uint32_t id = chan->chan_logid;
	int ret;
	uint32_t val;
	smn_reg_t reg;

	ASSERT3U(dimmno, <, ZEN_UMC_MAX_DIMMS);
	dimm = &chan->chan_dimms[dimmno];
	cs0 = &dimm->ud_cs[0];
	cs1 = &dimm->ud_cs[1];

	/*
	 * DDR4 organization has initial data that exists on a per-chip select
	 * basis. The rest of it is on a per-DIMM basis. First we grab the
	 * per-chip-select data. After this for loop, we will always duplicate
	 * all data that we gather into both chip-selects.
	 */
	for (uint_t i = 0; i < ZEN_UMC_MAX_CS_PER_DIMM; i++) {
		uint64_t addr;
		const uint16_t reginst = i + dimmno * 2;
		reg = UMC_BASE(id, reginst);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read base "
			    "register %x: %d", SMN_REG_ADDR(reg), ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_BASE_GET_ADDR(val) << UMC_BASE_ADDR_SHIFT;
		dimm->ud_cs[i].ucs_base.udb_base = addr;
		dimm->ud_cs[i].ucs_base.udb_valid = UMC_BASE_GET_EN(val);

		reg = UMC_BASE_SEC(id, reginst);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read "
			    "secondary base register %x: %d", SMN_REG_ADDR(reg),
			    ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_BASE_GET_ADDR(val) << UMC_BASE_ADDR_SHIFT;
		dimm->ud_cs[i].ucs_sec.udb_base = addr;
		dimm->ud_cs[i].ucs_sec.udb_valid = UMC_BASE_GET_EN(val);
	}

	reg = UMC_MASK_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read mask register "
		    "%x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}

	/*
	 * When we extract the masks, hardware only checks a limited range of
	 * bits. Therefore we need to always OR in those lower order bits.
	 */
	cs0->ucs_base_mask = (uint64_t)UMC_MASK_GET_ADDR(val) <<
	    UMC_MASK_ADDR_SHIFT;
	cs0->ucs_base_mask |= (1 << UMC_MASK_ADDR_SHIFT) - 1;
	cs1->ucs_base_mask = cs0->ucs_base_mask;

	reg = UMC_MASK_SEC_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read secondary mask "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs0->ucs_sec_mask = (uint64_t)UMC_MASK_GET_ADDR(val) <<
	    UMC_MASK_ADDR_SHIFT;
	cs0->ucs_sec_mask |= (1 << UMC_MASK_ADDR_SHIFT) - 1;
	cs1->ucs_sec_mask = cs0->ucs_sec_mask;

	reg = UMC_ADDRCFG_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read address config "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}

	cs0->ucs_nbanks = UMC_ADDRCFG_GET_NBANK_BITS(val) +
	    UMC_ADDRCFG_NBANK_BITS_BASE;
	cs1->ucs_nbanks = cs0->ucs_nbanks;
	cs0->ucs_ncol = UMC_ADDRCFG_GET_NCOL_BITS(val) +
	    UMC_ADDRCFG_NCOL_BITS_BASE;
	cs1->ucs_ncol = cs0->ucs_ncol;
	cs0->ucs_nrow_hi = UMC_ADDRCFG_DDR4_GET_NROW_BITS_HI(val);
	cs1->ucs_nrow_hi = cs0->ucs_nrow_hi;
	cs0->ucs_nrow_lo = UMC_ADDRCFG_GET_NROW_BITS_LO(val) +
	    UMC_ADDRCFG_NROW_BITS_LO_BASE;
	cs1->ucs_nrow_lo = cs0->ucs_nrow_lo;
	cs0->ucs_nbank_groups = UMC_ADDRCFG_GET_NBANKGRP_BITS(val);
	cs1->ucs_nbank_groups = cs0->ucs_nbank_groups;
	/*
	 * As the chip-select XORs don't always show up, use a dummy value
	 * that'll result in no change occurring here.
	 */
	cs0->ucs_cs_xor = cs1->ucs_cs_xor = 0;

	/*
	 * APUs don't seem to support various rank select bits.
	 */
	if (umc->umc_fdata->zufd_umc_style == ZEN_UMC_UMC_S_DDR4) {
		cs0->ucs_nrm = UMC_ADDRCFG_DDR4_GET_NRM_BITS(val);
		cs1->ucs_nrm = cs0->ucs_nrm;
	} else {
		cs0->ucs_nrm = cs1->ucs_nrm = 0;
	}

	reg = UMC_ADDRSEL_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read bank address "
		    "select register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs0->ucs_row_hi_bit = UMC_ADDRSEL_DDR4_GET_ROW_HI(val) +
	    UMC_ADDRSEL_DDR4_ROW_HI_BASE;
	cs1->ucs_row_hi_bit = cs0->ucs_row_hi_bit;
	cs0->ucs_row_low_bit = UMC_ADDRSEL_GET_ROW_LO(val) +
	    UMC_ADDRSEL_ROW_LO_BASE;
	cs1->ucs_row_low_bit = cs0->ucs_row_low_bit;
	cs0->ucs_bank_bits[0] = UMC_ADDRSEL_GET_BANK0(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs0->ucs_bank_bits[1] = UMC_ADDRSEL_GET_BANK1(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs0->ucs_bank_bits[2] = UMC_ADDRSEL_GET_BANK2(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs0->ucs_bank_bits[3] = UMC_ADDRSEL_GET_BANK3(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs0->ucs_bank_bits[4] = UMC_ADDRSEL_GET_BANK4(val) +
	    UMC_ADDRSEL_BANK_BASE;
	bcopy(cs0->ucs_bank_bits, cs1->ucs_bank_bits,
	    sizeof (cs0->ucs_bank_bits));

	reg = UMC_COLSEL_LO_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read column address "
		    "select low register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	for (uint_t i = 0; i < ZEN_UMC_MAX_COLSEL_PER_REG; i++) {
		cs0->ucs_col_bits[i] = UMC_COLSEL_REMAP_GET_COL(val, i) +
		    UMC_COLSEL_LO_BASE;
	}

	reg = UMC_COLSEL_HI_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read column address "
		    "select high register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	for (uint_t i = 0; i < ZEN_UMC_MAX_COLSEL_PER_REG; i++) {
		cs0->ucs_col_bits[i + ZEN_UMC_MAX_COLSEL_PER_REG] =
		    UMC_COLSEL_REMAP_GET_COL(val, i) + UMC_COLSEL_HI_BASE;
	}
	bcopy(cs0->ucs_col_bits, cs1->ucs_col_bits, sizeof (cs0->ucs_col_bits));

	/*
	 * The next two registers give us information about a given rank select.
	 * In the APUs, the inversion bits are there; however, the actual bit
	 * selects are not. In this case we read the reserved bits regardless.
	 * They should be ignored due to the fact that the number of banks is
	 * zero.
	 */
	reg = UMC_RMSEL_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read rank address "
		    "select register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs0->ucs_inv_msbs = UMC_RMSEL_DDR4_GET_INV_MSBE(val);
	cs1->ucs_inv_msbs = UMC_RMSEL_DDR4_GET_INV_MSBO(val);
	cs0->ucs_rm_bits[0] = UMC_RMSEL_DDR4_GET_RM0(val) +
	    UMC_RMSEL_BASE;
	cs0->ucs_rm_bits[1] = UMC_RMSEL_DDR4_GET_RM1(val) +
	    UMC_RMSEL_BASE;
	cs0->ucs_rm_bits[2] = UMC_RMSEL_DDR4_GET_RM2(val) +
	    UMC_RMSEL_BASE;
	bcopy(cs0->ucs_rm_bits, cs1->ucs_rm_bits, sizeof (cs0->ucs_rm_bits));

	reg = UMC_RMSEL_SEC_DDR4(id, dimmno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read secondary rank "
		    "address select register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs0->ucs_inv_msbs_sec = UMC_RMSEL_DDR4_GET_INV_MSBE(val);
	cs1->ucs_inv_msbs_sec = UMC_RMSEL_DDR4_GET_INV_MSBO(val);
	cs0->ucs_rm_bits_sec[0] = UMC_RMSEL_DDR4_GET_RM0(val) +
	    UMC_RMSEL_BASE;
	cs0->ucs_rm_bits_sec[1] = UMC_RMSEL_DDR4_GET_RM1(val) +
	    UMC_RMSEL_BASE;
	cs0->ucs_rm_bits_sec[2] = UMC_RMSEL_DDR4_GET_RM2(val) +
	    UMC_RMSEL_BASE;
	bcopy(cs0->ucs_rm_bits_sec, cs1->ucs_rm_bits_sec,
	    sizeof (cs0->ucs_rm_bits_sec));

	return (zen_umc_fill_dimm_common(umc, df, chan, dimmno, B_TRUE));
}

/*
 * The DDR5 based systems are organized such that almost all the information we
 * care about is split between two different chip-select structures in the UMC
 * hardware SMN space.
 */
static boolean_t
zen_umc_fill_chan_rank_ddr5(zen_umc_t *umc, zen_umc_df_t *df,
    zen_umc_chan_t *chan, const uint_t dimmno, const uint_t rankno)
{
	int ret;
	umc_cs_t *cs;
	uint32_t val;
	smn_reg_t reg;
	const uint32_t id = chan->chan_logid;
	const uint32_t regno = dimmno * 2 + rankno;

	ASSERT3U(dimmno, <, ZEN_UMC_MAX_DIMMS);
	ASSERT3U(rankno, <, ZEN_UMC_MAX_CS_PER_DIMM);
	cs = &chan->chan_dimms[dimmno].ud_cs[rankno];

	reg = UMC_BASE(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read base "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs->ucs_base.udb_base = (uint64_t)UMC_BASE_GET_ADDR(val) <<
	    UMC_BASE_ADDR_SHIFT;
	cs->ucs_base.udb_valid = UMC_BASE_GET_EN(val);
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_UMC_EADDR) != 0) {
		uint64_t addr;

		reg = UMC_BASE_EXT_DDR5(id, regno);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) !=
		    0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read "
			    "extended base register %x: %d", SMN_REG_ADDR(reg),
			    ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_BASE_EXT_GET_ADDR(val) <<
		    UMC_BASE_EXT_ADDR_SHIFT;
		cs->ucs_base.udb_base |= addr;
	}

	reg = UMC_BASE_SEC(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read secondary base "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs->ucs_sec.udb_base = (uint64_t)UMC_BASE_GET_ADDR(val) <<
	    UMC_BASE_ADDR_SHIFT;
	cs->ucs_sec.udb_valid = UMC_BASE_GET_EN(val);
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_UMC_EADDR) != 0) {
		uint64_t addr;

		reg = UMC_BASE_EXT_SEC_DDR5(id, regno);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) !=
		    0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read "
			    "extended secondary base register %x: %d",
			    SMN_REG_ADDR(reg), ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_BASE_EXT_GET_ADDR(val) <<
		    UMC_BASE_EXT_ADDR_SHIFT;
		cs->ucs_sec.udb_base |= addr;
	}

	reg = UMC_MASK_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read mask "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs->ucs_base_mask = (uint64_t)UMC_MASK_GET_ADDR(val) <<
	    UMC_MASK_ADDR_SHIFT;
	cs->ucs_base_mask |= (1 << UMC_MASK_ADDR_SHIFT) - 1;
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_UMC_EADDR) != 0) {
		uint64_t addr;

		reg = UMC_MASK_EXT_DDR5(id, regno);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) !=
		    0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read "
			    "extended mask register %x: %d", SMN_REG_ADDR(reg),
			    ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_MASK_EXT_GET_ADDR(val) <<
		    UMC_MASK_EXT_ADDR_SHIFT;
		cs->ucs_base_mask |= addr;
	}


	reg = UMC_MASK_SEC_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read secondary mask "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs->ucs_sec_mask = (uint64_t)UMC_MASK_GET_ADDR(val) <<
	    UMC_MASK_ADDR_SHIFT;
	cs->ucs_sec_mask |= (1 << UMC_MASK_ADDR_SHIFT) - 1;
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_UMC_EADDR) != 0) {
		uint64_t addr;

		reg = UMC_MASK_EXT_SEC_DDR5(id, regno);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) !=
		    0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read "
			    "extended mask register %x: %d", SMN_REG_ADDR(reg),
			    ret);
			return (B_FALSE);
		}

		addr = (uint64_t)UMC_MASK_EXT_GET_ADDR(val) <<
		    UMC_MASK_EXT_ADDR_SHIFT;
		cs->ucs_sec_mask |= addr;
	}

	reg = UMC_ADDRCFG_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read address config "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_CS_XOR) != 0) {
		cs->ucs_cs_xor = UMC_ADDRCFG_DDR5_GET_CSXOR(val);
	} else {
		cs->ucs_cs_xor = 0;
	}
	cs->ucs_nbanks = UMC_ADDRCFG_GET_NBANK_BITS(val) +
	    UMC_ADDRCFG_NBANK_BITS_BASE;
	cs->ucs_ncol = UMC_ADDRCFG_GET_NCOL_BITS(val) +
	    UMC_ADDRCFG_NCOL_BITS_BASE;
	cs->ucs_nrow_lo = UMC_ADDRCFG_GET_NROW_BITS_LO(val) +
	    UMC_ADDRCFG_NROW_BITS_LO_BASE;
	cs->ucs_nrow_hi = 0;
	cs->ucs_nrm = UMC_ADDRCFG_DDR5_GET_NRM_BITS(val);
	cs->ucs_nbank_groups = UMC_ADDRCFG_GET_NBANKGRP_BITS(val);

	reg = UMC_ADDRSEL_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read address select "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	cs->ucs_row_hi_bit = 0;
	cs->ucs_row_low_bit = UMC_ADDRSEL_GET_ROW_LO(val) +
	    UMC_ADDRSEL_ROW_LO_BASE;
	cs->ucs_bank_bits[4] = UMC_ADDRSEL_GET_BANK4(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs->ucs_bank_bits[3] = UMC_ADDRSEL_GET_BANK3(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs->ucs_bank_bits[2] = UMC_ADDRSEL_GET_BANK2(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs->ucs_bank_bits[1] = UMC_ADDRSEL_GET_BANK1(val) +
	    UMC_ADDRSEL_BANK_BASE;
	cs->ucs_bank_bits[0] = UMC_ADDRSEL_GET_BANK0(val) +
	    UMC_ADDRSEL_BANK_BASE;

	reg = UMC_COLSEL_LO_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read column address "
		    "select low register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	for (uint_t i = 0; i < ZEN_UMC_MAX_COLSEL_PER_REG; i++) {
		cs->ucs_col_bits[i] = UMC_COLSEL_REMAP_GET_COL(val, i) +
		    UMC_COLSEL_LO_BASE;
	}

	reg = UMC_COLSEL_HI_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read column address "
		    "select high register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	for (uint_t i = 0; i < ZEN_UMC_MAX_COLSEL_PER_REG; i++) {
		cs->ucs_col_bits[i + ZEN_UMC_MAX_COLSEL_PER_REG] =
		    UMC_COLSEL_REMAP_GET_COL(val, i) + UMC_COLSEL_HI_BASE;
	}

	/*
	 * Time for our friend, the RM Selection register. Like in DDR4 we end
	 * up reading everything here, even though most others have reserved
	 * bits here. The intent is that we won't look at the reserved bits
	 * unless something actually points us there.
	 */
	reg = UMC_RMSEL_DDR5(id, regno);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read rank multiply "
		    "select register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}

	/*
	 * DDR5 based devices have a primary and secondary msbs; however, they
	 * only have a single set of rm bits. To normalize things with the DDR4
	 * subsystem, we copy the primary bits to the secondary so we can use
	 * these the same way in the decoder/encoder.
	 */
	cs->ucs_inv_msbs = UMC_RMSEL_DDR5_GET_INV_MSBS(val);
	cs->ucs_inv_msbs_sec = UMC_RMSEL_DDR5_GET_INV_MSBS_SEC(val);
	cs->ucs_subchan = UMC_RMSEL_DDR5_GET_SUBCHAN(val) +
	    UMC_RMSEL_DDR5_SUBCHAN_BASE;
	cs->ucs_rm_bits[3] = UMC_RMSEL_DDR5_GET_RM3(val) + UMC_RMSEL_BASE;
	cs->ucs_rm_bits[2] = UMC_RMSEL_DDR5_GET_RM2(val) + UMC_RMSEL_BASE;
	cs->ucs_rm_bits[1] = UMC_RMSEL_DDR5_GET_RM1(val) + UMC_RMSEL_BASE;
	cs->ucs_rm_bits[0] = UMC_RMSEL_DDR5_GET_RM0(val) + UMC_RMSEL_BASE;
	bcopy(cs->ucs_rm_bits, cs->ucs_rm_bits_sec,
	    sizeof (cs->ucs_rm_bits));

	return (zen_umc_fill_dimm_common(umc, df, chan, dimmno, B_FALSE));
}

static void
zen_umc_fill_ddr_type(zen_umc_t *umc, zen_umc_chan_t *chan)
{
	umc_dimm_type_t dimm = UMC_DIMM_T_UNKNOWN;
	uint8_t val;

	/*
	 * The different UMC styles split into two groups. Those that support
	 * DDR4 and those that support DDR5 (with the hybrid group being in the
	 * DDR5 style camp). While all the values are consistent between
	 * different ones (e.g. reserved values correspond to unsupported
	 * items), we still check types based on the UMC's design type so if we
	 * see something weird, we don't accidentally use an older value.
	 */
	val = UMC_UMCCFG_GET_DDR_TYPE(chan->chan_umccfg_raw);
	switch (umc->umc_fdata->zufd_umc_style) {
	case ZEN_UMC_UMC_S_DDR4:
	case ZEN_UMC_UMC_S_DDR4_APU:
		switch (val) {
		case UMC_UMCCFG_DDR4_T_DDR4:
			dimm = UMC_DIMM_T_DDR4;
			break;
		case UMC_UMCCFG_DDR4_T_LPDDR4:
			dimm = UMC_DIMM_T_LPDDR4;
			break;
		default:
			break;
		}
		break;
	case ZEN_UMC_UMC_S_HYBRID_LPDDR5:
		switch (val) {
		case UMC_UMCCFG_DDR5_T_LPDDR5:
			dimm = UMC_DIMM_T_LPDDR5;
			break;
		case UMC_UMCCFG_DDR5_T_LPDDR4:
			dimm = UMC_DIMM_T_LPDDR4;
			break;
		default:
			break;
		}
		break;
	case ZEN_UMC_UMC_S_DDR5:
	case ZEN_UMC_UMC_S_DDR5_APU:
		switch (val) {
		case UMC_UMCCFG_DDR5_T_DDR5:
			dimm = UMC_DIMM_T_DDR5;
			break;
		case UMC_UMCCFG_DDR5_T_LPDDR5:
			dimm = UMC_DIMM_T_LPDDR5;
			break;
		default:
			break;
		}
		break;
	}

	chan->chan_type = dimm;
}

/*
 * Use the DDR4 frequency table to determine the speed of this. Note that our
 * hybrid based UMCs use 8 bits for the clock, while the traditional DDR4 ones
 * only use 7. The caller is responsible for using the right mask for the UMC.
 */
static void
zen_umc_fill_chan_ddr4(zen_umc_chan_t *chan, uint_t mstate,
    const uint32_t clock)
{
	for (size_t i = 0; i < ARRAY_SIZE(zen_umc_ddr4_map); i++) {
		if (clock == zen_umc_ddr4_map[i].zufm_reg) {
			chan->chan_clock[mstate] = zen_umc_ddr4_map[i].zufm_mhz;
			chan->chan_speed[mstate] =
			    zen_umc_ddr4_map[i].zufm_mts2;
			break;
		}
	}
}

static void
zen_umc_fill_chan_hyb_lpddr5(zen_umc_chan_t *chan, uint_t mstate)
{
	const uint32_t reg = chan->chan_dramcfg_raw[mstate];
	const uint32_t wck = UMC_DRAMCFG_HYB_GET_WCLKRATIO(reg);
	const uint32_t clock = UMC_DRAMCFG_HYB_GET_MEMCLK(reg);
	boolean_t twox;

	switch (wck) {
	case UMC_DRAMCFG_WCLKRATIO_1TO2:
		twox = B_TRUE;
		break;
	case UMC_DRAMCFG_WCLKRATIO_1TO4:
		twox = B_FALSE;
		break;
	default:
		return;
	}

	for (size_t i = 0; i < ARRAY_SIZE(zen_umc_lpddr5_map); i++) {
		if (clock == zen_umc_lpddr5_map[i].zufm_reg) {
			chan->chan_clock[mstate] =
			    zen_umc_lpddr5_map[i].zufm_mhz;

			if (twox) {
				chan->chan_speed[mstate] =
				    zen_umc_lpddr5_map[i].zufm_mts2;
			} else {
				chan->chan_speed[mstate] =
				    zen_umc_lpddr5_map[i].zufm_mts4;
			}
			break;
		}
	}
}

/*
 * Determine the current operating frequency of the channel. This varies based
 * upon the type of UMC that we're operating on as there are multiple ways to
 * determine this. There are up to four memory P-states that exist in the UMC.
 * This grabs it for a single P-state at a time.
 *
 * Unlike other things, if we cannot determine the frequency of the clock or
 * transfer speed, we do not consider this fatal because that does not stop
 * decoding. It only means that we cannot give a bit of useful information to
 * topo.
 */
static void
zen_umc_fill_chan_freq(zen_umc_t *umc, zen_umc_chan_t *chan, uint_t mstate)
{
	const uint32_t cfg = chan->chan_dramcfg_raw[mstate];
	const umc_dimm_type_t dimm_type = chan->chan_type;

	switch (umc->umc_fdata->zufd_umc_style) {
	case ZEN_UMC_UMC_S_HYBRID_LPDDR5:
		if (dimm_type == UMC_DIMM_T_LPDDR5) {
			zen_umc_fill_chan_hyb_lpddr5(chan, mstate);
		} else if (dimm_type != UMC_DIMM_T_LPDDR4) {
			zen_umc_fill_chan_ddr4(chan, mstate,
			    UMC_DRAMCFG_HYB_GET_MEMCLK(cfg));
		}
		break;
	case ZEN_UMC_UMC_S_DDR4:
	case ZEN_UMC_UMC_S_DDR4_APU:
		zen_umc_fill_chan_ddr4(chan, mstate,
		    UMC_DRAMCFG_DDR4_GET_MEMCLK(cfg));
		break;
	case ZEN_UMC_UMC_S_DDR5:
	case ZEN_UMC_UMC_S_DDR5_APU:
		chan->chan_clock[mstate] = UMC_DRAMCFG_DDR5_GET_MEMCLK(cfg);
		if (dimm_type == UMC_DIMM_T_DDR5) {
			chan->chan_speed[mstate] = 2 * chan->chan_clock[mstate];
		} else if (dimm_type == UMC_DIMM_T_LPDDR5) {
			switch (UMC_DRAMCFG_LPDDR5_GET_WCKRATIO(cfg)) {
			case UMC_DRAMCFG_WCLKRATIO_1TO2:
				chan->chan_speed[mstate] = 2 *
				    chan->chan_clock[mstate];
				break;
			case UMC_DRAMCFG_WCLKRATIO_1TO4:
				chan->chan_speed[mstate] = 4 *
				    chan->chan_clock[mstate];
				break;
			default:
				break;
			}
		}
		break;
	}
}

/*
 * Fill common channel information. While the locations of many of the registers
 * changed between the DDR4-capable and DDR5-capable devices, the actual
 * contents are the same so we process them together.
 */
static boolean_t
zen_umc_fill_chan_hash(zen_umc_t *umc, zen_umc_df_t *df, zen_umc_chan_t *chan,
    boolean_t ddr4)
{
	int ret;
	smn_reg_t reg;
	uint32_t val;

	const umc_chan_hash_flags_t flags = umc->umc_fdata->zufd_chan_hash;
	const uint32_t id = chan->chan_logid;
	umc_chan_hash_t *chash = &chan->chan_hash;
	chash->uch_flags = flags;

	if ((flags & UMC_CHAN_HASH_F_BANK) != 0) {
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_BANK_HASH; i++) {
			umc_bank_hash_t *bank = &chash->uch_bank_hashes[i];

			if (ddr4) {
				reg = UMC_BANK_HASH_DDR4(id, i);
			} else {
				reg = UMC_BANK_HASH_DDR5(id, i);
			}

			if ((ret = amdzen_c_smn_read(df->zud_dfno, reg,
			    &val)) != 0) {
				dev_err(umc->umc_dip, CE_WARN, "failed to read "
				    "bank hash register %x: %d",
				    SMN_REG_ADDR(reg), ret);
				return (B_FALSE);
			}

			bank->ubh_row_xor = UMC_BANK_HASH_GET_ROW(val);
			bank->ubh_col_xor = UMC_BANK_HASH_GET_COL(val);
			bank->ubh_en = UMC_BANK_HASH_GET_EN(val);
		}
	}

	if ((flags & UMC_CHAN_HASH_F_RM) != 0) {
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_RM_HASH; i++) {
			uint64_t addr;
			umc_addr_hash_t *rm = &chash->uch_rm_hashes[i];

			if (ddr4) {
				reg = UMC_RANK_HASH_DDR4(id, i);
			} else {
				reg = UMC_RANK_HASH_DDR5(id, i);
			}

			if ((ret = amdzen_c_smn_read(df->zud_dfno, reg,
			    &val)) != 0) {
				dev_err(umc->umc_dip, CE_WARN, "failed to read "
				    "rm hash register %x: %d",
				    SMN_REG_ADDR(reg), ret);
				return (B_FALSE);
			}

			addr = UMC_RANK_HASH_GET_ADDR(val);
			rm->uah_addr_xor = addr << UMC_RANK_HASH_SHIFT;
			rm->uah_en = UMC_RANK_HASH_GET_EN(val);

			if (ddr4 || (umc->umc_fdata->zufd_flags &
			    ZEN_UMC_FAM_F_UMC_EADDR) == 0) {
				continue;
			}

			reg = UMC_RANK_HASH_EXT_DDR5(id, i);
			if ((ret = amdzen_c_smn_read(df->zud_dfno, reg,
			    &val)) != 0) {
				dev_err(umc->umc_dip, CE_WARN, "failed to read "
				    "rm hash ext register %x: %d",
				    SMN_REG_ADDR(reg), ret);
				return (B_FALSE);
			}

			addr = UMC_RANK_HASH_EXT_GET_ADDR(val);
			rm->uah_addr_xor |= addr <<
			    UMC_RANK_HASH_EXT_ADDR_SHIFT;
		}
	}

	if ((flags & UMC_CHAN_HASH_F_PC) != 0) {
		umc_pc_hash_t *pc = &chash->uch_pc_hash;

		if (ddr4) {
			reg = UMC_PC_HASH_DDR4(id);
		} else {
			reg = UMC_PC_HASH_DDR5(id);
		}

		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read pc hash "
			    "register %x: %d", SMN_REG_ADDR(reg), ret);
			return (B_FALSE);
		}

		pc->uph_row_xor = UMC_PC_HASH_GET_ROW(val);
		pc->uph_col_xor = UMC_PC_HASH_GET_COL(val);
		pc->uph_en = UMC_PC_HASH_GET_EN(val);

		if (ddr4) {
			reg = UMC_PC_HASH2_DDR4(id);
		} else {
			reg = UMC_PC_HASH2_DDR5(id);
		}

		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read pc hash "
			    "2 register %x: %d", SMN_REG_ADDR(reg), ret);
			return (B_FALSE);
		}

		pc->uph_bank_xor = UMC_PC_HASH2_GET_BANK(val);
	}

	if ((flags & UMC_CHAN_HASH_F_CS) != 0) {
		for (uint_t i = 0; i < ZEN_UMC_MAX_CHAN_CS_HASH; i++) {
			uint64_t addr;
			umc_addr_hash_t *rm = &chash->uch_cs_hashes[i];

			if (ddr4) {
				reg = UMC_CS_HASH_DDR4(id, i);
			} else {
				reg = UMC_CS_HASH_DDR5(id, i);
			}

			if ((ret = amdzen_c_smn_read(df->zud_dfno, reg,
			    &val)) != 0) {
				dev_err(umc->umc_dip, CE_WARN, "failed to read "
				    "cs hash register %x", SMN_REG_ADDR(reg));
				return (B_FALSE);
			}

			addr = UMC_CS_HASH_GET_ADDR(val);
			rm->uah_addr_xor = addr << UMC_CS_HASH_SHIFT;
			rm->uah_en = UMC_CS_HASH_GET_EN(val);

			if (ddr4 || (umc->umc_fdata->zufd_flags &
			    ZEN_UMC_FAM_F_UMC_EADDR) == 0) {
				continue;
			}

			reg = UMC_CS_HASH_EXT_DDR5(id, i);
			if ((ret = amdzen_c_smn_read(df->zud_dfno, reg,
			    &val)) != 0) {
				dev_err(umc->umc_dip, CE_WARN, "failed to read "
				    "cs hash ext register %x",
				    SMN_REG_ADDR(reg));
				return (B_FALSE);
			}

			addr = UMC_CS_HASH_EXT_GET_ADDR(val);
			rm->uah_addr_xor |= addr << UMC_CS_HASH_EXT_ADDR_SHIFT;
		}
	}

	return (B_TRUE);
}

/*
 * This fills in settings that we care about which are valid for the entire
 * channel and are the same between DDR4/5 capable devices.
 */
static boolean_t
zen_umc_fill_chan(zen_umc_t *umc, zen_umc_df_t *df, zen_umc_chan_t *chan)
{
	uint32_t val;
	smn_reg_t reg;
	const uint32_t id = chan->chan_logid;
	int ret;
	boolean_t ddr4;

	if (umc->umc_fdata->zufd_umc_style == ZEN_UMC_UMC_S_DDR4 ||
	    umc->umc_fdata->zufd_umc_style == ZEN_UMC_UMC_S_DDR4_APU) {
		ddr4 = B_TRUE;
	} else {
		ddr4 = B_FALSE;
	}

	/*
	 * Begin by gathering all of the information related to hashing. What is
	 * valid here varies based on the actual chip family and then the
	 * registers vary based on DDR4 and DDR5.
	 */
	if (!zen_umc_fill_chan_hash(umc, df, chan, ddr4)) {
		return (B_FALSE);
	}

	reg = UMC_UMCCFG(id);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read UMC "
		    "configuration register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}

	chan->chan_umccfg_raw = val;
	if (UMC_UMCCFG_GET_ECC_EN(val)) {
		chan->chan_flags |= UMC_CHAN_F_ECC_EN;
	}

	/*
	 * Grab the DRAM configuration register. This can be used to determine
	 * the frequency and speed of the memory channel. At this time we only
	 * capture Memory P-state 0.
	 */
	reg = UMC_DRAMCFG(id, 0);

	/*
	 * This register contains information to determine the type of DIMM.
	 * All DIMMs in the channel must be the same type so we leave this
	 * setting on the channel. Once we have that, we proceed to obtain the
	 * currently configuration information for the DRAM in each memory
	 * P-state.
	 */
	zen_umc_fill_ddr_type(umc, chan);
	for (uint_t i = 0; i < ZEN_UMC_NMEM_PSTATES; i++) {
		chan->chan_clock[i] = ZEN_UMC_UNKNOWN_FREQ;
		chan->chan_speed[i] = ZEN_UMC_UNKNOWN_FREQ;

		reg = UMC_DRAMCFG(id, i);
		if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "failed to read DRAM "
			    "Configuration register P-state %u %x: %d", i,
			    SMN_REG_ADDR(reg), ret);
			return (B_FALSE);
		}
		chan->chan_dramcfg_raw[i] = val;

		zen_umc_fill_chan_freq(umc, chan, i);
	}

	/*
	 * Grab data that we can use to determine if we're scrambling or
	 * encrypting regions of memory.
	 */
	reg = UMC_DATACTL(id);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read data control "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	chan->chan_datactl_raw = val;
	if (UMC_DATACTL_GET_SCRAM_EN(val)) {
		chan->chan_flags |= UMC_CHAN_F_SCRAMBLE_EN;
	}

	if (UMC_DATACTL_GET_ENCR_EN(val)) {
		chan->chan_flags |= UMC_CHAN_F_ENCR_EN;
	}

	/*
	 * At the moment we snapshot the raw ECC control information. When we do
	 * further work of making this a part of the MCA/X decoding, we'll want
	 * to further take this apart for syndrome decoding. Until then, simply
	 * cache it for future us and observability.
	 */
	reg = UMC_ECCCTL(id);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read ECC control "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	chan->chan_eccctl_raw = val;

	/*
	 * Read and snapshot the UMC capability registers for debugging in the
	 * future.
	 */
	reg = UMC_UMCCAP(id);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read UMC cap"
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	chan->chan_umccap_raw = val;

	reg = UMC_UMCCAP_HI(id);
	if ((ret = amdzen_c_smn_read(df->zud_dfno, reg, &val)) != 0) {
		dev_err(umc->umc_dip, CE_WARN, "failed to read UMC cap high "
		    "register %x: %d", SMN_REG_ADDR(reg), ret);
		return (B_FALSE);
	}
	chan->chan_umccap_hi_raw = val;

	return (B_TRUE);
}

static int
zen_umc_fill_umc_cb(const uint_t dfno, const uint32_t fabid,
    const uint32_t instid, void *arg)
{
	zen_umc_t *umc = arg;
	zen_umc_df_t *df = &umc->umc_dfs[dfno];
	zen_umc_chan_t *chan = &df->zud_chan[df->zud_nchan];

	df->zud_nchan++;
	VERIFY3U(df->zud_nchan, <=, ZEN_UMC_MAX_UMCS);

	/*
	 * The data fabric is generally organized such that all UMC entries
	 * should be continuous in their fabric ID space; however, we don't
	 * want to rely on specific ID locations. The UMC SMN addresses are
	 * organized in a relative order. To determine the SMN ID to use (the
	 * chan_logid) we end up making the following assumptions:
	 *
	 *  o The iteration order will always be from the lowest component ID
	 *    to the highest component ID.
	 *  o The relative order that we encounter will be the same as the SMN
	 *    order. That is, the first thing we find (regardless of component
	 *    ID) will be SMN UMC entry 0, the next 1, etc.
	 */
	chan->chan_logid = df->zud_nchan - 1;
	chan->chan_fabid = fabid;
	chan->chan_instid = instid;
	chan->chan_nrules = umc->umc_fdata->zufd_cs_nrules;
	for (uint_t i = 0; i < umc->umc_fdata->zufd_cs_nrules; i++) {
		if (zen_umc_read_dram_rule(umc, dfno, instid, i,
		    &chan->chan_rules[i]) != 0) {
			return (-1);
		}
	}

	for (uint_t i = 0; i < umc->umc_fdata->zufd_cs_nrules - 1; i++) {
		int ret;
		uint32_t offset;
		uint64_t t;
		df_reg_def_t off_reg;
		chan_offset_t *offp = &chan->chan_offsets[i];

		switch (umc->umc_df_rev) {
		case DF_REV_2:
		case DF_REV_3:
		case DF_REV_3P5:
			ASSERT3U(i, ==, 0);
			off_reg = DF_DRAM_OFFSET_V2;
			break;
		case DF_REV_4:
			off_reg = DF_DRAM_OFFSET_V4(i);
			break;
		default:
			dev_err(umc->umc_dip, CE_WARN, "!encountered "
			    "unsupported DF revision processing DRAM Offsets: "
			    "0x%x", umc->umc_df_rev);
			return (-1);
		}

		if ((ret = amdzen_c_df_read32(dfno, instid, off_reg,
		    &offset)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "!failed to read DRAM "
			    "offset %u on 0x%x/0x%x: %d", i, dfno, instid, ret);
			return (-1);
		}

		offp->cho_raw = offset;
		offp->cho_valid = DF_DRAM_OFFSET_GET_EN(offset);

		switch (umc->umc_df_rev) {
		case DF_REV_2:
			t = DF_DRAM_OFFSET_V2_GET_OFFSET(offset);
			break;
		case DF_REV_3:
		case DF_REV_3P5:
			t = DF_DRAM_OFFSET_V3_GET_OFFSET(offset);
			break;
		case DF_REV_4:
			t = DF_DRAM_OFFSET_V4_GET_OFFSET(offset);
			break;
		default:
			dev_err(umc->umc_dip, CE_WARN, "!encountered "
			    "unsupported DF revision processing DRAM Offsets: "
			    "0x%x", umc->umc_df_rev);
			return (-1);
		}
		offp->cho_offset = t << DF_DRAM_OFFSET_SHIFT;
	}

	/*
	 * If this platform supports our favorete Zen 3 6-channel hash special
	 * then we need to grab the NP2 configuration registers. This will only
	 * be referenced if this channel is actually being used for a 6-channel
	 * hash, so even if the contents are weird that should still be ok.
	 */
	if ((umc->umc_fdata->zufd_flags & ZEN_UMC_FAM_F_NP2) != 0) {
		uint32_t np2;
		int ret;

		if ((ret = amdzen_c_df_read32(dfno, instid, DF_NP2_CONFIG_V3,
		    &np2)) != 0) {
			dev_err(umc->umc_dip, CE_WARN, "!failed to read NP2 "
			    "config: %d", ret);
			return (-1);
		}

		chan->chan_np2_raw = np2;
		chan->chan_np2_space0 = DF_NP2_CONFIG_V3_GET_SPACE0(np2);
	}

	/*
	 * Now that we have everything we need from the data fabric, read out
	 * the rest of what we need from the UMC channel data in SMN register
	 * space.
	 */
	switch (umc->umc_fdata->zufd_umc_style) {
	case ZEN_UMC_UMC_S_DDR4:
	case ZEN_UMC_UMC_S_DDR4_APU:
		for (uint_t i = 0; i < ZEN_UMC_MAX_DIMMS; i++) {
			if (!zen_umc_fill_chan_dimm_ddr4(umc, df, chan, i)) {
				return (-1);
			}
		}
		break;
	case ZEN_UMC_UMC_S_HYBRID_LPDDR5:
	case ZEN_UMC_UMC_S_DDR5:
	case ZEN_UMC_UMC_S_DDR5_APU:
		for (uint_t i = 0; i < ZEN_UMC_MAX_DIMMS; i++) {
			for (uint_t r = 0; r < ZEN_UMC_MAX_CS_PER_DIMM; r++) {
				if (!zen_umc_fill_chan_rank_ddr5(umc, df, chan,
				    i, r)) {
					return (-1);
				}
			}
		}
		break;
	default:
		dev_err(umc->umc_dip, CE_WARN, "!encountered unsupported "
		    "Zen family: 0x%x", umc->umc_fdata->zufd_umc_style);
		return (-1);
	}

	if (!zen_umc_fill_chan(umc, df, chan)) {
		return (-1);
	}

	return (0);
}

/*
 * Today there are no privileges for the memory controller information, it is
 * restricted based on file system permissions.
 */
static int
zen_umc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	zen_umc_t *umc = zen_umc;

	if ((flag & (FEXCL | FNDELAY | FNONBLOCK | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otyp != OTYP_CHR) {
		return (EINVAL);
	}

	if (getminor(*devp) >= umc->umc_ndfs) {
		return (ENXIO);
	}

	return (0);
}

static void
zen_umc_ioctl_decode(zen_umc_t *umc, mc_encode_ioc_t *encode)
{
	zen_umc_decoder_t dec;
	uint32_t sock, die, comp;

	bzero(&dec, sizeof (dec));
	if (!zen_umc_decode_pa(umc, encode->mcei_pa, &dec)) {
		encode->mcei_err = (uint32_t)dec.dec_fail;
		encode->mcei_errdata = dec.dec_fail_data;
		return;
	}

	encode->mcei_errdata = 0;
	encode->mcei_err = 0;
	encode->mcei_chan_addr = dec.dec_norm_addr;
	encode->mcei_rank_addr = UINT64_MAX;
	encode->mcei_board = 0;
	zen_fabric_id_decompose(&umc->umc_decomp, dec.dec_targ_fabid, &sock,
	    &die, &comp);
	encode->mcei_chip = sock;
	encode->mcei_die = die;
	encode->mcei_mc = dec.dec_umc_chan->chan_logid;
	encode->mcei_chan = 0;
	encode->mcei_dimm = dec.dec_dimm_no;
	encode->mcei_row = dec.dec_dimm_row;
	encode->mcei_column = dec.dec_dimm_col;
	/*
	 * We don't have a logical rank that something matches to, we have the
	 * actual chip-select and rank multiplication. If we could figure out
	 * how to transform that into an actual rank, that'd be grand.
	 */
	encode->mcei_rank = UINT8_MAX;
	encode->mcei_cs = dec.dec_dimm_csno;
	encode->mcei_rm = dec.dec_dimm_rm;
	encode->mcei_bank = dec.dec_dimm_bank;
	encode->mcei_bank_group = dec.dec_dimm_bank_group;
	encode->mcei_subchan = dec.dec_dimm_subchan;
}

static void
umc_decoder_pack(zen_umc_t *umc)
{
	char *buf = NULL;
	size_t len = 0;

	ASSERT(MUTEX_HELD(&umc->umc_nvl_lock));
	if (umc->umc_decoder_buf != NULL) {
		return;
	}

	if (umc->umc_decoder_nvl == NULL) {
		umc->umc_decoder_nvl = zen_umc_dump_decoder(umc);
		if (umc->umc_decoder_nvl == NULL) {
			return;
		}
	}

	if (nvlist_pack(umc->umc_decoder_nvl, &buf, &len, NV_ENCODE_XDR,
	    KM_NOSLEEP_LAZY) != 0) {
		return;
	}

	umc->umc_decoder_buf = buf;
	umc->umc_decoder_len = len;
}

static int
zen_umc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	int ret;
	zen_umc_t *umc = zen_umc;
	mc_encode_ioc_t encode;
	mc_snapshot_info_t info;

	if (getminor(dev) >= umc->umc_ndfs) {
		return (ENXIO);
	}

	switch (cmd) {
	case MC_IOC_DECODE_PA:
		if (crgetzoneid(credp) != GLOBAL_ZONEID ||
		    drv_priv(credp) != 0) {
			ret = EPERM;
			break;
		}

		if (ddi_copyin((void *)arg, &encode, sizeof (encode),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
			break;
		}

		zen_umc_ioctl_decode(umc, &encode);
		ret = 0;

		if (ddi_copyout(&encode, (void *)arg, sizeof (encode),
		    mode & FKIOCTL) != 0) {
			ret = EFAULT;
			break;
		}
		break;
	case MC_IOC_DECODE_SNAPSHOT_INFO:
		mutex_enter(&umc->umc_nvl_lock);
		umc_decoder_pack(umc);

		if (umc->umc_decoder_buf == NULL) {
			mutex_exit(&umc->umc_nvl_lock);
			ret = EIO;
			break;
		}

		if (umc->umc_decoder_len > UINT32_MAX) {
			mutex_exit(&umc->umc_nvl_lock);
			ret = EOVERFLOW;
			break;
		}

		info.mcs_size = umc->umc_decoder_len;
		info.mcs_gen = 0;
		if (ddi_copyout(&info, (void *)arg, sizeof (info),
		    mode & FKIOCTL) != 0) {
			mutex_exit(&umc->umc_nvl_lock);
			ret = EFAULT;
			break;
		}

		mutex_exit(&umc->umc_nvl_lock);
		ret = 0;
		break;
	case MC_IOC_DECODE_SNAPSHOT:
		mutex_enter(&umc->umc_nvl_lock);
		umc_decoder_pack(umc);

		if (umc->umc_decoder_buf == NULL) {
			mutex_exit(&umc->umc_nvl_lock);
			ret = EIO;
			break;
		}

		if (ddi_copyout(umc->umc_decoder_buf, (void *)arg,
		    umc->umc_decoder_len, mode & FKIOCTL) != 0) {
			mutex_exit(&umc->umc_nvl_lock);
			ret = EFAULT;
			break;
		}

		mutex_exit(&umc->umc_nvl_lock);
		ret = 0;
		break;
	default:
		ret = ENOTTY;
		break;
	}

	return (ret);
}

static int
zen_umc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

static void
zen_umc_cleanup(zen_umc_t *umc)
{
	nvlist_free(umc->umc_decoder_nvl);
	umc->umc_decoder_nvl = NULL;
	if (umc->umc_decoder_buf != NULL) {
		kmem_free(umc->umc_decoder_buf, umc->umc_decoder_len);
		umc->umc_decoder_buf = NULL;
		umc->umc_decoder_len = 0;
	}

	if (umc->umc_dip != NULL) {
		ddi_remove_minor_node(umc->umc_dip, NULL);
	}
	mutex_destroy(&umc->umc_nvl_lock);
	kmem_free(umc, sizeof (zen_umc_t));
}

static int
zen_umc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	int ret;
	zen_umc_t *umc;

	if (cmd == DDI_RESUME) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_ATTACH) {
		return (DDI_FAILURE);
	}
	if (zen_umc != NULL) {
		dev_err(dip, CE_WARN, "!zen_umc is already attached to a "
		    "dev_info_t: %p", zen_umc->umc_dip);
		return (DDI_FAILURE);
	}

	/*
	 * To get us going, we need to do several bits of set up. First, we need
	 * to use the knowledge about the actual hardware that we're using to
	 * encode a bunch of different data:
	 *
	 *  o The set of register styles and extra hardware features that exist
	 *    on the hardware platform.
	 *  o The number of actual rules there are for the CCMs and UMCs.
	 *  o How many actual things exist (DFs, etc.)
	 *  o Useful fabric and instance IDs for all of the different UMC
	 *    entries so we can actually talk to them.
	 *
	 * Only once we have all the above will we go dig into the actual data.
	 */
	umc = kmem_zalloc(sizeof (zen_umc_t), KM_SLEEP);
	mutex_init(&umc->umc_nvl_lock, NULL, MUTEX_DRIVER, NULL);
	umc->umc_family = chiprev_family(cpuid_getchiprev(CPU));
	umc->umc_ndfs = amdzen_c_df_count();
	umc->umc_dip = dip;

	if (!zen_umc_identify(umc)) {
		dev_err(dip, CE_WARN, "!encountered unsupported CPU");
		goto err;
	}

	umc->umc_df_rev = amdzen_c_df_rev();
	switch (umc->umc_df_rev) {
	case DF_REV_2:
	case DF_REV_3:
	case DF_REV_3P5:
	case DF_REV_4:
		break;
	default:
		dev_err(dip, CE_WARN, "!encountered unknown DF revision: %x",
		    umc->umc_df_rev);
		goto err;
	}

	if ((ret = amdzen_c_df_fabric_decomp(&umc->umc_decomp)) != 0) {
		dev_err(dip, CE_WARN, "!failed to get fabric decomposition: %d",
		    ret);
	}

	umc->umc_tom = rdmsr(MSR_AMD_TOM);
	umc->umc_tom2 = rdmsr(MSR_AMD_TOM2);

	/*
	 * For each DF, start by reading all of the data that we need from it.
	 * This involves finding a target CCM, reading all of the rules,
	 * ancillary settings, and related. Then we'll do a pass over all of the
	 * actual UMC targets there.
	 */
	for (uint_t i = 0; i < umc->umc_ndfs; i++) {
		if (amdzen_c_df_iter(i, ZEN_DF_TYPE_CCM_CPU,
		    zen_umc_fill_ccm_cb, umc) < 0 ||
		    amdzen_c_df_iter(i, ZEN_DF_TYPE_CS_UMC, zen_umc_fill_umc_cb,
		    umc) != 0) {
			goto err;
		}
	}

	/*
	 * Create a minor node for each df that we encounter.
	 */
	for (uint_t i = 0; i < umc->umc_ndfs; i++) {
		int ret;
		char minor[64];

		(void) snprintf(minor, sizeof (minor), "mc-umc-%u", i);
		if ((ret = ddi_create_minor_node(umc->umc_dip, minor, S_IFCHR,
		    i, "ddi_mem_ctrl", 0)) != 0) {
			dev_err(dip, CE_WARN, "!failed to create minor %s: %d",
			    minor, ret);
			goto err;
		}
	}

	zen_umc = umc;
	return (DDI_SUCCESS);

err:
	zen_umc_cleanup(umc);
	return (DDI_FAILURE);
}

static int
zen_umc_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **resultp)
{
	zen_umc_t *umc;

	if (zen_umc == NULL || zen_umc->umc_dip == NULL) {
		return (DDI_FAILURE);
	}
	umc = zen_umc;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		*resultp = (void *)umc->umc_dip;
		break;
	case DDI_INFO_DEVT2INSTANCE:
		*resultp = (void *)(uintptr_t)ddi_get_instance(
		    umc->umc_dip);
		break;
	default:
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
zen_umc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	zen_umc_t *umc;

	if (cmd == DDI_SUSPEND) {
		return (DDI_SUCCESS);
	} else if (cmd != DDI_DETACH) {
		return (DDI_FAILURE);
	}

	if (zen_umc == NULL) {
		dev_err(dip, CE_WARN, "!asked to detach zen_umc, but it "
		    "was never successfully attached");
		return (DDI_FAILURE);
	}

	umc = zen_umc;
	zen_umc = NULL;
	zen_umc_cleanup(umc);
	return (DDI_SUCCESS);
}

static struct cb_ops zen_umc_cb_ops = {
	.cb_open = zen_umc_open,
	.cb_close = zen_umc_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = zen_umc_ioctl,
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

static struct dev_ops zen_umc_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = zen_umc_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = zen_umc_attach,
	.devo_detach = zen_umc_detach,
	.devo_reset = nodev,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &zen_umc_cb_ops
};

static struct modldrv zen_umc_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD Zen Unified Memory Controller",
	.drv_dev_ops = &zen_umc_dev_ops
};

static struct modlinkage zen_umc_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &zen_umc_modldrv, NULL }
};

int
_init(void)
{
	return (mod_install(&zen_umc_modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&zen_umc_modlinkage, modinfop));
}

int
_fini(void)
{
	return (mod_remove(&zen_umc_modlinkage));
}
