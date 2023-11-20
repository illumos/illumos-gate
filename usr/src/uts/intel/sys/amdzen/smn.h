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
 * Copyright 2023 Oxide Computer Co.
 */

#ifndef _SYS_AMDZEN_SMN_H
#define	_SYS_AMDZEN_SMN_H

#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

/*
 * Generic definitions for the system management network (SMN) in Milan and many
 * other AMD Zen processors.  These are shared between the amdzen nexus and its
 * client drivers and kernel code that may require SMN access to resources.
 *
 * ------------------------
 * Endpoints and Addressing
 * ------------------------
 *
 * SMN addresses are 36 bits long but in practice we can use only 32.  Bits
 * [35:32] identify a destination node, but all consumers instead direct SMN
 * transactions to a specific node by selecting the address/data register pair
 * in the NBIO PCI config space corresponding to the destination.  Additional
 * information about nodes and the organisation of devices in the Zen
 * architecture may be found in the block comments in amdzen.c and cpuid.c.
 *
 * The SMN provides access to instances of various functional units present on
 * or accessed via each node.  Some functional units have only a single instance
 * per node while others may have many.  Each functional unit instance has one
 * or more apertures in which it decodes addresses.  The aperture portion of the
 * address consists of bits [31:20] and the remainder of the address is used to
 * specify a register instance within that functional unit.  To complicate
 * matters, some functional units have multiple smaller sub-units that decode
 * smaller regions within its parent's aperture; in some cases, the bits in a
 * mask describing the sub-unit's registers may not be contiguous.  To keep
 * software relatively simple, we generally treat sub-units and parent units the
 * same and try to choose collections of registers whose addresses can all be
 * computed in the same manner to form what we will describe as a unit.
 *
 * Each functional unit should typically have its own header containing register
 * definitions, accessors, and address calculation routines; some functional
 * units are small and straightforward while others may have numerous complex
 * sub-units, registers with many instances whose locations are computed in
 * unusual and nonstandard ways, and other features that need to be declared for
 * consumers.  Those functional units that are present across many processors
 * and have similar or identical contents across them should live in this
 * directory; umc.h is such an example.  Others may be specific to a particular
 * processor family (see cpuid.c) or other collection and may require their own
 * subdirectories, symbol prefixes, and so on.  Unlike the DF, the existence,
 * location, and format of registers accessible over SMN are not versioned nor
 * are they generally self-discoverable.  Each functional unit may be present or
 * absent, in varying numbers and with varying functionality, across the entire
 * Zen product range.  Therefore, at this time most per-unit headers are
 * intended for use only by code that will execute on a specific processor
 * family.  Unifying them over time is considered desirable to the extent the
 * hardware allows it.
 *
 * -----
 * Types
 * -----
 *
 * Practically every last one of us has screwed up the order of arguments to
 * functions like amdzen_smn_write32() when they take an address and a value of
 * the same type.  Repeatedly.  Often.  To safety this particularly annoying
 * footgun, we pass SMN register addresses around in a dedicated struct type
 * smn_reg_t, intended to be instantiated only by the amdzen_xx_smn_reg() and
 * analogous kernel functions and the macros that expand to them or, for the
 * YOLO crew, SMN_MAKE_REG().  Since the struct type and uint32_t are not
 * compatible, the compiler will always squawk if the register and value
 * arguments are reversed, leaving us far fewer baffling failures to debug at
 * runtime.  Typical callers don't require any awareness of this at all, but
 * those that want to pass the address around to e.g. log warnings can obtain
 * the uint32_t address via SMN_REG_ADDR().
 *
 * Register definitions within functional units are provided by objects of type
 * `const smn_reg_def_t`, the usage of which is described in detail in the next
 * section.  For now these are produced on demand by macros; see additional
 * notes on conventions below.  In time, this mechanism may be extended to
 * incorporate version information in a manner similar to that used in df.h.  An
 * automated mechanism for creating a single collection of register and field
 * definitions for C, in CTF, and/or for other language consumers as well as
 * automated register value decoding remains an open area for future work.
 *
 * -----------------------
 * Instances and Iterators
 * -----------------------
 *
 * Not only do some functional units have many instances, so too do many
 * registers.  AMD documentation describes registers in terms of a series of
 * iterators over various functional units, subunits, and other entities and
 * attributes that each multiply the number of register instances.  A concrete
 * example from the publicly-available Naples PPR (publication 54945 rev. 1.14)
 * may make this simpler to understand.  Unfortunately, SMN is not described by
 * this document, but the register instance syntax used is the same and is
 * described in additional detail in sections 1.3.3-4.  For our example, let us
 * consider the same MSR that AMD uses in their own example,
 * Core::X86::MSR::TSC.  We are given that this register has the following
 * instances: lthree[1:0]_core[3:0]_thread[1:0].  We therefore have three
 * iterators: one for 'lthree's, one for 'core's for each 'lthree', and one for
 * 'thread's for each 'core'.  We can also see that there are 16 total
 * instances; in fact, there are actually 16 per core-complex die (CCD), which
 * documents for more recent processors would expose as a fourth iterator.  To
 * keep things relatively simple, we will assume that there are only 16 per
 * processor.  If it were possible to access all of these instances via MMIO,
 * SMN, or some other flat address space (it isn't, as far as we can tell), a
 * function for computing the address of each instance would require three
 * parameters.  Let us suppose that this register really were accessible via
 * SMN; in that case, we would also be provided with a list of instance alias
 * such as
 *
 *	_thread[1:0]_core[7:0]_lthree[1:0]_alias_SMN: THREADREGS[1:0]x0000_0010;
 *	THREADREGS[1:0]=COREREGS[7:0]x0000_[4,0]000;
 *	COREREGS[7:0]=L3REGS[1:0]x000[7:0]_5000; L3REGS[1:0]=57[A,6]0_0000
 *
 * To compute the address of an instance of this hypothetical register, we would
 * begin by determining that its top-level functional unit is L3REGS with a base
 * aperture at 0x5760_0000.  There are two instances of this functional unit (01
 * and 1) and each subsequent instance is offset 0x40_0000 from the previous.
 * This allows us to compute the base address of each L3REGS block; a similar
 * process is then used to compute the base address of each COREREGS block, and
 * finally the address of each THREADREGS block that contains the register
 * instance.  In practice, we might choose instead to consider the COREREGS as
 * our functional unit, with instances at 0x5760_5000, 0x5761_5000, 0x57A0_5000,
 * and 0x57A1_5000; whether it is useful to do this depends on whether we need
 * to consider other registers in the L3REGS unit that may not have per-core
 * blocks or instances but would otherwise be interleaved with these.  This ends
 * up being something of a judgment call.  Let's suppose we want to consider the
 * entire L3REGS functional unit and write a function to compute the address of
 * any register (including our hypothetical TSC) in the subordinate THREADREGS
 * blocks.  We'll start by adding the new unit to the smn_unit_t enumeration;
 * let's call it SMN_UNIT_L3REGS_COREREGS since that's the sub-unit level at
 * which we can uniformly compute register instance addresses.  We have already
 * determined our base aperture and we know that we have 3 iterators and
 * therefore three parameters; all SMN address calculators return an smn_reg_t
 * and must accept an smn_reg_def_t.  Therefore our function's signature is:
 *
 * smn_reg_t amdzen_smn_l3regs_coreregs_reg(uint8_t l3no,
 *     const smn_reg_def_t def, uint16_t coreinst, uint16_t threadinst);
 *
 * We have chosen to use a base aperture of 0x5760_0000 and unit offset
 * 0x40_0000, so we can begin by computing a COREREGS aperture:
 *
 * const uint32_t aperture_base = 0x57600000;
 * const uint32_t aperture_off = l3no * 0x400000;
 * const uint32_t coreregs_aperture_base = 0x5000;
 * const uint32_t coreregs_aperture_off = coreinst * 0x10000;
 *
 * We can now consider the smn_reg_def_t our function will be given, which
 * describes THREADREGS::TSC.  Within the COREREGS functional sub-unit, each
 * thread register has 2 instances present at a stride of 0x4000 bytes (from our
 * hypothetical register definition), so the register would be defined as
 * follows:
 *
 * #define	D_L3REGS_COREREGS_THREAD_TSC	(const smn_reg_def_t){	\
 *	.srd_unit = SMN_UNIT_L3REGS_COREREGS,	\
 *	.srd_reg = 0x10,	\
 *	.srd_nents = 2,	\
 *	.srd_stride = 0x4000	\
 * }
 *
 * Note that describing the number of entries and their stride in the register
 * definition allows us to collapse the last functional sub-unit in our
 * calculation process: we need not compute the base aperture address of the
 * THREADREGS sub-unit.  Instead, we can follow our previous code with:
 *
 * const uint32_t aperture = aperture_base +
 *     coreregs_aperture_base + coreregs_aperture_off;
 * const uint32_t reg = def.srd_reg + threadinst * def.srd_stride;
 *
 * Finally, we convert the aperture address and register offset into the
 * appropriate type and return it:
 *
 * return (SMN_MAKE_REG(aperture + reg));
 *
 * As you can see, other registers in THREADREGS would be defined with the same
 * number entries and stride but a different offset (srd_reg member), while
 * other registers in the COREREGS block would have a different offset and
 * stride.  For example, if a block of per-core (not per-thread) registers were
 * located at COREREGS[7:0]x0000_1000, a register called "COREREGS::FrobberCntl"
 * in that block with a single instance at offset 0x48 might be defined as
 *
 * #define	D_L3REGS_COREREGS_FROB_CTL	(const smn_reg_def_t){	\
 *	.srd_unit = SMN_UNIT_L3REGS_COREREGS,	\
 *	.srd_reg = 0x1048,	\
 *	.srd_nents = 1	\
 * }
 *
 * You can satisfy yourself that the same calculation function we wrote above
 * will correctly compute the address of the sole instance (0) of this register.
 * To further simplify register definitions and callers, the actual address
 * calculation functions are written to treat srd_nents == 0 to mean a register
 * with a single instance, and to treat srd_stride == 0 as if it were 4 (the
 * space occupied by registers accessed by SMN is -- so far as we can tell,
 * practically always -- 4 bytes in size, even if the register itself is
 * smaller).  Additionally, a large number of assertions should be present in
 * such functions to guard against foreign unit register definitions,
 * out-of-bounds unit and register instance parameters, address overflow, and
 * register instance offsets that overflow improperly into an aperture base
 * address.  All of these conditions indicate either an incorrect register
 * definition or a bug in the caller.  See the template macro at the bottom of
 * this file and umc.h for additional examples of calculating and checking
 * register addresses.
 *
 * With address computation out of the way, we can then provide an accessor for
 * each instance this register:
 *
 * #define	L3REGS_COREREGS_THREAD_TSC(l3, core, thread)	\
 *	amdzen_l3regs_coreregs_reg(l3, D_L3REGS_COREREGS_THREAD_TSC, \
 *	core, thread)
 *
 * Our other per-core register's accessor would look like:
 *
 * #define	L3REGS_COREREGS_FROB_CTL(l3, core)	\
 *	amdzen_l3regs_coreregs_reg(l3, D_L3REGS_COREREGS_FROB_CTL, core, 0)
 *
 * The next section describes these conventions in greater detail.
 *
 * -----------
 * Conventions
 * -----------
 *
 * First, let's consider the names of the register definition and the
 * convenience macro supplied to obtain an instance of that register: we've
 * prefixed the global definition of the registers with D_ and the convenience
 * macros to return a specific instance are simply named for the register
 * itself.  Additionally, the two macros expand to objects of incompatible
 * types, so that using the wrong one will always be detected at compile time.
 * Why do we expose both of these?  The instance macro is useful for callers who
 * know at compile-time the name of the register of which they want instances;
 * this makes it unnecessary to remember the names of functions used to compute
 * register instance addresses.  The definition itself is useful to callers that
 * accept const smn_reg_def_t arguments referring to registers of which the
 * immediate caller does not know the names at compile time.
 *
 * You may wonder why we don't declare named constants for the definitions.
 * There are two ways we could do that and both are unfortunate: one would be to
 * declare them static in the header, the other to separate declarations in the
 * header from initialisation in a separate source file.  Measurements revealed
 * that the former causes a very substantial increase in data size, which will
 * be multiplied by the number of registers defined and the number of source
 * files including the header.  As convenient as it is to have these symbolic
 * constants available to debuggers and other tools at runtime, they're just too
 * big.  However, it is possible to generate code to be compiled into loadable
 * modules that would contain a single copy of the constants for this purpose as
 * well as for providing CTF to foreign-language binding generators.  The other
 * option considered here, putting the constants in separate source files, makes
 * maintenance significantly more challenging and makes it likely not only that
 * new registers may not be added properly but also that definitions, macros, or
 * both may be incorrect.  Neither of these options is terrible but for now
 * we've optimised for simplicity of maintenance and minimal data size at the
 * immediate but not necessarily permanent expense of some debugging
 * convenience.
 *
 * We wish to standardise as much as possible on conventions across all
 * Zen-related functional units and blocks (including those accessed by SMN,
 * through the DF directly, and by other means).  In general, some register and
 * field names are shortened from their official names for clarity and brevity;
 * the official names are always given in the comment above the definition.
 * AMD's functional units come from many internal teams and presumably several
 * outside vendors as well; as a result, there is no single convention to be
 * found throughout the PPRs and other documentation.  For example, different
 * units may have registers containing "CTL", "CNTL", "CTRL", "CNTRL", and
 * "CONTROL", as well as "FOO_CNTL", "FooCntl", and "Foo_Cntl".  Reflecting
 * longstanding illumos conventions, we collapse all such register names
 * regardless of case as follows:
 *
 * CTL/CTRL/CNTL/CNTRL/CONTROL				=> CTL
 * CFG/CONF/CONFIG/CONFIGURATION			=> CFG
 * EN/ENAB/ENABLE/ENABLED				=> EN
 * DIS/DISAB/DISABLE/DISABLED				=> DIS
 *
 * Note that if collapsing these would result in ambiguity, more of the official
 * names will be preserved.  In addition to collapsing register and field names
 * in this case-insensitive manner, we also follow standard code style practice
 * and name macros and constants in SCREAMING_SNAKE_CASE regardless of AMD's
 * official name.  It is similarly reasonable to truncate or abbreviate other
 * common terms in a consistent manner where doing so preserves uniqueness and
 * at least some semantic value; without doing so, some official register names
 * will be excessively unwieldy and may not even fit into 80 columns.  Please
 * maintain these practices and strive for consistency with existing examples
 * when abbreviation is required.
 *
 * As we have done elsewhere throughout the amdzen body of work, register fields
 * should always be given in order starting with the most significant bits and
 * working down toward 0; this matches AMD's documentation and makes it easier
 * for reviewers and other readers to follow.  The routines in bitext.h should
 * be used to extract and set bitfields unless there is a compelling reason to
 * do otherwise (e.g., assembly consumers).  Accessors should be named
 * UNIT_REG_GET_FIELD and UNIT_REG_SET_FIELD respectively, unless the register
 * has a single field that has no meaningful name (i.e., the field's name is the
 * same as the register's or it's otherwise obvious from the context what its
 * purpose is), in which case UNIT_REG_GET and UNIT_REG_SET are appropriate.
 * Additional getters and setters that select a particular bit from a register
 * or field consisting entirely of individual bits describing or controlling the
 * state of some entity may also be useful.  As with register names, be as brief
 * as possible without sacrificing too much information.
 *
 * Constant values associated with a field should be declared immediately
 * following that field.  If a constant or collection of constants is used in
 * multiple fields of the same register, the definitions should follow the last
 * such field; similarly, constants used in multiple registers should follow the
 * last such register, and a comment explaining the scope of their validity is
 * recommended.  Such constants should be named for the common elements of the
 * fields or registers in which they are valid.
 *
 * As noted above, SMN register definitions should omit the srd_nents and
 * srd_stride members when there is a single instance of the register within the
 * unit.  The srd_stride member should also be elided when the register
 * instances are contiguous.  All address calculation routines should be written
 * to support these conventions.  Each register should have an accessor macro or
 * function, and should accept instance numbers in order from superior to
 * inferior (e.g., from the largest functional unit to the smallest, ending with
 * the register instance itself).  This convention is similar to that used in
 * generic PCIe code in which a register is specified by bus, device, and
 * function numbers in that order.  Register accessor macros or inline functions
 * should not expose inapplicable taxons to callers; in our example above,
 * COREREGS_FROB_CTL has an instance for each core but is not associated with a
 * thread; therefore its accessor should not accept a thread instance argument
 * even though the address calculation function it uses does.
 *
 * Most of these conventions are not specific to registers accessed via SMN;
 * note also that some registers may be accessed in multiple ways (e.g., SMN and
 * MMIO, or SMN and the MSR instructions).  While the code here is generally
 * unaware of such aliased access methods, following these conventions will
 * simplify naming and usage if such a register needs to be accessed in multiple
 * ways.  Sensible additions to macro and symbol names such as the access method
 * to be used will generally be sufficient to disambiguate while allowing reuse
 * of associated field accessors, constants, and in some cases even register
 * offset, instance count, and stride.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	SMN_APERTURE_MASK	0xfff00000

/*
 * An instance of an SMN-accessible register.
 */
typedef struct smn_reg {
	uint32_t sr_addr;
	uint8_t sr_size;	/* Not size_t: can't ever be that big. */
} smn_reg_t;

/*
 * These are intended to be macro-like (and indeed some used to be macros) but
 * are implemented as inline functions so that we can use compound statements
 * without extensions and don't have to worry about multiple evaluation.  Hence
 * their capitalised names.
 */
static inline smn_reg_t
SMN_MAKE_REG_SIZED(const uint32_t addr, const uint8_t size)
{
	const uint8_t size_always = (size == 0) ? 4 : size;
	const smn_reg_t rv = {
	    .sr_addr = addr,
	    .sr_size = size_always
	};

	return (rv);
}

#define	SMN_MAKE_REG(x)		SMN_MAKE_REG_SIZED(x, 4)
#define	SMN_REG_ADDR(x)		((x).sr_addr)
#define	SMN_REG_SIZE(x)		((x).sr_size)

static inline boolean_t
SMN_REG_SIZE_IS_VALID(const smn_reg_t reg)
{
	return (reg.sr_size == 1 || reg.sr_size == 2 || reg.sr_size == 4);
}

/* Is this register suitably aligned for access of <size> bytes? */
#define	SMN_REG_IS_ALIGNED(x, size)	IS_P2ALIGNED(SMN_REG_ADDR(x), size)

/* Is this register naturally aligned with respect to its own width? */
static inline boolean_t
SMN_REG_IS_NATURALLY_ALIGNED(const smn_reg_t reg)
{
	return (SMN_REG_IS_ALIGNED(reg, reg.sr_size));
}

/* Does <val> fit into SMN register <x>? */
#define	SMN_REG_VALUE_FITS(x, val)	\
	(((val) & ~(0xffffffffU >> ((4 - SMN_REG_SIZE(x)) << 3))) == 0)

/*
 * Retrieve the base address of the register.  This is the address that will
 * actually be set in the index register when performing a read or write of the
 * underlying register via SMN.  It must always be 32-bit aligned.
 */
static inline uint32_t
SMN_REG_ADDR_BASE(const smn_reg_t reg)
{
	return (reg.sr_addr & ~3);
}

/*
 * The offset address is the byte offset into the 32-bit-wide data register that
 * will be returned by a read or set by a write, if the register is smaller than
 * 32 bits wide.  For registers that are 32 bits wide, this is always 0.
 */
static inline uint32_t
SMN_REG_ADDR_OFF(const smn_reg_t reg)
{
	return (reg.sr_addr & 3);
}

/*
 * This exists so that address calculation functions can check that the register
 * definitions they're passed are something they understand how to use.  While
 * many address calculation functions are similar, some functional units define
 * registers with multiple iterators, have differently-sized apertures, or both;
 * it's important that we reject foreign register definitions in these
 * functions.  In principle this could be done at compile time, but the
 * preprocessor gymnastics required to do so are excessively vile and we are
 * really already hanging it pretty far over the edge in terms of what the C
 * preprocessor can do for us.
 */
typedef enum smn_unit {
	SMN_UNIT_UNKNOWN,
	SMN_UNIT_IOAPIC,
	SMN_UNIT_IOHC,
	SMN_UNIT_IOHCDEV_PCIE,
	SMN_UNIT_IOHCDEV_NBIF,
	SMN_UNIT_IOHCDEV_SB,
	SMN_UNIT_IOAGR,
	SMN_UNIT_SDPMUX,
	SMN_UNIT_UMC,
	SMN_UNIT_PCIE_CORE,
	SMN_UNIT_PCIE_PORT,
	SMN_UNIT_PCIE_RSMU,
	SMN_UNIT_SCFCTP,
	SMN_UNIT_SMUPWR,
	SMN_UNIT_IOMMUL1,
	SMN_UNIT_IOMMUL2,
	SMN_UNIT_NBIF,
	SMN_UNIT_NBIF_ALT,
	SMN_UNIT_NBIF_FUNC
} smn_unit_t;

/*
 * srd_unit and srd_reg are required; they describe the functional unit and the
 * register's address within that unit's aperture (which may be the SDP-defined
 * aperture described above or a smaller one if a unit has been broken down
 * logically into smaller units).  srd_nents is optional; if not set, all
 * existing consumers assume a value of 0 is equivalent to 1: the register has
 * but a single instance in each unit.  srd_size is the width of the register in
 * bytes, which must be 0, 1, 2, or 4.  If 0, the size is assumed to be 4 bytes.
 * srd_stride is ignored if srd_nents is 0 or 1 and optional otherwise; it
 * describes the number of bytes to be added to the previous instance's address
 * to obtain that of the next instance.  If left at 0 it is assumed to be equal
 * to the width of the register.
 *
 * There are units in which registers have more complicated collections of
 * instances that cannot be represented perfectly by this simple descriptor;
 * they require custom address calculation macros and functions that may take
 * additional arguments, and they may not be able to check their arguments or
 * the computed addresses as carefully as would be ideal.
 */
typedef struct smn_reg_def {
	smn_unit_t	srd_unit;
	uint32_t	srd_reg;
	uint32_t	srd_stride;
	uint16_t	srd_nents;
	uint8_t		srd_size;
} smn_reg_def_t;

/*
 * This macro may be used by per-functional-unit code to construct an address
 * calculation function.  It is usable by some, BUT NOT ALL, functional units;
 * see the block comment above for an example that cannot be accommodated.  Here
 * we assume that there are at most 2 iterators in any register's definition.
 * Use this when possible, as it provides a large number of useful checks on
 * DEBUG bits.  Similar checks should be incorporated into implementations for
 * nonstandard functional units to the extent possible.
 */

#define	AMDZEN_MAKE_SMN_REG_FN(_fn, _unit, _base, _mask, _nunits, _unitshift) \
CTASSERT(((_base) & ~(_mask)) == 0);					\
static inline smn_reg_t							\
_fn(const uint8_t unitno, const smn_reg_def_t def, const uint16_t reginst) \
{									\
	const uint32_t unit32 = (const uint32_t)unitno;			\
	const uint32_t reginst32 = (const uint32_t)reginst;		\
	const uint32_t size32 = (def.srd_size == 0) ? 4 :		\
	    (const uint32_t)def.srd_size;				\
	ASSERT(size32 == 1 || size32 == 2 || size32 == 4);		\
	const uint32_t stride = (def.srd_stride == 0) ? size32 :	\
	    def.srd_stride;						\
	ASSERT3U(stride, >=, size32);					\
	const uint32_t nents = (def.srd_nents == 0) ? 1 :		\
	    (const uint32_t)def.srd_nents;				\
									\
	ASSERT3S(def.srd_unit, ==, SMN_UNIT_ ## _unit);			\
	ASSERT3U(unit32, <, (_nunits));					\
	ASSERT3U(nents, >, reginst32);					\
	ASSERT0(def.srd_reg & (_mask));					\
									\
	const uint32_t aperture_base = (_base);				\
									\
	const uint32_t aperture_off = (unit32 << (_unitshift));		\
	ASSERT3U(aperture_off, <=, UINT32_MAX - aperture_base);		\
									\
	const uint32_t aperture = aperture_base + aperture_off;		\
	ASSERT0(aperture & ~(_mask));					\
									\
	const uint32_t reg = def.srd_reg + reginst32 * stride;		\
	ASSERT0(reg & (_mask));						\
									\
	return (SMN_MAKE_REG_SIZED(aperture + reg, size32));		\
}

/*
 * An invalid SMN read will return all 1s similar to PCI.
 */
#define	SMN_EINVAL32	0xffffffff

#ifdef __cplusplus
}
#endif

#endif /* _SYS_AMDZEN_SMN_H */
