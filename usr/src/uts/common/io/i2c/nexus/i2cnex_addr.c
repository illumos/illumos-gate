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
 * This file contains all of the logic around how we look for overlapping
 * addresses. Addresses must uniquely identify a device on a given bus. The
 * logic in this file currently assumes each address type (e.g. 7-bit vs.
 * 10-bit) is a unique and non-overlapping space. That is the 7-bit and 10-bit
 * address 0x23 is different and cannot find one another. As with most things in
 * I2C this would be simple were it not for the case of multiplexers.
 *
 * As the kernel only allows a single segment on a mux to be active at any given
 * time, addresses below a mux are allowed to be duplicated as both cannot be
 * addressed. However addresses on different segments gets tricky fast. Consider
 * the following different bus topologies:
 *
 * -------------
 * Flat Topology
 * -------------
 *
 * All devices are connected to the controller with no intermediate bus.
 *
 *                         +------------+
 *                         | Controller |
 *                         +------------+
 *                               |
 *                               v
 *                               A
 *
 * This is the simplest case. Basically we can use each non-reserved address
 * once in A and tracking this is relatively easy.
 *
 * ----------
 * Single Mux
 * ----------
 *
 * There is a single mux in the tree with multiple segments under it. This looks
 * like:
 *
 *                         +------------+
 *                         | Controller |
 *                         +------------+
 *                               |
 *                               |-- A
 *                               v
 *                         +------------+
 *                         |    Mux     |
 *                         |            |
 *                         | 0  1  2  3 |
 *                         +------------+
 *                           |  |  |  |
 *                           v  v  v  v
 *                           B  C  D  E
 *
 * In this case we would allow address overlap between the downstream segments
 * of the mux. However, if an address is used in portion A, it cannot be used in
 * B-E. Similarly, if something is used in B-E, it can't really be used in A as
 * there would be now way to actually access it.
 *
 * ------------------
 * Single Layer Muxes
 * ------------------
 *
 * This is a variant on the previous case where we have multiple muxes, that
 * exist in parallel to one another. This often happens where someone is using
 * multiple 4-port muxes to deal with overlap. Let's draw this out and see how
 * our rules change:
 *
 *                         +------------+
 *                         | Controller |
 *                         +------------+
 *                               |
 *                               |-- A
 *                    +----------+---------+
 *                    v                    v
 *              +------------+       +------------+
 *              |    Mux     |       |    Mux     |
 *              |            |       |            |
 *              | 0  1  2  3 |       | 0  1  2  3 |
 *              +------------+       +------------+
 *                |  |  |  |           |  |  |  |
 *                v  v  v  v           v  v  v  v
 *                B  C  D  E           F  G  H  I
 *
 * In this case our rules are actually the same as in the prior case. While the
 * two muxes may be different devices, we basically say that anything in B-I can
 * overlap. However, the fact that we can't have an address both A and in B-I
 * still remains. This leads to a rule: muxes at the same level of the tree
 * should be considered the same.
 *
 * ---------------
 * Two Layer Muxes
 * ---------------
 *
 * Let's go back to the Single mux case and say no what happens if say C above
 * had a mux under it. First, let's draw this out:
 *
 *                         +------------+
 *                         | Controller |
 *                         +------------+
 *                               |
 *                               |-- A
 *                               v
 *                         +------------+
 *                         |    Mux     |
 *                         |            |
 *                         | 0  1  2  3 |
 *                         +------------+
 *                           |  |  |  |
 *                           v  |  v  v
 *                           B  |  D  E
 *                              |
 *                              |-- C
 *                              v
 *                         +------------+
 *                         |    Mux     |
 *                         |            |
 *                         | 0  1  2  3 |
 *                         +------------+
 *                           |  |  |  |
 *                           v  v  v  v
 *                           F  G  H  I
 *
 * So this design is not uncommon. Let's start with the simplest statement
 * possible: F-I can use overlapping addresses. The next one is more fun.
 * Anything in F-I can overlap in B, D, and E. Why is that? Basically this is
 * the same as the single layer mux. Similarly, anything in A cannot be used
 * elsewhere nor can something be added to A that is used elsewhere.
 *
 * Now some wrinkles: Anything in C can still be used in B, D, and E, but it
 * cannot be used in F-I. This mostly makes sense as it follows the single mux
 * case.
 *
 * ----------
 * Mux Forest
 * ----------
 *
 * Let's look at a complex series of muxes.
 * *
 *                         +------------+
 *                         | Controller |
 *                         +------------+
 *                               |
 *                               |-- A
 *                    +----------+---------+
 *                    v                    v
 *              +------------+       +------------+
 *              |    Mux     |       |    Mux     |
 *              |            |       |            |
 *              | 0  1  2  3 |       | 0  1  2  3 |
 *              +------------+       +------------+
 *                |  |  |  |           |  |  |  |
 *                v  |  v  v           v  v  |  v
 *                B  |  D  E           F  G  |  I
 *                   |                       |
 *                   |-- C                   |-- H
 *          +--------+-------+               v
 *          v                v          +------------+
 *    +------------+   +------------+   |    Mux     |
 *    |    Mux     |   |    Mux     |   |            |
 *    |            |   |            |   | 0  1  2  3 |
 *    | 0  1  2  3 |   | 0  1  2  3 |   +------------+
 *    +------------+   +------------+     |  |  |  |
 *      |  |  |  |       |  |  |  |       v  v  v  v
 *      v  v  v  v       v  v  v  v       R  S  T  U
 *      J  K  L  M       N  O  P  Q
 *
 * So we have a lot more going on here. Let's take this apart a bit. Let's start
 * with the first layer. This is covered by the Single Layer Mux rules. So what
 * happens when we start looking at their next layers. Let's start with the
 * right hand side and lay out a few observations:
 *
 *  - Addresses in R-U can overlap as much as they'd like per the normal single
 *    mux rule.
 *  - Addresses in R-U and H cannot overlap per the normal single mux rule.
 *  - Going up, Address in F, G, H, I are allowed to overlap. Similarly any
 *    addresses in R-U can be thought of as part of H while evaluating at this
 *    layer.
 *  - The implications of the above are that addresses in F, G, and I can
 *    overlap with any addresses in R-U.
 *  - Similarly, any address used in F-I and R-U cannot be used in A.
 *
 * Let's now pause and shift over to the left hand side of this forest before.
 * Similar to the single layer mux rules we can say the following:
 *
 *  - J-Q are allowed to overlap as much as they'd like.
 *  - C cannot overlap with J-Q.
 *  - B, D, and E can overlap with C and J-Q as much as they'd like.
 *  - All of these cannot overlap at all with A.
 *
 * -------------
 * Rules Summary
 * -------------
 *
 * 1) Muxes at the same level in the hierarchy can be thought of as one giant
 *    mux.
 * 2) Address overlap is always allowed for all the ports in the giant mux
 *    description from (1). Treat the set of used addresses on a giant mux as
 *    the union of all addresses used on all ports downstream.
 * 3) The union of addresses described in (2) cannot overlap with any upstream
 *    segments. For example:
 *      - The union of R-U cannot overlap with H.
 *      - The union of J-Q cannot overlap with C.
 *      - The union of B-U cannot overlap with A.
 * 4) These same sets of rules apply recursively throughout the tree.
 *
 * This means that when adding an address at any point in the three, it is
 * subject to the design of the rest of the tree. Note, it is strictly possible
 * to create something which is not actually a tree electrically. We don't
 * really have a good way of representing that and it definitely fits into the
 * I2C muxes are cursed territory. If we decided to support that, then we'll
 * have to revisit this and the set of rules.
 *
 * ------------------------------
 * Device with Multiple Addresses
 * ------------------------------
 *
 * There are two groups of devices with multiple addresses:
 *
 * 1) Those that have exclusive access to multiple addresses.
 * 2) Those that have an exclusive address and share a common address on the
 *    bus across all instances. The most prevalent example is the DDR4 EEPROM.
 *    All DDR4 EEPROMs share the same address to change a page.
 *
 * Issuing addresses in group (1) follows the same process as we have done to
 * date. However, we need a useful way to deal with group (2). To help this out
 * we make the following assumptions:
 *
 * 1) Only a single driver (e.g. a major_t) will need access to this at a time.
 *    A driver that uses this interface will know it is requesting it and can
 *    know how to coordinate usage of this address and the implications it has
 *    on devices.
 * 2) This will not be specified in reg[] information for the time being. This
 *    ensures that we always have a known driver and therefore a major_t to
 *    facilitate this.
 *
 * To facilitate this, we augment our tracking data with the major_t. We use
 * DDI_MAJOR_T_NONE to indicate that this is an exclusive address and the actual
 * major_t of the driver that owns it to indicate both that it is shared and
 * with whom.
 *
 * --------------
 * Implementation
 * --------------
 *
 * We are generally concerned with the address use from any series of i2c_port_t
 * instances in the tree. Basically a port is something that can have some
 * number of devices under it, whether it is a port on a controller, downstream
 * ports of an analog switch, or an in-band or out-of-band multiplexor, or
 * something else.
 *
 * A given port tracks all of the addresses that are in use immediately under it
 * and of all subsequent ports under it. For each address that is usable we
 * include a reference count, whether it is from our segment or a downstream
 * segment, and a major_t that is used to indicate whether this is a shared
 * address or not. This then occurs recursively up the tree. A few notes on how
 * this is used:
 *
 * 1) To determine if something is in use or not, you have to consult your port
 * and all of the parent ports. However, you do not have to iterate over all
 * ports in the tree.
 *
 * 2) The top-level port, aka the bus, tells us all addresses that are in use.
 * However, it doesn't not immediately answer the question of whether or not an
 * address can be used.
 *
 * 3) Exclusive addresses mark their way all the way up the tree; however,
 * shared addresses only consult the bus.
 *
 * 3) The overall algorithm for determining if an address is usable or not for
 * exclusive access is:
 *
 *	if current port reference count is non-zero:
 *		return false
 *	for each parent:
 *		if the reference count is zero:
 *			continue
 *		if the reference count is the maximum value:
 *			return false
 *		if the address is in use directly or it has a
 *		    non-DDI_MAJOR_T_NONE major:
 *			return false
 *	return true
 *
 * 4) To actually indicate that the address is in use you set the reference
 * count to 1 on the current port, mark it as directly used, and store the major
 * as DDI_MAJOR_T_NONE. Then for each case up the tree you bump the reference
 * count, validate it as remote, and that it has DDI_MAJOR_T_NONE as the major.
 *
 * 5) When removing an address, you decrement the reference count for this
 * address on each port up the tree.
 *
 * 6) The overall algorithm for determining if an address is usable or not for a
 * shared address is:
 *
 *	got to the bus
 *	if the reference count is non-zero:
 *		if the stored major differs from the caller's:
 *			return false
 *		if the reference count is the maximum value:
 *			return false
 *	return true
 *
 * Because all exclusive addresses always go all the way up the tree to the bus,
 * we can easily use this and simplify the implementation and don't have to walk
 * everywhere to determine conflicts on mux segments.
 *
 * 6) To indicate that a shared reference address is in use one goes to the bus.
 * Bump the reference count by one and ensure the major is set as expected and
 * that this is set as direct.
 *
 * 7) When removing an address, you decrement the reference count on the
 * top-most bus port. If the reference count is now zero, reset the major and
 * direct bit.
 *
 * 8) The major and direct bits are only valid if the reference-count is
 * non-zero.
 *
 * The above information is tracked on a per-address family basis. The reference
 * count is currently constrained to a uint8_t. This can be increased if the
 * need is there.
 */

#include "i2cnex.h"

static bool
i2c_addr_free_parent(i2c_port_t *port, void *arg)
{
	const i2c_addr_t *addr = arg;
	i2c_addr_track_t *track = &port->ip_track_7b;
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);
	VERIFY3U(track->at_refcnt[addr->ia_addr], >, 0);
	VERIFY3U(track->at_downstream[addr->ia_addr], ==, true);
	VERIFY3U(track->at_major[addr->ia_addr], ==, DDI_MAJOR_T_NONE);

	track->at_refcnt[addr->ia_addr]--;
	if (track->at_refcnt[addr->ia_addr] == 0) {
		track->at_downstream[addr->ia_addr] = false;
		track->at_major[addr->ia_addr] = DDI_MAJOR_T_UNKNOWN;
	}

	return (true);
}

void
i2c_addr_free(i2c_port_t *port, const i2c_addr_t *addr)
{
	i2c_addr_track_t *track;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	track = &port->ip_track_7b;
	VERIFY3U(track->at_refcnt[addr->ia_addr], >, 0);
	VERIFY3U(track->at_major[addr->ia_addr], ==, DDI_MAJOR_T_NONE);
	VERIFY3U(track->at_downstream[addr->ia_addr], ==, false);
	track->at_refcnt[addr->ia_addr]--;
	if (track->at_refcnt[addr->ia_addr] == 0) {
		track->at_downstream[addr->ia_addr] = false;
		track->at_major[addr->ia_addr] = DDI_MAJOR_T_UNKNOWN;
	}

	i2c_port_parent_iter(port, i2c_addr_free_parent, (void *)addr);
}

typedef struct {
	const i2c_addr_t *ipa_addr;
	i2c_error_t *ipa_err;
	bool ipa_valid;
} i2c_addr_check_t;

static bool
i2c_addr_alloc_check(i2c_port_t *port, void *arg)
{
	i2c_addr_check_t *check = arg;
	i2c_addr_track_t *track = &port->ip_track_7b;
	uint16_t idx = check->ipa_addr->ia_addr;

	VERIFY3U(check->ipa_addr->ia_type, ==, I2C_ADDR_7BIT);

	if (track->at_refcnt[idx] == 0) {
		return (true);
	}

	if (track->at_refcnt[idx] == UINT8_MAX) {
		check->ipa_valid = false;
		return (i2c_error(check->ipa_err, I2C_CORE_E_ADDR_REFCNT, 0));
	}

	/*
	 * While we store DDI_MAJOR_T_UNKNOWN (0) in the case where the
	 * reference count is zero, we have already dealt with that up above.
	 */
	if (!track->at_downstream[idx] ||
	    track->at_major[idx] != DDI_MAJOR_T_NONE) {
		check->ipa_valid = false;
		return (i2c_error(check->ipa_err, I2C_CORE_E_ADDR_IN_USE, 0));
	}

	return (true);
}

static bool
i2c_addr_alloc_parent(i2c_port_t *port, void *arg)
{
	const i2c_addr_t *addr = arg;
	i2c_addr_track_t *track = &port->ip_track_7b;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	if (track->at_refcnt[addr->ia_addr] > 0) {
		VERIFY3U(track->at_downstream[addr->ia_addr], ==, true);
		VERIFY3U(track->at_major[addr->ia_addr], ==, DDI_MAJOR_T_NONE);
	} else {
		track->at_downstream[addr->ia_addr] = true;
		track->at_major[addr->ia_addr] = DDI_MAJOR_T_NONE;
	}

	track->at_refcnt[addr->ia_addr]++;
	return (true);
}

bool
i2c_addr_alloc(i2c_port_t *port, const i2c_addr_t *addr, i2c_error_t *err)
{
	i2c_addr_track_t *track;
	i2c_addr_check_t check;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	track = &port->ip_track_7b;
	if (track->at_refcnt[addr->ia_addr] != 0) {
		return (i2c_error(err, I2C_CORE_E_ADDR_IN_USE, 0));
	}

	check.ipa_addr = addr;
	check.ipa_err = err;
	check.ipa_valid = true;
	i2c_port_parent_iter(port, i2c_addr_alloc_check, &check);
	if (!check.ipa_valid) {
		return (false);
	}

	track->at_refcnt[addr->ia_addr]++;
	track->at_downstream[addr->ia_addr] = false;
	track->at_major[addr->ia_addr] = DDI_MAJOR_T_NONE;
	i2c_port_parent_iter(port, i2c_addr_alloc_parent, (void *)addr);
	return (true);
}

static i2c_port_t *
i2c_port_topmost(i2c_port_t *port)
{
	i2c_port_t *last = port;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);

	for (i2c_nexus_t *nex = port->ip_nex->in_pnex; nex != NULL;
	    nex = nex->in_pnex) {
		if (nex->in_type == I2C_NEXUS_T_PORT) {
			last = nex->in_data.in_port;
		}
	}

	return (last);
}

typedef struct {
	const i2c_addr_t *iaa_addr;
	major_t iaa_major;
} i2c_addr_alloc_t;

static bool
i2c_addr_free_shared_cb(i2c_port_t *port, void *arg)
{
	const i2c_addr_alloc_t *alloc = arg;
	const i2c_addr_t *addr = alloc->iaa_addr;
	i2c_addr_track_t *track;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	track = &port->ip_track_7b;
	VERIFY3U(track->at_refcnt[addr->ia_addr], >, 0);
	VERIFY3U(track->at_downstream[addr->ia_addr], ==, false);
	VERIFY3U(track->at_major[addr->ia_addr], ==, alloc->iaa_major);

	track->at_refcnt[addr->ia_addr]--;
	if (track->at_refcnt[addr->ia_addr] == 0) {
		track->at_downstream[addr->ia_addr] = false;
		track->at_major[addr->ia_addr] = DDI_MAJOR_T_UNKNOWN;
	}

	return (true);
}

void
i2c_addr_free_shared(i2c_port_t *port, const i2c_addr_t *addr, major_t maj)
{
	i2c_addr_alloc_t alloc;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);
	alloc.iaa_addr = addr;
	alloc.iaa_major = maj;
	(void) i2c_port_iter(port, i2c_addr_free_shared_cb, &alloc);
}

static bool
i2c_addr_alloc_shared_cb(i2c_port_t *port, void *arg)
{
	const i2c_addr_alloc_t *alloc = arg;
	const i2c_addr_t *addr = alloc->iaa_addr;
	i2c_addr_track_t *track = &port->ip_track_7b;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	if (track->at_refcnt[addr->ia_addr] > 0) {
		VERIFY3U(track->at_downstream[addr->ia_addr], ==, false);
		VERIFY3U(track->at_major[addr->ia_addr], ==, alloc->iaa_major);
	} else {
		track->at_downstream[addr->ia_addr] = false;
		track->at_major[addr->ia_addr] = alloc->iaa_major;
	}

	track->at_refcnt[addr->ia_addr]++;
	return (true);
}

bool
i2c_addr_alloc_shared(i2c_port_t *port, const i2c_addr_t *addr, major_t maj,
    i2c_error_t *err)
{
	i2c_port_t *bus;
	i2c_addr_track_t *track;
	i2c_addr_alloc_t alloc;

	VERIFY3P(port->ip_nex->in_ctrl->ic_lock.cl_owner, !=, NULL);
	VERIFY3U(addr->ia_type, ==, I2C_ADDR_7BIT);

	/*
	 * For an address to be allocated as a shared address it must not be in
	 * use at the top-most port or be specifically a shared address there
	 * with our major. We never will set downstream for a shared address
	 * because it's complicated to track in this case and not relevant for
	 * shared addresses.
	 */
	bus = i2c_port_topmost(port);
	track = &bus->ip_track_7b;
	if (track->at_refcnt[addr->ia_addr] != 0) {
		if (track->at_major[addr->ia_addr] != maj) {
			return (i2c_error(err, I2C_CORE_E_ADDR_IN_USE, 0));
		}

		if (track->at_refcnt[addr->ia_addr] == UINT8_MAX) {
			return (i2c_error(err, I2C_CORE_E_ADDR_REFCNT, 0));
		}

		VERIFY3U(track->at_downstream[addr->ia_addr], ==, false);
	}

	alloc.iaa_addr = addr;
	alloc.iaa_major = maj;
	i2c_port_iter(port, i2c_addr_alloc_shared_cb, &alloc);

	return (true);
}

void
i2c_addr_info_7b(const i2c_port_t *port, ui2c_port_info_t *info)
{
	const i2c_addr_track_t *track = &port->ip_track_7b;

	for (uint8_t i = 0; i < 1 << 7; i++) {
		if (track->at_refcnt[i] == 0) {
			info->upo_7b[i].pai_major = DDI_MAJOR_T_NONE;
			info->upo_7b[i].pai_ndevs = 0;
			info->upo_7b[i].pai_downstream = false;
			continue;
		}

		info->upo_7b[i].pai_ndevs = track->at_refcnt[i];
		info->upo_7b[i].pai_downstream = track->at_downstream[i];
		info->upo_7b[i].pai_major = track->at_major[i];
	}
}
