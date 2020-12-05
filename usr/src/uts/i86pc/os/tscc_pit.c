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
 * Copyright 2020 Joyent, Inc.
 */

#include <sys/pit.h>
#include <sys/tsc.h>
#include <sys/archsystm.h>
#include <sys/prom_debug.h>

extern uint64_t freq_tsc_pit(uint32_t *);

/*
 * Traditionally, the PIT has been used to calibrate both the TSC and the
 * APIC. As we transition to supporting alternate TSC calibration sources
 * and using the TSC to calibrate the APIC, we may still want (for diagnostic
 * purposes) to know what would have happened if we had used the PIT
 * instead. As a result, if we are using an alternate calibration source
 * we will still measure the frequency using the PIT and save the result in
 * pit_tsc_hz for use by the APIC (to similarly save the timings using the
 * PIT).
 *
 * A wrinkle in this is that some systems no longer have a functioning PIT.
 * In these instances, we simply have no way to provide the 'what if the PIT
 * was used' values. When we try to use the PIT, we first perform a small
 * test to see if it appears to be working (i.e. will it count down). If
 * it does not, we set pit_is_broken to let the APIC calibration code that
 * it shouldn't attempt to get PIC timings.
 *
 * While the systems without a functioning PIT don't seem to experience
 * any undesirable behavior when attempting to use the non-functional/not
 * present PIT (i.e. they don't lock up or otherwise act funny -- the counter
 * values that are read just never change), we still allow pit_is_broken to be
 * set in /etc/system to inform the system to avoid attempting to use the PIT
 * at all.
 *
 * In the future, we could remove these transitional bits once we have more
 * history built up using the alternative calibration sources.
 */
uint64_t pit_tsc_hz;
int pit_is_broken;

/*
 * On all of the systems seen so far without functioning PITs, it appears
 * that they always just return the values written to the PITCTR0_PORT (or
 * more specifically when they've been programmed to start counting down from
 * 0xFFFF, they always return 0xFFFF no matter how little/much time has
 * elapsed).
 *
 * Since we have no better way to know if the PIT is broken, we use this
 * behavior to sanity check the PIT. We program the PIT to count down from
 * 0xFFFF and wait an amount of time and re-read the result. While we cannot
 * rely on the TSC frequency being known at this point, we do know that
 * we are almost certainly never going to see a TSC frequency below 1GHz
 * on any supported system.
 *
 * As such, we (somewhat) arbitrarily pick 400,000 TSC ticks as the amount
 * of time we wait before re-reading the PIT counter. On a 1GHz machine,
 * 1 PIT tick would correspond to approximately 838 TSC ticks, therefore
 * waiting 400,000 TSC ticks should correspond to approx 477 PIT ticks.
 * On a (currently) theoritical 100GHz machine, 400,000 TSC ticks would still
 * correspond to approx 4-5 PIT ticks, so this seems a reasonably safe value.
 */
#define	TSC_MIN_TICKS	400000ULL

static boolean_t
pit_sanity_check(void)
{
	uint64_t tsc_now, tsc_end;
	ulong_t flags;
	uint16_t pit_count;

	flags = clear_int_flag();

	tsc_now = tsc_read();
	tsc_end = tsc_now + TSC_MIN_TICKS;

	/*
	 * Put the PIT in mode 0, "Interrupt On Terminal Count":
	 */
	outb(PITCTL_PORT, PIT_C0 | PIT_LOADMODE | PIT_ENDSIGMODE);

	outb(PITCTR0_PORT, 0xFF);
	outb(PITCTR0_PORT, 0xFF);

	while (tsc_now < tsc_end)
		tsc_now = tsc_read();

	/*
	 * Latch the counter value and status for counter 0 with the
	 * readback command.
	 */
	outb(PITCTL_PORT, PIT_READBACK | PIT_READBACKC0);

	/*
	 * In readback mode, reading from the counter port produces a
	 * status byte, the low counter byte, and finally the high counter byte.
	 *
	 * We ignore the status byte -- as noted above, we've delayed for an
	 * amount of time that should allow the counter to count off at least
	 * 4-5 ticks (and more realistically at least a hundred), so we just
	 * want to see if the count has changed at all.
	 */
	(void) inb(PITCTR0_PORT);
	pit_count = inb(PITCTR0_PORT);
	pit_count |= inb(PITCTR0_PORT) << 8;

	restore_int_flag(flags);

	if (pit_count == 0xFFFF) {
		pit_is_broken = 1;
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
tsc_calibrate_pit(uint64_t *freqp)
{
	uint64_t processor_clks;
	ulong_t flags;
	uint32_t pit_counter;

	if (pit_is_broken)
		return (B_FALSE);

	if (!pit_sanity_check())
		return (B_FALSE);

	/*
	 * freq_tsc_pit() is a hand-rolled assembly function that returns
	 * the number of TSC ticks and sets pit_counter to the number
	 * of corresponding PIT ticks in the same time period.
	 */
	flags = clear_int_flag();
	processor_clks = freq_tsc_pit(&pit_counter);
	restore_int_flag(flags);

	if (pit_counter == 0 || processor_clks == 0 ||
	    processor_clks > (((uint64_t)-1) / PIT_HZ)) {
		return (B_FALSE);
	}

	*freqp = pit_tsc_hz = ((uint64_t)PIT_HZ * processor_clks) / pit_counter;
	return (B_TRUE);
}

/*
 * Typically any source besides the PIT is going to provide better
 * results, so a low preference is assigned to the PIT so it is tried last.
 */
static tsc_calibrate_t tsc_calibration_pit = {
	.tscc_source = "PIT",
	.tscc_preference = 10,
	.tscc_calibrate = tsc_calibrate_pit,
};
TSC_CALIBRATION_SOURCE(tsc_calibration_pit);
