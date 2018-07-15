/*
 * This file and its contents are supplied under the terms of the
	csrrs	t1, CDDL, t2), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2018, Joyent, Inc.
 */

/*
 * Test our disassembly of csr instructions and csr names.
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	/* User Trap */
	csrrs	t1, ustatus, t2 
	csrrs	t1, uie, t2 
	csrrs	t1, utvec, t2 
	/* User Trap Handling */
	csrrs	t1, uscratch, t2 
	csrrs	t1, uepc, t2 
	csrrs	t1, ucause, t2 
	csrrs	t1, utval, t2 
	csrrs	t1, uip, t2 
	/* User Floating-Point CSRs */
	csrrs	t1, fflags, t2 
	csrrs	t1, frm, t2 
	csrrs	t1, fcsr, t2 
	/* User Counters/Timers */
	csrrs	t1, cycle, t2 
	csrrs	t1, time, t2 
	csrrs	t1, instret, t2 
	csrrs	t1, hpmcounter3, t2 
	csrrs	t1, hpmcounter4, t2 
	csrrs	t1, hpmcounter5, t2 
	csrrs	t1, hpmcounter6, t2 
	csrrs	t1, hpmcounter7, t2 
	csrrs	t1, hpmcounter8, t2 
	csrrs	t1, hpmcounter9, t2 
	csrrs	t1, hpmcounter10, t2 
	csrrs	t1, hpmcounter11, t2 
	csrrs	t1, hpmcounter12, t2 
	csrrs	t1, hpmcounter13, t2 
	csrrs	t1, hpmcounter14, t2 
	csrrs	t1, hpmcounter15, t2 
	csrrs	t1, hpmcounter16, t2 
	csrrs	t1, hpmcounter17, t2 
	csrrs	t1, hpmcounter18, t2 
	csrrs	t1, hpmcounter19, t2 
	csrrs	t1, hpmcounter20, t2 
	csrrs	t1, hpmcounter21, t2 
	csrrs	t1, hpmcounter22, t2 
	csrrs	t1, hpmcounter23, t2 
	csrrs	t1, hpmcounter24, t2 
	csrrs	t1, hpmcounter25, t2 
	csrrs	t1, hpmcounter26, t2 
	csrrs	t1, hpmcounter27, t2 
	csrrs	t1, hpmcounter28, t2 
	csrrs	t1, hpmcounter29, t2 
	csrrs	t1, hpmcounter30, t2 
	csrrs	t1, hpmcounter31, t2 
	csrrs	t1, cycleh, t2 
	csrrs	t1, timeh, t2 
	csrrs	t1, instreth, t2 
	csrrs	t1, hpmcounter3h, t2 
	csrrs	t1, hpmcounter4h, t2 
	csrrs	t1, hpmcounter5h, t2 
	csrrs	t1, hpmcounter6h, t2 
	csrrs	t1, hpmcounter7h, t2 
	csrrs	t1, hpmcounter8h, t2 
	csrrs	t1, hpmcounter9h, t2 
	csrrs	t1, hpmcounter10h, t2 
	csrrs	t1, hpmcounter11h, t2 
	csrrs	t1, hpmcounter12h, t2 
	csrrs	t1, hpmcounter13h, t2 
	csrrs	t1, hpmcounter14h, t2 
	csrrs	t1, hpmcounter15h, t2 
	csrrs	t1, hpmcounter16h, t2 
	csrrs	t1, hpmcounter17h, t2 
	csrrs	t1, hpmcounter18h, t2 
	csrrs	t1, hpmcounter19h, t2 
	csrrs	t1, hpmcounter20h, t2 
	csrrs	t1, hpmcounter21h, t2 
	csrrs	t1, hpmcounter22h, t2
	csrrs	t1, hpmcounter23h, t2 
	csrrs	t1, hpmcounter24h, t2 
	csrrs	t1, hpmcounter25h, t2 
	csrrs	t1, hpmcounter26h, t2 
	csrrs	t1, hpmcounter27h, t2 
	csrrs	t1, hpmcounter28h, t2 
	csrrs	t1, hpmcounter29h, t2 
	csrrs	t1, hpmcounter30h, t2 
	csrrs	t1, hpmcounter31h, t2 
	/* Supervisor Trap Status */
	csrrs	t1, sstatus, t2 
	csrrs	t1, sedeleg, t2 
	csrrs	t1, sideleg, t2 
	csrrs	t1, sie, t2 
	csrrs	t1, stvec, t2 
	csrrs	t1, scounteren, t2 
	/* Supervisor Trap Handling */
	csrrs	t1, sscratch, t2 
	csrrs	t1, sepc, t2 
	csrrs	t1, scause, t2 
	csrrs	t1, stval, t2 
	csrrs	t1, sip, t2 
	/* Supervisor Protection and Translation */
	csrrs	t1, satp, t2 
	/* Machine Information Registers */
	csrrs	t1, mvendorid, t2 
	csrrs	t1, marchid, t2 
	csrrs	t1, mimpid, t2 
	csrrs	t1, mhartid, t2 
	/* Machine Trap Setup */
	csrrs	t1, mstatus, t2 
	csrrs	t1, misa, t2 
	csrrs	t1, medeleg, t2 
	csrrs	t1, mideleg, t2 
	csrrs	t1, mie, t2 
	csrrs	t1, mtvec, t2 
	csrrs	t1, mcounteren, t2 
	/* Machine Trap Handling */
	csrrs	t1, mscratch, t2 
	csrrs	t1, mepc, t2 
	csrrs	t1, mcause, t2 
	csrrs	t1, mtval, t2 
	csrrs	t1, mip, t2 
	/* Machine Protection and Translation */
	csrrs	t1, pmpcfg0, t2 
	csrrs	t1, pmpcfg1, t2 
	csrrs	t1, pmpcfg2, t2 
	csrrs	t1, pmpcfg3, t2 
	csrrs	t1, pmpaddr0, t2 
	csrrs	t1, pmpaddr1, t2 
	csrrs	t1, pmpaddr2, t2 
	csrrs	t1, pmpaddr3, t2 
	csrrs	t1, pmpaddr4, t2 
	csrrs	t1, pmpaddr5, t2 
	csrrs	t1, pmpaddr6, t2 
	csrrs	t1, pmpaddr7, t2 
	csrrs	t1, pmpaddr8, t2 
	csrrs	t1, pmpaddr9, t2 
	csrrs	t1, pmpaddr10, t2 
	csrrs	t1, pmpaddr11, t2 
	csrrs	t1, pmpaddr12, t2 
	csrrs	t1, pmpaddr13, t2 
	csrrs	t1, pmpaddr14, t2 
	csrrs	t1, pmpaddr15, t2
	/*
	 * Various instr variants
	 */
	csrrs	t1, ustatus, t2 
	csrrw	t1, uie, t2 
	csrrc	t1, utvec, t2 
	csrrwi	t1, uscratch, 0x17
	csrrsi	t1, uepc, 0x16
	csrrci	t1, ucause, 0x15
.size libdis_test, [.-libdis_test]
