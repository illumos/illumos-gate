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
 * Copyright (c) 2019, Joyent, Inc.
 */

#include <stdint.h>

/*
 * Basic sanity checking of enumerations, using specific numbers and arbitrary
 * numbers.
 */

enum ff6 {
	TERRA,
	LOCKE,
	EDGAR,
	SABIN,
	CELES,
	CYAN,
	SHADOW,
	GAU,
	SETZER,
	STRAGO,
	RELM,
	MOG,
	GOGO,
	UMARO,
	LEO,
	KEFKA
};

typedef enum ff10 {
	TIDUS = -10,
	YUNA = 23,
	AURON = -34,
	WAKA = 52,
	LULU = INT32_MAX,
	RIKKU = INT32_MIN,
	KHIMARI = 0
} ff10_t;

/*
 * The following enum is copy of the ddi_hp_cn_state_t enumeration which was
 * previously incorrectly converted by the tools. Notably, we always assumed
 * that the DWARF enum values were signed; however, in this case we needed to
 * check for an unsigned version before a signed version, otherwise some of the
 * entries below will have the wrong values.
 */
typedef enum chrono {
	CRONO = 0x1000,
	LUCCA = 0x2000,
	MARLE = 0x3000,
	FROG = 0x4000,
	ROBO = 0x5000,
	AYLA = 0x6000,
	MAGUS = 0x7000,
	SCHALA = 0x8000,
	LAVOS = 0x9000,
	BALTHAZAR = 0xa000
} chrono_t;

enum ff6 ff6;
ff10_t ff10;
chrono_t trigger;
