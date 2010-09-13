/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

#include <fcode/private.h>
#include <fcode/log.h>

#include <fcdriver/fcdriver.h>

static fc_cell_t
fc_reg_read(fcode_env_t *env, char *service, fstack_t virt, int *errp)
{
	fc_cell_t virtaddr, data;
	int error, nin;

	if (!is_mcookie(virt))
		forth_abort(env, "fc_reg_read: bad mcookie: 0x%x\n", virt);

	virtaddr = mcookie_to_addr(virt);

	/* Supress fc_run_priv error msgs on peeks */
	nin = ((errp == NULL) ? 1 : (1 | FCRP_NOERROR));

	error = fc_run_priv(env->private, service, nin, 1, virtaddr, &data);
	if (errp)
		/* Don't report error on peeks */
		*errp = error;
	else if (error) {
		forth_abort(env, "fc_read_reg: ERROR: cookie: %llx"
		    " virt: %llx\n", (uint64_t)virt, (uint64_t)virtaddr);
	}
	return (data);
}

static void
fc_reg_write(fcode_env_t *env, char *service, fstack_t virt, fc_cell_t data,
    int *errp)
{
	fc_cell_t virtaddr;
	int error, nin;

	if (!is_mcookie(virt))
		forth_abort(env, "fc_reg_write: bad mcookie: 0x%x\n", virt);

	virtaddr = mcookie_to_addr(virt);

	/* Supress fc_run_priv error msgs on pokes */
	nin = ((errp == NULL) ? 2 : (2 | FCRP_NOERROR));

	error = fc_run_priv(env->private, service, nin, 0, virtaddr, data);
	if (errp)
		/* Don't report error on pokes */
		*errp = error;
	else if (error) {
		forth_abort(env, "fc_write_reg: ERROR: cookie: %llx"
		    " virt: %llx\n", (uint64_t)virt, (uint64_t)virtaddr);
	}
}

static int
check_address_abuse(fcode_env_t *env, fstack_t addr, char *type,
    int want_mcookie, void (*alt)(fcode_env_t *))
{
	if (is_mcookie(addr) != want_mcookie) {
		debug_msg(DEBUG_ADDR_ABUSE, "Warning: %s to %s address: %llx\n",
		    type, want_mcookie ? "unmapped" : "mapped",
		    (uint64_t)addr);
		(*alt)(env);
		return (1);
	}
	return (0);
}

static void
rlfetch(fcode_env_t *env)
{
	fstack_t p;

	CHECK_DEPTH(env, 1, "rl@");
	p = TOS;
	if (!check_address_abuse(env, p, "rl@", 1, lfetch))
		TOS = (lforth_t)fc_reg_read(env, "rl@", p, NULL);
}

static void
rlstore(fcode_env_t *env)
{
	fstack_t p, d;

	CHECK_DEPTH(env, 2, "rl!");
	p = TOS;
	if (!check_address_abuse(env, p, "rl!", 1, lstore)) {
		p = POP(DS);
		d = POP(DS);
		fc_reg_write(env, "rl!", p, d, NULL);
	}
}

static void
rwfetch(fcode_env_t *env)
{
	fstack_t p;

	CHECK_DEPTH(env, 1, "rw@");
	p = TOS;
	if (!check_address_abuse(env, p, "rw@", 1, wfetch))
		TOS = (wforth_t)fc_reg_read(env, "rw@", p, NULL);
}

static void
rwstore(fcode_env_t *env)
{
	fstack_t p, d;

	CHECK_DEPTH(env, 2, "rw!");
	p = TOS;
	if (!check_address_abuse(env, p, "rw!", 1, wstore)) {
		p = POP(DS);
		d = POP(DS);
		fc_reg_write(env, "rw!", p, d, NULL);
	}
}

void
rbfetch(fcode_env_t *env)
{
	fstack_t p;

	CHECK_DEPTH(env, 1, "rb@");
	p = TOS;
	if (!check_address_abuse(env, p, "rb@", 1, cfetch)) {
		TOS = (uchar_t)fc_reg_read(env, "rb@", p, NULL);
	}
}

static void
rbstore(fcode_env_t *env)
{
	fstack_t	p, d;

	CHECK_DEPTH(env, 2, "rb!");
	p = TOS;
	if (!check_address_abuse(env, p, "rb!", 1, cstore)) {
		p = POP(DS);
		d = POP(DS);
		fc_reg_write(env, "rb!", p, d, NULL);
	}
}

/*
 * rx@        ( xa -- xv )
 */
static void
rxfetch(fcode_env_t *env)
{
	fstack_t p;
	xforth_t x;

	CHECK_DEPTH(env, 1, "rx@");
	p = TOS;
	if (!check_address_abuse(env, p, "rx@", 1, xfetch)) {
		p = POP(DS);
		push_xforth(env, (xforth_t)fc_reg_read(env, "rx@", p, NULL));
	}
}

/*
 * rx!        ( xv xa -- )
 */
static void
rxstore(fcode_env_t *env)
{
	fstack_t p;
	xforth_t d;

	CHECK_DEPTH(env, 2, "rx!");
	p = TOS;
	if (!check_address_abuse(env, p, "rx!", 1, xstore)) {
		p = POP(DS);
		d = pop_xforth(env);
		fc_reg_write(env, "rx!", p, d, NULL);
	}
}

static void
lpeek(fcode_env_t *env)
{
	fstack_t p;
	lforth_t r;
	int error;

	CHECK_DEPTH(env, 1, "lpeek");
	p = POP(DS);
	r = (lforth_t)fc_reg_read(env, "rl@", p, &error);
	if (error)
		PUSH(DS, FALSE);
	else {
		PUSH(DS, r);
		PUSH(DS, TRUE);
	}
}

static void
lpoke(fcode_env_t *env)
{
	fstack_t p, d;
	int error;

	CHECK_DEPTH(env, 2, "lpoke");
	p = POP(DS);
	d = POP(DS);
	fc_reg_write(env, "rl!", p, d, &error);
	PUSH(DS, error ? FALSE : TRUE);
}

static void
wpeek(fcode_env_t *env)
{
	fstack_t p;
	int error;
	wforth_t r;

	CHECK_DEPTH(env, 1, "wpeek");
	p = POP(DS);
	r = (wforth_t)fc_reg_read(env, "rw@", p, &error);
	if (error)
		PUSH(DS, FALSE);
	else {
		PUSH(DS, r);
		PUSH(DS, TRUE);
	}
}

static void
wpoke(fcode_env_t *env)
{
	fstack_t p, d;
	int error;

	CHECK_DEPTH(env, 2, "wpoke");
	p = POP(DS);
	d = POP(DS);
	fc_reg_write(env, "rw!", p, d, &error);
	PUSH(DS, error ? FALSE : TRUE);
}

static void
cpeek(fcode_env_t *env)
{
	fstack_t	p;
	uchar_t r;
	int error;

	CHECK_DEPTH(env, 1, "cpeek");
	p = POP(DS);
	r = (uchar_t)fc_reg_read(env, "rb@", p, &error);
	if (error)
		PUSH(DS, FALSE);
	else {
		PUSH(DS, r);
		PUSH(DS, TRUE);
	}
}

static void
cpoke(fcode_env_t *env)
{
	fstack_t	p, d;
	int error;

	CHECK_DEPTH(env, 2, "cpoke");
	p = POP(DS);
	d = POP(DS);
	fc_reg_write(env, "rb!", p, d, &error);
	PUSH(DS, error ? FALSE : TRUE);
}

/*
 * fcdriver version of cfetch, replaces base 'c@'
 */
static void
fcd_cfetch(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 1, "c@");
	if (!check_address_abuse(env, addr, "c@", 0, rbfetch))
		cfetch(env);
}

/*
 * fcdriver version of cstore, replaces base 'c!'
 */
static void
fcd_cstore(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 2, "c!");
	if (!check_address_abuse(env, addr, "c!", 0, rbstore))
		cstore(env);
}

/*
 * fcdriver version of wfetch, replaces base 'w@'
 */
static void
fcd_wfetch(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 1, "w@");
	if (!check_address_abuse(env, addr, "w@", 0, rwfetch))
		wfetch(env);
}

/*
 * fcdriver version of wstore, replaces base 'w!'
 */
static void
fcd_wstore(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 2, "w!");
	if (!check_address_abuse(env, addr, "w!", 0, rwstore))
		wstore(env);
}

/*
 * fcdriver version of lfetch, replaces base 'l@'
 */
static void
fcd_lfetch(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 1, "l@");
	if (!check_address_abuse(env, addr, "l@", 0, rlfetch))
		lfetch(env);
}

/*
 * fcdriver version of lstore, replaces base 'l!'
 */
static void
fcd_lstore(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 2, "l!");
	if (!check_address_abuse(env, addr, "l!", 0, rlstore))
		lstore(env);
}

/*
 * fcdriver version of xfetch, replaces base 'x@'
 */
static void
fcd_xfetch(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 1, "x@");
	if (!check_address_abuse(env, addr, "x@", 0, rxfetch))
		xfetch(env);
}

/*
 * fcdriver version of xstore, replaces base 'x!'
 */
static void
fcd_xstore(fcode_env_t *env)
{
	fstack_t addr = TOS;

	CHECK_DEPTH(env, 2, "x!");
	if (!check_address_abuse(env, addr, "x!", 0, rxstore))
		xstore(env);
}

/*
 * fcdriver version of move, replaces base 'move'
 */
static void
fcd_move(fcode_env_t *env)
{
	size_t len;
	uchar_t *destaddr, *srcaddr;

	CHECK_DEPTH(env, 3, "move");
	len = POP(DS);
	destaddr = ((uchar_t *)POP(DS));
	srcaddr = ((uchar_t *)POP(DS));
	for (; len > 0; len--, srcaddr++, destaddr++) {
		PUSH(DS, (fstack_t)srcaddr);
		fcd_cfetch(env);
		PUSH(DS, (fstack_t)destaddr);
		fcd_cstore(env);
	}
}

static void
fcd_comp(fcode_env_t *env)
{
	char *str1, *str2, byte1, byte2;
	size_t len;

	CHECK_DEPTH(env, 3, "comp");
	len  = (size_t)POP(DS);
	str1 = (char *)POP(DS);
	str2 = (char *)POP(DS);
	for (; len > 0; len--, str1++, str2++) {
		PUSH(DS, (fstack_t)str1);
		fcd_cfetch(env);
		byte1 = POP(DS);
		PUSH(DS, (fstack_t)str2);
		fcd_cfetch(env);
		byte2 = POP(DS);
		if (byte1 > byte2) {
			PUSH(DS, -1);
			return;
		}
		if (byte1 < byte2) {
			PUSH(DS, 1);
			return;
		}
	}
	PUSH(DS, 0);
}

char *
get_eeprom_value(fcode_env_t *env, char *name)
{
	FILE *fd;
	char buf[80], *p;

	sprintf(buf, "eeprom '%s'", name);
	if ((fd = popen(buf, "r")) == NULL)
		return (NULL);
	fgets(buf, sizeof (buf), fd);
	pclose(fd);
	if ((p = strchr(buf, '\n')) != NULL)
		*p = '\0';
	if ((p = strchr(buf, '=')) != NULL)
		return (p + 1);
	return (NULL);
}

static void
local_mac_address(fcode_env_t *env)
{
	char *mac_str;
	int mac_value;

	mac_str = get_eeprom_value(env, "local-mac-address?");
	if (mac_str != NULL && strcmp(mac_str, "true") == 0)
		mac_value = TRUE;
	else
		mac_value = FALSE;
	PUSH(DS, mac_value);
}

/*
 * Allow for programmatic over-ride of 'mac-address'
 */
#define	MAC_ADDR_SIZE	6
static char *mac_addr;
static int mac_addr_is_valid;

void
set_mac_address(char *macaddr)
{
	mac_addr_is_valid = 1;
	memcpy(mac_addr, macaddr, MAC_ADDR_SIZE);
}

void
push_mac_address(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)mac_addr);
	PUSH(DS, MAC_ADDR_SIZE);
}

/*
 * Does driver call to get this.
 */
static void
local_ether_addr(fcode_env_t *env)
{
	static fc_cell_t *mac_add;
	int error;

	mac_add = MALLOC(sizeof (fc_cell_t) * 2);
	error = fc_run_priv(env->private, "local-ether-addr", 0, 2, &mac_add[0],
	    &mac_add[1]);
	if (error) {
		bzero(mac_add, sizeof (mac_add));
	}

	PUSH(DS, (fstack_t)&mac_add[0]);
	PUSH(DS, 6);
}

/*
 * 'mac-address' - complicated by 'local-mac-address' stuff.
 */
static void
mac_address(fcode_env_t *env)
{
	fstack_t d;

	if (mac_addr_is_valid) {
		push_mac_address(env);
		return;
	}

	/*
	 * From here, we essentially re-implement OBP's 'mac-address' word.
	 * on some platforms, this may need to be re-implemented.
	 */
	local_mac_address(env);
	d = POP(DS);
	if (d) {
		push_a_string(env, "local-mac-address");
		get_inherited_prop(env);
		d = POP(DS);
		if (d == FALSE && TOS == 6)
			return;
		two_drop(env);
	}
	local_ether_addr(env);
}

/*
 * Allow for the programmatic setting of diagnostic-mode?
 */
static int diag_mode_is_valid = 0;
static int diag_mode = 0;

void
set_diagnostic_mode(fcode_env_t *env)
{
	fstack_t d = POP(DS);

	diag_mode = d;
	diag_mode_is_valid = 1;
}

void
push_diagnostic_mode(fcode_env_t *env)
{
	PUSH(DS, (fstack_t)diag_mode);
}

/*
 * 'diagnostic-mode?' - diagnostic-mode? is equivalent to NVRAM 'diag-switch?'
 */
static void
diagnostic_mode(fcode_env_t *env)
{
	char *diag_str;
	int diag_value;

	if (!diag_mode_is_valid) {
		diag_str = get_eeprom_value(env, "diag-switch?");
		if (diag_str != NULL && strcmp(diag_str, "false") == 0)
			diag_value = FALSE;
		else
			diag_value = TRUE;
		PUSH(DS, diag_value);
		set_diagnostic_mode(env);
	}

	push_diagnostic_mode(env);
}

/*
 * May need to implement other memory-access Fcodes here (depending upon
 * abuse), like fill, comp, +!, etc., etc.
 */

#pragma init(_init)

static void
_init(void)
{
	fcode_env_t *env = initial_env;

	mac_addr = MALLOC(MAC_ADDR_SIZE);

	ASSERT(env);
	NOTICE;

	ANSI(0x06e, 0,		"l@",			fcd_lfetch);
	ANSI(0x06f, 0,		"w@",			fcd_wfetch);
	ANSI(0x071, 0,		"c@",			fcd_cfetch);
	ANSI(0x073, 0,		"l!",			fcd_lstore);
	ANSI(0x074, 0,		"w!",			fcd_wstore);
	ANSI(0x075, 0,		"c!",			fcd_cstore);
	ANSI(0x078, 0,		"move",			fcd_move);
	ANSI(0x07a, 0,		"comp",			fcd_comp);

	ANSI(0x120, 0,		"diagnostic-mode?",	diagnostic_mode);

	ANSI(0x1a4, 0,		"mac-address",		mac_address);

	P1275(0x220, 0,		"cpeek",		cpeek);
	P1275(0x221, 0,		"wpeek",		wpeek);
	P1275(0x222, 0,		"lpeek",		lpeek);
	P1275(0x223, 0,		"cpoke",		cpoke);
	P1275(0x224, 0,		"wpoke",		wpoke);
	P1275(0x225, 0,		"lpoke",		lpoke);

	P1275(0x230, 0,		"rb@",			rbfetch);
	P1275(0x231, 0,		"rb!",			rbstore);
	P1275(0x232, 0,		"rw@",			rwfetch);
	P1275(0x233, 0,		"rw!",			rwstore);
	P1275(0x234, 0,		"rl@",			rlfetch);
	P1275(0x235, 0,		"rl!",			rlstore);

	P1275(0x246,	0,	"x@",			fcd_xfetch);
	P1275(0x247,	0,	"x!",			fcd_xstore);

	P1275(0x22e,	0,	"rx@",			rxfetch);
	P1275(0x22f,	0,	"rx!",			rxstore);
	FORTH(0,		"set-diagnostic-mode",	set_diagnostic_mode);
	FORTH(0,		"local-mac-address?",	local_mac_address);
	FORTH(0,		"local-ether-addr",	local_ether_addr);
}
