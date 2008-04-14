/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.
 * All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/file.h>
#include <signal.h>
#include <ucontext.h>
#include <stdio.h>
#include <floatingpoint.h>
#include <locale.h>
#include <unistd.h>
#include <fp.h>
#include <externs.h>
#include <fps_ereport.h>

#define	FPU_ID_MASK 0xCFF02FFF

extern int FPU_cpu;
static int check_conv();
uint_t trap_flag = 0x0;
unsigned int result_lsw;
unsigned int result_msw;
unsigned long fsr_at_trap;

extern unsigned long long_float_d(unsigned long);
extern unsigned long float_long_d(unsigned long);
int fpu_sysdiag(struct fps_test_ereport *report);
int restore_signals();
static int addition_test_dp(struct fps_test_ereport *report);
static int addition_test_sp(struct fps_test_ereport *report);
static int branching(struct fps_test_ereport *report);
static int chain_dp_test(struct fps_test_ereport *report);
static int chain_sp_test(struct fps_test_ereport *report);
static int check_conv(struct fps_test_ereport *report);
static int compare_dp(struct fps_test_ereport *report);
static int compare_dp_except(struct fps_test_ereport *report);
static int compare_sp(struct fps_test_ereport *report);
static int compare_sp_except(struct fps_test_ereport *report);
static int data_path_dp(struct fps_test_ereport *report);
static int data_path_sp(struct fps_test_ereport *report);
static int division_test_dp(struct fps_test_ereport *report);
static int division_test_sp(struct fps_test_ereport *report);
static int double_sing(struct fps_test_ereport *report);
static int fabs_ins_dp(struct fps_test_ereport *report);
static int fabs_ins_sp(struct fps_test_ereport *report);
static int float_to_integer_dp(struct fps_test_ereport *report);
static int float_to_integer_sp(struct fps_test_ereport *report);
static int float_to_long_dp(struct fps_test_ereport *report);
static int float_to_long_sp(struct fps_test_ereport *report);
static int get_negative_value_pn_dp(struct fps_test_ereport *report);
static int get_negative_value_pn_sp(struct fps_test_ereport *report);
static int get_negative_value_np_dp(struct fps_test_ereport *report);
static int get_negative_value_np_sp(struct fps_test_ereport *report);
static int fmovs_ins(struct fps_test_ereport *report);
static int integer_to_float_dp(struct fps_test_ereport *report);
static int integer_to_float_sp(struct fps_test_ereport *report);
static int long_to_float_dp(struct fps_test_ereport *report);
static int long_to_float_sp(struct fps_test_ereport *report);
static int multiplication_test_dp(struct fps_test_ereport *report);
static int multiplication_test_sp(struct fps_test_ereport *report);
static int no_branching(struct fps_test_ereport *report);
static int registers_four(struct fps_test_ereport *report);
static int registers_four_dp(struct fps_test_ereport *report);
static int registers_one(struct fps_test_ereport *report);
static int registers_one_dp(struct fps_test_ereport *report);
static int registers_two(struct fps_test_ereport *report);
static int registers_two_dp(struct fps_test_ereport *report);
static int single_doub(struct fps_test_ereport *report);
static int squareroot_test_dp(struct fps_test_ereport *report);
static int squareroot_test_sp(struct fps_test_ereport *report);
static int subtraction_test_dp(struct fps_test_ereport *report);
static int subtraction_test_sp(struct fps_test_ereport *report);
static int timing_test(struct fps_test_ereport *report);
static void fail_trap(struct fps_test_ereport *report, int flag_num);

/* SIGFPE */
static void	 sigfpe_handler(int, siginfo_t *, ucontext_t *);
static struct sigaction oldfpe, newfpe;

/* SIGSEGV */
static void	 sigsegv_handler(int, siginfo_t *, ucontext_t *);
static struct sigaction oldsegv, newsegv;

/* SIGILL */
static void	 sigill_handler(int, siginfo_t *, ucontext_t *);
static struct sigaction oldill, newill;

/* SIGBUS */
static void	 sigbus_handler(int, siginfo_t *, ucontext_t *);
static struct sigaction oldbus, newbus;

static unsigned int pat[] = {
	0x00000000,
	0x55555555,
	0xAAAAAAAA,
	0xCCCCCCCC,
	0x33333333,
	0xFFFFFFFF,
	0xA5A5A5A5,
	0x3C3C3C3C,
	0xF0F0F0F0,
	0xEEEEEEEE,
	0xDDDDDDDD,
	0xBBBBBBBB,
	0x77777777,
	0x11111111,
	0x22222222,
	0x44444444,
	0x88888888,
	0x66666666,
	0x99999999,
	0x00FF00FF,
	0xFF00FF00,
	0xFFFF0000,
	0x0000FFFF,

};

#define	PAT_NUM	(sizeof (pat)/sizeof (*pat))

/*
 * Double precision patterns
 */
static uint64_t pat_dp[] = {
	0x0000000000000000UL,
	0x5555555555555555UL,
	0xAAAAAAAAAAAAAAAAUL,
	0xCCCCCCCCCCCCCCCCUL,
	0x3333333333333333UL,
	0xFFFFFFFFFFFFFFFFUL,
	0xA5A5A5A5A5A5A5A5UL,
	0x3C3C3C3C3C3C3C3CUL,
	0xF0F0F0F0F0F0F0F0UL,
	0xEEEEEEEEEEEEEEEEUL,
	0xDDDDDDDDDDDDDDDDUL,
	0xBBBBBBBBBBBBBBBBUL,
	0x7777777777777777UL,
	0x1111111111111111UL,
	0x2222222222222222UL,
	0x4444444444444444UL,
	0x8888888888888888UL,
	0x6666666666666666UL,
	0x9999999999999999UL,
	0x00000000FFFFFFFFUL,
	0xFFFFFFFF00000000UL,
	0x0000FFFF0000FFFFUL,
	0xFFFF0000FFFF0000UL
};

#define	PAT_DP_NUM	(sizeof (pat_dp)/sizeof (*pat_dp))

struct value {
	unsigned long floatsingle;
	uint64_t floatdouble;
	uint64_t floatquad_u;
	uint64_t floatquad_l;
};

#define	N_VALS	(sizeof (val)/sizeof (*val))

static struct value val[] = {
	0, 0, 0, 0,
	0x3F800000, 0x3FF0000000000000, 0x3FFF000000000000, 0,
	0x40000000, 0x4000000000000000, 0x4000000000000000, 0,
	0x40400000, 0x4008000000000000, 0x4000800000000000, 0,
	0x40800000, 0x4010000000000000, 0x4001000000000000, 0,
	0x40A00000, 0x4014000000000000, 0x4001400000000000, 0,
	0x40C00000, 0x4018000000000000, 0x4001800000000000, 0,
	0x40E00000, 0x401C000000000000, 0x4001C00000000000, 0,
	0x41000000, 0x4020000000000000, 0x4002000000000000, 0,
	0x41100000, 0x4022000000000000, 0x4002200000000000, 0,
	0x41200000, 0x4024000000000000, 0x4002400000000000, 0,
	0x41300000, 0x4026000000000000, 0x4002600000000000, 0,
	0x41400000, 0x4028000000000000, 0x4002800000000000, 0,
	0x41500000, 0x402A000000000000, 0x4002A00000000000, 0,
	0x41600000, 0x402C000000000000, 0x4002C00000000000, 0,
	0x41700000, 0x402E000000000000, 0x4002E00000000000, 0,
	0x41800000, 0x4030000000000000, 0x4003000000000000, 0,
	0x41880000, 0x4031000000000000, 0x4003100000000000, 0,
	0x41900000, 0x4032000000000000, 0x4003200000000000, 0,
	0x41980000, 0x4033000000000000, 0x4003300000000000, 0,
	0x41a00000, 0x4034000000000000, 0x4003400000000000, 0,
	0x41a80000, 0x4035000000000000, 0x4003500000000000, 0,
	0x41b00000, 0x4036000000000000, 0x4003600000000000, 0,
	0x41b80000, 0x4037000000000000, 0x4003700000000000, 0,
	0x41c00000, 0x4038000000000000, 0x4003800000000000, 0,
	0x41c80000, 0x4039000000000000, 0x4003900000000000, 0,
	0x41d00000, 0x403a000000000000, 0x4003a00000000000, 0,
	0x41d80000, 0x403b000000000000, 0x4003b00000000000, 0,
	0x41e00000, 0x403c000000000000, 0x4003c00000000000, 0,
	0x41e80000, 0x403d000000000000, 0x4003d00000000000, 0,
	0x41f00000, 0x403e000000000000, 0x4003e00000000000, 0,
	0x41f80000, 0x403f000000000000, 0x4003f00000000000, 0,
	0x42000000, 0x4040000000000000, 0x4004000000000000, 0,
	0x42040000, 0x4040800000000000, 0x4004080000000000, 0,
	0x42080000, 0x4041000000000000, 0x4004100000000000, 0,
	0x420c0000, 0x4041800000000000, 0x4004180000000000, 0,
	0x42100000, 0x4042000000000000, 0x4004200000000000, 0,
	0x42140000, 0x4042800000000000, 0x4004280000000000, 0,
	0x42180000, 0x4043000000000000, 0x4004300000000000, 0,
	0x421c0000, 0x4043800000000000, 0x4004380000000000, 0,
	0x42200000, 0x4044000000000000, 0x4004400000000000, 0,
	0x42240000, 0x4044800000000000, 0x4004480000000000, 0,
	0x42280000, 0x4045000000000000, 0x4004500000000000, 0,
	0x422c0000, 0x4045800000000000, 0x4004580000000000, 0,
	0x42300000, 0x4046000000000000, 0x4004600000000000, 0,
	0x42340000, 0x4046800000000000, 0x4004680000000000, 0,
	0x42380000, 0x4047000000000000, 0x4004700000000000, 0,
	0x423c0000, 0x4047800000000000, 0x4004780000000000, 0,
	0x42400000, 0x4048000000000000, 0x4004800000000000, 0,
	0x42440000, 0x4048800000000000, 0x4004880000000000, 0,
	0x42480000, 0x4049000000000000, 0x4004900000000000, 0,
	0x424c0000, 0x4049800000000000, 0x4004980000000000, 0,
	0x42500000, 0x404a000000000000, 0x4004a00000000000, 0,
	0x42540000, 0x404a800000000000, 0x4004a80000000000, 0,
	0x42580000, 0x404b000000000000, 0x4004b00000000000, 0,
	0x425c0000, 0x404b800000000000, 0x4004b80000000000, 0,
	0x42600000, 0x404c000000000000, 0x4004c00000000000, 0,
	0x42640000, 0x404c800000000000, 0x4004c80000000000, 0,
	0x42680000, 0x404d000000000000, 0x4004d00000000000, 0,
	0x426c0000, 0x404d800000000000, 0x4004d80000000000, 0,
	0x42700000, 0x404e000000000000, 0x4004e00000000000, 0,
	0x42740000, 0x404e800000000000, 0x4004e80000000000, 0,
	0x42780000, 0x404f000000000000, 0x4004f00000000000, 0,
	0x427c0000, 0x404f800000000000, 0x4004f80000000000, 0,
	0x42800000, 0x4050000000000000, 0x4005000000000000, 0,
	0x42820000, 0x4050400000000000, 0x4005040000000000, 0,
	0x42840000, 0x4050800000000000, 0x4005080000000000, 0,
	0x42860000, 0x4050c00000000000, 0x40050c0000000000, 0,
	0x42880000, 0x4051000000000000, 0x4005100000000000, 0,
	0x428a0000, 0x4051400000000000, 0x4005140000000000, 0,
	0x428c0000, 0x4051800000000000, 0x4005180000000000, 0,
	0x428e0000, 0x4051c00000000000, 0x40051c0000000000, 0,
	0x42900000, 0x4052000000000000, 0x4005200000000000, 0,
	0x42920000, 0x4052400000000000, 0x4005240000000000, 0,
	0x42940000, 0x4052800000000000, 0x4005280000000000, 0,
	0x42960000, 0x4052c00000000000, 0x40052c0000000000, 0,
	0x42980000, 0x4053000000000000, 0x4005300000000000, 0,
	0x429a0000, 0x4053400000000000, 0x4005340000000000, 0,
	0x429c0000, 0x4053800000000000, 0x4005380000000000, 0,
	0x429e0000, 0x4053c00000000000, 0x40053c0000000000, 0,
	0x42a00000, 0x4054000000000000, 0x4005400000000000, 0,
	0x42a20000, 0x4054400000000000, 0x4005440000000000, 0,
	0x42a40000, 0x4054800000000000, 0x4005480000000000, 0,
	0x42a60000, 0x4054c00000000000, 0x40054c0000000000, 0,
	0x42a80000, 0x4055000000000000, 0x4005500000000000, 0,
	0x42aa0000, 0x4055400000000000, 0x4005540000000000, 0,
	0x42ac0000, 0x4055800000000000, 0x4005580000000000, 0,
	0x42ae0000, 0x4055c00000000000, 0x40055c0000000000, 0,
	0x42b00000, 0x4056000000000000, 0x4005600000000000, 0,
	0x42b20000, 0x4056400000000000, 0x4005640000000000, 0,
	0x42b40000, 0x4056800000000000, 0x4005680000000000, 0,
	0x42b60000, 0x4056c00000000000, 0x40056c0000000000, 0,
	0x42b80000, 0x4057000000000000, 0x4005700000000000, 0,
	0x42ba0000, 0x4057400000000000, 0x4005740000000000, 0,
	0x42bc0000, 0x4057800000000000, 0x4005780000000000, 0,
	0x42be0000, 0x4057c00000000000, 0x40057c0000000000, 0,
	0x42c00000, 0x4058000000000000, 0x4005800000000000, 0,
	0x42c20000, 0x4058400000000000, 0x4005840000000000, 0,
	0x42c40000, 0x4058800000000000, 0x4005880000000000, 0,
	0x42c60000, 0x4058c00000000000, 0x40058c0000000000, 0,
	0x42c80000, 0x4059000000000000, 0x4005900000000000, 0,
	0x42ca0000, 0x4059400000000000, 0x4005940000000000, 0,
	0x42cc0000, 0x4059800000000000, 0x4005980000000000, 0,
	0x42ce0000, 0x4059c00000000000, 0x40059c0000000000, 0,
	0x42d00000, 0x405a000000000000, 0x4005a00000000000, 0,
	0x42d20000, 0x405a400000000000, 0x4005a40000000000, 0,
	0x42d40000, 0x405a800000000000, 0x4005a80000000000, 0,
	0x42d60000, 0x405ac00000000000, 0x4005ac0000000000, 0,
	0x42d80000, 0x405b000000000000, 0x4005b00000000000, 0,
	0x42da0000, 0x405b400000000000, 0x4005b40000000000, 0,
	0x42dc0000, 0x405b800000000000, 0x4005b80000000000, 0,
	0x42de0000, 0x405bc00000000000, 0x4005bc0000000000, 0,
	0x42e00000, 0x405c000000000000, 0x4005c00000000000, 0,
	0x42e20000, 0x405c400000000000, 0x4005c40000000000, 0,
	0x42e40000, 0x405c800000000000, 0x4005c80000000000, 0,
	0x42e60000, 0x405cc00000000000, 0x4005cc0000000000, 0,
	0x42e80000, 0x405d000000000000, 0x4005d00000000000, 0,
	0x42ea0000, 0x405d400000000000, 0x4005d40000000000, 0,
	0x42ec0000, 0x405d800000000000, 0x4005d80000000000, 0,
	0x42ee0000, 0x405dc00000000000, 0x4005dc0000000000, 0,
	0x42f00000, 0x405e000000000000, 0x4005e00000000000, 0,
	0x42f20000, 0x405e400000000000, 0x4005e40000000000, 0,
	0x42f40000, 0x405e800000000000, 0x4005e80000000000, 0,
	0x42f60000, 0x405ec00000000000, 0x4005ec0000000000, 0,
	0x42f80000, 0x405f000000000000, 0x4005f00000000000, 0,
	0x42fa0000, 0x405f400000000000, 0x4005f40000000000, 0,
	0x42fc0000, 0x405f800000000000, 0x4005f80000000000, 0,
	0x42fe0000, 0x405fc00000000000, 0x4005fc0000000000, 0,
	0x43000000, 0x4060000000000000, 0x4006000000000000, 0,
	0x43010000, 0x4060200000000000, 0x4006020000000000, 0,
	0x43020000, 0x4060400000000000, 0x4006040000000000, 0,
	0x43030000, 0x4060600000000000, 0x4006060000000000, 0,
	0x43040000, 0x4060800000000000, 0x4006080000000000, 0,
	0x43050000, 0x4060a00000000000, 0x40060a0000000000, 0,
	0x43060000, 0x4060c00000000000, 0x40060c0000000000, 0,
	0x43070000, 0x4060e00000000000, 0x40060e0000000000, 0,
	0x43080000, 0x4061000000000000, 0x4006100000000000, 0,
	0x43090000, 0x4061200000000000, 0x4006120000000000, 0,
	0x430a0000, 0x4061400000000000, 0x4006140000000000, 0,
	0x430b0000, 0x4061600000000000, 0x4006160000000000, 0,
	0x430c0000, 0x4061800000000000, 0x4006180000000000, 0,
	0x430d0000, 0x4061a00000000000, 0x40061a0000000000, 0,
	0x430e0000, 0x4061c00000000000, 0x40061c0000000000, 0,
	0x430f0000, 0x4061e00000000000, 0x40061e0000000000, 0,
	0x43100000, 0x4062000000000000, 0x4006200000000000, 0,
	0x43110000, 0x4062200000000000, 0x4006220000000000, 0,
	0x43120000, 0x4062400000000000, 0x4006240000000000, 0,
	0x43130000, 0x4062600000000000, 0x4006260000000000, 0,
	0x43140000, 0x4062800000000000, 0x4006280000000000, 0,
	0x43150000, 0x4062a00000000000, 0x40062a0000000000, 0,
	0x43160000, 0x4062c00000000000, 0x40062c0000000000, 0,
	0x43170000, 0x4062e00000000000, 0x40062e0000000000, 0,
	0x43180000, 0x4063000000000000, 0x4006300000000000, 0,
	0x43190000, 0x4063200000000000, 0x4006320000000000, 0,
	0x431a0000, 0x4063400000000000, 0x4006340000000000, 0,
	0x431b0000, 0x4063600000000000, 0x4006360000000000, 0,
	0x431c0000, 0x4063800000000000, 0x4006380000000000, 0,
	0x431d0000, 0x4063a00000000000, 0x40063a0000000000, 0,
	0x431e0000, 0x4063c00000000000, 0x40063c0000000000, 0,
	0x431f0000, 0x4063e00000000000, 0x40063e0000000000, 0,
	0x43200000, 0x4064000000000000, 0x4006400000000000, 0,
	0x43210000, 0x4064200000000000, 0x4006420000000000, 0,
	0x43220000, 0x4064400000000000, 0x4006440000000000, 0,
	0x43230000, 0x4064600000000000, 0x4006460000000000, 0,
	0x43240000, 0x4064800000000000, 0x4006480000000000, 0,
	0x43250000, 0x4064a00000000000, 0x40064a0000000000, 0,
	0x43260000, 0x4064c00000000000, 0x40064c0000000000, 0,
	0x43270000, 0x4064e00000000000, 0x40064e0000000000, 0,
	0x43280000, 0x4065000000000000, 0x4006500000000000, 0,
	0x43290000, 0x4065200000000000, 0x4006520000000000, 0,
	0x432a0000, 0x4065400000000000, 0x4006540000000000, 0,
	0x432b0000, 0x4065600000000000, 0x4006560000000000, 0,
	0x432c0000, 0x4065800000000000, 0x4006580000000000, 0,
	0x432d0000, 0x4065a00000000000, 0x40065a0000000000, 0,
	0x432e0000, 0x4065c00000000000, 0x40065c0000000000, 0,
	0x432f0000, 0x4065e00000000000, 0x40065e0000000000, 0,
	0x43300000, 0x4066000000000000, 0x4006600000000000, 0,
	0x43310000, 0x4066200000000000, 0x4006620000000000, 0,
	0x43320000, 0x4066400000000000, 0x4006640000000000, 0,
	0x43330000, 0x4066600000000000, 0x4006660000000000, 0,
	0x43340000, 0x4066800000000000, 0x4006680000000000, 0,
	0x43350000, 0x4066a00000000000, 0x40066a0000000000, 0,
	0x43360000, 0x4066c00000000000, 0x40066c0000000000, 0,
	0x43370000, 0x4066e00000000000, 0x40066e0000000000, 0,
	0x43380000, 0x4067000000000000, 0x4006700000000000, 0,
	0x43390000, 0x4067200000000000, 0x4006720000000000, 0,
	0x433a0000, 0x4067400000000000, 0x4006740000000000, 0,
	0x433b0000, 0x4067600000000000, 0x4006760000000000, 0,
	0x433c0000, 0x4067800000000000, 0x4006780000000000, 0,
	0x433d0000, 0x4067a00000000000, 0x40067a0000000000, 0,
	0x433e0000, 0x4067c00000000000, 0x40067c0000000000, 0,
	0x433f0000, 0x4067e00000000000, 0x40067e0000000000, 0,
	0x43400000, 0x4068000000000000, 0x4006800000000000, 0,
	0x43410000, 0x4068200000000000, 0x4006820000000000, 0,
	0x43420000, 0x4068400000000000, 0x4006840000000000, 0,
	0x43430000, 0x4068600000000000, 0x4006860000000000, 0,
	0x43440000, 0x4068800000000000, 0x4006880000000000, 0,
	0x43450000, 0x4068a00000000000, 0x40068a0000000000, 0,
	0x43460000, 0x4068c00000000000, 0x40068c0000000000, 0,
	0x43470000, 0x4068e00000000000, 0x40068e0000000000, 0,
	0x43480000, 0x4069000000000000, 0x4006900000000000, 0,
	0x43490000, 0x4069200000000000, 0x4006920000000000, 0,
	0x434a0000, 0x4069400000000000, 0x4006940000000000, 0,
	0x434b0000, 0x4069600000000000, 0x4006960000000000, 0,
	0x434c0000, 0x4069800000000000, 0x4006980000000000, 0,
	0x434d0000, 0x4069a00000000000, 0x40069a0000000000, 0,
	0x434e0000, 0x4069c00000000000, 0x40069c0000000000, 0,
	0x434f0000, 0x4069e00000000000, 0x40069e0000000000, 0,
	0x43500000, 0x406a000000000000, 0x4006a00000000000, 0,
	0x43510000, 0x406a200000000000, 0x4006a20000000000, 0,
	0x43520000, 0x406a400000000000, 0x4006a40000000000, 0,
	0x43530000, 0x406a600000000000, 0x4006a60000000000, 0,
	0x43540000, 0x406a800000000000, 0x4006a80000000000, 0,
	0x43550000, 0x406aa00000000000, 0x4006aa0000000000, 0,
	0x43560000, 0x406ac00000000000, 0x4006ac0000000000, 0,
	0x43570000, 0x406ae00000000000, 0x4006ae0000000000, 0,
	0x43580000, 0x406b000000000000, 0x4006b00000000000, 0,
	0x43590000, 0x406b200000000000, 0x4006b20000000000, 0,
	0x435a0000, 0x406b400000000000, 0x4006b40000000000, 0,
	0x435b0000, 0x406b600000000000, 0x4006b60000000000, 0,
	0x435c0000, 0x406b800000000000, 0x4006b80000000000, 0,
	0x435d0000, 0x406ba00000000000, 0x4006ba0000000000, 0,
	0x435e0000, 0x406bc00000000000, 0x4006bc0000000000, 0,
	0x435f0000, 0x406be00000000000, 0x4006be0000000000, 0,
	0x43600000, 0x406c000000000000, 0x4006c00000000000, 0,
	0x43610000, 0x406c200000000000, 0x4006c20000000000, 0,
	0x43620000, 0x406c400000000000, 0x4006c40000000000, 0,
	0x43630000, 0x406c600000000000, 0x4006c60000000000, 0,
	0x43640000, 0x406c800000000000, 0x4006c80000000000, 0,
	0x43650000, 0x406ca00000000000, 0x4006ca0000000000, 0,
	0x43660000, 0x406cc00000000000, 0x4006cc0000000000, 0,
	0x43670000, 0x406ce00000000000, 0x4006ce0000000000, 0,
	0x43680000, 0x406d000000000000, 0x4006d00000000000, 0,
	0x43690000, 0x406d200000000000, 0x4006d20000000000, 0,
	0x436a0000, 0x406d400000000000, 0x4006d40000000000, 0,
	0x436b0000, 0x406d600000000000, 0x4006d60000000000, 0,
	0x436c0000, 0x406d800000000000, 0x4006d80000000000, 0,
	0x436d0000, 0x406da00000000000, 0x4006da0000000000, 0,
	0x436e0000, 0x406dc00000000000, 0x4006dc0000000000, 0,
	0x436f0000, 0x406de00000000000, 0x4006de0000000000, 0,
	0x43700000, 0x406e000000000000, 0x4006e00000000000, 0,
	0x43710000, 0x406e200000000000, 0x4006e20000000000, 0,
	0x43720000, 0x406e400000000000, 0x4006e40000000000, 0,
	0x43730000, 0x406e600000000000, 0x4006e60000000000, 0,
	0x43740000, 0x406e800000000000, 0x4006e80000000000, 0,
	0x43750000, 0x406ea00000000000, 0x4006ea0000000000, 0,
	0x43760000, 0x406ec00000000000, 0x4006ec0000000000, 0,
	0x43770000, 0x406ee00000000000, 0x4006ee0000000000, 0,
	0x43780000, 0x406f000000000000, 0x4006f00000000000, 0,
	0x43790000, 0x406f200000000000, 0x4006f20000000000, 0,
	0x437a0000, 0x406f400000000000, 0x4006f40000000000, 0,
	0x437b0000, 0x406f600000000000, 0x4006f60000000000, 0,
	0x437c0000, 0x406f800000000000, 0x4006f80000000000, 0,
	0x437d0000, 0x406fa00000000000, 0x4006fa0000000000, 0,
	0x437e0000, 0x406fc00000000000, 0x4006fc0000000000, 0,
	0x437f0000, 0x406fe00000000000, 0x4006fe0000000000, 0,
};

/* -ve of the values in val[] above */
static unsigned long neg_val_sp[N_VALS];
static uint64_t neg_val_dp[N_VALS];

/*
 * data_path_sp(struct fps_test_ereport *report)checks the data path
 * between registers and memory, between memory and an floating
 * registers, and between floating registers and the weitek chips.
 * All the bits are covered including the sign bit. If an error is
 * found, all relevant data is stored in report.
 */
#ifndef i86pc
static int
data_path_sp(struct fps_test_ereport *report)
{
	int i;
	int j;
	int k;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result;
	unsigned long value;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < 2; i++) {
		for (j = 1; j < 255; j++) {
			for (k = 0; k < 23; k++) {
				value = (i << 31) | (j << 23) | (1 << k);

				if (result = datap_add(value)) {
					observed = (uint64_t)result;
					expected = (uint64_t)0;
					setup_fps_test_struct(
					    NO_EREPORT_INFO,
					    report, 6217, &observed,
					    &expected, 1, 1);

					return (-1);
				}
				if (result = datap_mult(value)) {
					observed = (uint64_t)result;
					expected = (uint64_t)0;
					setup_fps_test_struct(
					    NO_EREPORT_INFO,
					    report, 6218, &observed,
					    &expected, 1, 1);

					return (-1);
				}
			}
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * data_path_dp(struct fps_test_ereport *report) performs the
 * same function as data_path_sp except it's double precision
 * instead of single. If an error is found, all relevant data
 * is stored in report.
 */
static int
data_path_dp(struct fps_test_ereport *report)
{
	int i;
	int j;
	int k;
	int l;
	uint64_t observed[2];
	uint64_t expected[2];
	unsigned long prev_fsr;
	unsigned long result_lsw = 0;
	unsigned long result_msw = 0;
	unsigned long value_lsw;
	unsigned long value_msw;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < 2; i++) {
		for (j = 1; j < 2047; j++) {
			for (k = 0; k < 52; k++) {
				value_lsw = (1 << k);

				if (k > 32)
					l = k - 32;
				else
					l = 32;

				value_msw = (i << 31) | (j << 20) | (1 << l);

				if (datap_add_dp(value_msw, value_lsw)) {
					observed[0] = (uint64_t)result_msw;
					observed[1] = (uint64_t)result_lsw;
					expected[0] = (uint64_t)value_msw;
					expected[1] = (uint64_t)value_lsw;
					setup_fps_test_struct(
					    NO_EREPORT_INFO, report,
					    6219, observed, expected,
					    2, 2);

					return (-1);
				}

				if (datap_mult_dp(value_msw, value_lsw)) {
					observed[0] = (uint64_t)result_msw;
					observed[1] = (uint64_t)result_lsw;
					expected[0] = (uint64_t)value_msw;
					expected[1] = (uint64_t)value_lsw;
					setup_fps_test_struct(
					    NO_EREPORT_INFO, report,
					    6220, observed, expected,
					    2, 2);

					return (-1);
				}
			}
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * timing_test(struct fps_test_ereport *report) does 10 add
 * operations continuously and 10 multiply operations
 * continusously. If an error is found, relevant data is
 * stored in report.
 */
static int
timing_test(struct fps_test_ereport *report)
{
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	for (i = 0; i < 1000; i++) {
		init_regs(0);
		if (result = timing_add_sp()) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6221, &observed, &expected, 1, 1);

			return (-1);
		}

		init_regs(0);

		if (result = timing_mult_sp()) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6222, &observed, &expected, 1, 1);

			return (-1);
		}

		init_regs(0);

		if (result = timing_add_dp()) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6223, &observed, &expected, 1, 1);

			return (-1);
		}

		init_regs(0);

		if (result = timing_mult_dp()) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6224, &observed, &expected, 1, 1);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * chain_sp_test(struct fps_test_ereport *report)
 * performs a series of single precision chaining
 * tests. If an error is found, relevant data is
 * stored in report.
 */
static int
chain_sp_test(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t result;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();
	init_regs(0);
	set_fsr(0);

	for (i = 1; i < 60; i++) {
		if ((result = chain_sp(i)) != (unsigned long) i) {
			observed = (uint64_t)result;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %d\nObserved: %d", i, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6225, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * chain_dp_test(struct fps_test_ereport *report)
 * performs a series of double precision chaining
 * tests. If an error is found, relevant data is
 * stored in report.
 */
static int
chain_dp_test(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t result;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();
	init_regs(0);
	set_fsr(0);

	for (i = 1; i < 60; i++) {
		if ((result = chain_dp(i)) != (unsigned long) i) {
			observed = (uint64_t)result;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %d\nObserved: %d", i, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6226, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * integer_to_float_sp(struct fps_test_ereport *report)
 * does continuous integer to float, single precision
 * conversions. If an error is found, relevant data is stored
 * in report.
 */
static int
integer_to_float_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = int_float_s(i);
		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, val[i].floatsingle,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6227, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * integer_to_float_dp(struct fps_test_ereport *report)
 * does continuous integer to float, double precision
 * conversions. If an error is found, relevant data is stored
 * in report.
 */
static int
integer_to_float_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = int_float_d(i);
		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i, val[i].floatdouble,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6228, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * long_to_float_sp(struct fps_test_ereport *report)
 * performs continuous, single precision, unsigned
 * long to float conversions. If an error is found,
 * relevant data is stored in report.
 */
static int
long_to_float_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t expected;
	uint64_t observed;
	unsigned long i;
	unsigned long prev_fsr;
	unsigned long result;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = long_float_s(i);
		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, val[i].floatdouble,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6353, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * long_to_float_dp(struct fps_test_ereport *report)
 * performs continuous, double precision, unsigned
 * long to float conversions. If an error is found,
 * relevant data is stored in report.
 */
static int
long_to_float_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t expected;
	uint64_t observed;
	unsigned long i;
	unsigned long prev_fsr;
	unsigned long res1;

	prev_fsr = get_fsr();
	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		res1 = long_float_d(i);
		if (res1 != val[i].floatdouble) {
			observed = (uint64_t)res1;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i, val[i].floatdouble,
			    res1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6354, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * float_to_integer_sp(struct fps_test_ereport *report)
 * performs continuous, single precision float to
 * integer conversions. If an error is found, relevant
 * data is stored in report.
 */
static int
float_to_integer_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t i;
	unsigned long prev_fsr;
	unsigned long result;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = float_int_s(val[i].floatsingle);
		if (result != i) {
			observed = (uint64_t)result;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, i,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6229, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	/*
	 * Value greater than highest representable value in int has to raise
	 * an invalid exception.
	 *
	 * Highest possible value in int (assume uint) is 2^32; Use 2^33 for a
	 * value greater.
	 */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);

	/* Set trap flag to solicited */
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(0x50000000);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstoi max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x50000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5307, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstoi max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x50000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5308, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	/* NaNs should raise an exception when converted */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(nan_sp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstoi NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5309, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstoi NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5310, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	/* + infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(PLUS_INF_SP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstoi +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5311, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstoi +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5312, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	/* - infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(MINUS_INF_SP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstoi -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5313, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstoi -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5314, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	/* Check for inexact exception raised because of fractions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NX);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(pi_sp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstoi inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5315, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NX) != FSR_CEXC_NX) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NX;
		expected = (uint64_t)FSR_CEXC_NX;
		snprintf(err_data, sizeof (err_data),
		    "fstoi inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5316, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * float_to_integer_dp(struct fps_test_ereport *report)
 * performs continuous, double precision float to
 * integer conversions. If an error is found, relevant
 * data is stored in report.
 */
static int
float_to_integer_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long res1;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 0; i < N_VALS; i++) {
		res1 = float_int_d(val[i].floatdouble);

		if (res1 != i) {
			observed = (uint64_t)res1;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, i,
			    res1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6230, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	/*
	 * Value greater than highest representable value in int has to raise
	 * an invalid exception.
	 *
	 * Highest possible value in int (assume uint) is 2^32; Use 2^33 for a
	 * value greater.
	 */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_d(0x4200000000000000);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi max value exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    0x4200000000000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5317, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi max value exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    0x4200000000000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5318, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* NaNs should raise an exception when converted */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_d(nan_dp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi NaN exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    nan_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5319, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi NaN exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    nan_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5320, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* + infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_d(PLUS_INF_DP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi +infinity exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    PLUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5321, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi +infinity exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    PLUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5322, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* - infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_d(MINUS_INF_DP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi -infinity exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    MINUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5323, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi -infinity exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    MINUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5324, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* Check for inexact exception raised because of fractions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NX);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_d(pi_dp);
	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi inexact exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    pi_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5325, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NX) != FSR_CEXC_NX) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NX;
		expected = (uint64_t)FSR_CEXC_NX;
		snprintf(err_data, sizeof (err_data),
		    "fdtoi inexact exception not raised, "
		    "fp val=%llx, fsr=%lx",
		    pi_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5326, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * float_to_long_sp(struct fps_test_ereport *report)
 * does continuous, single precision, float to long
 * conversions. If an error is found, relevant data
 * is stored in report.
 */
static int
float_to_long_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = float_long_s(val[i].floatsingle);

		if (result != i) {
			observed = (uint64_t)result;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, i,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6352, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	/*
	 * Value greater than highest representable value in int has to raise
	 * an invalid exception.
	 *
	 * Highest possible value in int (assume uint) is 2^64; Use 2^65 for a
	 * value greater.
	 */

	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_s(0x60000000);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstox max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x60000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5327, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstox max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x50000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5328, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* NaNs should raise an exception when converted */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_s(nan_sp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstox NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5329, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstox NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5330, &observed, &expected, 1, 1,
		    err_data);

		return (-1);
	}

	/* + infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_s(PLUS_INF_SP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstox +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5331, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstox +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5332, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* - infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_s(MINUS_INF_SP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstox -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5333, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fstox -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_SP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5334, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* Check for inexact exception raised because of fractions */

	set_fsr(prev_fsr | FSR_ENABLE_TEM_NX);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_int_s(pi_sp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fstox inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5335, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NX) != FSR_CEXC_NX) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NX;
		expected = (uint64_t)FSR_CEXC_NX;
		snprintf(err_data, sizeof (err_data),
		    "fstox inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_sp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5336, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * float_to_long_dp(struct fps_test_ereport *report)
 * does continuous, double precision, float to long
 * conversions. If an error is found, relevant data
 * is stored in report.
 */
static int
float_to_long_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long res1;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		res1 = float_long_d(val[i].floatdouble);

		if (res1 != i) {
			observed = (uint64_t)res1;
			expected = (uint64_t)i;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, i,
			    res1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6351, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	/*
	 * Value greater than highest representable value in long has to
	 * raise an invalid exception.
	 *
	 * Highest possible value in long (assume ulong) is 2^64; Use 2^65 for a
	 * value greater.
	 */

	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_d(0x4400000000000000);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtox max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x4400000000000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5337, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtox max value exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    0x4200000000000000, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5338, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* NaNs should raise an exception when converted */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_d(nan_dp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtox NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5339, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtox NaN exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    nan_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5340, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* + infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_d(PLUS_INF_DP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtox +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5341, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtox +infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    PLUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5342, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* - infinity exceptions */
	set_fsr(prev_fsr | FSR_ENABLE_TEM_NV);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_d(MINUS_INF_DP);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtox -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5343, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
		expected = (uint64_t)FSR_CEXC_NV;
		snprintf(err_data, sizeof (err_data),
		    "fdtox -infinity exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    MINUS_INF_DP, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5344, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	/* Check for inexact exception raised because of fractions */

	set_fsr(prev_fsr | FSR_ENABLE_TEM_NX);
	trap_flag = trap_flag | TRAP_SOLICITED;

	float_long_d(pi_dp);

	if (trap_flag) {
		observed = (uint64_t)trap_flag;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "fdtox inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5345, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	if ((fsr_at_trap & FSR_CEXC_NX) != FSR_CEXC_NX) {
		observed = (uint64_t)fsr_at_trap & FSR_CEXC_NX;
		expected = (uint64_t)FSR_CEXC_NX;
		snprintf(err_data, sizeof (err_data),
		    "fdtox inexact exception not raised, "
		    "fp val=%lx, fsr=%lx",
		    pi_dp, fsr_at_trap);
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 5346, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * single_doub(struct fps_test_ereport *report)
 * does continues single to double conversion.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
single_doub(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result;


	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = convert_sp_dp(val[i].floatsingle);

		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i,
			    val[i].floatdouble, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6231, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);

	return (0);
}

/*
 * double_sing(struct fps_test_ereport *report)
 * does continues double to single conversion.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
double_sing(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = convert_dp_sp(val[i].floatdouble);

		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i,
			    val[i].floatsingle, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6232, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * fmovs_ins(struct fps_test_ereport *report)
 * moves a value through the floating point
 * registers. If an error is found, relevant
 * data is stored
 * in report.
 */
static int
fmovs_ins(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	uint64_t observed;
	uint64_t expected;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);

	if ((result = move_regs(0x3F800000)) != 0x3F800000) {
		observed = (uint64_t)result;
		expected = (uint64_t)0x3F800000;
		snprintf(err_data, sizeof (err_data),
		    "Wrote to f0, read from f31");
		setup_fps_test_struct(IS_EREPORT_INFO,
		    report, 6233, &observed, &expected, 1,
		    1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * get_negative_value_pn_sp(struct fps_test_ereport *report)
 * converts single precision postive to negative values.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
get_negative_value_pn_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long prev_fsr;
	unsigned long result;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = negate_value_sp(val[i].floatsingle);
		if (result != neg_val_sp[i]) {
			observed = (uint64_t)result;
			expected = (uint64_t)neg_val_sp[i];
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, neg_val_sp[i],
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6234, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * get_negative_value_pn_dp(struct fps_test_ereport *report)
 * converts double precision postive to negative values.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
get_negative_value_pn_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	uint64_t result;

	init_regs_dp(0);

	for (i = 0; i < N_VALS; i++) {
		result = negate_value_dp(val[i].floatdouble);
		if (result != neg_val_dp[i]) {
			observed = (uint64_t)result;
			expected = (uint64_t)neg_val_dp[i];
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i, neg_val_dp[i],
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6362, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * get_negative_value_np_sp(struct fps_test_ereport *report)
 * converts single precision negative to positive values.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
get_negative_value_np_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < N_VALS; i++) {
		result = negate_value_sp(neg_val_sp[i]);

		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, val[i].floatsingle,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6235, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * get_negative_value_np_dp(struct fps_test_ereport *report)
 * converts double precision negative to positive values.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
get_negative_value_np_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	uint64_t result;

	init_regs_dp(0);

	for (i = 0; i < N_VALS; i++) {
		result = negate_value_dp(neg_val_dp[i]);

		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i, val[i].floatdouble,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6363, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * fabs_ins_sp(struct fps_test_ereport *report)
 * does single precision absolute value testing.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
fabs_ins_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 0; i < N_VALS; i++) {
		result = absolute_value_sp(neg_val_sp[i]);
		if (result != val[i].floatsingle) {
			observed = *(uint64_t *)&result;
			expected = *(uint64_t *)&(val[i].floatsingle);
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %d"
			    "\nObserved: %d", i, val[i].floatsingle,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6236, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * fabs_ins_dp(struct fps_test_ereport *report)
 * does double precision absolute value testing.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
fabs_ins_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	uint64_t result;

	init_regs_dp(0);

	for (i = 0; i < N_VALS; i++) {
		result = absolute_value_dp(neg_val_dp[i]);

		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d]\nExpected: %lld"
			    "\nObserved: %lld", i, val[i].floatdouble,
			    result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6361, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * addition_test_sp(struct fps_test_ereport *report)
 * tests single precision addition using floating
 * point registers (f4=f0+f2).
 * If an error is found, relevant data is stored
 * in report.
 */
static int
addition_test_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 0; i < (N_VALS - 1); i++) {
		result = add_sp(val[i].floatsingle, val[1].floatsingle);

		if (result != (val[i + 1].floatsingle)) {

			observed = (uint64_t)result;
			expected = (uint64_t)val[i + 1].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0+f2"
			    "\nExpected: %d\nObserved: %d",
			    i, val[i + 1].floatsingle, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6237, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * addition_test_dp(struct fps_test_ereport *report)
 * tests double precision addition using floating
 * point registers (f4=f0+f2).
 * If an error is found, relevant data is stored
 * in report.
 */
static int
addition_test_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 0; i < (N_VALS - 1); i++) {
		result = add_dp(val[i].floatdouble, val[1].floatdouble);

		if (result != (val[i + 1].floatdouble)) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i + 1].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0+f2"
			    "\nExpected: %lld\nObserved: %lld",
			    i, val[i + 1].floatdouble, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6238, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * subtraction_test_sp(struct fps_test_ereport *report)
 * tests single precision subtaction using floating
 * point registers (f4=f0-f2).
 * If an error is found, relevant data is stored
 * in report.
 */
static int
subtraction_test_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 1; i < N_VALS; i++) {
		result = sub_sp(val[i].floatsingle, val[i - 1].floatsingle);

		if (result != val[1].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[1].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0-f2"
			    "\nExpected: %d\nObserved: %d",
			    i, val[1].floatsingle, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6239, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * subtraction_test_dp(struct fps_test_ereport *report)
 * tests double precision subtaction using floating
 * point registers (f4=f0-f2).
 * If an error is found, relevant data is stored
 * in report.
 */
static int
subtraction_test_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 1; i < N_VALS; i++) {
		result = sub_dp(val[i].floatdouble, val[i - 1].floatdouble);

		if (result != val[1].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[1].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0-f2"
			    "\nExpected: %lld\nObserved: %lld",
			    i, val[1].floatdouble, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6240, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * squareroot_test_sp(struct fps_test_ereport *report)
 * tests single precision squareroot.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
squareroot_test_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long result, workvalue;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 1; i < N_VALS; i++) {
		workvalue = val[i].floatsingle;
		result = sqrt_sp(mult_sp(workvalue, workvalue));
		if (result != workvalue) {
			observed = (uint64_t)result;
			expected = (uint64_t)workvalue;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %d\nObserved: %d", workvalue,
			    result);
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6241, &observed, &expected, 1, 1);

			return (-1);
		}
	}

	/* fsqrt(x), where x>0, should be positive */
	result = sqrt_sp(half_sp);

	if (result & SIGN_FLAG_SP) {
		observed = (uint64_t)result & SIGN_FLAG_SP;
		expected = (uint64_t)0;
		setup_fps_test_struct(NO_EREPORT_INFO,
		    report, 8241, &observed, &expected, 1, 1);

		return (-1);
	}

	/* fsqrt(-0)=-0. */
	result = sqrt_sp(MINUS_ZERO_SP);

	if (!(result & MINUS_ZERO_SP)) {
		observed = (uint64_t)0;
		expected = (uint64_t)1;
		setup_fps_test_struct(NO_EREPORT_INFO,
		    report, 8242, &observed, &expected, 1, 1);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * squareroot_test_dp(struct fps_test_ereport *report)
 * tests double precision squareroot.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
squareroot_test_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long half_dp;
	unsigned long result;
	unsigned long workvalue;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);

	for (i = 1; i < N_VALS; i++) {
		workvalue = val[i].floatdouble;
		result = sqrt_dp(mult_dp(workvalue, workvalue));

		if (result != workvalue) {
			observed = (uint64_t)result;
			expected = (uint64_t)workvalue;
			snprintf(err_data, sizeof (err_data),
			    "\nExpected: %lld\nObserved: %lld", workvalue,
			    result);
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6242, &observed, &expected, 1, 1);

			return (-1);
		}
	}

	/* fsqrt(x), where x>0, should be positive */
	workvalue = half_msw;
	half_dp = workvalue << 32;
	half_dp = half_dp | half_lsw;
	result = sqrt_dp(half_dp);

	if (result & SIGN_FLAG_DP) {
		observed = (uint64_t)result & SIGN_FLAG_DP;
		expected = (uint64_t)0;
		setup_fps_test_struct(NO_EREPORT_INFO,
		    report, 8243, &observed, &expected, 1, 1);

		return (-1);
	}

	/* fsqrt(-0)=-0 */
	result = sqrt_dp(MINUS_ZERO_DP);

	if (!(result & MINUS_ZERO_DP)) {
		observed = (uint64_t)0;
		expected = (uint64_t)1;
		setup_fps_test_struct(NO_EREPORT_INFO,
		    report, 8244, &observed, &expected, 1, 1);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * division_test_sp(struct fps_test_ereport *report)
 * tests single precision division through registers.
 * (reg f4=f0/f2). If an error is found, relevant data
 * is stored in report.
 */
static int
division_test_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 1; i < N_VALS; i++) {
		result = div_sp(val[i].floatsingle, val[1].floatsingle);

		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0/f2"
			    "\nExpected: %d\nObserved: %d",
			    i, val[i].floatsingle, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6243, &observed, &expected, 1,
			    1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * division_test_dp(struct fps_test_ereport *report)
 * tests double precision division through registers.
 * (reg f4=f0/f2). If an error is found, relevant data
 * is stored in report.
 */
static int
division_test_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 1; i < N_VALS; i++) {
		result = div_dp(val[i].floatdouble, val[1].floatdouble);

		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0/f2"
			    "\nExpected: %lld\nObserved: %lld",
			    i, val[i].floatdouble, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6244, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * multiplication_test_sp(struct fps_test_ereport *report)
 * tests single precision multiplication through registers.
 * (reg f4=f0*f2). If an error is found, relevant data
 * is stored in report.
 */
static int
multiplication_test_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 0; i < N_VALS; i++) {
		result = mult_sp(val[i].floatsingle, val[1].floatsingle);

		if (result != val[i].floatsingle) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatsingle;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0*f2"
			    "\nExpected: %d\nObserved: %d",
			    i, val[i].floatsingle, result);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6245, &observed, &expected, 1, 1, err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * multiplication_test_dp(struct fps_test_ereport *report)
 * tests double precision multiplication through registers.
 * (reg f4=f0*f2). If an error is found, relevant data
 * is stored in report.
 */
static int
multiplication_test_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long result;
	unsigned long prev_fsr;

	prev_fsr = get_fsr();

	init_regs(0);
	for (i = 0; i < N_VALS; i++) {
		result = mult_dp(val[i].floatdouble, val[1].floatdouble);

		if (result != val[i].floatdouble) {
			observed = (uint64_t)result;
			expected = (uint64_t)val[i].floatdouble;
			snprintf(err_data, sizeof (err_data),
			    "Val Entry[%d], reg f4=f0*f2"
			    "\nExpected: %lld\nObserved: %lld",
			    i, val[i].floatdouble, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6246, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * compare_sp(struct fps_test_ereport *report)
 * performs single precision comparison tests.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
compare_sp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long prev_fsr;
	unsigned long result = 0;

	prev_fsr = get_fsr();
	set_fsr(prev_fsr & FSR_DISABLE_TEM);
	init_regs(0);

	for (i = 0; i < (N_VALS - 1); i++) {
#ifndef __lint
		result = fcmps_fcc(val[i].floatsingle, val[i].floatsingle, 0);
#endif

		if ((result & 0xc00) != 0) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6247, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

#ifndef __lint
		result = fcmps_fcc(val[i].floatsingle,
		    val[i + 1].floatsingle, 0);
#endif
		if ((result & 0xc00) != 0x400) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0x400;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6248, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

#ifndef __lint
		result = fcmps_fcc(val[i + 1].floatsingle,
		    val[i].floatsingle, 0);
#endif

		if ((result & 0xc00) != 0x800) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0x800;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6249, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

		set_fsr(prev_fsr & FSR_DISABLE_TEM);
#ifndef __lint
		result = fcmps_fcc(val[i].floatsingle, 0x7f800400, 0);
#endif

		if ((result & 0xc00) != 0xc00) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0xc00;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= NaN", i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6250, &observed, &expected, 1, 1, err_data);

			return (-1);
		}
	}

	/* Compare +/-zero and check if the comparision is okay */

	result = fcmps_fcc(MINUS_ZERO_SP, PLUS_ZERO_SP, 0);

	if (result & 0xc00) {
		observed = (uint64_t)result & 0xc00;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "f0= %d, f2= %d", +0, -0);
		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    8251, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * compare_dp(struct fps_test_ereport *report)
 * performs double precision comparison tests.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
compare_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_fsr;
	uint64_t observed;
	uint64_t expected;

	prev_fsr = get_fsr();
	set_fsr(prev_fsr & FSR_DISABLE_TEM);

	init_regs(0);

	for (i = 0; i < (N_VALS - 1); i++) {
		result = fcmpd_fcc(val[i].floatdouble, val[i].floatdouble, 0);
		if ((result & 0xc00) != 0) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6251, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

		result = fcmpd_fcc(val[i].floatdouble,
		    val[i + 1].floatdouble, 0);

		if ((result & 0xc00) != 0x400) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0x400;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6252, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

		result = fcmpd_fcc(val[i + 1].floatdouble,
		    val[i].floatdouble, 0);

		if ((result & 0xc00) != 0x800) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0x800;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6253, &observed, &expected, 1, 1, err_data);

			return (-1);
		}

		set_fsr(prev_fsr & FSR_DISABLE_TEM);
		result = fcmpd_fcc(val[i].floatdouble, 0x7ff0008000000000, 0);

		if ((result & 0xc00) != 0xc00) {
			observed = (uint64_t)result & 0xc00;
			expected = (uint64_t)0xc00;
			snprintf(err_data, sizeof (err_data),
			    "f0= %d, f2=NaN", i);
			setup_fps_test_struct(IS_EREPORT_INFO, report,
			    6254, &observed, &expected, 1, 1, err_data);

			return (-1);
		}
	}
	/* Compare +/-zero and check if the comparision is okay */

	result = fcmpd_fcc(MINUS_ZERO_DP, PLUS_ZERO_DP, 0);

	if (result & 0xc00) {
		observed = (uint64_t)result & 0xc00;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "f0= %d, f2= %d", +0, -0);
		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    8252, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	set_fsr(prev_fsr);
	return (0);
}

/*
 * branching(struct fps_test_ereport *report)
 * performs branch testing. If an error is found,
 * relevant data is stored in report.
 */
static int
branching(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_status;
	uint64_t observed;
	uint64_t expected;

	prev_status = get_fsr();
	init_regs(0);
	result = get_fsr();
	result = result & 0xC0400000;	/* set all exception bits to zero */
	set_fsr(result);

	for (i = 0; i < 64; i++) {
		if (result = branches(0, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6255, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(1, val[i + 1].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6256, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(2, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6257, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(2, val[i + 1].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6258, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(3, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d and f2= %d ", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6259, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(4, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6260, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(4, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6261, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(5, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6262, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(5, val[i + 1].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6263, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(6, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6264, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(7, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6265, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(8, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6266, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(8, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6267, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
		if (result = branches(9, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6268, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
		if (result = branches(9, val[i + 1].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6269, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(10, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6270, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(10, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6271, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(10, val[i + 1].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6272, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(11, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6273, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(11, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6274, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(12, val[i].floatsingle, 0x7f800400)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6275, &observed, &expected, 1, 1);

			return (-1);
		}

		if (result = branches(12, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6276, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(12, val[i].floatsingle,
		    val[i].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6277, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(13, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6278, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(14, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6279, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (result = branches(15, val[i].floatsingle,
		    val[i + 1].floatsingle)) {
			observed = (uint64_t)result;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d ", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6280, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_status);
	return (0);

}

/*
 * branching(struct fps_test_ereport *report)
 * performs negative branch testing. If an error is found,
 * relevant data is stored in report.
 */
static int
no_branching(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t observed;
	uint64_t expected;
	unsigned long result;
	unsigned long prev_status;

	prev_status = get_fsr();
	init_regs(0);
	result = get_fsr();
	result = result & 0xC0400000;	/* set all exception bits to zero */
	set_fsr(result);

	for (i = 0; i < 64; i++) {
		if (!(branches(0, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6281, &observed, &expected, 1, 1);

			return (-1);
		}

		if (!(branches(1, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6282, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(2, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6283, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(3, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6284, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(4, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6285, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(5, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6286, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(6, val[i].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6287, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(7, val[i + 1].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6288, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(8, val[i + 1].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6289, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(9, val[i].floatsingle,
		    val[i + 1].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6290, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(10, val[i].floatsingle,
		    val[i + 1].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i, i+1);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6291, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(11, val[i + 1].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6292, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(branches(12, val[i + 1].floatsingle,
		    val[i].floatsingle))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			snprintf(err_data, sizeof (err_data),
			    "reg f0= %d, f2= %d", i+1, i);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6293, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}

		if (!(result = branches(13, val[i].floatsingle, 0x7f800400))) {
			observed = (uint64_t)0;
			expected = (uint64_t)1;
			setup_fps_test_struct(NO_EREPORT_INFO,
			    report, 6294, &observed, &expected, 1, 1);

			return (-1);
		}

	}

	set_fsr(prev_status);

	return (0);
}

/*
 * compare_sp_except(struct fps_test_ereport *report)
 * does single precision exception testing.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
compare_sp_except(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_status;
	uint64_t observed;
	uint64_t expected;

	prev_status = get_fsr();
	init_regs(0);
	result = get_fsr();
	result = result | FSR_ENABLE_TEM_NV;

	set_fsr(result);

	for (i = 0; i < N_VALS; i++) {

		trap_flag = trap_flag | TRAP_SOLICITED;
		result = cmp_s_ex(val[i].floatsingle, 0x7fbfffff);
		if (trap_flag) {
			observed = (uint64_t)trap_flag;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "fcmpxs exception did not occur, fsr=%lo",
			    fsr_at_trap);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6295, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
		if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
			observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
			expected = (uint64_t)FSR_CEXC_NV;
			snprintf(err_data, sizeof (err_data),
			    "fcmpxs exception did not occur, fsr=%lo",
			    fsr_at_trap);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6296, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_status);
	return (0);
}

/*
 * compare_dp_except(struct fps_test_ereport *report)
 * does double precision exception testing.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
compare_dp_except(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned long result;
	unsigned long prev_status;
	uint64_t observed;
	uint64_t expected;

	prev_status = get_fsr();
	init_regs(0);
	result = get_fsr();
	result = result | FSR_ENABLE_TEM_NV;
	set_fsr(result);

	for (i = 0; i < 199; i++) {

		trap_flag = trap_flag | TRAP_SOLICITED;
		result = cmp_d_ex(val[i].floatdouble, 0x7ff0008000000000);
		if (trap_flag) {
			observed = (uint64_t)trap_flag;
			expected = (uint64_t)0;
			snprintf(err_data, sizeof (err_data),
			    "fcmpxd exception did not occur, fsr=%lo",
			    fsr_at_trap);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6297, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
		if ((fsr_at_trap & FSR_CEXC_NV) != FSR_CEXC_NV) {
			observed = (uint64_t)fsr_at_trap & FSR_CEXC_NV;
			expected = (uint64_t)FSR_CEXC_NV;
			snprintf(err_data, sizeof (err_data),
			    "fcmpxd exception did not occur, fsr=%lo",
			    fsr_at_trap);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6298, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	set_fsr(prev_status);
	return (0);
}

/*
 * Patterns used in the registers functions that are.
 * loaded into all registers.
 */

#define	ALLZEROES_DP	0x0000000000000000UL
#define	ALLZEROES_SP 	0x00000000U
#define	ALLONES_DP		0xFFFFFFFFFFFFFFFFUL
#define	ALLONES_SP		0xFFFFFFFFU

/*
 * registers_four(struct fps_test_ereport *report)
 * loads each nibble with 0xf on all the available FP
 * registers in single precision.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
registers_four(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	unsigned int result = 0;
	uint64_t observed;
	uint64_t expected;

#define	ARB_VAL 4

	for (i = 0; i < ARB_VAL; i++) {
		init_regs(ALLZEROES_SP);
		init_regs(ALLONES_SP);
	}

	init_regs(ALLZEROES_SP);
	for (i = 0; i < 32; i++) {
		read_fpreg(&result, i);
		if (result != ALLZEROES_SP) {
			observed = (uint64_t)result;
			expected = (uint64_t)ALLZEROES_SP;
			snprintf(err_data, sizeof (err_data),
			    "Reg: %d\nExpected: %d\nObserved: %d",
			    i, ALLZEROES_SP, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6345, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	init_regs(ALLONES_SP);

	for (i = 0; i < 32; i++) {
		read_fpreg(&result, i);
		if (result != ALLONES_SP) {
			observed = (uint64_t)result;
			expected = (uint64_t)ALLONES_SP;
			snprintf(err_data, sizeof (err_data),
			    "Reg: %d\nExpected: %d\nObserved: %d",
			    i, ALLONES_SP, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 8345, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * registers_four_dp(struct fps_test_ereport *report)
 * loads each nibble with 0xf on all the available FP
 * registers in double precision.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
registers_four_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	uint64_t expected;
	uint64_t observed;
	unsigned long result;

#define	ARB_VAL 4

	for (i = 0; i < ARB_VAL; i++) {
		init_regs_dp(ALLZEROES_DP);
		init_regs_dp(ALLONES_DP);
	}

	init_regs_dp(16);
	read_fpreg_dp(&result, 2);
	init_regs_dp(ALLZEROES_DP);
	for (i = 0; i < 64; i = i + 2) {
		result = ALLONES_DP;
		read_fpreg_dp(&result, i);
		if (result != ALLZEROES_DP) {
			observed = (uint64_t)result;
			expected = (uint64_t)ALLZEROES_DP;
			snprintf(err_data, sizeof (err_data),
			    "Reg: %d\nExpected: %lld\nObserved: %lld",
			    i, ALLZEROES_DP, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 6346, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	init_regs_dp(ALLONES_DP);

	for (i = 30; i < 64; i = i + 2) {
		read_fpreg_dp(&result, i);
		if (result != ALLONES_DP) {
			observed = (uint64_t)result;
			expected = (uint64_t)ALLONES_DP;
			snprintf(err_data, sizeof (err_data),
			    "Reg: %d\nExpected: %lld\nObserved: %lld",
			    i, ALLONES_DP, result);
			setup_fps_test_struct(IS_EREPORT_INFO,
			    report, 8346, &observed, &expected, 1, 1,
			    err_data);

			return (-1);
		}
	}

	return (0);
}

/*
 * registers_two(struct fps_test_ereport *report)
 * tests single precision rotating ones through the
 * floating point registers. If an error is found,
 * relevant data is stored in report.
 */
static int
registers_two(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int j;
	uint64_t expected;
	uint64_t observed;
	unsigned int result;
	unsigned int value;

	for (j = 0; j < 32; j++) {
		for (i = 0; i < 32; i++) {
			value = (1 << i);
			if ((result = register_test(j, value)) != value) {
				observed = (uint64_t)result;
				expected = (uint64_t)value;
				snprintf(err_data, sizeof (err_data),
				    "Reg: %d\nExpected: %d\nObserved: %d",
				    j, value, result);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 6301, &observed, &expected, 1,
				    1, err_data);

				return (-1);
			}
		}
	}

	return (0);
}

/*
 * registers_two_dp(struct fps_test_ereport *report)
 * tests double precision rotating ones through the
 * floating point registers. If an error is found,
 * relevant data is stored in report.
 */
static int
registers_two_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int j;
	uint64_t observed;
	uint64_t expected;
	unsigned long result;
	unsigned long value;

	for (j = 0; j < 32; j = j + 2) {
		for (i = 0; i < 64; i++) {
			value = (1 << i);
			result = register_test_dp(j, value);

			if (result != value) {
				observed = (*(uint64_t *)&result);
				expected = (*(uint64_t *)&value);
				snprintf(err_data, sizeof (err_data),
				    "Reg: %d\nExpected: %lld\nObserved: %lld",
				    j, value, result);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 5301, &observed, &expected, 1,
				    1, err_data);
				return (-1);
			}
		}
	}

	return (0);
}

/*
 * registers_one(struct fps_test_ereport *report)
 * passes a single precision pattern through the
 * floating point registers. If an error is found,
 * relevant data is stored in report.
 */
static int
registers_one(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int j;
	unsigned int	result;

	uint64_t observed;
	uint64_t expected;

	for (i = 0; i < 32; i++) {
		for (j = 0; j < PAT_NUM; j++) {
			result = register_test(i, pat[j]);
			if (result != pat[j]) {
				observed = (uint64_t)result;
				expected = (uint64_t)pat[j];
				snprintf(err_data, sizeof (err_data),
				    "Reg: %d\nExpected: %d\nObserved: %d",
				    i, pat[j], result);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 6302, &observed, &expected, 1,
				    1, err_data);

				return (-1);
			}
		}
	}

	return (0);
}

/*
 * registers_one_dp(struct fps_test_ereport *report)
 * passes a double precision pattern through the
 * floating point registers. If an error is found,
 * relevant data is stored in report.
 */
static int
registers_one_dp(struct fps_test_ereport *report)
{
	char err_data[MAX_INFO_SIZE];
	int i;
	int j;
	unsigned long result;

	uint64_t observed;
	uint64_t expected;

	for (i = 0; i < 64; i = i + 2) {
		for (j = 0; j < PAT_DP_NUM; j++) {
			result = register_test_dp(i, pat_dp[j]);
			if (result != pat_dp[j]) {
				observed = (uint64_t)result;
				expected = (uint64_t)pat[j];
				snprintf(err_data, sizeof (err_data),
				    "Reg: %d\nExpected: %lld"
				    "\nObserved: %lld",
				    i, pat[j], result);
				setup_fps_test_struct(IS_EREPORT_INFO,
				    report, 5302, &observed, &expected, 1,
				    1, err_data);

				return (-1);
			}
		}
	}

	return (0);
}

/*
 * sigsegv_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
 * sets up the sigsegv signal handler. If reached during
 * non-negative testing, application exits.
 */
/* ARGSUSED */
static void
sigsegv_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	ucp->uc_mcontext.fpregs.fpu_qcnt = 0;

	fsr_at_trap = ucp->uc_mcontext.fpregs.fpu_fsr;
	if (trap_flag == (trap_flag | TRAP_SOLICITED)) {
		trap_flag = trap_flag & (~TRAP_SOLICITED);
		return;
	}
	trap_flag = trap_flag | TRAP_UNSOLICITED;

	_exit(FPU_SIG_SEGV);
}

/*
 * sigbus_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
 * sets up the sigbus signal handler. If reached during
 * non-negative testing, application exits.
 */
/* ARGSUSED */
static void
sigbus_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	ucp->uc_mcontext.fpregs.fpu_qcnt = 0;

	fsr_at_trap = ucp->uc_mcontext.fpregs.fpu_fsr;
	if (trap_flag == (trap_flag | TRAP_SOLICITED)) {
		trap_flag = trap_flag & (~TRAP_SOLICITED);
		return;
	}
	trap_flag = trap_flag | TRAP_UNSOLICITED;

	_exit(FPU_SIG_BUS);

}

/*
 * sigfpe_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
 * sets up the sigfpe signal handler. If reached during
 * non-negative testing, application exits.
 */
/* ARGSUSED */
static void
sigfpe_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	ucp->uc_mcontext.fpregs.fpu_qcnt = 0;

	fsr_at_trap = ucp->uc_mcontext.fpregs.fpu_fsr;
	if (trap_flag == (trap_flag | TRAP_SOLICITED)) {
		trap_flag = trap_flag & (~TRAP_SOLICITED);
		return;
	}
	trap_flag = trap_flag | TRAP_UNSOLICITED;

	_exit(FPU_SIG_FPE);
}

/*
 * sigill_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
 * sets up the sigill signal handler. If reached during
 * non-negative testing, application exits.
 */
/* ARGSUSED */
static void
sigill_handler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	ucp->uc_mcontext.fpregs.fpu_qcnt = 0;

	fsr_at_trap = ucp->uc_mcontext.fpregs.fpu_fsr;
	if (trap_flag == (trap_flag | TRAP_SOLICITED)) {
		trap_flag = trap_flag & (~TRAP_SOLICITED);
		return;
	}
	trap_flag = trap_flag | TRAP_UNSOLICITED;

	_exit(FPU_SIG_ILL);
}

/*
 * winitfp() sets the signal handlers used
 * for negative testing. If sigaction fails,
 * the program exits.
 */
int
winitfp()
{
	sigemptyset(&newfpe.sa_mask);
	newfpe.sa_flags = SA_SIGINFO;
	newfpe.sa_handler = sigfpe_handler;
	if (sigaction(SIGFPE, &newfpe, &oldfpe)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	sigemptyset(&newill.sa_mask);
	newill.sa_flags = SA_SIGINFO;
	newill.sa_handler = sigill_handler;
	if (sigaction(SIGILL, &newill, &oldill)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	sigemptyset(&newbus.sa_mask);
	newbus.sa_flags = SA_SIGINFO;
	newbus.sa_handler = sigbus_handler;
	if (sigaction(SIGBUS, &newbus, &oldbus)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	sigemptyset(&newsegv.sa_mask);
	newsegv.sa_flags = SA_SIGINFO;
	newsegv.sa_handler = sigsegv_handler;
	if (sigaction(SIGSEGV, &newsegv, &oldsegv)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	return (0);
}
#endif

/*
 * restore_signals() turns off the signal
 * handlers used by restoring the original
 * values. If sigaction fails, the program
 * exits.
 */
int
restore_signals()
{
	if (sigaction(SIGSEGV, &oldsegv, &newsegv)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	if (sigaction(SIGBUS, &oldbus, &newbus)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	if (sigaction(SIGILL, &oldill, &newill)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	if (sigaction(SIGFPE, &oldfpe, &newfpe)) {
		_exit(FPU_SYSCALL_FAIL);
	}

	return (0);

}

/*
 * fpu_sysdiag(struct fps_test_ereport *report)
 * is the main caller of all fpu subtests. It
 * does the following tests: normal registers, fsr,
 * moving instructions, conversion instructions,
 * absolute values, compare, branching, arithmatic,
 * chain, datapath, and timing.
 * If an error is found, relevant data is stored
 * in report.
 */
int
fpu_sysdiag(struct fps_test_ereport *report)
{

	int i;

#ifndef i86pc

	/*
	 * Initialize neg_val_sp[] and neg_val_dp[] with the -ve versions of
	 * the values in val[]
	 */
	for (i = 0; i < N_VALS; i++) {
		neg_val_sp[i] = val[i].floatsingle |
		    ((uint32_t)1) << 31;

		neg_val_dp[i] = val[i].floatdouble |
		    ((uint64_t)1) << 63;
	}

	/* Register Testing */
	if (registers_four(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7001);
		return (-1);
	}

	if (registers_four_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7002);
	}

	if (registers_two(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7003);
	}

	if (registers_two_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7004);
	return (-1);
	}

	if (registers_one(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7005);
		return (-1);
	}

	if (registers_one_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7006);
		return (-1);
	}

	/* FSR testing */
	if (fsr_test(report)) {
		return (-1);

	}

	if (trap_flag) {
		fail_trap(report, 7007);
		return (-1);
	}

	if (fmovs_ins(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7008);
		return (-1);
	}

	/* Conversion routines */
	if (integer_to_float_sp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7009);
		return (-1);
	}

	if (integer_to_float_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7010);
		return (-1);
	}

	if (long_to_float_sp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7011);
		return (-1);
	}

	if (long_to_float_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7012);
		return (-1);
	}

	if (float_to_integer_sp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7013);
		return (-1);
	}

	if (float_to_integer_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7014);
		return (-1);
	}

	if (float_to_long_dp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7015);
		return (-1);
	}

	if (float_to_long_sp(report)) {
		return (-1);
	}

	if (trap_flag) {
		fail_trap(report, 7016);
		return (-1);
	}

	if (single_doub(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7017);
		return (-1);
	}
	if (double_sing(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7018);
		return (-1);
	}
	/* Absolute, -ve instructions */
	if (fabs_ins_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7019);
		return (-1);
	}
	if (fabs_ins_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7020);
		return (-1);
	}
	if (get_negative_value_pn_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7021);
		return (-1);
	}
	if (get_negative_value_pn_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7022);
		return (-1);
	}
	if (get_negative_value_np_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7023);
		return (-1);
	}
	if (get_negative_value_np_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7024);
		return (-1);
	}
	/* Compare and branch instructions */
	if (compare_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7025);
		return (-1);
	}
	if (compare_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7026);
		return (-1);
	}
	if (compare_sp_except(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7027);
		return (-1);
	}
	if (compare_dp_except(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7028);
		return (-1);
	}
	if (branching(report)) {
		return (-1);

	}
	if (trap_flag) {
		fail_trap(report, 7029);
		return (-1);
	}
	if (no_branching(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7030);
		return (-1);
	}
	/* Arithmetic instructions */
	if (addition_test_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7031);
		return (-1);
	}
	if (addition_test_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7032);
		return (-1);
	}
	if (subtraction_test_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7033);
		return (-1);
	}
	if (subtraction_test_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7034);
		return (-1);
	}
	if (multiplication_test_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7035);
		return (-1);
	}
	if (multiplication_test_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7036);
		return (-1);
	}
	if (squareroot_test_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7037);
		return (-1);
	}
	if (squareroot_test_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7038);
		return (-1);
	}
	if (division_test_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7039);
		return (-1);
	}
	if (division_test_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7040);
		return (-1);
	}
	/* chain, datapath, timing tests */
	if (chain_sp_test(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7041);
		return (-1);
	}
	if (chain_dp_test(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7042);
		return (-1);
	}
	if (data_path_sp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7043);
		return (-1);
	}
	if (data_path_dp(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7044);
		return (-1);
	}
	if (timing_test(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7045);
		return (-1);
	}
	if (check_conv(report)) {
		return (-1);
	}
	if (trap_flag) {
		fail_trap(report, 7046);
		return (-1);
	}
#endif				/* i86pc */

return (0);
}

#define	LLL 64
#define	REP_RXd "1104199269.000000"
#define	REP_RXc "1104199269,000000"
#define	REP_GCONd "4.5"
#define	REP_GCONc "4,5"

/*
 * check_conv(struct fps_test_ereport *report)
 * does a series of conversion testing.
 * If an error is found, relevant data is stored
 * in report.
 */
static int
check_conv(struct fps_test_ereport *report)
{
	char dec_point;
	char err_data[MAX_INFO_SIZE];
	double gcon;
	char l_buf[LLL];
	char *pREP_RX;
	char *pREP_GCON;
	double rx;
	long double qgcon;
	struct lconv *lconv2;
	uint64_t observed;
	uint64_t expected;

	(void) memset(l_buf, 0, LLL);

	lconv2 = localeconv();
	if (NULL == lconv2)
		return (0);
	if (NULL == lconv2->decimal_point)
		return (0);

	/* expect "." or ",". if not than return */
	if (1 == strlen(lconv2->decimal_point))
		dec_point = lconv2->decimal_point[0];
	else
		return (0);

	if (',' == dec_point) {
		pREP_RX = REP_RXc;
		pREP_GCON = REP_GCONc;
	} else if ('.' == dec_point) {
		pREP_RX = REP_RXd;
		pREP_GCON = REP_GCONd;
	} else
		return (0);

	rx = 1104199269;

	(void) snprintf(l_buf, LLL - 1, "%f", rx);
	if (strncmp(l_buf, pREP_RX, strlen(pREP_RX)) != 0) {
		observed = (uint64_t)1;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "\nObserved: %s\nExpected: %s", l_buf, pREP_RX);
		setup_fps_test_struct(IS_EREPORT_INFO,	report,
		    6326, &observed, &expected, 1, 1, err_data);

		return (-1);
	}

	gcon = 4.5;
	(void) memset(l_buf, 0, LLL);
	gconvert(gcon, 15, 0, l_buf);
	if (strncmp(l_buf, pREP_GCON, strlen(pREP_GCON)) != 0) {
		observed = (uint64_t)1;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "\nObserved: %s\nExpected: %s", l_buf, pREP_GCON);
		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    6327, &observed, &expected, 1, 1, err_data);

		return (-2);
	}

	qgcon = 4.5;
	(void) memset(l_buf, 0, LLL);
	qgconvert(&qgcon, 15, 0, l_buf);
	if (strncmp(l_buf, pREP_GCON, strlen(pREP_GCON)) != 0) {
		observed = (uint64_t)1;
		expected = (uint64_t)0;
		snprintf(err_data, sizeof (err_data),
		    "\nObserved: %s\nExpected: %s", l_buf, pREP_GCON);
		setup_fps_test_struct(IS_EREPORT_INFO, report,
		    6328, &observed, &expected, 1, 1, err_data);

		return (-3);
	}

	return (0);
}

/*
 * fail_trap(struct fps_test_ereport *report, int flag_num)
 * creates the ereport data if a trap flag is set after a
 * successful test when it shouldn't be.
 */
static void
fail_trap(struct fps_test_ereport *report, int flag_num)
{
	uint64_t observed = 1;
	uint64_t expected = 0;

	setup_fps_test_struct(NO_EREPORT_INFO, report,
	    flag_num, &observed, &expected, 1, 1);
}
