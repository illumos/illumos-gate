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
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Test AVX512 FP16 instructions
 */

.text
.align 16
.globl libdis_test
.type libdis_test, @function
libdis_test:
	vaddph %zmm0, %zmm8, %zmm16
	vaddph (%rax), %zmm7, %zmm15{%k4}
	vaddph (%rbx){1to32}, %zmm9, %zmm17{%k4}
	vaddph 0x8(%rcx){1to32}, %zmm10, %zmm18
	vaddph 0x80(%rdx){1to32}, %zmm11, %zmm19{%k4}
	vaddph 0x23(%r9), %zmm6, %zmm16{%k4}
	vaddph 0x42(%r9,%r10,8), %zmm6, %zmm16{%k4}
	vaddph 0x20(%r9), %zmm6, %zmm16{%k4}
	vaddph 0x40(%r9), %zmm6, %zmm16{%k4}
	vaddph {rn-sae}, %zmm1, %zmm11, %zmm21
	vaddph {rd-sae}, %zmm2, %zmm12, %zmm22{%k1}{z}
	vaddph {ru-sae}, %zmm3, %zmm13, %zmm23
	vaddph {rz-sae}, %zmm4, %zmm14, %zmm24
	vaddph %ymm0, %ymm10, %ymm20
	vaddph %ymm1, %ymm11, %ymm21{%k2}
	vaddph %ymm2, %ymm12, %ymm22{%k3}{z}
	vaddph (%rcx), %ymm13, %ymm23{%k4}
	vaddph (%rdx){1to16}, %ymm14, %ymm24
	vaddph 0x8(%rcx){1to16}, %ymm10, %ymm18
	vaddph 0x80(%rdx){1to16}, %ymm11, %ymm19{%k4}
	vaddph 0x23(%r9), %ymm6, %ymm16{%k4}
	vaddph 0x42(%r9,%r10,8), %ymm6, %ymm16{%k4}
	vaddph 0x20(%r9), %ymm6, %ymm16{%k4}
	vaddph 0x40(%r9), %ymm6, %ymm16{%k4}
	vaddph %xmm0, %xmm10, %xmm20
	vaddph %xmm1, %xmm11, %xmm21{%k2}
	vaddph %xmm2, %xmm12, %xmm22{%k3}{z}
	vaddph (%rcx), %xmm13, %xmm23{%k4}
	vaddph (%rdx){1to8}, %xmm14, %xmm24
	vaddph 0x8(%rcx){1to8}, %xmm15, %xmm23
	vaddph 0x80(%rdx){1to8}, %xmm16, %xmm22{%k4}
	vaddph 0x23(%r9), %xmm6, %xmm16{%k4}
	vaddph 0x42(%r9,%r10,8), %xmm6, %xmm16{%k4}

	vaddsh %xmm0, %xmm10, %xmm20
	vaddsh %xmm1, %xmm11, %xmm21{%k2}
	vaddsh %xmm2, %xmm12, %xmm22{%k3}{z}
	vaddsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vaddsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k5}
	vaddsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k6}{z}
	vaddsh {rz-sae}, %xmm6, %xmm16, %xmm26{%k7}
	vaddsh (%rcx), %xmm13, %xmm23{%k4}
	vaddsh 0x23(%r9), %xmm6, %xmm16{%k4}
	vaddsh 0x42(%r9,%r10,8), %xmm6, %xmm16{%k4}
	vaddsh 0x20(%r9), %xmm6, %xmm16{%k4}
	vaddsh 0x40(%r9), %xmm6, %xmm16{%k4}

	vcmpph $0x42, %zmm0, %zmm10, %k5
	vcmpph $0x42, %zmm1, %zmm11, %k6{%k4}
	vcmpph $0x42, {sae}, %zmm2, %zmm12, %k7{%k3}
	vcmpph $0x42, (%r8), %zmm12, %k2
	vcmpph $0x42, (%r8, %r9, 8), %zmm13, %k3
	vcmpph $0x42, 0x7777(%r10), %zmm14, %k4
	vcmpph $0x42, 0x7777(%r10){1to32}, %zmm14, %k4
        vcmpph $0x42, 0x80(%r10){1to32}, %zmm14, %k4
	vcmpph $0x42, 0x20(%r10), %zmm14, %k4
	vcmpph $0x42, 0x40(%r10), %zmm14, %k4
	vcmpph $0x42, %ymm1, %ymm11, %k6{%k4}
	vcmpph $0x42, %ymm2, %ymm12, %k7{%k3}
	vcmpph $0x42, (%r8), %ymm12, %k2
	vcmpph $0x42, (%r8, %r9, 8), %ymm13, %k3
	vcmpph $0x42, 0x7777(%r10), %ymm14, %k4
	vcmpph $0x42, 0x7777(%r10){1to16}, %ymm14, %k4
        vcmpph $0x42, 0x80(%r10){1to16}, %ymm14, %k4
	vcmpph $0x42, 0x20(%r10), %ymm14, %k4
	vcmpph $0x42, 0x40(%r10), %ymm14, %k4
	vcmpph $0x42, %xmm0, %xmm10, %k5
	vcmpph $0x42, %xmm1, %xmm11, %k6{%k4}
	vcmpph $0x42, %xmm2, %xmm12, %k7{%k3}
	vcmpph $0x42, (%r8), %xmm12, %k2
	vcmpph $0x42, (%r8, %r9, 8), %xmm13, %k3
	vcmpph $0x42, 0x7777(%r10), %xmm14, %k4
	vcmpph $0x42, 0x7777(%r10){1to8}, %xmm14, %k4
        vcmpph $0x42, 0x80(%r10){1to8}, %xmm14, %k4
	vcmpph $0x42, 0x20(%r10), %xmm14, %k4
	vcmpph $0x42, 0x40(%r10), %xmm14, %k4

	vcmpsh $0x23, %xmm0, %xmm10, %k1
	vcmpsh $0x23, %xmm1, %xmm11, %k1{%k2}
	vcmpsh $0x23, {sae}, %xmm2, %xmm12, %k2{%k3}
	vcmpsh $0x23, {sae}, %xmm3, %xmm13, %k3
	vcmpsh $0x42, (%rax), %xmm24, %k4
	vcmpsh $0x42, (%rbx, %rcx, 4), %xmm24, %k4
	vcmpsh $0x42, 0x7777(%rdx, %r8, 4), %xmm25, %k5{%k6}
	vcmpsh $0x42, 0x7777(%r9), %xmm26, %k6
	vcmpsh $0x42, 0x20(%r9), %xmm26, %k6
	vcmpsh $0x42, 0x40(%r9), %xmm26, %k6

	vcomish %xmm30, %xmm29
	vcomish {sae}, %xmm29, %xmm28
	vcomish (%rax), %xmm27
	vcomish 0x7777(%rax), %xmm26
	vcomish 0x7777(%rax, %rbx, 2), %xmm26
	vcomish 0x18(%rcx), %xmm25

	vcvtdq2ph %zmm10, %ymm20
	vcvtdq2ph %zmm9, %ymm19{%k1}
	vcvtdq2ph %zmm8, %ymm18{%k2}{z}
	vcvtdq2ph {rn-sae}, %zmm10, %ymm20
	vcvtdq2ph {rd-sae}, %zmm11, %ymm21
	vcvtdq2ph {ru-sae}, %zmm12, %ymm22
	vcvtdq2ph {rz-sae}, %zmm13, %ymm23
	vcvtdq2ph (%rax), %ymm23
	vcvtdq2ph 0x23(%rax), %ymm23
	vcvtdq2ph 0x23(%rax){1to16}, %ymm23
	vcvtdq2ph 0x80(%rbx){1to16}, %ymm24
	vcvtdq2ph 0x20(%rax), %ymm23
	vcvtdq2ph 0x40(%rax), %ymm23
	vcvtdq2ph 0x7777(%rax, %rbx, 8), %ymm23
	vcvtdq2ph %ymm10, %xmm20
	vcvtdq2ph %ymm9, %xmm19{%k1}
	vcvtdq2ph %ymm8, %xmm18{%k2}{z}
	vcvtdq2ph %xmm10, %xmm20
	vcvtdq2ph %xmm9, %xmm19{%k1}
	vcvtdq2ph %xmm8, %xmm18{%k2}{z}
	vcvtdq2phy 0x23(%rax), %xmm23
	vcvtdq2ph 0x23(%rax){1to8}, %xmm23
	vcvtdq2ph 0x80(%rax){1to8}, %xmm24
	vcvtdq2phy 0x20(%rax), %xmm23
	vcvtdq2phy 0x40(%rax), %xmm23
	vcvtdq2phy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtdq2phx 0x23(%rax), %xmm23
	vcvtdq2ph 0x23(%rax){1to4}, %xmm23
	vcvtdq2ph 0x80(%rax){1to4}, %xmm24
	vcvtdq2phx 0x20(%rax), %xmm23
	vcvtdq2phx 0x40(%rax), %xmm23
	vcvtdq2phx 0x7777(%rax, %rbx, 8), %xmm23

	vcvtpd2ph %zmm10, %xmm20
	vcvtpd2ph %zmm9, %xmm19{%k1}
	vcvtpd2ph %zmm8, %xmm18{%k2}{z}
	vcvtpd2ph {rn-sae}, %zmm10, %xmm20
	vcvtpd2ph {rd-sae}, %zmm11, %xmm21
	vcvtpd2ph {ru-sae}, %zmm12, %xmm22
	vcvtpd2ph {rz-sae}, %zmm13, %xmm23
	vcvtpd2ph %ymm10, %xmm20
	vcvtpd2ph %ymm9, %xmm19{%k1}
	vcvtpd2ph %ymm8, %xmm18{%k2}{z}
	vcvtpd2ph %xmm10, %xmm20
	vcvtpd2ph %xmm9, %xmm19{%k1}
	vcvtpd2ph %xmm8, %xmm18{%k2}{z}
	vcvtpd2phx 0x23(%rax), %xmm23
	vcvtpd2ph 0x23(%rax){1to8}, %xmm23
	vcvtpd2ph 0x80(%rax){1to8}, %xmm24
	vcvtpd2phx 0x20(%rax), %xmm23
	vcvtpd2phx 0x40(%rax), %xmm23
	vcvtpd2phx 0x7777(%rax, %rbx, 8), %xmm23
	vcvtpd2phy 0x23(%rax), %xmm23
	vcvtpd2ph 0x23(%rax){1to4}, %xmm23
	vcvtpd2ph 0x80(%rax){1to4}, %xmm24
	vcvtpd2phy 0x20(%rax), %xmm23
	vcvtpd2phy 0x40(%rax), %xmm23
	vcvtpd2phy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtpd2phz 0x23(%rax), %xmm23
	vcvtpd2ph 0x23(%rax){1to2}, %xmm23
	vcvtpd2ph 0x80(%rax){1to2}, %xmm24
	vcvtpd2phz 0x20(%rax), %xmm23
	vcvtpd2phz 0x40(%rax), %xmm23
	vcvtpd2phz 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2dq %ymm2, %zmm22
	vcvtph2dq %ymm3, %zmm23{%k3}
	vcvtph2dq %ymm4, %zmm24{%k4}{z}
	vcvtph2dq {rn-sae}, %ymm5, %zmm25
	vcvtph2dq {rd-sae}, %ymm6, %zmm26{%k6}
	vcvtph2dq {ru-sae}, %ymm7, %zmm27{%k7}{z}
	vcvtph2dq {rz-sae}, %ymm8, %zmm28
	vcvtph2dq 0x23(%rax), %zmm23
	vcvtph2dq 0x23(%rax){1to16}, %zmm23
	vcvtph2dq 0x80(%rax){1to16}, %zmm24
	vcvtph2dq 0x20(%rax), %zmm23
	vcvtph2dq 0x40(%rax), %zmm23
	vcvtph2dq 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2dq %xmm2, %ymm22
	vcvtph2dq %xmm3, %ymm23{%k3}
	vcvtph2dq %xmm4, %ymm24{%k4}{z}
	vcvtph2dq %xmm5, %ymm25
	vcvtph2dq %xmm6, %ymm26{%k6}
	vcvtph2dq %xmm7, %ymm27{%k7}{z}
	vcvtph2dq %xmm8, %ymm28
	vcvtph2dq 0x23(%rax), %ymm23
	vcvtph2dq 0x23(%rax){1to8}, %ymm23
	vcvtph2dq 0x80(%rax){1to8}, %ymm24
	vcvtph2dq 0x20(%rax), %ymm23
	vcvtph2dq 0x40(%rax), %ymm23
	vcvtph2dq 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2dq %xmm2, %xmm22
	vcvtph2dq %xmm3, %xmm23{%k3}
	vcvtph2dq %xmm4, %xmm24{%k4}{z}
	vcvtph2dq %xmm5, %xmm25
	vcvtph2dq %xmm6, %xmm26{%k6}
	vcvtph2dq %xmm7, %xmm27{%k7}{z}
	vcvtph2dq %xmm8, %xmm28
	vcvtph2dq 0x23(%rax), %xmm23
	vcvtph2dq 0x23(%rax){1to4}, %xmm23
	vcvtph2dq 0x80(%rax){1to4}, %xmm24
	vcvtph2dq 0x20(%rax), %xmm23
	vcvtph2dq 0x40(%rax), %xmm23
	vcvtph2dq 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2pd %xmm2, %zmm22
	vcvtph2pd %xmm3, %zmm23{%k3}
	vcvtph2pd %xmm4, %zmm24{%k4}{z}
	vcvtph2pd {sae}, %xmm5, %zmm25
	vcvtph2pd {sae}, %xmm6, %zmm26{%k6}
	vcvtph2pd {sae}, %xmm7, %zmm27{%k7}{z}
	vcvtph2pd 0x23(%rax), %zmm23
	vcvtph2pd 0x23(%rax){1to8}, %zmm23
	vcvtph2pd 0x80(%rax){1to8}, %zmm24
	vcvtph2pd 0x20(%rax), %zmm23
	vcvtph2pd 0x40(%rax), %zmm23
	vcvtph2pd 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2pd %xmm2, %ymm22
	vcvtph2pd %xmm3, %ymm23{%k3}
	vcvtph2pd %xmm4, %ymm24{%k4}{z}
	vcvtph2pd 0x23(%rax), %ymm23
	vcvtph2pd 0x23(%rax){1to4}, %ymm23
	vcvtph2pd 0x80(%rax){1to4}, %ymm24
	vcvtph2pd 0x20(%rax), %ymm23
	vcvtph2pd 0x40(%rax), %ymm23
	vcvtph2pd 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2pd %xmm2, %xmm22
	vcvtph2pd %xmm3, %xmm23{%k3}
	vcvtph2pd %xmm4, %xmm24{%k4}{z}
	vcvtph2pd 0x23(%rax), %xmm23
	vcvtph2pd 0x23(%rax){1to2}, %xmm23
	vcvtph2pd 0x80(%rax){1to2}, %xmm24
	vcvtph2pd 0x20(%rax), %xmm23
	vcvtph2pd 0x40(%rax), %xmm23
	vcvtph2pd 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2psx %ymm2, %zmm22
	vcvtph2psx %ymm3, %zmm23{%k3}
	vcvtph2psx %ymm4, %zmm24{%k4}{z}
	vcvtph2psx {sae}, %ymm5, %zmm25
	vcvtph2psx {sae}, %ymm6, %zmm26{%k6}
	vcvtph2psx {sae}, %ymm7, %zmm27{%k7}{z}
	vcvtph2psx 0x23(%rax), %zmm23
	vcvtph2psx 0x23(%rax){1to16}, %zmm23
	vcvtph2psx 0x80(%rax){1to16}, %zmm24
	vcvtph2psx 0x20(%rax), %zmm23
	vcvtph2psx 0x40(%rax), %zmm23
	vcvtph2psx 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2psx %xmm2, %ymm22
	vcvtph2psx %xmm3, %ymm23{%k3}
	vcvtph2psx %xmm4, %ymm24{%k4}{z}
	vcvtph2psx 0x23(%rax), %ymm23
	vcvtph2psx 0x23(%rax){1to8}, %ymm23
	vcvtph2psx 0x80(%rax){1to8}, %ymm24
	vcvtph2psx 0x20(%rax), %ymm23
	vcvtph2psx 0x40(%rax), %ymm23
	vcvtph2psx 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2psx %xmm2, %xmm22
	vcvtph2psx %xmm3, %xmm23{%k3}
	vcvtph2psx %xmm4, %xmm24{%k4}{z}
	vcvtph2psx 0x23(%rax), %xmm23
	vcvtph2psx 0x23(%rax){1to4}, %xmm23
	vcvtph2psx 0x80(%rax){1to4}, %xmm24
	vcvtph2psx 0x20(%rax), %xmm23
	vcvtph2psx 0x40(%rax), %xmm23
	vcvtph2psx 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2qq %xmm2, %zmm22
	vcvtph2qq %xmm3, %zmm23{%k3}
	vcvtph2qq %xmm4, %zmm24{%k4}{z}
	vcvtph2qq {rn-sae}, %xmm5, %zmm25
	vcvtph2qq {rd-sae}, %xmm6, %zmm26{%k6}
	vcvtph2qq {ru-sae}, %xmm7, %zmm27{%k7}{z}
	vcvtph2qq {rz-sae}, %xmm8, %zmm28
	vcvtph2qq 0x23(%rax), %zmm23
	vcvtph2qq 0x80(%rax){1to8}, %zmm24
	vcvtph2qq 0x20(%rax), %zmm23
	vcvtph2qq 0x40(%rax), %zmm23
	vcvtph2qq 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2qq %xmm2, %ymm22
	vcvtph2qq %xmm3, %ymm23{%k3}
	vcvtph2qq %xmm4, %ymm24{%k4}{z}
	vcvtph2qq 0x23(%rax), %ymm23
	vcvtph2qq 0x80(%rax){1to4}, %ymm24
	vcvtph2qq 0x20(%rax), %ymm23
	vcvtph2qq 0x40(%rax), %ymm23
	vcvtph2qq 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2qq %xmm2, %xmm22
	vcvtph2qq %xmm3, %xmm23{%k3}
	vcvtph2qq %xmm4, %xmm24{%k4}{z}
	vcvtph2qq 0x23(%rax), %xmm23
	vcvtph2qq 0x23(%rax){1to2}, %xmm23
	vcvtph2qq 0x23(%rax){1to2}, %xmm24
	vcvtph2qq 0x20(%rax), %xmm23
	vcvtph2qq 0x40(%rax), %xmm23
	vcvtph2qq 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2udq %ymm2, %zmm22
	vcvtph2udq %ymm3, %zmm23{%k3}
	vcvtph2udq %ymm4, %zmm24{%k4}{z}
	vcvtph2udq {rn-sae}, %ymm5, %zmm25
	vcvtph2udq {rd-sae}, %ymm6, %zmm26{%k6}
	vcvtph2udq {ru-sae}, %ymm7, %zmm27{%k7}{z}
	vcvtph2udq {rz-sae}, %ymm8, %zmm28
	vcvtph2udq 0x23(%rax), %zmm23
	vcvtph2udq 0x23(%rax){1to16}, %zmm23
	vcvtph2udq 0x80(%rax){1to16}, %zmm24
	vcvtph2udq 0x20(%rax), %zmm23
	vcvtph2udq 0x40(%rax), %zmm23
	vcvtph2udq 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2udq %xmm2, %ymm22
	vcvtph2udq %xmm3, %ymm23{%k3}
	vcvtph2udq %xmm4, %ymm24{%k4}{z}
	vcvtph2udq 0x23(%rax), %ymm23
	vcvtph2udq 0x23(%rax){1to8}, %ymm23
	vcvtph2udq 0x80(%rax){1to8}, %ymm24
	vcvtph2udq 0x20(%rax), %ymm23
	vcvtph2udq 0x40(%rax), %ymm23
	vcvtph2udq 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2udq %xmm2, %xmm22
	vcvtph2udq %xmm3, %xmm23{%k3}
	vcvtph2udq %xmm4, %xmm24{%k4}{z}
	vcvtph2udq 0x23(%rax), %xmm23
	vcvtph2udq 0x23(%rax){1to4}, %xmm23
	vcvtph2udq 0x80(%rax){1to4}, %xmm24
	vcvtph2udq 0x20(%rax), %xmm23
	vcvtph2udq 0x40(%rax), %xmm23
	vcvtph2udq 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2uqq %xmm2, %zmm22
	vcvtph2uqq %xmm3, %zmm23{%k3}
	vcvtph2uqq %xmm4, %zmm24{%k4}{z}
	vcvtph2uqq {rn-sae}, %xmm5, %zmm25
	vcvtph2uqq {rd-sae}, %xmm6, %zmm26{%k6}
	vcvtph2uqq {ru-sae}, %xmm7, %zmm27{%k7}{z}
	vcvtph2uqq {rz-sae}, %xmm8, %zmm28
	vcvtph2uqq 0x23(%rax), %zmm23
	vcvtph2uqq 0x23(%rax){1to8}, %zmm23
	vcvtph2uqq 0x80(%rax){1to8}, %zmm24
	vcvtph2uqq 0x20(%rax), %zmm23
	vcvtph2uqq 0x40(%rax), %zmm23
	vcvtph2uqq 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2uqq %xmm2, %ymm22
	vcvtph2uqq %xmm3, %ymm23{%k3}
	vcvtph2uqq %xmm4, %ymm24{%k4}{z}
	vcvtph2uqq 0x23(%rax), %ymm23
	vcvtph2uqq 0x23(%rax){1to4}, %ymm23
	vcvtph2uqq 0x80(%rax){1to4}, %ymm24
	vcvtph2uqq 0x20(%rax), %ymm23
	vcvtph2uqq 0x40(%rax), %ymm23
	vcvtph2uqq 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2uqq %xmm2, %xmm22
	vcvtph2uqq %xmm3, %xmm23{%k3}
	vcvtph2uqq %xmm4, %xmm24{%k4}{z}
	vcvtph2uqq 0x23(%rax), %xmm23
	vcvtph2uqq 0x23(%rax){1to2}, %xmm23
	vcvtph2uqq 0x80(%rax){1to2}, %xmm24
	vcvtph2uqq 0x20(%rax), %xmm23
	vcvtph2uqq 0x40(%rax), %xmm23
	vcvtph2uqq 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2uw %zmm2, %zmm22
	vcvtph2uw %zmm3, %zmm23{%k3}
	vcvtph2uw %zmm4, %zmm24{%k4}{z}
	vcvtph2uw {rn-sae}, %zmm5, %zmm25
	vcvtph2uw {rd-sae}, %zmm6, %zmm26{%k6}
	vcvtph2uw {ru-sae}, %zmm7, %zmm27{%k7}{z}
	vcvtph2uw {rz-sae}, %zmm8, %zmm28
	vcvtph2uw 0x23(%rax), %zmm23
	vcvtph2uw 0x23(%rax){1to32}, %zmm23
	vcvtph2uw 0x80(%rax){1to32}, %zmm24
	vcvtph2uw 0x20(%rax), %zmm23
	vcvtph2uw 0x40(%rax), %zmm23
	vcvtph2uw 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2uw %ymm2, %ymm22
	vcvtph2uw %ymm3, %ymm23{%k3}
	vcvtph2uw %ymm4, %ymm24{%k4}{z}
	vcvtph2uw 0x23(%rax), %ymm23
	vcvtph2uw 0x23(%rax){1to16}, %ymm23
	vcvtph2uw 0x80(%rax){1to16}, %ymm24
	vcvtph2uw 0x20(%rax), %ymm23
	vcvtph2uw 0x40(%rax), %ymm23
	vcvtph2uw 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2uw %xmm2, %xmm22
	vcvtph2uw %xmm3, %xmm23{%k3}
	vcvtph2uw %xmm4, %xmm24{%k4}{z}
	vcvtph2uw 0x23(%rax), %xmm23
	vcvtph2uw 0x23(%rax){1to8}, %xmm23
	vcvtph2uw 0x80(%rax){1to8}, %xmm24
	vcvtph2uw 0x20(%rax), %xmm23
	vcvtph2uw 0x40(%rax), %xmm23
	vcvtph2uw 0x7777(%rax, %rbx, 8), %xmm23

	vcvtph2w %zmm2, %zmm22
	vcvtph2w %zmm3, %zmm23{%k3}
	vcvtph2w %zmm4, %zmm24{%k4}{z}
	vcvtph2w {rn-sae}, %zmm5, %zmm25
	vcvtph2w {rd-sae}, %zmm6, %zmm26{%k6}
	vcvtph2w {ru-sae}, %zmm7, %zmm27{%k7}{z}
	vcvtph2w {rz-sae}, %zmm8, %zmm28
	vcvtph2w 0x23(%rax), %zmm23
	vcvtph2w 0x23(%rax){1to32}, %zmm23
	vcvtph2w 0x80(%rax){1to32}, %zmm24
	vcvtph2w 0x20(%rax), %zmm23
	vcvtph2w 0x40(%rax), %zmm23
	vcvtph2w 0x7777(%rax, %rbx, 8), %zmm23
	vcvtph2w %ymm2, %ymm22
	vcvtph2w %ymm3, %ymm23{%k3}
	vcvtph2w %ymm4, %ymm24{%k4}{z}
	vcvtph2w 0x23(%rax), %ymm23
	vcvtph2w 0x23(%rax){1to16}, %ymm23
	vcvtph2w 0x80(%rax){1to16}, %ymm24
	vcvtph2w 0x20(%rax), %ymm23
	vcvtph2w 0x40(%rax), %ymm23
	vcvtph2w 0x7777(%rax, %rbx, 8), %ymm23
	vcvtph2w %xmm2, %xmm22
	vcvtph2w %xmm3, %xmm23{%k3}
	vcvtph2w %xmm4, %xmm24{%k4}{z}
	vcvtph2w 0x23(%rax), %xmm23
	vcvtph2w 0x23(%rax){1to8}, %xmm23
	vcvtph2w 0x80(%rax){1to8}, %xmm24
	vcvtph2w 0x20(%rax), %xmm23
	vcvtph2w 0x40(%rax), %xmm23
	vcvtph2w 0x7777(%rax, %rbx, 8), %xmm23

	vcvtps2phx %zmm10, %ymm20
	vcvtps2phx %zmm9, %ymm19{%k1}
	vcvtps2phx %zmm8, %ymm18{%k2}{z}
	vcvtps2phx {rn-sae}, %zmm10, %ymm20
	vcvtps2phx {rd-sae}, %zmm11, %ymm21
	vcvtps2phx {ru-sae}, %zmm12, %ymm22
	vcvtps2phx {rz-sae}, %zmm13, %ymm23
	vcvtps2phx (%rax), %ymm23
	vcvtps2phx 0x23(%rax), %ymm23
	vcvtps2phx 0x23(%rax){1to16}, %ymm23
	vcvtps2phx 0x80(%rax){1to16}, %ymm24
	vcvtps2phx 0x20(%rax), %ymm23
	vcvtps2phx 0x40(%rax), %ymm23
	vcvtps2phx 0x7777(%rax, %rbx, 8), %ymm23
	vcvtps2phx %ymm10, %xmm20
	vcvtps2phx %ymm9, %xmm19{%k1}
	vcvtps2phx %ymm8, %xmm18{%k2}{z}
	vcvtps2phx %xmm10, %xmm20
	vcvtps2phx %xmm9, %xmm19{%k1}
	vcvtps2phx %xmm8, %xmm18{%k2}{z}
	vcvtps2phxy 0x23(%rax), %xmm23
	vcvtps2phx 0x23(%rax){1to8}, %xmm23
	vcvtps2phx 0x80(%rax){1to8}, %xmm24
	vcvtps2phxy 0x20(%rax), %xmm23
	vcvtps2phxy 0x40(%rax), %xmm23
	vcvtps2phxy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtps2phxx 0x23(%rax), %xmm23
	vcvtps2phx 0x23(%rax){1to4}, %xmm23
	vcvtps2phx 0x80(%rax){1to4}, %xmm24
	vcvtps2phxx 0x20(%rax), %xmm23
	vcvtps2phxx 0x40(%rax), %xmm23
	vcvtps2phxx 0x7777(%rax, %rbx, 8), %xmm23

	vcvtqq2ph %zmm10, %xmm20
	vcvtqq2ph %zmm9, %xmm19{%k1}
	vcvtqq2ph %zmm8, %xmm18{%k2}{z}
	vcvtqq2ph {rn-sae}, %zmm10, %xmm20
	vcvtqq2ph {rd-sae}, %zmm11, %xmm21
	vcvtqq2ph {ru-sae}, %zmm12, %xmm22
	vcvtqq2ph {rz-sae}, %zmm13, %xmm23
	vcvtqq2ph %ymm10, %xmm20
	vcvtqq2ph %ymm9, %xmm19{%k1}
	vcvtqq2ph %ymm8, %xmm18{%k2}{z}
	vcvtqq2ph %xmm10, %xmm20
	vcvtqq2ph %xmm9, %xmm19{%k1}
	vcvtqq2ph %xmm8, %xmm18{%k2}{z}
	vcvtqq2phx 0x23(%rax), %xmm23
	vcvtqq2ph 0x23(%rax){1to8}, %xmm23
	vcvtqq2ph 0x80(%rax){1to8}, %xmm24
	vcvtqq2phx 0x20(%rax), %xmm23
	vcvtqq2phx 0x40(%rax), %xmm23
	vcvtqq2phx 0x7777(%rax, %rbx, 8), %xmm23
	vcvtqq2phy 0x23(%rax), %xmm23
	vcvtqq2ph 0x23(%rax){1to4}, %xmm23
	vcvtqq2ph 0x80(%rax){1to4}, %xmm24
	vcvtqq2phy 0x20(%rax), %xmm23
	vcvtqq2phy 0x40(%rax), %xmm23
	vcvtqq2phy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtqq2phz 0x23(%rax), %xmm23
	vcvtqq2ph 0x23(%rax){1to2}, %xmm23
	vcvtqq2ph 0x80(%rax){1to2}, %xmm24
	vcvtqq2phz 0x20(%rax), %xmm23
	vcvtqq2phz 0x40(%rax), %xmm23
	vcvtqq2phz 0x7777(%rax, %rbx, 8), %xmm23

	vcvtsd2sh %xmm0, %xmm10, %xmm20
	vcvtsd2sh %xmm1, %xmm11, %xmm21{%k1}
	vcvtsd2sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vcvtsd2sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vcvtsd2sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vcvtsd2sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vcvtsd2sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vcvtsd2sh (%r8), %xmm8, %xmm28
	vcvtsd2sh 0x23(%r8), %xmm17, %xmm27
	vcvtsd2sh 0x20(%r8), %xmm17, %xmm27
	vcvtsd2sh 0x40(%r8), %xmm17, %xmm27
	vcvtsd2sh 0x7777(%r8), %xmm17, %xmm27{%k7}

	vcvtsh2sd %xmm0, %xmm10, %xmm20
	vcvtsh2sd %xmm1, %xmm11, %xmm21{%k1}
	vcvtsh2sd %xmm2, %xmm12, %xmm22{%k2}{z}
	vcvtsh2sd {sae}, %xmm3, %xmm13, %xmm23
	vcvtsh2sd {sae}, %xmm4, %xmm14, %xmm24{%k4}
	vcvtsh2sd {sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vcvtsh2sd (%r8), %xmm8, %xmm28
	vcvtsh2sd 0x23(%r8), %xmm17, %xmm27
	vcvtsh2sd 0x20(%r8), %xmm17, %xmm27
	vcvtsh2sd 0x40(%r8), %xmm17, %xmm27
	vcvtsh2sd 0x7777(%r8), %xmm17, %xmm27{%k7}

	vcvtsh2si %xmm20, %r8
	vcvtsh2si {rn-sae}, %xmm21,%r9
	vcvtsh2si {rd-sae}, %xmm22,%r10
	vcvtsh2si {ru-sae}, %xmm22,%r11
	vcvtsh2si {rz-sae}, %xmm23,%r12
	vcvtsh2si (%rax), %rbp
	vcvtsh2si 0x23(%rax), %rbp
	vcvtsh2si 0x20(%rax), %rbp
	vcvtsh2si 0x40(%rax), %rbp
	vcvtsh2si 0x7777(%rax), %rbp
	vcvtsh2si 0x23(%rax, %rbx, 4), %rbp
	vcvtsh2si %xmm20, %eax
	vcvtsh2si {rn-sae}, %xmm21,%ebx
	vcvtsh2si {rd-sae}, %xmm22,%ecx
	vcvtsh2si {ru-sae}, %xmm22,%edx
	vcvtsh2si {rz-sae}, %xmm23,%eax
	vcvtsh2si (%rax), %ebx
	vcvtsh2si 0x23(%rax), %ecx
	vcvtsh2si 0x20(%rax), %edx
	vcvtsh2si 0x40(%rax), %eax
	vcvtsh2si 0x7777(%rax), %ebx
	vcvtsh2si 0x23(%rax, %rbx, 4), %ecx

	vcvtsh2ss %xmm0, %xmm10, %xmm20
	vcvtsh2ss %xmm1, %xmm11, %xmm21{%k1}
	vcvtsh2ss %xmm2, %xmm12, %xmm22{%k2}{z}
	vcvtsh2ss {sae}, %xmm3, %xmm13, %xmm23
	vcvtsh2ss {sae}, %xmm4, %xmm14, %xmm24{%k4}
	vcvtsh2ss {sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vcvtsh2ss (%r8), %xmm8, %xmm28
	vcvtsh2ss 0x23(%r8), %xmm17, %xmm27
	vcvtsh2ss 0x20(%r8), %xmm17, %xmm27
	vcvtsh2ss 0x40(%r8), %xmm17, %xmm27
	vcvtsh2ss 0x7777(%r8), %xmm17, %xmm27{%k7}

	vcvtsh2usi %xmm20, %r8
	vcvtsh2usi {rn-sae}, %xmm21,%r9
	vcvtsh2usi {rd-sae}, %xmm22,%r10
	vcvtsh2usi {ru-sae}, %xmm22,%r11
	vcvtsh2usi {rz-sae}, %xmm23,%r12
	vcvtsh2usi (%rax), %rbp
	vcvtsh2usi 0x23(%rax), %rbp
	vcvtsh2usi 0x20(%rax), %rbp
	vcvtsh2usi 0x40(%rax), %rbp
	vcvtsh2usi 0x7777(%rax), %rbp
	vcvtsh2usi 0x23(%rax, %rbx, 4), %rbp
	vcvtsh2usi %xmm20, %eax
	vcvtsh2usi {rn-sae}, %xmm21,%ebx
	vcvtsh2usi {rd-sae}, %xmm22,%ecx
	vcvtsh2usi {ru-sae}, %xmm22,%edx
	vcvtsh2usi {rz-sae}, %xmm23,%eax
	vcvtsh2usi (%rax), %ebx
	vcvtsh2usi 0x23(%rax), %ecx
	vcvtsh2usi 0x20(%rax), %edx
	vcvtsh2usi 0x40(%rax), %eax
	vcvtsh2usi 0x7777(%rax), %ebx
	vcvtsh2usi 0x23(%rax, %rbx, 4), %ecx

	vcvtsi2sh %rax, %xmm0, %xmm1
	vcvtsi2sh %rax, {rn-sae}, %xmm11, %xmm21
	vcvtsi2sh %rax, {rd-sae}, %xmm12, %xmm22
	vcvtsi2sh %rax, {ru-sae}, %xmm13, %xmm23
	vcvtsi2sh %rax, {rz-sae}, %xmm14, %xmm24
	vcvtsi2sh (%r10), %xmm15, %xmm25
	vcvtsi2sh 0x23(%r10), %xmm15, %xmm25
	vcvtsi2sh 0x20(%r10), %xmm16, %xmm26
	vcvtsi2sh 0x40(%r10), %xmm17, %xmm27
	vcvtsi2sh 0x7777(%r10), %xmm18, %xmm28
	vcvtsi2sh 0x23(%r10, %r11, 8), %xmm19, %xmm29
	vcvtsi2sh %eax, %xmm0, %xmm1
	vcvtsi2sh %ebx, {rn-sae}, %xmm11, %xmm21
	vcvtsi2sh %ecx, {rd-sae}, %xmm12, %xmm22
	vcvtsi2sh %edx, {ru-sae}, %xmm13, %xmm23
	vcvtsi2sh %eax, {rz-sae}, %xmm14, %xmm24
	vcvtss2sh %xmm0, %xmm10, %xmm20
	vcvtss2sh %xmm1, %xmm11, %xmm21{%k1}
	vcvtss2sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vcvtss2sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vcvtss2sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vcvtss2sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vcvtss2sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vcvtss2sh (%r8), %xmm8, %xmm28
	vcvtss2sh 0x23(%r8), %xmm17, %xmm27
	vcvtss2sh 0x20(%r8), %xmm17, %xmm27
	vcvtss2sh 0x40(%r8), %xmm17, %xmm27
	vcvtss2sh 0x7777(%r8), %xmm17, %xmm27{%k7}

	vcvttph2dq %ymm2, %zmm22
	vcvttph2dq %ymm3, %zmm23{%k3}
	vcvttph2dq %ymm4, %zmm24{%k4}{z}
	vcvttph2dq {sae}, %ymm5, %zmm25
	vcvttph2dq {sae}, %ymm6, %zmm26{%k6}
	vcvttph2dq {sae}, %ymm7, %zmm27{%k7}{z}
	vcvttph2dq 0x23(%rax), %zmm23
	vcvttph2dq 0x23(%rax){1to16}, %zmm23
	vcvttph2dq 0x80(%rax){1to16}, %zmm24
	vcvttph2dq 0x20(%rax), %zmm23
	vcvttph2dq 0x40(%rax), %zmm23
	vcvttph2dq 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2dq %xmm2, %ymm22
	vcvttph2dq %xmm3, %ymm23{%k3}
	vcvttph2dq %xmm4, %ymm24{%k4}{z}
	vcvttph2dq %xmm5, %ymm25
	vcvttph2dq %xmm6, %ymm26{%k6}
	vcvttph2dq %xmm7, %ymm27{%k7}{z}
	vcvttph2dq %xmm8, %ymm28
	vcvttph2dq 0x23(%rax), %ymm23
	vcvttph2dq 0x23(%rax){1to8}, %ymm23
	vcvttph2dq 0x80(%rax){1to8}, %ymm24
	vcvttph2dq 0x20(%rax), %ymm23
	vcvttph2dq 0x40(%rax), %ymm23
	vcvttph2dq 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2dq %xmm2, %xmm22
	vcvttph2dq %xmm3, %xmm23{%k3}
	vcvttph2dq %xmm4, %xmm24{%k4}{z}
	vcvttph2dq %xmm5, %xmm25
	vcvttph2dq %xmm6, %xmm26{%k6}
	vcvttph2dq %xmm7, %xmm27{%k7}{z}
	vcvttph2dq %xmm8, %xmm28
	vcvttph2dq 0x23(%rax), %xmm23
	vcvttph2dq 0x23(%rax){1to4}, %xmm23
	vcvttph2dq 0x80(%rax){1to4}, %xmm24
	vcvttph2dq 0x20(%rax), %xmm23
	vcvttph2dq 0x40(%rax), %xmm23
	vcvttph2dq 0x7777(%rax, %rbx, 8), %xmm23

	vcvttph2qq %xmm2, %zmm22
	vcvttph2qq %xmm3, %zmm23{%k3}
	vcvttph2qq %xmm4, %zmm24{%k4}{z}
	vcvttph2qq {sae}, %xmm5, %zmm25
	vcvttph2qq {sae}, %xmm6, %zmm26{%k6}
	vcvttph2qq {sae}, %xmm7, %zmm27{%k7}{z}
	vcvttph2qq 0x23(%rax), %zmm23
	vcvttph2qq 0x23(%rax){1to8}, %zmm23
	vcvttph2qq 0x80(%rax){1to8}, %zmm24
	vcvttph2qq 0x20(%rax), %zmm23
	vcvttph2qq 0x40(%rax), %zmm23
	vcvttph2qq 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2qq %xmm2, %ymm22
	vcvttph2qq %xmm3, %ymm23{%k3}
	vcvttph2qq %xmm4, %ymm24{%k4}{z}
	vcvttph2qq 0x23(%rax), %ymm23
	vcvttph2qq 0x23(%rax){1to4}, %ymm23
	vcvttph2qq 0x80(%rax){1to4}, %ymm24
	vcvttph2qq 0x20(%rax), %ymm23
	vcvttph2qq 0x40(%rax), %ymm23
	vcvttph2qq 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2qq %xmm2, %xmm22
	vcvttph2qq %xmm3, %xmm23{%k3}
	vcvttph2qq %xmm4, %xmm24{%k4}{z}
	vcvttph2qq 0x23(%rax), %xmm23
	vcvttph2qq 0x23(%rax){1to2}, %xmm23
	vcvttph2qq 0x80(%rax){1to2}, %xmm24
	vcvttph2qq 0x20(%rax), %xmm23
	vcvttph2qq 0x40(%rax), %xmm23
	vcvttph2qq 0x7777(%rax, %rbx, 8), %xmm23

	vcvttph2udq %ymm2, %zmm22
	vcvttph2udq %ymm3, %zmm23{%k3}
	vcvttph2udq %ymm4, %zmm24{%k4}{z}
	vcvttph2udq {sae}, %ymm5, %zmm25
	vcvttph2udq {sae}, %ymm6, %zmm26{%k6}
	vcvttph2udq {sae}, %ymm7, %zmm27{%k7}{z}
	vcvttph2udq 0x23(%rax), %zmm23
	vcvttph2udq 0x23(%rax){1to16}, %zmm23
	vcvttph2udq 0x80(%rax){1to16}, %zmm24
	vcvttph2udq 0x20(%rax), %zmm23
	vcvttph2udq 0x40(%rax), %zmm23
	vcvttph2udq 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2udq %xmm2, %ymm22
	vcvttph2udq %xmm3, %ymm23{%k3}
	vcvttph2udq %xmm4, %ymm24{%k4}{z}
	vcvttph2udq 0x23(%rax), %ymm23
	vcvttph2udq 0x23(%rax){1to8}, %ymm23
	vcvttph2udq 0x80(%rax){1to8}, %ymm24
	vcvttph2udq 0x20(%rax), %ymm23
	vcvttph2udq 0x40(%rax), %ymm23
	vcvttph2udq 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2udq %xmm2, %xmm22
	vcvttph2udq %xmm3, %xmm23{%k3}
	vcvttph2udq %xmm4, %xmm24{%k4}{z}
	vcvttph2udq 0x23(%rax), %xmm23
	vcvttph2udq 0x23(%rax){1to4}, %xmm23
	vcvttph2udq 0x80(%rax){1to4}, %xmm24
	vcvttph2udq 0x20(%rax), %xmm23
	vcvttph2udq 0x40(%rax), %xmm23
	vcvttph2udq 0x7777(%rax, %rbx, 8), %xmm23

	vcvttph2uqq %xmm2, %zmm22
	vcvttph2uqq %xmm3, %zmm23{%k3}
	vcvttph2uqq %xmm4, %zmm24{%k4}{z}
	vcvttph2uqq {sae}, %xmm5, %zmm25
	vcvttph2uqq {sae}, %xmm6, %zmm26{%k6}
	vcvttph2uqq {sae}, %xmm7, %zmm27{%k7}{z}
	vcvttph2uqq 0x23(%rax), %zmm23
	vcvttph2uqq 0x23(%rax){1to8}, %zmm23
	vcvttph2uqq 0x80(%rax){1to8}, %zmm24
	vcvttph2uqq 0x20(%rax), %zmm23
	vcvttph2uqq 0x40(%rax), %zmm23
	vcvttph2uqq 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2uqq %xmm2, %ymm22
	vcvttph2uqq %xmm3, %ymm23{%k3}
	vcvttph2uqq %xmm4, %ymm24{%k4}{z}
	vcvttph2uqq 0x23(%rax), %ymm23
	vcvttph2uqq 0x23(%rax){1to4}, %ymm23
	vcvttph2uqq 0x80(%rax){1to4}, %ymm24
	vcvttph2uqq 0x20(%rax), %ymm23
	vcvttph2uqq 0x40(%rax), %ymm23
	vcvttph2uqq 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2uqq %xmm2, %xmm22
	vcvttph2uqq %xmm3, %xmm23{%k3}
	vcvttph2uqq %xmm4, %xmm24{%k4}{z}
	vcvttph2uqq 0x23(%rax), %xmm23
	vcvttph2uqq 0x23(%rax){1to2}, %xmm23
	vcvttph2uqq 0x80(%rax){1to2}, %xmm24
	vcvttph2uqq 0x20(%rax), %xmm23
	vcvttph2uqq 0x40(%rax), %xmm23
	vcvttph2uqq 0x7777(%rax, %rbx, 8), %xmm23

	vcvttph2uw %zmm2, %zmm22
	vcvttph2uw %zmm3, %zmm23{%k3}
	vcvttph2uw %zmm4, %zmm24{%k4}{z}
	vcvttph2uw {sae}, %zmm5, %zmm25
	vcvttph2uw {sae}, %zmm6, %zmm26{%k6}
	vcvttph2uw {sae}, %zmm7, %zmm27{%k7}{z}
	vcvttph2uw 0x23(%rax), %zmm23
	vcvttph2uw 0x23(%rax){1to32}, %zmm23
	vcvttph2uw 0x80(%rax){1to32}, %zmm24
	vcvttph2uw 0x20(%rax), %zmm23
	vcvttph2uw 0x40(%rax), %zmm23
	vcvttph2uw 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2uw %ymm2, %ymm22
	vcvttph2uw %ymm3, %ymm23{%k3}
	vcvttph2uw %ymm4, %ymm24{%k4}{z}
	vcvttph2uw 0x23(%rax), %ymm23
	vcvttph2uw 0x23(%rax){1to16}, %ymm23
	vcvttph2uw 0x80(%rax){1to16}, %ymm24
	vcvttph2uw 0x20(%rax), %ymm23
	vcvttph2uw 0x40(%rax), %ymm23
	vcvttph2uw 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2uw %xmm2, %xmm22
	vcvttph2uw %xmm3, %xmm23{%k3}
	vcvttph2uw %xmm4, %xmm24{%k4}{z}
	vcvttph2uw 0x23(%rax), %xmm23
	vcvttph2uw 0x23(%rax){1to8}, %xmm23
	vcvttph2uw 0x80(%rax){1to8}, %xmm24
	vcvttph2uw 0x20(%rax), %xmm23
	vcvttph2uw 0x40(%rax), %xmm23
	vcvttph2uw 0x7777(%rax, %rbx, 8), %xmm23

	vcvttph2w %zmm2, %zmm22
	vcvttph2w %zmm3, %zmm23{%k3}
	vcvttph2w %zmm4, %zmm24{%k4}{z}
	vcvttph2w {sae}, %zmm5, %zmm25
	vcvttph2w {sae}, %zmm6, %zmm26{%k6}
	vcvttph2w {sae}, %zmm7, %zmm27{%k7}{z}
	vcvttph2w 0x23(%rax), %zmm23
	vcvttph2w 0x23(%rax){1to32}, %zmm23
	vcvttph2w 0x80(%rax){1to32}, %zmm24
	vcvttph2w 0x20(%rax), %zmm23
	vcvttph2w 0x40(%rax), %zmm23
	vcvttph2w 0x7777(%rax, %rbx, 8), %zmm23
	vcvttph2w %ymm2, %ymm22
	vcvttph2w %ymm3, %ymm23{%k3}
	vcvttph2w %ymm4, %ymm24{%k4}{z}
	vcvttph2w 0x23(%rax), %ymm23
	vcvttph2w 0x23(%rax){1to16}, %ymm23
	vcvttph2w 0x80(%rax){1to16}, %ymm24
	vcvttph2w 0x20(%rax), %ymm23
	vcvttph2w 0x40(%rax), %ymm23
	vcvttph2w 0x7777(%rax, %rbx, 8), %ymm23
	vcvttph2w %xmm2, %xmm22
	vcvttph2w %xmm3, %xmm23{%k3}
	vcvttph2w %xmm4, %xmm24{%k4}{z}
	vcvttph2w 0x23(%rax), %xmm23
	vcvttph2w 0x23(%rax){1to8}, %xmm23
	vcvttph2w 0x80(%rax){1to8}, %xmm24
	vcvttph2w 0x20(%rax), %xmm23
	vcvttph2w 0x40(%rax), %xmm23
	vcvttph2w 0x7777(%rax, %rbx, 8), %xmm23

	vcvttsh2si %xmm20, %r8
	vcvttsh2si {sae}, %xmm21,%r9
	vcvttsh2si {sae}, %xmm22,%r10
	vcvttsh2si {sae}, %xmm22,%r11
	vcvttsh2si (%rax), %rbp
	vcvttsh2si 0x23(%rax), %rbp
	vcvttsh2si 0x20(%rax), %rbp
	vcvttsh2si 0x40(%rax), %rbp
	vcvttsh2si 0x7777(%rax), %rbp
	vcvttsh2si 0x23(%rax, %rbx, 4), %rbp
	vcvttsh2si %xmm20, %eax
	vcvttsh2si {sae}, %xmm21,%ebx
	vcvttsh2si {sae}, %xmm22,%ecx
	vcvttsh2si {sae}, %xmm22,%edx
	vcvttsh2si (%rax), %ebx
	vcvttsh2si 0x23(%rax), %ecx
	vcvttsh2si 0x20(%rax), %edx
	vcvttsh2si 0x40(%rax), %eax
	vcvttsh2si 0x7777(%rax), %ebx
	vcvttsh2si 0x23(%rax, %rbx, 4), %ecx

	vcvttsh2usi %xmm20, %r8
	vcvttsh2usi {sae}, %xmm21,%r9
	vcvttsh2usi {sae}, %xmm22,%r10
	vcvttsh2usi {sae}, %xmm22,%r11
	vcvttsh2usi (%rax), %rbp
	vcvttsh2usi 0x23(%rax), %rbp
	vcvttsh2usi 0x20(%rax), %rbp
	vcvttsh2usi 0x40(%rax), %rbp
	vcvttsh2usi 0x7777(%rax), %rbp
	vcvttsh2usi 0x23(%rax, %rbx, 4), %rbp
	vcvttsh2usi %xmm20, %eax
	vcvttsh2usi {sae}, %xmm21,%ebx
	vcvttsh2usi {sae}, %xmm22,%ecx
	vcvttsh2usi {sae}, %xmm22,%edx
	vcvttsh2usi (%rax), %ebx
	vcvttsh2usi 0x23(%rax), %ecx
	vcvttsh2usi 0x20(%rax), %edx
	vcvttsh2usi 0x40(%rax), %eax
	vcvttsh2usi 0x7777(%rax), %ebx
	vcvttsh2usi 0x23(%rax, %rbx, 4), %ecx

	vcvtudq2ph %zmm10, %ymm20
	vcvtudq2ph %zmm9, %ymm19{%k1}
	vcvtudq2ph %zmm8, %ymm18{%k2}{z}
	vcvtudq2ph {rn-sae}, %zmm10, %ymm20
	vcvtudq2ph {rd-sae}, %zmm11, %ymm21
	vcvtudq2ph {ru-sae}, %zmm12, %ymm22
	vcvtudq2ph {rz-sae}, %zmm13, %ymm23
	vcvtudq2ph (%rax), %ymm23
	vcvtudq2ph 0x23(%rax), %ymm23
	vcvtudq2ph 0x23(%rax){1to16}, %ymm23
	vcvtudq2ph 0x80(%rax){1to16}, %ymm24
	vcvtudq2ph 0x20(%rax), %ymm23
	vcvtudq2ph 0x40(%rax), %ymm23
	vcvtudq2ph 0x7777(%rax, %rbx, 8), %ymm23
	vcvtudq2ph %ymm10, %xmm20
	vcvtudq2ph %ymm9, %xmm19{%k1}
	vcvtudq2ph %ymm8, %xmm18{%k2}{z}
	vcvtudq2ph %xmm10, %xmm20
	vcvtudq2ph %xmm9, %xmm19{%k1}
	vcvtudq2ph %xmm8, %xmm18{%k2}{z}
	vcvtudq2phy 0x23(%rax), %xmm23
	vcvtudq2ph 0x23(%rax){1to8}, %xmm23
	vcvtudq2ph 0x80(%rax){1to8}, %xmm24
	vcvtudq2phy 0x20(%rax), %xmm23
	vcvtudq2phy 0x40(%rax), %xmm23
	vcvtudq2phy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtudq2phx 0x23(%rax), %xmm23
	vcvtudq2ph 0x23(%rax){1to4}, %xmm23
	vcvtudq2ph 0x80(%rax){1to4}, %xmm24
	vcvtudq2phx 0x20(%rax), %xmm23
	vcvtudq2phx 0x40(%rax), %xmm23
	vcvtudq2phx 0x7777(%rax, %rbx, 8), %xmm23

	vcvtuqq2ph %zmm10, %xmm20
	vcvtuqq2ph %zmm9, %xmm19{%k1}
	vcvtuqq2ph %zmm8, %xmm18{%k2}{z}
	vcvtuqq2ph {rn-sae}, %zmm10, %xmm20
	vcvtuqq2ph {rd-sae}, %zmm11, %xmm21
	vcvtuqq2ph {ru-sae}, %zmm12, %xmm22
	vcvtuqq2ph {rz-sae}, %zmm13, %xmm23
	vcvtuqq2ph %ymm10, %xmm20
	vcvtuqq2ph %ymm9, %xmm19{%k1}
	vcvtuqq2ph %ymm8, %xmm18{%k2}{z}
	vcvtuqq2ph %xmm10, %xmm20
	vcvtuqq2ph %xmm9, %xmm19{%k1}
	vcvtuqq2ph %xmm8, %xmm18{%k2}{z}
	vcvtuqq2phx 0x23(%rax), %xmm23
	vcvtuqq2ph 0x23(%rax){1to8}, %xmm23
	vcvtuqq2ph 0x80(%rax){1to8}, %xmm24
	vcvtuqq2phx 0x20(%rax), %xmm23
	vcvtuqq2phx 0x40(%rax), %xmm23
	vcvtuqq2phx 0x7777(%rax, %rbx, 8), %xmm23
	vcvtuqq2phy 0x23(%rax), %xmm23
	vcvtuqq2ph 0x23(%rax){1to4}, %xmm23
	vcvtuqq2ph 0x80(%rax){1to4}, %xmm24
	vcvtuqq2phy 0x20(%rax), %xmm23
	vcvtuqq2phy 0x40(%rax), %xmm23
	vcvtuqq2phy 0x7777(%rax, %rbx, 8), %xmm23
	vcvtuqq2phz 0x23(%rax), %xmm23
	vcvtuqq2ph 0x23(%rax){1to2}, %xmm23
	vcvtuqq2ph 0x80(%rax){1to2}, %xmm23
	vcvtuqq2phz 0x20(%rax), %xmm23
	vcvtuqq2phz 0x40(%rax), %xmm23
	vcvtuqq2phz 0x7777(%rax, %rbx, 8), %xmm23

	vcvtusi2sh %rax, %xmm0, %xmm1
	vcvtusi2sh %rax, {rn-sae}, %xmm11, %xmm21
	vcvtusi2sh %rax, {rd-sae}, %xmm12, %xmm22
	vcvtusi2sh %rax, {ru-sae}, %xmm13, %xmm23
	vcvtusi2sh %rax, {rz-sae}, %xmm14, %xmm24
	vcvtusi2sh (%r10), %xmm15, %xmm25
	vcvtusi2sh 0x23(%r10), %xmm15, %xmm25
	vcvtusi2sh 0x20(%r10), %xmm16, %xmm26
	vcvtusi2sh 0x40(%r10), %xmm17, %xmm27
	vcvtusi2sh 0x7777(%r10), %xmm18, %xmm28
	vcvtusi2sh 0x23(%r10, %r11, 8), %xmm19, %xmm29
	vcvtusi2sh %eax, %xmm0, %xmm1
	vcvtusi2sh %ebx, {rn-sae}, %xmm11, %xmm21
	vcvtusi2sh %ecx, {rd-sae}, %xmm12, %xmm22
	vcvtusi2sh %edx, {ru-sae}, %xmm13, %xmm23
	vcvtusi2sh %eax, {rz-sae}, %xmm14, %xmm24

	vcvtuw2ph %zmm2, %zmm22
	vcvtuw2ph %zmm3, %zmm23{%k3}
	vcvtuw2ph %zmm4, %zmm24{%k4}{z}
	vcvtuw2ph {rn-sae}, %zmm5, %zmm25
	vcvtuw2ph {rd-sae}, %zmm6, %zmm26{%k6}
	vcvtuw2ph {ru-sae}, %zmm7, %zmm27{%k7}{z}
	vcvtuw2ph {rz-sae}, %zmm8, %zmm28
	vcvtuw2ph 0x23(%rax), %zmm23
	vcvtuw2ph 0x23(%rax){1to32}, %zmm23
	vcvtuw2ph 0x80(%rax){1to32}, %zmm23
	vcvtuw2ph 0x20(%rax), %zmm23
	vcvtuw2ph 0x40(%rax), %zmm23
	vcvtuw2ph 0x7777(%rax, %rbx, 8), %zmm23
	vcvtuw2ph %ymm2, %ymm22
	vcvtuw2ph %ymm3, %ymm23{%k3}
	vcvtuw2ph %ymm4, %ymm24{%k4}{z}
	vcvtuw2ph 0x23(%rax), %ymm23
	vcvtuw2ph 0x23(%rax){1to16}, %ymm23
	vcvtuw2ph 0x80(%rax){1to16}, %ymm23
	vcvtuw2ph 0x20(%rax), %ymm23
	vcvtuw2ph 0x40(%rax), %ymm23
	vcvtuw2ph 0x7777(%rax, %rbx, 8), %ymm23
	vcvtuw2ph %xmm2, %xmm22
	vcvtuw2ph %xmm3, %xmm23{%k3}
	vcvtuw2ph %xmm4, %xmm24{%k4}{z}
	vcvtuw2ph 0x23(%rax), %xmm23
	vcvtuw2ph 0x23(%rax){1to8}, %xmm23
	vcvtuw2ph 0x80(%rax){1to8}, %xmm23
	vcvtuw2ph 0x20(%rax), %xmm23
	vcvtuw2ph 0x40(%rax), %xmm23
	vcvtuw2ph 0x7777(%rax, %rbx, 8), %xmm23

	vcvtw2ph %zmm2, %zmm22
	vcvtw2ph %zmm3, %zmm23{%k3}
	vcvtw2ph %zmm4, %zmm24{%k4}{z}
	vcvtw2ph {rn-sae}, %zmm5, %zmm25
	vcvtw2ph {rd-sae}, %zmm6, %zmm26{%k6}
	vcvtw2ph {ru-sae}, %zmm7, %zmm27{%k7}{z}
	vcvtw2ph {rz-sae}, %zmm8, %zmm28
	vcvtw2ph 0x23(%rax), %zmm23
	vcvtw2ph 0x23(%rax){1to32}, %zmm23
	vcvtw2ph 0x80(%rax){1to32}, %zmm23
	vcvtw2ph 0x20(%rax), %zmm23
	vcvtw2ph 0x40(%rax), %zmm23
	vcvtw2ph 0x7777(%rax, %rbx, 8), %zmm23
	vcvtw2ph %ymm2, %ymm22
	vcvtw2ph %ymm3, %ymm23{%k3}
	vcvtw2ph %ymm4, %ymm24{%k4}{z}
	vcvtw2ph 0x23(%rax), %ymm23
	vcvtw2ph 0x23(%rax){1to16}, %ymm23
	vcvtw2ph 0x80(%rax){1to16}, %ymm23
	vcvtw2ph 0x20(%rax), %ymm23
	vcvtw2ph 0x40(%rax), %ymm23
	vcvtw2ph 0x7777(%rax, %rbx, 8), %ymm23
	vcvtw2ph %xmm2, %xmm22
	vcvtw2ph %xmm3, %xmm23{%k3}
	vcvtw2ph %xmm4, %xmm24{%k4}{z}
	vcvtw2ph 0x23(%rax), %xmm23
	vcvtw2ph 0x23(%rax){1to8}, %xmm23
	vcvtw2ph 0x80(%rax){1to8}, %xmm23
	vcvtw2ph 0x20(%rax), %xmm23
	vcvtw2ph 0x40(%rax), %xmm23
	vcvtw2ph 0x7777(%rax, %rbx, 8), %xmm23

	vdivph %zmm0, %zmm10, %zmm20
	vdivph %zmm1, %zmm11, %zmm21{%k1}
	vdivph %zmm2, %zmm12, %zmm22{%k2}{z}
	vdivph {rn-sae}, %zmm3, %zmm13, %zmm23
	vdivph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vdivph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vdivph {rz-sae}, %zmm6, %zmm16, %zmm26
	vdivph (%rax), %zmm17, %zmm27
	vdivph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vdivph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vdivph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vdivph 0x20(%rcx), %zmm18, %zmm28
	vdivph 0x40(%rcx), %zmm17, %zmm27
	vdivph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vdivph %ymm0, %ymm10, %ymm20
	vdivph %ymm1, %ymm11, %ymm21{%k1}
	vdivph %ymm2, %ymm12, %ymm22{%k2}{z}
	vdivph (%rax), %ymm17, %ymm27
	vdivph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vdivph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vdivph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vdivph 0x20(%rcx), %ymm18, %ymm28
	vdivph 0x40(%rcx), %ymm17, %ymm27
	vdivph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vdivph %xmm0, %xmm10, %xmm20
	vdivph %xmm1, %xmm11, %xmm21{%k1}
	vdivph %xmm2, %xmm12, %xmm22{%k2}{z}
	vdivph (%rax), %xmm17, %xmm27
	vdivph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vdivph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vdivph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vdivph 0x20(%rcx), %xmm18, %xmm28
	vdivph 0x40(%rcx), %xmm17, %xmm27
	vdivph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vdivsh %xmm0, %xmm10, %xmm20
	vdivsh %xmm1, %xmm11, %xmm21{%k1}
	vdivsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vdivsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vdivsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vdivsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vdivsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vdivsh (%rax), %xmm17, %xmm27
	vdivsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vdivsh 0x20(%rcx), %xmm18, %xmm28
	vdivsh 0x40(%rcx), %xmm17, %xmm27
	vdivsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfcmaddcph %zmm0, %zmm10, %zmm20
	vfcmaddcph %zmm1, %zmm11, %zmm21{%k1}
	vfcmaddcph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfcmaddcph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfcmaddcph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfcmaddcph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfcmaddcph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfcmaddcph (%rax), %zmm17, %zmm27
	vfcmaddcph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfcmaddcph 0x23(%rbx){1to16}, %zmm19, %zmm29
	vfcmaddcph 0x80(%rbx){1to16}, %zmm19, %zmm29
	vfcmaddcph 0x20(%rcx), %zmm18, %zmm28
	vfcmaddcph 0x40(%rcx), %zmm17, %zmm27
	vfcmaddcph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfcmaddcph %ymm0, %ymm10, %ymm20
	vfcmaddcph %ymm1, %ymm11, %ymm21{%k1}
	vfcmaddcph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfcmaddcph (%rax), %ymm17, %ymm27
	vfcmaddcph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfcmaddcph 0x23(%rbx){1to8}, %ymm19, %ymm29
	vfcmaddcph 0x80(%rbx){1to8}, %ymm19, %ymm29
	vfcmaddcph 0x20(%rcx), %ymm18, %ymm28
	vfcmaddcph 0x40(%rcx), %ymm17, %ymm27
	vfcmaddcph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfcmaddcph %xmm0, %xmm10, %xmm20
	vfcmaddcph %xmm1, %xmm11, %xmm21{%k1}
	vfcmaddcph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfcmaddcph (%rax), %xmm17, %xmm27
	vfcmaddcph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfcmaddcph 0x23(%rbx){1to4}, %xmm19, %xmm29
	vfcmaddcph 0x80(%rbx){1to4}, %xmm19, %xmm29
	vfcmaddcph 0x20(%rcx), %xmm18, %xmm28
	vfcmaddcph 0x40(%rcx), %xmm17, %xmm27
	vfcmaddcph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmaddcph %zmm0, %zmm10, %zmm20
	vfmaddcph %zmm1, %zmm11, %zmm21{%k1}
	vfmaddcph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmaddcph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmaddcph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmaddcph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmaddcph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmaddcph (%rax), %zmm17, %zmm27
	vfmaddcph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmaddcph 0x23(%rbx){1to16}, %zmm19, %zmm29
	vfmaddcph 0x80(%rbx){1to16}, %zmm19, %zmm29
	vfmaddcph 0x20(%rcx), %zmm18, %zmm28
	vfmaddcph 0x40(%rcx), %zmm17, %zmm27
	vfmaddcph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmaddcph %ymm0, %ymm10, %ymm20
	vfmaddcph %ymm1, %ymm11, %ymm21{%k1}
	vfmaddcph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmaddcph (%rax), %ymm17, %ymm27
	vfmaddcph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmaddcph 0x23(%rbx){1to8}, %ymm19, %ymm29
	vfmaddcph 0x80(%rbx){1to8}, %ymm19, %ymm29
	vfmaddcph 0x20(%rcx), %ymm18, %ymm28
	vfmaddcph 0x40(%rcx), %ymm17, %ymm27
	vfmaddcph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmaddcph %xmm0, %xmm10, %xmm20
	vfmaddcph %xmm1, %xmm11, %xmm21{%k1}
	vfmaddcph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmaddcph (%rax), %xmm17, %xmm27
	vfmaddcph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmaddcph 0x23(%rbx){1to4}, %xmm19, %xmm29
	vfmaddcph 0x80(%rbx){1to4}, %xmm19, %xmm29
	vfmaddcph 0x20(%rcx), %xmm18, %xmm28
	vfmaddcph 0x40(%rcx), %xmm17, %xmm27
	vfmaddcph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfcmaddcsh %xmm0, %xmm10, %xmm20
	vfcmaddcsh %xmm1, %xmm11, %xmm21{%k1}
	vfcmaddcsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfcmaddcsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfcmaddcsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfcmaddcsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfcmaddcsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfcmaddcsh (%rax), %xmm17, %xmm27
	vfcmaddcsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfcmaddcsh 0x20(%rcx), %xmm18, %xmm28
	vfcmaddcsh 0x40(%rcx), %xmm17, %xmm27
	vfcmaddcsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmaddcsh %xmm0, %xmm10, %xmm20
	vfmaddcsh %xmm1, %xmm11, %xmm21{%k1}
	vfmaddcsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmaddcsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmaddcsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmaddcsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmaddcsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmaddcsh (%rax), %xmm17, %xmm27
	vfmaddcsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmaddcsh 0x20(%rcx), %xmm18, %xmm28
	vfmaddcsh 0x40(%rcx), %xmm17, %xmm27
	vfmaddcsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfcmulcph %zmm0, %zmm10, %zmm20
	vfcmulcph %zmm1, %zmm11, %zmm21{%k1}
	vfcmulcph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfcmulcph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfcmulcph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfcmulcph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfcmulcph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfcmulcph (%rax), %zmm17, %zmm27
	vfcmulcph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfcmulcph 0x23(%rbx){1to16}, %zmm19, %zmm29
	vfcmulcph 0x80(%rbx){1to16}, %zmm19, %zmm29
	vfcmulcph 0x20(%rcx), %zmm18, %zmm28
	vfcmulcph 0x40(%rcx), %zmm17, %zmm27
	vfcmulcph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfcmulcph %ymm0, %ymm10, %ymm20
	vfcmulcph %ymm1, %ymm11, %ymm21{%k1}
	vfcmulcph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfcmulcph (%rax), %ymm17, %ymm27
	vfcmulcph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfcmulcph 0x23(%rbx){1to8}, %ymm19, %ymm29
	vfcmulcph 0x80(%rbx){1to8}, %ymm19, %ymm29
	vfcmulcph 0x20(%rcx), %ymm18, %ymm28
	vfcmulcph 0x40(%rcx), %ymm17, %ymm27
	vfcmulcph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfcmulcph %xmm0, %xmm10, %xmm20
	vfcmulcph %xmm1, %xmm11, %xmm21{%k1}
	vfcmulcph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfcmulcph (%rax), %xmm17, %xmm27
	vfcmulcph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfcmulcph 0x23(%rbx){1to4}, %xmm19, %xmm29
	vfcmulcph 0x80(%rbx){1to4}, %xmm19, %xmm29
	vfcmulcph 0x20(%rcx), %xmm18, %xmm28
	vfcmulcph 0x40(%rcx), %xmm17, %xmm27
	vfcmulcph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmulcph %zmm0, %zmm10, %zmm20
	vfmulcph %zmm1, %zmm11, %zmm21{%k1}
	vfmulcph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmulcph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmulcph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmulcph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmulcph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmulcph (%rax), %zmm17, %zmm27
	vfmulcph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmulcph 0x23(%rbx){1to16}, %zmm19, %zmm29
	vfmulcph 0x80(%rbx){1to16}, %zmm19, %zmm29
	vfmulcph 0x20(%rcx), %zmm18, %zmm28
	vfmulcph 0x40(%rcx), %zmm17, %zmm27
	vfmulcph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmulcph %ymm0, %ymm10, %ymm20
	vfmulcph %ymm1, %ymm11, %ymm21{%k1}
	vfmulcph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmulcph (%rax), %ymm17, %ymm27
	vfmulcph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmulcph 0x23(%rbx){1to8}, %ymm19, %ymm29
	vfmulcph 0x80(%rbx){1to8}, %ymm19, %ymm29
	vfmulcph 0x20(%rcx), %ymm18, %ymm28
	vfmulcph 0x40(%rcx), %ymm17, %ymm27
	vfmulcph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmulcph %xmm0, %xmm10, %xmm20
	vfmulcph %xmm1, %xmm11, %xmm21{%k1}
	vfmulcph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmulcph (%rax), %xmm17, %xmm27
	vfmulcph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmulcph 0x23(%rbx){1to4}, %xmm19, %xmm29
	vfmulcph 0x80(%rbx){1to4}, %xmm19, %xmm29
	vfmulcph 0x20(%rcx), %xmm18, %xmm28
	vfmulcph 0x40(%rcx), %xmm17, %xmm27
	vfmulcph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfcmulcsh %xmm0, %xmm10, %xmm20
	vfcmulcsh %xmm1, %xmm11, %xmm21{%k1}
	vfcmulcsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfcmulcsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfcmulcsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfcmulcsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfcmulcsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfcmulcsh (%rax), %xmm17, %xmm27
	vfcmulcsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfcmulcsh 0x20(%rcx), %xmm18, %xmm28
	vfcmulcsh 0x40(%rcx), %xmm17, %xmm27
	vfcmulcsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmulcsh %xmm0, %xmm10, %xmm20
	vfmulcsh %xmm1, %xmm11, %xmm21{%k1}
	vfmulcsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmulcsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmulcsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmulcsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmulcsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmulcsh (%rax), %xmm17, %xmm27
	vfmulcsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmulcsh 0x20(%rcx), %xmm18, %xmm28
	vfmulcsh 0x40(%rcx), %xmm17, %xmm27
	vfmulcsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmaddsub132ph %zmm0, %zmm10, %zmm20
	vfmaddsub132ph %zmm1, %zmm11, %zmm21{%k1}
	vfmaddsub132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmaddsub132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmaddsub132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmaddsub132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmaddsub132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmaddsub132ph (%rax), %zmm17, %zmm27
	vfmaddsub132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmaddsub132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub132ph 0x20(%rcx), %zmm18, %zmm28
	vfmaddsub132ph 0x40(%rcx), %zmm17, %zmm27
	vfmaddsub132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmaddsub132ph %ymm0, %ymm10, %ymm20
	vfmaddsub132ph %ymm1, %ymm11, %ymm21{%k1}
	vfmaddsub132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmaddsub132ph (%rax), %ymm17, %ymm27
	vfmaddsub132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmaddsub132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub132ph 0x20(%rcx), %ymm18, %ymm28
	vfmaddsub132ph 0x40(%rcx), %ymm17, %ymm27
	vfmaddsub132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmaddsub132ph %xmm0, %xmm10, %xmm20
	vfmaddsub132ph %xmm1, %xmm11, %xmm21{%k1}
	vfmaddsub132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmaddsub132ph (%rax), %xmm17, %xmm27
	vfmaddsub132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmaddsub132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub132ph 0x20(%rcx), %xmm18, %xmm28
	vfmaddsub132ph 0x40(%rcx), %xmm17, %xmm27
	vfmaddsub132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmaddsub213ph %zmm0, %zmm10, %zmm20
	vfmaddsub213ph %zmm1, %zmm11, %zmm21{%k1}
	vfmaddsub213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmaddsub213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmaddsub213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmaddsub213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmaddsub213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmaddsub213ph (%rax), %zmm17, %zmm27
	vfmaddsub213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmaddsub213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub213ph 0x20(%rcx), %zmm18, %zmm28
	vfmaddsub213ph 0x40(%rcx), %zmm17, %zmm27
	vfmaddsub213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmaddsub213ph %ymm0, %ymm10, %ymm20
	vfmaddsub213ph %ymm1, %ymm11, %ymm21{%k1}
	vfmaddsub213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmaddsub213ph (%rax), %ymm17, %ymm27
	vfmaddsub213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmaddsub213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub213ph 0x20(%rcx), %ymm18, %ymm28
	vfmaddsub213ph 0x40(%rcx), %ymm17, %ymm27
	vfmaddsub213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmaddsub213ph %xmm0, %xmm10, %xmm20
	vfmaddsub213ph %xmm1, %xmm11, %xmm21{%k1}
	vfmaddsub213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmaddsub213ph (%rax), %xmm17, %xmm27
	vfmaddsub213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmaddsub213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub213ph 0x20(%rcx), %xmm18, %xmm28
	vfmaddsub213ph 0x40(%rcx), %xmm17, %xmm27
	vfmaddsub213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmaddsub231ph %zmm0, %zmm10, %zmm20
	vfmaddsub231ph %zmm1, %zmm11, %zmm21{%k1}
	vfmaddsub231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmaddsub231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmaddsub231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmaddsub231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmaddsub231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmaddsub231ph (%rax), %zmm17, %zmm27
	vfmaddsub231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmaddsub231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmaddsub231ph 0x20(%rcx), %zmm18, %zmm28
	vfmaddsub231ph 0x40(%rcx), %zmm17, %zmm27
	vfmaddsub231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmaddsub231ph %ymm0, %ymm10, %ymm20
	vfmaddsub231ph %ymm1, %ymm11, %ymm21{%k1}
	vfmaddsub231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmaddsub231ph (%rax), %ymm17, %ymm27
	vfmaddsub231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmaddsub231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmaddsub231ph 0x20(%rcx), %ymm18, %ymm28
	vfmaddsub231ph 0x40(%rcx), %ymm17, %ymm27
	vfmaddsub231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmaddsub231ph %xmm0, %xmm10, %xmm20
	vfmaddsub231ph %xmm1, %xmm11, %xmm21{%k1}
	vfmaddsub231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmaddsub231ph (%rax), %xmm17, %xmm27
	vfmaddsub231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmaddsub231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmaddsub231ph 0x20(%rcx), %xmm18, %xmm28
	vfmaddsub231ph 0x40(%rcx), %xmm17, %xmm27
	vfmaddsub231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsubadd132ph %zmm0, %zmm10, %zmm20
	vfmsubadd132ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsubadd132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsubadd132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsubadd132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsubadd132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsubadd132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsubadd132ph (%rax), %zmm17, %zmm27
	vfmsubadd132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsubadd132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd132ph 0x20(%rcx), %zmm18, %zmm28
	vfmsubadd132ph 0x40(%rcx), %zmm17, %zmm27
	vfmsubadd132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsubadd132ph %ymm0, %ymm10, %ymm20
	vfmsubadd132ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsubadd132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsubadd132ph (%rax), %ymm17, %ymm27
	vfmsubadd132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsubadd132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd132ph 0x20(%rcx), %ymm18, %ymm28
	vfmsubadd132ph 0x40(%rcx), %ymm17, %ymm27
	vfmsubadd132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsubadd132ph %xmm0, %xmm10, %xmm20
	vfmsubadd132ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsubadd132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsubadd132ph (%rax), %xmm17, %xmm27
	vfmsubadd132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsubadd132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd132ph 0x20(%rcx), %xmm18, %xmm28
	vfmsubadd132ph 0x40(%rcx), %xmm17, %xmm27
	vfmsubadd132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsubadd213ph %zmm0, %zmm10, %zmm20
	vfmsubadd213ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsubadd213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsubadd213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsubadd213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsubadd213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsubadd213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsubadd213ph (%rax), %zmm17, %zmm27
	vfmsubadd213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsubadd213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd213ph 0x20(%rcx), %zmm18, %zmm28
	vfmsubadd213ph 0x40(%rcx), %zmm17, %zmm27
	vfmsubadd213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsubadd213ph %ymm0, %ymm10, %ymm20
	vfmsubadd213ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsubadd213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsubadd213ph (%rax), %ymm17, %ymm27
	vfmsubadd213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsubadd213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd213ph 0x20(%rcx), %ymm18, %ymm28
	vfmsubadd213ph 0x40(%rcx), %ymm17, %ymm27
	vfmsubadd213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsubadd213ph %xmm0, %xmm10, %xmm20
	vfmsubadd213ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsubadd213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsubadd213ph (%rax), %xmm17, %xmm27
	vfmsubadd213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsubadd213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd213ph 0x20(%rcx), %xmm18, %xmm28
	vfmsubadd213ph 0x40(%rcx), %xmm17, %xmm27
	vfmsubadd213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsubadd231ph %zmm0, %zmm10, %zmm20
	vfmsubadd231ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsubadd231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsubadd231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsubadd231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsubadd231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsubadd231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsubadd231ph (%rax), %zmm17, %zmm27
	vfmsubadd231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsubadd231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsubadd231ph 0x20(%rcx), %zmm18, %zmm28
	vfmsubadd231ph 0x40(%rcx), %zmm17, %zmm27
	vfmsubadd231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsubadd231ph %ymm0, %ymm10, %ymm20
	vfmsubadd231ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsubadd231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsubadd231ph (%rax), %ymm17, %ymm27
	vfmsubadd231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsubadd231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsubadd231ph 0x20(%rcx), %ymm18, %ymm28
	vfmsubadd231ph 0x40(%rcx), %ymm17, %ymm27
	vfmsubadd231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsubadd231ph %xmm0, %xmm10, %xmm20
	vfmsubadd231ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsubadd231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsubadd231ph (%rax), %xmm17, %xmm27
	vfmsubadd231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsubadd231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsubadd231ph 0x20(%rcx), %xmm18, %xmm28
	vfmsubadd231ph 0x40(%rcx), %xmm17, %xmm27
	vfmsubadd231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd132ph %zmm0, %zmm10, %zmm20
	vfmadd132ph %zmm1, %zmm11, %zmm21{%k1}
	vfmadd132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmadd132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmadd132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmadd132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmadd132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmadd132ph (%rax), %zmm17, %zmm27
	vfmadd132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmadd132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmadd132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmadd132ph 0x20(%rcx), %zmm18, %zmm28
	vfmadd132ph 0x40(%rcx), %zmm17, %zmm27
	vfmadd132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmadd132ph %ymm0, %ymm10, %ymm20
	vfmadd132ph %ymm1, %ymm11, %ymm21{%k1}
	vfmadd132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmadd132ph (%rax), %ymm17, %ymm27
	vfmadd132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmadd132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmadd132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmadd132ph 0x20(%rcx), %ymm18, %ymm28
	vfmadd132ph 0x40(%rcx), %ymm17, %ymm27
	vfmadd132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmadd132ph %xmm0, %xmm10, %xmm20
	vfmadd132ph %xmm1, %xmm11, %xmm21{%k1}
	vfmadd132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd132ph (%rax), %xmm17, %xmm27
	vfmadd132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmadd132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmadd132ph 0x20(%rcx), %xmm18, %xmm28
	vfmadd132ph 0x40(%rcx), %xmm17, %xmm27
	vfmadd132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd132ph %zmm0, %zmm10, %zmm20
	vfnmadd132ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmadd132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmadd132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmadd132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmadd132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmadd132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmadd132ph (%rax), %zmm17, %zmm27
	vfnmadd132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmadd132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd132ph 0x20(%rcx), %zmm18, %zmm28
	vfnmadd132ph 0x40(%rcx), %zmm17, %zmm27
	vfnmadd132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmadd132ph %ymm0, %ymm10, %ymm20
	vfnmadd132ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmadd132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmadd132ph (%rax), %ymm17, %ymm27
	vfnmadd132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmadd132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd132ph 0x20(%rcx), %ymm18, %ymm28
	vfnmadd132ph 0x40(%rcx), %ymm17, %ymm27
	vfnmadd132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmadd132ph %xmm0, %xmm10, %xmm20
	vfnmadd132ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd132ph (%rax), %xmm17, %xmm27
	vfnmadd132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd132ph 0x20(%rcx), %xmm18, %xmm28
	vfnmadd132ph 0x40(%rcx), %xmm17, %xmm27
	vfnmadd132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd213ph %zmm0, %zmm10, %zmm20
	vfmadd213ph %zmm1, %zmm11, %zmm21{%k1}
	vfmadd213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmadd213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmadd213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmadd213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmadd213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmadd213ph (%rax), %zmm17, %zmm27
	vfmadd213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmadd213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmadd213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmadd213ph 0x20(%rcx), %zmm18, %zmm28
	vfmadd213ph 0x40(%rcx), %zmm17, %zmm27
	vfmadd213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmadd213ph %ymm0, %ymm10, %ymm20
	vfmadd213ph %ymm1, %ymm11, %ymm21{%k1}
	vfmadd213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmadd213ph (%rax), %ymm17, %ymm27
	vfmadd213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmadd213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmadd213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmadd213ph 0x20(%rcx), %ymm18, %ymm28
	vfmadd213ph 0x40(%rcx), %ymm17, %ymm27
	vfmadd213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmadd213ph %xmm0, %xmm10, %xmm20
	vfmadd213ph %xmm1, %xmm11, %xmm21{%k1}
	vfmadd213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd213ph (%rax), %xmm17, %xmm27
	vfmadd213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmadd213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmadd213ph 0x20(%rcx), %xmm18, %xmm28
	vfmadd213ph 0x40(%rcx), %xmm17, %xmm27
	vfmadd213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd213ph %zmm0, %zmm10, %zmm20
	vfnmadd213ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmadd213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmadd213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmadd213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmadd213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmadd213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmadd213ph (%rax), %zmm17, %zmm27
	vfnmadd213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmadd213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd213ph 0x20(%rcx), %zmm18, %zmm28
	vfnmadd213ph 0x40(%rcx), %zmm17, %zmm27
	vfnmadd213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmadd213ph %ymm0, %ymm10, %ymm20
	vfnmadd213ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmadd213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmadd213ph (%rax), %ymm17, %ymm27
	vfnmadd213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmadd213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd213ph 0x20(%rcx), %ymm18, %ymm28
	vfnmadd213ph 0x40(%rcx), %ymm17, %ymm27
	vfnmadd213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmadd213ph %xmm0, %xmm10, %xmm20
	vfnmadd213ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd213ph (%rax), %xmm17, %xmm27
	vfnmadd213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd213ph 0x20(%rcx), %xmm18, %xmm28
	vfnmadd213ph 0x40(%rcx), %xmm17, %xmm27
	vfnmadd213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd231ph %zmm0, %zmm10, %zmm20
	vfmadd231ph %zmm1, %zmm11, %zmm21{%k1}
	vfmadd231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmadd231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmadd231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmadd231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmadd231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmadd231ph (%rax), %zmm17, %zmm27
	vfmadd231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmadd231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmadd231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmadd231ph 0x20(%rcx), %zmm18, %zmm28
	vfmadd231ph 0x40(%rcx), %zmm17, %zmm27
	vfmadd231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmadd231ph %ymm0, %ymm10, %ymm20
	vfmadd231ph %ymm1, %ymm11, %ymm21{%k1}
	vfmadd231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmadd231ph (%rax), %ymm17, %ymm27
	vfmadd231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmadd231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmadd231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmadd231ph 0x20(%rcx), %ymm18, %ymm28
	vfmadd231ph 0x40(%rcx), %ymm17, %ymm27
	vfmadd231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmadd231ph %xmm0, %xmm10, %xmm20
	vfmadd231ph %xmm1, %xmm11, %xmm21{%k1}
	vfmadd231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd231ph (%rax), %xmm17, %xmm27
	vfmadd231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmadd231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmadd231ph 0x20(%rcx), %xmm18, %xmm28
	vfmadd231ph 0x40(%rcx), %xmm17, %xmm27
	vfmadd231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd231ph %zmm0, %zmm10, %zmm20
	vfnmadd231ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmadd231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmadd231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmadd231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmadd231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmadd231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmadd231ph (%rax), %zmm17, %zmm27
	vfnmadd231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmadd231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmadd231ph 0x20(%rcx), %zmm18, %zmm28
	vfnmadd231ph 0x40(%rcx), %zmm17, %zmm27
	vfnmadd231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmadd231ph %ymm0, %ymm10, %ymm20
	vfnmadd231ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmadd231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmadd231ph (%rax), %ymm17, %ymm27
	vfnmadd231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmadd231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmadd231ph 0x20(%rcx), %ymm18, %ymm28
	vfnmadd231ph 0x40(%rcx), %ymm17, %ymm27
	vfnmadd231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmadd231ph %xmm0, %xmm10, %xmm20
	vfnmadd231ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd231ph (%rax), %xmm17, %xmm27
	vfnmadd231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmadd231ph 0x20(%rcx), %xmm18, %xmm28
	vfnmadd231ph 0x40(%rcx), %xmm17, %xmm27
	vfnmadd231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd132sh %xmm0, %xmm10, %xmm20
	vfmadd132sh %xmm1, %xmm11, %xmm21{%k1}
	vfmadd132sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd132sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmadd132sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmadd132sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmadd132sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmadd132sh (%rax), %xmm17, %xmm27
	vfmadd132sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd132sh 0x20(%rcx), %xmm18, %xmm28
	vfmadd132sh 0x40(%rcx), %xmm17, %xmm27
	vfmadd132sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd132sh %xmm0, %xmm10, %xmm20
	vfnmadd132sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd132sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd132sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmadd132sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmadd132sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmadd132sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmadd132sh (%rax), %xmm17, %xmm27
	vfnmadd132sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd132sh 0x20(%rcx), %xmm18, %xmm28
	vfnmadd132sh 0x40(%rcx), %xmm17, %xmm27
	vfnmadd132sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd213sh %xmm0, %xmm10, %xmm20
	vfmadd213sh %xmm1, %xmm11, %xmm21{%k1}
	vfmadd213sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd213sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmadd213sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmadd213sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmadd213sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmadd213sh (%rax), %xmm17, %xmm27
	vfmadd213sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd213sh 0x20(%rcx), %xmm18, %xmm28
	vfmadd213sh 0x40(%rcx), %xmm17, %xmm27
	vfmadd213sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd213sh %xmm0, %xmm10, %xmm20
	vfnmadd213sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd213sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd213sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmadd213sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmadd213sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmadd213sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmadd213sh (%rax), %xmm17, %xmm27
	vfnmadd213sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd213sh 0x20(%rcx), %xmm18, %xmm28
	vfnmadd213sh 0x40(%rcx), %xmm17, %xmm27
	vfnmadd213sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmadd231sh %xmm0, %xmm10, %xmm20
	vfmadd231sh %xmm1, %xmm11, %xmm21{%k1}
	vfmadd231sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmadd231sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmadd231sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmadd231sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmadd231sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmadd231sh (%rax), %xmm17, %xmm27
	vfmadd231sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmadd231sh 0x20(%rcx), %xmm18, %xmm28
	vfmadd231sh 0x40(%rcx), %xmm17, %xmm27
	vfmadd231sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmadd231sh %xmm0, %xmm10, %xmm20
	vfnmadd231sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmadd231sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmadd231sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmadd231sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmadd231sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmadd231sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmadd231sh (%rax), %xmm17, %xmm27
	vfnmadd231sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmadd231sh 0x20(%rcx), %xmm18, %xmm28
	vfnmadd231sh 0x40(%rcx), %xmm17, %xmm27
	vfnmadd231sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub132ph %zmm0, %zmm10, %zmm20
	vfmsub132ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsub132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsub132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsub132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsub132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsub132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsub132ph (%rax), %zmm17, %zmm27
	vfmsub132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsub132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsub132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsub132ph 0x20(%rcx), %zmm18, %zmm28
	vfmsub132ph 0x40(%rcx), %zmm17, %zmm27
	vfmsub132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsub132ph %ymm0, %ymm10, %ymm20
	vfmsub132ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsub132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsub132ph (%rax), %ymm17, %ymm27
	vfmsub132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsub132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsub132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsub132ph 0x20(%rcx), %ymm18, %ymm28
	vfmsub132ph 0x40(%rcx), %ymm17, %ymm27
	vfmsub132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsub132ph %xmm0, %xmm10, %xmm20
	vfmsub132ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsub132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub132ph (%rax), %xmm17, %xmm27
	vfmsub132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsub132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsub132ph 0x20(%rcx), %xmm18, %xmm28
	vfmsub132ph 0x40(%rcx), %xmm17, %xmm27
	vfmsub132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub132ph %zmm0, %zmm10, %zmm20
	vfnmsub132ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmsub132ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmsub132ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmsub132ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmsub132ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmsub132ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmsub132ph (%rax), %zmm17, %zmm27
	vfnmsub132ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmsub132ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub132ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub132ph 0x20(%rcx), %zmm18, %zmm28
	vfnmsub132ph 0x40(%rcx), %zmm17, %zmm27
	vfnmsub132ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmsub132ph %ymm0, %ymm10, %ymm20
	vfnmsub132ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmsub132ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmsub132ph (%rax), %ymm17, %ymm27
	vfnmsub132ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmsub132ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub132ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub132ph 0x20(%rcx), %ymm18, %ymm28
	vfnmsub132ph 0x40(%rcx), %ymm17, %ymm27
	vfnmsub132ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmsub132ph %xmm0, %xmm10, %xmm20
	vfnmsub132ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub132ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub132ph (%rax), %xmm17, %xmm27
	vfnmsub132ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub132ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub132ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub132ph 0x20(%rcx), %xmm18, %xmm28
	vfnmsub132ph 0x40(%rcx), %xmm17, %xmm27
	vfnmsub132ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub213ph %zmm0, %zmm10, %zmm20
	vfmsub213ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsub213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsub213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsub213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsub213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsub213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsub213ph (%rax), %zmm17, %zmm27
	vfmsub213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsub213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsub213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsub213ph 0x20(%rcx), %zmm18, %zmm28
	vfmsub213ph 0x40(%rcx), %zmm17, %zmm27
	vfmsub213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsub213ph %ymm0, %ymm10, %ymm20
	vfmsub213ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsub213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsub213ph (%rax), %ymm17, %ymm27
	vfmsub213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsub213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsub213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsub213ph 0x20(%rcx), %ymm18, %ymm28
	vfmsub213ph 0x40(%rcx), %ymm17, %ymm27
	vfmsub213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsub213ph %xmm0, %xmm10, %xmm20
	vfmsub213ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsub213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub213ph (%rax), %xmm17, %xmm27
	vfmsub213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsub213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsub213ph 0x20(%rcx), %xmm18, %xmm28
	vfmsub213ph 0x40(%rcx), %xmm17, %xmm27
	vfmsub213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub213ph %zmm0, %zmm10, %zmm20
	vfnmsub213ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmsub213ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmsub213ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmsub213ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmsub213ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmsub213ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmsub213ph (%rax), %zmm17, %zmm27
	vfnmsub213ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmsub213ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub213ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub213ph 0x20(%rcx), %zmm18, %zmm28
	vfnmsub213ph 0x40(%rcx), %zmm17, %zmm27
	vfnmsub213ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmsub213ph %ymm0, %ymm10, %ymm20
	vfnmsub213ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmsub213ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmsub213ph (%rax), %ymm17, %ymm27
	vfnmsub213ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmsub213ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub213ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub213ph 0x20(%rcx), %ymm18, %ymm28
	vfnmsub213ph 0x40(%rcx), %ymm17, %ymm27
	vfnmsub213ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmsub213ph %xmm0, %xmm10, %xmm20
	vfnmsub213ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub213ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub213ph (%rax), %xmm17, %xmm27
	vfnmsub213ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub213ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub213ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub213ph 0x20(%rcx), %xmm18, %xmm28
	vfnmsub213ph 0x40(%rcx), %xmm17, %xmm27
	vfnmsub213ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub231ph %zmm0, %zmm10, %zmm20
	vfmsub231ph %zmm1, %zmm11, %zmm21{%k1}
	vfmsub231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfmsub231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfmsub231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfmsub231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfmsub231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfmsub231ph (%rax), %zmm17, %zmm27
	vfmsub231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfmsub231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfmsub231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfmsub231ph 0x20(%rcx), %zmm18, %zmm28
	vfmsub231ph 0x40(%rcx), %zmm17, %zmm27
	vfmsub231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfmsub231ph %ymm0, %ymm10, %ymm20
	vfmsub231ph %ymm1, %ymm11, %ymm21{%k1}
	vfmsub231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfmsub231ph (%rax), %ymm17, %ymm27
	vfmsub231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfmsub231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfmsub231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfmsub231ph 0x20(%rcx), %ymm18, %ymm28
	vfmsub231ph 0x40(%rcx), %ymm17, %ymm27
	vfmsub231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfmsub231ph %xmm0, %xmm10, %xmm20
	vfmsub231ph %xmm1, %xmm11, %xmm21{%k1}
	vfmsub231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub231ph (%rax), %xmm17, %xmm27
	vfmsub231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfmsub231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfmsub231ph 0x20(%rcx), %xmm18, %xmm28
	vfmsub231ph 0x40(%rcx), %xmm17, %xmm27
	vfmsub231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub231ph %zmm0, %zmm10, %zmm20
	vfnmsub231ph %zmm1, %zmm11, %zmm21{%k1}
	vfnmsub231ph %zmm2, %zmm12, %zmm22{%k2}{z}
	vfnmsub231ph {rn-sae}, %zmm3, %zmm13, %zmm23
	vfnmsub231ph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vfnmsub231ph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vfnmsub231ph {rz-sae}, %zmm6, %zmm16, %zmm26
	vfnmsub231ph (%rax), %zmm17, %zmm27
	vfnmsub231ph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vfnmsub231ph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub231ph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vfnmsub231ph 0x20(%rcx), %zmm18, %zmm28
	vfnmsub231ph 0x40(%rcx), %zmm17, %zmm27
	vfnmsub231ph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vfnmsub231ph %ymm0, %ymm10, %ymm20
	vfnmsub231ph %ymm1, %ymm11, %ymm21{%k1}
	vfnmsub231ph %ymm2, %ymm12, %ymm22{%k2}{z}
	vfnmsub231ph (%rax), %ymm17, %ymm27
	vfnmsub231ph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vfnmsub231ph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub231ph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vfnmsub231ph 0x20(%rcx), %ymm18, %ymm28
	vfnmsub231ph 0x40(%rcx), %ymm17, %ymm27
	vfnmsub231ph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vfnmsub231ph %xmm0, %xmm10, %xmm20
	vfnmsub231ph %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub231ph %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub231ph (%rax), %xmm17, %xmm27
	vfnmsub231ph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub231ph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub231ph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vfnmsub231ph 0x20(%rcx), %xmm18, %xmm28
	vfnmsub231ph 0x40(%rcx), %xmm17, %xmm27
	vfnmsub231ph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub132sh %xmm0, %xmm10, %xmm20
	vfmsub132sh %xmm1, %xmm11, %xmm21{%k1}
	vfmsub132sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub132sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmsub132sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmsub132sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmsub132sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmsub132sh (%rax), %xmm17, %xmm27
	vfmsub132sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub132sh 0x20(%rcx), %xmm18, %xmm28
	vfmsub132sh 0x40(%rcx), %xmm17, %xmm27
	vfmsub132sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub132sh %xmm0, %xmm10, %xmm20
	vfnmsub132sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub132sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub132sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmsub132sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmsub132sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmsub132sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmsub132sh (%rax), %xmm17, %xmm27
	vfnmsub132sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub132sh 0x20(%rcx), %xmm18, %xmm28
	vfnmsub132sh 0x40(%rcx), %xmm17, %xmm27
	vfnmsub132sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub213sh %xmm0, %xmm10, %xmm20
	vfmsub213sh %xmm1, %xmm11, %xmm21{%k1}
	vfmsub213sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub213sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmsub213sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmsub213sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmsub213sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmsub213sh (%rax), %xmm17, %xmm27
	vfmsub213sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub213sh 0x20(%rcx), %xmm18, %xmm28
	vfmsub213sh 0x40(%rcx), %xmm17, %xmm27
	vfmsub213sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub213sh %xmm0, %xmm10, %xmm20
	vfnmsub213sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub213sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub213sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmsub213sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmsub213sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmsub213sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmsub213sh (%rax), %xmm17, %xmm27
	vfnmsub213sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub213sh 0x20(%rcx), %xmm18, %xmm28
	vfnmsub213sh 0x40(%rcx), %xmm17, %xmm27
	vfnmsub213sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfmsub231sh %xmm0, %xmm10, %xmm20
	vfmsub231sh %xmm1, %xmm11, %xmm21{%k1}
	vfmsub231sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfmsub231sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfmsub231sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfmsub231sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfmsub231sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfmsub231sh (%rax), %xmm17, %xmm27
	vfmsub231sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfmsub231sh 0x20(%rcx), %xmm18, %xmm28
	vfmsub231sh 0x40(%rcx), %xmm17, %xmm27
	vfmsub231sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfnmsub231sh %xmm0, %xmm10, %xmm20
	vfnmsub231sh %xmm1, %xmm11, %xmm21{%k1}
	vfnmsub231sh %xmm2, %xmm12, %xmm22{%k2}{z}
	vfnmsub231sh {rn-sae}, %xmm3, %xmm13, %xmm23
	vfnmsub231sh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vfnmsub231sh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vfnmsub231sh {rz-sae}, %xmm6, %xmm16, %xmm26
	vfnmsub231sh (%rax), %xmm17, %xmm27
	vfnmsub231sh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vfnmsub231sh 0x20(%rcx), %xmm18, %xmm28
	vfnmsub231sh 0x40(%rcx), %xmm17, %xmm27
	vfnmsub231sh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vfpclassph $0x42, %zmm20, %k0
	vfpclassph $0x42, %zmm21, %k1{%k2}
	vfpclassphz $0x42, (%r8), %k2
	vfpclassphz $0x42, 0x23(%r9), %k3
	vfpclassph $0x42, 0x23(%r9){1to32}, %k3
	vfpclassph $0x42, 0x80(%r9){1to32}, %k3
	vfpclassphz $0x42, 0x20(%r9), %k4
	vfpclassphz $0x42, 0x40(%r9), %k5
	vfpclassphz $0x42, 0x7777(%r9), %k6{%k7}
	vfpclassphz $0x42, 0x7777(%r10, %r11, 8), %k7
	vfpclassph $0x42, %ymm20, %k0
	vfpclassph $0x42, %ymm21, %k1{%k2}
	vfpclassphy $0x42, (%r8), %k2
	vfpclassphy $0x42, 0x23(%r9), %k3
	vfpclassph $0x42, 0x23(%r9){1to16}, %k3
	vfpclassph $0x42, 0x80(%r9){1to16}, %k3
	vfpclassphy $0x42, 0x20(%r9), %k4
	vfpclassphy $0x42, 0x40(%r9), %k5
	vfpclassphy $0x42, 0x7777(%r9), %k6{%k7}
	vfpclassphy $0x42, 0x7777(%r10, %r11, 8), %k7
	vfpclassph $0x42, %xmm20, %k0
	vfpclassph $0x42, %xmm21, %k1{%k2}
	vfpclassphx $0x42, (%r8), %k2
	vfpclassphx $0x42, 0x23(%r9), %k3
	vfpclassph $0x42, 0x23(%r9){1to8}, %k3
	vfpclassph $0x42, 0x80(%r9){1to8}, %k3
	vfpclassphx $0x42, 0x20(%r9), %k4
	vfpclassphx $0x42, 0x40(%r9), %k5
	vfpclassphx $0x42, 0x7777(%r9), %k6{%k7}
	vfpclassphx $0x42, 0x7777(%r10, %r11, 8), %k7

	vfpclasssh $0x42, %xmm20, %k0
	vfpclasssh $0x42, %xmm21, %k1{%k2}
	vfpclasssh $0x42, (%r8), %k2
	vfpclasssh $0x42, 0x23(%r9), %k3
	vfpclasssh $0x42, 0x20(%r9), %k4
	vfpclasssh $0x42, 0x40(%r9), %k5
	vfpclasssh $0x42, 0x7777(%r9), %k6{%k7}
	vfpclasssh $0x42, 0x7777(%r10, %r11, 8), %k7

	vgetexpph %zmm2, %zmm22
	vgetexpph %zmm3, %zmm23{%k3}
	vgetexpph %zmm4, %zmm24{%k4}{z}
	vgetexpph {sae}, %zmm5, %zmm25
	vgetexpph {sae}, %zmm6, %zmm26{%k6}
	vgetexpph {sae}, %zmm7, %zmm27{%k7}{z}
	vgetexpph 0x23(%rax), %zmm23
	vgetexpph 0x23(%rax){1to32}, %zmm23
	vgetexpph 0x80(%rax){1to32}, %zmm23
	vgetexpph 0x20(%rax), %zmm23
	vgetexpph 0x40(%rax), %zmm23
	vgetexpph 0x7777(%rax, %rbx, 8), %zmm23
	vgetexpph %ymm2, %ymm22
	vgetexpph %ymm3, %ymm23{%k3}
	vgetexpph %ymm4, %ymm24{%k4}{z}
	vgetexpph 0x23(%rax), %ymm23
	vgetexpph 0x23(%rax){1to16}, %ymm23
	vgetexpph 0x80(%rax){1to16}, %ymm23
	vgetexpph 0x20(%rax), %ymm23
	vgetexpph 0x40(%rax), %ymm23
	vgetexpph 0x7777(%rax, %rbx, 8), %ymm23
	vgetexpph %xmm2, %xmm22
	vgetexpph %xmm3, %xmm23{%k3}
	vgetexpph %xmm4, %xmm24{%k4}{z}
	vgetexpph 0x23(%rax), %xmm23
	vgetexpph 0x23(%rax){1to8}, %xmm23
	vgetexpph 0x80(%rax){1to8}, %xmm23
	vgetexpph 0x20(%rax), %xmm23
	vgetexpph 0x40(%rax), %xmm23
	vgetexpph 0x7777(%rax, %rbx, 8), %xmm23

	vgetexpsh %xmm0, %xmm10, %xmm20
	vgetexpsh %xmm1, %xmm11, %xmm21{%k1}
	vgetexpsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vgetexpsh {sae}, %xmm3, %xmm13, %xmm23
	vgetexpsh {sae}, %xmm4, %xmm14, %xmm24{%k4}
	vgetexpsh {sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vgetexpsh (%rax), %xmm17, %xmm27
	vgetexpsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vgetexpsh 0x20(%rcx), %xmm18, %xmm28
	vgetexpsh 0x40(%rcx), %xmm17, %xmm27
	vgetexpsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vgetmantph $0x42, %zmm10, %zmm20
	vgetmantph $0x42, %zmm11, %zmm21{%k1}
	vgetmantph $0x42, %zmm12, %zmm22{%k1}{z}
	vgetmantph $0x42, {sae}, %zmm13, %zmm23
	vgetmantph $0x42, (%rax), %zmm20
	vgetmantph $0x42, 0x23(%rax), %zmm20
	vgetmantph $0x42, 0x23(%rax){1to32}, %zmm20
	vgetmantph $0x42, 0x80(%rax){1to32}, %zmm20
	vgetmantph $0x42, 0x20(%rax), %zmm20
	vgetmantph $0x42, 0x40(%rax), %zmm20
	vgetmantph $0x42, 0x7777(%rax), %zmm20
	vgetmantph $0x42, %ymm10, %ymm20
	vgetmantph $0x42, %ymm11, %ymm21{%k1}
	vgetmantph $0x42, %ymm12, %ymm22{%k1}{z}
	vgetmantph $0x42, %ymm13, %ymm23
	vgetmantph $0x42, (%rax), %ymm20
	vgetmantph $0x42, 0x23(%rax), %ymm20
	vgetmantph $0x42, 0x23(%rax){1to16}, %ymm20
	vgetmantph $0x42, 0x80(%rax){1to16}, %ymm20
	vgetmantph $0x42, 0x20(%rax), %ymm20
	vgetmantph $0x42, 0x40(%rax), %ymm20
	vgetmantph $0x42, 0x7777(%rax), %ymm20
	vgetmantph $0x42, %xmm10, %xmm20
	vgetmantph $0x42, %xmm11, %xmm21{%k1}
	vgetmantph $0x42, %xmm12, %xmm22{%k1}{z}
	vgetmantph $0x42, %xmm13, %xmm23
	vgetmantph $0x42, (%rax), %xmm20
	vgetmantph $0x42, 0x23(%rax), %xmm20
	vgetmantph $0x42, 0x23(%rax){1to8}, %xmm20
	vgetmantph $0x42, 0x80(%rax){1to8}, %xmm20
	vgetmantph $0x42, 0x20(%rax), %xmm20
	vgetmantph $0x42, 0x40(%rax), %xmm20
	vgetmantph $0x42, 0x7777(%rax), %xmm20

	vgetmantsh $0x42, %xmm0, %xmm10, %xmm20
	vgetmantsh $0x42, %xmm1, %xmm11, %xmm21{%k1}
	vgetmantsh $0x42, %xmm2, %xmm12, %xmm22{%k2}{z}
	vgetmantsh $0x42, {sae}, %xmm3, %xmm13, %xmm23{%k3}
	vgetmantsh $0x42, 0x23(%rax), %xmm10, %xmm20
	vgetmantsh $0x42, 0x23(%rbx), %xmm11, %xmm21
	vgetmantsh $0x42, 0x20(%rcx), %xmm12, %xmm22
	vgetmantsh $0x42, 0x40(%rdx), %xmm13, %xmm23
	vgetmantsh $0x42, 0x7777(%rcx), %xmm14, %xmm24

	vmaxph %zmm0, %zmm10, %zmm20
	vmaxph %zmm1, %zmm11, %zmm21{%k1}
	vmaxph %zmm2, %zmm12, %zmm22{%k2}{z}
	vmaxph {sae}, %zmm3, %zmm13, %zmm23
	vmaxph (%rax), %zmm17, %zmm27
	vmaxph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vmaxph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vmaxph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vmaxph 0x20(%rcx), %zmm18, %zmm28
	vmaxph 0x40(%rcx), %zmm17, %zmm27
	vmaxph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vmaxph %ymm0, %ymm10, %ymm20
	vmaxph %ymm1, %ymm11, %ymm21{%k1}
	vmaxph %ymm2, %ymm12, %ymm22{%k2}{z}
	vmaxph (%rax), %ymm17, %ymm27
	vmaxph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vmaxph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vmaxph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vmaxph 0x20(%rcx), %ymm18, %ymm28
	vmaxph 0x40(%rcx), %ymm17, %ymm27
	vmaxph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vmaxph %xmm0, %xmm10, %xmm20
	vmaxph %xmm1, %xmm11, %xmm21{%k1}
	vmaxph %xmm2, %xmm12, %xmm22{%k2}{z}
	vmaxph (%rax), %xmm17, %xmm27
	vmaxph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vmaxph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vmaxph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vmaxph 0x20(%rcx), %xmm18, %xmm28
	vmaxph 0x40(%rcx), %xmm17, %xmm27
	vmaxph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vmaxsh %xmm0, %xmm10, %xmm20
	vmaxsh %xmm1, %xmm11, %xmm21{%k1}
	vmaxsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vmaxsh {sae}, %xmm3, %xmm13, %xmm23
	vmaxsh {sae}, %xmm4, %xmm14, %xmm24{%k4}
	vmaxsh {sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vmaxsh (%rax), %xmm17, %xmm27
	vmaxsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vmaxsh 0x20(%rcx), %xmm18, %xmm28
	vmaxsh 0x40(%rcx), %xmm17, %xmm27
	vmaxsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vminph %zmm0, %zmm10, %zmm20
	vminph %zmm1, %zmm11, %zmm21{%k1}
	vminph %zmm2, %zmm12, %zmm22{%k2}{z}
	vminph {sae}, %zmm3, %zmm13, %zmm23
	vminph (%rax), %zmm17, %zmm27
	vminph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vminph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vminph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vminph 0x20(%rcx), %zmm18, %zmm28
	vminph 0x40(%rcx), %zmm17, %zmm27
	vminph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vminph %ymm0, %ymm10, %ymm20
	vminph %ymm1, %ymm11, %ymm21{%k1}
	vminph %ymm2, %ymm12, %ymm22{%k2}{z}
	vminph (%rax), %ymm17, %ymm27
	vminph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vminph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vminph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vminph 0x20(%rcx), %ymm18, %ymm28
	vminph 0x40(%rcx), %ymm17, %ymm27
	vminph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vminph %xmm0, %xmm10, %xmm20
	vminph %xmm1, %xmm11, %xmm21{%k1}
	vminph %xmm2, %xmm12, %xmm22{%k2}{z}
	vminph (%rax), %xmm17, %xmm27
	vminph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vminph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vminph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vminph 0x20(%rcx), %xmm18, %xmm28
	vminph 0x40(%rcx), %xmm17, %xmm27
	vminph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vminsh %xmm0, %xmm10, %xmm20
	vminsh %xmm1, %xmm11, %xmm21{%k1}
	vminsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vminsh {sae}, %xmm3, %xmm13, %xmm23
	vminsh {sae}, %xmm4, %xmm14, %xmm24{%k4}
	vminsh {sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vminsh (%rax), %xmm17, %xmm27
	vminsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vminsh 0x20(%rcx), %xmm18, %xmm28
	vminsh 0x40(%rcx), %xmm17, %xmm27
	vminsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vmovsh %xmm10, %xmm11, %xmm22
	vmovsh %xmm11, %xmm12, %xmm23{%k4}
	vmovsh %xmm12, %xmm13, %xmm24{%k5}{z}
	vmovsh (%rax), %xmm30
	vmovsh 0x23(%rax), %xmm30
	vmovsh 0x20(%rbx), %xmm29{%k1}
	vmovsh 0x40(%rcx), %xmm28
	vmovsh 0x7777(%rdx), %xmm27{%k2}{z}
	vmovsh 0x7777(%rcx, %rbx, 8), %xmm26
	vmovsh %xmm23, (%rax)
	vmovsh %xmm22, 0x23(%rax)
	vmovsh %xmm21, 0x20(%rbx)
	vmovsh %xmm20, 0x40(%rcx)
	vmovsh %xmm19, 0x7777(%rdx){%k3}
	vmovsh %xmm19, 0x7777(%r8, %r9, 4){%k3}
	/*
	 * gas only encodes vmovsh with encoding C (opcode 0x10). The .byte
	 * sequence here forces encoding D.
	 */
	vmovsh %xmm31, %xmm30, %xmm29{%k3}
	.byte 0x62
	.byte 0x05
	.byte 0x0e
	.byte 0x03
	.byte 0x11
	.byte 0xef

	vmovw (%rax), %xmm30
	vmovw 0x23(%rax), %xmm30
	vmovw 0x20(%rbx), %xmm29
	vmovw 0x40(%rcx), %xmm28
	vmovw 0x7777(%rdx), %xmm27
	vmovw 0x7777(%rcx, %rbx, 8), %xmm26
	vmovw %r11d, %xmm25
	vmovw %ebx, %xmm24
	vmovw %xmm23, (%rax)
	vmovw %xmm22, 0x23(%rax)
	vmovw %xmm21, 0x20(%rbx)
	vmovw %xmm20, 0x40(%rcx)
	vmovw %xmm19, 0x7777(%rdx)
	vmovw %xmm19, 0x7777(%r8, %r9, 4)
	vmovw %xmm18, %eax
	vmovw %xmm17, %r10d

	vmulph %zmm0, %zmm10, %zmm20
	vmulph %zmm1, %zmm11, %zmm21{%k1}
	vmulph %zmm2, %zmm12, %zmm22{%k2}{z}
	vmulph {rn-sae}, %zmm3, %zmm13, %zmm23
	vmulph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vmulph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vmulph {rz-sae}, %zmm6, %zmm16, %zmm26
	vmulph (%rax), %zmm17, %zmm27
	vmulph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vmulph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vmulph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vmulph 0x20(%rcx), %zmm18, %zmm28
	vmulph 0x40(%rcx), %zmm17, %zmm27
	vmulph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vmulph %ymm0, %ymm10, %ymm20
	vmulph %ymm1, %ymm11, %ymm21{%k1}
	vmulph %ymm2, %ymm12, %ymm22{%k2}{z}
	vmulph (%rax), %ymm17, %ymm27
	vmulph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vmulph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vmulph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vmulph 0x20(%rcx), %ymm18, %ymm28
	vmulph 0x40(%rcx), %ymm17, %ymm27
	vmulph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vmulph %xmm0, %xmm10, %xmm20
	vmulph %xmm1, %xmm11, %xmm21{%k1}
	vmulph %xmm2, %xmm12, %xmm22{%k2}{z}
	vmulph (%rax), %xmm17, %xmm27
	vmulph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vmulph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vmulph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vmulph 0x20(%rcx), %xmm18, %xmm28
	vmulph 0x40(%rcx), %xmm17, %xmm27
	vmulph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vmulsh %xmm0, %xmm10, %xmm20
	vmulsh %xmm1, %xmm11, %xmm21{%k1}
	vmulsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vmulsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vmulsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vmulsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vmulsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vmulsh (%rax), %xmm17, %xmm27
	vmulsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vmulsh 0x20(%rcx), %xmm18, %xmm28
	vmulsh 0x40(%rcx), %xmm17, %xmm27
	vmulsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vrcpph %zmm2, %zmm22
	vrcpph %zmm3, %zmm23{%k3}
	vrcpph %zmm4, %zmm24{%k4}{z}
	vrcpph 0x23(%rax), %zmm23
	vrcpph 0x23(%rax){1to32}, %zmm23
	vrcpph 0x80(%rax){1to32}, %zmm23
	vrcpph 0x20(%rax), %zmm23
	vrcpph 0x40(%rax), %zmm23
	vrcpph 0x7777(%rax, %rbx, 8), %zmm23
	vrcpph %ymm2, %ymm22
	vrcpph %ymm3, %ymm23{%k3}
	vrcpph %ymm4, %ymm24{%k4}{z}
	vrcpph 0x23(%rax), %ymm23
	vrcpph 0x23(%rax){1to16}, %ymm23
	vrcpph 0x80(%rax){1to16}, %ymm23
	vrcpph 0x20(%rax), %ymm23
	vrcpph 0x40(%rax), %ymm23
	vrcpph 0x7777(%rax, %rbx, 8), %ymm23
	vrcpph %xmm2, %xmm22
	vrcpph %xmm3, %xmm23{%k3}
	vrcpph %xmm4, %xmm24{%k4}{z}
	vrcpph 0x23(%rax), %xmm23
	vrcpph 0x23(%rax){1to8}, %xmm23
	vrcpph 0x80(%rax){1to8}, %xmm23
	vrcpph 0x20(%rax), %xmm23
	vrcpph 0x40(%rax), %xmm23
	vrcpph 0x7777(%rax, %rbx, 8), %xmm23

	vrcpsh %xmm0, %xmm10, %xmm20
	vrcpsh %xmm1, %xmm11, %xmm21{%k1}
	vrcpsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vrcpsh (%rax), %xmm17, %xmm27
	vrcpsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vrcpsh 0x20(%rcx), %xmm18, %xmm28
	vrcpsh 0x40(%rcx), %xmm17, %xmm27
	vrcpsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vreduceph $0x42, %zmm10, %zmm20
	vreduceph $0x42, %zmm11, %zmm21{%k1}
	vreduceph $0x42, %zmm12, %zmm22{%k1}{z}
	vreduceph $0x42, {sae}, %zmm13, %zmm23
	vreduceph $0x42, (%rax), %zmm20
	vreduceph $0x42, 0x23(%rax), %zmm20
	vreduceph $0x42, 0x23(%rax){1to32}, %zmm20
	vreduceph $0x42, 0x80(%rax){1to32}, %zmm20
	vreduceph $0x42, 0x20(%rax), %zmm20
	vreduceph $0x42, 0x40(%rax), %zmm20
	vreduceph $0x42, 0x7777(%rax), %zmm20
	vreduceph $0x42, %ymm10, %ymm20
	vreduceph $0x42, %ymm11, %ymm21{%k1}
	vreduceph $0x42, %ymm12, %ymm22{%k1}{z}
	vreduceph $0x42, %ymm13, %ymm23
	vreduceph $0x42, (%rax), %ymm20
	vreduceph $0x42, 0x23(%rax), %ymm20
	vreduceph $0x42, 0x23(%rax){1to16}, %ymm20
	vreduceph $0x42, 0x80(%rax){1to16}, %ymm20
	vreduceph $0x42, 0x20(%rax), %ymm20
	vreduceph $0x42, 0x40(%rax), %ymm20
	vreduceph $0x42, 0x7777(%rax), %ymm20
	vreduceph $0x42, %xmm10, %xmm20
	vreduceph $0x42, %xmm11, %xmm21{%k1}
	vreduceph $0x42, %xmm12, %xmm22{%k1}{z}
	vreduceph $0x42, %xmm13, %xmm23
	vreduceph $0x42, (%rax), %xmm20
	vreduceph $0x42, 0x23(%rax), %xmm20
	vreduceph $0x42, 0x23(%rax){1to8}, %xmm20
	vreduceph $0x42, 0x80(%rax){1to8}, %xmm20
	vreduceph $0x42, 0x20(%rax), %xmm20
	vreduceph $0x42, 0x40(%rax), %xmm20
	vreduceph $0x42, 0x7777(%rax), %xmm20

	vreducesh $0x42, %xmm0, %xmm10, %xmm20
	vreducesh $0x42, %xmm1, %xmm11, %xmm21{%k1}
	vreducesh $0x42, %xmm2, %xmm12, %xmm22{%k2}{z}
	vreducesh $0x42, {sae}, %xmm3, %xmm13, %xmm23{%k3}
	vreducesh $0x42, 0x23(%rax), %xmm10, %xmm20
	vreducesh $0x42, 0x23(%rbx), %xmm11, %xmm21
	vreducesh $0x42, 0x20(%rcx), %xmm12, %xmm22
	vreducesh $0x42, 0x40(%rdx), %xmm13, %xmm23
	vreducesh $0x42, 0x7777(%rcx), %xmm14, %xmm24

	vrndscaleph $0x42, %zmm10, %zmm20
	vrndscaleph $0x42, %zmm11, %zmm21{%k1}
	vrndscaleph $0x42, %zmm12, %zmm22{%k1}{z}
	vrndscaleph $0x42, {sae}, %zmm13, %zmm23
	vrndscaleph $0x42, (%rax), %zmm20
	vrndscaleph $0x42, 0x23(%rax), %zmm20
	vrndscaleph $0x42, 0x23(%rax){1to32}, %zmm20
	vrndscaleph $0x42, 0x80(%rax){1to32}, %zmm20
	vrndscaleph $0x42, 0x20(%rax), %zmm20
	vrndscaleph $0x42, 0x40(%rax), %zmm20
	vrndscaleph $0x42, 0x7777(%rax), %zmm20
	vrndscaleph $0x42, %ymm10, %ymm20
	vrndscaleph $0x42, %ymm11, %ymm21{%k1}
	vrndscaleph $0x42, %ymm12, %ymm22{%k1}{z}
	vrndscaleph $0x42, %ymm13, %ymm23
	vrndscaleph $0x42, (%rax), %ymm20
	vrndscaleph $0x42, 0x23(%rax), %ymm20
	vrndscaleph $0x42, 0x23(%rax){1to16}, %ymm20
	vrndscaleph $0x42, 0x80(%rax){1to16}, %ymm20
	vrndscaleph $0x42, 0x20(%rax), %ymm20
	vrndscaleph $0x42, 0x40(%rax), %ymm20
	vrndscaleph $0x42, 0x7777(%rax), %ymm20
	vrndscaleph $0x42, %xmm10, %xmm20
	vrndscaleph $0x42, %xmm11, %xmm21{%k1}
	vrndscaleph $0x42, %xmm12, %xmm22{%k1}{z}
	vrndscaleph $0x42, %xmm13, %xmm23
	vrndscaleph $0x42, (%rax), %xmm20
	vrndscaleph $0x42, 0x23(%rax), %xmm20
	vrndscaleph $0x42, 0x23(%rax){1to8}, %xmm20
	vrndscaleph $0x42, 0x80(%rax){1to8}, %xmm20
	vrndscaleph $0x42, 0x20(%rax), %xmm20
	vrndscaleph $0x42, 0x40(%rax), %xmm20
	vrndscaleph $0x42, 0x7777(%rax), %xmm20

	vrndscalesh $0x42, %xmm0, %xmm10, %xmm20
	vrndscalesh $0x42, %xmm1, %xmm11, %xmm21{%k1}
	vrndscalesh $0x42, %xmm2, %xmm12, %xmm22{%k2}{z}
	vrndscalesh $0x42, {sae}, %xmm3, %xmm13, %xmm23{%k3}
	vrndscalesh $0x42, 0x23(%rax), %xmm10, %xmm20
	vrndscalesh $0x42, 0x23(%rbx), %xmm11, %xmm21
	vrndscalesh $0x42, 0x20(%rcx), %xmm12, %xmm22
	vrndscalesh $0x42, 0x40(%rdx), %xmm13, %xmm23
	vrndscalesh $0x42, 0x7777(%rcx), %xmm14, %xmm24

	vrsqrtph %zmm2, %zmm22
	vrsqrtph %zmm3, %zmm23{%k3}
	vrsqrtph %zmm4, %zmm24{%k4}{z}
	vrsqrtph 0x23(%rax), %zmm23
	vrsqrtph 0x23(%rax){1to32}, %zmm23
	vrsqrtph 0x80(%rax){1to32}, %zmm23
	vrsqrtph 0x20(%rax), %zmm23
	vrsqrtph 0x40(%rax), %zmm23
	vrsqrtph 0x7777(%rax, %rbx, 8), %zmm23
	vrsqrtph %ymm2, %ymm22
	vrsqrtph %ymm3, %ymm23{%k3}
	vrsqrtph %ymm4, %ymm24{%k4}{z}
	vrsqrtph 0x23(%rax), %ymm23
	vrsqrtph 0x23(%rax){1to16}, %ymm23
	vrsqrtph 0x80(%rax){1to16}, %ymm23
	vrsqrtph 0x20(%rax), %ymm23
	vrsqrtph 0x40(%rax), %ymm23
	vrsqrtph 0x7777(%rax, %rbx, 8), %ymm23
	vrsqrtph %xmm2, %xmm22
	vrsqrtph %xmm3, %xmm23{%k3}
	vrsqrtph %xmm4, %xmm24{%k4}{z}
	vrsqrtph 0x23(%rax), %xmm23
	vrsqrtph 0x23(%rax){1to8}, %xmm23
	vrsqrtph 0x80(%rax){1to8}, %xmm23
	vrsqrtph 0x20(%rax), %xmm23
	vrsqrtph 0x40(%rax), %xmm23
	vrsqrtph 0x7777(%rax, %rbx, 8), %xmm23

	vrsqrtsh %xmm0, %xmm10, %xmm20
	vrsqrtsh %xmm1, %xmm11, %xmm21{%k1}
	vrsqrtsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vrsqrtsh (%rax), %xmm17, %xmm27
	vrsqrtsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vrsqrtsh 0x20(%rcx), %xmm18, %xmm28
	vrsqrtsh 0x40(%rcx), %xmm17, %xmm27
	vrsqrtsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vscalefph %zmm0, %zmm10, %zmm20
	vscalefph %zmm1, %zmm11, %zmm21{%k1}
	vscalefph %zmm2, %zmm12, %zmm22{%k2}{z}
	vscalefph {rn-sae}, %zmm3, %zmm13, %zmm23
	vscalefph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vscalefph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vscalefph {rz-sae}, %zmm6, %zmm16, %zmm26
	vscalefph (%rax), %zmm17, %zmm27
	vscalefph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vscalefph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vscalefph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vscalefph 0x20(%rcx), %zmm18, %zmm28
	vscalefph 0x40(%rcx), %zmm17, %zmm27
	vscalefph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vscalefph %ymm0, %ymm10, %ymm20
	vscalefph %ymm1, %ymm11, %ymm21{%k1}
	vscalefph %ymm2, %ymm12, %ymm22{%k2}{z}
	vscalefph (%rax), %ymm17, %ymm27
	vscalefph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vscalefph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vscalefph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vscalefph 0x20(%rcx), %ymm18, %ymm28
	vscalefph 0x40(%rcx), %ymm17, %ymm27
	vscalefph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vscalefph %xmm0, %xmm10, %xmm20
	vscalefph %xmm1, %xmm11, %xmm21{%k1}
	vscalefph %xmm2, %xmm12, %xmm22{%k2}{z}
	vscalefph (%rax), %xmm17, %xmm27
	vscalefph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vscalefph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vscalefph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vscalefph 0x20(%rcx), %xmm18, %xmm28
	vscalefph 0x40(%rcx), %xmm17, %xmm27
	vscalefph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vscalefsh %xmm0, %xmm10, %xmm20
	vscalefsh %xmm1, %xmm11, %xmm21{%k1}
	vscalefsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vscalefsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vscalefsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vscalefsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vscalefsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vscalefsh (%rax), %xmm17, %xmm27
	vscalefsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vscalefsh 0x20(%rcx), %xmm18, %xmm28
	vscalefsh 0x40(%rcx), %xmm17, %xmm27
	vscalefsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vsqrtph %zmm2, %zmm22
	vsqrtph %zmm3, %zmm23{%k3}
	vsqrtph %zmm4, %zmm24{%k4}{z}
	vsqrtph {rn-sae}, %zmm5, %zmm25
	vsqrtph {rd-sae}, %zmm6, %zmm26{%k6}
	vsqrtph {ru-sae}, %zmm7, %zmm27{%k7}{z}
	vsqrtph {rz-sae}, %zmm8, %zmm28
	vsqrtph 0x23(%rax), %zmm23
	vsqrtph 0x23(%rax){1to32}, %zmm23
	vsqrtph 0x80(%rax){1to32}, %zmm23
	vsqrtph 0x20(%rax), %zmm23
	vsqrtph 0x40(%rax), %zmm23
	vsqrtph 0x7777(%rax, %rbx, 8), %zmm23
	vsqrtph %ymm2, %ymm22
	vsqrtph %ymm3, %ymm23{%k3}
	vsqrtph %ymm4, %ymm24{%k4}{z}
	vsqrtph 0x23(%rax), %ymm23
	vsqrtph 0x23(%rax){1to16}, %ymm23
	vsqrtph 0x80(%rax){1to16}, %ymm23
	vsqrtph 0x20(%rax), %ymm23
	vsqrtph 0x40(%rax), %ymm23
	vsqrtph 0x7777(%rax, %rbx, 8), %ymm23
	vsqrtph %xmm2, %xmm22
	vsqrtph %xmm3, %xmm23{%k3}
	vsqrtph %xmm4, %xmm24{%k4}{z}
	vsqrtph 0x23(%rax), %xmm23
	vsqrtph 0x23(%rax){1to8}, %xmm23
	vsqrtph 0x80(%rax){1to8}, %xmm23
	vsqrtph 0x20(%rax), %xmm23
	vsqrtph 0x40(%rax), %xmm23
	vsqrtph 0x7777(%rax, %rbx, 8), %xmm23

	vsqrtsh %xmm0, %xmm10, %xmm20
	vsqrtsh %xmm1, %xmm11, %xmm21{%k1}
	vsqrtsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vsqrtsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vsqrtsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vsqrtsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vsqrtsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vsqrtsh (%rax), %xmm17, %xmm27
	vsqrtsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vsqrtsh 0x20(%rcx), %xmm18, %xmm28
	vsqrtsh 0x40(%rcx), %xmm17, %xmm27
	vsqrtsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vsubph %zmm0, %zmm10, %zmm20
	vsubph %zmm1, %zmm11, %zmm21{%k1}
	vsubph %zmm2, %zmm12, %zmm22{%k2}{z}
	vsubph {rn-sae}, %zmm3, %zmm13, %zmm23
	vsubph {rd-sae}, %zmm4, %zmm14, %zmm24{%k4}
	vsubph {ru-sae}, %zmm5, %zmm15, %zmm25{%k5}{z}
	vsubph {rz-sae}, %zmm6, %zmm16, %zmm26
	vsubph (%rax), %zmm17, %zmm27
	vsubph 0x23(%rbx), %zmm18, %zmm28{%k7}
	vsubph 0x23(%rbx){1to32}, %zmm19, %zmm29
	vsubph 0x80(%rbx){1to32}, %zmm19, %zmm29
	vsubph 0x20(%rcx), %zmm18, %zmm28
	vsubph 0x40(%rcx), %zmm17, %zmm27
	vsubph 0x7777(%rdx, %rbx, 8), %zmm16, %zmm26
	vsubph %ymm0, %ymm10, %ymm20
	vsubph %ymm1, %ymm11, %ymm21{%k1}
	vsubph %ymm2, %ymm12, %ymm22{%k2}{z}
	vsubph (%rax), %ymm17, %ymm27
	vsubph 0x23(%rbx), %ymm18, %ymm28{%k7}
	vsubph 0x23(%rbx){1to16}, %ymm19, %ymm29
	vsubph 0x80(%rbx){1to16}, %ymm19, %ymm29
	vsubph 0x20(%rcx), %ymm18, %ymm28
	vsubph 0x40(%rcx), %ymm17, %ymm27
	vsubph 0x7777(%rdx, %rbx, 8), %ymm16, %ymm26
	vsubph %xmm0, %xmm10, %xmm20
	vsubph %xmm1, %xmm11, %xmm21{%k1}
	vsubph %xmm2, %xmm12, %xmm22{%k2}{z}
	vsubph (%rax), %xmm17, %xmm27
	vsubph 0x23(%rbx), %xmm18, %xmm28{%k7}
	vsubph 0x23(%rbx){1to8}, %xmm19, %xmm29
	vsubph 0x80(%rbx){1to8}, %xmm19, %xmm29
	vsubph 0x20(%rcx), %xmm18, %xmm28
	vsubph 0x40(%rcx), %xmm17, %xmm27
	vsubph 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vsubsh %xmm0, %xmm10, %xmm20
	vsubsh %xmm1, %xmm11, %xmm21{%k1}
	vsubsh %xmm2, %xmm12, %xmm22{%k2}{z}
	vsubsh {rn-sae}, %xmm3, %xmm13, %xmm23
	vsubsh {rd-sae}, %xmm4, %xmm14, %xmm24{%k4}
	vsubsh {ru-sae}, %xmm5, %xmm15, %xmm25{%k5}{z}
	vsubsh {rz-sae}, %xmm6, %xmm16, %xmm26
	vsubsh (%rax), %xmm17, %xmm27
	vsubsh 0x23(%rbx), %xmm18, %xmm28{%k7}
	vsubsh 0x20(%rcx), %xmm18, %xmm28
	vsubsh 0x40(%rcx), %xmm17, %xmm27
	vsubsh 0x7777(%rdx, %rbx, 8), %xmm16, %xmm26

	vucomish %xmm30, %xmm29
	vucomish {sae}, %xmm29, %xmm28
	vucomish (%rax), %xmm27
	vucomish 0x7777(%rax), %xmm26
	vucomish 0x7777(%rax, %rbx, 2), %xmm26
	vucomish 0x18(%rcx), %xmm25
.size libdis_test, [.-libdis_test]
