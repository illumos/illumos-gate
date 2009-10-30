//
// Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
// Use is subject to license terms.
//
// Copyright (C) 4Front Technologies 1996-2008.
//
// CDDL HEADER START
//
// The contents of this file are subject to the terms of the
// Common Development and Distribution License (the "License").
// You may not use this file except in compliance with the License.
//
// You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
// or http://www.opensolaris.org/os/licensing.
// See the License for the specific language governing permissions
// and limitations under the License.
//
// When distributing Covered Code, include this CDDL HEADER in each
// file and include the License file at usr/src/OPENSOLARIS.LICENSE.
// If applicable, add the following below this CDDL HEADER, with the
// fields enclosed by brackets "[]" replaced with your own identifying
// information: Portions Copyright [yyyy] [name of copyright owner]
//
// CDDL HEADER END

	// Master volume
	.mono VOL_PCM		75
	
	// Monitor volumes
	.stereo	MON_SPDIF1	0
	.stereo	MON_SPDIF2	0
	.stereo	MON_DIGCD	0
	.stereo	MON_AUX2	0
	.stereo	MON_LINE2	0
	.stereo	MON_AC97	0

	// Output levels for various channels
	.stereo	VOL_FRONT	100
	.stereo	VOL_SURR	100
	.stereo	VOL_SIDE	100
	.mono	VOL_CEN		100
	.mono	VOL_LFE		100
	.stereo	VOL_HEADPH	100

	// Recording volume
	.stereo VOL_REC		100

	// Recording source enables
	.bool	REC_SPDIF1	0
	.bool	REC_SPDIF2	0
	.bool	REC_DIGCD	0
	.bool	REC_AC97	1
	.bool	REC_AUX2	0
	.bool	REC_LINE2	0
	.bool	REC_PCM		0

	// Sends
	.send	FX_FRONT_L	0
	.send	FX_FRONT_R	1
	.send	FX_SURR_L	2
	.send	FX_SURR_R	3
	.send	FX_CEN		4
	.send	FX_LFE		5
	.send	FX_SIDE_L	6
	.send	FX_SIDE_R	7
	.send	FX_SPDIF_L	20
	.send	FX_SPDIF_R	21

#ifdef AUDIGY
#include "emu10k2.mac"
#else
#include "emu10k1.mac"
#endif
