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
 * Copyright 2019 Joyent, Inc.
 */

#include "imc_test.h"

/*
 * Test various aspects of RIR decoding and rank interleaving.
 *
 * The first test series uses imc_rir_8w_4r_closed which basically tests our
 * rank interleaving across a single DIMM/channel in a closed page
 * configuration.  Technically such a configuration has aliasing, so it
 * shouldn't be used in the wild. This is to validate that we're doing
 * interleaving with a single rule across closed pages.
 *
 * The second test set, imc_rir_4w_4r_open is similar; however, it uses open
 * pages instead.
 *
 * The third test set, imc_rir_8w_4r_2dpc, is used to make sure that we can
 * properly perform interleaving across two DIMMs in a single channel
 * configuration.
 *
 * The fourth test set, imc_rir_2w_1r_3dpc, is used to make sure that we can use
 * multiple rank interleaving rules to point us to different parts of a DIMM on
 * a single channel.
 */

static const imc_t imc_rir_8w_4r_closed = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_TRUE,
			.icn_channels[0] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 4,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 8,
					.irle_nwaysbits = 3,
					.irle_limit = 0x80000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x3, 0x0 },
					.irle_entries[1] = { 0x2, 0x0 },
					.irle_entries[2] = { 0x1, 0x0 },
					.irle_entries[3] = { 0x0, 0x0 },
					.irle_entries[4] = { 0x2, 0x0 },
					.irle_entries[5] = { 0x3, 0x0 },
					.irle_entries[6] = { 0x0, 0x0 },
					.irle_entries[7] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_rir_4w_4r_open = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_FALSE,
			.icn_channels[0] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 8,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 4,
					.irle_nwaysbits = 2,
					.irle_limit = 0x80000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x2, 0x0 },
					.irle_entries[1] = { 0x0, 0x0 },
					.irle_entries[2] = { 0x3, 0x0 },
					.irle_entries[3] = { 0x1, 0x0 },
				}
			}
		}
	}
};

static const imc_t imc_rir_8w_4r_2dpc = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_TRUE,
			.icn_channels[0] = {
				.ich_ndimms = 2,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 4,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_dimms[1] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 4,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 8,
					.irle_nwaysbits = 3,
					.irle_limit = 0x100000000ULL,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x4, 0x0 },
					.irle_entries[2] = { 0x1, 0x0 },
					.irle_entries[3] = { 0x5, 0x0 },
					.irle_entries[4] = { 0x2, 0x0 },
					.irle_entries[5] = { 0x6, 0x0 },
					.irle_entries[6] = { 0x3, 0x0 },
					.irle_entries[7] = { 0x7, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_rir_2w_1r_3dpc = {
	.imc_gen = IMC_GEN_HASWELL,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x180000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x180000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x180000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
			.icn_dimm_type = IMC_DIMM_DDR3,
			.icn_ecc = B_TRUE,
			.icn_lockstep = B_FALSE,
			.icn_closed = B_TRUE,
			.icn_channels[0] = {
				.ich_ndimms = 3,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 1,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_dimms[1] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 1,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_dimms[2] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 1,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x80000000,
					.irle_nentries = 2,
					.irle_entries[0] = { 0x4, 0x0 },
					.irle_entries[1] = { 0x0, 0x0 },
				},
				.ich_rankileaves[1] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x100000000ULL,
					.irle_nentries = 2,
					.irle_entries[0] = { 0x8, 0x40000000 },
					.irle_entries[1] = { 0x4, 0x0 },
				},
				.ich_rankileaves[2] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x180000000ULL,
					.irle_nentries = 2,
					.irle_entries[0] = { 0x8, 0x40000000 },
					.irle_entries[1] = { 0x0, 0x40000000 },
				}
			}
		}
	}
};


const imc_test_case_t imc_test_rir[] = { {
	.itc_desc = "RIR target 0, 8-way/4-rank, closed (1)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 1, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x40,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x40,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 2, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x80,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x80,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 3, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0xc0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xc0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 4, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x100,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x100,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 5, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x140,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0
}, {
	.itc_desc = "RIR target 6, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x180,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x180,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0
},  {
	.itc_desc = "RIR target 7, 8-way/4-rank, closed",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x1c0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1c0,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0
}, {
	.itc_desc = "8-way/4-rank misc, closed (1)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x4000012f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x4000012f,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x800002f
}, {
	.itc_desc = "8-way/4-rank misc, closed (2)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x76543210,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x76543210,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0xeca8650
}, {
	.itc_desc = "8-way/4-rank misc, closed (3)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x12345678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x12345678,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x2468af8
}, {
	.itc_desc = "8-way/4-rank misc, closed (4)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x232023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x232023,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (5)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x232063,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x232063,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (6)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x2320a3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2320a3,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (7)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x2320e3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2320e3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (8)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x232123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x232123,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (9)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x232163,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x232163,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (10)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x2321a3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2321a3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "8-way/4-rank misc, closed (11)",
	.itc_imc =  &imc_rir_8w_4r_closed,
	.itc_pa = 0x2321e3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2321e3,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0x46423,
}, {
	.itc_desc = "4-way/4-rank, open (1)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x0,
}, {
	.itc_desc = "4-way/4-rank, open (2)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x2000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "4-way/4-rank, open (3)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x4000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x4000,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "4-way/4-rank, open (4)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x6000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x6000,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "4-way/4-rank, open (5)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x1234567,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1234567,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0x48c567
}, {
	.itc_desc = "4-way/4-rank, open (6)",
	.itc_imc =  &imc_rir_4w_4r_open,
	.itc_pa = 0x76543210,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x76543210,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1d951210
}, {
	.itc_desc = "2DPC (1)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabcfe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabcfe,
	.itc_dimmid = 1,
	.itc_rankid = 1,
	.itc_rankaddr = 0x1d9b57be
}, {
	.itc_desc = "2DPC (2)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabd3e,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabd3e,
	.itc_dimmid = 0,
	.itc_rankid = 2,
	.itc_rankaddr = 0x1d9b57be,
}, {
	.itc_desc = "2DPC (3)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabd7e,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabd7e,
	.itc_dimmid = 1,
	.itc_rankid = 2,
	.itc_rankaddr = 0x1d9b57be
}, {
	.itc_desc = "2DPC (4)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabdbe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabdbe,
	.itc_dimmid = 0,
	.itc_rankid = 3,
	.itc_rankaddr = 0x1d9b57be
}, {
	.itc_desc = "2DPC (5)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabdfe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabdfe,
	.itc_dimmid = 1,
	.itc_rankid = 3,
	.itc_rankaddr = 0x1d9b57be
}, {
	.itc_desc = "2DPC (6)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabe3e,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabe3e,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1d9b57fe
}, {
	.itc_desc = "2DPC (7)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabe7e,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabe7e,
	.itc_dimmid = 1,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1d9b57fe
}, {
	.itc_desc = "2DPC (8)",
	.itc_imc =  &imc_rir_8w_4r_2dpc,
	.itc_pa = 0xecdabebe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xecdabebe,
	.itc_dimmid = 0,
	.itc_rankid = 1,
	.itc_rankaddr = 0x1d9b57fe
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (1)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0x0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 1,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (2)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0x80000000ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x80000000ULL,
	.itc_dimmid = 2,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (3)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0x100000000ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x100000000ULL,
	.itc_dimmid = 2,
	.itc_rankid = 0,
	.itc_rankaddr = 0x40000000
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (4)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0x654321f5,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x654321f5,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x32a190f5
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (5)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0xdaddadf5,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0xdaddadf5,
	.itc_dimmid = 1,
	.itc_rankid = 0,
	.itc_rankaddr = 0x6d6ed6f5
}, {
	.itc_desc = "Multi-RIR 1R 3DPC (6)",
	.itc_imc =  &imc_rir_2w_1r_3dpc,
	.itc_pa = 0x170ff6099ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x170ff6099ULL,
	.itc_dimmid = 2,
	.itc_rankid = 0,
	.itc_rankaddr = 0x787fb059
}, {
	.itc_desc = NULL
} };
