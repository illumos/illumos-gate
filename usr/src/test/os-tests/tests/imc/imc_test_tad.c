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
 * This tests various aspects of the target address decoder.
 *
 * o TAD rules with different channel interleaving
 * o TAD rules with channel shifting (IVB->BRD)
 * o TAD rules with channel hashing (IVB->BRD)
 * o TAD rules with different granularities (SKX)
 * o Channel rules with mod2/3 variants (SKX)
 *
 * We use the most basic of SAD rules and RIR rules when constructing these.
 * Those are more generally exercised elsewhere. Basic socket granularity rules
 * are tested in imc_test_sad.c.
 *
 * There are currently no tests for mirroring or lockstep mode as that's not
 * more generally supported.
 */

static const imc_t imc_tad_1s_2cw = {
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
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This IMC has the a7mode/McChanShiftUp set. This means that instead of using
 * bits 0-6 for an address, it should use bits 0-7.
 */
static const imc_t imc_tad_1s_2cw_shiftup = {
	.imc_gen = IMC_GEN_IVY,
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
				.isr_a7mode = B_TRUE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This IMC has the channel hashing mode set on all of the channels in question.
 * This means that the TAD will hash the upper address bits into the channel
 * determination.
 */
static const imc_t imc_tad_1s_2cw_chanhash = {
	.imc_gen = IMC_GEN_HASWELL,
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
			.itad_flags = IMC_TAD_FLAG_CHANHASH,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This IMC has different TAD rules that cover different ranges, which change
 * how we interleave. The main goal is to make sure that we're always going to
 * the right place. This also requires us to set TAD offsets on a
 * per-channel/TAD rule basis. These are required to correctly make sure that we
 * map things. The following is how the address space should in theory look. We
 * have 2 GiB (0x80000000) of address space. We break that into 4 512 MiB
 * chunks. The first and last are 2-way interleaved. The middle two are 1-way
 * interleaved to a specific channel.
 */
static const imc_t imc_tad_1s_multirule = {
	.imc_gen = IMC_GEN_BROADWELL,
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
				.itr_limit = 0x20000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x20000000,
				.itr_limit = 0x40000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 1, 1, 0, 0 }
			},
			.itad_rules[2] = {
				.itr_base = 0x40000000,
				.itr_limit = 0x60000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[3] = {
				.itr_base = 0x60000000,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 1, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0x30000000, 0, 0,
				    0, 0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x10000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * The purpse of this IMC is to use a combination of both socket and channel
 * interleaving. It employs a system with two sockets, each which have 2 IMCs.
 * Each IMC has two channels. We have a 4-way socket interleave followed by a
 * 2-way channel interleave. We use a simplified memory layout (TOLM = 4 GiB) to
 * simplify other rules.
 */
static const imc_t imc_tad_2s_2cw_4sw = {
	.imc_gen = IMC_GEN_IVY,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0x200000000ULL,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x200000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 4, 1, 5, 0, 4, 1, 5 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x200000000ULL,
				.itr_sock_way = 4,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x200000000ULL,
				.itr_sock_way = 4,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 1, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	},
	.imc_sockets[1] = {
		.isock_nodeid = 1,
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
				.isr_targets = { 0, 4, 1, 5, 0, 4, 1, 5 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x200000000ULL,
				.itr_sock_way = 4,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 1, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x200000000ULL,
				.itr_sock_way = 4,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 1, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This IMC has a single socket with two IMCs and two channels. It uses the
 * default granularities and sizes. This just serves as a basis for the
 * subsequent tests.
 */
static const imc_t imc_skx_64b_gran = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 8, 9, 8, 9, 8, 9 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This tests a different channel granularity. Note the channel and socket
 * granulariites match at this point in time to simplify the test.
 */
static const imc_t imc_skx_256b_gran = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_10t8,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 8, 9, 8, 9, 8, 9 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_256B,
				.itr_chan_gran = IMC_TAD_GRAN_256B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This time, use a 4k granularity.
 */
static const imc_t imc_skx_4k_gran = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_14t12,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 8, 9, 8, 9, 8, 9 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_4KB,
				.itr_chan_gran = IMC_TAD_GRAN_4KB,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * Once more, with 1 GiB granularity.
 */
static const imc_t imc_skx_1g_gran = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 8, 9, 8, 9, 8, 9 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 1,
				.itr_chan_way = 2,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_1GB,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This tests a 1 socket, 4 channel-way configuration.
 */
static const imc_t imc_tad_1s_4cw = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 1, 1 },
				.ismc_mcroutes[3] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 2,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on 1imc_tad_1s_4cw that uses Skylake mod3 rules to change how the
 * target channel is determined. While we have six channels here, technically
 * this configuration has wasted memory. This is on purpose to simplify the
 * rules below.
 */
static const imc_t imc_tad_skx_mod3_45t6 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t6,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD3,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on imc_tad_skx_mod3_45t6, but here we test the 45t8 mod variant.
 */
static const imc_t imc_tad_skx_mod3_45t8 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t8,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD3,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on imc_tad_skx_mod3_45t6, but here we test the 45t12 mod variant.
 */
static const imc_t imc_tad_skx_mod3_45t12 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t12,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD3,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on imc_tad_skx_mod3_45t12, but instead of using mod3, we use the
 * mod2 variant that favors 0/1. This menas we can only output route entries, 0,
 * 1, 2, and 3.
 */
static const imc_t imc_tad_skx_mod2_01_45t12 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t12,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_01,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on imc_tad_skx_mod3_45t12, but instead of using mod3, we use the
 * mod2 variant that favors 1/2. This menas we can only output route entries, 2,
 * 3, 4, and 5.
 */
static const imc_t imc_tad_skx_mod2_12_45t12 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t12,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_12,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * A variant on imc_tad_skx_mod3_45t12, but instead of using mod3, we use the
 * mod2 variant that favors 0/2. This means we can only output route entries, 0,
 * 1, 4, and 5.
 */
static const imc_t imc_tad_skx_mod2_02_45t12 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x100000000ULL,
			.isad_tohm = 0,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x100000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_need_mod3 = B_TRUE,
				.isr_mod_mode = IMC_SAD_MOD_MODE_45t12,
				.isr_mod_type = IMC_SAD_MOD_TYPE_MOD2_02,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0xa, 0xb, 8, 9, 0xa,
				    0xb }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 0, 1 },
				.ismc_mcroutes[2] = { 0, 2 },
				.ismc_mcroutes[3] = { 1, 2 },
				.ismc_mcroutes[4] = { 1, 1 },
				.ismc_mcroutes[5] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_tad[1] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x100000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 4,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 3,
			.icn_dimm_type = IMC_DIMM_DDR4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[1] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			},
			.icn_channels[2] = {
				.ich_ndimms = 1,
				.ich_dimms[0] = {
					.idimm_present = B_TRUE,
					.idimm_nbanks = 3,
					.idimm_width = 8,
					.idimm_density = 2,
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 4,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x40000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

const imc_test_case_t imc_test_tad[] = {
/*
 * These tests come in pairs. The first two verify that we can get the same
 * address on the channel and interleave. The second set verifies that we end up
 * in the same channel when we're within interleaving. The third set shows that
 * we interleave again and will be used as a point of comparison in the next
 * group of tests. The fourth set varies this and makes sure that we can end up
 * on the right channel at different address ranges.
 */
{
	.itc_desc = "1 Socket, 2 Channel way (1)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x33333333,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x199999b3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999b3
}, {
	.itc_desc = "1 Socket, 2 Channel way (2)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x33333373,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x199999b3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999b3
}, {
	.itc_desc = "1 Socket, 2 Channel way (3)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x3333331a,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1999999a,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1999999a
}, {
	.itc_desc = "1 Socket, 2 Channel way (4)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x33333342,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x19999982,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x19999982
}, {
	.itc_desc = "1 Socket, 2 Channel way (5)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x333333b3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x199999f3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999f3
}, {
	.itc_desc = "1 Socket, 2 Channel way (6)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x333333f3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x199999f3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999f3
}, {
	.itc_desc = "1 Socket, 2 Channel way (7)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x22222222,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x11111122,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x11111122
}, {
	.itc_desc = "1 Socket, 2 Channel way (8)",
	.itc_imc = &imc_tad_1s_2cw,
	.itc_pa = 0x77777777,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3bbbbbb7,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3bbbbbb7
},
/*
 * This next set of tests is similar to the previous one, except we have the
 * a7mode / McChanShiftUp enabled, which means that we use 7-bits to index into
 * the channel by default rather than 6. We have tests that compare this
 * behavior that would have varied in the previous case, but does not now. We do
 * this mostly by using the same initial set of addresses (tests 1-6 of the
 * previous set).
 */
{
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (1)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x33333333,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x199999b3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999b3
}, {
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (2)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x33333373,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x199999f3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999f3
}, {
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (3)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x3333331a,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1999999a,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1999999a
}, {
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (4)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x33333342,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x199999c2,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999c2
}, {
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (5)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x333333b3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x199999b3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999b3
}, {
	.itc_desc = "1 Socket, 2 Channel way, Shift Up (6)",
	.itc_imc = &imc_tad_1s_2cw_shiftup,
	.itc_pa = 0x333333f3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x199999f3,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x199999f3
},
/*
 * This next set of tests focuses on channel hashing. This is when we take the
 * upper bits of the system addrses and use that to influence which channel
 * something should be directed to. To see this, we take addresses that have the
 * same base address (using bits 0-11) and see that they channels based on the
 * different upper bits, where as without channel hashing, we shouldn't expect
 * that.
 */
{
	.itc_desc = "1 Socket, 2 Channel way, Hashing (1)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00000bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x000005ed,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x000005ed
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (2)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00001bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x00000ded,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x00000ded
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (3)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00011bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x00008ded,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x00008ded
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (4)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00111bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x00088ded,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x00088ded
}, {
	/* The channel shouldn't change as it's not a bit we index on */
	.itc_desc = "1 Socket, 2 Channel way, Hashing (5)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00311bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x00188ded,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x00188ded
}, {
	/* This one shouldn't change as the 1 is > bit 28 */
	.itc_desc = "1 Socket, 2 Channel way, Hashing (6)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x20111bad,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x10088ded,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x10088ded
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (7)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00000bed,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x000005ed,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x000005ed
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (8)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00100bed,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x000805ed,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x000805ed
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (9)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00300bed,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x001805ed,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x001805ed
}, {
	.itc_desc = "1 Socket, 2 Channel way, Hashing (10)",
	.itc_imc = &imc_tad_1s_2cw_chanhash,
	.itc_pa = 0x00500bed,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x002805ed,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x002805ed
},
/*
 * This range of tests basically checks how we interleave in the multi-rule
 * system that we've put together. We have regions that should be direct mapped
 * an others that should be interleaved.
 */
{
	.itc_desc = "1s Multi-rule (1)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x07654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03b2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03b2a1a1
}, {
	.itc_desc = "1s Multi-rule (2)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x07654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03b2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03b2a1a1
}, {
	.itc_desc = "1s Multi-rule (3)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x17654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0bb2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0bb2a1a1
}, {
	.itc_desc = "1s Multi-rule (4)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x17654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0bb2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0bb2a1a1
}, {
	.itc_desc = "1s Multi-rule (5)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x27654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x17654321,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x17654321
}, {
	.itc_desc = "1s Multi-rule (6)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x27654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x17654361,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x17654361
}, {
	.itc_desc = "1s Multi-rule (7)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x37654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x27654321,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27654321
}, {
	.itc_desc = "1s Multi-rule (8)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x37654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x27654361,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27654361
}, {
	.itc_desc = "1s Multi-rule (9)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x47654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x17654321,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x17654321
}, {
	.itc_desc = "1s Multi-rule (10)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x47654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x17654361,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x17654361
}, {
	.itc_desc = "1s Multi-rule (11)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x57654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x27654321,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27654321
}, {
	.itc_desc = "1s Multi-rule (12)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x57654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x27654361,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27654361
}, {
	.itc_desc = "1s Multi-rule (13)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x67654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x33b2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x33b2a1a1
}, {
	.itc_desc = "1s Multi-rule (14)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x67654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x33b2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x33b2a1a1
}, {
	.itc_desc = "1s Multi-rule (15)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x77654321,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3bb2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3bb2a1a1
}, {
	.itc_desc = "1s Multi-rule (16)",
	.itc_imc = &imc_tad_1s_multirule,
	.itc_pa = 0x77654361,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3bb2a1a1,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3bb2a1a1
},
/*
 * This set of tests looks at using a combination of channel interleaving and
 * socket interleaving and makes sure that we handle that correctly when across
 * multiple IMCs and sockets. We have four tests per dimm. Two that show that we
 * are consistent within the cache line. Two that show that we are consistent
 * when we go to a different line.
 */
{
	.itc_desc = "2 socket, 4-sock way, 2-channel way (1)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60007,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (2)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (3)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150007ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (4)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150023ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (5)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60047,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (6)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60063,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (7)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150047ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (8)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150063ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (9)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60087,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (10)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff600a3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (11)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150087ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (12)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1500a3ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (13)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff600c7,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (14)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff600f3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec033,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec033
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (15)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1500c7ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (16)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1500f3ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a033,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a033
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (17)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60107,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (18)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (19)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150107ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (20)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150123ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (21)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60147,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (22)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60163,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (23)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150147ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (24)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150163ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (25)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff60187,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (26)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff601a3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fec023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (27)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff150187ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (28)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1501a3ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fe2a023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a023
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (29)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff601c7,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (30)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff601f3,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fec033,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fec033
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (31)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1501c7ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a007,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a007
}, {
	.itc_desc = "2 socket, 4-sock way, 2-channel way (32)",
	.itc_imc = &imc_tad_2s_2cw_4sw,
	.itc_pa = 0x1ff1501f3ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3fe2a033,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fe2a033
},
/*
 * This begins a series of tests related to Skylake channel granularities.
 */
{
	.itc_desc = "SKX 2ch 64b chan gran (1)",
	.itc_imc = &imc_skx_64b_gran,
	.itc_pa = 0x0c120000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090000
}, {
	.itc_desc = "SKX 2ch 64b chan gran (2)",
	.itc_imc = &imc_skx_64b_gran,
	.itc_pa = 0x0c120040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090000
}, {
	.itc_desc = "SKX 2ch 64b chan gran (3)",
	.itc_imc = &imc_skx_64b_gran,
	.itc_pa = 0x0c120023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090023
}, {
	.itc_desc = "SKX 2ch 64b chan gran (4)",
	.itc_imc = &imc_skx_64b_gran,
	.itc_pa = 0x0c120068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090028,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090028
},
/*
 * Move onto a 256 byte granularity and repeat.
 */
{
	.itc_desc = "SKX 2ch 256b chan gran (1)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090000
}, {
	.itc_desc = "SKX 2ch 256b chan gran (2)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090040
}, {
	.itc_desc = "SKX 2ch 256b chan gran (3)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090023
}, {
	.itc_desc = "SKX 2ch 256b chan gran (4)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090068
}, {
	.itc_desc = "SKX 2ch 256b chan gran (5)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090100,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090100
}, {
	.itc_desc = "SKX 2ch 256b chan gran (6)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090040
}, {
	.itc_desc = "SKX 2ch 256b chan gran (7)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090023
}, {
	.itc_desc = "SKX 2ch 256b chan gran (8)",
	.itc_imc = &imc_skx_256b_gran,
	.itc_pa = 0x0c120368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090168,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090168
},
/*
 * Now, use 4k granularities.
 */
{
	.itc_desc = "SKX 2ch 4k chan gran (1)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090000
}, {
	.itc_desc = "SKX 2ch 4k chan gran (2)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090040
}, {
	.itc_desc = "SKX 2ch 4k chan gran (3)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090023
}, {
	.itc_desc = "SKX 2ch 4k chan gran (4)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090068
}, {
	.itc_desc = "SKX 2ch 4k chan gran (5)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090300
}, {
	.itc_desc = "SKX 2ch 4k chan gran (6)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090140
}, {
	.itc_desc = "SKX 2ch 4k chan gran (7)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090123
}, {
	.itc_desc = "SKX 2ch 4k chan gran (8)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c120368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x06090368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090368
}, {
	.itc_desc = "SKX 2ch 4k chan gran (9)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090000
}, {
	.itc_desc = "SKX 2ch 4k chan gran (10)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c123040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06091040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06091040
}, {
	.itc_desc = "SKX 2ch 4k chan gran (11)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090023
}, {
	.itc_desc = "SKX 2ch 4k chan gran (12)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090068
}, {
	.itc_desc = "SKX 2ch 4k chan gran (13)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090300
}, {
	.itc_desc = "SKX 2ch 4k chan gran (14)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090140
}, {
	.itc_desc = "SKX 2ch 4k chan gran (15)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c123123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06091123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06091123
}, {
	.itc_desc = "SKX 2ch 4k chan gran (16)",
	.itc_imc = &imc_skx_4k_gran,
	.itc_pa = 0x0c121368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x06090368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x06090368
},
/*
 * Use a 1 GiB Interleaving next.
 */
{
	.itc_desc = "SKX 2ch 1g chan gran (1)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120000
}, {
	.itc_desc = "SKX 2ch 1g chan gran (2)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120040
}, {
	.itc_desc = "SKX 2ch 1g chan gran (3)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120023
}, {
	.itc_desc = "SKX 2ch 1g chan gran (4)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120068
}, {
	.itc_desc = "SKX 2ch 1g chan gran (5)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120300
}, {
	.itc_desc = "SKX 2ch 1g chan gran (6)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120140
}, {
	.itc_desc = "SKX 2ch 1g chan gran (7)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120123
}, {
	.itc_desc = "SKX 2ch 1g chan gran (8)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c120368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c120368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120368
}, {
	.itc_desc = "SKX 2ch 1g chan gran (9)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121000
}, {
	.itc_desc = "SKX 2ch 1g chan gran (10)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c123040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c123040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c123040
}, {
	.itc_desc = "SKX 2ch 1g chan gran (11)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121023
}, {
	.itc_desc = "SKX 2ch 1g chan gran (12)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121068
}, {
	.itc_desc = "SKX 2ch 1g chan gran (13)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121300
}, {
	.itc_desc = "SKX 2ch 1g chan gran (14)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121140
}, {
	.itc_desc = "SKX 2ch 1g chan gran (15)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c123123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c123123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c123123
}, {
	.itc_desc = "SKX 2ch 1g chan gran (16)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x0c121368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0c121368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c121368
}, {
	.itc_desc = "SKX 2ch 1g chan gran (1)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x4c120000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0c120000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120000
}, {
	.itc_desc = "SKX 2ch 1g chan gran (2)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x4c120040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0c120040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120040
}, {
	.itc_desc = "SKX 2ch 1g chan gran (3)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x5c120023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x1c120023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1c120023
}, {
	.itc_desc = "SKX 2ch 1g chan gran (4)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x6c120068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x2c120068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2c120068
}, {
	.itc_desc = "SKX 2ch 1g chan gran (5)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x7c120300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3c120300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3c120300
}, {
	.itc_desc = "SKX 2ch 1g chan gran (6)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x4c120140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0c120140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c120140
}, {
	.itc_desc = "SKX 2ch 1g chan gran (7)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x5c120123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x1c120123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1c120123
}, {
	.itc_desc = "SKX 2ch 1g chan gran (8)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x6c120368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x2c120368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2c120368
}, {
	.itc_desc = "SKX 2ch 1g chan gran (9)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x7c121000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3c121000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3c121000
}, {
	.itc_desc = "SKX 2ch 1g chan gran (10)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x4c123040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0c123040,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0c123040
}, {
	.itc_desc = "SKX 2ch 1g chan gran (11)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x5c121023,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x1c121023,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1c121023
}, {
	.itc_desc = "SKX 2ch 1g chan gran (12)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x6c121068,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x2c121068,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2c121068
}, {
	.itc_desc = "SKX 2ch 1g chan gran (13)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x7c121300,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3c121300,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3c121300
}, {
	.itc_desc = "SKX 2ch 1g chan gran (14)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x7c121140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3c121140,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3c121140
}, {
	.itc_desc = "SKX 2ch 1g chan gran (15)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x6c123123,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x2c123123,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2c123123
}, {
	.itc_desc = "SKX 2ch 1g chan gran (16)",
	.itc_imc = &imc_skx_1g_gran,
	.itc_pa = 0x5c121368,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x1c121368,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1c121368
},
/*
 * This round of tests puts together a 1 socekt configuration with 4 channel way
 * interleaving. This means that we're interleaving across two IMCs in the same
 * socket.
 */
{
	.itc_desc = "1 socket, 4-channel way (1)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13006,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (2)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13046,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (3)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13086,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (4)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff130c6,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (5)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13026,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c26,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c26
}, {
	.itc_desc = "1 socket, 4-channel way (6)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13077,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fc4c37,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c37
}, {
	.itc_desc = "1 socket, 4-channel way (7)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff13099,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x03fc4c19,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c19
}, {
	.itc_desc = "1 socket, 4-channel way (8)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x0ff130ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c3f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c3f
}, {
	.itc_desc = "1 socket, 4-channel way (9)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x8ff13006,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x23fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x23fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (10)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x3ff13046,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0ffc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0ffc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (11)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x4ff13086,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x13fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x13fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (12)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x9ff130c6,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x27fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27fc4c06
}, {
	.itc_desc = "1 socket, 4-channel way (13)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0xdff13026,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x37fc4c26,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x37fc4c26
}, {
	.itc_desc = "1 socket, 4-channel way (14)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0xeff13077,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x3bfc4c37,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3bfc4c37
}, {
	.itc_desc = "1 socket, 4-channel way (15)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x4ff13099,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x13fc4c19,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x13fc4c19
}, {
	.itc_desc = "1 socket, 4-channel way (16)",
	.itc_imc = &imc_tad_1s_4cw,
	.itc_pa = 0x8ff130ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x23fc4c3f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x23fc4c3f
},
/*
 * Test the first variation of mod3 rules. We basically try to find addresses
 * that map to all 6 channels and then do different variations thereof. We
 * mostly use the addresses from the previous test run to get a good random
 * smattering of addresses.
 */
{
	.itc_desc = "1s mod 3 45t6 (1)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13006,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (2)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13046,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (3)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13086,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (4)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff130c6,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x03fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (5)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13026,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x03fc4c26,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c26
}, {
	.itc_desc = "1s mod 3 45t6 (6)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13077,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c37,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c37
}, {
	.itc_desc = "1s mod 3 45t6 (7)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff13099,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x03fc4c19,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c19
}, {
	.itc_desc = "1s mod 3 45t6 (8)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x0ff130ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x03fc4c3f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x03fc4c3f
}, {
	.itc_desc = "1s mod 3 45t6 (9)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x8ff13006,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x23fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x23fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (10)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x3ff13046,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0ffc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0ffc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (11)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x4ff13086,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x13fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x13fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (12)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x9ff130c6,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x27fc4c06,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x27fc4c06
}, {
	.itc_desc = "1s mod 3 45t6 (13)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0xdff13026,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x37fc4c26,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x37fc4c26
}, {
	.itc_desc = "1s mod 3 45t6 (14)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0xeff13077,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x3bfc4c37,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3bfc4c37
}, {
	.itc_desc = "1s mod 3 45t6 (15)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x4ff13099,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x13fc4c19,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x13fc4c19
}, {
	.itc_desc = "1s mod 3 45t6 (16)",
	.itc_imc = &imc_tad_skx_mod3_45t6,
	.itc_pa = 0x8ff130ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x23fc4c3f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x23fc4c3f
},
/*
 * Now use PA bits 45:8 to determine the basic mod3 rule. We make sure that we
 * can construct addresses that hit every routing table entry.
 */
{
	.itc_desc = "1s mod 3 45t8 (1)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod 3 45t8 (2)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod 3 45t8 (3)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000100,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x40,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x40
}, {
	.itc_desc = "1s mod 3 45t8 (4)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000140,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x40,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x40
}, {
	.itc_desc = "1s mod 3 45t8 (5)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000280,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x80,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x80
}, {
	.itc_desc = "1s mod 3 45t8 (6)",
	.itc_imc = &imc_tad_skx_mod3_45t8,
	.itc_pa = 0x00000240,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x80,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x80
},
/*
 * Hit every valid routing table entry with a 45:12 rule.
 */
{
	.itc_desc = "1s mod 3 45t12 (1)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00000000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod 3 45t12 (2)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00000040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod 3 45t12 (3)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00001000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod 3 45t12 (4)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00001040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod 3 45t12 (5)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00002080,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = "1s mod 3 45t12 (6)",
	.itc_imc = &imc_tad_skx_mod3_45t12,
	.itc_pa = 0x00002040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
},
/*
 * Test to make sure we can trigger all variants of mod2 favoring 0/1.
 */
{
	.itc_desc = "1s mod2_01 45t12 (1)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00000000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_01 45t12 (2)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00000040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_01 45t12 (3)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00001000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_01 45t12 (4)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00001040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_01 45t12 (5)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00002080,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = "1s mod2_01 45t12 (6)",
	.itc_imc = &imc_tad_skx_mod2_01_45t12,
	.itc_pa = 0x00002040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
},
/*
 * Test to make sure we can trigger all variants of mod2 favoring 1/2.
 */
{
	.itc_desc = "1s mod2_12 45t12 (1)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00000000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_12 45t12 (2)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00000040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_12 45t12 (3)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00001000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_12 45t12 (4)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00001040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_12 45t12 (5)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00002080,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 2,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = "1s mod2_12 45t12 (6)",
	.itc_imc = &imc_tad_skx_mod2_12_45t12,
	.itc_pa = 0x00002040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 2,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
},
/*
 * Test to make sure we can trigger all variants of mod2 favoring 0/2.
 */
{
	.itc_desc = "1s mod2_02 45t12 (1)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00000000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_02 45t12 (2)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00000040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "1s mod2_02 45t12 (3)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00001000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 1,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_02 45t12 (4)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00001040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x400,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x400
}, {
	.itc_desc = "1s mod2_02 45t12 (5)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00002080,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = "1s mod2_02 45t12 (6)",
	.itc_imc = &imc_tad_skx_mod2_02_45t12,
	.itc_pa = 0x00002040,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 1,
	.itc_chanaddr = 0x800,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x800
}, {
	.itc_desc = NULL
} };
