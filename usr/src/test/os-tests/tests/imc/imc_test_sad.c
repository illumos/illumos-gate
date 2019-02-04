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
 * This tests various aspects of the source address decoder. We need to test
 * several of the following:
 *
 * o SAD rules with different interleave options
 *    - XOR (SNB->BRD)
 *    - 10t8, 14t12, 32t30 (SKX)
 * o SAD rules with a7mode (IVB->BRD)
 *    - And XOR
 * o Different SAD rules for different regions
 */

/*
 * This tests basics SAD interleaving with a 2 socket system that has a single
 * channel and DIMM. The other aspects are simplified to try and make life
 * easier.
 */

static const imc_t imc_sad_2s_basic = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
 * This is a 4 socket variants of the previous one. Each DIMM now has a much
 * smaller amount of memory in it.
 */
static const imc_t imc_sad_4s_basic = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 4,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
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
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	},
	.imc_sockets[2] = {
		.isock_nodeid = 2,
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
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	},
	.imc_sockets[3] = {
		.isock_nodeid = 3,
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
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This is similar to imc_sad_2s_basic; however, it enables the XOR mode.
 */
static const imc_t imc_sad_2s_xor = {
	.imc_gen = IMC_GEN_IVY,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_imode = IMC_SAD_IMODE_8t6XOR,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
				.isr_imode = IMC_SAD_IMODE_8t6XOR,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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

static const imc_t imc_sad_2s_a7 = {
	.imc_gen = IMC_GEN_IVY,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
 * This is a 4 socket variants of the previous one. Each DIMM now has a much
 * smaller amount of memory in it.
 */
static const imc_t imc_sad_4s_a7 = {
	.imc_gen = IMC_GEN_HASWELL,
	.imc_nsockets = 4,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	},
	.imc_sockets[2] = {
		.isock_nodeid = 2,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	},
	.imc_sockets[3] = {
		.isock_nodeid = 3,
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
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 2, 3, 0, 1, 2, 3 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 4,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x20000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0, 0, 0, 0,
				    0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 1,
					.irle_nwaysbits = 1,
					.irle_limit = 0x20000000,
					.irle_nentries = 8,
					.irle_entries[0] = { 0x0, 0x0 },
				}
			}
		}
	}
};

/*
 * This is similar to imc_sad_2s_basic; however, it enables the XOR mode.
 */
static const imc_t imc_sad_2s_a7_xor = {
	.imc_gen = IMC_GEN_BROADWELL,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
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
				.isr_imode = IMC_SAD_IMODE_8t6XOR,
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
				.isr_imode = IMC_SAD_IMODE_8t6XOR,
				.isr_a7mode = B_TRUE,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = IMC_TAD_FLAG_CHANSHIFT,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
 * This constructs an IMC that has multiple SAD rules that change how we
 * interleave across different regions of memory.
 */
static const imc_t imc_sad_2s_multirule = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 2,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0,
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x20000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x40000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 1, 1, 1, 1, 1, 1, 1, 1 }
			},
			.isad_rules[2] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x60000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[3] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 1, 0, 1, 0, 1, 0, 1, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x20000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x20000000,
				.itr_limit = 0x60000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[2] = {
				.itr_base = 0x60000000,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x40000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x30000000, 0, 0, 0, 0,
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
				.isr_limit = 0x20000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 1, 0, 1, 0, 1, 0, 1 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x40000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 1, 1, 1, 1, 1, 1, 1, 1 }
			},
			.isad_rules[2] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x60000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[3] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 1, 0, 1, 0, 1, 0, 1, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 12,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x20000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x20000000,
				.itr_limit = 0x60000000,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[2] = {
				.itr_base = 0x60000000,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
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

static const imc_t imc_sad_2s_skx_10t8 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 2,
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
				.isr_targets = { 8, 1, 8, 1, 8, 1, 8, 1 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_256B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_10t8,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 8, 0, 8, 0, 8, 0, 8 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 }
			}
		},
		.isock_ntad = 1,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_256B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 1,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0x100, 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0 },
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
 * This performs 2 way interleaving across memory controllers, rather than
 * across sockets.
 */
static const imc_t imc_sad_1s_skx_14t12 = {
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
				.ismc_mcroutes[1] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_4KB,
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
				.itr_limit = 0x80000000,
				.itr_sock_way = 2,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_4KB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
			}
		},
		.isock_imcs[1] = {
			.icn_nchannels = 1,
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
			}
		}
	},
};

static const imc_t imc_sad_4s_8w_skx_32t30 = {
	.imc_gen = IMC_GEN_SKYLAKE,
	.imc_nsockets = 4,
	.imc_sockets[0] = {
		.isock_nodeid = 0,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0x280000000ULL,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 8, 9, 8, 9, 8, 9 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 3, 3, 0, 0, 1, 1, 2, 2 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
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
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
	},
	.imc_sockets[1] = {
		.isock_nodeid = 1,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0x280000000ULL,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 3, 3, 0, 0, 8, 9, 2, 2 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
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
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
	},
	.imc_sockets[2] = {
		.isock_nodeid = 2,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0x280000000ULL,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 3, 3, 0, 0, 1, 1, 8, 9 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
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
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
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
	},
	.imc_sockets[3] = {
		.isock_nodeid = 3,
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,
			.isad_tohm = 0x280000000ULL,
			.isad_nrules = 24,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_32t30,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 8, 9, 0, 0, 1, 1, 2, 2 }
			},
			.isad_mcroute = {
				.ismc_nroutes = 6,
				.ismc_mcroutes[0] = { 0, 0 },
				.ismc_mcroutes[1] = { 1, 0 }
			}
		},
		.isock_ntad = 2,
		.isock_tad[0] = {
			.itad_flags = 0,
			.itad_nrules = 8,
			.itad_rules[0] = {
				.itr_base = 0x0,
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
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
				.itr_limit = 0x80000000,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x100000000ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 8,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_1GB,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		},
		.isock_nimc = 2,
		.isock_imcs[0] = {
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0x200000000ULL, 0, 0,
				    0, 0, 0, 0, 0, 0, 0 },
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
			.icn_nchannels = 1,
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
				.ich_tad_offsets = { 0, 0x240000000ULL, 0, 0,
				    0, 0, 0, 0, 0, 0, 0 },
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
	},
};

const imc_test_case_t imc_test_sad[] = {
/*
 * This first set of tests just makes sure that we properly handle SAD
 * interleaving rules and get routed to the right socket.
 */
{
	.itc_desc = "2 Socket SAD 8-6 Interleave (1)",
	.itc_imc = &imc_sad_2s_basic,
	.itc_pa = 0x0,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0
}, {
	.itc_desc = "2 Socket SAD 8-6 Interleave (2)",
	.itc_imc = &imc_sad_2s_basic,
	.itc_pa = 0x12345678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91a2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91a2b38
}, {
	.itc_desc = "2 Socket SAD 8-6 Interleave (3)",
	.itc_imc = &imc_sad_2s_basic,
	.itc_pa = 0x12345638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91a2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91a2b38
},
/*
 * This is the same as above, but uses a 4-socket configuration instead.
 */
{
	.itc_desc = "4 Socket SAD 8-6 Interleave (1)",
	.itc_imc = &imc_sad_4s_basic,
	.itc_pa = 0x12345638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x48d15b8,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x48d15b8
}, {
	.itc_desc = "4 Socket SAD 8-6 Interleave (2)",
	.itc_imc = &imc_sad_4s_basic,
	.itc_pa = 0x12345678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x48d15b8,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x48d15b8
}, {
	.itc_desc = "4 Socket SAD 8-6 Interleave (3)",
	.itc_imc = &imc_sad_4s_basic,
	.itc_pa = 0x123456b8,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x48d15b8,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x48d15b8
}, {
	.itc_desc = "4 Socket SAD 8-6 Interleave (4)",
	.itc_imc = &imc_sad_4s_basic,
	.itc_pa = 0x123456f8,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x48d15b8,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x48d15b8
},
/*
 * This is a variant on the basic 2s tests. XOR mode is enabled, so we use that
 * to see that we actually have differences versus the basic 2s tests.
 */
{
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (1)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12345638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91a2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91a2b38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (2)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12345678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91a2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91a2b38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (3)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12355638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91aab38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91aab38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (4)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12355678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91aab38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91aab38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (5)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12365638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91b2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91b2b38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (6)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12365678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91b2b38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91b2b38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (7)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12375638,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91bab38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91bab38
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR Interleave (8)",
	.itc_imc = &imc_sad_2s_xor,
	.itc_pa = 0x12375678,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x91bab38,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x91bab38
},
/*
 * Next, we're going to repeat the same initial set of tests that we had, but
 * we're also going to turn on a7 mode. First up is the 2 socket case.
 */
{
	.itc_desc = "2 Socket SAD 8-6 A7 Interleave (1)",
	.itc_imc = &imc_sad_2s_a7,
	.itc_pa = 0x2342000f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x11a1000f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x11a1000f
}, {
	.itc_desc = "2 Socket SAD 8-6 A7 Interleave (2)",
	.itc_imc = &imc_sad_2s_a7,
	.itc_pa = 0x2342004f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x11a1004f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x11a1004f
}, {
	.itc_desc = "2 Socket SAD 8-6 A7 Interleave (3)",
	.itc_imc = &imc_sad_2s_a7,
	.itc_pa = 0x2342020f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x11a1010f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x11a1010f
}, {
	.itc_desc = "2 Socket SAD 8-6 A7 Interleave (4)",
	.itc_imc = &imc_sad_2s_a7,
	.itc_pa = 0x2342024f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x11a1014f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x11a1014f
},
/*
 * Next, we're going to repeat the same initial set of tests that we had, but
 * we're also going to turn on a7 mode. First up is the 4 socket case.
 */
{
	.itc_desc = "4 Socket SAD 8-6 A7 (1)",
	.itc_imc = &imc_sad_4s_a7,
	.itc_pa = 0x2342000f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08d0800f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08d0800f
}, {
	.itc_desc = "4 Socket SAD 8-6 A7 (2)",
	.itc_imc = &imc_sad_4s_a7,
	.itc_pa = 0x2342008f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08d0800f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08d0800f
}, {
	.itc_desc = "4 Socket SAD 8-6 A7 (3)",
	.itc_imc = &imc_sad_4s_a7,
	.itc_pa = 0x2342020f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08d0808f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08d0808f
}, {
	.itc_desc = "4 Socket SAD 8-6 A7 (4)",
	.itc_imc = &imc_sad_4s_a7,
	.itc_pa = 0x2342028f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08d0808f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08d0808f
}, {
	.itc_desc = "4 Socket SAD 8-6 A7 (5)",
	.itc_imc = &imc_sad_4s_a7,
	.itc_pa = 0x23420f8f,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08d0838f,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08d0838f
},
/*
 * 2 Socket 8-6 XOR mode, with a7 set. Here, we'll end up working through all of
 * the XOR permutations to make sure that we're in good shape.
 */
{
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (1)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4200000b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2100000b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2100000b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (2)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4200020b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2100010b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2100010b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (3)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4201000b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2100800b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2100800b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (4)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4201020b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2100810b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2100810b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (5)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4202000b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2101000b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2101000b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (6)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4202020b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2101010b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2101010b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (7)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4203000b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2101800b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2101800b
}, {
	.itc_desc = "2 Socket SAD 8-6 XOR A7 (8)",
	.itc_imc = &imc_sad_2s_a7_xor,
	.itc_pa = 0x4203020b,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2101810b,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2101810b
},
/*
 * This is a multi-rule SAD that alternates how we target socket interleaving
 * depending on which address range we're at.
 */
{
	.itc_desc = "SAD Multi-rule (1)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x0ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x07fb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x07fb0003
}, {
	.itc_desc = "SAD Multi-rule (2)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x0ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x07fb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x07fb0003
}, {
	.itc_desc = "SAD Multi-rule (3)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x1ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0ffb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0ffb0003
}, {
	.itc_desc = "SAD Multi-rule (4)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x1ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0ffb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0ffb0003
}, {
	.itc_desc = "SAD Multi-rule (5)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x2ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1ff60003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1ff60003
},
{
	.itc_desc = "SAD Multi-rule (6)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x2ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1ff60043,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1ff60043
}, {
	.itc_desc = "SAD Multi-rule (7)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x3ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2ff60003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2ff60003
}, {
	.itc_desc = "SAD Multi-rule (8)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x3ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2ff60043,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2ff60043
}, {
	.itc_desc = "SAD Multi-rule (9)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x4ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1ff60003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1ff60003
}, {
	.itc_desc = "SAD Multi-rule (10)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x4ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x1ff60043,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x1ff60043
}, {
	.itc_desc = "SAD Multi-rule (11)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x5ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2ff60003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2ff60003
}, {
	.itc_desc = "SAD Multi-rule (12)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x5ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x2ff60043,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x2ff60043
}, {
	.itc_desc = "SAD Multi-rule (13)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x6ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x37fb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x37fb0003
}, {
	.itc_desc = "SAD Multi-rule (14)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x6ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x37fb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x37fb0003
}, {
	.itc_desc = "SAD Multi-rule (15)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x7ff60003,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3ffb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3ffb0003
}, {
	.itc_desc = "SAD Multi-rule (16)",
	.itc_imc = &imc_sad_2s_multirule,
	.itc_pa = 0x7ff60043,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3ffb0003,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3ffb0003
},
/*
 * Verify that SAD interleaving at 10-8 works.
 */
{
	.itc_desc = "SAD 2s SKX 10-8 (1)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x11220000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910000
}, {
	.itc_desc = "SAD 2s SKX 10-8 (2)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x11220100,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910000
}, {
	.itc_desc = "SAD 2s SKX 10-8 (3)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x112200ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089100ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089100ff
}, {
	.itc_desc = "SAD 2s SKX 10-8 (4)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x112201ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089100ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089100ff
}, {
	.itc_desc = "SAD 2s SKX 10-8 (5)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x7ffffeff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fffffff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fffffff
}, {
	.itc_desc = "SAD 2s SKX 10-8 (6)",
	.itc_imc = &imc_sad_2s_skx_10t8,
	.itc_pa = 0x7fffffff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x3fffffff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x3fffffff
},
/*
 * Again with SKX; however, now with 15-12.
 */
{
	.itc_desc = "SAD 2s SKX 14-12 (1)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x11220000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910000
}, {
	.itc_desc = "SAD 2s SKX 14-12 (2)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x11220100,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910100,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910100
}, {
	.itc_desc = "SAD 2s SKX 14-12 (3)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x112200ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089100ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089100ff
}, {
	.itc_desc = "SAD 2s SKX 14-12 (4)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x112201ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089101ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089101ff
}, {
	.itc_desc = "SAD 2s SKX 14-12 (5)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x11221000,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910000,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910000
}, {
	.itc_desc = "SAD 2s SKX 14-12 (6)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x11221100,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x08910100,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x08910100
}, {
	.itc_desc = "SAD 2s SKX 14-12 (7)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x112210ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089100ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089100ff
}, {
	.itc_desc = "SAD 2s SKX 14-12 (8)",
	.itc_imc = &imc_sad_1s_skx_14t12,
	.itc_pa = 0x112211ff,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x089101ff,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x089101ff
},
/*
 * This set covers using an 8-way socket granularity on Skylake. This means that
 * we have two IMCs per socket as well. We're also using 1 GiB granularity here.
 * So we want to verify that is working as well.
 */
{
	.itc_desc = "SAD 4s 8-way SKX 32-30 (1)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x0badcafe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (2)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x4badcafe,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (3)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x10badcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (4)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x14badcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (5)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x18badcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (6)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x1cbadcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (7)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x20badcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (8)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x24badcafeULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badcafe,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badcafe
},

{
	.itc_desc = "SAD 4s 8-way SKX 32-30 (9)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x0badca77,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (10)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x4badca77,
	.itc_pass = B_TRUE,
	.itc_nodeid = 0,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (11)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x10badca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (12)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x14badca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 1,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (13)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x18badca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (14)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x1cbadca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 2,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (15)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x20badca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 0,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = "SAD 4s 8-way SKX 32-30 (16)",
	.itc_imc = &imc_sad_4s_8w_skx_32t30,
	.itc_pa = 0x24badca77ULL,
	.itc_pass = B_TRUE,
	.itc_nodeid = 3,
	.itc_tadid = 1,
	.itc_channelid = 0,
	.itc_chanaddr = 0x0badca77,
	.itc_dimmid = 0,
	.itc_rankid = 0,
	.itc_rankaddr = 0x0badca77
}, {
	.itc_desc = NULL
} };
