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
 * This file tests several different miscellaneous failure modes by using
 * incomplete imc_t and imc_t with bad data.
 */

/*
 * This IMC is a nominally valid IMC; however, it has flags indicate that the
 * socket has bad data.
 */
static const imc_t imc_badsock = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_BAD_NODEID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_invalid_sad = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = 0,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_BAD_DRAM_ATTR,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_invalid_sad_rule = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = 0,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x34,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x42,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_invalid_sad_interleave = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = 0,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = 0
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = 0
			}
		}
	}
};

static const imc_t imc_invalid_sad_target = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = 0,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 9, 9, 9, 9, 9, 9, 9, 9 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_bad_tad_rule = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
				.itr_limit = 0x2,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x277777777ULL,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_bad_tad_3way = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
				.itr_chan_way = 3,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 3,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_bad_tad_target = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
				.itr_ntargets = 0,
				.itr_targets = { 0, 0, 0, 0 }
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 0,
				.itr_targets = { 0, 0, 0, 0 }
			}
		}
	}
};

static const imc_t imc_bad_tad_channelid = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
				.itr_targets = { 17, 23, 42, 167 }
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
				.itr_sock_way = 1,
				.itr_chan_way = 1,
				.itr_sock_gran = IMC_TAD_GRAN_64B,
				.itr_chan_gran = IMC_TAD_GRAN_64B,
				.itr_ntargets = 4,
				.itr_targets = { 17, 23, 42, 167 }
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
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_bad_channel_offset = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 0,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_bad_rir_rule = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x1,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_bad_rir_ileave = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 0
				}
			}
		}
	}
};

static const imc_t imc_bad_dimm_index = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x23, 0x0 },
					.irle_entries[1] = { 0x42, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_missing_dimm = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_present = B_FALSE
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_bad_rank_index = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x2, 0x0 },
					.irle_entries[1] = { 0x3, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_chanoff_underflow = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL,
					0x1000000000ULL
				},
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0, 0x0 },
					.irle_entries[1] = { 0x1, 0x0 }
				}
			}
		}
	}
};

static const imc_t imc_riroff_underflow = {
	.imc_gen = IMC_GEN_SANDY,
	.imc_nsockets = 1,
	.imc_sockets[0] = {
		.isock_valid = IMC_SOCKET_V_VALID,
		.isock_sad = {
			.isad_flags = 0,
			.isad_valid = IMC_SAD_V_VALID,
			.isad_tolm = 0x80000000,	/* 2 GiB */
			.isad_tohm = 0x280000000ULL,	/* 10 GiB */
			.isad_nrules = 10,
			.isad_rules[0] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x80000000,
				.isr_imode = IMC_SAD_IMODE_8t6,
				.isr_ntargets = IMC_MAX_SAD_INTERLEAVE,
				.isr_targets = { 0, 0, 0, 0, 0, 0, 0, 0 }
			},
			.isad_rules[1] = {
				.isr_enable = B_TRUE,
				.isr_limit = 0x280000000ULL,
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
			},
			.itad_rules[1] = {
				.itr_base = 0x80000000,
				.itr_limit = 0x280000000ULL,
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
					.idimm_nranks = 2,
					.idimm_nrows = 14,
					.idimm_ncolumns = 10,
					.idimm_size = 0x80000000
				},
				.ich_ntad_offsets = 12,
				.ich_tad_offsets = { 0, 0x80000000, 0, 0, 0, 0,
				    0, 0, 0, 0, 0 },
				.ich_nrankileaves = 8,
				.ich_rankileaves[0] = {
					.irle_enabled = B_TRUE,
					.irle_nways = 2,
					.irle_nwaysbits = 1,
					.irle_limit = 0x200000000ULL,
					.irle_nentries = 5,
					.irle_entries[0] = { 0x0,
					    0x100000000000ULL },
					.irle_entries[1] = { 0x1,
					    0x100000000000ULL }
				}
			}
		}
	}
};

const imc_test_case_t imc_test_fail[] = { {
	.itc_desc = "Bad Socket data (1)",
	.itc_imc = &imc_badsock,
	.itc_pa = 0x34,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SOCKET
}, {
	.itc_desc = "Bad Socket data (2)",
	.itc_imc = &imc_badsock,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SOCKET
}, {
	.itc_desc = "Bad Socket data (3)",
	.itc_imc = &imc_badsock,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SOCKET
}, {
	.itc_desc = "Bad SAD data (1)",
	.itc_imc = &imc_invalid_sad,
	.itc_pa = 0x34,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD
}, {
	.itc_desc = "Bad SAD data (2)",
	.itc_imc = &imc_invalid_sad,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD
}, {
	.itc_desc = "Bad SAD data (3)",
	.itc_imc = &imc_invalid_sad,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD
}, {
	.itc_desc = "Bad SAD rule (1)",
	.itc_imc = &imc_invalid_sad_rule,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_SAD_RULE
}, {
	.itc_desc = "Bad SAD rule (2)",
	.itc_imc = &imc_invalid_sad_rule,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_SAD_RULE
}, {
	.itc_desc = "Bad SAD rule (3)",
	.itc_imc = &imc_invalid_sad_rule,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_SAD_RULE
}, {
	.itc_desc = "Bad SAD interleave (1)",
	.itc_imc = &imc_invalid_sad_interleave,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE
}, {
	.itc_desc = "Bad SAD interleave (2)",
	.itc_imc = &imc_invalid_sad_interleave,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE
}, {
	.itc_desc = "Bad SAD interleave (3)",
	.itc_imc = &imc_invalid_sad_interleave,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_SAD_INTERLEAVE
}, {
	.itc_desc = "Bad SAD TAD target (1)",
	.itc_imc = &imc_invalid_sad_target,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_BAD_SOCKET
}, {
	.itc_desc = "Bad SAD TAD target (2)",
	.itc_imc = &imc_invalid_sad_target,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_BAD_SOCKET
}, {
	.itc_desc = "Bad SAD TAD target (3)",
	.itc_imc = &imc_invalid_sad_target,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_SAD_BAD_TAD
}, {
	.itc_desc = "Bad TAD rule (1)",
	.itc_imc = &imc_bad_tad_rule,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_TAD_RULE
}, {
	.itc_desc = "Bad TAD rule (2)",
	.itc_imc = &imc_bad_tad_rule,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_TAD_RULE
}, {
	.itc_desc = "Bad TAD rule (3)",
	.itc_imc = &imc_bad_tad_rule,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_TAD_RULE
}, {
	.itc_desc = "Unsupported 3 way interleave (1)",
	.itc_imc = &imc_bad_tad_3way,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_3_ILEAVE
}, {
	.itc_desc = "Unsupported 3 way interleave (2)",
	.itc_imc = &imc_bad_tad_3way,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_3_ILEAVE
}, {
	.itc_desc = "Unsupported 3 way interleave (3)",
	.itc_imc = &imc_bad_tad_3way,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_3_ILEAVE
}, {
	.itc_desc = "Bad TAD target index (1)",
	.itc_imc = &imc_bad_tad_target,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_BAD_TARGET_INDEX
}, {
	.itc_desc = "Bad TAD target index (2)",
	.itc_imc = &imc_bad_tad_target,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_BAD_TARGET_INDEX
}, {
	.itc_desc = "Bad TAD target index (3)",
	.itc_imc = &imc_bad_tad_target,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_TAD_BAD_TARGET_INDEX
}, {
	.itc_desc = "Bad TAD target channel (1)",
	.itc_imc = &imc_bad_tad_channelid,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_ID
}, {
	.itc_desc = "Bad TAD target channel (2)",
	.itc_imc = &imc_bad_tad_channelid,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_ID
}, {
	.itc_desc = "Bad TAD target channel (3)",
	.itc_imc = &imc_bad_tad_channelid,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_ID
}, {
	.itc_desc = "Bad channel offset target (1)",
	.itc_imc = &imc_bad_channel_offset,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET
}, {
	.itc_desc = "Bad channel offset target (2)",
	.itc_imc = &imc_bad_channel_offset,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET
}, {
	.itc_desc = "Bad channel offset target (3)",
	.itc_imc = &imc_bad_channel_offset,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_CHANNEL_TAD_OFFSET
}, {
	.itc_desc = "Bad RIR rule (1)",
	.itc_imc = &imc_bad_rir_rule,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_RIR_RULE
}, {
	.itc_desc = "Bad RIR rule (2)",
	.itc_imc = &imc_bad_rir_rule,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_NO_RIR_RULE
}, {
	.itc_desc = "Bad RIR rule (3)",
	.itc_pa = 0x123456789ULL,
	.itc_imc = &imc_bad_rir_rule,
	.itc_fail = IMC_DECODE_F_NO_RIR_RULE
}, {
	.itc_desc = "Bad RIR interleave target (1)",
	.itc_imc = &imc_bad_rir_ileave,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET
}, {
	.itc_desc = "Bad RIR interleave target (2)",
	.itc_imc = &imc_bad_rir_ileave,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET
}, {
	.itc_desc = "Bad RIR interleave target (3)",
	.itc_imc = &imc_bad_rir_ileave,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_RIR_ILEAVE_TARGET
}, {
	.itc_desc = "Bad RIR DIMM target (1)",
	.itc_imc = &imc_bad_dimm_index,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_INDEX
}, {
	.itc_desc = "Bad RIR DIMM target (2)",
	.itc_imc = &imc_bad_dimm_index,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_INDEX
}, {
	.itc_desc = "Bad RIR DIMM target (3)",
	.itc_imc = &imc_bad_dimm_index,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_INDEX
}, {
	.itc_desc = "Bad RIR DIMM target (1)",
	.itc_imc = &imc_missing_dimm,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_DIMM_NOT_PRESENT
}, {
	.itc_desc = "Bad RIR DIMM target (2)",
	.itc_imc = &imc_missing_dimm,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_DIMM_NOT_PRESENT
}, {
	.itc_desc = "Bad RIR DIMM target (3)",
	.itc_imc = &imc_missing_dimm,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_DIMM_NOT_PRESENT
}, {
	.itc_desc = "Bad RIR rank target (1)",
	.itc_imc = &imc_bad_rank_index,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_RANK
}, {
	.itc_desc = "Bad RIR rank target (2)",
	.itc_imc = &imc_bad_rank_index,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_RANK
}, {
	.itc_desc = "Bad RIR rank target (3)",
	.itc_imc = &imc_bad_rank_index,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_BAD_DIMM_RANK
}, {
	.itc_desc = "Bad channel offset underflow (1)",
	.itc_imc = &imc_chanoff_underflow,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_CHANOFF_UNDERFLOW
}, {
	.itc_desc = "Bad channel offset underflow (2)",
	.itc_imc = &imc_chanoff_underflow,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_CHANOFF_UNDERFLOW
}, {
	.itc_desc = "Bad channel offset underflow (3)",
	.itc_imc = &imc_chanoff_underflow,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_CHANOFF_UNDERFLOW
}, {
	.itc_desc = "Bad rank offset underflow (1)",
	.itc_imc = &imc_riroff_underflow,
	.itc_pa = 0x45,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_RANKOFF_UNDERFLOW
}, {
	.itc_desc = "Bad rank offset underflow (2)",
	.itc_imc = &imc_riroff_underflow,
	.itc_pa = 0x7fffff,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_RANKOFF_UNDERFLOW
}, {
	.itc_desc = "Bad rank offset underflow (3)",
	.itc_imc = &imc_riroff_underflow,
	.itc_pa = 0x123456789ULL,
	.itc_pass = B_FALSE,
	.itc_fail = IMC_DECODE_F_RANKOFF_UNDERFLOW
}, {
	.itc_desc = NULL
} };
