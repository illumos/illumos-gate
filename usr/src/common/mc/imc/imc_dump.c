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

/*
 * This implements logic to allow us to dump IMC data for decoding purposes,
 * such that we can later encode it elsewhere. In general, dumping is done by
 * the kernel and reconstituting this data is done by user land.
 */

#include "imc.h"

#ifndef _KERNEL
#include <stdint.h>
#include <strings.h>
#endif	/* !_KERNEL */


static nvlist_t *
imc_dump_sad(imc_sad_t *sad)
{
	uint_t i;
	nvlist_t *nvl;
	nvlist_t *rules[IMC_MAX_SAD_RULES];
	nvlist_t *routes[IMC_MAX_SAD_MCROUTES];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "isad_flags", sad->isad_flags);
	fnvlist_add_uint32(nvl, "isad_valid", sad->isad_valid);
	fnvlist_add_uint64(nvl, "isad_tolm", sad->isad_tolm);
	fnvlist_add_uint64(nvl, "isad_tohm", sad->isad_tohm);

	for (i = 0; i < sad->isad_nrules; i++) {
		nvlist_t *n = fnvlist_alloc();
		imc_sad_rule_t *r = &sad->isad_rules[i];

		fnvlist_add_boolean_value(n, "isr_enable", r->isr_enable);
		fnvlist_add_boolean_value(n, "isr_a7mode", r->isr_a7mode);
		fnvlist_add_boolean_value(n, "isr_need_mod3", r->isr_need_mod3);
		fnvlist_add_uint64(n, "isr_limit", r->isr_limit);
		fnvlist_add_uint32(n, "isr_type", r->isr_type);
		fnvlist_add_uint32(n, "isr_imode", r->isr_imode);
		fnvlist_add_uint32(n, "isr_mod_mode", r->isr_mod_mode);
		fnvlist_add_uint32(n, "isr_mod_type", r->isr_mod_type);
		fnvlist_add_uint8_array(n, "isr_targets", r->isr_targets,
		    r->isr_ntargets);

		rules[i] = n;
	}
	fnvlist_add_nvlist_array(nvl, "isad_rules", rules, sad->isad_nrules);
	for (i = 0; i < sad->isad_nrules; i++) {
		nvlist_free(rules[i]);
	}

	if (sad->isad_mcroute.ismc_nroutes == 0) {
		return (nvl);
	}

	for (i = 0; i <  sad->isad_mcroute.ismc_nroutes; i++) {
		nvlist_t *r = fnvlist_alloc();
		imc_sad_mcroute_entry_t *e =
		    &sad->isad_mcroute.ismc_mcroutes[i];

		fnvlist_add_uint8(r, "ismce_imc", e->ismce_imc);
		fnvlist_add_uint8(r, "ismce_pchannel", e->ismce_pchannel);
		routes[i] = r;
	}
	fnvlist_add_nvlist_array(nvl, "isad_mcroute", routes, i);
	for (i = 0; i <  sad->isad_mcroute.ismc_nroutes; i++) {
		nvlist_free(routes[i]);
	}

	return (nvl);
}

static nvlist_t *
imc_dump_tad(imc_tad_t *tad)
{
	uint_t i;
	nvlist_t *nvl;
	nvlist_t *rules[IMC_MAX_TAD_RULES];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "itad_valid", tad->itad_valid);
	fnvlist_add_uint32(nvl, "itad_flags", tad->itad_flags);
	for (i = 0; i < tad->itad_nrules; i++) {
		nvlist_t *t = fnvlist_alloc();
		imc_tad_rule_t *r = &tad->itad_rules[i];

		fnvlist_add_uint64(t, "itr_base", r->itr_base);
		fnvlist_add_uint64(t, "itr_limit", r->itr_limit);
		fnvlist_add_uint8(t, "itr_sock_way", r->itr_sock_way);
		fnvlist_add_uint8(t, "itr_chan_way", r->itr_chan_way);
		fnvlist_add_uint32(t, "itr_sock_gran", r->itr_sock_gran);
		fnvlist_add_uint32(t, "itr_chan_gran", r->itr_chan_gran);
		fnvlist_add_uint8_array(t, "itr_targets", r->itr_targets,
		    r->itr_ntargets);

		rules[i] = t;
	}
	fnvlist_add_nvlist_array(nvl, "itad_rules", rules, tad->itad_nrules);
	for (i = 0; i < tad->itad_nrules; i++) {
		nvlist_free(rules[i]);
	}

	return (nvl);
}

static nvlist_t *
imc_dump_channel(imc_channel_t *chan)
{
	uint_t i;
	nvlist_t *nvl;
	nvlist_t *dimms[IMC_MAX_DIMMPERCHAN];
	nvlist_t *ranks[IMC_MAX_RANK_WAYS];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "ich_valid", chan->ich_valid);
	for (i = 0; i < chan->ich_ndimms; i++) {
		nvlist_t *d = fnvlist_alloc();
		imc_dimm_t *dimm = &chan->ich_dimms[i];

		fnvlist_add_uint32(d, "idimm_valid", dimm->idimm_valid);
		fnvlist_add_boolean_value(d, "idimm_present",
		    dimm->idimm_present);
		if (!dimm->idimm_present)
			goto add;

		fnvlist_add_uint8(d, "idimm_nbanks", dimm->idimm_nbanks);
		fnvlist_add_uint8(d, "idimm_nranks", dimm->idimm_nranks);
		fnvlist_add_uint8(d, "idimm_width", dimm->idimm_width);
		fnvlist_add_uint8(d, "idimm_density", dimm->idimm_density);
		fnvlist_add_uint8(d, "idimm_nrows", dimm->idimm_nrows);
		fnvlist_add_uint8(d, "idimm_ncolumns", dimm->idimm_ncolumns);
		fnvlist_add_uint64(d, "idimm_size", dimm->idimm_size);
add:
		dimms[i] = d;
	}
	fnvlist_add_nvlist_array(nvl, "ich_dimms", dimms, i);
	for (i = 0; i < chan->ich_ndimms; i++) {
		nvlist_free(dimms[i]);
	}

	fnvlist_add_uint64_array(nvl, "ich_tad_offsets", chan->ich_tad_offsets,
	    chan->ich_ntad_offsets);

	for (i = 0; i < chan->ich_nrankileaves; i++) {
		uint_t j;
		nvlist_t *r = fnvlist_alloc();
		nvlist_t *ileaves[IMC_MAX_RANK_INTERLEAVES];
		imc_rank_ileave_t *rank = &chan->ich_rankileaves[i];

		fnvlist_add_boolean_value(r, "irle_enabled",
		    rank->irle_enabled);
		fnvlist_add_uint8(r, "irle_nways", rank->irle_nways);
		fnvlist_add_uint8(r, "irle_nwaysbits", rank->irle_nwaysbits);
		fnvlist_add_uint64(r, "irle_limit", rank->irle_limit);

		for (j = 0; j < rank->irle_nentries; j++) {
			nvlist_t *e = fnvlist_alloc();

			fnvlist_add_uint8(e, "irle_target",
			    rank->irle_entries[j].irle_target);
			fnvlist_add_uint64(e, "irle_offset",
			    rank->irle_entries[j].irle_offset);
			ileaves[j] = e;
		}
		fnvlist_add_nvlist_array(r, "irle_entries", ileaves, j);
		for (j = 0; j < rank->irle_nentries; j++) {
			nvlist_free(ileaves[j]);
		}

		ranks[i] = r;
	}
	fnvlist_add_nvlist_array(nvl, "ich_rankileaves", ranks, i);
	for (i = 0; i < chan->ich_nrankileaves; i++) {
		nvlist_free(ranks[i]);
	}

	return (nvl);
}

static nvlist_t *
imc_dump_mc(imc_mc_t *mc)
{
	uint_t i;
	nvlist_t *nvl;
	nvlist_t *channels[IMC_MAX_CHANPERMC];

	nvl = fnvlist_alloc();
	fnvlist_add_boolean_value(nvl, "icn_ecc", mc->icn_ecc);
	fnvlist_add_boolean_value(nvl, "icn_lockstep", mc->icn_lockstep);
	fnvlist_add_boolean_value(nvl, "icn_closed", mc->icn_closed);
	fnvlist_add_uint32(nvl, "icn_dimm_type", mc->icn_dimm_type);

	for (i = 0; i < mc->icn_nchannels; i++) {
		channels[i] = imc_dump_channel(&mc->icn_channels[i]);
	}
	fnvlist_add_nvlist_array(nvl, "icn_channels", channels, i);
	for (i = 0; i < mc->icn_nchannels; i++) {
		nvlist_free(channels[i]);
	}

	return (nvl);
}

static nvlist_t *
imc_dump_socket(imc_socket_t *sock)
{
	uint_t i;
	nvlist_t *nvl, *sad;
	nvlist_t *tad[IMC_MAX_TAD];
	nvlist_t *mc[IMC_MAX_IMCPERSOCK];

	nvl = fnvlist_alloc();

	sad = imc_dump_sad(&sock->isock_sad);
	fnvlist_add_nvlist(nvl, "isock_sad", sad);
	nvlist_free(sad);

	for (i = 0; i < sock->isock_ntad; i++) {
		tad[i] = imc_dump_tad(&sock->isock_tad[i]);
	}
	fnvlist_add_nvlist_array(nvl, "isock_tad", tad, i);
	for (i = 0; i < sock->isock_ntad; i++) {
		fnvlist_free(tad[i]);
	}

	fnvlist_add_uint32(nvl, "isock_nodeid", sock->isock_nodeid);

	for (i = 0; i  < sock->isock_nimc; i++) {
		mc[i] = imc_dump_mc(&sock->isock_imcs[i]);
	}
	fnvlist_add_nvlist_array(nvl, "isock_imcs", mc, i);
	for (i = 0; i < sock->isock_nimc; i++) {
		fnvlist_free(mc[i]);
	}
	return (nvl);
}

nvlist_t *
imc_dump_decoder(imc_t *imc)
{
	uint_t i;
	nvlist_t *nvl, *invl;
	nvlist_t *sockets[IMC_MAX_SOCKETS];

	nvl = fnvlist_alloc();
	fnvlist_add_uint32(nvl, "mc_dump_version", 0);
	fnvlist_add_string(nvl, "mc_dump_driver", "imc");

	invl = fnvlist_alloc();
	fnvlist_add_uint32(invl, "imc_gen", imc->imc_gen);

	for (i = 0; i < imc->imc_nsockets; i++) {
		sockets[i] = imc_dump_socket(&imc->imc_sockets[i]);
	}
	fnvlist_add_nvlist_array(invl, "imc_sockets", sockets, i);
	fnvlist_add_nvlist(nvl, "imc", invl);

	for (i = 0; i < imc->imc_nsockets; i++) {
		nvlist_free(sockets[i]);
	}
	nvlist_free(invl);

	return (nvl);
}

static boolean_t
imc_restore_sad(nvlist_t *nvl, imc_sad_t *sad)
{
	nvlist_t **rules, **routes;
	uint_t i, nroutes;

	if (nvlist_lookup_uint32(nvl, "isad_flags", &sad->isad_flags) != 0 ||
	    nvlist_lookup_uint32(nvl, "isad_valid", &sad->isad_valid) != 0 ||
	    nvlist_lookup_uint64(nvl, "isad_tolm", &sad->isad_tolm) != 0 ||
	    nvlist_lookup_uint64(nvl, "isad_tohm", &sad->isad_tohm) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "isad_rules",
	    &rules, &sad->isad_nrules) != 0) {
		return (B_FALSE);
	}

	for (i = 0; i < sad->isad_nrules; i++) {
		imc_sad_rule_t *r = &sad->isad_rules[i];
		uint8_t *targs;

		if (nvlist_lookup_boolean_value(rules[i], "isr_enable",
		    &r->isr_enable) != 0 ||
		    nvlist_lookup_boolean_value(rules[i], "isr_a7mode",
		    &r->isr_a7mode) != 0 ||
		    nvlist_lookup_boolean_value(rules[i], "isr_need_mod3",
		    &r->isr_need_mod3) != 0 ||
		    nvlist_lookup_uint64(rules[i], "isr_limit",
		    &r->isr_limit) != 0 ||
		    nvlist_lookup_uint32(rules[i], "isr_type",
		    &r->isr_type) != 0 ||
		    nvlist_lookup_uint32(rules[i], "isr_imode",
		    &r->isr_imode) != 0 ||
		    nvlist_lookup_uint32(rules[i], "isr_mod_mode",
		    &r->isr_mod_mode) != 0 ||
		    nvlist_lookup_uint32(rules[i], "isr_mod_type",
		    &r->isr_mod_type) != 0 ||
		    nvlist_lookup_uint8_array(rules[i], "isr_targets", &targs,
		    &r->isr_ntargets) != 0 ||
		    r->isr_ntargets > IMC_MAX_SAD_RULES) {
			return (B_FALSE);
		}

		bcopy(targs, r->isr_targets, r->isr_ntargets *
		    sizeof (uint8_t));
	}

	/*
	 * The mcroutes entry right now is only included conditionally.
	 */
	if (nvlist_lookup_nvlist_array(nvl, "isad_mcroute", &routes,
	    &nroutes) == 0) {
		if (nroutes > IMC_MAX_SAD_MCROUTES)
			return (B_FALSE);
		sad->isad_mcroute.ismc_nroutes = nroutes;
		for (i = 0; i < nroutes; i++) {
			imc_sad_mcroute_entry_t *r =
			    &sad->isad_mcroute.ismc_mcroutes[i];
			if (nvlist_lookup_uint8(routes[i], "ismce_imc",
			    &r->ismce_imc) != 0 ||
			    nvlist_lookup_uint8(routes[i], "ismce_pchannel",
			    &r->ismce_pchannel) != 0) {
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

static boolean_t
imc_restore_tad(nvlist_t *nvl, imc_tad_t *tad)
{
	nvlist_t **rules;

	if (nvlist_lookup_uint32(nvl, "itad_valid", &tad->itad_valid) != 0 ||
	    nvlist_lookup_uint32(nvl, "itad_flags", &tad->itad_flags) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "itad_rules", &rules,
	    &tad->itad_nrules) != 0 || tad->itad_nrules > IMC_MAX_TAD_RULES) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < tad->itad_nrules; i++) {
		imc_tad_rule_t *r = &tad->itad_rules[i];
		uint8_t *targs;

		if (nvlist_lookup_uint64(rules[i], "itr_base",
		    &r->itr_base) != 0 ||
		    nvlist_lookup_uint64(rules[i], "itr_limit",
		    &r->itr_limit) != 0 ||
		    nvlist_lookup_uint8(rules[i], "itr_sock_way",
		    &r->itr_sock_way) != 0 ||
		    nvlist_lookup_uint8(rules[i], "itr_chan_way",
		    &r->itr_chan_way) != 0 ||
		    nvlist_lookup_uint32(rules[i], "itr_sock_gran",
		    &r->itr_sock_gran) != 0 ||
		    nvlist_lookup_uint32(rules[i], "itr_chan_gran",
		    &r->itr_chan_gran) != 0 ||
		    nvlist_lookup_uint8_array(rules[i], "itr_targets",
		    &targs, &r->itr_ntargets) != 0 ||
		    r->itr_ntargets > IMC_MAX_TAD_TARGETS) {
			return (B_FALSE);
		}

		bcopy(targs, r->itr_targets, r->itr_ntargets *
		    sizeof (uint8_t));
	}

	return (B_TRUE);
}

static boolean_t
imc_restore_channel(nvlist_t *nvl, imc_channel_t *chan)
{
	nvlist_t **dimms, **rir;
	uint64_t *tadoff;

	if (nvlist_lookup_uint32(nvl, "ich_valid", &chan->ich_valid) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "ich_dimms", &dimms,
	    &chan->ich_ndimms) != 0 ||
	    chan->ich_ndimms > IMC_MAX_DIMMPERCHAN ||
	    nvlist_lookup_uint64_array(nvl, "ich_tad_offsets", &tadoff,
	    &chan->ich_ntad_offsets) != 0 ||
	    chan->ich_ntad_offsets > IMC_MAX_TAD_RULES ||
	    nvlist_lookup_nvlist_array(nvl, "ich_rankileaves", &rir,
	    &chan->ich_nrankileaves) != 0 ||
	    chan->ich_nrankileaves > IMC_MAX_RANK_WAYS) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < chan->ich_ndimms; i++) {
		imc_dimm_t *d = &chan->ich_dimms[i];

		if (nvlist_lookup_uint32(dimms[i], "idimm_valid",
		    &d->idimm_valid) != 0 ||
		    nvlist_lookup_boolean_value(dimms[i], "idimm_present",
		    &d->idimm_present) != 0) {
			return (B_FALSE);
		}

		if (!d->idimm_present)
			continue;

		if (nvlist_lookup_uint8(dimms[i], "idimm_nbanks",
		    &d->idimm_nbanks) != 0 ||
		    nvlist_lookup_uint8(dimms[i], "idimm_nranks",
		    &d->idimm_nranks) != 0 ||
		    nvlist_lookup_uint8(dimms[i], "idimm_width",
		    &d->idimm_width) != 0 ||
		    nvlist_lookup_uint8(dimms[i], "idimm_density",
		    &d->idimm_density) != 0 ||
		    nvlist_lookup_uint8(dimms[i], "idimm_nrows",
		    &d->idimm_nrows) != 0 ||
		    nvlist_lookup_uint8(dimms[i], "idimm_ncolumns",
		    &d->idimm_ncolumns) != 0 ||
		    nvlist_lookup_uint64(dimms[i], "idimm_size",
		    &d->idimm_size) != 0) {
			return (B_FALSE);
		}
	}

	bcopy(tadoff, chan->ich_tad_offsets, chan->ich_ntad_offsets *
	    sizeof (uint64_t));

	for (uint_t i = 0; i < chan->ich_nrankileaves; i++) {
		nvlist_t **ileaves;
		imc_rank_ileave_t *r = &chan->ich_rankileaves[i];

		if (nvlist_lookup_boolean_value(rir[i], "irle_enabled",
		    &r->irle_enabled) != 0 ||
		    nvlist_lookup_uint8(rir[i], "irle_nways",
		    &r->irle_nways) != 0 ||
		    nvlist_lookup_uint8(rir[i], "irle_nwaysbits",
		    &r->irle_nwaysbits) != 0 ||
		    nvlist_lookup_uint64(rir[i], "irle_limit",
		    &r->irle_limit) != 0 ||
		    nvlist_lookup_nvlist_array(rir[i], "irle_entries",
		    &ileaves, &r->irle_nentries) != 0 ||
		    r->irle_nentries > IMC_MAX_RANK_INTERLEAVES) {
			return (B_FALSE);
		}

		for (uint_t j = 0; j < r->irle_nentries; j++) {
			imc_rank_ileave_entry_t *ril = &r->irle_entries[j];

			if (nvlist_lookup_uint8(ileaves[j], "irle_target",
			    &ril->irle_target) != 0 ||
			    nvlist_lookup_uint64(ileaves[j], "irle_offset",
			    &ril->irle_offset) != 0) {
				return (B_FALSE);
			}
		}
	}

	return (B_TRUE);
}

static boolean_t
imc_restore_mc(nvlist_t *nvl, imc_mc_t *mc)
{
	nvlist_t **channels;

	if (nvlist_lookup_boolean_value(nvl, "icn_ecc", &mc->icn_ecc) != 0 ||
	    nvlist_lookup_boolean_value(nvl, "icn_lockstep",
	    &mc->icn_lockstep) != 0 ||
	    nvlist_lookup_boolean_value(nvl, "icn_closed",
	    &mc->icn_closed) != 0 ||
	    nvlist_lookup_uint32(nvl, "icn_dimm_type",
	    &mc->icn_dimm_type) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "icn_channels", &channels,
	    &mc->icn_nchannels) != 0 || mc->icn_nchannels > IMC_MAX_CHANPERMC) {
		return (B_FALSE);
	}

	for (uint_t i = 0; i < mc->icn_nchannels; i++) {
		if (!imc_restore_channel(channels[i], &mc->icn_channels[i])) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
imc_restore_socket(nvlist_t *nvl, imc_socket_t *sock)
{
	uint_t i;
	nvlist_t *sad, **tads, **imcs;

	if (nvlist_lookup_nvlist(nvl, "isock_sad", &sad) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "isock_tad", &tads,
	    &sock->isock_ntad) != 0 ||
	    nvlist_lookup_uint32(nvl, "isock_nodeid",
	    &sock->isock_nodeid) != 0 ||
	    nvlist_lookup_nvlist_array(nvl, "isock_imcs", &imcs,
	    &sock->isock_nimc) != 0 ||
	    sock->isock_ntad > IMC_MAX_TAD ||
	    sock->isock_nimc > IMC_MAX_IMCPERSOCK) {
		return (B_FALSE);
	}

	if (!imc_restore_sad(sad, &sock->isock_sad)) {
		return (B_FALSE);
	}

	for (i = 0; i < sock->isock_ntad; i++) {
		if (!imc_restore_tad(tads[i], &sock->isock_tad[i])) {
			return (B_FALSE);
		}
	}

	for (i = 0; i < sock->isock_nimc; i++) {
		if (!imc_restore_mc(imcs[i], &sock->isock_imcs[i])) {
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

boolean_t
imc_restore_decoder(nvlist_t *nvl, imc_t *imc)
{
	uint_t i;
	uint32_t vers;
	nvlist_t *invl, **socks;
	char *driver;

	bzero(imc, sizeof (imc_t));

	if (nvlist_lookup_uint32(nvl, "mc_dump_version", &vers) != 0 ||
	    vers != 0 ||
	    nvlist_lookup_string(nvl, "mc_dump_driver", &driver) != 0 ||
	    strcmp(driver, "imc") != 0 ||
	    nvlist_lookup_nvlist(nvl, "imc", &invl) != 0) {
		return (B_FALSE);
	}

	if (nvlist_lookup_uint32(invl, "imc_gen", &imc->imc_gen) != 0 ||
	    nvlist_lookup_nvlist_array(invl, "imc_sockets", &socks,
	    &imc->imc_nsockets) != 0 ||
	    imc->imc_nsockets > IMC_MAX_SOCKETS) {
		return (B_FALSE);
	}

	for (i = 0; i < imc->imc_nsockets; i++) {
		if (!imc_restore_socket(socks[i], &imc->imc_sockets[i]))
			return (B_FALSE);
	}

	return (B_TRUE);
}
