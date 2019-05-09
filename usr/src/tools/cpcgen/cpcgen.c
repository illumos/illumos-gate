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

/*
 * This program transforms Intel perfmon and AMD PMC data files into C files and
 * manual pages.
 */

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <err.h>
#include <libgen.h>
#include <libnvpair.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

#include <json_nvlist.h>

#define	EXIT_USAGE	2
#define	CPROC_MAX_STEPPINGS	16

typedef enum {
	CPCGEN_MODE_UNKNOWN = 0,
	CPCGEN_MODE_INTEL,
	CPCGEN_MODE_AMD
} cpc_mode_t;

typedef struct cpc_proc {
	struct cpc_proc *cproc_next;
	uint_t		cproc_family;
	uint_t		cproc_model;
	uint_t		cproc_nsteps;
	uint_t		cproc_steppings[CPROC_MAX_STEPPINGS];
} cpc_proc_t;

typedef enum cpc_file_type {
	CPC_FILE_CORE		= 1 << 0,
	CPC_FILE_OFF_CORE	= 1 << 1,
	CPC_FILE_UNCORE		= 1 << 2,
	CPC_FILE_FP_MATH	= 1 << 3,
	CPC_FILE_UNCORE_EXP	= 1 << 4
} cpc_type_t;

typedef struct cpc_map {
	struct cpc_map	*cmap_next;
	cpc_type_t	cmap_type;
	nvlist_t	*cmap_data;
	char		*cmap_path;
	const char	*cmap_name;
	cpc_proc_t	*cmap_procs;
} cpc_map_t;

typedef struct cpc_whitelist {
	const char	*cwhite_short;
	const char	*cwhite_human;
	uint_t		cwhite_mask;
} cpc_whitelist_t;

/*
 * List of architectures that we support generating this data for. This is done
 * so that processors that illumos doesn't support or run on aren't generated
 * (generally the Xeon Phi).
 */
static cpc_whitelist_t cpcgen_intel_whitelist[] = {
	/* Nehalem */
	{ "NHM-EP", "nhm_ep", CPC_FILE_CORE },
	{ "NHM-EX", "nhm_ex", CPC_FILE_CORE },
	/* Westmere */
	{ "WSM-EP-DP", "wsm_ep_dp", CPC_FILE_CORE },
	{ "WSM-EP-SP", "wsm_ep_sp", CPC_FILE_CORE },
	{ "WSM-EX", "wsm_ex", CPC_FILE_CORE },
	/* Sandy Bridge */
	{ "SNB", "snb", CPC_FILE_CORE },
	{ "JKT", "jkt", CPC_FILE_CORE },
	/* Ivy Bridge */
	{ "IVB", "ivb", CPC_FILE_CORE },
	{ "IVT", "ivt", CPC_FILE_CORE },
	/* Haswell */
	{ "HSW", "hsw", CPC_FILE_CORE },
	{ "HSX", "hsx", CPC_FILE_CORE },
	/* Broadwell */
	{ "BDW", "bdw", CPC_FILE_CORE },
	{ "BDW-DE", "bdw_de", CPC_FILE_CORE },
	{ "BDX", "bdx", CPC_FILE_CORE },
	/* Skylake */
	{ "SKL", "skl", CPC_FILE_CORE },
	{ "SKX", "skx", CPC_FILE_CORE },
	/* Cascade Lake */
	{ "CLX", "clx", CPC_FILE_CORE },
	/* Atom */
	{ "BNL", "bnl", CPC_FILE_CORE },
	{ "SLM", "slm", CPC_FILE_CORE },
	{ "GLM", "glm", CPC_FILE_CORE },
	{ "GLP", "glp", CPC_FILE_CORE },
	{ NULL }
};

typedef struct cpc_papi {
	const char	*cpapi_intc;
	const char	*cpapi_papi;
} cpc_papi_t;

/*
 * This table maps events with an Intel specific name to the corresponding PAPI
 * name. There may be multiple Intel events which map to the same PAPI event.
 * This is usually because different processors have different names for an
 * event. We use the title as opposed to the event codes because those can
 * change somewhat arbitrarily between processor generations.
 */
static cpc_papi_t cpcgen_intel_papi_map[] = {
	{ "CPU_CLK_UNHALTED.THREAD_P", "PAPI_tot_cyc" },
	{ "INST_RETIRED.ANY_P", "PAPI_tot_ins" },
	{ "BR_INST_RETIRED.ALL_BRANCHES", "PAPI_br_ins" },
	{ "BR_MISP_RETIRED.ALL_BRANCHES", "PAPI_br_msp" },
	{ "BR_INST_RETIRED.CONDITIONAL", "PAPI_br_cn" },
	{ "CYCLE_ACTIVITY.CYCLES_L1D_MISS", "PAPI_l1_dcm" },
	{ "L1I.HITS", "PAPI_l1_ich" },
	{ "ICACHE.HIT", "PAPI_l1_ich" },
	{ "L1I.MISS", "PAPI_L1_icm" },
	{ "ICACHE.MISSES", "PAPI_l1_icm" },
	{ "L1I.READS", "PAPI_l1_ica" },
	{ "ICACHE.ACCESSES", "PAPI_l1_ica" },
	{ "L1I.READS", "PAPI_l1_icr" },
	{ "ICACHE.ACCESSES", "PAPI_l1_icr" },
	{ "L2_RQSTS.CODE_RD_MISS", "PAPI_l2_icm" },
	{ "L2_RQSTS.MISS", "PAPI_l2_tcm" },
	{ "ITLB_MISSES.MISS_CAUSES_A_WALK", "PAPI_tlb_im" },
	{ "DTLB_LOAD_MISSES.MISS_CAUSES_A_WALK", "PAPI_tlb_dm" },
	{ "PAGE_WALKS.D_SIDE_WALKS", "PAPI_tlb_dm" },
	{ "PAGE_WALKS.I_SIDE_WALKS", "PAPI_tlb_im" },
	{ "PAGE_WALKS.WALKS", "PAPI_tlb_tl" },
	{ "INST_QUEUE_WRITES", "PAPI_tot_iis" },
	{ "MEM_INST_RETIRED.STORES" "PAPI_sr_ins" },
	{ "MEM_INST_RETIRED.LOADS" "PAPI_ld_ins" },
	{ NULL, NULL }
};

typedef struct cpcgen_ops {
	void (*cgen_op_gather)(const char *, const char *);
	void (*cgen_op_common)(int);
	char *(*cgen_op_name)(cpc_map_t *);
	boolean_t (*cgen_op_skip)(nvlist_t *, const char *, uint_t);
	boolean_t (*cgen_op_file_before)(FILE *, cpc_map_t *);
	boolean_t (*cgen_op_file_after)(FILE *, cpc_map_t *);
	boolean_t (*cgen_op_event)(FILE *, nvlist_t *, const char *, uint32_t);
} cpcgen_ops_t;

static cpcgen_ops_t cpcgen_ops;
static const char *cpcgen_intel_mapfile = "/mapfile.csv";
static const char *cpcgen_progname;
static cpc_map_t *cpcgen_maps;
static cpc_mode_t cpcgen_mode = CPCGEN_MODE_UNKNOWN;

/*
 * Constants used for generating data.
 */
/* BEGIN CSTYLED */
static const char *cpcgen_cfile_intel_header = ""
"/*\n"
" *  Copyright (c) 2018, Intel Corporation\n"
" *  Copyright (c) 2018, Joyent, Inc\n"
" *  All rights reserved.\n"
" *\n"
" *  Redistribution and use in source and binary forms, with or without\n"
" *  modification, are permitted provided that the following conditions are met:\n"
" * \n"
" *   1. Redistributions of source code must retain the above copyright notice,\n"
" *      this list of conditions and the following disclaimer.\n"
" * \n"
" *   2. Redistributions in binary form must reproduce the above copyright \n"
" *      notice, this list of conditions and the following disclaimer in the\n"
" *      documentation and/or other materials provided with the distribution.\n"
" * \n"
" *   3. Neither the name of the Intel Corporation nor the names of its \n"
" *      contributors may be used to endorse or promote products derived from\n"
" *      this software without specific prior written permission.\n"
" *\n"
" *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
" *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
" *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
" *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE\n"
" *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
" *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
" *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
" *  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
" *  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
" *  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
" *  POSSIBILITY OF SUCH DAMAGE.\n"
" *\n"
" * This file was automatically generated by cpcgen from the data file\n"
" * data/perfmon%s\n"
" *\n"
" * Do not modify this file. Your changes will be lost!\n"
" */\n"
"\n";
/* END CSTYLED */

static const char *cpcgen_cfile_intel_table_start = ""
"#include <core_pcbe_table.h>\n"
"\n"
"const struct events_table_t pcbe_core_events_%s[] = {\n";

static const char *cpcgen_cfile_intel_table_end = ""
"\t{ NT_END, 0, 0, \"\" }\n"
"};\n";

/* BEGIN CSTYLED */
static const char *cpcgen_manual_intel_intel_header = ""
".\\\" Copyright (c) 2018, Intel Corporation \n"
".\\\" Copyright (c) 2018, Joyent, Inc.\n"
".\\\" All rights reserved.\n"
".\\\"\n"
".\\\" Redistribution and use in source and binary forms, with or without \n"
".\\\" modification, are permitted provided that the following conditions are met:\n"
".\\\"\n"
".\\\"  1. Redistributions of source code must retain the above copyright notice,\n"
".\\\"     this list of conditions and the following disclaimer.\n"
".\\\"\n"
".\\\"  2. Redistributions in binary form must reproduce the above copyright\n"
".\\\"     notice, this list of conditions and the following disclaimer in the\n"
".\\\"     documentation and/or other materials provided with the distribution.\n"
".\\\"\n"
".\\\"  3. Neither the name of the Intel Corporation nor the names of its\n"
".\\\"     contributors may be used to endorse or promote products derived from\n"
".\\\"     this software without specific prior written permission.\n"
".\\\"\n"
".\\\" THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS \"AS IS\"\n"
".\\\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE\n"
".\\\" IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE\n"
".\\\" ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE\n"
".\\\" LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR\n"
".\\\" CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF\n"
".\\\" SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS\n"
".\\\" INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN\n"
".\\\" CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)\n"
".\\\" ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE\n"
".\\\" POSSIBILITY OF SUCH DAMAGE.\n"
".\\\"\n"
".\\\" This file was automatically generated by cpcgen from the data file\n"
".\\\" data/perfmon%s\n"
".\\\"\n"
".\\\" Do not modify this file. Your changes will be lost!\n"
".\\\"\n"
".\\\" We would like to thank Intel for providing the perfmon data for use in\n"
".\\\" our manual pages.\n"
".Dd June 18, 2018\n"
".Dt %s_EVENTS 3CPC\n"
".Os\n"
".Sh NAME\n"
".Nm %s_events\n"
".Nd processor model specific performance counter events\n"
".Sh DESCRIPTION\n"
"This manual page describes events specific to the following Intel CPU\n"
"models and is derived from Intel's perfmon data.\n"
"For more information, please consult the Intel Software Developer's Manual "
"or Intel's perfmon website.\n"
".Pp\n"
"CPU models described by this document:\n"
".Bl -bullet\n";
/* END CSTYLED */

static const char *cpcgen_manual_intel_data = ""
".El\n"
".Pp\n"
"The following events are supported:\n"
".Bl -tag -width Sy\n";

static const char *cpcgen_manual_intel_trailer = ""
".El\n"
".Sh SEE ALSO\n"
".Xr cpc 3CPC\n"
".Pp\n"
".Lk https://download.01.org/perfmon/index/";

static const char *cpcgen_cfile_cddl_header = ""
"/*\n"
" * This file and its contents are supplied under the terms of the\n"
" * Common Development and Distribution License (\"CDDL\"), version 1.0.\n"
" * You may only use this file in accordance with the terms of version\n"
" * 1.0 of the CDDL.\n"
" *\n"
" * A full copy of the text of the CDDL should have accompanied this\n"
" * source.  A copy of the CDDL is also available via the Internet at\n"
" * http://www.illumos.org/license/CDDL.\n"
" */\n"
"\n"
"/*\n"
" * Copyright 2019 Joyent, Inc\n"
" */\n"
"\n"
"/*\n"
" * This file was automatically generated by cpcgen.\n"
" */\n"
"\n"
"/*\n"
" * Do not modify this file. Your changes will be lost!\n"
" */\n"
"\n";

static const char *cpcgen_manual_amd_header = ""
".\\\" This file was automatically generated by cpcgen from the data file\n"
".\\\" data/amdpmc/%s\n"
".\\\"\n"
".\\\" Do not modify this file. Your changes will be lost!\n"
".\\\"\n"
".\\\" We would like to thank AMD for providing the PMC data for use in\n"
".\\\" our manual pages.\n"
".Dd March 25, 2019\n"
".Dt AMD_%s_EVENTS 3CPC\n"
".Os\n"
".Sh NAME\n"
".Nm amd_%s_events\n"
".Nd AMD family %s processor performance monitoring events\n"
".Sh DESCRIPTION\n"
"This manual page describes events specfic to AMD family %s processors.\n"
"For more information, please consult the appropriate AMD BIOS and Kernel\n"
"Developer's guide or Open-Source Register Reference manual.\n"
".Pp\n"
"Each of the events listed below includes the AMD mnemonic which matches\n"
"the name found in the AMD manual and a brief summary of the event.\n"
"If available, a more detailed description of the event follows and then\n"
"any additional unit values that modify the event.\n"
"Each unit can be combined to create a new event in the system by placing\n"
"the '.' character between the event name and the unit name.\n"
".Pp\n"
"The following events are supported:\n"
".Bl -tag -width Sy\n";

static const char *cpcgen_manual_amd_trailer = ""
".El\n"
".Sh SEE ALSO\n"
".Xr cpc 3CPC\n";

static const char *cpcgen_cfile_amd_header = ""
"/*\n"
" * This file was automatically generated by cpcgen from the data file\n"
" * data/perfmon%s\n"
" *\n"
" * Do not modify this file. Your changes will be lost!\n"
" */\n"
"\n";

static const char *cpcgen_cfile_amd_table_start = ""
"#include <opteron_pcbe_table.h>\n"
"#include <sys/null.h>\n"
"\n"
"const amd_event_t opteron_pcbe_%s_events[] = {\n";

static const char *cpcgen_cfile_amd_table_end = ""
"\t{ NULL, 0, 0 }\n"
"};\n";

static cpc_map_t *
cpcgen_map_lookup(const char *path)
{
	cpc_map_t *m;

	for (m = cpcgen_maps; m != NULL; m = m->cmap_next) {
		if (strcmp(path, m->cmap_path) == 0) {
			return (m);
		}
	}

	return (NULL);
}

/*
 * Parse a string of the form 'GenuineIntel-6-2E' and get out the family and
 * model.
 */
static void
cpcgen_parse_model(char *fsr, uint_t *family, uint_t *model, uint_t *nstepp,
    uint_t *steppings)
{
	const char *bstr = "GenuineIntel";
	const char *brand, *fam, *mod, *step;
	char *last;
	long l;
	uint_t nstep = 0;

	/*
	 * Tokeninze the string. There may be an optional stepping portion,
	 * which has a range of steppings enclosed by '[' and ']' characters.
	 * While the other parts are required, the stepping may be missing.
	 */
	if ((brand = strtok_r(fsr, "-", &last)) == NULL ||
	    (fam = strtok_r(NULL, "-", &last)) == NULL ||
	    (mod = strtok_r(NULL, "-", &last)) == NULL) {
		errx(EXIT_FAILURE, "failed to parse processor id \"%s\"", fsr);
	}
	step = strtok_r(NULL, "-", &last);

	if (strcmp(bstr, brand) != 0) {
		errx(EXIT_FAILURE, "brand string \"%s\" did not match \"%s\"",
		    brand, bstr);
	}

	errno = 0;
	l = strtol(fam, &last, 16);
	if (errno != 0 || l < 0 || l > UINT_MAX || *last != '\0') {
		errx(EXIT_FAILURE, "failed to parse family \"%s\"", fam);
	}
	*family = (uint_t)l;

	l = strtol(mod, &last, 16);
	if (errno != 0 || l < 0 || l > UINT_MAX || *last != '\0') {
		errx(EXIT_FAILURE, "failed to parse model \"%s\"", mod);
	}
	*model = (uint_t)l;

	if (step == NULL) {
		*nstepp = 0;
		return;
	}

	if (*step != '[' || ((last = strrchr(step, ']')) == NULL)) {
		errx(EXIT_FAILURE, "failed to parse stepping \"%s\": missing "
		    "stepping range brackets", step);
	}
	step++;
	*last = '\0';
	while (*step != '\0') {
		if (!isxdigit(*step)) {
			errx(EXIT_FAILURE, "failed to parse stepping: invalid "
			    "stepping identifier '0x%x'", *step);
		}

		if (nstep >= CPROC_MAX_STEPPINGS) {
			errx(EXIT_FAILURE, "failed to parse stepping: "
			    "encountered too many steppings");
		}

		switch (*step) {
		case '0':
			steppings[nstep] = 0x0;
			break;
		case '1':
			steppings[nstep] = 0x1;
			break;
		case '2':
			steppings[nstep] = 0x2;
			break;
		case '3':
			steppings[nstep] = 0x3;
			break;
		case '4':
			steppings[nstep] = 0x4;
			break;
		case '5':
			steppings[nstep] = 0x5;
			break;
		case '6':
			steppings[nstep] = 0x6;
			break;
		case '7':
			steppings[nstep] = 0x7;
			break;
		case '8':
			steppings[nstep] = 0x8;
			break;
		case '9':
			steppings[nstep] = 0x9;
			break;
		case 'a':
		case 'A':
			steppings[nstep] = 0xa;
			break;
		case 'b':
		case 'B':
			steppings[nstep] = 0xb;
			break;
		case 'c':
		case 'C':
			steppings[nstep] = 0xc;
			break;
		case 'd':
		case 'D':
			steppings[nstep] = 0xd;
			break;
		case 'e':
		case 'E':
			steppings[nstep] = 0xe;
			break;
		case 'f':
		case 'F':
			steppings[nstep] = 0xf;
			break;
		default:
			errx(EXIT_FAILURE, "encountered non-hex stepping "
			    "character: '%c'", *step);
		}
		nstep++;
		step++;
	}

	*nstepp = nstep;
}

static nvlist_t *
cpcgen_read_datafile(const char *datadir, const char *file)
{
	int fd;
	char *path;
	struct stat st;
	void *map;
	nvlist_t *nvl;
	nvlist_parse_json_error_t jerr;

	if (asprintf(&path, "%s/%s", datadir, file) == -1) {
		err(EXIT_FAILURE, "failed to construct path to data file %s",
		    file);
	}

	if ((fd = open(path, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open data file %s", path);
	}

	if (fstat(fd, &st) != 0) {
		err(EXIT_FAILURE, "failed to stat %s", path);
	}

	if ((map = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE,
	    fd, 0)) == MAP_FAILED) {
		err(EXIT_FAILURE, "failed to mmap %s", path);
	}

	if (nvlist_parse_json(map, st.st_size, &nvl, NVJSON_FORCE_INTEGER,
	    &jerr) != 0) {
		errx(EXIT_FAILURE, "failed to parse file %s at pos %ld: %s",
		    path, jerr.nje_pos, jerr.nje_message);
	}

	if (munmap(map, st.st_size) != 0) {
		err(EXIT_FAILURE, "failed to munmap %s", path);
	}

	if (close(fd) != 0) {
		err(EXIT_FAILURE, "failed to close data file %s", path);
	}
	free(path);

	return (nvl);
}

/*
 * Check the whitelist to see if we should use this model.
 */
static const char *
cpcgen_use_arch(const char *path, cpc_type_t type, const char *platform)
{
	const char *slash;
	size_t len;
	uint_t i;

	if (*path != '/') {
		errx(EXIT_FAILURE, "invalid path in mapfile: \"%s\": missing "
		    "leading '/'", path);
	}
	if ((slash = strchr(path + 1, '/')) == NULL) {
		errx(EXIT_FAILURE, "invalid path in mapfile: \"%s\": missing "
		    "second '/'", path);
	}
	/* Account for the last '/' character. */
	len = slash - path - 1;
	assert(len > 0);

	for (i = 0; cpcgen_intel_whitelist[i].cwhite_short != NULL; i++) {
		if (platform != NULL && strcasecmp(platform,
		    cpcgen_intel_whitelist[i].cwhite_short) != 0)
			continue;
		if (strncmp(path + 1, cpcgen_intel_whitelist[i].cwhite_short,
		    len) == 0 &&
		    (cpcgen_intel_whitelist[i].cwhite_mask & type) == type) {
			return (cpcgen_intel_whitelist[i].cwhite_human);
		}
	}

	return (NULL);
}

/*
 * Determine which CPU Vendor we're transmuting data from.
 */
static void
cpcgen_determine_vendor(const char *datadir)
{
	char *mappath;
	struct stat st;

	if (asprintf(&mappath, "%s/%s", datadir, cpcgen_intel_mapfile) == -1) {
		err(EXIT_FAILURE, "failed to construct path to mapfile");
	}

	if (stat(mappath, &st) == 0) {
		cpcgen_mode = CPCGEN_MODE_INTEL;
	} else {
		if (errno != ENOENT) {
			err(EXIT_FAILURE, "stat(2) of %s failed unexpectedly");
		}

		cpcgen_mode = CPCGEN_MODE_AMD;
	}

	free(mappath);
}

/*
 * Read in all the data files that exist for AMD.
 *
 * Our family names for AMD systems are based on the family and type so a given
 * name will look like f17h_core.json.
 */
static void
cpcgen_read_amd(const char *datadir, const char *platform)
{
	DIR *dir;
	struct dirent *d;
	const char *suffix = ".json";
	const size_t slen = strlen(suffix);

	if ((dir = opendir(datadir)) == NULL) {
		err(EXIT_FAILURE, "failed to open directory %s", datadir);
	}

	while ((d = readdir(dir)) != NULL) {
		char *name, *c;
		cpc_map_t *map;
		nvlist_t *parsed;

		if ((name = strdup(d->d_name)) == NULL) {
			errx(EXIT_FAILURE, "ran out of memory duplicating "
			    "name %s", d->d_name);
		}
		c = strstr(name, suffix);

		if (c == NULL) {
			free(name);
			continue;
		}

		if (*(c + slen) != '\0') {
			free(name);
			continue;
		}

		*c = '\0';
		c = strchr(name, '_');
		if (c == NULL) {
			free(name);
			continue;
		}
		*c = '\0';
		c++;
		if (strcmp(c, "core") != 0) {
			errx(EXIT_FAILURE, "unexpected AMD JSON file name: %s",
			    d->d_name);
		}

		if (platform != NULL && strcmp(platform, name) != 0) {
			free(name);
			continue;
		}

		if ((map = calloc(1, sizeof (cpc_map_t))) == NULL) {
			err(EXIT_FAILURE, "failed to allocate space for cpc "
			    "file");
		}

		parsed = cpcgen_read_datafile(datadir, d->d_name);
		if ((map->cmap_path = strdup(d->d_name)) == NULL) {
			err(EXIT_FAILURE, "failed to duplicate path string");
		}
		map->cmap_type = CPC_FILE_CORE;
		map->cmap_data = parsed;
		map->cmap_name = name;
		map->cmap_procs = NULL;

		map->cmap_next = cpcgen_maps;
		cpcgen_maps = map;
	}
}

/*
 * Read in the mapfile.csv that is used to map between processor families and
 * parse this. Each line has a comma separated value.
 */
static void
cpcgen_read_intel(const char *datadir, const char *platform)
{
	FILE *map;
	char *mappath, *last;
	char *data = NULL;
	size_t datalen = 0;
	uint_t lineno;

	if (asprintf(&mappath, "%s/%s", datadir, cpcgen_intel_mapfile) == -1) {
		err(EXIT_FAILURE, "failed to construct path to mapfile");
	}

	if ((map = fopen(mappath, "r")) == NULL) {
		err(EXIT_FAILURE, "failed to open data mapfile %s", mappath);
	}

	lineno = 0;
	while (getline(&data, &datalen, map) != -1) {
		char *fstr, *path, *tstr;
		const char *name;
		uint_t family, model, nsteps;
		uint_t steppings[CPROC_MAX_STEPPINGS];

		cpc_type_t type;
		cpc_map_t *map;
		cpc_proc_t *proc;

		/*
		 * The first line contains the header:
		 * Family-model,Version,Filename,EventType
		 */
		lineno++;
		if (lineno == 1) {
			continue;
		}

		if ((fstr = strtok_r(data, ",", &last)) == NULL ||
		    strtok_r(NULL, ",", &last) == NULL ||
		    (path = strtok_r(NULL, ",", &last)) == NULL ||
		    (tstr = strtok_r(NULL, "\n", &last)) == NULL) {
			errx(EXIT_FAILURE, "failed to parse mapfile line "
			    "%u in %s", lineno, mappath);
		}

		cpcgen_parse_model(fstr, &family, &model, &nsteps, steppings);

		if (strcmp(tstr, "core") == 0) {
			type = CPC_FILE_CORE;
		} else if (strcmp(tstr, "offcore") == 0) {
			type = CPC_FILE_OFF_CORE;
		} else if (strcmp(tstr, "uncore") == 0) {
			type = CPC_FILE_UNCORE;
		} else if (strcmp(tstr, "fp_arith_inst") == 0) {
			type = CPC_FILE_FP_MATH;
		} else if (strcmp(tstr, "uncore experimental") == 0) {
			type = CPC_FILE_UNCORE_EXP;
		} else {
			errx(EXIT_FAILURE, "unknown file type \"%s\" on line "
			    "%u", tstr, lineno);
		}

		if ((name = cpcgen_use_arch(path, type, platform)) == NULL)
			continue;

		if ((map = cpcgen_map_lookup(path)) == NULL) {
			nvlist_t *parsed;

			parsed = cpcgen_read_datafile(datadir, path);

			if ((map = calloc(1, sizeof (cpc_map_t))) == NULL) {
				err(EXIT_FAILURE, "failed to allocate space "
				    "for cpc file");
			}

			if ((map->cmap_path = strdup(path)) == NULL) {
				err(EXIT_FAILURE, "failed to duplicate path "
				    "string");
			}

			map->cmap_type = type;
			map->cmap_data = parsed;
			map->cmap_name = name;
			map->cmap_procs = NULL;

			map->cmap_next = cpcgen_maps;
			cpcgen_maps = map;
		}

		if ((proc = calloc(1, sizeof (cpc_proc_t))) == NULL) {
			err(EXIT_FAILURE, "failed to allocate memory for "
			    "family and model tracking");
		}

		proc->cproc_family = family;
		proc->cproc_model = model;
		proc->cproc_nsteps = nsteps;
		if (nsteps > 0) {
			bcopy(steppings, proc->cproc_steppings,
			    sizeof (steppings));
		}
		proc->cproc_next = map->cmap_procs;
		map->cmap_procs = proc;
	}

	if (errno != 0 || ferror(map)) {
		err(EXIT_FAILURE, "failed to read %s", mappath);
	}

	if (fclose(map) == EOF) {
		err(EXIT_FAILURE, "failed to close %s", mappath);
	}
	free(data);
	free(mappath);
}

static char *
cpcgen_manual_intel_name(cpc_map_t *map)
{
	char *name;

	if (asprintf(&name, "%s_events.3cpc", map->cmap_name) == -1) {
		warn("failed to assemble manual page name for %s",
		    map->cmap_path);
		return (NULL);
	}

	return (name);
}

static boolean_t
cpcgen_manual_intel_file_before(FILE *f, cpc_map_t *map)
{
	size_t i;
	char *upper;
	cpc_proc_t *proc;

	if ((upper = strdup(map->cmap_name)) == NULL) {
		warn("failed to duplicate manual name for %s", map->cmap_name);
		return (B_FALSE);
	}

	for (i = 0; upper[i] != '\0'; i++) {
		upper[i] = toupper(upper[i]);
	}

	if (fprintf(f, cpcgen_manual_intel_intel_header, map->cmap_path, upper,
	    map->cmap_name) == -1) {
		warn("failed to write out manual header for %s",
		    map->cmap_name);
		free(upper);
		return (B_FALSE);
	}
	free(upper);

	for (proc = map->cmap_procs; proc != NULL; proc = proc->cproc_next) {
		if (proc->cproc_nsteps > 0) {
			uint_t step;

			for (step = 0; step < proc->cproc_nsteps; step++) {
				if (fprintf(f, ".It\n.Sy Family 0x%x, Model "
				    "0x%x, Stepping 0x%x\n",
				    proc->cproc_family, proc->cproc_model,
				    proc->cproc_steppings[step]) == -1) {
					warn("failed to write out model "
					    "information for %s",
					    map->cmap_name);
					return (B_FALSE);
				}
			}
		} else {
			if (fprintf(f, ".It\n.Sy Family 0x%x, Model 0x%x\n",
			    proc->cproc_family, proc->cproc_model) == -1) {
				warn("failed to write out model information "
				    "for %s", map->cmap_name);
				return (B_FALSE);
			}
		}
	}

	if (fprintf(f, cpcgen_manual_intel_data) == -1) {
		warn("failed to write out manual header for %s",
		    map->cmap_name);
		return (B_FALSE);
	}

	free(upper);
	return (B_TRUE);
}

static boolean_t
cpcgen_manual_intel_file_after(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_manual_intel_trailer) == -1) {
		warn("failed to write out manual header for %s",
		    map->cmap_name);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_manual_intel_event(FILE *f, nvlist_t *nvl, const char *path,
    uint32_t ent)
{
	char *event, *lname, *brief = NULL, *public = NULL, *errata = NULL;
	size_t i;

	if (nvlist_lookup_string(nvl, "EventName", &event) != 0) {
		warnx("Found event without 'EventName' property "
		    "in %s, entry %u", path, ent);
		return (B_FALSE);
	}

	/*
	 * Intel uses capital names. CPC historically uses lower case names.
	 */
	if ((lname = strdup(event)) == NULL) {
		err(EXIT_FAILURE, "failed to duplicate event name %s", event);
	}
	for (i = 0; lname[i] != '\0'; i++) {
		lname[i] = tolower(event[i]);
	}

	/*
	 * Try to get the other event fields, but if they're not there, don't
	 * worry about it.
	 */
	(void) nvlist_lookup_string(nvl, "BriefDescription", &brief);
	(void) nvlist_lookup_string(nvl, "PublicDescription", &public);
	(void) nvlist_lookup_string(nvl, "Errata", &errata);
	if (errata != NULL && (strcmp(errata, "0") == 0 ||
	    strcmp(errata, "null") == 0)) {
		errata = NULL;
	}

	if (fprintf(f, ".It Sy %s\n", lname) == -1) {
		warn("failed to write out event entry %s", event);
		free(lname);
		return (B_FALSE);
	}

	if (public != NULL) {
		if (fprintf(f, "%s\n", public) == -1) {
			warn("failed to write out event entry %s", event);
			free(lname);
			return (B_FALSE);
		}
	} else if (brief != NULL) {
		if (fprintf(f, "%s\n", brief) == -1) {
			warn("failed to write out event entry %s", event);
			free(lname);
			return (B_FALSE);
		}
	}

	if (errata != NULL) {
		if (fprintf(f, ".Pp\nThe following errata may apply to this: "
		    "%s\n", errata) == -1) {

			warn("failed to write out event entry %s", event);
			free(lname);
			return (B_FALSE);
		}
	}

	free(lname);
	return (B_TRUE);
}

static char *
cpcgen_cfile_intel_name(cpc_map_t *map)
{
	char *name;

	if (asprintf(&name, "core_pcbe_%s.c", map->cmap_name) == -1) {
		warn("failed to assemble file name for %s", map->cmap_path);
		return (NULL);
	}

	return (name);
}

static boolean_t
cpcgen_cfile_intel_before(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_cfile_intel_header, map->cmap_path) == -1) {
		warn("failed to write header to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}

	if (fprintf(f, cpcgen_cfile_intel_table_start, map->cmap_name) == -1) {
		warn("failed to write header to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_cfile_intel_after(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_cfile_intel_table_end) == -1) {
		warn("failed to write footer to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_cfile_intel_event(FILE *f, nvlist_t *nvl, const char *path, uint_t ent)
{
	char *ecode, *umask, *name, *counter, *lname, *cmask;
	size_t i;

	if (nvlist_lookup_string(nvl, "EventName", &name) != 0) {
		warnx("Found event without 'EventName' property "
		    "in %s, entry %u", path, ent);
		return (B_FALSE);
	}

	if (nvlist_lookup_string(nvl, "EventCode", &ecode) != 0 ||
	    nvlist_lookup_string(nvl, "UMask", &umask) != 0 ||
	    nvlist_lookup_string(nvl, "Counter", &counter) != 0) {
		warnx("event %s (index %u) from %s, missing "
		    "required properties for C file translation",
		    name, ent, path);
		return (B_FALSE);
	}

	/*
	 * While we could try and parse the counters manually, just do this the
	 * max power way for now based on all possible values.
	 */
	if (strcmp(counter, "0") == 0 || strcmp(counter, "0,") == 0) {
		cmask = "C0";
	} else if (strcmp(counter, "1") == 0) {
		cmask = "C1";
	} else if (strcmp(counter, "2") == 0) {
		cmask = "C2";
	} else if (strcmp(counter, "3") == 0) {
		cmask = "C3";
	} else if (strcmp(counter, "0,1") == 0) {
		cmask = "C0|C1";
	} else if (strcmp(counter, "0,1,2") == 0) {
		cmask = "C0|C1|C2";
	} else if (strcmp(counter, "0,1,2,3") == 0) {
		cmask = "C0|C1|C2|C3";
	} else if (strcmp(counter, "0,2,3") == 0) {
		cmask = "C0|C2|C3";
	} else if (strcmp(counter, "1,2,3") == 0) {
		cmask = "C1|C2|C3";
	} else if (strcmp(counter, "2,3") == 0) {
		cmask = "C2|C3";
	} else {
		warnx("event %s (index %u) from %s, has unknown "
		    "counter value \"%s\"", name, ent, path, counter);
		return (B_FALSE);
	}


	/*
	 * Intel uses capital names. CPC historically uses lower case names.
	 */
	if ((lname = strdup(name)) == NULL) {
		err(EXIT_FAILURE, "failed to duplicate event name %s", name);
	}
	for (i = 0; lname[i] != '\0'; i++) {
		lname[i] = tolower(name[i]);
	}

	if (fprintf(f, "\t{ %s, %s, %s, \"%s\" },\n", ecode, umask, cmask,
	    lname) == -1) {
		warn("failed to write out entry %s from %s", name, path);
		free(lname);
		return (B_FALSE);
	}

	free(lname);

	/*
	 * Check if we have any PAPI aliases.
	 */
	for (i = 0; cpcgen_intel_papi_map[i].cpapi_intc != NULL; i++) {
		if (strcmp(name, cpcgen_intel_papi_map[i].cpapi_intc) != 0)
			continue;

		if (fprintf(f, "\t{ %s, %s, %s, \"%s\" },\n", ecode, umask,
		    cmask, cpcgen_intel_papi_map[i].cpapi_papi) == -1) {
			warn("failed to write out entry %s from %s", name,
			    path);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_generate_map(FILE *f, cpc_map_t *map, boolean_t start)
{
	cpc_proc_t *p;

	if (fprintf(f, "\t%sif (", start ? "" : "} else ") == -1) {
		return (B_FALSE);
	}

	for (p = map->cmap_procs; p != NULL; p = p->cproc_next) {
		/*
		 * Make sure the line is padded so the generated C code looks
		 * like reasonable C style.
		 */
		if (p != map->cmap_procs) {
			if (fputs("\t    ", f) == -1) {
				return (B_FALSE);
			}
		}

		if (p->cproc_nsteps > 0) {
			uint_t i;

			if (fprintf(f, "(model == 0x%x &&\n\t    (",
			    p->cproc_model) == -1) {
				return (B_FALSE);
			}

			for (i = 0; i < p->cproc_nsteps; i++) {
				if (fprintf(f, "stepping == 0x%x%s",
				    p->cproc_steppings[i],
				    i + 1 != p->cproc_nsteps ?
				    " ||\n\t    " : "") == -1) {
					return (B_FALSE);
				}
			}

			if (fputs("))", f) == -1) {
				return (B_FALSE);
			}
		} else if (fprintf(f, "model == 0x%x", p->cproc_model) == -1) {
			return (B_FALSE);
		}

		if (fprintf(f, "%s\n",
		    p->cproc_next != NULL ? " ||" : ") {") == -1) {
			return (B_FALSE);
		}
	}

	if (fprintf(f, "\t\t\treturn (pcbe_core_events_%s);\n",
	    map->cmap_name) == -1) {
		return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * This is a wrapper around unlinkat that makes sure that we don't clobber
 * errno, which is used for properly printing out error messages below.
 */
static void
cpcgen_remove_tmpfile(int dirfd, const char *path)
{
	int e = errno;
	(void) unlinkat(dirfd, path, 0);
	errno = e;
}

/*
 * Generate a header file that declares all of these arrays and provide a map
 * for models to the corresponding table to use.
 */
static void
cpcgen_common_intel_files(int dirfd)
{
	const char *fname = "core_pcbe_cpcgen.h";
	char *tmpname;
	int fd;
	FILE *f;
	cpc_map_t *map;

	if (asprintf(&tmpname, ".%s.%d", fname, getpid()) == -1) {
		err(EXIT_FAILURE, "failed to construct temporary file name");
	}

	if ((fd = openat(dirfd, tmpname, O_RDWR | O_CREAT, 0644)) < 0) {
		err(EXIT_FAILURE, "failed to create temporary file %s",
		    tmpname);
	}

	if ((f = fdopen(fd, "w")) == NULL) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to fdopen temporary file");
	}

	if (fprintf(f, cpcgen_cfile_intel_header, cpcgen_intel_mapfile) == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to temporary file "
		    "for %s", fname);
	}

	if (fprintf(f, "#ifndef _CORE_PCBE_CPCGEN_H\n"
	    "#define\t_CORE_PCBE_CPCGEN_H\n"
	    "\n"
	    "#ifdef __cplusplus\n"
	    "extern \"C\" {\n"
	    "#endif\n"
	    "\n"
	    "extern const struct events_table_t *core_cpcgen_table(uint_t, "
	    "uint_t);\n"
	    "\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	for (map = cpcgen_maps; map != NULL; map = map->cmap_next) {
		if (fprintf(f, "extern const struct events_table_t "
		    "pcbe_core_events_%s[];\n", map->cmap_name) == -1) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			errx(EXIT_FAILURE, "failed to write entry to "
			    "temporary file for %s", fname);
		}
	}

	if (fprintf(f, "\n"
	    "#ifdef __cplusplus\n"
	    "}\n"
	    "#endif\n"
	    "\n"
	    "#endif /* _CORE_PCBE_CPCGEN_H */\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	if (fflush(f) != 0 || fclose(f) != 0) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to flush and close temporary file");
	}

	if (renameat(dirfd, tmpname, dirfd, fname) != 0) {
		err(EXIT_FAILURE, "failed to rename temporary file %s",
		    tmpname);
	}

	free(tmpname);

	/* Now again for the .c file. */
	fname = "core_pcbe_cpcgen.c";
	if (asprintf(&tmpname, ".%s.%d", fname, getpid()) == -1) {
		err(EXIT_FAILURE, "failed to construct temporary file name");
	}

	if ((fd = openat(dirfd, tmpname, O_RDWR | O_CREAT, 0644)) < 0) {
		err(EXIT_FAILURE, "failed to create temporary file %s",
		    tmpname);
	}

	if ((f = fdopen(fd, "w")) == NULL) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to fdopen temporary file");
	}

	if (fprintf(f, cpcgen_cfile_intel_header, cpcgen_intel_mapfile) == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to temporary file "
		    "for %s", fname);
	}

	if (fprintf(f, "#include <core_pcbe_table.h>\n"
	    "#include <sys/null.h>\n"
	    "#include \"core_pcbe_cpcgen.h\"\n"
	    "\n"
	    "const struct events_table_t *\n"
	    "core_cpcgen_table(uint_t model, uint_t stepping)\n"
	    "{\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	for (map = cpcgen_maps; map != NULL; map = map->cmap_next) {
		if (!cpcgen_generate_map(f, map, map == cpcgen_maps)) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			errx(EXIT_FAILURE, "failed to write to temporary "
			    "file for %s", fname);
		}
	}

	if (fprintf(f, "\t} else {\n"
	    "\t\t\treturn (NULL);\n"
	    "\t}\n"
	    "}\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		errx(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	if (fflush(f) != 0 || fclose(f) != 0) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to flush and close temporary file");
	}

	if (renameat(dirfd, tmpname, dirfd, fname) != 0) {
		err(EXIT_FAILURE, "failed to rename temporary file %s",
		    tmpname);
	}

	free(tmpname);
}

/*
 * Look at a rule to determine whether or not we should consider including it or
 * not. At this point we've already filtered things such that we only get core
 * events.
 *
 * To consider an entry, we currently apply the following criteria:
 *
 * - The MSRIndex and MSRValue are zero. Programming additional MSRs is no
 *   supported right now.
 * - TakenAlone is non-zero, which means that it cannot run at the same time as
 *   another field.
 * - Offcore is one, indicating that it is off the core and we need to figure
 *   out if we can support this.
 * - If the counter is fixed, don't use it for now.
 * - If more than one value is specified in the EventCode or UMask values
 */
static boolean_t
cpcgen_skip_intel_entry(nvlist_t *nvl, const char *path, uint_t ent)
{
	char *event, *msridx, *msrval, *taken, *offcore, *counter;
	char *ecode, *umask;

	/*
	 * Require EventName, it's kind of useless without that.
	 */
	if (nvlist_lookup_string(nvl, "EventName", &event) != 0) {
		errx(EXIT_FAILURE, "Found event without 'EventName' property "
		    "in %s, entry %u", path, ent);
	}

	/*
	 * If we can't find an expected value, whine about it.
	 */
	if (nvlist_lookup_string(nvl, "MSRIndex", &msridx) != 0 ||
	    nvlist_lookup_string(nvl, "MSRValue", &msrval) != 0 ||
	    nvlist_lookup_string(nvl, "Counter", &counter) != 0 ||
	    nvlist_lookup_string(nvl, "EventCode", &ecode) != 0 ||
	    nvlist_lookup_string(nvl, "UMask", &umask) != 0 ||
	    nvlist_lookup_string(nvl, "Offcore", &offcore) != 0) {
		warnx("Skipping event %s (index %u) from %s, missing required "
		    "property", event, ent, path);
		return (B_TRUE);
	}

	/*
	 * MSRIndex and MSRvalue comes as either "0" or "0x00".
	 */
	if ((strcmp(msridx, "0") != 0 && strcmp(msridx, "0x00") != 0) ||
	    (strcmp(msrval, "0") != 0 && strcmp(msridx, "0x00") != 0) ||
	    strcmp(offcore, "0") != 0 || strchr(ecode, ',') != NULL ||
	    strchr(umask, ',') != NULL) {
		return (B_TRUE);
	}

	/*
	 * Unfortunately, not everything actually has "TakenAlone". If it
	 * doesn't, we assume that it doesn't have to be.
	 */
	if (nvlist_lookup_string(nvl, "TakenAlone", &taken) == 0 &&
	    strcmp(taken, "0") != 0) {
		return (B_TRUE);
	}


	if (strncasecmp(counter, "fixed", strlen("fixed")) == 0)
		return (B_TRUE);

	return (B_FALSE);
}
static char *
cpcgen_manual_amd_name(cpc_map_t *map)
{
	char *name;

	if (asprintf(&name, "amd_%s_events.3cpc", map->cmap_name) == -1) {
		warn("failed to assemble file name for %s", map->cmap_path);
		return (NULL);
	}

	return (name);
}

static boolean_t
cpcgen_manual_amd_file_before(FILE *f, cpc_map_t *map)
{
	size_t i;
	char *upper;
	const char *family;

	if ((upper = strdup(map->cmap_name)) == NULL) {
		warn("failed to duplicate manual name for %s", map->cmap_name);
		return (B_FALSE);
	}

	for (i = 0; upper[i] != '\0'; i++) {
		upper[i] = toupper(upper[i]);
	}

	family = map->cmap_name + 1;

	if (fprintf(f, cpcgen_manual_amd_header, map->cmap_path, upper,
	    family, family, family) == -1) {
		warn("failed to write out manual header for %s",
		    map->cmap_name);
		free(upper);
		return (B_FALSE);
	}

	free(upper);
	return (B_TRUE);
}

static boolean_t
cpcgen_manual_amd_file_after(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_manual_amd_trailer) == -1) {
		warn("failed to write out manual header for %s",
		    map->cmap_name);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_manual_amd_event(FILE *f, nvlist_t *nvl, const char *path, uint32_t ent)
{
	char *name, *mnemonic = NULL, *summary = NULL, *desc = NULL;
	char *umode;
	nvlist_t *units = NULL;
	uint32_t i, length;

	if (nvlist_lookup_string(nvl, "name", &name) != 0) {
		warnx("Found event without 'name' property in %s, entry %u",
		    path, ent);
		return (B_FALSE);
	}

	if (nvlist_lookup_string(nvl, "mnemonic", &mnemonic) != 0 ||
	    nvlist_lookup_string(nvl, "summary", &summary) != 0) {
		warnx("event %s in %s, entry %u, missing required fields",
		    name, path, ent);
		return (B_FALSE);
	}

	/*
	 * Allow the other fields to be missing.
	 */
	(void) nvlist_lookup_string(nvl, "description", &desc);
	(void) nvlist_lookup_nvlist(nvl, "units", &units);

	if (fprintf(f, ".It Sy %s\n", name) == -1) {
		warn("failed to write out event entry %s", name);
	}

	if (fprintf(f, ".Sy %s -\n"
	    "%s\n", mnemonic, summary) == -1) {
		warn("failed to write out event entry %s", name);
		return (B_FALSE);
	}

	if (desc != NULL) {
		if (fprintf(f, ".Pp\n%s\n", desc) == -1) {
			warn("failed to write out event entry %s", name);
			return (B_FALSE);
		}
	}

	if (units == NULL)
		return (B_TRUE);

	/*
	 * Skip units we don't know how to handle.
	 */
	if (nvlist_lookup_string(nvl, "unit_mode", &umode) == 0) {
		return (B_TRUE);
	}

	if (fprintf(f, ".Pp\n"
	    "This event has the following units which may be used\n"
	    "to modify the behavior of the event:\n"
	    ".Bl -tag -width Sy\n") == -1) {
		warn("failed to write out event entry %s", name);
		return (B_FALSE);
	}

	if (nvlist_lookup_uint32(units, "length", &length) != 0) {
		warnx("found units array, but could not look up length "
		    "property for events %s (index %u) in file %s",
		    name, ent, path);
		return (B_FALSE);
	}

	for (i = 0; i < length; i++) {
		nvlist_t *uvl;
		char num[64];
		char *uname, *udesc = NULL;

		(void) snprintf(num, sizeof (num), "%u", i);
		if (nvlist_lookup_nvlist(units, num, &uvl) != 0) {
			warnx("failed to look up unit %u for event %s (index "
			    "%u) in file %s", i, name, ent, path);
			return (B_FALSE);
		}

		if (nvlist_lookup_string(uvl, "name", &uname) != 0) {
			warnx("failed to find required members for unit array "
			    "entry %u of event %s (index %u) from file %s",
			    i, name, ent, path);
			return (B_FALSE);
		}
		(void) nvlist_lookup_string(uvl, "description", &udesc);
		if (fprintf(f, ".It Sy %s\n", uname) == -1) {
			warn("failed to write out event entry %s", name);
			return (B_FALSE);
		}

		if (udesc != NULL) {
			if (fprintf(f, "%s\n", udesc) == -1) {
				warn("failed to write out event entry %s",
				    name);
				return (B_FALSE);
			}
		}
	}

	if (fprintf(f, ".El\n") == -1) {
		warn("failed to write out event entry %s",
		    name);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static char *
cpcgen_cfile_amd_name(cpc_map_t *map)
{
	char *name;

	if (asprintf(&name, "opteron_pcbe_%s.c", map->cmap_name) == -1) {
		warn("failed to assemble file name for %s", map->cmap_path);
		return (NULL);
	}

	return (name);
}

/*
 * Generate a header file that can be used to synthesize the data events we care
 * about.
 */
static void
cpcgen_common_amd_files(int dirfd)
{
	const char *fname = "opteron_pcbe_cpcgen.h";
	char *tmpname;
	int fd;
	FILE *f;
	cpc_map_t *map;

	if (asprintf(&tmpname, ".%s.%d", fname, getpid()) == -1) {
		err(EXIT_FAILURE, "failed to construct temporary file name");
	}

	if ((fd = openat(dirfd, tmpname, O_RDWR | O_CREAT, 0644)) < 0) {
		err(EXIT_FAILURE, "failed to create temporary file %s",
		    tmpname);
	}

	if ((f = fdopen(fd, "w")) == NULL) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to fdopen temporary file");
	}

	if (fprintf(f, cpcgen_cfile_cddl_header) == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	if (fprintf(f, "#ifndef _OPTERON_PCBE_CPCGEN_H\n"
	    "#define\t_OPTERON_PCBE_CPCGEN_H\n"
	    "\n"
	    "#ifdef __cplusplus\n"
	    "extern \"C\" {\n"
	    "#endif\n"
	    "\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}

	for (map = cpcgen_maps; map != NULL; map = map->cmap_next) {
		if (fprintf(f, "extern const amd_event_t "
		    "opteron_pcbe_%s_events[];\n", map->cmap_name) == -1) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			err(EXIT_FAILURE, "failed to write header to "
			    "temporary file for %s", fname);
		}
	}

	if (fprintf(f, "\n"
	    "#ifdef __cplusplus\n"
	    "}\n"
	    "#endif\n"
	    "\n"
	    "#endif /* _OPTERON_PCBE_CPCGEN_H */\n") == -1) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to write header to "
		    "temporary file for %s", fname);
	}



	if (fflush(f) != 0 || fclose(f) != 0) {
		cpcgen_remove_tmpfile(dirfd, tmpname);
		err(EXIT_FAILURE, "failed to flush and close temporary file");
	}

	if (renameat(dirfd, tmpname, dirfd, fname) != 0) {
		err(EXIT_FAILURE, "failed to rename temporary file %s",
		    tmpname);
	}

	free(tmpname);
}

static boolean_t
cpcgen_cfile_amd_before(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_cfile_amd_header, map->cmap_name) == -1) {
		warn("failed to write header to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}

	if (fprintf(f, cpcgen_cfile_amd_table_start, map->cmap_name) == -1) {
		warn("failed to write header to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}


	return (B_TRUE);
}

static boolean_t
cpcgen_cfile_amd_after(FILE *f, cpc_map_t *map)
{
	if (fprintf(f, cpcgen_cfile_amd_table_end) == -1) {
		warn("failed to write footer to temporary file for %s",
		    map->cmap_path);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
cpcgen_cfile_amd_event(FILE *f, nvlist_t *nvl, const char *path, uint_t ent)
{
	char *name, *code, *umode;
	uint32_t i, length;
	nvlist_t *units;

	if (nvlist_lookup_string(nvl, "name", &name) != 0) {
		warnx("Found event without 'name' property in %s, entry %u",
		    path, ent);
		return (B_FALSE);
	}

	if (nvlist_lookup_string(nvl, "code", &code) != 0) {
		warnx("event %s (index %u) from %s missing required properties "
		    "for C translation", name, path, ent);
		return (B_FALSE);
	}

	if (fprintf(f, "\t{ \"%s\", %s, 0 },\n", name, code) == -1) {
		warn("failed to write out entry %s from %s", name, path);
		return (B_FALSE);
	}

	/*
	 * The 'units' array is optional. If the rule has a specific 'unit_mode'
	 * indicating how the units should be combined, skip that. We don't know
	 * how to properly process that right now.
	 */
	if (nvlist_lookup_nvlist(nvl, "units", &units) != 0) {
		return (B_TRUE);
	}

	if (nvlist_lookup_string(nvl, "unit_mode", &umode) == 0) {
		return (B_TRUE);
	}

	if (nvlist_lookup_uint32(units, "length", &length) != 0) {
		warnx("found units array, but could not look up length "
		    "property for events %s (index %u) in file %s",
		    name, ent, path);
		return (B_FALSE);
	}

	for (i = 0; i < length; i++) {
		nvlist_t *uvl;
		char num[64];
		char *uname, *urw;
		int32_t bit;

		(void) snprintf(num, sizeof (num), "%u", i);
		if (nvlist_lookup_nvlist(units, num, &uvl) != 0) {
			warnx("failed to look up unit %u for event %s (index "
			    "%u) in file %s", i, name, ent, path);
			return (B_FALSE);
		}

		if (nvlist_lookup_string(uvl, "name", &uname) != 0 ||
		    nvlist_lookup_string(uvl, "rw", &urw) != 0 ||
		    nvlist_lookup_int32(uvl, "bit", &bit) != 0) {
			warnx("failed to find required members for unit array "
			    "entry %u of event %s (index %u) from file %s",
			    i, name, ent, path);
			dump_nvlist(uvl, 0);
			return (B_FALSE);
		}

		if (bit < 0 || bit > 31) {
			warnx("event %s (index %u) from file %s has invalid "
			    "bit value: %d; skipping", name, ent, path, bit);
			continue;
		}

		if (strcasecmp(urw, "Read-write") != 0)
			continue;

		if (fprintf(f, "\t{ \"%s.%s\", %s, 0x%x },\n", name, uname,
		    code, 1U << bit) == -1) {
			warn("failed to write out entry %s from %s", name,
			    path);
			return (B_FALSE);
		}
	}

	return (B_TRUE);
}

/*
 * For each processor family, generate a data file that contains all of the
 * events that we support. Also generate a header that can be included that
 * declares all of the tables.
 */
static void
cpcgen_gen(int dirfd)
{
	cpc_map_t *map = cpcgen_maps;

	if (map == NULL) {
		errx(EXIT_FAILURE, "no platforms found or matched");
	}

	for (map = cpcgen_maps; map != NULL; map = map->cmap_next) {
		int fd, ret;
		FILE *f;
		char *tmpname, *name;
		uint32_t length, i;

		if ((name = cpcgen_ops.cgen_op_name(map)) == NULL) {
			exit(EXIT_FAILURE);
		}

		if (asprintf(&tmpname, ".%s.%d", name, getpid()) == -1) {
			err(EXIT_FAILURE, "failed to construct temporary file "
			    "name");
		}

		if ((fd = openat(dirfd, tmpname, O_RDWR | O_CREAT, 0644)) < 0) {
			err(EXIT_FAILURE, "failed to create temporary file %s",
			    tmpname);
		}

		if ((f = fdopen(fd, "w")) == NULL) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			err(EXIT_FAILURE, "failed to fdopen temporary file");
		}

		if (!cpcgen_ops.cgen_op_file_before(f, map)) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			exit(EXIT_FAILURE);
		}

		/*
		 * Iterate over array contents.
		 */
		if ((ret = nvlist_lookup_uint32(map->cmap_data, "length",
		    &length)) != 0) {
			errx(EXIT_FAILURE, "failed to look up length property "
			    "in parsed data for %s: %s", map->cmap_path,
			    strerror(ret));
		}

		for (i = 0; i < length; i++) {
			nvlist_t *nvl;
			char num[64];

			(void) snprintf(num, sizeof (num), "%u", i);
			if ((ret = nvlist_lookup_nvlist(map->cmap_data,
			    num, &nvl)) != 0) {
				cpcgen_remove_tmpfile(dirfd, tmpname);
				errx(EXIT_FAILURE, "failed to look up array "
				    "entry %u in parsed data for %s: %s", i,
				    map->cmap_path, strerror(ret));
			}

			if (cpcgen_ops.cgen_op_skip != NULL &&
			    cpcgen_ops.cgen_op_skip(nvl, map->cmap_path, i)) {
				continue;
			}

			if (!cpcgen_ops.cgen_op_event(f, nvl, map->cmap_path,
			    i)) {
				cpcgen_remove_tmpfile(dirfd, tmpname);
				exit(EXIT_FAILURE);
			}
		}

		if (!cpcgen_ops.cgen_op_file_after(f, map)) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			exit(EXIT_FAILURE);
		}

		if (fflush(f) != 0 || fclose(f) != 0) {
			cpcgen_remove_tmpfile(dirfd, tmpname);
			err(EXIT_FAILURE, "failed to flush and close "
			    "temporary file");
		}

		if (renameat(dirfd, tmpname, dirfd, name) != 0) {
			err(EXIT_FAILURE, "failed to rename temporary file %s",
			    tmpname);
		}

		free(name);
		free(tmpname);
	}
}

static void
cpcgen_usage(const char *fmt, ...)
{
	if (fmt != NULL) {
		va_list ap;

		(void) fprintf(stderr, "%s: ", cpcgen_progname);
		va_start(ap, fmt);
		(void) vfprintf(stderr, fmt, ap);
		va_end(ap);
	}

	(void) fprintf(stderr, "Usage: %s -a|-p platform -c|-H|-m -d datadir "
	    "-o outdir\n"
	    "\n"
	    "\t-a  generate data for all platforms\n"
	    "\t-c  generate C file for CPC\n"
	    "\t-d  specify the directory containt perfmon data\n"
	    "\t-H  generate header file and common files\n"
	    "\t-m  generate manual pages for CPC data\n"
	    "\t-o  output files in directory outdir\n"
	    "\t-p  generate data for a specified platform\n",
	    cpcgen_progname);
}

int
main(int argc, char *argv[])
{
	int c, outdirfd;
	boolean_t do_mpage = B_FALSE, do_cfile = B_FALSE, do_header = B_FALSE,
	    do_all = B_FALSE;
	const char *datadir = NULL, *outdir = NULL, *platform = NULL;
	uint_t count = 0;

	cpcgen_progname = basename(argv[0]);

	while ((c = getopt(argc, argv, ":acd:hHmo:p:")) != -1) {
		switch (c) {
		case 'a':
			do_all = B_TRUE;
			break;
		case 'c':
			do_cfile = B_TRUE;
			break;
		case 'd':
			datadir = optarg;
			break;
		case 'm':
			do_mpage = B_TRUE;
			break;
		case 'H':
			do_header = B_TRUE;
			break;
		case 'o':
			outdir = optarg;
			break;
		case 'p':
			platform = optarg;
			break;
		case ':':
			cpcgen_usage("Option -%c requires an operand\n",
			    optopt);
			return (2);
		case '?':
			cpcgen_usage("Unknown option: -%c\n", optopt);
			return (2);
		case 'h':
		default:
			cpcgen_usage(NULL);
			return (2);
		}
	}

	count = 0;
	if (do_mpage)
		count++;
	if (do_cfile)
		count++;
	if (do_header)
		count++;
	if (count > 1) {
		cpcgen_usage("Only one of -c, -h, and -m may be specified\n");
		return (2);
	} else if (count == 0) {
		cpcgen_usage("One of -c, -h, and -m is required\n");
		return (2);
	}

	count = 0;
	if (do_all)
		count++;
	if (platform != NULL)
		count++;
	if (count > 1) {
		cpcgen_usage("Only one of -a and -p may be specified\n");
		return (2);
	} else if (count == 0) {
		cpcgen_usage("One of -a and -p is required\n");
		return (2);
	}

	if (outdir == NULL) {
		cpcgen_usage("Missing required output directory (-o)\n");
		return (2);
	}

	if ((outdirfd = open(outdir, O_RDONLY)) < 0) {
		err(EXIT_FAILURE, "failed to open output directory %s", outdir);
	}

	if (datadir == NULL) {
		cpcgen_usage("Missing required data directory (-d)\n");
		return (2);
	}

	cpcgen_determine_vendor(datadir);

	switch (cpcgen_mode) {
	case CPCGEN_MODE_INTEL:
		cpcgen_ops.cgen_op_gather = cpcgen_read_intel;
		cpcgen_ops.cgen_op_common = cpcgen_common_intel_files;
		cpcgen_ops.cgen_op_skip = cpcgen_skip_intel_entry;
		if (do_mpage) {
			cpcgen_ops.cgen_op_name = cpcgen_manual_intel_name;
			cpcgen_ops.cgen_op_file_before =
			    cpcgen_manual_intel_file_before;
			cpcgen_ops.cgen_op_file_after =
			    cpcgen_manual_intel_file_after;
			cpcgen_ops.cgen_op_event = cpcgen_manual_intel_event;
		} else {
			cpcgen_ops.cgen_op_name = cpcgen_cfile_intel_name;
			cpcgen_ops.cgen_op_file_before =
			    cpcgen_cfile_intel_before;
			cpcgen_ops.cgen_op_file_after =
			    cpcgen_cfile_intel_after;
			cpcgen_ops.cgen_op_event = cpcgen_cfile_intel_event;
		}
		break;
	case CPCGEN_MODE_AMD:
		cpcgen_ops.cgen_op_gather = cpcgen_read_amd;
		cpcgen_ops.cgen_op_common = cpcgen_common_amd_files;
		cpcgen_ops.cgen_op_skip = NULL;
		if (do_mpage) {
			cpcgen_ops.cgen_op_name = cpcgen_manual_amd_name;
			cpcgen_ops.cgen_op_file_before =
			    cpcgen_manual_amd_file_before;
			cpcgen_ops.cgen_op_file_after =
			    cpcgen_manual_amd_file_after;
			cpcgen_ops.cgen_op_event = cpcgen_manual_amd_event;
		} else {
			cpcgen_ops.cgen_op_name = cpcgen_cfile_amd_name;
			cpcgen_ops.cgen_op_file_before =
			    cpcgen_cfile_amd_before;
			cpcgen_ops.cgen_op_file_after = cpcgen_cfile_amd_after;
			cpcgen_ops.cgen_op_event = cpcgen_cfile_amd_event;

		}
		break;
	default:
		errx(EXIT_FAILURE, "failed to determine if operating on AMD or "
		    "Intel");
		break;
	}

	cpcgen_ops.cgen_op_gather(datadir, platform);

	if (do_header) {
		cpcgen_ops.cgen_op_common(outdirfd);
		return (0);
	}

	cpcgen_gen(outdirfd);

	return (0);
}
