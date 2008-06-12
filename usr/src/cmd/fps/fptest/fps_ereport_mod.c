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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <kstat.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/types.h>
#include <sys/processor.h>
#include <unistd.h>
#include <fp.h>
#include <fps_defines.h>
#include <fps_ereport.h>
#include <fpst-defines.h>

#define	CLASS_HEAD "ereport.cpu"
#define	CLASS_TAIL "fpu.fpscrub"

/* nvlist */
static nvlist_t *fps_nvlist_create();

/* ereport piece generators */
static int fps_fmri_cpu_set(nvlist_t *fmri_cpu, uint32_t cpu_id);
static int fps_fmri_svc_set(nvlist_t *fmri_svc, const char *svc_fmri);
static int fps_post_ereport(nvlist_t *ereport);
static uint64_t fps_ena_generate(uint64_t timestamp, uint32_t cpuid,
		uchar_t format);

/* cpu check and name convert */
static char *fps_get_cpu_brand(uint32_t cpu_id);
static char *fps_convert_cpu_brand(char *brand);

/* ereport struct functions */
int fps_generate_ereport_struct(struct fps_test_ereport *report);
void setup_fps_test_struct(int mask, struct fps_test_ereport *rep, ...);
void initialize_fps_test_struct(struct fps_test_ereport *init_me);

/*
 * fps_nvlist_create() allocates the memory for an
 * nvlist.
 */
static nvlist_t *
fps_nvlist_create()
{
	int nr_malloc;
	nvlist_t *nvl;
	struct timeval timeout;

	timeout.tv_sec = 0;
	timeout.tv_usec = 10000;
	nr_malloc = 0;

	nvl = NULL;
	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);

	while (nvl == NULL && nr_malloc < 10) {
		select(1, NULL, NULL, NULL, &timeout);
		nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
		nr_malloc++;
	}

	return (nvl);
}

/*
 * fps_ena_generate(uint64_t timestamp, processorid_t cpuid,
 * uchar_t format)creates the ENA for the ereport.
 */
static uint64_t
fps_ena_generate(uint64_t timestamp, uint32_t cpuid, uchar_t format)
{
	uint64_t ena = 0;

	switch (format) {
	case FM_ENA_FMT1:
		if (timestamp) {
			ena = (uint64_t)((format & ENA_FORMAT_MASK) |
			    ((cpuid << ENA_FMT1_CPUID_SHFT) &
			    ENA_FMT1_CPUID_MASK) |
			    ((timestamp << ENA_FMT1_TIME_SHFT) &
			    ENA_FMT1_TIME_MASK));
		} else {
			ena = (uint64_t)((format & ENA_FORMAT_MASK) |
			    ((cpuid << ENA_FMT1_CPUID_SHFT) &
			    ENA_FMT1_CPUID_MASK) |
			    ((gethrtime() << ENA_FMT1_TIME_SHFT) &
			    ENA_FMT1_TIME_MASK));
		}
		break;
	case FM_ENA_FMT2:
		ena = (uint64_t)((format & ENA_FORMAT_MASK) |
		    ((timestamp << ENA_FMT2_TIME_SHFT) & ENA_FMT2_TIME_MASK));
		break;
	default:
		break;
	}

	return (ena);
}

/*
 * fps_fmri_svc_set(nvlist_t *fmri_svc, const char *svc_fmri)
 * adds the detector data to fmri_svc.
 */
static int
fps_fmri_svc_set(nvlist_t *fmri_svc, const char *svc_fmri)
{
	if (fmri_svc == NULL)
		return (1);

	if (svc_fmri == NULL)
		return (1);

	if (nvlist_add_uint8(fmri_svc, FM_FMRI_SVC_VERSION, 1) != 0)
		return (1);

	if (nvlist_add_string(fmri_svc, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_SVC) != 0)
		return (1);

	if (nvlist_add_string(fmri_svc, FM_FMRI_SVC_NAME,
	    svc_fmri) != 0)
		return (1);

	return (0);
}

/*
 * fps_fmri_cpu_set(nvlist_t *fmri_cpu, uint32_t cpu_id)
 * adds the resource data to fmri_cpu.
 */
static int
fps_fmri_cpu_set(nvlist_t *fmri_cpu, uint32_t cpu_id)
{
	if (fmri_cpu == NULL)
		return (1);

	if (nvlist_add_uint8(fmri_cpu, FM_VERSION,
	    FM_CPU_SCHEME_VERSION) != 0)
		return (1);

	if (nvlist_add_string(fmri_cpu, FM_FMRI_SCHEME,
	    FM_FMRI_SCHEME_CPU) != 0)
		return (1);

	if (nvlist_add_uint32(fmri_cpu, FM_FMRI_CPU_ID, cpu_id) != 0)
		return (1);
	return (0);
}

/*
 * fps_post_ereport(nvlist_t *ereport) posts an
 * ereport to the sysevent error channel.  The error
 * channel is assumed to be established by fps-transport.so.
 */
static int
fps_post_ereport(nvlist_t *ereport)
{
	evchan_t *scp;

	if (sysevent_evc_bind(CHANNEL, &scp, BIND_FLAGS) != 0) {
		return (1);
	}

	if (sysevent_evc_publish(scp, CLASS, SUBCLASS, VENDOR,
	    PUBLISHER, ereport, EVCH_NOSLEEP) != 0) {
		return (1);
	}

	(void) sleep(1);

	fflush(NULL);
	sysevent_evc_unbind(scp);

	return (0);
}
/*
 * fps_convert_cpu_brand(char *brand) changes
 * the kstat data to match the ereport class
 * names.
 */
static char *
fps_convert_cpu_brand(char *brand)
{
	if (brand == NULL)
		return (NULL);

	if (strcasecmp(brand, USIII_KSTAT) == 0)
		return (USIII);
	else if (strcasecmp(brand, USIIIi_KSTAT) == 0)
		return (USIIIi);
	else if (strcasecmp(brand, USIIIP_KSTAT) == 0)
		return (USIIIP);
	else if (strcasecmp(brand, USIV_KSTAT) == 0)
		return (USIV);
	else if (strcasecmp(brand, USIVP_KSTAT) == 0)
		return (USIVP);
	else
		return (NULL);
}

/*
 * get_cpu_brand(uint32_t cpu_id)gets the
 * brand of the CPU and returns the CPU
 * name to use in the ereport class name.
 */
static char *
fps_get_cpu_brand(uint32_t cpu_id)
{
	char *brand;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	kstat_named_t *knp;

	kc = kstat_open();
	if (kc == NULL) {
		return (NULL);
	}

	/* LINTED */
	if ((ksp = kstat_lookup(kc, "cpu_info", (int)cpu_id, NULL)) == NULL) {
		kstat_close(kc);
		return (NULL);
	}

	if ((kstat_read(kc, ksp, NULL)) == -1) {
		kstat_close(kc);
		return (NULL);
	}

	if ((knp = kstat_data_lookup(ksp, "brand")) == NULL) {
		kstat_close(kc);
		return (NULL);
	}

	brand = fps_convert_cpu_brand(KSTAT_NAMED_STR_PTR(knp));
	kstat_close(kc);

	if (brand == NULL)
		return (NULL);

	return (brand);
}

/*
 * fps_generate_ereport_struct(struct fps_test_ereport *report)
 * takes report and constructs an nvlist that will be used
 * for the ereport.
 */
int
fps_generate_ereport_struct(struct fps_test_ereport *report)
{
	char class_name[FM_MAX_CLASS];
	char *cpu_brand;
	char *string_data;
	int detector_available;
	int expect_size;
	int is_valid_cpu;
	int mask;
	int observe_size;
	int ret;
	nvlist_t *detector;
	nvlist_t *ereport;
	nvlist_t *resource;
	uint32_t cpu_id;
	uint32_t test;
	uint8_t fps_ver;
	uint64_t ena;
	uint64_t ereport_time;
	uint64_t *expect;
	uint64_t *observe;

	if (report == NULL)
		return (FPU_EREPORT_FAIL);

	ret = FPU_FOROFFLINE;
	cpu_id = report->cpu_id;
	test = report->test_id;
	mask = report->mask;
	is_valid_cpu = report->is_valid_cpu;
	expect_size = report->expected_size;
	expect = report->expected;
	observe_size = report->observed_size;
	observe = report->observed;
	string_data = report->info;
	detector_available = 1;

	/* allocate nvlists */
	if ((ereport = fps_nvlist_create()) == NULL)
		_exit(FPU_EREPORT_FAIL);

	if ((detector = fps_nvlist_create()) == NULL) {
		detector_available = 0;
		ret = FPU_EREPORT_INCOM;
	}

	/* setup class */
	if ((cpu_brand = fps_get_cpu_brand(cpu_id)) == NULL)
		_exit(FPU_EREPORT_FAIL);

	if ((snprintf(class_name, FM_MAX_CLASS, "%s.%s.%s",
	    CLASS_HEAD, cpu_brand, CLASS_TAIL)) < 0)
		_exit(FPU_EREPORT_FAIL);

	/* setup ena */
	ereport_time = gethrtime();
	ena = fps_ena_generate(ereport_time, cpu_id, FM_ENA_FMT1);

	/* setup detector */
	if (fps_fmri_svc_set(detector, getenv("SMF_FMRI")) != 0) {
		detector_available = 0;
		ret = FPU_EREPORT_INCOM;
	}

	/* setup fps-version */
	fps_ver = FPS_VERSION;

	/* setup resource */
	if (is_valid_cpu) {
		resource = fps_nvlist_create();

		if (fps_fmri_cpu_set(resource, cpu_id)) {
			_exit(FPU_EREPORT_FAIL);
		}
	} else {
		resource = NULL;
	}

	/* put it together */
	if (nvlist_add_string(ereport, NAME_FPS_CLASS, class_name) != 0)
		_exit(FPU_EREPORT_FAIL);

	if (ena != 0) {
		if (nvlist_add_uint64(ereport, NAME_FPS_ENA, ena) != 0)
			ret = FPU_EREPORT_INCOM;
	} else
		ret = FPU_EREPORT_INCOM;

	if (detector_available) {
		if (nvlist_add_nvlist(ereport, NAME_FPS_DETECTOR,
		    (nvlist_t *)detector) != 0)
			ret = FPU_EREPORT_INCOM;
	}

	if (nvlist_add_uint8(ereport, NAME_FPS_VERSION, fps_ver) != 0)
		_exit(FPU_EREPORT_FAIL);

	if (nvlist_add_uint32(ereport, NAME_FPS_TEST_ID, test) != 0)
		_exit(FPU_EREPORT_FAIL);

	if (nvlist_add_uint64_array(ereport, NAME_FPS_EXPECTED_VALUE,
	    expect, expect_size) != 0)
		ret = FPU_EREPORT_INCOM;

	if (nvlist_add_uint64_array(ereport, NAME_FPS_OBSERVED_VALUE,
	    observe, observe_size) != 0)
		ret = FPU_EREPORT_INCOM;

	if (mask & IS_EREPORT_INFO) {
		if (nvlist_add_string(ereport, NAME_FPS_STRING_DATA,
		    string_data) != 0)
			ret = FPU_EREPORT_INCOM;
	}

	if (is_valid_cpu) {
		if (nvlist_add_nvlist(ereport, NAME_FPS_RESOURCE,
		    (nvlist_t *)resource) != 0)
			_exit(FPU_EREPORT_FAIL);
	}

	/* publish */
	if (fps_post_ereport(ereport)) {
		_exit(FPU_EREPORT_FAIL);
	}

	/* free nvlists */
	nvlist_free(ereport);

	if (resource != NULL)
		nvlist_free(resource);

	if (detector != NULL)
		nvlist_free(detector);

	return (ret);
}

/*
 * initialize_fps_test_struct(struct fps_test_ereport *init_me)
 * creates the initial values for the init_me.
 */
void
initialize_fps_test_struct(struct fps_test_ereport *init_me)
{
	if (init_me == NULL)
		return;

	init_me->cpu_id = 0;
	init_me->test_id = 0;
	init_me->observed_size = 0;
	init_me->expected_size = 0;
	init_me->is_valid_cpu = 1;
	init_me->info[0] = '\0';
	init_me->mask = NO_EREPORT_INFO;
}

/*
 * setup_fps_test_struct(int mask, struct fps_test_ereport *rep,
 * ...) takes a variable amount of input and stores it in rep
 * based on mask provided.
 */
void
setup_fps_test_struct(int mask, struct fps_test_ereport *rep, ...)
{
	char *data;
	int i;
	uint64_t *exp_arg;
	uint64_t *obs_arg;
	va_list argptr;

	if (rep == NULL)
		return;

	/* begin parsing args */
	va_start(argptr, rep);

	/* test id */
	rep->test_id = va_arg(argptr, int);

	/* observed */
	obs_arg = va_arg(argptr, uint64_t *);

	/* expected */
	exp_arg = va_arg(argptr, uint64_t *);

	/* observed size */
	rep->observed_size = va_arg(argptr, int);

	/* expected size */
	rep->expected_size = va_arg(argptr, int);

	/* copy arrays of observed and expected */
	if (rep->observed_size < 1 || rep->expected_size < 1)
		return;

	if (obs_arg == NULL || exp_arg == NULL)
		return;

	for (i = 0; i < rep->observed_size; i++)
		rep->observed[i] = obs_arg[i];

	for (i = 0; i < rep->expected_size; i++)
		rep->expected[i] = exp_arg[i];

	rep->mask = mask;

	/* copy string data if there */
	if (mask & IS_EREPORT_INFO)	{
		data = va_arg(argptr, char *);

		if (data == NULL) {
			va_end(argptr);

			return;
		}

		strlcpy(rep->info, data, MAX_INFO_SIZE-1);
	}

	va_end(argptr);
}
