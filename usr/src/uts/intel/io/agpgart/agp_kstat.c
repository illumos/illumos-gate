/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/kstat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/agpgart.h>
#include <sys/agp/agpdefs.h>
#include <sys/agp/agpgart_impl.h>

/*
 * The values of type agp_arc_type_t are used as indices into arc_name
 * So if agp_arc_type_t's values are changed in the future, the content
 * of arc_name must be changed accordingly.
 */
static const char *arc_name[] = {
	"IGD_810",
	"IGD_830",
	"INTEL_AGP",
	"AMD64_AGP",
	"AMD64_NONAGP",
	"UNKNOWN"
};

static char *agpkstat_name[] = {
	"&arc_type",
	"master_dev_id",
	"master_dev_version",
	"master_dev_status",
	"$prealloc_size",
	"target_dev_id",
	"target_dev_version",
	"target_dev_status",
	"$aper_base",
	"$aper_size",
	"&agp_enabled",
	"agp_mode_set",
	"$aper_used",
	NULL
};

static void
agp_set_char_kstat(kstat_named_t *knp, const char *s)
{
	(void) strlcpy(knp->value.c, s, sizeof (knp->value.c));
}

static int
agp_kstat_update(kstat_t *ksp, int flag)
{
	agpgart_softstate_t *sc;
	kstat_named_t *knp;
	int tmp;

	if (flag != KSTAT_READ)
		return (EACCES);

	sc = ksp->ks_private;
	knp = ksp->ks_data;

	agp_set_char_kstat(knp++, arc_name[sc->asoft_devreg.agprd_arctype]);
	(knp++)->value.ui32 = sc->asoft_info.agpki_mdevid;
	(knp++)->value.ui32 = (sc->asoft_info.agpki_mver.agpv_major<<16) |
	    sc->asoft_info.agpki_mver.agpv_minor;
	(knp++)->value.ui32 = sc->asoft_info.agpki_mstatus;
	(knp++)->value.ui64 = (sc->asoft_info.agpki_presize << 10) & UI32_MASK;
	(knp++)->value.ui32 = sc->asoft_info.agpki_tdevid;
	(knp++)->value.ui32 = (sc->asoft_info.agpki_tver.agpv_major<<16) |
	    sc->asoft_info.agpki_tver.agpv_minor;
	(knp++)->value.ui32 = sc->asoft_info.agpki_tstatus;
	(knp++)->value.ui64 = sc->asoft_info.agpki_aperbase;
	(knp++)->value.ui64 =
	    (sc->asoft_info.agpki_apersize << 20) & UI32_MASK;

	tmp = sc->asoft_agpen;
	agp_set_char_kstat(knp++, (tmp > 0) ? "yes" : "no");

	(knp++)->value.ui32 = sc->asoft_mode;
	(knp++)->value.ui64 = (sc->asoft_pgused << 12) & UI32_MASK;

	return (0);
}

int
agp_init_kstats(agpgart_softstate_t *sc)
{
	int instance;
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;
	char **aknp;

	instance = ddi_get_instance(sc->asoft_dip);
	aknp = agpkstat_name;
	ksp = kstat_create(AGPGART_DEVNODE, instance, "agpinfo", "agp",
	    KSTAT_TYPE_NAMED, sizeof (agpkstat_name)/sizeof (char *) - 1,
	    KSTAT_FLAG_PERSISTENT);
	if (ksp == NULL)
		return (1);

	ksp->ks_private = sc;
	ksp->ks_update = agp_kstat_update;
	for (knp = ksp->ks_data; (np = (*aknp)) != NULL; knp++, aknp++) {
		switch (*np) {
		case '$':
			np += 1;
			type = KSTAT_DATA_UINT64;
			break;
		case '&':
			np += 1;
			type = KSTAT_DATA_CHAR;
			break;
		default:
			type = KSTAT_DATA_UINT32;
			break;

		}
		kstat_named_init(knp, np, type);
	}
	kstat_install(ksp);

	sc->asoft_ksp = ksp;

	return (0);
}

void
agp_fini_kstats(agpgart_softstate_t *sc)
{
	ASSERT(sc->asoft_ksp);
	kstat_delete(sc->asoft_ksp);
}
