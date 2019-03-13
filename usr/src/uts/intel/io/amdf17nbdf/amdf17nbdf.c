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
 * Copyright 2019, Joyent, Inc.
 */

/*
 * AMD Family 17 Northbridge and Data Fabric Driver
 *
 * This driver attaches to the AMD Family 17h northbridge and data fabric bus.
 * Each Zeppelin die ('processor node' in cpuid.c parlance) has its own
 * northbridge and access to the data fabric bus. The northbridge and data
 * fabric both provide access to various features such as:
 *
 *  - The System Management Network (SMN)
 *  - Data Fabric via Fabric Indirect Config Access (FICAA)
 *
 * These are required to access things such as temperature sensors or memory
 * controller configuration registers.
 *
 * In AMD Family 17h systems, the 'northbridge' is an ASIC that is part of the
 * package that contains many I/O capabilities related to things like PCI
 * express, etc. The 'data fabric' is the means by which different components
 * both inside the socket and multiple sockets are connected together. Both the
 * northbridge and the data fabric have dedicated PCI devices which the
 * operating system can use to interact with them.
 *
 * ------------------------
 * Mapping Devices Together
 * ------------------------
 *
 * The operating system needs to expose things like temperature sensors and DRAM
 * configuration registers in terms that are meaningful to the system such as
 * logical CPUs, cores, etc. This driver attaches to the PCI IDs that represent
 * the northbridge and data fabric; however, there are multiple PCI devices (one
 * per die) that exist. This driver does manage to map all of these three things
 * together; however, it requires some acrobatics. Unfortunately, there's no
 * direct way to map a northbridge to its corresponding die. However, we can map
 * a CPU die to a data fabric PCI device and a data fabric PCI device to a
 * corresponding northbridge PCI device.
 *
 * In current Zen based products, there is a direct mapping between processor
 * nodes and a data fabric PCI device. All of the devices are on PCI Bus 0 and
 * start from Device 0x18. Device 0x18 maps to processor node 0, 0x19 to
 * processor node 1, etc. This means that to map a logical CPU to a data fabric
 * device, we take its processor node id, add it to 0x18 and find the PCI device
 * that is on bus 0, device 0x18. As each data fabric device is attached based
 * on its PCI ID, we add it to the global list, amd_nbdf_dfs that is in the
 * amd_f17nbdf_t structure.
 *
 * The northbridge PCI device has a defined device and function, but the PCI bus
 * that it's on can vary. Each die has its own series of PCI buses that are
 * assigned to it and the northbridge PCI device is on the first of die-specific
 * PCI bus for each die. This also means that the northbridge will not show up
 * on PCI bus 0, which is the PCI bus that all of the data fabric devices are
 * on. While conventionally the northbridge with the lowest PCI bus value
 * would correspond to processor node zero, hardware does not guarantee that at
 * all. Because we don't want to be at the mercy of firmware, we don't rely on
 * this ordering, even though we have yet to find a system that deviates from
 * this scheme.
 *
 * One of the registers in the data fabric device's function 0
 * (AMDF17_DF_CFG_ADDR_CTL), happens to have the first PCI bus that is
 * associated with the processor node. This means, that we can map a data fabric
 * device to a northbridge by finding the northbridge whose PCI bus matches the
 * value in the corresponding data fabric's AMDF17_DF_CFG_ADDR_CTL.
 *
 * This means that we can map a northbridge to a data fabric device and a data
 * fabric device to a die. Because these are 1:1 mappings, there is a transitive
 * relationship and therefore we know which northbridge is associated with which
 * processor die. This is summarized in the following image:
 *
 *  +-------+      +----------------------------+         +--------------+
 *  | Die 0 | ---> | Data Fabric PCI BDF 0/18/0 |-------> | Northbridge  |
 *  +-------+      | AMDF17_DF_CFG_ADDR: bus 10 |         | PCI  10/0/0  |
 *     ...         +----------------------------+         +--------------+
 *  +-------+      +------------------------------+         +--------------+
 *  | Die n | ---> | Data Fabric PCI BDF 0/18+n/0 |-------> | Northbridge  |
 *  +-------+      | AMDF17_DF_CFG_ADDR: bus 133  |         | PCI 133/0/0  |
 *                 +------------------------------+         +--------------+
 *
 * Note, the PCI buses used by the northbridges here are arbitrary. They do not
 * reflect the actual values by hardware; however, the bus/device/function (BDF)
 * of the data fabric accurately models hardware. All of the BDF values are in
 * hex.
 *
 * -------------------------------
 * Attach and Detach Complications
 * -------------------------------
 *
 * Because we need to map different PCI devices together, this means that we
 * have multiple dev_info_t structures that we need to manage. Each of these is
 * independently attached and detached. While this is easily managed for attach,
 * it is not for detach.
 *
 * Once a device has been detached it will only come back if we have an active
 * minor node that will be accessed. While we have minor nodes associated with
 * the northbridges, we don't with the data fabric devices. This means that if
 * they are detached, nothing would ever cause them to be reattached. The system
 * also doesn't provide us a way or any guarantees around making sure that we're
 * attached to all such devices before we detach. As a result, unfortunately,
 * it's easier to basically have detach always fail.
 *
 * To deal with both development and if issues arise in the field, there is a
 * knob, amdf17df_allow_detach, which if set to a non-zero value, will allow
 * instances to detach.
 *
 * ---------------
 * Exposed Devices
 * ---------------
 *
 * Currently we expose a single set of character devices which represent
 * temperature sensors for this family of processors. Because temperature
 * sensors exist on a per-processor node basis, we create a single minor node
 * for each one. Because our naming matches the cpuid naming, FMA can match that
 * up to logical CPUs and take care of matching the sensors appropriately. We
 * internally rate limit the sensor updates to 100ms, which is controlled by the
 * global amdf17nbdf_cache_ms.
 */

#include <sys/modctl.h>
#include <sys/conf.h>
#include <sys/devops.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/open.h>
#include <sys/cred.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/list.h>
#include <sys/pci.h>
#include <sys/stddef.h>
#include <sys/stat.h>
#include <sys/x86_archext.h>
#include <sys/cpuvar.h>
#include <sys/sensors.h>

/*
 * The range of minors that we'll allow.
 */
#define	AMDF17_MINOR_LOW	1
#define	AMDF17_MINOR_HIGH	INT32_MAX

/*
 * This is the value of the first PCI data fabric device that globally exists.
 * It always maps to AMD's first nodeid (what we call cpi_procnodeid).
 */
#define	AMDF17_DF_FIRST_DEVICE	0x18

/*
 * The data fabric devices are defined to always be on PCI bus zero.
 */
#define	AMDF17_DF_BUSNO		0x00

/*
 * This register contains the BUS A of the the processor node that corresponds
 * to the data fabric device.
 */
#define	AMDF17_DF_CFG_ADDR_CTL		0x84
#define	AMDF17_DF_CFG_ADDR_CTL_MASK	0xff

/*
 * Northbridge registers that are related to accessing the SMN. One writes to
 * the SMN address register and then can read from the SMN data register.
 */
#define	AMDF17_NB_SMN_ADDR	0x60
#define	AMDF17_NB_SMN_DATA	0x64

/*
 * The following are register offsets and the meaning of their bits related to
 * temperature. These addresses are addresses in the System Management Network
 * which is accessed through the northbridge.  They are not addresses in PCI
 * configuration space.
 */
#define	AMDF17_SMU_THERMAL_CURTEMP			0x00059800
#define	AMDF17_SMU_THERMAL_CURTEMP_TEMPERATURE(x)	((x) >> 21)
#define	AMDF17_SMU_THERMAL_CURTEMP_RANGE_SEL		(1 << 19)

#define	AMDF17_SMU_THERMAL_CURTEMP_RANGE_ADJ		(-49)
#define	AMDF17_SMU_THERMAL_CURTEMP_DECIMAL_BITS		3
#define	AMDF17_SMU_THERMAL_CURTEMP_BITS_MASK		0x7

/*
 * The temperature sensor in family 17 is measured in terms of 0.125 C steps.
 */
#define	AMDF17_THERMAL_GRANULARITY	8

struct amdf17nb;
struct amdf17df;

typedef struct amdf17nb {
	list_node_t		amd_nb_link;
	dev_info_t		*amd_nb_dip;
	ddi_acc_handle_t	amd_nb_cfgspace;
	uint_t			amd_nb_bus;
	uint_t			amd_nb_dev;
	uint_t			amd_nb_func;
	struct amdf17df		*amd_nb_df;
	uint_t			amd_nb_procnodeid;
	id_t			amd_nb_temp_minor;
	hrtime_t		amd_nb_temp_last_read;
	int			amd_nb_temp_off;
	uint32_t		amd_nb_temp_reg;
	/* Values derived from the above */
	int64_t			amd_nb_temp;
} amdf17nb_t;

typedef struct amdf17df {
	list_node_t		amd_df_link;
	dev_info_t		*amd_df_f0_dip;
	ddi_acc_handle_t	amd_df_f0_cfgspace;
	uint_t			amd_df_procnodeid;
	uint_t			amd_df_iobus;
	amdf17nb_t		*amd_df_nb;
} amdf17df_t;

typedef struct amdf17nbdf {
	kmutex_t	amd_nbdf_lock;
	id_space_t	*amd_nbdf_minors;
	list_t		amd_nbdf_nbs;
	list_t		amd_nbdf_dfs;
} amdf17nbdf_t;

typedef enum {
	AMD_NBDF_TYPE_UNKNOWN,
	AMD_NBDF_TYPE_NORTHBRIDGE,
	AMD_NBDF_TYPE_DATA_FABRIC
} amdf17nbdf_type_t;

typedef struct {
	uint16_t		amd_nbdft_pci_did;
	amdf17nbdf_type_t	amd_nbdft_type;
} amdf17nbdf_table_t;

static const amdf17nbdf_table_t amdf17nbdf_dev_map[] = {
	/* Family 17h Ryzen, Epyc Models 00h-0fh (Zen uarch) */
	{ 0x1450, AMD_NBDF_TYPE_NORTHBRIDGE },
	{ 0x1460, AMD_NBDF_TYPE_DATA_FABRIC },
	{ PCI_EINVAL16 }
};

typedef struct {
	const char	*amd_nbdfo_brand;
	uint_t		amd_nbdfo_family;
	int		amd_nbdfo_off;
} amdf17nbdf_offset_t;

/*
 * AMD processors report a control temperature (called Tctl) which may be
 * different from the junction temperature, which is the value that is actually
 * measured from the die (sometimes called Tdie or Tjct). This is done so that
 * socket-based environmental monitoring can be consistent from a platform
 * perspective, but doesn't help us. Unfortunately, these values aren't in
 * datasheets that we can find, but have been documented partially in a series
 * of blog posts by AMD when discussing their 'Ryzen Master' monitoring software
 * for Windows.
 *
 * The brand strings below may contain partial matches such in the Threadripper
 * cases so we can match the entire family of processors. The offset value is
 * the quantity in degrees that we should adjust Tctl to reach Tdie.
 */
static const amdf17nbdf_offset_t amdf17nbdf_offsets[] = {
	{ "AMD Ryzen 5 1600X", 0x17, -20 },
	{ "AMD Ryzen 7 1700X", 0x17, -20 },
	{ "AMD Ryzen 7 1800X", 0x17, -20 },
	{ "AMD Ryzen 7 2700X", 0x17, -10 },
	{ "AMD Ryzen Threadripper 19", 0x17, -27 },
	{ "AMD Ryzen Threadripper 29", 0x17, -27 },
	{ NULL }
};

/*
 * This indicates a number of milliseconds that we should wait between reads.
 * This is somewhat arbitrary, but the goal is to reduce cross call activity
 * and reflect that the sensor may not update all the time.
 */
uint_t amdf17nbdf_cache_ms = 100;

/*
 * This indicates whether detach is allowed. It is not by default. See the
 * theory statement section 'Attach and Detach Complications' for more
 * information.
 */
uint_t amdf17nbdf_allow_detach = 0;

/*
 * Global data that we keep regarding the device.
 */
amdf17nbdf_t *amdf17nbdf;

static amdf17nb_t *
amdf17nbdf_lookup_nb(amdf17nbdf_t *nbdf, minor_t minor)
{
	ASSERT(MUTEX_HELD(&nbdf->amd_nbdf_lock));

	if (minor < AMDF17_MINOR_LOW || minor > AMDF17_MINOR_HIGH) {
		return (NULL);
	}

	for (amdf17nb_t *nb = list_head(&nbdf->amd_nbdf_nbs); nb != NULL;
	    nb = list_next(&nbdf->amd_nbdf_nbs, nb)) {
		if ((id_t)minor == nb->amd_nb_temp_minor) {
			return (nb);
		}
	}

	return (NULL);
}

static void
amdf17nbdf_cleanup_nb(amdf17nbdf_t *nbdf, amdf17nb_t *nb)
{
	if (nb == NULL)
		return;

	ddi_remove_minor_node(nb->amd_nb_dip, NULL);
	if (nb->amd_nb_temp_minor > 0) {
		id_free(nbdf->amd_nbdf_minors, nb->amd_nb_temp_minor);
	}
	if (nb->amd_nb_cfgspace != NULL) {
		pci_config_teardown(&nb->amd_nb_cfgspace);
	}
	kmem_free(nb, sizeof (amdf17nb_t));
}

static void
amdf17nbdf_cleanup_df(amdf17df_t *df)
{
	if (df == NULL)
		return;

	if (df->amd_df_f0_cfgspace != NULL) {
		pci_config_teardown(&df->amd_df_f0_cfgspace);
	}
	kmem_free(df, sizeof (amdf17df_t));
}

static int
amdf17nbdf_smn_read(amdf17nbdf_t *nbdf, amdf17nb_t *nb, uint32_t addr,
    uint32_t *valp)
{
	VERIFY(MUTEX_HELD(&nbdf->amd_nbdf_lock));

	pci_config_put32(nb->amd_nb_cfgspace, AMDF17_NB_SMN_ADDR, addr);
	*valp = pci_config_get32(nb->amd_nb_cfgspace, AMDF17_NB_SMN_DATA);

	return (0);
}

static int
amdf17nbdf_temp_read(amdf17nbdf_t *nbdf, amdf17nb_t *nb)
{
	int ret;
	uint32_t reg, rawtemp, decimal;

	ASSERT(MUTEX_HELD(&nbdf->amd_nbdf_lock));

	/*
	 * Update the last read time first. Even if this fails, we want to make
	 * sure that we latch the fact that we tried.
	 */
	nb->amd_nb_temp_last_read = gethrtime();
	if ((ret = amdf17nbdf_smn_read(nbdf, nb, AMDF17_SMU_THERMAL_CURTEMP,
	    &reg)) != 0) {
		return (ret);
	}

	nb->amd_nb_temp_reg = reg;

	/*
	 * Take the primary temperature value and break apart its decimal value
	 * from its main value.
	 */
	rawtemp = AMDF17_SMU_THERMAL_CURTEMP_TEMPERATURE(reg);
	decimal = rawtemp & AMDF17_SMU_THERMAL_CURTEMP_BITS_MASK;
	rawtemp = rawtemp >> AMDF17_SMU_THERMAL_CURTEMP_DECIMAL_BITS;

	if ((reg & AMDF17_SMU_THERMAL_CURTEMP_RANGE_SEL) != 0) {
		rawtemp += AMDF17_SMU_THERMAL_CURTEMP_RANGE_ADJ;
	}
	rawtemp += nb->amd_nb_temp_off;
	nb->amd_nb_temp = rawtemp << AMDF17_SMU_THERMAL_CURTEMP_DECIMAL_BITS;
	nb->amd_nb_temp += decimal;

	return (0);
}

static int
amdf17nbdf_temp_init(amdf17nbdf_t *nbdf, amdf17nb_t *nb)
{
	uint_t i, family;
	char buf[256];

	if (cpuid_getbrandstr(CPU, buf, sizeof (buf)) >= sizeof (buf)) {
		dev_err(nb->amd_nb_dip, CE_WARN, "!failed to read processor "
		    "brand string, brand larger than internal buffer");
		return (EOVERFLOW);
	}

	family = cpuid_getfamily(CPU);

	for (i = 0; amdf17nbdf_offsets[i].amd_nbdfo_brand != NULL; i++) {
		if (family != amdf17nbdf_offsets[i].amd_nbdfo_family)
			continue;
		if (strncmp(buf, amdf17nbdf_offsets[i].amd_nbdfo_brand,
		    strlen(amdf17nbdf_offsets[i].amd_nbdfo_brand)) == 0) {
			nb->amd_nb_temp_off =
			    amdf17nbdf_offsets[i].amd_nbdfo_off;
			break;
		}
	}

	return (amdf17nbdf_temp_read(nbdf, nb));
}

static amdf17nbdf_type_t
amdf17nbdf_dip_type(uint16_t dev)
{
	uint_t i;
	const amdf17nbdf_table_t *tp = amdf17nbdf_dev_map;

	for (i = 0; tp[i].amd_nbdft_pci_did != PCI_EINVAL16; i++) {
		if (tp[i].amd_nbdft_pci_did == dev) {
			return (tp[i].amd_nbdft_type);
		}
	}

	return (AMD_NBDF_TYPE_UNKNOWN);
}

static boolean_t
amdf17nbdf_map(amdf17nbdf_t *nbdf, amdf17nb_t *nb, amdf17df_t *df)
{
	int ret;
	char buf[128];

	ASSERT(MUTEX_HELD(&nbdf->amd_nbdf_lock));

	/*
	 * This means that we encountered a duplicate. We're going to stop
	 * processing, but we're not going to fail its attach at this point.
	 */
	if (nb->amd_nb_df != NULL) {
		dev_err(nb->amd_nb_dip, CE_WARN, "!trying to map NB %u/%u/%u "
		    "to DF procnode %u, but NB is already mapped to DF "
		    "procnode %u!",
		    nb->amd_nb_bus, nb->amd_nb_dev, nb->amd_nb_func,
		    df->amd_df_procnodeid, nb->amd_nb_df->amd_df_procnodeid);
		return (B_TRUE);
	}

	/*
	 * Now that we have found a mapping, initialize our temperature
	 * information and create the minor node.
	 */
	nb->amd_nb_procnodeid = df->amd_df_procnodeid;
	nb->amd_nb_temp_minor = id_alloc(nbdf->amd_nbdf_minors);

	if ((ret = amdf17nbdf_temp_init(nbdf, nb)) != 0) {
		dev_err(nb->amd_nb_dip, CE_WARN, "!failed to init SMN "
		    "temperature data on node %u: %d", nb->amd_nb_procnodeid,
		    ret);
		return (B_FALSE);
	}

	if (snprintf(buf, sizeof (buf), "procnode.%u", nb->amd_nb_procnodeid) >=
	    sizeof (buf)) {
		dev_err(nb->amd_nb_dip, CE_WARN, "!unexpected buffer name "
		    "overrun assembling temperature minor %u",
		    nb->amd_nb_procnodeid);
		return (B_FALSE);
	}

	if (ddi_create_minor_node(nb->amd_nb_dip, buf, S_IFCHR,
	    nb->amd_nb_temp_minor, DDI_NT_SENSOR_TEMP_CPU, 0) != DDI_SUCCESS) {
		dev_err(nb->amd_nb_dip, CE_WARN, "!failed to create minor node "
		    "%s", buf);
		return (B_FALSE);
	}

	/*
	 * Now that's it's all done, note that they're mapped to each other.
	 */
	nb->amd_nb_df = df;
	df->amd_df_nb = nb;

	return (B_TRUE);
}

static boolean_t
amdf17nbdf_add_nb(amdf17nbdf_t *nbdf, amdf17nb_t *nb)
{
	amdf17df_t *df;
	boolean_t ret = B_TRUE;

	mutex_enter(&nbdf->amd_nbdf_lock);
	list_insert_tail(&nbdf->amd_nbdf_nbs, nb);
	for (df = list_head(&nbdf->amd_nbdf_dfs); df != NULL;
	    df = list_next(&nbdf->amd_nbdf_dfs, df)) {
		if (nb->amd_nb_bus == df->amd_df_iobus) {
			ret = amdf17nbdf_map(nbdf, nb, df);
			break;
		}
	}
	mutex_exit(&nbdf->amd_nbdf_lock);

	return (ret);
}

static boolean_t
amdf17nbdf_add_df(amdf17nbdf_t *nbdf, amdf17df_t *df)
{
	amdf17nb_t *nb;
	boolean_t ret = B_TRUE;

	mutex_enter(&nbdf->amd_nbdf_lock);
	list_insert_tail(&nbdf->amd_nbdf_dfs, df);
	for (nb = list_head(&nbdf->amd_nbdf_nbs); nb != NULL;
	    nb = list_next(&nbdf->amd_nbdf_nbs, nb)) {
		if (nb->amd_nb_bus == df->amd_df_iobus) {
			ret = amdf17nbdf_map(nbdf, nb, df);
		}
	}
	mutex_exit(&nbdf->amd_nbdf_lock);

	return (ret);
}

static boolean_t
amdf17nbdf_attach_nb(amdf17nbdf_t *nbdf, dev_info_t *dip, ddi_acc_handle_t hdl,
    uint_t bus, uint_t dev, uint_t func)
{
	amdf17nb_t *nb;

	nb = kmem_zalloc(sizeof (amdf17nb_t), KM_SLEEP);
	nb->amd_nb_dip = dip;
	nb->amd_nb_cfgspace = hdl;
	nb->amd_nb_bus = bus;
	nb->amd_nb_dev = dev;
	nb->amd_nb_func = func;
	/*
	 * Set this to a value we won't get from the processor.
	 */
	nb->amd_nb_procnodeid = UINT_MAX;

	if (!amdf17nbdf_add_nb(nbdf, nb)) {
		amdf17nbdf_cleanup_nb(nbdf, nb);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static boolean_t
amdf17nbdf_attach_df(amdf17nbdf_t *nbdf, dev_info_t *dip, ddi_acc_handle_t hdl,
    uint_t bus, uint_t dev, uint_t func)
{
	amdf17df_t *df;

	if (bus != AMDF17_DF_BUSNO) {
		dev_err(dip, CE_WARN, "!encountered data fabric device with "
		    "unexpected PCI bus assignment, found 0x%x, expected 0x%x",
		    bus, AMDF17_DF_BUSNO);
		return (B_FALSE);
	}

	if (dev < AMDF17_DF_FIRST_DEVICE) {
		dev_err(dip, CE_WARN, "!encountered data fabric device with "
		    "PCI device assignment below the first minimum device "
		    "(0x%x): 0x%x", AMDF17_DF_FIRST_DEVICE, dev);
		return (B_FALSE);
	}

	/*
	 * At the moment we only care about function 0. However, we may care
	 * about Function 4 in the future which has access to the FICAA.
	 * However, only function zero should ever be attached, so this is just
	 * an extra precaution.
	 */
	if (func != 0) {
		dev_err(dip, CE_WARN, "!encountered data fabric device with "
		    "unxpected PCI function assignment, found 0x%x, expected "
		    "0x0", func);
		return (B_FALSE);
	}

	df = kmem_zalloc(sizeof (amdf17df_t), KM_SLEEP);
	df->amd_df_f0_dip = dip;
	df->amd_df_f0_cfgspace = hdl;
	df->amd_df_procnodeid = dev - AMDF17_DF_FIRST_DEVICE;
	df->amd_df_iobus = pci_config_get32(hdl, AMDF17_DF_CFG_ADDR_CTL) &
	    AMDF17_DF_CFG_ADDR_CTL_MASK;

	if (!amdf17nbdf_add_df(nbdf, df)) {
		amdf17nbdf_cleanup_df(df);
		return (B_FALSE);
	}

	return (B_TRUE);
}

static int
amdf17nbdf_open(dev_t *devp, int flags, int otype, cred_t *credp)
{
	amdf17nbdf_t *nbdf = amdf17nbdf;
	minor_t m;

	if (crgetzoneid(credp) != GLOBAL_ZONEID || drv_priv(credp)) {
		return (EPERM);
	}

	if ((flags & (FEXCL | FNDELAY | FWRITE)) != 0) {
		return (EINVAL);
	}

	if (otype != OTYP_CHR) {
		return (EINVAL);
	}

	m = getminor(*devp);

	/*
	 * Sanity check the minor
	 */
	mutex_enter(&nbdf->amd_nbdf_lock);
	if (amdf17nbdf_lookup_nb(nbdf, m) == NULL) {
		mutex_exit(&nbdf->amd_nbdf_lock);
		return (ENXIO);
	}
	mutex_exit(&nbdf->amd_nbdf_lock);

	return (0);
}

static int
amdf17nbdf_ioctl_kind(intptr_t arg, int mode)
{
	sensor_ioctl_kind_t kind;

	bzero(&kind, sizeof (sensor_ioctl_kind_t));
	kind.sik_kind = SENSOR_KIND_TEMPERATURE;

	if (ddi_copyout((void *)&kind, (void *)arg,
	    sizeof (sensor_ioctl_kind_t), mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
amdf17nbdf_ioctl_temp(amdf17nbdf_t *nbdf, minor_t minor, intptr_t arg, int mode)
{
	amdf17nb_t *nb;
	hrtime_t diff;
	sensor_ioctl_temperature_t temp;

	bzero(&temp, sizeof (temp));

	mutex_enter(&nbdf->amd_nbdf_lock);
	nb = amdf17nbdf_lookup_nb(nbdf, minor);
	if (nb == NULL) {
		mutex_exit(&nbdf->amd_nbdf_lock);
		return (ENXIO);
	}

	diff = NSEC2MSEC(gethrtime() - nb->amd_nb_temp_last_read);
	if (diff > 0 && diff > (hrtime_t)amdf17nbdf_cache_ms) {
		int ret;

		ret = amdf17nbdf_temp_read(nbdf, nb);
		if (ret != 0) {
			mutex_exit(&nbdf->amd_nbdf_lock);
			return (ret);
		}
	}

	temp.sit_unit = SENSOR_UNIT_CELSIUS;
	temp.sit_temp = nb->amd_nb_temp;
	temp.sit_gran = AMDF17_THERMAL_GRANULARITY;
	mutex_exit(&nbdf->amd_nbdf_lock);

	if (ddi_copyout(&temp, (void *)arg, sizeof (temp),
	    mode & FKIOCTL) != 0) {
		return (EFAULT);
	}

	return (0);
}

static int
amdf17nbdf_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp,
    int *rvalp)
{
	minor_t m;
	amdf17nbdf_t *nbdf = amdf17nbdf;

	if ((mode & FREAD) == 0) {
		return (EINVAL);
	}

	m = getminor(dev);

	switch (cmd) {
	case SENSOR_IOCTL_TYPE:
		return (amdf17nbdf_ioctl_kind(arg, mode));
	case SENSOR_IOCTL_TEMPERATURE:
		return (amdf17nbdf_ioctl_temp(nbdf, m, arg, mode));
	default:
		return (ENOTTY);
	}
}

/*
 * We don't really do any state tracking on close, so for now, just allow it to
 * always succeed.
 */
static int
amdf17nbdf_close(dev_t dev, int flags, int otype, cred_t *credp)
{
	return (0);
}

static int
amdf17nbdf_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	uint_t nregs;
	int *regs;
	uint_t bus, dev, func;
	uint16_t pci_did;
	ddi_acc_handle_t pci_hdl;
	amdf17nbdf_type_t type;
	amdf17nbdf_t *nbdf = amdf17nbdf;

	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);
	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, 0, "reg",
	    &regs, &nregs) != DDI_PROP_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to find pci 'reg' property");
		return (DDI_FAILURE);
	}

	if (nregs < 1) {
		ddi_prop_free(regs);
		return (DDI_FAILURE);
	}

	bus = PCI_REG_BUS_G(regs[0]);
	dev = PCI_REG_DEV_G(regs[0]);
	func = PCI_REG_FUNC_G(regs[0]);

	ddi_prop_free(regs);

	if (pci_config_setup(dip, &pci_hdl) != DDI_SUCCESS) {
		dev_err(dip, CE_WARN, "!failed to map pci devices");
		return (DDI_FAILURE);
	}

	pci_did = pci_config_get16(pci_hdl, PCI_CONF_DEVID);

	type = amdf17nbdf_dip_type(pci_did);
	switch (type) {
	case AMD_NBDF_TYPE_NORTHBRIDGE:
		if (!amdf17nbdf_attach_nb(nbdf, dip, pci_hdl, bus, dev, func)) {
			return (DDI_FAILURE);
		}
		break;
	case AMD_NBDF_TYPE_DATA_FABRIC:
		if (!amdf17nbdf_attach_df(nbdf, dip, pci_hdl, bus, dev, func)) {
			return (DDI_FAILURE);
		}
		break;
	default:
		pci_config_teardown(&pci_hdl);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Unfortunately, it's hard for us to really support detach here. The problem is
 * that we need both the data fabric devices and the northbridges to make sure
 * that we map everything. However, only the northbridges actually create minor
 * nodes that'll be opened and thus trigger them to reattach when accessed. What
 * we should probably look at doing in the future is making this into a nexus
 * driver that enumerates children like a temperature driver.
 */
static int
amdf17nbdf_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	amdf17nbdf_t *nbdf = amdf17nbdf;

	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);

	if (nbdf == NULL) {
		return (DDI_FAILURE);
	}

	if (amdf17nbdf_allow_detach == 0) {
		return (DDI_FAILURE);
	}

	mutex_enter(&nbdf->amd_nbdf_lock);
	for (amdf17nb_t *nb = list_head(&nbdf->amd_nbdf_nbs); nb != NULL;
	    nb = list_next(&nbdf->amd_nbdf_nbs, nb)) {
		if (dip == nb->amd_nb_dip) {
			list_remove(&nbdf->amd_nbdf_nbs, nb);
			if (nb->amd_nb_df != NULL) {
				ASSERT3P(nb->amd_nb_df->amd_df_nb, ==, nb);
				nb->amd_nb_df->amd_df_nb = NULL;
			}
			amdf17nbdf_cleanup_nb(nbdf, nb);
			mutex_exit(&nbdf->amd_nbdf_lock);
			return (DDI_SUCCESS);
		}
	}

	for (amdf17df_t *df = list_head(&nbdf->amd_nbdf_dfs); df != NULL;
	    df = list_next(&nbdf->amd_nbdf_nbs, df)) {
		if (dip == df->amd_df_f0_dip) {
			list_remove(&nbdf->amd_nbdf_dfs, df);
			if (df->amd_df_nb != NULL) {
				ASSERT3P(df->amd_df_nb->amd_nb_df, ==, df);
				df->amd_df_nb->amd_nb_df = NULL;
			}
			amdf17nbdf_cleanup_df(df);
			mutex_exit(&nbdf->amd_nbdf_lock);
			return (DDI_SUCCESS);
		}
	}
	mutex_exit(&nbdf->amd_nbdf_lock);

	return (DDI_FAILURE);
}

static int
amdf17nbdf_getinfo(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg,
    void **resultp)
{
	dev_t dev;
	minor_t minor;
	amdf17nbdf_t *nbdf;
	amdf17nb_t *nb;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
	case DDI_INFO_DEVT2INSTANCE:
		break;
	default:
		return (DDI_FAILURE);
	}

	dev = (dev_t)arg;
	minor = getminor(dev);
	nbdf = amdf17nbdf;

	mutex_enter(&nbdf->amd_nbdf_lock);
	nb = amdf17nbdf_lookup_nb(nbdf, (id_t)minor);
	if (nb == NULL) {
		mutex_exit(&nbdf->amd_nbdf_lock);
		return (DDI_FAILURE);
	}
	if (cmd == DDI_INFO_DEVT2DEVINFO) {
		*resultp = nb->amd_nb_dip;
	} else {
		int inst = ddi_get_instance(nb->amd_nb_dip);
		*resultp = (void *)(uintptr_t)inst;
	}
	mutex_exit(&nbdf->amd_nbdf_lock);

	return (DDI_SUCCESS);
}

static void
amdf17nbdf_destroy(amdf17nbdf_t *nbdf)
{
	amdf17nb_t *nb;
	amdf17df_t *df;

	while ((nb = list_remove_head(&nbdf->amd_nbdf_nbs)) != NULL) {
		amdf17nbdf_cleanup_nb(nbdf, nb);
	}
	list_destroy(&nbdf->amd_nbdf_nbs);

	while ((df = list_remove_head(&nbdf->amd_nbdf_dfs)) != NULL) {
		amdf17nbdf_cleanup_df(df);
	}
	list_destroy(&nbdf->amd_nbdf_dfs);

	if (nbdf->amd_nbdf_minors != NULL) {
		id_space_destroy(nbdf->amd_nbdf_minors);
	}

	mutex_destroy(&nbdf->amd_nbdf_lock);
	kmem_free(nbdf, sizeof (amdf17nbdf_t));
}

static amdf17nbdf_t *
amdf17nbdf_create(void)
{
	amdf17nbdf_t *nbdf;

	nbdf = kmem_zalloc(sizeof (amdf17nbdf_t), KM_SLEEP);
	mutex_init(&nbdf->amd_nbdf_lock, NULL, MUTEX_DRIVER, NULL);
	list_create(&nbdf->amd_nbdf_nbs, sizeof (amdf17nb_t),
	    offsetof(amdf17nb_t, amd_nb_link));
	list_create(&nbdf->amd_nbdf_dfs, sizeof (amdf17df_t),
	    offsetof(amdf17df_t, amd_df_link));
	if ((nbdf->amd_nbdf_minors = id_space_create("amdf17nbdf_minors",
	    AMDF17_MINOR_LOW, AMDF17_MINOR_HIGH)) == NULL) {
		amdf17nbdf_destroy(nbdf);
		return (NULL);
	}

	return (nbdf);
}

static struct cb_ops amdf17nbdf_cb_ops = {
	.cb_open = amdf17nbdf_open,
	.cb_close = amdf17nbdf_close,
	.cb_strategy = nodev,
	.cb_print = nodev,
	.cb_dump = nodev,
	.cb_read = nodev,
	.cb_write = nodev,
	.cb_ioctl = amdf17nbdf_ioctl,
	.cb_devmap = nodev,
	.cb_mmap = nodev,
	.cb_segmap = nodev,
	.cb_chpoll = nochpoll,
	.cb_prop_op = ddi_prop_op,
	.cb_flag = D_MP,
	.cb_rev = CB_REV,
	.cb_aread = nodev,
	.cb_awrite = nodev
};

static struct dev_ops amdf17nbdf_dev_ops = {
	.devo_rev = DEVO_REV,
	.devo_refcnt = 0,
	.devo_getinfo = amdf17nbdf_getinfo,
	.devo_identify = nulldev,
	.devo_probe = nulldev,
	.devo_attach = amdf17nbdf_attach,
	.devo_detach = amdf17nbdf_detach,
	.devo_reset = nodev,
	.devo_power = ddi_power,
	.devo_quiesce = ddi_quiesce_not_needed,
	.devo_cb_ops = &amdf17nbdf_cb_ops
};

static struct modldrv amdf17nbdf_modldrv = {
	.drv_modops = &mod_driverops,
	.drv_linkinfo = "AMD Family 17h Driver",
	.drv_dev_ops = &amdf17nbdf_dev_ops
};

static struct modlinkage amdf17nbdf_modlinkage = {
	.ml_rev = MODREV_1,
	.ml_linkage = { &amdf17nbdf_modldrv, NULL }
};

int
_init(void)
{
	int ret;
	amdf17nbdf_t *nbdf;

	if ((nbdf = amdf17nbdf_create()) == NULL) {
		return (ENOMEM);
	}

	if ((ret = mod_install(&amdf17nbdf_modlinkage)) != 0) {
		amdf17nbdf_destroy(amdf17nbdf);
		return (ret);
	}

	amdf17nbdf = nbdf;
	return (ret);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&amdf17nbdf_modlinkage, modinfop));
}

int
_fini(void)
{
	int ret;

	if ((ret = mod_remove(&amdf17nbdf_modlinkage)) != 0) {
		return (ret);
	}

	amdf17nbdf_destroy(amdf17nbdf);
	amdf17nbdf = NULL;
	return (ret);
}
