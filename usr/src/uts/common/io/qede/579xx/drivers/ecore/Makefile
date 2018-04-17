# Makefile for building ecore as a module.
AT?=@
export AT

KVER =
ifeq ($(KVER),)
    KVER = $(shell uname -r)
endif

__ARCH=$(shell uname -m)

# PREFIX may be set by the RPM build to set the effective root.
PREFIX =
ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
# SuSE source RPMs
    _KVER=$(shell echo $(KVER) | cut -d "-" -f1,2)
    _KFLA=$(shell echo $(KVER) | cut -d "-" -f3)
    _ARCH=$(shell file -b /lib/modules/$(shell uname -r)/build | cut -d "/" -f5)
    ifeq ($(_ARCH),)
        _ARCH=$(__ARCH)
    endif
    ifeq ($(shell ls /usr/src/linux-$(_KVER)-obj > /dev/null 2>&1 && echo linux),)
      ifeq ($(shell ls /usr/src/kernels/$(KVER)-$(__ARCH) > /dev/null 2>&1 && echo linux),)
        LINUX=
      else
        LINUX=/usr/src/kernels/$(KVER)-$(__ARCH)
        LINUXSRC=$(LINUX)
        ifeq ($(KERNEL_DIR),)
            KERNEL_DIR=$(LINUX)
        endif
      endif
    else
        ifeq ($(KERNEL_DIR),)
            KERNEL_DIR=/usr/src/linux-$(_KVER)-obj/$(_ARCH)/$(_KFLA)
        endif
        LINUXSRC=/usr/src/linux-$(_KVER)
    endif
else
    BCMPROC := $(__ARCH)
    BCMCFGS := /lib/modules/$(KVER)/build \
               /usr/src/kernels/$(KVER)-$(BCMPROC) \
               /usr/src/linux-$(shell echo $(KVER) | sed "s|\(.*\)-\([a-z]*\)|\1-obj/$(BCMPROC)/\2|") \
               /usr/src/linux

    # Delete any entries that do not exist.
    BCMTSTDIR = $(shell if ls $(DIR) > /dev/null 2>&1; then echo $(DIR); fi)
    BCMCFGS := $(foreach DIR, $(BCMCFGS), $(BCMTSTDIR))

    ifeq ($(BCMCFGS),)
            $(error Linux kernel config directory not found)
    else
        ifeq ($(KERNEL_DIR),)
            KERNEL_DIR := $(firstword $(BCMCFGS))
	    ifeq ($(LINUXSRC),)
	        ifneq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
		    LINUXSRC=/lib/modules/$(KVER)/source
	        endif
	    endif
        endif
    endif
endif

ifeq ($(LINUXSRC),)
   LINUXSRC=$(KERNEL_DIR)
endif

# paths
ifeq ($(shell ls /lib/modules/$(KVER)/updates > /dev/null 2>&1 && echo 1),1)
    DRV_DIR = updates
else
    ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.conf > /dev/null 2>&1 && echo 1),1)
        DRV_DIR = updates
    else
        ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.d/* > /dev/null 2>&1 && echo 1),1)
            DRV_DIR = updates
        else
            DRV_DIR = kernel/drivers/net
        endif
    endif
endif

sles_distro := $(wildcard /etc/SuSE-release)
ifneq ($(sles_distro),)
SLES_VERSION = $(shell cat /etc/SuSE-release | grep VERSION | grep -o -P [0-9]+)
SLES_PATCHLEVEL = $(shell cat /etc/SuSE-release | grep PATCHLEVEL | grep -o -P [0-9]+)
PADDED_PATCHLEVEL = $(shell if [ 10 -gt $(SLES_PATCHLEVEL) ]; then echo 0$(SLES_PATCHLEVEL); else echo $(SLES_PATCHLEVEL); fi)
SLES_DISTRO_VER = "0x$(SLES_VERSION)$(PADDED_PATCHLEVEL)"
EXTRA_CFLAGS += -DSLES_DISTRO=$(SLES_DISTRO_VER)
endif

SOURCES = ecore_chain.c ecore_cxt.c ecore_dev.c ecore_dbg_fw_funcs.c ecore_user_dbg_fw_funcs.c ecore_hw.c ecore_init_fw_funcs.c ecore_init_ops.c ecore_int.c ecore_mcp.c ecore_sp_commands.c ecore_spq.c ecore_dcbx.c ecore_phy.c  ecore_selftest.c ecore_mng_tlv.c
HEADERS_LL2 = ecore_ll2_api.h ecore_ll2.h
HEADERS_HSI = ecore_hsi_common.h ecore_hsi_iscsi.h ecore_hsi_roce.h ecore_hsi_rdma.h ecore_hsi_iwarp.h ecore_hsi_fcoe.h ecore_hsi_toe.h ecore_hsi_debug_tools.h ecore_hsi_init_func.h ecore_hsi_init_tool.h ../common/include/common_hsi.h ../common/include/eth_common.h ../common/include/fcoe_common.h ../common/include/iscsi_common.h ../common/include/roce_common.h ../common/include/rdma_common.h ../common/include/storage_common.h ../common/include/tcp_common.h ../common/include/iwarp_common.h
HEADERS = ecore_chain.h ecore_cxt_api.h ecore_cxt.h ecore_dbg_fw_funcs.h ecore_user_dbg_fw_funcs.h ecore_dbg_values.h ecore_dbg_values_user.h ecore_dev_api.h ecore_gtt_reg_addr.h ecore_gtt_values.h ecore.h ecore_hw_defs.h ecore_hw.h ecore_init_fw_funcs.h ecore_init_ops.h ecore_init_values.h ecore_init_values_zipped.h ecore_int_api.h ecore_int.h ecore_iro.h ecore_iro_values.h ecore_mcp.h ecore_phy_api.h ecore_mcp_api.h ecore_proto_if.h ecore_rt_defs.h ecore_sp_api.h ecore_sp_commands.h ecore_spq.h ecore_status.h ecore_utils.h ecore_dcbx.h ecore_dcbx_api.h ecore_selftest_api.h include/bcm_osal.h ../../hsi/hw/pcics_reg_driver.h  ../../hsi/hw/reg_addr.h ../../hsi/mcp/nvm_cfg.h ../../hsi/mcp/mcp_public.h ../../hsi/mcp/spad_layout.h ../../hsi/mfw_hsi.h ../../hsi/mcp/nvm_map.h ecore_tcp_ip.h
MODULE_NAME = ecore
obj-m += $(MODULE_NAME).o
ecore-objs = ecore_cxt.o ecore_dev.o ecore_dbg_fw_funcs.o ecore_user_dbg_fw_funcs.o ecore_hw.o ecore_init_fw_funcs.o ecore_init_ops.o ecore_int.o ecore_mcp.o ecore_phy.o ecore_sp_commands.o ecore_spq.o ecore_dcbx.o ecore_selftest.o ecore_chain.o  ecore_mng_tlv.o

#TODO - we need all HSI [e.g., ecore_cxt.c needs to know the size of all contexts.
#Either need to carefully revise this, or everyone will need all the HSI files.
#since both L2 and LL2 require ecore_hsi_eth.h, every flavour needs it
HEADERS += $(HEADERS_HSI) ecore_hsi_eth.h

# Determine the content of the ecore compilation - on default do everything
ifneq ($(L2), 1)
ifneq ($(ROCE), 1)
ifneq ($(FCOE), 1)
ifneq ($(ISCSI), 1)
ifneq ($(PTP), 1)
ifneq ($(IWARP), 1)
L2 = 1
ROCE = 1
FCOE = 1
ISCSI = 1
PTP = 1
IWARP = 1
endif
endif
endif
endif
endif
endif

HEADERS += ecore_l2_api.h ecore_l2.h
HEADERS += ecore_roce.h ecore_roce_api.h ecore_hsi_roce.h ecore_hsi_rdma.h
HEADERS += ecore_fcoe_api.h ecore_fcoe.h ecore_hsi_fcoe.h
HEADERS += ecore_hsi_iscsi.h ecore_iscsi_api.h ecore_iscsi.h ecore_ooo.h
HEADERS += $(HEADERS_LL2)
HEADERS += ecore_iov_api.h ecore_sriov.h ecore_vf_api.h ecore_vf.h ecore_vfpf_if.h
HEADERS += ecore_ptp_api.h

ifeq ($(L2), 1)
SRIOV ?= 1
ecore-objs += ecore_l2.o
SOURCES += ecore_l2.c
EXTRA_CFLAGS += -DCONFIG_ECORE_L2
endif
ifeq ($(ROCE), 1)
LL2 = 1
SOURCES += ecore_roce.c
ecore-objs += ecore_roce.o
EXTRA_CFLAGS += -DCONFIG_ECORE_ROCE
endif
ifeq ($(FCOE), 1)
LL2 = 1
SOURCES += ecore_fcoe.c
ecore-objs += ecore_fcoe.o
EXTRA_CFLAGS += -DCONFIG_ECORE_FCOE
endif
ifeq ($(ISCSI), 1)
LL2 = 1
SOURCES += ecore_iscsi.c ecore_ooo.c
ecore-objs += ecore_iscsi.o ecore_ooo.o
EXTRA_CFLAGS += -DCONFIG_ECORE_ISCSI
endif
ifeq ($(IWARP), 1)
LL2 = 1
EXTRA_CFLAGS += -DCONFIG_ECORE_IWARP
endif


#Derivatives
ifeq ($(LL2), 1)
SOURCES += ecore_ll2.c
ecore-objs += ecore_ll2.o
EXTRA_CFLAGS += -DCONFIG_ECORE_LL2
endif
ifeq ($(SRIOV), 1)
ecore-objs += ecore_sriov.o ecore_vf.o
SOURCES += ecore_sriov.c ecore_vf.c
EXTRA_CFLAGS += -DCONFIG_ECORE_SRIOV
endif
ifeq ($(PTP), 1)
ecore-objs += ecore_ptp.o
SOURCES += ecore_ptp.c
EXTRA_CFLAGS += -DCONFIG_ECORE_PTP
endif

#Add include subdir for both user/module flavours
EXTRA_CFLAGS += -DECORE_PACKAGE -I$(src)/include -I./include -I$(src)/../common/include/ -I./../common/include/ -I$(src)/../../hsi/hw/ -I./../../hsi/hw -I$(src)/../../hsi/mcp/ -I./../../hsi/mcp -I$(src)/../../hsi/ -I../../hsi/

all default: $(obj-m)

clean:
	rm -rf *.o *.ko .*.cmd *.mod.c Module.symvers modules.order

$(obj-m): $(SOURCES)
	$(MAKE) -C $(KERNEL_DIR) M=`pwd` modules

user: $(SOURCES)
	$(CC) -c $(SOURCES) $(EXTRA_CFLAGS)

tar: $(SOURCES) $(HEADERS)
	rm -rf /tmp/ecore.tar.gz
	rm -rf /tmp/ecore*
	mkdir /tmp/ecore
	cp -r $(SOURCES) $(HEADERS) release.txt /tmp/ecore/
	echo "L2 = $(L2)" >> /tmp/ecore/Makefile
	echo "FCOE = $(FCOE)" >> /tmp/ecore/Makefile
	echo "ISCSI = $(ISCSI)" >> /tmp/ecore/Makefile
	echo "ROCE = $(ROCE)" >> /tmp/ecore/Makefile
	echo "SRIOV = $(SRIOV)" >> /tmp/ecore/Makefile
	cat Makefile >> /tmp/ecore/Makefile
	tar czvf /tmp/ecore.tar.gz -C /tmp ecore
	rm -rf /tmp/ecore
