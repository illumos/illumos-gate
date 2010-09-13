# For <shared.h> and <stage1.h>.
INCLUDES = -I$(top_srcdir)/stage2 -I$(top_srcdir)/stage1

# Don't build the netboot support by default.
if NETBOOT_SUPPORT
LIBDRIVERS = libdrivers.a
else
LIBDRIVERS =
endif

noinst_LIBRARIES = $(LIBDRIVERS)

libdrivers_a_SOURCES = big_bswap.h bootp.h byteswap.h config.c cpu.h \
	dev.h elf.h endian.h etherboot.h fsys_tftp.c grub.h \
	i386_byteswap.h i386_elf.h i386_endian.h i386_timer.c \
	if_arp.h if_ether.h igmp.h in.h io.h ip.h isa.h latch.h \
	little_bswap.h misc.c nic.c nic.h osdep.h pci.c pci.h \
	pci_ids.h pci_io.c stdint.h tftp.h timer.c timer.h \
	types.h udp.h mii.h pic8259.c pic8259.h pxe.h basemem.c segoff.h
EXTRA_libdrivers_a_SOURCES = 3c595.c 3c595.h 3c90x.c davicom.c \
	e1000.c e1000_hw.h eepro100.c epic100.c epic100.h natsemi.c \
	ns8390.c ns8390.h pcnet32.c rtl8139.c sis900.c sis900.h \
	sundance.c tg3.c tg3.h tlan.c tlan.h tulip.c via-rhine.c \
	w89c840.c r8169.c forcedeth.c ns83820.c pnic.c pnic_api.c \
	undi.c undi.h
libdrivers_a_CFLAGS = $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	-DFSYS_TFTP=1 $(NET_CFLAGS) $(NET_EXTRAFLAGS)
# Filled by configure.
libdrivers_a_LIBADD = @NETBOOT_DRIVERS@
libdrivers_a_DEPENDENCIES = $(libdrivers_a_LIBADD)

EXTRA_DIST = README.netboot

# These below are several special rules for the device drivers.
# We cannot use a simple rule for them...

# What objects are derived from a driver?
#3c509_drivers = 3c509.o 3c529.o
3c595_drivers = 3c595.o
3c90x_drivers = 3c90x.o
#cs89x0_drivers = cs89x0.o
davicom_drivers = davicom.o
#depca_drivers = depca.o
#eepro_drivers = eepro.o
e1000_drivers = e1000.o
eepro100_drivers = eepro100.o
epic100_drivers = epic100.o
#fa311_drivers = fa311.o
forcedeth_drivers = forcedeth.o
#i82586_drivers = 3c507.o exos205.o ni5210.o
#lance_drivers = lance.o ne2100.o ni6510.o
natsemi_drivers = natsemi.o
#ni5010_drivers = ni5010.o
ns83820_drivers = ns83820.o
ns8390_drivers = 3c503.o ne.o ns8390.o wd.o
#otulip_drivers = otulip.o
pcnet32_drivers = pcnet32.o
pnic_drivers = pnic.o
r8169_drivers = r8169.o
rtl8139_drivers = rtl8139.o
sis900_drivers = sis900.o
#sk_g16_drivers = sk_g16.o
sundance_drivers = sundance.o
#smc9000_drivers = smc9000.o
tg3_drivers = tg3.o
#tiara_drivers = tiara.o
tlan_drivers = tlan.o
tulip_drivers = tulip.o
undi_drivers = undi.o
via_rhine_drivers = via_rhine.o
w89c840_drivers = w89c840.o


# Is it really necessary to specify dependecies explicitly?
#$(3c509_drivers): 3c509.c 3c509.h
#$(3c509_drivers): %.o: 3c509.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(3c595_drivers): 3c595.c 3c595.h
$(3c595_drivers): %.o: 3c595.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(3c90x_drivers): 3c90x.c
$(3c90x_drivers): %.o: 3c90x.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(cs89x0_drivers): cs89x0.c cs89x0.h
#$(cs89x0_drivers): %.o: cs89x0.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(davicom_drivers): davicom.c
$(davicom_drivers): %.o: davicom.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(depca_drivers): depca.c
#$(depca_drivers): %.o: depca.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(eepro_drivers): eepro.c
#$(eepro_drivers): %.o: eepro.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(e1000_drivers): e1000.c e1000_hw.h
$(e1000_drivers): %.o: e1000.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(eepro100_drivers): eepro100.c
$(eepro100_drivers): %.o: eepro100.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(epic100_drivers): epic100.c epic100.h
$(epic100_drivers): %.o: epic100.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(forcedeth_drivers): forcedeth.c
$(forcedeth_drivers): %.o: forcedeth.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(fa311_drivers): fa311.c
#$(fa311_drivers): %.o: fa311.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(i82586_drivers): i82586.c
#$(i82586_drivers): %.o: i82586.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(lance_drivers): lance.c
#$(lance_drivers): %.o: lance.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(natsemi_drivers): natsemi.c
$(natsemi_drivers): %.o: natsemi.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(ni5010_drivers): ni5010.c
#$(ni5010_drivers): %.o: ni5010.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(ns83820_drivers): ns83820.c
$(ns83820_drivers): %.o: ns83820.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(ns8390_drivers): ns8390.c ns8390.h
$(ns8390_drivers): %.o: ns8390.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(otulip_drivers): otulip.c otulip.h
#$(otulip_drivers): %.o: otulip.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(pcnet32_drivers): pcnet32.c
$(pcnet32_drivers): %.o: pcnet32.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(pnic_drivers): pnic.c
$(pnic_drivers): %.o: pnic.c pnic_api.h
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(rtl8139_drivers): rtl8139.c
$(rtl8139_drivers): %.o: rtl8139.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(r8169_drivers): r8169.c
$(r8169_drivers): %.o: r8169.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(sis900_drivers): sis900.c sis900.h
$(sis900_drivers): %.o: sis900.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(sk_g16_drivers): sk_g16.c sk_g16.h
#$(sk_g16_drivers): %.o: sk_g16.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(smc9000_drivers): smc9000.c smc9000.h
#$(smc9000_drivers): %.o: smc9000.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(sundance_drivers): sundance.c
$(sundance_drivers): %.o: sundance.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(tg3_drivers): tg3.c tg3.h
$(tg3_drivers): %.o: tg3.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

#$(tiara_drivers): tiara.c
#$(tiara_drivers): %.o: tiara.c
#	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
#	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(tlan_drivers): tlan.c tlan.h
$(tlan_drivers): %.o: tlan.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(tulip_drivers): tulip.c
$(tulip_drivers): %.o: tulip.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(undi_drivers): undi.c undi.h
$(undi_drivers): %.o: undi.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
          $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(via_rhine_drivers): via-rhine.c
$(via_rhine_drivers): %.o: via-rhine.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

$(w89c840_drivers): w89c840.c
$(w89c840_drivers): %.o: w89c840.c
	$(COMPILE) $(STAGE2_CFLAGS) -fno-builtin -nostdinc \
	  $(NET_EXTRAFLAGS) $($(basename $@)_o_CFLAGS) -o $@ -c $<

# Per-object flags.
#3c509_o_CFLAGS = -DINCLUDE_3C509=1
#3c529_o_CFLAGS = -DINCLUDE_3C529=1
3c595_o_CFLAGS = -DINCLUDE_3C595=1
3c90x_o_CFLAGS = -DINCLUDE_3C90X=1
#cs89x0_o_CFLAGS = -DINCLUDE_CS89X0=1
davicom_o_CFLAGS = -DINCLUDE_DAVICOM=1
#depca_o_CFLAGS = -DINCLUDE_DEPCA=1
#eepro_o_CFLAGS = -DINCLUDE_EEPRO=1
e1000_o_CFLAGS = -DINCLUDE_E1000=1
eepro100_o_CFLAGS = -DINCLUDE_EEPRO100=1
epic100_o_CFLAGS = -DINCLUDE_EPIC100=1
#fa311_o_CFLAGS = -DINCLUDE_FA311=1
forcedeth_o_CFLAGS = -DINCLUDE_FORCEDETH=1
#3c507_o_CFLAGS = -DINCLUDE_3C507=1
#exos205_o_CFLAGS = -DINCLUDE_EXOS205=1
#ni5210_o_CFLAGS = -DINCLUDE_NI5210=1
#lance_o_CFLAGS = -DINCLUDE_LANCE=1
#ne2100_o_CFLAGS = -DINCLUDE_NE2100=1
#ni6510_o_CFLAGS = -DINCLUDE_NI6510=1
natsemi_o_CFLAGS = -DINCLUDE_NATSEMI=1
#ni5010_o_CFLAGS = -DINCLUDE_NI5010=1
#3c503_o_CFLAGS = -DINCLUDE_3C503=1
#ne_o_CFLAGS = -DINCLUDE_NE=1
ns83820_o_CFLAGS = -DINCLUDE_NS83820=1
ns8390_o_CFLAGS = -DINCLUDE_NS8390=1
#wd_o_CFLAGS = -DINCLUDE_WD=1
#otulip_o_CFLAGS = -DINCLUDE_OTULIP=1
pcnet32_o_CFLAGS = -DINCLUDE_PCNET32=1
pnic_o_CFLAGS = -DINCLUDE_PNIC=1
r8169_o_CFLAGS = -DINCLUDE_R8169=1
rtl8139_o_CFLAGS = -DINCLUDE_RTL8139=1
sis900_o_CFLAGS = -DINCLUDE_SIS900=1
#sk_g16_o_CFLAGS = -DINCLUDE_SK_G16=1
#smc9000_o_CFLAGS = -DINCLUDE_SMC9000=1
sundance_o_CFLAGS = -DINCLUDE_SUNDANCE=1
#tiara_o_CFLAGS = -DINCLUDE_TIARA=1
tg3_o_CFLAGS = -DINCLUDE_TG3=1
tlan_o_CFLAGS = -DINCLUDE_TLAN=1
tulip_o_CFLAGS = -DINCLUDE_TULIP=1
undi_o_CFLAGS = -DINCLUDE_UNDI=1
via_rhine_o_CFLAGS = -DINCLUDE_VIA_RHINE=1
w89c840_o_CFLAGS = -DINCLUDE_W89C840=1
