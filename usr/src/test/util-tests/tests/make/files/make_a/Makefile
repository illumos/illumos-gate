
SUBDIRS=a b c

all: $(SUBDIRS)
	@echo "DIR=a CC=${CC}"

$(SUBDIRS): FRC
	@cd $@; make

FRC:
