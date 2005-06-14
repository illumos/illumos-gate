#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
NSGMLS=nsgmls
DOCS=archform.htm \
  build.htm \
  catalog.htm \
  features.htm \
  generic.htm \
  ideas.htm \
  index.htm \
  new.htm \
  nsgmls.htm \
  sgmldecl.htm \
  sgmlnorm.htm \
  sgmlsout.htm \
  spam.htm \
  spent.htm \
  sysdecl.htm \
  sysid.htm \
  winntu.htm

validate: $(DOCS)
	$(NSGMLS) -sB $(DOCS)
	touch validate
