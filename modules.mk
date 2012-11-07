mod_prison.la: mod_prison.slo freebsd.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_prison.lo freebsd.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_prison.la
