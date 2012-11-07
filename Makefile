APACHE=		/usr/local/httpd
APXS=		${APACHE}/bin/apxs

builddir=	.
top_srcdir=	${APACHE}
top_builddir=	${APACHE}
top_mkdir!=	${APXS} -q installbuilddir

include ${top_mkdir}/special.mk

DEFS=		-D_HAVE_LIBUTIL_H_ 
DEFS+=		-DPARANOID 
DEFS+=		-D_HAVE_RCTL_


LIBS=-L/usr/lib -lutil -L/usr/local/lib -ljail

all: local-shared-build

install: install-modules-yes

clean:
	-rm -f *.o *.lo *.slo *.la .libs


