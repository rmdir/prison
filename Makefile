#   the used tools
APXS?=apxs

DEFS=-D_HAVE_LIBUTIL_H_ -DPARANOID
LIBS=-L/usr/lib -lutil -L/usr/local/lib -ljail

all: compile
	
compile:	
	${APXS} -c mod_prison.c freebsd.c ${DEFS} ${LIBS}

install: 
	${APXS} -n prison -i mod_prison.la

#   cleanup
clean:
	-rm -fr *.o *.lo *.slo *.la .libs

