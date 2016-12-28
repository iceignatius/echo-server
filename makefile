APNAME = echo-server
INSTDIR = /usr/local

INSTDIR_BIN = $(INSTDIR)/bin
INSTDIR_CONF = $(INSTDIR)/etc/$(APNAME) 

.PHONY: all clean test install uninstall

all:
	cd submod && $(MAKE) $(MAKECMDGOALS)
	cd app && $(MAKE) $(MAKECMDGOALS)

clean:
	cd submod && $(MAKE) $(MAKECMDGOALS)
	cd app && $(MAKE) $(MAKECMDGOALS)
	cd test && $(MAKE) $(MAKECMDGOALS)

test:
	cd test && $(MAKE) $(MAKECMDGOALS)

install: all
	cp bin/$(APNAME) $(INSTDIR_BIN)/
	test -d $(INSTDIR_CONF) || mkdir $(INSTDIR_CONF)
	cp conf/* $(INSTDIR)/etc/$(APNAME)/

uninstall:
	rm $(INSTDIR_BIN)/$(APNAME)
	rm -r $(INSTDIR_CONF)
