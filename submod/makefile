.PHONY: all clean install uninstall

all:
	cd c11thrd && $(MAKE) $(MAKECMDGOALS)
	cd tcptest && $(MAKE) $(MAKECMDGOALS)
	cd inih/extra && $(MAKE) -f Makefile.static $(MAKECMDGOALS)

clean:
	cd c11thrd && $(MAKE) $(MAKECMDGOALS)
	cd tcptest && $(MAKE) $(MAKECMDGOALS)
	cd inih/extra && $(MAKE) -f Makefile.static $(MAKECMDGOALS)

install:

uninstall:
