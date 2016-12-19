.PHONY: all clean install uninstall

all:
	cd submod && $(MAKE) $(MAKECMDGOALS)

clean:
	cd submod && $(MAKE) $(MAKECMDGOALS)

install:

uninstall:
