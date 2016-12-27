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

install:

uninstall:
