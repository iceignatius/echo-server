SENDFILE = sample-text.txt
RECVFILE = resp-text.txt

.PHONY: all clean test

all:

clean:

test: all
	cd ../ && bin/echo-server &
	-rm $(RECVFILE)
	../submod/tcptest/bin/tcptest \
		127.0.0.1:4220 \
		--send=$(SENDFILE) \
		--recv=$(RECVFILE)
	diff $(SENDFILE) $(RECVFILE)
	-rm $(RECVFILE)
	../submod/tcptest/bin/tcptest \
		127.0.0.1:4221 \
		--send=$(SENDFILE) \
		--recv=$(RECVFILE) \
		--tls
	diff $(SENDFILE) $(RECVFILE)
