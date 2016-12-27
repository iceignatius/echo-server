SENDFILE = sample-text.txt
RECVFILE = resp-text.txt
TCPPORT = 4220
TLSPORT = 4221

.PHONY: all clean test
.PHONY: start_server test_tcp test_tls

all:

clean:

test: all start_server test_tcp test_tls

start_server:
	cd ../ && bin/echo-server \
		--auto-exit=10 \
		--config-file=../conf/config &

test_tcp:
	-rm $(RECVFILE)
	../submod/tcptest/bin/tcptest \
		127.0.0.1:$(TCPPORT) \
		--send=$(SENDFILE) \
		--recv=$(RECVFILE)
	diff $(SENDFILE) $(RECVFILE)

test_tls:
	-rm $(RECVFILE)
	../submod/tcptest/bin/tcptest \
		127.0.0.1:$(TLSPORT) \
		--send=$(SENDFILE) \
		--recv=$(RECVFILE) \
		--tls
	diff $(SENDFILE) $(RECVFILE)
