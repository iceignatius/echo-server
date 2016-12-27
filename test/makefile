SENDFILE = sample-text.txt
RECVFILE = resp-text.txt
TCPPORT = 4220
TLSPORT = 4221

.PHONY: all clean test
.PHONY: test_server_config start_server_background test_tcp test_tls

all:

clean:
	rm $(RECVFILE)

test: all test_server_config start_server_background test_tcp test_tls

test_server_config:
	cd ../ && bin/echo-server \
		--auto-exit=1 \
		--config-file=conf/config

start_server_background:
	cd ../ && bin/echo-server \
		--auto-exit=10 \
		--config-file=conf/config &

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
