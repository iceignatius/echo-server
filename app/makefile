# ----------------------------------------------------------
# ---- Echo server -----------------------------------------
# ----------------------------------------------------------

# Detect OS name
ifeq ($(OS),)
	OS := $(shell uname -s)
endif

# Tools setting
CC  := gcc
CXX := g++
LD  := g++
AR  := ar rcs

# Setting
OUTDIR  := ../bin
OUTPUT  := $(OUTDIR)/echo-server
TEMPDIR := temp
INCDIR  :=
INCDIR  += -I../submod/genutil
INCDIR  += -I../submod/c11thrd/include
INCDIR  += -I../submod/inih
LIBDIR  :=
LIBDIR  += -L../submod/c11thrd/lib
LIBDIR  += -L../submod/inih/extra
CFLAGS  :=
CFLAGS  += -Wall
CFLAGS  += -O2
CFLAGS  += -pthread
LDFLAGS :=
LDFLAGS += -s
LDFLAGS += -pthread
SRCS    :=
SRCS    += ../submod/genutil/gen/cirbuf.c
SRCS    += ../submod/genutil/gen/systime.c
SRCS    += ../submod/genutil/gen/timeinf.c
SRCS    += ../submod/genutil/gen/net/iptype.c
SRCS    += ../submod/genutil/gen/net/sockbase.c
SRCS    += ../submod/genutil/gen/net/socktcp.c
SRCS    += ../submod/genutil/gen/net/sockudp.c
SRCS    += ../submod/genutil/gen/net/urlpar.c
SRCS    += ../submod/genutil/gen/net/winwsa.c
SRCS    += epoll_encap.c
SRCS    += listener.c
SRCS    += serv_tcp.c
SRCS    += tls_resource.c
SRCS    += serv_tls.c
SRCS    += cmdopt.c
SRCS    += servconf.c
SRCS    += main.c
LIBS    :=
LIBS    += -lc11thrd
LIBS    += -lmbedtls
LIBS    += -lmbedx509
LIBS    += -lmbedcrypto
LIBS    += -linih
LIBS    += -lrt
OBJS    := $(notdir $(SRCS))
OBJS    := $(addprefix $(TEMPDIR)/,$(OBJS))
OBJS    := $(OBJS:%.c=%.o)
OBJS    := $(OBJS:%.cpp=%.o)
DEPS    := $(OBJS:%.o=%.d)

# Process summary
.PHONY: all clean
.PHONY: pre_step create_dir build_step post_step
.PHONY: install test
all: pre_step create_dir build_step post_step

# Clean process
clean:
ifeq ($(OS),Windows_NT)
	-del /Q $(subst /,\,$(OBJS))
	-del /Q $(subst /,\,$(DEPS))
	-del /Q $(subst /,\,$(OUTPUT))
	-rmdir /Q $(subst /,\,$(TEMPDIR))
	-rmdir /Q $(subst /,\,$(OUTDIR))
else
	-@rm -f $(OBJS) $(DEPS) $(OUTPUT)
	-@rmdir $(TEMPDIR) $(OUTDIR)
endif

# Build process

pre_step:
create_dir:
ifeq ($(OS),Windows_NT)
	@cmd /c if not exist $(subst /,\,$(TEMPDIR)) mkdir $(subst /,\,$(TEMPDIR))
	@cmd /c if not exist $(subst /,\,$(OUTDIR)) mkdir $(subst /,\,$(OUTDIR))
else
	@test -d $(TEMPDIR) || mkdir $(TEMPDIR)
	@test -d $(OUTDIR)  || mkdir $(OUTDIR)
endif
build_step: $(OUTPUT)
post_step:

$(OUTPUT): $(OBJS)
	$(LD) -o $@ $(LIBDIR) $(LDFLAGS) $^ $(LIBS)

define Compile-C-Unit
$(CC) -MM $(INCDIR) $(CFLAGS) -o $(TEMPDIR)/$*.d $< -MT $@
$(CC) -c  $(INCDIR) $(CFLAGS) -o $@ $<
endef
define Compile-Cpp-Unit
$(CXX) -MM $(INCDIR) $(CFLAGS) -o $(TEMPDIR)/$*.d $< -MT $@
$(CXX) -c  $(INCDIR) $(CFLAGS) -o $@ $<
endef

-include $(DEPS)

$(TEMPDIR)/%.o: ../submod/genutil/gen/%.c
	$(Compile-C-Unit)
$(TEMPDIR)/%.o: ../submod/genutil/gen/%.cpp
	$(Compile-Cpp-Unit)
$(TEMPDIR)/%.o: ../submod/genutil/gen/net/%.c
	$(Compile-C-Unit)
$(TEMPDIR)/%.o: ../submod/genutil/gen/net/%.cpp
	$(Compile-Cpp-Unit)
$(TEMPDIR)/%.o: %.c
	$(Compile-C-Unit)
$(TEMPDIR)/%.o: %.cpp
	$(Compile-Cpp-Unit)

# User extended process

install:

test: all
