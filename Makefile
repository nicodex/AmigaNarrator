EXE ?=
BUILDDIR ?= build
MUSASHIDIR ?= Musashi
GCC_WARNINGS ?= -Wall -Wextra -Wformat -pedantic

ifneq (,$(wildcard /usr/share/dpkg/buildflags.mk))
	export DEB_BUILD_MAINT_OPTIONS = optimize=+lto hardening=+all
	export DEB_CFLAGS_MAINT_APPEND = $(GCC_WARNINGS)
	export DEB_LDFLAGS_MAINT_APPEND = $(GCC_WARNINGS)
	include /usr/share/dpkg/buildflags.mk
	export CPPFLAGS CFLAGS LDFLAGS
else
	CC ?= gcc
	ifeq ($(CC),gcc)
		CFLAGS ?= -std=c99 -O2
		CFLAGS += $(GCC_WARNINGS)
		LDFLAGS += $(GCC_WARNINGS)
	endif
endif
CPPFLAGS += -DMUSASHI_CNF=\"$(abspath cpuconf.h)\"
CFLAGS += -I$(MUSASHIDIR)

MUSASHIOBJ= $(addprefix $(BUILDDIR)/,\
	m68kcpu.o \
	m68kdasm.o \
	softfloat.o \
	m68kops.o \
	)

.PHONY: all check clean
all: narrator$(EXE) translateas$(EXE) translator$(EXE)

$(BUILDDIR):
	mkdir -p $@

$(BUILDDIR)/m68kmake.o: $(MUSASHIDIR)/m68kmake.c \
	| $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

$(BUILDDIR)/m68kmake$(EXE): $(BUILDDIR)/m68kmake.o \
	| $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $<

$(BUILDDIR)/m68kops.h $(BUILDDIR)/m68kops.c: $(MUSASHIDIR)/m68k_in.c \
	| $(BUILDDIR)/m68kmake$(EXE)
	$(BUILDDIR)/m68kmake$(EXE) $(BUILDDIR)/ $<

$(BUILDDIR)/m68kcpu.o: $(MUSASHIDIR)/m68kcpu.c $(BUILDDIR)/m68kops.h cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -I$(BUILDDIR) -c $<

$(BUILDDIR)/m68kdasm.o: $(MUSASHIDIR)/m68kdasm.c cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

$(BUILDDIR)/softfloat.o: $(MUSASHIDIR)/softfloat/softfloat.c \
	$(MUSASHIDIR)/softfloat/softfloat.h \
	$(MUSASHIDIR)/softfloat/softfloat-macros \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

$(BUILDDIR)/m68kops.o: $(BUILDDIR)/m68kops.c $(BUILDDIR)/m68kops.h cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

$(BUILDDIR)/narrator.o: narrator.c cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

narrator$(EXE): $(BUILDDIR)/narrator.o $(MUSASHIOBJ)
	$(CC) -o $@ $^ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lm

$(BUILDDIR)/translateas.o: translateas.c cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

translateas$(EXE): $(BUILDDIR)/translateas.o $(MUSASHIOBJ)
	$(CC) -o $@ $^ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lm

$(BUILDDIR)/translator.o: translator.c cpuconf.h \
	Makefile | $(BUILDDIR)
	$(CC) -o $@ $(CPPFLAGS) $(CFLAGS) -c $<

translator$(EXE): $(BUILDDIR)/translator.o $(MUSASHIOBJ)
	$(CC) -o $@ $^ $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -lm

check:
	diff $(MUSASHIDIR)/m68kconf.h cpuconf.h ||:

clean:
	$(RM) narrator$(EXE) $(BUILDDIR)/narrator.o
	$(RM) translateas$(EXE) $(BUILDDIR)/translateas.o
	$(RM) translator$(EXE) $(BUILDDIR)/translator.o
	$(RM) $(MUSASHIOBJ)
	$(RM) $(BUILDDIR)/m68kops.h $(BUILDDIR)/m68kops.c
	$(RM) $(BUILDDIR)/m68kmake$(EXE) $(BUILDDIR)/m68kmake.o
	[ ! -d $(BUILDDIR) ] || rmdir $(BUILDDIR)

