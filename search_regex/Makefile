# Copyright 2009 The RE2 Authors.  All Rights Reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

# To build against ICU for full Unicode properties support,
# uncomment the next two lines:
# CCICU=$(shell pkg-config icu-uc --cflags) -DRE2_USE_ICU
# LDICU=$(shell pkg-config icu-uc --libs)

# To build against PCRE for testing or benchmarking,
# uncomment the next two lines:
# CCPCRE=-I/usr/local/include -DUSEPCRE
# LDPCRE=-L/usr/local/lib -lpcre

CXX?=g++
# can override
CXXFLAGS?=-O3 -g
LDFLAGS?=
# required
RE2_CXXFLAGS?=-std=c++11 -pthread -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -I. $(CCICU) $(CCPCRE)
RE2_LDFLAGS?=-pthread $(LDICU) $(LDPCRE)
AR?=ar
ARFLAGS?=rsc
NM?=nm
NMFLAGS?=-p

# Variables mandated by GNU, the arbiter of all good taste on the internet.
# http://www.gnu.org/prep/standards/standards.html
prefix=/usr/local
exec_prefix=$(prefix)
includedir=$(prefix)/include
libdir=$(exec_prefix)/lib
INSTALL=install
INSTALL_DATA=$(INSTALL) -m 644

all: CXXFLAGS:=-std=c++17 -pthread -I$(DESTDIR)$(includedir) $(CXXFLAGS) -lstdc++fs
all: LDFLAGS:=-pthread -L$(DESTDIR)$(libdir) -l:libre2.a $(LDICU) $(LDFLAGS)
all:
	$(CXX) search_regex.cc -o search_regex $(CXXFLAGS) $(LDFLAGS)
