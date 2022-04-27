#
#
#
COMMANDNAME = pkirpmsign
PROGRAMS = pkirpmverify pkirpmsign
SOURCEFILES := $(PROGRAMS:%=%.c)
DOCFILES = README.md TODO

ARCHIVE = $(COMMANDNAME).tar.gz

DIRS = BUILD RPMS SOURCES SPECS SRPMS

CC	= gcc
CFLAGS	+= -g -D__XMLSEC_FUNCTION__=__func__ -DXMLSEC_NO_SIZE_T -DXMLSEC_NO_GOST=1 -DXMLSEC_NO_GOST2012=1 -DXMLSEC_NO_CRYPTO_DYNAMIC_LOADING=1 -I/usr/include/xmlsec1 -I/usr/include/libxml2 -DXMLSEC_CRYPTO_OPENSSL=1 -DUNIX_SOCKETS
LDLIBS	+= -g -L/usr/lib/x86_64-linux-gnu -lxmlsec1-openssl -lxmlsec1 -lxslt -lxml2 -lssl -lcrypto

all: $(PROGRAMS) po/fr/$(COMMANDNAME).mo

$(ARCHIVE): $(PROGRAMS)
	tar cfz $@ $(SOURCEFILES) $(DOCFILES) Makefile po/$(COMMANDNAME).pot po/fr/$(COMMANDNAME).po

po/fr/$(COMMANDNAME).mo: po/fr/$(COMMANDNAME).po
	msgfmt --output-file=$@ $<

po/fr/$(COMMANDNAME).po: po/$(COMMANDNAME).pot
	msgmerge --update $@ $<

po/$(COMMANDNAME).pot: $(SOURCEFILES)
	xgettext -k_ -j -lC -c -s -o po/$(COMMANDNAME).pot $(SOURCEFILES)

rpm: $(ARCHIVE)
	rm -rf $(DIRS)
	mkdir $(DIRS)
	cp $(COMMANDNAME).spec SPECS
	cp $(ARCHIVE) SOURCES

clean:
	@rm -rf $(PROGRAMS) $(ARCHIVE) $(DIRS) po/fr/*.mo

check: $(PROGRAMS)
