PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
SYSCONFDIR = /etc
TARGET_DIR = ./target/release
EXE_NAMES =	acmed \
		tacd
EXE_FILES = $(foreach name,$(EXE_NAMES),$(TARGET_DIR)/$(name))
MAN_SRC_DIR = ./man/en
MAN_DST_DIR = $(TARGET_DIR)/man
MAN_SRC =	acmed.8 \
		acmed.toml.5 \
		tacd.8
MAN_FILES = $(foreach name,$(MAN_SRC),$(MAN_DST_DIR)/$(name).gz)

all: update $(EXE_FILES) man

man: $(MAN_DST_DIR) $(MAN_FILES)

$(EXE_NAMES): %: $(TARGET_DIR)/%

$(EXE_FILES): $(TARGET_DIR)/%: %/Cargo.toml
	cargo build --release --bin $(subst /Cargo.toml,,$<)
	strip $@

$(MAN_DST_DIR):
	@mkdir -p $(MAN_DST_DIR)

$(MAN_DST_DIR)/%.gz: $(MAN_SRC_DIR)/%
	gzip <"$<" >"$@"

update:
	cargo update

install:
	install -D --mode=0755 $(TARGET_DIR)/acmed $(DESTDIR)$(BINDIR)/acmed
	install -D --mode=0755 $(TARGET_DIR)/tacd $(DESTDIR)$(BINDIR)/tacd
	install -D --mode=0644 $(TARGET_DIR)/man/acmed.8.gz $(DESTDIR)$(DATADIR)/man/man8/acmed.8.gz
	install -D --mode=0644 $(TARGET_DIR)/man/acmed.toml.5.gz $(DESTDIR)$(DATADIR)/man/man5/acmed.toml.5.gz
	install -D --mode=0644 $(TARGET_DIR)/man/tacd.8.gz $(DESTDIR)$(DATADIR)/man/man8/tacd.8.gz
	install -D --mode=0644 acmed/acmed_example.toml $(DESTDIR)$(SYSCONFDIR)/acmed/acmed.toml
	install -d --mode=0700 $(DESTDIR)$(SYSCONFDIR)/acmed/accounts
	install -d --mode=0755 $(DESTDIR)$(SYSCONFDIR)/acmed/certs

clean:
	cargo clean

.PHONY: $(EXE_NAMES) all clean install man update
