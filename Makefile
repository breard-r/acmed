PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
SYSCONFDIR = /etc
TARGET_DIR = ./target/release
MAN_SRC_DIR = ./man/en
MAN_DST_DIR = $(TARGET_DIR)/man

all: update acmed tacd man

update:
	cargo update

acmed:
	cargo build --release --bin acmed
	strip "$(TARGET_DIR)/acmed"

tacd:
	cargo build --release --bin tacd
	strip "$(TARGET_DIR)/tacd"

man:
	@mkdir -p $(MAN_DST_DIR)
	gzip <"$(MAN_SRC_DIR)/acmed.8" >"$(MAN_DST_DIR)/acmed.8.gz"
	gzip <"$(MAN_SRC_DIR)/acmed.toml.5" >"$(MAN_DST_DIR)/acmed.toml.5.gz"
	gzip <"$(MAN_SRC_DIR)/tacd.8" >"$(MAN_DST_DIR)/tacd.8.gz"

install:
	install -D -m 0755 $(TARGET_DIR)/acmed $(DESTDIR)$(BINDIR)/acmed
	install -D -m 0755 $(TARGET_DIR)/tacd $(DESTDIR)$(BINDIR)/tacd
	install -D -m 0644 $(TARGET_DIR)/man/acmed.8.gz $(DESTDIR)$(DATADIR)/man/man8/acmed.8.gz
	install -D -m 0644 $(TARGET_DIR)/man/acmed.toml.5.gz $(DESTDIR)$(DATADIR)/man/man5/acmed.toml.5.gz
	install -D -m 0644 $(TARGET_DIR)/man/tacd.8.gz $(DESTDIR)$(DATADIR)/man/man8/tacd.8.gz
	install -D -m 0644 acmed/config/acmed.toml $(DESTDIR)$(SYSCONFDIR)/acmed/acmed.toml
	install -D -m 0644 acmed/config/default_hooks.toml $(DESTDIR)$(SYSCONFDIR)/acmed/default_hooks.toml
	install -d -m 0700 $(DESTDIR)$(SYSCONFDIR)/acmed/accounts
	install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/acmed/certs

clean:
	cargo clean

.PHONY: all update acmed tacd man install clean
