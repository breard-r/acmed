PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
MAN5DIR = $(DATADIR)/man/man5
MAN8DIR = $(DATADIR)/man/man8
SYSCONFDIR = /etc
VARLIBDIR = /var/lib
RUNSTATEDIR = /run
TARGET_DIR = ./target/$(TARGET)/release
MAN_SRC_DIR = ./man/en
MAN_DST_DIR = $(TARGET_DIR)/man

FEATURES = openssl_dyn

all: man_dir
	if test -n "$(TARGET)"; then \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --no-default-features --features "$(FEATURES)" --target "$(TARGET)"; \
	else \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --no-default-features --features "$(FEATURES)"; \
	fi
	gzip <"$(MAN_SRC_DIR)/acmed.8" >"$(MAN_DST_DIR)/acmed.8.gz"
	gzip <"$(MAN_SRC_DIR)/acmed.toml.5" >"$(MAN_DST_DIR)/acmed.toml.5.gz"

man_dir:
	@mkdir -p $(MAN_DST_DIR)

install:
	install -d -m 0755 $(DESTDIR)$(BINDIR)
	install -d -m 0755 $(DESTDIR)$(MAN8DIR)
	if test -f "$(TARGET_DIR)/acmed"; then \
	    install -d -m 0755 $(DESTDIR)$(MAN5DIR); \
	    install -d -m 0755 $(DESTDIR)$(SYSCONFDIR)/acmed; \
	    install -d -m 0755 $(DESTDIR)$(VARLIBDIR)/acmed/certs; \
	    install -d -m 0700 $(DESTDIR)$(VARLIBDIR)/acmed/accounts; \
	    install -m 0755 $(TARGET_DIR)/acmed $(DESTDIR)$(BINDIR)/acmed; \
	    install -m 0644 $(TARGET_DIR)/man/acmed.8.gz $(DESTDIR)$(MAN8DIR)/acmed.8.gz; \
	    install -m 0644 $(TARGET_DIR)/man/acmed.toml.5.gz $(DESTDIR)$(MAN5DIR)/acmed.toml.5.gz; \
	    install -m 0644 acmed/config/acmed.toml $(DESTDIR)$(SYSCONFDIR)/acmed/acmed.toml; \
	    install -m 0644 acmed/config/default_hooks.toml $(DESTDIR)$(SYSCONFDIR)/acmed/default_hooks.toml; \
	    install -m 0644 acmed/config/letsencrypt.toml $(DESTDIR)$(SYSCONFDIR)/acmed/letsencrypt.toml; \
	fi

clean:
	cargo clean

.PHONY: all man_dir install clean
