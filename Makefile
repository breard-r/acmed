PREFIX = /usr
EXEC_PREFIX = $(PREFIX)
BINDIR = $(EXEC_PREFIX)/bin
DATAROOTDIR = $(PREFIX)/share
DATADIR = $(DATAROOTDIR)
MAN5DIR = $(DATADIR)/man/man5
MAN8DIR = $(DATADIR)/man/man8
SYSCONFDIR = /etc
VARLIBDIR = /var/lib
RUNSTATEDIR = /var/run
TARGET_DIR = ./target/$(TARGET)/release
MAN_SRC_DIR = ./man/en
MAN_DST_DIR = $(TARGET_DIR)/man

FEATURES = openssl_dyn

all: update acmed tacd

update:
	cargo update

acmed: man_dir
	if test -n "$(TARGET)"; then \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --manifest-path "acmed/Cargo.toml" --no-default-features --features "$(FEATURES)" --target "$(TARGET)"; \
	else \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --manifest-path "acmed/Cargo.toml" --no-default-features --features "$(FEATURES)"; \
	fi
	strip "$(TARGET_DIR)/acmed"
	gzip <"$(MAN_SRC_DIR)/acmed.8" >"$(MAN_DST_DIR)/acmed.8.gz"
	gzip <"$(MAN_SRC_DIR)/acmed.toml.5" >"$(MAN_DST_DIR)/acmed.toml.5.gz"

tacd: man_dir
	if test -n "$(TARGET)"; then \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --manifest-path "tacd/Cargo.toml" --no-default-features --features "$(FEATURES)" --target "$(TARGET)"; \
	else \
	    VARLIBDIR="$(VARLIBDIR)" SYSCONFDIR="$(SYSCONFDIR)" RUNSTATEDIR="$(RUNSTATEDIR)" cargo build --release --manifest-path "tacd/Cargo.toml" --no-default-features --features "$(FEATURES)"; \
	fi
	strip "$(TARGET_DIR)/tacd"
	gzip <"$(MAN_SRC_DIR)/tacd.8" >"$(MAN_DST_DIR)/tacd.8.gz"

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
	fi
	if test -f "$(TARGET_DIR)/tacd"; then \
	    install -m 0755 $(TARGET_DIR)/tacd $(DESTDIR)$(BINDIR)/tacd; \
	    install -m 0644 $(TARGET_DIR)/man/tacd.8.gz $(DESTDIR)$(MAN8DIR)/tacd.8.gz; \
	fi

clean:
	cargo clean

.PHONY: all update acmed tacd man_dir install clean
