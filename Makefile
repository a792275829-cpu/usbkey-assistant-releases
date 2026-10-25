CC ?= clang
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic
CARGO ?= $(HOME)/.cargo/bin/cargo
RUST_TRANSPORT := rust-transport/target/release/usbkey-transport

BUILD_DIR := build
PCSC_PROBE := $(BUILD_DIR)/netca-pcsc-probe
USB_PROBE := $(BUILD_DIR)/netca-usb-probe
HID_PROBE := $(BUILD_DIR)/ft3000gm-hid-probe
HID_SIGNER := $(BUILD_DIR)/ft3000gm-signer
PROBES := $(USB_PROBE) $(PCSC_PROBE) $(HID_PROBE) $(HID_SIGNER)

.PHONY: all probe verify-key tls bridge test test-process-runner test-assistant-status test-assistant-layout test-assistant-update test-assistant-install test-pin-store app package clean

all: $(PROBES)

$(BUILD_DIR)/pin-store-tests: app/CertificatePinStore.swift tests/CertificatePinStoreTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -parse-as-library -framework Security -o $@

test-pin-store: $(BUILD_DIR)/pin-store-tests
	./$(BUILD_DIR)/pin-store-tests "$$(command -v node)" "$(CURDIR)"


$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(PCSC_PROBE): src/netca_pcsc_probe.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -ldl

$(USB_PROBE): src/netca_usb_probe.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -framework IOKit -framework CoreFoundation

$(HID_PROBE): src/ft3000gm_hid_probe.c src/ft3000gm_lock.h src/ft3000gm_devices.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -framework IOKit -framework CoreFoundation -framework Security

$(HID_SIGNER): src/ft3000gm_signer.c src/ft3000gm_lock.h src/ft3000gm_devices.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) $< -o $@ -framework IOKit -framework CoreFoundation

probe: $(PROBES)
	./$(USB_PROBE)
	./$(PCSC_PROBE)
	./$(HID_PROBE)

verify-key: $(HID_PROBE)
	./$(HID_PROBE) | /usr/bin/python3 -m json.tool

tls:
	/bin/sh scripts/setup_local_tls.sh

bridge: bridge-rust

.PHONY: rust-transport bridge-rust test-rust-transport
rust-transport:
	$(CARGO) build --locked --release --manifest-path rust-transport/Cargo.toml

bridge-rust: $(HID_PROBE) $(HID_SIGNER) rust-transport
	./$(RUST_TRANSPORT) --probe "$(CURDIR)/build/ft3000gm-hid-probe" --signer "$(CURDIR)/build/ft3000gm-signer" --cert "$(CURDIR)/.local/tls/localhost.crt" --key "$(CURDIR)/.local/tls/localhost.key"

test-rust-transport:
	$(CARGO) test --locked --manifest-path rust-transport/Cargo.toml
	$(CARGO) build --locked --manifest-path rust-transport/Cargo.toml
	/usr/bin/env node scripts/test_rust_transport.mjs
	/usr/bin/env node scripts/test_native_backend.mjs
	/usr/bin/env python3 tests/BridgeControlTests.py

test: $(PROBES) test-assistant-restart test-process-runner test-assistant-status test-assistant-update test-assistant-install test-desktop-entry test-rust-transport
	./$(USB_PROBE) | /usr/bin/python3 -m json.tool >/dev/null
	./$(PCSC_PROBE) | /usr/bin/python3 -m json.tool >/dev/null
	/usr/bin/env node --check server/netca_readonly_bridge.mjs
	/usr/bin/env node scripts/test_enveloped_data.mjs
	/usr/bin/env node scripts/test_decryption.mjs
	/usr/bin/env node scripts/test_bridge_architecture.mjs
	/usr/bin/env node scripts/test_device_lock.mjs
	/usr/bin/env node scripts/test_device_status.mjs
	/usr/bin/env node scripts/test_rpc_sessions.mjs
	/usr/bin/env node scripts/test_pin_persistence.mjs
	/usr/bin/env node scripts/test_device_monitor.mjs
	/usr/bin/env node scripts/test_device_selection.mjs
	/usr/bin/env node scripts/test_device_choice.mjs
	/usr/bin/env python3 tests/PatchManifestTests.py

$(BUILD_DIR)/process-runner-tests: app/ProcessRunner.swift tests/ProcessRunnerTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -parse-as-library -o $@

test-process-runner: $(BUILD_DIR)/process-runner-tests
	./$(BUILD_DIR)/process-runner-tests

$(BUILD_DIR)/assistant-status-tests: app/AssistantStatus.swift tests/AssistantStatusTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -parse-as-library -o $@

test-assistant-status: $(BUILD_DIR)/assistant-status-tests
	./$(BUILD_DIR)/assistant-status-tests

$(BUILD_DIR)/assistant-layout-tests: app/USBKeyAssistant.swift app/AssistantStatus.swift app/ProcessRunner.swift app/AssistantTheme.swift app/AssistantUpdate.swift app/AssistantUpdateInstall.swift app/AssistantUpdateWindow.swift app/CertificatePinStore.swift tests/AssistantLayoutTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -D ASSISTANT_UI_TEST -parse-as-library -framework AppKit -framework Security -o $@

test-assistant-layout: $(BUILD_DIR)/assistant-layout-tests
	./$(BUILD_DIR)/assistant-layout-tests

app package:
	/bin/sh scripts/build_release.sh

clean:
	rm -f $(PROBES)

$(BUILD_DIR)/assistant-update-tests: app/AssistantUpdate.swift tests/AssistantUpdateTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -parse-as-library -o $@

test-assistant-update: $(BUILD_DIR)/assistant-update-tests
	./$(BUILD_DIR)/assistant-update-tests

$(BUILD_DIR)/assistant-install-tests: app/AssistantUpdate.swift app/AssistantUpdateInstall.swift app/ProcessRunner.swift tests/AssistantUpdateInstallTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -parse-as-library -o $@

# Mounts a real disk image and replaces an installed copy in a temporary folder.
test-assistant-install: $(BUILD_DIR)/assistant-install-tests
	./$(BUILD_DIR)/assistant-install-tests

.PHONY: test-desktop-entry
test-desktop-entry:
	/usr/bin/env python3 tests/DesktopEntryTests.py

$(BUILD_DIR)/assistant-restart-tests: app/USBKeyAssistant.swift app/AssistantStatus.swift app/ProcessRunner.swift app/AssistantTheme.swift app/AssistantUpdate.swift app/AssistantUpdateInstall.swift app/AssistantUpdateWindow.swift app/CertificatePinStore.swift tests/AssistantRestartTests.swift | $(BUILD_DIR)
	/usr/bin/xcrun swiftc $^ -D ASSISTANT_UI_TEST -parse-as-library -framework AppKit -framework Security -o $@

.PHONY: test-assistant-restart
test-assistant-restart: $(BUILD_DIR)/assistant-restart-tests
	./$(BUILD_DIR)/assistant-restart-tests
