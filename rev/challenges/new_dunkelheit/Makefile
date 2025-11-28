.PHONY: all pack

BINARY := dunkelheit
RELEASE_BINARY := target/release/$(BINARY)
FINAL_BINARY := $(BINARY)

all:
	cargo build --release
	cp $(RELEASE_BINARY) $(FINAL_BINARY)
	strip --strip-all $(FINAL_BINARY)
	strip --remove-section=.comment $(FINAL_BINARY)
	strip --remove-section=.note $(FINAL_BINARY)
	strip --remove-section=.note.gnu.build-id $(FINAL_BINARY)
	strip --remove-section=.note.ABI-tag $(FINAL_BINARY)
	objcopy --remove-section=.eh_frame $(FINAL_BINARY) 2>/dev/null || true
	objcopy --remove-section=.eh_frame_hdr $(FINAL_BINARY) 2>/dev/null || true
	touch -t 197001010000 $(FINAL_BINARY) 2>/dev/null || true
	chmod +x $(FINAL_BINARY)
