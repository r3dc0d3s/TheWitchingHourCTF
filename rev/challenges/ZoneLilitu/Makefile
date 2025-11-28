# ============================
# ZoneLilitu Makefile
# ============================

CC      = cc
SRC     = main.c
OUT     = zonelilitu

CFLAGS  = -O2 -Wall -Wextra
LDFLAGS =

UPX     = upx
STRIP   = strip

all: $(OUT)

$(OUT): $(SRC)
	@echo "[*] Compiling..."
	$(CC) $(CFLAGS) $(SRC) -o $(OUT)

	@echo "[*] Stripping symbols..."
	$(STRIP) $(OUT)

	@echo "[*] Packing with UPX..."
	$(UPX) -9 $(OUT)

	@echo "[+] Build complete -> $(OUT)"

clean:
	@echo "[*] Cleaning..."
	rm -f $(OUT)

rebuild: clean all

