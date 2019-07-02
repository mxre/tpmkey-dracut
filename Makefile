.SILENT:
.PHONY: clean all install

all: tpmkey/tpmkey

clean:
	make -C tpmkey clean

tpmkey/tpmkey:
	make -C tpmkey

DRACUT_MODULES=/usr/lib/dracut/modules.d

install: install_crypt_lib install_tpm

install_tpm: tpmkey/tpmkey modules.d/91crypt-tpm/module-setup.sh modules.d/91crypt-tpm/crypt-tpm-lib.sh
	@echo -e "\x1b[31mINST\x1b[0m $^"
	install -D -m 0755 --target-directory="$(DRACUT_MODULES)/91crypt-tpm" $^

install_crypt_lib: modules.d/90crypt/parse-keydev.sh modules.d/90crypt/crypt-lib.sh 
	@echo -e "\x1b[31mINST\x1b[0m $^"
	install -D -m 0755 --target-directory="$(DRACUT_MODULES)/90crypt" $^
