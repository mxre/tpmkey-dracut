#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <gcrypt.h>
#include <tpmfunc.h>

static inline void init_gcrypt() {
        if (!gcry_check_version (GCRYPT_VERSION)) {
                fputs("libgcrypt version mismatch: compiled for version " GCRYPT_VERSION "\n", stderr);
                exit(2);
        }

        gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
        gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}

/**
 * Unseal key with TPM, store string in keyring
 */
static bool unseal_key(const char* filename) {
        uint8_t* blob = NULL;
        uint8_t buffer[100] = { 0 };
        uint32_t blob_length = 0;
        uint32_t length = 100;
        uint32_t err;
        int fd;
        struct stat st = { 0 };
        uint32_t parent_key_handle = TPM_KH_SRK;
        // well known password
        unsigned char pass[20] = {0};

        init_gcrypt();

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
                fprintf(stderr, "Could not open key from '%s': %m\n", filename);
                return false;
        }

        fstat(fd, &st);
        blob_length = st.st_size;
        blob = (uint8_t*) malloc(blob_length);

        if (read(fd, blob, blob_length) < 0) {
                fprintf(stderr, "Could not read key from '%s': %m\n", filename);
                close(fd);
                free(blob);
                return false;
        }
        close(fd);

        err = TPM_Unseal(parent_key_handle, pass, NULL, blob, blob_length, buffer, &length);
        free(blob);
        buffer[length] = '\0';

        if (!err) {
                if (length >= 100) {
                        fprintf(stderr, "Key is too long, systemd does not like that\n");
                        return false;
                }

               fputs((char*) buffer, stdout);
               fflush(stdout);
        } else {
                fprintf(stderr, "Error %s from TPM_Unseal\n", TPM_GetErrMsg(err));
                return false;
        }

        return true;
}

int main (int argc, char* argv[]) {
        char* keyfilename;

        if (argc != 2) {
                fprintf(stderr, "Need filename as parameter.\n");
                return 1;
        }
        keyfilename = argv[1];

        return unseal_key(keyfilename) ? 0 : 1;
}
