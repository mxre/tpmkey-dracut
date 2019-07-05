#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <keyutils.h>
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
static bool unseal_key(const char* filename, uint8_t** buffer, size_t* out_length) {
        uint8_t* blob = NULL;
        uint32_t blob_length = 0, length = 0, err;
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

        length = blob_length;
        *buffer = (uint8_t*) malloc(length);
        
        err = TPM_Unseal(parent_key_handle, pass, NULL, blob, blob_length, *buffer, &length);
        free(blob);
        (*buffer)[length] = '\0';

        if (!err) {
                *out_length = length;
        } else {
                free(*buffer);
                fprintf(stderr, "Error from TPM_Unseal: %s\n", TPM_GetErrMsg(err));
                return false;
        }

        return true;
}

int main (int argc, char* argv[]) {
        char* keyfilename = NULL, * outfile = NULL;
        FILE* output = stdout;
        uint8_t* buffer;
        size_t length;
        int ret = 1;

        if (argc < 2 || argc > 4) {
                fprintf(stderr, "Need filename as parameter.\n");
                return 1;
        }
        keyfilename = argv[1];
        if (argc == 3) {
                if (strncmp(argv[2], "key:", 4) == 0) {
                        outfile = argv[2] + 4;
                        output = NULL;
                } else {
                        outfile = argv[2];
                        
                        if (!(output = fopen(outfile, "wb"))) {
                                fprintf(stderr, "Could not open '%s' for writing: %m\n", outfile);
                                return 1;
                        }
                }
        }

        if (unseal_key(keyfilename, &buffer, &length)) {
                ret = 0;
                if (output) {
                        fputs((char*) buffer, output);
                        fflush(output);
                } else {
                        key_serial_t key_id = add_key("user", outfile, buffer, length, KEY_SPEC_SESSION_KEYRING);
                        if (key_id < 0) {
                                fprintf(stderr, "Could not insert key in keyring: %m\n");
                                ret = 1;
                        } else {
                                keyctl_set_timeout(key_id, 60);
                                keyctl_setperm(key_id, (key_perm_t) 0x3f000000);
                        }
                }
                free(buffer);
        }

        if (outfile && output) {
                if (ftell(output) == 0) {
                        ret = 1;
                        unlink(outfile);
                }
                fclose(output);
        }

        return ret;
}
