#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include <errno.h>
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
 * Unseal with TPM from TPM NVRAM
 */
static bool unseal_nv(uint32_t address, uint8_t** buffer, size_t* out_length) {
        uint8_t* blob = NULL;
        uint32_t blob_length = 0, length = 0, err;
        uint32_t parent_key_handle = TPM_KH_SRK;
        // well known password
        unsigned char pass[20] = {0};

        blob_length = 1024;
        blob = (uint8_t*) malloc(blob_length);
        err = TPM_NV_ReadValue(address, 0, blob_length, blob, &blob_length, NULL);
        if (err) {
                free(blob);
                fprintf(stderr, "Error from TPM_NV_ReadValue: %s\n", TPM_GetErrMsg(err));
                return false;
        }

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

/**
 * Unseal with TPM from file
 */
static bool unseal_file(const char* filename, uint8_t** buffer, size_t* out_length) {
        uint8_t* blob = NULL;
        uint32_t blob_length = 0, length = 0, err;
        int fd;
        struct stat st = { 0 };
        uint32_t parent_key_handle = TPM_KH_SRK;
        // well known password
        unsigned char pass[20] = {0};

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
        uint32_t nv_address = (uint32_t) -1;
        FILE* output = stdout;
        uint8_t* buffer;
        size_t length;
        int ret = 1;
        bool unseal;

        if (2 > argc || argc > 4) {
                fprintf(stderr, "Illegal number of arguments.");
                return 1;
        }
        if (argc == 2) {
                if (strncmp(argv[1], "nv:", 3) == 0) {
                        errno = 0;
                        char* ep;
                        long value = strtol(argv[1] + 5, &ep, 16);
                        if ((errno == ERANGE && (value == LONG_MAX || value == LONG_MIN)) || (errno != 0 && value == 0)) {
                                fprintf(stderr, "Illegal NV address\n");
                                return 1;
                        } else if (value < 0 && value > UINT32_MAX) {
                                fprintf(stderr, "Illegal NV address\n");
                                return 1;
                        } else {
                                nv_address = (uint32_t) value;
                        }
                } else {
                        keyfilename = argv[1];
                }
        }
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

        init_gcrypt();

        if (keyfilename) {
                unseal = unseal_file(keyfilename, &buffer, &length);
        } else {
                unseal = unseal_nv(nv_address, &buffer, &length);
        }
        if (unseal) {
                ret = 0;
                if (output) {
                        fwrite((char*) buffer, 1, length, output);
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
