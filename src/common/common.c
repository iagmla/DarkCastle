void urandom (uint8_t *buf, int num_bytes) {
    FILE *randfile;
    randfile = fopen("/dev/urandom", "rb");
    fread(buf, num_bytes, 1, randfile);
    fclose(randfile);
}

void file_present(char *filename) {
    if (access(filename, F_OK) == -1 ) {
        printf("%s not found\n", filename);
        exit(1);
    }
}
