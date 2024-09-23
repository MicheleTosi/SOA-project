#ifndef _SHA256_H
#define _SHA256_H

#define SHA256_LENGTH 32

extern int calculate_sha256(const char *password, size_t password_len, u8 *hashed_password);

extern int verify_password(const char *input_password, size_t input_password_len, const u8 *stored_hash);

extern void print_hash(const u8 *password);

#endif // SHA256_H
