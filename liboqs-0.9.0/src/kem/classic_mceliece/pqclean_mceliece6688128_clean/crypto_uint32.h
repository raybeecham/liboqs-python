#ifndef PQCLEAN_MCELIECE6688128_CLEAN_crypto_uint32_h
#define PQCLEAN_MCELIECE6688128_CLEAN_crypto_uint32_h

#include <inttypes.h>
typedef uint32_t crypto_uint32;

typedef int32_t crypto_uint32_signed;

#include "namespace.h"

#define crypto_uint32_signed_negative_mask CRYPTO_NAMESPACE(crypto_uint32_signed_negative_mask)
crypto_uint32_signed crypto_uint32_signed_negative_mask(crypto_uint32_signed crypto_uint32_signed_x);
#define crypto_uint32_nonzero_mask CRYPTO_NAMESPACE(crypto_uint32_nonzero_mask)
crypto_uint32 crypto_uint32_nonzero_mask(crypto_uint32 crypto_uint32_x);
#define crypto_uint32_zero_mask CRYPTO_NAMESPACE(crypto_uint32_zero_mask)
crypto_uint32 crypto_uint32_zero_mask(crypto_uint32 crypto_uint32_x);
#define crypto_uint32_unequal_mask CRYPTO_NAMESPACE(crypto_uint32_unequal_mask)
crypto_uint32 crypto_uint32_unequal_mask(crypto_uint32 crypto_uint32_x, crypto_uint32 crypto_uint32_y);
#define crypto_uint32_equal_mask CRYPTO_NAMESPACE(crypto_uint32_equal_mask)
crypto_uint32 crypto_uint32_equal_mask(crypto_uint32 crypto_uint32_x, crypto_uint32 crypto_uint32_y);
#define crypto_uint32_smaller_mask CRYPTO_NAMESPACE(crypto_uint32_smaller_mask)
crypto_uint32 crypto_uint32_smaller_mask(crypto_uint32 crypto_uint32_x, crypto_uint32 crypto_uint32_y);
#define crypto_uint32_min CRYPTO_NAMESPACE(crypto_uint32_min)
crypto_uint32 crypto_uint32_min(crypto_uint32 crypto_uint32_x, crypto_uint32 crypto_uint32_y);
#define crypto_uint32_max CRYPTO_NAMESPACE(crypto_uint32_max)
crypto_uint32 crypto_uint32_max(crypto_uint32 crypto_uint32_x, crypto_uint32 crypto_uint32_y);
#define crypto_uint32_minmax CRYPTO_NAMESPACE(crypto_uint32_minmax)
void crypto_uint32_minmax(crypto_uint32 *crypto_uint32_a, crypto_uint32 *crypto_uint32_b);

#endif
