
#include "cleanse.h"

#include <openssl/crypto.h>

void memory_cleanse(void *ptr, size_t len)
{
	OPENSSL_cleanse(ptr, len);
}