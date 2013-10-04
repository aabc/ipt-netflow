/* MurmurHash3, based on https://code.google.com/p/smhasher of Austin Appleby. */

static __always_inline uint32_t rotl32(const uint32_t x, const int8_t r)
{
	return (x << r) | (x >> (32 - r));
}

static __always_inline uint32_t fmix32(register uint32_t h)
{
	h ^= h >> 16;
	h *= 0x85ebca6b;
	h ^= h >> 13;
	h *= 0xc2b2ae35;
	h ^= h >> 16;
	return h;
}

static inline uint32_t murmur3(const void *key, const uint32_t len, const uint32_t seed)
{
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	const uint32_t *blocks;
	const uint8_t *tail;
	register uint32_t h1 = seed;
	uint32_t k1 = 0;
	uint32_t i;

	blocks = (const uint32_t *)key;
	for (i = len / 4; i; --i) {
		h1 ^= rotl32(*blocks++ * c1, 15) * c2;
		h1 = rotl32(h1, 13) * 5 + 0xe6546b64;
	}
	tail = (const uint8_t*)blocks;
	switch (len & 3) {
		case 3: k1 ^= tail[2] << 16;
		case 2: k1 ^= tail[1] << 8;
		case 1: k1 ^= tail[0];
			h1 ^= rotl32(k1 * c1, 15) * c2;
	}
	return fmix32(h1^ len);
}

