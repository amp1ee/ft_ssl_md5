#include "ft_ssl_md5.h"

uint32_t			swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00)
		| ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}

uint64_t			swap_uint64(uint64_t val)
{
	val = ((val << 8) & 0xFF00FF00FF00FF00ULL)
		| ((val >> 8) & 0x00FF00FF00FF00FFULL);
	val = ((val << 16) & 0xFFFF0000FFFF0000ULL)
		| ((val >> 16) & 0x0000FFFF0000FFFFULL);
	return (val << 32) | (val >> 32);
}

uint128_t			swap_uint128(uint128_t val)
{
	val = ((val << 8) & (uint128_t)0xFF00FF00FF00FF00)
		| ((val >> 8) & (uint128_t)0x00FF00FF00FF00FF);
	val = ((val << 16) & (uint128_t)0xFFFF0000FFFF0000)
		| ((val >> 16) & (uint128_t)0x0000FFFF0000FFFF);
	val = ((val << 32) & (uint128_t)0xFFFFFFFF00000000)
		| ((val >> 32) & (uint128_t)0x00000000FFFFFFFF);
	return (val << 64) | (val >> 64);
}

void				swap_words(uint64_t *words, int wsize, int n)
{
	int i;

	i = -1;
	while (++i < n)
		(wsize == sizeof(uint64_t)) ? words[i] = swap_uint64(words[i])
		: (((uint32_t *)words)[i] = swap_uint32(((uint32_t *)words)[i]));
}

char				*bytes_to_ascii(uint64_t bytes, size_t size)
{
	const char		*hexbase = "0123456789abcdef";
	char			*ascii;
	size_t			i;
	size_t			j;

	if (!(ascii = ft_strnew(size << 1)))
		return (NULL);
	i = 0;
	j = 0;
	while (j < size)
	{
		ascii[i++] = hexbase[((unsigned char *)&bytes)[j] / 16];
		ascii[i++] = hexbase[((unsigned char *)&bytes)[j] % 16];
		j++;
	}
	return (ascii);
}
