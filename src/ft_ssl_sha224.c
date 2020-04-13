#include "ft_ssl_md5.h"

void				init_sha224_context(t_context *ctx)
{
	ctx->sha2[A] = 0xC1059ED8;
	ctx->sha2[B] = 0x367CD507;
	ctx->sha2[C] = 0x3070DD17;
	ctx->sha2[D] = 0xF70E5939;
	ctx->sha2[E] = 0xFFC00B31;
	ctx->sha2[F] = 0x68581511;
	ctx->sha2[G] = 0x64F98FA7;
	ctx->sha2[H] = 0xBEFA4FA4;
}
