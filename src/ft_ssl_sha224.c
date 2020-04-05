#include "ft_ssl_md5.h"

void				init_sha224_context(t_context *ctx)
{
	ctx->sha2[0] = 0xC1059ED8;
	ctx->sha2[1] = 0x367CD507;
	ctx->sha2[2] = 0x3070DD17;
	ctx->sha2[3] = 0xF70E5939;
	ctx->sha2[4] = 0xFFC00B31;
	ctx->sha2[5] = 0x68581511;
	ctx->sha2[6] = 0x64F98FA7;
	ctx->sha2[7] = 0xBEFA4FA4;
}
