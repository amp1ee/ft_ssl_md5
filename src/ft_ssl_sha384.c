#include "ft_ssl_md5.h"
#include "ft_sha5.h"

void				init_sha384_context(t_context *ctx)
{
	ctx->sha5[0] = 0xcbbb9d5dc1059ed8;
	ctx->sha5[1] = 0x629a292a367cd507;
	ctx->sha5[2] = 0x9159015a3070dd17;
	ctx->sha5[3] = 0x152fecd8f70e5939;
	ctx->sha5[4] = 0x67332667ffc00b31;
	ctx->sha5[5] = 0x8eb44a8768581511;
	ctx->sha5[6] = 0xdb0c2e0d64f98fa7;
	ctx->sha5[7] = 0x47b5481dbefa4fa4;
}
