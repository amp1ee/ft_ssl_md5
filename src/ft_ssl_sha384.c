#include "ft_ssl_md5.h"
#include "ft_sha5.h"

void				init_sha384_context(t_context *ctx)
{
	ctx->sha5[A] = 0xcbbb9d5dc1059ed8;
	ctx->sha5[B] = 0x629a292a367cd507;
	ctx->sha5[C] = 0x9159015a3070dd17;
	ctx->sha5[D] = 0x152fecd8f70e5939;
	ctx->sha5[E] = 0x67332667ffc00b31;
	ctx->sha5[F] = 0x8eb44a8768581511;
	ctx->sha5[G] = 0xdb0c2e0d64f98fa7;
	ctx->sha5[H] = 0x47b5481dbefa4fa4;
}
