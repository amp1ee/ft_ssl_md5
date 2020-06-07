/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:45:08 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:45:10 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memmove(void *dst, const void *src, size_t len)
{
	unsigned char	*p_dst;
	unsigned char	*p_src;

	p_dst = (unsigned char *)dst;
	p_src = (unsigned char *)src;
	if (p_src < p_dst)
	{
		p_src = p_src + len - 1;
		p_dst = p_dst + len - 1;
		while (len > 0)
		{
			*(p_dst--) = *(p_src--);
			len--;
		}
	}
	else
	{
		while (len > 0)
		{
			*(p_dst++) = *(p_src++);
			len--;
		}
	}
	return (dst);
}
