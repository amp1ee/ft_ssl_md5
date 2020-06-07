/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memcpy.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:46:25 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:46:45 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	*ft_memcpy(void *dst, const void *src, size_t n)
{
	size_t			i;
	size_t			m;
	unsigned long	*w_ptr[2];
	unsigned char	*p_dst;
	unsigned char	*p_src;

	w_ptr[0] = (unsigned long *)dst;
	w_ptr[1] = (unsigned long *)src;
	i = 0;
	m = n / sizeof(long);
	while (i++ < m)
		*((w_ptr[0])++) = *((w_ptr[1])++);
	p_dst = (unsigned char *)w_ptr[0];
	p_src = (unsigned char *)w_ptr[1];
	i = 0;
	m = n % sizeof(long);
	while (i++ < m)
		*(p_dst++) = *(p_src++);
	return (dst);
}
