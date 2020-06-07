/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/02/04 16:56:28 by oahieiev          #+#    #+#             */
/*   Updated: 2018/02/04 16:56:29 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static int	ind(char digit, int base)
{
	int			ind;
	const char	*abc = "0123456789abcdef";

	ind = 0;
	while (ind < base &&
		(digit != abc[ind] && digit != ft_toupper(abc[ind])))
		ind++;
	return (ind);
}

int			ft_atoi_base(char *num, int base)
{
	int		res;
	int		len;
	int		i;
	int		index;

	if (base == 10)
		return (ft_atoi(num));
	if (base < 2)
		return (0);
	len = ft_strlen(num);
	res = 0;
	i = num[0] == '-' ? 1 : 0;
	while (i < len)
	{
		index = ind(num[i++], base);
		if (index == base)
			return (0);
		res = res * base + index;
	}
	return (num[0] == '-' ? -res : res);
}
