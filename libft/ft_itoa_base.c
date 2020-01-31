/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa_base.c                                     :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/02/04 16:55:33 by oahieiev          #+#    #+#             */
/*   Updated: 2018/02/04 16:55:34 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char	*ft_itoa_base(long long value, int base, char letter)
{
	int		i;
	int		neg;
	char	*res;
	char	c;

	neg = (value < 0) ? 1 : 0;
	value = (value < 0) ? -value : value;
	i = 0;
	while (ft_pow(base, i) - 1 < value)
		i++;
	res = malloc(sizeof(char) * (i + neg));
	c = (letter == 'X') ? 'A' : 'a';
	while ((i--) >= 0)
	{
		res[i + neg] = (value % base) > 9 ? (value % base) - 10 + c :
		(value % base) + '0';
		value /= base;
	}
	if (neg)
		res[0] = '-';
	return (res);
}
