/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_itoa.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 21:44:27 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 21:44:28 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

char		*ft_itoa(int n)
{
	int		i;
	int		neg;
	char	*str;

	if (n == -2147483648)
		return (ft_strdup("-2147483648"));
	i = 1;
	neg = (n < 0) ? 1 : 0;
	n *= (n < 0) ? -1 : 1;
	while (ft_pow(10, i) - 1 < n)
		if ((i++) > 8)
			break ;
	if (!(str = (char *)malloc(sizeof(char) * (i + neg + 1))))
		return (0);
	str[i + neg] = '\0';
	while (str && i > 0)
	{
		str[(i--) + neg - 1] = (n % 10) + '0';
		n /= 10;
	}
	if (neg)
		str[0] = '-';
	return (str);
}
