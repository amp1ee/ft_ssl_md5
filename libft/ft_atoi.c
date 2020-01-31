/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atoi.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:15:45 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/01 20:14:43 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_atoi(const char *str)
{
	int				sign;
	long long int	res;

	res = 0;
	sign = 1;
	while (ft_isdelim(*str))
		str++;
	if (*str == '-')
		sign = -1;
	if (*str == '-' || *str == '+')
		str++;
	while (*str && ft_isdigit(*str))
	{
		if ((res >= 922337203685477580) && ((*str - '0') > 7) && sign == 1)
			return (-1);
		else if ((res >= 922337203685477580) && ((*str - '0') > 8)
			&& sign == -1)
			return (0);
		res = (res * 10) + (*str - '0');
		str++;
	}
	return (sign * res);
}
