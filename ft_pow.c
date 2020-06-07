/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_pow.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:18:31 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:18:32 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

long long		ft_pow(long long nb, int pow)
{
	long long	res;

	res = 1;
	if (pow == 0)
		return (1);
	while (pow > 0)
	{
		res *= nb;
		pow--;
	}
	return (res);
}
