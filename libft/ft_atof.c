/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_atof.c                                          :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/10/12 19:41:16 by oahieiev          #+#    #+#             */
/*   Updated: 2019/10/12 19:41:18 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

static inline double	parse_fraction(char *str)
{
	double				fract;
	int					divisor;
	char				*tmp;

	fract = 0.0;
	divisor = 1;
	tmp = (char *)str;
	while (*tmp && ft_isdigit(*tmp))
	{
		divisor *= 10;
		tmp++;
	}
	if (*str)
		fract = (double)ft_atoi(str);
	fract = (fract / (double)divisor);
	return (fract);
}

double					ft_atof(const char *str)
{
	int					sign;
	int					whole;
	double				fract;
	double				res;

	res = 0;
	sign = 1;
	while (ft_isdelim(*str))
		str++;
	if (*str == '-')
		sign = -1;
	if (*str == '-' || *str == '+')
		str++;
	whole = ft_atoi(str);
	while (*str && ft_isdigit(*str))
		str++;
	if (*str && *str == '.')
		str++;
	fract = parse_fraction((char *)str);
	res = whole + fract;
	return (sign * res);
}
