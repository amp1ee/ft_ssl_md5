/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_isdelim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/10/31 18:50:54 by oahieiev          #+#    #+#             */
/*   Updated: 2017/10/31 18:51:06 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

int		ft_isdelim(int c)
{
	return (c == ' ' || c == '\n' || c == '\t' ||
		c == '\v' || c == '\f' || c == '\r');
}
