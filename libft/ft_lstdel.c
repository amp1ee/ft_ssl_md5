/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstdel.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:06:34 by oahieiev          #+#    #+#             */
/*   Updated: 2018/05/13 16:35:55 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstdel(t_list **alst, void (*del)(void *, size_t))
{
	t_list	*tmp;

	if (!alst || !del)
		return ;
	while (*alst)
	{
		tmp = *alst;
		if (tmp->content)
		{
			del(tmp->content, tmp->content_size);
			free(tmp->content);
			tmp->content = NULL;
		}
		*alst = (*alst)->next;
		free(tmp);
		tmp = NULL;
	}
}
