/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstmap.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2017/11/02 21:07:45 by oahieiev          #+#    #+#             */
/*   Updated: 2017/11/02 21:17:57 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

t_list		*ft_lstmap(t_list *lst, t_list *(*f)(t_list *elem))
{
	t_list	*fresh_h;
	t_list	*fresh;
	t_list	*tmp;

	if (!lst || !f)
		return (NULL);
	tmp = f(lst);
	if (!(fresh = ft_lstnew(tmp->content, tmp->content_size)))
		return (NULL);
	fresh_h = fresh;
	while (lst->next)
	{
		lst = lst->next;
		tmp = f(lst);
		if (!(fresh->next = ft_lstnew(tmp->content, tmp->content_size)))
		{
			ft_lstdel(&fresh_h, &ft_bzero);
			return (NULL);
		}
		fresh = fresh->next;
	}
	return (fresh_h);
}
