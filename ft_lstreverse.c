/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstreverse.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: oahieiev <marvin@42.fr>                    +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2018/05/08 15:30:11 by oahieiev          #+#    #+#             */
/*   Updated: 2018/05/08 15:30:13 by oahieiev         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_lstreverse(t_list **head)
{
	t_list	*temp;
	t_list	*temp2;
	t_list	*list;

	if (head == NULL)
		return ;
	list = *head;
	temp = NULL;
	while (list != NULL)
	{
		temp2 = list->next;
		list->next = temp;
		temp = list;
		list = temp2;
	}
	if (temp != NULL)
		*head = temp;
}
