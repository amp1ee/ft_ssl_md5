NAME = ft_ssl

SRCDIR   = ./src/
OBJDIR   = ./obj/
INCDIR   = ./include/
LIBFTDIR = ./libft/
SRC = $(addprefix $(SRCDIR),	ft_ssl_md5.c \
								ft_ssl_sha256.c)
OBJ = $(SRC:$(SRCDIR)%.c=$(OBJDIR)%.o)
HEADERS = $(wildcard $(INCDIR)*.h)

CC = gcc
LIBFT	 = $(addprefix $(LIBFTDIR), libft.a)
CFLAGS   = -Wall -Wextra -Werror
ifdef DEBUG
	CFLAGS += -g -DDEBUG=1
endif
LDFLAGS	 = -L$(LIBFTDIR) -lft

.PHONY: all clean fclean re

all: $(NAME)

$(NAME): $(OBJ) $(LIBFT)
	$(info Linking objects)
	@$(CC) $(OBJ) $(LDFLAGS) -o $(NAME)
	$(info Done.)

$(OBJDIR)%.o: $(SRCDIR)%.c $(HEADERS)
	$(info Compiling $<)
	@mkdir -p $(OBJDIR)
	@$(CC) $(CFLAGS) -c $< -o $@ -I$(INCDIR) -I$(LIBFTDIR)

$(LIBFT):
	@make -sC $(LIBFTDIR)

clean:
	$(info Deleting objects)
	@rm -rf $(OBJDIR)
	@make -sC $(LIBFTDIR) clean

fclean: clean
	$(info Deleting $(NAME))
	@rm -rf $(NAME)
#	@make -sC $(LIBFTDIR) fclean

re: fclean all
