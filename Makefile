NAME = ft_ssl
CC = gcc
CFLAGS = -Wall -Wextra -Werror

SRCDIR   = ./src/
OBJDIR   = ./obj/
INCDIR   = ./include/
LIBFTDIR = ./libft/
SRC = $(addprefix $(SRCDIR), ft_ssl_md5.c)
OBJ = $(SRC:$(SRCDIR)%.c=$(OBJDIR)%.o)
HEADERS = $(wildcard $(INCDIR)*.h)

all: $(NAME)

$(NAME): $(OBJ)
	$(info Linking objects)
	@$(CC) $(OBJ) -o $(NAME)
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
	@make -sC $(LIBFTDIR) fclean

re: fclean all
