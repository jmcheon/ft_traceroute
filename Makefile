NAME    := ft_traceroute
CC      := cc
CFLAGS  := -Wall -Wextra -Werror -Iinc

SRC_DIR := src
OBJ_DIR := obj
SRCS    := main.c trace.c output.c
OBJS    := $(SRCS:%.c=$(OBJ_DIR)/%.o)

all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDLIBS) -o $@

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c inc/ft_traceroute.h | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR):
	mkdir -p $@

clean:
	rm -rf $(OBJ_DIR)

fclean: clean
	rm -f $(NAME)

re: fclean all

.PHONY: all clean fclean re
