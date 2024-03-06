NAME        := dhcp-stats 
SRCS        := utils.c parser.c main.c
OBJS        := utils.o parser.o main.o
CC          :=	gcc	 
CFLAGS      := -Wextra -pedantic -g -std=gnu99 -lpcap -lncurses
RM          := rm -f
MAKEFLAGS   += --no-print-directory

all: $(OBJS) 
	$(CC) $(CFLAGS) -o $(NAME) $^

clean:
	$(RM) $(OBJS)
	$(RM) vgcore.*
	$(RM) tests

fclean: clean
	$(RM) $(NAME)
	

re:
	$(MAKE) fclean
	$(MAKE) all


tests: $(SRCS)
	$(CC) $(CFLAGS) -DTESTING -o $@ $^
	./$@

.PHONY: clean fclean re
