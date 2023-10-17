NAME        := dhcp-stats 
SRCS        := main.c 
OBJS        := main.o 
CC          :=	gcc	 
CFLAGS      := -Wextra -pedantic -g -std=gnu99 -lpcap
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