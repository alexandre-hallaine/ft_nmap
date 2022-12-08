NAME	:= nmap
#CFLAGS	:= -Wall -Wextra -Werror -Ofast

HEADERS	:= -I ./include
LIBS	:= -lpcap -lpthread
SRCDIR	:= ./src
OBJDIR	:= ./obj
SRCS	:= $(shell cd $(SRCDIR) && find . -name "*.c")
OBJS	:= $(SRCS:%.c=$(OBJDIR)/%.o)

all: $(NAME)

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ -c $< $(HEADERS) && echo "Compiling: $(notdir $<)"

$(NAME): $(OBJS)
	$(CC) $(OBJS) $(LIBS) $(HEADERS) -o $(NAME)

clean:
	rm -rf $(OBJDIR)
	$(MAKE) -C $(LIBMLX) clean

fclean: clean
	rm -f $(NAME)
	$(MAKE) -C $(LIBMLX) fclean

re: clean all

.PHONY: all, clean, fclean, re
.SILENT: