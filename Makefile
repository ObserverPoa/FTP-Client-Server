OBJS1 = cli.c
OBJS2 = srv.c
EXEC1 = cli
EXEC2 = srv

CFLAGS = -g

CC = gcc

all: cli srv

cli: $(OBJS1)
	$(CC) $(OBJS1) -o $(EXEC1)

srv: $(OBJS2)
	$(CC) $(OBJS2) -o $(EXEC2)

clean:
	rm -rf $(EXEC1) $(EXEC2)
