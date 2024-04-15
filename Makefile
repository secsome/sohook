CC = gcc
CFLAGS = -Wall -Wextra

TARGET_DEBUG = sohookd
TARGET_RELEASE = sohook
TEST_SO = test.so
TEST_SRC = test.c

SRCS = launcher.c hookdata.c elfhelper.c utils.c dynamic.c static.c vector.c debugger.c
OBJS = $(SRCS:.c=.o)
DBGOBJS = $(SRCS:.c=.od)

.PHONY: all clean

all: debug release

debug: $(TARGET_DEBUG)

release: $(TARGET_RELEASE)

$(TARGET_DEBUG): $(DBGOBJS)
	$(CC) $(CFLAGS) -g -o $@ $^

$(TARGET_RELEASE): $(OBJS)
	$(CC) $(CFLAGS) -O2 -o $@ $^

%.od: %.c
	$(CC) $(CFLAGS) -g -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) -O2 -c $< -o $@

test: $(TEST_SRC)
	$(CC) $(TEST_SRC) -shared -fPIC -o $(TEST_SO)

clean:
	rm -f $(TARGET_DEBUG) $(TARGET_RELEASE) $(OBJS) $(DBGOBJS)