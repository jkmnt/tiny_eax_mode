FLAGS := -O2 -std=c99 -Wall

all: eax_xtea_test.exe

eax_xtea_test.exe: crypt64.c eax_xtea_test.c
	gcc $(FLAGS) --output $@ $^

clean:
	rm -f *.exe

