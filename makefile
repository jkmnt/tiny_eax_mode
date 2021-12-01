FLAGS := -O2 -std=c99 -Wall

all: eax_xtea_test.exe eax_aes_test.exe

eax_xtea_test.exe: eax64.c eax_xtea_test.c
	gcc $(FLAGS) --output $@ $^

eax_aes_test.exe: eax128.c eax_aes_test.c aes128.c
	gcc $(FLAGS) --output $@ $^

clean:
	rm -f *.exe

