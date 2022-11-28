#!/bin/bash

# sin ninguna contramedida (ASLR, canarios de pila y pila no ejecutable)
sudo sysctl -w kernel.randomize_va_space=0
gcc -m32 -fno-stack-protector -z execstack -ggdb cifrado.c -o cifrado0

# pila no ejecutable
gcc -m32 -fno-stack-protector -ggdb cifrado.c -o cifrado1

# canarios de pila
gcc -m32 -z execstack -ggdb cifrado.c -o cifrado2

# ASLR
sudo sysctl -w kernel.randomize_va_space=1
gcc -m32 -fno-stack-protector -z execstack -ggdb cifrado.c -o cifrado3

# BUCLE FOR DE 0 A 3
for i in {0..3}
do
  sudo chown root cifrado${i}
  sudo chmod 4755 cifrado${i}
done
