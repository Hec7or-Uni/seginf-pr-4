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

## Conclusiones

## Referencias 


magicmagicmagicmagicmagicmagicmagicmagicmagicmagicmagicmagicmagi
magicmagicmagicmagicmagicmagicma
2147483647