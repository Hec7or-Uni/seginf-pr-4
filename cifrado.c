#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ----------  Constantes -----------------
#define MENU                                                               \
  "Hola! Menú:\n 1. Escribir palabra\n 2. Cifrar\n 3. Ver palabras\n 4. " \
  "Terminar\n"
#define X "Bien! Primer logro conseguido\n"
#define XX                                                                     \
  "Bravo!! Segundo logro conseguido...falta la inyección de una shell. ¿Te " \
  "atreves?\n"
#define COMM_SIZE 5
#define MAX_SIZE 64
#define N_ALFA 26
// ----------------------------------------

typedef int (*func_ptr)();

struct palabraCifrada {
  char palabra[MAX_SIZE];
  char cifrado[MAX_SIZE];
  unsigned offset;
  struct palabraCifrada *next;

} *lista = NULL;

int mostrarSecreto2() {
  printf(XX);
  return 0;
}

int mostrarSecreto1() {
  printf(X);
  return 0;
}

// ------------- escribir texto ----------------------
int escribirPalabra() {
  printf("Escribe la palabra:\n");
  char palabra[MAX_SIZE];
  memset(palabra, 0, MAX_SIZE);
  scanf("%s", palabra);
  printf("Escribe desplazamiento:\n");
  unsigned offset;
  scanf("%u", &offset);

  struct palabraCifrada *l =
      (struct palabraCifrada *)malloc(sizeof(struct palabraCifrada));

  if (l != NULL) {
    strcpy(l->palabra, palabra);
    l->offset = offset;
    l->next = NULL;
    if (lista == NULL) {
      lista = l;
    } else {
      struct palabraCifrada *p = lista;
      while (p->next != NULL) {
        p = p->next;
      }
      p->next = l;
    }
  }

  return 0;
}

// ------------- cifrar palabra ------------------------
int cifrar() {
  for (struct palabraCifrada *p = lista; p != NULL; p = p->next) {
    if (strlen(p->cifrado) == 0) {
      p->offset = p->offset % N_ALFA;
      // Cifrado César
      unsigned i = 0;
      while (p->palabra[i]) {
        p->cifrado[i] = p->palabra[i] + p->offset;
        i++;
      }
    }
  }

  return 0;
}

// ------------- ver palabras ------------------------
int verPalabras() {
  for (struct palabraCifrada *p = lista; p != NULL; p = p->next) {
    char texto[MAX_SIZE] = "";
    strcat(texto, p->palabra);
    strcat(texto, "\t");
    strcat(texto, p->cifrado);
    printf("%s\t Offset: %u\n", texto, p->offset);
  }

  return 0;
}

// ------------- terminar el programa  ------------------------
int terminar() { return 1; }

int main() {
  int terminado = 0;
  func_ptr opt[COMM_SIZE] = {NULL, escribirPalabra, cifrar, verPalabras,
                             terminar};
  func_ptr extra[2] = {NULL, mostrarSecreto1};

  do {
    char resp[MAX_SIZE];

    printf(MENU);
    scanf("%s", resp);
    resp[strlen(resp)] = '\0';
    int s = atoi(resp);
    terminado = opt[s]();

  } while (!terminado);

  return 0;
}
