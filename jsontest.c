#include <stdio.h>
#include <string.h>

#define JSON_IMPL
#include "json.h"

const char *test = "{\"name\":\"value\", \"want\":\"wantvalue\"}";

int main(int argc, char *argv[])
{
    char *namevalue;
    int namevaluelen;

    ParseJson((char *)test,
              strlen(test),
              "name",
              &namevalue,
              &namevaluelen);

    printf("%.*s\n", namevaluelen, namevalue);


    ParseJson((char *)test,
              strlen(test),
              "want",
              &namevalue,
              &namevaluelen);

    printf("%.*s\n", namevaluelen, namevalue);



    return 0;
}