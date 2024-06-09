%{
#include "parser.tab.h"
#include <stdio.h>
#include <stdlib.h>
%}

%%

"int"           { return INT; }
"return"        { return RETURN; }
"main"          { return MAIN; }
"void"          { return VOID; }
"println_int"   { return PRINTLN_INT; }


"+"             { return PLUS; }
"-"             { return MINUS; }
"*"             { return MUL; }
"/"             { return DIV; }
"%"             { return MOD; }

"<"             { return LT; }
"<="            { return LE; }
">"             { return GT; }
">="            { return GE; }
"=="            { return EQ; }
"!="            { return NE; }
"&&"            { return AND; }
"||"            { return OR; }
"!"             { return NOT; }
"~"             { return BIT_NOT; }
"&"             { return BIT_AND; }
"|"             { return BIT_OR; }
"^"             { return BIT_XOR; }

"="             { return ASSIGN; }

";"             { return SEMICOLON; }
"{"             { return LBRACE; }
"}"             { return RBRACE; }
"("             { return LPAREN; }
")"             { return RPAREN; }

[0-9]+          { yylval.ival = atoi(yytext); return NUMBER; }
[A-Za-z_][A-Za-z0-9_]* { yylval.sval = strdup(yytext); return IDENTIFIER; }

[ \t\n]+        { /* ignore whitespace */ }
.               { fprintf(stderr, "Unexpected character: %s\n", yytext); exit(1); }

%%

int yywrap(void) {
    return 1;
}
