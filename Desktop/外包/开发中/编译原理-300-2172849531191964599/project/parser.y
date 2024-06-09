%{
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "codegen.h"

extern int yylex(void);
extern char *yytext;
extern int yylineno;

void yyerror(const char *s) { 
    fprintf(stderr, "Error: %s at line %d, before token: '%s'\n", s, yylineno, yytext);  
}

// int yydebug = 1; // 启用调试模式
%}

%union {
    int ival;
    char *sval;
}

%token <sval> IDENTIFIER
%token <ival> NUMBER
%token INT RETURN MAIN VOID
%token PLUS MINUS MUL DIV MOD
%token LT LE GT GE EQ NE AND OR NOT BIT_NOT BIT_AND BIT_OR BIT_XOR
%token ASSIGN
%token SEMICOLON LBRACE RBRACE LPAREN RPAREN
%token PRINTLN_INT  // 输出整数的 token
%token COMMA  // 添加逗号作为一个 token

%type <ival> expression
%type <sval> statements statement variable_declaration expression_statement return_statement function_call function_definition parameter_list variable_list
%type <sval> type parameter_declaration

%left OR
%left AND
%left BIT_OR
%left BIT_XOR
%left BIT_AND
%left EQ NE
%left LT LE GT GE
%left PLUS MINUS
%left MUL DIV MOD
%right NOT
%right BIT_NOT
%right UNARY_MINUS  // 声明 UNARY_MINUS 的优先级

%start program

%%

program:
    function {  }
    ;

function:
    type MAIN LPAREN RPAREN LBRACE statements RBRACE {
        generate_function_header("main");  // 生成 main 函数的头部
        
        $6; // Statements
        generate_function_footer("main");  // 生成 main 函数的尾部
    }
    | type IDENTIFIER LPAREN RPAREN LBRACE statements RBRACE {
        generate_function_header($2);
        
        $6; // Statements
        generate_function_footer($2);
    }
    | function_definition
    ;

type:
    INT { $$ = "INT";  }
    | VOID { $$ = "VOID";  }
    ;

statements:
    statement {  }
    | statements statement {  }
    ;

statement:
    variable_declaration
    | expression_statement
    | return_statement
    | function_call
    | println_statement  // 输出整数语句
    ;

println_statement:
    PRINTLN_INT LPAREN expression RPAREN SEMICOLON {
        // 生成输出整数的汇编代码
        
        generate_println_int($3);
    }
    ;

variable_declaration:
    type variable_list SEMICOLON {
        // 生成变量声明的汇编代码
        
        generate_variable_declaration($2);
    }
    ;

variable_list:
    IDENTIFIER {  }
    | IDENTIFIER ASSIGN expression {  }
    | variable_list COMMA IDENTIFIER {  }
    | variable_list COMMA IDENTIFIER ASSIGN expression {  }
    ;

expression_statement:
    expression SEMICOLON {  }
    | IDENTIFIER ASSIGN expression SEMICOLON {
        
        generate_assignment($1, $3);
    }
    ;

return_statement:
    RETURN expression SEMICOLON {
        
        generate_return($2);
    }
    ;

function_call:
    IDENTIFIER LPAREN RPAREN SEMICOLON {
        
        generate_function_call($1);
    }
    | IDENTIFIER LPAREN parameter_list RPAREN SEMICOLON {
        
        generate_function_call_with_params($1, $3);
    }
    ;

function_definition:
    type IDENTIFIER LPAREN parameter_list RPAREN LBRACE statements RBRACE {
        // 生成函数定义的汇编代码
        
        generate_function_header($2);
        $7; // Statements
        generate_function_footer($2);
    }
    | VOID IDENTIFIER LPAREN parameter_list RPAREN LBRACE statements RBRACE {
        
        generate_function_header($2);
        $7; // Statements
        generate_function_footer($2);
    }
    ;

parameter_list:
    /* empty */ {  }
    | parameter_declaration {  }
    | parameter_list COMMA parameter_declaration {  }
    ;

parameter_declaration:
    type IDENTIFIER {  }
    ;

expression:
    NUMBER {
        $$ = $1;
        
    }
    | IDENTIFIER {
        $$ = lookup_variable($1);
        
    }
    | expression PLUS expression {
        $$ = generate_add($1, $3);
        
    }
    | expression MINUS expression {
        $$ = generate_sub($1, $3);
        
    }
    | expression MUL expression {
        $$ = generate_mul($1, $3);
        
    }
    | expression DIV expression {
        $$ = generate_div($1, $3);
        
    }
    | expression MOD expression {
        $$ = generate_mod($1, $3);
        
    }
    | LPAREN expression RPAREN {
        $$ = $2;
        
    }
    | MINUS expression %prec UNARY_MINUS {
        $$ = -$2;
        
    }
    | NOT expression {
        $$ = !$2;
        
    }
    | BIT_NOT expression {
        $$ = ~$2;
        
    }
    | expression AND expression {
        $$ = $1 && $3;
        
    }
    | expression OR expression {
        $$ = $1 || $3;
        
    }
    | expression LT expression {
        $$ = $1 < $3;
        
    }
    | expression LE expression {
        $$ = $1 <= $3;
        
    }
    | expression GT expression {
        $$ = $1 > $3;
        
    }
    | expression GE expression {
        $$ = $1 >= $3;
        
    }
    | expression EQ expression {
        $$ = $1 == $3;
        
    }
    | expression NE expression {
        $$ = $1 != $3;
        
    }
    | expression BIT_AND expression {
        $$ = $1 & $3;
        
    }
    | expression BIT_OR expression {
        $$ = $1 | $3;
        
    }
    | expression BIT_XOR expression {
        $$ = $1 ^ $3;
        
    }
    ;

%%
