#ifndef CODEGEN_H
#define CODEGEN_H

#include <string>

void generate_function_header(const std::string &function_name);
void generate_function_footer(const std::string &function_name);
void generate_variable_declaration(const std::string &variable_name);
void generate_variable_declaration_with_initialization(const std::string &variable_name, int initial_value);
void generate_function_call_with_params(const std::string &function_name, const std::string &params);
void generate_assignment(const std::string &variable_name, int value);
void generate_println_int(int value);
void generate_return(int return_value);
void generate_function_call(const std::string &function_name);
int lookup_variable(const std::string &variable_name);
int generate_add(int operand1, int operand2);
int generate_sub(int operand1, int operand2);
int generate_mul(int operand1, int operand2);
int generate_div(int operand1, int operand2);
int generate_mod(int operand1, int operand2);

// 新增的函数声明
void println_int(int value);

#endif // CODEGEN_H
