#include "codegen.h"
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>
// 符号表
std::unordered_map<std::string, int> symbol_table;

void generate_function_header(const std::string &function_name)
{
    std::cout << ".global " << function_name << std::endl;
    std::cout << function_name << ":" << std::endl;
    std::cout << "push ebp" << std::endl;
    std::cout << "mov ebp, esp" << std::endl;
}

void generate_function_footer(const std::string &function_name)
{
    std::cout << "pop ebp" << std::endl;
    std::cout << "ret" << std::endl;
}
void generate_variable_declaration(const std::string &variable_name)
{
    std::cout << "sub esp, 4" << std::endl;                                               // 为变量分配4字节的空间
    symbol_table[variable_name] = 0;                                                      // 将变量存储到符号表中，初始值为0
    std::cout << "mov dword ptr [ebp-" << 4 * symbol_table.size() << "], 0" << std::endl; // 初始化变量为0
}
void generate_variable_declaration_with_initialization(const std::string &variable_name, int initial_value)
{
    std::cout << "sub esp, 4" << std::endl;                                                               // 为变量分配4字节的空间
    symbol_table[variable_name] = initial_value;                                                          // 将变量和初始值存入符号表
    std::cout << "mov dword ptr [ebp-" << 4 * symbol_table.size() << "], " << initial_value << std::endl; // 初始化变量
}

void generate_return(int return_value)
{
    std::cout << "mov eax, " << return_value << std::endl;
}

void generate_function_call(const std::string &function_name)
{
    std::cout << "call " << function_name << std::endl;
}
void generate_function_call_with_params(const std::string &function_name, const std::string &params)
{
    std::istringstream param_stream(params);
    std::string token;
    std::vector<int> param_values;

    while (std::getline(param_stream, token, ','))
    {
        token.erase(0, token.find_first_not_of(' ')); // 去除前导空格
        token.erase(token.find_last_not_of(' ') + 1); // 去除末尾空格
        int value = symbol_table[token];              // 从符号表查找参数的值
        param_values.push_back(value);
    }

    for (auto it = param_values.rbegin(); it != param_values.rend(); ++it)
    {
        std::cout << "    push " << *it << std::endl; // 将参数逆序压栈
    }

    std::cout << "    call " << function_name << std::endl;               // 调用函数
    std::cout << "    add esp, " << param_values.size() * 4 << std::endl; // 恢复栈指针
}

void generate_assignment(const std::string &variable_name, int value)
{
    // 更新符号表
    symbol_table[variable_name] = value;

    // 生成赋值操作的汇编代码
    std::cout << "mov [" << variable_name << "], " << value << std::endl;
}
int lookup_variable(const std::string &variable_name)
{
    return 0; // 假设都返回0作为示例
}

int generate_add(int operand1, int operand2)
{
    std::cout << "add eax, " << operand2 << std::endl;
    return operand1 + operand2;
}

int generate_sub(int operand1, int operand2)
{
    std::cout << "sub eax, " << operand2 << std::endl;
    return operand1 - operand2;
}

int generate_mul(int operand1, int operand2)
{
    std::cout << "imul eax, " << operand2 << std::endl;
    return operand1 * operand2;
}

int generate_div(int operand1, int operand2)
{
    std::cout << "idiv eax, " << operand2 << std::endl;
    return operand1 / operand2;
}

int generate_mod(int operand1, int operand2)
{
    std::cout << "idiv eax, " << operand2 << std::endl;
    std::cout << "mov eax, edx" << std::endl;
    return operand1 % operand2;
}

// 新增的实现函数
void println_int(int value)
{
    // 使用汇编代码输出整数
    std::cout << "mov eax, " << value << std::endl; // 将整数值放入 eax 寄存器
    std::cout << "push eax" << std::endl;           // 将整数值推入堆栈
    std::cout << "call printf" << std::endl;        // 调用标准库函数 printf
    std::cout << "add esp, 4" << std::endl;         // 清理堆栈
}

void generate_println_int(int value)
{
    // 输出整数值的汇编代码
    std::cout << "mov eax, " << value << std::endl; // 将整数值放入 eax 寄存器
    std::cout << "push eax" << std::endl;           // 将整数值推入堆栈
    std::cout << "call printf" << std::endl;        // 调用标准库函数 printf
    std::cout << "add esp, 4" << std::endl;         // 清理堆栈
    // std::cout << "call exit" << std::endl;          // 调用标准库函数 exit
}