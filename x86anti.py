from idaapi import *
import idaapi
import idautils
import idc
from prettytable import PrettyTable

if idaapi.IDA_SDK_VERSION > 700:
    import ida_search
    from idc import (
        print_operand
    )
    from ida_bytes import (
        get_strlit_contents
    )
else:
    from idc import (
        GetOpnd as print_operand,
        GetString
    )


    def get_strlit_contents(*args):
        return GetString(args[0])

DEBUG = True

# fgetc,fgets,fread,fprintf,
# vspritnf

# set function_name
dangerous_functions = [
    "strcpy",
    "strcat",
    "sprintf",
    "read",
    "getenv"
]

attention_function = [
    "memcpy",
    "strncpy",
    "sscanf",
    "strncat",
    "snprintf",
    "vprintf",
    "printf"
]

command_execution_function = [
    "system",
    "execve",
    "popen",
    "unlink"
]

# describe arg num of function

one_arg_function = [
    "getenv",
    "system",
    "unlink"
]

two_arg_function = [
    "strcpy",
    "strcat",
    "popen"
]

three_arg_function = [
    "strncpy",
    "strncat",
    "memcpy",
    "execve",
    "read"
]

format_function_offset_dict = {
    "sprintf": 1,
    "sscanf": 1,
    "snprintf": 2,
    "vprintf": 0,
    "printf": 0
}

try:
    class MipsAudit_Menu_Context(idaapi.action_handler_t):
        def __init__(self):
            idaapi.action_handler_t.__init__(self)

        @classmethod
        def get_name(self):
            return self.__name__

        @classmethod
        def get_label(self):
            return self.label

        @classmethod
        def register(self, plugin, label):
            self.plugin = plugin
            self.label = label
            instance = self()
            return idaapi.register_action(idaapi.action_desc_t(
                self.get_name(),  # Name. Acts as an ID. Must be unique.
                instance.get_label(),  # Label. That's what users see.
                instance  # Handler. Called when activated, and for updating
            ))

        @classmethod
        def unregister(self):
            """Unregister the action.
            After unregistering the class cannot be used.
            """
            idaapi.unregister_action(self.get_name())

        @classmethod
        def activate(self, ctx):
            # dummy method
            return 1

        @classmethod
        def update(self, ctx):
            if ctx.form_type == idaapi.BWN_DISASM:
                return idaapi.AST_ENABLE_FOR_WIDGET
            return idaapi.AST_DISABLE_FOR_WIDGET


    class MIPS_Searcher(MipsAudit_Menu_Context):
        def activate(self, ctx):
            self.plugin.run()
            return 1

except:
    pass

def printFunc(func_name):
    string1 = "========================================"
    string2 = "========== Auditing " + func_name + " "
    strlen = len(string1) - len(string2)
    return string1 + "\n" + string2 + '=' * strlen + "\n" + string1

def getFuncAddr(func_name):
    func_addr = idc.get_name_ea_simple(func_name)
    if func_addr != BADADDR:
        print(printFunc(func_name))
        return func_addr
    return False

def audit(func_name):
    func_addr = getFuncAddr(func_name)
    if func_addr == False:
        return False

    # get arg num and set table
    if func_name in one_arg_function:
        arg_num = 1
    elif func_name in two_arg_function:
        arg_num = 2
    elif func_name in three_arg_function:
        arg_num = 3
    elif func_name in format_function_offset_dict:
        arg_num = format_function_offset_dict[func_name] + 1
    else:
        print(
                    "The %s function didn't write in the describe arg num of function array,please add it to,such as add to `two_arg_function` arary" % func_name)
        return
    table_head = ["func_name", "addr"]
    for num in range(0, arg_num):
        table_head.append("arg" + str(num + 1))
    if func_name in format_function_offset_dict:
        table_head.append("format&value[string_addr, num of '%', fmt_arg...]")
    table_head.append("local_buf_size")
    table = PrettyTable(table_head)

    # get first call
    extern_addr = idc.get_name_ea_simple("." + func_name)
    for addr in idautils.CodeRefsTo(extern_addr, 0):
        idc.set_color(addr, idc.CIC_ITEM, 0x00ff00)
        #print(idc.generate_disasm_line(addrs, 0))
        if func_name in format_function_offset_dict:
            info = auditFormat(addr, func_name, arg_num)
        else:
            info = auditAddr(addr, func_name, arg_num)
        table.add_row(info)
    print(table)

def auditFormat(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        print("debug 252")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    func = idaapi.get_func(call_addr)
    start = func.start_ea
    if func_name == "printf" or func_name == "vprintf":
        line = call_addr
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            if Mnemonics[0:1] == "l":
                idc.set_color(line, idc.CIC_ITEM, 0x005500)
                string_addr = get_operand_value(line,1)
                ls = []
                ls.append(get_str(string_addr))
                ret_list.append(ls)
                break
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            if Mnemonics[0:2] == "mo":
                idc.set_color(line, idc.CIC_ITEM, 0x00AA00)
                Arg = "0x%x" % line
                ret_list.insert(2,Arg)
                break
        ret_list.append(local_buf_size)
        return ret_list
    if func_name == "sprintf":
        line = call_addr
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            #print(idc.get_cmt(line,False))
            if Mnemonics[0:2] == "mo" and idc.get_cmt(line,False) != None:
                #print("yes")
                idc.set_color(line, idc.CIC_ITEM, 0x00AA00)
                Arg = "0x%x" % line
                ret_list.append(Arg)
                break
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            if Mnemonics[0:1] == "l":
                idc.set_color(line, idc.CIC_ITEM, 0x005500)
                string_addr = get_operand_value(line, 1)
                ls = []
                ls.append(get_str(string_addr))
                ret_list.append(ls)
                break
        ret_list.insert(2,0)
        ret_list.append(local_buf_size)
        return ret_list
    if func_name == "snprintf":
        line = call_addr
        num = 0
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            #print(idc.get_cmt(line,False))
            if Mnemonics[0:2] == "mo" and idc.get_cmt(line,False) != None:
                #print("yes")
                idc.set_color(line, idc.CIC_ITEM, 0x00AA00)
                Arg = "0x%x" % line
                ret_list.append(Arg)
                num+=1
                if num == 2:
                    break
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            if Mnemonics[0:1] == "l":
                idc.set_color(line, idc.CIC_ITEM, 0x005500)
                string_addr = get_operand_value(line, 1)
                ls = []
                ls.append(get_str(string_addr))
                ret_list.append(ls)
                register = idc.print_operand(line,0)
                while line >= start:
                    line = idc.prev_head(line)
                    if idc.print_operand(line,0) == register or idc.print_operand(line,1) == register:
                        addrr = "0x%x" % line
                        ret_list.insert(2,addrr)
                        ret_list.append(local_buf_size)
                        return ret_list
        ret_list.append(local_buf_size)
        return ret_list
    if func_name == "sscanf":
        line = call_addr
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            #print(Mnemonics[0:2])
            if Mnemonics[0:2] == "mo":
                idc.set_color(line, idc.CIC_ITEM, 0x005550)
                ret_list.append(line)
                break
        line = call_addr
        while line >= start:
            line = idc.prev_head(line)
            Mnemonics = print_insn_mnem(line)
            #print(Mnemonics[0:2])
            if Mnemonics[0:2] == "le":
                if idc.get_operand_type(line,1) == 2:
                    idc.set_color(line, idc.CIC_ITEM, 0x005500)
                    string_addr = get_operand_value(line, 1)
                    ls = []
                    ls.append(get_str(string_addr))
                    ret_list.append(ls)
                    break
        addrr = "0x%x" % line
        ret_list.insert(2,addrr)
        ret_list.append(local_buf_size)
        return ret_list


def get_str(ins_addr):
    string = ""
    start = ins_addr
    end = idc.next_head(ins_addr)
    for i in range(start,end):
        string += chr(idc.get_wide_byte(i))
    return string

def auditAddr(call_addr, func_name, arg_num):
    addr = "0x%x" % call_addr
    ret_list = [func_name, addr]
    # local buf size
    local_buf_size = idc.get_func_attr(call_addr, idc.FUNCATTR_FRSIZE)
    if local_buf_size == BADADDR:
        print("debug 236")
        local_buf_size = "get fail"
    else:
        local_buf_size = "0x%x" % local_buf_size
    # get arg
    func = idaapi.get_func(call_addr)
    start = func.start_ea
    line = call_addr
    flag = 0
    for num in range(0, arg_num):
        while line >= start:
            line = idc.prev_head(line)
            if idc.get_cmt(line, False) != None:
                flag = flag+1
                addrr = "0x%x" % line
                ret_list.append(addrr)
                break
    if flag != arg_num:
        for i in range(arg_num - flag):
            ret_list.append("get fail")
    ret_list.append(local_buf_size)
    return ret_list


def x86Audit():
    # the word create with figlet
    print("Auditing dangerous functions ......")
    for func_name in dangerous_functions:
        audit(func_name)

    print("Auditing attention function ......")
    for func_name in attention_function:
        audit(func_name)

    print("Auditing command execution function ......")
    for func_name in command_execution_function:
        audit(func_name)

    print("Finished! Enjoy the result ~")


if __name__ == '__main__':
    x86Audit()