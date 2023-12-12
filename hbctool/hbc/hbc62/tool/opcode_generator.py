import pathlib
import re
import json

basepath = pathlib.Path(__file__).parent.absolute()

with open(f"{basepath}/../raw/BytecodeList.def", "r") as bytecodeListFile:
    lines = bytecodeListFile.readlines()
# Init constants
jmp_operand = {
    "1": ["Addr8"],
    "1Long": ["Addr32"],
    "2": ["Addr8", "Reg8"],
    "2Long": ["Addr32", "Reg8"],
    "3": ["Addr8", "Reg8", "Reg8"],
    "3Long": ["Addr32", "Reg8", "Reg8"]
}

# Init variables
json_op = {}
opcode = 0
line_num  = 0

def addOp(name, operands):
    global opcode
    global json_op

    print(hex(opcode)[2:], name)
    json_op[name] = operands
    opcode = opcode + 1

# Read each line
for line in lines:
    line_num = line_num + 1

    # Example: DEFINE_OPCODE_4(NewArrayWithBuffer, Reg8, UInt16, UInt16, UInt16)
    # name = "NewArrayWithBuffer"
    # operands = ["Reg8", "UInt16", "UInt16", "UInt16"]
    if line.startswith("DEFINE_OPCODE_"):
        match = re.search(r'\((\w+)((, \w+)*)\)', line)
        name = match[1]
        operands = match[2].split(', ')[1:]
        addOp(name, operands)

    elif line.startswith("OPERAND_STRING_ID"):
        match = re.search(r'\((\w+), (\w+)\)', line)
        name = match[1]
        operandID = int(match[2]) - 1

        # Handle name not found / arg not found
        assert json_op[name], f"Opcode not found ({name})"
        assert json_op[name][operandID], f"Operand  not found ({operandID})"

        # Add ":S" to argument arg of json_op[name]
        json_op[name][operandID] += ":S"

    elif line.startswith("DEFINE_JUMP_"):
        match = re.search(r'(\d)\((\w+)\)', line)
        num_op = match[1]
        name = match[2]

        addOp(name, jmp_operand[f"{num_op}"])
        addOp(f"{name}Long", jmp_operand[f"{num_op}Long"])

    elif line.startswith("ASSERT_"):
        pass

    elif line.startswith("DEFINE_RET_TARGET"):
        pass

    elif line.startswith("DEFINE_OPERAND_TYPE"):
        pass

    elif (
        not line.startswith("#")
        and not line.startswith("//")
        and not line.startswith("/*")
        and not line.startswith(" *")
        and not line.startswith("#")
        and not line.startswith("  ")
        and not line.startswith("\n")
    ):
        # Unhandled cases
        print(line_num, line)

with open(f"{basepath}/../data/opcode.json", "w") as f:
    json.dump(json_op, f, indent=4)
