import re

from binaryninja.architecture import Architecture, BranchType, InstructionInfo, InstructionTextToken, InstructionTextTokenType, RegisterInfo
from binaryninja.binaryview import BinaryView, SegmentFlag, SymbolType
from binaryninja import log_warn, Symbol
from typing import List, Optional

class PIC16F54Disassembler:
    def __init__(self):
        self.SFRs = [
            "INDF",
            "TMR0",
            "PCL",
            "STATUS",
            "FSR",
            "PORTA",
            "PORTB"
        ]
        for i in range(25):
            self.SFRs.append(f"GPR{i}")

    def _disasm_f(self, data: int, addr: int):
        # f is one of the Special Function Registers (SFR)
        # So let's just return the text of it
        return self.SFRs[data & 0b1_1111]

    def _disasm_k(self, data: int, addr: int):
        return data & 0b1111_1111

    def _disasm_k9(self, data: int, addr: int):
        return data & 0b1_1111_1111

    def _disasm_d(self, data: int, addr: int):
        return (data & 0b0010_0000) >> 5

    def _disasm_b(self, data: int, addr: int):
        return (data & 0b1110_0000) >> 5

    def disasm(self, data: bytes, addr: int):
        data = int.from_bytes(data, "little")
        instruction_size = 2
        instruction_text = None
        # TODO assert values for sanity

        # Pull out some params in case we need them
        # Easier to just do them all at once here
        f = self._disasm_f(data, addr)
        k = self._disasm_k(data, addr)
        d = self._disasm_d(data, addr)
        b = self._disasm_b(data, addr)

        # Fixed instructions w/ no operands
        if data == 0 :
            instruction_text = "NOP"
        elif data == 0b0000_0000_0011:
            instruction_text = "SLEEP"
        elif data == 0b0000_0000_0010:
            instruction_text = "OPTION"
        elif data == 0b0000_0100_0000:
            instruction_text = "CLRW"
        elif data == 0b0000_0000_0100:
            instruction_text = "CLRWDT"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 3-bit prefix instructions
        masked_data = (data & 0b1110_0000_0000) >> 9
        if masked_data == 0b101:
            # Multiply by two to compensate for 12-bit addressable words
            # So REALLY the address is what is displayed divided by 2,
            # but doing it this way matches what binja will display
            k9 = self._disasm_k9(data, addr)
            k9 *= 2
            instruction_text = f"GOTO {k9}"

        if instruction_text is not None:
            return instruction_text, instruction_size


        # 4-bit prefix instructions
        masked_data = (data & 0b1111_0000_0000) >> 8
        if masked_data == 0b1110:
            instruction_text = f"ANDLW {k}"
        elif masked_data == 0b1001:
            # Multiply by two to compensate for 12-bit addressable words
            # So REALLY the address is what is displayed divided by 2,
            # but doing it this way matches what binja will display
            k *= 2
            instruction_text = f"CALL {k}"
        elif masked_data == 0b1101:
            instruction_text = f"IORLW {k}"
        elif masked_data == 0b1100:
            instruction_text = f"MOVLW {k}"
        elif masked_data == 0b1000:
            instruction_text = f"RETLW {k}"
        elif masked_data == 0b1111:
            instruction_text = f"XORLW {k}"
        elif masked_data == 0b0100:
            instruction_text = f"BCF {f}, {b}"
        elif masked_data == 0b0101:
            instruction_text = f"BSF {f}, {b}"
        elif masked_data == 0b0110:
            instruction_text = f"BTFSC {f}, {b}"
        elif masked_data == 0b0111:
            instruction_text = f"BTFSS {f}, {b}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 6-bit prefix instructions
        masked_data = (data & 0b1111_1100_0000) >> 6
        d = "DEST_F" if d else "DEST_W"
        if masked_data == 0b0001_11:
            instruction_text = f"ADDWF {f}, {d}"
        elif masked_data == 0b0001_01:
            instruction_text = f"ANDWF {f}, {d}"
        elif masked_data == 0b0010_01:
            instruction_text = f"COMF {f}, {d}"
        elif masked_data == 0b0001_11:
            instruction_text = f"DECF {f}, {d}"
        elif masked_data == 0b0010_11:
            instruction_text = f"DECFSZ {f}, {d}"
        elif masked_data == 0b0010_10:
            instruction_text = f"INCF {f}, {d}"
        elif masked_data == 0b0011_11:
            instruction_text = f"INCFSZ {f}, {d}"
        elif masked_data == 0b0001_00:
            instruction_text = f"IORWF {f}, {d}"
        elif masked_data == 0b0010_00:
            instruction_text = f"MOVF {f}, {d}"
        elif masked_data == 0b0011_01:
            instruction_text = f"RLF {f}, {d}"
        elif masked_data == 0b0011_00:
            instruction_text = f"RRF {f}, {d}"
        elif masked_data == 0b0000_10:
            instruction_text = f"SUBWF {f}, {d}"
        elif masked_data == 0b0011_10:
            instruction_text = f"SWAPF {f}, {d}"
        elif masked_data == 0b0001_10:
            instruction_text = f"XORWF {f}, {d}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 7-bit prefix instructions
        masked_data = (data & 0b1111_1110_0000) >> 5
        if masked_data == 0b0000_011:
            instruction_text = f"CLRF {f}"
        elif masked_data == 0b0000_001:
            instruction_text = f"MOVWF {f}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 9-bit prefix instructions
        masked_data = (data & 0b1111_1111_1000) >> 3
        # We don't parse a separate 3-bit f value because if
        # we reach this, all preceding bits were 0 anyway
        if masked_data == 0b0000_0000_0:
            instruction_text = f"TRIS {f}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        log_warn(f"Unknown instruction: {data:#X} @ {addr:#X}")
        return "UNKNOWN", instruction_size

class PIC16F54(Architecture):
    name = "PIC16F54"
    address_size = 2
    # These are fudged a bit because program word size is 12 bits
    default_int_size = 1
    instr_alignment = 2
    max_instr_length = 2

    regs = {
        "W": RegisterInfo("W", 1),
        # Hardware stack registers, 9-bits wide each
        "S1": RegisterInfo("S1", 2),
        "S2": RegisterInfo("S2", 2)
        # Flags is in STATUS SFR in memory, not a separate flags register
    }

    def __init__(self):
        super().__init__()
        self.PIC16F54Disassembler = PIC16F54Disassembler()

    def get_instruction_info(self, data, addr) -> InstructionInfo:
        instruction_text, instruction_size = self.PIC16F54Disassembler.disasm(data, addr)
        result = InstructionInfo()
        result.length = instruction_size


        if instruction_text.startswith("CALL"):
            dest = instruction_text.split(" ")[1]
            result.add_branch(BranchType.CallDestination, int(dest))
        elif instruction_text.startswith("GOTO"):
            dest = instruction_text.split(" ")[1]
            result.add_branch(BranchType.UnconditionalBranch, int(dest))
        elif instruction_text.startswith("RETLW"):
            result.add_branch(BranchType.FunctionReturn)
        elif (instruction_text.startswith("BTFSS")
            or instruction_text.startswith("BTFSC")
            or instruction_text.startswith("DECFSZ")
            or instruction_text.startswith("INCFSZ")):
            # Consider the branch true if it skips, for whatever
            # reason is being checked
            result.add_branch(BranchType.TrueBranch, addr+4)
            result.add_branch(BranchType.FalseBranch, addr+2)
        return result

    def get_instruction_text(self, data, addr):
        result: List(InstructionTextToken) = []
        instruction_text, instruction_size = self.PIC16F54Disassembler.disasm(data, addr)
        atoms = [t for t in re.split(r'([, ()\+])', instruction_text) if t]
        # First component is always the instruction mnemonic
        result.append(InstructionTextToken(InstructionTextTokenType.InstructionToken, atoms[0]))

        # If there are operands, add a space
        if atoms[1:]:
          result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))

        for atom in atoms[1:]:
            if not atom or atom == ' ':
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, ' '))
            elif atoms[0] in ["CALL", "GOTO"]:
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, text=hex(int(atom)), value=int(atom)))
            elif atom in self.regs.keys():
                result.append(InstructionTextToken(InstructionTextTokenType.RegisterToken, atom))
            elif atom.isdigit():
                result.append(InstructionTextToken(InstructionTextTokenType.IntegerToken, hex(int(atom)), value=int(atom)))
            elif atom == ",":
                result.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken, atom))
            elif atom in self.PIC16F54Disassembler.SFRs:
                value = 0x500 + self.PIC16F54Disassembler.SFRs.index(atom)
                result.append(InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, text=atom, value=value))
            elif atom in ["DEST_W", "DEST_F"]:
                result.append(InstructionTextToken(InstructionTextTokenType.TextToken, atom))
            else:
                raise Exception(f"unfamiliar token: {atom} from instruction {instruction_text}" )

        return result, instruction_size

    def get_instruction_low_level_il(self, data: bytes, addr: int, il: 'lowlevelil.LowLevelILFunction') -> Optional[int]:
        return None

class PIC16F54View(BinaryView):
    name = "PIC16F54 Flash"

    def __init__(self, data: BinaryView):
        super().__init__(parent_view=data, file_metadata=data.file)
        self.platform = Architecture["PIC16F54"].standalone_platform
        self.data = data
        self.disassembler = PIC16F54Disassembler()

    def init(self):
        self.add_auto_segment(0x0, 0x400, 0x0, 0x400, SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable)
        # This is not a real memory address; data memory is on a totally different bus
        # than program memory. Just base it at 0x500 so it's separated from things. It
        # is not backed by data from our provided Intel HEX dump
        self.add_auto_segment(0x500, 0x20, 0x0, 0x0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        # Similar with the two level hardware stack. Let's just make a fake segment to hold it
        #self.add_auto_segment(0x600, 0x4, 0x0, 0x0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)


        # Define all the SFRs
        for index, sfr in enumerate(self.disassembler.SFRs):
            self.define_auto_symbol_and_var_or_function(Symbol(SymbolType.DataSymbol, 0x500 + index, sfr), self.parse_type_string("char")[0])

        
        # Set the entry point and a comment explaining the PC rollover
        entry_point_address = 0x1ff * 2
        self.add_entry_point(entry_point_address)
        entry_point_function = self.get_function_at(entry_point_address)
        entry_point_function.set_comment_at(0x1ff * 2, "If PC goes >= 0x400, it rolls over to 0x0 and continues executing from there")

        # Address 0 is code if PC wraps around from 0x1ff -> 0x0
        self.add_function(0x0)
        return True
        
    @classmethod
    def is_valid_for_data(cls, data: BinaryView):
        log_warn(f"{data.view_type=}")
        # Need a flash dump of 0x400 bytes for program memory
        if data.length < 0x400:
            log_warn(f"Length too short: {data.length:#x}")
            return False

        # Since instructions are 12 bits, the top nibble
        # of every second byte should be 0b0000
        for i in range(0x1, 0x400, 2):
            if int.from_bytes(data[i]) & 0xF0:
                log_warn(f"Non-null nibble: {int.from_bytes(data[i]):#x} @ {i:#x}")
                return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        # Reset vector is 0x1ff, multiply by 2 because
        # of 12-bit addressable memory space and to match
        # the rest of the other memory translations
        return 0x1ff * 2

    def perform_get_address_size(self):
        return 2
    
PIC16F54.register()
PIC16F54View.register()
