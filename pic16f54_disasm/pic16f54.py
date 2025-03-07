import re

import binaryninja
from binaryninja.architecture import (
    Architecture,
    BranchType,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType,
    RegisterInfo,
)
from binaryninja.binaryview import BinaryView, SegmentFlag, SymbolType
from binaryninja import log_info, log_warn, Symbol
from binaryninja import (
    FlagRole,
    LowLevelILFlagCondition,
)
from typing import List, Optional


class PIC16F54Disassembler:
    def __init__(self):
        self.SFRs = ["INDF", "TMR0", "PCL", "STATUS", "FSR", "PORTA", "PORTB"]
        self.GPRs = []
        for i in range(25):
            self.GPRs.append(f"GPR{i}")
        self.TRISs = ["TRISA", "TRISB"]
        self.memory_mapped_regs = self.SFRs + self.GPRs + self.TRISs

    def _disasm_f(self, data: int, addr: int):
        # f is one of the Special Function Registers (SFR)
        # So let's just return the text of it
        return self.memory_mapped_regs[data & 0b1_1111]

    def _disasm_k(self, data: int, addr: int):
        return data & 0b1111_1111

    def _disasm_k9(self, data: int, addr: int):
        return data & 0b1_1111_1111

    def _disasm_d(self, data: int, addr: int):
        return (data & 0b0010_0000) >> 5

    def _disasm_b(self, data: int, addr: int):
        return (data & 0b1110_0000) >> 5

    def disasm(self, data: bytes, addr: int):
        data_int = int.from_bytes(data, "little")
        instruction_size = 2
        instruction_text = None
        # TODO assert values for sanity

        # Pull out some params in case we need them
        # Easier to just do them all at once here
        f = self._disasm_f(data_int, addr)
        k = self._disasm_k(data_int, addr)
        d = self._disasm_d(data_int, addr)
        b = self._disasm_b(data_int, addr)

        # Fixed instructions w/ no operands
        if data_int == 0:
            instruction_text = "NOP"
        elif data_int == 0b0000_0000_0011:
            instruction_text = "SLEEP"
        elif data_int == 0b0000_0000_0010:
            instruction_text = "OPTION"
        elif data_int == 0b0000_0100_0000:
            instruction_text = "CLRW"
        elif data_int == 0b0000_0000_0100:
            instruction_text = "CLRWDT"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 3-bit prefix instructions
        masked_data = (data_int & 0b1110_0000_0000) >> 9
        if masked_data == 0b101:
            # Multiply by two to compensate for 12-bit addressable words
            # So REALLY the address is what is displayed divided by 2,
            # but doing it this way matches what binja will display
            k9 = self._disasm_k9(data_int, addr)
            k9 *= 2
            instruction_text = f"GOTO {k9}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 4-bit prefix instructions
        masked_data = (data_int & 0b1111_0000_0000) >> 8
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
        masked_data = (data_int & 0b1111_1100_0000) >> 6
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
        masked_data = (data_int & 0b1111_1110_0000) >> 5
        if masked_data == 0b0000_011:
            instruction_text = f"CLRF {f}"
        elif masked_data == 0b0000_001:
            instruction_text = f"MOVWF {f}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        # 9-bit prefix instructions
        masked_data = (data_int & 0b1111_1111_1000) >> 3
        # We don't parse a separate 3-bit f value because if
        # we reach this, all preceding bits were 0 anyway
        if masked_data == 0b0000_0000_0:
            instruction_text = f"TRIS {f}"

        if instruction_text is not None:
            return instruction_text, instruction_size

        log_warn(f"Unknown instruction: {data_int:#X} @ {addr:#X}")
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
        "S2": RegisterInfo("S2", 2),
        # Flags is in STATUS SFR in memory, not a separate flags register
    }

    stack_pointer = "S1"
    flags = ["C", "DC", "Z", "PD", "TO", "PA0", "PA1", "PA2"]
    flag_roles = {
        "C": FlagRole.CarryFlagRole,
        "DC": FlagRole.HalfCarryFlagRole,
        "Z": FlagRole.ZeroFlagRole,
        "TO": FlagRole.SpecialFlagRole,
        "PD": FlagRole.SpecialFlagRole,
    }
    flag_write_types = ["", "c", "z", "cz", "topd"]

    flags_written_by_flag_write_type = {
        "": [],
        "c": ["C"],
        "z": ["Z"],
        "cz": ["C", "DC", "Z"],
        "topd": ["TO", "PD"]
    }

    flags_required_for_flag_condition = {
        LowLevelILFlagCondition.LLFC_E: ["Z"],
        LowLevelILFlagCondition.LLFC_UGT: ['C'],
    }

    def __init__(self):
        super().__init__()
        self.PIC16F54Disassembler = PIC16F54Disassembler()

    def get_instruction_info(self, data, addr) -> InstructionInfo:
        instruction_text, instruction_size = self.PIC16F54Disassembler.disasm(
            data, addr
        )
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
        elif (
            instruction_text.startswith("BTFSS")
            or instruction_text.startswith("BTFSC")
            or instruction_text.startswith("DECFSZ")
            or instruction_text.startswith("INCFSZ")
        ):
            # Consider the branch true if it skips, for whatever
            # reason is being checked
            result.add_branch(BranchType.TrueBranch, addr + 4)
            result.add_branch(BranchType.FalseBranch, addr + 2)
        return result

    def get_instruction_text(self, data, addr):
        result: List(InstructionTextToken) = []
        instruction_text, instruction_size = self.PIC16F54Disassembler.disasm(
            data, addr
        )
        atoms = [t for t in re.split(r"([, ()\+])", instruction_text) if t]
        # First component is always the instruction mnemonic
        result.append(
            InstructionTextToken(InstructionTextTokenType.InstructionToken, atoms[0])
        )

        # If there are operands, add a space
        if atoms[1:]:
            result.append(InstructionTextToken(InstructionTextTokenType.TextToken, " "))

        for atom in atoms[1:]:
            if not atom or atom == " ":
                result.append(
                    InstructionTextToken(InstructionTextTokenType.TextToken, " ")
                )
            elif atoms[0] in ["CALL", "GOTO"]:
                result.append(
                    InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken,
                        text=hex(int(atom)),
                        value=int(atom),
                    )
                )
            elif atom in self.regs.keys():
                result.append(
                    InstructionTextToken(InstructionTextTokenType.RegisterToken, atom)
                )
            elif atom.isdigit():
                result.append(
                    InstructionTextToken(
                        InstructionTextTokenType.IntegerToken,
                        hex(int(atom)),
                        value=int(atom),
                    )
                )
            elif atom == ",":
                result.append(
                    InstructionTextToken(
                        InstructionTextTokenType.OperandSeparatorToken, atom
                    )
                )
            elif atom in self.PIC16F54Disassembler.memory_mapped_regs:
                value = 0x500 + self.PIC16F54Disassembler.memory_mapped_regs.index(atom)
                result.append(
                    InstructionTextToken(
                        InstructionTextTokenType.PossibleAddressToken,
                        text=atom,
                        value=value,
                    )
                )
            elif atom in ["DEST_W", "DEST_F"]:
                result.append(
                    InstructionTextToken(InstructionTextTokenType.TextToken, atom)
                )
            else:
                raise Exception(
                    f"unfamiliar token: {atom} from instruction {instruction_text}"
                )

        return result, instruction_size

    #    def get_instruction_low_level_il(self, data: bytes, addr: int, il: 'lowlevelil.LowLevelILFunction') -> Optional[int]:
    #        return None

    def get_instruction_low_level_il(
        self, data: bytes, addr: int, il: "lowlevelil.LowLevelILFunction"
    ) -> Optional[int]:
        # flag_bits = PA2 PA1 PA0 TO PD Z DC C
        # flag_bits_in_order = C DC Z PD TO PA0 PA1 PA2
        instruction_text, instruction_size = self.PIC16F54Disassembler.disasm(
            data, addr
        )
        atoms = instruction_text.split()
        if atoms[0] == "CLRF":
            il.append(
                il.store(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(atoms[1]),
                    ),
                    value=il.const(1, 0),
                    flags="z",
                )
            )
        elif atoms[0] == "CLRW":
            il.append(il.set_reg(size=1, reg="W", value=il.const(1, 0), flags="z"))
        elif atoms[0] == "CALL":
            il.append(il.call(il.const(2, int(atoms[1]))))
        elif atoms[0] == "GOTO":
            dest = int(atoms[1])
            if dest == addr + 2:
                il.append(il.nop())
            else:
                il.append(il.jump(il.const(2, dest)))
        elif atoms[0] == "RETLW":
            il.append(il.set_reg(size=1, reg="W", value=il.const(1, int(atoms[1]))))
            il.append(il.ret(il.pop(0)))
        elif atoms[0] == "MOVLW":
            il.append(il.set_reg(size=1, reg="W", value=il.const(1, int(atoms[1]))))
        elif atoms[0] == "MOVWF":
            il.append(
                il.store(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(atoms[1]),
                    ),
                    value=il.reg(size=1, reg="W"),
                )
            )
        elif atoms[0] == "SUBWF":
            operation = il.sub(
                size=1,
                a=il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                ),
                b=il.reg(size=1, reg="W"),
                flags="cz",
            )
            if atoms[-1][-1] == "W":
                il.append(il.set_reg(size=1, reg="W", value=operation))
            else:
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1]
                            ),
                        ),
                        value=operation,
                    )
                )

            # next_label = il.LowLevelILLabel()
            # or_label = il.LowLevelILLabel()
            # and_label = il.LowLevelILLabel()

            # il.append(il.if_expr(cond, skip_label, next_label))

            # il.store(1, il.const(2, STATUS), il.load(1, STATUS))
        elif atoms[0] == "ADDWF":
            operation = il.add(
                1,
                il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                ),
                il.reg(size=1, reg="W"),
                flags="cz",
            )
            if atoms[-1][-1] == "W":
                il.append(il.set_reg(size=1, reg="W", value=operation))
            else:
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1][:-1]
                            ),
                        ),
                        value=operation,
                    )
                )
        elif atoms[0] == "ANDWF":
            operation = il.and_expr(
                il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                ),
                il.reg(size=1, reg="W"),
                flags="z",
            )
            if atoms[-1][-1] == "W":
                il.append(il.set_reg(size=1, reg="W", value=operation))
            else:
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1][:-1]
                            ),
                        ),
                        value=operation,
                    )
                )
        elif atoms[0] == "MOVF":
            if atoms[-1][-1] == "W":
                il.append(
                    il.set_reg(
                        size=1,
                        reg="W",
                        value=il.load(
                            size=1,
                            addr=il.const(
                                2,
                                0x500
                                + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                    atoms[1][:-1]
                                ),
                            ),
                        ),
                        flags="z",
                    )
                )
            else:
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1][:-1]
                            ),
                        ),
                        value=il.reg(size=1, reg="W"),
                        flags="z",
                    )
                )
        elif atoms[0] == "COMF":
            result = il.not_expr(
                1,
                il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                ),
                flags="z",
            )
            if atoms[-1][-1] == "W":
                il.append(il.set_reg(size=1, reg="W", value=result))
            else:
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1][:-1]
                            ),
                        ),
                        value=result,
                    )
                )
        elif atoms[0] == "ANDLW":
            il.append(
                il.set_reg(
                    size=1,
                    reg="W",
                    value=il.and_expr(
                        1,
                        il.reg(size=1, reg="W"),
                        il.const(1, int(atoms[1])),
                        flags="z",
                    ),
                )
            )
        elif atoms[0] == "INCF":
            result = il.add(
                1,
                il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                ),
                il.const(1, 1),
                flags="z",
            )
            if atoms[-1][-1] == "F":
                il.append(
                    il.store(
                        size=1,
                        addr=il.const(
                            2,
                            0x500
                            + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                atoms[1][:-1]
                            ),
                        ),
                        value=result,
                    )
                )
            else:
                il.append(il.set_reg(size=1, reg="W", value=result))
        elif atoms[0] == "BSF":
            value = atoms[1][:-1]
            il.append(
                il.store(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(value),
                    ),
                    value=il.or_expr(
                        1,
                        il.load(
                            size=1,
                            addr=il.const(
                                2,
                                0x500
                                + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                    value
                                ),
                            ),
                        ),
                        il.const(1, 1 << int(atoms[-1])),
                    ),
                )
            )
        elif atoms[0] == "BCF":
            value = atoms[1][:-1]
            il.append(
                il.set_reg(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(value),
                    ),
                    value=il.and_expr(
                        1,
                        il.load(
                            size=1,
                            addr=il.const(
                                2,
                                0x500
                                + self.PIC16F54Disassembler.memory_mapped_regs.index(
                                    value
                                ),
                            ),
                        ),
                        il.const(1, ~(1 << int(atoms[-1]))),
                    ),
                )
            )
        elif atoms[0] == "TRIS":
            il.append(
                il.store(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            "TRIS" + atoms[1][-1]
                        ),
                    ),
                    value=il.reg(size=1, reg="W"),
                )
            )
        elif atoms[0] in ["BTFSS", "BTFSC"]:
            bit = int(atoms[-1])
            cond = None
            if atoms[1][:-1] == "STATUS":
                if bit < 2:
                    cond = il.flag("C")
                elif bit == 2:
                    cond = il.flag("Z")
                else:
                    log_warn(f"Checking for bit {bit}")
                    cond = None

            if cond is None:
                il_val = il.load(
                    size=1,
                    addr=il.const(
                        2,
                        0x500
                        + self.PIC16F54Disassembler.memory_mapped_regs.index(
                            atoms[1][:-1]
                        ),
                    ),
                )
                cond = il.and_expr(1, il_val, il.const(1, 1 << bit))

            skip_label = il.get_label_for_address(Architecture["PIC16F54"], addr + 4)
            next_label = il.get_label_for_address(Architecture["PIC16F54"], addr + 2)

            if atoms[0] == "BTFSC":
                il.append(il.if_expr(cond, next_label, skip_label))
            else:
                il.append(il.if_expr(cond, skip_label, next_label))

        elif atoms[0] == "XORLW":
            il.append(
                il.set_reg(
                    size=1,
                    reg="W",
                    value=il.xor_expr(
                        1, il.reg(size=1, reg="W"), il.const(1, int(atoms[1]))
                    ),
                    flags="z"
                )
            )
        else:
            il.append(il.unimplemented())

        # instr size is always 2
        return 2


class PIC16F54View(BinaryView):
    name = "PIC16F54 Flash"

    def __init__(self, data: BinaryView):
        super().__init__(parent_view=data, file_metadata=data.file)
        self.platform = Architecture["PIC16F54"].standalone_platform
        self.data = data
        self.disassembler = PIC16F54Disassembler()

    def init(self):
        self.add_auto_segment(
            0x0,
            0x400,
            0x0,
            0x400,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable,
        )
        # This is not a real memory address; data memory is on a totally different bus
        # than program memory. Just base it at 0x500 so it's separated from things. It
        # is not backed by data from our provided Intel HEX dump
        self.add_auto_segment(
            0x500,
            0x22,
            0x0,
            0x0,
            SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable,
        )

        # Similar with the two level hardware stack. Let's just make a fake segment to hold it
        # self.add_auto_segment(0x600, 0x4, 0x0, 0x0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable)

        # Define all the memory mapped registers
        for index, mmr in enumerate(self.disassembler.memory_mapped_regs):
            self.define_auto_symbol(
                Symbol(SymbolType.DataSymbol, 0x500 + index, mmr),
            )

        # Set the entry point and a comment explaining the PC rollover
        entry_point_address = 0x1FF * 2
        self.add_entry_point(entry_point_address)
        entry_point_function = self.get_function_at(entry_point_address)
        undo_id = self.file.begin_undo_actions()
        entry_point_function.name = "RESET VECTOR"
        entry_point_function.set_comment_at(
            0x1FF * 2,
            "If PC goes >= 0x400, it rolls over to 0x0 and continues executing from there",
        )
        self.file.forget_undo_actions(undo_id)

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
            if int.from_bytes(data[i], byteorder="little") & 0xF0:
                log_warn(f"Non-null nibble: {int.from_bytes(data[i]):#x} @ {i:#x}")
                return False

        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        # Reset vector is 0x1ff, multiply by 2 because
        # of 12-bit addressable memory space and to match
        # the rest of the other memory translations
        return 0x1FF * 2

    def perform_get_address_size(self):
        return 2


PIC16F54.register()
PIC16F54View.register()
