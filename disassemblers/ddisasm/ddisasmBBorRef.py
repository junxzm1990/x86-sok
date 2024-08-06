import logging
import argparse
import subprocess
import time
from enum import Enum
from pathlib import Path

import blocks_pb2
import refInf_pb2
import gtirb
from gtirb_capstone.instructions import GtirbInstructionDecoder

logging.basicConfig(level=logging.INFO)


class DdisasmError(Exception):
    """
    Exception raised when ddisasm fails
    """

    pass


def disassemble(binary: Path, output: Path):
    """
    Run ddisasm on the given binary

    :param binary: the path to a binary to run ddisasm on
    :param output: the path to the output
    """
    try:
        subprocess.run(
            ["ddisasm", binary, "--ir", output, "-j", "1"], check=True
        )
    except subprocess.CalledProcessError as e:
        raise DdisasmError(f"ddisasm failed on {binary}: {e}")


def addBB(
    block: gtirb.CodeBlock,
    pbFunc: blocks_pb2.Function,
    decoder: GtirbInstructionDecoder,
):
    """
    Add the given block to the given pb function
    """
    pbBB = pbFunc.bb.add()
    pbBB.size = block.size
    pbBB.va = block.address
    pbBB.parent = pbFunc.va

    logging.debug(
        "The basic block address is 0x{0:x}, size is {1}".format(
            pbBB.va, pbBB.size
        )
    )

    for instr in decoder.get_instructions(block):
        instr.address
        logging.debug(
            "Instruction address is 0x{0:x}, size is {1}".format(
                instr.address, instr.size
            )
        )
        pbInst = pbBB.instructions.add()
        pbInst.va = instr.address
        pbInst.size = instr.size

    # get successors
    for out_edge in block.outgoing_edges:
        target_block = out_edge.target
        if not isinstance(target_block, gtirb.ProxyBlock):
            child = pbBB.child.add()
            child.va = target_block.address
            logging.debug(
                "Successor of 0x{0:x}: 0x{1:x}".format(
                    block.address, target_block.address
                )
            )


def dumpBlocks(ir: gtirb.IR, output: Path) -> None:
    """
    Create pb blocks for the given IR and dump the results to the given
    output path.
    """
    for m in ir.modules:
        logging.info("Module %s", m.name)
        decoder = GtirbInstructionDecoder(m.isa)

        bb_set = set()
        module = blocks_pb2.module()
        for function, func_name in m.aux_data["functionNames"].data.items():
            entries = m.aux_data.get("functionEntries").data[function]
            logging.debug("function: %s", func_name)

            # Pick the lowest address if there are multiple entries
            entry_block = min(entries)

            pbFunc = module.fuc.add()
            pbFunc.va = entry_block.address

            for block in m.aux_data["functionBlocks"].data[function]:
                addBB(block, pbFunc, decoder)
                bb_set.add(block)

        # Add the rest of blocks that do not belong to any function
        dummyFunc = module.fuc.add()
        dummyFunc.va = 0x0
        for block in m.code_blocks:
            if block in bb_set:
                continue
            addBB(block, dummyFunc, decoder)
            bb_set.add(block)

        if len(ir.modules) > 1:
            output = output.with_suffix(f"{m.name}.pb")

        logging.info("Writing output to %s", output)
        with open(output, "wb") as f:
            f.write(module.SerializeToString())


def ref_size(module: gtirb.Module) -> int:
    if (
        module.isa == gtirb.Module.ISA.IA32
        or module.isa == gtirb.Module.ISA.ARM
        or module.isa == gtirb.Module.ISA.MIPS32
    ):
        return 4
    elif (
        module.isa == gtirb.Module.ISA.X64
        or module.isa == gtirb.Module.ISA.ARM64
    ):
        return 8
    else:
        assert "Unsupported ISA"


def dumpRefs(ir: gtirb.IR, output: Path) -> None:
    """
    Collect symbol references and dump the results to the given output path.
    """

    refInf = refInf_pb2.RefList()

    def update_ref(module, ref, from_addr, to_addr, kind):
        ref.ref_va = from_addr
        ref.target_va = to_addr
        ref.kind = kind
        ref.ref_size = ref_size(module)

    class RefKind(Enum):
        C2C = 0
        C2D = 1
        D2C = 2
        D2D = 3

    def ref_kind(from_block, to_block) -> int:
        if isinstance(from_block, gtirb.CodeBlock) and isinstance(
            to_block, gtirb.CodeBlock
        ):
            return RefKind.C2C
        elif isinstance(from_block, gtirb.CodeBlock) and isinstance(
            to_block, gtirb.DataBlock
        ):
            return RefKind.C2D
        elif isinstance(from_block, gtirb.DataBlock) and isinstance(
            to_block, gtirb.CodeBlock
        ):
            return RefKind.D2C
        elif isinstance(from_block, gtirb.DataBlock) and isinstance(
            to_block, gtirb.DataBlock
        ):
            return RefKind.D2D
        else:
            assert False

    for m in ir.modules:
        for block in m.byte_blocks:
            sym_exprs = block.byte_interval.symbolic_expressions_at(
                range(block.address, block.address + block.size)
            )
            for bi, offset, sym_expr in sym_exprs:
                from_addr = bi.address + offset

                for symbol in sym_expr.symbols:
                    if symbol._payload is None:
                        continue

                    if isinstance(symbol._payload, gtirb.Block):
                        tblock = symbol._payload
                        if isinstance(tblock, gtirb.ProxyBlock):
                            # This is an external reference which is not
                            # captured here.
                            continue

                        to_addr = tblock.address
                        kind = ref_kind(block, tblock).value

                    else:  # int
                        to_addr = symbol._payload
                        kind = 0  # TODO

                    ref = refInf.ref.add()
                    update_ref(m, ref, from_addr, to_addr, kind)

                    logging.debug(
                        "%d: From 0x%x -> 0x%x"
                        % (kind, ref.ref_va, ref.target_va)
                    )

    logging.info("Collect Refs done! ready to write output...")
    with open(output, "wb") as f:
        f.write(refInf.SerializeToString())


class FileType(Enum):
    IR = "ir"
    ELF = "elf"
    PE = "pe"
    OTHERS = "others"


def get_magic_file_type(file_path: Path) -> FileType:
    """
    Get the FileType of the given file
    """
    with open(file_path, "rb") as magic_fp:
        magic = magic_fp.read(5)
        if magic[:5] == b"GTIRB":
            return FileType.IR
        elif magic[:4] == b"\x7fELF":
            return FileType.ELF
        else:
            dos_header = magic_fp.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                return FileType.OTHERS
            pe_offset = int.from_bytes(dos_header[60:64], byteorder="little")
            magic_fp.seek(pe_offset)
            if magic_fp.read(4) == b"PE\x00\x00":
                return FileType.PE
            else:
                return FileType.OTHERS


class ExtractMode(Enum):
    BB = "bb"
    REF = "ref"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-m",
        "--mode",
        choices=[ExtractMode.BB.value, ExtractMode.REF.value],
        help="Select extract-mode: `bb` or `ref`",
        default=ExtractMode.BB.value,
    )
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        help="input binary or gtirb-IR file",
        required=True,
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output of the protobuf file",
        required=True,
    )
    args = parser.parse_args()

    file_type = get_magic_file_type(args.input)

    if file_type == FileType.ELF or file_type == FileType.PE:
        logging.info("Run ddisasm on %s", args.input)
        start = time.monotonic()
        ir_path = args.output.with_suffix(".gtirb")
        disassemble(args.input, ir_path)
        logging.info("Done with ddisasm.")
        end = time.monotonic()
        logging.info(f"time-for-ddisasm: {args.input}: {end - start:.2f}")
    elif file_type == FileType.IR:
        ir_path = args.input
    else:
        logging.warning(f"Unknown file type: %s", args.input)
        exit(1)

    logging.info("Load gtirb-IR: %s...", ir_path)
    ir = gtirb.IR.load_protobuf(ir_path)
    logging.info("Done loading.")

    try:
        mode = ExtractMode(args.mode)
    except ValueError:
        logging.error("Invalid mode specified. Use 'bb' or 'ref'.")
        exit(1)

    if mode == ExtractMode.BB:
        logging.info("Dump blocks...")
        dumpBlocks(ir, args.output)
        logging.info("Done dumping blocks.")
    elif mode == ExtractMode.REF:
        logging.info("Dump refs...")
        dumpRefs(ir, args.output)
        logging.info("Done dumping refs.")

    logging.info("All done.")
