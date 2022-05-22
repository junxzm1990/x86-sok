//===-- ARMAsmBackend.h - ARM Assembler Backend -----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_LIB_TARGET_ARM_ARMASMBACKEND_H
#define LLVM_LIB_TARGET_ARM_ARMASMBACKEND_H

#include "MCTargetDesc/ARMFixupKinds.h"
#include "MCTargetDesc/ARMMCTargetDesc.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCSubtargetInfo.h"
#include "llvm/Support/TargetRegistry.h"

namespace llvm {

class ARMAsmBackend : public MCAsmBackend {
  const MCSubtargetInfo &STI;
  bool isThumbMode;    // Currently emitting Thumb code.
  bool IsLittleEndian; // Big or little endian.
public:
  ARMAsmBackend(const Target &T, const MCSubtargetInfo &STI, bool IsLittle)
      : MCAsmBackend(), STI(STI),
        isThumbMode(STI.getTargetTriple().isThumb()),
        IsLittleEndian(IsLittle) {}

  unsigned getNumFixupKinds() const override {
    return ARM::NumTargetFixupKinds;
  }

  bool hasNOP() const { return STI.getFeatureBits()[ARM::HasV6T2Ops]; }

  const MCFixupKindInfo &getFixupKindInfo(MCFixupKind Kind) const override;

  bool shouldForceRelocation(const MCAssembler &Asm, const MCFixup &Fixup,
                             const MCValue &Target) override;

  unsigned adjustFixupValue(const MCAssembler &Asm, const MCFixup &Fixup,
                            const MCValue &Target, uint64_t Value,
                            bool IsResolved, MCContext &Ctx,
                            bool IsLittleEndian) const;

  void applyFixup(const MCAssembler &Asm, const MCFixup &Fixup,
                  const MCValue &Target, MutableArrayRef<char> Data,
                  uint64_t Value, bool IsResolved) const override;

  unsigned getRelaxedOpcode(unsigned Op) const;

  bool mayNeedRelaxation(const MCInst &Inst) const override;

  const char *reasonForFixupRelaxation(const MCFixup &Fixup,
                                       uint64_t Value) const;

  bool fixupNeedsRelaxation(const MCFixup &Fixup, uint64_t Value,
                            const MCRelaxableFragment *DF,
                            const MCAsmLayout &Layout) const override;

  void relaxInstruction(const MCInst &Inst, const MCSubtargetInfo &STI,
                        MCInst &Res) const override;

  bool writeNopData(uint64_t Count, MCObjectWriter *OW) const override;

  //ztt add handle FixupSize
  unsigned getFixupKindSize(unsigned Kind) const override {
  switch (Kind) {
  default:
    llvm_unreachable("Unknown fixup kind!");

  case FK_Data_1:
  case ARM::fixup_arm_thumb_bcc:
  case ARM::fixup_arm_thumb_cp:
  case ARM::fixup_thumb_adr_pcrel_10:
    return 1;

  case FK_Data_2:
  case ARM::fixup_arm_thumb_br:
  case ARM::fixup_arm_thumb_cb:
  case ARM::fixup_arm_mod_imm:
    return 2;

  case ARM::fixup_arm_pcrel_10_unscaled:
  case ARM::fixup_arm_ldst_pcrel_12:
  case ARM::fixup_arm_pcrel_10:
  case ARM::fixup_arm_pcrel_9:
  case ARM::fixup_arm_adr_pcrel_12:
  case ARM::fixup_arm_uncondbl:
  case ARM::fixup_arm_condbl:
  case ARM::fixup_arm_blx:
  case ARM::fixup_arm_condbranch:
  case ARM::fixup_arm_uncondbranch:
    return 3;

  case FK_Data_4:
  case ARM::fixup_t2_ldst_pcrel_12:
  case ARM::fixup_t2_condbranch:
  case ARM::fixup_t2_uncondbranch:
  case ARM::fixup_t2_pcrel_10:
  case ARM::fixup_t2_pcrel_9:
  case ARM::fixup_t2_adr_pcrel_12:
  case ARM::fixup_arm_thumb_bl:
  case ARM::fixup_arm_thumb_blx:
  case ARM::fixup_arm_movt_hi16:
  case ARM::fixup_arm_movw_lo16:
  case ARM::fixup_t2_movt_hi16:
  case ARM::fixup_t2_movw_lo16:
  case ARM::fixup_t2_so_imm:
    return 4;

  case FK_SecRel_2:
    return 2;
  case FK_SecRel_4:
    return 4;
  }
  }

  void handleAssemblerFlag(MCAssemblerFlag Flag) override;

  unsigned getPointerSize() const { return 4; }
  bool isThumb() const { return isThumbMode; }
  void setIsThumb(bool it) { isThumbMode = it; }
  bool isLittle() const { return IsLittleEndian; }
};
} // end namespace llvm

#endif
