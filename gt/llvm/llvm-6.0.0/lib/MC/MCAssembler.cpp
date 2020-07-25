//===- lib/MC/MCAssembler.cpp - Assembler Backend Implementation ----------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "llvm/MC/MCAssembler.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/ADT/Twine.h"
#include "llvm/MC/MCAsmBackend.h"
#include "llvm/MC/MCAsmInfo.h"
#include "llvm/MC/MCAsmLayout.h"
#include "llvm/MC/MCCodeEmitter.h"
#include "llvm/MC/MCCodeView.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCDwarf.h"
#include "llvm/MC/MCExpr.h"
#include "llvm/MC/MCFixup.h"
#include "llvm/MC/MCFixupKindInfo.h"
#include "llvm/MC/MCFragment.h"
#include "llvm/MC/MCInst.h"
#include "llvm/MC/MCObjectWriter.h"
#include "llvm/MC/MCSection.h"
#include "llvm/MC/MCSectionELF.h"
#include "llvm/MC/MCSymbol.h"
#include "llvm/MC/MCValue.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/LEB128.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <cassert>
#include <cstdint>
#include <cstring>
#include <tuple>

// Koo
#include "llvm/MC/MCObjectFileInfo.h"
#include "llvm/Support/shuffleInfo.pb.h"
#include <sstream>
#include <fstream>
#include <iostream>
#include <string>
#include <iomanip>
#include <map>
#include <set>

#include <utility>

using namespace llvm;

#define DEBUG_TYPE "assembler"

namespace {
namespace stats {

STATISTIC(EmittedFragments, "Number of emitted assembler fragments - total");
STATISTIC(EmittedRelaxableFragments,
          "Number of emitted assembler fragments - relaxable");
STATISTIC(EmittedDataFragments,
          "Number of emitted assembler fragments - data");
STATISTIC(EmittedCompactEncodedInstFragments,
          "Number of emitted assembler fragments - compact encoded inst");
STATISTIC(EmittedAlignFragments,
          "Number of emitted assembler fragments - align");
STATISTIC(EmittedFillFragments,
          "Number of emitted assembler fragments - fill");
STATISTIC(EmittedOrgFragments,
          "Number of emitted assembler fragments - org");
STATISTIC(evaluateFixup, "Number of evaluated fixups");
STATISTIC(FragmentLayouts, "Number of fragment layouts");
STATISTIC(ObjectBytes, "Number of emitted object file bytes");
STATISTIC(RelaxationSteps, "Number of assembler layout and relaxation steps");
STATISTIC(RelaxedInstructions, "Number of relaxed instructions");
STATISTIC(PaddingFragmentsRelaxations,
          "Number of Padding Fragments relaxations");
STATISTIC(PaddingFragmentsBytes,
          "Total size of all padding from adding Fragments");

} // end namespace stats
} // end anonymous namespace

// FIXME FIXME FIXME: There are number of places in this file where we convert
// what is a 64-bit assembler value used for computation into a value in the
// object file, which may truncate it. We should detect that truncation where
// invalid and report errors back.

/* *** */

MCAssembler::MCAssembler(MCContext &Context, MCAsmBackend &Backend,
                         MCCodeEmitter &Emitter, MCObjectWriter &Writer)
    : Context(Context), Backend(Backend), Emitter(Emitter), Writer(Writer),
      BundleAlignSize(0), RelaxAll(false), SubsectionsViaSymbols(false),
      IncrementalLinkerCompatible(false), ELFHeaderEFlags(0) {
  VersionInfo.Major = 0; // Major version == 0 for "none specified"
}

MCAssembler::~MCAssembler() = default;

void MCAssembler::reset() {
  Sections.clear();
  Symbols.clear();
  IndirectSymbols.clear();
  DataRegions.clear();
  LinkerOptions.clear();
  FileNames.clear();
  ThumbFuncs.clear();
  BundleAlignSize = 0;
  RelaxAll = false;
  SubsectionsViaSymbols = false;
  IncrementalLinkerCompatible = false;
  ELFHeaderEFlags = 0;
  LOHContainer.reset();
  VersionInfo.Major = 0;

  // reset objects owned by us
  getBackend().reset();
  getEmitter().reset();
  getWriter().reset();
  getLOHContainer().reset();
}

bool MCAssembler::registerSection(MCSection &Section) {
  if (Section.isRegistered())
    return false;
  Sections.push_back(&Section);
  Section.setIsRegistered(true);
  return true;
}

bool MCAssembler::isThumbFunc(const MCSymbol *Symbol) const {
  if (ThumbFuncs.count(Symbol))
    return true;

  if (!Symbol->isVariable())
    return false;

  const MCExpr *Expr = Symbol->getVariableValue();

  MCValue V;
  if (!Expr->evaluateAsRelocatable(V, nullptr, nullptr))
    return false;

  if (V.getSymB() || V.getRefKind() != MCSymbolRefExpr::VK_None)
    return false;

  const MCSymbolRefExpr *Ref = V.getSymA();
  if (!Ref)
    return false;

  if (Ref->getKind() != MCSymbolRefExpr::VK_None)
    return false;

  const MCSymbol &Sym = Ref->getSymbol();
  if (!isThumbFunc(&Sym))
    return false;

  ThumbFuncs.insert(Symbol); // Cache it.
  return true;
}

bool MCAssembler::isSymbolLinkerVisible(const MCSymbol &Symbol) const {
  // Non-temporary labels should always be visible to the linker.
  if (!Symbol.isTemporary())
    return true;

  // Absolute temporary labels are never visible.
  if (!Symbol.isInSection())
    return false;

  if (Symbol.isUsedInReloc())
    return true;

  return false;
}

const MCSymbol *MCAssembler::getAtom(const MCSymbol &S) const {
  // Linker visible symbols define atoms.
  if (isSymbolLinkerVisible(S))
    return &S;

  // Absolute and undefined symbols have no defining atom.
  if (!S.isInSection())
    return nullptr;

  // Non-linker visible symbols in sections which can't be atomized have no
  // defining atom.
  if (!getContext().getAsmInfo()->isSectionAtomizableBySymbols(
          *S.getFragment()->getParent()))
    return nullptr;

  // Otherwise, return the atom for the containing fragment.
  return S.getFragment()->getAtom();
}

bool MCAssembler::evaluateFixup(const MCAsmLayout &Layout,
                                const MCFixup &Fixup, const MCFragment *DF,
                                MCValue &Target, uint64_t &Value) const {
  ++stats::evaluateFixup;

  // FIXME: This code has some duplication with recordRelocation. We should
  // probably merge the two into a single callback that tries to evaluate a
  // fixup and records a relocation if one is needed.

  // On error claim to have completely evaluated the fixup, to prevent any
  // further processing from being done.
  const MCExpr *Expr = Fixup.getValue();
  MCContext &Ctx = getContext();
  Value = 0;
  if (!Expr->evaluateAsRelocatable(Target, &Layout, &Fixup)) {
    Ctx.reportError(Fixup.getLoc(), "expected relocatable expression");
    return true;
  }
  if (const MCSymbolRefExpr *RefB = Target.getSymB()) {
    if (RefB->getKind() != MCSymbolRefExpr::VK_None) {
      Ctx.reportError(Fixup.getLoc(),
                      "unsupported subtraction of qualified symbol");
      return true;
    }
  }

  bool IsPCRel = Backend.getFixupKindInfo(
    Fixup.getKind()).Flags & MCFixupKindInfo::FKF_IsPCRel;

  bool IsResolved;
  if (IsPCRel) {
    if (Target.getSymB()) {
      IsResolved = false;
    } else if (!Target.getSymA()) {
      IsResolved = false;
    } else {
      const MCSymbolRefExpr *A = Target.getSymA();
      const MCSymbol &SA = A->getSymbol();
      if (A->getKind() != MCSymbolRefExpr::VK_None || SA.isUndefined()) {
        IsResolved = false;
      } else {
        IsResolved = getWriter().isSymbolRefDifferenceFullyResolvedImpl(
            *this, SA, *DF, false, true);
      }
    }
  } else {
    IsResolved = Target.isAbsolute();
  }

  Value = Target.getConstant();

  if (const MCSymbolRefExpr *A = Target.getSymA()) {
    const MCSymbol &Sym = A->getSymbol();
    if (Sym.isDefined())
      Value += Layout.getSymbolOffset(Sym);
  }
  if (const MCSymbolRefExpr *B = Target.getSymB()) {
    const MCSymbol &Sym = B->getSymbol();
    if (Sym.isDefined())
      Value -= Layout.getSymbolOffset(Sym);
  }

  bool ShouldAlignPC = Backend.getFixupKindInfo(Fixup.getKind()).Flags &
                         MCFixupKindInfo::FKF_IsAlignedDownTo32Bits;
  assert((ShouldAlignPC ? IsPCRel : true) &&
    "FKF_IsAlignedDownTo32Bits is only allowed on PC-relative fixups!");

  if (IsPCRel) {
    uint32_t Offset = Layout.getFragmentOffset(DF) + Fixup.getOffset();

    // A number of ARM fixups in Thumb mode require that the effective PC
    // address be determined as the 32-bit aligned version of the actual offset.
    if (ShouldAlignPC) Offset &= ~0x3;
    Value -= Offset;
  }

  // Let the backend force a relocation if needed.
  if (IsResolved && Backend.shouldForceRelocation(*this, Fixup, Target))
    IsResolved = false;

  return IsResolved;
}

uint64_t MCAssembler::computeFragmentSize(const MCAsmLayout &Layout,
                                          const MCFragment &F) const {
  switch (F.getKind()) {
  case MCFragment::FT_Data:
    return cast<MCDataFragment>(F).getContents().size();
  case MCFragment::FT_Relaxable:
    return cast<MCRelaxableFragment>(F).getContents().size();
  case MCFragment::FT_CompactEncodedInst:
    return cast<MCCompactEncodedInstFragment>(F).getContents().size();
  case MCFragment::FT_Fill: {
    auto &FF = cast<MCFillFragment>(F);
    int64_t Size = 0;
    if (!FF.getSize().evaluateAsAbsolute(Size, Layout))
      getContext().reportError(FF.getLoc(),
                               "expected assembly-time absolute expression");
    if (Size < 0) {
      getContext().reportError(FF.getLoc(), "invalid number of bytes");
      return 0;
    }
    return Size;
  }

  case MCFragment::FT_LEB:
    return cast<MCLEBFragment>(F).getContents().size();

  case MCFragment::FT_Padding:
    return cast<MCPaddingFragment>(F).getSize();

  case MCFragment::FT_SymbolId:
    return 4;

  case MCFragment::FT_Align: {
    const MCAlignFragment &AF = cast<MCAlignFragment>(F);
    unsigned Offset = Layout.getFragmentOffset(&AF);
    unsigned Size = OffsetToAlignment(Offset, AF.getAlignment());
    // If we are padding with nops, force the padding to be larger than the
    // minimum nop size.
    if (Size > 0 && AF.hasEmitNops()) {
      while (Size % getBackend().getMinimumNopSize())
        Size += AF.getAlignment();
    }
    if (Size > AF.getMaxBytesToEmit())
      return 0;
    return Size;
  }

  case MCFragment::FT_Org: {
    const MCOrgFragment &OF = cast<MCOrgFragment>(F);
    MCValue Value;
    if (!OF.getOffset().evaluateAsValue(Value, Layout)) {
      getContext().reportError(OF.getLoc(),
                               "expected assembly-time absolute expression");
        return 0;
    }

    uint64_t FragmentOffset = Layout.getFragmentOffset(&OF);
    int64_t TargetLocation = Value.getConstant();
    if (const MCSymbolRefExpr *A = Value.getSymA()) {
      uint64_t Val;
      if (!Layout.getSymbolOffset(A->getSymbol(), Val)) {
        getContext().reportError(OF.getLoc(), "expected absolute expression");
        return 0;
      }
      TargetLocation += Val;
    }
    int64_t Size = TargetLocation - FragmentOffset;
    if (Size < 0 || Size >= 0x40000000) {
      getContext().reportError(
          OF.getLoc(), "invalid .org offset '" + Twine(TargetLocation) +
                           "' (at offset '" + Twine(FragmentOffset) + "')");
      return 0;
    }
    return Size;
  }

  case MCFragment::FT_Dwarf:
    return cast<MCDwarfLineAddrFragment>(F).getContents().size();
  case MCFragment::FT_DwarfFrame:
    return cast<MCDwarfCallFrameFragment>(F).getContents().size();
  case MCFragment::FT_CVInlineLines:
    return cast<MCCVInlineLineTableFragment>(F).getContents().size();
  case MCFragment::FT_CVDefRange:
    return cast<MCCVDefRangeFragment>(F).getContents().size();
  case MCFragment::FT_Dummy:
    llvm_unreachable("Should not have been added");
  }

  llvm_unreachable("invalid fragment kind");
}

void MCAsmLayout::layoutFragment(MCFragment *F) {
  MCFragment *Prev = F->getPrevNode();

  // We should never try to recompute something which is valid.
  assert(!isFragmentValid(F) && "Attempt to recompute a valid fragment!");
  // We should never try to compute the fragment layout if its predecessor
  // isn't valid.
  assert((!Prev || isFragmentValid(Prev)) &&
         "Attempt to compute fragment before its predecessor!");

  ++stats::FragmentLayouts;

  // Compute fragment offset and size.
  if (Prev)
    F->Offset = Prev->Offset + getAssembler().computeFragmentSize(*this, *Prev);
  else
    F->Offset = 0;
  LastValidFragment[F->getParent()] = F;

  // If bundling is enabled and this fragment has instructions in it, it has to
  // obey the bundling restrictions. With padding, we'll have:
  //
  //
  //        BundlePadding
  //             |||
  // -------------------------------------
  //   Prev  |##########|       F        |
  // -------------------------------------
  //                    ^
  //                    |
  //                    F->Offset
  //
  // The fragment's offset will point to after the padding, and its computed
  // size won't include the padding.
  //
  // When the -mc-relax-all flag is used, we optimize bundling by writting the
  // padding directly into fragments when the instructions are emitted inside
  // the streamer. When the fragment is larger than the bundle size, we need to
  // ensure that it's bundle aligned. This means that if we end up with
  // multiple fragments, we must emit bundle padding between fragments.
  //
  // ".align N" is an example of a directive that introduces multiple
  // fragments. We could add a special case to handle ".align N" by emitting
  // within-fragment padding (which would produce less padding when N is less
  // than the bundle size), but for now we don't.
  //
  if (Assembler.isBundlingEnabled() && F->hasInstructions()) {
    assert(isa<MCEncodedFragment>(F) &&
           "Only MCEncodedFragment implementations have instructions");
    uint64_t FSize = Assembler.computeFragmentSize(*this, *F);

    if (!Assembler.getRelaxAll() && FSize > Assembler.getBundleAlignSize())
      report_fatal_error("Fragment can't be larger than a bundle size");

    uint64_t RequiredBundlePadding = computeBundlePadding(Assembler, F,
                                                          F->Offset, FSize);
    if (RequiredBundlePadding > UINT8_MAX)
      report_fatal_error("Padding cannot exceed 255 bytes");
    F->setBundlePadding(static_cast<uint8_t>(RequiredBundlePadding));
    F->Offset += RequiredBundlePadding;
  }
}

void MCAssembler::registerSymbol(const MCSymbol &Symbol, bool *Created) {
  bool New = !Symbol.isRegistered();
  if (Created)
    *Created = New;
  if (New) {
    Symbol.setIsRegistered(true);
    Symbols.push_back(&Symbol);
  }
}

void MCAssembler::writeFragmentPadding(const MCFragment &F, uint64_t FSize,
                                       MCObjectWriter *OW) const {
  // Should NOP padding be written out before this fragment?
  unsigned BundlePadding = F.getBundlePadding();
  if (BundlePadding > 0) {
    assert(isBundlingEnabled() &&
           "Writing bundle padding with disabled bundling");
    assert(F.hasInstructions() &&
           "Writing bundle padding for a fragment without instructions");

    unsigned TotalLength = BundlePadding + static_cast<unsigned>(FSize);
    if (F.alignToBundleEnd() && TotalLength > getBundleAlignSize()) {
      // If the padding itself crosses a bundle boundary, it must be emitted
      // in 2 pieces, since even nop instructions must not cross boundaries.
      //             v--------------v   <- BundleAlignSize
      //        v---------v             <- BundlePadding
      // ----------------------------
      // | Prev |####|####|    F    |
      // ----------------------------
      //        ^-------------------^   <- TotalLength
      unsigned DistanceToBoundary = TotalLength - getBundleAlignSize();
      if (!getBackend().writeNopData(DistanceToBoundary, OW))
          report_fatal_error("unable to write NOP sequence of " +
                             Twine(DistanceToBoundary) + " bytes");
      BundlePadding -= DistanceToBoundary;
    }
    if (!getBackend().writeNopData(BundlePadding, OW))
      report_fatal_error("unable to write NOP sequence of " +
                         Twine(BundlePadding) + " bytes");
  }
}

/// \brief Write the fragment \p F to the output file.
static void writeFragment(const MCAssembler &Asm, const MCAsmLayout &Layout,
                          const MCFragment &F) {
  MCObjectWriter *OW = &Asm.getWriter();

  // FIXME: Embed in fragments instead?
  uint64_t FragmentSize = Asm.computeFragmentSize(Layout, F);

  Asm.writeFragmentPadding(F, FragmentSize, OW);

  // This variable (and its dummy usage) is to participate in the assert at
  // the end of the function.
  uint64_t Start = OW->getStream().tell();
  (void) Start;

  ++stats::EmittedFragments;

  switch (F.getKind()) {
  case MCFragment::FT_Align: {
    ++stats::EmittedAlignFragments;
    const MCAlignFragment &AF = cast<MCAlignFragment>(F);
    assert(AF.getValueSize() && "Invalid virtual align in concrete fragment!");

    uint64_t Count = FragmentSize / AF.getValueSize();

    // FIXME: This error shouldn't actually occur (the front end should emit
    // multiple .align directives to enforce the semantics it wants), but is
    // severe enough that we want to report it. How to handle this?
    if (Count * AF.getValueSize() != FragmentSize)
      report_fatal_error("undefined .align directive, value size '" +
                        Twine(AF.getValueSize()) +
                        "' is not a divisor of padding size '" +
                        Twine(FragmentSize) + "'");

    // See if we are aligning with nops, and if so do that first to try to fill
    // the Count bytes.  Then if that did not fill any bytes or there are any
    // bytes left to fill use the Value and ValueSize to fill the rest.
    // If we are aligning with nops, ask that target to emit the right data.
    if (AF.hasEmitNops()) {
      if (!Asm.getBackend().writeNopData(Count, OW))
        report_fatal_error("unable to write nop sequence of " +
                          Twine(Count) + " bytes");
      break;
    }

    // Otherwise, write out in multiples of the value size.
    for (uint64_t i = 0; i != Count; ++i) {
      switch (AF.getValueSize()) {
      default: llvm_unreachable("Invalid size!");
      case 1: OW->write8 (uint8_t (AF.getValue())); break;
      case 2: OW->write16(uint16_t(AF.getValue())); break;
      case 4: OW->write32(uint32_t(AF.getValue())); break;
      case 8: OW->write64(uint64_t(AF.getValue())); break;
      }
    }
    break;
  }

  case MCFragment::FT_Data: 
    ++stats::EmittedDataFragments;
    OW->writeBytes(cast<MCDataFragment>(F).getContents());
    break;

  case MCFragment::FT_Relaxable:
    ++stats::EmittedRelaxableFragments;
    OW->writeBytes(cast<MCRelaxableFragment>(F).getContents());
    break;

  case MCFragment::FT_CompactEncodedInst:
    ++stats::EmittedCompactEncodedInstFragments;
    OW->writeBytes(cast<MCCompactEncodedInstFragment>(F).getContents());
    break;

  case MCFragment::FT_Fill: {
    ++stats::EmittedFillFragments;
    const MCFillFragment &FF = cast<MCFillFragment>(F);
    uint8_t V = FF.getValue();
    const unsigned MaxChunkSize = 16;
    char Data[MaxChunkSize];
    memcpy(Data, &V, 1);
    for (unsigned I = 1; I < MaxChunkSize; ++I)
      Data[I] = Data[0];

    uint64_t Size = FragmentSize;
    for (unsigned ChunkSize = MaxChunkSize; ChunkSize; ChunkSize /= 2) {
      StringRef Ref(Data, ChunkSize);
      for (uint64_t I = 0, E = Size / ChunkSize; I != E; ++I)
        OW->writeBytes(Ref);
      Size = Size % ChunkSize;
    }
    break;
  }

  case MCFragment::FT_LEB: {
    const MCLEBFragment &LF = cast<MCLEBFragment>(F);
    OW->writeBytes(LF.getContents());
    break;
  }

  case MCFragment::FT_Padding: {
    if (!Asm.getBackend().writeNopData(FragmentSize, OW))
      report_fatal_error("unable to write nop sequence of " +
                         Twine(FragmentSize) + " bytes");
    break;
  }

  case MCFragment::FT_SymbolId: {
    const MCSymbolIdFragment &SF = cast<MCSymbolIdFragment>(F);
    OW->write32(SF.getSymbol()->getIndex());
    break;
  }

  case MCFragment::FT_Org: {
    ++stats::EmittedOrgFragments;
    const MCOrgFragment &OF = cast<MCOrgFragment>(F);

    for (uint64_t i = 0, e = FragmentSize; i != e; ++i)
      OW->write8(uint8_t(OF.getValue()));

    break;
  }

  case MCFragment::FT_Dwarf: {
    const MCDwarfLineAddrFragment &OF = cast<MCDwarfLineAddrFragment>(F);
    OW->writeBytes(OF.getContents());
    break;
  }
  case MCFragment::FT_DwarfFrame: {
    const MCDwarfCallFrameFragment &CF = cast<MCDwarfCallFrameFragment>(F);
    OW->writeBytes(CF.getContents());
    break;
  }
  case MCFragment::FT_CVInlineLines: {
    const auto &OF = cast<MCCVInlineLineTableFragment>(F);
    OW->writeBytes(OF.getContents());
    break;
  }
  case MCFragment::FT_CVDefRange: {
    const auto &DRF = cast<MCCVDefRangeFragment>(F);
    OW->writeBytes(DRF.getContents());
    break;
  }
  case MCFragment::FT_Dummy:
    llvm_unreachable("Should not have been added");
  }

  assert(OW->getStream().tell() - Start == FragmentSize &&
         "The stream should advance by fragment size");
}

void MCAssembler::writeSectionData(const MCSection *Sec,
                                   const MCAsmLayout &Layout) const {
  // Ignore virtual sections.
  if (Sec->isVirtualSection()) {
    assert(Layout.getSectionFileSize(Sec) == 0 && "Invalid size for section!");

    // Check that contents are only things legal inside a virtual section.
    for (const MCFragment &F : *Sec) {
      switch (F.getKind()) {
      default: llvm_unreachable("Invalid fragment in virtual section!");
      case MCFragment::FT_Data: {
        // Check that we aren't trying to write a non-zero contents (or fixups)
        // into a virtual section. This is to support clients which use standard
        // directives to fill the contents of virtual sections.
        const MCDataFragment &DF = cast<MCDataFragment>(F);
        if (DF.fixup_begin() != DF.fixup_end())
          report_fatal_error("cannot have fixups in virtual section!");
        for (unsigned i = 0, e = DF.getContents().size(); i != e; ++i)
          if (DF.getContents()[i]) {
            if (auto *ELFSec = dyn_cast<const MCSectionELF>(Sec))
              report_fatal_error("non-zero initializer found in section '" +
                  ELFSec->getSectionName() + "'");
            else
              report_fatal_error("non-zero initializer found in virtual section");
          }
        break;
      }
      case MCFragment::FT_Align:
        // Check that we aren't trying to write a non-zero value into a virtual
        // section.
        assert((cast<MCAlignFragment>(F).getValueSize() == 0 ||
                cast<MCAlignFragment>(F).getValue() == 0) &&
               "Invalid align in virtual section!");
        break;
      case MCFragment::FT_Fill:
        assert((cast<MCFillFragment>(F).getValue() == 0) &&
               "Invalid fill in virtual section!");
        break;
      }
    }

    return;
  }

  uint64_t Start = getWriter().getStream().tell();
  (void)Start;

  for (const MCFragment &F : *Sec)
    writeFragment(*this, Layout, F);

  assert(getWriter().getStream().tell() - Start ==
         Layout.getSectionAddressSize(Sec));
}

std::tuple<MCValue, uint64_t, bool, bool> // Koo
MCAssembler::handleFixup(const MCAsmLayout &Layout, MCFragment &F, 
                         const MCFixup &Fixup) {
  // Evaluate the fixup.
  MCValue Target;
  uint64_t FixedValue;
  bool IsResolved = evaluateFixup(Layout, Fixup, &F, Target, FixedValue);
  
  // Koo: Fixme - the following line is redundant in evaluateFixup()
  bool IsPCRel = Backend.getFixupKindInfo(Fixup.getKind()).Flags &
                 MCFixupKindInfo::FKF_IsPCRel;
                 
  if (!IsResolved) {
    // The fixup was unresolved, we need a relocation. Inform the object
    // writer of the relocation, and give it an opportunity to adjust the
    // fixup value if need be.
    getWriter().recordRelocation(*this, Layout, &F, Fixup, Target, FixedValue);
  }
  return std::make_tuple(Target, FixedValue, IsResolved, IsPCRel); // Koo
}

// Koo: Dump all fixups if necessary 
//      In .text, .rodata, .data, .data.rel.ro, .eh_frame, and debugging sections
void dumpFixups(std::list<std::tuple<unsigned, unsigned, bool, std::string, std::string, bool, std::string, unsigned, unsigned>> \
                Fixups, std::string kind, bool isDebug) {
  if (Fixups.size() > 0) {
    DEBUG_WITH_TYPE("ccr-metadata", dbgs() << " - Fixups Info (." << kind << "): " << Fixups.size() << "\n");
    unsigned offset, size, numJTEntries, JTEntrySize;
    bool isRel, isNewSection;
    std::string FixupParentID, SymbolRefFixupName, sectionName;
    
    for (auto it = Fixups.begin(); it != Fixups.end(); ++it) {
      std::tie(offset, size, isRel, FixupParentID, SymbolRefFixupName, isNewSection, sectionName, numJTEntries, JTEntrySize) = *it;
      char isRelTF = isRel ? 'T' : 'F';
      if (isDebug && SymbolRefFixupName.length() > 0) {
        errs() << "\t[" << FixupParentID << "]\t(" << offset << ", "  << size << ", " << isRelTF;
        if (SymbolRefFixupName.length() > 0)
          errs() << ", JT#" << SymbolRefFixupName;
        errs() << ")\n";
      }
    }
  }
}

// Koo: Helper function to separate ID into MFID and MBBID
std::tuple<int, int> separateID(std::string ID) {
  return std::make_tuple(std::stoi(ID.substr(0, ID.find("_"))), \
                         std::stoi(ID.substr(ID.find("_") + 1, ID.length())));
}

// Koo: Convert int into hex (0x00abcdef)
template<typename T>
std::string hexlify(T i) {
    std::stringbuf buf;
    std::ostream os(&buf);
    os << "0x" << std::setfill('0') << std::setw(sizeof(T) * 2) << std::hex << i;
    return buf.str();
}

// Koo: Final value updates for the entire layout of both MFs and MBBs
void updateReorderInfoValues(const MCAsmLayout &Layout) {
  const MCAsmInfo *MAI = Layout.getAssembler().getContext().getAsmInfo();
  const MCObjectFileInfo *MOFI = Layout.getAssembler().getContext().getObjectFileInfo();
  std::map<std::string, std::tuple<unsigned, unsigned, std::list<std::string>>> \
        jumpTables = MOFI->getJumpTableTargets();
  
  // Show both MF and MBB offsets according to the final layout order
  DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "\n<MF/MBB Layout Summary>\n");
  DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "----------------------------------------------------------------------------------\n");
  DEBUG_WITH_TYPE("ccr-metadata", dbgs() << " Layout\tMF_MBB_ID\tMBBSize\tAlign\tFixups\tOffset   \tMFSize\tSection\n");
  
  // Deal with MFs and MBBs in a ELF code section (.text) only
  for (MCSection &Sec : Layout.getAssembler()) {
    MCSectionELF &ELFSec = static_cast<MCSectionELF &>(Sec);
    std::string tmpSN, sectionName = ELFSec.getSectionName();
    if (sectionName.find(".text") == 0) {
      unsigned totalOffset = 0, totalFixups = 0, totalAlignSize = 0;
      int MFID, MBBID, prevMFID = -1;
      std::string prevID, canFallThrough;
      unsigned MBBSize, MBBOffset, numFixups, alignSize, MBBType, tmpAssemble;
      std::set<std::string> countedMBBs;
      
      // Per each fragment in a .text section
      for (MCFragment &MCF : Sec) {
        // Here MCDataFragment has combined with the following MCRelaxableFragment or MCAlignFragment
        // Corner case: MCDataFragment with no instruction - just skip it
        if (isa<MCDataFragment>(MCF) && MCF.hasInstructions()) {

	    totalOffset = MCF.getOffset();

        // Update the MBB offset and MF Size for all collected MBBs in the MF
          for (std::string ID : MCF.getAllMBBs()) {
            if (ID.length() == 0 && std::get<0>(MAI->MachineBasicBlocks[ID]) > 0){
		    totalOffset += std::get<0>(MAI->MachineBasicBlocks[ID]);
		    continue;
             // llvm_unreachable("[CCR-Error] MCAssembler(updateReorderInfoValues) - MCSomething went wrong in MCRelaxableFragment: MBB size > 0 with no parentID?");
	    }
          
            if (countedMBBs.find(ID) == countedMBBs.end() && ID.length() > 0) {
              bool isStartMF = false; // check if the new MF begins
              std::tie(MFID, MBBID) = separateID(ID);
              std::tie(MBBSize, MBBOffset, numFixups, alignSize, MBBType, tmpSN, tmpAssemble) = MAI->MachineBasicBlocks[ID];
              
              if (tmpSN.length() > 0) continue;
              MAI->MBBLayoutOrder.push_back(ID);
              
              // Handle a corner case: see handleDirectEmitDirectives() in AsmParser.cpp
              if (MAI->specialCntPriorToFunc > 0) {
                MAI->updateByteCounter(ID, MAI->specialCntPriorToFunc, /*numFixups=*/ 0, /*isAlign=*/ false, /*isInline=*/ false);
                MBBSize += MAI->specialCntPriorToFunc;
                MAI->specialCntPriorToFunc = 0;
              }
  
              // Update the MBB offset, MF Size and section name accordingly
              std::get<1>(MAI->MachineBasicBlocks[ID]) = totalOffset;
              totalOffset += MBBSize;
              totalFixups += numFixups;
              totalAlignSize += alignSize;
              countedMBBs.insert(ID);
              MAI->MachineFunctionSizes[MFID] += MBBSize;
              std::get<5>(MAI->MachineBasicBlocks[ID]) = sectionName;
              canFallThrough = MAI->canMBBFallThrough[ID] ? "*":"";

              if (MFID > prevMFID) {
                isStartMF = true;
                std::get<4>(MAI->MachineBasicBlocks[prevID]) = 1; // Type = End of the function
              }
  
              unsigned layoutID = MCF.getLayoutOrder();
              if (isStartMF) 
                DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "----------------------------------------------------------------------------------\n");
              DEBUG_WITH_TYPE("ccr-metadata", dbgs() << " " << layoutID << "\t[DF " << ID << "]" << canFallThrough << "\t" << MBBSize << "B\t" \
                     << alignSize << "B\t" << numFixups << "\t" << hexlify(totalOffset) << "\t" \
                     << MAI->MachineFunctionSizes[MFID] << "B\t" << "(" << sectionName << ")\n");
                     
              prevMFID = MFID;
              prevID = ID;
            }
          }
        }
      
        // Check out MCRelaxableFragments, which have not combined with any MCDataFragment
        // It happens when there are consecutive MCRelaxableFragment (i.e., switch/case)
        if (isa<MCRelaxableFragment>(MCF) && MCF.hasInstructions()) {
          MCRelaxableFragment &MCRF = static_cast<MCRelaxableFragment&>(MCF);
          std::string ID = MCRF.getInst().getParent();
          
          if (ID.length() == 0 && std::get<0>(MAI->MachineBasicBlocks[ID]) > 0)
              llvm_unreachable("[CCR-Error] MCAssembler(updateReorderInfoValues) - MCSomething went wrong in MCRelaxableFragment: MBB size > 0 with no parentID?");
          
          // If yet the ID has not been showed up along with getAllMBBs(), 
          // it would be an independent RF that does not belong to any DF
          if (countedMBBs.find(ID) == countedMBBs.end() && ID.length() > 0) {
            bool isStartMF = false;
            std::tie(MFID, MBBID) = separateID(ID);
            std::tie(MBBSize, MBBOffset, numFixups, alignSize, MBBType, tmpSN, tmpAssemble) = MAI->MachineBasicBlocks[ID];
            
            if (tmpSN.length() > 0) continue;
            MAI->MBBLayoutOrder.push_back(ID);
            
            // Update the MBB offset, MF Size and section name accordingly
            std::get<1>(MAI->MachineBasicBlocks[ID]) = totalOffset;
            totalOffset += MBBSize;
            totalFixups += numFixups;
            totalAlignSize += alignSize;
            countedMBBs.insert(ID);
            MAI->MachineFunctionSizes[MFID] += MBBSize;
            std::get<5>(MAI->MachineBasicBlocks[ID]) = sectionName;
            canFallThrough = MAI->canMBBFallThrough[ID] ? "*":"";
            
            if (MFID > prevMFID) {
              isStartMF = true;
              std::get<4>(MAI->MachineBasicBlocks[prevID]) = 1; // Type = End of the function
            }
            
            unsigned layoutID = MCF.getLayoutOrder();
            if (isStartMF) 
              DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "----------------------------------------------------------------------------------\n");
            DEBUG_WITH_TYPE("ccr-metadata", dbgs() << " " << layoutID << "\t[DF " << ID << "]" << canFallThrough << "\t" << MBBSize << "B\t" \
                     << alignSize << "B\t" << numFixups << "\t" << hexlify(totalOffset) << "\t" \
                     << MAI->MachineFunctionSizes[MFID] << "B\t" << "(" << sectionName << ")\n");
                     
            prevMFID = MFID;
            prevID = ID;
          }
        }
      }
      
      // The last ID Type is always the end of the object
      // binpang, here we treat the end of section is both end of object and function
      std::get<4>(MAI->MachineBasicBlocks[prevID]) = 3; 

      DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "----------------------------------------------------------------------------------\n");
      DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "Code(B)\tNOPs(B)\tMFs\tMBBs\tFixups\n");
      DEBUG_WITH_TYPE("ccr-metadata", dbgs() << totalOffset << "\t" << totalAlignSize << "\t" << MAI->MachineFunctionSizes.size() \
                                             << "\t" << MAI->MachineBasicBlocks.size() << "\t" << totalFixups << "\n"); 
      DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "\tLegend\n\t(*) FallThrough MBB\n  ");
    }
  }
  
  // Dump if there is any CFI-generated JT
  if (jumpTables.size() > 0) {
    DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "\n<Jump Tables Summary>\n");
    unsigned totalEntries = 0;
    for(auto it = jumpTables.begin(); it != jumpTables.end(); ++it) {
      int JTI, MFID, MFID2, MBBID;
      unsigned entryKind, entrySize;
      std::list<std::string> JTEntries;
      
      std::tie(MFID, JTI) = separateID(it->first);
      std::tie(entryKind, entrySize, JTEntries) = it->second;
      
      DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "[JT@Function#" << MFID << "_" << JTI << "] " << "(Kind: " \
                      << entryKind << ", " << JTEntries.size() << " Entries of " << entrySize << "B each)\n");

      for (std::string JTE : JTEntries) {
        std::tie(MFID2, MBBID) = separateID(JTE);
        totalEntries++;
        if (MFID != MFID2)
          errs() << "[CCR-Error] MCAssembler::updateReorderInfoValues - JT Entry points to the outside of MF! \n";
        DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "\t[" << JTE << "]\t" << \
                        hexlify(std::get<1>(MAI->MachineBasicBlocks[JTE])) << "\n");
      }
    }
    
    DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "#JTs\t#Entries\n" << jumpTables.size() << "\t" << totalEntries << "\n");
  }
}

// Koo: These sections contain the fixups that we want to handle
static const char* fixupLookupSections[] = 
{
    ".text",
    ".rodata",
    ".data",
    ".data.rel.ro",
    ".init_array",
};


// Koo: Helper functions for serializeReorderInfo()
int getFixupSectionId(std::string secName) {
    for (size_t i = 0; i < sizeof(fixupLookupSections)/sizeof(*fixupLookupSections); ++i)
        if (secName.compare(fixupLookupSections[i]) == 0)
            return i;
    return -1;
}

ShuffleInfo::ReorderInfo_FixupInfo_FixupTuple* getFixupTuple(ShuffleInfo::ReorderInfo_FixupInfo* FI, std::string secName) {
  switch (getFixupSectionId(secName)) {
    case 0: return FI->add_text();
    case 1: return FI->add_rodata();
    case 2: return FI->add_data();
    case 3: return FI->add_datarel();
    case 4: return FI->add_initarray();
    default: llvm_unreachable("[CCR-Error] ShuffleInfo::getFixupTuple - No such section to collect fixups!");
  }
}

void setFixups(std::list<std::tuple<unsigned, unsigned, bool, std::string, std::string, bool, std::string, unsigned, unsigned>> Fixups,
               ShuffleInfo::ReorderInfo_FixupInfo* fixupInfo, std::string secName) {
  unsigned FixupOffset, FixupSize, FixupisRela, numJTEntries, JTEntrySize;
  std::string sectionName, FixupParentID, SymbolRefFixupName;
  bool isNewSection;
  
  for (auto F = Fixups.begin(); F != Fixups.end(); ++F) {
    ShuffleInfo::ReorderInfo_FixupInfo_FixupTuple* pFixupTuple = getFixupTuple(fixupInfo, secName);
    std::tie(FixupOffset, FixupSize, FixupisRela, FixupParentID, \
             SymbolRefFixupName, isNewSection, sectionName, numJTEntries, JTEntrySize) = *F;
    pFixupTuple->set_offset(FixupOffset);
    pFixupTuple->set_deref_sz(FixupSize);
    pFixupTuple->set_is_rela(FixupisRela);
    pFixupTuple->set_section_name(sectionName);
    if (isNewSection) 
      pFixupTuple->set_type(4); // let linker know if there are multiple .text sections
    else
      pFixupTuple->set_type(0); // c2c, c2d, d2c, d2d default=0; should be updated by linker
  
    // The following jump table information is fixups in .text for JT entry update only (pic/pie)
    if (numJTEntries > 0) {
       pFixupTuple->set_num_jt_entries(numJTEntries);
       pFixupTuple->set_jt_entry_sz(JTEntrySize);
    }
  }
}

// Koo: Serialize all information for future reordering, which has been stored in MCAsmInfo
void serializeReorderInfo(ShuffleInfo::ReorderInfo* ri, const MCAsmLayout &Layout) {
  // Set the binary information for reordering
  ShuffleInfo::ReorderInfo_BinaryInfo* binaryInfo = ri->mutable_bin();
  binaryInfo->set_rand_obj_offset(0x0);     // Should be updated at linking time
  binaryInfo->set_main_addr_offset(0x0);    // Should be updated at linking time
  
  const MCAsmInfo *MAI = Layout.getAssembler().getContext().getAsmInfo();
  
  // Identify this object file has been compiled from:
  //    obj_type = 0: a general source file (i.e., *.c, *.cc, *.cpp, ...)
  //    obj_type = 1: a source file that contains inline assembly
  //    obj_type = 2: standalone assembly file (i.e., *.s, *.S, ...)
  if (MAI->isAssemFile)
    binaryInfo->set_src_type(2);
  else if (MAI->hasInlineAssembly)
    binaryInfo->set_src_type(1);
  else
    binaryInfo->set_src_type(0);

  updateReorderInfoValues(Layout);
  
  // Set the layout of both Machine Functions and Machine Basic Blocks with protobuf definition
  std::string sectionName;
  unsigned MBBSize, MBBoffset, numFixups, alignSize, MBBtype, assembleType;
  unsigned objSz = 0, numFuncs = 0, numBBs = 0;
  int MFID, MBBID, prevMFID = 0;

  for (auto MBBI = MAI->MBBLayoutOrder.begin(); MBBI != MAI->MBBLayoutOrder.end(); ++MBBI) {
    ShuffleInfo::ReorderInfo_LayoutInfo* layoutInfo = ri->add_layout();
    std::string ID = *MBBI;
    std::tie(MFID, MBBID) = separateID(ID);
    std::tie(MBBSize, MBBoffset, numFixups, alignSize, MBBtype, sectionName, assembleType) = MAI->MachineBasicBlocks[ID];
    bool MBBFallThrough = MAI->canMBBFallThrough[ID];
 
    layoutInfo->set_bb_size(MBBSize);
    layoutInfo->set_type(MBBtype);
    layoutInfo->set_num_fixups(numFixups);
    layoutInfo->set_bb_fallthrough(MBBFallThrough);
    layoutInfo->set_section_name(sectionName);

    // binpang, add. handle inline assemble code
    layoutInfo->set_assemble_type(assembleType);

    // binpang, add padding size and offset of basic block
    layoutInfo->set_padding_size(alignSize);
    layoutInfo->set_offset(MBBoffset);
    
    if (MFID > prevMFID) {
      numFuncs++;
      numBBs = 0;
    }
    
    objSz += MBBSize;
    numBBs++;
    prevMFID = MFID;
  }

  binaryInfo->set_obj_sz(objSz);
  
  // Set the fixup information (.text, .rodata, .data, .data.rel.ro and .init_array)
  ShuffleInfo::ReorderInfo_FixupInfo* fixupInfo = ri->add_fixup();
  setFixups(MAI->FixupsText, fixupInfo, ".text");
  setFixups(MAI->FixupsRodata, fixupInfo, ".rodata");
  setFixups(MAI->FixupsData, fixupInfo, ".data");
  setFixups(MAI->FixupsDataRel, fixupInfo, ".data.rel.ro");
  setFixups(MAI->FixupsInitArray, fixupInfo, ".init_array");
  
  // Show the fixup information for each section
  DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "\n<Fixups Summary>\n");
  dumpFixups(MAI->FixupsText, "text", /*isDebug*/ false);
  dumpFixups(MAI->FixupsRodata, "rodata", false);
  dumpFixups(MAI->FixupsData, "data", false);
  dumpFixups(MAI->FixupsDataRel, "data.rel.ro", false);
  dumpFixups(MAI->FixupsInitArray, "init_array", false);
}

void MCAssembler::layout(MCAsmLayout &Layout) {
  DEBUG_WITH_TYPE("mc-dump", {
      errs() << "assembler backend - pre-layout\n--\n";
      dump(); });

  // Create dummy fragments and assign section ordinals.
  unsigned SectionIndex = 0;
  for (MCSection &Sec : *this) {
    // Create dummy fragments to eliminate any empty sections, this simplifies
    // layout.
    if (Sec.getFragmentList().empty())
      new MCDataFragment(&Sec);

    Sec.setOrdinal(SectionIndex++);
  }

  // Assign layout order indices to sections and fragments.
  for (unsigned i = 0, e = Layout.getSectionOrder().size(); i != e; ++i) {
    MCSection *Sec = Layout.getSectionOrder()[i];
    Sec->setLayoutOrder(i);

    unsigned FragmentIndex = 0;
    for (MCFragment &Frag : *Sec)
      Frag.setLayoutOrder(FragmentIndex++);
  }

  // Layout until everything fits.
  while (layoutOnce(Layout))
    if (getContext().hadError())
      return;

  DEBUG_WITH_TYPE("mc-dump", {
      errs() << "assembler backend - post-relaxation\n--\n";
      dump(); });

  // Finalize the layout, including fragment lowering.
  finishLayout(Layout);

  DEBUG_WITH_TYPE("mc-dump", {
      errs() << "assembler backend - final-layout\n--\n";
      dump(); });

  // Allow the object writer a chance to perform post-layout binding (for
  // example, to set the index fields in the symbol data).
  getWriter().executePostLayoutBinding(*this, Layout);

  // Koo - Collect what we need once layout has been finalized
  const MCAsmInfo *MAI = Layout.getAssembler().getContext().getAsmInfo();
  const MCObjectFileInfo *MOFI = Layout.getAssembler().getContext().getObjectFileInfo();
  bool isNewTextSection = false, isNewRodataSection = false;
  bool isNewDataSection = false, isNewDataRelSection = false, isNewInitSection = false;
  unsigned textSecCtr = 0, rodataSecCtr = 0, dataSecCtr = 0, dataRelSecCtr = 0, initSecCtr = 0;
  unsigned prevLayoutOrder;
  
  // Evaluate and apply the fixups, generating relocation entries as necessary.
  for (MCSection &Sec : *this) {
    // Koo
    MCSectionELF &ELFSec = static_cast<MCSectionELF &>(Sec);
    std::string secName = ELFSec.getSectionName();
    unsigned layoutOrder = ELFSec.getLayoutOrder();
    
    for (MCFragment &Frag : Sec) {
      // Data and relaxable fragments both have fixups.  So only process
      // those here.
      // FIXME: Is there a better way to do this?  MCEncodedFragmentWithFixups
      // being templated makes this tricky.
      
      // Koo - Attach the size of the alignment to the previous fragment.
      //       Here assumes a) no two alignments are consecutive.
      //                    b) data fragment (DF or RF) exists prior to AF. (may be broken in assembly)
      uint64_t fragOffset = Frag.getOffset();
      MCFragment *prevFrag;
      
      if (isa<MCDataFragment>(&Frag) && Frag.hasInstructions())
        prevFrag = static_cast<MCDataFragment*>(&Frag);
    
      if (isa<MCRelaxableFragment>(&Frag) && Frag.hasInstructions())
        prevFrag = static_cast<MCRelaxableFragment*>(&Frag);
    
      // Update alignment size to reflect to the size of MF and MBB
      if (MOFI->getObjectFileType() == llvm::MCObjectFileInfo::IsELF && \
         secName.find(".text") == 0 && (isa<MCAlignFragment>(&Frag)) && fragOffset > 0) {
         // Push this alignment to the previous MBB and the MF that the MBB belongs to
         unsigned alignSize;
         std::string ID;
         if (isa<MCDataFragment>(*prevFrag))
           ID = static_cast<MCDataFragment*>(prevFrag)->getLastParentTag();
         if (isa<MCRelaxableFragment>(*prevFrag))
           ID = static_cast<MCRelaxableFragment*>(prevFrag)->getInst().getParent();
         
         alignSize = computeFragmentSize(Layout, Frag);
         MAI->updateByteCounter(ID, alignSize, 0, /*isAlign=*/ true, /*isInline=*/ false);
      }
      
      if (isa<MCEncodedFragment>(&Frag) &&
          isa<MCCompactEncodedInstFragment>(&Frag))
        continue;
      if (!isa<MCEncodedFragment>(&Frag) && !isa<MCCVDefRangeFragment>(&Frag))
        continue;
      ArrayRef<MCFixup> Fixups;
      MutableArrayRef<char> Contents;
      if (auto *FragWithFixups = dyn_cast<MCDataFragment>(&Frag)) {
        Fixups = FragWithFixups->getFixups();
        Contents = FragWithFixups->getContents();
      } else if (auto *FragWithFixups = dyn_cast<MCRelaxableFragment>(&Frag)) {
        Fixups = FragWithFixups->getFixups();
        Contents = FragWithFixups->getContents();
      } else if (auto *FragWithFixups = dyn_cast<MCCVDefRangeFragment>(&Frag)) {
        Fixups = FragWithFixups->getFixups();
        Contents = FragWithFixups->getContents();
      } else
        llvm_unreachable("Unknown fragment with fixups!");
      for (const MCFixup &Fixup : Fixups) {
        uint64_t FixedValue;
        bool IsResolved;
        bool IsPCRel; // Koo
        MCValue Target;
        std::tie(Target, FixedValue, IsResolved, IsPCRel) = // Koo
            handleFixup(Layout, Frag, Fixup);
        getBackend().applyFixup(*this, Fixup, Target, Contents, FixedValue,
                                IsResolved);
                                
        // Koo: Collect fixups here (ELF format only)
        if (MOFI->getObjectFileType() == llvm::MCObjectFileInfo::IsELF) {
            unsigned offset = fragOffset + Fixup.getOffset();
            unsigned derefSize = 1 << getBackend().getFixupKindLog2Size(Fixup.getKind());
            unsigned jtEntryKind = 0, jtEntrySize = 0, numJTEntries = 0;
            std::map<std::string, std::tuple<unsigned, unsigned, std::list<std::string>>> JTs = MOFI->getJumpTableTargets();
            std::string fixupParentID = Fixup.getFixupParentID();
            std::string SymbolRefFixupName = Fixup.getSymbolRefFixupName();
            std::list<std::string> JTEs; // contains all target(MFID_MBBID) in the JT
            
            // The following handles multiple sections in C++
            if (secName.find(".text") == 0) {
              if (textSecCtr == 0) {
                prevLayoutOrder = layoutOrder;
                textSecCtr++;
              }
              else {
                isNewTextSection = (layoutOrder == prevLayoutOrder) ? false:true;
                if (isNewTextSection) textSecCtr++;
                prevLayoutOrder = layoutOrder;
              }
              if (Fixup.getIsJumpTableRef()) {
                std::tie(jtEntryKind, jtEntrySize, JTEs) = JTs[Fixup.getSymbolRefFixupName()];
                numJTEntries = JTEs.size();
              }
              MAI->FixupsText.push_back(std::make_tuple(offset, derefSize, IsPCRel, \
                   fixupParentID, SymbolRefFixupName, isNewTextSection, secName, numJTEntries, jtEntrySize));
            }
            
            else if (secName.find(".rodata") == 0) {
              if (rodataSecCtr == 0) {
                prevLayoutOrder = layoutOrder;
                rodataSecCtr++;
              }
              else {
                isNewRodataSection = (layoutOrder == prevLayoutOrder) ? false:true;
                if (isNewRodataSection) rodataSecCtr++;
                prevLayoutOrder = layoutOrder;
              }
              MAI->FixupsRodata.push_back(std::make_tuple(offset, derefSize, IsPCRel, \
                   fixupParentID, SymbolRefFixupName, isNewRodataSection, secName, numJTEntries, jtEntrySize));
            }
            
            else if (secName.find(".data") == 0) {
              // The following special section could be generated to support RELRO option
              // "When gcc sees a variable which is constant but requires a dynamic relocation, 
              // it puts it into a section named .data.rel.ro"
              if (secName.find(".data.rel.ro") == 0) {
                if (dataRelSecCtr == 0) {
                  prevLayoutOrder = layoutOrder;
                  dataRelSecCtr++;
                }
                else {
                  isNewDataRelSection = (layoutOrder == prevLayoutOrder) ? false:true;
                  if (isNewDataRelSection) dataRelSecCtr++;
                  prevLayoutOrder = layoutOrder;
                }
                MAI->FixupsDataRel.push_back(std::make_tuple(offset, derefSize, IsPCRel, \
                     fixupParentID, SymbolRefFixupName, isNewDataRelSection, secName, numJTEntries, jtEntrySize));
              }
              
              else {
                if (dataSecCtr == 0) {
                  prevLayoutOrder = layoutOrder;
                  dataSecCtr++;
                }
                else {
                  isNewDataSection =  (layoutOrder == prevLayoutOrder) ? false:true;
                  if (isNewDataSection) dataSecCtr++;
                  prevLayoutOrder = layoutOrder;
                }
                MAI->FixupsData.push_back(std::make_tuple(offset, derefSize, IsPCRel, \
                     fixupParentID, SymbolRefFixupName, isNewDataSection, secName, numJTEntries, jtEntrySize));
              }
            }
          
            else if (secName.find(".init_array") == 0) {
              if (initSecCtr == 0) {
                prevLayoutOrder = layoutOrder;
                initSecCtr++;
              }
              else {
                isNewInitSection = (layoutOrder == prevLayoutOrder) ? false:true;
                if (isNewInitSection) initSecCtr++;
                prevLayoutOrder = layoutOrder;
              }
              MAI->FixupsInitArray.push_back(std::make_tuple(offset, derefSize, IsPCRel, \
                   fixupParentID, SymbolRefFixupName, isNewInitSection, secName, numJTEntries, jtEntrySize));
            }
            
            // else // debug_* sections
        }
      }
    }
  }
}

// Koo: Serialize reorder_info data with Google's protocol buffer format, calling by
//      ELFObjectWriter::writeSectionData() from writeObject()@ELFObjectWriter.cpp
void MCAssembler::WriteRandInfo(const MCAsmLayout &Layout) const {
  ShuffleInfo::ReorderInfo reorder_info;
  serializeReorderInfo(&reorder_info, Layout);
  std::string randContents;
  
  if (!reorder_info.SerializeToString(&randContents)) {
    errs() << "[CCR-Error] MCAssembler::WriteRandInfo - Failed to serialize the shuffling information to .rand section! \n";
  }
  
  MCObjectWriter& OW = (*this).getWriter();
  OW.writeBytes(randContents);
  std::string objFileName(Layout.getAssembler().getContext().getMainFileName());
  
  if (objFileName.length() == 0)
    objFileName = getObjTmpName();

  DEBUG_WITH_TYPE("ccr-metadata", dbgs() << "Successfully wrote the metadata in a .rand section for " << objFileName << "\n");
  google::protobuf::ShutdownProtobufLibrary();
}

void MCAssembler::Finish() {
  // Create the layout object.
  MCAsmLayout Layout(*this);
  layout(Layout);

  raw_ostream &OS = getWriter().getStream();
  uint64_t StartOffset = OS.tell();

  // Write the object file.
  getWriter().writeObject(*this, Layout);

  stats::ObjectBytes += OS.tell() - StartOffset;
}

bool MCAssembler::fixupNeedsRelaxation(const MCFixup &Fixup,
                                       const MCRelaxableFragment *DF,
                                       const MCAsmLayout &Layout) const {
  MCValue Target;
  uint64_t Value;
  bool Resolved = evaluateFixup(Layout, Fixup, DF, Target, Value);
  if (Target.getSymA() &&
      Target.getSymA()->getKind() == MCSymbolRefExpr::VK_X86_ABS8 &&
      Fixup.getKind() == FK_Data_1)
    return false;
  return getBackend().fixupNeedsRelaxationAdvanced(Fixup, Resolved, Value, DF,
                                                   Layout);
}

bool MCAssembler::fragmentNeedsRelaxation(const MCRelaxableFragment *F,
                                          const MCAsmLayout &Layout) const {
  // If this inst doesn't ever need relaxation, ignore it. This occurs when we
  // are intentionally pushing out inst fragments, or because we relaxed a
  // previous instruction to one that doesn't need relaxation.
  if (!getBackend().mayNeedRelaxation(F->getInst()))
    return false;

  for (const MCFixup &Fixup : F->getFixups())
    if (fixupNeedsRelaxation(Fixup, F, Layout))
      return true;

  return false;
}

bool MCAssembler::relaxInstruction(MCAsmLayout &Layout,
                                   MCRelaxableFragment &F) {
  // Koo
  // Whether or not the instruction has been relaxed
  // The RelaxableFragment must be counted as the emitted bytes
  const MCAsmInfo *MAI = Layout.getAssembler().getContext().getAsmInfo();
  std::string ID = F.getInst().getParent();
  unsigned relaxedBytes = F.getRelaxedBytes();
  unsigned fixupCtr = F.getFixup();
  
  if (!fragmentNeedsRelaxation(&F, Layout)) {
    // [Case 1] Unrelaxed instruction
    if (ID.length() > 0) {
      unsigned curBytes = F.getInst().getByteCtr();
      if (relaxedBytes < curBytes) {
        // RelaxableFragment always contains relaxedBytes and fixupCtr variable 
        // for the adjustment in case of re-evaluation (simple hack but tricky)
        MAI->updateByteCounter(ID, curBytes - relaxedBytes, 1 - fixupCtr, 
                              /*isAlign=*/ false, /*isInline=*/ false);
        F.setRelaxedBytes(curBytes);
        F.setFixup(1);
        
        // If this fixup points to Jump Table Symbol, update it.
        F.getFixups()[0].setFixupParentID(ID);
      }
    }
    return false;
  }
    
  ++stats::RelaxedInstructions;

  // FIXME-PERF: We could immediately lower out instructions if we can tell
  // they are fully resolved, to avoid retesting on later passes.

  // Relax the fragment.

  MCInst Relaxed;
  getBackend().relaxInstruction(F.getInst(), F.getSubtargetInfo(), Relaxed);

  // Encode the new instruction.
  //
  // FIXME-PERF: If it matters, we could let the target do this. It can
  // probably do so more efficiently in many cases.
  SmallVector<MCFixup, 4> Fixups;
  SmallString<256> Code;
  raw_svector_ostream VecOS(Code);
  getEmitter().encodeInstruction(Relaxed, VecOS, Fixups, F.getSubtargetInfo());

  // Update the fragment.
  F.setInst(Relaxed);
  F.getContents() = Code;
  F.getFixups() = Fixups;

  // Koo [Case 2] Relaxed instruction: 
  // The only relaxations X86 does is from a 1byte pcrel to a 4byte pcrel
  // Note: The relaxable fragment could be re-evaluated multiple times for relaxation
  //       Thus update it only if the relaxable fragment has not been relaxed previously 
  if (relaxedBytes < Code.size() && ID.length() > 0) {
    MAI->updateByteCounter(ID, Code.size() - relaxedBytes, 1 - fixupCtr, \
                           /*isAlign=*/ false, /*isInline=*/ false);
    F.setRelaxedBytes(Code.size());
    F.setFixup(1);
    F.getFixups()[0].setFixupParentID(ID);
  }
  
  return true;
}

bool MCAssembler::relaxPaddingFragment(MCAsmLayout &Layout,
                                       MCPaddingFragment &PF) {
  uint64_t OldSize = PF.getSize();
  if (!getBackend().relaxFragment(&PF, Layout))
    return false;
  uint64_t NewSize = PF.getSize();

  ++stats::PaddingFragmentsRelaxations;
  stats::PaddingFragmentsBytes += NewSize;
  stats::PaddingFragmentsBytes -= OldSize;
  return true;
}

bool MCAssembler::relaxLEB(MCAsmLayout &Layout, MCLEBFragment &LF) {
  uint64_t OldSize = LF.getContents().size();
  int64_t Value;
  bool Abs = LF.getValue().evaluateKnownAbsolute(Value, Layout);
  if (!Abs)
    report_fatal_error("sleb128 and uleb128 expressions must be absolute");
  SmallString<8> &Data = LF.getContents();
  Data.clear();
  raw_svector_ostream OSE(Data);
  if (LF.isSigned())
    encodeSLEB128(Value, OSE);
  else
    encodeULEB128(Value, OSE);
  return OldSize != LF.getContents().size();
}

bool MCAssembler::relaxDwarfLineAddr(MCAsmLayout &Layout,
                                     MCDwarfLineAddrFragment &DF) {
  MCContext &Context = Layout.getAssembler().getContext();
  uint64_t OldSize = DF.getContents().size();
  int64_t AddrDelta;
  bool Abs = DF.getAddrDelta().evaluateKnownAbsolute(AddrDelta, Layout);
  assert(Abs && "We created a line delta with an invalid expression");
  (void) Abs;
  int64_t LineDelta;
  LineDelta = DF.getLineDelta();
  SmallString<8> &Data = DF.getContents();
  Data.clear();
  raw_svector_ostream OSE(Data);
  MCDwarfLineAddr::Encode(Context, getDWARFLinetableParams(), LineDelta,
                          AddrDelta, OSE);
  return OldSize != Data.size();
}

bool MCAssembler::relaxDwarfCallFrameFragment(MCAsmLayout &Layout,
                                              MCDwarfCallFrameFragment &DF) {
  MCContext &Context = Layout.getAssembler().getContext();
  uint64_t OldSize = DF.getContents().size();
  int64_t AddrDelta;
  bool Abs = DF.getAddrDelta().evaluateKnownAbsolute(AddrDelta, Layout);
  assert(Abs && "We created call frame with an invalid expression");
  (void) Abs;
  SmallString<8> &Data = DF.getContents();
  Data.clear();
  raw_svector_ostream OSE(Data);
  MCDwarfFrameEmitter::EncodeAdvanceLoc(Context, AddrDelta, OSE);
  return OldSize != Data.size();
}

bool MCAssembler::relaxCVInlineLineTable(MCAsmLayout &Layout,
                                         MCCVInlineLineTableFragment &F) {
  unsigned OldSize = F.getContents().size();
  getContext().getCVContext().encodeInlineLineTable(Layout, F);
  return OldSize != F.getContents().size();
}

bool MCAssembler::relaxCVDefRange(MCAsmLayout &Layout,
                                  MCCVDefRangeFragment &F) {
  unsigned OldSize = F.getContents().size();
  getContext().getCVContext().encodeDefRange(Layout, F);
  return OldSize != F.getContents().size();
}

bool MCAssembler::layoutSectionOnce(MCAsmLayout &Layout, MCSection &Sec) {
  // Holds the first fragment which needed relaxing during this layout. It will
  // remain NULL if none were relaxed.
  // When a fragment is relaxed, all the fragments following it should get
  // invalidated because their offset is going to change.
  MCFragment *FirstRelaxedFragment = nullptr;

  // Attempt to relax all the fragments in the section.
  for (MCSection::iterator I = Sec.begin(), IE = Sec.end(); I != IE; ++I) {
    // Check if this is a fragment that needs relaxation.
    bool RelaxedFrag = false;
    switch(I->getKind()) {
    default:
      break;
    case MCFragment::FT_Relaxable:
      assert(!getRelaxAll() &&
             "Did not expect a MCRelaxableFragment in RelaxAll mode");
      RelaxedFrag = relaxInstruction(Layout, *cast<MCRelaxableFragment>(I));
      break;
    case MCFragment::FT_Dwarf:
      RelaxedFrag = relaxDwarfLineAddr(Layout,
                                       *cast<MCDwarfLineAddrFragment>(I));
      break;
    case MCFragment::FT_DwarfFrame:
      RelaxedFrag =
        relaxDwarfCallFrameFragment(Layout,
                                    *cast<MCDwarfCallFrameFragment>(I));
      break;
    case MCFragment::FT_LEB:
      RelaxedFrag = relaxLEB(Layout, *cast<MCLEBFragment>(I));
      break;
    case MCFragment::FT_Padding:
      RelaxedFrag = relaxPaddingFragment(Layout, *cast<MCPaddingFragment>(I));
      break;
    case MCFragment::FT_CVInlineLines:
      RelaxedFrag =
          relaxCVInlineLineTable(Layout, *cast<MCCVInlineLineTableFragment>(I));
      break;
    case MCFragment::FT_CVDefRange:
      RelaxedFrag = relaxCVDefRange(Layout, *cast<MCCVDefRangeFragment>(I));
      break;
    }
    if (RelaxedFrag && !FirstRelaxedFragment)
      FirstRelaxedFragment = &*I;
  }
  if (FirstRelaxedFragment) {
    Layout.invalidateFragmentsFrom(FirstRelaxedFragment);
    return true;
  }
  return false;
}

bool MCAssembler::layoutOnce(MCAsmLayout &Layout) {
  ++stats::RelaxationSteps;

  bool WasRelaxed = false;
  for (iterator it = begin(), ie = end(); it != ie; ++it) {
    MCSection &Sec = *it;
    while (layoutSectionOnce(Layout, Sec))
      WasRelaxed = true;
  }

  return WasRelaxed;
}

void MCAssembler::finishLayout(MCAsmLayout &Layout) {
  // The layout is done. Mark every fragment as valid.
  for (unsigned int i = 0, n = Layout.getSectionOrder().size(); i != n; ++i) {
    MCSection &Section = *Layout.getSectionOrder()[i];
    Layout.getFragmentOffset(&*Section.rbegin());
    computeFragmentSize(Layout, *Section.rbegin());
  }
  getBackend().finishLayout(*this, Layout);
}
