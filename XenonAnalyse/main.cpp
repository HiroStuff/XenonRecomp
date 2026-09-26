#include <cassert>
#include <iterator>
#include <file.h>
#include <disasm.h>
#include <image.h>
#include <xbox.h>
#include <fmt/core.h>
#include "function.h"

//Added Search for and print out register save/load locations
//modificated from this fork: https://github.com/hedge-dev/XenonRecomp/pull/108
#include "fmt/xchar.h"
#include "function.h"
#include <algorithm>
#include <file.h>

#define SWITCH_ABSOLUTE 0
#define SWITCH_COMPUTED 1
#define SWITCH_BYTEOFFSET 2
#define SWITCH_SHORTOFFSET 3

struct SwitchTable
{
    std::vector<size_t> labels{};
    size_t base{};
    size_t defaultLabel{};
    uint32_t r{};
    uint32_t type{};
};

static const uint8_t RESTGPRLR_14[] = { 0xe9, 0xc1, 0xff, 0x68 };
static const uint8_t SAVEGPRLR_14[] = { 0xf9, 0xc1, 0xff, 0x68 };
static const uint8_t RESTFPR_14[] = { 0xc9, 0xcc, 0xff, 0x70 };
static const uint8_t SAVEFPR_14[] = { 0xd9, 0xcc, 0xff, 0x70 };
static const uint8_t RESTVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x60, 0xce };
static const uint8_t SAVEVMX_14[] = { 0x39, 0x60, 0xfe, 0xe0, 0x7d, 0xcb, 0x61, 0xce };
static const uint8_t RESTVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x60, 0xcb };
static const uint8_t SAVEVMX_64[] = { 0x39, 0x60, 0xfc, 0x00, 0x10, 0x0b, 0x61, 0xcb };
// Pattern for RtlUnwind call - used to find longjmp
// Looking for: bl RtlUnwind (branch link instruction)
// The actual pattern varies, so we search for function calls that reference RtlUnwind
static const uint8_t RTLUNWIND_PATTERN[] = { 0x48, 0x00, 0x00, 0x01 }; // bl (branch link) with link bit set

uint32_t BytePatternSearch(uint8_t* data, const uint32_t dataSize, const uint32_t baseAddress, const uint8_t pattern[], const size_t patternSize)
{
    auto result = std::search(data, data + dataSize, pattern, pattern + patternSize);
    if (result != data + dataSize) {
        return baseAddress + std::distance(data, result);
    }

    return UINT32_MAX;
}

void FindSetjmpLongjmp(Image& image)
{
    uint32_t rtlUnwindAddress = UINT32_MAX;

    for (const auto& symbol : image.symbols)
    {
        if (symbol.name == "__imp__RtlUnwind")
        {
            rtlUnwindAddress = static_cast<uint32_t>(symbol.address);
            break;
        }
    }

    if (rtlUnwindAddress == UINT32_MAX)
    {
        fmt::println("RtlUnwind is not imported by this XEX.");
        fmt::println("Do not try to guess longjmp/setjmp addresses.");
        return;
    }

    fmt::println("RtlUnwind thunk = 0x{:X}", rtlUnwindAddress);

    bool foundCaller = false;

    for (const auto& section : image.sections)
    {
        if (!(section.flags & SectionFlags_Code))
            continue;

        auto* code = reinterpret_cast<uint32_t*>(section.data);
        const uint32_t count = section.size / 4;

        for (uint32_t i = 0; i < count; i++)
        {
            const uint32_t instruction = ByteSwap(code[i]);

            if (PPC_OP(instruction) != PPC_OP_B)
                continue;

            if (!PPC_BL(instruction))
                continue;

            if (PPC_BA(instruction))
                continue;

            const uint32_t address =
            static_cast<uint32_t>(section.base + i * 4);

            const uint32_t target =
            address + PPC_BI(instruction);

            if (target == rtlUnwindAddress)
            {
                fmt::println(
                    "RtlUnwind call at 0x{:X}",
                    address
                );

                foundCaller = true;
            }
        }
    }

    if (!foundCaller)
        fmt::println("No direct calls to RtlUnwind found.");
}

void RegisterFunctionsSearch(Image& image)
{
    auto searchPattern = [&](const uint8_t* pattern, size_t patternSize) -> uint32_t
    {
        for (const auto& section : image.sections)
        {
            if (!(section.flags & SectionFlags_Code))
                continue;

            uint32_t address = BytePatternSearch(
                section.data,
                section.size,
                static_cast<uint32_t>(section.base),
                                                 pattern,
                                                 patternSize);

            if (address != UINT32_MAX)
                return address;
        }

        return UINT32_MAX;
    };

    const uint32_t restgprlr_14 = searchPattern(RESTGPRLR_14, sizeof(RESTGPRLR_14));
    const uint32_t savegprlr_14 = searchPattern(SAVEGPRLR_14, sizeof(SAVEGPRLR_14));
    const uint32_t restfpr_14 = searchPattern(RESTFPR_14, sizeof(RESTFPR_14));
    const uint32_t savefpr_14 = searchPattern(SAVEFPR_14, sizeof(SAVEFPR_14));
    const uint32_t restvmx_14 = searchPattern(RESTVMX_14, sizeof(RESTVMX_14));
    const uint32_t savevmx_14 = searchPattern(SAVEVMX_14, sizeof(SAVEVMX_14));
    const uint32_t restvmx_64 = searchPattern(RESTVMX_64, sizeof(RESTVMX_64));
    const uint32_t savevmx_64 = searchPattern(SAVEVMX_64, sizeof(SAVEVMX_64));

    auto printAddress = [](const char* name, uint32_t address)
    {
        if (address == UINT32_MAX)
            fmt::println("{} = FAILED TO FIND", name);
        else
            fmt::println("{} = 0x{:X}", name, address);
    };

    printAddress("restgprlr_14_address", restgprlr_14);
    printAddress("savegprlr_14_address", savegprlr_14);
    printAddress("restfpr_14_address", restfpr_14);
    printAddress("savefpr_14_address", savefpr_14);
    printAddress("restvmx_14_address", restvmx_14);
    printAddress("savevmx_14_address", savevmx_14);
    printAddress("restvmx_64_address", restvmx_64);
    printAddress("savevmx_64_address", savevmx_64);

    FindSetjmpLongjmp(image);
}

void ReadTable(Image& image, SwitchTable& table)
{
    uint32_t pOffset;
    ppc_insn insn;
    auto* code = (uint32_t*)image.Find(table.base);
    ppc::Disassemble(code, table.base, insn);
    pOffset = insn.operands[1] << 16;

    ppc::Disassemble(code + 1, table.base + 4, insn);
    pOffset += insn.operands[2];

    if (table.type == SWITCH_ABSOLUTE)
    {
        const auto* offsets = (be<uint32_t>*)image.Find(pOffset);
        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = offsets[i];
        }
    }
    else if (table.type == SWITCH_COMPUTED)
    {
        uint32_t base;
        uint32_t shift;
        const auto* offsets = (uint8_t*)image.Find(pOffset);

        ppc::Disassemble(code + 4, table.base + 0x10, insn);
        base = insn.operands[1] << 16;

        ppc::Disassemble(code + 5, table.base + 0x14, insn);
        base += insn.operands[2];

        ppc::Disassemble(code + 3, table.base + 0x0C, insn);
        shift = insn.operands[2];

        for (size_t i = 0; i < table.labels.size(); i++)
        {
            table.labels[i] = base + (offsets[i] << shift);
        }
    }
    else if (table.type == SWITCH_BYTEOFFSET || table.type == SWITCH_SHORTOFFSET)
    {
        if (table.type == SWITCH_BYTEOFFSET)
        {
            const auto* offsets = (uint8_t*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 3, table.base + 0x0C, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
        else if (table.type == SWITCH_SHORTOFFSET)
        {
            const auto* offsets = (be<uint16_t>*)image.Find(pOffset);
            uint32_t base;

            ppc::Disassemble(code + 4, table.base + 0x10, insn);
            base = insn.operands[1] << 16;

            ppc::Disassemble(code + 5, table.base + 0x14, insn);
            base += insn.operands[2];

            for (size_t i = 0; i < table.labels.size(); i++)
            {
                table.labels[i] = base + offsets[i];
            }
        }
    }
    else
    {
        assert(false);
    }
}

void ScanTable(const uint32_t* code, size_t base, SwitchTable& table)
{
    ppc_insn insn;
    uint32_t cr{ (uint32_t)-1 };
    for (int i = 0; i < 32; i++)
    {
        ppc::Disassemble(&code[-i], base - (4 * i), insn);
        if (insn.opcode == nullptr)
        {
            continue;
        }

        if (cr == -1 && (insn.opcode->id == PPC_INST_BGT || insn.opcode->id == PPC_INST_BGTLR || insn.opcode->id == PPC_INST_BLE || insn.opcode->id == PPC_INST_BLELR))
        {
            cr = insn.operands[0];
            if (insn.opcode->operands[1] != 0)
            {
                table.defaultLabel = insn.operands[1];
            }
        }
        else if (cr != -1)
        {
            if (insn.opcode->id == PPC_INST_CMPLWI && insn.operands[0] == cr)
            {
                table.r = insn.operands[1];
                table.labels.resize(insn.operands[2] + 1);
                table.base = base;
                break;
            }
        }
    }
}

void MakeMask(const uint32_t* instructions, size_t count)
{
    ppc_insn insn;
    for (size_t i = 0; i < count; i++)
    {
        ppc::Disassemble(&instructions[i], 0, insn);
        fmt::println("0x{:X}, // {}", ByteSwap(insn.opcode->opcode | (insn.instruction & insn.opcode->mask)), insn.opcode->name);
    }
}

void* SearchMask(const void* source, const uint32_t* compare, size_t compareCount, size_t size)
{
    assert(size % 4 == 0);
    uint32_t* src = (uint32_t*)source;
    size_t count = size / 4;
    ppc_insn insn;

    for (size_t i = 0; i < count; i++)
    {
        size_t c = 0;
        for (c = 0; c < compareCount; c++)
        {
            ppc::Disassemble(&src[i + c], 0, insn);
            if (insn.opcode == nullptr || insn.opcode->id != compare[c])
            {
                break;
            }
        }

        if (c == compareCount)
        {
            return &src[i];
        }
    }

    return nullptr;
}

static std::string out;

template<class... Args>
static void println(fmt::format_string<Args...> fmt, Args&&... args)
{
    fmt::vformat_to(std::back_inserter(out), fmt.get(), fmt::make_format_args(args...));
    out += '\n';
};

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("Usage: XenonAnalyse [input XEX file path] [output jump table TOML file path]");
        return EXIT_SUCCESS;
    }

    const auto file = LoadFile(argv[1]);
    auto image = Image::ParseImage(file.data(), file.size());

       RegisterFunctionsSearch(image);
    
    auto printTable = [&](const SwitchTable& table)
        {
            println("[[switch]]");
            println("base = 0x{:X}", table.base);
            println("r = {}", table.r);
            println("default = 0x{:X}", table.defaultLabel);
            println("labels = [");
            for (const auto& label : table.labels)
            {
                println("    0x{:X},", label);
            }

            println("]");
            println("");
        };

    std::vector<SwitchTable> switches{};

    println("# Generated by XenonAnalyse");

    auto scanPattern = [&](uint32_t* pattern, size_t count, size_t type)
        {
            for (const auto& section : image.sections)
            {
                if (!(section.flags & SectionFlags_Code))
                {
                    continue;
                }

                size_t base = section.base;
                uint8_t* data = section.data;
                uint8_t* dataStart = section.data;
                uint8_t* dataEnd = section.data + section.size;
                while (data < dataEnd && data != nullptr)
                {
                    data = (uint8_t*)SearchMask(data, pattern, count, dataEnd - data);

                    if (data != nullptr)
                    {
                        SwitchTable table{};
                        table.type = type;
                        ScanTable((uint32_t*)data, base + (data - dataStart), table);

                        // fmt::println("{:X} ; jmptable - {}", base + (data - dataStart), table.labels.size());
                        if (table.base != 0)
                        {
                            ReadTable(image, table);
                            printTable(table);
                            switches.emplace_back(std::move(table));
                        }

                        data += 4;
                    }
                    continue;
                }
            }
        };

    uint32_t absoluteSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LWZX,
        PPC_INST_MTCTR,
        PPC_INST_BCTR,
    };

    uint32_t computedSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_RLWINM,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t offsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_LBZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    uint32_t wordOffsetSwitch[] =
    {
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_RLWINM,
        PPC_INST_LHZX,
        PPC_INST_LIS,
        PPC_INST_ADDI,
        PPC_INST_ADD,
        PPC_INST_MTCTR,
    };

    println("# ---- ABSOLUTE JUMPTABLE ----");
    scanPattern(absoluteSwitch, std::size(absoluteSwitch), SWITCH_ABSOLUTE);

    println("# ---- COMPUTED JUMPTABLE ----");
    scanPattern(computedSwitch, std::size(computedSwitch), SWITCH_COMPUTED);

    println("# ---- OFFSETED JUMPTABLE ----");
    scanPattern(offsetSwitch, std::size(offsetSwitch), SWITCH_BYTEOFFSET);
    scanPattern(wordOffsetSwitch, std::size(wordOffsetSwitch), SWITCH_SHORTOFFSET);

    std::ofstream f(argv[2]);
    f.write(out.data(), out.size());

    return EXIT_SUCCESS;
}
