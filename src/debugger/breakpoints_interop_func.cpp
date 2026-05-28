// Copyright (c) 2026 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.

#include "debugger/breakpoints_interop_func.h"
#include "debugger/breakpoints_interop.h"
#include "metadata/interop_libraries.h"
#include "utils/logger.h"
#include <algorithm>
#include <unordered_set>


namespace netcoredbg
{
namespace InteropDebugging
{

// Must be called only in case all threads stopped and fixed (see InteropDebugger::StopAndDetach()).
void InteropFuncBreakpoints::RemoveAllAtDetach(pid_t pid)
{
    m_breakpointsMutex.lock();

    if (pid != 0)
    {
        for (const auto &entry : m_funcResolvedBreakpoints)
        {
            for (const auto &bp : entry.second)
            {
                if (bp.m_enabled)
                    m_sharedInteropBreakpoints->Remove(pid, entry.first, [](){}, [](std::uintptr_t){});
            }
        }
    }
    m_funcResolvedBreakpoints.clear();
    m_funcBreakpointsMapping.clear();

    m_breakpointsMutex.unlock();
}

int InteropFuncBreakpoints::AllBreakpointsActivate(pid_t pid, bool act, std::function<void()> StopAllThreads, std::function<void(std::uintptr_t)> FixAllThreads)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    int err_code = 0;
    std::unordered_set<uint32_t> failedIDs;

    assert((pid == 0 && m_funcResolvedBreakpoints.empty()) ||
           (pid != 0 && !m_funcResolvedBreakpoints.empty()));

    // resolved breakpoints
    for (auto &addr_bps : m_funcResolvedBreakpoints)
    {
        for (auto &bp : addr_bps.second)
        {
            int tmp = 0;
            if (bp.m_enabled && !act)
                tmp = m_sharedInteropBreakpoints->Remove(pid, addr_bps.first, StopAllThreads, FixAllThreads);
            else if (!bp.m_enabled && act)
                tmp = m_sharedInteropBreakpoints->Add(pid, addr_bps.first, bp.m_isThumbCode, StopAllThreads);

            if (tmp == 0)
                bp.m_enabled = act;
            else
            {
                err_code = tmp;
                failedIDs.emplace(bp.m_id);
            }
        }
    }

    // mapping (for both - resolved and unresolved breakpoints)
    for (auto &bps : m_funcBreakpointsMapping)
    {
        for (auto &bp : bps.second)
        {
            // Note, in case m_enabled field in resolved breakpoint was not changed by error, don't change it here too.
            if (failedIDs.find(bp.m_id) != failedIDs.end())
                continue;

            bp.m_enabled = act;
        }
    }

    return err_code;
}

int InteropFuncBreakpoints::BreakpointActivate(pid_t pid, uint32_t id, bool act, std::function<void()> StopAllThreads, std::function<void(std::uintptr_t)> FixAllThreads)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    assert((pid == 0 && m_funcResolvedBreakpoints.empty()) ||
           (pid != 0 && !m_funcResolvedBreakpoints.empty()));

    auto activateResolved = [&](std::uintptr_t resolved_brkAddr) -> int
    {
        auto bList_it = m_funcResolvedBreakpoints.find(resolved_brkAddr);
        if (bList_it == m_funcResolvedBreakpoints.end())
            return ENOENT;

        for (auto &bp : bList_it->second)
        {
            if (bp.m_id != id)
                continue;

            int err_code = 0;
            if (bp.m_enabled && !act)
                err_code = m_sharedInteropBreakpoints->Remove(pid, resolved_brkAddr, StopAllThreads, FixAllThreads);
            else if (!bp.m_enabled && act)
                err_code = m_sharedInteropBreakpoints->Add(pid, resolved_brkAddr, bp.m_isThumbCode, StopAllThreads);

            if (err_code == 0)
                bp.m_enabled = act;

            return err_code;
        }

        return ENOENT;
    };

    auto activateAllMapped = [&]() -> int
    {
        for (auto &bps : m_funcBreakpointsMapping)
        {
            for (auto &bp : bps.second)
            {
                if (bp.m_id != id)
                    continue;

                int err_code = 0;
                if (bp.m_resolved_brkAddr)
                    err_code = activateResolved(bp.m_resolved_brkAddr); // use mapped data for fast find resolved breakpoint
                
                if (err_code == 0)
                    bp.m_enabled = act;

                return err_code;
            }
        }

        return ENOENT;
    };

    return activateAllMapped();
}

void InteropFuncBreakpoints::AddAllBreakpointsInfo(std::vector<IDebugger::BreakpointInfo> &list)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    // m_funcResolvedBreakpoints should be first
    for (auto &addr_bps : m_funcResolvedBreakpoints)
    {
        list.reserve(list.size() + addr_bps.second.size());
        for(auto &bp : addr_bps.second)
        {
            list.emplace_back(IDebugger::BreakpointInfo{ bp.m_id, true, bp.m_enabled, bp.m_times, "", // TODO bp.m_condition
                                                         bp.m_funcName, 0, 0, bp.m_module, {} });
        }
    }

    for (auto &bps : m_funcBreakpointsMapping)
    {
        list.reserve(list.size() + bps.second.size());

        for(auto &bp : bps.second)
        {
            if (bp.m_resolved_brkAddr)
                continue;

            list.emplace_back(IDebugger::BreakpointInfo{ bp.m_id, false, bp.m_enabled, 0, bp.m_breakpoint.condition,
                                                         bp.m_breakpoint.func, 0, 0, bp.m_breakpoint.module, {} });
        }
    }
}

bool InteropFuncBreakpoints::IsFuncBreakpoint(std::uintptr_t addr, Breakpoint &breakpoint)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    auto find = m_funcResolvedBreakpoints.find(addr);
    if (find == m_funcResolvedBreakpoints.end())
        return false;

    for (auto &br : find->second)
    {
        if (!br.m_enabled)
            continue;

        // TODO condition support

        ++br.m_times;
        br.ToBreakpoint(breakpoint, true);
        return true;
    }

    return false;
}

bool InteropFuncBreakpoints::SetFuncBreakpoints(pid_t pid, InteropLibraries *pInteropLibraries,
                                                const std::vector<FuncBreakpoint> &funcBreakpoints,
                                                std::vector<Breakpoint> &breakpoints,
                                                std::function<void()> StopAllThreads,
                                                std::function<void(std::uintptr_t)> FixAllThreads,
                                                std::function<uint32_t()> getId)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    auto simpleFuncHash = [](const std::string &module, const std::string &func)
    {
        std::string key;
        if (!module.empty())
            key = module + "!";
        key += func;
        return key;
    };

    // Remove only breakpoints that are not in the new funcBreakpoints vector
    std::unordered_set<std::string> funcBreakpointFuncs;
    for (const auto &fb : funcBreakpoints)
    {
        funcBreakpointFuncs.insert(simpleFuncHash(fb.module, fb.func));
    }
    for (auto it = m_funcBreakpointsMapping.begin(); it != m_funcBreakpointsMapping.end();)
    {
        if (funcBreakpointFuncs.find(it->first) == funcBreakpointFuncs.end())
        {
            for (auto &oldBp : it->second)
            {
                // This breakpoint is not in the new list, remove it
                if (oldBp.m_resolved_brkAddr != 0 && pid != 0)
                {
                    auto addr_it = m_funcResolvedBreakpoints.find(oldBp.m_resolved_brkAddr);
                    if (addr_it != m_funcResolvedBreakpoints.end())
                    {
                        for (auto rit = addr_it->second.begin(); rit != addr_it->second.end(); ++rit)
                        {
                            if (rit->m_id == oldBp.m_id)
                            {
                                if (rit->m_enabled)
                                    m_sharedInteropBreakpoints->Remove(pid, oldBp.m_resolved_brkAddr, StopAllThreads, FixAllThreads);
                                addr_it->second.erase(rit);
                                break;
                            }
                        }
                        if (addr_it->second.empty())
                            m_funcResolvedBreakpoints.erase(addr_it);
                    }
                }
            }

            it = m_funcBreakpointsMapping.erase(it);
        }
        else
        {
            ++it;
        }
    }

    if (funcBreakpoints.empty())
        return true;

    // Export function breakpoints
    // Note, VSCode and MI/GDB protocols requires, that "breakpoints" and "funcBreakpoints" must have same indexes for same breakpoints.

    for (const auto &fb : funcBreakpoints)
    {
        std::string key = simpleFuncHash(fb.module, fb.func);

        // Check if this breakpoint already exists, export its info
        auto bpm = m_funcBreakpointsMapping.find(key);
        if (bpm != m_funcBreakpointsMapping.end())
        {
            for (auto &existingBp : bpm->second)
            {
                Breakpoint breakpoint;
                breakpoint.id = existingBp.m_id;
                breakpoint.verified = existingBp.m_resolved_brkAddr != 0;
                breakpoint.funcname = existingBp.m_breakpoint.func;
                breakpoint.params = existingBp.m_breakpoint.params;
                breakpoint.condition = existingBp.m_breakpoint.condition;
                if (existingBp.m_resolved_brkAddr == 0)
                {
                    if (!pid)
                        breakpoint.message = "Function breakpoint pending. Will resolve when debugging starts.";
                    else
                        breakpoint.message = "Function not found in loaded modules; will resolve when module loads";
                }
                breakpoints.push_back(breakpoint);
            }
            continue;
        }

        // New breakpoint, add it
        Breakpoint breakpoint;

        if (pid && pInteropLibraries)
        {
            // Try to resolve against all loaded modules
            // FindAddrByFuncName returns runtime addresses (offset already includes libStartAddr)
            auto entries = pInteropLibraries->FindAddrByFuncName(fb.func, fb.module);
            if (!entries.empty())
            {
                // Create a breakpoint for each match
                for (size_t i = 0; i < entries.size(); ++i)
                {
                    InteropFuncBreakpoint bp;
                    bp.m_id = getId();
                    bp.m_funcName = fb.func;
                    bp.m_module = fb.module;
                    bp.m_enabled = true;
                    bp.m_times = 0;

                    std::uintptr_t resolvedAddr = entries[i].addr; // Already a runtime address
                    bool isThumbCode = false;
#if DEBUGGER_UNIX_ARM
                    isThumbCode = pInteropLibraries->IsThumbCode(resolvedAddr);
#endif

                    bp.m_isThumbCode = isThumbCode;

                    if (bp.m_enabled)
                        m_sharedInteropBreakpoints->Add(pid, resolvedAddr, isThumbCode, StopAllThreads);

                    bp.ToBreakpoint(breakpoint, true);

                    m_funcBreakpointsMapping[key].emplace_back();
                    auto &mapBp = m_funcBreakpointsMapping[key].back();
                    mapBp.m_breakpoint = fb;
                    mapBp.m_id = bp.m_id;
                    mapBp.m_resolved_brkAddr = resolvedAddr;
                    mapBp.m_enabled = bp.m_enabled;

                    // Also add to resolved map
                    InteropFuncBreakpoint resolvedBp = bp;
                    m_funcResolvedBreakpoints[resolvedAddr].push_back(std::move(resolvedBp));

                    breakpoints.push_back(breakpoint);
                }
                continue; // Already added all matches
            }
        }

        // Store as pending (will be resolved on module load)
        InteropFuncBreakpoint bp;
        bp.m_id = getId();
        bp.m_funcName = fb.func;
        bp.m_module = fb.module;
        bp.m_enabled = true;
        bp.m_isThumbCode = false;
        bp.m_times = 0;

        bp.ToBreakpoint(breakpoint, false);
        if (!pid)
            breakpoint.message = "Function breakpoint pending. Will resolve when debugging starts.";
        else
            breakpoint.message = "Function not found in loaded modules; will resolve when module loads";

        m_funcBreakpointsMapping[key].emplace_back();
        auto &mapBp = m_funcBreakpointsMapping[key].back();
        mapBp.m_breakpoint = fb;
        mapBp.m_id = bp.m_id;
        mapBp.m_resolved_brkAddr = 0;
        mapBp.m_enabled = bp.m_enabled;
        breakpoints.push_back(breakpoint);
    }

    return true;
}

void InteropFuncBreakpoints::LoadModule(pid_t pid, InteropLibraries *pInteropLibraries,
                                        std::uintptr_t libStartAddr,
                                        std::function<void()> StopAllThreads,
                                        std::function<void(std::uintptr_t)> FixAllThreads,
                                        std::vector<BreakpointEvent> &events)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    for (auto &initialBreakpoints : m_funcBreakpointsMapping)
    {
        for (auto &initialBreakpoint : initialBreakpoints.second)
        {
            if (initialBreakpoint.m_resolved_brkAddr)
                continue;

            InteropFuncBreakpoint bp;
            bp.m_id = initialBreakpoint.m_id;
            bp.m_module = initialBreakpoint.m_breakpoint.module;
            bp.m_enabled = initialBreakpoint.m_enabled;
            bp.m_funcName = initialBreakpoint.m_breakpoint.func;
            // TODO condition

            auto entries = pInteropLibraries->FindAddrByFuncNameForLib(libStartAddr, bp.m_funcName);
            for (auto &entry : entries)
            {
                std::uintptr_t resolvedAddr = entry.addr;

                bool isThumbCode = false;
#if DEBUGGER_UNIX_ARM
                isThumbCode = pInteropLibraries->IsThumbCode(resolvedAddr);
#endif

                if (bp.m_enabled)
                {
                    // At this point we add breakpoint in unused memory (we are in the middle of lib load process)
                    m_sharedInteropBreakpoints->Add(pid, resolvedAddr, isThumbCode, [](){});
                }

                bp.m_isThumbCode = isThumbCode;

                initialBreakpoint.m_resolved_brkAddr = resolvedAddr;

                Breakpoint breakpoint;
                bp.ToBreakpoint(breakpoint, true);
                events.emplace_back(BreakpointChanged, breakpoint);

                m_funcResolvedBreakpoints[resolvedAddr].push_back(std::move(bp));
            }
        }
    }
}

void InteropFuncBreakpoints::UnloadModule(std::uintptr_t startAddr, std::uintptr_t endAddr,
                                          std::vector<BreakpointEvent> &events)
{
    std::lock_guard<std::mutex> lock(m_breakpointsMutex);

    std::size_t rBrkCount = m_funcResolvedBreakpoints.size();
    for (auto it = m_funcResolvedBreakpoints.begin(); it != m_funcResolvedBreakpoints.end();)
    {
        if (it->first >= startAddr && it->first < endAddr)
            it = m_funcResolvedBreakpoints.erase(it);
        else
            ++it;
    }
    if (rBrkCount == m_funcResolvedBreakpoints.size())
        return;

    for (auto &bps : m_funcBreakpointsMapping)
    {
        for (auto &bp : bps.second)
        {
            if (bp.m_resolved_brkAddr < startAddr || bp.m_resolved_brkAddr > endAddr)
                continue;

            Breakpoint breakpoint;
            breakpoint.id = bp.m_id;
            breakpoint.verified = false;
            breakpoint.funcname = bp.m_breakpoint.func;
            breakpoint.params = bp.m_breakpoint.params;
            breakpoint.condition = bp.m_breakpoint.condition;
            breakpoint.hitCount = 0;
            breakpoint.message = "No executable code of the debugger's target code type is associated with this function.";
            events.emplace_back(BreakpointChanged, breakpoint);
            // reset resolve status
            bp.m_resolved_brkAddr = 0;
        }
    }
}

} // namespace InteropDebugging
} // namespace netcoredbg
