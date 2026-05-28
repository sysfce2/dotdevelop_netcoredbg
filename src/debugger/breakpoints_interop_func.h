// Copyright (c) 2026 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.
#pragma once

#ifdef INTEROP_DEBUGGING

#include <cstdint>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>
#include "interfaces/types.h"
#include "interfaces/idebugger.h"

namespace netcoredbg
{
namespace InteropDebugging
{

class InteropBreakpoints;
class InteropLibraries;

class InteropFuncBreakpoints
{
public:

    InteropFuncBreakpoints(std::shared_ptr<InteropBreakpoints> &sharedInteropBreakpoints) :
        m_sharedInteropBreakpoints(sharedInteropBreakpoints)
    {}

    // Remove all native function breakpoints at interop detach.
    void RemoveAllAtDetach(pid_t pid);

    // Set/update function breakpoints. Called from Breakpoints::SetFuncBreakpoints().
    // pid=0 means no process yet (store as pending).
    // Returns: false on error, true on success.
    bool SetFuncBreakpoints(pid_t pid, InteropLibraries *pInteropLibraries,
                            const std::vector<FuncBreakpoint> &funcBreakpoints,
                            std::vector<Breakpoint> &breakpoints,
                            std::function<void()> StopAllThreads,
                            std::function<void(std::uintptr_t)> FixAllThreads,
                            std::function<uint32_t()> getId);

    // Activate/deactivate all function breakpoints.
    int AllBreakpointsActivate(pid_t pid, bool act,
                               std::function<void()> StopAllThreads,
                               std::function<void(std::uintptr_t)> FixAllThreads);

    // Activate/deactivate a single function breakpoint.
    int BreakpointActivate(pid_t pid, uint32_t id, bool act,
                           std::function<void()> StopAllThreads,
                           std::function<void(std::uintptr_t)> FixAllThreads);

    // Check if a native breakpoint hit is a function breakpoint.
    // Returns true and fills 'breakpoint' if matched.
    bool IsFuncBreakpoint(std::uintptr_t addr, Breakpoint &breakpoint);

    // Resolve pending breakpoints after a native module is loaded.
    // Called from InteropDebugger::LoadLib().
    void LoadModule(pid_t pid, InteropLibraries *pInteropLibraries,
                    std::uintptr_t libStartAddr,
                    std::function<void()> StopAllThreads,
                    std::function<void(std::uintptr_t)> FixAllThreads,
                    std::vector<BreakpointEvent> &events);

    // Revert resolved breakpoints when a native module is unloaded.
    // Called from InteropDebugger::UnloadLib().
    void UnloadModule(std::uintptr_t startAddr, std::uintptr_t endAddr,
                      std::vector<BreakpointEvent> &events);

    // Add all function breakpoint info for enumeration.
    void AddAllBreakpointsInfo(std::vector<IDebugger::BreakpointInfo> &list);

private:

    struct InteropFuncBreakpoint
    {
        uint32_t m_id;
        std::string m_module;
        std::string m_funcName;
        bool m_enabled;
        bool m_isThumbCode;
        uint32_t m_times;
        // TODO `m_condition` support

        InteropFuncBreakpoint() : m_id(0), m_enabled(true), m_isThumbCode(false), m_times(0) {}

        void ToBreakpoint(Breakpoint &breakpoint, bool verified) const
        {
            breakpoint.id = this->m_id;
            breakpoint.verified = verified;
            breakpoint.funcname = this->m_funcName;
            breakpoint.module = this->m_module;
            breakpoint.hitCount = this->m_times;
        }
    };

    struct InteropFuncBreakpointMapping
    {
        FuncBreakpoint m_breakpoint;
        uint32_t m_id;
        bool m_enabled;
        std::uintptr_t m_resolved_brkAddr;
        InteropFuncBreakpointMapping() : m_breakpoint("","",""), m_id(0), m_enabled(true), m_resolved_brkAddr(0) {}
        ~InteropFuncBreakpointMapping() = default;
    };

    std::mutex m_breakpointsMutex;
    std::shared_ptr<InteropBreakpoints> m_sharedInteropBreakpoints;

    // Resolved function breakpoints: address -> list of breakpoints at that address
    std::unordered_map<std::uintptr_t, std::list<InteropFuncBreakpoint>> m_funcResolvedBreakpoints;

    // All function breakpoints
    std::unordered_map<std::string, std::list<InteropFuncBreakpointMapping>> m_funcBreakpointsMapping;
};

} // namespace InteropDebugging
} // namespace netcoredbg

#endif // INTEROP_DEBUGGING
