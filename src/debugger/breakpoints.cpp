// Copyright (c) 2017 Samsung Electronics Co., LTD
// Distributed under the MIT License.
// See the LICENSE file in the project root for more information.

#include "debugger/breakpoint_break.h"
#include "debugger/breakpoint_entry.h"
#include "debugger/breakpoints_exception.h"
#include "debugger/breakpoints_func.h"
#include "debugger/breakpoints_line.h"
#include "debugger/breakpoints.h"
#include "debugger/breakpointutils.h"

#include <mutex>
#include <unordered_set>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <sstream>
#include "metadata/modules.h"
#include "metadata/typeprinter.h"
#include "utils/logger.h"
#include "utils/utf.h"
#include "managed/interop.h"
#include "utils/filesystem.h"

#include <palclr.h>

using std::string;

namespace netcoredbg
{

void Breakpoints::SetJustMyCode(bool enable)
{
    m_uniqueFuncBreakpoints->SetJustMyCode(enable);
    m_uniqueLineBreakpoints->SetJustMyCode(enable);
}

void Breakpoints::SetLastStoppedIlOffset(ICorDebugProcess *pProcess, const ThreadId &lastStoppedThreadId)
{
    m_uniqueBreakBreakpoint->SetLastStoppedIlOffset(pProcess, lastStoppedThreadId);
}

void Breakpoints::SetStopAtEntry(bool enable)
{
    m_uniqueEntryBreakpoint->SetStopAtEntry(enable);
}

HRESULT Breakpoints::ManagedCallbackBreak(ICorDebugAppDomain *pAppDomain, ICorDebugThread *pThread, const ThreadId &lastStoppedThreadId)
{
    return m_uniqueBreakBreakpoint->ManagedCallbackBreak(pAppDomain, pThread, lastStoppedThreadId);
}

HRESULT Breakpoints::InsertExceptionBreakpoint(const ExceptionBreakMode &mode, const std::string &name, uint32_t &id)
{
    m_nextBreakpointIdMutex.lock();
    id = m_nextBreakpointId++;
    m_nextBreakpointIdMutex.unlock();

    return m_uniqueExceptionBreakpoints->InsertExceptionBreakpoint(mode, name, id);
}

HRESULT Breakpoints::DeleteExceptionBreakpoint(const uint32_t id)
{
    return m_uniqueExceptionBreakpoints->DeleteExceptionBreakpoint(id);
}

HRESULT Breakpoints::GetExceptionInfoResponse(ICorDebugProcess *pProcess, ThreadId threadId, ExceptionInfoResponse &exceptionInfoResponse)
{
    return m_uniqueExceptionBreakpoints->GetExceptionInfoResponse(pProcess, threadId, exceptionInfoResponse);
}

void Breakpoints::DeleteAll()
{
    m_uniqueEntryBreakpoint->Delete();
    m_uniqueFuncBreakpoints->DeleteAll();
    m_uniqueLineBreakpoints->DeleteAll();
}

HRESULT Breakpoints::DisableAll(ICorDebugProcess *pProcess)
{
    HRESULT Status;
    ToRelease<ICorDebugAppDomainEnum> domains;
    IfFailRet(pProcess->EnumerateAppDomains(&domains));

    ICorDebugAppDomain *curDomain;
    ULONG domainsFetched;
    while (SUCCEEDED(domains->Next(1, &curDomain, &domainsFetched)) && domainsFetched == 1)
    {
        ToRelease<ICorDebugAppDomain> pDomain(curDomain);
        ToRelease<ICorDebugBreakpointEnum> breakpoints;
        if (FAILED(pDomain->EnumerateBreakpoints(&breakpoints)))
            continue;

        ICorDebugBreakpoint *curBreakpoint;
        ULONG breakpointsFetched;
        while (SUCCEEDED(breakpoints->Next(1, &curBreakpoint, &breakpointsFetched)) && breakpointsFetched == 1)
        {
            ToRelease<ICorDebugBreakpoint> pBreakpoint(curBreakpoint);
            pBreakpoint->Activate(FALSE);
        }
    }

    return S_OK;
}

HRESULT Breakpoints::SetFuncBreakpoints(ICorDebugProcess *pProcess, const std::vector<FuncBreakpoint> &funcBreakpoints, std::vector<Breakpoint> &breakpoints)
{
    return m_uniqueFuncBreakpoints->SetFuncBreakpoints(pProcess, funcBreakpoints, breakpoints, [&]() -> uint32_t
    {
        std::lock_guard<std::mutex> lock(m_nextBreakpointIdMutex);
        return m_nextBreakpointId++;
    });
}

HRESULT Breakpoints::SetLineBreakpoints(ICorDebugProcess *pProcess, const std::string& filename,
                                        const std::vector<LineBreakpoint> &lineBreakpoints, std::vector<Breakpoint> &breakpoints)
{
    return m_uniqueLineBreakpoints->SetLineBreakpoints(pProcess, filename, lineBreakpoints, breakpoints, [&]() -> uint32_t
    {
        std::lock_guard<std::mutex> lock(m_nextBreakpointIdMutex);
        return m_nextBreakpointId++;
    });
}

HRESULT Breakpoints::ManagedCallbackBreakpoint(IDebugger *debugger, ICorDebugThread *pThread, ICorDebugBreakpoint *pBreakpoint, Breakpoint &breakpoint, bool &atEntry)
{
    HRESULT Status;
    atEntry = false;
    if (SUCCEEDED(Status = m_uniqueEntryBreakpoint->ManagedCallbackBreakpoint(pThread, pBreakpoint)) &&
        Status == S_OK) // S_FALSE - no error, but not affect on callback
    {
        atEntry = true;
        return S_OK;
    }

    if (SUCCEEDED(Status = m_uniqueLineBreakpoints->ManagedCallbackBreakpoint(debugger, pThread, pBreakpoint, breakpoint)) &&
        Status == S_OK) // S_FALSE - no error, but not affect on callback
    {
        return S_OK;
    }

    return m_uniqueFuncBreakpoints->ManagedCallbackBreakpoint(debugger, pThread, pBreakpoint, breakpoint);
}

HRESULT Breakpoints::ManagedCallbackLoadModule(ICorDebugModule *pModule, std::vector<BreakpointEvent> &events)
{
    m_uniqueEntryBreakpoint->ManagedCallbackLoadModule(pModule);
    m_uniqueFuncBreakpoints->ManagedCallbackLoadModule(pModule, events);
    m_uniqueLineBreakpoints->ManagedCallbackLoadModule(pModule, events);
    return S_OK;
}

HRESULT Breakpoints::ManagedCallbackException(ICorDebugThread *pThread, CorDebugExceptionCallbackType dwEventType, StoppedEvent &event, std::string &textOutput)
{
    return m_uniqueExceptionBreakpoints->ManagedCallbackException(pThread, dwEventType, event, textOutput);
}

HRESULT Breakpoints::AllBreakpointsActivate(bool act)
{
    HRESULT Status1 = m_uniqueLineBreakpoints->AllBreakpointsActivate(act);
    HRESULT Status2 = m_uniqueFuncBreakpoints->AllBreakpointsActivate(act);
    return FAILED(Status1) ? Status1 : Status2;
}

HRESULT Breakpoints::BreakpointActivate(uint32_t id, bool act)
{
    if (SUCCEEDED(m_uniqueLineBreakpoints->BreakpointActivate(id, act)))
        return S_OK;

    return m_uniqueFuncBreakpoints->BreakpointActivate(id, act);
}

// This function allows to enumerate breakpoints (sorted by number).
// Callback which is called for each breakpoint might return `false` to stop iteration over breakpoints list.
void Breakpoints::EnumerateBreakpoints(std::function<bool (const IDebugger::BreakpointInfo&)>&& callback)
{
    std::vector<IDebugger::BreakpointInfo> list;
    m_uniqueLineBreakpoints->AddAllBreakpointsInfo(list);
    m_uniqueFuncBreakpoints->AddAllBreakpointsInfo(list);

    // sort breakpoint list by ascending order, preserve order of elements with same number
    std::stable_sort(list.begin(), list.end());

    for (const auto &item : list)
    {
        if (!callback(item))
            break;
    }

}

} // namespace netcoredbg
