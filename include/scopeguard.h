#ifndef PKTMINERG_SCOPEGUARD_H
#define PKTMINERG_SCOPEGUARD_H

#include <functional>

template <typename F, typename... Args>
class ScopeGuard {
public:
    static ScopeGuard<F, Args...> MakeGuard(F fun, Args... args) {
        return ScopeGuard<F, Args...>(fun, args...);
    }
    ScopeGuard& operator=(const ScopeGuard& other) {
        dismissed_ = other.dismissed_;
        other.Dismiss();
    }
    ScopeGuard(const ScopeGuard& other) throw() :
        dismissed_(other.dismissed_) {
        other.Dismiss();
    }
    ~ScopeGuard() throw() {
        SafeExecute();
    }
    void SafeExecute() throw() {
        if (!dismissed_) {
            try {
                Execute();
            } catch(...) {
            }
        }
    }
    void Dismiss() const throw() {
        dismissed_ = true;
    }
protected:
    ScopeGuard(F fun, Args... args) :
        dismissed_(false) {
        fun_ = std::bind(fun, args...);
    }
    void Execute() {
        fun_();
    }
    mutable bool dismissed_;
    std::function<void()> fun_;
};

template <typename F, typename... Args>
inline ScopeGuard<F, Args...> MakeGuard(F fun, Args... args) {
    return ScopeGuard<F, Args...>::MakeGuard(fun, args...);
};

#endif //PKTMINERG_SCOPEGUARD_H
