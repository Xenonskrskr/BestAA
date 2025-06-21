return dist(rng_) ^ GetTickCount();
    }
};

// Advanced thread hiding and execution
namespace ThreadStealth {
    
    class HiddenThreadManager {
    private:
        APCInjection::StealthAPCInjector apc_injector_;
        std::vector<HANDLE> hidden_threads_;
        std::mutex threads_mutex_;
        
        pNtSetInformationThread NtSetInformationThread_;
        
        enum class ThreadInformationClass {
            ThreadHideFromDebugger = 17
        };
        
    public:
        HiddenThreadManager() {
            auto& resolver = StealthAPI::getSyscallResolver();
            resolver.initialize();
            NtSetInformationThread_ = resolver.getDirectSyscall<pNtSetInformationThread>("NtSetInformationThread");
        }
        
        ~HiddenThreadManager() {
            cleanupThreads();
        }
        
        bool createStealthThread(LPTHREAD_START_ROUTINE start_routine, LPVOID parameter) {
            HANDLE thread_handle;
            
            // Create hidden thread via APC injection
            if (apc_injector_.createHiddenThread(start_routine, parameter, &thread_handle)) {
                
                // Hide from debugger
                if (NtSetInformationThread_) {
                    NtSetInformationThread_(thread_handle, 
                        static_cast<THREADINFOCLASS>(ThreadInformationClass::ThreadHideFromDebugger),
                        nullptr, 0);
                }
                
                // Set random thread priority to blend in
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> priority_dist(THREAD_PRIORITY_BELOW_NORMAL, THREAD_PRIORITY_ABOVE_NORMAL);
                SetThreadPriority(thread_handle, priority_dist(gen));
                
                {
                    std::lock_guard<std::mutex> lock(threads_mutex_);
                    hidden_threads_.push_back(thread_handle);
                }
                
                // Resume thread
                ResumeThread(thread_handle);
                
                return true;
            }
            
            return false;
        }
        
        bool injectAPCToAlertableThread(PVOID apc_routine, PVOID parameter) {
            // Find our own alertable thread or create one
            DWORD current_process_id = GetCurrentProcessId();
            return apc_injector_.injectAPCToProcess(current_process_id, apc_routine, parameter);
        }
        
        void cleanupThreads() {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            
            for (HANDLE thread_handle : hidden_threads_) {
                if (thread_handle && thread_handle != INVALID_HANDLE_VALUE) {
                    TerminateThread(thread_handle, 0);
                    CloseHandle(thread_handle);
                }
            }
            
            hidden_threads_.clear();
        }
        
        size_t getActiveThreadCount() const {
            std::lock_guard<std::mutex> lock(threads_mutex_);
            return hidden_threads_.size();
        }
    };
}

// Enhanced process hollowing detection and evasion
namespace ProcessStealth {
    
    class ProcessHollowingDetector {
    private:
        pNtQueryInformationProcess NtQueryInformationProcess_;
        PROCESS_BASIC_INFORMATION original_pbi_;
        bool baseline_established_ = false;
        
    public:
        ProcessHollowingDetector() {
            auto& resolver = StealthAPI::getSyscallResolver();
            resolver.initialize();
            NtQueryInformationProcess_ = resolver.getDirectSyscall<pNtQueryInformationProcess>("NtQueryInformationProcess");
            
            establishBaseline();
        }
        
        bool detectHollowing() {
            if (!NtQueryInformationProcess_ || !baseline_established_) return false;
            
            try {
                PROCESS_BASIC_INFORMATION current_pbi;
                ULONG return_length;
                
                NTSTATUS status = NtQueryInformationProcess_(
                    GetCurrentProcess(),
                    ProcessBasicInformation,
                    &current_pbi,
                    sizeof(current_pbi),
                    &return_length
                );
                
                if (!NT_SUCCESS(status)) return false;
                
                // Compare with baseline
                if (current_pbi.PebBaseAddress != original_pbi_.PebBaseAddress ||
                    current_pbi.UniqueProcessId != original_pbi_.UniqueProcessId) {
                    return true; // Potential hollowing detected
                }
                
                // Additional checks for image base modifications
                DWORD image_base;
                SIZE_T bytes_read;
                
                if (ReadProcessMemory(GetCurrentProcess(),
                    static_cast<BYTE*>(current_pbi.PebBaseAddress) + 8, // ImageBaseAddress offset
                    &image_base, sizeof(image_base), &bytes_read)) {
                    
                    HMODULE current_base = GetModuleHandle(nullptr);
                    if (image_base != reinterpret_cast<DWORD>(current_base)) {
                        return true; // Image base mismatch
                    }
                }
                
                return false;
                
            } catch (...) {
                return true; // Assume detection if exception occurs
            }
        }
        
        bool implementAntiHollowing() {
            // Implement various anti-hollowing techniques
            
            // 1. Code integrity checks
            if (!verifyCodeIntegrity()) return false;
            
            // 2. PEB protection
            if (!protectPEB()) return false;
            
            // 3. Module verification
            if (!verifyLoadedModules()) return false;
            
            return true;
        }
        
    private:
        void establishBaseline() {
            if (!NtQueryInformationProcess_) return;
            
            try {
                ULONG return_length;
                NTSTATUS status = NtQueryInformationProcess_(
                    GetCurrentProcess(),
                    ProcessBasicInformation,
                    &original_pbi_,
                    sizeof(original_pbi_),
                    &return_length
                );
                
                baseline_established_ = NT_SUCCESS(status);
                
            } catch (...) {
                baseline_established_ = false;
            }
        }
        
        bool verifyCodeIntegrity() {
            // Simple checksum verification of critical code sections
            HMODULE module_base = GetModuleHandle(nullptr);
            if (!module_base) return false;
            
            PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;
            
            PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(module_base) + dos_header->e_lfanew);
            
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;
            
            // Calculate checksum of .text section
            PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
            for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i) {
                if (strncmp(reinterpret_cast<const char*>(section_header[i].Name), ".text", 5) == 0) {
                    BYTE* section_start = reinterpret_cast<BYTE*>(module_base) + section_header[i].VirtualAddress;
                    DWORD section_size = section_header[i].Misc.VirtualSize;
                    
                    // Simple XOR checksum
                    DWORD checksum = 0;
                    for (DWORD j = 0; j < section_size; ++j) {
                        checksum ^= section_start[j];
                    }
                    
                    // Store/compare checksum (implementation specific)
                    // For demo purposes, we'll just verify it's not zero
                    return checksum != 0;
                }
            }
            
            return false;
        }
        
        bool protectPEB() {
            PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
            if (!peb) return false;
            
            // Set PAGE_GUARD on PEB to detect access
            DWORD old_protect;
            return VirtualProtect(peb, sizeof(PEB), PAGE_READONLY | PAGE_GUARD, &old_protect) != FALSE;
        }
        
        bool verifyLoadedModules() {
            PPEB peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
            if (!peb || !peb->Ldr) return false;
            
            PPEB_LDR_DATA ldr = peb->Ldr;
            PLIST_ENTRY current = ldr->InLoadOrderModuleList.Flink;
            
            int module_count = 0;
            while (current != &ldr->InLoadOrderModuleList && module_count < 100) {
                PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
                    current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                
                // Verify module integrity
                if (entry->DllBase) {
                    PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(entry->DllBase);
                    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                        return false; // Corrupted module detected
                    }
                }
                
                current = current->Flink;
                module_count++;
            }
            
            return module_count > 0;
        }
    };
}

// Enhanced stealth main application with all advanced techniques
class UltimateStealthAimSystem {
private:
    // Stealth components
    std::unique_ptr<PEBStealth::PEBManipulator> peb_manipulator_;
    std::unique_ptr<ThreadStealth::HiddenThreadManager> thread_manager_;
    std::unique_ptr<ProcessStealth::ProcessHollowingDetector> hollowing_detector_;
    std::unique_ptr<StealthMouseInput> mouse_input_;
    
    // Core functionality
    std::unique_ptr<EnhancedDetectionEngine> detection_engine_;
    std::unique_ptr<SmartMovementController> movement_controller_;
    std::unique_ptr<PerformanceOptimizer> performance_optimizer_;
    std::unique_ptr<EnhancedConfigManager> config_manager_;
    
    // Threading and synchronization
    std::atomic<bool> running_{true};
    std::atomic<bool> stealth_active_{true};
    std::mutex frame_mutex_;
    std::mutex targets_mutex_;
    std::condition_variable frame_cv_;
    
    // Current state
    cv::Mat current_frame_;
    std::vector<EnhancedTargetInfo> current_targets_;
    EnhancedTargetInfo selected_target_;
    bool has_selected_target_ = false;
    
    // Security monitoring
    std::atomic<bool> security_breach_detected_{false};
    std::chrono::steady_clock::time_point last_security_check_;
    
    // Input state
    std::atomic<bool> aim_active_{false};
    std::atomic<bool> left_mouse_pressed_{false};
    
public:
    UltimateStealthAimSystem() {
        initializeStealthComponents();
        initializeCoreComponents();
        
        // Start stealth operations immediately
        if (!initializeStealth()) {
            throw std::runtime_error("Failed to initialize stealth systems");
        }
        
        startStealthThreads();
    }
    
    ~UltimateStealthAimSystem() {
        shutdown();
    }
    
    bool initialize(const std::string& model_path) {
        try {
            // Verify stealth status before proceeding
            if (!performSecurityCheck()) {
                return false;
            }
            
            auto config = config_manager_->getConfig();
            
            // Initialize detection engine with stealth considerations
            if (!detection_engine_->initialize(model_path, config.detection.use_gpu)) {
                return false;
            }
            
            // Configure all components
            updateConfiguration(config);
            
            return true;
            
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    void setAimActive(bool active) {
        if (security_breach_detected_) {
            active = false; // Disable functionality if security breach detected
        }
        
        aim_active_ = active;
    }
    
    void setLeftMousePressed(bool pressed) {
        left_mouse_pressed_ = pressed;
    }
    
    bool getStealthStatus() const {
        return stealth_active_ && !security_breach_detected_;
    }
    
    EnhancedConfigManager::ApplicationConfig getCurrentConfig() const {
        return config_manager_->getConfig();
    }
    
private:
    void initializeStealthComponents() {
        peb_manipulator_ = std::make_unique<PEBStealth::PEBManipulator>();
        thread_manager_ = std::make_unique<ThreadStealth::HiddenThreadManager>();
        hollowing_detector_ = std::make_unique<ProcessStealth::ProcessHollowingDetector>();
        mouse_input_ = std::make_unique<StealthMouseInput>();
    }
    
    void initializeCoreComponents() {
        detection_engine_ = std::make_unique<EnhancedDetectionEngine>();
        movement_controller_ = std::make_unique<SmartMovementController>();
        performance_optimizer_ = std::make_unique<PerformanceOptimizer>();
        config_manager_ = std::make_unique<EnhancedConfigManager>();
    }
    
    bool initializeStealth() {
        try {
            // Initialize direct syscall resolver
            if (!StealthAPI::getSyscallResolver().initialize()) {
                return false;
            }
            
            // Apply PEB manipulations
            if (!peb_manipulator_->hideFromDebugger()) {
                return false;
            }
            
            if (!peb_manipulator_->spoofSystemInfo()) {
                return false;
            }
            
            // Spoof process name to appear legitimate
            if (!peb_manipulator_->spoofProcessName(L"C:\\Windows\\System32\\svchost.exe")) {
                return false;
            }
            
            // Hide our module from PEB
            if (!peb_manipulator_->hideModule("aim_system")) {
                // Non-critical, continue anyway
            }
            
            // Implement anti-hollowing protection
            if (!hollowing_detector_->implementAntiHollowing()) {
                return false;
            }
            
            last_security_check_ = std::chrono::steady_clock::now();
            
            return true;
            
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    void startStealthThreads() {
        // Create detection thread using stealth thread manager
        thread_manager_->createStealthThread([](LPVOID param) -> DWORD {
            auto* self = static_cast<UltimateStealthAimSystem*>(param);
            self->stealthDetectionLoop();
            return 0;
        }, this);
        
        // Create movement thread using stealth thread manager
        thread_manager_->createStealthThread([](LPVOID param) -> DWORD {
            auto* self = static_cast<UltimateStealthAimSystem*>(param);
            self->stealthMovementLoop();
            return 0;
        }, this);
        
        // Create security monitoring thread using stealth thread manager
        thread_manager_->createStealthThread([](LPVOID param) -> DWORD {
            auto* self = static_cast<UltimateStealthAimSystem*>(param);
            self->stealthSecurityLoop();
            return 0;
        }, this);
        
        // Create performance monitoring thread using stealth thread manager
        thread_manager_->createStealthThread([](LPVOID param) -> DWORD {
            auto* self = static_cast<UltimateStealthAimSystem*>(param);
            self->stealthPerformanceLoop();
            return 0;
        }, this);
    }
    
    void stealthDetectionLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);
        
        while (running_ && stealth_active_) {
            try {
                // Perform security check before processing
                if (!performQuickSecurityCheck()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                
                auto config = config_manager_->getConfig();
                
                if (!config.detection.enabled || security_breach_detected_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                
                // Capture screen with stealth considerations
                cv::Mat frame = captureScreenStealth();
                if (frame.empty()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(16));
                    continue;
                }
                
                auto detection_start = std::chrono::high_resolution_clock::now();
                
                // Detect targets
                std::vector<EnhancedTargetInfo> targets = detection_engine_->detectTargets(frame);
                
                auto detection_end = std::chrono::high_resolution_clock::now();
                auto detection_time = std::chrono::duration<double, std::milli>(
                    detection_end - detection_start).count();
                
                performance_optimizer_->recordDetectionTime(detection_time);
                
                // Update targets with stealth considerations
                {
                    std::lock_guard<std::mutex> lock(targets_mutex_);
                    current_targets_ = std::move(targets);
                    selectBestTargetStealth();
                }
                
                // Update frame
                {
                    std::lock_guard<std::mutex> lock(frame_mutex_);
                    current_frame_ = std::move(frame);
                }
                frame_cv_.notify_one();
                
                // Variable sleep to avoid detection
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> sleep_dist(12, 20);
                std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dist(gen)));
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    
    void stealthMovementLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        
        auto last_update = std::chrono::high_resolution_clock::now();
        
        while (running_ && stealth_active_) {
            try {
                if (security_breach_detected_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                
                auto config = config_manager_->getConfig();
                
                if (!config.aim.enabled || !aim_active_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                
                auto now = std::chrono::high_resolution_clock::now();
                double dt = std::chrono::duration<double>(now - last_update).count();
                last_update = now;
                
                // Get current mouse position
                POINT cursor_pos;
                GetCursorPos(&cursor_pos);
                MathUtils::Vector2D current_mouse(cursor_pos.x, cursor_pos.y);
                
                // Check for valid target
                EnhancedTargetInfo target;
                bool has_target = false;
                
                {
                    std::lock_guard<std::mutex> lock(targets_mutex_);
                    if (has_selected_target_) {
                        target = selected_target_;
                        has_target = true;
                    }
                }
                
                if (has_target) {
                    // Calculate aim point with stealth considerations
                    MathUtils::Vector2D aim_point = calculateStealthAimPoint(target, config);
                    
                    // Check FOV and apply stealth movement
                    double distance_to_target = (aim_point - current_mouse).magnitude();
                    
                    if (distance_to_target <= config.aim.fov_radius) {
                        movement_controller_->setTarget(aim_point);
                        
                        MathUtils::Vector2D movement = movement_controller_->getNextMovement(dt);
                        
                        if (movement.magnitude() > 0.01) {
                            // Use stealth mouse input
                            int dx = static_cast<int>(std::round(movement.x));
                            int dy = static_cast<int>(std::round(movement.y));
                            
                            mouse_input_->sendMouseMovement(dx, dy, true);
                        }
                    }
                }
                
                // High frequency with randomization
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> freq_dist(400, 600); // 400-600 microseconds
                std::this_thread::sleep_for(std::chrono::microseconds(freq_dist(gen)));
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }
    
    void stealthSecurityLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
        
        while (running_) {
            try {
                // Comprehensive security check
                if (!performComprehensiveSecurityCheck()) {
                    handleSecurityBreach();
                }
                
                // Random sleep interval for unpredictability
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> sleep_dist(15000, 45000); // 15-45 seconds
                std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dist(gen)));
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::milliseconds(30000));
            }
        }
    }
    
    void stealthPerformanceLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
        
        while (running_ && stealth_active_) {
            try {
                // Monitor performance with stealth considerations
                auto recommendations = performance_optimizer_->getRecommendations();
                
                // Apply optimizations more conservatively in stealth mode
                if (recommendations.performance_score < 0.6) {
                    auto config = config_manager_->getConfig();
                    
                    // Reduce quality more aggressively to maintain stealth
                    if (recommendations.should_reduce_detection_size) {
                        config.detection.detection_size = cv::Size(
                            std::max(320, recommendations.recommended_detection_size.width),
                            std::max(320, recommendations.recommended_detection_size.height)
                        );
                    }
                    
                    updateConfiguration(config);
                    performance_optimizer_->applyOptimizations(recommendations);
                }
                
                // Update CPU usage with stealth process name
                performance_optimizer_->recordCPUUsage(getCurrentCPUUsage());
                
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
    
    bool performQuickSecurityCheck() {
        // Quick checks performed frequently
        return !IsDebuggerPresent() && 
               !hollowing_detector_->detectHollowing() &&
               !security_breach_detected_;
    }
    
    bool performComprehensiveSecurityCheck() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_security_check_).count();
        
        // Only perform comprehensive check periodically
        if (elapsed < 30) {
            return !security_breach_detected_;
        }
        
        last_security_check_ = now;
        
        try {
            // 1. Debugger detection
            if (IsDebuggerPresent()) return false;
            
            // 2. Remote debugger detection
            BOOL remote_debugger = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger);
            if (remote_debugger) return false;
            
            // 3. Process hollowing detection
            if (hollowing_detector_->detectHollowing()) return false;
            
            // 4. Check for analysis tools
            if (detectAnalysisTools()) return false;
            
            // 5. VM detection
            if (detectVirtualMachine()) return false;
            
            // 6. Timing attack detection
            if (detectTimingAttacks()) return false;
            
            return true;
            
        } catch (...) {
            return false;
        }
    }
    
    void handleSecurityBreach() {
        security_breach_detected_ = true;
        stealth_active_ = false;
        
        // Implement security response
        // 1. Disable all functionality
        aim_active_ = false;
        
        // 2. Clear sensitive data
        clearSensitiveData();
        
        // 3. Implement decoy behavior
        implementDecoyBehavior();
    }
    
    cv::Mat captureScreenStealth() {
        // Implement screen capture with additional stealth measures
        
        // Check if capture is safe
        if (!isCaptureSecure()) {
            return cv::Mat();
        }
        
        // Use standard GDI capture but with timing randomization
        HDC screen_dc = GetDC(nullptr);
        if (!screen_dc) return cv::Mat();
        
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        
        HDC mem_dc = CreateCompatibleDC(screen_dc);
        HBITMAP bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        HGDIOBJ old_bitmap = SelectObject(mem_dc, bitmap);
        
        // Add random delay to avoid pattern detection
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delay_dist(0, 2);
        if (delay_dist(gen) > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(delay_dist(gen) * 100));
        }
        
        BitBlt(mem_dc, 0, 0, width, height, screen_dc, 0, 0, SRCCOPY);
        
        BITMAPINFOHEADER bi = {};
        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = width;
        bi.biHeight = -height;
        bi.biPlanes = 1;
        bi.biBitCount = 24;
        bi.biCompression = BI_RGB;
        
        cv::Mat result(height, width, CV_8UC3);
        GetDIBits(mem_dc, bitmap, 0, height, result.data,
                 reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
        
        cv::cvtColor(result, result, cv::COLOR_BGR2RGB);
        
        // Cleanup
        SelectObject(mem_dc, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        
        return result;
    }
    
    void selectBestTargetStealth() {
        if (current_targets_.empty()) {
            has_selected_target_ = false;
            return;
        }
        
        // Apply additional stealth considerations to target selection
        auto config = config_manager_->getConfig();
        
        POINT cursor_pos;
        GetCursorPos(&cursor_pos);
        MathUtils::Vector2D mouse_pos(cursor_pos.x, cursor_pos.y);
        
        EnhancedTargetInfo best_target;
        double best_score = -1.0;
        
        for (const auto& target : current_targets_) {
            double score = calculateStealthTargetScore(target, mouse_pos, config);
            
            if (score > best_score) {
                best_score = score;
                best_target = target;
            }
        }
        
        // Additional stealth validation
        if (best_score > 0.5 && isTargetSecure(best_target)) { // Higher threshold in stealth mode
            selected_target_ = best_target;
            has_selected_target_ = true;
        } else {
            has_selected_target_ = false;
        }
    }
    
    double calculateStealthTargetScore(const EnhancedTargetInfo& target,
                                     const MathUtils::Vector2D& mouse_pos,
                                     const EnhancedConfigManager::ApplicationConfig& config) {
        
        // Base score calculation
        double distance = (MathUtils::Vector2D(target.position.x, target.position.y) - mouse_pos).magnitude();
        double distance_score = 1.0 / (1.0 + distance / 100.0);
        double confidence_score = target.confidence;
        double stability_score = target.stability_score;
        
        // Additional stealth factors
        double stealth_score = 1.0;
        
        // Prefer targets that require less movement (more subtle)
        if (distance > 150.0) {
            stealth_score *= 0.7; // Penalize distant targets
        }
        
        // Prefer targets with higher confidence (less likely to be false positives)
        if (confidence_score < 0.8) {
            stealth_score *= 0.8;
        }
        
        // Prefer stable targets (less erratic movement)
        stealth_score *= (0.5 + 0.5 * stability_score);
        
        return (distance_score * 0.4 + confidence_score * 0.4 + stability_score * 0.2) * stealth_score;
    }
    
    MathUtils::Vector2D calculateStealthAimPoint(const EnhancedTargetInfo& target,
                                                const EnhancedConfigManager::ApplicationConfig& config) {
        
        MathUtils::Vector2D aim_point(target.position.x, target.position.y);
        
        // Reduced prediction in stealth mode for more natural movement
        if (config.aim.prediction_strength > 0.0) {
            double stealth_prediction = config.aim.prediction_strength * 0.7; // Reduce by 30%
            
            MathUtils::Vector2D predicted_offset(
                target.velocity.x * stealth_prediction,
                target.velocity.y * stealth_prediction
            );
            
            aim_point = aim_point + predicted_offset;
        }
        
        // Body part targeting with stealth considerations
        if (target.chest_region.width > 0 && target.chest_region.height > 0) {
            // Prefer chest over head in stealth mode (larger target, less suspicious)
            aim_point = MathUtils::Vector2D(
                target.chest_region.x + target.chest_region.width / 2,
                target.chest_region.y + target.chest_region.height / 2
            );
        } else if (target.head_region.width > 0 && target.head_region.height > 0) {
            aim_point = MathUtils::Vector2D(
                target.head_region.x + target.head_region.width / 2,
                target.head_region.y + target.head_region.height / 2
            );
        }
        
        // Add slight randomization for more human-like targeting
        std::random_device rd;
        std::mt19937 gen(rd());
        std::normal_distribution<double> offset_dist(0.0, 1.5);
        
        aim_point.x += offset_dist(gen);
        aim_point.y += offset_dist(gen);
        
        return aim_point;
    }
    
    bool isCaptureSecure() const {
        // Check if screen capture is safe from detection
        
        // 1. Check for screen recording software
        HWND obs_window = FindWindowA("Qt5QWindowIcon", nullptr); // OBS Studio
        if (obs_window) return false;
        
        HWND bandicam_window = FindWindowA("BandicamClass", nullptr); // Bandicam
        if (bandicam_window) return false;
        
        // 2. Check for remote desktop connections
        if (GetSystemMetrics(SM_REMOTESESSION)) return false;
        
        // 3. Check for suspicious processes
        if (detectScreenCaptureProcesses()) return false;
        
        return true;
    }
    
    bool isTargetSecure(const EnhancedTargetInfo& target) const {
        // Additional validation for stealth targeting
        
        // Check if target is in a suspicious location (e.g., always in same spot)
        static std::unordered_map<int, std::vector<cv::Point2f>> target_history;
        
        if (target.tracking_id >= 0) {
            auto& history = target_history[target.tracking_id];
            history.push_back(target.position);
            
            if (history.size() > 10) {
                history.erase(history.begin());
                
                // Calculate position variance
                cv::Point2f mean(0, 0);
                for (const auto& pos : history) {
                    mean.x += pos.x;
                    mean.y += pos.y;
                }
                mean.x /= history.size();
                mean.y /= history.size();
                
                double variance = 0.0;
                for (const auto& pos : history) {
                    double dx = pos.x - mean.x;
                    double dy = pos.y - mean.y;
                    variance += dx * dx + dy * dy;
                }
                variance /= history.size();
                
                // If target is too static, it might be a test/honeypot
                if (variance < 5.0) return false;
            }
        }
        
        return true;
    }
    
    bool detectAnalysisTools() const {
        // Detect common analysis and debugging tools
        std::vector<std::string> suspicious_processes = {
            "ollydbg.exe", "x64dbg.exe", "ida.exe", "ida64.exe",
            "cheatengine.exe", "processhacker.exe", "procmon.exe",
            "wireshark.exe", "fiddler.exe", "burpsuite.exe",
            "apispylite.exe", "detours.dll", "easyhook.dll"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        bool found_suspicious = false;
        
        if (Process32First(snapshot, &pe32)) {
            do {
                std::string process_name = pe32.szExeFile;
                std::transform(process_name.begin(), process_name.end(),
                              process_name.begin(), ::tolower);
                
                for (const auto& suspicious : suspicious_processes) {
                    if (process_name.find(suspicious) != std::string::npos) {
                        found_suspicious = true;
                        break;
                    }
                }
                
                if (found_suspicious) break;
                
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        return found_suspicious;
    }
    
    bool detectVirtualMachine() const {
        // Enhanced VM detection
        
        // 1. CPUID hypervisor check
        int cpu_info[4];
        __cpuid(cpu_info, 1);
        if (cpu_info[2] & (1 << 31)) return true;
        
        // 2. Check for VM-specific registry keys
        std::vector<std::string> vm_registry_keys = {
            "HARDWARE\\DESCRIPTION\\System\\SystemBiosVersion",
            "HARDWARE\\DESCRIPTION\\System\\VideoBiosVersion",
            "SOFTWARE\\Oracle\\VirtualBox Guest Additions",
            "SYSTEM\\ControlSet001\\Services\\VBoxSF",
            "SYSTEM\\ControlSet001\\Services\\vmhgfs",
            "SOFTWARE\\VMware, Inc.\\VMware Tools"
        };
        
        for (const auto& key_path : vm_registry_keys) {
            HKEY key;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key_path.c_str(), 0, KEY_READ, &key) == ERROR_SUCCESS) {
                RegCloseKey(key);
                return true;
            }
        }
        
        // 3. Check for VM processes
        std::vector<std::string> vm_processes = {
            "vmware.exe", "vmtoolsd.exe", "vboxservice.exe",
            "vboxtray.exe", "qemu.exe", "virtualbox.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            
            if (Process32First(snapshot, &pe32)) {
                do {
                    std::string process_name = pe32.szExeFile;
                    std::transform(process_name.begin(), process_name.end(),
                                  process_name.begin(), ::tolower);
                    
                    for (const auto& vm_proc : vm_processes) {
                        if (process_name.find(vm_proc) != std::string::npos) {
                            CloseHandle(snapshot);
                            return true;
                        }
                    }
                } while (Process32Next(snapshot, &pe32));
            }
            CloseHandle(snapshot);
        }
        
        // 4. Hardware checks
        MEMORYSTATUSEX mem_status = {};
        mem_status.dwLength = sizeof(mem_status);
        if (GlobalMemoryStatusEx(&mem_status)) {
            // VMs often have limited RAM
            if (mem_status.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) { // Less than 2GB
                return true;
            }
        }
        
        // 5. Check disk space (VMs often have small disks)
        ULARGE_INTEGER free_bytes, total_bytes;
        if (GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, nullptr)) {
            if (total_bytes.QuadPart < 50ULL * 1024 * 1024 * 1024) { // Less than 50GB
                return true;
            }
        }
        
        return false;
    }
    
    bool detectTimingAttacks() const {
        // Detect if code execution is being monitored through timing analysis
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Perform some operations that should take consistent time
        volatile int sum = 0;
        for (int i = 0; i < 10000; ++i) {
            sum += i * 2;
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // If operations take significantly longer than expected, might be under analysis
        return duration.count() > 50000; // 50ms threshold
    }
    
    bool detectScreenCaptureProcesses() const {
        std::vector<std::string> capture_processes = {
            "obs64.exe", "obs32.exe", "obs.exe",
            "bandicam.exe", "fraps.exe", "camtasia.exe",
            "screencast.exe", "snagit32.exe", "lightshot.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        bool found_capture = false;
        
        if (Process32First(snapshot, &pe32)) {
            do {
                std::string process_name = pe32.szExeFile;
                std::transform(process_name.begin(), process_name.end(),
                              process_name.begin(), ::tolower);
                
                for (const auto& capture_proc : capture_processes) {
                    if (process_name.find(capture_proc) != std::string::npos) {
                        found_capture = true;
                        break;
                    }
                }
                
                if (found_capture) break;
                
            } while (Process32Next(snapshot, &pe32));
        }
        
        CloseHandle(snapshot);
        return found_capture;
    }
    
    void clearSensitiveData() {
        // Securely clear sensitive data structures
        
        // Clear targets
        {
            std::lock_guard<std::mutex> lock(targets_mutex_);
            current_targets_.clear();
            has_selected_target_ = false;
            selected_target_ = EnhancedTargetInfo();
        }
        
        // Clear frame data
        {
            std::lock_guard<std::mutex> lock(frame_mutex_);
            current_frame_ = cv::Mat();
        }
        
        // Clear configuration (set to safe defaults)
        auto safe_config = EnhancedConfigManager::ApplicationConfig();
        safe_config.aim.enabled = false;
        safe_config.detection.enabled = false;
        config_manager_->updateConfig(safe_config);
    }
    
    void implementDecoyBehavior() {
        // Implement behavior to appear as legitimate software
        
        // Create fake network activity to mimic legitimate software
        thread_manager_->createStealthThread([](LPVOID) -> DWORD {
            try {
                // Fake HTTP requests to legitimate domains
                std::vector<std::string> legitimate_domains = {
                    "microsoft.com", "google.com", "cloudflare.com", "github.com"
                };
                
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> domain_dist(0, legitimate_domains.size() - 1);
                std::uniform_int_distribution<> delay_dist(30000, 120000); // 30-120 seconds
                
                while (true) {
                    // Sleep for random interval
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(gen)));
                    
                    // Make fake request (simplified - would need actual HTTP implementation)
                    std::string domain = legitimate_domains[domain_dist(gen)];
                    
                    // This would implement actual HTTP requests in a real scenario
                    // For demo purposes, we'll just simulate the delay
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            } catch (...) {
                // Silently exit on any error
            }
            return 0;
        }, nullptr);
        
        // Create fake file system activity
        thread_manager_->createStealthThread([](LPVOID) -> DWORD {
            try {
                char temp_path[MAX_PATH];
                GetTempPathA(sizeof(temp_path), temp_path);
                
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> delay_dist(60000, 300000); // 1-5 minutes
                
                while (true) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(delay_dist(gen)));
                    
                    // Create and delete temporary files to mimic normal activity
                    std::string temp_file = std::string(temp_path) + "\\tmp_" + 
                                          std::to_string(GetTickCount()) + ".tmp";
                    
                    HANDLE file = CreateFileA(temp_file.c_str(), GENERIC_WRITE, 0, nullptr,
                                            CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, nullptr);
                    
                    if (file != INVALID_HANDLE_VALUE) {
                        // Write some dummy data
                        DWORD bytes_written;
                        const char* dummy_data = "Temporary application data";
                        WriteFile(file, dummy_data, strlen(dummy_data), &bytes_written, nullptr);
                        CloseHandle(file);
                        
                        // Delete after short delay
                        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                        DeleteFileA(temp_file.c_str());
                    }
                }
            } catch (...) {
                // Silently exit on any error
            }
            return 0;
        }, nullptr);
    }
    
    double getCurrentCPUUsage() {
        static ULARGE_INTEGER last_cpu, last_sys_cpu, last_user_cpu;
        static DWORD num_processors = 0;
        static bool first_call = true;
        
        if (first_call) {
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            num_processors = sys_info.dwNumberOfProcessors;
            
            FILETIME ftime, fsys, fuser;
            GetSystemTimeAsFileTime(&ftime);
            memcpy(&last_cpu, &ftime, sizeof(FILETIME));
            
            GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
            memcpy(&last_sys_cpu, &fsys, sizeof(FILETIME));
            memcpy(&last_user_cpu, &fuser, sizeof(FILETIME));
            
            first_call = false;
            return 0.0;
        }
        
        FILETIME ftime, fsys, fuser;
        ULARGE_INTEGER now, sys, user;
        
        GetSystemTimeAsFileTime(&ftime);
        memcpy(&now, &ftime, sizeof(FILETIME));
        
        GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
        memcpy(&sys, &fsys, sizeof(FILETIME));
        memcpy(&user, &fuser, sizeof(FILETIME));
        
        double percent = static_cast<double>(sys.QuadPart - last_sys_cpu.QuadPart) +
                        (user.QuadPart - last_user_cpu.QuadPart);
        percent /= (now.QuadPart - last_cpu.QuadPart);
        percent /= num_processors;
        
        last_cpu = now;
        last_user_cpu = user;
        last_sys_cpu = sys;
        
        return percent * 100.0;
    }
    
    void updateConfiguration(const EnhancedConfigManager::ApplicationConfig& config) {
        config_manager_->updateConfig(config);
        
        // Update detection engine
        if (detection_engine_) {
            detection_engine_->setConfidenceThreshold(config.detection.confidence_threshold);
            detection_engine_->setNMSThreshold(config.detection.nms_threshold);
        }
        
        // Update movement controller
        if (movement_controller_) {
            SmartMovementController::MovementParams movement_params;
            movement_params.base_smoothing = config.aim.smoothing_factor;
            movement_params.adaptive_smoothing = config.aim.adaptive_smoothing;
            movement_params.human_factor = config.aim.human_like_movement ? 0.4 : 0.0; // Increased for stealth
            
            // Always use human-like movement in stealth mode
            movement_params.style = SmartMovementController::MovementParams::Style::HUMAN_LIKE;
            
            movement_controller_->updateParams(movement_params);
        }
    }
    
    void shutdown() {
        running_ = false;
        stealth_active_ = false;
        frame_cv_.notify_all();
        
        // Clean up stealth components
        if (thread_manager_) {
            thread_manager_->cleanupThreads();
        }
        
        // Clear sensitive data one final time
        clearSensitiveData();
    }
};

// Enhanced main function with stealth initialization
int stealthMain(int argc, char* argv[]) {
    try {
        // Initialize stealth systems early
        if (!StealthAPI::getSyscallResolver().initialize()) {
            return 1; // Silent failure
        }
        
        // Create stealth application
        UltimateStealthAimSystem stealth_app;
        
        // Initialize with model
        std::string model_path = "models/detection_model.onnx";
        if (!stealth_app.initialize(model_path)) {
            return 1; // Silent failure
        }
        
        // Main stealth loop
        bool running = true;
        auto last_status_check = std::chrono::steady_clock::now();
        
        while (running) {
            // Check stealth status periodically
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_status_check).count() >= 5) {
                if (!stealth_app.getStealthStatus()) {
                    // Stealth compromised, exit gracefully
                    break;
                }
                last_status_check = now;
            }
            
            // Handle input with stealth considerations
            if (GetAsyncKeyState(VK_RBUTTON) & 0x8000) {
                stealth_app.setAimActive(true);
            } else {
                stealth_app.setAimActive(false);
            }
            
            if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                stealth_app.setLeftMousePressed(true);
            } else {
                stealth_app.setLeftMousePressed(false);
            }
            
            // Emergency exit
            if (GetAsyncKeyState(VK_END) & 0x8000) {
                running = false;
            }
            
            // Variable sleep for stealth
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> sleep_dist(8, 15);
            std::this_thread::sleep_for(std::chrono::milliseconds(sleep_dist(gen)));
        }
        
        return 0;
        
    } catch (...) {
        return 1; // Silent failure
    }
}

// Entry point with additional stealth measures
int main(int argc, char* argv[]) {
    // Immediate stealth checks
    if (IsDebuggerPresent()) {
        return 0;
    }
    
    // Check for VM/analysis environment
    int cpu_info[4];
    __cpuid(cpu_info, 1);
    if (cpu_info[2] & (1 << 31)) { // Hypervisor bit
        return 0;
    }
    
    // Hide console window if present
    HWND console_window = GetConsoleWindow();
    if (console_window) {
        ShowWindow(console_window, SW_HIDE);
    }
    
    // Set process priority to appear normal
    SetPriorityClass(GetCurrentProcess(), NORMAL_PRIORITY_CLASS);
    
    // Call stealth main
    return stealthMain(argc, argv);
}// Enhanced Aim System - Advanced Stealth Version
// Includes NtUserSendInput, APC injection, PEB/TEB manipulation, and advanced evasion

#pragma once
#include <windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <opencv2/opencv.hpp>
#include <opencv2/dnn.hpp>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <chrono>
#include <vector>
#include <unordered_map>
#include <random>
#include <algorithm>
#include <intrin.h>

// Additional NT API structures and definitions
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG TimeDateStamp;
    PVOID LoadedImports;
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PVOID FastPebLock;
    PVOID FastPebLockRoutine;
    PVOID FastPebUnlockRoutine;
    ULONG EnvironmentUpdateCount;
    PVOID KernelCallbackTable;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID* ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;
    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;
    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;
    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps;
    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;
    PVOID LoaderLock;
    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ImageProcessAffinityMask;
    ULONG GdiHandleBuffer[34];
    PVOID PostProcessInitRoutine;
    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];
    ULONG SessionId;
    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo;
    UNICODE_STRING CSDVersion;
    PVOID ActivationContextData;
    PVOID ProcessAssemblyStorageMap;
    PVOID SystemDefaultActivationContextData;
    PVOID SystemAssemblyStorageMap;
    SIZE_T MinimumStackCommit;
} PEB, *PPEB;

// Advanced NT API function pointers
typedef NTSTATUS(NTAPI* pNtUserSendInput)(
    UINT cInputs,
    LPINPUT pInputs,
    int cbSize
);

typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    ULONG_PTR ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Stealth API resolver with direct syscalls
namespace StealthAPI {
    
    class DirectSyscallResolver {
    private:
        std::unordered_map<std::string, DWORD> syscall_numbers_;
        bool initialized_ = false;
        
        struct SyscallStub {
            BYTE mov_eax[5] = {0xB8, 0x00, 0x00, 0x00, 0x00}; // mov eax, syscall_number
            BYTE mov_edx[5] = {0xBA, 0x00, 0x00, 0x00, 0x00}; // mov edx, 0 (or syscall addr)
            BYTE syscall[2] = {0x0F, 0x05};                    // syscall
            BYTE ret[1] = {0xC3};                              // ret
        };
        
        std::unordered_map<std::string, std::unique_ptr<SyscallStub>> syscall_stubs_;
        
    public:
        bool initialize() {
            if (initialized_) return true;
            
            try {
                // Get NTDLL base address
                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                if (!ntdll) return false;
                
                // Parse NTDLL exports to find syscall numbers
                if (!extractSyscallNumbers(ntdll)) return false;
                
                // Create direct syscall stubs
                createSyscallStubs();
                
                initialized_ = true;
                return true;
                
            } catch (...) {
                return false;
            }
        }
        
        template<typename T>
        T getDirectSyscall(const std::string& function_name) {
            if (!initialized_) return nullptr;
            
            auto stub_it = syscall_stubs_.find(function_name);
            if (stub_it != syscall_stubs_.end()) {
                return reinterpret_cast<T>(stub_it->second.get());
            }
            
            return nullptr;
        }
        
    private:
        bool extractSyscallNumbers(HMODULE ntdll_base) {
            PIMAGE_DOS_HEADER dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(ntdll_base);
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return false;
            
            PIMAGE_NT_HEADERS nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(
                reinterpret_cast<BYTE*>(ntdll_base) + dos_header->e_lfanew);
            
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return false;
            
            PIMAGE_EXPORT_DIRECTORY export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
                reinterpret_cast<BYTE*>(ntdll_base) + 
                nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
            
            DWORD* name_table = reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(ntdll_base) + export_dir->AddressOfNames);
            DWORD* address_table = reinterpret_cast<DWORD*>(
                reinterpret_cast<BYTE*>(ntdll_base) + export_dir->AddressOfFunctions);
            WORD* ordinal_table = reinterpret_cast<WORD*>(
                reinterpret_cast<BYTE*>(ntdll_base) + export_dir->AddressOfNameOrdinals);
            
            for (DWORD i = 0; i < export_dir->NumberOfNames; ++i) {
                const char* function_name = reinterpret_cast<const char*>(
                    reinterpret_cast<BYTE*>(ntdll_base) + name_table[i]);
                
                // Only process Nt/Zw functions
                if (strncmp(function_name, "Nt", 2) == 0 || strncmp(function_name, "Zw", 2) == 0) {
                    WORD ordinal = ordinal_table[i];
                    BYTE* function_addr = reinterpret_cast<BYTE*>(ntdll_base) + address_table[ordinal];
                    
                    // Extract syscall number from function prologue
                    DWORD syscall_number = extractSyscallNumberFromFunction(function_addr);
                    if (syscall_number != 0xFFFFFFFF) {
                        syscall_numbers_[function_name] = syscall_number;
                    }
                }
            }
            
            return !syscall_numbers_.empty();
        }
        
        DWORD extractSyscallNumberFromFunction(BYTE* function_addr) {
            // Check for typical syscall stub pattern: mov eax, syscall_number
            if (function_addr[0] == 0xB8) { // mov eax, imm32
                return *reinterpret_cast<DWORD*>(&function_addr[1]);
            }
            
            // Alternative pattern: mov r10, rcx; mov eax, syscall_number
            if (function_addr[0] == 0x4C && function_addr[1] == 0x8B && 
                function_addr[2] == 0xD1 && function_addr[3] == 0xB8) {
                return *reinterpret_cast<DWORD*>(&function_addr[4]);
            }
            
            return 0xFFFFFFFF; // Not found
        }
        
        void createSyscallStubs() {
            for (const auto& [name, syscall_number] : syscall_numbers_) {
                auto stub = std::make_unique<SyscallStub>();
                
                // Set syscall number in mov eax instruction
                *reinterpret_cast<DWORD*>(&stub->mov_eax[1]) = syscall_number;
                
                // Make stub executable
                DWORD old_protect;
                VirtualProtect(stub.get(), sizeof(SyscallStub), PAGE_EXECUTE_READWRITE, &old_protect);
                
                syscall_stubs_[name] = std::move(stub);
            }
        }
    };
    
    // Global instance
    inline DirectSyscallResolver& getSyscallResolver() {
        static DirectSyscallResolver resolver;
        return resolver;
    }
}

// Advanced PEB/TEB manipulation for stealth
namespace PEBStealth {
    
    class PEBManipulator {
    private:
        PPEB original_peb_;
        PEB modified_peb_;
        bool modifications_applied_ = false;
        
    public:
        PEBManipulator() {
            original_peb_ = reinterpret_cast<PPEB>(__readgsqword(0x60));
            if (original_peb_) {
                memcpy(&modified_peb_, original_peb_, sizeof(PEB));
            }
        }
        
        bool hideFromDebugger() {
            if (!original_peb_) return false;
            
            try {
                // Clear BeingDebugged flag
                modified_peb_.BeingDebugged = FALSE;
                
                // Clear NtGlobalFlag (debugger artifacts)
                modified_peb_.NtGlobalFlag = 0;
                
                // Apply modifications
                return applyModifications();
                
            } catch (...) {
                return false;
            }
        }
        
        bool spoofProcessName(const std::wstring& fake_name) {
            if (!original_peb_ || !original_peb_->ProcessParameters) return false;
            
            try {
                // This would require more complex memory manipulation
                // For demonstration, we'll modify the image path
                
                // Create fake unicode string
                UNICODE_STRING fake_image_path;
                fake_image_path.Length = static_cast<USHORT>(fake_name.length() * sizeof(wchar_t));
                fake_image_path.MaximumLength = fake_image_path.Length + sizeof(wchar_t);
                fake_image_path.Buffer = const_cast<PWSTR>(fake_name.c_str());
                
                // This is a simplified example - real implementation would need
                // to allocate memory and properly update all references
                
                return true;
                
            } catch (...) {
                return false;
            }
        }
        
        bool hideModule(const std::string& module_name) {
            if (!original_peb_ || !original_peb_->Ldr) return false;
            
            try {
                PPEB_LDR_DATA ldr = original_peb_->Ldr;
                
                // Iterate through loaded modules
                PLIST_ENTRY current = ldr->InLoadOrderModuleList.Flink;
                
                while (current != &ldr->InLoadOrderModuleList) {
                    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(
                        current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
                    
                    if (entry->BaseDllName.Buffer) {
                        // Convert wide string to narrow for comparison
                        std::string current_name;
                        int len = WideCharToMultiByte(CP_UTF8, 0, 
                            entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t),
                            nullptr, 0, nullptr, nullptr);
                        
                        if (len > 0) {
                            current_name.resize(len);
                            WideCharToMultiByte(CP_UTF8, 0,
                                entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(wchar_t),
                                &current_name[0], len, nullptr, nullptr);
                        }
                        
                        // Check if this is the module to hide
                        if (current_name.find(module_name) != std::string::npos) {
                            // Unlink from all lists
                            RemoveEntryList(&entry->InLoadOrderLinks);
                            RemoveEntryList(&entry->InMemoryOrderLinks);
                            RemoveEntryList(&entry->InInitializationOrderLinks);
                            
                            return true;
                        }
                    }
                    
                    current = current->Flink;
                }
                
                return false;
                
            } catch (...) {
                return false;
            }
        }
        
        bool spoofSystemInfo() {
            if (!original_peb_) return false;
            
            try {
                // Spoof number of processors
                modified_peb_.NumberOfProcessors = 8; // Fake multi-core system
                
                // Spoof OS version to appear as legitimate Windows 10
                modified_peb_.OSMajorVersion = 10;
                modified_peb_.OSMinorVersion = 0;
                modified_peb_.OSBuildNumber = 19041;
                modified_peb_.OSPlatformId = VER_PLATFORM_WIN32_NT;
                
                return applyModifications();
                
            } catch (...) {
                return false;
            }
        }
        
        ~PEBManipulator() {
            restoreOriginal();
        }
        
    private:
        bool applyModifications() {
            if (!original_peb_) return false;
            
            try {
                // Change memory protection to allow writing
                DWORD old_protect;
                if (!VirtualProtect(original_peb_, sizeof(PEB), PAGE_READWRITE, &old_protect)) {
                    return false;
                }
                
                // Apply modifications
                memcpy(original_peb_, &modified_peb_, sizeof(PEB));
                
                // Restore original protection
                VirtualProtect(original_peb_, sizeof(PEB), old_protect, &old_protect);
                
                modifications_applied_ = true;
                return true;
                
            } catch (...) {
                return false;
            }
        }
        
        void restoreOriginal() {
            if (modifications_applied_ && original_peb_) {
                try {
                    DWORD old_protect;
                    VirtualProtect(original_peb_, sizeof(PEB), PAGE_READWRITE, &old_protect);
                    
                    // Restore only critical fields to avoid crashes
                    original_peb_->BeingDebugged = FALSE; // Keep this cleared
                    original_peb_->NtGlobalFlag = 0;      // Keep this cleared
                    
                    VirtualProtect(original_peb_, sizeof(PEB), old_protect, &old_protect);
                } catch (...) {
                    // Ignore errors during cleanup
                }
            }
        }
    };
}

// Advanced APC injection for stealth execution
namespace APCInjection {
    
    class StealthAPCInjector {
    private:
        pNtQueueApcThread NtQueueApcThread_;
        pNtCreateThreadEx NtCreateThreadEx_;
        
    public:
        StealthAPCInjector() {
            // Get direct syscall functions
            auto& resolver = StealthAPI::getSyscallResolver();
            resolver.initialize();
            
            NtQueueApcThread_ = resolver.getDirectSyscall<pNtQueueApcThread>("NtQueueApcThread");
            NtCreateThreadEx_ = resolver.getDirectSyscall<pNtCreateThreadEx>("NtCreateThreadEx");
        }
        
        bool injectAPCToThread(HANDLE thread_handle, PVOID apc_routine, 
                              PVOID param1 = nullptr, PVOID param2 = nullptr, PVOID param3 = nullptr) {
            if (!NtQueueApcThread_ || !thread_handle || thread_handle == INVALID_HANDLE_VALUE) {
                return false;
            }
            
            try {
                NTSTATUS status = NtQueueApcThread_(thread_handle, apc_routine, param1, param2, param3);
                return NT_SUCCESS(status);
                
            } catch (...) {
                return false;
            }
        }
        
        bool injectAPCToProcess(DWORD process_id, PVOID apc_routine, PVOID parameter) {
            if (!NtQueueApcThread_) return false;
            
            try {
                // Open target process
                HANDLE process_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | 
                                                  PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION,
                                                  FALSE, process_id);
                if (!process_handle) return false;
                
                // Find alertable thread
                HANDLE thread_handle = findAlertableThread(process_id);
                if (!thread_handle) {
                    CloseHandle(process_handle);
                    return false;
                }
                
                // Inject APC
                bool result = injectAPCToThread(thread_handle, apc_routine, parameter);
                
                CloseHandle(thread_handle);
                CloseHandle(process_handle);
                
                return result;
                
            } catch (...) {
                return false;
            }
        }
        
        // Create hidden thread using APC
        bool createHiddenThread(PVOID start_routine, PVOID parameter, PHANDLE thread_handle = nullptr) {
            if (!NtCreateThreadEx_) return false;
            
            try {
                HANDLE new_thread_handle;
                NTSTATUS status = NtCreateThreadEx_(
                    &new_thread_handle,
                    THREAD_ALL_ACCESS,
                    nullptr,
                    GetCurrentProcess(),
                    start_routine,
                    parameter,
                    0x1, // CREATE_SUSPENDED | HIDE_FROM_DEBUGGER
                    0,
                    0,
                    0,
                    nullptr
                );
                
                if (NT_SUCCESS(status)) {
                    if (thread_handle) {
                        *thread_handle = new_thread_handle;
                    } else {
                        CloseHandle(new_thread_handle);
                    }
                    return true;
                }
                
                return false;
                
            } catch (...) {
                return false;
            }
        }
        
    private:
        HANDLE findAlertableThread(DWORD process_id) {
            HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return nullptr;
            
            THREADENTRY32 thread_entry;
            thread_entry.dwSize = sizeof(THREADENTRY32);
            
            if (Thread32First(snapshot, &thread_entry)) {
                do {
                    if (thread_entry.th32OwnerProcessID == process_id) {
                        HANDLE thread_handle = OpenThread(THREAD_SET_CONTEXT, FALSE, thread_entry.th32ThreadID);
                        if (thread_handle) {
                            CloseHandle(snapshot);
                            return thread_handle;
                        }
                    }
                } while (Thread32Next(snapshot, &thread_entry));
            }
            
            CloseHandle(snapshot);
            return nullptr;
        }
    };
}

// Enhanced stealth mouse input using NtUserSendInput
class StealthMouseInput {
private:
    pNtUserSendInput NtUserSendInput_;
    std::mt19937 rng_;
    std::uniform_real_distribution<double> noise_dist_;
    
    // Input method randomization
    enum class InputMethod {
        NT_USER_SEND_INPUT,
        SEND_INPUT,
        MOUSE_EVENT,
        SET_CURSOR_POS
    };
    
    std::vector<InputMethod> available_methods_;
    std::uniform_int_distribution<size_t> method_selector_;
    
    // Timing randomization
    std::chrono::steady_clock::time_point last_input_time_;
    std::uniform_int_distribution<int> delay_dist_;
    
public:
    StealthMouseInput() : rng_(std::random_device{}()), 
                         noise_dist_(-0.5, 0.5),
                         delay_dist_(0, 2) {
        
        // Initialize NT API
        auto& resolver = StealthAPI::getSyscallResolver();
        resolver.initialize();
        NtUserSendInput_ = resolver.getDirectSyscall<pNtUserSendInput>("NtUserSendInput");
        
        // Setup available input methods
        available_methods_ = {
            InputMethod::NT_USER_SEND_INPUT,
            InputMethod::SEND_INPUT,
            InputMethod::MOUSE_EVENT,
            InputMethod::SET_CURSOR_POS
        };
        
        method_selector_ = std::uniform_int_distribution<size_t>(0, available_methods_.size() - 1);
        last_input_time_ = std::chrono::steady_clock::now();
    }
    
    bool sendMouseMovement(int dx, int dy, bool use_random_method = true) {
        // Apply human-like timing delays
        if (!applyHumanLikeTiming()) {
            return false; // Skip this input to maintain human-like patterns
        }
        
        // Add subtle noise for more natural movement
        dx = static_cast<int>(dx + noise_dist_(rng_));
        dy = static_cast<int>(dy + noise_dist_(rng_));
        
        if (dx == 0 && dy == 0) return true; // No movement needed
        
        // Choose input method
        InputMethod method = use_random_method ? 
            available_methods_[method_selector_(rng_)] : InputMethod::NT_USER_SEND_INPUT;
        
        switch (method) {
            case InputMethod::NT_USER_SEND_INPUT:
                return sendInputViaDirectSyscall(dx, dy);
                
            case InputMethod::SEND_INPUT:
                return sendInputViaWinAPI(dx, dy);
                
            case InputMethod::MOUSE_EVENT:
                return sendInputViaMouseEvent(dx, dy);
                
            case InputMethod::SET_CURSOR_POS:
                return sendInputViaCursorPos(dx, dy);
                
            default:
                return sendInputViaDirectSyscall(dx, dy);
        }
    }
    
    bool sendMouseClick(bool left_button, bool down) {
        INPUT input = {};
        input.type = INPUT_MOUSE;
        
        if (left_button) {
            input.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN : MOUSEEVENTF_LEFTUP;
        } else {
            input.mi.dwFlags = down ? MOUSEEVENTF_RIGHTDOWN : MOUSEEVENTF_RIGHTUP;
        }
        
        input.mi.time = 0;
        input.mi.dwExtraInfo = generateRandomExtraInfo();
        
        return sendInputViaDirectSyscall(input);
    }
    
private:
    bool sendInputViaDirectSyscall(int dx, int dy) {
        if (!NtUserSendInput_) return false;
        
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dx = dx;
        input.mi.dy = dy;
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        input.mi.time = 0;
        input.mi.dwExtraInfo = generateRandomExtraInfo();
        
        return sendInputViaDirectSyscall(input);
    }
    
    bool sendInputViaDirectSyscall(const INPUT& input) {
        if (!NtUserSendInput_) return false;
        
        try {
            NTSTATUS status = NtUserSendInput_(1, const_cast<LPINPUT>(&input), sizeof(INPUT));
            return NT_SUCCESS(status);
            
        } catch (...) {
            return false;
        }
    }
    
    bool sendInputViaWinAPI(int dx, int dy) {
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dx = dx;
        input.mi.dy = dy;
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        input.mi.time = 0;
        input.mi.dwExtraInfo = generateRandomExtraInfo();
        
        return SendInput(1, &input, sizeof(INPUT)) == 1;
    }
    
    bool sendInputViaMouseEvent(int dx, int dy) {
        mouse_event(MOUSEEVENTF_MOVE, dx, dy, 0, generateRandomExtraInfo());
        return true;
    }
    
    bool sendInputViaCursorPos(int dx, int dy) {
        POINT current_pos;
        if (!GetCursorPos(&current_pos)) return false;
        
        return SetCursorPos(current_pos.x + dx, current_pos.y + dy) != FALSE;
    }
    
    bool applyHumanLikeTiming() {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::microseconds>(
            now - last_input_time_).count();
        
        // Minimum interval between inputs (human-like)
        constexpr int min_interval_us = 500; // 0.5ms
        constexpr int max_interval_us = 2000; // 2ms
        
        if (elapsed < min_interval_us) {
            // Occasionally skip inputs to maintain human-like rhythm
            std::bernoulli_distribution skip_dist(0.1); // 10% chance to skip
            if (skip_dist(rng_)) {
                return false;
            }
        }
        
        // Add random micro-delays
        int random_delay = delay_dist_(rng_);
        if (random_delay > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(random_delay * 100));
        }
        
        last_input_time_ = now;
        return true;
    }
    
    ULONG_PTR generateRandomExtraInfo() {
        // Generate realistic extra info that mimics legitimate input
        std::uniform_int_distribution<ULONG_PTR> dist(0x1000, 0xFFFF);
        return dist(rng

// Forward declarations
class EnhancedDetectionEngine;
class AdaptiveTargetTracker;
class SmartMovementController;
class PerformanceOptimizer;

// Enhanced Mathematical Utilities with SIMD support
namespace MathUtils {
    
    // Optimized Vector2D with SSE support
    struct alignas(16) Vector2D {
        union {
            struct { double x, y; };
            __m128d data;
        };
        
        Vector2D() : x(0), y(0) {}
        Vector2D(double x_, double y_) : x(x_), y(y_) {}
        Vector2D(__m128d data_) : data(data_) {}
        
        // SIMD-optimized operations
        Vector2D operator+(const Vector2D& other) const {
            return Vector2D(_mm_add_pd(data, other.data));
        }
        
        Vector2D operator-(const Vector2D& other) const {
            return Vector2D(_mm_sub_pd(data, other.data));
        }
        
        Vector2D operator*(double scalar) const {
            __m128d scalar_vec = _mm_set1_pd(scalar);
            return Vector2D(_mm_mul_pd(data, scalar_vec));
        }
        
        double magnitude() const {
            __m128d squared = _mm_mul_pd(data, data);
            __m128d sum = _mm_hadd_pd(squared, squared);
            return _mm_cvtsd_f64(_mm_sqrt_sd(sum, sum));
        }
        
        Vector2D normalized() const {
            double mag = magnitude();
            return mag > 1e-9 ? *this * (1.0 / mag) : Vector2D(0, 0);
        }
        
        double dot(const Vector2D& other) const {
            __m128d mul = _mm_mul_pd(data, other.data);
            __m128d sum = _mm_hadd_pd(mul, mul);
            return _mm_cvtsd_f64(sum);
        }
        
        // Enhanced interpolation with acceleration curves
        Vector2D smoothLerp(const Vector2D& target, double t, double acceleration = 1.0) const {
            // Apply acceleration curve for more natural movement
            double adjusted_t = std::pow(t, acceleration);
            Vector2D diff = target - *this;
            return *this + diff * adjusted_t;
        }
    };
    
    // Advanced spline interpolation for smooth paths
    class CatmullRomSpline {
    private:
        std::vector<Vector2D> control_points_;
        std::vector<double> segment_lengths_;
        double total_length_;
        
    public:
        void addControlPoint(const Vector2D& point) {
            control_points_.push_back(point);
            recalculateSegments();
        }
        
        Vector2D evaluate(double t) const {
            if (control_points_.size() < 4) return Vector2D(0, 0);
            
            t = std::clamp(t, 0.0, 1.0);
            double scaled_t = t * (control_points_.size() - 3);
            int segment = static_cast<int>(scaled_t);
            double local_t = scaled_t - segment;
            
            segment = std::clamp(segment, 0, static_cast<int>(control_points_.size() - 4));
            
            const Vector2D& p0 = control_points_[segment];
            const Vector2D& p1 = control_points_[segment + 1];
            const Vector2D& p2 = control_points_[segment + 2];
            const Vector2D& p3 = control_points_[segment + 3];
            
            // Catmull-Rom spline formula
            double t2 = local_t * local_t;
            double t3 = t2 * local_t;
            
            Vector2D result = p1 * (2.0) +
                             (p2 - p0) * local_t +
                             (p0 * 2.0 - p1 * 5.0 + p2 * 4.0 - p3) * t2 +
                             (p1 * 3.0 - p0 - p2 * 3.0 + p3) * t3;
            
            return result * 0.5;
        }
        
    private:
        void recalculateSegments() {
            segment_lengths_.clear();
            total_length_ = 0.0;
            
            if (control_points_.size() < 2) return;
            
            for (size_t i = 1; i < control_points_.size(); ++i) {
                double length = (control_points_[i] - control_points_[i-1]).magnitude();
                segment_lengths_.push_back(length);
                total_length_ += length;
            }
        }
    };
}

// Enhanced Target Information with ML features
struct EnhancedTargetInfo {
    cv::Point2f position;
    cv::Point2f velocity;
    cv::Point2f acceleration;
    cv::Point2f predicted_position;
    
    float confidence;
    float stability_score;
    float threat_level;
    float visibility_score;
    
    cv::Rect2f bounding_box;
    cv::Rect2f head_region;
    cv::Rect2f chest_region;
    
    int tracking_id;
    std::chrono::steady_clock::time_point first_seen;
    std::chrono::steady_clock::time_point last_seen;
    
    // Advanced tracking data
    std::deque<cv::Point2f> position_history;
    std::deque<float> confidence_history;
    std::unique_ptr<cv::KalmanFilter> kalman_filter;
    
    // Behavioral analysis
    enum class MovementType {
        STATIC, LINEAR, CURVED, ERRATIC, PREDICTABLE
    } movement_type = MovementType::STATIC;
    
    float movement_predictability = 0.0f;
    float angular_velocity = 0.0f;
    
    // Quality metrics
    float target_quality_score = 0.0f;
    float hit_probability = 0.0f;
    float accessibility = 1.0f;
    
    EnhancedTargetInfo() {
        auto now = std::chrono::steady_clock::now();
        first_seen = last_seen = now;
        tracking_id = -1;
        
        // Initialize Kalman filter for position prediction
        kalman_filter = std::make_unique<cv::KalmanFilter>(4, 2);
        kalman_filter->transitionMatrix = (cv::Mat_<float>(4, 4) <<
            1, 0, 1, 0,
            0, 1, 0, 1,
            0, 0, 1, 0,
            0, 0, 0, 1);
        
        kalman_filter->measurementMatrix = (cv::Mat_<float>(2, 4) <<
            1, 0, 0, 0,
            0, 1, 0, 0);
        
        cv::setIdentity(kalman_filter->processNoiseCov, cv::Scalar::all(1e-4));
        cv::setIdentity(kalman_filter->measurementNoiseCov, cv::Scalar::all(1e-1));
        cv::setIdentity(kalman_filter->errorCovPost, cv::Scalar::all(0.1));
    }
    
    void updatePrediction() {
        if (!kalman_filter) return;
        
        // Predict next position
        cv::Mat prediction = kalman_filter->predict();
        predicted_position.x = prediction.at<float>(0);
        predicted_position.y = prediction.at<float>(1);
        
        // Update velocity from Kalman filter
        velocity.x = prediction.at<float>(2);
        velocity.y = prediction.at<float>(3);
        
        // Calculate movement type and predictability
        analyzeMovementPattern();
        calculateQualityMetrics();
    }
    
    void correct(const cv::Point2f& measured_position) {
        if (!kalman_filter) return;
        
        cv::Mat measurement = (cv::Mat_<float>(2, 1) << 
            measured_position.x, measured_position.y);
        kalman_filter->correct(measurement);
        
        // Update history
        position_history.push_back(measured_position);
        if (position_history.size() > 20) {
            position_history.pop_front();
        }
        
        updatePrediction();
    }
    
private:
    void analyzeMovementPattern() {
        if (position_history.size() < 5) {
            movement_type = MovementType::STATIC;
            movement_predictability = 0.5f;
            return;
        }
        
        // Calculate movement characteristics
        std::vector<float> speeds;
        std::vector<float> direction_changes;
        
        for (size_t i = 2; i < position_history.size(); ++i) {
            cv::Point2f v1 = position_history[i-1] - position_history[i-2];
            cv::Point2f v2 = position_history[i] - position_history[i-1];
            
            float speed = cv::norm(v2);
            speeds.push_back(speed);
            
            if (cv::norm(v1) > 0 && cv::norm(v2) > 0) {
                float dot = v1.dot(v2) / (cv::norm(v1) * cv::norm(v2));
                float angle_change = std::acos(std::clamp(dot, -1.0f, 1.0f));
                direction_changes.push_back(angle_change);
            }
        }
        
        // Classify movement type
        float avg_speed = std::accumulate(speeds.begin(), speeds.end(), 0.0f) / speeds.size();
        float speed_variance = 0.0f;
        for (float speed : speeds) {
            speed_variance += std::pow(speed - avg_speed, 2);
        }
        speed_variance /= speeds.size();
        
        float avg_direction_change = direction_changes.empty() ? 0.0f :
            std::accumulate(direction_changes.begin(), direction_changes.end(), 0.0f) / direction_changes.size();
        
        if (avg_speed < 1.0f) {
            movement_type = MovementType::STATIC;
            movement_predictability = 0.9f;
        } else if (avg_direction_change < 0.2f) {
            movement_type = MovementType::LINEAR;
            movement_predictability = 0.8f;
        } else if (speed_variance < avg_speed * 0.3f) {
            movement_type = MovementType::PREDICTABLE;
            movement_predictability = 0.7f;
        } else {
            movement_type = MovementType::ERRATIC;
            movement_predictability = 0.3f;
        }
    }
    
    void calculateQualityMetrics() {
        // Calculate overall target quality based on multiple factors
        float confidence_score = confidence;
        float stability_score_norm = std::min(1.0f, stability_score);
        float predictability_score = movement_predictability;
        float size_score = std::min(1.0f, (bounding_box.width * bounding_box.height) / 10000.0f);
        
        target_quality_score = 
            confidence_score * 0.3f +
            stability_score_norm * 0.25f +
            predictability_score * 0.2f +
            size_score * 0.15f +
            accessibility * 0.1f;
        
        // Calculate hit probability based on target characteristics
        hit_probability = target_quality_score * 
            (1.0f - std::min(1.0f, cv::norm(velocity) / 100.0f)) * // Moving targets are harder
            (0.5f + 0.5f * confidence); // Confidence affects hit chance
    }
};

// Enhanced Detection Engine with improved accuracy
class EnhancedDetectionEngine {
private:
    std::unique_ptr<cv::dnn::Net> primary_network_;
    std::unique_ptr<cv::dnn::Net> fallback_network_;
    
    // Multi-scale detection
    std::vector<float> detection_scales_ = {0.8f, 1.0f, 1.2f};
    
    // Detection parameters
    float confidence_threshold_ = 0.6f;
    float nms_threshold_ = 0.4f;
    
    // Performance optimization
    cv::Size input_size_ = cv::Size(416, 416);
    bool use_gpu_ = false;
    
    // Tracking integration
    std::vector<cv::Ptr<cv::Tracker>> active_trackers_;
    std::unordered_map<int, EnhancedTargetInfo> tracked_targets_;
    int next_tracking_id_ = 0;
    
    mutable std::mutex detection_mutex_;
    
public:
    EnhancedDetectionEngine() = default;
    
    bool initialize(const std::string& model_path, bool use_gpu = false) {
        try {
            primary_network_ = std::make_unique<cv::dnn::Net>(cv::dnn::readNet(model_path));
            
            if (use_gpu) {
                primary_network_->setPreferableBackend(cv::dnn::DNN_BACKEND_CUDA);
                primary_network_->setPreferableTarget(cv::dnn::DNN_TARGET_CUDA);
                use_gpu_ = true;
            } else {
                primary_network_->setPreferableBackend(cv::dnn::DNN_BACKEND_DEFAULT);
                primary_network_->setPreferableTarget(cv::dnn::DNN_TARGET_CPU);
            }
            
            return !primary_network_->empty();
            
        } catch (const std::exception& e) {
            return false;
        }
    }
    
    std::vector<EnhancedTargetInfo> detectTargets(const cv::Mat& frame) {
        std::lock_guard<std::mutex> lock(detection_mutex_);
        
        if (!primary_network_ || frame.empty()) {
            return {};
        }
        
        std::vector<EnhancedTargetInfo> all_detections;
        
        // Multi-scale detection for better accuracy
        for (float scale : detection_scales_) {
            cv::Size scaled_size(
                static_cast<int>(input_size_.width * scale),
                static_cast<int>(input_size_.height * scale)
            );
            
            auto detections = detectAtScale(frame, scaled_size, scale);
            all_detections.insert(all_detections.end(), detections.begin(), detections.end());
        }
        
        // Apply non-maximum suppression across all scales
        std::vector<EnhancedTargetInfo> filtered_detections = applyNMS(all_detections);
        
        // Update tracking
        updateTracking(frame, filtered_detections);
        
        return getTrackedTargets();
    }
    
    void setConfidenceThreshold(float threshold) {
        confidence_threshold_ = std::clamp(threshold, 0.1f, 1.0f);
    }
    
    void setNMSThreshold(float threshold) {
        nms_threshold_ = std::clamp(threshold, 0.1f, 1.0f);
    }
    
private:
    std::vector<EnhancedTargetInfo> detectAtScale(const cv::Mat& frame, 
                                                 const cv::Size& input_size, 
                                                 float scale_factor) {
        try {
            // Prepare input blob
            cv::Mat blob;
            cv::dnn::blobFromImage(frame, blob, 1.0/255.0, input_size, cv::Scalar(), true, false);
            primary_network_->setInput(blob);
            
            // Run inference
            std::vector<cv::Mat> outputs;
            primary_network_->forward(outputs, primary_network_->getUnconnectedOutLayersNames());
            
            // Parse detections
            return parseDetections(outputs, frame.size(), scale_factor);
            
        } catch (const std::exception& e) {
            return {};
        }
    }
    
    std::vector<EnhancedTargetInfo> parseDetections(const std::vector<cv::Mat>& outputs,
                                                   const cv::Size& frame_size,
                                                   float scale_factor) {
        std::vector<EnhancedTargetInfo> detections;
        
        for (const auto& output : outputs) {
            for (int i = 0; i < output.rows; ++i) {
                const float* data = output.ptr<float>(i);
                
                float confidence = data[4];
                if (confidence < confidence_threshold_) continue;
                
                // Parse bounding box
                float center_x = data[0] * frame_size.width;
                float center_y = data[1] * frame_size.height;
                float width = data[2] * frame_size.width;
                float height = data[3] * frame_size.height;
                
                EnhancedTargetInfo target;
                target.position = cv::Point2f(center_x, center_y);
                target.confidence = confidence;
                target.bounding_box = cv::Rect2f(
                    center_x - width/2, center_y - height/2, width, height
                );
                
                // Estimate body parts
                estimateBodyParts(target);
                
                detections.push_back(target);
            }
        }
        
        return detections;
    }
    
    void estimateBodyParts(EnhancedTargetInfo& target) {
        // Simple heuristic for body part estimation
        float box_width = target.bounding_box.width;
        float box_height = target.bounding_box.height;
        
        // Head region (top 30% of bounding box)
        target.head_region = cv::Rect2f(
            target.bounding_box.x + box_width * 0.2f,
            target.bounding_box.y,
            box_width * 0.6f,
            box_height * 0.3f
        );
        
        // Chest region (middle 40% of bounding box)
        target.chest_region = cv::Rect2f(
            target.bounding_box.x + box_width * 0.1f,
            target.bounding_box.y + box_height * 0.3f,
            box_width * 0.8f,
            box_height * 0.4f
        );
    }
    
    std::vector<EnhancedTargetInfo> applyNMS(const std::vector<EnhancedTargetInfo>& detections) {
        if (detections.empty()) return {};
        
        std::vector<cv::Rect> boxes;
        std::vector<float> scores;
        
        for (const auto& detection : detections) {
            boxes.push_back(cv::Rect(detection.bounding_box));
            scores.push_back(detection.confidence);
        }
        
        std::vector<int> indices;
        cv::dnn::NMSBoxes(boxes, scores, confidence_threshold_, nms_threshold_, indices);
        
        std::vector<EnhancedTargetInfo> filtered;
        for (int idx : indices) {
            filtered.push_back(detections[idx]);
        }
        
        return filtered;
    }
    
    void updateTracking(const cv::Mat& frame, const std::vector<EnhancedTargetInfo>& detections) {
        // Update existing trackers
        auto tracker_it = active_trackers_.begin();
        auto target_it = tracked_targets_.begin();
        
        while (tracker_it != active_trackers_.end() && target_it != tracked_targets_.end()) {
            cv::Rect2d bbox;
            if ((*tracker_it)->update(frame, bbox)) {
                // Update target position from tracker
                target_it->second.position = cv::Point2f(
                    bbox.x + bbox.width/2, bbox.y + bbox.height/2
                );
                target_it->second.bounding_box = bbox;
                target_it->second.correct(target_it->second.position);
                
                ++tracker_it;
                ++target_it;
            } else {
                // Remove failed tracker
                tracker_it = active_trackers_.erase(tracker_it);
                target_it = tracked_targets_.erase(target_it);
            }
        }
        
        // Associate new detections with existing targets or create new ones
        for (const auto& detection : detections) {
            int best_match_id = findBestMatch(detection);
            
            if (best_match_id >= 0) {
                // Update existing target
                tracked_targets_[best_match_id] = detection;
                tracked_targets_[best_match_id].tracking_id = best_match_id;
                tracked_targets_[best_match_id].correct(detection.position);
            } else {
                // Create new tracker
                cv::Ptr<cv::Tracker> tracker = cv::TrackerKCF::create();
                if (tracker->init(frame, cv::Rect(detection.bounding_box))) {
                    EnhancedTargetInfo new_target = detection;
                    new_target.tracking_id = next_tracking_id_++;
                    
                    active_trackers_.push_back(tracker);
                    tracked_targets_[new_target.tracking_id] = new_target;
                }
            }
        }
    }
    
    int findBestMatch(const EnhancedTargetInfo& detection) {
        int best_id = -1;
        float best_distance = std::numeric_limits<float>::max();
        
        for (const auto& [id, target] : tracked_targets_) {
            float distance = cv::norm(detection.position - target.position);
            if (distance < best_distance && distance < 50.0f) { // 50 pixel threshold
                best_distance = distance;
                best_id = id;
            }
        }
        
        return best_id;
    }
    
    std::vector<EnhancedTargetInfo> getTrackedTargets() {
        std::vector<EnhancedTargetInfo> targets;
        
        auto now = std::chrono::steady_clock::now();
        for (auto& [id, target] : tracked_targets_) {
            // Update timestamps
            target.last_seen = now;
            
            // Calculate stability and other metrics
            auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - target.first_seen).count();
            target.stability_score = std::min(1.0f, age / 1000.0f); // Max stability at 1 second
            
            targets.push_back(target);
        }
        
        return targets;
    }
};

// Smart Movement Controller with enhanced human-like behavior
class SmartMovementController {
private:
    struct MovementParams {
        double base_smoothing = 8.0;
        double adaptive_smoothing = true;
        double max_acceleration = 50.0;
        double human_factor = 0.3;
        double noise_intensity = 0.1;
        
        // Movement style preferences
        enum class Style {
            PRECISE, SMOOTH, HUMAN_LIKE, ADAPTIVE
        } style = Style::ADAPTIVE;
    } params_;
    
    MathUtils::Vector2D current_velocity_{0, 0};
    MathUtils::Vector2D target_position_{0, 0};
    MathUtils::Vector2D current_position_{0, 0};
    
    std::mt19937 rng_;
    std::normal_distribution<double> noise_dist_{0.0, 1.0};
    
    // Path planning
    std::unique_ptr<MathUtils::CatmullRomSpline> current_path_;
    double path_progress_ = 0.0;
    std::chrono::steady_clock::time_point path_start_time_;
    
    mutable std::mutex movement_mutex_;
    
public:
    SmartMovementController() : rng_(std::random_device{}()) {}
    
    void setTarget(const MathUtils::Vector2D& target) {
        std::lock_guard<std::mutex> lock(movement_mutex_);
        
        if ((target - target_position_).magnitude() > 5.0) {
            target_position_ = target;
            planPath();
        }
    }
    
    MathUtils::Vector2D getNextMovement(double dt) {
        std::lock_guard<std::mutex> lock(movement_mutex_);
        
        if (!current_path_) {
            return MathUtils::Vector2D(0, 0);
        }
        
        // Update path progress
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration<double>(now - path_start_time_).count();
        path_progress_ = std::min(1.0, elapsed / getPathDuration());
        
        if (path_progress_ >= 1.0) {
            current_path_.reset();
            return MathUtils::Vector2D(0, 0);
        }
        
        // Get target position from path
        MathUtils::Vector2D path_target = current_path_->evaluate(path_progress_);
        
        // Calculate movement with smoothing
        MathUtils::Vector2D desired_velocity = calculateDesiredVelocity(path_target, dt);
        
        // Apply human-like modifications
        if (params_.style == MovementParams::Style::HUMAN_LIKE || 
            params_.style == MovementParams::Style::ADAPTIVE) {
            desired_velocity = applyHumanLikeModifications(desired_velocity, dt);
        }
        
        // Smooth velocity changes
        current_velocity_ = smoothVelocity(current_velocity_, desired_velocity, dt);
        
        // Calculate final movement
        MathUtils::Vector2D movement = current_velocity_ * dt;
        current_position_ = current_position_ + movement;
        
        return movement;
    }
    
    void updateParams(const MovementParams& params) {
        std::lock_guard<std::mutex> lock(movement_mutex_);
        params_ = params;
    }
    
    bool isMoving() const {
        std::lock_guard<std::mutex> lock(movement_mutex_);
        return current_velocity_.magnitude() > 0.1;
    }
    
private:
    void planPath() {
        current_path_ = std::make_unique<MathUtils::CatmullRomSpline>();
        
        MathUtils::Vector2D direction = (target_position_ - current_position_).normalized();
        double distance = (target_position_ - current_position_).magnitude();
        
        // Create control points for smooth path
        current_path_->addControlPoint(current_position_ - direction * 10.0); // Before start
        current_path_->addControlPoint(current_position_); // Start
        
        // Add intermediate points for large movements
        if (distance > 100.0) {
            int num_intermediate = static_cast<int>(distance / 50.0);
            for (int i = 1; i <= num_intermediate; ++i) {
                double t = static_cast<double>(i) / (num_intermediate + 1);
                MathUtils::Vector2D intermediate = current_position_.smoothLerp(target_position_, t);
                
                // Add slight curve for natural movement
                MathUtils::Vector2D perpendicular(-direction.y, direction.x);
                double curve_amount = std::sin(t * M_PI) * distance * 0.1 * params_.human_factor;
                intermediate = intermediate + perpendicular * curve_amount;
                
                current_path_->addControlPoint(intermediate);
            }
        }
        
        current_path_->addControlPoint(target_position_); // End
        current_path_->addControlPoint(target_position_ + direction * 10.0); // After end
        
        path_progress_ = 0.0;
        path_start_time_ = std::chrono::steady_clock::now();
    }
    
    double getPathDuration() const {
        double distance = (target_position_ - current_position_).magnitude();
        double base_duration = distance / 200.0; // Base speed: 200 pixels/second
        
        // Adjust duration based on movement style
        switch (params_.style) {
            case MovementParams::Style::PRECISE:
                return base_duration * 1.5; // Slower for precision
            case MovementParams::Style::SMOOTH:
                return base_duration * 1.2;
            case MovementParams::Style::HUMAN_LIKE:
                return base_duration * (0.8 + params_.human_factor * 0.4);
            case MovementParams::Style::ADAPTIVE:
                return base_duration; // Adaptive timing
            default:
                return base_duration;
        }
    }
    
    MathUtils::Vector2D calculateDesiredVelocity(const MathUtils::Vector2D& target, double dt) {
        MathUtils::Vector2D error = target - current_position_;
        double distance = error.magnitude();
        
        if (distance < 1.0) {
            return MathUtils::Vector2D(0, 0);
        }
        
        // Calculate desired velocity with dynamic smoothing
        double smoothing = params_.adaptive_smoothing ? 
            calculateAdaptiveSmoothingr(distance) : params_.base_smoothing;
        
        MathUtils::Vector2D desired_velocity = error * (1.0 / smoothing);
        
        // Apply maximum acceleration constraint
        double max_velocity_change = params_.max_acceleration * dt;
        MathUtils::Vector2D velocity_change = desired_velocity - current_velocity_;
        
        if (velocity_change.magnitude() > max_velocity_change) {
            velocity_change = velocity_change.normalized() * max_velocity_change;
            desired_velocity = current_velocity_ + velocity_change;
        }
        
        return desired_velocity;
    }
    
    double calculateAdaptiveSmoothingr(double distance) const {
        // Increase smoothing for smaller distances (more precision)
        // Decrease smoothing for larger distances (faster movement)
        double min_smoothing = 2.0;
        double max_smoothing = 20.0;
        
        double normalized_distance = std::clamp(distance / 100.0, 0.0, 1.0);
        return max_smoothing - (max_smoothing - min_smoothing) * normalized_distance;
    }
    
    MathUtils::Vector2D applyHumanLikeModifications(const MathUtils::Vector2D& velocity, double dt) {
        MathUtils::Vector2D modified_velocity = velocity;
        
        // Add micro-tremors
        double tremor_x = noise_dist_(rng_) * params_.noise_intensity;
        double tremor_y = noise_dist_(rng_) * params_.noise_intensity;
        modified_velocity = modified_velocity + MathUtils::Vector2D(tremor_x, tremor_y);
        
        // Apply reaction time simulation (slight delay in direction changes)
        static MathUtils::Vector2D previous_direction(0, 0);
        MathUtils::Vector2D current_direction = velocity.normalized();
        
        if (previous_direction.magnitude() > 0) {
            double direction_change = std::acos(std::clamp(
                previous_direction.dot(current_direction), -1.0, 1.0));
            
            if (direction_change > 0.1) { // Significant direction change
                // Reduce velocity slightly to simulate human reaction time
                modified_velocity = modified_velocity * (1.0 - params_.human_factor * 0.2);
            }
        }
        
        previous_direction = current_direction;
        
        // Add acceleration/deceleration curves
        double velocity_magnitude = modified_velocity.magnitude();
        if (velocity_magnitude > 0) {
            // Apply sigmoid-like acceleration curve
            double progress = path_progress_;
            double acceleration_factor = 1.0;
            
            if (progress < 0.2) {
                // Accelerating phase
                acceleration_factor = 0.5 + 0.5 * (progress / 0.2);
            } else if (progress > 0.8) {
                // Decelerating phase
                acceleration_factor = 0.5 + 0.5 * ((1.0 - progress) / 0.2);
            }
            
            modified_velocity = modified_velocity * acceleration_factor;
        }
        
        return modified_velocity;
    }
    
    MathUtils::Vector2D smoothVelocity(const MathUtils::Vector2D& current, 
                                      const MathUtils::Vector2D& desired, 
                                      double dt) {
        // Exponential smoothing with adaptive factor
        double smoothing_factor = std::exp(-dt * params_.base_smoothing);
        return current * smoothing_factor + desired * (1.0 - smoothing_factor);
    }
};

// Performance Optimizer for adaptive quality control
class PerformanceOptimizer {
private:
    struct PerformanceMetrics {
        double avg_frame_time = 0.0;
        double avg_detection_time = 0.0;
        double avg_processing_time = 0.0;
        double cpu_usage = 0.0;
        double memory_usage = 0.0;
        int frames_processed = 0;
        
        std::chrono::steady_clock::time_point last_update;
        
        PerformanceMetrics() {
            last_update = std::chrono::steady_clock::now();
        }
    };
    
    PerformanceMetrics current_metrics_;
    std::deque<double> frame_time_history_;
    std::deque<double> detection_time_history_;
    
    // Adaptive parameters
    int current_quality_level_ = 3;
    cv::Size current_detection_size_ = cv::Size(416, 416);
    int current_skip_frames_ = 0;
    
    // Performance targets
    double target_fps_ = 60.0;
    double max_cpu_usage_ = 80.0;
    double max_frame_time_ = 16.67; // ~60 FPS
    
    mutable std::mutex metrics_mutex_;
    std::chrono::steady_clock::time_point last_optimization_;
    
public:
    PerformanceOptimizer() {
        last_optimization_ = std::chrono::steady_clock::now();
    }
    
    void recordFrameTime(double time_ms) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        frame_time_history_.push_back(time_ms);
        if (frame_time_history_.size() > 100) {
            frame_time_history_.pop_front();
        }
        
        updateAverages();
        current_metrics_.frames_processed++;
    }
    
    void recordDetectionTime(double time_ms) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        detection_time_history_.push_back(time_ms);
        if (detection_time_history_.size() > 50) {
            detection_time_history_.pop_front();
        }
        
        updateAverages();
    }
    
    void recordCPUUsage(double cpu_percent) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        current_metrics_.cpu_usage = cpu_percent;
    }
    
    struct OptimizationRecommendations {
        bool should_reduce_quality = false;
        bool should_increase_quality = false;
        bool should_skip_frames = false;
        bool should_reduce_detection_size = false;
        
        int recommended_quality_level = 3;
        cv::Size recommended_detection_size = cv::Size(416, 416);
        int recommended_skip_frames = 0;
        
        double performance_score = 1.0; // 0-1, higher is better
    };
    
    OptimizationRecommendations getRecommendations() {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - last_optimization_).count();
        
        OptimizationRecommendations recommendations;
        
        // Only optimize every few seconds to avoid oscillations
        if (elapsed < 3) {
            recommendations.recommended_quality_level = current_quality_level_;
            recommendations.recommended_detection_size = current_detection_size_;
            recommendations.recommended_skip_frames = current_skip_frames_;
            return recommendations;
        }
        
        last_optimization_ = now;
        
        // Calculate performance score
        double fps_score = std::min(1.0, getCurrentFPS() / target_fps_);
        double cpu_score = std::max(0.0, 1.0 - (current_metrics_.cpu_usage / max_cpu_usage_));
        double latency_score = std::max(0.0, 1.0 - (current_metrics_.avg_frame_time / max_frame_time_));
        
        recommendations.performance_score = (fps_score + cpu_score + latency_score) / 3.0;
        
        // Determine optimization actions
        if (recommendations.performance_score < 0.7) {
            // Performance is poor, need to optimize
            recommendations.should_reduce_quality = true;
            
            if (current_quality_level_ > 1) {
                recommendations.recommended_quality_level = current_quality_level_ - 1;
            }
            
            if (current_detection_size_.width > 320) {
                recommendations.recommended_detection_size = cv::Size(
                    current_detection_size_.width * 0.8,
                    current_detection_size_.height * 0.8
                );
                recommendations.should_reduce_detection_size = true;
            }
            
            if (current_skip_frames_ < 2) {
                recommendations.recommended_skip_frames = current_skip_frames_ + 1;
                recommendations.should_skip_frames = true;
            }
            
        } else if (recommendations.performance_score > 0.9 && current_quality_level_ < 5) {
            // Performance is good, can increase quality
            recommendations.should_increase_quality = true;
            recommendations.recommended_quality_level = current_quality_level_ + 1;
            
            if (current_skip_frames_ > 0) {
                recommendations.recommended_skip_frames = current_skip_frames_ - 1;
            }
        }
        
        return recommendations;
    }
    
    void applyOptimizations(const OptimizationRecommendations& recommendations) {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        
        if (recommendations.should_reduce_quality || recommendations.should_increase_quality) {
            current_quality_level_ = recommendations.recommended_quality_level;
        }
        
        if (recommendations.should_reduce_detection_size) {
            current_detection_size_ = recommendations.recommended_detection_size;
        }
        
        if (recommendations.should_skip_frames) {
            current_skip_frames_ = recommendations.recommended_skip_frames;
        }
    }
    
    double getCurrentFPS() const {
        if (current_metrics_.avg_frame_time <= 0) return 0.0;
        return 1000.0 / current_metrics_.avg_frame_time;
    }
    
    PerformanceMetrics getMetrics() const {
        std::lock_guard<std::mutex> lock(metrics_mutex_);
        return current_metrics_;
    }
    
private:
    void updateAverages() {
        if (!frame_time_history_.empty()) {
            double sum = std::accumulate(frame_time_history_.begin(), frame_time_history_.end(), 0.0);
            current_metrics_.avg_frame_time = sum / frame_time_history_.size();
        }
        
        if (!detection_time_history_.empty()) {
            double sum = std::accumulate(detection_time_history_.begin(), detection_time_history_.end(), 0.0);
            current_metrics_.avg_detection_time = sum / detection_time_history_.size();
        }
        
        current_metrics_.last_update = std::chrono::steady_clock::now();
    }
};

// Enhanced Configuration System with validation and profiles
class EnhancedConfigManager {
public:
    struct AimConfig {
        bool enabled = false;
        double smoothing_factor = 8.0;
        double prediction_strength = 0.3;
        double fov_radius = 100.0;
        double reaction_time_ms = 180.0;
        bool human_like_movement = true;
        bool adaptive_smoothing = true;
        
        enum class TargetPriority {
            CLOSEST, HIGHEST_CONFIDENCE, BEST_ANGLE, MOST_VULNERABLE
        } target_priority = TargetPriority::BEST_ANGLE;
        
        enum class MovementStyle {
            PRECISE, SMOOTH, HUMAN_LIKE, ADAPTIVE
        } movement_style = MovementStyle::ADAPTIVE;
        
        void validate() {
            smoothing_factor = std::clamp(smoothing_factor, 1.0, 20.0);
            prediction_strength = std::clamp(prediction_strength, 0.0, 1.0);
            fov_radius = std::clamp(fov_radius, 10.0, 500.0);
            reaction_time_ms = std::clamp(reaction_time_ms, 50.0, 1000.0);
        }
    };
    
    struct DetectionConfig {
        bool enabled = true;
        float confidence_threshold = 0.6f;
        float nms_threshold = 0.4f;
        cv::Size detection_size = cv::Size(416, 416);
        bool multi_scale_detection = true;
        bool use_gpu = false;
        int max_targets = 10;
        
        void validate() {
            confidence_threshold = std::clamp(confidence_threshold, 0.1f, 1.0f);
            nms_threshold = std::clamp(nms_threshold, 0.1f, 1.0f);
            max_targets = std::clamp(max_targets, 1, 50);
            
            // Ensure detection size is reasonable
            detection_size.width = std::clamp(detection_size.width, 320, 1024);
            detection_size.height = std::clamp(detection_size.height, 320, 1024);
        }
    };
    
    struct PerformanceConfig {
        int target_fps = 60;
        double max_cpu_usage = 80.0;
        bool adaptive_quality = true;
        bool enable_multithreading = true;
        int detection_threads = 2;
        bool enable_frame_skipping = true;
        
        void validate() {
            target_fps = std::clamp(target_fps, 15, 144);
            max_cpu_usage = std::clamp(max_cpu_usage, 30.0, 95.0);
            detection_threads = std::clamp(detection_threads, 1, 8);
        }
    };
    
    struct SecurityConfig {
        bool stealth_mode = true;
        bool randomize_timings = true;
        bool anti_detection = true;
        bool process_hiding = true;
        int security_check_interval_seconds = 60;
        
        void validate() {
            security_check_interval_seconds = std::clamp(
                security_check_interval_seconds, 10, 300);
        }
    };
    
    struct ApplicationConfig {
        AimConfig aim;
        DetectionConfig detection;
        PerformanceConfig performance;
        SecurityConfig security;
        
        void validate() {
            aim.validate();
            detection.validate();
            performance.validate();
            security.validate();
        }
        
        bool isValid() const {
            return aim.fov_radius > 0 && detection.confidence_threshold > 0;
        }
    };
    
private:
    ApplicationConfig config_;
    std::string config_file_path_;
    mutable std::mutex config_mutex_;
    
    // Configuration profiles
    std::unordered_map<std::string, ApplicationConfig> saved_profiles_;
    
    // Encryption for sensitive settings
    static constexpr uint8_t ENCRYPTION_KEY[] = {
        0x4B, 0x65, 0x79, 0x20, 0x46, 0x6F, 0x72, 0x20, 
        0x43, 0x6F, 0x6E, 0x66, 0x69, 0x67, 0x20, 0x45
    };
    
public:
    EnhancedConfigManager() {
        config_file_path_ = getConfigFilePath();
        loadConfiguration();
        
        // Create default profiles
        createDefaultProfiles();
    }
    
    ApplicationConfig getConfig() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        return config_;
    }
    
    void updateConfig(const ApplicationConfig& new_config) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        ApplicationConfig validated_config = new_config;
        validated_config.validate();
        
        if (validated_config.isValid()) {
            config_ = validated_config;
            saveConfiguration();
        }
    }
    
    bool saveProfile(const std::string& profile_name, const ApplicationConfig& config) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        ApplicationConfig validated_config = config;
        validated_config.validate();
        
        if (validated_config.isValid()) {
            saved_profiles_[profile_name] = validated_config;
            return saveProfilesToFile();
        }
        
        return false;
    }
    
    bool loadProfile(const std::string& profile_name) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        auto it = saved_profiles_.find(profile_name);
        if (it != saved_profiles_.end()) {
            config_ = it->second;
            saveConfiguration();
            return true;
        }
        
        return false;
    }
    
    std::vector<std::string> getAvailableProfiles() const {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        std::vector<std::string> profile_names;
        for (const auto& [name, config] : saved_profiles_) {
            profile_names.push_back(name);
        }
        
        return profile_names;
    }
    
    bool deleteProfile(const std::string& profile_name) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        
        auto erased = saved_profiles_.erase(profile_name);
        if (erased > 0) {
            saveProfilesToFile();
            return true;
        }
        
        return false;
    }
    
private:
    std::string getConfigFilePath() {
        char temp_path[MAX_PATH];
        GetTempPathA(sizeof(temp_path), temp_path);
        
        // Generate unique filename based on system info
        DWORD session_id;
        ProcessIdToSessionId(GetCurrentProcessId(), &session_id);
        
        std::ostringstream filename;
        filename << "sys_" << std::hex << session_id << "_" 
                << GetCurrentProcessId() << ".tmp";
        
        return std::string(temp_path) + "\\" + filename.str();
    }
    
    void loadConfiguration() {
        if (std::filesystem::exists(config_file_path_)) {
            if (loadFromFile(config_file_path_)) {
                return;
            }
        }
        
        // Load defaults
        config_ = createDefaultConfig();
    }
    
    void saveConfiguration() {
        saveToFile(config_file_path_);
    }
    
    bool loadFromFile(const std::string& file_path) {
        try {
            std::ifstream file(file_path, std::ios::binary);
            if (!file.is_open()) return false;
            
            // Read and decrypt file content
            std::vector<uint8_t> encrypted_data(
                (std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());
            
            std::vector<uint8_t> decrypted_data = decrypt(encrypted_data);
            
            // Parse configuration from decrypted data
            return parseConfigFromData(decrypted_data);
            
        } catch (const std::exception&) {
            return false;
        }
    }
    
    bool saveToFile(const std::string& file_path) {
        try {
            std::vector<uint8_t> config_data = serializeConfig();
            std::vector<uint8_t> encrypted_data = encrypt(config_data);
            
            std::ofstream file(file_path, std::ios::binary);
            if (!file.is_open()) return false;
            
            file.write(reinterpret_cast<const char*>(encrypted_data.data()),
                      encrypted_data.size());
            
            return file.good();
            
        } catch (const std::exception&) {
            return false;
        }
    }
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> encrypted = data;
        
        for (size_t i = 0; i < encrypted.size(); ++i) {
            encrypted[i] ^= ENCRYPTION_KEY[i % sizeof(ENCRYPTION_KEY)];
            encrypted[i] = static_cast<uint8_t>((encrypted[i] << 3) | (encrypted[i] >> 5));
        }
        
        return encrypted;
    }
    
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> decrypted = data;
        
        for (size_t i = 0; i < decrypted.size(); ++i) {
            decrypted[i] = static_cast<uint8_t>((decrypted[i] >> 3) | (decrypted[i] << 5));
            decrypted[i] ^= ENCRYPTION_KEY[i % sizeof(ENCRYPTION_KEY)];
        }
        
        return decrypted;
    }
    
    std::vector<uint8_t> serializeConfig() {
        std::ostringstream oss;
        
        // Serialize aim config
        oss << "[AIM]\n";
        oss << "enabled=" << config_.aim.enabled << "\n";
        oss << "smoothing_factor=" << config_.aim.smoothing_factor << "\n";
        oss << "prediction_strength=" << config_.aim.prediction_strength << "\n";
        oss << "fov_radius=" << config_.aim.fov_radius << "\n";
        oss << "reaction_time_ms=" << config_.aim.reaction_time_ms << "\n";
        oss << "human_like_movement=" << config_.aim.human_like_movement << "\n";
        oss << "adaptive_smoothing=" << config_.aim.adaptive_smoothing << "\n";
        oss << "target_priority=" << static_cast<int>(config_.aim.target_priority) << "\n";
        oss << "movement_style=" << static_cast<int>(config_.aim.movement_style) << "\n";
        
        // Serialize detection config
        oss << "[DETECTION]\n";
        oss << "enabled=" << config_.detection.enabled << "\n";
        oss << "confidence_threshold=" << config_.detection.confidence_threshold << "\n";
        oss << "nms_threshold=" << config_.detection.nms_threshold << "\n";
        oss << "detection_width=" << config_.detection.detection_size.width << "\n";
        oss << "detection_height=" << config_.detection.detection_size.height << "\n";
        oss << "multi_scale_detection=" << config_.detection.multi_scale_detection << "\n";
        oss << "use_gpu=" << config_.detection.use_gpu << "\n";
        oss << "max_targets=" << config_.detection.max_targets << "\n";
        
        // Serialize performance config
        oss << "[PERFORMANCE]\n";
        oss << "target_fps=" << config_.performance.target_fps << "\n";
        oss << "max_cpu_usage=" << config_.performance.max_cpu_usage << "\n";
        oss << "adaptive_quality=" << config_.performance.adaptive_quality << "\n";
        oss << "enable_multithreading=" << config_.performance.enable_multithreading << "\n";
        oss << "detection_threads=" << config_.performance.detection_threads << "\n";
        oss << "enable_frame_skipping=" << config_.performance.enable_frame_skipping << "\n";
        
        // Serialize security config
        oss << "[SECURITY]\n";
        oss << "stealth_mode=" << config_.security.stealth_mode << "\n";
        oss << "randomize_timings=" << config_.security.randomize_timings << "\n";
        oss << "anti_detection=" << config_.security.anti_detection << "\n";
        oss << "process_hiding=" << config_.security.process_hiding << "\n";
        oss << "security_check_interval_seconds=" << config_.security.security_check_interval_seconds << "\n";
        
        std::string str = oss.str();
        return std::vector<uint8_t>(str.begin(), str.end());
    }
    
    bool parseConfigFromData(const std::vector<uint8_t>& data) {
        std::string content(data.begin(), data.end());
        std::istringstream iss(content);
        std::string line;
        std::string current_section;
        
        ApplicationConfig new_config = createDefaultConfig();
        
        while (std::getline(iss, line)) {
            // Remove whitespace
            line.erase(line.find_last_not_of(" \t\r\n") + 1);
            if (line.empty() || line[0] == '#') continue;
            
            // Check for section headers
            if (line.front() == '[' && line.back() == ']') {
                current_section = line.substr(1, line.length() - 2);
                continue;
            }
            
            // Parse key-value pairs
            size_t eq_pos = line.find('=');
            if (eq_pos == std::string::npos) continue;
            
            std::string key = line.substr(0, eq_pos);
            std::string value = line.substr(eq_pos + 1);
            
            if (!parseKeyValue(current_section, key, value, new_config)) {
                return false; // Invalid configuration
            }
        }
        
        new_config.validate();
        if (new_config.isValid()) {
            config_ = new_config;
            return true;
        }
        
        return false;
    }
    
    bool parseKeyValue(const std::string& section, const std::string& key, 
                      const std::string& value, ApplicationConfig& config) {
        try {
            if (section == "AIM") {
                if (key == "enabled") config.aim.enabled = (value == "1" || value == "true");
                else if (key == "smoothing_factor") config.aim.smoothing_factor = std::stod(value);
                else if (key == "prediction_strength") config.aim.prediction_strength = std::stod(value);
                else if (key == "fov_radius") config.aim.fov_radius = std::stod(value);
                else if (key == "reaction_time_ms") config.aim.reaction_time_ms = std::stod(value);
                else if (key == "human_like_movement") config.aim.human_like_movement = (value == "1" || value == "true");
                else if (key == "adaptive_smoothing") config.aim.adaptive_smoothing = (value == "1" || value == "true");
                else if (key == "target_priority") config.aim.target_priority = static_cast<AimConfig::TargetPriority>(std::stoi(value));
                else if (key == "movement_style") config.aim.movement_style = static_cast<AimConfig::MovementStyle>(std::stoi(value));
            }
            else if (section == "DETECTION") {
                if (key == "enabled") config.detection.enabled = (value == "1" || value == "true");
                else if (key == "confidence_threshold") config.detection.confidence_threshold = std::stof(value);
                else if (key == "nms_threshold") config.detection.nms_threshold = std::stof(value);
                else if (key == "detection_width") config.detection.detection_size.width = std::stoi(value);
                else if (key == "detection_height") config.detection.detection_size.height = std::stoi(value);
                else if (key == "multi_scale_detection") config.detection.multi_scale_detection = (value == "1" || value == "true");
                else if (key == "use_gpu") config.detection.use_gpu = (value == "1" || value == "true");
                else if (key == "max_targets") config.detection.max_targets = std::stoi(value);
            }
            else if (section == "PERFORMANCE") {
                if (key == "target_fps") config.performance.target_fps = std::stoi(value);
                else if (key == "max_cpu_usage") config.performance.max_cpu_usage = std::stod(value);
                else if (key == "adaptive_quality") config.performance.adaptive_quality = (value == "1" || value == "true");
                else if (key == "enable_multithreading") config.performance.enable_multithreading = (value == "1" || value == "true");
                else if (key == "detection_threads") config.performance.detection_threads = std::stoi(value);
                else if (key == "enable_frame_skipping") config.performance.enable_frame_skipping = (value == "1" || value == "true");
            }
            else if (section == "SECURITY") {
                if (key == "stealth_mode") config.security.stealth_mode = (value == "1" || value == "true");
                else if (key == "randomize_timings") config.security.randomize_timings = (value == "1" || value == "true");
                else if (key == "anti_detection") config.security.anti_detection = (value == "1" || value == "true");
                else if (key == "process_hiding") config.security.process_hiding = (value == "1" || value == "true");
                else if (key == "security_check_interval_seconds") config.security.security_check_interval_seconds = std::stoi(value);
            }
            
            return true;
            
        } catch (const std::exception&) {
            return false;
        }
    }
    
    ApplicationConfig createDefaultConfig() {
        ApplicationConfig config;
        
        // Set reasonable defaults
        config.aim.enabled = false;
        config.aim.smoothing_factor = 8.0;
        config.aim.prediction_strength = 0.3;
        config.aim.fov_radius = 100.0;
        config.aim.reaction_time_ms = 180.0;
        config.aim.human_like_movement = true;
        config.aim.adaptive_smoothing = true;
        
        config.detection.enabled = true;
        config.detection.confidence_threshold = 0.6f;
        config.detection.nms_threshold = 0.4f;
        config.detection.detection_size = cv::Size(416, 416);
        config.detection.multi_scale_detection = true;
        config.detection.use_gpu = false;
        config.detection.max_targets = 10;
        
        config.performance.target_fps = 60;
        config.performance.max_cpu_usage = 80.0;
        config.performance.adaptive_quality = true;
        config.performance.enable_multithreading = true;
        config.performance.detection_threads = 2;
        config.performance.enable_frame_skipping = true;
        
        config.security.stealth_mode = true;
        config.security.randomize_timings = true;
        config.security.anti_detection = true;
        config.security.process_hiding = true;
        config.security.security_check_interval_seconds = 60;
        
        return config;
    }
    
    void createDefaultProfiles() {
        // High Performance Profile
        ApplicationConfig high_perf = createDefaultConfig();
        high_perf.performance.target_fps = 120;
        high_perf.performance.detection_threads = 4;
        high_perf.detection.detection_size = cv::Size(320, 320);
        high_perf.aim.smoothing_factor = 6.0;
        saved_profiles_["High Performance"] = high_perf;
        
        // High Precision Profile
        ApplicationConfig high_precision = createDefaultConfig();
        high_precision.aim.smoothing_factor = 12.0;
        high_precision.aim.prediction_strength = 0.5;
        high_precision.detection.confidence_threshold = 0.8f;
        high_precision.detection.detection_size = cv::Size(512, 512);
        high_precision.performance.target_fps = 60;
        saved_profiles_["High Precision"] = high_precision;
        
        // Stealth Profile
        ApplicationConfig stealth = createDefaultConfig();
        stealth.security.stealth_mode = true;
        stealth.security.randomize_timings = true;
        stealth.security.security_check_interval_seconds = 30;
        stealth.aim.human_like_movement = true;
        stealth.aim.reaction_time_ms = 220.0;
        stealth.performance.target_fps = 60;
        saved_profiles_["Stealth"] = stealth;
        
        // Balanced Profile (default)
        ApplicationConfig balanced = createDefaultConfig();
        saved_profiles_["Balanced"] = balanced;
    }
    
    bool saveProfilesToFile() {
        // Implementation would save profiles to a separate file
        return true;
    }
};

// Main Application Class with all enhancements
class EnhancedAimApplication {
private:
    // Core components
    std::unique_ptr<EnhancedDetectionEngine> detection_engine_;
    std::unique_ptr<SmartMovementController> movement_controller_;
    std::unique_ptr<PerformanceOptimizer> performance_optimizer_;
    std::unique_ptr<EnhancedConfigManager> config_manager_;
    
    // Threading
    std::thread detection_thread_;
    std::thread movement_thread_;
    std::thread performance_thread_;
    std::atomic<bool> running_{true};
    
    // Synchronization
    std::mutex frame_mutex_;
    std::mutex targets_mutex_;
    std::condition_variable frame_cv_;
    
    // Current state
    cv::Mat current_frame_;
    std::vector<EnhancedTargetInfo> current_targets_;
    EnhancedTargetInfo selected_target_;
    bool has_selected_target_ = false;
    
    // Performance monitoring
    std::chrono::steady_clock::time_point last_frame_time_;
    std::atomic<bool> frame_ready_{false};
    
    // Input state
    std::atomic<bool> aim_active_{false};
    std::atomic<bool> left_mouse_pressed_{false};
    
public:
    EnhancedAimApplication() {
        initializeComponents();
        startThreads();
    }
    
    ~EnhancedAimApplication() {
        shutdown();
    }
    
    bool initialize(const std::string& model_path) {
        auto config = config_manager_->getConfig();
        
        // Initialize detection engine
        if (!detection_engine_->initialize(model_path, config.detection.use_gpu)) {
            return false;
        }
        
        // Configure detection engine
        detection_engine_->setConfidenceThreshold(config.detection.confidence_threshold);
        detection_engine_->setNMSThreshold(config.detection.nms_threshold);
        
        // Configure movement controller
        SmartMovementController::MovementParams movement_params;
        movement_params.base_smoothing = config.aim.smoothing_factor;
        movement_params.adaptive_smoothing = config.aim.adaptive_smoothing;
        movement_params.human_factor = config.aim.human_like_movement ? 0.3 : 0.0;
        
        switch (config.aim.movement_style) {
            case EnhancedConfigManager::AimConfig::MovementStyle::PRECISE:
                movement_params.style = SmartMovementController::MovementParams::Style::PRECISE;
                break;
            case EnhancedConfigManager::AimConfig::MovementStyle::SMOOTH:
                movement_params.style = SmartMovementController::MovementParams::Style::SMOOTH;
                break;
            case EnhancedConfigManager::AimConfig::MovementStyle::HUMAN_LIKE:
                movement_params.style = SmartMovementController::MovementParams::Style::HUMAN_LIKE;
                break;
            case EnhancedConfigManager::AimConfig::MovementStyle::ADAPTIVE:
                movement_params.style = SmartMovementController::MovementParams::Style::ADAPTIVE;
                break;
        }
        
        movement_controller_->updateParams(movement_params);
        
        return true;
    }
    
    void updateConfiguration(const EnhancedConfigManager::ApplicationConfig& config) {
        config_manager_->updateConfig(config);
        
        // Update components with new configuration
        detection_engine_->setConfidenceThreshold(config.detection.confidence_threshold);
        detection_engine_->setNMSThreshold(config.detection.nms_threshold);
        
        // Update movement controller
        SmartMovementController::MovementParams movement_params;
        movement_params.base_smoothing = config.aim.smoothing_factor;
        movement_params.adaptive_smoothing = config.aim.adaptive_smoothing;
        movement_params.human_factor = config.aim.human_like_movement ? 0.3 : 0.0;
        
        movement_controller_->updateParams(movement_params);
    }
    
    void setAimActive(bool active) {
        aim_active_ = active;
    }
    
    void setLeftMousePressed(bool pressed) {
        left_mouse_pressed_ = pressed;
    }
    
    EnhancedConfigManager::ApplicationConfig getCurrentConfig() const {
        return config_manager_->getConfig();
    }
    
    PerformanceOptimizer::PerformanceMetrics getPerformanceMetrics() const {
        return performance_optimizer_->getMetrics();
    }
    
    std::vector<std::string> getAvailableProfiles() const {
        return config_manager_->getAvailableProfiles();
    }
    
    bool loadProfile(const std::string& profile_name) {
        return config_manager_->loadProfile(profile_name);
    }
    
    bool saveProfile(const std::string& profile_name) {
        auto current_config = config_manager_->getConfig();
        return config_manager_->saveProfile(profile_name, current_config);
    }
    
private:
    void initializeComponents() {
        detection_engine_ = std::make_unique<EnhancedDetectionEngine>();
        movement_controller_ = std::make_unique<SmartMovementController>();
        performance_optimizer_ = std::make_unique<PerformanceOptimizer>();
        config_manager_ = std::make_unique<EnhancedConfigManager>();
        
        last_frame_time_ = std::chrono::steady_clock::now();
    }
    
    void startThreads() {
        // Start detection thread
        detection_thread_ = std::thread([this]() {
            detectionLoop();
        });
        
        // Start movement thread
        movement_thread_ = std::thread([this]() {
            movementLoop();
        });
        
        // Start performance monitoring thread
        performance_thread_ = std::thread([this]() {
            performanceLoop();
        });
    }
    
    void detectionLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_NORMAL);
        
        while (running_) {
            try {
                auto config = config_manager_->getConfig();
                
                if (!config.detection.enabled) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }
                
                // Capture screen
                cv::Mat frame = captureScreen();
                if (frame.empty()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(16));
                    continue;
                }
                
                auto detection_start = std::chrono::high_resolution_clock::now();
                
                // Detect targets
                std::vector<EnhancedTargetInfo> targets = detection_engine_->detectTargets(frame);
                
                auto detection_end = std::chrono::high_resolution_clock::now();
                auto detection_time = std::chrono::duration<double, std::milli>(
                    detection_end - detection_start).count();
                
                performance_optimizer_->recordDetectionTime(detection_time);
                
                // Update current targets
                {
                    std::lock_guard<std::mutex> lock(targets_mutex_);
                    current_targets_ = std::move(targets);
                    
                    // Select best target
                    selectBestTarget();
                }
                
                // Update frame
                {
                    std::lock_guard<std::mutex> lock(frame_mutex_);
                    current_frame_ = std::move(frame);
                    frame_ready_ = true;
                }
                frame_cv_.notify_one();
                
                // Adaptive frame rate
                auto target_frame_time = std::chrono::milliseconds(
                    1000 / config.performance.target_fps);
                std::this_thread::sleep_for(target_frame_time);
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
    
    void movementLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
        
        auto last_update = std::chrono::high_resolution_clock::now();
        
        while (running_) {
            try {
                auto config = config_manager_->getConfig();
                
                if (!config.aim.enabled || !aim_active_) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                
                auto now = std::chrono::high_resolution_clock::now();
                double dt = std::chrono::duration<double>(now - last_update).count();
                last_update = now;
                
                // Get current mouse position
                POINT cursor_pos;
                GetCursorPos(&cursor_pos);
                MathUtils::Vector2D current_mouse(cursor_pos.x, cursor_pos.y);
                
                // Check if we have a target
                EnhancedTargetInfo target;
                bool has_target = false;
                
                {
                    std::lock_guard<std::mutex> lock(targets_mutex_);
                    if (has_selected_target_) {
                        target = selected_target_;
                        has_target = true;
                    }
                }
                
                if (has_target) {
                    // Calculate aim point
                    MathUtils::Vector2D aim_point = calculateAimPoint(target, config);
                    
                    // Check if target is within FOV
                    double distance_to_target = (aim_point - current_mouse).magnitude();
                    
                    if (distance_to_target <= config.aim.fov_radius) {
                        // Set target for movement controller
                        movement_controller_->setTarget(aim_point);
                        
                        // Get movement and apply it
                        MathUtils::Vector2D movement = movement_controller_->getNextMovement(dt);
                        
                        if (movement.magnitude() > 0.01) {
                            applyMouseMovement(movement);
                        }
                    }
                }
                
                // High frequency updates for smooth movement
                std::this_thread::sleep_for(std::chrono::microseconds(500)); // 2000 Hz
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }
    }
    
    void performanceLoop() {
        SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_LOWEST);
        
        while (running_) {
            try {
                // Record frame time
                auto now = std::chrono::steady_clock::now();
                auto frame_time = std::chrono::duration<double, std::milli>(
                    now - last_frame_time_).count();
                
                performance_optimizer_->recordFrameTime(frame_time);
                last_frame_time_ = now;
                
                // Get optimization recommendations
                auto recommendations = performance_optimizer_->getRecommendations();
                
                // Apply optimizations if needed
                if (recommendations.should_reduce_quality || 
                    recommendations.should_increase_quality) {
                    
                    auto config = config_manager_->getConfig();
                    
                    // Adjust detection size
                    if (recommendations.should_reduce_detection_size) {
                        config.detection.detection_size = recommendations.recommended_detection_size;
                    }
                    
                    // Update configuration
                    updateConfiguration(config);
                    
                    performance_optimizer_->applyOptimizations(recommendations);
                }
                
                // Update CPU usage
                performance_optimizer_->recordCPUUsage(getCurrentCPUUsage());
                
                std::this_thread::sleep_for(std::chrono::seconds(1));
                
            } catch (const std::exception& e) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
    
    cv::Mat captureScreen() {
        // Get screen DC
        HDC screen_dc = GetDC(nullptr);
        if (!screen_dc) return cv::Mat();
        
        // Get screen dimensions
        int width = GetSystemMetrics(SM_CXSCREEN);
        int height = GetSystemMetrics(SM_CYSCREEN);
        
        // Create compatible DC and bitmap
        HDC mem_dc = CreateCompatibleDC(screen_dc);
        HBITMAP bitmap = CreateCompatibleBitmap(screen_dc, width, height);
        HGDIOBJ old_bitmap = SelectObject(mem_dc, bitmap);
        
        // Copy screen to bitmap
        BitBlt(mem_dc, 0, 0, width, height, screen_dc, 0, 0, SRCCOPY);
        
        // Convert to OpenCV Mat
        BITMAPINFOHEADER bi = {};
        bi.biSize = sizeof(BITMAPINFOHEADER);
        bi.biWidth = width;
        bi.biHeight = -height; // Top-down DIB
        bi.biPlanes = 1;
        bi.biBitCount = 24;
        bi.biCompression = BI_RGB;
        
        cv::Mat result(height, width, CV_8UC3);
        GetDIBits(mem_dc, bitmap, 0, height, result.data, 
                 reinterpret_cast<BITMAPINFO*>(&bi), DIB_RGB_COLORS);
        
        // Convert BGR to RGB
        cv::cvtColor(result, result, cv::COLOR_BGR2RGB);
        
        // Cleanup
        SelectObject(mem_dc, old_bitmap);
        DeleteObject(bitmap);
        DeleteDC(mem_dc);
        ReleaseDC(nullptr, screen_dc);
        
        return result;
    }
    
    void selectBestTarget() {
        if (current_targets_.empty()) {
            has_selected_target_ = false;
            return;
        }
        
        auto config = config_manager_->getConfig();
        
        // Get current mouse position for distance calculations
        POINT cursor_pos;
        GetCursorPos(&cursor_pos);
        MathUtils::Vector2D mouse_pos(cursor_pos.x, cursor_pos.y);
        
        EnhancedTargetInfo best_target;
        double best_score = -1.0;
        
        for (const auto& target : current_targets_) {
            double score = calculateTargetScore(target, mouse_pos, config);
            
            if (score > best_score) {
                best_score = score;
                best_target = target;
            }
        }
        
        if (best_score > 0.0) {
            selected_target_ = best_target;
            has_selected_target_ = true;
        } else {
            has_selected_target_ = false;
        }
    }
    
    double calculateTargetScore(const EnhancedTargetInfo& target, 
                               const MathUtils::Vector2D& mouse_pos,
                               const EnhancedConfigManager::ApplicationConfig& config) {
        
        // Calculate distance score (closer is better)
        double distance = (MathUtils::Vector2D(target.position.x, target.position.y) - mouse_pos).magnitude();
        double distance_score = 1.0 / (1.0 + distance / 100.0);
        
        // Calculate confidence score
        double confidence_score = target.confidence;
        
        // Calculate stability score
        double stability_score = target.stability_score;
        
        // Calculate size score (larger targets are easier to hit)
        double target_area = target.bounding_box.width * target.bounding_box.height;
        double size_score = std::min(1.0, target_area / 10000.0);
        
        // Calculate movement predictability score
        double predictability_score = target.movement_predictability;
        
        // Combine scores based on target priority
        double final_score = 0.0;
        
        switch (config.aim.target_priority) {
            case EnhancedConfigManager::AimConfig::TargetPriority::CLOSEST:
                final_score = distance_score * 0.6 + confidence_score * 0.4;
                break;
                
            case EnhancedConfigManager::AimConfig::TargetPriority::HIGHEST_CONFIDENCE:
                final_score = confidence_score * 0.6 + distance_score * 0.4;
                break;
                
            case EnhancedConfigManager::AimConfig::TargetPriority::BEST_ANGLE:
                final_score = distance_score * 0.3 + confidence_score * 0.3 + 
                             stability_score * 0.2 + predictability_score * 0.2;
                break;
                
            case EnhancedConfigManager::AimConfig::TargetPriority::MOST_VULNERABLE:
                final_score = confidence_score * 0.25 + stability_score * 0.25 + 
                             size_score * 0.25 + predictability_score * 0.25;
                break;
        }
        
        return final_score;
    }
    
    MathUtils::Vector2D calculateAimPoint(const EnhancedTargetInfo& target,
                                         const EnhancedConfigManager::ApplicationConfig& config) {
        
        // Base aim point
        MathUtils::Vector2D aim_point(target.position.x, target.position.y);
        
        // Apply prediction if enabled
        if (config.aim.prediction_strength > 0.0) {
            MathUtils::Vector2D predicted_offset(
                target.velocity.x * config.aim.prediction_strength,
                target.velocity.y * config.aim.prediction_strength
            );
            
            aim_point = aim_point + predicted_offset;
        }
        
        // Apply body part targeting
        if (target.head_region.width > 0 && target.head_region.height > 0) {
            // Prefer head shots for better accuracy
            aim_point = MathUtils::Vector2D(
                target.head_region.x + target.head_region.width / 2,
                target.head_region.y + target.head_region.height / 2
            );
        } else if (target.chest_region.width > 0 && target.chest_region.height > 0) {
            // Fall back to chest
            aim_point = MathUtils::Vector2D(
                target.chest_region.x + target.chest_region.width / 2,
                target.chest_region.y + target.chest_region.height / 2
            );
        }
        
        return aim_point;
    }
    
    void applyMouseMovement(const MathUtils::Vector2D& movement) {
        // Use SendInput for smooth, undetectable mouse movement
        INPUT input = {};
        input.type = INPUT_MOUSE;
        input.mi.dx = static_cast<LONG>(std::round(movement.x));
        input.mi.dy = static_cast<LONG>(std::round(movement.y));
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        input.mi.time = 0;
        input.mi.dwExtraInfo = 0;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    double getCurrentCPUUsage() {
        static ULARGE_INTEGER last_cpu, last_sys_cpu, last_user_cpu;
        static DWORD num_processors = 0;
        static bool first_call = true;
        
        if (first_call) {
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            num_processors = sys_info.dwNumberOfProcessors;
            
            FILETIME ftime, fsys, fuser;
            GetSystemTimeAsFileTime(&ftime);
            memcpy(&last_cpu, &ftime, sizeof(FILETIME));
            
            GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
            memcpy(&last_sys_cpu, &fsys, sizeof(FILETIME));
            memcpy(&last_user_cpu, &fuser, sizeof(FILETIME));
            
            first_call = false;
            return 0.0;
        }
        
        FILETIME ftime, fsys, fuser;
        ULARGE_INTEGER now, sys, user;
        
        GetSystemTimeAsFileTime(&ftime);
        memcpy(&now, &ftime, sizeof(FILETIME));
        
        GetProcessTimes(GetCurrentProcess(), &ftime, &ftime, &fsys, &fuser);
        memcpy(&sys, &fsys, sizeof(FILETIME));
        memcpy(&user, &fuser, sizeof(FILETIME));
        
        double percent = static_cast<double>(sys.QuadPart - last_sys_cpu.QuadPart) + 
                        (user.QuadPart - last_user_cpu.QuadPart);
        percent /= (now.QuadPart - last_cpu.QuadPart);
        percent /= num_processors;
        
        last_cpu = now;
        last_user_cpu = user;
        last_sys_cpu = sys;
        
        return percent * 100.0;
    }
    
    void shutdown() {
        running_ = false;
        frame_cv_.notify_all();
        
        if (detection_thread_.joinable()) {
            detection_thread_.join();
        }
        if (movement_thread_.joinable()) {
            movement_thread_.join();
        }
        if (performance_thread_.joinable()) {
            performance_thread_.join();
        }
    }
};

// Example usage and main function
int main(int argc, char* argv[]) {
    try {
        // Initialize application
        EnhancedAimApplication app;
        
        // Initialize with model (example path)
        std::string model_path = "models/detection_model.onnx";
        if (!app.initialize(model_path)) {
            std::cerr << "Failed to initialize application with model: " << model_path << std::endl;
            return 1;
        }
        
        std::cout << "Enhanced Aim System initialized successfully!" << std::endl;
        std::cout << "Available profiles: ";
        auto profiles = app.getAvailableProfiles();
        for (const auto& profile : profiles) {
            std::cout << profile << " ";
        }
        std::cout << std::endl;
        
        // Example: Load a specific profile
        if (!profiles.empty()) {
            app.loadProfile(profiles[0]);
            std::cout << "Loaded profile: " << profiles[0] << std::endl;
        }
        
        // Main loop for handling input and monitoring
        bool running = true;
        while (running) {
            // Check for right mouse button (aim activation)
            if (GetAsyncKeyState(VK_RBUTTON) & 0x8000) {
                app.setAimActive(true);
            } else {
                app.setAimActive(false);
            }
            
            // Check for left mouse button (shooting)
            if (GetAsyncKeyState(VK_LBUTTON) & 0x8000) {
                app.setLeftMousePressed(true);
            } else {
                app.setLeftMousePressed(false);
            }
            
            // Check for exit key (ESC)
            if (GetAsyncKeyState(VK_ESCAPE) & 0x8000) {
                running = false;
            }
            
            // Print performance metrics every 5 seconds
            static auto last_metrics_print = std::chrono::steady_clock::now();
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_metrics_print).count() >= 5) {
                auto metrics = app.getPerformanceMetrics();
                std::cout << "Performance - FPS: " << (1000.0 / metrics.avg_frame_time) 
                         << ", Detection Time: " << metrics.avg_detection_time << "ms"
                         << ", CPU Usage: " << metrics.cpu_usage << "%" << std::endl;
                last_metrics_print = now;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        std::cout << "Application shutting down..." << std::endl;
        return 0;
        
    } catch (const std::exception& e) {
        std::cerr << "Application error: " << e.what() << std::endl;
        return 1;
    }
}