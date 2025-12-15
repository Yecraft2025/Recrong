const TRANSLATIONS = {
    zh: {
        // --- 通用 ---
        console: "控制台",
        settings: "设置",
        user_label: "当前用户",
        loading: "正在加载数据...",
        save_changes: "保存更改",
        discard: "放弃",
        cancel: "取消",
        confirm: "确认",
        back_dashboard: "返回主面板",

        // --- 错误与提示 ---
        msg_network_error: "请求失败，请检查网络连接。",
        msg_no_perm: "您当前无权执行此操作。",
        msg_unknown_user: "未知",
        msg_fill_incomplete: "请填写完整所有红色标记的区域",
        msg_save_success: "保存成功",
        msg_save_partial_fail: "部分保存失败: ",
        msg_changes: "变动: ",

        // --- Dashboard 表格 ---
        col_date: "提醒日期",
        col_cycle: "循环(天)",
        col_sender: "发送号码",
        col_content: "内容",
        col_status: "状态",
        col_del: "删除",
        status_running: "🟢 运行",
        status_stopped: "🔴 停止",

        // --- Dashboard 按钮 ---
        browser_timer: "定时器",
        trigger_now: "立即触发",
        new_task: "新建",

        // --- Dashboard 权限提示 ---
        msg_no_perm_view: "无权查看任务",
        msg_no_perm_add: "无权添加任务",
        msg_no_perm_del: "无权删除任务",
        msg_no_perm_edit: "无权修改数据",
        msg_confirm_del_title: "删除任务",
        msg_confirm_del_body: "确定要移除这行任务吗？保存后生效。",

        // --- 浏览器定时器 ---
        browser_timer_title: "浏览器定时发送",
        timer_warn_title: "⚠️ 重要提示：",
        timer_warn_list: `<li><b>临时性</b>：任务仅在当前页面运行，关闭或刷新页面即丢失。</li>
                          <li><b>本地化</b>：不会同步到服务器或其他设备。</li>
                          <li><b>依赖性</b>：执行时需保持登录状态且配额充足。</li>`,
        label_trigger_time: "触发时间:",
        label_sender: "发送号码:",
        label_content: "内容:",
        ph_from: "发送者号码...",
        ph_content: "提醒内容...",
        btn_start_timer: "启动定时任务",
        queue_title: "运行队列 (点击查看详情)",
        add_10s: "+10秒", add_30s: "+30秒", add_1m: "+1分", add_1h: "+1小时",
        msg_timer_fill_info: "请填写完整信息",
        msg_timer_future: "请选择未来的时间",
        msg_timer_queued: "定时任务已加入队列",
        msg_timer_success: "✅ 发送成功",
        msg_timer_failed: "❌ 发送失败",
        msg_timer_empty: "暂无运行中的任务",

        // --- 时间显示 ---
        time_overdue: "过期",
        time_today: "今天",
        time_tomorrow: "明天",
        time_day_after: "后天",
        time_days_later: "天后",
        time_stopped: "已停止",
        day: "天", hour: "时", min: "分", sec: "秒",

        // --- Settings 页面 ---
        settings_title: "设置",
        change_pwd_title: "修改密码",
        label_curr_pwd: "当前密码:",
        label_new_pwd: "新密码 (至少6位):",
        label_confirm_pwd: "确认新密码:",
        btn_confirm_change: "确认修改",
        account_actions: "账户操作",
        btn_logout: "退出登录",
        msg_pwd_mismatch: "两次输入的新密码不一致。",
        msg_saving: "处理中...",
        msg_success_redirect: "密码修改成功！正在跳转到登录页面...",
        msg_perm_denied_pwd: "您当前无权修改密码。",

        msg_trigger_success: "已触发服务器检查",
        msg_trigger_failed: "触发失败",
        msg_confirm_logout: "确定要退出登录吗？",

        verify_title: "验证并设置密码",
        msg_code_sent: "验证码已发送至: ",
        label_verify_code: "6位验证码",
        ph_verify_code: "输入短信验证码",
        label_set_pwd: "设置密码",
        ph_set_pwd: "输入新密码 (最少6位)",
        btn_complete_reg: "完成注册",
        msg_reg_success: "注册成功！正在跳转...",
        msg_reg_fail: "注册失败: ",
        msg_verify_invalid_phone: "无效的手机号码",
        ph_confirm_pwd: "再次输入密码",

        // Register Page
        register_title: "注册新账号",
        register_desc: "请输入您的短信 API [测试版] 链接以获取验证码。",
        label_sms_api: "短信 API 链接",
        ph_sms_api: "粘贴完整的 API 链接...",
        btn_get_code: "获取验证码",
        link_to_login: "已有账号？去登录",
        msg_api_fmt_err: "API 格式错误，请检查链接格式。",
        msg_num_mismatch: "链接中的 send 号码与 from 号码必须一致。",
        msg_requesting_code: "正在请求发送验证码...",
        msg_redirect_login: "账号已存在，正在跳转登录...",
        msg_redirect_verify: "验证码有效中，正在跳转验证...",
        label_agree: "我已阅读并同意",
        link_tos: "用户协议与隐私政策",
        msg_must_agree: "请先勾选同意用户协议与隐私政策",
        link_how_to_get: "如何获取 API？",

        // Login Page
        login_title: "登录",
        login_subtitle: "欢迎回来，请输入您的账号信息。",
        label_phone: "手机号码",
        ph_phone: "请输入 372 开头的号码",
        btn_login: "登录",
        link_no_account: "没有账号？去注册",
        msg_login_success: "登录成功，正在跳转...",
        link_how_to_get_num: "如何获取号码？",
        msg_invalid_phone_fmt: "号码格式错误!",
        btn_home: "首页",

        // Index Page
        kb_tutorial: "📖 教程",
        kb_go: "发送",

        // --- API Error Codes ---
        INVALID_VERIFY_CODE: "验证码错误或已过期",
        VERIFY_ENV_MISMATCH: "验证环境发生变化，请重新获取验证码",
        USER_ALREADY_EXISTS: "该手机号已被注册",
        INTERNAL_SERVER_ERROR: "服务器内部错误",
        BAD_REQUEST: "请求信息不完整",
        LOGIN_FAILED: "用户或密码错误",
        PERMISSION_DENIED_LOGIN: "您的账户已被禁止登录",
        LOGIN_LIMIT_EXCEEDED: "超出每周最大登录次数限制",
        SESSION_LIMIT_EXCEEDED: "已达到最大会话数，请先从其他设备登出",
        PERMISSION_DENIED_PWD: "无权修改密码",
        INVALID_PWD_FORMAT: "信息不完整或新密码少于6位",
        INVALID_CURRENT_PWD: "当前密码错误",
        PERMISSION_DENIED_MANAGE: "无权管理任务",
        INVALID_REMINDER_DATA: "表单信息不完整或格式错误",
        QUOTA_EXCEEDED: "已达到每日发送限额",
        SMS_API_ERROR: "短信 API 调用失败",
        MSG_REMINDER_CREATED: "任务添加成功！",
        MSG_NO_IMMEDIATE_TASKS: "暂无需要立即发送的任务。",
        MSG_REMINDER_UPDATED: "任务更新成功！",
        MSG_INSPECTION_COMPLETED: "检查完成！成功处理任务数: ",
        MSG_REMINDER_DELETED: "任务删除成功！",
        MSG_SEND_SUCCESS: "发送成功！",
        USER_NOT_FOUND: "操作未授权",
        INTERNAL_SERVER_ERROR_SENT: "发送过程中出错。",
        PERMISSION_DENIED_VIEW: "无权查看任务列表",
        PERMISSION_DENIED_ADD: "无权添加新任务",
        PERMISSION_DENIED_DELETE: "无权删除任务",
        REMINDER_NOT_FOUND: "任务不存在或无权操作",
        PERMISSION_DENIED_TRIGGER: "无权手动触发任务",
        PERMISSION_DENIED_CLIENT: "无权使用浏览器定时发送",
        MISSING_SMS_API: "请求格式错误，缺少 smsApi 字段",
        INVALID_API_FORMAT: "API 格式错误，请检查链接",
        VERIFICATION_CODE_ACTIVE: "验证码已发送，请勿频繁请求",
        VERIFICATION_LIMIT_EXCEEDED: "已达到24小时内验证码发送限额",
        SMS_SEND_FAILED: "短信发送失败，请检查 API Key 和号码",
        INVALID_JSON: "请求体不是有效的 JSON 格式",
        MISSING_SENDER_OR_BODY: "发送号码和内容不能为空",
        INVALID_PHONE_FORMAT: "手机号码格式错误",
        USER_DATA_ERROR: "用户数据异常"
    },
    en: {
        // --- General ---
        console: "Console",
        settings: "Settings",
        user_label: "User",
        loading: "Loading data...",
        save_changes: "Save Changes",
        discard: "Discard",
        cancel: "Cancel",
        confirm: "Confirm",
        back_dashboard: "Back to Dashboard",

        // --- Messages ---
        msg_network_error: "Network error, please check connection.",
        msg_no_perm: "Permission denied.",
        msg_unknown_user: "Unknown",
        msg_fill_incomplete: "Please fill in all red-highlighted fields",
        msg_save_success: "Saved successfully",
        msg_save_partial_fail: "Partial failure: ",
        msg_changes: "Changes: ",

        // --- Dashboard Table ---
        col_date: "Date",
        col_cycle: "Cycle(Days)",
        col_sender: "Sender ID",
        col_content: "Content",
        col_status: "Status",
        col_del: "Del",
        status_running: "🟢 Active",
        status_stopped: "🔴 Stopped",

        // --- Dashboard Buttons ---
        browser_timer: "Timer",
        trigger_now: "Trigger",
        new_task: "New",

        // --- Dashboard Permissions ---
        msg_no_perm_view: "No permission to view task",
        msg_no_perm_add: "No permission to add task",
        msg_no_perm_del: "No permission to delete task",
        msg_no_perm_edit: "No permission to edit data",
        msg_confirm_del_title: "Delete Task",
        msg_confirm_del_body: "Are you sure? Effect after save.",

        // --- Browser Timer ---
        browser_timer_title: "Browser Timer",
        timer_warn_title: "⚠️ Important:",
        timer_warn_list: `<li><b>Temporary</b>: The task only runs on the current page and is lost when the page is closed or refreshed. </li>
                          <li><b>Localization</b>: It will not synchronize to the server or other devices.</li>
                          <li><b>Dependency</b>: Must remain logged in and have sufficient quotas during execution.</li>`,
        label_trigger_time: "Trigger Time:",
        label_sender: "Sender ID:",
        label_content: "Content:",
        ph_from: "Sender ID...",
        ph_content: "Message content...",
        btn_start_timer: "Start Timer",
        queue_title: "Running Queue (Click for details)",
        add_10s: "+10s", add_30s: "+30s", add_1m: "+1m", add_1h: "+1h",
        msg_timer_fill_info: "Please fill all fields",
        msg_timer_future: "Please select a future time",
        msg_timer_queued: "Timer queued",
        msg_timer_success: "✅ Success",
        msg_timer_failed: "❌ Failed",
        msg_timer_empty: "No running tasks",

        // --- Time Display ---
        time_overdue: "Overdue",
        time_today: "Today",
        time_tomorrow: "Tomorrow",
        time_day_after: "Day after",
        time_days_later: "days left",
        time_stopped: "Stopped",
        day: "d", hour: "h", min: "m", sec: "s",

        // --- Settings Page ---
        settings_title: "Settings",
        change_pwd_title: "Change Password",
        label_curr_pwd: "Current Password:",
        label_new_pwd: "New Password (min 6 chars):",
        label_confirm_pwd: "Confirm New Password:",
        btn_confirm_change: "Update Password",
        account_actions: "Account Actions",
        btn_logout: "Logout",
        msg_pwd_mismatch: "New passwords do not match.",
        msg_saving: "Processing...",
        msg_success_redirect: "Password changed! Redirecting to login...",
        msg_perm_denied_pwd: "You do not have permission to change password.",

        msg_trigger_success: "Server check triggered",
        msg_trigger_failed: "Trigger failed",
        msg_confirm_logout: "Are you sure you want to log out?",

        verify_title: "Verify & Set Password",
        msg_code_sent: "Code sent to: ",
        label_verify_code: "6-Digit Code",
        ph_verify_code: "Enter SMS code",
        label_set_pwd: "Set Password",
        ph_set_pwd: "New password (min 6 chars)",
        btn_complete_reg: "Complete Registration",
        msg_reg_success: "Registration successful! Redirecting...",
        msg_reg_fail: "Registration failed: ",
        msg_verify_invalid_phone: "Invalid phone number",
        ph_confirm_pwd: "Re-enter password",

        // Register Page
        register_title: "Create Account",
        register_desc: "Enter your SMS API [BETA] link to receive a verification code.",
        label_sms_api: "SMS API Link",
        ph_sms_api: "Paste full API link...",
        btn_get_code: "Get Verification Code",
        link_to_login: "Already have an account? Login",
        msg_api_fmt_err: "Invalid API format. Please check the link.",
        msg_num_mismatch: "The 'send' number must match the 'from' number.",
        msg_requesting_code: "Requesting verification code...",
        msg_redirect_login: "Account exists, redirecting to login...",
        msg_redirect_verify: "Code active, redirecting to verify...",
        label_agree: "I have read and agree to the",
        link_tos: "Terms of Service & Privacy Policy",
        msg_must_agree: "Please agree to the Terms of Service & Privacy Policy first",
        link_how_to_get: "How to get API?",

        // Login Page
        login_title: "Login",
        login_subtitle: "Welcome back, please enter your details.",
        label_phone: "Phone Number",
        ph_phone: "Enter number starting with 372",
        btn_login: "Sign In",
        link_no_account: "No account? Create one",
        msg_login_success: "Login successful, redirecting...",
        link_how_to_get_num: "How to get a number?",
        msg_invalid_phone_fmt: "Invalid format!",
        btn_home: "Home",

        // Index Page
        kb_tutorial: "📖 Tutorial",
        kb_go: "GO",

        // --- API Error Codes ---
        INVALID_VERIFY_CODE: "The verification code is incorrect or has expired.",
        VERIFY_ENV_MISMATCH: "Environment changed, please request code again.",
        USER_ALREADY_EXISTS: "This phone number is already registered.",
        INTERNAL_SERVER_ERROR: "Internal Server Error",
        BAD_REQUEST: "Bad Request",
        LOGIN_FAILED: "Invalid username or password",
        PERMISSION_DENIED_LOGIN: "Account login banned",
        LOGIN_LIMIT_EXCEEDED: "Weekly login limit exceeded",
        SESSION_LIMIT_EXCEEDED: "Max sessions reached, please logout elsewhere",
        PERMISSION_DENIED_PWD: "No permission to change password",
        INVALID_PWD_FORMAT: "Invalid format or password too short",
        INVALID_CURRENT_PWD: "Incorrect current password",
        PERMISSION_DENIED_MANAGE: "No permission to manage tasks",
        INVALID_REMINDER_DATA: "Invalid reminder data",
        QUOTA_EXCEEDED: "Daily SMS quota exceeded",
        SMS_API_ERROR: "SMS API Error",
        MSG_REMINDER_CREATED: "Reminder added successfully!",
        MSG_NO_IMMEDIATE_TASKS: "There are no reminders that need to be sent immediately.",
        MSG_REMINDER_UPDATED: "Reminder update successful!",
        MSG_INSPECTION_COMPLETED: "Inspection completed! Successfully processed: ",
        MSG_REMINDER_DELETED: "Reminder deleted successfully!",
        MSG_SEND_SUCCESS: "Sent successfully!",
        USER_NOT_FOUND: "Unauthorized operation",
        INTERNAL_SERVER_ERROR_SENT: "An error occurred during the sending process.",
        PERMISSION_DENIED_VIEW: "No permission to view task list",
        PERMISSION_DENIED_ADD: "No authority to add new tasks",
        PERMISSION_DENIED_DELETE: "No permission to delete tasks",
        REMINDER_NOT_FOUND: "Reminder does not exist or access denied",
        PERMISSION_DENIED_TRIGGER: "No permission to manually trigger tasks",
        PERMISSION_DENIED_CLIENT: "No permission to use browser timer",
        MISSING_SMS_API: "Request format error, missing smsApi field",
        INVALID_API_FORMAT: "Invalid API format",
        VERIFICATION_CODE_ACTIVE: "Code already sent, please wait",
        VERIFICATION_LIMIT_EXCEEDED: "Daily verification limit reached",
        SMS_SEND_FAILED: "SMS sending failed, check API Key and Number",
        INVALID_JSON: "Invalid JSON body",
        MISSING_SENDER_OR_BODY: "Sender and content cannot be empty",
        INVALID_PHONE_FORMAT: "Phone number error",
        USER_DATA_ERROR: "User data abnormal"
    }
};

const storedLang = localStorage.getItem('appLang');
let currentLang = (storedLang && TRANSLATIONS[storedLang]) ? storedLang : 'zh';
if (storedLang !== currentLang) {
    localStorage.setItem('appLang', currentLang);
}

window.t = function(key) {
    if (!TRANSLATIONS[currentLang]) return key;
    return TRANSLATIONS[currentLang][key] || key;
};

// 切换语言函数
window.toggleLanguage = function() {
    currentLang = currentLang === 'zh' ? 'en' : 'zh';
    localStorage.setItem('appLang', currentLang);
    window.applyPageLanguage();

    if (typeof window.renderTable === 'function' && typeof window.getTableDataFromDOM === 'function') {
        window.renderTable(window.getTableDataFromDOM());
    }

    if (typeof window.renderClientTimers === 'function') {
        window.renderClientTimers();
    }
};

// 应用语言到页面 DOM
window.applyPageLanguage = function() {
    const langLabel = document.getElementById('langLabel');
    if (langLabel) langLabel.textContent = currentLang === 'zh' ? 'EN' : '中';

    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.innerHTML = t(key);
    });

    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
        const key = el.getAttribute('data-i18n-placeholder');
        el.placeholder = t(key);
    });
};

// 页面加载完成后自动应用
document.addEventListener('DOMContentLoaded', () => {
    window.applyPageLanguage();
});