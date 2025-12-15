const CONFIG = {
    PBKDF2_ITERATIONS: 100000,
    SESSION_EXPIRATION_DAYS: 30,
    VERIFICATION_CODE_EXPIRATION_MINUTES: 15,
    LOG_RETENTION_DAYS: 90,
    DEFAULT_MAX_SESSIONS: 5,
    DEFAULT_WEEKLY_LOGIN_LIMIT: 21,
    DEFAULT_DAILY_SMS_LIMIT: 10,
    MAX_VERIFICATION_SENDS_PER_DAY: 5,
    SMS_API_DOMAIN: 'api.nekoko.tel',
    ALLOWED_ORIGIN: 'your domain name',
};

const PERM_LOGIN           = 1;
const PERM_CHANGE_PASSWORD = 2;
const PERM_VIEW_TASKS      = 4;
const PERM_MANAGE_TASKS    = 8;
const PERM_TRIGGER_TASKS   = 16;
const PERM_CLIENT_TIMERS   = 32;
const PERM_DEFAULT         = 47;
const SESSION_EXPIRATION_MS = CONFIG.SESSION_EXPIRATION_DAYS * 24 * 60 * 60 * 1000;
const SESSION_EXPIRATION_SECONDS = CONFIG.SESSION_EXPIRATION_DAYS * 24 * 60 * 60;
const VERIFICATION_CODE_EXPIRATION_MS = CONFIG.VERIFICATION_CODE_EXPIRATION_MINUTES * 60 * 1000;
const LOG_RETENTION_MS = CONFIG.LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000;
const escapedDomain = CONFIG.SMS_API_DOMAIN.replace(/\./g, '\\.');
const SMS_API_URL_REGEX = new RegExp(`^https://${escapedDomain}/sms/send/(372\\d{8})\\?apikey=([A-Z0-9]{24})&from=(372\\d{8})&body=Your\\+test\\+message$`);

export default {
    async fetch(request, env, ctx) {
        if (request.method === "OPTIONS") {
            return handleCors(request, env);
        }
        try {
            const response = await handleApiRequest(request, env, ctx);
            return addCorsHeaders(response, request, env);
        } catch (e) {
            console.error("Worker Global Error:", e);
            return addCorsHeaders(new Response(JSON.stringify({ error: 'Internal Server Error' }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            }));
        }
    },
    async scheduled(event, env, ctx) {
        ctx.waitUntil(handleScheduledTasks(env));
    }
};

function getSafeOrigin(request, env) {
    const origin = request.headers.get("Origin");
    let allowedOrigins = [];
    if (env.ALLOWED_ORIGINS) {
        allowedOrigins = env.ALLOWED_ORIGINS.split(",");
    }
    else if (CONFIG.ALLOWED_ORIGIN) {
        allowedOrigins = [CONFIG.ALLOWED_ORIGIN];
    }
    if (origin && allowedOrigins.includes(origin)) {
        return origin;
    }
    return allowedOrigins.length > 0 ? allowedOrigins[0] : null;
}

function handleCors(request, env) {
    const safeOrigin = getSafeOrigin(request, env);
    if (!safeOrigin) {
        return new Response("Forbidden Origin", { status: 403 });
    }
    const headers = {
        "Access-Control-Allow-Origin": safeOrigin,
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
        "Access-Control-Max-Age": "86400",
        "Access-Control-Allow-Credentials": "true",
    };
    return new Response(null, { headers });
}

function addCorsHeaders(response, request, env) {
    const safeOrigin = getSafeOrigin(request, env);
    if (!safeOrigin) return response;
    const newHeaders = new Headers(response.headers);
    newHeaders.set("Access-Control-Allow-Origin", safeOrigin);
    newHeaders.set("Access-Control-Allow-Credentials", "true");
    return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders
    });
}

async function handleApiRequest(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/register' && request.method === 'POST') return handleRegister(request, env);
    if (url.pathname === '/api/verify' && request.method === 'POST') return handleVerify(request, env);
    if (url.pathname === '/api/login' && request.method === 'POST') return handleLogin(request, env);
    const auth = await authenticateUser(request, env);
    if (!auth.user) {
        return new Response(JSON.stringify({ error: 'Unauthorized: Missing or invalid token' }), {
            status: 401,
            headers: { 'Content-Type': 'application/json' }
        });
    }
    const secureDB = createSecureDatabaseHandler(env, auth.sessionToken);
    try {
        if (url.pathname === '/api/logout' && request.method === 'POST') {
            return await handleLogout(request, secureDB, auth.user.id, auth.sessionToken);
        }
        const reminderMatch = url.pathname.match(/^\/api\/reminders\/(\d+)$/);
        if (reminderMatch) {
            const reminderId = parseInt(reminderMatch[1], 10);
            if (request.method === 'PUT') {
                return await handleUpdateReminder(request, secureDB, auth.user.id, reminderId, env);
            }
            if (request.method === 'DELETE') {
                return await handleDeleteReminder(request, secureDB, auth.user.id, reminderId, env);
            }
        }
        if (url.pathname === '/api/reminders') {
            if (request.method === 'GET') return await getReminders(secureDB, auth.user.id, env);
            if (request.method === 'POST') return await createReminder(request, secureDB, auth.user.id, env);
        }
        if (url.pathname === '/api/reminders/check-now' && request.method === 'POST') {
            return await handleCheckNow(request, env, secureDB, auth.user);
        }
        if (url.pathname === '/api/send-direct' && request.method === 'POST') {
            return await handleSendDirect(request, env, secureDB, auth.user);
        }
        if (url.pathname === '/api/user/change-password' && request.method === 'POST') {
            return await handleChangePassword(request, env, secureDB, auth.user.id);
        }
        return new Response(JSON.stringify({ error: 'Not Found' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' }
        });
    } catch (e) {
        if (e instanceof SessionError) {
            return new Response(JSON.stringify({ error: 'Unauthorized: Session has ended' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        console.error("Protected Route Error:", e);
        return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
}

const a = (s) => new TextEncoder().encode(s);
const b = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
const sign = async (payload, secret) => {
    const header = { alg: "HS256", typ: "JWT" };
    const data = a(`${b(a(JSON.stringify(header)))}.${b(a(JSON.stringify(payload)))}`);
    const key = await crypto.subtle.importKey("raw", a(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    const signature = await crypto.subtle.sign("HMAC", key, data);
    return `${new TextDecoder().decode(data)}.${b(signature)}`;
};
const verify = async (token, secret) => {
    try {
        const [header, payload, signature] = token.split('.');
        const key = await crypto.subtle.importKey("raw", a(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
        const data = a(`${header}.${payload}`);
        const valid = await crypto.subtle.verify("HMAC", key, Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0)), data);
        if (!valid) return null;
        return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(payload.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0))));
    } catch (e) {
        return null;
    }
};

const bufferToHex = (buffer) => [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
const hexToBuffer = (hex) => {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
};

async function hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: CONFIG.PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, 256);
    return { hash: bufferToHex(derivedBits), salt: bufferToHex(salt) };
}

async function verifyPassword(password, storedHashHex, saltHex) {
    const salt = hexToBuffer(saltHex);
    const keyMaterial = await crypto.subtle.importKey(
        'raw',
        new TextEncoder().encode(password),
        { name: 'PBKDF2' },
        false,
        ['deriveBits']
    );
    const derivedBits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: salt, iterations: CONFIG.PBKDF2_ITERATIONS, hash: 'SHA-256' }, keyMaterial, 256);
    const newHashHex = bufferToHex(derivedBits);
    return newHashHex === storedHashHex;
}

function getClientInfo(request) {
    return {
        ip: request.headers.get('cf-connecting-ip') || 'N/A',
        userAgent: request.headers.get('user-agent') || 'N/A',
    };
}
async function logUserAction(db, userId, actionType, request = null, details = {}) {
    const { ip, userAgent } = request ? getClientInfo(request) : { ip: 'SYSTEM', userAgent: 'CRON' };
    const statement = await db.prepare(
        'INSERT INTO user_actions (user_id, action_type, ip_address, user_agent, details) VALUES (?, ?, ?, ?, ?)'
    );
    await statement.bind(userId, actionType, ip, userAgent, JSON.stringify(details)).run();
}

class SessionError extends Error {
    constructor(message) {
        super(message);
        this.name = 'SessionError';
    }
}

function createSecureDatabaseHandler(env, sessionToken) {
    const db = env.DB;
    return {
        async prepare(query) {
            const earliestValidDate = new Date(Date.now() - SESSION_EXPIRATION_MS).toISOString();
            const session = await db.prepare('SELECT user_id FROM user_sessions WHERE session_token = ? AND created_at >= ?')
                .bind(sessionToken, earliestValidDate).first();

            if (!session) {
                throw new SessionError('Invalid or expired session.');
            }
            return db.prepare(query);
        }
    };
}

async function checkPermission(env, userId, permissionMask) {
    const user = await env.DB.prepare('SELECT permissions FROM users WHERE id = ?').bind(userId).first();
    if (!user || user.permissions === null) return false;
    return (user.permissions & permissionMask) === permissionMask;
}

function errorResponse(message, code, status) {
    return new Response(JSON.stringify({ error: message, code: code }), {
        status: status,
        headers: { 'Content-Type': 'application/json' }
    });
}

async function authenticateUser(request, env) {
    const cookieHeader = request.headers.get('Cookie');
    if (!cookieHeader) return { user: null };
    function getCookie(name) {
        const match = cookieHeader.match(new RegExp('(^| )' + name + '=([^;]+)'));
        if (match) return match[2];
        return null;
    }
    const token = getCookie('auth_token');
    if (!token) {
        console.error("[Auth] No auth_token found in cookie");
        return { user: null };
    }
    const payload = await verify(token, env.JWT_SECRET);
    if (!payload) {
        console.error("[Auth] JWT Verify failed (Invalid Signature or Secret mismatch)");
        return { user: null };
    }
    if (payload && payload.userId && payload.sessionToken) {
        const earliestValidDate = new Date(Date.now() - SESSION_EXPIRATION_MS).toISOString();
        const session = await env.DB.prepare(
            'SELECT user_id FROM user_sessions WHERE session_token = ? AND created_at >= ?'
        ).bind(payload.sessionToken, earliestValidDate).first();
        if (session) {
            return {
                user: { id: payload.userId, phone: payload.phone },
                sessionToken: payload.sessionToken
            };
        } else {
            console.error("[Auth] Session not found in DB or expired");
        }
    }
    return { user: null };
}

async function handleLogin(request, env) {
    const { esimggNumber, password } = await request.json();
    const user = await env.DB.prepare('SELECT id, password_hash, password_salt, max_sessions, weekly_login_limit, permissions FROM users WHERE phone_number = ?')
        .bind(esimggNumber).first();
    if (!user) return errorResponse('User or password error', 'LOGIN_FAILED', 404);
    const userPerms = user.permissions !== null ? user.permissions : 0;
    if ((userPerms & PERM_LOGIN) !== PERM_LOGIN) {
         return errorResponse('Your account has been banned from logging in.', 'PERMISSION_DENIED_LOGIN', 403);
    }
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const loginCountStmt = env.DB.prepare("SELECT COUNT(*) as count FROM user_actions WHERE user_id = ? AND action_type = 'login' AND created_at >= ?");
    const { count: recentLogins } = await loginCountStmt.bind(user.id, sevenDaysAgo).first();
    if (recentLogins >= user.weekly_login_limit) return errorResponse('Exceeding the maximum weekly login limit', 'LOGIN_LIMIT_EXCEEDED', 429);
    const isPasswordCorrect = await verifyPassword(password, user.password_hash, user.password_salt);
    if (!isPasswordCorrect) return errorResponse('User or password error', 'LOGIN_FAILED', 401);
    const sessionCountStmt = env.DB.prepare('SELECT COUNT(*) as count FROM user_sessions WHERE user_id = ?');
    const { count: activeSessions } = await sessionCountStmt.bind(user.id).first();
    if (activeSessions >= user.max_sessions) return errorResponse('The maximum number of sessions has been reached. Please log out from another device first', 'SESSION_LIMIT_EXCEEDED', 429);
    const { ip, userAgent } = getClientInfo(request);
    const newSessionToken = crypto.randomUUID();
    const token = await sign({ userId: user.id, phone: esimggNumber, sessionToken: newSessionToken, exp: Math.floor(Date.now() / 1000) + SESSION_EXPIRATION_SECONDS }, env.JWT_SECRET);
    await env.DB.prepare('INSERT INTO user_sessions (user_id, session_token, ip_address, user_agent) VALUES (?, ?, ?, ?)').bind(user.id, newSessionToken, ip, userAgent).run();
    await logUserAction(env.DB, user.id, 'login', request);
    const cookieString = `auth_token=${token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=${SESSION_EXPIRATION_SECONDS}`;
    return new Response(JSON.stringify({
        success: true,
        permissions: userPerms,
        userId: user.id
    }), {
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': cookieString
        }
    });
}

async function handleLogout(request, secureDB, userId, sessionToken) {
    try {
        await logUserAction(secureDB, userId, 'logout', request, { session_token_prefix: sessionToken.substring(0, 8) + '...' });
    } catch (e) {
        console.error("Failed to log logout action:", e);
    }
    const statement = await secureDB.prepare('DELETE FROM user_sessions WHERE session_token = ? AND user_id = ?');
    await statement.bind(sessionToken, userId).run();
    const clearCookie = `auth_token=; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=0`;
    return new Response(JSON.stringify({ success: true, message: 'Successfully logged out' }), {
        headers: {
            'Content-Type': 'application/json',
            'Set-Cookie': clearCookie
        }
    });
}

async function handleVerify(request, env) {
    try {
        await env.DB.prepare('DELETE FROM verification_codes WHERE expires_at < ?').bind(Date.now()).run();

        const { phoneNumber, code, password } = await request.json();
        if (!phoneNumber || !code || !password || password.length < 6) {
            return errorResponse('Incomplete information or password less than 6 characters.', 'INVALID_PWD_FORMAT', 400);
        }
        const stored = await env.DB.prepare('SELECT code, api_key_temp, ip_address, user_agent FROM verification_codes WHERE phone_number = ?').bind(phoneNumber).first();
        if (!stored || stored.code !== code) {
            return errorResponse('The verification code is incorrect or has expired.', 'INVALID_VERIFY_CODE', 400);
        }
        const { ip, userAgent } = getClientInfo(request);
        if (stored.ip_address !== ip || stored.user_agent !== userAgent) {
            return errorResponse('Verify environmental changes, please obtain the verification code again!', 'VERIFY_ENV_MISMATCH', 400);
        }
        const { hash, salt } = await hashPassword(password);
        await env.DB.prepare(
            'INSERT INTO users (phone_number, api_key, password_hash, password_salt, max_sessions, weekly_login_limit, daily_sms_limit, permissions, total_sms_count) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)'
        ).bind(phoneNumber, stored.api_key_temp, hash, salt, CONFIG.DEFAULT_MAX_SESSIONS, CONFIG.DEFAULT_WEEKLY_LOGIN_LIMIT, CONFIG.DEFAULT_DAILY_SMS_LIMIT, PERM_DEFAULT).run();
        await env.DB.prepare('DELETE FROM verification_codes WHERE phone_number = ?').bind(phoneNumber).run();
        return new Response(JSON.stringify({ success: true, message: 'registered successfully' }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    } catch(e) {
        if (e.message?.includes('UNIQUE constraint failed')) {
            return errorResponse('This phone number has already been registered.', 'USER_ALREADY_EXISTS', 409);
        }
        console.error("Verify Error:", e);
        return new Response(JSON.stringify({ error: 'Internal server error.' }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

async function handleChangePassword(request, env, secureDB, userId) {
    if (!await checkPermission(env, userId, PERM_CHANGE_PASSWORD)) {
        return errorResponse('No authority to change password.', 'PERMISSION_DENIED_PWD', 403);
    }
    try {
        const { currentPassword, newPassword } = await request.json();
        if (!currentPassword || !newPassword || newPassword.length < 6) {
            return errorResponse('The information is incomplete or the new password is less than 6 characters.', 'INVALID_PWD_FORMAT', 400);
        }
        const user = await env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?').bind(userId).first();
        if (!user) {
            return errorResponse('unauthorized operation', 'USER_NOT_FOUND', 404);
        }
        const isPasswordCorrect = await verifyPassword(currentPassword, user.password_hash, user.password_salt);
        if (!isPasswordCorrect) {
            return errorResponse('The current password is incorrect.', 'INVALID_CURRENT_PWD', 401);
        }
        const { hash, salt } = await hashPassword(newPassword);
        const updateStmt = await secureDB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?');
        await updateStmt.bind(hash, salt, userId).run();
        await logUserAction(secureDB, userId, 'change_password', request);
        const deleteSessionsStmt = await secureDB.prepare('DELETE FROM user_sessions WHERE user_id = ?');
        await deleteSessionsStmt.bind(userId).run();
        return new Response(JSON.stringify({ success: true, message: 'Password changed successfully!' }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
        console.error("Change Password Error:", e);
        return errorResponse('Internal server error.', 'INTERNAL_SERVER_ERROR', 500);
    }
}

async function getReminders(secureDB, userId, env) {
    if (!await checkPermission(env, userId, PERM_VIEW_TASKS)) {
        return errorResponse('Do not have permission to view the task list.', 'PERMISSION_DENIED_VIEW', 403);
    }
    const statement = await secureDB.prepare('SELECT id, from_number, body, trigger_datetime, status, cycle_days FROM reminders WHERE user_id = ? ORDER BY created_at DESC');
    const { results } = await statement.bind(userId).all();
    return new Response(JSON.stringify(results), { headers: { 'Content-Type': 'application/json' } });
}

async function createReminder(request, secureDB, userId, env) {
    if (!await checkPermission(env, userId, PERM_MANAGE_TASKS)) {
        return errorResponse('No authority to add new tasks.', 'PERMISSION_DENIED_ADD', 403);
    }
    const { from, body, date, cycle_days } = await request.json();
    const cycle = parseInt(cycle_days, 10) || 0;
    if (!/^\d+$/.test(from) || !body || !date || cycle < 0) {
        return errorResponse('Form information is incomplete or formatted incorrectly', 'BAD_REQUEST', 400);
    }
    const statement = await secureDB.prepare('INSERT INTO reminders (user_id, from_number, body, trigger_datetime, cycle_days, status) VALUES (?, ?, ?, ?, ?, ?)');
    await statement.bind(userId, from, body, date, cycle, 'running').run();
    await logUserAction(secureDB, userId, 'create_reminder', request, { body, date, cycle });
    return new Response(JSON.stringify({ success: true, message: 'Reminder added successfully!', code: 'MSG_REMINDER_CREATED' }), { status: 201, headers: { 'Content-Type': 'application/json' } });
}

async function handleUpdateReminder(request, secureDB, userId, reminderId, env) {
    if (!await checkPermission(env, userId, PERM_MANAGE_TASKS)) {
        return errorResponse('No authority to modify tasks.', 'PERMISSION_DENIED_MANAGE', 403);
    }
    try {
        const { from_number, body, trigger_datetime, status, cycle_days } = await request.json();
        const cycle = parseInt(cycle_days, 10) || 0;
        if (!/^\d+$/.test(from_number) || !body || !trigger_datetime || !['running', 'stopped'].includes(status) || cycle < 0) {
            return errorResponse('The request information is incomplete or contains invalid values.', 'INVALID_REMINDER_DATA', 400);
        }
        const findStmt = await secureDB.prepare('SELECT id FROM reminders WHERE id = ? AND user_id = ?');
        const existingReminder = await findStmt.bind(reminderId, userId).first();
        if (!existingReminder) {
            return errorResponse('Reminder does not exist or has no authority to modify.', 'REMINDER_NOT_FOUND', 404);
        }
        const updateStmt = await secureDB.prepare(
            'UPDATE reminders SET from_number = ?, body = ?, trigger_datetime = ?, status = ?, cycle_days = ? WHERE id = ? AND user_id = ?'
        );
        await updateStmt.bind(from_number, body, trigger_datetime, status, cycle, reminderId, userId).run();
        await logUserAction(secureDB, userId, 'update_reminder', request, { reminderId });
        return new Response(JSON.stringify({ success: true, message: 'Reminder update successful!', code: 'MSG_REMINDER_UPDATED' }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
        console.error("Update Reminder Error:", e);
        return errorResponse('Internal server error.', 'INTERNAL_SERVER_ERROR', 500);
    }
}

async function processAndSendReminders(remindersList, env) {
    let sentCount = 0;
    for (const userId in remindersList) {
        const userReminders = remindersList[userId];
        if (!userReminders || userReminders.length === 0) continue;
        const user = userReminders[0];
        const userIdInt = parseInt(userId, 10);
        const twentyFourHoursAgoISO = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
        const countStmt = env.DB.prepare("SELECT COUNT(*) as count FROM user_actions WHERE user_id = ? AND action_type = 'sent_sms' AND created_at >= ?");
        const { count: sentInLast24h } = await countStmt.bind(userIdInt, twentyFourHoursAgoISO).first();
        if (sentInLast24h >= user.daily_sms_limit) {
            console.warn(`User ${userId} has exceeded their 24-hour SMS quota.`);
            await logUserAction(env.DB, userIdInt, 'quota_exceeded_stop', null, {
                limit: user.daily_sms_limit,
                current_usage: sentInLast24h,
                attempted_batch_size: userReminders.length
            });
            continue;
        }
        const mergedBody = userReminders.length === 1
            ? userReminders[0].body
            : userReminders.map(r => `【${r.from_number}】${r.body}`).join('\n\n');
        const url = `https://${CONFIG.SMS_API_DOMAIN}/sms/send/${user.phone_number}?apikey=${user.api_key}&from=${user.from_number}&body=${encodeURIComponent(mergedBody)}`;
        try {
            const smsResponse = await fetch(url);
            let isSuccess = false;
            let responseData = null;
            if (smsResponse.ok) {
                const responseText = await smsResponse.text();
                try {
                    responseData = JSON.parse(responseText);
                } catch (e) {
                    try {
                        const fixedJson = responseText.replace(/'/g, '"');
                        responseData = JSON.parse(fixedJson);
                    } catch (e2) {
                        console.error("Failed to parse response as JSON:", responseText);
                    }
                }
                if (responseData && responseData.message === "SMS sent successfully") {
                    isSuccess = true;
                }
            }
            if (isSuccess) {
                await logUserAction(env.DB, userIdInt, 'sent_sms', null, { mergedCount: userReminders.length });
                sentCount += userReminders.length;
                await env.DB.prepare('UPDATE users SET total_sms_count = total_sms_count + ? WHERE id = ?')
                    .bind(userReminders.length, userIdInt).run();
                const updates = [];
                for (const reminder of userReminders) {
                    if (reminder.cycle_days > 0) {
                        const currentTriggerDate = new Date(reminder.trigger_datetime);
                        currentTriggerDate.setDate(currentTriggerDate.getDate() + reminder.cycle_days);
                        const nextTriggerDate = currentTriggerDate.toISOString().split('T')[0];
                        updates.push(
                            env.DB.prepare("UPDATE reminders SET trigger_datetime = ? WHERE id = ?").bind(nextTriggerDate, reminder.id)
                        );
                    } else {
                        updates.push(
                            env.DB.prepare("UPDATE reminders SET status = 'stopped' WHERE id = ?").bind(reminder.id)
                        );
                    }
                }
                if(updates.length > 0) await env.DB.batch(updates);
            } else {
                const failReason = apiResponse ? JSON.stringify(apiResponse) : `HTTP ${smsResponse.status}`;
                await logUserAction(env.DB, userIdInt, 'sms_failed_stop', null, {
                    reason: failReason,
                    task_ids: userReminders.map(r => r.id)
                });
                const idsToFail = userReminders.map(r => r.id);
                const failStmt = await env.DB.prepare(`UPDATE reminders SET status = 'stopped' WHERE id IN (${idsToFail.join(',')})`);
                await failStmt.run();
            }
        } catch (e) {
            console.error(`Exception during merged SMS sending for user ${userId}:`, e);
            await logUserAction(env.DB, userIdInt, 'sms_exception_stop', null, { error: e.message });
            const idsToFail = userReminders.map(r => r.id);
            if (idsToFail.length > 0) {
                const failStmt = await env.DB.prepare(`UPDATE reminders SET status = 'stopped' WHERE id IN (${idsToFail.join(',')})`);
                await failStmt.run();
            }
        }
    }
    return sentCount;
}

async function handleScheduledTasks(env) {
    const today_utc8 = new Date(new Date().getTime() + 8 * 3600 * 1000).toISOString().split('T')[0];
    const reminderQuery = `
        SELECT
            r.id,
            r.from_number,
            r.body,
            r.trigger_datetime,
            r.cycle_days,
            u.phone_number,
            u.api_key,
            u.id as user_id,
            u.daily_sms_limit
        FROM reminders AS r
        JOIN users AS u ON r.user_id = u.id
        WHERE r.status = 'running' AND r.trigger_datetime <= ?
    `;
    const { results: dueReminders } = await env.DB.prepare(reminderQuery).bind(today_utc8).all();
    if (dueReminders.length > 0) {
        const groupedReminders = dueReminders.reduce((acc, reminder) => {
            const userId = reminder.user_id;
            if (!acc[userId]) {
                acc[userId] = [];
            }
            acc[userId].push(reminder);
            return acc;
        }, {});
        await processAndSendReminders(groupedReminders, env);
    }
    const now = Date.now();
    const oneDayAgo = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const sessionExpiryDate = new Date(now - SESSION_EXPIRATION_MS).toISOString();
    const logRetentionDate = new Date(now - LOG_RETENTION_MS).toISOString();
    const batch = [
        env.DB.prepare("DELETE FROM user_sessions WHERE created_at < ?").bind(sessionExpiryDate),
        env.DB.prepare("DELETE FROM user_actions WHERE created_at < ?").bind(logRetentionDate),
        env.DB.prepare("DELETE FROM verification_codes WHERE expires_at < ?").bind(now),
        env.DB.prepare("DELETE FROM verification_attempts WHERE created_at < ?").bind(oneDayAgo)
    ];
    await env.DB.batch(batch);
}

async function handleCheckNow(request, env, secureDB, user) {
    if (!await checkPermission(env, user.id, PERM_TRIGGER_TASKS)) {
        return errorResponse('No authority to manually trigger tasks.', 'PERMISSION_DENIED_TRIGGER', 403);
    }
    const today_utc8 = new Date(new Date().getTime() + 8 * 3600 * 1000).toISOString().split('T')[0];
    const query = `
        SELECT
            r.id,
            r.from_number,
            r.body,
            r.trigger_datetime,
            r.cycle_days,
            u.phone_number,
            u.api_key,
            u.id as user_id,
            u.daily_sms_limit
        FROM reminders AS r
        JOIN users AS u ON r.user_id = u.id
        WHERE r.status = 'running' AND r.trigger_datetime <= ? AND r.user_id = ?
    `;
    const { results: dueReminders } = await env.DB.prepare(query).bind(today_utc8, user.id).all();
    await logUserAction(secureDB, user.id, 'check_reminders_now', request);
    if (dueReminders.length === 0) return new Response(JSON.stringify({ message: "There are no reminders that need to be sent immediately.", code: 'MSG_NO_IMMEDIATE_TASKS' }), { headers: { 'Content-Type': 'application/json' } });
    const groupedReminders = { [user.id]: dueReminders };
    const sentCount = await processAndSendReminders(groupedReminders, env);
    return new Response(JSON.stringify({ message: `Inspection completed! Successfully processed ${sentCount} reminders.`, code: 'MSG_INSPECTION_COMPLETED', count: sentCount}), { headers: { 'Content-Type': 'application/json' } });
}

async function handleRegister(request, env) {
    try {
        const body = await request.json();
        if (!body || typeof body.smsApi !== 'string') {
            return errorResponse('Request format error, missing smsApi field.', 'MISSING_SMS_API', 400);
        }
        const smsApi = body.smsApi;
        const match = smsApi.match(SMS_API_URL_REGEX);
        if (!match) {
            return errorResponse('API format error.', 'INVALID_API_FORMAT', 400);
        }
        const [_, phoneNumber, apiKey, fromNumber] = match;
        if (phoneNumber !== fromNumber) {
            return errorResponse('API format error!', 'INVALID_API_FORMAT', 400);
        }
        const twentyFourHoursAgoISO = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(); // 24小时内的验证码sms
        await env.DB.prepare('DELETE FROM verification_attempts WHERE created_at < ?').bind(twentyFourHoursAgoISO).run();
        const existingUser = await env.DB.prepare('SELECT id FROM users WHERE phone_number = ?').bind(phoneNumber).first();
        if (existingUser) {
            return errorResponse('This phone number has been registered, please log in directly.', 'USER_ALREADY_EXISTS', 410);
        }
        const existingCode = await env.DB.prepare('SELECT expires_at FROM verification_codes WHERE phone_number = ?').bind(phoneNumber).first();
        if (existingCode && Date.now() < existingCode.expires_at) {
            return errorResponse('The verification code has been sent, please do not make frequent requests.', 'VERIFICATION_CODE_ACTIVE', 429);
        }
        const countStmt = env.DB.prepare("SELECT COUNT(*) as count FROM verification_attempts WHERE phone_number = ? AND created_at >= ?");
        const { count } = await countStmt.bind(phoneNumber, twentyFourHoursAgoISO).first();
        if (count >= CONFIG.MAX_VERIFICATION_SENDS_PER_DAY) {
            return errorResponse('The maximum limit for sending verification codes within 24 hours has been reached. Please try again later.', 'VERIFICATION_LIMIT_EXCEEDED', 429);
        }
        const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
        const finalApiUrl = smsApi.replace('Your+test+message', encodeURIComponent(`[Recrong] Your verification code is ${verificationCode}`));
        const smsResponse = await fetch(finalApiUrl);
        if (!smsResponse.ok) {
             const errorBody = await smsResponse.text();
             console.error("SMS API Error:", errorBody);
             return errorResponse(`SMS API call failed, status code: ${smsResponse.status}`, 'SMS_API_ERROR', 400);
        }
        const smsResult = await smsResponse.json();
        if (smsResult.message === "SMS sent successfully") {
            const expiresAt = Date.now() + VERIFICATION_CODE_EXPIRATION_MS;
            const { ip, userAgent } = getClientInfo(request);

            const batch = [
                env.DB.prepare('INSERT OR REPLACE INTO verification_codes (phone_number, code, api_key_temp, expires_at, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)').bind(phoneNumber, verificationCode, apiKey, expiresAt, ip, userAgent),
                env.DB.prepare('INSERT INTO verification_attempts (phone_number, ip_address, user_agent) VALUES (?, ?, ?)').bind(phoneNumber, ip, userAgent)
            ];
            await env.DB.batch(batch);
            return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
        } else {
            return errorResponse('SMS sending failed, please check API Key and number.', 'SMS_SEND_FAILED', 400);
        }
    } catch (e) {
        if (e instanceof SyntaxError) {
            return errorResponse('The request body is not a valid JSON.', 'INVALID_JSON', 400);
        }
        console.error("Register Error:", e);
        return errorResponse('Internal server error.', 'INTERNAL_SERVER_ERROR', 500);
    }
}

async function handleDeleteReminder(request, secureDB, userId, reminderId, env) {
    if (!await checkPermission(env, userId, PERM_MANAGE_TASKS)) {
        return errorResponse('No authority to delete tasks.', 'PERMISSION_DENIED_DELETE', 403);
    }
    try {
        const findStmt = await secureDB.prepare('SELECT id FROM reminders WHERE id = ? AND user_id = ?');
        const existingReminder = await findStmt.bind(reminderId, userId).first();
        if (!existingReminder) {
            return errorResponse('Reminder does not exist or has no authority to delete.', 'REMINDER_NOT_FOUND', 404);
        }
        const deleteStmt = await secureDB.prepare('DELETE FROM reminders WHERE id = ?');
        await deleteStmt.bind(reminderId).run();
        await logUserAction(secureDB, userId, 'delete_reminder', request, { reminderId });
        return new Response(JSON.stringify({ success: true, message: 'Reminder deleted successfully!', code: 'MSG_REMINDER_DELETED' }), { headers: { 'Content-Type': 'application/json' } });
    } catch (e) {
        console.error("Delete Reminder Error:", e);
        return errorResponse('Internal server error.', 'INTERNAL_SERVER_ERROR', 500);
    }
}

async function handleSendDirect(request, env, secureDB, user) {
    if (!await checkPermission(env, user.id, PERM_CLIENT_TIMERS)) {
        return errorResponse("Not authorized to use the browser's scheduled sending function.", 'PERMISSION_DENIED_CLIENT', 403);
    }
    const { from_number, body } = await request.json();
    if (!from_number || !body) {
        return errorResponse('The sending number and content cannot be empty.', 'MISSING_SENDER_OR_BODY', 400);
    }
    if (!/^\d+$/.test(from_number)) {
        return errorResponse('The sending number must be a pure number.', 'INVALID_PHONE_FORMAT', 400);
    }
    const fullUser = await env.DB.prepare('SELECT api_key, daily_sms_limit FROM users WHERE id = ?').bind(user.id).first();
    if (!fullUser) return errorResponse('User data is abnormal.', 'USER_DATA_ERROR', 500);
    const twentyFourHoursAgoISO = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const countStmt = env.DB.prepare("SELECT COUNT(*) as count FROM user_actions WHERE user_id = ? AND action_type = 'sent_sms' AND created_at >= ?");
    const { count: sentInLast24h } = await countStmt.bind(user.id, twentyFourHoursAgoISO).first();
    if (sentInLast24h >= fullUser.daily_sms_limit) {
        await logUserAction(secureDB, user.id, 'quota_exceeded_direct', request, { limit: fullUser.daily_sms_limit });
        return errorResponse('The daily sending limit has been reached.', 'QUOTA_EXCEEDED', 429);
    }
    const url = `https://${CONFIG.SMS_API_DOMAIN}/sms/send/${user.phone}?apikey=${fullUser.api_key}&from=${from_number}&body=${encodeURIComponent(body)}`;
    try {
        const smsResponse = await fetch(url);
        let isSuccess = false;
        let apiResponse = null;
        if (smsResponse.ok) {
            const text = await smsResponse.text();
            try { apiResponse = JSON.parse(text.replace(/'/g, '"')); } catch(e) {}
            if (apiResponse && apiResponse.message === "SMS sent successfully") {
                isSuccess = true;
            }
        }
        if (isSuccess) {
            await logUserAction(secureDB, user.id, 'sent_sms', request, { type: 'client_timer', from: from_number, body: encodeURIComponent(body)});
            await env.DB.prepare('UPDATE users SET total_sms_count = total_sms_count + 1 WHERE id = ?').bind(user.id).run();
            return new Response(JSON.stringify({ success: true, message: 'Sent successfully!', code: 'MSG_SEND_SUCCESS' }), { headers: { 'Content-Type': 'application/json' } });
        } else {
            const reason = apiResponse ? JSON.stringify(apiResponse) : `HTTP ${smsResponse.status}`;
            await logUserAction(secureDB, user.id, 'sms_failed_direct', request, { reason });
            return errorResponse('SMS API call failed:' + reason, 'SMS_API_ERROR', 502);
        }
    } catch (e) {
        console.error("Direct Send Error:", e);
        await logUserAction(secureDB, user.id, 'sms_exception_direct', request, { error: e.message });
        return errorResponse('An error occurred during the sending process.', 'INTERNAL_SERVER_ERROR_SENT', 500);
    }
}