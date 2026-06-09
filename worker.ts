import { init, initHttp, initWs } from '@init';
import {
	fallback,
	serveIcon,
	renderSecrets,
	handlePanel,
	handleSubscriptions,
	handleLogin,
	logout,
	renderError,
	handleWebsocket,
	handleDoH,
	handleProxyIPs
} from '@handlers';

// تابع کمکی برای پیدا کردن UUID کاربر از روی آدرس درخواست
function extractUUID(request: Request): string | null {
	const url = new URL(request.url);
	const pathName = url.pathname;
	
	// ۱. اگر درخواست برای لینک ساب‌اسکریپشن باشد: /sub/UUID
	if (pathName.startsWith('/sub/')) {
		return pathName.split('/')[2] || null;
	}
	
	// ۲. اگر درخواست اتصال فیلترشکن (WebSocket) باشد
	const encodedPathConfig = pathName.replace("/", "");
	try {
		const decoded = JSON.parse(atob(encodedPathConfig));
		return decoded.uuid || null; 
	} catch (e) {
		return null;
	}
}

export default {
	async fetch(request: Request, env: any, ctx: ExecutionContext) {
		try {
			const url = new URL(request.url);
			const pathName = url.pathname;
			const path = pathName.split('/')[1];

			// -----------------------------------------------------------------
			// --- بخش ۱: اندپوینت مدیریت کاربران مخفی (ساخت، حذف و تمدید) ---
			// -----------------------------------------------------------------
			if (path === 'manage-users') {
				const secret = url.searchParams.get('secret');
				const action = url.searchParams.get('action'); // add, delete
				const uuid = url.searchParams.get('uuid');
				const quota = url.searchParams.get('quota') || "50"; // پیش‌فرض ۵۰ گیگ
				const name = url.searchParams.get('name') || "User";

				// لایه امنیتی: حتماً این رمز را به یک عبارت سخت تغییر بده
				if (secret !== "YOUR_SECRET_ADMIN_PASSWORD") {
					return new Response('Unauthorized', { status: 401 });
				}

				if (!uuid) return new Response('UUID is required', { status: 400 });

				if (action === 'add' && env.DB) {
					await env.DB.prepare(
						"INSERT OR REPLACE INTO users (uuid, name, total_quota_gb, used_quota_bytes, status) VALUES (?, ?, ?, 0, 'active')"
					).bind(uuid, name, parseFloat(quota)).run();
					return new Response(`User [${name}] created/updated successfully with ${quota} GB.`, { status: 200 });
				}
				
				if (action === 'delete' && env.DB) {
					await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
					return new Response(`User [${uuid}] has been deleted from database.`, { status: 200 });
				}
				return new Response('Invalid action. Use action=add or action=delete', { status: 400 });
			}

			// -----------------------------------------------------------------
			// --- بخش ۲: لایه امنیتی فیلتر حجم و وضعیت کاربران از دیتابیس D1 ---
			// -----------------------------------------------------------------
			const upgradeHeader = request.headers.get('Upgrade');
			init(request, env);

			const userUUID = extractUUID(request);
			if (userUUID && env.DB) {
				// استعلام زنده وضعیت حجم کاربر از دیتابیس D1
				const user: any = await env.DB.prepare(
					"SELECT total_quota_gb, used_quota_bytes, status FROM users WHERE uuid = ?"
				).bind(userUUID).first();

				if (user) {
					const totalBytes = user.total_quota_gb * 1024 * 1024 * 1024;
					
					// اگر حجم تمام شده بود یا کاربر مسدود شده بود، اتصال را کاملاً قطع کن
					if (user.used_quota_bytes >= totalBytes || user.status !== 'active') {
						return new Response('Traffic Limit Exceeded or Account Expired.', { 
							status: 403,
							headers: { 'Content-Type': 'text/plain; charset=utf-8' }
						});
					}
					// ذخیره اطلاعات کاربر در حافظه موقت برای استفاده در هندلر ساب‌اسکریپشن
					globalThis.currentUserD1 = user;
				}
			}
			// -----------------------------------------------------------------

			if (upgradeHeader === 'websocket') {
				initWs(env);
				// پاس دادن پارامتر ctx برای عملیات‌های پس‌زمینه در VLESS
				return await handleWebsocket(request, ctx);
			} else {
				initHttp(request, env);

				switch (path) {
					case 'panel':
						return await handlePanel(request, env);

					case 'sub':
						return await handleSubscriptions(request, env);

					case 'login':
						return await handleLogin(request, env);

					case 'logout':
						return logout();

					case 'secrets':
						return await renderSecrets();

					case 'favicon.ico':
						return await serveIcon();

					case 'dns-query':
						return await handleDoH(request);

					case 'proxy-ip':
						return await handleProxyIPs(request, env);

					default:
						return await fallback(request);
				}
			}
		} catch (error) {
			return await renderError(error);
		}
	}
}
