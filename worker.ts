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

// تابع کمکی برای پیدا کردن UUID کاربر از روی آدرس درخواست ساب یا وب‌سوکت
function extractUUID(request: Request): string | null {
	const url = new URL(request.url);
	const pathName = url.pathname;
	
	if (pathName.startsWith('/sub/')) {
		return pathName.split('/')[2] || null;
	}
	
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
			// ۱. اندپوینت مدیریت کاربران مخفی (ساخت، حذف و تمدید از طریق لینک)
			// -----------------------------------------------------------------
			if (path === 'manage-users') {
				const secret = url.searchParams.get('secret');
				const action = url.searchParams.get('action'); 
				const uuid = url.searchParams.get('uuid');
				const quota = url.searchParams.get('quota') || "50"; 
				const name = url.searchParams.get('name') || "User";

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
					return new Response(`User [${uuid}] has been deleted.`, { status: 200 });
				}
				return new Response('Invalid action.', { status: 400 });
			}

			// -----------------------------------------------------------------
			// ۲. لایه کنترل ترافیک و حجم کاربران از دیتابیس D1
			// -----------------------------------------------------------------
			init(request, env);
			const userUUID = extractUUID(request);
			
			if (userUUID && env.DB) {
				const user: any = await env.DB.prepare(
					"SELECT total_quota_gb, used_quota_bytes, status FROM users WHERE uuid = ?"
				).bind(userUUID).first();

				if (user) {
					const totalBytes = user.total_quota_gb * 1024 * 1024 * 1024;
					if (user.used_quota_bytes >= totalBytes || user.status !== 'active') {
						return new Response('Traffic Limit Exceeded or Account Expired.', { 
							status: 403,
							headers: { 'Content-Type': 'text/plain; charset=utf-8' }
						});
					}
					globalThis.currentUserD1 = user;
				}
			}

			// -----------------------------------------------------------------
			// ۳. هدایت درخواست‌ها به هسته اصلی پنل وب BPB و وب‌سوکت‌ها
			// -----------------------------------------------------------------
			const upgradeHeader = request.headers.get('Upgrade');
			if (upgradeHeader === 'websocket') {
				initWs(env);
				return await handleWebsocket(request, ctx);
			} else {
				initHttp(request, env);

				// باز کردن دسترسی به صفحات پنل اصلی مدیریت
				if (pathName === '/' || path === 'panel' || path === 'login' || path === 'api') {
					// فراخوانی مستقیم توابع پنل اصلی بدون مسدودسازی
					if (path === 'login') return await handleLogin(request, env);
					if (path === 'logout') return logout();
					return await handlePanel(request, env); 
				}

				switch (path) {
					case 'sub':
						// فقط اگر کاربر در دیتابیس مجاز بود لینک ساب کار کند
						if (globalThis.currentUserD1) {
							return await handleSubscriptions(request, env);
						}
						return new Response('Invalid or Unauthorized Subscription Link', { status: 403 });

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
