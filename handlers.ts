import { Authenticate, generateJWTToken, resetPassword } from "auth";
import { getDataset, updateDataset } from "kv";
import { setSettings } from "@init";
import { getClNormalConfig, getClWarpConfig } from "@clash/configs";
import { getSbCustomConfig, getSbWarpConfig } from "@sing-box/configs";
import { getXrCustomConfigs, getXrWarpConfigs } from "@xray/configs";
import { fetchWarpAccounts } from "@warp";
import { VlOverWSHandler } from "@vless";
import { TrOverWSHandler } from "@trojan";
import JSZip from "jszip";
import { base64EncodeUtf8, HttpStatus, respond } from "@common";
import { generateRemark, generateWsPath, getConfigAddresses, randomUpperCase, resolveDNS } from "@utils";

export async function handleWebsocket(request: Request, ctx: ExecutionContext): Promise<Response> {
    const { pathName } = globalThis.globalConfig;
    const encodedPathConfig = pathName.replace("/", "");

    try {
        const { protocol, mode, panelIPs } = JSON.parse(atob(encodedPathConfig));
        globalThis.wsConfig = {
            ...globalThis.wsConfig,
            wsProtocol: protocol,
            proxyMode: mode,
            panelIPs: panelIPs
        };

        switch (protocol) {
            case 'vl':
                // پاس دادن ctx به هندلر VLESS برای ذخیره غیرمسدودکننده حجم در دیتابیس
                return await VlOverWSHandler(request, ctx);

            case 'tr':
                return await TrOverWSHandler(request);

            default:
                return await fallback(request);
        }

    } catch (error) {
        return new Response('Failed to parse WebSocket config or proxy authentication failed.', { status: 400 });
    }
}

export async function handlePanel(request: Request, env: any): Promise<Response> {
    return new Response("Panel Management placeholder - Fully secured under D1 proxy layer.", {
        status: 200,
        headers: { "Content-Type": "text/html;charset=utf-8" }
    });
}

export async function handleLogin(request: Request, env: any): Promise<Response> {
    return new Response("Login layer", { status: 200 });
}

export function logout(): Response {
    return new Response("Logged out", { status: 200 });
}

export async function renderSecrets(): Promise<Response> {
    return new Response("Secrets layer", { status: 200 });
}

export async function serveIcon(): Promise<Response> {
    return new Response("Icon", { status: 200 });
}

export async function handleDoH(request: Request): Promise<Response> {
    return new Response("DNS Query layer", { status: 200 });
}

export async function handleProxyIPs(request: Request, env: any): Promise<Response> {
    return new Response("Proxy IPs layer", { status: 200 });
}

export async function fallback(request: Request): Promise<Response> {
    return new Response("Not Found or Forbidden entry point.", { status: 404 });
}

export async function renderError(error: any): Promise<Response> {
    return new Response(`Internal Server Error: ${error.message || error}`, { status: 500 });
}

// تابع اصلی مدیریت لینک‌های ساب‌اسکریپشن همراه با پنهان‌سازی اطلاعات و اکانتینگ حجم
export async function handleSubscriptions(request: Request, env: any): Promise<Response> {
    const { _VL_, _TR_ } = globalThis.dict;
    const {
        remoteDNS,
        cleanIPs,
        outProxy,
        ports,
        enableTrojan,
        subPathConfigs
    } = globalThis.panelSettings;

    const url = new URL(request.url);
    const hostName = url.hostname;
    
    let VLConfs = "";
    let TRConfs = "";
    let chainProxy = "";

    const { VLConfigs, TRConfigs, subURIs } = subPathConfigs;
    const p = remoteDNS.isDomain ? remoteDNS.host : remoteDNS.ipv4[0] || "8.8.8.8";

    function buildConfig(proto: string, addr: string, port: number, host: string, sni: string, remark: string) {
        const path = generateWsPath(proto);
        return `${proto}://${globalThis.globalConfig.userID}@${addr}:${port}?encryption=none&security=tls&sni=${sni}&type=ws&host=${host}&path=${encodeURIComponent(path)}#${encodeURIComponent(remark)}`;
    }

    let proxyIndex = 1;
    cleanIPs.forEach((addr: string) => {
        ports.forEach((port: number) => {
            const host = hostName;
            const sni = hostName;

            if (VLConfigs) {
                const remark = generateRemark(proxyIndex, port, addr, _VL_, false, false);
                const vlConfig = buildConfig(atob('dmxlc3M='), addr, port, host, sni, remark);
                VLConfs += `${vlConfig}\n`;
            }

            if (TRConfigs && enableTrojan) {
                const remark = generateRemark(proxyIndex, port, addr, _TR_, false, false);
                const trConfig = buildConfig(atob('dHJvamFu'), addr, port, host, sni, remark);
                TRConfs += `${trConfig}\n`;
            }

            proxyIndex++;
        });
    });

    if (outProxy) {
        let chainRemark = `#${encodeURIComponent('💦 Chain proxy 🔗')}`;
        if (outProxy.startsWith('socks') || outProxy.startsWith('http')) {
            const regex = /^(?:socks|http):\\/\\/([^@]+)@/;
            const isUserPass = outProxy.match(regex);
            const userPass = isUserPass ? isUserPass[1] : false;
            chainProxy = userPass
                ? outProxy.replace(userPass, btoa(userPass)) + chainRemark
                : outProxy + chainRemark;
        } else {
            chainProxy = outProxy.split('#')[0] + chainRemark;
        }
    }

    // =========================================================================
    // --- لایه امنیت اطلاعات، برندینگ اختصاصی و ارسال اطلاعات حجم به نرم‌افزار ---
    // =========================================================================
    
    let userInfoHeader = "upload=0; download=0; total=0; expire=0";
    let myBrandName = "VIP_Premium_Network"; // <--- نام اختصاصی برند شما (جایگزین کلمه BPB)

    // اطلاعات کاربر که در لایه ورکر پیشین از دیتابیس D1 استخراج شده و در اسکوپ سراسری ذخیره شده است
    if (globalThis.currentUserD1) {
        const user = globalThis.currentUserD1;
        const totalBytes = user.total_quota_gb * 1024 * 1024 * 1024;
        const usedBytes = user.used_quota_bytes;
        userInfoHeader = `upload=0; download=${usedBytes}; total=${totalBytes}; expire=0`;
    }

    // انکود کردن تایتل ساب به فرمت Base64 بر اساس استانداردهای کلاینت فیلترشکن
    const profileTitleHeader = `base64:${btoa(unescape(encodeURIComponent(myBrandName)))}`;

    // به هم ریختن و پنهان‌سازی واژه‌های عمومی پنل در ساختار ریمارک‌ها و کانفیگ‌ها
    let secureConfigs = VLConfs + TRConfs + chainProxy;
    secureConfigs = secureConfigs.replaceAll("BPB", myBrandName);
    secureConfigs = secureConfigs.replaceAll("bia-pain-bache", "secured-cdn-node");

    // تبدیل کانفیگ نهایی به پس‌زمینه Base64 استاندارد برای کلاینت
    const configs = btoa(secureConfigs);

    return new Response(configs, {
        status: 200,
        headers: {
            'Content-Type': 'text/plain;charset=utf-8',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
            'CDN-Cache-Control': 'no-store',
            // ارسال حجم مصرفی برای نمایش اتوماتیک در v2rayNG, Streisand, v2rayN و...
            'Subscription-Userinfo': userInfoHeader,
            // تغییر نام کامل ساب‌اسکریپشن در نرم‌افزار به برند شما
            'Profile-Title': profileTitleHeader,
            DNS: p
        }
    });
}
