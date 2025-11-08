
function analyzeUrlDetailed(urlString, baseHref) {
  const info = {
    scheme: '', netloc: '', path: '',
    url_length: (urlString||'').length,
    has_ip: false, has_https: false,
    suspicious_words: false,
    punycode: false,
    many_subdomains: false,
    suspicious_tld: false,
    hostname_long: false,
    known_tunnel_host: false,
    at_symbol: false,
    hyphen_heavy: false,
    many_params: false,
    brand_mismatch: false,
    reasons: [],
    risk: 0,
    url: urlString
  };

  const TUNNELS = ['ngrok.io','trycloudflare.com','pages.dev','glitch.me','surge.sh','vercel.app','netlify.app','herokuapp.com'];
  const SUSP_TLDS = ['zip','xyz','top','click','rest','work','skin','country','gq','tk','ml','cf','ga','cam','club','quest'];
  const WORDS_PATH = ['login','verify','update','signin','account','security','recover','password','wallet'];
  const WORDS_ANY = ['free','gift','bonus'];
  const BRANDS = ['google','microsoft','outlook','office','onedrive','facebook','meta','instagram','whatsapp','amazon','netflix','apple','github','paypal','bank','sbi','hdfc','icici','kotak','axis','flipkart','zoho','adobe','steam','tiktok','telegram'];

  try {
    const u = new URL(urlString, baseHref);
    info.scheme = u.protocol.replace(':','');
    info.netloc = u.host;
    info.path = u.pathname + u.search + u.hash;
    info.has_https = (u.protocol === 'https:');
    const host = u.hostname.toLowerCase();

    info.has_ip = /^\d+\.\d+\.\d+\.\d+$/.test(host);
    info.punycode = host.includes('xn--');

    const parts = host.split('.');
    const sldParts = parts.slice(0, -2); // rough
    const subdomainCount = Math.max(0, sldParts.length);
    info.many_subdomains = subdomainCount >= 3;

    const tld = parts[parts.length-1] || '';
    info.suspicious_tld = SUSP_TLDS.includes(tld);

    info.hostname_long = host.length > 30;

    info.known_tunnel_host = TUNNELS.some(t => host.endsWith(t));

    info.at_symbol = urlString.includes('@');

    const hyphenCount = (host.match(/-/g) || []).length;
    info.hyphen_heavy = hyphenCount >= 3;

    const paramCount = Array.from(new URLSearchParams(u.search)).length;
    info.many_params = paramCount >= 5;

    const lowerPath = (u.pathname + u.search).toLowerCase();
    const hasPathWord = WORDS_PATH.some(w => lowerPath.includes(w));
    const hasAnyWord = WORDS_ANY.some(w => urlString.toLowerCase().includes(w));
    info.suspicious_words = hasPathWord || hasAnyWord;

    const brandInPath = BRANDS.find(b => lowerPath.includes(b));
    const brandInHost = BRANDS.find(b => host.includes(b));
    info.brand_mismatch = !!brandInPath && !brandInHost;

    // Scoring
    let risk = 0;
    function add(points, reason) { if (points>0){ risk += points; info.reasons.push(`${reason} (+${points})`);} }

    add(info.has_ip ? 35 : 0, 'Host is raw IP');
    add(!info.has_https ? 35 : 0, 'Connection not HTTPS');
    add(info.punycode ? 25 : 0, 'Punycode hostname');
    add(info.many_subdomains ? 15 : 0, 'Many subdomains');
    add(info.suspicious_tld ? 15 : 0, 'Suspicious TLD');
    add(info.hostname_long ? 10 : 0, 'Unusually long hostname');
    add(info.known_tunnel_host ? 25 : 0, 'Known tunneling/temporary host');
    add(info.at_symbol ? 25 : 0, "'@' used in URL");
    add(info.hyphen_heavy ? 10 : 0, 'Hyphen-heavy host');
    add(info.many_params ? 10 : 0, 'Many query parameters');
    add(info.url_length > 120 ? 20 : info.url_length > 75 ? 10 : 0, 'Long URL');
    add(info.suspicious_words ? 25 : 0, 'Suspicious keywords in path');
    add(info.brand_mismatch ? 20 : 0, 'Brand in path not in domain');

    info.risk = Math.min(100, risk);
    info.url = u.href;
  } catch(e) {
    info.reasons.push('Invalid URL');
    info.risk = 0;
  }
  return info;
}

function showBanner(info) {
  if (document.getElementById('phishguard-banner')) return;
  const banner = document.createElement('div');
  banner.id = 'phishguard-banner';
  banner.innerHTML = `⚠️ Potentially risky site (<strong>${info.netloc || ''}</strong>) — score <strong>${info.risk}</strong>/100<br><small>${info.reasons.join(' · ')}</small>`;
  document.documentElement.appendChild(banner);
}

function scanLinks() {
  const anchors = Array.from(document.querySelectorAll('a[href]'));
  for (const a of anchors) {
    const href = a.getAttribute('href');
    const info = analyzeUrlDetailed(href, window.location.href);
    if (info.risk >= 30) {
      a.classList.add('phishguard-link');
      a.setAttribute('data-phishguard-risk', String(info.risk));
      a.title = `PhishGuard: ${info.risk}/100 – ${info.reasons.join(' • ')}`;
    }
  }
}

function clickGuard(e) {
  const a = e.target.closest('a[href]');
  if (!a) return;
  const riskAttr = a.getAttribute('data-phishguard-risk');
  const info = riskAttr ? { risk: parseInt(riskAttr,10) } : analyzeUrlDetailed(a.href);
  const risk = info.risk;
  if (risk >= 50) {
    const proceed = confirm(`PhishGuard warning:\nThis link looks risky (score ${risk}/100).\nProceed?`);
    if (!proceed) e.preventDefault();
  }
}

chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'PHISHGUARD_SHOW_BANNER') showBanner(msg.info);
});

scanLinks();
addEventListener('click', clickGuard, { capture: true });

let lastPath = location.href;
setInterval(() => {
  if (location.href !== lastPath) {
    lastPath = location.href;
    scanLinks();
  }
}, 1500);
