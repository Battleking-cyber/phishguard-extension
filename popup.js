
const form = document.getElementById('form');
const urlInput = document.getElementById('url');
const result = document.getElementById('result');
const riskEl = document.getElementById('risk');
const bar = document.getElementById('bar');
const details = document.getElementById('details');

function render(info) {
  result.style.display = 'block';
  riskEl.textContent = String(info.risk);
  bar.value = info.risk;
  const cls = info.risk >= 50 ? 'bad' : info.risk >= 30 ? 'warn' : 'good';
  riskEl.className = `risk ${cls}`;
  details.textContent = [
    `URL: ${info.url}`,
    `Scheme: ${info.scheme}`,
    `Host: ${info.netloc}`,
    `Path: ${info.path}`,
    `Reasons: ${info.reasons.join(' | ')}`
  ].join('\n');
}

form.addEventListener('submit', (e) => {
  e.preventDefault();
  const raw = urlInput.value.trim();
  const url = raw.match(/^https?:\/\//i) ? raw : `http://${raw}`;
  chrome.runtime.sendMessage({ type: 'PHISHGUARD_CHECK_URL', url }, (info) => {
    info.url = url;
    render(info);
  });
});

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs[0]?.url) urlInput.value = tabs[0].url;
});
