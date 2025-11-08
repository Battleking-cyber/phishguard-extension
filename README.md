# 🛡️ PhishGuard – Phishing Link Detector (Chrome Extension)

**PhishGuard** is a Chrome extension that automatically detects phishing links and warns users about suspicious sites.

## 🚀 Features
- Real-time link scanning
- Page banner warnings
- Risk score breakdown (0–100)
- Popup analyzer tool
- Works on any website

## 🧠 Heuristics
- IP address in URL
- Missing HTTPS
- Suspicious keywords (`login`, `verify`, `account`)
- Tunnel hosts (`trycloudflare.com`, `ngrok.io`)
- Brand mismatch in path
- Suspicious TLDs (`.zip`, `.xyz`, `.top`, etc.)

## 🧩 Installation (Developer Mode)
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `phishguard` folder

## 💡 Future Plans
- Google Safe Browsing API integration
- Machine-learning URL scoring
- Firefox/Edge support

---

Made with ❤️ by [Battleking]


🧭 For Users — How to Download and Set Up PhishGuard Extension
🔹 Option 1 — From GitHub ZIP (easiest)

Go to your repository page on GitHub:
👉 https://github.com/Battleking-cyber/phishguard-extension

Click the green “Code” button → choose Download ZIP
(or direct link: https://github.com/Battleking-cyber/phishguard-extension/archive/refs/heads/main.zip)

Extract the ZIP file on your computer — it will create a folder like:

phishguard-extension-main/


Inside, you’ll see files like:

manifest.json
background.js
content.js
popup.html
popup.js
styles.css
icons/


Open Google Chrome (or Edge/Brave).

In the address bar, go to:

chrome://extensions


Turn on the toggle for Developer mode (top-right corner).

Click Load unpacked.

Browse to and select the folder where manifest.json is located (e.g., phishguard-extension-main).

Done ✅
The PhishGuard icon should appear in your toolbar.

🔹 Option 2 — If you shared a ready ZIP (phishguard_v1_1.zip)

If users downloaded your ZIP file directly (for example, from a release):

Right-click → Extract All.

You’ll get a folder phishguard_v1_1.

Then follow steps 5–10 above.

🔹 To Verify It Works

Visit any site with many links (like Google search results).
→ Suspicious links show a red dashed outline.

Try a suspicious URL (like a trycloudflare.com tunnel).
→ You should see a banner or popup warning.

🔹 To Update

If you push new code to GitHub:

The user can delete the old extension from chrome://extensions.

Re-download the new ZIP and repeat the steps.
