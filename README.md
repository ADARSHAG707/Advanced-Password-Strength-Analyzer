🧠 CipherSense – Advanced Password Strength Analyzer

# 🔐 CipherSense – Advanced Password Strength Analyzer

A sleek and intelligent password analyzer built with **Python (Tkinter)** that visualizes password strength using entropy, regex, and breach checks — all in real time.  
It’s a cybersecurity-focused desktop app that helps users understand how strong (or weak) their passwords really are. 💡

---

## 🚀 Features

✅ Real-time password strength analysis  
✅ Entropy-based scoring system  
✅ Detects weak patterns and repeated characters  
✅ Color-coded strength heatmap visualization  
✅ Checks password breach status via HaveIBeenPwned API  
✅ Export results to **CSV** or **JSON**  
✅ Minimal yet modern **Tkinter GUI**  
✅ Tracks analysis history for multiple passwords  

---

 🧠 How It Works

CipherSense evaluates passwords using:
- **Entropy formula** (bit-based randomness calculation)  
- **Regex pattern matching** for uppercase, lowercase, digits, and special chars  
- **Scoring system** (0–10 scale) with strength levels:  
  `Very Weak → Weak → Medium → Strong → Very Strong`  
- **HaveIBeenPwned API** to check if a password was exposed in public breaches  

---

## 🖼️ GUI Preview

💡 _Add your screenshots here:_


/screenshots/main_ui.png
/screenshots/analysis_result.png


---
🧾 Export Options

Export Results (CSV):
Saves analyzed passwords and scores to password_analysis.csv

Export Results (JSON):
Saves all history with details like entropy, score, and breach info.

🧰 Tech Stack
Component	Technology
Language	Python 3.8+
GUI	Tkinter
API	HaveIBeenPwned
Data	CSV, JSON
Styling	Custom dark mode Tkinter theme

🧑‍💻 Author
👤 Adarsh AG
