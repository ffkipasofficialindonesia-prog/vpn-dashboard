VPN DASHBOARD - GMAIL OTP REGISTRATION PATCH

Files:
- server.js: adds /api/auth/register/request-otp and /api/auth/register/verify
- app.js: adds member registration UI on the login screen
- package.json: adds nodemailer dependency

GMAIL SMTP CONFIGURATION (.env on VPS; do not upload .env to GitHub)
GMAIL_USER=your-sender@gmail.com
GMAIL_APP_PASSWORD=your-16-character-google-app-password

Use a Google App Password, not the normal Gmail password. App Passwords require 2-Step Verification on the Google account.

After replacing the files on the VPS:
1. cd /var/www/vpn-dashboard
2. npm install
3. Add the two GMAIL_* variables to .env using a secure editor.
4. node --check server.js
5. node --check public/app.js
6. pm2 restart vpn-dashboard
7. pm2 save

Registration behavior:
- New member registers with username, Gmail address, and password.
- A six-digit OTP is sent to that email and expires in 10 minutes.
- OTP resend is limited to once per 60 seconds per email.
- OTP verification allows up to five attempts.
- Successful verification creates an active member with Rp0 balance and SG2 access, then logs the member in.
- Existing admin/member username-password login is unchanged.
- Pending OTP data is held in memory; a server restart invalidates outstanding OTPs.

Do not share or commit the Gmail App Password, .env, or VPN API keys.
