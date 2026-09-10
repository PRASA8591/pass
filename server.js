const path = require('path');
const express = require('express');
require('dotenv').config();

const app = express();
const port = Number(process.env.PORT || 3000);

app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control', 'no-store');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' https://www.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https://time.prasatek.lk https://api.qrserver.com; font-src 'self' https://fonts.gstatic.com data:; connect-src 'self' https://www.gstatic.com https://*.googleapis.com https://*.gstatic.com https://*.firebaseapp.com https://*.firebaseio.com https://*.google.com; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"
  );
  next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.listen(port, () => console.log(`Pass vault running at http://localhost:${port}`));
