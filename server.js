require('dotenv').config();
const express = require('express');
const session = require('express-session');
const axios   = require('axios');
const path    = require('path');

const app = express();

const CONFIG = {
  CLIENT_ID    : process.env.DISCORD_CLIENT_ID,
  CLIENT_SECRET: process.env.DISCORD_CLIENT_SECRET,
  REDIRECT_URI : process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback',
  GUILD_ID     : process.env.GUILD_ID,
  SECRET       : process.env.SESSION_SECRET || 'secret123',
  PORT         : process.env.PORT || 3000,
  ALLOWED_ROLES: [
    '1501989817578160295',
    '1505994864301572096',
    '1501989817578160291',
    '1501989817578160292',
    '1501989817569902651',
    '1502159718943166586',
    '1501989817569902650',
    '1501989817569902648',
  ],
};

app.use(session({
  secret: CONFIG.SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 1000 * 60 * 60 * 8 },
}));

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login.html');
}

// Stockage des logs en mémoire
let logsMemoire = [];

// Route pour recevoir les logs depuis FiveM via webhook
app.post('/webhook/logs', (req, res) => {
  const { type, message, level, source } = req.body;
  logsMemoire.push({
    id     : logsMemoire.length,
    timeStr: new Date().toLocaleTimeString('fr-FR'),
    level  : level || 'INFO',
    source : source || type || 'fivem',
    message: message || JSON.stringify(req.body),
    raw    : JSON.stringify(req.body),
  });
  if (logsMemoire.length > 1000) logsMemoire.shift();
  res.json({ ok: true });
});

// Route root
app.get('/', (req, res) => {
  res.redirect('/login.html');
});

// OAuth Discord
app.get('/auth/discord', (req, res) => {
  const params = new URLSearchParams({
    client_id    : CONFIG.CLIENT_ID,
    redirect_uri : CONFIG.REDIRECT_URI,
    response_type: 'code',
    scope        : 'identify guilds',
  });
  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});

app.get('/auth/callback', async (req, res) => {
  const { code } = req.query;
  if (!code) return res.redirect('/login.html?error=no_code');

  try {
    const tokenRes = await axios.post(
      'https://discord.com/api/oauth2/token',
      new URLSearchParams({
        client_id    : CONFIG.CLIENT_ID,
        client_secret: CONFIG.CLIENT_SECRET,
        grant_type   : 'authorization_code',
        code         : code,
        redirect_uri : CONFIG.REDIRECT_URI,
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );

    const access_token = tokenRes.data.access_token;

    const userRes = await axios.get('https://discord.com/api/users/@me', {
      headers: { Authorization: 'Bearer ' + access_token },
    });
    const user = userRes.data;

    const guildsRes = await axios.get('https://discord.com/api/users/@me/guilds', {
      headers: { Authorization: 'Bearer ' + access_token },
    });
    const guilds = guildsRes.data;
    const inGuild = guilds.some(g => g.id === CONFIG.GUILD_ID);

    if (!inGuild) return res.redirect('/login.html?error=no_permission');

    req.session.user = {
      id      : user.id,
      username: user.username,
      avatar  : user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
        : 'https://cdn.discordapp.com/embed/avatars/0.png',
    };

    res.redirect('/panel.html');

  } catch (err) {
    console.error('[AUTH ERROR]', err.response?.data || err.message);
    res.redirect('/login.html?error=auth_failed');
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/login.html');
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json(req.session.user);
});

app.get('/api/logs', requireAuth, (req, res) => {
  res.json({ ok: true, logs: logsMemoire.slice(-500) });
});

app.listen(CONFIG.PORT, () => {
  console.log('\n✅  FiveM Log Panel démarré sur http://localhost:' + CONFIG.PORT);
  console.log('🔐  Discord OAuth → /auth/discord');
  console.log('📋  Rôles autorisés : ' + CONFIG.ALLOWED_ROLES.length + ' rôles');
  console.log('📡  Webhook FiveM → POST http://localhost:' + CONFIG.PORT + '/webhook/logs\n');
});
