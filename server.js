require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStoreFactory = require('connect-sqlite3');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  console.error('ERROR: Set SESSION_SECRET in .env to a random string of at least 32 characters.');
  process.exit(1);
}
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'business-deals.sqlite');
const db = new Database(DB_FILE);
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 type TEXT NOT NULL CHECK(type IN ('Job Application','Business Idea','Business Deal')),
 name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT DEFAULT '',
 subject TEXT NOT NULL, details TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'Pending',
 reply TEXT DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS admin_users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 password_hash TEXT NOT NULL
);
`);
const adminUsername = process.env.ADMIN_USERNAME || 'admin';
const adminPassword = process.env.ADMIN_PASSWORD || '';
if (!adminPassword || adminPassword.length < 10) {
  console.error('ERROR: Set ADMIN_PASSWORD in .env to a strong password of at least 10 characters.');
  process.exit(1);
}
const existingAdmin = db.prepare('SELECT id FROM admin_users WHERE username = ?').get(adminUsername);
if (!existingAdmin) {
  db.prepare('INSERT INTO admin_users (username,password_hash) VALUES (?,?)')
    .run(adminUsername, bcrypt.hashSync(adminPassword, 12));
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '20kb' }));
app.use(session({
  store: new (SQLiteStoreFactory(session))({ db: 'sessions.sqlite', dir: __dirname }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000 * 60 * 60 * 4 }
}));
app.use((req, res, next) => {
  if (!req.session.csrfToken) req.session.csrfToken = crypto.randomBytes(24).toString('hex');
  res.locals.csrf = req.session.csrfToken;
  res.locals.admin = Boolean(req.session.adminId);
  next();
});
function csrf(req, res, next) {
  const token = req.body._csrf;
  if (!token || token !== req.session.csrfToken) return res.status(403).send(page('Security check failed', '<p>Reload the page and try again.</p>'));
  next();
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 8, standardHeaders: 'draft-7', legacyHeaders: false, message: 'Too many login attempts. Try again later.' });
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt = s => esc(s).replace(/\r?\n/g, '<br>');
function layout(title, content, admin=false) {
 return `<!doctype html><html lang="bn"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="description" content="Business Deals — jobs, business ideas and business opportunities in one place"><title>${esc(title)} | Business Deals</title>
 <style>
 :root{--navy:#0b2045;--blue:#1556a4;--purple:#7438d5;--yellow:#ffd23f;--text:#12264a;--muted:#64748b;--line:#dce5f4}
 *{box-sizing:border-box}body{margin:0;background:linear-gradient(180deg,#f4f7ff,#fff 65%,#f8f4ff);font-family:system-ui,-apple-system,Segoe UI,sans-serif;color:var(--text);line-height:1.55}
 header{background:linear-gradient(105deg,#071b3c,#123d70 65%,#38217a);color:#fff}nav{max-width:1120px;margin:auto;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;gap:15px;flex-wrap:wrap}.brand{font-size:1.25rem;font-weight:900}.brand span{color:var(--yellow)}nav a{color:#fff;text-decoration:none;margin-left:14px;font-weight:650}
 main{max-width:1120px;margin:auto;padding:28px 20px 60px}.hero{padding:38px 30px;border-radius:24px;color:#fff;background:linear-gradient(115deg,#071b3c,#164e91 56%,#7736b7);box-shadow:0 18px 45px #173c7829}.eyebrow{color:var(--yellow);font-size:.78rem;letter-spacing:2px;font-weight:900;text-transform:uppercase}.hero h1{font-size:clamp(2.1rem,5vw,3.8rem);line-height:1.08;margin:12px 0}.hero h1 span{color:var(--yellow)}.hero p{color:#e1edff;max-width:700px}.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:20px 0}.card{background:#fff;border:1px solid var(--line);border-radius:18px;padding:21px;box-shadow:0 10px 28px #263b680c}.blue{background:linear-gradient(145deg,#eff6ff,#fff);border-color:#c8ddff}.green{background:linear-gradient(145deg,#e9fff4,#fff);border-color:#b8f0d3}.orange{background:linear-gradient(145deg,#fff2e8,#fff);border-color:#ffd5b8}.purple{background:linear-gradient(145deg,#f4edff,#fff);border-color:#dfcaff}.muted{color:var(--muted)}label{display:block;font-weight:750;margin:13px 0 6px}input,select,textarea{width:100%;border:1px solid #d5dfef;background:#fbfcff;color:#142341;padding:12px;border-radius:11px;font:inherit}textarea{min-height:120px;resize:vertical}.btn{display:inline-block;background:linear-gradient(135deg,#ffdf4f,#ffb91d);color:#142341;border:0;border-radius:11px;padding:11px 17px;font-weight:850;cursor:pointer;text-decoration:none;margin-top:12px}.btn.purplebtn{background:linear-gradient(135deg,#6637ee,#a53cff);color:#fff}.btn.gray{background:#eaf0ff;color:#173e80}.notice{padding:13px 15px;border-radius:12px;background:#fff8df;border:1px solid #f3d58c;color:#765312;margin:18px 0}.flash{padding:13px 15px;border-radius:12px;background:#e3faef;border:1px solid #a8ebcd;color:#075e3d;margin:15px 0}.error{background:#fff0f2;border-color:#ffc6cf;color:#9f1239}.row{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.tag{display:inline-block;padding:4px 9px;border-radius:999px;background:#e8efff;color:#254b91;font-size:.8rem}.Pending{background:#fff1c2;color:#885b00}.Accepted{background:#d8faeb;color:#08794f}.Rejected{background:#ffe2e8;color:#b42345}.Replied{background:#e9ddff;color:#6429bd}.application{border:1px solid var(--line);border-radius:15px;padding:17px;margin:12px 0;background:#fcfdff}.application h3{margin:8px 0}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.stat{background:linear-gradient(135deg,#eef5ff,#f4edff);border:1px solid #e2e8fa;border-radius:14px;padding:15px}.stat strong{display:block;font-size:1.6rem;color:#6337d8}.reply{background:#f3f6fc;border-radius:10px;padding:12px;margin-top:8px}footer{background:linear-gradient(105deg,#071b3c,#123d70 65%,#38217a);padding:25px 20px;color:#d8e5fb;text-align:center}
 @media(max-width:760px){.grid{grid-template-columns:1fr}.stats{grid-template-columns:1fr}.hero{padding:28px 22px}nav a{margin-left:0;margin-right:10px}}
 </style></head><body><header><nav><a class="brand" href="/">🤝 Business <span>Deals</span></a><div><a href="/">Home</a><a href="/#submit">Submit</a><a href="/admin">Admin</a></div></nav></header><main>${content}</main><footer>© ${new Date().getFullYear()} Business Deals · Jobs • Ideas • Opportunities</footer></body></html>`;
}
function page(title, content) { return layout(title, content); }

app.get('/', (req,res) => {
 const ok = req.query.sent === '1';
 const content = `
 <section class="hero"><div class="eyebrow">Ideas • Opportunities • Growth</div><h1>Make your next move<br>with <span>Business Deals.</span></h1><p>চাকরির আবেদন, নতুন ব্যবসার আইডিয়া এবং ব্যবসায়িক ডিল—সব এক জায়গায় জমা দিন। আপনার প্রস্তাব আমরা পর্যালোচনা করব।</p><a class="btn" href="#submit">Get Started →</a></section>
 ${ok?'<div class="flash">আপনার আবেদন সফলভাবে জমা হয়েছে। ধন্যবাদ!</div>':''}
 <section class="grid"><div class="card blue"><h2>💼 Job Apply</h2><p>আপনার জন্য সঠিক চাকরির সুযোগ খুঁজুন এবং আবেদন জমা দিন।</p><a class="btn" href="#submit">Apply Now →</a></div><div class="card green"><h2>💡 Business Ideas</h2><p>আপনার আইডিয়া শেয়ার করুন, বড় কিছু শুরু করুন।</p><a class="btn" href="#submit">Share Idea →</a></div><div class="card orange"><h2>🤝 Business Deals</h2><p>পার্টনারশিপ, বিনিয়োগ ও ব্যবসায়িক ডিলের প্রস্তাব দিন।</p><a class="btn" href="#submit">View Deals →</a></div></section>
 <section id="submit" class="card"><h2>Submit an application</h2><p class="muted">আপনার তথ্য দিন। * চিহ্নিত ঘরগুলো আবশ্যক।</p><form method="post" action="/apply">
 <input type="hidden" name="_csrf" value="${res.locals.csrf}">
 <label for="type">Application type *</label><select id="type" name="type" required><option>Job Application</option><option>Business Idea</option><option>Business Deal</option></select>
 <label for="name">Full name *</label><input id="name" name="name" maxlength="100" required>
 <label for="email">Email *</label><input id="email" name="email" type="email" maxlength="150" required>
 <label for="phone">Phone / WhatsApp</label><input id="phone" name="phone" maxlength="40">
 <label for="subject">Title / Position / Deal name *</label><input id="subject" name="subject" maxlength="160" required>
 <label for="details">Details *</label><textarea id="details" name="details" maxlength="5000" required></textarea>
 <button class="btn" type="submit">Submit application →</button></form></section>
 <div class="notice">নিরাপত্তা: আবেদনগুলো সার্ভারের ডেটাবেসে সংরক্ষিত হয়। ব্যক্তিগত/সংবেদনশীল তথ্য অপ্রয়োজনে জমা দেবেন না।</div>`;
 res.send(page('Home',content));
});
app.post('/apply', csrf, (req,res) => {
 const {type,name,email,phone='',subject,details}=req.body;
 if (!['Job Application','Business Idea','Business Deal'].includes(type) || !name?.trim() || !email?.trim() || !subject?.trim() || !details?.trim())
   return res.status(400).send(page('Invalid application','<div class="card"><h2>তথ্য অসম্পূর্ণ</h2><p>সব আবশ্যক ঘর পূরণ করে আবার চেষ্টা করুন।</p><a class="btn" href="/">Back</a></div>'));
 if ([name,email,phone,subject,details].some(v=>String(v).length>5000)) return res.status(400).send(page('Invalid application','<div class="card">Input too long.</div>'));
 db.prepare('INSERT INTO applications(type,name,email,phone,subject,details) VALUES(?,?,?,?,?,?)')
   .run(type,name.trim(),email.trim(),phone.trim(),subject.trim(),details.trim());
 res.redirect('/?sent=1');
});
app.get('/admin', (req,res) => {
 if (!req.session.adminId) {
   return res.send(page('Admin Login',`<div class="card" style="max-width:520px;margin:auto"><h1>🔐 Admin Login</h1><p class="muted">শুধু অনুমোদিত অ্যাডমিনের জন্য।</p>${req.query.error?'<div class="flash error">লগইন তথ্য সঠিক নয়।</div>':''}<form method="post" action="/admin/login"><input type="hidden" name="_csrf" value="${res.locals.csrf}"><label for="username">Username</label><input id="username" name="username" autocomplete="username" required><label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password" required><button class="btn purplebtn" type="submit">Login →</button></form></div>`));
 }
 const rows = db.prepare('SELECT * FROM applications ORDER BY id DESC LIMIT 500').all();
 const counts = db.prepare("SELECT COUNT(*) total, SUM(status='Pending') pending, SUM(reply != '') replied FROM applications").get();
 const cards = rows.map(a=>`<article class="application"><div class="row"><span class="tag">${esc(a.type)}</span><span class="tag ${esc(a.status)}">${esc(a.status)}</span></div><h3>${esc(a.subject)}</h3><p><strong>${esc(a.name)}</strong> · <a href="mailto:${encodeURIComponent(a.email)}">${esc(a.email)}</a>${a.phone?' · '+esc(a.phone):''}</p><p>${fmt(a.details)}</p><small class="muted">Submitted: ${esc(a.created_at)}</small>
 <form method="post" action="/admin/application/${a.id}"><input type="hidden" name="_csrf" value="${res.locals.csrf}"><label for="status${a.id}">Status</label><select id="status${a.id}" name="status">${['Pending','Accepted','Rejected','Replied'].map(s=>`<option ${a.status===s?'selected':''}>${s}</option>`).join('')}</select><label for="reply${a.id}">Reply</label><textarea id="reply${a.id}" name="reply" maxlength="5000">${esc(a.reply)}</textarea><button class="btn purplebtn" type="submit">Save reply & status</button></form>${a.reply?`<div class="reply"><strong>Saved reply:</strong><br>${fmt(a.reply)}</div>`:''}
 <form method="post" action="/admin/application/${a.id}/delete" onsubmit="return confirm('Delete this application?')"><input type="hidden" name="_csrf" value="${res.locals.csrf}"><button class="btn gray" type="submit">Delete application</button></form></article>`).join('');
 res.send(layout('Admin Dashboard',`<div class="row"><div><div class="eyebrow">Private workspace</div><h1>Admin Dashboard</h1><p class="muted">আবেদন দেখুন, উত্তর দিন এবং স্ট্যাটাস আপডেট করুন।</p></div><form method="post" action="/admin/logout"><input type="hidden" name="_csrf" value="${res.locals.csrf}"><button class="btn gray" type="submit">Log out</button></form></div><div class="stats"><div class="stat">Total<strong>${counts.total||0}</strong></div><div class="stat">Pending<strong>${counts.pending||0}</strong></div><div class="stat">Replied<strong>${counts.replied||0}</strong></div></div><h2>All applications (${rows.length})</h2>${cards||'<div class="card muted">এখনো কোনো আবেদন জমা পড়েনি।</div>'}`,true));
});
app.post('/admin/login', loginLimiter, csrf, (req,res) => {
 const user = db.prepare('SELECT * FROM admin_users WHERE username=?').get(String(req.body.username||''));
 if (!user || !bcrypt.compareSync(String(req.body.password||''),user.password_hash)) return res.redirect('/admin?error=1');
 req.session.regenerate(err => {
   if (err) return res.status(500).send('Session error');
   req.session.adminId=user.id;
   req.session.csrfToken=crypto.randomBytes(24).toString('hex');
   res.redirect('/admin');
 });
});
function requireAdmin(req,res,next){if(!req.session.adminId)return res.redirect('/admin');next();}
app.post('/admin/application/:id', requireAdmin, csrf, (req,res) => {
 const status=String(req.body.status||'');
 const reply=String(req.body.reply||'').trim();
 if(!['Pending','Accepted','Rejected','Replied'].includes(status)||reply.length>5000)return res.status(400).send(page('Invalid update','<div class="card">Invalid status or reply too long.</div>'));
 const nextStatus=reply && status==='Pending'?'Replied':status;
 db.prepare('UPDATE applications SET status=?,reply=?,updated_at=CURRENT_TIMESTAMP WHERE id=?').run(nextStatus,reply,Number(req.params.id));
 res.redirect('/admin');
});
app.post('/admin/application/:id/delete', requireAdmin, csrf, (req,res) => {
 db.prepare('DELETE FROM applications WHERE id=?').run(Number(req.params.id));res.redirect('/admin');
});
app.post('/admin/logout', requireAdmin, csrf, (req,res)=>req.session.destroy(()=>res.redirect('/')));
app.use((req,res)=>res.status(404).send(page('Not found','<div class="card"><h1>404</h1><p>Page not found.</p><a class="btn" href="/">Go home</a></div>')));
app.listen(PORT,()=>console.log(`Business Deals running on http://localhost:${PORT}`));
