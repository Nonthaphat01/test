const express = require('express');
const { rateLimit } = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Load .env automatically so PROMPTPAY_ID works when running `npm start`.
const ENV_FILE = path.join(__dirname, '.env');
if (fs.existsSync(ENV_FILE)) {
  try {
    for (const line of fs.readFileSync(ENV_FILE, 'utf8').split(/\r?\n/)) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/);
      if (!m || line.trim().startsWith('#')) continue;
      let value = m[2];
      if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
      if (process.env[m[1]] === undefined) process.env[m[1]] = value;
    }
  } catch (_) {}
}

const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const cookieSession = require('cookie-session');
const multer = require('multer');
const generatePromptPayPayload = require('promptpay-qr');
const QRCode = require('qrcode');

const userLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'TOO_MANY_LOGIN_ATTEMPTS' }
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 5,
  standardHeaders: 'draft-8',
  legacyHeaders: false,
  message: { error: 'TOO_MANY_LOGIN_ATTEMPTS' }
});

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

// กำหนดพาร์ธสำหรับเก็บข้อมูลและสลิป โดยบังคับใช้ /tmp บน Vercel
const DATA_DIR = process.env.VERCEL ? path.join('/tmp', 'data') : path.join(__dirname, 'data');
const SLIP_DIR = process.env.VERCEL ? path.join('/tmp', 'slips') : path.join(DATA_DIR, 'slips');

// ระบบ Lazy Initialization + Smart Copy Database ไปที่ /tmp เพื่อป้องกัน Read-only และข้อมูลหาย
let _db = null;
function getDb() {
  if (!_db) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.mkdirSync(SLIP_DIR, { recursive: true });

    const targetDbPath = path.join(DATA_DIR, 'mumu.db');
    const bundledDbPath = path.join(__dirname, 'data', 'mumu.db');

    if (!fs.existsSync(targetDbPath) && fs.existsSync(bundledDbPath)) {
      try {
        fs.copyFileSync(bundledDbPath, targetDbPath);
      } catch (err) {
        console.error('Failed to copy bundled db:', err);
      }
    }

    if (fs.existsSync(targetDbPath)) {
      try {
        fs.chmodSync(targetDbPath, 0o666);
      } catch (e) {}
    }

    _db = new Database(targetDbPath);
    _db.pragma('journal_mode = WAL');
    
    _db.exec(`
      CREATE TABLE IF NOT EXISTS products (
        id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
        image TEXT NOT NULL, packages_json TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY, user_id INTEGER, product_id TEXT, product_title TEXT NOT NULL,
        package_name TEXT NOT NULL, target_account TEXT NOT NULL, price REAL NOT NULL,
        payment_method TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
        delivered_text TEXT DEFAULT '', created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT UNIQUE, password_hash TEXT, balance REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT ''
      );
      CREATE TABLE IF NOT EXISTS admin_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS wallet_transactions (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, type TEXT NOT NULL, amount REAL NOT NULL, balance_after REAL NOT NULL, reference_id TEXT DEFAULT '', description TEXT NOT NULL, created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS deposit_requests (
        id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, amount REAL NOT NULL, status TEXT NOT NULL DEFAULT 'pending', slip_path TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT NOT NULL, reviewed_at TEXT DEFAULT ''
      );
    `);

    const seedProducts = [
      ['prod-netflix','Netflix Premium 4K','app','https://images.unsplash.com/photo-1574375927938-d5a98e8ffe85?q=80&w=400&auto=format&fit=crop',JSON.stringify([{name:'1 จอ (30 วัน) 4K Ultra HD',price:129},{name:'เหมาจอส่วนตัว (30 วัน)',price:429}])],
      ['prod-valorant','Valorant Points (VP)','game','https://images.unsplash.com/photo-1542751371-adc38448a05e?q=80&w=400&auto=format&fit=crop',JSON.stringify([{name:'475 VP',price:150},{name:'1,000 VP',price:300},{name:'2,050 VP',price:600}])],
      ['prod-youtube','YouTube Premium','app','https://images.unsplash.com/photo-1611162617213-7d7a39e9b1d7?q=80&w=400&auto=format&fit=crop',JSON.stringify([{name:'Family Plan (1 เดือน)',price:45},{name:'Family Plan (3 เดือน)',price:125}])],
      ['prod-freefire','Free Fire Diamonds','game','https://images.unsplash.com/photo-1538481199705-c710c4e965fc?q=80&w=400&auto=format&fit=crop',JSON.stringify([{name:'100 Diamonds',price:35},{name:'520 Diamonds',price:160}])]
    ];
    const insertProduct = _db.prepare('INSERT OR IGNORE INTO products (id,title,category,image,packages_json,created_at) VALUES (?,?,?,?,?,?)');
    for (const p of seedProducts) insertProduct.run(...p, new Date().toISOString());

    function addColumnIfMissing(table, column, definition){
      const cols = _db.prepare(`PRAGMA table_info(${table})`).all().map(x=>x.name);
      if(!cols.includes(column)) { try { _db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`); } catch(e) {} }
    }
    addColumnIfMissing('orders','user_id','INTEGER');
    addColumnIfMissing('orders','product_id','TEXT');
    addColumnIfMissing('orders','product_title',"TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing('orders','package_name',"TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing('orders','target_account',"TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing('orders','price','REAL NOT NULL DEFAULT 0');
    addColumnIfMissing('orders','payment_method',"TEXT NOT NULL DEFAULT 'wallet'");
    addColumnIfMissing('orders','status',"TEXT NOT NULL DEFAULT 'pending'");
    addColumnIfMissing('orders','delivered_text',"TEXT DEFAULT ''");
    addColumnIfMissing('orders','created_at',"TEXT NOT NULL DEFAULT ''");
    addColumnIfMissing('users','email','TEXT');
    addColumnIfMissing('users','password_hash','TEXT');
    addColumnIfMissing('users','created_at',"TEXT NOT NULL DEFAULT ''");

    _db.prepare("DELETE FROM users WHERE id=1 AND name='Demo Customer' AND (email IS NULL OR email='')").run();
    
    const adminUser = String(process.env.ADMIN_USERNAME || 'admin').trim();
    const adminPass = String(process.env.ADMIN_PASSWORD || 'change-me-now');
    const existingAdmin = _db.prepare('SELECT id FROM admin_users WHERE username=?').get(adminUser);
    if (!existingAdmin) {
      _db.prepare('INSERT INTO admin_users (username,password_hash) VALUES (?,?)').run(adminUser, bcrypt.hashSync(adminPass, 12));
    } else if (process.env.ADMIN_PASSWORD) {
      _db.prepare('UPDATE admin_users SET password_hash=? WHERE username=?').run(bcrypt.hashSync(adminPass, 12), adminUser);
    }
  }
  return _db;
}

// สร้าง Proxy สำหรับเชื่อมต่อฐานข้อมูลโดยไม่ต้องแก้โค้ดด้านล่าง
const db = new Proxy({}, {
  get(_, prop) {
    const database = getDb();
    const value = database[prop];
    return typeof value === 'function' ? value.bind(database) : value;
  }
});

app.use(express.json({limit:'100kb'}));
const uploadSlip = multer({ storage: multer.diskStorage({
  destination: (_, __, cb) => cb(null, SLIP_DIR),
  filename: (_, file, cb) => cb(null, `${Date.now()}-${Math.random().toString(36).slice(2)}${path.extname(file.originalname).toLowerCase()}`)
}), limits: { fileSize: 5 * 1024 * 1024 }, fileFilter: (_, file, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype)) });

if (
  !process.env.SESSION_SECRET ||
  process.env.SESSION_SECRET === 'dev-only-change-me'
) {
  throw new Error('SESSION_SECRET must be configured');
}

app.use(cookieSession({name:'mumu_session', keys:[process.env.SESSION_SECRET || 'dev-only-change-me'], httpOnly:true, sameSite:'lax', secure:process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000}));

function getCsrfToken(req) {
  if (!req.session.csrfToken) {
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
  }
  return req.session.csrfToken;
}

function csrfProtection(req, res, next) {
  if (!req.path.startsWith('/api/')) return next();
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method.toUpperCase())) {
    return next();
  }
  const expected = req.session?.csrfToken;
  const provided = req.get('X-CSRF-Token');
  if (typeof expected !== 'string' || typeof provided !== 'string') {
    return res.status(403).json({ error: 'CSRF_INVALID' });
  }
  const expectedBuffer = Buffer.from(expected);
  const providedBuffer = Buffer.from(provided);
  if (
    expectedBuffer.length !== providedBuffer.length ||
    !crypto.timingSafeEqual(expectedBuffer, providedBuffer)
  ) {
    return res.status(403).json({ error: 'CSRF_INVALID' });
  }
  next();
}

app.use(csrfProtection);

function requireAdmin(req,res,next){ if (!req.session.admin) return res.status(401).json({error:'ADMIN_REQUIRED'}); next(); }
function requireUser(req,res,next){ if (!req.session.user) return res.status(401).json({error:'LOGIN_REQUIRED'}); next(); }
function products(){ return db.prepare('SELECT * FROM products ORDER BY created_at ASC').all().map(p=>({...p,packages:JSON.parse(p.packages_json)})); }
function orders(userId){ return userId ? db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY rowid DESC').all(userId) : db.prepare('SELECT * FROM orders ORDER BY rowid DESC').all(); }
function user(userId){ return userId ? db.prepare('SELECT id,name,email,balance FROM users WHERE id=?').get(userId) : null; }
function transactions(userId){ return userId ? db.prepare('SELECT * FROM wallet_transactions WHERE user_id=? ORDER BY id DESC').all(userId) : []; }
function deposits(userId){ return userId ? db.prepare('SELECT * FROM deposit_requests WHERE user_id=? ORDER BY created_at DESC').all(userId) : db.prepare('SELECT d.*, u.name AS user_name, u.email AS user_email FROM deposit_requests d JOIN users u ON u.id=d.user_id ORDER BY d.created_at DESC').all(); }

app.get('/api/bootstrap',(req,res)=>{
  res.set('Cache-Control','no-store');
  const u=user(req.session.user?.id);
  const isAdmin=!!req.session.admin;
  const userCount=db.prepare('SELECT COUNT(*) AS count FROM users').get().count;
  const adminUsers=isAdmin ? db.prepare('SELECT id,name,email,balance,created_at FROM users ORDER BY id DESC').all() : [];
  const visibleOrders=isAdmin ? db.prepare('SELECT o.*, u.name AS user_name, u.email AS user_email FROM orders o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.rowid DESC').all() : (u ? orders(u.id) : []);
  res.json({csrfToken:getCsrfToken(req), products:products(), orders:visibleOrders, transactions:u?transactions(u.id):[], deposits:u?deposits(u.id):[], adminDeposits:isAdmin?deposits():[], adminUsers, user:u, userAuth:!!u, adminAuth:isAdmin, userCount});
});

app.post('/api/auth/register',(req,res)=>{
  const name=String(req.body?.name||'').trim(), email=String(req.body?.email||'').trim().toLowerCase(), password=String(req.body?.password||'');
  if(name.length<2 || name.length>80) return res.status(400).json({error:'INVALID_NAME'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({error:'INVALID_EMAIL'});
  if(password.length<6 || password.length>100) return res.status(400).json({error:'INVALID_PASSWORD'});
  if(db.prepare('SELECT id FROM users WHERE email=?').get(email)) return res.status(409).json({error:'EMAIL_EXISTS'});
  const info=db.prepare('INSERT INTO users (name,email,password_hash,balance,created_at) VALUES (?,?,?,?,?)').run(name,email,bcrypt.hashSync(password,12),0,new Date().toISOString());
  req.session.user={id:info.lastInsertRowid,email}; res.status(201).json({ok:true,user:user(Number(info.lastInsertRowid))});
});

app.post('/api/auth/login', userLoginLimiter, (req,res)=>{
 const email=String(req.body?.email||'').trim().toLowerCase(), password=String(req.body?.password||''); const row=db.prepare('SELECT * FROM users WHERE email=?').get(email); if(!row || !row.password_hash || !bcrypt.compareSync(password,row.password_hash)) return res.status(401).json({error:'INVALID_CREDENTIALS'}); req.session.user={id:row.id,email:row.email}; res.json({ok:true,user:user(row.id)}); });

app.post('/api/auth/change-password',requireUser,(req,res)=>{
  const currentPassword=String(req.body?.currentPassword||'');
  const newPassword=String(req.body?.newPassword||'');
  if(newPassword.length<6 || newPassword.length>100) return res.status(400).json({error:'INVALID_PASSWORD'});
  if(currentPassword===newPassword) return res.status(400).json({error:'PASSWORD_UNCHANGED'});
  const row=db.prepare('SELECT id,password_hash FROM users WHERE id=?').get(req.session.user.id);
  if(!row || !row.password_hash || !bcrypt.compareSync(currentPassword,row.password_hash)) return res.status(400).json({error:'INVALID_CURRENT_PASSWORD'});
  db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(bcrypt.hashSync(newPassword,12),row.id);
  res.set('Cache-Control','no-store').json({ok:true});
});

app.post('/api/auth/logout',(req,res)=>{ const admin=req.session.admin; req.session=null; if(admin) req.session={admin}; res.json({ok:true}); });

app.post('/api/admin/login', adminLoginLimiter, (req,res)=>{
  const username=String(req.body?.username||'').trim();
  const password=String(req.body?.password||'');
  if (!username || !password) return res.status(400).json({error:'MISSING_CREDENTIALS'});
  const row=db.prepare('SELECT * FROM admin_users WHERE username=?').get(username);
  if(!row || !bcrypt.compareSync(password,row.password_hash)) return res.status(401).json({error:'INVALID_CREDENTIALS'});
  req.session.admin={id:row.id,username:row.username}; res.json({ok:true});
});

app.post('/api/admin/logout',(req,res)=>{req.session=null;res.json({ok:true});});

app.post('/api/orders',requireUser,(req,res)=>{
  const productId=String(req.body?.productId||'');
  const packageName=String(req.body?.packageName||'');
  const price=Number(req.body?.price);
  const targetAccount=String(req.body?.targetAccount||'').trim();
  const paymentMethod=String(req.body?.paymentMethod||'wallet');
  if(paymentMethod !== 'wallet') return res.status(400).json({error:'WALLET_ONLY'});
  if(!productId || !packageName || !Number.isFinite(price) || price<=0) return res.status(400).json({error:'INVALID_ORDER'});
  if(!targetAccount || targetAccount.length>200) return res.status(400).json({error:'INVALID_TARGET'});
  const p=db.prepare('SELECT * FROM products WHERE id=?').get(productId);
  if(!p) return res.status(400).json({error:'PRODUCT_NOT_FOUND'});
  let packages=[]; try { packages=JSON.parse(p.packages_json||'[]'); } catch(e) { return res.status(500).json({error:'PRODUCT_DATA_INVALID'}); }
  const pkg=packages.find(x=>String(x.name)===packageName && Number(x.price)===price);
  if(!pkg) return res.status(400).json({error:'PACKAGE_NOT_FOUND'});
  try {
    const result=db.transaction(()=>{
      const u=user(req.session.user.id);
      if(!u) throw new Error('USER_NOT_FOUND');
      if(Number(u.balance) < price) throw new Error('INSUFFICIENT_BALANCE');
      const id='MUMU-'+Date.now().toString().slice(-6)+'-'+Math.floor(10+Math.random()*90);
      const newBalance=Number(u.balance)-price;
      db.prepare('UPDATE users SET balance=? WHERE id=?').run(newBalance,u.id);
      db.prepare('INSERT INTO orders (id,user_id,product_id,product_title,package_name,target_account,price,payment_method,status,delivered_text,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
        .run(id,u.id,p.id,p.title,pkg.name,targetAccount,price,'wallet','pending','',new Date().toISOString());
      db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)')
        .run(u.id,'debit',-price,newBalance,id,`ซื้อ ${p.title} - ${pkg.name}`,new Date().toISOString());
      return {id,user:user(u.id)};
    })();
    res.status(201).json({ok:true,id:result.id,user:result.user});
  } catch(e) {
    console.error('Create order error:',e);
    res.status(400).json({error:e.message||'ORDER_CREATE_FAILED'});
  }
});

app.post('/api/orders/cart',requireUser,(req,res)=>{
  const items=Array.isArray(req.body?.items)?req.body.items:[];
  if(!items.length || items.length>50) return res.status(400).json({error:'INVALID_CART'});
  const normalized=[];
  for(const raw of items){
    const productId=String(raw?.productId||'');
    const packageName=String(raw?.packageName||'');
    const targetAccount=String(raw?.targetAccount||'').trim();
    if(!productId || !packageName || !targetAccount || targetAccount.length>200) return res.status(400).json({error:'INVALID_CART_ITEM'});
    const p=db.prepare('SELECT * FROM products WHERE id=?').get(productId);
    if(!p) return res.status(400).json({error:'PRODUCT_NOT_FOUND'});
    let packages=[]; try { packages=JSON.parse(p.packages_json||'[]'); } catch(e) { return res.status(500).json({error:'PRODUCT_DATA_INVALID'}); }
    const pkg=packages.find(x=>String(x.name)===packageName);
    if(!pkg || !Number.isFinite(Number(pkg.price)) || Number(pkg.price)<=0) return res.status(400).json({error:'PACKAGE_NOT_FOUND'});
    normalized.push({product:p,pkg,packageName,targetAccount,price:Number(pkg.price)});
  }
  const total=normalized.reduce((sum,x)=>sum+x.price,0);
  try{
    const result=db.transaction(()=>{
      const u=user(req.session.user.id);
      if(!u) throw new Error('USER_NOT_FOUND');
      if(Number(u.balance)<total) throw new Error('INSUFFICIENT_BALANCE');
      const checkoutId='MUMU-CART-'+Date.now().toString().slice(-8)+'-'+Math.floor(10+Math.random()*90);
      let balance=Number(u.balance);
      const created=[];
      for(const item of normalized){
        const id='MUMU-'+Date.now().toString().slice(-6)+'-'+Math.floor(10+Math.random()*90);
        balance-=item.price;
        db.prepare('INSERT INTO orders (id,user_id,product_id,product_title,package_name,target_account,price,payment_method,status,delivered_text,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)')
          .run(id,u.id,item.product.id,item.product.title,item.pkg.name,item.targetAccount,item.price,'wallet','pending','',new Date().toISOString());
        created.push(id);
      }
      db.prepare('UPDATE users SET balance=? WHERE id=?').run(balance,u.id);
      db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)')
        .run(u.id,'debit',-total,balance,checkoutId,`ชำระตะกร้าสินค้า ${created.length} รายการ`,new Date().toISOString());
      return {checkoutId,orderIds:created,total,user:user(u.id)};
    })();
    res.status(201).json({ok:true,...result});
  }catch(e){
    console.error('Create cart order error:',e);
    res.status(400).json({error:e.message||'CART_CHECKOUT_FAILED'});
  }
});

const PROMPTPAY_ID = String(process.env.PROMPTPAY_ID || '').replace(/[^0-9]/g, '');
app.post('/api/wallet/deposit', requireUser, uploadSlip.single('slip'), async (req,res)=>{
  try {
    const amount=Number(req.body?.amount);
    const note=String(req.body?.note||'').slice(0,300);
    if(!Number.isFinite(amount)||amount<1||amount>100000) return res.status(400).json({error:'INVALID_AMOUNT'});
    if(!PROMPTPAY_ID) return res.status(503).json({error:'PROMPTPAY_NOT_CONFIGURED'});
    if(!req.file) return res.status(400).json({error:'SLIP_REQUIRED'});
    const id='DEP-'+Date.now()+'-'+Math.floor(100+Math.random()*900);
    const payload=generatePromptPayPayload(PROMPTPAY_ID,{amount});
    const qrDataUrl=await QRCode.toDataURL(payload,{width:320,margin:2});
    db.prepare('INSERT INTO deposit_requests (id,user_id,amount,status,slip_path,note,created_at) VALUES (?,?,?,?,?,?,?)').run(id,req.session.user.id,amount,'pending','/uploads/slips/'+req.file.filename,note,new Date().toISOString());
    res.status(201).json({ok:true,id,amount,qr:qrDataUrl,promptpayId:PROMPTPAY_ID});
  } catch(e){ if(req.file) try{fs.unlinkSync(path.join(SLIP_DIR,req.file.filename));}catch(_){}; res.status(500).json({error:'DEPOSIT_CREATE_FAILED'}); }
});

app.get('/api/wallet/deposit-qr', requireUser, async (req,res)=>{
  const amount=Number(req.query?.amount); if(!PROMPTPAY_ID||!Number.isFinite(amount)||amount<1||amount>100000) return res.status(400).json({error:'INVALID_REQUEST'});
  try { const payload=generatePromptPayPayload(PROMPTPAY_ID,{amount}); const qr=await QRCode.toDataURL(payload,{width:320,margin:2}); res.json({qr,promptpayId:PROMPTPAY_ID,amount}); } catch(e){ console.error('PromptPay QR error:', e); res.status(500).json({error:'QR_FAILED'}); }
});

app.get('/api/admin/deposits/:id/slip', requireAdmin, (req,res)=>{
  const d=db.prepare('SELECT slip_path FROM deposit_requests WHERE id=?').get(req.params.id);
  if(!d || !d.slip_path) return res.status(404).send('Slip not found');
  const file=path.basename(d.slip_path);
  const full=path.join(SLIP_DIR,file);
  if(!fs.existsSync(full)) return res.status(404).send('Slip not found');
  res.sendFile(full);
});

app.post('/api/admin/deposits/:id/approve', requireAdmin, (req,res)=>{
  const tx=db.transaction(()=>{
    const d=db.prepare('SELECT * FROM deposit_requests WHERE id=?').get(req.params.id);
    if(!d || d.status!=='pending') throw new Error('DEPOSIT_NOT_FOUND_OR_NOT_PENDING');
    const u=user(d.user_id); if(!u) throw new Error('USER_NOT_FOUND');
    const newBalance=u.balance+d.amount;
    db.prepare('UPDATE users SET balance=? WHERE id=?').run(newBalance,d.user_id);
    db.prepare("UPDATE deposit_requests SET status='approved',reviewed_at=? WHERE id=?").run(new Date().toISOString(),d.id);
    db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)').run(d.user_id,'credit',d.amount,newBalance,d.id,'เติมเงิน Wallet ผ่าน PromptPay',new Date().toISOString());
  });
  try{tx();res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}
});

app.post('/api/admin/deposits/:id/reject', requireAdmin, (req,res)=>{
  const r=db.prepare("UPDATE deposit_requests SET status='rejected',reviewed_at=? WHERE id=? AND status='pending'").run(new Date().toISOString(),req.params.id);
  if(!r.changes)return res.status(404).json({error:'DEPOSIT_NOT_FOUND_OR_NOT_PENDING'});res.json({ok:true});
});

app.post('/api/admin/deposits/bulk-approve', requireAdmin, (req,res)=>{
  const rawIds=req.body?.depositIds;
  if(!Array.isArray(rawIds) || rawIds.length<1 || rawIds.length>100) return res.status(400).json({error:'INVALID_DEPOSIT_IDS'});
  const depositIds=[...new Set(rawIds.map(id=>String(id||'').trim()).filter(Boolean))];
  if(depositIds.length!==rawIds.length) return res.status(400).json({error:'INVALID_DEPOSIT_IDS'});
  try {
    const approved=db.transaction(()=>{
      const getDeposit=db.prepare("SELECT * FROM deposit_requests WHERE id=?");
      const getUser=db.prepare('SELECT id,balance FROM users WHERE id=?');
      const creditUser=db.prepare('UPDATE users SET balance=? WHERE id=?');
      const approve=db.prepare("UPDATE deposit_requests SET status='approved',reviewed_at=? WHERE id=? AND status='pending'");
      const addTx=db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)');
      const done=[];
      for(const id of depositIds){
        const d=getDeposit.get(id);
        if(!d || d.status!=='pending') throw new Error('DEPOSIT_NOT_FOUND_OR_NOT_PENDING:'+id);
        const u=getUser.get(d.user_id);
        if(!u) throw new Error('USER_NOT_FOUND:'+id);
        const now=new Date().toISOString();
        const balance=Number(u.balance)+Number(d.amount);
        const changed=approve.run(now,id);
        if(!changed.changes) throw new Error('DEPOSIT_NOT_FOUND_OR_NOT_PENDING:'+id);
        creditUser.run(balance,d.user_id);
        addTx.run(d.user_id,'credit',d.amount,balance,d.id,'เติมเงิน Wallet ผ่าน PromptPay',now);
        done.push(id);
      }
      return done;
    })();
    res.json({ok:true,approved,count:approved.length});
  } catch(e) {
    const notPending=String(e.message||'').startsWith('DEPOSIT_NOT_FOUND_OR_NOT_PENDING');
    console.error('Bulk approve deposits error:',e);
    res.status(notPending?409:400).json({error:notPending?'DEPOSIT_NOT_FOUND_OR_NOT_PENDING':(String(e.message||'').startsWith('USER_NOT_FOUND')?'USER_NOT_FOUND':'DEPOSIT_BULK_APPROVE_FAILED')});
  }
});

app.post('/api/admin/orders/bulk-complete', requireAdmin, (req,res)=>{
  const rawIds = req.body?.orderIds;
  const deliveredTexts = req.body?.deliveredTexts;
  if(!Array.isArray(rawIds) || rawIds.length < 1 || rawIds.length > 100) {
    return res.status(400).json({error:'INVALID_ORDER_IDS'});
  }
  const orderIds = [...new Set(rawIds.map(id=>String(id||'').trim()).filter(Boolean))];
  if(orderIds.length !== rawIds.length) return res.status(400).json({error:'INVALID_ORDER_IDS'});
  if(!deliveredTexts || typeof deliveredTexts !== 'object' || Array.isArray(deliveredTexts)) {
    return res.status(400).json({error:'INVALID_DELIVERED_TEXTS'});
  }
  try {
    const result = db.transaction(()=>{
      const getOrder = db.prepare("SELECT id,status,user_id FROM orders WHERE id=?");
      const complete = db.prepare("UPDATE orders SET status='completed', delivered_text=? WHERE id=? AND status='pending'");
      const completed = [];
      let selectedOwnerId = null;
      for(const id of orderIds){
        const order = getOrder.get(id);
        if(!order || order.status !== 'pending') throw new Error('ORDER_NOT_FOUND_OR_NOT_PENDING:'+id);
        if(selectedOwnerId === null) selectedOwnerId = order.user_id;
        else if(String(selectedOwnerId ?? '') !== String(order.user_id ?? '')) throw new Error('MIXED_ORDER_OWNERS');
        const text = String(deliveredTexts[id] || 'เติมเงินเข้าไอดีเรียบร้อยแล้ว').trim().slice(0,1000);
        const changed = complete.run(text,id);
        if(!changed.changes) throw new Error('ORDER_NOT_FOUND_OR_NOT_PENDING:'+id);
        completed.push(id);
      }
      return completed;
    })();
    res.json({ok:true,completed:result,count:result.length});
  } catch(e) {
    console.error('Bulk complete orders error:',e);
    const notPending = String(e.message||'').startsWith('ORDER_NOT_FOUND_OR_NOT_PENDING');
    const mixedOwners = String(e.message||'') === 'MIXED_ORDER_OWNERS';
    res.status(notPending?409:(mixedOwners?400:500)).json({error:notPending?'ORDER_NOT_FOUND_OR_NOT_PENDING':(mixedOwners?'MIXED_ORDER_OWNERS':'ORDER_BULK_COMPLETE_FAILED'),details:notPending?String(e.message).split(':').slice(1).join(':'):undefined});
  }
});

app.post('/api/admin/orders/:id/complete',requireAdmin,(req,res)=>{
  const orderId=String(req.params.id||'');
  const text=String(req.body?.deliveredText||'เติมเงินเข้าไอดีเรียบร้อยแล้ว').trim().slice(0,1000);
  if(!orderId) return res.status(400).json({error:'INVALID_ORDER_ID'});
  try {
    const r=db.prepare("UPDATE orders SET status='completed', delivered_text=? WHERE id=? AND status='pending'").run(text,orderId);
    if(!r.changes) return res.status(404).json({error:'ORDER_NOT_FOUND_OR_NOT_PENDING'});
    res.json({ok:true,order:db.prepare('SELECT * FROM orders WHERE id=?').get(orderId)});
  } catch(e) { console.error('Complete order error:',e); res.status(500).json({error:'ORDER_COMPLETE_FAILED'}); }
});

app.post('/api/admin/orders/:id/cancel',requireAdmin,(req,res)=>{
  const orderId=String(req.params.id||'');
  try {
    const result=db.transaction(()=>{
      const order=db.prepare("SELECT * FROM orders WHERE id=? AND status='pending'").get(orderId);
      if(!order) throw new Error('ORDER_NOT_FOUND_OR_NOT_PENDING');
      const changed=db.prepare("UPDATE orders SET status='cancelled' WHERE id=? AND status='pending'").run(orderId);
      if(!changed.changes) throw new Error('ORDER_NOT_FOUND_OR_NOT_PENDING');
      if(String(order.payment_method||'wallet')==='wallet' && order.user_id){
        const u=user(order.user_id);
        if(!u) throw new Error('USER_NOT_FOUND');
        const refund=Number(order.price)||0;
        const newBalance=Number(u.balance)+refund;
        db.prepare('UPDATE users SET balance=? WHERE id=?').run(newBalance,order.user_id);
        db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)')
          .run(order.user_id,'credit',refund,newBalance,order.id,`คืนเงินจากการยกเลิกออเดอร์ ${order.id}`,new Date().toISOString());
        return {order:db.prepare('SELECT * FROM orders WHERE id=?').get(orderId),user:user(order.user_id),refunded:refund};
      }
      return {order:db.prepare('SELECT * FROM orders WHERE id=?').get(orderId),refunded:0};
    })();
    res.json({ok:true,...result});
  } catch(e) { console.error('Cancel order error:',e); res.status(400).json({error:e.message||'ORDER_CANCEL_FAILED'}); }
});

function normalizeProductPackages(input, legacyName, legacyPrice) {
  let raw = input;
  if (!Array.isArray(raw)) raw = [{ name: legacyName || 'แพ็กเกจเริ่มต้น', price: legacyPrice }];
  if (raw.length < 1 || raw.length > 100) throw new Error('INVALID_PACKAGES');
  const packages = raw.map((item) => {
    const name = String(item?.name || '').trim();
    const price = Number(item?.price);
    if (!name || name.length > 160 || !Number.isFinite(price) || price <= 0 || price > 10000000) throw new Error('INVALID_PACKAGES');
    return { name, price: Math.round(price * 100) / 100 };
  });
  const names = packages.map(p => p.name.toLocaleLowerCase());
  if (new Set(names).size !== names.length) throw new Error('DUPLICATE_PACKAGE_NAME');
  return packages;
}

app.post('/api/admin/products',requireAdmin,(req,res)=>{
  const {title,category,image,packageName,packagePrice,packages:packageInput}=req.body||{};
  const cleanTitle=String(title||'').trim();
  if(!cleanTitle || cleanTitle.length>160 || !['app','game'].includes(category)) return res.status(400).json({error:'INVALID_PRODUCT'});
  let packages;
  try { packages=normalizeProductPackages(packageInput,packageName,packagePrice); }
  catch(e) { return res.status(400).json({error:e.message||'INVALID_PACKAGES'}); }
  const id='prod-'+Date.now()+'-'+Math.random().toString(36).slice(2,7);
  db.prepare('INSERT INTO products VALUES (?,?,?,?,?,?)').run(id,cleanTitle,category,String(image||'').trim()||'https://images.unsplash.com/photo-1542751371-adc38448a05e?q=80&w=400&auto=format&fit=crop',JSON.stringify(packages),new Date().toISOString());
  res.status(201).json({ok:true,id});
});

app.put('/api/admin/products/:id',requireAdmin,(req,res)=>{
  const {title,category,image,packageName,packagePrice,packages:packageInput}=req.body||{};
  const cleanTitle=String(title||'').trim();
  if(!cleanTitle || cleanTitle.length>160 || !['app','game'].includes(category)) return res.status(400).json({error:'INVALID_PRODUCT'});
  const existing=db.prepare('SELECT id FROM products WHERE id=?').get(req.params.id);
  if(!existing) return res.status(404).json({error:'PRODUCT_NOT_FOUND'});
  let packages;
  try { packages=normalizeProductPackages(packageInput,packageName,packagePrice); }
  catch(e) { return res.status(400).json({error:e.message||'INVALID_PACKAGES'}); }
  db.prepare('UPDATE products SET title=?,category=?,image=?,packages_json=? WHERE id=?').run(
    cleanTitle, category,
    String(image||'').trim() || 'https://images.unsplash.com/photo-1542751371-adc38448a05e?q=80&w=400&auto=format&fit=crop',
    JSON.stringify(packages), req.params.id
  );
  res.json({ok:true});
});

app.delete('/api/admin/products/:id',requireAdmin,(req,res)=>{const r=db.prepare('DELETE FROM products WHERE id=?').run(req.params.id);if(!r.changes)return res.status(404).json({error:'PRODUCT_NOT_FOUND'});res.json({ok:true});});

app.get('/api/admin/users',requireAdmin,(req,res)=>{
    res.set('Cache-Control','no-store');
  try {
    const users=db.prepare('SELECT id,name,email,balance,created_at FROM users ORDER BY id DESC').all();
    res.json({users});
  } catch (e) {
    console.error('Admin users error:', e);
    res.status(500).json({error:'ADMIN_USERS_FAILED'});
  }
});

app.post('/api/admin/wallet/adjust',requireAdmin,(req,res)=>{
  const userId=Number(req.body?.userId);
  const amount=Number(req.body?.amount);
  if(!Number.isInteger(userId)||userId<=0||!Number.isFinite(amount)||amount===0||Math.abs(amount)>1000000) return res.status(400).json({error:'INVALID_REQUEST'});
  const tx=db.transaction(()=>{
    const u=user(userId);
    if(!u) throw new Error('USER_NOT_FOUND');
    const newBalance=Number(u.balance)+amount;
    if(amount<0 && newBalance<0) {
      throw new Error('INSUFFICIENT_BALANCE');
    }
    db.prepare('UPDATE users SET balance=? WHERE id=?').run(newBalance,userId);
    db.prepare('INSERT INTO wallet_transactions (user_id,type,amount,balance_after,reference_id,description,created_at) VALUES (?,?,?,?,?,?,?)')
      .run(userId,amount>0?'credit':'debit',amount,newBalance,'ADMIN-ADJUST','ปรับยอด Wallet โดยแอดมิน',new Date().toISOString());
    return user(userId);
  });
  try { res.json({ok:true,user:tx()}); } catch(e) { res.status(400).json({error:e.message}); }
});

app.get('/api/health',(req,res)=>res.json({ok:true,service:'mumu-topup',time:new Date().toISOString()}));

app.get('/admin',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use(express.static(path.join(__dirname,'public')));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  app.listen(PORT, HOST, ()=>console.log(`Mumu Topup-Premium Store\nServer listening on ${HOST}:${PORT}\nOn this PC: http://localhost:${PORT}`));
}

module.exports = app;
