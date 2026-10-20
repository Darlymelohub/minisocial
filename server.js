const express = require('express'), Database = require('better-sqlite3'), bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const db = new Database(process.env.DB_PATH || 'data.db');
const SECRET = process.env.JWT_SECRET || 'change-me-please';
db.exec(`
create table if not exists users(id integer primary key, name text unique, pass text, country text, bio text default '');
create table if not exists posts(id integer primary key, user_id int, text text, time int);
create table if not exists likes(post_id int, user_id int, primary key(post_id, user_id));
create table if not exists friends(user_id int, friend_id int, primary key(user_id, friend_id));`);
const app = express();
app.use(express.json({ limit: '20kb' }));
app.use(express.static('public'));
const sign = u => jwt.sign({ id: u.id }, SECRET, { expiresIn: '30d' });
const pub = u => ({ id: u.id, name: u.name, country: u.country, bio: u.bio });
function auth(req, res, next) {
  try { req.uid = jwt.verify((req.headers.authorization || '').slice(7), SECRET).id; next(); }
  catch (e) { res.status(401).json({ error: 'auth' }); }
}
app.post('/api/signup', (req, res) => {
  const { name = '', password = '', country = '' } = req.body;
  if (!/^[A-Za-z0-9_.-]{2,20}$/.test(name) || password.length < 4 || !country) return res.status(400).json({ error: 'invalid' });
  if (db.prepare('select 1 from users where name=?').get(name)) return res.status(409).json({ error: 'exists' });
  const r = db.prepare('insert into users(name,pass,country) values(?,?,?)').run(name, bcrypt.hashSync(password, 10), country);
  const u = db.prepare('select * from users where id=?').get(r.lastInsertRowid);
  res.json({ token: sign(u), user: pub(u) });
});
app.post('/api/login', (req, res) => {
  const { name = '', password = '' } = req.body;
  const u = db.prepare('select * from users where name=?').get(name);
  if (!u) return res.status(404).json({ error: 'nouser' });
  if (!bcrypt.compareSync(password, u.pass)) return res.status(401).json({ error: 'badpass' });
  res.json({ token: sign(u), user: pub(u) });
});
app.get('/api/me', auth, (req, res) => {
  const u = db.prepare('select * from users where id=?').get(req.uid);
  u ? res.json(pub(u)) : res.status(401).json({ error: 'auth' });
});
app.put('/api/me', auth, (req, res) => {
  db.prepare('update users set bio=? where id=?').run(String(req.body.bio || '').slice(0, 200), req.uid);
  res.json({ ok: true });
});
app.get('/api/feed', auth, (req, res) => {
  const where = req.query.mine === '1' ? 'p.user_id=@me'
    : '(p.user_id=@me or p.user_id in (select friend_id from friends where user_id=@me))';
  res.json(db.prepare(`select p.id, p.text, p.time, u.name, u.country,
    (select count(*) from likes where post_id=p.id) likes,
    exists(select 1 from likes where post_id=p.id and user_id=@me) liked
    from posts p join users u on u.id=p.user_id where ${where} order by p.time desc limit 100`).all({ me: req.uid }));
});
app.post('/api/posts', auth, (req, res) => {
  const text = String(req.body.text || '').trim().slice(0, 500);
  if (!text) return res.status(400).json({ error: 'empty' });
  db.prepare('insert into posts(user_id,text,time) values(?,?,?)').run(req.uid, text, Date.now());
  res.json({ ok: true });
});
app.delete('/api/posts/:id', auth, (req, res) => {
  db.prepare('delete from posts where id=? and user_id=?').run(req.params.id, req.uid);
  res.json({ ok: true });
});
app.post('/api/posts/:id/like', auth, (req, res) => {
  const r = db.prepare('delete from likes where post_id=? and user_id=?').run(req.params.id, req.uid);
  if (!r.changes) db.prepare('insert or ignore into likes values(?,?)').run(req.params.id, req.uid);
  res.json({ ok: true });
});
app.get('/api/users', auth, (req, res) => {
  res.json(db.prepare(`select id, name, country, bio,
    exists(select 1 from friends where user_id=@me and friend_id=users.id) isFriend
    from users where id<>@me order by name limit 200`).all({ me: req.uid }));
});
app.post('/api/friends/:id', auth, (req, res) => {
  const f = Number(req.params.id);
  if (f === req.uid) return res.status(400).json({ error: 'self' });
  const r = db.prepare('delete from friends where user_id=? and friend_id=?').run(req.uid, f);
  if (!r.changes) db.prepare('insert or ignore into friends values(?,?)').run(req.uid, f);
  res.json({ ok: true });
});
app.listen(process.env.PORT || 3000, () => console.log('MiniSocial en ligne'));
