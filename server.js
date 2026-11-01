const express = require('express');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { Server } = require('socket.io');
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: false }, maxHttpBufferSize: 1e6 });
const PORT = process.env.PORT || 3000;
const DB_FILE = process.env.RCARD_DB || path.join(__dirname, 'data.json');
const SECRET = process.env.RCARD_SECRET || crypto.randomBytes(32).toString('hex');
let db = { users: {}, names: {} };
try { if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); } catch (e) { console.error('Could not read database:', e.message); }
function saveDb() { const tmp = DB_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(db)); fs.renameSync(tmp, DB_FILE); }
function cleanName(s) { return String(s || '').trim().replace(/[^\p{L}\p{N}_-]/gu, '').slice(0, 18); }
function tokenFor(id) { const payload = Buffer.from(JSON.stringify({ id, exp: Date.now() + 30*24*60*60*1000 })).toString('base64url'); return payload + '.' + crypto.createHmac('sha256', SECRET).update(payload).digest('base64url'); }
function userFromToken(token) { try { const [p, sig] = String(token || '').split('.'); const expected = crypto.createHmac('sha256', SECRET).update(p).digest(); const got = Buffer.from(sig, 'base64url'); if (got.length !== expected.length || !crypto.timingSafeEqual(got, expected)) return null; const data = JSON.parse(Buffer.from(p, 'base64url').toString()); if (data.exp < Date.now() || !db.users[data.id]) return null; return db.users[data.id]; } catch { return null; } }
function publicUser(u) { return { id:u.id, username:u.username, rating:u.rating || 1000, wins:u.wins || 0, losses:u.losses || 0 }; }
app.use(express.json({ limit: '700kb' }));
app.use((req,res,next)=>{res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');next();});
app.get('/api/health', (_req,res)=>res.json({ok:true, game:'RCard PvP Online'}));
app.post('/api/register', (req,res)=>{
 const username = cleanName(req.body.username); const password = String(req.body.password || '');
 if (username.length < 3 || username.length > 18) return res.status(400).json({error:'Имя должно содержать 3–18 букв, цифр, _ или -.'});
 if (password.length < 8 || password.length > 128) return res.status(400).json({error:'Пароль должен быть длиной не менее 8 символов.'});
 const key = username.toLocaleLowerCase('ru-RU'); if (db.names[key]) return res.status(409).json({error:'Это имя уже занято.'});
 const id = crypto.randomUUID(), salt = crypto.randomBytes(16).toString('hex');
 const hash = crypto.scryptSync(password, salt, 64).toString('hex');
 db.users[id] = {id, username, salt, hash, rating:1000, wins:0, losses:0, state:{}, createdAt:Date.now()}; db.names[key] = id; saveDb();
 res.json({token:tokenFor(id), user:publicUser(db.users[id]), state:db.users[id].state});
});
app.post('/api/login', (req,res)=>{
 const username = cleanName(req.body.username), password = String(req.body.password || ''); const id = db.names[username.toLocaleLowerCase('ru-RU')]; const u = id && db.users[id];
 if (!u || password.length > 128) return res.status(401).json({error:'Неверное имя или пароль.'});
 const hash = crypto.scryptSync(password, u.salt, 64); if (!crypto.timingSafeEqual(hash, Buffer.from(u.hash,'hex'))) return res.status(401).json({error:'Неверное имя или пароль.'});
 res.json({token:tokenFor(id), user:publicUser(u), state:u.state || {}});
});
function auth(req,res,next) { const u = userFromToken(req.headers.authorization?.replace(/^Bearer\s+/i,'')); if (!u) return res.status(401).json({error:'Войди в аккаунт заново.'}); req.user=u; next(); }
app.get('/api/me', auth, (req,res)=>res.json({user:publicUser(req.user)}));
app.get('/api/state', auth, (req,res)=>res.json({state:req.user.state || {}}));
app.put('/api/state', auth, (req,res)=>{ const state=req.body?.state; if (!state || typeof state!=='object' || Array.isArray(state)) return res.status(400).json({error:'Некорректное сохранение.'}); const raw=JSON.stringify(state); if(raw.length>600000) return res.status(413).json({error:'Сохранение слишком большое.'}); req.user.state=state; req.user.updatedAt=Date.now(); saveDb(); res.json({ok:true}); });
app.get('/api/leaderboard', (_req,res)=>res.json({players:Object.values(db.users).map(publicUser).sort((a,b)=>b.rating-a.rating).slice(0,50)}));
app.use(express.static(__dirname));
const waiting = []; const socketUsers = new Map(); const duels = new Map();
function removeWaiting(socketId) { const i=waiting.findIndex(x=>x.socketId===socketId); if(i>=0) waiting.splice(i,1); }
function finishDuel(duel, winnerId) { if(duel.finished)return; duel.finished=true; const loserId=duel.players.find(id=>id!==winnerId); const winner=db.users[winnerId], loser=db.users[loserId]; if(winner&&loser){winner.wins=(winner.wins||0)+1;loser.losses=(loser.losses||0)+1;winner.rating=(winner.rating||1000)+25;loser.rating=Math.max(0,(loser.rating||1000)-15);saveDb();} io.to(duel.room).emit('duel:finished',{winnerId, winner:winner?winner.username:'Игрок', ratings:{[winnerId]:winner?.rating,[loserId]:loser?.rating}}); }
io.on('connection', socket=>{
 const u=userFromToken(socket.handshake.auth?.token); if(!u){socket.emit('online:error',{message:'Войди в аккаунт, чтобы играть онлайн.'});socket.disconnect(true);return;} socketUsers.set(socket.id,u.id); socket.emit('online:ready',{user:publicUser(u)});
 socket.on('match:join',()=>{ if(duels.has(socket.id))return; removeWaiting(socket.id); const opponentIndex=waiting.findIndex(x=>x.userId!==u.id); if(opponentIndex<0){waiting.push({socketId:socket.id,userId:u.id});socket.emit('match:queued');return;} const opponent=waiting.splice(opponentIndex,1)[0]; const otherSocket=io.sockets.sockets.get(opponent.socketId); if(!otherSocket){waiting.push({socketId:socket.id,userId:u.id});return;} const room='duel_'+crypto.randomUUID(); const players=[opponent.userId,u.id]; const duel={room,players,hp:{[players[0]]:100,[players[1]]:100},turn:players[0],finished:false}; duels.set(room,duel);duels.set(opponent.socketId,duel);duels.set(socket.id,duel);otherSocket.join(room);socket.join(room);io.to(room).emit('match:found',{room,players:players.map(id=>publicUser(db.users[id])),hp:duel.hp,turn:duel.turn}); });
 socket.on('match:cancel',()=>{removeWaiting(socket.id);socket.emit('match:cancelled');});
 socket.on('duel:attack',()=>{const duel=duels.get(socket.id);if(!duel||duel.finished)return;if(duel.turn!==u.id){socket.emit('duel:message',{message:'Сейчас ход соперника.'});return;}const target=duel.players.find(id=>id!==u.id);const damage=12+crypto.randomInt(0,15);duel.hp[target]=Math.max(0,duel.hp[target]-damage);duel.turn=target;io.to(duel.room).emit('duel:update',{attacker:u.id,target,damage,hp:duel.hp,turn:duel.turn,attackerName:u.username});if(duel.hp[target]<=0)finishDuel(duel,u.id);});
 socket.on('disconnect',()=>{removeWaiting(socket.id);socketUsers.delete(socket.id);const duel=duels.get(socket.id);if(duel&&!duel.finished){const other=duel.players.find(id=>id!==u.id);finishDuel(duel,other);}if(duel){for(const [sid,d] of duels)if(d===duel)duels.delete(sid);}});
});
server.listen(PORT,()=>console.log(`RCard PvP Online listening on ${PORT}`));
