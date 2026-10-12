const express = require('express');
const multer = require('multer');
const session = require('express-session');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const UPLOAD_DIR = path.join(ROOT, 'private_uploads');
const DB_FILE = path.join(ROOT, 'data', 'jobs.json');
fs.mkdirSync(UPLOAD_DIR, {recursive:true});
fs.mkdirSync(path.dirname(DB_FILE), {recursive:true});
if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, '[]', 'utf8');

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:false}));
app.use(express.json({limit:'32kb'}));
app.use(session({
  name:'csc_admin_session',
  secret:process.env.SESSION_SECRET || 'CHANGE_THIS_SESSION_SECRET_BEFORE_DEPLOYMENT',
  resave:false, saveUninitialized:false,
  cookie:{httpOnly:true,sameSite:'lax',secure:process.env.COOKIE_SECURE==='true',maxAge:8*60*60*1000}
}));
app.use('/api/login', rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:true,legacyHeaders:false}));
const storage = multer.diskStorage({
  destination: (_req,_file,cb)=>cb(null,UPLOAD_DIR),
  filename: (_req,file,cb)=>cb(null,crypto.randomBytes(18).toString('hex')+path.extname(file.originalname).toLowerCase())
});
const upload = multer({
  storage, limits:{fileSize:10*1024*1024,files:1},
  fileFilter:(_req,file,cb)=>{
    const ext=path.extname(file.originalname).toLowerCase();
    const allowed=['.pdf','.jpg','.jpeg','.png'];
    if(!allowed.includes(ext)) return cb(new Error('Sirf PDF, JPG aur PNG files allowed hain.'));
    cb(null,true);
  }
});
function readJobs(){try{return JSON.parse(fs.readFileSync(DB_FILE,'utf8'))}catch{return []}}
function writeJobs(jobs){fs.writeFileSync(DB_FILE,JSON.stringify(jobs,null,2),'utf8')}
function auth(req,res,next){if(req.session && req.session.admin===true)return next();return res.status(401).json({error:'Pehle admin login karein.'})}
function safeJob(j){return {id:j.id,originalName:j.originalName,customerName:j.customerName,copies:j.copies,printType:j.printType,status:j.status,createdAt:j.createdAt}}
app.use(express.static(PUBLIC));
app.get('/',(_req,res)=>res.sendFile(path.join(PUBLIC,'index.html')));
app.get('/admin',(_req,res)=>res.sendFile(path.join(PUBLIC,'admin.html')));

app.post('/api/upload',(req,res)=>{
  upload.single('document')(req,res,err=>{
    if(err){const code=err.code==='LIMIT_FILE_SIZE'?413:400;return res.status(code).json({error:err.message||'Upload error'});}
    if(!req.file)return res.status(400).json({error:'Document select karein.'});
    const ext=path.extname(req.file.originalname).toLowerCase();
    // Check file signatures, not just the browser-provided MIME type.
    const fd=fs.openSync(req.file.path,'r');const buf=Buffer.alloc(12);const n=fs.readSync(fd,buf,0,12,0);fs.closeSync(fd);
    const sig=buf.subarray(0,n);
    const valid=ext==='.pdf'?sig.subarray(0,5).toString()==='%PDF-':
      (ext==='.jpg'||ext==='.jpeg')?sig[0]===0xff&&sig[1]===0xd8&&sig[2]===0xff:
      ext==='.png'?sig.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])):false;
    if(!valid){fs.unlink(req.file.path,()=>{});return res.status(400).json({error:'File content format se match nahi karti. Original PDF/JPG/PNG upload karein.'});}
    const copies=Number(req.body.copies||1),printType=req.body.printType==='Color'?'Color':'BW';
    if(!Number.isSafeInteger(copies)||copies<1){fs.unlink(req.file.path,()=>{});return res.status(400).json({error:'Copies ki sankhya positive whole number honi chahiye.'});}
    const jobs=readJobs();const id=crypto.randomBytes(4).toString('hex').toUpperCase();
    const job={id,originalName:path.basename(req.file.originalname).slice(0,180),storedName:req.file.filename,customerName:String(req.body.customerName||'').trim().slice(0,100),copies,printType,status:'Pending',createdAt:new Date().toISOString()};
    jobs.unshift(job);writeJobs(jobs);return res.status(201).json({id,status:job.status,message:'Request submit ho gayi.'});
  });
});
app.post('/api/login',(req,res)=>{
  const username=process.env.ADMIN_USERNAME||'admin';
  const password=process.env.ADMIN_PASSWORD;
  if(!password)return res.status(503).json({error:'Admin password set nahi hai. .env file mein ADMIN_PASSWORD set karein.'});
  const givenUser=String(req.body.username||''),givenPass=String(req.body.password||'');
  const okUser=crypto.timingSafeEqual(Buffer.from(givenUser.padEnd(Math.max(1,username.length),'\0').slice(0,Math.max(1,username.length))),Buffer.from(username.padEnd(Math.max(1,username.length),'\0').slice(0,Math.max(1,username.length)))) && givenUser.length===username.length;
  const passBuf=Buffer.from(givenPass),expected=Buffer.from(password);
  const okPass=passBuf.length===expected.length&&crypto.timingSafeEqual(passBuf,expected);
  if(!okUser||!okPass)return res.status(401).json({error:'Username ya password galat hai.'});
  req.session.admin=true;return res.json({ok:true});
});
app.get('/api/me',auth,(_req,res)=>res.json({ok:true}));
app.post('/api/logout',auth,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/jobs',auth,(_req,res)=>res.json({jobs:readJobs().map(safeJob)}));
app.get('/api/jobs/:id/download',auth,(req,res)=>{
  const job=readJobs().find(j=>j.id===req.params.id);if(!job)return res.status(404).json({error:'Request nahi mili.'});
  const file=path.join(UPLOAD_DIR,path.basename(job.storedName));
  if(!fs.existsSync(file))return res.status(404).json({error:'File nahi mili.'});
  res.download(file,job.originalName);
});
app.post('/api/jobs/:id/printed',auth,(req,res)=>{
  const jobs=readJobs(),job=jobs.find(j=>j.id===req.params.id);if(!job)return res.status(404).json({error:'Request nahi mili.'});
  job.status='Printed';job.printedAt=new Date().toISOString();writeJobs(jobs);res.json({ok:true,job:safeJob(job)});
});
app.post('/api/jobs/:id/print',auth,(req,res)=>{
  const job=readJobs().find(j=>j.id===req.params.id);if(!job)return res.status(404).json({error:'Request nahi mili.'});
  const sumatra=process.env.SUMATRA_PATH;
  if(!sumatra||!fs.existsSync(sumatra))return res.status(503).json({error:'SumatraPDF configured nahi hai. README mein print setup dekhein.'});
  const file=path.join(UPLOAD_DIR,path.basename(job.storedName));
  if(!fs.existsSync(file))return res.status(404).json({error:'File nahi mili.'});
  const settings=[`${job.copies}x`,job.printType==='BW'?'monochrome':''].filter(Boolean).join(',');
  const args=['-print-to-default','-silent','-print-settings',settings,file];
  const child=spawn(sumatra,args,{windowsHide:true,stdio:'ignore'});
  child.on('error',()=>res.status(500).json({error:'Print helper launch nahi ho paya.'}));
  child.on('close',code=>{if(code!==0)return res.status(500).json({error:'Print command fail hua. Printer aur SumatraPDF check karein.'});const jobs=readJobs();const j=jobs.find(x=>x.id===job.id);if(j){j.status='Printed';j.printedAt=new Date().toISOString();writeJobs(jobs)}res.json({ok:true,status:'Printed'})});
});
app.use((err,_req,res,_next)=>{console.error(err);res.status(500).json({error:'Server error. Server logs check karein.'})});
app.listen(PORT,'0.0.0.0',()=>console.log(`CSC portal running on http://localhost:${PORT}`));
