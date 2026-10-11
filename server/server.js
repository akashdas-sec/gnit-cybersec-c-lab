
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { spawn, execFile } = require("child_process");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: "/terminal" });

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "..", "public")));

const DATA = path.join(__dirname, "data.json");
const PORT = process.env.PORT || 3000;
const sessions = new Map();

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, expected] = stored.split(":");
  const actual = crypto.scryptSync(password, salt, 64).toString("hex");
  return crypto.timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function loadDB() {
  if (fs.existsSync(DATA)) return JSON.parse(fs.readFileSync(DATA, "utf8"));
  const db = {
    nextProblemId: 4,
    nextSubmissionId: 1,
    users: [
      { id: 1, role: "admin", name: "GNIT Admin", username: "admin", password: hashPassword("admin123") },
      ...Array.from({length: 6}, (_, i) => ({
        id: i + 2, role: "student", name: `Student ${i + 1}`,
        username: `student${i + 1}`, password: hashPassword("student123")
      }))
    ],
    problems: [
      {
        id: 1, title: "Sum of Two Numbers", difficulty: "Easy",
        statement: "Read two integers and print their sum.",
        input: "Two integers a and b.",
        output: "Print a+b.",
        starter: "#include <stdio.h>\n\nint main() {\n    // Write your code here\n    return 0;\n}",
        tests: [["5 7","12"],["10 20","30"],["-2 8","6"]]
      },
      {
        id: 2, title: "Even or Odd", difficulty: "Easy",
        statement: "Read an integer and print Even if it is even, otherwise print Odd.",
        input: "One integer n.",
        output: "Even or Odd.",
        starter: "#include <stdio.h>\n\nint main() {\n    // Write your code here\n    return 0;\n}",
        tests: [["8","Even"],["7","Odd"],["0","Even"]]
      },
      {
        id: 3, title: "Largest of Three", difficulty: "Medium",
        statement: "Read three integers and print the largest value.",
        input: "Three integers.",
        output: "The largest integer.",
        starter: "#include <stdio.h>\n\nint main() {\n    // Write your code here\n    return 0;\n}",
        tests: [["1 9 4","9"],["20 3 11","20"],["-5 -2 -9","-2"]]
      }
    ],
    submissions: []
  };
  fs.writeFileSync(DATA, JSON.stringify(db, null, 2));
  return db;
}
const db = loadDB();
function saveDB() { fs.writeFileSync(DATA, JSON.stringify(db, null, 2)); }

function auth(req) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  return sessions.get(token) || null;
}
function requireAuth(req, res) {
  const u = auth(req);
  if (!u) { res.status(401).json({error:"Login required"}); return null; }
  return u;
}
function safeUser(u) { return {id:u.id, role:u.role, name:u.name, username:u.username}; }

app.get("/api/network", (req,res) => {
  const os = require("os");
  const ips = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const x of (list || [])) if (x.family === "IPv4" && !x.internal) ips.push(x.address);
  }
  res.json({ port: PORT, localIPs: ips });
});

app.post("/api/register", (req,res) => {
  const {name, username, password} = req.body || {};
  if (!name || !username || !password) return res.status(400).json({error:"All fields are required"});
  if (String(password).length < 6) return res.status(400).json({error:"Password must be at least 6 characters"});
  const un = String(username).trim().toLowerCase();
  if (!/^[a-z0-9._-]{3,30}$/.test(un)) return res.status(400).json({error:"Username: 3-30 letters/numbers/._-"});
  if (db.users.some(x => x.username === un)) return res.status(409).json({error:"Username already exists"});
  const user = {id: Math.max(...db.users.map(x=>x.id))+1, role:"student", name:String(name).trim(), username:un, password:hashPassword(password)};
  db.users.push(user); saveDB();
  res.json({ok:true, user:safeUser(user)});
});

app.post("/api/login", (req,res) => {
  const {username,password} = req.body || {};
  const u = db.users.find(x => x.username === String(username||"").trim().toLowerCase());
  if (!u || !verifyPassword(String(password||""), u.password)) return res.status(401).json({error:"Invalid username or password"});
  const token = crypto.randomBytes(32).toString("hex");
  sessions.set(token, safeUser(u));
  res.json({token, user:safeUser(u)});
});

app.get("/api/me", (req,res) => {
  const u = auth(req); if (!u) return res.status(401).json({error:"Not logged in"});
  res.json(u);
});

app.get("/api/problems", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  res.json(db.problems.map(p => ({...p, tests: undefined})));
});

app.get("/api/problems/:id", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  const p = db.problems.find(x=>x.id===Number(req.params.id));
  if (!p) return res.status(404).json({error:"Problem not found"});
  res.json(p);
});

app.get("/api/student/submissions", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  const list = db.submissions.filter(s=>s.userId===u.id).slice(-100).reverse();
  res.json(list);
});

app.get("/api/student/progress", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  const accepted = new Set(db.submissions.filter(s=>s.userId===u.id && s.status==="Accepted").map(s=>s.problemId));
  res.json({solved:accepted.size,total:db.problems.length,percent:db.problems.length?Math.round(accepted.size/db.problems.length*100):0});
});

app.post("/api/problems", (req,res) => {
  const u = requireAuth(req,res); if (!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  const {title,statement,input,output,difficulty,starter,tests} = req.body || {};
  if (!title || !statement || !Array.isArray(tests) || !tests.length) return res.status(400).json({error:"Title, statement and tests are required"});
  const p = {id:db.nextProblemId++, title, statement, input:input||"", output:output||"", difficulty:difficulty||"Easy",
             starter:starter||"#include <stdio.h>\nint main(){return 0;}", tests};
  db.problems.push(p); saveDB(); res.json(p);
});

app.delete("/api/problems/:id", (req,res) => {
  const u = requireAuth(req,res); if (!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  db.problems = db.problems.filter(p=>p.id!==Number(req.params.id)); saveDB(); res.json({ok:true});
});

function compile(source, cb) {
  const dir = fs.mkdtempSync(path.join(require("os").tmpdir(), "gnit-c-"));
  const cfile = path.join(dir, "main.c");
  const exe = path.join(dir, process.platform === "win32" ? "main.exe" : "main");
  fs.writeFileSync(cfile, source, "utf8");
  execFile("gcc", [cfile, "-O2", "-std=c11", "-o", exe], {timeout:5000}, (error, stdout, stderr) => {
    if (error) return cb(new Error(stderr || stdout || "Compilation failed"), null, dir);
    cb(null, exe, dir);
  });
}
function cleanup(dir) { try { fs.rmSync(dir,{recursive:true,force:true}); } catch(e){} }

app.post("/api/compile", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  compile(String(req.body.code||""), (err, exe, dir) => {
    const out = err ? {ok:false,error:err.message} : {ok:true};
    cleanup(dir); res.json(out);
  });
});

app.post("/api/submit", (req,res) => {
  const u = requireAuth(req,res); if (!u) return;
  const p = db.problems.find(x=>x.id===Number(req.body.problemId));
  if (!p) return res.status(404).json({error:"Problem not found"});
  const code = String(req.body.code||"");
  compile(code, (err, exe, dir) => {
    if (err) {
      const s={id:db.nextSubmissionId++,userId:u.id,userName:u.name,problemId:p.id,problemTitle:p.title,status:"Compilation Error",code,feedback:"Fix the compiler errors and try again.",at:new Date().toISOString()};
      db.submissions.push(s); saveDB(); return res.json({status:s.status,error:err.message});
    }
    let i=0, passed=0, firstError="";
    const runNext=()=>{
      if(i>=p.tests.length){
        const status=passed===p.tests.length?"Accepted":"Wrong Answer";
        const s={id:db.nextSubmissionId++,userId:u.id,userName:u.name,problemId:p.id,problemTitle:p.title,status,code,passed,total:p.tests.length,feedback:status==="Accepted"?"Great work!":"Check your logic and test cases.",at:new Date().toISOString()};
        db.submissions.push(s); saveDB(); cleanup(dir);
        return res.json({status,passed,total:p.tests.length,error:firstError});
      }
      const [input,expected]=p.tests[i++];
      const child=spawn(exe,[],{windowsHide:true});
      let out="", errout="", finished=false;
      const timer=setTimeout(()=>{if(!finished){finished=true;child.kill();firstError="Time limit exceeded";runNext();}},3000);
      child.stdout.on("data",d=>out+=d.toString());
      child.stderr.on("data",d=>errout+=d.toString());
      child.on("close",()=>{
        if(finished)return; finished=true; clearTimeout(timer);
        const norm=s=>s.trim().replace(/\s+/g," ");
        if(!errout && norm(out)===norm(expected)) passed++;
        else if(!firstError) firstError=errout || `Expected: ${expected}\nGot: ${out}`;
        runNext();
      });
      child.stdin.write(input+"\n"); child.stdin.end();
    };
    runNext();
  });
});

app.get("/api/admin/students", (req,res) => {
  const u=requireAuth(req,res); if(!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  const result=db.users.filter(x=>x.role==="student").map(st=>{
    const subs=db.submissions.filter(s=>s.userId===st.id);
    const accepted=new Set(subs.filter(s=>s.status==="Accepted").map(s=>s.problemId));
    return {id:st.id,name:st.name,username:st.username,solved:accepted.size,total:db.problems.length,
      percent:db.problems.length?Math.round(accepted.size/db.problems.length*100):0,
      runs:subs.length, last:subs.length?subs[subs.length-1].at:null};
  });
  res.json(result);
});
app.get("/api/admin/submissions", (req,res) => {
  const u=requireAuth(req,res); if(!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  res.json(db.submissions.slice(-200).reverse());
});
app.get("/api/admin/submissions/:id", (req,res) => {
  const u=requireAuth(req,res); if(!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  const s=db.submissions.find(x=>x.id===Number(req.params.id));
  if(!s)return res.status(404).json({error:"Submission not found"});
  res.json(s);
});
app.post("/api/admin/feedback/:submissionId", (req,res) => {
  const u=requireAuth(req,res); if(!u || u.role!=="admin") return res.status(403).json({error:"Admin only"});
  const s=db.submissions.find(x=>x.id===Number(req.params.submissionId));
  if(!s)return res.status(404).json({error:"Submission not found"});
  s.feedback=String(req.body.feedback||""); saveDB(); res.json({ok:true});
});

wss.on("connection",(ws,req)=>{
  const url=new URL(req.url,"http://localhost");
  const token=url.searchParams.get("token");
  const u=sessions.get(token);
  if(!u){ ws.close(1008,"Login required"); return; }

  let proc=null, dir=null, closed=false;
  const send=(type,data)=>{ if(ws.readyState===WebSocket.OPEN) ws.send(JSON.stringify({type,data})); };

  ws.on("message",(raw)=>{
    let msg; try{msg=JSON.parse(raw.toString())}catch{return}
    if(msg.type==="run"){
      if(proc) return send("error","A program is already running.");
      const source=String(msg.code||"");
      compile(source,(err,exe,d)=>{
        if(err){ send("compileError",err.message); return; }
        dir=d;
        send("status","Program started. Type input and press Enter.");
        proc=spawn(exe,[],{windowsHide:true});
        proc.stdout.on("data",d=>send("stdout",d.toString()));
        proc.stderr.on("data",d=>send("stderr",d.toString()));
        proc.on("close",(code,signal)=>{
          send("exit",`Process finished (code ${code}${signal?`, ${signal}`:""}).`);
          cleanup(dir); dir=null; proc=null;
        });
      });
    } else if(msg.type==="input"){
      if(proc && proc.stdin.writable) proc.stdin.write(String(msg.data||""));
    } else if(msg.type==="stop"){
      if(proc) proc.kill(); else send("status","No program is running.");
    }
  });
  ws.on("close",()=>{ if(proc) proc.kill(); cleanup(dir); });
});

app.get("*",(req,res)=>res.sendFile(path.join(__dirname,"..","public","index.html")));
server.listen(PORT,"0.0.0.0",()=>{
  console.log(`GNIT CyberSec C Lab V6 running on http://localhost:${PORT}`);
  const os=require("os");
  const ips=[];
  for(const list of Object.values(os.networkInterfaces())) for(const x of (list||[]))
    if(x.family==="IPv4"&&!x.internal) ips.push(x.address);
  if(ips.length) console.log("LAN access: " + ips.map(ip=>`http://${ip}:${PORT}`).join("  "));
});
