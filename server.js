const express = require("express"), fs = require("fs"), crypto = require("crypto");
const app = express();
app.use(express.json({ limit: "12mb" }));
app.use(express.static("public"));

// ---- Storage: SQLite database (built into Node 22.5+, nothing extra to install) ----
const { DatabaseSync } = require("node:sqlite"), path = require("path");
const hash = (p, s = crypto.randomBytes(8).toString("hex")) => s + ":" + crypto.scryptSync(p, s, 32).toString("hex");
const check = (p, h) => hash(p, h.split(":")[0]) === h;
const checkAsync = (p, h) => new Promise((ok, no) => { const [s, x] = h.split(":"); crypto.scrypt(p, s, 32, (e, k) => e ? no(e) : ok(k.toString("hex") === x)); });
const TABLES = ["users", "exams", "attempts", "results", "bank", "courses", "notices"];
const scryptP = (p, s) => new Promise((ok, no) => crypto.scrypt(p, s, 32, (e, k) => e ? no(e) : ok(k.toString("hex"))));
const keyOf = (t, x) => (t === "attempts" || t === "results") ? `${x.examId}:${x.studentId}` : String(x.id);
const sql = new DatabaseSync(path.join(process.env.DATA_DIR || ".", "exam.db"));   // set DATA_DIR on a host with a persistent disk
sql.exec("PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT); CREATE TABLE IF NOT EXISTS snaps (id INTEGER PRIMARY KEY AUTOINCREMENT, k TEXT NOT NULL, t INTEGER, img TEXT); CREATE INDEX IF NOT EXISTS snaps_k ON snaps(k);" +
  TABLES.map(t => `CREATE TABLE IF NOT EXISTS ${t} (id TEXT PRIMARY KEY, data TEXT NOT NULL);`).join(""));
const sig = Object.fromEntries(TABLES.map(t => [t, new Map()]));   // last saved JSON per row, so only changed rows are written
let db = { next: 2 }, fresh = false;
const nextRow = sql.prepare("SELECT v FROM meta WHERE k='next'").get();
if (nextRow) {
  db.next = +nextRow.v;
  for (const t of TABLES) db[t] = sql.prepare(`SELECT id, data FROM ${t} ORDER BY rowid`).all().map(r => { sig[t].set(r.id, r.data); return JSON.parse(r.data); });
} else {                                                            // first run: import the old db.json if it exists, else create the admin
  const old = fs.existsSync("db.json") ? JSON.parse(fs.readFileSync("db.json")) : null;
  db = { next: old?.next || 2, ...Object.fromEntries(TABLES.map(t => [t, old?.[t] || []])) };
  if (!old) db.users.push({ id: 1, name: "Admin", username: "admin", role: "admin", pw: hash("admin123") });
  else console.log("Imported db.json into exam.db (you can keep db.json as a backup)");
  fresh = true;
}
const stRow = sql.prepare("SELECT v FROM meta WHERE k='settings'").get();
db.settings = { siteName: "Exam System", minutes: 10, pass: 50, shuffle: true, showAnswers: true, ...(stRow ? JSON.parse(stRow.v) : {}) };
function flush(tables) {
  sql.exec("BEGIN");
  try {
    for (const t of tables) {
      const up = sql.prepare(`INSERT INTO ${t} (id, data) VALUES (?, ?) ON CONFLICT(id) DO UPDATE SET data = excluded.data`), seen = new Set();
      for (const x of db[t]) { const k = keyOf(t, x), j = JSON.stringify(x); seen.add(k); if (sig[t].get(k) !== j) { up.run(k, j); sig[t].set(k, j); } }
      for (const k of [...sig[t].keys()]) if (!seen.has(k)) { sql.prepare(`DELETE FROM ${t} WHERE id = ?`).run(k); sig[t].delete(k); }
    }
    sql.prepare("INSERT INTO meta (k, v) VALUES ('next', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(String(db.next));
    sql.prepare("INSERT INTO meta (k, v) VALUES ('settings', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v").run(JSON.stringify(db.settings));
    sql.exec("COMMIT");
  } catch (e) { sql.exec("ROLLBACK"); throw e; }
}
const save = (...t) => flush(t.length ? t : TABLES);   // save("attempts") writes only that table
if (fresh) save();

// ---- Auth ----
const sessions = {};
const auth = (...roles) => (req, res, next) => {
  const u = sessions[req.headers["x-token"]];
  if (!u || (roles.length && !roles.includes(u.role))) return res.status(403).json({ error: "Not allowed" });
  req.user = u; next();
};
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const u = db.users.find(x => x.username === username);
  if (!u || !(await checkAsync(String(password || ""), u.pw))) return res.status(401).json({ error: "Wrong username or password" });
  const token = crypto.randomBytes(16).toString("hex");
  sessions[token] = u;
  res.json({ token, name: u.name, role: u.role });
});
app.post("/api/password", auth(), (req, res) => {
  const u = db.users.find(x => x.id === req.user.id), { old, new: nw } = req.body;
  if (!check(old || "", u.pw) || !nw || nw.length < 6) return res.status(400).json({ error: "Wrong current password, or new password is under 6 characters" });
  u.pw = hash(nw); save(); res.json({ ok: true });
});

// ---- Admin ----
app.get("/api/users", auth("admin"), (req, res) => res.json(db.users.map(({ pw, ...u }) => u)));
app.post("/api/users", auth("admin"), (req, res) => {
  const { name, username, password, role } = req.body;
  if (!name || !username || !password || !["admin", "teacher", "student"].includes(role)) return res.status(400).json({ error: "Fill in all fields" });
  if (db.users.some(x => x.username === username)) return res.status(400).json({ error: "Username already taken" });
  db.users.push({ id: db.next++, name, username, role, pw: hash(password) }); save(); res.json({ ok: true });
});
app.put("/api/users/:id/password", auth("admin"), (req, res) => {
  const u = db.users.find(x => x.id == req.params.id);
  if (!u || !req.body.password) return res.status(400).json({ error: "Invalid request" });
  u.pw = hash(req.body.password); save(); res.json({ ok: true });
});
app.delete("/api/users/:id", auth("admin"), (req, res) => {
  db.users = db.users.filter(u => u.id != req.params.id || u.id === req.user.id); db.courses.forEach(c => { c.students = c.students.filter(x => x != req.params.id); }); save(); res.json({ ok: true });
});
app.get("/api/stats", auth("admin"), (req, res) => res.json({
  students: db.users.filter(u => u.role === "student").length, teachers: db.users.filter(u => u.role === "teacher").length,
  courses: db.courses.length, exams: db.exams.length, taken: db.results.length,
  avg: db.results.length ? Math.round(db.results.reduce((s, r) => s + (r.percent ?? 0), 0) / db.results.length) : 0 }));

// ---- Teacher: exams ----
app.post("/api/exams", auth("teacher"), (req, res) => {
  const { title, minutes, pass, shuffle, showAnswers, proctor, opensAt, closesAt, courseId, code, pick, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: "Title and questions are required" });
  if (courseId && !db.courses.some(c => c.id === +courseId && c.teacherId === req.user.id)) return res.status(400).json({ error: "Choose one of your own courses" });
  db.exams.push({ id: db.next++, title, minutes: Math.min(300, Math.max(1, +minutes || 10)), pass: Math.min(100, Math.max(0, +pass || 50)),
    shuffle: !!shuffle, showAnswers: !!showAnswers, proctor: !!proctor, courseId: +courseId || null, opensAt: +opensAt || null, closesAt: +closesAt || null, code: String(code || "").trim(), pick: Math.max(0, +pick || 0), teacherId: req.user.id, questions });
  save(); res.json({ ok: true });
});
app.delete("/api/exams/:id", auth("teacher"), (req, res) => {
  const id = +req.params.id;
  if (!db.exams.some(e => e.id === id && e.teacherId === req.user.id)) return res.status(404).json({ error: "Exam not found" });
  db.exams = db.exams.filter(e => e.id !== id);
  db.attempts = db.attempts.filter(a => a.examId !== id); db.results = db.results.filter(r => r.examId !== id);
  sql.prepare("DELETE FROM snaps WHERE k LIKE ?").run(`${id}:%`); save(); res.json({ ok: true });
});
app.get("/api/exams", auth("teacher", "student"), (req, res) => {
  if (req.user.role === "teacher") return res.json(db.exams.filter(e => e.teacherId === req.user.id));
  res.json(db.exams.filter(e => enrolled(e, req.user.id)).map(e => ({ id: e.id, course: courseName(e.courseId), courseId: e.courseId || null, needsCode: !!e.code, title: e.title, minutes: e.minutes, pass: e.pass ?? 50, count: e.pick > 0 && e.pick < e.questions.length ? e.pick : e.questions.length, opensAt: e.opensAt || null, closesAt: e.closesAt || null, proctor: !!e.proctor,
    status: db.results.some(r => r.examId === e.id && r.studentId === req.user.id) ? "done"
          : db.attempts.some(a => a.examId === e.id && a.studentId === req.user.id) ? "inprogress" : "new" })));
});

// ---- Student: take exam (random order, saved on server, server-side timer) ----
const shuffle = a => { a = [...a]; for (let i = a.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [a[i], a[j]] = [a[j], a[i]]; } return a; };
const range = n => [...Array(n).keys()];
const deadline = (e, a) => Math.min(a.startedAt + e.minutes * 60000, e.closesAt || Infinity) + (a.adjust || 0);   // a.adjust = minutes the teacher added/removed for one student
const remainingSec = (e, a) => Math.max(0, Math.round((deadline(e, a) - Date.now()) / 1000));
const makePaper = e => (e.pick > 0 && e.pick < e.questions.length ? shuffle(range(e.questions.length)).slice(0, e.pick) : e.shuffle ? shuffle(range(e.questions.length)) : range(e.questions.length)).map(qi => {
  const q = e.questions[qi], n = q.o ? q.o.length : 0, t = q.type || "mcq";
  return { qi, perm: (t === "mcq" || t === "multi") && e.shuffle ? shuffle(range(n)) : range(n) };
});
const view = (e, p) => p.map(({ qi, perm }) => { const q = e.questions[qi]; return { type: q.type || "mcq", q: q.q, img: q.img, pts: +q.pts || 1, o: q.o ? perm.map(i => q.o[i]) : undefined }; });
const norm = s => String(s ?? "").trim().toLowerCase().replace(/\s+/g, " ");
const grade = (e, p, ans) => {
  let score = 0, total = 0; const essays = [];
  const review = p.map(({ qi, perm }, k) => {
    const q = e.questions[qi], t = q.type || "mcq", g = ans[k], pts = +q.pts || 1; total += pts;
    let ok, yours, right;
    if (t === "essay") { essays.push({ q: q.q, guide: q.guide || "", answer: String(g || ""), max: pts, mark: null }); return { qi, type: t, pts, explain: q.explain || "", ei: essays.length - 1, q: q.q, yours: g ? "(submitted - your teacher will mark it)" : "No answer", right: "", ok: null }; }
    if (t === "text") { yours = g || ""; right = [].concat(q.a).join(" / "); ok = [].concat(q.a).map(norm).includes(norm(g)); }
    else if (t === "multi") {
      const sel = Array.isArray(g) ? g : [];
      ok = sel.length > 0 && sel.map(i => perm[i]).sort((a, b) => a - b).join() === [...q.a].sort((a, b) => a - b).join();
      yours = sel.map(i => q.o[perm[i]]).join(", "); right = q.a.map(i => q.o[i]).join(", ");
    } else { yours = g == null ? null : q.o[perm[g]]; right = q.o[q.a]; ok = g != null && perm[g] === q.a; }
    if (ok) score += pts;
    return { qi, type: t, pts, explain: q.explain || "", q: q.q, yours: yours || "No answer", right, ok };
  });
  return { score, total, essays, review };
};
const attemptOf = (req) => db.attempts.find(a => a.examId == req.params.id && a.studentId === req.user.id);

app.post("/api/exams/:id/start", auth("student"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.id);
  if (!e) return res.status(404).json({ error: "Exam not found" });
  if (!enrolled(e, req.user.id)) return res.status(403).json({ error: "You are not enrolled in this course" });
  if (e.code && !attemptOf(req) && String(req.body?.code || "").trim().toLowerCase() !== e.code.toLowerCase()) return res.status(403).json({ error: "Wrong access code" });
  if (db.results.some(r => r.examId === e.id && r.studentId === req.user.id)) return res.status(400).json({ error: "You already completed this exam" });
  let a = attemptOf(req);
  if (!a && e.opensAt && Date.now() < e.opensAt) return res.status(400).json({ error: "This exam is not open yet" });
  if (!a && e.closesAt && Date.now() > e.closesAt) return res.status(400).json({ error: "This exam is closed" });
  if (!a) { a = { examId: e.id, studentId: req.user.id, startedAt: Date.now(), paper: makePaper(e), answers: [], violations: 0 }; db.attempts.push(a); save("attempts"); }
  res.json({ title: e.title, questions: view(e, a.paper), answers: a.answers, violations: a.violations,
    remaining: remainingSec(e, a), proctor: !!e.proctor });
});
app.post("/api/exams/:id/save", auth("student"), (req, res) => {
  const a = attemptOf(req);
  if (!a) return res.status(400).json({ error: "Start the exam first" });
  a.answers = req.body.answers || []; a.violations = Math.max(a.violations, req.body.violations || 0); save("attempts"); res.json({ ok: true });
});
app.post("/api/exams/:id/snap", auth("student"), (req, res) => {      // webcam snapshots (stored in their own table)
  const a = attemptOf(req);
  if (!a || typeof req.body.img !== "string" || req.body.img.length > 80000) return res.status(400).json({ error: "Invalid snapshot" });
  const k = `${a.examId}:${a.studentId}`;
  if (sql.prepare("SELECT COUNT(*) AS n FROM snaps WHERE k = ?").get(k).n < 40) sql.prepare("INSERT INTO snaps (k, t, img) VALUES (?, ?, ?)").run(k, Date.now(), req.body.img);
  res.json({ ok: true });
});
app.post("/api/exams/:id/submit", auth("student"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.id), a = attemptOf(req);
  if (!e || !a) return res.status(400).json({ error: "Start the exam first" });
  const late = Date.now() > deadline(e, a) + 15000;   // late submissions use the last saved answers
  const { score, total, essays, review } = grade(e, a.paper, late ? a.answers : (req.body.answers || a.answers));
  const percent = Math.round(score / total * 100), pending = essays.length;
  const r = { examId: e.id, studentId: req.user.id, student: req.user.name, exam: e.title, score, total, percent,
    courseId: e.courseId || null, course: courseName(e.courseId), review, auto: score, essays, pending, passed: pending ? null : percent >= (e.pass ?? 50), violations: Math.max(a.violations, req.body.violations || 0), at: new Date().toISOString(), snaps: a.snaps || [], nsnaps: (a.snaps || []).length + sql.prepare("SELECT COUNT(*) AS n FROM snaps WHERE k = ?").get(`${e.id}:${req.user.id}`).n };
  db.results.push(r); db.attempts = db.attempts.filter(x => x !== a); save("attempts", "results");
  const { snaps, essays: ess, ...pub } = r; res.json({ ...pub, review: e.showAnswers ? review : undefined });
});

// ---- Results: admin all, teacher own exams, student own ----
app.get("/api/results", auth("admin", "teacher", "student"), (req, res) => {
  let r = db.results;
  if (req.user.role === "student") r = r.filter(x => x.studentId === req.user.id);
  if (req.user.role === "teacher") { const ids = db.exams.filter(e => e.teacherId === req.user.id).map(e => e.id); r = r.filter(x => ids.includes(x.examId)); }
  res.json(r.map(({ snaps, review, ...x }) => ({ ...x, snaps: x.nsnaps ?? (snaps || []).length,
    essays: req.user.role === "student" ? (x.essays || []).map(({ guide, ...q }) => q) : x.essays })));
});

app.get("/api/snaps/:examId/:studentId", auth("teacher", "admin"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.examId);
  if (!e || (req.user.role === "teacher" && e.teacherId !== req.user.id)) return res.status(404).json({ error: "Not found" });
  const old = db.results.find(x => x.examId === e.id && x.studentId == req.params.studentId)?.snaps || [];
  res.json([...old, ...sql.prepare("SELECT t, img FROM snaps WHERE k = ? ORDER BY t").all(`${e.id}:${req.params.studentId}`)]);
});

// ---- Review (student) and question analysis (teacher) ----
app.get("/api/review/:examId", auth("student"), (req, res) => {
  const r = db.results.find(x => x.examId == req.params.examId && x.studentId === req.user.id), e = r && db.exams.find(x => x.id === r.examId);
  if (!r) return res.status(404).json({ error: "No result yet" });
  const base = { exam: r.exam, score: r.score, total: r.total, percent: r.percent, passed: r.passed, pending: r.pending };
  if (!e?.showAnswers || !r.review) return res.json(base);
  res.json({ ...base, review: r.review.map(({ ei, qi, ...x }) => { const m = ei !== undefined ? r.essays[ei] : null; return m ? { ...x, yours: m.answer || "No answer", mark: m.mark, max: m.max, feedback: m.feedback || "" } : x; }) });
});
app.get("/api/analysis/:id", auth("teacher"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.id && x.teacherId === req.user.id);
  if (!e) return res.status(404).json({ error: "Exam not found" });
  const rows = e.questions.map((q, qi) => ({ qi, q: q.q, type: q.type || "mcq", n: 0, right: 0 }));
  db.results.filter(r => r.examId === e.id && r.review).forEach(r => r.review.forEach(x => {
    const row = rows[x.qi]; if (!row) return; row.n++;
    if (x.ok === true) row.right++;
    else if (x.ok === null && x.ei !== undefined) { const m = r.essays[x.ei]; if (m && m.mark !== null && m.mark !== undefined) row.right += m.mark / m.max; else row.n--; }
  }));
  res.json(rows.map(r => ({ ...r, pct: r.n ? Math.round(r.right / r.n * 100) : null })));
});

// ---- Edit exam + allow retake ----
app.put("/api/exams/:id", auth("teacher"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.id && x.teacherId === req.user.id);
  if (!e) return res.status(404).json({ error: "Exam not found" });
  const { title, minutes, pass, shuffle, showAnswers, proctor, opensAt, closesAt, courseId, code, pick, questions } = req.body;
  if (!title || !questions?.length) return res.status(400).json({ error: "Title and questions are required" });
  if (courseId && !db.courses.some(c => c.id === +courseId && c.teacherId === req.user.id)) return res.status(400).json({ error: "Choose one of your own courses" });
  if (JSON.stringify(questions) !== JSON.stringify(e.questions) && db.attempts.some(a => a.examId === e.id))
    return res.status(409).json({ error: "Students are taking this exam right now. Change the questions after they finish (you can still change the time from Live exams)." });
  Object.assign(e, { title, minutes: Math.min(300, Math.max(1, +minutes || 10)), pass: Math.min(100, Math.max(0, +pass || 50)), shuffle: !!shuffle, showAnswers: !!showAnswers,
    proctor: !!proctor, courseId: +courseId || null, opensAt: +opensAt || null, closesAt: +closesAt || null, code: String(code || "").trim(), pick: Math.max(0, +pick || 0), questions });
  save("exams"); res.json({ ok: true });
});
app.post("/api/exams/:id/reset", auth("teacher"), (req, res) => {   // deletes the student's result/attempt so they can take the exam again
  const e = db.exams.find(x => x.id == req.params.id && x.teacherId === req.user.id), sid = +req.body.studentId;
  if (!e || !sid) return res.status(400).json({ error: "Invalid request" });
  db.results = db.results.filter(r => !(r.examId === e.id && r.studentId === sid));
  db.attempts = db.attempts.filter(a => !(a.examId === e.id && a.studentId === sid));
  sql.prepare("DELETE FROM snaps WHERE k = ?").run(`${e.id}:${sid}`); save("results", "attempts"); res.json({ ok: true });
});

// ---- Live monitoring + time control ----
app.get("/api/exams/:id/remaining", auth("student"), (req, res) => {
  const e = db.exams.find(x => x.id == req.params.id), a = attemptOf(req);
  if (!e || !a) return res.status(404).json({ error: "Not in progress" });
  res.json({ remaining: remainingSec(e, a) });
});
app.get("/api/live", auth("teacher"), (req, res) => {
  const filled = x => x !== null && x !== undefined && x !== "" && !(Array.isArray(x) && !x.length);
  res.json(db.exams.filter(e => e.teacherId === req.user.id).map(e => ({ examId: e.id, title: e.title, minutes: e.minutes,
    students: db.attempts.filter(a => a.examId === e.id).map(a => ({ studentId: a.studentId, student: userInfo(a.studentId)?.name || "?",
      remaining: remainingSec(e, a), answered: a.answers.filter(filled).length, total: e.questions.length, violations: a.violations })) })).filter(x => x.students.length));
});
app.post("/api/exams/:id/time", auth("teacher"), (req, res) => {   // studentId given: that student only; otherwise the exam's total time (everyone, also in-progress)
  const e = db.exams.find(x => x.id == req.params.id && x.teacherId === req.user.id), n = Math.round(+req.body.minutes);
  if (!e || !n || Math.abs(n) > 600) return res.status(400).json({ error: "Invalid request" });
  if (req.body.studentId) {
    const a = db.attempts.find(x => x.examId === e.id && x.studentId === +req.body.studentId);
    if (!a) return res.status(404).json({ error: "That student is not in the exam" });
    a.adjust = (a.adjust || 0) + n * 60000; save("attempts");
  } else { e.minutes = Math.min(600, Math.max(1, e.minutes + n)); if (e.closesAt) e.closesAt += n * 60000; save("exams"); }
  res.json({ ok: true });
});

// ---- Announcements ----
app.get("/api/notices", auth(), (req, res) => {
  const u = req.user;
  res.json(db.notices.filter(n => u.role === "admin" || n.authorId === u.id || (u.role === "student" && (!n.courseId || db.courses.some(c => c.id === n.courseId && c.students.includes(u.id)))))
    .slice(-20).reverse().map(n => ({ ...n, course: courseName(n.courseId) })));
});
app.post("/api/notices", auth("admin", "teacher"), (req, res) => {
  const text = String(req.body.text || "").trim().slice(0, 500), cid = +req.body.courseId || null;
  if (!text) return res.status(400).json({ error: "Write the announcement first" });
  if (cid && !canManage(req.user, db.courses.find(c => c.id === cid))) return res.status(400).json({ error: "Choose one of your courses" });
  db.notices.push({ id: db.next++, authorId: req.user.id, author: req.user.name, courseId: cid, text, at: Date.now() }); save("notices"); res.json({ ok: true });
});
app.delete("/api/notices/:id", auth("admin", "teacher"), (req, res) => {
  db.notices = db.notices.filter(n => !(n.id == req.params.id && (req.user.role === "admin" || n.authorId === req.user.id))); save("notices"); res.json({ ok: true });
});

// ---- Courses, enrollment, settings, bulk import ----
const courseName = id => db.courses.find(c => c.id === id)?.name || "";
const enrolled = (e, uid) => !e.courseId || db.courses.some(c => c.id === e.courseId && c.students.includes(uid));   // exams without a course are open to everyone
const canManage = (u, c) => c && (u.role === "admin" || c.teacherId === u.id);
const userInfo = id => { const u = db.users.find(x => x.id === id); return u ? { id: u.id, name: u.name, username: u.username } : null; };

app.get("/api/public", (req, res) => res.json({ siteName: db.settings.siteName }));
app.get("/api/settings", auth(), (req, res) => res.json(db.settings));
app.put("/api/settings", auth("admin"), (req, res) => {
  const b = req.body, st = db.settings;
  if (typeof b.siteName === "string" && b.siteName.trim()) st.siteName = b.siteName.trim().slice(0, 60);
  st.minutes = Math.min(300, Math.max(1, +b.minutes || st.minutes)); st.pass = Math.min(100, Math.max(0, +b.pass || st.pass));
  st.shuffle = !!b.shuffle; st.showAnswers = !!b.showAnswers; save("courses"); res.json(st);
});
app.get("/api/courses", auth(), (req, res) => {
  const u = req.user;
  res.json(db.courses.filter(c => u.role === "admin" || (u.role === "teacher" ? c.teacherId === u.id : c.students.includes(u.id))).map(c => ({
    id: c.id, name: c.name, code: c.code, teacherId: c.teacherId, teacher: userInfo(c.teacherId)?.name || "", count: c.students.length,
    students: u.role === "student" ? undefined : c.students.map(userInfo).filter(Boolean) })));
});
app.post("/api/courses", auth("admin", "teacher"), (req, res) => {
  const { name, code } = req.body, tid = req.user.role === "teacher" ? req.user.id : +req.body.teacherId;
  if (!name?.trim()) return res.status(400).json({ error: "Course name is required" });
  if (!db.users.some(x => x.id === tid && x.role === "teacher")) return res.status(400).json({ error: "Choose a teacher for this course" });
  db.courses.push({ id: db.next++, name: name.trim(), code: String(code || "").trim(), teacherId: tid, students: [] }); save("courses"); res.json({ ok: true });
});
app.delete("/api/courses/:id", auth("admin", "teacher"), (req, res) => {
  const c = db.courses.find(x => x.id == req.params.id);
  if (!canManage(req.user, c)) return res.status(404).json({ error: "Course not found" });
  db.exams.forEach(e => { if (e.courseId === c.id) e.courseId = null; });
  db.courses = db.courses.filter(x => x !== c); save("courses", "exams"); res.json({ ok: true });
});
app.post("/api/courses/:id/enroll", auth("admin", "teacher"), (req, res) => {
  const c = db.courses.find(x => x.id == req.params.id);
  if (!canManage(req.user, c)) return res.status(404).json({ error: "Course not found" });
  const names = req.body.all ? db.users.filter(x => x.role === "student").map(x => x.username) : [].concat(req.body.usernames || []).map(x => String(x).trim()).filter(Boolean);
  const missing = []; let added = 0;
  names.forEach(n => { const u = db.users.find(x => x.username === n && x.role === "student"); if (!u) missing.push(n); else if (!c.students.includes(u.id)) { c.students.push(u.id); added++; } });
  save("courses"); res.json({ added, missing });
});
app.delete("/api/courses/:id/students/:sid", auth("admin", "teacher"), (req, res) => {
  const c = db.courses.find(x => x.id == req.params.id);
  if (!canManage(req.user, c)) return res.status(404).json({ error: "Course not found" });
  c.students = c.students.filter(x => x != req.params.sid); save("courses"); res.json({ ok: true });
});
app.post("/api/users/bulk", auth("admin"), async (req, res) => {
  const rows = Array.isArray(req.body.users) ? req.body.users.slice(0, 500) : [], c = db.courses.find(x => x.id === +req.body.courseId), skipped = []; let created = 0;
  for (const r of rows) {
    const name = String(r.name || "").trim(), username = String(r.username || "").trim(), password = String(r.password || "");
    if (!name || !username || password.length < 4 || db.users.some(x => x.username === username)) { skipped.push(username || name || "?"); continue; }
    const salt = crypto.randomBytes(8).toString("hex"), u = { id: db.next++, name, username, role: "student", pw: salt + ":" + await scryptP(password, salt) };
    db.users.push(u); created++; if (c) c.students.push(u.id);
  }
  save("users", "courses"); res.json({ created, skipped });
});

// ---- Essay grading (teacher marks written answers) ----
app.get("/api/grading", auth("teacher"), (req, res) => {
  const mine = db.exams.filter(e => e.teacherId === req.user.id).map(e => e.id), out = [];
  db.results.filter(r => mine.includes(r.examId)).forEach(r => (r.essays || []).forEach((x, k) => {
    if (x.mark === null) out.push({ examId: r.examId, studentId: r.studentId, student: r.student, exam: r.exam, k, q: x.q, guide: x.guide, answer: x.answer, max: x.max });
  }));
  res.json(out);
});
app.post("/api/grade", auth("teacher"), (req, res) => {
  const { examId, studentId, k, mark } = req.body;
  const e = db.exams.find(x => x.id === examId && x.teacherId === req.user.id);
  const r = e && db.results.find(x => x.examId === examId && x.studentId === studentId), x = r?.essays?.[k];
  if (!x || !(mark >= 0 && mark <= x.max)) return res.status(400).json({ error: "Invalid mark" });
  x.mark = mark; x.feedback = String(req.body.feedback || "").slice(0, 500);
  r.score = r.auto + r.essays.reduce((t, y) => t + (y.mark || 0), 0);
  r.pending = r.essays.filter(y => y.mark === null).length;
  r.percent = Math.round(r.score / r.total * 100);
  r.passed = r.pending ? null : r.percent >= (e.pass ?? 50);
  save(); res.json({ ok: true });
});

// ---- Question bank (per teacher) ----
app.get("/api/bank", auth("teacher"), (req, res) => res.json(db.bank.filter(b => b.teacherId === req.user.id)));
app.post("/api/bank", auth("teacher"), (req, res) => {
  const { subject, questions } = req.body;
  if (!subject || !questions?.length) return res.status(400).json({ error: "Subject and questions are required" });
  questions.forEach(q => db.bank.push({ id: db.next++, teacherId: req.user.id, subject, q })); save(); res.json({ ok: true });
});
app.delete("/api/bank/:id", auth("teacher"), (req, res) => {
  db.bank = db.bank.filter(b => !(b.id == req.params.id && b.teacherId === req.user.id)); save(); res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Open http://localhost:" + PORT));
