import { exec } from "child_process";
import express from "express";
const app = express();

app.get("/run", (req, res) => {
  // UNDEFENDED: req.query into command exec
  const ip = req.query.ip;
  exec("ping " + ip);
  res.send(ip);
});

app.post("/user", (req, res) => {
  // UNDEFENDED via DESTRUCTURING: { id } = req.body then SQL
  const { id } = req.body;
  db.query("SELECT * FROM users WHERE id = " + id);
  res.send("ok");
});

app.get("/guarded", (req, res) => {
  // GUARDED: Number() neutralises before exec
  const n = Number(req.query.n);
  exec("sleep " + n);
  res.send("ok");
});

app.get("/dom", (req, res) => {
  // UNDEFENDED: innerHTML write (XSS)
  const q = req.query.q;
  el.innerHTML = q;
});
