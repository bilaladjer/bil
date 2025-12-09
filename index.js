const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

// Middleware
app.use(cors({ origin: "*"}));
app.use(express.json());

// FAUSSE "base de données" en mémoire (pour test)
// En prod, remplace par une vraie BDD.
const users = []; // { id, username, passwordHash }
const tasks = []; // { id, userId, desc, deadline, statut, priority, notificationEnvoyee }

// Middleware d'authentification
function auth(req, res, next){
  const authHeader = req.headers.authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Token manquant" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = { id: payload.id, username: payload.username };
    next();
  } catch (e){
    return res.status(401).json({ error: "Token invalide" });
  }
}

// Route pour créer un utilisateur (inscription)
app.post("/api/register", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password){
    return res.status(400).json({ error: "username et password requis" });
  }
  if (users.find(u => u.username === username)){
    return res.status(400).json({ error: "Utilisateur déjà existant" });
  }
  const passwordHash = await bcrypt.hash(password, 10);
  const user = { id: users.length + 1, username, passwordHash };
  users.push(user);
  return res.status(201).json({ message: "Utilisateur créé" });
});

// Route de login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password){
    return res.status(400).json({ error: "username et password requis" });
  }
  const user = users.find(u => u.username === username);
  if (!user) return res.status(401).json({ error: "Identifiants incorrects" });

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) return res.status(401).json({ error: "Identifiants incorrects" });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: "7d" });
  return res.json({ token });
});

// Liste des tâches de l'utilisateur connecté
app.get("/api/tasks", auth, (req,res) => {
  const userTasks = tasks.filter(t => t.userId === req.user.id);
  res.json(userTasks);
});

// Ajouter une tâche
app.post("/api/tasks", auth, (req,res) => {
  const { desc, deadline, priority } = req.body || {};
  if (!desc || !deadline){
    return res.status(400).json({ error: "desc et deadline requis" });
  }
  const task = {
    id: tasks.length + 1,
    userId: req.user.id,
    desc,
    deadline,
    statut: "En cours",
    priority: priority || "normal",
    notificationEnvoyee: false
  };
  tasks.push(task);
  res.status(201).json(task);
});

// Marquer une tâche comme terminée
app.post("/api/tasks/:id/done", auth, (req,res) => {
  const id = parseInt(req.params.id, 10);
  const task = tasks.find(t => t.id === id && t.userId === req.user.id);
  if (!task) return res.status(404).json({ error: "Tâche non trouvée" });
  task.statut = "Terminé";
  task.notificationEnvoyee = false;
  res.json({ success: true });
});

// Supprimer une tâche
app.delete("/api/tasks/:id", auth, (req,res) => {
  const id = parseInt(req.params.id, 10);
  const idx = tasks.findIndex(t => t.id === id && t.userId === req.user.id);
  if (idx === -1) return res.status(404).json({ error: "Tâche non trouvée" });
  tasks.splice(idx, 1);
  res.json({ success: true });
});

// Petit test
app.get("/", (req,res) => {
  res.send("API TODO en ligne");
});

app.listen(PORT, () => {
  console.log("API listening on port " + PORT);
});
