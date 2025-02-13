const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { dynamoDB, USERS_TABLE } = require("../config/db");
const { v4: uuidv4 } = require("uuid");

const router = express.Router();

// 📌 1. Inscription d'un utilisateur
router.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  try {
    // Vérifier si l'utilisateur existe déjà
    const existingUser = await dynamoDB.get({
      TableName: USERS_TABLE,
      Key: { email },
    }).promise();

    if (existingUser.Item) return res.status(400).json({ message: "Email déjà utilisé" });

    // Hachage du mot de passe
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: uuidv4(),
      name,
      email,
      password: hashedPassword,
      role: "user",
    };

    await dynamoDB.put({
      TableName: USERS_TABLE,
      Item: newUser,
    }).promise();

    res.status(201).json({ message: "Utilisateur enregistré avec succès" });
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur", error });
  }
});

// 📌 2. Connexion d'un utilisateur
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Vérifier l'existence de l'utilisateur
    const result = await dynamoDB.get({
      TableName: USERS_TABLE,
      Key: { email },
    }).promise();

    if (!result.Item) return res.status(400).json({ message: "Utilisateur non trouvé" });

    const user = result.Item;

    // Vérifier le mot de passe
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Mot de passe incorrect" });

    // Génération du token JWT
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur", error });
  }
});

// 📌 3. Rafraîchissement du token
router.post("/refresh-token", (req, res) => {
  const { token } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const newToken = jwt.sign({ id: decoded.id, role: decoded.role }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({ token: newToken });
  } catch (error) {
    res.status(401).json({ message: "Token invalide ou expiré" });
  }
});

// 📌 4. Obtenir les informations de l'utilisateur connecté
router.get("/me", authMiddleware, async (req, res) => {
  try {
    const result = await dynamoDB.get({
      TableName: USERS_TABLE,
      Key: { email: req.user.email },
    }).promise();

    if (!result.Item) return res.status(404).json({ message: "Utilisateur non trouvé" });

    const { password, ...userWithoutPassword } = result.Item;
    res.json(userWithoutPassword);
  } catch (error) {
    res.status(500).json({ message: "Erreur serveur", error });
  }
});

module.exports = router;
