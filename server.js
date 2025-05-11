const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mysql = require("mysql2/promise");
const path = require("path");
const AWS = require("aws-sdk");
const multer = require("multer");
const multerS3 = require("multer-s3");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || "your-default-jwt-secret";

// Configure AWS only if S3 is enabled
let upload;
if (process.env.USE_S3 === "true") {
  // Configure AWS
  AWS.config.update({
    region: process.env.AWS_REGION || "us-east-1",
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  });

  // Initialize S3
  const s3 = new AWS.S3();

  // Configure S3 upload
  upload = multer({
    storage: multerS3({
      s3: s3,
      bucket: process.env.S3_BUCKET_NAME,
      acl: "public-read",
      metadata: function (req, file, cb) {
        cb(null, { fieldName: file.fieldname });
      },
      key: function (req, file, cb) {
        const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
      },
    }),
  });
} else {
  // Local storage fallback
  const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, "uploads/"); // Ensure this directory exists
    },
    filename: function (req, file, cb) {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(null, uniqueSuffix + path.extname(file.originalname));
    },
  });
  upload = multer({ storage: storage });
}

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASS || "",
  database: process.env.DB_NAME || "products_db",
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
};

let db;
(async () => {
  try {
    db = await mysql.createConnection(dbConfig);
    console.log("Connected to database successfully!");

    await db.execute(`CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) UNIQUE,
      password VARCHAR(255)
    )`);

    await db.execute(`CREATE TABLE IF NOT EXISTS products (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255),
      user_id INT,
      image_url VARCHAR(512),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);

    console.log("Database tables checked/created.");
  } catch (err) {
    console.error("Database initialization error:", err);
    console.log("Will retry connection in 5 seconds...");

    // Retry logic
    setTimeout(async () => {
      try {
        db = await mysql.createConnection(dbConfig);
        console.log("Connected to database on retry!");
      } catch (retryErr) {
        console.error("Failed to connect on retry:", retryErr);
        process.exit(1);
      }
    }, 5000);
  }
})();

// Middleware to verify token
const authenticate = async (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  try {
    const user = jwt.verify(token, JWT_SECRET);
    req.user = user;
    next();
  } catch {
    res.sendStatus(403);
  }
};

// Health check endpoint for AWS
app.get("/health", (req, res) => {
  res.status(200).send("Healthy");
});

// Public files (for local storage mode)
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Auth Routes
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  const hashed = await bcrypt.hash(password, 10);
  try {
    await db.execute("INSERT INTO users (email, password) VALUES (?, ?)", [
      email,
      hashed,
    ]);
    res.sendStatus(201);
  } catch (e) {
    console.error("Registration error:", e);
    res.status(400).send("Email already registered or database error.");
  }
});

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await db.execute("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (!rows.length) return res.sendStatus(401);
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.sendStatus(401);
    const token = jwt.sign({ id: user.id }, JWT_SECRET);
    res.json({ token });
  } catch (e) {
    console.error("Login error:", e);
    res.status(500).send("Server error during login");
  }
});

// Product Routes (CRUD)
app.get("/api/products", authenticate, async (req, res) => {
  try {
    const [products] = await db.execute(
      "SELECT * FROM products WHERE user_id = ?",
      [req.user.id]
    );
    res.json(products);
  } catch (e) {
    console.error("Error fetching products:", e);
    res.status(500).send("Server error while fetching products");
  }
});

app.post(
  "/api/products",
  authenticate,
  upload.single("image"),
  async (req, res) => {
    const { title } = req.body;
    let imageUrl = null;

    if (process.env.USE_S3 === "true" && req.file) {
      // S3 returns the URL in location
      imageUrl = req.file.location;
    } else if (req.file) {
      // Local path for development
      imageUrl = `/uploads/${req.file.filename}`;
    }

    try {
      await db.execute(
        "INSERT INTO products (title, user_id, image_url) VALUES (?, ?, ?)",
        [title, req.user.id, imageUrl]
      );
      res.sendStatus(201);
    } catch (error) {
      console.error("Error inserting product:", error);
      res.status(500).send("Error creating product");
    }
  }
);

app.put("/api/products/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const { title } = req.body;
  try {
    await db.execute(
      "UPDATE products SET title = ? WHERE id = ? AND user_id = ?",
      [title, id, req.user.id]
    );
    res.sendStatus(200);
  } catch (error) {
    console.error("Error updating product:", error);
    res.status(500).send("Error updating product");
  }
});

app.delete("/api/products/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    // First, get the product to check if it has an image to delete from S3
    const [products] = await db.execute(
      "SELECT * FROM products WHERE id = ? AND user_id = ?",
      [id, req.user.id]
    );

    // Delete the image from S3 if applicable
    if (
      process.env.USE_S3 === "true" &&
      products.length > 0 &&
      products[0].image_url
    ) {
      const s3 = new AWS.S3();
      // Extract the key from the S3 URL
      const urlParts = products[0].image_url.split("/");
      const key = urlParts[urlParts.length - 1];

      // Delete from S3
      const params = {
        Bucket: process.env.S3_BUCKET_NAME,
        Key: key,
      };

      s3.deleteObject(params, (err, data) => {
        if (err) console.error("Error deleting from S3:", err);
      });
    }

    // Delete from database
    await db.execute("DELETE FROM products WHERE id = ? AND user_id = ?", [
      id,
      req.user.id,
    ]);
    res.sendStatus(204);
  } catch (error) {
    console.error("Error deleting product:", error);
    res.status(500).send("Error deleting product");
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server started on port ${PORT}`));
