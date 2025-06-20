const express = require("express");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

app.use(express.json());
app.use(cors());

const dbPath = path.join(__dirname, "medication.db");

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (error) => {
    if (error) {
        console.log("Error opening database:", error.message);
    } else {
        console.log("Connected to the medication.db database.");
    }

    // Create 'user' table
    db.serialize(() => {
        db.run(
            `CREATE TABLE IF NOT EXISTS user (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            name TEXT,
            password TEXT,
            location TEXT
        )`,
            (err) => {
                if (err) {
                    console.error("Error creating table:", err.message);
                    process.exit(1);
                } else {
                    console.log("User table is ready.");
                }
            }
        );

        // Create 'medication' table
        db.run(
            `CREATE TABLE IF NOT EXISTS medication (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            name TEXT,
            dosage TEXT,
            frequency TEXT,
            taken_dates TEXT DEFAULT '',
            FOREIGN KEY(user_id) REFERENCES user(id)
        )`,
            (err) => {
                if (err) {
                    console.error("Error creating medication table:", err.message);
                } else {
                    console.log("Medication table is ready.");
                }
            }
        );

        app.listen(3000, () => {
            console.log("Server is Running at http://localhost:3000/");
        })
    })
});

// JWT Authentication Middleware
const authenticateToken = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    if (authHeader !== undefined) {
        jwtToken = authHeader.split(" ")[1];
    }
    if (authHeader === undefined) {
        response.status(401);
        response.send("User not logged in");
    } else {
        jwt.verify(jwtToken, "MY_SECRET_KEY", async (error, payload) => {
            if (error) {
                response.send("Invalid Access Token");
            } else {
                request.username = payload.username;
                next();
            }
        })
    }
};

// User Registration (sign up)
app.post("/users", async (request, response) => {
    try {
        const { username, name, password, location } = request.body;

        db.get(
            `SELECT * FROM user WHERE username = ?`, [username], async (err, dbUser) => {
                if (err) {
                    console.error("DB Error:", err.message);
                    response.status(500).json({ error: "Database error" });
                } else if (dbUser) {
                    response.status(400).json({ error: "User already exists" });
                } else {
                    const hashedPassword = await bcrypt.hash(password, 10);

                    db.run(
                        `INSERT INTO user (username, name, password, location) VALUES (?, ?, ?, ?)`,
                        [username, name, hashedPassword, location],
                        function (err) {
                            if (err) {
                                console.error("DB Insert Error:", err.message);
                                if (err.message.includes("UNIQUE constraint failed")) {
                                    return response.status(400).json({ error: "Username already exists" });
                                }
                                response.status(500).json({ error: "Error creating user" });
                            } else {
                                response.json({ message: "User created successfully" });
                            }
                        }
                    );
                }
            }
        );
    } catch (e) {
        console.error(e.message);
        response.status(500).send("Internal Server Error");
    }
});

// User Login (sign in)
app.post("/login", async (request, response) => {
    const { username, password } = request.body;

    if (!username || !password) {
        return response.status(400).json({ error_msg: "Username or password is invalid" });
    }

    db.get(
        `SELECT * FROM user WHERE username = ?`, [username], async (err, dbUser) => {
            if (err) {
                response.status(500).json({ error: "Database Error" });
            } else if (!dbUser) {
                response.status(400).json({ error_msg: "Invalid Username" });
            } else {
                const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
                if (isPasswordMatched) {
                    const payload = { username: username };
                    const jwtToken = jwt.sign(payload, "MY_SECRET_KEY");
                    response.json({ jwtToken });
                } else {
                    response.status(400).json({ error_msg: "Username and password didn't match" })
                }
            }
        }
    )
});

// Initial API
app.get("/", async (request, response) => {
    try {
        response.send("Welcome!, This is a Medication Management Company Assignment Backend domain you can access with endpoints.");
    } catch (e) {
        console.error(e.message);
        response.status(500).json({ error: 'Internal Server Error' });
    }
});

// Add Medication
app.post("/medications", authenticateToken, (request, response) => {
    const { name, dosage, frequency } = request.body;

    if (!name || !dosage || !frequency) {
        return response.status(400).json({ error: "All fields are required." });
    }

    db.get(`SELECT id FROM user WHERE username = ?`, [request.username], (error, user) => {
        if (error) {
            console.error("Database error:", error.message);
            return response.status(500).json({ error: "Internal server error while retrieving user." });
        }

        if (!user) {
            return response.status(404).json({ error: "User not found." });
        }

        db.run(
            `INSERT INTO medication (user_id, name, dosage, frequency) VALUES (?, ?, ?, ?)`,
            [user.id, name, dosage, frequency],
            function (error) {
                if (error) {
                    console.error("Database insert error:", error.message);
                    return response.status(500).json({ error: "Failed to add medication." });
                }

                return response.status(201).json({
                    message: "Medication added successfully.",
                    medicationId: this.lastID,
                });
            }
        );
    });
});

// View Medications
app.get("/medications", authenticateToken, (request, response) => {
    db.get(`SELECT id FROM user WHERE username = ?`, [request.username], (err, user) => {
        if (err || !user) {
            return response.status(400).json({ error: "User not found" });
        }

        db.all(`SELECT * FROM medication WHERE user_id = ?`, [user.id], (err, rows) => {
            if (err) {
                return response.status(500).json({ error: "Failed to fetch medications" });
            }
            response.status(200).json(rows);
        });
    });
});

// Mark Medication as Taken
app.post("/medications/:id/mark-taken", authenticateToken, (request, response) => {
    const medicationId = request.params.id;
    const today = new Date().toISOString().split("T")[0]; // yyyy-mm-dd

    db.get(`SELECT taken_dates FROM medication WHERE id = ?`, [medicationId], (err, row) => {
        if (err || !row) {
            return response.status(404).json({ error: "Medication not found" });
        }

        let dates = row.taken_dates ? row.taken_dates.split(",") : [];
        if (!dates.includes(today)) {
            dates.push(today);
        }

        db.run(
            `UPDATE medication SET taken_dates = ? WHERE id = ?`,
            [dates.join(","), medicationId],
            function (err) {
                if (err) {
                    return response.status(500).json({ error: "Failed to mark as taken" });
                }
                response.status(200).json({ message: "Medication marked as taken for today" });
            }
        );
    });
});

// Get All the users
app.get("/users", authenticateToken, (request, response) => {
    db.all("SELECT * FROM user", [], (err, rows) => {
        if (err) {
            return response.status(500).json({ error: "Failed to fetch users" });
        }
        response.json(rows);
    });
});

module.exports = app;