# Medication Management Backend Project
This is the backend service for the **Medication Management System**. It supports user authentication, medication tracking (CRUD), and adherence logging using a SQLite database. The backend is built with **Node.js**, **Express**, **SQLite**, and **JWT authentication**.

## Features

-  User Registration and Login with hashed passwords
-  Add, view, and update medications
-  Mark medications as taken per day
-  JWT-based authentication
-  SQLite database for persistent storage

## Technologies Used

- Node.js
- Express.js
- SQLite

## Installation setup
### 1. Clone the repository
```sh
git clone https://github.com/srinivas9548/Medication-Management-Backend-Project.git
cd Medication-Management-Backend-Project
```

### 2. Install dependencies
```sh
npm install
```

### 3. Start the server
```sh
nodemon index.js
```