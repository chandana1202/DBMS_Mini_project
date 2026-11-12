import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";

const users = {
  "asha@example.com":  "Demo@1234",
  "ravi@example.com":  "Demo@1234",
  "meera@example.com": "Demo@1234",
  "admin@example.com": "Demo@1234",
};

const con = await mysql.createConnection({
  host: process.env.MYSQL_HOST,
  user: process.env.ADMIN_DB_USER,
  password: process.env.ADMIN_DB_PASS,
  database: process.env.MYSQL_DB,
});

for (const [email, pw] of Object.entries(users)) {
  const hash = await bcrypt.hash(pw, 10);
  const [r] = await con.execute(
    "UPDATE app_user SET password_hash = ? WHERE email = ?", [hash, email]);
  console.log(email, r.affectedRows ? "ok" : "NOT FOUND");
}
await con.end();